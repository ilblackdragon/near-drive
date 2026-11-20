"""Read-only access to the ``drive.near`` contract (NEAR JSON-RPC view calls) and the reader-side
writer check: a record is accepted only if ``writer_pk`` is a signing key ``writer`` published
with ``set_sign_key`` (in force at ``ts_ms``) and the namespace rules let ``writer`` write ``path``.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Generic, Mapping, Optional, Sequence, TypeVar, Union

import httpx

from .manifest import PointerRecord
from .policy import Rule, resolve, rules_from_json
from .uri import is_valid_account_id

#: Clock skew tolerated around a key change (5 min, like the request-timestamp window).
SIGN_KEY_SKEW_MS = 5 * 60 * 1000
DEFAULT_CACHE_TTL = 60.0
DEFAULT_CACHE_MAX_ENTRIES = 1024
#: A failed check re-reads chain state once if the cached copy is older than this (seconds).
_REFRESH_AFTER = 5.0

NO_WRITER_CHECK = (
    "no writer check configured: records cannot be verified against their writer. Pass "
    "writer_check= (WriterCheck.chain(rpc_url, contract_id), or WriterCheck.trusted({...}) for "
    "dev/tests) or rpc_url= to Client"
)

V = TypeVar("V")


@dataclass(frozen=True)
class SignKeyEntry:
    """One entry of ``get_sign_keys(account_id)`` (oldest first)."""

    key: str
    #: Block time (ms) at which the key was published.
    since_ms: int

    @classmethod
    def from_dict(cls, v) -> "SignKeyEntry":
        if not isinstance(v, dict) or not isinstance(v.get("key"), str):
            raise ValueError("get_sign_keys: bad entry")
        s = v.get("since_ms")
        if isinstance(s, str) and s.isdigit():
            s = int(s)
        if not isinstance(s, int) or isinstance(s, bool) or s < 0:
            raise ValueError("get_sign_keys: bad since_ms")
        return cls(v["key"], s)


def sign_key_in_force(entries: Sequence[SignKeyEntry], key: str, ts_ms: int) -> bool:
    """Whether ``key`` is the key in force at ``ts_ms``: entry i covers
    ``[since_i - 5 min, since_{i+1} + 5 min)``, the latest entry is open-ended."""
    for i, e in enumerate(entries):
        if e.key != key or ts_ms < e.since_ms - SIGN_KEY_SKEW_MS:
            continue
        if i + 1 == len(entries) or ts_ms < entries[i + 1].since_ms + SIGN_KEY_SKEW_MS:
            return True
    return False


class StorageContract:
    """View calls on a deployed ``drive.near`` contract (``query`` / ``call_function``, finality
    ``final``)."""

    def __init__(self, rpc_url: str, contract_id: str, http: Optional[httpx.Client] = None, timeout: float = 10.0):
        self.rpc_url = rpc_url
        self.contract_id = contract_id
        self._http = http or httpx.Client(timeout=timeout)
        self._timeout = timeout

    def close(self) -> None:
        self._http.close()

    def view(self, method: str, args) -> object:
        """``method(args)`` as a view call; returns the decoded JSON result."""
        params = {
            "request_type": "call_function",
            "finality": "final",
            "account_id": self.contract_id,
            "method_name": method,
            "args_base64": base64.b64encode(json.dumps(args, separators=(",", ":")).encode()).decode(),
        }
        r = self._http.post(self.rpc_url, json={"jsonrpc": "2.0", "id": "near-drive", "method": "query", "params": params}, timeout=self._timeout)
        if r.status_code != 200:
            raise RuntimeError(f"rpc {method}: HTTP {r.status_code}")
        resp = r.json()
        if resp.get("error") is not None:
            raise RuntimeError(f"rpc {self.contract_id}.{method} error: {json.dumps(resp['error'])}")
        res = resp.get("result") or {}
        if res.get("error") is not None:
            raise RuntimeError(f"view {self.contract_id}.{method} failed: {res['error']}")
        raw = res.get("result")
        if not isinstance(raw, list) or not all(isinstance(b, int) and 0 <= b <= 255 for b in raw):
            raise RuntimeError(f"view {method}: missing result bytes")
        return json.loads(bytes(raw))

    def get_sign_keys(self, account_id: str) -> list[SignKeyEntry]:
        """Signing keys ``account_id`` published with ``set_sign_key``, oldest first."""
        v = self.view("get_sign_keys", {"account_id": account_id})
        if not isinstance(v, list):
            raise ValueError("get_sign_keys: expected a list")
        return [SignKeyEntry.from_dict(e) for e in v]

    def get_rules(self, namespace: str) -> list[Rule]:
        """The namespace's policy rules (empty: only the owner may read/write)."""
        return rules_from_json(self.view("get_rules", {"namespace": namespace}))


class _TtlCache(Generic[V]):
    """TTL + size-bounded, thread-safe. Failures are not cached."""

    def __init__(self, ttl: float, max_entries: int):
        self.ttl, self.max = ttl, max(1, max_entries)
        self._m: "OrderedDict[str, tuple[float, V]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, k: str, load: Callable[[], V], fresher_than: Optional[float] = None) -> V:
        max_age = min(self.ttl, fresher_than) if fresher_than is not None else self.ttl
        with self._lock:
            e = self._m.get(k)
            if e is not None and time.monotonic() - e[0] < max_age:
                return e[1]
        v = load()
        with self._lock:
            self._m.pop(k, None)
            self._m[k] = (time.monotonic(), v)
            while len(self._m) > self.max:
                self._m.popitem(last=False)
        return v

    def age(self, k: str) -> float:
        with self._lock:
            e = self._m.get(k)
            return float("inf") if e is None else time.monotonic() - e[0]

    def __len__(self) -> int:
        return len(self._m)


class WriterCheck:
    """How a client decides that a record's writer was allowed to write it. There is no default
    that skips the check: a client without one fails reads.

    - :meth:`chain`: ``drive.near`` state over NEAR RPC (production);
    - :meth:`trusted`: fixed account -> signing keys (+ optional rules), for tests and dev gateways;
    - :meth:`insecure_skip_writer_check`: no writer check at all (tests only).
    """

    def __init__(self, _kind: str, **kw):
        if _kind not in ("chain", "trusted", "insecure-skip"):
            raise ValueError("use WriterCheck.chain / .trusted / .insecure_skip_writer_check")
        self.kind = _kind
        self._kw = kw

    @classmethod
    def chain(
        cls,
        contract: Union[StorageContract, str],
        contract_id: Optional[str] = None,
        *,
        ttl: float = DEFAULT_CACHE_TTL,
        max_entries: int = DEFAULT_CACHE_MAX_ENTRIES,
        http: Optional[httpx.Client] = None,
    ) -> "WriterCheck":
        """Check against the drive contract (``get_sign_keys``, ``get_rules``), cached ``ttl``
        seconds (60) per account / namespace, at most ``max_entries`` each. ``contract`` is a
        :class:`StorageContract` or an RPC URL (then ``contract_id`` is required)."""
        if not isinstance(contract, StorageContract):
            if contract_id is None:
                raise ValueError("WriterCheck.chain(rpc_url, contract_id): contract_id is required")
            contract = StorageContract(contract, contract_id, http=http)
        return cls("chain", contract=contract, keys=_TtlCache(ttl, max_entries), rules=_TtlCache(ttl, max_entries))

    @classmethod
    def trusted(cls, sign_keys: Mapping[str, Sequence[str]], rules: Optional[Mapping[str, Sequence[Union[Rule, dict]]]] = None) -> "WriterCheck":
        """Fixed trust (tests, dev gateways): ``sign_keys`` maps an account to its signing keys
        (``RootKey.sign_public_key()``), all always in force; ``rules`` maps a namespace to its
        rules (absent: only the namespace owner may write)."""
        return cls(
            "trusted",
            keys={a: set(ks) for a, ks in sign_keys.items()},
            rules={ns: rules_from_json(list(rs)) for ns, rs in (rules or {}).items()},
        )

    @classmethod
    def insecure_skip_writer_check(cls) -> "WriterCheck":
        """INSECURE: accept any correctly self-signed record (a malicious gateway can forge
        writers). Tests only."""
        return cls("insecure-skip")

    @property
    def contract(self) -> Optional[StorageContract]:
        return self._kw.get("contract")

    def verify(self, r: PointerRecord) -> None:
        """Raise ``ValueError`` unless ``r.writer_pk`` is ``r.writer``'s signing key in force at
        ``r.ts_ms`` and ``r.writer`` may write ``r.path``."""
        if self.kind == "insecure-skip":
            return
        where = f"near://{r.namespace}/{r.path}"
        if not is_valid_account_id(r.writer):
            raise ValueError(f"record for {where}: invalid writer account {r.writer!r}")
        key_err = ValueError(f"record for {where} is signed with {r.writer_pk}, which is not a signing key of {r.writer} in force at ts {r.ts_ms}")
        rule_err = ValueError(f"record for {where} was written by {r.writer}, who may not write there under the namespace rules")
        if self.kind == "trusted":
            if r.writer_pk not in self._kw["keys"].get(r.writer, ()):
                raise key_err
            if not resolve(r.namespace, self._kw["rules"].get(r.namespace, []), r.path, r.writer).write:
                raise rule_err
            return
        c: StorageContract = self._kw["contract"]
        keys: _TtlCache = self._kw["keys"]
        rules: _TtlCache = self._kw["rules"]

        def keys_ok(fresh: Optional[float] = None) -> bool:
            return sign_key_in_force(keys.get(r.writer, lambda: c.get_sign_keys(r.writer), fresh), r.writer_pk, r.ts_ms)

        def rules_ok(fresh: Optional[float] = None) -> bool:
            return resolve(r.namespace, rules.get(r.namespace, lambda: c.get_rules(r.namespace), fresh), r.path, r.writer).write

        # A key or rule may have changed within the cache TTL: re-read once before rejecting.
        if not keys_ok() and (keys.age(r.writer) < _REFRESH_AFTER or not keys_ok(_REFRESH_AFTER)):
            raise key_err
        # Owners need no rules lookup.
        if r.writer != r.namespace and not rules_ok() and (rules.age(r.namespace) < _REFRESH_AFTER or not rules_ok(_REFRESH_AFTER)):
            raise rule_err
