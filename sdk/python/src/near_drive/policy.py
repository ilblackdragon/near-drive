"""Namespace access policy, a port of ``near_drive_core::policy`` (the rules ``drive.near`` holds).

Rules are evaluated in order; the first rule whose ``prefix`` pattern matches the path applies.
``{account}`` in a prefix captures one path segment that must be a valid account id; ``{account}``
in read/write/payer refers to that captured value. The namespace owner always has full access and
is the default payer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from .uri import is_valid_account_id


@dataclass
class Rule:
    prefix: str
    read: list = field(default_factory=list)
    write: list = field(default_factory=list)
    payer: Optional[str] = None

    @classmethod
    def from_dict(cls, v: Any) -> "Rule":
        if not isinstance(v, dict) or not isinstance(v.get("prefix"), str):
            raise ValueError("rule.prefix must be a string")

        def strs(k: str) -> list:
            x = v.get(k)
            if x is None:
                return []
            if not isinstance(x, list) or not all(isinstance(e, str) for e in x):
                raise ValueError(f"rule.{k} must be a list of strings")
            return list(x)

        payer = v.get("payer")
        if payer is not None and not isinstance(payer, str):
            raise ValueError("rule.payer must be a string")
        return cls(v["prefix"], strs("read"), strs("write"), payer)

    def to_dict(self) -> dict:
        return {"prefix": self.prefix, "read": self.read, "write": self.write, "payer": self.payer}


@dataclass(frozen=True)
class Access:
    read: bool
    write: bool
    payer: str


def rules_from_json(v: Any) -> list[Rule]:
    if not isinstance(v, list):
        raise ValueError("rules must be a list")
    return [r if isinstance(r, Rule) else Rule.from_dict(r) for r in v]


def _match_prefix(pattern: str, path: str) -> Optional[str]:
    """The captured ``{account}`` (``""`` when the pattern has none) if ``path`` is under
    ``pattern``, else None."""
    pre, sep, post = pattern.partition("{account}")
    if not sep:
        return "" if path.startswith(pattern) else None
    if not path.startswith(pre):
        return None
    rest = path[len(pre):]
    end = rest.find("/")
    if end < 0:
        end = len(rest)
    acct = rest[:end]
    if not is_valid_account_id(acct):
        return None
    return acct if rest[end:].startswith(post) else None


def resolve(namespace: str, rules: Sequence[Rule], path: str, signer: str) -> Access:
    owner = signer == namespace
    for r in rules:
        bound = _match_prefix(r.prefix, path)
        if bound is None:
            continue

        def allowed(lst: Sequence[str], bound: str = bound) -> bool:
            return any(e == "*" or e.replace("{account}", bound) == signer for e in lst)

        return Access(
            read=owner or allowed(r.read),
            write=owner or allowed(r.write),
            payer=r.payer.replace("{account}", bound) if r.payer is not None else namespace,
        )
    return Access(owner, owner, namespace)
