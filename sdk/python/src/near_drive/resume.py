"""Upload journal: lets an interrupted ``Client.put_file`` resume (same format as the Rust client).

One JSONL file per (account, URI, source file) under ``resume_dir``::

    {"header": {... what was being uploaded, incl. the object's `enc` ...}}
    {"i": 7, "ph": "<blake3 of chunk 7's plaintext>"}     before chunk 7 is sent (fsynced)
    {"i": 7, "cid": "b3:...", "len": 4194320}            after the gateway stored it

Resuming reuses the object's key (``enc``, unwrapped with the owner's root key), so identical
plaintext re-encrypts to identical chunks and the ones already stored are skipped. Sealing
*different* plaintext under the same chunk index would reuse a nonce, so a chunk is journaled
with its plaintext hash before it is ever sent, and on resume every journaled chunk is checked
against the file: any difference (the file changed) discards the journal and the upload
starts over with a fresh key.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

import blake3

from .crypto import EncInfo, chunk_plain_len
from .manifest import ChunkRef, enc_from_dict


def _fdatasync(fd: int) -> None:
    (getattr(os, "fdatasync", None) or os.fsync)(fd)


def journal_key(account: str, uri: str, src: str, chunk_size: int, public: bool, storage_class: Optional[str], share_with: Sequence[str], content_type: Optional[str]) -> dict:
    """What is being uploaded; a journal resumes only if all of it matches. Field order and
    names are those of the Rust ``JournalKey``."""
    src = os.path.realpath(src)
    st = os.stat(src)
    return {
        "account": account,
        "uri": uri,
        "src": src,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "chunk_size": chunk_size,
        "public": public,
        "class": storage_class,
        "share_with": list(share_with),
        "content_type": content_type,
    }


def journal_path(dir: Path, key: dict) -> Path:
    h = blake3.blake3(f"{key['account']}\n{key['uri']}\n{key['src']}".encode("utf-8")).hexdigest()
    return Path(dir) / f"{h[:32]}.jsonl"


def plain_hash(pt: bytes) -> str:
    return blake3.blake3(pt).hexdigest()


@dataclass
class Resumed:
    enc: Optional[EncInfo]
    #: Chunk index -> plaintext hash, for every chunk that may have been sent.
    dispatched: dict = field(default_factory=dict)
    done: dict = field(default_factory=dict)


def load(path: Path, key: dict) -> Optional[Resumed]:
    """Load a journal for exactly this upload; None if absent or for something else."""
    try:
        lines = Path(path).read_text("utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if not lines:
        return None
    try:
        h = json.loads(lines[0])["header"]
        if {k: h.get(k) for k in key} != key:
            return None
        r = Resumed(enc_from_dict(h.get("enc")))
    except (ValueError, KeyError, TypeError):
        return None
    for line in lines[1:]:
        # A torn final line (crash mid-write) fails to parse and is ignored.
        try:
            v = json.loads(line)
            i = v["i"]
            if not isinstance(i, int):
                continue
            if isinstance(v.get("ph"), str):
                r.dispatched[i] = v["ph"]
            elif isinstance(v.get("cid"), str) and isinstance(v.get("len"), int):
                r.done[i] = ChunkRef(v["cid"], v["len"])
        except (ValueError, KeyError, TypeError):
            continue
    # Only trust "done" for chunks whose plaintext hash was journaled first.
    r.done = {i: c for i, c in r.done.items() if i in r.dispatched}
    return r


def file_unchanged(src: str, chunk_size: int, r: Resumed) -> bool:
    """Check every journaled chunk's plaintext hash against the file now."""
    with open(src, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        for i, ph in r.dispatched.items():
            f.seek(i * chunk_size)
            b = f.read(chunk_plain_len(size, chunk_size, i))
            if plain_hash(b) != ph:
                return False
    return True


class Journal:
    def __init__(self, path: Path, f):
        self.path = Path(path)
        self._f = f
        self._lock = threading.Lock()

    @classmethod
    def create(cls, path: Path, key: dict, enc: Optional[EncInfo]) -> "Journal":
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        f = open(path, "w", encoding="utf-8")
        header = dict(key)
        header["enc"] = enc.to_dict() if enc is not None else None
        f.write(json.dumps({"header": header}, separators=(",", ":"), ensure_ascii=False) + "\n")
        f.flush()
        _fdatasync(f.fileno())
        return cls(path, f)

    @classmethod
    def append(cls, path: Path) -> "Journal":
        return cls(path, open(path, "a", encoding="utf-8"))

    def _write(self, v: dict, sync: bool) -> None:
        s = json.dumps(v, separators=(",", ":")) + "\n"
        with self._lock:
            self._f.write(s)
            self._f.flush()
            if sync:
                _fdatasync(self._f.fileno())

    def dispatched(self, i: int, ph: str) -> None:
        """Before chunk ``i`` is sealed and sent: durable, so a resume can never seal
        different plaintext under this index."""
        self._write({"i": i, "ph": ph}, True)

    def done(self, i: int, r: ChunkRef) -> None:
        self._write({"i": i, "cid": r.cid, "len": r.len}, False)

    def close(self) -> None:
        with self._lock:
            self._f.close()

    def finish(self) -> None:
        self.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
