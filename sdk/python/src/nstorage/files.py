"""Local key files, compatible with the ``nst`` CLI."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, Union

from .crypto import RootKey
from .keys import parse_secret_key, public_key_of


def default_credentials_path(account: str, network: str = "mainnet") -> Path:
    return Path.home() / ".near-credentials" / network / f"{account}.json"


def default_root_key_path(account: str, home: Union[str, Path, None] = None) -> Path:
    """``$NSTORAGE_HOME/keys/<account>.root`` (default ``~/.nstorage``), as used by ``nst keygen``."""
    base = Path(home or os.environ.get("NSTORAGE_HOME") or Path.home() / ".nstorage")
    return base / "keys" / f"{account}.root"


def load_credentials(path: Union[str, Path]) -> tuple[str, str]:
    """Load a NEAR credentials JSON; returns ``(account_id, private_key)``."""
    c = json.loads(Path(path).read_text())
    if public_key_of(parse_secret_key(c["private_key"])) != c["public_key"]:
        raise ValueError("credentials file public_key does not match private_key")
    return c["account_id"], c["private_key"]


def load_root_key(path: Union[str, Path]) -> Optional[RootKey]:
    try:
        return RootKey.from_hex(Path(path).read_text())
    except FileNotFoundError:
        return None


def generate_root_key_file(path: Union[str, Path]) -> RootKey:
    """Create a new root key file (mode 0600); refuses to overwrite."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    k = RootKey.generate()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(k.hex())
    return k
