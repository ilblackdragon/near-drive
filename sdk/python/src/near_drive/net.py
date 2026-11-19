"""Network behaviour: timeouts and retries for every gateway request (mirrors the Rust
``near_drive_client::NetConfig``).

- Each request gets a deadline that grows with its size
  (``base_timeout + bytes / min_throughput``), plus connect and idle (no bytes moving)
  timeouts, so a stalled connection fails fast and a slow but moving one is not cut off.
- Transient failures (connection errors, timeouts, truncated bodies, chunks whose bytes
  don't match their id, 5xx, 408, 429) are retried with full-jitter exponential backoff,
  honouring ``Retry-After``. Each attempt is signed afresh.

Chunk transfers are idempotent (content-addressed), so they retry freely. The record
commit is the only non-idempotent write; see ``Client._commit``.
"""
from __future__ import annotations

import os
import random
import sys
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, TypeVar

import httpx

T = TypeVar("T")


@dataclass
class NetConfig:
    #: Attempts per request (1 = no retries).
    attempts: int = 8
    #: First backoff in seconds; doubles per attempt (full jitter), capped at ``max_delay``.
    base_delay: float = 0.25
    max_delay: float = 30.0
    connect_timeout: float = 10.0
    #: Fail a request when no bytes move for this long.
    idle_timeout: float = 60.0
    #: Deadline for a request moving no payload.
    base_timeout: float = 30.0
    #: Slowest acceptable transfer rate (bytes/s); sets the deadline of large requests.
    min_throughput: int = 64 * 1024

    def timeout_for(self, nbytes: int) -> float:
        """Deadline (seconds) for a request that moves ``nbytes`` of payload (either direction)."""
        return self.base_timeout + nbytes / max(1, self.min_throughput)

    def delay(self, attempt: int, floor: Optional[float] = None) -> float:
        """Full-jitter backoff before retry number ``attempt`` (0-based), at least ``floor``."""
        cap = min(self.base_delay * (1 << min(attempt, 16)), self.max_delay)
        jitter = cap * random.random()
        return jitter if floor is None else max(jitter, min(floor, self.max_delay * 4))

    def httpx_timeout(self, deadline: Optional[float] = None) -> httpx.Timeout:
        idle = self.idle_timeout if deadline is None else min(self.idle_timeout, deadline)
        return httpx.Timeout(connect=self.connect_timeout, read=idle, write=idle, pool=self.base_timeout if deadline is None else deadline)

    def http_client(self) -> httpx.Client:
        return httpx.Client(timeout=self.httpx_timeout(), limits=httpx.Limits(max_keepalive_connections=32, keepalive_expiry=90.0))


def debug(msg: str) -> None:
    if os.environ.get("NEAR_DRIVE_DEBUG"):
        print(f"near-drive: {msg}", file=sys.stderr)


class Retry(Exception):
    """A transient failure; ``wait`` (seconds) is the server's ``Retry-After``, if any."""

    def __init__(self, cause: BaseException, wait: Optional[float] = None):
        super().__init__(str(cause))
        self.cause = cause
        self.wait = wait


class DeadlineExceeded(httpx.TimeoutException):
    """The whole request took longer than its size-based deadline."""


class Truncated(httpx.TransportError):
    """The response body ended before its Content-Length."""


def retryable_status(status: int) -> bool:
    return status >= 500 or status in (408, 429)


def retry_after(headers: Mapping[str, str]) -> Optional[float]:
    v = headers.get("retry-after")
    if v is None:
        return None
    try:
        return float(int(v.strip()))
    except ValueError:
        return None


def with_retries(cfg: NetConfig, what: str, f: Callable[[int], T], sleep: Callable[[float], None] = time.sleep) -> T:
    """Run ``f(attempt)`` until it returns, raises a non-``Retry`` error, or attempts run out
    (then the last cause is raised). Transport errors from httpx count as transient."""
    attempts = max(1, cfg.attempts)
    attempt = 0
    while True:
        try:
            return f(attempt)
        except Retry as r:
            err, wait = r.cause, r.wait
        except httpx.TransportError as e:
            err, wait = e, None
        if attempt + 1 >= attempts:
            debug(f"{what}: giving up after {attempts} attempts")
            raise err
        d = cfg.delay(attempt, wait)
        debug(f"{what}: {err!r}; retry {attempt + 1} in {d:.3f}s")
        sleep(d)
        attempt += 1
