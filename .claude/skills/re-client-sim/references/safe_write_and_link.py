"""Reference shapes for client/<slug>/: Link protocol, RecordingLink, SafeWriteGuard.

Copy and adapt; keep the guarantees. Derived from client/t900-c900 (link.py,
safe_write.py) with two hardenings: an unreadable state file fails closed instead
of resetting the counters, and the link refuses blocklisted (OTA/DFU) services.
"""
import datetime
import hashlib
import json
import os
import time
from typing import Callable, Dict, List, Optional, Protocol, Tuple

# Services the client must never write to (OTA/DFU). Fill from PROTOCOL.md; lowercase.
BLOCKED_SERVICES = frozenset()


class Link(Protocol):
    """The only seam between session code and hardware. One real class (bleak) implements it."""
    mtu: int

    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def services(self) -> List[str]: ...
    async def start_notify(self, char: str, cb: Callable[[bytes], None]) -> None: ...
    async def write(self, char: str, data: bytes, response: bool = False) -> None: ...
    async def read(self, char: str) -> bytes: ...


class RecordingLink:
    """Dry-run and simulator link: records every write, never touches a radio."""

    def __init__(self, services: Optional[List[str]] = None, mtu: int = 23, simulator=None):
        self.mtu, self._services, self.simulator = mtu, list(services or []), simulator
        self.writes: List[Tuple[str, bytes, bool]] = []
        self._cbs: Dict[str, Callable[[bytes], None]] = {}

    async def connect(self): pass
    async def disconnect(self): pass
    async def services(self): return list(self._services)
    async def start_notify(self, char, cb): self._cbs[char] = cb
    async def read(self, char): return self.simulator.read(char) if self.simulator else b""

    async def write(self, char, data, response=False):
        if any(char.lower().startswith(s) or s in char.lower() for s in BLOCKED_SERVICES):
            raise PermissionError("write to blocked OTA/DFU characteristic %s" % char)
        self.writes.append((char, bytes(data), response))
        for c, payload in (self.simulator.on_write(char, data) if self.simulator else []):
            self._cbs.get(c, lambda _b: None)(payload)


class GuardRefused(Exception):
    pass


class SafeWriteGuard:
    """Per-device write budget. The address is stored only as a SHA-256 prefix."""

    def __init__(self, state_dir: str, max_daily_writes: int, min_interval_sec: float):
        self.dir, self.cap, self.interval = state_dir, max_daily_writes, min_interval_sec

    def _path(self, address: str) -> str:
        return os.path.join(self.dir, "%s.json" % hashlib.sha256(address.upper().encode()).hexdigest()[:16])

    def _load(self, address: str) -> dict:
        today = datetime.date.today().isoformat()
        try:
            with open(self._path(address), encoding="utf-8") as f:
                st = json.load(f)
        except FileNotFoundError:
            st = {"date": today, "daily": 0, "total": 0, "last_ts": 0.0, "last_payload_sha256": ""}
        except (OSError, ValueError) as e:  # fail closed: never reset a budget we cannot read
            raise GuardRefused("guard state unreadable (%s); fix or remove it by hand" % e)
        if st.get("date") != today:
            st.update(date=today, daily=0)
        return st

    def check(self, address: str, payload: bytes, no_delta: bool = False, dry_run: bool = False) -> None:
        """Raise GuardRefused unless this write is allowed. Call after the payload is final,
        before the first data frame. Dry runs are checked but never counted."""
        st = self._load(address)
        if st["daily"] >= self.cap:
            raise GuardRefused("daily cap %d reached" % self.cap)
        if not no_delta and st["last_payload_sha256"] == hashlib.sha256(payload).hexdigest():
            raise GuardRefused("identical payload already written (use --no-delta to rewrite on purpose)")
        if not dry_run and time.time() - st["last_ts"] < self.interval:
            raise GuardRefused("minimum interval %.1fs not met" % self.interval)

    def record_success(self, address: str, payload: bytes, dry_run: bool = False) -> None:
        """Count only after the device confirmed the write."""
        if dry_run:
            return
        st = self._load(address)
        st.update(daily=st["daily"] + 1, total=st["total"] + 1, last_ts=time.time(),
                  last_payload_sha256=hashlib.sha256(payload).hexdigest())
        os.makedirs(self.dir, exist_ok=True)
        tmp = self._path(address) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, indent=1)
        os.replace(tmp, self._path(address))  # atomic: a crash never leaves a half-written ledger
