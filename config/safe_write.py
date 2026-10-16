#!/usr/bin/env python3
"""config/safe_write.py: Safe-write guard for device operations (Ground Rule 7).

Per-device state file keyed by a hash of the device address:
- Write counter, last payload hash (skip identical)
- Minimum interval between writes
- Hard daily cap
- Dry runs never count
- Count only after success

This protects the device from flash wear and bricking due to runaway
repeated-send features. No write path is shipped without this guard.

Usage:
    python config/safe_write.py --device <address> --record <payload_hash> --success
    python config/safe_write.py --device <address> --check
    python config/safe_write.py --device <address> --reset
"""
import argparse
import hashlib
import json
import os
import sys
import time

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe_write_state")


def device_key(address):
    """Return a stable key for a device address (hashed, never stored raw)."""
    return hashlib.sha256(address.encode()).hexdigest()[:16]


def state_path(address):
    return os.path.join(STATE_DIR, device_key(address) + ".json")


def load_state(address):
    path = state_path(address)
    if not os.path.isfile(path):
        return {"writes": 0, "last_payload": None, "last_write_ts": 0,
                "daily_count": 0, "daily_date": _today()}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(address, state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(state_path(address), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def _today():
    return time.strftime("%Y-%m-%d")


def check_write(address, payload_hash, min_interval=60, daily_cap=100):
    """Check whether a write to the device is allowed.

    Returns (allowed, reason, state).
    - Dry runs never reach here (caller must not call with dry_run=True).
    - Identical payload skipped (last_payload == payload_hash).
    - Minimum interval enforced.
    - Daily cap enforced.
    """
    state = load_state(address)
    now = time.time()
    today = _today()

    # Reset daily counter if new day
    if state.get("daily_date") != today:
        state["daily_count"] = 0
        state["daily_date"] = today

    # Skip identical payload
    if state.get("last_payload") == payload_hash:
        return False, "identical payload (skipped)", state

    # Minimum interval
    last_ts = state.get("last_write_ts", 0)
    if now - last_ts < min_interval:
        return False, "minimum interval not elapsed (%.1fs remaining)" % (
            min_interval - (now - last_ts)), state

    # Daily cap
    if state.get("daily_count", 0) >= daily_cap:
        return False, "daily write cap reached (%d/%d)" % (
            state["daily_count"], daily_cap), state

    return True, "ok", state


def record_write(address, payload_hash, success=True):
    """Record a write attempt. Only counts on success."""
    state = load_state(address)
    now = time.time()
    today = _today()

    if state.get("daily_date") != today:
        state["daily_count"] = 0
        state["daily_date"] = today

    state["last_payload"] = payload_hash
    if success:
        state["writes"] = state.get("writes", 0) + 1
        state["daily_count"] = state.get("daily_count", 0) + 1
        state["last_write_ts"] = now

    save_state(address, state)
    return state


def reset_state(address):
    path = state_path(address)
    if os.path.isfile(path):
        os.remove(path)
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Safe-write guard for device operations (Ground Rule 7)")
    parser.add_argument("--device", required=True, help="Device address (hashed internally, never stored raw)")
    parser.add_argument("--record", help="Payload hash to record after a write")
    parser.add_argument("--success", action="store_true", help="Mark the recorded write as successful (counts toward caps)")
    parser.add_argument("--check", action="store_true", help="Check whether a write is allowed (dry-run, does not count)")
    parser.add_argument("--reset", action="store_true", help="Reset the device state file")
    parser.add_argument("--payload-hash", help="Payload hash for --check (defaults to 'check')")
    parser.add_argument("--min-interval", type=int, default=60, help="Minimum seconds between writes (default: 60)")
    parser.add_argument("--daily-cap", type=int, default=100, help="Hard daily write cap (default: 100)")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    if args.reset:
        ok = reset_state(args.device)
        if args.json:
            print(json.dumps({"device": args.device, "reset": ok}))
        else:
            print("Reset %s: %s" % (args.device, ok))
        return 0

    if args.check:
        ph = args.payload_hash or "check"
        allowed, reason, state = check_write(args.device, ph, args.min_interval, args.daily_cap)
        if args.json:
            print(json.dumps({"device": args.device, "allowed": allowed, "reason": reason, "state": state}))
        else:
            print("Write %s: %s" % ("ALLOWED" if allowed else "DENIED", reason))
        return 0 if allowed else 1

    if args.record:
        state = record_write(args.device, args.record, args.success)
        if args.json:
            print(json.dumps({"device": args.device, "state": state}))
        else:
            print("Recorded write (success=%s). State: %s" % (args.success, state))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())