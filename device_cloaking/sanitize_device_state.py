#!/usr/bin/env python3
"""device_cloaking/sanitize_device_state.py: Shim pointing to root sanitize_device_state.py."""
import os
import sys

# Ensure repository root is on sys.path
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from sanitize_device_state import DeviceSanitizer, parse_lab_config, main

if __name__ == "__main__":
    main()
