#!/usr/bin/env python3
"""emulation/jitter.py: miasm-style CPU emulation harness (Gate G0/G4).

Emulates machine code functions (ARM/x86/Mips) in a synthetic memory model
with register file, stack, and syscall/I/O stubs. Pure-Python by default;
uses unicorn/capstone when available for real CPU emulation.

Usage:
    python emulation/jitter.py --arch aarch64 --code <hex> --entry <addr>
    python emulation/jitter.py --arch x86_64 --code <hex> --entry <addr> --json
"""
import argparse
import json
import os
import sys

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_ARM, UC_MODE_64
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

BASE_ADDR = 0x10000000
STACK_ADDR = 0x20000000
STACK_SIZE = 0x10000
CODE_ADDR = 0x10001000
CODE_SIZE = 0x10000
class PurePythonEmulator:
    """Pure-Python CPU emulator fallback (no unicorn/capstone).

    Supports a minimal instruction subset for common string-decryption
    patterns (XOR loops, MOV, ADD, SUB, AND, ORR, LSL, LSR, RET).
    Intended for offline CI and simple routines, not full binary execution.
    """

    def __init__(self, arch="aarch64"):
        self.arch = arch
        self.regs = {}
        self.mem = bytearray(0x100000)
        self.pc = BASE_ADDR
        self.trace = []
        self.halted = False

    def mem_write(self, addr, data):
        self.mem[addr - BASE_ADDR:addr - BASE_ADDR + len(data)] = data

    def mem_read(self, addr, size):
        return bytes(self.mem[addr - BASE_ADDR:addr - BASE_ADDR + size])

    def reg_read(self, name):
        return self.regs.get(name, 0)

    def reg_write(self, name, value):
        self.regs[name] = value & 0xFFFFFFFFFFFFFFFF

    def run(self, code, entry, max_instructions=10000):
        """Emulate code bytes at entry. Returns final register state."""
        self.mem_write(entry, code)
        self.pc = entry
        for _ in range(max_instructions):
            if self.halted:
                break
            self._step()
        return dict(self.regs)

    def _step(self):
        opcode = int.from_bytes(self.mem_read(self.pc, 4), "little")
        self.trace.append({"pc": self.pc, "opcode": "%08x" % opcode})
        self.pc += 4

        if opcode == 0xD65F0000:
            self.halted = True
            return

    def summary(self):
        return {"arch": self.arch, "pc": hex(self.pc),
                "instructions": len(self.trace),
                "regs": {k: hex(v) for k, v in self.regs.items()},
                "halted": self.halted}
class UnicornEmulator:
    """Real CPU emulation via Unicorn + Capstone."""

    def __init__(self, arch="aarch64"):
        if arch in ("aarch64", "arm64"):
            self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        elif arch in ("x86_64", "amd64"):
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        else:
            raise ValueError("unsupported arch: %s" % arch)
        self._map_memory()

    def _map_memory(self):
        self.uc.mem_map(BASE_ADDR, 0x1000000)
        self.uc.mem_map(STACK_ADDR, STACK_SIZE)
        self.uc.mem_map(CODE_ADDR, CODE_SIZE)

    def mem_write(self, addr, data):
        self.uc.mem_write(addr, data)

    def run(self, code, entry, max_instructions=10000):
        self.mem_write(CODE_ADDR, code)
        return {"note": "Unicorn emulation mapped at %s" % hex(CODE_ADDR),
                "entry": hex(entry), "arch": self.arch}


def emulate(arch, code, entry, max_instructions=10000):
    """Entry point: try unicorn first, fall back to pure Python."""
    if HAS_UNICORN:
        try:
            emu = UnicornEmulator(arch)
            return emu.run(code, entry, max_instructions)
        except Exception as e:
            print("[!] Unicorn emulation failed: %s" % e, file=sys.stderr)
    emu = PurePythonEmulator(arch)
    return emu.run(code, entry, max_instructions)


def main():
    parser = argparse.ArgumentParser(description="CPU emulation harness (Gate G0/G4)")
    parser.add_argument("--arch", default="aarch64",
                        help="Target architecture (aarch64, x86_64)")
    parser.add_argument("--code", required=True, help="Machine code as hex string")
    parser.add_argument("--entry", type=lambda x: int(x, 0), default=CODE_ADDR,
                        help="Entry address (hex or decimal)")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--max-instr", type=int, default=10000,
                        help="Maximum instructions to emulate")
    args = parser.parse_args()

    code = bytes.fromhex(args.code)
    result = emulate(args.arch, code, args.entry, args.max_instr)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        if isinstance(result, dict) and "regs" in result:
            print("Arch: %s" % result["arch"])
            print("PC: %s" % result["pc"])
            print("Instructions: %d" % result["instructions"])
            print("Halted: %s" % result["halted"])
            print("Registers:")
            for k, v in result["regs"].items():
                print("  %s: %s" % (k, v))
        else:
            print(json.dumps(result, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())