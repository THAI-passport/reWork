"""Minimal aarch64 unicorn harness for calling a native decryption or unpacker function in an Android malware .so.

Usage:
    python3 unicorn_aarch64_harness.py libmalware.so <func_vaddr_hex> [hex_input]
Dependencies:
    pip install unicorn pyelftools capstone
"""
import sys
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import (
    UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2
)

PAGE = 0x1000
BASE = 0x10000000           # Load base for Position Independent Code (PIC)
STACK, STACK_SIZE = 0x70000000, 0x100000
TLS = 0x71000000            # Zeroed page: stack canary checks read tpidr_el0 here
HEAP, HEAP_SIZE = 0x72000000, 0x1000000
DATA = 0x73000000           # Scratch memory for function arguments
SENTINEL = 0x7F000000       # Sentinel return address (stops emulation)

def up(x):
    return (x + PAGE - 1) & ~(PAGE - 1)

def load_elf(mu, path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            lo = (BASE + seg["p_vaddr"]) & ~(PAGE - 1)
            hi = up(BASE + seg["p_vaddr"] + seg["p_memsz"])
            mu.mem_map(lo, hi - lo)
            mu.mem_write(BASE + seg["p_vaddr"], seg.data())

class SimpleHeap:
    def __init__(self):
        self.top = HEAP

    def alloc(self, n):
        p = self.top
        self.top += ((n + 15) & ~15)
        if self.top > HEAP + HEAP_SIZE:
            raise MemoryError("Emulated heap exhausted")
        return p

def make_stubs(heap):
    def malloc(mu):
        size = mu.reg_read(UC_ARM64_REG_X0)
        mu.reg_write(UC_ARM64_REG_X0, heap.alloc(size))

    def free(mu):
        pass

    def memcpy(mu):
        d = mu.reg_read(UC_ARM64_REG_X0)
        s = mu.reg_read(UC_ARM64_REG_X1)
        n = mu.reg_read(UC_ARM64_REG_X2)
        mu.mem_write(d, bytes(mu.mem_read(s, n)))

    return {"malloc": malloc, "free": free, "memcpy": memcpy}

def emulate_function(so_path, func_offset, input_bytes=b""):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    load_elf(mu, so_path)

    # Initialize Stack, TLS, Heap, Data
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(TLS, PAGE)
    mu.mem_map(HEAP, HEAP_SIZE)
    mu.mem_map(DATA, PAGE)
    mu.mem_map(SENTINEL, PAGE)

    # Setup registers
    mu.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x1000)
    mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    mu.reg_write(UC_ARM64_REG_CPACR_EL1, mu.reg_read(UC_ARM64_REG_CPACR_EL1) | (3 << 20)) # Enable NEON/FP
    mu.reg_write(UC_ARM64_REG_LR, SENTINEL)

    # Pass argument in DATA page
    if input_bytes:
        mu.mem_write(DATA, input_bytes)
        mu.reg_write(UC_ARM64_REG_X0, DATA)
        mu.reg_write(UC_ARM64_REG_X1, len(input_bytes))

    entry_addr = BASE + func_offset
    print(f"[*] Starting emulation at 0x{entry_addr:x}...")
    try:
        mu.emu_start(entry_addr, SENTINEL, timeout=5000000)
    except Exception as e:
        print(f"[!] Emulation stopped: {e}")

    ret_val = mu.reg_read(UC_ARM64_REG_X0)
    print(f"[+] Emulation returned: x0 = 0x{ret_val:x}")
    return ret_val

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 unicorn_aarch64_harness.py <lib.so> <offset_hex> [hex_input]")
        sys.exit(1)
    so_file = sys.argv[1]
    offset = int(sys.argv[2], 16)
    inp = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b""
    emulate_function(so_file, offset, inp)
