"""Minimal aarch64 unicorn harness for calling one function in a native .so.

Template, not a finished tool: copy it to client/<slug>/tools/emulate_<lib>.py
and fill PLT_HOOKS and the call at the bottom. Never commit the .so itself.
Needs: pip install unicorn pyelftools (capstone only if you disassemble).

    python emulate.py lib.so <func_vaddr_hex> [hex_input]
"""
import sys

from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm64_const import (UC_ARM64_REG_CPACR_EL1, UC_ARM64_REG_LR, UC_ARM64_REG_PC,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_X0,
                                 UC_ARM64_REG_X1, UC_ARM64_REG_X2)

PAGE = 0x1000
BASE = 0x10000000           # load base for a PIC library
STACK, STACK_SIZE = 0x70000000, 0x100000
TLS = 0x71000000            # zeroed page: tpidr_el0 canary reads land here
HEAP, HEAP_SIZE = 0x72000000, 0x1000000
DATA = 0x73000000           # scratch for arguments
SENTINEL = 0x7F000000       # return address; emulation stops here


def up(x):
    return (x + PAGE - 1) & ~(PAGE - 1)


def load(mu, path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            lo = (BASE + seg["p_vaddr"]) & ~(PAGE - 1)
            hi = up(BASE + seg["p_vaddr"] + seg["p_memsz"])
            mu.mem_map(lo, hi - lo)  # PT_LOADs must not share a page; adjust if they do
            mu.mem_write(BASE + seg["p_vaddr"], seg.data())
    # Relocations (R_AARCH64_RELATIVE in .rela.dyn) are not applied here; add
    # them if the function reads pointers from .data or .got.


class Heap:
    def __init__(self):
        self.top = HEAP

    def alloc(self, n):
        p, self.top = self.top, self.top + ((n + 15) & ~15)
        if self.top > HEAP + HEAP_SIZE:
            raise MemoryError("bump heap exhausted")
        return p


def make_hooks(heap):
    def malloc(mu):
        mu.reg_write(UC_ARM64_REG_X0, heap.alloc(mu.reg_read(UC_ARM64_REG_X0)))

    def free(mu):
        pass

    def memcpy(mu):
        d, s, n = (mu.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2))
        mu.mem_write(d, bytes(mu.mem_read(s, n)))  # x0 already holds dst, the return value

    return {"malloc": malloc, "free": free, "memcpy": memcpy}


# PLT stub address (vaddr, without BASE) -> import name. Recover from .rela.plt order.
PLT_HOOKS = {}


def install(mu, hooks):
    by_addr = {BASE + a: hooks[n] for a, n in PLT_HOOKS.items()}

    def on_code(mu, addr, size, _):
        fn = by_addr.get(addr)
        if fn:
            fn(mu)
            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))  # LR, never LR-4
    mu.hook_add(UC_HOOK_CODE, on_code)


def setup(path):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    load(mu, path)
    for a, n in ((STACK, STACK_SIZE), (TLS, PAGE), (HEAP, HEAP_SIZE), (DATA, PAGE), (SENTINEL, PAGE)):
        mu.mem_map(a, n)
    mu.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x100)
    mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    mu.reg_write(UC_ARM64_REG_CPACR_EL1, mu.reg_read(UC_ARM64_REG_CPACR_EL1) | (3 << 20))  # FP/SIMD on
    install(mu, make_hooks(Heap()))
    return mu


def call(mu, func_vaddr, *args):
    """AAPCS64: up to 8 integer/pointer args in x0..x7, result in x0."""
    for i, v in enumerate(args):
        mu.reg_write(UC_ARM64_REG_X0 + i, v)
    mu.reg_write(UC_ARM64_REG_LR, SENTINEL)
    mu.emu_start(BASE + func_vaddr, SENTINEL)
    return mu.reg_read(UC_ARM64_REG_X0)


if __name__ == "__main__":
    lib, func = sys.argv[1], int(sys.argv[2], 16)
    data = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b""
    mu = setup(lib)
    mu.mem_write(DATA, data)
    print("x0=0x%x" % call(mu, func, DATA, len(data)))
    print("buf=%s" % bytes(mu.mem_read(DATA, max(len(data), 16))).hex())
