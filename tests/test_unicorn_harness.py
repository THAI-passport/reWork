"""Smoke test for the re-native-emulation harness on a hand-built synthetic ELF (no vendor code)."""
import importlib.util
import os
import struct
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, ".claude", "skills", "re-native-emulation", "scripts", "unicorn_aarch64_harness.py")

# stp x29,x30,[sp,-16]!; mrs x9,tpidr_el0; ldr x10,[x9]; fmov d0,x0; fmov x0,d0;
# bl 0x20; ldp x29,x30,[sp],16; ret; 0x20: nop (hooked as malloc); ret
CODE = struct.pack("<10I", 0xA9BF7BFD, 0xD53BD049, 0xF940012A, 0x9E670000, 0x9E660000,
                   0x94000003, 0xA8C17BFD, 0xD65F03C0, 0xD503201F, 0xD65F03C0)


def tiny_elf(code):
    off = 64 + 56
    eh = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    eh += struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, off, 0, 0, len(code), len(code), 0x1000)
    return eh + ph + code


def load_harness():
    spec = importlib.util.spec_from_file_location("harness", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Harness(unittest.TestCase):
    def test_plt_hook_tls_and_simd(self):
        try:
            import unicorn  # noqa: F401
            import elftools  # noqa: F401
        except ImportError:
            self.skipTest("unicorn or pyelftools not installed")
        h = load_harness()
        h.PLT_HOOKS[0x20] = "malloc"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "synthetic.so")
            open(p, "wb").write(tiny_elf(CODE))
            mu = h.setup(p)
            self.assertEqual(h.call(mu, 0, 40), h.HEAP)       # malloc hook ran and returned via LR
            self.assertEqual(h.call(mu, 0, 8), h.HEAP + 48)   # bump allocator, 16-byte aligned


if __name__ == "__main__":
    unittest.main()
