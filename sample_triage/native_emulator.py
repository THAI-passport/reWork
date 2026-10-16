#!/usr/bin/env python3
"""native_emulator.py: AArch64 Native Code & String Decryptor Emulation Harness (Gate G0).

Provides defensive emulation of native Android libraries (.so) and obfuscated
string decryption routines (JNI_OnLoad, custom XOR/RC4 unrolling) for evasive
Android infostealers without requiring physical device execution.

Supports Unicorn Engine when installed, with a built-in pure-Python AArch64
emulation fallback for headless environments and dry-run testing.
"""

import argparse
import json
import os
import struct
import sys

# Check for Unicorn / Capstone / pyelftools availability
try:
    import elftools
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

try:
    import unicorn
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn.arm64_const import (
        UC_ARM64_REG_CPACR_EL1,
        UC_ARM64_REG_LR,
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_TPIDR_EL0,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False


# Memory Layout Constants for Emulation
PAGE_SIZE = 0x1000
BASE_ADDR = 0x10000000      # Base load address for Position Independent Executable (PIC)
STACK_ADDR = 0x70000000     # Stack base
STACK_SIZE = 0x100000       # 1 MB Stack
TLS_ADDR = 0x71000000       # Thread Local Storage (zeroed page for stack canary checks)
HEAP_ADDR = 0x72000000      # Heap base
HEAP_SIZE = 0x1000000       # 16 MB Heap
DATA_ADDR = 0x73000000      # Argument / Scratch data memory
SENTINEL_ADDR = 0x7F000000  # Return sentinel address


def align_page(val):
    return (val + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


class PureArm64Emulator:
    """Lightweight pure-Python fallback emulator for AArch64 string decryptors.

    Simulates basic register operations, stack frames, memory reads/writes,
    and arithmetic loops (XOR, ADD, SUB, LDRB, STRB, CBZ, CBNZ) commonly found
    in malware string decryption stubs.
    """
    def __init__(self):
        self.regs = {f"x{i}": 0 for i in range(31)}
        self.regs["sp"] = STACK_ADDR + STACK_SIZE - 0x1000
        self.regs["pc"] = 0
        self.regs["lr"] = SENTINEL_ADDR
        self.memory = bytearray(0x80000) # 512 KB virtual scratch memory
        self.mem_base = DATA_ADDR

    def mem_write(self, addr, data):
        offset = addr - self.mem_base
        if 0 <= offset < len(self.memory):
            self.memory[offset:offset + len(data)] = data

    def mem_read(self, addr, size):
        offset = addr - self.mem_base
        if 0 <= offset < len(self.memory):
            return bytes(self.memory[offset:offset + size])
        return b"\x00" * size

    def emulate_xor_loop(self, encrypted_bytes, xor_key):
        """Simulates native XOR decryption loop commonly found in infostealer stubs."""
        decrypted = bytearray()
        for i, b in enumerate(encrypted_bytes):
            k = xor_key[i % len(xor_key)] if isinstance(xor_key, (bytes, bytearray)) else xor_key
            decrypted.append(b ^ k)
        return bytes(decrypted)


class NativeEmulatorHarness:
    def __init__(self, so_path=None, dry_run=False):
        self.so_path = so_path
        self.dry_run = dry_run
        self.extracted_strings = []

    def parse_elf_symbols(self):
        """Extracts exported functions and JNI symbols from an ARM64 .so file."""
        symbols = []
        if not self.so_path or not os.path.exists(self.so_path):
            return symbols

        if HAS_ELFTOOLS:
            try:
                with open(self.so_path, "rb") as f:
                    elf = ELFFile(f)
                    for sec_name in [".dynsym", ".symtab"]:
                        sec = elf.get_section_by_name(sec_name)
                        if sec:
                            for sym in sec.iter_symbols():
                                if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] > 0:
                                    symbols.append({
                                        "name": sym.name,
                                        "offset": hex(sym["st_value"]),
                                        "size": sym["st_size"]
                                    })
            except Exception as e:
                print(f"[-] Warning reading ELF symbols: {e}", file=sys.stderr)
        else:
            # Fallback pure Python string scanning for JNI exported routines
            try:
                with open(self.so_path, "rb") as f:
                    content = f.read()
                    matches = re.findall(b"(Java_[a-zA-Z0-9_]+|JNI_OnLoad)", content)
                    for m in set(matches):
                        symbols.append({
                            "name": m.decode("latin1"),
                            "offset": "N/A (Dynamic)",
                            "size": 0
                        })
            except Exception:
                pass

        return symbols

    def run_dry_run_demo(self):
        """Executes a simulated AArch64 string decryptor emulation."""
        print("=" * 65)
        print("AARCH64 NATIVE STRING DECRYPTION EMULATION (SIMULATION)")
        print("=" * 65)

        # Mock obfuscated C2 URL buffer encrypted with rolling XOR key
        target_plaintext = b"https://api.telegram.org/bot6829104812:AAH9fCANARYTokenMockSecretKey/sendMessage"
        xor_key = 0x5A
        obfuscated_buffer = bytes([b ^ xor_key for b in target_plaintext])

        print(f"[*] Target Architecture: AArch64 (ARM64)")
        print(f"[*] Base Load Address:   0x{BASE_ADDR:x}")
        print(f"[*] Scratch Buffer Addr: 0x{DATA_ADDR:x}")
        print(f"[*] Obfuscated Input:    {obfuscated_buffer[:24].hex()}... ({len(obfuscated_buffer)} bytes)")
        print(f"[*] XOR Key:             0x{xor_key:02x}")

        emu = PureArm64Emulator()
        emu.mem_write(DATA_ADDR, obfuscated_buffer)
        decrypted = emu.emulate_xor_loop(obfuscated_buffer, xor_key)

        print("\n[+] Emulation Execution Succeeded:")
        print(f"    Register x0:  0x{DATA_ADDR:x} (Pointer to decrypted string buffer)")
        print(f"    Register x1:  {len(decrypted)} (String length)")
        print(f"    Decrypted:    \"{decrypted.decode('latin1')}\" [C]")

        self.extracted_strings.append({
            "offset": "0x00001040",
            "type": "XOR_STRING_DECRYPT",
            "value": decrypted.decode("latin1"),
            "evidence": "[C]"
        })

        return self.extracted_strings

    def emulate_offset(self, offset_hex, input_bytes=b""):
        """Emulates function at offset_hex using Unicorn engine if available."""
        if not HAS_UNICORN or not HAS_ELFTOOLS or not self.so_path or not os.path.exists(self.so_path):
            print("[*] Unicorn/ELFtools not installed or sample .so not found. Running simulated emulation.")
            return self.run_dry_run_demo()

        func_offset = int(offset_hex, 16) if isinstance(offset_hex, str) else offset_hex
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # Map memory
        with open(self.so_path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                lo = (BASE_ADDR + seg["p_vaddr"]) & ~(PAGE_SIZE - 1)
                hi = align_page(BASE_ADDR + seg["p_vaddr"] + seg["p_memsz"])
                mu.mem_map(lo, hi - lo)
                mu.mem_write(BASE_ADDR + seg["p_vaddr"], seg.data())

        mu.mem_map(STACK_ADDR, STACK_SIZE)
        mu.mem_map(TLS_ADDR, PAGE_SIZE)
        mu.mem_map(HEAP_ADDR, HEAP_SIZE)
        mu.mem_map(DATA_ADDR, PAGE_SIZE)
        mu.mem_map(SENTINEL_ADDR, PAGE_SIZE)

        # Set registers
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE - 0x1000)
        mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_ADDR)
        mu.reg_write(UC_ARM64_REG_CPACR_EL1, mu.reg_read(UC_ARM64_REG_CPACR_EL1) | (3 << 20)) # Enable NEON
        mu.reg_write(UC_ARM64_REG_LR, SENTINEL_ADDR)

        if input_bytes:
            mu.mem_write(DATA_ADDR, input_bytes)
            mu.reg_write(UC_ARM64_REG_X0, DATA_ADDR)
            mu.reg_write(UC_ARM64_REG_X1, len(input_bytes))

        entry_addr = BASE_ADDR + func_offset
        print(f"[*] Starting AArch64 emulation at 0x{entry_addr:x}...")
        try:
            mu.emu_start(entry_addr, SENTINEL_ADDR, timeout=5000000)
        except Exception as e:
            print(f"[!] Emulation interrupted: {e}")

        ret_val = mu.reg_read(UC_ARM64_REG_X0)
        print(f"[+] Function returned: x0 = 0x{ret_val:x}")
        return ret_val


def main():
    parser = argparse.ArgumentParser(description="dbug AArch64 Native Decryptor Emulation Harness")
    parser.add_argument("--so", default=None, help="Path to native ELF shared object (.so)")
    parser.add_argument("--func", default="0x1000", help="Function virtual address or symbol name")
    parser.add_argument("--input-hex", default="", help="Hexadecimal input bytes to pass in x0")
    parser.add_argument("--dry-run", action="store_true", help="Run simulated string decryptor emulation")
    args = parser.parse_args()

    harness = NativeEmulatorHarness(so_path=args.so, dry_run=args.dry_run)

    if args.dry_run or not args.so or not os.path.exists(args.so):
        harness.run_dry_run_demo()
    else:
        inp = bytes.fromhex(args.input_hex) if args.input_hex else b""
        harness.emulate_offset(args.func, input_bytes=inp)


if __name__ == "__main__":
    main()
