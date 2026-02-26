#!/usr/bin/env python3
"""
pe_protect.py - Post-build PE protection for AiDA.dll

This script performs binary-level transformations on the compiled DLL to make
static analysis in IDA Pro, Ghidra, and Binary Ninja extremely difficult:

1. Strips all non-essential exports (keeps only PLUGIN)
2. Zeroes out debug directory entries
3. Wipes Rich header signature
4. Randomizes section names
5. Removes or corrupts non-essential data directories
6. Adds junk overlay data to confuse file-size heuristics
7. Patches the DOS stub with garbage

Usage:
    python pe_protect.py <input.dll> [output.dll]

If output is omitted, the input file is modified in-place.
"""

import struct
import sys
import os
import random
import hashlib
import time


def read_u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def read_u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def write_u16(data, offset, value):
    struct.pack_into('<H', data, offset, value & 0xFFFF)


def write_u32(data, offset, value):
    struct.pack_into('<I', data, offset, value & 0xFFFFFFFF)


def write_u64(data, offset, value):
    struct.pack_into('<Q', data, offset, value & 0xFFFFFFFFFFFFFFFF)


def rva_to_offset(data, pe_offset, rva):
    """Convert an RVA to a file offset using section headers."""
    num_sections = read_u16(data, pe_offset + 6)
    opt_hdr_size = read_u16(data, pe_offset + 20)
    section_start = pe_offset + 24 + opt_hdr_size

    for i in range(num_sections):
        sec_off = section_start + i * 40
        virt_size = read_u32(data, sec_off + 8)
        virt_addr = read_u32(data, sec_off + 12)
        raw_size = read_u32(data, sec_off + 16)
        raw_ptr = read_u32(data, sec_off + 20)

        if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
            return raw_ptr + (rva - virt_addr)

    return None


def wipe_rich_header(data, pe_offset):
    """Wipe the Rich header between DOS header and PE signature."""
    dos_end = 0x40
    region = data[dos_end:pe_offset]

    rich_sig = b'Rich'
    rich_pos = region.find(rich_sig)
    if rich_pos >= 0:
        for i in range(dos_end, pe_offset):
            data[i] = 0x00
        print(f"  [+] Wiped Rich header ({pe_offset - dos_end} bytes)")
    else:
        for i in range(dos_end, pe_offset):
            data[i] = 0x00
        print(f"  [+] Wiped DOS stub area ({pe_offset - dos_end} bytes)")


def wipe_debug_directory(data, pe_offset):
    """Zero out the debug data directory entry and its contents."""
    magic = read_u16(data, pe_offset + 24)
    if magic == 0x20B: 
        dd_offset = pe_offset + 24 + 144 
    else: 
        dd_offset = pe_offset + 24 + 128

    debug_rva = read_u32(data, dd_offset)
    debug_size = read_u32(data, dd_offset + 4)

    if debug_rva != 0 and debug_size != 0:
        file_off = rva_to_offset(data, pe_offset, debug_rva)
        if file_off is not None:
            for i in range(debug_size):
                if file_off + i < len(data):
                    data[file_off + i] = 0x00
            print(f"  [+] Wiped debug directory contents ({debug_size} bytes at RVA 0x{debug_rva:X})")

        write_u32(data, dd_offset, 0)
        write_u32(data, dd_offset + 4, 0)
        print("  [+] Zeroed debug data directory entry")
    else:
        print("  [*] No debug directory found")


def randomize_section_names(data, pe_offset):
    """Replace section names with random garbage to confuse disassemblers."""
    num_sections = read_u16(data, pe_offset + 6)
    opt_hdr_size = read_u16(data, pe_offset + 20)
    section_start = pe_offset + 24 + opt_hdr_size

    rng = random.Random(int(time.time()))

    for i in range(num_sections):
        sec_off = section_start + i * 40
        old_name = data[sec_off:sec_off + 8]

        chars = b'.abcdefghijklmnopqrstuvwxyz0123456789_'
        new_name = bytearray(8)
        new_name[0] = ord('.')
        for j in range(1, 8):
            new_name[j] = chars[rng.randint(0, len(chars) - 1)]

        data[sec_off:sec_off + 8] = new_name
        print(f"  [+] Section {i}: {old_name.rstrip(b'\\x00').decode('ascii', errors='replace')} -> {new_name.decode('ascii', errors='replace')}")


def wipe_export_function_names(data, pe_offset):
    """
    Wipe all export names except 'PLUGIN' to minimize visible symbols.
    The PLUGIN export is required by IDA's plugin loader.
    """
    magic = read_u16(data, pe_offset + 24)
    if magic == 0x20B:
        export_dd_offset = pe_offset + 24 + 112
    else:
        export_dd_offset = pe_offset + 24 + 96

    export_rva = read_u32(data, export_dd_offset)
    export_size = read_u32(data, export_dd_offset + 4)

    if export_rva == 0 or export_size == 0:
        print("  [*] No export directory found")
        return

    export_file_off = rva_to_offset(data, pe_offset, export_rva)
    if export_file_off is None:
        print("  [!] Could not resolve export directory RVA")
        return

    num_names = read_u32(data, export_file_off + 24)
    names_rva = read_u32(data, export_file_off + 32)

    if num_names == 0 or names_rva == 0:
        print("  [*] No named exports")
        return

    names_file_off = rva_to_offset(data, pe_offset, names_rva)
    if names_file_off is None:
        return

    kept = 0
    wiped = 0
    for i in range(num_names):
        name_ptr_off = names_file_off + i * 4
        name_rva = read_u32(data, name_ptr_off)
        name_file_off = rva_to_offset(data, pe_offset, name_rva)
        if name_file_off is None:
            continue

        name_end = name_file_off
        while name_end < len(data) and data[name_end] != 0:
            name_end += 1
        export_name = data[name_file_off:name_end].decode('ascii', errors='replace')

        if export_name == 'PLUGIN':
            kept += 1
            continue

        for j in range(name_file_off, min(name_end + 1, len(data))):
            data[j] = 0x00
        wiped += 1

    print(f"  [+] Export names: kept {kept}, wiped {wiped}")


def wipe_non_essential_directories(data, pe_offset):
    """Zero out data directory entries that aren't needed at runtime."""
    magic = read_u16(data, pe_offset + 24)
    if magic == 0x20B:
        dd_base = pe_offset + 24 + 112
    else:
        dd_base = pe_offset + 24 + 96

    num_dirs = read_u32(data, pe_offset + 24 + (116 if magic == 0x20B else 100))

    wipe_indices = [7, 8, 11, 14]

    for idx in wipe_indices:
        if idx < num_dirs:
            entry_off = dd_base + idx * 8
            old_rva = read_u32(data, entry_off)
            if old_rva != 0:
                write_u32(data, entry_off, 0)
                write_u32(data, entry_off + 4, 0)
                print(f"  [+] Wiped data directory [{idx}] (was RVA 0x{old_rva:X})")


def add_junk_overlay(data):
    """Append random junk data as an overlay to confuse file-size analysis."""
    rng = random.Random(int(time.time()) ^ 0xA1DA)
    junk_size = rng.randint(4096, 16384)
    junk = bytearray(rng.getrandbits(8) for _ in range(junk_size))

    fake_sigs = [
        b'\x50\x4B\x03\x04',  # ZIP
        b'\x7F\x45\x4C\x46',  # ELF
        b'\xCA\xFE\xBA\xBE',  # Java class / Mach-O fat
        b'\xCE\xFA\xED\xFE',  # Mach-O
    ]
    for sig in fake_sigs:
        pos = rng.randint(0, junk_size - len(sig))
        junk[pos:pos + len(sig)] = sig

    data.extend(junk)
    print(f"  [+] Added {junk_size} bytes of junk overlay")


def patch_checksum(data, pe_offset):
    """Recalculate and patch the PE checksum."""
    magic = read_u16(data, pe_offset + 24)
    if magic == 0x20B:
        checksum_off = pe_offset + 24 + 64
    else:
        checksum_off = pe_offset + 24 + 64

    write_u32(data, checksum_off, 0)

    checksum = 0
    remainder = len(data) % 4
    for i in range(0, len(data) - remainder, 4):
        if i == checksum_off:
            continue
        val = struct.unpack_from('<I', data, i)[0]
        checksum += val
        checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

    if remainder > 0:
        pad = data[-remainder:] + b'\x00' * (4 - remainder)
        val = struct.unpack_from('<I', bytes(pad), 0)[0]
        checksum += val
        checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += len(data)
    checksum &= 0xFFFFFFFF

    write_u32(data, checksum_off, checksum)
    print(f"  [+] Patched PE checksum: 0x{checksum:08X}")


def protect_pe(input_path, output_path):
    """Apply all PE protection transformations."""
    print(f"[*] Loading: {input_path}")

    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    if len(data) < 64:
        print("[!] File too small to be a valid PE")
        return False

    if data[0:2] != b'MZ':
        print("[!] Not a valid PE file (missing MZ signature)")
        return False

    pe_offset = read_u32(data, 0x3C)
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        print("[!] Not a valid PE file (missing PE signature)")
        return False

    print(f"[*] PE header at offset 0x{pe_offset:X}")
    print(f"[*] File size: {len(data)} bytes")
    print()

    print("[*] Phase 1: Wiping Rich header and DOS stub...")
    wipe_rich_header(data, pe_offset)

    print("[*] Phase 2: Wiping debug directory...")
    wipe_debug_directory(data, pe_offset)

    print("[*] Phase 3: Randomizing section names...")
    randomize_section_names(data, pe_offset)

    print("[*] Phase 4: Wiping non-essential export names...")
    wipe_export_function_names(data, pe_offset)

    print("[*] Phase 5: Wiping non-essential data directories...")
    wipe_non_essential_directories(data, pe_offset)

    print("[*] Phase 6: Adding junk overlay...")
    add_junk_overlay(data)

    print("[*] Phase 7: Patching PE checksum...")
    patch_checksum(data, pe_offset)

    print()
    print(f"[*] Writing protected PE: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(data)

    final_size = os.path.getsize(output_path)
    print(f"[*] Final size: {final_size} bytes")
    print("[*] Protection complete!")
    return True


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.dll> [output.dll]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path

    if not os.path.isfile(input_path):
        print(f"[!] Input file not found: {input_path}")
        sys.exit(1)

    success = protect_pe(input_path, output_path)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
