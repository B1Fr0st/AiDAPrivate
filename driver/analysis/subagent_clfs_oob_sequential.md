# CLFS.SYS OOB Write Analysis: CClfsBaseFilePersisted::AddContainer

## Target
- **Binary**: clfs.sys (Windows CLFS driver)
- **Function**: `CClfsBaseFilePersisted::AddContainer` at RVA 0x2B888 (VA 0x1C002B888)
- **IDA Instance**: pid 16896, port 13346
- **Goal**: Find OOB write vector past metadata buffer into adjacent pool memory

---

## 1. OffsetToAddr (RVA 0x35DF8) - Bounds Check Analysis

### Decompiled (from disassembly):
```asm
OffsetToAddr(CClfsBaseFile *this, unsigned int offset):
    rax = [rcx+30h]            ; m_rgBlocks (block descriptor array)
    r11d = offset              ; the offset parameter
    r10 = [rax+30h]            ; m_rgBlocks[2].buffer_ptr (block 2 = base record)
    call GetBaseLogRecord      ; r9 = base_log_record = buffer + block_base_offset
    
    v7 = ULongAdd(offset, [r10+28h])     ; offset + block_base_offset
    if overflow: return NULL
    
    eax = (WORD)[r10+4]        ; cSectors (16-bit from block header)
    eax <<= 9                  ; cSectors * 512
    if v7 >= eax: return NULL  ; CHECK: offset + base < cSectors * 512  (STRICT LESS THAN)
    
    return r9 + r11            ; base_log_record + offset
```

### Key Structure Offsets:
- `this->[30h]` = m_rgBlocks (array of 24-byte block descriptors)
- `m_rgBlocks[2]` = descriptor for block type 2 (base record block)
- `m_rgBlocks[2].buffer_ptr` (offset +0x00) = metadata buffer start
- `m_rgBlocks[2].size` (offset +0x08) = buffer size in bytes
- Block header at buffer+0:
  - `[buffer+4]` = cSectors (16-bit) - **used by OffsetToAddr bounds check**
  - `[buffer+0x28]` = block_base_offset (32-bit) - offset to base record within buffer
  - `[buffer+0x68]` = valid_data_size (32-bit) - **used by AllocSymbol bounds check**

### Critical Finding: START-ONLY Check
OffsetToAddr checks `offset + block_base_offset < cSectors * 512` using **strict less than (`<`)**, validating ONLY the START address of the data. It does NOT check that `offset + block_base_offset + write_size <= cSectors * 512`. A write of N bytes starting at the validated address can extend past the buffer.

---

## 2. AddContainer (RVA 0x2B888) - Write Operations

### Normal Flow (AddSymbol succeeds):
```
1. AddSymbol(name, hash_table, 0x30, &sym, &offset) -> returns CLFSHASHSYM
2. v14 = OffsetToAddr(this, offset)           -> CLFSHASHSYM pointer
3. StartingIndex = RtlFindClearBits(bitmap)    -> container slot index
4. v18 = OffsetToAddr(this, v14->[0x24])       -> container context pointer (cbDataOffset)
5. BaseLogRecord[0x328 + StartingIndex*4] = v14->[0x24]  -> write container offset to rgContainers
6. Write 0x30 bytes to v18:                    -> write container context
     v18[0]  = 0xC1FDF008  (signature, DWORD)
     v18[4]  = 0x30        (size, DWORD)
     v18[8]  = container_size (QWORD)
     v18[16] = StartingIndex (DWORD)
     v18[20] = -1          (DWORD)
     v18[24] = 0           (QWORD)
     v18[36] = 1           (QWORD)
     v18[44] = 0           (DWORD)
7. FlushImage()
8. CreateContainer()
9. AcquireContainerContext(StartingIndex) -> GetSymbol (validates +47)
10. Update context fields
```

### Write Region: v18 to v18+0x2F (48 bytes, 0x30)
The last write is `*(DWORD*)(v18 + 44) = 0`, ending at v18 + 48 = v18 + 0x30.

### STATUS_FILE_CORRUPT Path (0xC00000BD):
When AddSymbol returns 0xC00000BD, AddContainer uses an EXISTING symbol's cbDataOffset:
```asm
mov edx, [rsp+var_48]      ; offset from AddSymbol
call OffsetToAddr           ; get existing CLFSHASHSYM
mov edx, [rax+24h]          ; cbDataOffset from existing entry
call OffsetToAddr           ; get container context
mov eax, [rax+10h]          ; read StartingIndex (READ, not WRITE)
```
This path only READS from the container context, no write.

---

## 3. ClfsDecodeBlockPrivate (RVA 0x6750) - Sector Validation

```c
ClfsDecodeBlockPrivate(block_header, numSectors, flag, alignment, out):
    if (!numSectors) return error
    if (block_header[0] != 0x15 || block_header[1] != 0) return error
    if (numSectors < *(WORD*)(block_header + 4))  // numSectors < cSectors
        return error
    // ... sector flag validation, sector array decoding ...
```

**Key check**: `numSectors >= cSectors`. The buffer is allocated as `numSectors * 512` bytes, and `cSectors <= numSectors`, so `cSectors * 512 <= buffer_size`. This prevents cSectors from exceeding the buffer size during initial load.

---

## 4. AllocSymbol (VTable[3], RVA 0x43090) - Space Allocation

```c
AllocSymbol(this, size, out_ptr):
    BaseLogRecord = GetBaseLogRecord(this)
    v8 = m_rgBlocks[2].buffer_ptr           // buffer start
    v9 = BaseLogRecord->[0x1328]            // free_pool_offset
    
    // CHECK: allocation fits within valid_data_size
    if (BaseLogRecord + v9 + size + 0x1338 > v8 + *(DWORD*)(v8 + 0x68))
        //            ^free_pool   ^size    ^0x1338    ^valid_data_size
        return STATUS_BUFFER_TOO_SMALL
    
    ptr = BaseLogRecord + v9 + 0x1338
    memset(ptr, 0, size)
    BaseLogRecord->[0x1328] += size         // advance free pool
    *out_ptr = ptr
    return 0
```

**AllocSymbol checks against `valid_data_size` (block_header + 0x68), NOT `cSectors * 512`.**

---

## 5. Validation Functions

### ValidateCheckifWithinSymbolZone (RVA 0x7D34):
```c
ValidateCheckifWithinSymbolZone(this, offset, base_record):
    if (offset < 0x1338 || (offset - 0x1338) > base_record->[0x1328])
    //                    ^ free_pool_offset
        return error
    return 0
```
**Uses `<=` (allows equality)**: `offset <= free_pool_offset + 0x1338`

### ValidateOffsets (RVA 0x8294):
```c
v9 = *(DWORD*)(buffer + 0x68)           // valid_data_size
if (v9 > cSectors * 512) fail           // valid_data_size <= cSectors * 512

v10 = base_record + base_record->[0x1328] + 0x1338
if (v10 > buffer + v9) fail             // free_pool_end <= valid_data_size
```

### ValidateContainerContextOffsets (RVA 0x7FBC):
```c
for each rgContainers[i] != 0:
    v9 = rgContainers[i]                // cbDataOffset
    ValidateCheckifWithinSymbolZone(v9 + 47, base_record)  // CHECK end of 0x30-byte context
    ValidateCheckifWithinSymbolZone(v9 - 48, base_record)  // CHECK start of CLFSHASHSYM header
    // ... signature, size, index checks ...
```

### ValidateProcessQNode (RVA 0x85A0) - Hash Table Validation:
```c
v7 = node->offset                       // CLFSHASHSYM entry offset
ValidateCheckifWithinSymbolZone(v7, base_record)          // entry start in zone
v14 = 48                                 // container header size
ValidateCheckifWithinSymbolZone(v7 + v14 + 47, base_record) // entry END in zone
// = v7 + 95 <= free_pool_offset + 0x1338
```

---

## 6. ExtendMetadataBlock (RVA 0x51E8C) / ExtendMetadataBlockDescriptor (RVA 0x524E4)

### ExtendMetadataBlockDescriptor:
1. Allocates new buffer: `operator new(v11, PagedPoolCacheAligned)` where v11 = aligned total size
2. Copies old data: `memmove(new_buf, old_buf, old_size)`
3. Zeros new space: `memset(new_buf + old_size, 0, v11 - old_size)`
4. Updates cSectors: `*(WORD*)(new_buf + 4) = total_sectors`
5. Calls `ClfsStampLogBlock(new_buf, v11 - sector_array_size, alignment, NULL)`
6. Updates block descriptor: `descriptor.size = v11; descriptor.ptr = new_buf`

### ClfsStampLogBlock (RVA 0x871C):
```c
ClfsStampLogBlock(header, data_size, alignment, record):
    v7 = aligned_total_size
    *(WORD*)(header + 4) = v7 >> 9      // cSectors UPDATED
    *(WORD*)(header + 6) = v7 >> 9      // shadow cSectors UPDATED
    *(DWORD*)(header + 0x68) = v7 - sector_array_overhead  // valid_data_size UPDATED
```

**After extension, cSectors and valid_data_size are both updated to match the new buffer. No persistent mismatch.**

---

## 7. OOB Write Vector Analysis

### 7.1 OffsetToAddr Start-Only Check (THEORETICAL 47-BYTE OOB)

```
OffsetToAddr check:  cbDataOffset + block_base_offset < cSectors * 512
Maximum cbDataOffset: cSectors * 512 - block_base_offset - 1
Write start in buffer: block_base_offset + cbDataOffset = cSectors * 512 - 1 (last byte)
Write end in buffer:   cSectors * 512 - 1 + 0x30 = cSectors * 512 + 0x2F
OOB: 48 bytes (0x30) past buffer
```

**BUT**: Validation (ValidateProcessQNode) checks `cbDataOffset + 47 <= free_pool_offset + 0x1338 <= valid_data_size - block_base_offset <= cSectors * 512 - block_base_offset`. This limits cbDataOffset to `cSectors * 512 - block_base_offset - 47`, preventing the full 47-byte OOB.

### 7.2 Validation Off-By-One (CONFIRMED 1-BYTE OOB)

```
Validation check (ValidateCheckifWithinSymbolZone):
    cbDataOffset + 47 <= free_pool_offset + 0x1338    (uses <=)
    
With valid_data_size = cSectors * 512 (maximum, allowed by ValidateOffsets):
    free_pool_offset + 0x1338 <= cSectors * 512 - block_base_offset
    
Maximum cbDataOffset = cSectors * 512 - block_base_offset - 47

Write last byte at: block_base_offset + cbDataOffset + 47 = cSectors * 512
Buffer last byte at: cSectors * 512 - 1

=> 1 BYTE PAST BUFFER (off-by-one in <= check)
```

The value written at the OOB byte is the last byte of `*(DWORD*)(v18 + 44) = 0`, i.e., **0x00 (null byte)**.

### 7.3 Exploitation Requirements

Craft a .blf file with:
1. Block 2 (base record) size = N sectors (buffer = N * 512 bytes)
2. Block header: `cSectors = N`, `valid_data_size = N * 512`
3. Base record: `free_pool_offset = N * 512 - 0x70 - 0x1338` (maximum)
4. A CLFSHASHSYM entry in the container hash table with:
   - `cbDataOffset = N * 512 - 0x70 - 47` (= `N * 512 - 0xA1`)
   - Container context signature = 0xC1FDF008
   - Container context size = 0x30
   - `state` byte = 0 (free/unused, so FindSymbol will use it)
5. The matching `rgContainers` entry pointing to this symbol
6. Pass all validation checks (ValidateOffsets, ValidateContainerContextOffsets, ValidateContainerSymTblOffsets)

When `AddContainer` is called with a name matching the crafted CLFSHASHSYM entry:
- FindSymbol finds the entry and returns it
- AddContainer reads cbDataOffset from the entry
- OffsetToAddr returns a pointer to the container context (passes check)
- AddContainer writes 48 bytes, with the last byte landing 1 byte past the buffer

### 7.4 Bitmap/rgContainers Analysis

- Container bitmap: 1023 bits (0x3FF), **hardcoded in constructor, never resized**
- rgContainers array: 1024 entries * 4 bytes = 0x1000 bytes at BaseLogRecord + 0x328
- Minimum buffer for full rgContainers: 0x70 + 0x328 + 0x1000 = 0x1398 bytes (~10.2 sectors)
- For cSectors >= 11: rgContainers[1022] at buffer + 0x1390, within bounds (buffer >= 0x1600)
- **rgContainers OOB requires cSectors < 11, but minimum valid cSectors is ~11 (free pool requirement)**

### 7.5 valid_data_size vs cSectors*512 Gap

```
AllocSymbol checks:  allocation <= valid_data_size
OffsetToAddr checks: offset < cSectors * 512

If valid_data_size < cSectors * 512:
    Gap exists between valid_data_size and cSectors * 512
    Allocations stay within valid_data_size (safe)
    Crafted cbDataOffset in gap: passes OffsetToAddr, FAILS validation
```

The gap is not directly exploitable because validation catches crafted entries in the gap.

---

## 8. Complete Decompilations

### AddContainer (0x1C002B888):
```c
__int64 CClfsBaseFilePersisted::AddContainer(
    CClfsBaseFilePersisted *this,
    _UNICODE_STRING *name,
    const uint64 *container_size,
    uint a4, uint8 a5, uint8 a6,
    _CLFS_CONTAINER_CONTEXT *out_ctx)
{
    // ... lock, GetBaseLogRecord, bitmap check ...
    
    // Release lock, add symbol
    AddSymbol(this, name, hash_table, 0x30, &sym, &offset);
    // Re-acquire lock
    
    if (status >= 0) {
        BaseLogRecord = GetBaseLogRecord(this);
        sym = OffsetToAddr(this, offset);           // get CLFSHASHSYM
        StartingIndex = RtlFindClearBits(bitmap, 1, 0);
        RtlSetBits(bitmap, StartingIndex, 1);
        
        cbDataOffset = sym->[0x24];                  // KEY: read cbDataOffset
        ctx = OffsetToAddr(this, cbDataOffset);      // get container context pointer
        
        // WRITE to rgContainers array
        BaseLogRecord[0x328 + StartingIndex*4] = cbDataOffset;
        
        // WRITE 0x30 bytes to container context (THE OOB WRITE)
        ctx[0]  = 0xC1FDF008;    // signature
        ctx[1]  = 0x30;          // size
        ctx[8]  = *container_size; // container size (QWORD)
        ctx[16] = StartingIndex;   // index
        ctx[20] = -1;              // next free
        ctx[24] = 0;              // (QWORD)
        ctx[36] = 1;              // (QWORD)
        ctx[44] = 0;              // (DWORD) <-- last write, OOB byte here
        
        FlushImage();
        CreateContainer(...);
        AcquireContainerContext(StartingIndex, &ctx2);  // GetSymbol validates +47
        ctx2[36] = 2;             // state = active
        ctx2[24] = container_obj;  // link container
        ReleaseContainerContext(...);
        
        BaseLogRecord[0x12C]++;   // increment container count
        FlushImage();
    }
    // ... error cleanup, RemoveContainer, RtlClearBits ...
}
```

### OffsetToAddr (0x1C0035DF8):
```c
void *OffsetToAddr(CClfsBaseFile *this, unsigned int offset) {
    buffer_ptr = m_rgBlocks[2].buffer_ptr;     // [this+30h] -> [+30h]
    base_log_record = GetBaseLogRecord(this);  // r9
    
    if (!buffer_ptr) return NULL;
    
    result = ULongAdd(offset, buffer_ptr.[0x28], &sum);  // offset + block_base_offset
    if (result < 0) return NULL;                          // overflow
    
    if (sum >= (WORD)buffer_ptr.[4] << 9)                 // sum < cSectors * 512
        return NULL;
    
    return base_log_record + offset;                      // NOTE: uses raw offset, not sum
}
```

### ClfsDecodeBlockPrivate (0x1C0006750):
```c
__int64 ClfsDecodeBlockPrivate(_CLFS_LOG_BLOCK_HEADER *hdr, uint numSectors,
    char flag, uint8 align, uint *out) {
    if (!numSectors) return STATUS_INVALID_PARAMETER;
    if (hdr[0] != 0x15 || hdr[1] != 0) return STATUS_FILE_CORRUPT;
    if (numSectors < *(WORD*)(hdr + 4))  // numSectors >= cSectors
        return STATUS_FILE_CORRUPT;
    if (align > 0x10) return STATUS_INVALID_PARAMETER;
    // ... bit test for valid alignment ...
    if (!(*(DWORD*)(hdr + 16) & 1)) return STATUS_FILE_CORRUPT;
    
    sector_array_offset = *(DWORD*)(hdr + 0x68);
    sector_array = (char*)hdr + sector_array_offset;
    
    if (ULongAdd(sector_array_offset, 2 * numSectors, &end) < 0)
        return STATUS_FILE_CORRUPT;
    // ... alignment, bounds checks ...
    
    // Decode sectors (shuffle sector array entries)
    for (i = numSectors; ; --i) {
        sector_idx = i - 1;
        sector_offset = sector_idx << 9;  // sector_idx * 512
        sector_flag = *(BYTE*)(buffer + sector_offset + 510);
        // ... validate sector flags ...
        *(WORD*)(buffer + sector_offset + 510) = *(WORD*)&sector_array[2 * sector_idx];
        if (sector_idx == 0) {
            *(DWORD*)(buffer + 16) = (*(DWORD*)(buffer + 16) & ~3) | 2;
            *out = 0;
            return 0;  // success
        }
    }
}
```

### AllocSymbol (0x1C0043090):
```c
__int64 AllocSymbol(CClfsBaseFilePersisted *this, uint size, void **out) {
    BaseLogRecord = GetBaseLogRecord(this);
    if (!BaseLogRecord) return CLFS_ERROR;
    
    buffer_start = m_rgBlocks[2].buffer_ptr;
    free_pool = BaseLogRecord->[0x1328];  // free_pool_offset
    
    // CHECK: allocation fits within valid_data_size
    if (BaseLogRecord + free_pool + size + 0x1338 > buffer_start + buffer_start.[0x68])
    //                                        ^ valid_data_size
        return STATUS_BUFFER_TOO_SMALL;
    
    ptr = BaseLogRecord + free_pool + 0x1338;
    memset(ptr, 0, size);
    BaseLogRecord->[0x1328] += size;
    *out = ptr;
    return 0;
}
```

### ValidateCheckifWithinSymbolZone (0x1C0027D34):
```c
__int64 ValidateCheckifWithinSymbolZone(CClfsBaseFile *this, uint offset,
    _CLFS_BASE_RECORD_HEADER *base_record) {
    if (offset < 0x1338 || (offset - 0x1338) > base_record->[0x1328])
    //                               ^ free_pool_offset     USES <= (allows equality)
        return CLFS_ERROR;
    return 0;
}
```

### GetSymbol (0x1C0036460) - Used by AcquireContainerContext:
```c
__int64 GetSymbol(PERESOURCE *this, uint offset, int container_index,
    _CLFS_CONTAINER_CONTEXT **out) {
    if (offset < 0x1368) return CLFS_ERROR;
    
    if (!IsValidOffset(this, offset + 47))  // CHECK: offset + 47 within buffer
        goto fail;
    
    // OffsetToAddr-style check
    if (ULongAdd(offset, block_base_offset, &sum) < 0) goto fail;
    if (sum >= cSectors * 512) goto fail;
    
    ptr = base_log_record + offset;
    
    // Verify CLFSHASHSYM fields
    if (*(DWORD*)(ptr - 12) != offset) goto fail;        // cbDataOffset matches
    if (*(DWORD*)(ptr - 16) != offset + ClfsQuadAlign(0x30)) goto fail;  // size
    if (*(DWORD*)(ptr + 0) != 0xC1FDF008) goto fail;     // signature
    if (*(DWORD*)(ptr + 4) != 48) goto fail;              // context size
    if (*(DWORD*)(ptr + 16) != container_index) goto fail; // index
    
    *out = ptr;
    return 0;
}
```

### AcquireContainerContext (0x1C00361D0):
```c
__int64 AcquireContainerContext(PERESOURCE *this, uint index,
    _CLFS_CONTAINER_CONTEXT **out) {
    if (index >= 0x400) return CLFS_ERROR;  // max 1024 containers
    
    // Get base record, validate offsets
    buffer = m_rgBlocks[2].buffer_ptr;
    base_offset = buffer.[0x28];
    valid_size = buffer.[0x68];
    
    if (!valid_size || base_offset >= valid_size || base_offset < 0x70
        || valid_size - base_offset < 0x1338)
        ptr = NULL;
    
    if (ptr) {
        sym_offset = *(DWORD*)(ptr + 4 * index + 808);  // rgContainers[index]
        if (sym_offset)
            return GetSymbol(this, sym_offset, index, out);
        else
            return STATUS_NOT_FOUND;
    }
    return CLFS_ERROR;
}
```

### ReadMetadataBlock (0x1C0037EA0):
```c
__int64 ReadMetadataBlock(CClfsBaseFilePersisted *this, uint block_type) {
    if (block_type >= num_blocks) return STATUS_INVALID_PARAMETER;
    
    buf_size = block_descriptor[block_type].size;
    if (!buf_size) return 0;
    if (buf_size < 0x70) return CLFS_ERROR;
    
    buffer = ExAllocatePoolWithTag(PagedPoolCacheAligned, buf_size, 'Clfs');
    memset(buffer, 0, buf_size);
    
    CClfsContainer::ReadSector(container, event, 0, &read_buf, buf_size >> 9, &overlap);
    KeWaitForSingleObject(event, ...);
    
    ClfsDecodeBlock(buffer, buf_size >> 9, buffer[2], 0x10, &bad_sector);
    //            ^ numSectors = buf_size / 512
    
    // Validate sector array offset
    sector_array_off = buffer[10];  // buffer.[0x28] = block_base_offset
    if (sector_array_off >= buf_size || sector_array_off < 0x70
        || buf_size - sector_array_off < 8)
        return CLFS_ERROR;
    
    // Shadow block handling (compare with shadow, pick younger) ...
}
```

---

## 9. Mathematical Summary

### Buffer Layout:
```
buffer + 0x000:  CLFS_LOG_BLOCK_HEADER
  +0x00: signature (BYTE = 0x15, BYTE = 0x00)
  +0x04: cSectors (WORD) -- OffsetToAddr bounds limit
  +0x06: shadow cSectors (WORD)
  +0x28: block_base_offset (DWORD = 0x70) -- offset to base record
  +0x68: valid_data_size (DWORD) -- AllocSymbol bounds limit

buffer + 0x070: CLFS_BASE_RECORD_HEADER
  +0x000: base record fields...
  +0x328: rgContainers[0] (DWORD array, 1024 entries = 0x1000 bytes)
  +0x1328: free_pool_offset (DWORD) -- current free pool position
  +0x1338: free pool start (symbol zone start)

buffer + 0x070 + cbDataOffset: CONTAINER_CONTEXT (0x30 bytes)
  +0x00: signature (DWORD = 0xC1FDF008)
  +0x04: size (DWORD = 0x30)
  +0x08: container_size (QWORD)
  +0x10: StartingIndex (DWORD)
  +0x14: next_free (DWORD = -1)
  +0x18: reserved (QWORD = 0)
  +0x24: state (QWORD = 1)
  +0x2C: reserved (DWORD = 0)
```

### Bounds Check Comparison:
```
                    AllocSymbol          OffsetToAddr         Validation
                    (new entries)        (all entries)        (existing entries)
Check:              alloc_end <=         offset + base <      offset + 47 <=
                    valid_data_size      cSectors * 512       free_pool + 0x1338
                    (<=)                 (<)                  (<=)
Max offset:         VDS - base - size    CS*512 - base - 1    VDS - base - 47
                    (excludes data)      (start only!)        (includes data end)

Where VDS = valid_data_size, CS = cSectors, base = 0x70

If VDS = CS*512 (crafted max):
  AllocSymbol max:   CS*512 - base - size  (safe, size >= 0x60)
  OffsetToAddr max:  CS*512 - base - 1     (47-byte OOB possible!)
  Validation max:    CS*512 - base - 47    (1-byte OOB at boundary)

  Write at validation max:
    Start: buffer + CS*512 - 47
    End:   buffer + CS*512        <-- 1 BYTE PAST BUFFER
```

---

## 10. Conclusion

### Primary OOB Vector: 1-Byte Null Write Past Metadata Buffer

The validation function `ValidateCheckifWithinSymbolZone` uses `<=` (allows equality) when checking `cbDataOffset + 47 <= free_pool_offset + 0x1338`. When `valid_data_size = cSectors * 512` (the maximum allowed by `ValidateOffsets`), this permits a CLFSHASHSYM entry whose container context's last byte (at `cbDataOffset + 47`) lands at exactly `buffer + cSectors * 512`, which is **1 byte past the allocated buffer**.

The OOB byte is the last byte of `*(DWORD*)(container_context + 44) = 0`, writing **0x00** past the pool allocation boundary.

### Secondary Vector: OffsetToAddr Start-Only Check (47-byte theoretical OOB)

`OffsetToAddr` validates only the START address (`offset + base < cSectors * 512`), not the END (`offset + base + 0x30 <= cSectors * 512`). If a CLFSHASHSYM entry could have `cbDataOffset = cSectors * 512 - base - 1`, the 48-byte write would extend 47 bytes past the buffer. However, validation limits `cbDataOffset` to `cSectors * 512 - base - 47`, capping the OOB at 1 byte.

### Crafted File Requirements:
1. Set `cSectors` = N (buffer = N * 512 bytes)
2. Set `valid_data_size` = N * 512 (maximum allowed)
3. Set `free_pool_offset` = N * 512 - 0x70 - 0x1338 (maximum allowed)
4. Create a CLFSHASHSYM entry in the container hash table with:
   - `cbDataOffset` = N * 512 - 0x70 - 47 = N * 512 - 0xA1
   - Valid container context signature (0xC1FDF008) and size (0x30)
   - `state` = 0 (free, so FindSymbol will use it)
5. Link this entry in `rgContainers` array
6. Pass all validation checks (ValidateOffsets, ValidateContainerContextOffsets, ValidateContainerSymTblOffsets, ValidateProcessQNode)
7. Trigger `AddContainer` with a matching container name

### Pool Exploitation Notes:
- Buffer allocated with `ExAllocatePoolWithTag(PagedPoolCacheAligned, size, 'Clfs')`
- 1-byte null overflow into adjacent paged pool allocation
- Adjacent pool header corruption could lead to pool type confusion
- With careful pool Feng Shui, adjacent object could be a controlled structure
- Null byte at pool boundary can corrupt Size/PoolType fields of next pool chunk header
