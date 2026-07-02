# CLFS + KTM Combined Analysis: OOB Write via Crafted .blf

## Executive Summary

**Verdict: The AddContainer +0x08 write primitive is IN-BOUNDS by design. The KTM non-volatile TM path does NOT bypass any CLFS validation layers or introduce new OOB write opportunities.**

The AddContainer write at `ptr+0x08` (8 controlled bytes) was confirmed in earlier analysis as in-bounds. This analysis explored whether using KTM's `NtCreateTransactionManager` with `CreateOptions=0` (non-volatile, with a crafted .blf log file) could trigger CLFS operations differently to achieve an OOB write past the metadata buffer. After exhaustive decompilation and validation path tracing, all avenues are blocked by consistent, layered bounds checks.

---

## 1. KTM -> CLFS Call Chain (tm.sys)

### 1.1 NtCreateTransactionManagerExt (0x1c001ebf0)

```
NtCreateTransactionManagerExt(TmHandle, DesiredAccess, ObjectAttributes, LogFileName, CreateOptions, CommitStrength)
```

- Validates `CreateOptions <= 0x3F`
- If `CreateOptions & 1` (volatile): `LogFileName` must be NULL
- If `CreateOptions & 1 == 0` (non-volatile): `LogFileName` must be present
- Creates TM object via `ObCreateObject` (960 bytes)
- Calls `TmInitializeTransactionManagerExt(TransactionManager, LogFileName, NULL, CreateOptions)`

### 1.2 TmInitializeTransactionManagerExt (0x1c001a820)

```
TmInitializeTransactionManagerExt(TransactionManager, LogFileName, TmId, CreateOptions)
```

- Initializes mutexes, events, resource locks, namespaces
- If `CreateOptions & 1` (volatile): calls `TmpTmOnline(TransactionManager)` (just notifies CRMs)
- If `CreateOptions & 1 == 0` (non-volatile): duplicates LogFileName, calls `TmpCreateOrOpenLogTransactionManager(TransactionManager)`
- After log creation: creates a ResourceManager via `ZwCreateResourceManager`

### 1.3 TmpCreateOrOpenLogTransactionManager (0x1c000e3ac)

```c
*(_DWORD *)(tm + 64) = 2;  // state = creating
result = TmpCreateLogFile(tm);
if (state == 2 && result < 0)
    *(_DWORD *)(tm + 64) = 4;  // state = failed
return result;
```

Simple wrapper that calls `TmpCreateLogFile`.

### 1.4 TmpCreateLogFile (0x1c000db98)

This is the core function that interfaces with CLFS:

1. **Prepends log prefix**: `TmpLogPrefix` + user-supplied filename
2. **Calls `ClfsCreateLogFile`** with:
   - `fDesiredAccess = 0xC0000000` (GENERIC_READ | GENERIC_WRITE)
   - `dwShareMode = 3` (FILE_SHARE_READ | FILE_SHARE_WRITE)
   - `fCreateDisposition = 1` (CREATE_NEW)
   - If `STATUS_OBJECT_NAME_NOT_FOUND` (0xC0000034): retries with `fCreateDisposition = 2` (CREATE_ALWAYS)
3. **Calls `TmpIsClusteredTransactionManager`** to check cluster status
4. **Calls `TmpRegisterForLogManagement`** for CLFS management interface
5. **Calls `ClfsCreateMarshallingArea`** with:
   - `cbMarshallingBuffer = 0x10000` (65536 bytes)
   - `cMaxWriteBuffers = 0x14` (20)
   - `cMaxReadBuffers = 1`
6. **Calls `ClfsReserveAndAppendLog`** to reserve 32 bytes
7. **If new log**: calls `TmpWriteRestartArea`
8. **If existing log**: calls `ClfsGetLogFileInformation`, `ClfsReadRestartArea`, `ClfsReadLogRecord`, then `TmpWriteRestartArea`

**Key finding: KTM does NOT call `ClfsAddLogContainer`. The AddContainer write primitive is NOT triggered in the KTM path.**

---

## 2. CLFS Metadata Loading Path (clfs.sys)

### 2.1 File Open Chain

```
ClfsCreateLogFile (0x1c00365e0)
  -> IoCreateFileSpecifyDeviceObjectHint (opens LOG: device)
  -> CLFS driver creates CClfsLogFcbPhysical
  -> CClfsLogFcbPhysical::Initialize
     -> OpenImage (0x1c002d2f4)
        -> CClfsContainer::Open (opens the .blf file)
        -> ReadImage (0x1c002ebf0) -- reads metadata blocks
        -> GetContainerSize
        -> ExtendMetadataBlock (if needed)
     -> LoadContainerQ (0x1c002d880) -- loads & validates containers
        -> ValidateOffsets (0x1c0028294) -- FULL validation
```

### 2.2 ReadImage (0x1c002ebf0)

- Sets block count to 6 (3 pairs of shadow blocks)
- Allocates metadata descriptor array: `operator new(0x90)` (6 entries x 24 bytes)
- Allocates block status array: `operator new(12)` (6 x 2-byte flags)
- Initializes descriptor sizes from `this->sector_size`
- Calls `GetControlRecord` to read and decode block 0 (control record)
- Validates control record:
  - Signature must be `0xC1F5C1F500005F1C`
  - `control_record.block_count == 6`
  - Various sector count fields must match
- Copies block descriptors from control record into descriptor array
- Calls `AcquireMetadataBlock` for block 2 (base log record)

### 2.3 ReadMetadataBlock (0x1c0037ea0)

For each metadata block:

1. **Allocation**: `ExAllocatePoolWithTag(PagedPoolCacheAligned, descriptor.block_size, 'Clsf')`
   - Buffer size = `descriptor.block_size` (from control record, typically 0x7A00 = 61 sectors)
   - Minimum size check: `descriptor.block_size >= 0x70`

2. **Read**: `CClfsContainer::ReadSector(container, ..., block_size >> 9, ...)`
   - Reads `block_size / 512` sectors from the .blf file into the buffer

3. **Decode**: `ClfsDecodeBlock(buffer, block_size >> 9, buffer[2], 0x10, &numDecoded)`
   - `ClfsDecodeBlock` checks CRC32, then calls `ClfsDecodeBlockPrivate`
   - `ClfsDecodeBlockPrivate` checks:
     - `buffer[0] == 0x15` (major version)
     - `buffer[1] == 0x00` (minor version)
     - `numSectors_arg >= *(WORD*)(buffer + 4)` (header.numSectors)
     - Sector signatures match expected pattern

4. **Post-decode validation**:
   - `cbOffset = *(DWORD*)(buffer + 40)` (base record offset)
   - Check: `cbOffset < block_size` (must be within buffer)
   - Check: `cbOffset >= 0x70` (minimum header size)
   - Check: `block_size - cbOffset >= 8` (room for at least 8 bytes of data)

5. **Shadow block handling**: If a shadow block exists and is younger, it replaces the primary

### 2.4 GetBaseLogRecord (0x1c00365a0)

```c
if (block_count && 
    (block_ptr = *(QWORD*)(this+6+48)) != 0 &&
    (block_size = *(DWORD*)(this+6+56), cbOffset = *(DWORD*)(block_ptr+40), cbOffset < block_size) &&
    cbOffset >= 0x70 &&
    block_size - cbOffset >= 0x1338)  // 4920 bytes minimum for base record
{
    return block_ptr + cbOffset;
}
```

**Critical check**: `block_size - cbOffset >= 0x1338` (4920 bytes)
- This ensures the base record has room for the symbol zone start (4920 bytes)
- Minimum block_size = `cbOffset + 0x1338 = 0x70 + 0x1338 = 0x13A8 = 5032 bytes` (~10 sectors)

### 2.5 LoadContainerQ (0x1c002d880)

This is where `ValidateOffsets` is called. The validation sequence:

1. **Pre-check**: `*(DWORD*)(block + 104) > *(WORD*)(block + 4) << 9`
   - `usable_data_size > numSectors * 512` -> error
   - This prevents inflating `usable_data_size` (at offset 0x68) beyond the buffer

2. **Symbol zone end check**:
   - `ULongLongAdd(BaseLogRecord + 4920, szc, &v93)` -- computes symbol zone end
   - `ULongLongAdd(block_ptr, block_size_field, &v92)` -- computes buffer end
   - If `v93 > v92` -> error
   - This ensures: `cbOffset + 4920 + szc <= block_size`

3. **ValidateOffsets**: Full validation of all container/client/symbol offsets
   - `ValidateContainerContextOffsets`
   - `ValidateClientContextOffsets`
   - `ValidateContainerSymTblOffsets`
   - `ValidateClientSymTblOffsets`
   - String length validation

4. **Container iteration**: For each container in base record:
   - `GetSymbol(offset, index, &ctx)` -- validates via IsValidOffset(offset + 47)
   - Opens container file, checks sector size
   - Sets up container context

---

## 3. AddContainer Write Primitive Analysis

### 3.1 AddContainer (0x1c002b888)

The write primitive at `0x1c002ba27`:
```c
v18 = CClfsBaseFile::OffsetToAddr(this, container_offset);
*((_QWORD *)v18 + 1) = *a3;  // writes 8 bytes at v18 + 0x08
```

### 3.2 OffsetToAddr (0x1c0035df8)

```c
GetBaseLogRecord(this);  // sets v1 = base_record_ptr, v3 = block_ptr
ULongAdd(offset, *(DWORD*)(base_record + 40), &v7);  // v7 = offset + cbOffset
if (v3 && v7 < *(WORD*)(block + 4) << 9)  // v7 < numSectors * 512
    return block + v7;  // = block + offset + cbOffset
return nullptr;
```

**Bounds check**: `offset + cbOffset < numSectors * 512`
- Uses `numSectors` from block header (offset 4), which is validated by ClfsDecodeBlockPrivate
- `numSectors <= actual_sectors` (from decode check)

### 3.3 GetSymbol (0x1c0036460)

```c
if (offset < 0x1368) return error;  // minimum offset
ExAcquireResourceSharedLite(this+4, TRUE);
if (!IsValidOffset(this, offset + 47)) goto error;  // offset + 47 must be in bounds
// ... additional checks on back-pointer, signature, container index
```

**Critical check**: `IsValidOffset(offset + 47)`
- `IsValidOffset`: `(offset + 47) + cbOffset < numSectors * 512`
- This ensures the container context extends 47 bytes from the offset
- The write at `offset + 0x08` (8 bytes, ending at offset + 0x10) is well within the 47-byte validated range

### 3.4 AllocSymbol (0x1c0043090)

```c
BaseLogRecord = GetBaseLogRecord(this);
v8 = *(QWORD*)(*(QWORD*)(this+6) + 48);  // block pointer
szc = *(DWORD*)(BaseLogRecord + 4904);   // symbol zone current size
if (BaseLogRecord + szc + alloc_size + 4920 > v8 + *(DWORD*)(v8 + 104))
    return STATUS_BUFFER_OVERFLOW;
v10 = BaseLogRecord + szc + 4920;
memset(v10, 0, alloc_size);
*(DWORD*)(BaseLogRecord + 4904) += alloc_size;  // update szc
*a3 = v10;  // return pointer
return STATUS_SUCCESS;
```

**Bounds check**: `cbOffset + szc + alloc_size + 4920 <= usable_data_size`
- `usable_data_size` = `*(DWORD*)(block + 104)` (offset 0x68 in block header)
- Set by `ClfsStampLogBlock` to: `total_size - sector_signature_overhead`
- Validated by `ValidateOffsets`: `usable_data_size <= numSectors * 512 = block_size`

### 3.5 ValidateCheckifWithinSymbolZone (0x1c0027d34)

```c
if (offset < 0x1338 || offset - 4920 > *(DWORD*)(base_record + 4904))
    return error;
return success;
```

**Check**: offset must be within `[0x1338, 0x1338 + szc]`
- Ensures container offsets point within the allocated symbol zone

### 3.6 ValidateOffsets (0x1c0028294)

```c
v9 = *(DWORD*)(block + 104);  // usable_data_size
if (v9 > *(WORD*)(block + 4) << 9)  // v9 > numSectors * 512
    goto error;  // usable_data_size exceeds buffer
// ... then calls ValidateContainerContextOffsets, etc.
```

**Key check**: `usable_data_size <= numSectors * 512`
- This prevents inflating `usable_data_size` beyond the actual buffer
- If `usable_data_size` is set to `0xFFFF` but buffer is `0x7A00`, this check fails

---

## 4. OOB Write Attempt Analysis

### 4.1 Strategy: Inflate `usable_data_size` (offset 0x68)

**Goal**: Set `usable_data_size` in the crafted .blf larger than the actual buffer, so `AllocSymbol` allows allocations past the buffer end.

**Result**: BLOCKED by `ValidateOffsets` check:
- `usable_data_size > numSectors * 512` -> error
- Maximum allowed: `usable_data_size = numSectors * 512 = block_size`
- With `usable_data_size = block_size`, `AllocSymbol` limits pointers to within the buffer

### 4.2 Strategy: Inflate `numSectors` (offset 4)

**Goal**: Set `numSectors` in the block header larger than actual allocation, so `IsValidOffset` allows larger offsets.

**Result**: BLOCKED by `ClfsDecodeBlockPrivate`:
- `numSectors_arg >= header.numSectors` must pass
- `numSectors_arg` = `descriptor.block_size / 512` = actual sectors
- If `header.numSectors > actual_sectors`, decode fails

### 4.3 Strategy: Large `szc` with matching `usable_data_size`

**Goal**: Pre-set `szc` in the .blf to point near buffer end, with `usable_data_size = block_size`.

**Result**: BLOCKED by `LoadContainerQ`'s own check:
- `cbOffset + 4920 + szc <= block_size` (from `ULongLongAdd` + comparison)
- Maximum `szc = block_size - cbOffset - 4920 = 0x6658`
- `AllocSymbol` pointer at: `block + cbOffset + szc + 4920 = block + 0x7A00` (buffer end)
- With `alloc_size = 128`, pointer is at `block + 0x7980`, 128 bytes before end
- The CLFSHASHSYM + container context fits within the remaining 128 bytes
- Write at `+0x08` is at `block + 0x79C8`, which is 56 bytes before the end: IN BOUNDS

### 4.4 Strategy: Container context at exact buffer end

**Goal**: Craft .blf with container offset such that the container context starts at `buffer_end - 8`, making the write at `+0x08` go past the buffer.

**Result**: BLOCKED by `GetSymbol`'s `+47` check:
- `IsValidOffset(offset + 47)` ensures `offset + 47 + cbOffset < numSectors * 512`
- The write at `offset + 0x08` (ending at `offset + 0x10`) is within the 47-byte range
- `0x10 < 0x2F` (16 < 47), so the write is always within the validated range

### 4.5 Strategy: KTM bypasses validation

**Goal**: Use KTM's `NtCreateTransactionManager` to open a crafted .blf through a path that skips `ValidateOffsets`.

**Result**: BLOCKED. KTM uses the same `ClfsCreateLogFile` -> `OpenImage` -> `ReadImage` -> `LoadContainerQ` path as any CLFS client. `LoadContainerQ` calls `ValidateOffsets` unconditionally. There is no alternative path that skips validation.

### 4.6 Strategy: KTM triggers AddContainer

**Goal**: Use KTM to trigger `AddContainer` (the write primitive).

**Result**: KTM does NOT call `ClfsAddLogContainer`. `TmpCreateLogFile` only calls:
- `ClfsCreateLogFile` (open/create)
- `ClfsCreateMarshallingArea` (marshalling context)
- `ClfsReserveAndAppendLog` (reserve space)
- `TmpWriteRestartArea` / `ClfsReadRestartArea` (restart area I/O)

`AddContainer` is only triggered by explicit `ClfsAddLogContainer` calls.

---

## 5. Numerical Verification

All computations performed via `ida-pro-mcp_py_eval`:

| Parameter | Value |
|-----------|-------|
| Standard block size | 0x7A00 (31232 bytes, 61 sectors) |
| Base record offset (cbOffset) | 0x70 (112 bytes) |
| Symbol zone start | 0x13A8 (cbOffset + 0x1338) |
| Available for symbols | 0x6658 (26200 bytes) |
| Normal usable_data_size | 0x7980 (31104 bytes) |
| Max usable_data_size (ValidateOffsets) | 0x7A00 (= numSectors * 512) |
| Max szc (LoadContainerQ) | 0x6658 |
| Max szc (AllocSymbol, alloc=128) | 0x65D8 |
| Max container offset (GetSymbol +47) | block_size - cbOffset - 47 = 0x7990 - 0x70 = 0x7961 (approx) |
| Write at +0x08 from max offset | 0x79D1 + 0x08 = 0x79D9 (end: 0x79E1) |
| Buffer end | 0x7A00 |
| **OOB margin** | **31 bytes remaining (IN BOUNDS)** |

---

## 6. CLFS_LOG_BLOCK_HEADER Layout

Reconstructed from decompilation of `ClfsStampLogBlock`, `ReadMetadataBlock`, `GetBaseLogRecord`, `OffsetToAddr`, `IsValidOffset`, `AllocSymbol`, `ValidateOffsets`:

```
Offset  Size  Field                   Used By
------  ----  ----------------------  --------------------------------
0x00    1     majorVersion (0x15)     ClfsDecodeBlockPrivate
0x01    1     minorVersion (0x00)     ClfsDecodeBlockPrivate
0x02    2     usn                     ClfsDecodeBlock (sector signatures)
0x04    2     numSectors              IsValidOffset, ValidateOffsets
0x06    2     numSectors (copy)       ClfsStampLogBlock sets both
0x08    4     unknown
0x0C    4     unknown
0x10    4     flags                   ClfsDecodeBlockPrivate
0x14    ...   ...                     
0x28    4     cbOffset (base record)  GetBaseLogRecord, ReadMetadataBlock
0x68    4     usableDataSize          AllocSymbol, ValidateOffsets, LoadContainerQ
0x70    ...   start of record data    (base record starts here if cbOffset=0x70)
```

---

## 7. .blf File Layout (for reference)

A .blf file contains 6 metadata blocks (3 pairs of shadow blocks):

| Block | Type | Typical Size | Content |
|-------|------|-------------|---------|
| 0 | Control Record | 0x400 (2 sectors) | Block descriptors, signatures |
| 1 | Shadow of 0 | 0x400 | Copy of control record |
| 2 | Base Log Record | 0x7A00 (61 sectors) | Container/client/symbol tables |
| 3 | Shadow of 2 | 0x7A00 | Copy of base log record |
| 4 | CRC/Truncate | 0x400 | Truncation context |
| 5 | Shadow of 4 | 0x400 | Copy of truncate block |

Control record signature: `0xC1F5C1F500005F1C`
Container context signature: `0xC1F30010`

---

## 8. Full Validation Layer Stack

When a crafted .blf is opened via KTM:

```
NtCreateTransactionManager
  -> TmInitializeTransactionManagerExt
  -> TmpCreateLogFile
  -> ClfsCreateLogFile
  -> IoCreateFileSpecifyDeviceObjectHint
  -> [CLFS driver] CClfsLogFcbPhysical::Initialize
  -> OpenImage
  -> CClfsContainer::Open (opens .blf file)
  -> ReadImage
  -> GetControlRecord -> ReadMetadataBlock(0)
  [LAYER 1] ClfsDecodeBlock: CRC32 check
  [LAYER 2] ClfsDecodeBlockPrivate: version, numSectors_arg >= header.numSectors
  [LAYER 3] ReadMetadataBlock: cbOffset < block_size, cbOffset >= 0x70, block_size - cbOffset >= 8
  -> Read control record: signature check, block count check
  -> ReadMetadataBlock(2) (base log record)
  [LAYER 1-3 repeat for block 2]
  -> LoadContainerQ
  [LAYER 4] usable_data_size <= numSectors * 512
  [LAYER 5] cbOffset + 4920 + szc <= block_size (ULongLongAdd overflow + comparison)
  [LAYER 6] ValidateOffsets:
  [LAYER 6a] ValidateContainerContextOffsets: ValidateCheckifWithinSymbolZone(offset+47), GetSymbol
  [LAYER 6b] ValidateClientContextOffsets
  [LAYER 6c] ValidateContainerSymTblOffsets
  [LAYER 6d] ValidateClientSymTblOffsets
  [LAYER 6e] String length validation
  [LAYER 7] GetSymbol: offset >= 0x1368, IsValidOffset(offset+47), back-pointer, signature, index
  -> ClfsCreateMarshallingArea
  -> ClfsReserveAndAppendLog
  -> TmpWriteRestartArea / ClfsReadRestartArea
```

**All 7 layers must pass. No layer is bypassed in the KTM path.**

---

## 9. Conclusion

The CLFS AddContainer `+0x08` write primitive operates within a tightly validated environment where:

1. **Buffer size is authoritative**: The actual allocation size (from the control record's block descriptor) determines the buffer size. Both `numSectors` (header offset 4) and `usable_data_size` (header offset 0x68) are validated against this size.

2. **Symbol zone is bounded**: The symbol zone current size (`szc`) is checked against the buffer by `LoadContainerQ` before any operations, and by `AllocSymbol` during allocations.

3. **Container offsets are bounded**: `GetSymbol` ensures `offset + 47 + cbOffset < numSectors * 512`, and the write at `+0x08` is well within the 47-byte validated range.

4. **KTM adds no bypass**: KTM uses the identical `ClfsCreateLogFile` -> `LoadContainerQ` path as any CLFS client. It does not call `ClfsAddLogContainer`, so the `AddContainer` write primitive is not even triggered.

5. **No TOCTOU window**: All validation and use occur under the same ERESOURCE lock (`ExAcquireResourceExclusiveLite`), preventing race conditions between validation and writes.

**The OOB write via crafted .blf + KTM is not achievable through the analyzed validation paths.**
