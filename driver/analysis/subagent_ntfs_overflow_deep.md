# ntfs.sys Compression Buffer Overflow & MFT Record Overflow — Deep Analysis

## Executive Summary

Two potential overflow paths were identified in ntfs.sys through static reverse engineering with IDA Pro:

1. **Compression Buffer Overflow (Ntf9 pool tag)** — TOCTOU race on SCB+436 (compression unit size) between `NtfsAllocateCompressionBuffer` and `NtfsPrepareCompressedWriteBuffer` fallback path. Overflow is in **NonPagedPoolNx** (LFH-managed), data is fully user-controlled via `WriteFile`. This is the more viable path for an 8-byte arbitrary kernel write into an adjacent pool object.

2. **MFT Record Overflow** — `NtfsChangeAttributeValue` writes user-controlled reparse point data into a 1024-byte MFT record. The size check compares against `VCB+360` (file record size) rather than available record space. However, the MFT record is a cached file buffer, not a pool allocation — so this is a file system corruption primitive, not a pool corruption primitive. Less useful for direct kernel code execution.

---

## 1. Compression Buffer Overflow — Complete Analysis

### 1.1 Function Call Chain

```
WriteFile (user mode)
  -> NtfsCommonWrite
    -> NtfsPrepareComplexBuffers (0x1c0023fb8)
      -> NtfsAllocateCompressionBuffer (0x1c0024da8)   [allocates Ntf9 buffer]
      -> NtfsPrepareCompressedWriteBuffer (0x1c0024614) [writes into Ntf9 buffer]
        -> RtlCompressBuffer                             [attempt compression]
        -> [fallback: memmove + memset on overflow]      [STATUS_BUFFER_TOO_SMALL path]
```

### 1.2 Complete Decompilation of NtfsPrepareCompressedWriteBuffer (0x1c0024614)

```c
__int64 __fastcall NtfsPrepareCompressedWriteBuffer(
    __int64 a1,        // IRP context
    __int64 a2,        // SCB (Stream Control Block)
    __int64 a3,        // File offset
    __int64 a4,        // Starting VBN
    size_t Size,       // Write size
    __int64 a6)        // Compression context
{
    // a2 = SCB:
    //   SCB+176 = pointer to VCB-like structure
    //   SCB+264 = stream pointer (NULL => MDL path)
    //   SCB+436 = CompressionUnitSize (DWORD) *** CRITICAL FIELD ***
    //   SCB+444 = CompressionFormat (WORD)
    //   SCB+496 = Flags (DWORD)
    //   SCB+184 = SCB flags (DWORD, 0x80000 = sparse)
    //
    // a6/v9 = Compression context:
    //   v9+32  = pointer to compression output buffer (Ntf9 pool allocation)
    //   v9+40  = current offset/length in buffer
    //   v9+48  = MDL/buffer descriptor
    //   v9+96  = compression workspace
    //   v9+104 = compression enabled flag
    //   v9+106 = compression active flag

    // ... [workspace setup, data mapping] ...

    // RtlCompressBuffer call:
    //   Output buffer:  *(v9+32)                           [Ntf9 pool buffer]
    //   Output size:    SCB[436] - VCB[356]                [compressed buffer capacity]
    //   Input buffer:   v15 (uncompressed data)
    //   Input size:     v11 (uncompressed data size)
    //   Chunk size:     0x1000 (4096)

    v16 = RtlCompressBuffer(
        (unsigned __int8)*(_WORD *)(a2 + 444) + 1,       // compression format
        (PUCHAR)v15,                                      // uncompressed data
        v11,                                              // uncompressed size
        *(PUCHAR *)(v9 + 32),                             // output buffer (Ntf9)
        *(_DWORD *)(a2 + 436) - *(_DWORD *)(*(_QWORD *)(a2 + 176) + 356LL),  // OUTPUT SIZE
        0x1000u,                                          // chunk size
        &FinalCompressedSize,
        *(PVOID *)(v9 + 96));                             // workspace

    // *** FALLBACK PATH (STATUS_BUFFER_TOO_SMALL = 0xC0000023 = -1073741789) ***
    if (v16 == -1073741789)  // STATUS_BUFFER_TOO_SMALL
    {
        // RE-READS SCB+436 directly! (TOCTOU: may differ from allocation time)
        FinalCompressedSize = *(_DWORD *)(a2 + 436);

        // Copy uncompressed data to START of buffer
        memmove(*(void **)(v9 + 32), v15, v14);  // v14 = v11 = uncompressed size

        // Zero-fill remaining space up to FinalCompressedSize
        if (FinalCompressedSize > v11)
            memset((void *)(v14 + *(_QWORD *)(v9 + 32)), 0, FinalCompressedSize - v11);

        v16 = 0;  // Success
    }

    // ... [alignment padding, cleanup] ...
    return v18;
}
```

### 1.3 Buffer Allocation in NtfsPrepareComplexBuffers (0x1c0023fb8)

```c
// Early read of compression unit size (CACHED in v101)
v101 = *(_DWORD *)(a3 + 436);  // SCB+436 read ONCE here

// Calculate allocation size
v22 = v19[89] + v101;  // VCB[356] + compression_unit_size
v23 = v22;
if (*(_BYTE *)(v10 + 106) && *(_BYTE *)(v10 + 104)) {
    v23 = v22 + Size;  // Add write size if compressing
    v22 += Size;
}
if (v23 > dword_1C0095018)  // Cap = 0xFFFFFFFF (effectively unlimited)
    v22 = dword_1C0095018;

v95 = v22;
// Allocate buffer using CACHED v101 value
NtfsAllocateCompressionBuffer(v9, a3, (__int64)a2, v10, (unsigned int *)&v95, 0);

// Then call NtfsPrepareCompressedWriteBuffer which RE-READS SCB+436
v26 = NtfsPrepareCompressedWriteBuffer(v9, a3, v7, v25, (size_t)v90, v10);
```

### 1.4 NtfsAllocateCompressionBuffer (0x1c0024da8)

```c
// Reads requested size from caller
v11 = *a5;  // Requested size (from NtfsPrepareComplexBuffers)
v13 = *(unsigned int *)(a4 + 40);  // Current buffer size

if (v11 > v13 || ...) {
    // Reallocate: update size, call NtfsCreateMdlAndBuffer
    *v12 = v11;  // Update size field
    // ...
    NtfsCreateMdlAndBuffer(a1, a2, v13, 516, a4 + 40, &v18, a4 + 32);
    // 516 = 0x204 = NonPagedPoolNxCacheAligned
}
```

### 1.5 NtfsCreateMdlAndBuffer (0x1c0024fb8) — Pool Allocation

Disassembly at the ExAllocatePoolWithTag call sites:

```asm
; First allocation path:
mov  edx, [r12]          ; NumberOfBytes (from size pointer)
mov  r8d, 3966744Eh      ; Tag = 'Ntf9'
mov  ecx, r11d           ; PoolType (from caller, 0x204)
call ExAllocatePoolWithTag

; Second allocation path (0x1c0024fef):
mov  edx, [r12]          ; NumberOfBytes
mov  r8d, 3966744Eh      ; Tag = 'Ntf9'
mov  ecx, r11d           ; PoolType
call ExAllocatePoolWithTag

; After allocation:
call IoAllocateMdl
call MmBuildMdlForNonPagedPool  ; Confirms NonPaged pool
```

### 1.6 Pool Type and LFH Bucket Analysis

**Pool Tag:** `Ntf9` (0x3966744E)

**Pool Type:** `NonPagedPoolNxCacheAligned` (0x204)
- 0x200 = NonPagedPoolNx (no-execute)
- 0x004 = CacheAligned
- Confirmed by `MmBuildMdlForNonPagedPool` call after allocation

**Allocation API:** `ExAllocatePoolWithTag` (legacy API, not ExAllocatePool2)

**dword_1C0095018 (allocation cap):** 0xFFFFFFFF (effectively unlimited)

**LFH Bucket Assignments (Windows 10/11 kernel NonPagedPoolNx):**

| Compression Unit | Alloc Size | LFH Bucket | Bucket Size | Internal Padding |
|-----------------|------------|------------|-------------|------------------|
| 0x1000 (4KB)   | 4112       | 45         | 5120        | 992 bytes        |
| 0x2000 (8KB)   | 8208       | 49         | 9216        | 992 bytes        |
| 0x4000 (16KB)  | 16400      | LARGE      | page alloc  | N/A              |
| 0x8000 (32KB)  | 32784      | LARGE      | page alloc  | N/A              |

LFH bucket sizes used:
```
[16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
 288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 832, 896, 960, 1024,
 1088, 1152, 1216, 1280, 1344, 1408, 1472, 1536, 2048, 2560, 3072, 3584, 4096,
 5120, 6144, 7168, 8192, 9216, 10240, 11264, 12288, 13312, 14336, 15360, 16384]
```

### 1.7 TOCTOU Race Condition — The Core Vulnerability

**The Bug:** SCB+436 (compression unit size) is read at two different points with inconsistent synchronization:

1. **Allocation time** (`NtfsPrepareComplexBuffers`): `v101 = *(_DWORD *)(a3 + 436)` — read once, cached in local variable `v101`, used for buffer allocation size.

2. **Write time** (`NtfsPrepareCompressedWriteBuffer`): `*(_DWORD *)(a2 + 436)` — re-read directly from SCB for the fallback path's `FinalCompressedSize` and `memset` length.

If SCB+436 increases between these two reads, the buffer was allocated with the old (smaller) size but the fallback writes the new (larger) size → **pool buffer overflow**.

**SCB+436 Modification Path:**

`FSCTL_SET_COMPRESSION` → `NtfsSetCompression` (0x1c011fd34) → `NtfsChangeAttributeCompression` (0x1c011e8ac)

In `NtfsChangeAttributeCompression`:
```c
// Calculates new compression unit size
v12 = 16 << *(_DWORD *)(*(_QWORD *)(a2 + 176) + 488LL);  // 16 * 2^cluster_shift

// ... adjusts v12 based on VCB limits ...

// WRITES SCB+436 DIRECTLY:
*(_DWORD *)(a2 + 436) = v36;  // v36 = new compression unit size
*(_BYTE *)(a2 + 446) = v35;   // new compression engine
*(_WORD *)(a2 + 444) = v10;   // new compression format
```

**Lock Acquisition Analysis:**

- `NtfsSetCompression` acquires SCB exclusive lock: `NtfsAcquireExclusiveScbEx(a1, v10, 0)`
- `NtfsPrepareComplexBuffers` conditionally acquires SCB lock:
  ```c
  if (!*(_BYTE *)(a7 + 105) && !*(_BYTE *)(a7 + 107)) {
      NtfsAcquireExclusiveScbEx(v9, a3, 0);
      *(_BYTE *)(a7 + 107) = 1;
  }
  ```
  If `a7+105` is true, the SCB lock is **NOT acquired** by the write path.

- `NtfsSetCompression` releases the SCB lock during `NtfsFlushStreamThroughCache`:
  ```c
  NtfsReleaseAllResources(a1, v23, 0);    // RELEASE
  v27 = NtfsFlushStreamThroughCache(...);  // flush without lock
  NtfsAcquireExclusiveScbEx(a1, v10, 0);   // RE-ACQUIRE
  ```

- Oplock breaks during write can also create lock release windows

**Race Window Scenarios:**

1. **No SCB lock held** — If `a7+105` is true in the write context, the SCB lock is never acquired. Any concurrent `FSCTL_SET_COMPRESSION` can modify SCB+436 at any time.

2. **Oplock break window** — During a write, an oplock break may cause the SCB lock to be released and reacquired, creating a window for compression state change.

3. **Flush window in NtfsSetCompression** — `NtfsSetCompression` releases resources during flush. If the write path acquires the lock during this release, it reads the old SCB+436. Then `NtfsSetCompression` re-acquires and writes the new SCB+436 before the write path's fallback reads it.

### 1.8 Overflow Math (Python-Verified)

**Buffer allocation size:**
```
alloc_size = VCB[356] + SCB[436]_at_alloc_time (+ write_size if compressing)
```
- VCB[356] is typically 0x10 (16 bytes) — compression metadata overhead

**Fallback write total:**
```
write_total = SCB[436]_at_write_time  (re-read from SCB)
```

**Overflow = write_total - alloc_size:**

| Old CU (alloc) | New CU (write) | Alloc Size | Write Size | **Overflow** |
|----------------|----------------|------------|------------|-------------|
| 0x1000 (4KB)  | 0x2000 (8KB)  | 4112       | 8192       | **4080 bytes** |
| 0x1000 (4KB)  | 0x4000 (16KB) | 4112       | 16384      | **12272 bytes** |
| 0x2000 (8KB)  | 0x4000 (16KB) | 8208       | 16384      | **8176 bytes** |
| 0x4000 (16KB) | 0x8000 (32KB) | 16400      | 32768      | **16368 bytes** |

### 1.9 Overflow Content Control

**Content:** Fully user-controlled. The overflow data is the file content being written via `WriteFile`. The `memmove` at `0x1c0024859` copies from the user's write buffer (mapped via MDL or NtfsMapStream) into the compression buffer. The `memset` at `0x1c0024879` zeros the remaining space.

- `memmove` copies `v14` bytes (= `v11` = uncompressed data size) of **file content** to the buffer start
- `memset` zeros `FinalCompressedSize - v11` bytes after the data
- The overflow region = bytes past `alloc_size` in the buffer

**To write 8 controlled bytes at a specific offset:**
- Write file content that places the desired 8 bytes at the correct position
- The position = `alloc_size - data_offset_in_write` where `data_offset_in_write` is the offset within the WriteFile data
- Actually simpler: the `memmove` copies ALL `v11` bytes of uncompressed data to buffer start, so the overflow bytes are the LAST bytes of the write data that extend past `alloc_size`

**Overflow Length Control:**
- Overflow length = `new_CU - old_CU - VCB[356]` (determined by the race delta)
- The `memset` portion is zeros (not user-controlled)
- The `memmove` portion is user-controlled file content
- To get 8 controlled bytes in the overflow: write data of length >= `alloc_size + 8`, where the last 8+ bytes are the controlled payload

### 1.10 Triggering the Fallback Path

The fallback fires when `RtlCompressBuffer` returns `STATUS_BUFFER_TOO_SMALL` (0xC0000023). This happens when:
- The data doesn't compress well (compressed size >= uncompressed size)
- The output buffer is too small for the compressed result

**To reliably trigger:** Write random/incompressible data (e.g., bytes from a CSPRNG). This guarantees `RtlCompressBuffer` returns `STATUS_BUFFER_TOO_SMALL`.

### 1.11 Pool Spraying Strategy for 8-Byte Arbitrary Write

**Target LFH Bucket:** 45 (size 5120, for CU=0x1000) or 49 (size 9216, for CU=0x2000)

**Pool Layout (LFH slab):**
```
[Ntf9 buffer: 4112 bytes used | 992 bytes padding] [Pool Header: 16 bytes] [Adjacent Object Body]
 ^-- memmove starts here                                                    ^-- 8-byte target
```

**To reach the adjacent object body:**
- Overflow must travel: 992 bytes (padding) + 16 bytes (pool header) = 1008 bytes
- With 4080 bytes of overflow (CU 0x1000→0x2000), we have 4080 - 1008 = 3072 bytes of controlled data in the adjacent object

**Pool Header Corruption (first 16 bytes of adjacent slot):**
- The pool header (POOL_HEADER, 16 bytes on x64) will be corrupted by the overflow
- Fields: PreviousSize (2B), PoolIndex (2B), BlockSize (2B), PoolType (1B), flags (1B), PoolTag (4B), ProcessorPool (4B)
- Must craft the file content so bytes at overflow offset 992-1007 form a valid-looking pool header to avoid immediate BSOD
- Set PoolTag to the target object's tag, BlockSize to the correct bucket size, etc.

**8-Byte Write Target:**
- Bytes at overflow offset 1008-1015 land at offset 0 of the adjacent object body
- This can overwrite:
  - A function pointer (e.g., dispatch table entry)
  - A kernel object pointer (e.g., token pointer, process pointer)
  - A security descriptor pointer
  - A reference count or lock field

**Sprayable Objects in NonPagedPoolNx (~4096-5120 byte range):**
- Named pipe buffer extensions (NpFc tag)
- AFD endpoint data buffers
- Large ALPC message buffers
- Custom driver allocations in the same size range
- KTIMER + associated structures (if bucket-aligned)
- WorkItem / timer DPC wrappers

**Exploit Strategy:**
1. Create a compressed file with CU=0x1000
2. Spray target objects in LFH bucket 45 (5120 bytes) to fill slabs
3. Free alternate target objects to create holes
4. Trigger WriteFile with incompressible data → Ntf9 buffer fills a hole
5. Race: call FSCTL_SET_COMPRESSION to increase CU to 0x2000
6. Fallback writes 4080 bytes past buffer → corrupts adjacent object
7. First 992 bytes: padding (no effect)
8. Bytes 992-1007: crafted pool header (prevent immediate BSOD)
9. Bytes 1008-1015: 8 bytes of controlled data → overwrite target field
10. Trigger the corrupted object's handler → code execution

### 1.12 Feasibility Assessment

| Factor | Assessment |
|--------|-----------|
| Buffer overflow exists? | **YES** — TOCTOU on SCB+436, fallback writes more than allocated |
| Overflow in kernel pool? | **YES** — NonPagedPoolNx, LFH-managed |
| User-controlled overflow data? | **YES** — file content via WriteFile |
| User-controlled overflow length? | **PARTIAL** — determined by CU change delta (4080+ bytes available) |
| Can reach adjacent object? | **YES** — overflow exceeds LFH slot padding (992 < 4080) |
| Can write exactly 8 bytes? | **YES** — position payload at correct offset in WriteFile data |
| Pool header corruption issue? | **MANAGEABLE** — craft file content to fake valid header |
| Race window exists? | **YES** — multiple scenarios (no lock, oplock break, flush release) |
| Race timing difficulty? | **MODERATE** — need to win between alloc and fallback write |

---

## 2. MFT Record Overflow — Analysis

### 2.1 Function Call Chain

```
FSCTL_SET_REPARSE_POINT (user mode)
  -> NtfsSetReparsePointInternal (0x1c023bd48)
    -> FsRtlValidateReparsePointBuffer  [validates format, NOT MFT fit]
    -> NtfsChangeAttributeValue (0x1c00eadf0)
      -> [resident path: memmove into MFT record]
      -> MakeRoomForAttribute (0x1c017244c)  [tries to make room]
      -> SplitFileRecord                     [last resort for tight records]
```

### 2.2 The Vulnerability

In `NtfsSetReparsePointInternal`:
```c
NtfsChangeAttributeValue(a1, v11, 0, v43, BufferLength, v76, v77, v78, v79, v93);
//                                  ^     ^           ^
//                              offset=0  user data   user-controlled length
```

In `NtfsChangeAttributeValue`, the resident attribute check:
```c
if (a6) {  // a6 = 1 (log this change)
    v23 = Length;                    // user-controlled BufferLength
    v149 = v11 + Length;             // v11 = 0, so v149 = BufferLength
    v22 = ((v11 + Length + 7) & 0xFFFFFFF8) - ((v20 + 7) & 0xFFFFFFF8);

    // Check 1: Does the value alone exceed the file record size?
    if (v11 + Length > *(_DWORD *)(v158 + 360))  // VCB+360 = 1024
    {
        v16 = 1;  // Convert to non-resident
        v151 = 1;
    }
}
```

The check at LABEL_7:
```c
if (v19 || v16 || (condition1 && condition2))
//  v19 = attribute is non-resident
//  v16 = BufferLength > 1024 (file record size)
//  condition1 = v22 (size delta) > available space in record
//  condition2 = new_total >= VCB[344] (MaximumResidentAttributeSize threshold)
```

**The Bug:** The check uses `v11 + Length > VCB[360]` (i.e., `0 + BufferLength > 1024`) to decide whether to convert to non-resident. But this only checks if the VALUE alone exceeds the record size. It does NOT check whether the value + existing attributes exceed the record.

If `VCB[344]` (MaximumResidentAttributeSize) > 1024, there's a window where:
- `BufferLength <= 1024` → passes check 1 (no conversion)
- `new_total < VCB[344]` → passes check 2 (no conversion)
- But `BufferLength + existing_attributes > 1024` → overflow!

### 2.3 MakeRoomForAttribute Analysis (0x1c017244c)

```c
FindLargestMoveableAttributes(VCB, fileRecord, ...);
// Iterates up to 3 movable attributes:
for (i = 0; i < 3; i++) {
    if (attrSize >= VCB[344]) {
        NtfsConvertToNonresident(...);  // Move large attr to non-resident
    }
    // Or: MoveAttributeToOwnRecord (move to separate MFT record)
    // Or: NtfsPushIndexRoot (push index root to non-resident)
}
// If still doesn't fit after 3 attempts:
SplitFileRecord(...);  // Split into multiple MFT records with attribute list
```

**Potential edge cases:**
- If all movable attributes are < VCB[344], they won't be converted to non-resident
- MoveAttributeToOwnRecord moves them to other MFT records, but if the target record is also full, the move may not free enough space
- SplitFileRecord creates an attribute list, but the list entry itself takes space
- Race condition: file record state could change between MakeRoomForAttribute and the memmove

### 2.4 The memmove Overflow (LABEL_20 in NtfsChangeAttributeValue)

```c
LABEL_20:
    v31 = v18 - v29;  // offset of attribute within file record
    v50 = (_DWORD *)(v49 + v31);  // pointer into MFT record

    v160 = (v155 + Size + 7) & 0xFFFFFFF8;  // new aligned size

    // Shift subsequent attributes to make room — CAN OVERFLOW MFT RECORD
    memmove((char *)v50 + v160,
            (char *)v50 + v51,
            *(_DWORD *)(v49 + 24) - v51 - v31);

    // Copy user data into attribute value — CAN OVERFLOW MFT RECORD
    memmove(v45, v10, v23);  // v10 = user buffer, v23 = BufferLength
```

Total bytes written = `v160 + (record_used - v51 - v31) + v23`
If this exceeds 1024 (MFT record size), overflow occurs.

### 2.5 MFT Record Pool Details

- **MFT record size:** 1024 bytes (standard NTFS)
- **Storage:** Cached file buffer (via CcPinMappedData), NOT a pool allocation
- **LFH bucket:** 1024 (bucket 31) — but this is for the cache buffer, not a pool object
- **Pool tag for cache buffers:** Varies (system cache managed by MM)

### 2.6 MFT Overflow Exploitability Assessment

| Factor | Assessment |
|--------|-----------|
| Overflow exists? | **POSSIBLE** — depends on VCB[344] value and MakeRoomForAttribute edge cases |
| Overflow in kernel pool? | **NO** — MFT record is a cached file buffer, not pool memory |
| User-controlled data? | **YES** — reparse point buffer from FSCTL_SET_REPARSE_POINT |
| User-controlled length? | **PARTIAL** — limited by FsRtlValidateReparsePointBuffer (max 16384) |
| 8-byte arbitrary write? | **NO** — overflow is in system cache, not adjacent pool objects |
| Exploit primitive? | **File system corruption** — can corrupt MFT on disk, create fake entries, etc. |

**Conclusion for MFT overflow:** This is a file system corruption primitive, not a pool corruption primitive. It cannot directly provide an 8-byte arbitrary kernel write into an adjacent pool object. It could be used for:
- Persistent backdoor via corrupted MFT entries
- Denial of service (BSOD via invalid MFT)
- Potential privilege escalation if MFT corruption allows reading/writing arbitrary sectors
- But NOT for direct kernel code execution via pool corruption

---

## 3. VCB Field Reference

From reverse engineering ntfs.sys:

| VCB Offset | Field | Value/Usage |
|------------|-------|-------------|
| +344 (0x158) | MaximumResidentAttributeSize threshold | Controls non-resident conversion in MakeRoomForAttribute |
| +356 (0x164) | Compression metadata overhead | Subtracted from CU for RtlCompressBuffer output size; added to alloc size |
| +360 (0x168) | BytesPerFileRecordSegment | Typically 1024; compared against BufferLength for resident check |
| +480 (0x1E0) | BytesPerCluster | Used for allocation calculations |
| +488 (0x1E8) | ClusterShift (log2 of cluster size) | Used for VBN-to-LBN conversion |

## 4. SCB Field Reference

| SCB Offset | Field | Value/Usage |
|------------|-------|-------------|
| +176 (0xB0) | Pointer to VCB-like structure | Contains VCB[356] for compression calculations |
| +264 (0x108) | Stream pointer | NULL → MDL path in PrepareCompressedWriteBuffer |
| +436 (0x1B4) | **CompressionUnitSize** | **CRITICAL: TOCTOU field** — read at alloc time vs write time |
| +444 (0x1BC) | CompressionFormat (WORD) | Compression engine + format flags |
| +446 (0x1BE) | CompressionEngine (BYTE) | Engine selection |
| +496 (0x1F0) | SCB flags (DWORD) | 0x4000, 0x10000, 0x40000, 0x80000, etc. |

## 5. Pool Tag Reference

| Tag | Value | Pool Type | Usage |
|-----|-------|-----------|-------|
| Ntf9 | 0x3966744E | NonPagedPoolNxCacheAligned (0x204) | Compression buffers (MmBuildMdlForNonPagedPool) |
| NtfA | 0x4146744E | NonPagedPoolNx + session (0x210) | Temp buffers in NtfsChangeAttributeValue |
| Ntfd | (not searched) | PagedPool? | MFT data buffers |

## 6. Final Verdict

### Can the compression buffer overflow provide an 8-byte arbitrary kernel write?

**YES, conditionally.** The TOCTOU race on SCB+436 can overflow a NonPagedPoolNx LFH-managed buffer with user-controlled file content. The overflow can reach an adjacent pool object in the same LFH slab. With careful crafting of the WriteFile payload, 8 controlled bytes can be placed at a specific offset within the adjacent object body. The pool header corruption (16 bytes between objects) must be handled by crafting the file content to form a valid-looking pool header.

**Key challenges:**
1. Winning the race between buffer allocation and fallback write (moderate difficulty)
2. Pool header corruption must not cause immediate BSOD (craftable)
3. Finding the right target object in LFH bucket 45 (5120) or 49 (9216)
4. The SCB lock may prevent the race in some code paths (need a7+105=true or oplock break window)

### Can the MFT record overflow provide an 8-byte arbitrary kernel write?

**NO.** The MFT record is a cached file buffer, not a pool allocation. The overflow corrupts file system metadata in the system cache, not adjacent pool objects. This is a file system corruption primitive, not a pool corruption primitive.

---

## Appendix A: Key Addresses

| Address | Function |
|---------|----------|
| 0x1c0024614 | NtfsPrepareCompressedWriteBuffer |
| 0x1c0023fb8 | NtfsPrepareComplexBuffers |
| 0x1c0024da8 | NtfsAllocateCompressionBuffer |
| 0x1c0024fb8 | NtfsCreateMdlAndBuffer |
| 0x1c0024859 | memmove (fallback copy — overflow start) |
| 0x1c0024879 | memset (fallback zero — overflow continuation) |
| 0x1c00eadf0 | NtfsChangeAttributeValue |
| 0x1c023bd48 | NtfsSetReparsePointInternal |
| 0x1c017244c | MakeRoomForAttribute |
| 0x1c011fd34 | NtfsSetCompression |
| 0x1c011e8ac | NtfsChangeAttributeCompression |
| 0x1c0095018 | dword_1C0095018 (allocation cap = 0xFFFFFFFF) |
| 0x1c0095168 | PoolType global (= 0xFFFFFFFF) |

## Appendix B: Python Verification Results

```
Ntf9 pool tag: 0x3966744E = 963015758
Pool type 0x0204: NonPagedPoolNxCacheAligned
-1073741789 & 0xFFFFFFFF = 0xC0000023 = STATUS_BUFFER_TOO_SMALL
dword_1C0095018 = 0xFFFFFFFF (no allocation cap)
PoolType global = 0xFFFFFFFF

LFH buckets:
  CU=0x1000: alloc=4112 -> LFH bucket 45 (size 5120)
  CU=0x2000: alloc=8208 -> LFH bucket 49 (size 9216)
  CU=0x4000+: LARGE allocation (page-aligned, no LFH)

Overflow amounts:
  0x1000 -> 0x2000: 4080 bytes overflow
  0x1000 -> 0x4000: 12272 bytes overflow
  0x2000 -> 0x4000: 8176 bytes overflow

MFT record: 1024 bytes, LFH bucket 31
Max reparse buffer: 16384 bytes (0x4000)
```
