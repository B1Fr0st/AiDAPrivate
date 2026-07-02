# ntfs.sys Kernel Vulnerability Analysis - 8-Byte Arbitrary Kernel Write Hunt

## 1. Binary Survey

| Property | Value |
|----------|-------|
| Module | ntfs.sys |
| Architecture | x64 |
| Base Address | 0x1c0000000 |
| Image Size | 0x2d7000 (~2.8MB) |
| MD5 | 4523af0cd38f868971651691dbd3853d |
| SHA256 | 4df3be53bc3048aed67dacfc3ea1be61c3d8fe2755669710c8ce604ce39884f1 |
| Total Functions | 2730 |
| Named Functions | 2721 |
| Total Strings | 2088 |
| Total Segments | 11 |

### Segment Layout
| Segment | Start | End | Size | Perm |
|---------|-------|-----|------|------|
| .text | 0x1c0001000 | 0x1c0067000 | 0x66000 | rx |
| .rdata | 0x1c0067000 | 0x1c0094000 | 0x2d000 | r |
| .data | 0x1c0094000 | 0x1c00b1000 | 0x1d000 | rw |
| .pdata | 0x1c00b1000 | 0x1c00c0000 | 0xf000 | r |
| PAGE | 0x1c00c9000 | 0x1c0292000 | 0x1c9000 | rx |
| INIT | 0x1c0292000 | 0x1c0296000 | 0x4000 | rx |

### Key Imports
- ExAllocatePoolWithTag (ntoskrnl) - 1122 call sites
- ExAllocateFromNPagedLookasideList - 97 call sites
- RtlCompressBuffer / RtlGetCompressionWorkSpaceSize
- FsRtlValidateReparsePointBuffer
- CcPinMappedData / CcCopyWriteEx / CcFlushCache
- MmBuildMdlForNonPagedPool / IoAllocateMdl
- ObReferenceObjectByHandle

### Top Functions by Xref Count
| Function | Address | Xrefs | Type |
|----------|---------|-------|------|
| NtfsStatusTraceAndDebugInternal | 0x1c0018f70 | 3362 | dispatcher |
| NtfsRaiseStatusInternal | 0x1c0001e34 | 1196 | complex |
| memset | 0x1c0034b00 | 1024 | leaf |
| NtfsReleaseFcbEx | 0x1c00119a0 | 799 | complex |
| NtfsExtendedCompleteRequestInternal | 0x1c0011c70 | 752 | dispatcher |
| NtfsCleanupAttributeContext | 0x1c00fdae0 | 590 | complex |
| memmove | 0x1c0034840 | 549 | leaf |
| NtfsLookupInFileRecord | 0x1c00f3c90 | 382 | dispatcher |

---

## 2. User-Mode-Reachable IOCTL/FSCTL Handlers

### Dispatch Chain
```
User-mode -> NtfsFsdFileSystemControl (0x1c01256f0) -> NtfsCommonFileSystemControl (0x1c0155a84)
  -> NtfsUserFsRequest (0x1c0125b90) [cases 0,4] -> NtfsMountVolume (case 1)

User-mode -> NtfsFsdDeviceControl (0x1c0125570) -> NtfsCommonDeviceControl (0x1c0205790)
  -> IOCTL 0x7C004: STORAGE_MANAGE_DATA_SET_ATTRIBUTES
  -> IOCTL 0x538000: Volume snapshot/freeze
```

### FSCTL Codes (32 found in NtfsUserFsRequest)

| FSCTL | Hex | Handler |
|-------|-----|---------|
| LOCK_VOLUME | 0x90018 | NtfsLockVolume |
| UNLOCK_VOLUME | 0x9001C | NtfsUnlockVolume |
| DISMOUNT_VOLUME | 0x90020 | NtfsDismountVolume |
| SET_COMPRESSION | 0x9C040 | NtfsSetCompression |
| MARK_HANDLE | 0x900FC | NtfsMarkHandle |
| FILE_LEVEL_TRIM | 0x90264 | NtfsFileLevelTrim |
| QUERY_ALLOCATED_RANGES | 0x94024 | NtfsQueryAllocatedRanges |
| SET_REPARSE_POINT | 0x900A4 | NtfsSetReparsePointEx |
| GET_REPARSE_POINT | 0x900A8 | NtfsGetReparsePoint |
| DELETE_REPARSE_POINT | 0x900AC | NtfsDeleteReparsePoint |
| SET_SPARSE | 0x900C4 | NtfsSetSparse |
| READ_USN_JOURNAL | 0x900AC | NtfsReadUsnJournal |
| MOVE_FILE | 0x90094 | NtfsDefragFileInternal |
| OFFLOAD_READ | 0x90A64 | NtfsOffloadRead |
| GET_RETRIEVAL_POINTERS | 0x90073 | NtfsGetRetrievalPointers |
| GET_VOLUME_BITMAP | 0x9006F | NtfsGetVolumeBitmap |
| GET_NTFS_VOLUME_DATA | 0x90064 | NtfsGetVolumeData |
| QUERY_FILE_REGIONS | 0x90340 | NtfsQueryFileRegions |
| TxF FSCTLs | 0x9416C | TxfFsctl |
| PREFETCH_FILE | 0x900EC | NtfsPrefetchFile |
| STORAGE_RESERVE | 0x903EC | NtfsQueryStorageReserve |

---

## 3. Pool Allocations - Sizes, Types, Tags

### Constant-Size in Target LFH Ranges

| Function | Address | Size | Tag | Pool Type | LFH Bucket |
|----------|---------|------|-----|-----------|------------|
| NtfsQueryOffloadSupport | 0x1c00497bd | 1024 | varies | NonPagedPoolNx | **1024** |
| EfspCheckEfsPolicy | 0x1c01e7f5a | 1024 | varies | NonPagedPoolNx | **1024** |
| NtfsCreateFcb | 0x1c01102b7 | 352 | ftNF | NonPagedPool | 384 |
| NtfsCommonDeviceControl | 0x1c02059af | 56 | Ntf0 | NonPagedPoolNx | 64 |

### Variable-Size (User-Controlled)

| Function | Size Source | Tag | Pool Type | Notes |
|----------|-------------|-----|-----------|-------|
| NtfsCreateMdlAndBuffer | *a5 (SCB) | Ntf9 | NonPagedPool | Compression buffers |
| NtfsDefragFileInternal | User (cap 1MB) | NtFD | NonPagedPool | Defrag data |
| NtfsChangeAttributeValue | Length | NtfA | NonPagedPoolNx | Attribute write |
| NtfsAllocateNonpagedFcb | NumberOfBytes | caller | NonPagedPool | FCB |

### Pool Tags Decoded
| Hex | ASCII | Usage |
|-----|-------|-------|
| 0x3966744E | Ntf9 | Compression/MDL buffers |
| 0x4446744E | NtFD | Defrag buffers |
| 0x3066744E | Ntf0 | TxF thaw/snapshot |
| 0x4146744E | NtfA | Attribute temp buffers |

### NtfsAllocateNonpagedFcb (0x1c0023b80)
```cpp
char *__fastcall NtfsAllocateNonpagedFcb(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag) {
  char *result = (char *)ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
  if (result) {
    memset(result, 0, NumberOfBytes);
    KeInitializeEvent((PRKEVENT)(result + 32), SynchronizationEvent, 0);
    ExInitializeResourceLite((PERESOURCE)(result + 64));
    if (NumberOfBytes == 352)
      ExInitializeResourceLite((PERESOURCE)(result + 240));
  }
  return result;
}
```
- 352 bytes -> LFH bucket 384, very frequent, excellent for heap grooming

### NtfsCreateMdlAndBuffer (0x1c0024ea8)
```cpp
_QWORD *__fastcall NtfsCreateMdlAndBuffer(__int64 a1, __int64 a2, unsigned __int16 a3,
    POOL_TYPE a4, ULONG *a5, struct _MDL **a6, _QWORD *a7) {
  // Tag: Ntf9, Size from *a5, Pool type from a4
  PoolWithTag = ExAllocatePoolWithTag(a4, *a5, 0x3966744Eu);
  // Then IoAllocateMdl + MmBuildMdlForNonPagedPool
}
```

---

## 4. Vulnerability Analysis

### Vector 1: Compression Buffer Overflow - NtfsPrepareCompressedWriteBuffer
**Address:** 0x1c0024614 | **Risk:** HIGH

```cpp
__int64 __fastcall NtfsPrepareCompressedWriteBuffer(
    __int64 a1, __int64 a2, __int64 a3, __int64 a4, size_t Size, __int64 a6) {
  // a2 = SCB, a6 = compression context
  CompressionWorkSpaceSize = RtlGetCompressionWorkSpaceSize(
      (unsigned __int8)*(_WORD *)(a2 + 444) + 1, &v23, &v25);
  NtfsCreateMdlAndBuffer(a1, v10, 3, 516, &v23, 0, v9 + 96);

  v12 = MmMapLockedPagesSpecifyCache((PMDL)v20, 0, MmCached, nullptr, 0, 0x40000010u);
  v11 = *(_DWORD *)(*(_QWORD *)(v9 + 48) + 40LL);

  // Copies data to END of compression buffer
  v15 = (void *)(*(_QWORD *)(v9 + 32) + *(unsigned int *)(v9 + 40) - v11);
  memmove(v15, v12, v11);  // 0x1c002475b

  v16 = RtlCompressBuffer(
      (unsigned __int8)*(_WORD *)(a2 + 444) + 1, (PUCHAR)v15, v11,
      *(PUCHAR *)(v9 + 32),
      *(_DWORD *)(a2 + 436) - *(_DWORD *)(*(_QWORD *)(a2 + 176) + 356LL),
      0x1000u, &FinalCompressedSize, *(PVOID *)(v9 + 96));

  // OVERFLOW PATH: When compression fails (STATUS_BUFFER_OVERFLOW)
  if (v16 == -1073741789) {
    FinalCompressedSize = *(_DWORD *)(a2 + 436);  // SCB compression unit size
    memmove(*(void **)(v9 + 32), v15, v14);  // 0x1c0024859 - to buffer START
    if (FinalCompressedSize > v11)
      memset((void *)(v14 + *(_QWORD *)(v9 + 32)), 0,
             FinalCompressedSize - v11);     // 0x1c0024879 - ZEROES remaining
  }

  v18 = -*(_DWORD *)(*(_QWORD *)(a2 + 176) + 356LL) &
        (v17 + *(_DWORD *)(*(_QWORD *)(a2 + 176) + 356LL) - 1);
  if (v18 > v17)
    memset((void *)(*(_QWORD *)(v9 + 32) + v17), 0, v18 - v17);
}
```

**Analysis:**
- Buffer at *(v9+32) allocated with size from SCB+436 (compression unit size)
- When RtlCompressBuffer returns STATUS_BUFFER_OVERFLOW, stores uncompressed data
- memmove at 0x1c0024859 copies v14 bytes to buffer start -> OVERFLOW if v14 > buffer size
- memset at 0x1c0024879 zeroes FinalCompressedSize-v11 bytes -> OVERFLOW if unit size > buffer
- Buffer size from SCB field+436, set by NtfsSetCompression
- If SCB field manipulated via race between NtfsSetCompression and WriteFile -> overflow
- Pool tag Ntf9, NonPagedPool/NonPagedPoolNx
- 8-byte write from file content (user-controlled via WriteFile)

### Vector 2: MFT Record Overflow - NtfsChangeAttributeValue
**Address:** 0x1c00eadf0 | **Risk:** MEDIUM-HIGH

```cpp
void __fastcall NtfsChangeAttributeValue(__int64 a1, __int64 a2, unsigned int a3,
    char *a4, unsigned int Length, char a6, unsigned __int8 a7, ...) {
  // a2=FCB, a3=ValueOffset, a4=Source(user data), Length=user-controlled
  // v18=attribute in MFT record, v20=current size, v149=a3+Length, v22=size delta

  if (v22 > 0) {
    v59 = (*(unsigned __int16 *)(v18 + 20) + v149 + 7) & 0xFFFFFFF8;
    NtfsPinMappedData(..., record_size, ...);
    if (record_has_room) {
      memmove((void *)(v43 + v44), v10, v23);  // copies user data to MFT record
    } else {
      // Becomes non-resident
    }
  }
  // MFT record = 1024 bytes pool-backed
  // If v22 (size delta) overflows as 32-bit int -> wrong shift -> overflow
}
```

- MFT records are 1024 bytes (LFH bucket 1024)
- Resident attribute growth uses memmove to shift data in MFT record
- User-controlled Length for reparse points (FSCTL_SET_REPARSE_POINT InputBufferLength-32)
- If size delta integer overflow -> memmove shifts wrong amount -> pool overflow

### Vector 3: Defrag Race Condition - NtfsDefragFileInternal
**Address:** 0x1c00cd304 (0x1afc bytes) | **Risk:** MEDIUM

```cpp
__int64 __fastcall NtfsDefragFileInternal(...) {
  // User-controlled allocation:
  v35 = (unsigned __int64)*(unsigned int *)(a5 + 24) << cluster_shift;
  if (v35 > 0x100000) v35 = 0x100000;
  v38 = ExAllocatePoolWithTag((POOL_TYPE)512, (unsigned int)v35, 0x4446744Eu);
  v39 = IoAllocateMdl(v38, v37, 0, 0, nullptr);
  MmBuildMdlForNonPagedPool(v39);

  while (1) {
    v58 = NtfsLookupAllocation(a1, a3, *(_QWORD *)(v57 + 8), &v109, &v110);
    Clusters = NtfsPreAllocateClusters(a1, 0, ...);
    // RELEASES FCB lock
    NtfsReleaseFcbEx(a1, *(_QWORD *)(a3 + 168), 0);
    // Async I/O while lock released
    NtfsSingleAsync(a1, ..., v109 << shift, v69, ...);
    NtfsWaitOnIo(a1, ...);
    NtfsSingleAsync(a1, ..., dest_offset, v106, ...);
    // RE-ACQUIRES FCB lock
    NtfsAcquireExclusiveFcb(a1, *(_QWORD *)(a3 + 168), a3, 8);
    NtfsReallocateRange(a1, a3, *(_QWORD *)(v105 + 8), ...);
  }
}
```

- FCB lock released between NtfsLookupAllocation and NtfsReallocateRange
- During unlock: another thread can truncate, change compression, delete file
- NtfsReallocateRange uses user-provided cluster offset
- Pool buffer (user-sized NtFD tag) used for async I/O during race
- If allocation changes -> wrong cluster count -> buffer overflow

### Vector 4: NtfsMarkHandle CCB Write
**Address:** 0x1c01a054c (0x157c bytes) | **Risk:** MEDIUM

```cpp
__int64 __fastcall NtfsMarkHandle(_DWORD *Context, PIRP Irp) {
  if (IoIs32bitProcess(Irp)) {
    // Size >= 0xC, copies 32-bit struct
    LODWORD(v76) = *(_DWORD *)&MasterIrp->Type;
    v17 = (struct _IRP *)&v76;
  } else {
    // Size >= 0x18
    v17 = Irp->AssociatedIrp.MasterIrp;
  }
  // CRITICAL: User Type OR-written to CCB
  *(_DWORD *)(v79 + 100) |= *(_DWORD *)&v17->Type;
  // v79 = CCB (kernel pool), offset 100
  // User-controlled 32-bit from MARK_HANDLE_INFO.Type
}
```

- OR-write of user 32-bit value to CCB+100 (kernel pool)
- CCB location controllable via heap grooming
- OR operation only sets bits (4-byte, not 8-byte)

### Vector 5: NtfsQueryAllocatedRanges Truncation
**Address:** 0x1c01597a0 | **Risk:** LOW-MEDIUM

```cpp
v15 = *(unsigned int *)(v4 + 8);  // Output buffer length (user)
v82 = v15;  // 32-bit tracking
// Output loop:
while (1) {
  if (v82 < 0x10) { v55 = STATUS_BUFFER_OVERFLOW; break; }
  v82 -= 16; v17 += 2;
  *v17 = v25 << shift; v17[1] = v36 << shift;
}
// CRITICAL: 32-bit truncation
*(_QWORD *)(v12 + 56) = (unsigned int)((_DWORD)v17 - (_DWORD)v16 + 16);
```

### Vector 6: Reparse Point Chain
Entry: NtfsSetReparsePointEx (0x1c023b910) -> NtfsSetReparsePointInternal (0x1c023bd48) -> NtfsChangeAttributeValue

```cpp
// NtfsSetReparsePointEx
v14 = *(_DWORD *)(v5 + 16);  // InputBufferLength
if (v14 < 0x20) return STATUS_BUFFER_OVERFLOW;
v11 = NtfsSetReparsePointInternal(a1, a2, v21, v9,
    (int *)(a2[3] + 4LL), (_QWORD *)(a2[3] + 8LL),
    *(_DWORD *)a2[3], v14 - 32,  // BufferLength USER-CONTROLLED
    (PREPARSE_DATA_BUFFER)(a2[3] + 32LL));

// NtfsSetReparsePointInternal
result = FsRtlValidateReparsePointBuffer(BufferLength, ReparseBuffer);
if (result < 0) return result;
NtfsChangeAttributeValue(a1, v11, 0, v43, BufferLength, ...);
// BufferLength user-controlled, passed to attribute write
```

---

## 5. LFH Bucket Analysis

### Bucket 1024 (1009-1024 bytes)
- NtfsQueryOffloadSupport: 1024 bytes, NonPagedPoolNx
- EfspCheckEfsPolicy: 1024 bytes, NonPagedPoolNx
- MFT records: typically 1024 bytes (cache-backed pool)
- Most promising for 8-byte write target alignment

### Bucket 640 (625-640 bytes)
- No constant-size allocations found
- Variable from NtfsCreateMdlAndBuffer could land here

### Bucket 384 (369-384 bytes)
- NtfsCreateFcb: 352 bytes, NonPagedPool
- Very frequent (every file open), excellent for heap grooming

### Other
- Bucket 64: NtfsCommonDeviceControl event (56 bytes, Ntf0)
- Bucket 32: ERESOURCE structures

---

## 6. Most Promising Attack Vectors Ranked

### Rank 1: Compression Buffer Overflow (NtfsPrepareCompressedWriteBuffer)
**Address:** 0x1c0024614 | **Viability:** HIGH

- Trigger: WriteFile to compressed file
- Buffer size from SCB+436 (compression unit size)
- When RtlCompressBuffer fails -> raw copy -> memmove/memset overflow
- Race with FSCTL_SET_COMPRESSION to change compression unit size
- Pool tag Ntf9, 8-byte write from file content
- Attack: Create compressed file -> Thread1 writes, Thread2 races compression change
- -> overflow into adjacent LFH bucket 1024 allocation

### Rank 2: MFT Record Overflow via Reparse Point
**Address:** 0x1c00eadf0 | **Viability:** MEDIUM-HIGH

- Trigger: FSCTL_SET_REPARSE_POINT with crafted buffer
- MFT record = 1024 bytes (LFH bucket 1024)
- Resident attribute growth -> memmove shift -> overflow if delta overflows
- Attack: Small file -> set reparse point near MFT boundary -> overflow

### Rank 3: Defrag Race Condition
**Address:** 0x1c00cd304 | **Viability:** MEDIUM

- Trigger: FSCTL_MOVE_FILE + concurrent file modification
- FCB lock released between lookup and reallocation
- Race: truncate/modify file during unlock window
- Pool buffer overflow with file data

### Rank 4: NtfsMarkHandle CCB Write
**Address:** 0x1c01a054c | **Viability:** MEDIUM

- Trigger: FSCTL_MARK_HANDLE with crafted MARK_HANDLE_INFO
- 4-byte OR-write to CCB+100 (kernel pool)
- Heap groom CCB adjacent to target -> set bits in target

### Rank 5: NtfsQueryAllocatedRanges Truncation
**Address:** 0x1c01597a0 | **Viability:** LOW-MEDIUM

- 32-bit truncation in information field
- Unlikely controlled 8-byte write

---

## 7. Write-What-Where Patterns

1. memmove to pool buffer (NtfsPrepareCompressedWriteBuffer 0x1c0024859)
   - Source: file data, Dest: compression buffer (Ntf9), Size: from SCB

2. memset to pool buffer (NtfsPrepareCompressedWriteBuffer 0x1c0024879)
   - Dest: compression buffer+offset, Size: FinalCompressedSize-v11

3. memmove for MFT record (NtfsChangeAttributeValue)
   - Source: user reparse data, Dest: MFT record (1024B pool), Size: user Length

4. OR-write to CCB (NtfsMarkHandle)
   - Value: user 32-bit MARK_HANDLE_INFO.Type, Dest: CCB+100

5. ObReferenceObjectByHandle (NtfsMarkHandle)
   - User handle in MARK_HANDLE_INFO.MdlAddress, type-checked

---

## 8. Decompilation Index

| Function | Address | Size | Key Finding |
|----------|---------|------|-------------|
| NtfsCommonFileSystemControl | 0x1c0155a84 | 0x1db | FSCTL dispatch |
| NtfsCommonDeviceControl | 0x1c0205790 | 0x977 | Device IOCTL |
| NtfsAllocateCompressionBuffer | 0x1c0024da8 | 0xf7 | Compression alloc |
| NtfsPrepareCompressedWriteBuffer | 0x1c0024614 | 0x3b2 | OVERFLOW: memmove/memset |
| NtfsDeallocateCompressionBuffer | 0x1c0023f1c | 0x94 | Compression free |
| NtfsSetCompression | 0x1c011fd34 | 0xbd9 | SET_COMPRESSION |
| NtfsSetReparsePointEx | 0x1c023b910 | 0x42f | SET_REPARSE_POINT entry |
| NtfsSetReparsePointInternal | 0x1c023bd48 | 0x1264 | Reparse internal |
| NtfsChangeAttributeValue | 0x1c00eadf0 | ~0x2000 | OVERFLOW: MFT record |
| NtfsDefragFileInternal | 0x1c00cd304 | 0x1afc | RACE: TOCTOU defrag |
| NtfsMarkHandle | 0x1c01a054c | 0x157c | WRITE: OR to CCB+100 |
| NtfsQueryAllocatedRanges | 0x1c01597a0 | 0xab2 | TRUNC: 32-bit info |
| NtfsSparseOverAllocate | 0x1c022a21c | 0x4ac | Sparse over-alloc |
| NtfsAllocateNonpagedFcb | 0x1c0023b80 | 0xa4 | FCB pool alloc |
| NtfsCreateMdlAndBuffer | 0x1c0024ea8 | ~0x200 | MDL buffer alloc |
| NtfsUserFsRequest | 0x1c0125b90 | 0x847 | FSCTL switch (285 blocks) |
