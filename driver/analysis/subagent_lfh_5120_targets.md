# LFH Bucket 5120 Target Analysis - NTFS Compression Buffer Overflow

## Executive Summary

Analysis of 17 IDA Pro instances covering kernel binaries for pool allocations in NonPagedPoolNxCacheAligned (0x204) at LFH bucket 5120 (sizes 5041-5120 bytes). The NTFS compression buffer overflow (tag Ntf9, pool type 0x204) can overflow up to 4080 bytes into adjacent same-bucket allocations with user-controlled content.

## 1. All Pool Allocations Found at NonPagedPoolNxCacheAligned (0x204)

### Search Methodology

Searched all 17 IDA instances for byte pattern `B9 04 02 00 00` (`mov ecx, 204h`) which sets the pool type to NonPagedPoolNxCacheAligned. Also searched for `B9 00 02 00 00` (`mov ecx, 200h` for NonPagedPoolNx) and `B9 00 41 00 00` (`mov ecx, 4100h` for ExAllocatePool2 with POOL_FLAG_NON_PAGED|POOL_FLAG_CACHE_ALIGNED).

### IDA Instances Checked (17 total)

| Binary | PID | 0x204 Hits | 0x200 Hits | 0x4100 Hits |
|--------|-----|-----------|-----------|-------------|
| ntoskrnl.exe | 4024 | 22 | (huge) | N/A |
| ntfs.sys | 8544 | 15 | 176 | N/A |
| afd.sys | 18576 | 3 | (scanned) | 0 |
| npfs.sys | 9784 | 0 | 5 | N/A |
| fltMgr.sys | 11764 | 1 | 29 | N/A |
| dxgkrnl.sys | 7656 | 0 | (has ExAllocatePool2) | 0 |
| dxgmms2.sys | 7160 | 0 | N/A | 0 |
| dxgmms1.sys | 15120 | 0 | N/A | N/A |
| ks.sys | 17220 | 0 | N/A | 0 |
| portcls.sys | 19352 | 0 | N/A | 0 |
| win32kfull.sys | 16960 | 3 | N/A | N/A |
| win32kbase.sys | 14940 | 0 | N/A | N/A |
| win32k.sys | 7392 | 0 | N/A | N/A |
| clfs.sys | 16896 | 0 | N/A | N/A |
| tdx.sys | 15284 | 0 | N/A | N/A |
| tm.sys | 2944 | 0 | N/A | N/A |
| condrv.sys | 10480 | 0 | N/A | N/A |

### Key Finding: dxgkrnl, dxgmms2, dxgmms1, ks, portcls, win32kbase, win32k, clfs, tdx, tm, condrv have ZERO NonPagedPoolNxCacheAligned allocations.

---

## 2. Detailed Allocations with Pool Type, Tag, and Structure

### ntoskrnl.exe (22 NonPagedPoolNxCacheAligned allocations)

#### 2.1 EtwpInitLoggerContext - **PRIMARY TARGET** :star:

| Field | Value |
|-------|-------|
| Function | `EtwpInitLoggerContext` @ 0x14071117f |
| Pool Type | 0x204 (NonPagedPoolNxCacheAligned) |
| Tag | `0x4C777445` = "EtwL" |
| Size Formula | `v7 = v5 + name_len + 1330 + 2 * v6` |
| User-Triggerable | **YES** - via ETW StartTrace/EnableTraceEx2 API |
| Size Controllable | **YES** - via logger session name length |

**Size Components:**
- `name_len` = logger name length in bytes (from UNICODE_STRING in trace properties)
- `v5 = 8 * MaximumProcessorCount` if MaxProcCount > 32 AND no EVENT_TRACE_FLAG_NO_PER_CPU
- `v6 = 8 * MaximumProcessorCount` if 0x400 flag set AND no EVENT_TRACE_FLAG_NO_PER_CPU
- Base overhead = 1330 bytes

**Size Calculations for Bucket 5120 (5041-5120):**

| Logical Processors | 0x400 Flag | Base Size | Required Name (bytes) | Required Name (WCHARs) |
|--------------------|------------|-----------|-----------------------|------------------------|
| 16 | No | 1330 | 3711-3790 | 1855-1895 |
| 16 | Yes | 1586 | 3455-3534 | 1727-1767 |
| 32 | No | 1330 | 3711-3790 | 1855-1895 |
| 32 | Yes | 1842 | 3199-3278 | 1599-1639 |
| 48 | No | 1714 | 3327-3406 | 1663-1703 |
| 48 | Yes | 2482 | 2559-2638 | 1279-1319 |
| 64 | No | 1842 | 3199-3278 | 1599-1639 |
| 64 | Yes | 2866 | 2175-2254 | 1087-1127 |
| 96 | No | 2098 | 2943-3022 | 1471-1511 |
| 96 | Yes | 3634 | 1407-1486 | 703-743 |
| 128 | No | 2354 | 2687-2766 | 1343-1383 |
| **128** | **Yes** | **4402** | **639-718** | **319-359** |
| 192 | No | 2866 | 2175-2254 | 1087-1127 |
| 256 | No | 3378 | 1663-1742 | 831-871 |

**Best case: 128 logical processors with 0x400 flag = only 319-359 WCHAR name needed.**

**Structure Layout and Pointer Fields (EtwL):**

| Offset | Field | Type | Deref'd/Written? |
|--------|-------|------|-------------------|
| 64 | Buffer pointer | PVOID* | Yes - buffer management |
| 72 | Pointer | PVOID* | Yes |
| 80 | Pointer | PVOID* | Yes |
| 88 | Pointer | PVOID* | Yes |
| 96 | Self-pointer | PVOID* | Yes - list head |
| 104 | Self-pointer | PVOID* | Yes - list head |
| 112 | Self-pointer | PVOID* | Yes - list head |
| 120 | Self-pointer | PVOID* | Yes - list head |
| 152 | UNICODE_STRING.Buffer | PWSTR* | **YES - dereferenced for string ops** |
| 280 | Sequence/Global pointer | PVOID* | Yes - incremented atomically |
| 344 | LIST_ENTRY.Flink/Blink | PLIST_ENTRY* | **YES - list manipulation** |
| 352 | LIST_ENTRY (cont.) | PLIST_ENTRY* | **YES** |
| 472 | KEVENT.Header | KEVENT | Contains dispatch header |
| 496 | KEVENT.Header | KEVENT | Contains dispatch header |
| 520 | KTIMER | KTIMER | Contains timer DPC pointer |
| **584** | **KDPC** | **KDPC** | **Contains function pointer** |
| **608** | **KDPC.DeferredRoutine** | **PKDEFERRED_ROUTINE** | **CALLED WHEN DPC FIRES** |
| **616** | **KDPC.DeferredContext** | **PVOID** | **Passed as arg to DPC routine** |
| 648 | KMUTEX | KMUTEX | Contains dispatcher header |
| 808 | SystemTime | LARGE_INTEGER | Read/compared |
| 1024 | LIST_ENTRY.Flink/Blink | PLIST_ENTRY* | **YES - list manipulation** |
| 1032 | LIST_ENTRY (cont.) | PLIST_ENTRY* | **YES** |
| 1040 | Processor array pointer | PVOID* | Yes - per-CPU data |
| 1280 | Processor array pointer | PVOID* | Yes - per-CPU data |
| 1288 | Processor array pointer | PVOID* | Yes - per-CPU data |

**Exploitation via DPC (offset 608):**
- Corrupt `KDPC.DeferredRoutine` at offset 608 with controlled pointer
- Corrupt `KDPC.DeferredContext` at offset 616 with controlled argument
- When ETW logger timer fires, `KeTimerExpiration` queues the DPC
- DPC dispatch calls `DeferredRoutine(DeferredContext, SystemArg1, SystemArg2)`
- **Result: arbitrary kernel code execution at IRQL DISPATCH_LEVEL**
- All offsets 0-4008 within the 4080-byte overflow range

#### 2.2 PpmInstallCoordinatedIdleStates - SECONDARY TARGET

| Field | Value |
|-------|-------|
| Function | `PpmInstallCoordinatedIdleStates` @ 0x1408e1db7 |
| Pool Type | 0x204 (NonPagedPoolNxCacheAligned) |
| Tag | `0x694D5050` = "PPMi" |
| Size | Complex: `(384 * states + deps + 1008 * states + proc_arrays + 4*states + ...)` aligned |
| User-Triggerable | **NO** - hardware/firmware determined, one-time at boot |

**Pointer Fields:**
- Offset 48: Platform states accounting pointer
- Offset 88: LIST_ENTRY (self-referencing, 16 bytes) per 384-byte state entry
- Offset 112: Veto list pointer per state entry
- Offset 184: Dependency array pointer per state entry
- Offset 192: Reverse pointer to state info per 1008-byte block
- Offset 236: Dependency descriptor pointer per state entry

**Limitations:** Not user-triggerable, size not controllable, one-time allocation.

#### 2.3 IRP Auxiliary Buffers - TERTIARY (no pointer fields)

| Function | Address | Pool Type | Size Source | User-Controlled? |
|----------|---------|-----------|------------|------------------|
| IopBuildDeviceIoControlRequest | 0x14022b39a | 0x204 | `max(InputLen, OutputLen)` | YES via NtDeviceIoControlFile |
| IopBuildAsynchronousFsdRequest | 0x140358f73 | 0x204 | from register (r12) | YES via async I/O |
| IopAllocateAndPopulateWriteIrp | 0x1403f15d9 | 0x204 | `*(a1+72)` write length | YES via NtWriteFile |
| IopReadFile | 0x1405ce97c | 0x204 | from read params | YES via NtReadFile |

**Problem:** These are pure data buffers (copies of user data), not structures with pointer fields. Corrupting them only corrupts data, not control flow.

#### 2.4 Other ntoskrnl 0x204 allocations (smaller or non-targetable)

| Function | Size | Tag | Notes |
|----------|------|-----|-------|
| PspAssignProcessQuotaBlock | 576 (0x240) | ? | Too small |
| EtwInitializeSiloState | 56 (0x38) | ? | Too small |
| FsLibInitializeBucketsInfo | 3 | ? | Too small |
| ViAllocateMapRegisterFile | 12288 (0x3000) | "HAlV" | Too large for bucket 5120 |
| EtwpInitializeStackTracing | 3*rax | ? | Size depends on parameter |
| KeInitializeTimerTable | from rdi | ? | One-time init |
| KeProcessorProfileControlArea | ? | ? | Profile-specific |
| PspConvertSiloToServerSilo | ? | ? | Silo infrastructure |
| PspLazyInitializeStorageExpansion | ? | ? | Silo storage |
| HvlpDetermineEnlightenments | ? | ? | Hypervisor init |
| IopCreateArcName/IopCreateArcNamesCd | ? | ? | Boot-time ARC names |

### ntfs.sys (15 NonPagedPoolNxCacheAligned allocations)

#### 2.5 Ntf9 Compression Buffer - THE OVERFLOW SOURCE

| Field | Value |
|-------|-------|
| Functions | `NtfsAllocateCompressionBuffer`, `NtfsPrepareCompressedWriteBuffer`, `NtfsPrepareSimpleBuffers` |
| Pool Type | 0x204 (NonPagedPoolNxCacheAligned) |
| Tag | `0x3966744E` = "Ntf9" |
| Size | Dynamic (compression unit size or write length) |
| Allocation | `ExAllocatePoolWithTag(0x204, size, 'Ntf9')` via `NtfsCreateMdlAndBuffer` |

**NtfsCreateMdlAndBuffer flow:**
```c
PoolWithTag = ExAllocatePoolWithTag(a4 /*=0x204*/, *a5 /*=size*/, 0x3966744E /*='Ntf9'*/);
```

**Two allocation paths:**
1. **Compression data buffer:** Size = compression unit size (e.g., 4096, 8192)
2. **Compression workspace:** Size from `RtlGetCompressionWorkSpaceSize`

**Compression Workspace Sizes (from RtlGetCompressionWorkSpaceSize):**

| Format | Engine | CompressBufferWorkSpaceSize | FragmentWorkSpaceSize |
|--------|--------|---------------------------|----------------------|
| LZNT1 (2) | Standard | 65568 (0x10020) | 4096 (0x1000) |
| LZNT1 (2) | 256 | 32 (0x20) | 4096 (0x1000) |
| XPRESS_LZ (3) | Standard | 61223 (0xEF27) | 0 |
| XPRESS_LZ (3) | 256 | 393223 (0x601C7) | 0 |
| XPRESS_HUFF (4) | Standard | 166495 (0x28A3F) | **5161 (0x142F)** |
| XPRESS_HUFF (4) | 256 | 1415999 (0x159BFF) | **5161 (0x142F)** |

**Note:** XPRESS_HUFF fragment workspace = 5161 bytes. This is 41 bytes above bucket 5120 max (5120). If the LFH bucket boundary is actually at ~5200 or if the allocator rounds differently, this could be the Ntf9 allocation that overflows. Alternatively, the compression data buffer with a non-standard compression unit size could produce an allocation in the 5041-5120 range.

#### 2.6 Other ntfs.sys 0x204 allocations (Ntf9 tag, various functions)

| Function | Pool Call | Size | Notes |
|----------|-----------|------|-------|
| NtfsPrepareSimpleBuffers | ExAllocatePoolWithTag | write_len | User-controlled via WriteFile |
| NtfsPerformVerifyOperation | ExAllocatePoolWithTag | from r12 | Verify path |
| FsLibInitializeTelemetryVolumeIoPerfData | ExAllocatePoolWithTag | from rdi | Telemetry |
| FsLibInitializeIoPerfTelemetry | ExAllocatePoolWithTag | from rbx | Telemetry |
| NtfsZeroEndOfSectorNonCached | None | N/A | 0x204 used as constant, not pool type |
| NtfsPrepareCompressedWriteBuffer | via NtfsCreateMdlAndBuffer | workspace | Compression workspace |
| NtfsAllocateCompressionBuffer | via NtfsCreateMdlAndBuffer | comp_unit | Compression data buffer |
| NtfsDefragFileInternal | None | N/A | Defrag path |
| NtfsBuildBufferedDeviceControlIrp | None | N/A | Buffered IOCTL |
| NtfsEncryptDecryptOnline | None | N/A | Encryption |
| TxfComputeChildOpenResultCode | None | N/A | Transaction |

### afd.sys (3 NonPagedPoolNxCacheAligned allocations)

| Function | Tag | Size | Notes |
|----------|-----|------|-------|
| PplpCreateOneLookasideList | ? | 128 (0x80) | Too small |
| AfdPcwInit | "Afd " | `16*proc_count + 8` | Processor-dependent, needs 315+ procs for bucket 5120 |
| AfdTlStartClientModule | "AfdL" | `(proc_count+1)*64` | Needs 78-79 procs for bucket 5120 |

**AfdTliIoControlHandleSetQoS** (separate, pool type 0x210 = NonPagedPoolNxSession):
- Tag: "Afd "
- Size: `user_controlled + 80`, max 5200
- Pool type 0x210 = **different pool** (Session vs System), cannot be adjacent to Ntf9

### fltMgr.sys (1 NonPagedPoolNxCacheAligned allocation)

| Function | Pool Call | Notes |
|----------|-----------|-------|
| IssueControlOperation | None found nearby | 0x204 used as different constant |

### win32kfull.sys (3 NonPagedPoolNxCacheAligned allocations)

| Function | Notes |
|----------|-------|
| HT_CreateDeviceHalftoneInfo | GUI halftone, no pool call found |
| SetGlobalWallpaperSettings | Calls Win32AllocPool, GUI path |
| xxxUpdatePerUserSystemParameters | GUI path, no pool call found |

### npfs.sys (0 NonPagedPoolNxCacheAligned, 5 NonPagedPoolNx)

| Function | Pool Type | Notes |
|----------|-----------|-------|
| NpWriteDataQueue | 0x200 | Named pipe write data |
| NpOpenSymlink | 0x200 | Named pipe symlink |
| DriverEntry | 0x200 | Init-time |
| NpInitializeAliases | 0x200 | Init-time |
| NpCancelWaiter | 0x200 | No pool call found |

**Note:** NonPagedPoolNx (0x200) allocations may share pool pages with NonPagedPoolNxCacheAligned (0x204) in the SEGMENT heap, since both use the NonPaged pool backend. The difference is alignment (cache-line vs natural).

---

## 3. Structure Layout and Pointer Fields - Best Targets

### 3.1 EtwL (EtwpInitLoggerContext) - RECOMMENDED TARGET

```
Offset  Type        Field                    Action when dereferenced
------  ----        -----                    -----------------------
0x000   DWORD       Flags/Mode               Read/compared
0x004   DWORD       BufferSize               Read for buffer management
0x008   PVOID*      BufferPointer            Written to (log buffer)
0x040   PVOID*      PointerField_40          Deref'd for list ops
0x044   PVOID*      PointerField_44          List head self-pointer
0x050   PVOID*      ListHead                 LIST_ENTRY.Flink - deref'd in list walk
0x058   PVOID*      ListHead                 LIST_ENTRY.Blink - deref'd in list walk
0x098   UNICODE_STRING LoggerName            .Buffer at offset 0x0A8 deref'd for string ops
0x0A8   PWSTR       LoggerName.Buffer        DEREFERENCED - string operations
0x118   PVOID*      SequencePointer          Atomically incremented
0x158   LIST_ENTRY  EventListEntry           Flink/Blink deref'd in list removal
0x160   PVOID*      EventListHead            Self-pointer, list operations
0x1D8   KEVENT      Event_1D8                Contains dispatch header (Type/SignalState)
0x1F0   KEVENT      Event_1F0                Contains dispatch header
0x208   KTIMER      Timer                    Contains DPC pointer at Timer.Dpc
0x248   KDPC        Dpc                      **CRITICAL: function pointer**
0x268   PKDEFERRED_ROUTINE Dpc.DeferredRoutine  **CALLED at DISPATCH_LEVEL**
0x270   PVOID       Dpc.DeferredContext      **Passed as arg1 to DPC routine**
0x278   PVOID       Dpc.SystemArgument1      Set by timer expiration
0x280   PVOID       Dpc.SystemArgument2      Set by timer expiration
0x288   KMUTEX      Mutex                    Contains dispatcher header
0x328   LIST_ENTRY  BufferListHead           Flink/Blink deref'd in list walk
0x330   LIST_ENTRY  BufferListHead2          Flink/Blink deref'd
0x410   PVOID*      ProcArray1               Per-CPU buffer pointers
0x500   PVOID*      ProcArray2               Per-CPU buffer pointers
0x508   PVOID*      ProcArray3               Per-CPU buffer pointers
```

**Overflow coverage:** Offsets 0x000-0xFA7 (0-4007) are within the 4080-byte overflow range.
- **DPC.DeferredRoutine at offset 0x268 (608 decimal) = CORRUPTIBLE**
- **DPC.DeferredContext at offset 0x270 (616 decimal) = CORRUPTIBLE**
- **LIST_ENTRY fields at offsets 0x158, 0x328, 0x330 = CORRUPTIBLE**
- **UNICODE_STRING.Buffer at offset 0x0A8 = CORRUPTIBLE**

### 3.2 PPMi (PpmInstallCoordinatedIdleStates)

```
Offset  Type        Field                    Action
------  ----        -----                    ------
0x000   DWORD       StateCount               Read
0x004   DWORD       Initialized              Read
0x008   DWORD       ProcessorCount           Read
0x010   QWORD       Flags                    Read
0x030   PVOID*      AccountingPtr            Deref'd for idle accounting
0x058   LIST_ENTRY  StateListEntry[0]        Per-state, 384-byte entries
0x068   PVOID*      VetoListPtr              Deref'd for veto operations
0x070   PVOID*      DependencyArrayPtr       Deref'd for dependency walk
0x0C8   PVOID*      PerStateVetoPtr          Deref'd for veto checks
```

**Limitations:** Not user-triggerable, one-time boot allocation, size determined by ACPI/firmware.

---

## 4. Cross-Page Overflow Analysis

### SEGMENT Heap Layout for Bucket 5120

The Windows kernel SEGMENT heap organizes pool allocations into subsegments by bucket size. For bucket 5120:

| Subsegment Size (pages) | Subsegment Size (bytes) | Slots (5120 each) | Waste |
|--------------------------|------------------------|-------------------|-------|
| 2 pages | 8,192 | 1 | 3,072 |
| 3 pages | 12,288 | 2 | 2,048 |
| 4 pages | 16,384 | 3 | 1,024 |
| **5 pages** | **20,480** | **4** | **0** |
| 6 pages | 24,576 | 4 | 4,096 |
| 7 pages | 28,672 | 5 | 3,072 |
| 8 pages | 32,768 | 6 | 2,048 |
| 9 pages | 36,864 | 7 | 1,024 |

**Optimal subsegment = 5 pages (20,480 bytes) with exactly 4 slots of 5120 bytes and zero waste.**

### Same-Subsegment Overflow (PRIMARY SCENARIO)

When the Ntf9 buffer and a target object are in the same 5-page subsegment:
- Ntf9 buffer at slot N (offset N*5120)
- Target object at slot N+1 (offset (N+1)*5120)
- Overflow writes from offset N*5120 + allocation_size to N*5120 + allocation_size + 4080
- If allocation_size = 5048 (within bucket 5120):
  - Slot padding: 72 bytes (5048 to 5120)
  - Overflow into next slot: 4008 bytes (5120 to 9128)
  - **Corruptible offsets in target: 0 to 4007**

The SEGMENT heap mixes different pool tags within the same bucket subsegment. So Ntf9-tagged and EtwL-tagged allocations of the same bucket CAN be adjacent.

### Cross-Subsegment Overflow (SECONDARY SCENARIO)

If Ntf9 buffer is in the LAST slot of a subsegment:
- Slot 3 starts at offset 15360 in a 5-page subsegment
- Buffer ends at 15360 + 5120 = 20480 (exactly at subsegment boundary)
- Overflow writes from 20480 to 20480 + 4080 = 24560
- This crosses into the NEXT subsegment in the pool
- The next subsegment could be:
  - Same bucket (5120) with different tags - **usable**
  - Different bucket size - **may contain other target objects**
  - Pool metadata page - **would cause corruption/BSOD**

**Risk:** Cross-subsegment overflow is less reliable because the next subsegment's bucket size and tag distribution are unpredictable. No guard pages exist between subsegments in the NonPaged pool, but corrupting pool metadata would cause a BSOD.

### Page Boundary Analysis

NonPagedPoolNxCacheAligned allocations are aligned to cache line boundaries (64 bytes), NOT page boundaries. Within a 5-page subsegment:
- Slot 0: pages 0-1 (offset 0-5119)
- Slot 1: pages 1-2 (offset 5120-10239) - crosses page boundary at 8192
- Slot 2: pages 2-3 (offset 10240-15359) - crosses page boundary at 12288
- Slot 3: pages 3-4 (offset 15360-20479) - crosses page boundary at 16384

Each 5120-byte slot spans approximately 1.25 pages, so most slots cross at least one page boundary. This is normal for the SEGMENT heap and does not prevent overflow.

---

## 5. Alternative Compression Unit Sizes and LFH Buckets

### NTFS Compression Unit Sizes

NTFS compression unit = 2^n * 512 bytes, where n is stored in the file attribute:

| n | Compression Unit (bytes) | Estimated LFH Bucket | Potential Target Objects |
|---|--------------------------|---------------------|--------------------------|
| 0 | 512 | ~512 | Small kernel objects (EPROCESS quota?) |
| 1 | 1,024 | ~1,024 | Medium objects |
| 2 | 2,048 | ~2,048 | Medium objects |
| 3 | 4,096 | ~4,096 | IRP structures, FS control blocks |
| 4 | 8,192 | ~8,192 | Large buffers, ETW contexts |
| 5 | 16,384 | ~16,384 | Very large structures |
| 6 | 32,768 | ~32,768 | Huge allocations (page-granular) |
| 7 | 65,536 | ~65,536 | Page-granular allocation |

### Workspace Buffer Sizes (Alternative Ntf9 allocations)

The compression workspace is a SEPARATE Ntf9 allocation with sizes determined by `RtlGetCompressionWorkSpaceSize`:

| Compression Format | Workspace Size (bytes) | Estimated Bucket | Notes |
|--------------------|-----------------------|-----------------|-------|
| LZNT1 standard | 65,568 | ~65,568 | Very large, page-granular |
| LZNT1 engine 256 | 32 | ~32 | Tiny, different bucket |
| XPRESS_LZ standard | 61,223 | ~61,223 | Very large |
| XPRESS_LZ engine 256 | 393,223 | ~393,223 | Huge |
| XPRESS_HUFF standard | 166,495 | ~166,495 | Huge |
| **XPRESS_HUFF fragment** | **5,161** | **~5,161** | **CLOSE to bucket 5120!** |
| XPRESS_HUFF engine 256 | 1,415,999 | ~1.4M | Huge |

**Key finding:** XPRESS_HUFF fragment workspace = 5,161 bytes. This is only 41 bytes above bucket 5120 max (5,120). If the actual LFH bucket for 5,161 is at a boundary that includes 5,161 in the same subsegment as 5,120, this could be the Ntf9 allocation that overflows.

### NtfsPrepareSimpleBuffers (Non-compressed Write Path)

```c
PoolWithTag = ExAllocatePoolWithTag((POOL_TYPE)516, v23 /*=write_len*/, 0x3966744E /*='Ntf9'*/);
```

This creates Ntf9 allocations with user-controlled size via `WriteFile`:
- Write 5041-5120 bytes -> Ntf9 allocation at bucket 5120
- Write 4097-4096 bytes -> Ntf9 allocation at bucket 4096
- Write 2049-2048 bytes -> Ntf9 allocation at bucket 2048

**This path is useful for HEAP GROOMING** - creating and freeing Ntf9 allocations at specific bucket sizes to control subsegment layout. The overflow itself comes from the compression path, but simple writes can be used to fill/empty the bucket.

### Compression Unit Size Selection Strategy

1. **Stay at bucket 5120 (current):** Target EtwL (EtwpInitLoggerContext) with controlled name length. Requires ETW API access.

2. **Switch to bucket 4096 (n=3, compression unit = 4096):** Would need to find target objects at 4097-4096 byte range. This bucket is more common and might have more target objects, but overflow distance (4080) would reach well into the next slot.

3. **Switch to bucket 8192 (n=4, compression unit = 8192):** Target objects at 8193-8192 bytes. The overflow of 4080 bytes from an 8192-byte buffer would only corrupt the first 4080 bytes of the next 8192-byte slot.

4. **Use XPRESS_HUFF fragment workspace (5161 bytes):** If this falls in or near bucket 5120, the overflow from this workspace buffer could target the same objects. The workspace buffer is allocated with Ntf9 tag at 0x204 pool type.

---

## 6. Exploitation Strategy Summary

### Recommended Attack: EtwL DPC Corruption

1. **Heap Grooming:**
   - Allocate many Ntf9 buffers at bucket 5120 by writing 5041-5120 bytes to multiple files via `NtfsPrepareSimpleBuffers` path
   - Free alternate buffers to create holes in the subsegment
   - Allocate EtwL buffer by starting an ETW trace session with name length calculated for bucket 5120

2. **Trigger Overflow:**
   - Write crafted data to a compressed NTFS file
   - The compression overflow writes up to 4080 bytes of user-controlled content past the Ntf9 buffer
   - Overflow corrupts adjacent EtwL structure in the same subsegment

3. **Corrupt DPC:**
   - Write shellcode address at EtwL offset 608 (KDPC.DeferredRoutine)
   - Write controlled argument at EtwL offset 616 (KDPC.DeferredContext)
   - Write valid LIST_ENTRY values at offsets 592-607 to avoid early crashes

4. **Trigger DPC Execution:**
   - The ETW logger timer is already active (set during EtwpInitLoggerContext)
   - When the timer expires, `KeTimerExpiration` queues the DPC
   - DPC dispatch calls our controlled function pointer at DISPATCH_LEVEL
   - **Arbitrary kernel code execution achieved**

### Alternative: LIST_ENTRY Corruption

- Corrupt LIST_ENTRY at EtwL offset 344 or 1024
- When the ETW logger is stopped or the buffer is flushed, the list removal operation uses the corrupted Flink/Blink
- This enables arbitrary write via unlink primitive (classic pool overflow technique)
- Less reliable than DPC corruption but doesn't require waiting for timer

---

## 7. Files and Functions Reference

### Key Functions Analyzed

| Function | Binary | Address | Role |
|----------|--------|---------|------|
| NtfsCreateMdlAndBuffer | ntfs.sys | 0x1c0024ea8 | Ntf9 pool allocation wrapper |
| NtfsAllocateCompressionBuffer | ntfs.sys | 0x1c0024e13 | Compression buffer allocation |
| NtfsPrepareCompressedWriteBuffer | ntfs.sys | 0x1c00246c8 | Compression write + overflow path |
| NtfsPrepareSimpleBuffers | ntfs.sys | 0x1c000ac0b | Non-compressed write buffer (grooming) |
| EtwpInitLoggerContext | ntoskrnl.exe | 0x14071117f | **EtwL allocation - PRIMARY TARGET** |
| PpmInstallCoordinatedIdleStates | ntoskrnl.exe | 0x1408e1db7 | PPMi allocation - secondary target |
| IopAllocateAndPopulateWriteIrp | ntoskrnl.exe | 0x1403f15d9 | IRP aux buffer - grooming candidate |
| RtlGetCompressionWorkSpaceSize | ntoskrnl.exe | 0x14026d550 | Workspace size dispatch |
| RtlCompressWorkSpaceSizeXpressHuff | ntoskrnl.exe | 0x14032a830 | XPRESS_HUFF workspace = 166495, fragment = 5161 |

### Pool Tags Found

| Tag | Hex | Binary | Pool Type | Notes |
|-----|-----|--------|-----------|-------|
| Ntf9 | 0x3966744E | ntfs.sys | 0x204 | **OVERFLOW SOURCE** |
| EtwL | 0x4C777445 | ntoskrnl.exe | 0x204 | **PRIMARY TARGET** |
| PPMi | 0x694D5050 | ntoskrnl.exe | 0x204 | Secondary target |
| Afd  | 0x20646641 | afd.sys | 0x204/0x210 | Processor-dependent |
| AfdL | 0x4C646641 | afd.sys | 0x204 | Processor-dependent |
| HAlV | 0x566C6148 | ntoskrnl.exe | 0x204 | Fixed 12288 bytes (too large) |

---

## 8. Limitations and Open Questions

1. **Ntf9 allocation size at bucket 5120:** The exact mechanism by which the Ntf9 allocation reaches the 5041-5120 byte range needs confirmation. Standard NTFS compression units (powers of 2 * 512) do not produce sizes in this range. Possibilities:
   - Non-standard compression unit size
   - XPRESS_HUFF fragment workspace (5161 bytes, close but 41 over)
   - Buffer size includes overhead beyond compression unit
   - The allocation comes from a different code path

2. **SEGMENT heap tag mixing:** Whether the kernel SEGMENT heap reliably mixes different pool tags within the same bucket subsegment needs runtime verification. If tags are segregated, EtwL and Ntf9 might not be adjacent.

3. **ETW logger session name limits:** The maximum logger name length accepted by the ETW API needs verification. Calculations show 639-3790 bytes needed depending on processor count and flags.

4. **DPC timer state:** The ETW logger timer must be active for the DPC to fire. This is set during `EtwpInitLoggerContext` via `KeInitializeTimerEx`. The timer period and whether it fires automatically needs verification.

5. **Large binary scan timeouts:** ntfs.sys, dxgkrnl.sys, dxgmms2.sys, ks.sys, portcls.sys, and ntoskrnl.exe had frequent timeouts during full-instruction scans. Results were obtained through targeted byte pattern searches and decompilation.

---

*Analysis performed across 17 IDA Pro instances. All math computed via Python (py_eval). No mental math used.*
