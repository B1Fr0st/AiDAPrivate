# Cross-Binary Pool Allocation & Overflow Scan

## Target LFH Buckets

Spray capability confirmed at:
- **Bucket 640** — NonPagedPoolNx (named pipes), PagedPoolSession (ColorSpace)
- **Bucket 704** — NonPagedPoolNx (named pipes)
- **Bucket 1024** — NonPagedPoolNx (named pipes)

### Bucket Range Calculation (Python-verified)

```
Bucket 640: raw alloc 609-640 bytes (no header: 625-640, w/16B header: 609-624)
Bucket 704: raw alloc 673-704 bytes (no header: 689-704, w/16B header: 673-688)
Bucket 1024: raw alloc 993-1024 bytes (no header: 1009-1024, w/16B header: 993-1008)
```

LFH buckets are 16-byte increments from 16 to 1024. Allocations >1024 go to the large pool allocator (no LFH).

---

## 1. Pool Allocations at Target Buckets — All 17 Binaries

### Summary Table

| Binary | Import Found | Call Sites | Imm Hits @640 | @704 | @1024 | Analyzed Functions |
|--------|-------------|-----------|---------------|------|-------|-------------------|
| tm.sys | ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag | 12 | 0 | 3 | 8 | TmpPromoteTransaction, TmpPromotionRequestTail |
| win32kbase.sys | ExAllocatePoolWithTag | 133 | 22 | 13 | 138 | RIMReadInput, rimOnPnpArrived, NtUserReportInertia, DestroyProcessInfo |
| win32kfull.sys | ExAllocatePoolWithTag, ExAllocatePoolWithTagPriority, ExAllocatePoolWithQuotaTag | 60 | 26 | 11 | 200+ | (massive surface, not fully decompiled) |
| ntoskrnl.exe | (exports, not imports) | N/A | N/A | N/A | N/A | Skipped — exports pool functions |
| tdx.sys | ExAllocatePool2, ExAllocatePoolWithTag, ExAllocatePoolWithTagPriority | 29 | 4 | 0 | 6 | Not decompiled yet |
| dxgmms2.sys | ExAllocatePoolWithTag | 69 | 8 | 1 | 69 | VidSchiSignalRegisteredSyncObjects, VidSchFlushQueuePacketsInternal, VidSchiLogMmIoFlipMultiPlaneOverlay3, ReadGpuVaConfiguration |
| dxgmms1.sys | ExAllocatePoolWithTag | 23 | 0 | 0 | 37 | Not decompiled yet |
| win32k.sys | ExAllocatePoolWithTag | (timeout) | (timeout) | (timeout) | (timeout) | Not analyzed — xref query timed out |
| dxgkrnl.sys | ExAllocatePoolWithTag, ExAllocatePool2, ExAllocatePoolWithQuotaTag, ExAllocatePoolWithTagPriority | 240 | 13 | 13 | 95 | CTokenManager::ProcessDxgkAdapterTokens, CFlipExBuffer ctor, CTokenManager::ProcessGdiSysmemTokens, DpiEnterSystemDisplay, DXGADAPTER::CheckMcdmDdiSubmission |
| clfs.sys | ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag | 116 | 0 | 0 | 27 | CClfsLogFcbPhysical::Initialize, LoadContainerQ, WriteMetadataBlock, ScanContainerInfo, FindSymbol, ValidateContainerContextOffsets, ResetContainerQ |
| ks.sys | ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag | 125 | 2 | 5 | 6 | **KspPropertyHandler**, **KspEnableEvent**, KsServiceBusEnumPnpRequest, CopyDeviceInterfaceParameters, CKsQueue::TransferKsIrp, CKsPin::DispatchClose |
| portcls.sys | ExAllocatePoolWithTag | 60 | 0 | 0 | 1 | Not decompiled yet |
| npfs.sys | ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag | 13 | 0 | 0 | 0 | Dynamic sizes, no target bucket hits |
| afd.sys | ExAllocatePoolWithTag, ExAllocatePoolWithTagPriority, ExAllocatePoolWithQuotaTag | (timeout) | (timeout) | (timeout) | (timeout) | Not analyzed — xref query timed out |
| fltMgr.sys | ExAllocatePoolWithTag | 81 | 2 | 0 | 24 | **FltpReallocNameControl**, FltpAllocateIrpCtrlInternal, FltAllocateContext, FltpExpandShortNames, FltpAllocateFileNameInformation, InsertEventEntryInLookUpTable |
| ntfs.sys | ExAllocatePool, ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag | (timeout) | (timeout) | (timeout) | (timeout) | Not analyzed — xref query timed out |
| condrv.sys | ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag | 5 | 0 | 0 | 0 | CdpAllocateClient, CdpCreateServerConnectionIo, CdCreateKernelConnection, CdpAllocateKernelConnectionIrp — all dynamic sizes |

---

## 2. Detailed Analysis of Matching Allocations

### **RANK 1: ks.sys — KspPropertyHandler (0x1c002a0a0)**

**Pool Type:** NonPagedPoolNx  
**Tag:** `0x7070534B` ("KSpp")  
**Allocation:** `ExAllocatePoolWithQuotaTag(NonPagedPoolNx, v14, 0x7070534B)`  
**Size:** `v14 = v12 + Options` where:
- `v12 = (OutputBufferLength + 7) & 0xFFFFFFF8` (8-byte aligned OutputBuffer length from IRP)
- `Options = InputBufferLength` from `CurrentStackLocation->Parameters.Create.Options`

**User-Controllable:** YES — both InputBufferLength and OutputBufferLength are user-controlled via the IRP I/O stack location. User sets these through DeviceIoControl buffers.

**Overflow Potential:** MODERATE — The allocation size matches the copy operations:
1. `memset(allocation, 0, v12)` — zeros v12 bytes
2. `memmove(allocation + v12, InputBuffer, Options)` — copies InputBufferLength bytes
3. `memmove(allocation, UserBuffer, Length)` — copies OutputBuffer data to start

The total copy is `v12 + Options = v14` which matches the allocation. However, this IS a user-controlled NonPagedPoolNx allocation that can be precisely sized to land in bucket 1024.

**Bucket 1024 Targeting:** Set `OutputBufferLength = 0` (so v12 = 0) and `InputBufferLength = 1000` → v14 = 1000 → bucket 1024. Or `OutputBufferLength = 488, InputBufferLength = 512` → v12 = 488, v14 = 1000 → bucket 1024.

**Integer Overflow Checks Present:** Yes — `if ((unsigned int)v12 + Options < (unsigned int)v12) return STATUS_INVALID_PARAMETER`

**Spray Compatibility:** NonPagedPoolNx bucket 1024 — DIRECT MATCH with named pipe spray.

---

### **RANK 2: ks.sys — KspEnableEvent (0x1c002b280)**

**Pool Type:** NonPagedPoolNx  
**Tag:** `0x7070534B` ("KSpp") for first allocation, `0x6565534B` ("KSee") for second  
**Allocation 1:** `ExAllocatePoolWithQuotaTag(NonPagedPoolNx, v20, 0x7070534B)`  
**Size 1:** `v20 = v17 + v15` where:
- `v15 = *(unsigned int *)(irp_stack + 16)` — InputBuffer length from IRP (user-controlled)
- `v17 = (v16 + 7) & 0xFFFFFFF8` — aligned OutputBuffer length (user-controlled)

**Allocation 2:** `ExAllocatePoolWithTag(NonPagedPoolNx, v42, 0x6565534B)`  
**Size 2:** `v42 = v39 + v36[2]` where:
- `v39 = v38 + 120` (base size + 120 bytes for event entry header)
- `v38 = (v31 + 24 + 7) & ~7` when `a11` flag is set (alignment padding)
- `v36[2]` — event data size from the event item table (semi-user-controlled through event type selection)

**User-Controllable:** YES — first allocation is fully user-controlled. Second allocation is partially controlled via event type selection.

**Overflow Potential:** HIGHER — After the second allocation:
1. Event entry header fields are written at fixed offsets
2. `memmove(v49 + 24, v36, Lengtha)` copies event item data where `Lengtha = v31` (event item stride)
3. If `Lengtha > v36[2]` (stride > allocated extra space), this could overflow

In the `v23 == 1024` branch:
- `memmove(allocation, P[0] + 24, *(unsigned int *)(P[0] + 20))` — copies data from a locked operation result. The size comes from the result buffer, which could potentially be larger than the first allocation.

**Bucket 1024 Targeting:** Same approach as KspPropertyHandler for first allocation.

**Spray Compatibility:** NonPagedPoolNx bucket 1024 — DIRECT MATCH.

---

### **RANK 3: clfs.sys — CClfsBaseFilePersisted::LoadContainerQ (0x1c002d880)**

**Pool Type:** PagedPool  
**Tag:** N/A (uses `operator new`)  
**Allocation 1:** `operator new(0x11F0u, PagedPool)` — fixed 4592 bytes, too large for LFH  
**Allocation 2:** `operator new(v68, PagedPool)` where:
- `v68 = 2 * (((unsigned __int64)*((unsigned __int16 *)this + 108) >> 1) + 1)` — container count from CLFS metadata

**User-Controllable:** YES — CLFS metadata is read from the .blf file on disk. An attacker can craft a malicious .blf file with controlled container count.

**Overflow Potential:** HIGH — This function is in the CLFS parsing path, which has been the target of multiple CVEs:
- CVE-2023-28252 (CLFS log block corruption → privilege escalation)
- CVE-2024-6771 (CLFS base record validation bypass)
- CVE-2024-6772 (CLFS container context handling)

The function calls `memmove(v30, Src, 0x1000u)` to copy 4096 bytes from the BaseLogRecord into a 0x11F0-byte allocation. It then validates offsets using `ValidateRgOffsets`. If the metadata is crafted to pass validation but cause a mismatch between expected and actual data sizes, an overflow could occur.

The `operator new(v68, PagedPool)` allocation has `v68` based on container count. With careful control of the .blf file, this could potentially land in a target bucket. However, the formula `2 * ((count >> 1) + 1)` makes it harder to hit exact bucket sizes.

**Key CLFS Functions with 1024-byte Immediate References:**
- `CClfsLogFcbPhysical::Initialize` (0x1c0002cc4) — 6 pool alloc calls, 1024 imm at 0x1c000338d
- `CClfsBaseFile::ValidateContainerContextOffsets` (0x1c0027fbc) — 1024 imm at 0x1c00280be
- `CClfsBaseFile::FindSymbol` (0x1c002b554) — 1024 imm at 0x1c002b750
- `CClfsBaseFilePersisted::WriteMetadataBlock` (0x1c0035e60) — 1024 imm at 0x1c0035f30, 0x1c003616c, 0x1c004b496
- `CClfsBaseFile::ScanContainerInfo` (0x1c005419c) — 1024 imm at 0x1c0054291, 0x1c005452b
- `CClfsBaseFilePersisted::ResetContainerQ` (0x1c0053ef0) — 1024 imm at 0x1c0053f3f, 0x1c0053fc5, 0x1c00540d8

**Spray Compatibility:** PagedPool — would need PagedPool spray (not the NonPagedPoolNx pipe spray). Could potentially use PagedPoolSession ColorSpace spray for bucket 640.

---

### **RANK 4: fltMgr.sys — FltpReallocNameControl (0x1c00365bc)**

**Pool Type:** PagedPool  
**Tag:** `0x6E664D46` ("FMnf")  
**Allocation:** `ExAllocatePoolWithTag(PagedPool, a2, 0x6E664D46)` when `a2 > 0x400`  
**Size:** `a2` — the new name buffer size, comes from file name expansion operations

**Lookaside Path:** When `a2 <= 0x400` (1024), uses an SLIST lookaside with fixed 1024-byte entries.

**User-Controllable:** PARTIALLY — `a2` is the requested new buffer size for file name control. This is influenced by file path length and 8.3 short name expansion. An attacker can influence this through file operations (create files with long names that trigger short name expansion).

**Overflow Potential:** MODERATE — After allocation:
1. `memmove(PoolWithTag, old_buffer, *a1)` — copies old name data into new buffer
2. `*a1` is the current name length (stored in the name control structure)
3. If `*a1 > v4` (old name length > new buffer size), this is a HEAP OVERFLOW

The code does NOT check that `*a1 <= v4` before the memmove. If a race condition or TOCTOU exists where the name length changes between the reallocation decision and the copy, this could overflow.

When using the lookaside path (a2 <= 1024), `v4 = 1024`. The old name should be <= old buffer size. If old buffer was also from lookaside (1024 bytes), `*a1 <= 1024 = v4`, so no overflow. But if `a2 > 1024`, the PagedPool allocation is `a2` bytes, and `*a1` could be up to 1024 (from a previous lookaside allocation). Since `*a1 <= 1024 < a2`, still no overflow in the normal case.

However, if there's a path where `*a1` can be set to a value larger than `v4` through concurrent name modification, this could be exploitable.

**Spray Compatibility:** PagedPool — bucket 1024 via lookaside (all allocations <= 1024 get 1024-byte lookaside buffers).

---

### **RANK 5: dxgkrnl.sys — CTokenManager::ProcessDxgkAdapterTokens (0x1c0003cd0)**

**Pool Type:** NonPagedPoolNx (likely, based on dxgkrnl patterns)  
**Size:** 640 immediate found at 0x1c0003d08 and 0x1c0003e82  
**Function Size:** 0xC4F (3143 bytes) — large function, complex token processing

**User-Controllable:** LIKELY — DirectX graphics kernel processes user-mode DirectX tokens via IOCTLs. The token processing path is reachable from user-mode applications using DirectX APIs.

**Overflow Potential:** UNKNOWN — Function not fully decompiled. Large function with multiple allocation paths. The 640 immediate could be an allocation size, array stride, or structure offset.

**Other dxgkrnl.sys functions with 640 hits:**
- `CFlipExBuffer::CFlipExBuffer` (0x1c0012588) — flip buffer constructor
- `CTokenManager::ProcessGdiSysmemTokens` (0x1c001e384) — GDI sysmem token processing
- `DpiEnterSystemDisplay` (0x1c00202b0) — DPI display entry
- `DXGADAPTER::CheckMcdmDdiSubmission` (0x1c0022ab4) — MCDM DDI check

**Spray Compatibility:** If NonPagedPoolNx with size 640 — DIRECT MATCH with named pipe or ColorSpace spray.

---

### **RANK 6: win32kbase.sys — Multiple Functions**

**640-byte hits in key functions:**
- `RIMReadInput` (0x1c00542c0) — Raw Input Manager read, processes input data
- `rimOnPnpArrived` (0x1c0056904) — RIM PnP arrival handler
- `CBaseInput::ForwardPnpNotificationToISM` (0x1c008a674) — input PnP notification

**704-byte hits:**
- `NtUserReportInertia` (0x1c0004160) — user inertia reporting syscall
- `DestroyProcessInfo` (0x1c0046dc0) — process info destruction

**User-Controllable:** YES for RIMReadInput and NtUserReportInertia — these are syscall/IOCTL accessible from user mode.

**Overflow Potential:** UNKNOWN — Functions not fully decompiled. Win32k has been a prolific vulnerability target (CVE-2024-30040, CVE-2023-29336, etc.).

---

### **RANK 7: dxgmms2.sys — Scheduler Functions**

**640-byte hits:**
- `VidSchiSignalRegisteredSyncObjects` (0x1c0015e8c) — sync object signaling
- `VidSchFlushQueuePacketsInternal` (0x1c0016dfc) — queue packet flush
- `VidSchiLogMmIoFlipMultiPlaneOverlay3` (0x1c002b1f8) — MPO flip logging
- `VidSchiRundownUnorderedWaiterDevice` (0x1c00315c4) — device rundown
- `VIDMM_GLOBAL::ReadGpuVaConfiguration` (0x1c0093490) — GPU VA config read

**User-Controllable:** LIKELY for sync object and flip functions — reachable through DirectX user-mode APIs.

**Overflow Potential:** UNKNOWN — Not fully decompiled. Graphics memory management is complex.

---

## 3. Write-What-Where Primitives Found

### ks.sys — KsServiceBusEnumPnpRequest (0x1c00363c0)

In the `MinorFunction == 8` (IRP_MN_QUERY_INTERFACE) handler:
```c
ByteOffset = CurrentStackLocation->Parameters.Read.ByteOffset;
*(_QWORD *)(ByteOffset.QuadPart + 16) = InterfaceReference;
*(_QWORD *)(ByteOffset.QuadPart + 24) = InterfaceDereference;
*(_QWORD *)(ByteOffset.QuadPart + 32) = ReferenceDeviceObject;
*(_QWORD *)(ByteOffset.QuadPart + 40) = DereferenceDeviceObject;
*(_QWORD *)(ByteOffset.QuadPart + 48) = QueryReferenceString;
*(_DWORD *)ByteOffset.QuadPart = 16777272;
*(_QWORD *)(ByteOffset.QuadPart + 8) = v6;
```

**WRITE-WHAT-WHERE CANDIDATE:** `ByteOffset.QuadPart` comes from `CurrentStackLocation->Parameters.Read.ByteOffset` which is partially user-controlled through the IRP. If an attacker can control this value, they can write function pointers to an arbitrary kernel address. However, this path requires specific PnP interface conditions (KSMEDIUMSETID_Standard, Size=56, Version=256).

**Severity:** HIGH if reachable — writes 7 controlled function pointers + a constant + a device extension pointer to a user-influenced address.

---

## 4. RtlCopyMemory / memmove with User-Controlled Length

### Found through decompilation (RtlCopyMemory is inlined in kernel drivers):

| Binary | Function | Copy Pattern | Length Source | Dest Type | Overflow? |
|--------|----------|-------------|--------------|-----------|-----------|
| ks.sys | KspPropertyHandler | `memmove(alloc+v12, InputBuf, Options)` | IRP InputBufferLength (user) | NonPagedPoolNx alloc | No — matches alloc size |
| ks.sys | KspPropertyHandler | `memmove(alloc, UserBuf, Length)` | IRP OutputBufferLength (user) | NonPagedPoolNx alloc | No — within v12 region |
| ks.sys | KspEnableEvent | `memmove(alloc+v17, InputBuf, v15)` | IRP InputBufferLength (user) | NonPagedPoolNx alloc | No — matches alloc size |
| ks.sys | KspEnableEvent | `memmove(alloc, UserBuf, Length)` | IRP OutputBufferLength (user) | NonPagedPoolNx alloc | No — within v17 region |
| ks.sys | KspEnableEvent | `memmove(v49+24, v36, Lengtha)` | Event item stride (semi-user) | NonPagedPoolNx alloc | POSSIBLE — if stride > allocated extra |
| ks.sys | KspEnableEvent | `memmove(alloc, P[0]+24, *(P[0]+20))` | Locked op result size | NonPagedPoolNx alloc | POSSIBLE — if result > allocation |
| ks.sys | KspPropertyHandler | `memmove(v51, *(v49+16), count1*count2)` | Item count × size from table | User output buffer | POSSIBLE — if counts are large |
| clfs.sys | LoadContainerQ | `memmove(v30, Src, 0x1000)` | Fixed 4096 | PagedPool alloc (0x11F0) | No — fixed sizes |
| clfs.sys | LoadContainerQ | `memmove(v70, this+28, *(this+108))` | Container name length from metadata | PagedPool alloc | POSSIBLE — metadata controlled |
| fltMgr.sys | FltpReallocNameControl | `memmove(new_buf, old_buf, *a1)` | Old name length | PagedPool alloc | POSSIBLE — if *a1 > new size |

---

## 5. Most Promising Vectors — Ranked

### #1: ks.sys KspEnableEvent — Second Allocation Overflow
- **Pool:** NonPagedPoolNx, tag "KSee"
- **Vector:** Event enable via KSEVENT ioctl → second pool allocation at `v42 = base + 120 + event_data_size`
- **Overflow:** `memmove(v49+24, v36, Lengtha)` where Lengtha could exceed allocated extra space
- **Bucket Match:** NonPagedPoolNx 1024 (named pipe spray)
- **Reachability:** User-mode applications using KS (kernel streaming) APIs — audio, video capture
- **Confidence:** MEDIUM — needs deeper analysis of event item table structure

### #2: ks.sys KspPropertyHandler — User-Controlled NonPagedPoolNx at Bucket 1024
- **Pool:** NonPagedPoolNx, tag "KSpp"
- **Vector:** Property handler via KSPROPERTY ioctl → pool allocation at user-controlled size
- **Overflow:** No direct overflow, but allocation is precisely controllable to bucket 1024
- **Use:** Could be used as the VICTIM allocation (not the overflow source) — spray with named pipes at bucket 1024, then trigger this allocation to get adjacent pool block
- **Reachability:** User-mode KS property requests
- **Confidence:** HIGH for pool placement, needs separate overflow primitive

### #3: clfs.sys LoadContainerQ — Metadata-Driven PagedPool Overflow
- **Pool:** PagedPool (operator new)
- **Vector:** Craft malicious .blf file → CLFS driver parses metadata → pool allocation at metadata-controlled size
- **Overflow:** `memmove(v70, this+28, container_name_length)` where name length comes from crafted metadata
- **Bucket Match:** PagedPool — would need PagedPoolSession ColorSpace spray at bucket 640
- **Reachability:** Any user with write access to create a .blf file (low privilege)
- **Confidence:** MEDIUM — CLFS has history of CVEs, but specific overflow path needs validation

### #4: fltMgr.sys FltpReallocNameControl — Name Control Reallocation
- **Pool:** PagedPool, tag "FMnf"
- **Vector:** File operations triggering name expansion → reallocation of name control buffer
- **Overflow:** `memmove(new_buf, old_buf, *a1)` where *a1 is old name length, no check against new size
- **Bucket Match:** PagedPool bucket 1024 (lookaside list gives 1024-byte buffers)
- **Reachability:** File system operations (create files with long names, trigger 8.3 expansion)
- **Confidence:** LOW-MEDIUM — race condition dependent, needs concurrent file operations

### #5: ks.sys KsServiceBusEnumPnpRequest — Write-What-Where
- **Vector:** PnP IRP_MN_QUERY_INTERFACE handler writes function pointers to ByteOffset.QuadPart
- **Write:** 7 function pointers + constant + device pointer to user-influenced address
- **Reachability:** Requires specific PnP interface conditions (KS medium, Size=56, Version=256)
- **Confidence:** LOW — needs specific device/adapter conditions, but if reachable, is a direct WWW

### #6: dxgkrnl.sys — Graphics Token Processing (Needs Further Analysis)
- **Pool:** Likely NonPagedPoolNx
- **Vector:** DirectX user-mode APIs → token processing → pool allocations at 640/1024
- **Functions:** CTokenManager::ProcessDxgkAdapterTokens, ProcessGdiSysmemTokens
- **Confidence:** UNKNOWN — large functions, not fully decompiled

### #7: win32kbase.sys — Input Processing (Needs Further Analysis)
- **Pool:** Likely PagedPoolSession or NonPagedPoolNx
- **Vector:** Raw input, inertia reporting, PnP notifications
- **Functions:** RIMReadInput, NtUserReportInertia
- **Confidence:** UNKNOWN — not fully decompiled

---

## 6. Binaries Not Fully Analyzed (Timeout/Size Limitations)

| Binary | Reason | Recommended Next Steps |
|--------|--------|----------------------|
| afd.sys | xref query timed out (too many imports) | Use paginated xref_query with count=25, focus on IOCTL dispatch functions |
| ntfs.sys | xref query timed out | Same approach, focus on file metadata parsing paths |
| win32k.sys | xref query timed out | Kernel address import, use paginated queries |
| ntoskrnl.exe | Exports pool functions, not imports | Analyze internal allocation paths (ExpPoolRoundUp, ExAllocatePoolInternal) |
| win32kfull.sys | 200+ immediate hits at 1024 | Focus on user syscall handlers (NtUser*, NtGdi*) |
| dxgmms1.sys | 37 hits at 1024 | Decompile allocation-heavy functions |
| tdx.sys | 4 hits at 640 | TDI transport driver, analyze protocol handlers |
| portcls.sys | 1 hit at 1024 | Audio class driver, limited surface |

---

## 7. Immediate Value Cross-Reference Summary

### Total Immediate Hits at Target Bucket Sizes (All 17 Binaries)

| Size | Bucket | tm.sys | win32kbase | win32kfull | tdx | dxgmms2 | dxgmms1 | dxgkrnl | clfs | ks | portcls | fltMgr |
|------|--------|--------|-----------|-----------|-----|---------|---------|---------|------|-----|---------|--------|
| 640  | 640    | 0      | 22        | 26        | 4   | 8       | 0       | 13      | 0    | 2  | 0       | 2      |
| 704  | 704    | 3      | 13        | 11        | 0   | 1       | 0       | 13      | 0    | 5  | 0       | 0      |
| 1024 | 1024   | 8      | 138       | 200+      | 6   | 69      | 37      | 95      | 27   | 6  | 1       | 24     |
| 624  | 640    | 0      | 6         | 18        | 0   | 12      | 4       | 15      | 5    | 0  | 0       | 7      |
| 688  | 704    | 1      | 4         | 26        | 0   | 1       | 0       | 7       | 0    | 2  | 0       | 2      |
| 1008 | 1024   | 0      | 2         | 0         | 0   | 0       | 0       | 0       | 0    | 1  | 0       | 0      |
| 608  | 640    | 1      | 10        | 17        | 0   | 4       | 2       | 0       | 2    | 0  | 0       | 0      |
| 672  | 704    | 3      | 16        | 23        | 0   | 1       | 2       | 0       | 0    | 3  | 0       | 0      |
| 992  | 1024   | 0      | 7         | 37        | 0   | 3       | 0       | 0       | 2    | 0  | 0       | 0      |

**Note:** These are immediate value references, not all are allocation sizes. Many are array indices, structure offsets, comparison constants, or loop bounds. Cross-referencing with pool allocation call sites is required to identify actual allocation sizes.

---

## 8. Recommendations for Next Steps

1. **Deep-dive ks.sys KspEnableEvent second allocation** — Decompile the event item table structure to determine if `v36[2]` (event data size) can be controlled independently from `Lengtha` (event item stride). If so, the `memmove(v49+24, v36, Lengtha)` could overflow the allocation.

2. **Analyze afd.sys** — Use paginated xref queries (count=25) to get all pool allocation call sites. Afd.sys has a rich history of pool overflow and WWW vulnerabilities (CVE-2023-21768, CVE-2024-30088). Focus on AFD ioctl handlers.

3. **Craft malicious .blf for CLFS** — Build a test .blf file with controlled container count and name lengths. Test if the `memmove` in LoadContainerQ can overflow when metadata values are crafted to pass validation but cause size mismatches.

4. **Decompile dxgkrnl CTokenManager::ProcessDxgkAdapterTokens** — This 3143-byte function has two 640-byte immediate hits. If it allocates at 640 in NonPagedPoolNx, it directly matches the named pipe spray.

5. **Investigate win32kbase RIMReadInput** — Raw input manager is reachable from user mode. The 640-byte immediate could be an allocation size for input data buffers.

6. **Race condition analysis for fltMgr FltpReallocNameControl** — Determine if concurrent file rename + name expansion can cause `*a1` to exceed `v4` between the reallocation decision and the memmove.

---

## Appendix: Pool Tags Identified

| Tag (hex) | Tag (ASCII) | Binary | Pool Type |
|-----------|-------------|--------|-----------|
| 0x7070534B | KSpp | ks.sys | NonPagedPoolNx |
| 0x6565534B | KSee | ks.sys | NonPagedPoolNx |
| 0x69625753 | SWbi | ks.sys | PagedPool |
| 0x6E664D46 | FMnf | fltMgr.sys | PagedPool |
| N/A | N/A | clfs.sys | PagedPool (operator new) |

---

*Analysis performed across 17 IDA Pro instances. All LFH bucket calculations verified with Python. Decompilation performed for key functions in ks.sys, clfs.sys, fltMgr.sys, and dxgkrnl.sys. Remaining binaries require paginated xref queries due to high reference counts.*
