# Alternative 960-Byte NonPagedPoolNx Allocation Analysis

## Target: Find alternative kernel objects that create 960-byte NonPagedPoolNx allocations (LFH bucket 976, sizes 945-960) that don't zero on free, as backup if portcls PcCaptureFormat fails.

## IDA Instances Used

| Binary | PID | Port |
|--------|-----|------|
| ntoskrnl.exe | 8428 | 13346 |
| clfs.sys | 4924 | 13337 |
| portcls.sys | 11184 | 13338 |
| tdx.sys | 15240 | 13339 |
| dxgmms1.sys | 4980 | 13340 |
| dxgmms2.sys | 10784 | 13341 |
| dxgkrnl.sys | 12088 | 13343 |
| win32k.sys | 13756 | 13342 |
| win32kfull.sys | 5844 | 13344 |
| win32kbase.sys | 15092 | 13345 |

---

## 1. LFH Bucket Math (Python-verified via IDA py_eval)

```
Bucket 944 (index 59): total 929-944, user sizes 913-928
Bucket 960 (index 60): total 945-960, user sizes 929-944
Bucket 976 (index 61): total 961-976, user sizes 945-960  ← TARGET
Bucket 992 (index 62): total 977-992, user sizes 961-976
Bucket 1008 (index 63): total 993-1008, user sizes 977-992
```

Pool header = 16 bytes. User size + 16 = total. Total maps to bucket.

IRP size calculations:
```
StackSize=10: 208 + 72*10 = 928 → total 944 → bucket 944
StackSize=11: 208 + 72*11 = 1000 → total 1016 → bucket 1024
```

No IRP size falls in bucket 976 (user 945-960).

Hex conversions:
```
960 = 0x3C0   952 = 0x3B8   944 = 0x3B0   928 = 0x3A0
968 = 0x3C8   976 = 0x3D0   992 = 0x3E0
```

---

## 2. Complete Scan: All NonPagedPoolNx Allocations at 929-992 Bytes

### ntoskrnl.exe (PID 8428)

Scanned ALL 2540 xrefs to ExAllocatePoolWithTag (0x1409B4160) and ALL 24 xrefs to ExAllocatePool2 (0x1409B41B0).

**NonPagedPoolNx allocations at sizes 929-992:**

| # | Function | Address | Size | Hex | Tag | Zeroed? | User-Triggerable? | Offset 0x50 |
|---|----------|---------|------|-----|-----|---------|-------------------|-------------|
| 1 | EtwpCovSampCaptureContextStart | 0x140942285 | 960 | 0x3C0 | 'EtwV' (0x56777445) | **YES** (memset) | NO (singleton, ETW coverage sampling) | KTHREAD ptr (KeGetCurrentThread) |
| 2 | PopEtInit | 0x140a6d9e0 | 952 | 0x3B8 | 'PoET' (0x54456F50) | **YES** (memset) | NO (system init, PopEnergyEstimationEnabled) | InternTable data |
| 3 | FsFilterInit | 0x1403c8c67 | 968 | 0x3C8 | unknown | **YES** (memset) | NO (system init) | FS filter callback data |

**Bucket 960 (user 929-944): ZERO NonPagedPoolNx allocations**
**Bucket 944 (user 913-928): ZERO NonPagedPoolNx allocations**
**Bucket 1008 (user 977-992): ZERO NonPagedPoolNx allocations**

All 3 allocations at bucket 976/992 are **ZEROED** on alloc and **NOT user-triggerable**.

### dxgmms1.sys (PID 4980)

| # | Function | Address | Size | Hex | Tag | Zeroed? | User-Triggerable? | Offset 0x50 |
|---|----------|---------|------|-----|-----|---------|-------------------|-------------|
| 4 | VidSchiCreateContextInternal | 0x1c0052a70 | 960 | 0x3C0 | 'ViSh' (0x68536956) | **YES** (memset) | **YES** (D3DKMTCreateContext / GPU context creation) | **KTHREAD pointer** (KeGetCurrentThread at qword offset 10 = 0x50) |

**VidSchiCreateContextInternal details:**
- Pool type: 512 (0x200) = NonPagedPoolNx
- `ExAllocatePoolWithTag((POOL_TYPE)512, 0x3C0u, 0x68536956u)`
- `memset(PoolWithTag, 0, 0x3C0u)` — ZEROED on alloc
- Offset 0x50: `*((_QWORD *)v9 + 10) = KeGetCurrentThread()` — stores current KTHREAD pointer
- Free path: `VidSchTerminateContext` → `ExFreePoolWithTag` — NO zeroing on free
- User-triggerable: YES, via D3D device context creation (D3DKMTCreateContext IOCTL to dxgkrnl → dxgmms1)
- Also allocates 5x 1520-byte (0x5F0) packets in a loop

### clfs.sys (PID 4924)

- All NonPagedPoolNx allocations ≤264 bytes (224, 264 bytes)
- 992-byte allocations exist but are **PagedPool** (CClfsLogFcbPhysical::Initialize)
- NO NonPagedPoolNx allocations at 929-992

### portcls.sys (PID 11184)

- PcCaptureFormat: allocates only 14 bytes (0xE) — NOT the format buffer
- CreatePortPinWaveRT: 472 bytes (0x1D8) — pin creation, not format
- Largest NonPagedPoolNx allocation: 15 bytes
- NO pool allocations at 929-992 bytes
- The 960-byte format buffer allocation is done through the KS framework, not direct ExAllocatePoolWithTag

### tdx.sys (PID 15240)

- ZERO immediate value hits for any target size (960, 952, 944, 928, 968, 992)
- NO relevant allocations

### dxgkrnl.sys (PID 12088)

- 11 immediate-960 hits: all are WdLog error codes/line numbers, NOT allocation sizes
- VmBusCreateSyncObjectCblt: actual allocation is 56 bytes (ExAllocatePool2)
- DpiFdoHandleFilterResources: uses PagedPool, 960 is a resource descriptor field value
- NO NonPagedPoolNx allocations at 929-992

### dxgmms2.sys (PID 10784)

- 960 hit in CVirtualAddressAllocator::AllocateVirtualAddressRange — NOT a pool allocation
- NO NonPagedPoolNx allocations at 929-992

### win32k.sys / win32kfull.sys / win32kbase.sys

- win32k.sys: all hits are table entries (constant arrays), not allocation sizes
- win32kfull.sys: 6 immediate-960 hits, none near pool allocation calls
- win32kbase.sys: 2 immediate-960 hits, none near pool allocation calls
- These drivers use session pool, not system NonPagedPoolNx for most objects
- NO relevant NonPagedPoolNx allocations at 929-992

---

## 3. Nearby Bucket Non-Zeroed Allocations

From previous analysis (subagent_nonpaged_objects_960_704.md), 358 non-zeroed NonPagedPoolNx allocations were found. None at bucket 976.

Nearby non-zeroed allocations:

| Size | Hex | Bucket | Function | User-Triggerable? | Offset 0x50 |
|------|-----|--------|----------|-------------------|-------------|
| 672 | 0x2A0 | 688 | EtwTiLogInsertQueueUserApc | YES (QueueUserApc) | ETW buffer data (write-only) |
| 736 | 0x2E0 | 752 | ExpPartitionCreatePoolInternal | NO | MM partition data |
| 912 | 0x390 | 928 | sub_140A1CEE4 (INIT segment) | NO (boot init) | unknown |
| 784 | 0x310 | 800 | CmFcManagerStartRuntimePhase | NO | unknown |
| 840 | 0x348 | 864 | VfIrpLogRecordEvent | NO (verifier) | unknown |
| 888 | 0x378 | 896 | IopLiveDumpWriteDumpFile | NO (live dump) | unknown |

**None of the non-zeroed allocations fall in bucket 976 (945-960) or are both user-triggerable and have a pointer at offset 0x50.**

---

## 4. Common Kernel Object Sizes (from IDA Type Library)

| Object | Size | Hex | Bucket | Offset 0x50 | Pointer? | User-Triggerable? |
|--------|------|-----|--------|-------------|----------|-------------------|
| _KTM | 960 | 0x3C0 | 976 | NamespaceLink.Links.Blink (LIST_ENTRY*) | **YES** | YES (NtCreateTransactionManager) |
| _EPROCESS | 2624 | 0xA40 | 2640 | RotateInProgress (_ETHREAD*) | YES | YES (NtCreateProcess) |
| _KPROCESS | 1080 | 0x438 | 1088 | Affinity (_KAFFINITY_EX) | NO | embedded in EPROCESS |
| _ETHREAD | 2200 | 0x898 | 2208 | IrpList (_LIST_ENTRY) | YES (Blink) | YES (NtCreateThread) |
| _KTHREAD | 1072 | 0x430 | 1088 | CurrentRunTime (unsigned int) | NO | embedded in ETHREAD |
| _TOKEN | 1176 | 0x498 | 1184 | SessionId (unsigned int) | NO | YES (NtCreateToken) |
| _EJOB | 1600 | 0x640 | 1600 | TotalUserTime (_LARGE_INTEGER) | NO | YES (NtCreateJobObject) |
| _IRP | 208+72*N | varies | varies | PKEVENT UserEvent | **YES** | YES (any I/O) |
| _FILE_OBJECT | 216 | 0xD8 | 224 | Flags (ULONG) | NO | YES (NtCreateFile) |
| _HANDLE_TABLE | 128 | 0x80 | 128 | TableCode (ULONG_PTR) | NO | internal |
| _DEVICE_NODE | 784 | 0x310 | 800 | FxDevice (_POP_FX_DEVICE*) | **YES** | NO (PnP enumeration) |

### _KTM (960 bytes) — EXACT SIZE MATCH

- Struct size: 960 bytes (0x3C0) — exact match for bucket 976
- Offset 0x50: NamespaceLink.Links.Links.Blink (LIST_ENTRY pointer) — dereferenced during balanced link tree traversal
- User-triggerable: NtCreateTransactionManager, NtCreateTransaction
- **CRITICAL ISSUE**: NtCreateTransactionManager (0x1403d00c0) and TmInitializeTransactionManager (0x1403d05c0) are thunks (`jmp __imp_*`). The import `__imp_TmInitializeTransactionManager` at 0x1401314d8 points to 0xFFFFFFFFFFFFFFFF (unresolved). KTM implementation is NOT in this ntoskrnl IDB — it's in a separate module loaded at runtime.
- Cannot verify: pool type, zeroing behavior, free path, or allocation details

### ObpCreateObject Calls

Scanned ALL xrefs to ObpCreateObject (0x1407022d0) for body sizes 900-1000:
- **ZERO matches** — no kernel objects are created with body sizes in this range

---

## 5. KTM Allocation Path Analysis

```
NtCreateTransactionManager (0x1403d00c0) — thunk, size=7
  → jmp __imp_NtCreateTransactionManager

NtCreateTransaction (0x1403d00a0) — thunk, size=7
  → jmp __imp_NtCreateTransaction

TmInitializeTransactionManager (0x1403d05c0) — thunk
  → jmp __imp_TmInitializeTransactionManager (0x1401314d8 → 0xFFFFFFFFFFFFFFFF)

TmCreateEnlistment (0x1403d04e0) — thunk
  → jmp __imp_TmCreateEnlistment
```

KTM-related functions found in ntoskrnl:
- TmInitSystem (0x1403cffe0)
- TmInitSystemPhase2 (0x1403cffc0)
- CmKtmNotification (0x14066e410)
- CmTmCreateEnlistment (0x140766820)

The KTM implementation appears to be in a dynamically loaded module (likely `tm.sys` or a kernel extension). The _KTM structure at 960 bytes with Blink at offset 0x50 remains the best theoretical candidate, but the allocation path cannot be verified in this IDB.

---

## 6. IRP Approach (Alternative Bucket 944)

IRP at StackSize=10: 208 + 72*10 = 928 bytes → total 944 → bucket 944 (user 913-928)

| Property | Value |
|----------|-------|
| Allocation size | 928 bytes (0x3A0) |
| LFH bucket | 944 (user 913-928) |
| Pool type | NonPagedPoolNx (0x200) |
| Pool tag | 'Irp ' (0x20707249) |
| Zeroed on alloc | **YES** — memset(buf, 0, size) in IopAllocateIrpPrivate (0x1402D2220) |
| Offset 0x50 | **PKEVENT UserEvent** — pointer, dereferenced on IRP completion |
| User-triggerable | **YES** — NtReadFile, NtWriteFile, NtDeviceIoControlFile, etc. |
| Free path | ExFreePoolWithTag — NO zeroing on free |
| Lookaside bypass | IopLargeIrpStackLocations = 255 (signed char = -1), all IRPs go through pool alloc |

**IRP exploit flow (two-stage):**
1. Spray IRPs at 928 bytes (StackSize=10) via async I/O operations
2. Set UserEvent on each IRP to a controlled KEVENT handle
3. Complete and free the IRPs — UserEvent pointer survives at offset 0x50 (no zeroing on free)
4. Allocate portcls at 928 bytes (bucket 944) — reclaims freed IRP slot
5. portcls writes controlled data, including fake pointer at offset 0x50
6. Free portcls — controlled data survives
7. Allocate new IRP at 928 bytes — **BUT memset zeros the slot**, wiping our data at 0x50

**Problem**: The IRP memset in step 7 wipes our controlled data. The IRP cannot be the reclaiming (target) object because it zeros on alloc.

**Alternative IRP flow (IRP as source, portcls as target):**
1. Spray IRPs at 928 bytes, set UserEvent to controlled event
2. Free IRPs — UserEvent (valid KEVENT ptr) survives at 0x50
3. Allocate portcls at 928 bytes — reclaims slot, portcls does NOT zero on alloc
4. portcls reads stale UserEvent at offset 0x50 — gets a valid KEVENT pointer
5. This gives portcls a real kernel pointer at 0x50, not an arbitrary one

**Limitation**: UserEvent is a valid KEVENT pointer, not an attacker-controlled arbitrary address. This enables type confusion (treating KEVENT as a different structure) but not arbitrary read/write.

**Portcls at 928**: portcls can target bucket 944 by allocating at 928 bytes. The portcls format buffer size is user-controlled through the KSPIN_CONNECT structure.

---

## 7. VidSchiCreateContextInternal (dxgmms1.sys) — Best Alternative

This is the ONLY user-triggerable 960-byte NonPagedPoolNx allocation found across all 10 IDA instances.

| Property | Value |
|----------|-------|
| Function | VidSchiCreateContextInternal (0x1c0052a5e) |
| Module | dxgmms1.sys (PID 4980) |
| Allocation | ExAllocatePoolWithTag(NonPagedPoolNx, 0x3C0, 'ViSh') |
| Size | 960 bytes (0x3C0) — exact match |
| LFH bucket | 976 (user 945-960) |
| Pool tag | 'ViSh' (0x68536956) |
| Zeroed on alloc | **YES** — memset(buf, 0, 0x3C0) |
| Zeroed on free | **NO** — ExFreePoolWithTag (no zeroing) |
| User-triggerable | **YES** — D3DKMTCreateContext → dxgkrnl → dxgmms1 |
| Offset 0x50 | **KTHREAD pointer** (KeGetCurrentThread()) |
| Free function | VidSchTerminateContext → ExFreePoolWithTag |

**Content at offset 0x50:**
```c
*((_QWORD *)v9 + 10) = KeGetCurrentThread();  // offset 0x50 = KTHREAD ptr
```

**Other field offsets:**
```c
*(_DWORD *)v9 = 878799190;           // offset 0x00: tag 'ViSh'
*((_QWORD *)v9 + 7) = a3;             // offset 0x38: context handle
*((_QWORD *)v9 + 13) = a1;            // offset 0x68: adapter
*((_OWORD *)v9 + 7) = *(_OWORD *)a2;  // offset 0x70: user D3DDDI_CREATECONTEXT flags
*((_QWORD *)v9 + 16) = *(a2 + 16);    // offset 0x80: node ordinal
*((_DWORD *)v9 + 34) = *(a2 + 24);    // offset 0x88: priority
*((_DWORD *)v9 + 22) = *(a2 + 4);     // offset 0x58: node index
```

**Exploit viability:**
- The allocation is ZEROED on alloc, so it can't be the RECLAIMING object (it would wipe portcls data)
- It CAN be the SOURCE object: create context → free → portcls reclaims → portcls sees stale KTHREAD at 0x50
- The KTHREAD pointer at 0x50 is a valid kernel address but NOT user-controlled
- This enables KTHREAD type confusion, not arbitrary read/write
- For arbitrary control at 0x50, portcls must be the source (it writes user-controlled format data)

**Two-stage exploit with GPU context:**
1. Spray GPU contexts (960 bytes each, KTHREAD at 0x50)
2. Free some GPU contexts (KTHREAD pointers survive at 0x50)
3. Allocate portcls at 960 bytes → reclaims freed GPU context slot
4. portcls does NOT zero on alloc → stale KTHREAD ptr at 0x50 survives
5. portcls reads/dereferences offset 0x50 → gets KTHREAD pointer
6. If portcls treats 0x50 as a function pointer or object pointer → type confusion with KTHREAD

**Or reverse:**
1. portcls allocates 960, fills with controlled data (fake ptr at 0x50), frees
2. GPU context allocates 960 → reclaims slot → **BUT memset zeros it** → fake ptr wiped
3. NO-GO (GPU context zeros on alloc)

---

## 8. Complete Candidate Table

### Bucket 976 (user 945-960) — PRIMARY TARGET

| # | Object | Module | Size | Bucket | Pool Tag | Zeroed on Alloc | Zeroed on Free | User-Triggerable | Offset 0x50 | Ptr at 0x50? | User Controls 0x50? | Verdict |
|---|--------|--------|------|--------|----------|-----------------|----------------|-----------------|-------------|-------------|---------------------|---------|
| 1 | _KTM | ntoskrnl (thunk) | 960 | 976 | unknown | unknown | unknown | YES (NtCreateTransactionManager) | NamespaceLink.Links.Blink | **YES** (LIST_ENTRY*) | unknown | **BEST CANDIDATE** — can't verify due to thunk |
| 2 | VidSchiCreateContextInternal | dxgmms1.sys | 960 | 976 | 'ViSh' | YES (memset) | **NO** | **YES** (D3DKMTCreateContext) | KTHREAD ptr | **YES** | NO (kernel-set) | Source-only (stale KTHREAD) |
| 3 | EtwpCovSampCaptureContextStart | ntoskrnl | 960 | 976 | 'EtwV' | YES (memset) | NO | NO (singleton) | KTHREAD ptr | YES | NO | NO-GO (not user-triggerable) |
| 4 | PopEtInit | ntoskrnl | 952 | 976 | 'PoET' | YES (memset) | NO | NO (system init) | InternTable data | NO | NO | NO-GO (not user-triggerable) |
| 5 | FsFilterInit | ntoskrnl | 968 | 992 | unknown | YES (memset) | NO | NO (system init) | FS filter data | unknown | NO | NO-GO (wrong bucket, not user-triggerable) |

### Bucket 944 (user 913-928) — ALTERNATIVE TARGET

| # | Object | Module | Size | Bucket | Pool Tag | Zeroed on Alloc | Zeroed on Free | User-Triggerable | Offset 0x50 | Ptr at 0x50? | User Controls 0x50? | Verdict |
|---|--------|--------|------|--------|----------|-----------------|----------------|-----------------|-------------|-------------|---------------------|---------|
| 6 | _IRP (StackSize=10) | ntoskrnl | 928 | 944 | 'Irp ' | YES (memset) | **NO** | **YES** (any I/O) | PKEVENT UserEvent | **YES** | Partial (valid KEVENT only) | Source-only (stale KEVENT ptr) |

### Bucket 688 (user 657-672) — DISTANT ALTERNATIVE

| # | Object | Module | Size | Bucket | Pool Tag | Zeroed on Alloc | Zeroed on Free | User-Triggerable | Offset 0x50 | Ptr at 0x50? | User Controls 0x50? | Verdict |
|---|--------|--------|------|--------|----------|-----------------|----------------|-----------------|-------------|-------------|---------------------|---------|
| 7 | EtwTiLogInsertQueueUserApc | ntoskrnl | 672 | 688 | unknown | **NO** | NO | **YES** (QueueUserApc) | ETW buffer data | unknown | NO (write-only ETW) | Possible if portcls targets 672 |

---

## 9. Portcls Pool Allocation Analysis

Portcls does NOT directly call ExAllocatePoolWithTag for 960-byte format buffers. The PcCaptureFormat function allocates only 14 bytes. The 960-byte format buffer allocation is handled through the KS (Kernel Streaming) framework, likely via `KsCreatePin` → internal KS allocation → `ExAllocatePoolWithTag` in ks.sys (not loaded as an IDA instance).

Portcls pool allocations found:
- PcCaptureFormat: 14 bytes (0xE) — string/data, not format buffer
- CreatePortPinWaveRT: 472 bytes (0x1D8) — pin object creation
- CIrpStream::Init: 10240 bytes (0x2800) — IRP stream buffer
- CAllocatorMXF: 4096/4080 bytes — MIDI allocator
- Largest NonPagedPoolNx: 15 bytes (RegisterMiniportWMIProvider)

The portcls 960-byte allocation must be traced through the KS framework (ks.sys) which is not in the loaded IDA instances.

---

## 10. Strategy Recommendations

### Strategy A: KTM at 960 bytes (HIGHEST POTENTIAL)

The _KTM structure at exactly 960 bytes with a LIST_ENTRY Blink pointer at offset 0x50 is the best candidate. It's user-triggerable via NtCreateTransactionManager/NtCreateTransaction.

**Blocker**: KTM implementation is via thunks to an unresolved import. The actual allocation happens in a separate module not in the loaded IDA instances.

**Next step**: Load `tm.sys` or trace the KTM allocation path through WindDbg or a different analysis method. Verify:
1. Pool type is NonPagedPoolNx
2. Allocation is NOT zeroed on alloc
3. Free path uses ExFreePoolWithTag (no zeroing)
4. The Blink at offset 0x50 is dereferenced during normal KTM operations

### Strategy B: GPU Context at 960 bytes (BACKUP — Type Confusion)

VidSchiCreateContextInternal in dxgmms1.sys allocates exactly 960 bytes in NonPagedPoolNx with tag 'ViSh'. It's user-triggerable via D3DKMTCreateContext.

**Limitation**: Zeroed on alloc (memset), so can only be the SOURCE object (not the reclaiming target). The KTHREAD pointer at 0x50 is valid but not user-controlled.

**Exploit flow**:
1. Spray GPU contexts (960 bytes, KTHREAD at 0x50)
2. Free GPU contexts (KTHREAD ptr survives at 0x50)
3. portcls reclaims at 960 bytes → reads stale KTHREAD at 0x50
4. Type confusion: portcls dereferences KTHREAD as its own structure

### Strategy C: IRP at 928 bytes (BUCKET 944 — Alternative Size)

IRP at StackSize=10 is 928 bytes in bucket 944. portcls can target 928 bytes instead of 960.

**Limitation**: IRP is zeroed on alloc. Can only be SOURCE. UserEvent at 0x50 is a valid KEVENT pointer, not arbitrary.

**Exploit flow**:
1. Spray IRPs at 928 bytes, set UserEvent to controlled event
2. Free IRPs (UserEvent ptr survives at 0x50)
3. portcls reclaims at 928 bytes → reads stale UserEvent at 0x50
4. Type confusion: portcls treats KEVENT as its own pointer

### Strategy D: ETW Buffer at 672 bytes (NON-ZEROED, DIFFERENT BUCKET)

EtwTiLogInsertQueueUserApc allocates 672 bytes in NonPagedPoolNx, NOT zeroed. User-triggerable via QueueUserApc.

**Advantage**: NON-ZEROED on alloc — can be the RECLAIMING (target) object.

**Exploit flow**:
1. portcls allocates at 672 bytes, fills with controlled data (fake ptr at 0x50), frees
2. QueueUserApc triggers ETW allocation at 672 bytes → reclaims slot
3. ETW buffer does NOT zero → fake ptr at 0x50 survives
4. If ETW buffer reads/dereferences offset 0x50 → uses our fake pointer

**Blocker**: Need to verify that the ETW buffer at 672 bytes has a pointer at offset 0x50 that gets dereferenced. Previous analysis labeled it "write-only ETW buffer."

### Strategy E: Non-Zeroed Allocations at Any Size

From the 358 non-zeroed NonPagedPoolNx allocations in ntoskrnl, find one that:
1. Has a pointer at offset 0x50 that gets dereferenced
2. Is user-triggerable
3. Can be matched to a portcls allocation size

**Most promising**: Size 672 (EtwTiLogInsertQueueUserApc) is the only user-triggerable non-zeroed allocation near the target range. Need to check offset 0x50 field.

---

## 11. Search Methodology and Coverage

### Immediate Value Searches
Searched for immediate values 960, 952, 944, 928, 968, 992 across ALL 10 IDA instances:
- ntoskrnl: 14+42+35+17+8+102 = 218 total hits
- clfs.sys: 0+1+0+1+0+2 = 4 hits
- portcls.sys: 0+1+2+3+4+0 = 10 hits
- dxgkrnl.sys: 11+14+10+2+4+4 = 45 hits
- dxgmms2.sys: 1+1+2+0+1+3 = 8 hits
- dxgmms1.sys: 1+4+3+0+0+0 = 8 hits
- tdx.sys: 0 hits
- win32k.sys: 24 hits (table entries)
- win32kfull.sys: 6+12+3+12+0+37 = 70 hits
- win32kbase.sys: 2+9+5+2+0+7 = 25 hits

Most hits are error codes, line numbers, resource descriptors, or constant values — NOT allocation sizes.

### Pool Allocation Call Site Scans
Scanned all ExAllocatePoolWithTag and ExAllocatePool2 call sites in ntoskrnl for:
- Size parameter (rdx/edx) in range 929-992
- Pool type (rcx/ecx) = 0x200 (NonPagedPoolNx)

Results: Only 3 NonPagedPoolNx allocations at 929-992 in ntoskrnl (all zeroed, all system init).

### ObpCreateObject Scan
Scanned all ObpCreateObject calls for body sizes 900-1000: ZERO matches.

### Structure Size Search
Checked all IDA type library structs at 945-960 bytes: Only _KTM (960 bytes).

---

## 12. Final Verdict

**No perfect alternative exists** across all 10 loaded IDA instances for a 960-byte NonPagedPoolNx allocation that is:
- NOT zeroed on alloc
- User-triggerable
- Has user-controlled content at offset 0x50
- In bucket 976

**Best remaining options ranked by viability:**

1. **KTM (_KTM, 960 bytes)** — exact size, pointer at 0x50, user-triggerable, but allocation path untraceable (thunks to unresolved import). Requires loading tm.sys or WindDbg tracing.

2. **GPU Context (VidSchiCreateContextInternal, 960 bytes)** — exact size, user-triggerable, non-zeroed on free, but zeroed on alloc and KTHREAD at 0x50 is not user-controlled. Enables type confusion, not arbitrary R/W.

3. **IRP at 928 bytes (bucket 944)** — user-triggerable, UserEvent at 0x50 is dereferenced, non-zeroed on free, but zeroed on alloc and UserEvent is a valid KEVENT (not arbitrary). Requires portcls to target 928 instead of 960.

4. **ETW buffer at 672 bytes (bucket 688)** — non-zeroed on alloc, user-triggerable, but needs verification of offset 0x50 dereference. Requires portcls to target 672.

5. **Portcls remains primary** — portcls PcCaptureFormat fills user-controlled format data into the allocation at 0x50. The KS framework (ks.sys) handles the actual 960-byte allocation. If KsCreatePin works, portcls is still the best approach.
