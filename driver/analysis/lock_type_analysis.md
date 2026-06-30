# VIDMM Lock Type Analysis - D3DKMT Dangling Mapping Exploit

## 1. Executive Summary

**BEST LOCK TYPE: Type 5 (non-CPU-visible) on a system memory segment (Option C)**

Lock type 5 stores the CPU virtual address at `multi_alloc+0x10` via either `MmMapViewOfSection` (paravirtualized) or a driver callback (non-paravirtualized). The destroy path (`CloseOneAllocation` at `0x1C006A8D0`) checks `VIDMM_ALLOC+0x90` — a **completely different field** that is never set for type 5. The `DestroyOneAllocation` path (`0x1C0069DC0`) skips cleanup entirely when segment flags lack `0x40000`, `0x10000000`, `0x20000000`, and `0x8`. Only `VIDMM_GLOBAL::Unlock` (`0x1C006B220`) properly unmaps `multi_alloc+0x10` — and we never call it.

**The critical requirement is system memory backing pages.** For non-paravirtualized type 5 on a non-CPU-visible **system memory segment** (`VIDMM_SYSMEM_SEGMENT`), the backing pages are system RAM. When the allocation is destroyed, `UnlockAllocationBackingStore` frees the physical pages. The dangling PTE mapping at the CPU VA persists, pointing to freed system memory. GDI `SURFACE` object spray reclaims those pages, and writing to `pData + 0x50` corrupts `SURFACE.pvScan0` at `SURFACE+0x50`, yielding arbitrary kernel R/W via `GetBitmapBits`/`SetBitmapBits` at 200M+ ops/sec.

**Secondary option: Type 5 paravirtualized (WARP adapter)** — uses `MmMapViewOfSection` with system memory backing, but the section object is NOT dereferenced during destroy (skipped for `0x2000` flag), so the timing window for page reclamation depends on async/late cleanup.

---

## 2. Lock Type 1 Analysis (Default, CPU-Visible)

### Function: `VIDMM_GLOBAL::LockInternal` at `0x1C006BEB0`

Type 1 is the **default** lock type, set when `global_alloc+0x50 & 0x80` is set (CPU-visible) and no other special conditions apply.

### CPU VA Storage

Type 1 does NOT create a new mapping. It falls through to `LABEL_20` in `LockInternal`:

```c
// LABEL_20 (0x1C006C12D)
v24 = *(_DWORD *)(v13 + 80);  // global_alloc+0x50 (segment flags)
if ( (v24 & 0x4000) != 0 )    // CPU host aperture flag
{
    v25 = *(void **)(v13 + 528);  // global_alloc+0x210
}
else
{
    if ( (v24 & 0x2000) != 0 )    // paravirtualized flag
    {
        LockParavirtualizedAllocationOnHost(a3, a4);  // stores at global_alloc+0x210
        goto LABEL_28;
    }
    v15 = **(unsigned int **)(v13 + 496);  // segment flags
    if ( (v15 & 8) != 0 )
        v25 = *(void **)(v13 + 360);  // global_alloc+0x168
    else
        v25 = (void *)v12[2];         // multi_alloc+0x10
}
*a4 = v25;  // return CPU VA
```

For type 1, the CPU VA is read from an **existing mapping** — it assumes the allocation was already mapped during commit/paging. The specific field depends on segment flags:
- `0x4000` set: `global_alloc+0x210`
- `0x2000` set: `global_alloc+0x210` (via `LockParavirtualizedAllocationOnHost`)
- Segment flag `0x8` set: `global_alloc+0x168`
- Default: `multi_alloc+0x10`

### Backing Pages

Depends on the segment. CPU-visible segments use system memory or CPU-accessible VRAM (BAR).

### Destroy Path

Type 1 does not create a new mapping, so there is no new unmap needed. The existing mapping is managed by the commit/paging path.

### Reclaimability

Not applicable — no dangling mapping is created.

### Verdict

**Not useful for the exploit.** No new mapping is created; the CPU VA comes from an existing mapping that is properly managed.

---

## 3. Lock Type 3 Analysis (CPU-Visible Segment)

### Function: `VIDMM_GLOBAL::LockAllocInCpuVisibleSegment` at `0x1C00AF968`

### Trigger Conditions

From `VIDMM_GLOBAL::Lock` at `0x1C006B380`:

```c
v42 = *(_DWORD *)(v41 + 80);   // global_alloc+0x50 (segment flags)
v43 = *(_QWORD *)(v41 + 128);  // global_alloc+0x80 (segment pointer)
LODWORD(v63) = 1;              // default type 1
if ( (v42 & 0x80u) == 0 )      // NOT CPU visible
{
    LODWORD(v63) = 5;           // type 5
}
else if ( v43 )                 // CPU visible AND has segment
{
    v44 = *(_DWORD *)(v43 + 80);  // segment+0x50 (segment flags)
    if ( (v44 & 0x1001) == 0 )    // NOT aperture (0x1000) and NOT (0x1)
    {
        if ( (v44 & 4) != 0 )     // CPU visible memory segment flag
        {
            if ( (v40[4] & 1) == 0 )  // multi_alloc+0x20 & 1 == 0 (not locked)
            {
                LODWORD(v63) = 3;     // TYPE 3
            }
        }
    }
}
```

Type 3 requires ALL of:
1. `global_alloc+0x50 & 0x80` set (CPU-visible allocation)
2. `global_alloc+0x80` non-NULL (has segment pointer)
3. `segment+0x50 & 0x1001 == 0` (not aperture segment)
4. `segment+0x50 & 0x4` set (CPU-visible memory segment)
5. `multi_alloc+0x20 & 1 == 0` (not already locked)
6. `global_alloc+0x100 == 0` (not already locked)

### CPU VA Storage

`LockAllocInCpuVisibleSegment` calls `VIDMM_GLOBAL::Rotate` (`0x1C00B21DC`), which calls a virtual function on the process heap interface to map an MDL into system space:

```c
// LockAllocInCpuVisibleSegment (0x1C00AF968)
v2 = *a2;              // multi_alloc
v4 = **a2;             // global_alloc
v5 = *(_QWORD *)(v4 + 136);  // global_alloc+0x88 (segment offset)
v6 = *(struct _MDL **)(*(_QWORD *)(v4 + 128) + 32LL);  // segment+0x20 (MDL)

if ( (*(_DWORD *)(*((_QWORD *)this + 3) + 348LL) & 8) != 0 )
    v7 = VidMmiBuildMdlFromMdl(v2[2], *(_QWORD *)(v4 + 16), v6, v5 / 4096);
else
    v7 = VidMmiBuildMdlForContiguousMmIo(v2[2], *(_QWORD *)(v4 + 8), ...);

v10 = VIDMM_GLOBAL::Rotate(this, ..., v7, *(_QWORD *)(v4 + 16), ..., v4);
if ( v10 >= 0 )
{
    *((_BYTE *)v2 + 32) |= 1u;     // multi_alloc+0x20 |= 1 (locked flag)
    *(_BYTE *)(v4 + 90) = 1;       // global_alloc+0x5A = 1 (CPU visible lock flag)
}
```

After `Rotate` returns, `LockInternal` proceeds to `LABEL_20` to determine the CPU VA:
- If segment flags `& 0x8`: CPU VA = `global_alloc+0x168`
- Otherwise: CPU VA = `multi_alloc+0x10` (`v12[2]`)

The `Rotate` function (`0x1C00B21DC`) calls a virtual function at vtable offset `+0x30` on the process heap interface:
```c
result = (*(__int64 (__fastcall **)(...))(*(_QWORD *)a2 + 48LL))(a2, a1, a3);
```
This maps the MDL into the process address space, storing the CPU VA at the location specified by the process heap interface.

### Destroy Path — Does It Skip Unmap?

**YES.** `CloseOneAllocation` checks `VIDMM_ALLOC+0x90`:
```c
v19 = *(_QWORD *)&a2[6].Header.Lock;  // VIDMM_ALLOC + 6*0x18 = VIDMM_ALLOC+0x90
if ( v19 )
{
    if ( (**(_DWORD **)(v12 + 496) & 0x10000008) != 0 )
        MmUnmapViewOfSection(process, v19);
    *(_QWORD *)&a2[6].Header.Lock = 0;
}
```

`VIDMM_ALLOC+0x90` is **never set** by type 3. The CPU VA is at `multi_alloc+0x10` or `global_alloc+0x168` — neither is `VIDMM_ALLOC+0x90`.

However, `CloseOneAllocation` also has a `FreeAllocMappedVaRangeList` path:
```c
if ( a2[5].Header.WaitListHead.Flink != &a2[5].Header.WaitListHead )  // VIDMM_ALLOC+0x78
{
    CVirtualAddressAllocator::FreeAllocMappedVaRangeList(VirtualAddressAllocator, a2);
}
```
This checks `VIDMM_ALLOC+0x78` (a list entry). If the `Rotate` path adds the VA range to this list, it **may** get cleaned up. This needs further analysis to determine if type 3 populates this list.

Additionally, `DestroyOneAllocation` (`0x1C0069DC0`) has a cleanup path:
```c
if ( (*((_DWORD *)a3 + 21) & 0x40) != 0 )  // global_alloc+0x54 & 0x40 (has segment backing)
{
    v22 = *((_DWORD *)a3 + 20);  // global_alloc+0x50
    if ( (v22 & 0x2000) == 0 )   // NOT paravirtualized
    {
        if ( (v22 & 0x40000) == 0 && (**((_DWORD **)a3 + 62) & 0x10020008) == 0 )
            goto LABEL_42;  // SKIP ALL CLEANUP
        // ...
        if ( (v23 & 0x800000) != 0 )
        {
            MmUnmapViewInSystemSpace(*((PVOID *)a3 + 45));  // global_alloc+0x168
            *((_DWORD *)a3 + 20) &= ~0x800000u;
            *((_QWORD *)a3 + 45) = 0;
        }
        VidMmDereferenceObjectAsync(*((PVOID *)a3 + 44));  // global_alloc+0x160
    }
}
```

For type 3 on a CPU-visible memory segment:
- `global_alloc+0x54 & 0x40`: Set (has segment backing) — enters the block
- `global_alloc+0x50 & 0x2000`: NOT set (not paravirtualized) — enters the inner block
- `global_alloc+0x50 & 0x40000`: Depends on whether section is used
- `segment_flags & 0x10020008`: Segment flag `0x8` may be set for CPU-visible memory segments

If segment flags have `0x8` set (which is common for system memory segments), then `0x10020008 != 0`, and the cleanup does NOT skip. It would then unmap `global_alloc+0x168` if `0x800000` is set, and dereference `global_alloc+0x160`.

**But `multi_alloc+0x10` is never cleaned up by either path.** The only cleanup for `multi_alloc+0x10` is in `Unlock`:
```c
// VIDMM_GLOBAL::Unlock (0x1C006B220)
v9 = **(unsigned int **)(v5 + 496);  // segment flags
if ( (v9 & 0x40000) != 0 )
{
    if ( (v9 & 0x20000000) != 0 )
        MmUnmapViewOfSection(CurrentProcess, v2[2]);  // unmap multi_alloc+0x10
    else
        // driver callback unmap
    v2[2] = 0;  // clear multi_alloc+0x10
}
```

### Backing Pages

Type 3 uses a **CPU-visible memory segment** (`segment+0x50 & 0x4`). These segments are backed by **system memory** (RAM). The `VIDMM_SYSMEM_SEGMENT::CommitResource` function (`0x1C0066C20`) commits resources to system memory via `LockAllocationBackingStore`.

### Reclaimability

**YES** — system memory backing pages can potentially be reclaimed by GDI `SURFACE` objects, if the freed pages return to the same pool that `SURFACE::Allocate` draws from.

### Verdict

**VIABLE but with complications.** The destroy path skips unmap of `multi_alloc+0x10`, and backing pages are system memory. However:
1. The `FreeAllocMappedVaRangeList` path in `CloseOneAllocation` might clean up the mapping
2. The `DestroyOneAllocation` path might unmap `global_alloc+0x168` if segment flags have `0x8`
3. Need to verify if the `Rotate` mapping creates a system-space mapping that gets cleaned up

**Risk: The cleanup might be more thorough than type 5.**

---

## 4. Lock Type 4 Analysis (CPU Host Aperture / Aperture Fallback)

### Function: `VIDMM_GLOBAL::LockInAperture` at `0x1C00AFA64`

### Trigger Conditions

Type 4 is a **fallback** — it is set when types 1/3/5 fail in `LockInternal`:
```c
// LockInternal (0x1C006BEB0)
if ( v22 >= 0 )
    goto LABEL_20;  // success
// On failure:
*((_BYTE *)a2 + 4) = 1;  // set "already attempted" flag
*(_DWORD *)a2 = 4;       // set type to 4 (fallback)
```

Then on the next iteration, type 4 calls `LockInAperture`:
```c
if ( *(_DWORD *)a2 == 4 )
{
    ExReleasePushLockExclusiveEx(v13 + 472, 0);
    KeLeaveCriticalRegion();
    LODWORD(v11) = VIDMM_GLOBAL::LockInAperture(this, a3, v29, v28);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusiveEx(v13 + 472, 0);
}
```

### CPU VA Storage

`LockInAperture` evicts and re-pages the allocation:
```c
// LockInAperture (0x1C00AFA64)
v6 = **a2;  // global_alloc
if ( *((_QWORD *)v6 + 16) )  // global_alloc+0x80 (has segment)
{
    VIDMM_WORKER_THREAD::SuspendAccessToAllocation(*this, v6);
    VIDMM_GLOBAL::EvictOneAllocation(this, a2, 0);
}
return VIDMM_GLOBAL::PageInOneAllocation(this, a2, 2);  // page into aperture
```

After paging, the CPU VA is determined by `LABEL_20` based on segment flags. For aperture segments (flag `0x4000`), the CPU VA would be at `global_alloc+0x210`.

### Backing Pages

Aperture segments map to the GPU's **BAR (Base Address Register)** — this is **VRAM**, not system memory. BAR pages cannot be reclaimed by GDI `SURFACE` objects.

### Reclaimability

**NO** — BAR/VRAM pages cannot be reclaimed by `SURFACE` objects (which are in kernel session pool / system memory).

### Verdict

**NOT VIABLE.** Aperture segments use VRAM backing, which cannot be reclaimed by GDI `SURFACE` objects.

---

## 5. Lock Type 2 Analysis (CPU Host Aperture)

### Function: `VIDMM_GLOBAL::LockAllocInCpuHostAperture` at `0x1C00AF83C`

### Trigger Conditions

Type 2 is set in `LockInternal` when `*(_DWORD *)a2 == 2`:
```c
if ( *(_DWORD *)a2 == 2 )
{
    if ( (v12[4] & 1) != 0 )  // already locked
        goto LABEL_20;
    v22 = VIDMM_GLOBAL::LockAllocInCpuHostAperture(this, a3, 
        *(struct VIDMM_CPU_HOST_APERTURE **)(*(_QWORD *)(**a3 + 128) + 488LL));
}
```

Type 2 is not directly set by the `Lock` function's type determination logic. It may be set by a different caller or by the deferred command path. The CPU host aperture is a BAR mapping.

### CPU VA Storage

`LockAllocInCpuHostAperture` calls `BuildMdlForAllocInCpuHostAperture` and then `Rotate`:
```c
v3 = *(__int64 **)a2;  // multi_alloc
v6 = *v3;              // global_alloc
v7 = VIDMM_GLOBAL::BuildMdlForAllocInCpuHostAperture(this, a2, a3, &P);
v11 = VIDMM_GLOBAL::Rotate(this, ..., P, *(_QWORD *)(v6 + 16), ..., v6);
if ( v11 >= 0 )
{
    *((_BYTE *)v3 + 32) |= 1u;   // multi_alloc+0x20 |= 1
    *(_BYTE *)(v6 + 90) = 1;     // global_alloc+0x5A = 1
}
```

CPU VA determined by `LABEL_20`: for flag `0x4000`, uses `global_alloc+0x210`.

### Backing Pages

CPU host aperture uses **BAR mapping** — VRAM, not system memory.

### Reclaimability

**NO** — BAR pages cannot be reclaimed by `SURFACE` objects.

### Verdict

**NOT VIABLE.** CPU host aperture uses BAR/VRAM backing.

---

## 6. Lock Type 5 Analysis (Non-CPU-Visible)

### Function: `VIDMM_GLOBAL::LockInternal` at `0x1C006BEB0`, type 5 path

### Trigger Conditions

From `VIDMM_GLOBAL::Lock` at `0x1C006B380`:
```c
v42 = *(_DWORD *)(v41 + 80);  // global_alloc+0x50 (segment flags)
LODWORD(v63) = 1;             // default type 1
if ( (v42 & 0x80u) == 0 )     // NOT CPU visible
{
    LODWORD(v63) = 5;          // TYPE 5
}
```

Type 5 is triggered when `global_alloc+0x50 & 0x80 == 0` — the allocation is on a **non-CPU-visible segment**. This is the simplest trigger: any allocation on a non-CPU-visible segment gets type 5.

### CPU VA Storage

Type 5 has two sub-paths in `LockInternal`:

#### Sub-path A: Paravirtualized (segment flag `0x20000000`)

```c
// 0x1C006BF73
v16 = **(_DWORD **)(v13 + 496);  // segment flags
if ( (v16 & 0x20000000) != 0 )   // paravirtualized
{
    v28 = nullptr;
    CurrentProcess = PsGetCurrentProcess();
    LODWORD(v11) = MmMapViewOfSection(
        *(_QWORD *)(v13 + 352),    // global_alloc+0x160 (section object)
        CurrentProcess,             // target process
        v12 + 2,                    // base address = multi_alloc+0x10
        0,                          // zero bits
        *(_QWORD *)(v13 + 8),       // allocation size (global_alloc+0x8)
        &v28,                       // section offset
        v13 + 8,                    // view size pointer
        2,                          // inherit = ViewUnmap
        0,                          // allocation
        ~((_WORD)v16 << 8) & 0x400 | 4u);  // win32 protection
    if ( (int)v11 >= 0 )
        goto LABEL_20;
}
```

`MmMapViewOfSection` stores the CPU VA at `v12 + 2` = `multi_alloc + 0x10` (since `v12` is a `QWORD*`, `+2` = `+0x10` bytes).

#### Sub-path B: Non-paravirtualized (driver callback)

```c
// 0x1C006C005
else
{
    v18 = (*(__int64 (__fastcall **)(_QWORD, __int64, _QWORD))
           (**(_QWORD **)(v12[1] + 24) + 72LL))(
            *(_QWORD *)(v12[1] + 24),  // dxgadapter interface
            v12[3],                     // allocation handle
            *(_QWORD *)(v13 + 8));      // allocation size
    v12[2] = v18;  // store CPU VA at multi_alloc+0x10
    if ( v18 )
        goto LABEL_20;
    LODWORD(v11) = -1073741801;  // STATUS_INVALID_PARAMETER
}
```

The driver callback at vtable offset `+0x48` (`72/8*8 = 9th function`) maps the allocation and returns the CPU VA, which is stored at `v12[2]` = `multi_alloc + 0x10`.

**Both sub-paths store the CPU VA at `multi_alloc+0x10`.**

### Destroy Path — CONFIRMED SKIP

#### CloseOneAllocation (`0x1C006A8D0`)

```c
// 0x1C006AA15
v19 = *(_QWORD *)&a2[6].Header.Lock;  // VIDMM_ALLOC + 0x90
if ( v19 )  // only if VIDMM_ALLOC+0x90 is non-NULL
{
    if ( (**(_DWORD **)(v12 + 496) & 0x10000008) != 0 )
        MmUnmapViewOfSection(**(_QWORD **)(*(_QWORD *)&a2->Header.Lock + 8LL), v19);
    *(_QWORD *)&a2[6].Header.Lock = 0;
}
```

**`VIDMM_ALLOC+0x90` is NEVER set by type 5.** The CPU VA is at `multi_alloc+0x10`, not `VIDMM_ALLOC+0x90`. The unmap is **skipped**.

The `FreeAllocMappedVaRangeList` path at `VIDMM_ALLOC+0x78` checks a list that is **not populated by type 5** (type 5 does not go through `Rotate` or the virtual address allocator). This path is also skipped.

#### DestroyOneAllocation (`0x1C0069DC0`)

```c
// 0x1C006A0D6
if ( (*((_DWORD *)a3 + 21) & 0x40) != 0 )  // global_alloc+0x54 & 0x40
{
    v22 = *((_DWORD *)a3 + 20);  // global_alloc+0x50
    if ( (v22 & 0x2000) == 0 )   // NOT paravirtualized
    {
        if ( (v22 & 0x40000) == 0 &&    // no section
             (**((_DWORD **)a3 + 62) & 0x10020008) == 0 )  // segment flags
            goto LABEL_42;  // *** SKIP ALL CLEANUP ***
        // ...
        if ( (v23 & 0x800000) != 0 )
        {
            MmUnmapViewInSystemSpace(*((PVOID *)a3 + 45));  // global_alloc+0x168
        }
        VidMmDereferenceObjectAsync(*((PVOID *)a3 + 44));  // global_alloc+0x160
    }
    // For paravirtualized (0x2000 set): ENTIRE BLOCK SKIPPED
}
```

For **non-paravirtualized type 5** on a segment without flags `0x40000`, `0x10000000`, `0x20000000`, or `0x8`:
- `global_alloc+0x50 & 0x40000 == 0` AND `segment_flags & 0x10020008 == 0` → **SKIP ALL CLEANUP**
- The section object at `global_alloc+0x160` is NOT dereferenced
- The system space mapping at `global_alloc+0x168` is NOT unmapped
- `multi_alloc+0x10` is NOT unmapped

For **paravirtualized type 5** (`0x2000` set):
- The entire cleanup block is skipped (the `if ( (v22 & 0x2000) == 0 )` condition fails)
- The section object is NOT dereferenced
- `multi_alloc+0x10` is NOT unmapped

#### Unlock (`0x1C006B220`) — The Only Proper Cleanup

```c
// 0x1C006B2E4
v9 = **(unsigned int **)(v5 + 496);  // segment flags
if ( (v9 & 0x40000) != 0 )           // has section/MmMapViewOfSection
{
    if ( (v9 & 0x20000000) != 0 )     // paravirtualized
    {
        CurrentProcess = PsGetCurrentProcess();
        MmUnmapViewOfSection(CurrentProcess, v2[2]);  // unmap multi_alloc+0x10
    }
    else
    {
        // driver callback unmap
        (*(void (__fastcall **)(...))(**(_QWORD **)(v2[1] + 24) + 80LL))(
            *(_QWORD *)(v2[1] + 24), v2[3], v2[2]);  // unmap multi_alloc+0x10
    }
    v2[2] = 0;  // clear multi_alloc+0x10
}
else
{
    v8 = *(_QWORD *)(v5 + 440) != 0;  // global_alloc+0x1B8 (CPU host aperture)
}
```

**We never call `D3DKMTUnlock`, so this path is never executed.**

### Backing Pages

#### Non-paravirtualized (driver callback)

The driver callback maps the allocation from the segment where it resides. The backing pages depend on the segment type:
- **VRAM segment**: VRAM pages → **CANNOT** be reclaimed by `SURFACE` objects
- **System memory segment** (`VIDMM_SYSMEM_SEGMENT`): System RAM pages → **CAN** be reclaimed

When a non-CPU-visible system memory segment exists, the allocation uses system RAM. When destroyed:
1. `CloseOneAllocation` skips unmap of `multi_alloc+0x10` (checked `VIDMM_ALLOC+0x90`)
2. `DestroyOneAllocation` skips cleanup (flags don't match)
3. `UnlockAllocationBackingStore` frees the physical pages
4. The PTE at the CPU VA persists → **dangling mapping to freed system memory**
5. `SURFACE` spray reclaims the freed pages
6. Write to `pData + 0x50` → corrupts `SURFACE.pvScan0`

#### Paravirtualized (MmMapViewOfSection)

`MmMapViewOfSection` maps a section object (`global_alloc+0x160`) into the process. For WARP/paravirtualized GPUs, the section is backed by **system memory**.

However, the section object is **NOT dereferenced** during destroy for paravirtualized (the `0x2000` flag causes the cleanup block to be skipped). This means:
- The section persists after destroy
- The backing pages remain allocated by the section
- We **cannot** reclaim them with `SURFACE` objects until the section is cleaned up
- The section may be cleaned up asynchronously or when the process/device exits

### Reclaimability

- **Non-paravirtualized, system memory segment**: **YES** — physical pages are freed during destroy
- **Non-paravirtualized, VRAM segment**: **NO** — VRAM pages cannot be reclaimed
- **Paravirtualized (WARP)**: **DELAYED** — section holds pages, async cleanup needed

### Verdict

**BEST OPTION for non-paravirtualized on system memory segment.** The destroy path definitively skips the unmap, and the backing pages are freed system memory that can be reclaimed by `SURFACE` objects.

**VIABLE BUT COMPLEX for paravirtualized (WARP).** The section object persists, requiring a timing window or additional cleanup trigger.

---

## 7. Lock Type Determination Logic

### Function: `VIDMM_GLOBAL::Lock` at `0x1C006B380`

The lock type is determined in `VIDMM_GLOBAL::Lock` before calling `LockInternal`:

```c
// 0x1C006B8A7
v40 = *a2;                    // multi_alloc
v41 = *v40;                   // global_alloc
if ( !*((_DWORD *)v40 + 19) ) // multi_alloc+0x4C (lock count) == 0
{
    v42 = *(_DWORD *)(v41 + 80);   // global_alloc+0x50 (segment flags)
    v43 = *(_QWORD *)(v41 + 128);  // global_alloc+0x80 (segment pointer)
    LODWORD(v63) = 1;              // DEFAULT: type 1

    if ( (v42 & 0x80u) == 0 )      // NOT CPU visible
    {
        LODWORD(v63) = 5;          // TYPE 5 (non-CPU-visible)
    }
    else if ( v43 )                // CPU visible AND has segment
    {
        if ( (*((_DWORD *)this + 1762) & 0x20) != 0 )
            goto LABEL_80;         // deferred lock (type 1 with paging)

        v44 = *(_DWORD *)(v43 + 80);  // segment+0x50 (segment flags)
        if ( (v44 & 0x1001) == 0 )    // NOT aperture, NOT flag 0x1
        {
            if ( (**(_DWORD **)(v41 + 496) & 4) != 0    // segment flags & 4
                 && !*(_BYTE *)(v43 + 474)              // segment+0x1DA == 0
                 || (v42 & 0x10000) != 0 )              // OR allocation flag 0x10000
                goto LABEL_80;  // deferred lock

            if ( (v44 & 4) != 0 )     // CPU visible memory segment
            {
                if ( (v40[4] & 1) == 0 )  // multi_alloc+0x20 & 1 == 0
                {
                    LODWORD(v63) = 3;     // TYPE 3 (CPU-visible segment)
                    if ( *(_QWORD *)(v41 + 256) )  // global_alloc+0x100
                    {
                        v45 = 1;  // already locked, skip LockInternal
                        goto LABEL_79;
                    }
                }
            }
            else
            {
                if ( (v44 & 0x2000) == 0 )  // NOT paravirtualized
                    goto LABEL_72;  // v45=1, skip LockInternal (use existing mapping)
                v46 = *(_QWORD *)(v41 + 96);  // global_alloc+0x60
                if ( !v46 || (*(_BYTE *)(v46 + 32) & 1) == 0 )
                    goto LABEL_72;
                LODWORD(v63) = 0;  // TYPE 0 (special paravirtualized)
            }
        }
        // If (v44 & 0x1001) != 0: aperture segment → stays type 1
    }
}
```

### Summary of Triggers

| Condition | Lock Type |
|-----------|-----------|
| `global_alloc+0x50 & 0x80 == 0` | **Type 5** (non-CPU-visible) |
| `global_alloc+0x50 & 0x80 != 0` AND `segment+0x50 & 0x1001 == 0` AND `segment+0x50 & 0x4 != 0` AND not locked | **Type 3** (CPU-visible segment) |
| `global_alloc+0x50 & 0x80 != 0` AND `segment+0x50 & 0x1001 != 0` | **Type 1** (aperture, default) |
| `global_alloc+0x50 & 0x80 != 0` AND `segment+0x50 & 0x2000 != 0` AND conditions | **Type 0** (paravirtualized) |
| Lock fails (type 1/3/5 returns error) | **Type 4** (fallback to aperture) |
| Deferred lock conditions | **Type 1** with deferred paging |

### Key Segment Flags (at `segment+0x50`)

| Flag | Meaning |
|------|---------|
| `0x1` | Aperture segment |
| `0x4` | CPU-visible memory segment |
| `0x1000` | Aperture segment (alternate flag) |
| `0x2000` | Paravirtualized segment |
| `0x4000` | CPU host aperture |

### Key Allocation Flags (at `global_alloc+0x50`)

| Flag | Meaning |
|------|---------|
| `0x80` | CPU-visible allocation |
| `0x2000` | Paravirtualized allocation |
| `0x4000` | CPU host aperture allocation |
| `0x40000` | Has section object |
| `0x800000` | Has system-space mapping |
| `0x10000` | Deferred lock flag |

---

## 8. Allocation Creation Parameters

### Segment Enumeration

Use `D3DKMTQueryAdapterInfo` with type `D3DKMT_QAITYPE_QUERYSEGMENTS` (or `D3DKMT_QAITYPE_QUERYSEGMENTS3` on WDDM 2.x+) to enumerate adapter segments:

```c
D3DKMT_QUERYADAPTERINFO qai = {};
qai.hAdapter = hAdapter;
qai.Type = KMTQAITYPE_QUERYSEGMENTS;  // or KMTQAITYPE_QUERYSEGMENTS3
qai.pPrivateDriverData = &segmentBuffer;
qai.PrivateDriverDataSize = sizeof(segmentBuffer);

D3DKMTQueryAdapterInfo(&qai);
```

The returned `D3DKMT_QUERYSEGMENTINFO` (or `D3DKMT_QUERYSEGMENTINFO3`) structures contain:
- `Flags` field with segment properties
- `Aperture` flag: `TRUE` = aperture/BAR segment, `FALSE` = memory segment
- `CpuVisible` flag: `TRUE` = CPU can directly access
- `Size` field: segment size in bytes
- `BaseAddress`: segment base (for VRAM segments)
- `SegmentId`: 0-based segment index

### Targeting a Non-CPU-Visible System Memory Segment

To find a non-CPU-visible system memory segment:
1. Enumerate all segments via `D3DKMTQueryAdapterInfo`
2. Find segments where `Aperture == FALSE` (memory segment, not BAR) AND `CpuVisible == FALSE`
3. These are non-CPU-visible system memory segments
4. Use the segment ID in `D3DDDI_SEGMENTPREFERENCE` when creating the allocation

### D3DKMTCreateAllocation

```c
D3DKMT_CREATEALLOCATION createAlloc = {};
createAlloc.hDevice = hDevice;
createAlloc.NumAllocations = 1;

D3DDDI_ALLOCATIONINFO2 allocInfo = {};
allocInfo.pSystemBuffer = &privateData;  // driver-specific private data
allocInfo.SystemSysMemSize = sizeof(privateData);
allocInfo.pPrivateRuntimeData = nullptr;
allocInfo.PrivateRuntimeDataSize = 0;
allocInfo.hAllocation = 0;  // output

// Set segment preference to target non-CPU-visible system memory segment
allocInfo.SegmentId.SegmentId0 = targetSegmentId;  // 1-based
allocInfo.SegmentId.SegmentId1 = 0;
allocInfo.SegmentId.SegmentId2 = 0;

createAlloc.pAllocationInfo2 = &allocInfo;
createAlloc.AllocationInfo2Size = sizeof(allocInfo);

D3DKMTCreateAllocation(&createAlloc);
```

### D3DKMTCreateStandardAllocation

Standard allocations (`D3DKMTCreateAllocation` with `StandardAllocation` set) do not require driver-specific private data. The `D3DKM_CREATESTANDARDALLOCATION` structure supports types like:
- `D3DKMT_STANDARDALLOCATION_EXISTINGHEAP`
- `D3DKMT_STANDARDALLOCATION_INTERNAL`

The `DXGDEVICE::CreateStandardAllocation` function at `0x1C011CBDC` (dxgkrnl.sys) processes these. Standard allocations may allow segment preference control without needing driver-specific private data.

### Segment Selection in CreateOneAllocation

From `VIDMM_GLOBAL::CreateOneAllocation` at `0x1C005D110`:

```c
// 0x1C005E3F0
MostPreferredSegment = VIDMM_GLOBAL::GetMostPreferredSegment(
    a1, v130, a9, &v161);  // a9 = D3DDDI_SEGMENTPREFERENCE
```

The `GetMostPreferredSegment` function (`0x1C00857FC`) uses the `D3DDDI_SEGMENTPREFERENCE` to select the preferred segment. The segment preference is a bitmask where bits 0-4 specify the preferred segment, bits 5-9 specify the secondary, etc.

### Pool Tags for VIDMM Structures

| Structure | Pool Tag | Size |
|-----------|----------|------|
| `VIDMM_GLOBAL_ALLOC` (non-WDDM) | `Vi01` (0x31376956) | 504 bytes |
| `VIDMM_GLOBAL_ALLOC` (WDDM) | `Vi0a` (0x61305669) | 512/544 bytes |
| Sync objects | `Vi28` (0x38326956) | 0x28 bytes |
| Sync objects (alt) | `Vi42` (0x32346956) | 0x28 bytes |

---

## 9. SURFACE.pvScan0 Verification

### SURFACE Structure Layout

From `SURFMEM::bCreateDIB` at `0x1C0027C60` (win32kbase.sys):

| Offset | Field | Type | Source |
|--------|-------|------|--------|
| `+0x18` | `SURFOBJ` (embedded) | `SURFOBJ` | `SURFACE+24` used as `SURFOBJ*` |
| `+0x30` | hdev | `HDEV` | `SURFACE+48` |
| `+0x38` | sizlBitmap.cx | `LONG` | `SURFACE+56` |
| `+0x3C` | sizlBitmap.cy | `LONG` | `SURFACE+60` |
| `+0x40` | cjBits | `ULONG` | `SURFACE+64` |
| `+0x48` | **pvBits** | `PVOID` | `SURFACE+72` — bitmap data pointer |
| **`+0x50`** | **pvScan0** | `PVOID` | **`SURFACE+80` — scanline 0 pointer** |
| `+0x58` | lDelta | `LONG` | `SURFACE+88` — stride (positive = bottom-up, negative = top-down) |
| `+0x5C` | iUniq | `ULONG` | `SURFACE+92` |
| `+0x60` | iBitmapFormat | `ULONG` | `SURFACE+96` |
| `+0x64` | flags | `WORD` | `SURFACE+100` |
| `+0x66` | more flags | `WORD` | `SURFACE+102` |
| `+0x70` | surf flags | `DWORD` | `SURFACE+112` (includes `0x4000000` for bitmap) |
| `+0x80` | palette | `QWORD` | `SURFACE+128` |
| `+0xD0` | owner PID | `DWORD` | `SURFACE+208` |
| `+0x2B0` | flags byte | `BYTE` | `SURFACE+688` |

### pvScan0 Assignment in bCreateDIB

```c
// 0x1C0028370 (bottom-up bitmap)
*(_DWORD *)(v55 + 88) = v15;         // lDelta = stride (positive)
*(_QWORD *)(*(_QWORD *)this + 80LL) = *(_QWORD *)(*(_QWORD *)this + 72LL);
// pvScan0 = pvBits (for bottom-up)

// 0x1C0028384 (top-down bitmap)
*(_DWORD *)(v55 + 88) = -(int)v15;   // lDelta = -stride (negative)
*(_QWORD *)(*(_QWORD *)this + 80LL) = *(_QWORD *)(*(_QWORD *)this + 72LL)
                                      + (cjBits - v15);
// pvScan0 = pvBits + (cjBits - stride) (for top-down)
```

**CONFIRMED: `pvScan0` is at `SURFACE+0x50` (offset 80 decimal).**

### SURFACE Object Size

`SURFACE::tSize` = `0x2B8` = **696 bytes** (the SURFACE object itself, not including bitmap data).

### SURFACE Allocation

`SURFACE::Allocate` (`0x1C00808C0`) uses a **type isolation lookaside list** (`gpTypeIsolation`):

```c
v0 = (__int64)*gpTypeIsolation;
if ( *gpTypeIsolation )
{
    v1 = ExpInterlockedPopEntrySList((PSLIST_HEADER)(v0 + 48));  // try lookaside
    if ( !v1 )
    {
        // Allocate from pool: pool_type at v0+84, tag at v0+88, size at v0+92
        v1 = (*(func*)(v0 + 96))(*(DWORD*)(v0 + 84), *(DWORD*)(v0 + 92), *(DWORD*)(v0 + 88), v0 + 48);
    }
}
```

The bitmap **data** (pvBits) is allocated separately via:
- `PALLOCMEM2` with tag `Gpbm` (0x6D627047) for simple bitmaps
- `EngAllocUserMemEx` for user-mapped bitmaps
- `AllocateKernelSection` / `Win32CreateSection` for section-backed bitmaps
- `AllocateSharedSection` for shared bitmaps

### Pool Type

SURFACE objects are allocated in a **type-isolated pool** (Windows 10/11 GDI type isolation). The exact pool type and tag are determined at runtime by `gpTypeIsolation`. On modern Windows, SURFACE objects are typically in **NonPagedPool** (or a session-paged pool equivalent for GDI objects).

---

## 10. bDoGetSetBitmapBits Verification

### Function: `bDoGetSetBitmapBits` at `0x1C0018BA4` (win32kfull.sys)

### SetBitmapBits Path (a3 == 0)

When called from `GreSetBitmapBits` (`0x1C00187F0`):
```c
// GreSetBitmapBits calls:
bDoGetSetBitmapBits(surface_SURFOBJ, temp_SURFOBJ, 0);
// a1 = surface's SURFOBJ (at SURFACE+0x18)
// a2 = temp SURFOBJ (stack, with user buffer)
// a3 = 0
```

In `bDoGetSetBitmapBits`, when `a3 == 0`:
```c
// 0x1C0018BF5
pvScan0 = (char *)a1->pvScan0;    // SURFACE+0x50 — NO VALIDATION!
lDelta = a1->lDelta;               // SURFACE+0x58
v35 = lDelta;

// Calculate target address
v13 = &pvScan0[lDelta * (v10 / v8)];  // pvScan0 + lDelta * row_index

// WRITE to kernel memory at pvScan0 + offset
memmove(&v13[v12], pvBits, v32);  // write user data to pvScan0+offset
```

**This writes to `pvScan0 + lDelta * row + col_offset` WITHOUT any validation of pvScan0.**

### GetBitmapBits Path (a3 != 0)

When called from `GreGetBitmapBits` (`0x1C00183C4`):
```c
// GreGetBitmapBits calls:
bDoGetSetBitmapBits(&v32, surface_SURFOBJ, 1);
// a1 = temp SURFOBJ (stack, with user buffer)
// a2 = surface's SURFOBJ (at SURFACE+0x18)
// a3 = 1
```

In `bDoGetSetBitmapBits`, when `a3 != 0`:
```c
// 0x1C0018D9E
v21 = (char *)a2->pvScan0;   // SURFACE+0x50 — NO VALIDATION!
v22 = a2->lDelta;              // SURFACE+0x58

// Calculate source address
v27 = &v21[v22 * (v24 / v20)];  // pvScan0 + lDelta * row_index

// READ from kernel memory at pvScan0 + offset
memmove(v18, &v27[v26], v31);  // read from pvScan0+offset to user buffer
```

**This reads from `pvScan0 + lDelta * row + col_offset` WITHOUT any validation of pvScan0.**

### NtGdiGetBitmapBits (`0x1C00182E0`)

```c
NtGdiGetBitmapBits(HSURF a1, ULONG a2, void *a3)
{
    // ProbeForWrite + MmSecureVirtualMemory on user buffer
    // Then calls GreGetBitmapBits
    GreGetBitmapBits(a1);  // which calls bDoGetSetBitmapBits
}
```

### NtGdiSetBitmapBits (`0x1C0018710`)

```c
NtGdiSetBitmapBits(HSURF a1, SIZE_T Size, char *Address)
{
    // MmSecureVirtualMemory on user buffer
    // Then calls GreSetBitmapBits
    GreSetBitmapBits(a1);  // which calls bDoGetSetBitmapBits
}
```

### Full Call Chain

```
NtGdiGetBitmapBits → GreGetBitmapBits → bDoGetSetBitmapBits (a3=1, READ from pvScan0)
NtGdiSetBitmapBits → GreSetBitmapBits → bDoGetSetBitmapBits (a3=0, WRITE to pvScan0)
```

**CONFIRMED: Both paths use `SURFACE+0x50` (pvScan0) without any validation. Corrupting pvScan0 yields arbitrary kernel R/W.**

---

## 11. Paravirtualized Path Analysis (WARP)

### WARP Adapter Enumeration

WARP (Windows Advanced Rasterization Platform) is the Microsoft Basic Render Driver. It can be enumerated via:
- `D3DKMTEnumAdapters2` (`0x1C013C890` in dxgkrnl.sys)
- `D3DKMTEnumAdapters3` (`0x1C0175100` in dxgkrnl.sys)

WARP is enumerated as an adapter even when a physical GPU is present. The adapter LUID for WARP is typically `{0, 0}` or a specific Microsoft Basic Render Driver LUID.

### Paravirtualized Lock Path

For WARP, the segment flags have `0x20000000` set (paravirtualized segment). The type 5 paravirtualized path uses `MmMapViewOfSection`:

```c
MmMapViewOfSection(
    *(_QWORD *)(v13 + 352),   // global_alloc+0x160 (section object)
    CurrentProcess,            // target process
    v12 + 2,                   // base address = multi_alloc+0x10
    0,                         // zero bits
    *(_QWORD *)(v13 + 8),      // view size
    &v28,                      // section offset
    v13 + 8,                   // view size pointer
    2,                         // ViewUnmap
    0,                         // allocation
    ...);                      // page protection
```

The section object at `global_alloc+0x160` is created during allocation creation. For WARP, the section is backed by **system memory**.

### Paravirtualized Destroy Path

In `DestroyOneAllocation`:
```c
if ( (v22 & 0x2000) == 0 )  // NOT paravirtualized
{
    // cleanup code (MmUnmapViewInSystemSpace, VidMmDereferenceObjectAsync)
}
// For paravirtualized: ENTIRE BLOCK SKIPPED
```

The section object is **NOT dereferenced** during destroy for paravirtualized allocations. The section persists, holding the backing pages.

### Async Cleanup

`VidMmDereferenceObjectAsync` (`0x1C00873E8`) queues an async operation:
```c
VidMmQueueAsyncOperation(&asyncOp);
// If queueing fails, immediately calls ObfDereferenceObject(Object)
```

But this is only called for **non-paravirtualized** allocations (the paravirtualized path skips it). For paravirtualized, the section cleanup depends on:
1. Process exit (sections are automatically cleaned up)
2. Device destruction
3. Adapter destruction
4. Some other internal cleanup path

### UnlockParavirtualizedAllocationOnHost

`UnlockParavirtualizedAllocationOnHost` (`0x1C00B2F68`) is called by `Unlock`:
```c
if ( *((_QWORD *)a1 + 65) )  // global_alloc+0x208 (host mapping)
{
    VIDMM_PROCESS::UnmapHostAddressesFromGuest(
        v2,                              // VIDMM_PROCESS
        *((void **)a1 + 65),             // global_alloc+0x208 (host VA)
        *((_QWORD *)a1 + 66),            // global_alloc+0x210 (host MDL)
        *((_QWORD *)a1 + 1),             // global_alloc+0x8 (size)
        0);                              // not immediate
    *((_QWORD *)a1 + 66) = 0;  // clear global_alloc+0x210
    *((_QWORD *)a1 + 65) = 0;  // clear global_alloc+0x208
}
```

This unmaps the **host** addresses (GPU VA), not the CPU VA at `multi_alloc+0x10`. The CPU VA mapping (via `MmMapViewOfSection`) is NOT unmapped by this function.

### Timing Window

For paravirtualized type 5:
1. Create allocation on WARP adapter
2. Lock → `MmMapViewOfSection` maps section into process at `multi_alloc+0x10`
3. Destroy → `multi_alloc+0x10` not unmapped, section not dereferenced
4. The CPU VA mapping persists
5. The section holds the backing pages (system memory)
6. **The pages are NOT freed** → cannot reclaim with `SURFACE` objects
7. Only when the section is eventually cleaned up (process exit?) would pages be freed

**The timing window is uncertain and potentially very long (until process exit). This makes the WARP path unreliable for the GDI reclamation exploit.**

---

## 12. Best Exploitation Path Recommendation

### Option A: Lock Type 3 (CPU-Visible Segment)

| Criterion | Assessment |
|-----------|------------|
| **Viability** (destroy skips unmap) | YES — `CloseOneAllocation` checks `VIDMM_ALLOC+0x90`, not `multi_alloc+0x10` |
| **Backing page type** | System memory (CPU-visible memory segment) |
| **Reclaimability** | YES — system memory pages can be reclaimed by `SURFACE` |
| **Complexity** | Medium — need to target a CPU-visible system memory segment |
| **Reliability** | MEDIUM — `FreeAllocMappedVaRangeList` might clean up the mapping; `DestroyOneAllocation` might unmap `global_alloc+0x168` |
| **Rating** | **6/10** |

### Option B: Lock Type 5 Paravirtualized (WARP)

| Criterion | Assessment |
|-----------|------------|
| **Viability** | YES — `multi_alloc+0x10` not unmapped in destroy |
| **Backing page type** | System memory (section-backed) |
| **Reclaimability** | DELAYED — section holds pages, not freed during destroy |
| **Complexity** | High — need to race async/late cleanup |
| **Reliability** | LOW — timing window uncertain, pages may not be freed until process exit |
| **Rating** | **3/10** |

### Option C: Lock Type 5 Non-Paravirtualized (System Memory Segment) **[RECOMMENDED]**

| Criterion | Assessment |
|-----------|------------|
| **Viability** | YES — `CloseOneAllocation` checks `VIDMM_ALLOC+0x90` (never set), `DestroyOneAllocation` skips cleanup when flags match |
| **Backing page type** | System memory (non-CPU-visible `VIDMM_SYSMEM_SEGMENT`) |
| **Reclaimability** | YES — `UnlockAllocationBackingStore` frees physical pages during destroy, `SURFACE` spray reclaims them |
| **Complexity** | Medium — need to find a non-CPU-visible system memory segment on the target GPU |
| **Reliability** | HIGH — deterministic: pages are freed during destroy, PTE persists, immediate reclamation |
| **Rating** | **9/10** |

### Option D: Lock Type 4 (CPU Host Aperture)

| Criterion | Assessment |
|-----------|------------|
| **Viability** | N/A — fallback type, not directly triggerable |
| **Backing page type** | VRAM/BAR |
| **Reclaimability** | NO — VRAM pages cannot be reclaimed by `SURFACE` |
| **Rating** | **0/10** |

### RECOMMENDATION: Option C

**Lock type 5 on a non-CPU-visible system memory segment is the best exploitation path.**

**Exploit flow:**
1. Enumerate adapters via `D3DKMTEnumAdapters2`
2. Query segments via `D3DKMTQueryAdapterInfo` (`KMTQAITYPE_QUERYSEGMENTS`)
3. Find a segment where `Aperture == FALSE` AND `CpuVisible == FALSE` (non-CPU-visible system memory)
4. Create a `D3DKMT` device and allocation targeting that segment via `D3DDDI_SEGMENTPREFERENCE`
5. Call `D3DKMTLock` → type 5 triggered → CPU VA mapped at `multi_alloc+0x10` via driver callback
6. Call `D3DKMTDestroyAllocation` (do NOT call `D3DKMTUnlock`):
   - `CloseOneAllocation` checks `VIDMM_ALLOC+0x90` → NULL → skips unmap
   - `DestroyOneAllocation` checks `global_alloc+0x50 & 0x40000 == 0` AND `segment_flags & 0x10020008 == 0` → skips cleanup
   - `UnlockAllocationBackingStore` frees the physical pages
   - PTE at CPU VA persists → **dangling mapping to freed system memory**
7. Spray GDI bitmaps → `SURFACE` objects (0x2B8 bytes each) reclaim freed pages
8. Write to `pData + 0x50` → corrupts `SURFACE.pvScan0` at `SURFACE+0x50`
9. `GetBitmapBits`/`SetBitmapBits` → arbitrary kernel R/W at 200M+ ops/sec

**Key advantage:** The backing pages are freed **immediately** during destroy (no async cleanup, no section object holding pages). The reclamation window is deterministic.

---

## 13. What Needs Further Analysis

### 13.1 Non-CPU-Visible System Memory Segment Existence

Need to verify on the target hardware whether a non-CPU-visible system memory segment exists. This depends on the GPU driver and hardware:
- **NVIDIA**: Typically has VRAM segments (non-CPU-visible) and system memory segments (CPU-visible). May not have non-CPU-visible system memory segments.
- **AMD**: Similar to NVIDIA, but some APU configurations may have non-CPU-visible system memory segments.
- **Intel iGPU**: Shared memory architecture — may have non-CPU-visible system memory segments.
- **WARP**: Has paravirtualized segments only (not suitable for Option C).

**Action**: Run `D3DKMTQueryAdapterInfo` on the target to enumerate segments and check for `Aperture == FALSE && CpuVisible == FALSE`.

### 13.2 Driver Callback Mapping Details

For non-paravirtualized type 5, the driver callback at vtable offset `+0x48` maps the allocation. Need to understand:
- What CPU VA does the driver return?
- Is the mapping a process-space mapping or system-space mapping?
- Does the driver use `MmMapLockedPagesSpecifyCache` or similar?
- When `UnlockAllocationBackingStore` is called, does it also unmap the CPU VA, or only unlock the physical pages?

**Action**: Analyze the specific GPU driver's `DxgkCbMapMdlSegment` or equivalent callback.

### 13.3 SURFACE Pool Compatibility

Need to verify that the freed VIDMM backing pages return to the same pool that `SURFACE::Allocate` draws from. On Windows 10/11 with type isolation:
- SURFACE objects are in a type-isolated lookaside pool
- VIDMM backing pages may be from `MmAllocateContiguousMemory` or `ExAllocatePoolWithTag`
- The pools may not overlap

**Action**: Check if `SURFACE` spray can reclaim pages from the VIDMM backing store. May need to use a different kernel object for reclamation (e.g., `PALETTE`, `BRUSH`, or pool spray with matching tag).

### 13.4 D3DKMTCreateStandardAllocation Segment Control

Need to verify if `D3DKMTCreateStandardAllocation` allows segment preference control. Standard allocations might be easier to create without driver-specific private data.

**Action**: Analyze `DXGDEVICE::CreateStandardAllocation` (`0x1C011CBDC` in dxgkrnl.sys) for segment preference handling.

### 13.5 Lock Type 3 FreeAllocMappedVaRangeList

For type 3, need to verify if `Rotate` populates the VA range list at `VIDMM_ALLOC+0x78`. If it does, `CloseOneAllocation` would call `FreeAllocMappedVaRangeList`, which might unmap the CPU VA.

**Action**: Analyze `VIDMM_GLOBAL::Rotate` and the process heap interface virtual function to determine if the VA range list is populated.

### 13.6 VIDMM_ALLOC+0x90 Field Origin

Need to find what code path sets `VIDMM_ALLOC+0x90` (the field checked by `CloseOneAllocation`). This would help understand which allocation types DO get properly unmapped, and confirm that type 5 never sets it.

**Action**: Search for writes to `VIDMM_ALLOC+0x90` (offset `0x90` from the alloc structure) across dxgmms2.sys.

### 13.7 Alternative Reclamation Objects

If `SURFACE` objects cannot reclaim VIDMM backing pages, consider:
- `PALETTE` objects (smaller, different pool)
- `BRUSH` objects
- Direct pool spray with matching tag
- `CLIPFORMAT` objects
- Window objects (`tagWND`)

**Action**: Analyze pool tags and allocation sizes to find objects that match the VIDMM backing store pool.
