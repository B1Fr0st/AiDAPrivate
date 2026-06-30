# SURFACE Type Isolation Analysis — laSize Threshold Investigation

## Binary Analyzed
- **win32kbase.sys** (port 13339) — primary analysis target
- **win32kfull.sys** (port 13337) — cross-reference
- **ntoskrnl.exe** (port 13338) — not required for this analysis

## THE ANSWER

**SURFACE::Allocate uses type isolation for ALL SURFACE allocations. There is NO size threshold. The exploit as described does NOT work.**

`laSize[5]` = 952 (0x3B8) = `SURFACE::tSize + 256` = `696 + 256`. But this value is **irrelevant** because `SURFACE::Allocate` bypasses `AllocateObject` entirely and uses `gpTypeIsolation` directly. All SURFACEs go through type isolation, and all are **zeroed on free** via `memset(0, 0x2C0)` in `FreeIsolatedType`.

---

## Detailed Evidence

### 1. SURFACE::Allocate (0x1C00808C0) — Always Type Isolation

```c
struct _SLIST_ENTRY *__fastcall SURFACE::Allocate()
{
    v0 = (__int64)*gpTypeIsolation;           // gpTypeIsolation[0] = CLookAsideTypeIsolation<180224,704>
    if ( *gpTypeIsolation )
    {
        ++*(_DWORD *)(v0 + 68);               // increment alloc count
        v1 = ExpInterlockedPopEntrySList((PSLIST_HEADER)(v0 + 48));  // pop from SLIST
        if ( !v1 )
        {
            ++*(_DWORD *)(v0 + 72);           // increment miss count
            v1 = allocator_callback_at_v0_plus_96(pool_size, tag, obj_size, v0 + 48);
        }
    }
    else
        v1 = nullptr;

    if ( !v1 )
        return nullptr;

    if ( !AcquireReferenceCountedObjectHandle(0, v1, &v1[42].Next + 1) )
    {
        FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>(v1);  // free on failure
        return nullptr;
    }
    return v1;
}
```

**Key observations:**
- No size parameter. No size check. No `PALLOCMEM2` fallback.
- Always pops from `gpTypeIsolation[0]` SLIST (the `CLookAsideTypeIsolation<180224,704>` pool).
- If the SLIST is empty, calls the pool's allocator callback to create new objects **within the type isolation pool** — not regular pool.
- `FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>` is the only free function referenced — confirming this is a dedicated type isolation pool for 704-byte objects.

### 2. SURFACE::tSize = 696 (0x2B8) — Confirmed

```
Address: 0x1C024E5E0
Value:   696 (0x2B8) as u64le
Symbol:  ?tSize@SURFACE@@0_KA
```

The SURFACE struct is 696 bytes. The type isolation pool block size is 704 bytes (0x2C0) — 8 bytes larger for the SLIST entry header. 696 < 704, so SURFACEs always fit within the type isolation block.

### 3. laSize[5] = 952 (0x3B8) — Set in HmgCreate, But IRRELEVANT

```c
// HmgCreate (0x1C006BCFC)
memset(&laSize, 0, 0x7Cu);                                          // zero the array
HmgInitializeLookAsideList(1u, 0x868u, ..., 0x28u);                // type 1 (DC):      laSize[1] = 0x868 (2144)
HmgInitializeLookAsideList(4u, 0x70u,  ..., 0x60u);                // type 4 (REGION):  laSize[4] = 0x70  (112)
HmgInitializeLookAsideList(5u, (int)SURFACE::tSize + 256, ...);    // type 5 (SURFACE): laSize[5] = 696+256 = 952 (0x3B8)
HmgInitializeLookAsideList(8u, 0xC8u,  ..., 0xCu);                 // type 8 (PALETTE): laSize[8] = 0xC8  (200)
HmgInitializeLookAsideList(0x10u, 0xB8u, ..., 0x60u);              // type 16 (BRUSH):  laSize[16] = 0xB8 (184)
HmgInitializeLookAsideList(0xAu, 0x278u, ..., 0x40u);              // type 10 (FONT):   laSize[10] = 0x278 (632)
HmgInitializeLookAsideList(0xBu, 0x390u, ..., 0x37u);              // type 11:          laSize[11] = 0x390 (912)
```

```c
// HmgInitializeLookAsideList (0x1C006C124)
_BOOL8 __fastcall HmgInitializeLookAsideList(unsigned int type, unsigned int size, ...)
{
    if ( type << 24 < 0xCF9E93B9 )
    {
        *((_DWORD *)&laSize + type) = size;                        // laSize[type] = size
        v5 = Win32AllocPagedLookasideList(size, ...);              // create lookaside list
        (&pHmgLookAsideList)[type] = v5;                           // store in pHmgLookAsideList array
        return v5 != nullptr;
    }
    return false;
}
```

`laSize` is at **0x1C0250160** (all zeros in the static binary — initialized at runtime by HmgCreate).

`laSize[5] = 952` (0x3B8) is used **only** in `AllocateObject`:
```c
// AllocateObject (0x1C002BCC0)
if ( *((_DWORD *)&laSize + (unsigned int)a2) < v6 )   // if laSize[type] < Size
{
    // PALLOCMEM2 path — regular pool, NO type isolation
    v9 = PALLOCMEM2(v6, v11, a3);
    // NOTE: bit 15 at offset 14 is NOT set (stays clear)
}
else
{
    // pHmgLookAsideList path — old lookaside system
    v7 = (&pHmgLookAsideList)[(unsigned int)a2];
    // ...
    *((_WORD *)v9 + 7) = 0x8000;   // Set bit 15 at offset 14
}
```

**But SURFACE::Allocate NEVER calls AllocateObject.** The `laSize` check is only reachable through `HmgAlloc → AllocateObject`, and `HmgAlloc` is used only for DC allocation (type 1), not SURFACEs.

### 4. HmgAlloc (0x1C0001410) — Only for DCs, Not SURFACEs

```asm
; HmgAlloc disassembly — passes type to AllocateObject
movzx ebp, r8w        ; ebp = flags (a3)
movzx r15d, dl         ; r15d = type (a2)
mov edx, r15d          ; RDX = type → second arg to AllocateObject
call AllocateObject    ; AllocateObject(size=RCX, type=RDX, flag=R8)
```

Xrefs to HmgAlloc:
- `DCMEMOBJ::DCMEMOBJ(HDEV, ...)` at 0x1C00C8314 — DC allocation (type 1)
- `DCMEMOBJ::DCMEMOBJ(DCOBJ&)` at 0x1C013C550 — DC allocation (type 1)
- Data references (vtable/export table)

**HmgAlloc is never called with type 5 for SURFACE creation.** SURFACEs are created via `SURFMEM::bCreateDIB → SURFACE::Allocate`.

### 5. SURFMEM::bCreateDIB (0x1C0027C60) — The Bitmap Creation Path

```c
__int64 __fastcall SURFMEM::bCreateDIB(SURFMEM *this, _DEVBITMAPINFO *a2, ...)
{
    // 1. Calculate pixel data size (v15 = scanline size, height = a2[2])
    //    v28 = v15 * height  (total pixel data bytes)

    // 2. Calculate total inline size (if no user buffer provided)
    v29 = v28 + SURFACE::tSize;     // pixel data + SURFACE struct

    // 3. Allocate PIXEL DATA separately (various paths):
    //    - PALLOCMEM2(v29 - v27, ...) = PALLOCMEM2(v28, ...) — just pixel data
    //    - EngAllocUserMemEx(v29, ...) — user memory
    //    - AllocateSharedSection(v29, ...) — shared section
    //    - AllocateKernelSection(v29, ...) — kernel section
    //    - Win32CreateSection(...) — section object

    // 4. Allocate SURFACE struct via type isolation:
    v37 = SURFACE::Allocate();      // ← ALWAYS type isolation, no size check
    *(_QWORD *)this = v37;

    // 5. Link pixel data to SURFACE:
    *(_QWORD *)(*(_QWORD *)this + 72LL) = pv;   // SURFACE+0x48 = pv (pixel data base)
    *(_QWORD *)(*(_QWORD *)this + 80LL) = ...;   // SURFACE+0x50 = pvScan0 (scanline pointer)

    // 6. Insert into handle table with type 5:
    HmgInsertObjectHelper::Insert(..., 5u);      // type 5 = SURFACE
}
```

**The SURFACE struct and pixel data are SEPARATE allocations:**
- SURFACE struct: `SURFACE::Allocate()` → `gpTypeIsolation` (always type isolation, fixed 704-byte block)
- Pixel data: `PALLOCMEM2` / `EngAllocUserMemEx` / `AllocateSharedSection` / etc. (variable size, regular pool)

The pixel data size varies with bitmap dimensions, but the SURFACE struct size is ALWAYS 696 bytes (fits in 704-byte type isolation block).

### 6. SURFACE::Free (0x1C002B8C0) — Always FreeIsolatedType

```c
void __fastcall SURFACE::Free(PSLIST_ENTRY ListEntry)
{
    if ( *((_QWORD *)&ListEntry[42].Next + 1) )       // offset 0x158: reference count handle
        ReleaseReferenceCountedObjectHandle(0);

    if ( LOBYTE(ListEntry[43].Next) )                  // offset 0x158: flags byte
    {
        v2 = *((_QWORD *)&ListEntry[4].Next + 1);     // offset 0x28: associated allocation
        if ( v2 )
        {
            Win32FreePool(v2);                          // free associated allocation (NOT the SURFACE itself)
            *((_QWORD *)&ListEntry[4].Next + 1) = 0;
        }
    }

    FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>(ListEntry);  // ALWAYS type isolation free
}
```

**SURFACE::Free ALWAYS calls FreeIsolatedType.** It never calls `FreeObject` or `Win32FreePool` for the SURFACE struct itself. The `Win32FreePool` call at offset 0x28 is for an associated allocation, not the SURFACE.

### 7. FreeIsolatedType (0x1C002B910) — ZEROES Memory

```c
PSLIST_ENTRY __fastcall FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>(PSLIST_ENTRY ListEntry)
{
    v3 = (__int64)*gpTypeIsolation;
    if ( *gpTypeIsolation )
    {
        memset(ListEntry, 0, 0x2C0u);                 // ★ ZERO 704 BYTES ★

        ++*(_DWORD *)(v3 + 76);                       // increment free count
        v4 = v3 + 48;                                  // SLIST header

        if ( ExQueryDepthSList((PSLIST_HEADER)v4) < *(_WORD *)(v4 + 16) )
        {
            // Lookaside not full → push back to SLIST (already zeroed)
            return ExpInterlockedPushEntrySList((PSLIST_HEADER)v4, ListEntry);
        }
        else
        {
            // Lookaside full → call deleter callback (already zeroed)
            ++*(_DWORD *)(v4 + 32);                   // increment overflow count
            return deleter_callback_at_v4_plus_56(ListEntry, v4);
        }
    }
    return result;
}
```

**The `memset(ListEntry, 0, 0x2C0u)` executes BEFORE the depth check.** Regardless of whether the object returns to the SLIST or gets freed via the deleter callback, it is ALWAYS zeroed first.

### 8. FreeObject (0x1C002BC40) — The NON-SURFACE Path (for comparison)

```c
__int64 __fastcall FreeObject(__int64 a1, int a2)
{
    if ( *(__int16 *)(a1 + 14) >= 0 )          // bit 15 CLEAR → regular pool
        return Win32FreePool(a1);              // NO ZEROING

    // bit 15 SET → old lookaside list (pHmgLookAsideList)
    v3 = (&pHmgLookAsideList)[a2];
    // ... call lookaside free (NO ZEROING in FreeObject itself)
}
```

**FreeObject does NOT zero memory.** If bit 15 at offset 14 is clear, it calls `Win32FreePool` (no zeroing). If bit 15 is set, it returns to `pHmgLookAsideList` (no zeroing in FreeObject itself).

**But SURFACEs NEVER go through FreeObject.** The only callers of FreeObject are:
- `HmgAlloc` (error cleanup during DC allocation)
- `HmgFree` (general free for non-palette, non-SURFACE types)
- `EPATHOBJGC::bGarbageCollect`
- `bDeleteColorSpace`
- `GreCreateColorSpace` (error cleanup)
- `EngDeleteDriverObj`

None of these are in the SURFACE deletion path.

### 9. Full Deletion Chain — Verified End-to-End

**Path 1: NtGdiDeleteObjectApp (syscall)**
```
NtGdiDeleteObjectApp (0x1C0033780)
  → type 5 dispatch (v4-1-4 == 0)
  → HmgShareLockCheckIgnoreStockBit(handle, 5)
  → SURFREF::bDeleteSurface (0x1C00C920C)
    → SURFACE::bDeleteSurface(surface_ptr, cleanupType, 0) (0x1C000DEF0)
      → HmgRemoveObject(handle, ..., 5, ...)
      → pixel data cleanup (EngFreeUserMem / MmUnmapViewOfSection / vFreeKernelSection / Win32FreePool)
      → SURFACE::Free (0x1C002B8C0)
        → FreeIsolatedType<CLookAsideTypeIsolation<180224,704>> (0x1C002B910)
          → memset(surface, 0, 0x2C0)  ← ZEROS 704 BYTES
          → push to SLIST or call deleter (already zeroed)
```

**Path 2: GreDeleteObject (internal)**
```
GreDeleteObject (0x1C0039970)
  → type 5 dispatch (type-1-3-1 == 0)
  → bDeleteSurface (0x1C001CE70)
    → HmgShareLockCheckIgnoreStockBit(handle, 5)
    → SURFREF::bDeleteSurface (0x1C00C920C)
      → SURFACE::bDeleteSurface (0x1C000DEF0)
        → SURFACE::Free (0x1C002B8C0)
          → FreeIsolatedType (0x1C002B910)
            → memset(surface, 0, 0x2C0)  ← ZEROS 704 BYTES
```

**Neither path goes through HmgFree → FreeObject.** SURFACEs have dedicated deletion functions that always end at FreeIsolatedType → memset(0, 0x2C0).

### 10. TypeIsolationFactory::Create — SURFACE Pool Setup

```c
// TypeIsolationFactory::Create (0x1C00CB500)
char Create()
{
    v0 = gpTypeIsolation;                                          // array of type isolation pool pointers
    v1 = CLookAsideTypeIsolation<180224,704>::Create();           // SURFACE pool: 180224 bytes, 704-byte objects
    *v0 = v1;                                                      // gpTypeIsolation[0] = SURFACE pool

    v3 = CTypeIsolation<40960,160>::Create();                     // pool 2
    v0[2] = v3;

    v4 = CTypeIsolation<49152,192>::Create();                     // pool 3
    v0[3] = v4;

    // Recursive: pools 4-8
    // CLookAsideTypeIsolation<36864,144>, CTypeIsolation<81920,320>,
    // CTypeIsolation<917504,3584>, CTypeIsolation<28672,112>,
    // CTypeIsolation<233472,912>
}
```

**gpTypeIsolation[0]** = `CLookAsideTypeIsolation<180224,704>` = the SURFACE type isolation pool.
- Pool size: 180,224 bytes (0x2C000)
- Object size: 704 bytes (0x2C0)
- Capacity: 180224 / 704 = 256 objects

In `SURFACE::Allocate`, `*gpTypeIsolation` (i.e., `gpTypeIsolation[0]`) is always used — confirming the SURFACE-dedicated pool.

---

## Two Separate Allocation Systems

| Feature | Old System (AllocateObject/FreeObject) | New System (SURFACE::Allocate/Free) |
|---|---|---|
| **Lookaside list** | `pHmgLookAsideList[type]` | `gpTypeIsolation[0]` (for SURFACE) |
| **Size check** | `laSize[type] < Size` → PALLOCMEM2 or lookaside | No size check — always type isolation |
| **Allocation** | `HmgAlloc → AllocateObject` | `SURFACE::Allocate` (direct) |
| **Free** | `HmgFree → FreeObject` | `SURFACE::Free → FreeIsolatedType` |
| **Zeroing on free** | NO (Win32FreePool or lookaside push, no memset) | YES (`memset(0, 0x2C0)`) |
| **Bit 15 at offset 14** | Set for lookaside, clear for PALLOCMEM2 | Not used (different system) |
| **Used for SURFACEs?** | NO | YES |
| **Used for DCs?** | YES (type 1 via HmgAlloc) | NO |

---

## Exploit Viability Assessment

### The Proposed Exploit Strategy:
1. Create a large bitmap → SURFACE in regular pool
2. Select it into a DC → DC+0x1F0 = &SURFACE_regular_pool
3. TOCTOU delete the bitmap → SURFACE freed to regular pool (NOT zeroed)
4. Reclaim with bitmap pixel data of matching size → controlled data at &SURFACE
5. Set pvScan0 = TARGET at SURFACE+0x50
6. BitBlt through the DC → reads/writes through controlled pvScan0
7. ARBITRARY KERNEL R/W

### Why It Fails:

**Step 1 fails:** SURFACE::Allocate always uses `gpTypeIsolation` (type isolation). There is no size threshold that redirects SURFACEs to regular pool (PALLOCMEM2). The `laSize[5]` check in `AllocateObject` is unreachable for SURFACEs because `SURFACE::Allocate` bypasses `AllocateObject` entirely.

**Step 3 fails:** Even if the SURFACE were freed, `FreeIsolatedType` calls `memset(surface, 0, 0x2C0)` — zeroing the entire 704-byte object before returning it to the lookaside pool. The stale data is completely wiped. There is no `Win32FreePool` path for SURFACEs.

**Step 4 fails:** The freed SURFACE goes back to the type isolation SLIST (or is freed via the deleter callback, but already zeroed). The zeroed memory cannot be reclaimed with controlled data through normal bitmap allocation because:
- New SURFACEs are allocated from the same type isolation pool (popped from the same SLIST)
- The pixel data is a SEPARATE allocation (PALLOCMEM2, not from the type isolation pool)
- You cannot control the content of a type isolation block through bitmap pixel data

**The TOCTOU window is irrelevant** because even if you delete and reclaim in the same instant, the freed memory is zeroed before you can reclaim it.

### Potential Alternative Approaches (Not Validated):

1. **Type isolation pool exhaustion**: If all 256 SURFACE objects in the pool are in use, `SURFACE::Allocate` calls the allocator callback to create new objects. These new objects are still within the type isolation pool infrastructure, not regular pool.

2. **Pixel data UAF**: The pixel data (at SURFACE+0x48) IS allocated via `PALLOCMEM2` and freed via `Win32FreePool` (no zeroing). A TOCTOU on the pixel data buffer might be viable, but this is a different exploit primitive than the proposed SURFACE struct UAF.

3. **DC UAF via HmgAlloc/AllocateObject**: DCs (type 1) DO go through `AllocateObject` with `laSize[1] = 0x868 (2144)`. If a DC's actual size exceeds 2144, it would go to `PALLOCMEM2` (regular pool, no zeroing). This is a different attack surface.

---

## Key Addresses Summary

| Symbol | Address | Value / Function |
|---|---|---|
| `SURFACE::Allocate` | 0x1C00808C0 | Always type isolation via gpTypeIsolation |
| `SURFACE::Free` | 0x1C002B8C0 | Always FreeIsolatedType |
| `SURFACE::tSize` | 0x1C024E5E0 | 696 (0x2B8) |
| `FreeIsolatedType<...704>` | 0x1C002B910 | memset(0, 0x2C0) + push to SLIST |
| `AllocateObject` | 0x1C002BCC0 | laSize[type] < Size → PALLOCMEM2 or lookaside |
| `FreeObject` | 0x1C002BC40 | bit 15 check → Win32FreePool or lookaside |
| `HmgAlloc` | 0x1C0001410 | Calls AllocateObject (DCs only, type 1) |
| `HmgFree` | 0x1C007C860 | Calls FreeObject (non-SURFACE types) |
| `HmgCreate` | 0x1C006BCFC | Initializes laSize, lookaside lists, gpTypeIsolation |
| `HmgInitializeLookAsideList` | 0x1C006C124 | Sets laSize[type] = size |
| `laSize` array | 0x1C0250160 | DWORD array, laSize[5] = 952 (0x3B8) at runtime |
| `gpTypeIsolation` | 0x1C0250288 | Ptr to array; [0] = CLookAsideTypeIsolation<180224,704> |
| `TypeIsolationFactory::Create` | 0x1C00CB500 | Creates 8 type isolation pools |
| `SURFMEM::bCreateDIB` | 0x1C0027C60 | Bitmap creation: pixel data separate from SURFACE |
| `SURFACE::bDeleteSurface` | 0x1C000DEF0 | Full SURFACE deletion + pixel data cleanup |
| `SURFREF::bDeleteSurface` | 0x1C00C920C | Wrapper → SURFACE::bDeleteSurface |
| `bDeleteSurface` | 0x1C001CE70 | Lock + SURFREF::bDeleteSurface |
| `NtGdiDeleteObjectApp` | 0x1C0033780 | Syscall: type 5 → SURFREF::bDeleteSurface |
| `GreDeleteObject` | 0x1C0039970 | Internal: type 5 → bDeleteSurface |

---

## Conclusion

**laSize[5] = 952 (0x3B8). SURFACE::tSize = 696 (0x2B8). laSize[5] > SURFACE::tSize.**

But this comparison is **irrelevant**. SURFACE::Allocate does NOT use AllocateObject or laSize. It uses gpTypeIsolation directly — a dedicated `CLookAsideTypeIsolation<180224,704>` pool with 256 pre-allocated 704-byte blocks. All SURFACEs are allocated from and freed to this pool. FreeIsolatedType zeroes the entire 704-byte block with `memset(0, 0x2C0)` on every free.

The TOCTOU exploit does not work. The SURFACE memory is always type-isolated and always zeroed on free. There is no regular pool path for SURFACEs.
