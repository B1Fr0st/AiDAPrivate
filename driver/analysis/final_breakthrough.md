# FINAL BREAKTHROUGH ANALYSIS: GDI TOCTOU → Arbitrary Kernel R/W

## EXECUTIVE SUMMARY

The TOCTOU primitive works. The delete-pending state is confirmed. But the exploit is **blocked at a single point**: no user-mode-reachable GDI function writes a user-controlled value to `SURFACE+0x50` (pvScan0). `EngModifySurface` is the ONLY function that does this, and it has no user-mode syscall path.

This document presents the complete analysis of all explored paths, the confirmed blockers, and the remaining viable exploit approaches.

---

## 1. CONFIRMED PRIMITIVES

### 1.1 TOCTOU Arbitrary GDI Deletion

**Mechanism**: Batch buffer at TEB+0x300, cases 7/8 in `NtGdiFlushUserBatchInternal` (win32kfull.sys @ 0x1c008ef50).

**Flow**:
1. User writes a batch record (case 7 or 8) containing a GDI handle to TEB+0x300
2. User calls any GDI function that triggers batch flush
3. `NtGdiFlushUserBatchInternal` processes the record → calls `NtGdiDeleteObjectApp(handle)`
4. `NtGdiDeleteObjectApp` (win32kbase.sys @ 0x1c0033780) extracts type from handle: `v4 = BYTE2(a1) & 0x1F`
5. Type dispatch:
   - **Type 1 (DC)** → `bDeleteDCInternal` → **FAILS** (share count > 1, see §3.1)
   - **Type 5 (SURFACE/Bitmap)** → `SURFREF::bDeleteSurface` → works
   - Type 4 (REGION) → `RGNOBJAPI` path
   - Type 8 (PALETTE) → `bDeletePalette`
   - Type 10 (FONT) → `bDeleteFont`
   - Type 16 (BRUSH) → `bDeleteBrush`

**Runtime confirmed**: Bitmap deletion works on attempt 1 when bitmap is NOT in a DC.

### 1.2 DC Free Does NOT Zero

**Confirmed**: `vDeleteDCInternalWorker` (win32kbase.sys @ 0x1c014d314) → `XDCOBJ::bDeleteDC` → `FreeObject` → `Win32FreePool`. No memset. DC memory (0x868 bytes) retains stale data after free.

### 1.3 SURFACE Free DOES Zero

**Confirmed**: `SURFACE::Free` (win32kbase.sys @ 0x1c002b8c0):
```c
// 1. Free pixel data via Win32FreePool (if flag at SURFACE+0x2B0 is set)
if ( LOBYTE(ListEntry[43].Next) ) {  // SURFACE+0x2B0
    Win32FreePool(pvBits);            // Free pixel data (NOT zeroed)
    pvBits = 0;
}
// 2. Zero and return to type isolation lookaside list
FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>(ListEntry);  // ZEROS the SURFACE
```

**SURFACE::Allocate** (win32kbase.sys @ 0x1c00808c0) uses `gpTypeIsolation` — a type-isolated lookaside list with 704-byte slots (SURFACE::tSize = 0x2B8 = 696 bytes + 8 bytes alignment/metadata). SURFACEs can only be allocated/freed within this isolated pool.

### 1.4 Delete-Pending State

When a bitmap selected into a DC is deleted via TOCTOU:

**`SURFACE::bDeleteSurface`** (win32kbase.sys @ 0x1C000DEF0):
1. `HmgShareLockCheckIgnoreStockBit` locks the SURFACE (increments share count at OBJECT+8)
2. `HmgRemoveObject` is called with expected share count = 1
3. Actual share count = 2 (handle + DC reference + lock increment) → **HmgRemoveObject FAILS**
4. `HmgRemoveObject` sets `entry[15] |= 0x08` (delete-pending flag on handle table entry)
5. `bDeleteSurface` checks `v68` (share count from HmgRemoveObject):
   - `v68 != 1` (share count > 1): sets `SURFACE+0x70 |= 0x1000000` (delete-pending flag on SURFACE)
   - Calls `DEC_SHARE_REF_CNT(a1)` → decrements share count
6. Returns 0 (delete-pending, NOT freed)

**During delete-pending**:
- SURFACE is alive, NOT freed, NOT zeroed
- Pixel data is alive, NOT freed (pixel data is freed in `SURFACE::Free`, which is NOT called)
- `SURFACE+0x50` (pvScan0) is valid, pointing to original pixel data
- `SURFACE+0x48` (pvBits) is valid, pointing to original pixel data
- Handle table entry's object pointer is NOT cleared (HmgMarkLazyDelete is NOT called from bDeleteSurface)
- Handle is still valid and usable

### 1.5 HmgShareLockCheckIgnoreStockBit Ignores Delete-Pending

**`HmgShareLockCheckIgnoreStockBit`** (win32kbase.sys @ 0x1C0032E40):
```c
// Checks ONLY:
if ( *((_BYTE *)v25 + 14) == a2                    // Type match (entry[14])
  && ((HIWORD(a1) ^ v25[6]) & 0xFFFFFF7F) == 0 )   // Stamp match (entry[12])
{
    ++*(_DWORD *)(v4 + 8);  // Increment share count
    return v4;              // SUCCESS — returns locked object
}
// Does NOT check:
// - entry[15] & 0x08 (delete-pending flag set by HmgRemoveObject)
// - entry[15] & 0x02 (lazy-delete flag set by HmgMarkLazyDelete)
```

**Result**: Delete-pending bitmap handles STILL WORK for `GetBitmapBits`/`SetBitmapBits` and all GDI operations that use `SURFREF` (which calls `HmgShareLockCheckIgnoreStockBit`).

### 1.6 HmgMarkLazyDelete Is NOT Called from bDeleteSurface

**`HmgMarkLazyDelete`** (win32kbase.sys @ 0x1C0034A50):
- Sets `entry[15] |= 0x02` (lazy-delete flag)
- Clears `entry+16` (object pointer in handle table entry)
- **xrefs**: Only data references (0x1c022d674, 0x1c025b814) — NO code references from bDeleteSurface

**`HmgRemoveObject`** (win32kbase.sys @ 0x1C0032640):
- On share count mismatch: sets `entry[15] |= 0x08` (NOT 0x02)
- Does NOT clear the object pointer
- The handle entry remains valid and resolvable

---

## 2. KEY STRUCTURE LAYOUT

### SURFACE (type isolation, 704-byte slots, zeroed on free)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x00 | 8 | HOBJ (handle) | Back-pointer to handle |
| +0x08 | 4 | Share count | Incremented by HmgShareLock*, checked by HmgRemoveObject |
| +0x0C | 2 | Stamp | Matched against handle HIWORD |
| +0x18 | 8 | DHSURF (dhsurf) | Device handle surface |
| +0x30 | 8 | HDEV (hdev) | Device handle |
| +0x48 | 8 | pvBits | Pixel data base pointer |
| **+0x50** | **8** | **pvScan0** | **Scan0 pointer — controls bitmap R/W target** |
| +0x58 | 4 | lDelta | Stride (can be negative for bottom-up) |
| +0x64 | 2 | Format type | BMF_TYPE_* |
| +0x66 | 2 | Format flags | v47 in bDeleteSurface |
| +0x70 | 4 | Flags | 0x1000000 = delete-pending |
| +0x74 | 4 | More flags | & 9 = display surface |
| +0x2B0 | 1 | Pool-alloc flag | If set, SURFACE::Free frees pvBits via Win32FreePool |
| Total | 0x2B8 (696) | | Slot size: 704 (8 bytes alignment) |

### DC (session pool, 0x868 bytes, NOT zeroed on free)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x00 | 8 | HOBJ (handle) | |
| +0x0C | 2 | Share count | At DC+12, incremented by XDCOBJ::vLock via HmgLockEx |
| +0x1F0 | 8 | pSurface | Pointer to SURFACE — **overwritten to 0 by DCMEMOBJ constructor** |
| Total | 0x868 (2152) | | Session pool, Win32FreePool (no memset) |

### Handle Table Entry (24 bytes per entry in sub-table)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x00 | 8 | ? | |
| +0x08 | 4 | Count/flags | Checked in NtGdiDeleteObjectApp quick-return: & 0xFFFFFFFE == 0 |
| +0x0C | 2 | Stamp | Matched against handle HIWORD |
| +0x0E | 1 | Type | Object type (5=SURFACE, 1=DC, etc.) |
| +0x0F | 1 | Flags | bit 0: locked, bit 1: lazy-delete, bit 3: delete-pending |
| +0x10 | 8 | Object pointer | Points to the kernel object |

---

## 3. BLOCKED PATHS — DETAILED ANALYSIS

### 3.1 DC Deletion via TOCTOU — BLOCKED

**`NtGdiDeleteObjectApp`** with type 1 (DC) → `bDeleteDCInternal` → `bDeleteDCInternalEx`:

```c
DCOBJ::DCOBJ(v5, a1);  // Locks DC via HmgLockEx → increments DC+0x0C (share count)
if ( v5[0] && bDeleteDCOBJ(v5, ...) ) { ... }
```

**`bDeleteDCOBJ`** (win32kbase.sys @ 0x1c003c98c):
```c
if ( !a2 && !HmgQueryRemoveAttempted(**a1, 0) )  // Check: has removal been attempted?
    return 0;  // FAIL — normal DCs haven't had removal attempted
if ( *((_WORD *)*a1 + 6) > 1u && (v7 & 0x1C00000) == 0 )  // Share count > 1?
    return 0;  // FAIL — ERROR_BUSY (share count is 2: handle + DCOBJ lock)
```

**Blocker**: `DCOBJ::DCOBJ` in `bDeleteDCInternalEx` increments the DC's share count (at DC+0x0C) from 1 to 2. `bDeleteDCOBJ` then checks if share count > 1 → fails. Additionally, `HmgQueryRemoveAttempted` returns 0 for normal DCs.

**Conclusion**: DCs CANNOT be deleted via the TOCTOU batch buffer. The share count check in `bDeleteDCOBJ` always fails because `DCOBJ::DCOBJ` increments the count before the check.

### 3.2 EngModifySurface — THE pvScan0 Writer (Kernel-Only)

**`EngModifySurface`** (win32kbase.sys @ 0x1C009B440):

```c
BOOL EngModifySurface(HSURF hsurf, HDEV hdev, FLONG flHooks, FLONG flSurface,
                      DHSURF dhsurf, PVOID pvScan0, LONG lDelta, PVOID pvReserved)
{
    v12 = HmgShareLockIgnoreStockBit(hsurf);  // Lock surface (ignores delete-pending!)
    // ... condition checks ...
    if ( pvScan0 && lDelta )  // Both must be non-zero
    {
        if ( (flHooks & 0x1000) != 0 || (flSurface & 1) == 0 )  // HOOK_BITBLT or no "new surface"
        {
            if ( v14 )  // pvReserved == NULL, surface type checks, hdev match
            {
                *(_QWORD *)(v13 + 80) = pvScan0;  // SURFACE+0x50 = pvScan0 (USER-CONTROLLED!)
                *(_DWORD *)(v22 + 88) = lDelta;   // SURFACE+0x58 = lDelta
                *(_QWORD *)(v22 + 72) = pvScan0;  // SURFACE+0x48 = pvScan0 (also pvBits!)
                // ...
            }
        }
    }
}
```

**This is the ONLY function that writes a user-controlled value to SURFACE+0x50 (pvScan0).**

**Reachability from user mode**: NONE

- No `NtGdiEngModifySurface` syscall exists (confirmed by function search in win32kfull.sys)
- `win32kfull.sys` imports `EngModifySurface` from `win32kbase` (at import address 0x1c03649b8)
- All callers in `win32kfull.sys` are display driver multi-mon internal paths:
  - `PanEnableSurface` (0x1c0294ec0) — passes `pvScan0 = NULL`, `lDelta = 0` (useless)
  - `MULTIPANSURFLOCK::vLockBmp1AndPrepareForPunt` (0x1c0296658) — `pvScan0` from DHSURF
  - `MULTIPANSURFLOCK::vLockBmp2AndPrepareForPunt` (0x1c029672c) — `pvScan0` from DHSURF
  - `PANSURFLOCK::vLockBmpAndPrepareForPunt` (0x1c0296804) — `pvScan0` from DHSURF
  - `MULTIPANSURFLOCK::vUnLockBmp1AndRemovePunt` (0x1c0296f68)
  - `MULTIPANSURFLOCK::vUnLockBmp2AndRemovePunt` (0x1c0297024)
  - `MulCreateDeviceBitmapEx` (0x1c02a2420) — passes `pvScan0 = NULL`, `lDelta = 0` (useless)
- All PANSURFLOCK callers pass `pvScan0` from the DHSURF structure (`dhsurf[1]`), which is a display driver internal structure — NOT user-controlled
- In `win32kbase.sys`, the only caller is `MulEnableSurface` (0x1c0142080) — also passes `pvScan0 = NULL`

**`HmgShareLockIgnoreStockBit`** (win32kbase.sys @ 0x1C009A4B8) used by EngModifySurface:
- Checks type == 5 (hardcoded for SURFACE) and stamp
- Does NOT check delete-pending flag
- Would work on delete-pending handles IF we could call EngModifySurface

### 3.3 SURFACE Type Isolation — BLOCKED

**`SURFACE::Allocate`**: Uses `gpTypeIsolation` → `ExpInterlockedPopEntrySList` from a type-isolated lookaside list (`CLookAsideTypeIsolation<180224,704>`). SURFACEs can only come from this pool.

**`SURFACE::Free`**: Calls `FreeIsolatedType` which:
1. Zeros the memory (memset to 0)
2. Pushes the slot back to the lookaside SLIST

**Blocker**: Even if we free a SURFACE and try to reclaim its memory, the memory is:
1. Zeroed on free (pvScan0 = 0)
2. Returned to a type-isolated pool (only SURFACEs can use it)
3. Not accessible from regular pool allocations (pixel data, DCs, etc.)

### 3.4 DCMEMOBJ Overwrites DC+0x1F0 — BLOCKED

When a new DC is created, `DCMEMOBJ` constructor overwrites DC+0x50 through DC+0x220, which includes DC+0x1F0 (the SURFACE pointer). This means:
- If we free a DC (not zeroed) and reclaim its memory with a new DC, the new DC's DCMEMOBJ sets DC+0x1F0 = 0
- If we reclaim DC memory with bitmap pixel data and write a fake SURFACE pointer at offset 0x1F0, no DC handle resolves to that memory

### 3.5 Pixel Data Free Timing

**Critical finding**: For normal pool-allocated bitmaps, pixel data is freed in `SURFACE::Free`, NOT in `bDeleteSurface`.

**`bDeleteSurface` LABEL_59 path** (when HmgRemoveObject succeeds):
- For normal pool bitmaps (v47 & 8 == 0, v47 & 0x800 == 0, v47 & 0x10 == 0): the code reaches `goto LABEL_109` WITHOUT freeing pixel data
- `LABEL_109` calls `SURFACE::Free`
- `SURFACE::Free` frees pixel data via `Win32FreePool` (if flag at SURFACE+0x2B0 is set), then zeroes the SURFACE

**Sequence** (bitmap NOT in DC, deletion succeeds):
1. `HmgRemoveObject` succeeds → handle removed
2. Display driver callbacks (if any)
3. `LABEL_59`: no pixel data free for normal pool bitmaps
4. `LABEL_109`: `SURFACE::Free` → `Win32FreePool(pvBits)` → `FreeIsolatedType` (zeroes SURFACE)
5. Both pixel data free and SURFACE zero happen in the same function call — NO window between them

**Sequence** (bitmap IN DC, delete-pending):
1. `HmgRemoveObject` fails → delete-pending flag set
2. `DEC_SHARE_REF_CNT` → share count decremented
3. Returns 0 → `SURFACE::Free` is NEVER called
4. Pixel data is NOT freed, SURFACE is NOT zeroed
5. Everything is alive and valid — normal operation

### 3.6 No Other Function Writes to SURFACE+0x50

Exhaustive search of all `mov [reg+50h], reg` instructions in win32kbase.sys (80 results) and win32kfull.sys (50+ results):

- **win32kbase.sys**: Only `SURFMEM::bCreateDIB` writes to SURFACE+0x50, but it sets pvScan0 = pvBits (the kernel-allocated pixel data pointer), NOT a user-controlled value
- **win32kfull.sys**: `ShrinkDIB_CY_SrkCX` writes to offset 0x50 of a stack structure (not a SURFACE). `EngStretchBltNew` writes to a temporary internal SURFACE. No user-reachable path writes a user-controlled value to a persistent SURFACE's pvScan0
- **`EngModifySurface`** at 0x1C010777F: `mov [r13+50h], rax` — THE ONLY user-controlled write to SURFACE+0x50, but kernel-only

---

## 4. DELETE-PENDING STATE — FULL ANALYSIS

### 4.1 What Happens During Delete-Pending

When `HmgRemoveObject` fails (share count > 1):

1. `HmgRemoveObject` sets `entry[15] |= 0x08` (bit 3 — delete-pending flag on handle table entry)
2. `HmgRemoveObject` sets `*a6 = v19` (current share count) and returns 0
3. `bDeleteSurface` checks `v68` (share count from HmgRemoveObject):
   - If `v68 == 1`: checks `SURFACE+0x70 & 0x800` flag
   - If `v68 != 1` (share count > 1):
     - Checks conditions: `SURFACE+0xA0 != 0` OR `(flags & 0x800000 && format & 0x200)` OR `(SURFACE+0x70 & 0x800)`
     - If conditions met: sets `SURFACE+0x70 |= 0x1000000` (delete-pending flag on SURFACE)
     - Or if `SURFACE+0x70 & 0x800`: sets `SURFACE+0x140 = 1`, increments `glRenderEndDelete`
4. `DEC_SHARE_REF_CNT(a1)` — decrements share count
5. Returns 0

### 4.2 SURFACE State During Delete-Pending

| Field | Value | Notes |
|-------|-------|-------|
| SURFACE+0x48 (pvBits) | Valid | Points to original pixel data |
| SURFACE+0x50 (pvScan0) | Valid | Points to original pixel data (or derived from it) |
| SURFACE+0x58 (lDelta) | Valid | Original stride |
| SURFACE+0x70 (flags) | 0x1000000 set | Delete-pending flag |
| Pixel data | Allocated, valid | NOT freed |
| Handle table entry | Valid, object pointer intact | entry[15] bit 3 set |
| Handle | Valid, usable | HmgShareLockCheckIgnoreStockBit works |

### 4.3 Operations Available During Delete-Pending

- `GetBitmapBits(deleted_bitmap)` → `SURFREF` → `HmgShareLockCheckIgnoreStockBit` succeeds → reads from pvScan0 → reads pixel data **(normal operation)**
- `SetBitmapBits(deleted_bitmap)` → same path → writes through pvScan0 → writes pixel data **(normal operation)**
- `BitBlt` through DC with deleted bitmap → reads DC+0x1F0 = &SURFACE → reads pvScan0 → normal operation
- `SelectObject(DC, different_bitmap)` → deselects delete-pending bitmap → share count drops → if reaches 0 → SURFACE freed + zeroed

**All operations are normal. No corruption. No arbitrary R/W.**

---

## 5. THE FUNDAMENTAL BLOCKER

### The Problem

To achieve arbitrary kernel R/W, we need `SURFACE+0x50` (pvScan0) to point to arbitrary kernel memory. Then `GetBitmapBits`/`SetBitmapBits` would read/write that memory.

### Why We Can't Modify pvScan0

1. **SURFACE is in type isolation** — allocated from a separate lookaside list, zeroed on free, cannot be reclaimed by non-SURFACE allocations
2. **No user-mode function writes to SURFACE+0x50** — exhaustive instruction search confirmed only `EngModifySurface` and `SURFMEM::bCreateDIB` write to this offset
3. **`EngModifySurface` is kernel-only** — no `NtGdiEngModifySurface` syscall, all callers are display driver internal paths
4. **`SURFMEM::bCreateDIB` sets pvScan0 = pvBits** (kernel-allocated pixel data), not user-controlled
5. **DC deletion fails** — share count check in `bDeleteDCOBJ` prevents DC deletion via TOCTOU
6. **DCMEMOBJ overwrites DC+0x1F0** — creating a new DC at a freed DC's address zeroes the SURFACE pointer

### The Dead End

```
TOCTOU deletes bitmap
    ├── Bitmap NOT in DC → SURFACE freed + zeroed → pvScan0 = 0 → USELESS
    └── Bitmap IN DC → delete-pending → SURFACE alive, pvScan0 valid → NORMAL OPERATION
                                                                    │
                                    Need to modify pvScan0 ──────────┘
                                                    │
                                    EngModifySurface ──── KERNEL ONLY
                                                    │
                                    Other functions ──── NONE FOUND
                                                    │
                                    Type isolation ──── CAN'T WRITE TO SURFACE
                                                    │
                                    DC UAF ─────────── DC DELETION FAILS
                                                    │
                                    DEAD END
```

---

## 6. REMAINING VIABLE APPROACHES

### 6.1 UMPD (User-Mode Printer Driver) Path — PARTIALLY EXPLORED

There are 30+ `NtGdiEng*` syscalls in win32kfull.sys for User-Mode Printer Driver support. While `NtGdiEngModifySurface` does NOT exist, other UMPD functions might indirectly trigger `EngModifySurface` through display driver callbacks.

**Functions to investigate**:
- `NtGdiEngCreateDeviceSurface` (0x1c015d070) — creates a device surface, might call EngModifySurface during setup
- `NtGdiEngAssociateSurface` (0x1c015a6b0) — associates a surface with a device
- `NtGdiEngCreateBitmap` (0x1c015cf30) — creates an engine bitmap

**Requirement**: A UMPD context (user-mode printer driver registration) is needed to call these functions. This might require `NtGdiEngCreateEnableSurface` or similar setup.

**Status**: NOT FULLY EXPLORED. This is the most promising remaining path.

### 6.2 Multi-Threaded Race on Delete-Pending Bitmap

**Idea**: Use two threads where Thread A performs a GDI operation on the delete-pending bitmap while Thread B performs a second deletion that succeeds (frees the SURFACE).

**Flow**:
1. Create BITMAP1, select into DC1 → share count = 2
2. TOCTOU delete BITMAP1 → delete-pending, share count = 1 (after DEC_SHARE_REF_CNT)
3. Thread A: start `GetBitmapBits(BITMAP1)` → `HmgShareLockCheckIgnoreStockBit` → share count = 2
4. Thread B: `SelectObject(DC1, stock_bitmap)` → deselects BITMAP1 → share count drops
5. Thread B: share count reaches 0 → `SURFACE::Free` → SURFACE zeroed, pixel data freed
6. Thread A: reads pvScan0 (now 0 or stale) → null deref or UAF read

**Problem**: This gives a null dereference or UAF read, NOT arbitrary R/W. The SURFACE is zeroed before we can redirect pvScan0.

**Status**: LOW PROBABILITY of achieving arbitrary R/W. Might give a BSOD or info leak.

### 6.3 Pixel Data Reclamation After SURFACE::Free

**Idea**: Race the pixel data free in `SURFACE::Free` to reclaim it with controlled data.

**Flow**:
1. Create BITMAP1 (not in DC) with pixel data at address A
2. TOCTOU delete BITMAP1 → SURFACE::Free → Win32FreePool(A) → FreeIsolatedType (zeroes SURFACE)
3. Between Win32FreePool(A) and FreeIsolatedType: reclaim A with controlled data
4. But: SURFACE is zeroed immediately after → pvScan0 = 0 → can't use the bitmap

**Problem**: The window between `Win32FreePool` and `FreeIsolatedType` is within a single kernel function call. No user-mode interjection is possible. Even if we could reclaim the pixel data, the SURFACE is zeroed (pvScan0 = 0).

**Status**: BLOCKED. No window for user-mode reclamation.

### 6.4 Pool Layout Manipulation for Pixel Data Overlap

**Idea**: Carefully control pool allocation order to place two bitmaps' pixel data adjacent in pool, then use an overflow or type confusion to corrupt one bitmap's SURFACE via the other's pixel data.

**Problem**: SURFACEs are in type isolation (separate pool). Pixel data is in regular session pool. They cannot be adjacent. No overflow from pixel data to SURFACE is possible.

**Status**: BLOCKED by type isolation.

### 6.5 Use TOCTOU to Delete a Non-SURFACE Object with Non-Zeroed Free

**Idea**: Delete a GDI object type that is NOT zeroed on free (like DC) and reclaim its memory.

**Problem**: DC deletion fails (share count check). Other types (REGION, PALETTE, FONT, BRUSH) may or may not be zeroed on free, but none of them give us a path to corrupt a SURFACE's pvScan0.

**Types to check**:
- REGION: might not be zeroed (need to check `REGION::vDeleteREGION`)
- PALETTE: might not be zeroed (need to check `bDeletePalette`)
- BRUSH: might not be zeroed (need to check `bDeleteBrush`)

**Status**: PARTIALLY EXPLORED. Even if we can delete and reclaim these types, we can't use them to corrupt SURFACE+0x50.

### 6.6 Display Surface / DWM Path

**Idea**: Trigger a display driver or DWM code path that calls `EngModifySurface` on a surface we control.

**PANSURFLOCK analysis**: The `vLockBmpAndPrepareForPunt` functions call `EngModifySurface` with `pvScan0 = dhsurf[1]` (from the DHSURF structure). The DHSURF is the display driver's private surface structure.

**Potential**: If we can create a situation where the DHSURF's `pvScan0` field (at dhsurf+0x08) contains a user-controlled value, and trigger the PANSURFLOCK path, `EngModifySurface` would write that value to a SURFACE's pvScan0.

**Requirements**:
- A display surface (not a memory bitmap) — requires a display DC
- The display must be in "pan" mode (virtual desktop larger than physical display)
- The DHSURF structure must be corruptible

**Status**: NOT FULLY EXPLORED. Requires display mode changes and display driver interaction. May require admin privileges.

---

## 7. CRITICAL DATA FOR EXPLOIT DEVELOPMENT

### 7.1 EngModifySurface Call Pattern (from PANSURFLOCK::vLockBmpAndPrepareForPunt)

```c
EngModifySurface(
    (HSURF)(*this)[1],                           // hsurf = surface handle
    *(HDEV *)(*((_QWORD *)dhsurf + 4) + 48LL),  // hdev from DHPDEV
    0,                                            // flHooks = 0
    0,                                            // flSurface = 0 → (flSurface & 1) == 0 → condition met
    dhsurf,                                       // dhsurf = device handle surface
    *((PVOID *)dhsurf + 1),                       // pvScan0 = dhsurf[0x08] (DHSURF+8)
    *((_DWORD *)dhsurf + 4),                      // lDelta = dhsurf[0x10] (DHSURF+16)
    nullptr                                       // pvReserved = NULL → v14 = true
);
```

**Conditions met**: `pvScan0 != 0`, `lDelta != 0`, `(flSurface & 1) == 0`, `pvReserved == NULL`. The ONLY remaining condition is `v14` (surface type checks + hdev match).

### 7.2 Key Function Addresses (win32kbase.sys, imagebase 0x1C0000000)

| Function | Address | Purpose |
|----------|---------|---------|
| `NtGdiDeleteObjectApp` | 0x1C0033780 | Type dispatch for deletion |
| `SURFACE::bDeleteSurface` | 0x1C000DEF0 | Bitmap deletion logic |
| `HmgRemoveObject` | 0x1C0032640 | Handle removal + share count check |
| `HmgMarkLazyDelete` | 0x1C0034A50 | Sets lazy-delete flag (NOT called from bDeleteSurface) |
| `HmgShareLockCheckIgnoreStockBit` | 0x1C0032E40 | Lock handle (ignores delete-pending) |
| `HmgShareLockIgnoreStockBit` | 0x1C009A4B8 | Lock handle for EngModifySurface (ignores delete-pending) |
| `EngModifySurface` | 0x1C009B440 | THE pvScan0 writer (kernel-only) |
| `SURFACE::Allocate` | 0x1C00808C0 | Type isolation allocation |
| `SURFACE::Free` | 0x1C002B8C0 | Type isolation free + zero |
| `SURFMEM::bCreateDIB` | 0x1C0028000 | Bitmap creation (sets pvScan0 = pvBits) |
| `bDeleteDCInternal` | 0x1C0008F00 | DC deletion entry |
| `bDeleteDCInternalEx` | 0x1C003C730 | DC deletion logic |
| `bDeleteDCOBJ` | 0x1C003C98C | DC deletion check (share count) |
| `XDCOBJ::bCleanDC` | 0x1C00934E0 | DC cleanup (deselects bitmap) |
| `vDeleteDCInternalWorker` | 0x1C014D314 | DC free worker |
| `NtGdiFlushUserBatchInternal` | 0x1c008ef50 (win32kfull) | Batch buffer handler |

### 7.3 SURFACE::Free Pixel Data Free Logic

```c
// SURFACE::Free (win32kbase.sys @ 0x1C002B8C0)
void SURFACE::Free(PSLIST_ENTRY ListEntry) {
    // ListEntry = SURFACE pointer
    // ListEntry[43].Next = SURFACE+0x2B0 (pool-alloc flag byte)
    if ( LOBYTE(ListEntry[43].Next) ) {  // If pool-allocated pixel data
        pvBits = *((_QWORD *)&ListEntry[4].Next + 1);  // SURFACE+0x48
        if ( pvBits ) {
            Win32FreePool(pvBits);  // Free pixel data (NOT zeroed)
            pvBits = 0;             // Clear pointer
        }
    }
    FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>(ListEntry);  // Zero + return to lookaside
}
```

### 7.4 bDeleteSurface Delete-Pending Path

```c
// When HmgRemoveObject fails (share count > 1):
if ( v68 != 1 ) {  // v68 = current share count
    // Check lazy-delete conditions
    if ( !*(_QWORD *)(a1 + 160)           // SURFACE+0xA0 == 0
      && ((*(_DWORD *)a1 & 0x800000) == 0  // handle flag
      || (*(_WORD *)(a1 + 102) & 0x200) == 0)  // format flag
      && (*(_DWORD *)(a1 + 112) & 0x800) == 0 ) {  // SURFACE+0x70 & 0x800
        goto LABEL_25;  // NOT lazy delete — return error
    }
    v20 = *(_DWORD *)(a1 + 112);  // SURFACE+0x70 (flags)
    if ( (v20 & 0x800) != 0 ) {
        // Render-end delete path
        if ( !*(_DWORD *)(a1 + 320) ) {  // SURFACE+0x140
            *(_DWORD *)(a1 + 320) = 1;
            _InterlockedAdd(&glRenderEndDelete, 1u);
        }
    } else {
        // SET DELETE-PENDING FLAG
        *(_DWORD *)(a1 + 112) = v20 | 0x1000000;  // SURFACE+0x70 |= 0x1000000
    }
}
DEC_SHARE_REF_CNT(a1);  // Decrement share count
goto LABEL_119;          // Return 0 (delete-pending)
```

---

## 8. CONCLUSION

### The Exploit Is Blocked At

**"No user-mode-reachable function writes a user-controlled value to SURFACE+0x50 (pvScan0)."**

### What Works

- TOCTOU bitmap deletion (confirmed at runtime)
- Delete-pending state (SURFACE alive, handle usable, pvScan0 valid)
- HmgShareLockCheckIgnoreStockBit ignores delete-pending flag
- DC non-zeroed free (confirmed in code)
- SURFACE zeroed free (confirmed in code)
- Pixel data non-zeroed free (confirmed in code)

### What Doesn't Work

- DC deletion via TOCTOU (share count check in bDeleteDCOBJ)
- EngModifySurface from user mode (no syscall, kernel-only callers)
- SURFACE pool reclamation (type isolation, zeroed on free)
- DC memory reclamation for fake SURFACE pointer (DCMEMOBJ overwrites DC+0x1F0)
- Pixel data reclamation between free and zero (no window — same function call)

### Most Promising Remaining Path

**UMPD (User-Mode Printer Driver) exploration**: The 30+ `NtGdiEng*` syscalls in win32kfull.sys provide user-mode access to GDI engine functions for printer drivers. While `NtGdiEngModifySurface` doesn't exist, other UMPD functions might trigger display driver callbacks that call `EngModifySurface` internally. This requires:

1. Registering as a UMPD (finding the registration syscall)
2. Creating a device surface through the UMPD path
3. Triggering a code path that calls `EngModifySurface` with a surface we control
4. Controlling the DHSURF structure's pvScan0 field (dhsurf+0x08)

If this path exists, the exploit would be:
1. Register as UMPD
2. Create a device surface via UMPD
3. Trigger EngModifySurface with controlled pvScan0 → writes to SURFACE+0x50
4. Use GetBitmapBits/SetBitmapBits for arbitrary kernel R/W

### Alternative: Display Driver / Pan Mode Path

If we can trigger the PANSURFLOCK code path (multi-mon pan mode), `EngModifySurface` is called with `pvScan0 = dhsurf[1]`. If we can control the DHSURF structure, we control pvScan0. This requires:
1. Changing display settings to trigger pan mode
2. Creating a situation where the DHSURF is corruptible
3. Triggering a drawing operation that punts to the engine

**Status**: Requires further analysis of display driver interaction paths and DHSURF structure layout.
