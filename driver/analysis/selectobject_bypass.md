# SelectObject Bypass & EngModifySurface Reachability Analysis

## Binary Set Analyzed
| Binary | IDA Port | Imagebase |
|--------|----------|-----------|
| win32k.sys | 13337 | default |
| win32kbase.sys | 13338 | 0x1C0000000 |
| ntoskrnl.exe | 13339 | default |
| win32kfull.sys | 13340 | 0x1C0000000 |

## SURFACE Structure Map (Verified from Decompilation)

```
Offset  Field         Type    Description
------  -----         ----    -----------
0x00    flags         DWORD   0x400000=devbitmap, 0x200000=driver_surf, 0x40000=UMPD, 0x800000=redirected
0x18    dhsurf        QWORD   device-managed surface handle (user-controlled for device bitmaps)
0x28    palette       QWORD   XEPALOBJ (set by EngAssociateSurface from PDEV)
0x30    hdev          HDEV    PDEV handle (NULL for our bitmap, settable via EngAssociateSurface)
0x40    unk_40        QWORD   used in EngAssociateSurface checks
0x48    pjScan0       QWORD   derived scan0 (set from pvScan0 by EngModifySurface)
0x50    pvScan0       QWORD   **TARGET** — written ONLY by EngModifySurface with non-NULL pvScan0
0x58    lDelta        DWORD   scan line stride
0x64    iType         WORD    0=STYPE_BITMAP, 1=STYPE_DEVICE, 3=STYPE_DEVBITMAP
0x66    flags2        WORD    0x200=redirected, 0x1=top-down
0x70    more_flags    DWORD   0x800, 0x4000000, 0x8000000, 0x10, 0x1000000, bit0=pfnBitBlt dispatch
0x88    reserved      QWORD   cleared by EngAssociateSurface
0xA0    owner_dc      QWORD   DC that selected this surface
0xA8    excl_refcnt   DWORD   exclusive reference count
```

## Our Device Bitmap Properties

```
iType   = 3 (STYPE_DEVBITMAP)
flags   = 0x640000 = 0x400000 | 0x200000 | 0x040000
  0x400000 = STYPE_DEVBITMAP marker (set by CreateDriverSurfMem when iType==3)
  0x200000 = driver surface flag (set by CreateDriverSurfMem for any non-zero iType)
  0x040000 = UMPD flag (set when iFormat has 0x8000 bit)
dhsurf  = user-controlled fake DHSURF (pvScan0 at DHSURF+0x08, lDelta at DHSURF+0x10)
hdev    = NULL
pvScan0 = 0 (cleared at creation)
```

---

## Task 1: Why Does SelectObject Fail for Device Bitmaps?

### Call Chain
```
NtGdiSelectBitmap (win32kfull.sys @ 0x1C0100E90)
  → hbmSelectBitmapInternal (win32kbase.sys @ 0x1C00CA320)
```

### NtGdiSelectBitmap Decompile (0x1C0100E90)
```c
HBITMAP NtGdiSelectBitmap(HDC a1, HBITMAP a2) {
    MDCOBJ v8(a1);
    if (RFONTOBJ::bValid(v8)) {
        v4 = *(WORD*)(v8[0] + 12);   // DC dctype
        if (v4 <= 1) {                // dctype must be 0 (info) or 1 (memory)
            return hbmSelectBitmapInternal(v8, a2, 0, 0, 0);  // a3=0, a4=0, a5=0
        }
    }
    return nullptr;
}
```

**Key:** `a5 = 0` is passed to hbmSelectBitmapInternal. This matters for the final check.

### hbmSelectBitmapInternal Decompile (0x1C00CA320) — The Rejection Logic

The function has a compound OR-chain condition. ANY sub-condition failing sends control to `LABEL_75` (return NULL, no selection):

```c
HBITMAP hbmSelectBitmapInternal(DC **a1, HBITMAP a2, int a3, int a4, int a5) {
    v38 = HmgShareLockCheck(a2, 5);   // lock the bitmap surface
    if (!v38) goto LABEL_75;

    v11 = *a1;                        // DC pointer
    v12 = v38;                        // SURFACE pointer
    v36 = *((QWORD*)v11 + 6);         // DC's PDEV (hdev)
    v13 = *(DWORD*)(HmgPentryFromPobj(v11) + 8) & 0xFFFFFFFE;  // DC pentry flags

    // === THE GATE CONDITION (all must pass) ===
    if (
        // Check 1: DC dctype must be 1 (DCTYPE_MEMORY)
        *(DWORD*)(v11 + 32) != 1

        // Check 2: exclusive refcount + UMPD/redirect + owner mismatch
        || *(DWORD*)(v12 + 0xA8)          // excl_refcnt != 0
           && (*(DWORD*)v12 & 0x800000) == 0  // NOT redirected
           || (*(WORD*)(v12 + 0x66) & 0x200) == 0  // NOT UMPD-redirected
           && *(QWORD*)(v12 + 0xA0) != *(QWORD*)v11  // owner != DC

        // Check 3: bIsCompatible
        || !bIsCompatible(&v35, ..., v12, v36, 1)

        // Check 4: bIsSurfaceAllowedInDC
        || !bIsSurfaceAllowedInDC(v12, *(QWORD*)*a1 + 6))

        // Check 5: 0x800 flag
        || v13 && (*(DWORD*)(v12 + 0x70) & 0x800) != 0

        // Check 6: a5=0 and v13=0 → FAIL (from NtGdiSelectBitmap, a5 is always 0)
        || !a5 && !v13
    ) {
        goto LABEL_75;  // FAIL
    }
    // ... selection proceeds ...
}
```

### Check-by-Check Analysis for Our Bitmap (flags=0x640000, iType=3, hdev=NULL)

| Check | Condition | Our Value | Result |
|-------|-----------|-----------|--------|
| 1 | DC dctype == 1 | Use memory DC | PASS |
| 2 | excl_refcnt==0 OR (redirected AND owner==DC) | excl_refcnt=0 | PASS |
| 3 | bIsCompatible | iType=3, hdev=NULL | **FAIL** |
| 4 | bIsSurfaceAllowedInDC | 0x40000 flag set | **FAIL** |
| 5 | 0x800 flag if v13!=0 | 0x640000 & 0x800 = 0 | PASS |
| 6 | a5=0 and v13=0 | v13 = DC pentry flags & ~1 | PASS (if DC has flags) |

### Check 3: bIsCompatible (0x1C0029710) — FAILS

```c
__int64 bIsCompatible(QWORD *a1, __int64 a2, __int64 a3, __int64 a4, int a5) {
    if ((*(_WORD*)(a3 + 100) || *(_QWORD*)(a3 + 24))  // iType != 0 OR dhsurf != NULL
        && *(_QWORD*)(a3 + 48) != a4)                   // AND hdev != DC's PDEV
        return 0;  // FAIL
    // ...
}
```

For our bitmap:
- `iType = 3` → `iType != 0` is TRUE
- `dhsurf = user pointer` → `dhsurf != NULL` is TRUE
- `hdev = NULL` → `NULL != DC's PDEV` is TRUE (DC's PDEV is non-NULL for a display DC)
- **Result: FAIL (0)**

**Bypass:** If we set `hdev = DC's PDEV` via `NtGdiEngAssociateSurface`, then `hdev == DC's PDEV` and this check PASSES.

### Check 4: bIsSurfaceAllowedInDC (0x1C00CC650) — FAILS

```c
__int64 bIsSurfaceAllowedInDC(__int64 a1, __int64 a2) {
    v2 = *(QWORD*)(a1 + 48);     // SURFACE+0x30 = hdev
    if (SURFACE == pdibDefault) return 1;
    if (!a2) return 1;            // DC's PDEV is NULL → OK
    if (!*(QWORD*)(a1 + 40))     // SURFACE+0x28 (palette) == 0 → OK
        return 1;
    v5 = *(DWORD*)(a2 + 40) & 1; // PDEV display bit
    if (v5 && (*(DWORD*)(a1 + 112) & 0x40000) != 0  // display PDEV + 0x40000 flag → FAIL
        || v2 && v5 != (*(DWORD*)(v2 + 40) & 1))     // hdev type mismatch → FAIL
        return 0;
    return 1;
}
```

For our bitmap:
- `SURFACE+0x70 & 0x40000 = 0x640000 & 0x40000 = 0x40000 ≠ 0` → TRUE
- DC's PDEV is a display PDEV → `v5 = 1`
- `v5 && 0x40000` → **FAIL (0)**

Even after setting hdev via EngAssociateSurface:
- `v2 = DC's PDEV` (same as a2)
- `v5 == (*(DWORD*)(v2 + 40) & 1)` → TRUE (same PDEV, same display bit) → second sub-condition PASSES
- BUT `v5 && (0x40000 flag)` → **STILL FAILS**

### Root Cause: The 0x40000 UMPD Flag

The 0x40000 flag at `SURFACE+0x70` is set during creation in `CreateDriverSurfMem` (0x1C00C9DBC):

```c
if ((a6 & 0x8000) != 0) {  // iFormat has 0x8000 (UMPD flag)
    *(DWORD*)(v18 + 112) |= 0x40000u;  // SURFACE+0x70 |= 0x40000
}
```

The 0x8000 is always OR'd into iFormat by `NtGdiEngCreateDeviceBitmap`:
```c
HBITMAP NtGdiEngCreateDeviceBitmap(__int64 a1, struct tagSIZE a2) {
    if (ValidUmpdSizl(a2, 1) && (v2 - 1) <= 7)
        return EngCreateDeviceBitmap(v4, v3, v2 | 0x8000u);  // ALWAYS adds 0x8000
    return nullptr;
}
```

### Can We Clear the 0x40000 Flag?

**No.** There is no syscall that clears arbitrary SURFACE+0x70 flags:
- `NtGdiSetBitmapAttributes` (0x1C00A9770): Only calls `GreMakeBitmapStock()` if bit 0 is set. Does NOT touch SURFACE+0x70.
- `NtGdiClearBitmapAttributes` (0x1C0125420): Only calls `GreMakeBitmapNonStock()`. Does NOT touch SURFACE+0x70.
- `NtGdiEngAssociateSurface` (0x1C015A6B0): OR's hooks into SURFACE+0x70 (adds flags, never clears).
- No `NtGdiClearSurfaceFlags` or equivalent exists.

### Conclusions for Task 1

1. **SelectObject fails due to TWO independent checks:**
   - `bIsCompatible`: iType=3 + hdev=NULL → FAIL (fixable by setting hdev)
   - `bIsSurfaceAllowedInDC`: 0x40000 flag + display PDEV → FAIL (NOT fixable)

2. **The 0x40000 flag is the fundamental blocker.** It's set unconditionally when iFormat has 0x8000, and 0x8000 is always added by the syscall. No syscall can clear it.

3. **Cannot bypass SelectObject for device bitmaps with the 0x40000 flag on a display PDEV DC.**

---

## Task 2: Find a Way to Trigger EngModifySurface WITHOUT PAN Mode

### EngModifySurface Implementation (win32kbase.sys @ 0x1C009B440)

Full decompilation analysis:

```c
BOOL EngModifySurface(HSURF hsurf, HDEV hdev, FLONG flHooks, FLONG flSurface,
                      DHSURF dhsurf, PVOID pvScan0, LONG lDelta, PVOID pvReserved) {
    // Validation
    if (!hdev) return FALSE;
    surf = HmgShareLockIgnoreStockBit(hsurf);
    if (!surf) return FALSE;
    if ((flSurface & 0xFFFFFFF0) != 0) return FALSE;  // only low 4 bits of flSurface

    v14 = (pvReserved == nullptr);  // must be NULL

    // Check: surface must have 0x400000 flag OR iType == 1
    v15 = *(DWORD*)(surf + 112);  // SURFACE+0x70 flags
    if ((v15 & 0x400000) == 0 && *(WORD*)(surf + 100) != 1)
        v14 = 0;  // FAIL

    // Check: existing hdev must be NULL or match
    v16 = *(HDEV*)(surf + 48);  // SURFACE+0x30
    if (v16 && v16 != hdev)
        v14 = 0;  // FAIL

    // Check: if flags high bit set, hooks must match PDEV
    v17 = flHooks & 0xFFFFB7FF;
    if (v15 < 0 && ((DWORD)hdev[45] & 0x3B5EF) != v17 || ((DWORD)hdev[10] & 0x400) == 0)
        v14 = 0;  // FAIL

    // === TWO PATHS ===
    if (!pvScan0 || !lDelta) {
        // PATH A: pvScan0 == NULL → writes dhsurf/hdev/flags, NO pvScan0 write
        // ...
    } else {
        // PATH B: pvScan0 != NULL → WRITES pvScan0 to SURFACE+0x50!
        v19 = 0;
        if ((v17 & 0x1000) != 0 || (flSurface & 1) == 0)
            v19 = v14;  // all checks passed
        if (v19) {
            *(QWORD*)(surf + 80) = pvScan0;     // SURFACE+0x50 = pvScan0  ← TARGET WRITE
            *(DWORD*)(surf + 88) = lDelta;       // SURFACE+0x58 = lDelta
            *(WORD*)(surf + 100) = 0;            // SURFACE+0x64 = iType = 0
            // ... also sets pjScan0, flags2 ...
        }
    }
}
```

**Path B conditions for writing pvScan0:**
1. `hdev != NULL` (caller must provide valid HDEV)
2. Surface lockable
3. `pvReserved == NULL`
4. `(flSurface & 0xFFFFFFF0) == 0` (only low 4 bits)
5. `(flags & 0x400000) != 0` OR `iType == 1` — our bitmap has 0x400000 ✓
6. Existing hdev is NULL or matches — our bitmap has hdev=NULL ✓
7. `pvScan0 != NULL` AND `lDelta != 0` — caller provides these
8. `(v17 & 0x1000) != 0` OR `(flSurface & 1) == 0` — flSurface=0 → second TRUE ✓
9. All validation checks passed (v14 = TRUE)

### ALL References to EngModifySurface

#### win32kbase.sys (real implementation @ 0x1C009B440)

| Address | Type | Caller | pvScan0 | Useful? |
|---------|------|--------|---------|---------|
| 0x1C01420F0 | CODE | `MulEnableSurface` (0x1C0142080) | NULL | NO |
| 0x1C02385AC | DATA | function pointer table | — | table entry |
| 0x1C0249DF8 | DATA | function pointer table | — | table entry |
| 0x1C02612A4 | DATA | function pointer table | — | table entry |

**MulEnableSurface** (0x1C0142080):
```c
HSURF MulEnableSurface(DHPDEV a1) {
    DeviceSurface = EngCreateDeviceSurface((DHSURF)a1, v13, v2);  // iType=1
    EngModifySurface(DeviceSurface, v6, v5, 3u, (DHSURF)a1,
                     nullptr,   // ← pvScan0 = NULL
                     0,         // ← lDelta = 0
                     nullptr);
    // ...
}
```
Takes Path A (pvScan0=NULL). Does NOT write pvScan0. **NOT USEFUL.**

#### win32kfull.sys (thunk @ 0x1C0165A60 → win32kbase.sys)

| Address | Type | Caller | pvScan0 | Useful? |
|---------|------|--------|---------|---------|
| 0x1C029686A | CODE | `PANSURFLOCK::vLockBmpAndPrepareForPunt` | DHSURF+0x08 | **YES** |
| 0x1C02966C4 | CODE | `MULTIPANSURFLOCK::vLockBmp1AndPrepareForPunt` | DHSURF+0x08 | **YES** |
| 0x1C029679A | CODE | `MULTIPANSURFLOCK::vLockBmp2AndPrepareForPunt` | DHSURF+0x08 | **YES** |
| 0x1C0294FC8 | CODE | `PanEnableSurface` | NULL | NO |
| 0x1C032F648 | DATA | import table | — | import |
| 0x1C034E824 | DATA | import table | — | import |

#### win32k.sys (forwarder @ 0xFFFFF97FFF0041F0)

Just a forwarder through a function pointer (`qword_FFFFF97FFF065AA8`). No additional callers.

### Callers That Pass Non-NULL pvScan0 — ALL are Pan* Functions

#### PANSURFLOCK::vLockBmpAndPrepareForPunt (0x1C0296804)
```c
void PANSURFLOCK::vLockBmpAndPrepareForPunt(__int64 **this) {
    v2 = **this;                          // SURFOBJ
    *(this + 1) = v2;                     // store surface
    EngAcquireSemaphore(*(HSEMAPHORE*)(v2[4] + 776));
    dhsurf = (DHSURF)*(this + 1);         // DHSURF from surface
    if (!*(DWORD*)(dhsurf + 20)) {        // DHSURF+0x14 punt_count == 0
        EngModifySurface(
            (HSURF)(*this)[1],            // hsurf = surface handle
            *(HDEV*)(*((QWORD*)dhsurf + 4) + 48),  // hdev from DHSURF+0x20 → +0x30
            0,                             // flHooks = 0
            0,                             // flSurface = 0
            dhsurf,                        // dhsurf
            *((PVOID*)dhsurf + 1),        // pvScan0 = DHSURF+0x08 (USER CONTROLLED)
            *((DWORD*)dhsurf + 4),        // lDelta = DHSURF+0x10 (USER CONTROLLED)
            nullptr);                      // pvReserved = NULL
    }
    ++*((DWORD*)dhsurf + 5);              // DHSURF+0x14 punt_count++
}
```

#### MULTIPANSURFLOCK::vLockBmp1AndPrepareForPunt (0x1C0296658)
Same pattern: extracts pvScan0 from DHSURF+0x08, lDelta from DHSURF+0x10.

#### MULTIPANSURFLOCK::vLockBmp2AndPrepareForPunt (0x1C029672C)
Same pattern: extracts pvScan0 from DHSURF+0x08, lDelta from DHSURF+0x10.

### DHSURF Layout (Our Fake Structure)

```
Offset  Field        Source
------  -----        ------
0x00    unk_00       (surface pointer or similar)
0x08    pvScan0      USER CONTROLLED — passed to EngModifySurface as pvScan0
0x10    lDelta       USER CONTROLLED — passed to EngModifySurface as lDelta
0x14    punt_count   must be 0 for EngModifySurface to fire
0x20    pdev_ptr     → PDEV structure, PDEV+0x30 = hdev
```

### Dispatch Path to PanBitBlt

```
NtGdiBitBlt (0x1C0084DE0)
  → NtGdiBitBltInternal (0x1C0088600)
    → SURFACE::pfnBitBlt (0x1C00B9DA0)
      → if (SURFACE+0x70 & 1): return PDEV+0xB10 (driver BitBlt)
      → else: return EngBitBlt
    → PanBitBlt (0x1C0294720) [if PDEV is PAN-enabled]
      → MULTIPANSURFLOCK constructor (0x1C0294214)
        → if source iType == 3: vLockBmp2AndPrepareForPunt
          → EngModifySurface with DHSURF+0x08 as pvScan0
```

### PanBitBlt DDI Function Table Index

From the PAN driver function table at 0x1C032F7A8:
- PanEnablePDEV at DDI index 1
- PanEnableSurface at DDI index 4
- **PanBitBlt at DDI index 0x17 (23)**
- PanCopyBits at DDI index 0x0E (14)

`SURFACE::pfnBitBlt` reads from `PDEV+0xB10`. In a PAN-enabled PDEV, this slot contains PanBitBlt.

### Conclusion for Task 2

**EngModifySurface with non-NULL pvScan0 is ONLY reachable through Pan* functions.** The only three callers that pass non-NULL pvScan0 are:
1. `PANSURFLOCK::vLockBmpAndPrepareForPunt` (single-surface PAN)
2. `MULTIPANSURFLOCK::vLockBmp1AndPrepareForPunt` (multi-surface PAN, bitmap 1)
3. `MULTIPANSURFLOCK::vLockBmp2AndPrepareForPunt` (multi-surface PAN, bitmap 2)

All three are only called from the `MULTIPANSURFLOCK` constructor (0x1C0294214), which is only called from `PanBitBlt` (0x1C0294720). PanBitBlt is only dispatched from PAN-enabled PDEVs via `SURFACE::pfnBitBlt`.

**No other path to EngModifySurface with non-NULL pvScan0 exists in any of the four binaries.**

---

## Task 3: Can We Call EngModifySurface Directly via Syscall?

**NO.** There is no `NtGdiEngModifySurface` syscall.

Search results across all four binaries:
- win32kfull.sys: Only `EngModifySurface_0` (thunk, not a syscall)
- win32kbase.sys: Only `EngModifySurface` (engine function, not exported as syscall)
- win32k.sys: Only `EngModifySurface` (forwarder thunk)
- ntoskrnl.exe: Not present

No `NtGdi*` or `NtUser*` function calls `EngModifySurface` directly (except through the Pan* path). The only non-Pan code caller is `MulEnableSurface`, which passes `pvScan0=NULL`.

---

## Task 4: Can We Use NtGdiEngCreateDeviceSurface Instead?

### NtGdiEngCreateDeviceSurface (0x1C015D070)

```c
HSURF NtGdiEngCreateDeviceSurface(DHSURF dhsurf, SIZEL a2, int a3) {
    if (gUMPDSecurityLevel == 2                              // unrestricted
        || gUMPDSecurityLevel && bIsProcessLocalSystem()     // level 1 + LocalSystem
        || ValidUmpdSizl(a2, 0))                             // level 0 + valid size
    {
        if ((a3 - 1) <= 7)
            return EngCreateDeviceSurface(dhsurf, a2, a3 | 0x8000u);  // iType=1, adds 0x8000
    }
    return nullptr;
}
```

Creates `iType=1 (STYPE_DEVICE)` surfaces. Also adds 0x8000 to iFormat, so the 0x40000 flag is still set.

### MULTIPANSURFLOCK Handling of iType=1

```c
if (iType == 1) {
    // Replace surface with PANDEV shadow surface
    *a4 = *((SURFOBJ**)a2 + 8);  // shadow surface
    *a3 = *((SURFOBJ**)a2 + 8);
    *a7 = 1;
    // Lock shadow surfaces — NO EngModifySurface call
    MULTIPANSURFLOCK::vLockShadowW(this, a5, a8);
    MULTIPANSURFLOCK::bTryLockShadowR(this, a6, v18);
}
```

**iType=1 surfaces do NOT trigger EngModifySurface with pvScan0.** They use the shadow surface path, which replaces the surface with the PANDEV's pre-allocated shadow bitmap. No user-controlled pvScan0 is written.

### NtGdiEngAssociateSurface (0x1C015A6B0)

```c
__int64 NtGdiEngAssociateSurface(HSURF hsurf, HDEV a2, int a3) {
    v8 = HmgShareLockCheckIgnoreStockBit(hsurf, 5);
    if (v8) {
        if (*(DWORD*)(v8 + 112) & 0x40000) {  // requires 0x40000 flag (our bitmap has it)
            v10 = ValidUmpdHdev(a2);
            if (v10) {
                v11 = a3 & 0xFFFFB7EF;
                if ((v11 & 0xFFFC4A10) == 0 && ValidUmpdHooks(&v16, v11))
                    v6 = EngAssociateSurface(hsurf, v12, v11);  // calls EngAssociateSurface, NOT EngModifySurface
            }
        }
    }
}
```

**NtGdiEngAssociateSurface calls `EngAssociateSurface`, NOT `EngModifySurface`.**

### EngAssociateSurface (win32kbase.sys @ 0x1C00A3330)

```c
BOOL EngAssociateSurface(HSURF hsurf, HDEV hdev, FLONG flHooks) {
    v4 = flHooks & 0xFFFFB7EF;
    surf = HmgShareLockCheckIgnoreStockBit(hsurf, 5);
    if (surf) {
        if (*(DWORD*)(surf + 112) & 0x200000) {  // requires 0x200000 (our bitmap has it)
            *(QWORD*)(surf + 136) = 0;           // SURFACE+0x88 = 0
            *(QWORD*)(surf + 48) = hdev;          // SURFACE+0x30 = hdev  ← SETS HDEV
            *(QWORD*)(surf + 40) = *(QWORD*)(hdev + 225*8);  // SURFACE+0x28 = PDEV palette
            *(DWORD*)(surf + 112) |= v4;         // SURFACE+0x70 |= hooks (OR, never clears)
        }
    }
}
```

**EngAssociateSurface sets hdev but does NOT write pvScan0.** It OR's hooks into SURFACE+0x70 but never clears the 0x40000 flag.

### Conclusion for Task 4

- iType=1 surfaces do NOT trigger the EngModifySurface pvScan0 write path in PanBitBlt
- NtGdiEngAssociateSurface calls EngAssociateSurface (not EngModifySurface)
- EngAssociateSurface sets hdev but does NOT write pvScan0

---

## Task 5: Can We Modify the Bitmap's iType or Flags After Creation?

| Syscall | What It Does | Modifies SURFACE+0x70? | Modifies iType? |
|---------|-------------|----------------------|-----------------|
| `NtGdiSetBitmapAttributes` | Calls `GreMakeBitmapStock()` if bit 0 set | NO | NO |
| `NtGdiClearBitmapAttributes` | Calls `GreMakeBitmapNonStock()` | NO | NO |
| `NtGdiEngAssociateSurface` | OR's hooks into SURFACE+0x70, sets hdev | Only OR (adds) | NO |
| `NtGdiGetAndSetDCDword` | Modifies DC fields, not surface fields | NO | NO |

**There is no syscall that can:**
1. Clear the 0x40000 flag from SURFACE+0x70
2. Change iType from 3 to 0 or 1
3. Write to SURFACE+0x50 (pvScan0) directly

---

## Task 6 & 11: TOCTOU / Race Condition Approaches

### GDI Batch Buffer TOCTOU

The batch buffer TOCTOU can modify batch records between queuing and kernel flush. However:

1. **Batch records contain GDI operations (like PatBlt, BitBlt parameters), not SURFACE field modifications.** Modifying a batch record can change parameters of a GDI operation, but cannot directly write to a SURFACE's iType or pvScan0.

2. **In-flight BitBlt operations cannot be intercepted.** The batch buffer is processed atomically in kernel mode. Once the kernel starts processing a batch record, user-mode threads cannot modify the record.

3. **Surface handle swapping in batch records:** The TOCTOU can swap a bitmap handle in a batch record. However:
   - Swapping a normal bitmap handle with a device bitmap handle would cause the kernel to process the device bitmap through normal BitBlt (EngBitBlt), not PanBitBlt (since the PDEV is not PAN-enabled).
   - Even if the PDEV were PAN-enabled, the device bitmap would need to be the SOURCE surface, but batch BitBlt operations use DC-selected surfaces, and our device bitmap can't be selected.

### Delete + Realloc Race

Thread A selects normal bitmap, Thread B deletes it, hoping the device bitmap's SURFACE reuses the same memory:
- **Fails due to type isolation.** Normal bitmaps and device bitmaps are in different pool types. The freed normal bitmap's memory cannot be reused by a device bitmap allocation.

### iType Modification via TOCTOU

Cannot modify SURFACE+0x64 (iType) from user mode — it's in kernel memory. No GDI operation modifies iType after creation (except EngModifySurface which sets it to 0 as a side effect).

---

## Task 7: NtGdiBitBlt with Raw Parameters

### NtGdiBitBlt (0x1C0084DE0)

```c
__int64 NtGdiBitBlt(HDC a1, int a2, int a3, int a4, int a5, __int64 a6,
                    int a7, int a8, int a9, int a10, int a11) {
    return NtGdiBitBltInternal(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 & 0xFFFFFFFD);
}
```

**NtGdiBitBlt takes HDC handles, not raw surface handles.** It does not accept a source surface directly — it uses the source DC's currently selected bitmap. Since we can't select our device bitmap into a DC, we can't make it the BitBlt source through NtGdiBitBlt.

### NtGdiBitBltInternal (0x1C0088600)

The internal function:
1. Locks both DCs (destination and source)
2. Gets the destination surface from `DC+0x1F0` (selected bitmap)
3. Gets the source surface from `DC+0x1F0` (selected bitmap)
4. Calls `SURFACE::pfnBitBlt(dest_surface)` to get the BitBlt function pointer
5. If `dest_surface->flags & 1`: uses PDEV function table (PanBitBlt for PAN PDEVs)
6. Else: uses `EngBitBlt`

**The source surface comes from the source DC's selected bitmap. No way to pass a raw surface handle.**

---

## Task 8: NtGdiEngBitBlt with UMPD Registration

### gUMPDSecurityLevel = 0 (VERIFIED)

Read from win32kbase.sys at 0x1C0250208: **value = 0**.

This means **ANY process can register as UMPD** without requiring LocalSystem.

### NtGdiSetPUMPDOBJ (0x1C00A11D0) — UMPD Registration

```c
__int64 NtGdiSetPUMPDOBJ(__int64 a1, __int64 a2, QWORD *a3, DWORD *a4) {
    // Security check
    if (gUMPDSecurityLevel != 1          // level 0 → passes!
        || !v8
        || !bIsProcessLocalSystem(...)   // owner check
        || bIsProcessLocalSystem(...))   // current process check
    {
        // ... registration proceeds ...
    }
}
```

With `gUMPDSecurityLevel = 0`, the security check always passes. Any user-mode process can call `NtGdiSetPUMPDOBJ` to register as UMPD.

### NtGdiEngBitBlt (0x1C013B6A0) — UMPD BitBlt

```c
__int64 NtGdiEngBitBlt(SURFOBJ *a1, SURFOBJ *a2, XLATEOBJ *a3, CLIPOBJ *a4, ...) {
    ThreadCurrentObj = UMPDOBJ::GetThreadCurrentObj(...);
    if (!ThreadCurrentObj) return 0;     // must have UMPD registration

    // Wrap surfaces in UMPDSURFOBJ
    UMPDSURFOBJ(v48, a1, ThreadCurrentObj);   // target
    UMPDSURFOBJ(psoSrc, a2, ThreadCurrentObj); // source

    // Call EngBitBlt with the (unwrapped) surfaces
    v26 = EngBitBlt(psoTrg, v16, v17, pco, pxlo, v34, pptlSrc, ...);
}
```

**NtGdiEngBitBlt accepts raw SURFOBJ pointers and calls EngBitBlt.** This could pass our device bitmap as a source surface directly, bypassing the SelectObject restriction.

### Critical Limitation

`EngBitBlt` dispatches through the DESTINATION surface's PDEV function table via `SURFACE::pfnBitBlt`:

```c
// SURFACE::pfnBitBlt (0x1C00B9DA0)
if (*(DWORD*)this + 28) & 1)          // SURFACE+0x70 bit 0
    return *(func*)(*(QWORD*)(this + 6) + 2832);  // PDEV+0xB10
else
    return EngBitBlt;                  // default engine BitBlt
```

**Even with UMPD registration and NtGdiEngBitBlt, we still need:**
1. A destination surface with `SURFACE+0x70 & 1` set (bit 0 = driver-managed)
2. The PDEV at `PDEV+0xB10` to contain PanBitBlt
3. This only happens for PAN-enabled PDEVs

**The UMPD path does NOT bypass the PAN PDEV requirement.** It only bypasses the SelectObject restriction for the source surface.

### UMPD Driver PDEV Function Table

`UMPD_ldevFillTable` (0x1C011615C) fills the UMPD PDEV function table from `gpUMDriverFunc` — a table of UMPD wrapper functions that thunk to user mode. These are **NOT** PanBitBlt. The UMPD PDEV's BitBlt slot contains a UMPD wrapper, not PanBitBlt.

### Conclusion for Task 8

- **gUMPDSecurityLevel = 0** — any process can register as UMPD ✓
- NtGdiEngBitBlt can pass raw SURFOBJ pointers ✓
- BUT: EngBitBlt still dispatches through PDEV function table
- UMPD PDEVs have UMPD wrapper functions, NOT PanBitBlt
- **Still need a PAN-enabled PDEV to reach PanBitBlt**

---

## Task 9: Can We Create a Device Bitmap WITHOUT the 0x8000 Flag?

### NtGdiEngCreateDeviceBitmap (0x1C02B2310)

```c
HBITMAP NtGdiEngCreateDeviceBitmap(__int64 a1, struct tagSIZE a2) {
    if (ValidUmpdSizl(a2, 1) && (v2 - 1) <= 7)
        return EngCreateDeviceBitmap(v4, v3, v2 | 0x8000u);  // ALWAYS OR's 0x8000
    return nullptr;
}
```

**The 0x8000 flag is unconditionally OR'd into iFormat.** There is no parameter or flag to prevent it.

### EngCreateDeviceBitmap (win32kbase.sys @ 0x1C013F5B0)

```c
HBITMAP EngCreateDeviceBitmap(DHSURF dhsurf, SIZEL sizl, ULONG iFormatCompat) {
    return hbmCreateDriverSurface(3, dhsurf, sizl, 0, iFormatCompat, 0, (void*)0xDEADBEEF);
}
```

This is an engine function, not a syscall. It can only be called from kernel mode. From user mode, the only path is through `NtGdiEngCreateDeviceBitmap` which always adds 0x8000.

### CreateDriverSurfMem Flag Setup

```c
if (a2 == 3)   // iType == STYPE_DEVBITMAP
    *(DWORD*)(surf + 112) |= 0x400000;   // devbitmap flag
if (a2)        // iType != 0
    // Clear pvScan0, pjScan0, lDelta
*(DWORD*)(surf + 112) |= 0x200000;       // driver surface flag
if (a6 & 0x8000)  // iFormat has UMPD flag
    *(DWORD*)(surf + 112) |= 0x40000;    // UMPD flag → causes SelectObject failure
```

**Without the 0x8000 flag, the 0x40000 flag would NOT be set, and SelectObject would succeed.** But there is no user-mode way to create an iType=3 surface without 0x8000.

### Conclusion for Task 9

**Cannot create a device bitmap (iType=3) without the 0x8000 UMPD flag from user mode.** The syscall always adds it. The engine function is only callable from kernel mode.

---

## Task 10: Alternative Approach — No PAN Mode

### Can We Corrupt a Function Pointer Table?

To redirect a normal BitBlt to PanBitBlt, we'd need to:
1. Find the PDEV function table in kernel memory
2. Overwrite the BitBlt entry (PDEV+0xB10) with PanBitBlt's address

**This requires a kernel write primitive — which is exactly what we're trying to obtain.** Circular dependency.

### Can We Call PanBitBlt Directly?

PanBitBlt is at 0x1C0294720 in win32kfull.sys. It's a kernel function. There is no syscall that directly calls PanBitBlt. The only entry is through the PDEV function table dispatch.

### Can We Modify the PDEV Function Table?

PDEVs are kernel objects. No user-mode syscall modifies PDEV function table entries. The function table is set during `DrvEnablePDEV` / `PanEnablePDEV` and is read-only from user mode.

### Can We Use the TOCTOU to Corrupt iType?

Cannot modify SURFACE+0x64 (iType) from user mode. No GDI batch operation modifies iType after creation. The TOCTOU works on batch record parameters, not on kernel object fields.

### Conclusion for Task 10

**No alternative path to PanBitBlt exists without either:**
1. A PAN-enabled PDEV (requires display mode change)
2. A kernel write primitive (circular dependency)

---

## Task 12: Display Settings Fix — Making It Safe

### Previous Failure: CDS_RESET

The previous attempt used `ChangeDisplaySettingsExW` with `CDS_RESET`, which forces a full display reset:
1. Screen goes black (display off)
2. PDEV is destroyed
3. New PDEV is created (with PAN if CapabilityOverride is set)
4. Screen comes back on

This causes visible black/green flickering.

### Alternative Flag Combinations

| Flags | Behavior | PDEV Recreation? | Screen Impact |
|-------|----------|-----------------|---------------|
| CDS_RESET | Forces full reset | Yes | Black/green flicker |
| CDS_UPDATEREGISTRY \| CDS_NORESET | Saves to registry only | No | None (but no PAN PDEV) |
| CDS_UPDATEREGISTRY (no NORESET) | Saves + applies | Yes if mode differs | Mode change flicker |
| CDS_TEST | Tests mode support | No | None (but no PAN PDEV) |
| 0 (just apply) | Applies current registry settings | Yes if different | Mode change flicker |

### Key Problem

PDEV recreation is required to get a PAN-enabled PDEV. Any PDEV recreation causes visible screen disruption because:
1. The display driver's `DrvDisablePDEV` is called → display hardware reconfigured
2. `DrvEnablePDEV` (or `PanEnablePDEV`) is called → new PDEV with PAN function table
3. `DrvEnableSurface` is called → display surface recreated

On WDDM drivers (Windows 10/11), this always causes a brief display mode change visible to the user.

### Approaches That Don't Work

**a) CDS_NORESET + create DC:** Setting registry with CDS_NORESET does NOT create a new PDEV. Existing DCs use the old PDEV. No PAN PDEV is created.

**b) CDS_TEST:** Only tests mode support. Does NOT create a PDEV.

**c) Same resolution mode change:** Changing to the same resolution with PAN parameters still triggers PDEV recreation. The display driver still turns the screen off/on during PDEV recreation.

**d) Secondary display device:** Creating a secondary display adapter requires a driver. No user-mode mechanism exists to create a virtual display.

**e) Virtual display adapter:** Requires installing a virtual display driver (e.g., IddSampleDriver). This is a driver installation, not a user-mode operation.

### The Least Disruptive Approach (If Display Changes Were Allowed)

1. Set `CapabilityOverride` registry value to enable panning
2. Use `ChangeDisplaySettingsExW` with same resolution but different `dmPanningWidth`/`dmPanningHeight` (without CDS_RESET)
3. This triggers PDEV recreation with PAN mode
4. Perform the exploit
5. Restore original settings

However, this still causes a visible mode change. **There is no way to create a PAN PDEV without visible screen disruption.**

---

## Task 13: The KEY Question

### Constraints

1. **NO display settings changes** (causes screen issues)
2. **NO SelectObject** for device bitmaps (gle=6, blocked by 0x40000 flag)
3. **EngModifySurface** is the only pvScan0 writer
4. **EngModifySurface with non-NULL pvScan0** is only reachable via Pan* functions
5. **Pan* functions** are only dispatched from PAN-enabled PDEVs
6. **PAN-enabled PDEVs** require display mode changes

### Answer: NO

**There is NO way to get EngModifySurface called with controlled pvScan0 that:**
- Does NOT change display settings
- Does NOT require SelectObject on the device bitmap
- Is completely user-mode (no driver)
- Is traceless (no kernel modifications)

The dependency chain is unbreakable:

```
EngModifySurface(pvScan0 != NULL)
  ↑ only called from
PANSURFLOCK::vLockBmpAndPrepareForPunt / MULTIPANSURFLOCK::vLockBmp*
  ↑ only called from
MULTIPANSURFLOCK constructor
  ↑ only called from
PanBitBlt
  ↑ only dispatched from
PAN-enabled PDEV function table (PDEV+0xB10)
  ↑ only created by
PanEnablePDEV
  ↑ only called during
Display mode change (PDEV recreation)
  ↑ which requires
ChangeDisplaySettingsEx or equivalent → VISIBLE SCREEN IMPACT
```

### Alternative Approaches to Write pvScan0 to SURFACE+0x50

Since EngModifySurface is unreachable without display changes, we need **completely different vulnerability classes** to corrupt SURFACE+0x50:

#### A. Pool Overflow into Adjacent SURFACE

**Concept:** Overflow from an adjacent kernel pool allocation into a SURFACE's pvScan0 field at offset 0x50.

**Requirements:**
- Find a GDI object with a controllable heap buffer overflow
- The overflow must reach exactly SURFACE+0x50 (0x50 bytes from the start of the SURFACE)
- The SURFACE must be allocated in the same pool type as the overflowed object
- After corrupting pvScan0, use `NtGdiSetBitmapBits` on the bitmap to write through the fake pvScan0

**Feasibility:** Requires finding a new heap overflow vulnerability in GDI. This is a separate research effort.

#### B. Use-After-Free with Controlled Reallocation

**Concept:** Free a SURFACE, reallocate the same memory with controlled data that sets pvScan0 to our target address.

**Requirements:**
- Find a UAF in GDI surface management (e.g., race between DeleteObject and BitBlt)
- The freed SURFACE's pool allocation must be reused by a user-controlled allocation
- The user-controlled allocation must place our target address at offset 0x50

**Feasibility:** GDI UAFs exist but are increasingly rare due to type isolation. Would need specific vulnerability research.

#### C. Type Confusion

**Concept:** Make the kernel treat one GDI object type as a SURFACE, allowing writes to offset 0x50.

**Requirements:**
- Find a type confusion vulnerability in GDI handle management
- The confused type must allow controlled writes to offset 0x50

**Feasibility:** GDI type confusion is rare but not impossible. Would need specific vulnerability research.

#### D. Race Condition in Surface Creation

**Concept:** Race two threads creating/modifying surfaces to corrupt pvScan0.

**Requirements:**
- Find a race condition in GDI surface creation or modification
- The race must allow writing a controlled value to SURFACE+0x50

**Feasibility:** Requires specific vulnerability research.

#### E. CreateDIBSection + Arbitrary Kernel Address

**Concept:** CreateDIBSection creates a bitmap where pvScan0 points to user-mapped section memory. If we could map a section at a controlled kernel address...

**Requirements:**
- Map a section object at a controlled kernel address
- This is not possible from user mode without a kernel primitive

**Feasibility:** Not viable without an existing kernel primitive.

#### F. Registry-Only PAN PDEV (Speculative)

**Concept:** Set the `CapabilityOverride` registry value and trigger PDEV recreation through a non-display mechanism.

**Candidates for non-display PDEV recreation:**
- DPI change: `SetProcessDPIAware` / `SetThreadDpiAwarenessContext` — does NOT trigger PDEV recreation
- Workstation lock/unlock: triggers display reconfiguration — still causes screen change
- Session connect/disconnect: same as lock/unlock
- `EnumDisplayMonitors` / `EnumDisplayDevices`: read-only, no PDEV creation
- `NtUserCallOneParam` with specific parameters: no known parameter triggers PDEV recreation

**Feasibility:** No known non-display mechanism triggers PDEV recreation with PAN mode.

#### G. TOCTOU on Surface Handle During Batch Processing

**Concept:** Queue a batch operation with a normal bitmap, then swap the handle to our device bitmap before the batch is flushed.

**Problem:** Even if the swap succeeds, the kernel processes the device bitmap through `EngBitBlt` (not PanBitBlt) because the PDEV is not PAN-enabled. The MULTIPANSURFLOCK constructor is never called.

**Feasibility:** Does not help without a PAN PDEV.

---

## Summary of Findings

### SURFACE+0x50 (pvScan0) Write Analysis

| Method | Reachable Without Display Change? | Writes Controlled pvScan0? |
|--------|-----------------------------------|---------------------------|
| EngModifySurface via PanBitBlt | **NO** (needs PAN PDEV) | YES |
| EngModifySurface via MulEnableSurface | YES | NO (pvScan0=NULL) |
| EngModifySurface via PanEnableSurface | NO (needs PAN PDEV) | NO (pvScan0=NULL) |
| Direct NtGdiEngModifySurface syscall | **Does not exist** | N/A |
| CreateDriverSurfMem | YES | NO (sets pvScan0=0) |
| CreateDIBSection | YES | NO (user-mode address only) |
| Pool overflow | Unknown (needs vuln research) | Potentially YES |
| UAF + reallocation | Unknown (needs vuln research) | Potentially YES |

### SelectObject Failure Root Cause

The **0x40000 UMPD flag** at SURFACE+0x70 is the fundamental blocker. It is:
1. Set unconditionally by `NtGdiEngCreateDeviceBitmap` (always OR's 0x8000 into iFormat)
2. Causes `bIsSurfaceAllowedInDC` to fail for any display-PDEV DC
3. Cannot be cleared by any user-mode syscall

### gUMPDSecurityLevel = 0

Any process can register as UMPD via `NtGdiSetPUMPDOBJ`. This allows calling `NtGdiEngBitBlt` with raw SURFOBJ pointers, bypassing SelectObject. However, this does NOT bypass the PAN PDEV requirement — EngBitBlt still dispatches through the PDEV function table, and only PAN-enabled PDEVs have PanBitBlt.

### Recommended Next Steps

Since the EngModifySurface path is blocked without display changes, the exploit should pivot to one of these approaches:

1. **Pool overflow research:** Find a GDI heap overflow that can corrupt an adjacent SURFACE's pvScan0 (offset 0x50). Then use `NtGdiSetBitmapBits` to write through the corrupted pointer.

2. **UAF research:** Find a use-after-free in GDI surface management where a freed SURFACE's memory can be reallocated with controlled data at offset 0x50.

3. **Accept minimal display change:** If a very brief mode change (same resolution, no CDS_RESET) is acceptable, the PAN approach could work. The key is to avoid CDS_RESET and use a same-resolution mode change with PAN parameters. This would cause a brief flicker but not the sustained black/green screen seen with CDS_RESET.

4. **Alternative write primitive:** Look for other kernel write primitives that don't involve SURFACE+0x50 at all. For example, palette-based overflows, region-based overflows, or DC attribute overflows.

---

## Appendix: Key Function Addresses

| Function | Binary | Address | Description |
|----------|--------|---------|-------------|
| EngModifySurface | win32kbase.sys | 0x1C009B440 | Real implementation |
| EngModifySurface_0 | win32kfull.sys | 0x1C0165A60 | Thunk to win32kbase |
| EngModifySurface | win32k.sys | 0xFFFFF97FFF0041F0 | Forwarder thunk |
| NtGdiSelectBitmap | win32kfull.sys | 0x1C0100E90 | SelectObject syscall |
| hbmSelectBitmapInternal | win32kbase.sys | 0x1C00CA320 | Core selection logic |
| bIsSurfaceAllowedInDC | win32kbase.sys | 0x1C00CC650 | 0x40000 flag check |
| bIsCompatible | win32kbase.sys | 0x1C0029710 | iType/hdev compatibility |
| PanBitBlt | win32kfull.sys | 0x1C0294720 | PAN BitBlt dispatcher |
| PanEnablePDEV | win32kfull.sys | 0x1C0294B80 | PAN PDEV creation |
| PanEnableSurface | win32kfull.sys | 0x1C0294EC0 | PAN surface creation |
| MULTIPANSURFLOCK ctor | win32kfull.sys | 0x1C0294214 | PAN surface lock constructor |
| vLockBmpAndPrepareForPunt | win32kfull.sys | 0x1C0296804 | EngModifySurface caller (single) |
| vLockBmp1AndPrepareForPunt | win32kfull.sys | 0x1C0296658 | EngModifySurface caller (multi bmp1) |
| vLockBmp2AndPrepareForPunt | win32kfull.sys | 0x1C029672C | EngModifySurface caller (multi bmp2) |
| MulEnableSurface | win32kbase.sys | 0x1C0142080 | EngModifySurface (pvScan0=NULL) |
| NtGdiEngCreateDeviceBitmap | win32kfull.sys | 0x1C02B2310 | Device bitmap syscall |
| NtGdiEngCreateDeviceSurface | win32kfull.sys | 0x1C015D070 | Device surface syscall |
| NtGdiEngAssociateSurface | win32kfull.sys | 0x1C015A6B0 | Associate surface syscall |
| EngAssociateSurface | win32kbase.sys | 0x1C00A3330 | Engine associate (sets hdev) |
| CreateDriverSurfMem | win32kbase.sys | 0x1C00C9DBC | SURFACE creation + flag setup |
| SURFACE::pfnBitBlt | win32kfull.sys | 0x1C00B9DA0 | BitBlt function dispatch |
| NtGdiBitBlt | win32kfull.sys | 0x1C0084DE0 | BitBlt syscall |
| NtGdiBitBltInternal | win32kfull.sys | 0x1C0088600 | BitBlt internal impl |
| NtGdiEngBitBlt | win32kfull.sys | 0x1C013B6A0 | UMPD BitBlt syscall |
| NtGdiSetPUMPDOBJ | win32kfull.sys | 0x1C00A11D0 | UMPD registration syscall |
| NtGdiSetBitmapAttributes | win32kfull.sys | 0x1C00A9770 | Bitmap attributes (stock only) |
| NtGdiClearBitmapAttributes | win32kfull.sys | 0x1C0125420 | Bitmap attributes (stock only) |
| gUMPDSecurityLevel | win32kbase.sys | 0x1C0250208 | Value = 0 (any process) |

## Appendix: DHSURF Fake Structure for PANSURFLOCK

```
Offset  Size  Field           Required Value
------  ----  -----           --------------
0x00    8     surf_obj        surface object pointer (from EngLockSurface)
0x08    8     pvScan0         TARGET ADDRESS (written to SURFACE+0x50)
0x10    4     lDelta          scan line stride (non-zero, e.g. 0x1000)
0x14    4     punt_count      MUST BE 0 (EngModifySurface only fires if 0)
0x18    8     unk_18          (padding/unused)
0x20    8     pdev_ptr        → fake PDEV structure
              pdev_ptr+0x30   hdev (HDEV, must be valid and non-NULL)
```

## Appendix: EngModifySurface Validation Checklist

For the pvScan0 write path (Path B) to succeed:

| # | Condition | Our Bitmap | PANSURFLOCK Call |
|---|-----------|------------|------------------|
| 1 | hdev != NULL | N/A (caller provides) | From DHSURF+0x20→PDEV+0x30 |
| 2 | Surface lockable | Yes (valid HBITMAP) | Yes |
| 3 | pvReserved == NULL | N/A | NULL ✓ |
| 4 | (flSurface & 0xFFFFFFF0) == 0 | N/A | flSurface=0 ✓ |
| 5 | (flags & 0x400000) != 0 OR iType==1 | 0x640000 has 0x400000 ✓ | ✓ |
| 6 | existing hdev is NULL or matches | hdev=NULL ✓ | ✓ |
| 7 | pvScan0 != NULL AND lDelta != 0 | N/A | From DHSURF (controlled) ✓ |
| 8 | (flHooks & 0x1000) != 0 OR (flSurface & 1)==0 | N/A | flHooks=0, flSurface=0 → ✓ |
| 9 | All checks passed (v14 = TRUE) | ✓ | ✓ |

All conditions are satisfiable through the PANSURFLOCK path. The ONLY barrier is reaching PANSURFLOCK, which requires a PAN-enabled PDEV.
