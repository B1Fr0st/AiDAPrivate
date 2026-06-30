# PAN Mode Exploit Fix Analysis

## Problem 1: ChangeDisplaySettingsEx returned DISP_CHANGE_BADMODE (-2)

### Root Cause
`xxxUserChangeDisplaySettings` (win32kfull.sys @ 0x1C0019180) validates `dmSize`:
```c
v42 = a2[34];  // dmSize (WORD at DEVMODEW offset 68)
if ( (unsigned __int16)(v42 - 188) > 0x20u )  // must be [188, 220]
{
    v41 = -2;  // DISP_CHANGE_BADMODE
    goto LABEL_55;
}
```
sizeof(DEVMODEW) = 220 = 0xDC, which passes (220 - 188 = 32 = 0x20, and 0x20 > 0x20 is FALSE).

The actual -2 comes from deeper in the call chain: `xxxUserChangeDisplaySettingsInternal` → `DrvChangeDisplaySettings` → `DrvChangeDisplaySettingsInternal` → `DrvSetDisplayConfig`. The mode 1536x864 with only `DM_PELSWIDTH | DM_PELSHEIGHT` set is rejected by the display driver because:
1. The resolution may not match any supported mode
2. Missing fields (DM_BITSPERPEL, DM_DISPLAYFREQUENCY) cause mode matching failure
3. CDS_UPDATEREGISTRY requires the mode to be validated against the driver's mode list

### Fix
1. Use `EnumDisplaySettingsExW(ENUM_CURRENT_SETTINGS)` to get the EXACT current display mode
2. Pass the current mode back with `CDS_RESET` (0x40000000) to force PDEV recreation without changing the mode
3. Include all relevant fields: `DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL | DM_DISPLAYFREQUENCY`
4. Fallbacks:
   - `CDS_RESET | CDS_UPDATEREGISTRY` (force reset + update registry)
   - `ChangeDisplaySettingsExW(NULL, NULL, NULL, CDS_RESET, NULL)` (global reset)
   - `flags=0` (dynamic mode change without registry update)

### Key Functions Analyzed
- `NtUserChangeDisplaySettings` @ 0x1C0018E30: Entry point, checks flags, calls xxxUserChangeDisplaySettings
- `xxxUserChangeDisplaySettings` @ 0x1C0019180: Validates dmSize [188,220], copies DEVMODE, calls Internal
- `xxxUserChangeDisplaySettingsInternal` @ 0x1C00198CC: Flag validation, calls DrvChangeDisplaySettings
- `DrvChangeDisplaySettings` @ 0x1C0019E30: Calls DrvChangeDisplaySettingsInternal or DrvSetDisplayConfig

---

## Problem 2: SelectObject(hdcMem, hBitmap) failed

### Root Cause
`hbmSelectBitmapInternal` (win32kbase.sys @ 0x1C00CA320) calls `bIsCompatible` (win32kbase.sys @ 0x1C0029710):

```c
// bIsCompatible check:
if ( (*(_WORD *)(a3 + 100) || *(_QWORD *)(a3 + 24)) && *(_QWORD *)(a3 + 48) != a4 )
    return 0;  // NOT compatible
```

Where:
- `a3 + 100` = SURFACE iType (WORD) — device bitmap has iType=3 (STYPE_DEVBITMAP)
- `a3 + 24` = SURFOBJ.dhsurf (QWORD) — device bitmap has our fake DHSURF pointer (non-NULL)
- `a3 + 48` = SURFOBJ.hdev (QWORD) — device bitmap has hdev=NULL (set by EngCreateDeviceBitmap)
- `a4` = DC's hdev — memory DC created with CreateCompatibleDC(hdcDisplay) has the display's hdev (non-NULL)

Evaluation: `(3 != 0 || fake_ptr != NULL) && (NULL != display_hdev)` = `TRUE && TRUE` = `TRUE` → returns 0 (incompatible)

The device bitmap created by `NtGdiEngCreateDeviceBitmap` (@ 0x1C02B2310) has:
- iType = 3 (STYPE_DEVBITMAP)
- dhsurf = user-supplied pointer (our fake DHSURF)
- hdev = NULL (not set by EngCreateDeviceBitmap)
- flags = 0x8000 (HOOK_BITMAP) | other flags = 0x640000

The memory DC's hdev is the display device's hdev (non-NULL). Since NULL != display_hdev, bIsCompatible returns 0.

### NtGdiSelectBitmap Analysis
`NtGdiSelectBitmap` (win32kfull.sys @ 0x1C0100E90):
```c
v4 = *(unsigned __int16 *)(v8[0] + 12LL);  // DC type at offset 12
if ( (unsigned __int16)v4 <= 1u )  // allows types 0 (memory) and 1 (info), rejects 2 (display)
{
    v3 = hbmSelectBitmapInternal(v8, a2, 0, 0, 0);  // always passes a3=0, a4=0, a5=0
}
```
- DC type 0 (memory) and 1 (info) are allowed
- DC type 2 (display) is rejected
- Display DCs cannot be used for SelectBitmap

### NtGdiEngBitBlt Analysis
`NtGdiEngBitBlt` (win32kfull.sys @ 0x1C013B6A0) requires UMPD registration:
```c
ThreadCurrentObj = UMPDOBJ::GetThreadCurrentObj(ThreadWin32Thread);
if ( !ThreadCurrentObj )
    return 0;  // fails without UMPD registration
```
Not viable without UMPD registration.

### Fix: Metafile DC Approach
Use `CreateMetaFileW(NULL)` to create a metafile DC. The metafile DC:
- Has DC type 0 or 1 (memory DC) → passes NtGdiSelectBitmap check
- Has hdev=NULL (not associated with any display device) → passes bIsCompatible check

With both surface.hdev=NULL and dc.hdev=NULL:
```
(iType=3 || dhsurf!=NULL) && (NULL != NULL) = TRUE && FALSE = FALSE → compatible!
```

SelectObject succeeds, and the device bitmap becomes the metafile DC's selected surface.

Then `BitBlt(hdcDisplay, ..., hdcMeta, ..., SRCCOPY)`:
- hdcDisplay = DESTINATION (PAN PDEV → PanBitBlt in function table)
- hdcMeta = SOURCE (device bitmap with iType=3)

Flow:
1. NtGdiBitBlt → NtGdiBitBltInternal
2. Source SURFOBJ = metafile DC's surface = device bitmap (iType=3)
3. Destination SURFOBJ = display DC's surface (iType=1)
4. SURFACE::pfnBitBlt gets PanBitBlt from display DC's PAN PDEV
5. PanBitBlt(@0x1C0294720) receives both SURFOBJs
6. PanBitBlt gets dhpdev from iType==1 surface (display DC)
7. MULTIPANSURFLOCK(@0x1C0294214) constructor checks both surfaces:
   - v16 (lower ptr) checked first, v15 (higher ptr) checked second
   - For iType==3: calls vLockBmp1/vLockBmp2AndPrepareForPunt
   - For iType==1: takes shadow path
8. vLockBmp2AndPrepareForPunt(@0x1C029672C) calls EngModifySurface:
   ```c
   EngModifySurface(
       HSURF,           // device bitmap's surface handle
       HDEV,            // from PANDEV+0x30 → HDEV+48
       0,               // flHook = 0 (may clear hooks)
       0,               // flAttrs = 0
       dhsurf,          // our fake DHSURF
       pvScan0,         // DHSURF+0x08 = our target kernel address
       lDelta,          // DHSURF+0x10 = our controlled lDelta
       nullptr);
   ```
9. EngModifySurface writes pvScan0 to the device bitmap's SURFACE

### Key Structures
- SURFACE: base structure containing SURFOBJ at offset 0x18 (24)
- SURFACE+24 = SURFOBJ.dhsurf
- SURFACE+32 = SURFOBJ.hsurf
- SURFACE+40 = SURFOBJ.dhpdev
- SURFACE+48 = SURFOBJ.hdev
- SURFACE+56 = SURFOBJ.sizlBitmap.cx
- SURFACE+60 = SURFOBJ.sizlBitmap.cy
- SURFACE+96 = SURFOBJ.iBitmapFormat
- SURFACE+100 = SURFOBJ.iType (WORD)
- SURFACE+112 = SURFACE flags (DWORD)
- SURFACE+128 = SURFACE.hdevShare (QWORD, used by bIsCompatible as a2)

### MULTIPANSURFLOCK Constructor Details
```
@0x1C0294214 (win32kfull.sys)

Parameters: PANDEV*, &psoTrg, &psoSrc, prclTrg, prclSrc, &flag, pco

1. Orders surfaces by pointer value: v16=min(src,dst), v15=max(src,dst)
2. If v16==v15 (self-blit):
   - iType==3: vLockBmp1AndPrepareForPunt(this, 0)
   - iType==1: shadow path (vLockShadowW + bTryLockShadowR)
3. If v16!=v15 (different surfaces):
   - Check v16->iType:
     - 3: vLockBmp1AndPrepareForPunt(this, v16==src)
     - 1: shadow path
   - Check v15->iType:
     - 3: vLockBmp2AndPrepareForPunt(this, v15==src)
     - 1: shadow path
```

---

## Problem 3: GetBitmapBits returned 0 with gle=6

### Root Cause
`GreGetBitmapBits` (win32kfull.sys @ 0x1C00183C4) checks:
```c
if ( v34 && (*(_DWORD *)(v34 + 112) & 0x4000000) != 0 )
{
    // Process bitmap (iType==3 uses EngCopyBits, iType==0 uses bDoGetSetBitmapBits)
    ...
}
EngSetLastError(6u);  // ERROR_INVALID_HANDLE
return 0;
```

The device bitmap has SURFACE+112 flags = 0x640000. 
0x640000 & 0x4000000 = 0x00640000 & 0x04000000 = 0 → check fails → returns 0 with gle=6.

The 0x4000000 flag is separate from the 0x400000 flag:
- 0x400000: present in 0x640000 (used by EngModifySurface validation)
- 0x4000000: NOT present in 0x640000 (required by GreGetBitmapBits)

### iType==3 Path in GreGetBitmapBits
If the 0x4000000 check passes and iType==3:
```c
if ( *(_WORD *)(v34 + 100) == 3 )  // iType == 3
{
    // Create a temporary DIB
    SURFMEM::bCreateDIB(&dib, &bitmapInfo, ...)
    // Copy from device bitmap to DIB using EngCopyBits
    EngCopyBits(dib, deviceBitmap, NULL, NULL, &prclDest, &pptlSrc)
}
// Then copy from DIB to user buffer via bDoGetSetBitmapBits
bDoGetSetBitmapBits(&userBuf, &dib, 1)
```

This path uses EngCopyBits, which reads from the device bitmap's pvScan0. After EngModifySurface sets pvScan0 to our target address, EngCopyBits would read from the target.

### bDoGetSetBitmapBits Analysis
`bDoGetSetBitmapBits` (win32kfull.sys @ 0x1C0018BA4):
```c
if ( !a3 )  // reading (GetBitmapBits)
{
    pvScan0 = (char *)a1->pvScan0;  // directly uses pvScan0
    lDelta = a1->lDelta;
    // ... memmove from pvScan0 to pvBits
}
```
Directly reads from pvScan0. But this is only called after the 0x4000000 check passes.

### Fix: DIB+BitBlt Fallback
If GetBitmapBits fails (0x4000000 not set), use an alternative approach:
1. Create a DIB section: `CreateDIBSection(NULL, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0)`
2. Select DIB into a memory DC: `CreateCompatibleDC(NULL)` + `SelectObject`
3. Read: `BitBlt(hdcDib, 0, 0, w, h, hdcMeta, 0, 0, SRCCOPY)`
   - hdcDib = DESTINATION (DIB memory DC, normal PDEV)
   - hdcMeta = SOURCE (metafile DC with exploited device bitmap)
   - EngBitBlt reads from source.pvScan0 (target kernel address) and writes to dest.pvScan0 (DIB)
   - Read DIB bits from pBits (user-mode pointer)
4. Write: `BitBlt(hdcMeta, 0, 0, w, h, hdcDib, 0, 0, SRCCOPY)`
   - hdcMeta = DESTINATION (exploited device bitmap)
   - hdcDib = SOURCE (DIB with write data)
   - EngBitBlt reads from source.pvScan0 (DIB) and writes to dest.pvScan0 (target)
   - After EngModifySurface with flHook=0, surface hooks are cleared
   - SURFACE::pfnBitBlt returns EngBitBlt (not PDEV function) for non-hooked surfaces

This bypasses the 0x4000000 flag check entirely because we're not using Get/SetBitmapBits. Instead, we use BitBlt which calls EngBitBlt directly, and EngBitBlt accesses pvScan0 without checking the 0x4000000 flag.

---

## Summary of Changes

### Problem 1 Fix: Display Mode Change
- **Before**: `ChangeDisplaySettingsExW(L"\\\\.\\DISPLAY1", &dm, NULL, CDS_UPDATEREGISTRY, NULL)` with hardcoded 1536x864
- **After**: `EnumDisplaySettingsExW(ENUM_CURRENT_SETTINGS)` to get current mode, then `CDS_RESET` with all dmFields
- **Fallbacks**: CDS_RESET|CDS_UPDATEREGISTRY, global reset (NULL,NULL,NULL,CDS_RESET), flags=0

### Problem 2 Fix: BitBlt Trigger
- **Before**: `CreateCompatibleDC(hdcDisplay)` → `SelectObject(hdcMem, hBitmap)` → FAILS (bIsCompatible hdev mismatch)
- **After**: `CreateMetaFileW(NULL)` → `SelectObject(hdcMeta, hBitmap)` → SUCCESS (metafile DC hdev=NULL)
- **BitBlt**: `BitBlt(hdcDisplay, ..., hdcMeta, ..., SRCCOPY)` — display DC as dest (PanBitBlt), metafile DC as src (iType=3)

### Problem 3 Fix: GetBitmapBits
- **Before**: `GetBitmapBits(hBitmap, 8, buf)` → returns 0, gle=6 (0x4000000 flag not set)
- **After**: Try GetBitmapBits first. If it fails, use DIB+BitBlt fallback:
  - Create DIB section, BitBlt from metafile DC to DIB (reading via EngBitBlt/pvScan0)
  - BitBlt from DIB to metafile DC (writing via EngBitBlt/pvScan0)

## Files Changed
1. `C:\Users\ruar1337\AiDAPrivate\driver\win32k_uaf_exploit.cpp` — Updated exploit code
2. `C:\Users\ruar1337\AiDAPrivate\driver\analysis\pan_fix.md` — This analysis document
