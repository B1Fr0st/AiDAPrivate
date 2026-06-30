# UMPD Path Analysis: EngModifySurface pvScan0 Write Primitive

## Target Function

**EngModifySurface** @ `0x1C009B440` (win32kbase.sys)

This is the ONLY function that writes a user-controllable pvScan0 to `SURFACE+0x50`.

### EngModifySurface Prototype

```c
BOOL __stdcall EngModifySurface(
    HSURF hsurf,        // rcx - surface handle
    HDEV hdev,          // rdx - device handle
    FLONG flHooks,      // r8d - hook flags
    FLONG flSurface,    // r9d - surface flags
    DHSURF dhsurf,      // stack - device surface handle
    PVOID pvScan0,      // stack - THE CRITICAL PARAMETER
    LONG lDelta,        // stack - scan line stride
    PVOID pvReserved    // stack - reserved (must be nullptr)
);
```

### Critical Write Path in EngModifySurface

When `pvScan0 != nullptr` AND `lDelta != 0`, and the validation checks pass:

```c
// At 0x1c010777f:
*(_QWORD *)(SURFACE + 0x50) = pvScan0;     // PRIMARY WRITE TARGET
*(_DWORD *)(SURFACE + 0x58) = lDelta;      // stride
*(_WORD  *)(SURFACE + 0x64) = 0;           // iType = STYPE_BITMAP (0)

if (lDelta > 0) {
    *(_QWORD *)(SURFACE + 0x48) = pvScan0;  // alt pvScan0
    *(_WORD  *)(SURFACE + 0x66) |= 1;       // top-down flag
} else {
    *(_QWORD *)(SURFACE + 0x48) = (char*)pvScan0 + lDelta * (height - 1);  // bottom-up
    *(_WORD  *)(SURFACE + 0x66) &= ~1;
}
```

When `pvScan0 == nullptr` OR `lDelta == 0`, the function takes a DIFFERENT branch that does NOT write pvScan0 to SURFACE+0x50. Instead it only sets dhsurf, hooks, and flags.

### Write Condition Logic

The write to SURFACE+0x50 requires ALL of:
1. `pvScan0 != 0` AND `lDelta != 0`
2. `(flHooks & 0x1000) != 0` OR `(flSurface & 1) == 0` (either condition)
3. Surface validation passes (v14 = true):
   - `hdev != nullptr`
   - Surface lock succeeds via `HmgShareLockIgnoreStockBit(hsurf)`
   - `(flSurface & 0xFFFFFFF0) == 0`
   - Surface has `0x400000` flag OR `iType == 1` (STYPE_DEVICE)
   - Existing HDEV matches or is null
   - If surface is UMPD (`flHooks < 0`), hook/HDEV consistency checks

---

## Step 1: All Callers of EngModifySurface

### win32kbase.sys (definition site)

| Caller | Address | pvScan0 | lDelta | Path |
|--------|---------|---------|--------|------|
| `MulEnableSurface` | `0x1c0142080` | **nullptr** | 0 | Null branch (NO pvScan0 write) |

Only 1 code xref in win32kbase.sys. 3 data xrefs (export table / dispatch table entries at `0x1c02385ac`, `0x1c0249df8`, `0x1c02612a4` — no further code refs to these).

### win32kfull.sys (via IAT import at `0x1c03649b8`)

7 code callers found:

| # | Caller | Address | pvScan0 | lDelta | Writes to SURFACE+0x50? |
|---|--------|---------|---------|--------|--------------------------|
| 1 | `PanEnableSurface` | `0x1c0294ec0` | **nullptr** | 0 | NO (null branch) |
| 2 | `MulCreateDeviceBitmapEx` | `0x1c02a2420` | **nullptr** | 0 | NO (null branch) |
| 3 | `PANSURFLOCK::vLockBmpAndPrepareForPunt` | `0x1c0296804` | `*(dhsurf+0x08)` | `*(dhsurf+0x10)` | **YES** (if validation passes) |
| 4 | `MULTIPANSURFLOCK::vLockBmp1AndPrepareForPunt` | `0x1c0296658` | `*(dhsurf+0x08)` | `*(dhsurf+0x10)` | **YES** (if validation passes) |
| 5 | `MULTIPANSURFLOCK::vLockBmp2AndPrepareForPunt` | `0x1c029672c` | `*(dhsurf+0x08)` | `*(dhsurf+0x10)` | **YES** (if validation passes) |
| 6 | `MULTIPANSURFLOCK::vUnLockBmp1AndRemovePunt` | `0x1c0296f68` | **nullptr** | 0 | NO (null branch, restores surface) |
| 7 | `MULTIPANSURFLOCK::vUnLockBmp2AndRemovePunt` | `0x1c0297024` | **nullptr** | 0 | NO (null branch, restores surface) |

Plus 1 thunk: `EngModifySurface_0` @ `0x1c0165a60` — only data refs (dispatch tables at `0x1c032f648`, `0x1c034e824`), no direct code callers.

### Summary

Only **3 callers** pass a non-null pvScan0: the PANSURFLOCK/MULTIPANSURFLOCK "prepare for punt" functions. All other callers pass `pvScan0 = nullptr`, which takes the null branch and does NOT write to SURFACE+0x50.

---

## Step 2: pvScan0 Source Analysis

### PANSURFLOCK::vLockBmpAndPrepareForPunt (0x1c0296804)

```c
void __fastcall PANSURFLOCK::vLockBmpAndPrepareForPunt(__int64 **this)
{
    // this[0] = SURFOBJ pointer (set by PANSURFLOCK constructor)
    v2 = (__int64 *)**this;        // v2 = *(SURFOBJ) = SURFOBJ.dhsurf (first field)
    *(this + 1) = v2;              // store dhsurf
    EngAcquireSemaphore(*(HSEMAPHORE *)(v2[4] + 776));  // lock: *(dhsurf+0x20)+0x308
    
    dhsurf = (DHSURF)*(this + 1);  // dhsurf = SURFOBJ.dhsurf
    if (!*((_DWORD *)dhsurf + 5))  // if *(dhsurf+0x14) == 0 (refcount check)
    {
        EngModifySurface(
            (HSURF)(*this)[1],                        // hsurf = SURFOBJ.hsurf
            *(HDEV *)(*((_QWORD *)dhsurf + 4) + 48),  // hdev = *(*(dhsurf+0x20) + 0x30)
            0,                                         // flHooks = 0
            0,                                         // flSurface = 0
            dhsurf,                                    // dhsurf
            *((PVOID *)dhsurf + 1),                   // pvScan0 = *(dhsurf+0x08)  <-- KEY
            *((_DWORD *)dhsurf + 4),                  // lDelta = *(dhsurf+0x10)   <-- KEY
            nullptr);                                  // pvReserved = nullptr
    }
    ++*((_DWORD *)dhsurf + 5);  // increment refcount at dhsurf+0x14
    // ...
}
```

### DHSURF Structure Layout (as read by PANSURFLOCK)

| Offset | Type | Field | Role in EngModifySurface call |
|--------|------|-------|-------------------------------|
| +0x00 | QWORD | dhsurf (self) | Passed as dhsurf parameter |
| +0x08 | PVOID | **pvScan0** | Passed as pvScan0 → written to SURFACE+0x50 |
| +0x10 | LONG | **lDelta** | Passed as lDelta → written to SURFACE+0x58 |
| +0x14 | DWORD | refcount | Must be 0 for EngModifySurface to be called |
| +0x20 | QWORD | HDEV ptr | Dereferenced at +0x30 to get HDEV |

### MULTIPANSURFLOCK variants

`vLockBmp1AndPrepareForPunt` (0x1c0296658) and `vLockBmp2AndPrepareForPunt` (0x1c029672c) use the identical pattern — they read pvScan0 from `*(dhsurf+0x08)` and lDelta from `*(dhsurf+0x10)` and pass them to EngModifySurface.

---

## Step 3: NtGdiEng* Syscall Inventory (win32kfull.sys)

31 NtGdiEng* syscalls found:

| Category | Functions |
|----------|-----------|
| **Surface creation** | NtGdiEngCreateBitmap, NtGdiEngCreateDeviceSurface, NtGdiEngCreateDeviceBitmap, NtGdiEngCreatePalette, NtGdiEngCreateClip |
| **Surface management** | NtGdiEngAssociateSurface, NtGdiEngLockSurface, NtGdiEngUnlockSurface, NtGdiEngDeleteSurface, NtGdiEngEraseSurface, NtGdiEngMarkBandingSurface |
| **Rendering (bitmap)** | NtGdiEngBitBlt, NtGdiEngCopyBits, NtGdiEngStretchBlt, NtGdiEngStretchBltROP, NtGdiEngAlphaBlend, NtGdiEngTransparentBlt, NtGdiEngPlgBlt |
| **Rendering (vector)** | NtGdiEngLineTo, NtGdiEngFillPath, NtGdiEngStrokePath, NtGdiEngStrokeAndFillPath, NtGdiEngGradientFill |
| **Rendering (text)** | NtGdiEngTextOut |
| **Misc** | NtGdiEngPaint, NtGdiEngCheckAbort, NtGdiEngComputeGlyphSet, NtGdiEngDeleteClip, NtGdiEngDeletePalette, NtGdiEngDeletePath |

---

## Step 4: NtGdiEng* → EngModifySurface Call Chain Analysis

### Direct callee analysis

NtGdiEng* syscalls do NOT directly call EngModifySurface. They call the Eng* engine functions:

```
NtGdiEngBitBlt    → EngBitBlt    (0x1c00cb280)
NtGdiEngStretchBlt → EngStretchBlt → EngStretchBltNew
NtGdiEngAlphaBlend → EngAlphaBlend (0x1c00aca60)
```

The Eng* functions dispatch to driver DDI callbacks through indirect function pointer tables (DRVENABLEDATA dispatch). This is why static callgraph analysis doesn't show the Pan* functions as callees — the calls are indirect.

### Indirect dispatch path to EngModifySurface

```
NtGdiEngBitBlt
  → EngBitBlt
    → [DDI dispatch: DrvBitBlt function pointer]
      → PanBitBlt (if surface is on PAN-enabled PDEV)
        → MULTIPANSURFLOCK constructor
          → vLockBmp1/vLockBmp2AndPrepareForPunt (if surface iType == 3/STYPE_BITMAP)
            → EngModifySurface(pvScan0 = *(dhsurf+0x08))
              → writes pvScan0 to SURFACE+0x50
```

### Pan* function → PANSURFLOCK mapping

| Pan* function | Constructor used | PANSURFLOCK type |
|---------------|------------------|------------------|
| PanBitBlt | MULTIPANSURFLOCK | Locks bmp1 + bmp2 |
| PanStretchBlt | MULTIPANSURFLOCK | Locks bmp1 + bmp2 |
| PanAlphaBlend | MULTIPANSURFLOCK | Locks bmp1 + bmp2 |
| PanTransparentBlt | MULTIPANSURFLOCK | Locks bmp1 + bmp2 |
| PanGradientFill | PANSURFLOCK | Locks single bmp |
| PanStrokePath | PANSURFLOCK | Locks single bmp |
| PanStrokeAndFillPath | PANSURFLOCK | Locks single bmp |
| PanTextOut | PANSURFLOCK | Locks single bmp |

---

## Step 5: pvScan0 User-Controllability Trace

### The DHSURF Supply Chain

1. **NtGdiEngCreateDeviceBitmap** (`0x1c02b2310`, win32kfull.sys):
   ```asm
   ; Parameters: rcx=dhsurf, rdx=sizl, r8=iFormatCompat
   mov r10, rcx         ; save user-supplied dhsurf
   mov r9, rdx          ; save sizl
   call ValidUmpdSizl   ; validate size only
   ; NO UMPD object check
   ; NO gUMPDSecurityLevel check
   mov rcx, r10         ; dhsurf = user value
   call EngCreateDeviceBitmap
   ```
   
   **CRITICAL**: This syscall has NO UMPD registration check and NO security level check. It only validates the bitmap size via `ValidUmpdSizl`. Any process that can make this win32k syscall can create a device bitmap with an arbitrary DHSURF value.

2. **EngCreateDeviceBitmap** (`0x1c013f5b0`, win32kbase.sys):
   ```c
   HBITMAP EngCreateDeviceBitmap(DHSURF dhsurf, SIZEL sizl, ULONG iFormatCompat)
   {
       return hbmCreateDriverSurface(3, dhsurf, sizl, 0, iFormatCompat | 0x8000, 0, 0xDEADBEEF);
       //                                    ^^  iType = STYPE_BITMAP (3)
       //                                         ^^ user dhsurf stored in SURFACE
   }
   ```

3. The resulting SURFACE has:
   - `iType = STYPE_BITMAP (3)` at SURFACE+0x64
   - `dhsurf = user-supplied value` at SURFACE+0x18
   - `0x8000` flag set in format (UMPD marker)

4. **NtGdiEngCreateDeviceSurface** (`0x1c015d070`, win32kfull.sys):
   ```c
   HSURF NtGdiEngCreateDeviceSurface(DHSURF dhsurf, SIZEL sizl, int format)
   {
       if (gUMPDSecurityLevel == 2
           || (gUMPDSecurityLevel && bIsProcessLocalSystem(...))
           || ValidUmpdSizl(sizl, 0))  // <-- OR condition: size check bypasses security
       {
           return EngCreateDeviceSurface(dhsurf, sizl, format | 0x8000);
       }
       return nullptr;
   }
   ```
   
   The `ValidUmpdSizl` OR branch means the security level check is bypassed when the size is valid. However, this creates `iType = STYPE_DEVICE (1)`, which takes the shadow bitmap path in PANSURFLOCK (not the EngModifySurface path).

### The PANSURFLOCK trigger condition

In the PANSURFLOCK/MULTIPANSURFLOCK constructors:

```c
// PANSURFLOCK constructor (0x1c029440c):
iType = (*a3)->iType;
if (iType == 3)          // STYPE_BITMAP
{
    *this = *a3;          // store SURFOBJ
    vLockBmpAndPrepareForPunt(this);  // → EngModifySurface with *(dhsurf+0x08)
}
else if (iType == 1)     // STYPE_DEVICE
{
    // Shadow bitmap path — does NOT call EngModifySurface with pvScan0
}
```

**Only `iType == 3` (STYPE_BITMAP) surfaces trigger the EngModifySurface write path.** This means:
- `NtGdiEngCreateDeviceBitmap` (creates iType=3) → **CAN trigger the write**
- `NtGdiEngCreateDeviceSurface` (creates iType=1) → takes shadow path, NO write

### Full exploit chain

```
1. Attacker allocates user-mode buffer:
   buffer+0x08 = desired pvScan0 value (target address for write primitive)
   buffer+0x10 = non-zero lDelta (e.g., 1)
   buffer+0x14 = 0 (refcount, must be 0)
   buffer+0x20 = pointer to fake HDEV structure
   fake_hdev+0x30 = valid HDEV (from a display DC)

2. Attacker calls NtGdiEngCreateDeviceBitmap(
       dhsurf = buffer,        // user-controlled DHSURF
       sizl = {1, 1},          // minimal valid size
       iFormatCompat = 1       // BMF_1BPP (1-8 valid)
   )
   → Returns HBITMAP with iType=3, SURFACE.dhsurf = user buffer

3. Attacker performs GDI BitBlt:
   - Destination DC: display DC with PAN-enabled PDEV
   - Source: the UMPD device bitmap (HBITMAP from step 2)
   
   BitBlt → EngBitBlt → DrvBitBlt dispatch → PanBitBlt
   → MULTIPANSURFLOCK constructor sees source iType == 3
   → vLockBmp2AndPrepareForPunt
   → reads dhsurf from SURFOBJ.dhsurf (= user buffer)
   → reads pvScan0 = *(buffer+0x08) = attacker-controlled value
   → calls EngModifySurface with pvScan0 = attacker value
   → writes attacker value to SURFACE+0x50 of the PAN bitmap
```

### Kernel dereference of user-mode DHSURF

The PANSURFLOCK code dereferences the DHSURF in kernel mode without try/except:

```c
if (!*((_DWORD *)dhsurf + 5))     // *(dhsurf+0x14) — kernel reads user memory
{
    EngModifySurface(
        ...,
        *(HDEV *)(*((_QWORD *)dhsurf + 4) + 48),  // *(*(dhsurf+0x20)+0x30) — double deref
        ...,
        *((PVOID *)dhsurf + 1),    // *(dhsurf+0x08) — kernel reads user memory
        *((_DWORD *)dhsurf + 4),   // *(dhsurf+0x10) — kernel reads user memory
        ...
    );
}
```

Kernel-mode code at PASSIVE_LEVEL (inside semaphore) can read valid user-mode addresses. The attacker must ensure the buffer is locked in memory (VirtualLock) to prevent page faults.

---

## Step 6: NtGdiSetPUMPDOBJ Analysis

**NtGdiSetPUMPDOBJ** @ `0x1c00a11d0` (win32kfull.sys, size 0x353)

### UMPD Registration Flow

```c
__int64 NtGdiSetPUMPDOBJ(__int64 a1, __int64 a2, _QWORD *a3, _DWORD *a4)
{
    // a1 = UMPD handle, a2 = flag (set/unset), a3 = output, a4 = output
    v6 = a2;  // flag
    
    if (a1)
        v8 = HmgShareLock(a1, 17);  // lock UMPD object
    else
        v8 = 0;
    
    // Security check:
    if (gUMPDSecurityLevel != 1
        || !v8
        || (bIsProcessLocalSystem(UMPD_owner_process))
        || (bIsProcessLocalSystem(PsGetCurrentProcess())))
    {
        // Allowed — proceed with UMPD registration
        // Gets W32THREAD, checks session/attachment
        // If v6 (set flag):
        //   - Checks bSandboxedCurrentProcess() (blocks sandboxed processes)
        //   - Allocates UMPD thread context
        //   - UMPDOBJ::bTryAcquireExclussiveAccess
        //   - UMPDOBJ::vPushToCurrentThread (registers UMPD on thread)
        // If !v6 (unset flag):
        //   - Removes UMPD from thread
    }
    // else: fail
}
```

### gUMPDSecurityLevel values

| Value | Meaning | Effect |
|-------|---------|--------|
| 0 | No restriction | UMPD registration allowed for any process |
| 1 | Restricted | Requires LocalSystem (owner or current process) |
| 2 | Locked | NtGdiEngCreateDeviceSurface always allowed (bypassed) |

**Key finding**: `NtGdiEngCreateDeviceBitmap` does NOT check `gUMPDSecurityLevel` at all. It only checks `ValidUmpdSizl`. This means device bitmap creation with a controlled DHSURF is possible regardless of the security level setting.

### UMPD registration from normal user mode

- When `gUMPDSecurityLevel == 0`: any process can register a UMPD driver
- When `gUMPDSecurityLevel == 1`: requires LocalSystem (blocks normal users)
- When `gUMPDSecurityLevel == 2`: surface creation is explicitly allowed

However, for the exploit path via `NtGdiEngCreateDeviceBitmap`, **UMPD registration is NOT required**. The syscall only validates the bitmap size, not the caller's UMPD status.

### Sandbox check

NtGdiSetPUMPDOBJ calls `bSandboxedCurrentProcess()` before allowing UMPD registration. This blocks AppContainer/sandboxed processes from registering UMPD drivers. However, `NtGdiEngCreateDeviceBitmap` has no such check.

---

## Step 7: Complete Findings

### The Key Question: Can we call EngModifySurface from user mode with a controlled pvScan0 value?

**YES — with conditions.**

### Exploit Path Summary

```
NtGdiEngCreateDeviceBitmap(controlled_dhsurf, valid_size, valid_format)
  → EngCreateDeviceBitmap → hbmCreateDriverSurface(iType=3, dhsurf=controlled)
  → HBITMAP returned to user mode (iType=STYPE_BITMAP, dhsurf=user-controlled)

GDI BitBlt(display_dc, source=UMPD_device_bitmap)
  → EngBitBlt → DrvBitBlt dispatch (indirect)
  → PanBitBlt (if display PDEV has PAN support)
  → MULTIPANSURFLOCK constructor
  → vLockBmp2AndPrepareForPunt (source iType == 3)
  → reads pvScan0 = *(controlled_dhsurf + 0x08)
  → EngModifySurface(pvScan0 = controlled_value)
  → writes controlled_value to SURFACE+0x50
```

### Conditions Required

1. **NtGdiEngCreateDeviceBitmap accessibility**: The process must be able to make this win32k syscall. On Windows 10+, this requires a non-sandboxed desktop process. No UMPD registration needed. No gUMPDSecurityLevel check.

2. **PAN-enabled display PDEV**: The system must have a display device with panning (scrolling) support, which creates a PAN PDEV via `PanEnablePDEV`. This is present on systems where the display driver supports panning mode (common on some multi-monitor or virtual display configurations).

3. **Surface validation in EngModifySurface**: The attacker must set up the fake DHSURF structure with:
   - `DHSURF+0x08` = desired pvScan0 (arbitrary kernel address)
   - `DHSURF+0x10` = non-zero lDelta
   - `DHSURF+0x14` = 0 (refcount must be zero)
   - `DHSURF+0x20` = pointer to a structure with valid HDEV at +0x30
   - The HDEV must match the target surface's HDEV (or target surface HDEV must be null)
   - The surface must have `0x400000` flag OR `iType == 1` for validation to pass

4. **Kernel dereference safety**: The DHSURF buffer must be in user-mode address space and locked in memory (VirtualLock) to prevent kernel page faults on paged-out memory.

### Callers That Do NOT Provide Controlled pvScan0

| Caller | pvScan0 | Reason |
|--------|---------|--------|
| MulEnableSurface | nullptr | Hardcoded null — takes null branch |
| PanEnableSurface | nullptr | Hardcoded null — takes null branch |
| MulCreateDeviceBitmapEx | nullptr | Hardcoded null — takes null branch |
| PANSURFLOCK unlock functions | nullptr | Restoring surface to device mode |

### Callers That DO Provide Controlled pvScan0 (via DHSURF)

| Caller | pvScan0 source | Trigger condition |
|--------|----------------|-------------------|
| PANSURFLOCK::vLockBmpAndPrepareForPunt | `*(dhsurf+0x08)` | Surface iType == 3 (bitmap) |
| MULTIPANSURFLOCK::vLockBmp1AndPrepareForPunt | `*(dhsurf+0x08)` | Surface iType == 3 (bitmap) |
| MULTIPANSURFLOCK::vLockBmp2AndPrepareForPunt | `*(dhsurf+0x08)` | Surface iType == 3 (bitmap) |

### SURFACE+0x50 Write Impact

After `EngModifySurface` writes the controlled pvScan0 to `SURFACE+0x50`:
- The SURFACE's `pvScan0` field now points to an attacker-controlled address
- Any subsequent GDI rendering operation on this surface (BitBlt, FillRect, etc.) will write pixel data to the attacker-controlled address
- This is a **write-what-where primitive** via controlled bitmap surface scan0

### Mitigating Factors

1. **PAN PDEV requirement**: The exploit requires a PAN-enabled display PDEV. Not all systems have this. PAN is typically associated with display drivers that support virtual screen panning.

2. **HDEV validation**: The attacker must provide a valid HDEV in the fake DHSURF structure. This requires knowledge of the display device's HDEV value, which can be obtained through GDI information APIs.

3. **No try/except in PANSURFLOCK**: If the user-mode DHSURF buffer becomes invalid (paged out, freed), the kernel will bugcheck. The attacker must keep the buffer valid and locked.

4. **Win32k syscall filtering**: On modern Windows 10/11, Win32k syscall filtering may restrict access to NtGdiEng* syscalls for certain process types (AppContainer, sandboxed). A normal desktop process should have access.

5. **iType check**: The PANSURFLOCK constructor only calls vLockBmpAndPrepareForPunt when `iType == 3` (STYPE_BITMAP). NtGdiEngCreateDeviceSurface creates `iType == 1` (STYPE_DEVICE) which takes the shadow path. Only NtGdiEngCreateDeviceBitmap creates `iType == 3`.

### NtGdiEng* → EngModifySurface Reachability Matrix

| NtGdiEng* syscall | Reaches EngModifySurface? | Path |
|--------------------|---------------------------|------|
| NtGdiEngCreateDeviceBitmap | Indirect (creates surface with controlled dhsurf) | Surface creation → later BitBlt punting |
| NtGdiEngCreateDeviceSurface | Indirect (but iType=1, shadow path) | No pvScan0 write |
| NtGdiEngBitBlt | Indirect (via EngBitBlt → PanBitBlt → PANSURFLOCK) | If surface is PAN bitmap with controlled dhsurf |
| NtGdiEngStretchBlt | Indirect (via EngStretchBlt → PanStretchBlt) | Same as BitBlt |
| NtGdiEngAlphaBlend | Indirect (via EngAlphaBlend → PanAlphaBlend) | Same |
| NtGdiEngLineTo | Indirect (via EngLineTo → Pan* → PANSURFLOCK) | If PAN surface |
| NtGdiEngFillPath | Indirect (via EngFillPath → Pan* → PANSURFLOCK) | If PAN surface |
| NtGdiEngStrokePath | Indirect (via PanStrokePath → PANSURFLOCK) | If PAN surface |
| NtGdiEngTextOut | Indirect (via PanTextOut → PANSURFLOCK) | If PAN surface |
| All other NtGdiEng* | No direct path to EngModifySurface | — |

Note: The NtGdiEng* rendering syscalls call the Eng* engine functions, which dispatch to Pan* through indirect DDI function pointer tables. The Pan* functions are only dispatched for PAN-enabled PDEVs. For UMPD PDEVs, the Mul* proxy functions are used instead, and they always pass pvScan0=nullptr to EngModifySurface.

---

## Conclusion

**EngModifySurface CAN be reached from user mode with a controlled pvScan0 value**, but the path requires:

1. Creating a device bitmap via `NtGdiEngCreateDeviceBitmap` with a user-controlled DHSURF (no UMPD registration or security level check required)
2. Using that bitmap in a GDI rendering operation (BitBlt, etc.) where the destination is a PAN-enabled display surface
3. The PAN punting mechanism (`PANSURFLOCK`/`MULTIPANSURFLOCK`) reads pvScan0 from `*(DHSURF+0x08)` and passes it to `EngModifySurface`
4. `EngModifySurface` writes the controlled pvScan0 to `SURFACE+0x50`

The primary obstacle is the requirement for a PAN-enabled display PDEV. If the target system has PAN support (display driver with panning/scrolling capability), the full exploit chain is viable from a normal user-mode desktop process without UMPD registration.

The `NtGdiEngCreateDeviceBitmap` syscall is the critical entry point — it stores a user-supplied 64-bit DHSURF value in the SURFACE without validation, and this value is later dereferenced by the PANSURFLOCK punting code to extract pvScan0 and lDelta for the EngModifySurface call.
