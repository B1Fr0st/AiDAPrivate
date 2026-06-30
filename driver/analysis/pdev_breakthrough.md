# PDEV Breakthrough Analysis: Making the Kernel Dereference a Fake SURFACE

## Binary Analysis Setup
- **win32kfull.sys**: port 13337, imagebase 0x1C0000000
- **ntoskrnl.exe**: port 13338, imagebase 0x140000000
- **win32kbase.sys**: port 13339, imagebase 0x1C0000000
- All three IDA MCP instances confirmed alive, Hex-Rays ready

---

## 1. DC Structure Layout (0x868 bytes total)

### DC Allocation
- **Size**: 0x868 bytes (confirmed via `HmgAlloc(0x868u, ...)` in both DCMEMOBJ constructors)
- **Allocation**: `HmgAlloc(0x868u, 1u, 1u)` (copy) or `HmgAlloc(0x868u, 1u, 0x11u)` (display)
- **Zeroing**: `AllocateObject` zeroes DC+0x00 to DC+0x17 (24 bytes) — first `_OWORD` (16) + QWORD (8)

### DCMEMOBJ Constructors (TWO different constructors)

#### Display DC Constructor (0x1c00c8314) — `DCMEMOBJ::DCMEMOBJ(HDEV, uint, int)`
Called by `GreCreateDisplayDC` for display DCs:
1. `HmgAlloc(0x868u, 1u, 0x11u)` — allocate DC
2. DC+0x858 (2136) = UMPDOBJ (thread current)
3. DC+0x860 (2144) = 0xFFFF
4. **DC+0x220 to DC+0x3D0**: Filled with `WPP_MAIN_CB.Queue.Wcb.DeviceObject` data (432 bytes = 3x128 + 48)
5. DC+0x3D0 (976) = DC+0x220 (DC_ATTR self-pointer)
6. **DC+0x50 to DC+0x220**: Filled with `dclevelDefault` data (464 bytes = 3x128 + 80)
7. DC+0x20 (32) = a3 (DC type: 0=display, 1=memory, 2=info)
8. DC+0x24 (36) = 0 (flags)
9. DC+0x2C (44) = 0 (flags)
10. DC+0x4B0 (1200) = 0 (brush origin)
11. DC_ATTR+0x98 (152) = 0x120FFF (DC_ATTR flags)
12. DC+0x4F0 (1264) = DC+0xB0 (self-pointer)
13. DC+0x578 (1400) = DC+0xB0
14. DC+0x600 (1536) = DC+0xB0
15. DC+0x688 (1672) = DC+0xB0
16. DC+0x6D8 (1752) = 0
17. DC+0x6E0 (1760) = 0
18. DC+0x834 (2100) = -1 (0xFFFFFFFF)
19. DC+0x830 (2096) = 0xFFFF
20. DC+0x458 (1112) = CPushLock vtable
21. DC+0x460 (1120) = 0
22. DC+0x468 (1128) = 0
23. DC+0x478 (1144) = 0 (region pointer)
24. DC+0x820 (2080) = 0
25. DC+0x828 (2088) = 0
26. **DC+0x30 (48) = a2 (HDEV/PDEV pointer)**
27. **DC+0x38 — NOT SET** (survives reinit!)

#### Copy Constructor (0x1c013c550) — `DCMEMOBJ::DCMEMOBJ(DCMEMOBJ*, DC**)`
Called by `CreateCompatibleDC` for memory DCs:
1. `HmgAlloc(0x868u, 1u, 1u)` — allocate DC
2. DC+0x858 = UMPDOBJ
3. DC+0x860 = 0xFFFF
4. DC+0x24 = 0, DC+0x28 = 0, DC+0x2C = 0
5. DC+0x458 = CPushLock vtable, DC+0x460 = 0, DC+0x468 = 0
6. DC+0x478 = 0
7. **DC+0x30 = source_DC+0x30** (HDEV/PDEV copied from template)
8. **DC+0x3D0 = DC+0x220** (DC_ATTR self-pointer)
9. Calls `DC::vCopyTo` to copy dclevelDefault

#### DC::vCopyTo (0x1c007fdd8) — copies template DC data
- **Second copy block**: DC+0x50 to DC+0x220 (464 bytes from `dclevelDefault`)
- **First copy block**: DC+0x220 to DC+0x3D0 (432 bytes of DC_ATTR from source DC_ATTR)
- DC+0x128 (296) = array pointer (adjusted relative to dest DC)
- DC+0xC8 (200) = path handle (via `DC::hpath`)

### GreCreateDisplayDC (0x1c003cac0) — post-DCMEMOBJ setup
After DCMEMOBJ, sets:
- DC+0x18 = PDEV+0x708 (from `*((_QWORD *)a1 + 225)`)
- DC+0x40 = PDEV+0x30 (semaphore), later overwritten to `ghsemGreLock`
- DC+0x48 = PDEV+0x1C8 (if HDEV__ is 4-byte type)
- DC+0x4C = PDEV+0x214
- DC+0x200 = PDEV sizlBitmap (or 0x100000001 for type 1)
- If display DC with valid PDEV: `DC::pSurface(DC, PDEV+0x9F8)` — sets DC+0x1F0 to primary SURFACE
- Then `DC::bSetDefaultRegion`, `HmgAllocateDcAttr`, `SetupDCAttributes`

### SetupDCAttributes (0x1c002c988)
- Gets handle table entry for DC
- Calls `DC::RestoreAttributes` (copies from separate DC_ATTR to inline DC_ATTR)
- Stores separate DC_ATTR pointer in handle table entry+0x10

### HmgAllocateDcAttr (0x1c002c9d8)
- DC_ATTR allocated in **SECURE USER MEMORY** via `HmgAllocateSecureUserMemory`
- 11 DC_ATTR slots per process, each 352 (0x160) bytes
- Management structure (0x70 bytes) in regular pool via `PALLOCMEM2`
- Slots start at offset 3520 from secure memory base, each 352 bytes apart
- DC_ATTR slots are reusable (freed when DC is deleted, reused when new DC created)

---

## 2. Complete Surviving Field Map

### Fields SET by DCMEMOBJ/vCopyTo (OVERWRITTEN — do NOT survive):
| Range | Source | Content |
|-------|--------|---------|
| DC+0x00 to DC+0x17 | AllocateObject zero | Object header (24 bytes) |
| DC+0x20 | DCMEMOBJ | DC type (0/1/2) |
| DC+0x24 | DCMEMOBJ | 0 (flags) |
| DC+0x28 | DCMEMOBJ (display only) | 0 |
| DC+0x2C | DCMEMOBJ | 0 (flags) |
| DC+0x30 | DCMEMOBJ | HDEV/PDEV from template |
| DC+0x50 to DC+0x220 | DC::vCopyTo | dclevelDefault (464 bytes) |
| DC+0x220 to DC+0x3D0 | DCMEMOBJ/vCopyTo | DC_ATTR: WPP data (display) or dclevelDefault (memory) |
| DC+0x3D0 | DCMEMOBJ | DC+0x220 (DC_ATTR self-ptr) |
| DC+0x4B0 | DCMEMOBJ | 0 (brush origin) |
| DC+0x4F0 | DCMEMOBJ (display) | DC+0xB0 (self-ptr) |
| DC+0x458 | DCMEMOBJ | CPushLock vtable |
| DC+0x460 | DCMEMOBJ | 0 |
| DC+0x468 | DCMEMOBJ | 0 |
| DC+0x478 | DCMEMOBJ | 0 (region ptr) |
| DC+0x6D8-0x6E0 | DCMEMOBJ (display) | 0 |
| DC+0x820-0x828 | DCMEMOBJ (display) | 0 |
| DC+0x830-0x834 | DCMEMOBJ (display) | 0xFFFF / -1 |
| DC+0x858-0x860 | DCMEMOBJ | UMPDOBJ / 0xFFFF |

### Fields NOT SET (SURVIVE reinit):
| Range | Size | Known Content | Controllable? |
|-------|------|---------------|---------------|
| **DC+0x18 to DC+0x23** | 12 bytes | Set by GreCreateDisplayDC (PDEV+0x708) — for display DCs | For memory DCs: SURVIVES |
| **DC+0x38 to DC+0x4F** | 24 bytes | **UNKNOWN — never set by any constructor** | **YES** |
| **DC+0x3D8 to DC+0x457** | 128 bytes | Region ptrs (DC+0x470=REGION*, DC+0x480=REGION*, DC+0x488=REGION*), vis rect (DC+0x3E8-0x3F4) | **YES** |
| **DC+0x471 to DC+0x477** | 7 bytes | Unknown | **YES** |
| **DC+0x479 to DC+0x857** | 951 bytes | EBRUSHOBJ surviving fields, various DC extension data | **YES** |

---

## 3. Key DC Offset Reference

| Offset | Field | Set By | Survives? |
|--------|-------|--------|-----------|
| DC+0x18 | PDEV+0x708 (display) | GreCreateDisplayDC | Memory DC: YES |
| DC+0x20 | DC type (0/1/2) | DCMEMOBJ | NO |
| DC+0x24 | flags | DCMEMOBJ | NO |
| DC+0x30 | **HDEV/PDEV pointer** | DCMEMOBJ | NO |
| **DC+0x38** | **UNKNOWN** | **NOT SET** | **YES** |
| DC+0x40 | lock semaphore (HSEMAPHORE) | GreCreateDisplayDC | Memory DC: YES |
| DC+0x48 | PDEV+0x1C8 (display) | GreCreateDisplayDC | Memory DC: YES |
| DC+0x50 | dclevelDefault start | DC::vCopyTo | NO |
| DC+0x58 | palette pointer (DC+11*8) | DC::vCopyTo | NO |
| DC+0x1F0 | **SURFACE pointer (DC+62*8)** | DC::vCopyTo / pSurface | **NO** |
| DC+0x200 | sizlBitmap / flags | DCMEMOBJ/vCopyTo | NO |
| DC+0x220 | DC_ATTR (inline) | DCMEMOBJ/vCopyTo | NO |
| DC+0x3D0 | DC_ATTR pointer (=DC+0x220) | DCMEMOBJ | NO (set to DC+0x220) |
| DC+0x3E8 | vis rect left | bCompute/bSetDefaultRegion | YES (set during use) |
| DC+0x3F8 | Unknown | bSetDefaultRegion sets to 0 | During SelectObject |
| DC+0x408 | Unknown | bSetDefaultRegion sets to 0 | During SelectObject |
| DC+0x470 | REGION pointer (DC+142*8) | bCompute | YES |
| DC+0x478 | REGION pointer (DC+143*8) | DCMEMOBJ sets to 0 | NO (set to 0) |
| DC+0x480 | REGION pointer (DC+144*8) | bCompute | YES |
| DC+0x488 | REGION pointer (DC+145*8) | bCompute | YES |
| DC+0x4B0 | brush origin POINTL | DCMEMOBJ | NO (set to 0) |
| DC+0x4B8 | **EBRUSHOBJ start** | vInitBrush | Partial |
| DC+0x4C0 | EBRUSHOBJ+0x08 = pvRbrush | vInitBrush | **YES** |
| DC+0x4D8 | EBRUSHOBJ+0x20 = pvRbrush2 | vInitBrush | **YES** |
| DC+0x4E8 | EBRUSHOBJ+0x30 = palette cnt | vInitBrush | **YES** |
| DC+0x4EC | EBRUSHOBJ+0x34 = palette cnt2 | vInitBrush | **YES** |
| DC+0x4F8 | EBRUSHOBJ+0x40 = IcmDIB ptr | vInitBrush | **NO** (past surviving range) |
| DC+0x508 | EBRUSHOBJ+0x50 = SURFACE ptr | vInitBrush | NO |
| DC+0x530 | EBRUSHOBJ+0x78 = brush flags | vInitBrush | **YES** |
| DC+0x534 | EBRUSHOBJ+0x7C = brush hash | vInitBrush | **YES** |
| DC+0x538 | EBRUSHOBJ+0x80 = flags | vInitBrush | **YES** |
| DC+0x834 | Unknown DWORD | DCMEMOBJ (display) sets to -1 | YES (then modifiable via NtGdiGetAndSetDCDword) |

---

## 4. Rendering Code Path Analysis

### NtGdiPatBlt (0x1c00b3f50, win32kfull.sys)
```
DCOBJ lock → DC pointer
v23 = *(SURFACE**)(DC + 0x1F0)     // READ SURFACE from DC+0x1F0
if (!v23) skip                      // NULL check — exits if no SURFACE
v24 = *(QWORD*)(DC + 0x3D0)        // DC_ATTR pointer
GreDCSelectBrush(DC, DC_ATTR+0xA0) // Select brush if dirty
GrePatBltLockedDC(DC, EXFORMOBJ, ERECTL, rop, v23, ...)  // v23 = SURFACE
```

### GrePatBltLockedDC (0x1c00b34a4, win32kfull.sys)
Takes SURFACE* as `a5`:
```
a5+0x74 (SURFACE+0x74) = flags     // Read SURFACE flags
a5+0x70 (SURFACE+0x70) = flags     // More flags
a5+0xE0 (SURFACE+0xE0) = ptr       // Some pointer
a5+0x288 (SURFACE+0x288) = access  // Access check object
a5+0x80 (SURFACE+0x80) = palette   // Palette pointer
a5+0x5C (SURFACE+0x5C) = counter   // Usage counter (incremented)
a5+0x30 (SURFACE+0x30) = PDEV      // PDEV pointer

// Rendering call:
if (SURFACE+0x70 & 1)
    call *(QWORD*)(PDEV+0xB10)(SURFOBJ=surf+0x18, ...)  // Driver BitBlt
else
    EngBitBlt(SURFOBJ=surf+0x18, ...)

// EBRUSHOBJ initialization:
v28 = DC + 0x4B8                    // EBRUSHOBJ at DC+0x4B8
EBRUSHOBJ::vInitBrush(v28, DC, DC+0x58, palette, surf_palette, a5, 1)
```

### NtGdiBitBltInternal (0x1c0088600, win32kfull.sys)
```
v40 = *(QWORD*)(DC_dest + 0x1F0)   // dest SURFACE from DC+0x1F0
v180 = (SURFACE*)v40
if (!v40) skip                      // NULL check
v41 = *(QWORD*)(v40 + 0x80)        // SURFACE+0x80 = palette
v51 = *(QWORD*)(DC_src + 0x1F0)    // src SURFACE from DC+0x1F0

// Rendering:
if (rop == SRCCOPY)
    if (SURFACE+0x70 & 0x400)
        call *(QWORD*)(PDEV+0xB18)(SURFOBJ=surf+0x18, ...)  // CopyBits
    else
        EngCopyBits(SURFOBJ=surf+0x18, ...)
else
    pfnBitBlt = SURFACE::pfnBitBlt(v97)
    pfnBitBlt(SURFOBJ=surf+0x18, ...)  // Driver BitBlt

// EBRUSHOBJ:
v45 = DC + 0x4B8                    // EBRUSHOBJ at DC+0x4B8
EBRUSHOBJ::vInitBrush(v45, DC, DC+0x58, palette, surf_palette, v40, 1)
```

### SURFACE Structure Layout (SURFOBJ at SURFACE+0x18)
| SURFACE Offset | SURFOBJ Offset | Field |
|---------------|---------------|-------|
| SURFACE+0x18 | SURFOBJ+0x00 | DHSURF dhsurf |
| SURFACE+0x20 | SURFOBJ+0x08 | HSURF hsurf |
| SURFACE+0x28 | SURFOBJ+0x10 | DHPDEV dhpdev |
| SURFACE+0x30 | SURFOBJ+0x18 | HDEV hdev (PDEV ptr) |
| SURFACE+0x38 | SURFOBJ+0x20 | SIZEL sizlBitmap.cx |
| SURFACE+0x3C | SURFOBJ+0x24 | SIZEL sizlBitmap.cy |
| SURFACE+0x40 | SURFOBJ+0x28 | ULONG lDelta |
| SURFACE+0x48 | SURFOBJ+0x30 | PVOID pvBits |
| **SURFACE+0x50** | **SURFOBJ+0x38** | **PVOID pvScan0 (TARGET)** |
| SURFACE+0x58 | SURFOBJ+0x40 | RECTL rclClip |
| SURFACE+0x70 | — | ULONG flags (driver-managed bit at &1) |
| SURFACE+0x80 | — | XEPALOBJ palette |

---

## 5. Task-by-Task Analysis

### Task 1: DC+0x38 (PDEV Pointer) — CAN IT GIVE US A WRITE?

#### Finding: DC+0x38 is NOT the PDEV pointer
- **DC+0x30** is the HDEV/PDEV pointer (confirmed by DEVLOCKOBJ::bLock, hbmSelectBitmapInternal, XDCOBJ::vLock, GreCreateDisplayDC)
- **DC+0x38 is NEVER SET** by any DCMEMOBJ constructor, DC::vCopyTo, GreCreateDisplayDC, or any initialization function found
- DC+0x38 is between DC+0x30 (PDEV) and DC+0x40 (semaphore)
- It may be a removed/reserved field in this Windows version

#### DC+0x38 survives reinit: CONFIRMED
- Not zeroed by AllocateObject (only zeroes 0x00-0x17)
- Not set by DCMEMOBJ display constructor
- Not set by DCMEMOBJ copy constructor
- Not copied by DC::vCopyTo (copies 0x50-0x220 and 0x220-0x3D0)
- Not set by GreCreateDisplayDC (sets 0x18, 0x40, 0x48, 0x4C, 0x200)

#### Can DC+0x38 redirect to a SURFACE? NO EVIDENCE FOUND
- Searched DEVLOCKOBJ::bLock — reads DC+0x30, not DC+0x38
- Searched DEVLOCKOBJ::vLock — reads PDEVOBJ, not DC+0x38
- Searched NtGdiPatBlt — reads DC+0x1F0 for SURFACE, DC+0x3D0 for DC_ATTR
- Searched NtGdiBitBltInternal — reads DC+0x1F0 for SURFACE
- Searched DC::bCompute — reads DC+0x1F0, DC+0x470, DC+0x478, DC+0x480, DC+0x488
- Searched DC::bSetDefaultRegion — reads DC+0x30 (PDEV), DC+0x1F0 (SURFACE), DC+0x478
- Searched bSpDwmValidateSurface — reads DC+0x24, DC+0x1D8, DC+0x1F0, DC+0x1E8, DC+0x1EC, DC+0x30
- Searched DestroyCacheDC — operates on cache DC structure, not kernel DC
- Searched XDCOBJ::vLock — reads DC+0x30, DC+0x208, DC+0x848, DC+0x858
- **No function found that reads DC+0x38 and treats it as a SURFACE pointer**

#### PDEV → SURFACE path: TOO DEEP
- PDEV+0x9F8 (2552) = primary SURFACE pointer (confirmed by PDEVOBJ::vClearSurface, NtGdiBitBltInternal, bSpDwmValidateSurface)
- Our control range via bitmap pixel data = 0x868 bytes
- 0x9F8 > 0x868 → cannot put a controlled SURFACE pointer at PDEV+0x9F8 within our fake data
- PDEV+0xB10 (2832) = BitBlt function pointer
- PDEV+0xB18 (2840) = CopyBits function pointer
- All PDEV SURFACE/function pointers are beyond our 0x868 byte control range

### Task 2: DC_ATTR (DC+0x3D0) — DOES IT SURVIVE OR CAN WE CONTROL IT?

#### DC_ATTR pointer: SET by DCMEMOBJ
- DC+0x3D0 = DC+0x220 (inline DC_ATTR self-pointer)
- Overwritten by DCMEMOBJ, does NOT survive

#### DC_ATTR contents: OVERWRITTEN
- Display DC: DC+0x220 filled with WPP_MAIN_CB data (432 bytes)
- Memory DC: DC+0x220 filled with dclevelDefault DC_ATTR (432 bytes via DC::vCopyTo)
- Display DCs also get separate DC_ATTR via HmgAllocateDcAttr (in secure user memory)
- SetupDCAttributes copies from separate DC_ATTR to inline DC_ATTR

#### DC_ATTR fields accessible via NtGdiGetAndSetDCDword:
| Case (a2) | DC_ATTR Offset | Type | Content |
|-----------|---------------|------|---------|
| 1 | DC+0x24 (not DC_ATTR) | DWORD | flags bit 0x400 |
| 2 | DC+0x834 (not DC_ATTR) | DWORD | Unknown (set to -1 by display DCMEMOBJ) |
| 4 | DC_ATTR+0x160 | DWORD | Unknown |
| 6 | DC_ATTR+0x68 | DWORD | Map mode related |
| 7 | DC_ATTR+0xEC | DWORD | Map mode |
| 8 | — | — | Calls DC::iSetMapMode (not direct write) |
| 9 | DC+0xF8 (not DC_ATTR) | DWORD | Layout flags |

#### DC_ATTR pointer fields:
- DC_ATTR+0xF8 (248) = IcmDIB pointer (read by EBRUSHOBJ::vInitBrush as `*(void**)(DC_ATTR + 248)`)
  - NOT accessible via NtGdiGetAndSetDCDword
  - In overwritten range (DC+0x318 = DC_ATTR+0xF8)
  - Set to 0 by dclevelDefault or WPP data

#### Verdict: Cannot control DC_ATTR pointer fields via NtGdiGetAndSetDCDword

### Task 3: EBRUSHOBJ at DC+0x4B0

#### EBRUSHOBJ starts at DC+0x4B8 (confirmed by GrePatBltLockedDC and NtGdiBitBltInternal)
- `v28 = (char *)v26 + 1208` → 1208 = 0x4B8 (not 0x4B0 as task states)
- `v45 = (HDC)((char *)v170[0] + 1208)` → same, DC+0x4B8

#### EBRUSHOBJ layout (from vInitBrush decompilation):
| EBRUSHOBJ Offset | DC Offset | Field | Survives? |
|-----------------|-----------|-------|-----------|
| +0x00 | DC+0x4B8 | iSolidColor (DWORD) | YES |
| +0x04 | DC+0x4BC | flags (DWORD) | YES |
| +0x08 | DC+0x4C0 | **pvRbrush (RBRUSH ptr)** | **YES** |
| +0x10 | DC+0x4C8 | flags2 (DWORD) | YES |
| +0x18 | DC+0x4D0 | color (DWORD) | YES |
| +0x1C | DC+0x4D4 | rgb (DWORD) | YES |
| +0x20 | DC+0x4D8 | **pvRbrush2 (RBRUSH ptr)** | **YES** |
| +0x28 | DC+0x4E0 | palette type (DWORD) | YES |
| +0x2C | DC+0x4E4 | palette bpp (DWORD) | YES |
| +0x30 | DC+0x4E8 | DC palette cnt (DWORD) | **YES** |
| +0x34 | DC+0x4EC | DC palette cnt2 (DWORD) | **YES** |
| +0x38-0x3F | DC+0x4F0-0x4F7 | Unknown | Partial (DC+0x4F0 set by display DCMEMOBJ) |
| +0x40 | DC+0x4F8 | **IcmDIB ptr** | **NO** (past 0x4EF) |
| +0x50 | DC+0x508 | **SURFACE ptr** | **NO** |
| +0x58 | DC+0x510 | palette 1 ptr | NO |
| +0x60 | DC+0x518 | palette 2 ptr | NO |
| +0x68 | DC+0x520 | palette 3 (PDEV+0x710) | NO |
| +0x70 | DC+0x528 | BRUSH ptr | NO |
| +0x78 | DC+0x530 | brush flags (DWORD) | **YES** |
| +0x7C | DC+0x534 | brush hash (DWORD) | **YES** |
| +0x80 | DC+0x538 | flags (DWORD) | **YES** |
| +0x84 | DC+0x53C | color (DWORD) | **YES** |

#### EBRUSHOBJ vInitBrush cache check:
The cache check determines if the EBRUSHOBJ is reinitialized or kept as-is:
```
if (BRUSH+0x2C == EBRUSHOBJ+0x7C)          // DC+0x534 (survives)
  if (flags match)                           // DC+0x530 (survives)
    if (palette counts match)                // DC+0x4E8, DC+0x4EC (survive)
      if (IcmDIB matches DC_ATTR+0xF8)       // DC+0x4F8 (DOES NOT survive)
        if (brush flags match)               // DC+0x538 (survives)
          return early (KEEP STALE DATA)
```

**Critical**: The IcmDIB check at DC+0x4F8 does NOT survive. After reinit:
- DC+0x4F8 is whatever WPP/dclevelDefault data is there (likely 0)
- DC_ATTR+0xF8 (IcmDIB) is also 0 (from defaults)
- If both are 0, the check PASSES (0 == 0)

**If ALL cache checks pass, vInitBrush returns early and the STALE pvRbrush at DC+0x4C0 is used!**

#### Can stale RBRUSH redirect to SURFACE? NO DIRECT PATH
- pvRbrush (DC+0x4C0) is an RBRUSH pointer, not a SURFACE pointer
- RBRUSH is a realized brush structure containing dither patterns, color tables
- RBRUSH does NOT contain SURFACE pointers
- The driver's BitBlt receives BRUSHOBJ (first 0x28 bytes of EBRUSHOBJ) and dereferences pvRbrush for brush data
- No RBRUSH field is used as a SURFACE pointer

### Task 4: BitBlt Between Two DCs

#### Source and dest SURFACE both come from DC+0x1F0
- Source: `v51 = *(QWORD*)(DC_src + 496)` → DC_src+0x1F0
- Dest: `v40 = *(QWORD*)(DC_dest + 62*8)` → DC_dest+0x1F0
- Both are in the overwritten range → both are 0 after reinit

#### Alternative SURFACE sources: NONE FOUND
- EngBitBlt always receives SURFOBJ = SURFACE+0x18, where SURFACE comes from DC+0x1F0
- EngCopyBits same
- SURFACE::pfnBitBlt gets SURFACE from DC+0x1F0
- No GDI function accepts a user-provided SURFACE pointer
- No Eng* function gets SURFACE from a non-DC source

### Task 5: Stale SURFACE Pointer

#### After DC UAF + pixel data reclaim at address A:
- A+0x1F0 = stale value = &SURFACE1 (from before UAF)
- A+0x50 = our controlled pvScan0 (from SetBitmapBits)

#### Creating a new DC at A: BOTH destroyed
- DCMEMOBJ overwrites A+0x50 (via dclevelDefault copy from 0x50-0x220)
- DCMEMOBJ/vCopyTo overwrites A+0x1F0 (via DC_ATTR copy from 0x220-0x3D0, which includes 0x1F0? No, 0x1F0 is in 0x50-0x220 range)
- Actually: DC::vCopyTo second copy block is DC+0x50 to DC+0x220 (464 bytes), which INCLUDES DC+0x1F0
- So DC+0x1F0 is overwritten by dclevelDefault's SURFACE pointer (likely 0)

#### Creating DC at different address: can't connect to A
- New DC at Y has Y+0x1F0 = 0 (from dclevelDefault)
- SelectObject(DC_Y, BITMAP1) → Y+0x1F0 = &SURFACE1 (bitmap's SURFACE, not A)
- No mechanism to make Y+0x1F0 = A

### Task 6: NtGdiGetAndSetDCDword

#### Decompilation (0x1c010c5d0, win32kfull.sys):
```
DCOBJ lock → DC pointer (v20[0])
a2 = command index
a3 = new value
a4 = output pointer (receives old value)

Case 1 (a2=1): DC+0x24, bit 0x400 (flags)
Case 2 (a2=2): DC+0x834 (DWORD, in surviving range)
Case 4 (a2=4): DC_ATTR+0x160 (DWORD)
Case 6 (a2=6): DC_ATTR+0x68 (DWORD, map mode)
Case 7 (a2=7): DC_ATTR+0xEC (DWORD, layout)
Case 8 (a2=8): DC::iSetMapMode (indirect)
Case 9 (a2=9): DC+0xF8 (DWORD, layout flags)
```

#### Can it write to DC+0x1F0? NO
- No case writes to DC+0x1F0
- No case writes to any pointer field
- All writes are DWORDs (4 bytes), never QWORDs (8 bytes)
- Cannot corrupt a full 8-byte pointer

### Task 7: DC_ATTR Writable Pointer Fields

#### DC_ATTR in secure user memory (for display DCs):
- Allocated by `HmgAllocateSecureUserMemory` — user-mapped, kernel-managed
- 352 bytes per slot, 11 slots per process
- Likely read-only from user mode (secure user memory protection)
- Cannot directly write to DC_ATTR from user mode

#### DC_ATTR inline (for memory DCs):
- At DC+0x220, overwritten by dclevelDefault
- Cannot control after DC creation (except via NtGdiGetAndSetDCDword DWORD writes)

#### DC_ATTR pointer fields found:
- DC_ATTR+0xF8 = IcmDIB pointer (read by vInitBrush)
  - NOT writable via NtGdiGetAndSetDCDword
  - In overwritten range
  - Set to 0 by defaults

#### Verdict: No controllable DC_ATTR pointer fields

### Task 8: TOCTOU for Type Confusion During SelectObject

#### Batch buffer cases: TYPE-CHECKED
- All batch cases use `HmgShareLockCheck(handle, type)` with specific type checks
- SelectFont (case 6): type check for font (type 4)
- DeleteObject (cases 7/8): NO type check (our deletion primitive)
- No batch case for SelectBitmap or SelectPalette that bypasses type checks
- Swapping a handle during SelectObject would fail the type check

#### Race condition approach:
- SelectObject → DC+0x1F0 = &SURFACE
- DeleteObject(bitmap) via TOCTOU → SURFACE freed
- DC+0x1F0 = dangling to freed SURFACE
- SURFACE in type isolation → cannot reclaim with controlled data
- **BLOCKED by type isolation**

### Task 9: Any Way to Make Kernel Dereference Address A as SURFACE?

#### Checked all possible pointer sources:

**a) DC+0x1F0** — Overwritten by DCMEMOBJ/vCopyTo to 0 (dclevelDefault) ❌
**b) Handle table entry** — Kernel space, not user-writable ❌
**c) DC+0x38** — Survives but never read by any function found ❌
**d) DC+0x3A0+** — In DC_ATTR copy range (0x220-0x3D0), OVERWRITTEN ❌
   - Correction: DC+0x3D8+ survives, contains REGION pointers, not SURFACE ❌
**e) Global variables** — `gppdevList` etc., kernel-managed ❌
**f) Linked lists** — DC saved states, clip regions — no SURFACE pointers ❌
**g) Batch buffer** — No batch case passes raw SURFACE pointers ❌

#### Surviving pointer fields and their types:
| DC Offset | Type | Used as SURFACE? |
|-----------|------|-----------------|
| DC+0x38 | Unknown | Never accessed ❌ |
| DC+0x470 | REGION* | Used for clipping, not SURFACE ❌ |
| DC+0x480 | REGION* | Used for clipping ❌ |
| DC+0x488 | REGION* | Used for clipping ❌ |
| DC+0x4C0 | RBRUSH* | Used for brush realization ❌ |
| DC+0x4D8 | RBRUSH* | Used for brush realization ❌ |

### Task 10: DC+0x3A0 to DC+0x4EF

#### DC+0x3A0 to DC+0x3D0: OVERWRITTEN by DC_ATTR copy
- Part of the 432-byte DC_ATTR copy (DC+0x220 to DC+0x3D0)
- Not a surviving region (contrary to task description)
- Task's "DC+0x3A0+ STALE" appears incorrect based on vCopyTo analysis

#### DC+0x3D8 to DC+0x4EF: SURVIVES
Contains:
- DC+0x3E8-0x3F4: vis rect (set by bCompute during use, survives reinit)
- DC+0x3F8: set to 0 by bSetDefaultRegion (during SelectObject)
- DC+0x408: set to 0 by bSetDefaultRegion
- DC+0x410: window size (set by bSetDefaultRegion)
- DC+0x470: REGION pointer (used by bCompute, survives)
- DC+0x478: set to 0 by DCMEMOBJ
- DC+0x480: REGION pointer (survives)
- DC+0x488: REGION pointer (survives)
- DC+0x4B8-0x4EF: EBRUSHOBJ surviving fields (pvRbrush, pvRbrush2, palette counts)

No SURFACE pointers in this range.

---

## 6. THE BOTTOM LINE

### Is there ANY code path where the kernel reads a pointer from a location we control and treats it as a SURFACE?

**NO direct path found after exhaustive analysis.**

### Why it's blocked:
1. **DC+0x1F0 (SURFACE ptr)**: Always overwritten by DCMEMOBJ/DC::vCopyTo (dclevelDefault copy covers 0x50-0x220, which includes 0x1F0)
2. **No surviving DC field is used as a SURFACE pointer**: All surviving fields are REGION*, RBRUSH*, DWORDs, or unknown/unused
3. **SURFACE memory is in type isolation**: Cannot reclaim freed SURFACE memory with controlled data
4. **NtGdiGetAndSetDCDword writes DWORDs only**: Cannot corrupt full 8-byte pointers
5. **PDEV SURFACE pointer (PDEV+0x9F8) is too deep**: 2552 bytes > 0x868 byte control range
6. **DC+0x38 is never accessed**: Unknown field, survives but no kernel code reads it
7. **Batch buffer type checking**: Cannot swap handle types for type confusion
8. **DC_ATTR is overwritten and in secure memory**: Cannot control pointer fields

---

## 7. POTENTIAL BREAKTHROUGH APPROACHES (Not fully verified)

### Approach A: Non-Type-Isolated SURFACE
`AllocateObject` uses type isolation (lookaside list) only when `laSize[type] >= Size`. If a SURFACE is too large for the lookaside list, it's allocated from **regular pool** via `PALLOCMEM2`.
- **To verify**: Check `laSize[5]` (bitmap type) value in win32kbase.sys
- If large SURFACEs go to regular pool → free + reclaim with bitmap pixel data
- Need to find a way to create a SURFACE larger than `laSize[5]`
- SURFACE size might be fixed regardless of bitmap dimensions (pixel data is separate)
- **Potential**: Create a bitmap with unusually large SURFACE (e.g., via CreateDIBSection with specific flags)

### Approach B: EBRUSHOBJ Cache Bypass + RBRUSH Type Confusion
If vInitBrush cache check passes (all surviving fields match current brush state), stale pvRbrush at DC+0x4C0 is used without reinitialization.
- Set DC+0x534 (brush hash) to match current BRUSH+0x2C
- Set DC+0x530 (brush flags) to match
- Set DC+0x4E8, DC+0x4EC (palette counts) to match
- DC+0x4F8 (IcmDIB) must match DC_ATTR+0xF8 (likely 0 == 0)
- Set DC+0x538 (flags) to match
- **If cache passes**: stale pvRbrush (DC+0x4C0) is used by driver's BitBlt
- Set pvRbrush = A (our fake SURFACE address)
- Driver dereferences A expecting RBRUSH data, gets SURFACE data instead
- **Limitation**: RBRUSH fields ≠ SURFACE fields; no RBRUSH field is used as SURFACE ptr
- **However**: If the driver accesses pvRbrush+offset as a function pointer or indirect pointer, and our fake SURFACE has controlled data at that offset, we might get arbitrary execution or redirect

### Approach C: Separate DC_ATTR Reclaim (Display DCs)
Display DCs allocate a separate DC_ATTR in secure user memory via `HmgAllocateDcAttr`.
- DC_ATTR is 352 bytes, allocated in user-mapped secure memory
- 11 slots per process, reusable
- **To verify**: Is secure user memory writable from user mode?
- If writable → inject controlled DC_ATTR data → corrupt IcmDIB pointer at DC_ATTR+0xF8
- If IcmDIB pointer is set to A → vInitBrush stores A at EBRUSHOBJ+0x40
- EBRUSHOBJ+0x40 = DC+0x4F8 (doesn't survive, but is set during vInitBrush)
- **Limitation**: IcmDIB is used for color matching, not as a SURFACE pointer

### Approach D: WPP Data Manipulation
Display DCMEMOBJ fills DC+0x220 (DC_ATTR) with `WPP_MAIN_CB.Queue.Wcb.DeviceObject` data.
- If WPP tracing can be enabled/controlled → influence what data is written to DC+0x220
- If WPP data contains a pointer at DC_ATTR+0xF8 offset → that pointer would be used as IcmDIB
- **To verify**: What does WPP_MAIN_CB.Queue.Wcb.DeviceObject contain?
- **Limitation**: WPP data is kernel-controlled, unlikely to be user-influenceable

### Approach E: TOCTOU Delete + SURFACE Reclaim via Regular Pool
1. Select BITMAP1 into DC → DC+0x1F0 = &SURFACE1
2. TOCTOU delete BITMAP1 → SURFACE1 freed
3. If SURFACE1 was in regular pool (not type isolation) → reclaim with bitmap pixel data
4. DC+0x1F0 = &reclaimed_data → controlled SURFACE → pvScan0 = TARGET
5. Call BitBlt/PatBlt → reads controlled SURFACE → arbitrary R/W
- **Key requirement**: SURFACE1 must be in regular pool, not type isolation
- **To verify**: Check `laSize[5]` and SURFACE allocation size
- If SURFACE size > `laSize[5]` → goes to regular pool → THIS WORKS

### Approach F: DC UAF + Pre-fill + Display DC with Separate DC_ATTR
1. Create display DC1 at address X → separate DC_ATTR at address Y (secure user memory)
2. Delete DC1 → X freed, Y returned to DC_ATTR free list
3. Reclaim X with bitmap pixel data (0x868 bytes controlled)
4. Create display DC2 at X → DCMEMOBJ fills X with WPP data and dclevelDefault
5. GreCreateDisplayDC calls HmgAllocateDcAttr → might reuse Y
6. SetupDCAttributes → RestoreAttributes copies from Y to inline DC_ATTR at X+0x220
7. If Y still has stale data from DC1 → stale DC_ATTR data gets restored
8. **Potential**: If stale DC_ATTR has non-zero IcmDIB pointer → vInitBrush uses it
- **Limitation**: DC_ATTR is in secure user memory, likely zeroed or kernel-initialized when reused

---

## 8. RECOMMENDED NEXT STEPS

### Priority 1: Verify SURFACE type isolation threshold
- Decompile `SURFACE::Allocate` (0x1c00808c0) to find allocation size
- Find `laSize[5]` value in win32kbase.sys data section
- If SURFACE size > laSize[5], SURFACEs go to regular pool → Approach E works

### Priority 2: Verify EBRUSHOBJ cache bypass feasibility
- Determine if all cache check fields can be set to match current brush state
- If yes, stale pvRbrush is used → set pvRbrush = A for type confusion
- Analyze what the driver does with RBRUSH data at A — any pointer derefs?

### Priority 3: Check if secure user memory (DC_ATTR) is user-writable
- Decompile `HmgAllocateSecureUserMemory` to see page protections
- If writable → inject controlled IcmDIB pointer → trace if it leads to SURFACE deref

### Priority 4: Check SURFACE allocation for non-isolated paths
- Look for SURFACE creation paths that bypass AllocateObject (e.g., EngCreateSurface, driver-created surfaces)
- These might be in regular pool and reclaimable

---

## 9. KEY FUNCTION ADDRESSES

| Function | Address | Binary |
|----------|---------|--------|
| DCMEMOBJ (display) | 0x1c00c8314 | win32kbase.sys |
| DCMEMOBJ (copy) | 0x1c013c550 | win32kbase.sys |
| DC::vCopyTo | 0x1c007fdd8 | win32kbase.sys |
| DC::pSurface | 0x1c0021968 | win32kbase.sys |
| DC::bCompute | 0x1c003bfe0 | win32kbase.sys |
| DC::bSetDefaultRegion | 0x1c013c750 | win32kbase.sys |
| DEVLOCKOBJ::bLock | 0x1c003b780 | win32kbase.sys |
| DEVLOCKOBJ::vLock | 0x1c00bea44 | win32kbase.sys |
| EBRUSHOBJ::vInitBrush | 0x1c00679d0 | win32kbase.sys |
| PDEVOBJ::vClearSurface | 0x1c013e41c | win32kbase.sys |
| PDEVOBJ::vUnreferencePdev | 0x1c0022d50 | win32kbase.sys |
| hbmSelectBitmapInternal | 0x1c00ca320 | win32kbase.sys |
| HmgAllocateDcAttr | 0x1c002c9d8 | win32kbase.sys |
| SetupDCAttributes | 0x1c002c988 | win32kbase.sys |
| XDCOBJ::GetUserAttr | 0x1c0030590 | win32kbase.sys |
| XDCOBJ::vLock | 0x1c00c816c | win32kbase.sys |
| AllocateObject | 0x1c002bcc0 | win32kbase.sys |
| GreCreateDisplayDC | 0x1c003cac0 | win32kbase.sys |
| NtGdiPatBlt | 0x1c00b3f50 | win32kfull.sys |
| GrePatBltLockedDC | 0x1c00b34a4 | win32kfull.sys |
| NtGdiBitBltInternal | 0x1c0088600 | win32kfull.sys |
| NtGdiGetAndSetDCDword | 0x1c010c5d0 | win32kfull.sys |
| bSpDwmValidateSurface | 0x1c0087cc8 | win32kfull.sys |
| EngBitBlt | 0x1c00cb280 | win32kfull.sys |

---

## 10. SUMMARY

**The core problem**: We can create a fake SURFACE at a controlled address A with pvScan0 = TARGET, and we can control surviving DC fields by pre-filling memory with bitmap pixel data before DC creation. However, NO surviving DC field is used as a SURFACE pointer by any GDI rendering function. The only SURFACE pointer in the DC (DC+0x1F0) is always overwritten during DC initialization.

**Most promising approaches**:
1. **Approach E**: Find a way to create a SURFACE in regular (non-isolated) pool, then use TOCTOU to free it while it's selected in a DC, and reclaim with controlled data
2. **Approach B**: Exploit the EBRUSHOBJ cache bypass to use a stale RBRUSH pointer, and investigate if any driver dereferences RBRUSH fields as pointers that could redirect to a SURFACE
3. **Approach A**: Find a SURFACE allocation path that bypasses type isolation

**Analysis tools used**: IDA Pro MCP across 3 binaries (win32kfull.sys, ntoskrnl.exe, win32kbase.sys), Hex-Rays decompilation, instruction analysis, cross-reference tracing, offset calculation via py_eval
