# Non-Selectable GDI Object Deep Analysis: Write-Through-Pointer Primitive

## Executive Summary

Deep reverse engineering of win32kbase.sys and win32kfull.sys was performed to investigate non-selectable GDI object types that do NOT zero on free. The goal was to find a write-through-pointer primitive for a single 8-byte arbitrary kernel write.

### Key Findings

| Type | Name | Size | LFH Bucket | User-Callable | Zero on Free | Viability |
|------|------|------|------------|---------------|-------------|-----------|
| 0 | Unknown | ??? | ??? | ??? | Yes (confirmed) | **Unidentified** - no creation function found |
| 1 | DC | 0x868 (2152) | 2168+ (lookaside) | Yes | No | Lookaside path, complex |
| 6 | ClientObj | 24 | 48 | Yes (NtGdiCreateClientObj) | No | **Not viable** - header only, no body/pointers |
| 7 | Unknown | ??? | ??? | ??? | Yes (confirmed) | **Unidentified** - no creation function found |
| 9 | ColorSpace | 0x268 (616) | 640 | Yes (NtGdiCreateColorSpace) | **NO** | **BEST CANDIDATE** - 592B controllable body, no zeroing |
| 13 | Unknown | ??? | ??? | ??? | Yes (confirmed) | **Unidentified** - no creation function found |
| 14 | ColorTransform | 32 | 48 | Yes (NtGdiCreateColorTransform) | Pointer zeroed before free | **Not viable** - only ptr at 0x18 zeroed |
| 15 | DwmSprite | 0xB0 (176) | 192 | Indirect (window ops) | Partial (0xA8 zeroed) | **Secondary** - list ptrs survive but not controllable |

---

## 1. GDI Handle Management Architecture

### AllocateObject (win32kbase.sys @ 0x1c002bcc0)

For non-lookaside types with a3=0, only the first 24 bytes (BASEOBJECT header) are zeroed. The body (offsets 24+) retains whatever was in the pool memory.

### FreeObject (win32kbase.sys @ 0x1c002bc40)

Checks the lookaside flag at offset 14. If >= 0 (non-lookaside), calls Win32FreePool which does NOT zero memory. Pool block is returned with all body data intact.

### Win32AllocPool (win32kbase.sys @ 0x1c002c2d0)

Calls pool_alloc with PoolType = 33 (0x21) = PagedPool | POOL_RAISE_IF_ALLOCATION_FAILURE. **GDI objects are allocated from PagedPool.**

---

## 2. Lookaside List Initialization (HmgCreate @ 0x1c006bcfc)

Only types 1, 4, 5, 8, 10, 11, 16 have lookaside lists. Non-lookaside types (0, 2, 3, 6, 7, 9, 13, 14, 15, 17, 18, 21, 28) use the pool path.

Lookaside sizes:
- Type 1 (DC): 0x868 (2152 bytes)
- Type 4 (Palette): 0x70 (112 bytes)
- Type 5 (Surface): SURFACE::tSize + 256
- Type 8 (Palette): 0xC8 (200 bytes)
- Type 10 (Font): 0x278 (632 bytes)
- Type 11: 0x390 (912 bytes)
- Type 16 (Brush): 0xB8 (184 bytes)

---

## 3. LFH Bucket Calculations

Pool header = 16 bytes. Pool block size = object_size + 16. LFH bucket = smallest bucket >= pool_block_size.

```
Type                    ObjSize  PoolBlk   Bucket
----------------------------------------------------
Type 0 (Unknown)           ???      ???      ???
Type 1 (DC)              2152     2168      (lookaside)
Type 6 (ClientObj)          24       40       48
Type 7 (Unknown)           ???      ???      ???
Type 9 (ColorSpace)        616      632      640
Type 13 (Unknown)          ???      ???      ???
Type 14 (ColorTransform)    32       48       48
Type 15 (DwmSprite)        176      192      192
```

Same-bucket cross-reference:
- **Bucket 48**: Type 6 (ClientObj 24B) + Type 14 (ColorTransform 32B). Other PagedPool allocs 17-32 bytes.
- **Bucket 192**: Type 15 (DwmSprite 176B). Other PagedPool allocs 161-176 bytes.
- **Bucket 640**: Type 9 (ColorSpace 616B). Other PagedPool allocs 609-624 bytes.

---

## 4. Type 6: ClientObj (24 bytes)

### Create: NtGdiCreateClientObj (win32kfull @ 0x1c0118e60)
- AllocateObject(24, 6) -> 24 bytes from PagedPool
- HmgInsertObjectHelper::Insert(obj, 6, 0)
- HmgModifyHandleType encodes subtype in handle

### Delete: GreDeleteClientObj (win32kfull @ 0x1c0120760)
- HmgRemoveObject(a1, 0, 0, 1, 6, 0)
- FreeObject(result, 6) -- NO zeroing

### Structure (24 bytes)
- 0x00-0x17: BASEOBJECT header (only field - no body at all)

### Assessment: NOT VIABLE
Only 24 bytes = BASEOBJECT header only. No body, no pointer fields.

---

## 5. Type 14: COLORTRANSFORMOBJ (32 bytes)

### Create: NtGdiCreateColorTransform -> COLORTRANSFORMOBJ::hCreate (win32kfull @ 0x1c0293ac8)
- AllocateObject(32, 14) -> 32 bytes from PagedPool
- Calls driver IcmCreateColorTransform callback
- Stores driver result at Object+24 (offset 0x18)

### Delete: COLORTRANSFORMOBJ::bDelete (win32kfull @ 0x1c02938a4)
- Calls driver IcmDeleteColorTransform callback
- **ZEROES offset 0x18** (the driver pointer) before FreeObject
- FreeObject only called after offset 0x18 == 0

### Structure (32 bytes)
- 0x00-0x17: BASEOBJECT header
- 0x18: Driver color transform pointer (QWORD) -- ZEROED on delete

### Assessment: NOT VIABLE
The only pointer field at offset 0x18 is explicitly zeroed by bDelete before FreeObject.

---

## 6. Type 15: DWMSPRITE (176 bytes)

### Create: hspCreateDwmSpriteObj (win32kfull @ 0x1c0015e5c)
- AllocateObject(176, 15) -> 176 bytes from PagedPool
- Initializes self-referencing doubly-linked list at offsets 0x18/0x20
- Sets HWND at offset 0x28
- Sets a2 parameter at offset 0x30
- Initializes PushLock at offset 0x58 (GreInitializePushLock)
- Creates and sets SFMLOGICALSURFACE at offset 0xA8

### Delete: vspDestroyDwmSpriteObjInternal (win32kfull @ 0x1c0015944)
- Calls SetLogicalSurface(nullptr) which **ZEROES offset 0xA8**
- Calls vspRemoveStateReferencesForSprite which unlinks from list (does NOT zero Flink/Blink)
- HmgRemoveObject(type 15) + FreeObject -- NO zeroing

### Structure Layout (176 bytes)
```
Offset  Size  Field                                   Zeroed on Free?
0x00    24    BASEOBJECT header                       Partially (handle mgmt)
0x18    8     ListEntry.Flink                         NO - unlinked but not zeroed
0x20    8     ListEntry.Blink                         NO - unlinked but not zeroed
0x28    8     HWND                                    NO
0x30    8     a2 parameter / handle                   NO
0x38    4     Window position left                    NO
0x3C    4     Window position top                     NO
0x40    4     Window position right                   NO
0x44    4     Window position bottom                  NO
0x48    4     Update flags                            NO
0x4C    4     BLENDFUNCTION                           NO
0x50    4     Color key / alpha value (DWORD)         NO
0x54    4     (padding/unknown)                       NO
0x58    ~8    EX_PUSH_LOCK                            NO
0x68    8     Some QWORD pointer                      Zeroed in GreUpdateSpriteInternal
0x74    4     Counter/flags                           NO
0x9C    4     DPI scale X (float)                     NO
0xA0    4     DPI scale Y (float)                     NO
0xA4    4     Flags (0x10=delete, 0x20=DPI)           NO
0xA8    8     SFMLOGICALSURFACE* (QWORD ptr)          YES - zeroed by SetLogicalSurface
```

### Surviving Pointer Fields After Free
| Offset | Field | Controllable? |
|--------|-------|---------------|
| 0x18 | Flink | No - points to other DwmSprites/g_pDwmState |
| 0x20 | Blink | No - points to other DwmSprites/g_pDwmState |
| 0x28 | HWND | Semi - user handle, not kernel pointer |
| 0x30 | a2 | Unknown - depends on creation context |

### Assessment: SECONDARY CANDIDATE
List entry pointers survive but are NOT user-controllable. SFMLOGICALSURFACE ptr at 0xA8 is zeroed. Offset 0x50 is a DWORD, not a pointer. Creation is indirect via window ops. Needs same-bucket (192) target with write-through pointer.

---

## 7. Type 9: ColorSpace (616 bytes) -- BEST CANDIDATE

### Create: NtGdiCreateColorSpace (win32kbase @ 0x1c0148bd0) -> GreCreateColorSpace (0x1c00a06c4)
- User-mode callable (NtGdi prefix)
- AllocateObject(0x268, 9, 0) -> 616 bytes from PagedPool, a3=0 (no full zero)
- Copies 592 bytes of user-provided LOGCOLORSPACEEXW into object body

User data copy mapping:
```
Object Offset  Source Offset  Field
0x18           0             lcsSignature (DWORD)
0x1C           4             lcsVersion (DWORD)
0x20           8             lcsSize (DWORD)
0x24           12            lcsIntent (DWORD)
0x28           16            lcsUnused (DWORD)
0x2C           20            lcsEndpoints (16 bytes OWORD)
0x3C           36            lcsEndpoints cont. (16 bytes OWORD)
0x4C           52            lcsGammaRed (DWORD)
0x50           56            lcsGammaGreen (DWORD)  <-- OFFSET 0x50!
0x54           60            lcsGammaBlue (DWORD)
0x58           64            lcsFilename start (DWORD)
0x5E-0x263     68-611        lcsFilename (520 bytes wide string)
0x264          588           LOGCOLORSPACEEXW extra (DWORD)
```

### Delete: NtGdiDeleteColorSpace -> bDeleteColorSpace (win32kbase @ 0x1c00cb468)
- HmgRemoveObject(a1, 0, 0, 1, 9, nullptr)
- FreeObject(v3, 9) -- NO ZEROING AT ALL
- No destructor, no field cleanup, no driver callbacks

```c
__int64 __fastcall bDeleteColorSpace(struct HOBJ__ *a1, int a2)
{
    if (a1 == ghStockColorSpace) return a2 != 3;
    v3 = HmgRemoveObject(a1, 0, 0, 1, 9, nullptr);
    if (!v3) { EngSetLastError(0x57); return 0; }
    FreeObject(v3, 9);  // ENTIRE 616-BYTE BODY SURVIVES!
    return 1;
}
```

### User Control at Offset 0x50
- Object offset 0x50 = lcsGammaGreen (DWORD from source[56])
- Object offset 0x54 = lcsGammaBlue (DWORD from source[60])
- Together: QWORD at offset 0x50 is fully user-controllable
- **Can write arbitrary 8-byte value at offset 0x50**

### User Control via Filename
- Object offsets 0x5E to 0x263 (92 to 611) = 520 bytes via lcsFilename
- **Can write arbitrary 8-byte values at any 8-byte-aligned offset from 0x5E to 0x260**

### Assessment: BEST CANDIDATE
1. User-mode callable (NtGdiCreateColorSpace / NtGdiDeleteColorSpace)
2. 616 bytes, LFH bucket 640
3. NO zeroing on free - entire body survives
4. 592 bytes of user-controlled body data (offsets 0x18-0x267)
5. Can control QWORD at offset 0x50 via lcsGammaGreen + lcsGammaBlue
6. Can control 520 bytes at offsets 0x5E-0x263 via filename
7. Simple create/delete - no complex cleanup

Attack model:
1. NtGdiCreateColorSpace with crafted LOGCOLORSPACEEXW (QWORD at body offset X = target_address)
2. NtGdiDeleteColorSpace (body data survives in freed pool block)
3. Trigger same-bucket (640) allocation with write-through pointer at offset X
4. New object reads stale ColorSpace data as pointer and writes through it
5. Arbitrary kernel write achieved

**Remaining requirement:** Find PagedPool object of body size 593-624 bytes (bucket 640) with a pointer field that gets dereferenced and written through.

---

## 8. Types 0, 7, 13: Unidentified

No creation functions found in win32kbase.sys or win32kfull.sys despite exhaustive searching of:
- All AllocateObject callers
- All HmgAlloc callers
- All HmgInsertObjectHelper::Insert callers
- All HmgInsertObjectInternal callers
- All FreeObject callers
- All HmgRemoveObject callers
- All HmgFree callers
- String searches for type names

Possible explanations:
1. Legacy types no longer actively created
2. Created in other kernel modules (win32k.sys, dxgkrnl.sys)
3. Created only under specific conditions

Garbage collection bitmask (0x103A0):
- Type 7 IS garbage collectible (suggesting it's still recognized)
- Types 0 and 13 are NOT garbage collectible

---

## 9. Confirmed GDI Type Mapping

| Type | Name | Size | Lookaside? |
|------|------|------|-----------|
| 1 | DC | 0x868 (2152) | Yes |
| 2 | Region | Variable | No |
| 3 | Path | ~320 | CTypeIsolation |
| 4 | Palette | 0x70 (112) | Yes |
| 5 | Surface/Bitmap | SURFACE::tSize+256 | Yes |
| 6 | ClientObj | 24 | No |
| 8 | Palette (XEPAL) | 0xC8 (200) | Yes |
| 9 | ColorSpace | 0x268 (616) | No |
| 10 | Font | 0x278+ (632+) | Yes |
| 11 | Pen | 0x390 (912) | Yes |
| 14 | ColorTransform | 32 | No |
| 15 | DwmSprite | 0xB0 (176) | No |
| 16 | Brush | 0xB8 (184) | Yes |
| 17 | UMPDOBJ | Unknown | No |
| 18 | SFMLOGICALSURFACE | 304 | No |
| 21 | META | Variable | No |
| 28 | DRVOBJ | 64 | No |

---

## 10. Cross-Subsystem LFH Bucket Matching

### Bucket 640 (ColorSpace 616B)
- Need PagedPool allocs of 609-624 bytes from any subsystem
- No other GDI types in this bucket (Font=632B is bucket 704)
- Type 21 (META) can hit bucket 640 with user_data 545-576 bytes, but META body has no write-through pointers (just raw data + DWORDs)
- Requires searching ntoskrnl.exe, afd.sys, npfs.sys, and other PagedPool consumers for 609-624 byte allocations with pointer fields

### Bucket 192 (DwmSprite 176B)
- Need PagedPool allocs of 161-176 bytes
- No other GDI non-lookaside types in this range
- Brush (type 16, 184B) is lookaside and in bucket 208, not 192
- Requires searching other subsystems for 161-176 byte PagedPool allocations

### Bucket 48 (ClientObj 24B + ColorTransform 32B)
- Need PagedPool allocs of 17-32 bytes
- ClientObj has no body, ColorTransform ptr is zeroed
- Very small bucket, limited write-through potential

---

## 11. Conclusion

**ColorSpace (type 9, 616 bytes, bucket 640) is the strongest candidate for a write-through-pointer primitive:**

1. It is user-mode callable via NtGdiCreateColorSpace/NtGdiDeleteColorSpace
2. It does NOT zero any body data on free (bDeleteColorSpace just calls HmgRemoveObject + FreeObject)
3. It provides 592 bytes of user-controlled body data
4. The QWORD at offset 0x50 can be precisely controlled via lcsGammaGreen + lcsGammaBlue fields
5. 520 additional bytes (offsets 0x5E-0x263) can be controlled via the filename field
6. The create/delete paths are simple with no complex cleanup or driver callbacks

**The next step is to identify a PagedPool kernel object of body size 593-624 bytes (LFH bucket 640) that contains a pointer field at an offset overlapping with the ColorSpace body (0x18-0x267) which gets dereferenced and written through.** This requires searching ntoskrnl.exe and other kernel drivers for PagedPool allocations in the 609-624 byte range with write-through pointer semantics.

**DwmSprite (type 15, 176 bytes, bucket 192) is a secondary candidate** but has significant limitations: the surviving pointer fields (Flink/Blink at 0x18/0x20) are not user-controllable, the main pointer at 0xA8 is zeroed before free, and creation is indirect via window operations rather than a direct API call.

**Types 0, 7, and 13 remain unidentified** - no creation functions were found in either analyzed binary. These may be legacy types, types from other modules, or conditionally-created types that require further investigation in win32k.sys, dxgkrnl.sys, or display driver modules.
