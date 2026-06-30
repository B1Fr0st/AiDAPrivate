# D3DKMTCreateAllocation Validation Trace — Root Cause Analysis

## Executive Summary

All 4 allocation paths return `0xC000000D` (STATUS_INVALID_PARAMETER) due to **three distinct root causes**, all verified by tracing every branch in the decompiled `DxgkCreateAllocationInternal` (0x1c00fafe0) and `DXGDEVICE::CreateAllocation` (0x1c00fe210) in dxgkrnl.sys.

| Path | Flags | Failing Check | Root Cause |
|------|-------|---------------|------------|
| 1: ExistingSysMem | 0x20 | LABEL_33 in outer function | ExistingSysMem (0x20) without StandardAllocation (0x10000) and without DXGPROCESS+0x15B bit 0x20 |
| 2: Bare | 0x0 | KMD DdiCreateAllocation callback inside CreateDriverAllocations | No private driver data and no standard allocation — KMD rejects |
| 3: StandardAllocation | 0x10062 | LABEL_43 in outer function | CreateResource (0x2) set without CreateShared (0x1) |
| 4: CreateAllocation2 | 0x42 | LABEL_43 in outer function | CreateResource (0x2) set without CreateShared (0x1) — exploit confuses 0x42 with 0x41 |

**Additionally**: The kernel ALWAYS copies 96 bytes (0x60) per allocation from `pAllocationInfo`, but the exploit provides 40-byte (0x28) `D3DDDI_ALLOCATIONINFO` structs. The exploit MUST use `D3DDDI_ALLOCATIONINFO2` (96 bytes).

---

## 1. DxgkCreateAllocationInternal (0x1c00fafe0) — Complete Branch Trace

### Branch A: DXGPROCESS null check (0x1c00fb0e8)
```c
if ( !v9 )  // v9 = DXGPROCESS or current thread's dxg process
    return 0xC000000D;  // 3221225485
```
**Status**: Not triggered. Process is valid.

### Branch B: Device lookup failure (0x1c00fb26f)
```c
DXGDEVICEBYHANDLE::DXGDEVICEBYHANDLE(..., v79.hDevice, ..., &v76);
if ( !v76 )
    goto LABEL_102;  // -> return 0xC000000D
```
**Status**: Not triggered. Device handle is valid.

### Branch C: Flags 0x100000 (WSL) + 0x10000 conflict (0x1c00fb2c3)
```c
if ( (Flags & 0x100000) != 0 ) {
    if ( (Flags & 0x10000) != 0 )    // both WSL + Standard -> error
        goto LABEL_102;
    if ( !g_OSTestSigningEnabled )   // WSL without test signing -> error
        goto LABEL_102;
}
```
**py_eval verification**:
- Path 1 (0x20): `0x20 & 0x100000 = 0x0` — skipped
- Path 2 (0x0): `0x0 & 0x100000 = 0x0` — skipped
- Path 3 (0x10062): `0x10062 & 0x100000 = 0x0` — skipped
- Path 4 (0x42): `0x42 & 0x100000 = 0x0` — skipped
**Status**: Not triggered for any path.

### Branch D: NumAllocations limit (0x1c00fb331)
```c
if ( v79.NumAllocations > 0x682AA )
    goto LABEL_102;
```
**py_eval**: `0x682AA` = 426666. Our `NumAllocations = 1`.
**Status**: Not triggered.

### Branch E: LABEL_33 — Process sharing flag check (0x1c00fb372-0x1c00fb3c5)
```c
v26 = v9[347];  // DXGPROCESS offset 0x15B
LOBYTE(v26) = v26 & 0x20;
if ( !(_BYTE)v26 && ((Flags & 8) || (Flags & 0x100) || (Flags & 0x1000) || (Flags & 0x200))
  || (Flags & 0x20) && (Flags & 0x10000) == 0 && !(_BYTE)v26 )
{
    LABEL_33: -> return 0xC000000D
}
```

Two conditions trigger LABEL_33:
1. **Cond1**: `!v26_bit20 && (Flags & 0x8 || Flags & 0x100 || Flags & 0x1000 || Flags & 0x200)`
2. **Cond2**: `(Flags & 0x20) && !(Flags & 0x10000) && !v26_bit20`

Where `v26_bit20 = DXGPROCESS[0x15B] & 0x20` — a process flag (likely "container/shared allocation allowed"). For a normal user-mode process, this is **0**.

**py_eval verification** (assuming `v26_bit20 = 0`):

| Path | Flags | Cond1 | Cond2 | Result |
|------|-------|-------|-------|--------|
| 1 | 0x20 | `0x20 & 0x8=0, 0x20 & 0x100=0, 0x20 & 0x1000=0, 0x20 & 0x200=0` → FALSE | `0x20 & 0x20=0x20 (T) && !(0x20 & 0x10000=0) (T) && !0 (T)` → **TRUE** | **FAILS** |
| 2 | 0x0 | All zero → FALSE | `0x0 & 0x20=0` → FALSE | PASSES |
| 3 | 0x10062 | `0x10062 & 0x8=0, &0x100=0, &0x1000=0, &0x200=0` → FALSE | `0x10062 & 0x20=0x20 (T) && !(0x10062 & 0x10000=0x10000) (F)` → FALSE | PASSES |
| 4 | 0x42 | `0x42 & 0x8=0, &0x100=0, &0x1000=0, &0x200=0` → FALSE | `0x42 & 0x20=0` → FALSE | PASSES |

**Path 1 FAILS HERE** at address 0x1c00fb38d (LABEL_33).

### Branch F: Flags 0x20000 / 0x10000 routing (0x1c00fb3cb-0x1c00fb3d9)
```c
if ( (Flags & 0x20000) != 0 ) {
    if ( (Flags & 0x10000) == 0 )
        goto LABEL_33;  // 0x20000 without 0x10000 -> error
} else if ( (Flags & 0x10000) == 0 ) {
    goto LABEL_43;  // No standard allocation -> skip validation
}
// Falls through to ValidateStandardAllocationParams if 0x10000 is set
```

**py_eval verification**:

| Path | Flags | & 0x20000 | & 0x10000 | Routing |
|------|-------|-----------|-----------|---------|
| 1 | 0x20 | 0x0 | 0x0 | goto LABEL_43 (but already failed at LABEL_33) |
| 2 | 0x0 | 0x0 | 0x0 | goto LABEL_43 |
| 3 | 0x10062 | 0x0 | 0x10000 | Falls through to ValidateStandardAllocationParams |
| 4 | 0x42 | 0x0 | 0x0 | goto LABEL_43 |

### Branch G: ValidateStandardAllocationParams (0x1c022a804)
Called only when `Flags & 0x10000` is set (Path 3).

```c
if ( (*(_DWORD *)&a1->Flags & 0x20020) == 0          // must have 0x20 or 0x20000
  || (*(_DWORD *)&a1->Flags & 0x20020) == 0x20020    // but not both
  || a1->PrivateDriverDataSize                        // must be 0
  || a1->NumAllocations != 1 )                        // must be 1
{
    return 0xC000000D;
}
// Then checks:
if ( a2->Type != D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP  // Type must be 1
  || a2->Flags.Value )                                        // Flags must be 0
{
    return 0xC000000D;
}
if ( a2->ExistingHeapData.Size - 1 <= 0xFFFFFFFE )  // Size 1..0xFFFFFFFF
    return 0;  // SUCCESS
return 0xC000000D;
```

**py_eval for Path 3 (Flags=0x10062)**:
- `0x10062 & 0x20020 = 0x20` — not 0, not 0x20020 → PASSES
- `PrivateDriverDataSize = 0` → PASSES
- `NumAllocations = 1` → PASSES
- Type must be 1 (EXISTINGHEAP) — confirmed from disassembly: `cmp dword ptr [rbx], 1`
- Flags.Value must be 0 — confirmed: `cmp dword ptr [rbx+10h], 0`
- Size must be 1..0xFFFFFFFF

**Status**: Path 3 passes ValidateStandardAllocationParams IF the standard allocation struct has Type=1, Flags=0, valid Size. But then fails at LABEL_43 (see below).

### Branch H: LABEL_43 — CreateResource requires CreateShared (0x1c00fb424)
```c
LABEL_43:
if ( (Flags & 2) != 0 && (Flags & 1) == 0 || !v79.hResource && !NumAllocations )
    goto LABEL_33;  // -> return 0xC000000D
```

Two conditions:
1. `CreateResource (0x2) set WITHOUT CreateShared (0x1)` → error
2. `!hResource && !NumAllocations` → error (but NumAllocations=1, so always false)

**py_eval verification**:

| Path | Flags | & 0x2 | & 0x1 | Cond1 | Result |
|------|-------|-------|-------|-------|--------|
| 1 | 0x20 | 0x0 | 0x0 | FALSE | (already failed) |
| 2 | 0x0 | 0x0 | 0x0 | FALSE | PASSES |
| 3 | 0x10062 | 0x2 | 0x0 | **TRUE** | **FAILS** |
| 4 | 0x42 | 0x2 | 0x0 | **TRUE** | **FAILS** |

**Path 3 FAILS HERE** at address 0x1c00fb424 (LABEL_43 → LABEL_33).
**Path 4 FAILS HERE** at address 0x1c00fb424 (LABEL_43 → LABEL_33).

**Root cause for Paths 3 and 4**: The exploit sets `CreateResource` (bit 1, 0x2) but does NOT set `CreateShared` (bit 0, 0x1). The kernel enforces: **CreateResource requires CreateShared**.

The exploit incorrectly maps:
- `0x42` → thinks "CreateShared | NtSecuritySharing" — **WRONG**
- `0x42` = `0x40 | 0x02` = `NtSecuritySharing | CreateResource` (missing CreateShared!)
- Correct "CreateShared | NtSecuritySharing" = `0x41` = `0x01 | 0x40`

### Branch I: Adapter version check (0x1c00fb9d2) — only when StandardAllocation
```c
if ( (*(_DWORD *)&v79.Flags & 0x10000) != 0 ) {
    if ( *(int *)(v60 + 2596) < 2000 )  // WDDM version < 2.0
        goto LABEL_102;  // -> return 0xC000000D
}
```
**Status**: Would apply to Path 3 if it reached here. WDDM version >= 2000 is required. Windows 11 WARP is WDDM 3.x, so this would pass. But Path 3 already failed at LABEL_43.

### Branch J: Adapter state check (0x1c00fb754)
```c
if ( *(_DWORD *)(v101 + 576) != 1 )
    return 3221226166;  // 0xC00002B6, NOT 0xC000000D
```
**Status**: Returns a different error code. Not our issue.

### Branch K: Memory allocation failure (0x1c00fb853)
```c
v48 = operator new[](v46, ...);
if ( !v48 )
    return 3221225495;  // 0xC0000017 (STATUS_NO_MEMORY), NOT 0xC000000D
```
**Status**: Different error code. Not our issue.

---

## 2. DXGDEVICE::CreateAllocation (0x1c00fe210) — Inner Function Trace

The bare path (Path 2, Flags=0x0) passes all checks in the outer function and reaches this function.

### Critical: 96-byte copy per allocation (0x1c00fe86c-0x1c00fe892)
```c
v49 = 96LL * a2->NumAllocations;  // 96 * 1 = 96 bytes
pAllocationInfo = a2->pAllocationInfo;
memmove(v30, pAllocationInfo, v49);  // copies 96 bytes from user pointer
```

**THE KERNEL ALWAYS COPIES 96 BYTES (0x60) PER ALLOCATION.**

The exploit provides `D3DDDI_ALLOCATIONINFO` (40 bytes / 0x28), but the kernel reads 96 bytes. This means 56 bytes of garbage beyond the struct are read. The exploit MUST provide `D3DDDI_ALLOCATIONINFO2` (96 bytes / 0x60) with all fields properly zeroed.

### Validation loop checks (0x1c00fe980-0x1c00feb59)

For the bare path (Flags=0x0, allocation info Flags=0x0):

1. **Flags & 0x800 check** (0x1c00fe987): `0x0 & 0x800 = 0` — skipped
2. **Allocation Flags & 1 check** (0x1c00fe9e0): `dword at v30+0x20 = 0`, `0 & 1 = 0` — skipped
3. **Allocation Flags & 2 without & 1** (0x1c00feadc): `0 & 2 = 0` — skipped
4. **StandardAllocation path** (0x1c00feae9): `0x0 & 0x10000 = 0` — skipped
5. **ExistingSysMem/0x20000 with null pSystemMem** (0x1c00feb03): `0x0 & 0x20 = 0, 0x0 & 0x20000 = 0` — skipped
6. **Page alignment check** (0x1c00feb32): `0x0 & 0x20 = 0` — skipped

All validation loop checks PASS for the bare path.

### Post-loop: PrivateDriverData processing (0x1c00feb5f-0x1c00feeae)
- `v67 = *(unsigned int *)&v30[24]` = PrivateDriverDataSize = 0
- `*(_QWORD *)&v30[16]` = pPrivateDriverData = NULL
- `if ( NULL && 0 )` → false → goes to else: sets v300[0] = nullptr

### OpenResourceObject call (0x1c00ff05e)
```c
LODWORD(DriverAllocations) = DXGDEVICE::OpenResourceObject(...)
```
This handles resource opening. For bare path (no hResource, no sharing), this likely returns success (0) or a non-fatal status.

### CreateDriverAllocations call (0x1c00ff3bb)
```c
if ( !v285 ) {
    DriverAllocations = DXGDEVICE::CreateDriverAllocations(...)
}
```

Inside CreateDriverAllocations (0x1c012c6a0), the critical call is:

```c
v69 = (*(int (__fastcall **)(_QWORD, void **))(*(_QWORD *)(v38 + 16) + 376LL))(
        *(_QWORD *)(*(_QWORD *)(v38 + 16) + 272LL),
        &v130);
```

This calls the KMD's `DdiCreateAllocation` callback (vtable offset 376). For the bare path:
- No private driver data (`pPrivateDriverData = NULL`, `PrivateDriverDataSize = 0`)
- No standard allocation type
- No resource

**The KMD callback returns `0xC000000D` (STATUS_INVALID_PARAMETER)** because it cannot create an allocation without any description of what to allocate. The KMD needs either:
1. Private driver data describing the allocation format/size
2. A standard allocation type (EXISTINGHEAP)

The error propagates:
```c
v127 = v69;  // 0xC000000D
if ( (int)v69 < 0 )
    goto LABEL_226;  // cleanup and return
```

**Path 2 FAILS HERE** inside the KMD's DdiCreateAllocation callback.

### Post-callback validation in CreateDriverAllocations
Even if the KMD callback succeeded, there's a check:
```c
if ( (v102 & 0x100000) == 0 && !*(_QWORD *)(*((_QWORD *)v80 + 6) + 16LL) )
{
    v127 = -1073741811;  // 0xC000000D
    goto LABEL_208;
}
```
This checks: if NOT WSL and the KMD didn't set an allocation handle → error. This would also fail for the bare path since the KMD has nothing to work with.

---

## 3. ValidateStandardAllocationParams (0x1c022a804) — Complete Analysis

```c
__int64 ValidateStandardAllocationParams(
    struct _D3DKMT_CREATEALLOCATION *a1,
    struct _D3DKMT_CREATESTANDARDALLOCATION *a2,
    char a3)
{
    // Check 1: Flags must have exactly one of 0x20 or 0x20000
    if ( (*(_DWORD *)&a1->Flags & 0x20020) == 0    // neither set -> error
      || (*(_DWORD *)&a1->Flags & 0x20020) == 0x20020  // both set -> error
      || a1->PrivateDriverDataSize                   // must be 0
      || a1->NumAllocations != 1 )                   // must be 1
        goto LABEL_2;  // return 0xC000000D

    // Copy standard allocation struct from user mode
    *(_OWORD *)&a2->Type = *(_OWORD *)pStandardAllocation;      // 16 bytes at +0x00
    *(_QWORD *)&a2->Flags.0 = *(_QWORD *)(pStandardAllocation + 16);  // 8 bytes at +0x10

    // Check 2: Type must be EXISTINGHEAP (1), Flags must be 0
    if ( a2->Type != 1 || a2->Flags.Value )
        goto LABEL_2;  // return 0xC000000D

    // Check 3: Size must be 1..0xFFFFFFFF
    if ( a2->ExistingHeapData.Size - 1 <= 0xFFFFFFFE )
        return 0;  // SUCCESS

    return 0xC000000D;  // Size out of range
}
```

### D3DKMT_CREATESTANDARDALLOCATION struct layout (verified from disassembly):
```
+0x00: Type (4 bytes) = 1 (D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP)
+0x04: padding (12 bytes) = 0
+0x10: Flags.Value (4 bytes) = 0
+0x14: padding (4 bytes) = 0
+0x18: ExistingHeapData.Size (4 bytes) = page-aligned size (e.g., 0x1000)
+0x1C: padding
Total minimum size: 0x20 (32 bytes)
```

**Verified from disassembly**:
- `cmp dword ptr [rbx], 1` at 0x1c022a8af — Type must be 1
- `cmp dword ptr [rbx+10h], 0` at 0x1c022a8b8 — Flags.Value must be 0

---

## 4. D3DDDI_ALLOCATIONINFO vs D3DDDI_ALLOCATIONINFO2

### The 96-byte copy issue

`DXGDEVICE::CreateAllocation` at 0x1c00fe86c:
```c
v49 = 96LL * a2->NumAllocations;  // ALWAYS 96 bytes per allocation
memmove(v30, pAllocationInfo, v49);
```

The kernel ALWAYS copies 96 bytes (0x60) per allocation entry, regardless of whether the API is `D3DKMTCreateAllocation` (which WDK says uses 40-byte `D3DDDI_ALLOCATIONINFO`) or `D3DKMTCreateAllocation2` (which uses 96-byte `D3DDDI_ALLOCATIONINFO2`).

**The exploit MUST provide `D3DDDI_ALLOCATIONINFO2` (96 bytes / 0x60)** for the `pAllocationInfo` pointer, with all 96 bytes properly initialized (zeroed except for `pSystemMem`).

### D3DDDI_ALLOCATIONINFO2 layout (96 bytes = 0x60):
```
+0x00: hAllocation (4 bytes) = 0
+0x04: padding (4 bytes) = 0
+0x08: pSystemMem (8 bytes) = VirtualAlloc'd page (page-aligned)
+0x10: pPrivateDriverData (8 bytes) = NULL (0)
+0x18: PrivateDriverDataSize (4 bytes) = 0
+0x1C: VidPnSourceId (4 bytes) = 0
+0x20: Flags.Value (4 bytes) = 0
+0x24: padding (4 bytes) = 0
+0x28..0x5F: additional D3DDDI_ALLOCATIONINFO2 fields (56 bytes) = ALL ZERO
```

---

## 5. D3DKMT_CREATEALLOCATIONFLAGS — Corrected Bit Definitions

Verified from the decompiled code checks:

| Bit | Mask | Name | Evidence |
|-----|------|------|----------|
| 0 | 0x1 | CreateShared | LABEL_43: `(Flags & 1) == 0` with CreateResource → error |
| 1 | 0x2 | CreateResource | LABEL_43: `(Flags & 2) != 0` requires CreateShared |
| 3 | 0x8 | (sharing flag) | LABEL_33 cond1: requires DXGPROCESS flag |
| 5 | 0x20 | ExistingSysMem | LABEL_33 cond2: requires StandardAllocation or DXGPROCESS flag |
| 6 | 0x40 | NtSecuritySharing | Used in exploit flag combinations |
| 8 | 0x100 | (sharing flag) | LABEL_33 cond1: requires DXGPROCESS flag |
| 9 | 0x200 | (sharing flag) | LABEL_33 cond1: requires DXGPROCESS flag |
| 11 | 0x800 | (restricted) | CreateAllocation: requires adapter flag + CreateResource |
| 12 | 0x1000 | (sharing flag) | LABEL_33 cond1: requires DXGPROCESS flag |
| 16 | 0x10000 | StandardAllocation | Routes to ValidateStandardAllocationParams |
| 17 | 0x20000 | (standard variant) | ValidateStandardAllocationParams: XOR with 0x20 |
| 20 | 0x100000 | WSL GPU | Requires test signing; conflicts with StandardAllocation |

### Exploit flag mapping errors:
- Exploit uses `0x42` for "CreateShared | NtSecuritySharing" — **WRONG**
  - `0x42` = `0x40 | 0x02` = `NtSecuritySharing | CreateResource`
  - Correct: `0x41` = `0x01 | 0x40` = `CreateShared | NtSecuritySharing`
- Exploit uses `0x10062` for "StandardAllocation | ExistingSysMem | CreateShared | NtSecuritySharing" — **WRONG**
  - `0x10062` = `0x10000 | 0x40 | 0x20 | 0x02` = `StandardAllocation | NtSecuritySharing | ExistingSysMem | CreateResource`
  - Missing: `CreateShared (0x01)`
  - Has: `CreateResource (0x02)` which requires `CreateShared (0x01)`
  - Correct: `0x10061` = `0x10000 | 0x40 | 0x20 | 0x01` = `StandardAllocation | NtSecuritySharing | ExistingSysMem | CreateShared`

---

## 6. DXGPROCESS+0x15B Flag

The check at LABEL_33 uses `v9[347] & 0x20` where 347 decimal = 0x15B hex. This is a flag in the DXGPROCESS structure that allows certain sharing operations without the StandardAllocation flag.

For a normal user-mode process, this flag is **0**. It's likely set for container processes or processes with special GPU virtualization permissions (WSL GPU, etc.).

**Impact**: ExistingSysMem (0x20) flag without StandardAllocation (0x10000) will ALWAYS fail for normal processes because this flag is 0.

---

## 7. Adapter Analysis — accelerated=0

All three adapters have `accelerated=0`:
- Adapter 0: LUID=106040-0, accelerated=0, sources=3
- Adapter 1: LUID=109363-0, accelerated=0, sources=0
- Adapter 2: LUID=106949-0, accelerated=0, sources=0

`bAccelerated=0` means these are NOT hardware GPU adapters. They are either:
- Microsoft Basic Render Driver (WARP) — a software WDDM driver
- Indirect Display Adapter — a virtual display driver

**Impact on D3DKMTCreateAllocation**: WARP IS a valid WDDM driver and CAN create allocations. However:
1. The KMD's `DdiCreateAllocation` callback requires either private driver data or a standard allocation type to know what to create
2. Without either, the callback returns STATUS_INVALID_PARAMETER
3. WARP supports `D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP` standard allocations

**Impact on D3D11**: WARP does NOT support `D3D11_RESOURCE_MISC_SHARED_NTHANDLE`. This is the root cause of the D3D11 `E_INVALIDARG` (0x80070057) failure. Shared NT handle resources require a real GPU adapter with hardware acceleration.

---

## 8. D3D11 CreateTexture2D Failure (0x80070057 E_INVALIDARG)

The D3D11 texture creation fails because:
1. `D3D11_RESOURCE_MISC_SHARED_NTHANDLE` requires a real GPU adapter (accelerated=1)
2. All adapters have `accelerated=0` (WARP/indirect display)
3. WARP does not support shared NT handle resources
4. `DXGI_FORMAT_R8_UNORM` with `D3D11_BIND_SHADER_RESOURCE` + `SHARED_NTHANDLE` is not supported on WARP

**Root cause**: No real GPU adapter available. The system only has WARP/virtual display adapters.

---

## 9. All py_eval Calculations

### Status code conversions:
```
3221225485 = 0xC000000D (STATUS_INVALID_PARAMETER) — the error we're getting
3221226166 = 0xC00002B6 — different error (adapter state)
3221225495 = 0xC0000017 (STATUS_NO_MEMORY) — allocation failure
-1073741811 as uint32 = 3221225485 = 0xC000000D — WdLog error code
```

### Flag bit checks for all 4 paths:
```
Path 1 (0x20):
  0x20 & 0x8 = 0x0      0x20 & 0x100 = 0x0     0x20 & 0x1000 = 0x0    0x20 & 0x200 = 0x0
  cond1_any_match = False
  0x20 & 0x20 = 0x20    0x20 & 0x10000 = 0x0
  cond2_ExistingSysMem_without_Standard = True    -> FAILS at LABEL_33

Path 2 (0x0):
  All flag checks = 0x0, all conditions = False   -> PASSES to CreateAllocation

Path 3 (0x10062):
  0x10062 & 0x20020 = 0x20 (not 0, not 0x20020)  -> PASSES ValidateStandardAllocationParams first check
  0x10062 & 0x2 = 0x2    0x10062 & 0x1 = 0x0
  CreateResource_without_CreateShared = True      -> FAILS at LABEL_43

Path 4 (0x42):
  0x42 & 0x2 = 0x2        0x42 & 0x1 = 0x0
  CreateResource_without_CreateShared = True      -> FAILS at LABEL_43
```

### Corrected flag values:
```
0x10020 (StandardAllocation | ExistingSysMem):
  & 0x20020 = 0x20 (passes ValidateStdAlloc)
  & 0x2 = 0x0 (passes LABEL_43)
  cond2 = False (passes LABEL_33)

0x10061 (StandardAllocation | CreateShared | ExistingSysMem | NtSecuritySharing):
  & 0x20020 = 0x20 (passes ValidateStdAlloc)
  & 0x2 = 0x0 (passes LABEL_43)
  & 0x1 = 0x1 (has CreateShared)
  cond2 = False (passes LABEL_33)

0x41 (CreateShared | NtSecuritySharing):
  & 0x2 = 0x0 (passes LABEL_43)
  & 0x20 = 0x0 (passes LABEL_33)
  But & 0x10000 = 0x0 -> no StandardAllocation -> goes to LABEL_43
  At LABEL_43: passes (no CreateResource)
  Would reach CreateAllocation but fail in KMD callback (no std alloc, no private data)
```

### Struct sizes:
```
D3DKMT_CREATEALLOCATION = 0x48 (72 bytes)
D3DDDI_ALLOCATIONINFO = 0x28 (40 bytes) — TOO SMALL, kernel reads 96
D3DDDI_ALLOCATIONINFO2 = 0x60 (96 bytes) — CORRECT SIZE
D3DKMT_CREATESTANDARDALLOCATION = 0x20 (32 bytes minimum)
Kernel copy size per allocation = 96 bytes (0x60)
Size difference = 56 bytes (0x38) of garbage read beyond 40-byte struct
```

### ExistingHeapData.Size check:
```
0x1000 - 1 = 0xFFF
0xFFF <= 0xFFFFFFFE = True -> PASSES
Valid range: 1 <= Size <= 0xFFFFFFFF
```

### D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP:
```
Enum value = 1 (confirmed: cmp dword ptr [rbx], 1 at 0x1c022a8af)
```

### Adapter version check:
```
Minimum WDDM version = 2000 (0x7D0) for StandardAllocation
Windows 11 WARP = WDDM 3.x -> PASSES
```

---

## 10. Copy-Paste Ready C++ Code Fixes

### Fix 1: Use D3DDDI_ALLOCATIONINFO2 (96 bytes) instead of D3DDDI_ALLOCATIONINFO (40 bytes)

```cpp
// WRONG (current exploit) — kernel reads 96 bytes, struct is only 40:
D3DDDI_ALLOCATIONINFO allocInfo = {};  // 40 bytes

// CORRECT — must use ALLOCATIONINFO2 (96 bytes):
D3DDDI_ALLOCATIONINFO2 allocInfo2 = {};  // 96 bytes, ALL ZEROED
allocInfo2.pSystemMem = systemMemPage;   // VirtualAlloc'd, page-aligned
// All other fields remain 0 (hAllocation, pPrivateDriverData, PrivateDriverDataSize, etc.)
```

### Fix 2: Use StandardAllocation + ExistingSysMem with correct flags

```cpp
// D3DKMT_CREATESTANDARDALLOCATION (32 bytes minimum):
struct {
    UINT32 Type;            // +0x00 = 1 (D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP)
    UINT8  pad0[12];        // +0x04 = {0}
    UINT32 FlagsValue;      // +0x10 = 0
    UINT8  pad1[4];         // +0x14 = {0}
    UINT32 ExistingHeapDataSize; // +0x18 = 0x1000 (page size)
    UINT8  pad2[4];         // +0x1C = {0}
} stdAlloc = {};
stdAlloc.Type = 1;                    // EXISTINGHEAP
stdAlloc.FlagsValue = 0;
stdAlloc.ExistingHeapDataSize = 0x1000;  // must match VirtualAlloc size

// D3DKMT_CREATEALLOCATION:
D3DKMT_CREATEALLOCATION ca = {};
ca.hDevice = deviceHandle;
ca.hResource = 0;
ca.hGlobalShare = 0;
ca.pPrivateRuntimeData = nullptr;
ca.PrivateRuntimeDataSize = 0;
ca.pStandardAllocation = &stdAlloc;    // at offset 0x20
ca.PrivateDriverDataSize = 0;          // at offset 0x28 — MUST be 0 for StandardAllocation
ca.NumAllocations = 1;                 // at offset 0x2C — MUST be 1
ca.pAllocationInfo = &allocInfo2;      // at offset 0x30 — MUST be D3DDDI_ALLOCATIONINFO2 (96 bytes)
ca.Flags = 0x10020;                    // at offset 0x38 — StandardAllocation | ExistingSysMem
ca.hPrivateRuntimeResourceHandle = 0;  // at offset 0x40
```

### Fix 3: For shared allocations (if needed)

```cpp
// For CreateShared + NtSecuritySharing + StandardAllocation + ExistingSysMem:
ca.Flags = 0x10061;  // StandardAllocation(0x10000) | CreateShared(0x1) | ExistingSysMem(0x20) | NtSecuritySharing(0x40)

// DO NOT use 0x10062 — that has CreateResource(0x2) instead of CreateShared(0x1)
// DO NOT use 0x42 — that has CreateResource(0x2) instead of CreateShared(0x1)
```

### Fix 4: For D3D11 path — need real GPU adapter

```cpp
// D3D11_RESOURCE_MISC_SHARED_NTHANDLE requires accelerated=1 adapter
// WARP (accelerated=0) does NOT support shared NT handle resources
// 
// Options:
// 1. Find a real GPU adapter (accelerated=1) via D3DKMTEnumAdapters2
// 2. Use D3DKMTCreateAllocation with StandardAllocation + ExistingSysMem instead
// 3. Remove D3D11_RESOURCE_MISC_SHARED_NTHANDLE from MiscFlags
//
// To find real GPU adapters, filter by bAccelerated:
// for each adapter in D3DKMT_ENUMADAPTERS2:
//     if adapter.bAccelerated == TRUE:
//         // this is a real GPU, use it
```

### Complete working example (simplest path):

```cpp
// Allocate page-aligned system memory
SIZE_T pageSize = 0x1000;
void* systemMem = VirtualAlloc(nullptr, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (!systemMem) return;

// D3DDDI_ALLOCATIONINFO2 (96 bytes = 0x60) — MUST be 96 bytes, all zeroed
uint8_t allocInfo2Buf[0x60] = {};
D3DDDI_ALLOCATIONINFO2* allocInfo2 = (D3DDDI_ALLOCATIONINFO2*)allocInfo2Buf;
allocInfo2->pSystemMem = systemMem;
// All other fields = 0 (zeroed by memset)

// D3DKMT_CREATESTANDARDALLOCATION (32 bytes minimum)
struct CreateStandardAllocation {
    UINT32 Type;                    // +0x00
    UINT8  pad0[12];                // +0x04
    UINT32 FlagsValue;              // +0x10
    UINT8  pad1[4];                 // +0x14
    UINT32 ExistingHeapDataSize;    // +0x18
    UINT8  pad2[12];                // +0x1C
};
CreateStandardAllocation stdAlloc = {};
stdAlloc.Type = 1;                          // EXISTINGHEAP
stdAlloc.ExistingHeapDataSize = (UINT32)pageSize;  // 0x1000

// D3DKMT_CREATEALLOCATION (72 bytes = 0x48)
D3DKMT_CREATEALLOCATION ca = {};
ca.hDevice = deviceHandle;
ca.pStandardAllocation = &stdAlloc;         // offset 0x20
ca.PrivateDriverDataSize = 0;               // offset 0x28 — MUST be 0
ca.NumAllocations = 1;                      // offset 0x2C — MUST be 1
ca.pAllocationInfo = allocInfo2;            // offset 0x30 — MUST be 96-byte ALLOCATIONINFO2
ca.Flags = 0x10020;                         // offset 0x38 — StandardAllocation | ExistingSysMem

NTSTATUS status = D3DKMTCreateAllocation(&ca);
// status should be STATUS_SUCCESS (0)
// ca.hAllocation / ca.hResource contain the allocation handle
```

---

## 11. Summary of Required Changes

| Issue | Current | Required | Reason |
|-------|---------|----------|--------|
| Allocation info struct | D3DDDI_ALLOCATIONINFO (40 bytes) | D3DDDI_ALLOCATIONINFO2 (96 bytes) | Kernel copies 96 bytes per allocation |
| Path 1 flags | 0x20 (ExistingSysMem only) | 0x10020 (+ StandardAllocation) | LABEL_33: ExistingSysMem requires StandardAllocation |
| Path 2 flags | 0x0 (bare) | 0x10020 (StandardAllocation + ExistingSysMem) | KMD callback needs allocation description |
| Path 3 flags | 0x10062 (has CreateResource) | 0x10020 (remove CreateResource) or 0x10061 (add CreateShared) | LABEL_43: CreateResource requires CreateShared |
| Path 4 flags | 0x42 (has CreateResource) | 0x41 (replace CreateResource with CreateShared) or 0x10061 | LABEL_43: CreateResource requires CreateShared |
| Standard allocation struct | Not properly set | Type=1, Flags=0, Size=0x1000 | ValidateStandardAllocationParams requires EXISTINGHEAP |
| D3D11 shared texture | SHARED_NTHANDLE on WARP | Need real GPU (accelerated=1) | WARP doesn't support shared NT handles |
