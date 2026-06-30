# D3DKMTOpenResourceFromNtHandle Fix Summary

## Problem
`D3DKMTOpenResourceFromNtHandle` returned `0xC000000D` (STATUS_INVALID_PARAMETER) due to incorrect struct layouts, wrong field names, missing allocation info, and incompatible texture creation flags.

## Root Causes (5 bugs)

### Bug 1: D3DDDI_OPENALLOCATIONINFO2 Reserved[7] → Reserved[6]
- **IDA layout**: `Reserved` is `ULONG_PTR[6]` = 48 bytes, total struct = 80 bytes (0x50)
- **Code had**: `UINT64 Reserved[7]` = 56 bytes, total = 88 bytes (0x58)
- **Kernel impact**: Kernel allocates `80 * NumAllocations` and uses 80-byte stride in output loop. An 88-byte struct causes misaligned reads/writes of hAllocation.
- **Fix**: Changed `Reserved[7]` to `Reserved[6]` (line 312)

### Bug 2: Duplicate D3DDDI_OPENALLOCATIONINFO2 definition
- **Code had**: Two `typedef struct _D3DDDI_OPENALLOCATIONINFO2` definitions (lines 305-313 and 315-324)
- The second definition had completely wrong fields (`pSystemMem`, `VidPnSourceId`, `Flags`, `SegmentPreference`, `SegmentId`) — these belong to D3DDDI_ALLOCATIONINFO (v1), not v2
- Would cause C++ redefinition error
- **Fix**: Removed the second (wrong) definition entirely

### Bug 3: D3DKMT_OPENRESOURCEFROMNTHANDLE Pad5 overlap
- **IDA layout**: `pKeyedMutexPrivateRuntimeData` (8 bytes) at +0x58
- **Code had**: `UINT Pad5` (4 bytes) at +0x58 AND `pKeyedMutexPrivateRuntimeData` (8 bytes) also at +0x58 — overlapping fields without a union
- **Impact**: C compiler lays out Pad5 at +0x58, then pointer at +0x60 (8-byte aligned), shifting all subsequent fields by 8 bytes. Struct becomes 108-112 bytes instead of 104. Kernel copies exactly 0x68=104 bytes, so fields after +0x58 are read/written at wrong offsets.
- **Fix**: Removed `Pad5` (was at line 344). Now pKeyedMutexPrivateRuntimeData correctly sits at +0x58.

### Bug 4: Wrong field names in struct fill code
- **Code used**: `openRes->pOpenAllocationInfo`, `openRes->AllocationCount`, `openRes->Flags.Value`, `openRes->Flags.NtSecuritySharing`
- **IDA struct has**: `pOpenAllocationInfo2`, `NumAllocations`, no Flags field at all
- These wrong field names don't exist in the corrected struct → compile error
- **Fix**: Changed to `openRes->NumAllocations = 1`, `openRes->pOpenAllocationInfo2 = allocInfo`, removed Flags lines

### Bug 5: Missing NumAllocations and pOpenAllocationInfo2
- **Code had**: NumAllocations was 0 (struct zeroed), pOpenAllocationInfo2 was NULL
- **Kernel validation** (`OpenResourceFromGlobalHandleOrNtObject` at 0x1c012abd4):
  - Checks `!TotalPrivateDriverDataBufferSize && !ResourcePrivateDriverDataSize` → reject if both 0
  - Checks `NumAllocations` matches shared resource's allocation count
  - Allocates `80 * NumAllocations` bytes for internal D3DDDI_OPENALLOCATIONINFO2 array
  - Writes hAllocation output to user's `pOpenAllocationInfo2[i].hAllocation`
- **Fix**: Set `NumAllocations = 1`, provided valid `allocInfo` pointer, added `TotalPrivateDriverDataBufferSize = 4096` with `pTotalPrivateDriverDataBuffer` pointing to a 4096-byte buffer

## Additional Fix: Texture Creation Flags

### SHARED_KEYEDMUTEX removal
- **Code had**: `D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX`
- **Kernel impact** (`DxgkOpenResourceFromNtHandle` at 0x1c012b660): When the shared object has a keyed mutex, the kernel calls `DXGKEYEDMUTEX::Open` with `pKeyedMutexPrivateRuntimeData` and `KeyedMutexPrivateRuntimeDataSize` from the struct. With SHARED_KEYEDMUTEX, the kernel expects these fields to be valid.
- **Fix**: Changed to `D3D11_RESOURCE_MISC_SHARED_NTHANDLE` only. Without KEYEDMUTEX, the shared object has no keyed mutex pointer, and the kernel skips the `DXGKEYEDMUTEX::Open` call entirely.

### Staging texture
- **Code had**: `D3D11_USAGE_DEFAULT`, `D3D11_BIND_SHADER_RESOURCE`, `CPUAccessFlags = 0`
- **Fix**: Changed to `D3D11_USAGE_STAGING`, `BindFlags = 0`, `CPUAccessFlags = D3D11_CPU_ACCESS_READ | D3D11_CPU_ACCESS_WRITE`
- Staging textures are more likely to be in system memory (non-CPU-visible segment), which triggers the type 5 lock path — the dangling lock vulnerability target.

## Kernel Validation Flow (from IDA decompilation)

```
DxgkOpenResourceFromNtHandle (0x1c012b660)
  ├── Copies 0x68 bytes from user struct to kernel stack
  ├── ObReferenceObjectByHandle(hNtHandle) → shared allocation object
  ├── If shared object has keyed mutex: DXGKEYEDMUTEX::Open(pKeyedMutexPrivateRuntimeData, KeyedMutexPrivateRuntimeDataSize)
  ├── If shared object has sync object: DXGSYNCOBJECT::Open
  ├── Writes hKeyedMutex to +0x54, hSyncObject to +0x64
  └── OpenResourceFromGlobalHandleOrNtObject (0x1c012abd4)
       ├── Check: !TotalPrivateDriverDataBufferSize && !ResourcePrivateDriverDataSize → STATUS_INVALID_PARAMETER
       ├── DXGDEVICEBYHANDLE(hDevice) → device
       ├── Allocate 80 * NumAllocations for internal D3DDDI_OPENALLOCATIONINFO2 array
       ├── Allocate TotalPrivateDriverDataBufferSize, ResourcePrivateDriverDataSize, PrivateRuntimeDataSize buffers
       ├── Replace user pointers in kernel copy with kernel buffer pointers
       ├── DXGDEVICE::OpenResource (0x1c012b320)
       │    ├── Check NumAllocations matches shared resource count
       │    ├── Check PrivateRuntimeDataSize matches (if not VM)
       │    ├── Check ResourcePrivateDriverDataSize matches (if not VM)
       │    ├── Build internal D3DKMT_CREATEALLOCATION, call CreateAllocation
       │    └── Copy hAllocation to internal D3DDDI_OPENALLOCATIONINFO2 array
       └── Output loop: write hAllocation, pPrivateDriverData, PrivateDriverDataSize back to user's pOpenAllocationInfo2
           ├── Write hResource to user struct +0x50
           └── Update TotalPrivateDriverDataBufferSize at +0x40 with actual size
```

## hAlloc Extraction (verified correct)

The code at line 1144 reads `allocInfo->hAllocation` — this is the `hAllocation` field (offset +0x00) of the `D3DDDI_OPENALLOCATIONINFO2` struct, which the kernel fills during the output loop. This is correct and does NOT need to read from `openRes->hResource` (which is the resource handle, not the allocation handle).

The Lock call at line 1153 uses `hAlloc` (from `allocInfo->hAllocation`) as `lockData.hAllocation` — this is the correct allocation handle for `D3DKMTLock`.

## Files Modified
- `C:\Users\ruar1337\AiDAPrivate\driver\dxgkrnl_dangling_lock_exploit_verified.cpp`

## IDA Pro References
- `D3DKMT_OPENRESOURCEFROMNTHANDLE` type: 104 bytes, 15 members — confirmed layout
- `D3DDDI_OPENALLOCATIONINFO2` type: 80 bytes, 5 members — confirmed layout
- `DxgkOpenResourceFromNtHandle` (0x1c012b660): entry point, keyed mutex/sync object handling
- `OpenResourceFromGlobalHandleOrNtObject<_D3DKMT_OPENRESOURCEFROMNTHANDLE>` (0x1c012abd4): parameter validation, buffer allocation
- `DXGDEVICE::OpenResource<_D3DKMT_OPENRESOURCEFROMNTHANDLE>` (0x1c012b320): NumAllocations/PrivateRuntimeDataSize matching, CreateAllocation call, output writeback
