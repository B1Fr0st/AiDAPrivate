# D3DKMTCreateAllocation Crash Fix

## Problem

D3DKMTCreateAllocation crashes with 0xC0000005 (ACCESS_VIOLATION) in GDI32.dll's thunk code at RVA +0x3814. This happens on ALL three adapters with ALL flag combinations (ExistingSysMem, bare, StandardAllocation+Shared). Even with 512-byte zero-padded buffers, the crash persists.

## Root Cause

On Windows 10 22H2 (build 19045), D3DKMT functions are forwarded from gdi32.dll to gdi32full.dll via forwarding stubs. The crash at GDI32.dll+0x3814 occurs inside the forwarding stub code, not in the actual D3DKMT implementation. The forwarding stub has a bug or incompatibility that causes an access violation when marshaling the D3DKMT_CREATEALLOCATION struct.

## Fixes Applied

### Approach 1: gdi32full.dll Resolution (Primary Fix)

Modified `D3DKMTApi::Init()` to resolve D3DKMT function pointers from gdi32full.dll first, falling back to gdi32.dll only if gdi32full.dll is unavailable.

```
gdi32full.dll → gdi32.dll (fallback)
```

This bypasses the broken forwarding stub in gdi32.dll entirely. On Windows 10 22H2, gdi32full.dll contains the actual D3DKMT implementations, while gdi32.dll only contains thin forwarding stubs that crash.

**File:** `D3DKMTApi::Init()` (around line 530)
**Change:** Added gdi32full.dll load attempt before gdi32.dll, stored module handle in `m_gdiModule`.

### Approach 2: D3D11-Based Allocation Path (Fallback)

Added `CreateDanglingMappingsViaD3D11()` method to the `DanglingMapping` class. This completely bypasses manual struct marshaling — D3D11 handles all the private driver data correctly.

**Flow:**
1. Load `D3D11CreateDevice` from d3d11.dll via GetProcAddress
2. Create D3D11 device (HARDWARE driver, WARP fallback)
3. Get DXGI adapter LUID and match to D3DKMT adapter
4. Create D3DKMT device on matching adapter
5. Create D3D11 texture (1x1 R8_UNORM, DEFAULT usage, SHARED_NTHANDLE|SHARED_KEYEDMUTEX)
6. Query IDXGIResource1, call CreateSharedHandle → NT handle
7. Call D3DKMTOpenResourceFromNtHandle → D3DKMT allocation handle
8. D3DKMTLock → CPU VA (type 5 path, non-CPU-visible allocation)
9. D3DKMTDestroyAllocation (no unlock) → dangling VA

**Trigger:** If `CreateDanglingMappings()` produces fewer than 16 mappings via the direct D3DKMTCreateAllocation path, it automatically falls back to `CreateDanglingMappingsViaD3D11()`.

**File:** `DanglingMapping::CreateDanglingMappingsViaD3D11()` (new method, ~200 lines)
**Dependencies:** d3d11.lib, dxgi.lib, d3d11.h, dxgi1_2.h

### Approach 3: D3DKMTCreateAllocation2 (Additional Fallback)

Added resolution of `D3DKMTCreateAllocation2` from gdi32.dll/gdi32full.dll. This function uses `D3DDDI_ALLOCATIONINFO2` (96 bytes, includes SegmentPreference/SegmentId fields) instead of `D3DDDI_ALLOCATIONINFO` (40 bytes).

Added a 4th attempt in the allocation loop: after ExistingSysMem, bare, and StandardAllocation+Shared all fail, it tries CreateAllocation2 with CreateShared+NtSecuritySharing flags and D3DDDI_ALLOCATIONINFO2.

**File:** `DanglingMapping::CreateDanglingMappings()` inner loop
**Change:** Added CreateAllocation2 attempt after StandardAllocation+Shared failure path.

## New Types Added

### D3DDDI_OPENALLOCATIONINFO2 (80 bytes)
Used by D3DKMTOpenResourceFromNtHandle. Layout derived from IDA decompilation of `OpenResourceFromGlobalHandleOrNtObject<_D3DKMT_OPENRESOURCEFROMNTHANDLE>` in dxgkrnl.sys:
- 0x00: hAllocation (D3DKMT_HANDLE, output)
- 0x08: pPrivateDriverData (pointer, output)
- 0x10: PrivateDriverDataSize (UINT, output)
- 0x18: GpuVirtualAddress (UINT64)
- 0x20-0x4F: Reserved (40 bytes)

### D3DKMT_OPENRESOURCEFROMNTHANDLE (104 bytes / 0x68)
Layout verified from IDA decompilation. The kernel copies 104 bytes (7 OWORDs + 1 QWORD) from user mode:
- 0x00: hDevice (D3DKMT_HANDLE)
- 0x08: hNtHandle (HANDLE)
- 0x10: pOpenAllocationInfo (D3DDDI_OPENALLOCATIONINFO2*)
- 0x18: AllocationCount (UINT)
- 0x20: PrivateRuntimeDataSize (UINT)
- 0x28: pPrivateRuntimeData (pointer)
- 0x30: ResourcePrivateDriverDataSize (UINT)
- 0x38: pResourcePrivateDriverData (pointer)
- 0x40: TotalPrivateDriverDataSize (UINT)
- 0x48: Flags (D3DKMT_CREATEALLOCATIONFLAGS)
- 0x50: hResource (D3DKMT_HANDLE, OUTPUT)
- 0x58: pTotalPrivateDriverData (pointer, OUTPUT)
- 0x60: KeyedMutexHandle (UINT64, for keyed mutex resources)

## New API Functions Resolved

- `D3DKMTOpenResourceFromNtHandle` — from gdi32full.dll/gdi32.dll
- `D3DKMTCreateAllocation2` — from gdi32full.dll/gdi32.dll

## IDA Verification

- `DxgkOpenResourceFromNtHandle` at 0x1C012B660 in dxgkrnl.sys (pid=6892)
- `OpenResourceFromGlobalHandleOrNtObject<_D3DKMT_OPENRESOURCEFROMNTHANDLE>` at 0x1C012ABD4
- `DxgkCddOpenResourceFromNtHandle` at 0x1C022E540 (typed struct access confirms field names)
- D3DKMT_CREATEALLOCATION struct: 72 bytes, verified field order matches (IDA ordinal 894)
- D3DKMT_LOCK struct: 48 bytes, verified (IDA ordinal 1705)
- D3DDDI_ALLOCATIONINFO2 struct: 96 bytes, verified (IDA ordinal exists)

## Testing

Build the exploit and run it. The debug log will show:
1. Whether gdi32full.dll was loaded (Phase0)
2. Whether D3DKMTCreateAllocation succeeds via gdi32full.dll (Phase1)
3. If not, the D3D11 path will be attempted (Phase1-D3D11)
4. If D3D11 succeeds, dangling mappings will be created and the exploit continues normally
