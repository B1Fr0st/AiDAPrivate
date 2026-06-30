# Fix Implementation: Section-Backed Dangling PTE Exploit

## 1. Root Cause Recap

The original exploit used `ExistingSysMem` (0x20) flag which caused `D3DKMTLock` to return the user's own `VirtualAlloc` pointer directly. No kernel mapping was created. The "dangling PTE" was just a valid user-mode `VirtualAlloc` mapping that was never freed. Physical pages were never returned to the PFN free list, so GDI SURFACE objects could never reclaim them.

## 2. Fix Strategy

Remove `ExistingSysMem` (0x20) and provide an `hSection` from `CreateFileMappingW`. This creates a real section-backed allocation where:

1. The kernel calls `ObReferenceObjectByHandle(hSection)` to get a section object
2. Stores it at `global_alloc+0x160`
3. Lock creates a NEW kernel mapping (via `MmMapViewOfSection` or driver MDL callback)
4. Destroy skips the unmap (same bug -- `CloseOneAllocation` checks `VIDMM_ALLOC+0x90` which is NULL for type 5)
5. The section's pages ARE freed to PFN (`VidMmDereferenceObjectAsync` drops section ref)
6. The PTE at `multi_alloc+0x10` persists -- REAL dangling mapping
7. SURFACE spray reclaims the freed pages

## 3. All Changes Made

### Change 1: BITMAP_SPRAY_INITIAL 4096 -> 8192 (line 100)

Increased the initial GDI bitmap spray from 4096 to 8192 bitmaps for better reclaim probability. With more bitmaps allocated, more CSectionEntry sections are created, increasing the chance that a freed PFN page is reclaimed by a SURFACE object.

### Change 2: MAX_SCAN_RETRIES 5 -> 10 (line 103)

Doubled the maximum scan retry count from 5 to 10. Each retry sprays an additional 220 bitmaps. With the section-backed approach, the physical pages are actually freed to the PFN free list, so more retries give more chances for SURFACE reclaim to succeed.

### Change 3: D3DDDI_ALLOCATIONINFO2 struct -- added hSection union member (lines 228-231)

Changed the `pSystemMem` field at +0x08 to a union containing both `pSystemMem` and `hSection`. Both are `VOID*`/`HANDLE` (8 bytes on x64) at the same offset. The kernel reads `hSection` from this offset for non-ExistingSysMem StandardAllocation paths (confirmed via IDA decompilation of `DXGDEVICE::CreateVidMmAllocations` at 0x1C0156710).

```cpp
union {
    VOID *pSystemMem;
    HANDLE hSection;
};
```

This does not change the struct size or layout -- the union is still 8 bytes at +0x08.

### Change 4: DanglingMapping class -- added m_sectionHandles vector (line 702)

Added `std::vector<HANDLE> m_sectionHandles` to track all section handles created during allocation. Handles are pushed to this vector for debugging/tracking purposes. Each handle is closed immediately after `CreateAllocation2` returns (success or failure), since the kernel obtains its own reference via `ObReferenceObjectByHandle`.

### Change 5: CreateDanglingMappings -- new section-backed primary allocation path (lines 786-887)

**This is the core fix.** Replaced the primary allocation path that used `VirtualAlloc` + `ExistingSysMem` + `D3DDDI_ALLOCATIONINFO` (40 bytes) + `CreateAllocation` with a new path that uses:

- `CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE | SEC_COMMIT, 0, 0x1000, nullptr)` to create a pagefile-backed section object
- `D3DDDI_ALLOCATIONINFO2` (96 bytes, 0x60) instead of `D3DDDI_ALLOCATIONINFO` (40 bytes, 0x28)
- `allocInfo2->hSection = hSection` at offset +0x08 (same union as pSystemMem)
- `Flags.Value = 0x10000` (StandardAllocation ONLY, no ExistingSysMem)
- `CreateAllocation2` instead of `CreateAllocation` (accepts 96-byte ALLOCATIONINFO2 structs)
- `D3DKMT_CREATESTANDARDALLOCATION` with `EXISTINGHEAP` type and `Size = 0x1000` (unchanged)

The kernel always copies 96 bytes per allocation from `pAllocationInfo` when `CreateAllocation2` is used. The old `CreateAllocation` only copies 40 bytes.

After successful creation, `CloseHandle(hSection)` is called because the kernel has its own reference via `ObReferenceObjectByHandle`.

The old ExistingSysMem path is preserved as a fallback inside `if (!sectionPrimaryOK)`. The existing fallback chain (bare, StdAlloc+ExistingSysMem, CreateAllocation2 with CreateShared) remains unchanged at its original indentation level. The `st` variable from the section-backed primary naturally gates the fallback chain: if the section-backed primary succeeds (`st >= 0`), the `if (st < 0)` fallback chain is skipped.

### Change 6: Removed redundant allocInfo2 declaration in fallback chain (line 938)

The fallback chain previously declared `D3DDDI_ALLOCATIONINFO2 *allocInfo2` locally inside the `if (m_api->CreateAllocation2)` block. Since `allocInfo2` is now declared at the top of the for loop body (line 791), this local declaration was removed to avoid shadowing.

### Change 7: Enhanced Lock logging -- pData vs hSection comparison (lines 1009-1034)

After `D3DKMTLock`, added comprehensive logging:

- Logs whether `pData` is in kernel space (`>= 0xFFFF800000000000`) or user space
- If section-backed primary was used: compares `pData` vs `hSection` -- if different, confirms a REAL kernel mapping was created (not the user's own pointer)
- Logs the address difference between `pData` and `hSection`
- If ExistingSysMem fallback was used: compares `pData` vs `sysMem` -- if same, confirms the old bug (user pointer returned)

The key diagnostic: `pData != hSection` means the lock created a new kernel mapping via `MmMapViewOfSection` or driver callback, which is what we need for a real dangling PTE.

### Change 8: Enhanced Destroy/dangling logging -- 256-byte hex dump (lines 1053-1069)

After `D3DKMTDestroyAllocation`, added:

- 256-byte hex dump of the dangling VA post-destroy (shows whether freed pages contain non-zero data from SURFACE reclaim)
- Logs whether the post-destroy VA is in kernel or user space
- Logs allocation size, section size, and page count
- Added `VirtualFree(sysMem)` in failure paths for proper cleanup

### Change 9: Enhanced DumpDanglingVAs -- full page hex dumps and page fingerprints (lines 1361-1411)

Replaced the 16-byte hex dump with:

- Full 4096-byte page hex dump for the first 3 VAs
- 64-byte hex dump for remaining VAs
- Page fingerprint: counts non-zero bytes, finds first/last non-zero offsets
- Logs all non-zero byte offsets (up to 64) for pages with data
- Logs whether each VA is in kernel or user space

This helps diagnose whether SURFACE objects have reclaimed the freed pages.

### Change 10: Enhanced ScanForSurfaces -- page fingerprints and slot hex dumps (lines 1513-1606)

Added:

- Full page read (4096 bytes) for each dangling VA before slot scanning
- Page fingerprint logging (non-zero byte count, first/last non-zero offsets)
- Full page hex dump for the first 3 VAs with non-zero data
- 64-byte hex dump at each slot offset when `first8 != 0` (shows raw bytes even if SURFACE validation fails)

This provides much more diagnostic information when scanning for reclaimed SURFACE objects.

### Change 11: Enhanced DumpSurface -- full 0x2C0 bytes (lines 1608-1616)

Changed from 0x100 (256) bytes to `SURFACE_SIZE` (0x2C0 = 704 bytes) hex dump. This captures the entire SURFACE object including all fields up to `SURFACE_PID` at offset 0xD0 and beyond.

## 4. Technical Verification

### Flag Values (verified via Python)

| Flag | Value | Purpose |
|------|-------|---------|
| StandardAllocation | 0x10000 | Standard allocation type (set) |
| ExistingSysMem | 0x20 | Existing system memory (NOT set) |
| PAGE_READWRITE | 0x04 | Read-write page protection |
| SEC_COMMIT | 0x8000000 | Committed pages |
| PAGE_READWRITE \| SEC_COMMIT | 0x8000004 | Combined protection for CreateFileMappingW |

### Struct Sizes (verified via Python)

| Struct | Size | Notes |
|--------|------|-------|
| D3DDDI_ALLOCATIONINFO | 0x28 (40 bytes) | Used with CreateAllocation |
| D3DDDI_ALLOCATIONINFO2 | 0x60 (96 bytes) | Used with CreateAllocation2 |
| SURFACE_SIZE | 0x2C0 (704 bytes) | Full SURFACE object |
| Page size | 0x1000 (4096 bytes) | Standard x64 page |

### Kernel VA Check

A kernel address has the high 16 bits set to 0xFFFF (`>= 0xFFFF800000000000`). User addresses have the high 16 bits as 0x0000. This check is used in the enhanced logging to determine whether `pData` is a real kernel mapping.

### hSection Offset Verification

`D3DDDI_ALLOCATIONINFO2.hSection` is at offset +0x08, same as `pSystemMem`. The kernel's `DXGDEVICE::CreateVidMmAllocations` reads `v36->hSection` from this offset for non-ExistingSysMem StandardAllocation paths, calls `ObReferenceObjectByHandle(v37, 0x20000u, MmSectionObjectType, 1, &v112, nullptr)`, and stores the result at `global_alloc+0x160`.

## 5. What NOT Changed

- The D3D11 fallback path (`CreateDanglingMappingsViaD3D11`) remains unchanged -- it only triggers if the D3DKMT path yields fewer than 16 mappings
- The `KASLRBypass`, `KernelRW`, `ProcessRW` classes remain unchanged
- The `main()` function structure remains unchanged
- All EPROCESS, SURFACE, and VidMm offsets remain unchanged
- The fallback chain (bare, StdAlloc+ExistingSysMem, CreateAllocation2 with CreateShared) remains at original indentation -- the `st` variable naturally gates it

## 6. Expected Behavior After Fix

1. **CreateFileMappingW** creates a pagefile-backed section with 1 committed page (0x1000 bytes)
2. **CreateAllocation2** with `Flags=0x10000` and `hSection` causes the kernel to:
   - Call `ObReferenceObjectByHandle(hSection)` to get a section object
   - Store it at `global_alloc+0x160`
   - Set `v28->Flags |= 0x400000` (has section object)
3. **D3DKMTLock** creates a NEW kernel mapping via `MmMapViewOfSection` (paravirtualized) or driver callback (non-paravirtualized)
   - `pData` should be DIFFERENT from `hSection` (confirming real kernel mapping)
   - `pData` may be in kernel space or user space (depends on GPU driver)
4. **D3DKMTDestroyAllocation** calls `CloseOneAllocation` which checks `VIDMM_ALLOC+0x90` (NULL for type 5) -- skips unmap
   - `DestroyOneAllocation` calls `VidMmDereferenceObjectAsync(global_alloc+0x160)` -- drops section ref
   - Section's pages are freed to PFN free list
   - PTE at `multi_alloc+0x10` persists -- REAL dangling mapping
5. **GDI bitmap spray** creates SURFACE objects in CSectionEntry sections
   - CSectionEntry draws pages from PFN free list
   - Freed VIDMM pages are reclaimed by SURFACE objects
6. **ScanForSurfaces** finds SURFACE objects on the dangling pages
   - `first8` should be non-zero (SURFACE object data)
   - `ValidateSurface` should pass (correct iBitmapFormat, lDelta, pvScan0, etc.)
7. **pvScan0 corruption** yields arbitrary kernel R/W via GetBitmapBits/SetBitmapBits
8. **Token stealing** from System EPROCESS gives SYSTEM privileges

## 7. Files Modified

| File | Changes |
|------|---------|
| `dxgkrnl_dangling_lock_exploit_verified.cpp` | 11 targeted edits (see above) |
| `analysis/fix_implementation.md` | This file (new) |

## 8. Build Status

NOT BUILT. Per subagent rules, the host AI will build after reviewing the implementation.
