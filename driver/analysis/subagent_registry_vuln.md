# Windows Registry / Configuration Manager Vulnerability Analysis

## Target: ntoskrnl.exe (Windows 11 x64)
## Date: 2026-07-02
## IDA Pro Instance: pid 4024, imagebase 0x140000000

---

## 1. CM/Registry Functions Analyzed

### User-Mode API Layer (Nt* functions)
| Function | Address | Size | Notes |
|---|---|---|---|
| NtSetValueKey | 0x1406dcad0 | 0x825 | Max data size check: `cmp ebx, 0x7FFFF000` at 0x1406dcd39 |
| NtDeleteValueKey | 0x1406e1e10 | 0x4f0 | Captures value name with tag CMcb |
| NtDeleteKey | 0x1406e4f20 | 0x2ff | Calls CmDeleteKey after callback/notification |
| NtRenameKey | 0x140868ba0 | 0x4fd | Captures new name with tag CMtb |
| NtSetInformationKey | 0x1405f3a00 | 0x445 | Handles KeyWriteTime, KeyFlags, KeySecurity, KeyVirtualization |

### Core CM Layer (Cm* functions)
| Function | Address | Size | Notes |
|---|---|---|---|
| CmSetValueKey | 0x1406dd3d0 | 0xa31 | Main value set logic with transaction support |
| CmDeleteValueKey | 0x1406df254 | 0x73b | Value deletion with transaction support |
| CmDeleteKey | 0x1406e4704 | 0x5d9 | Key deletion, calls CmpFreeKeyByCell |
| CmRenameKey | 0x14086c974 | 0xfbe | Decompilation failed (large function) |

### Internal CM Functions (Cmp* functions)
| Function | Address | Size | Notes |
|---|---|---|---|
| CmpRemoveValueFromList | 0x140688570 | 0xe6 | Removes value from list, reallocates cell |
| CmpAddValueToListEx | 0x1406e0174 | 0x120 | Adds value to list, allocates/reallocates cell |
| CmpAddValueToList | 0x14087b328 | 0x21 | Wrapper, calls CmpAddValueToListEx with count=1 |
| CmpSetValueDataNew | 0x1406e1b84 | 0x1f3 | **INTEGER OVERFLOW** - allocates big value data cells |
| CmpSetValueDataExisting | 0x1406a3e6c | 0x1ed | Updates existing big value data, safe truncation |
| CmpSetValueKeyNew | 0x1406577d0 | 0xac | Creates new value, calls CmpAddValueKeyNew + CmpAddValueToList |
| CmpSetValueKeyExisting | 0x1406df998 | 0x2f9 | Updates existing value, handles small/big/inline |
| CmpSwapValueInList | 0x1402fbc98 | 0x72 | Replaces value cell index at given position |
| CmpFreeValue | 0x1406e4148 | 0x75 | Frees value cell + value data |
| CmpFreeValueData | 0x1406e41c4 | 0x11f | Frees big value data cells + cell index array |
| CmpAddValueKeyNew | 0x140657630 | 0x137 | Allocates value node cell + name + data |
| CmpFreeKeyByCell | 0x1406e3f90 | 0x1b2 | Frees key cell, subkey list, values, security |
| CmpSetValueKeyTombstone | 0x14086e96c | 0xa3 | Creates tombstone value for virtualization |
| CmpCloneKCBValueListForTrans | 0x14069fbf0 | 0xc8 | Clones value list for transaction |
| CmpRemoveSubKeyFromList | 0x1406e4380 | 0x2e4 | Removes subkey from root/leaf index |
| CmpAllocateKeyControlBlock | 0x1405effac | 0x80 | KCB allocation via lookaside list |
| CmpFreeKeyControlBlock | 0x14066d340 | 0xc9 | KCB free, returns to lookaside or pool |
| CmpAllocateUnitOfWork | 0x14069b770 | 0x6a | UoW allocation, PagedPool, tag CMUw |
| CmpAllocatePostBlock | 0x1406dc670 | 0xf5 | PostBlock allocation, PagedPool+Quota, tag CMpb |
| CmpAllocateTransientPoolWithTag | 0x140206f50 | 0xf | Wrapper for ExAllocatePoolWithTag |
| CmpAllocate | 0x1407200d0 | 0x5d | Hive bin allocation, PagedPool, tags CM20/CM16 |

### Hive Cell Management (Hv* functions)
| Function | Address | Size | Notes |
|---|---|---|---|
| HvAllocateCell | 0x140656a94 | 0x45 | Cell allocator, max 1MB, rounds to power-of-2 |
| HvReallocateCell | 0x1406df0c0 | 0x18b | Cell realloc, copies old data, frees old cell |
| HvFreeCell | 0x140656bc4 | 0x1a4 | Cell free, adds to free list |
| HvpDoAllocateCell | 0x1406564f8 | 0x270 | Core cell alloc, finds/splits free cell |
| HvpAddBin | 0x140721d48 | 0x5fc | Adds new bin to hive, calls CmpAllocate |
| HvpAllocateBin | 0x140723cac | 0x3d | Allocates bin from pool via function pointer |
| HvpFindFreeCell | 0x1406555dc | 0x1b8 | Finds free cell in hint table |
| HvpEnlistFreeCell | 0x140655978 | 0x126 | Adds cell to free list |

### Value Data Read Path
| Function | Address | Size | Notes |
|---|---|---|---|
| CmpValueToData | 0x1407ad254 | 0x61 | Wrapper, calls CmpGetValueData |
| CmpGetValueData | 0x1405f8410 | 0x239 | **Reads big values, allocates CMvd pool buffer** |

---

## 2. Pool Allocation Analysis

### Pool Tags Identified
| Tag (hex) | Tag (ASCII) | Usage | Pool Type |
|---|---|---|---|
| 0x77554D43 | CMUw | UnitOfWork | PagedPool |
| 0x62704D43 | CMpb | PostBlock | PagedPool+Quota |
| 0x34344D43 | CM44 | PostBlock Event | PagedPool+Quota |
| 0x35344D43 | CM45 | PostBlock List | PagedPool+Quota |
| 0x624E4D43 | CMNb | KCB Name Buffer | PagedPool (freed in CmpFreeKeyControlBlock) |
| 0x62724D43 | CMrb | KCB extra/ref data | PagedPool (freed in CmpFreeKeyControlBlock) |
| 0x64764D43 | CMvd | Value Data (read path) | PagedPool (allocated in CmpGetValueData) |
| 0x62634D43 | CMcb | Captured Value Name | PagedPool+Quota (NtSetValueKey, NtDeleteValueKey) |
| 0x62744D43 | CMtb | Captured Rename Name | PagedPool+Quota (NtRenameKey) |
| 0x30324D43 | CM20 | Hive Bin (volatile) | PagedPool (via CmpAllocate) |
| 0x36314D43 | CM16 | Hive Bin (stable) | PagedPool (via CmpAllocate) |
| 0x31324D43 | CM21 | Hive Bin (dirty) | PagedPool (via CmpAllocate) |

### Fixed-Size Pool Allocations
| Object | Size (bytes) | LFH Bucket | Tag | Notes |
|---|---|---|---|---|
| KCB (KeyControlBlock) | 0x138 (312) | 320 | Lookaside | Uses SLIST lookaside, falls back to pool |
| UoW (UnitOfWork) | 0x78 (120) | 128 | CMUw | PagedPool |
| PostBlock | 0x48 (72) | 128 | CMpb | PagedPool+Quota |
| PostBlock Event | 0x70 (112) | 128 | CM44 | PagedPool+Quota |
| PostBlock List | 0x18 (24) | 128 | CM45 | PagedPool+Quota |

### Variable-Size Pool Allocations
| Object | Size | LFH Bucket | Tag | Controllable? |
|---|---|---|---|---|
| CMvd (Value Data) | Value size | **User-controlled** | CMvd | Yes - via NtQueryValueKey read path |
| CMcb (Value Name) | Name length (max 0x7FFF) | **User-controlled** | CMcb | Yes - via NtSetValueKey/NtDeleteValueKey |
| CMtb (Rename Name) | Name length (max 0x1FF) | **User-controlled** | CMtb | Yes - via NtRenameKey (max 511 bytes) |
| Hive Bin | Page-aligned (>=4096) | >=4096 | CM20/CM16 | Indirectly via value data size |

### Registry Cells (NOT Pool Allocations)
Registry cells (value nodes, value lists, data cells, key nodes) are allocated from **hive bins**, not directly from the Windows pool. Hive bins are PagedPool allocations (tags CM20/CM16/CM21) that are managed by the hive's internal cell allocator. Cell sizes are rounded to 8-byte boundaries within bins.

---

## 3. LFH Bucket Analysis

### Target Buckets (640, 704, 1024)

**None of the fixed-size CM allocations fall in the 640, 704, or 1024 LFH buckets.** The closest are:
- KCB at 312 bytes -> bucket 320
- UoW at 120 bytes -> bucket 128
- PostBlock at 72 bytes -> bucket 128

**Variable-size allocations CAN target these buckets:**
- **CMvd (bucket 640):** Create a registry value with 625-640 bytes of data, then query it. CmpGetValueData allocates `ExAllocatePoolWithTag(PagedPool, value_size, 'CMvd')`.
- **CMvd (bucket 704):** Create a registry value with 689-704 bytes of data, then query it.
- **CMvd (bucket 1024):** Create a registry value with 1009-1024 bytes of data, then query it.
- **CMcb (bucket 640/704/1024):** Use NtSetValueKey or NtDeleteValueKey with a value name of appropriate length.

**Important:** CMvd allocations are **transient** - allocated during value read, freed after data copy. CMcb allocations are also transient - allocated during name capture, freed after operation. Neither provides a persistent object in the target bucket.

---

## 4. Vulnerabilities Found

### 4.1 INTEGER OVERFLOW in CmpSetValueDataNew (CONFIRMED)

**Location:** `CmpSetValueDataNew` at 0x1406e1b84
**Severity:** High (data corruption, potential code execution)
**Type:** Integer truncation leading to size mismatch

**Root Cause:**
The cell count calculation for big values (values > 16344 bytes) truncates the result to `unsigned __int16`:

```c
// At 0x1406e1cb9:
v15 = ((int)v5 + 16343) / 0x3FD8u;  // v5 = Size, result is 32-bit
// At 0x1406e1cc4:
v16 = HvAllocateCell(Hive, 4 * (unsigned int)(unsigned __int16)v15, ...);
//                                                    ^^^^^^^^^^^^^^^^
//                                                    TRUNCATION TO 16 BITS
```

**Trigger Conditions:**
1. Hive version >= 4 (true on modern Windows 10/11)
2. Value data size in range [16345, 0x7FFFFFFF] bytes
3. Cell count (ceil(Size / 16344)) must exceed 65535
4. Minimum size for overflow: 65536 * 16344 - 16343 = **1,071,104,041 bytes (~1021.5 MB)**
5. NtSetValueKey enforces max size of 0x7FFFF000 (2,048 MB) at 0x1406dcd39

**Overflow Math (at max size 0x7FFFF000):**
```
Full cell count:     131,393
Truncated (uint16):  321
Cell index array:    4 * 321 = 1,284 bytes allocated
Actual data stored:  321 * 16,344 = 5,246,424 bytes
Size in value node:  0x7FFFF000 = 2,147,479,552 bytes
Size mismatch:       2,142,233,128 bytes unaccounted
Overflow ratio:      409.3x
```

**Impact:**
- The CM_BIG_VALUE structure stores `count=321` (uint16) but the value node stores `size=0x7FFFF000`
- Only 321 data cells are allocated, holding ~5MB of data
- The value node claims ~2GB of data
- Querying this value triggers `CmpGetValueData` which allocates a ~2GB CMvd pool buffer (will likely fail)
- Updating this value with `CmpSetValueDataExisting` uses the same truncated count, so no OOB write occurs in the update path
- **The loop in CmpSetValueDataNew is bounded by the truncated count (uint16 comparison), so no direct OOB write in the allocation loop**

**Exploitation Constraints:**
- Requires ~1GB of data to trigger (user-mode allocation may fail)
- Kernel-mode caller (ZwSetValueKey) can provide a valid kernel buffer of ~1GB
- Creates a persistent size mismatch in the registry hive
- Could cause denial-of-service (query always fails)
- Could cause data corruption if partial reads succeed

**Alternative Sizes:**
| Size (hex) | Size (bytes) | Full Count | Truncated | Array Alloc |
|---|---|---|---|---|
| 0x3FD7C029 | 1,071,104,041 | 65,536 | 0 | 0 bytes |
| 0x3FD7C02D | 1,071,104,045 | 65,536 | 0 | 0 bytes |
| 0x3FDFFC18 | 1,071,669,272 | 65,537 | 1 | 4 bytes |
| 0x40000000 | 1,073,741,824 | 65,697 | 161 | 644 bytes |
| 0x7FFFF000 | 2,147,479,552 | 131,393 | 321 | 1,284 bytes |

When truncated count = 0, the cell index array is allocated with 0 bytes but the CM_BIG_VALUE header is still created. This is an interesting edge case.

### 4.2 Cell Leak in CmpRemoveValueFromList Error Path

**Location:** `CmpRemoveValueFromList` at 0x140688570
**Type:** Memory leak / cell leak

When `HvReallocateCell` fails (returns HCELL_NULL) during value list shrinkage:
```c
v10 = HvReallocateCell(Hive, v9, ...);
if (v10 == -1) {
    // v10 = -1 (HCELL_NULL)
    goto LABEL_5;
}
LABEL_5:
    a3[1] = v10;    // ValueList cell index = HCELL_NULL
    *a3 = v7;        // Count = count - 1
    return 0;        // Return success!
```

The old value list cell is released but not freed. The value list pointer is set to HCELL_NULL and the count is decremented. This loses the reference to the old cell (memory leak in hive space).

**Not directly exploitable as a write-what-where**, but could be used for hive space exhaustion.

### 4.3 No LIST_ENTRY / RemoveEntryList Patterns in CM Value Management

The Configuration Manager does **not** use `LIST_ENTRY` / `RemoveEntryList` patterns for value list management. Value lists are stored as arrays of HCELL_INDEX values (DWORDs) within hive cells. Subkey lists use similar array-based structures with 'lf' (leaf) and 'lh' (hash leaf) signatures.

This means the classic LIST_ENTRY corruption attack vector does not apply to CM value/subkey management.

### 4.4 Size Mismatch Read Path in CmpGetValueData

**Location:** `CmpGetValueData` at 0x1405f8410

When reading a big value with the integer overflow from 4.1:
```c
v22 = *(_DWORD *)(a3 + 4);  // Full size from value node (e.g., 0x7FFFF000)
PoolWithTag = ExAllocatePoolWithTag(PagedPool, v22, 'CMvd');  // Allocate full size
// If allocation succeeds (unlikely for ~2GB):
while (v8 < *(_WORD *)(v21 + 2))  // Loop bounded by TRUNCATED count from CM_BIG_VALUE
{
    v23 = get_cell(Hive, cell_index_array[v8], ...);
    v24 = min(v22, 16344);
    memmove(&PoolWithTag[16344 * v8], v23, v24);  // Copy into pool buffer
    v22 -= 16344;
    v8++;
}
```

The pool buffer is allocated with the **full size** (from value node), but data is only copied for **truncated_count** cells. The remaining pool buffer is **uninitialized**.

If the pool allocation succeeds (possible for moderate sizes near the truncation boundary), the returned data buffer contains:
- `truncated_count * 16344` bytes of valid data
- Remaining bytes are **uninitialized pool memory** (information disclosure)

**For sizes near the minimum overflow threshold (~1GB), the pool allocation will fail.** For smaller crafted sizes that still trigger truncation (if any path allows it), this could leak kernel pool memory.

### 4.5 No UAF in Standard Value Cell Lifecycle

The value cell lifecycle follows this pattern:
1. **Create:** `CmpAddValueKeyNew` -> `HvAllocateCell` (value node) + `CmpSetValueDataNew` -> `HvAllocateCell` (data cells)
2. **Update:** `CmpSetValueKeyExisting` -> `HvMarkCellDirty` + `CmpSetValueDataExisting` or `CmpSetValueDataNew` (reallocate)
3. **Delete:** `CmpRemoveValueFromList` -> `HvFreeCell` (value list shrink) + `CmpFreeValue` -> `CmpFreeValueData` -> `HvFreeCell` (data cells) + `HvFreeCell` (value node)

All cell accesses use `get_cell` / `release_cell` pairs with proper reference management. No stale pointer usage was found in the standard lifecycle. The transactional path (`CmpCloneKCBValueListForTrans`) duplicates the value list before modification, providing isolation.

### 4.6 No Race Conditions in Standard Operations

The CM uses a comprehensive locking hierarchy:
1. `CmpLockRegistry()` / `CmpLockRegistryExclusive()`
2. `CmpLockKcbStackTopExclusiveRestShared()` / `CmpLockKcbStackShared()`
3. `CmpLockHashEntryExclusiveByKcb()`
4. IX lock acquisition (`CmpLockIXLockIntent` / `CmpLockIXLockExclusive`)
5. `HvLockHiveFlusherShared()`

This locking hierarchy serializes value operations on the same key. No TOCTOU windows were found in the standard NtSetValueKey / NtDeleteValueKey / NtDeleteKey paths.

---

## 5. Most Promising Attack Vectors

### Vector 1: Integer Overflow in CmpSetValueDataNew (4.1) - DATA CORRUPTION
- **Feasibility:** Requires ~1GB data buffer (kernel-mode caller via ZwSetValueKey)
- **Impact:** Creates persistent size mismatch in registry hive
- **Write-What-Where:** No direct OOB write (loop bounded by truncated count)
- **Secondary effects:** Query failure (pool alloc fails), potential info disclosure if pool alloc succeeds for moderate sizes
- **Rating:** Medium - data corruption / DoS, not directly a write-what-where

### Vector 2: CMvd Pool Allocation for Heap Feng Shui - HEAP SHAPING
- **Feasibility:** Create registry values with specific sizes, query them to trigger CMvd allocations
- **Target buckets:** 640, 704, 1024 (by setting value data size to 625-640, 689-704, or 1009-1024 bytes)
- **Limitation:** CMvd allocations are **transient** (freed after read completes)
- **Could be used for:** Spraying PagedPool to fill LFH buckets before target object allocation
- **Rating:** Low - transient allocations, not persistent corruption

### Vector 3: CMcb Name Capture for Heap Feng Shui - HEAP SHAPING
- **Feasibility:** Call NtSetValueKey / NtDeleteValueKey with specific value name lengths
- **Target buckets:** 640, 704, 1024 (by using names of appropriate length, max 0x7FFF)
- **Limitation:** CMcb allocations are transient (freed after operation)
- **Rating:** Low - same as Vector 2

### Vector 4: Hive Bin Pool Allocation via Value Data - HEAP SHAPING
- **Feasibility:** Create registry values with data sizes that cause hive bin allocation in target size ranges
- **Mechanism:** HvAllocateCell -> HvpDoAllocateCell -> HvpAddBin -> CmpAllocate -> ExAllocatePoolWithTag
- **Bin size:** `(data_size + 4127) & 0xFFFFF000` (page-aligned, min 4096)
- **Limitation:** Bin sizes are page-aligned (multiples of 4096), so they can't target 640/704/1024 buckets
- **Rating:** Low - page-aligned sizes don't match target LFH buckets

### Vector 5: KCB Lookaside List Exhaustion - POOL FALLBACK
- **Mechanism:** Create many keys to exhaust the KCB lookaside list, forcing pool allocations
- **KCB size:** 0x138 (312) bytes -> LFH bucket 320
- **Tag:** CMNb (name), CMrb (extra ref data) when KCB is freed
- **Could be used for:** Placing KCB objects in PagedPool LFH bucket 320 for corruption
- **Rating:** Low - KCBs are in bucket 320, not target buckets 640/704/1024

---

## 6. Summary

### Confirmed Vulnerabilities
1. **Integer overflow in CmpSetValueDataNew** (0x1406e1b84) - uint16 truncation of cell count for big registry values. Requires ~1GB data, creates persistent size mismatch. Not a direct write-what-where but causes data corruption and potential info disclosure.

### No Direct Write-What-Where Found
The Configuration Manager's value management code does not contain a direct write-what-where primitive exploitable from user mode. The key findings are:
- Value lists use array-based storage (not LIST_ENTRY), eliminating the classic list corruption vector
- Cell management uses get_cell/release_cell with proper reference counting
- The locking hierarchy (registry lock -> KCB stack -> IX locks -> hive flusher lock) prevents race conditions
- The integer overflow in CmpSetValueDataNew creates a size mismatch but both the write loop and read loop are bounded by the truncated count
- Pool allocations for CM objects are either fixed-size (not in target LFH buckets) or transient

### Key Architectural Notes
- Registry cells are NOT pool allocations - they're managed within hive bins (PagedPool)
- The hive bin allocator manages its own free lists within bins
- Pool allocations in CM code are for auxiliary structures (KCB, UoW, PostBlock, transient buffers)
- The CMvd pool allocation in CmpGetValueData is the only user-controlled-size pool allocation in the read path
- The CMcb/CMtb pool allocations in NtSetValueKey/NtDeleteValueKey/NtRenameKey are the only user-controlled-size pool allocations in the write path

### Recommendations for Further Research
1. Analyze CmRenameKey (0x14086c974, decompilation failed) for potential name buffer handling issues
2. Investigate the virtualization layer (CmKeyBodyRemapToVirtual, CmpSetValueKeyTombstone) for additional attack surface
3. Analyze the transactional rollback path (CmpRollbackTransactionArray) for cleanup issues
4. Check the hive flush/save path for cell corruption during writeback
5. Investigate the CmpCallCallBacksEx path for callback-related vulnerabilities
6. Look at the HvpExpandMap / HvpShrinkMap functions for memory mapping issues during hive growth
