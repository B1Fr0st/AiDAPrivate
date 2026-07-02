# ntoskrnl Pool Adjacency Analysis: CLFS Metadata vs GDI SURFACE

## Executive Summary

**VERDICT: Pool adjacency between CLFS metadata buffers and GDI SURFACE objects is NOT possible.** GDI SURFACE objects reside in section-backed session space (via `MmCreateSection` + `MmMapViewInSessionSpace`), while CLFS metadata buffers reside in regular system paged pool (via `ExAllocatePoolWithTag` with `PagedPoolCacheAligned`). These are in completely different virtual address regions with different heap descriptors. Furthermore, even non-isolated GDI types (DC, ColorSpace, etc.) that use `Win32AllocPool` are in **session paged pool** (`PagedPoolSession = 0x21`), which is a separate heap from the system paged pool where CLFS metadata lives. An alternative exploitation strategy is required.

---

## 1. Pool Allocator Architecture (ntoskrnl.exe)

### 1.1 Allocation Call Chain

```
ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag)
  -> ExpAllocatePoolWithTagFromNode(PoolType, NumberOfBytes, Tag, Node, Flags)
       -> ExAllocateHeapPool(PoolType, NumberOfBytes, Tag, Node, Flags)
            -> [Special Pool] ExAllocateHeapSpecialPool (if verifier enabled)
            -> [LFH Lookaside] RtlpInterlockedPopEntrySList (for sizes <= 0xFE0)
            -> [LFH Bucket] RtlpHpLfhSlotAllocate (LFH bucket allocation)
            -> [VS Context] RtlpHpVsContextAllocateInternal (for medium sizes)
            -> [Segment] RtlpHpSegAlloc (for sizes > 0x20000)
            -> [Large] RtlpHpLargeAlloc (for very large allocations)
```

**Key addresses (ntoskrnl.exe):**
- `ExAllocatePoolWithTag`: `0x1409B4160` - wrapper, routes to `ExpAllocatePoolWithTagFromNode`
- `ExpAllocatePoolWithTagFromNode`: `0x1402BC810` - NUMA node iteration, calls `ExAllocateHeapPool`
- `ExAllocateHeapPool`: `0x1402BC8A0` - core allocator, implements "pool as heap" design
- `ExFreePoolWithTag`: `0x1409B4140` - wrapper, calls `ExFreeHeapPool`
- `ExFreeHeapPool`: `0x1402C2150` - core free, handles coalescing and tracking

### 1.2 Pool-as-Heap Design

Modern Windows (Win10 22H2/Win11) uses the **NT heap manager** internally for pool allocations. The pool allocator is a wrapper around the heap infrastructure:

- `ExAllocateHeapPool` uses `RtlpHp*` (Heap Platform) functions internally
- Allocations are served from per-NUMA-node heap descriptors
- The heap descriptor is selected based on `PoolType` in `ExAllocateHeapPool`

**Pool type routing in `ExAllocateHeapPool` (at `0x1402BC8A0`):**

| Pool Type | Value | Heap Selection in ExAllocateHeapPool |
|-----------|-------|--------------------------------------|
| `NonPagedPool` | 0 | `v15[0]` or `v15[1]` - system non-paged pool heap |
| `PagedPool` | 1 | `v15[3]` - system paged pool heap (when `v12 < NonPagedPool`, i.e., paged) |
| `PagedPoolCacheAligned` | 5 | Same as PagedPool heap, with cache-line alignment (flag 0x4) |
| `PagedPoolSession` | 0x21 (33) | Session-specific heap via process session pointer: `*(process->Session + 14560)` |
| `NonPagedPoolNx` | 0x200 (512) | `v15[0]` or `v15[1]` - system non-paged pool heap (NX) |

**Critical distinction:** `PagedPoolSession` (0x21) uses a **per-session heap descriptor** accessed through the current process's session object. `PagedPool` and `PagedPoolCacheAligned` use the **system-wide paged pool heap** (`v15[3]` where `v15 = &qword_140C58100[1048 * Node]`). These are completely separate heap structures.

### 1.3 Allocation Size Classes

| Size Range | Allocation Path | Function |
|------------|----------------|----------|
| <= 0xFE0 (4064 bytes) | LFH Lookaside / LFH Bucket | `RtlpHpLfhSlotAllocate` |
| 0xFE1 - 0x20000 (131072 bytes) | VS Context | `RtlpHpVsContextAllocateInternal` |
| > 0x20000 | Segment or Large Alloc | `RtlpHpSegAlloc` / `RtlpHpLargeAlloc` |

**CLFS metadata blocks (typical 0x7A00 = 31,232 bytes) fall into the VS Context range** - they are served by the Variable Size sub-allocator, not the LFH.

---

## 2. POOL_HEADER Structure

### 2.1 Layout (x64, 0x10 = 16 bytes)

```
Offset  Size    Field
------  ------  -----
0x00    UCHAR   PreviousSize (low byte, in 16-byte blocks)
0x01    UCHAR   PreviousSize (high byte) / PoolIndex
0x02    USHORT  BlockSize (in 16-byte blocks, size >> 4)
0x03    UCHAR   PoolType flags (PoolType & 0x6D | 2)
                bit 0: NonPaged
                bit 1: Paged
                bit 2: Quota
                bit 3: Coalescing marker
0x04    ULONG   PoolTag (4-byte ASCII tag, e.g., 'Cfls' = 0x73666C43)
0x08    ULONGLONG  PoolQuotaCookie / EPROCESS pointer (for quota pools)
```

**Verified from `ExAllocateHeapPool` decompile:**
- Header is written at `Internal+0` through `Internal+7` before returning `Internal+16` as user data
- `*(_BYTE *)(Internal + 2) = v19 >> 4` - BlockSize in 16-byte units
- `*(_DWORD *)(Internal + 4) = v138` - PoolTag
- `*(_BYTE *)(Internal + 3) = v12 & 0x6D | 2` - PoolType flags
- User data starts at `POOL_HEADER + 0x10`

### 2.2 Block Adjacency via POOL_HEADER

The `PreviousSize` field at offset 0x00-0x01 encodes the size of the immediately preceding pool block (in 16-byte units). This allows the allocator to walk backward to the previous allocation's header. The `BlockSize` field at offset 0x02 encodes the current block's size (same units). Adjacent blocks are contiguous in virtual memory, separated only by their respective POOL_HEADER structures.

---

## 3. GDI SURFACE Allocation Path

### 3.1 Type Isolation Architecture

GDI SURFACE objects use **type isolation** - a mechanism that allocates objects from section-backed memory rather than from the kernel pool.

**SURFACE type isolation parameters (verified from binary):**
- Template: `CLookAsideTypeIsolation<180224, 704>`
- Section size: 180,224 bytes (0x2C000 = 44 pages)
- Slot size: 704 bytes (0x2C0)
- Slots per section: 256 (computed: 180224 / 704 = 256)
- SURFACE::tSize: 696 bytes (0x2B8) - base SURFACE structure size
- Slot overhead: 8 bytes (704 - 696 = 0x8) - alignment padding

### 3.2 Allocation Call Chain

```
SURFACE::Allocate() [win32kbase.sys @ 0x1C00808C0]
  -> gpTypeIsolation lookaside pop (ExpInterlockedPopEntrySList)
  -> If lookaside empty: virtual call via gpTypeIsolation+96
       -> CTypeIsolation<180224,704>::Allocate() [win32kbase.sys @ 0x1C0149198]
            -> CSectionBitmapAllocator<180224,704>::Allocate() [win32kbase.sys @ 0x1C013CF40]
                 -> RtlFindClearBits (find free slot in bitmap)
                 -> CSectionBitmapAllocator::CommitSlot (commit memory for slot)
                 -> Return: base_address + (slot_index << 12)
            -> If no section available: CSectionEntry<180224,704>::Create() [win32kbase.sys @ 0x1C00A1DF0]
                 -> ExAllocatePoolWithTag(PagedPoolSession, 0x28, "Uiso") - management struct ONLY (0x28 bytes in session pool)
                 -> CSectionEntry<180224,704>::Initialize() [win32kbase.sys @ 0x1C00A1E4C]
                      -> PlatformCreateSection(0x2C000) [win32kbase.sys @ 0x1C00A202C]
                           -> MmCreateSection(&Object, SECTION_ALL_ACCESS, NULL, &size, SEC_COMMIT, 0x4000000, NULL, NULL)
                      -> PlatformMapViewInSessionSpace(section, &mappedBase, &viewSize) [win32kbase.sys @ 0x1C00A1FE4]
                           -> MmMapViewInSessionSpace(section, &mappedBase, &viewSize)
                      -> CSectionBitmapAllocator<180224,704>::Create(mappedBase)
```

### 3.3 Key Finding: SURFACE Memory Location

**GDI SURFACE objects are NOT in the kernel pool.** They reside in:
- **Section-backed memory** created by `MmCreateSection` with `SEC_COMMIT` flag
- **Mapped into kernel session space** via `MmMapViewInSessionSpace`
- The section is 0x2C000 (180,224) bytes = 44 pages, carved into 256 slots of 0x2C0 (704) bytes each
- Only the CSectionEntry management structure (0x28 bytes) is in `PagedPoolSession` pool - the actual SURFACE objects are in the section's virtual address range

**The SURFACE object's pvScan0 field at offset +0x50 (80 bytes from slot start) is in section-backed memory, not in pool memory.**

### 3.4 SURFACE::Free Path

```
SURFACE::Free() [win32kbase.sys @ 0x1C002B8C0]
  -> ReleaseReferenceCountedObjectHandle (if handle-based ref)
  -> Win32FreePool(secondary_buffer) (frees a secondary allocation, NOT the SURFACE itself)
  -> FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>(surface) - returns SURFACE to type isolation lookaside
```

The `Win32FreePool` call in `SURFACE::Free` frees a **secondary** allocation (the surface's pixel buffer or similar), not the SURFACE object itself. The SURFACE object is returned to the type isolation lookaside list.

---

## 4. CLFS Metadata Buffer Allocation Path

### 4.1 Pool Tag and Pool Type

**Pool tag:** `Cfls` (0x73666C43 in little-endian)
**Pool type:** `PagedPoolCacheAligned` (value 5 = PagedPool | 0x4)

The `PagedPoolCacheAligned` type uses the **same system-wide paged pool heap** as regular `PagedPool`. The 0x4 flag (CacheAligned) only affects alignment of the allocation within the heap, not the heap descriptor selection.

### 4.2 Allocation Call Chain

```
CClfsBaseFilePersisted::CreateMetadataBlock() [clfs.sys @ 0x1C003D9C4]
  -> ExAllocatePoolWithTag(PagedPoolCacheAligned, blockSize, 'Cfls')
  -> memset(buffer, 0, blockSize)
  -> ClfsStampLogBlock(buffer, ...)
  -> Store buffer pointer in metadata block array

CClfsBaseFilePersisted::ReadMetadataBlock() [clfs.sys @ 0x1C0037EA0]
  -> ExAllocatePoolWithTag(PagedPoolCacheAligned, blockSize, 'Cfls')
  -> memset(buffer, 0, blockSize)
  -> CClfsContainer::ReadSector() - read from .blf file
  -> ClfsDecodeBlock() - validate and decode
```

### 4.3 Free Path

```
CClfsBaseFile::FreeMetadataBlock() [clfs.sys @ 0x1C000AC70]
  -> ExFreePoolWithTag(buffer, 0)
```

### 4.4 Marshalling Context

```
ClfsCreateMarshallingAreaInternal() [clfs.sys @ 0x1C003BEB0]
  -> ExAllocatePoolWithTag(PagedPool, 0xC8, 'Cfls') - marshalling context struct (0xC8 bytes in regular PagedPool)
  -> CClfsKernelMarshallingContext::Initialize() [clfs.sys @ 0x1C003C0A4]
       -> ExAllocatePoolWithTag(NonPagedPoolNx=0x200, 0x80, 'Cfls') - lookaside list structs
       -> ExInitializePagedLookasideList() or ExInitializeNPagedLookasideList()
       -> ExAllocatePoolWithTag(NonPagedPoolNx=0x200, 0x68, 'Cfls') - ERESOURCE locks
```

### 4.5 CLFS Block Sizes

| Property | Value |
|----------|-------|
| Minimum block size | 0x200 (512 bytes) |
| Typical block 2 (base log record) | 0x7A00 (31,232 bytes = 61 sectors = 7.625 pages) |
| Pool header overhead | 0x10 (16 bytes) |
| Total with header | 0x7A10 (31,248 bytes) |
| Allocation class | VS Context (above LFH threshold 0xFE0, below large threshold 0x20000) |
| Pool tag | Cfls (0x73666C43) |
| Pool type | PagedPoolCacheAligned (5) |
| Heap | System-wide paged pool heap |

---

## 5. GDI Non-Isolated Object Types

### 5.1 Types Using Win32AllocPool (Session Pool)

From `HmgCreate()` [win32kbase.sys @ 0x1C006BCFC], the following GDI types are initialized with lookaside lists but are NOT in the type isolation factory:

| Type ID | Name | Size | In Type Isolation? | Pool |
|---------|------|------|--------------------|------|
| 1 | DC | 0x868 (2152 bytes) | No | PagedPoolSession |
| 4 | RGN | 0x70 (112 bytes) | Yes (size 112 in isolation list) | Section-backed |
| 5 | SURFACE | 0x2B8+256 (952 bytes lookaside) | Yes (size 704 in isolation) | Section-backed |
| 8 | PALETTE | 0xC8 (200 bytes) | No | PagedPoolSession |
| 0x10 | LFONT | 0xB8 (184 bytes) | No | PagedPoolSession |
| 0xA | COLORSPACE | 0x278 (632 bytes) | No | PagedPoolSession |
| 0xB | METAFILE | 0x390 (912 bytes) | Yes (size 912 in isolation list) | Section-backed |

**Win32AllocPool** [win32kbase.sys @ 0x1C002C2D0] calls through indirect function pointers with pool type parameter 33 (0x21 = `PagedPoolSession`):
```
Win32AllocPool(size, tag) -> ExAllocatePoolWithTag(PagedPoolSession=0x21, size, tag)
```

**Win32AllocPoolNonPaged** [win32kbase.sys @ 0x1C005C490] uses pool type 544 (0x220 = `NonPagedPoolNx | 0x20`):
```
Win32AllocPoolNonPaged(size, tag) -> ExAllocatePoolWithTag(0x220, size, tag)
```

### 5.2 Type Isolation Factory Instances

From `HmgCreate`, the `TypeIsolationFactory::Create` creates 8 type isolation instances:

| # | Template | Section Size | Slot Size | Section Pages | Slots | Likely GDI Type |
|---|----------|-------------|-----------|---------------|-------|-----------------|
| 1 | CLookAsideTypeIsolation<180224,704> | 0x2C000 | 0x2C0 | 44 | 256 | SURFACE |
| 2 | CTypeIsolation<40960,160> | 0xA000 | 0xA0 | 10 | 256 | ? |
| 3 | CTypeIsolation<49152,192> | 0xC000 | 0xC0 | 12 | 256 | ? |
| 4 | CLookAsideTypeIsolation<36864,144> | 0x9000 | 0x90 | 9 | 256 | ? |
| 5 | CTypeIsolation<81920,320> | 0x14000 | 0x140 | 20 | 256 | ? |
| 6 | CTypeIsolation<917504,3584> | 0xE0000 | 0xE00 | 224 | 256 | ? |
| 7 | CTypeIsolation<28672,112> | 0x7000 | 0x70 | 7 | 256 | RGN |
| 8 | CTypeIsolation<233472,912> | 0x39000 | 0x390 | 57 | 256 | METAFILE |

All type-isolated objects use section-backed session space, not pool memory.

---

## 6. Pool Coalescing and Reuse

### 6.1 Coalescing Mechanism

Pool coalescing is handled by the underlying NT heap manager. In `ExFreeHeapPool` [ntoskrnl.exe @ 0x1402C2150]:

1. When a block is freed, the allocator reads the POOL_HEADER at `P - 0x10`
2. It checks flag bit 2 (`v7 & 4`) at header offset +3 to determine if the previous block is free
3. If the previous block is free, it walks backward using `PreviousSize` (at offset 0x00-0x01) to find the previous block's header
4. The previous block's coalescing flag is set (`*(_BYTE *)(v8 + 3) |= 4u`)
5. The actual merging of adjacent free blocks is performed by `RtlpHpFreeHeap`

### 6.2 LFH Lookaside Reuse

For small allocations (<= 0xFE0 = 4064 bytes), freed blocks may be pushed to LFH lookaside lists instead of being coalesced:

```
In ExFreeHeapPool:
  if (v12 - 513) <= 0xD7F and v22 (LFH bucket exists):
    ++free_count
    if free_count < depth_limit:
      RtlpInterlockedPushEntrySList(bucket, entry)  // push to lookaside
    else:
      ++overflow_count
  else:
    RtlpHpFreeHeap(heap, entry, ...)  // normal free with coalescing
```

### 6.3 Exploit Implications

Pool coalescing can be leveraged to create predictable allocation patterns:
- Free adjacent objects to create a contiguous free region
- The heap manager merges the free blocks
- A new allocation of the right size can be served from the merged region
- This works **within the same heap** (same pool type, same NUMA node)

However, this only works for objects in the **same pool heap**. Since CLFS (system paged pool) and GDI (session paged pool or section-backed) are in different heaps, coalescing-based adjacency strategies cannot bridge them.

---

## 7. Adjacency Analysis

### 7.1 Can CLFS Metadata Be Adjacent to GDI SURFACE?

**NO.** The reasons are architectural:

1. **GDI SURFACE** objects are in section-backed session space:
   - Created via `MmCreateSection(SEC_COMMIT, 0x2C000)` 
   - Mapped via `MmMapViewInSessionSpace`
   - This memory is NOT pool memory - it's a separate VAD-backed allocation in the session's virtual address space
   - The section appears at a session-specific virtual address, not in the pool address range

2. **CLFS metadata** buffers are in system paged pool:
   - Allocated via `ExAllocatePoolWithTag(PagedPoolCacheAligned, size, 'Cfls')`
   - Uses the system-wide paged pool heap descriptor
   - Pool addresses are in the kernel pool virtual address range (typically `0xFFFFA8...` to `0xFFFFB8...` on x64)

3. **Different virtual address regions**: Section-backed memory and pool memory occupy completely different ranges in the kernel virtual address space. There is no mechanism for them to be adjacent.

### 7.2 Can CLFS Metadata Be Adjacent to Non-Isolated GDI Types?

**NO.** The reasons are heap-level:

1. **Non-isolated GDI types** (DC, PALETTE, LFONT, COLORSPACE) use `Win32AllocPool`:
   - `Win32AllocPool` routes to `ExAllocatePoolWithTag(PagedPoolSession=0x21, ...)`
   - `PagedPoolSession` uses a **per-session heap descriptor** accessed through `process->Session->PoolHeap`
   - Each session has its own pool heap, isolated from the system pool

2. **CLFS metadata** uses `PagedPoolCacheAligned` (5):
   - This maps to the **system-wide paged pool heap** (`v15[3]` in `ExAllocateHeapPool`)
   - The system pool heap is shared across all processes but separate from session pools

3. **In `ExAllocateHeapPool`**, the heap selection is explicit:
   ```
   if (v12 < NonPagedPool):  // PagedPool = 1, which is > 0, so this is for paged pool
       v17 = v15[3]           // System paged pool heap
   else if (v12 & 0x21) == 0x21:  // PagedPoolSession = 0x21
       v17 = *(process->Session + 14560)  // Session paged pool heap
   ```
   These are different heap structures with different pool pages. Allocations in one heap cannot be adjacent to allocations in another.

### 7.3 Summary Matrix

| Object Type | Pool Type | Pool Tag | Heap | Can Be Adjacent to CLFS? |
|-------------|-----------|----------|------|--------------------------|
| GDI SURFACE | N/A (section-backed) | N/A | Session section space | NO |
| GDI DC | PagedPoolSession (0x21) | Gdi/pool-specific | Session paged pool | NO |
| GDI COLORSPACE | PagedPoolSession (0x21) | Gdi/pool-specific | Session paged pool | NO |
| GDI PALETTE | PagedPoolSession (0x21) | Gdi/pool-specific | Session paged pool | NO |
| GDI LFONT | PagedPoolSession (0x21) | Gdi/pool-specific | Session paged pool | NO |
| CLFS metadata | PagedPoolCacheAligned (5) | Cfls | System paged pool | (reference) |
| Registry keys | PagedPool | CMK | System paged pool | YES (same heap) |
| Token objects | PagedPool | Toke | System paged pool | YES (same heap) |
| Named pipe attrs | PagedPool | Nmp | System paged pool | YES (same heap) |

---

## 8. Alternative Exploitation Strategy

Since GDI SURFACE objects cannot be made adjacent to CLFS metadata buffers, the exploit approach must change. Two viable alternatives:

### 8.1 Option A: Target System Paged Pool Objects

Find kernel objects that:
1. Are allocated in **system PagedPool** (not PagedPoolSession, not section-backed)
2. Have a **writable pointer at a known offset** that can be corrupted by a CLFS OOB write
3. Can be leveraged for kernel R/W after corruption

Candidate objects in system paged pool:
- **Registry key/value objects** (`CMK` tag) - in paged pool
- **Token objects** (`Toke` tag) - in paged pool, contain privilege fields
- **Named pipe attribute buffers** - in paged pool, used by NtCreateNamedPipeFile
- **ALPC port objects** - some in paged pool
- **File objects** - some in paged pool (depends on filesystem)

The classic CLFS exploit (CVE-2023-28252 and similar) targets **named pipe attribute buffers** or **registry transaction objects** in paged pool, not GDI objects.

### 8.2 Option B: Use a Different GDI Primitive

Instead of corrupting SURFACE pvScan0 via pool adjacency:
1. Use the CLFS OOB write to corrupt a **pipe attribute** or similar paged pool object
2. Leverage the corrupted object to achieve an arbitrary write primitive
3. Use the arbitrary write to modify a GDI SURFACE's pvScan0 directly (write to the section-backed address)
4. Then use GetBitmapBits/SetBitmapBits for kernel R/W

This is a two-stage approach: CLFS OOB -> pipe corruption -> arbitrary write -> SURFACE pvScan0 corruption -> bitmap R/W.

### 8.3 Option C: Leverage CLFS OOB Directly

If the CLFS OOB write is sufficiently controlled (arbitrary offset and value):
1. Find the kernel address of a GDI SURFACE object (via NtQuerySystemInformation or handle table leak)
2. Use the CLFS OOB write to directly overwrite the SURFACE's pvScan0 field at its section-backed address
3. This requires the OOB write to reach outside the pool allocation into the section address space, which may not be possible depending on the vulnerability

---

## 9. Pool Tag Reference

| Tag | Hex Value | Component | Pool Type |
|-----|-----------|-----------|-----------|
| Cfls | 0x73666C43 | CLFS metadata buffers | PagedPoolCacheAligned |
| Uiso | 0x6F736955 | GDI type isolation management | PagedPoolSession |
| Uiso | 0x6F736955 | GDI type isolation (lookaside mode) | NonPagedPoolNx (0x200) |
| IfiH | 0x48666C43 | CLFS lookaside list (Io context) | NonPagedPoolNx |
| IfiI | 0x49666C43 | CLFS lookaside list (Io pages) | PagedPool |

---

## 10. Key Binary Addresses

### ntoskrnl.exe (PID 8428, port 13346)
| Function | Address |
|----------|---------|
| ExAllocatePoolWithTag | 0x1409B4160 |
| ExAllocatePool2 | 0x1409B41B0 |
| ExAllocatePool3 | 0x1409B4270 |
| ExFreePoolWithTag | 0x1409B4140 |
| ExpAllocatePoolWithTagFromNode | 0x1402BC810 |
| ExAllocateHeapPool | 0x1402BC8A0 |
| ExFreeHeapPool | 0x1402C2150 |
| ExpPoolFlagsToPoolType | 0x1409B4010 |
| MmCreateSection | 0x140701E70 |
| MmCreateSectionEx | 0x140701EF4 |
| MiCreateSection | 0x140652DA0 |

### win32kbase.sys (PID 15092, port 13345)
| Function | Address |
|----------|---------|
| SURFACE::Allocate | 0x1C00808C0 |
| SURFACE::Free | 0x1C002B8C0 |
| HmgCreate | 0x1C006BCFC |
| Win32AllocPool | 0x1C002C2D0 |
| Win32FreePool | 0x1C002C230 |
| Win32AllocPoolZInit | 0x1C00298B0 |
| Win32AllocPoolNonPaged | 0x1C005C490 |
| PlatformCreateSection | 0x1C00A202C |
| PlatformMapViewInSessionSpace | 0x1C00A1FE4 |
| CSectionEntry<180224,704>::Create | 0x1C00A1DF0 |
| CSectionEntry<180224,704>::Initialize | 0x1C00A1E4C |
| CSectionBitmapAllocator<180224,704>::Allocate | 0x1C013CF40 |
| CTypeIsolation<180224,704>::Allocate | 0x1C0149198 |
| HMTagToIsolatedType | 0x1C0029864 |
| SURFACE::tSize (global) | 0x1C024E5E0 (value: 0x2B8 = 696) |
| gpTypeIsolation (global) | 0x1C0250288 |

### clfs.sys (PID 4924, port 13337)
| Function | Address |
|----------|---------|
| CClfsBaseFilePersisted::CreateMetadataBlock | 0x1C003D9C4 |
| CClfsBaseFilePersisted::ReadMetadataBlock | 0x1C0037EA0 |
| CClfsBaseFile::FreeMetadataBlock | 0x1C000AC70 |
| ClfsCreateMarshallingAreaInternal | 0x1C003BEB0 |
| CClfsKernelMarshallingContext::Initialize | 0x1C003C0A4 |
| CClfsBaseFile::AcquireMetadataBlock | 0x1C002EEAC |
| CClfsBaseFile::ReleaseMetadataBlock | 0x1C002D234 |
| CClfsBaseFilePersisted::ExtendMetadataBlock | 0x1C0051E8C |

---

## 11. Conclusion

**Pool adjacency between CLFS metadata buffers and GDI SURFACE objects is architecturally impossible** on this Windows build. The three memory regions are completely isolated:

1. **GDI SURFACE** -> Section-backed session space (`MmCreateSection` + `MmMapViewInSessionSpace`) - not pool memory at all
2. **GDI non-isolated types** -> Session paged pool (`PagedPoolSession = 0x21`) - per-session heap descriptor
3. **CLFS metadata** -> System paged pool (`PagedPoolCacheAligned = 5`) - system-wide heap descriptor

The exploit must either:
- Target objects in the **same system paged pool heap** as CLFS metadata (pipe attributes, registry objects, tokens)
- Use a multi-stage approach: CLFS OOB -> corrupt paged pool object -> achieve arbitrary write -> modify SURFACE pvScan0 at its section-backed address -> use bitmap R/W
- Or find a completely different path to kernel R/W that doesn't require pool adjacency with GDI objects
