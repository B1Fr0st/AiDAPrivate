# GDI Type Isolation: CSectionEntry Corruption Analysis

**Target:** win32kbase.sys (Windows 11 x64)
**Binary:** PID 15092, port 13345
**Analysis Date:** 2026-07-01

---

## 1. CSectionEntry Structure (0x28 bytes)

### 1.1 Allocation

```
CSectionEntry<180224,704>::Create  @ 0x1c00a1df0
  ExAllocatePoolWithTag(PagedPoolSession, 0x28, 0x6F736955)  // tag = 'Uiso'
  Zero [2], [3], [4]  (offsets 0x10, 0x18, 0x20)
  CSectionEntry::Initialize(ptr)
  On failure: ~CSectionEntry() + ExFreePoolWithTag()
```

### 1.2 Initialization

```
CSectionEntry<180224,704>::Initialize  @ 0x1c00a1e4c
  Section = PlatformCreateSection(0x2C000)
    MmCreateSection(&Object, 0xF001F, 0, &size, SEC_COMMIT=4, PAGE_READWRITE=0x4000000, 0, 0)
    Section size = 0x2C000 (180,224 bytes = 44 pages)
  *(QWORD*)(this + 0x10) = Section          // section object pointer
  PlatformMapViewInSessionSpace(Section, &this+0x18, 0x2C000)
    MmMapViewInSessionSpace(Section, &ViewBase, &ViewSize)
  *(QWORD*)(this + 0x18) = ViewBase         // session-space mapped view base
  BitmapAllocator = CSectionBitmapAllocator<180224,704>::Create(ViewBase)
  *(QWORD*)(this + 0x20) = BitmapAllocator  // bitmap allocator pointer
```

### 1.3 Complete Field Map (0x28 = 40 bytes = 5 QWORDs)

| Offset | Size | Field            | Source / Usage |
|--------|------|------------------|----------------|
| 0x00   | 8    | Flink            | Doubly-linked list next (to next CSectionEntry or CTypeIsolation head) |
| 0x08   | 8    | Blink            | Doubly-linked list prev |
| 0x10   | 8    | SectionObject    | Kernel section object from MmCreateSection; deref'd via ObfDereferenceObject in destructor |
| 0x18   | 8    | ViewBase         | Session-space mapped view base from MmMapViewInSessionSpace; unmapped via MmUnmapViewInSessionSpace in destructor |
| 0x20   | 8    | BitmapAllocator  | CSectionBitmapAllocator* (separate 0x28-byte PagedPoolSession alloc, tag 'Uiso') |

### 1.4 Destructor

```
~CSectionEntry  @ 0x1c00afd80
  v1 = this[4]  // BitmapAllocator at +0x20
  if (v1):
    Free bitmap allocator internals (pushlock, bitmap buffer)
    ExFreePoolWithTag(v1, 0)           // free bitmap allocator
  this[4] = 0
  if (this[3]):                        // ViewBase at +0x18
    MmUnmapViewInSessionSpace(this[3])
    this[3] = 0
  if (this[2]):                        // SectionObject at +0x10
    ObfDereferenceObject(this[2])
    this[2] = 0

CSectionEntry::Destroy  @ 0x1c00afd54
  ~CSectionEntry(this)
  ExFreePoolWithTag(this, 0)           // free CSectionEntry itself
```

---

## 2. CSectionBitmapAllocator Structure (0x28 bytes)

### 2.1 Allocation

```
CSectionBitmapAllocator<180224,704>::Create  @ 0x1c00a1eac
  ExAllocatePoolWithTag(PagedPoolSession, 0x28, 0x6F736955)  // tag = 'Uiso'
  Zero all fields
  CSectionBitmapAllocator::Initialize(ptr, view_base)
```

### 2.2 Initialization (XOR Obfuscation)

```
CSectionBitmapAllocator<180224,704>::Initialize  @ 0x1c00a1f24
  Seed = __rdtsc()
  Cookie = RtlRandomEx(&Seed) << 32 | RtlRandomEx(&Seed)   // 64-bit random cookie
  if (Cookie == 0) Cookie = 1                                // ensure non-zero
  this[2] = Cookie                                           // store cookie at +0x10
  this[3] ^= Cookie                                          // bitmap XOR cookie at +0x18
  PushLock = ExAllocatePoolWithTag(PagedPoolSession, 8, 'Uiso')
  this[0] = PushLock                                         // pushlock at +0x00
  BitmapBuffer = lambda(220)                                 // allocate RTL_BITMAP with 220 bits
  this[3] = BitmapBuffer ^ Cookie                            // obfuscated bitmap at +0x18
  this[1] = view_base ^ Cookie                               // obfuscated view base at +0x08
```

### 2.3 Complete Field Map (0x28 = 40 bytes)

| Offset | Size | Field            | Description |
|--------|------|------------------|-------------|
| 0x00   | 8    | PushLock         | EX_PUSH_LOCK* (synchronization for bitmap operations) |
| 0x08   | 8    | ViewBase^Cookie  | XOR-obfuscated session view base address |
| 0x10   | 8    | Cookie           | 64-bit random XOR cookie (RtlRandomEx seeded by TSC) |
| 0x18   | 8    | Bitmap^Cookie    | XOR-obfuscated RTL_BITMAP buffer pointer |
| 0x20   | 4    | HintIndex        | Rotating search hint for RtlFindClearBits (wraps at 0xDC = 220) |
| 0x24   | 4    | CommittedPages   | Lazy page commit counter (wraps at 0x2C = 44) |

### 2.4 Deobfuscation Formulas

```
real_view_base = allocator[2] ^ allocator[1]    // Cookie ^ (ViewBase ^ Cookie) = ViewBase
real_bitmap    = allocator[2] ^ allocator[3]    // Cookie ^ (Bitmap ^ Cookie) = Bitmap
```

---

## 3. CTypeIsolation::Allocate - SURFACE Path

### 3.1 SURFACE::Allocate @ 0x1c00808c0

```
v0 = *gpTypeIsolation                    // gpTypeIsolation[0] = CLookAsideTypeIsolation<180224,704>
++*(DWORD*)(v0 + 0x44)                   // increment alloc count
v1 = ExpInterlockedPopEntrySList(v0 + 0x30)   // pop from LOOKASIDE_LIST_EX SLIST
if (!v1):
    ++*(DWORD*)(v0 + 0x48)               // increment miss count
    v1 = alloc_callback(v0 + 0x60, ...)  // call CTypeIsolation::Allocate
AcquireReferenceCountedObjectHandle(v1)
```

### 3.2 CTypeIsolation<180224,704>::Allocate @ 0x1c0149198

```
if (*(BYTE*)(this + 0x24)):              // lookaside mode flag (debug only)
    // debug path: ExpInterlockedPopEntrySList at this+0x18
else:
    PushLock = *(this + 0x10)
    AcquireShared(PushLock)
    for each CSectionEntry in list (this -> Flink chain):
        v5 = CSectionBitmapAllocator<180224,704>::Allocate(entry[4])  // entry+0x20
        if (v5):
            ReleaseShared(PushLock)
            return v5                    // SUCCESS: found free slot
    ReleaseShared(PushLock)

    // All existing sections full -> create new CSectionEntry
    v6 = CSectionEntry<180224,704>::Create()
    v3 = CSectionBitmapAllocator::Allocate(*(v6 + 0x20))
    if (v3):
        AcquireExclusive(PushLock)
        // Link new CSectionEntry into list (Flink/Blink manipulation)
        *(DWORD*)(this + 0x20) += 220    // increment slot count
        ReleaseExclusive(PushLock)
    else:
        CSectionEntry::Destroy(v6)      // destroy on failure
    return v3
```

### 3.3 CSectionBitmapAllocator::Allocate @ 0x1c0081534

```
PushLock = *this                          // this+0x00
KeEnterCriticalRegion()
ExAcquirePushLockExclusiveEx(PushLock)

hint = *(DWORD*)(this + 0x20)             // HintIndex at +0x20
search_start = (hint < 0xDC) ? hint : 0   // 0xDC = 220 = max slots
slot_index = RtlFindClearBits(bitmap, 1, search_start)   // find free bit

if (slot_index != -1 && CommitSlot(this, slot_index)):
    RtlSetBit(bitmap, slot_index)
    *(DWORD*)(this + 0x20) = (hint + 1 >= 0xDC) ? 0 : hint + 1   // rotate hint

    // COMPUTE SLOT ADDRESS:
    real_view_base = this[2] ^ this[1]    // Cookie ^ (ViewBase^Cookie)
    page_index = slot_index / 5           // 5 slots per page (4096 / 704 = 5)
    slot_in_page = slot_index % 5
    slot_addr = real_view_base + (page_index << 12) + 704 * slot_in_page
    //         = real_view_base + page_index * 0x1000 + 0x2C0 * slot_in_page

ExReleasePushLockExclusiveEx(PushLock)
KeLeaveCriticalRegion()
return slot_addr
```

### 3.4 CommitSlot (Lazy Page Commit) @ 0x1c0081650

```
committed = *(DWORD*)(this + 0x24)        // CommittedPages at +0x24
if (committed >= 0x2C):                   // 44 = all pages committed
    return true
page_index = slot_index / 5
if (page_index < committed):              // page already committed
    return true
page_base = (page_index << 12) + (this[1] ^ this[2])   // deobfuscated page base
if (MmCommitSessionMappedView(page_base, 0x1000) >= 0):
    memset(page_base, 0, 0x1000)          // zero the newly committed page
    ++*(DWORD*)(this + 0x24)              // increment committed counter
    return true
return false
```

### 3.5 Slot Math (Python-verified)

```
Section size:    0x2C000 = 180,224 bytes (44 pages)
Slot size:       0x2C0   = 704 bytes
Slots per page:  4096 // 704 = 5 (uses 3520 bytes, wastes 576 bytes/page)
Total pages:     44
Usable slots:    5 x 44 = 220 (0xDC)
Raw slots:       180224 // 704 = 256 (if no page waste - NOT used)

Slot address = view_base + (slot_index / 5) * 0x1000 + 0x2C0 * (slot_index % 5)
Bitmap index  = 5 * ((addr - view_base) >> 12) + ((addr & 0xFFF) / 0x2C0)
```

---

## 4. CSectionEntry Allocation and Free

### 4.1 Pool Tag and Type

| Property       | Value                                      |
|----------------|--------------------------------------------|
| Pool type      | PagedPoolSession                           |
| Tag            | 0x6F736955 = 'Uiso' (little-endian)        |
| Size           | 0x28 (40 bytes)                            |

### 4.2 When CSectionEntry is Created

CSectionEntry is created when CTypeIsolation::Allocate exhausts all existing sections. After 220 SURFACE allocations fill the first section, the 221st allocation triggers CSectionEntry::Create.

**User-mode trigger:** Creating 221+ bitmaps (CreateBitmap) without freeing forces new CSectionEntry creation.

### 4.3 When CSectionEntry is Freed

**CRITICAL FINDING: CSectionEntry is NEVER freed during normal operation.**

CSectionEntry::Destroy (0x1c00afd54) is only called from:
1. CTypeIsolation::Allocate failure path (effectively impossible - fresh section has 220 free slots)
2. CLookAsideTypeIsolation::Create failure path (during initialization)
3. CLookAsideTypeIsolation::Destroy (session teardown only)
4. TypeIsolationFactory::Destroy (factory teardown)

**CTypeIsolation::Free does NOT destroy CSectionEntry.** The Free path only clears the bitmap bit and zeroes the slot. There is no "all slots free -> destroy CSectionEntry" logic. CSectionEntry objects persist until session teardown.

### 4.4 User-Mode Triggerability

| Action                     | Creates CSectionEntry? | Frees CSectionEntry? |
|----------------------------|------------------------|----------------------|
| CreateBitmap (221st+)      | YES (when sections full) | NO                  |
| DeleteBitmap               | NO                     | NO (only frees slot) |
| Delete all bitmaps in sect | NO                     | NO (CSectionEntry persists) |
| Session logoff             | NO                     | YES (session teardown) |

---

## 5. Corruption Approaches

### 5.1 Corrupt CSectionEntry ViewBase (+0x18)

**Concept:** Overwrite the ViewBase field at CSectionEntry+0x18 to redirect SURFACE allocation to controlled memory.

**Requirements:**
- (a) Kernel address of the target CSectionEntry
- (b) Kernel write primitive (arbitrary write gadget)

**Getting the address - NtQuerySystemInformation:**
- `SystemBigPoolInformation` (class 0x42): CSectionEntry is only 0x28 bytes - far below the tracking threshold (>= 0x1000). **Cannot leak.**
- `SystemPoolInformation` (class 0x09): Returns pool statistics, not individual allocations. **Cannot leak.**
- Session pool tracking is internal to the kernel. No standard user-mode API exposes PagedPoolSession allocation addresses for small blocks.
- `GdiSharedHandleTable` (via PEB): Contains kernel addresses of GDI SURFACE objects (section memory), NOT CSectionEntry addresses (session pool). Cannot map backward from SURFACE address to CSectionEntry without scanning session pool.

**VERDICT: GO* - but only with a pre-existing kernel information leak + write primitive. The GDI type isolation itself does not leak CSectionEntry addresses.**

### 5.2 UAF on CSectionEntry

**Concept:** Free a CSectionEntry, reclaim the 0x28-byte session pool allocation with controlled data, then trigger a new SURFACE allocation using the reclaimed CSectionEntry.

**Analysis:**
- CSectionEntry is NEVER freed during normal operation. Deleting all bitmaps only clears bitmap bits and zeroes slots. The CSectionEntry remains in the linked list.
- CSectionEntry::Destroy is only called during session teardown or creation-failure cleanup.
- There is no user-mode action that triggers CSectionEntry::Destroy.

**VERDICT: NO-GO. Cannot trigger CSectionEntry free from user mode. No UAF window exists.**

### 5.3 Reclaim with Controlled Data (Pool Spray)

**Concept:** If CSectionEntry were freed, spray 0x28-byte PagedPoolSession allocations with tag 'Uiso' to reclaim.

**Analysis:**
- CSectionEntry is never freed -> no reclaim opportunity.
- Even if freed: modern Windows (8+) zeroes pool blocks by default. Controlled data would be overwritten with zeros.
- The 0x28-byte size class is heavily used by 'Uiso' tag (both CSectionEntry and CSectionBitmapAllocator).

**VERDICT: NO-GO. No free occurs, and pool zeroing prevents reclaim even if it did.**

### 5.4 Corrupt Section Object Pointer (+0x10)

**Concept:** Replace SectionObject at CSectionEntry+0x10 with a section created via NtCreateSection, then map the same section in user mode via NtMapViewOfSection for direct read/write to SURFACE objects.

**Analysis:**
- Requirements: CSectionEntry address + kernel write primitive.
- The SectionObject is a kernel object pointer. From user mode, we cannot obtain the kernel object pointer for our section (NtQueryObject does not return kernel addresses).
- ObReferenceObjectByHandle is a kernel API, not accessible from user mode.

**VERDICT: NO-GO from user mode alone. Requires kernel write AND kernel API to obtain section object pointer. If a kernel write exists, ViewBase at +0x18 is simpler.**

### 5.5 Corrupt CSectionBitmapAllocator (XOR-Obfuscated Fields)

**Concept:** Overwrite the obfuscated ViewBase at CSectionBitmapAllocator+0x08 to redirect slot address computation.

**Analysis:**
- ViewBase stored as `ViewBase ^ Cookie` at +0x08. Cookie at +0x10.
- To write a valid obfuscated pointer, need to know the Cookie: `new_value = target ^ Cookie`.
- Cookie generated from `RtlRandomEx` seeded by `__rdtsc()` - 64-bit random, unpredictable from user mode.
- Alternatively, overwrite Cookie at +0x10 to known value, then overwrite +0x08 with target directly. Requires two precise writes.

**VERDICT: NO-GO without multi-write primitive or Cookie leak. CSectionEntry+0x18 ViewBase is simpler (no obfuscation).**

### 5.6 Corrupt Linked List Pointers (Flink/Blink)

**Concept:** Overwrite CSectionEntry Flink (+0x00) or Blink (+0x08) to point to fake CSectionEntry in controlled memory.

**Analysis:**
- List traversal protected by CPlatformReaderWriterLock (pushlock at CTypeIsolation+0x10).
- Integrity check: `if (*v9 != a1) __fastfail(3u)` - verifies prev node's Flink points back. Corrupting one pointer triggers __fastfail -> BSOD.
- To pass: need 4 precise writes (fake_entry.Blink, prev.Flink, fake.Flink, next.Blink).
- High BSOD risk if any pointer is inconsistent.

**VERDICT: THEORETICALLY POSSIBLE but requires 4+ precise kernel writes + fake CSectionEntry in kernel-accessible memory. High __fastfail BSOD risk. Not practical vs. directly overwriting ViewBase.**

### 5.7 Non-Zeroed Free Check

**Analysis - three layers of zeroing:**

1. **CSectionBitmapAllocator::Free** (0x1c0083690): `memset(slot, 0, 0x2C0)` - zeroes SURFACE slot
2. **CTypeIsolation::Free** (0x1c01493e0): `memset(surf, 0, 0x2C0)` - zeroes before lookaside push
3. **FreeIsolatedType** (0x1c002b910): `memset(ListEntry, 0, 0x2C0)` - zeroes before lookaside push

All three paths zero the full 0x2C0-byte SURFACE object. For CSectionEntry itself: ExFreePoolWithTag on modern Windows zeroes pool blocks by default.

**VERDICT: NO-GO. All freed memory is zeroed at every layer. No residual data.**

---

## 6. CLookAsideTypeIsolation Architecture

### 6.1 Structure Layout (0x90 bytes = 144 bytes)

| Offset | Size | Field                  | Description |
|--------|------|------------------------|-------------|
| 0x00   | 8    | Flink                  | CSectionEntry list head (doubly-linked) |
| 0x08   | 8    | Blink                  | CSectionEntry list tail |
| 0x10   | 8    | PushLock               | CPlatformReaderWriterLock* (list synchronization) |
| 0x18   | 8    | DebugLookaside         | PAGED_LOOKASIDE_LIST* (debug mode only, 0 in prod) |
| 0x20   | 4    | SlotCount              | Total slots across all sections (220 per section) |
| 0x24   | 1    | IsLookasideMode        | 0 = section-based (production), 1 = lookaside (debug) |
| 0x30   | 0x60 | LOOKASIDE_LIST_EX      | Outer lookaside list (SLIST cache for SURFACE reuse) |
| 0x30   | 16   | SLIST_HEADER           | Depth + sequence |
| 0x40   | 2    | MaxDepth               | 0x100 (256) - max cached SURFACE objects |
| 0x44   | 4    | AllocCount             | Incremented on each SURFACE::Allocate |
| 0x48   | 4    | AllocMissCount         | Incremented when lookaside pop fails |
| 0x4C   | 4    | FreeCount              | Incremented on each FreeIsolatedType |
| 0x50   | 4    | FreeOverflowCount      | Incremented when lookaside full -> section free |
| 0x60   | 8    | AllocCallback          | Function pointer -> CTypeIsolation::Allocate path |
| 0x68   | 8    | FreeCallback           | Function pointer -> CTypeIsolation::Free path |

### 6.2 Pool Details

| Property    | Value                              |
|-------------|------------------------------------|
| Pool type   | PagedPool (0x200) - NOT session    |
| Tag         | 'Uiso' (0x6F736955)                |
| Size        | 0x90 (144 bytes)                   |
| Global      | gpTypeIsolation[0]                 |

### 6.3 Allocation Flow (Production Mode)

```
SURFACE::Allocate
  -> ExpInterlockedPopEntrySList(LookasideListEx at +0x30)    [FAST PATH]
  -> if empty: AllocCallback -> CTypeIsolation::Allocate       [SLOW PATH]
    -> iterate CSectionEntry list
    -> CSectionBitmapAllocator::Allocate for each
    -> if all full: CSectionEntry::Create -> new section
```

### 6.4 Free Flow (Production Mode)

```
SURFACE::Free
  -> ReleaseReferenceCountedObjectHandle
  -> Win32FreePool (if owned pool allocation)
  -> FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>
    -> memset(surf, 0, 0x2C0)
    -> if SLIST depth < 0x100: push to LookasideListEx SLIST   [CACHE]
    -> if full: FreeCallback -> CTypeIsolation::Free            [SECTION RETURN]
      -> find owning CSectionEntry via CheckAllocationStatus
      -> CSectionBitmapAllocator::Free: clear bit, memset(slot, 0, 0x2C0)
```

---

## 7. Type Isolation Global Arrays

### 7.1 gpTypeIsolation (kernel GDI types)

| Index | Type                                              | Section  | Slot  | Slots |
|-------|---------------------------------------------------|----------|-------|-------|
| [0]   | CLookAsideTypeIsolation<180224,704> (SURFACE)     | 0x2C000  | 0x2C0 | 220   |
| [1]   | CLookAsideTypeIsolation<36864,144>                | 0x9000   | 0x90  | 252   |
| [2]   | CTypeIsolation<40960,160>                         | 0xA000   | 0xA0  | 280   |
| [3]   | CTypeIsolation<49152,192>                         | 0xC000   | 0xC0  | 256   |
| [4]   | CTypeIsolation<81920,320>                         | 0x14000  | 0x140 | 288   |
| [5]   | CTypeIsolation<917504,3584>                       | 0xE0000  | 0xE00 | 224   |
| [6]   | CTypeIsolation<28672,112>                         | 0x7000   | 0x70  | 252   |
| [7]   | CTypeIsolation<233472,912>                        | 0x39000  | 0x390 | 228   |

Global symbol: `?gpTypeIsolation@@3PEAPEAEEA` @ 0x1c0250288

### 7.2 gpUserTypeIsolation (user object types)

| Index | Type                          | Section  | Slot  |
|-------|-------------------------------|----------|-------|
| [0]   | CTypeIsolation<36864,144>     | 0x9000   | 0x90  |
| [1]   | CTypeIsolation<40960,160>     | 0xA000   | 0xA0  |
| [2]   | CTypeIsolation<86016,336>     | 0x15000  | 0x150 |
| [3]   | CTypeIsolation<81920,160>     | 0x14000  | 0xA0  |
| [4]   | CTypeIsolation<24576,96>      | 0x6000   | 0x60  |
| [5]   | CTypeIsolation<28672,112>     | 0x7000   | 0x70  |

Global symbol: `?gpUserTypeIsolation@@3PEAPEAEEA` @ 0x1c02507e8

### 7.3 HMTagToIsolatedType Mapping @ 0x1c0029864

| HMtag | IsolatedType Index | gpUserTypeIsolation Entry |
|-------|--------------------|---------------------------|
| 1     | 2                  | CTypeIsolation<86016,336> |
| 2     | 1                  | CTypeIsolation<40960,160> |
| 3     | 3                  | CTypeIsolation<81920,160> |
| >3    | 6                  | (falls through)           |

HMAllocateIsolatedType @ 0x1c00297f0 uses gpUserTypeIsolation.
HMFreeIsolatedType @ 0x1c0029778 uses gpUserTypeIsolation.
SURFACE uses gpTypeIsolation[0] directly via SURFACE::Allocate/SURFACE::Free.

---

## 8. PlatformCreateSection Details

```
PlatformCreateSection  @ 0x1c00a202c
  MmCreateSection(
    &Object,
    0xF001F,           // DesiredAccess
    NULL,               // ObjectAttributes
    &SectionSize,       // MaximumSize = 0x2C000 for SURFACE
    SEC_COMMIT = 4,     // AllocationAttributes
    PAGE_READWRITE = 0x4000000,  // Win32Protect
    NULL,               // FileHandle
    NULL                // FileObject
  )
  -> Returns kernel section object pointer

PlatformMapViewInSessionSpace @ 0x1c00a1fe4:
  MmMapViewInSessionSpace(Section, &ViewBase, &ViewSize)
  -> Maps section in session address space (kernel-mode only)
```

---

## 9. Error Handling - PlatformAbort

```
PlatformAbort  @ 0x1c014d890
  reason 0: KeBugCheckEx(0x164, 9, ptr, 0, 0)    // unknown
  reason 1: KeBugCheckEx(0x164, 0x23, ptr, 0, 0)  // misaligned slot
  reason 2: KeBugCheckEx(0x164, 0x22, ptr, 0, 0)  // double free (bit already clear)
  reason 3: KeBugCheckEx(0x164, 0x21, ptr, 0, 0)  // freed object not found in any section
```

Bugcheck 0x164 = WIN32K_INTERNAL_SYSTEM_TERMINATION. Any corruption causing CheckAllocationStatus to return an unexpected value will BSOD.

---

## 10. Summary of GO/NO-GO Verdicts

| # | Approach                          | Verdict    | Reason |
|---|-----------------------------------|------------|--------|
| 1 | Corrupt ViewBase (+0x18)          | GO*        | Works with pre-existing info leak + write primitive. No obfuscation on this field. |
| 2 | UAF on CSectionEntry              | NO-GO      | CSectionEntry never freed during normal operation. No UAF window. |
| 3 | Pool spray reclaim                | NO-GO      | No free occurs. Pool zeroing on modern Windows prevents reclaim. |
| 4 | Replace SectionObject (+0x10)     | NO-GO      | Cannot get kernel object pointer for user-created section from user mode. |
| 5 | Corrupt BitmapAllocator fields    | NO-GO      | XOR obfuscation with unpredictable 64-bit cookie. Cannot write valid value. |
| 6 | Corrupt linked list (Flink/Blink) | THEORY     | Requires 4+ precise writes + fake CSectionEntry in kernel memory. __fastfail risk. |
| 7 | Non-zeroed free exploit           | NO-GO      | Three layers of memset(0) zeroing on every free path. |

**\* GO with prerequisites:** Approach 1 is viable IF the attacker already possesses:
- A kernel information leak to obtain the CSectionEntry address (not available through standard APIs - 0x28 bytes is below BigPool tracking threshold; GdiSharedHandleTable gives SURFACE addresses, not CSectionEntry addresses)
- A kernel write primitive to overwrite the 8-byte ViewBase at CSectionEntry+0x18

**GDI type isolation itself does not provide the info leak or write primitive.** It is a hardened allocation scheme that prevents traditional pool-based UAF/reclaim attacks against GDI objects. The section-backed memory isolates SURFACE objects from kernel pool, and the XOR obfuscation in the bitmap allocator adds defense-in-depth. The main remaining attack surface is the un-obfuscated CSectionEntry fields (ViewBase, SectionObject, BitmapAllocator pointer), which require separate vulnerabilities to exploit.

---

## Appendix A: Key Function Addresses

| Function                                                        | Address       |
|-----------------------------------------------------------------|---------------|
| CSectionEntry<180224,704>::Create                               | 0x1c00a1df0   |
| CSectionEntry<180224,704>::Initialize                           | 0x1c00a1e4c   |
| CSectionEntry::~CSectionEntry (shared)                          | 0x1c00afd80   |
| CSectionEntry::Destroy (shared)                                 | 0x1c00afd54   |
| CSectionBitmapAllocator<180224,704>::Create                     | 0x1c00a1eac   |
| CSectionBitmapAllocator<180224,704>::Initialize                 | 0x1c00a1f24   |
| CSectionBitmapAllocator<180224,704>::Allocate                   | 0x1c0081534   |
| CSectionBitmapAllocator<180224,704>::Free                       | 0x1c0083690   |
| CSectionBitmapAllocator<180224,704>::CommitSlot                 | 0x1c0081650   |
| CTypeIsolation<180224,704>::Allocate                            | 0x1c0149198   |
| CTypeIsolation<180224,704>::Free                                | 0x1c01493e0   |
| CTypeIsolation<180224,704>::Initialize                          | 0x1c00b6930   |
| CLookAsideTypeIsolation<180224,704>::Create                     | 0x1c00b67b4   |
| CLookAsideTypeIsolation<180224,704>::Initialize                 | 0x1c00b68c4   |
| CLookAsideTypeIsolation<180224,704>::Destroy                    | 0x1c00b7920   |
| SURFACE::Allocate                                               | 0x1c00808c0   |
| SURFACE::Free                                                   | 0x1c002b8c0   |
| FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>           | 0x1c002b910   |
| HMAllocateIsolatedType                                          | 0x1c00297f0   |
| HMFreeIsolatedType                                              | 0x1c0029778   |
| HMTagToIsolatedType                                             | 0x1c0029864   |
| PlatformCreateSection                                           | 0x1c00a202c   |
| PlatformMapViewInSessionSpace                                   | 0x1c00a1fe4   |
| PlatformAbort                                                   | 0x1c014d890   |
| InitializeUserTypeIsolation                                     | 0x1c00aef80   |
| gpTypeIsolation                                                 | 0x1c0250288   |
| gpUserTypeIsolation                                             | 0x1c02507e8   |

## Appendix B: All CSectionEntry Template Specializations

| Template Params      | Section Size | Slot Size | Usable Slots | PlatformCreateSection Arg |
|----------------------|-------------|-----------|--------------|---------------------------|
| <24576, 96>          | 0x6000      | 0x60      | 168 (42 pg)  | 0x6000                    |
| <28672, 112>         | 0x7000      | 0x70      | 252 (28 pg)  | 0x7000                    |
| <36864, 144>         | 0x9000      | 0x90      | 252 (28 pg)  | 0x9000                    |
| <40960, 160>         | 0xA000      | 0xA0      | 280 (40 pg)  | 0xA000                    |
| <49152, 192>         | 0xC000      | 0xC0      | 256 (32 pg)  | 0xC000                    |
| <81920, 160>         | 0x14000     | 0xA0      | 500 (20 pg)  | 0x14000                   |
| <81920, 320>         | 0x14000     | 0x140     | 288 (16 pg)  | 0x14000                   |
| <86016, 336>         | 0x15000     | 0x150     | 228 (21 pg)  | 0x15000                   |
| <180224, 704> SURFACE| 0x2C000     | 0x2C0     | 220 (44 pg)  | 0x2C000                   |
| <233472, 912>        | 0x39000     | 0x390     | 228 (57 pg)  | 0x39000                   |
| <917504, 3584>       | 0xE0000     | 0xE00     | 224 (224 pg) | 0xE0000                   |
