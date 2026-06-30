# win32kbase.sys Deep Analysis Report

## IDA Instance Info
- IDA Base Address: 0x1C0000000
- Module: win32kbase.sys
- Hex-Rays: Ready
- Analysis Date: 2026-06-30
- Target OS: Windows 10 22H2 (build 19045)

## Task A: Validated Functions

### HmgShareLockCheck (0x1C002F050)
- **Signature**: `__int64 __fastcall HmgShareLockCheck(unsigned int handle, char type)`
- **Purpose**: Resolves a GDI handle to a kernel object pointer with type+stamp validation, increments share count
- **Validation**:
  - Type check: byte at handle_entry+14 must match `type` parameter
  - Stamp check: word at handle_entry+12 must match HIWORD(handle)
  - Handle index resolution through GdiHandleEntryDirectory with multi-level page table
- **Lock model**: Uses HANDLELOCK::vLockHandle (push lock per entry), increments DWORD at object+8 (share count)
- **Type 5 (SURFACE)**: Also does reference tracking at object+680 via NSInstrumentation
- **Type 16**: Reference tracking at object+136 via TrackObjectReferenceIncrement
- **Returns**: Kernel object pointer or 0 on failure
- **Key insight**: Both type AND stamp must match. The stamp is the upper 16 bits of the handle value, stored at entry+12.

### SURFREF::SURFREF (0x1C001DA78)
- **Signature**: `SURFREF *__fastcall SURFREF::SURFREF(SURFREF *this, HSURF hsurf)`
- **Purpose**: Constructor that locks a SURFACE handle
- **Logic**:
  - Calls UnexpectedThreadTerminationHandler constructor for RAII cleanup
  - Calls `HmgShareLockCheck(hsurf, 5)` where 5 = SURFACE type
  - Stores result at `this+0x20` (offset 32 = 4th qword)
- **Key insight**: SURFREF object holds the locked surface pointer at offset 0x20. If the handle is invalid/freed, the pointer is 0.

### EngModifySurface (0x1C009B440)
- **Signature**: `BOOL EngModifySurface(HSURF hsurf, HDEV hdev, FLONG flHooks, FLONG flSurface, DHSURF dhsurf, PVOID pvScan0, LONG lDelta, PVOID pvReserved)`
- **Purpose**: Modifies surface properties including pvScan0
- **Critical write**: `*(_QWORD *)(surface + 80) = pvScan0;` — writes pvScan0 to SURFACE+0x50
- **Also writes**: lDelta to SURFACE+0x58, iType to SURFACE+0x64, pvBits to SURFACE+0x48
- **Validation**: 
  - hdev must be non-null
  - HmgShareLockIgnoreStockBit must succeed (type 5 check with relaxed stamp)
  - flSurface must not have bits 0xFFFFFFF0 set
  - pvScan0 and lDelta must both be non-zero for the pvScan0 write path
  - Various flag conditions must be met
- **Callers in win32kbase.sys**: Only MulEnableSurface (0x1C0142080), which passes pvScan0=NULL
- **Key insight**: EngModifySurface is an exported Eng* function callable by display drivers. It cannot be called directly from user mode. However, it confirms pvScan0 is at SURFACE+0x50 with NO validation of the pointer value itself.

### EngCreateBitmap (0x1C00A34A0)
- **Signature**: `HBITMAP EngCreateBitmap(SIZEL sizl, LONG lWidth, ULONG iFormat, FLONG fl, PVOID pvBits)`
- **Purpose**: Creates a bitmap surface (thin wrapper)
- **Logic**: Calls `hbmCreateDriverSurface(0, nullptr, sizl, lWidth, iFormat, fl, pvBits)`
- **hbmCreateDriverSurface** (0x1C00A34D4): Calls `CreateDriverSurfMem` then extracts handle from SURFMEM+0x20
- **CreateDriverSurfMem** (0x1C00C9DBC): Calls `SURFMEM::bCreateDIB` for actual allocation

## Task B: GDI Handle Manager Analysis

### gpHandleManager (0x1C0250C00)
- **Type**: `GdiHandleManager*` — pointer to 32-byte structure
- **Structure layout** (from GdiHandleManager::Create at 0x1C006C408):
  - offset 0: DWORD (count/threshold, compared to 0x10000)
  - offset 4: DWORD (unused/flags)
  - offset 8: DWORD (gMaxGdiHandleCount)
  - offset 16: QWORD (pointer to GdiHandleEntryDirectory)
  - offset 24: QWORD (unused)
- **Pool tag**: "Ghmc" (0x636D6847)
- **Allocation**: Win32AllocPool(32, 0x636D6847)

### GdiHandleEntryDirectory
- **Structure layout** (from GetEntry at 0x1C0031220):
  - offset 2: WORD (range multiplier)
  - offset 2056 (514*4): DWORD (base index)
  - offset 8*(N+1): QWORD sub-directory pointers
- **Sub-directory entry**:
  - offset 0: QWORD (base pointer to 24-byte _ENTRY array)
  - offset 20: DWORD (max entries)
  - offset 24: QWORD (pointer to page table — 16-byte lock entries)

### Handle Table Entry (_ENTRY) — 24 bytes
```
Offset  Size  Field           Description
+0x00   4     dwHandle        Handle value (lower 24 bits = index)
+0x04   4     dwOwner         Owner PID
+0x08   4     dwLockFlags     Lock flags (bit 0 = locked)
+0x0C   2     wStamp          Handle stamp (must match HIWORD of handle)
+0x0E   1     bType           GDI object type (1=DC, 4=Region, 5=SURFACE, 8=Palette, 10=Font, 16=Brush)
+0x0F   1     bFlags          Entry flags (bit 5=0x20 deleted, bit 6=0x40 undeletable, bit 1=0x02 lazy-delete)
+0x10   8     pObject         Kernel object pointer — THE KASLR LEAK (visible in user mode!)
```
- **Total size**: 24 bytes (0x18)
- **Shared section**: `gpentHmgr = gpGdiSharedMemory` (mapped in user mode as PEB->GdiSharedHandleTable)
- **Section creation**: Win32CreateSection with 1,573,528 bytes (0x180018)
- **Section mapping**: MmMapViewInSessionSpace (kernel) + MmMapViewOfSection (user mode, PAGE_READWRITE)

### Lock Entry — 16 bytes (kernel-only page table)
```
Offset  Size  Field           Description
+0x00   8     PushLock        EX_PUSH_LOCK for this entry
+0x08   8     pObject         Kernel object pointer (same as _ENTRY+0x10)
```
- **Not visible in user mode** — separate from the shared section
- **Accessed via**: `page_table[index >> 8] + 16 * (index & 0xFF)`

### Handle Resolution Flow
1. Extract index: `handle & 0xFFFFFF` (lower 24 bits)
2. If index >= 0x10000, check if handle manager supports extended indices
3. Decode through GdiHandleManager::DecodeIndex (may XOR/transform)
4. Find sub-directory via GdiHandleEntryDirectory
5. Get 24-byte _ENTRY at `subdir_base + 24 * decoded_index`
6. Get 16-byte lock entry at `page_table[decoded_index >> 8] + 16 * (decoded_index & 0xFF)`
7. Acquire push lock on the lock entry
8. Validate type (entry+14) and stamp (entry+12)
9. Return object pointer from lock_entry+8

### Hmg* Function Catalog (40+ functions found)
| Function | Address | Purpose |
|---|---|---|
| HmgAlloc | 0x1C0001410 | Allocate GDI object with handle |
| HmgCreate | 0x1C006BCFC | Initialize handle manager (lookaside lists, type isolation, shared section) |
| HmgFree | 0x1C007C860 | Free GDI object by handle |
| HmgLock | 0x1C002EE50 | Exclusive lock (thread-owned, recursive) |
| HmgShareLock | 0x1C002FC10 | Shared lock (increments share count) |
| HmgShareLockCheck | 0x1C002F050 | Shared lock with type+stamp validation |
| HmgShareLockEx | 0x1C002EA50 | Extended shared lock with extra parameter |
| HmgShareLockIgnoreStockBit | 0x1C009A4B8 | Shared lock for type 5, ignores stamp bit 7 (stock objects) |
| HmgShareLockCheckIgnoreStockBit | 0x1C0032E40 | Same with check variant |
| HmgUnlock | 0x1C00A2804 | Exclusive unlock (type 4 only — DC specific) |
| HmgRemoveObject | 0x1C0032640 | Remove object from handle table |
| HmgReplaceObject | 0x1C002C750 | Replace one object with another in handle table |
| HmgSwapLockedHandleContents | 0x1C00BE150 | Swap two locked handles' contents |
| HmgMarkLazyDelete | 0x1C0034A50 | Mark object for lazy deletion |
| HmgValidHandle | 0x1C006B7C0 | Validate handle |
| HmgSetOwner | 0x1C00368E0 | Set handle owner |
| HmgIncrementShareReferenceCount | 0x1C002E1C0 | Increment share count |
| HmgDecrementShareReferenceCountEx | 0x1C002F680 | Decrement share count |
| HmgDecrementExclusiveReferenceCountEx | 0x1C002F320 | Decrement exclusive count |
| HmgMarkUndeletable | 0x1C001CDB0 | Mark object undeletable |
| HmgMarkDeletable | 0x1C0087350 | Mark object deletable |
| HmgMarkLazyDelete | 0x1C0034A50 | Mark for lazy deletion |
| HmgQueryAltLock | 0x1C000DE90 | Query alternate lock count |
| HmgLockAndModifyHandleType | 0x1C0017460 | Lock and change handle type |
| HmgModifyHandleType | 0x1C00174D0 | Modify handle type |

### Kernel Handle Manager vs User-Mode PEB->GdiSharedHandleTable
- **Same shared section**: Both point to the same memory (gpGdiSharedMemory / gpentHmgr)
- **User mode sees**: The 24-byte _ENTRY array with object pointers at offset 0x10
- **Kernel mode has**: Additional page table with push locks (16-byte entries, kernel-only)
- **CRITICAL**: The object pointer at _ENTRY+0x10 is visible in user mode — this is the KASLR bypass
- **Can the kernel handle manager be corrupted from user mode?**: The shared section is mapped PAGE_READWRITE in user mode. On modern Windows 10 22H2, this section may be mapped read-only for user mode (the MmMapViewOfSection call uses protection 4 = PAGE_READWRITE, but Windows may enforce read-only for user-mode mappings of this section). Testing required to confirm.

## Task C: EngCreateBitmap and SURFACE Allocation

### SURFACE::tSize
- **Value**: 0x2B8 (696 bytes) — global at 0x1C024E5E0
- **Type isolation slot size**: 0x2C0 (704 bytes) — 8 bytes padding/alignment

### SURFACE Structure Layout (reconstructed from code analysis)
```
Offset  Size  Field              Description
------  ----  -----------------  ------------------------------------------
0x00    8     pEntry             Pointer to handle table entry (_ENTRY*)
0x08    4     cShare             Share reference count (DWORD)
0x0C    2     cLock              Exclusive lock count (WORD)
0x0E    2     wFlags             Object flags (bit 15 = 0x8000 = lookaside-allocated)
0x10    8     pThread            Exclusive owner thread (KTHREAD*)
--- SURFOBJ begins at 0x18 ---
0x18    8     dhsurf             Device-managed surface handle (SURFOBJ.dhsurf)
0x20    8     hsurf              Surface handle / entry pointer (SURFOBJ.hsurf)
0x28    8     ppdev              Physical device pointer (extra field)
0x30    8     hdev               Device handle (SURFOBJ.hdev)
0x38    4     sizlBitmap.cx      Bitmap width
0x3C    4     sizlBitmap.cy      Bitmap height
0x40    4     cjBits             Size of bitmap bits
0x44    4     (padding)          Alignment padding
0x48    8     pvBits             Pointer to bitmap bits (SURFOBJ.pvBits)
0x50    8     pvScan0            Pointer to first scanline (SURFOBJ.pvScan0) *** TARGET ***
0x58    4     lDelta             Scanline stride
0x5C    4     iUniq              Unique surface ID
0x60    4     iBitmapFormat      Bitmap format enum
0x64    2     iType              Surface type (0=bitmap, 1=DC, 3=driver)
0x66    2     fjFlags            Surface flags (bit 0=bottom-up, bit 7=section, etc.)
0x68    8     (unknown)          Unknown field
0x70    4     flFlags            Surface flags (0x400000=driver, 0x200=hooked, etc.)
0x74    4     flFlags2           More flags
0x78    4     flFlags3           More flags
0x80    8     pPalette           XEPALOBJ palette object pointer
0x88    8     (unknown)          Unknown
0x90    8     (unknown)          Unknown
0x98    8     (unknown)          Unknown
0xA0    8     (unknown)          Unknown
0xA8    8     (unknown)          Unknown
0xB0    8     (unknown)          Unknown
0xB8    8     pvReserved         Reserved pointer (a4 parameter)
0xC0    8     pvAlpha            Alpha surface data
0xC8    8     cjAlpha            Alpha data size
0xD0    4     dwPID              Owner process ID (PID & 0xFFFFFFFC)
0xD4    4     dwFlags            Flags (a5 parameter)
0xD8    4     bUnused            Unused (a10 parameter)
0xE0    8     (unknown)          Unknown
0xE8    16    LinkedList         Doubly-linked list (prev/next)
0xF8    8     SectionObject      Section object for mapped surfaces
0x100   4     (zero)            Initialized to 0
0x104   4     (zero)            Initialized to 0
0x148   16    SectionData        Section metadata (OWORD)
0x158   16    SectionData2       Section metadata (OWORD)
0x168   16    SectionData3       Section metadata (OWORD)
0x178   16    SectionData4       Section metadata (OWORD)
0x188   16    SectionData5       Section metadata (OWORD)
0x198   16    SectionData6       Section metadata (OWORD)
0x1A8   16    SectionData7       Section metadata (OWORD)
0x1B8   16    SectionData8       Section metadata (OWORD)
0x1C8   16    SectionData9       Section metadata (OWORD)
0x1D8   16    SectionData10      Section metadata (OWORD)
0x1E8   8     SectionPtr         Section pointer (QWORD at +61*8)
0x210   16    LinkedList2        Second linked list (prev/next)
0x230   8     (zero)            Initialized to 0
0x238   8     (zero)            Initialized to 0
0x248   8     SectionObject2     Section object for shared surfaces
0x250   8     SectionViewBase    Section view base address
0x258   8     CalculatedView     Calculated user-mode view address
0x260   4     dwSectionFlag      Section flag (1)
0x264   4     dwSectionPID       Section PID
0x268   4     dwSectionFlag2     Section flag (1)
0x270   8     (zero)            Initialized to 0
0x278   8     (zero)            Initialized to 0
0x288   8     (zero)            Initialized to 0
0x290   4     (zero)            Initialized to 0
0x2A8   8     RefTracker         Reference tracker (NSInstrumentation, for type 5)
0x2B0   1     bSectionFlag       Section flag (v76 parameter)
------ Total: 0x2B8 (696 bytes) ------
With type isolation padding: 0x2C0 (704 bytes)
```

### SURFACE Allocation Path
1. **EngCreateBitmap** → hbmCreateDriverSurface → CreateDriverSurfMem → SURFMEM::bCreateDIB
2. **SURFMEM::bCreateDIB** (0x1C0027C60):
   - Calculates bitmap bits size based on format (1bpp, 4bpp, 8bpp, 16bpp, 24bpp, 32bpp)
   - Total allocation = bitmap_bits_size + SURFACE::tSize (for inline allocation)
   - Multiple allocation paths for bitmap bits:
     - User memory (EngAllocUserMemEx) — for user-mode accessible bitmaps
     - Shared section (AllocateSharedSection) — for cross-process surfaces
     - Kernel section (AllocateKernelSection) — for large surfaces
     - Pool allocation (PALLOCMEM2) — for small surfaces
   - Calls **SURFACE::Allocate** for the SURFACE object itself
   - Initializes all SURFACE fields
   - Calls HmgInsertObjectHelper::Insert to register in handle table
3. **SURFACE::Allocate** (0x1C00808C0):
   - Uses **Type Isolation** (not standard lookaside)
   - Pops from SLIST at type_isolation_obj+48
   - If SLIST empty, calls allocation function at type_isolation_obj+96
   - Calls AcquireReferenceCountedObjectHandle for reference tracking

### Pool Tags
| Tag | Hex | Used For |
|---|---|---|
| Gh05 | 0x35306847 | SURFACE direct pool allocation (type 5) |
| Gla5 | 0x35616C47 | SURFACE standard lookaside (type 5, old path) |
| Gila | 0x616C6947 | SURFACE type isolation pool (new path) |
| Uiso | 0x6F736955 | Type isolation metadata objects |
| Ghmc | 0x636D6847 | GdiHandleManager structure |

## Task D: EngModifySurface and pvScan0 Writers

### EngModifySurface pvScan0 Write Path
At 0x1C010777F:
```c
*(_QWORD *)(surface + 80) = pvScan0;    // SURFACE+0x50 = pvScan0
*(_DWORD *)(surface + 88) = lDelta;     // SURFACE+0x58 = lDelta
*(_WORD *)(surface + 100) = 0;          // SURFACE+0x64 = iType (set to bitmap)
```
Also writes:
- `SURFACE+0x48 (pvBits)` = pvScan0 or pvScan0 + lDelta*(height-1) depending on lDelta sign
- `SURFACE+0x66 (fjFlags)` = bit 0 set/cleared based on lDelta sign
- Various flag modifications at SURFACE+0x66, +0x70, +0x74

### All pvScan0 Write Paths Found
1. **SURFMEM::bCreateDIB** (0x1C0027C60):
   - At 0x1C002837A: `mov [r1+50h], r0` — sets pvScan0 = pvBits (for standard formats)
   - At 0x1C0028393: `mov [r2+50h], r1` — sets pvScan0 = pvBits (for bottom-up bitmaps)
   - At 0x1C00283C9: `mov [r1+50h], r0` — sets pvScan0 = pvBits (for top-down bitmaps)
   - At 0x1C00283D2: `mov [r0+50h], r13` — sets pvScan0 = 0 (for 9/10-bit formats)
   - At 0x1C0028577: `mov [r0+50h], r13` — sets pvScan0 = 0 (for section-mapped surfaces)
   - **pvScan0 is always set to pvBits or 0 during creation — no user-controlled value**

2. **EngModifySurface** (0x1C009B440):
   - At 0x1C010777F: `mov [r13+50h], pvScan0` — writes caller-provided pvScan0
   - **Only caller in win32kbase.sys**: MulEnableSurface, which passes pvScan0=NULL
   - **Exported function**: Can be called by display drivers (kernel mode only, not user syscalls)

3. **bMigrateSurfaceForConversion** (0x1C00BA100):
   - Swaps entire SURFACE contents between two surfaces, including pvScan0
   - Uses HmgSwapLockedHandleContents + manual field swaps
   - Called during surface format conversion (display driver context)

### No user-mode syscall directly writes pvScan0
The NtGdi* bitmap functions (NtGdiSetBitmapBits, NtGdiGetBitmapBits, NtGdiCreateBitmap, NtGdiCreateDIBSection) are in **win32kfull.sys**, not win32kbase.sys. They likely use bDoGetSetBitmapBits which reads pvScan0 from the SURFACE. The actual pvScan0 value is set during surface creation (always = pvBits) or via EngModifySurface (display driver only).

## Task E: GDI Object Free and Reclamation

### SURFACE::Free (0x1C002B8C0)
- Releases reference counted object handle
- If section flag set: frees the bitmap bits via Win32FreePool
- Calls **FreeIsolatedType<CLookAsideTypeIsolation<180224,704>>** to return to type isolation

### FreeIsolatedType (0x1C002B910)
```c
memset(ListEntry, 0, 0x2C0u);                    // ZERO entire 704-byte slot
if (ExQueryDepthSList(SLIST) < max_depth)
    ExpInterlockedPushEntrySList(SLIST, entry);  // Push to LIFO free list
else
    free_function(entry, SLIST);                 // Release underlying memory
```
- **CRITICAL**: The entire 0x2C0-byte slot is ZEROED before returning to free list
- **LIFO behavior**: Last-freed slot is first-reused
- **Max depth**: Checked at SLIST_HEADER+16; if exceeded, memory is released back to pool

### HmgFree (0x1C007C860)
- Acquires HmgrSemaphore
- Locks handle via HANDLELOCK::vLockHandle
- Gets object pointer and type from handle table
- Unlocks handle
- Releases semaphore
- For type 8 (palette): calls XEPALOBJ::FreePaletteMemory
- For other types: calls **FreeObject** (0x1C002BC40)

### FreeObject (0x1C002BC40)
- If word at object+14 >= 0 (bit 15 clear, NOT lookaside-allocated): calls Win32FreePool (direct pool free)
- If bit 15 set (lookaside-allocated): returns to lookaside list via function pointer at qword_1C0256D68
- **Note**: SURFACE objects freed via SURFACE::Free go through type isolation, NOT FreeObject

### Type Isolation System
**TypeIsolationFactory** creates 8 type isolation instances:
| Index | Class | ChunkSize | SlotSize | GDI Type |
|---|---|---|---|---|
| 0 | CLookAsideTypeIsolation<180224,704> | 0x2C000 | 0x2C0 | SURFACE (type 5) |
| 1 | CTypeIsolation<40960,160> | 0xA000 | 0xA0 | ? (type 4=Region?) |
| 2 | CTypeIsolation<49152,192> | 0xC000 | 0xC0 | ? |
| 3 | CLookAsideTypeIsolation<36864,144> | 0x9000 | 0x90 | ? (type 8=Palette?) |
| 4 | CTypeIsolation<81920,320> | 0x14000 | 0x140 | ? |
| 5 | CTypeIsolation<917504,3584> | 0xE0000 | 0xE00 | ? (type 10=Font?) |
| 6 | CTypeIsolation<28672,112> | 0x7000 | 0x70 | ? |
| 7 | CTypeIsolation<233472,912> | 0x39000 | 0x390 | ? (type 16=Brush?) |

**CLookAsideTypeIsolation** has an SLIST for fast LIFO allocation/free.
**CTypeIsolation** does NOT have an SLIST — uses a different (slower) allocation strategy.

### CLookAsideTypeIsolation<180224,704>::Initialize (0x1C00B68C4)
- ExInitializeLookasideListEx with:
  - Pool type: PagedPool (512)
  - Flags: 2
  - Size: 0x2C0 (704 bytes per slot)
  - Tag: **"Gila"** (0x616C6947)
  - Depth: 0x100 (256 initial entries)
- Also calls CTypeIsolation::Initialize for the base class

### Pool Reclaim Analysis
- **Type isolation prevents cross-type reclaim**: SURFACE objects only go into the SURFACE type isolation SLIST. A freed tagWND cannot reclaim a SURFACE slot.
- **Freed SURFACE slots are ZEROED**: memset(0, 0x2C0) before returning to SLIST
- **LIFO free list**: If you free SURFACE A and immediately allocate SURFACE B, B gets A's slot (but zeroed)
- **Standard lookaside lists still exist** (HmgInitializeLookAsideList) but SURFACE::Allocate uses type isolation instead
- **Can a window extra bytes allocation (tag "Usws") land in the same pool as SURFACE?**: NO — SURFACE uses "Gila" tag in PagedPool via type isolation, windows use different tags/pools

## Task F: SURFREF and Surface Locking

### SURFREF Lock Model
- SURFREF constructor calls HmgShareLockCheck with type 5
- SURFREF destructor (0x1C002CB94) decrements share count
- The surface pointer is stored at SURFREF+0x20
- If the handle is invalid/freed, the pointer is 0

### HmgShareLockIgnoreStockBit (0x1C009A4B8)
- **Relaxed stamp check**: `((HIWORD(handle) ^ entry_stamp) & 0xFFFFFF7F) == 0`
- This means bit 7 of the stamp is IGNORED — stock objects have this bit set
- Only checks type 5 (SURFACE)
- Used by EngModifySurface and NtGdiDeleteObjectApp for SURFACE deletion

### TOCTOU Analysis
- **Handle lock is held** during all surface operations (push lock per entry)
- The push lock prevents concurrent modification of the handle table entry
- However, the SURFACE object itself is only protected by the share count (object+8)
- If a surface has share count > 0, it cannot be deleted (HmgRemoveObject checks)
- **Potential TOCTOU**: Between SURFREF construction (lock) and surface use, if another thread frees the handle and the share count drops to 0, the surface could be freed while still referenced

### Use-After-Free Surface Lock Scenario
- If a SURFACE handle is freed but a SURFREF still holds a pointer to it:
  - SURFACE::Free zeroes the 0x2C0-byte slot and pushes to SLIST
  - The SURFREF still has the old (now-zeroed) pointer
  - Accessing the zeroed SURFACE would read nulls (pvScan0=0, etc.)
  - If another SURFACE is allocated in the same slot, the SURFREF would access the NEW surface's data
- This is a type-safe UAF (always a SURFACE in that slot) but data changes

## Task G: Additional pvScan0 Corruption Primitives

### Functions That Modify SURFACE Fields
1. **EngModifySurface** — writes pvScan0 (SURFACE+0x50), lDelta (+0x58), iType (+0x64), pvBits (+0x48)
2. **SURFMEM::bCreateDIB** — initializes all fields during creation
3. **bMigrateSurfaceForConversion** — swaps ALL fields between two surfaces
4. **SelectPaletteWorker** (0x1C0029675) — writes to [r0+50h] but likely a different structure (palette selection)
5. **BRUSHMEMOBJ constructor** (0x1C001D122) — writes to [r0+50h] but for brush objects, not SURFACE

### No User-Mode Path to Write Arbitrary pvScan0
- All pvScan0 write paths require kernel-mode display driver context
- NtGdi bitmap functions are in win32kfull.sys (not analyzed here)
- SetBitmapDimensionEx and similar APIs write to SURFACE+0x98 (dimension fields), not pvScan0
- **The only way to corrupt pvScan0 is through a kernel write primitive** (like the tagWND UAF)

## Task H: GDI Handle Type Validation

### Type Validation in Lock Functions
All GDI lock functions validate:
1. **Type check**: `entry[14] == expected_type` — byte at handle entry offset 14
2. **Stamp check**: `entry[12] == HIWORD(handle)` — word at handle entry offset 12

### HmgShareLockIgnoreStockBit Relaxation
- Stamp check: `((HIWORD(handle) ^ entry[12]) & 0xFFFFFF7F) == 0`
- Bit 7 of stamp is ignored (allows stock objects)
- Only for type 5 (SURFACE)

### Type Confusion Analysis
- **Can we pass a DC handle where a bitmap is expected?**: NO — type 1 (DC) != type 5 (SURFACE), lock fails
- **Can we modify the type in the handle table?**: Only if we can write to the shared section
- **HmgLockAndModifyHandleType** (0x1C0017460) and **HmgModifyHandleType** (0x1C00174D0) exist — these can change the type field in the handle entry. Need to analyze their callers to see if there's a user-callable path.
- **HmgSwapLockedHandleContents**: Swaps two handles of the SAME type (validated). Cannot be used for type confusion directly.
- **No function found that accesses offset 0x50 without type-checking first** — all access through SURFREF/HmgShareLock with type 5

## Task I: New Attack Surfaces

### NtGdiGetEntry (0x1C00AB2B0) — INFORMATION LEAK
- **Takes**: handle index (a1), user-mode buffer address (a2)
- **Copies 24 bytes** of the handle table entry to user mode:
  ```c
  *(_OWORD *)a2 = *(_OWORD *)Entry;           // 16 bytes (handle, owner, lock, stamp, type, flags)
  *(_QWORD *)(a2 + 16) = *((_QWORD *)Entry + 2); // 8 bytes (object pointer at entry+16)
  ```
- **Only validation**: `a2 + 24 > MmUserProbeAddress` — just bounds check
- **IMPACT**: Any process can read ANY GDI handle table entry and get the kernel object pointer
- **This is an alternative KASLR bypass** to PEB->GdiSharedHandleTable
- **Can read entries for other processes' GDI objects** — may leak other kernel addresses

### HmgSwapLockedHandleContents (0x1C00BE150) — OBJECT POINTER SWAP
- Swaps object pointers between two GDI handles of the same type
- Also swaps internal SURFACE data (for type 5: offset 85*8=680, reference tracker)
- Only called from bMigrateSurfaceForConversion (display driver context)
- **If exploitable**: Could swap a legitimate SURFACE's object pointer with a controlled object

### HmgReplaceObject (0x1C002C750) — OBJECT REPLACEMENT
- Replaces one GDI object with another in the handle table
- Only called from RGNOBJAPI::bSwap (region swap)
- **If exploitable**: Could replace a SURFACE object pointer with controlled memory

### MmUnsecureVirtualMemory in SURFACE::bDeleteSurface
- SURFACE deletion calls MmUnsecureVirtualMemory for secured surfaces
- The secure handle is stored at SURFACE+0xE0 (offset 224)
- If the PID at SURFACE+0xD0 matches current process, it unsecures the memory
- **Potential for race**: If we can corrupt the PID field, we might unsecure another process's memory

### ZwFreeVirtualMemory in SURFACE::bDeleteSurface
- For user-memory surfaces (flag 0x8 set, not 0x80), calls EngFreeUserMem
- For section-mapped surfaces, calls ZwUnmapViewOfSection + ZwFreeVirtualMemory
- **Potential for use-after-free**: If the bitmap bits are freed but a reference still exists

### Shared Section Mapping
- gpHmgrSharedHandleSection is created with 1,573,528 bytes
- Mapped in session space (kernel) and in process space (user mode)
- The user-mode mapping contains the full handle table with kernel object pointers
- **If the section is writable in user mode**: Could directly modify object pointers → arbitrary kernel R/W

### Lookaside List Function Pointers
- qword_1C0256D50: Lookaside allocation function pointer
- qword_1C0256D58: Lookaside allocation function pointer (secondary)
- qword_1C0256D60: Lookaside free validation function pointer
- qword_1C0256D68: Lookaside free function pointer
- **If these can be corrupted**: Could redirect SURFACE allocation/free to controlled functions

## Task J: Pool Tags and Object Sizes

### All Pool Tags Found
| Tag | Hex | Size | Object Type | Allocation |
|---|---|---|---|---|
| Gila | 0x616C6947 | 0x2C0 (704) | SURFACE (type 5) | Type isolation (PagedPool) |
| Uiso | 0x6F736955 | 0x90 (144) | Type isolation metadata | ExAllocatePoolWithTag |
| Ghmc | 0x636D6847 | 0x20 (32) | GdiHandleManager | Win32AllocPool |
| Gh05 | 0x35306847 | variable | SURFACE (type 5) | Direct pool (PALLOCMEM2) |
| Gla5 | 0x35616C47 | 0x3B8 (952) | SURFACE (type 5) | Standard lookaside (old path) |
| Gh01 | 0x31306847 | 0x868 | Type 1 (DC) | Direct pool |
| Gla1 | 0x31616C47 | 0x868 | Type 1 (DC) | Standard lookaside |
| Gh04 | 0x34306847 | 0x70 | Type 4 (Region) | Direct pool |
| Gla4 | 0x34616C47 | 0x70 | Type 4 (Region) | Standard lookaside |
| Gh08 | 0x38306847 | 0xC8 | Type 8 (Palette) | Direct pool |
| Gla8 | 0x38616C47 | 0xC8 | Type 8 (Palette) | Standard lookaside |
| Gh10 | 0x31306847 | 0xB8 | Type 16 (Brush) | Direct pool |
| Gla10 | 0x31616C47 | 0xB8 | Type 16 (Brush) | Standard lookaside |
| Gh0A | 0x41306847 | 0x278 | Type 10 (Font) | Direct pool |
| GlaA | 0x41616C47 | 0x278 | Type 10 (Font) | Standard lookaside |
| Gh0B | 0x42306847 | 0x390 | Type 11 (Enum) | Direct pool |
| GlaB | 0x42616C47 | 0x390 | Type 11 (Enum) | Standard lookaside |

### Lookaside List Sizes (from HmgCreate)
| Type | Lookaside Size | Max Depth (tag) |
|---|---|---|
| 1 (DC) | 0x868 (2152) | 0x28 (40) |
| 4 (Region) | 0x70 (112) | 0x60 (96) |
| 5 (SURFACE) | 0x3B8 (952) | 0x28 (40) |
| 8 (Palette) | 0xC8 (200) | 0x0C (12) |
| 16 (Brush) | 0xB8 (184) | 0x60 (96) |
| 10 (Font) | 0x278 (632) | 0x40 (64) |
| 11 (Enum) | 0x390 (912) | 0x37 (55) |

### SURFACE Allocation Size Analysis
- **SURFACE::tSize**: 0x2B8 (696 bytes) — the SURFACE object itself
- **Type isolation slot**: 0x2C0 (704 bytes) — 8 bytes alignment padding
- **Standard lookaside**: 0x3B8 (952 bytes) — includes space for stack backtrace (160 bytes) when tracing enabled
- **With inline bitmap bits**: SURFACE::tSize + bitmap_bits_size (can be much larger)
- **The type isolation slot (0x2C0) is the effective size for pool reclaim**

### Reclaim Candidates (same size class as SURFACE)
- **No other GDI type has 0x2C0 slot size** in the type isolation system
- **Standard pool allocations of 0x2C0 bytes** with different tags could potentially reclaim the same pool page
- **However, type isolation's SLIST ensures only SURFACE objects go into SURFACE slots**
- **For standard pool (not type isolation)**: Any 0x2C0-byte allocation could reclaim the same pool page, but type isolation bypasses standard pool for SURFACE

### User-Controllable Allocations Same Size as SURFACE (0x2C0 = 704 bytes)
- **Window extra bytes (Usws tag)**: Variable size, user-controlled via cbWndExtra — could potentially match 0x2C0
- **However**: Window allocations use different pool tags and are NOT in the type isolation system
- **Direct pool free vs type isolation**: If a SURFACE is allocated via direct pool (PALLOCMEM2) instead of type isolation (when lookaside is exhausted or size exceeds lookaside), it goes to standard paged pool where cross-type reclaim IS possible
- **Key question**: When does SURFACE allocation bypass type isolation? When the SLIST is empty AND the allocation function fails — but the allocation function creates new chunks, so this should be rare

## Summary of NEW Exploitation Ideas

### 1. KASLR Bypass via NtGdiGetEntry (HIGH FEASIBILITY)
- **Method**: Call NtGdiGetEntry with any GDI handle index to read the full 24-byte handle table entry including the kernel object pointer at offset 16
- **Advantage**: Works even if PEB->GdiSharedHandleTable is not mapped or is read-only
- **Can enumerate all GDI handles** to find SURFACE objects and their kernel addresses
- **No special privileges required** — it's a documented syscall

### 2. KASLR Bypass via PEB->GdiSharedHandleTable (CONFIRMED)
- **Method**: Read PEB->GdiSharedHandleTable (array of 24-byte entries), read QWORD at entry+16 for kernel object pointer
- **Confirmed**: The shared section contains kernel object pointers at offset 16 of each 24-byte entry

### 3. Handle Table Corruption via Shared Section (REQUIRES TESTING)
- **Method**: If PEB->GdiSharedHandleTable is mapped PAGE_READWRITE in user mode, directly modify the object pointer at entry+16
- **If writable**: Could point a bitmap handle to controlled memory, create fake SURFACE with controlled pvScan0
- **Risk**: Modern Windows may map this read-only for user mode
- **Testing required**: Try writing to PEB->GdiSharedHandleTable entries from user mode

### 4. tagWND UAF → Write to SURFACE+0x50 (PRIMARY STRATEGY)
- **Method**: Use the xxxSendTransformableMessageTimeout UAF to get a kernel write primitive
- **Steps**:
  1. Create a bitmap (SURFACE) and use KASLR bypass to find its kernel address
  2. Trigger the tagWND UAF to free a child window
  3. Use the dangling window pointer to write a controlled value to SURFACE+0x50 (pvScan0)
  4. Call GetBitmapBits/SetBitmapBits on the bitmap for arbitrary kernel R/W
- **Challenge**: The tagWND UAF gives a write to the freed tagWND memory, not to an arbitrary address. Need to figure out how to redirect the write to a SURFACE.

### 5. SURFACE LIFO Reclaim for Type-Safe UAF (MEDIUM FEASIBILITY)
- **Method**: 
  1. Allocate SURFACE A (bitmap)
  2. Free SURFACE A (goes to type isolation SLIST, zeroed)
  3. Trigger the tagWND UAF
  4. Allocate SURFACE B (gets A's slot from SLIST, zeroed)
  5. The old handle for A now points to B's memory (if handle wasn't properly cleaned up)
- **Challenge**: The handle table entry is updated when SURFACE A is deleted (object pointer cleared). Need a race condition where the handle still points to the freed SURFACE.

### 6. Race Condition in Surface Deletion (RESEARCH NEEDED)
- **Method**: Find a race between HmgRemoveObject (clears handle table entry) and SURFACE::Free (zeros and returns to SLIST)
- **Window**: Between HmgRemoveObject returning the object pointer and SURFACE::Free being called, another thread could allocate a new SURFACE in the same slot
- **If race is won**: Could get a handle pointing to a newly-allocated SURFACE with different data
- **Analysis needed**: The deletion path in SURFACE::bDeleteSurface calls HmgRemoveObject first, then frees bits, then calls SURFACE::Free. The window between HmgRemoveObject and SURFACE::Free is the race opportunity.

### 7. HmgSwapLockedHandleContents Abuse (LOW FEASIBILITY)
- **Method**: If we can call bMigrateSurfaceForConversion with controlled parameters, swap a legitimate SURFACE's contents with a controlled object
- **Challenge**: bMigrateSurfaceForConversion is called from display driver context, not user mode
- **Research needed**: Find if any user-mode API triggers surface migration

### 8. Type Confusion via HmgModifyHandleType (RESEARCH NEEDED)
- **Method**: If HmgModifyHandleType can be called from user mode, change a DC handle's type to 5 (SURFACE) and access it as a bitmap
- **Challenge**: HmgModifyHandleType likely requires kernel-mode caller
- **Research needed**: Analyze callers of HmgModifyHandleType (0x1C00174D0) and HmgLockAndModifyHandleType (0x1C0017460)

### 9. Palette Object Confusion (RESEARCH NEEDED)
- **Method**: Palette objects (type 8) have a different structure but similar size (0xC8). If a palette handle can be used where a SURFACE is expected, the kernel would interpret palette data as SURFACE fields
- **Challenge**: Type validation in lock functions prevents this
- **Bypass needed**: Would need to corrupt the type field in the handle table entry

### 10. Direct Pool Reclaim for Non-Isolated SURFACE (MEDIUM FEASIBILITY)
- **Method**: Force SURFACE allocation to bypass type isolation and use direct pool allocation, then reclaim with a user-controlled allocation of the same size
- **When does bypass happen**: When the type isolation SLIST is empty AND the fallback allocation function fails — extremely rare
- **Alternative**: If the type isolation chunk allocation itself uses standard pool, and the chunk is freed, a user-controlled allocation could reclaim the chunk page
- **Challenge**: Type isolation chunks are 0x2C000 bytes — large allocations that are unlikely to be reclaimed by user-controlled data

### 11. Section-Based Surface for Cross-Process Access (RESEARCH NEEDED)
- **Method**: SURFACE objects with the 0x800 flag use shared sections mapped in both kernel and user mode
- **If the section view is writable in user mode**: Could directly modify SURFACE fields including pvScan0
- **Analysis needed**: Check if DIB sections (NtGdiCreateDIBSection) create section-based SURFACEs where the user-mode view includes the SURFACE object itself

### 12. NtGdiGetStats Information Leak (RESEARCH NEEDED)
- **Function**: NtGdiGetStats at 0x1C013F480
- **Potential**: May leak GDI handle statistics or object information
- **Analysis needed**: Decompile and analyze what information it returns

## Key Conclusions

1. **SURFACE pvScan0 is at offset 0x50 (decimal 80)** — confirmed by EngModifySurface and SURFMEM::bCreateDIB
2. **Type isolation prevents direct cross-type pool reclaim** — SURFACE objects are isolated in "Gila" pool with SLIST-based LIFO free list
3. **Freed SURFACE slots are ZEROED** — memset(0, 0x2C0) before returning to free list
4. **NtGdiGetEntry is a confirmed KASLR bypass** — copies full handle table entry (with kernel pointer) to user mode
5. **No user-mode path directly writes pvScan0** — all pvScan0 writes are in kernel-mode display driver context
6. **The primary exploitation path remains**: tagWND UAF → kernel write primitive → corrupt SURFACE+0x50 (pvScan0) → GetBitmapBits/SetBitmapBits for arbitrary R/W
7. **The handle table section (PEB->GdiSharedHandleTable) may be writable in user mode** — if so, direct handle table corruption is possible (needs testing)
8. **SURFACE::bDeleteSurface has a window between HmgRemoveObject and SURFACE::Free** — potential race condition for UAF
