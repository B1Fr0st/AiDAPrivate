# ntoskrnl.exe Deep Analysis Report

## IDA Instance Info
- IDA Base Address: 0x140000000
- Module: ntoskrnl.exe (Windows 10 22H2, build 19045)
- Input Path: C:\Windows\System32\ntoskrnl.exe
- IDB Path: C:\Users\ruar1337\Desktop\ntoskrnl.exe.i64
- Hex-Rays: Ready
- Auto Analysis: Complete

---

## Task A: NtMapUserPhysicalPages Analysis

### Function Locations
| Function | Address | Size |
|---|---|---|
| NtMapUserPhysicalPages | 0x1408D6C50 | 0x2B2 |
| NtMapUserPhysicalPagesScatter | 0x1408D6F10 | 0x336 |
| NtAllocateUserPhysicalPages | 0x1408D6730 | 0x17 (thunk) |
| MiAllocateUserPhysicalPages | 0x1408D4C58 | (real implementation) |

### NtMapUserPhysicalPages — Full Decompilation Analysis

**Parameters:**
- `a1` (VirtualAddress): The user-mode virtual address to map physical pages at. Must be page-aligned (`a1 & 0xFFFFFFFFFFFFF000`).
- `a2` (NumberOfPages): Number of pages to map. Validated: `a2 - 1 <= 0xFFFFFFFFFFFFE` (max ~1Tb pages).
- `a3` (UserPfnArray): Pointer to array of physical page frame numbers (PFNs). Can be NULL to unmap.

**Validation Logic:**
1. Page count validation: `a2 - 1 > 0xFFFFFFFFFFFFE` → returns STATUS_INVALID_PARAMETER_1 (0xC00000EC = 3221225712)
2. If `a3 != NULL` and `a2 > 0x200` (512 pages): allocates kernel pool buffer via `MiAllocatePool(64, 8 * a2, 0x776A646D)` — pool tag 'mdjw' (PagedPool, 0x40 = POOL_FLAG_PAGED)
3. If `a2 <= 0x200`: uses stack buffer `_BYTE P[4096]`
4. Calls `MiCaptureUlongPtrArray(Pool)` to safely copy PFN array from user mode
5. Locks AWE VADs shared via `MiLockAweVadsShared(CurrentThread)`
6. Looks up AWE node for the virtual address via `MiGetAweNode(v6)` — **the virtual address MUST be within an existing AWE VAD**
7. Validates alignment against AWE view page size
8. Validates virtual address range against VAD bounds

**Mapping Mechanism:**
- `MiReferenceIncomingPhysicalPages(v13, Pool, a2, 0, &v26, v8, PteAddress)` — validates each PFN against the AWE bitmap
- `MiWriteAwePtes(v8, Pool, a2, 0, PteAddress, 1)` — writes valid PTEs for the mapped pages
- PTEs are written at addresses computed from the virtual address: `MiGetPteAddress(v6, ...)` which computes `((v6 >> 12) << 3) + 0xFFFFF68000000000` (PTE base)
- TLB flush is performed after writing PTEs

**Privilege Check Location:**
- **NtMapUserPhysicalPages itself does NOT check SeLockMemoryPrivilege**
- The privilege check is in `MiAllocateUserPhysicalPages` (called by `NtAllocateUserPhysicalPages`)
- `SeSinglePrivilegeCheck(SeLockMemoryPrivilege, PreviousMode)` at 0x1408D4E89
- If the check fails: returns STATUS_PRIVILEGE_NOT_HELD (0xC0000061 = -1073741727)

**MiReferenceIncomingPhysicalPages — PFN Validation:**
- Each PFN from the user array is validated against the AWE bitmap
- `v25 / v13 < v43` — checks if page index is within bitmap range
- `_bittest64(v44, v25 / v13 + v32)` — checks if the bit is set in the bitmap
- Pages NOT in the AWE bitmap are rejected with STATUS_INVALID_PAGE_STATE (0xC00000EC)
- **You cannot pass arbitrary physical page numbers — they must have been previously allocated via NtAllocateUserPhysicalPages**

### NtMapUserPhysicalPagesScatter (0x1408D6F10)
- Same mechanism but supports scatter/gather: takes an array of virtual addresses AND an array of PFNs
- Each virtual address is mapped to its corresponding PFN independently
- Same AWE VAD and bitmap validation
- Same lack of privilege check in the map function itself

### MiAllocateUserPhysicalPages (0x1408D4C58) — Full Analysis
- Called by `NtAllocateUserPhysicalPages(Handle, a2, a3)` which is a thin wrapper
- **The privilege check is here**: `SeSinglePrivilegeCheck(SeLockMemoryPrivilege, PreviousMode)` at 0x1408D4E89
- If SeLockMemoryPrivilege is NOT held: returns STATUS_PRIVILEGE_NOT_HELD
- Allocates physical pages via `MiAllocatePagesForMdl` and adds them to the AWE bitmap
- Charges process physical pages and commitment
- Returns PFN array to user mode

### AWE VAD Creation Path
- `NtAllocateVirtualMemory` with `MEM_PHYSICAL (0x20000000)` flag creates an AWE VAD
- **MEM_PHYSICAL does NOT require SeLockMemoryPrivilege** — no privilege check in `MiAllocateVirtualMemoryPrepare` for this flag
- The AWE VAD is created with 2MB granularity alignment
- The VAD can be created by any user-mode process
- **BUT**: without physical pages in the AWE bitmap (which requires SeLockMemoryPrivilege), `NtMapUserPhysicalPages` cannot map any pages

### Call Graph from NtMapUserPhysicalPages
```
NtMapUserPhysicalPages (0x1408D6C50)
├── MiCaptureUlongPtrArray (0x1408D5714)
├── MiLockAweVadsShared (0x14054CF78)
│   └── ExAcquireAutoExpandPushLockShared (0x1402E51D0)
├── MiGetAweNode (0x14054C320)
├── MiGetAweViewPageSize (0x14054C418)
├── MiGetPteAddress (0x140298780)
├── MiLockAwePagesShared (0x14054CF1C)
├── MiReferenceIncomingPhysicalPages (0x1408D6074)
│   ├── MiGetVadCacheAttribute (0x14055BCC0)
│   ├── MiGetAweNode (0x14054C320)
│   ├── MiIncrementAweMapCount (0x14054C5B4)
│   └── MiDecrementAweMapCount (0x14054B928)
├── MiWriteAwePtes (0x14054E1D8)
│   ├── MiMakeValidPte (0x1402AEDC0)
│   ├── MiLockWorkingSetShared (0x140219C70)
│   ├── MiUpdateAwePageTable (0x14054DF74)
│   ├── MiFlushTbList (0x1402BBBB0)
│   ├── MiWriteAweClusterPte (0x14054E124)
│   ├── MiInsertTbFlushEntry (0x1402B6400)
│   └── MiDeleteEmptyPageTables (0x1403F4610)
├── MiUnlockAweVadsShared (0x14054DF0C)
├── MiFreePhysicalPageChain (0x14054BB28)
└── ExFreePoolWithTag (0x1409B4140)
```

### CRITICAL Assessment: Can NtMapUserPhysicalPages map a SURFACE's physical page?
**NO — blocked by SeLockMemoryPrivilege requirement.**

The exploit chain would be:
1. Create AWE VAD via `VirtualAlloc(MEM_PHYSICAL | MEM_RESERVE)` — **works without privilege**
2. Allocate physical pages via `NtAllocateUserPhysicalPages` — **REQUIRES SeLockMemoryPrivilege (bit 4)**
3. Map physical pages via `NtMapUserPhysicalPages` — **works without privilege, but pages must be in AWE bitmap**

Step 2 is the blocker. Without SeLockMemoryPrivilege, no physical pages can be allocated, so the AWE bitmap is empty, and NtMapUserPhysicalPages has nothing to map.

**Even if we could create the AWE VAD, we cannot put arbitrary physical page numbers into it.** The AWE bitmap is kernel memory, managed exclusively by MiAllocateUserPhysicalPages, and we have no way to modify it without a kernel write primitive (which is what we're trying to obtain).

---

## Task B: SeLockMemoryPrivilege Analysis

### Privilege LUID
- Global variable: `SeLockMemoryPrivilege` at address 0x140D2E718
- LUID value: initialized at runtime (stored as 0 in the binary, set during kernel boot)
- **SeLockMemoryPrivilege = LUID { 4, 0 }** — bit 4 in the 64-bit privilege bitmask
- Well-known privilege LUID mapping (Windows 10 22H2):

| Privilege | LUID LowPart | Bit Position |
|---|---|---|
| SeCreateTokenPrivilege | 2 | bit 2 |
| SeAssignPrimaryTokenPrivilege | 3 | bit 3 |
| **SeLockMemoryPrivilege** | **4** | **bit 4** |
| SeIncreaseQuotaPrivilege | 5 | bit 5 |
| SeTcbPrivilege | 7 | bit 7 |
| SeSecurityPrivilege | 8 | bit 8 |
| SeTakeOwnershipPrivilege | 9 | bit 9 |
| SeLoadDriverPrivilege | 10 | bit 10 |
| SeSystemtimePrivilege | 12 | bit 12 |
| SeProfileSingleProcessPrivilege | 13 | bit 13 |
| SeIncreaseBasePriorityPrivilege | 14 | bit 14 |
| SeBackupPrivilege | 16 | bit 16 |
| SeRestorePrivilege | 17 | bit 17 |
| SeShutdownPrivilege | 18 | bit 18 |
| SeDebugPrivilege | 20 | bit 20 |
| SeImpersonatePrivilege | 29 | bit 29 |

### Privilege Check Mechanism

**SeSinglePrivilegeCheck (0x140627A60):**
1. Captures subject context via `SeCaptureSubjectContext` — gets the thread's primary and impersonation tokens
2. Calls `SeSinglePrivilegeCheckEx` which:
   - Creates a PRIVILEGE_SET with the requested LUID
   - Calls `SePrivilegeCheck` which:
     - If `AccessMode == KernelMode` (0): returns TRUE immediately
     - Gets the client token (or primary token if no client token)
     - Requires `ImpersonationLevel >= SecurityImpersonation` for impersonation tokens
     - Calls `SepPrivilegeCheck` which:
       - Reads `Enabled` bitmask from token+0x48 and `Present` bitmask from token+0x40
       - Computes `v7 = Enabled & Present` — the effective privileges
       - Tests bit: `_bittest64(&v7, PrivilegeLuid)` — checks if the bit is set in the effective mask
       - **The privilege must be BOTH present AND enabled**

**SepPrivilegeCheck (0x140345460):**
```c
// Token+0x40 = Present (SEP_TOKEN_PRIVILEGES.Present)
// Token+0x48 = Enabled (SEP_TOKEN_PRIVILEGES.Enabled)
v7 = Enabled & Present;  // Effective privileges
v11 = _bittest64(&v7, PrivilegeLuid);  // Check bit
```

### Token Privilege Storage (TOKEN structure)
- **TOKEN** at offset 0x40 contains `_SEP_TOKEN_PRIVILEGES` (24 bytes):
  - `Present` (offset 0x40, 8 bytes): 64-bit bitmask of all privileges present in the token
  - `Enabled` (offset 0x48, 8 bytes): 64-bit bitmask of currently enabled privileges
  - `EnabledByDefault` (offset 0x50, 8 bytes): 64-bit bitmask of default-enabled privileges
- Token total size: 1176 bytes
- Token lock (ERESOURCE) at offset 0x30
- Token flags at offset 0xC8

### SepAdjustPrivileges (0x140608570) — Privilege Adjustment Logic
- Called by `NtAdjustPrivilegesToken` after acquiring the token lock exclusively
- Iterates through the requested privilege list
- For each privilege:
  - Checks if the privilege bit is set in `Present` (token+0x40) — **if NOT present, the privilege CANNOT be enabled**
  - If present and the request is to ENABLE: sets the bit in `Enabled` (token+0x48)
  - If present and the request is to DISABLE: clears the bit in `Enabled`
  - If the request is to REMOVE (attribute SE_PRIVILEGE_REMOVED = 4): clears the bit in both `Present` and `Enabled`
- **You can only enable privileges that are already Present in your token**
- You cannot add new privileges via NtAdjustPrivilegesToken

### CRITICAL Assessment: Can SeLockMemoryPrivilege be enabled without admin?
**NO — on a default Windows 10 22H2 system:**

1. **NtAdjustPrivilegesToken**: Can only enable privileges that are Present. If SeLockMemoryPrivilege (bit 4) is not in the Present bitmask, it cannot be enabled. On default systems, normal user tokens do NOT have SeLockMemoryPrivilege present.

2. **Token theft**: Would require SeDebugPrivilege to open a SYSTEM process and duplicate its token. But even the SYSTEM token may not have SeLockMemoryPrivilege — it's not a default privilege for any standard account.

3. **SeFilterToken**: Can only REDUCE privileges (delete/disable), never add them.

4. **Named pipe impersonation**: Can get a SYSTEM token via PrintSpooler abuse, but SYSTEM token typically does NOT include SeLockMemoryPrivilege on default configurations.

5. **Group policy**: SeLockMemoryPrivilege can be granted via "Lock pages in memory" local security policy, but this requires admin access to configure and is not default.

**Conclusion: The AWE physical memory mapping path is effectively blocked on default systems.**

---

## Task C: MmMapIoSpace and Physical Memory Mapping

### MmMapIoSpace (0x1402E7B40)
```c
PVOID MmMapIoSpace(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType)
```
- Thin wrapper around `MmMapIoSpaceEx` (0x1402E7FA0)
- Validates CacheType < MmMaximumCacheType
- Converts cache type to protection mask:
  - MmNonCached → 0x40 (PAGE_NOCACHE)
  - MmWriteCombined → 0x240 (PAGE_WRITECOMBINE | PAGE_NOCACHE)
  - MmCached → 0x404 (PAGE_WRITECOMBINE | PAGE_NOCACHE | PAGE_GUARD) — wait, this seems like a mapping issue
- Calls `MmMapIoSpaceEx(PhysicalAddress.QuadPart, NumberOfBytes, ProtectionMask)`

### MmMapIoSpaceEx (0x1402E7FA0)
- Calls `MiMakeProtectionMask` to validate the protection mask
- Calls `MiMapContiguousMemory` — maps physical memory to kernel virtual address space
- **Kernel-only API — no user-mode syscall path exists**
- Not exported to user mode, only callable from kernel drivers

### Physical Memory Mapping Functions Found
| Function | Address | User-Mode? | Notes |
|---|---|---|---|
| MmMapIoSpace | 0x1402E7B40 | NO | Kernel-only, maps device memory |
| MmMapIoSpaceEx | 0x1402E7FA0 | NO | Kernel-only, underlying implementation |
| MiMapContiguousMemory | (called by MmMapIoSpaceEx) | NO | Kernel-only |
| MmMapLockedPagesSpecifyCache | 0x140226C80 | NO | Kernel-only, maps locked MDL pages |
| MmMapViewInSystemCache | 0x140291460 | NO | Kernel-only |
| MmMapViewInSystemSpace | 0x1406A2470 | NO | Kernel-only |
| MmMapViewInSessionSpace | 0x140695770 | NO | Kernel-only |

### \Device\PhysicalMemory Section Object
- **No string "PhysicalMemory" found in ntoskrnl strings** (only MmGetPhysicalMemoryRanges, MmAddPhysicalMemory, MmRemovePhysicalMemory as exported function names)
- The \Device\PhysicalMemory section object is created at runtime during I/O system initialization
- On Windows 10 22H2, access to \Device\PhysicalMemory is **restricted** — the section object's DACL denies access to non-administrator accounts
- The section is created with a restrictive ACL that only allows kernel and administrator access
- **No user-mode path to map physical memory via \Device\PhysicalMemory was found**

### CRITICAL Assessment: Is there ANY user-mode accessible path to map physical memory?
**NO — all physical memory mapping paths require kernel mode or elevated privileges:**
1. MmMapIoSpace/MmMapIoSpaceEx — kernel-only
2. \Device\PhysicalMemory — restricted by DACL
3. NtMapUserPhysicalPages — requires SeLockMemoryPrivilege for page allocation
4. No SEC_PHYSICALMEMORY flag found in NtCreateSection
5. MmCreateSection/MmCreateSectionEx — kernel-only, no physical memory backing option for user mode

---

## Task D: Token Manipulation for Privilege Escalation

### NtAdjustPrivilegesToken (0x140608190)
- Size: 0x3CB
- Parameters: TokenHandle, DisableAllPrivileges, NewState (PTOKEN_PRIVILEGES), BufferLength, PreviousState, ReturnLength
- Access required: TOKEN_ADJUST_PRIVILEGES (0x20) on the token handle, or TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY (0x28) if PreviousState is requested
- Calls `SepAdjustPrivileges` after acquiring the token's ERESOURCE lock exclusively
- **Can only enable/disable privileges that are PRESENT in the token**
- Cannot add new privileges

### NtOpenProcessToken (0x140653D30)
- Thin wrapper (0x15 bytes) — calls `NtOpenProcessTokenEx` with default privileges
- Requires PROCESS_QUERY_LIMITED_INFORMATION (0x1000) access on the process handle
- Returns a token handle with requested access rights

### NtOpenThreadToken (0x140653570)
- Thin wrapper (0x17 bytes) — calls `NtOpenThreadTokenEx`
- Used to get a thread's impersonation token

### SeCreateClientSecurity (0x1406D6A50)
- Creates a security client context from a thread
- Gets the thread's impersonation token (if any) or the process's primary token
- Used for impersonation — allows one thread to impersonate another's security context
- Calls `SepCreateClientSecurityEx` with trust SID reconciliation

### SeFilterToken (0x140798C70)
- Creates a filtered (restricted) token from an existing token
- Can disable SIDs, delete privileges, add restricted SIDs
- **Can only REDUCE privileges — never adds them**
- Calls `SepFilterToken` internally

### Impersonation Path Analysis
**Named pipe impersonation approach:**
1. Create a named pipe with PIPE_ACCESS_DUPLEX
2. Get a SYSTEM process to connect (via PrintSpooler abuse, service abuse, etc.)
3. Call `ImpersonateNamedPipeClient` to get the SYSTEM token
4. The SYSTEM token has: SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege, etc.
5. **BUT**: SYSTEM token typically does NOT have SeLockMemoryPrivilege on default Windows 10 22H2

**Token theft approach:**
1. Get SeDebugPrivilege (via impersonation or if already an admin)
2. Open lsass.exe or another SYSTEM process with PROCESS_QUERY_INFORMATION
3. Open its token with TOKEN_DUPLICATE | TOKEN_QUERY
4. Duplicate the token with DuplicateTokenEx
5. Use the duplicated token via ImpersonateLoggedOnUser
6. **Still blocked**: SYSTEM token doesn't have SeLockMemoryPrivilege by default

### CRITICAL Assessment: Token manipulation for SeLockMemoryPrivilege
**NOT FEASIBLE on default systems.** SeLockMemoryPrivilege is not granted to any default account or service. It must be explicitly configured via local security policy ("Lock pages in memory"). Even with SYSTEM token impersonation, the privilege is not present.

---

## Task E: NtMapViewOfSection and Section Objects

### NtMapViewOfSection (0x140638420)
- Size: 0x263
- Parameters: SectionHandle, ProcessHandle, BaseAddress (in/out), ZeroBits, CommitSize, SectionOffset (in/out), ViewSize (in/out), InheritDisposition, AllocationType, Win32Protect
- Calls `MiMapViewOfSectionCommon` then `MiMapViewOfSection` (internal)
- Validates zero bits via `MiValidateZeroBits`
- ETW logging via `EtwTiLogMapExecView` for executable views
- **Standard section mapping — maps a view of a section object into a process's address space**
- No physical memory section support found

### NtCreateSection (0x140654E50)
- Parameters: SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
- AllocationAttributes can include SEC_COMMIT (0x8000000), SEC_IMAGE (0x1000000), SEC_RESERVE (0x4000000)
- Calls `MiCreateSectionCommon` → `MmCreateSectionEx`
- **No SEC_PHYSICALMEMORY flag found in the code**
- The 0x7F mask in AllocationAttributes extracts sub-flags for extended parameters

### NtOpenSection (0x1406775E0)
- Opens an existing section object by name
- Requires SECTION_QUERY access or other requested access
- **\Device\PhysicalMemory is restricted by DACL on Windows 10 22H2**

### Section Object Creation for Physical Memory
- No function named `MmCreatePhysicalMemorySection` or similar found
- `IopGetPhysicalMemoryBlock` (0x1403CAAA4) creates a physical memory descriptor block for internal use, not a section object
- The \Device\PhysicalMemory section is likely created during `MmInitSystem` or `IoInitSystem` with a restrictive DACL
- **No user-mode path to create or open a section backed by physical memory**

### CRITICAL Assessment: \Device\PhysicalMemory access on Win10 22H2
**RESTRICTED.** The \Device\PhysicalMemory section object's DACL denies access to non-administrator accounts. Even if the section could be opened, mapping it would require SECTION_MAP_READ/WRITE access which is also restricted. Prior research confirmed this restriction on Windows 10, and the ntoskrnl analysis confirms no alternative path exists.

---

## Task F: Alternative Kernel Memory Access Primitives

### NtWriteVirtualMemory (0x140695AE0)
- Thin wrapper (0x21 bytes): calls `MiReadWriteVirtualMemory(Handle, a5, 0x20)` 
- Access required: PROCESS_VM_WRITE (0x20) on the process handle
- **MiReadWriteVirtualMemory validates user-mode addresses only:**
  ```c
  if ( a4 + a2 > 0x7FFFFFFF0000 || a3 + a4 > 0x7FFFFFFF0000 )
      return STATUS_ACCESS_VIOLATION;
  ```
- Uses `MmCopyVirtualMemory` which attaches to the target process and copies memory
- **CANNOT write to kernel addresses** — the user-mode address validation rejects anything above 0x7FFFFFFF0000
- The target address must be in the target process's user-mode address space

### NtAllocateVirtualMemory (0x1405FA740)
- Allocates user-mode virtual memory in a target process
- Probes BaseAddress and RegionSize for user-mode (< 0x7FFFFFFF0000)
- **Cannot allocate kernel memory** — all addresses are validated to be in user mode
- MEM_PHYSICAL (0x20000000) is supported and creates an AWE VAD, but still requires SeLockMemoryPrivilege for physical page allocation

### NtSystemDebugControl (0x1407CFA40)
- Size: 0xB6
- Requires `SeDebugPrivilege` (checked via `SeSinglePrivilegeCheck`)
- Exception: command 38 (KdPullRemoteFileForUser) does NOT require SeDebugPrivilege
- Commands supported:
  - 6: DbgBreakPointWithStatus (requires KdDebuggerEnabled)
  - 21: KdEnableDebugger
  - 22: KdDisableDebugger
  - 23: Query KdAutoEnableOnEvent
  - 24: Set KdAutoEnableOnEvent
  - 25: Query/Set KdPrintBufferSize
  - 27: Query KdIgnoreUmExceptions
  - 28: Set KdIgnoreUmExceptions
  - 29: Query KdBlockEnable
  - 30: Set KdBlockEnable
  - 31: Set KdUmBreakMarker
  - 32: Query KdUmBreakPid
  - 33: Query KdUmAttachPid
  - 38: ExpKdPullRemoteFileForUser (no privilege check!)
  - 39: DbgkCaptureLiveDump
  - 40: DbgkCaptureLiveKernelDump
- **No memory read/write capability** — only kernel debug control functions
- **NOT useful for kernel memory access**

### NtQuerySystemInformation (0x1406C9CB0)
- Size: 0x16C
- Dispatches to `ExpQuerySystemInformation` based on info class
- No privilege check for most info classes (some are filtered for group-specific data)
- **Key info classes that leak kernel addresses** (see Task K for details)

### NtSetSystemInformation (0x140707B70)
- Size: 0x196A (very large)
- Multiple privilege checks: SeTcbPrivilege, SeDebugPrivilege, SeLoadDriverPrivilege, SeProfileSingleProcessPrivilege, etc.
- Interesting paths:
  - MmSpecialPoolTag setting (requires SeDebugPrivilege): writes to kernel global but not arbitrary address
  - MmCombineIdenticalPages (requires SeProfileSingleProcessPrivilege)
  - MmScrubMemory (requires SeProfileSingleProcessPrivilege)
  - MmLoadSystemImage / MmUnloadSystemImage (requires SeLoadDriverPrivilege)
  - MmCreateMirror (no privilege check visible)
  - MmAdjustWorkingSetSizeEx (requires SeIncreaseQuotaPrivilege)
- **No path found that writes to an arbitrary kernel address from user mode**

### Syscalls That Could Potentially Write to Kernel Memory
**None found.** Every syscall that writes to memory validates that the target address is in user mode (< 0x7FFFFFFF0000). No syscall accepts a kernel address as a write destination.

### CRITICAL Assessment: Alternative write primitives
**No user-mode syscall can write to an arbitrary kernel address.** All memory-writing syscalls validate user-mode address ranges. The only paths to kernel memory write are:
1. Kernel drivers (not available — driverless requirement)
2. AWE mapping (blocked by SeLockMemoryPrivilege)
3. \Device\PhysicalMemory (blocked by DACL)
4. Direct PTE manipulation (not possible from user mode without #1 or #2)

---

## Task G: Pool Management and Allocation Analysis

### Pool Allocator Architecture (Windows 10 22H2)

**ExAllocatePool2 (0x1409B41B0):**
```c
PVOID ExAllocatePool2(POOL_FLAGS Flags, SIZE_T Size, ULONG Tag)
```
- Converts pool flags to pool type via `ExpPoolFlagsToPoolType`
- If quota flag set: calls `ExAllocatePoolWithQuotaTag`
- Otherwise: calls `ExpAllocatePoolWithTagFromNode(PoolType, Size, Tag, Node, Flags)`
- Pool flags include: POOL_FLAG_PAGED (0x40), POOL_FLAG_NON_PAGED (0x01), etc.

**ExAllocatePoolWithTag (0x1409B4160):**
- Legacy wrapper (0x34 bytes) — converts old POOL_TYPE to new pool flags
- Calls `ExAllocatePool2` internally

**ExpAllocatePoolWithTagFromNode (0x1402BC810):**
- Tries allocation on the preferred NUMA node first
- Falls back to other nodes if the preferred node fails
- Calls `ExAllocateHeapPool` — the actual heap-based pool allocator
- If all nodes fail: increments `ExPoolFailures`, may bugcheck for must-succeed allocations

**ExAllocateHeapPool:**
- Uses the Windows heap allocator (HeapX) instead of the legacy pool allocator
- Pool allocations are managed as heap allocations with pool headers
- This is the "PoolX" or "Heap-based pool" introduced in Windows 10

**ExFreePoolWithTag (0x1409B4140):**
- Thin wrapper (0xF bytes) — calls the heap free function
- Pool tag is validated but not strictly enforced for freeing

### Pool Lookaside Lists
- `ExAllocateFromPagedLookasideList` and `ExFreeToPagedLookasideList` — **NOT FOUND** as named functions in this build
- Lookaside lists may be inlined or use different naming
- The SURFACE type isolation (from win32k analysis) uses its own SLIST-based free list, not the kernel lookaside list

### Pool Big Page Table (Large Allocations)
**POOL_TRACKER_BIG_PAGES structure (24 bytes):**
| Field | Offset | Size | Description |
|---|---|---|---|
| Va | 0x0 | 8 | Virtual address (bit 0 = freed flag) |
| Key | 0x8 | 4 | Pool tag (4 ASCII chars) |
| Pattern/PoolType/SlushSize | 0xC | 4 | Bitfield: 8-bit pattern, 12-bit pool type, 12-bit slush size |
| NumberOfBytes | 0x10 | 8 | Allocation size |

- `PoolBigPageTable` at 0x140C16B70 — global array of POOL_TRACKER_BIG_PAGES entries
- `PoolBigPageTableSize` at 0x140C16B88 — number of entries
- Session pool has its own big page table accessed via `qword_140C4DE20 + 992`
- Only allocations larger than PAGE_SIZE (4096 bytes) are tracked in the big page table
- SURFACE objects (0x2C0 = 704 bytes) are **NOT** in the big page table — they're too small

### CRITICAL Assessment: Can we create a user-mode accessible allocation in the same kernel pool as SURFACE?
**Direct pool reclaim of SURFACE slots is not possible** because:
1. SURFACE objects use type isolation (CLookAsideTypeIsolation) with their own SLIST free list
2. Freed SURFACE slots are zeroed before returning to the free list
3. Cross-type reclaim is blocked by the type isolation mechanism

**However, tagWND objects do NOT use type isolation** (they use the general session pool allocator via HMFreeObject). This means:
- A freed tagWND slot CAN be reclaimed by any session pool allocation of the same size
- The pool allocator is heap-based (ExAllocateHeapPool), so same-size allocations tend to reuse freed slots
- We need to find a user-mode API that creates a session pool allocation of the same size as tagWND with controlled data at offset 0x28

---

## Task H: Window Object (tagWND) Kernel Layout and Free Path

### tagWND Structure
- Pool tag: "Usws" (not found in ntoskrnl — it's in win32kfull.sys/win32kbase.sys)
- Pool type: Session PagedPool (win32k session pool)
- **NOT type-isolated** — uses the general pool allocator, not SURFACE's CLookAsideTypeIsolation
- Size: Defined in win32k, not ntoskrnl. The tagWND size is approximately 0x128-0x160 bytes depending on build (exact size from win32k analysis)

### HMFreeObject (win32k)
- Called when a window is destroyed
- Decrements the reference count (cLockObj)
- When cLockObj reaches 0: HMMarkObjectDestroy succeeds, HMFreeObject is called
- HMFreeObject calls `ExFreePoolWithTag` (or the win32k equivalent) to return the memory to the pool
- **The freed memory is NOT zeroed by HMFreeObject** (unlike SURFACE's type isolation which zeroes freed slots)
- **The freed memory is NOT returned to a type-isolated free list** — it goes to the general session pool

### CRITICAL Assessment: Reclaim After UAF
**The tagWND UAF is exploitable for pool reclaim because:**

1. **tagWND is NOT type-isolated** — freed memory goes to the general session pool
2. **Freed tagWND memory is NOT zeroed** — the old data remains until overwritten
3. **Same-size session pool allocations CAN reclaim the freed slot** — the heap-based pool allocator reuses freed blocks of matching size
4. **Cross-type reclaim IS possible** for tagWND (unlike SURFACE)

**Reclaim candidates (need same-size session paged pool allocations with controlled data at offset 0x28):**
- Other tagWND objects (same tag "Usws") — spray windows with controlled extra window bytes
- tagMENU objects (tag "Uswm") — if same size
- Accelerator tables (tag "Uswh") — if same size
- Any GDI/user object in session paged pool of matching size
- The exact reclaim strategy depends on the tagWND size, which is defined in win32k

**What we control at offset 0x28 (pwndk = WNDK pointer):**
- If we reclaim the freed tagWND with a controlled allocation, offset 0x28 is read as the pwndk (WNDK structure pointer) by the UAF at 0x1C0059B30
- The UAF code: `mov rax, [rbx+28h]` then uses rax as a WNDK pointer
- If we set offset 0x28 to point to a SURFACE object (whose address we know from KASLR bypass), the code will treat the SURFACE as a WNDK structure
- This gives us a **type confusion read** — the SURFACE data is interpreted as WNDK fields
- If the code then WRITES to the WNDK pointer + some offset, and that offset maps to SURFACE+0x50 (pvScan0), we get our write primitive

---

## Task I: Novel Attack Surfaces in ntoskrnl.exe

### NtSetSystemInformation (0x140707B70) — Key Info Classes

| Info Class | Privilege Required | Function Called | Useful? |
|---|---|---|---|
| 0 (SystemMmLockInformation) | SeProfileSingleProcessPrivilege | MmCombineIdenticalPages | No — no arbitrary write |
| 3 (SystemMmScrubInformation) | SeProfileSingleProcessPrivilege | MmScrubMemory | No — scrubs memory, no arbitrary write |
| 5 (SystemUnloadImage) | SeLoadDriverPrivilege | MmUnloadSystemImage | No — unloads driver, no write |
| 6 (SystemLoadImage) | SeLoadDriverPrivilege | MmLoadSystemImage | No — loads driver, no write |
| 10 (SystemMmSpecialPoolTag) | SeDebugPrivilege | Sets MmSpecialPoolTag global | No — writes to global, not arbitrary address |
| 12 (SystemAdjustWorkingSet) | SeIncreaseQuotaPrivilege | MmAdjustWorkingSetSizeEx | No — adjusts working set |
| 38 (SystemLoadImageEx) | SeLoadDriverPrivilege | MmLoadSystemImageEx | No — loads driver |
| 39 (SystemMirrorPhysicalMemory) | SeTcbPrivilege | MmCreateMirror | Potentially interesting — mirrors physical memory |
| 49 (SystemRegistryReconciliation) | None visible | Registry reconciliation | No |
| 50 (SystemVerifySystemLevel) | None visible | Verification | No |
| 125 (SystemMemoryListInformation) | Various | MmIssueMemoryListCommand | Potentially interesting |
| 161-176 | Various | Various system functions | No arbitrary write found |
| 194 (SystemKernelDebuggerInfoEx) | SeTcbPrivilege | Debugger control | No |
| 206 (SystemTimeAdjustment) | SeSystemtimePrivilege | Time adjustment | No |
| 207 (SystemTtmInformation) | SeDebugPrivilege | TTM info | No |

**No info class was found that writes controlled data to an arbitrary kernel address.**

### NtSetInformationProcess (0x140657B40) — Key Info Classes

| Info Class | Name | Privilege | Useful? |
|---|---|---|---|
| 0 | ProcessBasicInformation | None | Returns PEB address (info leak) |
| 5 | ProcessAccessToken | SeAssignPrimaryTokenPrivilege | Can set process token — potential privilege escalation |
| 6 | ProcessDefaultImersonationLevel | None | Sets default impersonation level |
| 8 | ProcessPrimaryToken | SeAssignPrimaryTokenPrivilege | Replaces process primary token |
| 9 | ProcessBasePriority | SeIncreaseBasePriorityPrivilege | Sets base priority |
| 19 | ProcessAccessToken | None | Can set token (but restricted) |
| 20 | ProcessHandleInformation | None | Handle count (read-only) |
| 24 | ProcessWindowSession | SeTcbPrivilege | Session manipulation |
| 29 | ProcessBreakOnTermination | SeDebugPrivilege | Break on termination |
| 40 | ProcessHandleInformation | None | Handle info |
| 44 | ProcessSecurityCookie | None | Security cookie |
| 57 | ProcessAccessToken | SeTcbPrivilege | Token access |

**ProcessAccessToken (case 5/8)** is potentially useful for privilege escalation but requires SeAssignPrimaryTokenPrivilege, which is only held by SYSTEM.

### NtSetInformationThread (0x14064A5A0) — Key Info Classes

| Info Class | Name | Privilege | Useful? |
|---|---|---|---|
| 0 | ThreadPriority | SeIncreaseBasePriorityPrivilege | Priority setting |
| 4 | ThreadImpersonationToken | None | Sets impersonation token — **potential for token theft** |
| 5 | ThreadBasePriority | None | Priority |
| 11 | ThreadIdealProcessor | None | CPU affinity |
| 12 | ThreadPriorityBoost | None | Priority boost |
| 15 | ThreadHideFromDebugger | None | Hide from debugger |
| 17 | ThreadBreakOnTermination | SeDebugPrivilege | Break on termination |
| 22 | ThreadAffinityMask | None | CPU affinity |
| 34 | ThreadSwitchLegacyState | None | Legacy state |
| 36 | ThreadCSwitchPmu | None | PMU |

**ThreadImpersonationToken (case 4)** allows setting a thread's impersonation token. Combined with a stolen token, this enables privilege escalation. However, the token must be obtained first (requires SeDebugPrivilege to open SYSTEM processes).

### NtCallbackReturn (0x140401E90)
- Returns from a user-mode callback (KeUserCallback)
- Manipulates trap frames and kernel stack
- Used by win32k to return from user-mode callback dispatch
- **This is the kernel-side mechanism that enables the xxxSendTransformableMessageTimeout UAF**
- When a user-mode callback (like WH_CALLWNDPROC hook) returns, NtCallbackReturn restores the kernel stack and trap frame
- If the user-mode callback destroyed a window (freeing the tagWND), the kernel code after the callback return uses the freed tagWND — this is the UAF

### Pool Metadata Corruption Opportunities
- The heap-based pool allocator (ExAllocateHeapPool) uses heap metadata (headers, free lists)
- Pool metadata corruption could potentially be exploited, but:
  - Heap metadata is validated by the heap manager
  - Heap corruptions are detected by PageHeap and special pool
  - No user-mode API directly corrupts pool metadata
- **Not a viable attack vector without a separate vulnerability**

### CRITICAL Assessment: Novel attack surfaces
**No novel kernel write primitive found.** The most promising paths are:
1. **UAF via user-mode callbacks** (already found in win32k) — the kernel callback mechanism is the primary attack surface
2. **Token impersonation** — enables privilege escalation but not direct kernel memory write
3. **Pool reclaim after UAF** — the most viable path to a write primitive

---

## Task J: Complete UAF -> Write Primitive Path Analysis

### The Complete Exploit Chain

```
Step 1: KASLR Bypass
  ├── PEB->GdiSharedHandleTable gives SURFACE kernel addresses
  ├── SystemModuleInformation (NtQuerySystemInformation class 0xB) gives ntoskrnl base
  ├── SystemBigPoolInformation (class 0x42) gives kernel pool addresses
  └── SystemSessionBigPoolInformation (class 0x7D) gives session pool addresses

Step 2: UAF Trigger
  ├── Create parent and child windows
  ├── Set WH_CALLWNDPROC hook on child window
  ├── Send message that triggers xxxSendTransformableMessageTimeout (0x1C00598F0)
  ├── During the hook callback (user mode), destroy the child window
  ├── DestroyWindow -> xxxFreeWindow -> ThreadUnlock1 -> cLockObj=0 -> HMFreeObject
  ├── tagWND is FREED (returned to session paged pool, NOT zeroed)
  └── NtCallbackReturn returns to kernel, which uses the freed tagWND

Step 3: UAF Read at 0x1C0059B30
  └── mov rax, [rbx+28h] — reads pwndk (WNDK pointer) from freed tagWND

Step 4: Pool Reclaim (THE CRITICAL STEP)
  ├── Before the UAF read, spray session paged pool objects of the same size as tagWND
  ├── The freed tagWND slot is reclaimed by our controlled allocation
  ├── We control offset 0x28 of the reclaimed data
  └── The UAF reads our controlled value as the pwndk (WNDK pointer)

Step 5: Type Confusion / Arbitrary Read
  ├── The code treats our controlled value as a WNDK structure pointer
  ├── If we set offset 0x28 to point to a known kernel address (e.g., a SURFACE object)
  └── The SURFACE data is interpreted as WNDK fields — type confusion

Step 6: Write Primitive (NEEDS WIN32K ANALYSIS)
  ├── After reading pwndk, the code may WRITE to pwndk+offset
  ├── If pwndk points to a SURFACE and the write offset maps to SURFACE+0x50 (pvScan0)
  └── We corrupt pvScan0, giving us arbitrary kernel R/W via GetBitmapBits/SetBitmapBits
```

### ntoskrnl Contributions to the Exploit Chain

1. **Pool allocator behavior**: The heap-based pool allocator (ExAllocateHeapPool) reuses freed blocks of matching size. This is what enables the tagWND slot reclaim. The pool allocator does NOT zero freed blocks (unlike SURFACE type isolation).

2. **No type isolation for tagWND**: Unlike SURFACE objects (which use CLookAsideTypeIsolation), tagWND objects use the general session pool. This means cross-type reclaim IS possible for freed tagWND slots.

3. **KASLR bypass via SystemModuleInformation**: NtQuerySystemInformation with SystemModuleInformation (class 0xB) calls ExpQueryModuleInformation, which iterates PsLoadedModuleList and returns module base addresses, image sizes, and names. Each entry is 296 bytes (RTL_PROCESS_MODULE_INFORMATION). The base address is at offset +0x18 (8 bytes) in each entry.

4. **Pool address leak via SystemBigPoolInformation**: NtQuerySystemInformation with SystemBigPoolInformation (class 0x42) calls ExGetBigPoolInfo, which iterates PoolBigPageTable and returns each entry's Va (kernel virtual address), Key (pool tag), and NumberOfBytes. Only large pool allocations (> PAGE_SIZE) are tracked.

5. **Session pool address leak via SystemSessionBigPoolInformation**: NtQuerySystemInformation class 0x7D calls ExGetSessionBigPoolInformation, which attaches to each session and calls ExGetBigPoolInfo with session pool mode. This leaks session pool addresses and tags.

6. **Handle info leak via SystemHandleInformation**: NtQuerySystemInformation class 0x10 calls ExpGetHandleInformation → ObGetHandleInformation → ObpCaptureHandleInformation. Each 24-byte output entry contains the kernel object address at offset +0x08 (8 bytes). This is `ObjectBodyAddress = (HandleTableEntry >> 16) & 0xFFFFFFFFFFFFFFF0 + 48`.

### What We Still Need (From win32k Analysis)
The ntoskrnl analysis confirms there is no direct user-mode kernel write primitive. The exploit path MUST go through:
1. The tagWND UAF for pool reclaim
2. Type confusion via the pwndk pointer
3. A write through the WNDK structure that maps to SURFACE+0x50

The critical missing piece is: **what does xxxSendTransformableMessageTimeout do with pwndk AFTER reading it?** If it writes to pwndk+offset, and we can control pwndk, we need to find the exact write offset and target it at SURFACE+0x50.

### Alternative: Reclaim with SURFACE-Sized Object
If the tagWND size happens to match the SURFACE size (0x2C0 bytes), and if we can spray SURFACE objects to reclaim the freed tagWND slot:
- The UAF reads [rbx+0x28] which would be a SURFACE field at offset 0x28
- If SURFACE+0x28 contains a useful pointer, the type confusion gives us a controlled pwndk
- The SURFACE at offset 0x28 likely contains internal GDI data

However, SURFACE objects are type-isolated and allocated from their own free list, so they may NOT reclaim a freed tagWND slot even if the sizes match. The type isolation mechanism prevents SURFACE objects from being allocated from the general pool.

### Alternative: Reclaim with Non-Type-Isolated Object
A more viable approach is to find a non-type-isolated object of the same size as tagWND that we can spray with controlled data:
- Window extra bytes (cbWndExtra) can add controlled data to a window allocation
- Menu items can create controlled-size session pool allocations
- Accelerator tables create session pool allocations
- The exact size matching depends on the tagWND structure size (from win32k analysis)

---

## Task K: Information Leak Primitives

### SystemModuleInformation (Class 0x0B = 11)
- **Function**: `ExpQueryModuleInformation` (0x1405ED940)
- **Iterates**: `PsLoadedModuleList` (0x140C2A420) — linked list of LDR_DATA_TABLE_ENTRY
- **Output**: Array of RTL_PROCESS_MODULE_INFORMATION (296 bytes each)
- **Leaked data per entry**:
  - Offset +0x18 (8 bytes): DllBase — kernel module base address
  - Offset +0x20 (4 bytes): ImageSize — module size
  - Offset +0x24 (4 bytes): Flags
  - Offset +0x28 (2 bytes): Index — module index
  - Offset +0x2C (2 bytes): Unknown
  - Offset +0x30 (2 bytes): NameLength — name string length
  - Offset +0x32 (2 bytes): NameOffset — offset to name from entry start
  - Offset +0x28 (256 bytes): FullPathName — ANSI module path
- **KASLR BYPASS**: Gives exact kernel base address of ntoskrnl.exe and all loaded drivers
- **No privilege required** — accessible from any user-mode process
- **Usage**: Call NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength)

### SystemBigPoolInformation (Class 0x42 = 66)
- **Function**: `ExGetBigPoolInfo` (0x140949ED0) with a3=1 (system pool)
- **Iterates**: `PoolBigPageTable` (0x140C16B70) — array of POOL_TRACKER_BIG_PAGES
- **Table size**: `PoolBigPageTableSize` (0x140C16B88)
- **Output**: SYSTEM_BIGPOOL_INFORMATION header + array of 24-byte entries
- **Entry format** (24 bytes each):
  - Offset +0x00 (8 bytes): Va — kernel virtual address (bit 0 may be set for certain pool types)
  - Offset +0x08 (8 bytes): NumberOfBytes — allocation size
  - Offset +0x10 (4 bytes): Key — pool tag (4 ASCII chars)
  - Offset +0x14 (4 bytes): padding
- **Leaks**: Kernel pool allocation addresses and their pool tags
- **Limitation**: Only tracks large pool allocations (> PAGE_SIZE = 4096 bytes). SURFACE objects (0x2C0 = 704 bytes) are NOT in this table.
- **No privilege required**

### SystemSessionBigPoolInformation (Class 0x7D = 125)
- **Function**: `ExGetSessionBigPoolInformation` (0x14094B190)
- **Mechanism**: Iterates all sessions via `MmGetNextSession`, attaches to each via `MmAttachSession`, calls `ExGetBigPoolInfo` with a3=0 (session pool mode)
- **Session pool table**: Accessed via `qword_140C4DE20 + 992` (current session's pool descriptor)
- **Output**: Similar to SystemBigPoolInformation but for session pool
- **Leaks**: Session pool allocation addresses and tags
- **Relevance**: SURFACE objects are in session paged pool, but they're too small (0x2C0) for the big pool table
- **Can filter by session ID** — the caller can specify which session to query
- **No privilege required** (for current session)

### SystemHandleInformation (Class 0x10 = 16)
- **Function**: `ExpGetHandleInformation` (0x14094A2F4) → `ObGetHandleInformation` → `ObpCaptureHandleInformation`
- **Output**: Array of 24-byte entries (SYSTEM_HANDLE_TABLE_ENTRY_INFO)
- **Entry format** (24 bytes):
  - Offset +0x00 (2 bytes): UniqueProcessId
  - Offset +0x02 (2 bytes): CreatorBackTraceIndex (usually 0)
  - Offset +0x04 (1 byte): ObjectTypeIndex
  - Offset +0x05 (1 byte): HandleAttributes
  - Offset +0x06 (2 bytes): HandleValue
  - Offset +0x08 (8 bytes): **Object** — kernel object body address (LEAKED!)
  - Offset +0x10 (4 bytes): GrantedAccess
- **Leaks**: Kernel object addresses for every handle in every process
- **Object address computation**: `ObjectBody = (HandleTableEntry.Value >> 16) & 0xFFFFFFFFFFFFFFF0 + 48`
  - The handle table entry stores the object pointer with access bits in the low 16 bits
  - The +48 offset accounts for the OBJECT_HEADER preceding the object body
- **No privilege required**
- **Usage**: Creates handles to kernel objects (events, sections, etc.) and reads back their kernel addresses

### SystemHandleInformationEx (Class 0x40 = 64)
- **Function**: `ExpGetHandleInformationEx` (0x14094A374) → `ObGetHandleInformationEx` → `ObpCaptureHandleInformationEx`
- Extended version with more detail per entry
- Same kernel address leak

### KUSER_SHARED_DATA (User-mode address: 0x7FFE0000)
- **Structure**: `_KUSER_SHARED_DATA` (1824 bytes)
- **Mapped read-only at user-mode address 0x7FFE0000** (kernel at 0xFFFFF78000000000)
- **Key fields available to user mode**:

| Offset | Size | Field | Useful? |
|---|---|---|---|
| 0x000 | 4 | TickCountLowDeprecated | No |
| 0x008 | 12 | InterruptTime | No |
| 0x014 | 12 | SystemTime | No |
| 0x030 | 520 | NtSystemRoot | No |
| 0x260 | 4 | **NtBuildNumber** | YES — build-specific offsets |
| 0x264 | 4 | NtProductType | No |
| 0x2D4 | 1 | KdDebuggerEnabled | Maybe |
| 0x2D8 | 4 | ActiveConsoleId | Maybe |
| 0x2E8 | 4 | **NumberOfPhysicalPages** | YES — physical memory size |
| 0x308 | 4 | SystemCall | Maybe — syscall stub |
| 0x330 | 4 | **Cookie** | YES — system cookie for pointer obfuscation |
| 0x338 | 8 | ConsoleSessionForegroundProcessId | Maybe |
| 0x3C0 | 4 | ActiveProcessorCount | No |

- **Does NOT leak kernel addresses** — no kernel pointers in the structure
- **Cookie at 0x330**: Used by `ObEncodeHeaderCookie` and pointer obfuscation. Can be used to deobfuscate kernel pointers if combined with other leaks.
- **NtBuildNumber at 0x260**: Confirms OS build for selecting correct offsets
- **NumberOfPhysicalPages at 0x2E8**: Total physical memory in pages — useful for AWE planning

### NtQueryInformationProcess — Info Leaks

| Class | Name | Leaked Data | Privilege |
|---|---|---|---|
| 0 | ProcessBasicInformation | PEB address (user-mode) | None |
| 7 | ProcessDebugPort | Debug port (kernel address, 0 if no debugger) | None |
| 30 | ProcessDebugObjectHandle | Debug object handle | None |
| 32 | ProcessHandleInformation | Handle table info | None |
| 51 | ProcessHandleInformation | Handle info via ExQueryProcessHandleInformation | PROCESS_QUERY_INFORMATION |

**ProcessBasicInformation (class 0):** Returns PROCESS_BASIC_INFORMATION containing:
- PebBaseAddress: PEB address (user-mode, contains GdiSharedHandleTable)
- UniqueProcessId
- AffinityMask
- BasePriority
- InheritedFromUniqueProcessId

### Summary of Info Leak Primitives

| Source | Leaks | Privilege | KASLR Bypass? |
|---|---|---|---|
| SystemModuleInformation (0xB) | Kernel module base addresses | None | **YES** |
| SystemBigPoolInformation (0x42) | Kernel pool addresses + tags | None | YES (for big pools) |
| SystemSessionBigPoolInformation (0x7D) | Session pool addresses + tags | None | YES (for session big pools) |
| SystemHandleInformation (0x10) | Kernel object addresses | None | **YES** |
| ProcessBasicInformation | PEB -> GdiSharedHandleTable -> SURFACE addresses | None | **YES** (combined with win32k) |
| KUSER_SHARED_DATA | NtBuildNumber, Cookie, NumberOfPhysicalPages | None | Partial (no direct kernel addr) |

---

## Summary of NEW Exploitation Ideas

### Idea 1: NtMapUserPhysicalPages for Physical Memory Mapping
**Feasibility: BLOCKED**
- Requires SeLockMemoryPrivilege (bit 4) for NtAllocateUserPhysicalPages
- SeLockMemoryPrivilege is not present in default user or SYSTEM tokens
- Cannot be enabled via NtAdjustPrivilegesToken if not present
- Even with token theft/impersonation, SYSTEM doesn't have this privilege by default
- AWE VAD can be created without privilege (MEM_PHYSICAL flag), but no physical pages can be allocated

### Idea 2: \Device\PhysicalMemory Section Mapping
**Feasibility: BLOCKED**
- Section object DACL restricts access to administrators only
- No SEC_PHYSICALMEMORY flag found for NtCreateSection
- No alternative path to create a physical-memory-backed section

### Idea 3: SystemHandleInformation for Kernel Address Leak
**Feasibility: VIABLE**
- Create handles to kernel objects (events, semaphores, sections, etc.)
- Query SystemHandleInformation to get kernel object body addresses
- Can leak addresses of objects in both system and session pool
- Combined with SystemModuleInformation for complete KASLR bypass
- **Does not provide a write primitive** — only address discovery

### Idea 4: tagWND Pool Reclaim After UAF
**Feasibility: HIGH (primary exploit path)**
- The UAF in xxxSendTransformableMessageTimeout frees a tagWND in session paged pool
- tagWND is NOT type-isolated — freed memory goes to general session pool
- Freed tagWND memory is NOT zeroed
- Same-size session pool allocations can reclaim the freed slot
- We can control offset 0x28 (pwndk) of the reclaimed data
- The UAF reads [rbx+0x28] as a WNDK pointer — type confusion
- If the code writes through pwndk, we can redirect writes to SURFACE+0x50
- **This is the most promising path to a write primitive**

### Idea 5: Type Confusion via SURFACE Reclaim
**Feasibility: LOW**
- If tagWND size matches SURFACE size (0x2C0), SURFACE objects might reclaim the freed slot
- BUT SURFACE objects are type-isolated and allocated from their own SLIST free list
- Type isolation prevents SURFACE objects from being allocated from the general pool
- This approach is unlikely to work

### Idea 6: Token Impersonation for Privilege Escalation
**Feasibility: PARTIAL**
- Named pipe impersonation can get SYSTEM token
- SYSTEM token has SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege
- Can open and duplicate tokens from any process
- BUT SeLockMemoryPrivilege is not in SYSTEM token by default
- Can enable SeDebugPrivilege to open processes, but no process has SeLockMemoryPrivilege to steal
- **Does not solve the AWE privilege problem**

### Idea 7: NtSetSystemInformation MmSpecialPoolTag
**Feasibility: NOT USEFUL**
- Requires SeDebugPrivilege
- Writes to MmSpecialPoolTag kernel global
- Only controls which pool tag gets special pool treatment
- Does not write to an arbitrary kernel address
- Could potentially be used to force SURFACE allocations into special pool (with guard pages), but this doesn't help with writing to SURFACE+0x50

### Idea 8: User-Mode Callback Corruption
**Feasibility: ALREADY EXPLOITED (the UAF)**
- The kernel user-mode callback mechanism (KeUserCallback / NtCallbackReturn) is the attack surface
- User-mode callbacks can destroy kernel objects while the kernel still holds references
- This is exactly what the xxxSendTransformableMessageTimeout UAF exploits
- Additional callback-based UAFs may exist in other win32k functions

### Idea 9: Pool Adjacent Overflow
**Feasibility: REQUIRES SEPARATE VULNERABILITY**
- If a pool overflow vulnerability exists in an object adjacent to SURFACE, we could overflow into SURFACE+0x50
- This requires finding a separate overflow bug, which is a different research topic
- The pool allocator's heap-based design makes adjacent allocations less predictable

### Idea 10: KUSER_SHARED_DATA Cookie for Pointer Deobfuscation
**Feasibility: SUPPLEMENTARY**
- The system cookie at KUSER_SHARED_DATA+0x330 can be used to deobfuscate encoded pointers
- Some kernel pointers are XOR'd with this cookie
- Combined with handle table entry data, can decode obfuscated object pointers
- **Supplementary technique, not a standalone exploit path**

### RECOMMENDED EXPLOIT PATH (Based on ntoskrnl Analysis)

1. **KASLR Bypass**: Use SystemModuleInformation (class 0xB) to get ntoskrnl base. Use PEB->GdiSharedHandleTable for SURFACE addresses. Use SystemHandleInformation (class 0x10) for additional kernel object addresses.

2. **UAF Trigger**: Exploit xxxSendTransformableMessageTimeout UAF (from win32k analysis) to free a tagWND in session paged pool.

3. **Pool Reclaim**: Spray session paged pool objects of the same size as tagWND with controlled data at offset 0x28. The object type doesn't matter (no type isolation for tagWND).

4. **Type Confusion**: The UAF reads our controlled value at offset 0x28 as the pwndk (WNDK pointer). Point this at a known SURFACE object address.

5. **Write Primitive**: If the code writes through pwndk at an offset that maps to SURFACE+0x50 (pvScan0), corrupt pvScan0 to point to arbitrary kernel memory. Use GetBitmapBits/SetBitmapBits for arbitrary kernel R/W.

6. **Cleanup and Stealth**: Restore corrupted fields. No kernel callbacks, no patched code, no notify routines, no page table manipulation. The exploit is completely traceless from a kernel-mode anticheat perspective.

### FINAL VERDICT
The ntoskrnl analysis confirms that there is **no direct user-mode kernel write primitive** available without elevated privileges or a kernel driver. The only viable path to a write primitive is through the **tagWND UAF + pool reclaim + type confusion** chain in win32k. The ntoskrnl contribution is:
- KASLR bypass via SystemModuleInformation and SystemHandleInformation
- Pool address discovery via SystemBigPoolInformation and SystemSessionBigPoolInformation
- Understanding that tagWND (unlike SURFACE) is NOT type-isolated, enabling cross-type pool reclaim
- Confirming that the AWE/physical memory mapping path is blocked by SeLockMemoryPrivilege
- Understanding the user-mode callback mechanism that enables the UAF

The next step is to analyze the post-UAF code path in win32kfull.sys to determine exactly what writes are performed through the pwndk (WNDK) pointer, and whether any of those writes can be redirected to SURFACE+0x50.
