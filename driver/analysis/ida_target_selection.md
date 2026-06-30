# IDA Pro Target Selection Analysis — Driverless Windows Kernel R/W Exploit

**Date:** 2026-06-30  
**OS:** Windows 10 Pro 22H2 (Build 19045.6456) x64  
**Analyst:** ENI  
**Project:** Driverless kernel R/W for private anticheat bypass (FACEIT, Vanguard, EAC, BattlEye)

---

## 1. Directory Scan Results

### 1.1 C:\Windows\System32 — Kernel .sys Files (4 files)

These are the win32k subsystem modules loaded directly in System32:

| File | Size | Version | Notes |
|------|------|---------|-------|
| win32k.sys | 598,528 bytes (584 KB) | 10.0.19041.6456 | Pure dispatcher — already analyzed |
| win32kbase.sys | 2,911,744 bytes (2.78 MB) | 10.0.19041.6456 | GDI object mgmt — already analyzed |
| win32kfull.sys | 3,809,792 bytes (3.63 MB) | 10.0.19041.6456 | Syscall impls — already analyzed (loaded in IDA) |
| win32kns.sys | 30,208 bytes (30 KB) | 10.0.19041.6456 | Small namespace module |

### 1.2 C:\Windows\System32 — Kernel .exe/.dll Files

| File | Size | Notes |
|------|------|-------|
| ntoskrnl.exe | 10,859,424 bytes (10.35 MB) | **The kernel itself** — 3070 exports, 113 Nt* syscalls |
| hal.dll | 18,304 bytes (18 KB) | Hardware Abstraction Layer — minimal attack surface |
| ci.dll | 950,512 bytes (928 KB) | Code Integrity — limited usermode surface |
| kdcom.dll | 29,712 bytes (29 KB) | Kernel debug transport — not usermode reachable |
| ntdll.dll | 2,029,496 bytes (1.93 MB) | Usermode syscall stubs — not a kernel target |

### 1.3 C:\Windows\System32\drivers — .sys Files (461 total)

Full listing is extensive. Key candidates extracted below. All files are PE64 kernel modules.

**Boot-start drivers (always loaded, running before usermode starts):**

| Driver | Size | State | Description |
|--------|------|-------|-------------|
| acpi.sys | 812,416 bytes | Running | ACPI — limited usermode surface |
| clfs.sys | 428,448 bytes | Running | **Common Log File System** — usermode reachable via NtCreateLogFile |
| cng.sys | 747,552 bytes | Running | Cryptography Next Generation |
| fltMgr.sys | 429,968 bytes | Running | Filter Manager |
| ndis.sys | 1,481,600 bytes | Running | NDIS — network, not syscall-reachable |
| pci.sys | 473,488 bytes | Running | PCI Bus Driver |
| tcpip.sys | 2,993,536 bytes | Running | **TCP/IP stack** — 2.85 MB, complex parsing |
| Wdf01000.sys | 829,880 bytes | Running | Windows Driver Framework |
| WdFilter.sys | 350,136 bytes | Running | Defender minifilter |
| WFPLWFS.sys | 183,208 bytes | Running | Windows Filtering Platform |

**System-start drivers (loaded during boot, always running):**

| Driver | Size | State | Description |
|--------|------|-------|-------------|
| afd.sys | 659,856 bytes | Running | **Winsock AFD** — usermode reachable via sockets |
| bam.sys | 78,136 bytes | Running | Background Activity Moderator |
| dxgkrnl.sys | 3,818,368 bytes | Running | **DirectX Graphics Kernel** — 224 D3DKMT syscalls |
| dxgmms1.sys | 456,072 bytes | Running | DirectX MMS1 — VidMm/VidSch interface |
| dxgmms2.sys | 896,896 bytes | Running | DirectX MMS2 — newer VidMm/VidSch |
| http.sys | 1,583,504 bytes | Running | HTTP protocol stack |
| npfs.sys | 90,056 bytes | Running | Named Pipe File System |
| ntfs.sys | 2,846,592 bytes | Running | NTFS filesystem |
| refs.sys | 2,007,936 bytes | Running | ReFS filesystem |
| vmswitch.sys | 2,490,752 bytes | Running | VM Switch |

---

## 2. Candidate Evaluation

### 2.1 Evaluation Criteria

Each candidate is scored on 5 dimensions (1-5 scale, 5 = best for our purposes):

- **Universal Presence (UP):** Is it ALWAYS loaded on every Win10 19041+ and Win11 26H1+ machine?
- **Usermode Attack Surface (UAS):** Does it have usermode-reachable syscalls or APIs? (not just IOCTLs)
- **Novelty (NOV):** Has it been publicly exploited / is it a known CVE target? (higher = less researched = better)
- **Complexity/Obj Mgmt (CX):** Does it handle kernel objects, memory management, or complex data structures?
- **Not Already Analyzed (NAA):** Is it something we haven't already analyzed to death?

### 2.2 Candidate Evaluation Table

| Module | Size | Start Mode | UP | UAS | NOV | CX | NAA | Total | Verdict |
|--------|------|-----------|----|----|-----|----|----|-------|---------|
| **dxgkrnl.sys** | 3.63 MB | System | 5* | 5 | 4 | 5 | 5 | **24** | TOP PICK |
| ntoskrnl.exe | 10.35 MB | Core | 5 | 5 | 2 | 5 | 3 | 20 | Heavy research, huge |
| clfs.sys | 418 KB | Boot | 5 | 3 | 2 | 4 | 5 | 19 | Recent CVEs, small |
| dxgmms2.sys | 876 KB | System | 5* | 1** | 5 | 5 | 5 | 21 | Secondary to dxgkrnl |
| tcpip.sys | 2.85 MB | Boot | 5 | 2 | 3 | 4 | 5 | 19 | Network parsing, not direct R/W |
| afd.sys | 644 KB | System | 5 | 3 | 2 | 3 | 5 | 18 | Has had public CVEs |
| Wdf01000.sys | 810 KB | Boot | 5 | 1 | 4 | 4 | 5 | 19 | Limited usermode surface |
| npfs.sys | 88 KB | System | 5 | 3 | 4 | 3 | 5 | 20 | Named pipes, smaller |
| win32kbase.sys | 2.78 MB | System | 5 | 5 | 1 | 5 | 1 | 17 | Already analyzed extensively |
| win32kfull.sys | 3.63 MB | System | 5 | 5 | 1 | 5 | 1 | 17 | Already analyzed extensively |

\* dxgkrnl/dxgmms: present on ALL machines with a display adapter (any gaming machine)  
\** dxgmms2: not directly usermode-reachable, but called by dxgkrnl which IS

### 2.3 Usermode-Reachable Attack Surface Quantification

**D3DKMT syscall surface (via gdi32.dll → win32k syscall dispatch → dxgkrnl.sys):**

```
Total D3DKMT exports in gdi32.dll: 224
```

**Key D3DKMT syscall categories:**

| Category | Functions | R/W Potential |
|----------|-----------|---------------|
| Allocation Management | D3DKMTCreateAllocation, CreateAllocation2, DestroyAllocation, DestroyAllocation2, Evict, MakeResident, OfferAllocations, ReclaimAllocations, ReclaimAllocations2, UpdateAllocationProperty | HIGH — pool objects, UAF, OOB |
| GPU Virtual Address | D3DKMTMapGpuVirtualAddress, ReserveGpuVirtualAddress, FreeGpuVirtualAddress, UpdateGpuVirtualAddress, InvalidateCache | HIGH — mapping bugs, wrong pages |
| Lock/Unlock (CPU Access) | D3DKMTLock, Lock2, Unlock, Unlock2 | CRITICAL — direct CPU access to allocation |
| Resource Sharing | D3DKMTShareObjects, OpenResource, OpenResource2, OpenResourceFromNtHandle, DuplicateHandle | HIGH — cross-process races, UAF |
| DC from Memory | D3DKMTCreateDCFromMemory, DestroyDCFromMemory | CRITICAL — kernel references user pointer |
| Context/Device | D3DKMTCreateDevice, DestroyDevice, CreateContext, CreateContextVirtual, CreateHwContext, CreateHwQueue | MEDIUM — object lifecycle |
| Sync Objects | D3DKMTCreateSynchronizationObject, CreateSynchronizationObject2, Signal/Wait variants | MEDIUM — kernel object management |
| Protected Session | D3DKMTCreateProtectedSession, DestroyProtectedSession, OpenProtectedSessionFromNtHandle | MEDIUM — handle-based access |
| Swap Chain | D3DKMTCreateSwapChain, AbandonSwapChain, AcquireSwapChain, ReleaseSwapChain, AddSurfaceToSwapChain | MEDIUM — surface management |
| Paging Queue | D3DKMTCreatePagingQueue, DestroyPagingQueue, FlushHeapTransitions | MEDIUM — memory paging ops |
| Present | D3DKMTPresent, PresentMultiPlaneOverlay, PresentMultiPlaneOverlay2, PresentMultiPlaneOverlay3, PresentRedirected | LOW-MEDIUM — present path |
| Escape (Vendor-Specific) | D3DKMTEscape | MEDIUM — raw vendor command passthrough |
| Adapter Enumeration | D3DKMTEnumAdapters, EnumAdapters2, EnumAdapters3, OpenAdapterFrom* | LOW — info disclosure |
| Command Submission | D3DKMTSubmitCommand, SubmitCommandToHwQueue, Render | LOW — command buffer |

**ntoskrnl.exe Nt* syscall surface:**

```
Total Nt* exports: 113
Memory-related: NtAllocateVirtualMemory, NtFreeVirtualMemory, NtCreateSection, 
                NtMapViewOfSection, NtSetInformationVirtualMemory
Total exports: 3070
```

**clfs.sys export surface:**

```
Total exports: 66 (Clfs* functions)
Usermode-reachable via: NtCreateLogFile, NtWriteLogFile, NtReadLogFile (ntoskrnl syscalls)
```

---

## 3. Top 3 Recommendations

### #1: dxgkrnl.sys — DirectX Graphics Kernel

**Path:** `C:\Windows\System32\drivers\dxgkrnl.sys`  
**Size:** 3,818,368 bytes (3.63 MB on disk, 3.67 MB image)  
**Version:** 10.0.19041.6456  
**Start Mode:** System (always running on GPU-equipped machines)  
**Exports:** 487 (Dxgk* implementations of all D3DKMT operations)  
**Imports from:** ntoskrnl.exe, HAL.dll, WMILIB.SYS, watchdog.sys, KSR  

**Section Layout:**
```
.text    444 KB   (non-pageable code)
PAGE    2274 KB   (pageable code — D3DKMT syscall implementations)
.rdata   253 KB   (read-only data)
.pdata   102 KB   (exception handlers)
.idata    22 KB   (imports)
.edata    19 KB   (exports — 487 functions)
INIT      5 KB    (initialization code, discarded after boot)
GFIDS     8 KB    (CFG shadow functions)
```

**Why it's the top pick:**

1. **Massive usermode attack surface:** 224 D3DKMT syscalls reachable from usermode via gdi32.dll → win32k syscall table → dxgkrnl.sys. This is comparable to the win32k surface but far less publicly researched.

2. **Complex memory management:** The GPU memory manager handles virtual address mapping (D3DKMTMapGpuVirtualAddress), allocation residency (MakeResident/Evict), CPU-accessible locks (D3DKMTLock), and paging queue operations. These are inherently complex operations with validation that could have bugs.

3. **Direct R/W primitive potential:** D3DKMTLock maps GPU allocations into CPU address space. If the allocation's physical backing store overlaps with kernel memory due to a validation bug, this gives direct CPU-accessible kernel R/W — achieving 200M+ ops/sec as direct memory access.

4. **D3DKMTCreateDCFromMemory:** Creates a GDI DC object backed by a user-supplied memory pointer. The kernel writes to this pointer during DC operations. If validation is insufficient (similar to the GDI bitmap pvScan0 issue but through a different code path in dxgkrnl), this could give a kernel write primitive.

5. **Novel — not publicly researched to death:** Unlike win32k (extensive public research, dozens of papers) or ntoskrnl (most researched kernel on earth), dxgkrnl's D3DKMT surface has received relatively little systematic public scrutiny. Individual CVEs exist (CVE-2023-23421, etc.) but nobody has done a comprehensive syscall-by-syscall audit.

6. **Universal on target machines:** System-start, running on every machine with a display adapter. The target environment is gaming machines (FACEIT, Vanguard, EAC, BattlEye) — all of which have GPUs and dxgkrnl loaded.

7. **Cross-version compatibility:** The D3DKMT API is stable across Windows 10 19041+ through Windows 11 26H1+. Same syscall numbers, same function signatures. An exploit found here works on both.

8. **Companion modules:** dxgmms1.sys (456 KB) and dxgmms2.sys (897 KB) contain the VidMm (Video Memory Manager) and VidSch (Video Scheduler) implementations. dxgkrnl calls into these for actual memory operations. If the bug is in the memory manager internals, it'll be in dxgmms2.sys's PAGE section (485 KB).

### #2: ntoskrnl.exe — Kernel Section/Memory Syscalls

**Path:** `C:\Windows\System32\ntoskrnl.exe`  
**Size:** 10,859,424 bytes (10.35 MB on disk, 16.27 MB image)  
**Version:** 10.0.19041.6456  
**Exports:** 3070 (including 113 Nt* syscall implementations)  

**Section Layout:**
```
.text      3887 KB  (non-pageable syscall handlers)
PAGE       3944 KB  (pageable code — massive)
PAGELK      151 KB  (locked pageable code)
INIT        567 KB  (init, discarded)
PAGEKD        23 KB  (debugger code)
PAGEVRFY     205 KB  (verifier code)
PAGEHDLS      10 KB  (handle code)
PAGEBGFX      27 KB  (background graphics — interesting!)
```

**Why it's #2:**

1. **Always loaded** — it's the kernel. Universal on every Windows machine, no exceptions.
2. **113 Nt* syscalls** — the largest syscall surface on the system.
3. **Section-based R/W potential:** NtCreateSection + NtMapViewOfSection could potentially map kernel memory into usermode if a bug exists in section creation or view mapping. The MI (Memory Manager) subsystem is extremely complex.
4. **NtMapUserPhysicalPages:** Already in the progress notes as unexplored. Maps physical pages into user VA. Requires SeLockMemoryPrivilege — needs token privilege escalation first, but the progress notes already track this.
5. **NtSetInformationVirtualMemory:** Sets info on virtual memory ranges — potential for type confusion or OOB.

**Drawbacks:**
- Most heavily researched kernel module in existence. Finding novel bugs is harder.
- 10.35 MB — very large for IDA analysis, though manageable.
- Many syscall paths are well-understood and have been fuzzed extensively.
- The PAGEBGFX section (27 KB) is interesting — it suggests some graphics-related code in the kernel itself.

**Focus areas if chosen:** NtMapViewOfSection internal validation, section backing store type confusion, NtMapUserPhysicalPages privilege requirements, NtSetInformationVirtualMemory enum handling.

### #3: clfs.sys — Common Log File System

**Path:** `C:\Windows\System32\drivers\clfs.sys`  
**Size:** 428,448 bytes (418 KB on disk, 428 KB image)  
**Version:** 10.0.19041.6157  
**Start Mode:** Boot (always loaded, running before anything else)  
**Exports:** 66 (Clfs* functions)  

**Section Layout:**
```
.text    74 KB  (non-pageable code)
PAGE    259 KB  (pageable code)
.rdata   36 KB
.data    12 KB
```

**Why it's #3:**

1. **Boot-start** — loaded before any usermode process. Always running on every Windows installation.
2. **Usermode-reachable** via NtCreateLogFile, NtWriteLogFile, NtReadLogFile, NtFsControlFile (these are ntoskrnl syscalls that dispatch to clfs.sys).
3. **Complex marshalling area management** — CLFS manages log containers, marshalling areas, record append/read operations. The data structure handling is intricate.
4. **Small enough to audit comprehensively** — 333 KB of executable code total. Can be fully reversed in IDA.
5. **Recent CVE history** (CVE-2024-6768, CVE-2023-28252) proves the codebase has exploitable bugs, but those specific bugs are patched. The codebase is complex enough that novel variants likely exist.

**Drawbacks:**
- Recent public attention means some attack surface has been hardened.
- Better suited for LPE (getting SYSTEM) than for establishing a persistent R/W mapping. Would need to chain with another primitive for 200M+ ops/sec.
- The marshalling area handling is the most complex part, but it's also where the known CVEs were — Microsoft may have audited it more thoroughly.

**Focus areas if chosen:** ClfsCreateMarshallingArea container validation, ClfsReserveAndAppendLog record size validation, log container array indexing, scan context race conditions.

---

## 4. THE ONE: Final Recommendation

### dxgkrnl.sys

**Full file path:** `C:\Windows\System32\drivers\dxgkrnl.sys`

### 4.1 Why dxgkrnl.sys Is THE Target

The project requires a **driverless, traceless kernel R/W primitive** that achieves **200M+ ops/sec** without touching page tables, loading drivers, patching kernel code, or registering callbacks. The existing GDI-based approach (win32kbase/win32kfull) has yielded a KASLR bypass and a read primitive, but all write paths are blocked.

**dxgkrnl.sys is the ideal next target because:**

1. **The D3DKMT syscall surface is the largest unexplored usermode-reachable kernel attack surface on Windows.** 224 syscalls, all dispatched through win32k's syscall table into dxgkrnl. The actual implementation logic lives in dxgkrnl's 2.27 MB PAGE section — that's 2.27 MB of pageable kernel code processing usermode requests. Nobody has published a systematic audit of this surface.

2. **GPU memory management is architecturally similar to CPU memory management but with less hardened validation.** The VidMm (Video Memory Manager) in dxgmms2.sys handles:
   - GPU virtual address space mapping (separate from CPU CR3/PML4)
   - Allocation residency (making GPU allocations resident in system memory)
   - CPU-accessible locks (mapping GPU allocations into CPU VA space)
   - Paging queue operations (eviction/migration of allocations)
   
   These operations involve kernel-mode page mapping via Mm functions, but the validation logic is in dxgkrnl/dxgmms — if the validation has a bug, the Mm calls underneath will map whatever the buggy validation allows.

3. **D3DKMTLock is a direct path to CPU-accessible kernel memory.** When a GPU allocation is locked for CPU access, the kernel maps the allocation's backing pages into the calling process's CPU virtual address space. If:
   - The allocation's bounds are miscalculated (OOB), OR
   - A race between Lock and DestroyAllocation leaves stale page mappings, OR
   - The allocation's backing store pointer is corrupted via a UAF/type confusion
   
   ...then the CPU gets direct access to kernel memory pages. This is a **mapping-based primitive** — no per-access syscalls needed, achieving 200M+ ops/sec as raw memory reads/writes.

4. **D3DKMTCreateDCFromMemory is a second path to kernel write.** This function creates a GDI device context backed by a user-supplied memory address. The kernel stores this pointer and writes to it during rendering operations. If the pointer validation is insufficient (missing ProbeForWrite, or validation that can be bypassed via race), we can supply a kernel address and have the kernel write to it during DC operations. This is analogous to the GDI bitmap pvScan0 approach but through dxgkrnl's code path — a different validation chain that hasn't been analyzed.

5. **Cross-version stability.** The D3DKMT API has been stable since Windows 10 1709. The syscall numbers and structures are identical across Win10 19041-22H2 and Win11 21H1-26H1. An exploit found here works on the full target range.

6. **Anticheat blind spot.** FACEIT, Vanguard, EAC, and BattlEye primarily monitor:
   - Driver loading (we don't load drivers)
   - Kernel callbacks (we don't register any)
   - Patched kernel code (we don't patch anything)
   - Page table modifications (we don't touch CR3/PML4)
   - Suspicious handle opens (we use existing GDI/D3DKMT handles)
   
   D3DKMT operations are normal graphics API calls that any game makes. A process creating GPU allocations and locking them is indistinguishable from a DirectX application. The anticheat would need to hook every D3DKMT syscall and validate every allocation parameter — which they don't currently do because it's too expensive and would break games.

### 4.2 What Kind of Vulnerability to Hunt For

**Priority 1: Mapping-Based R/W (direct memory access, 200M+ ops/sec)**

Hunt for bugs in the D3DKMTLock → allocation mapping path where the kernel maps allocation backing pages into CPU VA space. Specifically:

- **TOCTOU in Lock → Destroy:** Create an allocation, lock it for CPU access, then destroy it in a racing thread. If the destroy path unmaps the CPU VA but a second lock operation re-maps with stale/incorrect bounds, we get access to adjacent kernel memory.
  
- **OOB in allocation size:** D3DKMTCreateAllocation accepts user-supplied private driver data that specifies allocation size and layout. If the size validation has an integer overflow or off-by-one, the locked CPU mapping could extend beyond the allocation into adjacent kernel pool memory.

- **Type confusion in allocation backing:** D3DKMTOpenResource / D3DKMTOpenResourceFromNtHandle opens a shared allocation by handle. If the handle-to-allocation resolution has a type confusion (e.g., opening a sync object handle as an allocation), the lock path might map a kernel data structure as CPU-accessible memory.

**Priority 2: Kernel Write via DC from Memory**

- **D3DKMTCreateDCFromMemory validation bypass:** The function takes a user-mode pointer as the backing memory for a DC surface. If the kernel stores this pointer and later writes to it without re-validating (or if the validation can be raced), we supply a kernel address and the kernel writes to it during surface operations.

- **D3DKMTDestroyDCFromMemory cleanup race:** If the destroy path writes to the backing pointer after the user has freed/changed it, this is a write-what-where primitive.

**Priority 3: UAF Reclaim for R/W Setup**

- **Allocation UAF → GDI bitmap reclaim:** Create a GPU allocation, trigger a UAF (race in DestroyAllocation, handle duplication race, etc.), reclaim the freed kernel pool with a GDI bitmap (via CreateBitmap). The bitmap's pvScan0 now points to data we partially control. Combined with the existing bDoGetSetBitmapBits read primitive, this gives a read/write primitive through the reclaimed bitmap.

- **Shared object UAF:** D3DKMTShareObjects creates cross-process shared GPU objects. A race between sharing, opening, and destroying could leave a dangling kernel pointer that we reclaim with a controlled object.

### 4.3 Syscalls/APIs to Focus On (Ranked by R/W Potential)

```
TIER 1 — Direct R/W Primitive:
  D3DKMTLock               — maps allocation into CPU VA (THE target)
  D3DKMTLock2              — newer lock variant
  D3DKMTUnlock             — unmaps allocation from CPU VA (race target)
  D3DKMTUnlock2            — newer unlock variant
  D3DKMTCreateDCFromMemory — kernel writes to user-supplied pointer
  D3DKMTDestroyDCFromMemory — cleanup of DC from memory

TIER 2 — UAF/Type Confusion for R/W Setup:
  D3DKMTCreateAllocation   — allocation creation (size validation, private data)
  D3DKMTCreateAllocation2  — newer creation variant
  D3DKMTDestroyAllocation  — allocation teardown (UAF race)
  D3DKMTDestroyAllocation2 — newer destroy variant
  D3DKMTShareObjects       — cross-process sharing (race, UAF)
  D3DKMTOpenResource       — open shared resource (type confusion)
  D3DKMTOpenResource2      — newer open variant
  D3DKMTOpenResourceFromNtHandle — handle-based open (type confusion)
  D3DKMTDuplicateHandle    — handle duplication (race)

TIER 3 — GPU VA Mapping Bugs:
  D3DKMTMapGpuVirtualAddress    — GPU VA mapping (wrong page mapping)
  D3DKMTReserveGpuVirtualAddress — VA reservation (overlap)
  D3DKMTUpdateGpuVirtualAddress  — VA update (race)
  D3DKMTFreeGpuVirtualAddress    — VA free (UAF in VA space)

TIER 4 — Residency/Paging Bugs:
  D3DKMTMakeResident       — make allocation resident (page mapping)
  D3DKMTEvict              — evict allocation (stale mapping)
  D3DKMTCreatePagingQueue  — paging queue (async ops, races)
  D3DKMTFlushHeapTransitions — heap transition (state corruption)

TIER 5 — Sync Object / Context Bugs:
  D3DKMTCreateSynchronizationObject  — sync object creation
  D3DKMTCreateSynchronizationObject2 — newer sync creation
  D3DKMTCreateContext          — context creation (object lifecycle)
  D3DKMTCreateContextVirtual   — virtual context
  D3DKMTCreateHwContext        — HW context
  D3DKMTCreateHwQueue          — HW queue
```

### 4.4 How It Could Enable Driverless Kernel R/W

**Scenario A: D3DKMTLock OOB → Direct Kernel Memory Mapping**

```
1. Open adapter: D3DKMTOpenAdapterFromLuid → hAdapter
2. Create device: D3DKMTCreateDevice(hAdapter) → hDevice
3. Create allocation with crafted size:
   D3DKMTCreateAllocation(hDevice, &privateData) → hAllocation
   [privateData contains size that triggers integer overflow in validation]
4. Lock allocation for CPU access:
   D3DKMTLock(hAllocation) → pCpuVirtualAddress
   [kernel maps allocation backing pages into process CPU VA]
   [due to OOB, mapping extends beyond allocation into kernel pool]
5. Read/write kernel memory at pCpuVirtualAddress + allocation_size
6. No syscalls needed per-access — direct memory R/W at CPU speed
7. 200M+ ops/sec achieved as raw memory accesses
```

**Scenario B: D3DKMTCreateDCFromMemory → Kernel Write Primitive**

```
1. D3DKMTCreateDCFromMemory(pKernelAddress, width, height, format)
   [pKernelAddress is a kernel address obtained via existing KASLR bypass]
   [if validation is bypassed via race or insufficient ProbeForWrite]
2. Kernel creates DC backed by pKernelAddress
3. Perform drawing operations on DC (FillRect, BitBlt, etc.)
4. Kernel writes pixel data to pKernelAddress — arbitrary kernel write
5. D3DKMTDestroyDCFromMemory — cleanup
6. Repeat for each write target
7. For reads: create DC backed by target, read back via GetBitmapBits
```

**Scenario C: Allocation UAF → GDI Bitmap Reclaim → R/W via pvScan0**

```
1. Create GPU allocation via D3DKMTCreateAllocation
2. Trigger UAF via race in D3DKMTDestroyAllocation + D3DKMTShareObjects
   [free the kernel allocation object but keep a reference]
3. Reclaim freed pool with GDI bitmap: CreateBitmap(width, height, ...)
   [bitmap's SURFACE object occupies same pool slot]
4. Use existing bDoGetSetBitmapBits to read pvScan0 (SURFACE+0x50)
5. If UAF lets us control pvScan0 value → arbitrary kernel R/W
6. Set pvScan0 to target kernel address
7. GetBitmapBits → kernel read; SetBitmapBits → kernel write
8. 200M+ ops/sec via rapid Get/SetBitmapBits on bitmap with controlled pvScan0
```

### 4.5 Secondary Targets to Load After dxgkrnl.sys

Once dxgkrnl.sys is loaded and the syscall handlers are identified, these companion modules should be loaded for deeper analysis:

| Module | Path | Why |
|--------|------|-----|
| dxgmms2.sys | C:\Windows\System32\drivers\dxgmms2.sys | VidMm (Video Memory Manager) — contains the actual allocation/locking/residency logic that dxgkrnl calls into |
| dxgmms1.sys | C:\Windows\System32\drivers\dxgmms1.sys | Older VidMm/VidSch interface — some legacy paths may still be reachable |
| win32k.sys | C:\Windows\System32\win32k.sys | The syscall dispatcher — to trace the D3DKMT syscall numbers to dxgkrnl entry points |

### 4.6 IDA Pro Loading Instructions

```
File: C:\Windows\System32\drivers\dxgkrnl.sys
Format: PE64 kernel module
Image base: will be assigned by IDA (typically 0x10000000 or similar for .sys)
Architecture: x64
Analysis: Full auto-analysis (may take 5-10 minutes due to 2.7 MB of code)
Hex-Rays: Enable for decompilation of Dxgk* syscall handlers
```

**IDA workspace setup after loading:**
1. Let auto-analysis complete fully
2. Filter function list for `Dxgk*` — these are the D3DKMT syscall implementations
3. Start with TIER 1 functions: DxgkLock, DxgkLock2, DxgkUnlock, DxgkUnlock2
4. Trace the lock path into dxgmms2.sys (VidMmInterface function table)
5. Map the allocation object structure (ALLOCATION struct) — look for size fields, backing store pointers, lock state
6. Analyze DxgkCreateDCFromMemory for pointer validation (ProbeForWrite, MmUserProbeAddress checks)
7. Analyze DxgkDestroyAllocation for the teardown path and identify race windows

---

## 5. Summary

| Metric | dxgkrnl.sys |
|--------|-------------|
| File path | C:\Windows\System32\drivers\dxgkrnl.sys |
| File size | 3,818,368 bytes (3.63 MB) |
| Image size | 3,845,120 bytes (3.67 MB) |
| Version | 10.0.19041.6456 (Win10 22H2) |
| Start mode | System (always running) |
| Total exports | 487 |
| Usermode-reachable syscalls | 224 (D3DKMT* via gdi32.dll) |
| Executable code | ~2.72 MB (.text 444KB + PAGE 2274KB) |
| Primary vulnerability class | Mapping-based R/W via D3DKMTLock OOB |
| Secondary vulnerability class | Kernel write via D3DKMTCreateDCFromMemory |
| Tertiary vulnerability class | UAF reclaim via allocation destroy race |
| R/W throughput potential | 200M+ ops/sec (direct memory access if mapping bug found) |
| Cross-version | Win10 19041+ through Win11 26H1+ (stable D3DKMT API) |
| Anticheat stealth | Normal graphics API calls, indistinguishable from game |
| Public research level | LOW (individual CVEs exist, no systematic audit) |

**Load `C:\Windows\System32\drivers\dxgkrnl.sys` in IDA Pro. Start with DxgkLock and DxgkCreateDCFromMemory.**
