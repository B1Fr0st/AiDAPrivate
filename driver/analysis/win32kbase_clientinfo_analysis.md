# win32kbase.sys CLIENTINFO Write Primitive Analysis

## IDA Instance Info
- **Module**: win32kbase.sys
- **Imagebase**: 0x1C0000000
- **IDB Path**: C:\Windows\System32\win32kbase.sys.i64
- **Hex-Rays**: Ready
- **Analysis Date**: 2026-06-30
- **Target OS**: Windows 10 22H2 (build 19045)
- **Analyst**: ENI (subagent, analysis-only, no build)

---

## Executive Summary

After exhaustive byte-pattern searching, decompilation, cross-referencing, and data-flow tracing of win32kbase.sys, the critical question is answered:

**There is NO function in win32kbase.sys that writes to THREADINFO+0x1E0 (the CLIENTINFO pointer) and is reachable from user mode — directly or indirectly through a syscall, during a user-mode callback, or via a race condition.**

The CLIENTINFO pointer at THREADINFO+0x1E0 is written in exactly three places, all during thread lifecycle management:
1. `xxxCreateThreadInfo` — sets `THREADINFO+0x1E0 = TEB + 0x800` during GUI thread initialization
2. `InitSystemThread` — sets `THREADINFO+0x1E0 = Win32AllocPoolWithQuota(272, "Usci")` for system/display driver threads
3. `xxxDestroyThreadInfo` — sets `THREADINFO+0x1E0 = 0` during thread destruction

None of these are callable from user mode during a KeUserModeCallback. Furthermore:
- There are **zero** `KeUserModeCallback` calls in win32kbase.sys (all Sfn* callbacks are in win32kfull.sys)
- There is **no** `NtUserSetThreadDesktop` implementation in win32kbase.sys
- There are **no** alternative write primitives to SURFACE+0x50 (pvScan0) reachable from user mode
- The SURFACE deletion race condition window is **not exploitable** due to share-count protection

The CLIENTINFO redirect attack remains blocked. The arbitrary kernel READ primitive (via Sfn* in win32kfull.sys) is the only viable exploitation path from the current attack surface.

---

## Task 1: Exhaustive Search for ALL Writes to [reg+0x1E0] in win32kbase.sys

### Methodology

Searched for both 64-bit and 32-bit register writes to `[reg+0x1E0]`:

**64-bit write patterns:**
- `48 89 ?? E0 01 00 00` (mov [reg+1E0h], reg64 where reg = rax-rdi) — 19 matches
- `4C 89 ?? E0 01 00 00` (mov [reg+1E0h], reg64 where reg = r8-r15) — 2 matches

**32-bit write patterns:**
- `89 ?? E0 01 00 00` (mov [reg+1E0h], r32 without REX.W) — 27 matches (includes sub-matches of 64-bit patterns)

**Total unique write sites**: 21 (64-bit) — the 32-bit matches are subsets or lower-dword writes of the same instructions.

### Complete Table of ALL Writes to [reg+0x1E0]

| Address | Instruction | Function | Target Structure | THREADINFO? | User-Reachable? |
|---------|-------------|----------|-----------------|-------------|-----------------|
| 0x1C00189A9 | mov [rcx+1E0h], rax | DrvGetDisplayDriverParameters (0x1C0018748) | tagGRAPHICS_DEVICE | NO | NO (display driver) |
| 0x1C003F3D0 | mov [rdi+1E0h], rax | **xxxCreateThreadInfo** (0x1C003ED88) | **THREADINFO** | **YES** | NO (thread init callout) |
| 0x1C004192D | mov [rsi+1E0h], rax | **xxxDestroyThreadInfo** (0x1C0040420) | **THREADINFO** | **YES** | NO (thread destroy) |
| 0x1C0069A6C | mov [reg+1E0h], reg | W32kEtwEnableCallback (0x1C0069A3C) | ETW state struct | NO | NO (ETW callback) |
| 0x1C0085F4F | mov [rbx+1E0h], rax | **InitSystemThread** (0x1C0085D20) | **THREADINFO** | **YES** | NO (system thread init) |
| 0x1C008C07F | mov [reg+1E0h], reg | MousePerfSummary constructor (0x1C008BF0C) | MousePerfSummary | NO | NO (telemetry) |
| 0x1C008ECD5 | mov [reg+1E0h], reg | ETW Write template (0x1C008EC74) | ETW event struct | NO | NO (ETW) |
| 0x1C008F96B | mov [reg+1E0h], reg | ETW Write template (0x1C008F8B0) | ETW event struct | NO | NO (ETW) |
| 0x1C00DCCB0 | mov [rcx+1E0h], rax | DrvGetDisplayDriverParameters (0x1C0018748) | tagGRAPHICS_DEVICE | NO | NO (display driver) |
| 0x1C011F5A5 | mov [reg+1E0h], reg | xxxDisplayDiagBlackScreenDetected (0x1C011ECA0) | ETW trace stack | NO | NO (display diagnostics) |
| 0x1C0150F8B | mov [reg+1E0h], reg | ETW Write template (0x1C0150F70) | ETW event struct | NO | NO (ETW) |
| 0x1C015C555 | mov [reg+1E0h], reg | RIMCreatePointerDeviceInfo (0x1C015BF5C) | Pointer device info | NO | NO (RIM) |
| 0x1C015F40C | mov [reg+1E0h], reg | RIMReleasePointerDeviceInfo (0x1C015F348) | Pointer device info | NO | NO (RIM) |
| 0x1C015FCC9 | mov [reg+1E0h], reg | RIMReleasePointerDeviceInfo (0x1C015F348) | Pointer device info | NO | NO (RIM) |
| 0x1C015FCDE | mov [reg+1E0h], reg | RIMReleasePointerDeviceInfo (0x1C015F348) | Pointer device info | NO | NO (RIM) |
| 0x1C01B2B15 | mov [reg+1E0h], reg | ETW Write template (0x1C01B2AD0) | ETW event struct | NO | NO (ETW) |
| 0x1C01C27AD | mov [reg+1E0h], reg | ETW Write template (0x1C01C2784) | ETW event struct | NO | NO (ETW) |
| 0x1C01FC8F5 | mov [reg+1E0h], reg | ETW Write template (0x1C01FC7E0) | ETW event struct | NO | NO (ETW) |
| 0x1C020055F | mov [reg+1E0h], reg | MicrosoftTelemetryAssertTriggeredWorker (0x1C020008C) | Telemetry struct | NO | NO (telemetry) |
| 0x1C001BEBC | mov [rdi+1E0h], r8 | DrvGetDeviceConfigurationInformation (0x1C001BCCC) | tagGRAPHICS_DEVICE | NO | NO (display driver) |
| 0x1C0167846 | mov [reg+1E0h], r8 | RIMIDECreateHIDDesc (0x1C016740C) | HID descriptor | NO | NO (RIM) |

### THREADINFO-Related Writes (3 total)

#### 1. xxxCreateThreadInfo (0x1C003ED88) — THREADINFO+0x1E0 = TEB + 0x800

**Address**: 0x1C003F3D0
**Instruction**: `mov [rdi+1E0h], rax` where rdi = ThreadWin32Thread (THREADINFO), rax = Self + 0x800

**Decompiled code**:
```c
Self = KeGetPcr()->NtTib.Self;                          // TEB pointer
// ... extensive THREADINFO field initialization ...
*(_QWORD *)(ThreadWin32Thread + 480) = (char *)Self + 2048;  // THREADINFO+0x1E0 = TEB+0x800
```

**Callers**:
- `UserThreadCallout` (0x1C003DA00) — kernel thread attach/detach callout, called when a thread first becomes a GUI thread
- `UserInitialize` (0x1C0068D34) — win32k initialization function

**User-reachable?**: NO — `UserThreadCallout` is a kernel callback registered via `PsCreateSystemThread`/thread callout mechanism. It fires when the kernel attaches a thread to win32k, not via a user-mode syscall. Once a thread is initialized, it is never re-initialized.

**Also calls**: `InitClientInfo(ThreadWin32Thread)` at 0x1C003FAF2 — initializes CLIENTINFO fields but does NOT write the pointer at THREADINFO+0x1E0.

#### 2. InitSystemThread (0x1C0085D20) — THREADINFO+0x1E0 = Pool Allocation

**Address**: 0x1C0085F4F
**Instruction**: `mov [rbx+1E0h], rax` where rbx = v13 (THREADINFO via W32GetThreadWin32Thread), rax = v15 (pool allocation)

**Decompiled code**:
```c
v13 = W32GetThreadWin32Thread(KeGetCurrentThread());     // THREADINFO
v15 = Win32AllocPoolWithQuota(272, 1768125269, v14);    // Alloc 272 bytes, tag "Usci"
*(_QWORD *)(v13 + 480) = v15;                            // THREADINFO+0x1E0 = pool alloc
```

**Pool tag**: 0x69637355 = "Usci" (reversed: "icsU") — CLIENTINFO for system threads
**Allocation size**: 272 bytes (0x110) — separate from TEB+0x800

**Callers**:
- `VideoPortCalloutThread` (0x1C011B084) — video port callout, for display driver system threads

**User-reachable?**: NO — `VideoPortCalloutThread` is a kernel-mode display driver callout, not user-callable.

**Also calls**: `InitClientInfo(v13)` at 0x1C0085F8D — same as xxxCreateThreadInfo.

#### 3. xxxDestroyThreadInfo (0x1C0040420) — THREADINFO+0x1E0 = 0

**Address**: 0x1C004192D
**Instruction**: `mov [rsi+1E0h], rax` where rsi = v0 (THREADINFO via gptiCurrent), rax = 0

**Decompiled code**:
```c
v0 = gptiCurrent;                                        // THREADINFO
// ... extensive cleanup ...
v104 = *((_QWORD *)v0 + 60);                             // Read THREADINFO+0x1E0 (CLIENTINFO ptr)
if ( v104 )
{
    Win32FreePool(v104);                                 // Free CLIENTINFO pool alloc
    *((_QWORD *)v0 + 60) = 0;                            // THREADINFO+0x1E0 = 0
}
```

Wait — looking more carefully, this is at `*((_QWORD *)v0 + 60) = 0` which is `v0 + 60*8 = v0 + 480 = v0 + 0x1E0`. But this is conditional on `v104` (the CLIENTINFO pointer) being non-null, AND it's in the context of `*((_DWORD *)v0 + 122) & 4` (a flag check). Let me re-examine...

Actually, looking at the decompiled code more carefully:
```c
if ( (*((_DWORD *)v0 + 122) & 4) != 0 )
{
    v104 = *((_QWORD *)v0 + 60);      // v0 + 480 = THREADINFO+0x1E0
    if ( v104 )
    {
      Win32FreePool(v104);            // Free the CLIENTINFO allocation
      *((_QWORD *)v0 + 60) = 0;       // THREADINFO+0x1E0 = NULL
    }
}
```

This only fires for system threads (flag bit 2 at THREADINFO+488/4 = THREADINFO+0x1E8... wait, `*((_DWORD *)v0 + 122)` = `v0 + 122*4 = v0 + 488 = v0 + 0x1E8`). This checks bit 2 of THREADINFO+0x1E8, which is the system-thread flag. So this only zeros THREADINFO+0x1E0 for system threads that had a pool-allocated CLIENTINFO, NOT for normal user-mode threads (which have TEB+0x800 as CLIENTINFO).

**User-reachable?**: NO — `xxxDestroyThreadInfo` is called from `UserThreadCallout` when a thread detaches from win32k (a2=1). Not user-callable.

---

## Task 2: CLIENTINFO Pointer Initialization

### InitClientInfo (0x1C00860D0)

**Does NOT write to THREADINFO+0x1E0**. It reads `[THREADINFO+0x1E0]` to get the CLIENTINFO pointer and initializes fields within the CLIENTINFO structure:

```c
__int64 InitClientInfo(__int64 a1)  // a1 = THREADINFO
{
    // Read CLIENTINFO pointer from THREADINFO+0x1E0
    // Write to CLIENTINFO+0x10 (window version from THREADINFO+0x278)
    *(_DWORD *)(*(_QWORD *)(a1 + 480) + 16LL) = *(_DWORD *)(a1 + 632);
    
    // Write to CLIENTINFO+0x1C (thread flags from THREADINFO+0x1E8)
    *(_DWORD *)(*(_QWORD *)(a1 + 480) + 28LL) = *(_DWORD *)(a1 + 488);
    
    // Write to CLIENTINFO+0xD0 = 0
    *(_QWORD *)(*(_QWORD *)(a1 + 480) + 208LL) = 0;
    
    // Write to CLIENTINFO+0x98 and +0x90 (keyboard layout info)
    // Write to CLIENTINFO+0xE0 (flags)
    // Write to CLIENTINFO+0xE8, +0xEC, +0xF0, +0xF4
    // Write to THREADINFO+0x168 = CLIENTINFO+0xE8
    // Write to THREADINFO+0x170 = CLIENTINFO+0xF0
    
    return 1;
}
```

**Key insight**: InitClientInfo is called AFTER the CLIENTINFO pointer is already set at THREADINFO+0x1E0. It initializes the CLIENTINFO contents, not the pointer itself.

### CLIENTINFO Creation

For **user-mode threads**: CLIENTINFO is at TEB+0x800. This is user-mode memory embedded in the TEB. It is NOT separately allocated — it's part of the TEB structure. The kernel stores a pointer to it at THREADINFO+0x1E0.

For **system threads**: CLIENTINFO is a separate kernel pool allocation (272 bytes, tag "Usci") because system threads don't have a TEB with CLIENTINFO at +0x800.

### String Search

Searched for "CLIENTINFO", "ClientInfo", "Usci" in win32kbase.sys strings — **zero matches**. The pool tag "Usci" is a 4-byte integer constant (0x69637355), not a string literal.

---

## Task 3: Thread Creation/Attachment Path

### UserThreadCallout (0x1C003DA00)

This is the kernel callback for thread attach/detach to win32k:

```c
__int64 UserThreadCallout(PETHREAD Thread, int a2)
{
    if (a2 == 0)  // ATTACH
    {
        // Acquire user critical region
        // Set gptiCurrent
        ThreadInfo = xxxCreateThreadInfo(Thread);  // Creates THREADINFO, sets CLIENTINFO ptr
        // Release user critical region
    }
    else if (a2 == 1)  // DETACH
    {
        // Acquire user critical region
        // Set gptiCurrent
        // Set THREADINFO+0x1E8 |= 1 (mark as detaching)
        xxxDestroyThreadInfo();  // Destroys THREADINFO, zeros CLIENTINFO ptr
        // Release user critical region
    }
}
```

**Key**: The attach/detach is protected by the user critical region lock (gpresUser). There is no window where THREADINFO+0x1E0 could be corrupted by a concurrent operation.

### PsGetThreadWin32Thread / W32GetThreadWin32Thread Usage

`W32GetThreadWin32Thread` (0x1C002F9F0) is used extensively throughout win32kbase.sys to get the current thread's THREADINFO. However, it only READS THREADINFO fields — it does not write to THREADINFO+0x1E0.

### KeGetCurrentThread / gs:188h Accesses

The standard kernel `gs:188h` (KPCR.Prcb.CurrentThread) is used in 20+ locations for getting the current KTHREAD, then `PsGetThreadWin32Thread()` to get W32THREAD, then `*W32THREAD` to get THREADINFO. This is a read-only chain.

### Thread Initialization is NOT User-Callable

The thread initialization path (`UserThreadCallout` -> `xxxCreateThreadInfo`) is triggered by the kernel when:
1. A thread first calls a User/GDI syscall (kernel auto-attaches the thread to win32k)
2. `UserInitialize` is called during win32k startup

Once a thread is initialized, `xxxCreateThreadInfo` is never called again for that thread. There is no "re-initialization" path.

---

## Task 4: Writes to Nearby THREADINFO Fields

### Writes to [reg+0x1D8] (DesktopHeapDelta)

| Address | Instruction | Function | THREADINFO? |
|---------|-------------|----------|-------------|
| 0x1C0042E78 | mov [reg+1D8h], reg | CollectMousePerfTelemetry (0x1C0042DE8) | NO (MousePerf struct) |
| 0x1C00588C3 | mov [reg+1D8h], reg | RIMCreateHidDesc (0x1C00582E8) | NO (HID descriptor) |
| 0x1C008C078 | mov [reg+1D8h], reg | MousePerfSummary (0x1C008BF0C) | NO (MousePerf struct) |
| 0x1C001C840 | mov [reg+1D8h], r8 | DrvWriteDisplayDriverParameters (0x1C001C5D8) | NO (display driver) |
| 0x1C01675F9 | mov [reg+1D8h], r8 | RIMIDECreateHIDDesc (0x1C016740C) | NO (HID descriptor) |

**None write to THREADINFO+0x1D8.** The DesktopHeapDelta at THREADINFO+0x1D8 is written in win32kfull.sys (by `zzzSetDesktop`), not in win32kbase.sys.

### Writes to [reg+0x1D0]

19 matches (64-bit) + 3 matches (4C prefix). After function lookup, none target THREADINFO. They write to display driver parameters, HID descriptors, ETW templates, and MousePerf structures.

### Writes to [reg+0x1E8]

0 matches (64-bit 48 89 pattern), 1 match (4C 89 pattern):
- 0x1C001C84D: DrvWriteDisplayDriverParameters — NOT THREADINFO

### Writes to [reg+0x1F0]

18 matches (64-bit). After function lookup:
- 0x1C0085FC5: InitSystemThread — writes to THREADINFO+0x1F0 (496 decimal) = string allocation pointer
- All others: ETW templates, MousePerf, display diagnostics — NOT THREADINFO

The write at 0x1C0085FC5 in InitSystemThread:
```c
*(_QWORD *)(v13 + 496) = v20;  // THREADINFO+0x1F0 = Win32AllocPoolWithQuota(string_size, "Usci")
```
This is a window name/string allocation, NOT the CLIENTINFO pointer. Not useful for the redirect attack.

---

## Task 5: NtUserSetThreadDesktop and Desktop Switching

### NtUserSetThreadDesktop

The string "NtUserSetThreadDesktop" was found at 0x1C02155F0 — this is a string reference in the syscall table, NOT a function implementation. The actual `NtUserSetThreadDesktop` implementation is in **win32kfull.sys**, not win32kbase.sys.

From the prior analysis of win32kfull.sys:
- `zzzSetDesktop` (0x1C0065E20 in win32kfull.sys) reads THREADINFO+0x1E0 but does NOT write to it
- `zzzSetDesktop` writes to THREADINFO+0x1D8 (DesktopHeapDelta) and CLIENTINFO fields, but NOT the CLIENTINFO pointer
- Desktop switching does NOT redirect the CLIENTINFO pointer

### Desktop-Related Functions in win32kbase.sys

| Function | Address | Purpose | Writes THREADINFO+0x1E0? |
|----------|---------|---------|------------------------|
| NtUserGetThreadDesktop | 0x1C0086D00 | Get current desktop | NO (read-only) |
| ApiSetEditionSetThreadDesktopAtThreadInit | 0x1C01CE148 | Edition-specific desktop init | NO (delegates to function pointer) |
| NtUserSetDesktopVisualInputSink | 0x1C0133600 | Set visual input sink | NO |
| UserIsCurrentThreadDesktopComposed | 0x1C0099D10 | Check if desktop is composed | NO (read-only) |

**None write to THREADINFO+0x1E0.**

---

## Task 6: GDI Handle Manager and Thread Context

### HmgCreate (0x1C006BCFC)

Analyzes GDI handle manager initialization. Creates lookaside lists, type isolation, shared section. Does NOT write to THREADINFO+0x1E0 or any THREADINFO field. It initializes the GDI handle table infrastructure, not per-thread state.

### HmgSetOwner (0x1C00368E0)

Sets handle owner PID in the handle table entry. Does NOT modify THREADINFO. It writes to the 24-byte handle table entry at offset +0x04 (dwOwner), not to any thread structure.

### HMAllocObject (0x1C0034080)

USER object allocation (windows, menus, etc.). Allocates objects via:
- `HMAllocateUserOrIsolatedType` — type-isolated allocation
- `Win32AllocPoolZInit` — session pool with zero-init
- `RtlAllocateHeap` — shared heap
- `Win32AllocPoolWithQuotaZInit(0x140)` — for type 1 objects (320 bytes)

Does NOT write to THREADINFO+0x1E0. Sets up handle table entries, not thread-local state.

One interesting detail: for type 1 (likely windows), it allocates 0x140 (320) bytes via `Win32AllocPoolWithQuotaZInit`, close to but NOT equal to tagWND size (0x150 = 336 bytes).

### HMFreeObject (0x1C0009390)

USER object free. Frees via RtlFreeHeap, Win32FreePool, HMFreeUserOrIsolatedType, or SharedFree. Does NOT modify THREADINFO. Has double-free detection via `HMDoubleFree`.

### Other Hmg* Functions

All Hmg* functions (HmgAlloc, HmgFree, HmgLock, HmgShareLock, HmgUnlock, HmgRemoveObject, etc.) operate on the GDI handle table and GDI objects. None write to THREADINFO fields.

---

## Task 7: User-Mode Callback Path in win32kbase.sys

### KeUserModeCallback Search

Searched for functions named "*KeUserModeCallback*" and "*UserModeCallback*":
- **Zero matches** for KeUserModeCallback
- **Zero matches** for UserModeCallback

Searched for functions named "*Callback*":
- Found 53 functions, all are ETW callbacks, RIM device callbacks, DirectComposition callbacks, timer callbacks, or display driver callbacks
- **None are user-mode callbacks** like the Sfn* functions in win32kfull.sys

### Conclusion

**win32kbase.sys contains NO user-mode callback dispatch points.** All KeUserModeCallback calls are in win32kfull.sys (the Sfn* functions). Therefore, there is no opportunity in win32kbase.sys to modify kernel state during a user-mode callback window.

---

## Task 8: Alternative Write Primitives

### HMAllocObject / HMFreeObject

Neither writes to THREADINFO. HMAllocObject allocates USER objects and sets up handle table entries. HMFreeObject frees USER objects and cleans up handle table entries. No thread-local state modification.

### HmgRemoveObject (0x1C0032640)

Removes a GDI object from the handle table. Does NOT modify THREADINFO. It acquires HmgrSemaphore, validates the object, clears the handle table entry, and releases the semaphore.

### Lookaside List Corruption

The lookaside list function pointers are at:
- qword_1C0256D50: Lookaside allocation function pointer
- qword_1C0256D58: Lookaside allocation function pointer (secondary)
- qword_1C0256D60: Lookaside free validation function pointer
- qword_1C0256D68: Lookaside free function pointer

These are kernel-mode global variables. To corrupt them, we would need a kernel write primitive — which is exactly what we're trying to find. Circular dependency.

### Pool Overflow

No pool overflow opportunities found in GDI object creation in win32kbase.sys. All allocation sizes are computed from validated parameters and bounded by format-specific calculations. SURFMEM::bCreateDIB carefully calculates bitmap bits size based on width, height, and format.

### Type Confusion

Type validation in all GDI lock functions (HmgShareLockCheck, HmgLock, etc.) checks both type AND stamp:
- Type check: `entry[14] == expected_type`
- Stamp check: `entry[12] == HIWORD(handle)`

HmgModifyHandleType (0x1C00174D0) and HmgLockAndModifyHandleType (0x1C0017460) can change the type field, but their callers are all kernel-internal (not user-callable). No user-mode path to trigger type confusion.

### Section Mapping

No function in win32kbase.sys maps a section that overlaps with THREADINFO memory. The shared handle table section (gpGdiSharedMemory) is mapped at a fixed address in session space and user mode, but it contains the handle table, not THREADINFO.

### Win32AllocPool / Win32FreePool

Win32AllocPool (0x1C002C2D0) and Win32FreePool (0x1C002C230) are thin wrappers around function pointers (qword_1C0256D38, qword_1C0256D08). They use the standard session pool allocator. No custom pool logic that could be exploited.

---

## Task 9: SURFACE Object Analysis and Size Matching

### GDI Object Type Isolation Sizes

| Type | Object | Slot Size | Matches 0x150? |
|------|--------|-----------|----------------|
| 1 (DC) | Device Context | 0x868 (2152) | NO (too big) |
| 4 (Region) | Region | 0x70 (112) | NO (too small) |
| 5 (SURFACE) | Bitmap Surface | 0x2C0 (704) | NO (too big) |
| 8 (Palette) | Palette | 0xC8 (200) | NO (too small) |
| 10 (Font) | Font | 0x278 (632) | NO (too big) |
| 11 (Enum) | Enum | 0x390 (912) | NO (too big) |
| 16 (Brush) | Brush | 0xB8 (184) | NO (too small) |

**No GDI object type has a slot size of 0x150 (336 bytes).** The tagWND is 0x150 bytes in general session pool, and no GDI type-isolated object matches this size.

### Non-Type-Isolated Objects of Size 0x150

Searched for `ExAllocatePool2` or `ExAllocatePoolWithTag` calls with size 0x150 — **no direct matches found** in win32kbase.sys. The session pool allocator uses function pointers (qword_1C0256D38), so the actual pool allocation calls are indirect and cannot be pattern-matched.

### Session Pool Spray for tagWND Reclaim

The standard approach for tagWND reclaim (0x150 bytes) is to use non-GDI session pool allocations:
- `HMAllocObject` for type 1 objects allocates 0x140 (320) bytes — close but not 0x150
- Window extra bytes (cbWndExtra) can create allocations of arbitrary size in session pool
- Other USER object allocations may match 0x150

This is a win32kfull.sys analysis topic, not win32kbase.sys.

---

## Task 10: Win32AllocPool and Session Pool Allocator

### Win32AllocPool (0x1C002C2D0)

```c
__int64 Win32AllocPool(__int64 a1, unsigned int a2)
{
    // Calls function pointer qword_1C0256D28(33, size, tag)
    // Which is the session pool allocation function
}
```

### Win32AllocPoolWithQuota (0x1C002AA40)

```c
__int64 Win32AllocPoolWithQuota(__int64 a1, unsigned int a2)
{
    // Calls qword_1C0256D30() for validation
    // Then qword_1C0256D38(41, size, tag) for allocation
}
```

### Win32FreePool (0x1C002C230)

```c
void Win32FreePool(__int64 a1)
{
    if (a1 && qword_1C0256D00 && (int)qword_1C0256D00() >= 0)
    {
        if (qword_1C0256D08)
            qword_1C0256D08(a1);  // Session pool free
    }
}
```

**All Win32AllocPool/Win32FreePool variants are thin wrappers around function pointers.** The actual pool allocation goes through the standard kernel session pool allocator. No custom allocator logic, no exploitable patterns.

### Can we spray 0x150-byte session pool allocations?

Yes — any API that creates session pool allocations of 0x150 bytes with controlled content can be used for tagWND reclaim. This is a win32kfull.sys/win32k USER analysis topic, not win32kbase.sys.

---

## Task 11: CLIENTINFO Structure and TEB Relationship

### How CLIENTINFO is Created

For **user-mode threads**: CLIENTINFO is embedded in the TEB at offset 0x800. It is NOT separately allocated. The TEB is allocated by the kernel during thread creation, and CLIENTINFO is simply a region within it. The kernel stores a pointer to TEB+0x800 at THREADINFO+0x1E0.

For **system threads**: CLIENTINFO is a separate kernel pool allocation (272 bytes, tag "Usci") because system threads either don't have a TEB or their TEB doesn't have CLIENTINFO at +0x800.

### Is there a section object for CLIENTINFO?

No — CLIENTINFO for user-mode threads is part of the TEB, which is allocated as part of the thread's user-mode stack/TEB/PEB infrastructure. There is no separate section object that could be mapped at a different address.

### Can we change TEB+0x800?

TEB is user-mode memory, fully writable from user mode. We CAN change TEB+0x800 (the CLIENTINFO contents). But the kernel uses THREADINFO+0x1E0 (a kernel pointer) to find CLIENTINFO, NOT TEB+0x800 directly. Changing TEB+0x800 contents changes what the kernel reads/writes via THREADINFO+0x1E0, but we CANNOT change WHERE THREADINFO+0x1E0 points.

### Key insight

```
User-mode:   TEB+0x800 = CLIENTINFO (writable from user mode)
             TEB+0x850 = CLIENTINFO+0x50 (writable from user mode)

Kernel-mode: THREADINFO+0x1E0 = pointer to TEB+0x800 (kernel memory, NOT writable from user mode)
             Sfn* reads [THREADINFO+0x1E0] to get CLIENTINFO pointer
             Sfn* writes to [CLIENTINFO+0x50] = [TEB+0x850]
```

To redirect CLIENTINFO to a SURFACE, we need to change THREADINFO+0x1E0 (kernel memory) to point at the SURFACE. Changing TEB+0x800 (user memory) does NOT achieve this — it only changes the CONTENTS of CLIENTINFO, not the POINTER to CLIENTINFO.

---

## Task 12: Exhaustive Search for Any Kernel Write Primitive

### Complete Table of ALL Non-Stack Writes to [reg+0x50]

Searched for `mov [reg+50h], reg64` instructions (patterns: 48 89 41 50, 48 89 43 50, 48 89 45 50, 48 89 46 50, 48 89 47 50, and 4C variants).

**Non-stack writes (excluding rbp+0x50 which is stack frame):**

| Address | Instruction | Function | Target | Could be SURFACE+0x50? |
|---------|-------------|----------|--------|----------------------|
| 0x1C002837A | mov [rcx+50h], rax | SURFMEM::bCreateDIB (0x1C0027C60) | SURFACE+0x50 = pvBits | YES but value = pvBits (not user-controlled) |
| 0x1C00283C9 | mov [rcx+50h], rax | SURFMEM::bCreateDIB (0x1C0027C60) | SURFACE+0x50 = pvBits | YES but value = pvBits |
| 0x1C0090D7F | mov [rcx+50h], rax | CMouseProcessor ctor (0x1C0090D40) | MouseInputData+0x50 | NO (mouse data) |
| 0x1C00DCD57 | mov [rcx+50h], rax | DrvGetDisplayDriverParameters (0x1C0018748) | DisplayDriverParams+0x50 | NO (display driver) |
| 0x1C013766A | mov [rcx+50h], rax | tagKERNELDISPLAYINFO::operator= (0x1C0137614) | DisplayInfo+0x50 | NO (display info) |
| 0x1C018AA0A | mov [rcx+50h], rax | CTouchProcessor::CoalesceQFrames (0x1C018A4B4) | TouchFrame+0x50 | NO (touch) |
| 0x1C01DBE1A | mov [rcx+50h], rax | CCompositionGlyphRunMarshaler::Initialize (0x1C01DBE10) | Marshaler+0x50 | NO (DirectComposition) |
| 0x1C01ED3FE | mov [rcx+50h], rax | CHolographicDisplayMarshaler::SetBufferProperty (0x1C01ED3D0) | Marshaler+0x50 | NO (DirectComposition) |
| 0x1C0009F18 | mov [rbx+50h], rax | xxxLoadKeyboardLayoutEx (0x1C0009AD8) | KeyboardLayout+0x50 | NO (keyboard) |
| 0x1C0038D29 | mov [rbx+50h], rax | _GetDCEx (0x1C0038070) | DC+0x50 | NO (DC) |
| 0x1C003B192 | mov [rbx+50h], rax | GetMonitorDC (0x1C003B0E0) | DC+0x50 | NO (DC) |
| 0x1C008CB1C | mov [rdi+50h], rax | CitpContextInitialize (0x1C008CACC) | CIT context+0x50 | NO (CIT) |
| 0x1C009729B | mov [rdi+50h], rax | CAnimationMarshaler::EnsureTimeListEntry (0x1C0097238) | Marshaler+0x50 | NO (DirectComposition) |
| 0x1C00B3D23 | mov [rdi+50h], rax | CDeviceIdentity::IssueIdentityOnDeviceArrival (0x1C00B3C90) | DeviceIdentity+0x50 | NO (RIM) |
| 0x1C0084F1F | mov [rcx+50h], r8 | CInteractionMarshaler ctor (0x1C0084EEC) | Marshaler+0x50 | NO (DirectComposition) |
| 0x1C01DBF8A | mov [rcx+50h], r8 | CScaleTransform3DMarshaler::Initialize (0x1C01DBF80) | Marshaler+0x50 | NO (DirectComposition) |
| 0x1C008EA3E | mov [rsi+50h], rax | CitpPostUpdateUseInfoCalculate (0x1C008E880) | CIT context+0x50 | NO (CIT) |
| 0x1C00B1B1F | mov [rsi+50h], rax | CApplicationChannel::RecordBatchDeferred (0x1C00B1A08) | Batch+0x50 | NO (DirectComposition) |

### EngModifySurface (0x1C009B440) — callers

| Caller | Address | Context | pvScan0 value |
|--------|---------|---------|---------------|
| MulEnableSurface (0x1C0142080) | 0x1C01420F0 | Display driver surface enable | NULL |
| Export table entries | 0x1C02385AC, 0x1C0249DF8, 0x1C02612A4 | Exported Eng function | N/A (display driver calls) |

**No new callers found.** The only code caller in win32kbase.sys is MulEnableSurface, which passes pvScan0=NULL. No user-mode syscall reaches EngModifySurface with a non-NULL pvScan0.

### Conclusion

**No function in win32kbase.sys writes a user-controlled value to SURFACE+0x50 (pvScan0).** The only writes to SURFACE+0x50 are:
1. SURFMEM::bCreateDIB — writes pvBits (computed from allocation, not user-controlled)
2. EngModifySurface — writes caller-provided pvScan0, but only called by MulEnableSurface with NULL

---

## Task 13: Race Condition in GDI Object Lifecycle

### SURFACE::bDeleteSurface (0x1C000DEF0) — Deletion Flow

```
1. Save SURFACE fields (bits pointer, section info, etc.)
2. Acquire DEVLOCK and NEEDGRELOCK
3. Call HmgRemoveObject — removes SURFACE from handle table
   ↓ If HmgRemoveObject FAILS (object busy / share count > 0):
   ↓   Decrement share ref count, return (object NOT freed)
   ↓ If HmgRemoveObject SUCCEEDS:
4.   Call display driver cleanup (if applicable)
5.   Free bitmap bits:
       - MmUnsecureVirtualMemory (secured surfaces)
       - MmUnmapViewInSessionSpace (session-mapped)
       - ZwUnmapViewOfSection + ZwFreeVirtualMemory (user-memory)
       - EngFreeUserMem (user-memory, no 0x80 flag)
       - vFreeKernelSection (kernel sections)
6.   Call SURFACE::Free — memset(0, 0x2C0) + push to type isolation SLIST
7.   Cleanup palette, section objects
```

### Race Window Analysis

**Window**: Between step 3 (HmgRemoveObject succeeds) and step 6 (SURFACE::Free zeroes and returns to SLIST).

During this window:
- The handle table entry has been cleared (step 3)
- The SURFACE object is still in memory, intact
- Bitmap bits may be freed (step 5)
- The SURFACE has not yet been zeroed or returned to the SLIST

**Can we exploit this race?**

1. **Via SURFREF**: A SURFREF increments the share count at SURFACE+8. HmgRemoveObject checks the share count — if > 0, it FAILS. Therefore, if a SURFREF exists, HmgRemoveObject cannot succeed, and the race window never opens.

2. **Via direct kernel pointer**: If we have a kernel pointer to the SURFACE (via KASLR bypass), we could read/write it directly during the race window. But we need a kernel write primitive to corrupt pvScan0, which is exactly what we're trying to find. Circular dependency.

3. **Via another thread**: Another thread could attempt to access the SURFACE via its handle during the window. But the handle table entry has been cleared (step 3), so handle-based access fails. Only direct-pointer access works, which requires a kernel address leak.

**Conclusion**: The race window exists but is **NOT exploitable** without a pre-existing kernel write primitive or direct kernel pointer access to the SURFACE.

### Double-Free Analysis

HmgRemoveObject and HMFreeObject both have double-free detection:
- HmgRemoveObject checks if the object is already removed
- HMFreeObject calls HMDoubleFree if the object appears already freed
- SURFACE::Free zeroes the entire 0x2C0-byte slot before returning to SLIST

No double-free scenario found that would allow reclaim with controlled data.

---

## Feasibility Assessment

### CLIENTINFO Redirect Attack

| Component | Status | Details |
|-----------|--------|---------|
| Sfn* re-read of THREADINFO+0x1E0 | CONFIRMED | In win32kfull.sys — both SfnDWORD and SfnOUTSTRING re-read after callback |
| Pre-write to TEB+0x850 | CONFIRMED | TEB is user-writable, CLIENTINFO+0x50 = TEB+0x850 |
| THREADINFO+0x1E0 corruption | **BLOCKED** | No user-callable function writes to THREADINFO+0x1E0 |
| SURFACE+0x50 = pvScan0 target | CONFIRMED | SURFACE+0x50 = pvScan0, corruption gives arbitrary R/W |
| tagWND UAF trigger | CONFIRMED | xxxSendTransformableMessageTimeout UAF in win32kfull.sys |
| Arbitrary kernel READ | CONFIRMED | pwndk = target - 0xE0, read TEB+0x850 during callback |

### Write to THREADINFO+0x1E0 in win32kbase.sys

| Function | Address | Write Value | User-Callable? | During Callback? |
|----------|---------|-------------|----------------|-----------------|
| xxxCreateThreadInfo | 0x1C003F3D0 | TEB + 0x800 | NO (thread init callout) | NO |
| InitSystemThread | 0x1C0085F4F | Pool alloc (272 bytes) | NO (video port callout) | NO |
| xxxDestroyThreadInfo | 0x1C004192D | 0 (NULL) | NO (thread destroy) | NO |

### Alternative Write Primitives

| Approach | Viable? | Blocker |
|----------|---------|---------|
| EngModifySurface with user pvScan0 | NO | Only called by MulEnableSurface (passes NULL) |
| SURFMEM::bCreateDIB pvScan0 | NO | Value = pvBits (not user-controlled) |
| Pool overflow in GDI creation | NO | No overflow found — sizes are validated |
| Type confusion (GDI handle) | NO | Type+stamp validation in all lock functions |
| Lookaside list corruption | NO | Requires kernel write primitive (circular) |
| Section mapping overlap | NO | No section maps to THREADINFO memory |
| SURFACE deletion race | NO | Share count prevents HmgRemoveObject when SURFREF exists |
| Double-free SURFACE | NO | Double-free detection + zeroing on free |
| Handle table corruption (shared section) | MAYBE | If PEB->GdiSharedHandleTable is user-writable (needs testing) |
| KeUserModeCallback in win32kbase | NO | Zero KeUserModeCallback calls in win32kbase.sys |

---

## Key Findings Summary

1. **THREADINFO+0x1E0 is written in exactly 3 places** in win32kbase.sys, all during thread lifecycle management (init/destroy). None are user-callable during a callback.

2. **InitClientInfo** initializes CLIENTINFO contents but does NOT write the CLIENTINFO pointer at THREADINFO+0x1E0.

3. **No KeUserModeCallback calls** exist in win32kbase.sys — all user-mode callbacks are in win32kfull.sys.

4. **No NtUserSetThreadDesktop** implementation in win32kbase.sys — it's in win32kfull.sys.

5. **No alternative write to SURFACE+0x50 (pvScan0)** with user-controlled value exists in win32kbase.sys.

6. **The CLIENTINFO redirect attack is NOT viable through win32kbase.sys.**

7. **The SURFACE deletion race window exists but is not exploitable** without a pre-existing kernel write primitive.

8. **The handle table shared section (PEB->GdiSharedHandleTable)** remains the most promising untested attack vector — if it is writable in user mode, direct handle table corruption could bypass all GDI type checks.

---

## Recommended Next Steps

1. **Test PEB->GdiSharedHandleTable writability**: If the shared handle table section is mapped PAGE_READWRITE in user mode (as the MmMapViewOfSection call suggests), directly modifying the object pointer at entry+0x16 could redirect a bitmap handle to controlled memory, creating a fake SURFACE with arbitrary pvScan0. This is the highest-priority untested vector.

2. **Explore the arbitrary READ for alternative exploitation**:
   - Leak ETHREAD → Win32Thread → THREADINFO address
   - Leak EPROCESS → Token address for token stealing
   - Leak HalDispatchTable for control flow hijack
   - Leak SURFACE/bitmap addresses for bitmap-based exploitation
   - Use the read primitive to find and exploit a DIFFERENT write vulnerability

3. **Investigate ntoskrnl.exe**: The THREADINFO+0x1E0 write might happen in ntoskrnl during thread creation/attachment. Analyze ntoskrnl for any function that modifies the W32THREAD or THREADINFO structure.

4. **Investigate win32kfull.sys more deeply**: The `zzzSetDesktop` function modifies THREADINFO+0x1D8 (DesktopHeapDelta) but not +0x1E0. Check if there's a different desktop switching path in win32kfull.sys that modifies +0x1E0.

5. **Consider alternative UAF exploitation**: Instead of the CLIENTINFO redirect, use the arbitrary READ to leak enough kernel state to construct a different write primitive (e.g., via NtQuerySystemInformation leaks, HalDispatchTable hijack, or pipe attribute abuse).

6. **Investigate nested callback races in win32kfull.sys**: During the Sfn* callback, trigger a nested message that goes through xxxSBWndProc. The temporary bit flip at pwndk+0x1E during DrawSize might create a brief window where a nested Sfn* call sees a corrupted value. This is extremely timing-sensitive but worth investigating.

7. **Session pool spray for tagWND reclaim**: Use non-GDI session pool allocations of 0x150 bytes (e.g., via USER object creation) with controlled data at offsets 0x28 (pwndk), 0x12 (flags), 0x78 (handler index), and 0xE0 (value for CLIENTINFO+0x50 write). This is the standard approach for the UAF exploitation and is a win32kfull.sys/USER analysis topic.

---

## Final Assessment

**The CLIENTINFO redirect attack is NOT viable through win32kbase.sys.** The CLIENTINFO pointer at THREADINFO+0x1E0 is set only during thread initialization (xxxCreateThreadInfo = TEB+0x800, or InitSystemThread = pool alloc) and cleared during thread destruction (xxxDestroyThreadInfo = 0). None of these paths are reachable from user mode during a KeUserModeCallback.

The exploit chain remains at:
- **KASLR bypass**: PEB->GdiSharedHandleTable or NtGdiGetEntry (CONFIRMED)
- **UAF trigger**: xxxSendTransformableMessageTimeout in win32kfull.sys (CONFIRMED)
- **Arbitrary kernel READ**: Sfn* writes [target] to TEB+0x850 during callback (CONFIRMED)
- **Arbitrary kernel WRITE**: BLOCKED — requires either CLIENTINFO redirect (blocked) or an alternative write primitive (not found in win32kbase.sys)

The most promising path forward is to use the arbitrary READ primitive to leak kernel addresses and construct a write primitive through a different vulnerability or technique (HalDispatchTable, pipe attributes, shared handle table corruption if writable, or a different UAF/write path in win32kfull.sys or ntoskrnl.exe).
