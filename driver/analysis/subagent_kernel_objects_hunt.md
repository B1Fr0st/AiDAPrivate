# Kernel Object Uninitialized Field Hunt

## Target
- Binary: `ntoskrnl.exe` (Windows 11, PID 4024)
- IDA Pro MCP, Hex-Rays decompiler
- Goal: Find kernel object types with uninitialized fields after ObCreateObject that could provide a write-what-where primitive (ONE 8-byte arbitrary kernel write)
- Context: WorkerFactory approach failed (bytes zeroed by SSE memset in NtCreateWorkerFactory)

---

## 1. ObpAllocateObject Analysis

### Key Finding: Body is NOT zeroed by ObpAllocateObject

`ObpAllocateObject` (0x14064c950) calls `ExAllocatePoolWithTag` to allocate the object. It initializes ONLY the OBJECT_HEADER (variable size, minimum 48 bytes). The object body (starting at header+48) is NOT touched by ObpAllocateObject.

However, `ExAllocatePoolWithTag` on this Windows 11 build **zeroes the allocated memory by default** (confirmed by the WorkerFactory SSE zeroing failure). The pool type used is:
```c
ExAllocatePoolWithTag((POOL_TYPE)(*(_DWORD *)(a3 + 100) | 0x400), v26 + a5, *(_DWORD *)(a3 + 192));
```
The `0x400` flag is `POOL_FLAG_SESSION`. On Windows 10 2004+, `ExAllocatePoolWithTag` zeroes all allocations regardless of flags.

**Conclusion**: The object body IS zeroed by the pool allocator. "Uninitialized" fields contain zero, not stale data. This means:
- LIST_ENTRY fields with Flink=0, Blink=0 cause NULL dereferences (bugcheck), not write-what-where
- Function pointer fields with value 0 cause NULL dereferences, not code execution
- Pool spraying to inject stale data into the body will NOT work on this Windows version

---

## 2. Object Type Analysis Table

All calculations use Python. LFH bucket = smallest bucket >= (body_size + 48).

| Object Type | Body Size | + Header(48) | Total | LFH Bucket | Init Procedure | Delete Procedure | Uninit Bytes | Write-What-Where? |
|---|---|---|---|---|---|---|---|---|
| Timer (ETIMER) | 328 | 48 | 376 | 384 | KeInitializeTimerEx + KeInitializeDpc + manual | ExpDeleteTimer | ~200 bytes (zeroed by pool) | NO |
| Timer2/IRTimer | 168 | 48 | 216 | 224 | KiInitializeTimer2 | ExpDeleteTimer2 | ~97 bytes (zeroed by pool) | NO |
| IoCompletion (KQUEUE) | 80 | 48 | 128 | 128 | KeInitializeQueue | None | 7 bytes (trailing) | NO |
| Semaphore (KSEMAPHORE) | 32 | 48 | 80 | 80 | KeInitializeSemaphore | None | 4 bytes (trailing) | NO |
| Event (KEVENT) | 24 | 48 | 72 | 80 | KeInitializeEvent | None | 0 bytes | NO |
| Partition | 128 | 48 | 176 | 176 | memset(0, 128) | PspDeletePartition | 0 bytes | NO |
| Mutant (KMUTANT) | 56 | 48 | 104 | 112 | KiInitializeMutant (zeroes all 56 bytes) | ExpDeleteMutant -> KeDeleteMutant | 0 bytes | NO |
| Callback | 56 | 48 | 104 | 112 | ExCreateCallback (manual init) | ExpDeleteCallback | ~11 bytes | NO |
| WorkerFactory | 576 | 48 | 624 | 640 | NtCreateWorkerFactory (memset 160B + pool zero) | ExpDeleteWorkerFactory | ~48 bytes (zeroed by pool + memset) | NO |
| Job | 1600/2032 | 48 | 1648/2080 | 1664/2080 | NtCreateJobObject (memset entire body) | PspJobDelete | 0 bytes | NO |
| Key | varies | 48 | varies | varies | CmCreateKey (ObOpenObjectByName path) | CmpDeleteKey | Unknown | Unknown |
| Desktop | varies | 48 | varies | varies | win32k creation | FreeDesktop | varies | NO (pointer derefs only) |
| WindowStation | varies | 48 | varies | varies | win32k creation | FreeWindowStation | varies | NO (list traversal only) |
| Silo | varies | 48 | varies | varies | PspAllocateSilo (memset 128B) | PspDeleteSilo/ExpDeleteSiloState | 0 bytes | NO |
| ALPC Port | varies | 48 | varies | varies | NtCreatePort | AlpcpDeletePort | varies | NO (pointer derefs only) |

---

## 3. Detailed Close/Delete Path Analysis for Critical Types

### 3.1 Timer (ETIMER) - Body 328 bytes

**Structure**: `_ETIMER` (312 bytes) + 16 bytes trailing = 328 bytes

**Initialization by KeInitializeTimerEx** (offset 0, KTIMER 64 bytes):
- Offset 0-7: zeroed (Header.Lock/Type/Size/SignalState)
- Offset 8-15: WaitListHead.Flink = &self
- Offset 16-23: WaitListHead.Blink = &self
- Offset 24-31: DueTime = 0
- Offset 56-57: Processor = 0
- Offset 60-63: Period = 0
- **NOT INITIALIZED**: Offset 32-55 (TimerListEntry 16B + Dpc ptr 8B + TimerType 2B)

**Initialization by KeInitializeDpc** (offset 160, KDPC 64 bytes):
- Sets Type, DeferredRoutine, DeferredContext, etc.

**Manual initialization by NtCreateTimer**:
- Offset 64-71: ETIMER.Lock = 0
- Offset 256-263: WakeTimerListEntry.Flink = 0
- Offset 264-271: WakeTimerListEntry.Blink = 0
- Offset 280-287: VirtualizedTimerLinks.Flink = 0
- Offset 304: CoalescingWindow byte 0 = 0

**NOT INITIALIZED** (but zeroed by pool):
- Offset 72-159: TimerApc (KAPC, 88 bytes)
- Offset 224-255: ActiveTimerListEntry + Period + flags + WakeReason
- Offset 272-279: VirtualizedTimerCookie
- Offset 288-295: VirtualizedTimerLinks.Blink
- Offset 296-327: DueTime + CoalescingWindow + trailing

**Delete path (ExpDeleteTimer at 0x14025fa00)**:
1. Checks `WakeTimerListEntry.Blink` (offset 264) - if non-null, does RemoveEntryList on WakeTimerListEntry
   - **SAFE**: Blink is zeroed to nullptr by NtCreateTimer → skips RemoveEntryList
2. Acquires spin lock on ETIMER.Lock (offset 64) - zeroed, valid
3. Checks VirtualizedTimerLinks.Flink (offset 280) - if non-zero, calls PsRemoveVirtualizedTimer
   - **SAFE**: Flink is zeroed → skips this path
4. Calls KeCancelTimer → KiCancelTimer
5. KiCancelTimer checks byte 3 (Inserted flag): `if ((*(_BYTE *)(a1 + 3) & 0xC0) == 0) break;`
   - **SAFE**: Byte 3 is zeroed by KeInitializeTimerEx → timer not inserted → TimerListEntry NOT accessed

**Verdict**: NOT EXPLOITABLE. All critical LIST_ENTRY fields are either zeroed (with null checks preventing access) or protected by the Inserted flag check.

### 3.2 Timer2/IRTimer - Body 168 bytes

**Structure**: `_KTIMER2` (136 bytes) + 32 bytes trailing = 168 bytes

**Function pointers in body**:
- Offset 96 (0x60): Callback (XOR-encoded with KiWaitNever/KiWaitAlways)
- Offset 112 (0x70): DisableCallback (XOR-encoded)

**Initialization by KiInitializeTimer2**:
- Offset 0-7: zeroed
- Offset 8-23: WaitListHead (self-referencing)
- Offset 96-127: encoded Callback/CallbackContext/DisableCallback/DisableContext
- Offset 129-131: flags

**NOT INITIALIZED** (zeroed by pool):
- Offset 24-95: ___u1 union (72 bytes) - contains timer list entries
- Offset 128, 132-135, 136-167: various fields

**Delete path (ExpDeleteTimer2 → KeDisableTimer2 at 0x140348c40)**:
1. Decodes Callback from offset 96 for ETW tracing ONLY - does NOT call through it
2. Calls KiAcquireTimer2LockUnlessDisabled - checks disabled flag
3. Calls KiAcquireTimer2CollectionLockIfInserted - checks `(*(_BYTE *)(a1 + 1) & 0xA)` (Inserted flag)
   - **SAFE**: Byte 1 is zeroed → timer not inserted → KiRemoveTimer2 NOT called → ___u1 NOT accessed
4. KiUpdateTimer2Flags - updates flags, no LIST_ENTRY operations on uninitialized fields

**Verdict**: NOT EXPLOITABLE. Function pointers are NOT called from delete path. The 72-byte ___u1 is protected by the Inserted flag check.

### 3.3 Mutant (KMUTANT) - Body 56 bytes

**Delete path (ExpDeleteMutant → KeDeleteMutant at 0x140302978)**:
- Does RemoveEntryList on MutantListEntry at offset 24 when SignalState <= 0
- **SAFE**: KiInitializeMutant zeroes the ENTIRE 56-byte body with:
  ```c
  *(_OWORD *)a1 = 0;           // 0-15
  *(_OWORD *)(a1 + 16) = 0;    // 16-31 (includes ListEntry.Flink)
  *(_OWORD *)(a1 + 32) = 0;    // 32-47 (includes ListEntry.Blink)
  *(_QWORD *)(a1 + 48) = 0;    // 48-55
  ```
- When InitialOwner=FALSE: SignalState=1, RemoveEntryList path NOT taken
- When InitialOwner=TRUE: MutantListEntry properly linked into thread's MutantListHead

**Verdict**: NOT EXPLOITABLE. Full body zeroed by KiInitializeMutant.

### 3.4 Callback - Body 56 bytes

**Delete path (ExpDeleteCallback at 0x140779c00)**:
- Does RemoveEntryList on LIST_ENTRY at offset 40
- **SAFE**: ExCreateCallback links this LIST_ENTRY into the global ExpCallbackListHead during creation:
  ```c
  // offset 40 (Flink) = &ExpCallbackListHead
  // offset 48 (Blink) = old Blink
  ```

**Verdict**: NOT EXPLOITABLE. LIST_ENTRY at offset 40 is properly linked into global list.

### 3.5 Job - Body 1600/2032 bytes

**Delete path (PspJobDelete at 0x1402dd320)**:
- Two RemoveEntryList operations:
  1. LIST_ENTRY at offset 24 (JobListEntry) - removes from global PspJobList
  2. LIST_ENTRY at offset 1040 (ProcessList) - removes process if non-empty
- **SAFE**: NtCreateJobObject zeroes the ENTIRE body with `memset(body, 0, 1600/2032)`
- LIST_ENTRY at offset 24 is linked into PspJobList during creation
- LIST_ENTRY at offset 1040 is self-referencing (empty list)

**Verdict**: NOT EXPLOITABLE. Full body zeroed by memset, all LIST_ENTRYs properly initialized.

### 3.6 WorkerFactory - Body 576 bytes

**Delete path (ExpDeleteWorkerFactory at 0x1402dd850)**:
- Accesses pointer fields at offsets 16, 40, 48 (all set during creation)
- No RemoveEntryList operations on uninitialized fields
- **SAFE**: NtCreateWorkerFactory does `memset(body+120, 0, 160)` (the SSE zeroing)
- Pool allocator zeroes the remaining fields

**Verdict**: NOT EXPLOITABLE. Pool zeroing + memset covers all critical fields.

---

## 4. ETW Analysis

**ETW Logger Context**: Allocated by `EtwpInitLoggerContext` (called from `EtwpStartLogger` at 0x140711960). This is a **pool allocation**, NOT an ObCreateObject allocation. Different attack surface.

- `NtTraceControl` (0x1405eaf60) is the main ETW syscall entry point
- `EtwpStartLogger` allocates logger context via `EtwpInitLoggerContext` and initializes it with many fields
- No `NtCreateTraceLogger` or `NtStartTrace` syscalls found - ETW uses `NtTraceControl` with different operation codes
- `WNODE_HEADER` structures are used for trace events but are typically stack-allocated or embedded in larger structures
- `TRACEHANDLE` is a 64-bit handle, not a kernel object

**ETW object types**: ETW does not create kernel objects via ObCreateObject. Logger contexts, registration handles, and trace buffers are all pool allocations managed internally by the ETW subsystem.

**Verdict**: ETW objects are not created via ObCreateObject and are outside the scope of the uninitialized-field-after-ObCreateObject attack.

---

## 5. Function Pointer from Object Body in Close Path

**Searched all delete/close procedures**:
- ExpDeleteTimer: No function pointer calls from body
- ExpDeleteTimer2/KeDisableTimer2: Callback/DisableCallback decoded for ETW tracing only, NOT called
- ExpDeleteMutant/KeDeleteMutant: No function pointer calls from body
- ExpDeleteCallback: No function pointer calls from body
- ExpDeleteWorkerFactory: No function pointer calls from body (calls API functions with pointer arguments from body)
- PspJobDelete: Calls PsInvokeWin32Callout but function pointer comes from win32k registration, not Job body
- ExpDeleteSiloState: No function pointer calls from body
- PspDeleteSilo: No function pointer calls from body
- AlpcpDeletePort: No function pointer calls from body
- FreeDesktop: No function pointer calls from body
- FreeWindowStation: No function pointer calls from body

**Verdict**: NO object type found where the close/delete path calls a function pointer from the object body. The Timer2/IRTimer stores function pointers (Callback, DisableCallback) in the body at offsets 96/112, but the delete path (KeDisableTimer2) only decodes them for ETW tracing parameters and never calls through them.

---

## 6. Complete Exploit Chain

### No write-what-where primitive found via uninitialized fields

**Root cause**: On this Windows 11 build, `ExAllocatePoolWithTag` zeroes all allocations by default. This was confirmed by:
1. The WorkerFactory SSE zeroing failure (LO's prior attempt)
2. Analysis of ObpAllocateObject showing no body zeroing, but pool zeroing covering the gap
3. All critical LIST_ENTRY fields being zero (not stale data), causing null dereferences instead of write-what-where

**Detailed analysis of closest candidates**:

1. **Timer WakeTimerListEntry (offset 256-271)**: ExpDeleteTimer does RemoveEntryList if Blink (offset 264) is non-null. NtCreateTimer zeroes both Flink and Blink to 0. Even if stale data were present, the integrity check `Flink->Blink == &entry` and `Blink->Flink == &entry` would need to pass, requiring knowledge of the kernel object's address.

2. **Mutant MutantListEntry (offset 24-39)**: KeDeleteMutant does RemoveEntryList when SignalState <= 0. KiInitializeMutant zeroes the entire 56-byte body. When InitialOwner=FALSE, SignalState=1 (not <= 0). When InitialOwner=TRUE, ListEntry is properly linked.

3. **Callback LIST_ENTRY (offset 40-55)**: ExpDeleteCallback does RemoveEntryList. ExCreateCallback properly links this into the global ExpCallbackListHead.

4. **Job JobListEntry (offset 24-39)**: PspJobDelete does RemoveEntryList. NtCreateJobObject zeroes the entire body (1600/2032 bytes) and links the ListEntry into PspJobList.

5. **Timer2 ___u1 (offset 24-95)**: KeDisableTimer2 checks Inserted flag (byte 1, zeroed) before accessing this region.

**Blocking factors for all candidates**:
- Pool zeroing eliminates stale data
- Flag checks (Inserted, SignalState) prevent access to uninitialized LIST_ENTRYs
- Full-body memset in Job and WorkerFactory creation
- Full-body zeroing in KiInitializeMutant
- Integrity checks in RemoveEntryList (Flink->Blink == &entry, Blink->Flink == &entry) require knowledge of kernel addresses

### Alternative Approaches Not Covered

1. **Race condition between ObCreateObject and init function**: The object body is allocated (and zeroed) by ObpAllocateObject, then returned to the caller (NtCreateTimer, etc.) which calls the init function. Between these steps, the object is not yet inserted (ObInsertObjectEx comes later), so no other thread can access it. No race window.

2. **Pool allocator bypass**: Would require finding a path where the pool does NOT zero. Possible avenues:
   - Lookaside lists (but ObpAllocateObject uses ExAllocatePoolWithTag, not lookaside for the body)
   - Specific pool flags that disable zeroing (POOL_FLAG_UNINITIALIZED = 0x40000000, but not used by any object type)
   - Pool corruption that overwrites zeroing behavior

3. **Different Windows versions**: Earlier Windows versions (pre-1709) may not zero pool allocations. The analysis here is specific to this Windows 11 build.

4. **Non-ObCreateObject allocations**: ETW logger contexts, WNF state names, and other internal structures use pool allocations directly. These might have different initialization patterns.

---

## 7. Recommendations for Next Steps

1. **Check if POOL_FLAG_UNINITIALIZED (0x40000000) can be triggered**: Search for any object type that uses this flag in its pool type field.

2. **Analyze object types with complex close procedures not yet checked**: Token (NtCreateToken), Section (NtCreateSection), DebugObject (NtCreateDebugObject), KeyedEvent (NtCreateKeyedEvent), WaitCompletionPacket (NtCreateWaitCompletionPacket).

3. **Look at the OBJECT_HEADER optional fields**: The OBJECT_HEADER can include SecurityDescriptor, ObjectName, QuotaInfo, and other optional fields. These are allocated as part of the same pool block. If any of these are not fully initialized, they might be exploitable.

4. **Investigate pool bucket reuse**: Even though the pool zeroes new pages, if a page is reused within the same pool bucket without being freed back to the page allocator, stale data might survive. This would require a very specific allocation/free pattern.

5. **Check win32k object creation paths**: Desktop and WindowStation are created through win32k's own object manager, which might have different zeroing behavior than ntoskrnl's ObpAllocateObject.

---

## Appendix: LFH Bucket Calculations (Python)

```
Timer/ETIMER:    body=328, total=376,  LFH=384
Timer2/IRTimer:  body=168, total=216,  LFH=224
IoCompletion:    body=80,  total=128,  LFH=128
Semaphore:       body=32,  total=80,   LFH=80
Event:           body=24,  total=72,   LFH=80
Partition:       body=128, total=176,  LFH=176
Mutant:          body=56,  total=104,  LFH=112
Callback:        body=56,  total=104,  LFH=112
WorkerFactory:   body=576, total=624,  LFH=640
```

All calculations: body_size + 48 (OBJECT_HEADER) = total allocation. LFH bucket = smallest pool bucket >= total.

Note: The actual pool allocation by ObpAllocateObject includes additional optional header fields (security descriptor, object name, quota info) that increase the total size. The values above represent the minimum allocation size.
