# WorkerFactory Deep Analysis — ntoskrnl.exe (PID 4024)

## Executive Summary

**The previous subagent's claim of "32 completely uninitialized bytes at body offsets 72-103" is INCORRECT.**

`ExpInitializeThreadHistory` (0x14035a764) explicitly zeroes all 32 bytes at offsets 72-103 using two 128-bit SSE stores (`movups xmmword ptr [rcx+48h], xmm0` and `movups xmmword ptr [rcx+58h], xmm0`) BEFORE the object becomes accessible via a handle. The zeroing occurs at step 7 of 12 in `NtCreateWorkerFactory`, before `KeSetTimer2` (step 11) and `ObInsertObject` (step 12).

The 4 QWORDs at offsets 72-103 are the **thread history array** — an array of 4 `KTHREAD*` pointers tracking active worker threads. They are properly managed throughout the WorkerFactory lifecycle with matched reference/dereference pairs under the WorkerFactory spin lock.

---

## 1. Complete WorkerFactory Body Layout (576 bytes / 0x240)

### Object Type Info
- **Type name**: `TpWorkerFactory`
- **Pool tag**: `TpWo` (0x6F577054)
- **Pool type**: NonPagedPoolNx (0x200)
- **Body size**: 576 bytes (0x240)
- **Close procedure**: `ExpCloseWorkerFactory` (0x1406f0300)
- **Delete procedure**: `ExpDeleteWorkerFactory` (0x1402dd850)
- **DefaultNonPagedPoolCharge**: 576 + 88 = 664 (includes header overhead charge)

### Pool Allocation
```
Unnamed: header(80) + body(576) = 656 bytes -> LFH bucket 704
Named:   header(112) + body(576) = 688 bytes -> LFH bucket 704
```
Both unnamed and named WorkerFactory allocations land in **LFH bucket 704** (641-704 byte range).

### Body Field Map

| Offset | Size | QWORD Idx | Field | Initialized By | Notes |
|--------|------|-----------|-------|----------------|-------|
| 0 | 8 | [0] | Unknown/reserved | ObCreateObject (not zeroed) | Not read by close path |
| 8 | 8 | [1] | Unknown/reserved | ObCreateObject (not zeroed) | Not read by close path |
| 16 | 8 | [2] | Completion port struct ptr | NtCreateWorkerFactory | Pool alloc 0x28 bytes |
| 24 | 8 | [3] | StartRoutine | NtCreateWorkerFactory (a6) | Worker thread entry |
| 32 | 8 | [4] | StartContext | NtCreateWorkerFactory (a7) | Passed to worker |
| 40 | 8 | [5] | Process handle | NtCreateWorkerFactory (v28) | ObOpenObjectByPointer |
| 48 | 8 | [6] | Process object ptr | NtCreateWorkerFactory (v19) | ObReferenceObjectByHandleWithTag |
| 56 | 8 | [7] | Stack reserve | NtCreateWorkerFactory (v24) | Default 0x10000 |
| 64 | 8 | [8] | Stack commit | NtCreateWorkerFactory (v25) | Default 0x1000 |
| 72 | 8 | [9] | ThreadHistory[0] | ExpInitializeThreadHistory | KTHREAD* ZEROED on init |
| 80 | 8 | [10] | ThreadHistory[1] | ExpInitializeThreadHistory | KTHREAD* ZEROED on init |
| 88 | 8 | [11] | ThreadHistory[2] | ExpInitializeThreadHistory | KTHREAD* ZEROED on init |
| 96 | 8 | [12] | ThreadHistory[3] | ExpInitializeThreadHistory | KTHREAD* ZEROED on init |
| 104 | 8 | [13] | EX_RUNDOWN_REF | NtCreateWorkerFactory (set to 0) | ExAcquireRundownProtection |
| 112 | 8 | [14] | Idle timeout | NtCreateWorkerFactory | -10000000 * seconds |
| 120 | 160 | [15..34] | Thread info / affinity | memset(v23+15, 0, 0xA0) | Zeroed 160 bytes |
| 280 | 4 | DWORD[70] | Counter | NtCreateWorkerFactory (0) | |
| 284 | 4 | DWORD[71] | MaxThreadCount | NtCreateWorkerFactory (a8) | User-supplied |
| 288 | 8 | [36] | Unknown | NtCreateWorkerFactory (0) | |
| 296 | 4 | DWORD[74] | PendingCreateCount | NtCreateWorkerFactory (0) | Incremented in CheckCreate |
| 300 | 4 | DWORD[75] | Unknown | NtCreateWorkerFactory (0) | |
| 304 | 8 | [38] | Unknown | NtCreateWorkerFactory (0) | |
| 312 | 4 | DWORD[78] | State flags | NtCreateWorkerFactory (0) + ExpInitThreadHistory | Bits control thread creation |
| 316 | 4 | DWORD[79] | ThreadBasePriority | NtCreateWorkerFactory | |
| 320 | 4 | DWORD[80] | LastCreateStatus | NtCreateWorkerFactory (0) | |
| 328 | ~136 | [41..57] | KTIMER2 | KeInitializeTimer2 | Embedded timer2 struct |
| 464 | ~48 | [58..63] | KQUEUE / notification | KeRegisterObjectNotification | |
| 512 | 4 | DWORD[128] | Unknown | NtCreateWorkerFactory (1) | Set to 1 |
| 568 | 4 | DWORD[142] | Unknown | NtCreateWorkerFactory (0) | |
| 576 | -- | -- | END OF BODY | -- | Total 576 bytes |

### ExpInitializeThreadHistory Assembly (CONFIRMED)
```asm
ExpInitializeThreadHistory:
  and dword ptr [rcx+138h], 0FFFFFFF8h    ; clear state flags at offset 312
  xorps xmm0, xmm0                         ; xmm0 = 0
  movups xmmword ptr [rcx+48h], xmm0       ; zero 16 bytes at offset 72-87 (ThreadHistory[0..1])
  movups xmmword ptr [rcx+58h], xmm0       ; zero 16 bytes at offset 88-103 (ThreadHistory[2..3])
  retn
```

### Initialization Order in NtCreateWorkerFactory (CRITICAL)

```
Step  1: ObCreateObject          -> Allocate body (NOT zeroed, residual pool data)
Step  2: v23 = body pointer
Step  3: Field assignments       -> offsets 16,24,32,40,48,56,64,112,280,284,288,296,300,304,312,320,512,568
Step  4: memset(v23+15, 0, 0xA0) -> Zero bytes 120-279
Step  5: More field assignments  -> (remaining fields)
Step  6: KeInitializeTimer2      -> Init timer at offset 328 (does NOT start it)
Step  7: ExpInitializeThreadHistory -> *** ZERO bytes 72-103 *** (THE 4 QWORDs)
Step  8: v23[13] = 0             -> Zero offset 104
Step  9: ObfReferenceObject      -> Reference completion port
Step 10: KeRegisterObjectNotification -> Register notification
Step 11: KeSetTimer2             -> START timer (after zeroing!)
Step 12: ObInsertObject          -> Create handle -> OBJECT BECOMES ACCESSIBLE
```

**The 4 QWORDs are zeroed at step 7, before any external code can access the object (step 12).**

---

## 2. Complete Decompilation Analysis

### ExpShutdownWorkerFactory (0x1403489e8) -- Close Path

```c
__int64 __fastcall ExpShutdownWorkerFactory(_QWORD *Object)
{
    KSPIN_LOCK *v2 = (KSPIN_LOCK *)Object[2];      // spin lock at offset 16
    KeAcquireInStackQueuedSpinLock(v2, &LockHandle);

    PVOID *v3 = (PVOID *)(Object + 9);              // offset 72 = ThreadHistory[0]
    __int64 v4 = 4;                                  // 4 QWORDs to process

    *((_DWORD *)Object + 78) = Object[39] & 0xFFFFFFF8 | 4;  // set shutdown flag

    do {
        if (*v3) {                                    // if ThreadHistory slot non-zero
            ObfDereferenceObjectWithTag(*v3, 0x746C6644u);   // deref KTHREAD*
            *v3 = nullptr;                             // zero the slot
        }
        ++v3;                                         // advance to next QWORD
        --v4;
    } while (v4);

    if ((Object[39] & 0x200) != 0)
        ExpLeaveWorkerFactoryAwayMode(Object);

    if ((_QWORD *)Object[62] == Object + 41
        && (unsigned __int8)KeDeregisterObjectNotification(Object + 41))
        ObfDereferenceObjectWithTag(Object, 0x746C6644u);

    *(_BYTE *)(Object[2] + 33LL) = 1;               // mark as shutting down
    // ... completion port cleanup ...
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&LockHandle);
    // ... IRQL restore ...
    KeCancelTimer2(Object + 41, 0);
    // ... IoSetIoCompletionEx2 if needed ...
}
```

### NtCreateWorkerFactory (0x140701630) -- Create Path

```c
NTSTATUS __fastcall NtCreateWorkerFactory(
    HANDLE *WorkerFactoryHandle,
    ACCESS_MASK DesiredAccess,
    int ObjectAttributes,
    void *CompletionPortHandle,
    HANDLE ProcessHandle,
    __int64 StartRoutine,
    __int64 StartContext,
    int MaxThreadCount,
    __int64 StackReserve,
    __int64 StackCommit)
{
    // 1. Allocate completion port struct (0x28 bytes, NonPagedPoolNx)
    PoolWithQuotaTag = ExAllocatePoolWithQuotaTag(520, 0x28, 'TpWc');

    // 2. Reference IO completion port
    ObReferenceObjectByHandle(CompletionPortHandle, 2, IoCompletionObjectType, ...);

    // 3. Reference current process (must be calling process)
    ObReferenceObjectByHandleWithTag(ProcessHandle, 0x2A, PsProcessType, ...);

    // 4. Allocate WorkerFactory body via ObCreateObject
    ObCreateObject(PreviousMode, ExpWorkerFactoryObjectType, ObjectAttributes, ...);

    // 5. Initialize body fields
    v23 = body_ptr;
    v23[2]  = completion_port_struct;     // offset 16
    v23[3]  = StartRoutine;               // offset 24
    v23[4]  = StartContext;               // offset 32
    v23[5]  = process_handle;             // offset 40
    v23[6]  = process_object;             // offset 48
    v23[7]  = StackReserve;               // offset 56
    v23[8]  = StackCommit;                // offset 64
    v23[14] = idle_timeout;               // offset 112
    memset(v23+15, 0, 0xA0);             // zero 120-279
    v23[39] = 0;                          // offset 312 (state flags)
    // ... more fields ...

    // 6. Initialize timer (does NOT start it)
    KeInitializeTimer2(v23 + 41, ...);

    // 7. *** ZERO THREAD HISTORY (offsets 72-103) ***
    ExpInitializeThreadHistory(v23);

    // 8. Zero rundown protection
    v23[13] = 0;                          // offset 104

    // 9. Register notification
    KeRegisterObjectNotification(v23 + 41, ...);

    // 10. Start timer
    KeSetTimer2(v23 + 41, v23[14], ...);

    // 11. Create handle -> object becomes accessible
    ObInsertObject(v23, ...);

    *WorkerFactoryHandle = handle;
    return status;
}
```

### ExpCloseWorkerFactory (0x1406f0300) -- Object Close Callback

```c
__int64 __fastcall ExpCloseWorkerFactory(__int64 a1, void *a2, __int64 a3, __int64 a4)
{
    if (a4 == 1)
        return ExpShutdownWorkerFactory(a2);
    return 0;
}
```

### ExpDeleteWorkerFactory (0x1402dd850) -- Object Delete Callback

```c
void __fastcall ExpDeleteWorkerFactory(PVOID *a1)
{
    KeAcquireInStackQueuedSpinLock(a1[2], &LockHandle);
    *((_BYTE *)a1[2] + 34) = 1;           // mark as deleting
    // ... read completion port state ...
    KeReleaseInStackQueuedSpinLock(&LockHandle);

    ObfDereferenceObjectWithTag(a1[6], 'ExWf');  // deref process object
    ObCloseHandle(a1[5], 0);                      // close process handle
    HalPutDmaAdapter(completion_port->DmaAdapter);
    if (!v5) {
        IoFreeMiniCompletionPacket(completion_port->packet);
        ExFreePoolWithTag(a1[2], 0);              // free completion port struct
    }
}
```

---

## 3. ObfDereferenceObjectWithTag Behavior with Controlled Pointer

### Function: ObfDereferenceObjectWithTag (0x1402cb850)

```c
LONG_PTR __stdcall ObfDereferenceObjectWithTag(PVOID Object, ULONG Tag)
{
    // Object header is at Object - 0x30 (48 bytes before body)
    // PointerCount is at header + 0x00 = Object - 48

    // Step 1: Atomically decrement PointerCount
    old_count = _InterlockedExchangeAdd64(
        (volatile signed __int64 *)Object - 6,   // Object - 48 bytes
        0xFFFFFFFFFFFFFFFF                        // -1
    );
    new_count = old_count - 1;

    // Step 2: If still referenced (old_count > 1), just return
    if (new_count > 0)
        return new_count;

    // Step 3: If count dropped to zero, prepare for deletion
    if (*((_QWORD *)Object - 5))           // check header field at Object-40
        KeBugCheckEx(0x18, ...);           // BSOD if invalid header

    if (new_count < 0)                     // underflow check
        KeBugCheckEx(0x18, 0, Object, 2, new_count);  // BSOD

    // Step 4: Defer or execute deletion
    if (high_IRQL || APCs_disabled) {
        ObpDeferObjectDeletion(Object - 48, Tag);  // deferred free
    } else {
        // Handle revocation cleanup
        if (header_flags & 0x40 && ...)
            ObpHandleRevocationBlockRemoveObject();

        // Full deletion: calls DeleteProcedure then frees pool
        ObpRemoveObjectRoutine(Object - 48, 0);
    }
    return new_count;
}
```

### ObpRemoveObjectRoutine (0x14063db60) -- Called when refcount hits 0

```c
__int64 __fastcall ObpRemoveObjectRoutine(__int64 header, char a2)
{
    // Determine OBJECT_TYPE from TypeIndex in header
    type = ObTypeIndexTable[ObHeaderCookie ^ header[24] ^ BYTE1(header)];

    if (type == ObpTypeObjectType)
        KeBugCheckEx(0xF4, ...);     // can't free the type type

    // Call OKProcedure (if present) for quota/security cleanup
    if (header[40]) {
        (*(type->OkProcedure))(header + 48, 2, ...);
    }

    // Call DeleteProcedure (if present)
    if (type->DeleteProcedure) {
        if (!a2)
            header[27] |= 0x80;
        type->DeleteProcedure(header + 48);
    }

    // Free the pool block
    ObpFreeObject(header);
}
```

### With Attacker-Controlled Pointer P

If the thread history slot contains value P (attacker-controlled):

1. **Read**: QWORD at `(P - 48)` is read as `PointerCount`
2. **Write**: `(old_value - 1)` is atomically written to `(P - 48)`
3. **If old_value > 1**: Only effect is atomic decrement at `(P - 48)`. Returns immediately.
4. **If old_value == 1**: Decrements to 0, then attempts full object deletion:
   - Reads `TypeIndex` from `(P - 24)` (header byte 24)
   - Looks up `ObTypeIndexTable[ObHeaderCookie ^ *(P-24) ^ BYTE1(P-48)]`
   - If the type lookup succeeds and has a DeleteProcedure, calls it with `P` as argument
   - Then calls `ObpFreeObject(P - 48)` which frees the pool block
5. **If old_value <= 0**: `KeBugCheckEx(0x18, ...)` -- BSOD

### Primitive Classification

| Property | Controllable? | Value |
|----------|--------------|-------|
| WHERE (address decremented) | YES | `P - 48` (P is the sprayed value) |
| WHAT (value written) | NO | Always `old_value - 1` |
| Number of decrements | UP TO 4 | One per non-zero thread history slot |
| Atomic | YES | `_InterlockedExchangeAdd64` |

**This is a DECREMENT-WHAT-WHERE primitive, not an arbitrary write.**

To decrement a QWORD at target address X:
- Spray value `P = X + 48` into the thread history slot
- `ObfDereferenceObjectWithTag` will atomically decrement QWORD at `X`

---

## 4. Pool Spray Feasibility at LFH Bucket 704

### WorkerFactory Allocation Details
- **Pool type**: NonPagedPoolNx (0x200)
- **Pool tag**: `TpWo` (0x6F577054)
- **Body size**: 576 bytes
- **Total allocation**: 656 (unnamed) or 688 (named)
- **LFH bucket**: 704 (range 641-704)

### Spray Candidates (User-Mode Accessible)

| Primitive | API | Size Control | NonPagedPoolNx? | Feasible? |
|-----------|-----|-------------|-----------------|-----------|
| Named pipe buffers | NtFsControlFile | Yes (buffer size) | Yes | MAYBE -- need 641-704 byte range |
| ALPC messages | NtAlpcSendWaitReceivePort | Yes (message size) | Yes | MAYBE -- depends on total alloc size |
| IoCompletion packets | NtSetIoCompletion | No (~96 bytes) | Yes | NO -- too small |
| ETHREAD | NtCreateThread | No (~832+ bytes) | Yes | NO -- too large |
| KEVENT/KSEMAPHORE | NtCreateEvent/Semaphore | No (~48 bytes) | Yes | NO -- too small |

**Most feasible**: Named pipe buffers or ALPC messages with controlled sizes in the 641-704 byte range. Both allocate from NonPagedPoolNx and can be triggered from user mode.

---

## 5. NtCreateWorkerFactory User-Mode Accessibility

### Requirements
1. **IO Completion Port handle** with WRITE access (0x2)
   - Create via `CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0)` from user mode
2. **Process handle** with access 0x2A to the **current process**
   - `GetCurrentProcess()` returns a handle with FULL_ACCESS
   - Or `OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | ...)`
   - Must be the calling process (enforced: `ApcState.Process != v30 -> STATUS_ACCESS_DENIED`)
3. **No special privileges required** -- no SeDebugPrivilege, no admin token needed

### Verdict
**NtCreateWorkerFactory IS callable from any unprivileged user-mode process.**
The only requirements are a self-process handle and an IO completion port, both obtainable without elevation.

### Close Path Accessibility
- **Path 1**: `NtClose(handle)` -> `ObpCloseHandle` -> `ExpCloseWorkerFactory` -> `ExpShutdownWorkerFactory`
- **Path 2**: `NtShutdownWorkerFactory(handle, &count)` -> `ExpShutdownWorkerFactory` -> `ExWaitForRundownProtectionRelease`
- Both are callable from user mode.

---

## 6. Exploit Chain Analysis

### The Claimed Vulnerability (UNINITIALIZED BYTES) -- DOES NOT EXIST

The previous subagent claimed that offsets 72-103 are "32 completely uninitialized bytes" that could contain attacker-controlled pointers from pool spray. **This is incorrect.**

**Evidence:**
1. `ExpInitializeThreadHistory` (0x14035a764) uses two 128-bit SSE stores to zero offsets 72-103:
   - `movups xmmword ptr [rcx+48h], xmm0` -> zeros bytes 72-87
   - `movups xmmword ptr [rcx+58h], xmm0` -> zeros bytes 88-103
2. This function is called at step 7 of 12 in `NtCreateWorkerFactory`, BEFORE:
   - The timer is started (step 11: `KeSetTimer2`)
   - The handle is created (step 12: `ObInsertObject`)
3. No external code can access the object before `ObInsertObject` creates the handle.
4. No field assignments between `ObCreateObject` (step 1) and `ExpInitializeThreadHistory` (step 7) read from offsets 72-103.
5. `ObCreateObject` -> `ObpAllocateObject` uses `ExAllocatePoolWithTag` which does NOT zero the body, but the thread history is explicitly zeroed before use.

### Thread History Lifecycle (Properly Managed)

1. **Creation**: `ExpInitializeThreadHistory` zeroes all 4 slots
2. **Thread registration**: `NtWaitForWorkViaWorkerFactory` adds current `KTHREAD*` to a free slot:
   - Calls `ObfReferenceObjectWithTag(KTHREAD, 'Dflt')` (increment ref)
   - Stores pointer in slot at offset `72 + 8*index`
   - If all 4 slots full, evicts oldest entry (deref old, store new, advance round-robin index)
3. **Thread timeout**: `ExpRemoveCurrentThreadFromThreadHistory` removes current thread:
   - Calls `ObfDereferenceObjectWithTag(KTHREAD, 'Dflt')` (decrement ref)
   - Zeros the slot
4. **Close**: `ExpShutdownWorkerFactory` iterates all 4 slots:
   - Calls `ObfDereferenceObjectWithTag(KTHREAD, 'Dflt')` for each non-zero slot
   - Zeros each slot after dereferencing
   - All operations under the WorkerFactory spin lock

**No double-free, no UAF, no race condition in the normal lifecycle.** All add/remove/close operations are serialized by the spin lock.

### Hypothetical Exploit (IF bytes were uninitialized -- they are NOT)

IF the bytes at 72-103 were truly uninitialized (which they are NOT), the exploit chain would be:

1. **Spray**: Fill NonPagedPoolNx LFH bucket 704 with controlled data
   - Place target address `P = X + 48` at the offset that will become body offset 72
   - Use named pipe buffers or ALPC messages (641-704 byte allocations)
2. **Free spray**: Release enough allocations to create LFH vacancies
3. **Create WorkerFactory**: `NtCreateWorkerFactory` allocates from bucket 704
   - `ObCreateObject` -> body has residual spray data at offsets 72-103
   - (In reality, `ExpInitializeThreadHistory` zeroes these before use)
4. **Close WorkerFactory**: `NtClose(handle)` triggers `ExpShutdownWorkerFactory`
   - Iterates 4 QWORDs at offsets 72-103
   - For each non-zero value, calls `ObfDereferenceObjectWithTag(value, 'Dflt')`
5. **Effect**: Atomic decrement of QWORD at `(P - 48) = X`
   - If `*X` was 1: drops to 0 -> triggers `ObpRemoveObjectRoutine` -> calls DeleteProcedure -> frees pool
   - If `*X` was > 1: just decrements, object stays alive
   - If `*X` was <= 0: `KeBugCheckEx` -> BSOD

**This would give a decrement-what-where primitive (not arbitrary write):**
- **WHERE**: controllable (X, via spray value P = X + 48)
- **WHAT**: uncontrollable (always old_value - 1)
- **Up to 4 decrements** per WorkerFactory close
- Could be used to decrement a refcount to 0 -> UAF, or decrement a counter

**BUT THIS EXPLOIT IS NOT POSSIBLE because ExpInitializeThreadHistory zeroes the bytes.**

### Alternative Attack Vectors (Also Analyzed)

1. **Race condition during close**: Thread history is always accessed under the WorkerFactory spin lock. No race possible between add/remove/close.

2. **Double dereference**: `ExpRemoveCurrentThreadFromThreadHistory` zeros the slot after dereferencing. `ExpShutdownWorkerFactory` checks for non-zero before dereferencing. No double-deref possible.

3. **Pool reuse after free**: The close path zeros all slots. The delete callback (`ExpDeleteWorkerFactory`) properly cleans up the completion port struct. No stale pointers remain.

4. **ObCreateObject body not zeroed**: While `ObpAllocateObject` does NOT zero the body (uses `ExAllocatePoolWithTag`, not the zeroing variant), the critical thread history region is explicitly zeroed by `ExpInitializeThreadHistory` before the object handle is created.

---

## 7. Python Calculations

```
Body size: 576 bytes (0x240)
Object header (unnamed): 80 bytes (48 base + 32 name_info)
Object header (named): 112 bytes (48 base + 32 name_info + 32 creator_info)

Unnamed total: 80 + 576 = 656 bytes -> LFH bucket 704 (waste = 48)
Named total: 112 + 576 = 688 bytes -> LFH bucket 704 (waste = 16)

Uninitialized region (claimed): bytes 72-103 (32 bytes, 4 QWORDs)
  QWORD[9]  at offset 72  -> ThreadHistory[0]
  QWORD[10] at offset 80  -> ThreadHistory[1]
  QWORD[11] at offset 88  -> ThreadHistory[2]
  QWORD[12] at offset 96  -> ThreadHistory[3]

Close path iteration: Object+9 (QWORD ptr math) = byte offset 72
  Iterations: 4 (one per QWORD)
  Each iteration: if non-zero -> ObfDereferenceObjectWithTag(slot, 'Dflt')

ExpInitializeThreadHistory zeroing:
  xmm0 = 0 (128-bit zero)
  [rcx+0x48] = xmm0  -> bytes 72-87  (ThreadHistory[0..1])
  [rcx+0x58] = xmm0  -> bytes 88-103 (ThreadHistory[2..3])
  Total: 32 bytes zeroed, matching exactly the 4 QWORDs in the close path

PoolType: 0x200 (NonPagedPoolNx) -- from OBJECT_TYPE_INITIALIZER byte 36
DefaultNonPagedPoolCharge: 576 + 88 = 664 -- body + header overhead charge
Pool tag: 'TpWo' (0x6F577054) -- from type name "TpWorkerFactory"

ObfDereferenceObjectWithTag with pointer P:
  Decrements QWORD at (P - 48) by 1
  If result == 0: calls ObpRemoveObjectRoutine(P - 48) -> DeleteProcedure(P) -> ObpFreeObject(P - 48)
  If result < 0: KeBugCheckEx (BSOD)
  If result > 0: returns immediately (just the decrement)
```

---

## 8. Functions Analyzed

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| NtCreateWorkerFactory | 0x140701630 | 0x36b | Syscall entry, creates WorkerFactory |
| ExpWorkerFactoryCheckCreate | 0x140242860 | 0x40f | Thread creation logic |
| ExpShutdownWorkerFactory | 0x1403489e8 | 0x15e | Close path -- iterates thread history |
| ExpCloseWorkerFactory | 0x1406f0300 | 0x18 | Close callback -> calls ExpShutdown |
| ExpDeleteWorkerFactory | 0x1402dd850 | 0x9b | Delete callback -- frees resources |
| ExpWorkerFactoryInitialization | 0x140a71a20 | 0x1be | Type init, creates object type |
| ExpInitializeThreadHistory | 0x14035a764 | 0x13 | *** ZEROES offsets 72-103 *** |
| ExpCheckThreadHistory | 0x140311ef0 | 0x166 | Reads thread history for scheduling |
| ExpRemoveCurrentThreadFromThreadHistory | 0x140317adc | 0x52 | Removes thread, derefs, zeros slot |
| NtWaitForWorkViaWorkerFactory | 0x140203110 | 0x1276 | Worker wait -- adds threads to history |
| NtShutdownWorkerFactory | 0x140323380 | 0x122 | Shutdown syscall |
| ObfDereferenceObjectWithTag | 0x1402cb850 | -- | Atomic refcount decrement |
| ObpRemoveObjectRoutine | 0x14063db60 | -- | Object deletion when refcount=0 |
| ObpAllocateObject | 0x14064c950 | -- | Object allocation (does NOT zero body) |
| ObCreateObjectTypeEx | 0x1407906a0 | -- | Type creation, stores PoolType at +100 |

---

## 9. Conclusion

**The WorkerFactory "uninitialized bytes" vulnerability at offsets 72-103 does NOT exist.** The bytes are properly zeroed by `ExpInitializeThreadHistory` before the object becomes accessible via a handle. The thread history is properly managed with matched ref/deref pairs under the WorkerFactory spin lock throughout the object lifecycle.

**If** the bytes were uninitialized (hypothetically), the close path would provide a **decrement-what-where primitive** (not arbitrary write) via `ObfDereferenceObjectWithTag`:
- WHERE: controllable via pool spray (P - 48, where P is the sprayed value)
- WHAT: uncontrollable (always old_value - 1)
- Up to 4 decrements per close
- Could potentially be used for refcount manipulation -> UAF

`NtCreateWorkerFactory` and the close paths (`NtClose`, `NtShutdownWorkerFactory`) are callable from unprivileged user mode. Pool spray at LFH bucket 704 in NonPagedPoolNx is feasible via named pipe buffers or ALPC messages.

The vulnerability class is correctly identified (type confusion / uninitialized object dereference in close path), but the specific claim of uninitialized bytes at offsets 72-103 is refuted by the presence of `ExpInitializeThreadHistory` in the creation path.
