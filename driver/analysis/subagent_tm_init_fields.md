# _KTM Field Initialization Analysis - TmInitializeTransactionManager

## Binary: tm.sys (KTM Implementation Driver)
## IDA Instance: PID 2944, Port 13337
## Date: 2026-07-02

---

## EXECUTIVE SUMMARY

**CRITICAL FINDING: Both LsnOrderedList (0x238) and RestartOrderedList (0x390) ARE initialized by TmInitializeTransactionManagerExt with self-pointing links (InitializeListHead equivalent).**

The original exploit hypothesis -- using uninitialized LIST_ENTRY fields for RemoveEntryList corruption during KTM close -- does NOT work for these specific fields. Both list entries are properly initialized before any close/delete path can execute.

However, **159 bytes of the 960-byte _KTM body remain uninitialized** with stale pool data, including a **72-byte gap at body offset 0x2C8-0x30F** that IS read by TmpCheckpoint (at offset 0x2E8) during the TmpTmOffline call in both Close and Delete paths.

---

## 1. FUNCTION MAP

| Function | Address | Size | Role |
|----------|---------|------|------|
| TmInitializeTransactionManagerExt | 0x1C001A820 | 0x3F2 | Main init (exported as TmInitializeTransactionManager) |
| TmpTransactionManagerInitialization | 0x1C00248C4 | 0xE3 | ObCreateObjectType registration (sets Close/Delete procedures) |
| NtCreateTransactionManagerExt | 0x1C001EBF0 | 0x328 | NtCreateTransactionManager syscall (calls ObCreateObject + init) |
| TmpCloseTransactionManager | 0x1C001B0E0 | 0xC7 | CloseProcedure (ObjectType callback) |
| TmpDeleteTransactionManager | 0x1C001B800 | 0x127 | DeleteProcedure (ObjectType callback) |
| TmpTmOffline | 0x1C001D250 | 0x1C8 | Offline transition (called in both Close and Delete) |
| TmpTmOnline | 0x1C001D420 | 0x60 | Online transition |
| TmpCheckpoint | 0x1C000C690 | ~0xB5E | Checkpoint logic (called from TmpTmOffline) |
| TmpNamespaceInitialize | 0x1C00221A4 | 0x64 | Namespace AVL table + mutex init (always returns 0) |

### Object Type Registration (TmpTransactionManagerInitialization)

```
Object type name: "TmTm"
Body size: 960 bytes (0x3C0)
Pool type: 256 (NonPagedPoolNx)
CloseProcedure: TmpCloseTransactionManager (0x1C001B0E0)
DeleteProcedure: TmpDeleteTransactionManager (0x1C001B800)
OpenProcedure: TmpOpenTransactionManager (0x1C000C610)
InitializeProcedure: NONE (zeroed in OBJECT_TYPE_INITIALIZER)
```

**KEY: No InitializeProcedure is set. ObCreateObject does NOT zero the body. The body retains stale pool data until TmInitializeTransactionManagerExt initializes specific fields.**

---

## 2. CALL CHAIN: Object Creation

```
NtCreateTransactionManagerExt (0x1C001EBF0)
  |
  |-- ObCreateObject(..., 960, ..., &TransactionManager)
  |     Allocates 960-byte body from NonPagedPoolNx. Body NOT zeroed.
  |
  |-- *((_DWORD *)TransactionManager + 16) = 0    // Pre-set state at +0x40 = 0
  |
  |-- TmInitializeTransactionManagerExt(TransactionManager, LogFileName, NULL, CreateOptions)
  |     Initializes specific fields (see Section 3)
  |     On failure: sets state=4, goto LABEL_9, returns error
  |
  |-- If init FAILS:
  |     ObfDereferenceObject(TransactionManager)
  |       -> TmpDeleteTransactionManager (DeleteProcedure)
  |            -> checks state at +0x40 (value=4, non-zero, enters cleanup)
  |            -> TmpTmOffline
  |            -> iterates RestartOrderedList at +0x390
  |
  |-- If init SUCCEEDS:
  |     ObInsertObject(TransactionManager, ...)
  |     *TmHandle = Handle
```

**CRITICAL: TmpNamespaceInitialize always returns 0 (success). The error path (LABEL_9) is only reachable AFTER both list entries are initialized (steps 33-39 in Section 3). Failures from TmpTmOnline, TmpCreateOrOpenLogTransactionManager, ZwCreateResourceManager, ObReferenceObjectByHandle, or TmpNamespaceInsert all occur after RestartOrderedList is initialized.**

---

## 3. COMPLETE FIELD INITIALIZATION MAP

### Verified from disassembly at 0x1C001A820

| Step | Body Offset | Size | Method | Value | Initialized? |
|------|-------------|------|--------|-------|--------------|
| 1 | 0x000 | 4 | mov dword ptr [rcx], 0B00B0004h | 0xB00B0004 | YES |
| 2 | 0x008 | 56 | KeInitializeMutex(rcx+8, 0) | Mutex | YES |
| 3 | 0x040 | 4 | mov dword ptr [rbx+40h], 1 | 1 | YES |
| 4 | 0x048 | 8 | mov [rbx+48h], r15 (r15=0) | 0 | YES (first QWORD of NamespaceLink only) |
| 5 | 0x068 | 1 | mov [rbx+68h], r15b | 0 | YES |
| 6 | 0x070 | 16 | movdqu [rbx+70h], xmm0 (from TmId) or ExUuidCreate | GUID | YES |
| 7 | 0x080 | 8 | mov [rbx+80h], r15 (r15=0) | 0 (flags) | YES |
| 8 | 0x088 | 2 | mov [r12], r15w (r12=rbx+0x88) | 0 | YES |
| 9 | 0x08A | 2 | mov [rbx+8Ah], r15w | 0 | YES |
| 10 | 0x090 | 8 | mov [rbx+90h], r15 | 0 | YES |
| 11 | 0x098 | 8 | mov [rbx+98h], r15 | 0 | YES |
| 12 | 0x0A0 | 8 | mov [rbx+0A0h], r15 | 0 | YES |
| 13 | 0x0A8 | 8 | mov [rbx+0A8h], r15 | 0 | YES |
| 14 | 0x0B0 | 168 | TmpNamespaceInitialize(rbx+0xB0) | Transactions namespace | YES (see 3a) |
| 15 | 0x158 | 168 | TmpNamespaceInitialize(rbx+0x158) | ResourceManagers namespace | YES (see 3a) |
| 16 | 0x200 | 56 | KeInitializeMutex(rbx+0x200, 0) | LsnOrderedMutex | YES |
| 17 | 0x238 | 8 | mov [rax], rax (rax=rbx+0x238) | self (Flink) | **YES - LsnOrderedList INITIALIZED** |
| 18 | 0x240 | 8 | mov [rax+8], rax (rax=rbx+0x238) | self (Blink) | **YES - LsnOrderedList INITIALIZED** |
| 19 | 0x248 | 8 | mov [rbx+248h], rdi (rdi=1) | 1 | YES |
| 20 | 0x250 | 4 | mov [rbx+250h], edi (edi=1) | 1 | YES |
| 21 | 0x258 | 8 | mov [rbx+258h], r15 (r15=0) | 0 | YES |
| 22 | 0x260 | 4 | mov [rbx+260h], r15d | 0 | YES |
| 23 | 0x268 | 24 | KeInitializeEvent(rbx+0x268, SynchronizationEvent, 0) | Event | YES |
| 24 | 0x288 | 8 | mov [rbx+288h], CLFS_LSN_NULL | NULL | YES |
| 25 | 0x290 | 8 | mov [rbx+290h], CLFS_LSN_NULL | NULL | YES |
| 26 | 0x298 | 8 | mov [rbx+298h], CLFS_LSN_NULL | NULL | YES |
| 27 | 0x2A0 | 8 | mov [r15], rdi (r15=rbx+0x2A0, rdi=0) | 0 | YES |
| 28 | 0x2A8 | 8 | mov [rbx+2A8h], rdi (rdi=0) | 0 | YES |
| 29 | 0x2B0 | 24 | KeInitializeEvent(rbx+0x2B0, NotificationEvent, 1) | Event | YES |
| 30 | 0x310 | 104 | ExInitializeResourceLite(rbx+0x310) | ERESOURCE | YES |
| 31 | 0x378 | 4 | mov [rbx+378h], r15d | 0 | YES |
| 32 | 0x37C | 8 | mov [rbx+37Ch], rdi (rdi=0) | 0 | YES |
| 33 | 0x388 | 8 | mov [rbx+388h], CLFS_LSN_NULL | NULL | YES |
| 34 | 0x390 | 8 | mov [rax], rax (rax=rbx+0x390) | self (Flink) | **YES - RestartOrderedList INITIALIZED** |
| 35 | 0x398 | 8 | mov [rax+8], rax (rax=rbx+0x390) | self (Blink) | **YES - RestartOrderedList INITIALIZED** |

### 3a. Namespace Initialization Detail (TmpNamespaceInitialize)

TmpNamespaceInitialize at 0x1C00221A4 initializes:
1. Selected fields of RTL_AVL_TABLE (104 bytes) via RtlInitializeGenericTableAvl
2. KeInitializeMutex at Table[1] (offset +104 within namespace, 56 bytes)

Namespace layout (168 bytes total):
- Bytes 0-103: RTL_AVL_TABLE (104 bytes) -- initialized by RtlInitializeGenericTableAvl
- Bytes 104-159: _KMUTANT (56 bytes) -- initialized by KeInitializeMutex
- Bytes 160-167: **8 bytes UNINITIALIZED**

| Namespace | Body Offset | AVL Range | Mutex Range | Uninit Range |
|-----------|-------------|-----------|-------------|--------------|
| Transactions | 0x0B0 | 0x0B0-0x117 | 0x118-0x14F | **0x150-0x157** |
| ResourceManagers | 0x158 | 0x158-0x1BF | 0x1C0-0x1F7 | **0x1F8-0x1FF** |

---

## 4. UNINITIALIZED FIELDS (Stale Pool Data)

### Complete Map of Uninitialized Body Ranges

| Body Offset Range | Size | Pool Offset Range | Description |
|-------------------|------|-------------------|-------------|
| 0x004-0x007 | 4 | 0x034-0x037 | Between state DWORD (0x000) and Mutex (0x008) |
| 0x044-0x047 | 4 | 0x074-0x077 | Between state2 DWORD (0x040) and NamespaceLink QWORD (0x048) |
| 0x050-0x067 | 24 | 0x080-0x097 | Rest of NamespaceLink after first QWORD (40-byte struct, only 8 bytes zeroed) |
| 0x069-0x06F | 7 | 0x099-0x09F | Between byte field (0x068) and GUID (0x070) |
| 0x08C-0x08F | 4 | 0x0BC-0x0BF | Between WORD fields (0x088-0x08B) and QWORD (0x090) |
| 0x150-0x157 | 8 | 0x180-0x187 | Transactions namespace tail (after AVL+Mutex) |
| 0x1F8-0x1FF | 8 | 0x228-0x22F | ResourceManagers namespace tail (after AVL+Mutex) |
| 0x280-0x287 | 8 | 0x2B0-0x2B7 | Between KeInitializeEvent #1 end (0x280) and CLFS_LSN (0x288) |
| **0x2C8-0x30F** | **72** | **0x2F8-0x33F** | **Between KeInitializeEvent #2 (0x2C8) and ERESOURCE (0x310) -- LARGEST GAP** |
| 0x384-0x387 | 4 | 0x3B4-0x3B7 | Between QWORD=0 (0x37C-0x383) and CLFS_LSN (0x388) |
| 0x3A0-0x3BF | 32 | 0x3D0-0x3EF | After RestartOrderedList (0x390-0x39F) to end of body (0x3C0) |

**Total uninitialized: 159 bytes out of 960 (16.6%)**

Pool offset = body offset + 0x30 (48-byte OBJECT_HEADER)

---

## 5. CLOSE/DELETE PATH ANALYSIS

### 5a. TmpCloseTransactionManager (CloseProcedure at 0x1C001B0E0)

Only executes if a4 == 1 (PreviousMode == KernelMode).
- Calls TmpTmOffline(a2)
- KeWaitForSingleObject on Mutex at +0x008 -- INITIALIZED
- Reads/saves handles at +0x2A0, +0x2A8 -- INITIALIZED (zeroed)
- KeReleaseMutex on +0x008 -- INITIALIZED
- ZwClose/ObfDereferenceObject on saved handles

**RemoveEntryList calls: NONE**
**Uninitialized field accesses: NONE**

### 5b. TmpDeleteTransactionManager (DeleteProcedure at 0x1C001B800)

- Checks state at +0x040 -- INITIALIZED (must be non-zero to enter cleanup)
- Sets flag at +0x080 -- INITIALIZED
- Calls TmpTmOffline (see 5c)
- CLFS cleanup at +0x0A8, +0x0A0, +0x098 -- all INITIALIZED (zeroed, skipped)
- RtlFreeUnicodeString on +0x088 if non-volatile and filename exists -- INITIALIZED
- **RestartOrderedList iteration at +0x390/+0x398:**
  - Reads Flink at +0x390 -- INITIALIZED (self-pointing)
  - While loop: `v5 != (QWORD*)(a1 + 912)` -- self-pointing means empty list, loop SKIPPED
  - If list had entries: manual RemoveEntryList + ExFreePoolWithTag + __fastfail(3) on corruption
- ExDeleteResourceLite at +0x310 -- INITIALIZED

**RemoveEntryList calls: Only on RestartOrderedList (0x390) -- INITIALIZED, list is empty, loop skipped**
**Uninitialized field accesses: NONE**

### 5c. TmpTmOffline (0x1C001D250) -- Called from both Close and Delete

- KeWaitForSingleObject on Mutex +0x008 -- INITIALIZED
- Checks state at +0x040 -- INITIALIZED
- If state != 5 (not already offline):
  - If !(flags & 1): calls TmpCheckpoint (see 5d)
  - Sets state to 5
  - TmpNamespaceExpire at +0x158 -- INITIALIZED
  - TmpNamespaceForEach at +0x158 and +0x0B0 -- INITIALIZED
  - ExAcquireResourceExclusiveLite at +0x310 -- INITIALIZED
  - CLFS cleanup at +0x0A8, +0x0A0, +0x098 -- INITIALIZED (zeroed)
  - ExReleaseResourceLite at +0x310 -- INITIALIZED
  - Reads +0x048 (NamespaceLink first QWORD) -- INITIALIZED (zeroed, skips TmpNamespaceRemove)
  - KeReleaseMutex at +0x008 -- INITIALIZED

**RemoveEntryList calls: NONE directly**
**Uninitialized field accesses: Indirectly via TmpCheckpoint (see 5d)**

### 5d. TmpCheckpoint (0x1C000C690) -- Called from TmpTmOffline

**Critical instruction at 0x1C000CCB4:**
```asm
mov rax, [rbx+2E8h]    ; READS UNINITIALIZED DATA at body offset 0x2E8
```

This reads 8 bytes from the **72-byte uninitialized gap (0x2C8-0x30F)** and uses the value as a CLFS_LSN (BaseLsn). The value is used in:
- ClfsLsnLess comparison (value comparison, NOT pointer dereference)
- Passed to TmpWriteRestartArea as part of checkpoint data

**This is a READ of controlled stale pool data, but it is used as a value (LSN), not as a pointer for list operations.**

Other TmpCheckpoint field accesses (all INITIALIZED):
- +0x080 flags, +0x040 state (must be 3=online), +0x310 ERESOURCE
- +0x008 Mutex, +0x378 flags, +0x0A0 CLFS marshalling, +0x098 log file object
- +0x200 LsnOrderedMutex, +0x238 LsnOrderedList (empty check)
- +0x398 RestartOrderedList.Blink (used to compute pointer to CLFS_LSN at +0x388)
- +0x390 RestartOrderedList (iterated, empty list skips loop)
- +0x084 flags, +0x288/+0x28C CLFS_LSN values
- **+0x2E8 -- UNINITIALIZED** (read as CLFS_LSN value, only when state==3 and a2==true)

**IMPORTANT: TmpCheckpoint only proceeds if state at +0x040 == 3 (online). If the TM was never brought online (state = 1 or 4 from error path), TmpCheckpoint returns early with STATUS_UNSUCCESSFUL and does NOT read +0x2E8.**

---

## 6. REMOVE ENTRY LIST ANALYSIS

### All RemoveEntryList-equivalent operations in close/delete paths:

| Function | LIST_ENTRY Field | Body Offset | Initialized? | Safe? |
|----------|-----------------|-------------|--------------|-------|
| TmpDeleteTransactionManager | RestartOrderedList | 0x390/0x398 | YES (self-pointing) | YES (empty list, loop skipped) |
| TmpCheckpoint | RestartOrderedList (iter) | 0x390/0x398 | YES (self-pointing) | YES (empty list, loop skipped) |
| TmpCheckpoint | LsnOrderedList (iter) | 0x238/0x240 | YES (self-pointing) | YES (empty list check) |
| TmpCloseTransactionManager | (none) | N/A | N/A | N/A |
| TmpTmOffline | (none) | N/A | N/A | N/A |

**RESULT: ZERO RemoveEntryList calls target uninitialized LIST_ENTRY fields.**

---

## 7. NtClose HANDLE TRACE

```
NtClose(handle)
  -> ObpCloseHandle
    -> ObpDecrementHandleCount
      -> ObjectType->CloseProcedure = TmpCloseTransactionManager
           - Calls TmpTmOffline (if PreviousMode == KernelMode)
           - Waits on Mutex at +0x008
           - Reads/saves handles at +0x2A0, +0x2A8
           - Releases Mutex
           - ZwClose/ObfDereferenceObject on saved handles
           - NO RemoveEntryList
    -> (if last handle) ObfDereferenceObject
      -> ObjectType->DeleteProcedure = TmpDeleteTransactionManager
           - Checks state at +0x040
           - Calls TmpTmOffline
           - CLFS cleanup (all fields zeroed, skipped)
           - RtlFreeUnicodeString (if non-volatile and filename exists)
           - Iterates RestartOrderedList at +0x390 (INITIALIZED, empty, skipped)
           - ExDeleteResourceLite at +0x310
           - RemoveEntryList on RestartOrderedList entries: ONLY if list non-empty
```

**Close vs Delete distinction:**
- **Close** (TmpCloseTransactionManager): No RemoveEntryList at all. Only mutex wait/release and handle cleanup.
- **Delete** (TmpDeleteTransactionManager): RemoveEntryList on RestartOrderedList entries, but list is initialized to empty (self-pointing). The manual unlink loop at 0x1C001B8C1 only executes if entries were added to the list during TM lifetime.

---

## 8. ANSWERS TO SPECIFIC QUESTIONS

### Q: Does the init code call InitializeListHead on LsnOrderedList (0x238)?
**A: YES.** Inline equivalent at 0x1C001A9B8-0x1C001A9CF:
```asm
lea rax, [rbx+238h]    ; rax = andLsnOrderedList
mov [rax+8], rax        ; Blink = andself
mov [rax], rax          ; Flink = andself
```

### Q: Does it call InitializeListHead on RestartOrderedList (0x390)?
**A: YES.** Inline equivalent at 0x1C001A9F8-0x1C001AA03:
```asm
lea rax, [rbx+390h]    ; rax = andRestartOrderedList
mov [rax+8], rax        ; Blink = andself
mov [rax], rax          ; Flink = andself
```

### Q: Does it call KeInitializeMutant on Mutex (0x008)?
**A: YES.** KeInitializeMutex(rbx+8, 0) at 0x1C001A866.

### Q: Does it call KeInitializeMutant on LsnOrderedMutex (0x200)?
**A: YES.** KeInitializeMutex(rbx+200h, 0) at 0x1C001A9AC.

### Q: Does it initialize NamespaceLink (0x048)?
**A: PARTIALLY.** Only the first QWORD (8 bytes) at +0x048 is zeroed. The remaining 32 bytes of the 40-byte _KTMOBJECT_NAMESPACE_LINK (0x050-0x067) are NOT initialized. If TmInitializeTransactionManagerExt succeeds, TmpNamespaceInsert is called which likely initializes the full NamespaceLink. If it fails, TmpTmOffline only reads the first QWORD (zeroed) and skips TmpNamespaceRemove.

### Q: Does it initialize Transactions namespace (0x0B0)?
**A: YES** (160 of 168 bytes). TmpNamespaceInitialize initializes RTL_AVL_TABLE (104 bytes) + _KMUTANT (56 bytes). Remaining 8 bytes (0x150-0x157) are NOT initialized.

### Q: Does it initialize ResourceManagers namespace (0x158)?
**A: YES** (160 of 168 bytes). Same as above. Remaining 8 bytes (0x1F8-0x1FF) are NOT initialized.

### Q: Does it zero the entire body?
**A: NO.** Only specific fields are initialized. 159 bytes remain uninitialized with stale pool data.

---

## 9. EXPLOIT IMPACT ASSESSMENT

### What DOES NOT work:
- **Uninitialized LsnOrderedList (0x238)**: INITIALIZED -- cannot use stale Flink/Blink for list corruption
- **Uninitialized RestartOrderedList (0x390)**: INITIALIZED -- cannot use stale Flink/Blink for list corruption
- **RemoveEntryList on uninitialized LIST_ENTRY**: No such path exists in close/delete handlers

### What MIGHT work:

#### Option A: TmpCheckpoint read of +0x2E8 (value, not pointer)
- **Body offset**: 0x2E8 (pool offset 0x318)
- **Size**: 8 bytes
- **Type**: CLFS_LSN (value, used in comparisons)
- **Condition**: TM must be in online state (state == 3) for TmpCheckpoint to proceed
- **Impact**: Controlled LSN value could influence checkpoint behavior (TmpWriteRestartArea), but this is a VALUE not a POINTER. No direct code execution path identified.
- **Uninitialized gap**: 0x2C8-0x30F (72 bytes) -- all controlled

#### Option B: NamespaceLink tail (0x050-0x067, 24 bytes)
- Only the first QWORD at +0x048 is zeroed. If TM init fails BEFORE TmpNamespaceInsert, the rest of the NamespaceLink has stale data. But TmpTmOffline only checks the first QWORD (zeroed) and skips namespace removal.

#### Option C: Namespace tail bytes (0x150-0x157, 0x1F8-0x1FF)
- 8 bytes each. Would need to find code that reads these specific offsets. TmpNamespaceForEach and TmpNamespaceExpire operate on the AVL table and mutex, not the tail bytes.

#### Option D: End-of-body gap (0x3A0-0x3BF, 32 bytes)
- Beyond RestartOrderedList. Would need to find code that accesses these offsets. No close/delete path accesses this range.

#### Option E: Different KTM object type
- Transaction (_KTRANSACTION), ResourceManager (_KRESOURCEMANAGER), or Enlistment (_KENLISTMENT) objects might have different initialization patterns with uninitialized LIST_ENTRY fields that DO get RemoveEntryList'd during close.
- **RECOMMENDED: Analyze TmpInitializeTransaction, TmpResourceManagerInitialization, and TmpInitializeEnlistment for the same pattern.**

#### Option F: Race condition
- If a handle can be closed WHILE TmInitializeTransactionManagerExt is still executing (before step 34/35 initializes RestartOrderedList), the delete path would see uninitialized data at +0x390. This requires a race window between ObCreateObject and the list init at step 34. However, the caller in NtCreateTransactionManagerExt sets state=0 before calling init, and TmpDeleteTransactionManager checks if (state != 0). During init, state is set to 1 at step 3, then to 4 on error. The only way state is 0 during delete is if TmInitializeTransactionManagerExt has not executed step 3 yet -- an extremely tight race that may not be winnable.

#### Option G: Post-init corruption
- If a separate write primitive exists (e.g., heap overflow from adjacent object), corrupting the RestartOrderedList at +0x390/+0x398 AFTER initialization but BEFORE close would cause TmpDeleteTransactionManager to iterate a corrupted list, hitting the __fastfail(3) check or following attacker-controlled Flink/Blink pointers.

---

## 10. POOL SPRAY OFFSET REFERENCE

For LFH bucket 1024 with 48-byte object header:

| Body Offset | Pool Offset | Field | Init Status | Spray Control? |
|-------------|-------------|-------|-------------|----------------|
| 0x000 | 0x030 | State/Magic | YES (0xB00B0004) | No |
| 0x008 | 0x038 | Mutex | YES (KeInitializeMutex) | No |
| 0x040 | 0x070 | State2 | YES (1) | No |
| 0x048 | 0x078 | NamespaceLink[0] | YES (0) | No |
| 0x050 | 0x080 | NamespaceLink[8-39] | **NO** | **YES (24 bytes)** |
| 0x068 | 0x098 | Byte field | YES (0) | No |
| 0x070 | 0x0A0 | TmId GUID | YES | No |
| 0x080 | 0x0B0 | Flags | YES (0) | No |
| 0x088 | 0x0B8 | UNICODE_STRING | YES | No |
| 0x090 | 0x0C0 | LogFileName buf | YES (0) | No |
| 0x098 | 0x0C8 | CLFS pointers | YES (0) | No |
| 0x0A0 | 0x0D0 | CLFS pointers | YES (0) | No |
| 0x0A8 | 0x0D8 | CLFS pointers | YES (0) | No |
| 0x0B0 | 0x0E0 | Tx Namespace | YES | No |
| 0x150 | 0x180 | Tx NS tail | **NO** | **YES (8 bytes)** |
| 0x158 | 0x188 | RM Namespace | YES | No |
| 0x1F8 | 0x228 | RM NS tail | **NO** | **YES (8 bytes)** |
| 0x200 | 0x230 | LsnOrderedMutex | YES | No |
| 0x238 | 0x268 | LsnOrderedList.Flink | **YES (self)** | No |
| 0x240 | 0x270 | LsnOrderedList.Blink | **YES (self)** | No |
| 0x248 | 0x278 | QWORD | YES (1) | No |
| 0x250 | 0x280 | DWORD | YES (1) | No |
| 0x258 | 0x288 | QWORD | YES (0) | No |
| 0x260 | 0x290 | DWORD | YES (0) | No |
| 0x268 | 0x298 | KeInitializeEvent #1 | YES | No |
| 0x280 | 0x2B0 | Gap | **NO** | **YES (8 bytes)** |
| 0x288 | 0x2B8 | CLFS_LSN | YES (NULL) | No |
| 0x290 | 0x2C0 | CLFS_LSN | YES (NULL) | No |
| 0x298 | 0x2C8 | CLFS_LSN | YES (NULL) | No |
| 0x2A0 | 0x2D0 | QWORD (handle) | YES (0) | No |
| 0x2A8 | 0x2D8 | QWORD (obj ptr) | YES (0) | No |
| 0x2B0 | 0x2E0 | KeInitializeEvent #2 | YES | No |
| **0x2C8** | **0x2F8** | **BIG GAP START** | **NO** | **YES** |
| **0x2E8** | **0x318** | **Read by TmpCheckpoint** | **NO** | **YES (8 bytes)** |
| **0x30F** | **0x33F** | **BIG GAP END** | **NO** | **YES (72 bytes total)** |
| 0x310 | 0x340 | ERESOURCE | YES | No |
| 0x378 | 0x3A8 | DWORD | YES (0) | No |
| 0x37C | 0x3AC | QWORD | YES (0) | No |
| 0x384 | 0x3B4 | Gap | **NO** | **YES (4 bytes)** |
| 0x388 | 0x3B8 | CLFS_LSN | YES (NULL) | No |
| 0x390 | 0x3C0 | RestartOrderedList.Flink | **YES (self)** | **No** |
| 0x398 | 0x3C8 | RestartOrderedList.Blink | **YES (self)** | **No** |
| 0x3A0 | 0x3D0 | End-of-body gap | **NO** | **YES (32 bytes)** |

**Total controllable stale bytes: 159 bytes across 9 ranges**

---

## 11. RECOMMENDATIONS

1. **LsnOrderedList and RestartOrderedList are NOT viable exploit targets** -- both are initialized with self-pointing links before any close/delete path can execute.

2. **The 72-byte gap at 0x2C8-0x30F is the most interesting uninitialized region** -- TmpCheckpoint reads 8 bytes at +0x2E8, but only when TM is online (state==3) and only as a CLFS_LSN value comparison, not a pointer dereference.

3. **Analyze other KTM object types** -- Transaction, ResourceManager, and Enlistment objects may have uninitialized LIST_ENTRY fields that DO get RemoveEntryList'd during their close/delete paths. These are the next targets to investigate.

4. **Consider CLFS interaction** -- The KTM close path heavily interacts with CLFS (clfs.sys). If the CLFS log file handle at +0x098 or marshalling area at +0x0A0 can be manipulated, the CLFS callbacks during close might provide a different attack surface.

5. **Pool overflow into adjacent object** -- If a heap overflow can reach the RestartOrderedList at +0x390/+0x398 from an adjacent pool chunk, the initialized self-pointing links can be corrupted post-init, and the delete path would follow attacker-controlled pointers.

---

## 12. VERIFICATION

- All offsets verified against disassembly of TmInitializeTransactionManagerExt at 0x1C001A820
- All close/delete field accesses verified against disassembly of TmpCloseTransactionManager, TmpDeleteTransactionManager, TmpTmOffline, and TmpCheckpoint
- Type sizes confirmed via IDA type info: _KMUTANT=56, _KEVENT=24, _ERESOURCE=104, _RTL_AVL_TABLE=104, _LIST_ENTRY=16, CLFS_LSN=8
- TmpNamespaceInitialize return value confirmed as always 0 (no failure path)
- Object body size confirmed as 960 bytes from TmpTransactionManagerInitialization
- No InitializeProcedure set for TmTm object type (body not zeroed by ObCreateObject)
