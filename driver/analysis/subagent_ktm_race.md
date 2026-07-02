# KTM Race Window Analysis: ObCreateObject vs LsnOrderedList Initialization

**Target:** tm.sys (KTM - Kernel Transaction Manager)
**IDA Instance:** PID 2944, port 13337
**Analysis Date:** 2026-07-02

---

## 1. Executive Summary

**The race window between ObCreateObject and LsnOrderedList/RestartOrderedList initialization is NOT exploitable.** There are zero failure paths between `state=1` (0x1c001a875) and both list initializations. The handle does not exist until `ObInsertObject` (after init completes), so no other thread can close it. ExUuidCreate's return value is not checked, TmpNamespaceInitialize always returns 0, and ExInitializeResourceLite's return value is not checked. The only failure paths that trigger `ObfDereferenceObject` then `TmpDeleteTransactionManager` occur AFTER both lists are already initialized.

---

## 2. NtCreateTransactionManagerExt (0x1C001EBF0) - Call Sequence

### 2.1 Object Creation and Insertion Flow

```
0x1c001edef  call    cs:__imp_ObCreateObject          ; Allocates TM object (960 bytes / 0x3C0)
0x1c001edf6  nop                                       ; ObCreateObject returns, eax = status
0x1c001edfb  mov     ebx, eax                          ; Save status
0x1c001ee01  test    eax, eax                          ; Check if ObCreateObject succeeded
0x1c001ee03  js      loc_1C001EE94                     ; If failed, jump to cleanup
0x1c001ee09  mov     rax, [rsp+0B8h+TransactionManager]; Load TM object pointer
0x1c001ee0e  mov     [rax+40h], edi                    ; state (+0x040) = 0
0x1c001ee11  mov     r9d, [rsp+0B8h+CreateOptions]     ; r9 = CreateOptions
0x1c001ee19  xor     r8d, r8d                          ; r8 = NULL (TmId parameter)
0x1c001ee1c  mov     rdx, [rsp+0B8h+LogFileName]       ; rdx = LogFileName
0x1c001ee21  mov     rcx, [rsp+0B8h+TransactionManager]; rcx = TM object pointer
0x1c001ee26  call    TmInitializeTransactionManagerExt ; CALL INIT
0x1c001ee2b  mov     ebx, eax                          ; Save init status
0x1c001ee36  test    eax, eax                          ; Check init return
0x1c001ee38  jns     loc_1C001EE48                     ; If success -> ObInsertObject
0x1c001ee3a  call    cs:__imp_ObfDereferenceObject     ; If FAIL -> triggers TmpDeleteTransactionManager
0x1c001ee5f  call    cs:__imp_ObInsertObject           ; Insert into handle table (HANDLE CREATED HERE)
0x1c001ee6b  mov     ebx, eax                          ; Save ObInsertObject status
0x1c001ee73  js      loc_1C001EE94                     ; If failed, cleanup
0x1c001ee7f  mov     [r15], rax                        ; Write handle to user buffer
```

### 2.2 Critical Ordering

| Step | Address | Operation | Handle Exists? |
|------|---------|-----------|----------------|
| 1 | 0x1c001edef | ObCreateObject allocates 960-byte TM object | NO |
| 2 | 0x1c001ee0e | state (+0x040) = 0 | NO |
| 3 | 0x1c001ee26 | TmInitializeTransactionManagerExt called | NO |
| 4 | 0x1c001ee36 | Init return value checked | NO |
| 5 | 0x1c001ee3a | ObfDereferenceObject (error path only) | NO |
| 6 | 0x1c001ee5f | ObInsertObject - handle created | YES (first time) |
| 7 | 0x1c001ee7f | Handle written to user buffer | YES |

**The handle does NOT exist until ObInsertObject at 0x1c001ee5f.** No other thread can call NtClose on the object during initialization.

### 2.3 Instruction Counts

| Window | Instructions | Byte Distance |
|--------|-------------|---------------|
| ObCreateObject return to TmInit call | 11 | 0x30 |
| TmInit call to ObInsertObject | 15 | 0x39 |
| state=1 to LsnOrderedList.Flink init | 68 | 0x15A |
| state=1 to RestartOrderedList.Flink init | 77 | 0x18E |
| ExUuidCreate to LsnOrderedList.Flink init | 48 | 0xF0 |
| LsnOrderedList.Flink to RestartOrderedList.Flink | 9 | 0x34 |

---

## 3. TmInitializeTransactionManagerExt (0x1C001A820) - Full Init Sequence

### 3.1 Step-by-Step Field Initialization

| Step | Address | Instruction | Offset | Field | Can Fail? |
|------|---------|-------------|--------|-------|-----------|
| 1 | 0x1c001a842 | mov dword ptr [rcx], 0B00B0004h | +0x000 | Cookie | No |
| 2 | 0x1c001a866 | call KeInitializeMutex | +0x008 | Mutex | No (void) |
| 3 | 0x1c001a875 | mov dword ptr [rbx+40h], 1 | +0x040 | State = 1 | No |
| 4 | 0x1c001a87c | mov [rbx+80h], r15 | +0x080 | Flags = 0 | No |
| 5 | 0x1c001a88a | mov [rbx+48h], r15 | +0x048 | Field = 0 | No |
| 6 | 0x1c001a892 | mov [rbx+68h], r15b | +0x068 | Field = 0 | No |
| 7 | 0x1c001a896 | mov [rbx+378h], r15d | +0x378 | Field = 0 | No |
| 8 | 0x1c001a89d | mov [rbx+98h], r15 | +0x098 | Field = 0 | No |
| 9 | 0x1c001a8a4 | mov [rbx+0A0h], r15 | +0x0A0 | Field = 0 | No |
| 10 | 0x1c001a8ab | mov [rbx+0A8h], r15 | +0x0A8 | Field = 0 | No |
| 11 | 0x1c001a8b2 | mov [rbx+90h], r15 | +0x090 | Field = 0 | No |
| 12 | 0x1c001a8b9 | mov [r12], r15w | +0x088 | Field = 0 | No |
| 13 | 0x1c001a8be | mov [rbx+8Ah], r15w | +0x08A | Field = 0 | No |
| 14 | 0x1c001a8c6 | test rdi, rdi | -- | TmId == NULL? | Branch (always NULL) |
| 14b | 0x1c001a8d5 | or dword ptr [rbx+80h], 20h | +0x080 | GUID-generated flag | No |
| 15 | 0x1c001a8df | call ExUuidCreate | +0x070 | GUID generation | RETURN VALUE NOT CHECKED |
| 16 | 0x1c001a8fb | call TmpNamespaceInitialize | +0x0B0 | Namespace 1 | Always returns 0 |
| -- | 0x1c001a904 | js loc_1C001AA25 | -- | Check #1 -> error | Never taken |
| 17 | 0x1c001a91a | call TmpNamespaceInitialize | +0x158 | Namespace 2 | Always returns 0 |
| -- | 0x1c001a923 | js loc_1C001AA25 | -- | Check #2 -> error | Never taken |
| 18 | 0x1c001a92e | mov [rbx+258h], r15 | +0x258 | Field = 0 | No |
| 19 | 0x1c001a937 | mov [rbx+250h], edi | +0x250 | Field = 1 | No |
| 20 | 0x1c001a944 | mov [rbx+260h], r15d | +0x260 | Field = 0 | No |
| 21 | 0x1c001a94e | call KeInitializeEvent | +0x268 | Event | No (void) |
| 22-25 | 0x1c001a976-994 | CLFS_LSN_NULL stores | +0x288..+0x298 | LSN fields | No |
| 26 | 0x1c001a9ac | call KeInitializeMutex | +0x200 | Mutex | No (void) |
| 27a | 0x1c001a9c9 | mov [rax+8], rax | +0x240 | LsnOrderedList.Blink = and-self | No |
| 27b | 0x1c001a9cf | mov [rax], rax | +0x238 | LsnOrderedList.Flink = and-self | No |
| 28 | 0x1c001a9d2 | call KeInitializeEvent | +0x2B0 | Event | No (void) |
| 29 | 0x1c001a9e5 | call ExInitializeResourceLite | +0x310 | ERESOURCE | RETURN NOT CHECKED |
| 30 | 0x1c001a9f1 | mov [rbx+37Ch], rdi | +0x37C | Field = 0 | No |
| 31a | 0x1c001a9ff | mov [rax+8], rax | +0x398 | RestartOrderedList.Blink = and-self | No |
| 31b | 0x1c001aa03 | mov [rax], rax | +0x390 | RestartOrderedList.Flink = and-self | No |
| 32 | 0x1c001aa06 | test sil, 2 | -- | CreateOptions and 2 | Can fail -> error |
| 33 | 0x1c001aa92 | test sil, 4 | -- | CreateOptions and 4 | Can fail -> error |
| 34 | 0x1c001aaf3 | call RtlDuplicateUnicodeString | +0x088 | Log file name dup | CAN FAIL -> error |
| 35 | 0x1c001ab18/ab1f | TmpCreateOrOpenLog / TmpTmOnline | -- | CLFS / online | CAN FAIL -> error |
| 36 | 0x1c001ab79 | call ZwCreateResourceManager | -- | RM creation | CAN FAIL -> error |

---

## 4. Failure Path Analysis

### 4.1 Error Path Entry Points (LABEL_9 at 0x1c001aa25)

| Address | Source | Before List Init? |
|---------|--------|-------------------|
| 0x1c001a904 | TmpNamespaceInitialize #1 return | YES but always returns 0, never taken |
| 0x1c001a923 | TmpNamespaceInitialize #2 return | YES but always returns 0, never taken |
| 0x1c001aa1d | InterlockedExchange for CreateOptions and 2 | NO - after both lists init |
| 0x1c001aa05 | InterlockedExchange for CreateOptions and 4 | NO - after both lists init |
| 0x1c001ab05 | RtlDuplicateUnicodeString | NO - after both lists init |
| 0x1c001ab28 | TmpTmOnline / TmpCreateOrOpenLog | NO - after both lists init |
| 0x1c001ab89 | ZwCreateResourceManager | NO - after both lists init |

**There are ZERO reachable failure paths between state=1 (0x1c001a875) and RestartOrderedList init (0x1c001aa03).**

### 4.2 ExUuidCreate Analysis

**Return value is NOT checked.** The instruction sequence after the call:

```
0x1c001a8df  call    cs:__imp_ExUuidCreate
0x1c001a8e6  nop     dword ptr [rax+rax+00h]      ; no test eax
0x1c001a8eb  mov     edx, 88h                     ; immediately continues
0x1c001a8f0  lea     rcx, [rbx+0B0h]; Table       ; loads next arg
0x1c001a8fb  call    TmpNamespaceInitialize       ; next call
```

No test eax, no js, no jz. ExUuidCreate is called as a void function. Even if it returns STATUS_INSUFFICIENT_RESOURCES, the init continues uninterrupted.

ExUuidCreate (ntoskrnl 0x14071fba0) CAN fail - it returns non-zero when ExpUuidGetValues fails (e.g., UUID counter exhaustion). But the failure is silently ignored.

### 4.3 TmpNamespaceInitialize Analysis

```c
__int64 TmpNamespaceInitialize(PRTL_AVL_TABLE Table, __int16 a2, __int16 a3)
{
  LOWORD(Table[1].RestartKey) = a2;
  WORD1(Table[1].RestartKey) = a3;
  BYTE4(Table[1].RestartKey) = 0;
  KeInitializeMutex((PRKMUTEX)&Table[1], 0);
  RtlInitializeGenericTableAvl(Table, ...);  // void function
  return 0;  // HARDCODED RETURN 0
}
```

**Always returns 0.** The js checks at 0x1c001a904 and 0x1c001a923 are dead code.

### 4.4 ExInitializeResourceLite Analysis

```
0x1c001a9e5  call    cs:__imp_ExInitializeResourceLite
0x1c001a9ec  nop     dword ptr [rax+rax+00h]
0x1c001a9f1  mov     [rbx+37Ch], rdi            ; no check of eax
```

Return value not checked. Even if it fails, init continues.

---

## 5. Delete Path Analysis

### 5.1 TmpDeleteTransactionManager (0x1C001B800)

```
0x1c001b816  cmp     [rcx+40h], esi             ; if state (+0x040) == 0
0x1c001b819  jz      loc_1C001B90F              ; skip entire cleanup
0x1c001b81f  bts     dword ptr [rcx+80h], 1Fh   ; set bit 31 in flags (+0x080)
0x1c001b827  call    TmpTmOffline               ; offline the TM
```

State must be non-zero to enter cleanup. On the error path, state is set to 4 at 0x1c001aa2c:
```
0x1c001aa2c  mov     dword ptr [rbx+40h], 4     ; state = 4 (error)
```

### 5.2 RestartOrderedList Iteration in TmpDeleteTransactionManager

```
0x1c001b8ba  lea     rsi, [rbx+390h]            ; rsi = and-TM.RestartOrderedList (head)
0x1c001b8c1  mov     rdi, [rsi]                 ; rdi = Flink = *(TM + 0x390)
0x1c001b8f7  cmp     rdi, rsi                   ; while (Flink != and-head)
0x1c001b8fa  jnz     loc_1C001B8C6              ; enter loop body if not equal
```

**Loop body (RemoveEntryList + ExFreePoolWithTag):**
```
0x1c001b8c6  mov     rdx, [rdi]                 ; rdx = next = entry->Flink
0x1c001b8c9  lea     rcx, [rdi-8]               ; rcx = entry base (LIST_ENTRY preceded by 8 bytes)
0x1c001b8cd  mov     r8, rdi                    ; r8 = current entry
0x1c001b8d0  mov     rdi, rdx                   ; advance to next

; Integrity check 1: next->Blink must == current
0x1c001b8d3  cmp     [rdx+8], r8                ; next->Blink == current?
0x1c001b8d7  jnz     loc_1C001B920              ; if not -> __fastfail(3) = BUGCHECK

; Integrity check 2: Blink->Flink must == current
0x1c001b8d9  mov     rax, [r8+8]                ; rax = current->Blink
0x1c001b8dd  cmp     [rax], r8                  ; Blink->Flink == current?
0x1c001b8e0  jnz     loc_1C001B920              ; if not -> __fastfail(3) = BUGCHECK

; RemoveEntryList write-what-where
0x1c001b8e2  mov     [rax], rdx                 ; Blink->Flink = next  (WRITE 1)
0x1c001b8e5  mov     [rdx+8], rax               ; next->Blink = Blink  (WRITE 2)

; Free the entry
0x1c001b8eb  call    ExFreePoolWithTag          ; ExFreePoolWithTag(entry - 8, 0)

; __fastfail handler
0x1c001b920  mov     ecx, 3
0x1c001b925  int     29h                        ; RtlFailFast(3) = immediate BUGCHECK
```

### 5.3 TmpTmOffline (0x1C001D250) - LsnOrderedList Access

TmpTmOffline checks state:
```c
if ( *(_DWORD *)(a1 + 64) == 5 )  // state == 5?
{
    KeReleaseMutex(...);
    KeLeaveCriticalRegion();
    return 0;  // early exit
}
```

On the error path, state = 4 (not 5), so the else branch is taken:
```c
v3 = *(_DWORD *)(a1 + 128);       // flags at +0x080
if ( (v3 & 1) == 0 )              // if NOT volatile
{
    TmpCheckpoint(a1, 0);          // call checkpoint
}
```

**TmpCheckpoint (0x1C000C690) accesses RestartOrderedList at +0x390** in two iteration loops. However, TmpCheckpoint checks state first:
```c
if ( *(_DWORD *)(a1 + 64) != 3 )  // state != 3?
{
    v9 = STATUS_UNSUCCESSFUL;
    goto LABEL_132;  // return early
}
```

On the error path, state = 4 (not 3), so **TmpCheckpoint returns immediately without touching any lists**.

**TmpTmOffline does NOT directly access LsnOrderedList (+0x238).** It accesses:
- +0x008 (mutex), +0x040 (state), +0x080 (flags)
- +0x0B0 (namespace 1), +0x158 (namespace 2)
- +0x310 (ERESOURCE), +0x0A0 (marshalling area), +0x098 (log file)
- +0x0A8 (CLFS mgmt client), +0x048 (namespace insertion flag)

---

## 6. Pool Memory Zeroing Analysis

### 6.1 ObpAllocateObject (ntoskrnl 0x14064c950)

ObpAllocateObject allocates memory via:
```c
PoolWithTag = ExAllocatePoolWithTag(
    *(_DWORD *)(a3 + 100) | 0x400,  // PoolType from ObjectType
    v26 + a5,                        // total size (header + body)
    *(_DWORD *)(a3 + 192)            // tag from ObjectType
);
```

**ExAllocatePoolWithTag does NOT guarantee zeroing.** The function initializes the object header fields individually but does NOT zero-fill the object body (the a5 bytes). The body is left with whatever data was in the previously freed pool chunk.

### 6.2 Implications

If the pool body is NOT zeroed, the memory at +0x238 (LsnOrderedList) and +0x390 (RestartOrderedList) would contain stale pool data from a previously freed allocation. A pool spray could potentially place controlled data at these offsets.

**However, this is irrelevant because there is no way to trigger the error path before the lists are initialized.**

---

## 7. ExUuidCreate Failure Analysis

### 7.1 Can ExUuidCreate Fail?

**Yes.** ExUuidCreate (ntoskrnl 0x14071fba0) can return a failure NTSTATUS:
- Fast path: Uses cached UUID counter. Returns STATUS_SUCCESS (0) or 0x40000016 depending on NlsMbCodePageTag.
- Slow path: Calls ExpUuidGetValues. If ExpUuidGetValues returns a non-zero NTSTATUS, ExUuidCreate returns that error immediately.

### 7.2 Does It Matter?

**No.** The return value is not checked in TmInitializeTransactionManagerExt:
```
0x1c001a8df  call    cs:__imp_ExUuidCreate
0x1c001a8e6  nop                                 ; no test, no branch
0x1c001a8eb  mov     edx, 88h                    ; continues to TmpNamespaceInitialize
```

Even if ExUuidCreate fails, the GUID at +0x070 may be partially written or contain stale data, but initialization continues. The error path is NOT triggered.

### 7.3 Can We Force ExUuidCreate to Fail?

Theoretically, UUID counter exhaustion could cause ExpUuidGetValues to fail, but:
1. Even if it fails, the return value is ignored
2. The init continues regardless
3. There is no way to redirect execution to the error path from ExUuidCreate failure

**ExUuidCreate failure is a dead end for exploitation.**

---

## 8. Alternative Attack Vectors Considered

### 8.1 Close Handle Before ObInsertObject

**Impossible.** The handle does not exist until ObInsertObject at 0x1c001ee5f. The object is only referenced by a stack-local pointer. No other thread can obtain a handle or reference to the object before insertion.

### 8.2 DuplicateHandle from Another Process

**Impossible.** DuplicateHandle requires an existing source handle. No handle exists before ObInsertObject.

### 8.3 NtQuerySystemInformation to Find Object Address

**Irrelevant.** Even if the kernel object address could be found, user-mode code cannot write to kernel memory without an existing write primitive.

### 8.4 Pool Spray + Init Failure

**No viable failure path.** The only operations between state=1 and list init that have error checks are:
- TmpNamespaceInitialize (always returns 0)
- No other checked operations exist in this window

All other operations are either:
- mov instructions (cannot fail)
- KeInitializeMutex / KeInitializeEvent (void functions)
- ExUuidCreate (return value ignored)
- ExInitializeResourceLite (return value ignored)

### 8.5 Volatile TM (CreateOptions = 0x1) Path

For volatile TM, CreateOptions and 1 == 1, so:
- LogFileName must be NULL (enforced at 0x1c001edaa)
- TmpTmOnline is called instead of TmpCreateOrOpenLogTransactionManager (at 0x1c001ab1f)
- Both are called AFTER both lists are initialized

The volatile flag at +0x080 bit 0 is set at 0x1c001aae0, which is AFTER both lists are initialized.

### 8.6 CreateOptions and 2 (CRM_ENABLE)

The InterlockedExchange at 0x1c001aa13 can fail if another TM already has CRM enabled (global single-instance constraint). This sets edi = 0xC000000D and jumps to the error path.

**But this is at 0x1c001aa06, which is AFTER RestartOrderedList init at 0x1c001aa03.** Both lists are already initialized. The delete path would see properly self-referencing lists and the iteration loop would immediately exit (Flink == and-head).

### 8.7 CreateOptions and 4

Similar to CRM_ENABLE - the InterlockedExchange at 0x1c001aa9d can fail. But this is even later (0x1c001aa92), well after both lists are initialized.

---

## 9. Hypothetical Exploit Chain (If a Failure Path Existed)

**This section describes what WOULD happen if a failure path existed between state=1 and list init. This is hypothetical - no such path exists.**

### 9.1 Prerequisites

1. Pool spray to place controlled data at offsets +0x238 (LsnOrderedList) and +0x390 (RestartOrderedList) within a 960-byte paged pool allocation
2. Trigger NtCreateTransactionManagerExt with parameters that cause init to fail after state=1 but before list init
3. The error path calls ObfDereferenceObject -> TmpDeleteTransactionManager

### 9.2 Delete Path with Uninitialized RestartOrderedList

If +0x390 contains controlled spray data instead of self-referencing pointers:

```
v5 = *(TM + 0x390)                    ; = controlled Flink (our spray)
while (v5 != (TM + 0x390))            ; if Flink != and-head, loop ENTERS
{
    v6 = *v5                           ; = *(controlled_Flink) = next Flink
    v7 = v5 - 8                        ; = controlled_Flink - 8 (entry base)
    ; Integrity check 1: *(next + 8) must == current (v5)
    ; Integrity check 2: *(current + 8)->Flink must == current (v5)
    ; If both pass:
    *(Blink) = next                     ; WRITE: controlled address <- controlled value
    *(next + 8) = Blink                 ; WRITE: controlled address <- controlled value
    ExFreePoolWithTag(v5 - 8, 0)       ; FREE: at controlled address
}
```

### 9.3 Write-What-Where Primitive

The RemoveEntryList writes:
- *(Blink) = Flink_next -- write controlled value to controlled address
- *(Flink_next + 8) = Blink -- write controlled value to controlled address

Followed by ExFreePoolWithTag(controlled_address, 0) -- free at controlled address.

### 9.4 Integrity Check Bypass

The __fastfail(3) checks require:
1. *(next_Flink + 8) == current_entry -- next node Blink must point back to current
2. *(current_Blink) == current_entry -- Blink Flink must point to current

This requires a self-consistent fake list structure in the spray data:
- At spray_addr +0x390: Flink = and-fake_node
- At and-fake_node +0x0: Flink = and-head (to terminate loop) or another node
- At and-fake_node +0x8: Blink = spray_addr +0x390

### 9.5 Why This Does Not Work

**There is no way to trigger the error path before list initialization.** The 68 instructions between state=1 and LsnOrderedList init, and the 77 instructions between state=1 and RestartOrderedList init, contain zero reachable failure paths.

---

## 10. CLFS Cleanup Before List Iteration

Even if the error path were reachable, TmpDeleteTransactionManager performs CLFS cleanup BEFORE the list iteration:

```
0x1c001b827  call    TmpTmOffline                 ; CLFS cleanup
0x1c001b82c  mov     rax, [rbx+0A8h]              ; CLFS mgmt client
0x1c001b842  mov     rcx, [rbx+0A0h]              ; marshalling area
0x1c001b84e  call    ClfsDeleteMarshallingArea
0x1c001b861  mov     rcx, [rbx+98h]               ; log file object
0x1c001b86d  call    ClfsCloseLogFileObject
0x1c001b888  call    ClfsMgmtDeregisterManagedClient
0x1c001b894  mov     eax, [rbx+80h]               ; flags check for volatile
0x1c001b8a7  lea     rcx, [rbx+88h]               ; unicode string
0x1c001b8ae  call    RtlFreeUnicodeString
0x1c001b8ba  lea     rsi, [rbx+390h]              ; <- LIST ITERATION STARTS HERE
```

If init fails before CLFS fields are initialized, the CLFS pointers at +0x098, +0x0A0, +0x0A8 would be NULL (if zeroed) or stale pool data (if not zeroed). The test/jz checks at 0x1c001b849, 0x1c001b868, 0x1c001b880 would skip CLFS calls for NULL pointers.

---

## 11. Complete Execution Flow Diagram

```
NtCreateTransactionManagerExt (0x1C001EBF0)
|
+- ObCreateObject (0x1c001edef)
|  +- Allocates 960-byte TM object via ExAllocatePoolWithTag
|  +- Object body NOT zeroed (stale pool data possible)
|
+- state (+0x040) = 0 (0x1c001ee0e)
|
+- TmInitializeTransactionManagerExt (0x1c001ee26)
|  |
|  +- [1]  +0x000 = 0xB00B0004 (cookie)         0x1c001a842
|  +- [2]  +0x008 = KeInitializeMutex            0x1c001a866
|  +- [3]  +0x040 = 1 (state = ONLINE_INIT)     0x1c001a875  STATE SET
|  +- [4-13] Various field zeroing (mov)         0x1c001a87c - 0x1c001a8be
|  |
|  +- [14] ExUuidCreate (+0x070)                 0x1c001a8df
|  |       +- Return value NOT CHECKED
|  |
|  +- [15] TmpNamespaceInitialize (+0x0B0)       0x1c001a8fb
|  |       +- js check 0x1c001a904 -> NEVER TAKEN
|  |
|  +- [16] TmpNamespaceInitialize (+0x158)       0x1c001a91a
|  |       +- js check 0x1c001a923 -> NEVER TAKEN
|  |
|  +- [17-25] Field inits, LSN nulls, events     0x1c001a92e - 0x1c001a9ac
|  |
|  +- [27] LsnOrderedList init (+0x238)          0x1c001a9c9/0x1c001a9cf  LSN LIST INIT
|  |       +- Flink = Blink = and-self
|  |
|  +- [28-30] Event, Resource, field init        0x1c001a9d2 - 0x1c001a9f1
|  |
|  +- [31] RestartOrderedList init (+0x390)      0x1c001a9ff/0x1c001aa03  RESTART LIST INIT
|  |       +- Flink = Blink = and-self
|  |
|  +- [32] CreateOptions and 2 check             0x1c001aa06  AFTER LISTS INIT
|  |       +- Can fail -> error path (state=4)
|  +- [33] CreateOptions and 4 check             0x1c001aa92  AFTER LISTS INIT
|  |       +- Can fail -> error path (state=4)
|  +- [34] RtlDuplicateUnicodeString              0x1c001aaf3  AFTER LISTS INIT
|  |       +- Can fail -> error path (state=4)
|  +- [35] TmpTmOnline / TmpCreateOrOpenLog      0x1c001ab18/ab1f  AFTER LISTS INIT
|  |       +- Can fail -> error path (state=4)
|  +- [36] ZwCreateResourceManager               0x1c001ab79  AFTER LISTS INIT
|          +- Can fail -> error path (state=4)
|
+- [if init fails] ObfDereferenceObject          0x1c001ee3a
|  +- Triggers TmpDeleteTransactionManager
|  +- state=4, lists already initialized
|  +- TmpTmOffline: TmpCheckpoint skipped (state!=3)
|  +- RestartOrderedList loop: Flink==and-head, exits immediately
|
+- [if init succeeds] ObInsertObject             0x1c001ee5f
   +- HANDLE CREATED HERE
   +- Handle written to user buffer              0x1c001ee7f
```

---

## 12. Conclusion

The race window between ObCreateObject and LsnOrderedList/RestartOrderedList initialization in tm.sys is **NOT exploitable** for the following reasons:

1. **No handle exists during initialization.** ObInsertObject is called only after TmInitializeTransactionManagerExt returns successfully. No other thread can obtain a handle to close.

2. **No failure path between state=1 and list init.** The 68 instructions between state=1 (0x1c001a875) and LsnOrderedList init (0x1c001a9cf), and 77 instructions to RestartOrderedList init (0x1c001aa03), contain only:
   - mov instructions (infallible)
   - KeInitializeMutex/KeInitializeEvent (void)
   - ExUuidCreate (return value not checked)
   - TmpNamespaceInitialize (always returns 0)
   - ExInitializeResourceLite (return value not checked)

3. **ExUuidCreate failure is ignored.** The return value is never tested. Even if ExUuidCreate fails, initialization continues to completion.

4. **All checkable failure points are after list init.** CreateOptions and 2 (0x1c001aa06), CreateOptions and 4 (0x1c001aa92), RtlDuplicateUnicodeString (0x1c001aaf3), TmpTmOnline/TmpCreateOrOpenLog (0x1c001ab18/ab1f), and ZwCreateResourceManager (0x1c001ab79) are all after both lists are initialized at 0x1c001a9cf and 0x1c001aa03.

5. **Even if a failure occurred before list init, the delete path has integrity checks.** TmpDeleteTransactionManager performs __fastfail(3) checks on list consistency. TmpTmOffline calls TmpCheckpoint which checks state==3 (error path has state=4, so TmpCheckpoint returns early).

6. **ObpAllocateObject does not zero the object body.** While this means stale pool data could be present at list offsets, it is irrelevant because the delete path cannot be triggered before list initialization.
