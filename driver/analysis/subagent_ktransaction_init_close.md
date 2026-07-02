# _KTRANSACTION Initialization and Close/Delete Path Analysis

**Binary:** tm.sys (PID 2944, port 13337)
**Date:** 2026-07-02

---

## 1. Type Inspection: _KTRANSACTION

IDA's local type library does not contain `_KTRANSACTION` (type_inspect returned size=-1). Size confirmed as **728 bytes (0x2D8)** from:
- `TmpTransactionInitialization` (0x1c00247b4): `HIDWORD(v2[5]) = 728` to ObCreateObjectType
- `NtCreateTransactionExt` (0x1c001d530): `ObCreateObject(..., 728, ...)`

### LIST_ENTRY Fields

| Offset | Field | Type |
|--------|-------|------|
| 0xC8 | EnlistmentHead | _LIST_ENTRY |
| 0x100 | PromotedEntry | _LIST_ENTRY |
| 0x1E8 | LsnOrderedEntry | _LIST_ENTRY |

Other embedded structures: KEVENT@0x00, KMUTEX@0x20, KEVENT@0x2C0, KMUTEX@0x278 — all initialized by Ke* functions, no raw LIST_ENTRY.

---

## 2. TmInitializeTransaction (0x1c0014314)

### LIST_ENTRY Initializations

All three LIST_ENTRYs are initialized via direct Flink/Blink writes (equivalent to InitializeListHead):

| Offset | Flink Write | Blink Write | Status |
|--------|------------|------------|--------|
| 0xC8 (EnlistmentHead) | `*((QWORD*)Object+25) = Object+200` | `*((QWORD*)Object+26) = Object+200` | **INITIALIZED (self-ref)** |
| 0x100 (PromotedEntry) | `*((QWORD*)Object+32) = Object+256` | `*((QWORD*)Object+33) = Object+256` | **INITIALIZED (self-ref)** |
| 0x1E8 (LsnOrderedEntry) | `*((QWORD*)Object+61) = Object+488` | `*((QWORD*)Object+62) = Object+488` | **INITIALIZED (self-ref)** |

### Other Key Fields Set

| Offset | Value | Field |
|--------|-------|-------|
| 0x00 | KeInitializeEvent | KEVENT (Transaction event) |
| 0x20 | KeInitializeMutex | Transaction Mutex |
| 0x58 | Object (self) | KTM back-pointer (self when no TM) |
| 0xC0 | 1 (QWORD write) | **State = 1** (KTransactionNormal) |
| 0xC4 | 0 (high DWORD of QWORD) | Flags |
| 0x1F8 | 1 | Outcome = 1 (TxOutcomeIndoubt) |
| 0x200 | 0 | KTM pointer = 0 |
| 0x2C0 | KeInitializeEvent | OutcomeEvent |
| 0x278 | KeInitializeMutex | PromoteMutex |

### TM Linkage (conditional on TmHandle parameter)

```
if ( TmHandle != NULL ) {
    TmpInsertTxTransactionManager(TmHandle);  // inserts into TM's AVL namespace
} else {
    TmpNamespaceInsert(&TmpTransactionsNamespace, nullptr);  // global namespace
}
```

**When TmHandle=NULL:** Transaction goes into global `TmpTransactionsNamespace`, NOT linked to any KTM. KTM pointer@0x200 stays 0.

---

## 3. LIST_ENTRY Initialization Summary

| Field | Offset | Initialized? | How | Self-Referencing? |
|-------|--------|-------------|-----|-------------------|
| EnlistmentHead | 0xC8 | **YES** | Direct Flink/Blink = self | YES |
| PromotedEntry | 0x100 | **YES** | Direct Flink/Blink = self | YES |
| LsnOrderedEntry | 0x1E8 | **YES** | Direct Flink/Blink = self | YES |

**ALL THREE LIST_ENTRY FIELDS ARE INITIALIZED. NONE LEFT UNINITIALIZED.**

---

## 4. Close Path: TmpCloseTransaction (0x1c0014bb0)

```c
NTSTATUS TmpCloseTransaction(a1, KTRANSACTION *a2, a3, a4) {
    if ( a4 == 1 || a3 == 1 )   // last handle close
        return TmRollbackTransactionExt(a2, 0);
    return STATUS_SUCCESS;
}
```

**No RemoveEntryList on any LIST_ENTRY.** Thin wrapper delegating to TmRollbackTransactionExt.

---

## 5. TmRollbackTransactionExt (0x1c0014620)

### State Check

State@0xC0 = 1 (set by TmInitializeTransaction). bittest(2310, 1):
- 2310 = 0x906, bits set: 1, 2, 8, 11
- State=1 passes (bit 1 = 1)

### Flow for State=1

```
if ( (State <= 0xB && bittest(2310, State)) || (State == 3 && (Flags & 2)) )
{
    if ( KTM@0x200 != NULL )
        -> TmpTxActionDoRollback(Transaction)
    else  // KTM is NULL (no TM or TM not online)
        -> State = 9, Outcome = 3
        -> KeSetEvent(Transaction)
        -> TmpFinalizeTransaction(Transaction)  // CALLED!
}
```

**TmpFinalizeTransaction IS called for both TM and no-TM cases** when State=1.

---

## 6. TmpFinalizeTransaction (0x1c0014cd0)

### LIST_ENTRY Operations

| LIST_ENTRY | RemoveEntryList? | Guard Condition |
|-----------|-----------------|-----------------|
| LsnOrderedEntry@0x1E8 | **YES** | `(State@0xC0 & 0x800000) != 0` |
| PromotedEntry@0x100 | Walked (not removed) | `(State@0xC0 & 0x500) == 0x500` |
| EnlistmentHead@0xC8 | NO | N/A |

### LsnOrderedEntry RemoveEntryList Detail

```c
if ( (State & 0x800000) != 0 ) {          // CHECK FLAG
    KeWaitForSingleObject(KTM + 512, ...); // KTM mutex
    if ( (State & 0x800000) != 0 ) {       // re-check
        // __fastfail(3) if list corrupted
        // RemoveEntryList(&LsnOrderedEntry)
        State &= ~0x800000;                // clear flag
    }
    KeReleaseMutex(KTM + 512, 0);
}
```

### The 0x800000 Flag

Set **only** in `TmpInsertTransactionLsnList` (0x1c00104c0):
```c
a1[24].offset.cidContainer |= 0x800000u;  // State@0xC0 |= 0x800000
```

Called from: `TmpLogTransaction` (when transaction is logged to CLFS).

**For create+close without enlisting/logging: 0x800000 is NEVER set. RemoveEntryList on LsnOrderedEntry is SKIPPED.**

---

## 7. TmpDeleteTransaction (0x1c0014be0)

```c
void TmpDeleteTransaction(a1) {
    *(DWORD*)(a1+0xC4) |= 0x80000000;  // mark deleted
    if ( *(DWORD*)(a1+0xC0) ) {        // State != 0
        // TmpNamespaceRemove (TM table or global)
        // RtlFreeUnicodeString (description)
        // ObfDereferenceObject (KTM back-ptr if not self)
        // ExFreePoolWithTag (notification buffer)
        // ObfDereferenceObject (superior transaction)
    }
}
```

**No RemoveEntryList on any LIST_ENTRY.** Cleanup only: namespace removal, string free, object derefs.

---

## 8. TmpFinalizeTransactionForcefully (0x1c0014e9c)

Walks EnlistmentHead@0xC8 list to finalize each enlistment, then calls TmpFinalizeTransaction. Does NOT RemoveEntryList on EnlistmentHead itself — enlistments remove themselves during their own finalization.

---

## 9. TmpInsertTransactionLsnList (0x1c00104c0)

Inserts LsnOrderedEntry@0x1E8 into KTM.LsnOrderedList:
1. Acquires KTM mutex (KTM+0x200)
2. If already linked (0x800000 set): RemoveEntryList first
3. Sets LsnOrderedEntry.Lsn = newLsn (at KTRANSACTION+0xF8)
4. Finds sorted insertion point in KTM.LsnOrderedList
5. Inserts via Flink/Blink manipulation
6. Sets 0x800000 flag on State@0xC0

**Only called from TmpLogTransaction (CLFS logging path). NOT called during NtCreateTransaction.**

---

## 10. Complete Flow: Create + Immediately Close

### TmHandle = NULL (no TM)

```
NtCreateTransaction(TmHandle=NULL)
  -> ObCreateObject(728) -> pool alloc 792 bytes
  -> TmInitializeTransaction:
     -> ALL 3 LIST_ENTRYs = self-referencing
     -> State@0xC0 = 1
     -> KTM@0x200 = 0
     -> TmpNamespaceInsert(global)
  -> ObInsertObject -> handle

CloseHandle
  -> TmpCloseTransaction (last handle)
     -> TmRollbackTransactionExt:
        -> State=1, bittest passes
        -> KTM@0x200=0 -> no-KTM branch
        -> State=9, TmpFinalizeTransaction:
           -> 0x800000? NO -> RemoveEntryList SKIPPED
           -> 0x500? NO -> PromotedEntry walk SKIPPED
           -> ObfDereferenceObject

Refcount -> 0
  -> TmpDeleteTransaction: namespace/string cleanup
  -> Object freed to LFH bucket
```

**Result: All 3 LIST_ENTRYs remain self-referencing throughout. No RemoveEntryList called. No uninitialized LIST_ENTRY corruption.**

### TmHandle = Valid TM

Same flow, except TmpTxActionDoRollback is called (because KTM@0x200 may be set). TmpFinalizeTransaction still called, 0x800000 still not set, RemoveEntryList still skipped.

---

## 11. NtCreateTransaction Requirements

### Signature (from NtCreateTransactionExt decompile)

```c
NTSTATUS NtCreateTransaction(
    PHANDLE TransactionHandle,     // out
    ACCESS_MASK DesiredAccess,     // in (MUST be non-zero)
    POBJECT_ATTRIBUTES ObjAttrs,   // in, optional
    LPGUID Uow,                    // in, optional (auto-generated if NULL)
    HANDLE TmHandle,               // in, OPTIONAL - CAN BE NULL!
    ULONG CreateOptions,           // in (must be 0 or 1)
    ULONG IsolationLevel,          // in
    ULONG IsolationFlags,          // in
    PLARGE_INTEGER Timeout,        // in, optional
    PUNICODE_STRING Description    // in, optional (max 128 chars)
);
```

### Key Findings

- **TmHandle CAN be NULL** — no TM required to create a transaction
- When NULL, transaction goes into global `TmpTransactionsNamespace`
- CreateOptions must be 0 or 1 (1 = volatile transaction)
- DesiredAccess must be non-zero
- Description string max 128 bytes
- Can create on volatile TM (TmHandle to volatile TM works)

### Minimal Call

```c
HANDLE hTx;
OBJECT_ATTRIBUTES oa = { sizeof(oa) };
NtCreateTransaction(&hTx, TRANSACTION_ALL_ACCESS, &oa, NULL, NULL, 0, 0, 0, NULL, NULL);
// or with volatile TM:
// NtCreateTransaction(&hTx, TRANSACTION_ALL_ACCESS, &oa, NULL, hVolatileTm, 0, 0, 0, NULL, NULL);
```

---

## 12. Pool Allocation Math

```
_KTRANSACTION body:    728 bytes (0x2D8)
+ OBJECT_HEADER:        48 bytes
= ObAllocateObject:    776 bytes (0x308)  [requested from pool]
+ POOL_HEADER:          16 bytes
= Total pool block:    792 bytes (0x318)
```

### LFH Bucket

| Scheme | Bucket | Slack | Notes |
|--------|--------|-------|-------|
| A (with 800 bucket) | 800 | 8 bytes | User estimate: covers 785-800 |
| B (without 800) | 832 | 40 bytes | Standard table: covers 769-832 |

**Need to verify on target Windows version.** The NT pool LFH bucket table varies between builds.

### Pipe Spray Targeting

If bucket = 800:
- Pipe buffer user_size: 776-783 to hit pool block 792-799, bucket 800
- Or user_size 784-799 for pool block 800 (exact bucket boundary)

If bucket = 832:
- Pipe buffer user_size: 776-815 to hit pool block 792-831, bucket 832

---

## 13. CRITICAL FINDING: No Uninitialized LIST_ENTRY

**ALL three LIST_ENTRY fields in _KTRANSACTION are initialized as self-referencing in TmInitializeTransaction.** There is NO LIST_ENTRY that is left uninitialized and then RemoveEntryList'd during close/delete.

### Per-Field Summary

| Field | Offset | Initialized? | RemoveEntryList'd? | Guard | Bug? |
|-------|--------|-------------|-------------------|-------|------|
| EnlistmentHead | 0xC8 | YES (self-ref) | NO (walked only) | N/A | NO |
| PromotedEntry | 0x100 | YES (self-ref) | NO (walked only) | 0x500 flag | NO |
| LsnOrderedEntry | 0x1E8 | YES (self-ref) | YES | 0x800000 flag | NO (flag never set for create+close) |

### Why LsnOrderedEntry Is Not Exploitable

1. LsnOrderedEntry@0x1E8 is initialized as self-referencing in TmInitializeTransaction
2. It's only inserted into KTM.LsnOrderedList by TmpInsertTransactionLsnList (sets 0x800000 flag)
3. TmpInsertTransactionLsnList is only called from TmpLogTransaction (CLFS logging)
4. For a create+close scenario without enlisting/logging, 0x800000 is never set
5. TmpFinalizeTransaction checks 0x800000 before RemoveEntryList — skips if not set
6. Even if RemoveEntryList were called on a self-referencing entry, it's a no-op (safe)

### Comparison to _KTM Approach

The _KTRANSACTION approach **fails for the same reason as _KTM**: all LIST_ENTRY fields are properly initialized. The KTM and KTRANSACTION objects both use self-referencing initialization for all their LIST_ENTRYs, leaving no uninitialized entry to exploit via RemoveEntryList corruption.

---

## 14. Potential Alternative Angles

While no uninitialized LIST_ENTRY exists, these observations may be useful:

1. **Pool size match**: _KTRANSACTION at 792 bytes (bucket 800/832) is a viable pool spray target for reclaiming freed KTRANSACTION memory with controlled data
2. **No TM required**: NtCreateTransaction with TmHandle=NULL creates a transaction without needing a TM, simplifying the spray
3. **Self-referencing pointers in freed memory**: After the object is freed, the LIST_ENTRY Flink/Blink fields (which point to the object itself) become stale self-pointers in freed pool memory. If reclaimed with pipe buffers, those offsets contain attacker-controlled data
4. **Potential UAF angle**: If there's a race between close and another operation that reads LIST_ENTRY fields after free, the self-referencing pointers would now point to pipe-controlled data
5. **State field at 0xC0**: The QWORD write of 1 sets State=1 and Flags@0xC4=0 simultaneously. This is the field that controls the 0x800000 and 0x500 guard bits for RemoveEntryList and PromotedEntry walk
