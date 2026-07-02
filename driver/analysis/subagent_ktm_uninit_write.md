# _KTM Uninitialized Byte Analysis - Write Primitive Investigation

## Executive Summary

**No write-what-where primitive found.** The 72-byte gap at 0x2C8-0x30F (the most promising range) contains:
- A CLFS_LSN at 0x2E8 read by TmpCheckpoint as a comparison value (not a pointer)
- Two WORK_QUEUE_ITEMs (0x2C8 and 0x2F0) initialized by CLFS callbacks before use
- The CLFS_LSN at 0x2E8 is ALWAYS written by TmpAdvanceBaseLsnRequiredNotification before TmpCheckpoint reads it

The uninitialized bytes influence control flow (ClfsLsnLess comparison) but are never dereferenced as pointers, used as write targets, or passed to functions that write through them.

---

## 1. Complete _KTM Struct Layout (960 bytes, NonPagedPoolNx)

### Object Type Registration

TmpTransactionManagerInitialization at 0x1c00248c4 registers the "TmTm" object type:

- Name: L"TmTm"
- Body size: 960 bytes (HIDWORD(v2[5]) = 960)
- Pool type: NonPagedPoolNx (LODWORD(v2[1]) = 0x100)
- OpenProcedure: TmpOpenTransactionManager
- CloseProcedure: TmpCloseTransactionManager
- DeleteProcedure: TmpDeleteTransactionManager
- InitializeProcedure: **NONE** (memset zeroed, never set)

**Critical:** No InitializeProcedure means ObCreateObject allocates 960 bytes but does NOT zero the body.

### Object Creation Flow

NtCreateTransactionManager -> ObCreateObject(960 bytes, NOT zeroed) -> TmInitializeTransactionManagerExt (initializes ~787 bytes) -> ObInsertObject

### Full Layout With All Initialization

| Offset | Size | Field | Init By | Status |
|---|---|---|---|---|
| 0x000 | 4 | Type tag (DWORD) | TmInit | INIT |
| 0x004 | 4 | Padding | - | UNINIT (never accessed) |
| 0x008 | 56 | KMUTEX | TmInit: KeInitializeMutex | INIT |
| 0x040 | 4 | State (DWORD) | NtCreate=0, TmInit=1 | INIT |
| 0x044 | 4 | Padding | - | UNINIT (never accessed) |
| 0x048 | 8 | VirtualClock (QWORD) | TmInit: =0 | INIT |
| 0x050 | 24 | Unknown fields | - | UNINIT (never accessed) |
| 0x068 | 1 | ConsoleFlags (BYTE) | TmInit: =0 | INIT |
| 0x069 | 7 | Padding | - | UNINIT (never accessed) |
| 0x070 | 16 | TmIdentity (GUID) | TmInit: ExUuidCreate | INIT |
| 0x080 | 8 | Flags (QWORD) | TmInit: =0, then ORed | INIT |
| 0x088 | 2 | LogFileName.Length | TmInit: =0 | INIT |
| 0x08A | 2 | LogFileName.MaxLength | TmInit: =0 | INIT |
| 0x08C | 4 | UNICODE_STRING padding | - | UNINIT (never accessed) |
| 0x090 | 8 | LogFileName.Buffer | TmInit: =0 | INIT |
| 0x098 | 8 | LogFileObject | TmInit: =0, TmpCreateLogFile | INIT |
| 0x0A0 | 8 | MarshallingArea | TmInit: =0, TmpCreateLogFile | INIT |
| 0x0A8 | 8 | LogManagementClient | TmInit: =0, TmpRegister | INIT |
| 0x0B0 | 104 | Namespace1 AVL_TABLE | TmInit: RtlInitGenericTableAvl | INIT |
| 0x118 | 56 | Namespace1 KMUTEX | TmInit: KeInitializeMutex | INIT |
| 0x150 | 5 | Namespace1 extras | TmpNamespaceInitialize | INIT |
| 0x155 | 3 | Padding | - | UNINIT (never accessed) |
| 0x158 | 104 | Namespace2 AVL_TABLE | TmInit: RtlInitGenericTableAvl | INIT |
| 0x1C0 | 56 | Namespace2 KMUTEX | TmInit: KeInitializeMutex | INIT |
| 0x1F8 | 5 | Namespace2 extras | TmpNamespaceInitialize | INIT |
| 0x1FD | 3 | Padding | - | UNINIT (never accessed) |
| 0x200 | 56 | KMUTEX (TxTable) | TmInit: KeInitializeMutex | INIT |
| 0x238 | 8 | TxListHead.Flink | TmInit: =&TM+568 | INIT |
| 0x240 | 8 | TxListHead.Blink | TmInit: =&TM+568 | INIT |
| 0x248 | 8 | TxListCount | TmInit: =1 | INIT |
| 0x250 | 4 | Unknown DWORD | TmInit: =1 | INIT |
| 0x254 | 4 | Padding | - | UNINIT (never accessed) |
| 0x258 | 8 | Unknown QWORD | TmInit: =0 | INIT |
| 0x260 | 4 | Unknown DWORD | TmInit: =0 | INIT |
| 0x264 | 4 | Padding | - | UNINIT (never accessed) |
| 0x268 | 24 | KEVENT (TxTable) | TmInit: KeInitializeEvent | INIT |
| 0x280 | 8 | Unknown | - | UNINIT (never accessed) |
| 0x288 | 8 | CLFS_LSN (BaseLsn) | TmInit: NULL, TmpCreateLogFile | INIT |
| 0x290 | 8 | CLFS_LSN (LastLsn) | TmInit: NULL, TmpCreateLogFile | INIT |
| 0x298 | 8 | CLFS_LSN (CurrentLsn) | TmInit: NULL | INIT |
| 0x2A0 | 8 | InternalRM Handle | TmInit: =0, ZwCreateRM | INIT |
| 0x2A8 | 8 | InternalRM Object | TmInit: =0, ObRefByHandle | INIT |
| 0x2B0 | 24 | KEVENT (LogFull) | TmInit: KeInitializeEvent | INIT |
| 0x2C8 | 32 | WQI1 (Checkpoint) | TmpQueueCheckpointTm | RUNTIME |
| 0x2E8 | 8 | CLFS_LSN (AdvanceTail) | TmpAdvanceBaseLsnNotif | RUNTIME |
| 0x2F0 | 32 | WQI2 (LogFull) | TmpLogGrowthCompletedNotif | RUNTIME |
| 0x310 | 104 | ERESOURCE | TmInit: ExInitResource | INIT |
| 0x378 | 4 | Flags2 (DWORD) | TmInit: =0 | INIT |
| 0x37C | 8 | LogFullStatus | TmInit: =0 | INIT |
| 0x384 | 4 | Padding | - | UNINIT (never accessed) |
| 0x388 | 8 | CLFS_LSN (RecoveryLsn) | TmInit: NULL | INIT |
| 0x390 | 8 | LsnListHead.Flink | TmInit: =&TM+912 | INIT |
| 0x398 | 8 | LsnListHead.Blink | TmInit: =&TM+912 | INIT |
| 0x3A0 | 32 | WQI3 (Offline) | TmpQueueOfflineTm | RUNTIME |

### Uninitialized Gap Summary

11 gaps totaling 69 bytes -- truly never accessed by any tm.sys code:

| # | Range | Size | Description |
|---|---|---|---|
| 1 | 0x004-0x007 | 4 | Padding (Type to KMUTEX) |
| 2 | 0x044-0x047 | 4 | Padding (KMUTEX to State) |
| 3 | 0x050-0x067 | 24 | Unknown -- no tm.sys code reads or writes |
| 4 | 0x069-0x06F | 7 | Padding (ConsoleFlags to GUID) |
| 5 | 0x08C-0x08F | 4 | UNICODE_STRING alignment padding |
| 6 | 0x155-0x157 | 3 | Padding after namespace1 |
| 7 | 0x1FD-0x1FF | 3 | Padding after namespace2 |
| 8 | 0x254-0x257 | 4 | Padding (DWORD to QWORD) |
| 9 | 0x264-0x267 | 4 | Padding (DWORD to KEVENT) |
| 10 | 0x280-0x287 | 8 | Unknown -- no tm.sys code reads or writes |
| 11 | 0x384-0x387 | 4 | Padding (QWORD to CLFS_LSN) |

4 ranges totaling 104 bytes -- runtime-initialized by callbacks before use:

| # | Range | Size | Description | Written By |
|---|---|---|---|---|
| 1 | 0x2C8-0x2E7 | 32 | Checkpoint WORK_QUEUE_ITEM | TmpQueueCheckpointTm |
| 2 | 0x2E8-0x2EF | 8 | CLFS_LSN (AdvanceTailLsn) | TmpAdvanceBaseLsnRequiredNotification |
| 3 | 0x2F0-0x30F | 32 | LogFullCompleted WORK_QUEUE_ITEM | TmpLogGrowthCompletedNotification |
| 4 | 0x3A0-0x3BF | 32 | Offline WORK_QUEUE_ITEM | TmpQueueOfflineTm |

Total uninitialized after TmInit: 173 bytes across 15 ranges

---

## 2. Code Paths That Read From Uninitialized Regions

### 2.1 TmpCheckpoint (0x1c000c690) -- READS 0x2E8 as CLFS_LSN

Decompilation key excerpt:

```c
__int64 __fastcall TmpCheckpoint(__int64 a1, unsigned __int8 a2)
{
    // a2 is the "forced checkpoint" flag from bit 3 at offset 0x84
    if ( v2 )  // v2 = a2
    {
        // READ FROM OFFSET 0x2E8 (a1 + 744)
        v21 = *(CLFS_LSN *)(a1 + 744);   // 0x1c000ccb4
        BaseLsn = v21;                     // Copy to local

        // WPP tracing uses v21 -- kernel-internal only
        if (WPP_GLOBAL_Control != &WPP_GLOBAL_Control && ...)
            WPP_SF_qi(..., a1, (CLFS_LSN)v21.ullOffset);
    }
    else
    {
        // a2=0 path: uses log file BaseLsn instead
        BaseLsn = pinfoBuffer.BaseLsn;
    }

    // COMPARISON: Is plsn2 < BaseLsn?
    if ( ClfsLsnLess(&plsn2, &BaseLsn) )   // 0x1c000cd10
    {
        if ( (*(_DWORD *)(a1 + 128) & 0x40) == 0 )
        {
            if ( v2 )
                ClfsMgmtTailAdvanceFailure(*(CLFS_MGMT_CLIENT *)(a1 + 168), -1072037844);
            goto LABEL_73;  // Exit -- no write to kernel address
        }

        // If flag 0x40 IS set: iterate LSN list, adjust plsn2
        // ... list traversal at a1+912 ...
    }

    // WRITE: plsn2 written to offset 0x288 (already initialized field)
    *(CLFS_LSN *)(a1 + 648) = plsn2;       // 0x1c000cf78

    // ... also calls TmpWriteRestartArea(a1, &plsn2, v22) ...
}
```

Analysis of the 0x2E8 read:

- Used as pointer? NO. Used as CLFS_LSN in ClfsLsnLess comparison.
- Used as offset? NO. Compared as whole LSN value.
- Used in comparison that changes control flow? YES. ClfsLsnLess determines branch.
- Passed to function that writes through it? NO. TmpWriteRestartArea gets plsn2, not BaseLsn.

**Verdict: LOGIC BUG (control flow influence), NOT write-what-where.**

### 2.2 TmpAdvanceBaseLsnRequiredNotification (0x1c000c660) -- WRITES 0x2E8 before read

```c
__int64 __fastcall TmpAdvanceBaseLsnRequiredNotification(__int64 a1, _QWORD *a2, __int64 a3)
{
    // WRITES to offset 0x2E8 BEFORE setting the flag that triggers the read
    *(_QWORD *)(a3 + 744) = *a2;                              // 0x1c000c667
    _InterlockedOr((volatile signed __int32 *)(a3 + 132), 8u); // 0x1c000c66e
    TmpQueueCheckpointTm(a3);                                   // 0x1c000c67a
    return 259;
}
```

This is the ONLY function that sets bit 3 (0x08) at offset 0x84, which triggers a2=1 in TmpCheckpoint. The write to 0x2E8 happens BEFORE the bit set, BEFORE the checkpoint is queued, BEFORE TmpCheckpoint runs.

### 2.3 TmpCheckpointWorker (0x1c000d200) -- Triggers the read path

```c
LONG_PTR __fastcall TmpCheckpointWorker(volatile signed __int32 *Object)
{
    _InterlockedAnd(Object + 33, 0xFFFFFFFE);   // Clear bit 0 at 0x84
    _m_prefetchw((const void *)(Object + 33));
    // Check if bit 3 was set, clear it, pass as a2
    TmpCheckpoint((__int64)Object, (_InterlockedAnd(Object + 33, 0xFFFFFFF7) & 8) != 0);
    return ObfDereferenceObject((PVOID)Object);
}
```

Object + 33 = Object + 33*4 = Object + 132 = Object + 0x84

### 2.4 TmpTmOffline (0x1c001d250) -- Calls TmpCheckpoint with a2=0

```c
if ( (*(_DWORD *)(a1 + 128) & 1) == 0 )
{
    TmpCheckpoint(a1, 0);  // a2=0 -- does NOT read 0x2E8
}
```

### 2.5 TmpLogGrowthCompletedNotification (0x1c000d2f0) -- Second WORK_QUEUE_ITEM at 0x2F0

```c
void __fastcall TmpLogGrowthCompletedNotification(__int64 a1, int a2, char a3, __int64 a4)
{
    *(_DWORD *)(a4 + 892) = a2;                    // 0x37C
    _InterlockedOr((volatile signed __int32 *)(a4 + 132), a3 != 0 ? 6 : 2);
    if ( !a3 )
        _InterlockedAnd((volatile signed __int32 *)(a4 + 132), 0xFFFFFFFB);

    // Second WORK_QUEUE_ITEM at 0x2F0
    *(_QWORD *)(a4 + 752) = 0;                     // 0x2F0 = Flink
    *(_QWORD *)(a4 + 768) = TmpLogFullCompletedWorker;  // 0x300
    *(_QWORD *)(a4 + 776) = a4;                    // 0x308
    ExQueueWorkItem((PWORK_QUEUE_ITEM)(a4 + 752), DelayedWorkQueue);
}
```

### 2.6 TmpQueueOfflineTm (0x1c001cf98) -- Third WORK_QUEUE_ITEM at 0x3A0

```c
void __fastcall TmpQueueOfflineTm(struct _WORK_QUEUE_ITEM *a1)
{
    // a1[29] = a1 + 29*32 = a1 + 928 = a1 + 0x3A0
    if ( (_InterlockedOr((volatile signed __int32 *)&a1[4].List.Flink + 1, 0x10u) & 0x10) == 0 )
    {
        v1 = a1 + 29;
        a1[29].List.Flink = NULL;                  // 0x3A0
        a1[29].WorkerRoutine = TmpOfflineWorker;   // 0x3B0
        a1[29].Parameter = a1;                     // 0x3B8
        ObfReferenceObject(a1);
        ExQueueWorkItem(v1, DelayedWorkQueue);
    }
}
```

### 2.7 All Other Functions Examined -- No Uninitialized Reads

| Function | Address | Uninit Gap Read? |
|---|---|---|
| TmpWriteRestartArea | 0x1c000d3a4 | NO |
| TmpCreateLogFile | 0x1c000db98 | NO |
| TmpRegisterForLogManagement | 0x1c000fd04 | NO |
| TmpRecover | 0x1c000e6d4 | NO |
| TmRecoverTransactionManagerExt | 0x1c000d850 | NO |
| NtQueryInformationTMExt | 0x1c001f2e0 | NO |
| NtSetInformationTMExt | 0x1c001fc90 | NO |
| TmpCloseTransactionManager | 0x1c001b0e0 | NO |
| TmpDeleteTransactionManager | 0x1c001b800 | NO |
| TmpCheckForProgressTM | 0x1c001b024 | NO |
| TmpFreezeThawTM | 0x1c001c0c0 | NO |
| TmpTmOffline | 0x1c001d250 | NO |
| TmpFinalizeTransaction | 0x1c0014cd0 | NO |
| TmpLogFullCompletedWorker | 0x1c000d260 | NO |
| TmpHeuristicAbortAfterCheckpoint | 0x1c001c210 | NO |
| TmpTransactionManagerInitialization | 0x1c00248c4 | NO |

### 2.8 Byte Pattern Searches

- 0x280 (640): Searched byte pattern 80 02 00 00 -- zero matches in code segments
- 0x3A0 (928): Searched A0 03 00 00 -- one match in TmpQueueOfflineTm (writes, not reads uninit)
- 0x050 (80): No function decompilation shows access to offsets 0x50-0x67

---

## 3. Write-Through-Uninit Analysis

| Path | Offset | Pointer? | Offset? | Comparison? | Write Func? | WWW? |
|---|---|---|---|---|---|---|
| TmpCheckpoint (a2=1) | 0x2E8 | NO | NO | YES (ClfsLsnLess) | NO | NO |

Detailed flow of TmpCheckpoint 0x2E8 read:

1. v21 = *(CLFS_LSN *)(a1 + 744) -- reads 8 bytes at 0x2E8
2. BaseLsn = v21 -- copies to local
3. ClfsLsnLess(&plsn2, &BaseLsn) -- comparison only, no dereference
4. If true: may call ClfsMgmtTailAdvanceFailure (error code, not BaseLsn)
5. May iterate LSN list at 0x390/0x398 (list entries, not BaseLsn as pointer)
6. May call TmpWriteRestartArea(a1, &plsn2, v22) -- passes plsn2, not BaseLsn
7. Writes *(CLFS_LSN *)(a1 + 648) = plsn2 -- writes plsn2 to 0x288, not through BaseLsn

The uninitialized value at 0x2E8 is NEVER used as a pointer. It only affects branch selection.

### Why 0x2E8 Is Not Truly Uninitialized At Read Time

Timeline:
1. TmpAdvanceBaseLsnRequiredNotification fires
   - WRITES *a2 to 0x2E8 (0x1c000c667)
   - SETS bit 3 at 0x84 (0x1c000c66e)
   - Calls TmpQueueCheckpointTm (0x1c000c67a)
2. Worker thread runs TmpCheckpointWorker
   - Clears bit 0, checks bit 3 -> SET
   - Calls TmpCheckpoint(a1, 1)
3. TmpCheckpoint reads 0x2E8 -- was written in step 1

No code path sets bit 3 without also writing to 0x2E8.

---

## 4. Pool Spray Feasibility Analysis

### LFH Bucket Alignment

- KTM body: 960 bytes -> NonPagedPoolNx LFH bucket 1024
- Named pipe buffers: user-controlled size -> can target bucket 1024
- Confirmed: named pipe spray at LFH bucket 1024 works for NonPagedPoolNx

### Spray Strategy

1. Create named pipes with buffer size in [897, 1024] range -> LFH bucket 1024
2. Write controlled data including fake CLFS_LSN at position for 0x2E8
3. Close some pipes to free buffers
4. NtCreateTransactionManager -> ObCreateObject(960) -> reuses freed pipe buffer
5. Uninitialized bytes contain pipe buffer remnants

### Why Pool Spray Does NOT Yield a Write Primitive

1. TmpAdvanceBaseLsnRequiredNotification overwrites 0x2E8 before TmpCheckpoint reads it
2. The value is used as comparison, not pointer -- controls branch, not write address
3. Write target (0x288) is fixed offset in KTM -- value written is plsn2 from list traversal
4. 69 bytes of never-accessed gaps cannot be exploited -- no code reads them
5. 104 bytes of runtime-init fields are always overwritten by callbacks before use

---

## 5. Exploit Chain Assessment

### Attempted Chain: Pool Spray -> Controlled 0x2E8 -> TmpCheckpoint Logic Bug

Step 1: Spray NonPagedPoolNx bucket 1024 with named pipes
Step 2: Free some pipe buffers
Step 3: NtCreateTransactionManager -> reuses freed buffer
Step 4: Trigger checkpoint with a2=1 -> requires TmpAdvanceBaseLsnRequiredNotification
        -> Which ALSO writes to 0x2E8, overwriting sprayed value
Step 5: TmpCheckpoint reads CLFS callback value, not sprayed value
Step 6: Even with control, value is used in ClfsLsnLess comparison -> branch selection only

**CHAIN BROKEN at Step 4:** The callback that enables the read path also overwrites the target byte.

### No Alternative Write Path Found

- No function reads any uninitialized gap value as a pointer
- No function passes an uninitialized gap value to a write operation
- No function uses an uninitialized gap value as an array index or offset
- The 69 bytes of truly never-accessed gaps are inert padding

---

## 6. Complete Decompilation Index

All decompiled functions with relevant excerpts:

### TmpCheckpoint (0x1c000c690) -- size 0xB5E
- Reads 0x2E8 as CLFS_LSN when a2=1 (bit 3 at 0x84 set)
- Uses in ClfsLsnLess comparison only
- Writes plsn2 to 0x288 (initialized field)
- Calls TmpWriteRestartArea with plsn2 (not BaseLsn)

### TmpAdvanceBaseLsnRequiredNotification (0x1c000c660) -- size 0x2A
- Writes *a2 to offset 0x2E8
- Sets bit 3 (0x08) at offset 0x84
- Calls TmpQueueCheckpointTm

### TmpCheckpointWorker (0x1c000d200) -- size 0x4F
- Clears bit 0 at 0x84
- Checks/clears bit 3 at 0x84
- Calls TmpCheckpoint with a2 = (bit 3 was set)

### TmpQueueCheckpointTm (0x1c001cf24) -- size 0x6D
- Sets bit 0 at 0x84
- Writes WORK_QUEUE_ITEM at 0x2C8 (Flink=0, Worker=TmpCheckpointWorker, Param=self)
- Calls ExQueueWorkItem

### TmpLogGrowthCompletedNotification (0x1c000d2f0)
- Writes WORK_QUEUE_ITEM at 0x2F0 (Flink=0, Worker=TmpLogFullCompletedWorker, Param=self)
- Sets bits 1,2 at 0x84
- Calls ExQueueWorkItem

### TmpQueueOfflineTm (0x1c001cf98) -- size 0x67
- Sets bit 4 (0x10) at 0x84
- Writes WORK_QUEUE_ITEM at 0x3A0 (Flink=0, Worker=TmpOfflineWorker, Param=self)
- Calls ExQueueWorkItem

### TmpWriteRestartArea (0x1c000d3a4)
- Receives plsn2 (not BaseLsn)
- Calls ClfsWriteRestartArea with plsn2
- Does NOT use 0x2E8 value

### NtCreateTransactionManagerExt (0x1c001ebf0) -- size 0x328
- Calls ObCreateObject with 960 bytes
- Sets 0x40 = 0
- Calls TmInitializeTransactionManagerExt
- Calls ObInsertObject

### TmInitializeTransactionManagerExt (0x1c001a820) -- size 0x3F2
- Initializes ~787 bytes of 960-byte body
- Key initializations: KMUTEX x3, KEVENT x2, ERESOURCE x1, RTL_AVL_TABLE x2
- CLFS_LSN_NULL x4, GUID, flags, list heads, QWORDs

### TmpTransactionManagerInitialization (0x1c00248c4) -- size 0xE3
- Registers TmTm object type with ObCreateObjectType
- Body size = 960, No InitializeProcedure
- Pool type = NonPagedPoolNx

### TmpCreateLogFile (0x1c000db98) -- size 0x80C
- Creates CLFS log file, marshalling area
- Overwrites 0x288 and 0x290 with actual LSN values
- Does not access uninitialized gaps

### TmpRecover (0x1c000e6d4)
- Reads log records for recovery
- Accesses 0x290, 0xA0, 0x398, 0x390, 0x84, 0x98, 0x298, 0x248
- No uninitialized gap access

---

## 7. Conclusion

The _KTM object has 173 bytes uninitialized after TmInitializeTransactionManagerExt (69 bytes truly never accessed + 104 bytes runtime-initialized by callbacks). The most promising target -- the CLFS_LSN at offset 0x2E8 read by TmpCheckpoint -- is:

1. Always written by TmpAdvanceBaseLsnRequiredNotification before being read
2. Used as a comparison value (ClfsLsnLess), not as a pointer
3. Cannot yield a write-what-where primitive even if controlled via pool spray

No write-what-where primitive exists through the uninitialized bytes in _KTM. The investigation confirms that while the TmTm object type lacks an InitializeProcedure (leaving the body unzeroed), the runtime callback architecture ensures that all readable uninitialized fields are written before use, and no uninitialized value is ever dereferenced as a pointer.
