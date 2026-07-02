# fltMgr.sys (Filter Manager) Vulnerability Analysis

## 1. Binary Survey

| Field | Value |
|-------|-------|
| **Path** | C:\Windows\System32\drivers\fltMgr.sys |
| **Architecture** | x64 |
| **Base Address** | 0x1C0000000 |
| **Image Size** | 0x6D000 (444 KB) |
| **MD5** | cd2ab114b91e7abf8bf529505bc5be30 |
| **Total Functions** | 1000 (993 named, 7 library, 0 unnamed) |
| **Total Strings** | 645 |
| **Segments** | 12 |

### Segment Layout
| Segment | Start | End | Size | Perm |
|---------|-------|-----|------|------|
| .text | 0x1C0001000 | 0x1C001B000 | 0x1A000 | rx |
| .rdata | 0x1C001B000 | 0x1C0028000 | 0xD000 | r |
| .data | 0x1C0028000 | 0x1C002B000 | 0x3000 | rw |
| PAGE | 0x1C0034000 | 0x1C005A000 | 0x26000 | rx |
| PAGEVRF2 | 0x1C005A000 | 0x1C005E000 | 0x4000 | rx |
| PAGEVRF1 | 0x1C005E000 | 0x1C0061000 | 0x3000 | rx |

### Key Imports
- ExAllocatePoolWithTag, ExFreePoolWithTag (pool allocation)
- ExAllocateFromNPagedLookasideList, ExFreeToNPagedLookasideList (lookaside)
- ExpInterlockedPopEntrySList (SLIST for per-CPU lookaside)
- MmProbeAndLockProcessPages, MmMapLockedPagesSpecifyCache (MDL handling)
- IoCsqInsertIrpEx, IoCsqRemoveNextIrp (cancel-safe IRP queue)
- ExAcquireFastMutex, ExAcquireRundownProtection (synchronization)
- ProbeForRead, ProbeForWrite (user buffer probing)

---

## 2. User-Mode-Reachable Interfaces and IOCTL Handlers

### 2.1 Dispatch Architecture

FltpDispatch (0x1C00049A0) routes IRPs based on target device object:
- **Control device** (DeviceObject global) -> FltpControlDispatch (0x1C000BCE0) -> FltpCommonDeviceControl (0x1C0041D88)
- **Message port device** (qword_1C0029878) -> FltpMsgDispatch (0x1C0041630)
- **Volume device** (type 0xF106) -> passthrough to filesystem

### 2.2 Communication Port IOCTLs (METHOD_NEITHER - CRITICAL)

All three IOCTLs use METHOD_NEITHER: user-mode buffer addresses passed directly to driver without I/O manager copying or probing.

| IOCTL Code | Hex | Function | User API | Method | Access |
|-----------|-----|----------|----------|--------|--------|
| 540703 | 0x8401F | FltpGetMessage | FilterGetMessage | METHOD_NEITHER | FILE_READ |
| 557083 | 0x8801B | FltpFilterMessage | FilterSendMessage | METHOD_NEITHER | FILE_WRITE |
| 557091 | 0x88023 | FltpFilterReply | FilterReplyMessage | METHOD_NEITHER | FILE_WRITE |

IOCTL Decode: DeviceType=0x8 (FILE_DEVICE_FILE_SYSTEM), Functions 0x6/0x7/0x8, Method=3 (NEITHER)

#### 2.2.1 FltpMsgDispatch (0x1C0041630) - Entry Point

```c
int __fastcall FltpMsgDispatch(__int64 a1, IRP *a2)
{
    CurrentStackLocation = a2->Tail.Overlay.CurrentStackLocation;
    MajorFunction = CurrentStackLocation->MajorFunction;

    if (MajorFunction == 14)  // IRP_MJ_DEVICE_CONTROL
    {
        LowPart = CurrentStackLocation->Parameters.Read.ByteOffset.LowPart;

        // METHOD_NEITHER: extract user buffers
        if ((LowPart & 3) == 3) {
            Parameters = CurrentStackLocation->Parameters.CreatePipe.Parameters; // Type3InputBuffer
            UserBuffer = a2->UserBuffer;  // OutputBuffer
        }

        Length = CurrentStackLocation->Parameters.Read.Length;     // OutputBufferLength
        Options = CurrentStackLocation->Parameters.Create.Options; // InputBufferLength

        // Validate FsContext2 is FltCcb (magic 0xF10D)
        v11 = *(_WORD **)(FileObject + 32);
        if (!v11 || *v11 != 0xF10D)
            return STATUS_INVALID_DEVICE_REQUEST;

        if (LowPart == 540703)        // IOCTL_FILTER_GET_MESSAGE
            result = FltpGetMessage(FileObject, (__int64)a2);
        else if (LowPart == 557083)   // IOCTL_FILTER_SEND_MESSAGE
        {
            if (Parameters && Options)  // Only non-zero check!
                result = FltpFilterMessage(FileObject, Parameters, Options,
                                          UserBuffer, Length, &v16,
                                          a2->RequestorMode == 0);
        }
        else if (LowPart == 557091)   // IOCTL_FILTER_REPLY_MESSAGE
            result = FltpFilterReply(FileObject, Parameters, Options,
                                    &v16, a2->RequestorMode == 0);
    }
    else if (MajorFunction == 0)  // IRP_MJ_CREATE
        result = FltpOpenClientPort(FileObject, a2);
    else if (MajorFunction == 2)  // IRP_MJ_CLOSE
    {
        FsContext2 = FileObject->FsContext2;
        ObfDereferenceObject(FsContext2[1]);
        FltpFreeFltCcb(FsContext2);
    }
    else if (MajorFunction == 18) // IRP_MJ_CLEANUP
        FltpCleanupCommunicationPort(FileObject);
}
```

Key: Only validation before FltpFilterMessage is `Parameters && Options` (non-zero). No size validation.

#### 2.2.2 FltpFilterMessage (0x1C000BBB0) - Send Message to Minifilter

```c
__int64 __fastcall FltpFilterMessage(
    __int64 a1, volatile void *a2, unsigned int a3,
    volatile void *a4, unsigned int Length, __int64 a6, char a7)
{
    v10 = *(_QWORD *)(a1 + 32);                     // FltCcb
    v11 = *(_QWORD *)(*(_QWORD *)(v10 + 8) + 16);  // Server port
    v12 = *(MessageNotifyCallback)(v11 + 32);       // Minifilter callback

    if (!v12) return STATUS_NOT_SUPPORTED;

    if (!a7) {  // User mode
        ProbeForRead(a2, a3, 1u);
        ProbeForWrite(a4, Length, 1u);
    }

    if (FltObjectReference(*(PVOID *)(v11 + 40)) < 0)
        return STATUS_PORT_DISCONNECTED;

    if (ExAcquireRundownProtection(...)) {
        // TOCTOU WINDOW: user can remap/unmap probed pages
        v13 = v12(..., a2, a3, a4, Length, a6);  // Callback with user buffers
        ExReleaseRundownProtection(...);
    }
    return v13;
}
```

Vulnerability: METHOD_NEITHER + ProbeForRead/Write + callback with user addresses. User can remap between probe and callback access.

#### 2.2.3 FltpFilterReply (0x1C000B9BC) - Reply to Minifilter

```c
__int64 __fastcall FltpFilterReply(
    __int64 a1, _QWORD *a2, unsigned int a3, unsigned int *a4, char a5)
{
    if (a3 < 0x10) return STATUS_INVALID_PARAMETER;  // Min 16 bytes

    if (!a5) ProbeForRead(a2, a3, 4u);
    v9 = a2[1];           // ReplyId at offset 8
    v10 = *(_DWORD *)a2;  // Status at offset 0

    v11 = *(_QWORD *)(a1 + 32);  // FltCcb
    ExAcquireFastMutex((PFAST_MUTEX)(v11 + 16));

    // Walk reply waiter list for matching ReplyId
    for (i = *(_QWORD **)(v11 + 72); i != (_QWORD *)(v11 + 72); i = *i) {
        v8 = i;
        if (i[2] == v9) {  // Match
            v17 = 1;
            *(_DWORD *)(v11 + 88) -= 2;  // Decrement count
            // Unlink from list
            break;
        }
    }
    ExReleaseFastMutex((PFAST_MUTEX)(v11 + 16));

    // RACE WINDOW: mutex released, reply not yet written

    if (v17) {
        v15 = a3 - 16;
        if (a3 - 16 >= *((_DWORD *)v8 + 14))
            v15 = *((_DWORD *)v8 + 14);  // Clamp to expected length

        memmove((void *)v8[6], a2 + 2, v15);  // Copy reply to waiter buffer
        *((_DWORD *)v8 + 15) = v10;  // Status
        *((_DWORD *)v8 + 14) = v15;  // Length
        KeSetEvent((PRKEVENT)v8 + 1, 0, 0);  // Signal event
    }
}
```

TOCTOU: Mutex released before memmove. FltSendMessage timeout path checks Flink==0 (already unlinked), waits for event. Currently handled correctly but fragile.

#### 2.2.4 FltSendMessage (0x1C000AEF0) - Kernel to User Message

```c
NTSTATUS __stdcall FltSendMessage(
    PFLT_FILTER Filter, PFLT_PORT *ClientPort,
    PVOID SenderBuffer, ULONG SenderBufferLength,  // OVERFLOW VECTOR
    PVOID ReplyBuffer, PULONG ReplyLength, PLARGE_INTEGER Timeout)
{
    PeekContext = SenderBufferLength + 16;  // INTEGER OVERFLOW

    v16 = IoCsqRemoveNextIrp((PIO_CSQ)(v10 + 96), &PeekContext);
    // FltpGetNextMessageWaiter: *PeekContext > IRP_buffer_size
    // If PeekContext wraps to 0, matches ANY IRP

    if (*(_DWORD *)(CurrentStackLocation + 8) >= PeekContext) {
        Mdl = IoAllocateMdl(v17->UserBuffer, PeekContext, 0, 1u, nullptr);
        MmProbeAndLockProcessPages(...);
        MappedSystemVa = MmMapLockedPagesSpecifyCache(...);

        memmove(MappedSystemVa + 2, SenderBuffer, SenderBufferLength);
        // If PeekContext=0, MDL is 0 bytes but copies SenderBufferLength bytes!
        // MASSIVE POOL OVERFLOW

        if (ReplyBuffer) {
            // Set up reply waiter on stack (v49[3] KEVENT array)
            v49[0].Blink = InterlockedIncrement64(...);  // ReplyId
            v49[2].Lock = ReplyBuffer;     // Reply buffer ptr
            v49[2].Flink_lo = *ReplyLength; // Reply length

            // Link into port reply waiter list
            ExAcquireFastMutex(v29);
            if ((v29[72] & 1) != 0) { /* disconnecting */ }
            v29[72] += 2;  // Increment waiter count
            ExReleaseFastMutex(v29);

            IofCompleteRequest(v17, 0);  // Send to user-mode
            // Wait for reply or disconnect
        }
    }
}
```

### 2.3 Control Device IOCTLs (METHOD_BUFFERED)

| IOCTL | Hex | Function | Privilege |
|-------|-----|----------|-----------|
| 540684 | 0x8400C | FltpLinkHandle | None |
| 540708 | 0x84024 | FltpFindFirst | None |
| 540712 | 0x84028 | FltpFindNext | None |
| 540716 | 0x8402C | FltpGetInformation | None |
| 557060 | 0x88004 | FltpLoadFilter | SE_LOAD_DRIVER_PRIVILEGE |
| 557064 | 0x88008 | FltpUnloadFilter | SE_LOAD_DRIVER_PRIVILEGE |
| 557072 | 0x88010 | FltpAttachVolume | None |
| 557076 | 0x88014 | FltpDetachVolume | None |

FltpLinkHandle has extensive bounds checking on all user-provided offsets and lengths.

---

## 3. Pool Allocations

### 3.1 NonPagedPoolNx (Exploit Targets)

| Tag | Hex | Function | Size | User-Reachable |
|-----|-----|----------|------|----------------|
| FMic | 0x63694D46 | FltpAllocateIrpCtrlInternal | (depth*128)+392 | Indirect (file I/O) |
| FMil | 0x6C694D46 | FltpExtendIrpCtrl | depth*128 | Indirect |
| FMcp | 0x70634D46 | FltpOpenClientPort | 16 | YES |
| FMcb | 0x62634D46 | FltpAllocateFltCcb | a2+96 (default 96) | YES |
| FMct | 0x74634D46 | FltpAllocateCompletionNodeTracking | Variable | Indirect |

### 3.2 IrpCtrl Size Table (FMic, NonPagedPoolNx)

| Depth | Size | Hex | LFH Bucket |
|-------|------|-----|------------|
| 0 | 392 | 0x188 | 400 |
| 1 | 520 | 0x208 | 528 |
| 2 | 648 | 0x288 | 656 |
| 3 | 776 | 0x308 | 784 |
| 4 | 904 | 0x388 | 912 |
| 5 | 1032 | 0x408 | 1536 (tier 2) |
| 6 | 1160 | 0x488 | 1536 |
| 7 | 1288 | 0x508 | 1536 |
| 8 | 1416 | 0x588 | 1536 |

Base structure = 392 bytes, per-depth node = 128 bytes, nodes start at offset 384.

### 3.3 PagedPool Allocations

| Tag | Function | Size |
|-----|----------|------|
| FMcb | FltpAllocateFltCcb (PagedPool variant) | a2+96 |
| FMfn | FltpAllocateFileNameInformation | Variable |
| FMtn | FltpSaveFileObjectFileName | 0x70 (112) |
| FMvo | FltpInitVolume | Variable |
| FMfl | FltRegisterFilter | Variable |
| FMdh | FltpGenerateDeviceHintEcp | 0x58 (88) |
| FMus | FltpCopyUnicodeString | Variable |
| FMrp | FltTagFile | Variable |

### 3.4 Lookaside List Behavior

IrpCtrl uses per-CPU SLIST lookaside lists:
- Two lists per CPU (split by depth threshold)
- Verifier-off: size check on recycled entries SKIPPED
- Smaller IrpCtrl can be reused for larger operation without validation
- Mitigated by Blink adjustment and FltpExtendIrpCtrl separate allocation

---

## 4. Vulnerability Primitives

### 4.1 INTEGER OVERFLOW: FltSendMessage PeekContext [HIGH]

Location: 0x1C000B013
Code: `PeekContext = SenderBufferLength + 16`

- PeekContext is ULONG (32-bit)
- SenderBufferLength >= 0xFFFFFFF0 wraps to 0
- FltpGetNextMessageWaiter: `0 > buffer_size` always FALSE -> matches first IRP
- IoAllocateMdl(UserBuffer, 0) -> zero-length MDL
- memmove(MappedSystemVa+2, SenderBuffer, 0xFFFFFFF0) -> ~4GB copy into 0-byte mapping
- Result: Massive NonPagedPoolNx overflow

Reachability: Kernel-mode (minifilter API). Needs vulnerable/malicious minifilter or SE_LOAD_DRIVER_PRIVILEGE to load one.

### 4.2 TOCTOU RACE: FltpFilterReply [MEDIUM]

Location: 0x1C000BABB
Mutex released before memmove to reply buffer. Waiter struct on FltSendMessage stack. Currently handled correctly (FltSendMessage waits for event on timeout). Fragile pattern. Low exploitability for 8-byte write.

### 4.3 METHOD_NEITHER TOCTOU: FltpFilterMessage [MEDIUM]

Location: 0x1C000BBF3
ProbeForRead/Write then callback with user addresses. User can remap between probe and callback. Requires minifilter without try/except. Not direct kernel write.

### 4.4 IRPCTL LOOKASIDE SIZE MISMATCH [MEDIUM-HIGH]

Location: 0x1C0007DD9
Without verifier, lookaside entries reused without size check. Mitigated by depth adjustment and extension allocation. Potential pool overflow if code writes per-depth nodes beyond allocation.

### 4.5 FltpTranslateIoctlDataBuffers [LOW-MEDIUM]

Location: 0x1C003AC94
For METHOD_NEITHER IOCTLs, stores raw user pointers (Type3InputBuffer, UserBuffer) in callback data. Minifilters accessing these without probing risk user-controlled kernel reads/writes.

---

## 5. LFH Bucket Analysis

| Target Bucket | Range | fltMgr.sys Allocations |
|---------------|-------|------------------------|
| 640 (625-640) | 625-640 | None directly. IrpCtrl depth=2=648 (bucket 656) |
| 1024 (1009-1024) | 1009-1024 | None directly. IrpCtrl depth=5=1032 (tier 2: 1536) |

No fltMgr.sys allocations fall exactly in target LFH buckets 640 or 1024. The IrpCtrl sizes skip past these ranges. The FMcb (96 bytes) and FMcp (16 bytes) are in small buckets.

For LFH heap spray into target buckets, consider cross-driver pool corruption: if another driver allocates in the 640 or 1024 bucket, corrupting an adjacent fltMgr.sys allocation (or vice versa) could provide the write primitive.

---

## 6. Most Promising Attack Vectors (Ranked)

### Rank 1: FltSendMessage Integer Overflow (via minifilter)
- **Severity:** HIGH
- **Type:** Pool overflow in NonPagedPoolNx
- **Primitive:** Arbitrary length write to mapped MDL pages
- **Reachability:** Requires minifilter calling FltSendMessage with SenderBufferLength >= 0xFFFFFFF0
- **Exploit path:** Load malicious minifilter via FltpLoadFilter (needs SE_LOAD_DRIVER_PRIVILEGE = admin), or corrupt a legitimate minifilter's SenderBufferLength via a separate vulnerability
- **8-byte write feasibility:** YES - controlled overflow into adjacent NonPagedPoolNx blocks can overwrite pool metadata or adjacent object fields

### Rank 2: IrpCtrl Lookaside Size Mismatch
- **Severity:** MEDIUM-HIGH
- **Type:** Pool overflow via lookaside recycling without size check
- **Primitive:** Write per-depth callback data nodes beyond allocation boundary
- **Reachability:** Indirect - triggered by file I/O through filter stack with multiple minifilters
- **Exploit path:** Create depth mismatch by loading/unloading minifilters to populate lookaside with wrong-size entries, then trigger file I/O that uses the recycled entry
- **8-byte write feasibility:** POTENTIAL - if callback data write at offset > allocation size reaches adjacent pool block

### Rank 3: METHOD_NEITHER Buffer TOCTOU (FltpFilterMessage)
- **Severity:** MEDIUM
- **Type:** User buffer remapping between probe and callback use
- **Primitive:** Unhandled kernel access violation or write to remapped page
- **Reachability:** Direct user-mode via FilterSendMessage IOCTL 0x8801B
- **Exploit path:** Open communication port, send IOCTL with buffer, remap buffer between probe and callback, cause kernel fault or write to controlled page
- **8-byte write feasibility:** LOW - depends on minifilter callback behavior, not fltMgr.sys itself

### Rank 4: FltpFilterReply TOCTOU Race
- **Severity:** MEDIUM
- **Type:** Race condition in reply waiter handling
- **Primitive:** Potential UAF on stack-based waiter struct
- **Reachability:** Direct user-mode via FilterReplyMessage IOCTL 0x88023 + timing
- **Exploit path:** Send reply while FltSendMessage times out, race the mutex release
- **8-byte write feasibility:** LOW - currently handled correctly, waiter on stack not pool

### Rank 5: FltpTranslateIoctlDataBuffers Buffer Confusion
- **Severity:** LOW-MEDIUM
- **Type:** Raw user pointers stored in callback data for METHOD_NEITHER IOCTLs
- **Primitive:** Minifilter accesses user-controlled memory from kernel context
- **Reachability:** Indirect - requires minifilter processing IOCTL callback data
- **8-byte write feasibility:** LOW - depends on minifilter, not fltMgr.sys

---

## 7. Key Function Addresses

| Function | Address | Size |
|----------|---------|------|
| FltpDispatch | 0x1C00049A0 | 0x130 |
| FltpControlDispatch | 0x1C000BCE0 | 0xFC |
| FltpMsgDispatch | 0x1C0041630 | 0x1DB |
| FltpCommonDeviceControl | 0x1C0041D88 | 0x13A |
| FltSendMessage | 0x1C000AEF0 | 0x7B3 |
| FltpFilterMessage | 0x1C000BBB0 | 0x129 |
| FltpFilterReply | 0x1C000B9BC | 0x1F4 |
| FltpGetMessage | 0x1C000B954 | 0x5F |
| FltpOpenClientPort | 0x1C0041814 | 0x4F0 |
| FltpCleanupCommunicationPort | 0x1C00420F0 | 0x112 |
| FltpDisconnectPort | 0x1C004223C | 0x7D |
| FltpPurgeMessageWaiters | 0x1C00422C0 | 0x65 |
| FltpAllocateIrpCtrlInternal | 0x1C0007D00 | 0x3A4 |
| FltpAllocateFltCcb | 0x1C0041D0C | 0x73 |
| FltpFreeFltCcb | 0x1C0042098 | 0x52 |
| FltCreateCommunicationPort | 0x1C004A830 | 0x19B |
| FltpGetNextMessageWaiter | 0x1C000C360 | 0x5B |
| FltpAddMessageWaiter | 0x1C000C0D0 | 0xEE |
| FltpRemoveMessageWaiter | 0x1C000C2C0 | 0x5F |
| FltpCancelMessageWaiter | 0x1C0018DB0 | 0x8C |
| FltpMoveIrpToCallbackData | 0x1C00080B0 | - |
| FltpTranslateIoctlDataBuffers | 0x1C003AC94 | - |
| FltpExtendIrpCtrl | 0x1C000DCA0 | - |
| FltpLinkHandle | 0x1C0041EE8 | - |
| FltpLoadFilter | 0x1C004AC70 | - |
| FltpUnloadFilter | 0x1C0058ADC | - |
| FltpAttachVolume | 0x1C0034764 | - |

---

## 8. Communication Port Lifecycle

### Connection Flow
1. Minifilter calls FltCreateCommunicationPort -> creates server port object (72 bytes, ObCreateObject)
2. User-mode calls FilterConnectCommunicationPort (IRP_MJ_CREATE to port device)
3. FltpOpenClientPort validates EA buffer ("FLTPORT" name, size checks)
4. Creates client port object (344 bytes, ObCreateObject, memset 0x158)
5. Allocates FltCcb (96 bytes, NonPagedPoolNx or PagedPool, tag FMcb)
6. Allocates connection context (16 bytes, NonPagedPoolNx, tag FMcp)
7. Calls minifilter's ConnectNotifyCallback
8. Returns handle to user-mode

### Message Flow
1. User-mode calls FilterGetMessage (IOCTL 0x8401F, METHOD_NEITHER)
   - IRP inserted into CSQ via IoCsqInsertIrpEx
   - IRP waits in queue until minifilter sends a message
2. Minifilter calls FltSendMessage
   - Dequeues IRP from CSQ (matching buffer size via PeekContext)
   - Maps user buffer via MDL (MmProbeAndLockProcessPages + MmMapLockedPagesSpecifyCache)
   - Copies sender data into mapped buffer
   - Completes IRP (user-mode receives message)
   - If reply expected: links waiter struct into port reply list, waits for event
3. User-mode calls FilterReplyMessage (IOCTL 0x88023, METHOD_NEITHER)
   - FltpFilterReply finds waiter by ReplyId
   - Copies reply data into waiter's reply buffer
   - Signals event to wake FltSendMessage

### Disconnection Flow
1. User-mode closes handle -> IRP_MJ_CLEANUP
2. FltpCleanupCommunicationPort:
   - Sets disconnecting flag at FltCcb+88
   - Calls FltpDisconnectPort: signals event, purges message IRPs from CSQ
   - Waits for rundown protection release
   - Calls DisconnectNotifyCallback
   - Completes rundown, unlinks from filter connection list
3. IRP_MJ_CLOSE:
   - ObfDereferenceObject(client port)
   - FltpFreeFltCcb (ExFreePoolWithTag, tag FMcb)

### Race Protections
- FltSendMessage holds ObfReferenceObject on FileObject -> prevents IRP_MJ_CLOSE until released
- FltpFilterMessage holds ExAcquireRundownProtection -> prevents cleanup during callback
- FltpPurgeMessageWaiters sets purge flag -> prevents new IRPs from being queued
- Disconnect event at port+312 wakes FltSendMessage from both message wait and reply wait

---

Analysis complete. fltMgr.sys provides a rich attack surface through METHOD_NEITHER IOCTLs for communication ports, with the most promising vector being the integer overflow in FltSendMessage's PeekContext calculation. The lookaside size mismatch is also notable for production (verifier-off) systems.
