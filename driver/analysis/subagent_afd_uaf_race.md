# afd.sys Connection Object UAF / Race Condition Analysis

## Binary Info
- **Module**: afd.sys (Ancillary Function Driver)
- **Base**: 0x1C0000000
- **Image Size**: 0xA7000
- **MD5**: a3f1cb8de2938baddc2c3e9824948ff2
- **Functions**: 1084 total, 1075 named

## IOCTL Dispatch Table (Confirmed)

| Index | IOCTL Code | Handler | Address |
|-------|-----------|---------|---------|
| 1 | 0x12007 | AfdConnect | 0x1C004D690 |
| 4 | 0x12010 | AfdAccept | 0x1C005BA30 |
| 32 | 0x12083 | AfdSuperAccept | 0x1C0059E40 |
| 46 | 0x120BB | AfdConnect | 0x1C004D690 |
| 49 | 0x120C7 | AfdSuperConnect | 0x1C00577B0 |
| 50 | 0x120CB | AfdSuperDisconnect | 0x1C0044B10 |
| 56 | 0x120E2 | AfdSanConnectHandler | 0x1C007D410 |

Dispatch logic: `(IoControlCode >> 2) & 0x3FF` = table index. Table at 0x1C00208A0, function pointers at 0x1C001F6A0.

## Connection Object Structure (256 bytes, 0x100)

```
Offset  Size  Field
------  ----  -----
0x00    16    SLIST_ENTRY (Next pointer + flags in HIDWORD)
0x04    4     Flags: 0x1000=connected_ref, 0x8000000=timer_wheel, 0x20000=TL, 0x100000=aborted, 0x10000=delete_pending
0x08    8     Endpoint pointer
0x10    8     File object pointer
0x18    8     Device object pointer
0x30    4     Connection reference count (32-bit interlocked) -- PRIMARY REFCOUNT
0x38    4     Additional state/flags
0x48    8     LIST_ENTRY Flink (as specified by LO)
0x50    8     LIST_ENTRY Blink
0xE8    8     Timer wheel entry (connection+232)
0xFC    4     Timer wheel tick count (connection+252)
```

## Endpoint Object Structure (Key Offsets)

```
Offset  Size  Field
0x00    2     Type (0xAFD1=datagram, 0xAFD2=connected, 0xAFD0=disconnected)
0x02    1     State byte (3=connecting, 4=connected, 6=closed)
0x30    8     KSPIN_LOCK (endpoint spinlock)
0x38    4     Endpoint primary reference count
0xB0    8     Connection pointer (endpoint+176)
0xE8    4     IRP reference count
0xF0    4     TL endpoint reference count
0x158   4     Connect-in-progress flag
```

## IRP Dispatch Lifecycle

1. **IRP_MJ_CREATE (0)**: AfdCreate - creates endpoint
2. **IRP_MJ_DEVICE_CONTROL (14)**: AfdDispatchDeviceControl - dispatches IOCTLs
3. **IRP_MJ_CLEANUP (0x12)**: AfdCleanupCore - cleanup when last handle closed
4. **IRP_MJ_CLOSE (2)**: AfdClose -> AfdCloseCore - final dereference when file object released

Critical: IRP_MJ_CLEANUP runs when the last handle is closed. IRP_MJ_CLOSE runs when the last reference to the file object is released. There is a gap between CLEANUP and CLOSE where pending IRPs can still hold file object references.

---

## Reference Count Analysis

### Connection Refcount at Offset 0x30 - Increment Locations

| Function | Address | Context | Amount |
|----------|---------|---------|--------|
| AfdAllocateConnection | 0x1C00588FC | Initial creation | +1 |
| AfdAddConnectedReference | 0x1C0058748 | After storing connection in endpoint | +1, sets 0x1000 flag |
| AfdConnect (TDI) | 0x1C004E1E9 | Before IofCallDriver | +1 (operation ref) |
| AfdSuperConnect (TL) | 0x1C0057C98 | Before TL connect call | +1 (operation ref) |
| AfdSuperConnect (TL) | 0x1C0057DA5 | If send data present | +1 (send buffer ref) |
| AfdAddConnectionToTimerWheel | 0x1C000703C | Timer wheel registration | +1, sets 0x8000000 flag |
| AfdTimerWheelHandler | 0x1C0007140 | DPC processing expired entry | +1 |
| AfdTLSuperConnectComplete | 0x1C0058C30 | Buffered send retry | +1 |

### Connection Refcount at Offset 0x30 - Decrement Locations

| Function | Address | Context | Triggers Free |
|----------|---------|---------|---------------|
| AfdCloseCore | 0x1C0037350 | Endpoint close | If reaches 0 -> AfdCloseConnection |
| AfdRestartConnect (error) | 0x1C006CD10 | -2: connected ref + operation ref | Each may trigger AfdCloseConnection |
| AfdRestartConnect (success) | 0x1C006CD10 | -1: operation ref only | If reaches 0 -> AfdCloseConnection |
| AfdRestartSuperConnect (error) | 0x1C006D130 | -2: connected ref + operation ref | Each may trigger AfdCloseConnection |
| AfdTLSuperConnectComplete (error) | 0x1C0058C30 | -2: connected ref + operation ref | Each may trigger AfdCloseConnection |
| AfdTLSuperConnectComplete (success) | 0x1C0058C30 | -1 at end | If reaches 0 -> AfdCloseConnection |
| AfdCleanupConnectionTimerWheelEntry | 0x1C0005594 | Timer wheel cleanup | If reaches 0 -> AfdCloseConnection |
| AfdTimerWheelHandler | 0x1C0007140 | After DPC processing | If reaches 0 -> AfdCloseConnection |
| AfdAbortConnection | 0x1C006D560 | Abort operation | If reaches 0 -> AfdCloseConnection |
| AfdDeleteConnectedReference | 0x1C004EDB0 | Delete connected ref | If reaches 0 -> AfdCloseConnection |

### Endpoint Refcount at Offset 0x38

| Function | Operation |
|----------|-----------|
| AfdCreate | +1 (initial creation) |
| AfdConnect | +1 (connect operation) |
| AfdSuperConnect | +1 (super connect) |
| AfdDereferenceEndpointInline | -1 (if reaches 0, free endpoint) |

### Endpoint IRP Refcount at Offset 0xE8

| Function | Operation |
|----------|-----------|
| AfdConnect (TDI) | +1 before IofCallDriver |
| AfdRestartConnect | -1 on completion |
| AfdSuperConnect (TL) | +1 before IofCallDriver |
| AfdRestartSuperConnect | -1 on completion |

---

## RACE 1 (CRITICAL): AfdCloseCore vs AfdTLSuperConnectComplete - Connection UAF

**Severity**: HIGH - Connection object UAF with read/write to freed memory

**Affected Functions**:
- AfdCloseCore (0x1C0037350) - reads/clears endpoint+0xB0 WITHOUT endpoint spinlock
- AfdTLSuperConnectComplete (0x1C0058C30) - reads endpoint+0xB0 WITHOUT endpoint spinlock

**Root Cause**: Both functions access the connection pointer at endpoint+0xB0 without acquiring the endpoint spinlock at endpoint+0x30. AfdRestartConnect and AfdGetConnectionReferenceFromEndpoint correctly acquire the spinlock before accessing this field, but AfdCloseCore and AfdTLSuperConnectComplete do not.

**Confirmed via disassembly of AfdCloseCore**:
```asm
; NO spinlock acquisition before this!
movzx ecx, word ptr [rbx]       ; check endpoint type
and ax, 0AFD2h
cmp ax, 0AFD2h
jz short loc_1C00373D1
loc_1C00373D1:
mov rdi, [rbx+0B0h]             ; READ connection pointer (NO LOCK!)
; ...
mov [rbx+0B0h], r8              ; CLEAR connection pointer (NO LOCK!)
lock xadd [rdi+30h], eax        ; decrement connection refcount
cmp eax, 1
jz short loc_1C00373F7          ; if was 1, call AfdCloseConnection -> FREE
```

**Race Window**:
```
Thread A (TL Completion)                    Thread B (Close)
---------------------------                 ---------------------------
AfdTLSuperConnectComplete:                  AfdCloseCore:
  v10 = *(endpoint + 0xB0)                  v3 = *(endpoint + 0xB0)    <-- same read, no lock
  // Thread A has connection C               *(endpoint + 0xB0) = 0    <-- clear
                                              lock xadd [C+0x30], -1   <-- decrement refcount
                                              if (was 1) AfdCloseConnection(C) -> C FREED
  v15 = *(v10 + 4)          <-- UAF READ   (C memory freed/reclaimed)
  *(v10 + 24) = 0           <-- UAF WRITE  (writing to freed/reclaimed memory)
  *(v10 + 4) = v15 & ~8     <-- UAF WRITE
  *(v10 + 16) = a3          <-- UAF WRITE (success path)
```

**Connection Refcount Flow During Race**:

1. AfdSuperConnect creates connection: refcount = 1
2. AfdAddConnectedReference: refcount = 2
3. Operation ref increment: refcount = 3
4. TL connect returns STATUS_PENDING (request pended)
5. Thread B: AfdCloseCore reads endpoint+0xB0 -> gets C
6. Thread B: AfdCloseCore clears endpoint+0xB0
7. Thread B: AfdCloseCore decrements C->refcount: 3 -> 2 (NOT freed yet)
8. Thread A: AfdTLSuperConnectComplete reads endpoint+0xB0 -> gets C (racy read)
9. Thread A accesses C+4, C+16, C+24 (flags, context, device object) WITHOUT holding a reference
10. Thread A decrements C->refcount: 2 -> 1 (error path first decrement)
11. Thread A decrements C->refcount: 1 -> 0 -> AfdCloseConnection(C) -> C FREED
12. But Thread A already accessed C at step 9 before the decrements!

If Thread A sees null (AfdCloseCore already cleared endpoint+0xB0):
- Thread A dereferences null -> BSOD (null pointer dereference)

**Exploit Potential**: The freed 256-byte connection object from NonPagedPoolNx can be reclaimed via heap spray. The writes at C+4 (flags), C+16 (file object), C+24 (device object) become controlled write-what-where primitives. The LIST_ENTRY at offset 0x48/0x50 can be corrupted for InsertHeadList/InsertTailList exploitation:
- InsertHeadList writes 8 bytes to corrupted_Flink+8
- InsertTailList writes 8 bytes to corrupted_Blink+0

---

## RACE 2 (MEDIUM): AfdSuperConnect Setup vs AfdCloseCore

**Severity**: MEDIUM - Endpoint state corruption, potential connection leak

**Root Cause**: In AfdSuperConnect, the connection pointer is stored at endpoint+0xB0 BEFORE the endpoint type is changed to AFD2. AfdCloseCore checks the type before accessing the connection pointer.

**Race Window**:
```
Thread A (SuperConnect)                    Thread B (Close)
---------------------------                ---------------------------
  *(endpoint + 0xB0) = C                   AfdCloseCore:
  // <-- RACE WINDOW -->                     // Check type: NOT AFD2 yet!
  *(endpoint) = 0xAFD2                       v3 = nullptr (missed connection)
  AfdAddConnectedReference(C)                BYTE2(endpoint) = 6  // set closed
                                              AfdDereferenceEndpointInline(endpoint)
```

**Consequence**: AfdCloseCore sets endpoint state to 6 (closed), AfdSuperConnect overrides with type AFD2. Endpoint is in inconsistent state. Connection C may not be properly cleaned up. Timer wheel entry may leak, leading to UAF in timer wheel handler accessing freed endpoint.

---

## RACE 3 (MEDIUM): AfdTimerWheelHandler - Stale Endpoint Pointer

**Severity**: MEDIUM - Endpoint UAF via stale pointer in timer wheel DPC

**Root Cause**: Timer wheel handler reads endpoint pointer from connection+8 then acquires endpoint spinlock. If endpoint freed between read and lock acquisition, UAF on endpoint spinlock.

**Mitigation**: AfdCleanupConnectionTimerWheelEntry is called from AfdCleanupCore (IRP_MJ_CLEANUP) which runs before AfdCloseCore (IRP_MJ_CLOSE). Timer wheel entry should be cleaned up before endpoint freed. But DPC at DISPATCH_LEVEL could fire between cleanup and close.

---

## RACE 4 (LOW): APC Path - Endpoint Leak

**Analysis**: APC is initialized at endpoint+0x50 and queued via KeInsertQueueApc. The endpoint refcount at 0x38 is NOT decremented by AfdRestartConnect (only 0xE8 is decremented). AfdConnectApcKernelRoutine calls AfdFinishConnect with a3=0 (SystemArgument2=0), so AfdDereferenceEndpointInline is NOT called. The endpoint refcount at 0x38 stays at 1 after AfdCloseCore. This is a memory leak, not a UAF.

---

## UAF Trigger Conditions

### Primary UAF Trigger (RACE 1)

**Prerequisites**:
- Windows 11 with afd.sys matching analyzed version (MD5: a3f1cb8de2938baddc2c3e9824948ff2)
- Socket endpoint with TL (Transport Layer) support (flag 0x100 at endpoint+0x08)
- Ability to issue IOCTL 0x120C7 (AfdSuperConnect) and close handle concurrently

**Trigger Steps**:

1. Create a TCP socket (creates AFD endpoint with TL flag 0x100)
2. Bind to a local address
3. Issue async AfdSuperConnect (IOCTL 0x120C7) to a remote target that causes TL connect to pend (STATUS_PENDING)
4. Immediately close the socket handle (CloseHandle)
5. Close triggers IRP_MJ_CLEANUP -> AfdCleanupCore, then IRP_MJ_CLOSE -> AfdCloseCore
6. AfdCloseCore reads endpoint+0xB0 (connection pointer) WITHOUT spinlock at 0x1C00373D1
7. TL transport completes the connect -> AfdTLSuperConnectComplete is called
8. AfdTLSuperConnectComplete reads endpoint+0xB0 WITHOUT spinlock
9. Race: both access connection pointer, AfdCloseCore may free connection while AfdTLSuperConnectComplete uses it

**Timing Window**: ~10-20 instructions wide. Race between:
- AfdCloseCore: `mov rdi, [rbx+0B0h]` (0x1C00373D1) through `lock xadd [rdi+30h], eax` (0x1C00373E4)
- AfdTLSuperConnectComplete: `v10 = *(FsContext + 176)` through subsequent v10 accesses

**Increasing Race Probability**:
- Multiple threads issuing connect+close in tight loop
- Target slow remote host to maximize pending window
- Use NtDeviceIoControlFile directly for precise IRP timing control
- Pin threads to different cores for true parallelism

### Memory Reclamation

After AfdCloseConnection -> AfdFreeConnection -> AfdFreeConnectionEx, the 256-byte connection goes to:
1. Connection recycling (AfdRefreshConnection) if endpoint has listen backlog
2. Lookaside list (PplConnectionPool) if depth < max
3. General pool free

For heap spray to reclaim the freed 256-byte connection:
- Spray with 256-byte NonPagedPoolNx allocations (pool tag 0x52646641)
- Use NtCreateFile to create file objects with similar-sized pool blocks
- Connection is from NonPagedPool with POOL_TYPE 512 (NonPagedPoolNx)

---

## Write-What-Where Exploitation Chain

If UAF is triggered and freed connection memory is reclaimed with controlled data:

1. **Corrupt LIST_ENTRY at offset 0x48/0x50**: Set Flink and Blink to target addresses
2. **Trigger list operation**: Any code path that calls InsertHeadList or InsertTailList on the corrupted LIST_ENTRY
3. **InsertHeadList(corrupted_entry, new_entry)**:
   - Writes new_entry to *(corrupted_Flink + 0x08)  [corrupted_Flink->Blink = new_entry]
   - Writes corrupted_Flink to *(new_entry + 0x00)  [new_entry->Flink = corrupted_Flink]
4. **InsertTailList(corrupted_entry, new_entry)**:
   - Writes new_entry to *(corrupted_Blink + 0x08)  [corrupted_Blink->Flink = new_entry]
   - Writes corrupted_Blink to *(new_entry + 0x00)  [new_entry->Blink = corrupted_Blink]

The corrupted Flink/Blink at connection+0x48/+0x50 are attacker-controlled values from the heap spray. This gives an 8-byte write to an arbitrary address with a controlled value (the new list entry address).

**Concrete exploitation steps**:
1. Trigger UAF on connection object C
2. Heap spray to reclaim C's 256-byte NonPagedPoolNx allocation
3. Set C+0x48 (Flink) = target_address - 0x08 (so write goes to target_address)
4. Set C+0x50 (Blink) = target_address - 0x08
5. Wait for a list operation on the corrupted LIST_ENTRY
6. InsertHeadList writes 8 bytes to target_address

**Alternative: Direct flag corruption**:
The UAF writes at C+4 (flags) and C+16/C+24 (pointers) can corrupt:
- C+4: Connection flags -> bypass security checks, change connection state
- C+16: File object pointer -> redirect to attacker-controlled file object
- C+24: Device object pointer -> redirect to attacker-controlled device object

---

## Key Function Address Reference

| Function | Address | Size |
|----------|---------|------|
| AfdConnect | 0x1C004D690 | 0x1001 |
| AfdSuperConnect | 0x1C00577B0 | 0xA2A |
| AfdSuperAccept | 0x1C0059E40 | 0x919 |
| AfdSuperDisconnect | 0x1C0044B10 | 0x27A |
| AfdCloseConnection | 0x1C0056D6C | 0xB7 |
| AfdCloseCore | 0x1C0037350 | 0xB1 |
| AfdClose | 0x1C0037304 | 0x46 |
| AfdCleanupCore | 0x1C00536EC | 0x6A7 |
| AfdCreateConnection | 0x1C00587B0 | 0x146 |
| AfdAllocateConnection | 0x1C00588FC | 0xE9 |
| AfdFreeConnection | 0x1C00406E0 | 0x1D |
| AfdFreeConnectionEx | 0x1C00039A0 | 0xC4 |
| AfdFreeConnectionResources | 0x1C0056C3C | 0xAB |
| AfdAddConnectedReference | 0x1C0058748 | 0x60 |
| AfdDeleteConnectedReference | 0x1C004EDB0 | 0x118 |
| AfdCheckAndReferenceConnection | 0x1C0002744 | 0x34 |
| AfdGetConnectionReferenceFromEndpoint | 0x1C0058E40 | 0x6C |
| AfdFinishConnect | 0x1C00589EC | 0x23C |
| AfdRestartConnect | 0x1C006CD10 | 0x2C9 |
| AfdRestartSuperConnect | 0x1C006D130 | 0x2EB |
| AfdTLSuperConnectComplete | 0x1C0058C30 | 0x207 |
| AfdConnectApcKernelRoutine | 0x1C003A1A0 | 0x8A |
| AfdConnectApcRundownRoutine | 0x1C0040DF0 | 0x36 |
| AfdAbortConnection | 0x1C006D560 | 0x136 |
| AfdDereferenceEndpointInline | 0x1C0003454 | 0x100 |
| AfdTimerWheelHandler | 0x1C0007140 | 0x2CC |
| AfdAddConnectionToTimerWheel | 0x1C000703C | 0xF0 |
| AfdCleanupConnectionTimerWheelEntry | 0x1C0005594 | 0x94 |
| AfdRemoveConnectionFromTimerWheel | 0x1C000771C | 0x1B |
| AfdCancelSuperAccept | 0x1C005E170 | 0x68 |
| AfdSanCancelConnect | 0x1C007D160 | 0x132 |
| AfdSanCancelAccept | 0x1C007CFF0 | 0x164 |
| AfdSanConnectHandler | 0x1C007D410 | 0xF36 |
| WskProCloseSocketWhileConnectInProgress | 0x1C00141D8 | 0x12E |
| AfdDispatch | 0x1C0053E00 | 0xEE |
| AfdDispatchDeviceControl | 0x1C005C390 | 0x8E |
