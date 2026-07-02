# AFD.SYS Vulnerability Analysis - 8-Byte Arbitrary Kernel Write Hunt

## 1. Binary Survey

| Field | Value |
|-------|-------|
| Path | C:\Windows\System32\drivers\afd.sys |
| Architecture | x64 |
| Base Address | 0x1C0000000 |
| Image Size | 0xA7000 (688KB) |
| MD5 | a3f1cb8de2938baddc2c3e9824948ff2 |
| Total Functions | 1084 |
| Total Strings | 509 |
| Segments | 15 |

### Segment Layout

| Segment | Start | End | Size | Perm |
|---------|-------|-----|------|------|
| .text | 0x1C0001000 | 0x1C001F000 | 0x1E000 | rx |
| .rdata | 0x1C001F000 | 0x1C002A000 | 0xB000 | r |
| .data | 0x1C002A000 | 0x1C002B000 | 0x1000 | rw |
| PAGE | 0x1C0034000 | 0x1C004D000 | 0x19000 | rx |
| PAGEAFD | 0x1C004D000 | 0x1C007A000 | 0x2D000 | rx |
| PAGESAN | 0x1C007C000 | 0x1C0081000 | 0x5000 | rx |
| PAGEWTDI | 0x1C0081000 | 0x1C0086000 | 0x5000 | rx |
| INIT | 0x1C0087000 | 0x1C008A000 | 0x3000 | rx |

### Key Source Files (from string xrefs)

| Source | Xrefs | Focus |
|--------|-------|-------|
| san.c | 25 | SAN |
| misc.c | 22 | Helpers |
| fastio.c | 13 | Fast I/O |
| afdrio.c | 12 | AFD I/O |
| tpackets.c | 11 | TDI packets |
| send.c | 9 | Send |
| connect.c | 5 | Connect |
| accept.c | 3 | Accept |

---

## 2. IOCTL Dispatch Architecture

### AfdDispatch (0x1C0053E00)
- IRP_MJ_CREATE -> AfdCreate
- IRP_MJ_CLOSE -> AfdClose
- IRP_MJ_READ -> AfdReceive
- IRP_MJ_WRITE -> AfdSend
- IRP_MJ_DEVICE_CONTROL -> AfdDispatchDeviceControl
- IRP_MJ_INTERNAL_DEVICE_CONTROL -> AfdWskDispatchInternalDeviceControl
- IRP_MJ_CLEANUP -> AfdCleanupCore

### AfdDispatchDeviceControl (0x1C005C390)
`c
v5 = (IoctlCode >> 2) & 0x3FF;
if (v5 < 0x49 && AfdIoctlTable[v5] == IoctlCode && AfdIrpCallDispatch[v5] != NULL)
    return AfdIrpCallDispatch[v5](Irp, IoStack);
`
- AfdIoctlTable at 0x1C00208A0: 73 DWORDs
- AfdIrpCallDispatch at 0x1C001F6A0: 73 function pointers

### AfdDispatchImmediateIrp (0x1C00118D0)
Second-level dispatch for synchronous IOCTLs.
AfdImmediateCallDispatch at 0x1C001F450: 38 handlers.
Passes user buffer pointers directly to handlers (METHOD_NEITHER).

---

## Complete IOCTL Handler Table (73 entries)

| # | IOCTL | Func | Method | Handler | Name |
|---|-------|------|--------|---------|------|
| 0 | 0x12003 | 0x800 | NEITHER | 0x1C0034DE0 | AfdBind |
| 1 | 0x12007 | 0x801 | NEITHER | 0x1C004D690 | AfdConnect |
| 2 | 0x1200B | 0x802 | NEITHER | 0x1C005D910 | AfdStartListen |
| 3 | 0x1200C | 0x803 | BUFFERED | 0x1C005B840 | AfdWaitForListen |
| 4 | 0x12010 | 0x804 | BUFFERED | 0x1C005BA30 | AfdAccept |
| 5 | 0x12017 | 0x805 | NEITHER | 0x1C0054F90 | AfdReceive |
| 6 | 0x1201B | 0x806 | NEITHER | 0x1C0056E30 | AfdReceiveDatagram |
| 7 | 0x1201F | 0x807 | NEITHER | 0x1C0055CA0 | AfdSend |
| 8 | 0x12023 | 0x808 | NEITHER | 0x1C0075370 | AfdSendDatagram |
| 9 | 0x12024 | 0x809 | BUFFERED | 0x1C005C950 | AfdPoll |
| 10-13 | 0x1202B-37 | 0x80A-80D | NEITHER | imm | AfdPartialDisconnect/QueryReceiveInfo/Handles |
| 14-17 | 0x1203B-47 | 0x80E-811 | NEITHER | imm | AfdSetInformation/GetRemoteAddr/GetContext/SetContext |
| 18-21 | 0x1204B-57 | 0x812-815 | NEITHER | imm | AfdSetConnectData x4 |
| 22-25 | 0x1205B-67 | 0x816-819 | NEITHER | imm | AfdGetConnectData x4 |
| 26-29 | 0x1206B-77 | 0x81A-81D | NEITHER | imm | AfdSetConnectData x4 |
| 30 | 0x1207B | 0x81E | NEITHER | imm | AfdGetInformation |
| 31 | 0x1207F | 0x81F | NEITHER | 0x1C00454A0 | AfdTransmitFile |
| 32 | 0x12083 | 0x820 | NEITHER | 0x1C0059E40 | AfdSuperAccept |
| 33 | 0x12087 | 0x821 | NEITHER | imm | AfdEventSelect |
| 35 | 0x1208C | 0x823 | BUFFERED | 0x1C006B7B0 | AfdDeferAccept |
| 37 | 0x12094 | 0x825 | BUFFERED | 0x1C0071920 | AfdSetQos |
| 38 | 0x12098 | 0x826 | BUFFERED | 0x1C0041A60 | AfdGetQos |
| 43 | 0x120AC | 0x82B | BUFFERED | 0x1C00723D0 | AfdRoutingInterfaceChange |
| 45 | 0x120B4 | 0x82D | BUFFERED | 0x1C005A760 | AfdAddressListChange |
| 46 | 0x120BB | 0x82E | NEITHER | 0x1C004D690 | AfdConnect |
| 47 | 0x120BF | 0x82F | NEITHER | 0x1C0053FA0 | AfdTliIoControl |
| 48 | 0x120C3 | 0x830 | NEITHER | 0x1C0045DC0 | AfdTransmitPackets |
| 49 | 0x120C7 | 0x831 | NEITHER | 0x1C00577B0 | AfdSuperConnect |
| 50 | 0x120CB | 0x832 | NEITHER | 0x1C0044B10 | AfdSuperDisconnect |
| 52 | 0x120D3 | 0x834 | NEITHER | 0x1C003A240 | AfdSendMessageDispatch |
| 56 | 0x120E2 | 0x838 | OUT_DIRECT | 0x1C007D410 | AfdSanConnectHandler |
| 62 | 0x120FB | 0x83E | NEITHER | 0x1C007C720 | AfdSanAcquireContext |
| 67 | 0x1210C | 0x843 | BUFFERED | 0x1C0046F10 | AfdSanAddrListChange |
| 68 | 0x12113 | 0x844 | NEITHER | 0x1C003FB70 | AfdUnBindSocket |
| 70 | 0x1211B | 0x846 | NEITHER | 0x1C0018170 | AfdRio |
| 71 | 0x1211F | 0x847 | NEITHER | 0x1C005E930 | AfdSocketTransferBegin |
| 72 | 0x12123 | 0x848 | NEITHER | 0x1C005E8B0 | AfdSocketTransferEnd |

imm = AfdDispatchImmediateIrp second-level dispatch

---

## 3. Pool Allocations - Sizes, Types, Tags

### NonPagedPoolNx Allocations (0x200/0x210)

| Tag | ASCII | PoolType | Size Pattern | Key Functions |
|-----|-------|----------|-------------|---------------|
| 0x49646641 | fdI | 0x210 Nx+Quota | user+0x60, 0x28 | AfdConnect, AfdReceive, AfdSend |
| 0x50646641 | fdP | 0x210 Nx+Quota | 40*count+184 | AfdPollGetInfo |
| 0x20646641 | fd_ | 0x210 Nx+Quota | count*16, count*16+8 | AfdFastIoDeviceControl, AfdTliIoControl |
| 0x4C646641 | fdL | 0x210 Nx+Quota | 0x58 fixed | AfdTliIoControl |
| 0x69646641 | fdi | 0x210 Nx+Quota | user-controlled | AfdTliIoControl |
| 0x63646641 | fdc | 0x210 Nx+Quota | 0xE8 fixed, user | AfdSetConnectData |
| 0x73646641 | fds | 0x210 Nx+Quota | 0x10, user+0xC | AfdAccept, AfdSanConnectHandler |
| 0x71646641 | fdq | 0x211 Paged+Quota | user+0x48 | AfdRoutingInterfaceChange |
| 0x68646641 | fdh | 0x210 Nx+Quota | 0x28, 0x48 | AfdAddressListChange |
| 0x46646641 | fdF | 0x210 Nx+Quota | count*24 | AfdTliGetTpInfo |
| 0x4D646641 | fdM | 0x210 Nx+Quota | user+0x50 aligned | AfdBuildSendMsgTracker |
| 0x52646641 | fdR | 0x200 Nx | user-controlled | AfdConnect address |
| 0x58646641 | fdX | 0x111 Paged+Quota | user-controlled | AfdSetContext |

### Lookaside List Allocations (NonPagedPoolNx)

| Object | Size | Pool | Tag |
|--------|------|------|-----|
| AFD Endpoint (standard) | 448 bytes | PplEndpointPool | fdA |
| AFD Endpoint (TDI/TL) | 480 bytes | PplTditlEndpointPool | fdA |
| AFD Connection | 256 bytes | PplConnectionPool | fdA |
| AFD Address | variable | PplAddressPool | fdR |

### Endpoint Structure (448/480 bytes)

`
+0x00  WORD  Signature (0xAFD0-0xAFD4)
+0x02  BYTE  State (1=dgram, 2=conn, 3=VC, 4=connected)
+0x08  DWORD EndpointFlags (0x100=TL, 0x200000=deferred, 0x400000=cond-accept)
+0x30  KSPIN_LOCK Lock
+0x40  QWORD Process (EPROCESS*)
+0x60  DWORD EventMask
+0x98  DWORD MaxListenBacklog
+0xB0  QWORD TransportInfo
+0xC0  QWORD Connection (AFD Connection*)
+0xF8  QWORD Transport (TL provider)
+0x158 QWORD ContextPtr (interlocked-locked)
+0x160 DWORD ContextSize
+0x168 DWORD EventSelectMask
+0x1A0 QWORD EventSelectObject (KEVENT*)
+0x1F8 QWORD TdiEndpoint
+0x232 DWORD RefCount3 (interlocked)
`

---

## 4. Overflow, UAF, and Write-What-Where Primitives

### AfdConnect (0x1C004D690) - IOCTL 0x12007 - METHOD_NEITHER

`c
// Non-TL path:
v5 = InputBufferLength - 24;
PoolWithQuotaTag = ExAllocatePoolWithQuotaTag(528, v5 + 96, 0x49646641);
memset(PoolWithQuotaTag, 0, 0x60);
memmove(&PoolWithQuotaTag[96], Src, v5);
`
Validation: InBufLen>=24 (64-bit), user_data>=8 for VC, sockaddr family check.
Buffer: [96-byte zeroed header][user data with sockaddr], stored in IRP->MasterIrp.
LFH 1024: InBufLen=952. LFH 640: InBufLen=568.

### AfdPoll (0x1C005C994) - IOCTL 0x12024 - METHOD_BUFFERED

`c
if (count > 0x6666661) return STATUS_QUOTA_EXCEEDED;
AfdPollGetInfo(40 * count + 184);
// ExAllocatePoolWithQuotaTag(528, 40*count+184, 0x50646641)
`
Validation: bufSize>=16, count fits in buffer, count<=0x6666661.
Historical CVE-2014-1767 target. Poll handle info = 40 bytes each.
LFH 1024: count=21.

### AfdTliIoControl (0x1C0053FA0) - IOCTL 0x120BF - METHOD_NEITHER

Three allocation paths:
1. Context: 0x58 bytes fixed, tag fdL
2. TDI action: 16*count+8 bytes, tag fd_, count<=0xFFFF
3. Input data: user-controlled, tag fdi, size-matched copy

`c
// TDI action copy loop (within bounds):
for (i=0; i<count; i++) {
    buf[16*i+16] = user[8*i+8];     // DWORD
    *(QWORD*)&buf[16*i+8] = user[8*i+4]; // QWORD
}
// Input data:
ExAllocatePoolWithQuotaTag(528, user_size, 0x69646641);
memmove(alloc, user_buf, user_size);
`
LFH 1024: TDI count=63 (1016), input_size=1009-1024.
LFH 640: TDI count=39 (632), input_size=625-640.

### AfdFastIoDeviceControl (0x1C0035800) - Fast I/O

6292 bytes, 425 blocks, complexity 230.
8+ ExAllocatePoolWithQuotaTag calls with count*16 pattern, tag fd_.
Checks count > 8 before pool alloc (smaller uses fast path).
LFH 1024: count=64. LFH 640: count=40.

### AfdSetConnectData (0x1C0071440) - IOCTLs 0x1204B-0x12077

`c
// Container: fixed 232 bytes
ExAllocatePoolWithQuotaTag(528, 0xE8, 0x63646641); // tag fdc
// Data buffer: user-controlled
ExAllocatePoolWithQuotaTag(528, v11, 0x63646641);
memset(v33, 0, v11);
memmove(*buf, user_data, v11);
`
For IOCTLs 0x81A-0x81D: v11 = first DWORD of user data (user controls size).
Container has 8 data buffer pointer/size slots.

### AfdEventSelect (0x1C005D540) - IOCTL 0x12087

`c
ObReferenceObjectByHandle(handle, 2, ExEventObjectType, ...);
*(QWORD*)(endpoint + 0x1A0) = event_obj;  // KEVENT*
*(DWORD*)(endpoint + 0x168) = event_mask;
// If mask matches: KeSetEvent(event_obj, ...)
`
If endpoint+0x1A0 corrupted via overflow, KeSetEvent writes to controlled address.

### AfdSanConnectHandler (0x1C007D410) - IOCTL 0x120E2

`c
ExAllocatePoolWithQuotaTag(528, user_size + 12, 0x73646641); // tag fds
// 6 memmove calls with user data
`
LFH 1024: user=997. LFH 640: user=613.

### AfdRoutingInterfaceChange (0x1C00723D0) - IOCTL 0x120AC

ExAllocatePoolWithQuotaTag(528, user_size + 0x48, 0x71646641).
Note: PoolType 0x211 = PagedPool (NOT NonPagedPoolNx).

---

## 5. LFH Bucket Analysis

### Bucket 1024 (1009-1024 bytes)

| Allocation Path | Formula | Input Value | Result | Tag |
|----------------|---------|-------------|--------|-----|
| AfdConnect | InBufLen+72 | 952 | 1024 | fdI |
| AfdPollGetInfo | 40*count+184 | count=21 | 1024 | fdP |
| AfdFastIoDeviceControl | count*16 | count=64 | 1024 | fd_ |
| AfdTliIoControl TDI action | count*16+8 | count=63 | 1016 | fd_ |
| AfdTliIoControl input data | user_size | 1009-1024 | var | fdi |
| AfdSetConnectData | data_size | 1009-1024 | var | fdc |
| AfdSanConnectHandler | user+12 | 997 | 1009 | fds |
| AfdRoutingInterfaceChange | user+0x48 | 937 | 1009 | fdq |

### Bucket 640 (625-640 bytes)

| Allocation Path | Formula | Input Value | Result | Tag |
|----------------|---------|-------------|--------|-----|
| AfdConnect | InBufLen+72 | 568 | 640 | fdI |
| AfdFastIoDeviceControl | count*16 | count=40 | 640 | fd_ |
| AfdTliIoControl TDI action | count*16+8 | count=39 | 632 | fd_ |
| AfdTliIoControl input data | user_size | 625-640 | var | fdi |
| AfdSetConnectData | data_size | 625-640 | var | fdc |
| AfdSanConnectHandler | user+12 | 613 | 625 | fds |
| AfdRoutingInterfaceChange | user+0x48 | 553 | 625 | fdq |

### Other Notable Buckets

| Bucket | Object | Size | Notes |
|--------|--------|------|-------|
| 240 | AfdSetConnectData container | 232 (0xE8) | tag fdc, fixed |
| 256 | AFD Connection | 256 (0x100) | lookaside (not LFH) |
| 448 | AFD Endpoint (standard) | 448 (0x1C0) | lookaside (not LFH) |
| 480 | AFD Endpoint (TDI/TL) | 480 (0x1E0) | lookaside (not LFH) |
| 88 | AfdTliIoControl context | 88 (0x58) | tag fdL, fixed |

---

## 6. Most Promising Attack Vectors (Ranked)

### Rank 1: AfdConnect Pool Overflow -> Adjacent Object Corruption

- IOCTL: 0x12007 (METHOD_NEITHER)
- Allocation: user_data+96 bytes, NonPagedPoolNx, tag fdI
- LFH 1024: InputBufferLength=952; LFH 640: InputBufferLength=568
- User controls both allocation size and buffer content
- Buffer: [96-byte zeroed header][user-controlled data with sockaddr]
- Stored in IRP->MasterIrp, used by connect completion
- Attack: Allocate in target LFH bucket, overflow into adjacent object
- Feasibility: HIGH - direct user control of size and content

### Rank 2: AfdPoll Info Buffer (Historical CVE Path)

- IOCTL: 0x12024 (METHOD_BUFFERED)
- Allocation: 40*count+184 bytes, NonPagedPoolNx, tag fdP
- LFH 1024: count=21
- CVE-2014-1767 was in this exact path
- Poll handle info entries contain HANDLE values processed by ObReferenceObjectByHandle
- Attack: Look for count/buffer-size mismatch or TOCTOU in poll processing
- Feasibility: MEDIUM - requires finding specific validation gap

### Rank 3: AfdTliIoControl Input Data Buffer

- IOCTL: 0x120BF (METHOD_NEITHER)
- Allocation: user-controlled, NonPagedPoolNx, tag fdi
- LFH 1024: user_size=1009-1024; LFH 640: user_size=625-640
- Also has TDI action array: count*16+8, tag fd_
- Buffer passed to transport layer (AfdTLIoControl / IofCallDriver)
- Attack: If transport layer processes buffer with different size assumptions
- Feasibility: MEDIUM - depends on transport layer behavior

### Rank 4: AfdFastIoDeviceControl WSABUF Array

- Fast I/O path (not standard IOCTL)
- Allocation: count*16 bytes, NonPagedPoolNx, tag fd_
- LFH 1024: count=64; LFH 640: count=40
- 6292 bytes, 425 blocks, complexity 230 - very complex
- count > 8 check transitions from fast path to pool allocation
- Attack: Edge cases in count validation, especially at count=8/9 boundary
- Feasibility: MEDIUM - complexity increases bug likelihood

### Rank 5: AfdSanConnectHandler Buffer

- IOCTL: 0x120E2 (METHOD_OUT_DIRECT)
- Allocation: user_size+12 bytes, NonPagedPoolNx, tag fds
- LFH 1024: user=997; LFH 640: user=613
- 6 memmove calls copying user data
- Attack: Size validation gap between allocation and copy
- Feasibility: MEDIUM - requires analysis of 6 copy paths

### Rank 6: Event Handle Pointer Corruption

- IOCTL: 0x12087 (AfdEventSelect)
- Target: endpoint+0x1A0 (KEVENT* pointer)
- KeSetEvent on corrupted pointer = 4-byte write to SignalState
- Endpoint is lookaside-allocated (448/480 bytes), not LFH
- Attack: Overflow from LFH allocation into lookaside-adjacent memory
- Feasibility: LOWER - 4-byte write not 8-byte, lookaside vs LFH mismatch

### Rank 7: AfdSetConnectData Container Corruption

- IOCTLs: 0x1204B-0x12077 (METHOD_NEITHER)
- Container: 232 bytes (0xE8) fixed, NonPagedPoolNx, tag fdc
- Data buffer: user-controlled, same tag
- Container has 8 data buffer pointer/size slots
- Attack: Corrupt container to hijack data buffer pointer
- Feasibility: MEDIUM - container is bucket 240, different from 1024/640

---

## Pool Spray Strategy for 8-Byte Arbitrary Write

1. Spray target LFH bucket (1024 or 640) with vulnerable fdI/fdP/fd_ allocations
2. Create hole by freeing one allocation (close socket / cancel IRP)
3. Allocate target object in the hole (same bucket, different tag)
4. Overflow from vulnerable allocation into target object
5. Trigger write through corrupted pointer in target object

### Cross-Tag LFH Adjacency
Windows 10/11 LFH allows different tags in same bucket to be adjacent.
- fdI (1024) can be adjacent to fdP (1024) or fdi (1024) or fd_ (1024)
- fd_ (640) can be adjacent to fdi (640) or fds (625)

### Integer Overflow Analysis
- AfdTliIoControl TDI action: 16*count+8, count<=0xFFFF -> max 1,048,584. No overflow.
- AfdPoll: 40*count+184, count<=0x6666661 -> max ~171M. No overflow.
- AfdFastIoDeviceControl: count*16, 32-bit count. Max 0xFFFFFFFF*16 overflows 32-bit but shl on 64-bit register is safe.
- AfdConnect: v5+96 where v5=InBufLen-24. InBufLen is 32-bit. No overflow for practical sizes.

### UAF Vectors
1. Socket close during async operation (connect, receive, send, poll pending)
2. AfdConnect buffer UAF: buffer in IRP->MasterIrp freed if IRP cancelled during transport processing
3. AfdEventSelect event UAF: race between close and KeSetEvent on SMP
4. AfdSetContext: custom interlocked lock protects context pointer, potential SMP race

### Write-Through-Pointer Patterns
1. KeSetEvent on corrupted KEVENT* at endpoint+0x1A0 (4-byte write)
2. memmove to corrupted data buffer pointer in fdc container (8-byte write possible)
3. IofCallDriver with corrupted device/file object pointers from connection structure
4. Completion routine registration with corrupted context pointers

---

Analysis complete. afd.sys PID 18576, port 13350.
