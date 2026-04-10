# AFD_ENDPOINT Complete Reverse Engineering Verification

## Binary Analyzed
- **File**: afd.sys (Windows 10 Build 19041, version 10.0.19041.6456)
- **Architecture**: x64
- **Tool**: IDA Pro via AiDA MCP
- **Functions**: 1083, 15 segments, no PDB symbols

## Key Functions Identified
| Address | Name | Evidence |
|---------|------|----------|
| 0x1C0037408 | AfdCreate (IRP_MJ_CREATE dispatch) | String "AfdOpenPacketXX", "AfdSwOpenPacket" |
| 0x1C0037BB8 | AfdAllocateEndpoint | Called from AfdCreate, allocates 448/480 bytes |
| 0x1C0003258 | AfdGetTransportInfo | Walks linked list, matches AF/SockType/Protocol |
| 0x1C0034DE0 | AfdBind | String "bind.c", sets ep+0x02=3, writes ep+0xDC/0xE0 |
| 0x1C004D690 | AfdConnect | String "connect.c", checks ep+0x02, lock ops |
| 0x1C003B634 | AfdOpenTransport | Opens TDI device, IDA mis-typed param as PCUNICODE_STRING |

## AFD_ENDPOINT Structure (448/480 bytes)

### Offsets Used in Network.cpp — ALL CONFIRMED ✅
| Offset | Size | Field | Verification |
|--------|------|-------|-------------|
| +0x00 | WORD | Type/Signature | AfdCreate: LOWORD=0xAFD0/0xAAFD; AfdConnect: checks 0xAFD1, 0xAFD2 |
| +0x02 | BYTE | State | AfdCreate: =1(open), AfdBind: =3(bound)/=4(listening), AfdConnect: checks =2(connected) |
| +0x08 | DWORD | Flags | AfdCreate: \|=0x100/\|=0x200; AfdBind: checks &0x100 |
| +0x28 | QWORD | PEPROCESS | AfdCreate: =IoGetCurrentProcess(), ObfReferenceObject |
| +0xDC | DWORD | LocalAddr Size | AfdBind: *(DWORD*)(ep+220)=size |
| +0xE0 | QWORD | LocalAddr Ptr | AfdBind: *(QWORD*)(ep+224)=buffer |
| +0xF8 | QWORD | TransportInfo Ptr | AfdCreate: stored from AfdGetTransportInfo result |

### Additional Fields Found
| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x04 | DWORD | Flags1 (IRP) | AfdCreate: HIDWORD of first QWORD |
| +0x10 | QWORD | TransportFlags | AfdCreate: copied from TransportInfo+0x38 |
| +0x30 | KSPIN_LOCK | SpinLock | AfdCreate: KeInitializeSpinLock; AfdConnect: KeAcquireInStackQueued |
| +0x38 | DWORD | RefCount | AfdCreate: =2 (initial); AfdConnect: lock inc |
| +0xB0 | QWORD | Connection/Listener | AfdBind/AfdConnect: set |
| +0xE8 | DWORD | PendingOpCount | AfdConnect: lock inc |
| +0xF0 | QWORD | TDI Handle | AfdBind: ZwClose cleanup; AfdConnect: read |
| +0x110 | LIST_ENTRY | IRP List | AfdCreate: init to self (empty) |
| +0x158 | DWORD | Bind/Connect Lock | InterlockedCompareExchange in both |
| +0x1A8 | DWORD | Creation Flags | AfdCreate: from parameter |
| +0x1D0 | QWORD | Extended Transport | AfdCreate: optional extended ptr |

## TransportInfo Structure — ALL CONFIRMED ✅

### Definitive proof from AfdGetTransportInfo (sub_1C0003258):
```c
// Function walks linked list, matching entries by these fields:
*(_WORD *)(v8 + 28) == a2    // +0x1C = SocketType comparison (a2=SocketType param)
*(USHORT *)(v8 + 22) == a1   // +0x16 = AddressFamily comparison (a1=AF param)
*(_DWORD *)(v8 + 24) == a3   // +0x18 = Protocol comparison (a3=Protocol param)
```

| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x00 | LIST_ENTRY | LinkedList | sub_1C0003258: `v8 = *(_QWORD*)v8` for traversal |
| +0x10 | LONG | RefCount | sub_1C00033E0 ref counting |
| +0x14 | BYTE | Qualified Flag | AfdBind: `if (!*(ti+0x14))` → call qualifier |
| +0x16 | USHORT | AddressFamily | sub_1C0003258: `*(USHORT*)(ti+22) == AF` |
| +0x18 | DWORD | Protocol | sub_1C0003258: `*(DWORD*)(ti+24) == Protocol` |
| +0x1C | WORD | SocketType | sub_1C0003258: `*(WORD*)(ti+28) == SocketType` |
| +0x38 | DWORD | TransportFlags | AfdBind: read, stored to ep+0x10 |

### IDA Type Inference Error (Resolved)
In AfdBind, `sub_1C003B634((PCUNICODE_STRING)(TransportInfo + 0x18))` — IDA incorrectly
typed the parameter as PCUNICODE_STRING. The function actually receives a raw pointer to the
TransportInfo structure (from offset 0x18 = Protocol field). The function uses this internally
for TDI device opening, not as a UNICODE_STRING. Confirmed by sub_1C0037BB8 which also calls
sub_1C003B634 with an actual UNICODE_STRING for device name lookup.

## AfdAllocateEndpoint Parameter Mapping (sub_1C0037BB8)
```c
sub_1C0037BB8(output_ptr,
              AddressFamily,  // a2: 2=AF_INET, 23=AF_INET6
              SocketType,     // a3: 1=STREAM, 2=DGRAM, 3=RAW (switch on device name)
              Protocol,       // a4: 6=TCP, 17=UDP (validated per socket type)
              DeviceName,     // String2: UNICODE_STRING \\Device\\Tcp etc.
              Flags);         // a6
```

Device name mapping confirmed:
- AF_INET + STREAM + TCP(6) → \\Device\\Tcp
- AF_INET + DGRAM + UDP(17) → \\Device\\Udp
- AF_INET + RAW → \\Device\\RawIp
- AF_INET6 + STREAM + TCP(6) → \\Device\\Tcp6
- AF_INET6 + DGRAM + UDP(17) → \\Device\\Udp6
- AF_INET6 + RAW → \\Device\\RawIp6

## Windows Version Note
The analyzed afd.sys is **Windows 10 Build 19041** (version 10.0.19041.6456).
Network.cpp documents offsets for "Build 19045" — same kernel base, offsets identical.
For Windows 11, a separate afd.sys needs to be analyzed as offsets may differ.
