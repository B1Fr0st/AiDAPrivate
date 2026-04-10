# AFD_ENDPOINT Reverse Engineering — Windows 11 24H2

## Binary Analyzed
- **File**: afd.sys (Windows 11 24H2, version 10.0.26100.8115)
- **Architecture**: x64
- **Tool**: IDA Pro via AiDA MCP
- **Functions**: 1122, 13 segments, **PDB symbols loaded**
- **Image base**: 0x140000000

## Key Functions (PDB Names)
| Address | Name | Size | Role |
|---------|------|------|------|
| 0x140017630 | AfdCreate | 2470 | IRP_MJ_CREATE dispatch, dispatches to AfdOpenPacketXX / AfdSwOpenPacket / AfdRioRDOpenPacket |
| 0x14000AB80 | AfdAllocateEndpoint | 1929 | Allocates 480/512 byte endpoint, populates all initial fields |
| 0x14000BBD4 | AfdGetTransportInfo | 670 | Walks AfdTransportInfoListHead by device name (UNICODE_STRING) |
| 0x14002A2E0 | AfdBind | 2986 | Sets state=3/4, writes local address to ep+0xEC/0xF0 |
| 0x14002DD70 | AfdConnect | 3605 | Checks state, creates connection, sets ep+0xC0 |
| 0x14002CD3C | AfdCreateConnection | 1330 | Creates connection object |

## AFD_ENDPOINT Structure (480/512 bytes)

### Size Change from Win10
- Win10: 448 bytes (standard) / 480 bytes (with TL extended transport)
- Win11: 480 bytes (standard) / 512 bytes (with TL extended transport)
- Delta: +32 bytes

### Offsets Used in Network.cpp — ALL VERIFIED ✅

| Offset | Size | Field | Win10 Offset | Delta | Verification |
|--------|------|-------|-------------|-------|-------------|
| +0x00 | WORD | Type/Signature | +0x00 | 0 | AfdAllocateEndpoint: `LOWORD(v19->Count) = 0xAFD0`; AfdConnect: checks 0xAAFD, 0xAFD1, 0xAFD2 |
| +0x02 | BYTE | State | +0x02 | 0 | AfdBind: `mov al, [rdi+2]`, `mov [rdi+2], r12b` (=3 bound); AfdConnect: checks `*(_BYTE*)(v6+2)==3` |
| +0x08 | DWORD | Flags | +0x08 | 0 | AfdBind: `mov eax, [rdi+8]; bt eax, 8`; AfdConnect: `*(_DWORD*)(v6+8) & 0x100` |
| +0x10 | DWORD | TransportFlags | +0x10 | 0 | AfdBind: `mov ecx, [rax+38h]; mov [rdi+10h], ecx`; AfdConnect: `*(_DWORD*)(v6+16) & 0x200` |
| **+0x30** | QWORD | PEPROCESS | +0x28 | **+8** | AfdAllocateEndpoint: `v19[6].Count = IoGetCurrentProcess()`; AfdConnect: `*(_QWORD*)(v6+48)` |
| +0x38 | KSPIN_LOCK | SpinLock | +0x30 | +8 | AfdBind: `lea rcx, [rdi+38h] ; SpinLock`; AfdConnect: `KeAcquireInStackQueuedSpinLock(v6+56)` |
| +0x40 | QWORD | RefCount | +0x38 | +8 | AfdAllocateEndpoint: `v19[8].Count = 2`; AfdConnect: `_InterlockedIncrement64(v6+64)` |
| +0xC0 | QWORD | Connection/Listener | +0xB0 | +0x10 | AfdBind: `mov [rdi+0C0h], rbx`; AfdConnect: `*(_QWORD*)(v6+192) = conn` |
| **+0xEC** | DWORD | LocalAddr Size | **+0xDC** | **+0x10** | AfdBind: `mov [rdi+0ECh], r12d` |
| **+0xF0** | QWORD | LocalAddr Ptr | **+0xE0** | **+0x10** | AfdBind: `mov [rdi+0F0h], rdx` |
| +0xF8 | DWORD | PendingOpCount | +0xE8 | +0x10 | AfdBind: `lock add [rdi+0F8h], r14d`; AfdConnect: `_InterlockedAdd(v6+248, 1)` |
| +0x100 | QWORD | TDI Handle | +0xF0 | +0x10 | AfdBind: `mov rcx, [rdi+100h] ; Handle` then `ZwClose` |
| **+0x108** | QWORD | TransportInfo Ptr | **+0xF8** | **+0x10** | AfdBind: `lea rbx, [rdi+108h]`; AfdAllocateEndpoint: `v19[33].Count = transport` |
| +0x168 | DWORD | Bind/Connect Lock | +0x158 | +0x10 | AfdBind: `lock cmpxchg [rdi+168h], r9d`; AfdConnect: `_InterlockedCompareExchange(v6+360, 4, 0)` |

### Additional Win11 Fields
| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x18 | QWORD | TDI Object | AfdBind: `mov rcx, [rdi+18h] ; Object` then `ObfDereferenceObject` |
| +0x28 | QWORD | DeviceObject/TDI | AfdBind: `mov rcx, [rdi+28h]` then `IofCallDriver` |
| +0x48 | DWORD | ListenBacklog | AfdBind: `mov dword ptr [rdi+48h], 4` |
| +0x110 | QWORD | TL Extended Info | AfdConnect: `*(_QWORD*)(v6+272)` for TL route |
| +0x120 | LIST_ENTRY | IRP List | AfdAllocateEndpoint: `v19[36/37]` self-referencing init |
| +0x180 | EX_RUNDOWN_REF | RundownProtection | AfdAllocateEndpoint: `ExInitializeRundownProtection(v19+48)` |
| +0x1C8 | DWORD | GroupID | AfdAllocateEndpoint: `v19[57].Count = groupId` |
| +0x1F0 | QWORD | TL Extended Transport | AfdAllocateEndpoint: `v19[62].Count = v11` |

## TransportInfo Sub-Structure — CONFIRMED SAME AS WIN10 ✅

### Evidence from AfdAllocateEndpoint (TlTransportListHead traversal):
```c
// AfdAllocateEndpoint walks AfdTlTransportListHead:
for ( i = AfdTlTransportListHead; i != &AfdTlTransportListHead; i = *(_QWORD*)i )
{
    if ( *(_WORD *)(i + 28) == (_WORD)a3 )        // +0x1C = SocketType
    {
        v22 = *(unsigned __int16 *)(i + 22);       // +0x16 = AddressFamily
        if ( (v22 == a2 || !(_WORD)v22)
            && (*(_DWORD *)(i + 24) == a4 || a3 == 3)  // +0x18 = Protocol
            && AfdTlReferenceTransport(i) )
        { /* found */ }
    }
}
```

### Evidence from AfdBind (TransportInfo flag read):
```asm
lea     rbx, [rdi+108h]        ; rbx = &ep->TransportInfo
mov     rcx, [rbx]             ; rcx = TransportInfo ptr
cmp     [rcx+14h], sil         ; TransportInfo+0x14 = QualifiedFlag
jnz     short ...
; If not qualified, call AfdGetTransportInfo:
add     rcx, 18h               ; rcx = TransportInfo+0x18 (device name UNICODE_STRING for classic)
mov     rdx, rbx               ; rdx = &ep->TransportInfo (output)
call    AfdGetTransportInfo
; After:
mov     rax, [rbx]             ; reload TransportInfo
mov     ecx, [rax+38h]         ; TransportInfo+0x38 = TransportFlags
mov     [rdi+10h], ecx         ; store to endpoint TransportFlags
```

| Offset | Size | Field | Status |
|--------|------|-------|--------|
| +0x00 | LIST_ENTRY | LinkedList | SAME |
| +0x10 | LONG | RefCount | SAME |
| +0x14 | BYTE | QualifiedFlag | SAME — AfdBind: `cmp [rcx+14h], sil` |
| +0x16 | USHORT | AddressFamily | SAME — AfdAllocateEndpoint: `*(USHORT*)(i+22)` |
| +0x18 | DWORD | Protocol | SAME — AfdAllocateEndpoint: `*(DWORD*)(i+24)` |
| +0x1C | WORD | SocketType | SAME — AfdAllocateEndpoint: `*(WORD*)(i+28)` |
| +0x38 | DWORD | TransportFlags | SAME — AfdBind: `mov ecx, [rax+38h]` |

### Note on Dual Transport Lists (Win11)
Win11 has TWO transport info lists:
1. **AfdTlTransportListHead** (TL/modern path) — AF/Proto/SocketType at +0x16/+0x18/+0x1C
2. **AfdTransportInfoListHead** (classic/TDI path) — UNICODE_STRING at +0x18 (device name)

For TL endpoints (flags & 0x100), the TransportInfo pointer points to the TL transport
with AF/Proto/SocketType at the expected offsets. For classic endpoints (!(flags & 0x100)),
the TransportInfo pointer points to the classic info where +0x18 is a UNICODE_STRING.

**Most modern Windows sockets use the TL path**, so reading AF/Proto from the TransportInfo
at +0x16/+0x18 is correct for the vast majority of cases.

## Summary of Changes from Win10 to Win11 24H2

### Offsets That Changed (Network.cpp-relevant only)
| Field | Win10 22H2 | Win11 24H2 | Delta |
|-------|-----------|-----------|-------|
| **TransportInfo Ptr** | +0xF8 | +0x108 | +0x10 |
| **LocalAddr Size** | +0xDC | +0xEC | +0x10 |
| **LocalAddr Ptr** | +0xE0 | +0xF0 | +0x10 |

### Offsets That Did NOT Change
| Field | Offset | Same? |
|-------|--------|-------|
| Type/Signature | +0x00 | ✅ |
| State | +0x02 | ✅ |
| Flags | +0x08 | ✅ |
| TransportFlags | +0x10 | ✅ |
| TransportInfo.AddressFamily | +0x16 | ✅ |
| TransportInfo.Protocol | +0x18 | ✅ |
| TransportInfo.SocketType | +0x1C | ✅ |
| TransportInfo.TransportFlags | +0x38 | ✅ |

## Pattern Scan Signatures

### For finding TransportInfo offset in AfdBind
Win10 pattern: `48 8D 9F F8 00 00 00` → `lea rbx, [rdi+0F8h]`
Win11 pattern: `48 8D 9F 08 01 00 00` → `lea rbx, [rdi+108h]`
Generic: `48 8D 9F ?? ?? 00 00` within AfdBind → offset is the DWORD at pattern+3

### For finding LocalAddr Ptr offset in AfdBind
Win10 pattern: `48 89 97 E0 00 00 00` → `mov [rdi+0E0h], rdx`
Win11 pattern: `48 89 97 F0 00 00 00` → `mov [rdi+0F0h], rdx`
Context: appears right after `mov [rdi+XX], r12d` (size store) with flags check `bt eax, 8`

### For finding LocalAddr Size offset in AfdBind
Win10 pattern: `44 89 A7 DC 00 00 00` → `mov [rdi+0DCh], r12d`
Win11 pattern: `44 89 A7 EC 00 00 00` → `mov [rdi+0ECh], r12d`
Context: immediately before LocalAddr Ptr store

### Recommended Dynamic Detection Strategy
1. Find AfdBind export/function in afd.sys
2. Scan for `48 8D 9F` (lea rbx, [rdi+imm32]) — the TransportInfo offset
3. Scan for `44 89 A7` (mov [rdi+imm32], r12d) near `48 89 97` (mov [rdi+imm32], rdx) — LocalAddr Size/Ptr pair
4. Alternatively: use NtBuildNumber-based offset table (simpler, more reliable)

### Build Number Mapping
| Build | Version | TransportInfo | LocalAddr Size | LocalAddr Ptr |
|-------|---------|--------------|----------------|---------------|
| 19041-19045 | Win10 22H2 | +0xF8 | +0xDC | +0xE0 |
| 26100 | Win11 24H2 | +0x108 | +0xEC | +0xF0 |

## Device Name Mapping (Unchanged)
- AF_INET + STREAM + TCP(6) → \\Device\\Tcp
- AF_INET + DGRAM + UDP(17) → \\Device\\Udp
- AF_INET + RAW → \\Device\\RawIp
- AF_INET6 + STREAM + TCP(6) → \\Device\\Tcp6
- AF_INET6 + DGRAM + UDP(17) → \\Device\\Udp6
- AF_INET6 + RAW → \\Device\\RawIp6
