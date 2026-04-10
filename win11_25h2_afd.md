# AFD_ENDPOINT Reverse Engineering — Windows 11 25H2

## Binary Analyzed
- **File**: afd.sys (Windows 11 25H2, version 10.0.26100.8036)
- **Architecture**: x64
- **Tool**: IDA Pro via AiDA MCP
- **Functions**: 1128, 13 segments, **PDB symbols loaded**
- **Image base**: 0x140000000
- **Kernel build**: 26100 (same base as Win11 24H2)

## Key Finding

**Win11 25H2 shares the same kernel build base (26100) as Win11 24H2.**
All AFD_ENDPOINT offsets are **IDENTICAL** to Win11 24H2.
The existing `IsWindows11_24H2OrNewer()` check (build >= 26100) handles both versions.

## Key Functions (PDB Names)
| Address | Name | Size | Role |
|---------|------|------|------|
| 0x14000AB10 | AfdAllocateEndpoint | 1919 | Allocates 480/512 byte endpoint, populates all initial fields |
| 0x140029F70 | AfdBind | 2964 | Sets state=3/4, writes local address to ep+0xEC/0xF0 |
| 0x14002D9A0 | AfdConnect | 3642 | Checks state, creates connection, sets ep+0xC0 |
| 0x14000BB54 | AfdGetTransportInfo | 670 | Walks AfdTransportInfoListHead by device name (UNICODE_STRING) |

## AFD_ENDPOINT Structure — IDENTICAL TO 24H2

### Network.cpp-Relevant Offsets — ALL VERIFIED ✅

| Offset | Size | Field | Win10 Offset | Delta | 25H2 Verification |
|--------|------|-------|-------------|-------|--------------------|
| +0x00 | WORD | Type/Signature | +0x00 | 0 | AfdAllocateEndpoint: `LOWORD(v19->Count) = 0xAFD0` |
| +0x02 | BYTE | State | +0x02 | 0 | AfdConnect: checks `*(_BYTE*)(v6+2)==3` |
| +0x08 | DWORD | Flags | +0x08 | 0 | AfdConnect: `*(_DWORD*)(v6+8) & 0x100` |
| +0x10 | DWORD | TransportFlags | +0x10 | 0 | AfdConnect: `*(_DWORD*)(v6+16) & 0x200` |
| **+0x30** | QWORD | PEPROCESS | +0x28 | **+8** | AfdAllocateEndpoint: `v19[6].Count = IoGetCurrentProcess()` |
| +0x38 | KSPIN_LOCK | SpinLock | +0x30 | +8 | AfdBind: `lea rcx, [rdi+38h]`; AfdConnect: `KeAcquireInStackQueuedSpinLock(v6+56)` |
| +0x40 | QWORD | RefCount | +0x38 | +8 | AfdAllocateEndpoint: `v19[8].Count = 2` |
| +0xC0 | QWORD | Connection/Listener | +0xB0 | +0x10 | AfdBind: `mov [rdi+0C0h], rbx`; AfdConnect: `*(_QWORD*)(v6+192) = conn` |
| **+0xEC** | DWORD | LocalAddr Size | **+0xDC** | **+0x10** | AfdBind: `mov [rdi+0ECh], r12d` |
| **+0xF0** | QWORD | LocalAddr Ptr | **+0xE0** | **+0x10** | AfdBind: `mov [rdi+0F0h], rdx` |
| +0xF8 | DWORD | PendingOpCount | +0xE8 | +0x10 | AfdBind: `lock add [rdi+0F8h], r14d`; AfdConnect: `_InterlockedAdd(v6+248, 1)` |
| +0x100 | QWORD | TDI Handle | +0xF0 | +0x10 | AfdBind: `mov rcx, [rdi+100h]` then `ZwClose` |
| **+0x108** | QWORD | TransportInfo Ptr | **+0xF8** | **+0x10** | AfdBind: `lea rbx, [rdi+108h]`; AfdAllocateEndpoint: `v19[33].Count = transport` |
| +0x168 | DWORD | Bind/Connect Lock | +0x158 | +0x10 | AfdBind: `lock cmpxchg [rdi+168h], r9d`; AfdConnect: `_InterlockedCompareExchange(v6+360, 4, 0)` |

## TransportInfo Sub-Structure — IDENTICAL ACROSS ALL THREE VERSIONS ✅

| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x00 | LIST_ENTRY | LinkedList | Linked list traversal in AfdAllocateEndpoint |
| +0x10 | LONG | RefCount | AfdAllocateEndpoint: `_InterlockedIncrement(transport + 0x10)` |
| +0x14 | BYTE | QualifiedFlag | AfdBind: `cmp [rcx+14h], sil` |
| +0x16 | USHORT | AddressFamily | AfdAllocateEndpoint: `*(USHORT*)(i+22)` — 2=AF_INET, 23=AF_INET6 |
| +0x18 | DWORD | Protocol | AfdAllocateEndpoint: `*(DWORD*)(i+24)` — 6=TCP, 17=UDP |
| +0x1C | WORD | SocketType | AfdAllocateEndpoint: `*(WORD*)(i+28)` — 1=STREAM, 2=DGRAM, 3=RAW |
| +0x38 | DWORD | TransportFlags | AfdBind: `mov ecx, [rax+38h]; mov [rdi+10h], ecx` |

## Three-Version Offset Summary

| Field | Win10 19045 (build 19041) | Win11 24H2 (build 26100) | Win11 25H2 (build 26100) |
|-------|--------------------------|--------------------------|--------------------------|
| TransportInfo Ptr | +0xF8 | +0x108 | +0x108 |
| LocalAddr Size | +0xDC | +0xEC | +0xEC |
| LocalAddr Ptr | +0xE0 | +0xF0 | +0xF0 |
| PEPROCESS | +0x28 | +0x30 | +0x30 |

**Win11 24H2 and 25H2 are IDENTICAL** — both use kernel build 26100.

## Pattern Scan Signatures (for dynamic offset detection)

### TransportInfo offset in AfdBind
- Win10: `48 8D 9F F8 00 00 00` → `lea rbx, [rdi+0F8h]`
- Win11: `48 8D 9F 08 01 00 00` → `lea rbx, [rdi+108h]`
- Generic: `48 8D 9F ?? ?? 00 00` → offset = *(DWORD*)(match+3)

### LocalAddr Size offset in AfdBind
- Win10: `44 89 A7 DC 00 00 00` → `mov [rdi+0DCh], r12d`
- Win11: `44 89 A7 EC 00 00 00` → `mov [rdi+0ECh], r12d`
- Generic: `44 89 A7 ?? ?? 00 00` near LocalAddr Ptr store → offset = *(DWORD*)(match+3)

### LocalAddr Ptr offset in AfdBind
- Win10: `48 89 97 E0 00 00 00` → `mov [rdi+0E0h], rdx`
- Win11: `48 89 97 F0 00 00 00` → `mov [rdi+0F0h], rdx`
- Generic: `48 89 97 ?? ?? 00 00` after LocalAddr Size store → offset = *(DWORD*)(match+3)

### Recommended Strategy
1. Find afd.sys base in kernel module list
2. Locate AfdBind by export name or pattern
3. Scan within AfdBind for the three patterns above
4. Extract offsets dynamically from instruction displacements
5. Fall back to build-number table if pattern scan fails
