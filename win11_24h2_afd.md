# AFD_ENDPOINT Reverse Engineering - Windows 11 24H2

## Binary Analyzed

- File: 5900FEED6BA94185AF1F9D7D0200778D474EFA89179BF337DE8C180D93117AF800.sys
- OS target: Windows 11 24H2
- Architecture: x64
- Image base: 0x140000000
- Image size: 0xB2000
- SHA-256: d087cc6d40354cbcfbe8f80e0aa42da3d30dcfa7bd3f814f74e0fe4e8aa703ce
- IDA source: C:\Users\ruar1337\Downloads\win11_25h2_afd.sys.i64, loaded through IDA Pro MCP and hash-matched to the 24H2 SYS above
- PDB symbols: loaded
- Verification date: 2026-06-23

The separate Windows 11 25H2 sample `C:\Users\ruar1337\Downloads\win11_25h2_afd.sys` was verified on 2026-06-23 and has the same MD5 (`d5a307b63f426720b11d1136162731a1`), SHA-256 (`d087cc6d40354cbcfbe8f80e0aa42da3d30dcfa7bd3f814f74e0fe4e8aa703ce`), image size (`0xB2000`), function addresses, and AfdBind signature hits as this 24H2 image. The hash-named 24H2 SYS exists at `C:\Users\ruar1337\Downloads\5900FEED6BA94185AF1F9D7D0200778D474EFA89179BF337DE8C180D93117AF800.sys`; its `.i64` database was not present during this verification. The duplicate `win11_25h2_afd.md` file was removed; use this document for both verified 24H2 and 25H2 samples.

## Key Functions

| Address | Name | Size | Role |
|---------|------|------|------|
| 0x1400178C0 | AfdCreate | 0x9A6 | IRP_MJ_CREATE path, references AfdOpenPacketXX and AfdSwOpenPacket |
| 0x14000ABE0 | AfdAllocateEndpoint | 0x789 | Allocates and initializes endpoint objects |
| 0x14000B4AC | AfdTlFindAndReferenceTransport | 0xB7 | Walks AfdTlTransportListHead and matches AF/protocol/socket type |
| 0x14000BC34 | AfdGetTransportInfo | 0x332 | Resolves classic transport info by UNICODE_STRING device name |
| 0x14002A2F0 | AfdBind | 0xB0F | Stores local address and resolves classic transport info |
| 0x14002DE20 | AfdConnect | 0xED9 | Connect path, validates endpoint state and uses transport/handle fields |
| 0x14002CE08 | AfdCreateConnection | 0x516 | Creates connection object |

## Endpoint Allocation

Current Win11 24H2 endpoint allocation sizes are:

| Mode | Size | Evidence |
|------|------|----------|
| Standard endpoint | 0x1F0 bytes | AfdAllocateEndpoint `mov ecx, 1F0h`, standard memset path `mov r8d, 1F0h` |
| TL extended endpoint | 0x210 bytes | AfdAllocateEndpoint `mov eax, 210h`, TL memset path `mov r8d, 210h` |

These sizes replace the stale 0x1E0/0x200 values from older notes.

## AFD_ENDPOINT Offsets

| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x00 | USHORT | Signature/type | AfdAllocateEndpoint stores 0xAFD0 or 0xAAFD; AfdConnect checks 0xAAFD and 0xAFD1 |
| +0x02 | UCHAR | State | AfdAllocateEndpoint initializes state 1 or 8; bind/connect paths read endpoint state here |
| +0x08 | ULONG | Flags | TL path sets bit 0x100; AfdBind and AfdConnect test bit 8 |
| +0x10 | ULONG | TransportFlags | AfdAllocateEndpoint/AfdBind copy current transport flags here |
| +0x30 | PEPROCESS | Owning process | AfdAllocateEndpoint stores IoGetCurrentProcess result at [rbx+30h] |
| +0x38 | KSPIN_LOCK | Endpoint spin lock | AfdAllocateEndpoint initializes [rbx+38h] |
| +0x40 | LONG64 | Refcount | AfdAllocateEndpoint stores 2 at [rbx+40h] |
| +0xC0 | PVOID | Connection/listener | AfdConnect stores connection at [rbx+0C0h] |
| +0xD0 | PVOID | Connect data buffer/state pointer | AfdConnect checks [rbx+0D0h] |
| +0xEC | ULONG | LocalAddr size | AfdBind stores r12d at [rdi+0ECh] in TL and classic paths |
| +0xF0 | PVOID | LocalAddr pointer | AfdBind stores rcx at [rdi+0F0h] in TL path and rax at [rdi+0F0h] in classic path |
| +0xF8 | ULONG | Pending operation count | AfdBind uses [rdi+0F8h] |
| +0x100 | PVOID | TDI handle/object | AfdConnect reads [r15+100h]/[rbx+100h] for connection creation |
| +0x110 | PVOID | TransportInfo pointer | AfdAllocateEndpoint stores at [rbx+110h]; AfdBind uses `lea rbx, [rdi+110h]`; AfdConnect reads [rbx+110h] |
| +0x128 | LIST_ENTRY | Endpoint list entry | AfdAllocateEndpoint initializes self-referencing list at [rbx+128h] |
| +0x170 | LONG | Bind/connect lock | AfdBind and AfdConnect use lock cmpxchg/xchg at [endpoint+170h] |
| +0x188 | EX_RUNDOWN_REF | Rundown protection | AfdAllocateEndpoint passes [rbx+188h] to ExInitializeRundownProtection |
| +0x1D0 | ULONG | Group id / creation field | AfdAllocateEndpoint stores esi at [rbx+1D0h] and edi at [rbx+1D4h] |
| +0x200 | PVOID | TL extended transport pointer | AfdAllocateEndpoint stores r13 at [rbx+200h] when extended TL data exists |

## Network.cpp-Relevant Offsets

| Field | Win10 22H2 | Current Win11 24H2 | Delta |
|-------|------------|--------------------|-------|
| TransportInfo pointer | +0xF8 | +0x110 | +0x18 |
| LocalAddr size | +0xDC | +0xEC | +0x10 |
| LocalAddr pointer | +0xE0 | +0xF0 | +0x10 |

The old Win11 24H2 note that used TransportInfo +0x108 is stale for the currently loaded image. Current AfdBind has exactly one `lea rbx, [rdi+110h]` match at 0x14002A6A3 and no `lea ... +108h` match.

## TransportInfo Layout

### TL Transport List

AfdTlFindAndReferenceTransport and the TL scan inside AfdAllocateEndpoint confirm:

| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x00 | LIST_ENTRY | List links | Traversal uses first pointer as next |
| +0x16 | USHORT | AddressFamily | Compared with requested address family |
| +0x18 | ULONG | Protocol | Compared with requested protocol, except raw socket type |
| +0x1C | USHORT | SocketType | Compared with requested socket type |

### Classic Transport Info

AfdGetTransportInfo confirms:

| Offset | Size | Field | Evidence |
|--------|------|-------|----------|
| +0x00 | LIST_ENTRY | AfdTransportInfoListHead links | Classic list traversal |
| +0x10 | LONG | Refcount | Interlocked increment path |
| +0x14 | UCHAR | Qualified flag | AfdBind checks [TransportInfo+14h] |
| +0x18 | UNICODE_STRING | Device name | AfdBind passes TransportInfo+18h to AfdGetTransportInfo |
| +0x40 | ULONG | TransportFlags | AfdBind loads [rax+40h] and stores to endpoint +0x10 |
| +0x58 | WCHAR[] | Inline device-name buffer | AfdGetTransportInfo allocation path stores the copied name buffer here |

Classic transport names still map through device suffixes:

| Device suffix | Address family | Protocol |
|---------------|----------------|----------|
| Tcp | AF_INET | IPPROTO_TCP |
| Udp | AF_INET | IPPROTO_UDP |
| RawIp | AF_INET | 0 |
| Tcp6 | AF_INET6 | IPPROTO_TCP |
| Udp6 | AF_INET6 | IPPROTO_UDP |
| RawIp6 | AF_INET6 | 0 |

## Exact Pattern Evidence

All patterns below were checked against the loaded IDA MCP image `win11_25h2_afd.sys.i64`, whose input SYS is byte-hash identical to the 24H2 SYS named above.

| Purpose | Pattern | Result |
|---------|---------|--------|
| TL local address store | `48 89 8F F0 00 00 00 44 89 A7 EC 00 00 00` | 0x14002A659 |
| Classic local address store | `48 89 87 F0 00 00 00 44 89 A7 EC 00 00 00` | 0x14002A6F6 |
| Old rdx local pointer store | `48 89 97 F0 00 00 00` | no matches in this image |
| Current TransportInfo lea | `48 8D 9F 10 01 00 00` | 0x14002A6A3 |
| Old +0x108 TransportInfo lea | `48 8D 9F 08 01 00 00` | no matches in this image |
| Old +0x108 rax lea | `48 8D 87 08 01 00 00` | no matches in this image |

## Dynamic Detection Requirements

Runtime code must not derive Win11 TransportInfo as `LocalAddrSize + 0x1C`. That old relationship produces +0x108 for current 24H2 and is wrong for this image.

Required detection order:

1. Resolve LocalAddr size/pointer from paired stores in AfdBind.
2. For Win11 local `+0xEC/+0xF0`, independently scan TransportInfo lea signatures.
3. Prefer current `48 8D 9F 10 01 00 00` -> +0x110.
4. Keep old `48 8D 9F 08 01 00 00` -> +0x108 as a compatibility signature only if it is present in the loaded afd.sys.
5. Log the matched local pattern, matched TransportInfo pattern, offsets, OS build, afd base, and fallback source.

## Build Mapping

| OS build family | TransportInfo | LocalAddr size | LocalAddr pointer | Status |
|-----------------|---------------|----------------|-------------------|--------|
| 19041-19045 Win10 22H2 | +0xF8 | +0xDC | +0xE0 | Verified in win10afd.md |
| 26100 current Win11 24H2 / 25H2 image | +0x110 | +0xEC | +0xF0 | Verified here; identical binary hash for the checked 25H2 sample |
| 26100 older/stale note | +0x108 | +0xEC | +0xF0 | Do not use unless the +0x108 lea pattern exists in the loaded image |

## Driver Alignment

Network code must:

- Accept endpoint signatures 0xAFD0, 0xAAFD, 0xAFD1, and 0xAFD2 before dereferencing endpoint fields.
- Treat `endpoint->Flags & 0x100` as the TL/classic discriminator.
- For TL endpoints, read address family/protocol from TransportInfo +0x16/+0x18 only after pointer validation.
- For classic endpoints, parse the UNICODE_STRING at TransportInfo +0x18 and map the device suffix to AF/protocol.
- Resolve TransportInfo independently from explicit AfdBind lea signatures, not by a fixed local-address delta.
- Emit KVALIDATE logs for the final offset source, local pattern, TransportInfo pattern, address family source, endpoint signature failures, and classic transport-name failures.
