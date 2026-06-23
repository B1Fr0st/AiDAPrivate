# AFD_ENDPOINT Reverse Engineering Verification - Windows 10 22H2 afd.sys

## Binary Analyzed

- Binary: `C:\Windows\System32\drivers\afd.sys`
- IDA database: `C:\Windows\System32\drivers\afd.sys.i64`
- Module: `afd.sys`
- Architecture: x64
- File version: `10.0.19041.5487 (WinBuild.160101.0800)`
- Product version: `10.0.19041.5487`
- Image base: `0x1C0000000`
- Image size: `0xA7000`
- SHA-256: `441d4adfc0e5c988fb34f0cc8381c4ad6c87ef6de4e3793954819a666b6d4a14`
- IDA MCP survey binary hash matches the on-disk `afd.sys` hash.
- Functions: 1084 total, 1075 named
- Named functions are available in IDA MCP.

This is the Windows 10 22H2 AFD binary currently loaded in IDA. The file version remains on the `19041` component branch, while the target OS family is Windows 10 22H2 / 19045.

## Key Functions

| Address | Name | Role |
|---|---|---|
| `0x1C0037408` | `AfdCreate` | IRP_MJ_CREATE dispatch; references `AfdOpenPacketXX` and `AfdSwOpenPacket` |
| `0x1C0037BB8` | `AfdAllocateEndpoint` | Allocates and initializes AFD endpoint objects |
| `0x1C0003258` | `AfdTlFindAndReferenceTransport` | Walks `AfdTlTransportListHead` by AF/socket type/protocol |
| `0x1C003B634` | `AfdGetTransportInfo` | Walks or creates classic transport-info entries by device name |
| `0x1C0034DE0` | `AfdBind` | Validates bind address, stores local address at endpoint `+0xDC/+0xE0`, sets bound/listening state |
| `0x1C004D690` | `AfdConnect` | Validates peer endpoint, creates connection object, transitions endpoint to connected state |

## AFD_ENDPOINT Size

`AfdAllocateEndpoint` charges and clears one of two endpoint sizes:

| Path | Size | Evidence |
|---|---:|---|
| Standard/classic endpoint | `0x1C0` / 448 bytes | `Amount = 448`, `memset(..., 448)` |
| TL-extended endpoint | `0x1E0` / 480 bytes | `Amount = 480`, `memset(..., 480)` |

## AFD_ENDPOINT Fields Confirmed In Current Image

| Offset | Size | Field | Evidence |
|---:|---:|---|---|
| `+0x00` | WORD | Type/signature | `AfdAllocateEndpoint`: writes `0xAFD0` for normal endpoints, `0xAAFD` for special endpoints. `AfdBind` and `AfdConnect` compare `0xAFD1`/`0xAAFD` states. |
| `+0x02` | BYTE | State | `AfdAllocateEndpoint`: writes `1` or `8`; `AfdBind`: validates and later writes `3` or `4`; `AfdConnect`: checks `1/2/3/4` depending path. |
| `+0x08` | DWORD | Flags | `AfdAllocateEndpoint`: sets bit `0x100` when a TL transport is stored; `AfdBind` branches on `flags & 0x100`. |
| `+0x10` | DWORD | Endpoint transport flags | `AfdAllocateEndpoint` and `AfdBind`: copy `TransportInfo+0x38` into endpoint `+0x10` when the transport is qualified. |
| `+0x18` | QWORD | Classic file/object field | `AfdBind`: rejects non-TL endpoint if this field is already set. Cleanup dereferences it on failure. |
| `+0x20` | QWORD | Device object / TDI device field | Used by bind/connect call-driver setup. |
| `+0x28` | QWORD | Owning `PEPROCESS` | `AfdAllocateEndpoint`: stores `IoGetCurrentProcess()` at `+0x28` and references it. `AfdConnect`: passes `*(PEPROCESS *)(ep+0x28)` to `AfdCreateConnection`. |
| `+0x30` | KSPIN_LOCK | Endpoint spin lock | `AfdAllocateEndpoint`: `KeInitializeSpinLock(ep+0x30)`. `AfdConnect`: `KeAcquireInStackQueuedSpinLock(ep+0x30)`. |
| `+0x38` | DWORD | Reference count | `AfdAllocateEndpoint`: initializes to `2`. Bind/connect paths increment/decrement it. |
| `+0x3C` | DWORD | Listen/backlog related state | `AfdBind`: writes `4` to `ep+0x3C` for `0xAFD1` listen transition. |
| `+0xB0` | QWORD | Connection/listener | `AfdBind`/`AfdConnect`: store connection object at `ep+0xB0`. |
| `+0xC0` | QWORD | Connect data buffer pointer | `AfdConnect`: tests `ep+0xC0` before connect data setup. |
| `+0xDC` | DWORD | Local address size | `AfdBind`: writes `r12d` at `ep+0xDC` on both TL and classic paths. |
| `+0xE0` | QWORD | Local address pointer | `AfdBind`: writes `r15` at `ep+0xE0` on both TL and classic paths. |
| `+0xE8` | DWORD | Pending operation count | `AfdBind`: increments `ep+0xE8` before dispatching bind IRP. |
| `+0xF0` | QWORD | Classic TDI handle | `AfdBind` cleanup closes `ep+0xF0`; `AfdConnect` passes it to `AfdCreateConnection`. |
| `+0xF8` | QWORD | TransportInfo pointer | `AfdAllocateEndpoint`: stores TL or classic transport pointer at `ep+0xF8`; `AfdBind` uses `lea rax, [rdi+0F8h]`. |
| `+0x110` | LIST_ENTRY | IRP list | `AfdAllocateEndpoint`: initializes `ep+0x110` as a self-referencing list. |
| `+0x158` | DWORD | Bind/connect lock | `AfdBind` and `AfdConnect`: `lock cmpxchg [ep+0x158]`. |
| `+0x1A8` | DWORD | Group ID | `AfdAllocateEndpoint`: stores `arg_28` at `ep+0x1A8`. |
| `+0x1AC` | DWORD | Group metadata | `AfdAllocateEndpoint`: stores `AfdGetGroup` output at `ep+0x1AC`. |
| `+0x1D0` | QWORD | TL extended transport pointer | `AfdAllocateEndpoint`: stores optional TL extended transport pointer for 480-byte endpoint. |

## TransportInfo Layouts

There are two relevant transport-info shapes in this Win10 image.

### TL TransportInfo (`AfdTlTransportListHead`)

`AfdTlFindAndReferenceTransport` walks `AfdTlTransportListHead` and matches:

| Offset | Size | Field | Evidence |
|---:|---:|---|---|
| `+0x00` | LIST_ENTRY | Linked-list entry | Traversal loads next pointer from `[entry+0x00]`. |
| `+0x10` | LONG | RefCount | `AfdTlReferenceTransport` increments this count. |
| `+0x14` | BYTE | Qualified flag | `AfdBind` checks `TransportInfo+0x14` before querying provider info. |
| `+0x16` | USHORT | AddressFamily | `AfdTlFindAndReferenceTransport`: `movzx eax, word ptr [rdi+16h]`. |
| `+0x18` | DWORD | Protocol | `AfdTlFindAndReferenceTransport`: `cmp [rdi+18h], ebp`. |
| `+0x1C` | WORD | SocketType | `AfdTlFindAndReferenceTransport`: `cmp [rdi+1Ch], si`. |
| `+0x38` | DWORD | TransportFlags | `AfdBind`: reads `[TransportInfo+0x38]` and writes endpoint `+0x10`. |

### Classic TransportInfo (`AfdTransportInfoListHead`)

`AfdGetTransportInfo` walks `AfdTransportInfoListHead` by device name. This layout is not the same as the TL list at `+0x18`.

| Offset | Size | Field | Evidence |
|---:|---:|---|---|
| `+0x00` | LIST_ENTRY | Linked-list entry | Traversal loads next pointer from `[entry+0x00]`. |
| `+0x10` | LONG | RefCount | New entry initializes `+0x10 = 1`; lookup increments it with `lock cmpxchg/inc`. |
| `+0x14` | BYTE | Qualified flag | New entry initializes `+0x14 = 0`; provider query sets it to `1`. |
| `+0x18` | UNICODE_STRING | Device name | New entry initializes `UNICODE_STRING` at `entry+0x18`; lookup compares `RtlCompareUnicodeString(entry+0x18, requestedName)`. |
| `+0x28` | provider info | Provider information block | `AfdQueryProviderInfo` output copies first 16-byte block to `entry+0x28`. |
| `+0x38` | DWORD/part of provider block | Transport flags source | `AfdBind`: reads `[TransportInfo+0x38]` and writes endpoint `+0x10` once qualified. |
| `+0x48` | provider info | Provider information tail | `AfdQueryProviderInfo` output copies tail pointer/qword to `entry+0x48`. |
| `+0x50` | WCHAR buffer | Device-name storage | New entry allocates `String2->Length + 0x52`, sets `Buffer = entry+0x50`. |

Important: for classic entries, `TransportInfo+0x18` is a `UNICODE_STRING`, not protocol. Code must not interpret classic `+0x18` as a DWORD protocol. The endpoint flag `AFD_ENDPOINT+0x08 & 0x100` identifies the TL transport path where `+0x16/+0x18/+0x1C` are AF/protocol/socket type.

## Device Name Mapping

`AfdAllocateEndpoint` maps AF/socket type/protocol to these device names before validating with `RtlEqualUnicodeString` or `RtlPrefixUnicodeString`:

| AF | SocketType | Protocol | Device |
|---:|---:|---:|---|
| `2` / `AF_INET` | `1` / stream | `6` / TCP | `\Device\Tcp` |
| `2` / `AF_INET` | `2` / datagram | `17` / UDP | `\Device\Udp` |
| `2` / `AF_INET` | `3` / raw | any accepted raw protocol | `\Device\RawIp` |
| `23` / `AF_INET6` | `1` / stream | `6` / TCP | `\Device\Tcp6` |
| `23` / `AF_INET6` | `2` / datagram | `17` / UDP | `\Device\Udp6` |
| `23` / `AF_INET6` | `3` / raw | any accepted raw protocol | `\Device\RawIp6` |

## Pattern Signatures Confirmed In Current Image

### LocalAddr Ptr and Size in `AfdBind`

Current Win10 uses `r15` for the local address pointer, not `rdx`.

| Pattern | Address(es) | Meaning |
|---|---|---|
| `4C 89 BF E0 00 00 00` | `0x1C003519F`, `0x1C0035244` | `mov [rdi+0E0h], r15` -> LocalAddr Ptr |
| `44 89 A7 DC 00 00 00` | `0x1C00351A6`, `0x1C003524B` | `mov [rdi+0DCh], r12d` -> LocalAddr Size |
| `4C 89 BF ?? ?? 00 00 44 89 A7 ?? ?? 00 00` | `0x1C003519F`, `0x1C0035244` | Stable pair; first displacement is ptr, second displacement is size |

The older Win10 claim `48 89 97 E0 00 00 00` is not present in this current image and must not be used as the primary Win10 signature.

### TransportInfo in `AfdBind`

| Pattern | Address(es) | Meaning |
|---|---|---|
| `48 8D 87 F8 00 00 00` | `0x1C00351EA`, `0x1C0035234` | `lea rax, [rdi+0F8h]` -> address of endpoint TransportInfo pointer |

The Win11 docs use an `rbx`-based `48 8D 9F ...` form. Current Win10 uses `rax` (`48 8D 87 F8 00 00 00`) in `AfdBind`.

## Driver Source Alignment

Checked against `driver/WhosWho/WhosWho/src/function/impl/Network.cpp`:

| Source item | Required Win10 22H2 behavior | Current status |
|---|---|---|
| `g_afd_fallback_win10` | `{ transport=0xF8, local_size=0xDC, local_ptr=0xE0 }` | Matches |
| Win10 local address pattern | `4C 89 BF ?? ?? 00 00 44 89 A7 ?? ?? 00 00` | Matches |
| Win10 transport-info pattern | `48 8D 87 F8 00 00 00` preferred; no `48 8D 9F F8...` required | Matches |
| Endpoint signature gate | Accept `0xAFD0`, `0xAAFD`, `0xAFD1`, `0xAFD2` before trusting `FsContext` | Matches |
| TL/classic discriminator | Parse TL AF/protocol only when `AFD_ENDPOINT+0x08 & 0x100` is set | Matches |
| Classic transport parsing | Treat `TransportInfo+0x18` as a `UNICODE_STRING` device name and derive AF/protocol from `Tcp`, `Udp`, `RawIp`, `Tcp6`, `Udp6`, `RawIp6` | Matches |
| Static fallback logging | Dynamic scan failure logs the static table source | Matches |

No Windows 10 22H2 driver source change is required for this AFD layout. The source already follows the layout and extraction behavior proven by the loaded binary.

For this current Win10 image, network code must use:

| Field | Required value |
|---|---:|
| `AFD_ENDPOINT.TransportInfo` | `0xF8` |
| `AFD_ENDPOINT.LocalAddrSize` | `0xDC` |
| `AFD_ENDPOINT.LocalAddrPtr` | `0xE0` |
| `AFD_ENDPOINT.Flags` | `0x08` |
| `AFD_ENDPOINT.PEPROCESS` | `0x28` |
| `TL TransportInfo.AddressFamily` | `0x16` |
| `TL TransportInfo.Protocol` | `0x18` |
| `TL TransportInfo.SocketType` | `0x1C` |
| `TL TransportInfo.TransportFlags` | `0x38` |
| `Classic TransportInfo.DeviceName` | `0x18` as `UNICODE_STRING` |
| `Classic TransportInfo.TransportFlags/provider block` | includes `0x38` |

Required extraction behavior:

- Validate endpoint signatures before trusting `FsContext`: accept `0xAFD0`, `0xAAFD`, `0xAFD1`, `0xAFD2`.
- Read TL AF/protocol only when `AFD_ENDPOINT.Flags & 0x100` is set.
- For non-TL/classic endpoints, derive AF/protocol from the classic device-name `UNICODE_STRING` at `TransportInfo+0x18`.
- Parse local address from endpoint `+0xDC/+0xE0`.
- Treat dynamic scan failure as diagnostic evidence and log the selected static table source.

## Summary

Current Windows 10 22H2 `afd.sys` version `10.0.19041.5487` matches the existing endpoint offset tuple `{ transport=0xF8, local_size=0xDC, local_ptr=0xE0 }`.

The important correction is the Win10 signature pattern and classic transport layout:

- Local address pointer store is `4C 89 BF E0 00 00 00`, not `48 89 97 E0 00 00 00`.
- TransportInfo address calculation is `48 8D 87 F8 00 00 00`, not the Win11 `48 8D 9F ...` form.
- Classic `TransportInfo+0x18` is a `UNICODE_STRING`; only TL transports use `+0x16/+0x18/+0x1C` as AF/protocol/socket type.
