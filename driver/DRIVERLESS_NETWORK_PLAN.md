# Driverless Network Capture Plan - AFD Endpoint Walking

## The Problem

WFP callouts require a kernel driver — you cannot register WFP filters
without a loaded driver. The driverless UAF exploit gives us arbitrary
kernel R/W but CANNOT register WFP/NDIS callbacks.

## The Solution: AFD Endpoint Walking

Instead of intercepting packets at the WFP layer (which needs callbacks),
we **walk the AFD endpoint list in kernel memory** and read socket
state directly. This is a polling approach, not a callback approach,
but it gives us the same information.

### How It Works

AFD.sys maintains a linked list of all socket endpoints in the system.
Each endpoint contains:
- The owning process (EPROCESS pointer at +0x28 on Win10, +0x30 on Win11)
- The local address (bound address, at +0xE0 on Win10, +0xF0 on Win11)
- The local address size (at +0xDC on Win10, +0xEC on Win11)
- The TransportInfo pointer (at +0xF8 on Win10, +0x110 on Win11)
- Connection state, peer address, etc.

With arbitrary kernel R/W, we can:
1. Find the AFD endpoint list head (by scanning afd.sys for the global)
2. Walk every endpoint in the system
3. For each endpoint, read the owning process to get PID
4. Read the local address to get bound IP:port
5. Read the TransportInfo to get protocol (TCP/UDP/raw)
6. Read connection state to get peer address
7. Filter by our target PID
8. Return connection table to usermode

### What We Get

| Feature | WFP Callout (driver) | AFD Walking (driverless) |
|---|---|---|
| Connection enumeration | YES | YES |
| Per-PID connections | YES | YES |
| Local/remote addresses | YES | YES |
| Protocol (TCP/UDP) | YES | YES |
| Connection state | YES | YES |
| Real-time packet capture | YES (callback) | NO (polling) |
| Packet modification | YES | NO |
| Packet injection | YES | NO |
| DNS spoofing | YES | NO (but can read DNS queries) |
| Bandwidth monitoring | YES | NO (but can count connections) |
| TCP fingerprinting | NO | NO |

### What We LOSE

- **Real-time packet capture**: We cannot capture individual packets
  without WFP. We can only poll connection state.
- **Packet modification/injection**: Cannot modify or inject packets.
- **DNS spoofing**: Cannot forge DNS responses.

### What We KEEP

- **Full connection table**: All TCP/UDP connections with PID, addresses, state
- **Per-process filtering**: Show only target process connections
- **Connection monitoring**: Poll for new/closed connections
- **Protocol identification**: TCP vs UDP vs raw
- **Local/remote address extraction**: Full IP:port for each endpoint

### AFD_ENDPOINT Offsets (All Versions)

| Field | Win10 21H2/22H2 | Win11 23H2 | Win11 24H2/25H2 | Win11 26H1 |
|---|---|---|---|---|
| Type/Signature | +0x00 | +0x00 | +0x00 | +0x00 |
| State | +0x02 | +0x02 | +0x02 | +0x02 |
| Flags | +0x08 | +0x08 | +0x08 | +0x08 |
| OwningProcess | +0x28 | +0x28 | +0x30 | +0x30 |
| SpinLock | +0x30 | +0x30 | +0x38 | +0x38 |
| RefCount | +0x38 | +0x38 | +0x40 | +0x40 |
| LocalAddrSize | +0xDC | +0xEC | +0xEC | +0xEC |
| LocalAddrPtr | +0xE0 | +0xF0 | +0xF0 | +0xF0 |
| TransportInfo | +0xF8 | +0x110 | +0x110 | +0x110 |
| EndpointListEntry | +0x110 | +0x128 | +0x128 | +0x128 |
| EndpointSize | 0x1C0/0x1E0 | 0x1F0/0x210 | 0x1F0/0x210 | 0x1F0/0x210 |

### TransportInfo Offsets

**TL Transport (Flags & 0x100 set)**:
| Offset | Field |
|---|---|
| +0x00 | LIST_ENTRY (list links) |
| +0x10 | RefCount |
| +0x14 | Qualified flag |
| +0x16 | AddressFamily (USHORT) |
| +0x18 | Protocol (ULONG) |
| +0x1C | SocketType (USHORT) |

**Classic Transport (Flags & 0x100 clear)**:
| Offset | Field |
|---|---|
| +0x00 | LIST_ENTRY (list links) |
| +0x10 | RefCount |
| +0x14 | Qualified flag |
| +0x18 | UNICODE_STRING DeviceName |
| +0x38/+0x40 | TransportFlags |

Classic device name suffixes: Tcp, Udp, RawIp, Tcp6, Udp6, RawIp6

### Implementation Plan

1. **Find AFD endpoint list head**:
   - Scan afd.sys for the global list head variable
   - Or: resolve a known endpoint (create a socket, find its kernel object)
   - Or: walk the AfdAllocateEndpoint function to find the list insert

2. **Walk endpoints** (from kernel polling thread):
   ```
   for each endpoint in AfdEndpointListHead:
       read endpoint type (must be 0xAFD0/0xAAFD/0xAFD1/0xAFD2)
       read OwningProcess -> EPROCESS
       read EPROCESS+UniqueProcessId -> PID
       if PID == target_pid:
           read LocalAddrPtr -> sockaddr
           read LocalAddrSize -> sockaddr length
           read TransportInfo -> AF/protocol
           read State -> connection state
           copy to shared memory response
   ```

3. **Usermode polling** (from comm.cpp replacement):
   - Send "enum connections" command via shared memory
   - Kernel thread walks AFD list, copies matching endpoints
   - Usermode receives connection table
   - Poll every 100ms for updates

4. **Connection state mapping**:
   - State 1 = Unbound
   - State 2 = Bound
   - State 3 = Listening
   - State 4 = Connected
   - State 5 = Closing

### Alternative: NtQuerySystemInformation + GetExtendedTcpTable

For basic connection enumeration, we can also use the existing Windows API
`GetExtendedTcpTable` / `GetExtendedUdpTable` from usermode. These return
PID-tagged connection tables WITHOUT needing kernel access. They work on
all Windows versions and don't require WFP.

However, these APIs:
- Only show TCP/UDP (not raw sockets)
- May be hooked by anti-cheat
- Don't show connection state in detail
- Are slower than direct kernel walking

For a P2C, the kernel AFD walking approach is better because:
- Anti-cheat cannot hook it (it's our kernel thread, not an API call)
- We get full endpoint state
- We can filter by PID at the kernel level
- It's invisible to usermode monitoring

### DNS Query Monitoring

For DNS query monitoring (without WFP):
- Read the DNS client cache in kernel memory
- Or: walk UDP endpoints on port 53
- Or: read the system DNS resolver state
- This gives us "what domains is the game resolving" without packet capture

### Summary

We CAN keep network features in a driverless P2C by replacing WFP callback-based
capture with AFD endpoint walking via kernel R/W. We lose real-time packet
capture and packet modification, but we keep full connection table enumeration,
per-PID filtering, and protocol/address extraction. This is sufficient for a P2C
that needs to monitor game network connections.
