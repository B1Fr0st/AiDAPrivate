# tdx.sys Vulnerability Analysis Report

## Target: tdx.sys (TDI Transport Driver)
- **File**: `C:\Windows\System32\drivers\tdx.sys`
- **Architecture**: x64
- **Image Size**: 0x24000 (147,456 bytes)
- **MD5**: 7fc44f8f693b13e2a048d190e913387e
- **SHA256**: f5396ebe8e13e0257146e6e78112e6034e3f33bdb7b37c3e67aedaaacb616264
- **Base Address (IDA)**: 0x1c0000000
- **PDB**: tdx.pdb
- **Source paths**: minio\netio\session\tdi\{address.c, connection.c, request.c, transport.c, tdiprovider.c, tlclient.c, channel.c}
- **Total Functions**: 273 (266 named, 7 library)
- **Total Strings**: 223

## Objective

Hunt for a driverless, traceless kernel R/W primitive on Windows 10 22H2 (build 19045) via GDI SURFACE (bitmap) pvScan0 corruption at offset 0x50. Specifically searching tdx.sys for:
1. A kernel pool allocation of ~616-720 bytes that does NOT zero on free
2. An arbitrary kernel write primitive
3. A pool overflow
4. A use-after-free
5. A kernel address leak

---

## 1. Binary Overview

### Segments
| Segment | Start | End | Size | Permissions |
|---------|-------|-----|------|-------------|
| .text | 0x1c0001000 | 0x1c0017000 | 0x16000 | rx |
| .rdata | 0x1c0017000 | 0x1c001a000 | 0x3000 | r |
| .data | 0x1c001a000 | 0x1c001b000 | 0x1000 | rw |
| .pdata | 0x1c001b000 | 0x1c001c000 | 0x1000 | r |
| .idata | 0x1c001c000 | 0x1c001c3a0 | 0x3a0 | r |
| .idata | 0x1c001c3a0 | 0x1c001e000 | 0x1c60 | r |
| PAGE | 0x1c001e000 | 0x1c001f000 | 0x1000 | rx |
| INIT | 0x1c001f000 | 0x1c0020000 | 0x1000 | rx |
| .rsrc | 0x1c0021000 | 0x1c0022000 | 0x1000 | r |

### Entrypoint
- `GsDriverEntry` at 0x1c001f010 (calls `DriverEntry` at 0x1c0014c74)

### Device Objects (User-Mode Accessible)
- **\Device\Tdx** - Control device (device type 0x21, flags 0x100 + 0x10)
- **\Device\Ip** - Symbolic link to \Device\Tdx
- **\Device\Ip6** - Symbolic link to \Device\Tdx
- **\DEVICE\TCPIP_{GUID}** - Per-adapter device objects created dynamically
- **\DEVICE\TCPIP6_{GUID}** - IPv6 variant

Users can open these via NtCreateFile. The TDI dispatch table routes to:
- `TdxTdiDispatchCreate` (IRP_MJ_CREATE)
- `TdxTdiDispatchDeviceControl` (IRP_MJ_DEVICE_CONTROL)
- `TdxTdiDispatchInternalDeviceControl` (IRP_MJ_INTERNAL_DEVICE_CONTROL)
- `TdxTdiDispatchCleanup` (IRP_MJ_CLEANUP)
- `TdxTdiDispatchClose` (IRP_MJ_CLOSE)

### Key Imports
| Category | APIs |
|----------|------|
| **Pool** | ExAllocatePoolWithTag, ExAllocatePool2, ExAllocatePoolWithTagPriority, ExFreePoolWithTag |
| **TDI** | TdiRegisterProvider, TdiDeregisterProvider, TdiRegisterDeviceObject, TdiRegisterNetAddress, TdiMapUserRequest, TdiProviderReady |
| **NETIO/NMR** | NmrRegisterClient, NmrRegisterProvider, NmrClientAttachProvider, NsiGetAllParameters, NsiGetParameter, NsiSetAllParameters, RtlCopyMdlToBuffer, RtlCopyBufferToMdl |
| **MDL** | IoAllocateMdl, MmProbeAndLockPages, MmMapLockedPagesSpecifyCache, MmUnlockPages, IoFreeMdl |
| **Sync** | KeAcquireSpinLockRaiseToDpc, KeReleaseSpinLock, KeWaitForSingleObject, KeInitializeEvent, KeSetEvent |
| **Objects** | ObReferenceObjectByHandle, ObfDereferenceObject, IoCreateDevice, IoDeleteDevice |
| **Security** | SeAssignSecurity, SeLockSubjectContext, SeUnlockSubjectContext, ObLogSecurityDescriptor |
| **Probing** | MmUserProbeAddress (used for user buffer bounds checks) |

---

## 2. Pool Allocation Summary

### Pool Tag Table

| Tag (hex) | Tag (ASCII) | Size (bytes) | Pool Type | API | Zeroed on Alloc? | Zeroed on Free? | Function |
|-----------|-------------|--------------|-----------|-----|------------------|-----------------|----------|
| 0x41786454 | TdxA | 816 (0x330) | NonPagedPoolNx | ExAllocatePoolWithTag | Yes (memset) | No | TdxCreateTransportAddress |
| 0x43786454 | TdxC | 640 (0x280) | NonPagedPoolNx | ExAllocatePoolWithTag | Yes (memset) | No | TdxCreateConnection |
| 0x49786454 | TdxI | user/48/128 | NonPagedPoolNx/Pool2 | ExAllocatePool2/ExAllocatePoolWithTag | **No** | No | TdxTdiDispatchDeviceControl, TdxTcpSetInformationEx, TdxIssueQueryAddressRequest |
| 0x63786454 | Tdxc | 56 (0x38) | NonPagedPoolNx | ExAllocatePoolWithTag | Yes (OWORD) | No | TdxCreateControlChannel |
| 0x42786454 | TdxB | 48 (0x30) | NonPagedPoolNx | ExAllocatePoolWithTag | **No** | No | TdxSendDatagramTransportAddress, TdxAllocateMessageTlRequest |
| 0x20786454 | Tdx (space) | user/32 | NonPagedPoolNx | ExAllocatePoolWithTagPriority | **No** (query) | No | TdxTcpQueryInformationEx, TdxSendDatagram, TdxAllocateTransportCleanupContext |
| 0x54786454 | TdxT | variable | NonPagedPoolNx | ExAllocatePoolWithTag | No | No | TdxInitializeTransport (2 calls) |
| 0x6F786454 | Tdxo | 312 (0x138) | NonPagedPoolNx | ExAllocatePoolWithTag | Yes (memset) | No | TdxCreateAndRegisterDeviceObject |
| 0x6E786454 | Tdxn | variable (a3+48) | NonPagedPoolNx | ExAllocatePoolWithTag | No | No | TdxCreateAndRegisterNetAddress |
| 0x49436454 | TdCI | 56 (0x38) | NonPagedPoolNx | ExAllocatePoolWithTag | **No** | No | TdxQueryConnectionInfo |

### Pool Type Analysis

All tdx.sys allocations use POOL_TYPE = 512 (0x200) = **NonPagedPoolNx** (regular NonPagedPool, execute-disabled). This is NOT session pool.

GDI SURFACE (bitmap) objects are allocated in **session pool** (NonPagedPool session space), which is a separate pool region from regular NonPagedPool on Windows 10 22H2.

### Pool Bucket Analysis (Win10 22H2 poolv3)

Approximate bucket boundaries: 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024, 1280, ...

| Allocation | Size | Bucket |
|------------|------|--------|
| TdxA (TransportAddress) | 816 | 896 |
| **TdxC (Connection)** | **640** | **640** |
| Tdxo (DeviceObject) | 312 | 320 |
| Tdxc (ControlChannel) | 56 | 64 |
| TdxB (RequestContext) | 48 | 48 |
| TdxI (QueryAddr) | 128 | 128 |
| Tdx (CleanupCtx) | 32 | 32 |
| TdCI (QueryConnInfo) | 56 | 64 |
| **GDI SURFACE** | **952** | **1024** |
| **GDI type-isolation slot** | **704** | **768** |

### Critical Finding: TdxC Connection Object (640 bytes)

The TdxC Connection object at 640 bytes falls within the target range of 616-720 bytes. However:

1. **Pool type mismatch**: TdxC is in regular NonPagedPool; GDI SURFACE is in session pool. Separate pool regions - a freed TdxC allocation **cannot** be reclaimed by a GDI SURFACE spray.

2. **Bucket mismatch**: 640 bytes maps to the 640-byte bucket. The GDI type-isolation slot at 704 bytes maps to the 768-byte bucket. Different buckets have separate free lists.

3. **Zeroed on alloc**: memset to 0 on allocation. While ExFreePoolWithTag does NOT zero on free, stale data can only be reused by another 640-byte NonPagedPool allocation - not a GDI SURFACE.

**Verdict: TdxC (640 bytes) is NOT viable for GDI SURFACE pool reuse.**
---

## 3. User-Mode-Reachable Entry Points

### 3.1 TdxTdiDispatchCreate (0x1c00142b0) - IRP_MJ_CREATE

Handles file open requests. Creates three object types based on EA (Extended Attributes):

1. **Control Channel** (EA name "ConnExt"): TdxCreateControlChannel - 56 bytes (Tdxc), entity type 3
2. **Transport Address** (EA name "TransAddr"): TdxCreateTransportAddress - 816 bytes (TdxA), entity type 1. Validates AF_INET (2) or AF_INET6 (23) and address length.
3. **Connection** (EA name "ConnExtn"): TdxCreateConnection - 640 bytes (TdxC), entity type 2

FsContext2 set to 1 (control), 2 (address), or 3 (connection).

### 3.2 TdxTdiDispatchDeviceControl (0x1c00145a0) - IRP_MJ_DEVICE_CONTROL

| IOCTL Code | Function | Notes |
|------------|----------|-------|
| 0x120003 | TdxTcpQueryInformationEx | Query TCP/IP info |
| 0x120028 | TdxTcpSetInformationEx | Set TCP/IP info |
| 0x128004 | TdxTcpSetInformationEx | Set TCP/IP info (variant) |
| 0x210038 | METHOD_NEITHER IOCTL | Passes user buffers to TdxIssueIoControlRequest |
| 0x210203 | Not supported | STATUS_NOT_SUPPORTED |
| 0x210207 | Not supported | STATUS_NOT_SUPPORTED |

**IOCTL 0x210038 Analysis** (METHOD_NEITHER - most dangerous):
- DeviceType=0x21, Function=0x00E, Method=3 (METHOD_NEITHER)
- Input: Type3InputBuffer (raw user-mode pointer)
- Output: raw user-mode pointer
- IRQL check: must be PASSIVE_LEVEL
- Allowlist: TdxTdiAllowedUserIOControlRequest for user-mode callers
- Buffer handling: pool copy (ExAllocatePool2, TdxI) or MDL lock (MmProbeAndLockPages)
- Output: always MDL-locked with IoWriteAccess
- Forwards to TdxIssueIoControlRequest

**TdxTdiAllowedUserIOControlRequest** (0x1c0002dc4):
- entity_type must be 1, 2, or 3
- type 3 (control channel): only function_code 0 allowed
- type 1 (address) or 2 (connection): all function_codes EXCEPT 0xFFFC and 0xFFFD

### 3.3 TdxTdiDispatchInternalDeviceControl (0x1c0001480)

**Entity type 1 (Address)**:
| Minor | Function |
|-------|----------|
| 3 | TdxConnectTransportAddress |
| 6 | TdxDisconnectTransportAddress |
| 7 | TdxSendTransportAddress |
| 9 | TdxSendDatagramTransportAddress |
| 0xA | TdxReceiveDatagramTransportAddress |
| 0xB | TdxSetEventTransportAddress |
| 0xC | TdxQueryInformationTransportAddress |
| 0x50 | TdxIssueIoControlEndpointRequest |

**Entity type 2 (Connection)**:
| Minor | Function |
|-------|----------|
| 1 | TdxAssociateConnection |
| 2 | TdxDisassociateConnection |
| 3 | TdxConnectConnection |
| 4 | TdxListenConnection |
| 5 | TdxAcceptConnection |
| 6 | TdxDisconnectConnection |
| 7 | TdxSendConnection |
| 8 | TdxReceiveConnection |
| 0xC | TdxQueryInformationConnection |
| 0x50 | TdxIssueIoControlEndpointRequest |

**Entity type 3 (Control channel)**:
| Minor | Function |
|-------|----------|
| 0xC | TdxQueryInformationControlChannel |

---

## 4. Vulnerability Analysis

### 4.1 Pool Overflow Analysis

**TdxSendDatagramTransportAddress (0x1c00014f0)**:
- TdxB alloc (48 bytes, NOT zeroed) - request context, specific fields written, no overflow
- Tdx (space) alloc (variable from sockaddr_size table) - allocation size equals copy size, no overflow
- sockaddr_size table at 0x1c0017878: index 2=16 (AF_INET), index 22=28 (AF_INET6)
- When transport has address: v21 hardcoded to 23, v37=28, TaListToSockAddr writes to 28-byte buffer - no overflow
- When no transport address: v37 from user data, memmove size = alloc size - no overflow

**TdxTcpQueryInformationEx (0x1c0012a68)**:
- User-controlled allocation size, copy size = alloc size - no overflow
- Output through zeroed stack buffers via RtlCopyBufferToMdl

**TdxTdiDispatchDeviceControl (0x210038 path)**:
- User-controlled allocation, memmove size = alloc size - no overflow

**Verdict: No pool overflow found in any tdx.sys code path.**

### 4.2 Use-After-Free Analysis

**Object Lifecycle**:
1. Creation: allocate, zero (TdxA/TdxC/Tdxc), initialize, attach, refcount=1
2. Reference: InterlockedIncrement on refcount
3. Dereference: InterlockedDecrement; at 0, TdxCleanupObjectHeader + ExFreePoolWithTag
4. Deletion: TdxDeleteObjectHeader sets delete-pending flag under spinlock, returns STATUS_PENDING

**TdxDeleteObjectHeader (0x1c0005e3c)**:
- Acquires spinlock, checks delete flag, sets bit 0, stores cleanup context, releases spinlock
- Does NOT free - actual free deferred to refcount reaching 0

**TdxDeleteConnection (0x1c0009d50)**:
- Acquires spinlock, reads associated address BEFORE setting delete flag
- References address while holding spinlock
- Sets delete-in-progress (0x200), decrements endpoint ref
- Disassociates, dereferences address
- Calls TdxDeleteObjectHeader

**Race condition assessment**: All object access protected by per-object spinlocks. Reference counting uses interlocked operations. Delete path references associated objects before proceeding.

**Verdict: No obvious UAF found. Reference counting with spinlock protection appears correct. Subtle races in async completion paths cannot be fully ruled out without dynamic analysis.**

### 4.3 Arbitrary Kernel Write Analysis

**TdxTcpSetInformationConnectionEx (0x1c0013b0c)**:
- Case 1 (TCP_NODELAY): writes flags at offset 0 of connection object
- Case 2 (TCP_BSDURGENT): writes flags at offset 0
- Case 6 (TCP_KEEPALIVE): writes 8 bytes at offset 0x38, 4 bytes at offset 0x40

The a4 parameter is the connection endpoint pointer from FsContext - user does NOT control it. Writes go to fixed offsets in the caller's own kernel object.

**Verdict: No arbitrary kernel write found. All writes go to fixed offsets within the caller's own kernel objects.**

### 4.4 Kernel Address Leak Analysis

**TdxQueryInformationControlChannel (0x1c000887c)**:
- Case 2: copies 40 bytes from transport+112 (configuration data, not pointers)
- Case 5: copies 216 bytes from zeroed stack buffer - no leak

**TdxTcpQueryInformationEx (0x1c0012a68)**:
- All output paths use memset-zeroed stack buffers
- Data from NsiGetAllParameters (network config, not kernel addresses)
- Pool buffer used as INPUT only, not output
- No stale pool data leaks to user mode

**Non-zeroed pool allocations (TdxB, TdxI, TdCI)**: Used for internal request contexts, NOT returned to user mode.

**Verdict: No kernel address leak found. All output paths use zeroed stack buffers or validated network stack data.**

### 4.5 Additional Observations

**IOCTL 0x210038 (METHOD_NEITHER)**: Handles raw user-mode pointers but properly probes. TOCTOU race between probe and use is theoretically possible but mitigated by MDL locking or pool copy.

**Feature Flag Dependencies**:
- Feature_903393592: Changes buffer handling (MDL vs pool copy)
- Feature_1041825081: Additional address family validation in send datagram
- Feature_Servicing_MemoryAllocationFailure: Changes pool flags for ExAllocatePool2
- Feature_2764111161: Blocks specific IOCTL function codes

**sockaddr_size Table (0x1c0017878)**:
Index 2=0x10 (16, AF_INET), Index 22=0x1C (28, AF_INET6), bounds check v21 < 0x23 (35). No OOB read.

---

## 5. Detailed Function Analysis

### TdxCreateTransportAddress (0x1c00053a0)
- Alloc: ExAllocatePoolWithTag(NonPagedPoolNx, 0x330, "TdxA") - 816 bytes, memset zeroed
- Validates AF_INET (len 14-126) or AF_INET6 (len 26-126)
- Security: SeAssignSecurity + ObLogSecurityDescriptor
- Free: ExFreePoolWithTag(v19, 0) - tag 0

### TdxCreateConnection (0x1c0009b70)
- Alloc: ExAllocatePoolWithTag(NonPagedPoolNx, 0x280, "TdxC") - 640 bytes, memset zeroed
- Free: ExFreePoolWithTag(v19, 0) - tag 0

### TdxCreateControlChannel (0x1c0008708)
- Alloc: ExAllocatePoolWithTag(NonPagedPoolNx, 0x38, "Tdxc") - 56 bytes, OWORD zeroed
- Free: ExFreePoolWithTag(PoolWithTag, 0) - tag 0

### TdxDeleteObjectHeader (0x1c0005e3c)
- Sets delete-pending flag (bit 0) under spinlock, returns STATUS_PENDING
- Does NOT free - deferred to refcount=0

### TdxIssueIoControlRequest (0x1c00118a4)
- For connections: references connection, calls TL dispatch, waits for completion
- For addresses: references address, selects TL request, calls TL dispatch
- Dereferences after completion

---

## 6. Exploitation Assessment

### 6.1 GDI SURFACE pvScan0 Corruption via tdx.sys

**VERDICT: NOT VIABLE**

| Requirement | Status | Details |
|------------|--------|---------|
| Pool alloc 616-720 bytes, no zero on free | PARTIAL | TdxC is 640 bytes, not zeroed on free, BUT in regular NonPagedPool not session pool |
| Arbitrary kernel write | NOT FOUND | All writes go to fixed offsets in caller's own objects |
| Pool overflow | NOT FOUND | All allocation sizes match copy/write sizes |
| Use-after-free | NOT FOUND | Reference counting with spinlock protection appears correct |
| Kernel address leak | NOT FOUND | Output paths use zeroed stack buffers |

### 6.2 Why tdx.sys Fails for This Attack

1. **Session Pool Isolation (FUNDAMENTAL BLOCKER)**: GDI SURFACE objects live in session pool, completely separate from regular NonPagedPool where tdx.sys allocates. Separate free lists, separate tracking, separate VA ranges. A freed tdx allocation will NEVER be reclaimed by a GDI SURFACE.

2. **Pool Bucket Mismatch**: TdxC (640) -> bucket 640; GDI TI slot (704) -> bucket 768. Different buckets, separate free lists.

3. **Zeroed-on-Alloc**: TdxA (816) and TdxC (640) are both memset-zeroed on alloc. Stale data overwritten before object init.

4. **No Overflow Vector**: All buffer sizes consistent between allocation and usage.

5. **No Dangling Pointer**: Reference counting (InterlockedIncrement/Decrement + spinlocks) prevents premature free.

### 6.3 Secondary Attack Surface Notes

- **IOCTL 0x210038 (METHOD_NEITHER)**: Raw user-mode pointers, properly probed. TOCTOU theoretically possible but mitigated.
- **Non-zeroed pool (TdxB, TdxI, TdCI)**: Stale pool data, but not returned to user mode.
- **User-controlled alloc sizes**: Could be used for pool exhaustion, but not for targeted corruption.
- **Feature flag dependency**: Buffer handling changes based on Feature_903393592.
- **Complex object lifecycle**: Subtle timing bugs possible under heavy load, but no immediate race found.

---

## 7. Conclusion

tdx.sys is a **well-hardened TDI-to-NMR shim driver** with a small attack surface (147KB, 273 functions). The driver properly uses reference counting, spinlocks, buffer probing, and allocation size validation.

**For the specific GDI SURFACE pvScan0 corruption attack: tdx.sys is NOT a viable attack surface.** The primary blocker is pool type isolation - all tdx allocations are in regular NonPagedPool while GDI SURFACE objects are in session pool. No pool overflow, UAF, arbitrary write, or kernel address leak was found.

**Recommendation**: Abandon tdx.sys for GDI SURFACE corruption. Focus on drivers that:
1. Allocate in session pool (win32k-related drivers, display drivers)
2. Have pool allocations matching the 704-byte type-isolation slot (bucket 768) or 952-byte SURFACE (bucket 1024)
3. Have known buffer overflow or UAF patterns in their IOCTL handlers

Alternative drivers already loaded in IDA: win32k.sys, win32kfull.sys, win32kbase.sys, dxgkrnl.sys, dxgmms1.sys, dxgmms2.sys, portcls.sys, clfs.sys, ntoskrnl.exe.
