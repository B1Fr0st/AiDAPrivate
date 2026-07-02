# condrv.sys — Kernel Vulnerability Analysis

## 1. Binary Survey

| Property | Value |
|----------|-------|
| **Module** | condrv.sys |
| **Architecture** | x64 |
| **Base Address** | 0x1C0000000 |
| **Image Size** | 0x12000 (72 KB) |
| **Total Functions** | 118 |
| **Named Functions** | 114 |
| **Total Strings** | 117 |
| **Segments** | 10 (.text, .rdata, .data, .pdata, .idata, PAGE, INIT, .rsrc) |
| **MD5** | 132d6ff8adefdc7e33905b04d32c220f |

### Segment Layout

| Segment | Start | End | Size | Permissions |
|---------|-------|-----|------|-------------|
| .text | 0x1C0001000 | 0x1C0002000 | 0x1000 | rx |
| .rdata | 0x1C0002000 | 0x1C0004000 | 0x2000 | r |
| .data | 0x1C0004000 | 0x1C0005000 | 0x1000 | rw |
| .pdata | 0x1C0005000 | 0x1C0006000 | 0x1000 | r |
| .idata | 0x1C0006000 | 0x1C0007000 | 0x2B0 | r |
| PAGE | 0x1C0007000 | 0x1C000E000 | 0x7000 | rx |
| INIT | 0x1C000E000 | 0x1C000F000 | 0x1000 | rx |
| .rsrc | 0x1C0010000 | 0x1C0011000 | 0x1000 | r |

### Key Imports

| Category | Notable APIs |
|----------|-------------|
| **Pool** | ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag, ExFreePoolWithTag |
| **MDL** | IoAllocateMdl, MmBuildMdlForNonPagedPool, MmProbeAndLockPages, MmMapLockedPagesSpecifyCache, MmUnlockPages, IoFreeMdl |
| **IRP** | IoAllocateIrp, IoFreeIrp, IofCompleteRequest, IoCancelIrp |
| **Locks** | ExAcquirePushLockExclusiveEx, ExReleasePushLockExclusiveEx, ExAcquirePushLockSharedEx, ExReleasePushLockSharedEx, KeEnterCriticalRegion, KeLeaveCriticalRegion |
| **Process** | KeStackAttachProcess, KeUnstackDetachProcess, PsIsSystemProcess, IoGetRequestorProcess, PsGetCurrentProcess, PsGetProcessId, PsGetProcessPeb, ZwCreateUserProcess, PsResumeProcess, ZwTerminateProcess |
| **Security** | SePrivilegeCheck, SeAccessCheck, SeAssignSecurityEx, SeQuerySecurityDescriptorInfo, SeSetSecurityDescriptorInfo |
| **Objects** | ObReferenceObjectByHandle, ObfReferenceObject, ObfDereferenceObject, ObfReferenceObjectWithTag, ObfDereferenceObjectWithTag |
| **Probe** | ProbeForWrite, MmUserProbeAddress, ExRaiseDatatypeMisalignment, ExGetPreviousMode |
| **Console** | BgkGetConsoleState, BgkDisplayCharacter, BgkSetCursor |

---

## 2. User-Mode-Reachable Interfaces

### 2.1 Device Object

condrv.sys creates a single device object (`CdDeviceObject`) in `DriverEntry` (0x1C000E080). The device is accessible via `\\.\ConDrv\<ObjectName>` or `NtCreateFile` with path `\Device\ConDrv\<ObjectName>`.

### 2.2 Object Creation Table (CdpDispatchCreate)

`CdpDispatchCreate` (0x1C000AF30) looks up the file name suffix in `CdpObjectCreationTable` (12 entries at 0x1C0003450). Each entry maps a name to a creation function.

| Entry | Name | Creation Function | Param | User-Accessible | Privilege Required |
|-------|------|-------------------|-------|-----------------|-------------------|
| 0 | `\Connect` | CdCreateConnection (0x1C0007BF0) | 0 | Yes | None |
| 1 | `\KernelConnect` | CdCreateKernelConnection (0x1C000CAB0) | 0 | No (RequestorMode check) | Kernel only |
| 2 | `\Reference` | CdCreateReferenceObject (0x1C000B190) | 0 | Yes | None |
| 3 | `\Input` | CdCreateDefaultObjectClient (0x1C00073C0) | 1 | Yes | None |
| 4 | `\Output` | CdCreateDefaultObjectClient (0x1C00073C0) | 2 | Yes | None |
| 5 | `\Server` | CdCreateServer (0x1C0007010) | 0 | Yes | None |
| 6 | `\Console` | CdCreateClient (0x1C0008400) | 4 | Yes | None |
| 7 | `\CurrentIn` | CdCreateClient (0x1C0008400) | 1 | Yes | None |
| 8 | `\CurrentOut` | CdCreateClient (0x1C0008400) | 2 | Yes | None |
| 9 | `\ScreenBuffer` | CdCreateClient (0x1C0008400) | 3 | Yes | None |
| 10 | `\Broker` | CdCreateBroker (0x1C000BFD0) | 0 | Yes | SeTcbPrivilege |
| 11 | `\Display` | CdCreateDisplayObject (0x1C000D4F0) | 0 | Yes | SeTcbPrivilege |

### 2.3 Dispatch Table (vtable-based)

All dispatch routines (`CdpDispatchDeviceControl`, `CdpDispatchWrite`, `CdpDispatchRead`, etc.) use a vtable stored in the file object's `FsContext`. The vtable is retrieved from the object header and dispatched through function pointers.

**Vtable layout** (offsets in QWORDs from vtable base):
- `[+0]`: Type object pointer (e.g., `CdClientType`, `CdServerType`, `CdConnectionType`, `CdBrokerType`, `CdDisplayType`, `CdReferenceType`)
- `[+1]`: Read handler
- `[+2]`: Write handler
- `[+3]`: IOCTL handler
- `[+6]`: Fast IOCTL handler

### 2.4 IOCTL Codes

All IOCTLs use DeviceType 0x50 (FILE_DEVICE_CONSOLE).

| IOCTL Code | Value | Function | Method | Handler | Description |
|------------|-------|----------|--------|---------|-------------|
| 0x500006 | 5242886 | 1 | METHOD_OUT_DIRECT | CdpServerIoctl / CdpServerFastIoctl / CdpBrokerFastIoctl | Read pending IO / Complete IO (size=40) |
| 0x50000B | 5242891 | 2 | METHOD_NEITHER | CdpServerFastIoctl / CdpBrokerFastIoctl | Complete IO (validated size=40) |
| 0x50000F | 5242895 | 3 | METHOD_NEITHER | CdpServerFastIoctl / CdpBrokerFastIoctl | Read IO input (size=24) |
| 0x500013 | 5242899 | 4 | METHOD_NEITHER | CdpServerFastIoctl | Write IO output (size=24) |
| 0x500016 | 5242902 | 5 | METHOD_OUT_DIRECT | CdpClientIoctl / CdpConnectionIoctl | Submit user IO |
| 0x50001B | 5242907 | 6 | METHOD_NEITHER | CdpServerFastIoctl / CdpBrokerFastIoctl | Disconnect IO pipe |
| 0x50001F | 5242911 | 7 | METHOD_NEITHER | CdpServerFastIoctl | Set server information (event handle) |
| 0x500023 | 5242915 | 8 | METHOD_NEITHER | CdpConnectionFastIoctl | Get connection property (kernel ptr leak) |
| 0x500027 | 5242919 | 9 | METHOD_NEITHER | CdpDisplayFastIoctl | Get display size |
| 0x50002B | 5242923 | 10 | METHOD_NEITHER | CdpDisplayFastIoctl | Update display |
| 0x50002F | 5242927 | 11 | METHOD_NEITHER | CdpDisplayFastIoctl | Set cursor information |
| 0x500033 | 5242931 | 12 | METHOD_NEITHER | CdpServerFastIoctl | Set server flag |
| 0x500037 | 5242935 | 13 | METHOD_NEITHER | CdpServerFastIoctl | Launch server process |
| 0x50003B | 5242939 | 14 | METHOD_NEITHER | CdpDisplayFastIoctl | Get font size |

### 2.5 Write/Read Paths

- **WriteFile** → `CdpDispatchWrite` → vtable[2] → `CdpClientWrite` (for client objects)
  - Maps user buffer via MDL, creates IO entry, queues to pipe via `CdAddIoToPipe`
- **ReadFile** → `CdpDispatchRead` → vtable[1] → `CdpServerIoctl` (IOCTL 0x500006) or `CdReadNextIo` (broker)
  - Queues read IRP pending; completed when write-side submits data

---

## 3. Pool Allocations

### 3.1 Complete Allocation Table

| Allocator Function | Size (bytes) | Hex | Pool Type | Tag | User-Reachable | LFH Bucket |
|--------------------|-------------|-----|-----------|-----|----------------|------------|
| CdpAllocateClient | 40 | 0x28 | PagedPool | CdCl | Yes | 48 |
| CdpCreateServerConnectionIo (#1) | 64 | 0x40 | NonPagedPoolNx | CdCo | Yes (indirect via Connect) | 64 |
| CdpCreateServerConnectionIo (#2) | 32 | 0x20 | NonPagedPoolNx | CdCc | Yes (indirect via Connect) | 32 |
| CdCreateKernelConnection | 16 | 0x10 | NonPagedPoolNx | CdCc | No (kernel only) | 16 |
| CdpAllocateKernelConnectionIrp | user-controlled | varies | NonPagedPoolNx | CdCc | No (kernel only) | N/A |
| CdpAllocateServer | 264 | 0x108 | PagedPool+Quota | CdSe | Yes (via \Server) | 288 |
| CdCreateClient | 24 | 0x18 | NonPagedPoolNx+Quota | CdCc | Yes (via \Console etc.) | 32 |
| CdpAllocateReferenceObject | 16 | 0x10 | PagedPool+Quota | CdRf | Yes (via \Reference) | 16 |
| CdCreateBroker | 168 | 0xA8 | PagedPool+Quota | CdBr | Yes (needs SeTcbPrivilege) | 176 |
| CdCreateDisplayObject | 8 | 0x08 | PagedPool+Quota | CdDi | Yes (needs SeTcbPrivilege) | 16 |

### 3.2 Pool Tags (decoded)

| Tag Value | ASCII | Purpose |
|-----------|-------|---------|
| 0x6C436443 | CdCl | Client object |
| 0x6F436443 | CdCo | Connection object |
| 0x63436443 | CdCc | Client completion / Connection IO |
| 0x65536443 | CdSe | Server object |
| 0x66526443 | CdRf | Reference object |
| 0x72426443 | CdBr | Broker object |
| 0x69446443 | CdDi | Display object |

### 3.3 Allocation Details

**CdpAllocateClient** (0x1C000A160):
```c
ExAllocatePoolWithTag(PagedPool, 0x28, 'CdCl');
// 5 QWORDs: [0]=CdClientType, [1-4]=zeroed
```

**CdpCreateServerConnectionIo** (0x1C0007CD0):
```c
// Connection object (NonPagedPoolNx when system process, else NonPagedPoolNx+Quota):
ExAllocatePoolWithTag(NonPagedPoolNx, 0x40, 'CdCo');
// 8 QWORDs: [0]=CdConnectionType, [1-2]=self-linked list, [3]=server, [4]=process, [5-7]=zeroed

// Connection IO buffer (NonPagedPoolNx):
ExAllocatePoolWithTag(NonPagedPoolNx, 0x20, 'CdCc');
// 4 QWORDs: [0]=connection ptr, [1-3]=MDL data (24 bytes probed for MDL)
```

**CdpAllocateServer** (0x1C00071B0):
```c
ExAllocatePoolWithQuotaTag(PagedPool+RAISE, 0x108, 'CdSe');
// 264 bytes, zeroed, [0]=CdServerType, [3]=refcount=1
// Contains IO pipe (5 hash buckets + queue), server list links, process info
```

**CdCreateClient** (0x1C0008400):
```c
ExAllocatePoolWithQuotaTag(NonPagedPoolNx+RAISE, 0x18, 'CdCc');
// 3 DWORDs: [0]=client ptr, [1]=type param, [2]=share access, [3-5]=desired access
// MDL created for 12 bytes at offset 8 (NonPagedPool, MmBuildMdlForNonPagedPool)
```

---

## 4. Vulnerability Analysis

### 4.1 Data Flow Architecture

condrv.sys implements a pipe-like architecture for console I/O:

1. **Write side**: User process opens a Client handle, sends data via WriteFile or IOCTL 0x500016
2. **Read side**: conhost.exe opens a Server/Connection handle, reads pending IO via IOCTL 0x500006
3. **Completion**: conhost.exe completes IO via IOCTL 0x50000B (CdCompleteIo), writing output data back to the originator

The IO submission path (`CdAddIoToPipe` / `CdSubmitUserIo`) creates MDL chains from user-supplied buffer descriptors, queues the IRP, and if a read IRP is pending, immediately completes it by copying data into the read IRP's output buffer.

### 4.2 Buffer Validation Analysis

**CdpConnectionIoctl** (IOCTL 0x500016 on Connection objects):
- Input buffer format: `[handle(8)] [count(4)] [size(4)] [descriptors...]`
- Each descriptor: `[size(4)] [padding(4)] [pointer(8)]` = 16 bytes
- Validation:
  - `count + size` overflow check: `(count + size) < count` → rejected
  - Max segments: `count + size > 0xFFFFFFE` → rejected
  - Buffer size: `InputBufferLength < 16 * (count + size + 1)` → rejected
  - Process validation: requestor must match connection owner
  - WOW64 pointer handling: uses 32-bit pointer field for WOW64 processes
- **Verdict**: Validation is correct. Integer overflow is properly checked.

**CdpCreateMdlChain** (0x1C0009760):
- Creates MDLs from user-supplied `{size, pointer}` descriptors
- Uses `IoAllocateMdl` + `MmProbeAndLockPages` for each segment
- WOW64: uses `v11[2]` (32-bit ptr at offset +8) instead of `*((void**)v11 + 1)` (64-bit ptr at offset +8)
- **Verdict**: Standard MDL-based buffer handling. Pages are probed and locked.

**CdAddIoToPipe / CdSubmitUserIo** (IO completion to read IRP):
- Read IRP output buffer minimum: 40 bytes (validated by CdpServerIoctl and CdReadNextIo)
- Header write: exactly 40 bytes at buffer start
- Data copy: limited to `min(total_data, Length - 40)` where Length is read IRP's buffer size
- Total written: `40 + min(data, Length-40) <= Length`
- **Verdict**: Copy is properly bounded. The `Length - 40` subtraction is safe because all queuing paths validate `>= 40`.

**CdCompleteIo** (0x1C0008AA0):
- Input: 40-byte completion structure from user mode
- Validates: `if (a4 != 40) return STATUS_INVALID_BUFFER_SIZE`
- Probes user buffer if PreviousMode == UserMode (alignment + bounds)
- Looks up IO entry in 5-bucket hash table using LUID-based key
- If found and has output data: calls `CdpWriteIoOutput` to write data to output MDLs
- Removes entry from hash table and linked list
- **Verdict**: Properly validated. Hash lookup is under push lock.

**CdReadIoInput wrapper** (0x1C0008E10, IOCTL 0x50000F):
- Input: 24-byte structure `{identifier(16), output_ptr(8), length(8)}`
- Validates: `if (a4 != 24) return error`
- Probes user buffer and output buffer
- Looks up IO entry in hash table, copies data from entry's input MDLs to user buffer
- Copy limited by user-supplied length (low 32 bits)
- **Verdict**: Properly validated. Output buffer is probed.

**CdWriteIoOutput wrapper** (0x1C0008770, IOCTL 0x500013):
- Input: 24-byte structure `{identifier(16), data_ptr(8), data_size(8)}`
- Validates: `if (a4 != 24) return error`
- Probes user buffer and data pointer
- Looks up IO entry in hash table, copies data FROM user buffer TO entry's output MDLs
- Copy limited by user-supplied size (low 32 bits)
- **Verdict**: Properly validated. Data source is probed. MDLs point to original submitter's locked pages.

### 4.3 Potential Weaknesses

#### 4.3.1 Kernel Pointer Leak (IOCTL 0x500023 — CdpConnectionFastIoctl)

```c
// CdpConnectionFastIoctl, IOCTL 0x500023 (5242915)
if (a5 == 8) {
    if (ExGetPreviousMode())
        ProbeForWrite(a4, 8, 4);
    *a4 = *(_QWORD *)(*(_QWORD *)(a1 + 24) + 184LL);
}
```

This reads 8 bytes from `connection->server + offset_184` and returns it to the user. The value at server+184 is set in `CdpSetServerInformation` to `PsGetCurrentProcessId()` — a kernel process ID value. This is an information leak useful for KASLR bypass but **not a write primitive**.

**Impact**: KASLR bypass (kernel pointer leak). Not useful for 8-byte arbitrary write.

#### 4.3.2 Fragile `Length - 40` Subtraction Pattern

In `CdpCompleteReadIo` (0x1C0007A30):
```c
if (v12 >= (unsigned __int64)v14 - 40)
    v16 = v14 - 40;
else
    v16 = v12;
```

If `v14` (read IRP buffer length) were < 40, the subtraction `v14 - 40` would underflow to a huge unsigned value, causing the check to fail and `v16 = v12` (full data size), enabling an oversized copy.

**Current status**: Safe. All paths that queue read IRPs (`CdpServerIoctl`, `CdReadNextIo`) validate `OutputBufferLength >= 0x28 (40)`. `CdpCompleteReadIo` is only called from `CdpCompleteReadIoIrp`, which is only called from those two validated paths.

**Risk**: If a future code change adds a new read IRP queuing path without the >= 40 check, this becomes exploitable as a heap overflow.

#### 4.3.3 IO ID Hash Table Predictability

The IO hash table (`CdpLookupIo` / `CdpAddToIoTable`) uses a 5-bucket hash (LUID_low % 5) with a secondary match on a 32-bit field. IO IDs are allocated via `ZwAllocateLocallyUniqueId`, which generates process-local LUIDs.

If an attacker can predict or brute-force another process's IO ID, they could call `CdCompleteIo`, `CdReadIoInput`, or `CdWriteIoOutput` to manipulate that process's IO entries. However:
- LUIDs are 64-bit kernel-allocated values with unpredictable increments
- The secondary 32-bit match field adds additional entropy
- Operations are bounded by the IO entry's own MDL sizes (locked pages)
- All operations are under push lock protection

**Impact**: Theoretical cross-process IO manipulation. Not practically exploitable for arbitrary write due to LUID unpredictability and MDL-based bounds.

#### 4.3.4 CdpLaunchServerProcess Complexity

`CdpLaunchServerProcess` (0x1C000A750, IOCTL 0x500037) is a complex function that:
1. Captures user process parameters (`PsCaptureUserProcessParameters`)
2. Creates a new process via `CdpCreateProcess` (wraps `ZwCreateUserProcess`)
3. Opens token and process handles
4. Attaches to the new process (`KeStackAttachProcess`)
5. Opens the server file object handle in the new process context
6. Writes command line to the new process's PEB (`ProbeForWrite` + `memmove`)
7. Modifies PEB `ProcessParameters` fields
8. Resumes the process (`PsResumeProcess`)

This function requires `PreviousMode == UserMode` (a2 == 1) and is reachable from user mode via fast IOCTL on a Server handle. The PEB manipulation is complex but targets a newly created process, not arbitrary kernel memory.

**Impact**: Complex attack surface for process creation manipulation. Not directly exploitable for arbitrary kernel write.

#### 4.3.5 Linked List Integrity (Defensive)

All linked list operations use `__fastfail(3u)` (FAST_FAIL_CORRUPT_LIST_HEAD) on corruption detection. This is a defensive measure that causes an immediate BSOD if a linked list is corrupted, preventing exploitation of list-based UAF or double-free bugs.

```c
// Example from CdAddIoToPipe:
if (*(_QWORD **)(*v37 + 8LL) == v37) {  // Check Flink->Blink == self
    // ... safe list removal ...
} else {
    __fastfail(3u);  // Corrupted list → BSOD
}
```

### 4.4 UAF Analysis

**Close/Disconnect paths**:
- `CdpServerClose` → `CdDereferenceServer` (reference-counted)
- `CdpConnectionClose` → queues disconnect IO, then `CdpFreeConnection`
- `CdpClientClose` → queues disconnect IO, then `CdpFreeClient`
- `CdpBrokerCleanup` → `CdDisconnectIoPipe`
- `CdDisconnectIoPipe` → removes all pending IOs under lock, completes them with STATUS_PIPE_DISCONNECTED

All close paths use reference counting and push lock protection. The `CdpPrepareIoCompletion` function removes IO entries from lists and frees MDL chains before completing the IRP. The `__fastfail` guards prevent use of corrupted list entries.

**Verdict**: No UAF found. Reference counting and lock discipline appear correct.

### 4.5 Overflow Analysis

**Integer overflow checks present**:
- `CdpConnectionIoctl`: `count + size` overflow → `(sum < count)` check
- `CdAddIoToPipe`: MDL chain total size overflow → `(total < element_size)` check
- `CdSubmitUserIo`: same MDL chain overflow check
- `CdpCompleteIo`: user buffer bounds → `MmUserProbeAddress` probe

**No overflow found in any reachable path.**

### 4.6 Write-What-Where Analysis

No write-what-where primitive found. All kernel writes go through:
1. MDL-mapped buffers (locked user pages, bounded by MDL byte counts)
2. Linked list operations (under push lock, with `__fastfail` guards)
3. Fixed-offset structure writes (at validated offsets within allocated objects)

No path was found where a user-mode caller can control both the destination address and the value of a kernel write.

---

## 5. LFH Bucket Analysis

### 5.1 Target Buckets

| Bucket | Range (bytes) | NonPagedPoolNx Allocations in condrv.sys |
|--------|--------------|----------------------------------------|
| 640 | 625-640 | **NONE** |
| 704 | 689-704 | **NONE** |
| 1024 | 1009-1024 | **NONE** |

### 5.2 NonPagedPoolNx Allocation Summary

| Allocation | Size | LFH Bucket | User-Reachable |
|-----------|------|------------|----------------|
| CdCo (Connection) | 64 | 64 | Yes (via \Connect) |
| CdCc (Connection IO) | 32 | 32 | Yes (indirect) |
| CdCc (Client) | 24 | 32 | Yes (via \Console etc.) |
| CdCc (Kernel Conn) | 16 | 16 | No (kernel only) |
| CdCc (Kernel Conn IRP) | user-controlled | varies | No (kernel only) |

**Largest user-reachable NonPagedPoolNx allocation: 64 bytes (CdCo tag, bucket 64)**

This is far below the smallest target bucket (640 bytes). The only user-controlled NonPagedPoolNx allocation size is in `CdpAllocateKernelConnectionIrp`, but it requires `RequestorMode == KernelMode` and is not reachable from user mode.

### 5.3 PagedPool Allocation Summary (for reference)

| Allocation | Size | LFH Bucket | User-Reachable |
|-----------|------|------------|----------------|
| CdSe (Server) | 264 | 288 | Yes |
| CdBr (Broker) | 168 | 176 | Yes (SeTcbPrivilege) |
| CdCl (Client) | 40 | 48 | Yes |
| CdRf (Reference) | 16 | 16 | Yes |
| CdDi (Display) | 8 | 16 | Yes (SeTcbPrivilege) |

No PagedPool allocations fall in the target NonPagedPoolNx LFH buckets either.

---

## 6. Conclusion

### 6.1 Summary

condrv.sys is a small (72 KB, 118 functions), well-structured Windows kernel driver that implements console I/O piping between user-mode processes and conhost.exe. The driver uses:

- **Push lock protection** on all shared data structures (pipe queues, hash tables, server/broker lists)
- **MDL-based buffer handling** with `MmProbeAndLockPages` for all user-supplied buffers
- **Integer overflow checks** in buffer size validation
- **Minimum buffer size validation** (>= 40 bytes for read IRPs)
- **`__fastfail(3u)`** on linked list corruption (defensive BSOD)
- **Reference counting** on server and client objects
- **RequestorMode checks** on kernel-only paths
- **`SeTcbPrivilege` checks** on broker and display object creation

### 6.2 Vulnerability Assessment

**No 8-byte arbitrary kernel write primitive found in condrv.sys.**

The driver does not provide:
1. Any NonPagedPoolNx allocations in the target LFH bucket sizes (640, 704, 1024)
2. Any user-controlled NonPagedPoolNx allocation sizes
3. Any write-what-where primitive
4. Any buffer overflow in user-reachable paths
5. Any use-after-free in close/disconnect paths

### 6.3 Notable Findings (Non-Write Primitives)

1. **Kernel pointer leak** via IOCTL 0x500023 (CdpConnectionFastIoctl): Reads `server+184` (process ID) and returns to user. Useful for KASLR bypass only.

2. **Fragile `Length - 40` pattern** in CdpCompleteReadIo: Currently safe due to upstream validation, but a single missing check in a future code path would enable a heap overflow.

3. **IO ID hash table** uses predictable 5-bucket hash with LUID-based keys. Cross-process IO manipulation is theoretical but impractical due to LUID unpredictability.

4. **CdpLaunchServerProcess** is a complex user-reachable function that creates processes and manipulates PEBs. Interesting attack surface but not an arbitrary write.

### 6.4 Recommendation

condrv.sys is **not suitable** as a target for an 8-byte arbitrary kernel write exploit via NonPagedPoolNx LFH bucket corruption at sizes 640, 704, or 1024. The driver's NonPagedPoolNx allocations are too small (max 64 bytes, bucket 64) and there are no user-controlled allocation sizes in NonPagedPoolNx. Consider analyzing other drivers (e.g., afd.sys, npfs.sys, fltMgr.sys) that may have larger NonPagedPoolNx allocations or more complex buffer handling.
