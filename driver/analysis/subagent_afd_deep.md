# AFD.SYS Deep IOCTL Analysis - 8-Byte Arbitrary Kernel Write Hunt

## Binary Info
- **File**: C:\Windows\System32\drivers\afd.sys
- **Base**: 0x1C0000000, Size: 0xA7000
- **MD5**: a3f1cb8de2938baddc2c3e9824948ff2
- **Functions**: 1084 total, 1075 named
- **IDA PID**: 18576

---

## 1. IOCTL Dispatch Table

Dispatch in `AfdDispatchDeviceControl` (0x1C005C390):
- `AfdIoctlTable` at 0x1C00208A0 (DWORD array)
- `AfdIrpCallDispatch` at 0x1C001F6A0 (QWORD function pointer array)
- Index = (IoControlCode >> 2) & 0x3FF, max 0x49 entries

| Index | IOCTL   | Method         | Handler              | Pool Tag |
|-------|---------|----------------|----------------------|----------|
| 1     | 0x12007 | METHOD_NEITHER | AfdConnect           | AfdI/AfdR|
| 9     | 0x12024 | METHOD_BUFFERED| AfdPoll              | AfdP     |
| 46    | 0x120BB | METHOD_NEITHER | AfdConnect (2nd)     | AfdI/AfdR|
| 47    | 0x120BF | METHOD_NEITHER | AfdTliIoControl      | AfdL/Afdi|
| 49    | 0x120C7 | METHOD_NEITHER | AfdSuperConnect      | -        |

AfdPoll dispatches to AfdPoll32 or AfdPoll64 based on IoIs32bitProcess.

---

## 2. AfdConnect Analysis (IOCTL 0x12007)

### Input Buffer (METHOD_NEITHER, user pointer probed)
64-bit: [BYTE flags][pad][QWORD transport_handle][QWORD conn_handle][sockaddr data...]
- v5 = InBufLen - 24 (sockaddr length)
32-bit: [BYTE flags][pad][DWORD transport_handle][DWORD conn_handle][sockaddr...]
- v5 = InBufLen - 12

### Allocation - Non-TL Path (endpoint flag 0x100 NOT set)
```c
buf = ExAllocatePoolWithQuotaTag(0x210, v5 + 96, 'AfdI'); // tag 0x49646641
memset(buf, 0, 0x60);              // zero 96-byte header
memmove(buf + 0x60, Src, v5);      // copy user sockaddr at offset 96
```

Layout: [96-byte zeroed header][user sockaddr data]
- 0x20: DWORD data_length (v5, set by driver)
- 0x28: QWORD self-ref pointer to buf+0x60 (set by driver, NOT user-controlled)
- 0x60: user sockaddr (DWORD must==1, WORD sockaddr_size at +0x64)

### Allocation - TL Path (flag 0x100 set)
```c
buf = ExAllocatePoolWithTagPriority(0x200, v5, 'AfdR'); // tag 0x52646641
memmove(buf, Src, v5);  // raw sockaddr, no header
```

### Size Validation
- v5 checked: (v5 & 0x80000000) == 0 (must be positive)
- Non-TL: v5 >= 8; TL: v5 >= 2
- No integer overflow: v5 < 0x80000000, v5+96 fits in SIZE_T

### Overflow: NONE. memset(96) + memmove(v5 at 96) within v5+96 allocation.

### LFH Buckets (Python-verified)
- 64-bit: AllocSize = InBufLen + 72. LFH 1024 at InBufLen=832 (alloc=904)
- 32-bit: AllocSize = InBufLen + 84. LFH 1024 at InBufLen=816 (alloc=900)

### Pointer Fields: None user-controlled. Offset 0x28 is self-referential.

---

## 3. AfdPoll Analysis (IOCTL 0x12024)

### Input (METHOD_BUFFERED system buffer)
- 0x00: QWORD timeout
- 0x08: DWORD count (poll entries, user-controlled)
- 0x0C: BYTE flags
- 0x10: entries (16 bytes each for 64-bit, 12 for 32-bit)

### Allocation
```c
if (count > 0x6666661) return error;
size = (int)(40 * count + 184);  // assembly: lea eax,[count+count*4]; lea eax,ds:0B8h[eax*8]; movsxd rcx,eax
poll_info = ExAllocatePoolWithQuotaTag(0x210, size, 'AfdP'); // tag 0x50646641
if (!poll_info) return error;  // NULL check present
```

### Integer Overflow Analysis (Python-verified)
- 40 * count overflows signed 32-bit at count >= 0x3333334 (53687092)
- movsxd sign-extends to 64-bit -> huge SIZE_T -> alloc fails -> NULL caught
- Safe range: count <= 33554429 (0x1FFFFFD) for valid allocation
- **CVE-2014-1767 pattern is PATCHED**: movsxd prevents small alloc + overflow

### Poll Info Layout (184-byte header + 40-byte entries)
- 0x00: DWORD refcount (atomic)
- 0x08: QWORD thread (KeGetCurrentThread)
- 0x10: QWORD IRP (atomic exchange for cancel safety)
- 0x18: DWORD entry_count
- 0xB0: BYTE timer_flag, 0xB1: san_flag, 0xB2: defer_flag
- 0xB8: entries (40 bytes each): back-ptr(0x00), next(0x08), fileobj(0x10), events(0x18), handle(0x1C)

### Pointer Fields: All kernel-set (thread, IRP, file_object from ObReferenceObjectByHandle). No user-controlled pointers.

### LFH Buckets: count=20 -> 984 (bucket 1024), count=21 -> 1024 (bucket 1024)

### UAF: Poll info has refcount at 0x00, freed via AfdFreePollInfo when refcount hits 0. Cancel uses atomic exchange on IRP pointer at 0x10 to prevent double-completion.

---

## 4. AfdTliIoControl Analysis (IOCTL 0x120BF)

### Input (METHOD_NEITHER)
32-bit (min 0x18): [DWORD req_type][DWORD sub_type][DWORD option][BYTE flags][QWORD data_ptr][QWORD data_len]
64-bit (min 0x20): same layout but with proper alignment

### Three Allocations
1. Context (fixed): `ExAllocatePoolWithQuotaTag(0x210, 0x58, 'AfdL')` - 88 bytes
2. InputData (user size): `ExAllocatePoolWithQuotaTag(0x210, user_size, 'Afdi')` + memmove
3. QoS (conditional): `ExAllocatePoolWithQuotaTag(0x210, 16*count+8, 'Afd ')` where count <= 0xFFFF

### Context Layout (0x58 = 88 bytes)
- 0x00-0x0C: request fields from user (type, subtype, option, flags)
- 0x10: QWORD input_data_ptr (user, probed)
- 0x18: QWORD input_data_len (user)
- 0x20: QWORD endpoint (kernel-set)
- 0x28: QWORD IRP (kernel-set)
- 0x38: QWORD input_buffer (kernel-set, points to 'Afdi' alloc)
- 0x40: QWORD output_mdl (kernel-set)
- 0x48: QWORD output_mapped (kernel-set)
- 0x50: QWORD qos_ptr (kernel-set, points to 'Afd ' alloc)

### Overflow: NONE. All sizes correctly bounded. QoS loop writes within allocation.

### Pointer Fields: All in context are kernel-set. No user-controlled pointers.

---

## 5. Connection Object Analysis

### AfdAllocateConnection (0x1C00588FC)
- From PplConnectionPool lookaside or AfdReuseConnection
- memset 0x100 (256 bytes), refcount=1 at offset 0x30, type=0xB018 at offset 0x00

### AfdCreateConnection (0x1C00587B0)
- PsChargeProcessPoolQuota(Process, NON_PAGED, 0x100)
- Sets FileObject(0x10), DeviceObject(0x18), Process(0x20)
- Initializes LIST_ENTRYs at offsets 0x38, 0x48, 0x68 (self-referential, empty)

### Connection Object Layout (256 bytes)

| Offset | Field          | Type           | Source             | Dereferenced? |
|--------|----------------|----------------|---------------------|---------------|
| 0x00   | Type/Flags     | DWORD+DWORD    | Driver             | Flags only    |
| 0x10   | FileObject     | PFILE_OBJECT   | AfdCreateConnection| **YES** - AfdTliIoControl, AfdFreeConnectionResources |
| 0x18   | DeviceObject   | PDEVICE_OBJECT | AfdCreateConnection| **YES** - AfdTliIoControl, AfdFreeConnectionResources |
| 0x20   | Process        | PEPROCESS      | AfdCreateConnection| **YES** - ObfDereferenceObject |
| 0x30   | Refcount       | volatile LONG  | Driver             | Atomic inc/dec |
| 0x38   | LIST_ENTRY A   | Flink+Blink    | Self-referential   | List ops      |
| 0x48   | LIST_ENTRY B   | Flink+Blink    | Self-referential   | List ops      |
| 0x50   | (B.Blink)      | QWORD          | Self->0x48         | **WRITE target in list insert** |
| 0x68   | LIST_ENTRY C   | Flink+Blink    | Self-referential   | List ops      |
| 0x90   | RecvWindowSize | DWORD          | Driver             | No            |
| 0x94   | SendWindowSize | DWORD          | Driver             | No            |
| 0xA8   | Handle         | HANDLE         | IoCreateFile       | ZwClose       |

### OFFSET 0x50 WRITE-WHAT-WHERE PRIMITIVE

Offset 0x50 is the Blink of LIST_ENTRY B at offset 0x48.

If corrupted via UAF to arbitrary address X:

**InsertHeadList(&list_B, new_entry):**
- new_entry->Blink = andlist_B (kernel addr)
- **X->Blink = new_entry** -> writes 8 bytes to X+8
- list_B.Flink = new_entry

**InsertTailList(&list_B, new_entry):**
- new_entry->Blink = X (reads from X)
- **X->Flink = new_entry** -> writes 8 bytes to X+0
- list_B.Blink = new_entry

This gives an 8-byte arbitrary kernel write of a kernel address (the new list entry) to attacker-controlled address X or X+8.

---

## 6. UAF and Race Condition Analysis

### Connection Refcounting
- AfdCheckAndReferenceConnection: atomic increment at +0x30, returns false if <= 0
- AfdGetConnectionReferenceFromEndpoint: spinlock on endpoint+0x30, reads conn ptr at endpoint+0xB0, increments conn refcount
- Dereference: _InterlockedExchangeAdd(conn+0x30, -1), if 1 -> AfdCloseConnection

### AfdCloseConnection (0x1C0056D6C)
- If TL (flag 0x20000): close handle via transport, AfdFreeConnectionEx
- If non-TL: increment AfdConnectionsFreeing, queue AfdFreeConnection work item
- AfdFreeConnection -> AfdFreeConnectionEx -> AfdFreeConnectionResources -> return to lookaside or free pool

### AfdCloseCore (0x1C0037350)
- Gets connection at endpoint+0xB0, nullifies it
- Decrements connection refcount
- Sets endpoint type to 6 (closed)
- AfdDereferenceEndpointInline -> decrements endpoint refcount

### AfdCleanupCore (0x1C00536EC)
- Takes endpoint spinlock
- AfdIndicatePollEvent(endpoint, 0x20) -> cancels pending polls
- Gets connection at endpoint+0xB0, increments refcount
- Cancels IRPs, disconnects, etc.
- Decrements connection refcount -> may free
- Completes queued IRPs from LIST_ENTRYs
- Dereferences endpoint

### Race Condition: Close Socket While Connect Pending

1. Thread A: AfdConnect creates connection, increments endpoint refcount, calls IofCallDriver
2. Thread B: Close socket -> AfdCleanupCore runs
   - Increments connection refcount (safety)
   - Cancels IRPs, disconnects
   - Decrements connection refcount (may not reach 0 due to Thread A's reference)
3. Transport driver completes connect IRP
4. AfdRestartConnect runs:
   - Accesses endpoint via IRP+184
   - Accesses connection via IRP stack context
   - Decrements connection refcount
   - Decrements endpoint refcount
   - Calls AfdFinishConnect or AfdCloseConnection

**The refcounting prevents UAF in normal flow.** Both connection and endpoint have their refcounts incremented before the IRP is passed to the transport driver.

### UAF Exploitation Strategy (Theoretical)

1. **Exhaust connection lookaside** (PplConnectionPool):
   - Create many sockets and connect them
   - This drains the lookaside list
   - New connections come from NonPagedPoolNx general pool

2. **Get a connection from general pool**:
   - Create one more socket+connect
   - This connection is from the general pool, not lookaside

3. **Obtain stale reference**:
   - Need a race window or a pending operation holding a reference
   - AfdTliIoControl gets connection ref under spinlock -> uses -> decrements
   - If we can close the socket between the get and use, and the connection gets freed...
   - But refcount prevents this

4. **Free the connection to general pool**:
   - Close all sockets
   - If lookaside is full, connection goes to general pool

5. **Spray same LFH bucket** (256 bytes):
   - AfdTliIoControl InputData with size=256 (tag 'Afdi')
   - Or another 256-byte allocation
   - Fill with controlled data including fake LIST_ENTRY at offset 0x48/0x50

6. **Trigger list operation on stale connection**:
   - The stale reference's LIST_ENTRY at 0x48/0x50 is now controlled
   - When a list insert/remove occurs, it writes to the corrupted address

### Key Challenge
The refcounting is correct in all examined paths. The UAF would require:
- A race window in the refcount check (very tight)
- OR a logic bug where a reference is not properly held
- OR a double-decrement causing premature free

No such bug was found in the examined code paths. The connection refcount is always incremented before use and decremented after, with atomic operations.

---

## 7. Write-What-Where Summary

### No direct write-what-where found in current code

All three IOCTL handlers (AfdConnect, AfdPoll, AfdTliIoControl) have:
- Correct allocation size calculations (no integer overflow)
- Correct bounds checking on user input
- No user-controlled pointer fields in allocations
- Proper NULL checks on allocation returns

### Most promising attack vector: Connection object UAF

If a UAF can be achieved on the connection object (256 bytes):
1. Corrupt LIST_ENTRY at offset 0x48/0x50 via reallocation
2. Trigger list insertion -> 8-byte write of kernel address to arbitrary location
3. Written value is a kernel address (list entry), not fully controlled
4. Target: function pointer in EPROCESS, token privileges, or similar

### Pool Tags for Cross-Tag LFH Spray

All use NonPagedPoolNx with quota (0x210):
- 'AfdI' (0x49646641) - AfdConnect non-TL: InBufLen+72 bytes
- 'AfdP' (0x50646641) - AfdPoll: 40*count+184 bytes
- 'Afdi' (0x69646641) - AfdTliIoControl input: user-controlled
- 'AfdL' (0x4C646641) - AfdTliIoControl context: 88 bytes fixed
- 'AfdR' (0x52646641) - AfdConnect TL address: InBufLen-24 bytes
- 'Afd ' (0x20646641) - AfdTliIoControl QoS: 16*count+8 bytes

Connection object: 256 bytes from lookaside (PplConnectionPool)
- When lookaside exhausted, comes from general pool
- No tag (lookaside-managed), but underlying alloc has a tag from the lookaside callback

### LFH 1024 Cross-Tag Adjacency
- AfdConnect: InBufLen=832 -> 904 bytes (bucket 1024)
- AfdPoll: count=20 -> 984 bytes (bucket 1024)
- AfdTliIoControl: InputData=952 -> 952 bytes (bucket 1024)
- All in NonPagedPoolNx quota, enabling cross-tag LFH adjacency

### LFH 256 for Connection Object Spray
- AfdTliIoControl InputData with size=256 (tag 'Afdi')
- AfdConnect with InBufLen=184 (64-bit) -> 256 bytes (tag 'AfdI')
- Connection object: 256 bytes from lookaside (same bucket when in general pool)

---

## 8. Exploit Chain (Theoretical)

```
1. Create ~2000 sockets to exhaust PplConnectionPool lookaside
2. Create target socket + connect -> connection from general pool (256 bytes, LFH 256)
3. Get stale connection reference (requires race or logic bug - NOT YET FOUND)
4. Close target socket -> connection refcount decrements
   - If lookaside full, connection freed to general pool LFH 256
5. Spray LFH 256 with AfdTliIoControl InputData (tag 'Afdi', 256 bytes):
   - Controlled data at offset 0x48: fake Flink = target_addr - 8
   - Controlled data at offset 0x50: fake Blink = target_addr
6. Trigger list operation on stale connection reference:
   - InsertHeadList -> writes kernel_addr to (target_addr - 8) + 8 = target_addr
   - This overwrites target with a kernel address
7. Use the corrupted target for privilege escalation
```

### Missing Piece
The critical missing piece is step 3: obtaining a stale (dangling) reference to the connection object after it has been freed. The refcounting in all examined paths (AfdTliIoControl, AfdCleanupCore, AfdRestartConnect, AfdCloseCore) appears correct. Further analysis needed on:
- AfdSuperConnect (0x120C7) path
- AfdSuperAccept (0x12083) path
- WSK dispatch paths
- SAN (Switched Access Network) paths
- Timer-based completion paths (AfdTimeoutPoll, AfdTimerWheelHandler)
- APC rundown paths (AfdConnectApcRundownRoutine, AfdSanPollApcRundownRoutine)

---

## 9. Functions Analyzed

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| AfdDispatchDeviceControl | 0x1C005C390 | 0x8E | IOCTL dispatch |
| AfdConnect | 0x1C004D690 | 0x1001 | Connect handler |
| AfdPoll | 0x1C005C950 | 0x3E | Poll dispatcher |
| AfdPoll64 | 0x1C005C994 | 0x769 | 64-bit poll |
| AfdPoll32 | 0x1C0072B5C | 0x961 | 32-bit poll |
| AfdPollGetInfo | 0x1C005D2B0 | 0x46 | Poll alloc |
| AfdCompletePollIrp | 0x1C005D2FC | 0xAE | Poll completion |
| AfdDerefPollInfoFileObjects | 0x1C005D3B0 | 0x68 | Poll file obj deref |
| AfdFreePollInfo | 0x1C005D420 | 0x4E | Poll free |
| AfdUpdatePollInfo | 0x1C005E0E0 | 0x84 | Poll update |
| AfdCheckPollEvents | 0x1C005D104 | 0x1A6 | Poll event check |
| AfdCancelPoll | 0x1C0072AC0 | 0x94 | Poll cancel |
| AfdIndicatePollEvent | 0x1C0052340 | 0x1CB | Poll event indicate |
| AfdTliIoControl | 0x1C0053FA0 | 0xBFB | TLI IO control |
| AfdAllocateConnection | 0x1C00588FC | 0xE9 | Connection alloc |
| AfdCreateConnection | 0x1C00587B0 | 0x146 | Connection create |
| AfdCloseConnection | 0x1C0056D6C | 0xB7 | Connection close |
| AfdFreeConnectionResources | 0x1C0056C3C | 0xAB | Connection free |
| AfdFreeConnection | 0x1C00406E0 | 0x1D | Connection free worker |
| AfdCloseCore | 0x1C0037350 | 0xB1 | Endpoint close |
| AfdCleanupCore | 0x1C00536EC | 0x6A7 | Endpoint cleanup |
| AfdDereferenceEndpointInline | 0x1C0003454 | 0x100 | Endpoint deref |
| AfdCheckAndRefConnection | 0x1C0002744 | 0x34 | Connection ref |
| AfdGetConnRefFromEndpoint | 0x1C0058E40 | 0x6C | Get conn from endpoint |
| AfdRestartConnect | 0x1C006CD10 | 0x2C9 | Connect completion |
| AfdReturnBuffer | 0x1C00520C0 | 0x272 | Buffer return |

---

## 10. Conclusion

The current afd.sys (Windows 11 x64, build matching SHA256 441d4a...) has hardened all three previously-vulnerable IOCTL paths:

1. **AfdConnect**: No integer overflow, proper bounds, self-referential pointers only
2. **AfdPoll**: movsxd sign-extension prevents CVE-2014-1767-style integer overflow, NULL check on alloc
3. **AfdTliIoControl**: Fixed context size, user-sized data correctly bounded, QoS loop bounded

The most promising remaining attack surface is the **connection object UAF via LIST_ENTRY corruption at offset 0x48/0x50**, which would give an 8-byte arbitrary kernel write. However, the refcounting on the connection object appears correct in all examined code paths. The exploit chain requires finding a race condition or logic bug that produces a dangling connection reference - this was not found in the analyzed paths but may exist in unexamined paths (SuperConnect, SuperAccept, SAN, timer/APC rundown).
