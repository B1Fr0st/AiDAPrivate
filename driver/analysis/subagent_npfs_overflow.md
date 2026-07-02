# npfs.sys Pool Overflow and Write-What-Where Analysis

## 1. Binary Survey

| Field | Value |
|-------|-------|
| Path | C:\Windows\System32\drivers\npfs.sys |
| Module | npfs.sys (Named Pipe File System) |
| Architecture | x64 |
| Base Address | 0x1C0000000 |
| Image Size | 0x1C000 (114688 bytes) |
| MD5 | e2093593f86b7c1ec93fcb9b1ea94c20 |
| Total Functions | 135 (132 named) |
| Total Strings | 160 |

### Key Imports

| Import | Address | Module |
|--------|---------|--------|
| ExAllocatePoolWithTag | 0x1C0007050 | ntoskrnl |
| ExAllocatePoolWithQuotaTag | 0x1C00070A8 | ntoskrnl |
| ExFreePoolWithTag | 0x1C0007058 | ntoskrnl |
| ExAcquirePushLockExclusiveEx | 0x1C0007078 | ntoskrnl |
| KeBugCheckEx | 0x1C00071B8 | ntoskrnl |
| IofCompleteRequest | 0x1C0007088 | ntoskrnl |
| IoAllocateIrp | 0x1C0007220 | ntoskrnl |
| SeCreateClientSecurity | 0x1C0007288 | ntoskrnl |

---

## 2. All Pool Allocations

### Pool Tag Summary

| Tag | Value | Used For | Pool Types |
|-----|-------|----------|------------|
| NpFc | 0x6346704E | CCB (Client Control Block) | PagedPoolSessionQuota (0x109) |
| NpFf | 0x4666704E | FCB + Event | PagedPoolQuota (0x9), NonPagedPoolNxQuota (0x208) |
| NpFn | 0x6E46704E | Pipe name buffer | NonPagedPoolNxQuota (0x208), PagedPoolQuota (0x9) |
| NpFr | 0x7246704E | Data Queue Entry | NonPagedPoolSessionNxQuota (0x308) |
| NpFs | 0x7346704E | Security Client Context | PagedPoolQuota (0x9) |
| NpFR | 0x5246704E | Write Data Buffer | NonPagedPoolNx (0x200) |
| NpAt | 0x7441704E | Attribute / Process Info | PagedPool (0x1) |
| NpFw | 0x7746704E | Waiter / Transceive | NonPagedPoolNxQuota (0x208), PagedPoolQuota (0x9) |
| NpFq | 0x7146704E | Query Directory name | PagedPoolQuota (0x9) |

### All Allocation Call Sites

| Function | Pool Type | Size | Tag | Notes |
|----------|-----------|------|-----|-------|
| NpCreateCcb | 0x109 PagedPoolSessionQuota | 0x1D0 (464) | NpFc | CCB with 2 embedded data queues |
| NpCreateNewNamedPipe | 0x9 PagedPoolQuota | 0x188 (392) | NpFf | FCB |
| NpCreateNewNamedPipe | 0x208 NonPagedPoolNxQuota | 0x38 (56) | NpFf | FCB Event |
| NpCreateNewNamedPipe | 0x208 NonPagedPoolNxQuota | pipe_name_len | NpFn | FCB Name |
| NpCreateNewNamedPipe | 0x109 PagedPoolSessionQuota | 0x1D0 (464) | NpFc | Server CCB |
| NpCreateNewNamedPipe | PagedPool | 0x28 (40) | NpAt | Process info |
| NpAddDataQueueEntry | 0x308 NPP-Session-Nx-Quota | write_size+48 | NpFr | Data Queue Entry WITH data |
| NpAddDataQueueEntry | 0x308 NPP-Session-Nx-Quota | 0x30 (48) | NpFr | Data Queue Entry NO data |
| NpAddDataQueueEntry | 0x9 PagedPoolQuota | 0x48 (72) | NpFs | Security Client Context |
| NpWriteDataQueue | 0x200 NonPagedPoolNx | write_data_size | NpFR | Write buffer (system pool!) |
| NpWriteDataQueue | 0x9 PagedPoolQuota | 0x48 (72) | NpFs | Security Client Context |
| NpAddWaiter | 0x208 NonPagedPoolNxQuota | name_len+176 | NpFw | Wait queue entry |
| NpTransceive | 0x9 PagedPoolQuota | transceive_size | NpFw | Transceive buffer |
| NpInternalTransceive | 0x9 PagedPoolQuota | transceive_size | NpFw | Internal transceive buffer |
| NpSetAttributeInList | PagedPool | 40+name+value | NpAt | Attribute list entry |
| NpQueryDirectory | 0x9 PagedPoolQuota | name_len+16 | NpFq | Directory search pattern |
| NpCreateClientEnd | PagedPool | 0x28 (40) | NpAt | Client process info |
| NpCreateClientEnd | 0x9 PagedPoolQuota | 0x48 (72) | NpFs | Security Client Context |

---

## 3. Data Queue Entry Structure

`
Offset 0:  LIST_ENTRY Flink (8 bytes)  - linked list forward pointer
Offset 8:  LIST_ENTRY Blink (8 bytes)  - linked list backward pointer
Offset 16: PIRP Irp (8 bytes)          - associated IRP pointer
Offset 24: PVOID SecurityContext (8)   - SECURITY_CLIENT_CONTEXT pointer
Offset 32: ULONG State/Type (4 bytes)  - entry state (0=data, 1=buffered, 2+=special)
Offset 36: ULONG DataLen (4 bytes)     - valid/consumed data length
Offset 40: ULONG TotalSize (4 bytes)   - total data size in entry
Offset 44: ULONG UNINITIALIZED (4)     - NEVER written, NEVER read by any code path
Offset 48: UCHAR Data[] (variable)     - inline data payload
`

### Allocation Details
- Pool Type: NonPagedPoolSessionNx | Quota (0x308 = 776)
- Tag: NpFr (0x7246704E)
- Size with data: user_write_size + 48
- Size without data: 48 bytes (0x30)
- Pool arena: SESSION NonPagedPoolNx - SEPARATE from system NonPagedPoolNx

### NpAddDataQueueEntry Decompilation (0x1C000D6C0)

`c
__int64 NpAddDataQueueEntry(
    int a1,           // security context flag
    __int64 a2,       // CCB pointer
    __int64 a3,       // Data Queue pointer (CCB+72 or CCB+168)
    int a4,           // has_data flag (1=has inline data)
    int a5,           // entry type (0=normal, 1=buffered, 2=special)
    size_t Size,      // data size
    __int64 a7,       // IRP pointer
    const void *a8,   // source data buffer
    int a9)           // offset (bytes already consumed)
{
    // Security context: ExAllocatePoolWithQuotaTag(9, 0x48, 'NpFs') = 72 bytes PagedPool

    if (!a5) {
        v14 = 48;
        if (a4) {
            v14 = Size + 48;
            if ((int)Size + 48 < (unsigned int)Size)  // integer overflow check (32-bit)
                return STATUS_INVALID_PARAMETER;
        }

        // Cache reuse: only for 48-byte no-data entries
        if (v14 == 48 && _interlockedbittestandreset(a3 + 40, 0))
            v16 = *(_DWORD **)(a3 + 40);  // reuse cached entry
        else
            v16 = nullptr;

        if (!v16)
            v16 = ExAllocatePoolWithQuotaTag(0x308, v14, 'NpFr');

        // Write fields
        v16[9] = v15;                    // offset 36: data length (clamped to queue space)
        *(QWORD*)(v16 + 16) = v13;       // offset 16: IRP pointer
        v16[8] = 0;                      // offset 32: state = 0
        *(QWORD*)(v16 + 24) = v12;       // offset 24: security context
        v16[10] = Size;                  // offset 40: total size
        // NOTE: offset 44 (v16[11]) is NEVER SET - uninitialized!

        if (a4) {
            memmove(v16 + 12, v23, (unsigned int)Size);  // copy at offset 48
        }

        // Link into queue
        *(QWORD*)v16 = a3;               // Flink = queue head
        *(QWORD*)(v16 + 8) = v18;        // Blink = prev tail
        *v18 = v16;
        *(QWORD*)(a3 + 8) = v16;         // queue tail = new entry

        // Update metadata
        *(DWORD*)(a3 + 32) += v15;       // BytesUsed
        *(DWORD*)(a3 + 16) = a4;         // State
        *(DWORD*)(a3 + 20) += Size;      // TotalBytes
        ++*(DWORD*)(a3 + 24);            // EntryCount
    }
}
`

### NpRemoveDataQueueEntry Decompilation (0x1C001308)

`c
__int64 NpRemoveDataQueueEntry(__int64 **a1, char a2, __int64 a3)
{
    if (*((_DWORD *)a1 + 4) == 2) return 0;  // queue empty

    v7 = *a1;  // first entry

    // SAFE UNLINK - __fastfail(3) = BSOD if check fails
    if ((*a1)[1] != a1 || (v8 = *v7, *(QWORD*)(v7 + 8) != v7))
        __fastfail(3);

    *a1 = v8;           // queue->Flink = next
    v8[1] = (QWORD)a1;  // next->Blink = queue

    // Update metadata
    *(DWORD*)(a1 + 5) -= *(DWORD*)(v7 + 10);  // TotalBytes -= entry size
    --*(DWORD*)(a1 + 6);                       // EntryCount--

    // CRITICAL: IRP pointer dereferenced
    v6 = v7[2];  // entry->Irp (offset 16)
    if (v6 && !_InterlockedExchange64((volatile __int64*)(v6 + 104), 0))
    {
        *(QWORD*)(v6 + 144) = 0;  // writes 0 to Irp+144
        v6 = 0;
    }

    // CRITICAL: SecurityContext freed
    NpFreeClientSecurityContext((PVOID)v7[3]);  // entry->SecurityContext (offset 24)

    // Cache or free
    if (a1[5] == v7)
        _interlockedbittestandset((volatile signed __int32 *)a1 + 10, 0);
    else
        ExFreePoolWithTag(v7, 0);
}
`

---

## 4. CCB Structure (464 bytes, PagedPoolSessionQuota, NpFc)

`
Offset   Size  Field
0        2     Type (0x0204)
4        4     State (1)
8        1     PipeMode
9        1     ServerEnd flag
40       8     FCB pointer
56       8     FileObject pointer
72-167   96    Data Queue 1 (Inbound):
  72     8     LIST_ENTRY Flink
  80     8     LIST_ENTRY Blink
  88     4     State (2=empty)
  92     4     TotalBytes
  96     4     EntryCount
  100    4     MaxQuota (from create params)
  104    4     BytesUsed
  108    4     PartialReadOffset
  112    8     Cache (pointer | flag bit 0)
  120    48    INLINE ENTRY (first cached no-data entry)
168-263  96    Data Queue 2 (Outbound):
  168    8     LIST_ENTRY Flink
  176    8     LIST_ENTRY Blink
  184    4     State (2=empty)
  188    4     TotalBytes
  192    4     EntryCount
  196    4     MaxQuota
  200    4     BytesUsed
  204    4     PartialReadOffset
  208    8     Cache (pointer | flag bit 0)
  216    48    INLINE ENTRY (first cached no-data entry)
264      8     SecurityClientContext (-1 = none)
272      16    LIST_ENTRY for CCB chain
432      8     Event pointer 1
440      8     Event pointer 2
448      8     ClientComputerName timestamp
456      4     CCB index
`

---

## 5. LFH Bucket Analysis

### Fixed-Size Allocations

| Allocation | Size | Bucket | Pool |
|------------|------|--------|------|
| CCB | 464 (0x1D0) | 512 | PagedPoolSessionQuota |
| FCB | 392 (0x188) | 416 | PagedPoolQuota |
| FCB Event | 56 (0x38) | 64 | NonPagedPoolNxQuota |
| DQE no-data | 48 (0x30) | 48 | NonPagedPoolSessionNxQuota |
| SecContext | 72 (0x48) | 80 | PagedPoolQuota |
| ProcessInfo | 40 (0x28) | 48 | PagedPool |
| Waiter (no name) | 176 (0xB0) | 192 | NonPagedPoolNxQuota |

### Variable-Size: Data Queue Entry (NpFr, Session NonPagedPoolNx)

Alloc = WriteFile(buffer_size) + 48

| Target Bucket | Write Size | Alloc Size |
|---------------|-----------|-----------|
| 512 | 464 (0x1D0) | 512 |
| 640 | 592 (0x250) | 640 |
| 768 | 720 (0x2D0) | 768 |
| 1024 | 976 (0x3D0) | 1024 |

WARNING: NonPagedPoolSessionNx (0x308) is SESSION pool.
KTM and ColorSpace are in SYSTEM NonPagedPoolNx (0x200).
Data Queue Entries CANNOT be adjacent to KTM/ColorSpace.

### Variable-Size: Write Data Buffer (NpFR, System NonPagedPoolNx)

Alloc = min(remaining_write, entry_data_size)

| Target Bucket | Write Size |
|---------------|-----------|
| 512 | 512 |
| 640 | 640 |
| 1024 | 1024 |

Write Data Buffer IS in system NonPagedPoolNx - CAN be adjacent to KTM/ColorSpace.
But it is a raw data buffer with no pointer fields.

### Variable-Size: FCB Name (NpFn, System NonPagedPoolNx)

Alloc = pipe_name_length (controlled via CreateNamedPipe)

| Target Bucket | Name Length (bytes) |
|---------------|--------------------|
| 640 | 640 (320 WCHARs) |
| 1024 | 1024 (512 WCHARs) |

### Variable-Size: Waiter (NpFw, System NonPagedPoolNx)

Alloc = 176 + pipe_name_length

| Target Bucket | Name Length | Total |
|---------------|------------|-------|
| 640 | 464 | 640 |
| 1024 | 848 | 1024 |

---

## 6. Overflow and OOB Write Path Analysis

### 6.1 NpAddDataQueueEntry - No Overflow

Allocation: ExAllocatePoolWithQuotaTag(0x308, Size + 48, 'NpFr')
Copy: memmove(entry + 48, source, Size)
Verdict: Allocation EXACTLY matches copy. No overflow.

Integer overflow check: (int)Size + 48 < (unsigned int)Size
- 32-bit arithmetic. Gap: 0x80000000-0xFFFFFFD0 not caught.
- But resulting alloc ~2GB fails due to quota. Not exploitable.

### 6.2 NpWriteDataQueue - No Overflow

Allocation: ExAllocatePoolWithTag(0x200, min(remaining, entry_size), 'NpFR')
Copy: memmove(buffer, user_data + offset, min(remaining, entry_size))
Verdict: Allocation EXACTLY matches copy. No overflow.

### 6.3 NpSetAttributeInList - No Overflow

Allocation: ExAllocatePoolWithTag(PagedPool, 40 + name_len + value_size, 'NpAt')
Overflow checks present: name overflow + total size overflow.
Verdict: No exploitable overflow.

### 6.4 NpTransceive - No Overflow

Allocation: ExAllocatePoolWithQuotaTag(0x9, NumberOfBytes, 'NpFw')
Copy: memmove(buffer, input + offset, NumberOfBytes)
Verdict: Allocation matches copy. No overflow.

### 6.5 NpReadDataQueue - No Overflow

No kernel pool allocation. Reads bounded by entry TotalSize.
Verdict: No overflow.

### 6.6 NpQueryDirectory - No Overflow

Output buffer writes bounded by remaining buffer size.
Verdict: Proper bounds checking. No overflow.

### 6.7 NpAddWaiter - No Overflow

Allocation: ExAllocatePoolWithQuotaTag(0x208, name_len + 176, 'NpFw')
Copy: memmove(buf + 176, name, name_len) - matches allocation.
Verdict: No overflow.

### Summary: No Direct Buffer Overflow Found

All pool allocation sizes match their copy sizes exactly. No path found where user data overflows a pool buffer within npfs.sys.

---

## 7. Uninitialized Memory

### 7.1 Data Queue Entry Offset 44

- Offset 44 (4 bytes) is NEVER written in NpAddDataQueueEntry
- ExAllocatePoolWithQuotaTag does NOT zero memory
- May contain stale pool metadata or kernel pointers
- Impact: Potential 4-byte info leak. Not a write primitive (never read).

### 7.2 CCB Inline Entry

CCB is zeroed with memset(0, 0x1D0). Inline entries start zeroed. Not an issue.

---

## 8. Write-What-Where Primitive Paths (via Corruption)

### 8.1 LIST_ENTRY Corruption - Safe Unlink

NpRemoveDataQueueEntry has safe unlink checks:
- Check 1: entry->Blink == queue_head
- Check 2: entry->Flink->Blink == entry
- Failure: __fastfail(3) -> KeBugCheckEx (BSOD)

If entry->Flink corrupted to target-8:
- Check 2 requires *(target) == entry_address (need info leak)
- If passes: *(target) = queue_head (not controlled value)
- BSOD if checks fail

### 8.2 IRP Pointer Corruption - Write-Zero Primitive

If entry->Irp (offset 16) corrupted to target-104:
- InterlockedExchange64(target, 0) writes 0 to target
- If *target was 0: also writes 0 to target+40
- Write-zero primitive. Can disable security fields.

### 8.3 SecurityContext Corruption - Free-Anywhere

If entry->SecurityContext (offset 24) corrupted to target:
- NpFreeClientSecurityContext -> ExFreePoolWithTag(target, 0)
- Requirements: target != 0, target != -1, target+16 must be valid
- Free-anywhere -> realloc with controlled data -> write-what-where

### 8.4 NpCancelDataQueueIrp - Cancel Path

Same safe unlink pattern. Cancel routine acquires push lock.
IRP pointer and SecurityContext dereferenced/freed same as above.

---

## 9. Complete Call Chains (User Mode to Kernel)

### WriteFile to Named Pipe

`
User mode: WriteFile(hPipe, buf, len)
  -> NpFsdWrite (0x1C000DB10) or NpFastWrite (0x1C000DA30)
    -> NpCommonWrite (0x1C000DC00)
      -> ExAcquirePushLockExclusiveEx(CCB+64)
      -> NpWriteDataQueue (0x1C000DEB0)
        -> ExAllocatePoolWithTag(0x200, size, 'NpFR') [if new buffer needed]
        -> memmove(buffer, user_data, size)
        -> ExAllocatePoolWithQuotaTag(0x9, 0x48, 'NpFs') [security context]
      -> NpAddDataQueueEntry (0x1C000D6C0) [if write pending]
        -> ExAllocatePoolWithQuotaTag(0x308, write_size+48, 'NpFr')
        -> memmove(entry+48, user_data, write_size)
      -> ExReleasePushLockExclusiveEx(CCB+64)
`

### ReadFile from Named Pipe

`
User mode: ReadFile(hPipe, buf, len)
  -> NpFsdRead (0x1C000D410) or NpFastRead (0x1C000A8C0)
    -> NpReadDataQueue (0x1C000E400)
      -> memmove(user_buffer, entry_data, bytes_to_read)
      -> NpRemoveDataQueueEntry (0x1C001308) [if entry fully consumed]
        -> Safe unlink from LIST_ENTRY
        -> Deref IRP pointer (offset 16)
        -> Free SecurityContext (offset 24)
        -> ExFreePoolWithTag or cache entry
`

### Transceive (FSCTL_PIPE_TRANSCEIVE)

`
User mode: DeviceIoControl(hPipe, FSCTL_PIPE_TRANSCEIVE, in, in_len, out, out_len)
  -> NpFsdFileSystemControl (0x1C000CB90)
    -> NpCommonFileSystemControl (0x1C000CC00)
      -> NpTransceive (0x1C000D0C0)
        -> NpWriteDataQueue (write input to other end)
        -> ExAllocatePoolWithQuotaTag(0x9, size, 'NpFw') [transceive buffer]
        -> NpAddDataQueueEntry (queue read request)
`

### Internal Transceive (FSCTL_PIPE_INTERNAL_TRANSCEIVE)

`
User mode: DeviceIoControl(hPipe, 0x11DFFF, ...)
  -> NpFsdFileSystemControl -> NpCommonFileSystemControl
    -> NpInternalTransceive (0x1C0014A00)
      -> NpWriteDataQueue
      -> IoAllocateIrp
      -> ExAllocatePoolWithQuotaTag(0x9, size, 'NpFw')
      -> NpAddDataQueueEntry (with data, type=1)
`

### CreateNamedPipe

`
User mode: CreateNamedPipeW(name, ...)
  -> NpFsdCreateNamedPipe (0x1C000B420)
    -> NpCreateNamedPipePrefix (0x1C000AF30)
      -> ExAllocatePoolWithQuotaTag(0x9, ..., 'NpFw') [prefix database]
      -> ExAllocatePoolWithQuotaTag(0x9, ..., 'NpFn') [prefix name]
    -> NpCreateNewNamedPipe (0x1C000C3A0)
      -> ExAllocatePoolWithQuotaTag(0x9, 0x188, 'NpFf') [FCB]
      -> ExAllocatePoolWithQuotaTag(0x208, 0x38, 'NpFf') [FCB Event]
      -> ExAllocatePoolWithQuotaTag(0x208, name_len, 'NpFn') [FCB Name]
      -> ExAllocatePoolWithTag(PagedPool, 0x28, 'NpAt') [Process info]
      -> ExAllocatePoolWithQuotaTag(0x109, 0x1D0, 'NpFc') [CCB]
`

### Disconnect (FSCTL_PIPE_DISCONNECT)

`
User mode: DeviceIoControl(hPipe, FSCTL_PIPE_DISCONNECT, ...)
  -> NpFsdFileSystemControl -> NpCommonFileSystemControl
    -> NpDisconnect (0x1C000E840)
      -> ExAcquirePushLockExclusiveEx
      -> NpSetDisconnectedPipeState (0x1C000EAB0)
      -> NpClearSecurity
      -> ExReleasePushLockExclusiveEx
`

### Peek (FSCTL_PIPE_PEEK)

`
User mode: DeviceIoControl(hPipe, FSCTL_PIPE_PEEK, ...)
  -> NpFsdFileSystemControl -> NpCommonFileSystemControl
    -> NpPeek (0x1C000A2F0)
      -> NpReadDataQueue (with peek mode, does not remove entries)
`

---

## 10. Race Condition Analysis

### Push Lock Protection

All data queue operations are protected by ExAcquirePushLockExclusiveEx(CCB+64):
- NpCommonWrite: acquires before NpWriteDataQueue/NpAddDataQueueEntry
- NpFsdRead/NpFastRead: acquires before NpReadDataQueue
- NpTransceive: acquires before NpWriteDataQueue/NpAddDataQueueEntry
- NpDisconnect: acquires before NpSetDisconnectedPipeState
- NpCommonCleanup: acquires before NpSetClosingPipeState

### Cancel Path (NpCancelDataQueueIrp)

Called in two contexts:
1. From I/O manager cancel: acquires push lock itself (a1 != 0)
2. From NpAddDataQueueEntry: lock already held (a1 = 0, skips lock)

Both paths are properly serialized. No TOCTOU race found.

### Data Queue Entry Cache

Single-entry cache at queue+40 (pointer with flag bit 0):
- Reuse: only for 48-byte no-data entries (v14 == 48)
- Cache on remove: if removed entry matches cached pointer
- No race: all operations under push lock
- Size mismatch: cached entry can be larger than needed (safe, just wasted space)

---

## 11. Exploitation Strategy

### Primary Finding

No direct buffer overflow exists in npfs.sys. All allocation sizes match copy sizes. The integer overflow check has a theoretical gap but is not practically exploitable.

### Best Approach: Heap Feng Shui + Adjacent Overflow from Other Driver

Since npfs.sys has no direct overflow, exploitation requires an overflow from an ADJACENT allocation in the same pool arena:

#### Strategy A: Session NonPagedPoolNx (Data Queue Entries)

1. Spray Data Queue Entries at target LFH bucket (e.g., 1024: write 976 bytes)
2. Find a vulnerable driver that allocates in NonPagedPoolSessionNx same bucket
3. Overflow from vulnerable allocation into adjacent Data Queue Entry
4. Corrupt IRP pointer (offset 16) -> write-zero primitive
5. Or corrupt SecurityContext (offset 24) -> free-anywhere -> write-what-where

#### Strategy B: System NonPagedPoolNx (Write Data Buffer / FCB Name)

1. Spray Write Data Buffers (tag NpFR) at target LFH bucket
   - Write exactly 1024 bytes to pipe with empty inbound queue
2. These ARE in system NonPagedPoolNx, same arena as KTM/ColorSpace
3. But Write Data Buffer has no pointer fields to corrupt
4. Use as padding/spray object between target and vulnerable allocation

#### Strategy C: System NonPagedPoolNx (Waiter entries)

1. Create Waiter entries (NpWaitForNamedPipe) with controlled name length
2. Waiter alloc = 176 + name_len in NonPagedPoolNx (system pool)
3. For bucket 1024: name length = 848 bytes
4. Waiter has pointer fields (DPC, Timer, FCB reference) that if corrupted
   could provide write primitives
5. Target: overflow from adjacent allocation into Waiter -> corrupt function pointers

### Recommended Next Steps

1. Look for vulnerable drivers that allocate in NonPagedPoolSessionNx (0x308)
2. Alternatively, use Write Data Buffer (NpFR) as heap spray in system NonPagedPoolNx
3. Combine with an overflow from another component (e.g., win32k, dxgkrnl, afd)
4. The Data Queue Entry's IRP pointer and SecurityContext are the best corruption targets
5. SecurityContext corruption gives free-anywhere -> realloc -> write-what-where
6. IRP pointer corruption gives write-zero (useful for disabling security checks)

---

## 12. Key Addresses

| Function | Address | Size |
|----------|---------|------|
| NpAddDataQueueEntry | 0x1C000D6C0 | 0x35E |
| NpRemoveDataQueueEntry | 0x1C001308 | 0x11B |
| NpWriteDataQueue | 0x1C000DEB0 | 0x433 |
| NpReadDataQueue | 0x1C000E400 | 0x438 |
| NpCommonWrite | 0x1C000DC00 | 0x2A0 |
| NpFsdWrite | 0x1C000DB10 | 0xE1 |
| NpFastWrite | 0x1C000DA30 | 0xCD |
| NpFsdRead | 0x1C000D410 | 0x2A8 |
| NpFastRead | 0x1C000A8C0 | 0x208 |
| NpCreateCcb | 0x1C000AAD0 | 0x1E2 |
| NpCreateNewNamedPipe | 0x1C000C3A0 | 0x70B |
| NpCreateClientEnd | 0x1C000BF90 | 0x402 |
| NpFsdFileSystemControl | 0x1C000CB90 | 0x5F |
| NpCommonFileSystemControl | 0x1C000CC00 | 0x4AC |
| NpTransceive | 0x1C000D0C0 | 0x346 |
| NpInternalTransceive | 0x1C0014A00 | 0x3BE |
| NpInternalWrite | 0x1C0014DC4 | 0x201 |
| NpInternalRead | 0x1C00147E0 | 0x218 |
| NpDisconnect | 0x1C000E840 | 0x12D |
| NpCommonCleanup | 0x1C000EC40 | 0x49C |
| NpFreeCcb | 0x1C000F3B0 | 0x82 |
| NpFreeFcb | 0x1C000F440 | 0xBD |
| NpCancelDataQueueIrp | 0x1C0001010 | 0x18E |
| NpGetNextRealDataQueueEntry | 0x1C000A6F0 | 0x2E |
| NpCompleteStalledWrites | 0x1C0013034 | 0xCB |
| NpSetAttributeInList | 0x1C00156A8 | 0x1DF |
| NpAddWaiter | 0x1C0001D8C | 0x208 |
| NpPeek | 0x1C000A2F0 | 0x13C |
| NpQueryDirectory | 0x1C00134B4 | 0x49B |
| NpSetListeningPipeState | 0x1C000E2F0 | 0x106 |
| NpFsdSetInformation | 0x1C000F870 | 0x1D1 |
| NpSetDisconnectedPipeState | 0x1C000EAB0 | 0x123 |
| NpSetClosingPipeState | 0x1C000F0F0 | 0x2AF |

---

## 13. Conclusion

npfs.sys is a compact (135 functions, 114KB) kernel driver with no direct buffer overflow in its data queue operations. All pool allocations match their copy sizes exactly. The driver uses safe LIST_ENTRY unlink checks (__fastfail(3) on failure) and push lock protection for all queue operations.

The primary exploitation value of npfs.sys lies in:

1. **Heap spray capability**: Data Queue Entries (NpFr) can be sprayed at any LFH bucket size in Session NonPagedPoolNx by controlling WriteFile buffer sizes. Write Data Buffers (NpFR) and Waiter entries (NpFw) can be sprayed in system NonPagedPoolNx.

2. **Corruption targets**: If an adjacent allocation overflows into a Data Queue Entry, the IRP pointer (offset 16) provides a write-zero primitive and the SecurityContext pointer (offset 24) provides a free-anywhere primitive.

3. **Free-anywhere to write-what-where**: Corrupting SecurityContext -> ExFreePoolWithTag(target) -> reallocate with controlled data via named pipe write -> write-what-where achieved.

4. **Pool type limitation**: Data Queue Entries are in Session NonPagedPoolNx (0x308), separate from system NonPagedPoolNx (0x200). KTM and ColorSpace objects are in system pool. Write Data Buffers (NpFR) ARE in system pool and CAN be adjacent to KTM/ColorSpace.

5. **Uninitialized memory**: 4 bytes at offset 44 in Data Queue Entries are never initialized (potential info leak, not a write primitive).
