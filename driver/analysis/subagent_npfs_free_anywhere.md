# NPFS.SYS Data Queue Entry (DQE) SecurityContext Corruption Primitive Analysis

## Binary Info
- **Module**: npfs.sys
- **Imagebase**: 0x1C0000000
- **Image size**: 0x1C000
- **MD5**: e2093593f86b7c1ec93fcb9b1ea94c20
- **SHA256**: 77e9e3eb9abb8be6a7cd304ce6faa331a07809c147546c390e52994b8dc1cd4e
- **IDA PID**: 9784
- **Functions analyzed**: 135 total, 132 named

---

## 1. Complete DQE Structure Layout

### DQE Structure (tag 'NpFr', pool type 0x308)

```
Offset  Size  Field                Description
------  ----  -------------------  ------------------------------------------
0x00    8     Flink                LIST_ENTRY.Flink - next DQE or DataQueue head
0x08    8     Blink                LIST_ENTRY.Blink - prev DQE or DataQueue head
0x10    8     IRP                  Pointer to the IRP associated with this entry
                                    -> Used for write-zero: xchg [IRP+0x68], 0
0x18    8     SecurityContext      Pointer to SECURITY_CLIENT_CONTEXT (or NULL)
                                    -> Freed via NpFreeClientSecurityContext
                                    -> ExFreePoolWithTag(ctx, 0) with TAG=0
0x20    4     QueueState           0=unprocessed, 1=processed, 2=empty/flushed
0x24    4     QuotaUsed            Bytes consumed from quota
0x28    4     DataLength           Total data length in this DQE
0x2C    4     (padding)            Alignment
0x30    var   DataBuffer           Inline data buffer (buffered mode only)
```

**Base size**: 0x30 (48 bytes)
**With inline data**: 0x30 + DataLength

### Pool Allocation Details

| Object           | Pool Type | Tag    | Size             | Pool Scope              |
|-----------------|-----------|--------|------------------|------------------------|
| DQE              | 0x308     | NpFr   | 0x30+data        | Session NP Nx (quota)  |
| SecurityContext  | 0x009     | NpFs   | 0x48             | PagedPool (quota)      |
| NpFR Buffer      | 0x200     | NpFR   | user-controlled  | System NP Nx           |

**Pool type breakdown**:
- 0x308 = NonPagedPoolNx(0x200) | Session(0x100) | Quota(0x008) -- session-scoped NonPagedPoolNx with quota
- 0x009 = PagedPool(0x001) | Quota(0x008) -- PagedPool with quota
- 0x200 = NonPagedPoolNx -- SYSTEM NonPagedPoolNx (shared across all sessions)

### SECURITY_CLIENT_CONTEXT Layout (tag 'NpFs', 0x48 bytes)

```
Offset  Size  Field                Description
------  ----  -------------------  ------------------------------------------
0x00    8     SecurityQOS          SecurityQualityOfService reference
0x08    8     (padding/flags)
0x10    8     AccessToken          PACCESS_TOKEN - THE TOKEN POINTER
                                    Read by NpFreeClientSecurityContext
                                    Passed to SeTokenType and PsDereference*Token
0x18    ...   remaining fields     DirectAccess, ImpersonationLevel, etc.
```

### DataQueue Structure

```
Offset  Size  Field                Description
------  ----  -------------------  ------------------------------------------
0x00    8     Flink                Self-referential when empty
0x08    8     Blink                Self-referential when empty
0x10    4     QueueState           2=empty
0x14    4     QueueType
0x18    4     BytesInQueue
0x1C    4     EntriesInQueue
0x20    4     QuotaUsed
0x24    4     QuotaAllocation
0x28    8     CachedDqe            Last freed DQE pointer; bit 0 = cache valid
0x2C    4     NextByteOffset
```

### CCB (Connection Context Block) Key Field

```
Offset  Size  Field                Description
------  ----  -------------------  ------------------------------------------
0x108   8     SecurityContext      Transferred from DQE+0x18 during read
                                    Values: 0=NULL, -1=sentinel, valid_ptr=active
```

---

## 2. Complete Decompilation of DQE Lifecycle

### 2.1 DQE Creation -- NpAddDataQueueEntry (0x1C000D6C0)

**Callers**: NpTransceive, NpFsdRead, NpCommonWrite, NpCommonFlushBuffers, NpCommonFileSystemControl, NpInternalRead, NpInternalTransceive, NpInternalWrite

**Key flow**:

```c
// SecurityContext creation (only for write direction, byte-stream pipe, no sentinel)
if (Direction == 1 && QueueType != 2) {
    if (!Direction && *(CCB+20) == 1 && *(CCB+264) != -1) {
        SecurityContext = ExAllocatePoolWithQuotaTag(0x9, 0x48, 'NpFs');  // PagedPool|Quota
        SeCreateClientSecurity(CurrentThread, SecurityQOS, 0, SecurityContext);
        if (FAILED) {
            ExFreePoolWithTag(SecurityContext, 0);
            SecurityContext = NULL;
        }
    }
}

// DQE allocation - try cached DQE first, then allocate
if (QueueType == 0) {  // Buffered mode
    AllocSize = HasData ? (DataSize + 0x30) : 0x30;
    if (AllocSize == 0x30 && interlockedbittestandreset(DataQueue+0x28, 0))
        DQE = *(DataQueue+0x28);  // Reuse cached
    else
        DQE = ExAllocatePoolWithQuotaTag(0x308, AllocSize, 'NpFr');  // Session NP Nx + Quota
} else {
    if (interlockedbittestandreset(DataQueue+0x28, 0))
        DQE = *(DataQueue+0x28);
    else
        DQE = ExAllocatePoolWithQuotaTag(0x308, 0x30, 'NpFr');
}

// Fill DQE fields
DQE[0x00] = DataQueue;           // Flink
DQE[0x08] = OldBlink;            // Blink
DQE[0x10] = IRP;                 // IRP pointer -> WRITE-ZERO TARGET
DQE[0x18] = SecurityContext;     // SecurityContext -> FREE-ANYWHERE TARGET
DQE[0x20] = QueueState;
DQE[0x24] = QuotaAmount;
DQE[0x28] = DataLength;

// Copy inline data (buffered mode)
if (HasData) memmove(DQE + 0x30, DataSource, DataSize);

// Link into DataQueue doubly-linked list
InsertTailList(DataQueue, DQE);

// Set IRP cancel routine
InterlockedExchange64(IRP + 0x68, NpCancelDataQueueIrp);

// If IRP already cancelled, call cancel handler
if (IRP->Cancel) {
    if (InterlockedExchange64(IRP + 0x68, 0))
        NpCancelDataQueueIrp(NULL, IRP);
}
```

### 2.2 DQE Removal -- NpRemoveDataQueueEntry (0x1C001308)

**Callers**: NpGetNextRealDataQueueEntry, NpWriteDataQueue (4x), NpReadDataQueue (2x), NpSetDisconnectedPipeState (3x), NpSetClosingPipeState (2x)

```c
__int64 NpRemoveDataQueueEntry(__int64 **DataQueue, char GetNext, __int64 CompletionList) {
    if (DataQueue->QueueState == 2) return 0;  // Empty

    DQE = *DataQueue;  // First DQE

    // Unlink from doubly-linked list
    Next = *DQE;
    Next[1] = DataQueue;
    *DataQueue = Next;

    // Update counters
    DataQueue->BytesInQueue -= DQE->DataLength;
    DataQueue->EntriesInQueue--;

    // === FREE-ANYWHERE PRIMITIVE ===
    NpFreeClientSecurityContext(DQE[3]);  // DQE[3] = offset 0x18

    // === WRITE-ZERO PRIMITIVE ===
    IRP = DQE[2];  // DQE[2] = offset 0x10
    if (IRP) {
        if (InterlockedExchange64(IRP + 0x68, 0)) {  // Zero CancelRoutine
            *(IRP + 0x90) = 0;  // Also zero if old was non-zero
            IRP = 0;
        }
    }

    // === DQE CACHING OR FREE ===
    if (DataQueue->CachedDqe == DQE)
        interlockedbittestandset(&DataQueue->CachedDqe, 0);  // Cache
    else
        ExFreePoolWithTag(DQE, 0);  // Free

    if (GetNext) NpGetNextRealDataQueueEntry(DataQueue, CompletionList);
    DataQueue->NextByteOffset = 0;
    return IRP;
}
```

**Assembly of write-zero site** (0x1C001319A):
```asm
mov  rsi, [rdi+10h]              ; rsi = DQE+0x10 (IRP pointer)
call NpFreeClientSecurityContext  ; Free DQE+0x18 (SecurityContext)
test rsi, rsi                     ; Check if IRP is NULL
jz   skip_zero                    ; Skip if NULL
xor  eax, eax                     ; eax = 0
xchg rax, [rsi+68h]              ; ATOMIC: [IRP+0x68] <- 0, old -> rax
test rax, rax                     ; Check old value
jnz  skip_zero2                  ; If non-zero, skip second zero
and  [rsi+90h], rax              ; Zero [IRP+0x90] (only if old was 0)
xor  esi, esi                     ; IRP = NULL
```

Note: `xchg` with a memory operand has an implicit LOCK prefix on x86-64.

### 2.3 NpFreeClientSecurityContext (0x1C000A670) -- The Free-Anywhere Core

```c
void NpFreeClientSecurityContext(PACCESS_TOKEN *P) {
    // Check: P != 0 AND P != 0xFFFFFFFFFFFFFFFF (-1)
    if ((unsigned __int64)P - 1 <= 0xFFFFFFFFFFFFFFFDULL) {
        TOKEN_TYPE TokenType = SeTokenType(P[2]);  // P[2] = *(P+0x10)
        PACCESS_TOKEN Token = P[2];

        if (TokenType == TokenPrimary)
            PsDereferencePrimaryToken(Token);
        else
            PsDereferenceImpersonationToken(Token);

        // === FREE with TAG=0 (accepts ANY pool tag) ===
        ExFreePoolWithTag(P, 0);
    }
}
```

**Callers**: NpCancelDataQueueIrp, NpAddDataQueueEntry, NpWriteDataQueue, NpReadDataQueue, NpRemoveDataQueueEntry, NpImpersonate, NpUnlinkCcb

**Critical**: `ExFreePoolWithTag(P, 0)` uses **tag=0**. In Windows 10+, tag=0 means "do not verify pool tag" -- the free succeeds regardless of what tag the target allocation was created with. This is a **universal pool free** primitive.

### 2.4 SecurityContext Transfer in NpReadDataQueue (0x1C000E400)

When reading from a pipe, the DQE's SecurityContext is **transferred** to the CCB:

```c
SecurityContext = DQE[0x18];  // DQE+0x18
if (SecurityContext) {
    ExistingCtx = CCB[0x108];  // CCB+0x108
    if (ExistingCtx && ExistingCtx != -1) {
        // FREE the CCB's existing SecurityContext
        SeTokenType(ExistingCtx[0x10]);
        PsDereference*Token(ExistingCtx[0x10]);
        ExFreePoolWithTag(ExistingCtx, 0);  // FREE with TAG=0
    }
    if (ExistingCtx == -1)
        NpFreeClientSecurityContext(SecurityContext);  // Free DQE's context
    else
        CCB[0x108] = SecurityContext;  // TRANSFER to CCB
}
DQE[0x18] = 0;  // Clear DQE's SecurityContext
```

### 2.5 DQE Cancellation -- NpCancelDataQueueIrp (0x1C0001010)

```c
void NpCancelDataQueueIrp(__int64 CancelParam, IRP *Irp) {
    if (CancelParam)
        IoReleaseCancelSpinLock(Irp->CancelIrql);

    DataQueue = Irp->DriverContext[2];
    CCB = Irp->CurrentStackLocation->FileObject->FsContext2 & ~3;

    if (CancelParam) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusiveEx(CCB + 64, 0);
    }

    DQE = Irp->DriverContext[3];
    if (DQE) {
        // Unlink from list, update counters
        SecurityContext = DQE[3];  // DQE+0x18
        // Cache or free DQE
    }

    if (CancelParam) {
        ExReleasePushLockExclusiveEx(CCB + 64, 0);
        KeLeaveCriticalRegion();
    }

    if (DQE) ExFreePoolWithTag(DQE, 0);  // Free DQE
    NpFreeClientSecurityContext(SecurityContext);  // Free SecurityContext

    Irp->IoStatus.Status = STATUS_CANCELLED;
    IofCompleteRequest(Irp, IO_NO_INCREMENT);
}
```

### 2.6 Other Free Paths

**NpImpersonate (0x1C00146E8)**: Frees CCB[0x108] and sets sentinel -1.

**NpUnlinkCcb (0x1C0015B78)**: Calls NpClearSecurity to extract CCB[0x108], then NpFreeClientSecurityContext.

**NpSetDisconnectedPipeState (0x1C000EAB0)**: Drains all DQEs via NpRemoveDataQueueEntry loop.

**NpSetClosingPipeState (0x1C000F0F0)**: Drains all DQEs with inline removal (same free-anywhere + write-zero pattern).

**NpWriteDataQueue (0x1C000DEB0)**: Has inline DQE removal at LABEL_37 with identical pattern. Also allocates NpFR buffer: `ExAllocatePoolWithTag(0x200, size, 'NpFR')`.

---

## 3. Verification of Primitives

### 3.1 Free-Anywhere Primitive (DQE+0x18) -- VERIFIED

DQE+0x18 is freed via `ExFreePoolWithTag(DQE+0x18, 0)` in 7 functions (see table in section 2).

**Constraints**:
1. P != 0 AND P != 0xFFFFFFFFFFFFFFFF (-1)
2. *(P+0x10) must survive SeTokenType + PsDereference*Token
3. If P+0x10 is NULL -> SeTokenType(NULL) -> BSOD
4. If P+0x10 is a valid TOKEN -> refcount decremented (potential token UAF)
5. Tag=0 means any pool tag is accepted -- universal free

**Can we control DQE+0x18 from user mode?**: NO. It is set by the driver to either NULL or a kernel-allocated SECURITY_CLIENT_CONTEXT. Corrupting it requires a prior memory corruption primitive.

**Can we trigger DQE+0x18 to be non-NULL?**: YES. Write to a byte-stream pipe with SECURITY_QUALITY_OF_SERVICE set and CCB sentinel not -1.

### 3.2 Write-Zero Primitive (DQE+0x10) -- VERIFIED

`xchg rax, [DQE+0x10 + 0x68]` atomically writes 0 to (DQE+0x10 + 0x68).

- If old value at +0x68 was 0: also zeros +0x90
- If old value was non-zero: only zeros +0x68
- Constraint: DQE+0x10 must be non-NULL

**Can we control DQE+0x10 from user mode?**: NO. It is set to the actual IRP pointer by the driver.

**Nature**: This is a **relative write-zero** at offset 0x68 from a controlled address. To zero address A, need DQE+0x10 = A - 0x68.

### 3.3 8-Byte Arbitrary Write Assessment

**Free-Anywhere -> Reclaim -> Write-What-Where**: YES, conditionally.
1. Free target T via DQE+0x18 = T (requires prior corruption)
2. Reclaim freed slot with controlled content (NpFR spray or other)
3. Code referencing T now reads attacker-controlled data

**Write-Zero -> Secondary Corruption -> Arbitrary Write**: PARTIALLY.
- Zero a refcount at offset 0x68 -> premature free -> reclaim -> write-what-where
- Zero a function pointer at offset 0x68 -> null deref (not useful directly)
- Zero a security descriptor pointer -> security bypass

---

## 4. Pool Type and LFH Bucket Analysis

### 4.1 NpFR Buffer -- System NonPagedPoolNx Spray

The most useful spray primitive:
- **Pool**: System NonPagedPoolNx (0x200) -- shared across all sessions
- **Tag**: 'NpFR' (0x5246704E)
- **Size**: User-controlled (write data length)
- **Content**: User-controlled (the write data)
- **Lifetime**: From pipe write until pipe read completes write IRP
- **Allocation**: `ExAllocatePoolWithTag(0x200, user_size, 'NpFR')` in NpWriteDataQueue
- **Free**: I/O manager when write IRP completes

**Target adjacency** (same System NonPagedPoolNx):
- KTM (Kernel Transaction Manager) objects
- ColorSpace objects (win32k)
- ALPC port objects
- Most kernel object allocations

### 4.2 DQE Spray -- Session NonPagedPoolNx

- **Pool**: Session NonPagedPoolNx with quota (0x308)
- **Tag**: 'NpFr' (0x7246704E)
- **Size**: 0x30 base, or 0x30 + data_size
- **Content**: NOT user-controlled (driver-set fields)
- **Cache**: Single-entry per DataQueue (last removed DQE cached, not freed)
- To force DQE frees: remove two DQEs in sequence (first cached, second freed)

### 4.3 SecurityContext Spray -- PagedPool

- **Pool**: PagedPool with quota (0x009)
- **Tag**: 'NpFs' (0x7346704E)
- **Size**: 0x48 (72 bytes) -- fixed
- **Content**: NOT user-controlled (SeCreateClientSecurity fills it)
- **Free**: Via NpFreeClientSecurityContext with tag=0

---

## 5. Reclaim Strategy After Free

### 5.1 After Freeing NpFR Buffer (System NonPagedPoolNx)

1. Free: Read from pipe -> write IRP completes -> I/O manager frees NpFR buffer
2. Reclaim: Allocate target object in same LFH bucket (match size)
3. Target fills freed slot, adjacent to other NpFR buffers
4. No overflow from NpFR (exact-size allocation)

### 5.2 After Freeing SecurityContext (PagedPool, 0x48 bytes)

1. Free: Read from pipe -> CCB's old SecurityContext freed (ExFreePoolWithTag ctx, 0)
2. Reclaim: PagedPool object of ~0x48 size
3. Tag=0 free means any tag target can be freed (if DQE+0x18 is corrupted to point at it)

### 5.3 After Freeing DQE (Session NonPagedPoolNx, 0x30 bytes)

1. Free: Disconnect/close pipe -> DQE freed (ExFreePoolWithTag DQE, 0)
2. Reclaim: Session NonPagedPoolNx object of ~0x30 size
3. Potential targets: GDI objects in session pool

### 5.4 After Freeing Arbitrary Target (via corrupted DQE+0x18)

1. Corrupt DQE+0x18 to point at target object T (requires prior primitive)
2. Trigger DQE removal (read/disconnect/cancel) -> NpFreeClientSecurityContext(T)
3. SeTokenType(T+0x10) and PsDereference*Token(T+0x10) must succeed
4. ExFreePoolWithTag(T, 0) frees T regardless of its pool tag
5. Reclaim T's slot with controlled content via NpFR spray (if in System NP Nx)
   or other spray matching T's pool and size

---

## 6. Complete Exploit Chain

### 6.1 Primitive Classification

The npfs DQE provides **amplification primitives**, not initial corruption primitives:

| Primitive | Type | Requires Initial Corruption? | Universal Tag Free? |
|-----------|------|-----|-----|
| Free-Anywhere (DQE+0x18) | Amplification | YES | YES (tag=0) |
| Write-Zero (DQE+0x10) | Amplification | YES | N/A |
| NpFR Spray | Pool Grooming | NO | N/A |
| SecurityContext Free | PagedPool Free | NO (triggered by read) | YES (tag=0) |

### 6.2 Exploit Chain A: Pool Overflow -> DQE Corruption -> Free-Anywhere -> Write-What-Where

1. **Initial corruption**: Use a separate pool overflow vulnerability in session NonPagedPoolNx to overflow into a DQE
2. **Corrupt DQE+0x18**: Overwrite with address of target object T
3. **Prepare reclaim**: Spray NpFR buffers of T's size in System NonPagedPoolNx (if T is in system pool) or match T's pool
4. **Trigger free**: Read from pipe or disconnect -> NpRemoveDataQueueEntry -> NpFreeClientSecurityContext(T)
   - T+0x10 must contain a valid-looking token pointer (satisfy SeTokenType)
   - ExFreePoolWithTag(T, 0) frees T regardless of tag
5. **Reclaim**: Allocate replacement object in T's pool/bucket with controlled content
6. **Write-what-where achieved**: Code referencing T now reads attacker data

### 6.3 Exploit Chain B: Write-Zero -> Refcount Zero -> UAF -> Write-What-Where

1. **Initial corruption**: Overflow or UAF to corrupt DQE+0x10 to point at (target - 0x68)
2. **Trigger write-zero**: Remove DQE -> xchg [target+0x68], 0
3. **If target+0x68 is a refcount**: Object freed prematurely
4. **Reclaim**: Spray controlled allocation into freed slot
5. **Write-what-where**: UAF via reclaimed slot

### 6.4 Exploit Chain C: NpFR Pool Grooming -> KTM/ColorSpace Adjacency

1. **Spray NpFR buffers**: Write to N pipes with controlled sizes matching target LFH bucket
2. **Create hole**: Read from one pipe -> NpFR buffer freed
3. **Allocate target**: KTM resource manager or ColorSpace object fills hole
4. **Target is now adjacent to NpFR buffers** with controlled content
5. **Use separate vulnerability** in KTM/ColorSpace to corrupt adjacent NpFR or vice versa
6. **NpFR content is user-controlled** -> can contain fake object headers, function pointers, etc.

### 6.5 Exploit Chain D: SecurityContext Free -> PagedPool UAF

1. **Create pipe with SecurityContext**: Write to byte-stream pipe with QoS set
2. **Read from pipe**: Transfers SecurityContext to CCB, frees old CCB context
3. **SecurityContext freed in PagedPool** (0x48 bytes, tag 'NpFs', tag=0 free)
4. **Reclaim**: Allocate PagedPool object of ~0x48 size
5. **If CCB still references freed context**: UAF on next read/write/impersonate
6. **Control UAF content** via reclaim object

### 6.6 Constraint Bypass for SeTokenType/PsDereference

To use the free-anywhere on a target T where T+0x10 is not a valid token:

**Option 1: Fake Token in NpFR Buffer**
1. Spray NpFR buffers in System NonPagedPoolNx with fake TOKEN at known offset
2. Corrupt DQE+0x18 to point at target T
3. Corrupt T+0x10 to point at NpFR buffer (containing fake TOKEN)
4. SeTokenType reads fake TOKEN -> returns controlled TokenType
5. PsDereference*Token decrements fake refcount (no crash if fields are valid)
6. ExFreePoolWithTag(T, 0) frees T

**Option 2: Target with Valid Token at +0x10**
1. Find target object where offset 0x10 naturally contains a pointer to a TOKEN-like object
2. The token's refcount is decremented (side effect, may cause token UAF)
3. ExFreePoolWithTag(T, 0) frees T

**Option 3: Target in PagedPool with Zero at +0x10**
- NOT viable: SeTokenType(NULL) -> BSOD

---

## 7. Summary

### Verified Findings

1. **DQE+0x18 (SecurityContext) IS freed via ExFreePoolWithTag with tag=0** -- VERIFIED in 7 code paths
2. **DQE+0x10 (IRP) IS used for InterlockedExchange64(addr+0x68, 0)** -- VERIFIED in 6 code paths
3. **Tag=0 means universal pool free** -- accepts any pool tag
4. **NpFR buffer is in System NonPagedPoolNx (0x200)** -- CAN be adjacent to KTM/ColorSpace
5. **DQE is in Session NonPagedPoolNx (0x308)** -- separate from system pool
6. **SecurityContext is in PagedPool (0x009)** -- separate from both
7. **DQE+0x10 and DQE+0x18 are NOT directly user-controllable** -- set by driver
8. **NpFR buffer size and content ARE user-controllable** -- pool spray primitive
9. **SecurityContext free can be triggered by pipe read** -- CCB transfer mechanism
10. **DQE single-entry cache** -- affects pool grooming strategy

### Primitive Assessment

- **Free-Anywhere**: Amplification primitive. Requires initial corruption to set DQE+0x18. Has SeTokenType/PsDereference constraint. Tag=0 makes it universal across pool tags.
- **Write-Zero**: Amplification primitive. Requires initial corruption to set DQE+0x10. Relative zero at +0x68 offset. Can cause secondary UAF if target field at +0x68 is a refcount.
- **NpFR Spray**: Direct primitive. User-controlled size and content in System NonPagedPoolNx. Useful for pool grooming and fake object placement.
- **SecurityContext Free**: Direct primitive. Triggered by pipe read. Frees PagedPool block (0x48 bytes) with tag=0. Can be used for PagedPool UAF.

### Key Addresses

| Function | Address | Size |
|----------|---------|------|
| NpAddDataQueueEntry | 0x1C000D6C0 | 0x35E |
| NpRemoveDataQueueEntry | 0x1C001308 | 0x11B |
| NpFreeClientSecurityContext | 0x1C000A670 | 0x1E |
| NpCancelDataQueueIrp | 0x1C0001010 | 0x18E |
| NpWriteDataQueue | 0x1C000DEB0 | 0x433 |
| NpReadDataQueue | 0x1C000E400 | 0x438 |
| NpSetDisconnectedPipeState | 0x1C000EAB0 | 0x123 |
| NpSetClosingPipeState | 0x1C000F0F0 | 0x2AF |
| NpImpersonate | 0x1C00146E8 | 0xF2 |
| NpUnlinkCcb | 0x1C0015B78 | 0xA9 |
| NpClearSecurity | 0x1C00011B0 | 0x19 |
| NpCommonWrite | 0x1C000DC00 | 0x2A0 |
| NpFsdWrite | 0x1C000DB10 | 0xE1 |
| NpFsdRead | 0x1C000D410 | 0x2A8 |

### Pool Tags

| Tag | Hex | Object | Pool |
|-----|-----|--------|------|
| NpFr | 0x7246704E | DQE | Session NP Nx (0x308) |
| NpFs | 0x7346704E | SecurityContext | PagedPool (0x009) |
| NpFR | 0x5246704E | Write Data Buffer | System NP Nx (0x200) |
