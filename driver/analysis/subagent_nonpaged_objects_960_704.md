# NonPagedPoolNx Object Analysis for Pool Reclamation at 960/704 Bytes

## Target: Find kernel objects in NonPagedPoolNx at sizes 960 or 704 bytes with a pointer at offset 0x50 that gets dereferenced.

## Binary: ntoskrnl.exe (Windows 10 22H2 x64) — IDA Pro PID 8428, port 13346

---

## 1. LFH Bucket Table (Extracted from ntoskrnl Binary)

The actual pool LFH bucket table was extracted from two globals in ntoskrnl:

- `RtlpLfhBucketIndexMap` at RVA `0x140011c50` — byte array mapping `(aligned_total_size >> 4)` to bucket index
- `RtlpBucketBlockSizes` at RVA `0x140012600` — word array mapping bucket index to actual bucket size

The LFH is used for total allocation sizes (user_size + 16-byte pool header, aligned to 16) between `0x210` (528) and `0xF80` (3968).

### Bucket Size Table (Complete)

| Index | Bucket Size | Interval | User Size Range |
|-------|-------------|----------|-----------------|
| 0-32  | 16-512      | 16 bytes | 1-496           |
| 33-64 | 528-1024    | 16 bytes | 513-1008        |
| 65-80 | 1088-2048   | 64 bytes | 1073-2032       |
| 81-96 | 2176-4096   | 128 bytes| 2161-4080       |

**CRITICAL**: Bucket sizes are at **16-byte intervals** up to 1024, not 32 or 64-byte intervals as commonly assumed.

### Target Bucket Computation (Python-verified)

```
User size 960: total=976, aligned=976 (0x3D0), bucket_index=61, bucket_size=976
  -> User sizes 945-960 all map to bucket 976

User size 704: total=720, aligned=720 (0x2D0), bucket_index=45, bucket_size=720
  -> User sizes 689-704 all map to bucket 720
```

To reclaim a freed portcls allocation at user size 960, the target object must also have a user size in **945-960**. For user size 704, the target must be in **689-704**.

---

## 2. Candidate Structures (from IDA Type Library)

### Structs in 945-960 range (LFH bucket 976 for 960)

| Struct | Size | Hex | Offset 0x50 Field | Type | Pointer? |
|--------|------|-----|--------------------|------|----------|
| `_KTM` | 960 | 0x3C0 | NamespaceLink.Links.Links.Blink | LIST_ENTRY ptr | **YES** |
| `_WHEA_XPF_CMC_DESCRIPTOR` | 932 | 0x3A4 | Banks[N] | array elem | No (wrong bucket: 944) |
| `_WHEA_ERROR_SOURCE_DESCRIPTOR` | 932 | 0x3A4 | same | same | No (wrong bucket: 944) |

**Only `_KTM` (960 bytes) falls in the correct LFH bucket (976).**

### Structs in 689-704 range (LFH bucket 720 for 704)

| Struct | Size | Hex | Offset 0x50 Field | Type | Pointer? |
|--------|------|-----|--------------------|------|----------|
| `_MI_PARTITION_MODWRITES` | 704 | 0x2C0 | AttemptForCantExtend.ActiveEntry | void** volatile | **YES** |
| `_HEAP` | 704 | 0x2C0 | Segment.NumberOfUnCommittedPages | unsigned int | **NO** |
| `_KPRIQUEUE` | 688 | 0x2B0 | EntryListHead[3].Blink | LIST_ENTRY ptr | YES (wrong bucket: 688) |
| `_TRIAGE_EX_WORK_QUEUE` | 688 | 0x2B0 | unknown | unknown | Unknown (wrong bucket: 688) |

**Only `_MI_PARTITION_MODWRITES` (704 bytes) has a pointer at 0x50 in the correct bucket.**

---

## 3. Detailed Candidate Analysis

### 3.1 IRP (_IRP) — THE STRONGEST POINTER CANDIDATE

| Property | Value |
|----------|-------|
| **Struct size** | 208 bytes (0xD0) base |
| **Allocation size** | 208 + 72 * StackSize (variable) |
| **Offset 0x50** | **PKEVENT UserEvent** — POINTER, dereferenced on IRP completion |
| **Pool type** | NonPagedPoolNx (0x200) |
| **Pool tag** | 'prI ' (0x20707249) |
| **Zeroed on alloc** | **YES** — `memset(buf, 0, size)` in `IopAllocateIrpPrivate` at RVA 0x1402D2220 |
| **User-triggerable** | **YES** — any I/O operation (NtReadFile, NtWriteFile, NtDeviceIoControlFile, etc.) |
| **Free path** | `ExFreePoolWithTag` — no zeroing on free |
| **Lookaside bypass** | `IopLargeIrpStackLocations = 255` (signed char = -1), so `StackSize <= -1` is never true → ALL IRPs go through pool allocation, not lookaside |

**IRP Size to LFH Bucket mapping:**

| StackSize | IRP Size | LFH Bucket | User Size Range |
|-----------|----------|------------|-----------------|
| 1 | 280 | 288 | 265-280 |
| 7 | 712 | 736 | 705-736 |
| 10 | 928 | 944 | 913-928 |
| 11 | 1000 | 1024 | 985-1008 |

**No IRP size falls in bucket 976 (945-960) or bucket 720 (689-704).**

The closest IRP sizes:
- StackSize=10 → 928 → bucket 944 (portcls would need to alloc at 913-928)
- StackSize=7 → 712 → bucket 736 (portcls would need to alloc at 705-736)

**Verdict: NO-GO for direct UAF reclamation** — the memset zeroing wipes the fake pointer at offset 0x50. However, the IRP remains the best candidate for alternative exploit strategies (see Section 5).

### 3.2 KTM (_KTM) — EXACT SIZE MATCH AT 960

| Property | Value |
|----------|-------|
| **Struct size** | 960 bytes (0x3C0) — **EXACT MATCH** |
| **LFH bucket** | 976 (user sizes 945-960) |
| **Offset 0x50** | NamespaceLink.Links.Links.Blink — LIST_ENTRY pointer |
| **Dereferenced?** | YES — during balanced link tree traversal (RtlBalancedLink operations) |
| **Pool type** | NonPagedPoolNx (expected, needs verification) |
| **Zeroed on alloc** | Unknown — allocation path is via thunks |
| **User-triggerable** | YES — NtCreateTransactionManager, NtCreateTransaction |
| **Free path** | Unknown — needs analysis |

**KTM Structure Layout at offset 0x50:**
```
_KTM + 0x48: NamespaceLink (_KTMOBJECT_NAMESPACE_LINK, 40 bytes)
  + 0x00: Links (_RTL_BALANCED_LINKS, 32 bytes)
    + 0x00: Links (_LIST_ENTRY, 16 bytes)
      + 0x00: Flink  (pointer)
      + 0x08: Blink  (pointer)  <-- THIS IS AT _KTM + 0x50
    + 0x10: Parent (pointer)
    + 0x18: Balance (byte + padding)
  + 0x20: Expired (byte)
```

**Analysis**: The Blink pointer at offset 0x50 is traversed when the kernel walks the balanced link tree during KTM namespace operations. If we control this pointer, we can redirect tree traversal to arbitrary kernel memory.

**Issue**: The NtCreateTransactionManager and NtCreateTransaction functions in this ntoskrnl build are thunks (size 0x7) that call `__imp_NtCreateTransactionManager` / `__imp_NtCreateTransaction`. The actual KTM implementation appears to be forwarded or in a separate module. The allocation path could not be fully traced.

**Verdict: POTENTIAL GO** — correct size, correct bucket, pointer at 0x50, user-triggerable. Needs further analysis to confirm pool type, zeroing behavior, and free path.

### 3.3 MI_PARTITION_MODWRITES — EXACT SIZE MATCH AT 704

| Property | Value |
|----------|-------|
| **Struct size** | 704 bytes (0x2C0) — **EXACT MATCH** |
| **LFH bucket** | 720 (user sizes 689-704) |
| **Offset 0x50** | AttemptForCantExtend.ActiveEntry — void** volatile |
| **Dereferenced?** | YES — volatile pointer, actively used in MM page file expansion |
| **Pool type** | NonPagedPoolNx (expected) |
| **Zeroed on alloc** | Unknown |
| **User-triggerable** | **NO** — internal MM structure, allocated during system initialization |
| **Free path** | Never freed (system lifetime object) |

**Verdict: NO-GO** — not user-triggerable, not allocatable on demand, never freed.

### 3.4 KPRIQUEUE — 688 bytes (WRONG BUCKET)

| Property | Value |
|----------|-------|
| **Struct size** | 688 bytes (0x2B0) |
| **LFH bucket** | 688 (user sizes 657-672) — **WRONG BUCKET for 704** |
| **Offset 0x50** | EntryListHead[3].Blink — LIST_ENTRY pointer |
| **Dereferenced?** | YES — during priority queue operations (KeInsertPriQueue, KeRemovePriQueue) |
| **User-triggerable** | Potentially via device I/O queue operations |
| **Pool type** | Likely NonPagedPoolNx (embedded in device queue structures) |

**Note**: If portcls targets user size 672 (bucket 688), KPRIQUEUE could work. But KPRIQUEUE at 688 bytes may be embedded in DEVICE_OBJECT rather than separately allocated.

**Verdict: NO-GO for 704 bucket** — wrong LFH bucket. Potential GO if targeting 672 bytes.

### 3.5 HEAP (_HEAP) — 704 bytes, NO POINTER AT 0x50

| Property | Value |
|----------|-------|
| **Struct size** | 704 bytes (0x2C0) — EXACT MATCH |
| **LFH bucket** | 720 (user sizes 689-704) |
| **Offset 0x50** | Segment.NumberOfUnCommittedPages — unsigned int (NOT a pointer) |
| **Verdict: NO-GO** — offset 0x50 is not a pointer |

---

## 4. Non-Zeroed NonPagedPoolNx Allocations in ntoskrnl

Comprehensive scan of all 2540 xrefs to `ExAllocatePoolWithTag` (at 0x1409B4160) in ntoskrnl:

| Metric | Count |
|--------|-------|
| Total xrefs | 2540 |
| NonPagedPoolNx (0x200) allocations with size info | 483 |
| Followed by memset/RtlZeroMemory | 125 |
| **NOT followed by zeroing** | **358** |

### Non-zeroed allocations near target buckets:

| Size | Hex | LFH Bucket | Function | User-triggerable? |
|------|-----|------------|----------|-------------------|
| 672 | 0x2A0 | 688 | EtwTiLogInsertQueueUserApc | Yes (QueueUserApc) — but write-only ETW buffer |
| 736 | 0x2E0 | 752 | ExpPartitionCreatePoolInternal | No |
| 912 | 0x390 | 928 | sub_140A1CEE4 (INIT segment) | No (boot init) |
| 968 | 0x3C8 | 992 | FsFilterInit | No (system init) |
| 784 | 0x310 | 800 | CmFcManagerStartRuntimePhase | No |
| 840 | 0x348 | 864 | VfIrpLogRecordEvent | No (verifier) |
| 888 | 0x378 | 896 | IopLiveDumpWriteDumpFile | No (live dump) |
| 1024 | 0x400 | 1024 | EtwpCCSwapStart | No |
| 1208 | 0x4B8 | 1264 | PopFxCreateDeviceCommon | No |
| 2200 | 0x898 | 2208 | PspCreateSecureThread | Yes (NtCreateThread) — but offset 0x50 = KTHREAD.CurrentRunTime (not a pointer) |

**None of the non-zeroed allocations fall in bucket 976 (945-960) or bucket 720 (689-704).**

### ExAllocatePool2 with POOL_FLAG_UNINITIALIZED

Searched all 24 xrefs to `ExAllocatePool2` (at 0x1409B41B0). **Zero** calls used `POOL_FLAG_UNINITIALIZED` (0x800). All ExAllocatePool2 calls use zeroed allocation.

---

## 5. Other Driver Analysis

### dxgkrnl.sys (PID 12088)

- 84 NonPagedPoolNx allocations found
- 66 not zeroed, 18 zeroed
- **All allocations are ≤104 bytes** — far too small for 960 or 704 buckets
- No allocations in target ranges

### dxgmms2.sys (PID 10784)

- 1 immediate-960 hit, 1 immediate-704 hit
- Neither near pool allocation calls

### clfs.sys (PID 4924)

- 30 NonPagedPoolNx allocations found
- 22 not zeroed
- **All allocations are ≤264 bytes** — far too small

### win32k.sys / win32kbase.sys / win32kfull.sys

- Not analyzed in detail — these use session pool (not system NonPagedPoolNx) for most objects

---

## 6. All Structs with Pointer at Offset 0x50 (Complete List)

154 structs in the IDA type library have a member at offset 0x50. Key ones with **pointers** at offset 0x50:

| Struct | Size | Offset 0x50 Field | Pointer Type | Allocated in NonPagedPoolNx? |
|--------|------|--------------------|--------------|-------------------------------|
| **_IRP** | 208 | UserEvent | PKEVENT | **YES** (but zeroed on alloc) |
| **_KTM** | 960 | NamespaceLink.Links.Blink | LIST_ENTRY* | Likely YES |
| _MI_PARTITION_MODWRITES | 704 | ActiveEntry | void** | YES (not user-triggerable) |
| _KPRIQUEUE | 688 | EntryListHead[3].Blink | LIST_ENTRY* | Embedded in device queue |
| _DEVICE_NODE | 784 | FxDevice | _POP_FX_DEVICE* | YES |
| _FILE_OBJECT | 216 | Flags | ULONG | YES (not a pointer) |
| _DRIVER_OBJECT | 336 | FastIoDispatch | PFAST_IO_DISPATCH | YES |
| _KINTERRUPT | 288 | DispatchAddress | function* | YES |
| _LPCP_PORT_OBJECT | 256 | PortContext | void* | YES |
| _CM_KEY_CONTROL_BLOCK | 312 | NameBlock | _CM_NAME_CONTROL_BLOCK* | YES |
| _CONTROL_AREA | 128 | WaitList | _MI_CONTROL_AREA_WAIT_BLOCK* | YES |
| _MMVAD | 136 | FirstPrototypePte | _MMPTE* | YES |
| _ERESOURCE | 104 | Reserved2 | PVOID | YES |
| _DEVOBJ_EXTENSION | 104 | DependencyNode | PVOID | YES |
| _FSRTL_ADVANCED_FCB_HEADER | 104 | FileContextSupportPointer | void** | YES |
| _POP_FX_COMPONENT | 440 | Device | _POP_FX_DEVICE* | YES |
| _POP_FX_DEVICE | 1208 | AcpiPlugin | _POP_FX_PLUGIN* | YES |
| _KALPC_REGION | 88 | ReadWriteView | _KALPC_VIEW* | YES |
| _ALPC_COMPLETION_LIST | 160 | Header | _ALPC_COMPLETION_LIST_HEADER* | YES |
| _CM_TRANS | 184 | KtmEnlistmentHandle | void* | YES |
| _CM_RM | 136 | CmHive | _CMHIVE* | YES |
| _BUS_HANDLER | 176 | SetBusData | function* | YES |
| _WNF_SUBSCRIPTION | 136 | CallbackRoutine | unsigned __int64 | YES |
| _MMPAGING_FILE | 288 | PfnsToFree | _SLIST_HEADER | YES |
| _POP_COOLING_EXTENSION | 144 | PnpFlushEvent | _KEVENT* | YES |
| _PO_DEVICE_NOTIFY | 104 | DriverName | wchar_t* | YES |
| _ETW_FILTER_HEADER | 104 | PayloadFilter | _ETW_PAYLOAD_FILTER* | YES |
| _OBJECT_TYPE_INITIALIZER | 120 | (union) | various | N/A |
| _PI_BUS_EXTENSION | 112 | FunctionalBusDevice | _DEVICE_OBJECT* | YES |
| _DMA_IOMMU_INTERFACE | 112 | MapIdentityRange | function* | YES |
| _HAL_IOMMU_DISPATCH | 152 | HalIommuFlushAllPasid | function* | YES |
| _INTERRUPT_FUNCTION_TABLE | 184 | SetLineState | function* | YES |
| _VF_TARGET_VERIFIED_DRIVER_DATA | 304 | PoolTrackers | _SLIST_HEADER | YES |
| _PNP_DEVICE_EVENT_ENTRY | 192 | Parent | _PNP_DEVICE_EVENT_ENTRY* | YES |

---

## 7. Summary Table

| # | Object | Size | Bucket | Offset 0x50 | Ptr? | NonPagedPoolNx? | Non-Zeroed? | User-Triggerable? | Verdict |
|---|--------|------|--------|-------------|------|-----------------|-------------|-------------------|---------|
| 1 | **_IRP** | 208+72*N | varies | PKEVENT UserEvent | **YES** | YES | **NO** (memset) | **YES** | **NO-GO** (zeroed) |
| 2 | **_KTM** | 960 | 976 | LIST_ENTRY Blink | **YES** | Likely | Unknown | **YES** | **POTENTIAL GO** |
| 3 | _MI_PARTITION_MODWRITES | 704 | 720 | void** ActiveEntry | **YES** | Likely | Unknown | **NO** | **NO-GO** |
| 4 | _HEAP | 704 | 720 | unsigned int | NO | N/A | N/A | N/A | **NO-GO** |
| 5 | _KPRIQUEUE | 688 | 688 | LIST_ENTRY Blink | YES | Embedded | Unknown | Maybe | **NO-GO** (wrong bucket) |
| 6 | _DEVICE_NODE | 784 | 800 | _POP_FX_DEVICE* | YES | YES | Unknown | No | NO-GO (wrong bucket) |
| 7 | _POP_FX_COMPONENT | 440 | 448 | _POP_FX_DEVICE* | YES | YES | Unknown | Maybe | NO-GO (wrong bucket) |

---

## 8. Alternative Exploit Strategies

Since no perfect candidate was found at 960/704 with ALL required properties, consider these alternatives:

### Strategy A: Target IRP at Alternative Size

The IRP has the best pointer at offset 0x50 (PKEVENT UserEvent, actively dereferenced on completion). Even though it's zeroed on allocation, use a two-stage approach:

1. Set portcls allocation size to 928 (matches IRP StackSize=10, bucket 944)
2. Allocate portcls at 928, fill with controlled data (fake pointer at 0x50)
3. Free portcls (data remains, no zeroing)
4. Allocate IRP at StackSize=10 (928 bytes, same bucket 944) — IRP zeroes memory
5. IRP's UserEvent at 0x50 is now 0 (zeroed)
6. Set IRP's UserEvent to a controlled event via IoBuildSynchronousFsdRequest
7. Free the IRP (ExFreePoolWithTag, no zeroing — UserEvent value remains in freed slot)
8. Allocate portcls again at 928 — reclaims the freed IRP slot
9. Portcls fills with controlled data, but now we know the exact IRP layout
10. Free portcls again
11. Allocate a new IRP — it reclaims the slot and reads UserEvent from our controlled data

**Problem**: Step 4 zeroes our data. The exploit needs a different approach:
- Use a race between IRP allocation and zeroing (unreliable)
- Use a different object that doesn't zero

### Strategy B: Target KTM at 960

The _KTM struct at exactly 960 bytes is in the correct LFH bucket (976) and has a LIST_ENTRY Blink pointer at offset 0x50. If the KTM allocation:
1. Uses NonPagedPoolNx
2. Does NOT zero the memory
3. Can be triggered from user mode (NtCreateTransactionManager)

Then:
1. Set portcls allocation size to 960
2. Allocate portcls at 960, fill with controlled data (fake Blink pointer at 0x50)
3. Free portcls (data remains)
4. Trigger KTM allocation via NtCreateTransactionManager
5. If KTM doesn't zero: our fake Blink at 0x50 survives
6. When the kernel traverses the KTM namespace balanced link tree, it dereferences our fake Blink
7. Controlled kernel R/W via fake LIST_ENTRY pointer

**Needs verification**: KTM allocation path, pool type, zeroing behavior.

### Strategy C: Target Non-Zeroed Allocation at Alternative Size

Since portcls size is controllable, target any size that matches a non-zeroed allocation with a pointer at 0x50. From the 358 non-zeroed allocations found:

Most promising non-zeroed allocations with potential for pointer at 0x50:
- **Size 208** in `KiIntSteerConnect` — same as IRP base size, not zeroed. Need to check offset 0x50.
- **Size 104** in multiple functions — _ERESOURCE size, offset 0x50 = Reserved2 (PVOID pointer). But 104 is very small (bucket 112).
- **Size 88** in multiple functions — _MMPAGE_FILE_EXPANSION.ActiveEntry (void**), but 88 is tiny (bucket 96).

### Strategy D: Target _DEVICE_NODE at 784

_DEVICE_NODE (784 bytes, bucket 800) has FxDevice (_POP_FX_DEVICE*) at offset 0x50. If the allocation is non-zeroed and user-triggerable (device enumeration), this could work with portcls targeting 784 bytes.

---

## 9. Pool Allocator Zeroing Behavior

From `ExAllocateHeapPool` (RVA 0x1402BC8A0):

The LFH path zeroes allocations conditionally:
```c
v22 = (v7 | pool_descriptor_flags) & 0x93000F0B;
if (v33 && (v22 & 2) != 0) {
    memset(v33, 0, v19);  // zeroing happens here
}
```

Where `v7 = (PoolType >> 9) & 2`. For NonPagedPoolNx (0x200):
- `v7 = (0x200 >> 9) & 2 = 1 & 2 = 0`

This means the allocator's automatic zeroing depends on the **pool descriptor flags**, not the pool type alone. If the pool descriptor doesn't have bit 1 set, the LFH allocation is NOT zeroed by the allocator. The caller must zero explicitly.

This explains why 358 out of 483 NonPagedPoolNx allocations are NOT followed by zeroing — the allocator may not zero them, and the callers don't either.

---

## 10. Final Recommendations

### Primary Target: _KTM at 960 bytes (bucket 976)

- **GO** if KTM allocation can be confirmed as NonPagedPoolNx and non-zeroing
- User-triggerable via NtCreateTransactionManager
- LIST_ENTRY Blink at offset 0x50 is dereferenced during tree traversal
- Portcls allocates at 960, fills with fake Blink, frees, KTM reclaims

### Secondary Target: IRP at 928 bytes (bucket 944)

- PKEVENT UserEvent at offset 0x50 is the best dereferenced pointer
- User-triggerable via any I/O operation
- Requires bypassing the memset zeroing (race condition or two-stage exploit)
- Portcls allocates at 928, IRP StackSize=10 reclaims same bucket

### Tertiary Target: _DEVICE_NODE at 784 bytes (bucket 800)

- FxDevice pointer at offset 0x50
- Need to verify allocation path, zeroing, and user-triggerability

### Investigation Next Steps

1. **Trace KTM allocation**: Follow `NtCreateTransactionManager` → find the actual KTM object allocation. Check if it uses `ExAllocatePoolWithTag(NonPagedPoolNx, 960, tag)` without zeroing.
2. **Check KTM free path**: Verify KTM objects are freed with `ExFreePoolWithTag` (no zeroing).
3. **Verify KTM Blink dereference**: Confirm that the kernel dereferences the Blink at offset 0x50 during normal KTM operations (not just during tree rebalancing).
4. **Check _DEVICE_NODE allocation**: Trace `IoCreateDevice` → device node creation. Check pool type, size, zeroing, and offset 0x50 usage.
5. **Race condition for IRP**: If zeroing can be raced (between ExAllocatePoolWithTag return and memset call), the IRP becomes viable.
6. **Check other kernel modules**: Look at win32kbase.sys, tcpip.sys, and other loaded drivers for NonPagedPoolNx allocations at 945-960 or 689-704 bytes.

---

## Appendix A: IRP Allocation Details

**Function**: `IopAllocateIrpPrivate` at RVA 0x1402D2220

```c
// Size calculation
v10 = 72 * StackSize + 208;  // sizeof(IO_STACK_LOCATION) * StackSize + sizeof(IRP)

// Allocation
result = ExAllocatePoolWithTag(NonPagedPoolNx, v10, 0x20707249);  // tag = 'Irp '

// ALWAYS zeroed
memset((void *)v8, 0, v10);

// IRP header initialization
*(WORD*)v8 = 6;           // Type = IRP_TYPE
*(WORD*)(v8+2) = v10;     // Size
*(BYTE*)(v8+66) = StackSize;
*(BYTE*)(v8+67) = StackSize + 1;
```

**IopLargeIrpStackLocations = 255** (stored at 0x140C4616C)
- As signed char: -1
- Condition `StackSize <= -1` is never true for valid StackSize values
- ALL IRPs bypass lookaside and go through ExAllocatePoolWithTag

## Appendix B: LFH Bucket Table (Complete, from ntoskrnl)

```
Index  Bucket  Index  Bucket  Index  Bucket  Index  Bucket
  0      16     25    400     50    800     75   1728
  1      32     26    416     51    816     76   1792
  2      48     27    432     52    832     77   1856
  3      64     28    448     53    848     78   1920
  4      80     29    464     54    864     79   1984
  5      96     30    480     55    880     80   2048
  6     112     31    496     56    896     81   2176
  7     128     32    512     57    912     82   2304
  8     144     33    528     58    928     83   2432
  9     160     34    544     59    944     84   2560
 10     176     35    560     60    960     85   2688
 11     192     36    576     61    976     86   2816
 12     208     37    592     62    992     87   2944
 13     224     38    608     63   1008     88   3072
 14     240     39    624     64   1024     89   3200
 15     256     40    640     65   1088     90   3328
 16     272     41    656     66   1152     91   3456
 17     288     42    672     67   1216     92   3584
 18     304     43    688     68   1280     93   3712
 19     320     44    704     69   1344     94   3840
 20     336     45    720     70   1408     95   3968
 21     352     46    736     71   1472     96   4096
 22     368     47    752     72   1536
 23     384     48    768     73   1600
 24     400     49    784     74   1664
```

Note: Bucket sizes include 16-byte pool header. User size = bucket_size - 16 (approximately, due to alignment).

## Appendix C: Key Addresses in ntoskrnl

| Symbol | Address | Description |
|--------|---------|-------------|
| ExAllocatePoolWithTag | 0x1409B4160 | Main pool allocation wrapper |
| ExAllocatePool2 | 0x1409B41B0 | New pool allocation API |
| ExAllocateHeapPool | 0x1402BC8A0 | Actual pool allocator |
| ExpAllocatePoolWithTagFromNode | 0x1402BC810 | Node-aware allocator |
| IopAllocateIrpPrivate | 0x1402D2220 | IRP allocation (with memset) |
| RtlpLfhBucketIndexMap | 0x140011C50 | LFH bucket index lookup table |
| RtlpBucketBlockSizes | 0x140012600 | LFH bucket size table |
| IopLargeIrpStackLocations | 0x140C4616C | IRP lookaside threshold (=255/-1) |
| IopMediumIrpStackLocations | 0x140C46168 | IRP medium lookaside threshold (=255/-1) |
