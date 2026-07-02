# ks.sys Deep Overflow / Write-What-Where Analysis

**Date:** 2026-07-02  
**Binary:** ks.sys (Kernel Streaming, Windows x64)  
**IDA Instance:** PID 17220, IDB: `C:\Windows\System32\drivers\ks.sys.i64`  
**Analyst:** ENI (subagent deep-dive)

---

## 1. IDA Instance Confirmation

`ida-pro-mcp_list_instances` confirmed ks.sys loaded at PID 17220, port 13347, backend GUI.

All calls routed with `pid=17220`.

---

## 2. Function Discovery Results

### Property Handler Functions (via `func_query` with `*Property*` and entity_query regex)

| Address | Name | Size (bytes) | Segment |
|---------|------|-------------|---------|
| `0x1c0029ce0` | `KsPropertyHandler` | 33 | PAGE |
| **`0x1c002a0a0`** | **`KspPropertyHandler`** | **2328** | PAGE |
| `0x1c002c830` | `FindPropertyItem` | 31 | PAGE |
| `0x1c002cd60` | `KsPinPropertyHandler` | 33 | PAGE |
| `0x1c002cfa0` | `KspPinPropertyHandler` | 1438 | PAGE |
| `0x1c002dae0` | `KsTopologyPropertyHandler` | 1021 | PAGE |
| `0x1c00451f0` | `KsFastPropertyHandler` | 524 | PAGE |
| `0x1c0045410` | `KsPropertyHandlerWithAllocator` | 45 | PAGE |
| `0x1c0045444` | `SerializePropertySet` | 766 | PAGE |
| `0x1c0045748` | `UnserializePropertySet` | 541 | PAGE |

### Enable Event Functions (via `func_query` with `*Enable*`)

| Address | Name | Size (bytes) | Segment |
|---------|------|-------------|---------|
| `0x1c002b230` | `KsEnableEvent` | 63 | PAGE |
| **`0x1c002b280`** | **`KspEnableEvent`** | **2436** | PAGE |
| `0x1c0042bc0` | `KsEnableEventWithAllocator` | 92 | PAGE |

### Bus Enum Functions (via `func_query` with `*BusEnum*`)

| Address | Name | Size (bytes) | Segment |
|---------|------|-------------|---------|
| **`0x1c0035180`** | **`KsServiceBusEnumCreateRequest`** | **996** | PAGE |
| `0x1c00363c0` | `KsServiceBusEnumPnpRequest` | 2236 | PAGE |
| `0x1c003b580` | `KsIsBusEnumChildDevice` | 39 | PAGE |
| `0x1c003fb00` | `KsCreateBusEnumObject` | 1564 | PAGE |
| `0x1c0040130` | `KsGetBusEnumIdentifier` | 261 | PAGE |
| `0x1c0040270` | `KsInstallBusEnumInterface` | 213 | PAGE |
| `0x1c0040350` | `KsRemoveBusEnumInterface` | 213 | PAGE |
| `0x1c0040430` | `KspInstallBusEnumInterface` | 458 | PAGE |
| `0x1c0040600` | `KspRemoveBusEnumInterface` | 236 | PAGE |

### String Searches (find_regex)

`find_regex` with "Property" returned 5 IoGetDeviceProperty/BCrypt string references only.  
`find_regex` with "EnableEvent" returned 0 matches.  
`find_regex` with "BusEnum" returned 0 matches.  
**Conclusion:** `find_regex` searches string table content, not function names. Function discovery was performed via `func_query` and `entity_query` with regex filters instead.

---

## 3. Decompiled Functions

### 3.1 KspPropertyHandler (`0x1c002a0a0`)

**Prototype:** `NTSTATUS __fastcall KspPropertyHandler(PIRP Irp, unsigned int a2, __int64 a3, __int64 (__fastcall *a4)(_QWORD,_QWORD,_QWORD), unsigned int a5, __int64 a6, unsigned int a7)`

**Parameters (recovered from call sites):**
- `Irp` — the IRP
- `a2` — PropertySetsCount
- `a3` — PropertySet array pointer
- `a4` — Allocator callback (optional, nullptr for default)
- `a5` — unused when no allocator
- `a6` — PropertyItem array (optional)
- `a7` — PropertyItem count

**Allocation Pattern (the core vulnerability surface):**

```
CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
Options = CurrentStackLocation->Parameters.Create.Options;    // InputBufferLength (DeviceIoControl nInBufferSize)
v11 = CurrentStackLocation->Parameters.Read.Length;            // OutputBufferLength (DeviceIoControl nOutBufferSize)
Length = v11;
v12 = (v11 + 7) & 0xFFFFFFF8;                                 // 8-byte align output length
v61 = v12;

// Check: input must be >= 0x18 (24 bytes, KSPROPERTY header)
if (Options < 0x18) return STATUS_INVALID_PARAMETER;

// Overflow check on alignment
if (v12 < v11) return STATUS_INVALID_PARAMETER;

// Total allocation
v14 = v12 + Options;                                           // aligned_output + input_buffer_length

// Overflow check on sum
if (v12 + Options < v12) return STATUS_INVALID_PARAMETER;

// Allocation
Irp->AssociatedIrp.MasterIrp = ExAllocatePoolWithQuotaTag(NonPagedPoolNx, v14, 'KSpp');

// Zero output area
memset(Irp->AssociatedIrp.MasterIrp, 0, v12);

// Copy input after output area
memmove((char*)Irp->AssociatedIrp.MasterIrp + v12, Parameters, Size);

// Write Flags field into buffer at offset aligned_output + 4
*(ULONG*)((char*)&Irp->AssociatedIrp.MasterIrp->Flags + v12 + 4) = OutboundQuota;
```

**Buffer Layout After Allocation:**
```
[ Output Area: v12 bytes (zeroed) ][ Input Area: Options bytes (copied from user) ]
^--- buf                          ^--- buf + v12                        ^--- buf + v14
```

**Key Write at `0x1c002a1c4`:**
```
*(ULONG*)((char*)buf + v12 + 4) = KSPROPERTY.Flags
```
This writes 4 bytes at `buf + aligned_output + 4`, which is bytes 4-7 of the copied input area. The value is the `Flags` field from the user-supplied `KSPROPERTY` header. This is a controlled 4-byte write within the allocation bounds.

**Integer Overflow Analysis (via py_eval):**

| v11 (OutputBufferLength) | aligned (v12) | v12 < v11? | Result |
|--------------------------|---------------|------------|--------|
| 0xFFFFFFF8 | 0xFFFFFFF8 | No (==) | Passes check |
| 0xFFFFFFF9 | 0x00000000 | Yes | Caught |
| 0xFFFFFFFA | 0x00000000 | Yes | Caught |
| 0xFFFFFFFC | 0x00000000 | Yes | Caught |
| 0xFFFFFFFF | 0x00000000 | Yes | Caught |

For `v11=0xFFFFFFF8`: `v14 = 0xFFFFFFF8 + Options`. If `Options=0x18`, `v14 = 0x100000010` wraps to `0x10` (16). The check `v14 < v12` catches this: `0x10 < 0xFFFFFFF8` is true, returns error.

**Conclusion:** Integer overflow in size computation IS checked and caught. The `v12 < v11` and `v12 + Options < v12` checks prevent classic integer overflow exploitation.

**Handler Callback Dispatch:**
The function dispatches to property handler callbacks at multiple points:
- `0x1c002a914`: `v54[1](Irp, v21, v19)` — get handler callback
- `0x1c002a8e3`: `v58(Irp, v21, v19)` — set handler callback  
- `0x1c002a57c`: `v36(Irp, v34, v19)` — support handler callback
- `0x1c002a375`: `v52[7](Irp, v21, v19, v28)` — topology handler callback

These callbacks receive the buffer pointer (`v19 = MasterIrp`). If any callback writes more than `aligned_output` bytes to the output area, it overflows into the input area and potentially past the allocation boundary into adjacent LFH pool objects.

**Sized List Query Path (`0x1c002a967`):**
```c
for (j = (_OWORD **)(-40LL * a2 + v7); a2; --a2) {
    *(_OWORD *)&v19->Type = **j;     // 16-byte write
    v19 = (struct _IRP *)((char*)v19 + 16);
    j += 5;                           // advance 200 bytes in property set array
}
```
Writes `16 * PropertySetsCount` bytes. Bounded by check: `if (v56 >= v59)` where `v59 = 16 * count`. Since `v56 = Length` and `Length <= aligned_output`, this write fits within the output area.

**Property Item Data Path (`0x1c002a70f`):**
```c
for (k = count; k; --k) {
    *(_OWORD*)p_Blink = *(_OWORD*)v49;                    // 16 bytes
    v51 = (char*)(p_Blink + 2);                            // +16
    memmove(v51, *(void**)(v49+16), count_i * size_i);    // variable copy
    p_Blink = (struct _LIST_ENTRY**)&v51[count_i * size_i]; // advance
}
```
Total write = `v40 = 40 + sum(16 + count_i * size_i)`. Bounded by check: `if (Length >= v40)` and `Length <= aligned_output`.

---

### 3.2 KspEnableEvent (`0x1c002b280`)

**Prototype:** `__int64 __fastcall KspEnableEvent(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5, __int64 a6, __int64 (__fastcall *a7)(...), unsigned int a8, __int64 a9, unsigned int a10, char a11)`

**Parameters (recovered from call sites):**
- `a1` — IRP (cast to __int64)
- `a2` — EventSetsCount
- `a3` — EventSet array
- `a4` — EventsList
- `a5` — EventsFlags (KSEVENTS_LOCKTYPE)
- `a6` — EventsLock
- `a7` — Allocator callback (optional)
- `a8` — extra param
- `a9` — PropertyItem array (optional)
- `a10` — PropertyItem count
- `a11` — bool flag (serialized event)

**Allocation Pattern (identical structure to KspPropertyHandler):**

```
v14 = *(_QWORD *)(a1 + 184);                        // IO_STACK_LOCATION
v15 = *(unsigned int *)(v14 + 16);                   // InputBufferLength
v16 = *(_DWORD *)(v14 + 8);                          // OutputBufferLength
Length = v16;
v17 = (v16 + 7) & 0xFFFFFFF8;                        // 8-byte align output

// Check: input >= 0x18
if (v15 < 0x18) return 3221225990;  // STATUS_INVALID_PARAMETER

// Overflow check
if (v17 < v16) return 3221225990;

// Total allocation
v20 = v17 + v15;

// Overflow check on sum  
if ((int)v17 + (int)v15 < (unsigned int)v17) return 3221225990;

// Allocation
*(_QWORD *)(a1 + 24) = ExAllocatePoolWithQuotaTag(NonPagedPoolNx, v20, 'KSpp');

// Zero output area
memset(*(void **)(a1 + 24), 0, v17);

// Copy input after output area
memmove((void*)(v17 + *(_QWORD*)(a1+24)), *(const void**)(v65[0]+32), v15);

// Write Flags into buffer
*(_DWORD *)(v17 + *(_QWORD *)(a1 + 24) + 20) = v21;  // KSEVENT.Flags
```

**Buffer Layout (identical to KspPropertyHandler):**
```
[ Output Area: v17 bytes (zeroed) ][ Input Area: v15 bytes (copied from user) ]
```

**Additional Allocation in Event Entry Path (`0x1c002b71a`):**
```c
v42 = v39 + v36[2];   // v39 = v38 + 120, v38 = optional extra + 24
PoolWithTag = ExAllocatePoolWithTag(NonPagedPoolNx, v42, 'KSe_');
```
This is a second allocation for the event entry structure. Size = `120 + optional_extra + event_data_size`. The `v36[2]` (event data size) comes from the event item descriptor, not directly from user input.

**Event Entry Population (`0x1c002b73c`-`0x1c002b7e6`):**
The event entry is populated with multiple pointer fields:
- `+0x00`: callback function pointer (`v36[3]`)
- `+0x08`: 16 bytes of event GUID (from input)
- `+0x18`: 8 more bytes (event GUID continued)
- `+0x30`: event object pointer (from `ObReferenceObjectByHandle`)
- `+0x40`: input buffer first DWORD (event type)
- `+0x48`: event set pointer (`a3`)
- `+0x50`: event item pointer (`v36`)
- `+0x58`: additional context pointer
- `+0x60-0x6C`: zeroed / type-specific fields

**If `a11` (serialized flag) is set:**
```c
v49 = &v44[(v36[2] + 127) & ~7];  // aligned offset past event data
*(_OWORD*)v49 = *(_OWORD*)a3;     // copy event set descriptor (16 bytes)
*((_QWORD*)v49 + 2) = *(_QWORD*)(a3 + 16);  // copy event set pointer
memmove(v49 + 24, v36, Lengtha);  // copy event item descriptor
*((_QWORD*)v44 + 10) = v49;       // store pointer
*((_QWORD*)v44 + 11) = v49 + 24;  // store pointer
```
This copies the event item descriptor into the tail of the allocation. If `v36[2]` (event data size) is crafted to cause misalignment, the `memmove(v49 + 24, v36, Lengtha)` could write past the allocation. However, `v42 = v39 + v36[2]` accounts for this in the allocation size.

---

### 3.3 KsServiceBusEnumCreateRequest (`0x1c0035180`)

**Prototype:** `NTSTATUS __stdcall KsServiceBusEnumCreateRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)`

**Analysis:**
This is a PnP IRP_MJ_CREATE dispatch handler for bus enumerator devices. It:
1. Acquires a fast mutex on the device extension
2. Walks a linked list of child device entries
3. Uses `_wcsnicmp` to match the requested file name against child device reference strings
4. If matched, either issues a reparse or creates a PDO via `CreatePdo`
5. Queues the IRP on a list and returns STATUS_PENDING

**No user-controlled allocation sizes.** The function does not allocate buffers based on user-supplied sizes. It operates on kernel-internal device extension structures and list entries.

**Callers:** Only a data reference at `0x1c0022b60` (dispatch table entry for IRP_MJ_CREATE).

---

## 4. LFH Bucket 1024 Analysis (via py_eval)

### Calculation

```
alloc_size = aligned_output + input_buffer_length
aligned_output = (OutputBufferLength + 7) & ~7   (8-byte alignment)
input_buffer_length >= 24 (0x18, KSPROPERTY/KSEVENT header minimum)
LFH bucket 1024 covers sizes 1009-1024
```

### Results

**Total valid (aligned_output, input_length) combinations: 1994**

#### Scenario A: Maximum output area, minimal input (24 bytes)

| OutputBufferLength | aligned_output | input_length | total_alloc |
|---------------------|---------------|-------------|-------------|
| 1000 | 1000 | 24 | 1024 |

Only one combination. `OutputBufferLength=1000`, `aligned=1000`, `input=24`, `total=1024`.

#### Scenario B: Zero/minimal output, maximum input

| OutputBufferLength | aligned_output | input_length | total_alloc |
|---------------------|---------------|-------------|-------------|
| 0-7 | 0 | 1009-1024 | 1009-1024 |

16 combinations. Output area is 0 bytes, entire allocation is input data.

#### Scenario C: Balanced split hitting exactly 1024

All combinations where `aligned_output + input_length = 1024` and `input_length >= 24`:

- `aligned=0, input=1024` (out_len 0-7)
- `aligned=8, input=1016` (out_len 8-15)
- `aligned=16, input=1008` (out_len 16-23)
- ...
- `aligned=1000, input=24` (out_len 1000-1007)

Total: 126 exact-1024 combinations.

### Practical Exploitation Values

**Best overflow target:** `OutputBufferLength=1000, InputBufferLength=24, alloc=1024`
- Output area: 1000 bytes (maximum in 1024 bucket)
- Input area: 24 bytes (minimum, just KSPROPERTY header)
- Any handler callback writing >1000 bytes overflows 24 bytes into the input area
- If the handler writes >1024 bytes total, it overflows into the next LFH bucket object

**Best heap spray target:** `OutputBufferLength=0, InputBufferLength=1024, alloc=1024`
- Output area: 0 bytes
- Input area: 1024 bytes (entire allocation is attacker-controlled data)
- No output handler will be called (buffer too small for most paths)
- Useful for filling LFH bucket 1024 with controlled data

**Best write-what-where target:** `OutputBufferLength=504, InputBufferLength=512, alloc=1016`
- Balanced split, output area = 504 bytes
- Input area = 512 bytes of fully controlled data
- The Flags overwrite at `buf+504+4` writes attacker-controlled 4 bytes
- Handler callbacks that write to output area can be steered to overflow

---

## 5. User-Mode Reachability Analysis

### KspPropertyHandler — **USER-MODE REACHABLE**

**Call chain:**
```
User mode: DeviceIoControl(hKsDevice, IOCTL_KS_PROPERTY (0x2F0003), ...)
  -> KspHandleAutomationIoControl (case 0x2F0003)
    -> KspPropertyHandler(Irp, setsCount, setArray, nullptr, 0, 0, 0)
```

Also reachable via:
- `KsPropertyHandler` (direct export, wraps to `KspPropertyHandler`)
- `KsPropertyHandlerWithAllocator` (export with allocator)
- `DefAllocatorIoControl` (default allocator path)
- `DefClockIoControl` (clock property path)

**IOCTL:** `IOCTL_KS_PROPERTY = 0x2F0003` (METHOD_NEITHER, FILE_DEVICE_KS = 0x2F)

Any user-mode process that can open a handle to a KS device (webcam, microphone, audio adapter, DVD, etc.) can send this IOCTL via `DeviceIoControl`. The `Irp->RequestorMode` check at `0x1c002a110` confirms user-mode requests are handled (ProbeForRead is called for user-mode).

### KspEnableEvent — **USER-MODE REACHABLE**

**Call chain:**
```
User mode: DeviceIoControl(hKsDevice, IOCTL_KS_ENABLE_EVENT (0x2F0007), ...)
  -> KspHandleAutomationIoControl (case 0x2F0007)
    -> KspEnableEvent(Irp, setsCount, setArray, eventsList, 1, eventsLock, nullptr, 0, 0, 0, 1)
```

Also reachable via:
- `KsEnableEvent` (direct export)
- `KsEnableEventWithAllocator` (export with allocator)
- `DefAllocatorIoControl`
- `DefClockIoControl`

**IOCTL:** `IOCTL_KS_ENABLE_EVENT = 0x2F0007`

Same user-mode access requirements as property handler.

### KsServiceBusEnumCreateRequest — **NOT DIRECTLY USER-MODE REACHABLE VIA IOCTL**

This function is an IRP_MJ_CREATE handler for bus enumerator child devices. It is reached via the PnP manager's create dispatch, not via a user-mode DeviceIoControl call. While user-mode can trigger IRP_MJ_CREATE by opening a device file handle, the function does not process user-controlled buffer sizes or perform allocations based on user input.

**Verdict:** Not exploitable via the same allocation-size-control vector as the property/event handlers.

---

## 6. Overflow and Write-What-Where Assessment

### KspPropertyHandler

| Question | Answer |
|----------|--------|
| User-mode reachable? | **YES** — via IOCTL_KS_PROPERTY (0x2F0003) |
| Can we control allocation size? | **YES** — `alloc = align(OutputBufferLength) + InputBufferLength` |
| Can we overflow the allocation? | **INDIRECT** — integer overflow is checked; handler callbacks may overflow |
| Are there pointer fields that get written through? | **YES** — handler callbacks receive buffer pointer; sized list query writes 16-byte GUIDs |

**Overflow vectors:**
1. **Handler callback overflow:** Property handler callbacks (`v54[1]`, `v58`, `v36`, `v52[7]`) receive the allocated buffer pointer. If a handler writes more than `aligned_output` bytes, it overflows into the input area and potentially past the allocation.
2. **Flags field overwrite:** At `0x1c002a1c4`, `*(ULONG*)(buf + aligned_output + 4) = KSPROPERTY.Flags`. This is a controlled 4-byte write at a known offset within the buffer. Not an overflow by itself but can corrupt data in the input area.
3. **Sized list query:** Writes `16 * PropertySetsCount` bytes. Bounded by output length check. Safe.
4. **Property item data copy:** Writes variable-length sub-item data. Bounded by output length check. Safe.
5. **Integer overflow in size computation:** Checked and caught by `v12 < v11` and `v12 + Options < v12` guards. Safe.

### KspEnableEvent

| Question | Answer |
|----------|--------|
| User-mode reachable? | **YES** — via IOCTL_KS_ENABLE_EVENT (0x2F0007) |
| Can we control allocation size? | **YES** — `alloc = align(OutputBufferLength) + InputBufferLength` (identical pattern) |
| Can we overflow the allocation? | **INDIRECT** — same as KspPropertyHandler; event add callback may overflow |
| Are there pointer fields that get written through? | **YES** — event entry contains function pointers, object pointers, set/item pointers |

**Overflow vectors:**
1. **Same allocation pattern as KspPropertyHandler:** Identical `aligned_output + input_length` allocation with same checks.
2. **Event entry allocation:** Second allocation at `0x1c002b71a` for event entry structure (`ExAllocatePoolWithTag` with tag `'KSe_'`). Size includes `120 + optional_extra + event_data_size`. The event data size comes from the event item descriptor, not directly user-controlled.
3. **Serialized event copy:** When `a11=1`, copies event item descriptor into tail of event entry allocation. Size is accounted for in allocation.
4. **Event add callback:** The `v36[2]` callback (`0x1c002b94f`) receives the IRP, input buffer, and event entry. If this callback writes past the event entry allocation, overflow occurs.
5. **Object reference writes:** `ObReferenceObjectByHandle` stores object pointers at `PoolWithTag + 48`. These are kernel object pointers, not user-controlled values.

### KsServiceBusEnumCreateRequest

| Question | Answer |
|----------|--------|
| User-mode reachable? | **NO** — PnP create dispatch, no user-controlled buffers |
| Can we control allocation size? | **NO** — no user-controlled allocation sizes |
| Can we overflow the allocation? | **NO** — no allocations from user input |
| Are there pointer fields that get written through? | **NO** — operates on internal device extension structures |

---

## 7. LFH Bucket 1024 — Detailed Math (py_eval output)

```
LFH bucket 1024 target range: 1009-1024
Total valid combinations: 1994

Key combinations:
  aligned_out=1000, input_len=24,  total=1024  (max output, min input)
  aligned_out=0,    input_len=1024, total=1024 (zero output, max input)
  aligned_out=504,  input_len=512,  total=1016 (balanced split)
  aligned_out=992,  input_len=24,   total=1016 (near-max output)
```

**Integer overflow check results:**
```
v11=0xFFFFFFF8 -> aligned=0xFFFFFFF8, v12==v11, passes alignment check
  BUT v14 = 0xFFFFFFF8 + Options wraps, caught by sum overflow check
v11=0xFFFFFFF9 -> aligned=0x00000000, v12 < v11, CAUGHT
All other large values: CAUGHT by alignment check
```

**Conclusion:** Integer overflow is properly guarded. The exploitable surface is LFH bucket manipulation + handler callback overflows, not integer overflow.

---

## 8. Summary of Findings

### Primary Vulnerability: Attacker-Controlled Pool Allocation Size

Both `KspPropertyHandler` and `KspEnableEvent` allocate NonPagedPoolNx buffers with sizes fully controlled by the user via `DeviceIoControl` parameters:
- `OutputBufferLength` (nOutBufferSize) controls the output area size (zeroed)
- `InputBufferLength` (nInBufferSize) controls the input area size (copied from user)

The allocation is `align8(OutputBufferLength) + InputBufferLength`, with:
- Minimum input: 24 bytes (KSPROPERTY/KSEVENT header)
- Integer overflow checks present and effective
- Pool tag: `'KSpp'` (0x7070534B)

### Exploitation Strategy

1. **LFH Bucket Targeting:** Choose `OutputBufferLength` and `InputBufferLength` to hit LFH bucket 1024 (sizes 1009-1024). 1994 valid combinations exist.

2. **Heap Feng Shui:** Spray the 1024 bucket with controlled allocations to position target objects adjacent to the KS buffer. Use `OutputBufferLength=0, InputBufferLength=1024` to fill the bucket with attacker-controlled data.

3. **Handler Callback Overflow:** Trigger a property handler that writes more than `aligned_output` bytes to the output area. With `OutputBufferLength=1000`, any handler writing >1000 bytes overflows 24 bytes into adjacent pool memory.

4. **Write-What-Where via Flags:** The `*(ULONG*)(buf + aligned_output + 4) = Flags` write at `0x1c002a1c4` (KspPropertyHandler) and `0x1c002b37c` (KspEnableEvent) is a controlled 4-byte write at a predictable offset. While within bounds, it corrupts the copied input data, which may be used by subsequent handler callbacks as pointer fields.

5. **Event Entry Pointer Fields:** In KspEnableEvent, the event entry structure at `buf + 32` contains:
   - Function pointer at `+0x00` (callback from event item)
   - Object pointer at `+0x30` (from ObReferenceObjectByHandle)
   - Event set pointer at `+0x48`
   - Event item pointer at `+0x50`
   If an overflow corrupts these fields in an adjacent event entry, subsequent event triggering would call through corrupted function pointers or dereference corrupted object pointers.

### Secondary Finding: KsServiceBusEnumCreateRequest

Not exploitable via the allocation-size-control vector. It is a PnP create handler with no user-controlled buffer allocations. Its only reference is a data xref at `0x1c0022b60` (IRP_MJ_CREATE dispatch table).

---

## 9. Key Addresses

| Address | Function | Significance |
|---------|----------|-------------|
| `0x1c002a0a0` | KspPropertyHandler | Main property handler, alloc + dispatch |
| `0x1c002a191` | KspPropertyHandler+0xF1 | ExAllocatePoolWithQuotaTag call |
| `0x1c002a1a6` | KspPropertyHandler+0x106 | memset output area to zero |
| `0x1c002a1bb` | KspPropertyHandler+0x11B | memmove input to buf+aligned_output |
| `0x1c002a1c4` | KspPropertyHandler+0x124 | **ULONG Flags write at buf+aligned_output+4** |
| `0x1c002a914` | KspPropertyHandler+0x874 | GET handler callback dispatch |
| `0x1c002a8e3` | KspPropertyHandler+0x843 | SET handler callback dispatch |
| `0x1c002a57c` | KspPropertyHandler+0x5DC | Support handler callback dispatch |
| `0x1c002a967` | KspPropertyHandler+0x8C7 | Sized list query 16-byte writes |
| `0x1c002a70f` | KspPropertyHandler+0x66F | Property item data memmove |
| `0x1c002b280` | KspEnableEvent | Main event enable handler |
| `0x1c002b346` | KspEnableEvent+0xC6 | ExAllocatePoolWithQuotaTag call |
| `0x1c002b35a` | KspEnableEvent+0xDA | memset output area to zero |
| `0x1c002b373` | KspEnableEvent+0xF3 | memmove input to buf+aligned_output |
| `0x1c002b37c` | KspEnableEvent+0xFC | **ULONG Flags write at buf+aligned_output+20** |
| `0x1c002b71a` | KspEnableEvent+0x49A | Event entry ExAllocatePoolWithTag |
| `0x1c002b94f` | KspEnableEvent+0x6CF | Event add callback dispatch |
| `0x1c0035180` | KsServiceBusEnumCreateRequest | PnP create dispatch (no user alloc) |

---

*Analysis complete. All math performed via IDA Pro py_eval. No builds executed.*
