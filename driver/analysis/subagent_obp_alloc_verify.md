# ObpAllocateObject Verification: KTM vs portcls LFH Bucket Analysis

## Executive Summary

**portcls (960 bytes, LFH bucket 976) CANNOT reclaim KTM object slots.**

ObpAllocateObject allocates `total_header_size + ObjectBodySize` via ExAllocatePoolWithTag. Even with the absolute minimum 48-byte OBJECT_HEADER, a 960-byte KTM object body yields a 1008-byte allocation (pool bucket 1024), which is a different LFH bucket than portcls at 976. The exploit approach requires redesign.

---

## 1. ObpAllocateObject Found

- **Function**: `ObpAllocateObject` at `0x14064c950` (size 0x3C0 = 960 bytes)
- **Binary**: `ntoskrnl.exe` (PID 8428, port 13346)
- **IDB**: `C:\Users\ruar1337\Desktop\ntoskrnl.exe.i64`

## 2. Decompiled ObpAllocateObject - Critical Allocation Path

The ExAllocatePoolWithTag call is at `0x14064cb1f`:

```c
// Header size computation (v26 = total optional headers + OBJECT_HEADER)
v25 = v23 + v11 + v13 + (v16 != 0 ? 0x10 : 0) + (v22 != 0 ? 0x20 : 0)
      + (v37 != 0 ? 0x10 : 0) + v24;
v26 = v25 + v21 + v20;

// CRITICAL: overflow check before allocation
if ( v26 + a5 < v26 )
    return STATUS_INVALID_PARAMETER;  // 0xC000000D

// THE ALLOCATION: size = v26 + a5 = HEADER + BODY
PoolWithTag = (char *)ExAllocatePoolWithTag(
    (POOL_TYPE)(*(_DWORD *)(a3 + 100) | 0x400),  // PoolType from ObjectType
    v26 + a5,                                      // *** SIZE = HEADER + BODY ***
    *(_DWORD *)(a3 + 192));                        // PoolTag from ObjectType
```

### Assembly Confirmation (0x14064caf8 - 0x14064cb1f)

```asm
mov eax, [rsp+78h+arg_20]    ; eax = a5 = ObjectBodySize
add eax, ecx                  ; eax = ObjectBodySize + v26 (total header)
cmp eax, ecx                  ; overflow check
jnb loc_14064CB0F
...
loc_14064CB0F:
mov ecx, [rdi+64h]            ; PoolType from ObjectType (+100)
mov r8d, [rdi+0C0h]           ; PoolTag from ObjectType (+192)
bts ecx, 0Ah                  ; set POOL_FLAG_UNINITIALIZED (bit 10)
mov edx, eax                  ; edx = v26 + ObjectBodySize = TOTAL SIZE
call ExAllocatePoolWithTag    ; *** ALLOCATES HEADER + BODY ***
```

**The size parameter is `v26 + a5` where v26 is the computed total header size and a5 is the ObjectBodySize. This is definitively HEADER + BODY, not BODY alone.**

## 3. OBJECT_HEADER Size = 48 bytes (0x30) on This Build

### Proof 1: ObCreateObjectEx Return Value

```asm
; At 0x140651fc3 in ObCreateObjectEx:
lea rcx, [rbx+30h]    ; Object body = ObjectHeader + 0x30 (48 bytes)
mov [rax], rcx         ; *Object = ObjectHeader + 48
```

The caller receives `ObjectHeader + 48` as the object body pointer. This means OBJECT_HEADER occupies 48 bytes.

### Proof 2: ObpAllocateObject Base Header Size

```asm
; At 0x14064cad1 in ObpAllocateObject:
mov eax, 30h           ; eax = 48 (0x30)
mov ebp, 40h           ; ebp = 64 (0x40)
cmovz ebp, eax         ; if no audit required, ebp = 48
```

- `v24 = 48` when `SeAuditHeaderRequired` returns FALSE (no audit)
- `v24 = 64` when audit is required (16 extra bytes for audit header)

### OBJECT_HEADER Layout (48 bytes / 0x30 on this build)

```
+0x00  PointerCount           (QWORD, 8 bytes)  - set to 1
+0x08  HandleCount            (QWORD, 8 bytes)  - set to 0
+0x10  Lock                   (QWORD, 8 bytes)  - set to 0 (EX_PUSH_LOCK)
+0x18  TypeIndex              (BYTE, 1 byte)    - ObHeaderCookie ^ ObjectType->TypeIndex ^ ...
+0x19  TraceFlags             (BYTE, 1 byte)    - set to 0
+0x1A  InfoMask               (BYTE, 1 byte)    - bitmask for optional headers
+0x1B  Flags                  (BYTE, 1 byte)    - object flags
+0x1C  Reserved               (DWORD, 4 bytes)  - padding
+0x20  ObjectCreateInfo       (QWORD, 8 bytes)  - pointer to OBJECT_CREATE_INFO
+0x28  SecurityDescriptor/0   (QWORD, 8 bytes)  - set to 0 initially
= 0x30 = 48 bytes total
```

### Note on LO's 56-byte Assumption

LO assumed OBJECT_HEADER = 56 bytes. This was likely based on pre-Windows 10 1607 layouts where the header included `NameInfoOffset`, `HandleInfoOffset`, and `QuotaInfoOffset` fields (8 additional bytes, total 56). In Windows 10 1607+ and Windows 11, these offset fields were removed and replaced by the `InfoMask` bitfield at +0x1A, reducing the header to 48 bytes. **However, the conclusion remains the same regardless of whether the header is 48 or 56 bytes.**

## 4. Optional Header Components in ObpAllocateObject

The total header size `v26` is computed as:

| Component | Variable | Size | Condition |
|-----------|----------|------|-----------|
| OBJECT_HEADER base | v24 | 48 or 64 | 64 if SeAuditHeaderRequired |
| Creator info | v21 | 0 or 48 | ObjectType flags bit 7 set |
| Name info struct | v20 | 0 or 48 | Object has a name |
| Name capture | v23 | 0 or 16 | a7 (name buffer) provided |
| Name info | v11 | 0 or 32 | Object has name (v10 non-zero) |
| Process quota | v13 | 0 or 32 | Calling thread NOT in system process |
| Handle info | v16 | 0 or 16 | ObjectType flags & 0x10 |
| Process info | v22 | 0 or 32 | ObjectType flags & 0x20 |
| Exclusive/audit | v37 | 0 or 16 | ObjectAttributes & 0x20 (OBJ_EXCLUSIVE) |

### Minimum Header (unnamed, system process, no audit, no special flags)

```
v23=0 + v11=0 + v13=0 + 0 + 0 + 0 + v24=48 = v25=48
v26 = 48 + v21=0 + v20=0 = 48
```

### Typical User-Mode Named Object (non-system process, named, with audit)

```
v23=16 + v11=32 + v13=32 + 0 + 0 + 0 + v24=64 = v25=144
v26 = 144 + v21=0 + v20=48 = 192
```

## 5. ObCreateObject and ObCreateObjectEx Call Chain

### ObCreateObject (0x1407022d0) - Thin Wrapper

```c
__int64 __fastcall ObCreateObject(int a1, int a2, int a3, char a4)
{
    return ObCreateObjectEx(a1, a2, a3, a4);  // direct tail call
}
```

### ObCreateObjectEx (0x140651ea0) - Full Implementation

Key flow:
1. Pops OBJECT_CREATE_INFO from PPLookasideList[4] lookaside list (or allocates if empty)
2. Calls `ObpCaptureObjectCreateInformation` to fill in CreateInfo
3. Calls `ObpAllocateObject(CreateInfo, PreviousMode, ObjectType, CapturedInfo, ObjectBodySize, &ObjectHeader, NameInfo)`
4. ObpAllocateObject allocates via ExAllocatePoolWithTag(HEADER + BODY)
5. Returns `ObjectHeader + 48` as the object body pointer

```c
// The call at 0x140651f97:
Object = ObpAllocateObject(
    (_DWORD)v16,          // CreateInfo
    a4,                   // PreviousMode
    (_DWORD)a2,           // ObjectType
    (unsigned int)&v35,   // Captured info (security/name)
    a6,                   // *** ObjectBodySize ***
    (__int64)&a5,         // output: ObjectHeader pointer
    v34);                 // name info

// Return the object body (header + 48):
*a9 = v22 + 48;  // v22 = ObjectHeader, +48 = sizeof(OBJECT_HEADER)
```

### Lookaside List is for CreateInfo, NOT for Objects

PPLookasideList[4] caches OBJECT_CREATE_INFO buffers, not object allocations. The object itself is ALWAYS allocated by ExAllocatePoolWithTag inside ObpAllocateObject. There is no per-object-type lookaside bypass.

## 6. OBJECT_TYPE TotalSizeOfObject Field - Does NOT Exist

### ObCreateObjectTypeEx (0x1407906a0) Analysis

The OBJECT_TYPE is allocated with body size 216 bytes:
```c
Object = ObpAllocateObject(v57, 0, (__int64)v15, &DestinationString_8, 216, (char **)Size, nullptr);
```

Fields written to OBJECT_TYPE in ObCreateObjectTypeEx:
- +0x20: DefaultObject pointer
- +0x28: TypeIndex (byte)
- +0x2C: TotalNumberOfObjects
- +0x34: HighWaterNumberOfObjects
- +0x40-0xB7: OBJECT_TYPE_INITIALIZER (120 bytes copied from caller)
- +0x64: PoolType
- +0x68/0x6C: PagedPoolCharge / NonPagedPoolCharge
- +0x98: SecurityDescriptor procedure
- +0xC0: PoolTag
- +0xC8: LIST_ENTRY

**No TotalSizeOfObject field exists in OBJECT_TYPE on this build.** The ObjectBodySize is passed as a parameter to ObCreateObject/ObCreateObjectEx by the caller (KTM module) each time an object is created.

### Fields Accessed by ObpAllocateObject from OBJECT_TYPE

| Offset | Field | Usage |
|--------|-------|-------|
| +0x28 (40) | TypeIndex | BYTE, used for ObHeaderCookie XOR |
| +0x2C (44) | TotalNumberOfObjects | InterlockedIncrement |
| +0x34 (52) | HighWaterNumberOfObjects | Updated if count exceeds |
| +0x42 (66) | ObjectTypeFlags | BYTE, controls optional header allocation |
| +0x64 (100) | PoolType | ULONG, pool type for ExAllocatePoolWithTag |
| +0xC0 (192) | PoolTag | ULONG, tag for ExAllocatePoolWithTag |

## 7. KTM Object Types

KTM object types are global pointers in ntoskrnl.exe, initialized at boot via `TmInitSystem`:

```c
// In Phase1InitializationDiscard at 0x140a3b3d3:
inited = TmInitSystem(
    &TmResourceManagerObjectType,    // 0x140cfcb20
    &TmEnlistmentObjectType,         // 0x140cfcc60
    &TmTransactionManagerObjectType, // 0x140cfcb18
    &TmTransactionObjectType);       // 0x140cfc790
```

The actual KTM implementation (including ObCreateObject calls with ObjectBodySize) is in the KTM module (`tm.sys`), accessed through API set `api-ms-win-ntos-tm-l1-1-0`. The ObjectBodySize of 960 bytes for KTM TransactionManager objects comes from the KTM module's call to ObCreateObject, which we cannot directly verify from the ntoskrnl.exe IDB since the KTM globals are zeroed in the static image.

However, the allocation path through ObpAllocateObject is definitive: regardless of what ObjectBodySize the KTM module passes, the total ExAllocatePoolWithTag size will be `header_size + ObjectBodySize`.

## 8. LFH Bucket Computation

### Windows 10/11 x64 Kernel Pool LFH Bucket Scheme

- POOL_HEADER = 16 bytes (prepended by pool allocator)
- Up to 1024 bytes total (alloc + header): **16-byte granularity**
- 1024 to 4096 bytes total: **64-byte granularity**
- Above 4096: 128-byte granularity

### Computed Buckets (using ida-pro-mcp_py_eval)

| Scenario | Header | Body | Alloc Size | + Pool Header | LFH Bucket |
|----------|--------|------|------------|---------------|------------|
| portcls (960 bytes, direct pool) | 0 | 960 | 960 | 976 | **976** |
| KTM min (48B header, no optional) | 48 | 960 | 1008 | 1024 | **1024** |
| KTM (56B header, LO's assumption) | 56 | 960 | 1016 | 1032 | **1088** |
| KTM with audit (64B base header) | 64 | 960 | 1024 | 1040 | **1088** |
| KTM user-mode named (176B header) | 176 | 960 | 1136 | 1152 | **1152** |

### Reclamation Analysis

| KTM Scenario | KTM Bucket | portcls Bucket | Can Reclaim? |
|--------------|------------|----------------|---------------|
| KTM min (48B header) | 1024 | 976 | **NO** |
| KTM (56B header) | 1088 | 976 | **NO** |
| KTM with audit | 1088 | 976 | **NO** |
| KTM user-mode named | 1152 | 976 | **NO** |

**In ALL scenarios, the KTM LFH bucket is different from the portcls LFH bucket (976). portcls at 960 bytes CANNOT reclaim KTM object slots.**

## 9. Exploit Redesign Options

Since portcls (960 bytes, bucket 976) cannot reclaim KTM slots, the exploit needs one of:

### Option A: Match the KTM bucket
Find a vulnerable object that allocates at exactly 1008 bytes (48B header + 960B body = 1008, pool total 1024, bucket 1024). This requires a different vulnerable driver/object, not portcls at 960.

### Option B: Match a different KTM object body size
If a different KTM object type (Transaction, ResourceManager, Enlistment) has a body size B such that `48 + B + 16 = 976`, then `B = 912`. Check if any KTM object type has a 912-byte body.

With LO's 56-byte header: `56 + B + 16 = 976` → `B = 904`.

### Option C: Find a portcls allocation at 1008 bytes
If portcls has a different vulnerable allocation path that requests 1008 bytes (pool bucket 1024), it could reclaim KTM minimum slots.

### Option D: Use a non-object pool allocation for reclamation
Instead of using another kernel object, find a controllable ExAllocatePoolWithTag call (in any driver) that allocates exactly 1008 bytes (or 1024 including header) to reclaim KTM slots.

## 10. Verification Summary

| Question | Answer |
|----------|--------|
| Does ObpAllocateObject alloc header+body or just body? | **HEADER + BODY** (v26 + a5) |
| What is ExAllocatePoolWithTag size parameter? | `v26 + a5` = total_header_size + ObjectBodySize |
| Does it use ObjectType->TotalSizeOfObject? | **No** - field does not exist on this build |
| What is OBJECT_HEADER size on this build? | **48 bytes (0x30)** - confirmed by two independent proofs |
| What was LO's 56-byte assumption? | Pre-Win10 1607 layout with offset fields (now removed) |
| Minimum KTM alloc for 960-byte body? | **1008 bytes** (48 + 960) |
| KTM LFH bucket (minimum)? | **1024** (1008 + 16 pool header) |
| portcls LFH bucket? | **976** (960 + 16 pool header) |
| Can portcls reclaim KTM slots? | **NO** - 976 != 1024 |

## References

- `ObpAllocateObject`: `ntoskrnl.exe:0x14064c950`
- `ObCreateObject`: `ntoskrnl.exe:0x1407022d0` (thin wrapper)
- `ObCreateObjectEx`: `ntoskrnl.exe:0x140651ea0`
- `ObCreateObjectTypeEx`: `ntoskrnl.exe:0x1407906a0`
- `ExAllocatePoolWithTag` call: `ntoskrnl.exe:0x14064cb1f`
- Object body return (`lea rcx,[rbx+30h]`): `ntoskrnl.exe:0x140651fc3`
- Header size v24=48 (`mov eax,30h`): `ntoskrnl.exe:0x14064cad1`
- KTM type init (`TmInitSystem`): `ntoskrnl.exe:0x140a3b3d3`
- TmTransactionManagerObjectType: `ntoskrnl.exe:0x140cfcb18`
- TmTransactionObjectType: `ntoskrnl.exe:0x140cfc790`
- TmResourceManagerObjectType: `ntoskrnl.exe:0x140cfcb20`
- TmEnlistmentObjectType: `ntoskrnl.exe:0x140cfcc60`
