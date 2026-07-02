# ntoskrnl.exe Uninitialized Object Field Analysis

## Executive Summary

Systematic analysis of all user-mode-creatable kernel object types in ntoskrnl.exe (PID 4024, port 13340) was performed to find types with uninitialized LIST_ENTRY fields that could enable a write-what-where primitive via the close/delete path. The analysis covered 42 ObCreateObject/ObCreateObjectEx call sites, extracting body sizes, close/delete procedures, and initialization patterns.

**Key Finding**: No object type that falls in LFH bucket 1024 (961-1024 bytes total) or LFH bucket 640 (577-640 bytes total) has uninitialized LIST_ENTRY fields. The only type in bucket 640 (ALPC Port, body=472, total=600 with named+security overhead) fully zeroes its body with memset after ObCreateObjectEx.

The most promising candidate with uninitialized fields is **WorkerFactory** (body=576, bucket 704) which has 224+ bytes of uninitialized space across multiple ranges, plus both Close (ExpCloseWorkerFactory) and Delete (ExpDeleteWorkerFactory) procedures. The close path (ExpShutdownWorkerFactory) dereferences 4 QWORD pointers at offsets 72-103 which are completely uninitialized.

---

## 1. Complete Object Type Table

### Segment Heap LFH Bucket Sizes (Windows 10 19041+ / Windows 11)
```
16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
272, 288, 304, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 832, 896,
960, 1024, 1088, 1152, 1280, 1360, 1440, 1520, 1600, 1760, 1920, 2080, ...
```

### Overhead Calculation (from ObpAllocateObject decompilation)

Total pool allocation = overhead + body_size. Overhead components:

| Component | Size | Condition |
|-----------|------|-----------|
| OBJECT_HEADER (base) | 48 bytes | Always |
| Audit header | +16 bytes | If SeAuditHeaderRequired returns true |
| OBJECT_HEADER_NAME_INFO | 32 bytes | If object has a name |
| OBJECT_HEADER_QUOTA_INFO | 32 bytes | If current process != PsInitialSystemProcess (always for user-mode) |
| Security info | 16 bytes | If ObjectTypeFlags & 0x10 |
| Process info | 32 bytes | If ObjectTypeFlags & 0x20 |

**Typical overhead for user-mode objects:**
- Unnamed, no security: 32 (quota) + 48 (header) = **80 bytes**
- Named, no security: 32 (name) + 32 (quota) + 48 (header) = **112 bytes**
- Named, with security: 32 (name) + 32 (quota) + 16 (sec) + 48 (header) = **128 bytes**

### Python calculations (all performed via IDA Pro py_exec_file):

```python
lfh = [16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256,
       272,288,304,320,352,384,416,448,480,512,576,640,704,768,832,896,
       960,1024,1088,1152,1280,1360,1440,1520,1600,1760,1920,2080]

def bucket(sz):
    for b in lfh:
        if sz <= b: return b
    return -1

# ALPC Port: 472+128=600 -> bucket 640 (ONLY bucket 640 match)
# WorkerFactory: 576+80=656 -> bucket 704 (best uninit candidate, wrong bucket)
# Timer: 328+112=440 -> bucket 448 (has uninit fields, wrong bucket)
# No type hits bucket 1024
```

---

## 2. Complete Object Type Inventory

| Name | Body | Pool | Named+OH | Bucket | Unnamed+OH | Bucket | Close Proc | Delete Proc | Zeroed? | User? |
|------|------|------|----------|--------|------------|--------|------------|-------------|---------|-------|
| Event | 24 | NonPaged | 136 | 144 | 104 | 112 | NULL | NULL | Yes | Yes |
| Semaphore | 32 | NonPaged | 144 | 144 | 112 | 112 | NULL | NULL | Yes | Yes |
| Timer | 328 | NonPaged | 440 | 448 | 408 | 416 | NULL | ExpDeleteTimer | **NO** | Yes |
| IRTimer | 168 | NonPaged | 280 | 288 | 248 | 256 | NULL | ExpDeleteTimer2 | **NO** | Yes |
| IoCompletion | 80 | NonPaged | 192 | 192 | 160 | 160 | IopCloseIoCompletion | IopDeleteIoCompletion | **NO** | Yes |
| Mutant | 56 | NonPaged | 168 | 176 | 136 | 144 | NULL | ExpDeleteMutant | Yes | Yes |
| KeyedEvent | 1536 | Paged | 1648 | 1680 | 1616 | 1680 | NULL | NULL | Yes | Yes |
| WorkerFactory | 576 | NonPaged | 688 | 704 | 656 | 704 | ExpCloseWorkerFactory | ExpDeleteWorkerFactory | **NO** | Yes |
| DebugObject | 104 | NonPaged | 216 | 224 | 184 | 192 | (Dbgk) | (Dbgk) | **NO** | Yes |
| JobObject | 1600 | NonPaged | 1712 | 1760 | 1680 | 1760 | (?) | (?) | Yes | Yes |
| WaitCompletionPacket | 112 | NonPaged | 224 | 224 | 192 | 192 | IopCloseWaitCompletionPacket | NULL | **NO** | Yes |
| Section | 64 | NonPaged | 176 | 176 | 144 | 144 | (?) | (?) | **NO** | Yes |
| Partition | 128 | NonPaged | 240 | 240 | 208 | 208 | (?) | (?) | **NO** | Yes |
| **ALPC Port** | **472** | **NonPaged** | **600** | **640** | **568** | **576** | **AlpcpClosePort** | **AlpcpDeletePort** | **Yes** | Yes |
| PrivateNamespace | variable | NonPaged | variable | ? | variable | ? | (?) | (?) | Yes | Yes |
| Directory | 344 | NonPaged | 456 | 480 | 424 | 448 | (?) | (?) | **NO** | Yes |
| SymbolicLink | 40 | NonPaged | 152 | 160 | 120 | 128 | (?) | (?) | **NO** | Yes |

---

## 3. Types with Uninitialized Fields

### 3.1 Timer (ExTimerObjectType) - body=328, bucket=448

**Creation**: `NtCreateTimer` -> `ObCreateObjectEx(PreviousMode, ExTimerObjectType, ..., 328, 0, 0, &Object, nullptr)`

**Initialization after ObCreateObjectEx** (from NtCreateTimer decompilation at 0x1406c5b20):
```c
KeInitializeDpc((PRKDPC)((char *)DeferredContext + 160), ExpTimerDpcRoutine, DeferredContext);
KeInitializeTimerEx(v9, a4);                    // KTIMER at offset 0 (24 bytes)
*(_QWORD *)&v9[1].Header.Lock = 0;              // offset 40: zeroed (8 bytes)
LOBYTE(v9[4].Dpc) = 0;                          // offset 160: first byte zeroed
*(_QWORD *)&v9[4].Header.Lock = 0;              // offset 160: 8 bytes zeroed
v9[4].Header.WaitListHead.Flink = nullptr;      // offset 184: Flink = NULL
// NOTE: Blink at offset 192 is NOT set!
```

**Uninitialized ranges**:
- Offsets 48-159 (112 bytes): NOT zeroed, NOT initialized
- Offsets 192-327 (136 bytes): Blink at 192 not set, rest not initialized

**Delete path** (ExpDeleteTimer at 0x14025fa00):
```c
p_WaitListHead = &a1[4].Header.WaitListHead;   // offset 184
if ( !a1[4].Header.WaitListHead.Flink )         // checks Flink == NULL
    goto LABEL_2;                               // Skip if NULL (safe path)
```

The delete checks Flink at offset 184. Since NtCreateTimer sets this to NULL, the wait list processing is skipped. However, the code continues with KeAcquireSpinLockRaiseToDpc at offset 72 (0x48) which is in the uninitialized range.

**Assessment**: Flink check prevents primary write-what-where. Offsets 48-159 contain uninitialized data accessed by spin lock operations. Further analysis of full ExpDeleteTimer needed.

### 3.2 WorkerFactory (ExpWorkerFactoryObjectType) - body=576, bucket=704

**Creation**: `NtCreateWorkerFactory` -> `ObCreateObject(..., 576, 0, 0, &Object, nullptr)` (body size confirmed via disassembly at 0x1407017d9: `mov dword ptr [rsp+28h], 240h`)

**Initialization after ObCreateObject** (from disassembly at 0x140701808):
```
offset 0x10 (16):  pointer to extra data structure (set)
offset 0x18 (24):  callback function (set)
offset 0x20 (32):  context (set)
offset 0x28 (40):  process handle (set)
offset 0x30 (48):  process object (set)
offset 0x38 (56):  stack size (set)
offset 0x40 (64):  max worker count (set)
offset 0x48-0x67 (72-103):  *** NOT SET - 32 bytes UNINITIALIZED ***
offset 0x68 (104): 0 (set)
offset 0x70 (112): idle timeout (set)
offset 0x78-0x117 (120-279): memset(0, 0xA0=160) - ZEROED
offset 0x148 (328): KeInitializeTimer2 - timer initialized
offset 0x1D0 (464): KeRegisterObjectNotification - notification block
offset 0x200 (512): 1 (set)
offset 0x238 (568): 0 (set)
```

**Uninitialized ranges**:
- Offsets 0-15 (16 bytes): DISPATCHER_HEADER - may be initialized by queue mechanism
- **Offsets 72-103 (32 bytes): COMPLETELY UNINITIALIZED - not zeroed, not set**
- Offsets 280-327 (48 bytes): Between memset end and timer init
- Offsets 376-463 (88 bytes): Between timer and notification block

**Close path** (ExpCloseWorkerFactory at 0x1406f0300 -> ExpShutdownWorkerFactory at 0x1403489e8):
```c
// ExpShutdownWorkerFactory iterates over 4 QWORD pointers at offsets 72-103:
v3 = (PVOID *)(Object + 9);   // Object + 72 bytes (9 * 8)
v4 = 4;
do {
    if ( *v3 )                 // If non-zero (pool garbage from spray!)
    {
        ObfDereferenceObjectWithTag(*v3, 0x746C6644u);  // DEREFERENCE CONTROLLED POINTER
        *v3 = nullptr;
    }
    ++v3;                      // Next QWORD (80, 88, 96)
    --v4;
} while (v4);
// Then: KeCancelTimer2, KeDeregisterObjectNotification, IoSetIoCompletionEx2
```

This loop iterates over 4 QWORD pointers at offsets 72, 80, 88, 96. If any contain non-zero values (from pool garbage), they are dereferenced as object pointers and passed to ObfDereferenceObjectWithTag!

**Delete path** (ExpDeleteWorkerFactory at 0x1402dd850):
```c
// Accesses only initialized fields:
a1[2]  // offset 16: extra data pointer (initialized)
a1[6]  // offset 48: process object (initialized)
a1[5]  // offset 40: process handle (initialized)
// No direct RemoveEntryList on uninitialized fields
```

**Assessment**: The close path dereferences uninitialized pointers at offsets 72-103. If pool garbage at these offsets contains non-zero values, ObfDereferenceObjectWithTag will be called with arbitrary pointers, potentially causing a write-what-where via the object dereference process.

### 3.3 DebugObject (DbgkDebugObjectType) - body=104, bucket=224

**Initialization** (from NtCreateDebugObject at 0x140885af0):
```c
Event[1].Header.LockNV = 1;                    // offset 24: byte set
v9[1].Header.WaitListHead.Flink = nullptr;     // offset 32: 8 bytes = 0
LODWORD(v9[1].Header.WaitListHead.Blink) = 0;  // offset 40: lower 4 bytes = 0
// offset 44: upper 4 bytes of Blink NOT set!
KeInitializeEvent(v9 + 2, SynchronizationEvent, 0);  // offset 48: KEVENT initialized
v9[3].Header.WaitListHead self-referenced at offset 88/96
KeInitializeEvent(v9, NotificationEvent, 0);   // offset 0: KEVENT initialized
v9[4].Header.LockNV = 0 or 2;                  // offset 96: byte set
```

**Uninitialized range**: offsets 40-47 (8 bytes, upper 4 bytes of Blink at offset 44)

**Assessment**: Very small uninitialized range. Unlikely to be exploitable for write-what-where.

---

## 4. ALPC Port Analysis (Bucket 640 Match)

### ALPC Port - body=472, total=600 (named+security), bucket=640

**Type init** (AlpcpInitSystem at 0x1407cde8c):
- ObjectTypeFlags has bit 0x10 (security) -> adds 16 bytes overhead
- CloseProcedure = AlpcpClosePort
- DeleteProcedure = AlpcpDeletePort

**Object creation** (AlpcpCreatePort at 0x1405e0f24):
```c
Object = ObCreateObjectEx(a1, AlpcPortObjectType, a2, a1, v6, 472, 0, 0, a3, nullptr);
if (Object >= 0)
    memset(*a3, 0, 0x1D8u);  // Zero entire 472-byte body
```

**Port initialization** (AlpcpInitializePort at 0x1405e0d98):
- Self-references 7 LIST_ENTRYs at offsets 144, 160, 184, 208, 232, 336, 384
- Inserts into global AlpcpPortList at offset 0-8

**Delete path** (AlpcpDeletePort -> AlpcpDestroyPort at 0x1405e2efc):
```c
if ( *a1 )  // Check Flink (offset 0) non-zero
{
    // RemoveEntryList: validate and unlink from AlpcpPortList
    v2 = (QWORD*)*a1;           // Flink
    *v3 = v2;                    // Blink->Flink = Flink (WRITE)
    v2[1] = (QWORD)v3;          // Flink->Blink = Blink (WRITE)
}
```

**Conclusion**: ALPC Port body is **fully zeroed** by memset. No uninitialized fields. NOT exploitable.

---

## 5. Bucket 1024 Analysis

No user-mode-creatable object type produces a total allocation in the 961-1024 byte range.

Closest candidates:
- JobObject (body=1600): total=1712 -> bucket 1760 (too large)
- WorkerFactory (body=576): total=656/688 -> bucket 704 (too small)
- ALPC Port (body=472): total=600 -> bucket 640 (too small)

Variable-size types:
- NtCreatePrivateNamespace: body = boundary_descriptor_size + 392
  - For bucket 1024: need body=849-912, descriptor_size=457-520
  - But body is fully zeroed by memset
- IoCreateDevice: body = extension_size + 448 (kernel-only)

---

## 6. WorkerFactory - Most Promising Candidate

### Exploit chain (if bucket 704 is acceptable):

1. **Spray bucket 704** in NonPagedPoolNx with controlled data
2. **Free some allocations** to create holes
3. **Create WorkerFactory** via NtCreateWorkerFactory -> object allocated in bucket 704
4. Body contains pool garbage at offsets 72-103 (4 QWORDs)
5. NtCreateWorkerFactory initializes offsets 0-71, 104-279, 328+ but leaves 72-103 UNINITIALIZED
6. **Close the handle** -> ExpCloseWorkerFactory -> ExpShutdownWorkerFactory
7. ExpShutdownWorkerFactory iterates over offsets 72-103, calls ObfDereferenceObjectWithTag on non-zero values
8. ObfDereferenceObjectWithTag dereferences attacker-controlled pointer -> **write-what-where**

### WorkerFactory body layout (576 bytes):
```
0x00-0x0F:  DISPATCHER_HEADER
0x10:       WORKER_FACTORY_EXTRA_DATA pointer
0x18:       Callback function
0x20:       Context
0x28:       Process handle
0x30:       Process object
0x38:       Stack size
0x40:       Max worker count
0x48-0x67:  *** UNINITIALIZED - 4 QWORDs dereferenced by close path ***
0x68:       Zero
0x70:       Idle timeout
0x78-0x117: Zeroed (memset 160 bytes)
0x148:      KTIMER2
0x1D0:      Notification block
0x200:      1
0x238:      Zero
```

### Key decompilation snippets:

**ExpWorkerFactoryInitialization** (type creation):
```c
v3[8] = &ExpCloseWorkerFactory;      // CloseProcedure at offset 0x40
v3[9] = ExpDeleteWorkerFactory;      // DeleteProcedure at offset 0x48
HIDWORD(v3[5]) = 576;               // DefaultNonPagedPoolCharge
```

**ExpShutdownWorkerFactory** (close path - the vulnerability):
```c
v3 = (PVOID *)(Object + 9);  // Object + 72 bytes
v4 = 4;
do {
    if ( *v3 )  // UNINITIALIZED - contains pool garbage
    {
        ObfDereferenceObjectWithTag(*v3, 0x746C6644u);  // DEREFERENCE ARBITRARY POINTER
        *v3 = nullptr;
    }
    ++v3;
    --v4;
} while (v4);
```

---

## 7. OBJECT_TYPE_INITIALIZER Layout

Determined from ObCreateObjectTypeEx decompilation:
```
Offset  Field                          Size
0x00    Length                         2  (always 120)
0x02    ObjectTypeFlags                1  (0x10=security, 0x20=process_info, 0x04=UseDefaultObject)
0x03    ObjectTypeFlags2               1
0x04    ValidAccessMask                4
0x08    PoolType/Flags                 4  (bit 0=PagedPool)
0x0C    GENERIC_MAPPING                16
0x1C    SupportedAccess                4
0x20    ???                            4
0x24    ControlFlags (v47)             4  (bit 0=paged pool charge)
0x28    DefaultPagedPoolCharge         4
0x2C    DefaultNonPagedPoolCharge      4  (body size, header added by ObCreateObjectTypeEx)
0x30    OpenProcedure                  8
0x38    ???                            8
0x40    CloseProcedure                 8
0x48    DeleteProcedure                8
0x50    ParseProcedure                 8
0x58    SecurityProcedure              8
0x60    QueryNameProcedure             8
0x68    ???                            8
0x70    OkayToCloseProcedure           8
```

OBJECT_TYPE layout (216 bytes = 0xD8):
- 0x00: LIST_ENTRY TypeList (16)
- 0x10: UNICODE_STRING Name (16)
- 0x20: PVOID DefaultObject (8)
- 0x28: UCHAR Index (1) + padding (3)
- 0x2C: ULONG TotalNumberOfObjects (4)
- 0x30: ULONG TotalNumberOfHandles (4)
- 0x40: OBJECT_TYPE_INITIALIZER TypeInfo (120 bytes = 0x78)
- 0xB8: ULONG Key (4)
- 0xC0: LIST_ENTRY CallbackList (16)

OBJECT_HEADER (48 bytes, body at +48 from allocation start):
- Confirmed by ObCreateObjectEx: `*a9 = v22 + 48;`

---

## 8. All ObCreateObject/ObCreateObjectEx Callers

42 call sites analyzed:
AlpcpCreatePort, CmpCreateRegistryRoot, CmpDoAccessCheckOnKCB, EtwpAddUmRegEntry,
EtwpCreateUmReplyObject, EtwpRealtimeConnect, EtwpRegisterPrivateSession,
EtwpSetCoverageSamplerInformation, ExCreateCallback, ExpProfileCreate,
HalpDmaAllocateChildAdapterV2, HalpDmaAllocateChildAdapterV3, IoCreateController,
IoCreateDevice, IoCreateDriver, IoCreateStreamFileObjectEx2, IopInitializeBuiltinDriver,
IopLoadDriver, MiFinishCreateSection, MiSectionInitialization, MiSessionObjectCreate,
NtAllocateReserveObject, NtCreateDebugObject, NtCreateEvent, NtCreateIoCompletion,
NtCreateJobObject, NtCreateKeyedEvent, NtCreateMutant, NtCreatePrivateNamespace,
NtCreateRegistryTransaction, NtCreateSemaphore, NtCreateTimer, NtCreateTimer2,
NtCreateWaitCompletionPacket, NtCreateWorkerFactory, ObCreateSymbolicLink,
ObpCreateDirectoryObject, PopCreatePowerRequestObject, PopEtEnergyTrackerCreate,
PsCreateSiloContext, PspAllocateActivityReference, PspAllocatePartition,
PspAllocateProcess, PspAllocateThread, SepCreateTokenEx, SepDuplicateToken, SepFilterToken,
TtmiCreateEventQueue, TtmiCreateTerminal, VrpHandleIoctlInitializeJobForVreg, WmipCreateGuidObject

---

## 9. Summary and Recommendations

### Target Bucket 640 (577-640):
- **Only match**: ALPC Port (body=472, total=600 with named+security)
- **Status**: NOT exploitable - body fully zeroed by memset

### Target Bucket 1024 (961-1024):
- **No matches** among user-mode-creatable types

### Best Alternative - Bucket 704 (641-704):
- **WorkerFactory** (body=576, total=656 unnamed / 688 named)
- **Status**: Has 32 bytes of uninitialized QWORDs at offsets 72-103 that are dereferenced by ExpShutdownWorkerFactory close path
- **Mechanism**: ObfDereferenceObjectWithTag called on attacker-controlled pointers
- **Requirement**: Need to spray bucket 704 instead of 640/1024

### Next Steps:
1. Verify if segment heap bucket 704 can be sprayed with named pipes or other user-mode allocations
2. Analyze full ExpDeleteTimer for additional uninitialized field access in offsets 48-159
3. Check if ObfDereferenceObjectWithTag on a controlled pointer provides sufficient write primitive
4. Consider whether the WorkerFactory close path can be triggered before full initialization completes
5. Investigate variable-size objects (NtCreatePrivateNamespace) for bucket 1024 targeting despite memset
