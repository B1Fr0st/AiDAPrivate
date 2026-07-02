# Kernel Exploit Link Verification: Links 1-3

**Date:** 2026-07-02  
**Tool:** IDA Pro MCP (Hex-Rays decompiler)  
**Targets:** ntdll.dll (pid 3440), ntoskrnl.exe (pid 4024), npfs.sys (pid 9784)

---

## LINK 1: NtQuerySystemInformation(SystemBigPoolInformation) leaks kernel pool addresses

### VERDICT: YES

### Evidence

#### ntdll.dll — Syscall Stub (pid 3440)

**Function:** `NtQuerySystemInformation` @ `0x18009dc50`

Decompiled output confirms a standard user-mode syscall stub:

```c
NTSTATUS __stdcall NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS result;
    result = 54;                    // syscall number = 0x36
    if ((MEMORY[0x7FFE0308] & 1) != 0)
        __asm { int 2Eh; }          // legacy interrupt path
    else
        __asm { syscall; }          // modern syscall path
    return result;
}
```

- Syscall number: **54 (0x36)**
- SystemInformationClass is passed in RCX (first fastcall argument)
- Dispatches to kernel `NtQuerySystemInformation` @ `0x1406c9cb0`

#### ntoskrnl.exe — Kernel Handler (pid 4024)

**Function:** `NtQuerySystemInformation` @ `0x1406c9cb0`

```c
__int64 __fastcall NtQuerySystemInformation(__int64 a1, __int64 a2, int a3, __int64 a4)
{
    // ...
    if ((int)a1 < 74 || (int)a1 >= 83) {
        switch ((int)a1) {
            // case 66 is NOT in the group-aware switch
            // Falls through to default -> breaks
            default: break;
        }
    }
    // For class 66: reaches here
    v6 = 0;
    return ExpQuerySystemInformation(a1, p_Group, v6, a2, a3, a4);
}
```

**Function:** `ExpQuerySystemInformation` @ `0x1406c9e30`

Jump table at `0x1406CA1C3` dispatches **case 66** (SystemBigPoolInformation = 0x42):

```asm
0x1406cb1ab: cmp     edi, 20h ; jumptable 00000001406CA1C3 case 66
0x1406cb1ae: jnb     short loc_1406CB1CB
; ... ExIsRestrictedCaller check ...
0x1406cb1e9: call    ExGetBigPoolInfo
```

**Function:** `ExGetBigPoolInfo` @ `0x1405b369c`

Decompiled output confirms it reads from `PoolBigPageTable` (global @ `0x140c16b70`) and
writes entries to the user buffer:

```c
// Source: PoolBigPageTable, size = PoolBigPageTableSize
// Each source entry = 24 bytes

// Output entry construction:
*(_QWORD *)v36 = v18;                          // +0: VirtualAddress
if (a3 == 1 && (*(_DWORD *)(v34 + 12) & 0x100) == 0)
    *(_QWORD *)v36 = v18 | 1;                  // Set bit 0 for NonPaged
v36[4] = *(_DWORD *)(v34 + 8);                 // +16: Tag (DWORD)
*((_QWORD *)v36 + 1) = *(_QWORD *)(v34 + 16);  // +8: SizeInBytes (QWORD)
v36 += 6;                                      // Advance 24 bytes (6 * 4)
```

#### py_eval: Structure offset calculation

```
SYSTEM_BIG_POOL_ENTRY (24 bytes / 0x18):
  +0:  PVOID    VirtualAddress  (8 bytes, bit 0 = NonPaged flag)
  +8:  SIZE_T   SizeInBytes     (8 bytes)
  +16: ULONG    Tag             (4 bytes, UCHAR Tag[4])
  +20: padding                  (4 bytes)

Advance per entry: v36 += 6 (DWORD*) = 6 * 4 = 24 bytes ✓
Class number: 0x42 = 66 decimal ✓
Jump table: case 66 @ 0x1406cb1ab → ExGetBigPoolInfo @ 0x1406cb1e9 ✓
Source table: PoolBigPageTable @ 0x140c16b70 ✓
```

### Conclusion

`NtQuerySystemInformation(SystemBigPoolInformation)` (class 0x42/66) dispatches through
`ExpQuerySystemInformation` jump table case 66 to `ExGetBigPoolInfo`, which iterates the
kernel global `PoolBigPageTable` and returns entries containing:
- **VirtualAddress** (kernel VA of the big pool allocation, bit 0 encodes NonPaged)
- **SizeInBytes** (allocation size)
- **Tag** (4-byte pool tag)

These are **kernel virtual addresses** of pool allocations tracked in the big pool table.

---

## LINK 2: Named pipe WriteFile >4096 creates big pool allocation with tag 'NpFr' in NonPagedPool

### VERDICT: YES

### Evidence

#### npfs.sys — Write Path (pid 9784)

**Complete call chain:**
```
WriteFile
  → NpFsdWrite @ 0x1c000db10  (IRP-based)
  → NpFastWrite @ 0x1c000da30 (fast IO)
    → NpCommonWrite @ 0x1c000dc00
      → NpWriteDataQueue @ 0x1c000deb0
        → returns STATUS_MORE_PROCESSING_REQUIRED (-1073741802) if buffer not fully consumed
      → NpAddDataQueueEntry @ 0x1c000d6c0  (queues remaining write data)
```

**NpFastWrite** @ `0x1c000da30` confirmed calls `NpCommonWrite`:

```c
_BOOL8 __fastcall NpFastWrite(...) {
    KeEnterCriticalRegion();
    v9 = (unsigned __int8)NpCommonWrite(a1, a6, a3, KeGetCurrentThread(), a7, 0, v13) != 0;
    // ... complete deferred IRPs ...
    KeLeaveCriticalRegion();
    return v9;
}
```

**NpCommonWrite** @ `0x1c000dc00` — when `NpWriteDataQueue` returns `STATUS_MORE_PROCESSING_REQUIRED`:

```c
v22 = NpWriteDataQueue(..., v32, v8, ...);
if (v22 == -1073741802) {  // STATUS_MORE_PROCESSING_REQUIRED
    LODWORD(Size) = v8;     // total write size
    *(_DWORD *)v7 = NpAddDataQueueEntry(v12, v11, v19, 1, 0, Size, a6, v21, (int)v8 - (int)v31);
}
```

**NpAddDataQueueEntry** @ `0x1c000d6c0` — the key allocation:

```c
// a4 = 1 (write type), a5 = 0, Size = write length
if (!a5) {
    v14 = 48;
    if (a4) {                          // write operation
        v14 = Size + 48;               // allocation = user_data + 48 bytes header
    }
    // ...
    v16 = ExAllocatePoolWithQuotaTag(
        (POOL_TYPE)776,                // 0x308 = NonPagedPoolNx + flags
        v14,                           // Size + 48
        0x7246704E                     // 'NpFr' pool tag
    );
    // ...
    v16[9] = v15;                      // +36: data length
    *((_QWORD *)v16 + 2) = v13;       // +16: IRP link
    v16[10] = Size;                    // +40: total size
    if (a4) {
        // Copy user data into allocation at offset 48
        memmove(v16 + 12, v23, (unsigned int)Size);  // v16+12 = v16 + 48 bytes
    }
}
```

#### py_eval: Tag and pool type decoding

```
Pool tag: 0x7246704E
  Byte 0: 0x4E = 'N'
  Byte 1: 0x70 = 'p'
  Byte 2: 0x46 = 'F'
  Byte 3: 0x72 = 'r'
  → Tag string: "NpFr" ✓

Pool type: 776 decimal = 0x308
  Bit 0: 0 → NonPaged (PagedPool = 1) ✓
  0x200: NonPagedPoolNx flag set ✓
  0x100: additional pool flags
  0x008: quota-related flag
  → NonPaged pool allocation ✓
```

#### py_eval: Allocation size for 8192-byte write

```
write_size      = 8192
header_overhead = 48
total_alloc     = 8192 + 48 = 8240 bytes
big_pool_threshold = 4096 (PAGE_SIZE)
is_big_pool     = 8240 > 4096 = True ✓

Data copy: memmove(alloc + 48, user_buffer, 8192)
  → User data stored at offset 48 in the NpFr-tagged NonPaged allocation
```

### Conclusion

Named pipe `WriteFile` with data > 4096 bytes triggers the following allocation chain:

1. `NpCommonWrite` calls `NpWriteDataQueue`; if the reader can't consume all data,
   it calls `NpAddDataQueueEntry`
2. `NpAddDataQueueEntry` calls `ExAllocatePoolWithQuotaTag(NonPagedPool, Size+48, 'NpFr')`
3. For 8192 bytes: allocation = 8240 bytes > 4096 → **big pool allocation**
4. User data is copied into the allocation via `memmove(alloc+48, user_buffer, 8192)`

The allocation is:
- **NonPaged pool** (POOL_TYPE 0x308, NonPagedPoolNx)
- **Tag 'NpFr'** (0x7246704E)
- **Size > 4096** → tracked in `PoolBigPageTable` (big pool)
- **Contains user-controlled data** at offset 48

This allocation will appear in `NtQuerySystemInformation(SystemBigPoolInformation)` results
with tag 'NpFr', leaking its kernel virtual address.

---

## LINK 3: NtQuerySystemInformation(SystemModuleInformation) leaks ntoskrnl base address

### VERDICT: YES

### Evidence

#### ntdll.dll — Syscall Stub (pid 3440)

Same syscall stub as Link 1 (`NtQuerySystemInformation` @ `0x18009dc50`, syscall number 54).
The `SystemInformationClass` parameter (0x0B = 11) is passed in RCX.

#### ntoskrnl.exe — Kernel Handler (pid 4024)

**Function:** `NtQuerySystemInformation` @ `0x1406c9cb0`

For class 11 (0x0B): 11 < 74, enters the switch, no matching case, falls through to:

```c
v6 = 0;
return ExpQuerySystemInformation(a1, p_Group, v6, a2, a3, a4);
```

**Function:** `ExpQuerySystemInformation` @ `0x1406c9e30`

Jump table at `0x1406CA1C3` dispatches **case 11** (SystemModuleInformation = 0x0B):

```asm
0x1406cadee: movzx   ecx, r12b; jumptable 00000001406CA1C3 case 11
0x1406cadf2: call    ExIsRestrictedCaller
; ... restriction check ...
0x1406cadff: call    KeEnterCriticalRegion
0x1406cae06: lea     rcx, PsLoadedModuleResource
0x1406cae0d: call    ExAcquireResourceExclusiveLite
0x1406cae1d: call    ExpQueryModuleInformation
0x1406cae24: lea     rcx, PsLoadedModuleResource  ; release lock after
```

**Function:** `ExpQueryModuleInformation` @ `0x1405ed940`

```c
__int64 __fastcall ExpQueryModuleInformation(__int64 a1, _DWORD *a2, unsigned int a3, unsigned int *a4)
{
    v8 = 8;                                    // initial offset = 8 (Count field)
    v9 = a2 + 2;                               // output ptr starts at offset 8
    v10 = (PVOID *)PsLoadedModuleList;          // iterate loaded module list
    
    while (v10 != &PsLoadedModuleList) {
        v8 += 296;                              // each RTL_PROCESS_MODULE = 296 bytes
        
        if (a3 >= v11) {
            // Write module information to output buffer:
            *((_QWORD *)v9 + 2) = v10[6];       // +16: ImageBase (kernel base address)
            v9[6] = *((_DWORD *)v10 + 16);      // +24: ImageSize
            v9[7] = *((_DWORD *)v10 + 26);      // +28: Flags
            *((_WORD *)v9 + 16) = v6;            // +32: LoadOrderIndex
            *((_WORD *)v9 + 17) = 0;             // +34: InitOrderIndex
            *((_WORD *)v9 + 18) = *((_WORD *)v10 + 54);  // +36: LoadCount
            
            // Convert module name from UNICODE to ANSI at +40
            RtlUnicodeStringToAnsiString(&DestinationString, (PCUNICODE_STRING)(v10 + 9), 0);
            
            v9 += 74;                            // advance 296 bytes (74 * 4)
            ++v6;
        }
        v10 = (PVOID *)*v10;                    // next module
    }
    
    *a2 = v6;                                   // write Count at offset 0
    return v7;
}
```

#### py_eval: RTL_PROCESS_MODULE structure

```
RTL_PROCESS_MODULE (296 bytes):
  +0:  HANDLE   Section          (8 bytes)
  +8:  PVOID    MappedBase       (8 bytes)
  +16: PVOID    ImageBase        (8 bytes)  ← kernel base address
  +24: ULONG    ImageSize        (4 bytes)
  +28: ULONG    Flags            (4 bytes)
  +32: USHORT   LoadOrderIndex   (2 bytes)
  +34: USHORT   InitOrderIndex   (2 bytes)
  +36: USHORT   LoadCount        (2 bytes)
  +38: USHORT   OffsetToFileName (2 bytes)
  +40: UCHAR    FullPathName[256]
  Total: 296 bytes ✓ (v9 += 74, 74 * 4 = 296)

RTL_PROCESS_MODULES:
  +0: ULONG  Count               (4 bytes + 4 padding = 8 bytes)
  +8: RTL_PROCESS_MODULE Modules[1]
  Total first entry: 8 + 296 = 304 bytes

Class number: 0x0B = 11 decimal ✓
Jump table: case 11 @ 0x1406cadee → ExpQueryModuleInformation @ 0x1406cae1d ✓
Source: PsLoadedModuleList @ 0x140c2a420 ✓
Lock: PsLoadedModuleResource acquired before iteration ✓
```

### Conclusion

`NtQuerySystemInformation(SystemModuleInformation)` (class 0x0B/11) dispatches through
`ExpQuerySystemInformation` jump table case 11 to `ExpQueryModuleInformation`, which:

1. Acquires `PsLoadedModuleResource` lock
2. Iterates `PsLoadedModuleList` (kernel linked list of loaded drivers/modules)
3. For each module, writes `RTL_PROCESS_MODULE` (296 bytes) containing:
   - **ImageBase** at offset +16 (the kernel base address of the module)
   - **ImageSize** at offset +24
   - **FullPathName** at offset +40 (ANSI image path, e.g., "\SystemRoot\system32\ntoskrnl.exe")
4. The first entry in `PsLoadedModuleList` is always **ntoskrnl.exe**

This returns the **ntoskrnl.exe base address** directly to any user-mode caller with
`NtQuerySystemInformation` access (no special privileges required for this class on
most Windows versions).

---

## Summary Table

| Link | Claim | Verdict | Key Evidence |
|------|-------|---------|--------------|
| 1 | NtQuerySystemInformation(SystemBigPoolInformation) leaks kernel pool VAs | **YES** | `ExpQuerySystemInformation` case 66 → `ExGetBigPoolInfo` reads `PoolBigPageTable`, returns VirtualAddress/SizeInBytes/Tag per entry |
| 2 | Named pipe WriteFile >4096 creates big pool NpFr NonPaged allocation with user data | **YES** | `NpAddDataQueueEntry` calls `ExAllocatePoolWithQuotaTag(0x308, Size+48, 'NpFr')`, copies user data at offset 48; 8192-byte write → 8240-byte alloc > 4096 |
| 3 | NtQuerySystemInformation(SystemModuleInformation) leaks ntoskrnl base | **YES** | `ExpQuerySystemInformation` case 11 → `ExpQueryModuleInformation` iterates `PsLoadedModuleList`, returns ImageBase at offset +16 in each 296-byte RTL_PROCESS_MODULE entry |

### Exploit Chain Implication

Links 1-3 form a complete kernel base + pool address leak chain:

1. **Link 3**: Leak ntoskrnl.exe base address via `SystemModuleInformation` (class 0x0B)
2. **Link 2**: Spray known data into kernel pool via named pipe `WriteFile` > 4096 bytes,
   creating 'NpFr'-tagged NonPaged big pool allocations containing attacker-controlled data
3. **Link 1**: Leak the kernel VA of those 'NpFr' allocations via `SystemBigPoolInformation`
   (class 0x42), matching by tag 'NpFr' and size

This provides a user-mode attacker with:
- The kernel base address (for ROP gadget calculation)
- The exact kernel VA of attacker-controlled pool data (for arbitrary read/write primitives
  or fake object spray)
