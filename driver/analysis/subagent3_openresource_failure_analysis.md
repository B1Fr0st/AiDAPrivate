# Subagent 3: OpenResourceFromNtHandle STATUS_INVALID_PARAMETER Analysis

## 1. Executive Summary

**Root Cause**: `D3DKMTOpenResourceFromNtHandle` returns `STATUS_INVALID_PARAMETER` (0xC000000D) because the exploit does not provide matching `PrivateRuntimeDataSize` and `ResourcePrivateDriverDataSize` values. The kernel performs exact-match validation against values stored in the shared resource by the D3D11 runtime when the texture was created. The exploit sets both to 0, but D3D11 stores non-zero values for shared textures with `NTHANDLE | KEYEDMUTEX`.

**Fix**: Call `D3DKMTQueryResourceInfoFromNtHandle` before `D3DKMTOpenResourceFromNtHandle` to query the expected sizes from the shared resource, then provide matching sizes and valid buffers in the OpenResource call.

---

## 2. IDA Multi-Binary Analysis Results

### 2a. Functions Decompiled (dxgkrnl.sys, PID 12320, port 13339)

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| `DxgkOpenResourceFromNtHandle` | 0x1C012B660 | 0x37B | Top-level syscall handler |
| `OpenResourceFromGlobalHandleOrNtObject<_D3DKMT_OPENRESOURCEFROMNTHANDLE>` | 0x1C012ABD4 | 0x72A | Template: device lookup, validation, buffer alloc |
| `DXGDEVICE::OpenResource<_D3DKMT_OPENRESOURCEFROMNTHANDLE>` | 0x1C012B320 | 0x338 | Core resource opening: NumAllocations/PrivateRuntimeData/ResourcePrivateDriverData checks |
| `DxgkQueryResourceInfoFromNtHandle` | 0x1C012A530 | 0x69B | Query API: returns expected sizes |
| `DXGDEVICE::QueryResourceInfo<_D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE>` | 0x1C012B9E4 | 0x289 | Core query: reads sizes from shared resource |

### 2b. DxgkOpenResourceFromNtHandle Flow (0x1C012B660)

1. Copies 104 bytes (6 OWORDs + 1 QWORD) from user struct
2. `ObReferenceObjectByHandle(hNtHandle, 0x20000, g_pDxgkSharedAllocationObjectType, ...)` — gets shared allocation object
3. `DXGKEYEDMUTEX::Open(keyedMutex, &hKeyedMutex, pKeyedMutexPrivateRuntimeData, KeyedMutexPrivateRuntimeDataSize, 1)` — opens keyed mutex
4. `DXGSYNCOBJECT::Open(syncObject, ...)` — opens sync object
5. Writes `hKeyedMutex` to user struct at offset +0x54 (a1+84)
6. Writes `hSyncObject` to user struct at offset +0x64 (a1+100)
7. Calls `OpenResourceFromGlobalHandleOrNtHandle<_D3DKMT_OPENRESOURCEFROMNTHANDLE>(a1, 0, sharedAllocObj, readOnlyFlag)`

**Evidence**: The log shows `hKeyedMutex=0x40002A80, hSyncObject=0x40002AC0` are populated, confirming steps 3-6 succeed. The failure occurs in step 7.

### 2c. OpenResourceFromGlobalHandleOrNtHandle Validation (0x1C012ABD4)

1. Copies 104 bytes from user struct into local buffer `v100` (memset to 0 first)
2. `v10 = (unsigned int *)v100` — DWORD pointer to struct copy
3. **Check 1**: `DXGPROCESS::GetCurrent()` must succeed
4. `DXGDEVICEBYHANDLE(v10[0])` — lookup device by handle
5. **Check 2**: `!v10[16] && !v10[12]` — both `TotalPrivateDriverDataBufferSize` (offset 0x40) AND `ResourcePrivateDriverDataSize` (offset 0x30) must not be 0. **Exploit passes this** (TotalPrivateDriverDataBufferSize = 4096).
6. Allocates kernel buffers: `80 * NumAllocations` bytes for allocation info, plus buffers for runtime data, resource private data, total private data
7. Replaces user pointers with kernel buffer pointers in the struct copy
8. Calls `DXGDEVICE::OpenResource<_D3DKMT_OPENRESOURCEFROMNTHANDLE>(device, structCopy, 0, sharedAllocObj, coreAccess, flag, nullptr, nullptr, nullptr)`

**Disassembly evidence** at call site (0x1C012AF71-0x1C012AF77):
```asm
mov rdx, rdi           ; rdx = struct pointer (v10/v100 kernel copy) -- NOT 0!
mov rcx, r14            ; rcx = DXGDEVICE*
call DXGDEVICE::OpenResource<...>
```
The Hex-Rays decompiler incorrectly showed the second parameter as `0`, but the disassembly proves `rdx = rdi` = the struct pointer.

### 2d. DXGDEVICE::OpenResource Validation Chain (0x1C012B320)

**Disassembly-verified validation checks** (rdi = struct pointer, r14 = shared resource, bl = isDxgProcess flag):

```asm
; Check 1: shared alloc object != NULL
test r15, r15
jz  loc_1C01C9D04           ; -> STATUS_INVALID_PARAMETER

; Check 2: shared resource != NULL
mov r14, [r15+10h]
test r14, r14
jz  loc_1C01C9C05           ; -> STATUS_INVALID_PARAMETER

; Check 3: flag bit 1 at shared_resource+0x88-0x2C
mov rax, [r14+88h]
mov ecx, [rax-2Ch]
test cl, 2
jnz loc_1C01C9CB6           ; -> STATUS_ACCESS_DENIED (different error)

; Check 4: NumAllocations exact match
mov ecx, [rdi+10h]          ; our NumAllocations (struct+0x10)
cmp [r14+84h], ecx          ; vs shared_resource+0x84
jnz loc_1C01C9C61           ; -> STATUS_INVALID_PARAMETER

; Check 5: shared_resource+0x0C bit 2 must NOT be set
mov eax, [r14+0Ch]
test al, 4
jnz loc_1C01C9D04           ; -> STATUS_INVALID_PARAMETER

; Check 6: isDxgProcess? (process+0x15B & 0x20)
and bl, 20h
jnz loc_1C012B403           ; if DxgProcess, skip checks 7-8

; Check 7: PrivateRuntimeDataSize EXACT MATCH (non-DxgProcess only)
mov eax, [r14+70h]          ; expected PrivateRuntimeDataSize (shared_resource+0x70)
cmp [rdi+20h], eax           ; our PrivateRuntimeDataSize (struct+0x20)
jnz loc_1C01C9C26           ; -> STATUS_INVALID_PARAMETER

; Check 8: ResourcePrivateDriverDataSize EXACT MATCH (non-DxgProcess only)
mov ecx, [rdi+30h]          ; our ResourcePrivateDriverDataSize (struct+0x30)
cmp ecx, [r14+80h]          ; vs expected (shared_resource+0x80)
jnz loc_1C01C9D59           ; -> STATUS_INVALID_PARAMETER
```

**Error path at loc_1C01C9D04** (confirmed via py_eval):
```asm
call    cs:__imp_WdLogNewEntry5_WdError
mov     rbx, 0FFFFFFFFC000000Dh    ; STATUS_INVALID_PARAMETER
mov     [rax+18h], rsi             ; log: DXGDEVICE*
mov     [rax+20h], rbx             ; log: error code
jmp     loc_1C01C9C8E              ; cleanup and return
```

**Error path at loc_1C01C9D59** (ResourcePrivateDriverDataSize mismatch):
```asm
call    cs:__imp_WdLogNewEntry5_WdWarning
mov     rbx, 0FFFFFFFFC000000Dh    ; STATUS_INVALID_PARAMETER
mov     ecx, [rdi+30h]             ; our ResourcePrivateDriverDataSize
mov     [rax+20h], rcx             ; log: our value
mov     ecx, [r14+80h]             ; expected value
mov     [rax+28h], rcx             ; log: expected value
mov     [rax+30h], rbx             ; log: error code
call    cs:__imp_WdLogEvent5_WdWarning
```

### 2e. Root Cause Identification

The exploit sets:
- `PrivateRuntimeDataSize = 0` (not set, zeroed by `openBuf = {}`)
- `ResourcePrivateDriverDataSize = 0` (not set, zeroed by `openBuf = {}`)

The kernel checks (Check 7 and Check 8) perform **exact match** against values stored in the shared resource object:
- `shared_resource+0x70` = PrivateRuntimeDataSize (set by D3D11 runtime during CreateAllocation)
- `shared_resource+0x80` = ResourcePrivateDriverDataSize (set by D3D11 runtime during CreateAllocation)

When D3D11 creates a shared texture with `D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX` (0x900), the D3D11 runtime internally calls `D3DKMTCreateAllocation` with non-zero `PrivateRuntimeDataSize` and `ResourcePrivateDriverDataSize`. These values are GPU-driver-specific and stored in the shared resource kernel object.

Since the exploit is a normal user-mode process (not a DxgProcess), the kernel does NOT skip checks 7-8. The exact match fails because `0 != expected_value`, returning `STATUS_INVALID_PARAMETER`.

---

## 3. Struct Layout Comparison

### 3a. D3DKMT_OPENRESOURCEFROMNTHANDLE (104 bytes = 0x68) — CORRECT

| Offset | Size | Exploit Field | Kernel Access | Match |
|--------|------|---------------|---------------|-------|
| +0x00 | 4 | hDevice | v10[0], used for DXGDEVICEBYHANDLE | YES |
| +0x04 | 4 | Pad0 | — | YES |
| +0x08 | 8 | hNtHandle | Handle[1], used for ObReferenceObjectByHandle | YES |
| +0x10 | 4 | NumAllocations | v10[4], rdi+0x10, checked vs shared_resource+0x84 | YES |
| +0x14 | 4 | Pad1 | — | YES |
| +0x18 | 8 | pOpenAllocationInfo2 | v10[6-7], replaced with kernel buffer | YES |
| +0x20 | 4 | PrivateRuntimeDataSize | v10[8], rdi+0x20, checked vs shared_resource+0x70 | YES |
| +0x24 | 4 | Pad2 | — | YES |
| +0x28 | 8 | pPrivateRuntimeData | v10[10-11], kernel copies data TO this buffer | YES |
| +0x30 | 4 | ResourcePrivateDriverDataSize | v10[12], rdi+0x30, checked vs shared_resource+0x80 | YES |
| +0x34 | 4 | Pad3 | — | YES |
| +0x38 | 8 | pResourcePrivateDriverData | v10[14-15], kernel copies data TO this buffer | YES |
| +0x40 | 4 | TotalPrivateDriverDataBufferSize | v10[16], checked: must not be 0 if ResourcePrivateDriverDataSize is 0 | YES |
| +0x44 | 4 | Pad4 | — | YES |
| +0x48 | 8 | pTotalPrivateDriverDataBuffer | v10[18-19], kernel copies data TO this buffer | YES |
| +0x50 | 4 | hResource (OUT) | v10[20], written back at a1+0x50 | YES |
| +0x54 | 4 | hKeyedMutex (OUT) | written back at a1+84 (0x54) | YES |
| +0x58 | 8 | pKeyedMutexPrivateRuntimeData | v51[1], passed to DXGKEYEDMUTEX::Open | YES |
| +0x60 | 4 | KeyedMutexPrivateRuntimeDataSize | v52[0], passed to DXGKEYEDMUTEX::Open | YES |
| +0x64 | 4 | hSyncObject (OUT) | written back at a1+100 (0x64) | YES |

**Struct size**: 104 bytes. Kernel copies 104 bytes (6 OWORDs + 1 QWORD). **MATCH**.

### 3b. D3DDDI_OPENALLOCATIONINFO2 (80 bytes = 0x50) — CORRECT

The kernel uses **80-byte stride** for the user's `pOpenAllocationInfo2` array in `OpenResourceFromGlobalHandleOrNtObject`:
```asm
mov eax, 50h ; 'P'      ; 80 bytes per allocation
mul rcx               ; 80 * NumAllocations
call operator new[]   ; allocate kernel buffer
```

And in the write-back loop:
```c
v41 = 80LL * v34;  // 80-byte stride for user buffer
```

The exploit's struct is 80 bytes. **MATCH**.

Note: The kernel's internal `D3DDDI_ALLOCATIONINFO2` is 96 bytes (used in `DXGDEVICE::OpenResource`: `96 * NumAllocations`), but the user-facing struct for `OpenResourceFromNtHandle` is 80 bytes. These are different structs.

### 3c. D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE (40 bytes = 0x28) — NEW

| Offset | Size | Field | Direction | Source |
|--------|------|-------|-----------|--------|
| +0x00 | 4 | hDevice | INPUT | user |
| +0x04 | 4 | Pad0 | — | — |
| +0x08 | 8 | hNtHandle | INPUT | user |
| +0x10 | 4 | Pad1 | — | — |
| +0x14 | 4 | Pad2 | — | — |
| +0x18 | 4 | PrivateRuntimeDataSize | OUTPUT | a2[6] = shared_resource+0x70 |
| +0x1C | 4 | TotalPrivateDriverDataBufferSize | OUTPUT | a2[7] = sum of allocation private driver data sizes |
| +0x20 | 4 | ResourcePrivateDriverDataSize | OUTPUT | a2[8] = shared_resource+0x80 (or from DdiGetStandardAllocationDriverData) |
| +0x24 | 4 | NumAllocations | OUTPUT | a2[9] = shared_resource+0x84 |

**Verified from decompiled `DXGDEVICE::QueryResourceInfo` (0x1C012B9E4)**:
```c
// Same-adapter path:
a2[6] = *(_DWORD *)(v8 + 112);   // PrivateRuntimeDataSize from shared_resource+0x70
a2[7] = v13;                      // TotalPrivateDriverDataBufferSize (accumulated)
a2[8] = *(_DWORD *)(v8 + 128);   // ResourcePrivateDriverDataSize from shared_resource+0x80
a2[9] = *(_DWORD *)(v8 + 132);   // NumAllocations from shared_resource+0x84
```

Kernel reads 32 bytes from user, writes 40 bytes back. **VERIFIED**.

---

## 4. Fix Applied

### 4a. New API: D3DKMTQueryResourceInfoFromNtHandle

Added the `D3DKMTQueryResourceInfoFromNtHandle` API to query expected sizes before calling `D3DKMTOpenResourceFromNtHandle`.

**Changes**:
1. Added `D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE` struct definition (40 bytes)
2. Added `pfnD3DKMTQueryResourceInfoFromNtHandle` function pointer typedef
3. Added `SafeQueryResourceInfo` SEH wrapper
4. Added `QueryResourceInfoFromNtHandle` member to `D3DKMTApi` class
5. Resolved from gdi32.dll via `GetProcAddress(gdi, "D3DKMTQueryResourceInfoFromNtHandle")`
6. Added null check and logging

### 4b. Query-Then-Open Flow

Before calling `D3DKMTOpenResourceFromNtHandle`, the exploit now:

1. Calls `D3DKMTQueryResourceInfoFromNtHandle` with `hDevice` and `hNtHandle`
2. Gets back: `PrivateRuntimeDataSize`, `ResourcePrivateDriverDataSize`, `TotalPrivateDriverDataBufferSize`, `NumAllocations`
3. Allocates stack buffers: `runtimeDataBuf[1024]`, `resourcePrivDataBuf[1024]`, `totalPrivDataBuf[4096]`
4. Sets the `D3DKMT_OPENRESOURCEFROMNTHANDLE` fields with the queried sizes and buffer pointers:
   - `PrivateRuntimeDataSize` = queried value (exact match for kernel check)
   - `pPrivateRuntimeData` = `runtimeDataBuf` (if size > 0, else nullptr)
   - `ResourcePrivateDriverDataSize` = queried value (exact match for kernel check)
   - `pResourcePrivateDriverData` = `resourcePrivDataBuf` (if size > 0, else nullptr)
   - `TotalPrivateDriverDataBufferSize` = queried value (or 4096 fallback)
   - `pTotalPrivateDriverDataBuffer` = `totalPrivDataBuf`
   - `NumAllocations` = queried value (or 1 fallback)
5. Calls `D3DKMTOpenResourceFromNtHandle` with the correct parameters

**Fallback**: If `D3DKMTQueryResourceInfoFromNtHandle` is not available or fails, falls back to zeroed sizes (original behavior, which may still fail but degrades gracefully).

### 4c. Buffer Allocation

The exploit allocates stack buffers:
- `runtimeDataBuf[1024]` — for PrivateRuntimeData output
- `resourcePrivDataBuf[1024]` — for ResourcePrivateDriverData output
- `totalPrivDataBuf[4096]` — for TotalPrivateDriverData output
- `allocInfoBuf[80 * 4 + 64]` — for up to 4 D3DDDI_OPENALLOCATIONINFO2 entries

Sizes are capped at buffer capacity. The kernel copies data FROM the shared resource TO these buffers, so they just need to be large enough.

---

## 5. Keyed Mutex and Sync Object

The kernel's `DxgkOpenResourceFromNtHandle` opens the keyed mutex and sync object BEFORE calling `OpenResourceFromGlobalHandleOrNtHandle`. The log confirms these succeed:
```
hKeyedMutex=0x40002A80, hSyncObject=0x40002AC0
```

The `D3DKMTOpenResourceFromNtHandle` struct's `pKeyedMutexPrivateRuntimeData` (offset +0x58) and `KeyedMutexPrivateRuntimeDataSize` (offset +0x60) are left as NULL/0 by the exploit. The kernel's `DXGKEYEDMUTEX::Open` accepts these values (the keyed mutex doesn't require runtime data for opening). No fix needed for these fields.

**D3DKMTLock and keyed mutex**: The kernel does NOT require the keyed mutex to be acquired before calling `D3DKMTLock`. The keyed mutex is a separate synchronization primitive for inter-process resource sharing, not a prerequisite for locking. The exploit can call `D3DKMTLock` directly after `OpenResourceFromNtHandle` succeeds.

---

## 6. Alternative Approach Considered: Skip OpenResourceFromNtHandle

Considered whether to skip `OpenResourceFromNtHandle` entirely and use:
- `D3DKMTOpenResource` (not FromNtHandle) with a global share handle — requires `D3D11_RESOURCE_MISC_SHARED` (0x2) instead of NTHANDLE, different creation flags
- `ID3D11Device1::OpenSharedResource1` + D3D11 Map — D3D11 Map uses D3DKMTLock2 internally, not D3DKMTLock, and may not trigger the same dangling lock vulnerability
- Direct D3DKMT CreateAllocation with StandardAllocation — already attempted, requires Flags=0x10020, separate code path

**Decision**: The QueryResourceInfo approach is the cleanest fix. It uses a documented kernel API to get the exact expected sizes, then provides matching values. No hooks, no guessing, no alternative code paths.

---

## 7. IDA Instances Used

| Instance | Binary | PID | Port | Key Functions Analyzed |
|----------|--------|-----|------|----------------------|
| 3 | dxgkrnl.sys | 12320 | 13339 | `DxgkOpenResourceFromNtHandle`, `OpenResourceFromGlobalHandleOrNtObject`, `DXGDEVICE::OpenResource`, `DxgkQueryResourceInfoFromNtHandle`, `DXGDEVICE::QueryResourceInfo`, type definitions |

---

## 8. Files Changed

| File | Changes |
|------|---------|
| `C:\Users\ruar1337\AiDAPrivate\driver\dxgkrnl_dangling_lock_exploit_verified.cpp` | 1. Added `D3DKMT_QUERYRESOURCEINFOFROMNTHANDLE` struct (40 bytes). 2. Added `pfnD3DKMTQueryResourceInfoFromNtHandle` typedef. 3. Added `SafeQueryResourceInfo` SEH wrapper. 4. Added `QueryResourceInfoFromNtHandle` to `D3DKMTApi` class. 5. Resolved from gdi32.dll. 6. Added null check and logging. 7. Rewrote `CreateDanglingMappingsViaD3D11` OpenResource setup to query-then-open with correct sizes and buffers. 8. Updated Phase0 logging. |

---

## 9. Build Instructions

The host AI should build with:

```cmd
cl.exe /EHsc /O2 /std:c++17 /W3 dxgkrnl_dangling_lock_exploit_verified.cpp /Fe:dxgkrnl_dangling_lock_exploit_verified.exe /link d3d11.lib dxgi.lib gdi32.lib user32.lib ntdll.lib advapi32.lib
```

- `/W3` (not `/W4`) to avoid C4456 variable shadowing warnings in the D3DKMT path
- `dxgi.lib` for `CreateDXGIFactory1`
- `gdi32.lib` for `D3DKMT*` exports including `D3DKMTQueryResourceInfoFromNtHandle`
- After building, run the `.exe` and check `exploit_debug.log` for the QueryResourceInfo and OpenResource logging output
