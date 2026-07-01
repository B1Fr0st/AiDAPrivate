# Subagent 4: D3DKMTLock STATUS_INVALID_PARAMETER Root Cause Analysis & Fix

## 1. IDA Analysis

### 1.1 Functions Decompiled

| Function | Address | Binary | Size |
|----------|---------|--------|------|
| `DxgkLock` | `0x1c010de40` | dxgkrnl.sys | 0x586 |
| `DxgkLock2` | `0x1c010cd80` | dxgkrnl.sys | 0x5cb |
| `DXGDEVICE::Lock` | `0x1c010d860` | dxgkrnl.sys | - |
| `DxgkUnlock2` | `0x1c010d360` | dxgkrnl.sys | 0x4ef |
| `DxgkAcquireKeyedMutex` | `0x1c0293cd0` | dxgkrnl.sys | 0x29b |
| `DxgkReleaseKeyedMutex` | `0x1c0295050` | dxgkrnl.sys | 0x252 |

### 1.2 DxgkLock (D3DKMTLock handler)

`DxgkLock` is the kernel handler for the user-mode `D3DKMTLock` API. It:
1. Copies the `D3DKMT_LOCK` struct from user mode
2. Resolves the device handle via `DXGDEVICEBYHANDLE`
3. Acquires device/adapter locks
4. Calls `DXGDEVICE::Lock(this, &lockData, coreDeviceAccess)`

The actual validation logic is inside `DXGDEVICE::Lock`, not in `DxgkLock` itself.

### 1.3 DXGDEVICE::Lock Validation Chain

Decompiled `DXGDEVICE::Lock` at `0x1c010d860` performs these checks in order:

1. **Flags range check**: `if (Flags.Value >= 0x800)` → `STATUS_INVALID_PARAMETER`
   - Exploit uses `Flags.Value = 0x1`, passes this check (0x1 < 0x800)

2. **NumPages/pPages consistency**: `if (NumPages == 0) != (pPages == NULL)` → `STATUS_INVALID_PARAMETER`
   - Exploit uses `NumPages=0, pPages=NULL`, passes

3. **Handle table lookup**: Extracts handle index `(hAlloc >> 6) & 0xFFFFFF`, checks bounds, checks handle type == 5 (allocation)
   - If handle not found or wrong type → `v24 = nullptr` → `STATUS_INVALID_PARAMETER`

4. **Allocation reference valid**: `if (!v77)` → `STATUS_INVALID_PARAMETER`
   - Allocation reference from `DXGALLOCATIONREFERENCE` constructor

5. **Allocation reference count**: `if (!Count)` → `STATUS_INVALID_PARAMETER`
   - `Count = v77[3].Count` (allocation reference field at offset 0x18)

6. **Owner device match**: `if ((DXGDEVICE *)v77[1].Count != this)` → `STATUS_INVALID_PARAMETER`
   - `v77[1].Count` is the owner device at offset 0x08 of allocation reference
   - Exploit uses same hDevice for OpenResource and Lock, should pass

7. **SYNC CHECK** (the failing one):
```c
if ((*(_DWORD *)(v77[6].Count + 4) & 2) == 0) {    // bypass check
    v27 = v77[5].Count;                               // sync object at offset 0x28
    if (v27) {                                         // sync object exists?
        v51 = *(_DWORD *)(v27 + 4);                    // sync flags
        if ((v51 & 1) != 0 && (v51 & 2) == 0) {       // synchronized allocation?
            v25 = *(_QWORD *)(*((_QWORD *)this + 2) + 16LL);  // adapter
            v52 = *(_DWORD *)(v25 + 348);              // adapter flags at offset 0x15C
            if ((v52 & 0x10) == 0 && (v52 & 8) == 0) { // adapter lacks sync support
                goto LABEL_81;                          // STATUS_INVALID_PARAMETER
            }
        }
    }
}
```

### 1.4 DxgkLock2 (D3DKMTLock2 handler) — DIFFERENT validation

`DxgkLock2` at `0x1c010cd80` has an **additional bypass** that `DXGDEVICE::Lock` does NOT have:

```c
v27 = *((_QWORD *)v77 + 5);                    // sync object
if (v27) {
    v61 = *(_DWORD *)(v27 + 4);                 // sync flags
    if ((v61 & 1) != 0 && (v61 & 2) == 0) {    // synchronized allocation
        v62 = *(_DWORD *)(*(_QWORD *)(v27 + 56) + 12LL);  // nested structure flags
        if ((v62 & 0x200) == 0 && (v62 & 0x400) == 0) {   // BYPASS CHECK
            // Only then check adapter flags (with additional 0x80 check at +2060)
            v63 = *(_DWORD *)(v25 + 348);
            if ((v63 & 0x10) == 0 && (v63 & 8) == 0 && (*(_DWORD *)(v25 + 2060) & 0x80u) == 0) {
                // FAIL
            }
        }
        // If v62 & 0x200 or v62 & 0x400 → SKIP adapter check → LOCK SUCCEEDS
    }
}
```

**Key difference**: `DxgkLock2` checks `v62 & 0x200` or `v62 & 0x400` in the sync object's nested structure. If either bit is set, the adapter flags check is **skipped entirely**, allowing the lock to proceed. `DXGDEVICE::Lock` (called by `DxgkLock`) does NOT have this bypass.

### 1.5 Struct Layouts from IDA Types

**`_D3DKMT_LOCK`** (48 bytes):
| Offset | Field | Type | Size |
|--------|-------|------|------|
| 0x00 | hDevice | D3DKMT_HANDLE | 4 |
| 0x04 | hAllocation | D3DKMT_HANDLE | 4 |
| 0x08 | PrivateDriverData | UINT | 4 |
| 0x0C | NumPages | UINT | 4 |
| 0x10 | pPages | const UINT* | 8 |
| 0x18 | pData | void* | 8 |
| 0x20 | Flags | D3DDDICB_LOCKFLAGS | 4 |
| 0x28 | GpuVirtualAddress | D3DGPU_VIRTUAL_ADDRESS | 8 |

**`_D3DKMT_LOCK2`** (24 bytes):
| Offset | Field | Type | Size |
|--------|-------|------|------|
| 0x00 | hDevice | D3DKMT_HANDLE | 4 |
| 0x04 | hAllocation | D3DKMT_HANDLE | 4 |
| 0x08 | Flags | D3DDDICB_LOCK2FLAGS | 4 |
| 0x10 | pData | PVOID | 8 |

**`_D3DKMT_UNLOCK2`** (8 bytes):
| Offset | Field | Type | Size |
|--------|-------|------|------|
| 0x00 | hDevice | D3DKMT_HANDLE | 4 |
| 0x04 | hAllocation | D3DKMT_HANDLE | 4 |

**`D3DDDICB_LOCKFLAGS`** (kernel internal, 4 bytes):
| Bit | Name |
|-----|------|
| 0 (0x001) | ReadOnly |
| 1 (0x002) | WriteOnly |
| 2 (0x004) | DonotWait |
| 3 (0x008) | IgnoreSync |
| 4 (0x010) | LockEntire |
| 5 (0x020) | DonotEvict |
| 6 (0x040) | AcquireAperture |
| 7 (0x080) | Discard |
| 8 (0x100) | NoExistingReference |
| 9 (0x200) | UseAlternateVA |
| 10 (0x400) | IgnoreReadSync |

**`D3DKMT_LOCKFLAGS`** (user-mode, 4 bytes) — different layout:
| Bit | Name |
|-----|------|
| 0 (0x001) | Lock |
| 1 (0x002) | Discard |
| 2 (0x004) | ReadOnly |
| 3 (0x008) | DoNotWait |
| 4 (0x010) | NotifyOnly |
| 5 (0x020) | Reserve |
| 6 (0x040) | NoExistingUpdate |
| 7 (0x080) | Reserved1 |
| 8 (0x100) | NoSynchronize |
| 9 (0x200) | IgnoreReadSync |
| 10 (0x400) | Reserved2 |
| 11 (0x800) | MaskSync |

## 2. Root Cause

**`D3DKMTLock` returns `STATUS_INVALID_PARAMETER` (0xC000000D) because:**

1. The exploit creates D3D11 textures with `D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX` (MiscFlags=0x900)
2. The `KEYEDMUTEX` flag causes the kernel to create a **sync object** at allocation reference offset 0x28
3. The sync object has flags `(flags & 1) != 0 && (flags & 2) == 0` indicating a "synchronized" allocation
4. `DXGDEVICE::Lock` checks adapter flags at `adapter + 348 (0x15C)`:
   - If `(adapter_flags & 0x10) == 0 AND (adapter_flags & 0x08) == 0` → **FAIL**
5. The NVIDIA MX130 and Intel UHD adapters do NOT have bits 0x10 or 0x08 set at offset 0x15C
6. Therefore, the sync check fails and `DXGDEVICE::Lock` returns `STATUS_INVALID_PARAMETER`

**The user's lock flags (Flags.Value) do NOT affect the sync check** — the sync check is based entirely on the allocation's internal properties and adapter capabilities. Changing `NoSynchronize` or `IgnoreReadSync` flags in the user's `D3DKMT_LOCKFLAGS` does not bypass this check.

**`DxgkLock2` (D3DKMTLock2) has an additional bypass**: it checks `v62 & 0x200` or `v62 & 0x400` in the sync object's nested structure. If either bit is set, the adapter flags check is skipped. This bypass does NOT exist in `DXGDEVICE::Lock`.

## 3. Fix Applied

### 3.1 Multi-Strategy Lock

Replaced the single `D3DKMTLock` call with a 5-strategy approach:

| Strategy | API | Conditions | Why |
|----------|-----|-----------|-----|
| 1 | `D3DKMTLock2` | `useKeyedMutex=true` | Has sync check bypass (0x200/0x400 in nested struct) |
| 2 | `D3DKMTLock` Flags=0x1 | Always | Basic lock (works for non-sync allocations) |
| 3 | `D3DKMTLock` Flags=0x301 | Always | Lock + NoSynchronize + IgnoreReadSync |
| 4 | `D3DKMTLock` Flags=0x5 | Always | Lock + ReadOnly |
| 5 | `AcquireKeyedMutex` + `D3DKMTLock` | `useKeyedMutex=true, hKeyedMutex!=0` | Acquire sync before lock |

### 3.2 NTHANDLE-Only Textures (No KEYEDMUTEX)

Modified the texture creation loop to try `D3D11_RESOURCE_MISC_SHARED_NTHANDLE` only (0x800) for the first half of iterations, then fall back to `NTHANDLE | KEYEDMUTEX` (0x900) for the second half.

**Rationale**: Without `KEYEDMUTEX`, the allocation's sync object at offset 0x28 will be NULL, and the sync check in `DXGDEVICE::Lock` will be skipped entirely (the `if (v27)` check fails). This is the most likely fix to work.

### 3.3 New APIs Added

- `D3DKMTLock2` / `D3DKMTUnlock2` — resolved from gdi32.dll
- `D3DKMTAcquireKeyedMutex` / `D3DKMTReleaseKeyedMutex` — resolved from gdi32.dll

### 3.4 New Structs Added

- `D3DKMT_LOCK2` (24 bytes, from IDA type analysis)
- `D3DKMT_UNLOCK2` (8 bytes, from IDA type analysis)
- `D3DKMT_ACQUIREKEYEDMUTEX` (32 bytes, from decompiled `DxgkAcquireKeyedMutex`)
- `D3DKMT_RELEASEKEYEDMUTEX` (24 bytes, inferred from `DxgkReleaseKeyedMutex`)

### 3.5 New Safe Wrappers

- `SafeLock2` — SEH wrapper for `D3DKMTLock2`
- `SafeUnlock2` — SEH wrapper for `D3DKMTUnlock2`
- `SafeAcquireKeyedMutex` — SEH wrapper for `D3DKMTAcquireKeyedMutex`
- `SafeReleaseKeyedMutex` — SEH wrapper for `D3DKMTReleaseKeyedMutex`

## 4. Python Calculations

All calculations performed via Python (no mental math):

### Flag values
- `Lock` = 0x1 (bit 0 in D3DKMT_LOCKFLAGS)
- `NoSynchronize` = 0x100 (bit 8)
- `IgnoreReadSync` = 0x200 (bit 9)
- `Lock | NoSynchronize | IgnoreReadSync` = 0x301
- `Lock | ReadOnly` = 0x5
- All combinations < 0x800 (pass kernel range check)

### D3D11 MiscFlags
- `NTHANDLE` = 0x800
- `KEYEDMUTEX` = 0x100
- `NTHANDLE | KEYEDMUTEX` = 0x900
- `NTHANDLE` only = 0x800

### Handle analysis
- `hAlloc = 0x40002B40`
- `index = (0x40002B40 >> 6) & 0xFFFFFF = 173 (0xAD)`
- `type = (0x40002B40 >> 25) & 0x60 = 32 (0x20)`

### NTSTATUS values
- `STATUS_INVALID_PARAMETER` = 0xC000000D = -1073741811 (signed)
- `STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE` = 0xC01E0101
- `STATUS_GRAPHICS_ALLOCATION_INVALID` = 0xC01E0100

### Keyed mutex timeout
- 1 second = -10000000 (in 100ns units, relative)

## 5. Files Changed

| File | Changes |
|------|---------|
| `C:\Users\ruar1337\AiDAPrivate\driver\dxgkrnl_dangling_lock_exploit_verified.cpp` | Added D3DKMT_LOCK2, D3DKMT_UNLOCK2, D3DKMT_ACQUIREKEYEDMUTEX, D3DKMT_RELEASEKEYEDMUTEX structs; added pfnD3DKMTLock2, pfnD3DKMTUnlock2, pfnD3DKMTAcquireKeyedMutex, pfnD3DKMTReleaseKeyedMutex typedefs; added SafeLock2, SafeUnlock2, SafeAcquireKeyedMutex, SafeReleaseKeyedMutex wrappers; added Lock2, Unlock2, AcquireKeyedMutex, ReleaseKeyedMutex API members and resolution in D3DKMTApi; replaced single D3DKMTLock call with 5-strategy multi-lock approach; modified texture creation to try NTHANDLE-only first (no KEYEDMUTEX); added additional NTSTATUS codes; updated debug banner |

## 6. Build Instructions

```cmd
cl.exe /nologo /W3 /MT /Fe:dxgkrnl_dangling_lock_exploit_verified.exe dxgkrnl_dangling_lock_exploit_verified.cpp /link gdi32.lib user32.lib ntdll.lib advapi32.lib d3d11.lib dxgi.lib
```

The host AI should build with the canonical build system after reviewing this changeset.
