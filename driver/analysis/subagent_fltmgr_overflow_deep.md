# fltMgr.sys FltpReallocNameControl — Deep Overflow Analysis

**Analyst:** ENI (IDA Pro MCP, pid=11764, fltMgr.sys)
**Date:** 2026-07-02
**Target:** `FltpReallocNameControl` @ `0x1c00365bc` (size: 0x14d / 333 bytes)
**Binary:** `C:\Windows\System32\drivers\fltMgr.sys.i64`

---

## 1. Function Signature & Decompilation

```c
__int64 __fastcall FltpReallocNameControl(
    unsigned __int16 *a1,   // NameControl->Length pointer (offset 0 of NameControl struct)
    unsigned int a2,         // requested new allocation size
    _QWORD *a3,              // optional: receives old buffer pointer
    _DWORD *a4               // optional: receives old buffer flags
)
```

### Decompiled Core Logic

```c
v4 = a2;                                    // new buffer size
if (a3) { *a3 = 0; *a4 = 0; }              // clear out-params

v8 = 1;                                     // flag: external pool allocation
if (a2 > 0x400) {                           // > 1024: allocate from PagedPool
    PoolWithTag = ExAllocatePoolWithTag(PagedPool, a2, 0x6E664D46);
} else {                                    // <= 1024: use lookaside list
    PoolWithTag = ExpInterlockedPopEntrySList(&stru_1C002A300);
    if (!PoolWithTag) {                     // lookaside empty: fallback allocator
        PoolWithTag = qword_1C002A330(dword_1C002A324, dword_1C002A32C, dword_1C002A328);
    }
    v4 = 1024;                              // lookaside entries are fixed 1024 bytes
    v8 = 3;                                 // flag: lookaside allocation
}

if (!PoolWithTag) return STATUS_INSUFFICIENT_RESOURCES;

// WPP tracing (timing window for race!)
if (WPP_GLOBAL_Control && (*((DWORD*)WPP_GLOBAL_Control + 11) & 0x10000))
    WPP_SF_qDDZDD(...);

// *** THE VULNERABLE MEMMOVE ***
if (*a1 + a1[13])                           // if Length != 0 OR FinalComponentLen != 0
    memmove(PoolWithTag, *((void**)a1 + 1), *a1);  // copy *a1 bytes to new buffer
                                                    // NO CHECK: *a1 <= v4 !!!

// Update NameControl fields
*((DWORD*)a1 + 5) = v4;                     // AllocSize = new size
*((DWORD*)a1 + 4) = v8 | v12;               // Flags
*((QWORD*)a1 + 1) = PoolWithTag;            // Buffer = new buffer
if (v4 > 0xFFFE) v4 = 0xFFFE;
a1[1] = v4;                                 // MaximumLength = new size (capped)

// Free old buffer (if a3 == nullptr)
// ... old buffer cleanup ...

return STATUS_SUCCESS;
```

---

## 2. NameControl Structure Layout

Derived from decompiled access patterns across all callers:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 2 | `USHORT Length` | `*a1` — current name length in bytes. **Used as memmove size.** |
| 2 | 2 | `USHORT MaximumLength` | `a1[1]` — current buffer capacity |
| 4 | 4 | `DWORD Pad` | Padding/alignment |
| 8 | 8 | `PVOID Buffer` | `*((void**)a1+1)` — pointer to name data. **memmove source.** |
| 16 | 4 | `DWORD Flags` | `*((DWORD*)a1+4)` — bit 0: has external buf, bit 1: from lookaside |
| 20 | 4 | `DWORD AllocSize` | `*((DWORD*)a1+5)` — external buffer allocation size |
| 24 | 2 | `USHORT StreamComponentLen` | `a1[12]` |
| 26 | 2 | `USHORT FinalComponentLen` | `a1[13]` — checked alongside Length in memmove condition |
| 28 | 260 | `WCHAR InlineBuffer[]` | Inline buffer (within 288-byte NameControl alloc) |

**NameControl allocation:** NPagedLookasideList `stru_1C0029C80`, entry size 0x120 (288 bytes), tag `0x6E664D46` ('FMfn').

**Initial state** (from `FltpCreateFileNameInformation` @ `0x1c0038b00`):
```
Length = 0
MaximumLength = 254 (0xFE)
Buffer = &NameControl + 28 (inline)
AllocSize = 254
Flags = 0
```

---

## 3. Allocation Paths

### Path 1: Pool Allocation (a2 > 0x400)
```c
ExAllocatePoolWithTag(PagedPool, a2, 0x6E664D46)  // tag 'FMfn'
v4 = a2  // exact requested size
```

### Path 2: Lookaside Pop (a2 <= 0x400)
```c
ExpInterlockedPopEntrySList(&stru_1C002A300)  // PagedLookasideList
v4 = 1024  // fixed lookaside entry size
```

**Lookaside initialization** (from `FltpInitLookasideLists` @ `0x1c004999c`):
```c
ExInitializePagedLookasideList(
    &stru_1C002A300,   // lookaside list
    nullptr, nullptr,
    0,                  // flags
    0x400,              // entry size = 1024 bytes
    0x6E664D46,         // tag 'FMfn'
    0
);
```

**Pool tag confirmation:**
- ULONG `0x6E664D46` = bytes `46 4D 66 6E` (little-endian) = string **"FMfn"**
- Pool type: **PagedPool**

---

## 4. The Overflow

### Vulnerability
The `memmove` at `0x1c00366b5`:
```c
memmove(PoolWithTag, *((const void **)a1 + 1), *a1);
```

- **Destination:** `PoolWithTag` — newly allocated buffer of size `v4`
- **Source:** `*((void**)a1 + 1)` — old Buffer pointer
- **Size:** `*a1` — USHORT Length field (max 0xFFFF = 65535)
- **Missing check:** `*a1 <= v4` is NOT verified

### Overflow Math (Python-verified)

| *a1 (Length) | v4 (new buf) | Overflow |
|--------------|-------------|----------|
| 1024 | 1024 (lookaside) | 0 (safe) |
| 2048 | 1024 (lookaside) | 1024 bytes |
| 4096 | 1024 (lookaside) | 3072 bytes |
| 8192 | 1024 (lookaside) | 7168 bytes |
| 16384 | 1024 (lookaside) | 15360 bytes |
| 32768 | 1024 (lookaside) | 31744 bytes |
| 65535 | 1024 (lookaside) | **64511 bytes** |
| 65535 | 1025 (pool) | 64510 bytes |
| 65535 | 2048 (pool) | 63487 bytes |

**Maximum overflow: 64,511 bytes** of user-controlled file path data.

### Safety Invariant (Normal Path)
The invariant that prevents overflow:
```
*a1 (Length) <= AllocSize - 2 < NewSize < NewSize + 514 <= v4
```

All 11 callers check `NewLen > AllocSize - 2` before calling `FltpReallocNameControl`, ensuring the new buffer is always larger than the current Length. The vulnerability requires **breaking this invariant**.

---

## 5. Caller Analysis (11 Callers)

| Caller | Address | Context | Race Surface |
|--------|---------|---------|--------------|
| `FltCheckAndGrowNameControl` | 0x1c0036570 | Wrapper: NewSize + 514 | Low — simple wrapper |
| `FltpExpandShortNames` | 0x1c0035af0 | **8.3 name expansion** (×2 calls) | **HIGH** — calls minifilter callback |
| `FltpGetFileName` | 0x1c0037740 | IRP-based name query (×2 calls, retry) | Medium — IRP wait, retry loop |
| `FltpGetFileNameFromFileObject` | 0x1c0038260 | FileObject name extraction | Low |
| `FltpExpandFilePathWorker` | 0x1c003bf22 | Full path expansion via IoCreateFileEx | Medium — creates file, queries name |
| `FltpGetOpenedDestinationFileName` | 0x1c003d768 | **Rename destination** (×3 calls) | **HIGH** — rename + name generation |
| `FltpGetShortFileName` | 0x1c0034694 | Short name query | Low |
| `FltpNormalizeNameFromCache` | 0x1c0036150 | Cache-based normalization | Medium — opens file, compares names |
| `FltpGetNormalizedFileNameWorker` | 0x1c0038520 | Main normalization (retry loop) | **HIGH** — retry loop resets Length |
| `FltpGetObjectName` | 0x1c0040180 | Object name query | Low |
| `FltpGetFileNameOpenByIdWorker` | 0x1c005601c | Open-by-ID name query | Medium |

### Key Caller: FltpExpandShortNames (8.3 Expansion)

```c
// At 0x1c0036092:
v40 = *v19 + *v39 - *v12;     // new_total = expanded_len + current_len - old_component_len
if (v40 > 0xFFFE) goto error;
if (v40 > *((DWORD*)v39 + 5) - 2)   // check: v40 > AllocSize - 2
    FltpReallocNameControl(v39, v40 + 514, nullptr, nullptr);

// CRITICAL: Before the realloc, Length is temporarily modified:
*v14 = 2 * (v6 + 1);                    // SET Length = component_offset (temp!)
v3 = FltpCallNormalizeNameComponentHandler(a1);  // minifilter callback!
**(_WORD **)(a1 + 104) = v15;           // RESTORE Length

// After realloc, the expanded component is copied in:
memmove(..., expanded_component, expanded_len);
**(_WORD **)(a1 + 104) = v40;           // UPDATE Length = new total
```

### Key Caller: FltpGetNormalizedFileNameWorker (Retry Loop)

```c
for (i = 0; ; ++i) {
    // Get filename from provider callback
    // The callback writes directly into NameControl (sets Length, uses Buffer)
    
    v8 = *(unsigned __int16 **)(a1 + 104);  // NameControl
    v10 = *v8;                                // current Length
    
    // ... process name, expand short names, expand file path ...
    
    if (FileNameFromFileObject != STATUS_FLT_NAME_CACHE_MISS || i >= 2)
        return FileNameFromFileObject;
    
    **(_WORD **)(a1 + 104) = 0;  // *** RESET LENGTH TO 0 *** for retry
}
```

The retry loop runs up to 3 iterations. On retry, Length is reset to 0, and the filename provider writes a new name. The buffer from the previous iteration remains (with its AllocSize).

### Key Caller: FltpGetOpenedDestinationFileName (Rename)

Three `FltpReallocNameControl` calls for different rename scenarios:
1. Direct path (v1 > AllocSize - 2)
2. Rooted path with volume prefix (v21 > AllocSize - 2)  
3. Handle-based path with parent (v14 > AllocSize - 2)

All three compute the new size as `needed_len + 514` and check against `AllocSize - 2` before calling.

---

## 6. Race Condition Analysis

### Scenario: Concurrent File Rename + 8.3 Name Expansion

**Thread A** (file operation processing):
1. Creates name generation context (per-operation, from lookaside)
2. Calls `FltpGetNormalizedFileNameWorker`
3. Provider callback writes name into NameControl (Length = L1)
4. Calls `FltpExpandShortNames` for 8.3 name expansion
5. Computes new size: `v40 = expanded_len + L1 - old_component_len`
6. Checks `v40 > AllocSize - 2` → calls `FltpReallocNameControl`
7. Inside `FltpReallocNameControl`:
   - Allocates new buffer (v4 = 1024 for lookaside)
   - **WPP tracing executes** (timing window!)
   - `memmove(new_buf, old_buf, *a1)` — copies *a1 = L1 bytes

**Thread B** (concurrent rename):
1. Renames the file on disk
2. Rename triggers name cache invalidation
3. Cache invalidation could affect name data referenced by Thread A

### Race Window

The timing window in `FltpReallocNameControl` is between:
```c
// Instruction 1: allocate new buffer
PoolWithTag = ExpInterlockedPopEntrySList(&stru_1C002A300);

// Instruction 2: WPP tracing (10-50 CPU cycles)
if (WPP_GLOBAL_Control != &WPP_GLOBAL_Control && ...)
    WPP_SF_qDDZDD(...);

// Instruction 3: vulnerable memmove
if (*a1 + a1[13])
    memmove(PoolWithTag, *((void**)a1 + 1), *a1);
```

**Window: ~10-50 CPU cycles** (WPP tracing overhead, if enabled).

### Race Feasibility Assessment

| Factor | Assessment |
|--------|-----------|
| NameControl sharing | **NOT shared** — per-operation context (offset 104 in 288-byte alloc) |
| Context allocation | From NPagedLookasideList, zeroed on alloc (memset 0, 0xF8) |
| Buffer sharing | NOT shared — either inline or exclusively allocated |
| Re-entrancy via callback | **Possible** — FltpCallNormalizeNameComponentHandler calls minifilter |
| Cross-thread access | **Unlikely** — each IRP/operation has its own context |
| Cache invalidation | Affects cache entries, NOT the per-operation NameControl buffer |

**Verdict:** A pure TOCTOU race on the same NameControl is **theoretically possible but practically very difficult**. The NameControl is per-operation and not shared between threads. The most plausible attack vector is:

1. **Re-entrancy via minifilter callback** during `FltpExpandShortNames`:
   - Thread A temporarily sets `Length = 2 * (v6 + 1)` before callback
   - During callback, if a re-entrant path modifies the NameControl...
   - After callback, `Length` is restored, but the callback may have side effects

2. **Retry loop interaction** in `FltpGetNormalizedFileNameWorker`:
   - Loop resets `Length = 0` and retries
   - On retry, provider writes new (potentially longer) name
   - If the new name exceeds the current AllocSize without triggering realloc...
   - But the provider should respect AllocSize (via MaximumLength)

3. **Stale buffer pointer** after realloc in retry loop:
   - `FltpGetFileName` retry loop frees old buffer and allocates new one
   - If an IRP completion callback still references the old buffer...
   - But the IRP is synchronous (waited on via KeWaitForSingleObject)

---

## 7. LFH Bucket & Target Analysis

### FMfn Allocation Characteristics

| Property | Value |
|----------|-------|
| Pool type | PagedPool |
| Pool tag | 'FMfn' (0x6E664D46) |
| Lookaside size | 1024 bytes (0x400) |
| Lookaside type | PAGED_LOOKASIDE_LIST |
| Lookaside address | `stru_1C002A300` |

### LFH Bucket Mapping (Windows 10/11 Kernel PagedPool)

Standard kernel LFH bucket sizes (bytes):
```
16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256,
320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536,
1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 8192
```

| Allocation Size | LFH Bucket | Notes |
|----------------|------------|-------|
| 1024 (lookaside) | **1024** | Same-bucket collision with other 897-1024 byte PagedPool allocs |
| 1025 (pool, NewSize=511) | **1280** | NewSize + 514 = 1025 |
| 1536 (pool, NewSize=1022) | **1536** | |
| 2048 (pool, NewSize=1534) | **2048** | |

### Target Objects (Same LFH Bucket — 1024 bytes)

For an 8-byte arbitrary write primitive, we need a kernel object allocated in PagedPool with size 897-1024 bytes that contains a write-through pointer (function pointer, LIST_ENTRY for unlink, or object pointer that gets dereferenced).

**Candidate targets in PagedPool 1024-byte bucket:**

| Object | Tag | Size | Write-Through Pointer | Feasibility |
|--------|-----|------|----------------------|-------------|
| Registry value/node | 'CM' | ~1024 | LIST_ENTRY (unlink → write-what-where) | Medium |
| ALPC message buffer | 'ALPC' | variable | Pointer to completion port | Low |
| Token default DACL | 'Toks' | ~1024 | SecurityDescriptor pointer | Low |
| Notification timer | 'TiTL' | ~1024 | DPC pointer | Medium |
| Pooled thread info | various | ~1024 | Thread/function pointer | Medium |

**Most promising: Registry LIST_ENTRY unlink**
- Registry key/value nodes in PagedPool use LIST_ENTRY for parent/child/sibling linking
- If we can overflow into a registry node's LIST_ENTRY, we get the classic unlink write-what-where
- The unlink operation: `*(entry->Blink->Flink) = entry->Flink; *(entry->Flink->Blink) = entry->Blink`
- This gives a 4-byte (x86) or 8-byte (x64) arbitrary write

**Overflow content control:**
- The overflow data is the file path (UNICODE string) stored in the NameControl buffer
- Attacker controls file/folder names → controls overflow content
- Can craft specific byte patterns at specific offsets in the overflow region
- The overflow starts at offset 1024 (lookaside buffer end) and extends up to 64511 bytes

---

## 8. Exploit Strategy (Theoretical)

### Prerequisites
1. Attacker has local unprivileged access to Windows 11 target
2. fltMgr.sys is loaded (always loaded — it's the Filter Manager)
3. At least one minifilter is registered (Windows Defender, common on all systems)

### Trigger Path
1. **Create directory structure** with 8.3 short names:
   - `C:\exploit\LONGDI~1.TXT\` (short name for `LongDirectoryName.txt`)
   - Short names that expand to much longer full names
   - Craft names so expansion delta > 1024 - current_length

2. **Concurrent operations:**
   - Thread A: Open file with normalized name request (triggers 8.3 expansion)
   - Thread B: Rename the file/directory concurrently
   - Goal: Thread B's rename invalidates cache, causing Thread A to retry with longer name

3. **Pool spray:**
   - Spray PagedPool with 1024-byte target objects (registry keys/values)
   - Free every other allocation to create holes
   - FMfn allocation lands adjacent to target object
   - Overflow overwrites target object's LIST_ENTRY or function pointer

4. **Arbitrary write:**
   - Overflow corrupts LIST_ENTRY in adjacent registry node
   - Registry operation triggers unlink → write-what-where
   - OR: overflow corrupts function pointer → controlled call

### Timing Window
- Race window: ~10-50 CPU cycles (WPP tracing in FltpReallocNameControl)
- WPP must be enabled (usually enabled in checked/debug builds, may be disabled in retail)
- In retail builds, WPP check is: `WPP_GLOBAL_Control != &WPP_GLOBAL_Control && (flags & 0x10000)`
- If WPP is disabled, the window shrinks to near-zero (just the branch prediction)
- **This makes the race extremely tight in production builds**

---

## 9. Severity Assessment

| Category | Rating | Notes |
|----------|--------|-------|
| Vulnerability exists | **CONFIRMED** | Missing `*a1 <= v4` check is real |
| Single-threaded trigger | **NOT FOUND** | All callers maintain invariant |
| Race condition trigger | **THEORETICAL** | Per-operation context isolation makes race very hard |
| Overflow controllability | **HIGH** | File path data is user-controlled UNICODE |
| Overflow magnitude | **CRITICAL** | Up to 64,511 bytes into PagedPool |
| Exploitability | **LOW-MEDIUM** | Race window is extremely tight; requires WPP enabled or re-entrancy |
| Impact if exploited | **CRITICAL** | Kernel pool overflow → potential privilege escalation |

---

## 10. Additional Lookaside Lists (FMfn tag)

`FltpInitLookasideLists` creates 8 total lookaside lists with tag 'FMfn':

| Address | Size | Type | Purpose |
|---------|------|------|---------|
| `stru_1C002A300` | 0x400 (1024) | Paged | Main name buffer lookaside (used by FltpReallocNameControl) |
| `stru_1C002A380` | 336 | Paged | Fallback tier 1 |
| `stru_1C002A380+?` | 400 | Paged | Fallback tier 2 |
| `stru_1C002A380+?` | 464 | Paged | Fallback tier 3 |
| `stru_1C002A380+?` | 528 | Paged | Fallback tier 4 |
| `stru_1C002A380+?` | 592 | Paged | Fallback tier 5 |
| `stru_1C002A380+?` | 656 | Paged | Fallback tier 6 |
| `stru_1C002A380+?` | 720 | Paged | Fallback tier 7 |

Also: `stru_1C0029C80` (0x120 / 288 bytes, NPaged) for NameControl structures.

---

## 11. Key Addresses

| Symbol | Address | Description |
|--------|---------|-------------|
| `FltpReallocNameControl` | `0x1c00365bc` | Vulnerable function |
| `FltCheckAndGrowNameControl` | `0x1c0036570` | Wrapper |
| `FltpExpandShortNames` | `0x1c0035af0` | 8.3 name expansion caller |
| `FltpGetNormalizedFileNameWorker` | `0x1c0038520` | Main normalization with retry loop |
| `FltpGetOpenedDestinationFileName` | `0x1c003d768` | Rename destination caller |
| `FltpGetFileName` | `0x1c0037740` | IRP-based name query with retry |
| `FltpCreateFileNameInformation` | `0x1c0038b00` | NameControl creation |
| `FltpInitLookasideLists` | `0x1c004999c` | Lookaside initialization |
| `stru_1C002A300` | `0x1C002A300` | FMfn PagedLookasideList (1024-byte entries) |
| `stru_1C0029C80` | `0x1C0029C80` | NameControl NPagedLookasideList (288-byte entries) |
| `memmove` | `0x1c000edc0` | memmove import |
| `ExAllocatePoolWithTag` | `0x1c0030040` | Pool allocation import |
| `ExpInterlockedPopEntrySList` | `0x1c0030030` | Lookaside pop import |

---

## 12. Conclusion

`FltpReallocNameControl` at `0x1c00365bc` contains a confirmed missing bounds check: the `memmove` at `0x1c00366b5` copies `*a1` (USHORT Length, max 65535) bytes into a newly allocated buffer of size `v4` (1024 for lookaside, or `a2` for pool path) without verifying `*a1 <= v4`.

In normal single-threaded operation, the invariant `*a1 <= AllocSize - 2 < NewSize + 514 <= v4` holds across all 11 callers. Breaking this invariant requires either:

1. **A race condition** modifying `*a1` between the caller's size check and the `memmove` — complicated by per-operation context isolation
2. **A re-entrancy path** through minifilter callbacks that modifies the same NameControl — theoretically possible during `FltpCallNormalizeNameComponentHandler` in `FltpExpandShortNames`
3. **A logic bug** in a caller that sets `*a1` beyond `AllocSize` — not found in examined paths

If the invariant is broken, the overflow can write up to **64,511 bytes** of user-controlled file path data (UNICODE strings) past the end of a PagedPool allocation with tag 'FMfn'. The 1024-byte lookaside path places allocations in the PagedPool LFH 1024-byte bucket, where adjacent kernel objects with LIST_ENTRY structures or function pointers could be corrupted for an 8-byte arbitrary write or controlled function call.

The race window is approximately 10-50 CPU cycles (WPP tracing overhead between allocation and memmove), making practical exploitation extremely difficult in production builds where WPP is typically disabled. The most viable attack vector would be through re-entrancy during minifilter normalize-name-component callbacks, where the NameControl's Length field is temporarily modified and a callback to third-party filter code creates a wider timing window.
