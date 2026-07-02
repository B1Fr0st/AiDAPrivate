# Link H Verification: _setjmp Collateral Damage Analysis

## VERDICT: YES — The system survives long enough to execute GetBitmapBits successfully.

The _setjmp write corrupts 31 globals (22 distinct named symbols + padding) in win32kbase.sys `.data` section. Of these, **exactly ONE** is accessed by the GetBitmapBits critical path: `gpHandleManager` (RVA 0x250C00), which is the intended target. All other corrupted globals are either initialization-only, display-settings-related, HID-related, or memory-allocation-related — none are touched between _setjmp return and GetBitmapBits completion.

---

## 1. _setjmp jmp_buf Layout and Corrupted Global Map

**win32kbase.sys image base:** 0x1C0000000  
**RCX (jmp_buf base):** 0x1C0250BF8 (RVA 0x250BF8 = gpHandleManager - 8)  
**Write range:** [RCX+0x00] through [RCX+0xF8], 248 bytes (standard MSVC x64 `_setjmp`)

### Standard MSVC x64 jmp_buf register save order:
```
0x00: RBX    0x08: RSI    0x10: RDI    0x18: R12    0x20: R13
0x28: R14    0x30: R15    0x38: RBP    0x40: RSP    0x48: RIP
0x50: MxCsr+pad(8)    0x58: XMM6(16)    0x68: XMM7(16)    0x78: XMM8(16)
0x88: XMM9(16)    0x98: XMM10(16)    0xA8: XMM11(16)    0xB8: XMM12(16)
0xC8: XMM13(16)    0xD8: XMM14(16)    0xE8: XMM15(16)
```

### Complete Corrupted Global Map

| Offset | Register | VA | RVA | Global Name | Size | Classification |
|--------|----------|----|-----|-------------|------|----------------|
| 0x00 | RBX | 0x1C0250BF8 | 0x250BF8 | gpRGBXlate | 8 | SAFE — palette xlate, not in GetBitmapBits |
| **0x08** | **RSI** | **0x1C0250C00** | **0x250C00** | **gpHandleManager** | **8** | **THE GOAL — corrupted to fake table addr** |
| 0x10 | RDI | 0x1C0250C08 | 0x250C08 | gpTmpGlobal | 8 | SAFE — temp buffer, init/cleanup only |
| 0x18 | R12 | 0x1C0250C10 | 0x250C10 | gGDISessionLimitReachedAtLeastOnce | 1 | SAFE — boolean flag, session limit logic |
| 0x20 | R13 | 0x1C0250C18 | 0x250C18 | gpentHmgr | 8 | **SAFE — only 1 xref: HmgCreate (init)** |
| 0x28 | R14 | 0x1C0250C20 | 0x250C20 | gpGdiDevCaps | 8 | SAFE — display settings only |
| 0x30 | R15 | 0x1C0250C28 | 0x250C28 | gMaxGdiHandleCount | 4 | SAFE — handle creation/quota only |
| 0x38 | RBP | 0x1C0250C30 | 0x250C30 | GreEngLoadModuleAllocListLock | 8 | SAFE — cleanup/init semaphore |
| 0x40 | RSP | 0x1C0250C38 | 0x250C38 | gbGreSessionCleanup | 4 | SAFE — cleanup flag |
| **0x48** | **RIP** | **0x1C0250C40** | **0x250C40** | **MultiUserEngAllocListLock** | **8** | **DANGEROUS but AVOIDED** |
| 0x50 | MxCsr | 0x1C0250C48 | 0x250C48 | (unnamed padding) | 8 | SAFE — no named global |
| 0x58 | XMM6 | 0x1C0250C50 | 0x250C50 | gulDriverFailureReason | 4 | SAFE — driver failure logging |
| 0x60 | XMM6+8 | 0x1C0250C58 | 0x250C58 | gpDevicesPerLuid | 8 | SAFE — display adapter mgmt |
| 0x68 | XMM7 | 0x1C0250C60 | 0x250C60 | gpAdapterLuids | 8 | SAFE — display adapter mgmt |
| 0x78 | XMM8 | 0x1C0250C70 | 0x250C70 | gcMaximumAdapterCount | 4 | SAFE — display adapter mgmt |
| 0x80 | XMM8+8 | 0x1C0250C78 | 0x250C78 | gDrvDpiWin8Style | 4 | SAFE — DPI settings |
| 0x84 | XMM8+0xC | 0x1C0250C7C | 0x250C7C | gForceDisconnect | 4 | SAFE — display disconnect |
| 0x88 | XMM9 | 0x1C0250C80 | 0x250C80 | gdmLogPixelsOfPrimary | 2 | SAFE — DPI settings |
| 0x90 | XMM9+8 | 0x1C0250C88 | 0x250C88 | gpReferenceTracker | 8 | SAFE — init/cleanup only |
| 0x98 | XMM10 | 0x1C0250C90 | 0x250C90 | ghModHidParse | 8 | SAFE — HID init/uninit only |
| 0xA0 | XMM10+8 | 0x1C0250C98 | 0x250C98 | gpfnHidP_SetUsageValue | 8 | SAFE — HID input processing |
| 0xA8 | XMM11 | 0x1C0250CA0 | 0x250CA0 | gpfnHidP_FreeCollectionDescription | 8 | SAFE — HID input processing |
| 0xB0 | XMM11+8 | 0x1C0250CA8 | 0x250CA8 | gpfnHidP_SetUsages | 8 | SAFE — HID input processing |
| 0xB8 | XMM12 | 0x1C0250CB0 | 0x250CB0 | gpfnHidP_GetSpecificButtonCaps | 8 | SAFE — HID input processing |
| 0xC0 | XMM12+8 | 0x1C0250CB8 | 0x250CB8 | gpfnHidP_GetSpecificValueCaps | 8 | SAFE — HID input processing |
| 0xC8 | XMM13 | 0x1C0250CC0 | 0x250CC0 | gpfnHidP_GetLinkCollectionNodes | 8 | SAFE — HID input processing |
| 0xD0 | XMM13+8 | 0x1C0250CC8 | 0x250CC8 | gpfnHidP_GetCaps | 8 | SAFE — HID input processing |
| 0xD8 | XMM14 | 0x1C0250CD0 | 0x250CD0 | gpfnHidP_GetUsageValueArray | 8 | SAFE — HID input processing |
| 0xE0 | XMM14+8 | 0x1C0250CD8 | 0x250CD8 | gpfnHidP_GetUsagesEx | 8 | SAFE — HID input processing |
| 0xE8 | XMM15 | 0x1C0250CE0 | 0x250CE0 | gpfnHidP_GetUsages | 8 | SAFE — HID input processing |
| 0xF0 | XMM15+8 | 0x1C0250CE8 | 0x250CE8 | gpfnHidP_GetUsageValue | 8 | SAFE — HID input processing |

---

## 2. gpentHmgr Analysis (RVA 0x250C18, offset 0x20 = R13)

### What is it?
`gpentHmgr` is a `PEAU_ENTRY@@` (pointer to `_ENTRY` array) — a legacy GDI handle entry table pointer.

### Xref analysis (IDA Pro verified):
```
gpentHmgr (0x1C0250C18) has EXACTLY 1 xref:
  -> 0x1C006BFD4 in HmgCreate
```

**gpentHmgr is ONLY accessed by `HmgCreate` (GDI handle manager initialization).** It is NEVER accessed by:
- `HmgLock` — 0 refs to gpentHmgr, 2 refs to gpHandleManager
- `HmgShareLockCheck` — 0 refs to gpentHmgr, 4 refs to gpHandleManager
- `HmgShareLockEx` — 0 refs to gpentHmgr, 4 refs to gpHandleManager
- `DEC_SHARE_REF_CNT` — 0 refs to gpentHmgr, 1 ref to gpHandleManager
- `INC_SHARE_REF_CNT` — 0 refs to gpentHmgr, 1 ref to gpHandleManager
- `HANDLELOCK::vLockHandle` — 0 refs to gpentHmgr, refs to gpHandleManager

### Does the AFD return path access it?
No. AFD is a network driver in a separate module. It cannot directly access win32kbase globals. The AFD IOCTL completion path goes through the ntoskrnl I/O manager, which also does not touch GDI state.

### If GDI is called LATER (after bitmap R/W fix), will it crash?
If gpentHmgr remains corrupted (R13 value), a later call to `HmgCreate` would crash. However, `HmgCreate` is only called during GDI session initialization — it is not called during normal GDI operations. The exploit should restore gpentHmgr (and all other corrupted globals) after achieving kernel R/W via GetBitmapBits/SetBitmapBits.

---

## 3. MultiUserEngAllocListLock Analysis (RVA 0x250C40, offset 0x48 = RIP)

### What value is written?
The `_setjmp` return address (RIP) is written here. This is a code address (in AFD or the calling function), NOT a valid `HSEMAPHORE__` (ERESOURCE) pointer.

### What accesses it?
- `EngAllocMem` (0x1C007BAC0): 3 refs
- `EngFreeMem` (0x1C007E1D0): 3 refs
- `MultiUserGreTrackRemoveEngResource`: 3 refs
- `MultiUserGreTrackAddEngResource`: 3 refs
- `MultiUserGreCleanupEngResources`: 3 refs
- `InitializeGre`: 1 ref

### Is it accessed by GetBitmapBits?
**NO** — when bitmap format != BMF_3PLANES (3):
- `SURFMEM::bCreateDIB` is NOT called (skipped by `*(_WORD *)(v34 + 100) == 3` check)
- `EngCopyBits` is NOT called (same conditional block)
- `bDoGetSetBitmapBits` does NOT call EngAllocMem/EngFreeMem
- `SURFMEM::~SURFMEM` returns immediately when SURFMEM is zeroed (first QWORD = NULL check at 0x1C0031B49)

If EngAllocMem WERE called, it would:
1. Check `if (MultiUserEngAllocListLock)` — passes (RIP is non-null)
2. Call `ExEnterCriticalRegionAndAcquireResourceExclusive(corrupted_value)` — would try to interpret a code address as an ERESOURCE, likely causing a deadlock or crash

**This path is avoided because the exploit bitmap uses a standard format (e.g., BMF_32BPP = 6, not BMF_3PLANES = 3).**

---

## 4. GetBitmapBits Call Chain Analysis

### Complete path (verified via decompilation):

```
NtGdiGetBitmapBits (win32kfull 0x1C00182E0)
  -> GreGetBitmapBits (win32kfull 0x1C00183C4)
    -> DYNAMICMODECHANGESHARELOCK::constructor (uses ghsemDynamicModeChange, RVA 0x24EC48 — NOT CORRUPTED)
    -> SURFREF::SURFREF (win32kfull 0x1C00838AC)
      -> HmgShareLockCheck (win32kbase 0x1C002F050)
        -> HANDLELOCK::vLockHandle (win32kbase 0x1C0030A00) -> gpHandleManager ONLY
        -> GdiHandleEntryDirectory::GetEntry -> gpHandleManager+0x10 (EntryDirectory)
        -> Returns: SURFACE pointer from fake entry table
    -> SURFREFVIEW::bMap (win32kbase 0x1C007AAD0)
      -> SURFACE::Map (win32kbase 0x1C007AB20)
        -> Early return 0 for non-section bitmaps (normal case)
        -> Uses ghsemMapRot (RVA 0x24EC20 — NOT CORRUPTED) only if section mapping needed
      -> Returns 1 (success) when SURFACE::Map returns 0
    -> [format == 3 path SKIPPED]
    -> bDoGetSetBitmapBits (win32kfull 0x1C0018BA4)
      -> PDEVOBJ::vSync — operates on SURFOBJ, no global access
      -> memmove(pvBits, pvScan0 + offset, count) — READS KERNEL MEMORY via fake pvScan0
    -> SURFREFVIEW::bUnMap — cleanup, no global access
    -> SURFMEM::~SURFMEM (win32kbase 0x1C0031B30)
      -> First QWORD check: if NULL, return immediately — ZEROED SURFMEM, returns
    -> DEC_SHARE_REF_CNT (win32kbase 0x1C002F510) -> gpHandleManager ONLY
    -> DYNAMICMODECHANGESHARELOCK::destructor (uses ghsemDynamicModeChange — NOT CORRUPTED)
```

### Handle Resolution Path (the critical chain):
```
gpHandleManager (CORRUPTED = fake_table_addr)
  -> [gpHandleManager + 0x10] = GdiHandleEntryDirectory* (from fake table)
    -> GdiHandleEntryDirectory::GetEntry(directory, handle_index)
      -> [directory + 24] = entry table pointer array
      -> [table + 8 * (index >> 8)] = sub-table
      -> [sub_table + 16 * (index & 0xFF) + 8] = SURFACE pointer (FAKE SURFACE)
        -> [SURFACE + 24] = SURFOBJ
          -> SURFOBJ.pvScan0 = TARGET KERNEL ADDRESS (read via memmove)
```

---

## 5. Non-Corrupted Globals in GetBitmapBits Path

| Global | RVA | In Corrupted Range? | Used By |
|--------|-----|---------------------|---------|
| gpHandleManager | 0x250C00 | **YES (THE GOAL)** | All handle resolution |
| ghsemDynamicModeChange | 0x24EC48 | NO | DYNAMICMODECHANGESHARELOCK |
| ghsemMapRot | 0x24EC20 | NO | SURFACE::Map (section mapping) |
| ghsemHmgr | 0x2501E0 | NO | SURFMEM::~SURFMEM (real surface only) |
| gpTypeIsolation | 0x250288 | NO | SURFMEM::~SURFMEM (real surface only) |
| galBitsPerPixel | (win32kfull) | NO | bDoGetSetBitmapBits |
| gbLockEtw | 0x24EBD4 | NO | ETW tracing (various) |
| Microsoft_Windows_Win32kEnableBits | 0x255000 | NO | ETW tracing (various) |

---

## 6. AFD Return Path Analysis

The return path from _setjmp to user-mode GetBitmapBits:

```
_setjmp returns (globals corrupted)
  -> AFD IOCTL handler continues (afd.sys — separate module, no win32kbase access)
    -> IRP completion (ntoskrnl I/O manager — no GDI access)
      -> Syscall return to user mode
        -> User calls GetBitmapBits (NtGdiGetBitmapBits)
```

**No function in the AFD/ntoskrnl return path accesses any win32kbase.sys global.** AFD and ntoskrnl are separate kernel modules that do not interact with GDI state. The window between corruption and GetBitmapBits is a pure syscall return path with no GDI callbacks.

---

## 7. Summary of Dangerous Globals

| Global | Risk Level | Why It's Safe |
|--------|-----------|---------------|
| gpHandleManager | **INTENTIONAL** | Corrupted to fake table — this IS the exploit |
| MultiUserEngAllocListLock | **DANGEROUS** | EngAllocMem/EngFreeMem would crash on corrupted lock. AVOIDED because GetBitmapBits doesn't call them when format != 3 |
| gpentHmgr | **LOW** | Only 1 xref (HmgCreate). Not in handle resolution. Safe unless GDI re-initializes |
| gpRGBXlate | **LOW** | Palette functions only. Not in GetBitmapBits |
| All HID function pointers (10 globals) | **LOW** | Only accessed during HID input processing. Not in GetBitmapBits |
| All display settings globals (6 globals) | **LOW** | Only accessed during display mode changes. Not in GetBitmapBits |
| All init/cleanup globals (4 globals) | **LOW** | Only accessed during GDI init or session cleanup. Not in GetBitmapBits |

---

## 8. VERDICT

**YES — The system survives long enough to execute GetBitmapBits after the _setjmp collateral damage.**

### Evidence:
1. **gpentHmgr has exactly 1 xref** (HmgCreate, initialization only). Zero references from handle resolution functions (HmgLock, HmgShareLockCheck, HmgShareLockEx, DEC_SHARE_REF_CNT, INC_SHARE_REF_CNT, HANDLELOCK::vLockHandle).

2. **All handle resolution functions use ONLY gpHandleManager** — verified by decompilation and xref analysis. The modern Windows GDI handle table is accessed through `GdiHandleManager → GdiHandleEntryDirectory → GdiHandleEntryTable → entries`, not through the legacy `gpentHmgr` direct pointer.

3. **EngAllocMem/EngFreeMem (which access corrupted MultiUserEngAllocListLock) are NOT called** by GetBitmapBits when the bitmap format is not BMF_3PLANES (3). The exploit uses a standard bitmap format (e.g., 32BPP).

4. **SURFMEM::~SURFMEM returns immediately** when the SURFMEM structure is zeroed (first QWORD = NULL check at 0x1C0031B49). No DIB is created when format != 3, so the destructor is a no-op.

5. **The AFD return path** (IOCTL completion → I/O manager → syscall return) does not access any win32kbase globals.

6. **All non-target globals** in the corrupted range belong to subsystems (display settings, HID, palette, memory allocation) that are not invoked during the GetBitmapBits critical path.

### The complete GetBitmapBits kernel read chain:
```
gpHandleManager (FAKE) → GdiHandleEntryDirectory (FAKE) → entry table (FAKE) → SURFACE (FAKE) → SURFOBJ.pvScan0 → memmove to user buffer → KERNEL MEMORY READ
```

No corrupted global other than gpHandleManager is touched. The exploit is viable.
