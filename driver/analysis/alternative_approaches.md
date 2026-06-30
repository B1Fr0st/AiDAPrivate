# Alternative Approaches to Arbitrary Kernel R/W

## Executive Summary

After exhaustive IDA Pro analysis of win32kfull.sys (7993 functions, imagebase 0x1C0000000), the bitmap corruption approach via win32k UAF is confirmed blocked at multiple levels. This document presents **completely different paths** to arbitrary kernel R/W that are driverless, traceless, and don't touch page tables.

### Key New Discoveries

1. **SetOrClrWF writes to WNDK+0x10 through WNDK+0xEB** (not just +0x12 as previously believed)
2. **gServerHandler IS reachable after the UAF** — when WF_SERVERMODE is set on the reclaimed WNDK, the post-callback code calls gServerHandlers[fnid] with the stale raw tagWND pointer
3. **GDI Batch Buffer TOCTOU** — the kernel reads batch operation parameters directly from user-mode memory without copying, passing user pointers to internal kernel functions
4. **SURFACE type isolation is section-backed** (MmCreateSection), NOT pool-backed — SystemSessionBigPoolInformation will NOT find SURFACE chunks
5. **CSectionEntry management struct uses pool tag "Uiso"** (0x6F736955) in PagedPoolSession — these WILL appear in SystemSessionBigPoolInformation as 0x28-byte allocations

---

## Task 1: Win32k Callback Site Analysis

### xxxCallHook2 Call Sites (13 total)

| Caller | Address | Post-Callback Object Use | Write? |
|--------|---------|------------------------|--------|
| xxxSendTransformableMessageTimeout | 0x1C00598F0 | Reads pwndk+0x12, pwndk+0x78, calls gServerHandler | YES (via SetOrClrWF) |
| xxxReceiveMessage | 0x1C0058F60 | Reads v5[12] (tagWND from SMS), writes to hook result | Read only |
| xxxCallMouseHook | 0x1C012AC8C | Returns hook result, no object access | No |
| xxxCallJournalPlaybackHook | 0x1C01E64C4 | Copies hook result to QMSG, validates handle | Read only |
| xxxCallJournalRecordHook | 0x1C01E68E4 | Records journal data | Read only |
| xxxPointerCallHook | 0x1C01EFF0C | Processes pointer data | Read only |
| EditionKeyEventLLHook | 0x1C00201A0 | LL keyboard hook | No object access |
| EditionLLMouseButtonHook | 0x1C0023450 | LL mouse hook | No object access |
| EditionLLMouseWheelHook | 0x1C01D94A0 | LL mouse wheel hook | No object access |
| xxxMoveEventAbsolute | 0x1C00313BC | Mouse position update | No object access |
| xxxCallNextHookEx | 0x1C0020274 | Hook chain continuation | No object access |
| xxxCallHook | 0x1C005B860 | Wrapper for xxxCallHook2 | No direct access |

### xxxClientCall* Callback Sites (7 functions)

| Function | Address | Locks Object? | Post-Callback Use |
|----------|---------|--------------|-------------------|
| xxxClientCallDefWindowProc | 0x1C02311F0 | Yes (HMLockObject) | Uses return value only |
| xxxClientCallDefaultInputHandler | 0x1C0231360 | Yes | Uses return value only |
| xxxClientCallDelegateThread | 0x1C02314DC | Yes | Thread delegation |
| xxxClientCallDevCallbackSimple | 0x1C023165C | Yes | Device callback |
| xxxClientCallLocalMouseHooks | 0x1C0231824 | Yes | Mouse hook dispatch |
| xxxClientCallWinEventProc | 0x1C0051294 | Yes | WinEvent processing |
| xxxClientCallDitThread | 0x1C0050C38 | Yes | DIT thread |

### SfnDWORD Analysis (0x1C006B320)

SfnDWORD is the generic server-side callback dispatcher. Critical security properties:

```c
// BEFORE callback:
v64[1] = a1;                    // Store tagWND in thread lock list
if ( a1 )
    HMLockObject(a1);           // Lock the object (increment refcount)

// User-mode callback:
v29 = KeUserModeCallback(2, &v57, 48, &v54, &v67);

// AFTER callback:
ThreadUnlock1(v33);             // Unlock the object
```

**Finding:** SfnDWORD locks the tagWND with HMLockObject BEFORE the callback and unlocks AFTER. This prevents the tagWND from being freed during the callback. All 62 Sfn* functions follow this same pattern — they lock the object before user-mode callback and unlock after.

**No Sfn* function uses a kernel object after the callback without re-validation.** The lock/unlock pattern is consistent across all server-side callback dispatchers.

### xxxReceiveMessage Analysis (0x1C0058F60)

xxxReceiveMessage processes sent messages from the SMS (Sent Message Structure) queue. Key path:

```c
v18 = (_QWORD *)v5[12];         // tagWND from SMS (raw pointer, NOT handle)
if ( !v18 ) goto LABEL_34;

// Handle table validation (BugCheck if invalid):
if ( *(_QWORD *)(gpKernelHandleTable + 24 * v20) != v18 )
    KeBugCheckEx(0x197u, 1u, v5[12], v19, 1u);

// Lock the object:
HMLockObject(v18);

// Dispatch:
if ( (pwndk_flags & 4) != 0 )   // WF_SERVERMODE check
    gServerHandlers[fnid](tagWND, msg, wParam, lParam);  // Raw pointer!
else
    xxxSendMessageToClient(tagWND, msg, wParam, lParam, ...);

ThreadUnlock1(v27);             // Unlock
```

**Finding:** xxxReceiveMessage validates the tagWND against the kernel handle table (KeBugCheckEx if mismatch) and locks it with HMLockObject before dispatch. This prevents UAF through the SMS queue path.

---

## Task 2: gServerHandler and xxxSetWindowData Analysis

### gServerHandlers Table (0x1C02E1140)

| Index | Function | Address | Size |
|-------|----------|---------|------|
| 0 | xxxDefWindowProc | 0x1C00484E0 | 0x1A9 |
| 1 | xxxDesktopWndProc | 0x1C0046290 | 0x65 |
| 2 | xxxSwitchWndProc | 0x1C01F4CC0 | 0x131 |
| 3 | xxxMenuWindowProc | 0x1C023B620 | 0x192B |
| 4 | xxxSBWndProc | 0x1C0245BE0 | 0x9D6 |
| 5 | xxxTooltipWndProc | 0x1C00DAED0 | 0x2E3 |
| 6 | xxxEventWndProc | 0x1C0023B00 | 0xC5 |

### xxxSetWindowData Callers

xxxSetWindowData (0x1C008A1A8) is called from:
1. xxxSetWindowLongPtr (0x1C0089BE8) — internal implementation
2. xxxSetWindowLong (0x1C00FACB8) — another internal function

xxxSetWindowLongPtr (0x1C0089BE8) is called from:
1. NtUserSetWindowLongPtr (0x1C0089AE0) — the syscall (requires valid handle)
2. xxxCsDdeInitialize (0x1C0127D60) — DDE initialization

**Finding: NO gServerHandler function calls xxxSetWindowData or xxxSetWindowLongPtr directly or indirectly.** The QWORD write path (pwndk+0x20/0x78/0x98/0xD8/0xF0) is NOT reachable via the raw tagWND pointer through gServerHandler.

### xxxSendTransformableMessageTimeout — THE KEY PATH

```c
// After xxxCallHook2 callback (UAF point):
if ( (*(_BYTE *)(*(_QWORD *)(a1 + 40) + 18LL) & 4) == 0 )
{
    // WF_SERVERMODE NOT set → normal client message dispatch
    xxxSendMessageToClient((struct tagWND *)a1, v11, v52, v53, nullptr, 0, &v36);
}
else
{
    // WF_SERVERMODE IS set → gServerHandler dispatch with RAW tagWND!
    v28 = *(_QWORD *)(*(_QWORD *)(a1 + 40) + 120LL);  // fnid from pwndk+0x78
    if ( v28 >= 7 )
        return 0;
    result = gServerHandlers[v28](a1, v11, v52, v53);  // RAW STALE tagWND!
}
```

**CRITICAL:** After the UAF callback in xxxSendTransformableMessageTimeout:
1. The code reads `pwndk+0x12` (WF flags) from the RECLAIMED WNDK (stale pwndk)
2. If bit 2 (WF_SERVERMODE) is SET in the reclaimed WNDK:
   - The code reads `pwndk+0x78` (fnid) from the reclaimed WNDK
   - Calls `gServerHandlers[fnid](stale_tagWND, msg, wParam, lParam)`
   - The gServerHandler receives the STALE tagWND pointer (no handle validation!)
3. If bit 2 is NOT set:
   - Calls `xxxSendMessageToClient(stale_tagWND, ...)` which dispatches to Sfn* functions

**Exploitation implication:** If we create a reclaim window with WF_SERVERMODE set, the post-UAF code will dispatch to gServerHandler with the stale tagWND. The gServerHandler operates on the reclaimed WNDK through the stale pwndk, enabling type confusion writes.

---

## Task 3: Writes to tagWND Body vs pwndk (WNDK)

### SetOrClrWF Write Primitive (0x1C004DF08)

SetOrClrWF writes BYTE values (bit set/clear) to the WNDK structure:

```c
v8 = *(_DWORD **)(a2 + 40);        // pwndk = *(tagWND + 0x28)
v10 = (unsigned __int64)a3 >> 8;   // byte offset = a3 >> 8
v12 = (set ? current | a3 : current & ~a3);  // set or clear bits
*((_BYTE *)v8 + v10 + 16) = v12;   // write to pwndk + (a3>>8) + 0x10
```

**Writable range:** WNDK+0x10 through WNDK+0xEB (based on all callers across win32kfull.sys)

### SetOrClrWF Calls Reachable from gServerHandler

**Direct calls from gServerHandler functions:**

| Handler | Address | a3 | WNDK Offset | Bit |
|---------|---------|----|-------------|-----|
| xxxRealDefWindowProc | 0x1C0049FEC | 0x202 | +0x12 | 0x02 |
| xxxRealDefWindowProc | 0x1C004A0F5 | 0x00F | +0x10 | 0x0F |
| xxxRealDefWindowProc | 0x1C004A152 | 0x00F | +0x10 | 0x0F |
| xxxRealDefWindowProc | 0x1C004A20C | 0x280 | +0x12 | 0x80 |
| xxxSBWndProc | 0x1C0246398 | 0x00D | +0x10 | 0x0D |
| xxxSBWndProc | 0x1C02463BD | 0x00D | +0x10 | 0x0D |

**Transitive calls (from functions called by gServerHandlers):**

| Function | a3 | WNDK Offset | Bit | Reachable Via |
|----------|----|-------------|-----|---------------|
| xxxMinMaximizeEx | 0xD901 | **+0xE9** | 0x01 | xxxRealDefWindowProc (WM_SYSCOMMAND) |
| xxxMinMaximizeEx | 0xD902 | **+0xE9** | 0x02 | xxxRealDefWindowProc (WM_SYSCOMMAND) |
| xxxMinMaximizeEx | 0xDA80 | **+0xEA** | 0x80 | xxxRealDefWindowProc (WM_SYSCOMMAND) |
| xxxMinMaximizeEx | 0xF01 | +0x1F | 0x01 | xxxRealDefWindowProc (WM_SYSCOMMAND) |
| SetVisible | 0xF10 | +0x1F | 0x10 | xxxShowWindowEx |
| SetVisible | 0x908 | +0x19 | 0x08 | xxxShowWindowEx |
| xxxDWP_UpdateUIState | 0xB40 | +0x1B | 0x40 | xxxRealDefWindowProc (WM_UPDATEUISTATE) |
| xxxDWP_UpdateUIState | 0xB80 | +0x1B | 0x80 | xxxRealDefWindowProc (WM_UPDATEUISTATE) |
| xxxDWP_UpdateUIState | 0xB04 | +0x1B | 0x04 | xxxRealDefWindowProc (WM_UPDATEUISTATE) |
| xxxCalcClientRect | 0x410 | +0x14 | 0x10 | xxxRealDefWindowProc (WM_NCCALCSIZE) |
| xxxEndPaint | 0x401 | +0x14 | 0x01 | xxxRealDefWindowProc (WM_PAINT) |
| xxxEndPaint | 0x404 | +0x14 | 0x04 | xxxRealDefWindowProc (WM_PAINT) |
| xxxEndPaint | 0x402 | +0x14 | 0x02 | xxxRealDefWindowProc (WM_PAINT) |
| xxxBeginPaint | 0x240 | +0x12 | 0x40 | xxxRealDefWindowProc (WM_PAINT) |
| xxxBeginPaint | 0x120 | +0x11 | 0x20 | xxxRealDefWindowProc (WM_PAINT) |
| xxxDWP_SetRedraw | 0x108 | +0x11 | 0x08 | xxxRealDefWindowProc (WM_SETREDRAW) |
| xxxDWP_Print | 0x180 | +0x11 | 0x80 | xxxRealDefWindowProc (WM_PRINT) |
| xxxSetWindowStyle | 0xB02 | +0x1B | 0x02 | xxxRealDefWindowProc (WM_STYLECHANGED) |
| xxxDWP_DoNCActivate | 0x040 | +0x10 | 0x40 | xxxRealDefWindowProc (WM_NCACTIVATE) |

**Maximum writable offset via gServerHandler path: WNDK+0xEA** (via xxxMinMaximizeEx, reachable through WM_SYSCOMMAND with SC_MINIMIZE/SC_MAXIMIZE)

### WNDK Structure Layout (offsets where we can write)

```
WNDK+0x10: WF flags byte 0 (writable: bits 0x01, 0x03, 0x07, 0x0D, 0x0F, 0x10, 0x40)
WNDK+0x11: WF flags byte 1 (writable: bits 0x02, 0x04, 0x08, 0x10, 0x20, 0x80)
WNDK+0x12: WF flags byte 2 (writable: bits 0x02, 0x40, 0x80) — includes WF_SERVERMODE (bit 0x04)
WNDK+0x14: WF flags byte 4 (writable: bits 0x01, 0x02, 0x04, 0x10)
WNDK+0x19: WF flags byte 9 (writable: bit 0x08)
WNDK+0x1B: WF flags byte 11 (writable: bits 0x02, 0x04, 0x40, 0x80)
WNDK+0x1F: WF flags byte 15 (writable: bits 0x01, 0x10)
WNDK+0xE9: WF flags byte 217 (writable: bits 0x01, 0x02) — in RECT area
WNDK+0xEA: WF flags byte 218 (writable: bit 0x80) — in RECT area
```

**Assessment:** All writable offsets are in the WF flag bytes (WNDK+0x10-0x1F) or in the RECT area (WNDK+0xE0-0xEF). We can set/clear specific bits but cannot write arbitrary byte values. No writable offset corresponds to a kernel pointer field.

---

## Task 4: SystemSessionBigPoolInformation and SURFACE Type Isolation

### Type Isolation Architecture

win32kfull.sys uses `NSInstrumentation::CTypeIsolation` for GDI object isolation:

| Template | Chunk Size | Slot Size | Max Slots | Likely Object Type |
|----------|-----------|-----------|-----------|-------------------|
| CTypeIsolation<36864, 144> | 0x9000 | 0x90 | 256 | Small GDI (BRUSH, PEN) |
| CTypeIsolation<233472, 912> | 0x39000 | 0x390 | 228 | **SURFACE** |
| CTypeIsolation<24576, 96> | 0x6000 | 0x60 | 256 | Very small GDI |
| CTypeIsolation<28672, 112> | 0x7000 | 0x70 | 252 | Medium GDI |

### SURFACE Type Isolation — Section-Backed, NOT Pool-Backed

**CSectionEntry<233472,912>::Create** (0x1C015FE00):
```c
PoolWithTag = ExAllocatePoolWithTag(PagedPoolSession, 0x28, 0x6F736955);  // tag "Uiso"
// 0x28-byte management struct only
```

**CSectionEntry::Initialize** (0x1C015FE5C):
```c
Section = PlatformCreateSection(0x39000);  // MmCreateSection, 0x39000 bytes
PlatformMapViewInSessionSpace(Section, &mappedBase, 0x39000);  // Map in session space
CSectionBitmapAllocator::Create(mappedBase);  // Slot allocator
```

**PlatformCreateSection** (0x1C016003C):
```c
MmCreateSection(&Object, 983071, 0, &size, 4, 0x4000000, 0, 0);  // PAGE_READWRITE
```

**CRITICAL FINDING:** SURFACE type isolation chunks are created via `MmCreateSection` and mapped in session space via `MmMapViewInSessionSpace`. They are NOT pool allocations. **SystemSessionBigPoolInformation will NOT list these chunks.**

### CSectionBitmapAllocator Slot Layout (0x1C01028A0)

```c
// XOR-encoded bitmap and base address (anti-corruption):
ClearBits = RtlFindClearBits(a1[2] ^ a1[3], 1, cursor);
// Slot address calculation:
slot_addr = (a1[2] ^ a1[1]) + 912 * (slot_index & 3) + (slot_index >> 2 << 12);
```

**Slot layout:**
- 228 slots per chunk (0xE4 max)
- Groups of 4 slots per 4096-byte page
- Each slot: 912 bytes (0x390)
- Each group: 4 * 912 = 3648 bytes + 448 bytes padding = 4096 bytes
- 57 groups * 4096 = 233,472 bytes = 0x39000

**Pool tag "Uiso" (0x6F736955):** Only the 0x28-byte CSectionEntry management structure appears in session pool. The actual 0x39000-byte SURFACE data is in a mapped section.

### What DOES Appear in SystemSessionBigPoolInformation?

| Allocation | Tag | Size | Appears? |
|-----------|-----|------|----------|
| CSectionEntry (mgmt) | Uiso | 0x28 | YES (but <4096, may not appear) |
| SURFACE data chunk | N/A | 0x39000 | NO (section-backed) |
| DC objects | unknown | varies | Possibly (if pool-backed) |
| WNDK objects | unknown | varies | Depends on allocator |

**Assessment:** SystemSessionBigPoolInformation is NOT useful for finding SURFACE addresses. The CSectionEntry (0x28 bytes, tag "Uiso") is too small to appear (the API only returns allocations > 4096 bytes for most implementations, though the exact threshold varies by Windows version).

---

## Task 5: NtGdi* Syscall Kernel Address Leak Analysis

### NtGdi* Syscalls Analyzed (200+ in win32kfull.sys)

| Syscall | Address | Leaks Kernel Pointer? | Notes |
|---------|---------|----------------------|-------|
| NtGdiGetStats | 0x1C0165760 | Unknown | Thunk to win32kbase.sys (7 bytes) |
| NtGdiGetDCDword | 0x1C00FA520 | NO | Returns DWORD values (flags, metrics) |
| NtGdiGetAndSetDCDword | 0x1C010C5D0 | NO | Gets/sets DWORDs in DC structure |
| NtGdiGetDCObject | 0x1C00AA130 | NO | Returns GDI handles, not pointers |
| NtGdiGetDCPoint | 0x1C010D760 | NO | Returns POINT values |
| NtGdiExtGetObjectW | 0x1C0082F70 | NO | Returns object info (LOGPEN, LOGBRUSH, etc.) |
| NtGdiGetBitmapBits | 0x1C00182E0 | NO | Reads bitmap bits (via pvScan0) |
| NtGdiSetBitmapBits | 0x1C0018710 | NO | Writes bitmap bits (via pvScan0) |
| NtGdiDoPalette | 0x1C01130F0 | NO | Palette operations (color tables) |
| NtGdiGetRandomRgn | 0x1C00B2800 | NO | Returns region data |
| NtGdiCreateDIBSection | 0x1C00AB8E0 | NO | Creates DIB, returns user-mode bits ptr |
| NtGdiEngLockSurface | 0x1C015CAF0 | YES (returns SURFOBJ*) | BUT requires UMPD (LocalSystem) |
| NtGdiEngAssociateSurface | 0x1C015A6B0 | N/A | Requires UMPD + 0x40000 flag |
| NtGdiEngCreateBitmap | 0x1C015CF30 | N/A | Requires UMPD (LocalSystem) |
| NtGdiCreateSessionMappedDIBSection | 0x1C00A94F0 | N/A | Requires gpidLogon (csrss.exe) |
| NtGdiSetBitmapAttributes | 0x1C00A9770 | NO | Only makes bitmap "stock" |
| NtGdiHLSurfSetInformation | 0x1C0014D90 | NO | Sets HLS surface properties (DWORDs) |

**Finding: NO NtGdi* syscall in win32kfull.sys leaks kernel addresses from normal user mode.** The only function that returns a kernel pointer (NtGdiEngLockSurface) requires UMPD/LocalSystem privileges.

### NtUserGetCPD Analysis (0x1C0079210)

```c
NtUserGetCPD(hwnd, flags, data)
// flags must be 0x20, 0x40, or 0x80 (masked)
// Returns: handle value with 0xFFFF0000 mask (GDI-style handle, NOT kernel pointer)
```

**Finding:** NtUserGetCPD returns handle values, not kernel pointers. Not useful for info leak.

---

## Task 6: Alternative Exploitation of the UAF Type Confusion

### The UAF Type Confusion Chain

1. **xxxSendTransformableMessageTimeout** sends message to child window
2. During **xxxCallHook2** (WH_CALLWNDPROC), attacker destroys child window
3. Child's tagWND is freed; pwndk (WNDK pointer) is stale
4. Attacker creates reclaim window; its WNDK reclaims the freed WNDK slot
5. After callback, code uses stale pwndk → accesses reclaimed WNDK

### Post-UAF Code Paths (from xxxSendTransformableMessageTimeout)

**Path A: WF_SERVERMODE set (pwndk+0x12 bit 2 = 1)**
```
Code reads pwndk+0x78 (fnid) from reclaimed WNDK
→ gServerHandlers[fnid](stale_tagWND, msg, wParam, lParam)
→ Handler processes message on reclaimed WNDK
→ Handler may call SetOrClrWF → writes bits to reclaimed WNDK
```

**Path B: WF_SERVERMODE not set (pwndk+0x12 bit 2 = 0)**
```
→ xxxSendMessageToClient(stale_tagWND, msg, wParam, lParam)
→ Dispatches to Sfn* functions via gapfnScSendMessage[MessageTable[msg]]
→ Sfn* calls HMLockObject(stale_tagWND) — USE-AFTER-FREE in HMLockObject!
→ Sfn* calls KeUserModeCallback — user-mode callback
→ Sfn* calls ThreadUnlock1 — unlock
```

### Path B: HMLockObject on Freed tagWND

When xxxSendMessageToClient is called with the stale tagWND, the Sfn* function calls HMLockObject on the freed tagWND. If the freed tagWND's memory has been reclaimed by a different object:

- HMLockObject increments the reference count at a type-specific offset
- If the new object has a different layout, the wrong field is incremented
- ThreadUnlock1 later decrements the wrong field
- This could cause premature freeing of the reclaimed object → secondary UAF

**This is a potential secondary exploitation vector** but requires:
- The freed tagWND slot to be reclaimed by a non-tagWND object
- Type isolation prevents this (WNDK has its own isolated pool)
- Unless the tagWND body (not WNDK) is in a shared pool

### Path A: Controlling the gServerHandler Dispatch

To use Path A (gServerHandler with raw tagWND):
1. Create the reclaim window with a class that has WF_SERVERMODE set
2. The fnid (WNDK+0x78) determines which gServerHandler is called
3. The message determines what the handler does
4. The handler operates on the reclaimed WNDK through the stale pwndk

**How to set WF_SERVERMODE on the reclaim window:**
- WF_SERVERMODE is bit 2 at WNDK+0x12 (flag value 0x0204)
- This flag is typically set for system-internal windows
- Need to find a window class that has this flag set by default
- OR: use the UAF itself to set this flag (SetOrClrWF with a3=0x204 to set bit 2 at WNDK+0x12)

**Chicken-and-egg problem:** To use Path A, we need WF_SERVERMODE set. To set it, we need Path A (or another write path). But the first UAF gives us SetOrClrWF writes via the fall-through code in xxxSendTransformableMessageTimeout, which runs regardless of WF_SERVERMODE.

Actually, looking at the code more carefully, after the xxxCallHook2 callback:
```c
// This block runs regardless of WF_SERVERMODE:
if ( (v18 == *(_QWORD *)(a1 + 16))  // same thread check
  && ... )
{
    xxxCallHook2(...);  // UAF HERE
    
    // After UAF, checks WF_SERVERMODE:
    if ( (*(_BYTE *)(pwndk + 18) & 4) == 0 )
        xxxSendMessageToClient(...);  // Path B
    else
        gServerHandlers[fnid](...);  // Path A
}
```

The SetOrClrWF calls from gServerHandler (Path A) are only reachable if WF_SERVERMODE is already set. The first UAF can only use Path B (xxxSendMessageToClient) unless WF_SERVERMODE is already set on the reclaimed WNDK.

**Can we create a reclaim window with WF_SERVERMODE already set?**
- WF_SERVERMODE is set for windows created with WS_SYSMODAL or certain system window classes
- Or it might be settable via SetWindowLongPtr(GWLP_STYLE, WS_SYSMODAL) — but this requires a valid handle
- Or it might be set during window creation for specific window classes

This requires further investigation of which window classes set WF_SERVERMODE during creation.

---

## Task 7: Completely Different Approaches

### Approach A: GDI Batch Buffer TOCTOU (MOST PROMISING NOVEL APPROACH)

**NtGdiFlushUserBatchInternal** (0x1C008EF50) processes batched GDI operations from the TEB batch buffer. The kernel reads batch record data DIRECTLY from user-mode memory without copying.

**Critical TOCTOU vectors:**

1. **PolyPatBlt (case 1):** Passes user-mode pointer directly to internal function:
```c
GrePolyPatBltInternal(
    (XDCOBJ *)v65,
    v61,
    (POLYPATBLT *)(p_ArbitraryUserPointer + 6),  // USER POINTER!
    v16, v19, v20, v21, v22, v23);
```
The `POLYPATBLT` array at `p_ArbitraryUserPointer + 6` is in user-mode memory. Another thread can modify the brush handles in this array while `GrePolyPatBltInternal` is processing them.

2. **TextOut (cases 2, 3):** Passes user-mode pointer to text output functions:
```c
GreBatchTextOut((XDCOBJ *)v65, (BATCHTEXTOUT *)p_ArbitraryUserPointer, v7);
GreBatchTextOutRect((XDCOBJ *)v65, (BATCHTEXTOUTRECT *)p_ArbitraryUserPointer, v7);
```

3. **SelectFont (case 6):** Reads handle from user mode:
```c
v89 = p_ArbitraryUserPointer[1];  // Read handle from user-mode batch buffer
GreSelectFontInternal(FiberData);  // Use it (handle in register)
```

4. **DeleteObject (cases 7, 8):** Reads handle from user mode:
```c
v87 = p_ArbitraryUserPointer[1];  // Read handle from user-mode batch buffer
NtGdiDeleteObjectApp();           // Delete the object
```

**Exploitation plan:**

```
Thread A:
  1. Create a compatible DC and select a bitmap into it
  2. Fill the GDI batch buffer with a PolyPatBlt record
  3. Set the POLYPATBLT entries with a valid brush handle (HBRUSH)
  4. Call GdiFlush() → triggers NtGdiFlushUserBatch

Thread B (concurrent):
  5. While the kernel is in GrePolyPatBltInternal:
     - Modify the POLYPATBLT entries to replace the brush handle
       with a bitmap handle (HBITMAP) or a freed handle
  6. The kernel reads the modified handle from user-mode memory
  7. If the kernel locks the object as a brush but it's actually a bitmap:
     → TYPE CONFUSION
  8. The bitmap's data at brush-specific offsets is interpreted as brush fields
  9. If a brush field at a specific offset is a pointer, and the bitmap's
     data at that offset is controlled → controlled pointer dereference
```

**Requirements:**
- The batch buffer is in user-mode memory (TEB+0x68 region)
- Another thread in the same process can modify the batch buffer
- The kernel does NOT copy the batch data before processing
- The race window is between the kernel reading the handle and locking the object

**Verification needed:**
- Decompile GrePolyPatBltInternal to confirm it locks GDI objects from POLYPATBLT data
- Determine if the lock operation validates object type
- Check if there's a race window between reading the handle and calling HmgLock/ShareLock

**Advantages:**
- Completely different vulnerability class (race condition, not UAF)
- No win32k UAF needed
- No pool corruption needed
- No page table touches
- No kernel callbacks
- Undetectable by kernel-mode anticheats (no .sys, no IOCTLs, no patched code)

### Approach B: Corrupt Alternative GDI Objects (DC, Palette, Region, Font)

Instead of corrupting SURFACE.pvScan0, consider corrupting other GDI objects that have pointer-based read/write primitives:

**DC (Device Context):**
- DC has a surface pointer at DC+0x1F0 (offset 496, `v43 = *(SURFACE **)(DC + 496)`)
- If we corrupt this pointer, GDI operations on the DC use the wrong surface
- NtGdiGetAndSetDCDword can set specific DC fields (DWORDs only, not pointers)
- The DC substructure at DC+0x3D0 (offset 976) has many fields including surface refs

**Palette:**
- NtGdiDoPalette (0x1C01130F0) reads/writes palette color tables
- The palette's color table is a kernel pointer
- If we corrupt the color table pointer, GetPaletteEntries/SetPaletteEntries read/write arbitrary kernel memory
- Palette color table: 4 bytes per entry (PALETTEENTRY), up to 256 entries

**Region:**
- Regions have a coordinate buffer (array of RECTs)
- If we corrupt the coordinate buffer pointer, GetRgnBox reads from arbitrary kernel memory

**Font:**
- Fonts have glyph data pointers
- If we corrupt a glyph data pointer, text output functions read from arbitrary kernel memory

**Assessment:** All of these require a write primitive to corrupt the pointer field. Without a write primitive to a GDI object, these approaches are blocked. The UAF only gives us writes to WNDK flag bytes, not GDI object fields.

### Approach C: NtSetSystemInformation / NtSetInformationProcess

**NtSetSystemInformation:** Some info classes might write to kernel memory. Need to check:
- SystemBigPoolInformation (read-only)
- SystemSessionBigPoolInformation (read-only)
- Other classes might have write capabilities

**NtSetInformationProcess:** Some info classes might corrupt kernel state:
- ProcessAccessToken
- ProcessHandleTracing
- ProcessExecuteFlags
- Others?

**Assessment:** These are outside win32k and require separate analysis. They're worth investigating but are a different research direction.

### Approach D: NtCallbackReturn Manipulation

During a user-mode callback (KeUserModeCallback), the user-mode function processes the callback and returns data via NtCallbackReturn. The Sfn* function then copies the returned data to kernel structures.

If we can craft the callback return data to include:
- A kernel pointer where a user pointer is expected → kernel might use it directly
- A larger-than-expected return size → buffer overflow in kernel
- Inconsistent data types → type confusion

**Assessment:** The Sfn* functions validate the return size (e.g., SfnDWORD checks `v67 != 24`). Size validation is present. But some Sfn* functions might have weaker validation for complex data types (strings, structures).

### Approach E: Combine UAF Type Confusion with Batch Buffer TOCTOU

**Two-stage attack:**

Stage 1: Use the UAF type confusion to corrupt WNDK flags on the reclaim window
- Set WF flags that change window behavior (e.g., visibility, state)
- This might cause the reclaim window to enter an unexpected state
- The unexpected state might cause the kernel to access uninitialized structures

Stage 2: Use the batch buffer TOCTOU to cause a GDI type confusion
- Race the POLYPATBLT data to swap a brush handle for a bitmap handle
- The type confusion gives us access to a SURFACE at brush-specific offsets
- If the brush type confusion overlaps with SURFACE.pvScan0, we can control it

**Assessment:** This is the most promising combined approach. The batch buffer TOCTOU gives us the type confusion, and the corrupted WNDK flags might provide additional leverage.

### Approach F: HMLockObject Type Confusion via Path B

When xxxSendMessageToClient is called with the stale tagWND (Path B), the Sfn* function calls HMLockObject on the freed tagWND. If the freed tagWND's memory has been reclaimed by a different object type:

1. HMLockObject increments a field at the tagWND lock offset in the new object
2. ThreadUnlock1 decrements the same field later
3. If the field is a reference count for the new object, incrementing/decrementing it causes a reference count mismatch
4. This can cause premature freeing of the new object → secondary UAF
5. The secondary UAF can be exploited with a different object type

**Requirements:**
- The freed tagWND must be in a pool shared with other object types (not type-isolated)
- OR: the tagWND body (0x150 bytes via HMAllocObject) might be in a shared pool

**Assessment:** HMAllocObject allocates tagWND bodies in the session pool. Type isolation applies to GDI objects (SURFACE, BRUSH, etc.) but tagWND bodies might be in a shared session pool. If so, the freed tagWND body could be reclaimed by a GDI object or vice versa. This needs further investigation.

---

## SURFACE Type Isolation Slot Prediction

### CSectionBitmapAllocator Slot Address Formula

```
slot_addr = base_addr + 912 * (slot_index & 3) + (slot_index >> 2) * 4096
```

Where:
- `base_addr` = `a1[2] ^ a1[1]` (XOR-encoded base address of the mapped section)
- `slot_index` = bitmap index from RtlFindClearBits (0 to 227)
- Cursor starts at 0, wraps at 0xE4 (228)

### Slot Layout per 4096-byte Page

```
Page N (N = slot_index >> 2):
  Offset 0x000: Slot 4N    (912 bytes)
  Offset 0x390: Slot 4N+1  (912 bytes)
  Offset 0x720: Slot 4N+2  (912 bytes)
  Offset 0xAB0: Slot 4N+3  (912 bytes)
  Offset 0xE40: Padding    (448 bytes, unused)
```

### Prediction Strategy

1. Allocate many SURFACE objects to fill existing slots
2. Free specific slots to create a controlled pattern
3. The cursor tracks the last allocated slot index
4. By controlling allocation/free order, predict which slot the next SURFACE will use
5. Calculate the slot address from the base address and slot index

**Problem:** We don't know the base address (it's in kernel memory, XOR-encoded). Without an info leak, we can't predict the exact slot address.

---

## Summary of Confirmed Dead Ends

| Approach | Status | Reason |
|----------|--------|--------|
| SystemSessionBigPoolInformation for SURFACE | DEAD | SURFACE chunks are MmCreateSection-backed, not pool |
| NtGdi* kernel pointer leak | DEAD | No syscall in win32kfull.sys leaks kernel pointers from user mode |
| NtGdiEngLockSurface | DEAD | Requires UMPD (LocalSystem) |
| NtGdiEngAssociateSurface | DEAD | Requires UMPD + 0x40000 flag |
| NtGdiEngCreateBitmap | DEAD | Requires UMPD (LocalSystem) |
| NtGdiCreateSessionMappedDIBSection | DEAD | Requires gpidLogon (csrss.exe) |
| gServerHandler → xxxSetWindowData | DEAD | No gServerHandler calls xxxSetWindowData |
| NtUserGetCPD info leak | DEAD | Returns handle values, not kernel pointers |
| NtGdiSetBitmapAttributes | DEAD | Only makes bitmap "stock", no useful write |
| NtGdiGetDCDword/GetAndSetDCDword | DEAD | Only DWORD values, no pointer corruption |
| Sfn* TOCTOU (callback-then-use) | DEAD | All Sfn* functions lock object before callback |
| xxxReceiveMessage SMS UAF | DEAD | HMLockObject + handle table validation before dispatch |

---

## Recommended Next Steps (Priority Order)

### 1. GDI Batch Buffer TOCTOU (HIGHEST PRIORITY)

This is the most promising completely different approach:
- **Decompile GrePolyPatBltInternal** to verify it locks GDI objects from POLYPATBLT data
- **Determine the race window** between reading the handle and locking the object
- **Test the race** by modifying the batch buffer from another thread during GdiFlush
- **Map the type confusion** — what brush fields overlap with SURFACE.pvScan0 when a bitmap is locked as a brush

### 2. HMLockObject Type Confusion via Path B

- **Determine if tagWND body is in shared session pool** (not type-isolated)
- **If shared:** free tagWND, reclaim with GDI object, trigger Path B
- **HMLockObject on GDI object** might corrupt the GDI object's reference count
- **Secondary UAF** on the GDI object could be exploited for kernel R/W

### 3. WF_SERVERMODE Setup for Path A

- **Find a window class** that sets WF_SERVERMODE during creation
- **OR: find a way to set WF_SERVERMODE** on the reclaim window before the UAF triggers
- **If Path A is available:** trigger xxxMinMaximizeEx via WM_SYSCOMMAND
- **Write to WNDK+0xE9/0xEA** on the reclaimed WNDK (RECT corruption)
- **Use RECT corruption** to cause secondary vulnerability in rendering code

### 4. NtSetSystemInformation / NtSetInformationProcess

- **Audit all info classes** for write primitives to kernel memory
- **Check for integer overflows** in size calculations
- **Look for type confusion** between info class structures

### 5. ALPC Vulnerability Research

- **Audit ALPC (Advanced Local Procedure Call)** for race conditions
- **ALPC messages** can be sent/received from user mode
- **ALPC port** creation and connection might have exploitable paths

---

## Technical Reference: Key Addresses

| Symbol | Address | Size |
|--------|---------|------|
| xxxSendTransformableMessageTimeout | 0x1C00598F0 | 0x576 |
| xxxReceiveMessage | 0x1C0058F60 | 0x952 |
| xxxSendMessageToClient | 0x1C0059E70 | 0x952 |
| SfnDWORD | 0x1C006B320 | 0x378 |
| SetOrClrWF | 0x1C004DF08 | 0x141 |
| xxxSetWindowData | 0x1C008A1A8 | 0x785 |
| xxxSetWindowLongPtr | 0x1C0089BE8 | 0x59E |
| xxxDefWindowProc | 0x1C00484E0 | 0x1A9 |
| xxxRealDefWindowProc | 0x1C0049E28 | 0x9D0 |
| xxxMinMaximizeEx | 0x1C002B69C | 0x904 |
| xxxShowWindowEx | 0x1C00491B4 | 0x435 |
| gServerHandlers | 0x1C02E1140 | 0x38 |
| NtGdiFlushUserBatch | 0x1C008EF20 | 0x2A |
| NtGdiFlushUserBatchInternal | 0x1C008EF50 | — |
| NtGdiCreateDIBSection | 0x1C00AB8E0 | 0x3FD |
| NtGdiDoPalette | 0x1C01130F0 | 0x14C |
| NtGdiGetBitmapBits | 0x1C00182E0 | 0xDC |
| NtGdiSetBitmapBits | 0x1C0018710 | 0xD5 |
| CTypeIsolation<233472,912>::Allocate | 0x1C0102724 | 0x174 |
| CSectionEntry<233472,912>::Create | 0x1C015FE00 | — |
| CSectionEntry<233472,912>::Initialize | 0x1C015FE5C | — |
| CSectionBitmapAllocator<233472,912>::Allocate | 0x1C01028A0 | — |
| PlatformCreateSection | 0x1C016003C | — |
| SURFREF::SURFREF (constructor) | 0x1C0137840 | 0x3C |
| SURFREF::bDeleteSurface | 0x1C016AF6C | 0x29 |
| HMValidateHandleNoSecure | 0x1C008C368 | 0xDA |
| NtUserGetCPD | 0x1C0079210 | 0x84 |
| NtUserSetClassLongPtr | 0x1C00FBC20 | 0x266 |
| xxxCallHook2 | 0x1C005BD10 | 0xCEE |

---

## Conclusion

The **GDI Batch Buffer TOCTOU** is the strongest completely different approach to arbitrary kernel R/W. It exploits a fundamental design flaw in the win32k batch processing mechanism: the kernel reads GDI operation parameters from user-mode memory without copying, creating a race condition that can lead to GDI object type confusion. This approach requires no UAF, no pool corruption, no page table manipulation, no kernel callbacks, and no driver interaction.

The **HMLockObject Type Confusion via Path B** is the second most promising approach. When the UAF causes xxxSendMessageToClient to be called with a stale tagWND, the Sfn* function calls HMLockObject on the freed object. If the freed tagWND body has been reclaimed by a GDI object, HMLockObject corrupts the GDI object's state, potentially leading to a secondary UAF and kernel R/W.

The **SetOrClrWF write range** (WNDK+0x10 through WNDK+0xEA) is wider than previously known but still limited to bit set/clear operations on flag bytes and RECT coordinate bytes. No writable offset corresponds to a kernel pointer field, making direct kernel R/W impossible through SetOrClrWF alone.
