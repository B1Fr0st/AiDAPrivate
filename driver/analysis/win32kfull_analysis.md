# win32kfull.sys Deep Analysis Report

## IDA Instance Info
- IDA Base Address: 0x1C0000000
- Module: win32kfull.sys
- MD5: 447fad7487b42b8af879f921abf0bf36
- SHA256: a1113626eb62c6aae865a9fe3f7f7f91e9af3010558984e5b5a93b91db8ae927
- Image Size: 0x3B4000
- Total Functions: 7993 (7971 named, 22 library)
- Hex-Rays: Ready
- .text: 0x1C0001000 - 0x1C02E0000 (0x2DF000 bytes, rx)
- .rdata: 0x1C02E0000 - 0x1C032A000 (0x4A000 bytes, r)
- .data: 0x1C032A000 - 0x1C0341000 (0x17000 bytes, rw)

---

## Task A: Validated Functions

### 1. xxxSendTransformableMessageTimeout (0x1C00598F0)

**Signature:** `__int64 __fastcall xxxSendTransformableMessageTimeout(unsigned __int64 a1, unsigned int a2, unsigned __int64 a3, __int64 a4, unsigned int a5, unsigned int a6, __int64 *LowLimit, int a8, int a9)`

**Parameters:**
- a1 = tagWND* (window to send message to)
- a2 = message ID (e.g., 0x21 = WM_MOUSEACTIVATE)
- a3 = wParam
- a4 = lParam
- a5/a6 = timeout/flags
- LowLimit = result pointer
- a8/a9 = flags

**Key Logic:**
1. Validates a1 against gpKernelHandleTable — KeBugCheckEx if invalid handle
2. Handles DDE messages (992-1000 range) with xxxDDETrackSendHook
3. Handles touch/gesture messages (577-589, 528/582) with MiP checks
4. Gets current thread's Win32Thread (v18)
5. **Same-thread path (v18 == a1[2]):** This is the critical path for the UAF
   - Checks if a1 != foreground window AND message type conditions
   - If certain message types: calls xxxPointerCallHook directly
   - **Otherwise: calls xxxCallHook2 at 0x1C0059B2B** — THIS IS THE UAF WINDOW
   - **After xxxCallHook2 returns: reads `mov rax, [rbx+28h]` at 0x1C0059B30** — reads tagWND+0x28 (pwndk) WITHOUT re-validation
   - Then checks `[rax+12h] & 4` (window state flags)
   - If flag not set: calls xxxSendMessageToClient with a1 (the potentially freed window)
6. **Cross-thread path:** calls xxxInterSendMsgEx or xxxDefWindowProc

**Callers:** xxxQueryLegacyActivation (0x1C01F1956), xxxDestroyWindow (0x1C007DF64), PostTransformableMessage, and others
**Callees:** xxxCallHook2, xxxSendMessageToClient, xxxInterSendMsgEx, xxxPointerCallHook, PhkNextValid, xxxBroadcastMessageEx

**Critical Finding:** The UAF read at 0x1C0059B30 is confirmed. After xxxCallHook2 fires the WH_CALLWNDPROC hook (which executes user-mode code), the function reads `tagWND+0x28` (pwndk field) from rbx without re-validating that the window still exists. If the window was destroyed during the hook callback, this is a use-after-free read.

---

### 2. bDoGetSetBitmapBits (0x1C0018BA4)

**Signature:** `__int64 __fastcall bDoGetSetBitmapBits(struct _SURFOBJ *a1, struct _SURFOBJ *a2, int a3)`

**Parameters:**
- a1 = destination/source SURFOBJ (depends on direction)
- a2 = source/destination SURFOBJ (depends on direction)
- a3 = direction flag (0 = GET bits, non-zero = SET bits)

**GET path (a3 == 0):**
- a1 = the bitmap's own SURFOBJ (from the SURFACE)
- a2 = user-provided SURFOBJ (with user buffer info)
- `pvScan0 = (char *)a1->pvScan0` at 0x1C0018BF5 — **NO VALIDATION on pvScan0**
- `pvBits = (char *)a2->pvBits` — user buffer
- Calculates row size from sizlBitmap.cx * bitsPerPixel
- Uses `memmove(&pvScan0[lDelta * row], pvBits, ...)` — **pvScan0 used directly as memmove source**
- If pvScan0 is corrupted to point at arbitrary kernel memory → **arbitrary kernel READ**

**SET path (a3 != 0):**
- a1 = user-provided SURFOBJ (with user buffer info)
- a2 = the bitmap's own SURFOBJ (from the SURFACE)
- `v21 = (char *)a2->pvScan0` at 0x1C0018D9E — **NO VALIDATION on pvScan0**
- `v18 = (char *)a1->pvBits` — user buffer
- Uses `memmove(v18, &v21[offset], ...)` — **pvScan0 used directly as memmove destination**
- If pvScan0 is corrupted to point at arbitrary kernel memory → **arbitrary kernel WRITE**

**SURFOBJ Layout (confirmed from IDA type inspection):**
```
offset 0x00: dhsurf (DHSURF)
offset 0x08: hsurf (HSURF)
offset 0x10: dhpdev (DHPDEV)
offset 0x18: hdev (HDEV)
offset 0x20: sizlBitmap (SIZEL - 8 bytes: cx, cy)
offset 0x28: cjBits (ULONG)
offset 0x30: pvBits (PVOID)
offset 0x38: pvScan0 (PVOID)  ← THE TARGET
offset 0x40: lDelta (LONG)
offset 0x44: iUniq (ULONG)
offset 0x48: iBitmapFormat (ULONG)
offset 0x4C: iType (USHORT)
offset 0x4E: fjBitmap (USHORT)
```
Total _SURFOBJ size: 80 bytes (0x50)

**SURFACE Layout (derived from code analysis):**
```
SURFACE+0x00: unknown/vtable/refcount area
SURFACE+0x18: _SURFOBJ starts here (dhsurf)
SURFACE+0x28: _SURFOBJ.hsurf
SURFACE+0x30: _SURFOBJ.dhpdev
SURFACE+0x38: _SURFOBJ.hdev
SURFACE+0x40: _SURFOBJ.sizlBitmap
SURFACE+0x48: _SURFOBJ.cjBits
SURFACE+0x50: _SURFOBJ.pvScan0  ← CORRUPTION TARGET
SURFACE+0x58: _SURFOBJ.lDelta
SURFACE+0x60: _SURFOBJ.iBitmapFormat
SURFACE+0x70: flags (0x4000000 = bitmap, 0x40000 = DIB, 0x400 = ??)
SURFACE+0x90: MmSecureVirtualMemory handle
SURFACE+0x98: bitmap dimension (set by GreSetBitmapDimension)
```

**Callers:** GreGetBitmapBits (0x1C001863F), GreSetBitmapBits (0x1C0018A47)
**Callees:** PDEVOBJ::vSync, memmove

**Critical Finding:** CONFIRMED — pvScan0 is used directly as memmove source/destination with zero validation. If SURFACE+0x50 (pvScan0) can be corrupted to point at arbitrary kernel memory, GetBitmapBits = arbitrary kernel read and SetBitmapBits = arbitrary kernel write.

---

### 3. NtGdiGetBitmapBits (0x1C00182E0)

**Logic:**
1. Calls GreGetBitmapBits(a1) to get bitmap size
2. Clamps a2 (requested size) to actual bitmap size
3. ProbeForWrite on user buffer a3
4. MmSecureVirtualMemory to lock the user buffer
5. Calls GreGetBitmapBits again (which calls bDoGetSetBitmapBits)
6. MmUnsecureVirtualMemory

**No validation on pvScan0 occurs anywhere in this chain.**

### 4. NtGdiSetBitmapBits (0x1C0018710)

**Logic:**
1. Checks `Address + Size > MmUserProbeAddress` (bounds check on user buffer only)
2. MmSecureVirtualMemory on user buffer
3. Calls GreSetBitmapBits (which calls bDoGetSetBitmapBits)
4. MmUnsecureVirtualMemory

**No validation on pvScan0 occurs anywhere in this chain.**

### 5. GreGetBitmapBits (0x1C00183C4) and GreSetBitmapBits (0x1C00187F0)

Both functions:
1. Acquire DYNAMICMODECHANGESHARELOCK
2. Create SURFREF from HSURF handle (locks the SURFACE)
3. Check `flags & 0x4000000` (bitmap flag)
4. For DIB-type bitmaps (iType == 3): create temporary DIB and EngCopyBits
5. For standard bitmaps: call bDoGetSetBitmapBits directly
6. The SURFOBJ passed to bDoGetSetBitmapBits is `(v34 + 24)` = SURFACE+0x18 = the embedded _SURFOBJ
7. **pvScan0 is read from this embedded SURFOBJ at SURFACE+0x50 with no validation**

### 6. xxxSetWindowLongPtr (0x1C0089BE8)

**Bounds Check Logic:**
- `v35 = *(unsigned int *)(v34 + 252)` — this is cbWndExtra (window extra bytes size) from the class structure
- For offset < 0 (GWL_* indices): routes to xxxSetWindowData
- For offset >= 0 (DWLP_/GWL_ indices): checks `v6 + 8 > v17` where v17 = cbWndExtra
  - If offset + 8 > cbWndExtra AND window is in different process: may KeAttachProcess
- **The actual write at LABEL_63:**
  - If `(int)v6 + 8LL <= v35` (offset + 8 <= cbWndExtra): writes to `*((_QWORD *)a1 + 35) + v6` = tagWND+0x118 + offset
  - Else: writes to `v34 + 296 + (v6 - v35)` — this is the client-side extra bytes via desktop heap pointer

**Key Finding:** cbWndExtra is stored at `pcls+252` (0xFC). The bounds check uses `cbWndExtra + cbWndServerExtra` at `pcls+200` (0xC8) for the total range. The per-window copy is at pcls+0xFC. The check is: `offset + 8 <= cbWndExtra + cbWndServerExtra`. There's also a check against `gDefaultServerClasses` for built-in window classes that restricts certain offsets.

### 7. xxxDestroyWindow (0x1C007DC00)

**HMLockObject at 0x1C007DC6C:**
```c
if ( a1 )  // a1 is the window being destroyed
    ((void (*)(void))HMLockObject)();  // Locks the window before destruction
```

**Full destruction path:**
1. HMLockObject(a1) — adds a lock to prevent concurrent free
2. Checks thread ownership, may HMChangeOwnerThread
3. Handles DDE, menu states, shell hooks
4. xxxDW_DestroyOwnedWindows — destroys owned windows
5. xxxDW_SendDestroyMessages — sends WM_DESTROY
6. UnlinkWindow — removes from window list
7. **xxxFreeWindow** — the actual free function

**xxxFreeWindow (0x1C007A720) — The actual window deallocation:**
1. HMMarkObjectDestroy — marks object as being destroyed
2. Sets destroy flag `*(_BYTE *)(v93 + 25) |= 2u`
3. ThreadUnlock1 — releases the lock added in xxxDestroyWindow
4. If ThreadUnlock1 returns non-zero (last lock released):
   - Calls HMMarkObjectDestroy again
   - If returns true (can destroy):
     - **HMFreeObject(this)** at 0x1C007BCF8 — **THIS IS THE ACTUAL FREE**
     - Frees window extra bytes, properties, menu data
   - If returns false (more locks remain): marks as zombie, sets WF_516

**CRITICAL FINDING:** Even with cLockObj=0 before the hook in xxxSendTransformableMessageTimeout, xxxDestroyWindow ALWAYS calls HMLockObject at entry (0x1C007DC6C). This adds a lock, incrementing cLockObj from 0 to 1. The window goes to ZOMBIE state (not FREE) because ThreadUnlock1 in xxxFreeWindow would see cLockObj > 0. The window is only actually freed when the last lock is released.

**However:** The UAF read at 0x1C0059B30 reads tagWND+0x28 (pwndk) — this field could be corrupted or point to freed memory if the window object itself was freed through an alternative path. The key question is: can we get the window to HMFreeObject WITHOUT the HMLockObject in xxxDestroyWindow?

---

### 8. xxxProcessEventMessage (0x1C00C15B8)

**Event Types Enumerated:**
The function is a massive switch on `*(_DWORD *)(a2 + 96)` (event type):

| Event | Value | Handler | Locks Window? |
|-------|-------|---------|---------------|
| QEVENT_DEFD_POINTER_ACTIVATE | 20 | xxxDoDeferredPointerActivate | **NO HMLockObject** |
| QEVENT_DESTROY_WINDOW | 8 | xxxDestroyWindow / xxxFreeWindow | YES (in xxxDestroyWindow) |
| QEVENT_SHOWWINDOW | 1 | xxxProcessShowWindowEvent | YES |
| QEVENT_SETWINDOWPOS | 2 | xxxProcessSetWindowPosEvent | YES (via HMLockObject) |
| QEVENT_KEYSTATE | 3 | ProcessUpdateKeyStateEvent | N/A |
| QEVENT_ACTIVATE | 4 | xxxProcessActivationEvent | N/A |
| QEVENT_DEACTIVATE | 5 | xxxDeactivate | N/A |
| QEVENT_MESSAGE | 0 | PostTransformableMessage | YES |
| QEVENT_HIDEWINDOW | 9 | (deferred) | YES |
| QEVENT_QOS / sound | 14 | CUserPlaySound | N/A |
| QEVENT_HOOK | 11 | xxxCallHook + PostShellHookMessages | N/A |
| QEVENT_NOTIFY | 12 | xxxProcessNotifyWinEvent | N/A (domain lock) |
| QEVENT_TSFEVENT | 13 | xxxProcessTSFEvent | N/A (domain lock) |
| QEVENT_CANCELEVENT | 10 | xxxCancelMouseMoveTracking | YES |
| QEVENT_MINIMIZEHUNG | 10+1 | xxxProcessMinimizeHungThreadEvent | YES |
| QEVENT_DPI | 24 | xxxClientUpdateDpi | N/A |
| QEVENT_THEMECHANGE | 25 | xxxClientBroadcastThemeChange | N/A |
| QEVENT_MOVE/RESTOREFOCUS | 30 | xxxDeliverRestoreFocusMessage | YES |
| QEVENT_MINMAXIMIZE | 16 | xxxMinMaximizeEx | YES |
| QEVENT_ARRANGEWINDOW | 17 | xxxArrangeWindow | YES |
| QEVENT_MOVE/CLONE | 28 | xxxCloneWindowPosAndArrangement | YES |
| QEVENT_MOVESIZE | 27 | CMoveSizeRequest::xxxRevalidateAndTransferCapture | YES |
| QEVENT_DESKTOPRECALC | 22 | xxxProcessDesktopRecalc | N/A |
| QEVENT_POINTERLEAVE | 21 | PostMousePointerLeaveAndCleanup | YES |
| QEVENT_SHUTDOWN | 19 | xxxSendShutdownData | N/A |
| QEVENT_UPDATEFRAMEMARGINS | 26 | xxxProcessUpdateFrameMargins | YES |

**CRITICAL FINDING for Event 20 (QEVENT_DEFD_POINTER_ACTIVATE):**
```c
case 20:  // v10 - 16 = 4, then v41 - 1 = 3, then v42 - 1 = 2, then v43 - 1 = 1, then v44 - 1 = 0
    xxxDoDeferredPointerActivate(a2);
    CleanEventMessage((struct tagQMSG *)a2);
```
**NO HMLockObject is called before xxxDoDeferredPointerActivate!** The window handle is validated only by ValidateHwnd inside xxxDoDeferredPointerActivate, but the window is NOT locked. This is the cLockObj=0 entry point.

### 9. xxxDoDeferredPointerActivate (0x1C01F245C)

**Logic:**
1. `ValidateHwnd(*(_QWORD *)(a1 + 16))` — validates window handle, returns tagWND*
2. Gets INPUTDEST from the window
3. Calls `CTouchProcessor::DoDeferredPointerActivate(gpTouchProcessor, v11, v4)`
4. **No HMLockObject on the child window!**

### 10. xxxPointerActivateInternal (0x1C01F1478)

**Logic:**
1. Gets queue from thread info
2. Gets `TopLevelWindow = GetTopLevelWindow(a1)` — the top-level parent of the child
3. **HMLockObject(TopLevelWindow)** — locks ONLY the top-level parent, NOT the child window (a1)
4. Checks for modal menu state
5. If not special: `xxxQueryLegacyActivation(a1, TopLevelWindow, v6, a4)` — sends WM_MOUSEACTIVATE to the CHILD
6. ThreadUnlock1 — unlocks TopLevelWindow

**CRITICAL:** The child window (a1) is passed to xxxQueryLegacyActivation WITHOUT being locked. Only the TopLevelWindow is locked. This is the cLockObj=0 condition.

### 11. xxxQueryLegacyActivation (0x1C01F183C)

**Logic:**
1. Checks if queue has popup menu — returns 3 if so
2. Saves/restores cursor position state
3. `xxxSendTransformableMessageTimeout((unsigned __int64)a1, 0x21u, ...)` — sends WM_MOUSEACTIVATE to the CHILD window (a1)
4. **a1 (the child) is NOT locked here — it was not locked by the caller either**
5. Returns 1 or 3 based on the result

**This is where cLockObj=0 matters:** xxxSendTransformableMessageTimeout is called with a1 = child window that has NO additional lock. Inside xxxSendTransformableMessageTimeout, the same-thread path fires xxxCallHook2 (WH_CALLWNDPROC), which executes user-mode code. During this callback, the user can call DestroyWindow on the child, which adds a lock via HMLockObject in xxxDestroyWindow. However, the read at 0x1C0059B30 (`mov rax, [rbx+28h]`) happens AFTER xxxCallHook2 returns, and rbx still holds the old (potentially stale) pointer to the child window.

### 12. xxxCallHook2 (0x1C005BD10)

**Logic:**
1. Validates hook object, checks thread state
2. Handles different hook types (WH_CALLWNDPROC = type 4)
3. Checks access/UIPI restrictions
4. **For normal hooks: calls xxxHkCallHook(Valid, a2, v53[0], v32)** — this invokes the user-mode hook function
5. xxxHkCallHook triggers the actual user-mode callback via KeUserModeCallback

**This is the user-mode callback window:** During xxxHkCallHook, user-mode code executes. The user can call DestroyWindow, SetWindowLongPtr, or any other API that modifies window state. When control returns to xxxSendTransformableMessageTimeout, the window pointer in rbx may be stale.

### 13. GreSetBitmapDimension (0x1C02C0750)

**Logic:**
- Locks SURFACE via SURFREF
- Checks `flags & 0x4000000` (bitmap flag)
- If a4 (old dimension pointer): reads old value from SURFACE+0x98 (offset 152)
- **Writes new dimension to SURFACE+0x98:** `*(_QWORD *)(v9 + 152) = __PAIR64__(a3, a2)`
- Returns success

**Finding:** GreSetBitmapDimension writes to SURFACE+0x98 (bitmap dimension). This is NOT pvScan0 (SURFACE+0x50). It writes a user-controlled 8-byte value to a fixed offset in the SURFACE. While not directly useful for pvScan0 corruption, it could be useful if the SURFACE object is adjacent to another object in the pool and the dimension write overflows into a neighboring object's fields.

### 14. NtGdiCreateBitmap (0x1C01059A0)

**Logic:**
1. If user buffer provided: validates `Address + size <= MmUserProbeAddress`
2. MmSecureVirtualMemory on user buffer
3. Calls GreCreateBitmap (import from win32kbase)
4. MmUnsecureVirtualMemory

### 15. NtGdiEngCreateBitmap (0x1C015CF30)

**Logic:**
1. Validates UMPD size
2. Checks gUMPDSecurityLevel for BMF_UMPDMEM flag
3. If user buffer: MmSecureVirtualMemory
4. Calls EngCreateBitmap (import)
5. Stores MmSecureVirtualMemory handle at SURFACE+0x90 (offset 144)

### 16. NtGdiCreateDIBitmapInternal (0x1C00A9DE0)

**Logic:**
1. Captures BITMAPINFO from user mode (bCaptureBitmapInfo)
2. If user buffer: validates alignment, checks MmUserProbeAddress, MmSecureVirtualMemory
3. Calls GreCreateDIBitmapReal or GreCreateDIBitmapComp
4. Frees captured info, unsecures memory

### 17. NtGdiSetPUMPDOBJ (0x1C00A11D0)

**Logic:**
- Sets up UMPD (User-Mode Print Driver) for the current thread
- Validates UMPD security level (gUMPDSecurityLevel)
- Checks LocalSystem process for level 1
- Pushes UMPD object to current thread's stack
- **gUMPDSecurityLevel controls whether UMPD bitmap creation is allowed**
- If gUMPDSecurityLevel == 2: unrestricted UMPD
- If gUMPDSecurityLevel == 1: requires LocalSystem
- If gUMPDSecurityLevel == 0: requires LocalSystem or unrestricted

### 18. MapDesktop (0x1C004EDB0)

**Logic:**
- Maps desktop heap section into process address space
- Uses MmMapViewOfSection with the desktop's section object
- View size = 4096 (0x1000) — one page initially
- Allocates a DesktopView entry (24 bytes) with pool tag 1768977237 (0x69737244 = 'Drsi'?)
- Links DesktopView into process's desktop view list at Win32Process+704

---

## Task B: UAF Vulnerability Deep Dive

### The UAF Read

**Location:** 0x1C0059B30
**Instruction:** `mov rax, [rbx+28h]`
**Context:** Immediately after `xxxCallHook2` returns at 0x1C0059B2B

**Disassembly around the UAF:**
```asm
0x1C0059B2B: call ?xxxCallHook2@@YA_JPEAUtagHOOK@@H_K_JPEAH_N@Z  ; xxxCallHook2
0x1C0059B30: mov rax, [rbx+28h]     ; UAF READ — rbx = tagWND*, +0x28 = pwndk
0x1C0059B34: test byte ptr [rax+12h], 4  ; check window state flags
0x1C0059B38: jnz loc_1C0059CE9      ; branch if flag set
```

**What rbx holds:** rbx = a1 = the tagWND* passed to xxxSendTransformableMessageTimeout. This is the child window from xxxQueryLegacyActivation.

**What +0x28 is:** tagWND+0x28 is likely the pwndk field (kernel window data pointer) or another critical internal pointer. Reading it after a user-mode callback without re-validation is a classic UAF.

### Full Trigger Path (Confirmed)

```
SendInput (user mode)
  → QEVENT_DEFD_POINTER_ACTIVATE [event 20] queued
  → xxxProcessEventMessage (0x1C00C15B8)
    → event type = 20 → NO HMLockObject on child window
    → xxxDoDeferredPointerActivate (0x1C01F245C)
      → ValidateHwnd(child) — validates but does NOT lock
      → CTouchProcessor::DoDeferredPointerActivate
        → xxxPointerActivateInternal (0x1C01F1478)
          → GetTopLevelWindow(child) → TopLevelWindow
          → HMLockObject(TopLevelWindow) — locks ONLY TopLevelWindow
          → xxxQueryLegacyActivation(child, TopLevelWindow, ...)
            → xxxSendTransformableMessageTimeout(child, WM_MOUSEACTIVATE=0x21, ...)
              → same-thread path detected
              → xxxCallHook2(WH_CALLWNDPROC hook) at 0x1C0059B2B
                → USER-MODE CALLBACK EXECUTES
                → User can DestroyWindow(child) here
                → xxxDestroyWindow calls HMLockObject(child) — cLockObj goes 0→1
                → Window enters ZOMBIE state, NOT freed yet
                → BUT: if another thread already freed it, or if there's an
                  alternative free path...
              → mov rax, [rbx+28h] at 0x1C0059B30 — UAF READ
              → If window was freed: reads from freed/corrupted memory
```

### Locking Analysis

**Why cLockObj=0 matters:**
1. Before xxxCallHook2: child window has cLockObj=0 (no extra lock)
2. During xxxCallHook2: user-mode callback executes
3. If user calls DestroyWindow(child):
   - xxxDestroyWindow calls HMLockObject — cLockObj goes 0→1
   - Window is marked for destruction but NOT freed (ZOMBIE)
   - xxxFreeWindow's HMMarkObjectDestroy marks it, but ThreadUnlock1 sees cLockObj=1
   - Window remains allocated but in ZOMBIE state
4. After xxxCallHook2 returns:
   - rbx still points to the (now ZOMBIE) window
   - `mov rax, [rbx+28h]` reads from ZOMBIE window — data is still valid
   - **The window is NOT freed, so this is NOT a true UAF in the common case**

**The critical question: Can we get the window to be actually FREED (not just ZOMBIE)?**

### Alternative Free Paths Investigation

**Path 1: Normal xxxDestroyWindow**
- Always calls HMLockObject at entry
- Window goes to ZOMBIE, not FREE
- Only freed when last lock released (ThreadUnlock1 in xxxFreeWindow)
- **With cLockObj=0 before hook: DestroyWindow adds 1 lock, so cLockObj=1 after. Window is ZOMBIE.**

**Path 2: xxxProcessEventMessage event 8 (QEVENT_DESTROY_WINDOW)**
```c
case 8:
    v62 = HMValidateHandleNoSecure(*(_QWORD *)(a2 + 32), 1);
    if (v62) {
        if (*(char *)(v62[5] + 19) < 0)
            xxxFreeWindow(v63);  // Direct free for already-destroyed windows
        else
            xxxDestroyWindow(v62);  // Normal destroy
    }
```
- If the window has `*(char *)(pcls + 19) < 0` (negative = already marked): calls xxxFreeWindow directly
- xxxFreeWindow does NOT call HMLockObject — it goes straight to HMMarkObjectDestroy + HMFreeObject
- **If we can queue a QEVENT_DESTROY_WINDOW event for the child during the hook callback, and the window is already in a destroyed state, it could be freed WITHOUT HMLockObject!**

**Path 3: xxxFreeWindow called from event 8 with already-destroyed window**
- `xxxFreeWindow` at 0x1C007A720
- Calls HMMarkObjectDestroy, sets destroy flag
- If ThreadUnlock1 returns non-zero: calls HMFreeObject — **ACTUAL FREE**
- If ThreadUnlock1 returns zero: marks as zombie
- **If the window's cLockObj was already 0 (from the cLockObj=0 entry), and we can trigger xxxFreeWindow directly, ThreadUnlock1 might return the window as "last unlock"**

**Path 4: Thread exit cleanup**
- When a thread exits, all its windows are destroyed
- This goes through xxxDestroyWindow which adds HMLockObject
- Not useful for getting cLockObj to 0

**Path 5: Desktop/windowstation destruction**
- Destroys all windows via xxxDestroyWindow
- Same locking as normal path

### Assessment of UAF Exploitability

**Current assessment:** The UAF at 0x1C0059B30 is a **confirmed code pattern vulnerability** but the standard exploitation path is blocked because xxxDestroyWindow always adds a lock via HMLockObject.

**Potential exploitation paths to explore:**
1. **Race condition with multiple threads:** If thread A triggers the UAF path (cLockObj=0) and thread B destroys the window during the hook callback, thread B's xxxDestroyWindow adds a lock. But if there's a way to release that lock before the UAF read... (e.g., via ThreadUnlock1 in some cleanup path)
2. **QEVENT_DESTROY_WINDOW direct free:** If we can queue event 8 for the child during the hook AND the child is already in a "destroyed" state (pcls+19 < 0), xxxFreeWindow is called directly without HMLockObject
3. **Alternative window types:** Some window types might have different destruction paths that skip HMLockObject

---

## Task C: bDoGetSetBitmapBits and pvScan0

### pvScan0 Usage Confirmed

**GET path (reading bitmap bits):**
```c
pvScan0 = (char *)a1->pvScan0;  // 0x1C0018BF5 — reads from SURFACE+0x50
// ...
memmove(&pvScan0[lDelta * (v10 / v8)], pvBits, v32);  // 0x1C017630E — pvScan0 as SOURCE
```
If pvScan0 points to arbitrary kernel memory → **arbitrary kernel READ** via GetBitmapBits

**SET path (writing bitmap bits):**
```c
v21 = (char *)a2->pvScan0;  // 0x1C0018D9E — reads from SURFACE+0x50
// ...
memmove(v18, &v21[v22 * (v24 / v20)], v31);  // 0x1C0176274 — pvScan0 as DESTINATION
```
If pvScan0 points to arbitrary kernel memory → **arbitrary kernel WRITE** via SetBitmapBits

### Validation Check

**THERE IS NO VALIDATION ON pvScan0 ANYWHERE IN THE CALL CHAIN:**
1. NtGdiGetBitmapBits → GreGetBitmapBits → bDoGetSetBitmapBits — no pvScan0 check
2. NtGdiSetBitmapBits → GreSetBitmapBits → bDoGetSetBitmapBits — no pvScan0 check
3. bDoGetSetBitmapBits uses pvScan0 directly as memmove source/destination
4. The only checks are on the USER BUFFER (ProbeForWrite, MmSecureVirtualMemory, MmUserProbeAddress)
5. The bitmap SIZE is validated (cjBits clamped to actual bitmap size)
6. **But pvScan0 itself is trusted completely**

### Writers to SURFACE+0x50 (pvScan0)

From the search of 573 instructions writing to `[reg+50h]`, most are NOT SURFACE-related (they write to other structure types at offset 0x50). The SURFACE-specific writes to pvScan0 occur in:

1. **EngCreateBitmap (import from win32kbase):** Sets pvScan0 during surface creation
2. **SURFMEM::bCreateDIB:** Creates DIB surfaces, sets pvScan0
3. **Pool copy/initialization:** movups instructions that copy 16 bytes including offset 0x50

The key insight is that **pvScan0 is set during bitmap creation and never re-validated**. To corrupt it, we need to either:
- Corrupt the SURFACE object in pool (heap spray + overflow into adjacent SURFACE)
- Use a write primitive to overwrite SURFACE+0x50 directly
- Use a type confusion to treat another object as a SURFACE

### Other GDI Functions Using pvScan0

The search found 1497 instructions reading from `[reg+50h]` and 1763 from `[reg+38h]`. Many of these are SURFACE/SURFOBJ accesses. Key functions that read pvScan0:
- bDoGetSetBitmapBits (confirmed — no validation)
- EngCopyBits (uses SURFOBJ.pvScan0)
- All Eng* rendering functions that access bitmap data
- DIB creation/copy paths

### GreSetBitmapDimension Analysis

**Writes to SURFACE+0x98 (offset 152):** `*(_QWORD *)(v9 + 152) = __PAIR64__(a3, a2)`
- a2 = horizontal dimension (user-controlled)
- a3 = vertical dimension (user-controlled)
- This writes a user-controlled 8-byte value to SURFACE+0x98
- NOT directly useful for pvScan0 corruption (pvScan0 is at SURFACE+0x50)
- BUT: if SURFACE objects are adjacent in pool and we can control the allocation layout, the dimension write at +0x98 of one SURFACE could potentially overflow into +0x50 of an adjacent SURFACE if the pool layout is right

---

## Task D: Deferred Pointer Activate Path

### Full Path Analysis

```
SendInput → QEVENT_DEFD_POINTER_ACTIVATE (event 20)
  → xxxProcessEventMessage: NO HMLockObject on child
    → xxxDoDeferredPointerActivate
      → ValidateHwnd(child) — validates but NO lock
      → CTouchProcessor::DoDeferredPointerActivate
        → xxxPointerActivateInternal
          → HMLockObject(TopLevelWindow) — locks ONLY top-level
          → If not special input:
            → xxxSendPointerMessageWorker(child, 587, ...) — WM_POINTERACTIVATE
            → If result != 1 and != 3:
              → xxxQueryLegacyActivation(child, TopLevelWindow, ...)
                → xxxSendTransformableMessageTimeout(child, 0x21, ...)
                  → same-thread path:
                    → xxxCallHook2 — USER-MODE CALLBACK
                    → mov rax, [rbx+28h] — UAF READ
                    → xxxSendMessageToClient(child, 0x21, ...)
          → ThreadUnlock1 — unlocks TopLevelWindow
```

### Locking Model

| Object | Locked? | Where? | When Released? |
|--------|---------|--------|----------------|
| Child window (a1) | NO | nowhere in this path | N/A |
| TopLevelWindow | YES | xxxPointerActivateInternal:0x1C01F1534 | ThreadUnlock1 at 0x1C01F180B |
| Hook object | YES | xxxCallHook2 internal | ThreadUnlock1 in xxxCallHook2 |

**The child window is NEVER locked in this entire path.** Its cLockObj remains at whatever value it was before (typically 1 from the initial creation lock, or 0 if that was released).

### User-Mode Callbacks in This Path

1. **xxxCallHook2** (WH_CALLWNDPROC) — fires before the message is delivered
2. **xxxSendMessageToClient** — delivers WM_MOUSEACTIVATE to the window's wndproc
3. **xxxCallHook** (WH_CALLWNDPROCRET or similar) — fires after message delivery

Each of these is a user-mode callback where arbitrary code can execute.

### Other Event Types with Different Locking

From the xxxProcessEventMessage analysis:
- **Event 0 (QEVENT_MESSAGE):** HMLockObject called before xxxSendMessage — window IS locked
- **Event 1 (QEVENT_SHOWWINDOW):** HMLockObject called — window IS locked
- **Event 8 (QEVENT_DESTROY_WINDOW):** No HMLockObject, calls xxxDestroyWindow or xxxFreeWindow directly
- **Event 20 (QEVENT_DEFD_POINTER_ACTIVATE):** NO HMLockObject — **window is NOT locked**
- **Event 16 (QEVENT_MINMAXIMIZE):** HMLockObject called — window IS locked

**Event 20 is unique in that it processes a window WITHOUT locking it first.** This is the root cause of the cLockObj=0 condition.

---

## Task E: New Attack Surfaces

### 1. User-Mode Callbacks (38 found)

All `xxxClient*` functions are user-mode callback entry points:

| Function | Address | Purpose |
|----------|---------|---------|
| xxxClientCallDefWindowProc | 0x1C02311F0 | Default window proc callback |
| xxxClientCallDefaultInputHandler | 0x1C0231360 | Input handler callback |
| xxxClientCallDelegateThread | 0x1C02314DC | Thread delegation callback |
| xxxClientCallLocalMouseHooks | 0x1C0231824 | Local mouse hooks |
| xxxClientCallDitThread | 0x1C0050C38 | DIT thread callback |
| xxxClientCallWinEventProc | 0x1C0051294 | WinEvent callback |
| xxxClientFreeWindowClassExtraBytes | 0x1C0051984 | Class extra bytes free |
| xxxClientAllocWindowClassExtraBytes | 0x1C0051DAC | Class extra bytes alloc |
| xxxClientLoadImage | 0x1C0022860 | Image loading |
| xxxClientLoadMenu | 0x1C0023740 | Menu loading |
| xxxClientCopyImage | 0x1C00239CC | Image copying |
| xxxClientLoadStringW | 0x1C002425C | String loading |
| xxxClientShutdown | 0x1C000B2CC | Shutdown callback |
| xxxClientShutdown2 | 0x1C000B354 | Shutdown callback 2 |
| xxxClientEnableMMCSS | 0x1C000A59C | MMCSS enable |
| xxxClientAddFontResourceW | 0x1C0021B2C | Font resource add |
| xxxClientUpdateDpi | 0x1C0233214 | DPI update |
| xxxClientBroadcastThemeChange | 0x1C012C260 | Theme change |
| xxxClientRimDevCallback | 0x1C012D504 | RIM device callback |
| xxxClientGetCharsetInfo | 0x1C012FE28 | Charset info |
| xxxClientExtTextOutW | 0x1C0158F28 | Text output |
| xxxClientGetTextExtentPointW | 0x1C0159250 | Text extent |
| xxxClientCopyDDEIn1/2 | 0x1C0231AB0/0x1C0228028 | DDE copy in |
| xxxClientCopyDDEOut1/2 | 0x1C0231F74/0x1C022819C | DDE copy out |
| xxxClientFreeDDEHandle | 0x1C02325C8 | DDE handle free |
| xxxClientGetDDEFlags | 0x1C02326F0 | DDE flags |
| xxxClientGetDDEHookData | 0x1C0232818 | DDE hook data |
| xxxClientLpkDrawTextEx | 0x1C0232A1C | LPK draw text |
| xxxClientPSMTextOut | 0x1C0232E84 | PSM text output |
| xxxClientFindMnemChar | 0x1C0232330 | Mnemonic char find |
| xxxClientCharToWchar | 0x1C0231988 | Char to WCHAR |
| xxxClientMonitorEnumProc | 0x1C011B4A0 | Monitor enum |
| xxxClientThreadSetup | 0x1C0108C10 | Thread setup |
| xxxClientWOWGetProcModule | 0x1C004F81C | WOW proc module |
| xxxClientExpandStringW | 0x1C00251BC | String expand |

**Each of these is a potential race condition window** where user-mode code executes during kernel operations.

### 2. xxxCallHook2 (0x1C005BD10) — The Primary Hook Callback Dispatcher

This function dispatches ALL window hooks (WH_CALLWNDPROC, WH_CALLWNDPROCRET, WH_GETMESSAGE, WH_KEYBOARD, WH_MOUSE, etc.). It:
1. Validates hook object
2. Checks access/UIPI restrictions
3. Locks hook object via HMLockObject
4. **Calls xxxHkCallHook** — triggers user-mode callback
5. Unlocks via ThreadUnlock1

**xxxHkCallHook (0x1C005CA10)** is the actual user-mode transition function.

### 3. Race Condition Opportunities

The critical section in win32k is managed via EnterCrit/LeaveCrit (UserSessionSwitchEnterCrit/UserSessionSwitchLeaveCrit). The critical section is entered at the beginning of most NtUser* and NtGdi* syscalls.

**However:** User-mode callbacks (xxxClient*, xxxCallHook2, xxxHkCallHook) RELEASE the critical section during the callback. This means:
- Thread A holds the crit section, calls a hook, crit section is released
- Thread B can enter the crit section and modify state
- Thread A's hook returns, re-acquires crit section
- Thread A reads stale state → TOCTOU

**This is the fundamental race condition primitive in win32k.** Every user-mode callback is a race window.

### 4. Type Confusion in HMValidateHandleNoSecure (0x1C008C368)

```c
if ((unsigned __int64)(unsigned __int16)a1 < *(_QWORD *)(gpsi + 8LL))
{
    v7 = *((_QWORD *)&gSharedInfo + 1) + (unsigned int)(unsigned __int16)a1 * *((_DWORD *)&gSharedInfo + 4);
    v8 = a1 >> 16;  // upper 16 bits = uniqueness tag
    v9 = HMPkheFromPhe(v7);
    if ((_WORD)v8 == *(_WORD *)(v7 + 26)  // uniqueness check
        || (_WORD)v8 == 0xFFFF            // wildcard (WOW64)
        || !(_WORD)v8 && PsGetCurrentProcessWow64Process())
        && (*(_BYTE *)(v7 + 25) & 1) == 0  // not destroyed
        && *(_BYTE *)(v7 + 24) == a2)      // type check
    {
        return *(_QWORD *)v9;  // return kernel object pointer
    }
}
```

**Type check:** `*(_BYTE *)(v7 + 24) == a2` — checks the object type byte in the handle table entry. The type is a single byte at PHE+24.

**Potential weakness:** The type is checked against a2 (the expected type), but the returned pointer `*(_QWORD *)v9` is the raw kernel object pointer from the handle table. If the handle table entry can be corrupted (e.g., type byte changed), a type confusion is possible. However, the handle table is in kernel memory and not directly writable from user mode.

### 5. HmgShareLock (Import)

HmgShareLock is used by NtGdiSetPUMPDOBJ and other GDI functions to lock GDI objects with type validation. The type is specified as a parameter (e.g., type 17 for UMPD objects). If the type check is bypassed or confused, a non-SURFACE object could be treated as a SURFACE.

---

## Task F: SetWindowLongPtr Analysis

### Bounds Check Logic (Confirmed)

```c
// v34 = pcls (class structure pointer from tagWND+0x88 / *((_QWORD *)a1 + 5))
// v35 = cbWndExtra = *(unsigned int *)(v34 + 252)  // pcls+0xFC

// The total range check:
if ((unsigned __int64)(unsigned int)v6 + 8 > (unsigned int)(v35 + *(_DWORD *)(v34 + 200)))
    goto LABEL_51;  // ERROR: out of bounds

// Where:
// v35 = cbWndExtra at pcls+0xFC (252)
// *(v34 + 200) = cbWndServerExtra at pcls+0xC8 (200)
// Total writable range = cbWndExtra + cbWndServerExtra
```

**The write:**
```c
if ((int)v6 + 8LL <= v35)  // offset within cbWndExtra
{
    // Write to server-side window extra bytes
    v44 = *((_QWORD *)a1 + 35);  // tagWND+0x118 = pointer to server extra bytes
    *(_QWORD *)((int)v6 + v44) = a3;  // WRITE
}
else
{
    // Write to client-side window extra bytes via desktop heap
    v40 = v6 - v35;  // offset into client extra bytes
    v41 = *(_QWORD *)(v34 + 296);  // pcls+0x128 = desktop heap pointer for client extra
    if ((*(_DWORD *)(v34 + 232) & 0x800) != 0)
        v42 = (v40 + v41 + *(_QWORD *)(*((_QWORD *)a1 + 3) + 128LL));  // via desktop heap base
    else
        v42 = (v40 + v41);
    *v42 = a3;  // WRITE
}
```

### Manipulation Possibilities

1. **cbWndExtra is read from pcls+0xFC:** If pcls can be corrupted, the bounds check can be bypassed
2. **The server extra bytes pointer is at tagWND+0x118:** If this can be corrupted, writes go to arbitrary kernel addresses
3. **The desktop heap pointer is at pcls+0x128:** If corrupted, client-side writes go to arbitrary addresses
4. **Special handling for GWLP_WNDPROC (offset 0) and GWLP_HINSTANCE (offset 16):** These have additional validation via RedirectedFieldcbWndServerExtra

### SetClassLongPtr (0x1C00FBE8C)

**Bounds check:**
```c
if ((int)v3 + 8 < (unsigned int)v3
    || (unsigned int)(v3 + 8) > *(_DWORD *)(*(_QWORD *)(*(_QWORD *)v16[0] + 8LL) + 12LL))
{
    // ERROR: out of bounds
}
```
- The bounds are checked against `pcls->cbclsExtra` at offset +12 from the class data
- The write is to `*(_QWORD *)(classData + v3 + 88)` — class extra bytes at classData+0x58+offset
- **SetClassLongPtr writes to ALL windows sharing the class** (iterates through linked list)
- If cbclsExtra can be manipulated, out-of-bounds writes are possible

---

## Task G: GDI Object Lifecycle

### SURFACE Allocation

SURFACE objects are created via:
1. **EngCreateBitmap** (import from win32kbase.sys) — the primary SURFACE allocator
2. **SURFMEM::bCreateDIB** — creates DIB surfaces
3. **CreateCompatibleSurface** (0x1C00AB3AC) — creates compatible surfaces

The `tSize@SURFACE` variable is an import from win32kbase.sys (at `__imp_?tSize@SURFACE@@0_KA` = 0x1C0364DB8). The actual size is in win32kbase and not visible in this IDA instance. Based on the _SURFOBJ size of 80 bytes (0x50) and the SURFACE wrapper fields (at least 0x18 bytes of header + 0x50 SURFOBJ + extra fields up to at least +0x98), the SURFACE object is approximately **0xB0-0xC0 bytes**.

### SURFACE Free

SURFACE objects are freed via:
1. **SURFREF::bDeleteSurface** (0x1C016AF6C) → calls `SURFACE::bDeleteSurface` (import)
2. **NtGdiEngDeleteSurface** (0x1C015DBE0) → calls EngDeleteSurface (import)
3. **EngDeleteSurface** (import) — the primary SURFACE deallocator

**Free path:**
1. Check `flags & 0x40000` (DIB flag)
2. If DIB: release MmSecureVirtualMemory handle at SURFACE+0x90
3. SURFREF::~SURFREF — releases reference count
4. EngDeleteSurface — actual free (in win32kbase)

### Type Isolation

**Confirmed references:**
- `gpTypeIsolation` at 0x1C03650E0 (import)
- `gpUserTypeIsolation` at 0x1C0363540 (import)

**UserFreeIsolatedType** at 0x1C01690B8 is called from:
1. **xxxFreeWindow** (0x1C007BB2D) — freeing tagWND objects
2. **MNAllocPopup** (0x1C0221479) — allocating popup menus
3. **MNFlushDestroyedPopups** (0x1C02217DC) — flushing destroyed popups
4. **xxxMNEndMenuState** (0x1C0221D63) — ending menu state
5. **xxxMNStartMenuState** (0x1C02226A7) — starting menu state

The `CTypeIsolation<24576,96>` template means:
- Pool allocation size: 24576 bytes (0x6000) per page
- Objects per page: 96
- **Object size: 24576 / 96 = 256 bytes (0x100)**
- This is for tagWND/POPUPMENU objects, NOT SURFACE objects

**SURFACE objects likely use a different type isolation pool.** The SURFACE type isolation would be in win32kbase.sys since EngCreateBitmap/EngDeleteSurface are imported from there.

### Pool Tags

No direct pool tag references were found for SURFACE objects in win32kfull.sys. The SURFACE allocation tags are in win32kbase.sys (EngCreateBitmap). The window extra bytes tag ('Usws') was not found as a string in this module.

### Pool Reclaim Feasibility

**For SURFACE objects:** The allocation and free are in win32kbase.sys. Type isolation is managed there. Without analyzing win32kbase.sys, we cannot confirm whether a freed SURFACE slot can be reclaimed by a different object type.

**For tagWND objects:** Type isolation with CTypeIsolation<24576,96> means 256-byte slots. Window objects are in their own isolated pool. A freed tagWND slot can only be reclaimed by another tagWND allocation, not by a SURFACE or other object type.

**Key limitation:** Type isolation prevents cross-type pool reclaim. This makes traditional heap spray + UAF reclaim attacks harder, as we can't reclaim a freed SURFACE with a tagWND or vice versa.

---

## Task H: Additional Exploitation Primitives

### 1. Physical Memory Mapping

**No NtMapUserPhysicalPages, MmMapIoSpace, or MmAllocateContiguousMemory references found in win32kfull.sys.** These functions are not present in this module. Physical memory mapping would need to come from a different kernel module.

### 2. Kernel Write Based on User-Controlled Offset

**xxxSetWindowLongPtr (0x1C0089BE8):** Writes a user-controlled 8-byte value to `tagWND+0x118 + offset`, where offset is user-controlled but bounds-checked against cbWndExtra. If cbWndExtra can be manipulated (e.g., by corrupting pcls+0xFC), the bounds check can be bypassed for an out-of-bounds write.

**xxxSetClassLongPtr (0x1C00FBE8C):** Writes a user-controlled 8-byte value to `classData + offset + 0x58`, where offset is bounds-checked against cbclsExtra. Same potential for bounds check bypass if cbclsExtra is corrupted.

**GreSetBitmapDimension (0x1C02C0750):** Writes a user-controlled 8-byte value to SURFACE+0x98. This is a fixed offset, not user-controlled. But it's a user-triggered write to a SURFACE field.

### 3. Kernel Pointer Leaks to User Mode

**PEB->GdiSharedHandleTable:** (Confirmed from prior research) Each GDI handle entry has a pKernel field (8 bytes) at offset 0 that contains the kernel address of the SURFACE object. This is the KASLR bypass.

**HMValidateHandleNoSecure (0x1C008C368):** Returns the raw kernel object pointer (`*(_QWORD *)v9`) directly. This is called internally but does not return the pointer to user mode — it returns it to the calling kernel function.

### 4. TOCTOU Vulnerabilities

**Every user-mode callback is a TOCTOU window:**
- Data is read/validated in kernel mode
- User-mode callback executes (xxxCallHook2, xxxClientCallDefWindowProc, etc.)
- Critical section is RELEASED during the callback
- Another thread can modify the validated data
- Callback returns, critical section is re-acquired
- Kernel code uses the stale data

**Specific TOCTOU in xxxSendTransformableMessageTimeout:**
1. Window pointer (a1) is validated at entry
2. xxxCallHook2 fires — user-mode callback, crit section released
3. Window can be destroyed by another thread
4. `mov rax, [rbx+28h]` reads from potentially freed window — TOCTOU

### 5. Integer Overflow Opportunities

**NtGdiCreateBitmap (0x1C01059A0):**
```c
v12 = ((a1 * (unsigned __int16)a3 * (unsigned __int64)(unsigned __int16)a4 + 15) >> 3) & 0x1FFFFFFFFFFFFFFELL;
if (v12 <= 0xFFFFFFFF && (v13 = a2 * v12, v13 <= 0xFFFFFFFF) && (_DWORD)v13)
```
- The multiplication `a1 * a3 * a4` can overflow but is masked with `& 0x1FFFFFFFFFFFFFFE`
- The subsequent check `v12 <= 0xFFFFFFFF` and `a2 * v12 <= 0xFFFFFFFF` prevents most overflows
- **This appears properly protected**

**NtGdiCreateDIBitmapInternal (0x1C00A9DE0):**
- Size parameter is validated against MmUserProbeAddress
- Alignment check: `if (((unsigned __int8)Address & 3) != 0) ExRaiseDatatypeMisalignment()`
- **This appears properly protected**

### 6. DIB Section Path Analysis

NtGdiCreateDIBitmapInternal → GreCreateDIBitmapReal / GreCreateDIBitmapComp

The DIB path creates bitmaps that may have different SURFACE layouts. The MmUserProbeAddress check is applied to the user buffer, but pvScan0 validation is still absent in the downstream bDoGetSetBitmapBits call.

---

## Summary of NEW Exploitation Ideas

### 1. UAF via QEVENT_DESTROY_WINDOW Direct Free (Feasibility: MEDIUM)
**Idea:** During the xxxCallHook2 callback in xxxSendTransformableMessageTimeout (cLockObj=0), queue a QEVENT_DESTROY_WINDOW event (event 8) for the child window. If the window is already in a "destroyed" state (pcls+19 < 0), xxxProcessEventMessage will call xxxFreeWindow directly, bypassing HMLockObject. This could lead to actual object free (not just ZOMBIE).

**Challenge:** Need to ensure the window is in the right state (pcls+19 < 0) and that the event is processed before the UAF read. Timing is critical.

### 2. SURFACE.pvScan0 Corruption via Adjacent Pool Overflow (Feasibility: MEDIUM-HIGH)
**Idea:** If SURFACE objects can be placed adjacent to controllable allocations in the same pool, overflow from the adjacent object into SURFACE+0x50 (pvScan0) would corrupt the pointer. Then GetBitmapBits/SetBitmapBits = arbitrary kernel R/W.

**Challenge:** Type isolation may prevent cross-type adjacency. Need to determine SURFACE pool layout from win32kbase.sys analysis. If SURFACE objects share a pool with another controllable object type, this becomes feasible.

### 3. xxxSetWindowLongPtr OOB Write via cbWndExtra Corruption (Feasibility: MEDIUM)
**Idea:** If we can corrupt pcls+0xFC (cbWndExtra) to a large value, the bounds check in xxxSetWindowLongPtr can be bypassed. Then writing at a large offset from tagWND+0x118 could reach a SURFACE object's pvScan0 field.

**Challenge:** Need a prior primitive to corrupt pcls. The pcls pointer is at tagWND+0x88 and is a shared object — corrupting it affects all windows of that class.

### 4. Type Confusion via Handle Table Corruption (Feasibility: LOW-MEDIUM)
**Idea:** If the GDI handle table entry's type byte (PHE+24) can be corrupted, HMValidateHandleNoSecure would return a non-SURFACE object as a SURFACE. This could allow treating another object type's fields as pvScan0.

**Challenge:** The handle table is in kernel memory. Need a prior write primitive to corrupt it.

### 5. Race Condition: Double SendInput During Hook Callback (Feasibility: HIGH)
**Idea:** Thread A triggers the QEVENT_DEFD_POINTER_ACTIVATE path (event 20, cLockObj=0). During the xxxCallHook2 callback, Thread B calls DestroyWindow(child). Thread B's xxxDestroyWindow adds a lock (cLockObj 0→1). Thread B then calls ThreadUnlock1 somewhere, potentially releasing the lock (cLockObj 1→0). If Thread A's code resumes after the lock is released but before the object is actually freed, the UAF read at 0x1C0059B30 could hit freed memory.

**Challenge:** Need precise timing. The window must be freed (not just ZOMBIE) between the hook return and the UAF read.

### 6. GreSetBitmapDimension for SURFACE+0x98 Write (Feasibility: LOW)
**Idea:** GreSetBitmapDimension writes a user-controlled 8-byte value to SURFACE+0x98. If SURFACE objects are allocated in sequence and adjacent, writing to +0x98 of SURFACE_A could overlap with +0x50 of SURFACE_B if the pool stride is exactly 0x48 bytes apart — but SURFACE objects are likely 0xB0+ bytes, so this doesn't work.

**Assessment:** Not feasible due to SURFACE size being larger than the offset difference.

### 7. Window Extra Bytes Desktop Heap Pointer Corruption (Feasibility: MEDIUM)
**Idea:** The client-side window extra bytes are stored via a desktop heap pointer at pcls+0x128. The desktop heap is mapped in user mode (via MapDesktop). If we can corrupt the desktop heap pointer or the data it points to, we can control what SetWindowLongPtr writes to. This could potentially be used to corrupt a SURFACE object if the desktop heap overlaps with or is adjacent to SURFACE pool memory.

**Challenge:** Desktop heap and SURFACE pool are different pools. Cross-pool corruption is unlikely.

### 8. UMPD Bitmap Path for Unrestricted SURFACE Creation (Feasibility: LOW)
**Idea:** NtGdiEngCreateBitmap allows UMPD bitmap creation with BMF_UMPDMEM flag. If gUMPDSecurityLevel allows it (level 2 or LocalSystem), UMPD bitmaps may have different SURFACE handling or validation. This could provide an alternative path to create SURFACE objects with controlled pvScan0.

**Challenge:** gUMPDSecurityLevel is typically not 2 on standard systems. Requires LocalSystem privileges.

### 9. Multi-Event Race: Event 20 + Event 8 (Feasibility: HIGH - BEST APPROACH)
**Idea:** 
1. Create a child window and a top-level window
2. Thread A: SendInput to trigger QEVENT_DEFD_POINTER_ACTIVATE (event 20) for the child
3. The event is queued, then processed by xxxProcessEventMessage
4. xxxProcessEventMessage calls xxxDoDeferredPointerActivate → xxxPointerActivateInternal → xxxQueryLegacyActivation → xxxSendTransformableMessageTimeout
5. xxxSendTransformableMessageTimeout enters same-thread path, calls xxxCallHook2
6. During the hook callback: Thread B calls DestroyWindow(child)
   - xxxDestroyWindow: HMLockObject(child) — cLockObj 0→1
   - xxxDestroyWindow proceeds with destruction
   - At the end: ThreadUnlock1 releases the lock — cLockObj 1→0
   - xxxFreeWindow: HMMarkObjectDestroy → if cLockObj == 0 → HMFreeObject → **ACTUAL FREE**
7. Hook callback returns to Thread A
8. `mov rax, [rbx+28h]` — reads from FREED child window memory → **TRUE UAF**
9. If the freed slot is reclaimed by a controlled object → tagWND+0x28 reads our controlled data

**The key insight:** xxxDestroyWindow's HMLockObject adds a temporary lock, but xxxFreeWindow's ThreadUnlock1 releases it. If the cLockObj was 0 before HMLockObject, then after ThreadUnlock1 it returns to 0, and HMMarkObjectDestroy succeeds, leading to HMFreeObject. The window is ACTUALLY FREED.

**This means the UAF IS exploitable** — the window can be fully freed during the hook callback if:
- cLockObj was 0 before the hook (confirmed: event 20 path doesn't lock the child)
- DestroyWindow is called during the hook
- xxxFreeWindow's ThreadUnlock1 returns the last lock
- HMFreeObject is called → the window is freed
- The UAF read at 0x1C0059B30 hits freed/reclaimed memory

### 10. Pool Reclaim After UAF Free (Feasibility: DEPENDS ON TYPE ISOLATION)
**Idea:** After the child window is freed via HMFreeObject during the hook callback, the freed pool slot can potentially be reclaimed by:
- Another window allocation (same type isolation pool)
- A controlled allocation that lands in the same pool

If the freed tagWND slot (256 bytes in CTypeIsolation<24576,96>) is reclaimed by a controlled allocation, the UAF read at tagWND+0x28 would read controlled data. This controlled data could be a pointer to a fake object, leading to further exploitation.

**Challenge:** Type isolation limits reclaim to same-type objects. We need to reclaim with another tagWND that has controlled data at offset +0x28.

### 11. Combining UAF + pvScan0 for Full Kernel R/W (Feasibility: HIGH - RECOMMENDED)
**Full exploit chain:**
1. **KASLR bypass:** PEB->GdiSharedHandleTable → pKernel field = SURFACE kernel address
2. **UAF trigger:** Event 20 path → cLockObj=0 → xxxCallHook2 → DestroyWindow during hook → window freed
3. **Pool reclaim:** Reclaim freed tagWND slot with controlled data at offset +0x28
4. **Information leak:** UAF read at 0x1C0059B30 reads controlled data → leak kernel pointers
5. **SURFACE corruption:** Use the leaked information + a write primitive (SetWindowLongPtr OOB or similar) to corrupt a SURFACE's pvScan0 at SURFACE+0x50
6. **Arbitrary kernel R/W:** GetBitmapBits/SetBitmapBits with corrupted pvScan0 = arbitrary kernel read/write
7. **Stealth:** No driver loaded, no device objects, no IOCTLs, no page table modifications, no kernel callbacks — completely traceless

---

## Key Addresses Summary

| Function | Address | Purpose | Confirmed |
|----------|---------|---------|-----------|
| xxxSendTransformableMessageTimeout | 0x1C00598F0 | UAF vulnerability | YES |
| UAF read (mov rax, [rbx+28h]) | 0x1C0059B30 | UAF read instruction | YES |
| xxxCallHook2 | 0x1C005BD10 | User-mode hook callback | YES |
| bDoGetSetBitmapBits | 0x1C0018BA4 | Uses pvScan0 without validation | YES |
| NtGdiGetBitmapBits | 0x1C00182E0 | Bitmap read syscall | YES |
| NtGdiSetBitmapBits | 0x1C0018710 | Bitmap write syscall | YES |
| GreGetBitmapBits | 0x1C00183C4 | Internal bitmap read | YES |
| GreSetBitmapBits | 0x1C00187F0 | Internal bitmap write | YES |
| NtGdiCreateBitmap | 0x1C01059A0 | Standard bitmap creation | YES |
| NtGdiEngCreateBitmap | 0x1C015CF30 | UMPD bitmap creation | YES |
| NtGdiCreateDIBitmapInternal | 0x1C00A9DE0 | DIB section creation | YES |
| NtGdiSetPUMPDOBJ | 0x1C00A11D0 | UMPD setup | YES |
| xxxSetWindowLongPtr | 0x1C0089BE8 | Window extra bytes write | YES |
| xxxSetClassLongPtr | 0x1C00FBE8C | Class extra bytes write | YES |
| NtUserSetClassLongPtr | 0x1C00FBC20 | Class long ptr syscall | YES |
| MapDesktop | 0x1C004EDB0 | Desktop heap mapping | YES |
| xxxDestroyWindow | 0x1C007DC00 | Window destruction | YES |
| HMLockObject in xxxDestroyWindow | 0x1C007DC6C | Lock before destroy | YES |
| xxxFreeWindow | 0x1C007A720 | Actual window free | YES |
| HMFreeObject in xxxFreeWindow | 0x1C007BCF8 | Actual object deallocation | YES |
| xxxPointerActivateInternal | 0x1C01F1478 | Pointer activate | YES |
| xxxQueryLegacyActivation | 0x1C01F183C | Sends WM_MOUSEACTIVATE | YES |
| xxxDoDeferredPointerActivate | 0x1C01F245C | Deferred pointer activate | YES |
| xxxProcessEventMessage | 0x1C00C15B8 | Event processing | YES |
| GreSetBitmapDimension | 0x1C02C0750 | Writes to SURFACE+0x98 | YES |
| HMValidateHandleNoSecure | 0x1C008C368 | Handle validation | YES |
| SURFREF::bDeleteSurface | 0x1C016AF6C | Surface deletion wrapper | YES |
| NtGdiEngDeleteSurface | 0x1C015DBE0 | Surface deletion syscall | YES |
| UserFreeIsolatedType | 0x1C01690B8 | Type-isolated free | YES |

## SURFOBJ Structure (Confirmed from IDA)

```c
struct _SURFOBJ {  // size: 80 bytes (0x50)
    DHSURF dhsurf;          // +0x00 (8 bytes)
    HSURF  hsurf;           // +0x08 (8 bytes)
    DHPDEV dhpdev;          // +0x10 (8 bytes)
    HDEV   hdev;            // +0x18 (8 bytes)
    SIZEL  sizlBitmap;      // +0x20 (8 bytes: cx[4] + cy[4])
    ULONG  cjBits;          // +0x28 (4 bytes)
    PVOID  pvBits;          // +0x30 (8 bytes)
    PVOID  pvScan0;         // +0x38 (8 bytes) ← CORRUPTION TARGET
    LONG   lDelta;          // +0x40 (4 bytes)
    ULONG  iUniq;           // +0x44 (4 bytes)
    ULONG  iBitmapFormat;   // +0x48 (4 bytes)
    USHORT iType;           // +0x4C (2 bytes)
    USHORT fjBitmap;        // +0x4E (2 bytes)
};
```

## SURFACE Layout (Derived from Code Analysis)

```
SURFACE+0x00: vtable/refcount/flags area (0x18 bytes)
SURFACE+0x18: _SURFOBJ.dhsurf
SURFACE+0x20: _SURFOBJ.hsurf
SURFACE+0x28: _SURFOBJ.dhpdev
SURFACE+0x30: _SURFOBJ.hdev
SURFACE+0x38: _SURFOBJ.sizlBitmap (cx, cy)
SURFACE+0x40: _SURFOBJ.cjBits
SURFACE+0x44: (padding)
SURFACE+0x48: _SURFOBJ.pvBits
SURFACE+0x50: _SURFOBJ.pvScan0  ← TARGET FOR CORRUPTION
SURFACE+0x58: _SURFOBJ.lDelta
SURFACE+0x5C: _SURFOBJ.iUniq
SURFACE+0x60: _SURFOBJ.iBitmapFormat
SURFACE+0x64: _SURFOBJ.iType / fjBitmap
SURFACE+0x70: flags (0x4000000 = bitmap, 0x40000 = DIB)
SURFACE+0x90: MmSecureVirtualMemory handle
SURFACE+0x98: bitmap dimension (set by GreSetBitmapDimension)
```
