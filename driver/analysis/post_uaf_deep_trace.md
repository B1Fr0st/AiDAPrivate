# Post-UAF Deep Trace: win32kfull.sys Write Primitive Analysis

## IDA Instance Info
- **Module**: win32kfull.sys
- **Imagebase**: 0x1C0000000
- **IDB Path**: C:\Windows\System32\win32kfull.sys.i64
- **Hex-Rays**: Ready
- **Analysis Date**: 2026-06-30

## Executive Summary

After exhaustive decompilation and analysis of the entire post-UAF call chain in `xxxSendTransformableMessageTimeout` (0x1C00598F0), **NO direct write primitive to pwndk+0x50 (SURFACE+0x50 / pvScan0) was found**. All Sfn* callback dispatchers write to CLIENTINFO+0x50 (a kernel thread-local structure), not to pwndk+0x50. SetOrClrWF has no callers with flags in the 0x4000 range needed to target pwndk+0x50. However, several controlled writes to OTHER SURFACE offsets were identified that could be useful in a multi-stage exploit.

---

## Task 1: Full Decompile of xxxSendTransformableMessageTimeout

### Function: 0x1C00598F0

The UAF occurs at 0x1C0059B30: `mov rax, [rbx+28h]` — reads pwndk from freed/reclaimed tagWND+0x28.

**Post-UAF flow:**

```
rbx = tagWND* (freed, reclaimed with controlled data)
rax = [rbx+0x28] = pwndk (controlled — points at SURFACE or fake WNDK)

test byte ptr [rax+12h], 4    ; check WNDK flags bit 2
jnz loc_1C0059CE9             ; branch if bit 2 SET
```

### Fall-Through Path (bit 2 CLEAR):
1. Calls `xxxSendMessageToClient(tagWND, msg, wParam, lParam, nullptr, 0, &v36)` at 0x1C0059B6D
2. After return, checks if tagWND is still current window
3. May call `xxxCallHook` (WH_CALLWNDPROCRET hook)
4. For WM_SYSCOMMAND (576): calls `FreeTouchInputInfo`
5. For WM_GESTURE (281): calls `FreeGestureInfo`
6. Returns result

### Branch Path (bit 2 SET) at 0x1C0059CE9:
1. `IoGetStackLimits` — checks stack space (must be >= 0x2000)
2. Reads `v28 = *(_QWORD *)(*(_QWORD *)(a1 + 40) + 120LL)` = pwndk+0x78 (handler index)
3. Validates `v28 < 7`
4. Calls `gServerHandlers[v28](tagWND, msg, wParam, lParam)` at 0x1C0059D5C
5. Returns result

### Writes in xxxSendTransformableMessageTimeout (post-UAF):
- **NONE to [reg+0x50]** — no writes to any [reg+0x50] in the entire function
- The only memory writes are to stack variables and the `*v14 = v24` (return value to caller's pointer)

---

## Task 2: Deep Trace Fall-Through Path

### xxxSendMessageToClient (0x1C0059E70)

Decompiled fully. Key operations:
- Reads pwndk from `*((_QWORD *)a1 + 5)` = tagWND+0x28
- Reads pwndk+0x12 (flags), pwndk+0x78 (handler index), pwndk+0x2A (window type)
- Dispatches:
  - If `(msg & 0x1FFFF) >= 0x400`: calls `SfnDWORD(a1, msg, wParam, lParam, pwndk+0x78, gpsi+752)`
  - Else: calls `gapfnScSendMessage[MessageTable[msg]](a1, msg, wParam, lParam, pwndk+0x78, gpsi+752, ...)`
- For filtered messages (certain window types): calls `xxxDefWindowProc(a1)`

**Writes to [reg+0x50]**: NONE in this function

### SfnDWORD (0x1C006B320)

Decompiled fully. Key operations:
1. Reads `a1[5]` = tagWND+0x28 = pwndk
2. Gets CLIENTINFO: `v20 = *(_QWORD *)(v12 + 480)` where v12 = W32THREAD
3. **Writes to CLIENTINFO+0x40**: `*(_QWORD *)(v20 + 64) = *a1` (HWND from tagWND+0x00)
4. **Writes to CLIENTINFO+0x48**: `*(_QWORD *)(v20 + 72) = v15` (pwndk - DesktopHeapDelta)
5. **Writes to CLIENTINFO+0x50**: `*(_QWORD *)(v20 + 80) = v22` where `v22 = *(_QWORD *)(a1[5] + 224)` = **pwndk+0xE0**
6. Calls `KeUserModeCallback(2, &v57, 48, &v54, &v67)` — transitions to user mode
7. After callback: restores CLIENTINFO+0x40 and +0x50

**Critical finding**: The write at 0x1C006B4B2 (`mov [rax+50h], rcx`) writes to **CLIENTINFO+0x50**, NOT pwndk+0x50. rax = `[rsi+1E0h]` = CLIENTINFO pointer from W32THREAD. rcx = `[pwndk+0xE0]`.

### SfnOUTSTRING (0x1C00D25F0) — Handler for WM_MOUSEACTIVATE

WM_MOUSEACTIVATE (0x21) maps to MessageTable[0x21] = index 4 = SfnOUTSTRING.

Decompiled fully. Same pattern as SfnDWORD:
- Writes pwndk+0xE0 to CLIENTINFO+0x50 at 0x1C00D2A03
- Also writes `*((_QWORD *)v21 + 5) = v16` to a heap-allocated callback buffer at [r14+0x28] (0x1C00D28AF) — this is the callback data structure, NOT pwndk
- Calls `KeUserModeCallback(35, v21, ...)` — transitions to user mode

### ALL Sfn* Functions — Complete Write Survey

| Sfn Function | Address | [reg+50h] Write | Target |
|---|---|---|---|
| SfnDWORD | 0x1C006B320 | 0x1C006B4B2 | CLIENTINFO+0x50 |
| SfnOUTSTRING | 0x1C00D25F0 | 0x1C00D2A03 | CLIENTINFO+0x50 |
| SfnNCDESTROY | 0x1C0051AB0 | 0x1C0051C42 | CLIENTINFO+0x50 |
| SfnINLPWINDOWPOS | 0x1C0051F60 | 0x1C0052120 | CLIENTINFO+0x50 |
| SfnINOUTSTYLECHANGE | 0x1C00D6480 | 0x1C00D661D | CLIENTINFO+0x50 |
| SfnINOUTNCCALCSIZE | 0x1C00F9950 | 0x1C00F9B3F | CLIENTINFO+0x50 |
| SfnINOUTLPWINDOWPOS | 0x1C00F84A0 | 0x1C00F865A | CLIENTINFO+0x50 |
| SfnEMPTY | 0x1C004F910 | 0x1C004FA50 | CLIENTINFO+0x50 |
| SfnDWORDOPTINLPMSG | 0x1C0138CC0 | 0x1C0138F0D | CLIENTINFO+0x50 |
| SfnINOUTLPSCROLLINFO | 0x1C010E000 | 0x1C010E181 | CLIENTINFO+0x50 |
| SfnINSTRINGNULL | 0x1C004FD4F | NONE | - |
| SfnGETWINDOWDATA | 0x1C0228EB0 | NONE | - |

**ALL Sfn* writes go to CLIENTINFO+0x50, value = pwndk+0xE0. CLIENTINFO is at [W32THREAD+0x1E0] — a kernel thread structure. Not directly user-controllable.**

### CLIENTINFO+0x50 Redirect Analysis

The CLIENTINFO pointer is re-read after the user-mode callback:
```c
v34 = *(_QWORD *)(v12 + 480);  // re-read from W32THREAD+0x1E0
*(_OWORD *)(v34 + 64) = v55;   // restore CLIENTINFO+0x40
*(_QWORD *)(v34 + 80) = v56;   // restore CLIENTINFO+0x50
```

W32THREAD is a kernel structure. User-mode code cannot directly modify it. The CLIENTINFO pointer in W32THREAD+0x1E0 normally points to TEB+0x800 (Win32ClientInfo). To redirect the CLIENTINFO write to a SURFACE, an attacker would need to corrupt W32THREAD+0x1E0 to point at a SURFACE — which requires a separate kernel write primitive.

---

## Task 3: Deep Trace All 7 gServerHandlers

### Handler 0: xxxDefWindowProc (0x1C00484E0)
- Reads pwndk+0x12 (byte 18 flags), pwndk+0x13 (byte 19 flags), pwndk+0x2A (window type)
- Dispatches to SfnDWORD or gapfnScSendMessage based on message number
- Falls through to xxxRealDefWindowProc for certain conditions
- **Writes to [reg+0x50]**: NONE
- **Writes to [reg+0x28]**: NONE

### Handler 1: xxxDesktopWndProc (0x1C0046290)
- Reads tagWND+0x68 (offset 104)
- Increments/decrements a counter at [v4+0x20]
- Dispatches to xxxDesktopWndProcWorker
- **Writes to [reg+0x50]**: NONE

### Handler 2: xxxSwitchWndProc (0x1C01F4CC0)
- Validates class (size 672)
- Writes to `**((_QWORD **)a1 + 35)` = tagWND+0x118 (window data pointer)
- Handles WM_CREATE, WM_PAINT, WM_SHOWWINDOW, WM_QUERYNEWPALETTE
- Falls through to xxxDefWindowProc
- **Writes to [reg+0x50]**: NONE

### Handler 3: xxxMenuWindowProc (0x1C023B620)
- Very complex, handles 30+ message types
- Extensive menu operations (popup, hierarchy, painting, scrolling)
- Calls xxxSendMessage (recursive), xxxSetWindowPos, xxxDefWindowProc
- **Writes to [reg+0x50]**: NONE
- Deep callees checked: xxxMNSelectItem, xxxMNKeyDown, xxxMNOpenHierarchy, etc. — none write to [reg+0x50]

### Handler 4: xxxSBWndProc (0x1C0245BE0)
- Validates class (size 666)
- SetOrClrWF calls with flag 0x0D → pwndk+0x10 (at 0x1C0246398, 0x1C02463BD)
  - These are `SetOrClrWF(1, *v11, 3588, ...)` — wait, 3588 = 0xE04
  - **Correction**: flag = 0xE04 → (0xE04 >> 8) + 0x10 = 0xE + 0x10 = 0x1E → writes to **pwndk+0x1E**
- Also: `*(_DWORD *)(v13 + 28) &= 0xFFCFFFFF` — writes to pwndk+0x1C (clears bits 20,19)
- Sends WM_HSCROLL/WM_VSCROLL via xxxSendTransformableMessageTimeout
- **Writes to [reg+0x50]**: NONE
- **Writes to pwndk+0x1C and pwndk+0x1E**: YES (wrong offset for pvScan0)

### Handler 5: xxxTooltipWndProc (0x1C00DAED0)
- Validates class (size 694)
- Writes `*(_DWORD *)(v9 + 40)` = tagTOOLTIPWND+0x28 (NOT tagWND+0x28)
  - v9 = `*((_QWORD *)a1 + 35)` = tagWND+0x118 (tooltip-specific data pointer)
  - So this writes to tagWND+0x118+0x28, NOT tagWND+0x28
- Writes `*(_DWORD *)(*(_QWORD *)(*(_QWORD *)v9 + 24LL) + 48LL) &= 0xFFFFFCFF`
  - This is tagWND+0x18+0x30 = tagWND+0x48? No: *v9 = tagWND, then +24 = tagWND+0x18, then +48 = tagWND+0x18+0x30 = tagWND+0x48
  - Actually: `*(_QWORD *)v9` = first qword of tagTOOLTIPWND = tagWND* (set earlier as `*(_QWORD *)v9 = a1`)
  - Then `*(_QWORD *)(*(_QWORD *)v9 + 24LL)` = tagWND+0x18 = pti (thread info)
  - Then `+ 48LL` = pti+0x30 = thread flags
  - This writes to THREADINFO+0x30, NOT to tagWND or pwndk
- Calls xxxSendTransformableMessageTimeout recursively for WM_PRINT (0x317)
- **Writes to [reg+0x50]**: NONE
- **Prior analysis claim that xxxTooltipWndProc writes to [tagWND+0x28] is INCORRECT** — it writes to tagTOOLTIPWND+0x28 (which is at tagWND+0x118+0x28)

### Handler 6: xxxEventWndProc (0x1C0023B00)
- Reads tagWND+0x118 (offset 280) as event data pointer
- Validates a handle from the event data
- Handles WM_DESTROY (2) and WM_DISPLAYCHANGE (60)
- Falls through to xxxDefWindowProc
- **Writes to [reg+0x50]**: NONE

---

## Task 4: SetOrClrWF Deep Analysis

### Function: SetOrClrWF (0x1C004DF08)

Decompiled fully. Write formula confirmed:

```c
v8 = *(_DWORD **)(a2 + 40);        // v8 = pwndk = [tagWND+0x28]
v10 = (unsigned __int64)a3 >> 8;   // v10 = flag >> 8
*((_BYTE *)v8 + v10 + 16) = v12;   // writes to pwndk + (flag >> 8) + 0x10
```

**For pwndk+0x50**: `(flag >> 8) + 0x10 = 0x50` → `flag >> 8 = 0x40` → `flag = 0x4000 + bits`

### SetOrClrWF Caller Flag Analysis (266 total callers)

**Flags >= 0x4000 (would reach pwndk+0x50+):**

| Flag | Offset | Function | Reachable from post-UAF? |
|---|---|---|---|
| 0xDB01 | pwndk+0xEB | NtUserSetCoreWindow, SetWindowSubtreeCoreWindowStatus | NO |
| 0xDB02 | pwndk+0xEB | SetWindowSubtreeCoreWindowStatus | NO |
| 0xDB80 | pwndk+0xEB | xxxSetBridgeWindowChild | NO |
| 0xDA20 | pwndk+0xEA | xxxCreateWindowEx | NO |
| 0xDA40 | pwndk+0xEA | xxxCreateWindowEx | NO |
| 0xDA80 | pwndk+0xEA | xxxMinMaximizeEx, xxxCloneWindowPosAndArrangement | NO |
| 0xDA01 | pwndk+0xEA | xxxDisableImmersiveOwner | NO |
| 0xD901 | pwndk+0xE9 | xxxMinMaximizeEx, MakeArrangedStateObservable | NO |
| 0xD902 | pwndk+0xE9 | xxxMinMaximizeEx | NO |
| 0xD910 | pwndk+0xE9 | NtUserSetChildWindowNoActivate | NO |
| 0xD920 | pwndk+0xE9 | xxxSendSysCommandToWindow | NO |

**NO callers with flag in 0x4000-0x40FF range (→ pwndk+0x50).**

**NO callers with flag in 0x3800-0x47FF range (→ pwndk+0x48 to pwndk+0x57).**

The flag range has a massive gap: 0x0XXX (→ pwndk+0x10-0x1F) jumps directly to 0xBXXX (→ pwndk+0x1B) and 0xDXXX (→ pwndk+0xE9-0xEB). No flags exist in the 0x3800-0xCFFF range that would target pwndk+0x48-0xDF.

### ValidateState (0x1C0131938)

```c
BOOL8 ValidateState(__int16 a1) {
    return HIBYTE(a1) <= 0xF && ((BYTE)a1 & byte_1C02EB270[HIBYTE(a1)]) == (BYTE)a1;
}
```

ValidateState lookup table at 0x1C02EB270:

| High Byte | Mask | Allowed Low Bytes |
|---|---|---|
| 0x00-0x04 | 0x00 | 0x00 only (no flags) |
| 0x05 | 0x02 | 0x02 |
| 0x06 | 0x00 | 0x00 only |
| 0x07 | 0x10 | 0x10 |
| 0x08 | 0x00 | 0x00 only |
| 0x09 | 0x03 | 0x01, 0x02, 0x03 |
| 0x0A | 0x02 | 0x02 |
| 0x0B | 0x00 | 0x00 only |
| 0x0C | 0x20 | 0x20 |
| 0x0D | 0x0A | 0x02, 0x08, 0x0A |
| 0x0E | 0xB9 | 0x01, 0x08, 0x09, 0x10, 0x20, 0x80, 0x88, 0x89, 0x98, 0x99, 0xA0, 0xB0, 0xB8, 0xB9, etc. |
| 0x0F | 0x02 | 0x02 |

**Maximum offset via SetWindowState: pwndk + (0x0F) + 0x10 = pwndk+0x1F. CANNOT reach pwndk+0x50.**

### SetOrClrWF calls in post-UAF reachable functions:

| Function | Flag | Target Offset |
|---|---|---|
| xxxRealDefWindowProc | 0x202 | pwndk+0x12 |
| xxxRealDefWindowProc | 0x280 | pwndk+0x12 |
| xxxDestroyWindow | 0x480 | pwndk+0x14 |
| xxxDestroyWindow | 0x380 | pwndk+0x13 |
| xxxDWP_DoNCActivate | 0x40 | pwndk+0x10 |
| xxxDWP_UpdateUIState | 0xB04/0xB40/0xB80 | pwndk+0x1B |
| xxxDrawCaptionBar | 0x708 | pwndk+0x17 |
| xxxCalcClientRect | 0x410 | pwndk+0x14 |
| xxxDWP_SetRedraw | 0x108 | pwndk+0x11 |
| xxxSetWindowStyle | 0xB02 | pwndk+0x1B |
| xxxSetWindowData | 0x204/0x208 | pwndk+0x12 |
| xxxSBWndProc | 0xE04 | pwndk+0x1E |

**Maximum offset via post-UAF reachable SetOrClrWF: pwndk+0x1E. CANNOT reach pwndk+0x50.**

---

## Task 5: Search for Writes to [reg+0x50]

### Methodology
Searched all functions in the post-UAF call chain for `mov [reg+50h]`, `and [reg+50h]`, `or [reg+50h]`, etc. (excluding stack-relative [rbp+50h] and [rsp+50h]).

### Results in post-UAF reachable functions:

| Function | Address | Instruction | Target |
|---|---|---|---|
| SfnDWORD | 0x1C006B4B2 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnDWORD | 0x1C006B640 | `movsd [rax+50h], xmm1` | CLIENTINFO+0x50 (restore) |
| SfnOUTSTRING | 0x1C00D2A03 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnNCDESTROY | 0x1C0051C42 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnINLPWINDOWPOS | 0x1C0052120 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnINOUTSTYLECHANGE | 0x1C00D661D | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnINOUTNCCALCSIZE | 0x1C00F9B3F | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnINOUTLPWINDOWPOS | 0x1C00F865A | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnEMPTY | 0x1C004FA50 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnDWORDOPTINLPMSG | 0x1C0138F0D | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| SfnINOUTLPSCROLLINFO | 0x1C010E181 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 |
| xxxInterSendMsgEx | 0x1C005AD8B | `mov [rdi+50h], ecx` | Linked list node+0x50 (tick count) |

### Functions with NO writes to [reg+0x50]:
- xxxSendTransformableMessageTimeout
- xxxSendMessageToClient
- xxxDefWindowProc
- xxxRealDefWindowProc
- xxxDesktopWndProc / xxxDesktopWndProcWorker
- xxxSwitchWndProc
- xxxMenuWindowProc
- xxxSBWndProc
- xxxTooltipWndProc
- xxxEventWndProc
- xxxDestroyWindow
- xxxSysCommand
- xxxDWP_DoNCActivate
- xxxDWP_UpdateUIState
- xxxDrawCaptionBar
- xxxCalcClientRect
- xxxDWP_SetCursor
- DefSetText
- xxxAdjustSize
- xxxDWP_SetRedraw
- xxxRedrawTitle
- xxxInternalDoSyncPaint
- xxxSetWindowData
- xxxDispatchMessage
- NtUserMessageCall
- xxxSendMessage
- SetOrClrWF
- SetWindowState / ClearWindowState

**CONCLUSION: No write to [pwndk+0x50] exists in ANY function reachable from the post-UAF code path.**

---

## Task 6: User-Mode Callback Analysis

### Callback Flow (Fall-Through Path)

1. `xxxSendMessageToClient` dispatches to SfnDWORD or SfnOUTSTRING (for WM_MOUSEACTIVATE)
2. Sfn* function calls `KeUserModeCallback(ApiNumber, data, size, &output, &outputSize)`
3. User-mode window procedure executes
4. Kernel re-enters critical section
5. Sfn* function reads return value from user-mode output buffer

### User-Mode API Calls During Callback

During the callback, user-mode code can call Win32 APIs that trigger kernel writes:

| API | Kernel Handler | Write Target | Useful for pvScan0? |
|---|---|---|---|
| SetWindowLongPtr(GWLP_HINSTANCE) | xxxSetWindowData | pwndk+0x20 = SURFACE+0x20 | NO (wrong offset) |
| SetWindowLongPtr(GWLP_USERDATA) | xxxSetWindowData | pwndk+0xD8 = SURFACE+0xD8 | NO |
| SetWindowLongPtr(GWLP_WNDPROC) | xxxSetWindowData | pwndk+0x78 = SURFACE+0x78 | NO |
| SetWindowLongPtr(GWLP_ID) | xxxSetWindowData | pwndk+0x98 = SURFACE+0x98 | NO |
| SetWindowLongPtr(DWLP_DLGPROC) | xxxSetWindowData | pwndk+0xEA = SURFACE+0xEA | NO |
| ShowWindow | xxxShowWindowEx | SetOrClrWF (pwndk+0x10-0x1F) | NO |
| DestroyWindow | xxxDestroyWindow | SetOrClrWF (pwndk+0x10-0x14) | NO |
| SendMessage | NtUserMessageCall → xxxSendTransformableMessageTimeout | Recursive UAF | MAYBE (see below) |
| SetClassLongPtr | class data writes | Different structure | NO |
| SetProp | property list | Session pool alloc | NO |

### Recursive UAF Path

If the user-mode callback calls `SendMessage(reclaimedWnd, someMsg, ...)`, it triggers:
1. `NtUserMessageCall` → `xxxSendMessage` → `xxxSendTransformableMessageTimeout`
2. The same tagWND (reclaimed) is passed again
3. The UAF read at 0x1C0059B30 occurs again: `mov rax, [rbx+28h]` = pwndk
4. The same post-UAF code paths are available

**However**: The recursive call uses the SAME pwndk (from tagWND+0x28). If the first callback modified pwndk via SetWindowLongPtr, the second call would read the modified pwndk. But xxxSetWindowData doesn't write to pwndk+0x28 (the pwndk pointer itself) — it writes to other offsets within pwndk.

**Wait**: Actually, in the first callback, the user-mode code calls SetWindowLongPtr on the reclaimed tagWND. But `xxxSetWindowData` reads pwndk from `*((_QWORD *)a1 + 5)` = tagWND+0x28. If tagWND+0x28 was set by the attacker during reclaim, SetWindowLongPtr writes to the attacker-controlled pwndk+offset. The writes go to pwndk+0x20, 0x78, 0x98, 0xD8, 0xEA — NONE at pwndk+0x50.

---

## Task 7: tagWND+0x50 Field Analysis

### tagWND Structure (0x150 bytes / 336 bytes)

| Offset | Field | Access Pattern |
|---|---|---|
| 0x00 | HWND (handle) | Read by Sfn* for CLIENTINFO |
| 0x10 | pti (THREADINFO*) | Read for thread checks |
| 0x18 | flags byte | Read for validation |
| 0x28 | pwndk (WNDK*) | **UAF READ TARGET** |
| 0x50 | ??? | **No accesses found in post-UAF path** |
| 0x68 | ??? | Read by xxxDesktopWndProc |
| 0xA8 | window ID | Written by xxxSetWindowData GWLP_ID |
| 0x118 | window data (class-specific) | Read/written by various handlers |

**tagWND+0x50**: No kernel code in the post-UAF call chain reads or writes to this offset. If we could reclaim the freed tagWND with a SURFACE (impossible due to size mismatch — 0x150 vs 0x2B8), tagWND+0x50 would equal SURFACE+0x50 = pvScan0. But there is no write primitive to tagWND+0x50 in the reachable code.

---

## Task 8: Alternative Write Primitive Search

### Functions taking tagWND* that write to [tagWND+0x50] or [pwndk+0x50]

**NO function found** in win32kfull.sys that:
1. Takes a tagWND* as parameter
2. Writes to [tagWND+0x50] directly
3. Is reachable from the post-UAF code path

### Functions writing to [pwndk+0x50] where pwndk = [tagWND+0x28]

**NO function found.** The SetOrClrWF formula (pwndk + (flag>>8) + 0x10) would require flag=0x4000, but no caller uses this flag value.

### xxxRealDefWindowProc Deep Analysis

Decompiled fully (57K chars). Handles ~40 message types. Calls SetOrClrWF only with flags 0x202 and 0x280 (both → pwndk+0x12). All deeper callees checked — none write to [reg+0x50].

---

## Task 9: Reclaim Strategy Analysis

### Size Calculations (using py_eval)

```
tagWND = 0x150 bytes (336 bytes) — session paged pool, NOT type-isolated
SURFACE = 0x2B8 bytes (696 bytes) — type-isolated in "Gila" pool, slot 0x2C0
```

**Size mismatch**: 0x150 < 0x2B8. The pool allocator will NOT serve a 0x2C0-byte slot for a 0x150-byte request. Direct cross-type reclaim of tagWND with SURFACE is **IMPOSSIBLE**.

### Alternative Reclaim Objects (0x150 bytes in session pool)

Objects of exactly 0x150 bytes that could reclaim the freed tagWND:
- Requires further research into session pool object sizes
- Common candidates: tagMENU, tagPOPUPMENU, tagMENUWND, tagTOOLTIPWND
- These would need controlled data at offset 0x28 (to set pwndk) and would benefit from a write to offset 0x50

### SURFACE Size Reduction

To make a SURFACE fit in 0x150 bytes:
```
SURFACE base = 0x2B8 (SURFOBJ header + BASEOBJECT)
SURFOBJ starts at SURFACE+0x18
SURFOBJ size = 0x40 (64 bytes)
BASEOBJECT size = 0x18 (24 bytes)
Remaining = 0x2B8 - 0x18 - 0x40 = 0x260 (bitmap data area)
```
Reducing SURFACE to 0x150 would require eliminating 0x168 bytes of bitmap storage. This is not possible with standard GDI bitmap creation APIs.

---

## Task 10: SfnDWORD Message Table

### gapfnScSendMessage Table (0x1C02E26D0)

| Index | Function | Address |
|---|---|---|
| 0 | SfnDWORD | 0x1C006B320 |
| 1 | SfnNCDESTROY | 0x1C0051AB0 |
| 2 | SfnINLPCREATESTRUCT | 0x1C0020F50 |
| 3 | SfnINSTRINGNULL | 0x1C004FD4F |
| 4 | SfnOUTSTRING | 0x1C00D25F0 |
| 5 | SfnINSTRING | 0x1C011EB70 |
| 6 | SfnINOUTLPPOINT5 | 0x1C0103A80 |
| 7 | SfnINLPDRAWITEMSTRUCT | 0x1C0154F10 |
| 8 | SfnINOUTLPMEASUREITEMSTRUCT | 0x1C0158070 |
| 9 | SfnINLPDELETEITEMSTRUCT | 0x1C022AB40 |
| ... | ... | ... |

### WM_MOUSEACTIVATE (0x21) Dispatch

```
MessageTable[0x21] = 4
gapfnScSendMessage[4] = SfnOUTSTRING (0x1C00D25F0)
```

SfnOUTSTRING handles string-based messages (WM_GETTEXT, WM_SETTEXT, WM_MOUSEACTIVATE, etc.). For WM_MOUSEACTIVATE, the string handling path is not taken (it's a DWORD message), so SfnOUTSTRING effectively behaves like SfnDWORD — writes pwndk+0xE0 to CLIENTINFO+0x50 and calls KeUserModeCallback.

### Key Message Mappings

| Message | Value | Table Index | Sfn Handler |
|---|---|---|---|
| WM_MOUSEACTIVATE | 0x21 | 4 | SfnOUTSTRING |
| WM_NCCREATE | 0x81 | 0 | SfnDWORD |
| WM_NCHITTEST | 0x84 | 0 | SfnDWORD |
| WM_ACTIVATE | 0x06 | 0 | SfnDWORD |
| WM_CLOSE | 0x10 | 0 | SfnDWORD |
| WM_PAINT | 0x0F | 0 | SfnDWORD |
| WM_ERASEBKGND | 0x14 | 0 | SfnDWORD |
| WM_SETTEXT | 0x0C | 0 | SfnDWORD |
| WM_NCACTIVATE | 0x24 | 0 | SfnDWORD |

**ALL Sfn* handlers write to CLIENTINFO+0x50, NOT pwndk+0x50.**

---

## Task 11: Comprehensive Write Search

### Complete Map of Writes in Post-UAF Call Chain

| Write Location | Instruction | Target | Value | Useful for pvScan0? |
|---|---|---|---|---|
| SfnDWORD 0x1C006B4B2 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 | pwndk+0xE0 | NO (CLIENTINFO, not pwndk) |
| SfnDWORD 0x1C006B640 | `movsd [rax+50h], xmm1` | CLIENTINFO+0x50 | saved old value | NO (restore) |
| SfnOUTSTRING 0x1C00D2A03 | `mov [rax+50h], rcx` | CLIENTINFO+0x50 | pwndk+0xE0 | NO |
| SfnOUTSTRING 0x1C00D28AF | `mov [r14+28h], rbx` | Callback buffer+0x28 | pwndk delta | NO (heap buffer) |
| Sfn* (all) | `mov [rax+40h], rcx` | CLIENTINFO+0x40 | HWND | NO |
| Sfn* (all) | `mov [rax+48h], ...` | CLIENTINFO+0x48 | pwndk delta | NO |
| SetOrClrWF (various) | `mov [pwndk+XX], byte` | pwndk+0x10 to 0x1F | flag bits | NO (wrong offset) |
| xxxSBWndProc 0x1C0245E95 | `and [pwndk+1Ch], dword` | pwndk+0x1C | clears bits 20,19 | NO |
| xxxSetWindowData | `mov [pwndk+20h], qword` | pwndk+0x20 | hInstance | NO |
| xxxSetWindowData | `mov [pwndk+78h], qword` | pwndk+0x78 | wndproc | NO |
| xxxSetWindowData | `mov [pwndk+98h], qword` | pwndk+0x98 | window ID | NO |
| xxxSetWindowData | `mov [pwndk+D8h], qword` | pwndk+0xD8 | user data | NO |
| xxxSetWindowData | `mov [pwndk+EAh], byte` | pwndk+0xEA | dialog proc flags | NO |
| xxxSetWindowData | `mov [pwndk+28h], word` | pwndk+0x28 | WOW module | NO (overwrites pwndk+0x28 partial) |
| HMLockObject | increment [obj+08h] | SURFACE+0x08 | lock count +1 | NO |

---

## Task 12: HMLockObject and Handle-Based Writes

### HMLockObject Analysis

When SfnDWORD calls `HMLockObject(a1)`:
1. Reads `*a1` = tagWND+0x00 = HWND (handle value)
2. If tagWND is reclaimed with a SURFACE, tagWND+0x00 = SURFACE+0x00 = BASEOBJECT.hHm (GDI handle)
3. HMLockObject increments the lock count at SURFACE+0x08 (BASEOBJECT.cLockObj)

**This is a controlled increment at SURFACE+0x08, NOT at SURFACE+0x50.**

### HmgSetOwner, HmgMarkLazyDelete, and other Hmg* functions

These functions operate on the handle table entry, not on the object body. They modify:
- Handle table entry flags
- Handle table entry owner
- Handle table entry lock count

None of these write to the object body at offset 0x50.

---

## Complete Write Table: All Writes in Post-UAF Call Chain

### Writes to pwndk (SURFACE when type-confused):

| Offset | Write Type | Value | Source Function | Reachable? |
|---|---|---|---|---|
| pwndk+0x10 | BYTE (set/clear) | flag bits | SetOrClrWF (various) | YES |
| pwndk+0x11 | BYTE (set/clear) | flag bits | SetOrClrWF | YES |
| pwndk+0x12 | BYTE (set/clear) | flag bits | SetOrClrWF | YES |
| pwndk+0x13 | BYTE (set/clear) | flag bits | SetOrClrWF | YES |
| pwndk+0x14 | BYTE (set/clear) | flag bits | SetOrClrWF | YES |
| pwndk+0x17 | BYTE (set/clear) | flag bits | SetOrClrWF | YES |
| pwndk+0x1B | BYTE (set/clear) | flag bits | SetOrClrWF | YES |
| pwndk+0x1C | DWORD (AND) | clears bits 20,19 | xxxSBWndProc | YES |
| pwndk+0x1E | BYTE (set/clear) | flag bits | SetOrClrWF (xxxSBWndProc) | YES |
| pwndk+0x20 | QWORD | hInstance value | xxxSetWindowData | YES (via callback) |
| pwndk+0x28 | WORD | WOW module | xxxSetWindowData | YES (via callback) |
| pwndk+0x78 | QWORD | window procedure | xxxSetWindowData | YES (via callback) |
| pwndk+0x98 | QWORD | window ID | xxxSetWindowData | YES (via callback) |
| pwndk+0xD8 | QWORD | user data | xxxSetWindowData | YES (via callback) |
| pwndk+0xEA | BYTE | dialog proc flags | xxxSetWindowData | YES (via callback) |
| pwndk+0xF0 | QWORD | unknown | xxxSetWindowData | YES (via callback) |

### Writes NOT to pwndk but to other structures:

| Target | Offset | Value | Source | Notes |
|---|---|---|---|---|
| CLIENTINFO | +0x40 | HWND | Sfn* | Thread-local, not pwndk |
| CLIENTINFO | +0x48 | pwndk delta | Sfn* | Thread-local, not pwndk |
| CLIENTINFO | +0x50 | pwndk+0xE0 | Sfn* | Thread-local, not pwndk |
| SURFACE | +0x08 | lock count+1 | HMLockObject | Handle-based increment |
| Callback buffer | +0x28 | pwndk delta | Sfn* | Heap allocation, not pwndk |

---

## Assessment of Each Write's Usefulness for pvScan0 Corruption

### Direct pvScan0 Corruption (pwndk+0x50 = SURFACE+0x50)

**IMPOSSIBLE** with the writes available in the post-UAF code path. No write targets pwndk+0x50.

### Indirect pvScan0 Corruption Strategies

1. **CLIENTINFO redirect**: If W32THREAD+0x1E0 could be corrupted to point at a SURFACE, the Sfn* write to CLIENTINFO+0x50 would write pwndk+0xE0 to SURFACE+0x50 = pvScan0. But corrupting W32THREAD+0x1E0 requires a separate kernel write primitive.

2. **SURFOBJ field corruption**: Writing to pwndk+0x20 (SURFACE+0x20 = SURFOBJ.hsurf) via SetWindowLongPtr(GWLP_HINSTANCE) corrupts the surface handle. This could potentially cause GDI to misinterpret the SURFACE, but it doesn't directly corrupt pvScan0.

3. **Multi-stage via pwndk+0x28 partial write**: xxxSetWindowData writes a 16-bit value to pwndk+0x28. If pwndk points at a SURFACE, this corrupts SURFACE+0x28 = SURFOBJ.dhpdev. Corrupting dhpdev could cause GDI to use a fake physical device structure, potentially leading to further corruption. This is a complex multi-stage approach.

4. **pwndk+0x78 write (GWLP_WNDPROC)**: Writing to pwndk+0x78 = SURFACE+0x78 could corrupt SURFACE data at that offset. If this is part of a bitmap's internal structure, it might cause issues. However, SURFACE+0x78 is past the SURFOBJ (which ends at SURFACE+0x58), so this is in the bitmap data area.

5. **pwndk+0xD8 write (GWLP_USERDATA)**: Writing to pwndk+0xD8 = SURFACE+0xD8. This is deep in the bitmap data area and unlikely to affect bitmap operations.

6. **SetOrClrWF byte writes (pwndk+0x10 to 0x1F)**: These write to SURFACE+0x10 to 0x1F, which overlaps with the BASEOBJECT structure (SURFACE+0x00 to 0x17). Corrupting BASEOBJECT flags could affect object lifecycle but not pvScan0.

---

## New Write Primitives Discovered

### 1. xxxSetWindowData GWLP_HINSTANCE → pwndk+0x20 (controlled 8-byte write)
- **Trigger**: User-mode callback calls `SetWindowLongPtr(hwnd, GWLP_HINSTANCE, controlledValue)`
- **Write**: `*(_QWORD *)(pwndk + 0x20) = controlledValue`
- **SURFACE impact**: Corrupts SURFOBJ.hsurf (SURFACE+0x20)
- **Usefulness**: Low for pvScan0, but could be used in a multi-stage exploit

### 2. xxxSetWindowData GWLP_USERDATA → pwndk+0xD8 (controlled 8-byte write)
- **Trigger**: User-mode callback calls `SetWindowLongPtr(hwnd, GWLP_USERDATA, controlledValue)`
- **Write**: `*(_QWORD *)(pwndk + 0xD8) = controlledValue`
- **SURFACE impact**: Corrupts SURFACE+0xD8 (deep in bitmap data)
- **Usefulness**: Low

### 3. xxxSetWindowData pwndk+0x28 partial overwrite (16-bit write)
- **Trigger**: SetWindowLongPtr with GWLP_WNDPROC on WOW window
- **Write**: `*(_WORD *)(pwndk + 0x28) = wowModuleId`
- **SURFACE impact**: Corrupts SURFACE+0x28 = SURFOBJ.dhpdev (partial 16-bit overwrite)
- **Usefulness**: Medium — could corrupt dhpdev for multi-stage

### 4. HMLockObject controlled increment at SURFACE+0x08
- **Trigger**: SfnDWORD calls HMLockObject(tagWND) which reads [tagWND+0] as handle
- **Write**: `*(_DWORD *)(SURFACE + 0x08) += 1` (lock count increment)
- **Usefulness**: Low — only an increment, not a controlled value write

---

## Final Assessment

### Verdict: NO direct write to pwndk+0x50 (SURFACE+0x50 / pvScan0) exists in the post-UAF code path.

The exhaustive analysis decompiled:
- xxxSendTransformableMessageTimeout (main UAF function)
- xxxSendMessageToClient (fall-through dispatcher)
- SfnDWORD + 10 other Sfn* functions (all write to CLIENTINFO, not pwndk)
- All 7 gServerHandlers (xxxDefWindowProc, xxxDesktopWndProc, xxxSwitchWndProc, xxxMenuWindowProc, xxxSBWndProc, xxxTooltipWndProc, xxxEventWndProc)
- xxxRealDefWindowProc (40+ message handlers, 30+ callees)
- SetOrClrWF (266 callers analyzed, flag formula confirmed)
- SetWindowState/ClearWindowState (ValidateState limits max offset to pwndk+0x1F)
- xxxSetWindowData (SetWindowLongPtr handler — writes to pwndk+0x20/0x78/0x98/0xD8/0xEA/0xF0)
- xxxInterSendMsgEx (NOT in post-UAF path — else branch only)
- 12 deeper callees of xxxRealDefWindowProc
- NtUserMessageCall, xxxSendMessage, xxxDispatchMessage

### Recommended Next Steps

1. **CLIENTINFO redirect approach**: Investigate whether W32THREAD+0x1E0 (CLIENTINFO pointer) can be corrupted through a different vulnerability or through the user-mode callback. If so, redirecting CLIENTINFO to a SURFACE would cause the Sfn* write (pwndk+0xE0 → CLIENTINFO+0x50) to corrupt SURFACE+0x50 = pvScan0.

2. **Alternative object reclaim**: Instead of reclaiming with a SURFACE, find a 0x150-byte session pool object with a useful write at offset 0x50. tagWND itself could be reclaimed with another tagWND whose pwndk points at a SURFACE.

3. **Multi-stage corruption**: Use the controlled writes at pwndk+0x20 (GWLP_HINSTANCE) or pwndk+0x28 (partial overwrite) to corrupt SURFOBJ fields, then trigger a GDI operation that uses the corrupted fields to write to pvScan0 indirectly.

4. **Different UAF target**: Instead of targeting pvScan0 through the post-UAF write path, consider using the UAF READ primitive to leak kernel addresses, then use a separate write primitive (e.g., via a different bug or via GDI operations on a corrupted bitmap) to corrupt pvScan0.

5. **Atomic QUEUExxx swap**: Investigate whether any lock-free/atomic operations during the callback could be exploited to create a write-what-where condition at pwndk+0x50.

6. **Race condition during callback**: During the KeUserModeCallback, user-mode code runs while the kernel holds references to the reclaimed tagWND. A race condition between two threads accessing the same reclaimed tagWND could potentially create an unexpected write to pwndk+0x50.
