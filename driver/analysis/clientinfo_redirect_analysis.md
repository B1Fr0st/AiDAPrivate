# CLIENTINFO Redirect Attack Path & Arbitrary Kernel READ Primitive Analysis

## IDA Instance Info
- **Module**: win32kfull.sys
- **Imagebase**: 0x1C0000000
- **IDB Path**: C:\Windows\System32\win32kfull.sys.i64
- **Hex-Rays**: Ready
- **Analysis Date**: 2026-06-30
- **MD5**: 447fad7487b42b8af879f921abf0bf36

---

## Executive Summary

After exhaustive decompilation and instruction-level analysis of the Sfn* callback dispatchers, SetOrClrWF write paths, and THREADINFO structure layout in win32kfull.sys:

1. **Sfn* Re-read CONFIRMED**: Both SfnDWORD (0x1C006B320) and SfnOUTSTRING (0x1C00D25F0) re-read the CLIENTINFO pointer from THREADINFO+0x1E0 AFTER the KeUserModeCallback, and restore saved values to the re-read location. This enables the CLIENTINFO redirect attack IF the pointer can be corrupted during the callback.

2. **Arbitrary Kernel READ CONFIRMED**: Setting pwndk = target_address - 0xE0 causes `*(QWORD*)(target_address)` to be written to CLIENTINFO+0x50 (TEB+0x850), which is readable from user mode during the callback. This is a fully functional arbitrary kernel READ primitive.

3. **CLIENTINFO Redirect BLOCKED**: No function in win32kfull.sys permanently writes to THREADINFO+0x1E0 (the CLIENTINFO pointer). The only SetOrClrWF path that reaches THREADINFO+0x1E0 (via xxxSBWndProc, flag 0xE04) performs a TEMPORARY bit flip that is undone before the function returns. The CLIENTINFO pointer is set during thread initialization (likely in win32kbase.sys) and never modified in win32kfull.sys.

4. **Missing Piece**: A permanent kernel write primitive to THREADINFO+0x1E0 is required to complete the CLIENTINFO redirect. The arbitrary READ primitive can leak the THREADINFO address, but no write mechanism exists in the current attack surface to corrupt the CLIENTINFO pointer.

---

## Task 1: Verify Sfn* Restore Path — Re-read of W32THREAD+0x1E0

### SfnOUTSTRING (0x1C00D25F0) — Handler for WM_MOUSEACTIVATE (0x21)

**CONFIRMED: Re-reads CLIENTINFO from THREADINFO+0x1E0 after callback.**

#### Before Callback (Save + Modify):
```c
// v117 = *PsGetThreadWin32Thread(KeGetCurrentThread())  — THREADINFO base (cached)
v36 = v117;
v37 = *(_QWORD *)(v117 + 480);           // Read CLIENTINFO from THREADINFO+0x1E0
v130 = *(_OWORD *)(v37 + 64);            // Save CLIENTINFO+0x40..+0x4F (16 bytes)
v131 = *(_QWORD *)(v37 + 80);            // Save CLIENTINFO+0x50 (8 bytes)

// Write to CLIENTINFO:
*(_QWORD *)(v37 + 72) = v16;             // CLIENTINFO+0x48 = pwndk - DesktopHeapDelta
*(_QWORD *)(*(_QWORD *)(v36 + 480) + 64LL) = v38;   // CLIENTINFO+0x40 = HWND (tagWND+0x00)
*(_QWORD *)(*(_QWORD *)(v36 + 480) + 80LL) = v39;   // CLIENTINFO+0x50 = [pwndk+0xE0]
```

#### After Callback (Re-read + Restore):
```c
// v36 is the CACHED THREADINFO base (set before callback)
v52 = *(_QWORD *)(v36 + 480);            // RE-READ CLIENTINFO from THREADINFO+0x1E0
*(_OWORD *)(v52 + 64) = v130;            // Restore CLIENTINFO+0x40..+0x4F (16-byte OWORD)
*(_QWORD *)(v52 + 80) = v131;            // Restore CLIENTINFO+0x50 (8-byte QWORD)
```

#### Exact Restore Instruction Sequence:
```asm
; SfnOUTSTRING restore at 0x1C00D2B7A:
0x1C00D2B7A:  mov     rax, [r13+1E0h]        ; RE-READ CLIENTINFO ptr from THREADINFO+0x1E0
0x1C00D2B81:  movups  xmm0, [rsp+418h+var_318]  ; Load saved OWORD (CLIENTINFO+0x40..+0x4F)
0x1C00D2B89:  movups  xmmword ptr [rax+40h], xmm0  ; Restore 16 bytes at CLIENTINFO+0x40
0x1C00D2B8D:  movsd   xmm1, [rsp+418h+var_308]    ; Load saved QWORD (CLIENTINFO+0x50)
0x1C00D2B96:  movsd   qword ptr [rax+50h], xmm1   ; Restore 8 bytes at CLIENTINFO+0x50
```

**Key**: `r13` = THREADINFO base (cached before callback). `[r13+1E0h]` re-reads the CLIENTINFO pointer. If THREADINFO+0x1E0 was corrupted during the callback, `rax` points to the corrupted location (e.g., SURFACE), and the restore writes saved values there.

### SfnDWORD (0x1C006B320) — Same Pattern Confirmed

#### Exact Restore Instruction Sequence:
```asm
; SfnDWORD restore at 0x1C006B62A:
0x1C006B62A:  mov     rax, [rsi+1E0h]        ; RE-READ CLIENTINFO ptr from THREADINFO+0x1E0
0x1C006B631:  movups  xmm0, [rsp+108h+var_B8]   ; Load saved OWORD
0x1C006B636:  movups  xmmword ptr [rax+40h], xmm0  ; Restore 16 bytes at CLIENTINFO+0x40
0x1C006B63A:  movsd   xmm1, [rsp+108h+var_A8]    ; Load saved QWORD
0x1C006B640:  movsd   qword ptr [rax+50h], xmm1   ; Restore 8 bytes at CLIENTINFO+0x50
```

**Key**: `rsi` = THREADINFO base (cached before callback). Same re-read pattern.

### Findings Summary:
1. **YES** — Both functions read CLIENTINFO from THREADINFO+0x1E0 BEFORE the callback
2. **YES** — Both functions RE-READ CLIENTINFO from THREADINFO+0x1E0 AFTER the callback
3. **Restore content**: 16-byte OWORD at +0x40 (covers +0x40 and +0x48), then 8-byte QWORD at +0x50
4. **Restore uses the RE-READ pointer** (not a cached pointer) — the CLIENTINFO pointer is re-fetched from THREADINFO+0x1E0
5. **Exact sequence**: `mov rax, [reg+1E0h]` → `movups [rax+40h], xmm0` → `movsd [rax+50h], xmm1`

---

## Task 2: Finding W32THREAD / THREADINFO Address from User Mode

### Structure Relationship:
```
PsGetThreadWin32Thread(KeGetCurrentThread())  →  W32THREAD*
*W32THREAD                                     →  THREADINFO* (pti)
THREADINFO + 0x1E0                             →  CLIENTINFO* (normally TEB+0x800)
THREADINFO + 0x1D8                             →  DesktopHeapDelta
```

Verified via W32GetThreadWin32Thread (0x1C008E480):
```c
__int64 W32GetThreadWin32Thread(__int64 a1) {
    if (!KeIsAttachedProcess() || same_session) {
        ThreadWin32Thread = PsGetThreadWin32Thread(a1);
        if (ThreadWin32Thread)
            return *(_QWORD *)ThreadWin32Thread;  // Dereferences to get THREADINFO
    }
    return 0;
}
```

### Methods to Obtain THREADINFO Address:

#### a) TEB Fields:
- **gs:30h** (TEB self): Accessed in 7 locations (UserSetLastError, UserSetLastStatus, xxxHandleCoreMessagingQueueCompletion) — but in kernel mode, gs: points to KPCR, NOT TEB
- **gs:188h** (KTHREAD): 20+ hits — standard kernel-mode current thread access
- **gs:68h, gs:78h**: 0 hits — Win32ThreadInfo TEB fields NOT accessed from kernel mode
- The TEB's Win32ThreadInfo field (if it exists) is NOT used by win32kfull.sys to find THREADINFO

#### b) NtQueryInformationThread:
- ThreadWin32ThreadInfo info class may exist in ntoskrnl but is NOT referenced from win32kfull.sys
- Would need analysis of ntoskrnl.exe (separate IDB)

#### c) SystemHandleInformation (class 0x10):
- Create handle to current thread → query SystemHandleInformation → get kernel ETHREAD address
- ETHREAD contains Win32Thread pointer at a known offset (varies by build)
- Read Win32Thread → dereference → THREADINFO
- This requires a separate leak primitive (e.g., NtQuerySystemInformation)

#### d) PsGetThreadWin32Thread:
- Imported from ntoskrnl, used extensively in win32kfull.sys
- Returns W32THREAD pointer
- Cannot be called from user mode directly

#### e) KTHREAD/W32THREAD offset:
- On Win10 22H2 x64, ETHREAD.Win32Thread is at a fixed offset
- Can be found by analyzing ntoskrnl or using SystemHandleInformation leak
- The arbitrary READ primitive (Task 4) can then read ETHREAD.Win32Thread to get W32THREAD, then *W32THREAD to get THREADINFO

### Recommended Approach:
1. Use NtQuerySystemInformation(SystemHandleInformation) to leak ETHREAD kernel address
2. Use the arbitrary READ primitive to read ETHREAD.Win32Thread → W32THREAD
3. Use the arbitrary READ primitive to read *W32THREAD → THREADINFO
4. Now THREADINFO address is known

---

## Task 3: CLIENTINFO Redirect — How to Corrupt W32THREAD+0x1E0 During Callback

### a) Writes to THREADINFO+0x1E0 in win32kfull.sys:

**EXHAUSTIVE SEARCH RESULT: NO permanent writes to THREADINFO+0x1E0 exist in win32kfull.sys.**

Searched all `mov [reg+1E0h], reg64` instructions (48 89 XX E0 01 00 00) in .text segment:

| Address | Instruction | Function | Target Type |
|---|---|---|---|
| 0x1C001E0C5 | mov [rcx+1E0h], rax | RFONTOBJ::bAllocateCache | Font cache object (NOT THREADINFO) |
| 0x1C009E506 | mov [rax+1E0h], r14 | RFONTOBJ::bInitCache | Font cache object (NOT THREADINFO) |
| 0x1C00D5219 | mov [rbx+1E0h], rcx | GreHintDCWnd | DC/GDI object (NOT THREADINFO) |
| 0x1C01AC0E1 | mov [rdi+1E0h], r15 | GdiDeleteSprite | Sprite object (NOT THREADINFO) |

**None of these write to THREADINFO+0x1E0.** All 4 writes target GDI/font/sprite objects.

### b) NtUserSetThreadDesktop / zzzSetDesktop:

Decompiled zzzSetDesktop (0x1C0065E20):
- Reads THREADINFO+0x1E0 (CLIENTINFO ptr): 5 READ operations
- Does NOT write to THREADINFO+0x1E0
- Writes to THREADINFO+0x1D8 (DesktopHeapDelta): `*((_QWORD *)a1 + 59) = v15`
- Writes to CLIENTINFO+0x20, +0x28, +0x60 (via the existing CLIENTINFO pointer)
- **CONCLUSION**: SetThreadDesktop does NOT modify the CLIENTINFO pointer itself

### c) Thread Initialization:
- xxxDesktopThread (0x1C00D9400) uses W32GetThreadWin32Thread but does NOT write to THREADINFO+0x1E0
- The CLIENTINFO pointer initialization likely occurs in win32kbase.sys (not in this IDB)

### d) Desktop Switching:
- zzzSetDesktop updates DesktopHeapDelta and CLIENTINFO fields, but NOT the CLIENTINFO pointer
- Switching desktops does NOT redirect CLIENTINFO

### e) Direct TEB Manipulation:
- TEB+0x800 IS the CLIENTINFO structure (not a pointer to it)
- The kernel accesses CLIENTINFO via THREADINFO+0x1E0 (kernel pointer to TEB+0x800)
- Modifying TEB+0x800 from user mode does NOT change THREADINFO+0x1E0
- The kernel always uses THREADINFO+0x1E0 to find CLIENTINFO, never TEB+0x800 directly

### f) SetOrClrWF Path (DETAILED):

#### SetOrClrWF (0x1C004DF08) — Write Formula:
```c
v8 = *(_DWORD **)(a2 + 40);          // pwndk = [tagWND+0x28]
v10 = (unsigned __int64)a3 >> 8;     // high byte of flag
v11 = *((_BYTE *)v8 + v10 + 16);     // current byte at pwndk + (flag>>8) + 0x10
if (a1)  // SET mode
    v12 = v11 | (BYTE)a3;            // OR with low byte
else     // CLEAR mode
    v12 = v11 & ~(BYTE)a3;           // AND with complement
*((_BYTE *)v8 + v10 + 16) = v12;     // write byte
```

**Does NOT call ValidateState** — operates directly on the flag value.

#### xxxSBWndProc (0x1C0245BE0) — Handler 4 in gServerHandlers:
- **0 ValidateState calls**
- **2 SetOrClrWF calls** with flag 0xE04 (high byte 0x0E → offset 0x1E)

```asm
0x1C024637A:  mov     r13d, 0E04h          ; flag = 0xE04
0x1C0246380:  mov     rax, [rcx+28h]       ; pwndk = [tagWND+0x28]
0x1C0246384:  movzx   ebx, byte ptr [rax+1Eh]  ; read byte at pwndk+0x1E
0x1C0246388:  and     ebx, 4               ; check bit 2
0x1C024638B:  jnz     short loc_1C02463A0  ; skip if bit 2 already SET
0x1C024638D:  mov     rdx, rcx             ; tagWND
0x1C0246390:  mov     r8d, r13d            ; flag = 0xE04
0x1C0246393:  mov     ecx, esi             ; SET mode (esi=1)
0x1C0246395:  mov     r9d, esi
0x1C0246398:  call    SetOrClrWF           ; SET bit 2 of pwndk+0x1E

; ... DrawSize ...

0x1C02463AE:  test    ebx, ebx             ; was bit 2 originally CLEAR?
0x1C02463B0:  jnz     short loc_1C02463C2  ; skip if was SET
0x1C02463B2:  mov     rdx, [r14]           ; tagWND
0x1C02463B5:  mov     r8d, r13d            ; flag = 0xE04
0x1C02463B8:  mov     r9d, esi
0x1C02463BB:  xor     ecx, ecx             ; CLEAR mode
0x1C02463BD:  call    SetOrClrWF           ; CLEAR bit 2 of pwndk+0x1E (RESTORE)
```

**CRITICAL**: The SetOrClrWF modifications in xxxSBWndProc are TEMPORARY:
1. Bit 2 of pwndk+0x1E is SET before DrawSize
2. Bit 2 is CLEARED after DrawSize (restoring original value)
3. The net effect is NO permanent change to pwndk+0x1E

If pwndk = THREADINFO + 0x1C2:
- pwndk+0x1E = THREADINFO+0x1E0 (byte 0 of CLIENTINFO pointer)
- Bit 2 is temporarily flipped during DrawSize, then restored
- **NO permanent corruption of THREADINFO+0x1E0**

### g) SetOrClrWF Caller Flag Summary:

| Function | Flag | Offset | Permanent? | Reachable from UAF? |
|---|---|---|---|---|
| xxxSBWndProc | 0xE04 | pwndk+0x1E | **TEMPORARY** | YES (gServerHandler[4]) |
| xxxMinMaximizeEx | 0xF01 | pwndk+0x1F | Permanent | NO (not gServerHandler) |
| xxxMinMaximizeEx | 0xD901 | pwndk+0x1D | Permanent | NO |
| xxxRealDefWindowProc | 0x202 | pwndk+0x12 | Permanent | YES (via Sfn* callback) |
| xxxEndPaint | 0x401 | pwndk+0x14 | Permanent | YES (via Sfn* callback) |
| xxxLocalActivateWindow | 0x210 | pwndk+0x12 | Permanent | Indirect |
| SfnPOWERBROADCAST | 0x301 | pwndk+0x13 | Permanent | YES (Sfn* function) |

**Maximum PERMANENT offset via post-UAF reachable SetOrClrWF**: pwndk+0x1D (flag 0xD901 from xxxMinMaximizeEx, but NOT reachable from gServerHandler path).

**Maximum offset via gServerHandler path**: pwndk+0x1E (flag 0xE04 from xxxSBWndProc), but **TEMPORARY only**.

### CONCLUSION for Task 3:
**There is NO mechanism in win32kfull.sys to permanently write to THREADINFO+0x1E0 during the KeUserModeCallback.** The CLIENTINFO redirect attack path is BLOCKED at this point.

---

## Task 4: Arbitrary READ Primitive — Confirmed and Detailed

### Data Flow:
```
1. UAF: tagWND freed + reclaimed with pwndk = target_address - 0xE0
2. xxxSendTransformableMessageTimeout: reads pwndk from [tagWND+0x28]
3. xxxSendMessageToClient: reads pwndk+0x12, pwndk+0x78, dispatches to Sfn*
4. Sfn* function:
   a. Reads CLIENTINFO from THREADINFO+0x1E0 → CLIENTINFO (normally TEB+0x800)
   b. Saves CLIENTINFO+0x50 → v56 (saved for restore)
   c. Reads [pwndk+0xE0] = [target_address] 
   d. Writes [target_address] to CLIENTINFO+0x50 = TEB+0x850
   e. Calls KeUserModeCallback → user mode executes
5. During callback: user-mode code reads TEB+0x850 → gets [target_address]
6. After callback: Sfn* restores v56 to CLIENTINFO+0x50 (overwrites [target_address] value)
```

### a) SfnOUTSTRING data flow CONFIRMED:
```c
v39 = *(_QWORD *)(a1[5] + 224);   // a1[5] = pwndk, 224 = 0xE0
                                   // v39 = *(QWORD*)(pwndk + 0xE0) = *(QWORD*)(target)
*(_QWORD *)(*(_QWORD *)(v36 + 480) + 80LL) = v39;  // CLIENTINFO+0x50 = v39
```

### b) TEB+0x850 accessibility:
- TEB is at `gs:[0x30]` in user mode (x64)
- CLIENTINFO is at TEB+0x800
- CLIENTINFO+0x50 = TEB+0x800+0x50 = TEB+0x850
- TEB is a user-mode structure, fully readable/writable from user mode
- **CONFIRMED: TEB+0x850 is readable from user mode**

### c) Timing:
- Write to CLIENTINFO+0x50 happens BEFORE KeUserModeCallback
- User-mode code runs AFTER the write
- During the callback, TEB+0x850 contains [target_address]
- **CONFIRMED: Correct timing for read**

### d) Value preservation:
- After the callback, Sfn* restores the original CLIENTINFO+0x50 value
- The read value is ONLY available DURING the callback
- **CONFIRMED: Must read during callback, value is ephemeral**

### e) DesktopHeapDelta:
- Located at THREADINFO+0x1D8 (offset 472 decimal)
- Used in: `v15 = pwndk - *(QWORD*)(THREADINFO + 0x1D8)` → written to CLIENTINFO+0x48
- Does NOT affect the +0x50 write
- The +0x50 write uses [pwndk+0xE0] directly, no delta subtraction
- **CONFIRMED: DesktopHeapDelta does not affect the READ primitive**

### f) Multi-read:
- Each UAF trigger with pwndk = target - 0xE0 reads [target] into TEB+0x850
- Multiple triggers with different pwndk values read different addresses
- **CONFIRMED: Multiple reads are possible**

---

## Task 5: Pre-writing to TEB+0x850

### a) TEB writability:
- TEB is a user-mode structure at `gs:[0x30]` (x64)
- All TEB fields are writable from user mode (no kernel protection)
- TEB+0x850 (CLIENTINFO+0x50) is writable
- **CONFIRMED: Writable from user mode**

### b) Timing for CLIENTINFO redirect:
1. Pre-write controlled value to TEB+0x850 BEFORE triggering the UAF
2. Sfn* function saves TEB+0x850 → v56 = our controlled value
3. Sfn* writes [pwndk+0xE0] to CLIENTINFO+0x50 (overwrites our value temporarily)
4. During callback: THREADINFO+0x1E0 is corrupted to point at SURFACE
5. After callback: Sfn* re-reads THREADINFO+0x1E0 → gets SURFACE address
6. Sfn* restores v56 to SURFACE+0x50 = our controlled value → pvScan0 CORRUPTED

**NOTE**: Step 4 requires the CLIENTINFO redirect, which is blocked (see Task 3).

### c) What value to write:
- Write the target kernel address for pvScan0 to point at
- After redirect: SURFACE+0x50 = our value → GetBitmapBits/SetBitmapBits reads/writes at that address
- This gives arbitrary kernel R/W via the bitmap

### d) TEB offset calculation:
```
TEB base = gs:[0x30]
CLIENTINFO = TEB + 0x800
CLIENTINFO+0x50 = TEB + 0x800 + 0x50 = TEB + 0x850
```
**VERIFIED: 0x800 + 0x50 = 0x850**

---

## Task 6: Search for ANY Write to [pwndk+0x50] in win32kfull.sys

### Methodology:
Searched all `mov [reg+50h], reg64` instructions (48/4C 89 40-47 50) in .text segment.

### Results: 92 writes to [reg+0x50] found

#### Sfn* Functions (write to CLIENTINFO+0x50, NOT pwndk+0x50):
| Function | Address | Target |
|---|---|---|
| SfnDWORD | 0x1C006B4B2 | CLIENTINFO+0x50 (rax = [THREADINFO+0x1E0]) |
| SfnOUTSTRING | 0x1C00D2A03 | CLIENTINFO+0x50 |
| SfnEMPTY | 0x1C004FA50 | CLIENTINFO+0x50 |
| SfnINLPHELPINFOSTRUCT | 0x1C022AFFC | callback buffer+0x50 |
| SfnINLPHLPSTRUCT | 0x1C022B468 | callback buffer+0x50 |
| SfnINPGESTURENOTIFYSTRUCT | 0x1C022DC36 | callback buffer+0x50 |
| SfnPOPTINLPUINT | 0x1C022F40D | callback buffer+0x50 |
| SfnTOUCHHITTESTING | 0x1C023055A | callback buffer+0x50 |

#### GDI/Font Functions (write to GDI object+0x50, NOT pwndk+0x50):
| Function | Address | Target |
|---|---|---|
| LinkWindow | 0x1C006FD0A | window object+0x50 |
| UnlinkWindow | 0x1C007E9E8 | window object+0x50 |
| GreRealizePalette | 0x1C011BCA1 | DC object+0x50 |
| SURFFAKEOBJ constructor | 0x1C016AA9B | surface object+0x50 |
| various DIB functions | multiple | DIB surface+0x50 |

#### Stack-relative writes (rbp+0x50):
- Multiple hits in GreSetBitmapBits, GreGetGlyphOutlineInternal, etc.
- These are stack variable accesses, not pwndk writes

### CONCLUSION:
**NO writes to [pwndk+0x50] exist in any reachable path.** All Sfn* writes go to CLIENTINFO+0x50, which is at [THREADINFO+0x1E0]+0x50, not at pwndk+0x50. All other writes target GDI objects or stack variables.

---

## Task 7: TEB Win32ThreadInfo Field Investigation

### gs: Access Pattern Search:
Searched for `65 48 8B` (gs: prefix + REX.W + MOV) in .text segment: 200+ hits found.

### Specific TEB Offset Accesses:

| gs: Offset | Hits | Meaning | In Kernel Mode |
|---|---|---|---|
| gs:30h | 7 | KPCR.Self (NOT TEB self in kernel mode) | KPCR field |
| gs:40h | 0 | N/A | N/A |
| gs:68h | 0 | Win32ThreadInfo (TEB) | NOT accessed |
| gs:78h | 0 | Win32ThreadInfo alt offset | NOT accessed |
| gs:188h | 20+ | KPCR.Prcb.CurrentThread (KTHREAD*) | Standard kernel access |

### Findings:
- win32kfull.sys (kernel mode) uses `gs:188h` to get KTHREAD, then `PsGetThreadWin32Thread()` to get W32THREAD
- **gs:68h and gs:78h (TEB Win32ThreadInfo) are NOT accessed from kernel mode**
- The kernel does NOT read the TEB's Win32ThreadInfo field to find W32THREAD
- The W32THREAD/THREADINFO address is NOT available in the TEB from user mode via standard gs: access

### Implications:
- Cannot leak W32THREAD address from TEB fields
- Must use NtQuerySystemInformation(SystemHandleInformation) or similar to leak kernel object addresses
- The arbitrary READ primitive can then be used to traverse ETHREAD → Win32Thread → THREADINFO

---

## Task 8: Sfn* Callback Data Structure

### SfnDWORD Callback Data (48 bytes):
```
Offset  Field              Source
0x00    pwndk - Delta      v15 = a1[5] - THREADINFO+0x1D8
0x08    message            v58 = a2 (message number)
0x0C    flags              v59 = 0
0x10    wParam             v60 = a3
0x18    lParam             v61 = a4
0x20    pwndk+0x78 value   v62 = a5 = *(QWORD*)(pwndk+0x78)
0x28    extra              v63 = a6
```
Called as: `KeUserModeCallback(2, &v57, 48, &v54, &v67)`

### SfnOUTSTRING Callback Data:
More complex — includes a heap-allocated buffer with string data. Key fields:
```
Buffer+0x00: size (DWORD)
Buffer+0x08: buffer ptr (QWORD)
Buffer+0x10: buffer size (QWORD)
Buffer+0x18: (QWORD)
Buffer+0x20: pwndk - Delta (QWORD) [offset +0x28 from struct start]
Buffer+0x24: message (DWORD)
Buffer+0x28: (QWORD)
Buffer+0x30: wParam (QWORD) [as a5]
Buffer+0x38: lParam (QWORD) [as a6]
Buffer+0x40: pwndk+0x78 value (QWORD)
Buffer+0x48: string data size (QWORD)
Buffer+0x50: string data pointer (QWORD)
```
Called as: `KeUserModeCallback(35, v21, (unsigned int)*v21, &v120, &v114)`

### Does callback data include kernel pointers?
- `pwndk - DesktopHeapDelta`: This is a USER-VISIBLE address (kernel desktop heap address minus delta = user desktop heap address). Safe.
- `pwndk+0x78`: This is a raw read from pwndk+0x78. In normal operation, this is a handler index (small integer). In our UAF scenario, we control this value.
- **No direct kernel address leak** in normal operation. In UAF scenario, pwndk is controlled, so pwndk+0x78 can be anything.

---

## Task 9: W32THREAD / THREADINFO Structure Layout

### Key Offsets (verified via decompilation):

| Offset (hex) | Offset (dec) | Field | Access Type |
|---|---|---|---|
| +0x00 | +0 | pti (THREADINFO*) | Read: `*PsGetThreadWin32Thread()` |
| +0x10 | +16 | ThreadLock linked list | Read/Write |
| +0x1A0 | +416 | Callback chain head | Read/Write |
| +0x1D0 | +464 | Queue/desktop pointer | Read |
| +0x1D8 | +472 | DesktopHeapDelta | Read (in Sfn* for pwndk-delta) |
| +0x1E0 | +480 | CLIENTINFO pointer | Read (Sfn* save/modify/restore) |
| +0x188 | +392 | ObjLock (tagObjLock) | Lock/Unlock |
| +0x5C8 | +1480 | InCallback flag (byte) | Read/Write (Sfn* save/restore) |

### CLIENTINFO+0x1E0 is NEVER written in win32kfull.sys:
- 80 READ accesses found across all Sfn* functions, hook dispatchers, message functions
- 0 WRITE accesses to THREADINFO+0x1E0 (all 4 write hits are to GDI/font/sprite objects)
- The CLIENTINFO pointer is set during thread initialization, likely in win32kbase.sys
- Once set, it is NEVER modified by any function in win32kfull.sys

---

## Task 10: Multi-Trigger UAF Feasibility

### Requirements per UAF trigger:
1. Create a child window
2. Set WH_CALLWNDPROC hook
3. Trigger SendInput → WM_MOUSEACTIVATE
4. During hook callback: destroy child window
5. Reclaim freed tagWND (0x150 bytes) with controlled data
6. Message processing continues with reclaimed tagWND

### Reusability:
- Each trigger uses a NEW child window (previous one is destroyed)
- The same top-level window can be reused for multiple child windows
- No inherent rate limit, but rapid triggers may cause synchronization issues

### For CLIENTINFO redirect (if write primitive existed):
- 8 bytes to corrupt (THREADINFO+0x1E0 through +0x1E7)
- Each SetOrClrWF call writes 1 byte
- Need clear+set per byte = 16 triggers max, 8 triggers min
- Plus 1+ triggers for the final Sfn* callback with redirect
- Total: ~10-20 UAF triggers

### For arbitrary READ:
- 1 trigger per read (pwndk = target - 0xE0, read TEB+0x850 during callback)
- Multiple reads for multiple addresses
- Total: 1 trigger per kernel address to read

---

## Task 11: SetOrClrWF Bit Analysis for THREADINFO+0x1E0 Corruption

### Flag-to-Offset Mapping:
```
offset = (flag >> 8) + 0x10
```

For pwndk = THREADINFO + 0x1C2 (fixed):
| Flag High Byte | Offset from pwndk | THREADINFO Target |
|---|---|---|
| 0x0E | +0x1E | +0x1E0 (byte 0) |
| 0x0F | +0x1F | +0x1E1 (byte 1) |
| 0x10 | +0x20 | +0x1E2 (byte 2) — EXCEEDS ValidateState max (0x0F) |

### ValidateState Limits (0x1C0131938):
```c
BOOL8 ValidateState(__int16 a1) {
    return HIBYTE(a1) <= 0xF && ((BYTE)a1 & mask[HIBYTE(a1)]) == (BYTE)a1;
}
```

| High Byte | Allowed Low Bytes |
|---|---|
| 0x0E | 0x01, 0x08, 0x09, 0x10, 0x20, 0x80, 0x88, 0x89, 0x98, 0x99, 0xA0, 0xB0, 0xB8, 0xB9 |
| 0x0F | 0x02 only |

**Maximum reachable offset via ValidateState**: pwndk + 0x0F + 0x10 = pwndk+0x1F

### xxxSBWndProc BYPASSES ValidateState:
- xxxSBWndProc calls SetOrClrWF directly (0 ValidateState calls confirmed)
- Uses flag 0xE04 (low byte 0x04, which is NOT in ValidateState's allowed list for 0x0E)
- This means ANY low byte could theoretically be used through xxxSBWndProc

### BUT: xxxSBWndProc modifications are TEMPORARY:
- Bit 2 is SET before DrawSize, then CLEARED after
- Net effect: NO permanent change to pwndk+0x1E
- **Cannot be used for permanent THREADINFO+0x1E0 corruption**

### SetOrClrWF callers with high byte 0x0E:
| Caller | Flag | Permanent? | Reachable from UAF? |
|---|---|---|---|
| xxxSBWndProc | 0xE04 | **NO (temporary)** | YES (gServerHandler[4]) |

**No other callers with high byte 0x0E found in the post-UAF reachable path.**

---

## Task 12: SURFACE Reclaim with Size Matching

### Size Analysis:
```
tagWND = 0x150 bytes (336 bytes)
SURFACE = 0x2B8 bytes (696 bytes)
SURFACE pool slot = 0x2C0 bytes (704 bytes)
Size difference = 0x170 bytes (368 bytes)
```

### Can SURFACE reclaim tagWND? **NO** — size mismatch of 0x170 bytes.

### Alternative GDI objects at 0x150 bytes:
- Would need to search HMAllocObject calls with size 0x150
- Other USER objects of this size may exist but would need specific analysis
- Session pool allocations of 0x150 bytes with controlled data at offset 0x50 could work

### Non-GDI reclaim:
- Session pool spray with 0x150-byte allocations
- Data at offset 0x28 (pwndk) and offset 0x00 (HWND) must be controlled
- Data at offset 0x12 (flags byte) and offset 0x78 (handler index) must be controlled
- This is the standard approach for tagWND reclaim in UAF exploits

---

## Task 13: CLIENTINFO+0x48 (pvBits) Corruption Analysis

### When CLIENTINFO is redirected to a SURFACE:

#### Temporary writes (during Sfn* execution, before callback):
| CLIENTINFO Offset | SURFACE Offset | SURFOBJ Field | Value Written |
|---|---|---|---|
| +0x40 | +0x40 | sizlBitmap.cx | HWND (from tagWND+0x00) |
| +0x48 | +0x48 | pvBits | pwndk - DesktopHeapDelta |
| +0x50 | +0x50 | pvScan0 | [pwndk+0xE0] |

#### Restore (after callback):
| CLIENTINFO Offset | SURFACE Offset | SURFOBJ Field | Value Restored |
|---|---|---|---|
| +0x40..+0x4F | +0x40..+0x4F | sizlBitmap + pvBits | Saved OWORD (original values) |
| +0x50 | +0x50 | pvScan0 | Saved QWORD (v56 = pre-written TEB+0x850 value) |

### Analysis:
a) **Temporary corruption of sizlBitmap and pvBits**: Only exists between the CLIENTINFO write and the restore. If no GDI operations access the bitmap during this window, no impact. The corruption is during kernel-mode execution (between Sfn* writes and callback return), so no user-mode GDI calls can interfere.

b) **OWORD restore of +0x40/+0x48**: Uses `movups [rax+40h], xmm0` which restores 16 bytes. This properly restores both sizlBitmap (8 bytes at +0x40) and pvBits (8 bytes at +0x48) to their original SURFACE values.

c) **QWORD restore of +0x50**: Uses `movsd [rax+50h], xmm1` which restores 8 bytes. The restored value is v56, which was saved BEFORE the callback from the ORIGINAL CLIENTINFO+0x50 (TEB+0x850). If we pre-wrote a controlled value to TEB+0x850, v56 = our controlled value.

d) **After Sfn* returns**: SURFACE has original sizlBitmap, original pvBits, and OUR CONTROLLED pvScan0.

e) **CONFIRMED**: The save/restore sequence is correct. The only persistent corruption is pvScan0 = our pre-written value.

**BUT**: This requires the CLIENTINFO redirect (THREADINFO+0x1E0 corruption), which is BLOCKED (see Task 3).

---

## Confirmed Data Flow Diagram

### Arbitrary READ Primitive (CONFIRMED):
```
User Mode:
  1. Pre-write 0 to TEB+0x850 (optional, for cleanliness)
  2. Trigger UAF: create child, hook, SendInput, destroy child during hook
  3. Reclaim tagWND with pwndk = target_addr - 0xE0

Kernel Mode:
  4. xxxSendTransformableMessageTimeout(tagWND, WM_MOUSEACTIVATE, ...)
  5. Reads pwndk = [tagWND+0x28] = target_addr - 0xE0
  6. pwndk+0x12 bit 2 CLEAR → fall-through path
  7. xxxSendMessageToClient(tagWND, ...)
  8. Dispatches to SfnOUTSTRING (WM_MOUSEACTIVATE = 0x21)
  9. SfnOUTSTRING:
     a. CLIENTINFO = [THREADINFO+0x1E0]  → TEB+0x800
     b. Save v56 = [CLIENTINFO+0x50] = [TEB+0x850]
     c. Read [pwndk+0xE0] = [target_addr]
     d. Write [target_addr] to [CLIENTINFO+0x50] = [TEB+0x850]
     e. KeUserModeCallback(35, ...) → user mode

User Mode (during callback):
  10. Read TEB+0x850 → value = [target_addr]  ← ARBITRARY KERNEL READ

Kernel Mode (after callback):
  11. SfnOUTSTRING re-reads CLIENTINFO = [THREADINFO+0x1E0]  → TEB+0x800
  12. Restores v56 to [CLIENTINFO+0x50] = [TEB+0x850]
  13. Value at TEB+0x850 is now restored to pre-callback value
```

### CLIENTINFO Redirect Attack (BLOCKED):
```
User Mode:
  1. Pre-write SURFACE_addr to TEB+0x850
  2. Trigger UAF with pwndk for Sfn* mode (bit 2 CLEAR)

Kernel Mode:
  3. Sfn* saves v56 = [TEB+0x850] = SURFACE_addr
  4. Sfn* writes to CLIENTINFO (TEB+0x800)
  5. KeUserModeCallback → user mode

User Mode (during callback):
  6. ??? NEED TO CORRUPT THREADINFO+0x1E0 → SURFACE ???
     BLOCKED: No mechanism exists in win32kfull.sys

Kernel Mode (after callback):
  7. Sfn* re-reads [THREADINFO+0x1E0] → still TEB+0x800 (NOT redirected)
  8. Restores v56 to [TEB+0x850] (writes SURFACE_addr to TEB, not SURFACE)
  9. No pvScan0 corruption occurs
```

---

## Feasibility Assessment

| Approach | Viable? | Blocker |
|---|---|---|
| Arbitrary kernel READ | **YES** | None — fully functional |
| CLIENTINFO redirect via SetOrClrWF | **NO** | SetOrClrWF in xxxSBWndProc is temporary (SET then CLEAR) |
| CLIENTINFO redirect via zzzSetDesktop | **NO** | zzzSetDesktop does not write THREADINFO+0x1E0 |
| CLIENTINFO redirect via direct TEB write | **NO** | Kernel uses THREADINFO+0x1E0, not TEB directly |
| CLIENTINFO redirect via NtUserSetThreadDesktop | **NO** | Calls zzzSetDesktop which doesn't modify CLIENTINFO ptr |
| pvScan0 corruption via direct pwndk+0x50 write | **NO** | No writes to [pwndk+0x50] in any reachable path |
| SURFACE reclaim of tagWND | **NO** | Size mismatch (0x150 vs 0x2C0) |

---

## Blockers and Potential Bypasses

### Blocker 1: No permanent write to THREADINFO+0x1E0
**Bypass options:**
1. **Analyze win32kbase.sys**: The CLIENTINFO pointer is initialized during thread creation. If win32kbase.sys has a function that modifies THREADINFO+0x1E0, it might be callable from user mode during the callback.
2. **Race condition**: If there's a window between xxxSBWndProc's SET and CLEAR where the bit is flipped, and another Sfn* call happens in between (nested), the nested call might see the corrupted CLIENTINFO. This is extremely timing-sensitive.
3. **Alternative write primitive**: Use the arbitrary READ to leak enough information to construct a different write primitive (e.g., via HalDispatchTable, pipe attributes, or other known kernel exploitation techniques).
4. **Different vulnerability**: The UAF might have other write paths not yet explored.

### Blocker 2: SURFACE cannot reclaim tagWND (size mismatch)
**Bypass options:**
1. **Different GDI object**: Find a GDI object that is exactly 0x150 bytes with a useful field at offset 0x50
2. **Session pool spray**: Use non-GDI session pool allocations of 0x150 bytes with controlled data
3. **Different reclaim target**: Instead of SURFACE, target a different kernel structure that has a useful field at +0x50

### Blocker 3: ValidateState limits flag high byte to 0x0F
**Bypass options:**
1. **xxxSBWndProc bypasses ValidateState** (confirmed: 0 ValidateState calls)
2. But xxxSBWndProc only uses flag 0xE04 (bit 2), and modifications are temporary
3. Need a different caller that bypasses ValidateState with higher flags AND is reachable from the UAF path

---

## Final Assessment

### Is the CLIENTINFO redirect path viable?
**NO — the CLIENTINFO redirect path is NOT viable with the current attack surface in win32kfull.sys.**

The fundamental missing piece is a **permanent kernel write primitive to THREADINFO+0x1E0**. While the Sfn* re-read pattern is confirmed and would enable the redirect if the pointer were corrupted, no mechanism exists to corrupt it:

1. No function in win32kfull.sys writes to THREADINFO+0x1E0
2. SetOrClrWF via xxxSBWndProc reaches THREADINFO+0x1E0 but only temporarily
3. SetOrClrWF via other callers either doesn't reach offset 0x1E or isn't reachable from the UAF path
4. zzzSetDesktop modifies CLIENTINFO fields but not the pointer itself

### What IS viable?
**The arbitrary kernel READ primitive is fully functional.** Setting pwndk = target - 0xE0 causes `*(target)` to be written to TEB+0x850, readable from user mode during the callback. This provides:
- Kernel address space reads
- Structure layout discovery
- Token/EPROCESS address leakage
- SURFACE/bitmap kernel address discovery
- Facilitation of other exploitation techniques

---

## Recommended Next Steps

1. **Analyze win32kbase.sys**: Search for functions that write to THREADINFO+0x1E0 (CLIENTINFO pointer initialization/modification). If found, check if they're callable from user mode during the callback.

2. **Explore the arbitrary READ for alternative exploitation**:
   - Leak ETHREAD → Win32Thread → THREADINFO address
   - Leak EPROCESS → Token address for token stealing
   - Leak HalDispatchTable for control flow hijack
   - Leak SURFACE/bitmap addresses for bitmap-based exploitation

3. **Investigate nested callback races**: During the Sfn* callback, trigger a nested message that goes through xxxSBWndProc. If the timing is right, the outer Sfn* might re-read the CLIENTINFO pointer during the brief window where xxxSBWndProc has flipped bit 2. This is extremely timing-sensitive and may not be reliable.

4. **Search for other win32kfull.sys write primitives**: The arbitrary READ can leak kernel addresses. Look for other kernel structures or APIs that write to controlled offsets when given leaked addresses.

5. **Consider alternative UAF targets**: If there are other UAF vulnerabilities in win32kfull.sys with different post-UAF paths, they might provide direct write primitives.

6. **Investigate HMValidateHandle for tagWND leaks**: Use the arbitrary READ to read the handle table and find tagWND kernel addresses, enabling more targeted attacks.
