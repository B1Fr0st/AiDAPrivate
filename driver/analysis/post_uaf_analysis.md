# Post-UAF Code Path Analysis — xxxSendTransformableMessageTimeout

## UAF Context
- **UAF read location**: 0x1C0059B30
- **Instruction**: `mov rax, [rbx+28h]` — reads pwndk (WNDK pointer) from freed tagWND
- **rbx** = tagWND* (freed and potentially reclaimed with controlled data)
- **rax** = pwndk (WNDK pointer — controlled if reclaimed, set to SURFACE address)
- **IDA imagebase**: 0x1C0000000

---

## Task 1: Full Decompilation of xxxSendTransformableMessageTimeout (0x1C00598F0)

### Complete Pseudocode (annotated)

```c
__int64 xxxSendTransformableMessageTimeout(
    unsigned __int64 a1,    // tagWND* (rbx)
    unsigned int a2,        // message (esi)
    unsigned __int64 a3,    // wParam
    __int64 a4,             // lParam
    unsigned int a5,        // flags
    unsigned int a6,        // timeout
    __int64 *LowLimit,      // result output
    int a8, int a9)
{
    // -- Handle validation --
    // Validates a1 (tagWND) against gpKernelHandleTable
    // BugChecks if invalid
    
    // -- DDE message handling (msg 992-1000) --
    // Calls xxxDDETrackSendHook, ValidateDDEConvPair
    
    // -- MiP (Message Integrity Protection) checks --
    // For certain messages, checks IsMiPEnabledForWindow
    
    // -- Get current thread info --
    CurrentThread = KeGetCurrentThread();
    v18 = PsGetThreadWin32Thread(CurrentThread);  // tagTHREADINFO
    
    // -- Check if window belongs to current thread --
    if (v18 == *(QWORD*)(a1 + 16))  // [tagWND+0x10] = pti
    {
        // -- HOOK CALLBACK SECTION (triggers UAF) --
        if (a1 != *(QWORD*)(v18 + 1464)  // not active window
            && ...conditions...
            && thread_flags & 0x20)
        {
            // Build CWPSTRUCT
            v43 = *(QWORD*)a1;     // hwnd
            v42 = v11;             // message
            v41[1] = v52;          // wParam
            v41[0] = v53;          // lParam
            
            // Call WH_CALLWNDPROC hook or xxxPointerCallHook
            // THIS IS WHERE THE UAF IS TRIGGERED:
            // During the hook callback, user mode calls DestroyWindow(child)
            // → xxxDestroyWindow → xxxFreeWindow → HMFreeObject
            // → tagWND is ACTUALLY FREED
            // → Hook callback can spray objects to reclaim the freed slot
            // → Hook callback returns
            // → Execution falls through to 0x1C0059B30
            xxxCallHook2(Valid, 0, 0, v41, nullptr, 0);
        }
        
        // ============================================================
        // UAF READ at 0x1C0059B30
        // ============================================================
        // rbx = tagWND (FREED + RECLAIMED with controlled data)
        // [rbx+0x28] = our controlled pwndk value → SURFACE address
        
        if ((*(BYTE*)(*(QWORD*)(a1 + 40) + 18) & 4) == 0)  // [pwndk+0x12] & 4
        // i.e., WNDK+0x12 bit 2 is CLEAR
        {
            // -- FALL-THROUGH PATH: xxxSendMessageToClient --
            v22 = v53;  // lParam
            v23 = v52;  // wParam
            
            // Calls xxxSendMessageToClient with the freed/reclaimed tagWND
            // This dispatches the message to the user-mode window procedure
            xxxSendMessageToClient((tagWND*)a1, v11, v52, v53, nullptr, 0, &v36);
            
            // After xxxSendMessageToClient returns:
            if (a1 != *(QWORD*)(v18 + 1464)  // check active window
                && thread_flags & 0x2000)
            {
                // Another hook callback (WH_CALLWNDPROCRET)
                v49 = *(QWORD*)a1;  // READ [tagWND+0] = hwnd (UAF read #2)
                xxxCallHook(0, 0, v47, 12);
            }
            else
            {
                v24 = v36;
            }
            
            // Free touch/gesture info if needed
            if (v11 == 576) FreeTouchInputInfo(v22, 1);
            else if (v11 == 281) FreeGestureInfo(v22, 1);
            
            if (!v14) return v24;
            *v14 = v24;  // write result to LowLimit
            return 1;
        }
        else
        // WNDK+0x12 bit 2 is SET
        {
            // -- BRANCH PATH: gServerHandlers (at 0x1C0059CE9) --
            // Stack limit check
            IoGetStackLimits(&LowLimit, &HighLimit);
            if (HighLimit - LowLimit < 0x2000) return 0;
            
            // Read server handler index from [pwndk+0x78]
            v28 = *(QWORD*)(*(QWORD*)(a1 + 40) + 120);  // [pwndk+0x78]
            if (v28 >= 7) return 0;
            
            // Call gServerHandlers[v28](tagWND, msg, wParam, lParam)
            result = gServerHandlers[v28](a1, v11, v52, v53);
            v24 = result;
            if (v14) { *v14 = v24; return 1; }
        }
    }
    else
    {
        // -- CROSS-THREAD PATH: xxxInterSendMsgEx or xxxDefWindowProc --
        // Window belongs to different thread
        if (HMPheFromObject(a1) & 1)
            return xxxDefWindowProc((tagWND*)a1);
        return xxxInterSendMsgEx(a1, v11, v52, v53, 1, ...);
    }
}
```

### Key Observations:
1. The UAF read at 0x1C0059B30 reads `[rbx+0x28]` = pwndk from the freed tagWND
2. The code then reads `[pwndk+0x12]` to check WNDK flags (bit 2)
3. **Fall-through path** (bit 2 clear): calls `xxxSendMessageToClient` → `SfnDWORD` → `KeUserModeCallback` (user-mode window procedure)
4. **Branch path** (bit 2 set): calls `gServerHandlers[[pwndk+0x78]]` (kernel-side handler)
5. **We control pwndk** (via reclaim), so we control which path is taken and what value is at `[pwndk+0x78]`

---

## Task 2: Instruction-by-Instruction Trace from 0x1C0059B30

### Block at 0x1C0059B30 (UAF Read + Flag Check)

| Address | Instruction | Registers | Memory Access | R/W | Notes |
|---------|------------|-----------|--------------|-----|-------|
| 0x1C0059B30 | `mov rax, [rbx+28h]` | rax←[rbx+0x28] | [tagWND+0x28] | **READ** | **UAF READ** — reads pwndk from freed/reclaimed tagWND |
| 0x1C0059B34 | `test byte ptr [rax+12h], 4` | flags←[rax+0x12]&4 | [pwndk+0x12] | **READ** | Checks WNDK flag bit 2 |
| 0x1C0059B38 | `jnz loc_1C0059CE9` | — | — | — | Branch if bit 2 SET → branch path |

### Fall-Through Path (bit 2 CLEAR) — 0x1C0059B3E to return

| Address | Instruction | Registers | Memory Access | R/W | Notes |
|---------|------------|-----------|--------------|-----|-------|
| 0x1C0059B3E | `lea rax, [rsp+var_F8]` | rax←rsp+offset | stack | — | Setup output ptr |
| 0x1C0059B43 | `mov [rsp+var_118], rax` | — | stack | WRITE | Store output ptr |
| 0x1C0059B48 | `mov [rsp+var_120], r14d` | — | stack | WRITE | Store 0 |
| 0x1C0059B4D | `mov [rsp+BugCheckParameter4], r14` | — | stack | WRITE | Store nullptr |
| 0x1C0059B52 | `mov r12, [rsp+arg_18]` | r12←lParam | stack | READ | Load lParam |
| 0x1C0059B5A | `mov r9, r12` | r9←r12 | — | — | 6th param = lParam |
| 0x1C0059B5D | `mov rdi, [rsp+arg_10]` | rdi←wParam | stack | READ | Load wParam |
| 0x1C0059B65 | `mov r8, rdi` | r8←rdi | — | — | 5th param = wParam |
| 0x1C0059B68 | `mov edx, esi` | edx←esi | — | — | 4th param = msg |
| 0x1C0059B6A | `mov rcx, rbx` | rcx←rbx | — | — | 1st param = tagWND |
| 0x1C0059B6D | `call xxxSendMessageToClient` | — | — | CALL | **Dispatches to user-mode window proc** |
| 0x1C0059B72 | `cmp rbx, [r15+5B8h]` | flags←rbx vs [r15+0x5B8] | [thread+0x5B8] | READ | Check if active window |
| 0x1C0059B79 | `jz loc_1C0059B99` | — | — | — | Skip hook if active |
| 0x1C0059B7B | `mov rax, [r15+1D0h]` | rax←[r15+0x1D0] | [thread+0x1D0] | READ | Get desktop |
| 0x1C0059B82 | `mov rcx, [rax]` | rcx←[rax] | [desktop] | READ | Get desktop info |
| 0x1C0059B85 | `mov edx, [rcx+10h]` | edx←[rcx+0x10] | [desktopinfo+0x10] | READ | Get flags |
| 0x1C0059B88 | `or edx, [r15+2A8h]` | edx←|[thread+0x2A8] | [thread+0x2A8] | READ | OR thread flags |
| 0x1C0059B8F | `bt edx, 0Dh` | — | — | — | Test bit 13 (0x2000) |
| 0x1C0059B93 | `jb loc_1C0189E45` | — | — | — | If set, call WH_CALLWNDPROCRET hook |
| 0x1C0059B99 | `mov rbx, [rsp+var_F8]` | rbx←result | stack | READ | Get xxxSendMessageToClient result |
| 0x1C0059B9E | `cmp esi, 240h` | — | — | — | Check if msg == WM_TOUCH (576) |
| 0x1C0059BA4 | `jz loc_1C0189E99` | — | — | — | If yes, FreeTouchInputInfo |
| 0x1C0059BAA | `cmp esi, 119h` | — | — | — | Check if msg == WM_GESTURE (281) |
| 0x1C0059BB0 | `jz loc_1C0189EAC` | — | — | — | If yes, FreeGestureInfo |
| 0x1C0059BB6 | `test r13, r13` | — | — | — | Check LowLimit param |
| 0x1C0059BB9 | `jnz loc_1C0059D6E` | — | — | — | If set, write result to *LowLimit |
| 0x1C0059BBF | `mov rax, rbx` | rax←rbx (result) | — | — | Return value |
| 0x1C0059BC2 | `add rsp, 110h; pop r15-rbx; retn` | — | — | RET | **Function return** |

### Branch Path (bit 2 SET) — 0x1C0059CE9 to return

| Address | Instruction | Registers | Memory Access | R/W | Notes |
|---------|------------|-----------|--------------|-----|-------|
| 0x1C0059CE9 | `mov [rsp+HighLimit], r14` | — | stack | WRITE | Clear HighLimit = 0 |
| 0x1C0059CF1 | `mov [rsp+LowLimit], r14` | — | stack | WRITE | Clear LowLimit = 0 |
| 0x1C0059CF9 | `lea rdx, [rsp+HighLimit]` | rdx←&HighLimit | — | — | 2nd param for IoGetStackLimits |
| 0x1C0059D01 | `lea rcx, [rsp+LowLimit]` | rcx←&LowLimit | — | — | 1st param for IoGetStackLimits |
| 0x1C0059D09 | `call IoGetStackLimits` | — | — | CALL | Get stack limits |
| 0x1C0059D15 | `lea rax, [rsp+HighLimit]` | rax←&HighLimit | — | — | |
| 0x1C0059D1D | `sub rax, [rsp+LowLimit]` | rax←HighLimit-LowLimit | stack | READ | Compute stack size |
| 0x1C0059D25 | `cmp rax, 2000h` | — | — | — | Check stack >= 0x2000 |
| 0x1C0059D2B | `jb loc_1C0059DB8` | — | — | — | If stack too small, return 0 |
| 0x1C0059D31 | `mov rax, [rbx+28h]` | rax←[rbx+0x28] | [tagWND+0x28] | **READ** | **UAF READ #2** — reads pwndk again |
| 0x1C0059D35 | `mov rax, [rax+78h]` | rax←[rax+0x78] | [pwndk+0x78] | **READ** | Read server handler index |
| 0x1C0059D39 | `cmp rax, 7` | — | — | — | Check index < 7 |
| 0x1C0059D3D | `jnb loc_1C0059DB8` | — | — | — | If >= 7, return 0 |
| 0x1C0059D3F | `mov rax, gServerHandlers[r12+rax*8]` | rax←handler | kernel table | READ | Load function pointer |
| 0x1C0059D47 | `mov r9, [rsp+arg_18]` | r9←lParam | stack | READ | 4th param |
| 0x1C0059D4F | `mov r8, [rsp+arg_10]` | r8←wParam | stack | READ | 3rd param |
| 0x1C0059D57 | `mov edx, esi` | edx←msg | — | — | 2nd param = msg |
| 0x1C0059D59 | `mov rcx, rbx` | rcx←tagWND | — | — | 1st param = tagWND (freed/reclaimed) |
| 0x1C0059D5C | `call __guard_dispatch_icall_fptr` | — | — | CALL | **Call gServerHandler(tagWND, msg, wParam, lParam)** |
| 0x1C0059D62 | `mov rbx, rax` | rbx←result | — | — | Save handler result |
| 0x1C0059D65 | `test r13, r13` | — | — | — | Check LowLimit param |
| 0x1C0059D68 | `jz loc_1C0059BC2` | — | — | — | If null, return result |
| 0x1C0059D6E | `mov [r13+0], rbx` | — | [*LowLimit] | WRITE | Write result to output |
| 0x1C0059D72 | `mov eax, 1` | eax←1 | — | — | Return 1 |
| 0x1C0059D77 | `jmp loc_1C0059BC2` | — | — | JMP | **Function return** |

---

## Task 3: All Writes Through pwndk (rax) After UAF Read

### CRITICAL FINDING: NO writes to [pwndk + 0x50] exist in the post-UAF code path

After exhaustive analysis of every function in the post-UAF call chain, the following writes through pwndk were found:

| Address | Function | Instruction | Offset from pwndk | Value Written | Type | Useful? |
|---------|----------|------------|-------------------|---------------|------|---------|
| 0x1C0245E95 | xxxSBWndProc | `and dword ptr [v13+0x1C], 0xFFCFFFFF` | **+0x1C** | AND (clears bits 20,19) | DWORD AND | NO — wrong offset, only clears bits |
| NONE | — | — | **+0x50** | — | — | **NO WRITE TO pwndk+0x50 EXISTS** |

### All READS through pwndk in post-UAF code:

| Address | Function | Instruction | Offset | What is read |
|---------|----------|------------|--------|-------------|
| 0x1C0059B34 | xxxSendTransformableMessageTimeout | `test byte ptr [rax+12h], 4` | +0x12 | WNDK flags (bit 2) |
| 0x1C0059D35 | xxxSendTransformableMessageTimeout | `mov rax, [rax+78h]` | +0x78 | Server handler index |
| 0x1C0059ECD | xxxSendMessageToClient | `[pwndk+0x12] & 8` | +0x12 | WNDK flags (bit 3) |
| 0x1C0059F0E | xxxSendMessageToClient | `[pwndk+0x78]` | +0x78 | Server handler |
| 0x1C0059FCA | xxxSendMessageToClient | `[pwndk+0x2A]` | +0x2A | WNDK+0x2A (fnid) |
| 0x1C0059FF9 | xxxSendMessageToClient | `[pwndk+0x78]` | +0x78 | Server handler (again) |
| 0x1C006B496 | SfnDWORD | `mov rax, [rbx+28h]` | reads pwndk from tagWND | UAF read #2 |
| 0x1C006B49A | SfnDWORD | `mov rcx, [rax+0E0h]` | +0xE0 | WNDK+0xE0 (DC attribute) |
| 0x1C004852F | xxxDefWindowProc | `[pwndk+0x13]` | +0x13 | WNDK+0x13 (class flags) |
| 0x1C004858C | xxxDefWindowProc | `[pwndk+0x12]`, `[pwndk+0x18]`, `[pwndk+0x2A]` | +0x12,+0x18,+0x2A | Various WNDK fields |

### Offset computation for pvScan0 targeting:

```
Target: write to [pwndk + 0x50] = [SURFACE + 0x50] = pvScan0

SetOrClrWF approach:
  SetOrClrWF writes to [pwndk + (flag>>8) + 0x10]
  For pwndk+0x50: (flag>>8) + 0x10 = 0x50 → flag>>8 = 0x40 → flag = 0x40XX
  BUT: NO SetOrClrWF calls with flag >= 0x4000 exist in win32kfull.sys
  Maximum SetOrClrWF offset: pwndk + 0x1F (flag = 0x0FC0)

Result: No mechanism to write to [pwndk + 0x50] through the post-UAF code path.
```

---

## Task 4: Branch Analysis at 0x1C0059CE9

### Branch Path (WNDK+0x12 bit 2 SET) — gServerHandlers path

**Full trace:**
1. 0x1C0059CE9: Clear stack vars, call IoGetStackLimits
2. Stack size check: if (HighLimit - LowLimit) < 0x2000, return 0
3. 0x1C0059D31: **Second UAF read** — `mov rax, [rbx+28h]` reads pwndk again
4. 0x1C0059D35: `mov rax, [rax+78h]` reads `[pwndk+0x78]` = server handler index
5. If index >= 7: return 0
6. 0x1C0059D3F: Load `gServerHandlers[index]` from kernel table
7. 0x1C0059D5C: Call handler with (tagWND, msg, wParam, lParam)
8. Write result to *LowLimit if provided
9. Return

**gServerHandlers table (at 0x1C02E1140):**

| Index | Address | Function |
|-------|---------|----------|
| 0 | 0x1C00484E0 | xxxDefWindowProc |
| 1 | 0x1C0046290 | xxxDesktopWndProc |
| 2 | 0x1C01F4CC0 | xxxSwitchWndProc |
| 3 | 0x1C023B620 | xxxMenuWindowProc |
| 4 | 0x1C0245BE0 | xxxSBWndProc |
| 5 | 0x1C00DAED0 | xxxTooltipWndProc |
| 6 | 0x1C0023B00 | xxxEventWndProc |

### Path Control
**We can control which path is taken** because:
- We control pwndk (via reclaim data at tagWND+0x28)
- We control [pwndk+0x12] (we point pwndk at a SURFACE, so [pwndk+0x12] = SURFACE+0x12)
- Setting bit 2 at SURFACE+0x12 selects the branch path
- We control [pwndk+0x78] = SURFACE+0x78, selecting the handler index (0-6)

### Which path is more useful?
- **Fall-through path**: Calls xxxSendMessageToClient → SfnDWORD → KeUserModeCallback (user-mode execution)
- **Branch path**: Calls a kernel-side handler with the freed tagWND as parameter

Neither path contains a direct write to [pwndk+0x50]. The fall-through path provides a user-mode callback opportunity (potential for additional exploitation). The branch path provides a controlled handler selection but no write to pvScan0.

---

## Task 5: Function Calls After UAF Read

### Fall-through path calls:

| Function | Address | Receives tagWND? | Receives pwndk? | Writes to pwndk? | Writes to tagWND? |
|----------|---------|-------------------|-----------------|-------------------|-------------------|
| xxxSendMessageToClient | 0x1C0059E70 | Yes (a1) | Reads via [a1+0x28] | NO writes to pwndk | NO writes to tagWND body |
| SfnDWORD | 0x1C006B320 | Yes (a1) | Reads via [a1+5] | NO writes to pwndk | Writes to CLIENTINFO (not tagWND) |
| KeUserModeCallback | (import) | No | No | N/A (user mode) | N/A |
| xxxCallHook | 0x1C005B860 | No (receives hwnd) | No | NO | NO |
| FreeTouchInputInfo | 0x1C01DC5C0 | No | No | NO | NO |
| FreeGestureInfo | 0x1C02276C0 | No | No | NO | NO |

### Branch path calls:

| Function | Address | Receives tagWND? | Receives pwndk? | Writes to pwndk? | Writes to tagWND? |
|----------|---------|-------------------|-----------------|-------------------|-------------------|
| IoGetStackLimits | (import) | No | No | NO | NO |
| gServerHandlers[0-6] | various | Yes (a1/rcx) | Reads via [a1+0x28] | See below | See below |
| xxxDefWindowProc | 0x1C00484E0 | Yes | Reads pwndk | NO | NO |
| xxxDesktopWndProc | 0x1C0046290 | Yes | Minimal | NO | NO |
| xxxSwitchWndProc | 0x1C01F4CC0 | Yes | Reads pwndk | NO | NO |
| xxxMenuWindowProc | 0x1C023B620 | Yes | Reads pwndk | NO | NO |
| xxxSBWndProc | 0x1C0245BE0 | Yes | Reads pwndk | **AND write to [pwndk+0x1C]** | Writes to [tagWND+0x118] |
| xxxTooltipWndProc | 0x1C00DAED0 | Yes | Reads pwndk | NO | **Write to [tagWND+0x28]** (overwrites pwndk) |
| xxxEventWndProc | 0x1C0023B00 | Yes | Minimal | NO | NO |

### SfnDWORD detailed write analysis:
```asm
; At 0x1C006B483-0x1C006B4B2 in SfnDWORD:
0x1c006b483: mov rcx, [rbx]           ; READ [tagWND+0] = hwnd (UAF read)
0x1c006b486: mov rax, [rsi+1E0h]      ; rax = CLIENTINFO pointer (thread-local)
0x1c006b48d: mov [rax+40h], rcx       ; WRITE [CLIENTINFO+0x40] = hwnd (NOT pwndk+0x50!)
0x1c006b496: mov rax, [rbx+28h]       ; READ [tagWND+0x28] = pwndk (UAF read #2)
0x1c006b49a: mov rcx, [rax+0E0h]      ; READ [pwndk+0xE0] (from fake pwndk/SURFACE)
0x1c006b4ab: mov rax, [rsi+1E0h]      ; rax = CLIENTINFO pointer (again)
0x1c006b4b2: mov [rax+50h], rcx       ; WRITE [CLIENTINFO+0x50] = [pwndk+0xE0]
```

**The `mov [rax+50h], rcx` at 0x1C006B4B2 writes to CLIENTINFO+0x50, NOT pwndk+0x50.** rax = [rsi+1E0h] = CLIENTINFO pointer. This is a thread-local data write, not a write through the controlled pwndk pointer.

---

## Task 6: Basic Block CFG After UAF

### All paths from UAF read (0x1C0059B30) to function return:

```
Block 0x1C0059B30 (UAF READ + flag check)
├── FALL-THROUGH (bit 2 CLEAR)
│   ├── Block 0x1C0059B3E (setup + call xxxSendMessageToClient)
│   │   ├── Block 0x1C0059B72 (check active window)
│   │   │   ├── Block 0x1C0059B7B (check hook flags)
│   │   │   │   ├── Block 0x1C0189E45 (WH_CALLWNDPROCRET hook)
│   │   │   │   │   └── Block 0x1C0059B9E (check msg type)
│   │   │   │   └── Block 0x1C0059B99 (get result)
│   │   │   │       └── Block 0x1C0059B9E (check msg type)
│   │   │   │           ├── Block 0x1C0189E99 (FreeTouchInputInfo)
│   │   │   │           │   └── Block 0x1C0059BB6 (check LowLimit)
│   │   │   │           ├── Block 0x1C0189EAC (FreeGestureInfo)
│   │   │   │           │   └── Block 0x1C0059BB6 (check LowLimit)
│   │   │   │           └── Block 0x1C0059BB6 (check LowLimit)
│   │   │   │               ├── Block 0x1C0059D6E (write *LowLimit)
│   │   │   │               │   └── Block 0x1C0059BC2 (RETURN)
│   │   │   │               └── Block 0x1C0059BBF → Block 0x1C0059BC2 (RETURN)
│   │   │   └── Block 0x1C0059B99 (skip hook, get result)
│   │   └── (same continuation as above)
│
└── BRANCH (bit 2 SET)
    └── Block 0x1C0059CE9 (stack limit check)
        ├── Block 0x1C0059DB8 (return 0, stack too small)
        │   └── Block 0x1C0059BC2 (RETURN)
        └── Block 0x1C0059D31 (read pwndk+0x78, check < 7)
            ├── Block 0x1C0059DB8 (return 0, index >= 7)
            │   └── Block 0x1C0059BC2 (RETURN)
            └── Block 0x1C0059D3F (call gServerHandler)
                └── Block 0x1C0059D62 (get result)
                    ├── Block 0x1C0059BC2 (RETURN, no LowLimit)
                    └── Block 0x1C0059D6E (write *LowLimit)
                        └── Block 0x1C0059BC2 (RETURN)
```

### Write analysis per path:
- **ALL paths**: No writes to [pwndk + any_offset] except the AND write in xxxSBWndProc (only on branch path with handler index 4)
- **ALL paths**: No writes to [tagWND + 0x50]
- The only writes are to stack variables, *LowLimit output, and CLIENTINFO (thread-local)

---

## Task 7: tagWND Size and Reclaim Strategy

### tagWND Allocation Size: **0x150 bytes (336 bytes)**

**Evidence** (from xxxCreateWindowEx at 0x1C0075140):
```asm
0x1c0075a0a: mov r9d, 150h          ; r9 = 0x150 = allocation size
0x1c0075a10: mov r8b, 1             ; r8 = object type flag
0x1c0075a13: mov rdx, [rsp+var_2B0] ; rdx = owner
0x1c0075a1b: mov rcx, [rsp+var_448] ; rcx = handle context
0x1c0075a20: call HMAllocObject     ; allocate 0x150-byte tagWND
```

**Pool**: Session pool (via HMAllocObject from win32kbase)
**Zeroing**: HMAllocObject allocates with zero-initialization (ZInit variant seen for sub-allocations)

### WNDK allocation (separate):
- Tag: "Usws" (0x73777355) — used in `Win32AllocPoolZInit` calls
- Size: variable, depends on cbWndExtra from window class
- WNDK is a **separate allocation** from the tagWND body

### Reclaim Requirements:
- **Size**: Must be exactly 0x150 bytes (pool allocator rounds up, so 0x141-0x150 would work)
- **Pool**: Session pool (same as tagWND)
- **Controlled data at offset 0x28**: Must be able to set this to a SURFACE kernel address

### Reclaim Candidates:

1. **Another tagWND** (CreateWindow): Same size, same pool. But pwndk at +0x28 points to a valid WNDK, not a SURFACE. Limited control over offset 0x28.

2. **SURFACE (bitmap)**: Default SURFACE is ~0x88 bytes — TOO SMALL for 0x150-byte slot. Would need a SURFACE with inline bitmap data totaling 0x150 bytes. Possible with specific bitmap dimensions.

3. **Other USER objects of size 0x150**: Need to enumerate HMAllocObject callers with r9=0x150.

4. **Raw pool allocation**: If we can trigger a 0x150-byte session pool allocation with controlled content (e.g., via SetProp, SetWindowLongPtr with large cbWndExtra).

### Controlled fields needed in reclaimed data:
- **Offset 0x28** (pwndk): Set to SURFACE kernel address (from KASLR bypass)
- **Offset 0x12** (accessed via [pwndk+0x12]): Set bit 2 to control branch — this is at SURFACE+0x12, which is in the BASEOBJECT header
- **Offset 0x78** (accessed via [pwndk+0x78]): Set to 0-6 for handler selection — this is at SURFACE+0x78, which is SURFOBJ+0x60

---

## Task 8: xxxFreeWindow (0x1C007A720) Free Path Confirmation

### Free Path Analysis:

```c
// In xxxFreeWindow:
HMMarkObjectDestroy(this);           // First mark — sets destroy flag
*(_BYTE *)(_HMPheFromObject(this) + 25) |= 2u;  // Set "destroy in progress" flag

// ... extensive cleanup (properties, menus, shadows, DCEs, etc.) ...

result = ThreadUnlock1();            // Decrement cLockObj
if (result)                          // If cLockObj reached 0
{
    // ... more cleanup ...
    if (HMMarkObjectDestroy(this))   // Second mark — check if should free
    {
        // ... final cleanup ...
        HMFreeObject(this);          // ★ ACTUALLY FREE THE OBJECT ★
        // After this, the 0x150-byte tagWND body is freed to the session pool
    }
    else
    {
        // Zombie path — object not freed, becomes zombie
        *(_QWORD *)(pwndk + 120) = 0;  // Clear server handler
        // ... set zombie flags ...
    }
}
```

### Conditions for actual free (HMFreeObject called):
1. ThreadUnlock1 returns non-zero (cLockObj decremented to 0)
2. Second HMMarkObjectDestroy returns true (object marked for destruction)

### During the UAF trigger:
- The tagWND's cLockObj was 0 (confirmed by exploit chain: "cLockObj=0")
- xxxDestroyWindow calls HMLockObject (cLockObj: 0→1)
- xxxFreeWindow calls ThreadUnlock1 (cLockObj: 1→0, returns non-zero)
- Second HMMarkObjectDestroy returns true
- **HMFreeObject is called — the tagWND is ACTUALLY FREED (not zombie)**

### Writes to pwndk in xxxFreeWindow (BEFORE the free):
- `[pwndk+0x30] = 0` (clear spwndParent)
- `[pwndk+0x38] = 0` (clear spwndLastActive)
- `[pwndk+0x40] = 0` (clear spwndOwner)
- `[pwndk+0xB0] = 0` (clear property list ptr)
- `[pwndk+0xA8] = 0` (clear update region)
- `[pndk+0xFC] = 0` (clear counter)
- `[pwndk+0x78] = 0` (zombie path only — clear server handler)
- `SetOrClrWF(0, this, 0x0204)` — writes to [pwndk+0x12]
- `SetOrClrWF(0, this, 0x0220)` — writes to [pwndk+0x12]
- `SetOrClrWF(0, this, 0x0FC0)` — writes to [pwndk+0x1F]
- `SetOrClrWF(1, this, 0x0F00)` — writes to [pwndk+0x1F] (no-op, bit mask = 0x00)

**These writes happen BEFORE HMFreeObject, so they go to the original (not-yet-freed) tagWND/WNDK. They do NOT affect the reclaimed data.**

---

## Task 9: HMAllocObject and HMFreeObject

### HMAllocObject (imported from win32kbase at 0x1C0365FD0):
- **Not decompilable** (imported from win32kbase.sys, not in this IDB)
- **Called in xxxCreateWindowEx** with: rcx=context, rdx=owner, r8=1(type), r9=0x150(size)
- **Pool**: Session pool (win32k session pool allocator)
- **Zeroing**: The "ZInit" variant is used for sub-allocations (WNDK, extra bytes). HMAllocObject behavior depends on win32kbase implementation — likely zero-initialized.

### HMFreeObject (imported from win32kbase at 0x1C0365FE8):
- **Called in xxxFreeWindow** at 0x1C007BCF8 with: rcx=tagWND pointer
- **Frees the 0x150-byte tagWND body** back to the session pool
- **Memory is NOT zeroed on free** (confirmed by exploit chain: "freed memory NOT zeroed")
- **Goes to the general free list** (not a lookaside list, based on exploit chain stating "cross-type reclaim IS possible")

### Handle table:
- The HM handle table entry is **separate** from the tagWND body
- cLockObj is in the handle table entry, NOT in the tagWND body
- HMLockObject reads [tagWND+0] to get the handle, then operates on the handle table entry
- HMFreeObject frees the body AND removes/invalidates the handle table entry

---

## Task 10: xxxSendMessage Variants

### Functions found:

| Function | Address | Relevant to post-UAF? |
|----------|---------|----------------------|
| xxxSendMessage | 0x1C005D594 | Wrapper, calls xxxSendMessageEx |
| xxxSendMessageEx | 0x1C005D440 | Core send logic |
| xxxSendMessageToClient | 0x1C0059E70 | **YES** — called on fall-through path |
| xxxSendMessageCallback | 0x1C0040544 | Not called post-UAF |
| xxxSendMessageBSM | 0x1C003EB40 | Not called post-UAF |
| xxxSendMessageFF | 0x1C0161950 | Not called post-UAF |
| xxxWrapSendMessage | 0x1C00598C0 | Not called post-UAF |

### xxxSendMessageToClient (0x1C0059E70) — detailed:
- Reads `[a1+0x28]` = pwndk (UAF read)
- Reads `[pwndk+0x12]` for flags (bit 3: & 8)
- Reads `[pwndk+0x78]` for server handler
- Reads `[pwndk+0x2A]` for fnid
- Calls `SfnDWORD` or `gapfnScSendMessage[MessageTable[msg]]` with tagWND as first param
- Alternatively calls `xxxDefWindowProc(a1)` for certain window types
- **NO writes to pwndk or tagWND body**
- Writes only to `*a7` (result output, stack variable)

### xxxSendMessage (0x1C005D594):
- Simple wrapper that calls xxxSendMessageEx
- xxxSendMessageEx calls xxxSendTransformableMessageTimeout
- **This is how the UAF is triggered** — the caller sends a message via xxxSendMessage, which calls xxxSendTransformableMessageTimeout

---

## Task 11: Complete Reclaim Strategy

### Strategy A: Reclaim with raw pool allocation (controlled data)

**Approach**: Spray 0x150-byte session pool allocations with controlled content.

**How to spray 0x150-byte session pool objects:**
1. **CreateWindow with cbWndExtra**: If we register a window class with `cbWndExtra = 0x150 - sizeof(tagWND header)`, the extra bytes allocation might be 0x150 bytes. BUT: the extra bytes are a separate allocation from the tagWND body.

2. **SetProp with large data**: SetProp creates property entries in the session pool. If the entry size matches 0x150, we could use this. But property entries are typically smaller.

3. **CreateAcceleratorTable**: Calls HMAllocObject with a specific size. If we can control the size to be 0x150, this could work.

4. **CreateMenu**: Calls HMAllocObject for tagMENU. If tagMENU is 0x150 bytes, this could work.

5. **DDE conversations**: Creates tagDDECONV objects in the session pool.

**Controlled data layout needed:**
```
Offset 0x00: [hwnd or controlled value — read by HMLockObject]
Offset 0x10: [pti — compared with current thread]
Offset 0x28: [SURFACE kernel address — becomes pwndk] ← CRITICAL
Offset 0x38: [tagObjLock — must be valid or benign]
Offset 0x50: [??? — target for write, but no write exists here]
Offset 0x118: [SBWND/extra data pointer — used by xxxSBWndProc]
```

### Strategy B: Reclaim with another tagWND

**Approach**: Create a new window after the free to reclaim the slot with a new tagWND.

**Problem**: The new tagWND has a valid pwndk pointing to a valid WNDK. We can't control pwndk to point at a SURFACE. However, we CAN control WNDK fields via SetWindowLongPtr.

**SetWindowLongPtr offsets** (write to WNDK, not tagWND):
- GWLP_WNDPROC: Sets window procedure in WNDK
- GWLP_USERDATA: Sets user data in WNDK
- GWLP_HINSTANCE: Sets instance handle in WNDK
- GWLP_ID: Sets window ID in WNDK

These write to the WNDK, not the tagWND body. Not directly useful for pvScan0 overwrite.

### Strategy C: Reclaim with SURFACE (bitmap)

**Approach**: Create a bitmap whose SURFACE allocation is exactly 0x150 bytes.

**SURFACE size calculation:**
- BASEOBJECT: 0x18 bytes
- SURFOBJ: ~0x68 bytes (fixed portion)
- Bitmap bits: inline for small bitmaps
- Total needed: 0x150 bytes
- Bitmap bits needed: 0x150 - 0x18 - 0x68 = 0xD0 = 208 bytes

**For a monochrome bitmap (1 bpp):**
- 208 bytes × 8 = 1664 bits = ~41×41 pixels (41×41/8 = 210 bytes)

**For a 32bpp bitmap:**
- 208 bytes / 4 = 52 pixels = ~7×8 pixels (7×8×4 = 224 bytes = 0xE0)
- Would need exact size match — pool allocator rounds to 0x10 alignment

**SURFACE layout at critical offsets (if reclaiming tagWND):**
```
SURFACE+0x00 = BASEOBJECT.h (GDI handle) → tagWND+0x00 = HWND
SURFACE+0x08 = BASEOBJECT.cLockObj → tagWND+0x08
SURFACE+0x10 = BASEOBJECT padding → tagWND+0x10 = pti
SURFACE+0x18 = SURFOBJ.dhsurf → tagWND+0x18
SURFACE+0x20 = SURFOBJ.hsurf → tagWND+0x20
SURFACE+0x28 = SURFOBJ.iType (STYPE_BITMAP=1) → tagWND+0x28 = pwndk ★
SURFACE+0x50 = SURFOBJ.pvScan0 → tagWND+0x50 ★★★
```

**KEY INSIGHT**: If SURFACE reclaims tagWND, then:
- tagWND+0x28 = SURFACE+0x28 = SURFOBJ.iType (typically 1 = STYPE_BITMAP)
- This would make pwndk = 1, causing a crash when the code reads [pwndk+0x12]

**This approach requires controlling SURFOBJ.iType to be a valid kernel address — not normally possible.**

### Strategy D: Reclaim with controlled data, use SURFACE separately

**Approach**: 
1. Reclaim freed tagWND with 0x150-byte controlled data
2. Set offset 0x28 = SURFACE kernel address (pwndk → SURFACE)
3. Set pwndk+0x12 (SURFACE+0x12) to control branch
4. Set pwndk+0x78 (SURFACE+0x78) to control handler selection
5. The post-UAF code READS from the SURFACE but does NOT WRITE to it
6. **No write to pvScan0 is achieved through this path alone**

---

## Task 12: Alternative Write Primitives in Post-UAF Code

### Write-what-where analysis:

**No write-what-where pattern found in the post-UAF code path.**

The post-UAF code:
1. READS [tagWND+0x28] = pwndk (controlled) — **information leak, not write**
2. READS [pwndk+0x12] = flags — **controlled read from SURFACE**
3. READS [pwndk+0x78] = handler index — **controlled read from SURFACE**
4. Calls handler or user callback — **no write back to tagWND or pwndk**
5. Writes result to stack or *LowLimit — **not useful**

### HMLockObject/ThreadUnlock1 side effects:

SfnDWORD calls:
```c
HMLockObject(a1);     // Reads [a1+0] = handle, increments cLockObj in handle table
KeUserModeCallback();  // User-mode execution
ThreadUnlock1();       // Decrements cLockObj in handle table, removes lock list entry
```

**HMLockObject does NOT write to the tagWND body.** It operates on the separate handle table entry. If the tagWND is freed and reclaimed:
- [a1+0] = reclaimed data at offset 0 (our controlled value)
- HMLockObject interprets this as a handle and looks up the handle table
- If the handle is invalid, HMLockObject may crash or fail silently
- If the handle is valid (for another object), it increments that object's lock count

**This is not a write to the tagWND body or to pvScan0.**

### Writes to [rbx+offset] (tagWND fields) in post-UAF code:

| Function | Write | Offset | Value | Useful? |
|----------|-------|--------|-------|---------|
| SfnDWORD | `mov [rax+40h], rcx` | CLIENTINFO+0x40 | hwnd | NO — writes to thread data |
| SfnDWORD | `mov [rax+50h], rcx` | CLIENTINFO+0x50 | [pwndk+0xE0] | NO — writes to thread data |
| xxxTooltipWndProc | `mov [rbx+28h], ecx` | tagWND+0x28 | tick count | Overwrites pwndk with garbage |
| xxxSBWndProc | `and [pwndk+0x1C], ...` | pwndk+0x1C | AND operation | Clears bits, wrong offset |

**No useful write-what-where primitive found.**

---

## Task 13: DestroyWindow → FreeWindow → FreeObject Timing

### Full timing analysis:

```
xxxSendTransformableMessageTimeout(tagWND, msg, ...)
│
├── Calls xxxCallHook2() — triggers WH_CALLWNDPROC hook
│   │
│   ├── [USER MODE] Hook callback runs
│   │   │
│   │   ├── User calls DestroyWindow(child)  ← child = same tagWND being messaged
│   │   │   │
│   │   │   ├── xxxDestroyWindow(tagWND) [0x1C007DC00]
│   │   │   │   ├── HMLockObject(tagWND) — cLockObj: 0→1
│   │   │   │   ├── ... destruction logic ...
│   │   │   │   ├── xxxFreeWindow(tagWND) [0x1C007A720]
│   │   │   │   │   ├── HMMarkObjectDestroy — marks for destruction
│   │   │   │   │   ├── ... cleanup (properties, menus, DCEs, etc.) ...
│   │   │   │   │   ├── ThreadUnlock1 — cLockObj: 1→0 (returns non-zero)
│   │   │   │   │   ├── HMMarkObjectDestroy — returns true (should free)
│   │   │   │   │   └── HMFreeObject(tagWND) ★ TAGWND IS FREED ★
│   │   │   │   │       └── 0x150-byte body returned to session pool free list
│   │   │   │   │
│   │   │   │   └── xxxDestroyWindow returns 1
│   │   │   │
│   │   │   ├── [USER MODE] Spray objects to reclaim freed slot ★
│   │   │   │   └── 0x150-byte objects with controlled data at offset 0x28
│   │   │   │
│   │   │   └── Hook callback returns
│   │
│   └── xxxCallHook2 returns
│
├── 0x1C0059B30: mov rax, [rbx+28h] ★ UAF READ ★
│   └── rbx still points to freed (now reclaimed) tagWND
│       └── [rbx+0x28] = controlled pwndk value → SURFACE address
│
├── 0x1C0059B34: test [rax+12h], 4 — checks SURFACE+0x12
│
└── ... continues execution with controlled pwndk ...
```

### CRITICAL TIMING ANSWER:
**xxxFreeWindow (and HMFreeObject) happen DURING the hook callback, BEFORE the hook callback returns.** The sequence is:

1. xxxCallHook2 triggers user-mode hook
2. User-mode hook calls DestroyWindow → xxxDestroyWindow → xxxFreeWindow → **HMFreeObject** (tagWND freed)
3. User-mode hook **sprays objects** to reclaim the freed slot
4. User-mode hook returns
5. xxxCallHook2 returns
6. Execution reaches 0x1C0059B30 — **UAF read from reclaimed data**

The object is freed AND reclaimed BEFORE the UAF read occurs. This is the critical timing that makes the exploit possible.

---

## Task 14: Other Post-UAF Writes in Called Functions

### Comprehensive search results:

All functions in the post-UAF call chain were searched for writes to:
- `[pwndk + offset]` (any offset, through the controlled WNDK pointer)
- `[tagWND + 0x50]` (the target offset for pvScan0 overwrite)
- `[tagWND + any_offset]` (any tagWND body field)

### Results:

| Function | Writes to pwndk? | Writes to tagWND+0x50? | Writes to tagWND body? |
|----------|-------------------|------------------------|------------------------|
| xxxSendTransformableMessageTimeout | NO | NO | NO |
| xxxSendMessageToClient | NO | NO | NO |
| SfnDWORD | NO | NO (writes to CLIENTINFO+0x50) | NO |
| xxxDefWindowProc | NO | NO | NO |
| xxxRealDefWindowProc | NO | NO | NO (13 writes, all to non-tagWND/pwndk) |
| xxxDesktopWndProc | NO | NO | NO |
| xxxSwitchWndProc | NO | NO | NO |
| xxxMenuWindowProc | NO | NO | NO |
| xxxSBWndProc | AND to [pwndk+0x1C] | NO | Write to [tagWND+0x118] |
| xxxTooltipWndProc | NO | NO | Write to [tagWND+0x28] (overwrites pwndk) |
| xxxEventWndProc | NO | NO | NO |
| SetOrClrWF | Max offset pwndk+0x1F | NO | NO |

### Conclusion:
**No function in the post-UAF call chain writes to [pwndk + 0x50] or [tagWND + 0x50].**

---

## Task 15: UAF as Information Leak

### What the UAF read gives us:

The UAF read at 0x1C0059B30 reads `[tagWND+0x28]` from the freed/reclaimed tagWND. If we control the reclaimed data, this is not an information leak — it's a controlled read (we already know what we put there).

However, if we DON'T reclaim the slot, the freed memory might contain stale data from the original tagWND. The stale pwndk value at offset 0x28 would be the original WNDK kernel address — this is an **information leak of a kernel pointer**.

### Subsequent reads through pwndk:

After the UAF read, the code reads from pwndk at several offsets:
- `[pwndk+0x12]` — WNDK flags
- `[pwndk+0x78]` — server handler index
- `[pwndk+0xE0]` — DC attribute (in SfnDWORD)
- `[pwndk+0x2A]` — fnid (in xxxSendMessageToClient)

If pwndk points at a SURFACE:
- `[SURFACE+0x12]` = BASEOBJECT+0x12 (likely part of cLockObj or padding)
- `[SURFACE+0x78]` = SURFOBJ+0x60 (some SURFOBJ field)
- `[SURFACE+0xE0]` = SURFOBJ+0xC8 (some SURFOBJ field)
- `[SURFACE+0x2A]` = SURFOBJ+0x12 (iType high byte + cjSize low byte)

These reads from the SURFACE could be used to:
1. **Control branch direction**: Set [SURFACE+0x12] bit 2 to select branch path
2. **Control handler selection**: Set [SURFACE+0x78] to 0-6 to select gServerHandler
3. **Leak SURFACE field values**: The values read from SURFACE fields are used in kernel operations

### SURFACE+0x12 field analysis:
```
SURFACE+0x12 = BASEOBJECT+0x12
  BASEOBJECT layout (0x18 bytes):
    +0x00: h (HANDLE, 8 bytes)
    +0x08: cLockObj (ULONG, 4 bytes)
    +0x0C: padding (4 bytes)
    +0x10: dwFlags/cookie (ULONG, 4 bytes)
    +0x14: padding (4 bytes)
  
  SURFACE+0x12 = BASEOBJECT+0x12 = high 2 bytes of dwFlags
  Bit 2 of this byte controls the branch at 0x1C0059B38
```

### Chaining multiple UAF reads:
If we can trigger the UAF multiple times, each iteration reads from the SURFACE at different offsets (depending on the code path taken). This could be used to:
1. Leak SURFACE field values to user mode (via the result of xxxSendMessageToClient)
2. Build a profile of the SURFACE layout
3. Use leaked values to construct a separate write primitive

However, the results of the reads are either used internally (for branch decisions) or returned as the function result. The function result is returned to the caller of xxxSendTransformableMessageTimeout, which is xxxSendMessage → xxxSendMessageEx. The result eventually reaches the original message sender, which could be user-mode code.

---

## CRITICAL SUMMARY

### Primary Finding: NO Direct Write to pwndk+0x50

After exhaustive analysis of every instruction and function call in the post-UAF code path of `xxxSendTransformableMessageTimeout`, **there is NO write to `[pwndk + 0x50]` (SURFACE+0x50 = pvScan0) anywhere in the execution path.**

The post-UAF code performs only **READS** through the controlled pwndk pointer:
- `[pwndk+0x12]` — flag check
- `[pwndk+0x78]` — handler index
- `[pwndk+0x2A]` — fnid check
- `[pwndk+0xE0]` — DC attribute

The only write through pwndk found in any reachable function is:
- `xxxSBWndProc`: `AND dword ptr [pwndk+0x1C], 0xFFCFFFFF` — a bit-clearing AND at offset 0x1C, not 0x50

### tagWND Size
- **0x150 bytes (336 bytes)** — confirmed from `mov r9d, 150h` before `HMAllocObject` call in xxxCreateWindowEx at 0x1C0075A0A

### Free Path Confirmation
- The tagWND IS actually freed (not zombie) during the WH_CALLWNDPROC hook callback
- `HMFreeObject` is called in `xxxFreeWindow` when `cLockObj` reaches 0
- The freed memory returns to the session pool free list, NOT zeroed
- Cross-type reclaim is possible (same pool, same size, no type isolation)

### Best Alternative Exploitation Strategies

Since no direct write to `pwndk+0x50` exists, the exploit must use one of these alternative approaches:

#### Strategy 1: Reclaim with SURFACE, find write via separate code path
1. Create a bitmap with SURFACE size = 0x150 bytes (inline bitmap data)
2. Free the tagWND (UAF)
3. Reclaim with the SURFACE (same size, same pool)
4. SURFACE+0x50 = pvScan0 overlaps with tagWND+0x50
5. Find a DIFFERENT code path (not in xxxSendTransformableMessageTimeout) that writes to tagWND+0x50
6. This could be: SetWindowLongPtr, NtUserCallNoParam, or another Win32 API that modifies tagWND fields
7. **Challenge**: The handle is invalid after HMFreeObject. Need to find a code path that accesses the tagWND by pointer (not handle) and writes to offset 0x50.

#### Strategy 2: Use user-mode callback for write
1. Reclaim with controlled data (pwndk → SURFACE)
2. Set WNDK+0x12 bit 2 CLEAR → fall-through path
3. xxxSendMessageToClient → SfnDWORD → KeUserModeCallback
4. During user-mode callback, the window procedure runs
5. The window procedure can:
   a. Create/destroy objects to manipulate pool layout
   b. Call SetWindowLongPtr on a different window to write controlled data
   c. Trigger additional kernel code paths that write to the SURFACE
6. **Challenge**: The window procedure operates on the (invalid) HWND from the reclaimed data. Need the HWND to be valid for a different window, or find a side-channel write.

#### Strategy 3: Use HMLockObject counter manipulation
1. Reclaim with controlled data where [tagWND+0] = a valid GDI handle
2. SfnDWORD calls HMLockObject(tagWND) which reads [tagWND+0] as a handle
3. HMLockObject increments cLockObj for that handle's object
4. If the handle points to a SURFACE, cLockObj at SURFACE+0x08 is incremented
5. This is a controlled increment (by 1) at SURFACE+0x08
6. **Challenge**: SURFACE+0x08 is cLockObj, not pvScan0 (SURFACE+0x50). The offset doesn't match.

#### Strategy 4: Multi-step type confusion
1. Reclaim with controlled data (pwndk → address A)
2. Post-UAF code reads [A+0x78] = value V
3. If V < 7, calls gServerHandlers[V](tagWND, msg, wParam, lParam)
4. Handler receives the reclaimed tagWND
5. If handler writes to [tagWND + 0x50], and tagWND is reclaimed by a SURFACE, the write goes to SURFACE+0x50 = pvScan0
6. **Challenge**: Need (a) a handler that writes to [tagWND+0x50] and (b) the tagWND slot to be reclaimed by a SURFACE (not just controlled data). None of the 7 handlers write to [tagWND+0x50].

#### Strategy 5: Use xxxTooltipWndProc write to [tagWND+0x28]
1. Reclaim with controlled data, set pwndk = SURFACE
2. Set [SURFACE+0x12] bit 2 → branch path
3. Set [SURFACE+0x78] = 5 → select xxxTooltipWndProc
4. xxxTooltipWndProc writes `mov [rbx+28h], ecx` (tick count value) to tagWND+0x28
5. This overwrites pwndk with a tick count — NOT useful directly
6. BUT: if we can control what value is written (e.g., by manipulating tick count), and if tagWND is reclaimed by a SURFACE, the write to tagWND+0x28 = SURFACE+0x28 = SURFOBJ.iType could corrupt the SURFACE type
7. **Challenge**: The written value is a tick count computation, not directly controllable. And offset 0x28 is not pvScan0 (offset 0x50).

### Most Viable Path: Strategy 1 (SURFACE reclaim + separate write)
The most viable approach is to reclaim the freed tagWND slot directly with a SURFACE of the same size (0x150 bytes), making tagWND+0x50 overlap with SURFACE+0x50 (pvScan0). Then find a separate kernel code path that writes to the tagWND body at offset 0x50. This requires:
1. Creating a bitmap with SURFACE allocation = 0x150 bytes
2. Timing the free/reclaim so the SURFACE lands in the tagWND's freed slot
3. Finding a separate write to tagWND+0x50 (possibly through a different message or API call that accesses the window object by kernel pointer)

### Final Assessment
The post-UAF code in `xxxSendTransformableMessageTimeout` does NOT contain a write to `pwndk+0x50`. The exploit chain's "pvScan0 R/W" step must be achieved through a mechanism outside the immediate post-UAF code path — either through a separate kernel write triggered during the user-mode callback, through a multi-step type confusion, or through a different vulnerability in the reclaim/handler chain. The UAF provides the type confusion (controlled pwndk pointing at SURFACE), but the actual pvScan0 overwrite requires a write primitive from a different source.
