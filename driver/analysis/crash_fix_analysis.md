# Win32k UAF Exploit Crash Fix Analysis

## BSOD Crash: SYSTEM_SERVICE_EXCEPTION (3b) in DefSetText

### Crash Details

```
SYSTEM_SERVICE_EXCEPTION (3b)
Arg1: c0000005 (STATUS_ACCESS_VIOLATION)
Arg2: ffff9a101a6fb137 (win32kfull!DefSetText+0x1ab)
Arg3: ffffa4888cf319a0 (context record)

Crash instruction: mov word ptr [rax+rcx*2], bx
  rax = 0 (NULL string buffer pointer)
  rcx = 0 (text_length / 2 = 0)
  bx  = 0 (null terminator)
```

### Task 1: Crash Analysis (IDA Pro Confirmed)

#### 1a. Crash Instruction Location

DefSetText is at `0x1c004af8c` (imagebase `0x1c0000000`). The crash is at `DefSetText+0x1ab = 0x1c004b137`.

Disassembly of the crash sequence:
```asm
0x1c004b127: mov rax, [rdi+28h]     ; rax = pwndk (tagWND+0x28)
0x1c004b12b: mov ecx, [rax+0B8h]    ; ecx = pwndk+0xB8 (text_length in WNDK)
0x1c004b131: shr rcx, 1             ; rcx = text_length / 2 (wchar index)
0x1c004b134: mov rax, [r15]         ; rax = *(tagWND+0xB8) = string buffer pointer
0x1c004b137: mov [rax+rcx*2], bx    ; CRASH: write null terminator to buffer[index]
```

Where `r15 = tagWND + 0xB8` (set at `0x1c004aff1: lea r15, [rcx+0B8h]`).

#### 1b. NULL Pointer Write Confirmed

The crash is a NULL pointer write:
- `rax = *(tagWND+0xB8) = 0` (string buffer is NULL)
- `rcx = *(pwndk+0xB8) >> 1 = 0` (text_length = 0)
- `bx = 0` (null terminator)
- Write target: `[0 + 0*2] = [NULL]` → BSOD

#### 1c. Root Cause: Dual Failure

**Problem 1 — Kernel Stack Corruption:**
The WH_CALLWNDPROC hook callback calls `CreateWindowExW` to create the reclaim window. This is a win32k syscall that reuses the same kernel thread stack. The `CREATESTRUCT` copy on the stack (from `NtUserfnINLPCREATESTRUCT` at `0x1c0033d30`, local `v17[7]` at `[rsp+40h]`) is overwritten by the new `CreateWindowEx` call's stack frames.

When the hook returns, the kernel continues processing the original `WM_NCCREATE`. `xxxRealDefWindowProc` reads the `lParam` (CREATESTRUCT pointer) which now points to corrupted stack data. The `LargeUnicodeString` at `lParam+0x50` has garbage values.

**Problem 2 — NULL String Buffer:**
Even without stack corruption, `xxxFreeWindow` (at `0x1c007a720`) frees the string buffer and clears `tagWND+0xB8` to NULL:
```asm
0x1c007b769: mov r8, [rdi+0B8h]      ; r8 = string buffer
0x1c007b782: call RtlFreeHeap        ; free the buffer
0x1c007b799: mov [rdi+0B8h], r14     ; tagWND+0xB8 = 0 (r14 = 0)
```

When `DefSetText` runs on the freed tagWND:
1. Reads `pwndk+0xBC` (max_length) — stale value from original WNDK (offset 188 > 96, NOT zeroed by `UserFreeIsolatedType`)
2. If `max_length >= BytesInUnicodeString(2)` → skips alloc path
3. Uses existing buffer at `tagWND+0xB8` — which is NULL
4. Writes null terminator to NULL → BSOD

#### 1d. Value of Length/rdx

From the crash context, `rdx = 2`. This is `BytesInUnicodeString`, computed in `DefSetText`:
```c
v6 = v5 & 0xFFFFFFFE;   // v5 = *a2 (string Length = 0), v6 = 0
v7 = v6 + 2;            // v7 = 2 (BytesInUnicodeString = 2, for null terminator)
```

The text_length written to `pwndk+0xB8` is `v7 - 2 = 0`, confirming `rcx = 0` at the crash.

### Task 2: Reclaim Strategy Analysis

#### Approach A: Separate Thread for Reclaim

**Feasible for crash fix, NOT for bitmap corruption.**

- Thread A: hook fires, `DestroyWindow(child)` only (no `CreateWindowEx`)
- Thread B: signaled by Thread A, creates reclaim window
- Thread B's stack does NOT corrupt Thread A's kernel stack
- The user critical section is released during user-mode callbacks (standard win32k behavior)
- Thread B can allocate while Thread A is in the hook

**BUT:** Thread B's extra bytes are a separate allocation from the tagWND body. `SetWindowLongPtr(positive)` writes to extra bytes, NOT to tagWND+0x28 (pwndk). No bitmap corruption.

#### Approach B-D: Pool Allocation Analysis

**IDA Pro confirmed:** Searched for `mov r8d/r9d, 150h` across the entire binary:

| Address | Function | Type |
|---------|----------|------|
| `0x1c003e69d` | `xxxNormalizeRect` | `memset` (stack buffer) |
| `0x1c003e968` | `xxxDeferWindowPosAndCheckPoint` | `memset` (stack buffer) |
| `0x1c0041df0` | `FindOldMonitor` | `memset` (stack buffer) |
| `0x1c0075a0a` | `xxxCreateWindowEx` | `HMAllocObject` (pool, ZInit=1) |

**Only one pool allocation of 0x150 bytes exists:** `HMAllocObject` in `xxxCreateWindowEx`, with `r8b = 1` (ZInit flag = TRUE, zero-initialized).

**Conclusion:** No non-ZInit 0x150-byte session pool allocation exists. Cannot spray controlled data into the freed tagWND slot.

#### Approach E: Different HMAllocObject Object Type

No other `HMAllocObject` calls with size 0x150 were found. The only 0x150-byte HMAllocObject is for tagWND in `xxxCreateWindowEx`.

#### Approach F/G: WNDK Reclaim + Arbitrary Read

**Sfn* path NOT available.** `xxxDefWindowProc` at `0x1c00484e0`:
```c
if ( gihmodUserApiHook < 0 )
    return xxxRealDefWindowProc(a1);
```
When `gihmodUserApiHook < 0` (no UxTheme hook loaded, which is the normal state), the kernel goes directly to `xxxRealDefWindowProc`, bypassing the `Sfn*` dispatch entirely. The arbitrary READ via `Sfn* + TEB+0x850` is not achievable.

#### Approach H: WNDK Reclaim with New Window

**Partially feasible.** The WNDK can be reclaimed by a new window's WNDK:

1. WNDK and POPUPMENU share `CTypeIsolation<24576,96>` (256-byte slots)
2. `UserFreeIsolatedType` zeros only 0x60 (96) bytes before freeing
3. `MNAllocPopup` also zeros only 0x60 bytes when allocating
4. A new window's WNDK allocation can reclaim the freed slot

**BUT:** `SetOrClrWF` writes to `pwndk+0x12` (in the reclaimed WNDK), not to a SURFACE. We need `pwndk = SURFACE+0x32` for bitmap corruption, and we cannot control `pwndk` (`tagWND+0x28`).

### Type Isolation Pool Analysis (IDA Confirmed)

| Pool | Slot Size | Slots | Used By |
|------|-----------|-------|---------|
| `CTypeIsolation<36864,144>` | 256 bytes | 144 | tagCLS (ClassAlloc/ClassFree), RFONTOBJ |
| `CTypeIsolation<24576,96>` | 256 bytes | 96 | WNDK (xxxFreeWindow), POPUPMENU (MNAllocPopup) |
| `CTypeIsolation<28672,112>` | 256 bytes | 112 | Scrollbar tracking (xxxSBTrackInit/xxxEndScroll) |

Key: The second template parameter is the number of slots per pool section, NOT the slot size. All pools use 256-byte (0x100) slots.

### SetOrClrWF Analysis (0x1c004df08)

```c
v8 = *(_DWORD **)(a2 + 40);       // v8 = pwndk = *(tagWND+0x28)
v10 = (unsigned __int64)a3 >> 8;  // v10 = 0x202 >> 8 = 2
// Writes to: pwndk[v10 + 16] = pwndk[0x12]
// When a1=1 (SET): pwndk[0x12] |= (a3 & 0xFF) = pwndk[0x12] |= 0x02
```

`SetOrClrWF(1, tagWND, 0x202, 1)` writes ONE BYTE (`0x02`) to `pwndk+0x12`. For bitmap corruption, `pwndk+0x12` must be `SURFACE+0x44` (the bitmap height field), requiring `pwndk = SURFACE+0x32`.

### WM_NCCREATE Path in xxxRealDefWindowProc (0x1c0049e28)

Message dispatch: `WM_NCCREATE (0x81)` → `129 - 123 - 4 - 1 - 1 = 0` → `jz loc_1C0049F38`

```
loc_1C0049F38:
  mov rax, [rsi+28h]           ; rax = pwndk
  test [rax+1Eh], 30h          ; check bits 4-5 of pwndk+0x1E
  jnz loc_1C004A46F            ; if SET → InitPwSB path (still reaches DefSetText)
  
  test r15, r15                ; check lParam
  jz skip                      ; if NULL → skip
  lea rax, [r15+50h]           ; rax = lParam+0x50 (window name string)
  cmp [rsi+18h], 0             ; check tagWND+0x18 (desktop)
  jz skip                      ; if NULL → skip
  mov rcx, [rax+8]             ; string buffer
  test rcx, rcx
  jz skip                      ; if NULL → skip
  
  call SetOrClrWF(1, tagWND, 0x202, 1)  ; writes pwndk[0x12] |= 0x02
  call DefSetText(tagWND, lParam+0x50)  ; sets window text
```

### Task 3: Stack Corruption Fix

**Fix: Remove `CreateWindowEx` from hook callback entirely.**

The hook callback must only call `DestroyWindow(child)` and signal a separate thread. No win32k syscalls that use significant kernel stack should be made from within the hook callback.

### Task 4: Exploit Rewrite

#### Crash Avoidance Strategy

1. **No `CreateWindowEx` in hook**: Only `DestroyWindow(child)` in the hook callback
2. **Child with NULL title**: `CreateWindowExW(..., NULL, ...)` — no `lpWindowName`
   - During child creation, `DefSetText` is NOT called (string buffer is NULL at `lParam+0x58`)
   - `WNDK+0xBC` (max_length) stays 0 from zero-initialization
   - After `UserFreeIsolatedType`, `WNDK+0xBC` (offset 188 > 96) retains value 0
3. **During UAF DefSetText**: `pwndk+0xBC = 0 < 2 (BytesInUnicodeString)` → alloc path
   - `DesktopAlloc` allocates new 2-byte buffer
   - Stores at `tagWND+0xB8` (freed tagWND memory — harmless write to freed pool)
   - Writes null terminator to new buffer → NO CRASH

#### WNDK Reclaim Strategy

1. Thread A: hook fires, `DestroyWindow(child)` only, signals Thread B
2. Thread B: creates a new window (with NULL title) → WNDK allocated from type isolation pool
3. Thread B's WNDK may reclaim the freed WNDK slot (LIFO from SLIST)
4. Thread B signals Thread A, hook returns
5. Kernel reads stale `pwndk` → points to reclaimed WNDK

#### Bitmap Corruption: NOT Achievable

The bitmap corruption approach requires `pwndk = SURFACE+0x32` so that `SetOrClrWF` writes to `SURFACE+0x44` (bitmap height). This is impossible because:

1. `pwndk` (`tagWND+0x28`) is set during `HMAllocObject` and never changed
2. After free, the stale `pwndk` points to the freed WNDK, not a SURFACE
3. No API writes to `tagWND+0x28`
4. `SetWindowLongPtr(positive)` writes to extra bytes (separate allocation)
5. `SetWindowLongPtr(negative/GWLP)` writes to pwndk fields, not the pwndk pointer
6. The only 0x150-byte session pool allocation is `HMAllocObject` (ZInit, zeros the body)
7. WNDK (type isolation) and SURFACE (GDI pool) are in different pools — can't overlap

#### What the Fixed Exploit Achieves

1. **KASLR bypass**: GDI handle table leaks SURFACE kernel addresses (unchanged)
2. **UAF primitive**: DestroyWindow in hook frees tagWND + WNDK without BSOD
3. **WNDK reclaim**: Separate thread reclaims freed WNDK slot
4. **SetOrClrWF write**: Writes 0x02 to reclaimed WNDK+0x12 (limited, non-exploitable)
5. **No BSOD**: Graceful handling, all operations safe

#### Alternative Approaches for Future Work

1. **Different UAF trigger**: Use a message/hook combination that gives a write to a more useful offset
2. **Type confusion via tagWND body reclaim**: If the freed tagWND is reclaimed by a new tagWND from another thread, the old kernel code corrupts the new tagWND (type confusion)
3. **POPUPMENU type confusion**: Reclaim freed WNDK with POPUPMENU — the kernel interprets POPUPMENU data as WNDK fields
4. **Different vulnerability class**: Abandon the win32k UAF and use a different kernel exploit primitive
5. **User API hook loading**: If `gihmodUserApiHook >= 0` can be achieved, the Sfn* dispatch path becomes available for arbitrary READ via TEB+0x850
