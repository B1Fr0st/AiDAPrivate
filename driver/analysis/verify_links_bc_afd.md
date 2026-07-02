# LINK B & LINK C Verification — afd.sys (pid 18576)

## LINK B: AfdCloseConnection reads conn+0x10 and conn+0x18 from spray (NOT overwritten before read)

### Function: AfdCloseConnection @ 0x1C0056D6C

### 0x20000 Flag Path Trace

The 0x20000 flag is checked at conn+0x04 (high DWORD of the first QWORD):

```
0x1C0056D81: mov r8d, [rcx+4]            ; read conn+0x04 (flags DWORD)
0x1C0056D88: mov rdi, rcx                ; rdi = conn (base of spray object)
0x1C0056D94: bt r8d, 11h                 ; test bit 17 (0x20000)
0x1C0056D99: jnb loc_1C00654E6           ; if NOT set -> other path (refresh-check)
0x1C0056D9F: test [rdi+4], 20000h        ; re-confirm 0x20000
0x1C0056DA6: jz loc_1C006562F            ; if NOT set -> AfdQueueWorkItem path
```

### Critical Reads of conn+0x10 and conn+0x18

When 0x20000 IS set, the code enters the close-and-dereference path:

```
0x1C0056DAC: cmp qword ptr [rdi+10h], 0  ; *** FIRST READ conn+0x10 ***
0x1C0056DB1: jz  loc_1C0056E19           ; if zero -> AfdFreeConnectionEx (skip)
0x1C0056DB3: lea rbx, [rdi+48h]          ; rbx = &conn+0x48 (list head)
0x1C0056DB7: mov rcx, [rbx]              ; read conn+0x48 (list Flink)
0x1C0056DBA: cmp rcx, rbx                ; list empty? (Flink == &head)
0x1C0056DBD: jnz loc_1C00655FA           ; if not empty -> list cleanup loop
; --- list empty path (conn+0x48 points to self) ---
0x1C0056DC3: mov rax, [rdi+8]            ; read conn+0x08 (endpoint object)
0x1C0056DC7: mov rbx, [rax+0F8h]         ; read [conn+0x08]+0xF8 (transport ptr)
0x1C0056DCE: lock xadd [rbx+10h], esi    ; WRITE +2 to TRANSPORT+0x10 (NOT conn!)
;   ^^^ esi=2 (set at 0x1C0056D8B: mov esi, 2)
0x1C0056DD3: mov rcx, [rdi+10h]          ; *** SECOND READ conn+0x10 (call arg1) ***
0x1C0056DD7: lea rax, AfdTLCloseConnectionHandleComplete
0x1C0056DDE: mov [rsp+var_18], rax       ; WRITE to STACK (not conn)
0x1C0056DE3: lea rdx, [rsp+var_18]
0x1C0056DE8: mov rax, [rdi+18h]          ; *** READ conn+0x18 (function table ptr) ***
0x1C0056DEC: mov [rsp+var_10], rdi       ; WRITE to STACK (not conn)
0x1C0056DF1: mov rax, [rax]              ; deref [conn+0x18] -> actual func ptr
0x1C0056DF4: call __guard_dispatch_icall ; indirect call (CFG-protected)
0x1C0056DFA: mov rcx, rbx               ; rcx = transport ptr
0x1C0056DFD: call AfdTlDereferenceTransport
```

### Write Audit: Does ANYTHING write conn+0x10 or conn+0x18 before reads?

| Address | Instruction | Type | Target |
|---------|------------|------|--------|
| 0x1C0056D81 | `mov r8d, [rcx+4]` | READ | conn+0x04 |
| 0x1C0056D9F | `test [rdi+4], 20000h` | READ | conn+0x04 |
| 0x1C0056DAC | `cmp [rdi+10h], 0` | **READ** | **conn+0x10** |
| 0x1C0056DB7 | `mov rcx, [rbx]` | READ | conn+0x48 |
| 0x1C0056DC3 | `mov rax, [rdi+8]` | READ | conn+0x08 |
| 0x1C0056DC7 | `mov rbx, [rax+0F8h]` | READ | [conn+0x08]+0xF8 |
| 0x1C0056DCE | `lock xadd [rbx+10h], esi` | **WRITE** | **TRANSPORT+0x10** (NOT conn!) |
| 0x1C0056DD3 | `mov rcx, [rdi+10h]` | **READ** | **conn+0x10** |
| 0x1C0056DDE | `mov [rsp+var_18], rax` | WRITE | STACK |
| 0x1C0056DE8 | `mov rax, [rdi+18h]` | **READ** | **conn+0x18** |
| 0x1C0056DEC | `mov [rsp+var_10], rdi` | WRITE | STACK |

**Writes to conn+0x10 before its first read (0x1C0056DAC): 0**
**Writes to conn+0x18 before its read (0x1C0056DE8): 0**

The only intermediate write is `lock xadd [rbx+10h], esi` at 0x1C0056DCE, which writes to **TRANSPORT+0x10** (where rbx = [conn+0x08]+0xF8), a completely separate object. Stack writes at 0x1C0056DDE and 0x1C0056DEC do not touch the connection object.

### List Loop Path (0x1C00655FA) — Also Does NOT Touch conn+0x10/0x18

If the list at conn+0x48 is NOT empty, the loop at 0x1C00655FA runs:
```
0x1C0065609: mov [rbx], rax     ; WRITE to conn+0x48 (list head Flink only)
0x1C006560C: mov [rax+8], rbx   ; WRITE to list entry+0x08 (Blink)
0x1C0065615: and [rcx+48h], ax  ; WRITE to list entry+0x48
0x1C006561D: call AfdReturnBuffer ; called with list entry + process, NOT conn ptr
```
No writes to conn+0x10 or conn+0x18 in the loop either.

### VERDICT LINK B: **YES**

conn+0x10 and conn+0x18 are read **directly from the spray** without being overwritten. The exact read instructions are:
- `0x1C0056DAC: cmp qword ptr [rdi+10h], 0` — first read of conn+0x10
- `0x1C0056DD3: mov rcx, [rdi+10h]` — second read of conn+0x10 (call argument)
- `0x1C0056DE8: mov rax, [rdi+18h]` — read of conn+0x18 (function table pointer)

Zero writes to conn+0x10 or conn+0x18 occur before these reads. The spray values are consumed as-is.

---

## LINK C: AfdTlDereferenceTransport returns cleanly with zeroed fake transport

### Function: AfdTlDereferenceTransport @ 0x1C0003970

### Full Disassembly

```
0x1C0003970: sub rsp, 28h
0x1C0003974: lea rax, WskTdiTransport        ; rax = 0x1C002A0D0 (afd.sys .data)
0x1C000397B: cmp rcx, rax                     ; compare our transport ptr with global
0x1C000397E: jz  short loc_1C0003993          ; if EQUAL -> skip to clean return
0x1C0003980: mov eax, 0FFFFFFFEh              ; eax = -2 (signed)
0x1C0003985: lock xadd [rcx+10h], eax         ; old=[rcx+0x10], [rcx+0x10]+=(-2), eax=old
0x1C000398A: cmp eax, 3                        ; was old value == 3?
0x1C000398D: jz  loc_1C000D2D4                ; if YES -> cleanup path
0x1C0003993: add rsp, 28h                     ; *** CLEAN RETURN ***
0x1C0003997: retn

; Cleanup path (ONLY if old == 3):
0x1C000D2D4: mov rcx, [rcx+40h]               ; read transport+0x40 (NmrBindingHandle)
0x1C000D2D8: call __imp_NmrClientDetachProviderComplete
0x1C000D2E5: jmp loc_1C0003993                ; jump back to clean return
```

### Fields Accessed on the Transport Object

| Field | Offset | Access | Condition |
|-------|--------|--------|-----------|
| Transport ptr | rcx | Compared with WskTdiTransport (0x1C002A0D0) | Always |
| Reference count | +0x10 | `lock xadd -2` (read+write) | Only if ptr != WskTdiTransport |
| NmrBindingHandle | +0x40 | Read | ONLY if old refcount == 3 |

No other fields are accessed. No other code paths exist.

### Math: Reference Count with Zeroed Transport

Computed via py_eval:

```
Initial [transport+0x10] = 0  (zeroed buffer)

Step 1 — AfdCloseConnection @ 0x1C0056DCE:
  lock xadd [transport+0x10], esi  (esi = 2)
  old = 0, new = 0 + 2 = 2

Step 2 — AfdTlDereferenceTransport @ 0x1C0003985:
  lock xadd [transport+0x10], eax  (eax = 0xFFFFFFFE = -2)
  old = 2, new = 2 + (-2) = 0

Step 3 — Check at 0x1C000398A:
  cmp eax, 3  →  2 == 3?  →  FALSE
  NmrClientDetachProviderComplete NOT called
```

### Pointer Comparison: WskTdiTransport vs Fake Transport

- WskTdiTransport VA: `0x00000001C002A0D0` (afd.sys .data segment)
- Fake transport: kernel pool allocation (address `0xFFFF8000xxxxxxxx` range)
- These will NEVER be equal → the `jz` at 0x1C000397E is NOT taken → enters xadd path

### What If All Fields Are Zero?

- `[transport+0x10]` = 0 → after +2 = 2 → after -2 = 0, xadd returns old=2
- `[transport+0x40]` = 0 → **NEVER accessed** (old=2 ≠ 3, cleanup path skipped)
- All other zeroed fields → **NEVER accessed**
- No NULL pointer dereferences, no invalid memory access
- Function reaches `0x1C0003993: add rsp, 28h; retn` — clean return

### VERDICT LINK C: **YES**

AfdTlDereferenceTransport returns cleanly with a zeroed fake transport. The reference count math is:
- Start: 0 → AfdCloseConnection +2 → 2 → AfdTlDereferenceTransport -2 → old=2, new=0
- old=2 ≠ 3 → cleanup path (NmrClientDetachProviderComplete) is **NOT taken**
- Only fields accessed: rcx (pointer compare) and [rcx+0x10] (refcount xadd)
- [rcx+0x40] is never touched. No crash. Clean `retn`.

---

## Summary

| Link | Question | Verdict | Key Evidence |
|------|----------|---------|--------------|
| B | conn+0x10 and conn+0x18 read from spray without overwrite? | **YES** | 0 writes to conn+0x10/0x18 before reads; only write is to TRANSPORT+0x10 at 0x1C0056DCE |
| C | AfdTlDereferenceTransport returns cleanly with zeroed transport? | **YES** | refcount: 0→2→0, old=2≠3, cleanup skipped, only [rcx+0x10] accessed, clean retn |
