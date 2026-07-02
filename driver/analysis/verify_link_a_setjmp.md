# LINK A VERIFICATION: _setjmp writes controlled RBX to [RCX+8] and returns 0

**Target:** `_setjmp` @ `0x140408ED0` in `ntoskrnl.exe` (pid 4024)
**Date:** 2026-07-02
**Verdict:** **YES** — confirmed with exact disassembly evidence below.

---

## 1. Full Disassembly (26 instructions, 0x140408ED0 – 0x140408F5C)

```
_setjmp:
140408ED0  mov [rcx], rdx                          ; Buf->Part[0] = RDX
140408ED3  mov [rcx+8], rbx                        ; *** THE WRITE ***
140408ED7  mov [rcx+18h], rbp
140408EDB  mov [rcx+20h], rsi
140408EDF  mov [rcx+28h], rdi
140408EE3  mov [rcx+30h], r12
140408EE7  mov [rcx+38h], r13
140408EEB  mov [rcx+40h], r14
140408EEF  mov [rcx+48h], r15
140408EF3  lea r8, [rsp+arg_0]                     ; R8 = RSP+8 (stack pointer at call site)
140408EF8  mov [rcx+10h], r8                       ; Buf->Part[2] = stack pointer
140408EFC  mov r8, [rsp+0]                         ; R8 = return address from stack
140408F00  mov [rcx+50h], r8                       ; Buf->Part[10] = return address
140408F04  stmxcsr dword ptr [rcx+58h]             ; save MXCSR (4 bytes)
140408F08  movdqa xmmword ptr [rcx+60h], xmm6
140408F0D  movdqa xmmword ptr [rcx+70h], xmm7
140408F12  movdqa xmmword ptr [rcx+80h], xmm8
140408F1B  movdqa xmmword ptr [rcx+90h], xmm9
140408F24  movdqa xmmword ptr [rcx+A0h], xmm10
140408F2D  movdqa xmmword ptr [rcx+B0h], xmm11
140408F36  movdqa xmmword ptr [rcx+C0h], xmm12
140408F3F  movdqa xmmword ptr [rcx+D0h], xmm13
140408F48  movdqa xmmword ptr [rcx+E0h], xmm14
140408F51  movdqa xmmword ptr [rcx+F0h], xmm15
140408F5A  xor eax, eax                            ; EAX = 0
140408F5C  retn                                    ; return 0
```

## 2. Decompiled Pseudocode (Hex-Rays)

```c
int __cdecl setjmp(jmp_buf Buf)
{
  Buf->Part[0] = v1;           // RDX → [RCX+0x00]
  Buf->Part[1] = v2;           // RBX → [RCX+0x08]  ← THE WRITE
  Buf[1].Part[1] = v3;         // RBP → [RCX+0x18]
  Buf[2].Part[0] = v5;         // RSI → [RCX+0x20]
  Buf[2].Part[1] = v4;         // RDI → [RCX+0x28]
  Buf[3].Part[0] = v6;         // R12 → [RCX+0x30]
  Buf[3].Part[1] = v7;         // R13 → [RCX+0x38]
  Buf[4].Part[0] = v8;         // R14 → [RCX+0x40]
  Buf[4].Part[1] = v9;         // R15 → [RCX+0x48]
  Buf[1].Part[0] = &v22;       // RSP → [RCX+0x10]
  Buf[5].Part[0] = retaddr;    // ret addr → [RCX+0x50]
  LODWORD(Buf[5].Part[1]) = _mm_getcsr();  // MXCSR → [RCX+0x58]
  Buf[6]  = v10;  // XMM6  → [RCX+0x60]
  Buf[7]  = v11;  // XMM7  → [RCX+0x70]
  Buf[8]  = v12;  // XMM8  → [RCX+0x80]
  Buf[9]  = v13;  // XMM9  → [RCX+0x90]
  Buf[10] = v14;  // XMM10 → [RCX+0xA0]
  Buf[11] = v15;  // XMM11 → [RCX+0xB0]
  Buf[12] = v16;  // XMM12 → [RCX+0xC0]
  Buf[13] = v17;  // XMM13 → [RCX+0xD0]
  Buf[14] = v18;  // XMM14 → [RCX+0xE0]
  Buf[15] = v19;  // XMM15 → [RCX+0xF0]
  return 0;
}
```

## 3. Verification Checklist

| Check | Result | Evidence |
|-------|--------|----------|
| Writes RBX to [RCX+8] | **YES** | `140408ED3: mov [rcx+8], rbx` — 2nd instruction |
| RBX NOT modified before write | **YES** | Only instruction before it is `140408ED0: mov [rcx], rdx` which does NOT touch RBX. No `mov rbx, ...`, no `push rbx`, no `xchg rbx`, nothing. RBX flows directly from caller. |
| Returns 0 via xor eax,eax; retn | **YES** | `140408F5A: xor eax, eax` + `140408F5C: retn` — last two instructions |
| No prologue/epilogue | **YES** | No `push rbp`, no `sub rsp`, no frame setup. This is a leaf function — it uses the raw RSP from the call site. |

## 4. Complete Write Map — ALL [RCX+offset] Stores

22 writes total, covering 252 bytes across a 256-byte range (0x000–0x0FF):

| Offset | Value Written | Size (bytes) | Instruction Address | Instruction |
|--------|--------------|-------------|---------------------|-------------|
| 0x0000 | RDX | 8 | 140408ED0 | `mov [rcx], rdx` |
| **0x0008** | **RBX** | **8** | **140408ED3** | **`mov [rcx+8], rbx`** ← TARGET WRITE |
| 0x0010 | R8 (RSP+8) | 8 | 140408EF8 | `mov [rcx+10h], r8` |
| 0x0018 | RBP | 8 | 140408ED7 | `mov [rcx+18h], rbp` |
| 0x0020 | RSI | 8 | 140408EDB | `mov [rcx+20h], rsi` |
| 0x0028 | RDI | 8 | 140408EDF | `mov [rcx+28h], rdi` |
| 0x0030 | R12 | 8 | 140408EE3 | `mov [rcx+30h], r12` |
| 0x0038 | R13 | 8 | 140408EE7 | `mov [rcx+38h], r13` |
| 0x0040 | R14 | 8 | 140408EEB | `mov [rcx+40h], r14` |
| 0x0048 | R15 | 8 | 140408EEF | `mov [rcx+48h], r15` |
| 0x0050 | return address | 8 | 140408F00 | `mov [rcx+50h], r8` (from `[rsp+0]`) |
| 0x0058 | MXCSR | 4 | 140408F04 | `stmxcsr dword ptr [rcx+58h]` |
| 0x0060 | XMM6 | 16 | 140408F08 | `movdqa [rcx+60h], xmm6` |
| 0x0070 | XMM7 | 16 | 140408F0D | `movdqa [rcx+70h], xmm7` |
| 0x0080 | XMM8 | 16 | 140408F12 | `movdqa [rcx+80h], xmm8` |
| 0x0090 | XMM9 | 16 | 140408F1B | `movdqa [rcx+90h], xmm9` |
| 0x00A0 | XMM10 | 16 | 140408F24 | `movdqa [rcx+A0h], xmm10` |
| 0x00B0 | XMM11 | 16 | 140408F2D | `movdqa [rcx+B0h], xmm11` |
| 0x00C0 | XMM12 | 16 | 140408F36 | `movdqa [rcx+C0h], xmm12` |
| 0x00D0 | XMM13 | 16 | 140408F3F | `movdqa [rcx+D0h], xmm13` |
| 0x00E0 | XMM14 | 16 | 140408F48 | `movdqa [rcx+E0h], xmm14` |
| 0x00F0 | XMM15 | 16 | 140408F51 | `movdqa [rcx+F0h], xmm15` |

## 5. Corruption Map: RCX = gpHandleManager − 8

**Calculation (via py_eval):**
```
win32kbase_base     = 0xFFFFF96000000000
gpHandleManager     = 0xFFFFF96000250C00
RCX (= gphm - 8)    = 0xFFFFF96000250BF8
```

When `_setjmp` is called with `RCX = 0xFFFFF96000250BF8`, every `[RCX+offset]` write maps to:

| [RCX+offset] | Value | Target VA | Relative to gpHandleManager |
|-------------|-------|-----------|---------------------------|
| [RCX+0x0000] | RDX | 0xFFFFF96000250BF8 | gphm − 0x8 |
| **[RCX+0x0008]** | **RBX** | **0xFFFFF96000250C00** | **gphm + 0x0 = gpHandleManager** |
| [RCX+0x0010] | R8(RSP) | 0xFFFFF96000250C08 | gphm + 0x8 |
| [RCX+0x0018] | RBP | 0xFFFFF96000250C10 | gphm + 0x10 |
| [RCX+0x0020] | RSI | 0xFFFFF96000250C18 | gphm + 0x18 |
| [RCX+0x0028] | RDI | 0xFFFFF96000250C20 | gphm + 0x20 |
| [RCX+0x0030] | R12 | 0xFFFFF96000250C28 | gphm + 0x28 |
| [RCX+0x0038] | R13 | 0xFFFFF96000250C30 | gphm + 0x30 |
| [RCX+0x0040] | R14 | 0xFFFFF96000250C38 | gphm + 0x38 |
| [RCX+0x0048] | R15 | 0xFFFFF96000250C40 | gphm + 0x40 |
| [RCX+0x0050] | retaddr | 0xFFFFF96000250C48 | gphm + 0x48 |
| [RCX+0x0058] | MXCSR | 0xFFFFF96000250C50 | gphm + 0x50 |
| [RCX+0x0060] | XMM6 | 0xFFFFF96000250C58 | gphm + 0x58 |
| [RCX+0x0070] | XMM7 | 0xFFFFF96000250C68 | gphm + 0x68 |
| [RCX+0x0080] | XMM8 | 0xFFFFF96000250C78 | gphm + 0x78 |
| [RCX+0x0090] | XMM9 | 0xFFFFF96000250C88 | gphm + 0x88 |
| [RCX+0x00A0] | XMM10 | 0xFFFFF96000250C98 | gphm + 0x98 |
| [RCX+0x00B0] | XMM11 | 0xFFFFF96000250CA8 | gphm + 0xA8 |
| [RCX+0x00C0] | XMM12 | 0xFFFFF96000250CB8 | gphm + 0xB8 |
| [RCX+0x00D0] | XMM13 | 0xFFFFF96000250CC8 | gphm + 0xC8 |
| [RCX+0x00E0] | XMM14 | 0xFFFFF96000250CD8 | gphm + 0xD8 |
| [RCX+0x00F0] | XMM15 | 0xFFFFF96000250CE8 | gphm + 0xE8 |

**Total corrupted range:** `0xFFFFF96000250BF8` – `0xFFFFF96000250CF7` (256 bytes)
**Total bytes written:** 252 bytes (4-byte gap at 0x5C–0x5F after the dword MXCSR store)

## 6. VERDICT

**YES.** `_setjmp` at `0x140408ED0`:

1. **Writes caller-controlled RBX to [RCX+8]** — confirmed at `140408ED3: mov [rcx+8], rbx`. This is the 2nd instruction. The only instruction before it (`140408ED0: mov [rcx], rdx`) does NOT modify RBX. No prologue, no push, no mov rbx — RBX is consumed directly from the caller's register state.

2. **Returns 0** — confirmed at `140408F5A: xor eax, eax` followed by `140408F5C: retn`. Clean leaf function, no epilogue.

3. **When RCX = gpHandleManager − 8 (0xFFFFF96000250BF8)**: the `[RCX+8]` write lands exactly on `gpHandleManager` (0xFFFFF96000250C00), planting the attacker-controlled RBX value there.

4. **Collateral damage**: 21 additional writes corrupt 248 bytes surrounding gpHandleManager — from gphm−8 through gphm+0xF0. The most dangerous side-effect is `[RCX+0x00] = RDX` which writes to gphm−8, and `[RCX+0x10] = RSP` which writes the kernel stack pointer to gphm+8. The XMM writes (gphm+0x58 through gphm+0xF8) spray 160 bytes of XMM register state into the HandleManager structure.
