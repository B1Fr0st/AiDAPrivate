# AFD UAF RIP Control → 8-Byte Write Primitive Analysis

## Date: 2026-07-02
## Target: ntoskrnl.exe (Windows 11 x64) + afd.sys
## IDA Instances: ntoskrnl.exe pid=4024, afd.sys pid=18576

---

## 1. THE PRIMITIVE

`AfdTLStartBufferedVcSend` in afd.sys performs an indirect call:

```
func_ptr = *(QWORD*)(*(QWORD*)(conn+0x18) + 0x18)
func_ptr(rcx, rdx)
```

### Calling Convention (confirmed from afd.sys disassembly at 0x1c004fc50)

| Register | Source | Control |
|----------|--------|---------|
| **rcx** | `conn[2]` = `*(qword*)(conn+0x10)` | **FULLY CONTROLLED** |
| **rdx** | `&v15` (kernel stack buffer pointer) | Stack ptr, NOT directly controlled |
| **r8** | Leftover from AFDETW_TRACEBSEND | NOT controlled |
| **r9** | Leftover from AFDETW_TRACEBSEND | NOT controlled |

- Call goes through `__guard_dispatch_icall_fptr` (CFG-protected) — target must be CFG-valid
- All exported ntoskrnl functions are CFG-valid

### Stack Buffer v15 Contents (at rdx)

The v15 buffer is zeroed by memset, then populated with AFD arguments:

| Offset | Value | Control |
|--------|-------|---------|
| [rdx+0x00] | AfdTLBufferedSendComplete (afd.sys func ptr) | Fixed |
| [rdx+0x08] | a5 (5th arg to AfdTLStartBufferedVcSend) | **User-controlled** |
| [rdx+0x10] | a4 (4th arg, DWORD) | **User-controlled** |
| [rdx+0x18] | a2 (2nd arg) | **User-controlled** |
| [rdx+0x20] | a5 (5th arg, duplicate) | **User-controlled** |
| [rdx+0x28] | a3 (3rd arg) | **User-controlled** |
| [rdx+0x30] | a5 (5th arg, duplicate) | **User-controlled** |
| [rdx+0x38..0x48] | 0 (zeroed) | Zero |

---

## 2. STATIC TABLE ANALYSIS

### HalDispatchTable (0x140c00a60)

| Offset | Address | Function | Useful? |
|--------|---------|----------|---------|
| +0x00 | 0x0000000000000004 | (size/count field) | N/A |
| +0x08 | 0x0000000140726060 | xHalSetSystemInformation | No (stub) |
| +0x10 | 0x0000000140726060 | xHalSetSystemInformation | No (stub) |
| **+0x18** | **0x0000000140725F70** | **xHalAllocatePmcCounterSet** | **NO — 6-byte stub returning STATUS_NOT_IMPLEMENTED** |
| +0x20 | 0x0000000000000000 | NULL | No |
| +0x28 | 0x000000014088D9F0 | (unknown) | Not checked |
| +0x30 | 0x000000014088DBB0 | (unknown) | Not checked |
| +0x38 | 0x000000014088DE30 | (unknown) | Not checked |

### HalPrivateDispatchTable (0x140c00590)

| Offset | Address | Function | Useful? |
|--------|---------|----------|---------|
| +0x00 | 0x0000000000000033 | (size = 51) | N/A |
| +0x08 | 0x00000001402526A0 | HalSystemVectorDispatchEntry | No (3-byte stub) |
| +0x10 | 0x00000001402526A0 | HalSystemVectorDispatchEntry | No (3-byte stub) |
| **+0x18** | **0x0000000140990320** | **xHalPowerEarlyRestore** | **NO — 3-byte stub** |
| +0x20 | 0x0000000140725F70 | xHalAllocatePmcCounterSet | No (stub) |
| +0x28 | 0x0000000000000000 | NULL | No |
| +0x30 | 0x0000000140990310 | xHalDpMaskLevelTriggeredInterrupts | No (6-byte stub) |
| +0x38 | 0x00000001404F1420 | xHalTranslateBusAddress | No (30-byte stub) |
| +0x40 | 0x00000001404F1420 | xHalTranslateBusAddress | No (stub) |
| +0x48 | 0x0000000140364E50 | xHalHaltSystem | No (4-byte stub) |
| +0x50 | 0x0000000000000000 | NULL | No |
| +0x58 | 0x0000000000000000 | NULL | No |
| +0x60 | 0x00000001403CFD40 | xKdEnumerateDebuggingDevices | No (6-byte stub) |
| +0x68 | 0x00000001403CFD40 | xKdEnumerateDebuggingDevices | No (stub) |
| +0x70 | 0x00000001403CFD40 | xKdEnumerateDebuggingDevices | No (stub) |
| +0x78 | 0x00000001402526A0 | HalSystemVectorDispatchEntry | No (stub) |
| +0x80 | 0x000000014039A2F0 | xHalTimerWatchdogStop | No (3-byte stub) |
| +0x88 | 0x0000000140364E70 | xHalVectorToIDTEntry | No (3-byte stub) |

### Conclusion on Static Tables

**Neither HalDispatchTable nor HalPrivateDispatchTable has a useful function at +0x18.** All entries are HAL stubs. Must use **kernel pool spray** to create a fake table where +0x18 contains the desired function pointer.

---

## 3. CANDIDATE WRITE GADGETS

### CANDIDATE 1: KeInitializeDpc — 8-BYTE WRITE OF RDX (STACK PTR)

**Address:** 0x1403446c0 | **Size:** 0x19 (25 bytes) | **CFG-valid:** Yes (exported)

**Disassembly:**
```asm
xor eax, eax
mov dword ptr [rcx], 113h      ; [rcx+0x00] = 0x113 (DWORD, fixed)
mov [rcx+38h], rax             ; [rcx+0x38] = 0 (QWORD, zero)
mov [rcx+10h], rax             ; [rcx+0x10] = 0 (QWORD, zero)
mov [rcx+18h], rdx             ; [rcx+0x18] = rdx (QWORD — 8-BYTE WRITE!)
mov [rcx+20h], r8              ; [rcx+0x20] = r8 (QWORD, uncontrolled)
retn
```

**In our context:** rcx=controlled, rdx=kernel stack ptr to v15 buffer

**Writes:**
| Target | Value | Size | Notes |
|--------|-------|------|-------|
| [rcx+0x00] | 0x113 | DWORD | Fixed value |
| [rcx+0x10] | 0 | QWORD | Zero write |
| **[rcx+0x18]** | **rdx** | **QWORD** | **8-byte write of kernel stack pointer** |
| [rcx+0x20] | r8 | QWORD | Uncontrolled |
| [rcx+0x38] | 0 | QWORD | Zero write |

**Value written to [rcx+0x18]:** rdx = kernel stack pointer to v15 buffer containing:
- AfdTLBufferedSendComplete at [rdx+0x00]
- User-controlled a5 at [rdx+0x08]
- User-controlled a2 at [rdx+0x18]

**Assessment:** Writes a kernel stack address (pointing to partially controlled data) to [rcx+0x18]. The stack buffer contains controlled data at known offsets. If the written pointer is later dereferenced as a structure, the attacker controls fields within it. However, the stack address is ephemeral (valid only during AfdTLStartBufferedVcSend's execution).

**Best for:** Overwriting a pointer field (like pvScan0) with a pointer to controlled kernel stack data, enabling a second-stage primitive that reads through the overwritten pointer.

---

### CANDIDATE 2: KeInitializeTimerEx — 8-BYTE ZERO WRITE (CLEANEST)

**Address:** 0x140341af0 | **Size:** 0x24 (36 bytes) | **CFG-valid:** Yes (exported)

**Disassembly:**
```asm
xor r8d, r8d
lea rax, [rcx+8]
add dl, 8
mov [rcx], r8                 ; [rcx+0x00] = 0 (QWORD)
mov [rcx], dl                 ; [rcx+0x00] = Type+8 (BYTE, overwrites low byte)
mov [rax+8], rax              ; [rcx+0x10] = rcx+8 (QWORD, self-ref)
mov [rax], rax                ; [rcx+0x08] = rcx+8 (QWORD, self-ref)
mov [rcx+18h], r8             ; [rcx+0x18] = 0 (QWORD — 8-BYTE ZERO WRITE!)
mov [rcx+3Ch], r8d            ; [rcx+0x3C] = 0 (DWORD)
mov [rcx+38h], r8w            ; [rcx+0x38] = 0 (WORD)
retn
```

**In our context:** rcx=controlled, rdx=Type(uncontrolled, but only affects [rcx+0x00] byte)

**Writes:**
| Target | Value | Size | Notes |
|--------|-------|------|-------|
| [rcx+0x00] | 0, then byte | QWORD+BYTE | First zeroed, then low byte set to Type+8 |
| [rcx+0x08] | rcx+8 | QWORD | Self-referencing pointer |
| [rcx+0x10] | rcx+8 | QWORD | Self-referencing pointer |
| **[rcx+0x18]** | **0** | **QWORD** | **8-byte zero write** |
| [rcx+0x38] | 0 | WORD | Zero |
| [rcx+0x3C] | 0 | DWORD | Zero |

**Assessment:** Clean 8-byte zero write to [rcx+0x18]. No locks, no IRQL changes, no list walks, no function calls. Side effects corrupt [rcx+0x00..0x10] (24 bytes before target) and [rcx+0x38..0x3F] (8 bytes at +0x38). The self-referencing pointers at [rcx+0x08] and [rcx+0x10] write rcx+8 (a kernel address), which could be problematic.

**Best for:** Zeroing out a target QWORD field. Side effects must be tolerable or the target must be in a region where corrupting 48 bytes around [rcx] is acceptable.

---

### CANDIDATE 3: KeInitializeDeviceQueue — ALT 8-BYTE ZERO WRITE

**Address:** 0x1403793b0 | **Size:** 0x23 (35 bytes) | **CFG-valid:** Yes (exported)

**Disassembly:**
```asm
lea rax, [rcx+8]
mov dword ptr [rcx], 280014h  ; [rcx+0x00] = 0x280014 (DWORD, fixed)
mov [rax+8], rax              ; [rcx+0x10] = rcx+8 (QWORD, self-ref)
mov [rax], rax                ; [rcx+0x08] = rcx+8 (QWORD, self-ref)
and qword ptr [rcx+18h], 0    ; [rcx+0x18] = 0 (QWORD — 8-BYTE ZERO WRITE!)
mov byte ptr [rcx+20h], 0     ; [rcx+0x20] = 0 (BYTE)
and qword ptr [rcx+20h], 0FFh ; [rcx+0x20] = 0xFF (QWORD via AND)
retn
```

**Writes:**
| Target | Value | Size | Notes |
|--------|-------|------|-------|
| [rcx+0x00] | 0x280014 | DWORD | Fixed value |
| [rcx+0x08] | rcx+8 | QWORD | Self-referencing pointer |
| [rcx+0x10] | rcx+8 | QWORD | Self-referencing pointer |
| **[rcx+0x18]** | **0** | **QWORD** | **8-byte zero write** |
| [rcx+0x20] | 0xFF | QWORD | Via AND mask |

**Assessment:** Similar to KeInitializeTimerEx but different side effects. The `and qword ptr [rcx+20h], 0FFh` is a read-modify-write that preserves only the low byte — could be problematic.

---

### CANDIDATE 4: SeSetAccessStateGenericMapping — 16-BYTE CONTROLLED COPY

**Address:** 0x140650800 | **Size:** 0x0D (13 bytes) | **CFG-valid:** Yes (exported)

**Disassembly:**
```asm
mov rax, [rcx+48h]            ; rax = *(rcx+0x48) — pointer dereference
movups xmm0, xmmword ptr [rdx] ; xmm0 = 16 bytes from [rdx] (v15 stack buffer)
movdqu xmmword ptr [rax+8], xmm0 ; [*(rcx+0x48) + 8] = 16 bytes from [rdx]
retn
```

**In our context:** rcx=controlled, rdx=stack ptr to v15

**Operation:**
1. Reads a pointer from [rcx+0x48]
2. Reads 16 bytes from [rdx] (the v15 stack buffer)
3. Writes those 16 bytes to [*([rcx+0x48]) + 8]

**Written data (16 bytes from v15):**
- Bytes 0-7: AfdTLBufferedSendComplete (NOT controlled — afd.sys function ptr)
- Bytes 8-15: a5 (CONTROLLED — 5th arg to AfdTLStartBufferedVcSend)

**Write target:** `*(*(rcx+0x48) + 8)` — double dereference through rcx

**Assessment:** This is a 16-byte write where 8 bytes (the second QWORD) are user-controlled. However, it requires a double dereference: [rcx+0x48] must be a valid pointer, and that pointer + 8 must be the target address. This requires setting up a pointer chain in controlled kernel memory.

**Best for:** Situations where you have a controlled pointer chain and want to write 16 bytes (8 controlled + 8 fixed) to a specific target.

---

### CANDIDATE 5: KeSetEvent — 4-BYTE ONLY (LO's original assumption was WRONG)

**Address:** 0x1402c3c30 | **Size:** 0x511 (1297 bytes) | **CFG-valid:** Yes (exported)

**LO's assumption:** KeSetEvent writes to [rcx+0x18] (KEVENT.Header.SignalState)
**REALITY:** KeSetEvent writes to **[rcx+0x04]** (SignalState at DISPATCHER_HEADER +0x04)

**Confirmed from disassembly:**
```asm
mov esi, [rbx+4]              ; read old SignalState (rbx = rcx = Event)
mov dword ptr [rbx+4], 1      ; Event->Header.SignalState = 1 (DWORD, 4 bytes)
```

**KEVENT struct layout (confirmed from IDA type info):**
```
_KEVENT (size = 24 bytes / 0x18):
  +0x00: DISPATCHER_HEADER.Header (union, 4 bytes) — Type/Absolute/Size/Inserted
  +0x04: SignalState (LONG, 4 bytes) ← WRITTEN BY KeSetEvent
  +0x08: WaitListHead.Flink (QWORD)
  +0x10: WaitListHead.Blink (QWORD)
```

**Assessment:** Only a 4-byte DWORD write of value 1 to [rcx+0x04]. Complex function with IRQL raises, lock acquisitions, and WaitListHead traversal — likely crashes if [rcx+0x08] is not a valid self-referencing list. NOT suitable for an 8-byte write.

---

## 4. EXPLOIT MATH: Targeting SURFACE+0x50 (pvScan0)

Hypothetical SURFACE base = 0xFFFFF90123450000
Target (pvScan0) = 0xFFFFF90123450050

### KeInitializeDpc (writes rdx to [rcx+0x18])

```
rcx = TARGET - 0x18 = 0xFFFFF90123450050 - 0x18 = 0xFFFFF90123450038
→ [0xFFFFF90123450050] = rdx (kernel stack ptr to controlled v15 buffer)

Side effects:
  [0xFFFFF90123450038] = 0x113         (DWORD, corrupts SURFACE+0x38)
  [0xFFFFF90123450048] = 0             (QWORD, corrupts SURFACE+0x48)
  [0xFFFFF90123450050] = rdx           (QWORD, WRITES TO pvScan0!)
  [0xFFFFF90123450058] = r8            (QWORD, corrupts SURFACE+0x58)
  [0xFFFFF90123450070] = 0             (QWORD, corrupts SURFACE+0x70)
```

### KeInitializeTimerEx (writes 0 to [rcx+0x18])

```
rcx = TARGET - 0x18 = 0xFFFFF90123450050 - 0x18 = 0xFFFFF90123450038
→ [0xFFFFF90123450050] = 0 (8-byte zero write)

Side effects:
  [0xFFFFF90123450038] = 0 + byte      (QWORD+BYTE, corrupts SURFACE+0x38)
  [0xFFFFF90123450040] = 0xFFFFF90123450040 (self-ref, corrupts SURFACE+0x40)
  [0xFFFFF90123450048] = 0xFFFFF90123450040 (self-ref, corrupts SURFACE+0x48)
  [0xFFFFF90123450050] = 0             (QWORD, ZEROS pvScan0!)
  [0xFFFFF90123450070] = 0             (WORD, corrupts SURFACE+0x70)
  [0xFFFFF90123450074] = 0             (DWORD, corrupts SURFACE+0x74)
```

### KeSetEvent (writes 1 to [rcx+0x04] — CORRECTED from LO's [rcx+0x18])

```
LO's WRONG calc:  rcx = TARGET - 0x18 = 0xFFFFF90123450038
CORRECT calc:     rcx = TARGET - 0x04 = 0xFFFFF9012345004C
→ [0xFFFFF90123450050] = 1 (DWORD, 4 bytes only — NOT 8 bytes)

Crash risk: KeSetEvent reads [rcx+0x08] (WaitListHead.Flink) and traverses the list.
  [0xFFFFF90123450054] must be a valid self-referencing LIST_ENTRY or crash.
```

### SeSetAccessStateGenericMapping (16-byte copy to double-deref target)

```
To write to SURFACE+0x50:
  Need: *(*(rcx+0x48) + 8) = SURFACE+0x50
  So: *(rcx+0x48) must point to a QWORD = SURFACE+0x48
  And: rcx+0x48 must be a valid pointer to that QWORD

Written data (16 bytes from rdx):
  Bytes 0-7:  AfdTLBufferedSendComplete (NOT controlled)
  Bytes 8-15: a5 (CONTROLLED)
```

---

## 5. RECOMMENDATION

### Best 8-Byte Write Gadget: KeInitializeDpc (0x1403446c0)

**Why:** It's the only candidate that writes a non-zero, non-self-referencing 8-byte value to [rcx+0x18]. The value written (rdx) is a kernel stack pointer to a buffer containing user-controlled data. This enables a two-stage exploit:

1. **Stage 1 — Stack pointer write:** Use KeInitializeDpc to write the v15 stack pointer to pvScan0 (SURFACE+0x50). Now pvScan0 points to the v15 stack buffer.

2. **Stage 2 — Controlled read/write through pvScan0:** Since pvScan0 now points to controlled data on the kernel stack, any GDI operation that reads/writes through pvScan0 will access the v15 buffer contents, which include user-controlled values (a2, a3, a4, a5).

**Setup:**
- Spray kernel pool with a fake function table where +0x18 = 0x1403446c0 (KeInitializeDpc)
- Set conn+0x18 = address of sprayed fake table
- Set conn+0x10 = SURFACE + 0x38 (so rcx = SURFACE + 0x38, writes to [SURFACE + 0x50])
- Trigger AfdTLStartBufferedVcSend

**Caveats:**
- Side effects corrupt SURFACE+0x38 (DWORD 0x113), SURFACE+0x48 (QWORD 0), SURFACE+0x58 (QWORD r8), SURFACE+0x70 (QWORD 0)
- The v15 stack buffer is only valid during AfdTLStartBufferedVcSend execution — race window
- r8 value at [SURFACE+0x58] is uncontrolled (leftover from AFDETW_TRACEBSEND)

### Alternative: KeInitializeTimerEx (0x140341af0) for 8-byte zero write

If the goal is specifically to zero pvScan0 (rather than write a controlled pointer):
- Same rcx calculation: rcx = SURFACE + 0x38
- Cleaner execution (no r8 dependency, no uncontrolled writes at +0x20)
- But writes 0, not a controlled value

---

## 6. FUNCTION REFERENCE TABLE

| Function | Address | Size | Write Target | Write Value | Size | CFG |
|----------|---------|------|-------------|-------------|------|-----|
| KeInitializeDpc | 0x1403446c0 | 0x19 | [rcx+0x18] | rdx (stack ptr) | QWORD | Yes |
| KeInitializeTimerEx | 0x140341af0 | 0x24 | [rcx+0x18] | 0 | QWORD | Yes |
| KeInitializeDeviceQueue | 0x1403793b0 | 0x23 | [rcx+0x18] | 0 | QWORD | Yes |
| SeSetAccessStateGenericMapping | 0x140650800 | 0x0D | [*([rcx+0x48])+8] | [rdx] (16 bytes) | 16 bytes | Yes |
| KeSetEvent | 0x1402c3c30 | 0x511 | [rcx+0x04] | 1 | DWORD | Yes |
| KeInitializeEvent | 0x1402d40a0 | 0x1B | [rcx+0x08],[rcx+0x10] | rcx+8 (self-ref) | QWORD | Yes |
| KeInitializeSemaphore | 0x1402d6db0 | 0x1A | [rcx+0x08],[rcx+0x10] | rcx+8 (self-ref) | QWORD | Yes |
| KeResetEvent | 0x140344c50 | 0x99 | [rcx+0x04] | 0 | DWORD | Yes |

---

## 7. KDPC STRUCT LAYOUT (confirmed from IDA)

```
_KDPC (size = 64 bytes / 0x40):
  +0x00: union { Type, Importance, Number } (4 bytes)
  +0x08: DpcListEntry (SINGLE_LIST_ENTRY, 8 bytes)
  +0x10: ProcessorHistory (KAFFINITY, 8 bytes)
  +0x18: DeferredRoutine (PKDEFERRED_ROUTINE, 8 bytes) ← WRITTEN BY KeInitializeDpc
  +0x20: DeferredContext (PVOID, 8 bytes)
  +0x28: SystemArgument1 (PVOID, 8 bytes)
  +0x30: SystemArgument2 (PVOID, 8 bytes)
  +0x38: DpcData (PVOID, 8 bytes)
```

## 8. KTIMER STRUCT LAYOUT (confirmed from IDA)

```
_KTIMER (size = 64 bytes / 0x40):
  +0x00: Header (DISPATCHER_HEADER, 24 bytes)
  +0x18: DueTime (ULARGE_INTEGER, 8 bytes) ← ZEROED BY KeInitializeTimerEx
  +0x20: TimerListEntry (LIST_ENTRY, 16 bytes)
  +0x30: Dpc (PKDPC*, 8 bytes)
  +0x38: Processor (USHORT, 2 bytes)
  +0x3A: TimerType (USHORT, 2 bytes)
  +0x3C: Period (ULONG, 4 bytes)
```

## 9. KEVENT STRUCT LAYOUT (confirmed from IDA)

```
_KEVENT (size = 24 bytes / 0x18):
  +0x00: Header (DISPATCHER_HEADER, 24 bytes)
    +0x00: union { Type, Absolute, Size, Inserted } (4 bytes)
    +0x04: SignalState (LONG, 4 bytes) ← WRITTEN BY KeSetEvent (value = 1)
    +0x08: WaitListHead (LIST_ENTRY, 16 bytes)
      +0x08: Flink (QWORD)
      +0x10: Blink (QWORD)
```

---

## 10. CORRECTION TO LO's ORIGINAL ASSUMPTION

**LO assumed:** KeSetEvent writes to [rcx+0x18] (KEVENT.Header.SignalState)
**Reality:** SignalState is at DISPATCHER_HEADER +0x04, NOT +0x18

LO's proposed calc: `rcx = target_addr - 0x18`
Corrected calc: `rcx = target_addr - 0x04`

But KeSetEvent is only a 4-byte write anyway. For a true 8-byte write, use KeInitializeDpc or KeInitializeTimerEx instead.
