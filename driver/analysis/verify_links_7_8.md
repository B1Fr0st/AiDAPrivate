# Link Verification: Links 7 and 8

## LINK 7: NTFS compression TOCTOU overflow writes controlled data into adjacent EtwL

### Target Function
- **Function**: `NtfsPrepareCompressedWriteBuffer` @ `0x1c0024614` (ntfs.sys, pid 8544)
- **Caller**: `NtfsPrepareComplexBuffers` @ `0x1c0023fb8`
- **Buffer Allocator**: `NtfsAllocateCompressionBuffer` @ `0x1c0024da8`

### TOCTOU Mechanism

**First read of SCB+436 (0x1B4)**: In `NtfsPrepareComplexBuffers`, the initial read occurs at `0x1c0024073`:
```c
v101 = *(_DWORD *)(a3 + 436);  // Initial read of SCB+436
```
This value feeds into `v95`, which is passed to `NtfsAllocateCompressionBuffer` to size the compressed buffer at `*(v10 + 32)`.

**Second read of SCB+436**: Inside `NtfsPrepareCompressedWriteBuffer`, the fallback path re-reads SCB+436.

### Fallback Path Analysis (STATUS_BUFFER_TOO_SMALL = 0xC0000023)

At `0x1c00247d9`, the return from `RtlCompressBuffer` is compared:
```asm
0x1c00247d9: cmp esi, 0C0000023h       ; STATUS_BUFFER_TOO_SMALL
0x1c00247df: jz  short loc_1C0024841   ; jump to fallback
```

The fallback path at `0x1c0024841`:
```asm
0x1c0024841: mov eax, [r15+1B4h]       ; RE-READ SCB+436 (0x1B4 = 436) -- TOCTOU!
0x1c0024848: mov [rsp+arg_18], eax     ; save as FinalCompressedSize
0x1c002484f: mov r8, r13               ; r13 = v14 = v11 (input data size)
0x1c0024852: mov rdx, rdi              ; rdi = v15 (source = user write data)
0x1c0024855: mov rcx, [rbx+20h]        ; rbx+20h = v9+32 = compressed buffer base
0x1c0024859: call memmove              ; memmove(buffer, user_data, v11)
0x1c002485e: mov eax, [rsp+arg_18]     ; reload FinalCompressedSize (new SCB+436)
0x1c0024865: cmp eax, r12d             ; compare with v11
0x1c0024868: jbe short loc_1C002487E   ; skip memset if FinalCompressedSize <= v11
0x1c002486a: sub eax, r12d             ; eax = FinalCompressedSize - v11
0x1c002486d: mov r8d, eax              ; size = FinalCompressedSize - v11
0x1c0024870: mov rcx, [rbx+20h]        ; buffer base
0x1c0024874: add rcx, r13              ; buffer + v11 (offset past user data)
0x1c0024877: xor edx, edx              ; fill = 0 (ZEROS)
0x1c0024879: call memset               ; memset(buffer+v11, 0, FinalCompressedSize-v11)
```

### Critical Question: USER-CONTROLLED data or ZEROS?

**The memmove** copies `v14 = v11` bytes of user write data into the buffer starting at offset 0.
- `v11` is bounded by the **initial** SCB+436 value:
  - Path 1: `v11 = *(_DWORD *)(*(_QWORD *)(v9 + 48) + 40LL)` (MDL byte count, set during allocation)
  - Path 2: `v11 = Size` parameter from caller, where `Size <= v101 = initial_SCB+436` (see `NtfsPrepareComplexBuffers` at `0x1c0024110`)
- Since `v11 <= initial_SCB+436` and the buffer was allocated for `>= initial_SCB+436`, **memmove does NOT overflow**.

**The memset** writes `(FinalCompressedSize - v11)` bytes of ZEROS starting at `buffer + v11`.
- `FinalCompressedSize = new_SCB+436` (re-read at `0x1c0024841`)
- If `new_SCB+436 > buffer_size`, the memset writes ZEROS past the buffer boundary.
- **The overflow is ZEROS from memset, NOT user data from memmove.**

### Overflow Math (Python verified)

```
Initial SCB+436 = 0x1000, buffer allocated = 5120 bytes, new SCB+436 = 0x2000:
  memmove: 4096 bytes of USER DATA at buffer+0    -> fits in 5120 buffer
  memset:  4096 bytes of ZEROS at buffer+4096     -> writes 0x1000..0x2000
           buffer ends at 0x1400
           overflow = 3072 (0xC00) bytes of ZEROS past buffer
```

### VERDICT: LINK 7 = **NO**

The NTFS TOCTOU overflow writes **ZEROS** (from `memset`), not user-controlled data (from `memmove`). The `memmove` is bounded by `v11` which is `<= initial_SCB+436 <= buffer_size`, so it never overflows. The `memset` extends from `v11` to the re-read `FinalCompressedSize` (new SCB+436), overflowing past the allocated buffer with zero bytes only. The previous verifier's conclusion that "overflow writes ZEROS (memset)" is **correct**.

---

## LINK 8: ETW session stop calls RemoveEntryList on EtwL+344 LIST_ENTRY

### Functions Analyzed (ntoskrnl.exe, pid 4024)

| Function | Address | Size |
|---|---|---|
| `EtwpStopLoggerInstance` | `0x1407109d0` | `0x1da` |
| `EtwpStopTrace` | `0x14071177c` | `0x1dc` |
| `EtwpFlushTrace` | `0x140710e5c` | `0x135` |
| `EtwpFreeLoggerContext` | `0x14069817c` | `0x4a9` |
| `EtwpTraceMessageVa` | `0x14025cdc0` | `0x632` |

### RemoveEntryList Search

- Searched for text "RemoveEntryList" in range `0x1406b0000-0x140720000`: **0 results**
- RemoveEntryList is an inlined macro (writes Flink to Blink+0, Blink to Flink+8). No inlined LIST_ENTRY unlink patterns found in any ETW stop/flush/cleanup function.
- **EtwL+344 (0x158) is never referenced** in any stop/flush/cleanup function.

### EtwpStopLoggerInstance Analysis

Decompiled at `0x1407109d0`. Key operations:
1. `InterlockedOr(EtwL+832, 0x40)` — set stop flag
2. `EtwpUpdateLoggerGroupMasks` / `EtwpDisableTraceProviders`
3. If flag `0x4000`: acquire push lock at `v1+432`, clear entries at `v1+152+32*i`, release push lock
4. `InterlockedExchange(EtwL+336, 0)` — check if already stopped
5. Cancel timer via `ExCancelTimer`
6. **Write through pointer**: `*(EtwL+1080 -> v1, then *(v1+456) + 8*logger_id) = EtwL | 1`
7. Signal event or queue DPC
8. `EtwpSendSessionNotification`

**No RemoveEntryList. No LIST_ENTRY unlink at EtwL+344.**

### EtwpFreeLoggerContext Analysis

Decompiled at `0x14069817c`. Contains three linked-list **cleanup walks** (free each entry), NOT RemoveEntryList unlinks:
- `EtwL+112 (0x70)`: Walks list, frees each entry until sentinel at `P+112`
- `EtwL+1024 (0x400)`: Walks list, frees each entry until sentinel at `P+1024`
- `EtwL+128 (0x80)`: Head-advance walk, frees each entry

Also writes through pointer: `*(*(v1+456) + 8*logger_id) = 1` where `v1 = *(EtwL+1080)`.

**No RemoveEntryList. No LIST_ENTRY unlink at EtwL+344.**

### __fastfail(3) Check Analysis

Searched for `int 29h` (CD 29) bytes across ntoskrnl.exe. Found 30+ instances, but **none fall within any ETW stop/flush/cleanup function range**:

```
EtwpStopLoggerInstance: 0x1407109d0 - 0x140710baa -> no int 29h
EtwpStopTrace:          0x14071177c - 0x140711958 -> no int 29h
EtwpFlushTrace:         0x140710e5c - 0x140710f91 -> no int 29h
EtwpFreeLoggerContext:  0x14069817c - 0x140698625 -> no int 29h
EtwpTraceMessageVa:     0x14025cdc0 - 0x14025d3f2 -> no int 29h
```

### EtwL+280 (0x118) Dereference in EtwpTraceMessageVa

Disassembly at `0x14025d0a7`:
```asm
0x14025d0a7: mov rax, [r10+118h]    ; Read pointer at EtwL+280
0x14025d0ae: test rax, rax           ; NULL check
0x14025d0b1: jnz  loc_140439073     ; If non-NULL, go to InterlockedIncrement
```

If non-NULL:
```c
v31 = *(volatile signed __int32 **)(EtwL + 280);
v29 = _InterlockedIncrement(v31);  // Write through pointer
```

**If EtwL+280 is zeroed by NTFS overflow**: NULL check at `test rax, rax` catches it. InterlockedIncrement is **skipped**. No crash, no write.

**If EtwL+280 were controlled (NOT possible with zeros overflow)**: InterlockedIncrement would write `old_value + 1` to the controlled address. But the NTFS overflow writes ZEROS, so this path is not reachable.

### Write-Through-Pointer Paths in Stop/Cleanup

| Location | Code | If EtwL+1080 zeroed |
|---|---|---|
| `EtwpStopLoggerInstance` @ `0x140710b43` | `*(*(v1+456) + 8*logger_id) = EtwL|1` where `v1 = *(EtwL+1080)` | `v1 = 0`, deref `*(0+456)` = NULL page = **BSOD** (not controlled write) |
| `EtwpFreeLoggerContext` @ `0x1406985f0` | `*(*(v1+456) + 8*logger_id) = 1` where `v1 = *(EtwL+1080)` | Same: **BSOD** |

### VERDICT: LINK 8 = **NO**

There is **no path** where corrupting EtwL fields via the NTFS overflow leads to writing a controlled value to a controlled kernel address. Specifically:

1. **No RemoveEntryList** calls exist in any ETW stop/flush/cleanup function. EtwL+344 is never unlinked.
2. **No __fastfail(3)** checks exist in ETW stop paths (because there are no LIST_ENTRY unlinks to protect).
3. **EtwL+280** (InterlockedIncrement target) has a NULL check — zeroing it safely skips the write.
4. **EtwL+1080** (pointer used for session table write) — if zeroed, causes NULL page dereference (BSOD), not a controlled write.
5. The NTFS overflow writes **ZEROS**, not controlled data, so no EtwL pointer field can be set to an attacker-chosen address.

The best alternative write path (EtwL+280 -> InterlockedIncrement) is blocked because the overflow zeroes the pointer, and the NULL check catches it. The only exploitable consequence of the NTFS zeros overflow into EtwL is a **denial-of-service (BSOD)** via NULL pointer dereference, not a controlled write primitive.
