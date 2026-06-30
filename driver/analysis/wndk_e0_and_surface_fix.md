# WNDK+0xE0 and SURFACE Address Fix Analysis

## Target: win32kfull.sys (Windows 10 22H2, build 19045)
## IDA imagebase: 0x1C0000000

---

## Task 1: What Writes Non-Zero to WNDK+0xE0

### Methodology
Searched all `mov [reg+0E0h], reg64/imm` instructions in win32kfull.sys. Found 50+ writes
across the binary. Filtered for WNDK writes by checking if the base register was loaded from
`[reg+0x28]` (the tagWND->pwndk access pattern: `a1[5]` in decompiled code = `[tagWND+0x28]`).

### Results: Writes to [pwndk+0xE0] in win32kfull.sys

| Address | Function | Instruction | Value Written |
|---------|----------|-------------|---------------|
| 0x1C0075DE8 | xxxCreateWindowEx | `mov [rcx+0E0h], rax` | a17 (17th parameter, usually 0) |
| 0x1C0076B3D | xxxCreateWindowEx | `mov qword ptr [rdi+0E0h], 0` | 0 (DPI boundary path) |
| 0x1C0051AB0+ | SfnNCDESTROY | `*(_QWORD *)(a1[5] + 224) = 0` | 0 (post-callback zeroing) |

**NO other function in win32kfull.sys writes a non-zero value to [pwndk+0xE0].**

### What is pwndk+0xE0?

The field at pwndk+0xE0 (offset 224) is a **RECT** (window coordinates), NOT a kernel pointer.

Evidence from xxxCreateWindowEx at 0x1C0076B3D:
```asm
mov qword ptr [rdi+0E0h], 0          ; zero the RECT
lea r8, [rdi+0E0h]                    ; &pwndk[0xE0] as RECT output
lea rdx, [rsp+var_378]               ; source rect
mov rcx, r12                          ; window
call LogicalToPhysicalInPlaceRectWithSubpixel  ; fills pwndk[0xE0] with physical coords
```

The 16-byte RECT at pwndk+0xE0 (left, top at 0xE0; right, bottom at 0xE8) stores the window's
physical coordinates for per-monitor DPI transitions. The 8-byte qword at 0xE0 is (top << 32 | left)
— a pair of small integers, never a kernel address.

### What is a17 in NtUserCreateWindowEx?

NtUserCreateWindowEx (0x1C00BF1E0) passes a17 directly to xxxCreateWindowEx:
```c
Window = xxxCreateWindowEx(v33, v34, v41, v42, a5, a6, a7, a8, a9,
                            v22, v64, a12, a13, a14, a15, a16, a17);
```

a17 is the 17th parameter (index 16). It arrives from the user32.dll CreateWindowEx wrapper
and represents an internal creation parameter. For normal CreateWindowEx calls, a17 = 0.
a17 is ONLY used once in xxxCreateWindowEx — to write to [pwndk+0xE0] at 0x1C0075DE8.

### Does GetDC write to WNDK+0xE0?

**No.** NtUserGetDCEx (0x1C0114AB0) calls `_GetDCEx(pwnd, hrgn, flags)`. _GetDCEx is imported
from win32kbase.sys (not in win32kfull.sys). xxxBeginPaint (0x1C007D854) calls _GetDCEx but
does not write to [pwndk+0xE0] itself. Since _GetDCEx is in another module, we cannot confirm
from win32kfull.sys analysis alone, but the field is a RECT for DPI, not a DC pointer.

### Does SetWindowLongPtr write to WNDK+0xE0?

**No.** xxxSetWindowData (0x1C008A1A8) maps GWLP_* indices to these WNDK offsets:
- GWLP_USERDATA (-21): pwndk+0xD8 (216)
- GWLP_ID (-12): pwndk+0x98 (152)
- GWLP_HINSTANCE (-6): pwndk+0x20 (32)
- GWLP_WNDPROC (-4): pwndk+0x78 (120)
- GWLP_HWNDPARENT (-8): complex owner switch
- Index -2: pwndk+0xF0 (240)
- Index -40: pwndk+0xEA (234, byte flag)

None of these is 0xE0 (224).

### Conclusion for Blocker 1

**WNDK+0xE0 is a dead end for kernel address leakage.** The field contains window coordinates
(RECT), not kernel pointers. It is 0 on creation and only gets non-zero coordinate values during
DPI transitions. No user-mode API can write a useful kernel address to this field.

---

## Task 2: Different Sfn* Functions for Different pwndk Offsets

### Methodology
Decompiled and analyzed all 58 Sfn* functions in win32kfull.sys. Searched each for reads
from `a1[5] + offset` (the pwndk access pattern).

### Results

**ALL 58 Sfn* functions read the SAME offset: [pwndk+0xE0] (224 = 0xE0).**

Every Sfn* function follows this pattern:
```c
if (a1)
    v = *(_QWORD *)(a1[5] + 224);  // read [pwndk+0xE0]
else
    v = 0;
*(_QWORD *)(*(_QWORD *)(threadInfo + 480) + 80LL) = v;  // write to CLIENTINFO+0x50 = TEB+0x850
```

Confirmed by decompiling: SfnDWORD, SfnEMPTY, SfnNCDESTROY, SfnOUTSTRING, SfnINLPCREATESTRUCT,
and all others. No Sfn* function reads a different pwndk offset.

### Sfn* functions that also WRITE to [pwndk+0xE0]:
- **SfnNCDESTROY** (0x1C0051AB0): zeroes [pwndk+0xE0] after callback: `*(_QWORD *)(a1[5] + 224) = 0;`
- **SfnINLPKDRAWSWITCHWND** (0x1C022B760): writes to [rbp+0xE0] (local stack, NOT pwndk)
- **SfnINOUTNEXTMENU** (0x1C022D2E0): writes to [rbp+0xE0] (local stack, NOT pwndk)

### Conclusion for Task 2

**We CANNOT read multiple WNDK fields by sending different messages.** All Sfn* functions
read the same [pwndk+0xE0] offset. The message → Sfn* function → pwndk offset mapping is:
ALL messages → ALL Sfn* → [pwndk+0xE0] → TEB+0x850.

---

## Task 3: SURFACE Address Leak Alternatives

### NtGdiGetEntry

**NOT in win32kfull.sys.** NtGdiGetEntry is likely in win32kbase.sys. Cannot be called directly
from user mode unless exposed as a syscall. No syscall stub found in win32kfull.sys.

### GDI Handle Table (PEB->GdiSharedHandleTable) Layout

The GDI handle table entry (GDI_ENTRY) in user mode:
```
+0x00 (QWORD): pKernel — ENCODED: 0xFFFFFFFFFF000000 | (handle & 0xFFFFFF)
+0x08 (WORD):  wProcessId
+0x0A (WORD):  wUnique (upper 16 bits of handle)
+0x0C (DWORD): dwType (object type: 1=bitmap, 3=DC, etc.)
+0x10 (QWORD): pUser (user-mode pointer, for DIB sections)
Total: 24 bytes
```

The pKernel field is **NOT a real kernel pointer**. It's a placeholder encoding.
The real SURFACE address is in the **kernel handle table** (gpKernelHandleTable), accessed
via `HmgShareLock(handle, type)` which is imported from win32kbase.sys.

### USER Handle Table (gSharedInfo) Layout

The USER handle table is DIFFERENT from the GDI handle table:
```
gSharedInfo structure:
+0x00 (QWORD): aulObjects (user-mode base, adjusted from kernel base)
+0x08 (QWORD): PHE table base (kernel-side)
+0x10 (DWORD): cbObject — entry size for USER handle table entries
```

USER handle table entries have type at +24, flags at +25, uniqueness at +26.
This means USER table entries are **larger than 24 bytes** (at least 28 bytes, likely 32).

The USER table is for HWNDs, HMENU, etc. The GDI table (PEB+0xF8) is for HBITMAP, HDC, etc.
They are separate tables with different entry sizes.

### HmgShareLock — The Kernel Handle Decoder

SURFREF::vAltLock (0x1C026CCBC) calls `HmgShareLock(handle, 5)` to get the real SURFACE pointer:
```c
void SURFREF::vAltLock(SURFREF *this, HSURF a2) {
    *((_QWORD *)this + 4) = HmgShareLock(a2, 5);  // 5 = SURFACE type
}
```

HmgShareLock is imported — its implementation is in win32kbase.sys. It looks up the handle
in gpKernelHandleTable and returns the real kernel object pointer. This is not callable from
user mode.

### GetMaxGdiHandleCount

```c
__int64 GetMaxGdiHandleCount() { return 0x1000000; }  // 16M entries
```

This confirms the GDI handle table supports up to 16M entries, consistent with 24-bit handle
indices (0xFFFFFFFFFF000000 | 24-bit index).

### DuplicateHandle Failure

DuplicateHandle fails for GDI handles (gle=6 = ERROR_INVALID_HANDLE) because GDI handles are
NOT Windows NT handles. They're indices into the GDI shared handle table, not entries in the
process handle table. SystemHandleInformation (class 0x10) only returns NT handles (process,
thread, event, section, etc.), not GDI handles.

### SystemBigPoolInformation (class 0x0C)

Returns pool allocations with:
- VirtualAddress: kernel address
- SizeInBytes: allocation size
- Tag: 4-byte pool tag

**Only tracks allocations > PAGE_SIZE (4096 bytes).**
- Individual SURFACE objects (0x2C0 = 704 bytes): NOT tracked
- SURFACE type isolation chunks (0x2C000 = 180224 bytes): TRACKED

### SystemSessionBigPoolInformation (class 0x7D)

Similar to SystemBigPoolInformation but for **session pool** allocations. SURFACE objects are
allocated from session paged pool, so this is the correct class to query.

Returns entries with:
- VirtualAddress: kernel address (bit 0 set = paged pool, clear = nonpaged pool)
- SizeInBytes: allocation size (actual size, not including pool header)
- Tag: 4-byte pool tag

### SURFACE Pool Tag

The exact pool tag for SURFACE type isolation chunks could not be determined from
win32kfull.sys alone (the allocation happens in win32kbase.sys via GreCreateBitmap).
Common candidates: 'GlaS', 'Surb', 'cSGP', but none found as byte patterns in win32kfull.sys.

**Practical approach**: Filter SystemSessionBigPoolInformation results by size (0x2C00 or
0x2C000 bytes for type isolation chunks) rather than by tag. Allocations of exactly this size
are very likely SURFACE type isolation chunks.

### Strategy for SURFACE Address Leak

1. Query SystemSessionBigPoolInformation (class 0x7D)
2. Filter entries by size ≈ 0x2C000 (SURFACE type isolation chunk size)
3. Each matching entry gives a chunk base address
4. SURFACE slots are at chunk_base + N * 0x2C0
5. Create many bitmaps, query pool info, match new chunks to SURFACE allocations
6. If we can determine the slot index N, we get the real SURFACE address

**Limitation**: We cannot directly determine which slot index our bitmap's SURFACE occupies
within a chunk. The slot index depends on the type isolation SLIST state.

**Alternative**: Create a large number of bitmaps, free them all, then create exactly 2.
The SLIST is LIFO, so the 2 new bitmaps get the last 2 freed slots — adjacent in memory.
The chunk base from SystemSessionBigPoolInformation + calculated slot offset = SURFACE address.

---

## Summary of Findings

| Question | Answer |
|----------|--------|
| Does GetDC write DC address to WNDK+0xE0? | **No** — WNDK+0xE0 is a RECT for DPI coordinates |
| Do different Sfn* functions read different pwndk offsets? | **No** — ALL 58 Sfn* read [pwndk+0xE0] |
| Is NtGdiGetEntry callable from user mode? | **Not found in win32kfull.sys** (in win32kbase.sys) |
| What is gSharedInfo.cbObject? | At gSharedInfo+0x10, for USER table (not GDI table) |
| What is the GDI table pKernel encoding? | 0xFFFFFFFFFF000000 \| (handle & 0xFFFFFF) |
| Can SystemSessionBigPoolInformation find SURFACE chunks? | **Yes** — 0x2C000 byte chunks are > 4096 |
| Is the SfnDWORD "arbitrary READ" useful? | **No** — reads a RECT (0 or small coordinates), not a kernel pointer |

---

## Recommended Exploit Strategy Changes

1. **Abandon WNDK+0xE0 for kernel address leakage**: The field is a RECT (coordinates),
   not a kernel pointer. No user-mode API can write a useful kernel address there.

2. **Use SystemSessionBigPoolInformation for SURFACE address leak**: Query class 0x7D,
   filter by size 0x2C000, find SURFACE type isolation chunk base addresses.

3. **Use controlled allocation/free for slot prediction**: Free all bitmaps, create exactly 2
   back-to-back. They should occupy adjacent slots in the same chunk. Use the chunk base
   from pool info + calculated slot offsets for SURFACE_A and SURFACE_B addresses.

4. **Use HWND kernel addresses from SystemHandleInformation**: Already working. tagWND
   addresses are obtainable for HWNDs via class 0x10.

5. **Remove fake "arbitrary R/W" verification**: The current VerifyArbRW function reads/writes
   bitmap B's own pixel data (not kernel memory via corrupted pvScan0). This is misleading.

6. **Honest reporting**: Only claim arbitrary R/W if the bitmap height corruption succeeds
   AND the read value matches a known kernel address pattern.
