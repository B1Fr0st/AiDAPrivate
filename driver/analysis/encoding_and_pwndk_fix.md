# GDI Handle Table pKernel Encoding & pwndk Arbitrary READ Analysis

## Binary: win32kfull.sys (Windows 10 build 19041.1)
## IDA Imagebase: 0x1C0000000

---

## Problem 1: GDI Handle Table pKernel Encoding

### Finding: User-Mode GDI Table Does NOT Contain Real Kernel Pointers

The exploit reads PEB->GdiSharedHandleTable (PEB+0xF8) and interprets the first 8 bytes
of each 24-byte entry as the SURFACE kernel address (pKernel). This is WRONG on Windows 10
build 19041+.

#### Evidence from HMValidateHandleNoSecure (0x1C008C368)

```cpp
// HMValidateHandleNoSecure decompiled:
v7 = *((_QWORD *)&gSharedInfo + 1) + (unsigned int)(unsigned __int16)a1 * *((_DWORD *)&gSharedInfo + 4);
// v7 = handleTableBase + (handle & 0xFFFF) * entrySize  →  this is the PHE (user entry)

v9 = HMPkheFromPhe(v7);  // Convert PHE → PKHE (kernel entry)
return *(_QWORD *)v9;     // Return first QWORD of PKHE = real kernel object pointer
```

The function:
1. Reads the PHE (user-mode handle table entry) from `gSharedInfo`
2. Calls `HMPkheFromPhe()` to convert to PKHE (kernel handle table entry)
3. Returns `*(QWORD*)PKHE` — the REAL kernel object pointer from the KERNEL table

**HMPkheFromPhe is imported from win32kbase.sys** — the kernel handle table is separate
from the user-mode table. The user-mode table (PEB->GdiSharedHandleTable) does NOT contain
real kernel pointers.

#### The Encoded pKernel Value

The "pKernel" field in the user-mode GDI table entry is:
```
encoded = 0xFFFFFFFFFF000000 | (handle & 0xFFFFFF)
```

Example: `HBITMAP=0x05050DDE → pKernel=0xFFFFFFFFFF050DDE`

This is NOT an XOR-encoded pointer. It's a placeholder/marker value containing the handle
index with a high-bit marker. The real SURFACE address exists only in the PKHE (kernel
handle table), accessible via `HMPkheFromPhe` (a kernel function not callable from user mode).

#### gCookie Usage

`gCookie` (imported from win32kbase as `?gCookie@@3_KA`, type `unsigned __int64`) is used
in `xxxCreateDesktopEx2` at 0x1C0122C49:
```cpp
***((_QWORD ***)Object + 1) = (unsigned int)v22 | ((gCookie ^ (unsigned __int64)Object) << 32);
```

This shows gCookie is used for XOR-encoding kernel pointers, but this encoding is applied
to DESKTOP object identifiers, NOT to GDI handle table entries. The GDI handle table
encoding is a different mechanism (the placeholder pattern above).

### Fix for Problem 1: Alternative KASLR Bypass

Since the user-mode GDI table does not contain real SURFACE addresses, we use:

1. **SystemHandleInformation (class 0x10)** for USER object addresses (HWNDs) — this already
   works in the existing exploit via `LeakKernelObjectAddr()`.
   
2. **For GDI SURFACE addresses**: Once we have arbitrary kernel R/W (via bitmap corruption),
   we can read the kernel GDI handle table (PKHE) directly. But this is a chicken-and-egg
   problem — we need SURFACE addresses to get arbitrary R/W.

3. **Solution**: Use the tagWND kernel address (from SystemHandleInformation) + the SfnDWORD
   arbitrary READ to bootstrap. The tagWND address gives us a known kernel address. We can
   then use the arbitrary READ to walk kernel structures and find SURFACE addresses.

4. **Alternative**: Use `NtQuerySystemInformation(SystemBigPoolInformation)` (class 0x0C) to
   find pool allocations. GDI SURFACE objects are allocated in paged pool with specific tags.
   We can search for pool allocations matching the SURFACE size and tag to find their
   kernel addresses.

5. **Simplest runtime fix**: Create a bitmap, duplicate its handle via `DuplicateHandle`
   into a process handle, then query `SystemHandleInformation` to find the kernel object
   address. GDI handles CAN appear in SystemHandleInformation when duplicated as kernel
   handles. The returned Object address may need an offset adjustment to get the SURFACE
   address (e.g., Object + 0x10 or Object - 0x18 for BASEOBJECT header).

---

## Problem 2: SfnDWORD Arbitrary READ via TEB+0x850

### Finding: xxxSendMessageToClient ALWAYS Dispatches to Sfn*

#### xxxSendMessageToClient (0x1C0059E70) Flow Analysis

The function checks `gihmodUserApiHook`:
```cpp
if ( gihmodUserApiHook >= 0 )
    goto LABEL_6;  // → Sfn* dispatch

if ( gihmodDManipHook >= 0 )
    goto LABEL_6;  // → Sfn* dispatch

if ( v9 == 90 )  // WM_MOUSEACTIVATE
    goto LABEL_6;  // → Sfn* dispatch

// Check window type (pwndk+0x2A & 0x2FFF)
v18 = *(_WORD *)(v17 + 42) & 0x2FFF;
if ( (unsigned __int16)(v18 - 673) > 9u )
    goto LABEL_6;  // → Sfn* dispatch (for normal windows)

// Only for specific window types (673-682 range):
// Check lpfnWndProc, check Sfn* filter table
// If filter says no Sfn* → xxxDefWindowProc
// Otherwise → Sfn* dispatch
```

**For normal windows (pwndk+0x2A NOT in 673-682 range), the code ALWAYS goes to LABEL_6
which dispatches to `gapfnScSendMessage[]` (Sfn* functions).**

The `gihmodUserApiHook < 0` bypass does NOT skip Sfn* — it just takes a different path
that STILL reaches Sfn* for most messages.

### SfnDWORD (0x1C006B320) — The Arbitrary READ Mechanism

WM_NCCREATE (0x81) maps to `MessageTable[0x81] = 0` → `gapfnScSendMessage[0] = SfnDWORD`.

SfnDWORD performs:
```cpp
v20 = *(_QWORD *)(v12 + 480);           // v20 = CLIENTINFO pointer
v56 = *(_QWORD *)(v20 + 80);            // save original CLIENTINFO+0x50

// Write [pwndk+0xE0] to CLIENTINFO+0x50:
if ( a1 )
    v22 = *(_QWORD *)(a1[5] + 224);     // v22 = *(pwndk + 0xE0)
else
    v22 = 0;
*(_QWORD *)(*(_QWORD *)(v12 + 480) + 80LL) = v22;  // CLIENTINFO+0x50 = [pwndk+0xE0]

KeUserModeCallback(2, &v57, 48, &v54, &v67);  // → __fnDWORD in user mode

// Restore:
*(_QWORD *)(v34 + 80) = v56;            // restore CLIENTINFO+0x50
```

**During KeUserModeCallback, CLIENTINFO+0x50 = TEB+0x850 contains [pwndk+0xE0].**
The user-mode window procedure (called during the callback) can read TEB+0x850 directly.

### All Sfn* Functions Share This Pattern

Verified across:
- SfnDWORD (0x1C006B320): reads `*(a1[5] + 224)` → CLIENTINFO+0x50
- SfnNCDESTROY (0x1C0051AB0): reads `*(a1[5] + 224)` → CLIENTINFO+0x50
- SfnINLPCREATESTRUCT (0x1C0020F50): reads `*(a1[5] + 224)` → CLIENTINFO+0x50
- SfnINSTRINGNULL (0x1C004FDF0): reads `*(a1[5] + 224)` → CLIENTINFO+0x50
- SfnOUTSTRING (0x1C00D25F0): reads `*(a1[5] + 224)` → CLIENTINFO+0x50

All Sfn* functions read `[pwndk+0xE0]` and write it to `CLIENTINFO+0x50 = TEB+0x850`.

### UAF Exploitation of Arbitrary READ

After the UAF:
- `UserFreeIsolatedType` zeroes WNDK offsets 0x00-0x5F (96 bytes)
- WNDK offset 0xE0 (224) is NOT zeroed — stale data survives
- The stale `pwndk` in tagWND+0x28 still points to the freed WNDK body
- Sending WM_NCCREATE to the stale window reads `[pwndk+0xE0]` → TEB+0x850

### What Writes to pwndk+0xE0 (WNDK+0xE0)

Found in `xxxCreateWindowEx` (0x1C0075140) at address 0x1C0075DE8:
```asm
mov rcx, [rdi+28h]      ; rcx = pwndk = *(tagWND + 0x28)
mov rax, [rsp+4A8h+arg_80]  ; rax = a17 (17th parameter)
mov [rcx+0E0h], rax     ; pwndk+0xE0 = a17
```

`a17` is the 17th parameter of `xxxCreateWindowEx`, passed through unchanged from
`NtUserCreateWindowEx`. This is an internal parameter not directly user-controlled
from the `CreateWindowEx` API. Its value depends on internal win32k state.

### Exploit Strategy for Arbitrary READ

1. **Before UAF**: Create child window, then send WM_NCCREATE and read TEB+0x850
   to capture the pre-UAF value of `[pwndk+0xE0]`.

2. **After UAF**: Send WM_NCCREATE to the stale window and read TEB+0x850 to
   capture the stale `[pwndk+0xE0]` value.

3. **If the stale value is a kernel pointer**: Use it as a bootstrap for further
   kernel memory reads via additional UAF triggers.

4. **If the stale value is 0 or not useful**: The arbitrary READ mechanism works,
   but we need a way to pre-write a useful value to pwndk+0xE0 before the UAF.

### SystemHandleInformation for GDI SURFACE Addresses

SystemHandleInformation (NtQuerySystemInformation class 0x10) returns kernel object
addresses for handles in the process handle table. GDI handles (HBITMAP) are NOT in
the process handle table by default, but can be added via `DuplicateHandle`:

1. Create bitmap: `HBITMAP hBmp = CreateBitmap(...)`
2. Duplicate as kernel handle: `DuplicateHandle(GetCurrentProcess(), (HANDLE)hBmp, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)`
3. Query SystemHandleInformation for hDup → get Object kernel address
4. The Object address is the SURFACE (or BASEOBJECT header before SURFACE)
5. If Object = BASEOBJECT, then SURFACE = Object + 0x18 (or similar offset)
6. Compare with encoded GDI table value to determine the exact offset

**Note**: `DuplicateHandle` may not work for GDI handles on all Windows versions.
An alternative is `NtQuerySystemInformation(SystemBigPoolInformation)` (class 0x0C)
which returns pool allocation addresses and sizes. SURFACE objects are allocated in
paged pool and can be identified by their size (0x2C0 for 23x4x32 bitmaps).

---

## Summary of Key Addresses

| Symbol | Address | Description |
|--------|---------|-------------|
| HMValidateHandleNoSecure | 0x1C008C368 | Handle validation, calls HMPkheFromPhe |
| HMPkheFromPhe (import) | 0x1C03642F0 | PHE→PKHE conversion (in win32kbase) |
| gCookie (import) | 0x1C0363590 | XOR cookie (in win32kbase) |
| xxxSendMessageToClient | 0x1C0059E70 | Message dispatch, always calls Sfn* |
| SfnDWORD | 0x1C006B320 | Reads [pwndk+0xE0] → CLIENTINFO+0x50 |
| gapfnScSendMessage | 0x1C02E26D0 | Sfn* function pointer array |
| MessageTable | 0x1C02EF170 | Message→Sfn index mapping |
| gihmodUserApiHook | 0x1C032FC18 | User API hook module handle |
| xxxCreateWindowEx | 0x1C0075140 | Writes a17 to [pwndk+0xE0] |
| NtUserCreateWindowEx | 0x1C00BF1E0 | Syscall handler, passes a17 through |

## MessageTable Mapping (Key Messages)

| Message | Value | Table Index | Sfn Function |
|---------|-------|-------------|--------------|
| WM_NULL | 0x00 | 0 | SfnDWORD |
| WM_CREATE | 0x01 | 4 | SfnOUTSTRING |
| WM_DESTROY | 0x02 | 2 | SfnINLPCREATESTRUCT |
| WM_NCCREATE | 0x81 | 0 | SfnDWORD |
| WM_NCDESTROY | 0x82 | 0 | SfnDWORD |
| WM_SETTEXT | 0x0C | 0 | SfnDWORD |
| WM_GETTEXT | 0x0D | 4 | SfnOUTSTRING |

## CLIENTINFO/TEB Layout

- W32THREAD+0x1E0 → pointer to CLIENTINFO
- CLIENTINFO is at TEB+0x800 on x64 Windows 10
- CLIENTINFO+0x40 = TEB+0x840 (written by Sfn*: *a1 = tagWND first QWORD)
- CLIENTINFO+0x48 = TEB+0x848 (written by Sfn*: window delta)
- CLIENTINFO+0x50 = TEB+0x850 (written by Sfn*: [pwndk+0xE0] ← ARBITRARY READ)
