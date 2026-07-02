# ALPC (Advanced Local Procedure Call) Analysis — ntoskrnl.exe

**Target:** ntoskrnl.exe (IDA Pro PID 8428, port 13346)
**Date:** 2026-07-01
**Objective:** Evaluate ALPC as a driverless kernel R/W primitive, alternative to GDI SURFACE
**Context:** portcls UAF provides controlled NonPagedPoolNx allocations at 945-960 and 689-704 byte ranges

---

## 1. Function Enumeration

### 1.1 Alpc* Function Count

- **Total Alpc* functions:** 252 (after filtering Hal* false positives from glob match)
- **NtAlpc* syscalls:** 23
- **ZwAlpc* stubs:** 22 (0x1F bytes each, simple syscall wrappers at 0x1403FA950-0x1403FAC10)
- **VfZwAlpc* verifier wrappers:** 10
- **Legacy Lpc* functions:** ~15 (LpcRequestPort, LpcSendWaitReceivePort, LpcExitProcess, LpcInitializeProcess, LpcInitSystem, LpcpRequestWaitReplyPort, LpcpCopyRequestData, etc.)
- **Legacy Nt*Port syscalls:** NtCreatePort, NtConnectPort, NtSecureConnectPort, NtAcceptConnectPort, NtListenPort, NtReplyPort, NtReplyWaitReceivePort, NtReplyWaitReceivePortEx, NtReplyWaitReplyPort, NtRequestPort, NtRequestWaitReplyPort, NtImpersonateClientOfPort, NtQueryInformationPort, NtCreateWaitablePort, NtRegisterThreadTerminatePort, NtSetDefaultHardErrorPort

### 1.2 Key NtAlpc Syscalls

| Address | Function | Size |
|---------|----------|------|
| 0x14068D710 | NtAlpcCreatePort | 0x41 |
| 0x1405DE5A0 | NtAlpcConnectPort | 0x74 |
| 0x1405DE620 | NtAlpcConnectPortEx | 0x76 |
| 0x1405DF9C0 | NtAlpcAcceptConnectPort | 0x8F |
| 0x1405E79F0 | NtAlpcSendWaitReceivePort | 0x278 |
| 0x14068F3D0 | NtAlpcDisconnectPort | 0x9A |
| 0x140701A00 | NtAlpcCreatePortSection | 0x1C5 |
| 0x1406FFB20 | NtAlpcCreateSectionView | 0x21F |
| 0x140693DE0 | NtAlpcCreateResourceReserve | 0xED |
| 0x1406DB2A0 | NtAlpcCreateSecurityContext | 0x1EE |
| 0x1406FF3A0 | NtAlpcSetInformation | 0x40B |
| 0x1406612C0 | NtAlpcQueryInformation | 0x21B |
| 0x1405E9A10 | NtAlpcImpersonateClientOfPort | 0x1BB |
| 0x1406A4060 | NtAlpcCancelMessage | 0x182 |

### 1.3 Key Internal Functions

| Address | Function | Size | Role |
|---------|----------|------|------|
| 0x14068D758 | AlpcpCreateConnectionPort | 0x2A1 | Server port creation |
| 0x1405E054C | AlpcpCreateClientPort | 0x438 | Client port creation |
| 0x1405E0F24 | AlpcpCreatePort | 0x5D | ObCreateObjectEx wrapper |
| 0x1405E0D98 | AlpcpInitializePort | 0x186 | Port list/queue init |
| 0x1405E103C | AlpcpAcceptConnectPort | 0xB4F | Connection acceptance (LARGEST) |
| 0x1405E4800 | AlpcpSendMessage | 0xA41 | Message send (2nd LARGEST) |
| 0x1405E55B0 | AlpcpCompleteDispatchMessage | 0xA80 | Message completion |
| 0x1405E7C70 | AlpcpReceiveMessage | 0x700 | Message receive |
| 0x1406D976C | AlpcpAllocateBlob | 0xAD | **Core blob allocator** |
| 0x1405E09E4 | AlpcpAllocateMessage | 0xD8 | Message allocator |
| 0x140701BCC | AlpcpCreateSection | 0x29A | ALPC section creation |
| 0x1406FFD48 | AlpcpCreateSectionView | 0xF5 | Section view creation |
| 0x1406D9820 | AlpcpCreateView | 0x284 | **View mapping (critical)** |
| 0x140693ED4 | AlpcpCreateReserve | 0x24D | Resource reserve creation |
| 0x1406D92CC | AlpcpCreateSecurityContext | 0x179 | Security context creation |

---

## 2. Core Syscall Decompile Summary

### 2.1 NtCreatePort (0x140772C00)

```
NtCreatePort → AlpcpCreateConnectionPort(PortHandle, DesiredAccess, NULL, MaxDataSize, NULL, TRUE)
```
- Wrapper: disables APCs, calls AlpcpCreateConnectionPort, re-enables APCs
- Creates a connection port (server-side) via ObCreateObjectEx

### 2.2 NtConnectPort (0x1405DDB10)

```
NtConnectPort → NtSecureConnectPort(..., NULL, ...)
```
- Simple redirect to NtSecureConnectPort with NULL server SID

### 2.3 NtAcceptConnectPort (0x14069B0F0)

```
NtAcceptConnectPort → AlpcpAcceptConnectPort(..., AcceptConnection, ...)
```
- Accepts a connection request, calls the massive AlpcpAcceptConnectPort (0xB4F bytes)

### 2.4 NtAlpcConnectPort (0x1405DE5A0)

```
NtAlpcConnectPort → AlpcpConnectPort(...)
```
- Redirects to AlpcpConnectPort (0x3F8 bytes), the modern connection path

---

## 3. ALPC Object Type Analysis

### 3.1 Blob Allocation Architecture

All ALPC secondary objects (connections, messages, sections, views, reserves) are allocated through **AlpcpAllocateBlob** (0x1406D976C).

**Allocation logic:**
```c
// Pseudocode of AlpcpAllocateBlob
void* AlpcpAllocateBlob(type_object, user_size, force_paged) {
    total_size = user_size + 48;  // 48-byte blob header overhead

    if (force_paged || lookaside_max_size < total_size) {
        // PAGED PATH: use lookaside alloc function or ExAllocatePoolWithTag
        if (type_has_lookaside_fn)
            result = lookaside_allocate_fn(PagedPool, total_size, tag);
        else
            result = ExAllocatePoolWithTag(PagedPool, total_size, tag);
    } else {
        // LOOKASIDE FAST PATH (still paged lookaside on Win10/11)
        result = ExAllocateFromNPagedLookasideList(&AlpcpLookasides + index);
    }

    if (result) {
        // Zero first 48 bytes (3 x OWORD)
        result[0] = 0; result[1] = 0; result[2] = 0;
        // Set type byte at offset 0x11
        *((BYTE*)result + 17) = type_object->type_id;
        // Self-link at offsets 0x00 and 0x08
        *(QWORD*)result = result;
        *(QWORD*)(result+8) = result;
        // Flags at offset 0x10
        *(BYTE*)(result+16) = flags;
        // Reference count at offset 0x18
        *(QWORD*)(result+24) = 1;
        // Return pointer past 24-byte header
        return result + 0x18;
    }
    return NULL;
}
```

**Blob header layout (24 bytes before returned pointer):**
```
+0x00: Flink (self-link)
+0x08: Blink (self-link)
+0x10: Flags byte
+0x11: Type byte (AlpcConnectionType, AlpcMessageType, etc.)
+0x18: Reference count (QWORD, initialized to 1)
+0x18: === RETURNED POINTER (user data starts here) ===
```

**Total allocation = user_size + 48 bytes** (24 before + 24 after user data)

### 3.2 Per-Type Allocation Details

#### Port Object (AlpcPortObjectType)

| Property | Value |
|----------|-------|
| **Allocator** | ObCreateObjectEx (object manager) |
| **Body size** | 0x1D8 (472) bytes |
| **Total with OBJECT_HEADER** | ~0x208 (520) bytes |
| **Pool** | PagedPool (object manager default for ALPC Port type) |
| **Zeroed** | 0x1D8 bytes memset to 0 (AlpcpCreatePort) |
| **User trigger** | NtCreatePort, NtAlpcCreatePort |
| **Offset 0x50** | Within zeroed region, between list heads at 0x048 and 0x058 — **NOT a pointer, NOT user-controlled** |

**Port object structure (from AlpcpInitializePort):**
```
+0x000: PortList Flink
+0x008: PortList Blink
+0x010: CommunicationInfo blob pointer (set in accept/connect)
+0x020: ConnectionPort pointer / OwnerProcess
+0x030: ConnectionPort object pointer
+0x040: various state
+0x050: (zeroed, between list heads — NOT a useful pointer)
+0x058: (zeroed)
+0x060-0x0F8: Multiple list heads (pending queue, large message queue, cancel queue, etc.)
+0x098: Semaphore/Event pointer (NonPagedPool lookaside or AlpcpDummyEvent)
+0x0A0: various flags
+0x100: Port attributes DWORD (flags including 0x100000 system-mapping bit)
+0x110-0x140: Port attributes (MaxMessageLength, SecurityQoS, etc.)
+0x160: PushLock (port lock)
+0x180: Resource list head
+0x1A0: Port state flags (type: connection=2/communication=4, disconnect=0x20, etc.)
+0x1B8: IO Completion Port handle
+0x1C0: Completion list pointer
+0x1B0: Various resource pointers
```

#### Connection Blob (AlpcConnectionType)

| Property | Value |
|----------|-------|
| **Allocator** | AlpcpAllocateBlob(force_paged=1) |
| **User data size** | 80 bytes |
| **Total allocation** | 80 + 48 = 128 bytes (0x80) |
| **Pool** | **PagedPool** (forced) |
| **Zeroed** | 80 bytes memset to 0 |
| **User trigger** | NtCreatePort → AlpcpCreateConnectionPort |
| **Offset 0x50** | = 80 bytes from returned ptr = **END OF BLOB** (out of bounds) |

#### Message Blob (AlpcMessageType)

| Property | Value |
|----------|-------|
| **Allocator** | AlpcpAllocateBlob → AlpcpAllocateMessageFunction |
| **User data size** | user_size + 240 (min 280, default 792) |
| **Total allocation** | user_size + 288 (min 328, default 840, max ~65793) |
| **Pool** | **PagedPool** (always forced a3=1) |
| **Zeroed** | First 0x118 (280) bytes memset to 0 |
| **User trigger** | NtAlpcSendWaitReceivePort, NtAlpcCreateResourceReserve |
| **Pool tag** | 'AlMs' (0x734D6C41) |
| **Message handle** | Created via ExCreateHandleEx in AlpcMessageTable |

**Message size calculation (py_eval):**
```
If user_size == 0: total = 792 + 48 = 840 bytes (0x348) — default lookaside size
If user_size >= 0x28: total = user_size + 240 + 48 = user_size + 288
Minimum: 0x28 + 288 = 328 bytes (0x148)
Maximum: 0xFFD7 + 288 = 65783 bytes
```

**To match portcls UAF ranges:**
- Range [945, 960]: user_size = [657, 672] (0x291-0x2A0) — **VALID, user-controllable**
- Range [689, 704]: user_size = [401, 416] (0x191-0x1A0) — **VALID, user-controllable**

**BUT: messages are in PagedPool, NOT NonPagedPoolNx. Cross-pool reuse does not work.**

#### Section Blob (AlpcSectionType)

| Property | Value |
|----------|-------|
| **Allocator** | AlpcpAllocateBlob(force_paged=1) |
| **User data size** | 72 bytes |
| **Total allocation** | 72 + 48 = 120 bytes (0x78) |
| **Pool** | **PagedPool** (forced) |
| **Zeroed** | 72 bytes memset to 0 |
| **User trigger** | NtAlpcCreatePortSection |
| **Offset 0x50** | = 80 bytes from returned ptr — **BEYOND 72-byte blob** (out of bounds) |

**Section blob structure:**
```
+0x00: Section object pointer (from MmCreateSection or ObReferenceObjectByHandle)
+0x08: Section size (aligned to AlpcpRegionGranularity)
+0x10: Handle table entry pointer
+0x18: Handle table index
+0x20: Owning port object pointer
+0x28: Owning process (KeGetCurrentThread()->ApcState.Process)
+0x30: Flags (bit 0 = secure section, bit 1 = from handle)
+0x38: Region list head (self-link at +0x38, Flink at +0x40)
+0x40: Region list Flink
```

#### View Blob (AlpcViewType)

| Property | Value |
|----------|-------|
| **Allocator** | AlpcpAllocateBlob(force_paged=0) |
| **User data size** | 96 bytes |
| **Total allocation** | 96 + 48 = 144 bytes (0x90) |
| **Pool** | **PagedPool** (lookaside or fallback) |
| **Zeroed** | 96 bytes memset to 0 |
| **User trigger** | NtAlpcCreateSectionView → AlpcpCreateSectionView → AlpcpCreateView |
| **Offset 0x50** | = 80 bytes from returned ptr — within 96-byte blob |

**View blob structure:**
```
+0x00: Section blob list link (Flink to section+0x38)
+0x08: Section blob list link (Blink)
+0x10: Parent section blob pointer
+0x18: Owning port object pointer
+0x20: Target process object pointer
+0x28: View base address (QWORD) — mapped VA
+0x30: View size (QWORD)
+0x38: View region offset
+0x40: Secure handle (MmUnsecureVirtualMemory)
+0x48: Process object (for attach/detach)
+0x50: Flags DWORD (bit 0 = writable, bit 2 = unlinked, bit 3 = system-space)
+0x58: Process view list link (Flink)
+0x60: Process view list link (Blink)
```

#### Reserve Blob (AlpcReserveType)

| Property | Value |
|----------|-------|
| **Allocator** | AlpcpAllocateBlob(force_paged=1) |
| **User data size** | 48 bytes |
| **Total allocation** | 48 + 48 = 96 bytes (0x60) |
| **Pool** | **PagedPool** (forced) |
| **Zeroed** | 48 bytes memset to 0 |
| **User trigger** | NtAlpcCreateResourceReserve |
| **Offset 0x50** | = 80 bytes from returned ptr — **BEYOND 48-byte blob** (out of bounds) |

#### Semaphore (Port Event Object)

| Property | Value |
|----------|-------|
| **Allocator** | ExAllocateFromNPagedLookasideList(&AlpcpNPLookasides) |
| **Total allocation** | 0x200 (512) bytes |
| **Pool** | **NonPagedPool** (NP lookaside) |
| **Pool tag** | 'AlSe' (0x65536C41) |
| **User trigger** | NtCreatePort/NtCreateWaitablePort with waitable flag |
| **Size match** | 512 bytes — **DOES NOT match** portcls UAF ranges [945-960, 689-704] |

### 3.3 Pool Type Summary

| Object | Pool | Tag | NonPagedPoolNx? |
|--------|------|-----|-----------------|
| Port object | PagedPool | (obj mgr) | NO |
| Connection blob | PagedPool | (type) | NO |
| Message blob | PagedPool | AlMs | NO |
| Section blob | PagedPool | (type) | NO |
| View blob | PagedPool | (type) | NO |
| Reserve blob | PagedPool | (type) | NO |
| Semaphore | NonPagedPool | AlSe | NO (NonPagedPool, not Nx) |
| DummyEvent | NonPagedPoolNx | AlIn | YES (but 24 bytes, one-time alloc) |
| SecondaryMsgTable | PagedPool | AlHa | NO |

**ALL user-triggerable ALPC allocations are in PagedPool. The only NonPagedPool allocation (semaphore, 512 bytes) does not match portcls UAF sizes and is in NonPagedPool (not NonPagedPoolNx).**

---

## 4. ALPC Section Mapping Analysis

### 4.1 Section Creation (AlpcpCreateSection, 0x140701BCC)

```c
// Section blob allocated: AlpcpAllocateBlob(AlpcSectionType, 72, 1) = 120 bytes PagedPool

// Two creation paths:
if (section_handle_provided) {
    // Path 1: Reference existing section by handle
    ObReferenceObjectByHandle(section_handle, SECTION_MAP_WRITE, MmSectionObjectType, ...);
} else {
    // Path 2: Create new section via MmCreateSection
    section_size = align_up(user_size, AlpcpRegionGranularity);
    MmCreateSection(
        &section_obj,
        SECTION_ALL_ACCESS,    // 0xF0001F
        NULL,                   // ObjectAttributes
        &section_size,
        PAGE_READWRITE,         // 4
        SEC_COMMIT,             // 0x8000000 — pagefile-backed committed section
        NULL,                   // FileHandle
        NULL                    // FileObject
    );
}
```

**Key finding:** ALPC sections are pagefile-backed committed sections (SEC_COMMIT | PAGE_READWRITE). They are NOT views of physical memory, kernel memory, or existing kernel sections. The section object is either user-supplied (via handle) or newly created from the pagefile.

### 4.2 View Creation (AlpcpCreateView, 0x1406D9820)

```c
// View blob allocated: AlpcpAllocateBlob(AlpcViewType, 96, 0) = 144 bytes

// TWO mapping paths:
if ((port->flags[0x100] & 0x100000) == 0) {
    // PATH A: User-space mapping
    if (section->flags & SEC_SECURE)  // bit 1
        MmMapSecureViewOfSection(section_obj, process, &view_base, ...);
    else
        MmMapViewOfSection(section_obj, process, &view_base, 0, 0,
                           &section_offset, &view_size,
                           2,    // ViewShare
                           0,    // allocation
                           4);   // Win32NtViewMap
} else {
    // PATH B: SYSTEM-SPACE mapping
    MiMapViewInSystemSpace(
        section_obj,
        &unk_140C4CDA8,     // system PTE pool descriptor
        &view_base,          // kernel VA output
        &view_size,
        &section_offset,
        0, 0
    );
    view_flags |= 8;  // mark as system-space view
}
```

### 4.3 System-Space Mapping Flag (0x100000)

The `0x100000` bit at port object offset 0x100 controls whether views are mapped into system space or user space.

**Can user mode set this flag? NO.**

From AlpcpValidateAndSetPortAttributes (0x1405E0B04):
```c
if ((*(_DWORD *)attributes & 0x100000) != 0 && KeGetCurrentThread()->PreviousMode)
    return STATUS_INVALID_PARAMETER;  // Explicitly blocked from user mode!
```

From NtAlpcSetInformation (0x1406FF3A0), information class 1:
```c
// Only allows toggling bit 0x20000, NOT 0x100000
port->flags[0x100] ^= (port->flags[0x100] ^ user_value) & 0x20000;
```

**The 0x100000 flag is kernel-internal only. User mode cannot trigger system-space mapping.**

### 4.4 User-Space Mapping Path

When the system-space flag is NOT set (the only path available from user mode):
- `MmMapViewOfSection` maps the ALPC section into the **client process's user VA**
- The view base address and size are written back to the user-mode buffer via NtAlpcCreateSectionView
- This is a standard user-mode section view — the section contains pagefile-backed pages, NOT kernel memory

### 4.5 View Attribute Exposure (AlpcpExposeViewAttribute)

When a message with a view attribute is received, the view base address and size are exposed to the receiving process:
```c
*(QWORD*)(output + 16) = view_blob->view_base;    // mapped VA
*(QWORD*)(output + 24) = view_blob->view_size;     // view size
if (view_flags & 1)  // secure view
    *(DWORD*)(output) = 0x40000;  // ALPC_PORFLG_SECURE_VIEW
```

The exposed VA is a **user-mode** address in the receiving process's address space. No kernel addresses are leaked.

### 4.6 Secure View Handling

ALPC supports "secure views" where the mapped pages are initially read-only:
- `MmMapSecureViewOfSection` creates the view with read-only protection
- `MmUnsecureVirtualMemory` (in AlpcpRestoreWriteAccess / AlpcpForceUnlinkSecureView) restores write access
- The secure handle is stored at view_blob+0x40
- The process for attach/detach is stored at view_blob+0x48
- `KiStackAttachProcess` / `KiUnstackDetachProcess` are used to operate in the target process context

This is a protection mechanism, not an attack vector — it prevents the sender from writing to the view before the receiver accepts it.

---

## 5. Portcls UAF Size Matching

### 5.1 Size Match Analysis (py_eval)

```
Portcls UAF target ranges:
  Range 1: 945-960 bytes (0x3B1-0x3C0)
  Range 2: 689-704 bytes (0x2B1-0x2C0)

ALPC object sizes (total allocation including 48-byte blob header):
  Port object:         520 bytes (0x208)  — NO MATCH
  Connection blob:     128 bytes (0x80)   — NO MATCH
  Message (default):   840 bytes (0x348)  — NO MATCH
  Message (min):       328 bytes (0x148)  — NO MATCH
  Section blob:        120 bytes (0x78)   — NO MATCH
  View blob:           144 bytes (0x90)   — NO MATCH
  Reserve blob:         96 bytes (0x60)   — NO MATCH
  Semaphore:           512 bytes (0x200)  — NO MATCH
  DummyEvent:           24 bytes (0x18)   — NO MATCH

Message blob with custom user_size:
  To hit [945, 960]: user_size = [657, 672] — VALID (within 0x28-0xFFD7)
  To hit [689, 704]: user_size = [401, 416] — VALID (within 0x28-0xFFD7)
```

### 5.2 Pool Type Mismatch

Even though ALPC message blobs CAN be sized to match the portcls UAF ranges:

- **ALPC messages are in PagedPool** (ExAllocatePoolWithTag(PagedPool, ...))
- **Portcls UAF frees NonPagedPoolNx allocations**
- PagedPool and NonPagedPoolNx use **separate pool backends** with separate freelists
- Windows 10/11 pool isolation prevents cross-pool reuse
- **Cross-pool heap feng shui between PagedPool and NonPagedPoolNx is NOT viable**

### 5.3 Semaphore (Only NonPagedPool ALPC Object)

The only NonPagedPool allocation accessible via ALPC is the port semaphore:
- Size: 512 bytes (0x200) — does NOT match either UAF range
- Pool: NonPagedPool (not NonPagedPoolNx) — different pool type
- Tag: 'AlSe'
- Allocated via ExAllocateFromNPagedLookasideList — lookaside allocations bypass the normal pool allocator

**VERDICT: NO ALPC object can match the portcls UAF in both size AND pool type.**

---

## 6. Vulnerability Assessment

### 6.1 UAF Potential

**AlpcpDisconnectPort (0x1405E26FC):**
- Sets disconnect flag (0x20) at offset 0x1A0
- Uses ObReferenceObjectSafe before accessing connected port
- Cancels messages in multiple queues (pending, large, cancel, direct)
- Releases push locks between operations — potential race window between disconnect and message dispatch

**AlpcpDeletePort (0x1405E2D20):**
- Clears communication info blob pointer at offset 0x10
- Dereferences connection port, completion packet lookaside
- Calls AlpcpDestroyPort for final cleanup
- Uses HalPutDmaAdapter (ObfDereferenceObjectWithTag) for object dereference

**Race condition surface:** The disconnect-to-delete path has multiple lock releases and re-acquisitions. Messages in flight during disconnect could reference freed objects. However:
- ObReferenceObjectSafe is used before accessing connected ports
- Message blobs are reference-counted (AlpcpLockForCachedReferenceBlob)
- The canceled message queue processing happens under locks

**Assessment:** Race conditions exist in theory but are protected by reference counting and safe reference patterns. No obvious UAF without winning a narrow race against reference count checks.

### 6.2 Overflow Potential

**AlpcpCaptureAttributes (0x1405E6290, 0x5CF bytes):**
- Large function handling user-supplied message attributes
- Multiple attribute types (security, context, view, handle, direct, work-on-behalf)
- Each has capture, expose, and release paths
- 32-bit variants (AlpcpCapture*Attribute32) add WoW64 complexity

**AlpcpAcceptConnectPort (0x1405E103C, 0xB4F bytes):**
- Largest ALPC function
- Handles connection request validation, port creation, message dispatch
- Multiple user-mode probes and captures
- Potential for TOCTOU (time-of-check-time-of-use) on user-mode buffers

**Assessment:** The large attribute capture and connection acceptance functions have complex user-mode interaction. Historical ALPC CVEs (CVE-2018-8413, CVE-2020-17087) targeted similar paths. However, modern Windows has extensive ProbeForRead/ProbeForWrite and SEH wrappers.

### 6.3 Type Confusion Potential

**Blob type system:** Each blob has a type byte at offset 0x11 (from allocation start) / offset 0x29 (from returned pointer). The type is checked when looking up blobs by handle (AlpcReferenceBlobByHandle verifies type). Type confusion would require either:
1. Corrupting the type byte (requires write primitive — circular dependency)
2. Passing a valid handle of one type where another is expected (checked by AlpcReferenceBlobByHandle)

**Assessment:** Type confusion is mitigated by handle-based lookup with type verification.

### 6.4 Known Historical ALPC Vulnerabilities

- **CVE-2018-8413:** ALPC handle table race in AlpcpCreateSecurityContext — UAF on security context blob
- **CVE-2020-17087:** ALPC message size integer overflow in AlpcpReceiveMessage — pool overflow
- **CVE-2021-36955:** ALPC information disclosure via uninitialized padding
- These are patch-level dependent; the analyzed binary appears to have fixes applied

---

## 7. Driverless Kernel R/W Assessment

### 7.1 Can ALPC Map Kernel Memory? — NO

1. **System-space mapping requires kernel-only flag:** The MiMapViewInSystemSpace path in AlpcpCreateView requires bit 0x100000 at port offset 0x100, which is explicitly blocked from user mode (AlpcpValidateAndSetPortAttributes rejects it when PreviousMode != 0).

2. **Sections are pagefile-backed:** MmCreateSection creates sections with SEC_COMMIT | PAGE_READWRITE from the pagefile, NOT from existing kernel memory. You cannot create an ALPC section that views kernel memory.

3. **User-supplied section handles are validated:** ObReferenceObjectByHandle with SECTION_MAP_WRITE access check. You can supply a handle to your own section, but that section still maps to user-controlled pages, not kernel pages.

4. **MmMapViewOfSection maps into user VA:** The user-accessible mapping path maps the section into the client process's user-mode address space, not kernel space.

### 7.2 Can ALPC Provide Pool Overlap for portcls UAF? — NO

1. **All ALPC blobs are in PagedPool:** Connection, message, section, view, and reserve blobs are all allocated with PagedPool (via AlpcpAllocateBlob with force_paged=1 or paged lookaside).

2. **Portcls UAF is in NonPagedPoolNx:** Cross-pool reuse between PagedPool and NonPagedPoolNx is not viable on modern Windows.

3. **The only NonPagedPool ALPC object (semaphore, 512 bytes) does not match portcls UAF sizes.**

4. **Semaphore uses lookaside allocation:** ExAllocateFromNPagedLookasideList bypasses the normal pool allocator, making controlled allocation/free timing difficult.

### 7.3 Can ALPC Provide Information Leaks? — LIMITED

1. **View attributes expose user VAs:** AlpcpExposeViewAttribute writes the mapped view base and size to the receiving process. These are user-mode addresses, not kernel addresses.

2. **Port query information:** NtAlpcQueryInformation can query basic port info, server session info, connected SID info. These return metadata, not kernel pointers.

3. **Message query information:** NtAlpcQueryInformationMessage can query SID, token, handle info from messages. No kernel address exposure observed.

4. **No KASLR bypass found through ALPC.**

### 7.4 Alternative Attack Vectors via ALPC

1. **ALPC impersonation:** NtAlpcImpersonateClientOfPort and NtAlpcImpersonateClientContainerOfPort allow server to impersonate client. This is a privilege escalation vector if a higher-privilege process connects to a lower-privilege server, but requires already having a port connection to a privileged process.

2. **ALPC message handle table:** The AlpcMessageTable (ExCreateHandleTable) stores message handles. The handle value is stored at message+0x108 (offset 264 from returned pointer) with bit 31 set. Handle table corruption could potentially be levered if combined with another write primitive.

3. **ALPC completion list:** AlpcpInitializeCompletionList (0x65C270, 0x463 bytes) sets up I/O completion ports for ALPC. The completion list uses bitmap-based buffer allocation (AlpcpAllocateFromBitmap). Complex state management could have edge cases.

---

## 8. Final Verdict

### 8.1 GO/NO-GO Summary

| Question | Answer | Verdict |
|----------|--------|---------|
| Can ALPC objects match portcls UAF sizes? | Yes (messages) | Partial |
| Can ALPC objects match portcls UAF pool type? | No (PagedPool vs NonPagedPoolNx) | **NO-GO** |
| Can ALPC map kernel memory to user space? | No (system-space flag blocked from user mode) | **NO-GO** |
| Can ALPC sections view kernel memory? | No (pagefile-backed sections only) | **NO-GO** |
| Can ALPC provide KASLR bypass? | No kernel pointers exposed | **NO-GO** |
| Can ALPC provide direct kernel R/W? | No | **NO-GO** |
| Are there exploitable ALPC UAF/overflow bugs? | Potential races, but protected by refcounts | **UNLIKELY** |
| Is ALPC a viable alternative to GDI SURFACE? | No | **NO-GO** |

### 8.2 Overall Assessment

**ALPC is NOT a viable path for driverless kernel R/W exploitation in the context of the portcls UAF.**

The fundamental blockers are:

1. **Pool type mismatch:** All user-triggerable ALPC allocations are in PagedPool. The portcls UAF operates in NonPagedPoolNx. Cross-pool reuse is not viable on Windows 10/11 with pool isolation.

2. **No kernel memory mapping:** The system-space section mapping path (MiMapViewInSystemSpace) requires a kernel-internal flag (0x100000) that is explicitly blocked from user mode. ALPC sections are pagefile-backed, not views of kernel memory.

3. **No KASLR bypass:** ALPC does not expose kernel addresses through any observed query/expose path.

4. **No size+pool match:** While ALPC messages can be sized to match the portcls UAF ranges (945-960 or 689-704 bytes), they are in the wrong pool type.

**Recommendation:** Continue pursuing the GDI SURFACE approach or explore other NonPagedPoolNx allocation sources (e.g., USER* objects, window station/desktop objects, or other kernel driver allocations that use NonPagedPoolNx at matching sizes).
