# UAF Race Verification: LINK D and LINK E

**Target:** afd.sys (pid 18576)  
**Date:** 2026-07-02  
**Tool:** IDA Pro MCP (decompilation + disassembly + py_eval)

---

## LINK D: The UAF Race — AfdCloseCore frees connection, AfdCloseConnection runs on freed memory

### D1. AfdCloseCore Decompile (0x1C0037350)

```c
__int64 __fastcall AfdCloseCore(PSLIST_ENTRY ListEntry)
{
  // ...
  if ( ((__int64)ListEntry->Next & 0xAFD2) == 0xAFD2 )
    v3 = ListEntry[11].Next;          // reads endpoint+0xB0 → connection pointer
  else
    v3 = nullptr;
  if ( v3 )
  {
    ListEntry[11].Next = nullptr;     // clears endpoint+0xB0
    if ( _InterlockedExchangeAdd((volatile signed __int32 *)&v3[3], 0xFFFFFFFF) == 1 )
      AfdCloseConnection(v3);         // called if refcount was 1 (now 0)
    *((_QWORD *)&ListEntry[20].Next + 1) = v3;  // stores conn at endpoint+0x148
  }
  // ...
  AfdDereferenceEndpointInline(ListEntry);
  return 0;
}
```

### D2. Spinlock-Free Read at 0x1C00373D1

**CONFIRMED.** Disassembly at `0x1c00373d1`:

```asm
loc_1C00373D1:
  mov rdi, [rbx+0B0h]    ; read endpoint+0xB0 → connection pointer, NO SPINLOCK
  jmp short loc_1C0037384
```

No `lock` prefix, no spinlock acquisition, no IRQL raise before this read. The code path is:
- `0x1c003736b`: `movzx ecx, word ptr [rbx]` (read endpoint type)
- `0x1c003737f`: `jz loc_1C00373D1` (if type == AFD2)
- `0x1c00373d1`: `mov rdi, [rbx+0B0h]` (read connection pointer — **UNPROTECTED**)

### D3. Refcount at conn+0x30 and AfdCloseConnection Call

Disassembly of the refcount decrement:

```asm
0x1c00373da:  mov [rbx+0B0h], r8        ; NULL out endpoint+0xB0
0x1c00373e1:  or eax, 0FFFFFFFFh        ; eax = -1 (0xFFFFFFFF)
0x1c00373e4:  lock xadd [rdi+30h], eax  ; atomic: old=*addr; *addr=old+eax; eax=old
0x1c00373e9:  cmp eax, 1                ; was old value == 1?
0x1c00373ec:  jz short loc_1C00373F7    ; if yes → call AfdCloseConnection
0x1c00373f7:  mov rcx, rdi              ; rcx = connection pointer
0x1c00373fa:  call AfdCloseConnection   ; call with our (potentially freed) connection
```

**Refcount location: `conn + 0x30`** (confirmed via `lock xadd [rdi+30h], eax`).

### D4. xadd Math Verification (py_eval)

```
conn+0x30 initial value: 1
xadd decrement (signed): -1
new value at conn+0x30 after xadd: 0
eax after xadd (old value returned): 1
cmp eax, 1 → ZF=1
jz taken (AfdCloseConnection called): True
```

**With `conn+0x30 = 1` in our spray:**
- `lock xadd [rdi+30h], eax` with eax=0xFFFFFFFF: atomically reads old=1, writes new=0, returns 1 in eax
- `cmp eax, 1` → ZF=1 → `jz` TAKEN
- `AfdCloseConnection(v3)` IS called on our sprayed connection data

### D5. Return After AfdCloseConnection

After `AfdCloseConnection` returns:

```asm
0x1c00373ff:  jmp short loc_1C00373EE
0x1c00373ee:  mov [rbx+148h], rdi       ; store conn ptr at endpoint+0x148
0x1c00373f5:  jmp short loc_1C00373A5   ; continue to cleanup
0x1c00373a5:  mov r8, rbx
0x1c00373a8:  mov byte ptr [rbx+2], 6   ; set endpoint state = CLOSED (6)
0x1c00373b6:  call AFDETW_TRACECLOSE    ; ETW trace
0x1c00373be:  call AfdDereferenceEndpointInline  ; deref endpoint
0x1c00373c3:  mov rbx, [rsp+38h+arg_0]  ; restore rbx
0x1c00373c8:  xor eax, eax              ; return 0
0x1c00373ca:  add rsp, 30h
0x1c00373ce:  pop rdi
0x1c00373cf:  retn                      ; return to AfdClose
```

**AfdCloseCore returns normally to its caller (AfdClose) after AfdCloseConnection.**

### LINK D VERDICT: **YES** — The race triggers AfdCloseConnection on our sprayed data.

**Evidence:**
1. `mov rdi, [rbx+0B0h]` at `0x1c00373d1` reads the connection pointer from `endpoint+0xB0` **WITHOUT any spinlock** — concurrent free between this read and the `lock xadd` is possible
2. The refcount is at `conn+0x30` (confirmed by `lock xadd [rdi+30h], eax`)
3. With `conn+0x30 = 1` in spray: `lock xadd` returns old=1, new=0 → `cmp eax,1` → ZF=1 → `jz` taken → `call AfdCloseConnection` executed
4. AfdCloseConnection operates on `rdi` (our sprayed connection) — reads `conn+0x04` flags, `conn+0x08` transport, `conn+0x10` handle, `conn+0x18` function pointer table
5. The function pointer at `conn+0x18` (dereferenced as `mov rax, [rdi+18h]; mov rax, [rax]; call __guard_dispatch_icall_fptr`) is our **controlled gadget call** at `0x1c0056df4`

---

## LINK E: Full Return Path from _setjmp to User Mode Has ZERO GDI Access

### E1. Gadget Call Site (0x1c0056df4)

Disassembly at the gadget call inside AfdCloseConnection:

```asm
0x1c0056dc7:  mov rbx, [rax+0F8h]       ; rbx = transport object (conn→transport+0xF8)
0x1c0056dce:  lock xadd [rbx+10h], esi   ; increment transport refcount by 2
0x1c0056dd3:  mov rcx, [rdi+10h]        ; rcx = conn+0x10 (handle/transport context)
0x1c0056dd7:  lea rax, AfdTLCloseConnectionHandleComplete  ; default callback
0x1c0056dde:  mov [rsp+38h+var_18], rax ; store callback in local struct
0x1c0056de3:  lea rdx, [rsp+38h+var_18] ; rdx = &local_struct
0x1c0056de8:  mov rax, [rdi+18h]        ; rax = conn+0x18 (function pointer table)
0x1c0056dec:  mov [rsp+38h+var_10], rdi ; store conn in local struct
0x1c0056df1:  mov rax, [rax]            ; rax = *function_pointer_table → GADGET TARGET
0x1c0056df4:  call cs:__guard_dispatch_icall_fptr  ; INDIRECT CALL → our controlled function
0x1c0056dfa:  mov rcx, rbx              ; rcx = transport object
0x1c0056dfd:  call AfdTlDereferenceTransport  ; dereference transport
0x1c0056e02:  mov rbx, [rsp+38h+arg_0]  ; epilogue
0x1c0056e07:  mov rsi, [rsp+38h+arg_8]
0x1c0056e0c:  mov rdi, [rsp+38h+arg_10]
0x1c0056e11:  add rsp, 30h
0x1c0056e15:  pop r14
0x1c0056e17:  retn                      ; return to AfdCloseCore
```

**After the gadget returns → `AfdTlDereferenceTransport` → `AfdCloseConnection` returns (retn).**

### E2. Full Return Chain

```
Gadget call (0x1c0056df4)
  ↓ returns
AfdTlDereferenceTransport (0x1c0056dfd)
  → NmrClientDetachProviderComplete (NMR — Network Module Registrar)
  ↓ returns
AfdCloseConnection retn (0x1c0056e17)
  ↓ returns to
AfdCloseCore at 0x1c00373ff
  → mov [rbx+148h], rdi (store conn ptr)
  → AFDETW_TRACECLOSE (ETW trace only)
  → AfdDereferenceEndpointInline (endpoint refcount decrement)
    → pool lookaside: ExpInterlockedPushEntrySList / ExQueryDepthSList
    → OR AfdQueueWorkItem(AfdFreeEndpoint/AfdFreeEndpointTditl)
      → AfdFreeEndpointResources (cleans up: ZwClose, ObfDereferenceObject, ExFreePoolWithTag, etc.)
  → return 0
  ↓ returns to
AfdClose at 0x1c0037339
  → return value from AfdCloseCore
  ↓ returns to
AfdDispatch at 0x1c0053e76
  → a2->IoStatus.Status = v7
  → IofCompleteRequest(a2, AfdPriorityBoost)  [I/O manager IRP completion]
  → return v7
  ↓ returns to
I/O Manager (ntoskrnl) — IRP_MJ_CLOSE dispatch complete
  ↓
NtClose system service
  ↓
User mode (closesocket/NtClose returns)
```

### E3. GDI Access Check — Every Function in the Return Path

**42 unique functions** traversed in the return path. Categorized:

| Category | Functions | GDI? |
|---|---|---|
| ETW/Tracing | AFDETW_TRACECLOSE, AFDETW_TRACESTATUS, EtwEx_tidActivityInfo, WPP_SF_q, WPP_SF_qq, WPP_SF_d | NO |
| Network/TDI | NmrClientDetachProviderComplete, AfdTdiClearVcEventHandlers, AfdTlDereferenceTransport, AfdFreeTransportInfo, AfdFreeNPConnectionResources, AfdIssueDeviceControl | NO |
| Memory/Pool | ExFreePoolWithTag, ExpInterlockedPushEntrySList, ExQueryDepthSList, PplpLazyInitializeLookasideList, PsReturnPoolQuota | NO |
| Object Manager | ObfDereferenceObject, ObDereferenceSecurityDescriptor, ZwClose | NO |
| Synchronization | KeInitializeEvent, KeWaitForSingleObject | NO |
| I/O Manager | IofCompleteRequest | NO |
| AFD Internal | AfdClose, AfdCloseCore, AfdCloseConnection, AfdDereferenceEndpointInline, AfdFreeEndpoint, AfdFreeEndpointTditl, AfdFreeEndpointResources, AfdFreeConnectionEx, AfdFreeConnectionResources, AfdRefreshConnection, AfdQueueWorkItem, AfdReturnBuffer, AfdFreeQueuedConnections, AfdRioCleanupRioState, AfdRioCleanupRegistrationDomain, AfdDereferenceGroup, AfdDereferenceCompartment, AfdRemoveEndpointFromList, AfdFreeConnectDataBuffers, AfdSanCleanupHelper, AfdTLCloseConnectionHandleComplete, AfdDispatch | NO |

**py_eval result:**
```
Total functions in return path: 42
GDI/win32k functions found: 0
  NONE - return path is completely GDI-free
```

### E4. Specific Checks

**Does AfdCloseCore call any win32k/GDI function after AfdCloseConnection returns?**
NO. After AfdCloseConnection returns, AfdCloseCore executes:
- `mov [rbx+148h], rdi` (store conn ptr — memory write, not GDI)
- `mov byte ptr [rbx+2], 6` (set endpoint state — memory write, not GDI)
- `call AFDETW_TRACECLOSE` (ETW tracing — kernel event, not GDI)
- `call AfdDereferenceEndpointInline` (pool/lookaside refcount — not GDI)
- `return 0`

**Does the I/O manager cleanup path touch GDI?**
NO. `IofCompleteRequest` is a pure kernel I/O infrastructure function in ntoskrnl.exe. It completes the IRP, invokes completion routines, and returns. The IRP_MJ_CLOSE dispatch path through the I/O manager (`IopfCloseFile`/`IoCloseFile` → driver dispatch → `IofCompleteRequest`) has no dependency on the win32k/GDI subsystem. The I/O manager operates entirely within the kernel I/O layer.

### LINK E VERDICT: **YES** — The return path from _setjmp to user mode is completely free of GDI access.

**Evidence:**
1. After the gadget call at `0x1c0056df4`, the only function called is `AfdTlDereferenceTransport`, which calls only `NmrClientDetachProviderComplete` (NMR kernel API, not GDI)
2. AfdCloseConnection returns via `retn` to AfdCloseCore, which calls only `AFDETW_TRACECLOSE` (ETW) and `AfdDereferenceEndpointInline` (pool lookaside/work item) — neither touches GDI
3. AfdDereferenceEndpointInline's deepest callees (`AfdFreeEndpointResources`, `AfdFreeEndpoint`) use only: ZwClose, ObfDereferenceObject, ExFreePoolWithTag, PsReturnPoolQuota, KeInitializeEvent, KeWaitForSingleObject, pool lookaside functions, and ETW — zero GDI
4. AfdCloseConnection's own cleanup path (via `AfdFreeConnectionEx` → `AfdFreeConnectionResources`) uses: AfdIssueDeviceControl, ZwClose, ObfDereferenceObject, ExFreePoolWithTag, PsReturnPoolQuota, pool lookaside — zero GDI
5. AfdDispatch calls `IofCompleteRequest` (I/O manager IRP completion — pure kernel I/O, not GDI)
6. The I/O manager's IRP_MJ_CLOSE path back to NtClose and user mode is kernel I/O infrastructure with no win32k/GDI dependency
7. **42 functions** in the complete return path — **0 GDI/win32k calls**

---

## Summary

| Link | Question | Verdict | Key Evidence |
|---|---|---|---|
| **D** | Does the race trigger AfdCloseConnection on our sprayed data? | **YES** | `mov rdi, [rbx+0B0h]` at 0x1c00373d1 is spinlock-free; `lock xadd [rdi+30h], -1` with conn+0x30=1 returns old=1, new=0; `cmp eax,1` → ZF=1 → `jz` taken → `call AfdCloseConnection` executed on sprayed connection |
| **E** | Is the return path from _setjmp to user mode completely free of GDI access? | **YES** | 42 functions in the full return path (gadget → AfdTlDereferenceTransport → AfdCloseConnection ret → AfdCloseCore → AfdClose → AfdDispatch → IofCompleteRequest → I/O mgr → NtClose → user mode); zero GDI/win32k calls; all functions are kernel networking, I/O, memory, object manager, synchronization, or ETW |
