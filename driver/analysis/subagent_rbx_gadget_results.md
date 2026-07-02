# RBX Write Gadget Analysis - ntoskrnl.exe

**Target:** ntoskrnl.exe (IDA Pro pid 4024, IDB: C:\Users\ruar1337\Desktop\ntoskrnl.exe.i64)
**Date:** 2026-07-02
**Objective:** Find exported functions that write RBX to [RCX+offset], classify LEAF vs HAS_CALLS, verify LEAF functions.

---

## Summary

- Total byte pattern matches (all functions): 157
- Matches in EXPORTED functions: 137
- TRUE LEAF (no calls in ANY chunk): **2**
- HAS_CALLS: 135

### Byte Patterns Scanned

| Pattern | Bytes | Offset | Matches |
|---------|-------|--------|---------|
| mov [rcx], rbx | 48 89 19 | 0x00 | 75 |
| mov [rcx+8], rbx | 48 89 59 08 | 0x08 | 53 |
| mov [rcx+0x10], rbx | 48 89 59 10 | 0x10 | 6 |
| mov [rcx+0x18], rbx | 48 89 59 18 | 0x18 | 11 |
| mov [rcx+0x20], rbx | 48 89 59 20 | 0x20 | 8 |
| mov [rcx+0x28], rbx | 48 89 59 28 | 0x28 | 1 |
| mov [rcx+0x30], rbx | 48 89 59 30 | 0x30 | 0 |
| mov [rcx+0x38], rbx | 48 89 59 38 | 0x38 | 3 |
| mov [rcx+0x40], rbx | 48 89 59 40 | 0x40 | 0 |

---

## TRUE LEAF Functions (2)

### 1. _setjmp @ 0x140408ed0 (141 bytes, 1 chunk)

Instruction: mov [rcx+8], rbx at 0x140408ed3 (offset 0x08)

Disassembly:
```
_setjmp:
  140408ed0:  mov [rcx], rdx              ; [RCX+0x00] = RDX
  140408ed3:  mov [rcx+8], rbx            ; <-- TARGET: [RCX+0x08] = RBX
  140408ed7:  mov [rcx+18h], rbp          ; [RCX+0x18] = RBP
  140408edb:  mov [rcx+20h], rsi          ; [RCX+0x20] = RSI
  140408edf:  mov [rcx+28h], rdi          ; [RCX+0x28] = RDI
  140408ee3:  mov [rcx+30h], r12          ; [RCX+0x30] = R12
  140408ee7:  mov [rcx+38h], r13          ; [RCX+0x38] = R13
  140408eeb:  mov [rcx+40h], r14          ; [RCX+0x40] = R14
  140408eef:  mov [rcx+48h], r15          ; [RCX+0x48] = R15
  140408ef3:  lea r8, [rsp+arg_0]         ; r8 = RSP+8
  140408ef8:  mov [rcx+10h], r8           ; [RCX+0x10] = RSP (stack leak)
  140408efc:  mov r8, [rsp+0]             ; r8 = return address from [RSP]
  140408f00:  mov [rcx+50h], r8           ; [RCX+0x50] = retaddr (ROP slot consumed)
  140408f04:  stmxcsr dword ptr [rcx+58h] ; [RCX+0x58] = MXCSR
  140408f08:  movdqa xmmword ptr [rcx+60h], xmm6   ; [RCX+0x60] = XMM6
  140408f0d:  movdqa xmmword ptr [rcx+70h], xmm7   ; [RCX+0x70] = XMM7
  140408f12:  movdqa xmmword ptr [rcx+80h], xmm8   ; [RCX+0x80] = XMM8
  140408f1b:  movdqa xmmword ptr [rcx+90h], xmm9   ; [RCX+0x90] = XMM9
  140408f24:  movdqa xmmword ptr [rcx+0A0h], xmm10 ; [RCX+0xA0] = XMM10
  140408f2d:  movdqa xmmword ptr [rcx+0B0h], xmm11 ; [RCX+0xB0] = XMM11
  140408f36:  movdqa xmmword ptr [rcx+0C0h], xmm12 ; [RCX+0xC0] = XMM12
  140408f3f:  movdqa xmmword ptr [rcx+0D0h], xmm13 ; [RCX+0xD0] = XMM13
  140408f48:  movdqa xmmword ptr [rcx+0E0h], xmm14 ; [RCX+0xE0] = XMM14
  140408f51:  movdqa xmmword ptr [rcx+0F0h], xmm15 ; [RCX+0xF0] = XMM15
  140408f5a:  xor eax, eax               ; return 0
  140408f5c:  retn
```

Verification:
- Writes RBX to [RCX+0x08]: YES
- Does NOT modify RBX before the write: YES (RBX read at instruction #2, no prior modification)
- Returns cleanly: YES (xor eax, eax; retn)
- Doesn't crash on arbitrary RCX: NO - writes 256 bytes to [RCX+0x00] through [RCX+0xFF]

Side Effects (CRITICAL):
- Writes RDX to [RCX+0x00]
- Writes RSP to [RCX+0x10] (stack pointer leak)
- Writes RBP, RSI, RDI, R12-R15 to [RCX+0x18] through [RCX+0x48]
- Reads return address from [RSP] and writes to [RCX+0x50] (consumes ROP chain slot)
- Writes MXCSR to [RCX+0x58] via stmxcsr
- Writes XMM6-XMM15 to [RCX+0x60] through [RCX+0xF0] (160 bytes of XMM state)
- Total write span: 256 bytes (0x100)

Gadget Assessment: Context-dump primitive, NOT a clean write-what-where gadget. RCX must point to valid writable buffer of at least 256 bytes. The [rsp] read for return address consumes the next ROP chain entry. Usable as full register-context save primitive but too noisy for targeted single-field writes.

---

### 2. _setjmpex @ 0x140408f90 (141 bytes, 1 chunk)

Instruction: mov [rcx+8], rbx at 0x140408f93 (offset 0x08)

Disassembly:
```
_setjmpex:
  140408f90:  mov [rcx], rdx              ; [RCX+0x00] = RDX
  140408f93:  mov [rcx+8], rbx            ; <-- TARGET: [RCX+0x08] = RBX
  140408f97:  mov [rcx+18h], rbp          ; [RCX+0x18] = RBP
  140408f9b:  mov [rcx+20h], rsi          ; [RCX+0x20] = RSI
  140408f9f:  mov [rcx+28h], rdi          ; [RCX+0x28] = RDI
  140408fa3:  mov [rcx+30h], r12          ; [RCX+0x30] = R12
  140408fa7:  mov [rcx+38h], r13          ; [RCX+0x38] = R13
  140408fab:  mov [rcx+40h], r14          ; [RCX+0x40] = R14
  140408faf:  mov [rcx+48h], r15          ; [RCX+0x48] = R15
  140408fb3:  lea r8, [rsp+arg_0]         ; r8 = RSP+8
  140408fb8:  mov [rcx+10h], r8           ; [RCX+0x10] = RSP
  140408fbc:  mov r8, [rsp+0]             ; r8 = return address
  140408fc0:  mov [rcx+50h], r8           ; [RCX+0x50] = retaddr
  140408fc4:  stmxcsr dword ptr [rcx+58h] ; [RCX+0x58] = MXCSR
  140408fc8:  movdqa xmmword ptr [rcx+60h], xmm6   ; [RCX+0x60] = XMM6
  140408fcd:  movdqa xmmword ptr [rcx+70h], xmm7   ; [RCX+0x70] = XMM7
  140408fd2:  movdqa xmmword ptr [rcx+80h], xmm8   ; [RCX+0x80] = XMM8
  140408fdb:  movdqa xmmword ptr [rcx+90h], xmm9   ; [RCX+0x90] = XMM9
  140408fe4:  movdqa xmmword ptr [rcx+0A0h], xmm10 ; [RCX+0xA0] = XMM10
  140408fed:  movdqa xmmword ptr [rcx+0B0h], xmm11 ; [RCX+0xB0] = XMM11
  140408ff6:  movdqa xmmword ptr [rcx+0C0h], xmm12 ; [RCX+0xC0] = XMM12
  140408fff:  movdqa xmmword ptr [rcx+0D0h], xmm13 ; [RCX+0xD0] = XMM13
  140409008:  movdqa xmmword ptr [rcx+0E0h], xmm14 ; [RCX+0xE0] = XMM14
  140409011:  movdqa xmmword ptr [rcx+0F0h], xmm15 ; [RCX+0xF0] = XMM15
  14040901a:  xor eax, eax               ; return 0
  14040901c:  retn
```

Verification:
- Writes RBX to [RCX+0x08]: YES
- Does NOT modify RBX before the write: YES (identical structure to _setjmp)
- Returns cleanly: YES (xor eax, eax; retn)
- Doesn't crash on arbitrary RCX: NO - writes 256 bytes total

Side Effects: Identical to _setjmp - full non-volatile register context dump.
Gadget Assessment: Same as _setjmp - context-dump primitive, not a clean write-what-where. Byte-identical structure to _setjmp.

---

## Previously Misclassified as LEAF (False Positives)

Three functions were initially classified as LEAF when only scanning the primary function chunk. Correctly reclassified as HAS_CALLS when scanning ALL chunks via idautils.Chunks():

### SepAdtDetermineInsertQueue @ 0x1403cb160
- Instruction at 0x1404b36a3 is in a TAIL chunk (not primary)
- True size across all chunks: 258 bytes (not 70)
- Calls: ExAllocatePoolWithTag, ExQueueWorkItem, memset, SepAdtGenerateDiscardAudit
- Also zeros RBX before the write (xor ebx, ebx, then mov [rcx], rbx writes 0)

### HalpHvInitMcaPcrContext @ 0x1403c5150
- Instruction at 0x1404b0a30 is in a TAIL chunk (not primary)
- True size across all chunks: 696 bytes (not 81)
- Calls: KeGetCurrentProcessorNumberEx, HalpMmAllocCtxAlloc, KeBugCheckEx, memset, ExAllocatePoolWithTag, HalpGetMcaPcrContext, ExFreePoolWithTag, KeSetTargetProcessorDpcEx
- The write is mov [rcx+0x20], rbx where RCX = RBX at that point (self-referential)

### AslPathToNetworkPathNt @ 0x140753a2c
- Instruction at 0x140753a4e IS in primary chunk
- True size across all chunks: 295 bytes (not 113)
- Calls: AslAlloc, wcscpy_s, wcscat_s, AslLogCallPrintf
- Zeros RBX before write: v2 = 0 (xor ebx, ebx) then *a1 = nullptr (writes 0, not controlled value)

---

## Complete Exported Function List (137 functions, sorted by true size)

| # | Function | Address | TrueSize | Off | Type | Insn@ | ChunkLoc | Chunks |
|---|----------|---------|----------|-----|------|-------|----------|--------|
| 1 | MiTryToAcquireExpansionLockAtDpc | 0x1402ec668 | 41 | 0x00 | CALLS | 0x1402ec67b | primary | 1 |
| 2 | SepInitializeSharedSidMap | 0x14079e22c | 54 | 0x00 | CALLS | 0x14079e240 | primary | 1 |
| 3 | RtlSetConsoleSessionForegroundProcessId | 0x140695df0 | 63 | 0x08 | CALLS | 0x14080a4d2 | tail | 2 |
| 4 | PspCompleteServerSiloShutdown | 0x140905e70 | 77 | 0x18 | CALLS | 0x140905ead | primary | 1 |
| 5 | KiProcessDisconnectList | 0x140521c2c | 80 | 0x08 | CALLS | 0x140521c4f | primary | 1 |
| 6 | RaspClearCache | 0x1409f35fc | 82 | 0x08 | CALLS | 0x1409f3630 | primary | 1 |
| 7 | IopInterlockedInsertTailList | 0x1403c8dc0 | 84 | 0x00 | CALLS | 0x1403c8df0 | primary | 2 |
| 8 | IopInterlockedInsertHeadList | 0x1403c4bb8 | 84 | 0x08 | CALLS | 0x1403c4be8 | primary | 2 |
| 9 | PiDrvDbUnloadNodeDpcRoutine | 0x14032b950 | 100 | 0x18 | CALLS | 0x14032b990 | primary | 1 |
| 10 | CmpTransEnlistUowInCmTrans | 0x1403613fc | 108 | 0x00 | CALLS | 0x140361434 | primary | 2 |
| 11 | RtlInitEnumerationHashTable | 0x14031eb70 | 114 | 0x08 | CALLS | 0x14031ebb9 | primary | 2 |
| 12 | PipAddBindingId | 0x1407b6658 | 128 | 0x08 | CALLS | 0x1407b66b5 | primary | 2 |
| 13 | PspHardDereferenceSiloWorker | 0x14020098c | 129 | 0x18 | CALLS | 0x1402009ee | primary | 2 |
| 14 | MiInitializeImageExtents | 0x1408cffdc | 132 | 0x10 | CALLS | 0x1408d0049 | primary | 1 |
| 15 | KeInsertDeviceQueue | 0x14051a8c0 | 134 | 0x00 | CALLS | 0x14051a91d | primary | 1 |
| 16 | MiAddEntryToImportList | 0x140545488 | 140 | 0x00 | CALLS | 0x1405454dc | primary | 1 |
| 17 | _setjmp | 0x140408ed0 | 141 | 0x08 | LEAF | 0x140408ed3 | primary | 1 |
| 18 | _setjmpex | 0x140408f90 | 141 | 0x08 | LEAF | 0x140408f93 | primary | 1 |
| 19 | PspPrepareEnclaveThreadWait | 0x14090e380 | 142 | 0x00 | CALLS | 0x14090e3f1 | primary | 1 |
| 20 | WdipSemFreePool | 0x140930188 | 145 | 0x08 | CALLS | 0x1409301d7 | primary | 1 |
| 21 | FsRtlNotifyCompleteIrpList | 0x1406758e8 | 150 | 0x08 | CALLS | 0x140675931 | primary | 1 |
| 22 | DmrpRmrrTreeAddNewScope | 0x1404e8878 | 154 | 0x00 | CALLS | 0x1404e88f0 | primary | 1 |
| 23 | CmpSignalDeferredPosts | 0x1406e05a0 | 155 | 0x08 | CALLS | 0x1406e05e0 | primary | 2 |
| 24 | AlpcpInsertMessagePendingQueue | 0x1405e3c64 | 159 | 0x08 | CALLS | 0x1405e3cd1 | primary | 1 |
| 25 | AlpcpInsertMessageDirectQueue | 0x14067f608 | 159 | 0x08 | CALLS | 0x14067f675 | primary | 1 |
| 26 | AlpcpInsertMessageLargeMessageQueue | 0x14068b124 | 159 | 0x08 | CALLS | 0x14068b191 | primary | 1 |
| 27 | AlpcpInsertMessageMainQueue | 0x14069de84 | 159 | 0x08 | CALLS | 0x14069def1 | primary | 1 |
| 28 | CmpCleanupParseContext | 0x1406ce840 | 166 | 0x08 | CALLS | 0x1406ce879 | primary | 2 |
| 29 | IvmdFindDeviceEntry | 0x1404e4b58 | 169 | 0x00 | CALLS | 0x1404e4be1 | primary | 1 |
| 30 | PiPnpRtlGetCurrentOperation | 0x1406b015c | 170 | 0x00 | CALLS | 0x1406b0189 | primary | 1 |
| 31 | KeInsertByKeyDeviceQueue | 0x14051a800 | 172 | 0x08 | CALLS | 0x14051a881 | primary | 1 |
| 32 | HalpInterruptSetLineSpecificOverride | 0x1403ef6c4 | 180 | 0x00 | CALLS | 0x1403ef754 | primary | 1 |
| 33 | IommuGetLibraryContext | 0x1404d8d10 | 180 | 0x08 | CALLS | 0x1404d8da1 | primary | 1 |
| 34 | RtlStringCbCatExA | 0x1404b6018 | 182 | 0x00 | CALLS | 0x1404b60ba | primary | 1 |
| 35 | TtmpAcquireSessionById | 0x1408ff560 | 193 | 0x00 | CALLS | 0x1408ff582 | primary | 1 |
| 36 | PiDrvDbUnloadNodeWorkerCallback | 0x140725ae0 | 194 | 0x18 | CALLS | 0x140725b71 | primary | 1 |
| 37 | HalpIommuCreateDmarPageTable | 0x1404db8fc | 201 | 0x00 | CALLS | 0x1404db982 | primary | 1 |
| 38 | RtlpHpVsContextMultiAlloc | 0x140303964 | 206 | 0x00 | CALLS | 0x140303a21 | primary | 1 |
| 39 | PiSwAddPdoAssociation | 0x140770770 | 206 | 0x00 | CALLS | 0x1407707e0 | primary | 2 |
| 40 | WmipUpdateAddGuid | 0x140933788 | 212 | 0x00 | CALLS | 0x14093383f | primary | 1 |
| 41 | ExpWnfDeleteScopeInstances | 0x14095cb6c | 221 | 0x08 | CALLS | 0x14095cbfe | primary | 1 |
| 42 | WmipFindGEByGuid | 0x1406b7fb0 | 224 | 0x08 | CALLS | 0x1406b8080 | primary | 1 |
| 43 | HalpHvMapDeviceMsiRange | 0x1409a7388 | 230 | 0x10 | CALLS | 0x1409a7438 | primary | 1 |
| 44 | VfTargetEtwRegister | 0x1409d6f64 | 232 | 0x00 | CALLS | 0x1409d700f | primary | 1 |
| 45 | HalpDmaUseEmergencyLogicalAddressResources | 0x1404b84f8 | 242 | 0x00 | CALLS | 0x1404b8566 | primary | 1 |
| 46 | HalpDmaStartWcb | 0x1404b8400 | 242 | 0x08 | CALLS | 0x1404b8465 | primary | 1 |
| 47 | KsepCacheDeviceInsertData | 0x1407cc530 | 244 | 0x00 | CALLS | 0x1407cc5bc | primary | 2 |
| 48 | TtmpQueueTerminalDisplayStateOntoDevice | 0x1408fd190 | 244 | 0x08 | CALLS | 0x1408fd268 | primary | 1 |
| 49 | IopInsertPassiveInterruptBlock | 0x14050d3d4 | 246 | 0x00 | CALLS | 0x14050d430 | primary | 1 |
| 50 | CmpGetKnownHivePathNode | 0x140a8ebcc | 247 | 0x00 | CALLS | 0x140a8eca6 | primary | 1 |
| 51 | MiScanPagefiles | 0x14033c2fc | 255 | 0x18 | CALLS | 0x14047f09a | tail | 2 |
| 52 | SmPrepareForFatalHeapCorruption | 0x14059fbe0 | 256 | 0x08 | CALLS | 0x14059fc69 | primary | 1 |
| 53 | PspGetNextJobProcess | 0x14068edb0 | 256 | 0x08 | CALLS | 0x14068ee06 | primary | 2 |
| 54 | SepAdtDetermineInsertQueue | 0x1403cb160 | 258 | 0x00 | CALLS | 0x1404b36a3 | tail | 2 |
| 55 | HalpIommuCreateIncreaseAliasTrack | 0x1403ef980 | 262 | 0x00 | CALLS | 0x1403efa43 | primary | 1 |
| 56 | SmKmEtwLogStoreChange | 0x14092afdc | 266 | 0x00 | CALLS | 0x14092b07b | primary | 1 |
| 57 | WbMoveHeapExecutedBlockToBackOfLRU | 0x1406c6310 | 267 | 0x00 | CALLS | 0x1406c63a0 | primary | 2 |
| 58 | MiBeginPageAccessor | 0x1402954c8 | 269 | 0x20 | CALLS | 0x140295526 | primary | 2 |
| 59 | TtmpSetDisplayRequestEnded | 0x1409001d0 | 272 | 0x08 | CALLS | 0x140900233 | primary | 1 |
| 60 | ViTargetTrackContiguousMemory | 0x1409d76b0 | 272 | 0x08 | CALLS | 0x1409d7790 | primary | 1 |
| 61 | EtwpAddKmRegEntry | 0x140762550 | 275 | 0x08 | CALLS | 0x1407625ed | primary | 2 |
| 62 | KiTpAccessMemory | 0x140a12008 | 280 | 0x20 | CALLS | 0x140a12103 | primary | 1 |
| 63 | HalpDmaAllocateEmergencyResources | 0x140a65f28 | 289 | 0x00 | CALLS | 0x140a65f95 | primary | 2 |
| 64 | AslPathToNetworkPathNt | 0x140753a2c | 295 | 0x00 | CALLS | 0x140753a4e | primary | 2 |
| 65 | KiInsertSecondarySignalList | 0x140519318 | 296 | 0x00 | CALLS | 0x14051937b | primary | 1 |
| 66 | PoFxSetTargetDripsDevicePowerState | 0x1408e44c0 | 302 | 0x00 | CALLS | 0x1408e45cf | primary | 1 |
| 67 | PnprMmAddRange | 0x1408ae420 | 304 | 0x08 | CALLS | 0x1408ae4dd | primary | 1 |
| 68 | MiInsertNewCombineBlocks | 0x14036b1a8 | 307 | 0x00 | CALLS | 0x14036b222 | primary | 2 |
| 69 | WmipLinkDataSourceToList | 0x140757600 | 314 | 0x00 | CALLS | 0x1407576f0 | primary | 2 |
| 70 | RtlInsertElementGenericTableFullAvl | 0x14032dcf0 | 321 | 0x08 | CALLS | 0x14032ddee | primary | 2 |
| 71 | TtmiCreateEventQueue | 0x1409053a8 | 331 | 0x00 | CALLS | 0x1409054c3 | primary | 1 |
| 72 | PfSnInitializePrefetcher | 0x140a6aa00 | 346 | 0x10 | CALLS | 0x140a6ab21 | primary | 1 |
| 73 | FopInitializeFonts | 0x140a95f14 | 350 | 0x00 | CALLS | 0x140a96004 | primary | 2 |
| 74 | CmpFreeCallbackObjectContexts | 0x1405d6b4c | 352 | 0x08 | CALLS | 0x1405d6c19 | primary | 2 |
| 75 | IopInitializeActiveConnectBlock | 0x140761d44 | 356 | 0x00 | CALLS | 0x140837484 | tail | 2 |
| 76 | PfpServiceMainThreadBoost | 0x14038c848 | 361 | 0x00 | CALLS | 0x14038c8d7 | primary | 2 |
| 77 | ResFwGetContext | 0x1409f1298 | 365 | 0x00 | CALLS | 0x1409f12c4 | primary | 2 |
| 78 | TlgRegisterAggregateProviderEx | 0x1407a4f3c | 374 | 0x00 | CALLS | 0x1407a500e | primary | 2 |
| 79 | ExRegisterCallback | 0x14037e950 | 387 | 0x08 | CALLS | 0x14037e9e4 | primary | 2 |
| 80 | CmRegisterMachineHiveLoadedNotification | 0x140799bd0 | 398 | 0x00 | CALLS | 0x140799ca4 | primary | 2 |
| 81 | ViDeadlockMergeNodes | 0x1409df614 | 404 | 0x00 | CALLS | 0x1409df70f | primary | 1 |
| 82 | WmipQueueLegacyEtwWork | 0x1407c7688 | 412 | 0x00 | CALLS | 0x14085e0bd | tail | 2 |
| 83 | HalpVpptAcknowledgeInterrupt | 0x1404c0650 | 412 | 0x08 | CALLS | 0x1404c0734 | primary | 1 |
| 84 | DeleteNodeFromTree | 0x14032dad0 | 426 | 0x08 | CALLS | 0x14032dbec | primary | 1 |
| 85 | KeInsertPriQueue | 0x14023b8e0 | 441 | 0x08 | CALLS | 0x14042d746 | tail | 2 |
| 86 | PnprMapPhysicalPages | 0x1409add1c | 447 | 0x00 | CALLS | 0x1409addd9 | primary | 1 |
| 87 | EtwpAddUmRegEntry | 0x1405ead90 | 453 | 0x08 | CALLS | 0x1405eaea7 | primary | 2 |
| 88 | PnpInsertEventInQueue | 0x140634c88 | 477 | 0x00 | CALLS | 0x140634d83 | primary | 2 |
| 89 | FsRtlIsHpfsDbcsLegal | 0x14088cba0 | 492 | 0x08 | CALLS | 0x14088cc42 | primary | 1 |
| 90 | MiLockMemoryLists | 0x1403888d0 | 503 | 0x08 | CALLS | 0x1403889ff | primary | 1 |
| 91 | KeRegisterBugCheckReasonCallback | 0x14039df60 | 508 | 0x00 | CALLS | 0x14039e02d | primary | 2 |
| 92 | CmpVolumeManagerGetContextForFile | 0x140721284 | 511 | 0x00 | CALLS | 0x14072141e | primary | 2 |
| 93 | RtlAvlInsertNodeEx | 0x140296bd0 | 514 | 0x00 | CALLS | 0x140296d29 | primary | 1 |
| 94 | HvlDmaMapDeviceSparsePages | 0x1404f4710 | 516 | 0x08 | CALLS | 0x1404f47eb | primary | 1 |
| 95 | KiRequestProcessInSwap | 0x1402f28a0 | 524 | 0x00 | CALLS | 0x1402f294b | primary | 2 |
| 96 | ExpWakePushLock | 0x140271c20 | 537 | 0x20 | CALLS | 0x140271d8c | primary | 2 |
| 97 | WmipUpdateModifyGuid | 0x1407c4800 | 548 | 0x08 | CALLS | 0x14085cf7d | tail | 2 |
| 98 | PopFxCreateDeviceCommon | 0x1403be568 | 556 | 0x18 | CALLS | 0x1403be632 | primary | 1 |
| 99 | PiUpdateDriverDBCache | 0x14077e2ac | 565 | 0x08 | CALLS | 0x14084d61c | tail | 2 |
| 100 | ExpHpCompactionRoutine | 0x14027b0d0 | 568 | 0x00 | CALLS | 0x14027b279 | primary | 2 |
| 101 | SepQueueWorkItem | 0x14034d010 | 584 | 0x18 | CALLS | 0x14034d143 | primary | 2 |
| 102 | HalpDmaAllocateDomain | 0x1403c6bb8 | 596 | 0x00 | CALLS | 0x1403c6c32 | primary | 2 |
| 103 | MiReserveDriverPtes | 0x14075f5b4 | 602 | 0x08 | CALLS | 0x14075f750 | primary | 2 |
| 104 | PiDcResetChildDeviceContainerCallback | 0x1408a35e0 | 609 | 0x00 | CALLS | 0x1408a37e9 | primary | 1 |
| 105 | PiDevCfgConvertPropertyFromValue | 0x140734a5c | 684 | 0x00 | CALLS | 0x140734ad5 | primary | 2 |
| 106 | MiDeleteLargeUserPde | 0x14054f89c | 690 | 0x28 | CALLS | 0x14054fb06 | primary | 1 |
| 107 | HalpHvInitMcaPcrContext | 0x1403c5150 | 696 | 0x20 | CALLS | 0x1404b0a30 | tail | 2 |
| 108 | PopEtEnergyTrackerCreate | 0x1407cb888 | 718 | 0x08 | CALLS | 0x1407cba53 | primary | 2 |
| 109 | KeRegisterObjectNotification | 0x140202ed8 | 735 | 0x00 | CALLS | 0x140202f56 | primary | 2 |
| 110 | PspCopyAndFixupParameters | 0x140612c14 | 737 | 0x20 | CALLS | 0x140612e29 | primary | 2 |
| 111 | CmNotifyRunDown | 0x1406c5510 | 741 | 0x00 | CALLS | 0x140815782 | tail | 2 |
| 112 | PoRegisterPowerSettingCallback | 0x1406f4a10 | 752 | 0x00 | CALLS | 0x1406f4b94 | primary | 2 |
| 113 | FsRtlAddToTunnelCacheEx | 0x1406689e0 | 827 | 0x00 | CALLS | 0x140668cdb | primary | 2 |
| 114 | DrvDbCreateDatabaseNode | 0x1407a45b8 | 866 | 0x00 | CALLS | 0x1407a46ea | primary | 2 |
| 115 | RtlpHpSegMgrVaCtxFree | 0x140594b70 | 875 | 0x00 | CALLS | 0x140594c42 | primary | 1 |
| 116 | MiClearPageFileHash | 0x140324cd4 | 878 | 0x00 | CALLS | 0x140324dd8 | primary | 2 |
| 117 | PfpFlushBuffers | 0x1406315b0 | 926 | 0x00 | CALLS | 0x140631649 | primary | 2 |
| 118 | IopTranslateAndAdjustReqDesc | 0x1407c2fe4 | 957 | 0x18 | CALLS | 0x1407c3238 | primary | 2 |
| 119 | KiMarkBugCheckRegions | 0x1403dc0d8 | 984 | 0x00 | CALLS | 0x1403dc1c0 | primary | 1 |
| 120 | AlpcpReplyLegacySynchronousRequest | 0x1405e1bdc | 998 | 0x18 | CALLS | 0x1405e1f73 | primary | 1 |
| 121 | CmpNotifyChangeKey | 0x1406dc7b0 | 1002 | 0x08 | CALLS | 0x1406dc827 | primary | 2 |
| 122 | FsRtlPrepareMdlWriteDev | 0x14088b220 | 1004 | 0x08 | CALLS | 0x14088b561 | primary | 1 |
| 123 | FsRtlCopyWrite | 0x14088a800 | 1125 | 0x08 | CALLS | 0x14088abcb | primary | 1 |
| 124 | ExAcquireFastResourceSharedStarveExclusive | 0x14038e9b0 | 1253 | 0x00 | CALLS | 0x14038eadd | primary | 2 |
| 125 | ExAcquireFastResourceShared | 0x14038ec80 | 1265 | 0x00 | CALLS | 0x14038ef70 | primary | 2 |
| 126 | IoCreateDevice | 0x140719050 | 1273 | 0x08 | CALLS | 0x1407191fb | primary | 2 |
| 127 | ExAcquireFastResourceExclusive | 0x14038e5d0 | 1276 | 0x00 | CALLS | 0x14038e8c2 | primary | 2 |
| 128 | PiPnpRtlObjectEventWorker | 0x1407463d0 | 1422 | 0x00 | CALLS | 0x140828493 | tail | 2 |
| 129 | MiScrubLargeMappedPage | 0x1405639c8 | 1467 | 0x00 | CALLS | 0x140563e5b | primary | 1 |
| 130 | MiPrepareImagePagesForHotPatch | 0x14053eb0c | 1479 | 0x38 | CALLS | 0x14053f03c | primary | 1 |
| 131 | KiInitializeUserApc | 0x140309ce4 | 1659 | 0x08 | CALLS | 0x14030a077 | primary | 2 |
| 132 | PopBatteryWorker | 0x14077f630 | 3288 | 0x00 | CALLS | 0x14084dc40 | tail | 2 |
| 133 | RtlpHpVsChunkSplit | 0x1402bf820 | 3826 | 0x20 | CALLS | 0x1402c0417 | primary | 2 |
| 134 | MiUserFault | 0x14020d730 | 3928 | 0x38 | CALLS | 0x14020d776 | primary | 1 |
| 135 | MiBuildForkPte | 0x1405581fc | 4027 | 0x00 | CALLS | 0x140558e6b | primary | 1 |
| 136 | MiStealPage | 0x140334cb4 | 5733 | 0x00 | CALLS | 0x140335d0a | primary | 1 |
| 137 | SepVariableInitialization | 0x140a48b6c | 7436 | 0x00 | CALLS | 0x140a4a835 | primary | 1 |
