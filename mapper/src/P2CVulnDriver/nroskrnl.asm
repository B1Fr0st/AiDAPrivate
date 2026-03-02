Function: 140aa1b74
Prototype: __int64 __fastcall(__int64)

--- Decompiled C/C++ ---
__int64 __fastcall MmVerifyCallbackFunction(__int64 a1)
{
  return MmVerifyCallbackFunctionCheckFlags(a1, 32);
}


--- Local Variables ---
// __int64 a1; // location: cx, size: 8
// __int64 ; // location: ax, size: 8


--- String Literals Referenced ---
// No string literals referenced.


--- Callers (Functions that call this one) ---
// --- Called by: MmVerifyCallbackFunction at 0x140aa1b74 (Depth: 0) ---
// Language: C/C++
```cpp
__int64 __fastcall MmVerifyCallbackFunction(__int64 a1)
{
  return MmVerifyCallbackFunctionCheckFlags(a1, 32);
}

```

// --- Called by: KeRegisterBoundCallback at 0x1405afd70 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall KeRegisterBoundCallback(__int64 a1)
{
  __int64 v2; // rbx
  __int64 v3; // rax
  __int64 v4; // rsi

  v2 = 0;
  if ( (unsigned int)MmVerifyCallbackFunction(a1) )
  {
    v3 = ExAllocateCallBack(a1, 0);
    v4 = v3;
    if ( v3 )
    {
      if ( (unsigned __int8)ExCompareExchangeCallBack(&KiBoundsCallback, v3, 0) )
        return a1;
      else
        PspUserApcKernelRoutine(v4);
    }
  }
  return v2;
}

```



--- Callees (Functions this one calls) ---
// --- Calls: MmVerifyCallbackFunction at 0x140aa1b74 (Depth: 0) ---
// Language: C/C++
```cpp
__int64 __fastcall MmVerifyCallbackFunction(__int64 a1)
{
  return MmVerifyCallbackFunctionCheckFlags(a1, 32);
}

```

// --- Calls: MmVerifyCallbackFunctionCheckFlags at 0x1404f5c54 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall MmVerifyCallbackFunctionCheckFlags(__int64 a1, int a2)
{
  unsigned int v3; // ebx
  __int64 v4; // rax

  v3 = 0;
  v4 = MiLockLoadedDataTableEntry(a1, 1);
  if ( v4 )
  {
    if ( !a2 || (a2 & *(_DWORD *)(v4 + 104)) != 0 )
      v3 = 1;
    MiUnlockLoadedDataTableEntry(v4, 1);
  }
  return v3;
}

```

// --- Calls: MiLockLoadedDataTableEntry at 0x14039845c (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall MiLockLoadedDataTableEntry(__int64 a1, int a2)
{
  __int64 DataTableEntryByAddress; // rax
  __int64 v5; // r11
  __int64 v6; // rbx

  MiAcquireLoadLock(0);
  DataTableEntryByAddress = MmFindDataTableEntryByAddress(a1);
  v6 = DataTableEntryByAddress;
  if ( DataTableEntryByAddress )
  {
    MiLockLoaderEntry(DataTableEntryByAddress, a2 == 0 ? 2 : 0);
    return v6;
  }
  else
  {
    MmReleaseLoadLockShared(v5);
    return 0;
  }
}

```

// --- Calls: MiAcquireLoadLock at 0x1403984b8 (Depth: 3) ---
// Language: C/C++
```cpp
struct _KTHREAD *__fastcall MiAcquireLoadLock(int a1)
{
  struct _KTHREAD *CurrentThread; // rbx
  bool v2; // zf

  CurrentThread = KeGetCurrentThread();
  --CurrentThread->SpecialApcDisable;
  --CurrentThread->KernelApcDisable;
  if ( a1 )
  {
    ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, 1u);
    if ( !dword_140E2D718 )
      qword_140E2D710 = (__int64)CurrentThread;
    ++dword_140E2D718;
  }
  else
  {
    ExAcquireResourceSharedLite(&PsLoadedModuleResource, 1u);
    ++LODWORD(CurrentThread[1].Teb);
  }
  v2 = CurrentThread->SpecialApcDisable++ == -1;
  if ( v2 && ($727077A9B6E167EAE1398C74674DC5A5 *)CurrentThread->ApcState.ApcListHead[0].Flink != &CurrentThread->___u25 )
    KiCheckForKernelApcDelivery();
  return CurrentThread;
}

```

// --- Calls: ExAcquireResourceSharedLite at 0x1402f0d80 (Depth: 4) ---
// Language: C/C++
```cpp
BOOLEAN __stdcall ExAcquireResourceSharedLite(PERESOURCE Resource, BOOLEAN Wait)
{
  USHORT Flag; // cx
  unsigned __int8 v5; // dl
  char v7; // al
  int v8; // ebp
  struct _ERESOURCE *v9; // r9
  int v10; // ecx
  KSPIN_LOCK *v11; // r14
  __int64 v12; // rdi
  __int64 v13; // r12
  _BOOL8 v14; // r8
  signed __int64 Flink; // rax
  BOOLEAN v16; // di
  ULONG_PTR Pool2; // rsi
  int v18; // r8d
  struct _KTHREAD *v19; // rcx
  USHORT v20; // r9
  int v21; // r15d
  unsigned __int8 v22; // al
  unsigned __int8 v23; // dl
  struct _KTHREAD *v24; // rcx
  ULONG_PTR v25; // r9
  struct _LIST_ENTRY *v26; // rtt
  char v27; // r13
  int v28; // r15d
  int v29; // ebp
  int v30; // r13d
  signed __int32 *SchedulerAssist; // r8
  signed __int32 v32; // eax
  signed __int32 v33; // ett
  __int64 v34; // r8
  unsigned __int8 CurrentIrql; // cl
  struct _KTHREAD *CurrentThread; // r8

  Flag = Resource->Flag;
  v5 = (Wait == 0) + 1;
  if ( (Flag & 0x41) == 1 )
    KeBugCheckEx(0x1C6u, 0xFu, (ULONG_PTR)Resource, 0, 0);
  if ( (Flag & 1) == 0 )
    return ExpAcquireResourceSharedLite(Resource, Wait);
  CurrentIrql = KeGetCurrentIrql();
  CurrentThread = KeGetCurrentThread();
  if ( CurrentIrql > v5 )
    KeBugCheckEx(0x1C6u, 0, CurrentIrql, v5, 0);
  if ( CurrentIrql >= 2u && (KeGetPcr()->Prcb.DpcRequestSummary & 0x10001) != 0 )
LABEL_36:
    KeBugCheckEx(0x1C6u, 5u, 0, 0, 0);
  if ( (CurrentThread->ApcState.InProgressFlags & 2) != 0 )
LABEL_30:
    KeBugCheckEx(0x1C6u, 6u, 0, 0, 0);
  if ( !CurrentIrql && (CurrentThread->MiscFlags & 0x400) == 0 && !CurrentThread->WaitBlock[3].SpareLong )
    goto LABEL_34;
  do
    Pool2 = ExAllocatePool2(0x40u);
  while ( !Pool2 );
  *(_OWORD *)Pool2 = 0;
  *(_OWORD *)(Pool2 + 16) = 0;
  *(_QWORD *)(Pool2 + 32) = 0;
  v18 = 2;
  v19 = KeGetCurrentThread();
  *(_BYTE *)(Pool2 + 37) |= 1u;
  *(_QWORD *)(Pool2 + 16) = v19;
  if ( Wait )
    v18 = 10;
  v20 = Resource->Flag;
  v21 = v18 & 0x10;
  v22 = ((v18 & 8) == 0) + 1;
  if ( (v20 & 1) == 0 )
    KeBugCheckEx(0x1C6u, 3u, (ULONG_PTR)Resource, 0, 0);
  v23 = KeGetCurrentIrql();
  v24 = KeGetCurrentThread();
  if ( v23 > v22 )
    KeBugCheckEx(0x1C6u, 0, v23, v22, 0);
  if ( v23 >= 2u && (KeGetPcr()->Prcb.DpcRequestSummary & 0x10001) != 0 )
    goto LABEL_36;
  if ( (v20 & 8) == 0 && (v24->ApcState.InProgressFlags & 2) != 0 )
    goto LABEL_30;
  if ( !v23 && (v24->MiscFlags & 0x400) == 0 && !v24->WaitBlock[3].SpareLong )
LABEL_34:
    KeBugCheckEx(0x1C6u, 7u, 0, 0, 0);
  v25 = *(_QWORD *)(Pool2 + 16) & 0xFFFFFFFFFFFFFFFEuLL;
  if ( (struct _KTHREAD *)v25 != v24 )
    KeBugCheckEx(0x1C6u, 9u, Pool2, v25, 0);
  v7 = *(_BYTE *)(Pool2 + 37);
  v8 = v18;
  if ( (v7 & 2) == 0 )
  {
    v9 = *(struct _ERESOURCE **)(Pool2 + 24);
    if ( v9 )
    {
      if ( v9 != Resource )
        KeBugCheckEx(0x1C6u, 2u, Pool2, (ULONG_PTR)v9, 0);
    }
  }
  v10 = *(_DWORD *)(Pool2 + 32);
  if ( !v10 || (v7 & 4) != 0 )
  {
    v11 = (KSPIN_LOCK *)KeGetCurrentThread();
    v12 = 0;
    v13 = 0;
    v14 = (v18 & 8) == 0;
    if ( !*(_BYTE *)(Pool2 + 36) )
      v13 = KeAbPreAcquire(Resource, 0, v14);
    while ( 1 )
    {
      _m_prefetchw(Resource);
      Flink = (signed __int64)Resource->SystemResourcesList.Flink;
      if ( ((__int64)Resource->SystemResourcesList.Flink & 1) != 0 || (Flink & 2) != 0 )
        break;
      v26 = Resource->SystemResourcesList.Flink;
      if ( v26 == (struct _LIST_ENTRY *)_InterlockedCompareExchange64(
                                          (volatile signed __int64 *)Resource,
                                          Flink ^ (Flink ^ (Flink + 4)) & 0xFFFFFFFFFFFFFFFCuLL,
                                          Flink) )
      {
        v27 = 3;
        if ( v21 )
          v27 = 15;
        v28 = v27 & 2;
        v29 = v27 & 4;
        v30 = v27 & 8;
        if ( (ULONG *)Pool2 != &Resource->ActiveEntries )
          *(_QWORD *)(Pool2 + 24) = Resource;
        *(_DWORD *)(Pool2 + 32) = 1;
        LOBYTE(v14) = 1;
        LOBYTE(v12) = v29 != 0;
        *(_QWORD *)(Pool2 + 16) = (unsigned __int64)v11 | v12;
        ExpSaveAbHandle(Pool2, v13, v14);
        if ( v28 )
          _disable();
        if ( v29 )
        {
          KxAcquireSpinLock(v11 + 217);
          LOBYTE(v34) = 1;
          ExpAddFastOwnerEntryToThreadList(v11, Resource, v34, Pool2);
          KxReleaseSpinLock(v11 + 217);
        }
        else
        {
          ExpAddFastOwnerEntryToThreadList(v11, Resource, 0, Pool2);
        }
        if ( v28 )
        {
          SchedulerAssist = (signed __int32 *)KeGetCurrentPrcb()->SchedulerAssist;
          if ( SchedulerAssist )
          {
            _m_prefetchw(SchedulerAssist);
            v32 = *SchedulerAssist;
            do
            {
              v33 = v32;
              v32 = _InterlockedCompareExchange(SchedulerAssist, v32 & 0xFFDFFFFF, v32);
            }
            while ( v33 != v32 );
            if ( (v32 & 0x200000) != 0 )
              KiRemoveSystemWorkPriorityKick();
          }
          _enable();
        }
        if ( v29 )
        {
          if ( v30 )
          {
            if ( v13 )
              KeAbMarkCrossThreadReleasable(Resource, v13);
          }
          ObfReferenceObjectWithTag(v11, 0x746C6644u);
        }
        v16 = 1;
        goto LABEL_13;
      }
    }
    v16 = ExpAcquireFastResourceSharedSlow((ULONG_PTR)Resource, v8);
    if ( !v16 )
      goto LABEL_14;
  }
  else
  {
    v16 = 1;
    *(_DWORD *)(Pool2 + 32) = v10 + 1;
  }
LABEL_13:
  if ( (unsigned __int8)ExIsFastResourceHeldExclusive((ULONG_PTR)Resource) )
LABEL_14:
    ExFreePoolWithTag((PVOID)Pool2, 0);
  return v16;
}

```

// --- Calls: KiCheckForKernelApcDelivery at 0x14026b800 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 __fastcall KiCheckForKernelApcDelivery(__int64 a1, __int64 a2)
{
  __int64 CurrentIrql; // rcx
  char v4; // al
  __int64 v5; // r8
  int v6; // edx
  char v7; // r9
  int v8; // [rsp+20h] [rbp-28h] BYREF
  __int128 v9; // [rsp+24h] [rbp-24h]

  if ( KeGetCurrentIrql() )
  {
    v9 = 0;
    KeGetCurrentThread()->ApcState.KernelApcPending = 1;
    if ( KiAmdTprLowerInterruptDelayDynamicWorkaround )
    {
      v4 = HalpDisableInterrupts(a1, a2, KeGetCurrentPrcb());
      v6 = *(_DWORD *)(v5 + 168);
      v7 = v4;
      *(_DWORD *)(v5 + 168) = v6 | 2;
      if ( !v6 )
        __writemsr(0xC0010015, __readmsr(0xC0010015) | 0x100000000LL);
      if ( v7 )
        _enable();
    }
    v8 = 5;
    return HalpInterruptSendIpi(&v8, 31);
  }
  else
  {
    CurrentIrql = KeGetCurrentIrql();
    __writecr8(1u);
    if ( KiIrqlFlags )
      KiRaiseIrqlProcessIrqlFlags(CurrentIrql, 1);
    KiDeliverApc(0, 0, 0);
    if ( KiIrqlFlags )
      KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql());
    __writecr8(0);
    return 0;
  }
}

```

// --- Calls: ExAcquireResourceExclusiveLite at 0x140229e70 (Depth: 4) ---
// Language: Assembly
```cpp
; Exported entry 221. ExAcquireResourceE…


; Attributes: bp-based frame fpd=57h

; BOOLEAN __stdcall ExAcquireResourceExc…
public ExAcquireResourceExclusiveLite
ExAcquireResourceExclusiveLite proc near

var_108= dword ptr -108h
var_E8= qword ptr -0E8h
SystemArgument1= qword ptr -0D0h
var_C8= byte ptr -0C8h
var_C0= qword ptr -0C0h
LockHandle= _KLOCK_QUEUE_HANDLE ptr -0B8…
var_A0= qword ptr -0A0h
var_98= qword ptr -98h
var_90= qword ptr -90h
var_85= byte ptr -85h
var_80= qword ptr -80h
var_78= qword ptr -78h
var_70= qword ptr -70h
var_68= _KLOCK_QUEUE_HANDLE ptr -68h
var_50= xmmword ptr -50h
var_40= xmmword ptr -40h
var_28= qword ptr -28h
var_s8= qword ptr  8
arg_8= qword ptr  18h
arg_10= qword ptr  20h
arg_18= qword ptr  28h

mov     r11, rsp
push    rbp
push    rbx
push    rsi
push    r12
lea     rbp, [r11-5Fh]
sub     rsp, 0E8h
test    dl, dl
mov     rbx, rcx
movzx   ecx, word ptr [rcx+1Ah]
movzx   r12d, dl
setz    r8b
movzx   eax, cl
inc     r8b
and     al, 41h
xor     esi, esi
cmp     al, 1
jz      loc_14022A1B0

loc_140229EA6:
mov     [r11+10h], rdi
mov     [r11+18h], r13
mov     [r11+20h], r14
mov     [r11-28h], r15
test    cl, 1
jnz     loc_14022AAE6
xor     eax, eax
mov     [rbp+57h+var_98], rsi
xorps   xmm0, xmm0
mov     qword ptr [rbp+57h+LockHandle.Ol…
movups  xmmword ptr [rbp+57h+LockHandle.…
mov     [rbp+57h+var_85], al
mov     r13, gs:188h
test    dword ptr cs:PerfGlobalGroupMask…
jz      loc_14022ABA7
mov     r15b, 1

loc_140229EEF:
inc     dword ptr gs:9078h
lea     rdi, [rbx+60h]
mov     [rbp+57h+LockHandle.LockQueue.Lo…
mov     [rbp+57h+LockHandle.LockQueue.Ne…
nop
mov     r14, cr8
mov     eax, 2
mov     cr8, rax
cmp     cs:KiIrqlFlags, esi
jnz     loc_14022A170

loc_140229F1D:
test    byte ptr cs:PerfGlobalGroupMask+…
mov     [rbp+57h+LockHandle.OldIrql], r1…
jnz     loc_14022A141

loc_140229F2E:
lea     rdx, [rbp+57h+LockHandle]
xchg    rdx, [rdi]
test    rdx, rdx
jnz     loc_14022A181

loc_140229F3E:
cmp     [rbx+40h], esi
jnz     loc_14022A1CA
mov     r14d, 1
mov     [rbx+30h], r13
mov     eax, 80h
mov     [rbx+18h], r14w
or      [rbx+1Ah], ax
movzx   r12d, r14b
mov     eax, [rbx+38h]
and     eax, 7
mov     [rbx+40h], r14d
or      eax, 8
mov     [rbx+38h], eax
test    byte ptr cs:PerfGlobalGroupMask+…
jz      loc_14022A0AA
mov     eax, cs:PopHibernateInProgress
test    eax, eax
jnz     loc_14022A0AA
mov     rdx, [rbp+57h+var_s8]
lea     rcx, [rbp+57h+LockHandle]
call    KiReleaseQueuedSpinLockInstrumen…

loc_140229F9B:
cmp     cs:KiIrqlFlags, esi
movzx   edi, [rbp+57h+LockHandle.OldIrql…
jz      short loc_140229FB4
mov     rcx, cr8
movzx   edx, dil
call    KiLowerIrqlProcessIrqlFlags

loc_140229FB4:
mov     cr8, rdi
inc     dword ptr gs:907Ch
inc     dword ptr gs:9064h
test    r15b, r15b
jz      loc_14022A078
mov     eax, [rbx+44h]
mov     dword ptr [rbp+57h+var_C0], eax
mov     dword ptr [rbp+57h+SystemArgumen…
rdtsc
mov     r15, gs:20h
mov     rcx, rbx
shl     rdx, 20h
or      rax, rdx
mov     byte ptr [rbp+57h+SystemArgument…
mov     rdi, rax
mov     edx, 10000h
movzx   eax, byte ptr [r15+0D1h]
movzx   r13d, byte ptr [r15+0D0h]
inc     dword ptr [r15+8F70h]
mov     word ptr [rbp+57h+SystemArgument…
mov     [rbp+57h+var_C8], al
mov     byte ptr [rbp+57h+SystemArgument…
call    EtwpGetTrackingLockSlotForThread
test    rax, rax
jz      short loc_14022A078
inc     dword ptr [r15+8F74h]
mov     ecx, [rax+20h]
mov     [rax+8], rdi
test    ecx, ecx
jz      loc_14022A168
cmp     ecx, 4
jnz     loc_14022A168
cmp     [rax+18h], r13w
jnz     loc_14022A160
movzx   ecx, [rbp+57h+var_C8]
cmp     [rax+1Ah], cl
jnz     loc_14022A160
sub     rdi, [rax]
mov     [rax], rdi

loc_14022A064:
mov     ecx, dword ptr [rbp+57h+SystemAr…
mov     [rax+18h], ecx
mov     ecx, dword ptr [rbp+57h+var_C0]
mov     [rax+2Ch], ecx
mov     [rax+20h], r14d
mov     [rax+24h], r14d

loc_14022A078:
movzx   eax, r12b

loc_14022A07C:
mov     r14, [rsp+100h+arg_18]
mov     r13, [rsp+100h+arg_10]
mov     rdi, [rsp+100h+arg_8]
mov     r15, [rsp+0E0h]
add     rsp, 0E8h
pop     r12
pop     rsi
pop     rbx
pop     rbp
retn
algn_14022A0A9:
align 2

loc_14022A0AA:
prefetchw byte ptr [rbp+57h+LockHandle.L…
mov     rax, [rbp+57h+LockHandle.LockQue…
test    rax, rax
jnz     short loc_14022A0DA
mov     rcx, [rbp+57h+LockHandle.LockQue…
lea     rax, [rbp+57h+LockHandle]
lock cmpxchg [rcx], rsi
lea     rcx, [rbp+57h+LockHandle]
cmp     rax, rcx
jz      loc_140229F9B
lea     rcx, [rbp+57h+LockHandle]
call    KxWaitForLockChainValid

loc_14022A0DA:
lea     r8, [rax+8]
mov     [rbp+57h+LockHandle.LockQueue.Ne…
mov     rcx, [rbp+57h+LockHandle.LockQue…
mov     rax, rcx
xchg    rax, [r8]
xor     al, cl
test    al, 4
jz      loc_140229F9B
lock or [rsp+0], esi
shr     r8, 5
lea     r9, KiHaltOnAddressHashTable
and     r8d, 7Fh
call    KeDisableInterrupts
mov     rdx, rsi
movzx   edi, al
xchg    rdx, [r9+r8*8]
call    KiHaltOnAddressWakeEntireList
test    dil, dil
jz      loc_140229F9B
mov     rcx, gs:20h
mov     r8, [rcx+8EB8h]
test    r8, r8
jnz     short loc_14022A18F

loc_14022A13B:
sti
jmp     loc_140229F9B

loc_14022A141:
mov     eax, cs:PopHibernateInProgress
test    eax, eax
jnz     loc_140229F2E
mov     rdx, rdi
lea     rcx, [rbp+57h+LockHandle]
call    KiAcquireQueuedSpinLockInstrumen…
jmp     loc_140229F3E

loc_14022A160:
mov     [rax], r14
jmp     loc_14022A064

loc_14022A168:
mov     [rax], rsi
jmp     loc_14022A064

loc_14022A170:
movzx   edx, al
movzx   ecx, r14b
call    KiRaiseIrqlProcessIrqlFlags
jmp     loc_140229F1D

loc_14022A181:
lea     rcx, [rbp+57h+LockHandle]
call    KxWaitForLockOwnerShip
jmp     loc_140229F3E

loc_14022A18F:
prefetchw byte ptr [r8]
mov     eax, [r8]

loc_14022A196:
mov     edx, eax
btr     edx, 15h
lock cmpxchg [r8], edx
jnz     short loc_14022A196
bt      eax, 15h
jnb     short loc_14022A13B
call    KiRemoveSystemWorkPriorityKick
jmp     short loc_14022A13B

loc_14022A1B0:          ; BugCheckParame…
xor     r9d, r9d
mov     [rsp+20h], rsi  ; BugCheckParame…
mov     r8, rbx         ; BugCheckParame…
mov     ecx, 1C6h       ; BugCheckCode
lea     edx, [r9+0Fh]   ; BugCheckParame…
call    KeBugCheckEx
align 2

loc_14022A1CA:
movzx   eax, byte ptr [rbx+1Ah]
test    al, al
jns     short loc_14022A1D8
cmp     [rbx+30h], r13
jz      short loc_14022A22D

loc_14022A1D8:
test    r12b, r12b
jz      loc_14022A6CB
inc     dword ptr [rbx+4Ch]
lea     rax, [rbp+57h+var_80]
mov     [rbp+57h+var_78], rax
lea     rax, [rbp+57h+var_80]
mov     [rbp+57h+var_80], rax
mov     rax, [rbx+28h]
mov     [rbp+57h+var_A0], rsi
mov     [rbp+57h+var_98], rsi
mov     qword ptr [rbp-31h], 60001h
mov     [rbp+57h+var_90], r13
mov     [rbp+57h+var_70], rsi
test    rax, rax
jz      loc_14022A2DA
mov     rcx, [rax+8]
cmp     [rcx], rax
jz      loc_14022A7E0

loc_14022A226:
mov     ecx, 3
int     29h             ; Win8: RtlFailF…

loc_14022A22D:
mov     edi, [rbx+38h]
lea     rcx, [rbp+57h+LockHandle] ; Lock…
lea     eax, [rdi+8]
xor     edi, eax
and     edi, 7
xor     edi, eax
mov     [rbx+38h], edi
shr     edi, 3
call    KeReleaseInStackQueuedSpinLock
inc     dword ptr gs:9080h
inc     dword ptr gs:9064h
test    r15b, r15b
jz      short loc_14022A2D2
mov     rsi, gs:20h
mov     edx, 10000h
mov     r15d, [rbx+44h]
mov     rcx, rbx
mov     byte ptr [rbp+57h+SystemArgument…
movzx   eax, byte ptr [rsi+0D0h]
inc     dword ptr [rsi+8F70h]
mov     word ptr [rbp+57h+SystemArgument…
movzx   eax, byte ptr [rsi+0D1h]
mov     byte ptr [rbp+57h+SystemArgument…
call    EtwpGetTrackingLockSlotForThread
mov     rcx, rax
test    rax, rax
jz      short loc_14022A2D2
inc     dword ptr [rsi+8F74h]
mov     r14d, 1
cmp     dword ptr [rax+20h], 0
jnz     loc_14022ABAF
mov     eax, 2
mov     [rcx], r14
mov     [rcx+8], rax
mov     eax, dword ptr [rbp+57h+SystemAr…
mov     [rcx+18h], eax
mov     [rcx+24h], edi
mov     [rcx+2Ch], r15d

loc_14022A2CE:
mov     [rcx+20h], r14d

loc_14022A2D2:
mov     r12b, 1
jmp     loc_14022A078

loc_14022A2DA:
lea     rax, [rbp+57h+var_A0]
mov     [rbp+57h+var_98], rax
lea     rax, [rbp+57h+var_A0]
mov     [rbp+57h+var_A0], rax
lea     rax, [rbp+57h+var_A0]
mov     [rbx+28h], rax

loc_14022A2F2:
test    byte ptr cs:PerfGlobalGroupMask+…
jz      loc_14022A675
mov     eax, cs:PopHibernateInProgress
test    eax, eax
jnz     loc_14022A675
mov     rdx, [rbp+57h+var_s8]
lea     rcx, [rbp+57h+LockHandle]
call    KiReleaseQueuedSpinLockInstrumen…

loc_14022A31A:
cmp     cs:KiIrqlFlags, esi
movzx   r14d, [rbp+57h+LockHandle.OldIrq…
jz      short loc_14022A334
mov     rcx, cr8
movzx   edx, r14b
call    KiLowerIrqlProcessIrqlFlags

loc_14022A334:
mov     cr8, r14
inc     dword ptr gs:9084h
mov     r12d, 4
test    r15b, r15b
jz      short loc_14022A3C0
xorps   xmm0, xmm0
movups  [rbp+57h+var_50], xmm0
movups  [rbp+57h+var_40], xmm0
movups  xmmword ptr [rbp+27h], xmm0
rdtsc
mov     r14, gs:20h
shl     rdx, 20h
or      rax, rdx
mov     byte ptr [rbp+57h+SystemArgument…
mov     edx, 10000h
mov     r12, rax
movzx   ecx, byte ptr [r14+0D0h]
inc     dword ptr [r14+8F70h]
mov     word ptr [rbp+57h+SystemArgument…
movzx   ecx, byte ptr [r14+0D1h]
mov     byte ptr [rbp+57h+SystemArgument…
mov     rcx, rbx
call    EtwpGetTrackingLockSlotForThread
test    rax, rax
jz      short loc_14022A3BA
inc     dword ptr [r14+8F74h]
mov     ecx, dword ptr [rbp+57h+SystemAr…
mov     dword ptr [rax+20h], 4
mov     [rax], r12
mov     [rax+18h], ecx

loc_14022A3BA:
mov     r12d, 4

loc_14022A3C0:
mov     r8, gs:188h
mov     edx, esi
mov     rax, [r8+220h]
mov     ecx, [r8+5A0h]
shr     ecx, 9
and     ecx, 7
mov     rax, [rax+2A0h]
test    rax, rax
jz      short loc_14022A3F6
mov     eax, [rax+43Ch]
cmp     ecx, eax
cmovge  ecx, eax

loc_14022A3F6:
cmp     ecx, 2
jl      loc_14022A78D

loc_14022A3FF:
cmp     ecx, 1
jle     short loc_14022A40C

loc_14022A404:
test    byte ptr [rbx+1Ah], 4
cmovz   edx, r12d

loc_14022A40C:
movsx   ecx, byte ptr [r8+0C3h]
mov     r9d, edx
movzx   eax, byte ptr [rbx+1Bh]
or      r9d, 2
test    byte ptr [rbx+1Ah], 2
cmovnz  r9d, edx
mov     edx, r9d
or      edx, 0FF00h
cmp     ecx, eax
cmovle  edx, r9d
test    edx, edx
jz      short loc_14022A442
mov     rcx, rbx
call    ExpApplyPriorityBoost

loc_14022A442:
mov     r8d, 10224h
lea     rdx, [rbp+57h+var_A0]
mov     rcx, rbx
call    ExpWaitForResource
xor     eax, eax
xorps   xmm0, xmm0
mov     qword ptr [rbp+57h+var_68.OldIrq…
mov     r14d, 1
movzx   eax, word ptr [rbx+1Ah]
movups  xmmword ptr [rbp+57h+var_68.Lock…
test    al, 8
jnz     loc_14022A5AE
mov     edx, esi
test    al, 4
jz      short loc_14022A4AB
mov     rax, [r13+220h]
mov     ecx, [r13+5A0h]
shr     ecx, 9
and     ecx, 7
mov     rax, [rax+2A0h]
test    rax, rax
jz      short loc_14022A4A4
mov     eax, [rax+43Ch]
cmp     ecx, eax
cmovge  ecx, eax

loc_14022A4A4:
cmp     ecx, 2
cmovl   edx, r12d

loc_14022A4AB:
mov     r12d, edx
or      r12d, 2
test    byte ptr [rbx+1Ah], 2
cmovz   r12d, edx
test    r12d, r12d
jz      loc_14022A5AE
mov     [rbp+57h+var_68.LockQueue.Lock],…
mov     [rbp+57h+var_68.LockQueue.Next],…
nop
mov     rax, cr8
mov     [rbp+57h+var_C0], rax
mov     ecx, 2
mov     cr8, rcx
cmp     cs:KiIrqlFlags, esi
jnz     loc_14022A779

loc_14022A4E9:
test    byte ptr cs:PerfGlobalGroupMask+…
mov     [rbp+57h+var_68.OldIrql], al
jnz     loc_14022A6E4

loc_14022A4F9:
lea     rdx, [rbp+57h+var_68]
xchg    rdx, [rdi]
test    rdx, rdx
jnz     loc_14022A7B1

loc_14022A509:
mov     rax, [rbx+30h]
lea     rdi, [rbx+30h]
cmp     rax, r13
jz      short loc_14022A53B
mov     rdi, [rbx+10h]
test    rax, rax
mov     edx, [rbx+48h]
mov     rcx, rsi
mov     eax, [rbx+40h]
setnz   cl
add     rdx, rax
mov     r9, rdi
test    rdi, rdi
jnz     loc_14022A71C

loc_14022A538:
mov     rdi, rsi

loc_14022A53B:
test    r12b, 4
jnz     loc_14022A7BF

loc_14022A545:
test    r12b, 2
jz      short loc_14022A57D
mov     eax, [rdi+8]
test    al, 4
jnz     loc_14022A713
mov     eax, r14d
lock xadd [r13+5E4h], eax
inc     eax
cmp     eax, r14d
jnz     short loc_14022A579
movzx   eax, byte ptr [r13+318h]
test    al, al
jnz     loc_14022A805

loc_14022A579:
or      dword ptr [rdi+8], 4

loc_14022A57D:          ; LockHandle
lea     rcx, [rbp+57h+var_68]
call    KeReleaseInStackQueuedSpinLock
test    r12d, r12d
jz      short loc_14022A5AE
test    r12b, 4
jz      short loc_14022A5A0
xor     r8d, r8d
mov     rcx, r13
lea     edx, [r8+2]
call    IoBoostThreadIoPriority

loc_14022A5A0:
test    r12b, 2
jz      short loc_14022A5AE
mov     rcx, r13
call    PsBoostThreadOutstandingIoQoS

loc_14022A5AE:
inc     dword ptr gs:907Ch
inc     dword ptr gs:9064h
test    r15b, r15b
jz      loc_14022A66C
mov     eax, [rbx+44h]
mov     dword ptr [rbp+57h+var_C0], eax
mov     dword ptr [rbp+57h+SystemArgumen…
rdtsc
mov     r15, gs:20h
mov     rcx, rbx
shl     rdx, 20h
or      rax, rdx
mov     byte ptr [rbp+57h+SystemArgument…
mov     edx, 10000h
mov     rdi, rax
movzx   r13d, byte ptr [r15+0D0h]
movzx   r12d, byte ptr [r15+0D1h]
inc     dword ptr [r15+8F70h]
mov     word ptr [rbp+57h+SystemArgument…
mov     byte ptr [rbp+57h+SystemArgument…
call    EtwpGetTrackingLockSlotForThread
mov     rcx, rax
test    rax, rax
jz      short loc_14022A66C
inc     dword ptr [r15+8F74h]
mov     [rax+8], rdi
mov     eax, [rax+20h]
test    eax, eax
jz      loc_14022A70B
cmp     eax, 4
jnz     loc_14022A70B
cmp     [rcx+18h], r13w
jnz     loc_14022A703
cmp     [rcx+1Ah], r12b
jnz     loc_14022A703
sub     rdi, [rcx]
mov     [rcx], rdi

loc_14022A658:
mov     eax, dword ptr [rbp+57h+SystemAr…
mov     [rcx+18h], eax
mov     eax, dword ptr [rbp+57h+var_C0]
mov     [rcx+2Ch], eax
mov     [rcx+20h], r14d
mov     [rcx+24h], r14d

loc_14022A66C:
movzx   r12d, r14b
jmp     loc_14022A078

loc_14022A675:
prefetchw byte ptr [rbp+57h+LockHandle.L…
mov     rax, [rbp+57h+LockHandle.LockQue…
test    rax, rax
jnz     short loc_14022A6A5
mov     rcx, [rbp+57h+LockHandle.LockQue…
lea     rax, [rbp+57h+LockHandle]
lock cmpxchg [rcx], rsi
lea     rcx, [rbp+57h+LockHandle]
cmp     rax, rcx
jz      loc_14022A31A
lea     rcx, [rbp+57h+LockHandle]
call    KxWaitForLockChainValid

loc_14022A6A5:
lea     rcx, [rax+8]
mov     [rbp+57h+LockHandle.LockQueue.Ne…
mov     rdx, [rbp+57h+LockHandle.LockQue…
mov     rax, rdx
xchg    rax, [rcx]
xor     al, dl
test    al, 4
jz      loc_14022A31A
call    KeWakeAddressAll
jmp     loc_14022A31A

loc_14022A6CB:          ; LockHandle
lea     rcx, [rbp+57h+LockHandle]
call    KeReleaseInStackQueuedSpinLock
inc     dword ptr gs:9088h
xor     r12b, r12b
jmp     loc_14022A078

loc_14022A6E4:
mov     eax, cs:PopHibernateInProgress
test    eax, eax
jnz     loc_14022A4F9
mov     rdx, rdi
lea     rcx, [rbp+57h+var_68]
call    KiAcquireQueuedSpinLockInstrumen…
jmp     loc_14022A509

loc_14022A703:
mov     [rcx], r14
jmp     loc_14022A658

loc_14022A70B:
mov     [rcx], rsi
jmp     loc_14022A658

loc_14022A713:
and     r12d, 0FFFFFFFDh
jmp     loc_14022A57D

loc_14022A71C:
mov     r8d, [rdi+8]
shl     r8, 4
add     r8, rdi
add     rdi, 10h
cmp     rcx, rdx
jnb     loc_14022A538

loc_14022A734:
mov     rax, [rdi]
cmp     rax, r13
jz      short loc_14022A75B
test    rax, rax
jz      short loc_14022A74D
inc     rcx
cmp     rcx, rdx
jz      loc_14022A538

loc_14022A74D:
add     rdi, 10h
cmp     rdi, r8
jnz     short loc_14022A734
jmp     loc_14022A538

loc_14022A75B:
mov     rcx, gs:188h
mov     rax, rdi
sub     rax, r9
sar     rax, 4
mov     [rcx+460h], al
jmp     loc_14022A53B

loc_14022A779:
movzx   edx, cl
movzx   ecx, al
call    KiRaiseIrqlProcessIrqlFlags
mov     rax, [rbp+57h+var_C0]
jmp     loc_14022A4E9

loc_14022A78D:
mov     rax, gs:188h
cmp     r8, rax
jnz     loc_14022A3FF
cmp     [r8+5E0h], edx
jz      loc_14022A3FF
jmp     loc_14022A404

loc_14022A7B1:
lea     rcx, [rbp+57h+var_68]
call    KxWaitForLockOwnerShip
jmp     loc_14022A509

loc_14022A7BF:
mov     eax, [rdi+8]
test    r14b, al
jnz     short loc_14022A7FC
xor     r9d, r9d
xor     r8d, r8d
xor     edx, edx
mov     rcx, r13
call    PsBoostThreadIoEx
or      [rdi+8], r14d
jmp     loc_14022A545

loc_14022A7E0:
mov     [rbp+57h+var_98], rcx
lea     rdx, [rbp+57h+var_A0]
mov     [rbp+57h+var_A0], rax
mov     [rcx], rdx
lea     rcx, [rbp+57h+var_A0]
mov     [rax+8], rcx
jmp     loc_14022A2F2

loc_14022A7FC:
and     r12d, 0FFFFFFFBh
jmp     loc_14022A545

loc_14022A805:
mov     rax, cr8
mov     [rbp+57h+var_C0], rax
mov     ecx, 2
mov     cr8, rcx
cmp     cs:KiIrqlFlags, esi
jnz     short loc_14022A870

loc_14022A81E:
mov     rax, gs:20h
lea     r8, [r13+328h]
mov     rcx, r13
mov     [rbp+57h+SystemArgument1], rax
lea     rdx, [rax+9178h]
call    KiAbThreadInsertList
test    eax, eax
jz      short loc_14022A84E
mov     rcx, [rbp+57h+SystemArgument1] ;…
call    KiAbQueueAutoBoostDpc

loc_14022A84E:
cmp     cs:KiIrqlFlags, esi
jz      short loc_14022A863
mov     rcx, cr8
movzx   edx, byte ptr [rbp+57h+var_C0]
call    KiLowerIrqlProcessIrqlFlags

loc_14022A863:
movzx   eax, byte ptr [rbp+57h+var_C0]
mov     cr8, rax
jmp     loc_14022A579

loc_14022A870:
movzx   edx, cl
movzx   ecx, al
call    KiRaiseIrqlProcessIrqlFlags
jmp     short loc_14022A81E

loc_14022A87D:
mov     rdi, gs:188h
mov     r14d, 1
test    r12b, r12b
jz      loc_14022AAD9
lea     r12d, [r14+8]
movzx   eax, r14b
lea     r15d, [r14+7]

loc_14022A8A1:
xor     al, r14b
inc     al
mov     rdx, cr8
mov     r8, gs:188h
cmp     dl, al
jbe     short loc_14022A8D1
movzx   r8d, dl         ; BugCheckParame…
mov     ecx, 1C6h       ; BugCheckCode
xor     edx, edx        ; BugCheckParame…
movzx   r9d, al         ; BugCheckParame…
mov     [rsp+20h], rsi  ; BugCheckParame…
call    KeBugCheckEx
db 0CCh

loc_14022A8D1:
cmp     dl, 2
jnb     short loc_14022A933

loc_14022A8D6:
test    cl, 8
jnz     short loc_14022A901
movzx   eax, byte ptr [r8+0C0h]
test    al, 2
jz      short loc_14022A901

loc_14022A8E7:          ; BugCheckParame…
xor     r9d, r9d
mov     [rsp+20h], rsi  ; BugCheckParame…
xor     r8d, r8d        ; BugCheckParame…
mov     ecx, 1C6h       ; BugCheckCode
lea     edx, [r9+6]     ; BugCheckParame…
call    KeBugCheckEx
db 0CCh

loc_14022A901:
cmp     dl, r14b
jnb     short loc_14022A95C
test    dword ptr [r8+74h], 400h
jnz     short loc_14022A95C
cmp     [r8+1E4h], esi
jnz     short loc_14022A95C

loc_14022A919:          ; BugCheckParame…
xor     r9d, r9d
mov     [rsp+20h], rsi  ; BugCheckParame…
xor     r8d, r8d        ; BugCheckParame…
mov     ecx, 1C6h       ; BugCheckCode
lea     edx, [r9+7]     ; BugCheckParame…
call    KeBugCheckEx
db 0CCh

loc_14022A933:
mov     eax, gs:3A3Ch
test    eax, 10001h
jz      short loc_14022A8D6

loc_14022A942:          ; BugCheckParame…
xor     r9d, r9d
mov     [rsp+20h], rsi  ; BugCheckParame…
xor     r8d, r8d        ; BugCheckParame…
mov     ecx, 1C6h       ; BugCheckCode
lea     edx, [r9+5]     ; BugCheckParame…
call    KeBugCheckEx
align 4

loc_14022A95C:
mov     r8d, esi
test    r15d, r15d
mov     rcx, rbx
setz    r8b
xor     edx, edx
call    KeAbPreAcquire
mov     rdx, rax
mov     [rbp+57h+var_C0], rax
xor     eax, eax
lock cmpxchg [rbx], r14
lea     r13, [rbx+40h]
jnz     loc_14022AA3C
test    r12b, 10h
mov     ecx, 3
mov     eax, 0Fh
cmovnz  ecx, eax
mov     r15d, ecx
mov     ebx, ecx
and     r15d, 2
and     ebx, 4
test    cl, 8
jz      loc_14022AA34
movzx   r12d, r14b

loc_14022A9B2:
test    ebx, ebx
mov     [r13+20h], r14d
setnz   sil
or      rsi, rdi
mov     [r13+10h], rsi
test    rdx, rdx
jz      short loc_14022A9DB
movzx   eax, byte ptr [rdx+8]
and     al, 3Fh
mov     [rdx+0Ah], r14b
add     al, al
or      al, r14b
mov     [r13+24h], al

loc_14022A9DB:
test    r15d, r15d
jz      short loc_14022A9E1
cli

loc_14022A9E1:
test    ebx, ebx
jnz     loc_14022AB63
lea     rax, [rdi+6B8h]
mov     rcx, [rax]
cmp     [rcx+8], rax
jnz     loc_14022A226
mov     [r13+0], rcx
mov     [r13+8], rax
mov     [rcx+8], r13
mov     [rax], r13

loc_14022AA0C:
test    r15d, r15d
jz      short loc_14022AA27
mov     rcx, gs:20h
mov     r8, [rcx+8EB8h]
test    r8, r8
jnz     short loc_14022AA5F

loc_14022AA26:
sti

loc_14022AA27:
test    ebx, ebx
jnz     short loc_14022AA9E

loc_14022AA2B:
movzx   eax, r14b
jmp     loc_14022A07C

loc_14022AA34:
xor     r12b, r12b
jmp     loc_14022A9B2

loc_14022AA3C:
cmp     [r13+10h], rdi
jz      short loc_14022AA84
test    r15d, r15d
jz      short loc_14022AAB9
mov     r9, rdx
mov     [rsp+20h], r12d
mov     rdx, rax
mov     r8, rdi
mov     rcx, rbx
call    ExpAcquireFastResourceExclusiveS…
jmp     short loc_14022AA2B

loc_14022AA5F:
prefetchw byte ptr [r8]
mov     eax, [r8]

loc_14022AA66:
mov     edx, eax
btr     edx, 15h
lock cmpxchg [r8], edx
jnz     short loc_14022AA66
bt      eax, 15h
jnb     short loc_14022AA7E
call    KiRemoveSystemWorkPriorityKick

loc_14022AA7E:
mov     rdx, [rbp+57h+var_C0]
jmp     short loc_14022AA26

loc_14022AA84:
inc     dword ptr [r13+20h]
test    rdx, rdx
jz      short loc_14022AA2B
mov     rcx, rbx        ; BugCheckParame…
call    KeAbPostReleaseEx
movzx   eax, r14b
jmp     loc_14022A07C

loc_14022AA9E:
test    r12b, r12b
jnz     short loc_14022AACD

loc_14022AAA3:          ; Tag
mov     edx, 746C6644h
mov     rcx, rdi        ; Object
call    ObfReferenceObjectWithTag
movzx   eax, r14b
jmp     loc_14022A07C

loc_14022AAB9:
test    rdx, rdx
jz      short loc_14022AAC6
mov     rcx, rbx        ; BugCheckParame…
call    KeAbPostReleaseEx

loc_14022AAC6:
xor     al, al
jmp     loc_14022A07C

loc_14022AACD:
test    rdx, rdx
jz      short loc_14022AAA3
call    KeAbMarkCrossThreadReleasable
jmp     short loc_14022AAA3

loc_14022AAD9:
mov     r15d, esi
xor     al, al
mov     r12d, r14d
jmp     loc_14022A8A1

loc_14022AAE6:
mov     rdx, cr8
mov     r9, gs:188h
cmp     dl, r8b
jbe     short loc_14022AB12
movzx   r9d, r8b        ; BugCheckParame…
mov     ecx, 1C6h       ; BugCheckCode
movzx   r8d, dl         ; BugCheckParame…
xor     edx, edx        ; BugCheckParame…
mov     [rsp+20h], rsi  ; BugCheckParame…
call    KeBugCheckEx
align 2

loc_14022AB12:
cmp     dl, 2
jb      short loc_14022AB2A
mov     eax, gs:3A3Ch
test    eax, 10001h
jnz     loc_14022A942

loc_14022AB2A:
movzx   eax, byte ptr [r9+0C0h]
test    al, 2
jnz     loc_14022A8E7
cmp     dl, 1
jnb     loc_14022A87D
test    dword ptr [r9+74h], 400h
jnz     loc_14022A87D
cmp     [r9+1E4h], esi
jz      loc_14022A919
jmp     loc_14022A87D

loc_14022AB63:          ; SpinLock
lea     rcx, [rdi+6C8h]
call    KxAcquireSpinLock
lea     rax, [rdi+6D0h]
mov     rdx, [rax]
cmp     [rdx+8], rax
jnz     loc_14022A226
mov     [r13+0], rdx
lea     rcx, [rdi+6C8h]
mov     [r13+8], rax
mov     [rdx+8], r13
mov     [rax], r13
call    KxReleaseSpinLock
mov     rdx, [rbp+57h+var_C0]
jmp     loc_14022AA0C

loc_14022ABA7:
xor     r15b, r15b
jmp     loc_140229EEF

loc_14022ABAF:
cmp     [rax+24h], edi
jnb     loc_14022A2CE
mov     [rax+24h], edi
jmp     loc_14022A2CE
ExAcquireResourceExclusiveLite endp


```

// --- Calls: MmFindDataTableEntryByAddress at 0x14039876c (Depth: 3) ---
// Language: C/C++
```cpp
__int64 *__fastcall MmFindDataTableEntryByAddress(unsigned __int64 a1)
{
  unsigned __int64 v1; // r9
  _QWORD *v2; // rdx
  unsigned __int64 v3; // r8
  __int64 v5; // r10
  __int64 i; // r8
  __int64 *v7; // r8

  v1 = a1;
  if ( !PsLoadedModuleList )
  {
    v5 = KeLoaderBlock_0 + 16;
    for ( i = *(_QWORD *)(KeLoaderBlock_0 + 16); i != v5; i = *v7 )
    {
      if ( (unsigned int)MiImageContainsVa(i, v1) )
        return v7;
    }
    return 0;
  }
  v2 = (_QWORD *)qword_140E2D780;
  while ( v2 )
  {
    v3 = *(v2 - 20);
    if ( a1 > v3 + (unsigned int)(*((_DWORD *)v2 - 36) - 1) )
    {
      v2 = (_QWORD *)v2[1];
    }
    else
    {
      if ( a1 >= v3 )
        break;
      v2 = (_QWORD *)*v2;
    }
  }
  if ( !v2 )
    return 0;
  return v2 - 26;
}

```

// --- Calls: MiImageContainsVa at 0x1403955b8 (Depth: 4) ---
// Language: C/C++
```cpp
_BOOL8 __fastcall MiImageContainsVa(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // rax

  v2 = *(_QWORD *)(a1 + 48);
  return a2 >= v2 && a2 < v2 + *(unsigned int *)(a1 + 64);
}

```

// --- Calls: MiLockLoaderEntry at 0x140398a40 (Depth: 3) ---
// Language: C/C++
```cpp
__int64 __fastcall MiLockLoaderEntry(__int64 a1, int a2)
{
  struct _KTHREAD *CurrentThread; // rsi
  volatile signed __int32 *v3; // rbx
  ULONG_PTR v6; // rcx
  __int64 v7; // rdi
  __int64 result; // rax
  __int64 v9; // rdi

  CurrentThread = KeGetCurrentThread();
  v3 = (volatile signed __int32 *)(a1 + 232);
  v6 = a1 + 232;
  --CurrentThread->SpecialApcDisable;
  if ( !a2 )
  {
    result = KeAbPreAcquire(v6, 0, 0);
    v9 = result;
    if ( _interlockedbittestandset64(v3, 0) )
      result = ExfAcquirePushLockExclusiveEx(v3, result, v3);
    if ( v9 )
      *(_BYTE *)(v9 + 10) = 1;
LABEL_8:
    *(_QWORD *)(a1 + 240) = CurrentThread;
    return result;
  }
  if ( a2 != 2 )
  {
    result = ExAcquireAutoExpandPushLockExclusive(v6, 0);
    if ( a2 > 1 )
      return result;
    goto LABEL_8;
  }
  v7 = KeAbPreAcquire(v6, 0, 0);
  result = _InterlockedCompareExchange64((volatile signed __int64 *)v3, 17, 0);
  if ( result )
    result = ExfAcquirePushLockSharedEx(v3, 0, v7, v3);
  if ( v7 )
    *(_BYTE *)(v7 + 10) = 1;
  return result;
}

```

// --- Calls: KeAbPreAcquire at 0x1402ef160 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 *__fastcall KeAbPreAcquire(__int64 a1, __int64 a2)
{
  struct _KTHREAD *CurrentThread; // rbx
  __int64 *v3; // rdi
  _KLOCK_ENTRIES *KernelAbEntries; // rsi
  unsigned int AvailableEntryBitmap; // eax
  signed __int32 *v7; // r8
  signed __int16 OrphanedEntryBitmap; // dx
  unsigned int v10; // ecx
  signed __int32 *SchedulerAssist; // r8
  signed __int32 v12; // eax
  signed __int32 v13; // ett
  signed __int32 v14; // eax
  signed __int32 v15; // ett
  unsigned int v16; // [rsp+58h] [rbp+10h]
  __int64 v17; // [rsp+68h] [rbp+20h] BYREF

  CurrentThread = KeGetCurrentThread();
  v3 = (__int64 *)a2;
  v17 = 0;
  if ( a2 )
  {
    if ( !*(_BYTE *)(a2 + 9) )
      goto LABEL_9;
    _disable();
    KiAbEntryFreeAndEnableInterrupts(a2, CurrentThread, a1, 0, &v17);
LABEL_15:
    *v3 = a1 & 0x7FFFFFFFFFFFFFFCLL;
    goto LABEL_9;
  }
  _disable();
  KernelAbEntries = CurrentThread->KernelAbEntries;
  AvailableEntryBitmap = KernelAbEntries->AvailableEntryBitmap;
  if ( KernelAbEntries->AvailableEntryBitmap )
  {
LABEL_13:
    _BitScanForward(&v10, AvailableEntryBitmap);
    v16 = v10;
    KernelAbEntries->AvailableEntryBitmap = AvailableEntryBitmap & (unsigned __int8)~(1 << v10);
    SchedulerAssist = (signed __int32 *)KeGetCurrentPrcb()->SchedulerAssist;
    if ( SchedulerAssist )
    {
      _m_prefetchw(SchedulerAssist);
      v12 = *SchedulerAssist;
      do
      {
        v13 = v12;
        v12 = _InterlockedCompareExchange(SchedulerAssist, v12 & 0xFFDFFFFF, v12);
      }
      while ( v13 != v12 );
      if ( (v12 & 0x200000) != 0 )
        KiRemoveSystemWorkPriorityKick();
    }
    _enable();
    v3 = (__int64 *)&KernelAbEntries->Entries[v16];
    goto LABEL_15;
  }
  if ( KernelAbEntries->OrphanedEntryBitmap )
  {
    OrphanedEntryBitmap = KernelAbEntries->OrphanedEntryBitmap;
    KernelAbEntries->OrphanedEntryBitmap = 0;
    AvailableEntryBitmap = OrphanedEntryBitmap;
    if ( !OrphanedEntryBitmap )
      goto LABEL_9;
    goto LABEL_13;
  }
  if ( (*((_DWORD *)&CurrentThread->$F6E8E81C3EACE4482EE2626591212BC8::$3C37BCD2CC8A9A13CF8DF3DA08EBA37B::__s0 + 1)
      & 0x10000) == 0 )
    _interlockedbittestandset((volatile signed __int32 *)&CurrentThread->___u16 + 1, 0x10u);
  v7 = (signed __int32 *)KeGetCurrentPrcb()->SchedulerAssist;
  if ( v7 )
  {
    _m_prefetchw(v7);
    v14 = *v7;
    do
    {
      v15 = v14;
      v14 = _InterlockedCompareExchange(v7, v14 & 0xFFDFFFFF, v14);
    }
    while ( v15 != v14 );
    if ( (v14 & 0x200000) != 0 )
      KiRemoveSystemWorkPriorityKick();
  }
  _enable();
  if ( (WORD2(xmmword_140FC5B10) & 0x1000) != 0 )
    EtwTraceAutoBoostEntryExhaustion(CurrentThread, a1);
LABEL_9:
  if ( (_DWORD)v17 )
    KiAbThreadRemoveBoostsSlow((ULONG_PTR)CurrentThread);
  return v3;
}

```

// --- Calls: ExfAcquirePushLockSharedEx at 0x1402ef41c (Depth: 4) ---
// Language: C/C++
```cpp
signed __int64 __fastcall ExfAcquirePushLockSharedEx(signed __int64 *a1, char a2, __int64 *a3, __int64 a4)
{
  unsigned __int64 i; // rdx
  __int64 v9; // r8
  bool v10; // r15
  signed __int64 v11; // rdi
  signed __int64 v12; // rcx
  signed __int64 result; // rax
  bool v14; // cl
  bool v15; // zf
  signed __int64 v16; // rax
  unsigned __int64 v18; // r8
  unsigned __int64 v19; // r9
  unsigned __int64 v20; // rcx
  unsigned __int64 v21; // rax
  __int16 Object; // [rsp+40h] [rbp-40h] BYREF
  char v23; // [rsp+42h] [rbp-3Eh]
  _BYTE v24[5]; // [rsp+43h] [rbp-3Dh] BYREF
  _QWORD v25[3]; // [rsp+48h] [rbp-38h] BYREF
  __int16 *p_Object; // [rsp+60h] [rbp-20h]
  __int64 v27; // [rsp+68h] [rbp-18h]
  int v28; // [rsp+70h] [rbp-10h]
  signed __int32 v29; // [rsp+74h] [rbp-Ch] BYREF
  __int64 *v30; // [rsp+78h] [rbp-8h]
  int v31; // [rsp+B0h] [rbp+30h] BYREF

  memset_0(&Object, 0, 0x40u);
  v31 = 0;
  v9 = 1;
  v10 = ExpPushLockAllowImplicitUpgrade && (a2 & 4) == 0;
  _m_prefetchw(a1);
  v11 = *a1;
  while ( ((v11 & 2) != 0 || (v11 & 1) != 0 && (v11 & 0xFFFFFFFFFFFFFFF0uLL) == 0) && (!v10 || (v11 & 1) != 0) )
  {
    if ( a3 )
    {
      KeAbPreWait(a3);
      v9 = 1;
    }
    v27 = 0;
    v14 = 0;
    v30 = a3;
    v29 = 2;
    if ( (v11 & 2) != 0 )
    {
      p_Object = 0;
      v28 = -1;
      v25[2] = v11 & 0xFFFFFFFFFFFFFFF0uLL;
      i = (unsigned __int64)&Object | v11 & 9 | 6;
      v14 = (v11 & 4) == 0;
    }
    else
    {
      v28 = -2;
      p_Object = &Object;
      i = (unsigned __int64)v24;
    }
    v16 = _InterlockedCompareExchange64(a1, i, v11);
    v15 = v11 == v16;
    v11 = v16;
    if ( !v15 )
      goto LABEL_28;
    if ( v14 )
      ExpOptimizePushLockList(a1, i, 1);
    *(_DWORD *)&v24[1] = 0;
    v25[1] = v25;
    v25[0] = v25;
    Object = 1;
    v23 = 6;
    if ( MEMORY[0xFFFFF7800000036A] > 1u )
    {
      if ( MEMORY[0xFFFFF78000000297] )
      {
        v18 = __rdtsc();
        v19 = v18 + (unsigned int)ExpSpinCycleCount;
        while ( 1 )
        {
          i = 0;
          __asm { monitorx rax, rcx, rdx }
          if ( (v29 & 2) == 0 )
            break;
          v20 = v18;
          v21 = __rdtsc();
          i = (unsigned __int64)HIDWORD(v21) << 32;
          v18 = v21;
          if ( v21 < v20 || v21 >= v19 )
            break;
          __asm { mwaitx  rax, rcx, rbx }
        }
      }
      else
      {
        for ( i = 0;
              (v29 & 2) != 0 && (_DWORD)i != ExpSpinCycleCount / (unsigned int)MEMORY[0xFFFFF780000002D6];
              i = (unsigned int)(i + 1) )
        {
          _mm_pause();
        }
      }
    }
    if ( _interlockedbittestandreset(&v29, 1u) )
      KeWaitForSingleObject(&Object, WrPushLock, 0, 0, 0);
LABEL_29:
    if ( a3 )
      a3 = KeAbPreAcquire(a4, (__int64)a3);
    v9 = 1;
  }
  v12 = (v11 | 1) + 16;
  if ( (v11 & 2) != 0 )
    v12 = v11 | 1;
  result = _InterlockedCompareExchange64(a1, v12, v11);
  if ( v11 != result )
  {
    if ( a3 )
      KeAbPreWait(a3);
LABEL_28:
    RtlBackoff(&v31, i, v9);
    v11 = *a1;
    _m_prefetchw(a1);
    goto LABEL_29;
  }
  return result;
}

```

// --- Calls: ExAcquireAutoExpandPushLockExclusive at 0x1402ed3e0 (Depth: 4) ---
// Language: C/C++
```cpp
void __fastcall ExAcquireAutoExpandPushLockExclusive(ULONG_PTR BugCheckParameter2, ULONG_PTR BugCheckParameter1)
{
  __int64 *v3; // r13
  unsigned int v4; // r9d
  unsigned __int64 v5; // r14
  __int64 v6; // rdx
  unsigned int v7; // ecx
  volatile signed __int32 *v8; // rcx
  unsigned int v9; // ebx
  __int64 v10; // rdi
  unsigned int v11; // esi
  unsigned int v12; // r14d
  unsigned int v13; // ecx
  unsigned int v14; // ecx
  volatile signed __int32 *v15; // roff
  volatile signed __int32 *v16; // rcx

  v3 = 0;
  if ( (BugCheckParameter1 & 0xFFFFFFF8) != 0 )
    KeBugCheckEx(0x152u, (unsigned int)BugCheckParameter1, BugCheckParameter2, 0, 0);
  if ( (BugCheckParameter1 & 2) == 0 )
    v3 = KeAbPreAcquire(BugCheckParameter2, 0);
  if ( _interlockedbittestandset64((volatile signed __int32 *)BugCheckParameter2, 0) )
    ExfAcquirePushLockExclusiveEx(BugCheckParameter2, v3, BugCheckParameter2);
  v4 = *(_DWORD *)(BugCheckParameter2 + 8);
  v5 = v4;
  if ( (v4 & 1) != 0 )
  {
    v6 = (v4 >> 13) & 0x3FFFF;
    _BitScanReverse(&v7, v6);
    v8 = (volatile signed __int32 *)(*(_QWORD *)(*(_QWORD *)(*(_QWORD *)ExSaPageArrays + 8LL * (v7 - 2))
                                               + 8 * (v6 ^ (unsigned int)(1 << v7))
                                               + 8)
                                   + 8LL * ((*(_DWORD *)(BugCheckParameter2 + 8) >> 4) & 0x1FF));
    if ( _interlockedbittestandset64(v8, 0) )
      ExfAcquirePushLockExclusiveEx(v8, v3, BugCheckParameter2);
    v9 = 1;
    LODWORD(v10) = KeQueryMaximumProcessorCountEx(0xFFFFu);
    if ( (unsigned int)v10 > 1 )
    {
      v11 = ((unsigned int)v5 >> 13) & 0x3FFFF;
      v12 = (v5 >> 4) & 0x1FF;
      do
      {
        _BitScanReverse(&v13, v11);
        if ( _interlockedbittestandset64(
               (volatile signed __int32 *)(*(_QWORD *)(*(_QWORD *)(*(_QWORD *)(ExSaPageArrays + 8LL * v9)
                                                                 + 8LL * (v13 - 2))
                                                     + 8 * (v11 ^ (unsigned __int64)(unsigned int)(1 << v13))
                                                     + 8)
                                         + 8LL * v12),
               0) )
        {
          v10 = (unsigned int)(v10 - 1);
          _BitScanReverse(&v14, v11);
          v15 = (volatile signed __int32 *)(*(_QWORD *)(*(_QWORD *)(*(_QWORD *)(ExSaPageArrays + 8 * v10)
                                                                  + 8LL * (v14 - 2))
                                                      + 8 * (v11 ^ (unsigned __int64)(unsigned int)(1 << v14))
                                                      + 8)
                                          + 8LL * v12);
          v16 = v15;
          if ( _interlockedbittestandset64(v15, 0) )
            ExfAcquirePushLockExclusiveEx(v16, v3, BugCheckParameter2);
        }
        else
        {
          ++v9;
        }
      }
      while ( v9 < (unsigned int)v10 );
    }
  }
  if ( v3 )
    *((_BYTE *)v3 + 10) = 1;
}

```

// --- Calls: ExfAcquirePushLockExclusiveEx at 0x1402eec10 (Depth: 4) ---
// Language: C/C++
```cpp
signed __int64 __fastcall ExfAcquirePushLockExclusiveEx(unsigned __int64 *a1, __int64 *a2, __int64 a3)
{
  unsigned __int64 v6; // rdx
  unsigned __int64 v7; // r8
  unsigned __int64 v8; // rdi
  __int64 v9; // r13
  bool v10; // cl
  bool v11; // zf
  signed __int64 v12; // rax
  _QWORD *v13; // rcx
  signed __int64 v14; // rax
  int i; // ecx
  signed __int64 result; // rax
  __int64 v18; // rdx
  unsigned __int64 v19; // r9
  unsigned __int64 v20; // rcx
  unsigned __int64 v21; // rax
  _QWORD *v22; // rax
  __int64 v23; // rax
  __int16 Object; // [rsp+30h] [rbp-40h] BYREF
  char v25; // [rsp+32h] [rbp-3Eh]
  int v26; // [rsp+34h] [rbp-3Ch]
  _QWORD v27[3]; // [rsp+38h] [rbp-38h] BYREF
  __int16 *p_Object; // [rsp+50h] [rbp-20h]
  __int64 v29; // [rsp+58h] [rbp-18h]
  int v30; // [rsp+60h] [rbp-10h]
  unsigned int v31; // [rsp+64h] [rbp-Ch] BYREF
  __int64 *v32; // [rsp+68h] [rbp-8h]
  int v33; // [rsp+B0h] [rbp+40h] BYREF

  memset_0(&Object, 0, 0x40u);
  v33 = 0;
  _m_prefetchw(a1);
  v8 = *a1;
  v9 = (unsigned int)(unsigned __int8)v33 + 3;
  while ( (v8 & 1) != 0 )
  {
    if ( a2 )
    {
      *(_BYTE *)a2 |= 2u;
      if ( *a2 < 0 )
        KiAbEntryRemoveFromTree(a2);
      *((_BYTE *)a2 + 9) = 1;
      *(_BYTE *)a2 &= ~2u;
    }
    v10 = 0;
    v32 = a2;
    v31 = v9;
    v29 = 0;
    if ( (v8 & 2) != 0 )
    {
      p_Object = 0;
      v30 = -1;
      v27[2] = v8 & 0xFFFFFFFFFFFFFFF0uLL;
      v6 = (unsigned __int64)&Object | v8 & 8 | 7;
      v10 = (v8 & 4) == 0;
    }
    else
    {
      v18 = 11;
      p_Object = &Object;
      v30 = v8 >> 4;
      if ( v30 <= 1 )
        v18 = v9;
      v6 = (unsigned __int64)&Object | v18;
      if ( !(unsigned int)(v8 >> 4) )
        v30 = -2;
    }
    v12 = _InterlockedCompareExchange64((volatile signed __int64 *)a1, v6, v8);
    v11 = v8 == v12;
    v8 = v12;
    if ( !v11 )
      goto LABEL_38;
    if ( v10 )
    {
      while ( (v6 & 1) != 0 )
      {
        v13 = (_QWORD *)(v6 & 0xFFFFFFFFFFFFFFF0uLL);
        if ( !*(_QWORD *)((v6 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) )
        {
          do
          {
            v22 = v13;
            v13 = (_QWORD *)v13[3];
            v13[5] = v22;
            v23 = v13[4];
          }
          while ( !v23 );
          if ( v13 != (_QWORD *)(v6 & 0xFFFFFFFFFFFFFFF0uLL) )
            *(_QWORD *)((v6 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) = v23;
        }
        v14 = _InterlockedCompareExchange64((volatile signed __int64 *)a1, v6 - 4, v6);
        v11 = v6 == v14;
        v6 = v14;
        if ( v11 )
          goto LABEL_14;
      }
      ExpWakePushLock(a1);
    }
LABEL_14:
    v27[1] = v27;
    v27[0] = v27;
    Object = 1;
    v25 = 6;
    v26 = 0;
    if ( MEMORY[0xFFFFF7800000036A] > 1u )
    {
      if ( MEMORY[0xFFFFF78000000297] )
      {
        v7 = __rdtsc();
        v19 = v7 + (unsigned int)ExpSpinCycleCount;
        while ( 1 )
        {
          v6 = 0;
          __asm { monitorx rax, rcx, rdx }
          if ( (v31 & 2) == 0 )
            break;
          v20 = v7;
          v21 = __rdtsc();
          v6 = (unsigned __int64)HIDWORD(v21) << 32;
          v7 = v21;
          if ( v21 < v20 || v21 >= v19 )
            break;
          __asm { mwaitx  rax, rcx, rbx }
        }
      }
      else
      {
        for ( i = 0; ; ++i )
        {
          v6 = v31;
          if ( (v31 & 2) == 0 || i == ExpSpinCycleCount / (unsigned int)MEMORY[0xFFFFF780000002D6] )
            break;
          _mm_pause();
        }
      }
    }
    if ( _interlockedbittestandreset((volatile signed __int32 *)&v31, 1u) )
      KeWaitForSingleObject(&Object, WrPushLock, 0, 0, 0);
LABEL_22:
    if ( a2 )
      a2 = KeAbPreAcquire(a3, (__int64)a2);
  }
  result = _InterlockedCompareExchange64((volatile signed __int64 *)a1, v8 + 1, v8);
  if ( v8 != result )
  {
    if ( a2 )
      KeAbPreWait(a2);
LABEL_38:
    RtlBackoff(&v33, v6, v7);
    v8 = *a1;
    _m_prefetchw(a1);
    goto LABEL_22;
  }
  return result;
}

```

// --- Calls: MmReleaseLoadLockShared at 0x140398b10 (Depth: 3) ---
// Language: C/C++
```cpp
__int64 __fastcall MmReleaseLoadLockShared(struct _KTHREAD *CurrentThread)
{
  if ( !CurrentThread )
    CurrentThread = KeGetCurrentThread();
  return MiReleaseLoadLock(CurrentThread, 0);
}

```

// --- Calls: MiReleaseLoadLock at 0x140398830 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 __fastcall MiReleaseLoadLock(__int64 a1, int a2)
{
  __int64 v3; // rdx
  __int64 v4; // rcx
  bool v5; // zf

  --*(_WORD *)(a1 + 486);
  if ( a2 )
  {
    if ( !--dword_140E2D718 )
      qword_140E2D710 = 0;
  }
  else
  {
    --*(_DWORD *)(a1 + 1456);
  }
  ExReleaseResourceLite(&PsLoadedModuleResource);
  v5 = (*(_WORD *)(a1 + 486))++ == 0xFFFF;
  if ( v5 && *(_QWORD *)(a1 + 152) != a1 + 152 )
    KiCheckForKernelApcDelivery(v4, v3);
  return KeLeaveCriticalRegionThread(a1);
}

```

// --- Calls: MiUnlockLoadedDataTableEntry at 0x1403983c4 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall MiUnlockLoadedDataTableEntry(__int64 a1, int a2)
{
  struct _KTHREAD *CurrentThread; // rcx

  MiUnlockLoaderEntry(a1, a2 == 0 ? 2 : 0);
  CurrentThread = KeGetCurrentThread();
  if ( !CurrentThread )
    CurrentThread = KeGetCurrentThread();
  return MiReleaseLoadLock((__int64)CurrentThread, 0);
}

```

// --- Calls: MiUnlockLoaderEntry at 0x140398988 (Depth: 3) ---
// Language: C/C++
```cpp
$727077A9B6E167EAE1398C74674DC5A5 *__fastcall MiUnlockLoaderEntry(__int64 a1, int a2)
{
  struct _KTHREAD *CurrentThread; // rdi
  volatile signed __int64 *v3; // rbx
  $727077A9B6E167EAE1398C74674DC5A5 *result; // rax
  __int64 v5; // rdx
  __int64 v6; // rcx
  ULONG_PTR v8; // rcx

  CurrentThread = KeGetCurrentThread();
  if ( a2 <= 1 )
    *(_QWORD *)(a1 + 240) = 0;
  v3 = (volatile signed __int64 *)(a1 + 232);
  if ( !a2 )
  {
    if ( (_InterlockedExchangeAdd64(v3, 0xFFFFFFFFFFFFFFFFuLL) & 6) == 2 )
      ExfTryToWakePushLock(a1 + 232);
    goto LABEL_9;
  }
  if ( a2 == 2 )
  {
    if ( _InterlockedCompareExchange64(v3, 0, 17) != 17 )
      ExfReleasePushLockShared(a1 + 232);
LABEL_9:
    result = ($727077A9B6E167EAE1398C74674DC5A5 *)KeAbPostRelease((ULONG_PTR)v3);
    goto LABEL_10;
  }
  v8 = a1 + 232;
  if ( a2 == 3 )
    result = ($727077A9B6E167EAE1398C74674DC5A5 *)ExReleaseAutoExpandPushLockShared(v8, 0);
  else
    result = ($727077A9B6E167EAE1398C74674DC5A5 *)ExReleaseAutoExpandPushLockExclusive(v8, 0);
LABEL_10:
  if ( CurrentThread->SpecialApcDisable++ == -1 )
  {
    result = &CurrentThread->___u25;
    if ( ($727077A9B6E167EAE1398C74674DC5A5 *)result->ApcState.ApcListHead[0].Flink != result )
      return ($727077A9B6E167EAE1398C74674DC5A5 *)KiCheckForKernelApcDelivery(v6, v5);
  }
  return result;
}

```

// --- Calls: ExfReleasePushLockShared at 0x140211290 (Depth: 4) ---
// Language: C/C++
```cpp
signed __int64 __fastcall ExfReleasePushLockShared(signed __int64 *a1)
{
  signed __int64 result; // rax
  signed __int64 v3; // r8
  signed __int64 v4; // rtt
  __int64 v5; // r8
  __int64 v6; // rdx
  signed __int64 v7; // rcx
  signed __int64 v8; // rtt
  unsigned __int64 i; // rcx
  __int64 v10; // rdx

  _m_prefetchw(a1);
  result = *a1;
  while ( (result & 2) == 0 )
  {
    v3 = 0;
    if ( (result & 0xFFFFFFFFFFFFFFF0uLL) != 0x10 )
      v3 = result - 16;
    v4 = result;
    result = _InterlockedCompareExchange64(a1, v3, result);
    if ( v4 == result )
      return result;
  }
  if ( (result & 8) != 0 )
  {
    for ( i = result & 0xFFFFFFFFFFFFFFF0uLL; ; i = *(_QWORD *)(i + 24) )
    {
      v10 = *(_QWORD *)(i + 32);
      if ( v10 )
        break;
    }
    if ( _InterlockedDecrement((volatile signed __int32 *)(v10 + 48)) > 0 )
      return result;
    v5 = -9;
  }
  else
  {
    v5 = -1;
  }
  do
  {
    v6 = v5 + 4;
    v7 = result & 6;
    if ( v7 != 2 )
      v6 = v5;
    v8 = result;
    result = _InterlockedCompareExchange64(a1, result + v6, result);
  }
  while ( v8 != result );
  if ( v7 == 2 )
    return ExpWakePushLock(a1);
  return result;
}

```

// --- Calls: KeAbPostRelease at 0x14026b390 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 __fastcall KeAbPostRelease(ULONG_PTR BugCheckParameter2)
{
  struct _KTHREAD *CurrentThread; // r10
  _KLOCK_ENTRIES *KernelAbEntries; // r8
  ULONG_PTR v3; // r9
  unsigned int i; // eax
  char *v5; // rbx
  __int64 v6; // rdx
  __int64 result; // rax
  struct _KPRCB *CurrentPrcb; // rcx
  _DWORD *SchedulerAssist; // r8
  __int64 v10; // rdx
  int v11; // ett

  CurrentThread = KeGetCurrentThread();
  _disable();
  KernelAbEntries = CurrentThread->KernelAbEntries;
  v3 = BugCheckParameter2 & 0x7FFFFFFFFFFFFFFCLL;
  for ( i = 0; i < KernelAbEntries->EntryCount; ++i )
  {
    v5 = (char *)KernelAbEntries + 88 * i;
    v6 = *((_QWORD *)v5 + 2);
    if ( (v6 & 0x7FFFFFFFFFFFFFFCLL) == v3 && v5[26] && (v6 & 1) == 0 )
    {
      v5[26] = 0;
      return KiAbEntryFreeAndEnableInterrupts(v5 + 16, CurrentThread, BugCheckParameter2, 1, 0);
    }
  }
  result = *((unsigned int *)&CurrentThread->MiscFlags + 1);
  if ( (result & 0x10000) == 0 )
    KeBugCheckEx(0x162u, (ULONG_PTR)CurrentThread, BugCheckParameter2, 0, 0);
  CurrentPrcb = KeGetCurrentPrcb();
  SchedulerAssist = CurrentPrcb->SchedulerAssist;
  if ( SchedulerAssist )
  {
    _m_prefetchw(SchedulerAssist);
    LODWORD(result) = *SchedulerAssist;
    do
    {
      v10 = (unsigned int)result;
      LODWORD(v10) = result & 0xFFDFFFFF;
      v11 = result;
      result = (unsigned int)_InterlockedCompareExchange(SchedulerAssist, result & 0xFFDFFFFF, result);
    }
    while ( v11 != (_DWORD)result );
    if ( (result & 0x200000) != 0 )
      result = KiRemoveSystemWorkPriorityKick(CurrentPrcb, v10, SchedulerAssist, v3);
  }
  _enable();
  return result;
}

```

// --- Calls: ExfTryToWakePushLock at 0x140212e30 (Depth: 4) ---
// Language: C/C++
```cpp
int __fastcall ExfTryToWakePushLock(volatile signed __int64 *a1)
{
  signed __int64 v1; // rax
  signed __int64 v3; // rdx
  volatile signed __int64 v4; // rtt
  int v5; // esi
  _QWORD *v6; // rcx
  struct _KEVENT *v7; // rbx
  signed __int64 *p_Blink; // rcx
  bool v9; // zf
  unsigned __int8 CurrentIrql; // di
  struct _KEVENT *Blink; // rsi
  struct _LIST_ENTRY *Flink; // rdx
  _QWORD *v13; // rax

  v1 = *a1;
  if ( (*a1 & 7) == 2 )
  {
    v3 = v1 + 4;
    v4 = *a1;
    v1 = _InterlockedCompareExchange64(a1, v1 + 4, v1);
    if ( v4 == v1 )
    {
      v5 = 1;
      while ( 1 )
      {
        while ( (v3 & 1) != 0 )
        {
          v1 = _InterlockedCompareExchange64(a1, v3 - 4, v3);
          v9 = v3 == v1;
          v3 = v1;
          if ( v9 )
            return v1;
        }
        v6 = (_QWORD *)(v3 & 0xFFFFFFFFFFFFFFF0uLL);
        v7 = *(struct _KEVENT **)((v3 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20);
        if ( !v7 )
        {
          do
          {
            v13 = v6;
            v6 = (_QWORD *)v6[3];
            v6[5] = v13;
            v7 = (struct _KEVENT *)v6[4];
          }
          while ( !v7 );
          if ( v6 != (_QWORD *)(v3 & 0xFFFFFFFFFFFFFFF0uLL) )
            *(_QWORD *)((v3 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) = v7;
        }
        p_Blink = (signed __int64 *)&v7[1].Header.WaitListHead.Blink;
        if ( (v7[2].Header.SignalState & 1) != 0 )
        {
          v1 = *p_Blink;
          if ( *p_Blink )
            break;
        }
        v1 = _InterlockedCompareExchange64(a1, 0, v3);
        v9 = v3 == v1;
        v3 = v1;
        if ( v9 )
          goto LABEL_9;
      }
      *(_QWORD *)((v3 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) = v1;
      *p_Blink = 0;
      _InterlockedAnd64(a1, 0xFFFFFFFFFFFFFFFBuLL);
      v5 = 0;
LABEL_9:
      CurrentIrql = 2;
      if ( *p_Blink )
      {
        CurrentIrql = KeGetCurrentIrql();
        __writecr8(2u);
        if ( KiIrqlFlags )
        {
          LOBYTE(v3) = 2;
          LOBYTE(p_Blink) = CurrentIrql;
          LODWORD(v1) = KiRaiseIrqlProcessIrqlFlags(p_Blink, v3);
        }
      }
      if ( !v5 )
      {
        Flink = v7[2].Header.WaitListHead.Flink;
        if ( Flink )
          LODWORD(v1) = KiAbConvertWaiterToOwnerEntry(*((_QWORD *)&Flink[-1].Flink - 11 * ((__int64)Flink->Blink & 0x3F)));
      }
      do
      {
        Blink = (struct _KEVENT *)v7[1].Header.WaitListHead.Blink;
        if ( !_interlockedbittestandreset(&v7[2].Header.SignalState, 1u) )
          LODWORD(v1) = KeSetEvent(v7, 0, 0);
        v7 = Blink;
      }
      while ( Blink );
      if ( CurrentIrql != 2 )
      {
        if ( KiIrqlFlags )
          KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql());
        LODWORD(v1) = CurrentIrql;
        __writecr8(CurrentIrql);
      }
    }
  }
  return v1;
}

```

// --- Calls: ExReleaseAutoExpandPushLockShared at 0x140211480 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 __fastcall ExReleaseAutoExpandPushLockShared(ULONG_PTR BugCheckParameter2, ULONG_PTR BugCheckParameter1)
{
  char v2; // si
  struct _KTHREAD *CurrentThread; // r10
  _KLOCK_ENTRIES *KernelAbEntries; // r8
  unsigned int v5; // edx
  __int64 v6; // r9
  _KLOCK_ENTRY *v7; // rcx
  __int64 result; // rax
  struct _KPRCB *CurrentPrcb; // rcx
  _DWORD *SchedulerAssist; // r8
  __int64 v11; // rdx
  int v12; // ett
  ULONG_PTR v13; // rbx
  unsigned int v14; // edi
  unsigned int v15; // edi
  unsigned __int64 v16; // [rsp+60h] [rbp+18h] BYREF

  v2 = BugCheckParameter1;
  v16 = 0;
  if ( (BugCheckParameter1 & 0xFFFFFFF8) != 0 || (BugCheckParameter2 & 2) != 0 && (BugCheckParameter1 & 2) != 0 )
    KeBugCheckEx(0x152u, (unsigned int)BugCheckParameter1, BugCheckParameter2, 0, 0);
  v13 = BugCheckParameter2 & 0xFFFFFFFFFFFFFFFCuLL;
  if ( (BugCheckParameter2 & 1) != 0 )
  {
    _m_prefetchw((const void *)(v13 + 12));
    v14 = *(_DWORD *)(v13 + 12);
    if ( v14 >= 0x80000000 && (*(_DWORD *)(v13 + 8) & 3) == 0 )
    {
      if ( (unsigned __int16)v14 < (unsigned int)ExpAeCycleCountThreshold
        || (v14 & 0xF0000) >= 0xF0000
        || KeGetCurrentIrql() >= 2u )
      {
        v14 = (v14 >> 2) & 0x3FF33FFF;
        *(_DWORD *)(v13 + 12) = v14;
      }
      else
      {
        ExpTryExpandAutoExpandPushLock(BugCheckParameter2 & 0xFFFFFFFFFFFFFFFCuLL);
      }
    }
    result = _InterlockedCompareExchange64((volatile signed __int64 *)v13, 0, 17);
    if ( result != 17 )
    {
      if ( (v14 & ExpAeSamplingPeriodMask) != 0 )
      {
        ExfReleasePushLockSharedEx(v13, 0);
        result = *(unsigned int *)(v13 + 12);
        if ( (unsigned int)result < 0x80000000 )
        {
          result = (unsigned int)(result + 0x100000);
          *(_DWORD *)(v13 + 12) = result;
        }
        goto LABEL_5;
      }
      result = ExfReleasePushLockSharedEx(v13, &v16);
      if ( !v16 )
        goto LABEL_5;
      v15 = *(_DWORD *)(v13 + 12);
      if ( v15 >= 0x80000000 )
        goto LABEL_5;
      result = v16 >> ExpAeCycleCountScaler;
      if ( v16 >> ExpAeCycleCountScaler > 0x1FF )
        result = 511;
      v14 = result + v15;
    }
    if ( v14 < 0x80000000 )
      *(_DWORD *)(v13 + 12) = v14 + 0x100000;
  }
  else
  {
    result = _InterlockedCompareExchange64((volatile signed __int64 *)v13, 0, 17);
    if ( result != 17 )
      result = ExfReleasePushLockShared((signed __int64 *)(BugCheckParameter2 & 0xFFFFFFFFFFFFFFFCuLL));
    v13 = *(_QWORD *)(v13 + 8);
  }
LABEL_5:
  if ( (v2 & 2) == 0 )
  {
    CurrentThread = KeGetCurrentThread();
    _disable();
    KernelAbEntries = CurrentThread->KernelAbEntries;
    v5 = 0;
    v6 = v13 & 0x7FFFFFFFFFFFFFFCLL;
    while ( v5 < KernelAbEntries->EntryCount )
    {
      v7 = &KernelAbEntries->Entries[v5];
      if ( (*(_QWORD *)&v7->LockState.__s0 & 0x7FFFFFFFFFFFFFFCLL) == v6
        && v7->AcquiredByte
        && (*(_QWORD *)&v7->LockState.__s0 & 1) == 0 )
      {
        v7->AcquiredByte = 0;
        return KiAbEntryFreeAndEnableInterrupts(v7, CurrentThread, v13, 1, 0);
      }
      ++v5;
    }
    result = *((unsigned int *)&CurrentThread->MiscFlags + 1);
    if ( (result & 0x10000) == 0 )
      KeBugCheckEx(0x162u, (ULONG_PTR)CurrentThread, v13, 0, 0);
    CurrentPrcb = KeGetCurrentPrcb();
    SchedulerAssist = CurrentPrcb->SchedulerAssist;
    if ( SchedulerAssist )
    {
      _m_prefetchw(SchedulerAssist);
      LODWORD(result) = *SchedulerAssist;
      do
      {
        v11 = (unsigned int)result;
        LODWORD(v11) = result & 0xFFDFFFFF;
        v12 = result;
        result = (unsigned int)_InterlockedCompareExchange(SchedulerAssist, result & 0xFFDFFFFF, result);
      }
      while ( v12 != (_DWORD)result );
      if ( (result & 0x200000) != 0 )
        result = KiRemoveSystemWorkPriorityKick(CurrentPrcb, v11, SchedulerAssist, v6);
    }
    _enable();
  }
  return result;
}

```

// --- Calls: ExReleaseAutoExpandPushLockExclusive at 0x140212820 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 __fastcall ExReleaseAutoExpandPushLockExclusive(ULONG_PTR BugCheckParameter2, ULONG_PTR BugCheckParameter1)
{
  char v3; // di
  int v4; // eax
  signed __int64 v5; // rax
  signed __int64 v6; // rdx
  __int64 result; // rax
  __int64 v8; // rtt
  struct _KTHREAD *CurrentThread; // r10
  _KLOCK_ENTRIES *KernelAbEntries; // r8
  unsigned int v11; // edx
  ULONG_PTR v12; // r9
  _KLOCK_ENTRY *v13; // rcx
  struct _KPRCB *CurrentPrcb; // rcx
  _DWORD *SchedulerAssist; // r8
  __int64 v16; // rdx
  int v17; // ett

  v3 = BugCheckParameter1;
  if ( (BugCheckParameter1 & 0xFFFFFFF8) != 0 )
    KeBugCheckEx(0x152u, (unsigned int)BugCheckParameter1, BugCheckParameter2, 0, 0);
  v4 = *(_DWORD *)(BugCheckParameter2 + 8);
  if ( (v4 & 1) != 0 )
  {
    ExpReleaseFannedOutPushLockExclusive(v4 & 0xFFFFFFF8);
  }
  else if ( (*(_DWORD *)(BugCheckParameter2 + 12) & 0xF0000u) < 0xF0000 )
  {
    *(_DWORD *)(BugCheckParameter2 + 12) += 0x10000;
  }
  _m_prefetchw((const void *)BugCheckParameter2);
  v5 = *(_QWORD *)BugCheckParameter2;
  v6 = *(_QWORD *)BugCheckParameter2 - 16LL;
  if ( (*(_QWORD *)BugCheckParameter2 & 0xFFFFFFFFFFFFFFF0uLL) <= 0x10 )
    v6 = 0;
  if ( (v5 & 2) != 0
    || (v8 = *(_QWORD *)BugCheckParameter2,
        result = _InterlockedCompareExchange64((volatile signed __int64 *)BugCheckParameter2, v6, v5),
        v8 != result) )
  {
    result = ExfReleasePushLock(BugCheckParameter2, v6);
  }
  if ( (v3 & 2) == 0 )
  {
    CurrentThread = KeGetCurrentThread();
    _disable();
    KernelAbEntries = CurrentThread->KernelAbEntries;
    v11 = 0;
    v12 = BugCheckParameter2 & 0x7FFFFFFFFFFFFFFCLL;
    while ( v11 < KernelAbEntries->EntryCount )
    {
      v13 = &KernelAbEntries->Entries[v11];
      if ( (*(_QWORD *)&v13->LockState.__s0 & 0x7FFFFFFFFFFFFFFCLL) == v12
        && v13->AcquiredByte
        && (*(_QWORD *)&v13->LockState.__s0 & 1) == 0 )
      {
        v13->AcquiredByte = 0;
        return KiAbEntryFreeAndEnableInterrupts(v13, CurrentThread, BugCheckParameter2, 1, 0);
      }
      ++v11;
    }
    result = *((unsigned int *)&CurrentThread->MiscFlags + 1);
    if ( (result & 0x10000) == 0 )
      KeBugCheckEx(0x162u, (ULONG_PTR)CurrentThread, BugCheckParameter2, 0, 0);
    CurrentPrcb = KeGetCurrentPrcb();
    SchedulerAssist = CurrentPrcb->SchedulerAssist;
    if ( SchedulerAssist )
    {
      _m_prefetchw(SchedulerAssist);
      LODWORD(result) = *SchedulerAssist;
      do
      {
        v16 = (unsigned int)result;
        LODWORD(v16) = result & 0xFFDFFFFF;
        v17 = result;
        result = (unsigned int)_InterlockedCompareExchange(SchedulerAssist, result & 0xFFDFFFFF, result);
      }
      while ( v17 != (_DWORD)result );
      if ( (result & 0x200000) != 0 )
        result = KiRemoveSystemWorkPriorityKick(CurrentPrcb, v16, SchedulerAssist, v12);
    }
    _enable();
  }
  return result;
}

```



--- Struct Member Usage & Data Cross-References ---
// No struct context could be determined for this function.

--- Decompiler Warnings ---
using guessed type __int64 __fastcall MmVerifyCallbackFunctionCheckFlags(_QWORD, _QWORD);

0000000140A9FB30  49 8D 7E 08 41 C7 06 07  00 00 00 48 85 D2 74 0E  I.~.A......H....
0000000140A9FB40  48 83 C2 38 48 8B CF E8  64 3D 95 FF EB 13 44 0F  H...H...d=......
0000000140A9FB50  B7 07 33 D2 49 8B 4E 10  E8 E3 78 C1 FF 66 44 89  ..3...N......fD.
0000000140A9FB60  27 85 DB 74 0A 8B D3 49  8B CF E8 E5 15 C9 FF 48  '..............H
0000000140A9FB70  8B 5C 24 50 8B C6 48 8B  74 24 60 48 8B 6C 24 58  .\$P....t$`H.l$X
0000000140A9FB80  48 8B 7C 24 68 48 83 C4  30 41 5F 41 5E 41 5C C3  H.|$hH...A_A^A\.
0000000140A9FB90  CC CC CC CC CC CC CC CC  48 8B C4 48 89 58 08 48  ........H....X.H
0000000140A9FBA0  89 68 18 56 57 41 54 41  56 41 57 48 83 EC 60 45  .h.VWATAVAWH....
0000000140A9FBB0  33 E4 0F 57 C0 44 89 60  10 4C 8B F1 0F 11 40 C8  3......`.L......
0000000140A9FBC0  65 48 8B 04 25 88 01 00  00 48 8D 0D 10 B9 4E 00  eH..%....H....N.
0000000140A9FBD0  B2 01 41 8B EC 41 8B F4  66 FF 88 E4 01 00 00 90  ..A.............
0000000140A9FBE0  E8 8B A2 78 FF 4D 85 F6  0F 84 D6 01 00 00 45 0F  苢  x.M........E.
0000000140A9FBF0  B7 46 02 45 8D 4C 24 02  41 BA 00 01 00 00 66 45  .F.E.L$.A.....fE
0000000140A9FC00  3B C1 0F 82 C3 00 00 00  49 8B 4E 08 48 85 C9 0F  ;.......I.N.H...
0000000140A9FC10  84 B6 00 00 00 41 0F B7  16 66 41 3B D0 0F 87 A1  .....A...fA;....
0000000140A9FC20  01 00 00 66 85 D2 74 7C  66 44 39 21 74 33 66 41  ...f...|fD9!t3fA
0000000140A9FC30  3B D0 75 0D 8B C2 48 D1  E8 66 44 39 64 41 FE 74  ;........fD9dA.t
0000000140A9FC40  20 49 8B C0 49 2B C1 48  3B D0 77 1A 48 8B C2 48   I...+..;...H...
0000000140A9FC50  D1 E8 66 44 39 64 41 FE  74 07 66 44 39 24 41 75  ..fD9dA.t.fD9$Au
0000000140A9FC60  05 48 8B E9 EB 65 49 03  D1 41 B8 50 70 73 75 49  .H....I....PpsuI
0000000140A9FC70  8B CA E8 79 84 0C 00 48  8B D8 48 85 C0 0F 84 F1  ...y...H........
0000000140A9FC80  00 00 00 45 0F B7 06 48  8B C8 49 8B 56 08 E8 AD  ...E...H....V...
0000000140A9FC90  73 C1 FF 41 0F B7 06 48  8B EB 48 D1 E8 66 44 89  s..A...H........
0000000140A9FCA0  24 43 EB 27 66 44 39 21  74 B7 41 B8 50 70 73 75  $C...D9!t.A.Ppsu
0000000140A9FCB0  49 8B D1 49 8B CA E8 35  84 0C 00 48 85 C0 0F 84  I......5...H....
0000000140A9FCC0  B0 00 00 00 66 44 89 20  48 8B E8 C7 84 24 98 00  ....fD. H....$..
0000000140A9FCD0  00 00 00 10 00 00 BB 23  00 00 C0 45 8B FC 8B C3  .......#........
0000000140A9FCE0  48 8B FE 81 FB 23 00 00  C0 0F 85 8C 00 00 00 41  H....#.........A
0000000140A9FCF0  83 FF 05 0F 83 D0 00 00  00 48 85 F6 74 0A 33 D2  .........H......
0000000140A9FD00  48 8B CE E8 C8 8F 0C 00  8B 94 24 98 00 00 00 B9  H...ȏ ....$.....
0000000140A9FD10  00 01 00 00 48 03 D2 41  B8 50 70 20 20 E8 CE 83  ....H....Pp  ...
0000000140A9FD20  0C 00 48 8B F0 48 85 C0  74 4A 48 8B 0D 17 64 3C  ..H.....tJH...d<
0000000140A9FD30  00 48 8D 84 24 98 00 00  00 44 89 64 24 48 45 33  .H..$....D.d$HE3
0000000140A9FD40  C9 48 89 44 24 40 4C 8B  C5 8B 84 24 98 00 00 00  ...D$@L.ŋ .$....
0000000140A9FD50  33 D2 89 44 24 38 48 89  74 24 30 4C 89 64 24 28  3..D$8H.t$0L.d$(
0000000140A9FD60  4C 89 64 24 20 E8 66 98  F1 FF 8B D8 41 FF C7 E9  L.d$ .......A...
0000000140A9FD70  6A FF FF FF BB 9A 00 00  C0 EB 4E 85 C0 78 4A 66  j.........N...Jf
0000000140A9FD80  44 39 26 74 44 48 8B D7  48 8D 4C 24 50 E8 7E DE  D9&tDH....L$P...
0000000140A9FD90  9B FF 8B D8 85 C0 78 14  48 8B 54 24 58 45 33 C0  ...؅ ...H.T$XE3.
0000000140A9FDA0  48 8B 0D A1 63 3C 00 E8  E4 9C F1 FF 0F B7 44 24  H...c<........D$
0000000140A9FDB0  50 48 83 C0 02 48 D1 E8  48 8D 3C 47 66 44 39 27  PH...H..H.<GfD9'
0000000140A9FDC0  75 C3 EB 05 BB 0D 00 00  C0 48 8D 0D 10 B7 4E 00  u.............N.
0000000140A9FDD0  E8 0B DB 76 FF E8 F6 B4  76 FF 48 85 F6 74 0A 33  ...v....v.H.....
0000000140A9FDE0  D2 48 8B CE E8 E7 8E 0C  00 49 8B D6 48 8B CD E8  .........I......
0000000140A9FDF0  7C E0 E0 FF 4C 8D 5C 24  60 8B C3 49 8B 5B 30 49  |...L.\$`....[0I
0000000140A9FE00  8B 6B 40 49 8B E3 41 5F  41 5E 41 5C 5F 5E C3 CC  .k@I....A^A\_^..
0000000140A9FE10  CC CC CC CC CC CC CC CC  48 89 5C 24 08 55 48 8D  ........H.\$.UH.
0000000140A9FE20  6C 24 A9 48 81 EC 90 00  00 00 48 8B 05 CF A8 36  l$.H......H..Ϩ 6
0000000140A9FE30  00 48 33 C4 48 89 45 47  80 3D 0A 78 3C 00 00 48  .H3...EG.=.x<..H
0000000140A9FE40  8B DA C7 45 FF 1A 00 00  00 0F 84 8F 00 00 00 48  ...E...........H
0000000140A9FE50  8B 0D 42 74 46 00 48 8D  15 DB E5 57 FF E8 EE 29  ..BtF.H....W....
0000000140A9FE60  7B FF 84 C0 74 78 8A 05  84 A4 46 00 48 8D 15 C5  {....x....F.H...
0000000140A9FE70  E5 57 FF 83 65 13 00 41  B9 04 00 00 00 83 65 23  ....e..A......e#
0000000140A9FE80  00 45 33 C0 83 65 33 00  83 65 43 00 48 8B 0D 05  .E3..e3..eC.H...
0000000140A9FE90  74 46 00 88 45 F7 48 8D  45 F7 48 89 45 07 48 8D  tF..E.........H.
0000000140A9FEA0  45 FF 48 89 45 17 8B 45  FF C1 E0 03 89 45 2F 48  E.H.E..E.....E/H
0000000140A9FEB0  8D 05 3A A4 46 00 48 89  45 37 48 8D 45 07 48 89  ..:.F.H.E7H.E.H.
0000000140A9FEC0  44 24 20 C7 45 0F 01 00  00 00 44 89 4D 1F 48 89  D$ .......D.M.H.
0000000140A9FED0  5D 27 C7 45 3F 08 00 00  00 E8 72 EA 96 FF 48 8B  ]'..?.........H.
0000000140A9FEE0  4D 47 48 33 CC E8 16 CF  BF FF 48 8B 9C 24 A0 00  MGH3...Ͽ .H..$..
0000000140A9FEF0  00 00 48 81 C4 90 00 00  00 5D C3 CC CC CC CC CC  ..H.Đ ...]......
0000000140A9FF00  CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC  ................
0000000140A9FF10  40 53 48 83 EC 20 48 8D  0D 43 A1 46 00 E8 02 41  @SH......C.F....
0000000140A9FF20  98 FF 8B 05 A0 9D 46 00  48 8B 0D E1 9C 46 00 48  ......F.H......H
0000000140A9FF30  6B D8 70 48 8D 05 96 9D  46 00 C6 05 D7 9C 46 00  k..H....F...ל F.
0000000140A9FF40  00 48 03 D8 E8 33 00 00  00 48 83 0D BF 9C 46 00  .H...3...H....F.
0000000140A9FF50  FF 8B 03 FF C8 83 F8 01  77 08 8A 4B 39 E8 2E EC  ....ȃ ..w..K9...
0000000140A9FF60  CA FF 48 8D 0D F7 A0 46  00 E8 1A B4 91 FF 48 83  ..H...........H.
0000000140A9FF70  C4 20 5B C3 CC CC CC CC  CC CC CC CC 48 89 4C 24  ..[...........L$
0000000140A9FF80  08 55 53 57 48 8B EC 48  83 EC 60 33 FF 40 38 3D  .USWH........@8=
0000000140A9FF90  F0 74 3C 00 0F 84 02 05  00 00 48 8B 0D 2F A3 46  ..........H../.F
0000000140A9FFA0  00 48 8D 15 C0 93 58 FF  E8 A3 28 7B FF 84 C0 0F  .H....X....{....
0000000140A9FFB0  84 E7 04 00 00 BA E0 02  00 00 B9 00 01 00 00 41  ...............A
0000000140A9FFC0  B8 54 56 45 50 E8 26 81  0C 00 48 8B D8 48 85 C0  .TVEP.....H.....
0000000140A9FFD0  0F 84 C6 04 00 00 0F B6  0D AC A3 46 00 8D 57 01  ...........F..W.
0000000140A9FFE0  0F B6 05 A1 A3 46 00 23  C2 40 88 7D 28 89 45 30  .....F.#...}(.E0
0000000140A9FFF0  8B C1 23 C2 89 45 D0 8B  C1 D1 E8 23 C2 89 45 38  .....EЋ ......E8
0000000140AA0000  8B C1 C1 E8 04 23 C2 89  45 F0 8B C1 C1 E8 03 23  ........E.......
0000000140AA0010  C2 89 45 EC 8B C1 C1 E8  05 83 E0 03 C1 E9 02 89  ..E.............
0000000140AA0020  45 E8 23 CA 0F B6 05 B6  A3 46 00 89 45 E0 0F B6  E........F..E...
0000000140AA0030  05 AB A3 46 00 89 45 D8  0F B6 05 79 A3 46 00 89  ...F..E....y.F..
0000000140AA0040  45 DC 8B 05 F0 A2 46 00  89 45 E4 48 8D 05 AE A2  E܋ ......E......
0000000140AA0050  46 00 89 4D D4 48 89 03  48 8D 05 C9 A2 46 00 48  F..M....H..ɢ F.H
0000000140AA0060  C7 43 08 04 00 00 00 48  89 43 10 48 8D 45 30 48  .......H.C.H.E0H
0000000140AA0070  C7 43 18 08 00 00 00 48  89 43 20 48 8D 05 0E A3  .......H.C H....
0000000140AA0080  46 00 48 C7 43 28 04 00  00 00 48 89 43 30 48 8D  F.H..(....H.C0H.
0000000140AA0090  05 03 A3 46 00 48 C7 43  38 08 00 00 00 48 89 43  ...F.H..8....H.C
0000000140AA00A0  40 48 8D 05 F8 A2 46 00  48 C7 43 48 08 00 00 00  @H....F.H..H....
0000000140AA00B0  48 89 43 50 48 8D 05 65  A2 46 00 48 C7 43 58 08  H.CPH..e.F.H..X.
0000000140AA00C0  00 00 00 48 89 43 60 48  8D 05 4E A2 46 00 48 C7  ...H.C`H..N.F.H.
0000000140AA00D0  43 68 08 00 00 00 48 89  43 70 48 8D 05 7F A2 46  Ch....H.CpH....F
0000000140AA00E0  00 48 C7 43 78 04 00 00  00 48 89 83 80 00 00 00  .H..x....H......
0000000140AA00F0  48 8D 45 28 48 C7 83 88  00 00 00 08 00 00 00 48  H.E(Hǃ ........H
0000000140AA0100  89 83 90 00 00 00 48 8D  05 0B A2 46 00 48 89 93  ......H....F.H..
0000000140AA0110  98 00 00 00 48 89 83 A0  00 00 00 48 8D 05 36 A2  ....H......H..6.
0000000140AA0120  46 00 48 C7 83 A8 00 00  00 04 00 00 00 48 89 83  F.Hǃ ........H..
0000000140AA0130  B0 00 00 00 48 8D 05 49  A2 46 00 48 C7 83 B8 00  ....H..I.F.Hǃ ..
0000000140AA0140  00 00 08 00 00 00 48 89  83 C0 00 00 00 48 8D 45  ......H......H.E
0000000140AA0150  38 48 C7 83 C8 00 00 00  04 00 00 00 48 89 83 D0  8Hǃ ........H...
0000000140AA0160  00 00 00 48 8D 45 D0 48  C7 83 D8 00 00 00 04 00  ...H.E..ǃ ......
0000000140AA0170  00 00 48 89 83 E0 00 00  00 48 C7 83 E8 00 00 00  ..H......Hǃ ....
0000000140AA0180  04 00 00 00 48 C7 83 F8  00 00 00 08 00 00 00 48  ....Hǃ ........H
0000000140AA0190  8D 05 D2 A1 46 00 48 89  83 F0 00 00 00 48 8D 45  ..ҡ F.H......H.E
0000000140AA01A0  D4 48 89 83 00 01 00 00  48 8D 05 01 A2 46 00 48  ........H....F.H
0000000140AA01B0  C7 83 08 01 00 00 04 00  00 00 48 89 83 10 01 00  ǃ ........H.....
0000000140AA01C0  00 48 8D 05 EC A1 46 00  48 C7 83 18 01 00 00 04  .H......Hǃ .....
0000000140AA01D0  00 00 00 48 89 83 20 01  00 00 48 8D 05 DB A1 46  ...H.. ...H....F
0000000140AA01E0  00 48 C7 83 28 01 00 00  04 00 00 00 48 89 83 30  .Hǃ (.......H..0
0000000140AA01F0  01 00 00 48 8D 05 CE A1  46 00 48 C7 83 38 01 00  ...H..Ρ F.Hǃ 8..
0000000140AA0200  00 04 00 00 00 48 89 83  40 01 00 00 48 8D 05 B9  .....H..@...H...
0000000140AA0210  A1 46 00 48 C7 83 48 01  00 00 04 00 00 00 48 89  .F.Hǃ H.......H.
0000000140AA0220  83 50 01 00 00 48 8D 05  DC A0 46 00 48 C7 83 58  .P...H..ܠ F.Hǃ X
0000000140AA0230  01 00 00 04 00 00 00 48  89 83 60 01 00 00 48 8D  .......H..`...H.
0000000140AA0240  05 CB A0 46 00 48 C7 83  68 01 00 00 04 00 00 00  .ˠ F.Hǃ h.......
0000000140AA0250  48 89 83 70 01 00 00 48  8D 05 7E A1 46 00 48 C7  H..p...H..~.F.H.
0000000140AA0260  83 78 01 00 00 08 00 00  00 48 89 83 80 01 00 00  .x.......H......
0000000140AA0270  48 8D 45 D8 48 C7 83 88  01 00 00 04 00 00 00 48  H.E..ǃ ........H
0000000140AA0280  89 83 90 01 00 00 48 8D  05 57 A1 46 00 48 C7 83  ......H..W.F.Hǃ 
0000000140AA0290  98 01 00 00 04 00 00 00  48 89 83 A0 01 00 00 48  ........H......H
0000000140AA02A0  8D 05 42 A1 46 00 48 C7  83 A8 01 00 00 04 00 00  ..B.F.Hǃ .......
0000000140AA02B0  00 48 89 83 B0 01 00 00  48 8D 45 DC 48 C7 83 B8  .H......H.E..ǃ .
0000000140AA02C0  01 00 00 04 00 00 00 48  89 83 C0 01 00 00 48 8D  .......H......H.
0000000140AA02D0  45 E0 48 C7 83 C8 01 00  00 04 00 00 00 48 89 83  E............H..
0000000140AA02E0  D0 01 00 00 48 8D 45 20  48 C7 83 D8 01 00 00 04  ....H.E Hǃ .....
0000000140AA02F0  00 00 00 48 89 83 E0 01  00 00 48 8D 05 BF A0 46  ...H......H....F
0000000140AA0300  00 48 C7 83 E8 01 00 00  08 00 00 00 48 89 83 F0  .Hǃ ........H...
0000000140AA0310  01 00 00 48 8D 05 AA A0  46 00 48 C7 83 F8 01 00  ...H....F.Hǃ ...
0000000140AA0320  00 04 00 00 00 48 89 83  00 02 00 00 48 8D 45 E4  .....H......H.E.
0000000140AA0330  48 C7 83 08 02 00 00 04  00 00 00 48 89 83 10 02  Hǃ ........H....
0000000140AA0340  00 00 48 8D 45 E8 48 C7  83 18 02 00 00 04 00 00  ..H.E...........
0000000140AA0350  00 48 89 83 20 02 00 00  48 8D 45 EC 48 C7 83 28  .H.. ...H.E....(
0000000140AA0360  02 00 00 04 00 00 00 48  89 83 30 02 00 00 48 8D  .......H..0...H.
0000000140AA0370  45 F0 48 C7 83 38 02 00  00 04 00 00 00 48 89 83  E....8.......H..
0000000140AA0380  40 02 00 00 48 8D 05 ED  9F 46 00 48 C7 83 48 02  @...H......Hǃ H.
0000000140AA0390  00 00 04 00 00 00 48 89  83 50 02 00 00 48 8D 05  ......H..P...H..
0000000140AA03A0  CC 9F 46 00 48 C7 83 58  02 00 00 04 00 00 00 48  ..F.Hǃ X.......H
0000000140AA03B0  89 83 60 02 00 00 48 8D  05 9F A0 46 00 48 C7 83  ..`...H....F.Hǃ 
0000000140AA03C0  68 02 00 00 08 00 00 00  48 89 83 70 02 00 00 48  h.......H..p...H
0000000140AA03D0  8D 05 AE A0 46 00 48 C7  83 78 02 00 00 04 00 00  ....F.Hǃ x......
0000000140AA03E0  00 48 89 83 80 02 00 00  48 8D 05 99 A0 46 00 48  .H......H....F.H
0000000140AA03F0  89 93 88 02 00 00 48 89  83 90 02 00 00 48 C7 83  ......H......Hǃ 
0000000140AA0400  98 02 00 00 08 00 00 00  48 C7 83 A8 02 00 00 08  ........Hǃ .....
0000000140AA0410  00 00 00 48 8D 05 76 A0  46 00 48 89 83 A0 02 00  ...H..v.F.H.....
0000000140AA0420  00 44 8D 4F 2E 48 C7 83  B8 02 00 00 08 00 00 00  .D.O.Hǃ ........
0000000140AA0430  48 8D 05 61 A0 46 00 48  89 83 B0 02 00 00 4C 8D  H..a.F.H......L.
0000000140AA0440  05 43 70 3C 00 48 C7 83  C8 02 00 00 08 00 00 00  .Cp<.Hǃ ........
0000000140AA0450  48 8D 05 49 A0 46 00 48  89 83 C0 02 00 00 48 8D  H..I.F.H......H.
0000000140AA0460  15 03 8F 58 FF 48 8D 05  3C A0 46 00 48 C7 83 D8  ...X.H..<.F.Hǃ .
0000000140AA0470  02 00 00 08 00 00 00 48  89 83 D0 02 00 00 48 8B  .......H......H.
0000000140AA0480  0D 4B 9E 46 00 48 89 5C  24 20 E8 C1 E4 96 FF BA  .K.F.H.\$ ......
0000000140AA0490  54 56 45 50 48 8B CB E8  34 88 0C 00 48 83 C4 60  TVEPH...4...H...
0000000140AA04A0  5F 5B 5D C3 CC CC CC CC  CC CC CC CC 4C 8B DC 49  _[].............
0000000140AA04B0  89 5B 18 56 57 41 56 48  83 EC 40 48 8B 05 3E A2  .[.VWAVH......>.
0000000140AA04C0  36 00 48 33 C4 48 89 44  24 38 33 FF 8B C2 48 8B  6.H3...D$83.....
0000000140AA04D0  F1 49 89 7B C8 33 C9 8B  D7 45 85 C0 49 89 4B D0  ......ɋ ......K.
0000000140AA04E0  4D 8B F1 89 4C 24 30 0F  94 C2 4D 8D 4B D0 4D 8D  M.....0.....K...
0000000140AA04F0  43 C8 8B C8 8B DF E8 B5  75 A1 FF 8B D0 85 C0 75  Cȋ ȋ ...u...Ѕ ..
0000000140AA0500  39 8B 4C 24 2C 8D 5F 01  8B C1 C1 E8 04 83 E0 03  9.L$,._.........
0000000140AA0510  89 06 8B C1 C1 E8 08 24  3F 88 46 04 8B 44 24 30  ........?.F..D$0
0000000140AA0520  89 46 0C 8B C1 C1 E8 0E  83 E0 03 89 46 08 8B C1  .F..........F...
0000000140AA0530  C1 E8 06 23 C3 89 46 14  EB 11 81 FA 17 01 00 00  ...#É F.........
0000000140AA0540  75 11 8B 4C 24 2C BB 01  00 00 00 C1 E9 07 23 CB  u..L$,........#.
0000000140AA0550  89 4E 10 4D 85 F6 74 0D  81 FA 22 00 00 80 40 0F  .N.M......"...@.
0000000140AA0560  95 C7 41 89 3E 8B C3 48  8B 4C 24 38 48 33 CC E8  ....>....L$8H3..
0000000140AA0570  8C C8 BF FF 48 8B 5C 24  70 48 83 C4 40 41 5E 5F  .ȿ .H.\$pH...A^_
0000000140AA0580  5E C3 CC CC CC CC CC CC  CC CC CC CC CC CC CC CC  ^...............
0000000140AA0590  48 89 5C 24 08 48 89 74  24 10 57 48 83 EC 30 33  H.\$.H.t$.WH....
0000000140AA05A0  DB 48 8B FA 89 5C 24 24  48 85 D2 75 07 B8 0D 00  .....\$$H.......
0000000140AA05B0  00 C0 EB 57 48 85 C9 74  0D 48 8B 81 38 01 00 00  ...WH....H..8...
0000000140AA05C0  48 8B 48 28 EB 07 48 8B  0D B3 AD 4E 00 4C 8D 44  H.H(.......N.L.D
0000000140AA05D0  24 20 48 89 5C 24 28 48  8D 15 52 97 FB FF 89 5C  $ H.\$(H..R....\
0000000140AA05E0  24 20 E8 09 C0 F9 FF 8B  F0 85 C0 78 0F 48 8B 4C  $ ...........H.L
0000000140AA05F0  24 28 48 89 0F 48 89 5C  24 28 EB 05 48 8B 5C 24  $(H..H.\$(....\$
0000000140AA0600  28 48 8B CB E8 6F AD FD  FF 8B C6 48 8B 5C 24 40  (H...o.......\$@
0000000140AA0610  48 8B 74 24 48 48 83 C4  30 5F C3 CC CC CC CC CC  H.t$HH..._......
0000000140AA0620  CC CC CC CC 4C 8B DC 49  89 5B 08 49 89 73 10 55  ....L....[.I.s.U
0000000140AA0630  49 8D 6B A1 48 81 EC 90  00 00 00 49 83 63 90 00  I.k.H......I.c..
0000000140AA0640  48 8D 45 1F 83 65 1B 00  0F 57 C0 48 83 65 27 00  H.E..e...W...e'.
0000000140AA0650  41 8B D8 48 83 65 1F 00  40 8A F2 45 33 C0 49 89  A....e..@.....I.
0000000140AA0660  43 88 33 D2 C6 45 7F 00  45 33 C9 0F 11 45 2F 0F  C.3..E..E3...E/.
0000000140AA0670  11 45 3F E8 78 09 DA FF  89 45 17 85 C0 0F 88 9F  .E?......E......
0000000140AA0680  00 00 00 48 8B 4D 1F 4C  8D 45 7F 45 33 C9 48 8D  ...H.M.L.E.E3...
0000000140AA0690  55 27 E8 69 92 DA FF 89  45 17 85 C0 78 74 48 8D  U'......E....tH.
0000000140AA06A0  4D 2F E8 F9 32 DA FF 48  8D 45 17 44 8B CB 48 89  M/.....H.E.D....
0000000140AA06B0  44 24 48 48 8D 55 2F 48  8D 45 1B 45 33 C0 48 89  D$HH.U/H.E.E3...
0000000140AA06C0  44 24 40 48 8D 05 06 0F  09 00 40 88 74 24 38 48  D$@H......@.t$8H
0000000140AA06D0  8B 75 27 48 89 44 24 30  48 8B CE 48 83 64 24 28  .u'H.D$0H....d$(
0000000140AA06E0  00 83 64 24 20 00 E8 F5  5A 8D FF 48 8D 4D 2F 8A  ..d$ ......H.M/.
0000000140AA06F0  D8 E8 9A 31 DA FF 84 DB  74 04 83 65 17 00 48 85  ...1.......e..H.
0000000140AA0700  F6 74 0F 4C 8B 45 1F 48  8B CE 8A 55 7F E8 0E E2  .....E.H.Ί U....
0000000140AA0710  DB FF 48 83 7D 1F 00 74  09 48 8B 4D 1F E8 3E F5  ..H.}..t.H.M....
0000000140AA0720  86 FF 8B 45 17 4C 8D 9C  24 90 00 00 00 49 8B 5B  ...E.L..$....I.[
0000000140AA0730  10 49 8B 73 18 49 8B E3  5D C3 CC CC CC CC CC CC  .I.s.I..........
0000000140AA0740  CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC  ................
0000000140AA0750  48 8B 81 40 06 00 00 C3  CC CC CC CC CC CC CC CC  H..@............
0000000140AA0760  48 83 EC 38 48 8B 05 BD  69 53 00 48 85 C0 74 0E  H.......iS.H....
0000000140AA0770  48 8B 00 E8 58 AB C0 FF  48 83 C4 38 C3 CC B8 BB  H.......H.......
0000000140AA0780  00 00 C0 EB F3 CC CC CC  CC CC CC CC 48 89 5C 24  ............H.\$
0000000140AA0790  08 48 89 6C 24 10 48 89  74 24 20 57 41 54 41 55  .H.l$.H.t$ WATAU
0000000140AA07A0  41 56 41 57 48 81 EC 50  01 00 00 48 8B 05 4E 9F  AVAWH......H..N.
0000000140AA07B0  36 00 48 33 C4 48 89 84  24 40 01 00 00 65 48 8B  6.H3....$@...eH.
0000000140AA07C0  04 25 88 01 00 00 4C 8D  2D 73 BD 4E 00 45 33 E4  .%....L.-s.N.E3.
0000000140AA07D0  49 8B F8 4C 8B F2 4C 8B  F9 41 8B EC 40 8A B0 32  I..L.....A.....2
0000000140AA07E0  02 00 00 48 8D 1D 16 BD  4E 00 4C 39 25 47 84 53  ...H....N.L9%G.S
0000000140AA07F0  00 0F 85 D7 00 00 00 48  8B 05 6A 87 53 00 44 39  .......H..j.S.D9
0000000140AA0800  60 04 0F 84 FC 01 00 00  45 33 C9 4C 89 64 24 20  `.......E3...d$ 
0000000140AA0810  44 8A C6 33 D2 49 8B CD  E8 63 D0 84 FF 3D C0 00  D........cЄ .=..
0000000140AA0820  00 00 0F 84 05 02 00 00  3D 01 01 00 00 0F 84 FA  ........=.......
0000000140AA0830  01 00 00 4C 39 25 FE 83  53 00 0F 85 81 00 00 00  ...L9%..S.......
0000000140AA0840  48 8D 05 A9 85 C6 FF 48  89 1D CA BC 4E 00 48 8D  H......H..ʼ N.H.
0000000140AA0850  0D CB BC 4E 00 48 89 05  B4 BC 4E 00 4C 89 25 9D  .˼ N.H....N.L.%.
0000000140AA0860  BC 4E 00 E8 08 1B 7A FF  BA 01 00 00 00 48 8B CB  .N....z......H..
0000000140AA0870  E8 BB F5 86 FF 45 33 C9  4C 89 64 24 20 44 8A C6  .....E3...d$ D..
0000000140AA0880  48 8D 0D 99 BC 4E 00 33  D2 E8 F2 CF 84 FF 8B D8  H....N.3........
0000000140AA0890  3D C0 00 00 00 74 12 3D  01 01 00 00 74 0B 8B 0D  =....t.=....t...
0000000140AA08A0  94 BC 4E 00 85 C9 0F 48  D9 45 33 C0 33 D2 49 8B  ..N....H..3.....
0000000140AA08B0  CD E8 9A 51 78 FF 85 DB  74 14 8B C3 E9 6C 01 00  ...Qx........l..
0000000140AA08C0  00 45 33 C0 33 D2 49 8B  CD E8 82 51 78 FF BA B8  .E3........Qx...
0000000140AA08D0  00 00 00 41 B8 49 6F 20  20 8D 4A 48 E8 0F 78 0C  ...A.Io  .JH....
0000000140AA08E0  00 48 8B D8 48 85 C0 0F  84 3B 01 00 00 4C 89 60  .H.......;...L.`
0000000140AA08F0  28 41 0F 10 07 0F 11 40  30 41 8B 4F 10 89 48 40  (A.....@0A.O..H@
0000000140AA0900  41 0F 28 06 0F 11 40 44  41 0F 28 4E 10 0F 11 48  A.(...@DA.(N...H
0000000140AA0910  54 41 0F 28 46 20 0F 11  40 64 41 0F 28 4E 30 0F  TA.(F ..@dA.(N0.
0000000140AA0920  11 48 74 83 7F 08 24 0F  82 EA 00 00 00 8B 47 0C  .Ht...$.......G.
0000000140AA0930  89 83 84 00 00 00 0F 10  47 10 F3 0F 7F 83 88 00  ........G.......
0000000140AA0940  00 00 0F 10 4F 20 F3 0F  7F 8B 98 00 00 00 8B 47  ....O .........G
0000000140AA0950  08 83 F8 24 76 21 83 C0  DC 41 B8 10 00 00 00 83  ...$v!...A......
0000000140AA0960  F8 10 77 03 44 8B C0 48  8D 57 30 48 8D 8B A8 00  ..w.D....W0H....
0000000140AA0970  00 00 E8 C9 66 C1 FF 48  C7 03 90 00 B8 00 48 8D  .......H......H.
0000000140AA0980  44 24 30 48 8B 0D AE 82  53 00 4C 8D 4C 24 40 4C  D$0H....S.L.L$@L
0000000140AA0990  89 64 24 28 4C 8B C3 BA  00 00 02 00 48 89 44 24  .d$(L.ú ....H.D$
0000000140AA09A0  20 48 C7 44 24 30 00 01  00 00 E8 01 A4 F8 FF 8B   H..$0..........
0000000140AA09B0  D8 3D 37 00 00 C0 74 07  3D 03 07 00 C0 75 4C 45  ..7.....=.....LE
0000000140AA09C0  33 C9 4C 89 64 24 20 44  8A C6 33 D2 49 8B CD E8  3...d$ D........
0000000140AA09D0  AC CE 84 FF 48 8B 0D 5D  82 53 00 8B D8 E8 7E F2  .΄ .H..].S....~.
0000000140AA09E0  86 FF 45 33 C0 4C 89 25  4C 82 53 00 33 D2 49 8B  ..E3...%L.S.3...
0000000140AA09F0  CD E8 5A 50 78 FF 85 ED  75 11 BD 01 00 00 00 E9  ..ZPx...........
0000000140AA0A00  DF FD FF FF B8 9F 02 00  C0 EB 22 85 DB 0F 49 5C  .........."...I\
0000000140AA0A10  24 68 E9 A3 FE FF FF 33  D2 48 8B CB E8 AF 82 0C  $h.....3........
0000000140AA0A20  00 B8 05 00 00 80 EB 05  B8 9A 00 00 C0 48 8B 8C  ................
0000000140AA0A30  24 40 01 00 00 48 33 CC  E8 C3 C3 BF FF 4C 8D 9C  $@...H3......L..
0000000140AA0A40  24 50 01 00 00 49 8B 5B  30 49 8B 6B 38 49 8B 73  $P...I.[0I.k8I.s
0000000140AA0A50  48 49 8B E3 41 5F 41 5E  41 5D 41 5C 5F C3 CC CC  HI....A^A]A\_...
0000000140AA0A60  CC CC CC CC CC CC CC CC  48 89 5C 24 10 57 48 83  ........H.\$.WH.
0000000140AA0A70  EC 60 48 8B 05 87 9C 36  00 48 33 C4 48 89 44 24  .......6.H3...D$
0000000140AA0A80  50 0F 57 C0 48 8B F9 0F  11 44 24 20 0F 11 44 24  P.W......D$ ..D$
0000000140AA0A90  30 0F 11 44 24 40 E8 29  D4 9E FF 65 48 8B 04 25  0..D$@.....eH..%
0000000140AA0AA0  88 01 00 00 4C 8D 44 24  20 33 D2 48 8B 88 B8 00  ....L.D$ 3......
0000000140AA0AB0  00 00 48 8B 81 10 04 00  00 48 8B CF 48 89 87 10  ..H......H......
0000000140AA0AC0  04 00 00 E8 E8 A4 86 FF  33 D2 48 8B CF E8 A6 02  ........3.......
0000000140AA0AD0  E5 FF 48 85 C0 75 07 BB  17 00 00 C0 EB 0D 48 8B  ..............H.
0000000140AA0AE0  D0 48 8B CF E8 9F 00 E5  FF 8B D8 33 D2 48 8D 4C  ...............L
0000000140AA0AF0  24 20 E8 99 B9 86 FF 85  DB 78 19 8B 15 BB 50 52  $ 虹  .........PR
0000000140AA0B00  00 81 E2 01 00 00 10 83  FA 01 75 08 48 8B CF E8  ..........u.H...
0000000140AA0B10  AC CB D3 FF 8B C3 48 8B  4C 24 50 48 33 CC E8 DD  ........L$PH3...
0000000140AA0B20  C2 BF FF 48 8B 5C 24 78  48 83 C4 60 5F C3 CC CC  ¿ .H.\$xH..._...
0000000140AA0B30  CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC  ................
0000000140AA0B40  48 89 5C 24 08 48 89 74  24 10 57 48 83 EC 20 48  H.\$.H.t$.WH....
0000000140AA0B50  8B F2 48 8B F9 48 85 D2  74 27 48 85 C9 48 8D 05  .....H...'H.....
0000000140AA0B60  CC 5F 3C 00 48 8B D9 48  0F 44 D8 45 33 C0 48 8B  ..<.H....D..3...
0000000140AA0B70  CB E8 EA E5 84 FF 48 8B  D6 48 8B CB E8 EF F5 76  ......H.........
0000000140AA0B80  FF 48 85 FF 74 08 48 8B  CF E8 4A 82 EA FF 48 8B  .H..t.H...J.....
0000000140AA0B90  5C 24 30 48 8B 74 24 38  48 83 C4 20 5F C3 CC CC  \$0H.t$8H..._...
0000000140AA0BA0  CC CC CC CC CC CC CC CC  48 89 5C 24 08 48 89 6C  ........H.\$.H.l
0000000140AA0BB0  24 10 48 89 74 24 18 57  48 83 EC 20 48 8B 59 60  $.H.t$.WH.....Y`
0000000140AA0BC0  48 8B F1 48 83 E3 F8 48  8B 6B 20 48 8B 5B 28 48  H......H.k H.[(H
0000000140AA0BD0  8B D5 65 48 8B 3C 25 88  01 00 00 48 8B CF E8 DD  ...H.<%....H....
0000000140AA0BE0  D8 9B FF 48 8B 16 48 83  E3 F8 48 8B CB 48 8B 52  ؛ .H..H........R
0000000140AA0BF0  20 E8 EA E6 E4 FF 48 8B  D5 48 8B CF 8B D8 E8 ED   ..........ϋ ...
0000000140AA0C00  2C 9C FF 48 8B 6C 24 38  8B C3 48 8B 5C 24 30 48  ,..H.l$8....\$0H
0000000140AA0C10  8B 74 24 40 48 83 C4 20  5F C3 CC CC CC CC CC CC  .t$@H..._.......
0000000140AA0C20  CC CC CC CC 48 89 5C 24  08 48 89 74 24 10 57 48  ....H.\$.H.t$.WH
0000000140AA0C30  83 EC 30 8B 42 04 48 8B  DA 83 E0 1F 48 8B F9 83  ....B.H.ڃ ......
0000000140AA0C40  E8 02 83 F8 01 77 3B 48  8B 52 10 0F 10 81 B0 02  .....w;H.R......
0000000140AA0C50  00 00 0F 11 02 F2 0F 10  89 C0 02 00 00 F2 0F 11  ................
0000000140AA0C60  4A 10 8B 43 04 24 1F 3C  02 75 0B 8B 52 18 C1 EA  J..C.$.<.u..R...
0000000140AA0C70  05 83 E2 07 EB 07 E8 15  2D 9E FF 8B D0 E8 AA 09  ................
0000000140AA0C80  0B 00 8B 43 04 83 E0 1F  3C 1B 75 17 48 8B 43 10  ...C......u.H.C.
0000000140AA0C90  8B 48 08 80 E1 03 80 F9  01 75 08 F0 83 25 29 D4  .H.......u......
0000000140AA0CA0  46 00 FE 48 B8 20 03 00  00 80 F7 FF FF 48 B9 04  F..H. ..........
0000000140AA0CB0  00 00 00 80 F7 FF FF 48  8B 00 8B 09 44 8B 4B 04  ............D.K.
0000000140AA0CC0  8B F0 48 0F AF F1 48 C1  E8 20 48 C1 EE 18 48 0F  ......... H...H.
0000000140AA0CD0  AF C1 41 C1 E9 05 48 C1  E0 08 48 03 F0 48 C1 EE  ......H...H.....
0000000140AA0CE0  0A 03 35 65 60 3C 00 41  F6 C1 01 74 26 48 8B CF  ..5e`<.A....&H..
0000000140AA0CF0  E8 EB FA A1 FF 41 D1 E9  4C 8B C0 41 83 E1 01 33  .....A..L.......
0000000140AA0D00  D2 41 8B C9 E8 37 2C D4  FF 33 D2 48 8B CF E8 A9  .....7,..3......
0000000140AA0D10  C6 C9 FF 8B 53 04 44 8B  C6 4C 8B 4B 10 8B C2 C1  ....S.D....K....
0000000140AA0D20  E8 07 83 E2 1F 48 8B CF  89 44 24 20 E8 97 AC 8B  .......ω D$ 藬  .
0000000140AA0D30  FF 48 8B 5C 24 40 48 8B  74 24 48 48 83 C4 30 5F  .H.\$@H.t$HH..._
0000000140AA0D40  C3 CC CC CC CC CC CC CC  89 54 24 10 89 4C 24 08  .........T$..L$.
0000000140AA0D50  55 48 8D 6C 24 A9 48 81  EC 90 00 00 00 48 8B 05  UH.l$.H......H..
0000000140AA0D60  9C 99 36 00 48 33 C4 48  89 45 47 E8 80 35 9D FF  ..6.H3...EG.....
0000000140AA0D70  45 33 C0 48 8B 90 50 03  00 00 0F B7 02 66 D1 E8  E3....P......f..
0000000140AA0D80  44 38 05 FE 66 3C 00 66  89 45 F7 74 5A 48 C7 45  D8..f<.f.E......
0000000140AA0D90  0F 02 00 00 00 45 8D 48  04 48 8D 45 F7 48 89 45  .....E.H.H.E....
0000000140AA0DA0  07 48 8B 42 08 0F B7 0A  48 8D 15 89 D7 57 FF 48  .H.B....H......H
0000000140AA0DB0  89 45 17 48 8D 45 67 48  89 45 27 48 8D 45 6F 48  .E.H.EgH.E'H.EoH
0000000140AA0DC0  89 45 37 48 8D 45 07 89  4D 1F 48 8B 0D 87 97 46  .E7H.E..M.H....F
0000000140AA0DD0  00 48 89 44 24 20 44 89  45 23 4C 89 4D 2F 4C 89  .H.D$ D.E#L.M/L.
0000000140AA0DE0  4D 3F E8 69 DB 96 FF 48  8B 4D 47 48 33 CC E8 0D  M?.....H.MGH3...
0000000140AA0DF0  C0 BF FF 48 81 C4 90 00  00 00 5D C3 CC CC CC CC  ...H.Đ ...].....
0000000140AA0E00  CC CC CC CC 48 89 5C 24  10 57 48 83 EC 60 48 8B  ....H.\$.WH.....
0000000140AA0E10  05 EB 98 36 00 48 33 C4  48 89 44 24 58 83 64 24  .....H3...D$X.d$
0000000140AA0E20  20 00 0F 57 C0 0F 11 44  24 28 48 8B F9 0F 11 44   ..W...D$(H....D
0000000140AA0E30  24 38 0F 11 44 24 48 E8  90 0C DD FF 48 83 C7 10  $8..D$H.....H...
0000000140AA0E40  48 8B 1F 48 3B DF 0F 84  A7 00 00 00 48 39 7B 08  H..H;.......H9{.
0000000140AA0E50  0F 85 96 00 00 00 48 8B  03 48 39 58 08 0F 85 89  ......H..H9X....
0000000140AA0E60  00 00 00 48 89 07 48 8D  0D D3 44 45 00 48 89 78  ...H..H....E.H.x
0000000140AA0E70  08 E8 DA 68 86 FF E8 55  A4 76 FF 48 8D 54 24 20  .........v.H.T$ 
0000000140AA0E80  48 8B CB E8 D8 7E F6 FF  48 8D 4C 24 28 E8 4E EA  H.........L$(...
0000000140AA0E90  10 00 BA 08 00 00 00 48  8B CB E8 35 0D DD FF 48  .......H...5...H
0000000140AA0EA0  8D 4C 24 28 E8 77 EA 10  00 48 83 7B 38 00 74 09  .L$(.....H.{8.t.
0000000140AA0EB0  48 8B 4B 38 E8 F3 EC DC  FF 48 8B 4B 48 48 85 C9  H.K8.....H.KHH..
0000000140AA0EC0  74 05 E8 99 ED 86 FF 48  8B 4B 50 48 85 C9 74 05  t......H.KPH....
0000000140AA0ED0  E8 FB CB BF FF BA 43 4D  54 72 48 8B CB E8 EE 7D  ......CMTrH.....
0000000140AA0EE0  0C 00 E8 E5 0B DD FF E9  54 FF FF FF B9 03 00 00  ................
0000000140AA0EF0  00 CD 29 48 8D 0D 46 44  45 00 E8 51 68 86 FF E8  ...H..FDE.......
0000000140AA0F00  CC A3 76 FF 33 C0 48 8B  4C 24 58 48 33 CC E8 ED  ..v.3...L$XH3...
0000000140AA0F10  BE BF FF 48 8B 5C 24 78  48 83 C4 60 5F C3 CC CC  ...H.\$xH..._...
0000000140AA0F20  CC CC CC CC CC CC CC CC  40 55 48 8D 6C 24 B1 48  ........@UH.l$.H
0000000140AA0F30  81 EC E0 00 00 00 48 8B  05 C3 97 36 00 48 33 C4  ......H..× 6.H3.
0000000140AA0F40  48 89 45 3F 83 3D 35 67  36 00 05 44 8B D2 44 8A  H.E?.=5g6..D....
0000000140AA0F50  D9 0F 86 CA 00 00 00 48  BA 00 00 00 00 00 40 00  .......H......@.
0000000140AA0F60  00 48 8D 0D 18 67 36 00  E8 D3 17 98 FF 84 C0 0F  .H...g6.........
0000000140AA0F70  84 AC 00 00 00 83 65 EB  00 48 8D 45 9F 83 65 FB  ......e....E..e.
0000000140AA0F80  00 48 8D 0D F8 66 36 00  83 65 0B 00 BA 04 00 00  .H...f6..e......
0000000140AA0F90  00 83 65 1B 00 83 65 2B  00 83 65 3B 00 48 89 45  ..e...e+..e;.H.E
0000000140AA0FA0  DF 48 8D 45 A3 48 89 45  EF 48 8D 45 A7 48 89 45  ...E.H.E...E.H.E
0000000140AA0FB0  FF 48 8D 45 AB 48 89 45  0F 8B 45 7F 89 45 AF 48  .H.E.H.E..E..E.H
0000000140AA0FC0  8D 45 AF 48 89 45 1F 48  8D 45 B7 89 55 F7 89 55  .E.H.E.H.E..U...
0000000140AA0FD0  07 89 55 17 89 55 27 BA  08 00 00 00 48 89 45 2F  ..U..U'.....H.E/
0000000140AA0FE0  48 8D 45 BF 48 89 44 24  28 89 54 24 20 44 89 45  H.E.H.D$(.T$ D.E
0000000140AA0FF0  A7 45 33 C0 44 89 4D AB  45 33 C9 89 55 37 48 8D  .E3...M.E3ɉ U7H.
0000000140AA1000  15 D1 7B 5A FF 44 88 5D  9F C7 45 E7 01 00 00 00  ...Z.D.]........
0000000140AA1010  44 89 55 A3 48 C7 45 B7  00 00 00 01 E8 9F 5C 97  D.U.H...........
0000000140AA1020  FF 48 8B 4D 3F 48 33 CC  E8 D3 BD BF FF 48 81 C4  .H.M?H3..ӽ ..H..
0000000140AA1030  E0 00 00 00 5D C3 CC CC  CC CC CC CC CC CC CC CC  ....]...........
0000000140AA1040  48 89 5C 24 10 57 48 83  EC 20 48 83 64 24 30 00  H.\$.WH.....d$0.
0000000140AA1050  48 8B F9 48 8B 49 08 48  8B DA 48 85 C9 75 13 48  H..H.I.H.......H
0000000140AA1060  21 0A 48 21 4A 08 48 21  4A 10 48 8B 07 48 89 02  !.H!J.H!J.H..H..
0000000140AA1070  EB 39 48 83 64 24 40 00  4C 8D 44 24 40 48 8D 54  ....d$@.L.D$@H.T
0000000140AA1080  24 30 E8 49 C0 E9 FF 85  C0 78 22 48 83 23 00 48  $0........"H.#.H
0000000140AA1090  83 63 10 00 48 8B 44 24  30 48 89 43 08 48 8B 47  .c..H.D$0H.C.H.G
0000000140AA10A0  10 48 89 43 10 48 8B 07  48 89 03 33 C0 48 8B 5C  .H.C.H..H..3...\
0000000140AA10B0  24 38 48 83 C4 20 5F C3  CC CC CC CC CC CC CC CC  $8H..._.........
0000000140AA10C0  48 83 EC 78 48 8B 05 35  96 36 00 48 33 C4 48 89  H......5.6.H3...
0000000140AA10D0  44 24 60 44 8B DA E8 9D  51 9F FF 45 33 D2 84 C0  D$`D....Q..E3...
0000000140AA10E0  74 44 8B D1 48 8D 4C 24  20 E8 B6 16 A3 FF 41 8B  tD....L$ .....A.
0000000140AA10F0  D3 48 8D 4C 24 30 E8 A9  16 A3 FF 45 85 C0 48 8D  ...L$0.....E....
0000000140AA1100  4C 24 40 41 0F 94 C2 41  8B D2 E8 95 16 A3 FF 41  L$@A...........A
0000000140AA1110  8B D1 48 8D 4C 24 50 E8  88 16 A3 FF 4C 8D 4C 24  ....L$P.....L.L$
0000000140AA1120  20 E8 12 38 A0 FF 48 8B  4C 24 60 48 33 CC E8 CD   .....H.L$`H3...
0000000140AA1130  BC BF FF 48 83 C4 78 C3  CC CC CC CC CC CC CC CC  ...H............
0000000140AA1140  40 55 48 8D 6C 24 A9 48  81 EC 90 00 00 00 48 8B  @UH.l$.H......H.
0000000140AA1150  05 AB 95 36 00 48 33 C4  48 89 45 47 48 8B 15 5D  ...6.H3...EGH..]
0000000140AA1160  CD 46 00 48 85 D2 0F 84  A8 00 00 00 C6 45 F8 04  ...H............
0000000140AA1170  C6 45 F7 00 80 3A 00 0F  86 97 00 00 00 32 C0 83  .............2..
0000000140AA1180  65 13 00 41 B9 04 00 00  00 83 65 23 00 45 33 C0  e..A......e#.E3.
0000000140AA1190  83 65 33 00 83 65 43 00  0F B6 C0 48 6B C8 38 48  .e3..eC.....k..H
0000000140AA11A0  8D 45 F7 C7 45 0F 01 00  00 00 48 89 45 07 48 8D  .E........H.E.H.
0000000140AA11B0  45 F8 48 89 45 17 48 8D  42 20 48 03 C1 C7 45 1F  E.H.E.H.B H...E.
0000000140AA11C0  01 00 00 00 48 89 45 27  48 8D 42 30 48 03 C1 C7  ....H.E'H.B0H...
0000000140AA11D0  45 2F 10 00 00 00 48 8B  0D BB 60 46 00 48 8D 15  E/....H...`F.H..
0000000140AA11E0  64 D3 57 FF 48 89 45 37  48 8D 45 07 48 89 44 24  d...H.E7H.E.H.D$
0000000140AA11F0  20 C7 45 3F 10 00 00 00  E8 53 D7 96 FF 8A 45 F7   ..?..........E.
0000000140AA1200  48 8B 15 B9 CC 46 00 FE  C0 88 45 F7 3A 02 0F 82  H.........E.....
0000000140AA1210  6B FF FF FF 48 8B 4D 47  48 33 CC E8 E0 BB BF FF  k...H.MGH3......
0000000140AA1220  48 81 C4 90 00 00 00 5D  C3 CC CC CC CC CC CC CC  H.Đ ...]........
0000000140AA1230  48 89 5C 24 08 48 89 6C  24 10 48 89 74 24 20 57  H.\$.H.l$.H.t$ W
0000000140AA1240  41 56 41 57 48 83 EC 30  8B 1D 62 62 45 00 49 8B  AVAWH.....bbE.I.
0000000140AA1250  F0 8B 05 5D 62 45 00 8B  EA 40 B7 01 4D 85 C0 0F  ....bE......M...
0000000140AA1260  84 8B 00 00 00 4D 8D 78  64 41 8B 1F 8B D3 C1 EA  .....M.xdA......
0000000140AA1270  02 8A CB 40 22 D7 40 22  CF E8 06 20 C5 FF 44 8B  ....".."... ..D.
0000000140AA1280  F0 83 F8 02 72 19 F0 41  83 0F 02 F0 83 0D 1D 62  ....r..........b
0000000140AA1290  45 00 08 48 8D 0D 56 61  45 00 E8 51 12 90 FF 40  E..H..VaE......@
0000000140AA12A0  84 EF 0F 84 1B 01 00 00  45 85 F6 0F 84 12 01 00  ........E.......
0000000140AA12B0  00 C1 EB 02 BD FF FF FF  3F EB 1D 48 83 64 24 20  ........?....d$ 
0000000140AA12C0  00 4C 8D 44 24 60 41 B9  04 00 00 00 48 8D 4E 68  .L.D$`A.....H.Nh
0000000140AA12D0  49 8B D7 E8 48 6C 8F FF  8B 46 64 89 44 24 60 C1  I...Hl...Fd.D$`.
0000000140AA12E0  E8 02 2B C3 23 C5 41 3B  C6 72 D0 E9 D3 00 00 00  .......;........
0000000140AA12F0  8B D3 8A CB C1 EA 05 40  22 CF 40 22 D7 E8 82 1F  .ӊ .....".."....
0000000140AA1300  C5 FF 8B F0 83 F8 02 72  14 F0 83 0D 9F 61 45 00  .......r.....aE.
0000000140AA1310  10 48 8D 0D D8 60 45 00  E8 D3 11 90 FF 40 F6 C5  .H....E......@..
0000000140AA1320  02 74 54 80 3D AE 61 45  00 00 74 4B C1 EB 05 BF  .tT.=.aE..tK....
0000000140AA1330  FF FF FF 07 03 DE BE 00  00 00 04 23 DF EB 24 48  ...........#..$H
0000000140AA1340  83 64 24 20 00 4C 8D 44  24 60 41 B9 04 00 00 00  .d$ .L.D$`A.....
0000000140AA1350  48 8D 15 5D 61 45 00 48  8D 0D F2 5F 45 00 E8 BD  H..]aE.H........
0000000140AA1360  6B 8F FF 8B 05 4B 61 45  00 89 44 24 60 2B C3 23  k....KaE..D$`+..
0000000140AA1370  C7 3B C6 73 CA EB 4C 40  84 EF 74 47 85 F6 74 43  ......L@........
0000000140AA1380  C1 EB 05 BF FF FF FF 07  EB 24 48 83 64 24 20 00  ............d$ .
0000000140AA1390  4C 8D 44 24 60 41 B9 04  00 00 00 48 8D 15 0E 61  L.D$`A.....H...a
0000000140AA13A0  45 00 48 8D 0D 9F 5F 45  00 E8 72 6B 8F FF 8B 05  E.H..._E........
0000000140AA13B0  FC 60 45 00 89 44 24 60  C1 E8 05 2B C3 23 C7 3B  .`E..D$`...+....
0000000140AA13C0  C6 72 C7 48 8B 5C 24 50  48 8B 6C 24 58 48 8B 74  .....\$PH.l$XH.t
0000000140AA13D0  24 68 48 83 C4 30 41 5F  41 5E 5F C3 CC CC CC CC  $hH...A_A^_.....
0000000140AA13E0  CC CC CC CC 8B 44 24 28  4C 8B D1 32 C9 44 23 C0  .....D$(L.....#.
0000000140AA13F0  44 8B DA 45 84 C9 74 1F  45 85 C0 74 14 8B 15 A9  D.......E.......
0000000140AA1400  9B 46 00 85 D0 75 0A 0B  D0 B1 01 89 15 9B 9B 46  .F......б .....F
0000000140AA1410  00 84 C9 75 1B C3 CC 45  85 C0 75 17 8B 0D 8A 9B  .......E........
0000000140AA1420  46 00 85 C8 74 0D F7 D0  23 C8 89 0D 7C 9B 46 00  F...........|.F.
0000000140AA1430  45 08 1A C3 CC CC CC CC  CC CC CC CC 48 83 EC 28  E...............
0000000140AA1440  48 8D 15 B9 0D 04 00 B9  03 00 00 00 E8 93 07 98  H...............
0000000140AA1450  FF 48 8D 0D 10 D1 57 FF  E8 13 C4 9E FF 48 83 C4  .H...........H..
0000000140AA1460  28 C3 CC CC CC CC CC CC  CC CC CC CC 40 53 48 83  (............SH.
0000000140AA1470  EC 20 4C 8D 49 28 4C 8B  D2 49 8B 09 49 3B C9 74  ....I(L.....I;..
0000000140AA1480  35 48 8D 59 D8 4C 8B 43  38 4D 85 C0 74 16 49 8B  5H.Y...C8M....I.
0000000140AA1490  12 49 2B 50 48 75 08 49  8B 52 08 49 2B 50 50 48  .I+PHu.I.R.I+PPH
0000000140AA14A0  85 D2 74 05 48 8B 09 EB  D3 48 8B CB E8 D7 15 F3  ....H...........
0000000140AA14B0  FF 48 8B C3 EB 02 33 C0  48 83 C4 20 5B C3 CC CC  .H....3.....[...
0000000140AA14C0  CC CC CC CC CC CC CC CC  4C 8B DC 49 89 5B 08 57  ........L....[.W
0000000140AA14D0  48 83 EC 30 49 83 63 F0  00 4D 8D 4B 20 83 64 24  H.....c....K .d$
0000000140AA14E0  58 00 48 8B C2 49 8B F8  48 8D 15 81 33 04 00 41  X.H.....H...3..A
0000000140AA14F0  B8 04 00 00 00 48 8B D9  48 8B C8 45 89 43 E8 E8  .....H.......C..
0000000140AA1500  1C 4C F1 FF 85 C0 78 58  8B 44 24 58 0F B6 C8 84  .L....xX.D$X..Ȅ 
0000000140AA1510  C0 74 3E 83 F9 01 75 48  0F B7 0D E1 2A 52 00 8B  ..>...uH........
0000000140AA1520  D0 C1 EA 08 3B D1 73 38  48 83 3F 00 75 32 8B C8  .......8H.?.u2..
0000000140AA1530  48 8D 1D 89 D1 52 00 48  C1 E9 08 48 8B 1C CB 48  H......H...H....
0000000140AA1540  8D 4B 10 E8 C8 D9 87 FF  85 C0 75 14 48 89 1F EB  .K..........H...
0000000140AA1550  0F A9 00 FF FF FF 74 08  0F BA AB F0 01 00 00 14  ......t.........
0000000140AA1560  48 8B 5C 24 40 48 83 C4  30 5F C3 CC CC CC CC CC  H.\$@H..._......
0000000140AA1570  CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC  ................
0000000140AA1580  48 83 EC 28 33 D2 E8 0D  00 00 00 48 83 C4 28 C3  H..........H....
0000000140AA1590  CC CC CC CC CC CC CC CC  4C 8B DC 49 89 5B 08 49  ........L....[.I
0000000140AA15A0  89 73 10 57 41 54 41 55  41 56 41 57 48 81 EC E0  .s.WATAUAVAWH...
0000000140AA15B0  00 00 00 44 8A FA 48 8B  F1 0F 57 C0 0F 11 44 24  ...D..H.......D$
0000000140AA15C0  60 45 33 ED 4C 89 6C 24  70 45 89 6B 8C 45 89 6B  `E3...l$pE.k.E.k
0000000140AA15D0  A4 4C 89 6C 24 50 44 89  6C 24 44 4C 89 6C 24 58  .L.l$PD.l$DL.l$X
0000000140AA15E0  45 88 6B 18 45 8B F5 48  C7 44 24 78 00 00 02 00  E.k.E.....$x....
0000000140AA15F0  48 8D 05 79 B7 03 00 49  89 83 78 FF FF FF 45 8A  H..y...I..x...E.
0000000140AA1600  E5 65 48 8B 04 25 88 01  00 00 8A 90 32 02 00 00  .....%......2...
0000000140AA1610  84 D2 0F 84 D1 00 00 00  45 84 FF 0F 85 C8 00 00  ........E.......
0000000140AA1620  00 48 8B 0D E0 74 53 00  E8 13 89 DA FF 84 C0 75  .H..............
0000000140AA1630  0A B8 61 00 00 C0 E9 FB  03 00 00 49 B8 00 00 FF  ..a........I....
0000000140AA1640  FF FF 7F 00 00 49 8B C0  49 3B F0 48 0F 42 C6 90  .....I...;....Ɛ 
0000000140AA1650  8B 10 89 54 24 60 48 8B  48 08 48 89 4C 24 68 66  ...T$`H.H.H.L$hf
0000000140AA1660  85 D2 75 0A B8 0D 00 00  C0 E9 C8 03 00 00 F6 C1  ................
0000000140AA1670  01 0F 85 DD 03 00 00 0F  B7 D2 48 8D 04 0A 49 3B  ..............I;
0000000140AA1680  C0 77 05 48 3B C1 73 03  41 8A 00 B9 21 01 00 00  ...H;...A...!...
0000000140AA1690  41 B8 49 6F 4E 32 E8 55  6A 0C 00 48 8B F8 48 89  A.IoN2.....H..H.
0000000140AA16A0  44 24 70 44 0F B7 44 24  60 48 8B 54 24 68 48 8B  D$pD..D$`H.T$hH.
0000000140AA16B0  C8 E8 8A 59 C1 FF 48 89  7C 24 68 48 8D 4C 24 60  ...Y..H.|$hH.L$`
0000000140AA16C0  E8 4B FD BF FF 8B D8 48  8B CF E9 5E 03 00 00 8B  ...........^....
0000000140AA16D0  D8 48 8B 4C 24 70 48 85  C9 74 07 33 D2 E8 EE 75  ...L$pH....3....
0000000140AA16E0  0C 00 8B C3 E9 4D 03 00  00 48 8B D6 48 8D 0D 1D  .....M...H......
0000000140AA16F0  59 58 FF E8 7C FD 92 FF  4C 89 6C 24 48 44 89 6C  YX......L.l$HD.l
0000000140AA1700  24 40 E8 C9 BF 98 FF 84  C0 74 14 48 8B D6 48 8D  $@.........H....
0000000140AA1710  0D 2B BD 03 00 E8 B6 05  98 FF E9 12 FF FF FF 44  .+.............D
0000000140AA1720  88 6C 24 20 41 B9 19 00  02 00 4C 8B C6 33 D2 48  .l$ A.....L.....
0000000140AA1730  8D 4C 24 50 E8 A7 D8 FC  FF 8B D8 85 C0 0F 88 9D  .L$P......؅ ....
0000000140AA1740  02 00 00 48 8D 54 24 40  48 8B 4C 24 50 E8 E2 C5  ...H.T$@H.L$P...
0000000140AA1750  F2 FF 8B D8 33 D2 48 8B  4C 24 50 E8 00 7D DF FF  ....3...L$P.....
0000000140AA1760  85 DB 0F 88 78 02 00 00  C7 84 24 90 00 00 00 30  ....x...Ǆ $....0
0000000140AA1770  00 00 00 4C 89 AC 24 98  00 00 00 C7 84 24 A8 00  ...L..$....Ǆ $..
0000000140AA1780  00 00 40 02 00 00 48 8D  44 24 40 48 89 84 24 A0  ..@...H.D$@H..$.
0000000140AA1790  00 00 00 0F 57 C0 F3 0F  7F 84 24 B0 00 00 00 48  ....W.....$....H
0000000140AA17A0  8D 44 24 58 48 89 44 24  30 4C 89 6C 24 28 C7 44  .D$XH.D$0L.l$(..
0000000140AA17B0  24 20 01 00 00 00 45 33  C9 45 33 C0 48 8B 15 B5  $ ....E3..3.....
0000000140AA17C0  44 52 00 48 8D 8C 24 90  00 00 00 E8 90 03 DF FF  DR.H..$.........
0000000140AA17D0  8B D8 85 C0 0F 88 06 02  00 00 4C 8B 05 97 44 52  .؅ .......L...DR
0000000140AA17E0  00 4C 89 AC 24 28 01 00  00 4C 89 6C 24 28 48 8D  .L..$(...L.l$(H.
0000000140AA17F0  84 24 28 01 00 00 48 89  44 24 20 45 33 C9 33 D2  .$(...H.D$ E3...
0000000140AA1800  48 8B 4C 24 58 E8 E6 F7  D9 FF 8B D8 33 D2 48 8B  H.L$X...........
0000000140AA1810  4C 24 58 E8 48 7C DF FF  85 DB 0F 88 C0 01 00 00  L$X.............
0000000140AA1820  48 8B BC 24 28 01 00 00  48 8B 4F 18 E8 EF C7 99  H..$(...H.O.....
0000000140AA1830  FF 44 0F B7 70 44 41 C1  E6 10 0F B7 40 46 44 0B  .D..pDA.....@FD.
0000000140AA1840  F0 4C 39 6F 68 0F 84 85  01 00 00 4C 39 6F 28 0F  ....h......L9o(.
0000000140AA1850  84 7B 01 00 00 45 84 FF  75 16 48 8B CF E8 96 83  .{...E..u.H.....
0000000140AA1860  F2 FF 85 C0 75 0A E8 F5  E3 86 FF E9 6B 01 00 00  ....u...........
0000000140AA1870  48 8D 94 24 20 01 00 00  48 8B CF E8 5C 35 A3 FF  H..$ ...H...\5..
0000000140AA1880  8B D8 B9 00 00 00 80 03  C1 85 C1 0F 85 4F 01 00  .ع ..........O..
0000000140AA1890  00 81 FB 10 00 00 C0 0F  84 43 01 00 00 44 38 AC  .........C...D8.
0000000140AA18A0  24 20 01 00 00 0F 84 18  01 00 00 65 48 8B 0C 25  $ .........eH..%
0000000140AA18B0  88 01 00 00 48 8B 05 F5  41 52 00 48 39 81 B8 00  ....H......H9...
0000000140AA18C0  00 00 75 53 E8 EB 38 AF  FF 85 C0 74 31 E8 5E 79  ..uS........1...
0000000140AA18D0  9E FF 48 8B C8 E8 B6 AF  99 FF 48 8B D8 48 8B 47  ..H.......H....G
0000000140AA18E0  68 48 8B BC 24 28 01 00  00 48 8B CF E8 DF 99 C0  hH..$(...H...ߙ .
0000000140AA18F0  FF 48 8B CB E8 97 32 9A  FF E9 A1 00 00 00 48 8B  .H....2.......H.
0000000140AA1900  47 68 48 8B BC 24 28 01  00 00 48 8B CF E8 BE 99  GhH..$(...H.....
0000000140AA1910  C0 FF E9 88 00 00 00 33  D2 44 8D 42 50 48 8D 8C  .......3...BPH..
0000000140AA1920  24 90 00 00 00 E8 16 5B  C1 FF 45 33 C0 33 D2 48  $.........E3....
0000000140AA1930  8D 8C 24 B0 00 00 00 E8  A4 01 96 FF 48 8B BC 24  ..$.........H..$
0000000140AA1940  28 01 00 00 48 89 BC 24  C8 00 00 00 48 8D 05 7D  (...H..$....H..}
0000000140AA1950  AA 01 00 48 89 84 24 A0  00 00 00 48 8D 84 24 90  ...H..$....H..$.
0000000140AA1960  00 00 00 48 89 84 24 A8  00 00 00 4C 89 AC 24 90  ...H..$....L..$.
0000000140AA1970  00 00 00 BA 01 00 00 00  48 8D 8C 24 90 00 00 00  ........H..$....
0000000140AA1980  E8 AB E4 86 FF 4C 89 6C  24 20 45 33 C9 45 33 C0  .....L.l$ E3..3.
0000000140AA1990  33 D2 48 8D 8C 24 B0 00  00 00 E8 E1 BE 84 FF 48  3....$.........H
0000000140AA19A0  8D 4F 38 E8 4C 6F FE FF  48 8B D7 48 8B CF E8 55  .O8.....H......U
0000000140AA19B0  87 A0 FF 48 8B CF E8 A5  96 F2 FF 48 8B CF E8 9D  ...H............
0000000140AA19C0  E2 86 FF 48 8B CF E8 95  E2 86 FF 41 8B DD EB 10  ...H.......A....
0000000140AA19D0  48 8B CF E8 88 E2 86 FF  41 B4 01 BB 10 00 00 C0  H.......A.......
0000000140AA19E0  44 89 74 24 20 4C 8D 4C  24 40 44 8B C3 48 8B D6  D.t$ L.L$@D.....
0000000140AA19F0  48 8D 0D D9 50 58 FF E8  50 FF 92 FF 85 DB 79 23  H....X.........#
0000000140AA1A00  45 84 E4 75 1E 44 89 74  24 20 4C 8D 4C 24 40 44  E....D.t$ L.L$@D
0000000140AA1A10  8B C3 48 8D 54 24 78 48  8D 0D 42 53 58 FF E8 45  ....T$xH..BSX...
0000000140AA1A20  FE 92 FF 48 8B 4C 24 48  48 85 C9 74 07 33 D2 E8  ...H.L$HH....3..
0000000140AA1A30  9C 72 0C 00 8B C3 4C 8D  9C 24 E0 00 00 00 49 8B  .r.......$....I.
0000000140AA1A40  5B 30 49 8B 73 38 49 8B  E3 41 5F 41 5E 41 5D 41  [0I.s8I....A^A]A
0000000140AA1A50  5C 5F C3 CC E8 E7 00 DF  FF 90 CC CC CC CC CC CC  \_..............
0000000140AA1A60  CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC  ................
0000000140AA1A70  83 FA 02 0F 85 99 00 00  00 53 48 83 EC 20 49 83  .........SH.....
0000000140AA1A80  F9 20 0F 85 85 00 00 00  33 D2 45 8D 41 E1 48 8D  . ......3...A...
0000000140AA1A90  0D 4B E0 44 00 E8 C6 D6  84 FF F0 48 0F BA 2D 3C  .K............-<
0000000140AA1AA0  E0 44 00 00 72 53 48 85  C0 74 04 C6 40 0A 01 48  ....rSH........H
0000000140AA1AB0  8B 1D 32 E0 44 00 EB 0F  48 8B CB E8 6C 93 FA FF  ..2.........l...
0000000140AA1AC0  48 8B 9B 60 01 00 00 48  85 DB 75 EC 48 83 C8 FF  H..`...H........
0000000140AA1AD0  F0 48 0F C1 05 07 E0 44  00 24 06 3C 02 75 0C 48  .........$.<.u.H
0000000140AA1AE0  8D 0D FA DF 44 00 E8 45  13 77 FF 48 8D 0D EE DF  .........w.H....
0000000140AA1AF0  44 00 E8 99 98 7C FF EB  14 48 85 C0 74 0F 48 8B  D.虘  |........H.
0000000140AA1B00  D0 48 8D 0D D8 DF 44 00  E8 63 E6 76 FF 48 83 C4  ......D....v.H..
0000000140AA1B10  20 5B C3 CC CC CC CC CC  CC CC CC CC 48 83 EC 28   [..........H...
0000000140AA1B20  83 F9 16 73 40 8B C1 83  E8 07 74 1E 83 E8 01 74  ...s@...........
0000000140AA1B30  19 83 E8 01 74 14 83 E8  01 74 0F 83 E8 01 74 0A  ................
0000000140AA1B40  83 E8 01 74 05 83 F8 08  75 1B 0F AE E8 8B D1 48  ........u......H
0000000140AA1B50  8D 05 F2 79 36 00 48 C1  E2 05 48 8B 14 02 8B 12  ......H...H.....
0000000140AA1B60  E8 5B C2 A9 FF 48 83 C4  28 C3 CC CC CC CC CC CC  .....H..........
0000000140AA1B70  CC CC CC CC 48 83 EC 28  BA 20 00 00 00 E8 D2 40  ....H.... ......
0000000140AA1B80  A5 FF 48 83 C4 28 C3 CC  CC CC CC CC CC CC CC CC  ..H.............
0000000140AA1B90  40 53 48 83 EC 40 80 79  48 00 48 8B D9 74 47 0F  @SH....yH.H...G.
0000000140AA1BA0  57 C0 48 8D 54 24 20 0F  11 44 24 20 0F 11 44 24  W...T$ ..D$ ..D$
0000000140AA1BB0  30 E8 8A 27 F4 FF 8B 5B  18 48 8D 0D 20 80 46 00  0........H.. .F.
0000000140AA1BC0  E8 C3 97 91 FF 8B CB E8  AC 32 A1 FF 25 FF FF FF  .........2..%...
0000000140AA1BD0  00 33 C9 8B D0 E8 86 33  00 00 48 8D 0D FF 7F 46  .3ɋ ...3..H....F
0000000140AA1BE0  00 E8 3E 24 98 FF 33 C0  48 83 C4 40 5B C3 CC CC  ......3.....[...
0000000140AA1BF0  CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC  ................
0000000140AA1C00  48 8B C4 48 89 58 20 44  88 40 18 48 89 48 08 56  H....X D.@.H.H.V
0000000140AA1C10  57 41 54 41 56 41 57 48  83 EC 40 45 8A F0 48 8B  WATAVAWH........
0000000140AA1C20  DA 48 8B F1 45 33 E4 44  89 60 10 44 0F B7 02 48  .......D.`.D...H
0000000140AA1C30  8B 52 08 48 8D 48 10 E8  C4 3B E0 FF 8B 54 24 78  .R.H.H.......T$x
0000000140AA1C40  FF C2 89 54 24 78 81 FA  FF FF 00 00 76 1B B8 F0  ...T$x......v...
0000000140AA1C50  00 00 C0 48 8B 9C 24 88  00 00 00 48 83 C4 40 41  ......$....H...A
0000000140AA1C60  5F 41 5E 41 5C 5F 5E C3  CC 4C 8D 7E 02 48 8D 7E  _A^A\_^..L.~.H.~
0000000140AA1C70  08 4D 8B CF 4C 8B C7 41  8A CE E8 71 F2 99 FF 89  .M.........q....
0000000140AA1C80  44 24 30 85 C0 78 CC 0F  B7 03 41 0F B7 17 89 44  D$0.......A....D
0000000140AA1C90  24 20 4C 8B 4B 08 4C 8D  44 24 78 48 8B 0F E8 FD  $ L.K.L.D$xH....
0000000140AA1CA0  5C E0 FF 8B D8 89 44 24  30 85 C0 78 15 8B 54 24  \...؉ D$0.....T$
0000000140AA1CB0  78 48 8B 07 44 88 24 02  66 89 16 41 8B DC 89 5C  xH..D.$.f..A.܉ \
0000000140AA1CC0  24 30 85 DB 79 14 45 84  F6 74 0F 48 8B 0F E8 DD  $0....E.........
0000000140AA1CD0  6F 0C 00 4C 89 27 66 45  89 27 8B C3 E9 72 FF FF  o..L.'fE.'...r..
0000000140AA1CE0  FF CC CC CC CC CC CC CC  40 55 48 8D 6C 24 F0 48  .........UH.l$..
0000000140AA1CF0  81 EC 10 01 00 00 48 8B  05 03 8A 36 00 48 33 C4  ......H....6.H3.
0000000140AA1D00  48 89 45 00 83 3D 75 59  36 00 05 44 8A D2 0F 86  H.E..=uY6..D....
0000000140AA1D10  2D 01 00 00 48 BA 00 00  00 00 00 40 00 00 48 8D  -...H......@..H.
0000000140AA1D20  0D 5B 59 36 00 E8 16 0A  98 FF 84 C0 0F 84 0F 01  .[Y6............
0000000140AA1D30  00 00 8A 05 65 57 3C 00  48 8D 15 62 6D 5A FF 88  ....eW<.H..bmZ..
0000000140AA1D40  44 24 30 48 8D 0D 36 59  36 00 48 8D 44 24 30 44  D$0H..6Y6.H.D$0D
0000000140AA1D50  88 44 24 32 48 89 44 24  70 45 84 C9 48 8D 44 24  .D$2H.D$pE....D$
0000000140AA1D60  31 48 C7 44 24 78 01 00  00 00 48 89 45 80 0F 94  1H..$x....H.E...
0000000140AA1D70  44 24 34 48 8D 44 24 32  44 88 54 24 31 48 89 45  D$4H.D$2D.T$1H.E
0000000140AA1D80  90 45 33 C9 8A 45 40 45  33 C0 88 44 24 33 48 8D  .E3Ɋ E@E3..D$3H.
0000000140AA1D90  44 24 33 48 89 45 A0 48  8D 44 24 34 48 89 45 B0  D$3H.E.H.D$4H.E.
0000000140AA1DA0  8A 05 F6 56 3C 00 88 44  24 35 48 8D 44 24 35 48  .......D$5H.D$5H
0000000140AA1DB0  89 45 C0 8B 45 50 89 44  24 38 48 8D 44 24 38 48  .E..EP.D$8H.D$8H
0000000140AA1DC0  89 45 D0 48 8B 05 26 85  46 00 48 89 44 24 40 48  .E....&.F.H.D$@H
0000000140AA1DD0  8D 44 24 40 48 89 45 E0  48 8D 44 24 48 48 89 45  .D$@H.E...D$HH.E
0000000140AA1DE0  F0 48 8D 44 24 50 48 89  44 24 28 C7 44 24 20 0B  ....$PH.D$(..$ .
0000000140AA1DF0  00 00 00 48 C7 45 88 01  00 00 00 48 C7 45 98 01  ...H.......H....
0000000140AA1E00  00 00 00 48 C7 45 A8 01  00 00 00 48 C7 45 B8 01  ...H.......H....
0000000140AA1E10  00 00 00 48 C7 45 C8 01  00 00 00 48 C7 45 D8 04  ...H.......H....
0000000140AA1E20  00 00 00 48 C7 45 E8 08  00 00 00 48 C7 44 24 48  ...H.......H..$H
0000000140AA1E30  00 00 00 01 48 C7 45 F8  08 00 00 00 E8 7F 4E 97  ....H...........
0000000140AA1E40  FF 48 8B 4D 00 48 33 CC  E8 B3 AF BF FF 48 81 C4  .H.M.H3......H..
0000000140AA1E50  10 01 00 00 5D C3 CC CC  CC CC CC CC CC CC CC CC  ....]...........
0000000140AA1E60  40 55 48 8D 6C 24 A9 48  81 EC A0 00 00 00 48 8B  @UH.l$.H......H.
0000000140AA1E70  05 8B 88 36 00 48 33 C4  48 89 45 47 83 3D FD 57  ...6.H3...EG.=.W
0000000140AA1E80  36 00 05 8A 05 D7 57 3C  00 8A 0D 95 96 36 00 76  6......<.....6.v
0000000140AA1E90  64 88 45 E8 48 8D 15 A7  73 5A FF 88 4D E7 48 8D  d.E.....sZ..M...
0000000140AA1EA0  45 E8 48 89 45 27 48 8D  4D E7 48 8D 45 E9 48 89  E...E'H.M...E...
0000000140AA1EB0  4D 17 48 89 45 37 48 8D  0D C3 57 36 00 48 8D 45  M.H.E7H....6.H.E
0000000140AA1EC0  F7 44 88 45 E9 48 89 44  24 28 45 33 C9 45 33 C0  .......D$(E3..3.
0000000140AA1ED0  C7 44 24 20 05 00 00 00  48 C7 45 1F 01 00 00 00  ..$ ....H.......
0000000140AA1EE0  48 C7 45 2F 01 00 00 00  48 C7 45 3F 01 00 00 00  H../....H..?....
0000000140AA1EF0  E8 CB 4D 97 FF 48 8B 4D  47 48 33 CC E8 FF AE BF  .....H.MGH3.....
0000000140AA1F00  FF 48 81 C4 A0 00 00 00  5D C3 CC CC CC CC CC CC  .H.Ġ ...].......
0000000140AA1F10  CC CC CC CC 48 83 EC 58  48 8B 05 E1 87 36 00 48  ....H..........H
0000000140AA1F20  33 C4 48 89 44 24 40 0F  57 C0 BA 1C 00 00 00 0F  3...D$@.W.......
0000000140AA1F30  11 44 24 30 0F 11 44 24  20 65 48 8B 04 25 88 01  .D$0..D$ eH..%..
0000000140AA1F40  00 00 0F 10 80 08 05 00  00 8B 81 08 01 00 00 48  ...............H
0000000140AA1F50  8D 4C 24 20 C7 44 24 30  01 00 00 00 F3 0F 7F 44  .L$ ..$0........
0000000140AA1F60  24 20 89 44 24 38 E8 19  00 00 00 48 8B 4C 24 40  $ .D$8.....H.L$@
0000000140AA1F70  48 33 CC E8 88 AE BF FF  48 83 C4 58 C3 CC CC CC  H3......H.......
0000000140AA1F80  CC CC CC CC 48 89 5C 24  08 48 89 6C 24 10 56 57  ....H.\$.H.l$.VW
0000000140AA1F90  41 54 41 56 41 57 48 83  EC 20 8B FA 48 8D 2D AD  ATAVAWH.....H.-.
0000000140AA1FA0  CF 46 00 48 8B F1 45 33  C0 48 8B CD 33 D2 E8 AD  ...H.....H......
0000000140AA1FB0  D1 84 FF 48 8B D8 33 C0  44 8D 60 11 F0 4C 0F B1  ф .H......`.....
0000000140AA1FC0  25 8B CF 46 00 74 10 4C  8B CD 4C 8B C3 33 D2 48  %....t.L........
0000000140AA1FD0  8B CD E8 45 D4 84 FF 45  33 F6 48 85 DB 74 04 C6  ...EԄ .E3....t..
0000000140AA1FE0  43 0A 01 48 8B 1D 86 54  36 00 4C 8D 3D 7F 54 36  C..H...T6.L.=.T6
0000000140AA1FF0  00 EB 11 48 8B 43 10 8B  D7 48 8B CE E8 CF 92 C0  .....C.......ϒ .
0000000140AA2000  FF 48 8B 1B 49 3B DF 75  EA 49 8B C4 F0 4C 0F B1  .H..I;.......L..









Function: 1404f5c54
Prototype: __int64 __fastcall(__int64, int)

--- Decompiled C/C++ ---
__int64 __fastcall MmVerifyCallbackFunctionCheckFlags(__int64 a1, int a2)
{
  unsigned int v3; // ebx
  __int64 v4; // rax

  v3 = 0;
  v4 = MiLockLoadedDataTableEntry(a1, 1);
  if ( v4 )
  {
    if ( !a2 || (a2 & *(_DWORD *)(v4 + 104)) != 0 )
      v3 = 1;
    MiUnlockLoadedDataTableEntry(v4, 1);
  }
  return v3;
}


--- Local Variables ---
// int a2; // location: dx, size: 4
// __int64 a1; // location: cx, size: 8
// int ; // location: di, size: 4
// unsigned int v3; // location: bx, size: 4
// __int64 v4; // location: ax, size: 8
// __int64 ; // location: ax, size: 8


--- String Literals Referenced ---
// No string literals referenced.


--- Callers (Functions that call this one) ---
// --- Called by: MmVerifyCallbackFunctionCheckFlags at 0x1404f5c54 (Depth: 0) ---
// Language: C/C++
```cpp
__int64 __fastcall MmVerifyCallbackFunctionCheckFlags(__int64 a1, int a2)
{
  unsigned int v3; // ebx
  __int64 v4; // rax

  v3 = 0;
  v4 = MiLockLoadedDataTableEntry(a1, 1);
  if ( v4 )
  {
    if ( !a2 || (a2 & *(_DWORD *)(v4 + 104)) != 0 )
      v3 = 1;
    MiUnlockLoadedDataTableEntry(v4, 1);
  }
  return v3;
}

```

// --- Called by: PsSetCreateThreadNotifyRoutineEx at 0x1407701c0 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall PsSetCreateThreadNotifyRoutineEx(int a1, __int64 a2)
{
  unsigned int v4; // ebx

  if ( a1 )
  {
    if ( a1 != 1 )
      return 3221225485LL;
    v4 = 2;
  }
  else
  {
    v4 = 1;
  }
  if ( (unsigned int)MmVerifyCallbackFunctionCheckFlags(a2, 32) )
    return PspSetCreateThreadNotifyRoutine(a2, v4);
  else
    return 3221225506LL;
}

```

// --- Called by: ObRegisterCallbacks at 0x1409d8900 (Depth: 1) ---
// Language: C/C++
```cpp
NTSTATUS __stdcall ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration, PVOID *RegistrationHandle)
{
  unsigned int v2; // ebx
  NTSTATUS inserted; // esi
  int OperationRegistrationCount; // eax
  int v7; // ebp
  __int64 Pool2; // rax
  _WORD *v9; // rdi
  unsigned int Length; // edx
  void *v12; // rcx
  unsigned int i; // ebp
  OB_OPERATION_REGISTRATION *v14; // rsi
  __int64 PreOperation; // rcx
  __int16 v16; // ax
  __int64 v17; // rax
  __int64 PostOperation; // rcx
  _WORD *v19; // rdx
  _QWORD *v20; // r14
  __int64 v21; // rcx
  _QWORD *v22; // rax

  v2 = 0;
  inserted = 0;
  if ( (CallbackRegistration->Version & 0xFF00) != 0x100 )
    return -1073741811;
  OperationRegistrationCount = CallbackRegistration->OperationRegistrationCount;
  if ( !(_WORD)OperationRegistrationCount )
    return -1073741811;
  v7 = (OperationRegistrationCount << 6) + CallbackRegistration->Altitude.Length + 32;
  Pool2 = ExAllocatePool2(0x100u);
  v9 = (_WORD *)Pool2;
  if ( !Pool2 )
    return -1073741670;
  *(_WORD *)Pool2 = 256;
  *(_QWORD *)(Pool2 + 8) = CallbackRegistration->RegistrationContext;
  Length = CallbackRegistration->Altitude.Length;
  *(_WORD *)(Pool2 + 18) = Length;
  *(_WORD *)(Pool2 + 16) = Length;
  v12 = (void *)(Pool2 + v7 - Length);
  *(_QWORD *)(Pool2 + 24) = v12;
  memmove(v12, CallbackRegistration->Altitude.Buffer, Length);
  for ( i = 0; i < CallbackRegistration->OperationRegistrationCount; ++i )
  {
    v14 = &CallbackRegistration->OperationRegistration[i];
    if ( !v14->Operations || ((*v14->ObjectType)->TypeInfo.ObjectTypeFlags & 0x40) == 0 )
    {
LABEL_11:
      inserted = -1073741811;
      break;
    }
    PreOperation = (__int64)v14->PreOperation;
    if ( PreOperation )
    {
      if ( !(unsigned int)MmVerifyCallbackFunctionCheckFlags(PreOperation, 32) )
        goto LABEL_21;
    }
    else if ( !v14->PostOperation )
    {
      goto LABEL_11;
    }
    PostOperation = (__int64)v14->PostOperation;
    if ( PostOperation && !(unsigned int)MmVerifyCallbackFunctionCheckFlags(PostOperation, 32) )
    {
LABEL_21:
      inserted = -1073741790;
      break;
    }
    v19 = &v9[32 * (unsigned __int64)i + 16];
    *((_QWORD *)v19 + 1) = v19;
    *(_QWORD *)v19 = v19;
    *((_QWORD *)v19 + 7) = 0;
    *((_DWORD *)v19 + 4) = v14->Operations;
    *((_QWORD *)v19 + 3) = v9;
    *((_QWORD *)v19 + 4) = *v14->ObjectType;
    *((_QWORD *)v19 + 5) = v14->PreOperation;
    *((_QWORD *)v19 + 6) = v14->PostOperation;
    inserted = ObpInsertCallbackByAltitude();
    if ( inserted < 0 )
      break;
    ++v9[1];
  }
  v16 = v9[1];
  if ( inserted < 0 )
  {
    if ( v16 )
    {
      do
      {
        v20 = &v9[32 * (unsigned __int64)v2 + 16];
        ObpLockObjectTypeExclusive(v20[4]);
        v21 = *v20;
        if ( *(_QWORD **)(*v20 + 8LL) != v20 || (v22 = (_QWORD *)v20[1], (_QWORD *)*v22 != v20) )
          __fastfail(3u);
        *v22 = v21;
        *(_QWORD *)(v21 + 8) = v22;
        ObpUnlockObjectType(v20[4]);
        ++v2;
      }
      while ( v2 < (unsigned __int16)v9[1] );
    }
    ExFreePoolWithTag(v9, 0x6C46624Fu);
  }
  else
  {
    if ( v16 )
    {
      do
      {
        v17 = v2++;
        *(_DWORD *)&v9[32 * v17 + 26] |= 1u;
      }
      while ( v2 < (unsigned __int16)v9[1] );
    }
    *RegistrationHandle = v9;
  }
  return inserted;
}

```

// --- Called by: PspSetCreateProcessNotifyRoutine at 0x140a883c0 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall PspSetCreateProcessNotifyRoutine(__int64 a1, unsigned int a2)
{
  __int64 v2; // rbx
  int v3; // esi
  struct _KTHREAD *CurrentThread; // rbp
  __int64 i; // r14
  __int64 v7; // rax
  struct _EX_RUNDOWN_REF *v8; // rdi
  int v10; // edx
  void *v11; // rdi
  volatile signed __int32 *v12; // rax
  __int64 j; // rbx

  v2 = a2;
  v3 = a2 & 2;
  if ( (a2 & 1) != 0 )
  {
    CurrentThread = KeGetCurrentThread();
    --CurrentThread->KernelApcDisable;
    for ( i = 0; ; i = (unsigned int)(i + 1) )
    {
      if ( (unsigned int)i >= 0x40 )
      {
        KiLeaveCriticalRegionUnsafe(CurrentThread);
        return 3221225594LL;
      }
      v7 = ExReferenceCallBackBlock(&PspCreateProcessNotifyRoutine + i);
      v8 = (struct _EX_RUNDOWN_REF *)v7;
      if ( v7 )
      {
        LODWORD(v2) = v2 & 0xFFFFFFFE;
        if ( *(_QWORD *)(v7 + 8) == a1
          && *(_DWORD *)(v7 + 16) == (_DWORD)v2
          && (unsigned __int8)ExCompareExchangeCallBack(&PspCreateProcessNotifyRoutine + i, 0, v7) )
        {
          v12 = &PspCreateProcessNotifyRoutineCount;
          if ( v3 )
            v12 = &PspCreateProcessNotifyRoutineExCount;
          _InterlockedDecrement(v12);
          ExDereferenceCallBackBlock(&PspCreateProcessNotifyRoutine + i, v8);
          KiLeaveCriticalRegionUnsafe(CurrentThread);
          ExWaitForRundownProtectionRelease(v8);
          ExFreePoolWithTag(v8, 0);
          return 0;
        }
        ExDereferenceCallBackBlock(&PspCreateProcessNotifyRoutine + i, v8);
      }
    }
  }
  if ( (a2 & 2) != 0 )
    v10 = 32;
  else
    v10 = 0;
  if ( !(unsigned int)MmVerifyCallbackFunctionCheckFlags(a1, v10) )
    return 3221225506LL;
  v11 = (void *)ExAllocateCallBack(a1, v2);
  if ( !v11 )
    return 3221225626LL;
  for ( j = 0; ; j = (unsigned int)(j + 1) )
  {
    if ( (unsigned int)j >= 0x40 )
    {
      ExFreePoolWithTag(v11, 0);
      return 3221225485LL;
    }
    if ( (unsigned __int8)ExCompareExchangeCallBack(&PspCreateProcessNotifyRoutine + j, v11, 0) )
      break;
  }
  if ( v3 )
  {
    _InterlockedIncrement(&PspCreateProcessNotifyRoutineExCount);
    if ( (PspNotifyEnableMask & 4) == 0 )
      _interlockedbittestandset(&PspNotifyEnableMask, 2u);
  }
  else
  {
    _InterlockedIncrement(&PspCreateProcessNotifyRoutineCount);
    if ( (PspNotifyEnableMask & 2) == 0 )
      _interlockedbittestandset(&PspNotifyEnableMask, 1u);
  }
  return 0;
}

```

// --- Called by: PsSetCreateProcessNotifyRoutine at 0x140770130 (Depth: 2) ---
// Language: C/C++
```cpp
NTSTATUS __stdcall PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine, BOOLEAN Remove)
{
  return PspSetCreateProcessNotifyRoutine((__int64)NotifyRoutine, Remove != 0);
}

```

// --- Called by: PsSetCreateProcessNotifyRoutineEx at 0x140770150 (Depth: 2) ---
// Language: C/C++
```cpp
NTSTATUS __stdcall PsSetCreateProcessNotifyRoutineEx(PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove)
{
  return PspSetCreateProcessNotifyRoutine((__int64)NotifyRoutine, (unsigned int)(Remove != 0) + 2);
}

```

// --- Called by: PsSetCreateProcessNotifyRoutineEx2 at 0x140770170 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall PsSetCreateProcessNotifyRoutineEx2(int a1, __int64 a2, char a3)
{
  if ( a1 )
    return 3221225485LL;
  else
    return PspSetCreateProcessNotifyRoutine(a2, (unsigned int)(a3 != 0) + 6);
}

```

// --- Called by: MmVerifyCallbackFunction at 0x140aa1b74 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall MmVerifyCallbackFunction(__int64 a1)
{
  return MmVerifyCallbackFunctionCheckFlags(a1, 32);
}

```

// --- Called by: KeRegisterBoundCallback at 0x1405afd70 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall KeRegisterBoundCallback(__int64 a1)
{
  __int64 v2; // rbx
  __int64 v3; // rax
  __int64 v4; // rsi

  v2 = 0;
  if ( (unsigned int)MmVerifyCallbackFunction(a1) )
  {
    v3 = ExAllocateCallBack(a1, 0);
    v4 = v3;
    if ( v3 )
    {
      if ( (unsigned __int8)ExCompareExchangeCallBack(&KiBoundsCallback, v3, 0) )
        return a1;
      else
        PspUserApcKernelRoutine(v4);
    }
  }
  return v2;
}

```



--- Callees (Functions this one calls) ---
// --- Calls: MmVerifyCallbackFunctionCheckFlags at 0x1404f5c54 (Depth: 0) ---
// Language: C/C++
```cpp
__int64 __fastcall MmVerifyCallbackFunctionCheckFlags(__int64 a1, int a2)
{
  unsigned int v3; // ebx
  __int64 v4; // rax

  v3 = 0;
  v4 = MiLockLoadedDataTableEntry(a1, 1);
  if ( v4 )
  {
    if ( !a2 || (a2 & *(_DWORD *)(v4 + 104)) != 0 )
      v3 = 1;
    MiUnlockLoadedDataTableEntry(v4, 1);
  }
  return v3;
}

```

// --- Calls: MiLockLoadedDataTableEntry at 0x14039845c (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall MiLockLoadedDataTableEntry(__int64 a1, int a2)
{
  __int64 DataTableEntryByAddress; // rax
  __int64 v5; // r11
  __int64 v6; // rbx

  MiAcquireLoadLock(0);
  DataTableEntryByAddress = MmFindDataTableEntryByAddress(a1);
  v6 = DataTableEntryByAddress;
  if ( DataTableEntryByAddress )
  {
    MiLockLoaderEntry(DataTableEntryByAddress, a2 == 0 ? 2 : 0);
    return v6;
  }
  else
  {
    MmReleaseLoadLockShared(v5);
    return 0;
  }
}

```

// --- Calls: MiAcquireLoadLock at 0x1403984b8 (Depth: 2) ---
// Language: C/C++
```cpp
struct _KTHREAD *__fastcall MiAcquireLoadLock(int a1)
{
  struct _KTHREAD *CurrentThread; // rbx
  bool v2; // zf

  CurrentThread = KeGetCurrentThread();
  --CurrentThread->SpecialApcDisable;
  --CurrentThread->KernelApcDisable;
  if ( a1 )
  {
    ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, 1u);
    if ( !dword_140E2D718 )
      qword_140E2D710 = (__int64)CurrentThread;
    ++dword_140E2D718;
  }
  else
  {
    ExAcquireResourceSharedLite(&PsLoadedModuleResource, 1u);
    ++LODWORD(CurrentThread[1].Teb);
  }
  v2 = CurrentThread->SpecialApcDisable++ == -1;
  if ( v2 && ($727077A9B6E167EAE1398C74674DC5A5 *)CurrentThread->ApcState.ApcListHead[0].Flink != &CurrentThread->___u25 )
    KiCheckForKernelApcDelivery();
  return CurrentThread;
}

```

// --- Calls: MmFindDataTableEntryByAddress at 0x14039876c (Depth: 2) ---
// Language: C/C++
```cpp
__int64 *__fastcall MmFindDataTableEntryByAddress(unsigned __int64 a1)
{
  unsigned __int64 v1; // r9
  _QWORD *v2; // rdx
  unsigned __int64 v3; // r8
  __int64 v5; // r10
  __int64 i; // r8
  __int64 *v7; // r8

  v1 = a1;
  if ( !PsLoadedModuleList )
  {
    v5 = KeLoaderBlock_0 + 16;
    for ( i = *(_QWORD *)(KeLoaderBlock_0 + 16); i != v5; i = *v7 )
    {
      if ( (unsigned int)MiImageContainsVa(i, v1) )
        return v7;
    }
    return 0;
  }
  v2 = (_QWORD *)qword_140E2D780;
  while ( v2 )
  {
    v3 = *(v2 - 20);
    if ( a1 > v3 + (unsigned int)(*((_DWORD *)v2 - 36) - 1) )
    {
      v2 = (_QWORD *)v2[1];
    }
    else
    {
      if ( a1 >= v3 )
        break;
      v2 = (_QWORD *)*v2;
    }
  }
  if ( !v2 )
    return 0;
  return v2 - 26;
}

```

// --- Calls: MiLockLoaderEntry at 0x140398a40 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall MiLockLoaderEntry(__int64 a1, int a2)
{
  struct _KTHREAD *CurrentThread; // rsi
  volatile signed __int32 *v3; // rbx
  ULONG_PTR v6; // rcx
  __int64 v7; // rdi
  __int64 result; // rax
  __int64 v9; // rdi

  CurrentThread = KeGetCurrentThread();
  v3 = (volatile signed __int32 *)(a1 + 232);
  v6 = a1 + 232;
  --CurrentThread->SpecialApcDisable;
  if ( !a2 )
  {
    result = KeAbPreAcquire(v6, 0, 0);
    v9 = result;
    if ( _interlockedbittestandset64(v3, 0) )
      result = ExfAcquirePushLockExclusiveEx(v3, result, v3);
    if ( v9 )
      *(_BYTE *)(v9 + 10) = 1;
LABEL_8:
    *(_QWORD *)(a1 + 240) = CurrentThread;
    return result;
  }
  if ( a2 != 2 )
  {
    result = ExAcquireAutoExpandPushLockExclusive(v6, 0);
    if ( a2 > 1 )
      return result;
    goto LABEL_8;
  }
  v7 = KeAbPreAcquire(v6, 0, 0);
  result = _InterlockedCompareExchange64((volatile signed __int64 *)v3, 17, 0);
  if ( result )
    result = ExfAcquirePushLockSharedEx(v3, 0, v7, v3);
  if ( v7 )
    *(_BYTE *)(v7 + 10) = 1;
  return result;
}

```

// --- Calls: MmReleaseLoadLockShared at 0x140398b10 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall MmReleaseLoadLockShared(struct _KTHREAD *CurrentThread)
{
  if ( !CurrentThread )
    CurrentThread = KeGetCurrentThread();
  return MiReleaseLoadLock(CurrentThread, 0);
}

```

// --- Calls: MiUnlockLoadedDataTableEntry at 0x1403983c4 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall MiUnlockLoadedDataTableEntry(__int64 a1, int a2)
{
  struct _KTHREAD *CurrentThread; // rcx

  MiUnlockLoaderEntry(a1, a2 == 0 ? 2 : 0);
  CurrentThread = KeGetCurrentThread();
  if ( !CurrentThread )
    CurrentThread = KeGetCurrentThread();
  return MiReleaseLoadLock((__int64)CurrentThread, 0);
}

```

// --- Calls: MiUnlockLoaderEntry at 0x140398988 (Depth: 2) ---
// Language: C/C++
```cpp
$727077A9B6E167EAE1398C74674DC5A5 *__fastcall MiUnlockLoaderEntry(__int64 a1, int a2)
{
  struct _KTHREAD *CurrentThread; // rdi
  volatile signed __int64 *v3; // rbx
  $727077A9B6E167EAE1398C74674DC5A5 *result; // rax
  __int64 v5; // rdx
  __int64 v6; // rcx
  ULONG_PTR v8; // rcx

  CurrentThread = KeGetCurrentThread();
  if ( a2 <= 1 )
    *(_QWORD *)(a1 + 240) = 0;
  v3 = (volatile signed __int64 *)(a1 + 232);
  if ( !a2 )
  {
    if ( (_InterlockedExchangeAdd64(v3, 0xFFFFFFFFFFFFFFFFuLL) & 6) == 2 )
      ExfTryToWakePushLock(a1 + 232);
    goto LABEL_9;
  }
  if ( a2 == 2 )
  {
    if ( _InterlockedCompareExchange64(v3, 0, 17) != 17 )
      ExfReleasePushLockShared(a1 + 232);
LABEL_9:
    result = ($727077A9B6E167EAE1398C74674DC5A5 *)KeAbPostRelease((ULONG_PTR)v3);
    goto LABEL_10;
  }
  v8 = a1 + 232;
  if ( a2 == 3 )
    result = ($727077A9B6E167EAE1398C74674DC5A5 *)ExReleaseAutoExpandPushLockShared(v8, 0);
  else
    result = ($727077A9B6E167EAE1398C74674DC5A5 *)ExReleaseAutoExpandPushLockExclusive(v8, 0);
LABEL_10:
  if ( CurrentThread->SpecialApcDisable++ == -1 )
  {
    result = &CurrentThread->___u25;
    if ( ($727077A9B6E167EAE1398C74674DC5A5 *)result->ApcState.ApcListHead[0].Flink != result )
      return ($727077A9B6E167EAE1398C74674DC5A5 *)KiCheckForKernelApcDelivery(v6, v5);
  }
  return result;
}

```

// --- Calls: MiReleaseLoadLock at 0x140398830 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall MiReleaseLoadLock(__int64 a1, int a2)
{
  __int64 v3; // rdx
  __int64 v4; // rcx
  bool v5; // zf

  --*(_WORD *)(a1 + 486);
  if ( a2 )
  {
    if ( !--dword_140E2D718 )
      qword_140E2D710 = 0;
  }
  else
  {
    --*(_DWORD *)(a1 + 1456);
  }
  ExReleaseResourceLite(&PsLoadedModuleResource);
  v5 = (*(_WORD *)(a1 + 486))++ == 0xFFFF;
  if ( v5 && *(_QWORD *)(a1 + 152) != a1 + 152 )
    KiCheckForKernelApcDelivery(v4, v3);
  return KeLeaveCriticalRegionThread(a1);
}

```



--- Struct Member Usage & Data Cross-References ---
// No struct context could be determined for this function.

--- Decompiler Warnings ---
using guessed type __int64 __fastcall MiUnlockLoadedDataTableEntry(_QWORD, _QWORD);
using guessed type __int64 __fastcall MiLockLoadedDataTableEntry(_QWORD, _QWORD);

00000001404F5A90  E8 8B CD D4 FF 8B 7B 28  40 8A E8 85 FF 75 08 48  ......{(@....u.H
00000001404F5AA0  8B CB E8 C9 C8 D4 FF 8B  CF 23 CE 3B CE 75 04 33  ...............3
00000001404F5AB0  FF EB 0A 0B FE 89 7B 28  BF 01 00 00 00 40 8A D5  ......{(.....@..
00000001404F5AC0  48 8D 0D F9 17 94 00 E8  14 C8 D4 FF 85 FF 74 0E  H.............t.
00000001404F5AD0  48 8D 4B 60 45 33 C0 33  D2 E8 72 FF D2 FF 48 83  H.K`E3....r...H.
00000001404F5AE0  64 24 20 00 45 33 C9 45  33 C0 48 8B CB 41 8D 51  d$ .E3..3......Q
00000001404F5AF0  12 E8 8A 7D DF FF B8 01  00 00 00 EB 02 33 C0 48  ................
00000001404F5B00  8B 5C 24 40 48 8B 6C 24  48 48 8B 74 24 50 48 83  .\$@H.l$HH.t$PH.
00000001404F5B10  C4 30 5F C3 CC CC CC CC  CC CC CC CC 48 83 EC 28  .._.............
00000001404F5B20  48 83 64 24 30 00 8B 0D  1C DC AC 00 89 4C 24 30  H.d$0....ܬ ..L$0
00000001404F5B30  F6 C1 10 75 42 48 8B 44  24 30 41 B9 01 00 00 00  ....BH.D$0A.....
00000001404F5B40  41 0B C9 48 89 44 24 30  89 4C 24 30 48 8D 0D 55  A....D$0.L$0H..U
00000001404F5B50  66 BE FF 48 8B 54 24 30  45 8D 41 02 E8 13 68 04  f..H.T$0E.A.....
00000001404F5B60  00 48 8B 4C 24 30 4C 8D  05 3B 66 BE FF BA 03 00  .H.L$0L..;f.....
00000001404F5B70  00 00 E8 8D 68 04 00 48  83 C4 28 C3 CC CC CC CC  .......H........
00000001404F5B80  CC CC CC CC 48 83 EC 28  48 83 64 24 30 00 8B 0D  ....H.....d$0...
00000001404F5B90  A4 DB AC 00 89 4C 24 30  F6 C1 10 75 42 48 8B 44  .....L$0....BH.D
00000001404F5BA0  24 30 41 B9 01 00 00 00  41 0B C9 48 89 44 24 30  $0A.....A....D$0
00000001404F5BB0  89 4C 24 30 48 8D 0D 25  66 BE FF 48 8B 54 24 30  .L$0H..%f..H.T$0
00000001404F5BC0  45 8D 41 02 E8 AB 67 04  00 48 8B 4C 24 30 4C 8D  E.A......H.L$0L.
00000001404F5BD0  05 0B 66 BE FF BA 03 00  00 00 E8 25 68 04 00 48  ..f............H
00000001404F5BE0  83 C4 28 C3 CC CC CC CC  CC CC CC CC 48 83 EC 28  ................
00000001404F5BF0  48 83 64 24 30 00 8B 0D  34 DB AC 00 89 4C 24 30  H.d$0...4....L$0
00000001404F5C00  F6 C1 10 75 42 48 8B 44  24 30 41 B9 01 00 00 00  ....BH.D$0A.....
00000001404F5C10  41 0B C9 48 89 44 24 30  89 4C 24 30 48 8D 0D 4D  A....D$0.L$0H..M
00000001404F5C20  65 BE FF 48 8B 54 24 30  45 8D 41 02 E8 43 67 04  e..H.T$0E.A.....
00000001404F5C30  00 48 8B 4C 24 30 4C 8D  05 33 65 BE FF BA 03 00  .H.L$0L..3e.....
00000001404F5C40  00 00 E8 BD 67 04 00 48  83 C4 28 C3 CC CC CC CC  .......H........
00000001404F5C50  CC CC CC CC 48 89 5C 24  08 57 48 83 EC 20 8B FA  ....H.\$.WH.....
00000001404F5C60  33 DB 8D 53 01 E8 F2 27  EA FF 48 8B C8 48 85 C0  3ۍ S............
00000001404F5C70  74 18 85 FF 74 05 85 78  68 74 05 BB 01 00 00 00  t...t..xht......
00000001404F5C80  BA 01 00 00 00 E8 3A 27  EA FF 8B C3 48 8B 5C 24  ..............\$
00000001404F5C90  30 48 83 C4 20 5F C3 CC  CC CC CC CC CC CC CC CC  0H..._..........
00000001404F5CA0  48 8B C4 48 89 58 08 48  89 68 10 48 89 70 18 48  H....X.H.h.H.p.H
00000001404F5CB0  89 78 20 41 56 48 83 EC  30 65 48 8B 2C 25 88 01  .x AVH....H.,%..
00000001404F5CC0  00 00 48 8B FA 48 8B D9  66 FF 8D E4 01 00 00 90  ..H..H..........
00000001404F5CD0  8B 42 0C 8B 35 23 E5 AC  00 B8 00 40 00 00 44 8B  .B..5#.....@..D.
00000001404F5CE0  42 04 3B F0 44 8B 32 0F  42 F0 41 8B C0 41 2B C6  B.;.....B....A+.
00000001404F5CF0  3B C6 0F 83 8F 00 00 00  48 8B 81 C8 41 00 00 8B  ;.......H.......
00000001404F5D00  91 BC 04 00 00 48 05 FF  FF 03 00 48 25 00 00 FC  .....H.....H%...
00000001404F5D10  FF 48 3B C2 0F 46 D0 41  3B D0 76 6B 83 B9 D0 04  .H;..F..;..k....
00000001404F5D20  00 00 00 75 62 41 8D 80  00 00 04 00 48 8B CF 3B  ...ubA......H...
00000001404F5D30  C2 0F 46 D0 E8 6B B3 17  00 85 C0 79 46 48 83 64  ..F..k......FH.d
00000001404F5D40  24 20 00 48 8D 8B D8 04  00 00 C7 83 D0 04 00 00  $ .H......ǃ ....
00000001404F5D50  01 00 00 00 45 33 C9 48  8B 15 42 AE B1 FF 45 33  ....E3....B...E3
00000001404F5D60  C0 E8 4A DA DE FF 48 8B  CB E8 5A 13 FB FF 85 C0  ..J...H...Z.....
00000001404F5D70  74 11 48 8D 8B A0 03 00  00 45 33 C0 33 D2 E8 CD  t.H......E3.....
00000001404F5D80  FC D2 FF 44 8B 47 04 45  2B C6 74 12 41 3B F0 48  ...D.G.E+...A;..
00000001404F5D90  8B D7 48 8B CB 44 0F 46  C6 E8 4A 78 FD FF 48 8B  .......F..Jx..H.
00000001404F5DA0  CD E8 8A 6C D1 FF 48 8B  5C 24 40 48 8B 6C 24 48  ...l..H.\$@H.l$H
00000001404F5DB0  48 8B 74 24 50 48 8B 7C  24 58 48 83 C4 30 41 5E  H.t$PH.|$XH...A^
00000001404F5DC0  C3 CC CC CC CC CC CC CC  48 83 EC 28 4C 8D 05 ED  ........H.......
00000001404F5DD0  6B BE FF E8 28 DB FD FF  48 83 C4 28 C3 CC CC CC  k.......H.......
00000001404F5DE0  CC CC CC CC 48 83 EC 28  48 83 64 24 30 00 8B 05  ....H.....d$0...
00000001404F5DF0  04 D7 AC 00 89 44 24 30  A8 10 74 05 83 E0 01 EB  .....D$0..t.....
00000001404F5E00  0F 48 8B 4C 24 30 BA 03  00 00 00 E8 0C 00 00 00  .H.L$0..........
00000001404F5E10  48 83 C4 28 C3 CC CC CC  CC CC CC CC 48 83 EC 28  H...........H...
00000001404F5E20  4C 8D 05 89 53 BE FF E8  D4 DA FD FF 48 83 C4 28  L...S.......H...
00000001404F5E30  C3 CC CC CC CC CC CC CC  4C 89 4C 24 20 55 48 8D  ........L.L$ UH.
00000001404F5E40  AC 24 70 FF FF FF 48 81  EC 90 01 00 00 48 8B 05  .$p...H......H..
00000001404F5E50  AC 48 91 00 48 33 C4 48  89 85 80 00 00 00 8B 05  .H..H3..........
00000001404F5E60  C8 49 91 00 48 8D 15 A5  8B B2 FF 89 44 24 30 48  ....H.......D$0H
00000001404F5E70  8D 0D 3A 0D 91 00 48 8D  85 B8 00 00 00 48 C7 44  ..:...H......H..
00000001404F5E80  24 58 08 00 00 00 48 89  44 24 50 41 B9 14 00 00  $X....H.D$PA....
00000001404F5E90  00 48 8D 85 C0 00 00 00  48 C7 44 24 68 08 00 00  .H......H..$h...
00000001404F5EA0  00 48 89 44 24 60 45 33  C0 48 8D 85 C8 00 00 00  .H.D$`E3........
00000001404F5EB0  48 C7 44 24 78 08 00 00  00 48 89 44 24 70 48 8D  H..$x....H.D$pH.
00000001404F5EC0  85 D0 00 00 00 48 89 45  80 48 8D 85 D8 00 00 00  .....H.E.H......
00000001404F5ED0  48 89 45 90 48 8D 85 E0  00 00 00 48 89 45 A0 48  H.E.H......H.E.H
00000001404F5EE0  8D 85 E8 00 00 00 48 89  45 B0 48 8D 85 F0 00 00  ......H.E.H.....
00000001404F5EF0  00 48 89 45 C0 48 8D 85  F8 00 00 00 48 89 45 D0  .H.E........H.E.
00000001404F5F00  48 8D 85 00 01 00 00 48  89 45 E0 48 8D 85 08 01  H......H.E......
00000001404F5F10  00 00 48 89 45 F0 48 8D  85 10 01 00 00 48 89 45  ..H.E........H.E
00000001404F5F20  00 48 8D 85 18 01 00 00  48 89 45 10 48 8D 85 20  .H......H.E.H.. 
00000001404F5F30  01 00 00 48 89 45 20 48  8D 85 28 01 00 00 48 89  ...H.E H..(...H.
00000001404F5F40  45 30 48 8D 85 30 01 00  00 48 89 45 40 48 8D 85  E0H..0...H.E@H..
00000001404F5F50  38 01 00 00 48 89 45 50  48 8D 85 40 01 00 00 48  8...H.EPH..@...H
00000001404F5F60  89 45 60 48 8D 44 24 30  48 89 45 70 48 8D 44 24  .E`H.D$0H.EpH.D$
00000001404F5F70  40 48 89 44 24 20 48 C7  45 88 08 00 00 00 48 C7  @H.D$ H.......H.
00000001404F5F80  45 98 08 00 00 00 48 C7  45 A8 08 00 00 00 48 C7  E.....H.......H.
00000001404F5F90  45 B8 08 00 00 00 48 C7  45 C8 08 00 00 00 48 C7  E.....H.......H.
00000001404F5FA0  45 D8 08 00 00 00 48 C7  45 E8 08 00 00 00 48 C7  E.....H.......H.
00000001404F5FB0  45 F8 08 00 00 00 48 C7  45 08 08 00 00 00 48 C7  E.....H.......H.
00000001404F5FC0  45 18 08 00 00 00 48 C7  45 28 08 00 00 00 48 C7  E.....H..(....H.
00000001404F5FD0  45 38 08 00 00 00 48 C7  45 48 08 00 00 00 48 C7  E8....H..H....H.
00000001404F5FE0  45 58 08 00 00 00 48 C7  45 68 08 00 00 00 48 C7  EX....H..h....H.
00000001404F5FF0  45 78 04 00 00 00 E8 01  F6 F1 FF 48 8B 8D 80 00  Ex..............
00000001404F6000  00 00 48 33 CC E8 F6 6D  1A 00 48 81 C4 90 01 00  ..H3......H.Đ ..
00000001404F6010  00 5D C3 CC CC CC CC CC  CC CC CC CC 48 89 5C 24  .]..........H.\$
00000001404F6020  08 48 89 7C 24 10 80 79  03 0B 4C 8B DA 75 69 41  .H.|$..y..L...iA
00000001404F6030  83 F8 07 72 63 0F B7 0A  41 BA 03 00 00 00 41 3B  ...rc...A.....A;
00000001404F6040  CA 72 55 41 8D 40 FC 3B  C8 77 4D 48 8D 3C 0A 0F  ..UA.@.;..MH.<..
00000001404F6050  B7 1F 83 FB 04 72 41 41  8B D0 2B D1 3B DA 77 38  .....rAA.......8
00000001404F6060  41 83 61 0C 00 48 8D 04  1F 4D 89 19 2B D3 41 89  A.a..H...M..+...
00000001404F6070  49 08 41 C6 41 0C 02 41  83 61 1C 00 49 89 79 10  I.A....A.a..I.y.
00000001404F6080  41 89 59 18 41 C6 41 1C  01 41 83 61 2C 00 49 89  A.Y.A....A.a,.I.
00000001404F6090  41 20 41 89 51 28 EB 12  41 83 61 0C 00 41 BA 01  A A.Q(....a..A..
00000001404F60A0  00 00 00 4D 89 19 45 89  41 08 48 8B 44 24 28 44  ...M..E.A.H.D$(D
00000001404F60B0  89 10 48 8B 5C 24 08 48  8B 7C 24 10 C3 CC CC CC  ..H.\$.H.|$.....
00000001404F60C0  CC CC CC CC 48 83 EC 28  45 33 D2 4C 8B C9 0F BD  ....H....3......
00000001404F60D0  CA 45 8D 42 01 41 D3 E0  44 33 C2 8D 51 FE 49 8B  ...B.A..D3..Q.I.
00000001404F60E0  0C D1 4E 89 54 C1 08 48  83 29 01 75 0B 4D 89 14  ....T..H.).u.M..
00000001404F60F0  D1 33 D2 E8 D8 2B 67 00  48 83 C4 28 C3 CC CC CC  ......g.H.......
00000001404F6100  CC CC CC CC 48 83 EC 28  48 83 64 24 30 00 8B 05  ....H.....d$0...
00000001404F6110  6C D9 AC 00 89 44 24 30  A8 10 74 05 83 E0 01 EB  l٬ ..D$0..t.....
00000001404F6120  0F 48 8B 4C 24 30 BA 03  00 00 00 E8 0C 00 00 00  .H.L$0..........






Function: 14079de9c
Prototype: __int64 __fastcall(__int64, __int64)

--- Decompiled C/C++ ---
__int64 __fastcall EtwpInitializeSiloState(__int64 a1, __int64 a2)
{
  __int64 v4; // rdi
  unsigned int v5; // ebx
  char IsHostSilo; // si
  __int64 MaximumProcessorCount; // r14
  __int64 v8; // rax
  __int64 v9; // r9
  __int64 v10; // rcx
  __int64 v11; // r8
  __int64 v12; // rcx
  __int64 v13; // rdx
  _QWORD *Pool2; // rax
  __int64 v15; // rbp
  struct _KTHREAD *CurrentThread; // rax
  signed __int64 *v17; // rsi
  __int64 v18; // rax
  __int64 v19; // rbp
  _WORD *v20; // r9
  __int64 v21; // rdx
  __int64 v22; // r8
  signed __int64 v23; // rax
  signed __int64 v24; // rdx
  signed __int64 v25; // rtt

  v4 = *(_QWORD *)(PsGetServerSiloGlobals(a1) + 832);
  v5 = 0;
  IsHostSilo = PsIsHostSilo();
  if ( IsHostSilo )
  {
    Pool2 = (_QWORD *)ExAllocatePool2(0x100u);
    *(_QWORD *)(v4 + 4168) = Pool2;
    if ( !Pool2 )
      return (unsigned int)-1073741801;
    Pool2[3] = 0;
    Pool2[2] = EtwpUnsubscribeContainerStateWnf;
    *Pool2 = 0;
    *(_DWORD *)(v4 + 4160) = 0;
    ExSubscribeWnfStateChange(
      v4 + 4152,
      (unsigned int)&WNF_CONT_CONTAINER_STATE,
      1,
      0,
      (__int64)EtwpContainerStateWnfCallback,
      0);
  }
  else
  {
    MaximumProcessorCount = KeQueryMaximumProcessorCountEx(0xFFFFu);
    v8 = ExAllocatePool2(0x48u);
    *(_QWORD *)(v4 + 4144) = v8;
    if ( !v8 )
      return (unsigned int)-1073741801;
    v9 = MaximumProcessorCount;
    v10 = v8 + (MaximumProcessorCount << 6);
    if ( (_DWORD)MaximumProcessorCount )
    {
      v11 = 0;
      do
      {
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144)) = v10;
        v11 += 64;
        v12 = v10 + 8LL * *(unsigned int *)(v4 + 16);
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144) - 56) = v12;
        v13 = v12 + 8LL * *(unsigned int *)(v4 + 16);
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144) - 48) = v13;
        v10 = v13 + 8LL * *(unsigned int *)(v4 + 16);
        --v9;
      }
      while ( v9 );
    }
  }
  v15 = PsAttachSiloToCurrentThread(a1);
  EtwpQuerySiloRegistrySettings(v4);
  EtwpQueryPartitionRegistryInformation(v4 + 4176, v4 + 4216, v4 + 4224, v4 + 4228, v4 + 4208, v4 + 4192);
  if ( IsHostSilo )
    qword_1410077D8 = KeQueryPerformanceCounter(0).QuadPart;
  EtwpInitializeAutoLoggers(a2);
  if ( IsHostSilo )
    qword_1410077E0 = KeQueryPerformanceCounter(0).QuadPart;
  PsDetachSiloFromCurrentThread(v15);
  CurrentThread = KeGetCurrentThread();
  v17 = (signed __int64 *)(v4 + 432);
  --CurrentThread->KernelApcDisable;
  v18 = KeAbPreAcquire(v4 + 432, 0, 0);
  v19 = v18;
  if ( _interlockedbittestandset64((volatile signed __int32 *)(v4 + 432), 0) )
    ExfAcquirePushLockExclusiveEx(v4 + 432, v18, v4 + 432);
  if ( v19 )
    *(_BYTE *)(v19 + 10) = 1;
  v20 = (_WORD *)(v4 + 4048);
  *(_QWORD *)(v4 + 440) = KeGetCurrentThread();
  v21 = v4 + 156;
  LODWORD(v22) = 0;
  do
  {
    if ( *v20 )
    {
      *(_WORD *)(v21 + 2) = *v20;
      *(_DWORD *)(v21 - 4) = 1;
      *(_BYTE *)v21 = -1;
      *(_QWORD *)(v21 + 12) = -1;
      *(_QWORD *)(v21 + 20) = 0;
      *(_DWORD *)(v21 + 4) = 64;
      *(_BYTE *)(v4 + 4064) |= 1 << v22;
    }
    v22 = (unsigned int)(v22 + 1);
    ++v20;
    v21 += 32;
  }
  while ( (unsigned int)v22 < 8 );
  *(_QWORD *)(v4 + 440) = 0;
  _m_prefetchw(v17);
  v23 = *v17;
  v24 = *v17 - 16;
  if ( (*v17 & 0xFFFFFFFFFFFFFFF0uLL) <= 0x10 )
    v24 = 0;
  if ( (v23 & 2) != 0 || (v25 = *v17, v25 != _InterlockedCompareExchange64(v17, v24, v23)) )
    ExfReleasePushLock(v4 + 432, v24, v22, v20);
  KeAbPostRelease(v4 + 432);
  KeLeaveCriticalRegion();
  *(_QWORD *)(v4 + 4096) = 0;
  *(_QWORD *)(v4 + 4080) = 0;
  *(_QWORD *)(v4 + 4088) = 0;
  return v5;
}


--- Local Variables ---
// __int64 a2; // location: dx, size: 8
// __int64 a1; // location: cx, size: 8
// __int64 ; // location: r15, size: 8
// __int64 ; // location: bp, size: 8
// __int64 v4; // location: di, size: 8
// unsigned int v5; // location: bx, size: 4
// char IsHostSilo; // location: si, size: 1
// __int64 MaximumProcessorCount; // location: r14, size: 8
// __int64 v8; // location: ax, size: 8
// __int64 v9; // location: r9, size: 8
// __int64 v10; // location: cx, size: 8
// __int64 v11; // location: r8, size: 8
// __int64 v12; // location: cx, size: 8
// __int64 v13; // location: dx, size: 8
// _QWORD * Pool2; // location: ax, size: 8
// __int64 v15; // location: bp, size: 8
// struct _KTHREAD * CurrentThread; // location: ax, size: 8
// signed __int64 * v17; // location: si, size: 8
// __int64 v18; // location: ax, size: 8
// __int64 v19; // location: bp, size: 8
// _WORD * v20; // location: r9, size: 8
// __int64 v21; // location: dx, size: 8
// __int64 v22; // location: r8, size: 8
// signed __int64 v23; // location: ax, size: 8
// signed __int64 v24; // location: dx, size: 8
// signed __int64 v25; // location: tt, size: 8
// __int64 ; // location: ax, size: 8


--- String Literals Referenced ---
// No string literals referenced.


--- Callers (Functions that call this one) ---
// --- Called by: EtwpInitializeSiloState at 0x14079de9c (Depth: 0) ---
// Language: C/C++
```cpp
__int64 __fastcall EtwpInitializeSiloState(__int64 a1, __int64 a2)
{
  __int64 v4; // rdi
  unsigned int v5; // ebx
  char IsHostSilo; // si
  __int64 MaximumProcessorCount; // r14
  __int64 v8; // rax
  __int64 v9; // r9
  __int64 v10; // rcx
  __int64 v11; // r8
  __int64 v12; // rcx
  __int64 v13; // rdx
  _QWORD *Pool2; // rax
  __int64 v15; // rbp
  struct _KTHREAD *CurrentThread; // rax
  signed __int64 *v17; // rsi
  __int64 v18; // rax
  __int64 v19; // rbp
  _WORD *v20; // r9
  __int64 v21; // rdx
  __int64 v22; // r8
  signed __int64 v23; // rax
  signed __int64 v24; // rdx
  signed __int64 v25; // rtt

  v4 = *(_QWORD *)(PsGetServerSiloGlobals(a1) + 832);
  v5 = 0;
  IsHostSilo = PsIsHostSilo();
  if ( IsHostSilo )
  {
    Pool2 = (_QWORD *)ExAllocatePool2(0x100u);
    *(_QWORD *)(v4 + 4168) = Pool2;
    if ( !Pool2 )
      return (unsigned int)-1073741801;
    Pool2[3] = 0;
    Pool2[2] = EtwpUnsubscribeContainerStateWnf;
    *Pool2 = 0;
    *(_DWORD *)(v4 + 4160) = 0;
    ExSubscribeWnfStateChange(
      v4 + 4152,
      (unsigned int)&WNF_CONT_CONTAINER_STATE,
      1,
      0,
      (__int64)EtwpContainerStateWnfCallback,
      0);
  }
  else
  {
    MaximumProcessorCount = KeQueryMaximumProcessorCountEx(0xFFFFu);
    v8 = ExAllocatePool2(0x48u);
    *(_QWORD *)(v4 + 4144) = v8;
    if ( !v8 )
      return (unsigned int)-1073741801;
    v9 = MaximumProcessorCount;
    v10 = v8 + (MaximumProcessorCount << 6);
    if ( (_DWORD)MaximumProcessorCount )
    {
      v11 = 0;
      do
      {
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144)) = v10;
        v11 += 64;
        v12 = v10 + 8LL * *(unsigned int *)(v4 + 16);
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144) - 56) = v12;
        v13 = v12 + 8LL * *(unsigned int *)(v4 + 16);
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144) - 48) = v13;
        v10 = v13 + 8LL * *(unsigned int *)(v4 + 16);
        --v9;
      }
      while ( v9 );
    }
  }
  v15 = PsAttachSiloToCurrentThread(a1);
  EtwpQuerySiloRegistrySettings(v4);
  EtwpQueryPartitionRegistryInformation(v4 + 4176, v4 + 4216, v4 + 4224, v4 + 4228, v4 + 4208, v4 + 4192);
  if ( IsHostSilo )
    qword_1410077D8 = KeQueryPerformanceCounter(0).QuadPart;
  EtwpInitializeAutoLoggers(a2);
  if ( IsHostSilo )
    qword_1410077E0 = KeQueryPerformanceCounter(0).QuadPart;
  PsDetachSiloFromCurrentThread(v15);
  CurrentThread = KeGetCurrentThread();
  v17 = (signed __int64 *)(v4 + 432);
  --CurrentThread->KernelApcDisable;
  v18 = KeAbPreAcquire(v4 + 432, 0, 0);
  v19 = v18;
  if ( _interlockedbittestandset64((volatile signed __int32 *)(v4 + 432), 0) )
    ExfAcquirePushLockExclusiveEx(v4 + 432, v18, v4 + 432);
  if ( v19 )
    *(_BYTE *)(v19 + 10) = 1;
  v20 = (_WORD *)(v4 + 4048);
  *(_QWORD *)(v4 + 440) = KeGetCurrentThread();
  v21 = v4 + 156;
  LODWORD(v22) = 0;
  do
  {
    if ( *v20 )
    {
      *(_WORD *)(v21 + 2) = *v20;
      *(_DWORD *)(v21 - 4) = 1;
      *(_BYTE *)v21 = -1;
      *(_QWORD *)(v21 + 12) = -1;
      *(_QWORD *)(v21 + 20) = 0;
      *(_DWORD *)(v21 + 4) = 64;
      *(_BYTE *)(v4 + 4064) |= 1 << v22;
    }
    v22 = (unsigned int)(v22 + 1);
    ++v20;
    v21 += 32;
  }
  while ( (unsigned int)v22 < 8 );
  *(_QWORD *)(v4 + 440) = 0;
  _m_prefetchw(v17);
  v23 = *v17;
  v24 = *v17 - 16;
  if ( (*v17 & 0xFFFFFFFFFFFFFFF0uLL) <= 0x10 )
    v24 = 0;
  if ( (v23 & 2) != 0 || (v25 = *v17, v25 != _InterlockedCompareExchange64(v17, v24, v23)) )
    ExfReleasePushLock(v4 + 432, v24, v22, v20);
  KeAbPostRelease(v4 + 432);
  KeLeaveCriticalRegion();
  *(_QWORD *)(v4 + 4096) = 0;
  *(_QWORD *)(v4 + 4080) = 0;
  *(_QWORD *)(v4 + 4088) = 0;
  return v5;
}

```

// --- Called by: PspInitializeServerSiloDeferred at 0x140768ba0 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall PspInitializeServerSiloDeferred(_QWORD *Object)
{
  __int64 ServerSiloGlobals; // rbp
  int ApiSets; // edi
  __int64 v4; // r14
  __int64 v5; // rbx
  __int64 v6; // rcx
  __int64 v7; // r14
  __int64 v8; // rbx
  __int64 v9; // rbx
  __int64 v10; // rbx
  unsigned int CurrentSiloMaxLoggers; // eax
  __int64 v12; // rbx
  __int64 v13; // rax
  int v14; // eax
  int v15; // eax
  unsigned int v16; // ebx
  __int64 v18; // rax
  char v19; // [rsp+40h] [rbp+8h] BYREF
  char v20; // [rsp+48h] [rbp+10h] BYREF

  ServerSiloGlobals = PsGetServerSiloGlobals(Object);
  RtlNlsInitState(ServerSiloGlobals);
  ApiSets = sub_14064CCEC(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspSiloInitializeUserSharedData(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspSiloInitializeSystemRootSymlink(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspInitializeProtectedProcessParameters(ServerSiloGlobals);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspSiloLoadApiSets(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v4 = Object[188];
  v19 = 0;
  v5 = PsAttachSiloToCurrentThread(Object);
  ApiSets = ExIsMultiSessionSku(&v19);
  PsDetachSiloFromCurrentThread(v5);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v6 = *(_QWORD *)(v4 + 1288);
  v20 = 0;
  *(_BYTE *)(v6 + 28) = v19;
  v7 = Object[188];
  v8 = PsAttachSiloToCurrentThread(Object);
  ApiSets = ExIsStateSeparationEnabled(&v20);
  PsDetachSiloFromCurrentThread(v8);
  if ( ApiSets < 0 )
    goto LABEL_25;
  *(_BYTE *)(*(_QWORD *)(v7 + 1288) + 29LL) = v20;
  v9 = PsAttachSiloToCurrentThread(Object);
  ApiSets = RtlInitFunctionalityCache();
  PsDetachSiloFromCurrentThread(v9);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = ObInitServerSilo(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = ExpTimeZoneInitSiloState(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v10 = PsAttachSiloToCurrentThread(Object);
  ApiSets = ExInitializeNls();
  if ( ApiSets >= 0 )
    *(_QWORD *)(*(_QWORD *)(PsGetCurrentServerSiloGlobals() + 1024) + 8LL) = 1;
  PsDetachSiloFromCurrentThread(v10);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = SeInitServerSilo((__int64)Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = CmInitServerSiloState(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  CurrentSiloMaxLoggers = EtwpGetCurrentSiloMaxLoggers();
  ApiSets = EtwpPreInitializeSiloState(Object, CurrentSiloMaxLoggers);
  if ( ApiSets < 0 || (ApiSets = EtwpInitializeSiloState(Object, 0), ApiSets < 0) )
  {
    v18 = PsGetServerSiloGlobals(Object);
    EtwpCleanupSiloState(*(PVOID *)(v18 + 832));
LABEL_25:
    *(_DWORD *)(ServerSiloGlobals + 1272) = 4;
    PspDeleteExternalServerSiloState(Object);
    return (unsigned int)ApiSets;
  }
  v12 = PsAttachSiloToCurrentThread(Object);
  v13 = PsGetServerSiloGlobals(Object);
  *(_QWORD *)(v13 + 936) = 0;
  v14 = DbgkpInitializePhase1SiloState(v13 + 936);
  ApiSets = 0;
  if ( v14 < 0 )
    ApiSets = v14;
  PsDetachSiloFromCurrentThread(v12);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v15 = PspNotifyServerSiloCreation(Object);
  v16 = v15;
  if ( v15 >= 0 )
    return 0;
  PsTerminateServerSilo(Object, (unsigned int)v15);
  return v16;
}

```

// --- Called by: PspQueueDeferredWorkAndWait at 0x140768e08 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall PspQueueDeferredWorkAndWait(__int64 a1, _QWORD *a2)
{
  struct _WORK_QUEUE_ITEM WorkItem; // [rsp+30h] [rbp-50h] BYREF
  struct _KEVENT Event; // [rsp+50h] [rbp-30h] BYREF
  __int64 (__fastcall *v6)(_QWORD *); // [rsp+68h] [rbp-18h]
  _QWORD *v7; // [rsp+70h] [rbp-10h]
  unsigned int v8; // [rsp+78h] [rbp-8h]
  int v9; // [rsp+7Ch] [rbp-4h]

  WorkItem.List.Blink = 0;
  memset(&Event, 0, sizeof(Event));
  v9 = 0;
  if ( (KeGetCurrentThread()->ApcState.Process[3].ActiveGroupsMask.Masks[1] & 0x100000000000LL) != 0 )
    return PspInitializeServerSiloDeferred(a2);
  KeInitializeEvent(&Event, SynchronizationEvent, 0);
  v8 = 0;
  WorkItem.List.Flink = 0;
  v6 = PspInitializeServerSiloDeferred;
  v7 = a2;
  WorkItem.WorkerRoutine = (void (__fastcall *)(void *))PspDeferredWorkerRoutine;
  WorkItem.Parameter = &Event;
  ExQueueWorkItem(&WorkItem, DelayedWorkQueue);
  KeWaitForSingleObject(&Event, UserRequest, 0, 0, 0);
  return v8;
}

```

// --- Called by: EtwpInitialize at 0x140c32efc (Depth: 1) ---
// Language: C/C++
```cpp
void __fastcall EtwpInitialize(int a1, int a2, __int64 a3)
{
  char v5; // di
  __int64 v6; // rcx
  unsigned int CurrentSiloMaxLoggers; // eax
  _QWORD *v8; // rdi
  _QWORD *i; // rbx
  unsigned int v10; // ebp
  int v11; // eax
  __int64 v12; // rcx
  __int64 v13; // rdx
  unsigned int j; // edi
  __int64 Prcb; // rax
  __int64 v16; // rsi
  int v17; // eax
  int v18; // eax
  __int64 Pool2; // rax
  int v20; // [rsp+60h] [rbp+8h] BYREF

  if ( !a3 || (v5 = 1, *(_QWORD *)(a3 + 8) == a3 + 8) )
    v5 = 0;
  if ( !a1 )
  {
    KiInitializeMutant(&EtwpGroupMaskMutex, 0, 1u, 0);
    KiInitializeMutant(&EtwpCrimsonMaskMutex, 0, 1u, 0);
    EtwpSecurityLock = 0;
    EtwpInitializeStackLookasideList();
    dword_140FC64FC |= 0x880000u;
    LOBYTE(v6) = v5;
    EtwpBootDeferredGroupMask |= 0x10000u;
    EtwpInitializeBootTimeStamps(v6);
    if ( !a3 || (CurrentSiloMaxLoggers = *(_DWORD *)a3) == 0 )
    {
      if ( a2 )
        CurrentSiloMaxLoggers = EtwpGetCurrentSiloMaxLoggers();
      else
        CurrentSiloMaxLoggers = 80;
    }
    if ( (int)EtwpPreInitializeSiloState(0, CurrentSiloMaxLoggers) < 0 )
      KeBugCheck(0x11Du);
    EtwpHostSiloState = *(_QWORD *)(PsGetServerSiloGlobals(0) + 832);
    EtwInitializeProcessor(KeGetCurrentPrcb());
    qword_140E0EA68 = *(_QWORD *)(EtwpHostSiloState + 456);
    qword_140E0EA70 = EtwpHostSiloState;
    if ( a3 )
    {
      v8 = (_QWORD *)(a3 + 8);
      for ( i = *(_QWORD **)(a3 + 8); i != v8; i = (_QWORD *)*i )
        EtwpStartBootLogger(i);
    }
LABEL_42:
    ++EtwpBootPhase;
    return;
  }
  if ( a1 != 1 )
  {
    if ( a1 != 2 )
      return;
    EtwpUpdateFileInfoDriverState(
      (unsigned int)&PerfGlobalGroupMask,
      (unsigned int)&PerfGlobalGroupMask,
      1,
      EtwpHostSiloState,
      0);
    goto LABEL_42;
  }
  v10 = KeNumberProcessors_0;
  if ( v5 )
    EtwpFixBootSystemTime();
  v11 = EtwpInitializeSecurity();
  if ( v11 < 0 )
    KeBugCheckEx(0x11Du, 1u, v11, 0, 0);
  v12 = 896;
  v13 = 9;
  do
  {
    *(_WORD *)(v12 + MmWriteableSharedUserData) = 0;
    v12 += 2;
    --v13;
  }
  while ( v13 );
  for ( j = 0; j < v10; ++j )
  {
    Prcb = KeGetPrcb(j);
    v16 = Prcb;
    if ( !*(_QWORD *)(Prcb + 35752) )
    {
      v17 = EtwInitializeProcessor(Prcb);
      if ( v17 < 0 )
        KeBugCheckEx(0x11Du, 2u, v17, j, 0);
    }
    v18 = EtwInitializeProcessorActivityId(v16);
    if ( v18 < 0 )
      KeBugCheckEx(0x11Du, 2u, v18, j, 0);
  }
  EtwpReadConfigParameters(v12);
  EtwpInitializeRegistration();
  EtwpInitializePrivateSessionDemuxObject();
  EtwpInitializeRealTimeConnection();
  EtwCPUSpeedInMHz = *(_DWORD *)(KeGetPrcb(0) + 68);
  EtwpInitializeLastBranchTracing();
  EtwpInitializeProcessorTrace();
  dword_140EFEB10 = 0;
  EtwpAdjustBuffersWorkItem.WorkerRoutine = (void (__fastcall *)(void *))EtwpAdjustTraceBuffers;
  EtwpMdlTable = 0;
  qword_140EFEB08 = 0;
  EtwpAdjustBuffersWorkItem.Parameter = &EtwpBufferAdjustmentActive;
  dword_140EFEB04 = 12;
  EtwpBufferAdjustmentCount = 8;
  EtwpAdjustBuffersWorkItem.List.Flink = 0;
  word_140EFEF82 = 0;
  KiInitializeTimer2(&EtwpMemInfoTimer, EtwpLogMemInfoTimerCallback, 0, 8);
  EtwpInitializeProviderTraits();
  if ( !ExRegisterCallback((PCALLBACK_OBJECT)ExCbPowerState, EtwpPowerStateCallback, 0) )
    goto LABEL_39;
  EtwpInitializeKsrSupport();
  EtwpLoadMicroarchitecturalPmcs();
  EtwpSiloAllowedGroupMask |= 0x1600370Fu;
  dword_140FC5EFC |= 0x8206u;
  dword_140FC5F00 |= 0x10040u;
  dword_140FC5F10 |= 0x1FFFFFFFu;
  EtwpMapEnableFlags(&EtwpSiloAllowedGroupMask, 0);
  EtwpFixBootLoggers();
  if ( (int)EtwpInitializeSiloState(0, a3) < 0 )
LABEL_39:
    KeBugCheck(0x11Du);
  EtwpBugCheckCallback.State = 0;
  KeRegisterBugCheckReasonCallback(
    &EtwpBugCheckCallback,
    EtwpBugCheckMultiPartCallback,
    KbCallbackSecondaryMultiPartDumpData,
    (PUCHAR)&EtwpComponentName);
  EtwRegister(&EventTracingProvGuid, EtwpTracingProvEnableCallback, 0, &EtwpEventTracingProvRegHandle);
  WdipSemInitialize();
  PerfDiagInitialize();
  EtwpInitializeCoverage();
  EtwpInitializeCoverageSampler();
  Pool2 = ExAllocatePool2(0x40u);
  if ( !Pool2 )
    KeBugCheckEx(0x11Du, 3u, 0xFFFFFFFFC0000017uLL, 0, 0);
  dword_140EFEB90 = -849937013;
  EtwpTiQueryVadBloomFilter = 0x8000;
  qword_140EFEB88 = Pool2;
  EtwRegister(&KernelProvGuid, EtwpKernelProvEnableCallback, 0, &EtwKernelProvRegHandle);
  TlgRegisterAggregateProvider(&dword_140E09100);
  EtwRegister(&PsProvGuid, EtwpCrimsonProvEnableCallback, (PVOID)1, &EtwpPsProvRegHandle);
  TlgRegisterAggregateProviderEx(&dword_140E09138, EtwpTraceLoggingProvEnableCallback, PsProvTraceLoggingGuid);
  TraceLoggingRegisterEx_EtwRegister_EtwSetInformation(&dword_140E06EF0, 0, 0);
  EtwRegister(&NetProvGuid, EtwpCrimsonProvEnableCallback, (PVOID)0x10000, &EtwpNetProvRegHandle);
  EtwRegister(&DiskProvGuid, EtwpCrimsonProvEnableCallback, (PVOID)0x100, &EtwpDiskProvRegHandle);
  EtwRegister(&FileProvGuid, EtwpCrimsonProvEnableCallback, (PVOID)0x2000000, &EtwpFileProvRegHandle);
  EtwRegister(&RegistryProvGuid, EtwpRegTraceEnableCallback, 0, &EtwpRegTraceHandle);
  EtwRegister(&MemoryProvGuid, EtwpCrimsonProvEnableCallback, (PVOID)0x20000001, &EtwpMemoryProvRegHandle);
  EtwRegister(&MS_Windows_Kernel_AppCompat_Provider, 0, 0, &EtwAppCompatProvRegHandle);
  EtwRegister(&KernelAuditApiCallsGuid, 0, 0, &EtwApiCallsProvRegHandle);
  EtwRegister(&CVEAuditProviderGuid, 0, 0, &EtwCVEAuditProvRegHandle);
  EtwRegister(&ThreatIntProviderGuid, 0, 0, &EtwThreatIntProvRegHandle);
  EtwRegister(&MS_Windows_Security_LPAC_Provider, 0, 0, &EtwLpacProvRegHandle);
  EtwRegister(&SecurityMitigationsProviderGuid, 0, 0, &EtwSecurityMitigationsRegHandle);
  EtwRegister(&CpuStarvationProvGuid, EtwpCpuStarvationProvEnableCallback, 0, &EtwCpuStarvationProvRegHandle);
  EtwRegister(&CpuPartitionProvGuid, 0, 0, &EtwCpuPartitionProvRegHandle);
  ++EtwpBootPhase;
  ZwUpdateWnfStateData(&WNF_ETW_SUBSYSTEM_INITIALIZED, 0, 0, 0, 0, 0, 0);
  EtwpTraceSystemInitialization();
  v20 = 0;
  if ( (int)guard_dispatch_icall_no_overrides(45, 4, &EtwpMaxPmcCounter, &v20) < 0 )
    EtwpMaxPmcCounter = 8;
  EtwpMaxProfilingSources = EtwpMaxPmcCounter;
  UcInitialize(1);
}

```

// --- Called by: EtwInitialize at 0x14079c1a0 (Depth: 2) ---
// Language: C/C++
```cpp
void __fastcall EtwInitialize(unsigned int a1, __int64 a2)
{
  __int64 v3; // rdi
  __int64 v4; // rdi
  __int64 v5; // rax
  __int64 v6; // rdi
  __int64 v7; // rax
  __int64 v8; // rbx

  if ( a2 && (v3 = *(_QWORD *)(a2 + 240)) != 0 && *(_QWORD *)(v3 + 3680) && *(_QWORD *)(v3 + 3688) )
    v4 = v3 + 3672;
  else
    v4 = 0;
  if ( a1 )
  {
    if ( a1 < 3 )
    {
      while ( (unsigned __int8)EtwpBootPhase <= a1 )
        EtwpInitialize((unsigned __int8)EtwpBootPhase, a1, v4);
    }
    else if ( a1 == 3 )
    {
      v5 = EtwpHostSiloState;
      v6 = 0;
      ++EtwpBootPhase;
      if ( *(_DWORD *)(EtwpHostSiloState + 16) )
      {
        do
        {
          if ( ExAcquireRundownProtectionCacheAwareEx(
                 *(PEX_RUNDOWN_REF_CACHE_AWARE *)(*(_QWORD *)(v5 + 448) + 8 * v6),
                 1u) )
          {
            if ( (unsigned int)v6 < *(_DWORD *)(EtwpHostSiloState + 16) )
            {
              v7 = *(_QWORD *)(EtwpHostSiloState + 456);
              v8 = *(_QWORD *)(v7 + 8 * v6);
              if ( (v8 & 1) == 0
                && (*(_DWORD *)(v8 + 12) & 0x400) == 0
                && (unsigned __int8)EtwpBuffersFlushRequired(*(_QWORD *)(v7 + 8 * v6)) )
              {
                if ( (unsigned __int8)KeGetEffectiveIrql() > 2u )
                {
                  if ( !_interlockedbittestandset((volatile signed __int32 *)(v8 + 824), 8u) )
                    KeInsertQueueDpc((PRKDPC)(v8 + 568), 0, 0);
                }
                else
                {
                  KeSetEvent((PRKEVENT)(v8 + 480), 0, 0);
                }
              }
            }
            ExReleaseRundownProtectionCacheAwareEx(
              *(PEX_RUNDOWN_REF_CACHE_AWARE *)(*(_QWORD *)(EtwpHostSiloState + 448) + 8 * v6),
              1u);
          }
          v5 = EtwpHostSiloState;
          v6 = (unsigned int)(v6 + 1);
        }
        while ( (unsigned int)v6 < *(_DWORD *)(EtwpHostSiloState + 16) );
      }
    }
  }
  else if ( v4 )
  {
    if ( *(_QWORD *)(v4 + 8) != v4 + 8 )
      EtwpInitialize((unsigned __int8)EtwpBootPhase, 0, v4);
  }
}

```



--- Callees (Functions this one calls) ---
// --- Calls: EtwpInitializeSiloState at 0x14079de9c (Depth: 0) ---
// Language: C/C++
```cpp
__int64 __fastcall EtwpInitializeSiloState(__int64 a1, __int64 a2)
{
  __int64 v4; // rdi
  unsigned int v5; // ebx
  char IsHostSilo; // si
  __int64 MaximumProcessorCount; // r14
  __int64 v8; // rax
  __int64 v9; // r9
  __int64 v10; // rcx
  __int64 v11; // r8
  __int64 v12; // rcx
  __int64 v13; // rdx
  _QWORD *Pool2; // rax
  __int64 v15; // rbp
  struct _KTHREAD *CurrentThread; // rax
  signed __int64 *v17; // rsi
  __int64 v18; // rax
  __int64 v19; // rbp
  _WORD *v20; // r9
  __int64 v21; // rdx
  __int64 v22; // r8
  signed __int64 v23; // rax
  signed __int64 v24; // rdx
  signed __int64 v25; // rtt

  v4 = *(_QWORD *)(PsGetServerSiloGlobals(a1) + 832);
  v5 = 0;
  IsHostSilo = PsIsHostSilo();
  if ( IsHostSilo )
  {
    Pool2 = (_QWORD *)ExAllocatePool2(0x100u);
    *(_QWORD *)(v4 + 4168) = Pool2;
    if ( !Pool2 )
      return (unsigned int)-1073741801;
    Pool2[3] = 0;
    Pool2[2] = EtwpUnsubscribeContainerStateWnf;
    *Pool2 = 0;
    *(_DWORD *)(v4 + 4160) = 0;
    ExSubscribeWnfStateChange(
      v4 + 4152,
      (unsigned int)&WNF_CONT_CONTAINER_STATE,
      1,
      0,
      (__int64)EtwpContainerStateWnfCallback,
      0);
  }
  else
  {
    MaximumProcessorCount = KeQueryMaximumProcessorCountEx(0xFFFFu);
    v8 = ExAllocatePool2(0x48u);
    *(_QWORD *)(v4 + 4144) = v8;
    if ( !v8 )
      return (unsigned int)-1073741801;
    v9 = MaximumProcessorCount;
    v10 = v8 + (MaximumProcessorCount << 6);
    if ( (_DWORD)MaximumProcessorCount )
    {
      v11 = 0;
      do
      {
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144)) = v10;
        v11 += 64;
        v12 = v10 + 8LL * *(unsigned int *)(v4 + 16);
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144) - 56) = v12;
        v13 = v12 + 8LL * *(unsigned int *)(v4 + 16);
        *(_QWORD *)(v11 + *(_QWORD *)(v4 + 4144) - 48) = v13;
        v10 = v13 + 8LL * *(unsigned int *)(v4 + 16);
        --v9;
      }
      while ( v9 );
    }
  }
  v15 = PsAttachSiloToCurrentThread(a1);
  EtwpQuerySiloRegistrySettings(v4);
  EtwpQueryPartitionRegistryInformation(v4 + 4176, v4 + 4216, v4 + 4224, v4 + 4228, v4 + 4208, v4 + 4192);
  if ( IsHostSilo )
    qword_1410077D8 = KeQueryPerformanceCounter(0).QuadPart;
  EtwpInitializeAutoLoggers(a2);
  if ( IsHostSilo )
    qword_1410077E0 = KeQueryPerformanceCounter(0).QuadPart;
  PsDetachSiloFromCurrentThread(v15);
  CurrentThread = KeGetCurrentThread();
  v17 = (signed __int64 *)(v4 + 432);
  --CurrentThread->KernelApcDisable;
  v18 = KeAbPreAcquire(v4 + 432, 0, 0);
  v19 = v18;
  if ( _interlockedbittestandset64((volatile signed __int32 *)(v4 + 432), 0) )
    ExfAcquirePushLockExclusiveEx(v4 + 432, v18, v4 + 432);
  if ( v19 )
    *(_BYTE *)(v19 + 10) = 1;
  v20 = (_WORD *)(v4 + 4048);
  *(_QWORD *)(v4 + 440) = KeGetCurrentThread();
  v21 = v4 + 156;
  LODWORD(v22) = 0;
  do
  {
    if ( *v20 )
    {
      *(_WORD *)(v21 + 2) = *v20;
      *(_DWORD *)(v21 - 4) = 1;
      *(_BYTE *)v21 = -1;
      *(_QWORD *)(v21 + 12) = -1;
      *(_QWORD *)(v21 + 20) = 0;
      *(_DWORD *)(v21 + 4) = 64;
      *(_BYTE *)(v4 + 4064) |= 1 << v22;
    }
    v22 = (unsigned int)(v22 + 1);
    ++v20;
    v21 += 32;
  }
  while ( (unsigned int)v22 < 8 );
  *(_QWORD *)(v4 + 440) = 0;
  _m_prefetchw(v17);
  v23 = *v17;
  v24 = *v17 - 16;
  if ( (*v17 & 0xFFFFFFFFFFFFFFF0uLL) <= 0x10 )
    v24 = 0;
  if ( (v23 & 2) != 0 || (v25 = *v17, v25 != _InterlockedCompareExchange64(v17, v24, v23)) )
    ExfReleasePushLock(v4 + 432, v24, v22, v20);
  KeAbPostRelease(v4 + 432);
  KeLeaveCriticalRegion();
  *(_QWORD *)(v4 + 4096) = 0;
  *(_QWORD *)(v4 + 4080) = 0;
  *(_QWORD *)(v4 + 4088) = 0;
  return v5;
}

```

// --- Calls: PsGetServerSiloGlobals at 0x1402f8270 (Depth: 1) ---
// Language: C/C++
```cpp
void *__fastcall PsGetServerSiloGlobals(__int64 a1)
{
  if ( a1 )
    return *(void **)(a1 + 1504);
  else
    return &PspHostSiloGlobals;
}

```

// --- Calls: PsIsHostSilo at 0x14043dc20 (Depth: 1) ---
// Language: C/C++
```cpp
bool __fastcall PsIsHostSilo(__int64 a1)
{
  return a1 == 0;
}

```

// --- Calls: KeQueryMaximumProcessorCountEx at 0x1402ed360 (Depth: 1) ---
// Language: C/C++
```cpp
ULONG __stdcall KeQueryMaximumProcessorCountEx(USHORT GroupNumber)
{
  if ( KeDynamicPartitioningSupported )
  {
    if ( GroupNumber == 0xFFFF || !GroupNumber && KiMaximumGroups == 1 )
      return KeMaximumProcessors;
    else
      return GroupNumber < (USHORT)KiMaximumGroups ? KiMaximumGroupSize : 0;
  }
  else if ( GroupNumber == 0xFFFF )
  {
    return KeNumberProcessors_0;
  }
  else if ( GroupNumber >= (unsigned __int16)KiActiveGroups )
  {
    return 0;
  }
  else
  {
    return __popcnt(KeActiveProcessors.Bitmap[GroupNumber]);
  }
}

```

// --- Calls: ExAllocatePool2 at 0x140b680f0 (Depth: 1) ---
// Language: C/C++
```cpp
ULONG_PTR __fastcall ExAllocatePool2(ULONG_PTR BugCheckParameter3, ULONG_PTR a2, ULONG_PTR a3)
{
  __int64 PoolWithTagFromNode; // rsi
  ULONG v4; // edi
  ULONG_PTR v5; // rbx
  __int64 v6; // rcx
  ULONG_PTR v7; // r9
  ULONG_PTR v9; // r14
  _KPROCESS *Process; // r15
  ULONG_PTR v11; // rax
  ULONG_PTR v12; // rbp
  ULONG_PTR v13; // rdx
  __int16 v14; // cx
  __int64 v15; // r10
  _KSCHEDULING_GROUP *SchedulingGroup; // rax
  unsigned __int64 *v17; // r12
  char v18; // r8
  unsigned __int64 v19; // r13
  unsigned __int64 v20; // rax
  unsigned __int64 v21; // rdx
  bool v22; // zf
  signed __int64 v23; // rax
  unsigned __int64 v24; // rax
  signed __int64 v25; // rdx
  unsigned __int64 v26; // rdx
  unsigned __int64 v27; // rax
  unsigned __int64 v28; // rcx
  __int64 HeapFromVA; // rax
  ULONG_PTR v30; // rbx
  _BYTE *BugCheckParameter4; // rdx
  KIRQL v32; // al
  int v33; // r8d
  unsigned __int64 v34; // r12
  unsigned int v35; // r9d
  char *v36; // rcx
  unsigned __int64 v37; // rcx
  unsigned __int64 v38; // rcx
  char v39; // al
  signed __int32 v40[8]; // [rsp+0h] [rbp-A8h] BYREF
  __int64 v41; // [rsp+40h] [rbp-68h]
  unsigned __int64 v42; // [rsp+48h] [rbp-60h] BYREF
  __int64 v43; // [rsp+50h] [rbp-58h]
  ULONG_PTR v44; // [rsp+58h] [rbp-50h]
  __int64 v45[2]; // [rsp+60h] [rbp-48h] BYREF
  __int64 retaddr; // [rsp+A8h] [rbp+0h]
  char v47; // [rsp+B0h] [rbp+8h]
  __int64 v48; // [rsp+C8h] [rbp+20h] BYREF

  PoolWithTagFromNode = 0;
  v4 = a3;
  v5 = BugCheckParameter3;
  *(_OWORD *)v45 = 0;
  if ( (BugCheckParameter3 & 0x1C0) == 0
    || (((BugCheckParameter3 & 0x1C0) - 1) & BugCheckParameter3 & 0x1C0) != 0
    || (BugCheckParameter3 & 0xFFFFF000) != 0
    || (BugCheckParameter3 & 0x10) != 0
    || (BugCheckParameter3 & 0x800) != 0
    || !(_DWORD)a3 )
  {
    v6 = 3221225485LL;
    goto LABEL_4;
  }
  if ( (ExpPoolFlags & 8) != 0 )
  {
    if ( (BugCheckParameter3 & 0x200) == 0 )
    {
      LODWORD(v45[1]) = 32;
      v45[0] = v45[0] & 0xFFFFFFFFFFFFFF00uLL | 1;
      return VfHandlePoolAlloc(
               NonPagedPool,
               BugCheckParameter3 & 0xFFFFFFFFFFFFFFFEuLL,
               a2,
               a3,
               LowPoolPriority,
               (__int64)v45,
               1,
               retaddr);
    }
    v5 = BugCheckParameter3 & 0xFFFFFFFFFFFFFDFFuLL;
  }
  v7 = KeGetCurrentPrcb()->SchedulerSubNode->Affinity.Reserved[0];
  if ( (v5 & 1) == 0 )
  {
    LODWORD(v7) = v7 | 0x80000000;
    PoolWithTagFromNode = ExpAllocatePoolWithTagFromNode(v5, a2, a3, v7);
    if ( !PoolWithTagFromNode )
    {
      v6 = 3221225626LL;
      goto LABEL_4;
    }
    return PoolWithTagFromNode;
  }
  v9 = v5;
  LODWORD(v48) = 0;
  v41 = 0;
  Process = KeGetCurrentThread()->ApcState.Process;
  if ( Process == PsInitialSystemProcess )
    v9 = v5 & 0xFFFFFFFFFFFFFFFEuLL;
  LODWORD(v7) = v7 | 0x80000000;
  v11 = ExpAllocatePoolWithTagFromNode(v9, a2, a3, v7);
  v12 = v11;
  if ( v11 )
  {
    if ( (v9 & 1) != 0 )
    {
      if ( !ExpSpecialAllocations
        || (HeapFromVA = ExGetHeapFromVA(v11), !(unsigned int)ExpHpIsSpecialPoolHeap(HeapFromVA)) )
      {
        v44 = v12 & 0xFFF;
        if ( (v12 & 0xFFF) != 0 )
        {
          v13 = v12 - 16;
          if ( (*(_BYTE *)(v12 - 13) & 4) != 0 )
            v13 += -16LL * (unsigned __int8)*(_WORD *)v13;
          v14 = *(_WORD *)(v13 + 2);
          v41 = 16LL * (unsigned __int8)v14;
          LODWORD(v48) = *(_DWORD *)(v13 + 4);
          if ( (v14 & 0x800) != 0 )
            *(_QWORD *)(v13 + 8) = ExpPoolQuotaCookie ^ v13;
        }
        else
        {
          v32 = ExAcquireSpinLockShared(&ExpLargePoolTableLock);
          v33 = 1;
          v34 = v32;
          v35 = (PoolBigPageTableSize - 1) & ((40543 * (v12 >> 12)) ^ ((40543 * (v12 >> 12)) >> 32));
          while ( 1 )
          {
            v36 = (char *)PoolBigPageTable + 32 * v35;
            if ( *(_QWORD *)v36 == v12 )
              break;
            if ( ++v35 >= (unsigned __int64)PoolBigPageTableSize )
            {
              if ( !v33 )
                goto LABEL_61;
              v35 = 0;
              v33 = 0;
            }
          }
          if ( !v36 )
LABEL_61:
            KeBugCheckEx(0x19u, 0x22u, v12, (unsigned int)v9, 0);
          if ( (*((_DWORD *)v36 + 3) & 0x100) != 0 )
          {
            *((_QWORD *)v36 + 3) = ExpPoolQuotaCookie ^ v12;
            LODWORD(v48) = *((_DWORD *)v36 + 2);
            v41 = *((_QWORD *)v36 + 2);
          }
          ExReleaseSpinLockSharedFromDpcLevel(&ExpLargePoolTableLock);
          if ( KiIrqlFlags )
            KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql());
          __writecr8(v34);
        }
        if ( Process != PsInitialSystemProcess )
        {
          v15 = (v9 & 0x100) != 0;
          SchedulingGroup = Process[1].SchedulingGroup;
          v43 = v15;
          v17 = (unsigned __int64 *)(&SchedulingGroup->Policy + 16 * v15);
          v18 = PspResourceFlags[8 * v15];
          v47 = v18;
          _m_prefetchw(v17);
          v19 = *v17;
          _InterlockedOr(v40, 0);
LABEL_28:
          v20 = v17[8];
LABEL_29:
          v42 = v20;
          while ( 1 )
          {
            v21 = v19 + v41;
            if ( v19 + v41 < v19 )
              break;
            if ( v21 <= v20 )
            {
              v23 = _InterlockedCompareExchange64((volatile signed __int64 *)v17, v21, v19);
              v22 = v19 == v23;
              v19 = v23;
              if ( !v22 )
                goto LABEL_28;
              _m_prefetchw(v17 + 1);
              v24 = v17[1];
              do
              {
                if ( v21 <= v24 )
                  break;
                v37 = v24;
                v24 = _InterlockedCompareExchange64((volatile signed __int64 *)v17 + 1, v21, v24);
              }
              while ( v24 != v37 );
              if ( Process && (v18 & 4) != 0 )
              {
                v25 = _InterlockedExchangeAdd64((volatile signed __int64 *)&Process[1].ThreadListHead.Blink + v15, v41);
                v26 = v41 + v25;
                _m_prefetchw(&Process[1].DeepFreezeStartTime + v15);
                v27 = *(&Process[1].DeepFreezeStartTime + v15);
                do
                {
                  if ( v26 <= v27 )
                    break;
                  v28 = v27;
                  v27 = _InterlockedCompareExchange64(
                          (volatile signed __int64 *)&Process[1].DeepFreezeStartTime + v15,
                          v26,
                          v27);
                }
                while ( v27 != v28 );
              }
              goto LABEL_45;
            }
            if ( (v18 & 1) == 0 || !v17[10] )
              break;
            v38 = _InterlockedExchange64((volatile __int64 *)v17 + 9, 0);
            if ( v38 )
            {
              v20 = v38 + _InterlockedExchangeAdd64((volatile signed __int64 *)v17 + 8, v38);
              goto LABEL_29;
            }
            v39 = PspExpandQuota(v15, (_DWORD)v17, v19, v41, (__int64)&v42);
            v15 = v43;
            if ( !v39 )
              break;
            v20 = v42;
            v18 = v47;
          }
          if ( *(int *)&PspResourceFlags[8 * v15 + 4] >= 0 )
            goto LABEL_45;
          ExFreePoolWithTag((PVOID)v12, v4);
          v6 = 3221225626LL;
          goto LABEL_4;
        }
LABEL_45:
        v30 = 0;
        if ( v44 )
        {
          v30 = v12 - 16;
          if ( (*(_BYTE *)(v12 - 13) & 4) != 0 )
            v30 += -16LL * (unsigned __int8)*(_WORD *)v30;
          if ( (*(_BYTE *)(v30 + 3) & 8) == 0 )
            goto LABEL_54;
          BugCheckParameter4 = (_BYTE *)(ExpPoolQuotaCookie ^ *(_QWORD *)(v30 + 8) ^ v30);
          *(_QWORD *)(v30 + 8) = (unsigned __int64)Process ^ ExpPoolQuotaCookie ^ v30;
        }
        else
        {
          BugCheckParameter4 = (_BYTE *)ExpStampBigPoolEntry(v12, v9, (__int64)&v48);
        }
        if ( BugCheckParameter4
          && BugCheckParameter4 != (_BYTE *)-1LL
          && ((unsigned __int64)BugCheckParameter4 < 0xFFFF800000000000uLL || (*BugCheckParameter4 & 0x7F) != 3) )
        {
          if ( v30 )
            LODWORD(PoolWithTagFromNode) = *(_DWORD *)(v30 + 4);
          KeBugCheckEx(0xC2u, 0xDu, v12, (unsigned int)PoolWithTagFromNode, (ULONG_PTR)BugCheckParameter4);
        }
LABEL_54:
        ObfReferenceObjectWithTag(Process, v4);
        return v12;
      }
    }
  }
  PoolWithTagFromNode = v12;
  if ( !v12 )
  {
    v6 = 3221225626LL;
LABEL_4:
    if ( (v5 & 0x20) != 0 )
      RtlRaiseStatus(v6);
  }
  return PoolWithTagFromNode;
}

```

// --- Calls: RtlRaiseStatus at 0x140233fc0 (Depth: 2) ---
// Language: C/C++
```cpp
// Alternative name is 'ExRaiseStatus'
void __fastcall __noreturn RtlRaiseStatus(int a1)
{
  __int64 v2; // r8
  char v3; // bl
  unsigned int v4; // eax
  _DWORD v5[2]; // [rsp+20h] [rbp-578h] BYREF
  __int64 v6; // [rsp+28h] [rbp-570h]
  __int64 v7; // [rsp+30h] [rbp-568h]
  int v8; // [rsp+38h] [rbp-560h]
  _BYTE v9[132]; // [rsp+3Ch] [rbp-55Ch] BYREF
  _BYTE v10[1240]; // [rsp+C0h] [rbp-4D8h] BYREF

  memset_0(v9, 0, 0x7Cu);
  v6 = 0;
  v8 = 0;
  v7 = -1;
  v5[0] = a1;
  v3 = 1;
  v5[1] = 129;
  do
  {
    LOBYTE(v2) = v3;
    v4 = RtlRaiseNoncontinuableException(v5, v10, v2);
    --v3;
  }
  while ( !v3 );
  RtlRaiseStatus(v4);
}

```

// --- Calls: ExpAllocatePoolWithTagFromNode at 0x14025d850 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall ExpAllocatePoolWithTagFromNode(
        ULONG_PTR BugCheckParameter2,
        size_t Size,
        ULONG_PTR BugCheckParameter4,
        int a4)
{
  unsigned int v4; // edi
  int v7; // r14d
  int v8; // ebx
  int v9; // r15d
  unsigned int v10; // eax
  __int64 result; // rax

  v4 = BugCheckParameter4;
  if ( a4 >= 0 )
    v7 = 1;
  else
    v7 = (unsigned __int16)KeNumberNodes;
  v8 = a4 & 0x7FFFFFFF;
  if ( a4 >= 0 )
    v8 = a4;
  v9 = 0;
  v10 = v8;
  while ( 1 )
  {
    result = ExAllocateHeapPool(BugCheckParameter2, Size, v4, v10);
    if ( result )
      break;
    if ( --v7 )
    {
      if ( ++v9 != (unsigned __int16)KeNumberNodes )
      {
        v10 = *(_DWORD *)(qword_140E2D9D0 + 4LL * (v9 + v8 * (unsigned int)(unsigned __int16)KeNumberNodes));
        if ( v10 != -1 )
          continue;
      }
    }
    ++ExPoolFailures;
    return 0;
  }
  return result;
}

```

// --- Calls: VfHandlePoolAlloc at 0x140b9eac0 (Depth: 2) ---
// Language: C/C++
```cpp
PVOID __fastcall VfHandlePoolAlloc(
        POOL_TYPE PoolType,
        ULONG_PTR BugCheckParameter3,
        unsigned __int64 a3,
        ULONG Tag,
        EX_POOL_PRIORITY Priority,
        __int64 a6,
        int a7,
        __int64 a8)
{
  ULONG_PTR v10; // rbx
  POOL_TYPE v11; // esi
  union _SLIST_HEADER *VerifierData; // r13
  ULONG_PTR v13; // rcx
  ULONG_PTR v14; // r8
  ULONG_PTR v15; // rdx
  __int64 v17; // r12
  __int64 v18; // r15
  EX_POOL_PRIORITY v19; // r14d
  PSLIST_ENTRY v20; // rsi
  __int64 PoolWithTagPriority; // rax
  __int64 v22; // rbx
  __int64 v23; // rax
  __int64 v24; // rax
  __int64 v25; // rcx
  unsigned int v26; // r15d
  __int64 v27; // r14
  __int64 v28; // rdx
  _SLIST_ENTRY *v29; // rax
  unsigned int i; // edx
  char v31; // [rsp+40h] [rbp-40h] BYREF
  int v32; // [rsp+44h] [rbp-3Ch]
  SIZE_T NumberOfBytes; // [rsp+48h] [rbp-38h]
  unsigned int v34; // [rsp+50h] [rbp-30h]
  unsigned __int64 v35; // [rsp+58h] [rbp-28h]
  unsigned __int64 v36; // [rsp+60h] [rbp-20h]
  __int128 v37; // [rsp+68h] [rbp-18h] BYREF
  __int64 v38; // [rsp+78h] [rbp-8h]
  POOL_TYPE v39; // [rsp+C0h] [rbp+40h] BYREF
  char v40; // [rsp+C8h] [rbp+48h] BYREF
  ULONG Taga; // [rsp+D8h] [rbp+58h] BYREF

  Taga = Tag;
  v39 = PoolType;
  LODWORD(NumberOfBytes) = 0;
  v34 = 0;
  v10 = BugCheckParameter3;
  v11 = PoolType;
  VerifierData = 0;
  if ( BugCheckParameter3 )
  {
    if ( (int)ExpPoolFlagsToPoolType(BugCheckParameter3, 0, (unsigned int)&v39, (unsigned int)&v31, (__int64)&v40) < 0 )
    {
      v14 = Tag;
      v15 = a3;
LABEL_4:
      if ( a6 )
        return (PVOID)ExAllocatePool3(v13, a7);
      else
        return (PVOID)ExAllocatePool2(v13, v15, v14);
    }
    v11 = v39;
  }
  v17 = a8;
  if ( KernelVerifier )
  {
    if ( (v11 & 0x80u) == 0 )
    {
      v11 |= 0x80u;
      v39 = v11;
      if ( v10 )
        v10 |= 0x200uLL;
    }
    else
    {
      LODWORD(NumberOfBytes) = 1;
      VerifierData = (union _SLIST_HEADER *)VfTargetDriversGetVerifierData(a8);
      if ( !VerifierData )
      {
        v14 = Tag;
        v15 = a3;
        if ( !v10 )
          return ExAllocatePoolWithTagPriority(v11, a3, Tag, Priority);
        v13 = v10;
        goto LABEL_4;
      }
    }
  }
  if ( (MmVerifierData & 1) != 0 )
    ExAllocatePoolSanityChecks((unsigned int)v11, a3, &Taga, v17);
  v32 = 0;
  if ( !a3 && (unsigned int)VfVerifyMode <= 1 )
  {
    v32 = 1;
    a3 = 1;
  }
  v36 = a3;
  v35 = a3;
  _InterlockedIncrement(&dword_140F03D50);
  v18 = v39;
  if ( (v39 & 2) != 0 && (VfRuleClasses & 4) != 0 && (unsigned int)VfFaultsIsSystemSufficientlyBooted() )
    CarReportRuleViolationFromNt(0xC2u, 0x9Au, v18 & 0xFFFFFFFFFFFFFF7FuLL, a3, Taga, 2, v17);
  v19 = Priority;
  if ( (VfRuleClasses & 1) != 0 || DifpSpecialPoolEnabled )
  {
    if ( (Priority & 9) == 0 )
    {
      if ( MmSpecialPoolCatchOverruns == 1 )
        v19 = Priority | 8;
      else
        v19 = Priority | 9;
    }
    if ( v10 )
      v10 |= 0x100000000uLL;
  }
  v20 = 0;
  if ( (VfRuleClasses & 8) != 0
    && !_bittest(&VfOptionFlags, 0xCu)
    && (v18 & 0x20) == 0
    && Taga != 1850304854
    && Taga != 1316118851 )
  {
    if ( !(_DWORD)NumberOfBytes )
      VerifierData = (union _SLIST_HEADER *)VfTargetDriversGetVerifierData(v17);
    if ( VerifierData && (NumberOfBytes = a3 + 8, a3 + 8 >= a3) )
    {
      v20 = RtlpInterlockedPopEntrySList(VerifierData + 5);
      if ( v20 || (v20 = (PSLIST_ENTRY)ViGrowPoolAllocation(VerifierData)) != 0 )
      {
        a3 = NumberOfBytes;
        LODWORD(v18) = v18 | 0x40;
        v39 = (int)v18;
        if ( !v10 )
        {
LABEL_47:
          PoolWithTagPriority = (__int64)ExAllocatePoolWithTagPriority((POOL_TYPE)v18, a3, Taga, v19);
          goto LABEL_51;
        }
        v10 |= 0x400uLL;
      }
    }
    else
    {
      ++dword_140F03D7C;
    }
  }
  if ( !v10 )
    goto LABEL_47;
  if ( a6 )
    PoolWithTagPriority = ExAllocatePool3(v10, a7);
  else
    PoolWithTagPriority = ExAllocatePool2(v10, a3, Taga);
LABEL_51:
  v22 = PoolWithTagPriority;
  if ( !PoolWithTagPriority )
  {
    ++dword_140F03D68;
    if ( (MmVerifierData & 0x1000) != 0 )
    {
      v38 = 0;
      v37 = 0;
      if ( (unsigned int)ViTargetUpdateTreeAllowed() )
      {
        if ( !(unsigned int)VfDriverIsKernelImageAddress(v17) )
        {
          VfAvlInitializeLockContext(&v37, 1);
          v23 = VfAvlLookupTreeNode(&ViTargetDriversAvl, &v37, v17, 1);
          if ( v23 )
          {
            v24 = *(_QWORD *)(v23 + 64);
            if ( v24 )
            {
              _InterlockedAdd((volatile signed __int32 *)(v24 + 176), 1u);
              LOBYTE(v18) = v39;
            }
          }
          VfAvlCleanupLockContext(&v37);
        }
      }
    }
    if ( v20 )
      RtlpInterlockedPushEntrySList(VerifierData + 5, v20);
    if ( (v18 & 0x10) != 0 )
      RtlRaiseStatus(-1073741670);
    return 0;
  }
  if ( v32 && (VfRuleClasses & 8) != 0 )
  {
    v25 = 3LL * (((unsigned __int8)_InterlockedExchangeAdd(&ViBugcheckWorkaroundLogIndex, 1u) + 1) & 0xF);
    ViBugcheckWorkaroundLog[2 * v25] = 1;
    qword_140FFE818[v25] = v17;
    qword_140FFE820[v25] = PoolWithTagPriority;
  }
  v26 = 0;
  _InterlockedIncrement(&dword_140F03D54);
  if ( (unsigned int)ExIsSpecialPoolAddress(PoolWithTagPriority) == 1 )
  {
    v26 = 1;
LABEL_70:
    _InterlockedIncrement(&dword_140F03D58);
    goto LABEL_71;
  }
  if ( a3 > 0xFE0 )
    goto LABEL_70;
LABEL_71:
  v27 = Taga;
  if ( v20 )
  {
    v28 = (unsigned int)v39;
    *((_QWORD *)&v20->Next + 1) = v17;
    v20->Next = (_SLIST_ENTRY *)(v22 | v26);
    v29 = (_SLIST_ENTRY *)v36;
    if ( !v26 )
      v29 = (_SLIST_ENTRY *)a3;
    *((_QWORD *)&v20[1].Next + 1) = v27;
    v20[1].Next = v29;
    ViPostPoolAllocation(v20, v28);
  }
  if ( (VfRuleClasses & 8) != 0 )
  {
    if ( (unsigned int)(DifpPoolTagsSize - 1) > 9 )
    {
LABEL_81:
      ViPtLogPoolTraceWrapper(v22, (unsigned int)v27, v35, 0);
    }
    else
    {
      for ( i = v34; i < DifpPoolTagsSize; ++i )
      {
        if ( *((_DWORD *)&DifpPoolTags + i) == (_DWORD)v27 )
          goto LABEL_81;
      }
    }
    if ( v20 && !v26 && (v39 & 0x400) == 0 )
      VfFillAllocatedMemory((void *)v22);
  }
  return (PVOID)v22;
}

```

// --- Calls: ExGetHeapFromVA at 0x1402642b0 (Depth: 2) ---
// Language: C/C++
```cpp
ULONG_PTR __fastcall ExGetHeapFromVA(ULONG_PTR BugCheckParameter3)
{
  int v2; // eax
  __int64 v3; // rcx
  ULONG_PTR v4; // rax
  ULONG_PTR result; // rax
  __int64 v6; // rax
  __int128 v7; // [rsp+30h] [rbp-28h] BYREF
  __int128 v8; // [rsp+40h] [rbp-18h]
  int v9; // [rsp+60h] [rbp+8h]
  int v10; // [rsp+64h] [rbp+Ch]

  if ( (_WORD)BugCheckParameter3 )
  {
    v2 = 0;
LABEL_3:
    v9 = 0x100000;
    v10 = 0x1000000;
    v3 = 192LL * v2;
    v4 = BugCheckParameter3 & -(__int64)(unsigned int)*(&v9 + v2);
    result = (RtlpHpHeapGlobals ^ *(_QWORD *)(v4 + 16) ^ v4) - v3 - 320;
    goto LABEL_4;
  }
  v6 = RtlCSparseBitmapBitmaskRead(&dword_140E681D0, 2 * ((BugCheckParameter3 - qword_140E681C8) >> 20));
  if ( v6 )
  {
    v2 = v6 - 1;
    if ( v2 != 2 )
      goto LABEL_3;
  }
  v7 = 0;
  v8 = 0;
  RtlpHpVaMgrCtxQuery(&unk_140E68218, BugCheckParameter3, &v7);
  result = *(_QWORD *)v8;
LABEL_4:
  if ( !result )
    KeBugCheckEx(0xC2u, 0, 0, BugCheckParameter3, 0);
  return result;
}

```

// --- Calls: ExpHpIsSpecialPoolHeap at 0x1402654a8 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall ExpHpIsSpecialPoolHeap(__int64 a1)
{
  unsigned int v1; // edx
  __int64 *i; // rax

  v1 = 0;
  for ( i = &qword_140EEEB00; (__int64)i < (__int64)qword_140EEEB20; ++i )
  {
    if ( a1 == *i )
      return 1;
  }
  return v1;
}

```

// --- Calls: ObfReferenceObjectWithTag at 0x1402ef2f0 (Depth: 2) ---
// Language: C/C++
```cpp
LONG_PTR __stdcall ObfReferenceObjectWithTag(PVOID Object, ULONG Tag)
{
  __int64 BugCheckParameter4; // rbx

  ObpTraceObjectReferenceIfActive((char *)Object - 48, 1, Tag);
  BugCheckParameter4 = _InterlockedIncrement64((volatile signed __int64 *)Object - 6);
  if ( BugCheckParameter4 <= 1 )
    KeBugCheckEx(0x18u, 0, (ULONG_PTR)Object, 0x10u, BugCheckParameter4);
  return BugCheckParameter4;
}

```

// --- Calls: ExFreePoolWithTag at 0x140b68cd0 (Depth: 2) ---
// Language: Assembly
```cpp
POOLCODE:0000000140B68CD0 ; Exported entry 290. ExFreePoolWithTag
POOLCODE:0000000140B68CD0
POOLCODE:0000000140B68CD0 ; =============== S U B R O U T I N E ======…
POOLCODE:0000000140B68CD0
POOLCODE:0000000140B68CD0 ; Attributes: bp-based frame fpd=57h
POOLCODE:0000000140B68CD0
POOLCODE:0000000140B68CD0 ; void __stdcall ExFreePoolWithTag(PVOID P, …
POOLCODE:0000000140B68CD0                 public ExFreePoolWithTag
POOLCODE:0000000140B68CD0 ExFreePoolWithTag proc near             ; CO…
POOLCODE:0000000140B68CD0                                         ; Al…
POOLCODE:0000000140B68CD0
POOLCODE:0000000140B68CD0 var_D8          = qword ptr -0D8h
POOLCODE:0000000140B68CD0 BugCheckParameter4= qword ptr -0D0h
POOLCODE:0000000140B68CD0 var_C0          = qword ptr -0C0h
POOLCODE:0000000140B68CD0 BugCheckParameter3= qword ptr -0B8h
POOLCODE:0000000140B68CD0 var_B0          = byte ptr -0B0h
POOLCODE:0000000140B68CD0 var_AF          = byte ptr -0AFh
POOLCODE:0000000140B68CD0 var_AC          = dword ptr -0ACh
POOLCODE:0000000140B68CD0 var_A8          = dword ptr -0A8h
POOLCODE:0000000140B68CD0 var_A4          = dword ptr -0A4h
POOLCODE:0000000140B68CD0 var_A0          = dword ptr -0A0h
POOLCODE:0000000140B68CD0 var_98          = qword ptr -98h
POOLCODE:0000000140B68CD0 LockHandle      = _KLOCK_QUEUE_HANDLE ptr -9…
POOLCODE:0000000140B68CD0 var_78          = dword ptr -78h
POOLCODE:0000000140B68CD0 var_74          = dword ptr -74h
POOLCODE:0000000140B68CD0 var_68          = xmmword ptr -68h
POOLCODE:0000000140B68CD0 var_58          = xmmword ptr -58h
POOLCODE:0000000140B68CD0 var_48          = xmmword ptr -48h
POOLCODE:0000000140B68CD0 var_38          = qword ptr -38h
POOLCODE:0000000140B68CD0 var_30          = qword ptr -30h
POOLCODE:0000000140B68CD0 var_28          = qword ptr -28h
POOLCODE:0000000140B68CD0 var_20          = qword ptr -20h
POOLCODE:0000000140B68CD0 var_s8          = qword ptr  8
POOLCODE:0000000140B68CD0 arg_0           = qword ptr  10h
POOLCODE:0000000140B68CD0 arg_8           = qword ptr  18h
POOLCODE:0000000140B68CD0 arg_10          = qword ptr  20h
POOLCODE:0000000140B68CD0 arg_18          = byte ptr  28h
POOLCODE:0000000140B68CD0
POOLCODE:0000000140B68CD0                 mov     rax, rsp
POOLCODE:0000000140B68CD3                 mov     [rax+8], rcx
POOLCODE:0000000140B68CD7                 push    rbp
POOLCODE:0000000140B68CD8                 push    rsi
POOLCODE:0000000140B68CD9                 push    r13
POOLCODE:0000000140B68CDB                 lea     rbp, [rax-5Fh]
POOLCODE:0000000140B68CDF                 sub     rsp, 0E0h
POOLCODE:0000000140B68CE6                 mov     rsi, 0FFFF8000000000…
POOLCODE:0000000140B68CF0                 mov     r13, rcx
POOLCODE:0000000140B68CF3                 cmp     rcx, rsi
POOLCODE:0000000140B68CF6                 jb      loc_140B68D93
POOLCODE:0000000140B68CFC                 test    r13b, 0Fh
POOLCODE:0000000140B68D00                 jnz     loc_140B68D93
POOLCODE:0000000140B68D06
POOLCODE:0000000140B68D06 loc_140B68D06:                          ; DA…
POOLCODE:0000000140B68D06                                         ; .r…
POOLCODE:0000000140B68D06                 mov     [rax-28h], r12
POOLCODE:0000000140B68D0A                 xorps   xmm0, xmm0
POOLCODE:0000000140B68D0D                 movups  [rbp+57h+var_68], xm…
POOLCODE:0000000140B68D11                 xor     r12d, r12d
POOLCODE:0000000140B68D14                 mov     word ptr [rbp+57h+va…
POOLCODE:0000000140B68D1A                 mov     byte ptr [rbp+57h+va…
POOLCODE:0000000140B68D1E                 mov     byte ptr [rbp+57h+va…
POOLCODE:0000000140B68D22                 mov     [rax-38h], r15
POOLCODE:0000000140B68D26                 mov     byte ptr [rbp+57h+va…
POOLCODE:0000000140B68D2A                 test    r13w, r13w
POOLCODE:0000000140B68D2E                 jz      loc_140B69ADA
POOLCODE:0000000140B68D34                 mov     eax, r12d
POOLCODE:0000000140B68D37
POOLCODE:0000000140B68D37 loc_140B68D37:                          ; CO…
POOLCODE:0000000140B68D37                 cdqe
POOLCODE:0000000140B68D39                 mov     [rbp+57h+var_78], 10…
POOLCODE:0000000140B68D40                 mov     [rbp+57h+var_74], 10…
POOLCODE:0000000140B68D47                 mov     r15d, [rbp+rax*4+57h…
POOLCODE:0000000140B68D4C                 lea     rax, [rax+rax*2]
POOLCODE:0000000140B68D50                 dec     r15
POOLCODE:0000000140B68D53                 shl     rax, 6
POOLCODE:0000000140B68D57                 not     r15
POOLCODE:0000000140B68D5A                 and     r15, r13
POOLCODE:0000000140B68D5D                 xor     r15, [r15+10h]
POOLCODE:0000000140B68D61                 xor     r15, cs:RtlpHpHeapGl…
POOLCODE:0000000140B68D68                 sub     r15, rax
POOLCODE:0000000140B68D6B                 sub     r15, 140h
POOLCODE:0000000140B68D72
POOLCODE:0000000140B68D72 loc_140B68D72:                          ; CO…
POOLCODE:0000000140B68D72                 mov     [rbp+57h+arg_10], r1…
POOLCODE:0000000140B68D76                 test    r15, r15
POOLCODE:0000000140B68D79                 jnz     short loc_140B68DB0
POOLCODE:0000000140B68D7B                 mov     r9, r13         ; Bu…
POOLCODE:0000000140B68D7E                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B68D83                 xor     r8d, r8d        ; Bu…
POOLCODE:0000000140B68D86                 xor     edx, edx        ; Bu…
POOLCODE:0000000140B68D88                 mov     ecx, 0C2h       ; Bu…
POOLCODE:0000000140B68D8D                 call    KeBugCheckEx
POOLCODE:0000000140B68D8D ; ------------------------------------------…
POOLCODE:0000000140B68D92                 db 0CCh
POOLCODE:0000000140B68D93 ; ------------------------------------------…
POOLCODE:0000000140B68D93
POOLCODE:0000000140B68D93 loc_140B68D93:                          ; CO…
POOLCODE:0000000140B68D93                                         ; Ex…
POOLCODE:0000000140B68D93                                         ; DA…
POOLCODE:0000000140B68D93                 mov     edx, 99h        ; Bu…
POOLCODE:0000000140B68D98                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B68DA1                 xor     r9d, r9d        ; Bu…
POOLCODE:0000000140B68DA4                 mov     r8, r13         ; Bu…
POOLCODE:0000000140B68DA7                 lea     ecx, [rdx+29h]  ; Bu…
POOLCODE:0000000140B68DAA                 call    KeBugCheckEx
POOLCODE:0000000140B68DAA ; ------------------------------------------…
POOLCODE:0000000140B68DAF                 align 10h
POOLCODE:0000000140B68DB0
POOLCODE:0000000140B68DB0 loc_140B68DB0:                          ; CO…
POOLCODE:0000000140B68DB0                                         ; DA…
POOLCODE:0000000140B68DB0                 mov     eax, cs:ExpSpecialAl…
POOLCODE:0000000140B68DB6                 mov     [rsp+0F0h+arg_8], rb…
POOLCODE:0000000140B68DBE                 mov     [rsp+0D8h], rdi
POOLCODE:0000000140B68DC6                 mov     [rsp+0F0h+var_28], r…
POOLCODE:0000000140B68DCE                 test    eax, eax
POOLCODE:0000000140B68DD0                 jnz     loc_140B69029
POOLCODE:0000000140B68DD6
POOLCODE:0000000140B68DD6 loc_140B68DD6:                          ; CO…
POOLCODE:0000000140B68DD6                 mov     edi, 80h
POOLCODE:0000000140B68DDB                 lea     edx, [rdi-7Eh]
POOLCODE:0000000140B68DDE                 test    r13, 0FFFh
POOLCODE:0000000140B68DE5                 jz      loc_140B69737
POOLCODE:0000000140B68DEB                 movzx   eax, byte ptr [r13-0…
POOLCODE:0000000140B68DF0                 lea     r14, [r13-10h]
POOLCODE:0000000140B68DF4                 lea     rbx, cs:140000000h
POOLCODE:0000000140B68DFB                 mov     edx, 100h
POOLCODE:0000000140B68E00                 lea     r8d, [rdi+7Fh]
POOLCODE:0000000140B68E04                 test    al, 8
POOLCODE:0000000140B68E06                 jnz     loc_140B69526
POOLCODE:0000000140B68E0C
POOLCODE:0000000140B68E0C loc_140B68E0C:                          ; CO…
POOLCODE:0000000140B68E0C                                         ; Ex…
POOLCODE:0000000140B68E0C                 test    byte ptr [r14+3], 4
POOLCODE:0000000140B68E11                 jz      short loc_140B68E31
POOLCODE:0000000140B68E13                 movzx   eax, word ptr [r14]
POOLCODE:0000000140B68E17                 mov     ecx, 0FFh
POOLCODE:0000000140B68E1C                 and     ax, cx
POOLCODE:0000000140B68E1F                 movzx   ecx, ax
POOLCODE:0000000140B68E22                 neg     rcx
POOLCODE:0000000140B68E25                 shl     rcx, 4
POOLCODE:0000000140B68E29                 add     r14, rcx
POOLCODE:0000000140B68E2C                 or      byte ptr [r14+3], 4
POOLCODE:0000000140B68E31
POOLCODE:0000000140B68E31 loc_140B68E31:                          ; CO…
POOLCODE:0000000140B68E31                 movzx   r8d, byte ptr [r14+3…
POOLCODE:0000000140B68E36                 mov     rcx, rdx
POOLCODE:0000000140B68E39                 mov     ebx, [r14+4]
POOLCODE:0000000140B68E3D                 test    r8b, 1
POOLCODE:0000000140B68E41                 mov     r9d, r8d
POOLCODE:0000000140B68E44                 cmovz   rcx, rdi
POOLCODE:0000000140B68E48                 mov     rdx, rcx
POOLCODE:0000000140B68E4B                 or      rdx, 4
POOLCODE:0000000140B68E4F                 test    r8b, 20h
POOLCODE:0000000140B68E53                 cmovz   rdx, rcx
POOLCODE:0000000140B68E57                 or      rdx, 2
POOLCODE:0000000140B68E5B                 mov     [rbp+57h+var_C0], rd…
POOLCODE:0000000140B68E5F                 and     r9d, 8
POOLCODE:0000000140B68E63                 jnz     loc_140B69509
POOLCODE:0000000140B68E69
POOLCODE:0000000140B68E69 loc_140B68E69:                          ; CO…
POOLCODE:0000000140B68E69                 test    r8b, 0DEh
POOLCODE:0000000140B68E6D                 jz      short loc_140B68EBC
POOLCODE:0000000140B68E6F                 mov     rcx, rdx
POOLCODE:0000000140B68E72                 or      rcx, 8
POOLCODE:0000000140B68E76                 test    r8b, 4
POOLCODE:0000000140B68E7A                 cmovz   rcx, rdx
POOLCODE:0000000140B68E7E                 mov     rdx, rcx
POOLCODE:0000000140B68E81                 bts     rdx, 9
POOLCODE:0000000140B68E86                 test    r8b, 80h
POOLCODE:0000000140B68E8A                 cmovz   rdx, rcx
POOLCODE:0000000140B68E8E                 mov     rcx, rdx
POOLCODE:0000000140B68E91                 bts     rcx, 0Ah
POOLCODE:0000000140B68E96                 test    r8b, 40h
POOLCODE:0000000140B68E9A                 cmovz   rcx, rdx
POOLCODE:0000000140B68E9E                 mov     [rbp+57h+var_C0], rc…
POOLCODE:0000000140B68EA2                 test    r9d, r9d
POOLCODE:0000000140B68EA5                 jnz     short loc_140B68EBC
POOLCODE:0000000140B68EA7                 mov     [rbp+57h+var_C0], rc…
POOLCODE:0000000140B68EAB                 test    r8b, 10h
POOLCODE:0000000140B68EAF                 jz      short loc_140B68EBC
POOLCODE:0000000140B68EB1                 mov     rax, rcx
POOLCODE:0000000140B68EB4                 or      rax, 20h
POOLCODE:0000000140B68EB8                 mov     [rbp+57h+var_C0], ra…
POOLCODE:0000000140B68EBC
POOLCODE:0000000140B68EBC loc_140B68EBC:                          ; CO…
POOLCODE:0000000140B68EBC                                         ; Ex…
POOLCODE:0000000140B68EBC                 movzx   eax, word ptr [r14+2…
POOLCODE:0000000140B68EC1                 lea     rdi, [r14+10h]
POOLCODE:0000000140B68EC5                 movzx   edx, al
POOLCODE:0000000140B68EC8                 shl     rdx, 4
POOLCODE:0000000140B68ECC                 mov     [rbp+57h+BugCheckPar…
POOLCODE:0000000140B68ED0
POOLCODE:0000000140B68ED0 loc_140B68ED0:                          ; CO…
POOLCODE:0000000140B68ED0                 mov     eax, cs:ExpPoolFlags
POOLCODE:0000000140B68ED6                 mov     rsi, [rbp+57h+var_C0…
POOLCODE:0000000140B68EDA                 test    eax, 207h
POOLCODE:0000000140B68EDF                 jnz     loc_140B69F6A
POOLCODE:0000000140B68EE5
POOLCODE:0000000140B68EE5 loc_140B68EE5:                          ; CO…
POOLCODE:0000000140B68EE5                                         ; Ex…
POOLCODE:0000000140B68EE5                 mov     eax, cs:ExpPoolFlags
POOLCODE:0000000140B68EEB                 test    al, 10h
POOLCODE:0000000140B68EED                 jz      short loc_140B68F00
POOLCODE:0000000140B68EEF                 mov     r8, [rbp+57h+BugChec…
POOLCODE:0000000140B68EF3                 mov     r9, r13
POOLCODE:0000000140B68EF6                 mov     edx, ebx
POOLCODE:0000000140B68EF8                 mov     rcx, r14
POOLCODE:0000000140B68EFB                 call    VfPtFreePoolNotifica…
POOLCODE:0000000140B68F00
POOLCODE:0000000140B68F00 loc_140B68F00:                          ; CO…
POOLCODE:0000000140B68F00                 mov     eax, cs:PoolHitTag
POOLCODE:0000000140B68F06                 mov     [rbp+57h+var_A8], r1…
POOLCODE:0000000140B68F0A                 mov     byte ptr [rbp+57h+ar…
POOLCODE:0000000140B68F0E                 mov     [rbp+57h+var_AF], 0
POOLCODE:0000000140B68F12                 cmp     ebx, eax
POOLCODE:0000000140B68F14                 jnz     short loc_140B68F17
POOLCODE:0000000140B68F16                 int     3               ; Tr…
POOLCODE:0000000140B68F17
POOLCODE:0000000140B68F17 loc_140B68F17:                          ; CO…
POOLCODE:0000000140B68F17                 mov     eax, dword ptr cs:Pe…
POOLCODE:0000000140B68F1D                 test    al, 41h
POOLCODE:0000000140B68F1F                 jnz     loc_140B69FF2
POOLCODE:0000000140B68F25
POOLCODE:0000000140B68F25 loc_140B68F25:                          ; CO…
POOLCODE:0000000140B68F25                                         ; Ex…
POOLCODE:0000000140B68F25                 mov     eax, gs:1A4h
POOLCODE:0000000140B68F2D                 lea     r11, cs:140000000h
POOLCODE:0000000140B68F34                 mov     r9, cs:PoolTrackTabl…
POOLCODE:0000000140B68F3B                 mov     r11, rva ExPoolTagTa…
POOLCODE:0000000140B68F43                 mov     eax, ebx
POOLCODE:0000000140B68F45                 imul    rcx, rax, 9E5Fh
POOLCODE:0000000140B68F4C                 mov     rdx, rcx
POOLCODE:0000000140B68F4F                 shr     rdx, 20h
POOLCODE:0000000140B68F53                 xor     edx, ecx
POOLCODE:0000000140B68F55                 and     edx, r9d
POOLCODE:0000000140B68F58                 mov     r10d, edx
POOLCODE:0000000140B68F5B
POOLCODE:0000000140B68F5B loc_140B68F5B:                          ; CO…
POOLCODE:0000000140B68F5B                                         ; Ex…
POOLCODE:0000000140B68F5B                 mov     eax, edx
POOLCODE:0000000140B68F5D                 lea     rcx, [rax+rax*4]
POOLCODE:0000000140B68F61                 add     rcx, rcx
POOLCODE:0000000140B68F64                 mov     eax, [r11+rcx*8]
POOLCODE:0000000140B68F68                 lea     r8, [r11+rcx*8]
POOLCODE:0000000140B68F6C                 cmp     eax, ebx
POOLCODE:0000000140B68F6E                 jz      loc_140B6935F
POOLCODE:0000000140B68F74                 test    eax, eax
POOLCODE:0000000140B68F76                 jz      loc_140B69A5C
POOLCODE:0000000140B68F7C
POOLCODE:0000000140B68F7C loc_140B68F7C:                          ; CO…
POOLCODE:0000000140B68F7C                 lea     eax, [rdx+1]
POOLCODE:0000000140B68F7F                 and     eax, r9d
POOLCODE:0000000140B68F82                 mov     edx, eax
POOLCODE:0000000140B68F84                 cmp     eax, r10d
POOLCODE:0000000140B68F87                 jnz     short loc_140B68F5B
POOLCODE:0000000140B68F89                 xorps   xmm0, xmm0
POOLCODE:0000000140B68F8C                 lea     rcx, ExpTaggedPoolLo…
POOLCODE:0000000140B68F93                 movups  xmmword ptr [rbp+57h…
POOLCODE:0000000140B68F97                 xor     eax, eax
POOLCODE:0000000140B68F99                 mov     [rbp+57h+LockHandle.…
POOLCODE:0000000140B68F9D                 mov     [rbp+57h+LockHandle.…
POOLCODE:0000000140B68FA1                 mov     qword ptr [rbp+57h+L…
POOLCODE:0000000140B68FA5                 nop
POOLCODE:0000000140B68FA6                 mov     rdi, cr8
POOLCODE:0000000140B68FAA                 mov     eax, 2
POOLCODE:0000000140B68FAF                 mov     cr8, rax
POOLCODE:0000000140B68FB3                 cmp     cs:KiIrqlFlags, 0
POOLCODE:0000000140B68FBA                 jnz     loc_140B69A8F
POOLCODE:0000000140B68FC0
POOLCODE:0000000140B68FC0 loc_140B68FC0:                          ; CO…
POOLCODE:0000000140B68FC0                 test    byte ptr cs:PerfGlob…
POOLCODE:0000000140B68FC7                 mov     [rbp+57h+LockHandle.…
POOLCODE:0000000140B68FCB                 jnz     loc_140B698D3
POOLCODE:0000000140B68FD1
POOLCODE:0000000140B68FD1 loc_140B68FD1:                          ; CO…
POOLCODE:0000000140B68FD1                 lea     rdx, [rbp+57h+LockHa…
POOLCODE:0000000140B68FD5                 xchg    rdx, cs:ExpTaggedPoo…
POOLCODE:0000000140B68FDC                 test    rdx, rdx
POOLCODE:0000000140B68FDF                 jnz     loc_140B69BD3
POOLCODE:0000000140B68FE5
POOLCODE:0000000140B68FE5 loc_140B68FE5:                          ; CO…
POOLCODE:0000000140B68FE5                                         ; Ex…
POOLCODE:0000000140B68FE5                 mov     r9, cs:PoolTrackTabl…
POOLCODE:0000000140B68FEC                 mov     edx, r12d
POOLCODE:0000000140B68FEF                 mov     r10, cs:PoolTrackTab…
POOLCODE:0000000140B68FF6                 db      66h, 66h
POOLCODE:0000000140B68FF6                 nop     word ptr [rax+rax+00…
POOLCODE:0000000140B69000
POOLCODE:0000000140B69000 loc_140B69000:                          ; CO…
POOLCODE:0000000140B69000                 mov     eax, edx
POOLCODE:0000000140B69002                 cmp     rax, r9
POOLCODE:0000000140B69005                 jnb     loc_140B69D21
POOLCODE:0000000140B6900B                 lea     r8, [rax+rax*4]
POOLCODE:0000000140B6900F                 shl     r8, 4
POOLCODE:0000000140B69013                 add     r8, r10
POOLCODE:0000000140B69016                 mov     eax, [r8]
POOLCODE:0000000140B69019                 cmp     eax, ebx
POOLCODE:0000000140B6901B                 jz      short loc_140B6904F
POOLCODE:0000000140B6901D                 test    eax, eax
POOLCODE:0000000140B6901F                 jz      loc_140B69D21
POOLCODE:0000000140B69025                 inc     edx
POOLCODE:0000000140B69027                 jmp     short loc_140B69000
POOLCODE:0000000140B69029 ; ------------------------------------------…
POOLCODE:0000000140B69029
POOLCODE:0000000140B69029 loc_140B69029:                          ; CO…
POOLCODE:0000000140B69029                 lea     rax, qword_140EEEB00
POOLCODE:0000000140B69030                 lea     rcx, qword_140EEEB20
POOLCODE:0000000140B69037
POOLCODE:0000000140B69037 loc_140B69037:                          ; CO…
POOLCODE:0000000140B69037                 cmp     rax, rcx
POOLCODE:0000000140B6903A                 jge     loc_140B68DD6
POOLCODE:0000000140B69040                 cmp     r15, [rax]
POOLCODE:0000000140B69043                 jz      loc_140B6A2D7
POOLCODE:0000000140B69049                 add     rax, 8
POOLCODE:0000000140B6904D                 jmp     short loc_140B69037
POOLCODE:0000000140B6904F ; ------------------------------------------…
POOLCODE:0000000140B6904F
POOLCODE:0000000140B6904F loc_140B6904F:                          ; CO…
POOLCODE:0000000140B6904F                 bt      rsi, 8
POOLCODE:0000000140B69054                 jb      loc_140B69516
POOLCODE:0000000140B6905A                 mov     r9d, 1
POOLCODE:0000000140B69060                 lea     rdx, [r8+8]
POOLCODE:0000000140B69064                 lea     rax, [r8+18h]
POOLCODE:0000000140B69068
POOLCODE:0000000140B69068 loc_140B69068:                          ; CO…
POOLCODE:0000000140B69068                 lock inc qword ptr [rax]
POOLCODE:0000000140B6906C                 mov     r10, [rbp+57h+BugChe…
POOLCODE:0000000140B69070                 mov     rcx, r10
POOLCODE:0000000140B69073                 neg     rcx
POOLCODE:0000000140B69076                 lock xadd [rdx], rcx
POOLCODE:0000000140B6907B                 cmp     qword ptr [r8+48h], …
POOLCODE:0000000140B69080                 jnz     loc_140B6A045
POOLCODE:0000000140B69086
POOLCODE:0000000140B69086 loc_140B69086:                          ; CO…
POOLCODE:0000000140B69086                                         ; Ex…
POOLCODE:0000000140B69086                 lea     rcx, [rbp+57h+LockHa…
POOLCODE:0000000140B6908A                 call    KeReleaseInStackQueu…
POOLCODE:0000000140B6908F
POOLCODE:0000000140B6908F loc_140B6908F:                          ; CO…
POOLCODE:0000000140B6908F                                         ; Ex…
POOLCODE:0000000140B6908F                 bt      rsi, 0Ah
POOLCODE:0000000140B69094                 jnb     loc_140B69BCA
POOLCODE:0000000140B6909A                 shr     rsi, 8
POOLCODE:0000000140B6909E                 xor     r9d, r9d
POOLCODE:0000000140B690A1                 and     esi, 1
POOLCODE:0000000140B690A4                 mov     rcx, r13        ; Bu…
POOLCODE:0000000140B690A7                 mov     r8d, esi
POOLCODE:0000000140B690AA                 mov     rsi, [rbp+57h+BugChe…
POOLCODE:0000000140B690AE                 mov     rdx, rsi        ; Bu…
POOLCODE:0000000140B690B1                 call    ViFreeTrackedPool
POOLCODE:0000000140B690B6
POOLCODE:0000000140B690B6 loc_140B690B6:                          ; CO…
POOLCODE:0000000140B690B6                 cmp     cs:byte_140FCDC28, 0
POOLCODE:0000000140B690BD                 jnz     loc_140B69DA7
POOLCODE:0000000140B690C3
POOLCODE:0000000140B690C3 loc_140B690C3:                          ; CO…
POOLCODE:0000000140B690C3                                         ; Ex…
POOLCODE:0000000140B690C3                 mov     rdx, [r15+38h]
POOLCODE:0000000140B690C7                 lea     rax, [rsi-201h]
POOLCODE:0000000140B690CE                 cmp     rax, 0D7Fh
POOLCODE:0000000140B690D4                 jbe     loc_140B69E50
POOLCODE:0000000140B690DA
POOLCODE:0000000140B690DA loc_140B690DA:                          ; CO…
POOLCODE:0000000140B690DA                 lea     rsi, cs:140000000h
POOLCODE:0000000140B690E1
POOLCODE:0000000140B690E1 loc_140B690E1:                          ; CO…
POOLCODE:0000000140B690E1                 test    r14w, r14w
POOLCODE:0000000140B690E5                 jz      short loc_140B690F0
POOLCODE:0000000140B690E7                 lea     rbx, [r15+140h]
POOLCODE:0000000140B690EE                 jmp     short loc_140B6912F
POOLCODE:0000000140B690F0 ; ------------------------------------------…
POOLCODE:0000000140B690F0
POOLCODE:0000000140B690F0 loc_140B690F0:                          ; CO…
POOLCODE:0000000140B690F0                 mov     rdx, r14
POOLCODE:0000000140B690F3                 lea     rcx, dword_140E681D0
POOLCODE:0000000140B690FA                 sub     rdx, cs:qword_140E68…
POOLCODE:0000000140B69101                 shr     rdx, 14h
POOLCODE:0000000140B69105                 add     rdx, rdx
POOLCODE:0000000140B69108                 call    RtlCSparseBitmapBitm…
POOLCODE:0000000140B6910D                 test    rax, rax
POOLCODE:0000000140B69110                 jz      loc_140B6A114
POOLCODE:0000000140B69116                 cmp     eax, 3
POOLCODE:0000000140B69119                 jz      loc_140B6A114
POOLCODE:0000000140B6911F                 lea     rbx, [r15+140h]
POOLCODE:0000000140B69126                 cmp     eax, 2
POOLCODE:0000000140B69129                 jz      loc_140B69E2E
POOLCODE:0000000140B6912F
POOLCODE:0000000140B6912F loc_140B6912F:                          ; CO…
POOLCODE:0000000140B6912F                                         ; Ex…
POOLCODE:0000000140B6912F                 mov     r9, [rbx]
POOLCODE:0000000140B69132                 mov     rdx, r9
POOLCODE:0000000140B69135                 and     rdx, r14
POOLCODE:0000000140B69138                 mov     rax, rdx
POOLCODE:0000000140B6913B                 xor     rax, [rdx+10h]
POOLCODE:0000000140B6913F                 xor     rax, rbx
POOLCODE:0000000140B69142                 xor     rax, cs:RtlpHpHeapGl…
POOLCODE:0000000140B69149                 jnz     loc_140B693ED
POOLCODE:0000000140B6914F                 movzx   r10d, byte ptr [rbx+…
POOLCODE:0000000140B69154                 mov     r8d, r14d
POOLCODE:0000000140B69157                 sub     r8d, edx
POOLCODE:0000000140B6915A                 mov     ecx, r10d
POOLCODE:0000000140B6915D                 shr     r8d, cl
POOLCODE:0000000140B69160                 shl     r8, 5
POOLCODE:0000000140B69164                 add     r8, rdx
POOLCODE:0000000140B69167                 movzx   eax, byte ptr [r8+1A…
POOLCODE:0000000140B6916C                 neg     rax
POOLCODE:0000000140B6916F                 shl     rax, 5
POOLCODE:0000000140B69173                 add     r8, rax
POOLCODE:0000000140B69176                 mov     rdi, r8
POOLCODE:0000000140B69179                 sub     rdi, rdx
POOLCODE:0000000140B6917C                 sar     rdi, 5
POOLCODE:0000000140B69180                 movzx   r11d, byte ptr [r8+1…
POOLCODE:0000000140B69185                 shl     rdi, cl
POOLCODE:0000000140B69188                 add     rdi, rdx
POOLCODE:0000000140B6918B                 cmp     rdi, r14
POOLCODE:0000000140B6918E                 setz    al
POOLCODE:0000000140B69191                 lea     ecx, [rax+r11]
POOLCODE:0000000140B69195                 cmp     cl, 0Bh
POOLCODE:0000000140B69198                 jnz     loc_140B698F2
POOLCODE:0000000140B6919E                 mov     rsi, [rbx+18h]
POOLCODE:0000000140B691A2                 mov     rax, rdi
POOLCODE:0000000140B691A5                 movzx   edx, word ptr [rdi+2…
POOLCODE:0000000140B691A9                 mov     r8d, r14d
POOLCODE:0000000140B691AC                 shr     rax, 0Ch
POOLCODE:0000000140B691B0                 xor     eax, [rdi+28h]
POOLCODE:0000000140B691B3                 xor     eax, dword ptr cs:qw…
POOLCODE:0000000140B691B9                 movzx   ecx, ax
POOLCODE:0000000140B691BC                 shr     rax, 10h
POOLCODE:0000000140B691C0                 add     rax, rdi
POOLCODE:0000000140B691C3                 shl     rdx, 6
POOLCODE:0000000140B691C7                 sub     r8d, eax
POOLCODE:0000000140B691CA                 mov     eax, r8d
POOLCODE:0000000140B691CD                 mov     ebx, [rdx+rsi+48h]
POOLCODE:0000000140B691D1                 imul    rbx, rax
POOLCODE:0000000140B691D5                 shr     rbx, 20h
POOLCODE:0000000140B691D9                 mov     eax, ebx
POOLCODE:0000000140B691DB                 imul    eax, ecx
POOLCODE:0000000140B691DE                 cmp     r8d, eax
POOLCODE:0000000140B691E1                 jnz     loc_140B694D4
POOLCODE:0000000140B691E7                 mov     rdx, gs:20h
POOLCODE:0000000140B691F0                 mov     r9d, 1
POOLCODE:0000000140B691F6                 mov     r8d, [rsi+4Ch]
POOLCODE:0000000140B691FA                 mov     eax, r8d
POOLCODE:0000000140B691FD                 shr     eax, 0Dh
POOLCODE:0000000140B69200                 and     eax, 3FFFFh
POOLCODE:0000000140B69205                 shr     r8, 4
POOLCODE:0000000140B69209                 bsr     ecx, eax
POOLCODE:0000000140B6920C                 and     r8d, 1FFh
POOLCODE:0000000140B69213                 shl     r9d, cl
POOLCODE:0000000140B69216                 add     ecx, 0FFFFFFFEh
POOLCODE:0000000140B69219                 xor     r9d, eax
POOLCODE:0000000140B6921C                 mov     [rbp+57h+var_A0], ec…
POOLCODE:0000000140B6921F                 mov     rax, [rdx+8BB0h]
POOLCODE:0000000140B69226                 mov     rax, [rax+rcx*8]
POOLCODE:0000000140B6922A                 mov     rax, [rax+r9*8+8]
POOLCODE:0000000140B6922F                 mov     rax, [rax+r8*8]
POOLCODE:0000000140B69233                 test    rax, rax
POOLCODE:0000000140B69236                 jz      loc_140B6A1EA
POOLCODE:0000000140B6923C
POOLCODE:0000000140B6923C loc_140B6923C:                          ; CO…
POOLCODE:0000000140B6923C                 cmp     ax, [rdi+2Eh]
POOLCODE:0000000140B69240                 jz      loc_140B6A19F
POOLCODE:0000000140B69246
POOLCODE:0000000140B69246 loc_140B69246:                          ; CO…
POOLCODE:0000000140B69246                 mov     eax, ebx
POOLCODE:0000000140B69248                 mov     r9, rbx
POOLCODE:0000000140B6924B                 and     eax, 3Fh
POOLCODE:0000000140B6924E                 movzx   ecx, al
POOLCODE:0000000140B69251                 mov     rax, rbx
POOLCODE:0000000140B69254                 shr     rax, 6
POOLCODE:0000000140B69258                 mov     rax, [rdi+rax*8+40h]
POOLCODE:0000000140B6925D                 bt      rax, rcx
POOLCODE:0000000140B69261                 jnb     loc_140B69A27
POOLCODE:0000000140B69267                 mov     rax, [rdi+10h]
POOLCODE:0000000140B6926B
POOLCODE:0000000140B6926B loc_140B6926B:                          ; CO…
POOLCODE:0000000140B6926B                 mov     rcx, rax
POOLCODE:0000000140B6926E                 mov     [rbp+57h+BugCheckPar…
POOLCODE:0000000140B69272                 shr     rcx, 30h
POOLCODE:0000000140B69276                 mov     [rbp+57h+var_C0], ra…
POOLCODE:0000000140B6927A                 cmp     cl, 1
POOLCODE:0000000140B6927D                 jnz     short loc_140B69283
POOLCODE:0000000140B6927F                 mov     byte ptr [rbp+57h+va…
POOLCODE:0000000140B69283
POOLCODE:0000000140B69283 loc_140B69283:                          ; CO…
POOLCODE:0000000140B69283                 test    r14, r14
POOLCODE:0000000140B69286                 jz      short loc_140B692B4
POOLCODE:0000000140B69288                 mov     r8, [rsi+50h]
POOLCODE:0000000140B6928C                 movzx   ecx, word ptr [rbp+5…
POOLCODE:0000000140B69290                 mov     edx, r8d
POOLCODE:0000000140B69293                 mov     [r14], cx
POOLCODE:0000000140B69297                 xor     edx, [r14]
POOLCODE:0000000140B6929A                 movzx   ecx, cl
POOLCODE:0000000140B6929D                 rol     edx, cl
POOLCODE:0000000140B6929F                 lea     ecx, [rbx+1]
POOLCODE:0000000140B692A2                 shr     r8, 20h
POOLCODE:0000000140B692A6                 xor     edx, r8d
POOLCODE:0000000140B692A9                 mov     word ptr [rbp+57h+va…
POOLCODE:0000000140B692AD                 xor     edx, r14d
POOLCODE:0000000140B692B0                 mov     [r14+8], edx
POOLCODE:0000000140B692B4
POOLCODE:0000000140B692B4 loc_140B692B4:                          ; CO…
POOLCODE:0000000140B692B4                 inc     word ptr [rbp+57h+va…
POOLCODE:0000000140B692B8                 movzx   edx, word ptr [rdi+2…
POOLCODE:0000000140B692BC                 mov     rcx, [rbp+57h+var_C0…
POOLCODE:0000000140B692C0                 shl     rdx, 6
POOLCODE:0000000140B692C4                 lock cmpxchg [rdi+10h], rcx
POOLCODE:0000000140B692CA                 jnz     short loc_140B6926B
POOLCODE:0000000140B692CC                 cmp     byte ptr [rdx+rsi+5C…
POOLCODE:0000000140B692D1                 jz      loc_140B69B31
POOLCODE:0000000140B692D7
POOLCODE:0000000140B692D7 loc_140B692D7:                          ; CO…
POOLCODE:0000000140B692D7                                         ; Ex…
POOLCODE:0000000140B692D7                 cmp     byte ptr [rbp+57h+Bu…
POOLCODE:0000000140B692DB                 jnz     loc_140B694D4
POOLCODE:0000000140B692E1                 movzx   r9d, word ptr [rbp+5…
POOLCODE:0000000140B692E6                 shl     r9d, 6
POOLCODE:0000000140B692EA                 add     r9, rsi
POOLCODE:0000000140B692ED                 prefetchw byte ptr [r9+8]
POOLCODE:0000000140B692F2                 mov     rax, [r9+8]
POOLCODE:0000000140B692F6                 mov     r10, [rdi+18h]
POOLCODE:0000000140B692FA                 mov     rdx, rax
POOLCODE:0000000140B692FD                 and     edx, 0FFFh
POOLCODE:0000000140B69303                 mov     r8, r10
POOLCODE:0000000140B69306                 and     r8d, 0FFFh
POOLCODE:0000000140B6930D                 mov     rcx, rax
POOLCODE:0000000140B69310                 sub     rcx, rdx
POOLCODE:0000000140B69313                 or      rcx, r8
POOLCODE:0000000140B69316                 mov     [rdi+18h], rcx
POOLCODE:0000000140B6931A                 mov     rcx, rdi
POOLCODE:0000000140B6931D                 or      rcx, rdx
POOLCODE:0000000140B69320                 lock cmpxchg [r9+8], rcx
POOLCODE:0000000140B69326                 jz      loc_140B694D4
POOLCODE:0000000140B6932C
POOLCODE:0000000140B6932C loc_140B6932C:                          ; CO…
POOLCODE:0000000140B6932C                 mov     rdx, rax
POOLCODE:0000000140B6932F                 mov     rcx, r10
POOLCODE:0000000140B69332                 xor     rcx, rax
POOLCODE:0000000140B69335                 and     edx, 0FFFh
POOLCODE:0000000140B6933B                 and     rcx, 0FFFFFFFFFFFFF0…
POOLCODE:0000000140B69342                 mov     r8, rax
POOLCODE:0000000140B69345                 xor     rcx, r10
POOLCODE:0000000140B69348                 mov     [rdi+18h], rcx
POOLCODE:0000000140B6934C                 or      rdx, rdi
POOLCODE:0000000140B6934F                 lock cmpxchg [r9+8], rdx
POOLCODE:0000000140B69355                 cmp     rax, r8
POOLCODE:0000000140B69358                 jnz     short loc_140B6932C
POOLCODE:0000000140B6935A                 jmp     loc_140B694D4
POOLCODE:0000000140B6935F ; ------------------------------------------…
POOLCODE:0000000140B6935F
POOLCODE:0000000140B6935F loc_140B6935F:                          ; CO…
POOLCODE:0000000140B6935F                 bt      rsi, 8
POOLCODE:0000000140B69364                 jnb     loc_140B699C5
POOLCODE:0000000140B6936A                 mov     r9d, r12d
POOLCODE:0000000140B6936D                 lea     rdx, [r8+20h]
POOLCODE:0000000140B69371                 lea     rax, [r8+30h]
POOLCODE:0000000140B69375                 mov     r10, r12
POOLCODE:0000000140B69378
POOLCODE:0000000140B69378 loc_140B69378:                          ; CO…
POOLCODE:0000000140B69378                 lock inc qword ptr [rax]
POOLCODE:0000000140B6937C                 mov     rbx, [rbp+57h+BugChe…
POOLCODE:0000000140B69380                 mov     rcx, rbx
POOLCODE:0000000140B69383                 neg     rcx
POOLCODE:0000000140B69386                 lock xadd [rdx], rcx
POOLCODE:0000000140B6938B                 cmp     qword ptr [r8+48h], …
POOLCODE:0000000140B69390                 jz      loc_140B6908F
POOLCODE:0000000140B69396                 mov     eax, r9d
POOLCODE:0000000140B69399                 test    byte ptr [r8+rax*8+3…
POOLCODE:0000000140B6939F                 lea     r11, [r8+rax*8]
POOLCODE:0000000140B693A3                 jnz     loc_140B6908F
POOLCODE:0000000140B693A9                 mov     rax, [r11+38h]
POOLCODE:0000000140B693AD                 lea     r9, ds:3Fh[rbx*4]
POOLCODE:0000000140B693B5                 and     r9, 0FFFFFFFFFFFFFFC…
POOLCODE:0000000140B693B9                 mov     ebx, 80h
POOLCODE:0000000140B693BE                 cmp     r9, 40h ; '@'
POOLCODE:0000000140B693C2                 cmovz   r9, rbx
POOLCODE:0000000140B693C6
POOLCODE:0000000140B693C6 loc_140B693C6:                          ; CO…
POOLCODE:0000000140B693C6                 lea     rbx, [r9+rcx]
POOLCODE:0000000140B693CA                 cmp     rcx, rax
POOLCODE:0000000140B693CD                 jge     loc_140B6908F
POOLCODE:0000000140B693D3                 cmp     rbx, rax
POOLCODE:0000000140B693D6                 jge     loc_140B6908F
POOLCODE:0000000140B693DC                 lock cmpxchg [r11+38h], rbx
POOLCODE:0000000140B693E2                 jz      loc_140B6A165
POOLCODE:0000000140B693E8                 mov     rcx, [rdx]
POOLCODE:0000000140B693EB                 jmp     short loc_140B693C6
POOLCODE:0000000140B693ED ; ------------------------------------------…
POOLCODE:0000000140B693ED
POOLCODE:0000000140B693ED loc_140B693ED:                          ; CO…
POOLCODE:0000000140B693ED                                         ; Ex…
POOLCODE:0000000140B693ED                 mov     rdx, [rbx+38h]
POOLCODE:0000000140B693F1                 xor     r9d, r9d
POOLCODE:0000000140B693F4                 mov     [rsp+28h], r12
POOLCODE:0000000140B693F9                 mov     r8, r14
POOLCODE:0000000140B693FC                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69401                 lea     ecx, [r9+9]
POOLCODE:0000000140B69405                 call    RtlpLogHeapFailure
POOLCODE:0000000140B6940A                 jmp     loc_140B694D4
POOLCODE:0000000140B6940F ; ------------------------------------------…
POOLCODE:0000000140B6940F
POOLCODE:0000000140B6940F loc_140B6940F:                          ; CO…
POOLCODE:0000000140B6940F                 test    r10d, r10d
POOLCODE:0000000140B69412                 jz      short loc_140B6942C
POOLCODE:0000000140B69414                 test    r11, r11
POOLCODE:0000000140B69417                 mov     r8d, r12d
POOLCODE:0000000140B6941A                 mov     r9d, 1
POOLCODE:0000000140B69420                 mov     rcx, r13        ; Bu…
POOLCODE:0000000140B69423                 setnz   r8b
POOLCODE:0000000140B69427                 call    ViFreeTrackedPool
POOLCODE:0000000140B6942C
POOLCODE:0000000140B6942C loc_140B6942C:                          ; CO…
POOLCODE:0000000140B6942C                 mov     esi, [rbx+4]
POOLCODE:0000000140B6942F                 mov     eax, cs:PoolHitTag
POOLCODE:0000000140B69435                 mov     [rbp+57h+var_AC], r1…
POOLCODE:0000000140B69439                 mov     byte ptr [rbp+57h+ar…
POOLCODE:0000000140B6943D                 mov     [rbp+57h+arg_18], r1…
POOLCODE:0000000140B69441                 cmp     esi, eax
POOLCODE:0000000140B69443                 jnz     short loc_140B69446
POOLCODE:0000000140B69445                 int     3               ; Tr…
POOLCODE:0000000140B69446
POOLCODE:0000000140B69446 loc_140B69446:                          ; CO…
POOLCODE:0000000140B69446                 mov     eax, dword ptr cs:Pe…
POOLCODE:0000000140B6944C                 test    al, 41h
POOLCODE:0000000140B6944E                 jnz     loc_140B6A0A7
POOLCODE:0000000140B69454
POOLCODE:0000000140B69454 loc_140B69454:                          ; CO…
POOLCODE:0000000140B69454                                         ; Ex…
POOLCODE:0000000140B69454                 mov     eax, gs:1A4h
POOLCODE:0000000140B6945C                 and     rdi, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B69460                 mov     r8, cs:PoolTrackTabl…
POOLCODE:0000000140B69467                 mov     ecx, eax
POOLCODE:0000000140B69469                 lea     rax, cs:140000000h
POOLCODE:0000000140B69470                 mov     r11, rva ExPoolTagTa…
POOLCODE:0000000140B69478                 imul    rcx, rsi, 9E5Fh
POOLCODE:0000000140B6947F                 mov     rdx, rcx
POOLCODE:0000000140B69482                 shr     rdx, 20h
POOLCODE:0000000140B69486                 xor     edx, ecx
POOLCODE:0000000140B69488                 and     edx, r8d
POOLCODE:0000000140B6948B                 mov     r10d, edx
POOLCODE:0000000140B6948E
POOLCODE:0000000140B6948E loc_140B6948E:                          ; CO…
POOLCODE:0000000140B6948E                                         ; Ex…
POOLCODE:0000000140B6948E                 mov     eax, edx
POOLCODE:0000000140B69490                 lea     rcx, [rax+rax*4]
POOLCODE:0000000140B69494                 add     rcx, rcx
POOLCODE:0000000140B69497                 mov     eax, [r11+rcx*8]
POOLCODE:0000000140B6949B                 lea     r9, [r11+rcx*8]
POOLCODE:0000000140B6949F                 cmp     eax, esi
POOLCODE:0000000140B694A1                 jz      loc_140B698B8
POOLCODE:0000000140B694A7                 test    eax, eax
POOLCODE:0000000140B694A9                 jz      loc_140B69AA7
POOLCODE:0000000140B694AF
POOLCODE:0000000140B694AF loc_140B694AF:                          ; CO…
POOLCODE:0000000140B694AF                 lea     eax, [rdx+1]
POOLCODE:0000000140B694B2                 and     eax, r8d
POOLCODE:0000000140B694B5                 mov     edx, eax
POOLCODE:0000000140B694B7                 cmp     eax, r10d
POOLCODE:0000000140B694BA                 jnz     short loc_140B6948E
POOLCODE:0000000140B694BC                 mov     r8, rdi
POOLCODE:0000000140B694BF                 mov     rdx, r14
POOLCODE:0000000140B694C2                 mov     ecx, esi
POOLCODE:0000000140B694C4                 call    ExpRemovePoolTracker…
POOLCODE:0000000140B694C9
POOLCODE:0000000140B694C9 loc_140B694C9:                          ; CO…
POOLCODE:0000000140B694C9                 mov     rdx, rbx
POOLCODE:0000000140B694CC                 mov     rcx, r15
POOLCODE:0000000140B694CF                 call    RtlpHpFreeHeap
POOLCODE:0000000140B694D4
POOLCODE:0000000140B694D4 loc_140B694D4:                          ; CO…
POOLCODE:0000000140B694D4                                         ; Ex…
POOLCODE:0000000140B694D4                 mov     r14, [rsp+0F0h+var_2…
POOLCODE:0000000140B694DC                 mov     rdi, [rsp+0D8h]
POOLCODE:0000000140B694E4                 mov     rbx, [rsp+0F0h+arg_8…
POOLCODE:0000000140B694EC                 mov     r12, [rsp+0F0h+var_2…
POOLCODE:0000000140B694F4                 mov     r15, [rsp+0F0h+var_3…
POOLCODE:0000000140B694FC                 add     rsp, 0E0h
POOLCODE:0000000140B69503                 pop     r13
POOLCODE:0000000140B69505                 pop     rsi
POOLCODE:0000000140B69506                 pop     rbp
POOLCODE:0000000140B69507                 retn
POOLCODE:0000000140B69507 ; ------------------------------------------…
POOLCODE:0000000140B69508 byte_140B69508  db 0CCh                 ; DA…
POOLCODE:0000000140B69508                                         ; .p…
POOLCODE:0000000140B69509 ; ------------------------------------------…
POOLCODE:0000000140B69509
POOLCODE:0000000140B69509 loc_140B69509:                          ; CO…
POOLCODE:0000000140B69509                                         ; DA…
POOLCODE:0000000140B69509                 or      rdx, 1
POOLCODE:0000000140B6950D                 mov     [rbp+57h+var_C0], rd…
POOLCODE:0000000140B69511                 jmp     loc_140B68E69
POOLCODE:0000000140B69516 ; ------------------------------------------…
POOLCODE:0000000140B69516
POOLCODE:0000000140B69516 loc_140B69516:                          ; CO…
POOLCODE:0000000140B69516                 mov     r9d, r12d
POOLCODE:0000000140B69519                 lea     rdx, [r8+20h]
POOLCODE:0000000140B6951D                 lea     rax, [r8+30h]
POOLCODE:0000000140B69521                 jmp     loc_140B69068
POOLCODE:0000000140B69526 ; ------------------------------------------…
POOLCODE:0000000140B69526
POOLCODE:0000000140B69526 loc_140B69526:                          ; CO…
POOLCODE:0000000140B69526                 mov     rcx, r14
POOLCODE:0000000140B69529                 test    al, 4
POOLCODE:0000000140B6952B                 jz      short loc_140B6953F
POOLCODE:0000000140B6952D                 movzx   eax, word ptr [r14]
POOLCODE:0000000140B69531                 and     ax, r8w
POOLCODE:0000000140B69535                 movzx   eax, ax
POOLCODE:0000000140B69538                 shl     rax, 4
POOLCODE:0000000140B6953C                 sub     rcx, rax
POOLCODE:0000000140B6953F
POOLCODE:0000000140B6953F loc_140B6953F:                          ; CO…
POOLCODE:0000000140B6953F                 xor     rcx, [rcx+8]
POOLCODE:0000000140B69543                 xor     rcx, cs:ExpPoolQuota…
POOLCODE:0000000140B6954A                 jz      loc_140B68E0C
POOLCODE:0000000140B69550                 cmp     rcx, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B69554                 jz      loc_140B68E0C
POOLCODE:0000000140B6955A                 mov     eax, cs:ExpSpecialAl…
POOLCODE:0000000140B69560                 test    eax, eax
POOLCODE:0000000140B69562                 jnz     loc_140B6A0F6
POOLCODE:0000000140B69568
POOLCODE:0000000140B69568 loc_140B69568:                          ; CO…
POOLCODE:0000000140B69568                 mov     rax, r13
POOLCODE:0000000140B6956B                 shr     rax, 27h
POOLCODE:0000000140B6956F                 and     eax, 1FFh
POOLCODE:0000000140B69574                 add     eax, 0FFFFFF00h
POOLCODE:0000000140B69579                 movzx   eax, byte ptr [rax+r…
POOLCODE:0000000140B69581                 cmp     al, 5
POOLCODE:0000000140B69583                 jz      loc_140B6A3B8
POOLCODE:0000000140B69589
POOLCODE:0000000140B69589 loc_140B69589:                          ; CO…
POOLCODE:0000000140B69589                 mov     esi, 40h ; '@'
POOLCODE:0000000140B6958E
POOLCODE:0000000140B6958E loc_140B6958E:                          ; CO…
POOLCODE:0000000140B6958E                 test    byte ptr [r14+3], 4
POOLCODE:0000000140B69593                 mov     rdx, r14
POOLCODE:0000000140B69596                 jz      short loc_140B695AD
POOLCODE:0000000140B69598                 movzx   eax, word ptr [r14]
POOLCODE:0000000140B6959C                 and     ax, r8w
POOLCODE:0000000140B695A0                 movzx   ecx, ax
POOLCODE:0000000140B695A3                 neg     rcx
POOLCODE:0000000140B695A6                 shl     rcx, 4
POOLCODE:0000000140B695AA                 add     rdx, rcx
POOLCODE:0000000140B695AD
POOLCODE:0000000140B695AD loc_140B695AD:                          ; CO…
POOLCODE:0000000140B695AD                 movzx   eax, word ptr [rdx+2…
POOLCODE:0000000140B695B1                 mov     r14d, [rdx+4]
POOLCODE:0000000140B695B5                 movzx   ebx, al
POOLCODE:0000000140B695B8                 shl     rbx, 4
POOLCODE:0000000140B695BC                 shr     ax, 8
POOLCODE:0000000140B695C0                 test    al, 8
POOLCODE:0000000140B695C2                 jz      loc_140B69729
POOLCODE:0000000140B695C8                 mov     rdi, rdx
POOLCODE:0000000140B695CB                 mov     rax, rdx
POOLCODE:0000000140B695CE                 xor     rdi, [rdx+8]
POOLCODE:0000000140B695D2                 xor     rax, cs:ExpPoolQuota…
POOLCODE:0000000140B695D9                 mov     [rdx+8], rax
POOLCODE:0000000140B695DD                 xor     rdi, cs:ExpPoolQuota…
POOLCODE:0000000140B695E4                 jz      loc_140B69724
POOLCODE:0000000140B695EA                 cmp     rdi, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B695EE                 jz      loc_140B69724
POOLCODE:0000000140B695F4                 mov     rax, 0FFFF8000000000…
POOLCODE:0000000140B695FE                 cmp     rdi, rax
POOLCODE:0000000140B69601                 jb      loc_140B69FCF
POOLCODE:0000000140B69607                 movzx   eax, byte ptr [rdi]
POOLCODE:0000000140B6960A                 and     al, 7Fh
POOLCODE:0000000140B6960C                 cmp     al, 3
POOLCODE:0000000140B6960E                 jnz     loc_140B69FCF
POOLCODE:0000000140B69614                 and     esi, 100h
POOLCODE:0000000140B6961A                 cmp     rdi, cs:PsInitialSys…
POOLCODE:0000000140B69621                 jz      loc_140B696F2
POOLCODE:0000000140B69627                 mov     rcx, [rdi+2F8h]
POOLCODE:0000000140B6962E                 lea     rdx, cs:140000000h
POOLCODE:0000000140B69635                 mov     eax, r12d
POOLCODE:0000000140B69638                 mov     [rbp+57h+var_C0], rc…
POOLCODE:0000000140B6963C                 test    rsi, rsi
POOLCODE:0000000140B6963F                 setnz   al
POOLCODE:0000000140B69642                 mov     r15d, eax
POOLCODE:0000000140B69645                 mov     eax, eax
POOLCODE:0000000140B69647                 shl     rax, 7
POOLCODE:0000000140B6964B                 mov     [rbp+57h+var_98], ra…
POOLCODE:0000000140B6964F                 movzx   r13d, ds:rva PspReso…
POOLCODE:0000000140B69658                 lea     r12, [rax+rcx]
POOLCODE:0000000140B6965C                 prefetchw byte ptr [r12]
POOLCODE:0000000140B69661                 mov     rsi, [r12]
POOLCODE:0000000140B69665                 mov     rax, [r12+40h]
POOLCODE:0000000140B6966A                 cmp     qword ptr [r12+50h],…
POOLCODE:0000000140B69670                 jz      short loc_140B69697
POOLCODE:0000000140B69672                 imul    rcx, r15, 38h ; '8'
POOLCODE:0000000140B69676                 cmp     rax, rsi
POOLCODE:0000000140B69679                 jbe     short loc_140B69697
POOLCODE:0000000140B6967B                 lea     r8, rva qword_140F05…
POOLCODE:0000000140B69682                 add     r8, rcx
POOLCODE:0000000140B69685                 mov     rcx, rax
POOLCODE:0000000140B69688                 sub     rcx, rsi
POOLCODE:0000000140B6968B                 mov     rdx, [r8]
POOLCODE:0000000140B6968E                 cmp     rcx, rdx
POOLCODE:0000000140B69691                 ja      loc_140B69B68
POOLCODE:0000000140B69697
POOLCODE:0000000140B69697 loc_140B69697:                          ; CO…
POOLCODE:0000000140B69697                                         ; Ex…
POOLCODE:0000000140B69697                 mov     r11, [rbp+57h+var_98…
POOLCODE:0000000140B6969B                 lea     r10, PspSystemQuotaB…
POOLCODE:0000000140B696A2                 mov     r8, rbx
POOLCODE:0000000140B696A5
POOLCODE:0000000140B696A5 loc_140B696A5:                          ; CO…
POOLCODE:0000000140B696A5                                         ; Ex…
POOLCODE:0000000140B696A5                 cmp     rbx, rsi
POOLCODE:0000000140B696A8                 mov     r9, rsi
POOLCODE:0000000140B696AB                 mov     rcx, rsi
POOLCODE:0000000140B696AE                 mov     rax, rsi
POOLCODE:0000000140B696B1                 cmovb   r9, rbx
POOLCODE:0000000140B696B5                 sub     rcx, rbx
POOLCODE:0000000140B696B8                 xor     edx, edx
POOLCODE:0000000140B696BA                 cmp     rbx, rsi
POOLCODE:0000000140B696BD                 cmovb   rdx, rcx
POOLCODE:0000000140B696C1                 lock cmpxchg [r12], rdx
POOLCODE:0000000140B696C7                 mov     rsi, rax
POOLCODE:0000000140B696CA                 jnz     short loc_140B696A5
POOLCODE:0000000140B696CC                 sub     rbx, r9
POOLCODE:0000000140B696CF                 jnz     loc_140B69D84
POOLCODE:0000000140B696D5                 test    r13b, 4
POOLCODE:0000000140B696D9                 jz      short loc_140B696E7
POOLCODE:0000000140B696DB                 neg     r8
POOLCODE:0000000140B696DE                 lock add [rdi+r15*8+200h], r…
POOLCODE:0000000140B696E7
POOLCODE:0000000140B696E7 loc_140B696E7:                          ; CO…
POOLCODE:0000000140B696E7                 mov     r13, [rbp+57h+arg_0]
POOLCODE:0000000140B696EB                 xor     r12d, r12d
POOLCODE:0000000140B696EE                 mov     r15, [rbp+57h+arg_10…
POOLCODE:0000000140B696F2
POOLCODE:0000000140B696F2 loc_140B696F2:                          ; CO…
POOLCODE:0000000140B696F2                 cmp     cs:ObpTraceFlags, 0
POOLCODE:0000000140B696F9                 jz      short loc_140B6970D
POOLCODE:0000000140B696FB                 xor     edx, edx
POOLCODE:0000000140B696FD                 lea     rcx, [rdi-30h]
POOLCODE:0000000140B69701                 mov     r9d, r14d
POOLCODE:0000000140B69704                 lea     r8d, [rdx+1]
POOLCODE:0000000140B69708                 call    ObpPushStackInfo
POOLCODE:0000000140B6970D
POOLCODE:0000000140B6970D loc_140B6970D:                          ; CO…
POOLCODE:0000000140B6970D                 mov     rsi, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B69714                 lock xadd [rdi-30h], rsi
POOLCODE:0000000140B6971A                 sub     rsi, 1
POOLCODE:0000000140B6971E                 jle     loc_140B69ECC
POOLCODE:0000000140B69724
POOLCODE:0000000140B69724 loc_140B69724:                          ; CO…
POOLCODE:0000000140B69724                                         ; Ex…
POOLCODE:0000000140B69724                 mov     edi, 80h
POOLCODE:0000000140B69729
POOLCODE:0000000140B69729 loc_140B69729:                          ; CO…
POOLCODE:0000000140B69729                 mov     edx, 100h
POOLCODE:0000000140B6972E                 lea     r14, [r13-10h]
POOLCODE:0000000140B69732                 jmp     loc_140B68E0C
POOLCODE:0000000140B69737 ; ------------------------------------------…
POOLCODE:0000000140B69737
POOLCODE:0000000140B69737 loc_140B69737:                          ; CO…
POOLCODE:0000000140B69737                 mov     rcx, r13
POOLCODE:0000000140B6973A                 lea     rax, cs:140000000h
POOLCODE:0000000140B69741                 shr     rcx, 27h
POOLCODE:0000000140B69745                 mov     edi, 100h
POOLCODE:0000000140B6974A                 and     ecx, 1FFh
POOLCODE:0000000140B69750                 mov     esi, 40h ; '@'
POOLCODE:0000000140B69755                 add     ecx, 0FFFFFF00h
POOLCODE:0000000140B6975B                 movzx   eax, byte ptr [rcx+r…
POOLCODE:0000000140B69763                 cmp     al, 4
POOLCODE:0000000140B69765                 jz      short loc_140B6976C
POOLCODE:0000000140B69767                 cmp     al, 5
POOLCODE:0000000140B69769                 cmovz   esi, edi
POOLCODE:0000000140B6976C
POOLCODE:0000000140B6976C loc_140B6976C:                          ; CO…
POOLCODE:0000000140B6976C                 mov     r14, cr8
POOLCODE:0000000140B69770                 mov     cr8, rdx
POOLCODE:0000000140B69774                 cmp     cs:KiIrqlFlags, r12d
POOLCODE:0000000140B6977B                 jnz     loc_140B69BBC
POOLCODE:0000000140B69781
POOLCODE:0000000140B69781 loc_140B69781:                          ; CO…
POOLCODE:0000000140B69781                 test    byte ptr cs:PerfGlob…
POOLCODE:0000000140B69788                 jz      loc_140B699DC
POOLCODE:0000000140B6978E                 mov     eax, cs:PopHibernate…
POOLCODE:0000000140B69794                 test    eax, eax
POOLCODE:0000000140B69796                 jnz     loc_140B699DC
POOLCODE:0000000140B6979C                 movzx   edx, r14b
POOLCODE:0000000140B697A0                 lea     rcx, ExpLargePoolTab…
POOLCODE:0000000140B697A7                 call    ExpAcquireSpinLockSh…
POOLCODE:0000000140B697AC
POOLCODE:0000000140B697AC loc_140B697AC:                          ; CO…
POOLCODE:0000000140B697AC                                         ; Ex…
POOLCODE:0000000140B697AC                 mov     r8, cs:PoolBigPageTa…
POOLCODE:0000000140B697B3                 mov     rax, r13
POOLCODE:0000000140B697B6                 mov     r9, cs:PoolBigPageTa…
POOLCODE:0000000140B697BD                 mov     r10d, 1
POOLCODE:0000000140B697C3                 shr     rax, 0Ch
POOLCODE:0000000140B697C7                 imul    rcx, rax, 9E5Fh
POOLCODE:0000000140B697CE                 lea     edx, [r8-1]
POOLCODE:0000000140B697D2                 mov     rax, rcx
POOLCODE:0000000140B697D5                 shr     rax, 20h
POOLCODE:0000000140B697D9                 xor     rcx, rax
POOLCODE:0000000140B697DC                 and     edx, ecx
POOLCODE:0000000140B697DE
POOLCODE:0000000140B697DE loc_140B697DE:                          ; CO…
POOLCODE:0000000140B697DE                                         ; Ex…
POOLCODE:0000000140B697DE                 mov     ecx, edx
POOLCODE:0000000140B697E0                 shl     rcx, 5
POOLCODE:0000000140B697E4                 add     rcx, r9
POOLCODE:0000000140B697E7                 mov     rax, [rcx]
POOLCODE:0000000140B697EA                 cmp     rax, r13
POOLCODE:0000000140B697ED                 jz      short loc_140B6981A
POOLCODE:0000000140B697EF                 inc     edx
POOLCODE:0000000140B697F1                 mov     eax, edx
POOLCODE:0000000140B697F3                 cmp     rax, r8
POOLCODE:0000000140B697F6                 jb      short loc_140B697DE
POOLCODE:0000000140B697F8                 test    r10d, r10d
POOLCODE:0000000140B697FB                 jnz     loc_140B6A09C
POOLCODE:0000000140B69801
POOLCODE:0000000140B69801 loc_140B69801:                          ; CO…
POOLCODE:0000000140B69801                 mov     edx, 22h ; '"'  ; Bu…
POOLCODE:0000000140B69806                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6980B                 mov     r9, rsi         ; Bu…
POOLCODE:0000000140B6980E                 mov     r8, r13         ; Bu…
POOLCODE:0000000140B69811                 lea     ecx, [rdx-9]    ; Bu…
POOLCODE:0000000140B69814                 call    KeBugCheckEx
POOLCODE:0000000140B69814 ; ------------------------------------------…
POOLCODE:0000000140B69819                 align 2
POOLCODE:0000000140B6981A
POOLCODE:0000000140B6981A loc_140B6981A:                          ; CO…
POOLCODE:0000000140B6981A                 test    rcx, rcx
POOLCODE:0000000140B6981D                 jz      short loc_140B69801
POOLCODE:0000000140B6981F                 mov     eax, [rcx+0Ch]
POOLCODE:0000000140B69822                 mov     rsi, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B69829                 mov     ebx, [rcx+8]
POOLCODE:0000000140B6982C                 mov     edx, eax
POOLCODE:0000000140B6982E                 shr     rdx, 8
POOLCODE:0000000140B69832                 and     edx, 0FFFh
POOLCODE:0000000140B69838                 mov     [rbp+57h+var_C0], rd…
POOLCODE:0000000140B6983C                 mov     rdx, [rcx+10h]
POOLCODE:0000000140B69840                 mov     [rbp+57h+BugCheckPar…
POOLCODE:0000000140B69844                 test    edi, eax
POOLCODE:0000000140B69846                 jnz     loc_140B69A49
POOLCODE:0000000140B6984C                 mov     rdi, rsi
POOLCODE:0000000140B6984F
POOLCODE:0000000140B6984F loc_140B6984F:                          ; CO…
POOLCODE:0000000140B6984F                 lock dec cs:ExpPoolBigEntrie…
POOLCODE:0000000140B69856                 mov     [rcx+18h], r12
POOLCODE:0000000140B6985A                 lock inc qword ptr [rcx]
POOLCODE:0000000140B6985E                 test    byte ptr cs:PerfGlob…
POOLCODE:0000000140B69865                 jnz     loc_140B69EA9
POOLCODE:0000000140B6986B
POOLCODE:0000000140B6986B loc_140B6986B:                          ; CO…
POOLCODE:0000000140B6986B                 lock and cs:ExpLargePoolTabl…
POOLCODE:0000000140B69876                 lock dec cs:ExpLargePoolTabl…
POOLCODE:0000000140B6987D
POOLCODE:0000000140B6987D loc_140B6987D:                          ; CO…
POOLCODE:0000000140B6987D                 cmp     cs:KiIrqlFlags, r12d
POOLCODE:0000000140B69884                 jz      short loc_140B69893
POOLCODE:0000000140B69886                 mov     rcx, cr8
POOLCODE:0000000140B6988A                 movzx   edx, r14b
POOLCODE:0000000140B6988E                 call    KiLowerIrqlProcessIr…
POOLCODE:0000000140B69893
POOLCODE:0000000140B69893 loc_140B69893:                          ; CO…
POOLCODE:0000000140B69893                 movzx   eax, r14b
POOLCODE:0000000140B69897                 mov     cr8, rax
POOLCODE:0000000140B6989B                 lea     rax, [rdi-1]
POOLCODE:0000000140B6989F                 cmp     rax, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B698A3                 jbe     loc_140B69BE1
POOLCODE:0000000140B698A9
POOLCODE:0000000140B698A9 loc_140B698A9:                          ; CO…
POOLCODE:0000000140B698A9                                         ; Ex…
POOLCODE:0000000140B698A9                 mov     rdx, [rbp+57h+BugChe…
POOLCODE:0000000140B698AD                 mov     r14, r13
POOLCODE:0000000140B698B0                 mov     rdi, r13
POOLCODE:0000000140B698B3                 jmp     loc_140B68ED0
POOLCODE:0000000140B698B8 ; ------------------------------------------…
POOLCODE:0000000140B698B8
POOLCODE:0000000140B698B8 loc_140B698B8:                          ; CO…
POOLCODE:0000000140B698B8                 shr     rdi, 8
POOLCODE:0000000140B698BC                 mov     r8, r9
POOLCODE:0000000140B698BF                 not     edi
POOLCODE:0000000140B698C1                 mov     rdx, r14
POOLCODE:0000000140B698C4                 and     edi, 1
POOLCODE:0000000140B698C7                 mov     ecx, edi
POOLCODE:0000000140B698C9                 call    ExpPoolTrackerReturn…
POOLCODE:0000000140B698CE                 jmp     loc_140B694C9
POOLCODE:0000000140B698D3 ; ------------------------------------------…
POOLCODE:0000000140B698D3
POOLCODE:0000000140B698D3 loc_140B698D3:                          ; CO…
POOLCODE:0000000140B698D3                 mov     eax, cs:PopHibernate…
POOLCODE:0000000140B698D9                 test    eax, eax
POOLCODE:0000000140B698DB                 jnz     loc_140B68FD1
POOLCODE:0000000140B698E1                 mov     rdx, rcx
POOLCODE:0000000140B698E4                 lea     rcx, [rbp+57h+LockHa…
POOLCODE:0000000140B698E8                 call    KiAcquireQueuedSpinL…
POOLCODE:0000000140B698ED                 jmp     loc_140B68FE5
POOLCODE:0000000140B698F2 ; ------------------------------------------…
POOLCODE:0000000140B698F2
POOLCODE:0000000140B698F2 loc_140B698F2:                          ; CO…
POOLCODE:0000000140B698F2                 mov     rax, r8
POOLCODE:0000000140B698F5                 mov     [rbp+57h+var_A4], r1…
POOLCODE:0000000140B698F9                 and     rax, r9
POOLCODE:0000000140B698FC                 mov     rdx, r8
POOLCODE:0000000140B698FF                 sub     rdx, rax
POOLCODE:0000000140B69902                 mov     ecx, r10d
POOLCODE:0000000140B69905                 sar     rdx, 5
POOLCODE:0000000140B69909                 shl     rdx, cl
POOLCODE:0000000140B6990C                 add     rdx, rax
POOLCODE:0000000140B6990F                 movzx   eax, r11b
POOLCODE:0000000140B69913                 and     al, 3
POOLCODE:0000000140B69915                 cmp     al, 3
POOLCODE:0000000140B69917                 jnz     loc_140B693ED
POOLCODE:0000000140B6991D                 cmp     r14, rdx
POOLCODE:0000000140B69920                 jz      loc_140B69A17
POOLCODE:0000000140B69926                 cmp     r11b, 0Fh
POOLCODE:0000000140B6992A                 jnz     loc_140B693ED
POOLCODE:0000000140B69930                 cmp     r14, rdx
POOLCODE:0000000140B69933                 jbe     loc_140B69A17
POOLCODE:0000000140B69939                 mov     rcx, [rbx+20h]
POOLCODE:0000000140B6993D                 lea     r9, [rbp+57h+var_A4]
POOLCODE:0000000140B69941                 mov     r8, r14
POOLCODE:0000000140B69944                 call    RtlpHpVsContextFree
POOLCODE:0000000140B69949                 test    eax, eax
POOLCODE:0000000140B6994B                 jz      loc_140B694D4
POOLCODE:0000000140B69951                 mov     r8, [rbx+18h]
POOLCODE:0000000140B69955                 mov     ecx, [rbp+57h+var_A4…
POOLCODE:0000000140B69958                 movzx   eax, word ptr [r8+44…
POOLCODE:0000000140B6995D                 cmp     ecx, eax
POOLCODE:0000000140B6995F                 jnb     loc_140B694D4
POOLCODE:0000000140B69965                 add     ecx, 0Fh
POOLCODE:0000000140B69968                 shr     rcx, 4
POOLCODE:0000000140B6996C                 movzx   r9d, byte ptr [rcx+r…
POOLCODE:0000000140B69975                 dec     r9d
POOLCODE:0000000140B69978                 lea     r10, [r8+r9*8]
POOLCODE:0000000140B6997C
POOLCODE:0000000140B6997C loc_140B6997C:                          ; CO…
POOLCODE:0000000140B6997C                 mov     rcx, [r10+1C0h]
POOLCODE:0000000140B69983                 mov     rax, rcx
POOLCODE:0000000140B69986                 mov     [rbp+57h+var_C0], rc…
POOLCODE:0000000140B6998A                 shr     rax, 10h
POOLCODE:0000000140B6998E                 mov     rdx, rcx
POOLCODE:0000000140B69991                 test    cl, 1
POOLCODE:0000000140B69994                 jz      short loc_140B699B8
POOLCODE:0000000140B69996                 cmp     ax, 1
POOLCODE:0000000140B6999A                 jbe     short loc_140B699A7
POOLCODE:0000000140B6999C                 dec     ax
POOLCODE:0000000140B6999F                 mov     word ptr [rbp+57h+va…
POOLCODE:0000000140B699A3                 mov     rdx, [rbp+57h+var_C0…
POOLCODE:0000000140B699A7
POOLCODE:0000000140B699A7 loc_140B699A7:                          ; CO…
POOLCODE:0000000140B699A7                 mov     rax, rcx
POOLCODE:0000000140B699AA                 lock cmpxchg [r10+1C0h], rdx
POOLCODE:0000000140B699B3                 cmp     rax, rcx
POOLCODE:0000000140B699B6                 jnz     short loc_140B6997C
POOLCODE:0000000140B699B8
POOLCODE:0000000140B699B8 loc_140B699B8:                          ; CO…
POOLCODE:0000000140B699B8                 mov     rcx, [r8+r9*8+1C0h]
POOLCODE:0000000140B699C0                 jmp     loc_140B694D4
POOLCODE:0000000140B699C5 ; ------------------------------------------…
POOLCODE:0000000140B699C5
POOLCODE:0000000140B699C5 loc_140B699C5:                          ; CO…
POOLCODE:0000000140B699C5                 mov     r9d, 1
POOLCODE:0000000140B699CB                 lea     rdx, [r8+8]
POOLCODE:0000000140B699CF                 lea     rax, [r8+18h]
POOLCODE:0000000140B699D3                 lea     r10d, [r9+17h]
POOLCODE:0000000140B699D7                 jmp     loc_140B69378
POOLCODE:0000000140B699DC ; ------------------------------------------…
POOLCODE:0000000140B699DC
POOLCODE:0000000140B699DC loc_140B699DC:                          ; CO…
POOLCODE:0000000140B699DC                                         ; Ex…
POOLCODE:0000000140B699DC                 prefetchw byte ptr cs:ExpLar…
POOLCODE:0000000140B699E3                 mov     eax, cs:ExpLargePool…
POOLCODE:0000000140B699E9                 btr     eax, 1Fh
POOLCODE:0000000140B699ED
POOLCODE:0000000140B699ED loc_140B699ED:                          ; CO…
POOLCODE:0000000140B699ED                 lea     ecx, [rax+1]
POOLCODE:0000000140B699F0                 lock cmpxchg cs:ExpLargePool…
POOLCODE:0000000140B699F8                 jz      loc_140B697AC
POOLCODE:0000000140B699FE                 test    eax, eax
POOLCODE:0000000140B69A00                 jns     short loc_140B699ED
POOLCODE:0000000140B69A02                 movzx   edx, r14b
POOLCODE:0000000140B69A06                 lea     rcx, ExpLargePoolTab…
POOLCODE:0000000140B69A0D                 call    ExpWaitForSpinLockSh…
POOLCODE:0000000140B69A12                 jmp     loc_140B697AC
POOLCODE:0000000140B69A17 ; ------------------------------------------…
POOLCODE:0000000140B69A17
POOLCODE:0000000140B69A17 loc_140B69A17:                          ; CO…
POOLCODE:0000000140B69A17                                         ; Ex…
POOLCODE:0000000140B69A17                 mov     rdx, r8
POOLCODE:0000000140B69A1A                 mov     rcx, rbx
POOLCODE:0000000140B69A1D                 call    RtlpHpSegPageRangeSh…
POOLCODE:0000000140B69A22                 jmp     loc_140B694D4
POOLCODE:0000000140B69A27 ; ------------------------------------------…
POOLCODE:0000000140B69A27
POOLCODE:0000000140B69A27 loc_140B69A27:                          ; CO…
POOLCODE:0000000140B69A27                                         ; Ex…
POOLCODE:0000000140B69A27                 mov     rdx, [rsi]
POOLCODE:0000000140B69A2A                 mov     r8, r14
POOLCODE:0000000140B69A2D                 mov     [rsp+28h], r12
POOLCODE:0000000140B69A32                 mov     ecx, 11h
POOLCODE:0000000140B69A37                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69A3C                 mov     r9, rdi
POOLCODE:0000000140B69A3F                 call    RtlpLogHeapFailure
POOLCODE:0000000140B69A44                 jmp     loc_140B694D4
POOLCODE:0000000140B69A49 ; ------------------------------------------…
POOLCODE:0000000140B69A49
POOLCODE:0000000140B69A49 loc_140B69A49:                          ; CO…
POOLCODE:0000000140B69A49                 mov     rdi, [rcx+18h]
POOLCODE:0000000140B69A4D                 xor     rdi, cs:ExpPoolQuota…
POOLCODE:0000000140B69A54                 xor     rdi, r13
POOLCODE:0000000140B69A57                 jmp     loc_140B6984F
POOLCODE:0000000140B69A5C ; ------------------------------------------…
POOLCODE:0000000140B69A5C
POOLCODE:0000000140B69A5C loc_140B69A5C:                          ; CO…
POOLCODE:0000000140B69A5C                 mov     rax, cs:PoolTrackTab…
POOLCODE:0000000140B69A63                 mov     eax, [rax+rcx*8]
POOLCODE:0000000140B69A66                 test    eax, eax
POOLCODE:0000000140B69A68                 jz      loc_140B68F7C
POOLCODE:0000000140B69A6E                 mov     [r8], eax
POOLCODE:0000000140B69A71                 mov     rax, cs:PoolTrackTab…
POOLCODE:0000000140B69A78                 mov     rax, [rax+rcx*8+48h]
POOLCODE:0000000140B69A7D                 test    rax, rax
POOLCODE:0000000140B69A80                 jz      loc_140B68F5B
POOLCODE:0000000140B69A86                 mov     [r8+48h], rax
POOLCODE:0000000140B69A8A                 jmp     loc_140B68F5B
POOLCODE:0000000140B69A8F ; ------------------------------------------…
POOLCODE:0000000140B69A8F
POOLCODE:0000000140B69A8F loc_140B69A8F:                          ; CO…
POOLCODE:0000000140B69A8F                 movzx   edx, al
POOLCODE:0000000140B69A92                 movzx   ecx, dil
POOLCODE:0000000140B69A96                 call    KiRaiseIrqlProcessIr…
POOLCODE:0000000140B69A9B                 lea     rcx, ExpTaggedPoolLo…
POOLCODE:0000000140B69AA2                 jmp     loc_140B68FC0
POOLCODE:0000000140B69AA7 ; ------------------------------------------…
POOLCODE:0000000140B69AA7
POOLCODE:0000000140B69AA7 loc_140B69AA7:                          ; CO…
POOLCODE:0000000140B69AA7                 mov     rax, cs:PoolTrackTab…
POOLCODE:0000000140B69AAE                 mov     eax, [rax+rcx*8]
POOLCODE:0000000140B69AB1                 test    eax, eax
POOLCODE:0000000140B69AB3                 jz      loc_140B694AF
POOLCODE:0000000140B69AB9                 mov     [r9], eax
POOLCODE:0000000140B69ABC                 mov     rax, cs:PoolTrackTab…
POOLCODE:0000000140B69AC3                 mov     rax, [rax+rcx*8+48h]
POOLCODE:0000000140B69AC8                 test    rax, rax
POOLCODE:0000000140B69ACB                 jz      loc_140B6948E
POOLCODE:0000000140B69AD1                 mov     [r9+48h], rax
POOLCODE:0000000140B69AD5                 jmp     loc_140B6948E
POOLCODE:0000000140B69ADA ; ------------------------------------------…
POOLCODE:0000000140B69ADA
POOLCODE:0000000140B69ADA loc_140B69ADA:                          ; CO…
POOLCODE:0000000140B69ADA                                         ; DA…
POOLCODE:0000000140B69ADA                 mov     rdx, r13
POOLCODE:0000000140B69ADD                 lea     rcx, dword_140E681D0
POOLCODE:0000000140B69AE4                 sub     rdx, cs:qword_140E68…
POOLCODE:0000000140B69AEB                 shr     rdx, 14h
POOLCODE:0000000140B69AEF                 add     rdx, rdx
POOLCODE:0000000140B69AF2                 call    RtlCSparseBitmapBitm…
POOLCODE:0000000140B69AF7                 test    rax, rax
POOLCODE:0000000140B69AFA                 jz      short loc_140B69B07
POOLCODE:0000000140B69AFC                 dec     eax
POOLCODE:0000000140B69AFE                 cmp     eax, 2
POOLCODE:0000000140B69B01                 jnz     loc_140B68D37
POOLCODE:0000000140B69B07
POOLCODE:0000000140B69B07 loc_140B69B07:                          ; CO…
POOLCODE:0000000140B69B07                 xorps   xmm0, xmm0
POOLCODE:0000000140B69B0A                 lea     r8, [rbp+57h+var_58]
POOLCODE:0000000140B69B0E                 mov     rdx, r13
POOLCODE:0000000140B69B11                 lea     rcx, unk_140E68218
POOLCODE:0000000140B69B18                 movups  [rbp+57h+var_58], xm…
POOLCODE:0000000140B69B1C                 movups  [rbp+57h+var_48], xm…
POOLCODE:0000000140B69B20                 call    RtlpHpVaMgrCtxQuery
POOLCODE:0000000140B69B25                 mov     rax, qword ptr [rbp+…
POOLCODE:0000000140B69B29                 mov     r15, [rax]
POOLCODE:0000000140B69B2C                 jmp     loc_140B68D72
POOLCODE:0000000140B69B31 ; ------------------------------------------…
POOLCODE:0000000140B69B31
POOLCODE:0000000140B69B31 loc_140B69B31:                          ; CO…
POOLCODE:0000000140B69B31                                         ; DA…
POOLCODE:0000000140B69B31                 mov     byte ptr [rdx+rsi+5C…
POOLCODE:0000000140B69B36                 mov     rcx, [rsi]
POOLCODE:0000000140B69B39                 mov     rax, [rcx+38h]
POOLCODE:0000000140B69B3D                 mov     rax, [rax]
POOLCODE:0000000140B69B40                 shr     rax, 8
POOLCODE:0000000140B69B44                 cmp     al, 1
POOLCODE:0000000140B69B46                 jnz     loc_140B69D16
POOLCODE:0000000140B69B4C                 mov     eax, cs:ExpHpGCSched…
POOLCODE:0000000140B69B52
POOLCODE:0000000140B69B52 loc_140B69B52:                          ; CO…
POOLCODE:0000000140B69B52                 test    eax, eax
POOLCODE:0000000140B69B54                 jnz     loc_140B692D7
POOLCODE:0000000140B69B5A                 mov     rcx, [rcx+38h]
POOLCODE:0000000140B69B5E                 call    RtlpHpEnvCompactionS…
POOLCODE:0000000140B69B63                 jmp     loc_140B692D7
POOLCODE:0000000140B69B68 ; ------------------------------------------…
POOLCODE:0000000140B69B68
POOLCODE:0000000140B69B68 loc_140B69B68:                          ; CO…
POOLCODE:0000000140B69B68                 cmp     rdx, rbx
POOLCODE:0000000140B69B6B                 mov     rcx, rax
POOLCODE:0000000140B69B6E                 cmova   rdx, rbx
POOLCODE:0000000140B69B72                 sub     rcx, rdx
POOLCODE:0000000140B69B75                 lock cmpxchg [r12+40h], rcx
POOLCODE:0000000140B69B7C                 jnz     loc_140B69697
POOLCODE:0000000140B69B82                 mov     rax, rdx
POOLCODE:0000000140B69B85                 lock xadd [r12+48h], rax
POOLCODE:0000000140B69B8C                 add     rdx, rax
POOLCODE:0000000140B69B8F                 cmp     rdx, [r8]
POOLCODE:0000000140B69B92                 jbe     loc_140B69697
POOLCODE:0000000140B69B98                 xor     r8d, r8d
POOLCODE:0000000140B69B9B                 xchg    r8, [r12+48h]
POOLCODE:0000000140B69BA0                 test    r8, r8
POOLCODE:0000000140B69BA3                 jz      loc_140B69697
POOLCODE:0000000140B69BA9                 xor     r9d, r9d
POOLCODE:0000000140B69BAC                 mov     rdx, r12
POOLCODE:0000000140B69BAF                 mov     ecx, r15d
POOLCODE:0000000140B69BB2                 call    PspReturnResourceQuo…
POOLCODE:0000000140B69BB7                 jmp     loc_140B69697
POOLCODE:0000000140B69BBC ; ------------------------------------------…
POOLCODE:0000000140B69BBC
POOLCODE:0000000140B69BBC loc_140B69BBC:                          ; CO…
POOLCODE:0000000140B69BBC                 movzx   ecx, r14b
POOLCODE:0000000140B69BC0                 call    KiRaiseIrqlProcessIr…
POOLCODE:0000000140B69BC5                 jmp     loc_140B69781
POOLCODE:0000000140B69BCA ; ------------------------------------------…
POOLCODE:0000000140B69BCA
POOLCODE:0000000140B69BCA loc_140B69BCA:                          ; CO…
POOLCODE:0000000140B69BCA                 mov     rsi, [rbp+57h+BugChe…
POOLCODE:0000000140B69BCE                 jmp     loc_140B690B6
POOLCODE:0000000140B69BD3 ; ------------------------------------------…
POOLCODE:0000000140B69BD3
POOLCODE:0000000140B69BD3 loc_140B69BD3:                          ; CO…
POOLCODE:0000000140B69BD3                 lea     rcx, [rbp+57h+LockHa…
POOLCODE:0000000140B69BD7                 call    KxWaitForLockOwnerSh…
POOLCODE:0000000140B69BDC                 jmp     loc_140B68FE5
POOLCODE:0000000140B69BE1 ; ------------------------------------------…
POOLCODE:0000000140B69BE1
POOLCODE:0000000140B69BE1 loc_140B69BE1:                          ; CO…
POOLCODE:0000000140B69BE1                 mov     rcx, [rbp+57h+var_C0…
POOLCODE:0000000140B69BE5                 and     ecx, 100h
POOLCODE:0000000140B69BEB                 cmp     rdi, cs:PsInitialSys…
POOLCODE:0000000140B69BF2                 jz      loc_140B69CBE
POOLCODE:0000000140B69BF8                 mov     r13, [rdi+2F8h]
POOLCODE:0000000140B69BFF                 lea     r9, cs:140000000h
POOLCODE:0000000140B69C06                 mov     eax, r12d
POOLCODE:0000000140B69C09                 test    rcx, rcx
POOLCODE:0000000140B69C0C                 setnz   al
POOLCODE:0000000140B69C0F                 mov     r12d, eax
POOLCODE:0000000140B69C12                 movzx   eax, ds:rva PspResou…
POOLCODE:0000000140B69C1B                 mov     [rbp+57h+var_B0], al
POOLCODE:0000000140B69C1E                 mov     eax, r12d
POOLCODE:0000000140B69C21                 shl     rax, 7
POOLCODE:0000000140B69C25                 mov     [rbp+57h+var_98], ra…
POOLCODE:0000000140B69C29                 lea     r14, [rax+r13]
POOLCODE:0000000140B69C2D                 prefetchw byte ptr [r14]
POOLCODE:0000000140B69C31                 mov     r15, [r14]
POOLCODE:0000000140B69C34                 mov     rax, [r14+40h]
POOLCODE:0000000140B69C38                 cmp     qword ptr [r14+50h],…
POOLCODE:0000000140B69C3D                 jz      short loc_140B69C5F
POOLCODE:0000000140B69C3F                 imul    r8, r12, 38h ; '8'
POOLCODE:0000000140B69C43                 cmp     rax, r15
POOLCODE:0000000140B69C46                 jbe     short loc_140B69C5F
POOLCODE:0000000140B69C48                 mov     rdx, [r8+r9+0F056C8h…
POOLCODE:0000000140B69C50                 mov     rcx, rax
POOLCODE:0000000140B69C53                 sub     rcx, r15
POOLCODE:0000000140B69C56                 cmp     rcx, rdx
POOLCODE:0000000140B69C59                 ja      loc_140B69DD6
POOLCODE:0000000140B69C5F
POOLCODE:0000000140B69C5F loc_140B69C5F:                          ; CO…
POOLCODE:0000000140B69C5F                                         ; Ex…
POOLCODE:0000000140B69C5F                 mov     r8, [rbp+57h+BugChec…
POOLCODE:0000000140B69C63                 lea     r10, PspSystemQuotaB…
POOLCODE:0000000140B69C6A                 mov     r11, [rbp+57h+var_98…
POOLCODE:0000000140B69C6E
POOLCODE:0000000140B69C6E loc_140B69C6E:                          ; CO…
POOLCODE:0000000140B69C6E                                         ; Ex…
POOLCODE:0000000140B69C6E                 cmp     r8, r15
POOLCODE:0000000140B69C71                 mov     r9, r15
POOLCODE:0000000140B69C74                 mov     rcx, r15
POOLCODE:0000000140B69C77                 mov     rax, r15
POOLCODE:0000000140B69C7A                 cmovb   r9, r8
POOLCODE:0000000140B69C7E                 sub     rcx, r8
POOLCODE:0000000140B69C81                 xor     edx, edx
POOLCODE:0000000140B69C83                 cmp     r8, r15
POOLCODE:0000000140B69C86                 cmovb   rdx, rcx
POOLCODE:0000000140B69C8A                 lock cmpxchg [r14], rdx
POOLCODE:0000000140B69C8F                 mov     r15, rax
POOLCODE:0000000140B69C92                 jnz     short loc_140B69C6E
POOLCODE:0000000140B69C94                 sub     r8, r9
POOLCODE:0000000140B69C97                 jnz     loc_140B69EF5
POOLCODE:0000000140B69C9D                 test    [rbp+57h+var_B0], 4
POOLCODE:0000000140B69CA1                 jz      short loc_140B69CB3
POOLCODE:0000000140B69CA3                 mov     rax, [rbp+57h+BugChe…
POOLCODE:0000000140B69CA7                 neg     rax
POOLCODE:0000000140B69CAA                 lock add [rdi+r12*8+200h], r…
POOLCODE:0000000140B69CB3
POOLCODE:0000000140B69CB3 loc_140B69CB3:                          ; CO…
POOLCODE:0000000140B69CB3                 mov     r13, [rbp+57h+arg_0]
POOLCODE:0000000140B69CB7                 xor     r12d, r12d
POOLCODE:0000000140B69CBA                 mov     r15, [rbp+57h+arg_10…
POOLCODE:0000000140B69CBE
POOLCODE:0000000140B69CBE loc_140B69CBE:                          ; CO…
POOLCODE:0000000140B69CBE                 cmp     cs:ObpTraceFlags, 0
POOLCODE:0000000140B69CC5                 jz      short loc_140B69CD9
POOLCODE:0000000140B69CC7                 xor     edx, edx
POOLCODE:0000000140B69CC9                 lea     rcx, [rdi-30h]
POOLCODE:0000000140B69CCD                 mov     r9d, ebx
POOLCODE:0000000140B69CD0                 lea     r8d, [rdx+1]
POOLCODE:0000000140B69CD4                 call    ObpPushStackInfo
POOLCODE:0000000140B69CD9
POOLCODE:0000000140B69CD9 loc_140B69CD9:                          ; CO…
POOLCODE:0000000140B69CD9                 lock xadd [rdi-30h], rsi
POOLCODE:0000000140B69CDF                 sub     rsi, 1
POOLCODE:0000000140B69CE3                 jg      loc_140B698A9
POOLCODE:0000000140B69CE9                 mov     rcx, [rdi-28h]
POOLCODE:0000000140B69CED                 test    rcx, rcx
POOLCODE:0000000140B69CF0                 jnz     loc_140B6A1F7
POOLCODE:0000000140B69CF6                 test    rsi, rsi
POOLCODE:0000000140B69CF9                 jns     loc_140B6A248
POOLCODE:0000000140B69CFF                 xor     edx, edx        ; Bu…
POOLCODE:0000000140B69D01                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69D06                 lea     r9d, [rcx+4]    ; Bu…
POOLCODE:0000000140B69D0A                 mov     r8, rdi         ; Bu…
POOLCODE:0000000140B69D0D                 lea     ecx, [rdx+18h]  ; Bu…
POOLCODE:0000000140B69D10                 call    KeBugCheckEx
POOLCODE:0000000140B69D10 ; ------------------------------------------…
POOLCODE:0000000140B69D15                 align 2
POOLCODE:0000000140B69D16
POOLCODE:0000000140B69D16 loc_140B69D16:                          ; CO…
POOLCODE:0000000140B69D16                 mov     eax, cs:ExpHpGCSched…
POOLCODE:0000000140B69D1C                 jmp     loc_140B69B52
POOLCODE:0000000140B69D21 ; ------------------------------------------…
POOLCODE:0000000140B69D21
POOLCODE:0000000140B69D21 loc_140B69D21:                          ; CO…
POOLCODE:0000000140B69D21                                         ; Ex…
POOLCODE:0000000140B69D21                 lea     rcx, [rbp+57h+LockHa…
POOLCODE:0000000140B69D25                 call    KeReleaseInStackQueu…
POOLCODE:0000000140B69D2A                 mov     eax, gs:1A4h
POOLCODE:0000000140B69D32                 mov     r8d, dword ptr cs:Po…
POOLCODE:0000000140B69D39                 mov     ecx, eax
POOLCODE:0000000140B69D3B                 dec     r8d
POOLCODE:0000000140B69D3E                 lea     rax, cs:140000000h
POOLCODE:0000000140B69D45                 mov     rdx, rva ExPoolTagTa…
POOLCODE:0000000140B69D4D                 lea     rcx, [r8+r8*4]
POOLCODE:0000000140B69D51                 mov     rax, [rbp+57h+BugChe…
POOLCODE:0000000140B69D55                 shl     rcx, 4
POOLCODE:0000000140B69D59                 neg     rax
POOLCODE:0000000140B69D5C                 add     rcx, rdx
POOLCODE:0000000140B69D5F                 bt      rsi, 8
POOLCODE:0000000140B69D64                 jb      short loc_140B69D75
POOLCODE:0000000140B69D66                 lock inc qword ptr [rcx+18h]
POOLCODE:0000000140B69D6B                 lock add [rcx+8], rax
POOLCODE:0000000140B69D70                 jmp     loc_140B6908F
POOLCODE:0000000140B69D75 ; ------------------------------------------…
POOLCODE:0000000140B69D75
POOLCODE:0000000140B69D75 loc_140B69D75:                          ; CO…
POOLCODE:0000000140B69D75                 lock inc qword ptr [rcx+30h]
POOLCODE:0000000140B69D7A                 lock add [rcx+20h], rax
POOLCODE:0000000140B69D7F                 jmp     loc_140B6908F
POOLCODE:0000000140B69D84 ; ------------------------------------------…
POOLCODE:0000000140B69D84
POOLCODE:0000000140B69D84 loc_140B69D84:                          ; CO…
POOLCODE:0000000140B69D84                 cmp     [rbp+57h+var_C0], r1…
POOLCODE:0000000140B69D88                 jnz     loc_140B69E3A
POOLCODE:0000000140B69D8E                 mov     r9, r8          ; Bu…
POOLCODE:0000000140B69D91                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69D96                 mov     r8, r15         ; Bu…
POOLCODE:0000000140B69D99                 mov     rdx, rdi        ; Bu…
POOLCODE:0000000140B69D9C                 mov     ecx, 21h ; '!'  ; Bu…
POOLCODE:0000000140B69DA1                 call    KeBugCheckEx
POOLCODE:0000000140B69DA1 ; ------------------------------------------…
POOLCODE:0000000140B69DA6                 db 0CCh
POOLCODE:0000000140B69DA7 ; ------------------------------------------…
POOLCODE:0000000140B69DA7
POOLCODE:0000000140B69DA7 loc_140B69DA7:                          ; CO…
POOLCODE:0000000140B69DA7                 mov     rax, 0FFFF8000000000…
POOLCODE:0000000140B69DB1                 cmp     r14, rax
POOLCODE:0000000140B69DB4                 jnb     loc_140B6A3C8
POOLCODE:0000000140B69DBA                 mov     edx, 2          ; Bu…
POOLCODE:0000000140B69DBF                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69DC4                 mov     r9, r14         ; Bu…
POOLCODE:0000000140B69DC7                 mov     ecx, 1F1h       ; Bu…
POOLCODE:0000000140B69DCC                 lea     r8d, [rdx-1]    ; Bu…
POOLCODE:0000000140B69DD0                 call    KeBugCheckEx
POOLCODE:0000000140B69DD0 ; ------------------------------------------…
POOLCODE:0000000140B69DD5                 align 2
POOLCODE:0000000140B69DD6
POOLCODE:0000000140B69DD6 loc_140B69DD6:                          ; CO…
POOLCODE:0000000140B69DD6                 cmp     rdx, [rbp+57h+BugChe…
POOLCODE:0000000140B69DDA                 mov     rcx, rax
POOLCODE:0000000140B69DDD                 cmova   rdx, [rbp+57h+BugChe…
POOLCODE:0000000140B69DE2                 sub     rcx, rdx
POOLCODE:0000000140B69DE5                 lock cmpxchg [r14+40h], rcx
POOLCODE:0000000140B69DEB                 jnz     loc_140B69C5F
POOLCODE:0000000140B69DF1                 mov     rax, rdx
POOLCODE:0000000140B69DF4                 lock xadd [r14+48h], rax
POOLCODE:0000000140B69DFA                 add     rdx, rax
POOLCODE:0000000140B69DFD                 cmp     rdx, [r8+r9+0F056C8h…
POOLCODE:0000000140B69E05                 jbe     loc_140B69C5F
POOLCODE:0000000140B69E0B                 xor     r8d, r8d
POOLCODE:0000000140B69E0E                 xchg    r8, [r14+48h]
POOLCODE:0000000140B69E12                 test    r8, r8
POOLCODE:0000000140B69E15                 jz      loc_140B69C5F
POOLCODE:0000000140B69E1B                 xor     r9d, r9d
POOLCODE:0000000140B69E1E                 mov     rdx, r14
POOLCODE:0000000140B69E21                 mov     ecx, r12d
POOLCODE:0000000140B69E24                 call    PspReturnResourceQuo…
POOLCODE:0000000140B69E29                 jmp     loc_140B69C5F
POOLCODE:0000000140B69E2E ; ------------------------------------------…
POOLCODE:0000000140B69E2E
POOLCODE:0000000140B69E2E loc_140B69E2E:                          ; CO…
POOLCODE:0000000140B69E2E                 add     rbx, 0C0h
POOLCODE:0000000140B69E35                 jmp     loc_140B6912F
POOLCODE:0000000140B69E3A ; ------------------------------------------…
POOLCODE:0000000140B69E3A
POOLCODE:0000000140B69E3A loc_140B69E3A:                          ; CO…
POOLCODE:0000000140B69E3A                 mov     [rbp+57h+var_C0], r1…
POOLCODE:0000000140B69E3E                 lea     r12, [r11+r10]
POOLCODE:0000000140B69E42                 prefetchw byte ptr [r12]
POOLCODE:0000000140B69E47                 mov     rsi, [r12]
POOLCODE:0000000140B69E4B                 jmp     loc_140B696A5
POOLCODE:0000000140B69E50 ; ------------------------------------------…
POOLCODE:0000000140B69E50
POOLCODE:0000000140B69E50 loc_140B69E50:                          ; CO…
POOLCODE:0000000140B69E50                 test    rdx, rdx
POOLCODE:0000000140B69E53                 jz      loc_140B690DA
POOLCODE:0000000140B69E59                 lea     eax, [rsi+0Fh]
POOLCODE:0000000140B69E5C                 shr     eax, 4
POOLCODE:0000000140B69E5F                 lea     rsi, cs:140000000h
POOLCODE:0000000140B69E66                 movzx   ecx, byte ptr [rax+r…
POOLCODE:0000000140B69E6E                 add     ecx, 0FFFFFFDFh
POOLCODE:0000000140B69E71                 inc     rcx
POOLCODE:0000000140B69E74                 shl     rcx, 6
POOLCODE:0000000140B69E78                 add     rcx, rdx        ; Li…
POOLCODE:0000000140B69E7B                 inc     dword ptr [rcx+1Ch]
POOLCODE:0000000140B69E7E                 movzx   eax, word ptr [rcx+1…
POOLCODE:0000000140B69E82                 cmp     [rcx], ax
POOLCODE:0000000140B69E85                 jnb     short loc_140B69EA1
POOLCODE:0000000140B69E87                 mov     rdx, r14        ; Li…
POOLCODE:0000000140B69E8A                 call    RtlpInterlockedPushE…
POOLCODE:0000000140B69E8F                 mov     eax, 1
POOLCODE:0000000140B69E94
POOLCODE:0000000140B69E94 loc_140B69E94:                          ; CO…
POOLCODE:0000000140B69E94                 test    eax, eax
POOLCODE:0000000140B69E96                 jz      loc_140B690E1
POOLCODE:0000000140B69E9C                 jmp     loc_140B694D4
POOLCODE:0000000140B69EA1 ; ------------------------------------------…
POOLCODE:0000000140B69EA1
POOLCODE:0000000140B69EA1 loc_140B69EA1:                          ; CO…
POOLCODE:0000000140B69EA1                 inc     dword ptr [rcx+20h]
POOLCODE:0000000140B69EA4                 mov     eax, r12d
POOLCODE:0000000140B69EA7                 jmp     short loc_140B69E94
POOLCODE:0000000140B69EA9 ; ------------------------------------------…
POOLCODE:0000000140B69EA9
POOLCODE:0000000140B69EA9 loc_140B69EA9:                          ; CO…
POOLCODE:0000000140B69EA9                 mov     eax, cs:PopHibernate…
POOLCODE:0000000140B69EAF                 test    eax, eax
POOLCODE:0000000140B69EB1                 jnz     loc_140B6986B
POOLCODE:0000000140B69EB7                 mov     rdx, [rbp+57h+var_s8…
POOLCODE:0000000140B69EBB                 lea     rcx, ExpLargePoolTab…
POOLCODE:0000000140B69EC2                 call    ExpReleaseSpinLockSh…
POOLCODE:0000000140B69EC7                 jmp     loc_140B6987D
POOLCODE:0000000140B69ECC ; ------------------------------------------…
POOLCODE:0000000140B69ECC
POOLCODE:0000000140B69ECC loc_140B69ECC:                          ; CO…
POOLCODE:0000000140B69ECC                 mov     rcx, [rdi-28h]
POOLCODE:0000000140B69ED0                 test    rcx, rcx
POOLCODE:0000000140B69ED3                 jnz     short loc_140B69F27
POOLCODE:0000000140B69ED5                 test    rsi, rsi
POOLCODE:0000000140B69ED8                 jns     loc_140B6A23A
POOLCODE:0000000140B69EDE                 xor     edx, edx        ; Bu…
POOLCODE:0000000140B69EE0                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69EE5                 lea     r9d, [rcx+4]    ; Bu…
POOLCODE:0000000140B69EE9                 mov     r8, rdi         ; Bu…
POOLCODE:0000000140B69EEC                 lea     ecx, [rdx+18h]  ; Bu…
POOLCODE:0000000140B69EEF                 call    KeBugCheckEx
POOLCODE:0000000140B69EEF ; ------------------------------------------…
POOLCODE:0000000140B69EF4                 db 0CCh
POOLCODE:0000000140B69EF5 ; ------------------------------------------…
POOLCODE:0000000140B69EF5
POOLCODE:0000000140B69EF5 loc_140B69EF5:                          ; CO…
POOLCODE:0000000140B69EF5                 cmp     r13, r10
POOLCODE:0000000140B69EF8                 jnz     short loc_140B69F14
POOLCODE:0000000140B69EFA                 mov     r9, [rbp+57h+BugChec…
POOLCODE:0000000140B69EFE                 mov     rdx, rdi        ; Bu…
POOLCODE:0000000140B69F01                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69F06                 mov     ecx, 21h ; '!'  ; Bu…
POOLCODE:0000000140B69F0B                 mov     r8, r12         ; Bu…
POOLCODE:0000000140B69F0E                 call    KeBugCheckEx
POOLCODE:0000000140B69F0E ; ------------------------------------------…
POOLCODE:0000000140B69F13                 align 4
POOLCODE:0000000140B69F14
POOLCODE:0000000140B69F14 loc_140B69F14:                          ; CO…
POOLCODE:0000000140B69F14                 mov     r13, r10
POOLCODE:0000000140B69F17                 lea     r14, [r11+r10]
POOLCODE:0000000140B69F1B                 prefetchw byte ptr [r14]
POOLCODE:0000000140B69F1F                 mov     r15, [r14]
POOLCODE:0000000140B69F22                 jmp     loc_140B69C6E
POOLCODE:0000000140B69F27 ; ------------------------------------------…
POOLCODE:0000000140B69F27
POOLCODE:0000000140B69F27 loc_140B69F27:                          ; CO…
POOLCODE:0000000140B69F27                 mov     r9d, 3          ; Bu…
POOLCODE:0000000140B69F2D                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69F32                 lea     r11, cs:140000000h
POOLCODE:0000000140B69F39                 mov     r8, rdi         ; Bu…
POOLCODE:0000000140B69F3C                 lea     rax, [rdi-30h]
POOLCODE:0000000140B69F40                 shr     rax, 8
POOLCODE:0000000140B69F44                 movzx   edx, al
POOLCODE:0000000140B69F47                 lea     ecx, [r9+15h]   ; Bu…
POOLCODE:0000000140B69F4B                 movzx   eax, byte ptr [rdi-1…
POOLCODE:0000000140B69F4F                 xor     rdx, rax
POOLCODE:0000000140B69F52                 movzx   eax, byte ptr cs:ObH…
POOLCODE:0000000140B69F59                 xor     rdx, rax
POOLCODE:0000000140B69F5C                 mov     rdx, ds:rva ObTypeIn…
POOLCODE:0000000140B69F64                 call    KeBugCheckEx
POOLCODE:0000000140B69F64 ; ------------------------------------------…
POOLCODE:0000000140B69F69                 align 2
POOLCODE:0000000140B69F6A
POOLCODE:0000000140B69F6A loc_140B69F6A:                          ; CO…
POOLCODE:0000000140B69F6A                 test    sil, 0C0h
POOLCODE:0000000140B69F6E                 setnz   cl
POOLCODE:0000000140B69F71                 bt      eax, 9
POOLCODE:0000000140B69F75                 setb    al
POOLCODE:0000000140B69F78                 test    al, cl
POOLCODE:0000000140B69F7A                 jz      short loc_140B69F84
POOLCODE:0000000140B69F7C                 mov     rcx, r14
POOLCODE:0000000140B69F7F                 call    ExpCheckForLookaside
POOLCODE:0000000140B69F84
POOLCODE:0000000140B69F84 loc_140B69F84:                          ; CO…
POOLCODE:0000000140B69F84                 mov     eax, cs:ExpPoolFlags
POOLCODE:0000000140B69F8A                 test    al, 1
POOLCODE:0000000140B69F8C                 jz      short loc_140B69F9A
POOLCODE:0000000140B69F8E                 mov     rdx, [rbp+57h+BugChe…
POOLCODE:0000000140B69F92                 mov     rcx, r14        ; Bu…
POOLCODE:0000000140B69F95                 call    KeCheckForTimer
POOLCODE:0000000140B69F9A
POOLCODE:0000000140B69F9A loc_140B69F9A:                          ; CO…
POOLCODE:0000000140B69F9A                 mov     eax, cs:ExpPoolFlags
POOLCODE:0000000140B69FA0                 test    al, 4
POOLCODE:0000000140B69FA2                 jz      short loc_140B69FB0
POOLCODE:0000000140B69FA4                 mov     rdx, [rbp+57h+BugChe…
POOLCODE:0000000140B69FA8                 mov     rcx, r14
POOLCODE:0000000140B69FAB                 call    ExpCheckForResource
POOLCODE:0000000140B69FB0
POOLCODE:0000000140B69FB0 loc_140B69FB0:                          ; CO…
POOLCODE:0000000140B69FB0                 mov     eax, cs:ExpPoolFlags
POOLCODE:0000000140B69FB6                 test    al, 2
POOLCODE:0000000140B69FB8                 jz      loc_140B68EE5
POOLCODE:0000000140B69FBE                 mov     rdx, [rbp+57h+BugChe…
POOLCODE:0000000140B69FC2                 mov     rcx, r14        ; Bu…
POOLCODE:0000000140B69FC5                 call    ExpCheckForWorker
POOLCODE:0000000140B69FCA                 jmp     loc_140B68EE5
POOLCODE:0000000140B69FCF ; ------------------------------------------…
POOLCODE:0000000140B69FCF
POOLCODE:0000000140B69FCF loc_140B69FCF:                          ; CO…
POOLCODE:0000000140B69FCF                                         ; Ex…
POOLCODE:0000000140B69FCF                 test    rdx, rdx
POOLCODE:0000000140B69FD2                 jz      short loc_140B69FD7
POOLCODE:0000000140B69FD4                 mov     r12d, r14d
POOLCODE:0000000140B69FD7
POOLCODE:0000000140B69FD7 loc_140B69FD7:                          ; CO…
POOLCODE:0000000140B69FD7                 mov     r9d, r12d       ; Bu…
POOLCODE:0000000140B69FDA                 mov     r8, r13         ; Bu…
POOLCODE:0000000140B69FDD                 mov     edx, 0Dh        ; Bu…
POOLCODE:0000000140B69FE2                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B69FE7                 mov     ecx, 0C2h       ; Bu…
POOLCODE:0000000140B69FEC                 call    KeBugCheckEx
POOLCODE:0000000140B69FEC ; ------------------------------------------…
POOLCODE:0000000140B69FF1                 align 2
POOLCODE:0000000140B69FF2
POOLCODE:0000000140B69FF2 loc_140B69FF2:                          ; CO…
POOLCODE:0000000140B69FF2                 mov     edx, esi
POOLCODE:0000000140B69FF4                 lea     rax, [rbp+57h+var_AF…
POOLCODE:0000000140B69FF8                 and     edx, 10h
POOLCODE:0000000140B69FFB                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A000                 lea     r9, [rbp+57h+arg_10]
POOLCODE:0000000140B6A004                 mov     rcx, rsi
POOLCODE:0000000140B6A007                 lea     r8, [rbp+57h+var_A8]
POOLCODE:0000000140B6A00B                 call    ExpPoolFlagsToPoolTy…
POOLCODE:0000000140B6A010                 test    eax, eax
POOLCODE:0000000140B6A012                 js      loc_140B68F25
POOLCODE:0000000140B6A018                 cmp     byte ptr [rbp+57h+ar…
POOLCODE:0000000140B6A01C                 mov     edx, [rbp+57h+var_A8…
POOLCODE:0000000140B6A01F                 jz      short loc_140B6A027
POOLCODE:0000000140B6A021                 or      edx, 8
POOLCODE:0000000140B6A024                 mov     [rbp+57h+var_A8], ed…
POOLCODE:0000000140B6A027
POOLCODE:0000000140B6A027 loc_140B6A027:                          ; CO…
POOLCODE:0000000140B6A027                 mov     rax, [rbp+57h+BugChe…
POOLCODE:0000000140B6A02B                 mov     ecx, 0E22h
POOLCODE:0000000140B6A030                 mov     r9, rdi
POOLCODE:0000000140B6A033                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A038                 mov     r8d, ebx
POOLCODE:0000000140B6A03B                 call    EtwTracePool
POOLCODE:0000000140B6A040                 jmp     loc_140B68F25
POOLCODE:0000000140B6A045 ; ------------------------------------------…
POOLCODE:0000000140B6A045
POOLCODE:0000000140B6A045 loc_140B6A045:                          ; CO…
POOLCODE:0000000140B6A045                 movsxd  rax, r9d
POOLCODE:0000000140B6A048                 test    byte ptr [r8+rax*8+3…
POOLCODE:0000000140B6A04E                 lea     r11, [r8+rax*8]
POOLCODE:0000000140B6A052                 jnz     loc_140B69086
POOLCODE:0000000140B6A058                 mov     rax, [r11+38h]
POOLCODE:0000000140B6A05C                 lea     r10, ds:3Fh[r10*4]
POOLCODE:0000000140B6A064                 and     r10, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B6A068                 mov     ebx, 80h
POOLCODE:0000000140B6A06D                 cmp     r10, 40h ; '@'
POOLCODE:0000000140B6A071                 cmovz   r10, rbx
POOLCODE:0000000140B6A075
POOLCODE:0000000140B6A075 loc_140B6A075:                          ; CO…
POOLCODE:0000000140B6A075                 lea     rbx, [r10+rcx]
POOLCODE:0000000140B6A079                 cmp     rcx, rax
POOLCODE:0000000140B6A07C                 jge     loc_140B69086
POOLCODE:0000000140B6A082                 cmp     rbx, rax
POOLCODE:0000000140B6A085                 jge     loc_140B69086
POOLCODE:0000000140B6A08B                 lock cmpxchg [r11+38h], rbx
POOLCODE:0000000140B6A091                 jz      loc_140B6A124
POOLCODE:0000000140B6A097                 mov     rcx, [rdx]
POOLCODE:0000000140B6A09A                 jmp     short loc_140B6A075
POOLCODE:0000000140B6A09C ; ------------------------------------------…
POOLCODE:0000000140B6A09C
POOLCODE:0000000140B6A09C loc_140B6A09C:                          ; CO…
POOLCODE:0000000140B6A09C                 mov     edx, r12d
POOLCODE:0000000140B6A09F                 mov     r10d, r12d
POOLCODE:0000000140B6A0A2                 jmp     loc_140B697DE
POOLCODE:0000000140B6A0A7 ; ------------------------------------------…
POOLCODE:0000000140B6A0A7
POOLCODE:0000000140B6A0A7 loc_140B6A0A7:                          ; CO…
POOLCODE:0000000140B6A0A7                 mov     edx, edi
POOLCODE:0000000140B6A0A9                 lea     rax, [rbp+57h+arg_18…
POOLCODE:0000000140B6A0AD                 and     edx, 10h
POOLCODE:0000000140B6A0B0                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A0B5                 lea     r9, [rbp+57h+arg_0]
POOLCODE:0000000140B6A0B9                 mov     rcx, rdi
POOLCODE:0000000140B6A0BC                 lea     r8, [rbp+57h+var_AC]
POOLCODE:0000000140B6A0C0                 call    ExpPoolFlagsToPoolTy…
POOLCODE:0000000140B6A0C5                 test    eax, eax
POOLCODE:0000000140B6A0C7                 js      loc_140B69454
POOLCODE:0000000140B6A0CD                 mov     edx, [rbp+57h+var_AC…
POOLCODE:0000000140B6A0D0                 cmp     byte ptr [rbp+57h+ar…
POOLCODE:0000000140B6A0D4                 jz      short loc_140B6A0DC
POOLCODE:0000000140B6A0D6                 or      edx, 8
POOLCODE:0000000140B6A0D9                 mov     [rbp+57h+var_AC], ed…
POOLCODE:0000000140B6A0DC
POOLCODE:0000000140B6A0DC loc_140B6A0DC:                          ; CO…
POOLCODE:0000000140B6A0DC                 mov     ecx, 0E22h
POOLCODE:0000000140B6A0E1                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A0E6                 mov     r9, r13
POOLCODE:0000000140B6A0E9                 mov     r8d, esi
POOLCODE:0000000140B6A0EC                 call    EtwTracePool
POOLCODE:0000000140B6A0F1                 jmp     loc_140B69454
POOLCODE:0000000140B6A0F6 ; ------------------------------------------…
POOLCODE:0000000140B6A0F6
POOLCODE:0000000140B6A0F6 loc_140B6A0F6:                          ; CO…
POOLCODE:0000000140B6A0F6                 mov     rcx, r13
POOLCODE:0000000140B6A0F9                 call    ExIsSpecialPoolAddre…
POOLCODE:0000000140B6A0FE                 mov     edx, 100h
POOLCODE:0000000140B6A103                 test    eax, eax
POOLCODE:0000000140B6A105                 jnz     loc_140B68E0C
POOLCODE:0000000140B6A10B                 lea     r8d, [rdx-1]
POOLCODE:0000000140B6A10F                 jmp     loc_140B69568
POOLCODE:0000000140B6A114 ; ------------------------------------------…
POOLCODE:0000000140B6A114
POOLCODE:0000000140B6A114 loc_140B6A114:                          ; CO…
POOLCODE:0000000140B6A114                                         ; Ex…
POOLCODE:0000000140B6A114                 mov     rdx, r14
POOLCODE:0000000140B6A117                 mov     rcx, r15
POOLCODE:0000000140B6A11A                 call    RtlpHpLargeFree
POOLCODE:0000000140B6A11F                 jmp     loc_140B694D4
POOLCODE:0000000140B6A124 ; ------------------------------------------…
POOLCODE:0000000140B6A124
POOLCODE:0000000140B6A124 loc_140B6A124:                          ; CO…
POOLCODE:0000000140B6A124                 mov     rdx, [r8+48h]
POOLCODE:0000000140B6A128                 sub     rax, rbx
POOLCODE:0000000140B6A12B                 mov     r10, rax
POOLCODE:0000000140B6A12E                 neg     r10
POOLCODE:0000000140B6A131                 test    rax, rax
POOLCODE:0000000140B6A134                 cmovns  r10, rax
POOLCODE:0000000140B6A138                 movsxd  rax, r9d
POOLCODE:0000000140B6A13B                 lea     rcx, [rax+rax*2]
POOLCODE:0000000140B6A13F                 mov     rax, [rdx+rcx*8+10h]
POOLCODE:0000000140B6A144                 mov     r8, [rdx+rcx*8+18h]
POOLCODE:0000000140B6A149                 test    rax, rax
POOLCODE:0000000140B6A14C                 jnz     short loc_140B6A157
POOLCODE:0000000140B6A14E                 test    r8, r8
POOLCODE:0000000140B6A151                 jz      loc_140B69086
POOLCODE:0000000140B6A157
POOLCODE:0000000140B6A157 loc_140B6A157:                          ; CO…
POOLCODE:0000000140B6A157                 neg     r10
POOLCODE:0000000140B6A15A                 lock add [rdx+rcx*8+20h], r1…
POOLCODE:0000000140B6A160                 jmp     loc_140B69086
POOLCODE:0000000140B6A165 ; ------------------------------------------…
POOLCODE:0000000140B6A165
POOLCODE:0000000140B6A165 loc_140B6A165:                          ; CO…
POOLCODE:0000000140B6A165                 mov     rdx, [r8+48h]
POOLCODE:0000000140B6A169                 sub     rax, rbx
POOLCODE:0000000140B6A16C                 mov     rcx, rax
POOLCODE:0000000140B6A16F                 neg     rcx
POOLCODE:0000000140B6A172                 test    rax, rax
POOLCODE:0000000140B6A175                 cmovns  rcx, rax
POOLCODE:0000000140B6A179                 add     rdx, r10
POOLCODE:0000000140B6A17C                 mov     rax, [rdx+10h]
POOLCODE:0000000140B6A180                 mov     r8, [rdx+18h]
POOLCODE:0000000140B6A184                 test    rax, rax
POOLCODE:0000000140B6A187                 jnz     short loc_140B6A192
POOLCODE:0000000140B6A189                 test    r8, r8
POOLCODE:0000000140B6A18C                 jz      loc_140B6908F
POOLCODE:0000000140B6A192
POOLCODE:0000000140B6A192 loc_140B6A192:                          ; CO…
POOLCODE:0000000140B6A192                 neg     rcx
POOLCODE:0000000140B6A195                 lock add [rdx+20h], rcx
POOLCODE:0000000140B6A19A                 jmp     loc_140B6908F
POOLCODE:0000000140B6A19F ; ------------------------------------------…
POOLCODE:0000000140B6A19F
POOLCODE:0000000140B6A19F loc_140B6A19F:                          ; CO…
POOLCODE:0000000140B6A19F                 cmp     byte ptr [rdi+16h], …
POOLCODE:0000000140B6A1A3                 jz      loc_140B69246
POOLCODE:0000000140B6A1A9                 mov     ecx, ebx
POOLCODE:0000000140B6A1AB                 mov     rax, rbx
POOLCODE:0000000140B6A1AE                 shr     rax, 6
POOLCODE:0000000140B6A1B2                 and     ecx, 3Fh
POOLCODE:0000000140B6A1B5                 mov     rdx, [rdi+rax*8+40h]
POOLCODE:0000000140B6A1BA                 mov     r8, 0FFFFFFFFFFFFFFF…
POOLCODE:0000000140B6A1C1                 rol     r8, cl
POOLCODE:0000000140B6A1C4                 mov     r9, rbx
POOLCODE:0000000140B6A1C7                 lea     rcx, [rdi+rax*8]
POOLCODE:0000000140B6A1CB                 mov     rax, r8
POOLCODE:0000000140B6A1CE                 and     rax, rdx
POOLCODE:0000000140B6A1D1                 not     r8
POOLCODE:0000000140B6A1D4                 mov     [rcx+40h], rax
POOLCODE:0000000140B6A1D8                 test    rdx, r8
POOLCODE:0000000140B6A1DB                 jz      loc_140B69A27
POOLCODE:0000000140B6A1E1                 inc     word ptr [rdi+20h]
POOLCODE:0000000140B6A1E5                 jmp     loc_140B694D4
POOLCODE:0000000140B6A1EA ; ------------------------------------------…
POOLCODE:0000000140B6A1EA
POOLCODE:0000000140B6A1EA loc_140B6A1EA:                          ; CO…
POOLCODE:0000000140B6A1EA                 mov     rcx, rsi
POOLCODE:0000000140B6A1ED                 call    RtlpHpLfhThreadDataI…
POOLCODE:0000000140B6A1F2                 jmp     loc_140B6923C
POOLCODE:0000000140B6A1F7 ; ------------------------------------------…
POOLCODE:0000000140B6A1F7
POOLCODE:0000000140B6A1F7 loc_140B6A1F7:                          ; CO…
POOLCODE:0000000140B6A1F7                 mov     r9d, 3          ; Bu…
POOLCODE:0000000140B6A1FD                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A202                 lea     r11, cs:140000000h
POOLCODE:0000000140B6A209                 mov     r8, rdi         ; Bu…
POOLCODE:0000000140B6A20C                 lea     rax, [rdi-30h]
POOLCODE:0000000140B6A210                 shr     rax, 8
POOLCODE:0000000140B6A214                 movzx   edx, al
POOLCODE:0000000140B6A217                 lea     ecx, [r9+15h]   ; Bu…
POOLCODE:0000000140B6A21B                 movzx   eax, byte ptr [rdi-1…
POOLCODE:0000000140B6A21F                 xor     rdx, rax
POOLCODE:0000000140B6A222                 movzx   eax, byte ptr cs:ObH…
POOLCODE:0000000140B6A229                 xor     rdx, rax
POOLCODE:0000000140B6A22C                 mov     rdx, ds:rva ObTypeIn…
POOLCODE:0000000140B6A234                 call    KeBugCheckEx
POOLCODE:0000000140B6A234 ; ------------------------------------------…
POOLCODE:0000000140B6A239                 align 2
POOLCODE:0000000140B6A23A
POOLCODE:0000000140B6A23A loc_140B6A23A:                          ; CO…
POOLCODE:0000000140B6A23A                 lea     rcx, [rdi-30h]
POOLCODE:0000000140B6A23E                 call    ObpDeferObjectDeleti…
POOLCODE:0000000140B6A243                 jmp     loc_140B69724
POOLCODE:0000000140B6A248 ; ------------------------------------------…
POOLCODE:0000000140B6A248
POOLCODE:0000000140B6A248 loc_140B6A248:                          ; CO…
POOLCODE:0000000140B6A248                 lea     rcx, [rdi-30h]
POOLCODE:0000000140B6A24C                 call    ObpDeferObjectDeleti…
POOLCODE:0000000140B6A251                 jmp     loc_140B698A9
POOLCODE:0000000140B6A256 ; ------------------------------------------…
POOLCODE:0000000140B6A256
POOLCODE:0000000140B6A256 loc_140B6A256:                          ; CO…
POOLCODE:0000000140B6A256                 mov     eax, [rbx]
POOLCODE:0000000140B6A258                 lea     r8, [rbx+10h]
POOLCODE:0000000140B6A25C                 mov     ecx, eax
POOLCODE:0000000140B6A25E                 mov     r10d, eax
POOLCODE:0000000140B6A261                 shr     ecx, 10h
POOLCODE:0000000140B6A264                 and     r10d, 4000h
POOLCODE:0000000140B6A26B                 jz      short loc_140B6A271
POOLCODE:0000000140B6A26D                 lea     r8, [rbx+18h]   ; Bu…
POOLCODE:0000000140B6A271
POOLCODE:0000000140B6A271 loc_140B6A271:                          ; CO…
POOLCODE:0000000140B6A271                                         ; Ex…
POOLCODE:0000000140B6A271                 cmp     r8, r13
POOLCODE:0000000140B6A274                 jb      short loc_140B6A2B4
POOLCODE:0000000140B6A276                 lea     r9, [r13+0FFFh]
POOLCODE:0000000140B6A27D                 and     r9, 0FFFFFFFFFFFFF00…
POOLCODE:0000000140B6A284                 lea     r8, [rdx+r13]   ; Bu…
POOLCODE:0000000140B6A288
POOLCODE:0000000140B6A288 loc_140B6A288:                          ; CO…
POOLCODE:0000000140B6A288                 cmp     r8, r9
POOLCODE:0000000140B6A28B                 jnb     loc_140B6940F
POOLCODE:0000000140B6A291                 cmp     [r8], cl
POOLCODE:0000000140B6A294                 jz      loc_140B6A4AE
POOLCODE:0000000140B6A29A                 mov     r9, rax         ; Bu…
POOLCODE:0000000140B6A29D                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A2A6                 mov     rdx, r13        ; Bu…
POOLCODE:0000000140B6A2A9                 mov     ecx, 0C1h       ; Bu…
POOLCODE:0000000140B6A2AE                 call    KeBugCheckEx
POOLCODE:0000000140B6A2AE ; ------------------------------------------…
POOLCODE:0000000140B6A2B3                 align 4
POOLCODE:0000000140B6A2B4
POOLCODE:0000000140B6A2B4 loc_140B6A2B4:                          ; CO…
POOLCODE:0000000140B6A2B4                 cmp     [r8], cl
POOLCODE:0000000140B6A2B7                 jz      loc_140B6A4A6
POOLCODE:0000000140B6A2BD                 mov     r9, rax         ; Bu…
POOLCODE:0000000140B6A2C0                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A2C9                 mov     rdx, r13        ; Bu…
POOLCODE:0000000140B6A2CC                 mov     ecx, 0C1h       ; Bu…
POOLCODE:0000000140B6A2D1                 call    KeBugCheckEx
POOLCODE:0000000140B6A2D1 ; ------------------------------------------…
POOLCODE:0000000140B6A2D6                 db 0CCh
POOLCODE:0000000140B6A2D7 ; ------------------------------------------…
POOLCODE:0000000140B6A2D7
POOLCODE:0000000140B6A2D7 loc_140B6A2D7:                          ; CO…
POOLCODE:0000000140B6A2D7                 lock dec cs:ExpSpecialAlloca…
POOLCODE:0000000140B6A2DE                 mov     rcx, r13
POOLCODE:0000000140B6A2E1                 call    MmDeterminePoolType
POOLCODE:0000000140B6A2E6                 mov     rbx, r13
POOLCODE:0000000140B6A2E9                 mov     rdi, rax
POOLCODE:0000000140B6A2EC                 and     rbx, 0FFFFFFFFFFFFF0…
POOLCODE:0000000140B6A2F3                 cmp     cs:byte_140FCDC28, r…
POOLCODE:0000000140B6A2FA                 jnz     loc_140B6A393
POOLCODE:0000000140B6A300
POOLCODE:0000000140B6A300 loc_140B6A300:                          ; CO…
POOLCODE:0000000140B6A300                 mov     edx, [rbx+4]
POOLCODE:0000000140B6A303                 mov     eax, r13d
POOLCODE:0000000140B6A306                 and     eax, 0FFFh
POOLCODE:0000000140B6A30B                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A310                 mov     ecx, 1000h
POOLCODE:0000000140B6A315                 mov     r9d, 80h
POOLCODE:0000000140B6A31B                 sub     ecx, eax
POOLCODE:0000000140B6A31D                 mov     esi, ecx
POOLCODE:0000000140B6A31F                 mov     r8d, ecx
POOLCODE:0000000140B6A322                 mov     rcx, r13
POOLCODE:0000000140B6A325                 call    ExpFreePoolChecks
POOLCODE:0000000140B6A32A                 mov     r11, rdi
POOLCODE:0000000140B6A32D                 mov     r8d, 100h       ; Bu…
POOLCODE:0000000140B6A333                 and     r11, r8
POOLCODE:0000000140B6A336                 mov     rcx, cr8
POOLCODE:0000000140B6A33A                 setz    al
POOLCODE:0000000140B6A33D                 inc     al
POOLCODE:0000000140B6A33F                 cmp     cl, al
POOLCODE:0000000140B6A341                 jbe     short loc_140B6A35C
POOLCODE:0000000140B6A343                 movzx   edx, cl         ; Bu…
POOLCODE:0000000140B6A346                 mov     r9, r13         ; Bu…
POOLCODE:0000000140B6A349                 lea     ecx, [r8-3Fh]   ; Bu…
POOLCODE:0000000140B6A34D                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A356                 call    KeBugCheckEx
POOLCODE:0000000140B6A356 ; ------------------------------------------…
POOLCODE:0000000140B6A35B                 align 4
POOLCODE:0000000140B6A35C
POOLCODE:0000000140B6A35C loc_140B6A35C:                          ; CO…
POOLCODE:0000000140B6A35C                 movzx   edx, word ptr [rbx]
POOLCODE:0000000140B6A35F                 and     edx, 1FFFh      ; Bu…
POOLCODE:0000000140B6A365                 lea     r14, [rdx+0Fh]
POOLCODE:0000000140B6A369                 and     r14, 0FFFFFFFFFFFFFF…
POOLCODE:0000000140B6A36D                 cmp     r14, rsi
POOLCODE:0000000140B6A370                 jz      loc_140B6A256
POOLCODE:0000000140B6A376                 mov     r8d, edx        ; Bu…
POOLCODE:0000000140B6A379                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A382                 mov     rdx, r13        ; Bu…
POOLCODE:0000000140B6A385                 mov     r9, rsi         ; Bu…
POOLCODE:0000000140B6A388                 mov     ecx, 0C1h       ; Bu…
POOLCODE:0000000140B6A38D                 call    KeBugCheckEx
POOLCODE:0000000140B6A38D ; ------------------------------------------…
POOLCODE:0000000140B6A392                 db 0CCh
POOLCODE:0000000140B6A393 ; ------------------------------------------…
POOLCODE:0000000140B6A393
POOLCODE:0000000140B6A393 loc_140B6A393:                          ; CO…
POOLCODE:0000000140B6A393                 cmp     rbx, rsi
POOLCODE:0000000140B6A396                 jnb     loc_140B6A44F
POOLCODE:0000000140B6A39C                 mov     edx, 2          ; Bu…
POOLCODE:0000000140B6A3A1                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A3A6                 mov     r9, rbx         ; Bu…
POOLCODE:0000000140B6A3A9                 mov     ecx, 1F1h       ; Bu…
POOLCODE:0000000140B6A3AE                 lea     r8d, [rdx-1]    ; Bu…
POOLCODE:0000000140B6A3B2                 call    KeBugCheckEx
POOLCODE:0000000140B6A3B2 ; ------------------------------------------…
POOLCODE:0000000140B6A3B7                 align 8
POOLCODE:0000000140B6A3B8
POOLCODE:0000000140B6A3B8 loc_140B6A3B8:                          ; CO…
POOLCODE:0000000140B6A3B8                 cmp     al, 4
POOLCODE:0000000140B6A3BA                 jz      loc_140B69589
POOLCODE:0000000140B6A3C0                 mov     rsi, rdx
POOLCODE:0000000140B6A3C3                 jmp     loc_140B6958E
POOLCODE:0000000140B6A3C8 ; ------------------------------------------…
POOLCODE:0000000140B6A3C8
POOLCODE:0000000140B6A3C8 loc_140B6A3C8:                          ; CO…
POOLCODE:0000000140B6A3C8                 test    r14b, 7
POOLCODE:0000000140B6A3CC                 jz      short loc_140B6A3EF
POOLCODE:0000000140B6A3CE                 mov     eax, 2
POOLCODE:0000000140B6A3D3                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A3DC                 mov     r8d, eax        ; Bu…
POOLCODE:0000000140B6A3DF                 mov     edx, eax        ; Bu…
POOLCODE:0000000140B6A3E1                 mov     r9, r14         ; Bu…
POOLCODE:0000000140B6A3E4                 mov     ecx, 1F1h       ; Bu…
POOLCODE:0000000140B6A3E9                 call    KeBugCheckEx
POOLCODE:0000000140B6A3E9 ; ------------------------------------------…
POOLCODE:0000000140B6A3EE                 db 0CCh
POOLCODE:0000000140B6A3EF ; ------------------------------------------…
POOLCODE:0000000140B6A3EF
POOLCODE:0000000140B6A3EF loc_140B6A3EF:                          ; CO…
POOLCODE:0000000140B6A3EF                 lea     rax, [rsi+r14]
POOLCODE:0000000140B6A3F3                 cmp     rax, r14
POOLCODE:0000000140B6A3F6                 jnb     short loc_140B6A414
POOLCODE:0000000140B6A3F8                 mov     edx, 2          ; Bu…
POOLCODE:0000000140B6A3FD                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A402                 mov     r9, r14         ; Bu…
POOLCODE:0000000140B6A405                 mov     ecx, 1F1h       ; Bu…
POOLCODE:0000000140B6A40A                 lea     r8d, [rdx+1]    ; Bu…
POOLCODE:0000000140B6A40E                 call    KeBugCheckEx
POOLCODE:0000000140B6A40E ; ------------------------------------------…
POOLCODE:0000000140B6A413                 align 4
POOLCODE:0000000140B6A414
POOLCODE:0000000140B6A414 loc_140B6A414:                          ; CO…
POOLCODE:0000000140B6A414                 mov     rbx, 800000000000h
POOLCODE:0000000140B6A41E                 mov     rdi, rsi
POOLCODE:0000000140B6A421                 add     rbx, r14
POOLCODE:0000000140B6A424                 shr     rdi, 3
POOLCODE:0000000140B6A428                 shr     rbx, 3
POOLCODE:0000000140B6A42C                 add     rbx, cs:KasaniShadow
POOLCODE:0000000140B6A433                 test    rdi, rdi
POOLCODE:0000000140B6A436                 jnz     short loc_140B6A4B6
POOLCODE:0000000140B6A438
POOLCODE:0000000140B6A438 loc_140B6A438:                          ; CO…
POOLCODE:0000000140B6A438                 test    sil, 7
POOLCODE:0000000140B6A43C                 jz      loc_140B690C3
POOLCODE:0000000140B6A442                 movzx   eax, sil
POOLCODE:0000000140B6A446                 and     al, 7
POOLCODE:0000000140B6A448                 mov     [rbx], al
POOLCODE:0000000140B6A44A                 jmp     loc_140B690C3
POOLCODE:0000000140B6A44F ; ------------------------------------------…
POOLCODE:0000000140B6A44F
POOLCODE:0000000140B6A44F loc_140B6A44F:                          ; CO…
POOLCODE:0000000140B6A44F                 lea     rax, [rbx+1000h]
POOLCODE:0000000140B6A456                 cmp     rax, rbx
POOLCODE:0000000140B6A459                 jnb     short loc_140B6A47C
POOLCODE:0000000140B6A45B                 mov     ecx, 1000h
POOLCODE:0000000140B6A460                 mov     edx, 2          ; Bu…
POOLCODE:0000000140B6A465                 mov     [rsp+0F0h+BugCheckPa…
POOLCODE:0000000140B6A46A                 mov     r9, rbx         ; Bu…
POOLCODE:0000000140B6A46D                 mov     ecx, 1F1h       ; Bu…
POOLCODE:0000000140B6A472                 lea     r8d, [rdx+1]    ; Bu…
POOLCODE:0000000140B6A476                 call    KeBugCheckEx
POOLCODE:0000000140B6A476 ; ------------------------------------------…
POOLCODE:0000000140B6A47B                 align 4
POOLCODE:0000000140B6A47C
POOLCODE:0000000140B6A47C loc_140B6A47C:                          ; CO…
POOLCODE:0000000140B6A47C                 mov     rcx, 800000000000h
POOLCODE:0000000140B6A486                 xor     edx, edx        ; Va…
POOLCODE:0000000140B6A488                 add     rcx, rbx
POOLCODE:0000000140B6A48B                 mov     r8d, 200h       ; Si…
POOLCODE:0000000140B6A491                 shr     rcx, 3
POOLCODE:0000000140B6A495                 add     rcx, cs:KasaniShadow…
POOLCODE:0000000140B6A49C                 call    memset_0
POOLCODE:0000000140B6A4A1                 jmp     loc_140B6A300
POOLCODE:0000000140B6A4A6 ; ------------------------------------------…
POOLCODE:0000000140B6A4A6
POOLCODE:0000000140B6A4A6 loc_140B6A4A6:                          ; CO…
POOLCODE:0000000140B6A4A6                 inc     r8
POOLCODE:0000000140B6A4A9                 jmp     loc_140B6A271
POOLCODE:0000000140B6A4AE ; ------------------------------------------…
POOLCODE:0000000140B6A4AE
POOLCODE:0000000140B6A4AE loc_140B6A4AE:                          ; CO…
POOLCODE:0000000140B6A4AE                 inc     r8
POOLCODE:0000000140B6A4B1                 jmp     loc_140B6A288
POOLCODE:0000000140B6A4B6 ; ------------------------------------------…
POOLCODE:0000000140B6A4B6
POOLCODE:0000000140B6A4B6 loc_140B6A4B6:                          ; CO…
POOLCODE:0000000140B6A4B6                 mov     r8, rdi         ; Si…
POOLCODE:0000000140B6A4B9                 xor     edx, edx        ; Va…
POOLCODE:0000000140B6A4BB                 mov     rcx, rbx        ; vo…
POOLCODE:0000000140B6A4BE                 call    memset_0
POOLCODE:0000000140B6A4C3                 add     rbx, rdi
POOLCODE:0000000140B6A4C6                 jmp     loc_140B6A438
POOLCODE:0000000140B6A4C6 ExFreePoolWithTag endp
POOLCODE:0000000140B6A4C6
POOLCODE:0000000140B6A4C6 ; ------------------------------------------…

```

// --- Calls: ExAcquireSpinLockShared at 0x140304970 (Depth: 2) ---
// Language: C/C++
```cpp
KIRQL __stdcall ExAcquireSpinLockShared(PEX_SPIN_LOCK SpinLock)
{
  KIRQL CurrentIrql; // bl
  signed __int32 v4; // eax
  signed __int32 v5; // ett

  CurrentIrql = KeGetCurrentIrql();
  __writecr8(2u);
  if ( KiIrqlFlags )
    KiRaiseIrqlProcessIrqlFlags(CurrentIrql, 2);
  if ( (BYTE6(PerfGlobalGroupMask) & 0x21) == 0 || PopHibernateInProgress )
  {
    _m_prefetchw((const void *)SpinLock);
    v4 = *SpinLock & 0x7FFFFFFF;
    while ( 1 )
    {
      v5 = v4;
      v4 = _InterlockedCompareExchange(SpinLock, v4 + 1, v4);
      if ( v5 == v4 )
        break;
      if ( v4 < 0 )
      {
        ExpWaitForSpinLockSharedAndAcquire(SpinLock, CurrentIrql);
        return CurrentIrql;
      }
    }
  }
  else
  {
    ExpAcquireSpinLockSharedAtDpcLevelInstrumented(SpinLock, CurrentIrql);
  }
  return CurrentIrql;
}

```

// --- Calls: KeBugCheckEx at 0x1404fb240 (Depth: 2) ---
// Language: C/C++
```cpp
// local variable allocation has failed, the output may be wrong!
void __stdcall __noreturn KeBugCheckEx(
        ULONG BugCheckCode,
        ULONG_PTR BugCheckParameter1,
        ULONG_PTR BugCheckParameter2,
        ULONG_PTR BugCheckParameter3,
        ULONG_PTR BugCheckParameter4)
{
  _CONTEXT *Context; // r10
  char **v6; // r8
  void *v7; // r9
  signed __int8 CurrentIrql; // al
  __int64 v9; // [rsp+30h] [rbp-8h]
  char *retaddr; // [rsp+38h] [rbp+0h] BYREF
  unsigned __int64 v11; // [rsp+40h] [rbp+8h]
  char v15; // [rsp+68h] [rbp+30h] BYREF

  v11 = *(_QWORD *)&BugCheckCode;
  _disable();
  RtlCaptureContext(KeGetCurrentPrcb()->Context);
  KiSaveProcessorControlState(&KeGetCurrentPrcb()->ProcessorState);
  Context = KeGetCurrentPrcb()->Context;
  Context->Rcx = v11;
  *(_QWORD *)&Context->EFlags = v9;
  if ( &byte_1404FB229 == retaddr )
  {
    v6 = (char **)&v15;
    v7 = KeBugCheck;
  }
  else
  {
    v6 = &retaddr;
    v7 = KeBugCheckEx;
  }
  Context->Rsp = (unsigned __int64)v6;
  Context->Rip = (unsigned __int64)v7;
  CurrentIrql = KeGetCurrentIrql();
  __writegsbyte(0x87D8u, CurrentIrql);
  if ( CurrentIrql < 2 )
    __writecr8(2u);
  if ( (v9 & 0x200) != 0 )
    _enable();
  _InterlockedIncrement(&KiHardwareTrigger);
  if ( &byte_1404FB229 != retaddr )
    KeBugCheck2(v11, BugCheckParameter1, BugCheckParameter2, BugCheckParameter3, BugCheckParameter4, 0);
  KeBugCheck2(v11, 0, 0, 0, 0, 0);
}

```

// --- Calls: ExReleaseSpinLockSharedFromDpcLevel at 0x140327240 (Depth: 2) ---
// Language: C/C++
```cpp
void __stdcall ExReleaseSpinLockSharedFromDpcLevel(PEX_SPIN_LOCK SpinLock)
{
  void *retaddr; // [rsp+28h] [rbp+0h]

  if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 || PopHibernateInProgress )
  {
    _InterlockedAnd(SpinLock, 0xBFFFFFFF);
    _InterlockedDecrement(SpinLock);
  }
  else
  {
    ExpReleaseSpinLockSharedFromDpcLevelInstrumented(SpinLock, retaddr);
  }
}

```

// --- Calls: KiLowerIrqlProcessIrqlFlags at 0x1404f46d8 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall KiLowerIrqlProcessIrqlFlags(unsigned __int8 a1, unsigned __int8 a2)
{
  __int64 result; // rax
  struct _KPRCB *CurrentPrcb; // r10
  _DWORD *SchedulerAssist; // r8
  bool v5; // zf

  result = (unsigned int)KiIrqlFlags;
  if ( (KiIrqlFlags & 1) != 0 && a1 <= 0xFu && a2 <= 0xFu && a1 >= 2u )
  {
    CurrentPrcb = KeGetCurrentPrcb();
    SchedulerAssist = CurrentPrcb->SchedulerAssist;
    result = ~(unsigned __int16)(-1LL << (a2 + 1));
    v5 = ((unsigned int)result & SchedulerAssist[5]) == 0;
    SchedulerAssist[5] &= result;
    if ( v5 )
      return KiRemoveSystemWorkPriorityKick(CurrentPrcb);
  }
  return result;
}

```

// --- Calls: ExpStampBigPoolEntry at 0x1403c3230 (Depth: 2) ---
// Language: C/C++
```cpp
ULONG_PTR __fastcall ExpStampBigPoolEntry(
        ULONG_PTR BugCheckParameter2,
        ULONG_PTR BugCheckParameter3,
        __int64 a3,
        _QWORD *a4,
        _DWORD *a5)
{
  unsigned int v7; // edi
  unsigned __int8 CurrentIrql; // si
  int v10; // r10d
  unsigned int v11; // edx
  char *v12; // rax
  ULONG_PTR v13; // rdi
  ULONG_PTR v14; // rbx
  __int64 v15; // rdx
  signed __int32 v17; // eax
  signed __int32 v18; // ett
  void *retaddr; // [rsp+38h] [rbp+0h]

  v7 = BugCheckParameter3;
  CurrentIrql = KeGetCurrentIrql();
  __writecr8(2u);
  if ( KiIrqlFlags )
    KiRaiseIrqlProcessIrqlFlags(CurrentIrql, 2);
  if ( (BYTE6(PerfGlobalGroupMask) & 0x21) == 0 || PopHibernateInProgress )
  {
    _m_prefetchw(&ExpLargePoolTableLock);
    v17 = ExpLargePoolTableLock & 0x7FFFFFFF;
    while ( 1 )
    {
      v18 = v17;
      v17 = _InterlockedCompareExchange(&ExpLargePoolTableLock, v17 + 1, v17);
      if ( v18 == v17 )
        break;
      if ( v17 < 0 )
      {
        ExpWaitForSpinLockSharedAndAcquire(&ExpLargePoolTableLock, CurrentIrql);
        break;
      }
    }
  }
  else
  {
    ExpAcquireSpinLockSharedAtDpcLevelInstrumented(&ExpLargePoolTableLock, CurrentIrql);
  }
  v10 = 1;
  v11 = (PoolBigPageTableSize - 1)
      & ((40543 * (BugCheckParameter2 >> 12))
       ^ ((40543 * (BugCheckParameter2 >> 12)) >> 32));
  while ( 1 )
  {
    v12 = (char *)PoolBigPageTable + 32 * v11;
    if ( *(_QWORD *)v12 == BugCheckParameter2 )
      break;
    if ( ++v11 >= (unsigned __int64)PoolBigPageTableSize )
    {
      if ( !v10 )
        goto LABEL_10;
      v11 = 0;
      v10 = 0;
    }
  }
  if ( !v12 )
LABEL_10:
    KeBugCheckEx(0x19u, 0x22u, BugCheckParameter2, v7, 0);
  if ( (*((_DWORD *)v12 + 3) & 0x100) != 0 )
  {
    v13 = BugCheckParameter2 ^ ExpPoolQuotaCookie ^ *((_QWORD *)v12 + 3);
    v14 = ExpPoolQuotaCookie ^ BugCheckParameter2;
    *a5 = *((_DWORD *)v12 + 2);
    v15 = *((_QWORD *)v12 + 2);
    *((_QWORD *)v12 + 3) = a3 ^ v14;
    *a4 = v15;
  }
  else
  {
    v13 = -1;
  }
  if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 || PopHibernateInProgress )
  {
    _InterlockedAnd(&ExpLargePoolTableLock, 0xBFFFFFFF);
    _InterlockedDecrement(&ExpLargePoolTableLock);
  }
  else
  {
    ExpReleaseSpinLockSharedFromDpcLevelInstrumented(&ExpLargePoolTableLock, retaddr);
  }
  if ( KiIrqlFlags )
    KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), CurrentIrql);
  __writecr8(CurrentIrql);
  return v13;
}

```

// --- Calls: PspExpandQuota at 0x1402de458 (Depth: 2) ---
// Language: C/C++
```cpp
char __fastcall PspExpandQuota(unsigned int a1, __int64 a2, __int64 a3, __int64 a4, unsigned __int64 *a5)
{
  int *v7; // rsi
  __int64 v10; // rdx
  unsigned __int64 v11; // rbp
  __int64 v12; // rdx
  char v13; // al
  __int64 v14; // rdx
  __int64 v15; // rax
  signed __int64 v16; // rbx
  unsigned __int64 v17; // rbx
  char v19; // [rsp+60h] [rbp+8h] BYREF
  __int64 v20; // [rsp+68h] [rbp+10h] BYREF

  v20 = 0;
  v19 = 0;
  v7 = &PspQuotaExpansionDescriptors[14 * a1];
  PspLockQuotaExpansion(v7, &v19);
  v11 = *(_QWORD *)(a2 + 64);
  if ( a3 + a4 <= v11 )
  {
    LOBYTE(v10) = v19;
    PspUnlockQuotaExpansion(v7, v10);
    *a5 = v11;
    return 1;
  }
  v12 = *(_QWORD *)(a2 + 64);
  if ( *((__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD, _QWORD))v7 + 3) == MmRaisePoolQuota )
    v13 = MmRaisePoolQuota(a1, v12, 0, &v20);
  else
    v13 = guard_dispatch_icall_no_overrides(a1, v12, 0, &v20);
  if ( v13 || PspReleaseReturnedQuota(a1, v7) && (unsigned __int8)guard_dispatch_icall_no_overrides(a1, v11, 0, &v20) )
  {
    v15 = v20 - v11;
    v16 = _InterlockedExchangeAdd64((volatile signed __int64 *)(a2 + 64), v20 - v11);
    LOBYTE(v14) = v19;
    v17 = v15 + v16;
    PspUnlockQuotaExpansion(v7, v14);
    *a5 = v17;
    return 1;
  }
  LOBYTE(v14) = v19;
  PspUnlockQuotaExpansion(v7, v14);
  *a5 = v11;
  return 0;
}

```

// --- Calls: ExSubscribeWnfStateChange at 0x140a17a10 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall ExSubscribeWnfStateChange(__int64 a1, __int64 a2)
{
  struct _KTHREAD *CurrentThread; // rax
  unsigned int v3; // ebx

  CurrentThread = KeGetCurrentThread();
  --CurrentThread->KernelApcDisable;
  v3 = ExpWnfSubscribeWnfStateChange(0, a1, a2);
  KeLeaveCriticalRegion();
  return v3;
}

```

// --- Calls: ExpWnfSubscribeWnfStateChange at 0x140a17b5c (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall ExpWnfSubscribeWnfStateChange(
        __int64 a1,
        __int64 a2,
        void *a3,
        int a4,
        int a5,
        int a6,
        int a7,
        char a8)
{
  ACCESS_MASK v8; // r14d
  int NameInstance; // esi
  unsigned __int64 v10; // rbx
  __int64 v11; // r15
  int v12; // r13d
  _KPROCESS *Process; // rax
  int v14; // eax
  int v15; // r13d
  __int64 v16; // rbx
  BOOL v17; // edx
  int v18; // r8d
  __int64 v19; // r8
  __int64 v21; // [rsp+68h] [rbp-60h] BYREF
  int v22; // [rsp+70h] [rbp-58h] BYREF
  PVOID P; // [rsp+78h] [rbp-50h] BYREF
  _KPROCESS *v24; // [rsp+80h] [rbp-48h]
  int v25[2]; // [rsp+88h] [rbp-40h] BYREF
  unsigned __int64 v26; // [rsp+90h] [rbp-38h]
  struct _EX_RUNDOWN_REF *v27; // [rsp+98h] [rbp-30h] BYREF

  v26 = 0;
  v22 = 0;
  P = 0;
  *(_QWORD *)v25 = 0;
  v21 = 0;
  v27 = 0;
  v8 = 0;
  NameInstance = ExpCaptureWnfStateName(a3);
  if ( NameInstance >= 0 )
  {
    if ( (a7 & 0xFFFFFFE0) != 0 )
    {
      NameInstance = -1073741811;
      goto LABEL_34;
    }
    v10 = v26;
    v11 = (v26 >> 4) & 3;
    if ( a8 )
    {
      v12 = 0;
      v8 = (a7 & 0x11) != 0;
      if ( (a7 & 0xFFFFFFEE) != 0 )
        v8 |= 2u;
    }
    else
    {
      v12 = 1;
    }
    if ( a8 )
    {
      Process = KeGetCurrentThread()->ApcState.Process;
      v10 = v26;
    }
    else
    {
      Process = PsInitialSystemProcess;
    }
    v24 = Process;
    NameInstance = ExpWnfResolveScopeInstance((int)v25, (int)Process, 0, (v26 >> 6) & 0xF, 0);
    if ( NameInstance >= 0 )
    {
      v14 = ExpWnfLookupNameInstance(*(_QWORD *)v25, v10, &v21);
      NameInstance = v14;
      if ( v14 != -1073741772 || (_DWORD)v11 == 3 )
      {
        if ( v14 < 0 )
          goto LABEL_34;
        if ( !v12 )
        {
          NameInstance = ExpWnfCheckCallerAccess(*(PSECURITY_DESCRIPTOR *)(v21 + 72), v8);
          if ( NameInstance < 0 )
            goto LABEL_34;
        }
        v15 = (int)v24;
      }
      else
      {
        NameInstance = ExpWnfLookupPermanentName(v10, &P);
        if ( NameInstance < 0 )
          goto LABEL_34;
        if ( !v12 )
        {
          NameInstance = ExpWnfCheckCallerAccess(*((PSECURITY_DESCRIPTOR *)P + 2), v8);
          if ( NameInstance < 0 )
            goto LABEL_34;
        }
        v15 = (int)v24;
        NameInstance = ExpWnfCreateNameInstance(v25[0], v10, (_DWORD)P, (_DWORD)v24, (__int64)&v21);
        ExFreePoolWithTag(P, 0x20666E57u);
        P = 0;
        if ( NameInstance < 0 )
          goto LABEL_34;
      }
      v16 = v21;
      NameInstance = ExpWnfSubscribeNameInstance(v21, v15, a5, a6, a4, a7, a8, a1, a2, (__int64)&v27, (__int64)&v22);
      if ( NameInstance >= 0 )
      {
        v17 = 0;
        if ( a4 != *(_DWORD *)(v16 + 96) )
          v17 = *(_QWORD *)(v16 + 88) != 0;
        v18 = v17 | 8;
        if ( *(_DWORD *)(v21 + 164) )
          v18 = v17;
        if ( !v22 )
        {
          if ( *(_DWORD *)(v21 + 160) )
            v18 |= 2u;
          else
            v18 |= 4u;
        }
        v19 = a7 & ~v22 & (unsigned int)v18;
        if ( (_DWORD)v19 )
          ExpWnfNotifySubscription(v21, v27, v19, a8 != 0);
      }
    }
  }
LABEL_34:
  if ( v27 )
    ExReleaseRundownProtection_0(v27 + 1);
  if ( v21 )
    ExReleaseRundownProtection_0((PEX_RUNDOWN_REF)(v21 + 8));
  if ( *(_QWORD *)v25 )
    ExReleaseRundownProtection_0((PEX_RUNDOWN_REF)(*(_QWORD *)v25 + 8LL));
  if ( P )
    ExFreePoolWithTag(P, 0x20666E57u);
  return (unsigned int)NameInstance;
}

```

// --- Calls: KeLeaveCriticalRegion at 0x14020b2d0 (Depth: 2) ---
// Language: C/C++
```cpp
void KeLeaveCriticalRegion(void)
{
  KeLeaveCriticalRegionThread(KeGetCurrentThread());
}

```

// --- Calls: PsAttachSiloToCurrentThread at 0x14043c890 (Depth: 1) ---
// Language: C/C++
```cpp
struct _LIST_ENTRY *__fastcall PsAttachSiloToCurrentThread(struct _LIST_ENTRY *a1)
{
  struct _KTHREAD *CurrentThread; // rdx
  struct _LIST_ENTRY *result; // rax

  CurrentThread = KeGetCurrentThread();
  result = CurrentThread[1].WaitBlock[3].WaitListEntry.Blink;
  CurrentThread[1].WaitBlock[3].WaitListEntry.Blink = a1;
  return result;
}

```

// --- Calls: EtwpQuerySiloRegistrySettings at 0x1406442b8 (Depth: 1) ---
// Language: C/C++
```cpp
void __fastcall EtwpQuerySiloRegistrySettings(__int64 a1)
{
  _WORD *v2; // rbx
  _WORD *Pool2; // rax
  unsigned __int64 v4; // rax
  HANDLE v5; // rcx
  void *Src[2]; // [rsp+30h] [rbp-D0h] BYREF
  UNICODE_STRING DestinationString; // [rsp+40h] [rbp-C0h] BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+50h] [rbp-B0h] BYREF
  int v9; // [rsp+80h] [rbp-80h] BYREF
  void **v10; // [rsp+88h] [rbp-78h]
  _QWORD v11[4]; // [rsp+A0h] [rbp-60h] BYREF
  int v12; // [rsp+C0h] [rbp-40h]
  __int16 *v13; // [rsp+C8h] [rbp-38h]
  __int16 v14; // [rsp+130h] [rbp+30h] BYREF
  HANDLE KeyHandle; // [rsp+138h] [rbp+38h] BYREF

  KeyHandle = 0;
  *(&ObjectAttributes.Length + 1) = 0;
  *(&ObjectAttributes.Attributes + 1) = 0;
  DestinationString = 0;
  v14 = 0;
  v2 = 0;
  *(_OWORD *)Src = 0;
  RtlInitUnicodeString(&DestinationString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI");
  ObjectAttributes.Length = 48;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.RootDirectory = 0;
  ObjectAttributes.Attributes = 576;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
  if ( ZwOpenKey(&KeyHandle, 0x20019u, &ObjectAttributes) >= 0 )
  {
    memset_0(v11, 0, 0x70u);
    v12 = 1;
    v11[0] = &EtwpQueryRegistryCallback;
    v9 = 1;
    v11[3] = &v9;
    v11[2] = L"RTBacklogRoot";
    v13 = &v14;
    v10 = Src;
    if ( (int)RtlQueryRegistryValuesEx(0x40000000, KeyHandle, v11, 0, 0) >= 0 )
    {
      if ( Src[1] )
      {
        if ( LOWORD(Src[0]) >= 4u )
        {
          Pool2 = (_WORD *)ExAllocatePool2(0x100u, WORD1(Src[0]) + 2LL, 0x50777445u);
          v2 = Pool2;
          if ( Pool2 )
          {
            memmove(Pool2, Src[1], WORD1(Src[0]));
            v4 = (unsigned __int64)LOWORD(Src[0]) >> 1;
            if ( v2[v4 - 1] != 92 )
            {
              v2[v4] = 92;
              v2[((unsigned __int64)LOWORD(Src[0]) >> 1) + 1] = 0;
            }
          }
        }
      }
    }
  }
  v5 = KeyHandle;
  *(_QWORD *)(a1 + 4112) = v2;
  if ( v5 )
    ZwClose(v5);
  RtlFreeAnsiString((PUNICODE_STRING)Src);
}

```

// --- Calls: RtlInitUnicodeString at 0x14041d920 (Depth: 2) ---
// Language: C/C++
```cpp
void __stdcall RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
  size_t v3; // rax

  *(_QWORD *)&DestinationString->Length = 0;
  DestinationString->Buffer = (wchar_t *)SourceString;
  if ( SourceString )
  {
    v3 = 2 * wcslen(SourceString);
    if ( v3 >= 0xFFFE )
      LOWORD(v3) = -4;
    DestinationString->Length = v3;
    DestinationString->MaximumLength = v3 + 2;
  }
}

```

// --- Calls: ZwOpenKey at 0x14069db30 (Depth: 2) ---
// Language: C/C++
```cpp
NTSTATUS __stdcall ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
  _disable();
  __readeflags();
  return KiServiceInternal(KeyHandle, DesiredAccess, ObjectAttributes);
}

```

// --- Calls: memset_0 at 0x1406b7440 (Depth: 2) ---
// Language: C/C++
```cpp
void *__cdecl memset_0(void *a1, int Val, size_t Size)
{
  void *result; // rax
  __int64 v4; // rdx
  __m128 v5; // xmm0
  char *v6; // r8
  __m128 *v7; // rdx
  _OWORD *v8; // r9
  size_t v9; // r8
  __m128 *v10; // r9
  size_t v11; // r8
  _DWORD *v12; // r9
  size_t v13; // r8

  result = a1;
  v4 = 0x101010101010101LL * (unsigned __int8)Val;
  v5 = _mm_movelh_ps((__m128)(unsigned __int64)v4, (__m128)(unsigned __int64)v4);
  if ( Size >= 0x40 )
  {
    if ( (_isa_info & 2) != 0 && Size >= 0x320 )
      return _memset_repmovs();
    *(__m128 *)a1 = v5;
    v6 = (char *)a1 + Size;
    a1 = (void *)(((unsigned __int64)a1 + 16) & 0xFFFFFFFFFFFFFFF0uLL);
    Size = v6 - (_BYTE *)a1;
    if ( Size >= 0x40 )
    {
      v7 = (__m128 *)((char *)a1 + Size - 16);
      v8 = (_OWORD *)(((unsigned __int64)a1 + Size - 48) & 0xFFFFFFFFFFFFFFF0uLL);
      v9 = Size >> 6;
      do
      {
        *(__m128 *)a1 = v5;
        *((__m128 *)a1 + 1) = v5;
        a1 = (char *)a1 + 64;
        --v9;
        *((__m128 *)a1 - 2) = v5;
        *((__m128 *)a1 - 1) = v5;
      }
      while ( v9 );
      *v8 = v5;
      v8[1] = v5;
      v8[2] = v5;
      *v7 = v5;
      return result;
    }
LABEL_9:
    v10 = (__m128 *)((char *)a1 + Size - 16);
    *(__m128 *)a1 = v5;
    v11 = (Size & 0x20) >> 1;
    *v10 = v5;
    *(__m128 *)((char *)a1 + v11) = v5;
    *(__m128 *)((char *)v10 - v11) = v5;
    return result;
  }
  if ( Size >= 0x10 )
    goto LABEL_9;
  if ( Size < 4 )
  {
    if ( Size )
    {
      *(_BYTE *)a1 = v4;
      if ( Size != 1 )
        *(_WORD *)((char *)a1 + Size - 2) = v4;
    }
  }
  else
  {
    v12 = (char *)a1 + Size - 4;
    *(_DWORD *)a1 = v4;
    v13 = (Size & 8) >> 1;
    *v12 = v4;
    *(_DWORD *)((char *)a1 + v13) = v4;
    *(_DWORD *)((char *)v12 - v13) = v4;
  }
  return result;
}

```

// --- Calls: RtlQueryRegistryValuesEx at 0x1409cfd10 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall RtlQueryRegistryValuesEx(int a1, int a2, int a3, int a4)
{
  ULONG v5; // [rsp+20h] [rbp-18h]

  return RtlpQueryRegistryValues(a1, a2, a3, a4, v5, 1);
}

```

// --- Calls: memmove at 0x1406b7040 (Depth: 2) ---
// Language: C/C++
```cpp
// Alternative name is 'RtlCopyMemory'
// Alternative name is 'RtlMoveMemory'
// Alternative name is 'memcpy'
void *__cdecl memmove(void *a1, const void *Src, size_t Size)
{
  void *result; // rax
  __int64 v4; // r11
  __int64 v5; // rdx
  __int128 v6; // xmm1
  bool v7; // cf
  signed __int64 v8; // rdx
  char v9; // r11
  _BYTE *v10; // rcx
  char v11; // r11
  char *v12; // r11
  signed __int64 v13; // rdx
  __m128 v14; // xmm0
  unsigned __int64 v15; // rcx
  unsigned __int64 v16; // rcx
  __m128 v17; // xmm1
  unsigned __int64 v18; // r8
  unsigned __int64 v19; // r9
  __int128 v20; // xmm1
  __int128 v21; // xmm2
  __int128 v22; // xmm3
  __m128 v23; // xmm4
  unsigned __int64 j; // r9
  unsigned __int64 v25; // r8
  unsigned __int64 v26; // r9
  __m128 v27; // xmm1
  __m128 v28; // xmm2
  __m128 v29; // xmm3
  __m128 v30; // xmm4
  char *v31; // rcx
  __int128 v32; // xmm0
  unsigned __int64 v33; // rcx
  size_t v34; // r8
  _OWORD *v35; // r11
  __int128 v36; // xmm1
  size_t v37; // r9
  __int128 v38; // xmm1
  __int128 v39; // xmm2
  __int128 v40; // xmm3
  __int128 v41; // xmm4
  size_t i; // r9
  size_t v43; // r8

  result = a1;
  if ( Size < 8 )
  {
    if ( Size )
    {
      v7 = Src < a1;
      v8 = (_BYTE *)Src - (_BYTE *)a1;
      if ( v7 )
      {
        v10 = (char *)a1 + Size;
        do
        {
          v11 = v10[v8 - 1];
          --v10;
          --Size;
          *v10 = v11;
        }
        while ( Size );
      }
      else
      {
        do
        {
          v9 = *((_BYTE *)a1 + v8);
          a1 = (char *)a1 + 1;
          --Size;
          *((char *)a1 - 1) = v9;
        }
        while ( Size );
      }
    }
  }
  else if ( Size > 0x10 )
  {
    if ( Size > 0x20 )
    {
      v12 = (char *)Src + Size;
      v7 = Src < a1;
      v13 = (_BYTE *)Src - (_BYTE *)a1;
      if ( v7 && v12 > a1 )
      {
        v31 = (char *)a1 + Size;
        v32 = *(_OWORD *)&v31[v13 - 16];
        v33 = (unsigned __int64)(v31 - 16);
        v34 = Size - 16;
        if ( (v33 & 0xF) != 0 )
        {
          v35 = (_OWORD *)v33;
          v33 &= 0xFFFFFFFFFFFFFFF0uLL;
          v36 = *(_OWORD *)(v33 + v13);
          *v35 = v32;
          v32 = v36;
          v34 = v33 - (_QWORD)result;
        }
        v37 = v34 >> 6;
        if ( v34 >> 6 )
        {
          v34 &= 0x3Fu;
          do
          {
            v38 = *(_OWORD *)(v33 + v13 - 16);
            v39 = *(_OWORD *)(v33 + v13 - 32);
            v40 = *(_OWORD *)(v33 + v13 - 48);
            v41 = *(_OWORD *)(v33 + v13 - 64);
            *(_OWORD *)v33 = v32;
            v33 -= 64LL;
            --v37;
            *(_OWORD *)(v33 + 48) = v38;
            *(_OWORD *)(v33 + 32) = v39;
            *(_OWORD *)(v33 + 16) = v40;
            v32 = v41;
          }
          while ( v37 );
        }
        for ( i = v34 >> 4; i; --i )
        {
          *(_OWORD *)v33 = v32;
          v32 = *(_OWORD *)(v33 + v13 - 16);
          v33 -= 16LL;
        }
        v43 = v34 & 0xF;
        if ( v43 )
          *(_OWORD *)(v33 - v43) = *(_OWORD *)(v33 - v43 + v13);
        *(_OWORD *)v33 = v32;
      }
      else
      {
        v14 = *(__m128 *)((char *)a1 + v13);
        v15 = (unsigned __int64)a1 + 16;
        if ( (v15 & 0xF) != 0 )
        {
          v16 = v15 & 0xFFFFFFFFFFFFFFF0uLL;
          v17 = *(__m128 *)(v16 + v13);
          *(__m128 *)result = v14;
          v14 = v17;
          v15 = v16 + 16;
        }
        v18 = (unsigned __int64)result + Size - v15;
        v19 = v18 >> 6;
        if ( v18 >> 6 )
        {
          if ( v19 > 0x1000 )
          {
            v26 = v18 >> 6;
            v18 &= 0x3Fu;
            _mm_prefetch((const char *)(v15 + v13 + 64), 0);
            do
            {
              v27 = *(__m128 *)(v15 + v13);
              v28 = *(__m128 *)(v15 + v13 + 16);
              v29 = *(__m128 *)(v15 + v13 + 32);
              v30 = *(__m128 *)(v15 + v13 + 48);
              _mm_stream_ps((float *)(v15 - 16), v14);
              v15 += 64LL;
              _mm_prefetch((const char *)(v15 + v13 + 64), 0);
              --v26;
              _mm_stream_ps((float *)(v15 - 64), v27);
              _mm_stream_ps((float *)(v15 - 48), v28);
              _mm_stream_ps((float *)(v15 - 32), v29);
              v14 = v30;
            }
            while ( v26 );
            _mm_sfence();
          }
          else
          {
            v18 &= 0x3Fu;
            do
            {
              v20 = *(_OWORD *)(v15 + v13);
              v21 = *(_OWORD *)(v15 + v13 + 16);
              v22 = *(_OWORD *)(v15 + v13 + 32);
              v23 = *(__m128 *)(v15 + v13 + 48);
              *(__m128 *)(v15 - 16) = v14;
              v15 += 64LL;
              --v19;
              *(_OWORD *)(v15 - 64) = v20;
              *(_OWORD *)(v15 - 48) = v21;
              *(_OWORD *)(v15 - 32) = v22;
              v14 = v23;
            }
            while ( v19 );
          }
        }
        for ( j = v18 >> 4; j; --j )
        {
          *(__m128 *)(v15 - 16) = v14;
          v14 = *(__m128 *)(v15 + v13);
          v15 += 16LL;
        }
        v25 = v18 & 0xF;
        if ( v25 )
          *(_OWORD *)(v15 + v25 - 16) = *(_OWORD *)(v15 + v25 - 16 + v13);
        *(__m128 *)(v15 - 16) = v14;
      }
    }
    else
    {
      v6 = *(_OWORD *)((char *)Src + Size - 16);
      *(_OWORD *)a1 = *(_OWORD *)Src;
      *(_OWORD *)((char *)a1 + Size - 16) = v6;
    }
  }
  else
  {
    v4 = *(_QWORD *)Src;
    v5 = *(_QWORD *)((char *)Src + Size - 8);
    *(_QWORD *)a1 = v4;
    *(_QWORD *)((char *)a1 + Size - 8) = v5;
  }
  return result;
}

```

// --- Calls: ZwClose at 0x14069dad0 (Depth: 2) ---
// Language: C/C++
```cpp
NTSTATUS __stdcall ZwClose(HANDLE Handle)
{
  _disable();
  __readeflags();
  return KiServiceInternal(Handle);
}

```

// --- Calls: RtlFreeAnsiString at 0x14089b2e0 (Depth: 2) ---
// Language: C/C++
```cpp
// Alternative name is 'RtlFreeAnsiString'
// Alternative name is 'RtlFreeUTF8String'
void __stdcall RtlFreeAnsiString(PUNICODE_STRING UnicodeString)
{
  wchar_t *Buffer; // rcx

  Buffer = UnicodeString->Buffer;
  if ( Buffer )
  {
    ExFreePool(Buffer);
    *UnicodeString = 0;
  }
}

```

// --- Calls: EtwpQueryPartitionRegistryInformation at 0x14064400c (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall EtwpQueryPartitionRegistryInformation(
        GUID *a1,
        PVOID *a2,
        _WORD *a3,
        _DWORD *a4,
        _QWORD *a5,
        GUID *a6)
{
  int RegistryValues; // ebx
  ULONG v11; // ebx
  CHAR *Pool2; // rax
  NTSTATUS v13; // eax
  _WORD v15[2]; // [rsp+30h] [rbp-D0h] BYREF
  ULONG UTF8StringActualByteCount; // [rsp+34h] [rbp-CCh] BYREF
  HANDLE KeyHandle; // [rsp+38h] [rbp-C8h] BYREF
  PCWCH UnicodeStringSource[2]; // [rsp+40h] [rbp-C0h] BYREF
  UNICODE_STRING UnicodeString; // [rsp+50h] [rbp-B0h] BYREF
  UNICODE_STRING DestinationString; // [rsp+60h] [rbp-A0h] BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+70h] [rbp-90h] BYREF
  int v22; // [rsp+A0h] [rbp-60h] BYREF
  _DWORD *v23; // [rsp+A8h] [rbp-58h]
  int v24; // [rsp+B0h] [rbp-50h] BYREF
  PCWCH *v25; // [rsp+B8h] [rbp-48h]
  int v26; // [rsp+C0h] [rbp-40h] BYREF
  UNICODE_STRING *p_UnicodeString; // [rsp+C8h] [rbp-38h]
  _QWORD v28[4]; // [rsp+E0h] [rbp-20h] BYREF
  int v29; // [rsp+100h] [rbp+0h]
  void *v30; // [rsp+118h] [rbp+18h]
  const wchar_t *v31; // [rsp+128h] [rbp+28h]
  int *v32; // [rsp+130h] [rbp+30h]
  int v33; // [rsp+138h] [rbp+38h]
  _WORD *v34; // [rsp+140h] [rbp+40h]
  void *v35; // [rsp+150h] [rbp+50h]
  const wchar_t *v36; // [rsp+160h] [rbp+60h]
  int *v37; // [rsp+168h] [rbp+68h]
  int v38; // [rsp+170h] [rbp+70h]
  _WORD *v39; // [rsp+178h] [rbp+78h]

  KeyHandle = 0;
  *(&ObjectAttributes.Length + 1) = 0;
  *(&ObjectAttributes.Attributes + 1) = 0;
  UTF8StringActualByteCount = 0;
  v15[0] = 0;
  DestinationString = 0;
  *a4 = 0;
  *(_OWORD *)UnicodeStringSource = 0;
  UnicodeString = 0;
  RtlInitUnicodeString(&DestinationString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
  ObjectAttributes.Length = 48;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.RootDirectory = 0;
  ObjectAttributes.Attributes = 576;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
  RegistryValues = ZwOpenKey(&KeyHandle, 0x20019u, &ObjectAttributes);
  if ( RegistryValues >= 0 )
  {
    memset_0(v28, 0, 0xE0u);
    v23 = a4;
    v33 = 1;
    v28[0] = &EtwpQueryRegistryCallback;
    v28[3] = &v22;
    v30 = &EtwpQueryRegistryCallback;
    v28[2] = L"ContainerType";
    v24 = 1;
    v29 = 4;
    v22 = 4;
    v32 = &v24;
    v31 = L"ContainerId";
    v34 = v15;
    v25 = UnicodeStringSource;
    v37 = &v26;
    v36 = L"ContainerCorrelationId";
    v39 = v15;
    v35 = &EtwpQueryRegistryCallback;
    v38 = 1;
    v26 = 1;
    p_UnicodeString = &UnicodeString;
    RegistryValues = RtlQueryRegistryValuesEx(0x40000000, (int)KeyHandle, (int)v28, 0);
    if ( RegistryValues >= 0 )
    {
      *a5 = 0;
      if ( (unsigned int)StringToGuidNoBrackets(UnicodeStringSource, a1) )
        *a1 = CPER_EMPTY_GUID;
      if ( !RtlUnicodeToUTF8N(0, 0, &UTF8StringActualByteCount, UnicodeStringSource[1], LOWORD(UnicodeStringSource[0])) )
      {
        v11 = UTF8StringActualByteCount;
        if ( UTF8StringActualByteCount < 0xFFFF )
        {
          Pool2 = (CHAR *)ExAllocatePool2(0x48u, UTF8StringActualByteCount, 0x61777445u);
          *a2 = Pool2;
          if ( Pool2 )
          {
            v13 = RtlUnicodeToUTF8N(
                    Pool2,
                    v11,
                    &UTF8StringActualByteCount,
                    UnicodeStringSource[1],
                    LOWORD(UnicodeStringSource[0]));
            if ( !v13 || v13 == 263 )
            {
              *a3 = UTF8StringActualByteCount;
            }
            else
            {
              ExFreePoolWithTag(*a2, 0x61777445u);
              *a2 = 0;
            }
          }
        }
      }
      RegistryValues = StringToGuidNoBrackets(&UnicodeString, a6);
      if ( RegistryValues )
      {
        RegistryValues = 0;
        *a6 = CPER_EMPTY_GUID;
      }
    }
  }
  if ( KeyHandle )
    ZwClose(KeyHandle);
  RtlFreeAnsiString((PUNICODE_STRING)UnicodeStringSource);
  RtlFreeAnsiString(&UnicodeString);
  return (unsigned int)RegistryValues;
}

```

// --- Calls: StringToGuidNoBrackets at 0x1406446bc (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall StringToGuidNoBrackets(unsigned __int16 *a1, __int64 a2)
{
  unsigned int v2; // r8d
  __int64 v4; // r10
  int v5; // eax
  int v7; // ecx
  int v8; // edx
  unsigned __int64 v9; // rcx
  char v10; // al
  __int64 v11; // rax

  v2 = 0;
  if ( !a1 )
    return 3221225485LL;
  v4 = *((_QWORD *)a1 + 1);
  if ( !v4 || *a1 >> 1 != 36 )
    return 3221225485LL;
  *(_OWORD *)a2 = 0;
  while ( v2 < 0x24 )
  {
    if ( v2 <= 0x17 && (v5 = 8659200, _bittest(&v5, v2)) )
    {
      if ( *(_WORD *)(v4 + 2LL * v2) != 45 )
        return 3221225485LL;
    }
    else
    {
      v7 = *(unsigned __int16 *)(v4 + 2LL * v2);
      if ( (unsigned __int16)(v7 - 48) > 9u )
      {
        if ( (unsigned __int16)(v7 - 97) > 5u )
        {
          if ( (unsigned __int16)(v7 - 65) > 5u )
            return 3221225485LL;
          v8 = v7 - 55;
        }
        else
        {
          v8 = v7 - 87;
        }
      }
      else
      {
        v8 = v7 - 48;
      }
      if ( v2 >= 8 )
      {
        if ( v2 >= 0xD )
        {
          if ( v2 >= 0x12 )
          {
            if ( v2 >= 0x17 )
            {
              v11 = ((v2 - 24) >> 1) + 2;
              v9 = (unsigned int)v11;
              v10 = *(_BYTE *)(v11 + a2 + 8);
            }
            else
            {
              v9 = (unsigned __int64)(v2 - 19) >> 1;
              v10 = *(_BYTE *)(v9 + a2 + 8);
            }
            *(_BYTE *)(v9 + a2 + 8) = v8 + 16 * v10;
          }
          else
          {
            *(_WORD *)(a2 + 6) = v8 + 16 * *(_WORD *)(a2 + 6);
          }
        }
        else
        {
          *(_WORD *)(a2 + 4) = v8 + 16 * *(_WORD *)(a2 + 4);
        }
      }
      else
      {
        *(_DWORD *)a2 = v8 + 16 * *(_DWORD *)a2;
      }
    }
    ++v2;
  }
  return 0;
}

```

// --- Calls: RtlUnicodeToUTF8N at 0x1408a62e0 (Depth: 2) ---
// Language: C/C++
```cpp
NTSTATUS __stdcall RtlUnicodeToUTF8N(
        PCHAR UTF8StringDestination,
        ULONG UTF8StringMaxByteCount,
        PULONG UTF8StringActualByteCount,
        PCWCH UnicodeStringSource,
        ULONG UnicodeStringByteCount)
{
  NTSTATUS v5; // ebx
  unsigned int v6; // r10d
  int v8; // r11d
  CHAR *v9; // rbp
  const WCHAR *v10; // rsi
  int v11; // edx
  __int64 v12; // rdx
  unsigned __int64 v13; // rax
  unsigned __int64 v14; // rdx
  NTSTATUS result; // eax
  const WCHAR *v16; // r10
  unsigned int v17; // edx
  int v18; // r8d
  CHAR v19; // al
  CHAR v20; // al
  unsigned int v21; // eax
  int v22; // r8d
  unsigned int v23; // eax

  v5 = 0;
  v6 = 0;
  v8 = (int)UTF8StringDestination;
  if ( !UnicodeStringSource )
    return -1073741582;
  if ( !UTF8StringDestination )
  {
    if ( UTF8StringActualByteCount )
      return CountUnicodeToUTF8(UnicodeStringSource, UnicodeStringByteCount);
    else
      return -1073741811;
  }
  if ( (UnicodeStringByteCount & 1) != 0 )
    return -1073741581;
  v9 = &UTF8StringDestination[UTF8StringMaxByteCount];
  v10 = &UnicodeStringSource[(unsigned __int64)UnicodeStringByteCount >> 1];
  while ( 1 )
  {
    do
    {
      if ( UnicodeStringSource >= v10 )
      {
        if ( !v6 )
          goto LABEL_16;
        break;
      }
      v11 = *UnicodeStringSource;
      if ( v6 )
      {
        if ( (unsigned int)(v11 - 56320) <= 0x3FF )
        {
          v6 = v11 + (v6 << 10) - 56613888;
          ++UnicodeStringSource;
        }
        break;
      }
      v6 = *UnicodeStringSource++;
LABEL_8:
      ;
    }
    while ( v6 - 55296 <= 0x3FF );
    if ( v6 - 55296 <= 0x7FF )
    {
      v5 = 263;
      v6 = 65533;
LABEL_40:
      v12 = (v6 > 0xFFFF) + 2LL;
      goto LABEL_41;
    }
    v12 = 1;
    if ( v6 <= 0x7F )
      goto LABEL_11;
    if ( v6 > 0x7FF )
      goto LABEL_40;
LABEL_41:
    ++v12;
LABEL_11:
    if ( UTF8StringDestination > &v9[-v12] )
      break;
    if ( v6 > 0x7F )
    {
      if ( v6 <= 0x7FF )
      {
        v20 = (v6 >> 6) | 0xC0;
      }
      else
      {
        if ( v6 > 0xFFFF )
        {
          *UTF8StringDestination++ = (v6 >> 18) | 0xF0;
          v19 = (v6 >> 12) & 0x3F | 0x80;
        }
        else
        {
          v19 = (v6 >> 12) | 0xE0;
        }
        *UTF8StringDestination++ = v19;
        v20 = (v6 >> 6) & 0x3F | 0x80;
      }
      *UTF8StringDestination++ = v20;
      LOBYTE(v6) = v6 & 0x3F | 0x80;
    }
    *UTF8StringDestination++ = v6;
    v13 = v10 - UnicodeStringSource;
    v14 = v9 - UTF8StringDestination;
    if ( v13 > 0xD )
    {
      if ( v14 < v13 )
        v13 = v9 - UTF8StringDestination;
      v16 = &UnicodeStringSource[v13 - 5];
LABEL_26:
      while ( UnicodeStringSource < v16 )
      {
        v17 = *UnicodeStringSource++;
        if ( v17 <= 0x7F )
        {
          *UTF8StringDestination++ = v17;
          if ( ((unsigned __int8)UnicodeStringSource & 2) == 0 )
            goto LABEL_29;
          v17 = *UnicodeStringSource++;
          if ( v17 <= 0x7F )
          {
            *UTF8StringDestination++ = v17;
LABEL_29:
            while ( UnicodeStringSource < v16 )
            {
              v18 = *((_DWORD *)UnicodeStringSource + 1);
              v17 = *(_DWORD *)UnicodeStringSource;
              if ( ((*(_DWORD *)UnicodeStringSource | v18) & 0xFF80FF80) != 0 )
              {
                v17 = (unsigned __int16)v17;
                ++UnicodeStringSource;
                if ( (unsigned __int16)v17 > 0x7Fu )
                  goto LABEL_55;
                *UTF8StringDestination++ = v17;
                goto LABEL_26;
              }
              *UTF8StringDestination = v17;
              UnicodeStringSource += 4;
              UTF8StringDestination[2] = v18;
              UTF8StringDestination[1] = BYTE2(v17);
              UTF8StringDestination[3] = BYTE2(v18);
              UTF8StringDestination += 4;
            }
            break;
          }
        }
LABEL_55:
        if ( v17 > 0x7FF )
        {
          if ( v17 - 55296 > 0x7FF )
          {
            v23 = v17 | 0xE0000;
          }
          else
          {
            if ( v17 > 0xDBFF )
            {
              --UnicodeStringSource;
              break;
            }
            v22 = *UnicodeStringSource++;
            if ( (unsigned int)(v22 - 56320) > 0x3FF )
            {
              UnicodeStringSource -= 2;
              break;
            }
            v17 = v22 + (v17 << 10) - 56613888;
            *UTF8StringDestination++ = (v17 >> 18) | 0xF0;
            v23 = v17 & 0x3F000 | 0x80000;
          }
          --v16;
          *UTF8StringDestination++ = v23 >> 12;
          v21 = v17 & 0xFC0 | 0x2000;
        }
        else
        {
          v21 = v17 | 0x3000;
        }
        *UTF8StringDestination = v21 >> 6;
        --v16;
        UTF8StringDestination[1] = v17 & 0x3F | 0x80;
        UTF8StringDestination += 2;
      }
    }
    else if ( v14 >= v13 )
    {
      while ( UnicodeStringSource < v10 )
      {
        v6 = *UnicodeStringSource++;
        if ( v6 > 0x7F )
          goto LABEL_8;
        *UTF8StringDestination++ = v6;
      }
LABEL_16:
      result = v5;
      goto LABEL_17;
    }
    v6 = 0;
  }
  result = -1073741789;
LABEL_17:
  *UTF8StringActualByteCount = (_DWORD)UTF8StringDestination - v8;
  return result;
}

```

// --- Calls: __security_check_cookie at 0x14069ce00 (Depth: 2) ---
// Language: C/C++
```cpp
void __cdecl _security_check_cookie(uintptr_t StackCookie)
{
  __int64 v1; // rcx

  if ( StackCookie != _security_cookie )
ReportFailure:
    _report_gsfailure(StackCookie);
  v1 = __ROL8__(StackCookie, 16);
  if ( (_WORD)v1 )
  {
    StackCookie = __ROR8__(v1, 16);
    goto ReportFailure;
  }
}

```

// --- Calls: KeQueryPerformanceCounter at 0x14036b0a0 (Depth: 1) ---
// Language: C/C++
```cpp
LARGE_INTEGER __stdcall KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency)
{
  ULONG_PTR v2; // rsi
  LONGLONG v3; // rbx
  __int64 v4; // rcx
  unsigned __int64 v5; // rax
  __int64 v6; // rdx
  LARGE_INTEGER result; // rax
  __int64 v8; // rdx
  unsigned __int64 v9; // rax
  int v10; // r9d
  __int64 v11; // rdx
  __int64 v12; // rdx
  int v13; // ecx
  unsigned __int64 v14; // rax
  int v15; // r9d
  signed __int64 v16; // rdx
  __int64 v17; // r15
  __int64 v18; // r8
  LONGLONG v19; // r8
  __int64 v20; // r15
  __int64 v21; // rdi
  __int64 v22; // rax
  __int64 (__fastcall *v23)(_QWORD); // rdx
  __int64 v24; // rax
  unsigned __int64 v25; // r10
  signed __int64 v26; // rax
  int v27; // r9d
  unsigned __int64 v28; // rcx
  __int64 v29; // rdx
  __int64 v30; // r8
  __int64 v31; // rcx
  unsigned __int64 v32; // r8
  signed __int64 v33; // rdx
  __int64 v34; // rdi
  __int64 InternalData; // rax
  __int64 (__fastcall *v36)(_QWORD); // rdx
  __int64 Counter; // rax
  unsigned __int64 v38; // r10
  signed __int64 v39; // rax
  int v40; // r9d
  unsigned __int64 v41; // rcx
  __int64 v42; // rdx
  __int64 v43; // r8
  __int64 v44; // rcx
  unsigned __int64 v45; // r8
  __int64 v46; // rcx
  __int64 v47; // rcx
  signed __int32 v48[8]; // [rsp+0h] [rbp-48h] BYREF
  signed __int64 v49; // [rsp+58h] [rbp+10h] BYREF
  __int64 v50; // [rsp+60h] [rbp+18h] BYREF

  v2 = HalpPerformanceCounter;
  if ( *(_DWORD *)(HalpPerformanceCounter + 228) == 5 )
  {
    v3 = 10000000;
    if ( HalpTimerReferencePage )
    {
      if ( (*(_DWORD *)(HalpPerformanceCounter + 224) & 0x10000) != 0 )
        v4 = *(_QWORD *)(HalpPerformanceCounter + 72)
           + *(_DWORD *)(HalpPerformanceCounter + 80) * KeGetPcr()->Prcb.Number;
      else
        v4 = *(_QWORD *)(HalpPerformanceCounter + 72);
      v5 = *(_QWORD *)(HalpPerformanceCounter + 112);
      if ( (__int64 (__fastcall *)())v5 == HalpTscQueryCounterOrdered )
      {
        __asm { rdtscp }
        v6 = v5 | ((_QWORD)HalpTscQueryCounterOrdered << 32);
      }
      else
      {
        v6 = guard_dispatch_icall_no_overrides(v4, HalpTscQueryCounterOrdered);
      }
      result.QuadPart = MEMORY[0xFFFFF780000003B8]
                      + (((unsigned __int64)v6 * (unsigned __int128)*((unsigned __int64 *)HalpTimerReferencePage + 1)) >> 64);
      goto LABEL_8;
    }
    if ( *(_DWORD *)(HalpPerformanceCounter + 220) != 64 )
    {
      do
      {
        v17 = *(_QWORD *)(v2 + 208);
        do
        {
          v34 = *(_QWORD *)(v2 + 200);
          InternalData = HalpTimerGetInternalData(v2);
          v36 = *(__int64 (__fastcall **)(_QWORD))(v2 + 112);
          if ( v36 == HalpHpetQueryCounter )
            Counter = HalpHpetQueryCounter(InternalData);
          else
            Counter = guard_dispatch_icall_no_overrides(InternalData, v36);
          v38 = Counter;
          _InterlockedOr(v48, 0);
          v39 = *(_QWORD *)(v2 + 200);
        }
        while ( v34 != v39 );
      }
      while ( v17 != *(_QWORD *)(v2 + 208) );
      v40 = *(_DWORD *)(v2 + 220);
      v41 = v34 ^ v38;
      if ( _bittest64((const __int64 *)&v41, (unsigned __int8)(v40 - 1)) )
      {
        if ( v40 == 64 )
          v43 = -1;
        else
          v43 = (1LL << v40) - 1;
        v44 = 0;
        if ( v40 != 64 )
          v44 = 1LL << v40;
        v45 = v34 & v43;
        v16 = v38 | v34 ^ v45;
        if ( v38 < v45 )
          v16 += v44;
        _InterlockedCompareExchange64((volatile signed __int64 *)(v2 + 200), v16, v39);
      }
      else
      {
        if ( v40 == 64 )
          v42 = -1;
        else
          v42 = (1LL << v40) - 1;
        v16 = v38 | v34 & ~v42;
      }
      goto LABEL_36;
    }
    v12 = HalpTimerGetInternalData(HalpPerformanceCounter);
    if ( *(__int64 (__fastcall **)())(v2 + 112) == HalpHvCounterQueryCounter )
    {
      if ( !HalpHvTimerApi )
      {
        v16 = __readmsr(0x40000020u);
LABEL_35:
        v17 = *(_QWORD *)(v2 + 208);
LABEL_36:
        result.QuadPart = HalpTimerScaleCounter(v17 + v16, *(_QWORD *)(v2 + 192), 10000000);
        goto LABEL_8;
      }
      if ( (__int64 (__fastcall *)())HalpHvTimerApi == HvlGetReferenceTimeUsingTscPage )
      {
        v13 = 0;
        v49 = 0;
        while ( 1 )
        {
          v14 = (unsigned __int64)HvlpReferenceTscPage;
          v15 = *(_DWORD *)HvlpReferenceTscPage;
          if ( !*(_DWORD *)HvlpReferenceTscPage )
            break;
          if ( MEMORY[0xFFFFF78000000294] )
          {
            __asm { rdtscp }
            LODWORD(v49) = v13;
          }
          else
          {
            if ( KeGetCurrentPrcb()->CpuVendor == 2 )
            {
              _mm_lfence();
            }
            else if ( KeGetCurrentPrcb()->CpuVendor == 1 )
            {
              _mm_mfence();
            }
            v14 = __rdtsc();
            LODWORD(v12) = HIDWORD(v14);
            v14 = (unsigned int)v14;
            v12 = (unsigned int)v12;
          }
          v12 = *((_QWORD *)HvlpReferenceTscPage + 2)
              + (((v14 | (v12 << 32)) * (unsigned __int128)*((unsigned __int64 *)HvlpReferenceTscPage + 1)) >> 64);
          v49 = v12;
          v13 = *(_DWORD *)HvlpReferenceTscPage;
          if ( *(_DWORD *)HvlpReferenceTscPage == v15 )
            goto LABEL_34;
        }
        HvlpGetRegister64(589828, &v49);
LABEL_34:
        v16 = v49;
        goto LABEL_35;
      }
      v47 = 0;
    }
    else
    {
      v47 = v12;
    }
    v16 = guard_dispatch_icall_no_overrides(v47, v12);
    goto LABEL_35;
  }
  v3 = *(_QWORD *)(HalpPerformanceCounter + 192);
  if ( *(_DWORD *)(HalpPerformanceCounter + 220) == 64 )
  {
    if ( (*(_DWORD *)(HalpPerformanceCounter + 224) & 0x10000) != 0 )
      v8 = *(_QWORD *)(HalpPerformanceCounter + 72) + *(_DWORD *)(HalpPerformanceCounter + 80) * KeGetPcr()->Prcb.Number;
    else
      v8 = *(_QWORD *)(HalpPerformanceCounter + 72);
    if ( *(__int64 (__fastcall **)())(HalpPerformanceCounter + 112) == HalpHvCounterQueryCounter )
    {
      if ( !HalpHvTimerApi )
      {
        result.QuadPart = *(_QWORD *)(HalpPerformanceCounter + 208) + __readmsr(0x40000020u);
        goto LABEL_8;
      }
      if ( (__int64 (__fastcall *)())HalpHvTimerApi == HvlGetReferenceTimeUsingTscPage )
      {
        v50 = 0;
        while ( 1 )
        {
          v9 = (unsigned __int64)HvlpReferenceTscPage;
          v10 = *(_DWORD *)HvlpReferenceTscPage;
          if ( !*(_DWORD *)HvlpReferenceTscPage )
            break;
          if ( MEMORY[0xFFFFF78000000294] )
          {
            __asm { rdtscp }
          }
          else
          {
            if ( KeGetCurrentPrcb()->CpuVendor == 2 )
            {
              _mm_lfence();
            }
            else if ( KeGetCurrentPrcb()->CpuVendor == 1 )
            {
              _mm_mfence();
            }
            v9 = __rdtsc();
            LODWORD(v8) = HIDWORD(v9);
            v9 = (unsigned int)v9;
            v8 = (unsigned int)v8;
          }
          v8 = *((_QWORD *)HvlpReferenceTscPage + 2)
             + (((v9 | (v8 << 32)) * (unsigned __int128)*((unsigned __int64 *)HvlpReferenceTscPage + 1)) >> 64);
          v50 = v8;
          if ( *(_DWORD *)HvlpReferenceTscPage == v10 )
            goto LABEL_23;
        }
        HvlpGetRegister64(589828, &v50);
LABEL_23:
        v11 = v50;
        goto LABEL_24;
      }
      v46 = 0;
    }
    else
    {
      v46 = v8;
    }
    v11 = guard_dispatch_icall_no_overrides(v46, v8);
LABEL_24:
    result.QuadPart = *(_QWORD *)(v2 + 208) + v11;
    goto LABEL_8;
  }
  do
  {
    v20 = *(_QWORD *)(v2 + 208);
    do
    {
      v21 = *(_QWORD *)(v2 + 200);
      v22 = HalpTimerGetInternalData(v2);
      v23 = *(__int64 (__fastcall **)(_QWORD))(v2 + 112);
      if ( v23 == HalpHpetQueryCounter )
        v24 = HalpHpetQueryCounter(v22);
      else
        v24 = guard_dispatch_icall_no_overrides(v22, v23);
      v25 = v24;
      _InterlockedOr(v48, 0);
      v26 = *(_QWORD *)(v2 + 200);
    }
    while ( v21 != v26 );
  }
  while ( v20 != *(_QWORD *)(v2 + 208) );
  v27 = *(_DWORD *)(v2 + 220);
  v28 = v21 ^ v25;
  if ( _bittest64((const __int64 *)&v28, (unsigned __int8)(v27 - 1)) )
  {
    if ( v27 == 64 )
      v30 = -1;
    else
      v30 = (1LL << v27) - 1;
    v31 = 0;
    if ( v27 != 64 )
      v31 = 1LL << v27;
    v32 = v21 & v30;
    v33 = v25 | v21 ^ v32;
    if ( v25 < v32 )
      v33 += v31;
    _InterlockedCompareExchange64((volatile signed __int64 *)(v2 + 200), v33, v26);
    result.QuadPart = v20 + v33;
  }
  else
  {
    if ( v27 == 64 )
      v29 = -1;
    else
      v29 = (1LL << v27) - 1;
    result.QuadPart = v20 + (v25 | v21 & ~v29);
  }
LABEL_8:
  if ( v2 == HalpOriginalPerformanceCounter || !HalpOriginalPerformanceCounter )
  {
    if ( PerformanceFrequency )
      PerformanceFrequency->QuadPart = v3;
  }
  else
  {
    v18 = *(_QWORD *)(HalpOriginalPerformanceCounter + 192);
    if ( *(_DWORD *)(HalpOriginalPerformanceCounter + 228) == 5 )
      v18 = 10000000;
    result.QuadPart = ((__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))HalpTimerScaleCounter)(
                        (LARGE_INTEGER)result.QuadPart,
                        v3,
                        v18);
    if ( PerformanceFrequency )
      PerformanceFrequency->QuadPart = v19;
  }
  return result;
}

```

// --- Calls: HalpTimerGetInternalData at 0x1402eac20 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall HalpTimerGetInternalData(__int64 a1)
{
  if ( (*(_DWORD *)(a1 + 224) & 0x10000) != 0 )
    return *(_QWORD *)(a1 + 72) + *(_DWORD *)(a1 + 80) * KeGetPcr()->Prcb.Number;
  else
    return *(_QWORD *)(a1 + 72);
}

```

// --- Calls: HalpTimerScaleCounter at 0x1402b9e70 (Depth: 2) ---
// Language: C/C++
```cpp
unsigned __int64 __fastcall HalpTimerScaleCounter(unsigned __int64 a1, unsigned __int64 a2, __int64 a3)
{
  if ( a1 && a2 && a2 != a3 )
    return a3 * (a1 / a2) + a3 * (a1 % a2) / a2;
  else
    return a1;
}

```

// --- Calls: HalpHpetQueryCounter at 0x1403c2860 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 HalpHpetQueryCounter()
{
  return *(unsigned int *)(HalpHpetBaseAddress + 240);
}

```

// --- Calls: HvlpGetRegister64 at 0x1403c2880 (Depth: 2) ---
// Language: C/C++
```cpp
unsigned __int64 __fastcall HvlpGetRegister64(int a1, unsigned __int64 *a2)
{
  int v3; // ecx
  int v4; // ecx
  unsigned int v5; // ecx
  unsigned __int64 result; // rax
  int v7; // ecx
  int v8; // ecx
  int v9; // ecx
  int v10; // ecx
  int v11; // ecx
  int v12; // ecx
  int v13; // ecx
  int v14; // ecx
  int v15; // ecx
  bool v16; // zf
  int v17; // ecx
  int v18; // ecx
  int v19; // ecx
  int v20; // ecx
  int v21; // ecx
  int v22; // ecx
  int v23; // ecx
  int v24; // ecx
  int v25; // ecx
  int v26; // ecx
  int v27; // ecx

  if ( a1 > 655362 )
  {
    if ( a1 <= 655370 )
    {
      if ( a1 == 655370 )
        goto LABEL_32;
      v18 = a1 - 655363;
      if ( !v18 )
        goto LABEL_32;
      v19 = v18 - 1;
      if ( !v19 )
        goto LABEL_32;
      v20 = v19 - 1;
      if ( !v20 )
        goto LABEL_32;
      v21 = v20 - 1;
      if ( !v21 )
        goto LABEL_32;
      v22 = v21 - 1;
      if ( !v22 )
        goto LABEL_32;
      v17 = v22 - 1;
      v16 = v17 == 0;
      goto LABEL_37;
    }
    v23 = a1 - 655371;
    if ( !v23 )
      goto LABEL_32;
    v24 = v23 - 1;
    if ( !v24 )
      goto LABEL_32;
    v25 = v24 - 1;
    if ( !v25 )
      goto LABEL_32;
    v26 = v25 - 1;
    if ( !v26 )
      goto LABEL_32;
    v27 = v26 - 1;
    if ( !v27 )
      goto LABEL_32;
    if ( v27 == 4 )
    {
      v5 = 1073741955;
      goto LABEL_7;
    }
  }
  else
  {
    if ( a1 == 655362 )
      goto LABEL_32;
    if ( a1 > 589826 )
    {
      v3 = a1 - 589827;
      if ( !v3 )
      {
        v5 = 1073741826;
        goto LABEL_7;
      }
      v4 = v3 - 1;
      if ( !v4 )
      {
        v5 = 1073741856;
LABEL_7:
        result = __readmsr(v5);
        *a2 = result;
        return result;
      }
      v13 = v4 - 3;
      if ( !v13 )
      {
        v5 = 1073741828;
        goto LABEL_7;
      }
      v14 = v13 - 12;
      if ( !v14 )
      {
        v5 = 1073741939;
        goto LABEL_7;
      }
      v15 = v14 - 4;
      if ( !v15 )
      {
        v5 = 1073741857;
        goto LABEL_7;
      }
      v17 = v15 - 65513;
      v16 = v17 == 0;
LABEL_37:
      if ( !v16 && v17 != 1 )
        return RtlRaiseException((ULONG_PTR)&qword_140E0A880);
LABEL_32:
      v5 = a1 + 1073086608;
      goto LABEL_7;
    }
    if ( a1 == 589826 )
    {
      v5 = 0x40000000;
      goto LABEL_7;
    }
    v7 = a1 - 528;
    if ( !v7 || (v8 = v7 - 1) == 0 || (v9 = v8 - 1) == 0 || (v10 = v9 - 1) == 0 || (v11 = v10 - 1) == 0 )
    {
      v5 = a1 + 1073741552;
      goto LABEL_7;
    }
    v12 = v11 - 1;
    if ( !v12 )
    {
      v5 = 1073742085;
      goto LABEL_7;
    }
    if ( v12 == 91 )
    {
      v5 = 1073742102;
      goto LABEL_7;
    }
  }
  return RtlRaiseException((ULONG_PTR)&qword_140E0A880);
}

```

// --- Calls: _guard_dispatch_icall_no_overrides at 0x1406ab2d0 (Depth: 2) ---
// Language: Assembly
```cpp
.text:00000001406AB2D0
.text:00000001406AB2D0 ; =============== S U B R O U T I N E =========…
.text:00000001406AB2D0
.text:00000001406AB2D0
.text:00000001406AB2D0 ; __int64 __fastcall guard_dispatch_icall_no_ov…
.text:00000001406AB2D0 _guard_dispatch_icall_no_overrides proc near
.text:00000001406AB2D0                                         ; CODE …
.text:00000001406AB2D0                                         ; KiExp…
.text:00000001406AB2D0 ; __unwind { // _guard_icall_handler
.text:00000001406AB2D0                 mov     r11, cs:_guard_icall_bi…
.text:00000001406AB2D7                 test    rax, rax
.text:00000001406AB2DA                 jge     loc_1406AB35A
.text:00000001406AB2E0                 test    r11, r11
.text:00000001406AB2E3                 jz      short loc_1406AB301
.text:00000001406AB2E5                 mov     r10, rax
.text:00000001406AB2E8                 shr     r10, 9
.text:00000001406AB2EC                 mov     r11, [r11+r10*8]
.text:00000001406AB2F0                 mov     r10, rax
.text:00000001406AB2F3                 shr     r10, 3
.text:00000001406AB2F7                 test    al, 0Fh
.text:00000001406AB2F9                 jnz     short loc_1406AB343
.text:00000001406AB2FB                 bt      r11, r10
.text:00000001406AB2FF                 jnb     short loc_1406AB35A
.text:00000001406AB301
.text:00000001406AB301 loc_1406AB301:                          ; CODE …
.text:00000001406AB301                                         ; _guar…
.text:00000001406AB301                 mov     r11, cs:_retpoline_imag…
.text:00000001406AB308                 mov     r10, rax
.text:00000001406AB30B                 test    r11, r11
.text:00000001406AB30E                 jz      short loc_1406AB33E
.text:00000001406AB310                 shr     r10, 10h
.text:00000001406AB314                 bt      [r11], r10
.text:00000001406AB318                 jnb     short loc_1406AB325
.text:00000001406AB31A                 call    loc_1406AB320
.text:00000001406AB31A ; ---------------------------------------------…
.text:00000001406AB31F                 align 20h
.text:00000001406AB320
.text:00000001406AB320 loc_1406AB320:                          ; CODE …
.text:00000001406AB320                 mov     [rsp+0], rax
.text:00000001406AB324                 retn
.text:00000001406AB325 ; ---------------------------------------------…
.text:00000001406AB325
.text:00000001406AB325 loc_1406AB325:                          ; CODE …
.text:00000001406AB325                 or      byte ptr gs:85Eh, 1
.text:00000001406AB32E                 test    byte ptr gs:85Eh, 2
.text:00000001406AB337                 jnz     short loc_1406AB33E
.text:00000001406AB339                 jmp     __guard_retpoline_exit_…
.text:00000001406AB33E ; ---------------------------------------------…
.text:00000001406AB33E
.text:00000001406AB33E loc_1406AB33E:                          ; CODE …
.text:00000001406AB33E                                         ; _guar…
.text:00000001406AB33E                 lfence
.text:00000001406AB341                 jmp     rax
.text:00000001406AB343 ; ---------------------------------------------…
.text:00000001406AB343
.text:00000001406AB343 loc_1406AB343:                          ; CODE …
.text:00000001406AB343                 btr     r10, 0
.text:00000001406AB348                 bt      r11, r10
.text:00000001406AB34C                 jnb     short loc_1406AB35A
.text:00000001406AB34E                 or      r10, 1
.text:00000001406AB352                 bt      r11, r10
.text:00000001406AB356                 jnb     short loc_1406AB35A
.text:00000001406AB358                 jmp     short loc_1406AB301
.text:00000001406AB35A ; ---------------------------------------------…
.text:00000001406AB35A
.text:00000001406AB35A loc_1406AB35A:                          ; CODE …
.text:00000001406AB35A                                         ; _guar…
.text:00000001406AB35A                 mov     rcx, rax        ; BugCh…
.text:00000001406AB35D                 jmp     _guard_icall_bugcheck
.text:00000001406AB35D ; } // starts at 1406AB2D0
.text:00000001406AB35D _guard_dispatch_icall_no_overrides endp
.text:00000001406AB35D
.text:00000001406AB35D ; ---------------------------------------------…

```

// --- Calls: EtwpInitializeAutoLoggers at 0x1407a4ed4 (Depth: 1) ---
// Language: Assembly
```cpp
PAGE:00000001407A4ED4
PAGE:00000001407A4ED4 ; =============== S U B R O U T I N E ==========…
PAGE:00000001407A4ED4
PAGE:00000001407A4ED4 ; Attributes: bp-based frame fpd=120h
PAGE:00000001407A4ED4
PAGE:00000001407A4ED4 ; __int64 __fastcall EtwpInitializeAutoLoggers(_…
PAGE:00000001407A4ED4 EtwpInitializeAutoLoggers proc near     ; CODE X…
PAGE:00000001407A4ED4                                         ; DATA X…
PAGE:00000001407A4ED4
PAGE:00000001407A4ED4 TableContext    = qword ptr -200h
PAGE:00000001407A4ED4 var_1F8         = dword ptr -1F8h
PAGE:00000001407A4ED4 var_1F0         = qword ptr -1F0h
PAGE:00000001407A4ED4 NewElement      = byte ptr -1E0h
PAGE:00000001407A4ED4 var_1DC         = qword ptr -1DCh
PAGE:00000001407A4ED4 Table           = RTL_AVL_TABLE ptr -1D0h
PAGE:00000001407A4ED4 SourceString    = word ptr -160h
PAGE:00000001407A4ED4 var_150         = qword ptr -150h
PAGE:00000001407A4ED4 var_148         = word ptr -148h
PAGE:00000001407A4ED4 Path            = word ptr -140h
PAGE:00000001407A4ED4 var_B0          = byte ptr -0B0h
PAGE:00000001407A4ED4 var_20          = qword ptr -20h
PAGE:00000001407A4ED4 var_10          = byte ptr -10h
PAGE:00000001407A4ED4
PAGE:00000001407A4ED4 ; __unwind { // __GSHandlerCheck
PAGE:00000001407A4ED4                 mov     rax, rsp
PAGE:00000001407A4ED7                 mov     [rax+10h], rbx
PAGE:00000001407A4EDB                 mov     [rax+18h], rsi
PAGE:00000001407A4EDF                 mov     [rax+20h], rdi
PAGE:00000001407A4EE3                 push    rbp
PAGE:00000001407A4EE4                 push    r14
PAGE:00000001407A4EE6                 push    r15
PAGE:00000001407A4EE8                 lea     rbp, [rax-128h]
PAGE:00000001407A4EEF                 sub     rsp, 210h
PAGE:00000001407A4EF6                 mov     rax, cs:__security_cooki…
PAGE:00000001407A4EFD                 xor     rax, rsp
PAGE:00000001407A4F00                 mov     [rbp+120h+var_20], rax
PAGE:00000001407A4F07                 mov     r8d, 80h
PAGE:00000001407A4F0D                 lea     rdx, cs:140000000h
PAGE:00000001407A4F14                 lea     rax, rva aRegistryMachin…
PAGE:00000001407A4F1B                 mov     rdi, rcx
PAGE:00000001407A4F1E                 movups  xmm0, xmmword ptr [rax]
PAGE:00000001407A4F21                 lea     rcx, [rbp+120h+Path]
PAGE:00000001407A4F25                 movups  xmm1, xmmword ptr [rax+1…
PAGE:00000001407A4F29                 movups  xmmword ptr [rcx], xmm0
PAGE:00000001407A4F2C                 movups  xmm0, xmmword ptr [rax+2…
PAGE:00000001407A4F30                 movups  xmmword ptr [rcx+10h], x…
PAGE:00000001407A4F34                 movups  xmm1, xmmword ptr [rax+3…
PAGE:00000001407A4F38                 movups  xmmword ptr [rcx+20h], x…
PAGE:00000001407A4F3C                 movups  xmm0, xmmword ptr [rax+4…
PAGE:00000001407A4F40                 movups  xmmword ptr [rcx+30h], x…
PAGE:00000001407A4F44                 movups  xmm1, xmmword ptr [rax+5…
PAGE:00000001407A4F48                 movups  xmmword ptr [rcx+40h], x…
PAGE:00000001407A4F4C                 movups  xmm0, xmmword ptr [rax+6…
PAGE:00000001407A4F50                 movups  xmmword ptr [rcx+50h], x…
PAGE:00000001407A4F54                 movups  xmmword ptr [rcx+60h], x…
PAGE:00000001407A4F58                 movups  xmm0, xmmword ptr [rax+7…
PAGE:00000001407A4F5C                 mov     eax, [rax+r8]
PAGE:00000001407A4F60                 movups  xmmword ptr [rcx+r8-10h]…
PAGE:00000001407A4F66                 mov     [rcx+r8], eax
PAGE:00000001407A4F6A                 lea     rax, rva aRegistryMachin…
PAGE:00000001407A4F71                 movups  xmm0, xmmword ptr [rax]
PAGE:00000001407A4F74                 lea     rcx, [rbp+120h+var_B0]
PAGE:00000001407A4F78                 xor     edx, edx        ; Val
PAGE:00000001407A4F7A                 movups  xmm1, xmmword ptr [rax+1…
PAGE:00000001407A4F7E                 movups  xmmword ptr [rcx], xmm0
PAGE:00000001407A4F81                 movups  xmm0, xmmword ptr [rax+2…
PAGE:00000001407A4F85                 movups  xmmword ptr [rcx+10h], x…
PAGE:00000001407A4F89                 movups  xmm1, xmmword ptr [rax+3…
PAGE:00000001407A4F8D                 movups  xmmword ptr [rcx+20h], x…
PAGE:00000001407A4F91                 movups  xmm0, xmmword ptr [rax+4…
PAGE:00000001407A4F95                 movups  xmmword ptr [rcx+30h], x…
PAGE:00000001407A4F99                 movups  xmm1, xmmword ptr [rax+5…
PAGE:00000001407A4F9D                 movups  xmmword ptr [rcx+40h], x…
PAGE:00000001407A4FA1                 movups  xmm0, xmmword ptr [rax+6…
PAGE:00000001407A4FA5                 movups  xmmword ptr [rcx+50h], x…
PAGE:00000001407A4FA9                 movups  xmm1, xmmword ptr [rax+7…
PAGE:00000001407A4FAD                 mov     rax, [rax+r8]
PAGE:00000001407A4FB1                 movups  xmmword ptr [rcx+60h], x…
PAGE:00000001407A4FB5                 movups  xmm0, xmmword ptr cs:aGl…
PAGE:00000001407A4FBC                 movups  xmmword ptr [rcx+r8-10h]…
PAGE:00000001407A4FC2                 mov     [rcx+r8], rax
PAGE:00000001407A4FC6                 lea     r8d, [rdx+68h]  ; Size
PAGE:00000001407A4FCA                 movzx   eax, word ptr cs:aGlobal…
PAGE:00000001407A4FD1                 lea     rcx, [rsp+220h+Table] ; …
PAGE:00000001407A4FD6                 movups  xmmword ptr [rbp+120h+So…
PAGE:00000001407A4FDA                 mov     [rbp+120h+var_148], ax
PAGE:00000001407A4FDE                 movsd   xmm0, qword ptr cs:aGlob…
PAGE:00000001407A4FE6                 movsd   [rbp+120h+var_150], xmm0
PAGE:00000001407A4FEB                 call    memset_0
PAGE:00000001407A4FF0                 xor     esi, esi
PAGE:00000001407A4FF2                 lea     r9, EtwpFreeKeyNameEntry…
PAGE:00000001407A4FF9                 lea     r8, EtwpAllocateKeyNameE…
PAGE:00000001407A5000                 mov     [rsp+220h+TableContext],…
PAGE:00000001407A5005                 lea     rdx, EtwpAvlCompareKeyNa…
PAGE:00000001407A500C                 lea     rcx, [rsp+220h+Table] ; …
PAGE:00000001407A5011                 call    RtlInitializeGenericTabl…
PAGE:00000001407A5016                 test    rdi, rdi
PAGE:00000001407A5019                 jz      short loc_1407A5066
PAGE:00000001407A501B                 lea     rbx, [rdi+8]
PAGE:00000001407A501F                 cmp     [rbx], rbx
PAGE:00000001407A5022                 jz      short loc_1407A5066
PAGE:00000001407A5024                 mov     rdx, rdi
PAGE:00000001407A5027                 lea     rcx, [rbp+120h+Path]
PAGE:00000001407A502B                 call    EtwpEnableBootLoggerRegi…
PAGE:00000001407A5030                 mov     rdi, [rbx]
PAGE:00000001407A5033                 jmp     short loc_1407A5061
PAGE:00000001407A5035 ; ----------------------------------------------…
PAGE:00000001407A5035
PAGE:00000001407A5035 loc_1407A5035:                          ; CODE X…
PAGE:00000001407A5035                 mov     rdx, [rdi+10h]  ; Buffer
PAGE:00000001407A5039                 or      r8, 0FFFFFFFFFFFFFFFFh
PAGE:00000001407A503D
PAGE:00000001407A503D loc_1407A503D:                          ; CODE X…
PAGE:00000001407A503D                 inc     r8
PAGE:00000001407A5040                 cmp     [rdx+r8*2], si
PAGE:00000001407A5045                 jnz     short loc_1407A503D
PAGE:00000001407A5047                 lea     r8d, ds:2[r8*2] ; Buffer…
PAGE:00000001407A504F                 lea     r9, [rsp+220h+NewElement…
PAGE:00000001407A5054                 lea     rcx, [rsp+220h+Table] ; …
PAGE:00000001407A5059                 call    RtlInsertElementGenericT…
PAGE:00000001407A505E                 mov     rdi, [rdi]
PAGE:00000001407A5061
PAGE:00000001407A5061 loc_1407A5061:                          ; CODE X…
PAGE:00000001407A5061                 cmp     rdi, rbx
PAGE:00000001407A5064                 jnz     short loc_1407A5035
PAGE:00000001407A5066
PAGE:00000001407A5066 loc_1407A5066:                          ; CODE X…
PAGE:00000001407A5066                                         ; EtwpIn…
PAGE:00000001407A5066                 mov     r14d, 74777445h
PAGE:00000001407A506C                 mov     r15d, 208h
PAGE:00000001407A5072                 mov     ebx, 100h
PAGE:00000001407A5077                 mov     r8d, r14d
PAGE:00000001407A507A                 mov     edx, r15d
PAGE:00000001407A507D                 mov     ecx, ebx        ; BugChe…
PAGE:00000001407A507F                 call    ExAllocatePool2
PAGE:00000001407A5084                 mov     rdi, rax
PAGE:00000001407A5087                 test    rax, rax
PAGE:00000001407A508A                 jz      loc_1407A5171
PAGE:00000001407A5090                 lea     rax, [rsp+220h+var_1DC]
PAGE:00000001407A5095                 xor     r9d, r9d
PAGE:00000001407A5098                 mov     [rsp+220h+var_1F0], rax …
PAGE:00000001407A509D                 lea     rcx, aEtwautologgerp ; "…
PAGE:00000001407A50A4                 mov     [rsp+220h+var_1F8], r15d…
PAGE:00000001407A50A9                 xor     r8d, r8d
PAGE:00000001407A50AC                 xor     edx, edx
PAGE:00000001407A50AE                 mov     [rsp+220h+TableContext],…
PAGE:00000001407A50B3                 call    RtlGetPersistedStateLoca…
PAGE:00000001407A50B8                 test    eax, eax
PAGE:00000001407A50BA                 jz      short loc_1407A50CA
PAGE:00000001407A50BC                 mov     edx, r14d       ; Tag
PAGE:00000001407A50BF                 mov     rcx, rdi        ; P
PAGE:00000001407A50C2                 call    ExFreePoolWithTag
PAGE:00000001407A50C7                 mov     rdi, rsi
PAGE:00000001407A50CA
PAGE:00000001407A50CA loc_1407A50CA:                          ; CODE X…
PAGE:00000001407A50CA                 mov     r8d, r14d
PAGE:00000001407A50CD                 mov     rdx, r15
PAGE:00000001407A50D0                 mov     rcx, rbx        ; BugChe…
PAGE:00000001407A50D3                 call    ExAllocatePool2
PAGE:00000001407A50D8                 mov     rbx, rax
PAGE:00000001407A50DB                 test    rax, rax
PAGE:00000001407A50DE                 jz      short loc_1407A5151
PAGE:00000001407A50E0                 lea     rax, [rsp+220h+var_1DC]
PAGE:00000001407A50E5                 xor     r9d, r9d
PAGE:00000001407A50E8                 mov     [rsp+220h+var_1F0], rax …
PAGE:00000001407A50ED                 lea     rcx, aEtwgloballogge ; "…
PAGE:00000001407A50F4                 mov     [rsp+220h+var_1F8], r15d…
PAGE:00000001407A50F9                 xor     r8d, r8d
PAGE:00000001407A50FC                 xor     edx, edx
PAGE:00000001407A50FE                 mov     [rsp+220h+TableContext],…
PAGE:00000001407A5103                 call    RtlGetPersistedStateLoca…
PAGE:00000001407A5108                 test    eax, eax
PAGE:00000001407A510A                 jz      short loc_1407A511A
PAGE:00000001407A510C                 mov     edx, r14d       ; Tag
PAGE:00000001407A510F                 mov     rcx, rbx        ; P
PAGE:00000001407A5112                 call    ExFreePoolWithTag
PAGE:00000001407A5117                 mov     rbx, rsi
PAGE:00000001407A511A
PAGE:00000001407A511A loc_1407A511A:                          ; CODE X…
PAGE:00000001407A511A                 mov     r8, rbx
PAGE:00000001407A511D                 lea     rdx, [rbp+120h+var_B0]
PAGE:00000001407A5121                 lea     rcx, [rbp+120h+SourceStr…
PAGE:00000001407A5125                 call    EtwStartAutoLogger
PAGE:00000001407A512A                 lea     r8, [rsp+220h+Table]
PAGE:00000001407A512F                 mov     rdx, rdi
PAGE:00000001407A5132                 lea     rcx, [rbp+120h+Path] ; P…
PAGE:00000001407A5136                 call    EtwpEnumerateAutologgerP…
PAGE:00000001407A513B                 test    rdi, rdi
PAGE:00000001407A513E                 jz      short loc_1407A5161
PAGE:00000001407A5140                 lea     r8, [rsp+220h+Table]
PAGE:00000001407A5145                 xor     edx, edx
PAGE:00000001407A5147                 mov     rcx, rdi        ; Path
PAGE:00000001407A514A                 call    EtwpEnumerateAutologgerP…
PAGE:00000001407A514F                 jmp     short loc_1407A5156
PAGE:00000001407A5151 ; ----------------------------------------------…
PAGE:00000001407A5151
PAGE:00000001407A5151 loc_1407A5151:                          ; CODE X…
PAGE:00000001407A5151                 test    rdi, rdi
PAGE:00000001407A5154                 jz      short loc_1407A5171
PAGE:00000001407A5156
PAGE:00000001407A5156 loc_1407A5156:                          ; CODE X…
PAGE:00000001407A5156                 mov     edx, r14d       ; Tag
PAGE:00000001407A5159                 mov     rcx, rdi        ; P
PAGE:00000001407A515C                 call    ExFreePoolWithTag
PAGE:00000001407A5161
PAGE:00000001407A5161 loc_1407A5161:                          ; CODE X…
PAGE:00000001407A5161                 test    rbx, rbx
PAGE:00000001407A5164                 jz      short loc_1407A5171
PAGE:00000001407A5166                 mov     edx, r14d       ; Tag
PAGE:00000001407A5169                 mov     rcx, rbx        ; P
PAGE:00000001407A516C                 call    ExFreePoolWithTag
PAGE:00000001407A5171
PAGE:00000001407A5171 loc_1407A5171:                          ; CODE X…
PAGE:00000001407A5171                                         ; EtwpIn…
PAGE:00000001407A5171                 lea     rcx, [rsp+220h+Table] ; …
PAGE:00000001407A5176                 call    EtwpFreeKeyNameList
PAGE:00000001407A517B                 mov     rcx, [rbp+120h+var_20]
PAGE:00000001407A5182                 xor     rcx, rsp        ; StackC…
PAGE:00000001407A5185                 call    __security_check_cookie
PAGE:00000001407A518A                 lea     r11, [rsp+220h+var_10]
PAGE:00000001407A5192                 mov     rbx, [r11+28h]
PAGE:00000001407A5196                 mov     rsi, [r11+30h]
PAGE:00000001407A519A                 mov     rdi, [r11+38h]
PAGE:00000001407A519E                 mov     rsp, r11
PAGE:00000001407A51A1                 pop     r15
PAGE:00000001407A51A3                 pop     r14
PAGE:00000001407A51A5                 pop     rbp
PAGE:00000001407A51A6                 retn
PAGE:00000001407A51A6 ; ----------------------------------------------…
PAGE:00000001407A51A7                 db 0CCh
PAGE:00000001407A51A7 ; } // starts at 1407A4ED4
PAGE:00000001407A51A7 EtwpInitializeAutoLoggers endp
PAGE:00000001407A51A7

```

// --- Calls: RtlInitializeGenericTableAvl at 0x14045f450 (Depth: 2) ---
// Language: C/C++
```cpp
void __stdcall RtlInitializeGenericTableAvl(
        PRTL_AVL_TABLE Table,
        PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
        PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
        PRTL_AVL_FREE_ROUTINE FreeRoutine,
        PVOID TableContext)
{
  memset_0(Table, 0, sizeof(RTL_AVL_TABLE));
  Table->CompareRoutine = (_RTL_GENERIC_COMPARE_RESULTS (__fastcall *)(_RTL_AVL_TABLE *, void *, void *))CompareRoutine;
  Table->FreeRoutine = (void (__fastcall *)(_RTL_AVL_TABLE *, void *))FreeRoutine;
  Table->TableContext = TableContext;
  Table->BalancedRoot.Parent = &Table->BalancedRoot;
  Table->AllocateRoutine = (void *(__fastcall *)(_RTL_AVL_TABLE *, unsigned int))AllocateRoutine;
}

```

// --- Calls: EtwpEnableBootLoggerRegistryProviders at 0x140c3428c (Depth: 2) ---
// Language: C/C++
```cpp
void __fastcall EtwpEnableBootLoggerRegistryProviders(__int64 a1, __int64 a2)
{
  __int64 v3; // rax
  ULONG_PTR v5; // r15
  wchar_t *Pool2; // rsi
  _QWORD *v7; // rdi
  _QWORD *i; // rbx
  const WCHAR *v9; // r14
  __int64 v10; // rax
  __int64 v11; // r14
  UNICODE_STRING DestinationString; // [rsp+30h] [rbp-28h] BYREF

  DestinationString = 0;
  v3 = -1;
  do
    ++v3;
  while ( *(_WORD *)(a1 + 2 * v3) );
  v5 = (unsigned int)(2 * v3 + 260);
  Pool2 = (wchar_t *)ExAllocatePool2(0x100u, v5, 0x74777445u);
  if ( Pool2 )
  {
    v7 = (_QWORD *)(a2 + 8);
    for ( i = (_QWORD *)*v7; i != v7; i = (_QWORD *)*i )
    {
      v9 = (const WCHAR *)i[2];
      if ( !RtlStringCbPrintfW(Pool2, v5, L"%ws\\%ws", a1, v9) )
      {
        RtlInitUnicodeString(&DestinationString, v9);
        v10 = EtwpAcquireLoggerContextByLoggerName(EtwpHostSiloState, &DestinationString, 0);
        v11 = v10;
        if ( v10 )
        {
          EtwpEnableKeyProviders(*(_QWORD *)(v10 + 1360), *(_DWORD *)v10, (_DWORD)Pool2, 0, 0);
          EtwpReleaseLoggerContext(v11, 0);
        }
      }
    }
    ExFreePoolWithTag(Pool2, 0);
  }
}

```

// --- Calls: RtlInsertElementGenericTableAvl at 0x1403e57e0 (Depth: 2) ---
// Language: C/C++
```cpp
PVOID __stdcall RtlInsertElementGenericTableAvl(
        PRTL_AVL_TABLE Table,
        PVOID Buffer,
        CLONG BufferSize,
        PBOOLEAN NewElement)
{
  void *v4; // rdi
  size_t v5; // r13
  _RTL_BALANCED_LINKS *i; // r14
  _RTL_GENERIC_COMPARE_RESULTS (__fastcall *CompareRoutine)(_RTL_AVL_TABLE *, void *, void *); // rax
  _RTL_BALANCED_LINKS *v11; // r8
  RTL_GENERIC_COMPARE_RESULTS v12; // eax
  _RTL_BALANCED_LINKS *RightChild; // rax
  int v14; // ebp
  _RTL_BALANCED_LINKS *v15; // rsi
  SIZE_T v17; // rdx
  void *(__fastcall *AllocateRoutine)(_RTL_AVL_TABLE *, unsigned int); // rax
  _RTL_BALANCED_LINKS *PoolWithTag; // rax
  _RTL_BALANCED_LINKS *v20; // rdx
  _RTL_BALANCED_LINKS *j; // rcx
  char v22; // al
  bool v23; // zf
  char Balance; // cl

  v4 = 0;
  v5 = BufferSize;
  i = 0;
  if ( Table->NumberGenericTableElements )
  {
    for ( i = Table->BalancedRoot.RightChild; ; i = RightChild )
    {
      CompareRoutine = Table->CompareRoutine;
      v11 = i + 1;
      if ( (char *)CompareRoutine == (char *)PiDmCompareObjects )
      {
        v12 = PiDmCompareObjects(Table, Buffer, v11);
      }
      else if ( (char *)CompareRoutine == (char *)PnpCompareInstancePath )
      {
        v12 = (unsigned int)PnpCompareInstancePath(Table, Buffer, v11);
      }
      else if ( (char *)CompareRoutine == (char *)PiPnpRtlObjectEventCompareObjects )
      {
        v12 = PiPnpRtlObjectEventCompareObjects(Table, Buffer, v11);
      }
      else
      {
        v12 = (unsigned int)guard_dispatch_icall_no_overrides(Table, Buffer);
      }
      if ( v12 )
      {
        if ( v12 != GenericGreaterThan )
        {
          v15 = i;
          v14 = 1;
          goto LABEL_18;
        }
        RightChild = i->RightChild;
        if ( !RightChild )
        {
          v14 = 3;
          goto LABEL_23;
        }
      }
      else
      {
        RightChild = i->LeftChild;
        if ( !RightChild )
        {
          v14 = 2;
          goto LABEL_23;
        }
      }
    }
  }
  v14 = 0;
LABEL_23:
  v17 = (unsigned int)(v5 + 32);
  if ( (unsigned int)v17 >= (unsigned int)v5
    && ((AllocateRoutine = Table->AllocateRoutine,
         (char *)AllocateRoutine != (char *)PiPnpRtlOperationAllocateGenericTableEntry)
      ? ((char *)AllocateRoutine != (char *)SshpCacheDatabaseAllocate
       ? ((char *)AllocateRoutine != (char *)ExAllocatePoolWithTag
        ? (PoolWithTag = (_RTL_BALANCED_LINKS *)guard_dispatch_icall_no_overrides(Table, v17))
        : (PoolWithTag = (_RTL_BALANCED_LINKS *)ExAllocatePoolWithTag((POOL_TYPE)Table, v17, BufferSize)))
       : (PoolWithTag = (_RTL_BALANCED_LINKS *)SshpCacheDatabaseAllocate(Table, v17)))
      : (PoolWithTag = (_RTL_BALANCED_LINKS *)PiPnpRtlOperationAllocateGenericTableEntry(Table, v17)),
        (v15 = PoolWithTag) != 0) )
  {
    *(_OWORD *)&PoolWithTag->Parent = 0;
    *(_OWORD *)&PoolWithTag->RightChild = 0;
    ++Table->NumberGenericTableElements;
    if ( v14 )
    {
      v20 = PoolWithTag;
      if ( v14 == 2 )
        i->LeftChild = PoolWithTag;
      else
        i->RightChild = PoolWithTag;
      PoolWithTag->Parent = i;
      Table->BalancedRoot.Balance = -1;
      for ( j = PoolWithTag->Parent; ; i = j )
      {
        v22 = -1;
        v23 = j->LeftChild == v20;
        Balance = i->Balance;
        if ( !v23 )
          v22 = 1;
        if ( Balance )
          break;
        j = i->Parent;
        v20 = i;
        i->Balance = v22;
      }
      if ( Balance == v22 )
      {
        RebalanceNode(i);
      }
      else
      {
        i->Balance = 0;
        if ( !Table->BalancedRoot.Balance )
          ++Table->DepthOfTree;
      }
    }
    else
    {
      Table->BalancedRoot.RightChild = PoolWithTag;
      PoolWithTag->Parent = &Table->BalancedRoot;
      Table->DepthOfTree = 1;
    }
    memmove(&v15[1], Buffer, v5);
LABEL_18:
    if ( NewElement )
      *NewElement = v14 != 1;
    Table->WhichOrderedElement = 0;
    Table->OrderedPointer = 0;
    return &v15[1];
  }
  else if ( NewElement )
  {
    *NewElement = 0;
  }
  return v4;
}

```

// --- Calls: RtlGetPersistedStateLocation at 0x1409cfb00 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall RtlGetPersistedStateLocation(
        PCWSTR SourceString,
        const WCHAR *a2,
        _WORD *a3,
        unsigned int a4,
        void *a5,
        unsigned int a6,
        unsigned int *a7)
{
  _DWORD *Pool2; // rdi
  signed int v11; // ebx
  __int64 v12; // rax
  unsigned int v13; // eax
  unsigned int v14; // ecx
  const void *v16; // rdx
  NTSTATUS v17; // eax
  NTSTATUS v18; // eax
  unsigned int v19; // esi
  ULONG Length; // ebx
  NTSTATUS v21; // eax
  unsigned __int64 v22; // rax
  HANDLE KeyHandle; // [rsp+30h] [rbp-50h] BYREF
  HANDLE Handle; // [rsp+38h] [rbp-48h] BYREF
  UNICODE_STRING DestinationString; // [rsp+40h] [rbp-40h] BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+50h] [rbp-30h] BYREF
  ULONG ResultLength; // [rsp+C8h] [rbp+48h] BYREF

  KeyHandle = 0;
  Handle = 0;
  ResultLength = 0;
  Pool2 = 0;
  memset(&ObjectAttributes, 0, 44);
  DestinationString = 0;
  if ( a4 > 1 )
    return 3221225713LL;
  if ( byte_140E67708 )
  {
    v11 = -1073741772;
  }
  else
  {
    ObjectAttributes.Length = 48;
    ObjectAttributes.ObjectName = (PUNICODE_STRING)&qword_140B32478[2 * (int)a4];
    ObjectAttributes.RootDirectory = 0;
    ObjectAttributes.Attributes = 576;
    *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
    v17 = ZwOpenKey(&KeyHandle, 0x20019u, &ObjectAttributes);
    v11 = v17;
    if ( v17 == -1073741772 )
    {
      byte_140E67708 = 1;
    }
    else
    {
      if ( v17 < 0 )
        goto LABEL_9;
      RtlInitUnicodeString(&DestinationString, SourceString);
      ObjectAttributes.RootDirectory = KeyHandle;
      ObjectAttributes.Length = 48;
      ObjectAttributes.ObjectName = &DestinationString;
      ObjectAttributes.Attributes = 576;
      *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
      v18 = ZwOpenKey(&Handle, 0x20019u, &ObjectAttributes);
      v11 = v18;
      if ( v18 != -1073741772 )
      {
        if ( v18 < 0 )
          goto LABEL_9;
        if ( !a2 )
          a2 = L"TargetNtPath";
        RtlInitUnicodeString(&DestinationString, a2);
        v19 = a6;
        Length = a6 + 16;
        if ( a6 + 16 < a6 )
          goto LABEL_8;
        Pool2 = (_DWORD *)ExAllocatePool2(0x100u, Length, 0x70657373u);
        if ( !Pool2 )
        {
          v11 = -1073741801;
          goto LABEL_9;
        }
        v21 = ZwQueryValueKey(Handle, &DestinationString, KeyValuePartialInformation, Pool2, Length, &ResultLength);
        v11 = v21;
        if ( v21 < 0 )
        {
          if ( v21 != -2147483643 )
            goto LABEL_9;
        }
        else if ( Pool2[1] != 1 )
        {
          v11 = -1073741788;
          goto LABEL_9;
        }
        v14 = Pool2[2];
        ResultLength = v14;
        if ( v21 >= 0 && *((_WORD *)Pool2 + ((unsigned __int64)v14 >> 1) + 5) )
        {
          v22 = v14 + 2;
          ResultLength = v22;
          v14 += 2;
          if ( v19 < (unsigned int)v22 )
          {
            v11 = -2147483643;
          }
          else
          {
            *((_WORD *)Pool2 + (v22 >> 1) + 5) = 0;
            v14 = ResultLength;
          }
        }
        if ( a7 )
          *a7 = v14;
        if ( v11 < 0 )
          goto LABEL_9;
        v16 = Pool2 + 3;
        goto LABEL_20;
      }
    }
  }
  if ( a3 )
  {
    v12 = -1;
    do
      ++v12;
    while ( a3[v12] );
    v13 = v12 + 1;
    v14 = 2 * v13;
    ResultLength = 2 * v13;
    if ( 2 * v13 < v13 )
    {
LABEL_8:
      v11 = -1073741675;
      goto LABEL_9;
    }
    v11 = a6 < v14 ? 0x80000005 : 0;
    if ( a7 )
      *a7 = v14;
    if ( v14 > a6 )
      goto LABEL_9;
    v16 = a3;
LABEL_20:
    memmove(a5, v16, v14);
  }
LABEL_9:
  if ( KeyHandle )
    ZwClose(KeyHandle);
  if ( Handle )
    ZwClose(Handle);
  if ( Pool2 )
    ExFreePoolWithTag(Pool2, 0);
  return (unsigned int)v11;
}

```

// --- Calls: EtwStartAutoLogger at 0x1407a3b38 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall EtwStartAutoLogger(wchar_t *SourceString, __int64 a2, const WCHAR *a3)
{
  void *v4; // rsi
  char *v5; // rbx
  PCWSTR v6; // rdx
  int RegistryValues; // edi
  ULONG_PTR v8; // rax
  _WORD *v9; // rsi
  _WORD *v10; // r12
  char *v11; // r14
  char *v12; // r13
  int v13; // r15d
  __int64 v14; // r9
  int v15; // eax
  unsigned int v16; // edi
  unsigned int v17; // edx
  unsigned int v18; // eax
  unsigned __int16 v19; // cx
  char *v20; // r12
  unsigned __int16 v21; // ax
  unsigned __int16 v22; // si
  __int64 v23; // rcx
  char *v24; // rcx
  int v25; // eax
  int v26; // eax
  unsigned int v27; // eax
  const WCHAR *v28; // rdx
  GUID v29; // xmm0
  __int64 v30; // rsi
  __int64 v31; // rcx
  int started; // eax
  unsigned int v33; // r15d
  unsigned int i; // eax
  unsigned int v35; // esi
  ULONG_PTR v36; // r12
  unsigned int v37; // r14d
  __int64 CurrentServerSiloGlobals; // rax
  __int64 v39; // rax
  const WCHAR *v40; // rdx
  ULONG v41; // eax
  ULONG Class; // [rsp+20h] [rbp-E0h]
  ULONG Classa; // [rsp+20h] [rbp-E0h]
  ULONG Classb; // [rsp+20h] [rbp-E0h]
  _WORD v46[2]; // [rsp+40h] [rbp-C0h] BYREF
  int v47; // [rsp+44h] [rbp-BCh] BYREF
  ULONG_PTR Pool2; // [rsp+48h] [rbp-B8h]
  unsigned int v49; // [rsp+50h] [rbp-B0h] BYREF
  int v50; // [rsp+54h] [rbp-ACh] BYREF
  HANDLE Handle; // [rsp+58h] [rbp-A8h] BYREF
  unsigned __int16 v52; // [rsp+60h] [rbp-A0h]
  ULONG Disposition; // [rsp+64h] [rbp-9Ch] BYREF
  int v54; // [rsp+68h] [rbp-98h] BYREF
  int v55; // [rsp+6Ch] [rbp-94h] BYREF
  ULONG ValueData; // [rsp+70h] [rbp-90h] BYREF
  HANDLE KeyHandle; // [rsp+78h] [rbp-88h] BYREF
  __int64 v58; // [rsp+80h] [rbp-80h] BYREF
  char *v59; // [rsp+88h] [rbp-78h]
  __int64 v60; // [rsp+90h] [rbp-70h] BYREF
  char *v61; // [rsp+98h] [rbp-68h]
  UNICODE_STRING v62; // [rsp+A0h] [rbp-60h] BYREF
  __int64 v63; // [rsp+B0h] [rbp-50h] BYREF
  char *v64; // [rsp+B8h] [rbp-48h]
  int v65; // [rsp+C0h] [rbp-40h] BYREF
  int v66; // [rsp+C4h] [rbp-3Ch] BYREF
  int v67; // [rsp+C8h] [rbp-38h] BYREF
  PCWSTR SourceStringa; // [rsp+D0h] [rbp-30h]
  UNICODE_STRING v69; // [rsp+D8h] [rbp-28h] BYREF
  UNICODE_STRING GuidString; // [rsp+E8h] [rbp-18h] BYREF
  UNICODE_STRING UnicodeString; // [rsp+F8h] [rbp-8h] BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+108h] [rbp+8h] BYREF
  UNICODE_STRING DestinationString; // [rsp+138h] [rbp+38h] BYREF
  wchar_t *Str1; // [rsp+148h] [rbp+48h]
  __int64 v75; // [rsp+150h] [rbp+50h]
  GUID Guid; // [rsp+158h] [rbp+58h] BYREF
  int v77; // [rsp+170h] [rbp+70h] BYREF
  int *v78; // [rsp+178h] [rbp+78h]
  int v79; // [rsp+180h] [rbp+80h] BYREF
  int *v80; // [rsp+188h] [rbp+88h]
  int v81; // [rsp+190h] [rbp+90h] BYREF
  char *v82; // [rsp+198h] [rbp+98h]
  int v83; // [rsp+1A0h] [rbp+A0h] BYREF
  char *v84; // [rsp+1A8h] [rbp+A8h]
  int v85; // [rsp+1B0h] [rbp+B0h] BYREF
  char *v86; // [rsp+1B8h] [rbp+B8h]
  int v87; // [rsp+1C0h] [rbp+C0h] BYREF
  char *v88; // [rsp+1C8h] [rbp+C8h]
  int v89; // [rsp+1D0h] [rbp+D0h] BYREF
  __int64 *v90; // [rsp+1D8h] [rbp+D8h]
  int v91; // [rsp+1E0h] [rbp+E0h] BYREF
  __int64 *v92; // [rsp+1E8h] [rbp+E8h]
  int v93; // [rsp+1F0h] [rbp+F0h] BYREF
  char *v94; // [rsp+1F8h] [rbp+F8h]
  int v95; // [rsp+200h] [rbp+100h] BYREF
  char *v96; // [rsp+208h] [rbp+108h]
  int v97; // [rsp+210h] [rbp+110h] BYREF
  char *v98; // [rsp+218h] [rbp+118h]
  int v99; // [rsp+220h] [rbp+120h] BYREF
  int *v100; // [rsp+228h] [rbp+128h]
  int v101; // [rsp+230h] [rbp+130h] BYREF
  UNICODE_STRING *p_GuidString; // [rsp+238h] [rbp+138h]
  int v103; // [rsp+240h] [rbp+140h] BYREF
  char *v104; // [rsp+248h] [rbp+148h]
  int v105; // [rsp+250h] [rbp+150h] BYREF
  unsigned int *v106; // [rsp+258h] [rbp+158h]
  int v107; // [rsp+260h] [rbp+160h] BYREF
  UNICODE_STRING *p_UnicodeString; // [rsp+268h] [rbp+168h]
  int v109; // [rsp+270h] [rbp+170h] BYREF
  __int64 *v110; // [rsp+278h] [rbp+178h]
  int v111; // [rsp+280h] [rbp+180h] BYREF
  int *v112; // [rsp+288h] [rbp+188h]
  int v113; // [rsp+290h] [rbp+190h] BYREF
  UNICODE_STRING *v114; // [rsp+298h] [rbp+198h]
  int v115; // [rsp+2A0h] [rbp+1A0h] BYREF
  char *v116; // [rsp+2A8h] [rbp+1A8h]
  int v117[2]; // [rsp+2C0h] [rbp+1C0h] BYREF
  const wchar_t *v118; // [rsp+2D0h] [rbp+1D0h]
  int *v119; // [rsp+2D8h] [rbp+1D8h]
  int v120; // [rsp+2E0h] [rbp+1E0h]
  int *v121; // [rsp+2E8h] [rbp+1E8h]
  __int128 v122; // [rsp+2F8h] [rbp+1F8h]
  __int128 v123; // [rsp+308h] [rbp+208h]
  __int128 v124; // [rsp+318h] [rbp+218h]
  __int64 v125; // [rsp+328h] [rbp+228h]
  void *v126; // [rsp+330h] [rbp+230h]
  const wchar_t *v127; // [rsp+340h] [rbp+240h]
  int *v128; // [rsp+348h] [rbp+248h]
  int v129; // [rsp+350h] [rbp+250h]
  char *v130; // [rsp+358h] [rbp+258h]
  void *v131; // [rsp+368h] [rbp+268h]
  const wchar_t *v132; // [rsp+378h] [rbp+278h]
  int *v133; // [rsp+380h] [rbp+280h]
  int v134; // [rsp+388h] [rbp+288h]
  char *v135; // [rsp+390h] [rbp+290h]
  void *v136; // [rsp+3A0h] [rbp+2A0h]
  const wchar_t *v137; // [rsp+3B0h] [rbp+2B0h]
  int *v138; // [rsp+3B8h] [rbp+2B8h]
  int v139; // [rsp+3C0h] [rbp+2C0h]
  char *v140; // [rsp+3C8h] [rbp+2C8h]
  void *v141; // [rsp+3D8h] [rbp+2D8h]
  const wchar_t *v142; // [rsp+3E8h] [rbp+2E8h]
  int *v143; // [rsp+3F0h] [rbp+2F0h]
  int v144; // [rsp+3F8h] [rbp+2F8h]
  _WORD *v145; // [rsp+400h] [rbp+300h]
  int v146; // [rsp+408h] [rbp+308h]
  void *v147; // [rsp+410h] [rbp+310h]
  const wchar_t *v148; // [rsp+420h] [rbp+320h]
  int *v149; // [rsp+428h] [rbp+328h]
  int v150; // [rsp+430h] [rbp+330h]
  char *v151; // [rsp+438h] [rbp+338h]
  int v152; // [rsp+440h] [rbp+340h]
  void *v153; // [rsp+448h] [rbp+348h]
  const wchar_t *v154; // [rsp+458h] [rbp+358h]
  int *v155; // [rsp+460h] [rbp+360h]
  int v156; // [rsp+468h] [rbp+368h]
  char *v157; // [rsp+470h] [rbp+370h]
  int v158; // [rsp+478h] [rbp+378h]
  void *v159; // [rsp+480h] [rbp+380h]
  const wchar_t *v160; // [rsp+490h] [rbp+390h]
  int *v161; // [rsp+498h] [rbp+398h]
  int v162; // [rsp+4A0h] [rbp+3A0h]
  int *v163; // [rsp+4A8h] [rbp+3A8h]
  int v164; // [rsp+4B0h] [rbp+3B0h]
  void *v165; // [rsp+4B8h] [rbp+3B8h]
  const wchar_t *v166; // [rsp+4C8h] [rbp+3C8h]
  int *v167; // [rsp+4D0h] [rbp+3D0h]
  int v168; // [rsp+4D8h] [rbp+3D8h]
  int *v169; // [rsp+4E0h] [rbp+3E0h]
  int v170; // [rsp+4E8h] [rbp+3E8h]
  void *v171; // [rsp+4F0h] [rbp+3F0h]
  const wchar_t *v172; // [rsp+500h] [rbp+400h]
  int *v173; // [rsp+508h] [rbp+408h]
  int v174; // [rsp+510h] [rbp+410h]
  int *v175; // [rsp+518h] [rbp+418h]
  int v176; // [rsp+520h] [rbp+420h]
  void *v177; // [rsp+528h] [rbp+428h]
  const wchar_t *v178; // [rsp+538h] [rbp+438h]
  int *v179; // [rsp+540h] [rbp+440h]
  int v180; // [rsp+548h] [rbp+448h]
  int *v181; // [rsp+550h] [rbp+450h]
  void *v182; // [rsp+560h] [rbp+460h]
  const wchar_t *v183; // [rsp+570h] [rbp+470h]
  int *v184; // [rsp+578h] [rbp+478h]
  int v185; // [rsp+580h] [rbp+480h]
  wchar_t *Buffer; // [rsp+588h] [rbp+488h]
  int Length; // [rsp+590h] [rbp+490h]
  void *v188; // [rsp+598h] [rbp+498h]
  const WCHAR *v189; // [rsp+5A8h] [rbp+4A8h]
  int *v190; // [rsp+5B0h] [rbp+4B0h]
  int v191; // [rsp+5B8h] [rbp+4B8h]
  char *v192; // [rsp+5C0h] [rbp+4C0h]
  void *v193; // [rsp+5D0h] [rbp+4D0h]
  const wchar_t *v194; // [rsp+5E0h] [rbp+4E0h]
  int *v195; // [rsp+5E8h] [rbp+4E8h]
  int v196; // [rsp+5F0h] [rbp+4F0h]
  unsigned int *v197; // [rsp+5F8h] [rbp+4F8h]
  void *v198; // [rsp+608h] [rbp+508h]
  const wchar_t *v199; // [rsp+618h] [rbp+518h]
  int *v200; // [rsp+620h] [rbp+520h]
  int v201; // [rsp+628h] [rbp+528h]
  wchar_t *v202; // [rsp+630h] [rbp+530h]
  int v203; // [rsp+638h] [rbp+538h]
  void *v204; // [rsp+640h] [rbp+540h]
  const wchar_t *v205; // [rsp+650h] [rbp+550h]
  int *v206; // [rsp+658h] [rbp+558h]
  int v207; // [rsp+660h] [rbp+560h]
  char *v208; // [rsp+668h] [rbp+568h]
  int v209; // [rsp+670h] [rbp+570h]
  void *v210; // [rsp+678h] [rbp+578h]
  const wchar_t *v211; // [rsp+688h] [rbp+588h]
  int *v212; // [rsp+690h] [rbp+590h]
  int v213; // [rsp+698h] [rbp+598h]
  int *v214; // [rsp+6A0h] [rbp+5A0h]
  void *v215; // [rsp+6B0h] [rbp+5B0h]
  const wchar_t *v216; // [rsp+6C0h] [rbp+5C0h]
  int *v217; // [rsp+6C8h] [rbp+5C8h]
  int v218; // [rsp+6D0h] [rbp+5D0h]
  wchar_t *v219; // [rsp+6D8h] [rbp+5D8h]
  int v220; // [rsp+6E0h] [rbp+5E0h]
  void *v221; // [rsp+6E8h] [rbp+5E8h]
  const wchar_t *v222; // [rsp+6F8h] [rbp+5F8h]
  int *v223; // [rsp+700h] [rbp+600h]
  int v224; // [rsp+708h] [rbp+608h]
  int v225; // [rsp+718h] [rbp+618h]

  SourceStringa = a3;
  v75 = a2;
  LODWORD(v64) = 0;
  LODWORD(v61) = 0;
  LODWORD(v59) = 0;
  Str1 = SourceString;
  v65 = 1;
  v4 = 0;
  *(&ObjectAttributes.Length + 1) = 0;
  v5 = 0;
  *(&ObjectAttributes.Attributes + 1) = 0;
  DestinationString = 0;
  KeyHandle = 0;
  Handle = 0;
  ValueData = 0;
  v54 = 0;
  GuidString = 0;
  v63 = 0;
  UnicodeString = 0;
  v60 = 0;
  v69 = 0;
  v58 = 0;
  v49 = 0;
  v55 = 0;
  v50 = 0;
  v47 = 0;
  v46[0] = 0;
  v67 = 0;
  v66 = 100;
  v52 = 0;
  Guid = 0;
  *(_QWORD *)&v62.Length = *(_QWORD *)(PsGetCurrentServerSiloGlobals() + 832);
  RtlInitUnicodeString(&DestinationString, v6);
  ObjectAttributes.Length = 48;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.RootDirectory = 0;
  ObjectAttributes.Attributes = 576;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
  RegistryValues = ZwOpenKey(&KeyHandle, 0x2001Fu, &ObjectAttributes);
  if ( RegistryValues >= 0 )
  {
    Pool2 = ExAllocatePool2(0x100u, 0x2000u, 0x50777445u);
    v4 = (void *)Pool2;
    if ( !Pool2 || (v8 = ExAllocatePool2(0x100u, 0x504u, 0x50777445u), (v5 = (char *)v8) == 0) )
    {
      RegistryValues = -1073741801;
      goto LABEL_92;
    }
    *(_DWORD *)(v8 + 44) = 0x20000;
    *(_DWORD *)(v8 + 48) = 4;
    RtlInitUnicodeString((PUNICODE_STRING)(v8 + 144), SourceString);
    *((_DWORD *)v5 + 18) = 0x80000000;
    v9 = v5 + 180;
    v10 = v5 + 224;
    v5[74] = -1;
    v11 = v5 + 1252;
    *((_WORD *)v5 + 36) = 176;
    *((_DWORD *)v5 + 44) = 1;
    v12 = v5 + 1272;
    v13 = 180;
    memset_0(v117, 0, 0x498u);
    *(_QWORD *)v117 = &EtwpQueryRegistryCallback;
    v120 = 4;
    v119 = &v77;
    v77 = 4;
    v118 = L"Start";
    v78 = &v54;
    *((_QWORD *)&v123 + 1) = &v79;
    *(_QWORD *)&v123 = L"Immutable";
    *(_QWORD *)&v122 = &EtwpQueryRegistryCallback;
    LODWORD(v124) = 4;
    v79 = 4;
    v80 = &v47;
    RegistryValues = RtlpQueryRegistryValues(0x40000000, (int)KeyHandle, (int)v117, 0, Class, 1);
    if ( RegistryValues < 0 )
      goto LABEL_91;
    if ( !SourceStringa )
    {
LABEL_14:
      if ( !v47 )
      {
        if ( Handle )
        {
          v125 = 0;
          v121 = &v54;
          v122 = 0;
          v123 = 0;
          v124 = 0;
          RegistryValues = RtlpQueryRegistryValues(0x40000000, (int)Handle, (int)v117, 0, Classa, 1);
          if ( RegistryValues < 0 )
            RegistryValues = 0;
        }
      }
      if ( !v54 )
        goto LABEL_91;
      LODWORD(v63) = 40;
      v120 = 4;
      *(_QWORD *)v117 = &EtwpQueryRegistryCallback;
      v119 = &v77;
      v118 = L"FlushThreshold";
      v77 = 4;
      v78 = (int *)(v5 + 76);
      *(_QWORD *)&v122 = &EtwpQueryRegistryCallback;
      *((_QWORD *)&v123 + 1) = &v79;
      *(_QWORD *)&v123 = L"BufferSize";
      v80 = (int *)(v5 + 48);
      v128 = &v81;
      v127 = L"MinimumBuffers";
      v82 = v5 + 52;
      v133 = &v83;
      v132 = L"FlushTimer";
      v84 = v5 + 68;
      v138 = &v85;
      v137 = L"MaximumBuffers";
      v86 = v5 + 56;
      v143 = &v87;
      v142 = L"FileName";
      v145 = v46;
      v88 = v5 + 128;
      v64 = v5 + 184;
      v149 = &v89;
      v148 = L"EnableKernelFlags";
      v90 = &v63;
      v59 = v5 + 228;
      v155 = &v91;
      v154 = L"StackWalkingFilter";
      LODWORD(v124) = 4;
      v79 = 4;
      v126 = &EtwpQueryRegistryCallback;
      v129 = 4;
      v81 = 4;
      v131 = &EtwpQueryRegistryCallback;
      v134 = 4;
      v83 = 4;
      v136 = &EtwpQueryRegistryCallback;
      v139 = 4;
      v85 = 4;
      v141 = &EtwpQueryRegistryCallback;
      v144 = 1;
      v87 = 1;
      v147 = &EtwpQueryRegistryCallback;
      v150 = 3;
      v89 = 3;
      LODWORD(v58) = 1024;
      v153 = &EtwpQueryRegistryCallback;
      v156 = 3;
      v91 = 3;
      v92 = &v58;
      v161 = &v93;
      v160 = L"ClockType";
      v163 = &v65;
      v94 = v5 + 40;
      v167 = &v95;
      v166 = L"MaxFileSize";
      v169 = &v66;
      v96 = v5 + 60;
      v173 = &v97;
      v172 = L"LogFileMode";
      v175 = &v67;
      v98 = v5 + 64;
      v179 = &v99;
      v178 = L"DisableRealtimePersistence";
      v100 = &v55;
      v184 = &v101;
      v183 = L"Guid";
      Buffer = v46;
      p_GuidString = &GuidString;
      v190 = &v103;
      v189 = L"FileCounter";
      v104 = v5 + 96;
      v195 = &v105;
      v194 = L"FileMax";
      v106 = &v49;
      v200 = &v107;
      v159 = &EtwpQueryRegistryCallback;
      v162 = 4;
      v164 = 4;
      v93 = 4;
      v165 = &EtwpQueryRegistryCallback;
      v168 = 4;
      v170 = 4;
      v95 = 4;
      v171 = &EtwpQueryRegistryCallback;
      v174 = 4;
      v176 = 4;
      v97 = 4;
      v177 = &EtwpQueryRegistryCallback;
      v180 = 4;
      v99 = 4;
      v182 = &EtwpQueryRegistryCallback;
      v185 = 1;
      v101 = 1;
      v188 = &EtwpQueryRegistryCallback;
      v191 = 4;
      v103 = 4;
      v193 = &EtwpQueryRegistryCallback;
      v196 = 4;
      v105 = 4;
      v198 = &EtwpQueryRegistryCallback;
      v199 = L"PoolTagFilter";
      v201 = 1;
      v202 = v46;
      p_UnicodeString = &UnicodeString;
      v61 = v5 + 1276;
      v206 = &v109;
      v205 = L"StackCaching";
      v110 = &v60;
      v212 = &v111;
      v211 = L"EnableSecurityProvider";
      v112 = &v50;
      v217 = &v113;
      v216 = L"DisallowList";
      v219 = v46;
      v114 = &v69;
      v223 = &v115;
      v222 = L"V2Options";
      v224 = 11;
      v115 = 11;
      v107 = 1;
      v204 = &EtwpQueryRegistryCallback;
      v207 = 3;
      v109 = 3;
      v210 = &EtwpQueryRegistryCallback;
      v213 = 4;
      v111 = 4;
      v215 = &EtwpQueryRegistryCallback;
      v218 = 1;
      v113 = 1;
      v221 = &EtwpQueryRegistryCallback;
      v116 = v5 + 80;
      LODWORD(v60) = 8;
      v225 = 8;
      RegistryValues = RtlpQueryRegistryValues(0x40000000, (int)KeyHandle, (int)v117, 0, Classa, 1);
      if ( RegistryValues < 0 )
        goto LABEL_91;
      if ( Handle )
      {
        if ( v47 )
        {
          *(_QWORD *)&v122 = 0;
          v119 = &v103;
          *(_QWORD *)v117 = &EtwpQueryRegistryCallback;
          v118 = L"FileCounter";
          v120 = 4;
          v121 = (int *)(v5 + 96);
          v78 = (int *)(v5 + 96);
          v77 = 4;
        }
        else
        {
          v121 = (int *)(v5 + 76);
          *((_QWORD *)&v124 + 1) = v5 + 48;
          v130 = v5 + 52;
          v135 = v5 + 68;
          v140 = v5 + 56;
          v145 = (_WORD *)*((_QWORD *)v5 + 17);
          v146 = *((unsigned __int16 *)v5 + 64);
          v151 = v64;
          v152 = v63;
          v157 = v59;
          v158 = v58;
          v163 = (int *)(v5 + 40);
          v169 = (int *)(v5 + 60);
          v175 = (int *)(v5 + 64);
          v181 = &v55;
          Buffer = GuidString.Buffer;
          Length = GuidString.Length;
          v192 = v5 + 96;
          v197 = &v49;
          v202 = UnicodeString.Buffer;
          v203 = UnicodeString.Length;
          v208 = v61;
          v209 = v60;
          v214 = &v50;
          v219 = v69.Buffer;
          v220 = v69.Length;
        }
        RtlpQueryRegistryValues(0x40000000, (int)Handle, (int)v117, 0, Classb, 1);
      }
      v14 = 1;
      v15 = *((_DWORD *)v5 + 28) | 2;
      *((_DWORD *)v5 + 28) = v15;
      if ( !v55 )
        *((_DWORD *)v5 + 28) = v15 | 1;
      v16 = (unsigned int)v63 >> 2;
      if ( (unsigned __int16)((unsigned int)v63 >> 2) )
      {
        *((_WORD *)v5 + 91) = 1;
        *v9 = v16 + 1;
        ++*((_WORD *)v5 + 89);
        *((_WORD *)v5 + 88) += v16 + 1;
        v13 = 4 * (unsigned __int16)*v9 + 180;
      }
      v17 = v58;
      if ( (_DWORD)v58 )
      {
        v18 = (unsigned int)v58 >> 2;
        *((_WORD *)v5 + 113) = 3;
        v19 = (v17 >> 2) + 1;
        if ( (v17 & 3) == 0 )
          v19 = v18;
        *v10 = v19 + 1;
        ++*((_WORD *)v5 + 89);
        *((_WORD *)v5 + 88) += *v10;
        v13 += 4 * (unsigned __int16)*v10;
        if ( (_WORD)v16 )
          v9 += 2 * (unsigned __int16)*v9;
        if ( v9 != v10 )
          memmove(v9, v5 + 224, 4LL * v19 + 4);
      }
      if ( UnicodeString.Buffer )
      {
        v20 = &v5[4 * *((unsigned __int16 *)v5 + 88) + 176];
        v21 = EtwpParsePoolTagFilter(&UnicodeString, v5 + 1256, 0, v14);
        v22 = v21;
        if ( v21 )
        {
          *((_WORD *)v5 + 627) = 4;
          *(_WORD *)v11 = v21 + 1;
          ++*((_WORD *)v5 + 89);
          *((_WORD *)v5 + 88) += *(_WORD *)v11;
          v13 += 4 * *(unsigned __int16 *)v11;
          if ( v20 != v11 )
            memmove(v20, v5 + 1252, 4LL * v21 + 4);
        }
      }
      else
      {
        v22 = v52;
      }
      if ( (_DWORD)v60 == 8 )
      {
        v23 = *((unsigned __int16 *)v5 + 88);
        *(_DWORD *)v12 = 327683;
        ++*((_WORD *)v5 + 89);
        *((_WORD *)v5 + 88) += *(_WORD *)v12;
        v24 = &v5[4 * v23 + 176];
        v13 += 4 * *(unsigned __int16 *)v12;
        if ( v24 != v12 )
          memmove(v24, v5 + 1272, 0xCu);
      }
      if ( !(_WORD)v16 && !(_DWORD)v58 && !(_DWORD)v60 && !v22 )
        *((_DWORD *)v5 + 18) = 0;
      v25 = *((_DWORD *)v5 + 16);
      if ( ((v25 & 0x500) == 0 || (v25 & 0x200) != 0)
        && !*((_QWORD *)v5 + 17)
        && !RtlCreateUnicodeString((PUNICODE_STRING)v5 + 8, L"%SystemRoot%") )
      {
        RegistryValues = -1073741801;
LABEL_91:
        v4 = (void *)Pool2;
        goto LABEL_92;
      }
      if ( v50 )
      {
        v26 = *((_DWORD *)v5 + 16);
        if ( (v26 & 0x80u) == 0 || (v26 & 0x100) == 0 || *((_QWORD *)v5 + 17) )
        {
          RegistryValues = -1073741790;
          goto LABEL_91;
        }
        *((_DWORD *)v5 + 28) |= 0x8004000u;
      }
      if ( v49 )
      {
        v27 = *((_DWORD *)v5 + 24) + 1;
        *((_DWORD *)v5 + 24) = v27;
        if ( v27 > v49 || v27 > 0x10 )
          *((_DWORD *)v5 + 24) = 1;
        v28 = (const WCHAR *)Handle;
        if ( !Handle )
          v28 = (const WCHAR *)KeyHandle;
        RtlWriteRegistryValue(0x40000000u, v28, L"FileCounter", 4u, v5 + 96, 4u);
      }
      if ( !wcscmp(Str1, L"GlobalLogger") )
      {
        v29 = GlobalLoggerGuid;
        Guid = GlobalLoggerGuid;
      }
      else
      {
        if ( GuidString.Buffer )
          RegistryValues = RtlGUIDFromString(&GuidString, &Guid);
        else
          RegistryValues = -1073741811;
        if ( RegistryValues < 0 )
          goto LABEL_91;
        v29 = Guid;
      }
      v30 = *(_QWORD *)&v62.Length;
      v31 = *(_QWORD *)&v62.Length;
      *(_DWORD *)v5 = v13;
      *(GUID *)(v5 + 24) = v29;
      started = EtwpStartLogger(v31, v5);
      v33 = *((unsigned __int16 *)v5 + 4);
      RegistryValues = started;
      if ( started >= 0 )
      {
        if ( *((_WORD *)v5 + 4) && v50 )
        {
          for ( i = 0; i < 8; ++i )
          {
            if ( !*(_WORD *)(v30 + 2LL * i + 4048) )
            {
              *(_WORD *)(v30 + 2LL * i + 4048) = v33;
              break;
            }
          }
        }
        if ( v69.Length )
        {
          if ( v69.Length == 76 * (v69.Length / 0x4Cu) )
          {
            v62.Buffer = v69.Buffer;
            v62.Length = 76;
            *(&v62.MaximumLength + 2) = 0;
            *(_DWORD *)&v62.MaximumLength = (unsigned __int16)(v69.MaximumLength - v69.Length + 76);
            v35 = v69.Length / 0x4Cu;
            if ( v35 <= 0x200 )
            {
              v36 = Pool2;
              v37 = 0;
              if ( v35 )
              {
                while ( 1 )
                {
                  RegistryValues = RtlGUIDFromString(&v62, (GUID *)(v36 + 16LL * v37));
                  if ( RegistryValues )
                    break;
                  v62.Buffer += 38;
                  if ( ++v37 >= v35 )
                    goto LABEL_88;
                }
              }
              else
              {
LABEL_88:
                if ( !RegistryValues )
                {
                  CurrentServerSiloGlobals = PsGetCurrentServerSiloGlobals();
                  EtwpUpdateDisallowList(*(_QWORD *)(CurrentServerSiloGlobals + 832), v33, v35, v36);
                }
              }
            }
          }
        }
        v39 = PsGetCurrentServerSiloGlobals();
        EtwpEnableKeyProviders(*(_QWORD *)(v39 + 832), v33, v75, (_DWORD)SourceStringa, v47);
      }
      goto LABEL_91;
    }
    Disposition = 0;
    RtlInitUnicodeString(&DestinationString, SourceStringa);
    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0;
    ObjectAttributes.ObjectName = &DestinationString;
    ObjectAttributes.Attributes = 576;
    *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
    RegistryValues = ZwCreateKey(&Handle, 0x2001Fu, &ObjectAttributes, 0, 0, 0, &Disposition);
    if ( RegistryValues == -1073741772 )
    {
      if ( (unsigned int)EtwpCreateKeyTreeForPath(SourceStringa) )
      {
LABEL_11:
        RegistryValues = 0;
        Handle = 0;
LABEL_12:
        if ( Disposition == 1 )
          v47 = 1;
        goto LABEL_14;
      }
      RegistryValues = ZwCreateKey(&Handle, 0x2001Fu, &ObjectAttributes, 0, 0, 0, &Disposition);
    }
    if ( !RegistryValues )
      goto LABEL_12;
    goto LABEL_11;
  }
LABEL_92:
  v40 = (const WCHAR *)KeyHandle;
  if ( KeyHandle )
  {
    if ( RegistryValues < 0 )
    {
      v41 = RtlNtStatusToDosError(RegistryValues);
      v40 = (const WCHAR *)KeyHandle;
      ValueData = v41;
    }
    if ( Handle )
      v40 = (const WCHAR *)Handle;
    RtlWriteRegistryValue(0x40000000u, v40, L"Status", 4u, &ValueData, 4u);
    ZwClose(KeyHandle);
  }
  if ( Handle )
    ZwClose(Handle);
  if ( v5 )
  {
    RtlFreeAnsiString((PUNICODE_STRING)v5 + 8);
    ExFreePoolWithTag(v5, 0);
  }
  if ( v4 )
    ExFreePoolWithTag(v4, 0);
  RtlFreeAnsiString(&GuidString);
  RtlFreeAnsiString(&UnicodeString);
  RtlFreeAnsiString(&v69);
  return (unsigned int)RegistryValues;
}

```

// --- Calls: EtwpEnumerateAutologgerPath at 0x1407a4bd8 (Depth: 2) ---
// Language: C/C++
```cpp
void __fastcall EtwpEnumerateAutologgerPath(PCWSTR Path, const WCHAR *a2, RTL_AVL_TABLE *a3)
{
  WCHAR *v5; // rdi
  __int64 v6; // rbx
  ULONG v7; // r13d
  unsigned __int64 v8; // rdx
  unsigned __int64 v9; // rcx
  PCWSTR v10; // rax
  ULONG_PTR v11; // r15
  wchar_t *Pool2; // rbx
  NTSTATUS v13; // esi
  RTL_AVL_TABLE *v14; // rcx
  NTSTATUS v15; // ecx
  const WCHAR *v16; // rdx
  BOOLEAN NewElement[4]; // [rsp+30h] [rbp-D0h] BYREF
  ULONG ResultLength; // [rsp+34h] [rbp-CCh] BYREF
  ULONG ValueData; // [rsp+38h] [rbp-C8h] BYREF
  HANDLE KeyHandle; // [rsp+40h] [rbp-C0h] BYREF
  PRTL_AVL_TABLE Table; // [rsp+48h] [rbp-B8h]
  UNICODE_STRING DestinationString; // [rsp+50h] [rbp-B0h] BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+60h] [rbp-A0h] BYREF
  _BYTE KeyInformation[12]; // [rsp+90h] [rbp-70h] BYREF
  unsigned int v25; // [rsp+9Ch] [rbp-64h]
  wchar_t Buffer[136]; // [rsp+A0h] [rbp-60h] BYREF

  Table = a3;
  ResultLength = 0;
  *(&ObjectAttributes.Length + 1) = 0;
  *(&ObjectAttributes.Attributes + 1) = 0;
  KeyHandle = 0;
  NewElement[0] = 0;
  v5 = 0;
  DestinationString = 0;
  memset_0(KeyInformation, 0, 0x120u);
  v6 = -1;
  v7 = 0;
  if ( a2 )
  {
    v8 = -1;
    do
      ++v8;
    while ( a2[v8] );
    v9 = -1;
    do
      ++v9;
    while ( Path[v9] );
    v10 = Path;
    if ( v9 <= v8 )
      v10 = a2;
  }
  else
  {
    v10 = Path;
  }
  do
    ++v6;
  while ( v10[v6] );
  RtlInitUnicodeString(&DestinationString, Path);
  ObjectAttributes.Length = 48;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.RootDirectory = 0;
  ObjectAttributes.Attributes = 576;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
  if ( ZwOpenKey(&KeyHandle, 0x20019u, &ObjectAttributes) >= 0 )
  {
    v11 = (unsigned int)(2 * v6 + 260);
    Pool2 = (wchar_t *)ExAllocatePool2(0x100u, v11, 0x74777445u);
    if ( Pool2 )
    {
      if ( !a2 || (v5 = (WCHAR *)ExAllocatePool2(0x100u, (unsigned int)v11, 0x74777445u)) != 0 )
      {
        while ( 1 )
        {
          v13 = ZwEnumerateKey(KeyHandle, v7, KeyBasicInformation, KeyInformation, 0x11Eu, &ResultLength);
          if ( v13 < 0 )
          {
            v15 = v13;
            if ( v13 == -2147483622 )
              v15 = 0;
            ValueData = RtlNtStatusToDosError(v15);
            v16 = a2;
            if ( !a2 )
              v16 = Path;
            RtlWriteRegistryValue(0, v16, L"Status", 4u, &ValueData, 4u);
            if ( v13 != -2147483643 && v13 != -1073741789 )
              break;
          }
          else if ( v25 < 0x102 )
          {
            v14 = Table;
            Buffer[(unsigned __int64)v25 >> 1] = 0;
            RtlInsertElementGenericTableAvl(v14, Buffer, v25 + 2, NewElement);
            if ( NewElement[0] )
            {
              if ( !RtlStringCbPrintfW(Pool2, v11, L"%ws\\%ws", Path, Buffer)
                && (!a2 || !RtlStringCbPrintfW(v5, v11, L"%ws\\%ws", a2, Buffer)) )
              {
                EtwStartAutoLogger(Buffer, (__int64)Pool2, v5);
              }
            }
          }
          ++v7;
        }
      }
    }
    if ( KeyHandle )
      ZwClose(KeyHandle);
    if ( Pool2 )
      ExFreePoolWithTag(Pool2, 0);
    if ( v5 )
      ExFreePoolWithTag(v5, 0);
  }
}

```

// --- Calls: EtwpFreeKeyNameList at 0x1407a4ea0 (Depth: 2) ---
// Language: C/C++
```cpp
PVOID __fastcall EtwpFreeKeyNameList(PRTL_AVL_TABLE Table)
{
  RTL_AVL_TABLE *i; // rbx
  PVOID result; // rax

  for ( i = Table; ; Table = i )
  {
    result = RtlEnumerateGenericTableAvl(Table, 1u);
    if ( !result )
      break;
    RtlDeleteElementGenericTableAvl(i, result);
  }
  return result;
}

```

// --- Calls: PsDetachSiloFromCurrentThread at 0x140444b90 (Depth: 1) ---
// Language: C/C++
```cpp
struct _KTHREAD *__fastcall PsDetachSiloFromCurrentThread(struct _LIST_ENTRY *a1)
{
  struct _KTHREAD *result; // rax

  result = KeGetCurrentThread();
  result[1].WaitBlock[3].WaitListEntry.Blink = a1;
  return result;
}

```

// --- Calls: KeAbPreAcquire at 0x1402ef160 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 *__fastcall KeAbPreAcquire(__int64 a1, __int64 a2)
{
  struct _KTHREAD *CurrentThread; // rbx
  __int64 *v3; // rdi
  _KLOCK_ENTRIES *KernelAbEntries; // rsi
  unsigned int AvailableEntryBitmap; // eax
  struct _KPRCB *v7; // rcx
  signed __int32 *v8; // r8
  signed __int16 OrphanedEntryBitmap; // dx
  unsigned int v11; // ecx
  struct _KPRCB *CurrentPrcb; // rcx
  signed __int32 *SchedulerAssist; // r8
  signed __int32 v14; // eax
  signed __int32 v15; // ett
  signed __int32 v16; // eax
  signed __int32 v17; // ett
  unsigned int v18; // [rsp+58h] [rbp+10h]
  __int64 v19; // [rsp+68h] [rbp+20h] BYREF

  CurrentThread = KeGetCurrentThread();
  v3 = (__int64 *)a2;
  v19 = 0;
  if ( a2 )
  {
    if ( !*(_BYTE *)(a2 + 9) )
      goto LABEL_9;
    _disable();
    KiAbEntryFreeAndEnableInterrupts(a2, CurrentThread, a1, 0, &v19);
LABEL_15:
    *v3 = a1 & 0x7FFFFFFFFFFFFFFCLL;
    goto LABEL_9;
  }
  _disable();
  KernelAbEntries = CurrentThread->KernelAbEntries;
  AvailableEntryBitmap = KernelAbEntries->AvailableEntryBitmap;
  if ( KernelAbEntries->AvailableEntryBitmap )
  {
LABEL_13:
    _BitScanForward(&v11, AvailableEntryBitmap);
    v18 = v11;
    KernelAbEntries->AvailableEntryBitmap = AvailableEntryBitmap & (unsigned __int8)~(1 << v11);
    CurrentPrcb = KeGetCurrentPrcb();
    SchedulerAssist = (signed __int32 *)CurrentPrcb->SchedulerAssist;
    if ( SchedulerAssist )
    {
      _m_prefetchw(SchedulerAssist);
      v14 = *SchedulerAssist;
      do
      {
        v15 = v14;
        v14 = _InterlockedCompareExchange(SchedulerAssist, v14 & 0xFFDFFFFF, v14);
      }
      while ( v15 != v14 );
      if ( (v14 & 0x200000) != 0 )
        KiRemoveSystemWorkPriorityKick(CurrentPrcb);
    }
    _enable();
    v3 = (__int64 *)&KernelAbEntries->Entries[v18];
    goto LABEL_15;
  }
  if ( KernelAbEntries->OrphanedEntryBitmap )
  {
    OrphanedEntryBitmap = KernelAbEntries->OrphanedEntryBitmap;
    KernelAbEntries->OrphanedEntryBitmap = 0;
    AvailableEntryBitmap = OrphanedEntryBitmap;
    if ( !OrphanedEntryBitmap )
      goto LABEL_9;
    goto LABEL_13;
  }
  if ( (*((_DWORD *)&CurrentThread->$F6E8E81C3EACE4482EE2626591212BC8::$3C37BCD2CC8A9A13CF8DF3DA08EBA37B::__s0 + 1)
      & 0x10000) == 0 )
    _interlockedbittestandset((volatile signed __int32 *)&CurrentThread->___u16 + 1, 0x10u);
  v7 = KeGetCurrentPrcb();
  v8 = (signed __int32 *)v7->SchedulerAssist;
  if ( v8 )
  {
    _m_prefetchw(v8);
    v16 = *v8;
    do
    {
      v17 = v16;
      v16 = _InterlockedCompareExchange(v8, v16 & 0xFFDFFFFF, v16);
    }
    while ( v17 != v16 );
    if ( (v16 & 0x200000) != 0 )
      KiRemoveSystemWorkPriorityKick(v7);
  }
  _enable();
  if ( (WORD2(xmmword_140FC5B10) & 0x1000) != 0 )
    EtwTraceAutoBoostEntryExhaustion(CurrentThread, a1);
LABEL_9:
  if ( (_DWORD)v19 )
    KiAbThreadRemoveBoostsSlow((ULONG_PTR)CurrentThread);
  return v3;
}

```

// --- Calls: EtwTraceAutoBoostEntryExhaustion at 0x1402ef7dc (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall EtwTraceAutoBoostEntryExhaustion(__int64 a1, __int64 a2)
{
  __int64 result; // rax
  int v5; // eax
  __int64 v6; // rcx
  __int64 v7; // [rsp+30h] [rbp-38h] BYREF
  int v8; // [rsp+38h] [rbp-30h]
  int v9; // [rsp+3Ch] [rbp-2Ch]
  __int64 *v10; // [rsp+40h] [rbp-28h] BYREF
  int v11; // [rsp+48h] [rbp-20h]
  int v12; // [rsp+4Ch] [rbp-1Ch]

  v9 = 0;
  result = Feature_Servicing_AutoBoostEtwEventingFixes__private_IsEnabledNoReportingNoInline();
  if ( !(_DWORD)result )
  {
    v5 = *(_DWORD *)(a1 + 1296);
    v6 = *(_QWORD *)(a1 + 544);
    v12 = 0;
    v8 = v5;
    v10 = &v7;
    v7 = a2;
    v11 = 16;
    return EtwTraceSiloKernelEvent(*(_QWORD *)(v6 + 1520), (unsigned int)&v10, 1, -1610608640, 1348, 6298114);
  }
  return result;
}

```

// --- Calls: KiAbThreadRemoveBoostsSlow at 0x1402ef890 (Depth: 2) ---
// Language: C/C++
```cpp
void __fastcall KiAbThreadRemoveBoostsSlow(ULONG_PTR BugCheckParameter1, __int64 a2, int a3, __int64 *a4)
{
  __int64 v6; // rbp
  ULONG_PTR v7; // rdi
  unsigned int v8; // esi
  char v9; // bp
  __int64 v10; // rdx
  __int64 *v11; // r15
  bool i; // zf
  int v13; // eax
  unsigned int v14; // r14d
  int v15; // r12d
  char v16; // al
  char v17; // al
  int v18; // eax
  struct _KPRCB *CurrentPrcb; // r14
  __int64 *v20; // rsi
  __int64 v21; // [rsp+38h] [rbp-40h] BYREF
  __int64 v22; // [rsp+88h] [rbp+10h]

  if ( a3 )
  {
    v22 = a2;
    v6 = a2;
    v7 = BugCheckParameter1;
    if ( (a3 & 0x40000000) != 0 )
    {
      _InterlockedDecrement((volatile signed __int32 *)(BugCheckParameter1 + 860));
      LOBYTE(a2) = 1;
      PsBoostThreadIoEx(BugCheckParameter1, a2, 0, 0);
    }
    if ( a3 < 0 )
    {
      _InterlockedDecrement((volatile signed __int32 *)(v7 + 864));
      PsBoostThreadIoQoS(v7, 1);
    }
    v8 = a3 & 0x3FFFFFFF;
    if ( (a3 & 0x3FFFFFFF) != 0 )
    {
      v9 = 0;
      LOBYTE(BugCheckParameter1) = -1;
      v21 = 0;
      v10 = 2;
      if ( a4 )
      {
        v11 = a4;
      }
      else
      {
        v11 = &v21;
        BugCheckParameter1 = KeGetCurrentIrql();
        __writecr8(2u);
        if ( KiIrqlFlags )
          KiRaiseIrqlProcessIrqlFlags(BugCheckParameter1, 2);
      }
      for ( i = !_BitScanForward((unsigned int *)&v13, v8); !i; i = !_BitScanForward((unsigned int *)&v13, v8) )
      {
        v14 = 0;
        v15 = (char)v13 + 1;
        while ( _interlockedbittestandset64((volatile signed __int32 *)(v7 + 64), 0) )
        {
          do
          {
            if ( (++v14 & HvlLongSpinCountMask) == 0
              && (HvlEnlightenments & 0x40) != 0
              && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(BugCheckParameter1, v10) )
            {
              HvlNotifyLongSpinWait(v14);
            }
            else
            {
              _mm_pause();
            }
          }
          while ( *(_QWORD *)(v7 + 64) );
        }
        v16 = *(_BYTE *)(v15 + v7 + 824);
        if ( !v16 )
          KeBugCheckEx(0x157u, v7, v15, 2u, 0);
        v17 = v16 - 1;
        *(_BYTE *)(v15 + v7 + 824) = v17;
        if ( !v17 )
        {
          v10 = *(unsigned int *)(v7 + 856);
          BugCheckParameter1 = (unsigned int)v15;
          LODWORD(v10) = v10 ^ (1 << v15);
          *(_DWORD *)(v7 + 856) = v10;
          if ( (unsigned int)v10 < 1 << v15 && *(char *)(v7 + 195) <= 31 )
          {
            v18 = KiComputeThreadPriority(v7, 0);
            BugCheckParameter1 = (unsigned int)*(char *)(v7 + 195);
            if ( v18 < (int)BugCheckParameter1 )
              KiSetPriorityThread(v7, v11, (unsigned int)v18);
          }
        }
        *(_QWORD *)(v7 + 64) = 0;
        v8 &= v8 - 1;
      }
      if ( !a4 )
      {
        CurrentPrcb = KeGetCurrentPrcb();
        v20 = (__int64 *)*v11;
        if ( *v11 )
        {
          *v11 = *v20;
          do
          {
            KiDeferredReadySingleThread(CurrentPrcb, v20 - 27, v11, 0);
            v20 = (__int64 *)*v11;
            ++v9;
            if ( *v11 )
              *v11 = *v20;
            if ( (v9 & 0xF) == 0 )
              KiFlushSoftwareInterruptBatch(&CurrentPrcb->DeferredDispatchInterrupts);
          }
          while ( v20 );
        }
        KiFlushSoftwareInterruptBatch(&CurrentPrcb->DeferredDispatchInterrupts);
        KiCheckForThreadDispatch(CurrentPrcb);
      }
      v6 = v22;
    }
    if ( (WORD2(xmmword_140FC5B10) & 0x1000) != 0 )
      EtwTraceAutoBoostClearFloor(v7, v6, (unsigned int)a3);
  }
}

```

// --- Calls: KiAbEntryFreeAndEnableInterrupts at 0x140210230 (Depth: 2) ---
// Language: C/C++
```cpp
void __fastcall KiAbEntryFreeAndEnableInterrupts(__int64 a1, ULONG_PTR a2, __int64 a3, int a4, _QWORD *a5)
{
  __int64 v9; // rbx
  unsigned __int8 v10; // cl
  struct _KPRCB *v11; // rcx
  signed __int32 *v12; // r8
  struct _KPRCB *CurrentPrcb; // rcx
  signed __int32 *SchedulerAssist; // r8
  signed __int32 v15; // eax
  signed __int32 v16; // ett
  signed __int32 v17; // eax
  signed __int32 v18; // ett

  if ( *(__int64 *)a1 < 0 )
  {
    *(_BYTE *)a1 |= 2u;
    CurrentPrcb = KeGetCurrentPrcb();
    SchedulerAssist = (signed __int32 *)CurrentPrcb->SchedulerAssist;
    if ( SchedulerAssist )
    {
      _m_prefetchw(SchedulerAssist);
      v17 = *SchedulerAssist;
      do
      {
        v18 = v17;
        v17 = _InterlockedCompareExchange(SchedulerAssist, v17 & 0xFFDFFFFF, v17);
      }
      while ( v18 != v17 );
      if ( (v17 & 0x200000) != 0 )
        KiRemoveSystemWorkPriorityKick(CurrentPrcb);
    }
    _enable();
    KiAbEntryRemoveFromTree(a1);
    _disable();
  }
  v9 = *(unsigned int *)(a1 + 80);
  *(_DWORD *)(a1 + 80) = 0;
  *(_BYTE *)(a1 + 9) = 0;
  *(_QWORD *)a1 = 0;
  if ( a4 )
  {
    v10 = *(_BYTE *)(a1 + 8) & 0x3F;
    *(_WORD *)(a1 - 88LL * v10 - 8) |= (unsigned __int8)(1 << v10);
  }
  v11 = KeGetCurrentPrcb();
  v12 = (signed __int32 *)v11->SchedulerAssist;
  if ( v12 )
  {
    _m_prefetchw(v12);
    v15 = *v12;
    do
    {
      v16 = v15;
      v15 = _InterlockedCompareExchange(v12, v15 & 0xFFDFFFFF, v15);
    }
    while ( v16 != v15 );
    if ( (v15 & 0x200000) != 0 )
      KiRemoveSystemWorkPriorityKick(v11);
  }
  _enable();
  if ( a5 )
  {
    *a5 = v9;
  }
  else if ( (_DWORD)v9 )
  {
    KiAbThreadRemoveBoostsSlow(a2, a3, v9, 0);
  }
}

```

// --- Calls: KiRemoveSystemWorkPriorityKick at 0x140211898 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall KiRemoveSystemWorkPriorityKick(__int64 a1)
{
  int *v1; // r8
  int v3; // r11d
  __int64 result; // rax
  int v5; // ecx
  __int64 v6; // rdx

  v1 = *(int **)(a1 + 36536);
  v3 = *v1;
  result = (unsigned int)v1[5];
  if ( (*v1 & 0x280000) != 0 )
    return result;
  if ( (_DWORD)result )
    return result;
  if ( v1[7] )
    return result;
  if ( v1[8] )
    return result;
  if ( *((_QWORD *)v1 + 5) != *((_QWORD *)v1 + 6) )
    return result;
  result = *(_QWORD *)(a1 + 56);
  if ( !result || *(_BYTE *)(a1 + 34661) )
    return result;
  v5 = *(_BYTE *)result & 0x7F;
  if ( (*(_BYTE *)result & 0x7F) == 0 )
  {
    result = *(_QWORD *)(a1 + 16);
    v6 = *(_QWORD *)(a1 + 24);
    if ( result == v6 || *(_QWORD *)(a1 + 8) == v6 && !result )
      v5 = KiVpThreadSystemWorkPriority;
LABEL_13:
    if ( v5 >= 16 )
      return result;
    goto LABEL_14;
  }
  if ( v5 != 63 )
    goto LABEL_13;
  v5 = 0;
LABEL_14:
  result = (unsigned int)(unsigned __int8)v3 - 1;
  if ( (unsigned int)result <= 0x1E && (unsigned __int8)v3 > v5 && (unsigned __int8)v3 >= KiVpThreadSystemWorkPriority )
  {
    v1[3] = 3;
    if ( (BYTE4(xmmword_140FC5B10) & 0x20) != 0 && !KeGetPcr()->Prcb.CombinedNmiMceActive )
    {
      *(_BYTE *)(a1 + 34661) = 1;
      EtwTraceXSchedulerPriorityKickSend(*(unsigned int *)(a1 + 36));
      *(_BYTE *)(a1 + 34661) = 0;
    }
    return HvlpSetRegister64(589851, 4294967294LL);
  }
  return result;
}

```

// --- Calls: ExfAcquirePushLockExclusiveEx at 0x1402eec10 (Depth: 1) ---
// Language: C/C++
```cpp
signed __int64 __fastcall ExfAcquirePushLockExclusiveEx(unsigned __int64 *a1, __int64 *a2, __int64 a3)
{
  unsigned __int64 v6; // rdi
  __int64 v7; // r13
  bool v8; // cl
  unsigned __int64 v9; // rdx
  bool v10; // zf
  signed __int64 v11; // rax
  _QWORD *v12; // rcx
  signed __int64 v13; // rax
  int i; // ecx
  signed __int64 result; // rax
  __int64 v17; // rdx
  unsigned __int64 v18; // r8
  unsigned __int64 v19; // r9
  unsigned __int64 v20; // rcx
  unsigned __int64 v21; // rax
  _QWORD *v22; // rax
  __int64 v23; // rax
  __int16 Object; // [rsp+30h] [rbp-40h] BYREF
  char v25; // [rsp+32h] [rbp-3Eh]
  int v26; // [rsp+34h] [rbp-3Ch]
  _QWORD v27[3]; // [rsp+38h] [rbp-38h] BYREF
  __int16 *p_Object; // [rsp+50h] [rbp-20h]
  __int64 v29; // [rsp+58h] [rbp-18h]
  int v30; // [rsp+60h] [rbp-10h]
  signed __int32 v31; // [rsp+64h] [rbp-Ch] BYREF
  __int64 *v32; // [rsp+68h] [rbp-8h]
  int v33; // [rsp+B0h] [rbp+40h] BYREF

  memset_0(&Object, 0, 0x40u);
  v33 = 0;
  _m_prefetchw(a1);
  v6 = *a1;
  v7 = (unsigned int)(unsigned __int8)v33 + 3;
  while ( (v6 & 1) != 0 )
  {
    if ( a2 )
    {
      *(_BYTE *)a2 |= 2u;
      if ( *a2 < 0 )
        KiAbEntryRemoveFromTree(a2);
      *((_BYTE *)a2 + 9) = 1;
      *(_BYTE *)a2 &= ~2u;
    }
    v8 = 0;
    v32 = a2;
    v31 = v7;
    v29 = 0;
    if ( (v6 & 2) != 0 )
    {
      p_Object = 0;
      v30 = -1;
      v27[2] = v6 & 0xFFFFFFFFFFFFFFF0uLL;
      v9 = (unsigned __int64)&Object | v6 & 8 | 7;
      v8 = (v6 & 4) == 0;
    }
    else
    {
      v17 = 11;
      p_Object = &Object;
      v30 = v6 >> 4;
      if ( v30 <= 1 )
        v17 = v7;
      v9 = (unsigned __int64)&Object | v17;
      if ( !(unsigned int)(v6 >> 4) )
        v30 = -2;
    }
    v11 = _InterlockedCompareExchange64((volatile signed __int64 *)a1, v9, v6);
    v10 = v6 == v11;
    v6 = v11;
    if ( !v10 )
      goto LABEL_38;
    if ( v8 )
    {
      while ( (v9 & 1) != 0 )
      {
        v12 = (_QWORD *)(v9 & 0xFFFFFFFFFFFFFFF0uLL);
        if ( !*(_QWORD *)((v9 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) )
        {
          do
          {
            v22 = v12;
            v12 = (_QWORD *)v12[3];
            v12[5] = v22;
            v23 = v12[4];
          }
          while ( !v23 );
          if ( v12 != (_QWORD *)(v9 & 0xFFFFFFFFFFFFFFF0uLL) )
            *(_QWORD *)((v9 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) = v23;
        }
        v13 = _InterlockedCompareExchange64((volatile signed __int64 *)a1, v9 - 4, v9);
        v10 = v9 == v13;
        v9 = v13;
        if ( v10 )
          goto LABEL_14;
      }
      ExpWakePushLock(a1);
    }
LABEL_14:
    v27[1] = v27;
    v27[0] = v27;
    Object = 1;
    v25 = 6;
    v26 = 0;
    if ( MEMORY[0xFFFFF7800000036A] > 1u )
    {
      if ( MEMORY[0xFFFFF78000000297] )
      {
        v18 = __rdtsc();
        v19 = v18 + (unsigned int)ExpSpinCycleCount;
        while ( 1 )
        {
          __asm { monitorx rax, rcx, rdx }
          if ( (v31 & 2) == 0 )
            break;
          v20 = v18;
          v21 = __rdtsc();
          v18 = v21;
          if ( v21 < v20 || v21 >= v19 )
            break;
          __asm { mwaitx  rax, rcx, rbx }
        }
      }
      else
      {
        for ( i = 0; (v31 & 2) != 0 && i != ExpSpinCycleCount / (unsigned int)MEMORY[0xFFFFF780000002D6]; ++i )
          _mm_pause();
      }
    }
    if ( _interlockedbittestandreset(&v31, 1u) )
      KeWaitForSingleObject(&Object, WrPushLock, 0, 0, 0);
LABEL_22:
    if ( a2 )
      a2 = KeAbPreAcquire(a3, (__int64)a2);
  }
  result = _InterlockedCompareExchange64((volatile signed __int64 *)a1, v6 + 1, v6);
  if ( v6 != result )
  {
    if ( a2 )
      KeAbPreWait(a2);
LABEL_38:
    RtlBackoff(&v33);
    v6 = *a1;
    _m_prefetchw(a1);
    goto LABEL_22;
  }
  return result;
}

```

// --- Calls: KeWaitForSingleObject at 0x1402ed880 (Depth: 2) ---
// Language: C/C++
```cpp
// Alternative name is 'KeWaitForMutexObject'
NTSTATUS __stdcall KeWaitForSingleObject(
        PVOID Object,
        KWAIT_REASON WaitReason,
        KPROCESSOR_MODE WaitMode,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout)
{
  KPROCESSOR_MODE v5; // bp
  struct _KTHREAD *CurrentThread; // rdi
  unsigned __int8 CurrentIrql; // si
  unsigned __int8 *p_WaitIrql; // r12
  struct _KPRCB *CurrentPrcb; // rsi
  PLARGE_INTEGER v10; // rcx
  unsigned __int64 v11; // rdx
  unsigned __int64 v12; // r14
  unsigned int v13; // esi
  unsigned int v14; // ebx
  NTSTATUS v15; // ebp
  $C581F84972614542F01355BBD9808AD6 *v16; // r9
  unsigned int v17; // esi
  struct _KPRCB *v18; // r14
  __int64 ThreadTimerDelay; // rdx
  unsigned __int64 v20; // rcx
  unsigned __int64 v21; // rax
  unsigned int v22; // esi
  _KWAIT_STATUS_REGISTER v23; // al
  int v24; // ebx
  unsigned __int64 v25; // rdi
  PVOID *v27; // rcx
  int v28; // eax
  int v29; // eax
  unsigned int v30; // esi
  volatile unsigned __int8 DpcRoutineActive; // cl
  int v32; // eax
  char v33; // al
  __int64 *p_AbWaitObject; // r8
  struct _LIST_ENTRY *v35; // rdx
  struct _LIST_ENTRY *v36; // rcx
  volatile __int64 WaitStatus; // rsi
  __int64 v38; // rcx
  _KWAIT_STATUS_REGISTER v39; // al
  int v40; // ebx
  unsigned __int64 WaitIrql; // rdi
  _QWORD *v42; // rcx
  unsigned int v43; // esi
  ULONG_PTR v44; // rdx
  unsigned __int8 v45; // al
  bool v46; // zf
  __int64 *v47; // rsi
  unsigned __int8 v48; // si
  unsigned __int8 v49; // al
  unsigned int v50; // eax
  unsigned int v51; // eax
  __int64 *v52; // rax
  unsigned int v53; // ebp
  ULONG_PTR WobPriority; // rcx
  unsigned __int8 v55; // al
  ULONG_PTR v56; // rcx
  unsigned __int8 v57; // al
  __int64 *v58; // rax
  unsigned __int8 v59; // al
  unsigned int v60; // eax
  unsigned int v61; // eax
  unsigned __int8 v62; // al
  unsigned int v63; // eax
  unsigned int v64; // eax
  char v65; // r8
  struct _KPRCB *v66; // rcx
  signed __int32 *v67; // r8
  signed __int32 v68; // eax
  signed __int32 v69; // ett
  char v70; // al
  _LIST_ENTRY *v71; // r9
  _LIST_ENTRY *AwaitingCompletion; // r14
  char v73; // r8
  struct _KPRCB *v74; // rcx
  signed __int32 *v75; // r8
  signed __int32 v76; // eax
  signed __int32 v77; // ett
  _LIST_ENTRY *Flink; // rax
  struct _LIST_ENTRY *v79; // rcx
  struct _LIST_ENTRY *Blink; // rax
  struct _LIST_ENTRY *v81; // rax
  struct _KPRCB *v82; // rcx
  signed __int32 *SchedulerAssist; // r8
  signed __int32 v84; // eax
  signed __int32 v85; // ett
  char v86; // r8
  _LIST_ENTRY *v87; // rax
  struct _LIST_ENTRY *v88; // rcx
  struct _KPRCB *v89; // rcx
  signed __int32 *v90; // r8
  signed __int32 v91; // eax
  signed __int32 v92; // ett
  signed __int32 v93[8]; // [rsp+0h] [rbp-D8h] BYREF
  bool v94; // [rsp+30h] [rbp-A8h]
  int v95; // [rsp+34h] [rbp-A4h]
  int v96; // [rsp+38h] [rbp-A0h]
  LONGLONG QuadPart; // [rsp+40h] [rbp-98h]
  __int64 *v98; // [rsp+48h] [rbp-90h]
  __int64 v99; // [rsp+50h] [rbp-88h] BYREF
  __int64 v100; // [rsp+58h] [rbp-80h] BYREF
  __int64 v101; // [rsp+60h] [rbp-78h] BYREF
  __int64 v102; // [rsp+70h] [rbp-68h] BYREF
  __int128 v103; // [rsp+78h] [rbp-60h]
  __int64 v104; // [rsp+88h] [rbp-50h]
  unsigned __int8 v106; // [rsp+E8h] [rbp+10h]

  v106 = WaitReason;
  v5 = WaitMode;
  v102 = 0;
  CurrentThread = KeGetCurrentThread();
  QuadPart = 0;
  v94 = 0;
  v98 = 0;
  v96 = 0;
  if ( _bittestandreset((signed __int32 *)&CurrentThread->___u16, 2u) )
  {
    p_WaitIrql = &CurrentThread->WaitIrql;
    v96 = (2 * _bittestandreset((signed __int32 *)&CurrentThread->___u16, 0x10u)) | 1;
  }
  else
  {
    CurrentIrql = KeGetCurrentIrql();
    __writecr8(2u);
    if ( KiIrqlFlags )
      KiRaiseIrqlProcessIrqlFlags(CurrentIrql, 2);
    p_WaitIrql = &CurrentThread->WaitIrql;
    CurrentThread->WaitIrql = CurrentIrql;
  }
  CurrentPrcb = KeGetCurrentPrcb();
  if ( CurrentPrcb->NestingLevel <= 1u )
  {
    if ( CurrentPrcb->RcuData.AwaitingCompletion )
    {
      v70 = KeDisableInterrupts();
      AwaitingCompletion = CurrentPrcb->RcuData.AwaitingCompletion;
      v73 = v70;
      if ( AwaitingCompletion )
      {
        Flink = AwaitingCompletion->Flink;
        if ( AwaitingCompletion[-1].Blink )
        {
          if ( AwaitingCompletion != Flink )
            CurrentPrcb->RcuData.AwaitingCompletion = Flink;
        }
        else
        {
          if ( Flink == AwaitingCompletion )
          {
            CurrentPrcb->RcuData.AwaitingCompletion = v71;
          }
          else
          {
            CurrentPrcb->RcuData.AwaitingCompletion = Flink;
            v79 = AwaitingCompletion->Flink;
            Blink = AwaitingCompletion->Blink;
            if ( AwaitingCompletion->Flink->Blink != AwaitingCompletion || Blink->Flink != AwaitingCompletion )
              goto LABEL_65;
            Blink->Flink = v79;
            v79->Blink = Blink;
          }
          v81 = AwaitingCompletion[3].Flink;
          AwaitingCompletion->Flink = v71;
          AwaitingCompletion[1].Flink = v81[3].Blink;
        }
        if ( v73 )
        {
          v82 = KeGetCurrentPrcb();
          SchedulerAssist = (signed __int32 *)v82->SchedulerAssist;
          if ( SchedulerAssist )
          {
            _m_prefetchw(SchedulerAssist);
            v84 = *SchedulerAssist;
            do
            {
              v85 = v84;
              v84 = _InterlockedCompareExchange(SchedulerAssist, v84 & 0xFFDFFFFF, v84);
            }
            while ( v85 != v84 );
            if ( (v84 & 0x200000) != 0 )
              KiRemoveSystemWorkPriorityKick((__int64)v82);
          }
          _enable();
        }
        if ( AwaitingCompletion[1].Flink != AwaitingCompletion[1].Blink )
        {
          if ( ((__int64)AwaitingCompletion[2].Blink->Flink & (__int64)AwaitingCompletion[2].Flink[2].Blink) != 0 )
          {
            v86 = KeDisableInterrupts();
            if ( !AwaitingCompletion->Flink )
            {
              v87 = CurrentPrcb->RcuData.AwaitingCompletion;
              if ( v87 )
              {
                v88 = v87->Blink;
                if ( v88->Flink != v87 )
                  goto LABEL_65;
                AwaitingCompletion->Flink = v87;
                AwaitingCompletion->Blink = v88;
                v88->Flink = AwaitingCompletion;
                v87->Blink = AwaitingCompletion;
              }
              else
              {
                AwaitingCompletion->Blink = AwaitingCompletion;
                AwaitingCompletion->Flink = AwaitingCompletion;
                CurrentPrcb->RcuData.AwaitingCompletion = AwaitingCompletion;
              }
            }
            if ( v86 )
            {
              v89 = KeGetCurrentPrcb();
              v90 = (signed __int32 *)v89->SchedulerAssist;
              if ( v90 )
              {
                _m_prefetchw(v90);
                v91 = *v90;
                do
                {
                  v92 = v91;
                  v91 = _InterlockedCompareExchange(v90, v91 & 0xFFDFFFFF, v91);
                }
                while ( v92 != v91 );
                if ( (v91 & 0x200000) != 0 )
                  KiRemoveSystemWorkPriorityKick((__int64)v89);
              }
              _enable();
            }
          }
          else if ( (unsigned int)KiSrcuReportQuiescent(&AwaitingCompletion[-1].Blink, AwaitingCompletion[1].Flink) )
          {
            KiSrcuFlushCompleted(AwaitingCompletion[3].Flink);
          }
        }
        v5 = WaitMode;
      }
      else if ( v70 )
      {
        v74 = KeGetCurrentPrcb();
        v75 = (signed __int32 *)v74->SchedulerAssist;
        if ( v75 )
        {
          _m_prefetchw(v75);
          v76 = *v75;
          do
          {
            v77 = v76;
            v76 = _InterlockedCompareExchange(v75, v76 & 0xFFDFFFFF, v76);
          }
          while ( v77 != v76 );
          if ( (v76 & 0x200000) != 0 )
            KiRemoveSystemWorkPriorityKick((__int64)v74);
        }
        _enable();
      }
    }
    if ( CurrentPrcb->RcuData.GracePeriodNeeded && !CurrentPrcb->RcuData.NestingLevel )
    {
      v65 = KeDisableInterrupts();
      if ( CurrentPrcb->RcuData.GracePeriodNeeded && !CurrentPrcb->RcuData.NestingLevel )
      {
        CurrentPrcb->RcuData.GracePeriodNeeded = 0;
        _InterlockedOr(v93, 0);
        CurrentPrcb->RcuData.GraceSequenceQuiescent = qword_140F1FF68;
      }
      if ( v65 )
      {
        v66 = KeGetCurrentPrcb();
        v67 = (signed __int32 *)v66->SchedulerAssist;
        if ( v67 )
        {
          _m_prefetchw(v67);
          v68 = *v67;
          do
          {
            v69 = v68;
            v68 = _InterlockedCompareExchange(v67, v68 & 0xFFDFFFFF, v68);
          }
          while ( v69 != v68 );
          if ( (v68 & 0x200000) != 0 )
            KiRemoveSystemWorkPriorityKick((__int64)v66);
        }
        _enable();
      }
    }
    if ( CurrentPrcb->RcuData.GraceSequenceQuiescent != CurrentPrcb->RcuData.GraceSequenceReported )
    {
      v42 = (_QWORD *)((char *)&KiRcuData + 32 * CurrentPrcb->Number);
      if ( (*v42 & *(_QWORD *)(v42[1] + 56LL)) == 0 )
      {
        if ( (unsigned int)KiRcuReportQuiescentState() )
          KiRcuFlushCompleted(CurrentPrcb->RcuData.ExpediteReporting);
      }
    }
  }
  v10 = Timeout;
  v11 = 0xFFFFF78000000008uLL;
  if ( Timeout )
  {
    if ( Timeout->HighPart < 0 )
    {
      p_WaitIrql = &CurrentThread->WaitIrql;
      v95 = 2;
      QuadPart = MEMORY[0xFFFFF78000000008]
               - MEMORY[0xFFFFF780000003B0]
               - (Timeout->QuadPart
                + CurrentThread->RelativeTimerBias);
      v5 = WaitMode;
    }
    else
    {
      QuadPart = Timeout->QuadPart;
      v95 = 1;
    }
  }
  else
  {
    v95 = 0;
  }
  while ( 1 )
  {
    v12 = *p_WaitIrql;
    v101 = 0;
    while ( 1 )
    {
      CurrentThread->MiscFlags &= ~0x10u;
      CurrentThread->WaitRegister.Flags = 0;
      CurrentThread->WaitMode = v5;
      if ( Alertable )
        CurrentThread->MiscFlags |= 0x10u;
      v13 = 0;
      while ( _interlockedbittestandset64((volatile signed __int32 *)&CurrentThread->ThreadLock, 0) )
      {
        do
        {
          if ( (++v13 & HvlLongSpinCountMask) == 0
            && (HvlEnlightenments & 0x40) != 0
            && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(v10, v11) )
          {
            HvlNotifyLongSpinWait(v13);
          }
          else
          {
            _mm_pause();
          }
        }
        while ( CurrentThread->ThreadLock );
      }
      if ( !CurrentThread->ApcState.KernelApcPending || CurrentThread->SpecialApcDisable || (_BYTE)v12 )
        break;
      CurrentThread->ThreadLock = 0;
      if ( KiIrqlFlags )
        KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), 1u);
      __writecr8(1u);
      KiDeliverApc(0, 0, 0);
      v10 = (PLARGE_INTEGER)KeGetCurrentIrql();
      __writecr8(2u);
      if ( KiIrqlFlags )
        KiRaiseIrqlProcessIrqlFlags(v10, 2);
      *p_WaitIrql = 0;
    }
    v14 = v96;
    if ( !Alertable )
      break;
    if ( CurrentThread->Alerted[v5] )
    {
      CurrentThread->Alerted[v5] = 0;
      v15 = 257;
    }
    else if ( !v5 || (unsigned __int8 *)CurrentThread->ApcState.ApcListHead[1].Flink == &CurrentThread->ApcStateFill[16] )
    {
      if ( CurrentThread->Alerted[0] )
      {
        CurrentThread->Alerted[0] = 0;
        v15 = 257;
      }
      else
      {
        v15 = 0;
      }
    }
    else
    {
      CurrentThread->ApcState.UserApcPendingAll |= 2u;
      v15 = 192;
    }
    if ( v15 )
      goto LABEL_27;
LABEL_35:
    v16 = &CurrentThread->___u33;
    CurrentThread->WaitBlockFill6[68] = 5;
    CurrentThread->WaitReason = v106;
    v15 = 0;
    v17 = 0;
    CurrentThread->WaitBlock[2].SpareLong = MEMORY[0xFFFFF78000000320];
    CurrentThread->ThreadLock = 0;
    v18 = KeGetCurrentPrcb();
    CurrentThread->WaitBlock[0].WaitType = 1;
    CurrentThread->WaitBlockFill4[17] = 4;
    CurrentThread->WaitBlock[0].WaitKey = 0;
    CurrentThread->WaitBlock[0].Object = Object;
    if ( _interlockedbittestandset((volatile signed __int32 *)Object, 7u) )
    {
      do
      {
        if ( (++v17 & HvlLongSpinCountMask) == 0
          && (HvlEnlightenments & 0x40) != 0
          && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(v10, v11) )
        {
          HvlNotifyLongSpinWait(v17);
        }
        else
        {
          _mm_pause();
        }
      }
      while ( (*(_DWORD *)Object & 0x80u) != 0 || _interlockedbittestandset((volatile signed __int32 *)Object, 7u) );
      v16 = &CurrentThread->___u33;
    }
    ThreadTimerDelay = *((unsigned int *)Object + 1);
    v20 = *(unsigned __int8 *)Object;
    LOBYTE(v20) = *(_BYTE *)Object & 0x7F;
    if ( (_BYTE)v20 == 2 )
    {
      v94 = (*((_BYTE *)Object + 48) & 2) != 0;
      if ( (int)ThreadTimerDelay <= 0
        && (CurrentThread != *((struct _KTHREAD **)Object + 5) || *((_BYTE *)Object + 2) != v18->DpcRoutineActive) )
      {
        goto LABEL_38;
      }
      v28 = *((_DWORD *)Object + 1);
      if ( v28 == 0x80000000 )
      {
        _InterlockedAnd((volatile signed __int32 *)Object, 0xFFFFFF7F);
        KiFastExitThreadWait(v18, (ULONG_PTR)CurrentThread);
        RtlRaiseStatus(-1073741423);
      }
      v29 = v28 - 1;
      *((_DWORD *)Object + 1) = v29;
      if ( v29 )
        goto LABEL_42;
      CurrentThread->WaitStatus = 0;
      v30 = 0;
      while ( _interlockedbittestandset64((volatile signed __int32 *)&CurrentThread->ThreadLock, 0) )
      {
        do
        {
          if ( (++v30 & HvlLongSpinCountMask) == 0
            && (HvlEnlightenments & 0x40) != 0
            && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(v20, ThreadTimerDelay) )
          {
            HvlNotifyLongSpinWait(v30);
          }
          else
          {
            _mm_pause();
          }
        }
        while ( CurrentThread->ThreadLock );
      }
      if ( *((_BYTE *)Object + 49) )
        --CurrentThread->KernelApcDisable;
      if ( v18->CurrentThread == CurrentThread )
        DpcRoutineActive = v18->DpcRoutineActive;
      else
        DpcRoutineActive = 0;
      v104 = 0;
      v32 = *(_DWORD *)Object;
      v103 = 0;
      LODWORD(v103) = v32;
      BYTE2(v103) = DpcRoutineActive;
      *(_DWORD *)Object = v103;
      v33 = *((_BYTE *)Object + 48);
      *((_QWORD *)Object + 5) = CurrentThread;
      if ( (v33 & 1) != 0 )
      {
        *((_BYTE *)Object + 48) = v33 & 0xFE;
        CurrentThread->WaitStatus |= 0x80uLL;
      }
      if ( (*((_BYTE *)Object + 48) & 2) != 0 )
        CurrentThread->AbWaitObject = Object;
      else
        CurrentThread->AbWaitObject = 0;
      p_AbWaitObject = (__int64 *)&CurrentThread->AbWaitObject;
      v35 = CurrentThread->MutantListHead.Blink;
      v36 = (struct _LIST_ENTRY *)((char *)Object + 24);
      if ( v35->Flink == &CurrentThread->MutantListHead )
      {
        v36->Flink = &CurrentThread->MutantListHead;
        *((_QWORD *)Object + 4) = v35;
        v35->Flink = v36;
        CurrentThread->MutantListHead.Blink = v36;
        _InterlockedAnd((volatile signed __int32 *)Object, 0xFFFFFF7F);
        CurrentThread->WaitBlockFill6[68] = 2;
        CurrentThread->ThreadLock = 0;
        WaitStatus = CurrentThread->WaitStatus;
        v38 = *p_AbWaitObject;
        if ( *p_AbWaitObject )
        {
          CurrentThread->AbWaitObject = 0;
          v52 = KeAbPreAcquire(v38, 0);
          if ( v52 )
            *((_BYTE *)v52 + 10) = 1;
        }
        v99 = 0;
        if ( v14 >= 2 )
        {
          v53 = 0;
          while ( _interlockedbittestandset64((volatile signed __int32 *)&CurrentThread->ThreadLock, 0) )
          {
            do
            {
              if ( (++v53 & HvlLongSpinCountMask) == 0
                && (HvlEnlightenments & 0x40) != 0
                && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(v38, v35) )
              {
                HvlNotifyLongSpinWait(v53);
              }
              else
              {
                _mm_pause();
              }
            }
            while ( CurrentThread->ThreadLock );
          }
          WobPriority = CurrentThread->WobPriority;
          v55 = CurrentThread->PriorityFloorCounts[WobPriority];
          if ( !v55 )
            KeBugCheckEx(0x157u, (ULONG_PTR)CurrentThread, WobPriority, 2u, 0);
          v59 = v55 - 1;
          CurrentThread->PriorityFloorCounts[WobPriority] = v59;
          if ( !v59 )
          {
            v60 = CurrentThread->PriorityFloorSummary ^ (1 << WobPriority);
            CurrentThread->PriorityFloorSummary = v60;
            if ( v60 < 1 << WobPriority && CurrentThread->Priority <= 31 )
            {
              v61 = KiComputeThreadPriority(CurrentThread, 0);
              if ( (int)v61 < CurrentThread->Priority )
                KiSetPriorityThread(CurrentThread, &v99, v61);
            }
          }
          CurrentThread->WobPriority = 32;
          CurrentThread->ThreadLock = 0;
        }
        v39.Flags = (unsigned __int8)CurrentThread->WaitRegister;
        v40 = v14 & 1;
        if ( (v39.Flags & 0x38) != 0 )
        {
          if ( (v39.Flags & 0x18) != 0 )
          {
            KiExitThreadWaitReschedule(v18);
            return WaitStatus;
          }
          else
          {
            KiProcessDeferredReadyList(v18);
            KiDeliverApc(0, 0, 0);
            if ( KiIrqlFlags )
              KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), 0);
            __writecr8(0);
            return WaitStatus;
          }
        }
        else
        {
          WaitIrql = CurrentThread->WaitIrql;
          if ( v40 )
          {
            KiProcessDeferredReadyList(v18);
            return WaitStatus;
          }
          else
          {
            if ( KiIrqlFlags )
              KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), WaitIrql);
            __writecr8(WaitIrql);
            return WaitStatus;
          }
        }
      }
LABEL_65:
      __fastfail(3u);
    }
    if ( (int)ThreadTimerDelay > 0 )
    {
      if ( (*(_BYTE *)Object & 7) == 1 )
      {
        *((_DWORD *)Object + 1) = 0;
      }
      else if ( (_BYTE)v20 == 5 )
      {
        *((_DWORD *)Object + 1) = ThreadTimerDelay - 1;
      }
      goto LABEL_42;
    }
LABEL_38:
    v21 = QuadPart;
    if ( v95 == 2 )
    {
      ThreadTimerDelay = CurrentThread->ThreadTimerDelay;
      v20 = MEMORY[0xFFFFF78000000008] - CurrentThread->RelativeTimerBias - MEMORY[0xFFFFF780000003B0];
      v21 = QuadPart;
      if ( CurrentThread->WaitMode
        && !CurrentThread->WaitBlock[3].SpareLong
        && !*p_WaitIrql
        && !CurrentThread->ApcState.InProgressFlags
        && (_DWORD)ThreadTimerDelay )
      {
        v21 = QuadPart + ThreadTimerDelay;
      }
    }
    else
    {
      if ( !v95 )
        goto LABEL_64;
      if ( !QuadPart )
        goto LABEL_41;
      v20 = MEMORY[0xFFFFF78000000014];
    }
    if ( v20 > v21 )
    {
LABEL_41:
      v15 = 258;
LABEL_42:
      _InterlockedAnd((volatile signed __int32 *)Object, 0xFFFFFF7F);
      CurrentThread->WaitBlockFill6[68] = 2;
      _InterlockedOr(v93, 0);
      if ( CurrentThread->ThreadLock )
      {
        v22 = 0;
        while ( _interlockedbittestandset64((volatile signed __int32 *)&CurrentThread->ThreadLock, 0) )
        {
          do
          {
            if ( (++v22 & HvlLongSpinCountMask) == 0
              && (HvlEnlightenments & 0x40) != 0
              && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(v20, ThreadTimerDelay) )
            {
              HvlNotifyLongSpinWait(v22);
            }
            else
            {
              _mm_pause();
            }
          }
          while ( CurrentThread->ThreadLock );
        }
        CurrentThread->ThreadLock = 0;
      }
      v100 = 0;
      if ( v14 >= 2 )
      {
        v43 = 0;
        while ( _interlockedbittestandset64((volatile signed __int32 *)&CurrentThread->ThreadLock, 0) )
        {
          do
          {
            if ( (++v43 & HvlLongSpinCountMask) == 0
              && (HvlEnlightenments & 0x40) != 0
              && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(v20, ThreadTimerDelay) )
            {
              HvlNotifyLongSpinWait(v43);
            }
            else
            {
              _mm_pause();
            }
          }
          while ( CurrentThread->ThreadLock );
        }
        v44 = CurrentThread->WobPriority;
        v45 = CurrentThread->PriorityFloorCounts[v44];
        if ( !v45 )
          KeBugCheckEx(0x157u, (ULONG_PTR)CurrentThread, v44, 2u, 0);
        v49 = v45 - 1;
        CurrentThread->PriorityFloorCounts[v44] = v49;
        if ( !v49 )
        {
          v50 = CurrentThread->PriorityFloorSummary ^ (1 << v44);
          CurrentThread->PriorityFloorSummary = v50;
          if ( v50 < 1 << v44 && CurrentThread->Priority <= 31 )
          {
            v51 = KiComputeThreadPriority(CurrentThread, 0);
            if ( (int)v51 < CurrentThread->Priority )
              KiSetPriorityThread(CurrentThread, &v100, v51);
          }
        }
        CurrentThread->WobPriority = 32;
        CurrentThread->ThreadLock = 0;
      }
      v23.Flags = (unsigned __int8)CurrentThread->WaitRegister;
      v24 = v14 & 1;
      if ( (v23.Flags & 0x38) != 0 )
      {
        if ( (v23.Flags & 0x18) != 0 )
        {
          KiExitThreadWaitReschedule(v18);
        }
        else
        {
          KiProcessDeferredReadyList(v18);
          KiDeliverApc(0, 0, 0);
          if ( KiIrqlFlags )
            KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), 0);
          __writecr8(0);
        }
      }
      else
      {
        v25 = CurrentThread->WaitIrql;
        if ( v24 )
        {
          KiProcessDeferredReadyList(v18);
        }
        else
        {
          if ( KiIrqlFlags )
            KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), v25);
          __writecr8(v25);
        }
      }
      return v15;
    }
LABEL_64:
    v27 = (PVOID *)*((_QWORD *)Object + 2);
    if ( *v27 != (char *)Object + 8 )
      goto LABEL_65;
    v16->WaitBlock[0].WaitListEntry.Flink = (struct _LIST_ENTRY *)((char *)Object + 8);
    v16->WaitBlock[0].WaitListEntry.Blink = (struct _LIST_ENTRY *)v27;
    *v27 = v16;
    *((_QWORD *)Object + 2) = v16;
    _InterlockedAnd((volatile signed __int32 *)Object, 0xFFFFFF7F);
    v46 = !v94;
    CurrentThread->WaitBlockCount = 1;
    if ( v46 )
    {
      v47 = v98;
    }
    else
    {
      v47 = KeAbPreAcquire((__int64)Object, 0);
      v98 = v47;
    }
    if ( v47 )
    {
      *(_BYTE *)v47 |= 2u;
      if ( *v47 < 0 )
        KiAbEntryRemoveFromTree(v47);
      *((_BYTE *)v47 + 9) = 1;
      *(_BYTE *)v47 &= ~2u;
    }
    v15 = KiCommitThreadWait((ULONG_PTR)CurrentThread, v14, (__int64)&v102);
    v96 = 0;
    if ( v47 )
    {
      v58 = KeAbPreAcquire((__int64)Object, (__int64)v47);
      if ( (v15 & 0xFFFFFF7F) != 0 )
      {
        KeAbPostReleaseEx((ULONG_PTR)Object);
        v98 = 0;
      }
      else
      {
        v98 = v58;
        *((_BYTE *)v58 + 10) = 1;
      }
    }
    CurrentThread->AbWaitObject = 0;
    if ( v15 != 256 )
      return v15;
    v48 = KeGetCurrentIrql();
    __writecr8(2u);
    if ( KiIrqlFlags )
      KiRaiseIrqlProcessIrqlFlags(v48, 2);
    v5 = WaitMode;
    *p_WaitIrql = v48;
  }
  if ( (CurrentThread->ApcState.UserApcPendingAll & 2) == 0 || !v5 )
    goto LABEL_35;
  v15 = 192;
LABEL_27:
  if ( v14 >= 2 )
  {
    v56 = CurrentThread->WobPriority;
    v57 = CurrentThread->PriorityFloorCounts[v56];
    if ( !v57 )
      KeBugCheckEx(0x157u, (ULONG_PTR)CurrentThread, v56, 2u, 0);
    v62 = v57 - 1;
    CurrentThread->PriorityFloorCounts[v56] = v62;
    if ( !v62 )
    {
      v63 = CurrentThread->PriorityFloorSummary ^ (1 << v56);
      CurrentThread->PriorityFloorSummary = v63;
      if ( v63 < 1 << v56 && CurrentThread->Priority <= 31 )
      {
        v64 = KiComputeThreadPriority(CurrentThread, 0);
        if ( (int)v64 < CurrentThread->Priority )
          KiSetPriorityThread(CurrentThread, &v101, v64);
      }
    }
    CurrentThread->WobPriority = 32;
  }
  CurrentThread->ThreadLock = 0;
  if ( (v14 & 1) != 0 )
  {
    KiProcessDeferredReadyList(KeGetCurrentPrcb());
  }
  else
  {
    if ( KiIrqlFlags )
      KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), v12);
    __writecr8(v12);
  }
  return v15;
}

```

// --- Calls: ExpWakePushLock at 0x1404096e0 (Depth: 2) ---
// Language: C/C++
```cpp
int __fastcall ExpWakePushLock(volatile signed __int64 *a1, signed __int64 a2)
{
  int v3; // edi
  _QWORD *v4; // rcx
  struct _KEVENT *v5; // rbx
  signed __int64 Blink; // rax
  bool v7; // zf
  unsigned __int8 CurrentIrql; // si
  struct _KEVENT *v9; // rdi
  struct _LIST_ENTRY *Flink; // rdx
  _QWORD *v11; // rax

  v3 = 1;
  while ( 1 )
  {
    while ( (a2 & 1) != 0 )
    {
      Blink = _InterlockedCompareExchange64(a1, a2 - 4, a2);
      v7 = a2 == Blink;
      a2 = Blink;
      if ( v7 )
        return Blink;
    }
    v4 = (_QWORD *)(a2 & 0xFFFFFFFFFFFFFFF0uLL);
    v5 = *(struct _KEVENT **)((a2 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20);
    if ( !v5 )
    {
      do
      {
        v11 = v4;
        v4 = (_QWORD *)v4[3];
        v4[5] = v11;
        v5 = (struct _KEVENT *)v4[4];
      }
      while ( !v5 );
      if ( v4 != (_QWORD *)(a2 & 0xFFFFFFFFFFFFFFF0uLL) )
        *(_QWORD *)((a2 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) = v5;
    }
    if ( (v5[2].Header.SignalState & 1) != 0 )
    {
      Blink = (signed __int64)v5[1].Header.WaitListHead.Blink;
      if ( Blink )
        break;
    }
    Blink = _InterlockedCompareExchange64(a1, 0, a2);
    v7 = a2 == Blink;
    a2 = Blink;
    if ( v7 )
      goto LABEL_7;
  }
  *(_QWORD *)((a2 & 0xFFFFFFFFFFFFFFF0uLL) + 0x20) = Blink;
  v5[1].Header.WaitListHead.Blink = 0;
  _InterlockedAnd64(a1, 0xFFFFFFFFFFFFFFFBuLL);
  v3 = 0;
LABEL_7:
  CurrentIrql = 2;
  if ( v5[1].Header.WaitListHead.Blink )
  {
    CurrentIrql = KeGetCurrentIrql();
    LODWORD(Blink) = 2;
    __writecr8(2u);
    if ( KiIrqlFlags )
      LODWORD(Blink) = KiRaiseIrqlProcessIrqlFlags(CurrentIrql, 2);
  }
  if ( !v3 )
  {
    Flink = v5[2].Header.WaitListHead.Flink;
    if ( Flink )
      LODWORD(Blink) = KiAbConvertWaiterToOwnerEntry(*((_QWORD *)&Flink[-1].Flink - 11 * ((__int64)Flink->Blink & 0x3F)));
  }
  do
  {
    v9 = (struct _KEVENT *)v5[1].Header.WaitListHead.Blink;
    if ( !_interlockedbittestandreset(&v5[2].Header.SignalState, 1u) )
      LODWORD(Blink) = KeSetEvent(v5, 0, 0);
    v5 = v9;
  }
  while ( v9 );
  if ( CurrentIrql != 2 )
  {
    if ( KiIrqlFlags )
      KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), CurrentIrql);
    LODWORD(Blink) = CurrentIrql;
    __writecr8(CurrentIrql);
  }
  return Blink;
}

```

// --- Calls: KeAbPreWait at 0x1402ed730 (Depth: 2) ---
// Language: C/C++
```cpp
char __fastcall KeAbPreWait(__int64 *a1)
{
  char result; // al

  *(_BYTE *)a1 |= 2u;
  if ( *a1 < 0 )
    KiAbEntryRemoveFromTree(a1);
  *((_BYTE *)a1 + 9) = 1;
  result = *(_BYTE *)a1 & 0xFD;
  *(_BYTE *)a1 = result;
  return result;
}

```

// --- Calls: RtlBackoff at 0x140206fc0 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall RtlBackoff(unsigned int *a1)
{
  unsigned int v1; // r8d
  __int64 result; // rax
  unsigned __int64 v3; // rax
  unsigned int i; // ecx

  v1 = *a1;
  if ( *a1 )
  {
    if ( v1 < 0x1FFF )
      v1 *= 2;
  }
  else
  {
    result = (unsigned int)KeNumberProcessors_0;
    if ( (_DWORD)KeNumberProcessors_0 == 1 )
      return result;
    v1 = 64;
  }
  *a1 = v1;
  v3 = __rdtsc();
  result = 10 * (((v1 - 1) & (unsigned int)v3) + v1) / MEMORY[0xFFFFF780000002D6];
  for ( i = 0; i < (unsigned int)result; ++i )
    _mm_pause();
  return result;
}

```

// --- Calls: KiAbEntryRemoveFromTree at 0x140210370 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall KiAbEntryRemoveFromTree(__int64 *a1, __int64 a2)
{
  __int64 v2; // rbx
  char v4; // cl
  unsigned __int64 v5; // rbx
  __int64 v6; // rax
  volatile LONG *v7; // rsi
  __int64 v8; // r13
  unsigned __int8 CurrentIrql; // r12
  int v10; // r15d
  signed __int32 v11; // eax
  signed __int32 v12; // ett
  __int64 v13; // rcx
  unsigned __int64 v14; // rdi
  int v15; // ecx
  unsigned __int64 v16; // rax
  unsigned __int64 v17; // rax
  __int64 *v18; // rsi
  unsigned __int64 *v19; // rcx
  __int64 v21; // r8
  _QWORD *v22; // rcx
  __int64 v23; // rax
  bool v24; // zf
  unsigned __int8 v25; // dl
  unsigned __int64 v26; // rbx
  __int64 v27; // rdi
  _QWORD *v28; // rdx
  __int64 v29; // rcx
  _QWORD *v30; // rax
  int v31; // ecx
  unsigned int v32; // edi
  __int64 v33; // rdx
  unsigned __int64 v34; // rcx
  __int64 v35; // rax
  unsigned __int8 v36; // dl
  __int64 v37; // rax
  __int64 v38; // rcx
  __int128 v39; // [rsp+20h] [rbp-30h] BYREF
  __int64 v40; // [rsp+30h] [rbp-20h]
  __int128 v41; // [rsp+38h] [rbp-18h] BYREF
  __int64 v42; // [rsp+48h] [rbp-8h]
  void *retaddr; // [rsp+88h] [rbp+38h]
  PEX_SPIN_LOCK SpinLock; // [rsp+98h] [rbp+48h]

  v2 = *a1;
  v40 = 0;
  v4 = *((_BYTE *)a1 + 8);
  v42 = 0;
  v5 = v2 & 0x7FFFFFFFFFFFFFFCLL;
  v39 = 0;
  v41 = 0;
  if ( v4 < 0 )
  {
    v21 = *(_QWORD *)(a1[-11 * (v4 & 0x3F) - 2] + 544);
    a2 = (unsigned int)(v5 >> 4) % *(_DWORD *)(v21 + 96);
    v8 = *(_QWORD *)(v21 + 88) + 24 * a2;
    v7 = (volatile LONG *)(v8 + 16);
  }
  else
  {
    v6 = ((v5 >> 4) & 0x3FF) << 6;
    v7 = (volatile LONG *)((char *)&unk_140E16F10 + v6);
    v8 = (__int64)&KiAbTreeArray + v6;
  }
  SpinLock = v7;
  CurrentIrql = KeGetCurrentIrql();
  __writecr8(2u);
  if ( KiIrqlFlags )
    KiRaiseIrqlProcessIrqlFlags(CurrentIrql, 2);
  v10 = *((_BYTE *)a1 + 11) & 1;
  if ( (*((_BYTE *)a1 + 11) & 1) != 0 )
    goto LABEL_73;
  if ( (BYTE6(PerfGlobalGroupMask) & 0x21) != 0 && !PopHibernateInProgress )
  {
    LOBYTE(a2) = -1;
    ExpAcquireSpinLockSharedAtDpcLevelInstrumented(v7, a2);
    goto LABEL_11;
  }
  _m_prefetchw((const void *)v7);
  v11 = *v7 & 0x7FFFFFFF;
  do
  {
    v12 = v11;
    v11 = _InterlockedCompareExchange(v7, v11 + 1, v11);
    if ( v12 == v11 )
      goto LABEL_11;
  }
  while ( v11 >= 0 );
  LOBYTE(a2) = -1;
  ExpWaitForSpinLockSharedAndAcquire(v7, a2);
  while ( 1 )
  {
LABEL_11:
    v13 = *(_QWORD *)(v8 + 8);
    v14 = *(_QWORD *)v8;
    if ( (v13 & 1) != 0 )
    {
      if ( !v14 )
        goto LABEL_19;
      v14 ^= v8;
    }
    v15 = v13 & 1;
    while ( v14 )
    {
      v16 = *(_QWORD *)(v14 - 16) & 0x7FFFFFFFFFFFFFFCLL;
      if ( v16 < v5 )
      {
        v17 = *(_QWORD *)(v14 + 8);
        if ( v15 && v17 )
          goto LABEL_107;
      }
      else
      {
        if ( v16 <= v5 )
          break;
        v17 = *(_QWORD *)v14;
        if ( v15 && v17 )
        {
LABEL_107:
          v14 ^= v17;
          continue;
        }
      }
      v14 = v17;
    }
LABEL_19:
    v18 = (__int64 *)(v14 - 16);
    *(_QWORD *)&v39 = 0;
    *((_QWORD *)&v39 + 1) = v14 - 16 + 72;
    if ( (BYTE6(PerfGlobalGroupMask) & 0x21) == 0 || PopHibernateInProgress )
    {
      if ( _InterlockedExchange64((volatile __int64 *)(v14 - 16 + 72), (__int64)&v39) )
        KxWaitForLockOwnerShip(&v39);
    }
    else
    {
      KiAcquireQueuedSpinLockInstrumented(&v39, v14 - 16 + 72);
    }
    if ( v18 != a1 )
      break;
    if ( v10 )
    {
      v19 = (unsigned __int64 *)(v18 + 7);
      if ( (v18[7] || (v19 = (unsigned __int64 *)(v18 + 5), v18[5])) && v19 )
      {
        v26 = *v19;
        v27 = *v19 - 16;
        RtlRbRemoveNode(v19, *v19);
        v28 = v18 + 2;
        *(_OWORD *)v26 = *((_OWORD *)v18 + 1);
        *(_QWORD *)(v26 + 16) = v18[4];
        if ( *(_QWORD *)v26 )
        {
          *(_QWORD *)(*(_QWORD *)v26 + 16LL) = v26 | *(_DWORD *)(*(_QWORD *)v26 + 16LL) & 3;
        }
        else
        {
          v37 = *(_QWORD *)(v8 + 8);
          if ( (v37 & 1) != 0 )
          {
            if ( v37 == 1 )
              v38 = 0;
            else
              v38 = v37 ^ (v8 | 1);
          }
          else
          {
            v38 = *(_QWORD *)(v8 + 8);
          }
          if ( (_QWORD *)v38 == v28 )
          {
            if ( (v37 & 1) != 0 )
            {
              *(_QWORD *)(v8 + 8) = v8 ^ v26;
              *(_BYTE *)(v8 + 8) = v8 ^ v26 | 1;
            }
            else
            {
              *(_QWORD *)(v8 + 8) = v26;
            }
          }
        }
        v29 = *(_QWORD *)(v26 + 8);
        if ( v29 )
          *(_QWORD *)(v29 + 16) = v26 | *(_DWORD *)(v29 + 16) & 3;
        v30 = (_QWORD *)(*(_QWORD *)(v26 + 16) & 0xFFFFFFFFFFFFFFFCuLL);
        if ( v30 )
        {
          if ( (_QWORD *)*v30 == v28 )
            *v30 = v26;
          else
            v30[1] = v26;
        }
        else
        {
          if ( (*(_BYTE *)(v8 + 8) & 1) != 0 )
            v26 ^= v8;
          *(_QWORD *)v8 = v26;
        }
        *((_QWORD *)&v41 + 1) = v27 + 72;
        *(_QWORD *)&v41 = 0;
        if ( (BYTE6(PerfGlobalGroupMask) & 0x21) == 0 || PopHibernateInProgress )
        {
          if ( _InterlockedExchange64((volatile __int64 *)(v27 + 72), (__int64)&v41) )
            KxWaitForLockOwnerShip(&v41);
        }
        else
        {
          KiAcquireQueuedSpinLockInstrumented(&v41, v27 + 72);
        }
        if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 || PopHibernateInProgress )
          *SpinLock = 0;
        else
          ExpReleaseSpinLockExclusiveFromDpcLevelInstrumented(SpinLock, retaddr);
        *(_OWORD *)(v27 + 40) = *(_OWORD *)(v18 + 5);
        *(_OWORD *)(v27 + 56) = *(_OWORD *)(v18 + 7);
        *(_BYTE *)(v27 + 84) = *((_BYTE *)v18 + 84);
        v31 = *(_DWORD *)(v27 + 84) ^ (*((_DWORD *)v18 + 21) ^ *(_DWORD *)(v27 + 84)) & 0x7F00;
        *(_DWORD *)(v27 + 84) = v31;
        if ( (*((_BYTE *)v18 + 11) & 2) != 0 )
        {
          *(_BYTE *)(v27 + 84) = v31 - 1;
          *((_BYTE *)v18 + 11) &= ~2u;
        }
        if ( (*((_BYTE *)v18 + 11) & 4) != 0 )
        {
          *(_DWORD *)(v27 + 84) ^= ((unsigned __int16)*(_DWORD *)(v27 + 84)
                                  ^ (unsigned __int16)(((unsigned __int16)(*(_DWORD *)(v27 + 84) >> 8) - 1) << 8))
                                 & 0x7F00;
          *((_BYTE *)v18 + 11) &= ~4u;
        }
        *(_BYTE *)(v27 + 11) |= 1u;
        if ( (BYTE6(PerfGlobalGroupMask) & 1) != 0 && !PopHibernateInProgress )
        {
          KiReleaseQueuedSpinLockInstrumented(&v41, retaddr);
          goto LABEL_32;
        }
        _m_prefetchw(&v41);
        v35 = v41;
        if ( !(_QWORD)v41 )
        {
          if ( (__int128 *)_InterlockedCompareExchange64(
                             *((volatile signed __int64 **)&v41 + 1),
                             0,
                             (signed __int64)&v41) == &v41 )
            goto LABEL_32;
          v35 = KxWaitForLockChainValid(&v41);
        }
        *(_QWORD *)&v41 = 0;
        v36 = BYTE8(v41);
        if ( ((v36 ^ (unsigned __int8)_InterlockedExchange64((volatile __int64 *)(v35 + 8), *((__int64 *)&v41 + 1))) & 4) != 0 )
          KeWakeAddressAll();
      }
      else
      {
        RtlRbRemoveNode(v8, v14);
        if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 || PopHibernateInProgress )
          *SpinLock = 0;
        else
          ExpReleaseSpinLockExclusiveFromDpcLevelInstrumented(SpinLock, retaddr);
        if ( (*((_BYTE *)v18 + 11) & 2) != 0 )
        {
          --*((_BYTE *)v18 + 84);
          *((_BYTE *)v18 + 11) &= ~2u;
        }
        if ( (*((_BYTE *)v18 + 11) & 4) != 0 )
        {
          *((_DWORD *)v18 + 21) ^= ((unsigned __int16)*((_DWORD *)v18 + 21)
                                  ^ (unsigned __int16)(((unsigned __int16)(*((_DWORD *)v18 + 21) >> 8) - 1) << 8))
                                 & 0x7F00;
          *((_BYTE *)v18 + 11) &= ~4u;
        }
      }
LABEL_32:
      *((_BYTE *)v18 + 7) &= ~0x80u;
      *((_BYTE *)v18 + 11) &= ~1u;
      if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 )
        goto LABEL_45;
      goto LABEL_33;
    }
    v7 = SpinLock;
    ExReleaseSpinLockSharedFromDpcLevel(SpinLock);
    KxReleaseQueuedSpinLock(&v39);
    v10 = 1;
LABEL_73:
    if ( (BYTE6(PerfGlobalGroupMask) & 0x21) == 0 || PopHibernateInProgress )
    {
      v32 = 0;
      if ( _interlockedbittestandset(v7, 0x1Fu) )
      {
        LOBYTE(a2) = -1;
        v32 = ExpWaitForSpinLockExclusiveAndAcquire(v7, a2);
      }
      v33 = *(unsigned int *)v7;
      v34 = v33 & 0xFFFFFFFFBFFFFFFFuLL;
      if ( (v33 & 0xBFFFFFFF) != 0x80000000 )
      {
        do
        {
          if ( (v33 & 0x40000000) == 0 )
            _InterlockedOr(v7, 0x40000000u);
          if ( (++v32 & HvlLongSpinCountMask) == 0
            && (HvlEnlightenments & 0x40) != 0
            && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall(v34, v33) )
          {
            HvlNotifyLongSpinWait(v32);
          }
          else
          {
            _mm_pause();
          }
          v33 = *(unsigned int *)v7;
        }
        while ( (*v7 & 0xBFFFFFFF) != 0x80000000 );
      }
    }
    else
    {
      LOBYTE(a2) = -1;
      ExpAcquireSpinLockExclusiveAtDpcLevelInstrumented(v7, a2);
    }
  }
  if ( v10 )
  {
    if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 || PopHibernateInProgress )
      *SpinLock = 0;
    else
      ExpReleaseSpinLockExclusiveFromDpcLevelInstrumented(SpinLock, retaddr);
  }
  else if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 || PopHibernateInProgress )
  {
    _InterlockedAnd(SpinLock, 0xBFFFFFFF);
    _InterlockedDecrement(SpinLock);
  }
  else
  {
    ExpReleaseSpinLockSharedFromDpcLevelInstrumented(SpinLock, retaddr);
  }
  *((_BYTE *)a1 + 7) &= ~0x80u;
  if ( *((_BYTE *)a1 + 9) )
  {
    v22 = v18 + 7;
    if ( (*((_BYTE *)a1 + 11) & 2) != 0 )
    {
      --*((_BYTE *)v18 + 84);
      *((_BYTE *)a1 + 11) &= ~2u;
    }
    if ( (*((_BYTE *)a1 + 11) & 4) != 0 )
    {
      *((_DWORD *)v18 + 21) ^= ((unsigned __int16)*((_DWORD *)v18 + 21)
                              ^ (unsigned __int16)(((unsigned __int16)(*((_DWORD *)v18 + 21) >> 8) - 1) << 8))
                             & 0x7F00;
      *((_BYTE *)a1 + 11) &= ~4u;
    }
  }
  else
  {
    v22 = v18 + 5;
  }
  RtlRbRemoveNode(v22, a1 + 2);
  if ( (BYTE6(PerfGlobalGroupMask) & 1) == 0 )
    goto LABEL_45;
LABEL_33:
  if ( !PopHibernateInProgress )
  {
    KiReleaseQueuedSpinLockInstrumented(&v39, retaddr);
    goto LABEL_35;
  }
LABEL_45:
  v23 = v39;
  v24 = (_QWORD)v39 == 0;
  _m_prefetchw(&v39);
  if ( v24 )
  {
    if ( (__int128 *)_InterlockedCompareExchange64(*((volatile signed __int64 **)&v39 + 1), 0, (signed __int64)&v39) != &v39 )
    {
      v23 = KxWaitForLockChainValid(&v39);
      goto LABEL_48;
    }
  }
  else
  {
LABEL_48:
    *(_QWORD *)&v39 = 0;
    v25 = BYTE8(v39);
    if ( ((v25 ^ (unsigned __int8)_InterlockedExchange64((volatile __int64 *)(v23 + 8), *((__int64 *)&v39 + 1))) & 4) != 0 )
      KeWakeAddressAll();
  }
LABEL_35:
  _InterlockedDecrement8((volatile signed __int8 *)(a1[-11 * ((_BYTE)a1[1] & 0x3F) - 2] - (*((_BYTE *)a1 + 9) != 0) + 793));
  if ( KiIrqlFlags )
    KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), CurrentIrql);
  __writecr8(CurrentIrql);
  return CurrentIrql;
}

```

// --- Calls: ExfReleasePushLock at 0x1402116f0 (Depth: 1) ---
// Language: C/C++
```cpp
__int64 __fastcall ExfReleasePushLock(_QWORD *a1)
{
  _m_prefetchw(a1);
  if ( (*a1 & 2) != 0 || *a1 >= 0x10u )
    return ExfReleasePushLockShared();
  else
    return ExfReleasePushLockExclusive();
}

```

// --- Calls: ExfReleasePushLockExclusive at 0x140211720 (Depth: 2) ---
// Language: C/C++
```cpp
int __fastcall ExfReleasePushLockExclusive(volatile signed __int64 *a1)
{
  signed __int64 v1; // rax
  __int64 v2; // r8
  signed __int64 v3; // rdx
  signed __int64 v4; // rtt

  v1 = _InterlockedCompareExchange64(a1, 0, 1);
  if ( v1 != 1 )
  {
    do
    {
      if ( (v1 & 4) != 0 || (v1 & 2) == 0 )
        v2 = -1;
      else
        v2 = 3;
      v3 = v2 + v1;
      v4 = v1;
      v1 = _InterlockedCompareExchange64(a1, v2 + v1, v1);
    }
    while ( v4 != v1 );
    if ( v2 == 3 )
      LODWORD(v1) = ExpWakePushLock(a1, v3);
  }
  return v1;
}

```

// --- Calls: ExfReleasePushLockShared at 0x140211290 (Depth: 2) ---
// Language: C/C++
```cpp
int __fastcall ExfReleasePushLockShared(signed __int64 *a1)
{
  signed __int64 v2; // rax
  signed __int64 v3; // r8
  signed __int64 v4; // rtt
  __int64 v5; // r8
  __int64 v6; // rdx
  signed __int64 v7; // rcx
  signed __int64 v8; // rdx
  signed __int64 v9; // rtt
  unsigned __int64 i; // rcx
  __int64 v11; // rdx

  _m_prefetchw(a1);
  v2 = *a1;
  while ( (v2 & 2) == 0 )
  {
    v3 = 0;
    if ( (v2 & 0xFFFFFFFFFFFFFFF0uLL) != 0x10 )
      v3 = v2 - 16;
    v4 = v2;
    v2 = _InterlockedCompareExchange64(a1, v3, v2);
    if ( v4 == v2 )
      return v2;
  }
  if ( (v2 & 8) != 0 )
  {
    for ( i = v2 & 0xFFFFFFFFFFFFFFF0uLL; ; i = *(_QWORD *)(i + 24) )
    {
      v11 = *(_QWORD *)(i + 32);
      if ( v11 )
        break;
    }
    if ( _InterlockedDecrement((volatile signed __int32 *)(v11 + 48)) > 0 )
      return v2;
    v5 = -9;
  }
  else
  {
    v5 = -1;
  }
  do
  {
    v6 = v5 + 4;
    v7 = v2 & 6;
    if ( v7 != 2 )
      v6 = v5;
    v8 = v2 + v6;
    v9 = v2;
    v2 = _InterlockedCompareExchange64(a1, v8, v2);
  }
  while ( v9 != v2 );
  if ( v7 == 2 )
    LODWORD(v2) = ExpWakePushLock(a1, v8);
  return v2;
}

```

// --- Calls: KeAbPostRelease at 0x14026b390 (Depth: 1) ---
// Language: C/C++
```cpp
void __fastcall KeAbPostRelease(ULONG_PTR BugCheckParameter2)
{
  struct _KTHREAD *CurrentThread; // r10
  _KLOCK_ENTRIES *KernelAbEntries; // r8
  unsigned int i; // eax
  char *v4; // rbx
  __int64 v5; // rdx
  struct _KPRCB *CurrentPrcb; // rcx
  signed __int32 *SchedulerAssist; // r8
  signed __int32 v8; // eax
  signed __int32 v9; // ett

  CurrentThread = KeGetCurrentThread();
  _disable();
  KernelAbEntries = CurrentThread->KernelAbEntries;
  for ( i = 0; i < KernelAbEntries->EntryCount; ++i )
  {
    v4 = (char *)KernelAbEntries + 88 * i;
    v5 = *((_QWORD *)v4 + 2);
    if ( (v5 & 0x7FFFFFFFFFFFFFFCLL) == (BugCheckParameter2 & 0x7FFFFFFFFFFFFFFCLL) && v4[26] && (v5 & 1) == 0 )
    {
      v4[26] = 0;
      KiAbEntryFreeAndEnableInterrupts((__int64)(v4 + 16), (ULONG_PTR)CurrentThread, BugCheckParameter2, 1, 0);
      return;
    }
  }
  if ( (*((_DWORD *)&CurrentThread->$F6E8E81C3EACE4482EE2626591212BC8::$3C37BCD2CC8A9A13CF8DF3DA08EBA37B::__s0 + 1)
      & 0x10000) == 0 )
    KeBugCheckEx(0x162u, (ULONG_PTR)CurrentThread, BugCheckParameter2, 0, 0);
  CurrentPrcb = KeGetCurrentPrcb();
  SchedulerAssist = (signed __int32 *)CurrentPrcb->SchedulerAssist;
  if ( SchedulerAssist )
  {
    _m_prefetchw(SchedulerAssist);
    v8 = *SchedulerAssist;
    do
    {
      v9 = v8;
      v8 = _InterlockedCompareExchange(SchedulerAssist, v8 & 0xFFDFFFFF, v8);
    }
    while ( v9 != v8 );
    if ( (v8 & 0x200000) != 0 )
      KiRemoveSystemWorkPriorityKick((__int64)CurrentPrcb);
  }
  _enable();
}

```



--- Struct Member Usage & Data Cross-References ---
// No struct context could be determined for this function.

--- Decompiler Warnings ---
using guessed type __int64 WNF_CONT_CONTAINER_STATE;
using guessed type __int64 __fastcall ExfReleasePushLock(_QWORD, _QWORD, _QWORD, _QWORD);
using guessed type __int64 __fastcall ExfAcquirePushLockExclusiveEx(_QWORD, _QWORD, _QWORD);
using guessed type __int64 __fastcall KeAbPreAcquire(_QWORD, _QWORD, _QWORD);
using guessed type __int64 __fastcall PsGetServerSiloGlobals(_QWORD);
using guessed type __int64 __fastcall PsAttachSiloToCurrentThread(_QWORD);
using guessed type __int64 PsIsHostSilo(void);
using guessed type __int64 __fastcall PsDetachSiloFromCurrentThread(_QWORD);
using guessed type __int64 __fastcall EtwpContainerStateWnfCallback();
using guessed type __int64 __fastcall EtwpQueryPartitionRegistryInformation(_DWORD, _DWORD, _DWORD, _DWORD, __int64, __int64);
using guessed type __int64 __fastcall EtwpQuerySiloRegistrySettings(_QWORD);
using guessed type __int64 __fastcall EtwpUnsubscribeContainerStateWnf();
using guessed type __int64 __fastcall EtwpInitializeAutoLoggers(_QWORD);
using guessed type __int64 __fastcall ExSubscribeWnfStateChange(_DWORD, _DWORD, _DWORD, _DWORD, __int64, __int64);
using guessed type __int64 qword_1410077D8;
using guessed type __int64 qword_1410077E0;

Function: 1407841fc
Prototype: __int64()

--- Decompiled C/C++ ---
__int64 SepInitializeCodeIntegrity()
{
  unsigned int v0; // edi
  __int64 v1; // rcx
  unsigned int *v2; // rdx
  char *v3; // rbx
  char *v4; // rcx
  __int64 v5; // rax
  __int128 v7; // [rsp+30h] [rbp-38h] BYREF
  __int128 v8; // [rsp+40h] [rbp-28h]
  __int64 v9; // [rsp+50h] [rbp-18h]

  v9 = 0;
  v7 = 0;
  v0 = 6;
  v8 = 0;
  memset_0(&unk_140F04704, 0, 0xF4u);
  SeCiCallbacks = 256;
  qword_140F047F8 = 167772176;
  if ( KeLoaderBlock_0 )
  {
    v1 = *(_QWORD *)(KeLoaderBlock_0 + 240);
    if ( v1 )
    {
      v2 = *(unsigned int **)(v1 + 2904);
      if ( v2 )
        v0 = *v2;
    }
    v3 = *(char **)(KeLoaderBlock_0 + 216);
    if ( v3 )
    {
      v4 = strstr(*(const char **)(KeLoaderBlock_0 + 216), "MINTCBIGNOREKD");
      if ( v4 )
      {
        v5 = -1;
        do
          ++v5;
        while ( aMintcbignorekd[v5] );
        if ( (v4 == v3 || *(v4 - 1) == 32) && (v4[(unsigned int)v5] & 0xDF) == 0 )
          SeCiDebugOptions |= 1u;
      }
    }
    *(_QWORD *)&v7 = KeLoaderBlock_0 + 80;
    *((_QWORD *)&v7 + 1) = KeLoaderBlock_0 + 112;
    *(_QWORD *)&v8 = KeLoaderBlock_0 + 64;
    *((_QWORD *)&v8 + 1) = KeLoaderBlock_0 + 96;
    v9 = KeLoaderBlock_0 + 48;
  }
  return CiInitialize(v0, &v7, 5, &SeCiCallbacks, SeCiPrivateApis);
}


--- Local Variables ---
// unsigned int v0; // location: di, size: 4
// __int64 v1; // location: cx, size: 8
// unsigned int * v2; // location: dx, size: 8
// char * v3; // location: bx, size: 8
// char * v4; // location: cx, size: 8
// __int64 v5; // location: ax, size: 8
// __int64 ; // location: ax, size: 8
// __int128 v7; // location: ^30, size: 16
// __int128 v8; // location: ^40, size: 16
// __int64 v9; // location: ^50, size: 8


--- String Literals Referenced ---
"MINTCBIGNOREKD"


--- Callers (Functions that call this one) ---
// --- Called by: SepInitializeCodeIntegrity at 0x1407841fc (Depth: 0) ---
// Language: C/C++
```cpp
__int64 SepInitializeCodeIntegrity()
{
  unsigned int v0; // edi
  __int64 v1; // rcx
  unsigned int *v2; // rdx
  char *v3; // rbx
  char *v4; // rcx
  __int64 v5; // rax
  __int128 v7; // [rsp+30h] [rbp-38h] BYREF
  __int128 v8; // [rsp+40h] [rbp-28h]
  __int64 v9; // [rsp+50h] [rbp-18h]

  v9 = 0;
  v7 = 0;
  v0 = 6;
  v8 = 0;
  memset_0(&unk_140F04704, 0, 0xF4u);
  SeCiCallbacks = 256;
  qword_140F047F8 = 167772176;
  if ( KeLoaderBlock_0 )
  {
    v1 = *(_QWORD *)(KeLoaderBlock_0 + 240);
    if ( v1 )
    {
      v2 = *(unsigned int **)(v1 + 2904);
      if ( v2 )
        v0 = *v2;
    }
    v3 = *(char **)(KeLoaderBlock_0 + 216);
    if ( v3 )
    {
      v4 = strstr(*(const char **)(KeLoaderBlock_0 + 216), "MINTCBIGNOREKD");
      if ( v4 )
      {
        v5 = -1;
        do
          ++v5;
        while ( aMintcbignorekd[v5] );
        if ( (v4 == v3 || *(v4 - 1) == 32) && (v4[(unsigned int)v5] & 0xDF) == 0 )
          SeCiDebugOptions |= 1u;
      }
    }
    *(_QWORD *)&v7 = KeLoaderBlock_0 + 80;
    *((_QWORD *)&v7 + 1) = KeLoaderBlock_0 + 112;
    *(_QWORD *)&v8 = KeLoaderBlock_0 + 64;
    *((_QWORD *)&v8 + 1) = KeLoaderBlock_0 + 96;
    v9 = KeLoaderBlock_0 + 48;
  }
  return CiInitialize(v0, &v7, 5, &SeCiCallbacks, SeCiPrivateApis);
}

```

// --- Called by: SepInitializationPhase1 at 0x140784c10 (Depth: 1) ---
// Language: Assembly
```cpp
PAGE:0000000140784C10
PAGE:0000000140784C10 ; =============== S U B R O U T I N E ==========…
PAGE:0000000140784C10
PAGE:0000000140784C10 ; Attributes: bp-based frame fpd=57h
PAGE:0000000140784C10
PAGE:0000000140784C10 ; __int64 SepInitializationPhase1(void)
PAGE:0000000140784C10 SepInitializationPhase1 proc near       ; CODE X…
PAGE:0000000140784C10                                         ; SeInit…
PAGE:0000000140784C10                                         ; DATA X…
PAGE:0000000140784C10
PAGE:0000000140784C10 InitialState    = byte ptr -0B0h
PAGE:0000000140784C10 var_A8          = byte ptr -0A8h
PAGE:0000000140784C10 var_A0          = qword ptr -0A0h
PAGE:0000000140784C10 DirectoryHandle = qword ptr -90h
PAGE:0000000140784C10 UnicodeString   = UNICODE_STRING ptr -88h
PAGE:0000000140784C10 EventHandle     = qword ptr -78h
PAGE:0000000140784C10 ObjectAttributes= OBJECT_ATTRIBUTES ptr -70h
PAGE:0000000140784C10 DestinationString= STRING ptr -40h
PAGE:0000000140784C10 SecurityDescriptor= byte ptr -30h
PAGE:0000000140784C10 var_8           = qword ptr -8
PAGE:0000000140784C10 var_s0          = byte ptr  0
PAGE:0000000140784C10
PAGE:0000000140784C10 ; __unwind { // __GSHandlerCheck
PAGE:0000000140784C10                 mov     rax, rsp
PAGE:0000000140784C13                 mov     [rax+8], rbx
PAGE:0000000140784C17                 mov     [rax+10h], rsi
PAGE:0000000140784C1B                 mov     [rax+18h], rdi
PAGE:0000000140784C1F                 mov     [rax+20h], r12
PAGE:0000000140784C23                 push    rbp
PAGE:0000000140784C24                 lea     rbp, [rax-5Fh]
PAGE:0000000140784C28                 sub     rsp, 0D0h
PAGE:0000000140784C2F                 mov     rax, cs:__security_cooki…
PAGE:0000000140784C36                 xor     rax, rsp
PAGE:0000000140784C39                 mov     [rbp+57h+var_8], rax
PAGE:0000000140784C3D                 xor     r12d, r12d
PAGE:0000000140784C40                 xorps   xmm0, xmm0
PAGE:0000000140784C43                 movups  xmmword ptr [rbp+57h+Des…
PAGE:0000000140784C47                 mov     dword ptr [rbp+57h+Objec…
PAGE:0000000140784C4B                 mov     dword ptr [rbp+57h+Objec…
PAGE:0000000140784C4F                 mov     [rbp+57h+DirectoryHandle…
PAGE:0000000140784C53                 mov     [rbp+57h+EventHandle], r…
PAGE:0000000140784C57                 movups  xmmword ptr [rbp+57h+Uni…
PAGE:0000000140784C5B                 call    PsIsCurrentThreadInServe…
PAGE:0000000140784C60                 mov     dil, al
PAGE:0000000140784C63                 test    al, al
PAGE:0000000140784C65                 jnz     short loc_140784CB6
PAGE:0000000140784C67                 mov     rcx, gs:188h
PAGE:0000000140784C70                 xor     r9d, r9d
PAGE:0000000140784C73                 mov     [rsp+0D0h+var_A0], r12 ;…
PAGE:0000000140784C78                 xor     r8d, r8d
PAGE:0000000140784C7B                 mov     qword ptr [rsp+0D0h+var_…
PAGE:0000000140784C80                 mov     dword ptr [rsp+0D0h+Init…
PAGE:0000000140784C85                 mov     rdx, [rcx+0B8h]
PAGE:0000000140784C8C                 mov     rcx, [rdx+248h]
PAGE:0000000140784C93                 xor     edx, edx
PAGE:0000000140784C95                 and     rcx, 0FFFFFFFFFFFFFFF0h …
PAGE:0000000140784C99                 call    ObInsertObjectEx
PAGE:0000000140784C9E                 call    SeMakeAnonymousLogonToke…
PAGE:0000000140784CA3                 mov     cs:SeAnonymousLogonToken…
PAGE:0000000140784CAA                 call    SeMakeAnonymousLogonToke…
PAGE:0000000140784CAF                 mov     cs:SeAnonymousLogonToken…
PAGE:0000000140784CB6
PAGE:0000000140784CB6 loc_140784CB6:                          ; CODE X…
PAGE:0000000140784CB6                 lea     rdx, aSecurity  ; "\\Sec…
PAGE:0000000140784CBD                 lea     rcx, [rbp+57h+Destinatio…
PAGE:0000000140784CC1                 call    RtlInitAnsiString
PAGE:0000000140784CC6                 mov     r8b, 1          ; Alloca…
PAGE:0000000140784CC9                 lea     rdx, [rbp+57h+Destinatio…
PAGE:0000000140784CCD                 lea     rcx, [rbp+57h+UnicodeStr…
PAGE:0000000140784CD1                 call    RtlAnsiStringToUnicodeSt…
PAGE:0000000140784CD6                 mov     edx, 1          ; Revisi…
PAGE:0000000140784CDB                 lea     rcx, [rbp+57h+SecurityDe…
PAGE:0000000140784CDF                 call    RtlCreateSecurityDescrip…
PAGE:0000000140784CE4                 mov     edx, 100h
PAGE:0000000140784CE9                 mov     ecx, 40h ; '@'  ; BugChe…
PAGE:0000000140784CEE                 mov     r8d, 20206553h
PAGE:0000000140784CF4                 call    ExAllocatePool2
PAGE:0000000140784CF9                 mov     rbx, rax
PAGE:0000000140784CFC                 test    rax, rax
PAGE:0000000140784CFF                 jz      loc_140784E84
PAGE:0000000140784D05                 mov     esi, 2
PAGE:0000000140784D0A                 mov     edx, 100h       ; AclLen…
PAGE:0000000140784D0F                 mov     r8d, esi        ; AclRev…
PAGE:0000000140784D12                 mov     rcx, rax        ; Acl
PAGE:0000000140784D15                 call    RtlCreateAcl
PAGE:0000000140784D1A                 mov     rcx, cs:SeLocalSystemSid
PAGE:0000000140784D21                 mov     r9d, 0F000Fh    ; int
PAGE:0000000140784D27                 mov     [rsp+0D0h+var_A8], r12b …
PAGE:0000000140784D2C                 xor     r8d, r8d        ; int
PAGE:0000000140784D2F                 mov     qword ptr [rsp+0D0h+Init…
PAGE:0000000140784D34                 mov     edx, esi        ; int
PAGE:0000000140784D36                 mov     rcx, rbx        ; int
PAGE:0000000140784D39                 call    RtlpAddKnownAce
PAGE:0000000140784D3E                 mov     rax, cs:SeAliasAdminsSid
PAGE:0000000140784D45                 mov     r9d, 20003h     ; int
PAGE:0000000140784D4B                 mov     [rsp+0D0h+var_A8], r12b …
PAGE:0000000140784D50                 xor     r8d, r8d        ; int
PAGE:0000000140784D53                 mov     edx, esi        ; int
PAGE:0000000140784D55                 mov     qword ptr [rsp+0D0h+Init…
PAGE:0000000140784D5A                 mov     rcx, rbx        ; int
PAGE:0000000140784D5D                 call    RtlpAddKnownAce
PAGE:0000000140784D62                 mov     rax, cs:SeWorldSid
PAGE:0000000140784D69                 mov     r9d, esi        ; int
PAGE:0000000140784D6C                 mov     [rsp+0D0h+var_A8], r12b …
PAGE:0000000140784D71                 xor     r8d, r8d        ; int
PAGE:0000000140784D74                 mov     edx, esi        ; int
PAGE:0000000140784D76                 mov     qword ptr [rsp+0D0h+Init…
PAGE:0000000140784D7B                 mov     rcx, rbx        ; int
PAGE:0000000140784D7E                 call    RtlpAddKnownAce
PAGE:0000000140784D83                 xor     r9d, r9d        ; DaclDe…
PAGE:0000000140784D86                 lea     rcx, [rbp+57h+SecurityDe…
PAGE:0000000140784D8A                 mov     r8, rbx         ; Dacl
PAGE:0000000140784D8D                 mov     dl, 1           ; DaclPr…
PAGE:0000000140784D8F                 call    RtlSetDaclSecurityDescri…
PAGE:0000000140784D94                 lea     rax, [rbp+57h+UnicodeStr…
PAGE:0000000140784D98                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784D9C                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784DA0                 lea     r8, [rbp+57h+ObjectAttri…
PAGE:0000000140784DA4                 lea     rax, [rbp+57h+SecurityDe…
PAGE:0000000140784DA8                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784DAF                 mov     esi, 30h ; '0'
PAGE:0000000140784DB4                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784DB8                 mov     edx, 0F000Fh    ; Desire…
PAGE:0000000140784DBD                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784DC0                 lea     rcx, [rbp+57h+DirectoryH…
PAGE:0000000140784DC4                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784DC8                 call    ZwCreateDirectoryObject
PAGE:0000000140784DCD                 lea     rcx, [rbp+57h+UnicodeStr…
PAGE:0000000140784DD1                 call    RtlFreeAnsiString
PAGE:0000000140784DD6                 xor     edx, edx        ; Tag
PAGE:0000000140784DD8                 mov     rcx, rbx        ; P
PAGE:0000000140784DDB                 call    ExFreePoolWithTag
PAGE:0000000140784DE0                 lea     rdx, aLsaAuthenticat ; "…
PAGE:0000000140784DE7                 lea     rcx, [rbp+57h+Destinatio…
PAGE:0000000140784DEB                 call    RtlInitAnsiString
PAGE:0000000140784DF0                 mov     r8b, 1          ; Alloca…
PAGE:0000000140784DF3                 lea     rdx, [rbp+57h+Destinatio…
PAGE:0000000140784DF7                 lea     rcx, [rbp+57h+UnicodeStr…
PAGE:0000000140784DFB                 call    RtlAnsiStringToUnicodeSt…
PAGE:0000000140784E00                 mov     rax, [rbp+57h+DirectoryH…
PAGE:0000000140784E04                 lea     r8, [rbp+57h+ObjectAttri…
PAGE:0000000140784E08                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784E0C                 lea     rcx, [rbp+57h+EventHandl…
PAGE:0000000140784E10                 lea     rax, [rbp+57h+UnicodeStr…
PAGE:0000000140784E14                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784E17                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784E1B                 xor     r9d, r9d        ; EventT…
PAGE:0000000140784E1E                 mov     rax, cs:SePublicDefaultS…
PAGE:0000000140784E25                 mov     edx, 40000000h  ; Desire…
PAGE:0000000140784E2A                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784E2E                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784E35                 mov     [rbp+57h+ObjectAttribute…
PAGE:0000000140784E39                 mov     [rsp+0D0h+InitialState],…
PAGE:0000000140784E3E                 call    ZwCreateEvent
PAGE:0000000140784E43                 lea     rcx, [rbp+57h+UnicodeStr…
PAGE:0000000140784E47                 call    RtlFreeAnsiString
PAGE:0000000140784E4C                 mov     rcx, [rbp+57h+DirectoryH…
PAGE:0000000140784E50                 call    ZwClose
PAGE:0000000140784E55                 mov     rcx, [rbp+57h+EventHandl…
PAGE:0000000140784E59                 call    ZwClose
PAGE:0000000140784E5E                 test    dil, dil
PAGE:0000000140784E61                 jnz     short loc_140784E7B
PAGE:0000000140784E63                 call    SepInitProcessAuditSd
PAGE:0000000140784E68                 call    SepInitializeCodeIntegri…
PAGE:0000000140784E6D                 call    SepInitializeAuthorizati…
PAGE:0000000140784E72                 call    SepInitializeSingletonAt…
PAGE:0000000140784E77                 test    eax, eax
PAGE:0000000140784E79                 js      short loc_140784E84
PAGE:0000000140784E7B
PAGE:0000000140784E7B loc_140784E7B:                          ; CODE X…
PAGE:0000000140784E7B                 call    SddlBaseInitialize
PAGE:0000000140784E80                 mov     al, 1
PAGE:0000000140784E82                 jmp     short loc_140784E86
PAGE:0000000140784E84 ; ----------------------------------------------…
PAGE:0000000140784E84
PAGE:0000000140784E84 loc_140784E84:                          ; CODE X…
PAGE:0000000140784E84                                         ; SepIni…
PAGE:0000000140784E84                 xor     al, al
PAGE:0000000140784E86
PAGE:0000000140784E86 loc_140784E86:                          ; CODE X…
PAGE:0000000140784E86                 mov     rcx, [rbp+57h+var_8]
PAGE:0000000140784E8A                 xor     rcx, rsp        ; StackC…
PAGE:0000000140784E8D                 call    __security_check_cookie
PAGE:0000000140784E92                 lea     r11, [rsp+0D0h+var_s0]
PAGE:0000000140784E9A                 mov     rbx, [r11+10h]
PAGE:0000000140784E9E                 mov     rsi, [r11+18h]
PAGE:0000000140784EA2                 mov     rdi, [r11+20h]
PAGE:0000000140784EA6                 mov     r12, [r11+28h]
PAGE:0000000140784EAA                 mov     rsp, r11
PAGE:0000000140784EAD                 pop     rbp
PAGE:0000000140784EAE                 retn
PAGE:0000000140784EAE ; ----------------------------------------------…
PAGE:0000000140784EAF                 db 0CCh
PAGE:0000000140784EAF ; } // starts at 140784C10
PAGE:0000000140784EAF SepInitializationPhase1 endp
PAGE:0000000140784EAF

```

// --- Called by: SeInitServerSilo at 0x140784a7c (Depth: 2) ---
// Language: C/C++
```cpp
__int64 __fastcall SeInitServerSilo(__int64 a1)
{
  __int64 ServerSiloGlobals; // rsi
  __int64 v3; // rbp
  signed int LogonSessionTrack; // ebx

  if ( (unsigned __int8)PsIsHostSilo() )
    KeBugCheckEx(0x33u, 0, 0, 0, 0);
  ServerSiloGlobals = PsGetServerSiloGlobals(a1);
  v3 = PsAttachSiloToCurrentThread();
  LogonSessionTrack = SepCreateLogonSessionTrack(&SeSystemAuthenticationId);
  if ( LogonSessionTrack >= 0 )
  {
    LogonSessionTrack = SepReferenceLogonSessionSilo(&SeSystemAuthenticationId, a1, ServerSiloGlobals + 736);
    if ( LogonSessionTrack >= 0 )
    {
      LogonSessionTrack = SepCreateLogonSessionTrack(&SeAnonymousAuthenticationId);
      if ( LogonSessionTrack < 0 )
        goto LABEL_9;
      LogonSessionTrack = SepReferenceLogonSessionSilo(&SeAnonymousAuthenticationId, a1, ServerSiloGlobals + 744);
      if ( LogonSessionTrack >= 0 )
      {
        LogonSessionTrack = (unsigned __int8)SepInitializationPhase1() == 0 ? 0xC0000001 : 0;
        goto LABEL_9;
      }
    }
    SepDeleteLogonSessionTrack(&SeSystemAuthenticationId, 0);
  }
LABEL_9:
  PsDetachSiloFromCurrentThread(v3);
  return (unsigned int)LogonSessionTrack;
}

```

// --- Called by: PspInitializeServerSiloDeferred at 0x140768ba0 (Depth: 3) ---
// Language: C/C++
```cpp
__int64 __fastcall PspInitializeServerSiloDeferred(_QWORD *Object)
{
  __int64 ServerSiloGlobals; // rbp
  int ApiSets; // edi
  __int64 v4; // r14
  __int64 v5; // rbx
  __int64 v6; // rcx
  __int64 v7; // r14
  __int64 v8; // rbx
  __int64 v9; // rbx
  __int64 v10; // rbx
  unsigned int CurrentSiloMaxLoggers; // eax
  __int64 v12; // rbx
  __int64 v13; // rax
  int v14; // eax
  int v15; // eax
  unsigned int v16; // ebx
  __int64 v18; // rax
  char v19; // [rsp+40h] [rbp+8h] BYREF
  char v20; // [rsp+48h] [rbp+10h] BYREF

  ServerSiloGlobals = PsGetServerSiloGlobals(Object);
  RtlNlsInitState(ServerSiloGlobals);
  ApiSets = sub_14064CCEC(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspSiloInitializeUserSharedData(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspSiloInitializeSystemRootSymlink(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspInitializeProtectedProcessParameters(ServerSiloGlobals);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = PspSiloLoadApiSets(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v4 = Object[188];
  v19 = 0;
  v5 = PsAttachSiloToCurrentThread(Object);
  ApiSets = ExIsMultiSessionSku(&v19);
  PsDetachSiloFromCurrentThread(v5);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v6 = *(_QWORD *)(v4 + 1288);
  v20 = 0;
  *(_BYTE *)(v6 + 28) = v19;
  v7 = Object[188];
  v8 = PsAttachSiloToCurrentThread(Object);
  ApiSets = ExIsStateSeparationEnabled(&v20);
  PsDetachSiloFromCurrentThread(v8);
  if ( ApiSets < 0 )
    goto LABEL_25;
  *(_BYTE *)(*(_QWORD *)(v7 + 1288) + 29LL) = v20;
  v9 = PsAttachSiloToCurrentThread(Object);
  ApiSets = RtlInitFunctionalityCache();
  PsDetachSiloFromCurrentThread(v9);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = ObInitServerSilo(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = ExpTimeZoneInitSiloState(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v10 = PsAttachSiloToCurrentThread(Object);
  ApiSets = ExInitializeNls();
  if ( ApiSets >= 0 )
    *(_QWORD *)(*(_QWORD *)(PsGetCurrentServerSiloGlobals() + 1024) + 8LL) = 1;
  PsDetachSiloFromCurrentThread(v10);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = SeInitServerSilo((__int64)Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  ApiSets = CmInitServerSiloState(Object);
  if ( ApiSets < 0 )
    goto LABEL_25;
  CurrentSiloMaxLoggers = EtwpGetCurrentSiloMaxLoggers();
  ApiSets = EtwpPreInitializeSiloState(Object, CurrentSiloMaxLoggers);
  if ( ApiSets < 0 || (ApiSets = EtwpInitializeSiloState(Object, 0), ApiSets < 0) )
  {
    v18 = PsGetServerSiloGlobals(Object);
    EtwpCleanupSiloState(*(PVOID *)(v18 + 832));
LABEL_25:
    *(_DWORD *)(ServerSiloGlobals + 1272) = 4;
    PspDeleteExternalServerSiloState(Object);
    return (unsigned int)ApiSets;
  }
  v12 = PsAttachSiloToCurrentThread(Object);
  v13 = PsGetServerSiloGlobals(Object);
  *(_QWORD *)(v13 + 936) = 0;
  v14 = DbgkpInitializePhase1SiloState(v13 + 936);
  ApiSets = 0;
  if ( v14 < 0 )
    ApiSets = v14;
  PsDetachSiloFromCurrentThread(v12);
  if ( ApiSets < 0 )
    goto LABEL_25;
  v15 = PspNotifyServerSiloCreation(Object);
  v16 = v15;
  if ( v15 >= 0 )
    return 0;
  PsTerminateServerSilo(Object, (unsigned int)v15);
  return v16;
}

```

// --- Called by: PspQueueDeferredWorkAndWait at 0x140768e08 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 __fastcall PspQueueDeferredWorkAndWait(__int64 a1, _QWORD *a2)
{
  struct _WORK_QUEUE_ITEM WorkItem; // [rsp+30h] [rbp-50h] BYREF
  struct _KEVENT Event; // [rsp+50h] [rbp-30h] BYREF
  __int64 (__fastcall *v6)(_QWORD *); // [rsp+68h] [rbp-18h]
  _QWORD *v7; // [rsp+70h] [rbp-10h]
  unsigned int v8; // [rsp+78h] [rbp-8h]
  int v9; // [rsp+7Ch] [rbp-4h]

  WorkItem.List.Blink = 0;
  memset(&Event, 0, sizeof(Event));
  v9 = 0;
  if ( (KeGetCurrentThread()->ApcState.Process[3].ActiveGroupsMask.Masks[1] & 0x100000000000LL) != 0 )
    return PspInitializeServerSiloDeferred(a2);
  KeInitializeEvent(&Event, SynchronizationEvent, 0);
  v8 = 0;
  WorkItem.List.Flink = 0;
  v6 = PspInitializeServerSiloDeferred;
  v7 = a2;
  WorkItem.WorkerRoutine = (void (__fastcall *)(void *))PspDeferredWorkerRoutine;
  WorkItem.Parameter = &Event;
  ExQueueWorkItem(&WorkItem, DelayedWorkQueue);
  KeWaitForSingleObject(&Event, UserRequest, 0, 0, 0);
  return v8;
}

```

// --- Called by: PspConvertSiloToServerSilo at 0x140768674 (Depth: 5) ---
// Language: C/C++
```cpp
__int64 __fastcall PspConvertSiloToServerSilo(__int64 a1, __int64 a2, ULONG_PTR a3, int a4)
{
  unsigned int v7; // ebx
  char *Pool2; // rax
  char *v10; // rdi
  int SiloRootDirectoryPath; // ebp
  struct _KTHREAD *CurrentThread; // r14
  __int64 v13; // rcx

  v7 = 0;
  if ( (unsigned __int8)PsIsCurrentThreadInServerSilo() )
    return 3221225569LL;
  Pool2 = (char *)ExAllocatePool2(0x48u);
  v10 = Pool2;
  if ( !Pool2 )
    return 3221225626LL;
  *((_DWORD *)Pool2 + 318) = 0;
  *((_DWORD *)Pool2 + 319) = 259;
  *((_DWORD *)Pool2 + 334) = a4;
  if ( a3
    && (SiloRootDirectoryPath = ObpReferenceObjectByHandleWithTag(a3, 0x65446953u, (__int64)(Pool2 + 1280), 0, 0),
        SiloRootDirectoryPath < 0)
    || (SiloRootDirectoryPath = ObGetSiloRootDirectoryPath(a1, v10 + 1248), SiloRootDirectoryPath < 0)
    || ((CurrentThread = KeGetCurrentThread(),
         PspLockJobExclusive(a1, CurrentThread),
         !(unsigned __int8)PsIsServerSilo(a1))
      ? (!PsGetParentSilo()
       ? (!(unsigned __int8)PspJobHasChildren(a1)
        ? ((*(_DWORD *)(a1 + 256) & 0x400000) != 0
         ? (*(_QWORD *)(a1 + 1504) = v10, SiloRootDirectoryPath = 0)
         : (SiloRootDirectoryPath = -1073741811))
        : (SiloRootDirectoryPath = -1073740529))
       : (SiloRootDirectoryPath = -1073741791))
      : (SiloRootDirectoryPath = -1073740536),
        PspUnlockJob(a1, CurrentThread),
        SiloRootDirectoryPath < 0) )
  {
    PspDeleteServerSiloGlobals(v10);
    return (unsigned int)SiloRootDirectoryPath;
  }
  else
  {
    EtwTraceJobServerSiloStateChange(a1, 0);
    if ( (int)PspQueueDeferredWorkAndWait(v13, (_QWORD *)a1) < 0 )
      return (unsigned int)-1073740955;
    return v7;
  }
}

```

// --- Called by: NtSetInformationJobObject at 0x140ac2d90 (Depth: 6) ---
// Language: C/C++
```cpp
__int64 __fastcall NtSetInformationJobObject(ULONG_PTR BugCheckParameter1, int a2, void *a3, unsigned int a4)
{
  size_t v4; // r12
  __int64 v5; // rdi
  unsigned int v7; // ecx
  bool v8; // zf
  __m128i *v9; // r13
  __int64 result; // rax
  __int64 v11; // rdx
  int v12; // esi
  char v13; // bl
  int v14; // eax
  int v15; // r8d
  unsigned __int64 v16; // rdx
  unsigned __int64 v17; // r9
  unsigned __int64 v18; // r11
  unsigned __int64 v19; // r10
  ULONG_PTR MiniCompletionPacket; // rbx
  PRKEVENT v21; // r14
  void *v22; // rdi
  unsigned int v23; // ebx
  struct _ERESOURCE *p_WaitListHead; // rcx
  int Silo; // eax
  unsigned int v26; // r13d
  __int64 v27; // r9
  char v28; // al
  unsigned int v29; // eax
  char v30; // al
  unsigned __int64 v31; // r14
  unsigned int v32; // r13d
  __int64 v33; // rdi
  struct _LIST_ENTRY *v34; // rsi
  struct _LIST_ENTRY *v35; // rcx
  ULONG v36; // edx
  BOOLEAN v37; // al
  unsigned int v38; // r13d
  struct _LIST_ENTRY *v39; // r13
  unsigned __int16 PrimaryGroupThread; // ax
  __int64 v41; // rax
  struct _SECURITY_SUBJECT_CONTEXT *v42; // rax
  struct _KEVENT *v43; // rcx
  __int64 *v44; // rax
  bool v45; // cf
  __int64 v46; // rax
  __int64 v47; // rdi
  struct _LIST_ENTRY *p_Blink; // rsi
  struct _LIST_ENTRY *i; // rdi
  PVOID v50; // rcx
  unsigned int v51; // ecx
  unsigned int v52; // ebx
  unsigned __int16 v53; // di
  __int64 v54; // r14
  unsigned __int16 epi16; // ax
  __int64 v56; // rax
  struct _LIST_ENTRY *Pool2; // rdi
  SECURITY_IMPERSONATION_LEVEL *p_ImpersonationLevel; // r13
  BOOLEAN v59; // al
  __int64 v60; // rax
  struct _SECURITY_SUBJECT_CONTEXT *v61; // rax
  struct _KEVENT *v62; // rdx
  __int64 *v63; // rax
  __int64 v64; // r8
  __int64 v65; // rsi
  struct _LIST_ENTRY *v66; // rdi
  int v67; // eax
  __int64 v68; // r8
  struct _LIST_ENTRY *v69; // r9
  unsigned int v70; // edx
  __int64 v71; // rdx
  int v72; // eax
  LONG v73; // edi
  char v74; // bl
  int v75; // esi
  bool v76; // cc
  int v77; // eax
  __int64 RateControl; // rax
  __int64 v79; // rdx
  __int16 v80; // cx
  struct _LIST_ENTRY *v81; // rax
  struct _LIST_ENTRY *v82; // rcx
  struct _LIST_ENTRY *v83; // rcx
  int v84; // ebx
  __int64 v85; // rcx
  int v86; // r8d
  struct _ERESOURCE *v87; // rbx
  KPROCESSOR_MODE v88; // bl
  BOOLEAN v89; // al
  __int64 v90; // rdx
  BOOLEAN v91; // al
  unsigned __int64 v92; // rcx
  __int64 v93; // rdx
  __int64 v94; // rax
  __int64 v95; // rdx
  __int64 v96; // r8
  unsigned int v97; // edx
  int v98; // eax
  int v99; // edx
  int *v100; // r9
  int *v101; // r10
  int v102; // r8d
  struct _LIST_ENTRY **v103; // r13
  struct _LIST_ENTRY *v104; // rbx
  void *v105; // rsi
  struct _LIST_ENTRY *v106; // rbx
  int Flink; // edi
  __int64 v108; // rdx
  _DWORD *v109; // rax
  __int64 v110; // r8
  __int64 v111; // rdx
  __int64 v112; // r9
  _DWORD *v113; // rax
  _DWORD *v114; // r8
  int v115; // edx
  struct _LIST_ENTRY *v116; // rax
  struct _LIST_ENTRY *v117; // r8
  int JobMemoryUsageNotificationViolations; // ebx
  _WORD *v119; // rbx
  unsigned __int16 v120; // cx
  ULONG_PTR v121; // rcx
  _WORD *v122; // rax
  ULONG v123; // edx
  void *v124; // rcx
  char v125; // bl
  PETHREAD v126; // r13
  BOOLEAN v127; // al
  unsigned __int64 v128; // xmm0_8
  PVOID v129; // rbx
  unsigned __int16 v130; // si
  void *v131; // rax
  void *v132; // rdi
  PETHREAD v133; // r13
  signed __int32 v134[8]; // [rsp+0h] [rbp-C98h] BYREF
  PRKEVENT Event; // [rsp+40h] [rbp-C58h] BYREF
  KPROCESSOR_MODE PreviousMode; // [rsp+48h] [rbp-C50h]
  int v137; // [rsp+4Ch] [rbp-C4Ch]
  __int16 v138; // [rsp+50h] [rbp-C48h] BYREF
  KPROCESSOR_MODE v139; // [rsp+52h] [rbp-C46h]
  int v140; // [rsp+58h] [rbp-C40h]
  unsigned __int16 v141; // [rsp+60h] [rbp-C38h]
  unsigned int v142; // [rsp+64h] [rbp-C34h]
  struct _LIST_ENTRY *v143; // [rsp+68h] [rbp-C30h] BYREF
  int JobLimitInformationValidFlags; // [rsp+70h] [rbp-C28h]
  __int64 v145; // [rsp+78h] [rbp-C20h]
  PETHREAD Thread; // [rsp+80h] [rbp-C18h]
  PVOID P; // [rsp+88h] [rbp-C10h]
  __int8 v148; // [rsp+90h] [rbp-C08h]
  __int8 v149; // [rsp+91h] [rbp-C07h]
  __int64 v150; // [rsp+98h] [rbp-C00h]
  PVOID Object[2]; // [rsp+A0h] [rbp-BF8h] BYREF
  ULONG_PTR BugCheckParameter1a[2]; // [rsp+B0h] [rbp-BE8h] BYREF
  void *Src; // [rsp+C0h] [rbp-BD8h]
  PSECURITY_SUBJECT_CONTEXT v154; // [rsp+C8h] [rbp-BD0h]
  unsigned int v155; // [rsp+D0h] [rbp-BC8h]
  struct _SECURITY_SUBJECT_CONTEXT SubjectContext; // [rsp+D8h] [rbp-BC0h] BYREF
  void *v157; // [rsp+F8h] [rbp-BA0h]
  __int64 v158[2]; // [rsp+100h] [rbp-B98h] BYREF
  __int64 v159; // [rsp+110h] [rbp-B88h] BYREF
  struct _LIST_ENTRY *v160; // [rsp+118h] [rbp-B80h] BYREF
  __int64 v161; // [rsp+120h] [rbp-B78h] BYREF
  void *v162; // [rsp+128h] [rbp-B70h]
  __m128i v163; // [rsp+130h] [rbp-B68h] BYREF
  unsigned int v164; // [rsp+140h] [rbp-B58h]
  __int32 v165; // [rsp+144h] [rbp-B54h]
  __int32 v166; // [rsp+148h] [rbp-B50h]
  __int32 v167; // [rsp+14Ch] [rbp-B4Ch]
  int v168; // [rsp+150h] [rbp-B48h]
  __int32 v169; // [rsp+154h] [rbp-B44h]
  __int128 v170; // [rsp+158h] [rbp-B40h] BYREF
  __int128 v171; // [rsp+168h] [rbp-B30h]
  __m128i v172; // [rsp+180h] [rbp-B18h]
  __m128i v173; // [rsp+190h] [rbp-B08h]
  __m128i v174; // [rsp+1A0h] [rbp-AF8h]
  __m128i v175; // [rsp+1B0h] [rbp-AE8h]
  __int64 v176; // [rsp+1C0h] [rbp-AD8h]
  __int64 v177; // [rsp+1D0h] [rbp-AC8h]
  ULONG_PTR v178; // [rsp+1D8h] [rbp-AC0h]
  __int64 v179; // [rsp+1E0h] [rbp-AB8h]
  _BYTE v180[16]; // [rsp+1F0h] [rbp-AA8h] BYREF
  __int64 v181; // [rsp+200h] [rbp-A98h]
  void *v182; // [rsp+208h] [rbp-A90h]
  int v183; // [rsp+214h] [rbp-A84h]
  unsigned __int16 v184; // [rsp+218h] [rbp-A80h]
  __int64 v185; // [rsp+228h] [rbp-A70h]
  __int64 v186; // [rsp+240h] [rbp-A58h]
  struct _PRIVILEGE_SET RequiredPrivileges; // [rsp+280h] [rbp-A18h] BYREF
  __int128 v188; // [rsp+2A0h] [rbp-9F8h] BYREF
  _BYTE v189[28]; // [rsp+2B0h] [rbp-9E8h]
  unsigned __int64 v190; // [rsp+2D0h] [rbp-9C8h]
  __m128i v191; // [rsp+2F0h] [rbp-9A8h] BYREF
  __int128 v192; // [rsp+300h] [rbp-998h] BYREF
  __int128 v193; // [rsp+310h] [rbp-988h]
  __int128 v194; // [rsp+320h] [rbp-978h]
  __int64 v195; // [rsp+330h] [rbp-968h]
  __int128 v196; // [rsp+338h] [rbp-960h] BYREF
  __int128 v197; // [rsp+348h] [rbp-950h]
  __int128 v198; // [rsp+358h] [rbp-940h]
  struct _LIST_ENTRY *v199; // [rsp+370h] [rbp-928h] BYREF
  struct _LIST_ENTRY *v200; // [rsp+378h] [rbp-920h]
  __int64 v201; // [rsp+380h] [rbp-918h]
  unsigned __int64 v202; // [rsp+388h] [rbp-910h]
  unsigned __int64 v203; // [rsp+390h] [rbp-908h]
  int v204; // [rsp+398h] [rbp-900h]
  __int64 v205; // [rsp+3A0h] [rbp-8F8h]
  unsigned int v206; // [rsp+3A8h] [rbp-8F0h]
  unsigned int v207; // [rsp+3ACh] [rbp-8ECh]
  unsigned __int64 v208; // [rsp+3E0h] [rbp-8B8h]
  unsigned __int64 v209; // [rsp+3E8h] [rbp-8B0h]
  unsigned __int64 v210; // [rsp+400h] [rbp-898h]
  __int64 v211; // [rsp+410h] [rbp-888h] BYREF
  _QWORD v212[33]; // [rsp+418h] [rbp-880h] BYREF
  char v213[224]; // [rsp+520h] [rbp-778h] BYREF
  struct _LIST_ENTRY *v214; // [rsp+600h] [rbp-698h]
  struct _LIST_ENTRY *Blink; // [rsp+608h] [rbp-690h]
  unsigned __int64 v216; // [rsp+610h] [rbp-688h]
  struct _LIST_ENTRY *v217; // [rsp+618h] [rbp-680h]
  unsigned int v218; // [rsp+620h] [rbp-678h]
  int v219; // [rsp+624h] [rbp-674h]
  __int64 v220; // [rsp+628h] [rbp-670h] BYREF
  char v221[308]; // [rsp+630h] [rbp-668h] BYREF
  int v222; // [rsp+764h] [rbp-534h]
  struct _LIST_ENTRY *v223; // [rsp+7D0h] [rbp-4C8h]
  unsigned __int64 v224; // [rsp+7D8h] [rbp-4C0h]
  struct _LIST_ENTRY *v225; // [rsp+7E0h] [rbp-4B8h]
  char v226; // [rsp+96Dh] [rbp-32Bh]

  v4 = a4;
  v5 = a2;
  v150 = BugCheckParameter1;
  v140 = a2;
  v142 = a2;
  Src = a3;
  memset_0(v212, 0, 0x100u);
  v160 = 0;
  v159 = 0;
  v138 = 0;
  v161 = 0;
  memset_0(&v199, 0, 0x98u);
  v191 = 0;
  v163 = 0;
  Object[0] = 0;
  memset_0(v180, 0, 0x90u);
  Event = 0;
  v170 = 0;
  v171 = 0;
  memset(&SubjectContext, 0, sizeof(SubjectContext));
  LODWORD(v157) = 0;
  memset_0(&v188, 0, 0x48u);
  v196 = 0;
  v197 = 0;
  v198 = 0;
  v192 = 0;
  v193 = 0;
  v194 = 0;
  v195 = 0;
  v143 = 0;
  memset(&RequiredPrivileges, 0, sizeof(RequiredPrivileges));
  BugCheckParameter1a[0] = 0;
  *(_OWORD *)v158 = 0;
  if ( (unsigned int)(v5 - 1) > 0x32 )
    return 3221225475LL;
  switch ( (_DWORD)v5 )
  {
    case 9:
      if ( (_DWORD)v4 == 144 || (_DWORD)v4 == 152 )
        goto LABEL_14;
      return 3221225476LL;
    case 0xC:
      v8 = (((_DWORD)v4 - 48) & 0xFFFFFFF7) == 0;
LABEL_13:
      if ( v8 )
        goto LABEL_14;
      return 3221225476LL;
    case 0x1F:
      if ( (_DWORD)v4 == 48 || (_DWORD)v4 == 96 )
        goto LABEL_14;
      v8 = (_DWORD)v4 == 144;
      goto LABEL_13;
  }
  v7 = dword_140B3499C[v5];
  if ( (_DWORD)v4 != v7 && ((_DWORD)v5 != 11 && (_DWORD)v5 != 14 || (unsigned int)v4 < v7) )
    return 3221225476LL;
LABEL_14:
  Thread = KeGetCurrentThread();
  PreviousMode = Thread->PreviousMode;
  v139 = PreviousMode;
  if ( PreviousMode )
  {
    v9 = (__m128i *)Src;
    if ( (_DWORD)v4 )
    {
      if ( ((dword_140B34A6C[v5] - 1) & (unsigned int)Src) != 0 )
        ExRaiseDatatypeMisalignment();
      if ( (unsigned __int64)Src + v4 > 0x7FFFFFFF0000LL || (char *)Src + v4 < Src )
        v9 = (__m128i *)Src;
    }
  }
  else
  {
    v9 = (__m128i *)Src;
  }
  if ( !BugCheckParameter1 )
    return 3221225480LL;
  result = ObpReferenceObjectByHandleWithTag(BugCheckParameter1, 0x79517350u, (__int64)&Event, 0, 0);
  if ( (int)result >= 0 )
  {
    v12 = 0;
    v137 = 0;
    v13 = 0;
    --Thread->SpecialApcDisable;
    if ( v140 <= 25 )
    {
      if ( v140 != 25 )
      {
        if ( v140 <= 14 )
        {
          if ( v140 == 14 )
          {
LABEL_190:
            P = 0;
            v51 = 16;
            if ( v142 != 14 )
              v51 = 2;
            v142 = v51;
            v52 = (unsigned int)v4 / v51;
            if ( (unsigned int)v4 % v51 )
            {
              v12 = -1073741820;
              goto LABEL_446;
            }
            v155 = (unsigned int)v4 / v51;
            v211 = 2097153;
            memset_0(v212, 0, 0x100u);
            v53 = KeQueryActiveGroupCount() - 1;
            v54 = v142;
            while ( v52 )
            {
              if ( v140 == 14 )
              {
                v163 = *v9;
                epi16 = _mm_extract_epi16(v163, 4);
                v141 = epi16;
                v150 = v163.m128i_i64[0];
              }
              else
              {
                v56 = v9->m128i_u16[0];
                v141 = v56;
                if ( (unsigned __int16)v56 > v53 )
                  goto LABEL_204;
                v150 = KeActiveProcessors.Bitmap[v56];
                epi16 = v141;
              }
              if ( epi16 > v53 || v212[epi16] || v150 != (v150 & KeActiveProcessors.Bitmap[epi16]) )
              {
LABEL_204:
                v12 = -1073741811;
                v137 = -1073741811;
                break;
              }
              KeAddGroupAffinityEx(&v211, v141);
              v52 = --v155;
              v9 = (__m128i *)((char *)Src + v54);
              Src = (char *)Src + v54;
              v12 = v137;
            }
            Pool2 = 0;
            v21 = Event;
            if ( v12 < 0 )
              goto LABEL_485;
            if ( !*(_QWORD *)&Event[22].Header.Lock )
            {
              Pool2 = (struct _LIST_ENTRY *)ExAllocatePool2(0x100u);
              if ( !Pool2 )
                goto LABEL_123;
              P = (PVOID)PsChargeSharedPoolQuota(KeGetCurrentThread()->ApcState.Process, 40);
              if ( !P )
              {
                v35 = Pool2;
                goto LABEL_126;
              }
              v21 = Event;
            }
            SeCaptureSubjectContextEx(
              Thread,
              Thread->ApcState.Process,
              (PSECURITY_SUBJECT_CONTEXT)&SubjectContext.ImpersonationLevel);
            p_ImpersonationLevel = &SubjectContext.ImpersonationLevel;
            if ( PreviousMode )
            {
              RequiredPrivileges.PrivilegeCount = 1;
              RequiredPrivileges.Control = 1;
              RequiredPrivileges.Privilege[0].Luid = SeDebugPrivilege;
              RequiredPrivileges.Privilege[0].Attributes = 0;
              v59 = SePrivilegeCheck(
                      &RequiredPrivileges,
                      (PSECURITY_SUBJECT_CONTEXT)&SubjectContext.ImpersonationLevel,
                      1);
              LODWORD(SubjectContext.ClientToken) = (__int64)SubjectContext.ClientToken & 0xFFFFFFFE | v59 & 1;
            }
            else
            {
              LODWORD(SubjectContext.ClientToken) |= 1u;
            }
            ExAcquireResourceExclusiveLite((PERESOURCE)&v21[2].Header.WaitListHead, 1u);
            v12 = PspEnumJobsAndProcessesInJobHierarchy(v21, (__int64)&SubjectContext, 1);
            v137 = v12;
            if ( v12 >= 0 )
            {
              v60 = *(_QWORD *)&v21[22].Header.Lock;
              if ( v60 )
              {
                v170 = *(_OWORD *)(v60 + 8);
                v171 = *(_OWORD *)(v60 + 24);
                p_ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL *)&v170;
              }
              else
              {
                *(_QWORD *)&v21[22].Header.Lock = Pool2;
                v21[22].Header.WaitListHead.Flink = (struct _LIST_ENTRY *)P;
                Pool2 = 0;
                p_ImpersonationLevel = 0;
              }
              v61 = *(struct _SECURITY_SUBJECT_CONTEXT **)&v21[22].Header.Lock;
              *v61 = SubjectContext;
              v61[1].ClientToken = v157;
              v158[0] = (__int64)v21;
              HIDWORD(v158[1]) = v21[10].Header.WaitListHead.Blink;
              LODWORD(v158[1]) = -17;
              v62 = v21 + 11;
              v63 = &v211;
              v64 = 2;
              do
              {
                *(_OWORD *)&v62->Header.Lock = *(_OWORD *)v63;
                *(_OWORD *)&v62->Header.WaitListHead.Blink = *((_OWORD *)v63 + 1);
                v62[1].Header.WaitListHead = (LIST_ENTRY)*((_OWORD *)v63 + 2);
                *(_OWORD *)&v62[2].Header.Lock = *((_OWORD *)v63 + 3);
                *(_OWORD *)&v62[2].Header.WaitListHead.Blink = *((_OWORD *)v63 + 4);
                v62[3].Header.WaitListHead = (LIST_ENTRY)*((_OWORD *)v63 + 5);
                *(_OWORD *)&v62[4].Header.Lock = *((_OWORD *)v63 + 6);
                v62 = (struct _KEVENT *)((char *)v62 + 128);
                v62[-1].Header.WaitListHead = (LIST_ENTRY)*((_OWORD *)v63 + 7);
                v63 += 16;
                --v64;
              }
              while ( v64 );
              *(_QWORD *)&v62->Header.Lock = *v63;
              if ( v140 == 14 && (unsigned int)KeIsEmptyAffinityEx(&v21[11], v62, 0, 128) )
              {
                LODWORD(v21[10].Header.WaitListHead.Blink) &= ~0x10u;
                _InterlockedAnd((volatile signed __int32 *)&v21[64].Header.WaitListHead.Blink, 0xFFFFFFFD);
              }
              else
              {
                LODWORD(v21[10].Header.WaitListHead.Blink) |= 0x10u;
                _InterlockedOr((volatile signed __int32 *)&v21[64].Header.WaitListHead.Blink, 2u);
              }
              v21 = Event;
              PspEnumJobsAndProcessesInJobHierarchy(Event, (__int64)v158, 5);
              v12 = v137;
            }
            ExReleaseResourceLite((PERESOURCE)&v21[2].Header.WaitListHead);
            if ( p_ImpersonationLevel )
              SeReleaseSubjectContext((PSECURITY_SUBJECT_CONTEXT)p_ImpersonationLevel);
            if ( !Pool2 )
              goto LABEL_485;
            ExFreePoolWithTag(Pool2, 0x614A7350u);
            v50 = P;
LABEL_229:
            PsReturnSharedPoolQuota(v50);
            goto LABEL_485;
          }
          if ( v140 == 2 )
          {
LABEL_70:
            memmove(&v199, v9, v4);
            if ( (unsigned int)v4 < 0x98 )
              memset_0((char *)&v199 + v4, 0, 152 - v4);
            JobLimitInformationValidFlags = PspGetJobLimitInformationValidFlags((unsigned int)v140, (unsigned int)v4);
            v26 = v201;
            if ( (~JobLimitInformationValidFlags & (unsigned int)v201) != 0 )
              goto LABEL_73;
            memset_0(v213, 0, 0x728u);
            memset(&SubjectContext, 0, sizeof(SubjectContext));
            v157 = 0;
            v218 = v26;
            P = 0;
            v145 = 0;
            v154 = 0;
            v219 = (v26 & 8) != 0 ? v204 : 0;
            if ( (v26 & 0x20) != 0 )
            {
              if ( v206 > 6 )
                goto LABEL_456;
              if ( v206 - 3 <= 1 )
              {
                LOBYTE(v27) = PreviousMode;
                v28 = ((__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD))SeCheckPrivilegedObject)(
                        SeIncreaseBasePriorityPrivilege,
                        v150,
                        2,
                        v27)
                    & 1;
                v13 = 4 * v28;
                if ( !v28 )
                  goto LABEL_78;
              }
              v226 = v206;
            }
            else
            {
              v226 = 0;
            }
            if ( (v26 & 0x80u) == 0 )
            {
              v222 = 5;
            }
            else
            {
              v29 = v207;
              if ( v207 >= 0xA )
                goto LABEL_456;
              if ( v207 > 5 )
              {
                LOBYTE(v27) = PreviousMode;
                v30 = ((__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD))SeCheckPrivilegedObject)(
                        SeIncreaseBasePriorityPrivilege,
                        v150,
                        2,
                        v27)
                    & 1;
                v13 = 4 * v30;
                if ( !v30 )
                  goto LABEL_78;
                v29 = v207;
              }
              v222 = v29;
            }
            if ( (v26 & 2) != 0 )
            {
              if ( !v199 )
                goto LABEL_456;
              v214 = v199;
            }
            else
            {
              v214 = 0;
            }
            if ( (v26 & 4) != 0 )
            {
              if ( !v200 )
                goto LABEL_456;
              Blink = v200;
            }
            if ( (v26 & 1) == 0 )
            {
              v216 = 0;
              v217 = 0;
              goto LABEL_106;
            }
            v31 = v202;
            if ( !v202 && !v203 || v202 == -1 && v203 == -1 || v202 > v203 || v202 < 0x14000 )
              goto LABEL_456;
            if ( v202 <= PspMinimumWorkingSet || SeSinglePrivilegeCheck(SeIncreaseBasePriorityPrivilege, PreviousMode) )
            {
              v216 = v31;
              v217 = (struct _LIST_ENTRY *)v203;
LABEL_106:
              if ( (v26 & 0x100) != 0 )
              {
                if ( v208 < 0x1000 )
                  goto LABEL_456;
                v223 = (struct _LIST_ENTRY *)(v208 >> 12);
              }
              else
              {
                v223 = 0;
              }
              if ( (v26 & 0x200) != 0 )
              {
                if ( v209 < 0x1000 )
                  goto LABEL_456;
                v224 = v209 >> 12;
              }
              else
              {
                v224 = 0;
              }
              if ( (v26 & 0x200000) == 0 )
              {
                v225 = 0;
                goto LABEL_118;
              }
              if ( v210 >= 0x1000 )
              {
                v225 = (struct _LIST_ENTRY *)(v210 >> 12);
LABEL_118:
                v220 = 2097153;
                memset_0(v221, 0, 0x100u);
                v32 = v218;
                v142 = v218;
                v21 = Event;
                v33 = 2;
                if ( (v218 & 0x10) == 0 )
                  goto LABEL_133;
                if ( ((__int64)Event[64].Header.WaitListHead.Blink & 2) == 0 && v205 )
                {
                  if ( !*(_QWORD *)&Event[22].Header.Lock )
                  {
                    v34 = (struct _LIST_ENTRY *)ExAllocatePool2(0x100u);
                    P = v34;
                    if ( !v34 )
                      goto LABEL_123;
                    v145 = PsChargeSharedPoolQuota(KeGetCurrentThread()->ApcState.Process, 40);
                    if ( !v145 )
                    {
                      v35 = v34;
LABEL_126:
                      v36 = 1632269136;
LABEL_127:
                      ExFreePoolWithTag(v35, v36);
                      v12 = -1073741670;
                      goto LABEL_446;
                    }
                    v21 = Event;
                    v142 = v218;
                    v12 = v137;
                  }
                  SeCaptureSubjectContextEx(
                    Thread,
                    Thread->ApcState.Process,
                    (PSECURITY_SUBJECT_CONTEXT)&SubjectContext.ImpersonationLevel);
                  v154 = (PSECURITY_SUBJECT_CONTEXT)&SubjectContext.ImpersonationLevel;
                  if ( PreviousMode )
                  {
                    RequiredPrivileges.PrivilegeCount = 1;
                    RequiredPrivileges.Control = 1;
                    RequiredPrivileges.Privilege[0].Luid = SeDebugPrivilege;
                    RequiredPrivileges.Privilege[0].Attributes = 0;
                    v37 = SePrivilegeCheck(
                            &RequiredPrivileges,
                            (PSECURITY_SUBJECT_CONTEXT)&SubjectContext.ImpersonationLevel,
                            1);
                    LODWORD(SubjectContext.ClientToken) = (__int64)SubjectContext.ClientToken & 0xFFFFFFFE | v37 & 1;
                  }
                  else
                  {
                    LODWORD(SubjectContext.ClientToken) |= 1u;
                  }
                  v13 |= 2u;
                  v32 = v142;
LABEL_133:
                  ExAcquireResourceExclusiveLite((PERESOURCE)&v21[2].Header.WaitListHead, 1u);
                  if ( (v32 & 4) == 0 )
                  {
                    if ( (v32 & 0x40) != 0 )
                    {
                      v32 |= (__int64)v21[10].Header.WaitListHead.Blink & 4;
                      Blink = v21[9].Header.WaitListHead.Blink;
                    }
                    else
                    {
                      Blink = 0;
                    }
                  }
                  v38 = v32 & 0xFFFFFFBF;
                  v218 = v38;
                  if ( (v13 & 2) != 0 )
                  {
                    if ( ((__int64)v21[64].Header.WaitListHead.Blink & 2) != 0 )
                    {
LABEL_139:
                      v12 = -1073741811;
                      v137 = -1073741811;
LABEL_140:
                      v39 = (struct _LIST_ENTRY *)v145;
LABEL_173:
                      if ( (v13 & 1) != 0 )
                      {
                        v46 = KeAbPreAcquire(&qword_140FC60B8, 0, 0);
                        v47 = v46;
                        if ( _interlockedbittestandset64((volatile signed __int32 *)&qword_140FC60B8, 0) )
                          ExfAcquirePushLockExclusiveEx(&qword_140FC60B8, v46, &qword_140FC60B8);
                        if ( v47 )
                          *(_BYTE *)(v47 + 10) = 1;
                        _InterlockedOr((volatile signed __int32 *)&Event[64].Header.WaitListHead.Blink, 0x100u);
                        v21 = Event;
                        p_Blink = (struct _LIST_ENTRY *)&Event[1].Header.WaitListHead.Blink;
                        for ( i = Event[1].Header.WaitListHead.Blink; i != p_Blink; i = i->Flink )
                        {
                          if ( ((__int64)i[-23].Blink & 1) == 0 )
                            PspAddProcessToWorkingSetChangeList(&i[-54].Blink);
                        }
                        v12 = v137;
                      }
                      ExReleaseResourceLite((PERESOURCE)&v21[2].Header.WaitListHead);
                      if ( (v13 & 1) != 0 )
                        PspApplyWorkingSetLimits(v21);
                      if ( v154 )
                        SeReleaseSubjectContext(v154);
                      if ( !P )
                        goto LABEL_485;
                      ExFreePoolWithTag(P, 0x614A7350u);
                      v50 = v39;
                      goto LABEL_229;
                    }
                    if ( ((__int64)v21[10].Header.WaitListHead.Blink & 0x10) != 0 )
                    {
                      KeFirstGroupAffinityEx(&v163, &v21[11]);
                      PrimaryGroupThread = v163.m128i_u16[4];
                    }
                    else
                    {
                      PrimaryGroupThread = KeQueryPrimaryGroupThread(KeGetCurrentThread());
                      v163.m128i_i16[4] = PrimaryGroupThread;
                    }
                    if ( v205 != (KeActiveProcessors.Bitmap[PrimaryGroupThread] & v205) )
                    {
                      v21 = Event;
                      goto LABEL_139;
                    }
                    KeAddGroupAffinityEx(&v220, v163.m128i_u16[4]);
                    v21 = Event;
                    v12 = PspEnumJobsAndProcessesInJobHierarchy(Event, (__int64)&SubjectContext, 1);
                    v137 = v12;
                    if ( v12 < 0 )
                      goto LABEL_140;
                    v41 = *(_QWORD *)&v21[22].Header.Lock;
                    v39 = (struct _LIST_ENTRY *)v145;
                    if ( v41 )
                    {
                      v170 = *(_OWORD *)(v41 + 8);
                      v171 = *(_OWORD *)(v41 + 24);
                      v154 = (PSECURITY_SUBJECT_CONTEXT)&v170;
                    }
                    else
                    {
                      *(_QWORD *)&v21[22].Header.Lock = P;
                      v21[22].Header.WaitListHead.Flink = v39;
                      P = 0;
                      v154 = 0;
                    }
                    v42 = *(struct _SECURITY_SUBJECT_CONTEXT **)&v21[22].Header.Lock;
                    *v42 = SubjectContext;
                    v42[1].ClientToken = v157;
                  }
                  else
                  {
                    v45 = (v38 & 0x4000) != 0;
                    v39 = (struct _LIST_ENTRY *)v145;
                    if ( v45 && ((__int64)v21[64].Header.WaitListHead.Blink & 2) == 0 )
                    {
                      v12 = -1073741811;
                      v137 = -1073741811;
                      goto LABEL_173;
                    }
                  }
                  if ( ((__int64)v21[10].Header.WaitListHead.Blink & 1) != 0 && (v218 & 1) == 0 )
                  {
                    _InterlockedOr(v134, 0);
                    if ( (qword_140FC60B8 & 1) != 0 )
                      ExfAcquireReleasePushLockExclusive((ULONG_PTR)&qword_140FC60B8);
                    v12 = v137;
                    v21 = Event;
                  }
                  v158[0] = (__int64)v21;
                  HIDWORD(v158[1]) = v21[10].Header.WaitListHead.Blink;
                  *(_QWORD *)&v21[10].Header.Lock = v216;
                  v21[10].Header.WaitListHead.Flink = v217;
                  HIDWORD(v21[10].Header.WaitListHead.Blink) = v219;
                  if ( (v13 & 2) != 0 )
                  {
                    v43 = v21 + 11;
                    v44 = &v220;
                    do
                    {
                      *(_OWORD *)&v43->Header.Lock = *(_OWORD *)v44;
                      *(_OWORD *)&v43->Header.WaitListHead.Blink = *((_OWORD *)v44 + 1);
                      v43[1].Header.WaitListHead = (LIST_ENTRY)*((_OWORD *)v44 + 2);
                      *(_OWORD *)&v43[2].Header.Lock = *((_OWORD *)v44 + 3);
                      *(_OWORD *)&v43[2].Header.WaitListHead.Blink = *((_OWORD *)v44 + 4);
                      v43[3].Header.WaitListHead = (LIST_ENTRY)*((_OWORD *)v44 + 5);
                      *(_OWORD *)&v43[4].Header.Lock = *((_OWORD *)v44 + 6);
                      v43 = (struct _KEVENT *)((char *)v43 + 128);
                      v43[-1].Header.WaitListHead = (LIST_ENTRY)*((_OWORD *)v44 + 7);
                      v44 += 16;
                      --v33;
                    }
                    while ( v33 );
                    *(_QWORD *)&v43->Header.Lock = *v44;
                  }
                  BYTE5(v21[45].Header.WaitListHead.Blink) = v226;
                  v21[24].Header.SignalState = v222;
                  v21[9].Header.WaitListHead.Flink = v214;
                  v21[9].Header.WaitListHead.Blink = Blink;
                  if ( v140 == 9 )
                  {
                    PspLockJobMemoryLimitsExclusive(v21, 0, 0);
                    LODWORD(v21[10].Header.WaitListHead.Blink) = v218
                                                               | (__int64)v21[10].Header.WaitListHead.Blink
                                                               & ~JobLimitInformationValidFlags;
                    v21[28].Header.WaitListHead.Blink = v223;
                    *(_QWORD *)&v21[29].Header.Lock = v224;
                    v21[29].Header.WaitListHead.Flink = v225;
                    PspUnlockJobMemoryLimitsExclusive(v21, 0, 0);
                  }
                  else
                  {
                    LODWORD(v21[10].Header.WaitListHead.Blink) = v218
                                                               | (__int64)v21[10].Header.WaitListHead.Blink
                                                               & ~JobLimitInformationValidFlags;
                  }
                  LODWORD(v158[1]) = ~(LODWORD(v21[10].Header.WaitListHead.Blink) | HIDWORD(v158[1]));
                  if ( (v201 & 4) != 0 )
                  {
                    PspEnumJobsAndProcessesInJobHierarchy(v21, (__int64)&v21[9].Header.WaitListHead.Blink, 1);
                    v21[7].Header.WaitListHead.Blink = 0;
                    *(_QWORD *)&v21[8].Header.Lock = 0;
                    KeResetEvent(v21);
                  }
                  if ( ((__int64)v21[10].Header.WaitListHead.Blink & 6) != 0 )
                  {
                    _InterlockedAdd64(&PspJobTimeLimitsRequest, 1u);
                    v21 = Event;
                    v12 = v137;
                  }
                  if ( (v158[1] & 1) == 0 )
                    v13 |= 1u;
                  PspEnumJobsAndProcessesInJobHierarchy(v21, (__int64)v158, 5);
                  goto LABEL_173;
                }
                goto LABEL_460;
              }
LABEL_456:
              v12 = -1073741811;
              goto LABEL_446;
            }
LABEL_78:
            v12 = -1073741727;
            goto LABEL_446;
          }
          if ( v140 != 4 )
          {
            if ( v140 == 5 )
            {
              v172 = *v9;
              v173 = v9[1];
              v174.m128i_i64[0] = v9[2].m128i_i64[0];
              v12 = (v172.m128i_i32[0] & 0xFFFFFFF0) != 0 ? -1073741811 : -1073741637;
LABEL_446:
              v21 = Event;
              goto LABEL_485;
            }
            if ( v140 != 6 )
            {
              if ( v140 == 7 )
              {
                MiniCompletionPacket = 0;
                *(__m128i *)BugCheckParameter1a = *v9;
                if ( BugCheckParameter1a[1] )
                {
                  v12 = ObpReferenceObjectByHandleWithTag(BugCheckParameter1a[1], 0x624A7350u, (__int64)Object, 0, 0);
                  v21 = Event;
                  if ( v12 >= 0 )
                  {
                    if ( Event[51].Header.WaitListHead.Flink
                      || (MiniCompletionPacket = IoAllocateMiniCompletionPacket(&PspNotificationPacketCallback, Event)) != 0 )
                    {
                      ExAcquireResourceExclusiveLite((PERESOURCE)&v21[2].Header.WaitListHead, 1u);
                      if ( *(_QWORD *)&v21[23].Header.Lock
                        || ((__int64)v21[10].Header.WaitListHead.Blink & 0x2000) != 0
                        && ((__int64)v21[64].Header.WaitListHead.Blink & 1) != 0 )
                      {
                        ExReleaseResourceLite((PERESOURCE)&v21[2].Header.WaitListHead);
                        ObfDereferenceObjectWithTag(Object[0], 0x624A7350u);
                        v12 = -1073741811;
                      }
                      else
                      {
                        if ( !v21[51].Header.WaitListHead.Flink )
                        {
                          v21[51].Header.WaitListHead.Flink = (struct _LIST_ENTRY *)MiniCompletionPacket;
                          MiniCompletionPacket = 0;
                        }
                        PspLockJobMemoryLimitsExclusive(v21, 0, 0);
                        v21[23].Header.WaitListHead.Flink = (struct _LIST_ENTRY *)BugCheckParameter1a[0];
                        *(PVOID *)&v21[23].Header.Lock = Object[0];
                        v21[23].Header.WaitListHead.Blink = 0;
                        PspUnlockJobMemoryLimitsExclusive(v21, 0, 0);
                        if ( (v21[46].Header.LockNV & 0x40) != 0 )
                          PspEnumJobsAndProcessesInJobHierarchy(v21, (__int64)v21, 1);
                        ExReleaseResourceLite((PERESOURCE)&v21[2].Header.WaitListHead);
                      }
                    }
                    else
                    {
                      v12 = -1073741670;
                    }
                  }
                  if ( MiniCompletionPacket )
                  {
                    *(_QWORD *)(MiniCompletionPacket + 56) = 0;
                    IopFreeMiniCompletionPacket(MiniCompletionPacket);
                  }
                }
                else
                {
                  v21 = Event;
                  ExAcquireResourceExclusiveLite((PERESOURCE)&Event[2].Header.WaitListHead, 1u);
                  PspLockJobMemoryLimitsExclusive(v21, 0, 0);
                  v22 = *(void **)&v21[23].Header.Lock;
                  *(_QWORD *)&v21[23].Header.Lock = 0;
                  PspUnlockJobMemoryLimitsExclusive(v21, 0, 0);
                  ExReleaseResourceLite((PERESOURCE)&v21[2].Header.WaitListHead);
                  if ( v22 )
                    ObfDereferenceObjectWithTag(v22, 0x624A7350u);
                }
                goto LABEL_485;
              }
              if ( v140 != 9 )
              {
                if ( v140 != 11 )
                {
                  if ( v140 == 12 )
                    goto LABEL_42;
LABEL_445:
                  v12 = -1073741821;
                  goto LABEL_446;
                }
                goto LABEL_190;
              }
              goto LABEL_70;
            }
            v164 = v9->m128i_i32[0];
            v23 = v164;
            v21 = Event;
            if ( v164 <= 1 )
            {
              ExAcquireResourceExclusiveLite((PERESOURCE)&Event[2].Header.WaitListHead, 1u);
              HIDWORD(v21[22].Header.WaitListHead.Blink) = v23;
LABEL_66:
              p_WaitListHead = (struct _ERESOURCE *)&v21[2].Header.WaitListHead;
LABEL_67:
              ExReleaseResourceLite(p_WaitListHead);
              goto LABEL_485;
            }
LABEL_460:
            v12 = -1073741811;
            goto LABEL_485;
          }
          v165 = v9->m128i_i32[0];
          v21 = Event;
          Silo = PspSetUILimitJobObject((__int64)Event);
          goto LABEL_484;
        }
        if ( v140 != 15 )
        {
          if ( v140 != 16 )
          {
            if ( v140 == 18 )
            {
              v191 = *v9;
              if ( !v191.m128i_i32[0] || (v191.m128i_i32[0] & 0xFFFFFFF0) != 0 )
                goto LABEL_73;
              if ( (v191.m128i_i8[0] & 1) != 0 || (v191.m128i_i8[0] & 8) == 0 )
              {
                v21 = Event;
                v12 = PspFreezeJobTree(Event, &v191);
                if ( v12 >= 0 )
                  v9->m128i_i32[0] = v191.m128i_i32[0];
                goto LABEL_485;
              }
              goto LABEL_456;
            }
            if ( v140 != 21 )
            {
              switch ( v140 )
              {
                case 22:
                  LOBYTE(v138) = v9->m128i_i8[0];
                  v21 = Event;
                  ExAcquireResourceExclusiveLite((PERESOURCE)&Event[2].Header.WaitListHead, 1u);
                  if ( ((__int64)v21[64].Header.WaitListHead.Blink & 0x20) == 0 )
                    goto LABEL_238;
                  v69 = v21[51].Header.WaitListHead.Blink;
                  v70 = (unsigned int)v69[2].Blink;
                  if ( (v70 & 0x40) != 0 )
                    goto LABEL_238;
                  if ( (v70 & 0x21) != 0 )
                  {
                    v12 = -1073741637;
                    goto LABEL_66;
                  }
                  if ( ((v70 >> 3) & 1) == ((_BYTE)v138 != 0) )
                    goto LABEL_238;
                  LOBYTE(v68) = -(char)v138;
                  v71 = ((_BYTE)v138 != 0 ? 8 : 0) | v70 & 0xFFFFFFF7;
                  LODWORD(v69[2].Blink) = v71;
                  LOBYTE(v71) = v138;
                  KeSetSchedulingGroupRankBias(&v21[51].Header.WaitListHead.Blink[8], v71, v68);
                  PspEnumJobsAndProcessesInJobHierarchy(v21, (__int64)&v138, 1);
                  break;
                case 23:
                  if ( v9->m128i_i8[0] != 1 )
                  {
                    v12 = -1073741811;
                    v137 = -1073741811;
                    v21 = Event;
                    goto LABEL_485;
                  }
                  v21 = Event;
                  PspEnumJobsAndProcessesInJobHierarchy(Event, 0, 0);
                  goto LABEL_315;
                case 24:
                  v65 = v9->m128i_i64[0];
                  v177 = v9->m128i_i64[0];
                  v21 = Event;
                  ExAcquireResourceExclusiveLite((PERESOURCE)&Event[2].Header.WaitListHead, 1u);
                  if ( ((__int64)v21[64].Header.WaitListHead.Blink & 0x20) == 0 )
                  {
LABEL_238:
                    v12 = -1073741811;
                    goto LABEL_66;
                  }
                  v66 = v21[51].Header.WaitListHead.Blink;
                  v67 = (int)v66[2].Blink;
                  if ( (v67 & 0x10) == 0 )
                  {
                    LODWORD(v66[2].Blink) = v67 | 0x10;
                    KeInitializeDpc((PRKDPC)&v66[3], PspJobCycleTimeNotificationDpcRoutine, v21);
                  }
                  KeSetSchedulingGroupCycleNotification(&v66[8], &v66[3], v65);
                  break;
                default:
                  goto LABEL_445;
              }
              v12 = 0;
              goto LABEL_66;
            }
            v148 = v9->m128i_i8[0];
            v21 = Event;
            v72 = PspSetBackgroundJobTree(Event);
LABEL_253:
            v12 = v72;
            if ( v72 < 0 )
              goto LABEL_485;
            goto LABEL_315;
          }
          v166 = v9->m128i_i32[0];
          v73 = v166;
          v21 = Event;
          if ( (v166 & 0xFFFFC001) != 0 )
            goto LABEL_460;
          ExAcquireResourceExclusiveLite((PERESOURCE)&Event[2].Header.WaitListHead, 1u);
          PspLockJobMemoryLimitsExclusive(v21, 0, 0);
          v21[46].Header.LockNV = v73;
          PspUnlockJobMemoryLimitsExclusive(v21, 0, 0);
          goto LABEL_314;
        }
        memmove(&v159, v9, v4);
        v74 = v159;
        if ( (v159 & 0xFFFFFFC0) != 0 )
          goto LABEL_456;
        v75 = 0;
        LODWORD(v143) = HIDWORD(v159);
        if ( (v159 & 1) == 0 )
        {
LABEL_278:
          v21 = Event;
          PspLockJobChain(Event, Thread, 0);
          v77 = (int)v21[64].Header.WaitListHead.Blink;
          if ( (v74 & 1) != 0 )
          {
            if ( (v77 & 0x20) == 0 )
            {
              RateControl = PspAllocateRateControl(2);
              v79 = RateControl;
              if ( !RateControl )
              {
                v12 = -1073741670;
                goto LABEL_312;
              }
              v21[51].Header.WaitListHead.Blink = (struct _LIST_ENTRY *)RateControl;
LABEL_286:
              LODWORD(v21[51].Header.WaitListHead.Blink[2].Blink) = 0;
              v80 = WORD2(v159);
              HIDWORD(v21[51].Header.WaitListHead.Blink[2].Blink) = HIDWORD(v159);
              if ( (v74 & 1) != 0 )
              {
                if ( (v74 & 4) != 0 )
                {
                  LODWORD(v21[51].Header.WaitListHead.Blink[2].Blink) |= 1u;
                  WORD1(v143) = v80;
                }
                if ( (v74 & 2) != 0 )
                {
                  LODWORD(v21[51].Header.WaitListHead.Blink[2].Blink) |= 4u;
                  HIDWORD(v143) = v75 & 0xFFFFFFFE;
                }
                else
                {
                  HIDWORD(v143) = v75 | 1;
                  if ( (v74 & 0x14) == 0 )
                    WORD1(v143) = 10000;
                }
                if ( (v74 & 8) != 0 )
                  LODWORD(v21[51].Header.WaitListHead.Blink[2].Blink) |= 2u;
                if ( (v74 & 0x10) != 0 )
                  LODWORD(v21[51].Header.WaitListHead.Blink[2].Blink) |= 0x20u;
                if ( (v74 & 0x20) != 0 )
                  LODWORD(v21[51].Header.WaitListHead.Blink[2].Blink) |= 0x80u;
                v81 = v21[51].Header.WaitListHead.Blink;
                v82 = v81 + 8;
                if ( v81 == (struct _LIST_ENTRY *)v79 )
                {
                  v82->Flink = v143;
                  v12 = PspAddSchedulingGroupToJobChain(v21[54].Header.WaitListHead.Flink, v21);
                  v137 = v12;
                  if ( v12 < 0 )
                  {
                    v83 = v21[51].Header.WaitListHead.Blink;
                    if ( v83 )
                    {
                      PspFreeRateControl(v83);
                      v21[51].Header.WaitListHead.Blink = 0;
                    }
                    goto LABEL_312;
                  }
                  _InterlockedOr((volatile signed __int32 *)&v21[64].Header.WaitListHead.Blink, 0x20u);
                  v21 = Event;
                }
                else
                {
                  BugCheckParameter1a[0] = (ULONG_PTR)&v81[8];
                  if ( ((__int64)v81[2].Blink & 4) != 0 )
                    KeSetSchedulingGroupWeights(1, BugCheckParameter1a, &v143);
                  else
                    KeSetSchedulingGroupCpuRates(v82, BugCheckParameter1a, &v143);
                }
                v160 = v21[51].Header.WaitListHead.Blink[2].Blink;
              }
              else
              {
                HIDWORD(v143) = v75 | 3;
                LODWORD(v143) = 655370000;
                LODWORD(v21[51].Header.WaitListHead.Blink[2].Blink) |= 0x40u;
                v84 = (int)v143;
                HIDWORD(v21[51].Header.WaitListHead.Blink[2].Blink) = (_DWORD)v143;
                BugCheckParameter1a[0] = (ULONG_PTR)&v21[51].Header.WaitListHead.Blink[8];
                HIBYTE(v138) = (*(_DWORD *)(BugCheckParameter1a[0] + 4) & 4) != 0;
                v21[52].Header.WaitListHead.Flink = (struct _LIST_ENTRY *)((char *)v21[52].Header.WaitListHead.Flink
                                                                         + KeQuerySchedulingGroupReadyTime(
                                                                             BugCheckParameter1a[0],
                                                                             v79));
                KeSetSchedulingGroupCpuRates(v85, BugCheckParameter1a, &v143);
                HIDWORD(v160) = v84;
                if ( HIBYTE(v138) )
                {
                  HIBYTE(v138) = 0;
                  PspEnumJobsAndProcessesInJobHierarchy(v21, (__int64)&v138 + 1, 1);
                }
              }
              v12 = 0;
              if ( (PerfGlobalGroupMask & 0x80000) != 0 )
                EtwTraceJobSetQuery((_DWORD)v21, 15, (unsigned int)&v160, 0, 0, 1829);
LABEL_312:
              PspUnlockJobChain(v21, Thread, 0);
              goto LABEL_485;
            }
          }
          else if ( (v77 & 0x20) == 0 )
          {
            v12 = -1073741811;
            goto LABEL_312;
          }
          v79 = 0;
          goto LABEL_286;
        }
        if ( (v159 & 2) != 0 )
        {
          if ( (v159 & 0x10) != 0 )
            goto LABEL_456;
          v76 = (unsigned int)(HIDWORD(v159) - 1) <= 8;
        }
        else
        {
          if ( (v159 & 0x10) == 0 )
          {
            if ( (unsigned int)(HIDWORD(v159) - 1) > 0x270F )
              goto LABEL_456;
            goto LABEL_276;
          }
          if ( (v159 & 4) != 0 || !WORD2(v159) || WORD2(v159) > HIWORD(v159) )
            goto LABEL_456;
          v76 = HIWORD(v159) <= 0x2710u;
        }
        if ( !v76 )
          goto LABEL_456;
LABEL_276:
        if ( (v159 & 0x20) != 0 )
          v75 = 8;
        goto LABEL_278;
      }
      v21 = Event;
      ExAcquireResourceExclusiveLite((PERESOURCE)&Event[2].Header.WaitListHead, 1u);
      KeResetEvent(v21);
LABEL_314:
      ExReleaseResourceLite((PERESOURCE)&v21[2].Header.WaitListHead);
      goto LABEL_315;
    }
    if ( v140 > 42 )
    {
      if ( v140 == 43 )
      {
        v179 = v9->m128i_i64[0];
        LOBYTE(v11) = PreviousMode;
        v21 = Event;
        Silo = PspSetJobMemoryPartition(Event, v11);
        goto LABEL_484;
      }
      if ( v140 == 44 )
      {
        v21 = Event;
        ExAcquireResourceExclusiveLite((PERESOURCE)&Event[2].Header.WaitListHead, 1u);
        if ( SLODWORD(v21[64].Header.WaitListHead.Blink) < 0 )
        {
          v12 = -1073741791;
          goto LABEL_66;
        }
        *(__m128i *)&v21[62].Header.Lock = *v9;
        _InterlockedOr((volatile signed __int32 *)&v21[64].Header.WaitListHead.Blink, 0x80000000);
        v21 = Event;
        goto LABEL_314;
      }
      if ( v140 != 45 )
      {
        switch ( v140 )
        {
          case '.':
            v161 = v9->m128i_i64[0];
            v21 = Event;
            v72 = PspSetEnergyTrackingStateJobTree(Event, (__int64)&v161);
            goto LABEL_253;
          case '/':
            v149 = v9->m128i_i8[0];
            if ( v149 != 1 )
              goto LABEL_456;
            v127 = SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode);
            v21 = Event;
            if ( !v127 )
            {
              v12 = -1073741727;
              goto LABEL_485;
            }
            if ( ((__int64)Event[64].Header.WaitListHead.Blink & 0x40000000) == 0 )
              goto LABEL_460;
            v12 = (unsigned __int8)PspSetJobSiloThreadImpersonationPolicy(Event, 2) == 0 ? 0xC0000022 : 0;
LABEL_485:
            v133 = Thread;
            v8 = Thread->SpecialApcDisable++ == -1;
            if ( v8 && ($727077A9B6E167EAE1398C74674DC5A5 *)v133->ApcState.ApcListHead[0].Flink != &v133->___u25 )
              KiCheckForKernelApcDelivery();
            if ( v12 )
            {
              if ( (PerfGlobalGroupMask & 0x80000) != 0 )
                EtwTraceJobSetQuery((_DWORD)v21, v140, 0, 0, v12, 1831);
            }
            ObfDereferenceObjectWithTag(v21, 0x79517350u);
            return (unsigned int)v12;
          case '0':
            Object[0] = (PVOID)v9->m128i_i64[0];
            if ( ((__int64)Object[0] & 0xFFFFFFFE) != 0 )
              goto LABEL_73;
            if ( HIDWORD(Object[0]) >= 5 )
              goto LABEL_456;
            v21 = Event;
            PspSetIoPriorityLimitJobTree(Event);
            break;
          case '1':
            Object[0] = (PVOID)v9->m128i_i64[0];
            if ( ((__int64)Object[0] & 0xFFFFFFFE) != 0 )
              goto LABEL_73;
            if ( HIDWORD(Object[0]) >= 8 )
              goto LABEL_456;
            v21 = Event;
            if ( ((__int64)Object[0] & 1) != 0 && !HIDWORD(Object[0]) )
              goto LABEL_460;
            PspSetPagePriorityLimitJobTree(Event);
            break;
          default:
            goto LABEL_445;
        }
LABEL_315:
        v12 = 0;
        goto LABEL_485;
      }
      v21 = Event;
      if ( ((__int64)Event[64].Header.WaitListHead.Blink & 0x40000000) == 0 )
        goto LABEL_341;
      v162 = 0;
      *(__m128i *)Object = *v9;
      v128 = _mm_srli_si128(*(__m128i *)Object, 8).m128i_u64[0];
      v129 = (PVOID)v128;
      if ( !v128
        || (v130 = (unsigned __int16)Object[0], (unsigned __int16)(LOWORD(Object[0]) - 1) > 0x206u)
        || ((__int64)Object[0] & 1) != 0 )
      {
        v12 = -1073741811;
        v137 = -1073741811;
        goto LABEL_485;
      }
      if ( PreviousMode == 1 )
      {
        if ( (v128 & 1) != 0 )
          ExRaiseDatatypeMisalignment();
        if ( v128 + LOWORD(Object[0]) > 0x7FFFFFFF0000LL || v128 + LOWORD(Object[0]) < v128 )
        {
          v21 = Event;
          v129 = Object[1];
          v130 = (unsigned __int16)Object[0];
        }
      }
      v131 = (void *)ExAllocatePool2(0x100u);
      v132 = v131;
      v162 = v131;
      if ( !v131 )
      {
        v12 = -1073741670;
        v137 = -1073741670;
        goto LABEL_485;
      }
      memmove(v131, v129, v130);
      if ( wcsnlen((const wchar_t *)v132, (unsigned __int64)v130 >> 1) == (unsigned __int64)v130 >> 1 )
      {
        Object[1] = v132;
        v12 = PspAssignSiloSystemRootPath(v21, Object);
      }
      else
      {
        v12 = -1073741811;
      }
      if ( !v132 )
        goto LABEL_485;
      v123 = 1918071632;
      v124 = v132;
LABEL_429:
      ExFreePoolWithTag(v124, v123);
      goto LABEL_485;
    }
    if ( v140 == 42 )
    {
      v125 = 0;
      v172 = *v9;
      v173 = v9[1];
      v174 = v9[2];
      v175 = v9[3];
      v176 = v9[4].m128i_i64[0];
      v21 = Event;
      if ( (v172.m128i_i32[0] & 0xFFFFFFFC) != 0 || (v172.m128i_i8[0] & 3) == 0 )
      {
        v12 = -1073741811;
      }
      else
      {
        v125 = 8;
        v126 = Thread;
        PspLockRootJobExclusive(Event, Thread, BugCheckParameter1a);
        PspLockJobConditionally(v21, BugCheckParameter1a);
        v12 = PspSetJobIoAttribution(v21);
        if ( v12 >= 0 )
        {
          PspUnlockJobConditionally(v21, BugCheckParameter1a);
          PspUnlockJob(BugCheckParameter1a[0], v126);
          v125 = 0;
        }
      }
      if ( v125 == 8 )
      {
        PspUnlockJobConditionally(v21, BugCheckParameter1a);
        PspUnlockJob(BugCheckParameter1a[0], Thread);
      }
      goto LABEL_485;
    }
    if ( v140 == 27 )
    {
      v21 = Event;
      PspLockJobMemoryLimitsExclusive(Event, 0, 0);
      *(_QWORD *)&v21[30].Header.Lock = 0;
      v21[29].Header.WaitListHead.Blink = 0;
      PspUnlockJobMemoryLimitsExclusive(v21, 0, 0);
      v12 = 0;
      goto LABEL_485;
    }
    if ( v140 != 31 )
    {
      switch ( v140 )
      {
        case ' ':
          v21 = Event;
          Silo = PspSetNetRateControl(v9, (unsigned int)v4);
          goto LABEL_484;
        case '!':
LABEL_42:
          if ( (_DWORD)v4 == 48 )
          {
            memmove(&v196, v9, v4);
            v15 = DWORD2(v198);
            __SET_PAIR__(v18, v19, v196);
            v188 = v196;
            __SET_PAIR__(v16, v17, v197);
            *(_OWORD *)v189 = v197;
            *(_DWORD *)&v189[16] = v198;
            *(_QWORD *)&v189[20] = *(_QWORD *)((char *)&v198 + 4);
            v14 = 459268;
            JobLimitInformationValidFlags = 459268;
          }
          else
          {
            if ( (_DWORD)v4 == 56 )
            {
              memmove(&v192, v9, v4);
              v15 = v195;
              *(_DWORD *)&v189[24] = v195;
              __SET_PAIR__(v18, v19, v192);
              v188 = v192;
              __SET_PAIR__(v92, v17, v193);
              v190 = *((_QWORD *)&v193 + 1);
              *(_QWORD *)v189 = v193;
              v16 = v194;
              *(_OWORD *)&v189[8] = v194;
              v14 = 2589188;
              JobLimitInformationValidFlags = 2589188;
              goto LABEL_349;
            }
            memmove(&v188, v9, v4);
            v14 = 2064900;
            JobLimitInformationValidFlags = 2064900;
            v15 = *(_DWORD *)&v189[24];
            v16 = *(_QWORD *)&v189[8];
            v17 = *(_QWORD *)v189;
            v18 = *((_QWORD *)&v188 + 1);
            v19 = v188;
          }
          v92 = v190;
LABEL_349:
          if ( (~v14 & v15) == 0 )
          {
            if ( (v15 & 0x8000) != 0 )
            {
              if ( v92 < 0x1000 )
                goto LABEL_73;
            }
            else
            {
              v92 = 0;
              v190 = 0;
            }
            if ( (v15 & 0x200) != 0 )
            {
              if ( v16 < 0x1000 || v16 < v92 )
                goto LABEL_73;
            }
            else
            {
              *(_QWORD *)&v189[8] = 0;
            }
            if ( (v15 & 4) != 0 )
            {
              if ( !v17 )
                goto LABEL_73;
            }
            else
            {
              *(_QWORD *)v189 = 0;
            }
            if ( (v15 & 0x10000) != 0 )
            {
              if ( !v19 )
                goto LABEL_73;
            }
            else
            {
              *(_QWORD *)&v188 = 0;
            }
            if ( (v15 & 0x20000) != 0 )
            {
              if ( !v18 )
                goto LABEL_73;
            }
            else
            {
              *((_QWORD *)&v188 + 1) = 0;
            }
            v93 = 0;
            do
            {
              v94 = PspNotificationLimitRateControlToleranceField(&v188, v93);
              PspNotificationLimitRateControlToleranceIntervalField(&v188, v95, v96, v94);
              v98 = PspRateControlLimitFlag(v97);
              if ( (v98 & v102) != 0 )
              {
                if ( !*v100 || *v100 > 3 || !*v101 || *v101 > 3 )
                  goto LABEL_456;
              }
              else
              {
                *v100 = 0;
                *v101 = 0;
              }
              v93 = (unsigned int)(v99 + 1);
            }
            while ( (int)v93 < 3 );
            v21 = Event;
            v103 = &Event[50].Header.WaitListHead.Blink;
            if ( Event[50].Header.WaitListHead.Blink )
            {
              v104 = 0;
              v105 = 0;
              goto LABEL_386;
            }
            v104 = (struct _LIST_ENTRY *)ExAllocatePool2(0x100u);
            if ( v104 )
            {
              v105 = (void *)PsChargeSharedPoolQuota(KeGetCurrentThread()->ApcState.Process, 136);
              v35 = v104;
              if ( !v105 )
              {
                v36 = 1649046352;
                goto LABEL_127;
              }
              memset_0(v104, 0, 0x88u);
              v21 = Event;
LABEL_386:
              ExAcquireResourceExclusiveLite((PERESOURCE)&v21[2].Header.WaitListHead, 1u);
              if ( *v103 )
              {
                if ( v104 )
                {
                  ExFreePoolWithTag(v104, 0x624A7350u);
                  PsReturnSharedPoolQuota(v105);
                }
              }
              else
              {
                *v103 = v104;
                *(_QWORD *)&v21[51].Header.Lock = v105;
              }
              v106 = v21[50].Header.WaitListHead.Blink;
              Flink = (int)v106->Flink;
              *(_OWORD *)&v106->Blink = v188;
              v106[1].Blink = *(struct _LIST_ENTRY **)v189;
              v108 = 0;
              do
              {
                v109 = (_DWORD *)PspNotificationLimitRateControlToleranceField(&v188, v108);
                *(_DWORD *)(v110 - 12) = *v109;
                v113 = (_DWORD *)PspNotificationLimitRateControlToleranceIntervalField(&v188, v111, v110, v112);
                *v114 = *v113;
                v108 = (unsigned int)(v115 + 1);
              }
              while ( (int)v108 < 3 );
              PspLockJobMemoryLimitsExclusive(v21, 0, 0);
              v106[2].Flink = (struct _LIST_ENTRY *)(v190 >> 12);
              v106[2].Blink = (struct _LIST_ENTRY *)(*(_QWORD *)&v189[8] >> 12);
              LODWORD(v21[50].Header.WaitListHead.Blink->Flink) = *(_DWORD *)&v189[24];
              PspUnlockJobMemoryLimitsExclusive(v21, 0, 0);
              if ( ((__int64)v21[50].Header.WaitListHead.Blink->Flink & 0xFFFF7DFF) != 0 )
              {
                _InterlockedAdd64(&PspJobTimeLimitsRequest, 1u);
                v21 = Event;
              }
              if ( Flink )
              {
                v116 = v21[50].Header.WaitListHead.Blink;
                if ( LODWORD(v116->Flink) )
                {
LABEL_399:
                  if ( (PerfGlobalGroupMask & 0x80000) != 0 )
                    EtwTraceJobSetQuery((_DWORD)v21, v140, (unsigned int)&v188, 0, 0, 1829);
                  ExReleaseResourceLite((PERESOURCE)&v21[2].Header.WaitListHead);
                  PspLockJobMemoryLimitsShared(v21, 0);
                  v117 = v21[65].Header.WaitListHead.Flink;
                  v21 = Event;
                  JobMemoryUsageNotificationViolations = PspGetJobMemoryUsageNotificationViolations(
                                                           Event,
                                                           Event[50].Header.WaitListHead.Flink,
                                                           (char *)Event[50].Header.WaitListHead.Flink
                                                         + (unsigned __int64)v117,
                                                           33280);
                  PspUnlockJobMemoryLimitsShared(v21, 0);
                  if ( JobMemoryUsageNotificationViolations )
                  {
                    PspScheduleEnforcementWorker(v21[54].Header.WaitListHead.Blink);
                    v21 = Event;
                  }
                  goto LABEL_315;
                }
              }
              else
              {
                v116 = v21[50].Header.WaitListHead.Blink;
                if ( !LODWORD(v116->Flink) )
                  goto LABEL_399;
              }
              PspEnumJobsAndProcessesInJobHierarchy(v21, (__int64)v116, 5);
              goto LABEL_399;
            }
LABEL_123:
            v12 = -1073741670;
            goto LABEL_485;
          }
LABEL_73:
          v12 = -1073741811;
          goto LABEL_446;
        case '#':
          v21 = Event;
          Silo = PspCreateSilo(Event);
          goto LABEL_484;
        case '%':
          v91 = SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode);
          v21 = Event;
          if ( v91 )
          {
            if ( ((__int64)Event[64].Header.WaitListHead.Blink & 0x40000000) != 0 )
            {
              if ( !(unsigned __int8)PspSetJobSiloThreadImpersonationPolicy(Event, 4) )
                goto LABEL_343;
              v167 = v9->m128i_i32[0];
              Silo = ObCreateSiloRootDirectory(v21);
              goto LABEL_484;
            }
LABEL_341:
            v12 = -1073740535;
            goto LABEL_485;
          }
          break;
        case '(':
          v88 = PreviousMode;
          v89 = SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode);
          v21 = Event;
          if ( v89 )
          {
            if ( ((__int64)Event[64].Header.WaitListHead.Blink & 0x40000000) != 0 )
            {
              if ( !(unsigned __int8)PspSetJobSiloThreadImpersonationPolicy(Event, 4) )
                goto LABEL_343;
              v178 = v9->m128i_i64[0];
              v168 = v9->m128i_i32[2];
              LOBYTE(v90) = v88;
              Silo = PspConvertSiloToServerSilo((__int64)v21, v90, v178, v168);
LABEL_484:
              v12 = Silo;
              goto LABEL_485;
            }
            goto LABEL_341;
          }
          break;
        case ')':
          v169 = v9->m128i_i32[0];
          v21 = Event;
          if ( (unsigned __int8)PspJobIsAppSilo(Event) && v86 == 2 )
          {
            v87 = (struct _ERESOURCE *)&v21[2].Header.WaitListHead;
            ExAcquireResourceExclusiveLite((PERESOURCE)&v21[2].Header.WaitListHead, 1u);
            if ( LODWORD(v21[60].Header.WaitListHead.Blink) )
            {
              v12 = -1073740529;
            }
            else
            {
              v45 = _interlockedbittestandset((volatile signed __int32 *)&v21[64].Header.WaitListHead.Blink, 0x1Du);
              v21 = Event;
              if ( v45 )
              {
                v12 = 255;
              }
              else
              {
                PspHardDereferenceSiloWorker(Event);
                v12 = 0;
              }
            }
            p_WaitListHead = v87;
            goto LABEL_67;
          }
LABEL_343:
          v12 = -1073741811;
          goto LABEL_485;
        default:
          goto LABEL_445;
      }
      v12 = -1073741727;
      goto LABEL_485;
    }
    v119 = 0;
    Object[1] = 0;
    memmove(v180, v9, v4);
    if ( v182 )
    {
      v120 = v184;
      if ( !v184 )
        goto LABEL_417;
      if ( ((unsigned __int8)v182 & 1) != 0 )
        ExRaiseDatatypeMisalignment();
      if ( (unsigned __int64)v182 + v184 > 0x7FFFFFFF0000LL || (char *)v182 + v184 < v182 )
      {
        v120 = v184;
        v119 = Object[1];
      }
      if ( !v120 || (v120 & 1) != 0 )
      {
LABEL_417:
        v12 = -1073741811;
        v137 = -1073741811;
        v21 = Event;
        goto LABEL_427;
      }
      v121 = 32;
      if ( PreviousMode == 1 )
        v121 = 257;
      v122 = (_WORD *)ExAllocatePool2(v121);
      v119 = v122;
      Object[1] = v122;
      if ( !v122 )
      {
        v12 = -1073741801;
        v137 = -1073741801;
        v21 = Event;
        goto LABEL_427;
      }
      memmove(v122, v182, v184);
      v119[(unsigned __int64)v184 >> 1] = 0;
      v182 = v119;
    }
    if ( (v183 & 0xFFFFFFF0) != 0 )
    {
      v12 = -1073741811;
    }
    else
    {
      if ( !v185 && !v181 && !v186 || (unsigned __int8)PspIsContextAdmin() )
      {
        v21 = Event;
        v12 = PspSetJobIoRateControl(Event, v180);
        goto LABEL_427;
      }
      v12 = -1073741790;
    }
    v21 = Event;
LABEL_427:
    if ( !v119 )
      goto LABEL_485;
    v123 = 0;
    v124 = v119;
    goto LABEL_429;
  }
  return result;
}

```

// --- Called by: SeInitSystem at 0x140c2fa90 (Depth: 2) ---
// Language: C/C++
```cpp
__int64 SeInitSystem()
{
  if ( !(_DWORD)InitializationPhase )
    return SepInitializationPhase0();
  if ( (_DWORD)InitializationPhase != 1 )
    KeBugCheckEx(0x33u, 0, (unsigned int)InitializationPhase, 0, 0);
  return SepInitializationPhase1();
}

```

// --- Called by: InitBootProcessor at 0x140c00c88 (Depth: 3) ---
// Language: Assembly
```cpp
INIT:0000000140C00C88
INIT:0000000140C00C88 ; =============== S U B R O U T I N E ==========…
INIT:0000000140C00C88
INIT:0000000140C00C88 ; Attributes: bp-based frame fpd=100h
INIT:0000000140C00C88
INIT:0000000140C00C88 ; __int64 __fastcall InitBootProcessor(_QWORD)
INIT:0000000140C00C88 InitBootProcessor proc near             ; CODE X…
INIT:0000000140C00C88                                         ; DATA X…
INIT:0000000140C00C88
INIT:0000000140C00C88 pcbRemaining    = qword ptr -1E0h
INIT:0000000140C00C88 dwFlags         = dword ptr -1D8h
INIT:0000000140C00C88 Size            = qword ptr -1D0h
INIT:0000000140C00C88 ppszDestEnd     = qword ptr -1C8h
INIT:0000000140C00C88 DestinationString= STRING ptr -1C0h
INIT:0000000140C00C88 var_1A8         = qword ptr -1A8h
INIT:0000000140C00C88 var_1A0         = qword ptr -1A0h
INIT:0000000140C00C88 var_198         = qword ptr -198h
INIT:0000000140C00C88 var_190         = qword ptr -190h
INIT:0000000140C00C88 var_188         = qword ptr -188h
INIT:0000000140C00C88 var_180         = qword ptr -180h
INIT:0000000140C00C88 var_178         = qword ptr -178h
INIT:0000000140C00C88 var_170         = byte ptr -170h
INIT:0000000140C00C88 pszDest         = byte ptr -130h
INIT:0000000140C00C88 var_30          = qword ptr -30h
INIT:0000000140C00C88 var_20          = byte ptr -20h
INIT:0000000140C00C88
INIT:0000000140C00C88 ; __unwind { // __GSHandlerCheck
INIT:0000000140C00C88                 mov     rax, rsp
INIT:0000000140C00C8B                 mov     [rax+10h], rbx
INIT:0000000140C00C8F                 mov     [rax+18h], rsi
INIT:0000000140C00C93                 mov     [rax+20h], rdi
INIT:0000000140C00C97                 push    rbp
INIT:0000000140C00C98                 push    r12
INIT:0000000140C00C9A                 push    r13
INIT:0000000140C00C9C                 push    r14
INIT:0000000140C00C9E                 push    r15
INIT:0000000140C00CA0                 lea     rbp, [rax-108h]
INIT:0000000140C00CA7                 sub     rsp, 1E0h
INIT:0000000140C00CAE                 mov     rax, cs:__security_cooki…
INIT:0000000140C00CB5                 xor     rax, rsp
INIT:0000000140C00CB8                 mov     [rbp+100h+var_30], rax
INIT:0000000140C00CBF                 or      cs:dword_140FCF8F4, 0FFF…
INIT:0000000140C00CC6                 lea     rax, PspTimeZoneStateBuf…
INIT:0000000140C00CCD                 xor     r13d, r13d
INIT:0000000140C00CD0                 mov     cs:qword_140FCEE08, rax
INIT:0000000140C00CD7                 mov     eax, cs:NtBuildNumber
INIT:0000000140C00CDD                 mov     rbx, rcx
INIT:0000000140C00CE0                 movzx   ecx, ax
INIT:0000000140C00CE3                 xorps   xmm0, xmm0
INIT:0000000140C00CE6                 mov     eax, 0FDE9h
INIT:0000000140C00CEB                 mov     cs:dword_140FCEE3C, 103h
INIT:0000000140C00CF5                 lea     r15d, [r13+1]
INIT:0000000140C00CF9                 mov     cs:word_140FCED48, ax
INIT:0000000140C00D00                 mov     cs:dword_140FCEE38, r15d
INIT:0000000140C00D07                 mov     cs:word_140FCED88, ax
INIT:0000000140C00D0E                 mov     cs:dword_140FCEE78, ecx
INIT:0000000140C00D14                 mov     edx, [rbx]      ; BugChe…
INIT:0000000140C00D16                 mov     [rsp+200h+ppszDestEnd], …
INIT:0000000140C00D1B                 mov     [rsp+200h+var_1A8], r13
INIT:0000000140C00D20                 mov     qword ptr [rsp+200h+Dest…
INIT:0000000140C00D25                 movups  xmmword ptr [rsp+200h+De…
INIT:0000000140C00D2A                 cmp     edx, 0Ah
INIT:0000000140C00D2D                 jnz     loc_140C01639
INIT:0000000140C00D33                 cmp     [rbx+4], r13d
INIT:0000000140C00D37                 jnz     loc_140C01639
INIT:0000000140C00D3D                 cmp     dword ptr [rbx+8], 170h
INIT:0000000140C00D44                 jnz     loc_140C01639
INIT:0000000140C00D4A                 mov     rcx, [rbx+0F0h]
INIT:0000000140C00D51                 mov     eax, [rcx]
INIT:0000000140C00D53                 cmp     eax, 1130h
INIT:0000000140C00D58                 jnz     loc_140C0163C
INIT:0000000140C00D5E                 cmp     dword ptr [rcx+0BA8h], 0…
INIT:0000000140C00D68                 jnz     loc_140C0163C
INIT:0000000140C00D6E                 mov     ecx, [rcx+0B54h]
INIT:0000000140C00D74                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C00D7B                 mov     [rax+2C4h], ecx
INIT:0000000140C00D81                 lea     rcx, PspHostSiloGlobals
INIT:0000000140C00D88                 call    ExpInitLicensing
INIT:0000000140C00D8D                 lea     rcx, PspHostSiloGlobals
INIT:0000000140C00D94                 call    RtlNlsInitState
INIT:0000000140C00D99                 xor     ecx, ecx
INIT:0000000140C00D9B                 call    VslGetNestedPageProtecti…
INIT:0000000140C00DA0                 and     eax, 6
INIT:0000000140C00DA3                 cmp     al, 6
INIT:0000000140C00DA5                 jnz     short loc_140C00DAF
INIT:0000000140C00DA7                 mov     rcx, rbx
INIT:0000000140C00DAA                 call    ExpRevokeBootLoaderPageP…
INIT:0000000140C00DAF
INIT:0000000140C00DAF loc_140C00DAF:                          ; CODE X…
INIT:0000000140C00DAF                 mov     rdi, [rbx+0D8h]
INIT:0000000140C00DB6                 mov     cs:InitializationPhase, …
INIT:0000000140C00DBD                 test    rdi, rdi
INIT:0000000140C00DC0                 jz      short loc_140C00E2A
INIT:0000000140C00DC2                 mov     rcx, rdi        ; String
INIT:0000000140C00DC5                 call    _strupr
INIT:0000000140C00DCA                 lea     rdx, aBurnmemory ; "BURN…
INIT:0000000140C00DD1                 mov     rcx, rdi        ; Str
INIT:0000000140C00DD4                 call    strstr
INIT:0000000140C00DD9                 test    rax, rax
INIT:0000000140C00DDC                 jz      short loc_140C00E0F
INIT:0000000140C00DDE                 lea     rdx, asc_140C5E410 ; "="
INIT:0000000140C00DE5                 mov     rcx, rax        ; Str
INIT:0000000140C00DE8                 call    strstr
INIT:0000000140C00DED                 test    rax, rax
INIT:0000000140C00DF0                 jz      short loc_140C00E0F
INIT:0000000140C00DF2                 lea     rcx, [rax+1]    ; Str
INIT:0000000140C00DF6                 call    atol
INIT:0000000140C00DFB                 movsxd  rdx, eax
INIT:0000000140C00DFE                 shl     rdx, 8
INIT:0000000140C00E02                 test    rdx, rdx
INIT:0000000140C00E05                 jz      short loc_140C00E0F
INIT:0000000140C00E07                 mov     rcx, rbx
INIT:0000000140C00E0A                 call    ExBurnMemory
INIT:0000000140C00E0F
INIT:0000000140C00E0F loc_140C00E0F:                          ; CODE X…
INIT:0000000140C00E0F                                         ; InitBo…
INIT:0000000140C00E0F                 lea     rdx, aForcegroupawar ; "…
INIT:0000000140C00E16                 mov     rcx, rdi        ; Str
INIT:0000000140C00E19                 call    strstr
INIT:0000000140C00E1E                 test    rax, rax
INIT:0000000140C00E21                 jz      short loc_140C00E2A
INIT:0000000140C00E23                 mov     cs:KeForceGroupAwareness…
INIT:0000000140C00E2A
INIT:0000000140C00E2A loc_140C00E2A:                          ; CODE X…
INIT:0000000140C00E2A                                         ; InitBo…
INIT:0000000140C00E2A                 lea     rcx, [rbx+20h]
INIT:0000000140C00E2E                 mov     rax, r13
INIT:0000000140C00E31                 mov     rdx, [rcx]
INIT:0000000140C00E34                 jmp     short loc_140C00E4E
INIT:0000000140C00E36 ; ----------------------------------------------…
INIT:0000000140C00E36
INIT:0000000140C00E36 loc_140C00E36:                          ; CODE X…
INIT:0000000140C00E36                 mov     r8, [rdx+20h]   ; BugChe…
INIT:0000000140C00E3A                 mov     r9, [rdx+28h]   ; BugChe…
INIT:0000000140C00E3E                 cmp     r8, rax
INIT:0000000140C00E41                 jb      loc_140C0166A
INIT:0000000140C00E47                 mov     rdx, [rdx]      ; BugChe…
INIT:0000000140C00E4A                 lea     rax, [r8+r9]
INIT:0000000140C00E4E
INIT:0000000140C00E4E loc_140C00E4E:                          ; CODE X…
INIT:0000000140C00E4E                 cmp     rdx, rcx
INIT:0000000140C00E51                 jnz     short loc_140C00E36
INIT:0000000140C00E53                 mov     rax, [rbx+0E0h]
INIT:0000000140C00E5A                 test    rax, rax
INIT:0000000140C00E5D                 jz      short loc_140C00E6F
INIT:0000000140C00E5F                 mov     rax, [rax+10h]
INIT:0000000140C00E63                 mov     cs:InitNlsTableBase, rax
INIT:0000000140C00E6A                 call    ExPreInitializeNls
INIT:0000000140C00E6F
INIT:0000000140C00E6F loc_140C00E6F:                          ; CODE X…
INIT:0000000140C00E6F                 mov     rax, [rbx+0F0h]
INIT:0000000140C00E76                 mov     rcx, [rax+0BA0h]
INIT:0000000140C00E7D                 mov     cs:ExLeapSecondData, rcx
INIT:0000000140C00E84                 call    WheaInitializeServices
INIT:0000000140C00E89                 mov     rax, cs:off_140E00AF0
INIT:0000000140C00E90                 mov     rcx, cs:HalIommuDispatch
INIT:0000000140C00E97                 call    _guard_dispatch_icall_no…
INIT:0000000140C00E9C                 rdtsc
INIT:0000000140C00E9E                 mov     ecx, cs:InitializationPh…
INIT:0000000140C00EA4                 shl     rdx, 20h
INIT:0000000140C00EA8                 or      rax, rdx
INIT:0000000140C00EAB                 mov     rdx, rbx
INIT:0000000140C00EAE                 mov     cs:qword_1410077F8, rax
INIT:0000000140C00EB5                 call    HalInitSystem
INIT:0000000140C00EBA                 test    al, al
INIT:0000000140C00EBC                 jz      loc_140C0165F
INIT:0000000140C00EC2                 rdtsc
INIT:0000000140C00EC4                 mov     ecx, cs:InitializationPh…
INIT:0000000140C00ECA                 shl     rdx, 20h
INIT:0000000140C00ECE                 or      rax, rdx
INIT:0000000140C00ED1                 mov     rdx, rbx
INIT:0000000140C00ED4                 mov     cs:qword_141007800, rax
INIT:0000000140C00EDB                 call    KeInitializeClock
INIT:0000000140C00EE0                 mov     ecx, r15d
INIT:0000000140C00EE3                 call    PsInitializeQuotaSystem
INIT:0000000140C00EE8                 mov     rcx, rbx
INIT:0000000140C00EEB                 call    CmInitSystem0
INIT:0000000140C00EF0                 cmp     cs:PopEnergyEstimationEn…
INIT:0000000140C00EF7                 jnz     short loc_140C00F09
INIT:0000000140C00EF9                 mov     rax, cs:KiProcessorBlock
INIT:0000000140C00F00                 mov     rcx, [rax+18h]
INIT:0000000140C00F04                 lock btr dword ptr [rcx], 15h
INIT:0000000140C00F09
INIT:0000000140C00F09 loc_140C00F09:                          ; CODE X…
INIT:0000000140C00F09                 xor     ecx, ecx
INIT:0000000140C00F0B                 call    KeInitSystem
INIT:0000000140C00F10                 test    al, al
INIT:0000000140C00F12                 jz      loc_140C0167A
INIT:0000000140C00F18                 call    ExComputeTickCountMultip…
INIT:0000000140C00F1D                 mov     rcx, cs:MmWriteableShare…
INIT:0000000140C00F24                 lea     r9, [rsp+200h+var_1A8]
INIT:0000000140C00F29                 mov     cs:ExpTickCountMultiplie…
INIT:0000000140C00F2F                 lea     rdx, [rsp+200h+var_188]
INIT:0000000140C00F34                 mov     r8d, 3
INIT:0000000140C00F3A                 mov     [rsp+200h+var_1A0], r13
INIT:0000000140C00F3F                 mov     dword ptr [rsp+200h+Size…
INIT:0000000140C00F44                 mov     [rcx+4], eax
INIT:0000000140C00F47                 lea     rcx, cs:140000000h
INIT:0000000140C00F4E                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C00F55                 mov     [rax+23Ch], r13d
INIT:0000000140C00F5C                 mov     [rsp+200h+var_188], 0Bh
INIT:0000000140C00F65                 mov     [rbp+100h+var_180], r15
INIT:0000000140C00F69                 mov     [rbp+100h+var_178], r13
INIT:0000000140C00F6D                 call    LdrFindResource_U
INIT:0000000140C00F72                 test    eax, eax
INIT:0000000140C00F74                 js      short loc_140C00FA1
INIT:0000000140C00F76                 mov     rdx, [rsp+200h+var_1A8]
INIT:0000000140C00F7B                 lea     r9, [rsp+200h+Size]
INIT:0000000140C00F80                 lea     r8, [rsp+200h+var_1A0]
INIT:0000000140C00F85                 lea     rcx, cs:140000000h
INIT:0000000140C00F8C                 call    LdrAccessResource
INIT:0000000140C00F91                 test    eax, eax
INIT:0000000140C00F93                 js      short loc_140C00FA1
INIT:0000000140C00F95                 mov     rax, [rsp+200h+var_1A0]
INIT:0000000140C00F9A                 mov     cs:KiBugCodeMessages, ra…
INIT:0000000140C00FA1
INIT:0000000140C00FA1 loc_140C00FA1:                          ; CODE X…
INIT:0000000140C00FA1                                         ; InitBo…
INIT:0000000140C00FA1                 and     cs:CmNtGlobalFlag2, 201F…
INIT:0000000140C00FAB                 mov     eax, cs:CmGlobalValidati…
INIT:0000000140C00FB1                 mov     rcx, cs:MmWriteableShare…
INIT:0000000140C00FB8                 mov     [rcx+258h], eax
INIT:0000000140C00FBE                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C00FC5                 mov     [rax+28Bh], r15b
INIT:0000000140C00FCC                 mov     eax, cs:CmNtSpBuildNumbe…
INIT:0000000140C00FD2                 and     eax, 0FFFh
INIT:0000000140C00FD7                 mov     word ptr cs:CmNtCSDVersi…
INIT:0000000140C00FDF                 cmp     cs:CmNtCSDReleaseType, r…
INIT:0000000140C00FE6                 mov     cs:CmNtSpBuildNumber, ea…
INIT:0000000140C00FEC                 jz      short loc_140C00FF7
INIT:0000000140C00FEE                 shl     eax, 10h
INIT:0000000140C00FF1                 or      cs:CmNtCSDVersion, eax
INIT:0000000140C00FF7
INIT:0000000140C00FF7 loc_140C00FF7:                          ; CODE X…
INIT:0000000140C00FF7                 mov     edi, 4
INIT:0000000140C00FFC                 cmp     cs:InitTickRolloverDelay…
INIT:0000000140C01002                 jnz     short loc_140C0100C
INIT:0000000140C01004                 cmp     cs:InitTickRolloverDelay…
INIT:0000000140C0100A                 jz      short loc_140C01013
INIT:0000000140C0100C
INIT:0000000140C0100C loc_140C0100C:                          ; CODE X…
INIT:0000000140C0100C                 mov     cs:InitTickRolloverDelay…
INIT:0000000140C01013
INIT:0000000140C01013 loc_140C01013:                          ; CODE X…
INIT:0000000140C01013                 mov     eax, cs:InitTickRollover…
INIT:0000000140C01019                 test    eax, eax
INIT:0000000140C0101B                 jz      short loc_140C0104A
INIT:0000000140C0101D                 neg     eax
INIT:0000000140C0101F                 mov     dl, r15b
INIT:0000000140C01022                 imul    rcx, rax, 2710h
INIT:0000000140C01029                 call    KeAdjustInterruptTime
INIT:0000000140C0102E                 xor     ecx, ecx        ; Perfor…
INIT:0000000140C01030                 call    KeQueryPerformanceCounte…
INIT:0000000140C01035                 mov     rcx, cs:MmWriteableShare…
INIT:0000000140C0103C                 mov     [rcx+348h], rax
INIT:0000000140C01043                 mov     cs:KiSystemTimeErrorAccu…
INIT:0000000140C0104A
INIT:0000000140C0104A loc_140C0104A:                          ; CODE X…
INIT:0000000140C0104A                 mov     eax, cs:CmNtGlobalFlag
INIT:0000000140C01050                 xor     ecx, ecx
INIT:0000000140C01052                 or      cs:NtGlobalFlag, eax
INIT:0000000140C01058                 mov     eax, cs:CmNtGlobalFlag2
INIT:0000000140C0105E                 or      cs:NtGlobalFlag2, eax
INIT:0000000140C01064                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C0106B                 mov     [rax+3C0h], r15d
INIT:0000000140C01072                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C01079                 mov     [rax+3C4h], r15b
INIT:0000000140C01080                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C01087                 mov     [rax+36Ah], r15w
INIT:0000000140C0108F                 call    ExInitSystem
INIT:0000000140C01094                 test    al, al
INIT:0000000140C01096                 jz      loc_140C017B4
INIT:0000000140C0109C                 mov     rcx, rbx
INIT:0000000140C0109F                 call    WheaSelLogInitialize
INIT:0000000140C010A4                 call    KeNumaInitialize
INIT:0000000140C010A9                 mov     rcx, rbx
INIT:0000000140C010AC                 call    VerifierInitSystem
INIT:0000000140C010B1                 call    InitializeDynamicPartiti…
INIT:0000000140C010B6                 call    KeInitializeXSaveStructu…
INIT:0000000140C010BB                 mov     r14d, 100h
INIT:0000000140C010C1                 mov     qword ptr cs:KiSystemAva…
INIT:0000000140C010CC                 mov     r8d, r14d       ; Size
INIT:0000000140C010CF                 lea     rcx, KiSystemAvailableCp…
INIT:0000000140C010D6                 xor     edx, edx        ; Val
INIT:0000000140C010D8                 call    memset_0
INIT:0000000140C010DD                 lea     rax, KiAvailableCpusSubs…
INIT:0000000140C010E4                 mov     cs:KiAvailableCpusSubscr…
INIT:0000000140C010EB                 xor     ecx, ecx        ; Perfor…
INIT:0000000140C010ED                 mov     cs:qword_140F22118, rax
INIT:0000000140C010F4                 mov     cs:KiAvailableCpusSubscr…
INIT:0000000140C010FB                 call    KeQueryPerformanceCounte…
INIT:0000000140C01100                 mov     rdx, rbx
INIT:0000000140C01103                 mov     cs:EtwBootPerfData, rax
INIT:0000000140C0110A                 xor     ecx, ecx
INIT:0000000140C0110C                 call    MmInitSystem
INIT:0000000140C01111                 xor     ecx, ecx        ; Perfor…
INIT:0000000140C01113                 call    KeQueryPerformanceCounte…
INIT:0000000140C01118                 mov     cs:qword_1410077A8, rax
INIT:0000000140C0111F                 mov     rdx, r13
INIT:0000000140C01122                 mov     rcx, [rbx+0F0h]
INIT:0000000140C01129                 mov     esi, 8
INIT:0000000140C0112E                 test    rcx, rcx
INIT:0000000140C01131                 jz      short loc_140C0114D
INIT:0000000140C01133                 mov     rax, [rcx+0B58h]
INIT:0000000140C0113A                 test    rax, rax
INIT:0000000140C0113D                 jz      short loc_140C0114D
INIT:0000000140C0113F                 mov     eax, [rax]
INIT:0000000140C01141                 test    sil, al
INIT:0000000140C01144                 jz      short loc_140C0114D
INIT:0000000140C01146                 mov     rdx, [rcx+1118h]
INIT:0000000140C0114D
INIT:0000000140C0114D loc_140C0114D:                          ; CODE X…
INIT:0000000140C0114D                                         ; InitBo…
INIT:0000000140C0114D                 mov     rcx, cs:KiProcessorBlock
INIT:0000000140C01154                 add     rcx, 91C0h
INIT:0000000140C0115B                 call    cs:__imp_SymCryptEntropy…
INIT:0000000140C01162                 nop     dword ptr [rax+rax+00h]
INIT:0000000140C01167                 mov     rdx, rbx
INIT:0000000140C0116A                 xor     ecx, ecx
INIT:0000000140C0116C                 call    EtwInitialize
INIT:0000000140C01171                 xor     ecx, ecx
INIT:0000000140C01173                 mov     cs:KiHwPolicyDriverImage…
INIT:0000000140C0117A                 call    VmInitSystem
INIT:0000000140C0117F                 test    eax, eax
INIT:0000000140C01181                 js      loc_140C01697
INIT:0000000140C01187                 mov     rdx, rbx
INIT:0000000140C0118A                 xor     ecx, ecx
INIT:0000000140C0118C                 call    HalInitializeBios
INIT:0000000140C01191                 xor     r8d, r8d
INIT:0000000140C01194                 mov     rdx, rbx
INIT:0000000140C01197                 xor     ecx, ecx
INIT:0000000140C01199                 call    InbvDriverInitialize
INIT:0000000140C0119E                 cmp     cs:KiBugCodeMessages, r1…
INIT:0000000140C011A5                 jz      short loc_140C011EA
INIT:0000000140C011A7                 mov     r12d, dword ptr [rsp+200…
INIT:0000000140C011AC                 mov     r8d, 6342694Bh
INIT:0000000140C011B2                 mov     edx, r12d
INIT:0000000140C011B5                 mov     ecx, 40h ; '@'  ; BugChe…
INIT:0000000140C011BA                 call    ExAllocatePool2
INIT:0000000140C011BF                 mov     r15, rax
INIT:0000000140C011C2                 test    rax, rax
INIT:0000000140C011C5                 jz      loc_140C016B0
INIT:0000000140C011CB                 mov     rdx, cs:KiBugCodeMessage…
INIT:0000000140C011D2                 mov     r8d, r12d       ; Size
INIT:0000000140C011D5                 mov     rcx, rax        ; void *
INIT:0000000140C011D8                 call    memmove
INIT:0000000140C011DD                 mov     cs:KiBugCodeMessages, r1…
INIT:0000000140C011E4                 mov     r15d, 1
INIT:0000000140C011EA
INIT:0000000140C011EA loc_140C011EA:                          ; CODE X…
INIT:0000000140C011EA                 mov     r12d, 2
INIT:0000000140C011F0                 cmp     [rbx+0Ch], r12d
INIT:0000000140C011F4                 jb      loc_140C016BB
INIT:0000000140C011FA                 xor     r8d, r8d
INIT:0000000140C011FD                 mov     [rsp+200h+var_190], r13
INIT:0000000140C01202                 lea     rdx, [rsp+200h+var_198]
INIT:0000000140C01207                 mov     [rsp+200h+var_198], rbx
INIT:0000000140C0120C                 lea     rcx, InitLoadDebuggerSym…
INIT:0000000140C01213                 call    MiEnumerateSystemImages
INIT:0000000140C01218                 cmp     cs:KdBreakAfterSymbolLoa…
INIT:0000000140C0121F                 jz      short loc_140C01229
INIT:0000000140C01221                 mov     ecx, r15d       ; Status
INIT:0000000140C01224                 call    DbgBreakPointWithStatus
INIT:0000000140C01229
INIT:0000000140C01229 loc_140C01229:                          ; CODE X…
INIT:0000000140C01229                 mov     rax, gs:20h
INIT:0000000140C01232                 mov     rcx, [rax+8EB8h]
INIT:0000000140C01239                 mov     al, cs:KiHaltOnAddressFl…
INIT:0000000140C0123F                 neg     rcx
INIT:0000000140C01242                 mov     rcx, rbx
INIT:0000000140C01245                 sbb     dl, dl
INIT:0000000140C01247                 and     al, 0FDh
INIT:0000000140C01249                 and     dl, r12b
INIT:0000000140C0124C                 or      dl, al
INIT:0000000140C0124E                 mov     eax, cs:HvlEnlightenment…
INIT:0000000140C01254                 shr     eax, 1Ch
INIT:0000000140C01257                 and     dl, 0FBh
INIT:0000000140C0125A                 and     al, dil
INIT:0000000140C0125D                 or      al, r15b
INIT:0000000140C01260                 or      dl, al
INIT:0000000140C01262                 mov     cs:KiHaltOnAddressFlags,…
INIT:0000000140C01268                 call    ExpInitializeBootEnviron…
INIT:0000000140C0126D                 cmp     cs:KiKernelCetEnabled, r…
INIT:0000000140C01274                 jz      short loc_140C012CB
INIT:0000000140C01276                 mov     r8b, cs:KeKernelCetWrssE…
INIT:0000000140C0127D                 test    r12b, r8b
INIT:0000000140C01280                 jz      short loc_140C012A6
INIT:0000000140C01282                 cmp     byte ptr cs:KdDebuggerNo…
INIT:0000000140C01289                 jz      short loc_140C012A6
INIT:0000000140C0128B                 cmp     byte ptr cs:KdDebuggerNo…
INIT:0000000140C01292                 jnz     short loc_140C012A6
INIT:0000000140C01294                 and     r8b, 0FDh
INIT:0000000140C01298                 mov     cs:KeKernelCetWrssDebugg…
INIT:0000000140C0129F                 mov     cs:KeKernelCetWrssEnable…
INIT:0000000140C012A6
INIT:0000000140C012A6 loc_140C012A6:                          ; CODE X…
INIT:0000000140C012A6                                         ; InitBo…
INIT:0000000140C012A6                 mov     ecx, 6A2h
INIT:0000000140C012AB                 rdmsr
INIT:0000000140C012AD                 shl     rdx, 20h
INIT:0000000140C012B1                 or      rax, rdx
INIT:0000000140C012B4                 test    r8b, r8b
INIT:0000000140C012B7                 jnz     short loc_140C012BF
INIT:0000000140C012B9                 and     rax, 0FFFFFFFFFFFFFFFDh
INIT:0000000140C012BD                 jmp     short loc_140C012C2
INIT:0000000140C012BF ; ----------------------------------------------…
INIT:0000000140C012BF
INIT:0000000140C012BF loc_140C012BF:                          ; CODE X…
INIT:0000000140C012BF                 or      rax, r12
INIT:0000000140C012C2
INIT:0000000140C012C2 loc_140C012C2:                          ; CODE X…
INIT:0000000140C012C2                 mov     rdx, rax
INIT:0000000140C012C5                 shr     rdx, 20h
INIT:0000000140C012C9                 wrmsr
INIT:0000000140C012CB
INIT:0000000140C012CB loc_140C012CB:                          ; CODE X…
INIT:0000000140C012CB                 call    PsInitializeWin32kServic…
INIT:0000000140C012D0                 call    PsInitializeWin32kKernel…
INIT:0000000140C012D5                 test    cs:MiFlags, 40000h
INIT:0000000140C012E0                 jz      short loc_140C012F3
INIT:0000000140C012E2                 xor     r8d, r8d
INIT:0000000140C012E5                 lea     rcx, MiProtectKernelCfgD…
INIT:0000000140C012EC                 xor     edx, edx
INIT:0000000140C012EE                 call    MiEnumerateSystemImages
INIT:0000000140C012F3
INIT:0000000140C012F3 loc_140C012F3:                          ; CODE X…
INIT:0000000140C012F3                 mov     rcx, rbx
INIT:0000000140C012F6                 call    HvlPhase1Initialize
INIT:0000000140C012FB                 mov     rax, [rbx+0F0h]
INIT:0000000140C01302                 cmp     dword ptr [rax], 1130h
INIT:0000000140C01308                 jb      short loc_140C01312
INIT:0000000140C0130A                 mov     rcx, rbx
INIT:0000000140C0130D                 call    HeadlessInit
INIT:0000000140C01312
INIT:0000000140C01312 loc_140C01312:                          ; CODE X…
INIT:0000000140C01312                 mov     rcx, rbx
INIT:0000000140C01315                 call    BootApplicationPersisten…
INIT:0000000140C0131A                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C01321                 mov     dword ptr [rax+2B4h], 7F…
INIT:0000000140C0132B                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C01332                 mov     dword ptr [rax+2B8h], 80…
INIT:0000000140C0133C                 cmp     cs:CmNtCSDVersion, r13d
INIT:0000000140C01343                 jz      loc_140C0142A
INIT:0000000140C01349                 xor     r8d, r8d
INIT:0000000140C0134C                 lea     rax, [rsp+200h+ppszDestE…
INIT:0000000140C01351                 mov     r9d, 40000087h
INIT:0000000140C01357                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C0135C                 lea     rcx, cs:140000000h
INIT:0000000140C01363                 lea     edx, [r8+0Bh]
INIT:0000000140C01367                 call    RtlFindMessage
INIT:0000000140C0136C                 test    eax, eax
INIT:0000000140C0136E                 js      loc_140C016DB
INIT:0000000140C01374                 mov     rdx, [rsp+200h+ppszDestE…
INIT:0000000140C01379                 lea     rcx, [rsp+200h+Destinati…
INIT:0000000140C0137E                 add     rdx, rdi        ; Source…
INIT:0000000140C01381                 call    RtlInitAnsiString
INIT:0000000140C01386                 mov     eax, 0FFFEh
INIT:0000000140C0138B                 lea     r9, [rsp+200h+Destinatio…
INIT:0000000140C01390                 add     word ptr [rsp+200h+Desti…
INIT:0000000140C01395                 lea     r8, aZUC        ; "%Z %u…
INIT:0000000140C0139C                 mov     eax, cs:CmNtCSDVersion
INIT:0000000140C013A2                 movzx   ecx, al
INIT:0000000140C013A5                 lea     eax, [rcx+40h]
INIT:0000000140C013A8                 neg     ecx
INIT:0000000140C013AA                 lea     rcx, [rbp+100h+pszDest] …
INIT:0000000140C013AE                 sbb     edx, edx
INIT:0000000140C013B0                 and     edx, eax
INIT:0000000140C013B2                 movzx   eax, byte ptr cs:CmNtCSD…
INIT:0000000140C013B9                 mov     [rsp+200h+dwFlags], edx …
INIT:0000000140C013BD                 mov     rdx, r14        ; cbDest
INIT:0000000140C013C0                 mov     dword ptr [rsp+200h+pcbR…
INIT:0000000140C013C4                 call    RtlStringCbPrintfA
INIT:0000000140C013C9                 test    eax, eax
INIT:0000000140C013CB                 js      loc_140C016F3
INIT:0000000140C013D1                 test    cs:CmNtCSDVersion, 0FFFF…
INIT:0000000140C013DB                 jz      short loc_140C01453
INIT:0000000140C013DD                 lea     rax, [rsp+200h+Destinati…
INIT:0000000140C013E2                 mov     [rsp+200h+ppszDestEnd], …
INIT:0000000140C013E7                 lea     r9, [rsp+200h+ppszDestEn…
INIT:0000000140C013EC                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C013F1                 lea     rcx, [rbp+100h+pszDest] …
INIT:0000000140C013F5                 call    RtlStringCbCatExA
INIT:0000000140C013FA                 test    eax, eax
INIT:0000000140C013FC                 js      loc_140C0170C
INIT:0000000140C01402                 movzx   r9d, word ptr cs:CmNtCSD…
INIT:0000000140C0140A                 lea     r8, aVU         ; "v.%u"
INIT:0000000140C01411                 mov     rdx, qword ptr [rsp+200h…
INIT:0000000140C01416                 mov     rcx, [rsp+200h+ppszDestE…
INIT:0000000140C0141B                 call    RtlStringCbPrintfA
INIT:0000000140C01420                 test    eax, eax
INIT:0000000140C01422                 js      loc_140C01725
INIT:0000000140C01428                 jmp     short loc_140C01453
INIT:0000000140C0142A ; ----------------------------------------------…
INIT:0000000140C0142A
INIT:0000000140C0142A loc_140C0142A:                          ; CODE X…
INIT:0000000140C0142A                 lea     rax, [rsp+200h+Destinati…
INIT:0000000140C0142F                 lea     rcx, [rbp+100h+pszDest] …
INIT:0000000140C01433                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C01438                 call    RtlStringCbCopyExA
INIT:0000000140C0143D                 test    eax, eax
INIT:0000000140C0143F                 js      loc_140C0173E
INIT:0000000140C01445                 sub     r14w, [rsp+200h+Destinat…
INIT:0000000140C0144B                 mov     cs:CmCSDVersionString.Ma…
INIT:0000000140C01453
INIT:0000000140C01453 loc_140C01453:                          ; CODE X…
INIT:0000000140C01453                                         ; InitBo…
INIT:0000000140C01453                 lea     rdx, [rbp+100h+pszDest] …
INIT:0000000140C01457                 lea     rcx, [rsp+200h+Destinati…
INIT:0000000140C0145C                 call    RtlInitAnsiString
INIT:0000000140C01461                 mov     r8b, r15b       ; Alloca…
INIT:0000000140C01464                 lea     rdx, [rsp+200h+Destinati…
INIT:0000000140C01469                 lea     rcx, CmCSDVersionString …
INIT:0000000140C01470                 call    RtlAnsiStringToUnicodeSt…
INIT:0000000140C01475                 test    eax, eax
INIT:0000000140C01477                 js      loc_140C01756
INIT:0000000140C0147D                 mov     r9d, 6
INIT:0000000140C01483                 mov     dword ptr [rsp+200h+pcbR…
INIT:0000000140C0148B                 lea     r8, aUU         ; "%u.%u…
INIT:0000000140C01492                 lea     rcx, [rbp+100h+var_170] …
INIT:0000000140C01496                 lea     edi, [r9+3Ah]
INIT:0000000140C0149A                 mov     edx, edi        ; cbDest
INIT:0000000140C0149C                 call    RtlStringCbPrintfA
INIT:0000000140C014A1                 test    eax, eax
INIT:0000000140C014A3                 js      loc_140C0176F
INIT:0000000140C014A9                 lea     rdx, [rbp+100h+var_170]
INIT:0000000140C014AD                 lea     rcx, CmVersionString ; D…
INIT:0000000140C014B4                 call    RtlCreateUnicodeStringFr…
INIT:0000000140C014B9                 test    al, al
INIT:0000000140C014BB                 jz      loc_140C017B4
INIT:0000000140C014C1                 test    cs:NtGlobalFlag, 2000h
INIT:0000000140C014CB                 mov     esi, 800000h
INIT:0000000140C014D0                 jz      short loc_140C01508
INIT:0000000140C014D2                 mov     r14d, 63617453h
INIT:0000000140C014D8                 mov     edx, esi
INIT:0000000140C014DA                 mov     r8d, r14d
INIT:0000000140C014DD                 mov     ecx, edi        ; BugChe…
INIT:0000000140C014DF                 call    ExAllocatePool2
INIT:0000000140C014E4                 mov     rdi, rax
INIT:0000000140C014E7                 test    rax, rax
INIT:0000000140C014EA                 jz      short loc_140C01508
INIT:0000000140C014EC                 mov     r8d, esi
INIT:0000000140C014EF                 mov     edx, esi
INIT:0000000140C014F1                 mov     rcx, rax
INIT:0000000140C014F4                 call    RtlpInitializeStackTrace…
INIT:0000000140C014F9                 test    eax, eax
INIT:0000000140C014FB                 jns     short loc_140C01508
INIT:0000000140C014FD                 mov     edx, r14d       ; Tag
INIT:0000000140C01500                 mov     rcx, rdi        ; P
INIT:0000000140C01503                 call    ExFreePoolWithTag
INIT:0000000140C01508
INIT:0000000140C01508 loc_140C01508:                          ; CODE X…
INIT:0000000140C01508                                         ; InitBo…
INIT:0000000140C01508                 test    cs:NtGlobalFlag, esi
INIT:0000000140C0150E                 jz      short loc_140C01515
INIT:0000000140C01510                 call    RtlInitializeExceptionLo…
INIT:0000000140C01515
INIT:0000000140C01515 loc_140C01515:                          ; CODE X…
INIT:0000000140C01515                 lea     rax, HandleTableListHead
INIT:0000000140C0151C                 mov     cs:HandleTableListLock, …
INIT:0000000140C01523                 mov     cs:qword_140FD8FB0, rax
INIT:0000000140C0152A                 mov     cs:HandleTableListHead, …
INIT:0000000140C01531                 call    HalQueryMaximumProcessor…
INIT:0000000140C01536                 xor     ecx, ecx
INIT:0000000140C01538                 mov     cs:ExpFreeListCount, eax
INIT:0000000140C0153E                 call    ObInitSystem
INIT:0000000140C01543                 test    al, al
INIT:0000000140C01545                 jz      loc_140C01788
INIT:0000000140C0154B                 mov     edx, 9
INIT:0000000140C01550                 lea     ecx, [rdx+5Eh]
INIT:0000000140C01553                 call    cs:__imp_SymCryptModuleI…
INIT:0000000140C0155A                 nop     dword ptr [rax+rax+00h]
INIT:0000000140C0155F                 call    SeInitSystem
INIT:0000000140C01564                 test    al, al
INIT:0000000140C01566                 jz      loc_140C01793
INIT:0000000140C0156C                 mov     rdx, rbx
INIT:0000000140C0156F                 xor     ecx, ecx
INIT:0000000140C01571                 call    PsInitSystem
INIT:0000000140C01576                 test    al, al
INIT:0000000140C01578                 jz      loc_140C017A9
INIT:0000000140C0157E                 call    DbgkInitialize
INIT:0000000140C01583                 test    eax, eax
INIT:0000000140C01585                 js      loc_140C017A9
INIT:0000000140C0158B                 call    PpInitSystem
INIT:0000000140C01590                 test    al, al
INIT:0000000140C01592                 jz      loc_140C0179E
INIT:0000000140C01598                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C0159F                 mov     dword ptr [rax+26Ch], 0A…
INIT:0000000140C015A9                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C015B0                 mov     [rax+270h], r13d
INIT:0000000140C015B7                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C015BE                 mov     dword ptr [rax+260h], 65…
INIT:0000000140C015C8                 mov     rcx, cs:MmWriteableShare…
INIT:0000000140C015CF                 movzx   eax, cs:KeProcessorArchi…
INIT:0000000140C015D6                 mov     [rcx+26Ah], ax
INIT:0000000140C015DD                 mov     ecx, 8664h
INIT:0000000140C015E2                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C015E9                 mov     [rax+2Ch], cx
INIT:0000000140C015ED                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C015F4                 mov     [rax+2Eh], cx
INIT:0000000140C015F8                 mov     rax, cs:MmWriteableShare…
INIT:0000000140C015FF                 mov     [rax+3A4h], r13d
INIT:0000000140C01606                 xor     eax, eax
INIT:0000000140C01608                 mov     rcx, [rbp+100h+var_30]
INIT:0000000140C0160F                 xor     rcx, rsp        ; StackC…
INIT:0000000140C01612                 call    __security_check_cookie
INIT:0000000140C01617                 lea     r11, [rsp+200h+var_20]
INIT:0000000140C0161F                 mov     rbx, [r11+38h]
INIT:0000000140C01623                 mov     rsi, [r11+40h]
INIT:0000000140C01627                 mov     rdi, [r11+48h]
INIT:0000000140C0162B                 mov     rsp, r11
INIT:0000000140C0162E                 pop     r15
INIT:0000000140C01630                 pop     r14
INIT:0000000140C01632                 pop     r13
INIT:0000000140C01634                 pop     r12
INIT:0000000140C01636                 pop     rbp
INIT:0000000140C01637                 retn
INIT:0000000140C01637 ; ----------------------------------------------…
INIT:0000000140C01638                 db 0CCh
INIT:0000000140C01639 ; ----------------------------------------------…
INIT:0000000140C01639
INIT:0000000140C01639 loc_140C01639:                          ; CODE X…
INIT:0000000140C01639                                         ; InitBo…
INIT:0000000140C01639                 mov     eax, r13d
INIT:0000000140C0163C
INIT:0000000140C0163C loc_140C0163C:                          ; CODE X…
INIT:0000000140C0163C                                         ; InitBo…
INIT:0000000140C0163C                 mov     edi, 4
INIT:0000000140C01641                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C01646                 mov     rcx, rbx
INIT:0000000140C01649                 mov     ecx, 100h       ; BugChe…
INIT:0000000140C0164E                 mov     r8d, [rbx+rdi]  ; BugChe…
INIT:0000000140C01652                 lea     esi, [rdi+4]
INIT:0000000140C01655                 mov     r9d, [rbx+rsi]  ; BugChe…
INIT:0000000140C01659                 call    KeBugCheckEx
INIT:0000000140C01659 ; ----------------------------------------------…
INIT:0000000140C0165E                 db 0CCh
INIT:0000000140C0165F ; ----------------------------------------------…
INIT:0000000140C0165F
INIT:0000000140C0165F loc_140C0165F:                          ; CODE X…
INIT:0000000140C0165F                 mov     ecx, 5Ch ; '\'  ; BugChe…
INIT:0000000140C01664                 call    KeBugCheck
INIT:0000000140C01664 ; ----------------------------------------------…
INIT:0000000140C01669                 align 2
INIT:0000000140C0166A
INIT:0000000140C0166A loc_140C0166A:                          ; CODE X…
INIT:0000000140C0166A                 mov     ecx, 31h ; '1'  ; BugChe…
INIT:0000000140C0166F                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C01674                 call    KeBugCheckEx
INIT:0000000140C01674 ; ----------------------------------------------…
INIT:0000000140C01679                 align 2
INIT:0000000140C0167A
INIT:0000000140C0167A loc_140C0167A:                          ; CODE X…
INIT:0000000140C0167A                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C0167D                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C01682                 mov     rdx, 0FFFFFFFFC0000001h …
INIT:0000000140C01689                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C0168D                 lea     r8d, [r9+0Bh]   ; BugChe…
INIT:0000000140C01691                 call    KeBugCheckEx
INIT:0000000140C01691 ; ----------------------------------------------…
INIT:0000000140C01696                 db 0CCh
INIT:0000000140C01697 ; ----------------------------------------------…
INIT:0000000140C01697
INIT:0000000140C01697 loc_140C01697:                          ; CODE X…
INIT:0000000140C01697                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C0169A                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C0169D                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C016A2                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C016A6                 lea     r8d, [r9+13h]   ; BugChe…
INIT:0000000140C016AA                 call    KeBugCheckEx
INIT:0000000140C016AA ; ----------------------------------------------…
INIT:0000000140C016AF                 align 10h
INIT:0000000140C016B0
INIT:0000000140C016B0 loc_140C016B0:                          ; CODE X…
INIT:0000000140C016B0                 mov     ecx, 7Dh ; '}'  ; BugChe…
INIT:0000000140C016B5                 call    KeBugCheck
INIT:0000000140C016B5 ; ----------------------------------------------…
INIT:0000000140C016BA                 db 0CCh
INIT:0000000140C016BB ; ----------------------------------------------…
INIT:0000000140C016BB
INIT:0000000140C016BB loc_140C016BB:                          ; CODE X…
INIT:0000000140C016BB                 mov     cs:IopAutoReboot, r13d
INIT:0000000140C016C2                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C016C5                 mov     edx, [rbx+0Ch]  ; BugChe…
INIT:0000000140C016C8                 mov     r8, r12         ; BugChe…
INIT:0000000140C016CB                 mov     ecx, 196h       ; BugChe…
INIT:0000000140C016D0                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C016D5                 call    KeBugCheckEx
INIT:0000000140C016D5 ; ----------------------------------------------…
INIT:0000000140C016DA                 db 0CCh
INIT:0000000140C016DB ; ----------------------------------------------…
INIT:0000000140C016DB
INIT:0000000140C016DB loc_140C016DB:                          ; CODE X…
INIT:0000000140C016DB                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C016DE                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C016E1                 mov     r8, rdi         ; BugChe…
INIT:0000000140C016E4                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C016E9                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C016ED                 call    KeBugCheckEx
INIT:0000000140C016ED ; ----------------------------------------------…
INIT:0000000140C016F2                 db 0CCh
INIT:0000000140C016F3 ; ----------------------------------------------…
INIT:0000000140C016F3
INIT:0000000140C016F3 loc_140C016F3:                          ; CODE X…
INIT:0000000140C016F3                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C016F6                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C016F9                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C016FE                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C01702                 lea     r8d, [r9+5]     ; BugChe…
INIT:0000000140C01706                 call    KeBugCheckEx
INIT:0000000140C01706 ; ----------------------------------------------…
INIT:0000000140C0170B                 align 4
INIT:0000000140C0170C
INIT:0000000140C0170C loc_140C0170C:                          ; CODE X…
INIT:0000000140C0170C                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C0170F                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C01712                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C01717                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C0171B                 lea     r8d, [r9+6]     ; BugChe…
INIT:0000000140C0171F                 call    KeBugCheckEx
INIT:0000000140C0171F ; ----------------------------------------------…
INIT:0000000140C01724                 db 0CCh
INIT:0000000140C01725 ; ----------------------------------------------…
INIT:0000000140C01725
INIT:0000000140C01725 loc_140C01725:                          ; CODE X…
INIT:0000000140C01725                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C01728                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C0172B                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C01730                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C01734                 lea     r8d, [r9+7]     ; BugChe…
INIT:0000000140C01738                 call    KeBugCheckEx
INIT:0000000140C01738 ; ----------------------------------------------…
INIT:0000000140C0173D                 align 2
INIT:0000000140C0173E
INIT:0000000140C0173E loc_140C0173E:                          ; CODE X…
INIT:0000000140C0173E                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C01741                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C01744                 mov     r8, rsi         ; BugChe…
INIT:0000000140C01747                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C0174C                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C01750                 call    KeBugCheckEx
INIT:0000000140C01750 ; ----------------------------------------------…
INIT:0000000140C01755                 align 2
INIT:0000000140C01756
INIT:0000000140C01756 loc_140C01756:                          ; CODE X…
INIT:0000000140C01756                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C01759                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C0175C                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C01761                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C01765                 lea     r8d, [r9+9]     ; BugChe…
INIT:0000000140C01769                 call    KeBugCheckEx
INIT:0000000140C01769 ; ----------------------------------------------…
INIT:0000000140C0176E                 db 0CCh
INIT:0000000140C0176F ; ----------------------------------------------…
INIT:0000000140C0176F
INIT:0000000140C0176F loc_140C0176F:                          ; CODE X…
INIT:0000000140C0176F                 xor     r9d, r9d        ; BugChe…
INIT:0000000140C01772                 movsxd  rdx, eax        ; BugChe…
INIT:0000000140C01775                 mov     [rsp+200h+pcbRemaining],…
INIT:0000000140C0177A                 lea     ecx, [r9+31h]   ; BugChe…
INIT:0000000140C0177E                 lea     r8d, [r9+0Ah]   ; BugChe…
INIT:0000000140C01782                 call    KeBugCheckEx
INIT:0000000140C01782 ; ----------------------------------------------…
INIT:0000000140C01787                 align 8
INIT:0000000140C01788
INIT:0000000140C01788 loc_140C01788:                          ; CODE X…
INIT:0000000140C01788                 mov     ecx, 5Eh ; '^'  ; BugChe…
INIT:0000000140C0178D                 call    KeBugCheck
INIT:0000000140C0178D ; ----------------------------------------------…
INIT:0000000140C01792                 db 0CCh
INIT:0000000140C01793 ; ----------------------------------------------…
INIT:0000000140C01793
INIT:0000000140C01793 loc_140C01793:                          ; CODE X…
INIT:0000000140C01793                 mov     ecx, 5Fh ; '_'  ; BugChe…
INIT:0000000140C01798                 call    KeBugCheck
INIT:0000000140C01798 ; ----------------------------------------------…
INIT:0000000140C0179D                 align 2
INIT:0000000140C0179E
INIT:0000000140C0179E loc_140C0179E:                          ; CODE X…
INIT:0000000140C0179E                 mov     ecx, 8Fh        ; BugChe…
INIT:0000000140C017A3                 call    KeBugCheck
INIT:0000000140C017A3 ; ----------------------------------------------…
INIT:0000000140C017A8                 db 0CCh
INIT:0000000140C017A9 ; ----------------------------------------------…
INIT:0000000140C017A9
INIT:0000000140C017A9 loc_140C017A9:                          ; CODE X…
INIT:0000000140C017A9                                         ; InitBo…
INIT:0000000140C017A9                 mov     ecx, 60h ; '`'  ; BugChe…
INIT:0000000140C017AE                 call    KeBugCheck
INIT:0000000140C017AE ; ----------------------------------------------…
INIT:0000000140C017B3                 align 4
INIT:0000000140C017B4
INIT:0000000140C017B4 loc_140C017B4:                          ; CODE X…
INIT:0000000140C017B4                                         ; InitBo…
INIT:0000000140C017B4                 mov     ecx, 31h ; '1'  ; BugChe…
INIT:0000000140C017B9                 call    KeBugCheck
INIT:0000000140C017B9 ; ----------------------------------------------…
INIT:0000000140C017BE                 db 0CCh
INIT:0000000140C017BE ; } // starts at 140C00C88
INIT:0000000140C017BE InitBootProcessor endp
INIT:0000000140C017BE

```

// --- Called by: KiInitializeKernel at 0x140b4e8b0 (Depth: 4) ---
// Language: C/C++
```cpp
__int64 __fastcall KiInitializeKernel(
        struct _KPROCESS *a1,
        __int64 a2,
        __int64 a3,
        ULONG_PTR a4,
        unsigned int a5,
        __int64 a6)
{
  char v7; // al
  unsigned __int64 v8; // rax
  unsigned __int64 v9; // rcx
  unsigned __int64 v10; // rax
  ULONG_PTR v11; // rax
  unsigned __int64 v12; // rax
  unsigned __int64 v13; // rax
  unsigned __int64 v14; // rcx
  unsigned __int64 v15; // rax
  int v16; // r12d
  int v17; // eax
  ULONG_PTR v18; // rbx
  char XSaveFeatureFlags; // al
  ULONG_PTR v20; // rcx
  ULONG_PTR v21; // rbx
  unsigned __int64 v22; // rax
  unsigned __int64 v23; // rax
  __int64 v24; // rdx
  ULONG_PTR v25; // r8
  __int64 v26; // r10
  __int64 v27; // r9
  int TopologyIdForProcessor; // eax
  __int64 v29; // rcx
  int v30; // r9d
  int v31; // r11d
  __int64 v32; // r12
  __int64 v33; // rbx
  int v34; // r12d
  unsigned int v35; // ebx
  __int64 result; // rax
  ULONG_PTR BugCheckParameter1; // [rsp+30h] [rbp-2A8h] BYREF
  __int64 v38; // [rsp+38h] [rbp-2A0h] BYREF
  __int64 v39; // [rsp+40h] [rbp-298h]
  __int64 v40; // [rsp+48h] [rbp-290h]
  _BYTE *v41; // [rsp+50h] [rbp-288h]
  struct _KPROCESS *v42; // [rsp+58h] [rbp-280h]
  __int64 v43; // [rsp+60h] [rbp-278h]
  ULONG_PTR v44; // [rsp+68h] [rbp-270h]
  __int64 v45; // [rsp+70h] [rbp-268h]
  __int128 v46; // [rsp+78h] [rbp-260h] BYREF
  _DWORD v47[7]; // [rsp+90h] [rbp-248h] BYREF
  int v48; // [rsp+ACh] [rbp-22Ch]

  v38 = a3;
  v39 = a2;
  v42 = a1;
  v43 = a2;
  v44 = a4;
  v40 = a6;
  v45 = a6;
  v46 = 0;
  if ( !a5 )
  {
    HvlPhase0Initialize(a6);
    if ( KiSystemCallSelector == 1 && (HvlEnlightenments & 0x80000) != 0 )
      *(_DWORD *)(MmWriteableSharedUserData + 776) = 1;
  }
  BugCheckParameter1 = *(_QWORD *)(a4 + 36768);
  v41 = (_BYTE *)(a4 + 141);
  v7 = *(_BYTE *)(a4 + 141);
  if ( v7 == 2 || ((v7 - 1) & 0xFD) == 0 )
    KiSetHardwareSpeculationControlFeatures(a4, BugCheckParameter1);
  KiCheckMicrocode(a4);
  memset_0(v47, 0, 0x200u);
  _fxsave(v47);
  if ( a5 )
  {
    if ( KiFpuLeakage )
      BugCheckParameter1 |= 0x20000000000uLL;
    KiSetPageAttributesTable();
    KiInitializeTopologyStructures(a4);
    v16 = 65471;
  }
  else
  {
    KiFpuLeakage = KiDetectFpuLeakage();
    if ( KiFpuLeakage )
      BugCheckParameter1 |= 0x20000000000uLL;
    if ( KiFlushPcid )
    {
      v8 = __readcr3();
      __writecr3(v8);
      if ( !KeGetCurrentThread()->ApcState.Process->AddressPolicy )
        KiSetUserTbFlushPending();
    }
    else
    {
      v9 = __readcr4();
      if ( (v9 & 0x20080) != 0 )
      {
        __writecr4(v9 ^ 0x80);
        __writecr4(v9);
      }
      else
      {
        v10 = __readcr3();
        __writecr3(v10);
      }
    }
    KiSetPageAttributesTable();
    if ( MEMORY[0xFFFFF78000000280] )
      v11 = BugCheckParameter1 | 0x80000000;
    else
      v11 = BugCheckParameter1 & 0xFFFFFFFF3FFFFFFFuLL | 0x40000000;
    BugCheckParameter1 = v11;
    v12 = __readcr4();
    __writecr4(v12 | 0x18);
    if ( KiFlushPcid )
    {
      v13 = __readcr3();
      __writecr3(v13);
      if ( !KeGetCurrentThread()->ApcState.Process->AddressPolicy )
        KiSetUserTbFlushPending();
    }
    else
    {
      v14 = __readcr4();
      if ( (v14 & 0x20080) != 0 )
      {
        __writecr4(v14 ^ 0x80);
        __writecr4(v14);
      }
      else
      {
        v15 = __readcr3();
        __writecr3(v15);
      }
    }
    KiConfigureProcessorBlock(a4);
    KiInitializeTopologyStructures(a4);
    v16 = 65471;
    v17 = 65471;
    if ( v48 )
      v17 = v48;
    KiMxCsrMask = v17;
    KeCompactServiceTable((unsigned int)KiServiceTable, (unsigned int)KiArgumentTable, KiServiceLimit, 0, 0x40000000u);
  }
  KiInitializeCoreControlBlock(a4 + 41240, a4 + 44736);
  KiAddProcessorToCoreControlBlock(a4 + 41240, a4);
  KiSetCacheInformation();
  PoInitializePrcb((PVOID)a4);
  *(_QWORD *)(a4 + 36504) = 0;
  *(_QWORD *)(a4 + 36512) = a4 + 36512;
  if ( MEMORY[0xFFFFF780000003D8] )
  {
    BugCheckParameter1 |= 0x800000uLL;
    v18 = BugCheckParameter1;
    XSaveFeatureFlags = RtlGetXSaveFeatureFlags();
    v20 = BugCheckParameter1;
    if ( (XSaveFeatureFlags & 8) != 0 )
    {
      v18 = BugCheckParameter1 | 0x8000;
      BugCheckParameter1 = v18;
      v20 = v18;
    }
    if ( (XSaveFeatureFlags & 0x10) != 0 )
    {
      v20 = v18 | 0x4000000000LL;
      BugCheckParameter1 = v18 | 0x4000000000LL;
    }
    if ( (XSaveFeatureFlags & 0x40) != 0 )
      BugCheckParameter1 = v20 | 0x80000000000000LL;
  }
  KiSetControlEnforcement(a4, &BugCheckParameter1);
  KiCheckEnqueueStoreFeaturePresence(a4, &BugCheckParameter1);
  v21 = BugCheckParameter1;
  if ( a5 )
  {
    if ( v48 )
      v16 = v48;
    v25 = KeFeatureBits & 0xFFFFFFFF37FFFFFFuLL | 0x8000000;
    if ( (BugCheckParameter1 & 0x8000000) == 0 )
      v25 = KeFeatureBits & 0xFFFFFFFF37FFFFFFuLL;
    if ( *v41 == 2 && *(_BYTE *)(a4 + 64) == 6 && *(_BYTE *)(a4 + 67) == 23 && *(_BYTE *)(a4 + 66) == 10 )
    {
      KeGetTopologyIdForProcessor(a4, 4, v25);
      v27 = 0;
      if ( (_DWORD)KeNumberProcessors_0 )
      {
        while ( 1 )
        {
          TopologyIdForProcessor = KeGetTopologyIdForProcessor(KiProcessorBlock[v27], 4, v25);
          if ( v31 == TopologyIdForProcessor )
            break;
          v27 = (unsigned int)(v30 + 1);
          if ( (unsigned int)v27 >= (unsigned int)KeNumberProcessors_0 )
            goto LABEL_59;
        }
        v26 = v29;
      }
LABEL_59:
      v21 = BugCheckParameter1 & 0xFFFFFFFFFFEFFFFFuLL;
      if ( (*(_DWORD *)(v26 + 36768) & 0x100000) != 0 )
        v21 |= 0x100000uLL;
    }
    if ( v21 != v25
      || v16 != KiMxCsrMask
      || *(_DWORD *)(KiProcessorBlock[0] + 232) != *(_DWORD *)(a4 + 232)
      || *(_DWORD *)(KiProcessorBlock[0] + 160) != *(_DWORD *)(a4 + 160)
      || *(_DWORD *)(KiProcessorBlock[0] + 164) != *(_DWORD *)(a4 + 164) )
    {
      KeBugCheckEx(0x3Eu, v21, v25, 0, 0);
    }
    if ( KiIrqlFlags )
      KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql());
    __writecr8(2u);
    HvlEnlightenProcessor(0);
  }
  else
  {
    KeProcessorArchitecture = 9;
    KeProcessorLevel = *(char *)(a4 + 64);
    KeProcessorRevision = *(_WORD *)(a4 + 66);
    KeFeatureBits = BugCheckParameter1;
    if ( KiIrqlFlags )
      KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql());
    __writecr8(1u);
    KiFreezeExecutionLock = 0;
    KiInitSystem(v42);
    v22 = __rdtsc();
    KiWaitNever = __ROR8__(v22 ^ __ROL8__(v22, 43), v22 & 0xF);
    v23 = __rdtsc();
    KiWaitAlways = __ROL8__(__ROR8__(v23, 47) ^ v23, v23 & 0xF);
    HviGetHypervisorFeatures(&v46);
    if ( (WORD6(v46) & 0x1000) != 0 )
      KiNPIEPEnabled = 1;
    if ( (unsigned int)KiIsKernelCfgActive() )
      RtlInitKernelModeSpecialMachineFrameEntries();
  }
  if ( KiNPIEPEnabled )
  {
    v24 = 0;
    __writemsr(0x40000040u, 0xFu);
  }
  KiEnableXSave(0, v24);
  *(_QWORD *)(MmWriteableSharedUserData + 760) = 195;
  *(_BYTE *)(MmWriteableSharedUserData + 630) = 1;
  *(_BYTE *)(MmWriteableSharedUserData + 631) = 1;
  *(_BYTE *)(MmWriteableSharedUserData + 634) = 1;
  *(_BYTE *)(MmWriteableSharedUserData + 636) = 1;
  *(_BYTE *)(MmWriteableSharedUserData + 637) = 1;
  *(_BYTE *)(MmWriteableSharedUserData + 638) = 1;
  *(_BYTE *)(MmWriteableSharedUserData + 642) = 1;
  if ( (v21 & 0x80000) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 641) = 1;
  if ( (v21 & 0x4000) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 635) = 1;
  if ( (v21 & 0x800000) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 645) = 1;
  if ( (v21 & 0x10000000) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 650) = 1;
  if ( (v21 & 0x4000000) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 648) = 1;
  if ( (v21 & 0x8000000) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 649) = 1;
  if ( (v21 & 0x100000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 656) = 1;
  if ( (v21 & 0x400000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 660) = 1;
  if ( (v21 & 0x800000000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 664) = 1;
  if ( (v21 & 0x1000000000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 665) = 1;
  if ( (v21 & 0x2000000000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 666) = 1;
  if ( (v21 & 0x4000000000000LL) != 0 && (MEMORY[0xFFFFF780000003D8] & 4) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 667) = 1;
  if ( (v21 & 0x8000000000000LL) != 0 && (MEMORY[0xFFFFF780000003D8] & 4) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 668) = 1;
  if ( (v21 & 0x10000000000000LL) != 0 && (MEMORY[0xFFFFF780000003D8] & 0xE0) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 669) = 1;
  if ( (v21 & 0x40000000000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 670) = 1;
  if ( (v21 & 0x200000000000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 688) = 1;
  if ( (unsigned int)Feature_Test57481295__private_IsEnabledDeviceUsageNoInline() && (v21 & 0x400000000000000LL) != 0 )
    *(_BYTE *)(MmWriteableSharedUserData + 689) = 1;
  *(_BYTE *)(MmWriteableSharedUserData + 749) = KiVirtFlags;
  v32 = v39;
  if ( a5 )
  {
    KiStartIdleThread(v39, a4, v38);
    v33 = v40;
  }
  else
  {
    v33 = v40;
    KiInitializeAndStartInitialThread(v39, v38, a4, v40);
  }
  if ( a5 )
  {
    KiStartPrcbThreads(a4);
    if ( !(unsigned __int8)HalInitSystem(1u) )
      KeBugCheck(0x5Cu);
  }
  else
  {
    InitBootProcessor(v33);
  }
  if ( *v41 == 1 )
    KiConfigureAmdTprLowerInterruptDelayWorkaround(a4);
  KiCompleteKernelInit(a4, v32, a5);
  v34 = KiBootProcessorsStarted;
  *(_QWORD *)(v33 + 136) = 0;
  v35 = 0;
  while ( 1 )
  {
    result = (unsigned int)KiBarrierWait;
    LODWORD(v38) = KiBarrierWait;
    if ( !KiBarrierWait )
      break;
    if ( (++v35 & HvlLongSpinCountMask) == 0
      && (HvlEnlightenments & 0x40) != 0
      && (unsigned __int8)KiCheckVpBackingLongSpinWaitHypercall() )
    {
      if ( v34 )
        HvlNotifyLongSpinWait(v35);
      else
        KeHaltOnAddress(&KiBarrierWait, &v38, 4);
    }
    else
    {
      _mm_pause();
    }
  }
  if ( a5 )
    result = KiInitializeProcessorCycleAccumulation(a4);
  if ( KiClockTimerPerCpuTickScheduling )
  {
    if ( a5 )
      return KeInitializeClockOtherProcessors(a4);
  }
  return result;
}

```

// --- Called by: KiSystemStartup at 0x140b413a0 (Depth: 5) ---
// Language: C/C++
```cpp
// write access to const memory has been detected, the output may be wrong!
NTSTATUS __stdcall __noreturn KiSystemStartup(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  unsigned int *v2; // r10
  unsigned __int64 v4; // r8
  unsigned __int64 v5; // r8
  unsigned __int64 v6; // r8
  unsigned __int64 v7; // r8
  __int64 v8; // r8
  unsigned __int64 v10; // rdx
  __int64 v11; // rax
  unsigned int v13; // eax
  void *v14; // rsp
  __int64 v15; // rax
  struct _KPROCESS *v16; // rcx
  __int64 v17; // rdx
  unsigned __int64 v18; // r8

  KeLoaderBlock_0 = (__int64)DriverObject;
  if ( !*((_DWORD *)DriverObject->MajorFunction[3] + 9) )
    KasanInitSystem(DriverObject, 0);
  if ( !*(_DWORD *)(*(_QWORD *)(KeLoaderBlock_0 + 136) + 36LL) )
    KdInitSystem(0xFFFFFFFFLL);
  v2 = *(unsigned int **)(KeLoaderBlock_0 + 136);
  _RDX = v2 - 96;
  *((_QWORD *)_RDX + 3) = _RDX;
  *((_QWORD *)_RDX + 4) = v2;
  v4 = __readcr0();
  *((_QWORD *)v2 + 32) = v4;
  v5 = __readcr2();
  *((_QWORD *)v2 + 33) = v5;
  v6 = __readcr3();
  *((_QWORD *)v2 + 34) = v6;
  v7 = __readcr4();
  *((_QWORD *)v2 + 35) = v7;
  __sgdt((char *)v2 + 342);
  v8 = *((_QWORD *)v2 + 43);
  *(_QWORD *)_RDX = v8;
  __sidt((char *)v2 + 358);
  *((_QWORD *)_RDX + 7) = *((_QWORD *)v2 + 45);
  __asm
  {
    str     word ptr [rdx+2F0h]
    sldt    word ptr [rdx+2F2h]
  }
  *v2 = 8064;
  _mm_setcsr(*v2);
  if ( !v2[9] )
    *(_WORD *)(v8 + 80) = 15360;
  __DS__ = 43;
  if ( !VslVsmEnabled )
  {
    _AX = 0;
    __asm { lldt    ax }
  }
  *MK_FP(43, _RDX + 2) = *MK_FP(43, v8 + 66);
  *MK_FP(43, (char *)_RDX + 10) = *MK_FP(43, v8 + 68);
  *MK_FP(43, (char *)_RDX + 11) = *MK_FP(43, v8 + 71);
  *MK_FP(43, _RDX + 3) = *MK_FP(43, v8 + 72);
  v10 = (unsigned __int64)_RDX >> 32;
  __writemsr(0xC0000101, __PAIR64__(v10, (int)v2 - 384));
  __writemsr(0xC0000102, __PAIR64__(v10, (int)v2 - 384));
  if ( !*MK_FP(43, v2 + 9) )
  {
    _guard_dispatch_icall_fptr[0] = guard_dispatch_icall_thunk_10345483385596137414;
    _guard_check_icall_fptr[0] = guard_check_icall_no_overrides;
  }
  v11 = KiInitializeKernelShadowStacks(KeLoaderBlock_0, v10);
  if ( v11 )
  {
    _R8 = v11;
    if ( !*MK_FP(43, *MK_FP(43, KeLoaderBlock_0 + 136) + 36LL) )
    {
      v13 = 1;
      if ( (KiKernelCetAuditModeEnabled & 1) != 0 )
        v13 = 3;
      __writemsr(0x6A2u, v13);
      __asm { setssbsy }
    }
    __asm
    {
      rstorssp qword ptr [r8]
      saveprevssp
    }
  }
  KiInitializeBootStructures(KeLoaderBlock_0);
  if ( !*MK_FP(43, *MK_FP(43, KeLoaderBlock_0 + 136) + 36LL) )
    KdInitSystem(0);
  KiInitializeXSaveConfiguration(KeLoaderBlock_0, (unsigned int)*MK_FP(43, *MK_FP(43, KeLoaderBlock_0 + 136) + 36LL));
  if ( KiIrqlFlags )
    KzSetIrqlUnsafe(15);
  else
    __writecr8(0xFu);
  v14 = alloca((unsigned int)KiXSaveAreaLength);
  v15 = KeLoaderBlock_0;
  v16 = (struct _KPROCESS *)*MK_FP(43, KeLoaderBlock_0 + 144);
  v17 = *MK_FP(43, KeLoaderBlock_0 + 152);
  if ( (KiKvaShadow & 1) != 0 )
  {
    v18 = *MK_FP(43, *MK_FP(43, &KeGetPcr()->IdtBase) + 4216LL);
    __writegsqword(0xB008u, v18);
  }
  else
  {
    v18 = *MK_FP(43, *MK_FP(43, &KeGetPcr()->TssBase) + 4LL);
  }
  __writegsqword(0x1A8u, v18);
  KiInitializeKernel(v16, v17, v18, *MK_FP(43, v15 + 136), *MK_FP(43, *MK_FP(43, v15 + 136) + 36LL), v15);
  if ( !*MK_FP(43, &KeGetPcr()->Prcb.Number) )
    _security_cookie_complement = ~_security_cookie;
  *MK_FP(43, &KeGetCurrentThread()->WaitBlockFill11[70]) = 2;
  KiIdleLoop();
}

```

// --- Called by: Phase1InitializationDiscard at 0x140c02048 (Depth: 3) ---
// Language: C/C++
```cpp
char __fastcall Phase1InitializationDiscard(ULONG_PTR BugCheckParameter3)
{
  __int64 v2; // r12
  char *Pool2; // r13
  struct _KTHREAD *CurrentThread; // rcx
  char *v5; // rcx
  char *v6; // rax
  const char *v7; // rdi
  char *v8; // rax
  char *v9; // rax
  char *v10; // rax
  char *v11; // rbx
  __int16 v12; // ax
  int v13; // edx
  char v14; // al
  char *v15; // rax
  char *v16; // rbx
  unsigned int v17; // eax
  char *v18; // rcx
  __int64 v19; // r14
  unsigned int v20; // eax
  unsigned int v21; // r15d
  __int64 v22; // r14
  __int64 v23; // rax
  char v24; // al
  __int64 v25; // rax
  __int64 v26; // rbx
  ULONG_PTR v27; // rcx
  __int64 v28; // rcx
  int Message; // eax
  NTSTRSAFE_PSTR v30; // rbx
  int v31; // r15d
  NTSTATUS v32; // eax
  size_t v33; // r14
  char *v34; // rbx
  NTSTATUS v35; // eax
  NTSTATUS v36; // eax
  NTSTATUS v37; // eax
  ULONG_PTR v38; // r10
  _OWORD *v39; // rax
  char *v40; // rcx
  __int64 v41; // rdx
  __int128 v42; // xmm1
  int v43; // eax
  char *v44; // rax
  char *v45; // rax
  __int16 v46; // bx
  LARGE_INTEGER v47; // rax
  __int64 CurrentServerSiloGlobals; // rax
  char *v49; // rax
  char *v50; // rax
  char *v51; // rax
  char *v52; // rax
  char *v53; // rax
  char *v54; // rax
  char *v55; // rax
  char *v56; // rax
  char *v57; // rax
  char *v58; // rax
  const char *v59; // rbx
  int v60; // r9d
  int v61; // eax
  __int64 v62; // rdx
  __int64 v63; // rbx
  _QWORD *v64; // rcx
  NTSTATUS v65; // eax
  int inited; // eax
  int v67; // eax
  int SystemRootLink; // eax
  int v69; // eax
  __int64 v70; // rdx
  __int64 v71; // rcx
  __int64 v72; // r8
  __int64 *v73; // r9
  __int64 DisplayContext; // rax
  ULONG_PTR v75; // rbx
  int v76; // eax
  int v77; // eax
  int v78; // eax
  int v79; // eax
  int v80; // ebx
  char *v86; // rax
  const char *v87; // rbx
  int v88; // eax
  int v89; // ecx
  int v90; // r9d
  __int16 v91; // ax
  bool v92; // zf
  int v93; // eax
  ULONG dwFlags[2]; // [rsp+20h] [rbp-E0h]
  int pszFormat; // [rsp+28h] [rbp-D8h]
  char v97; // [rsp+40h] [rbp-C0h] BYREF
  char v98; // [rsp+41h] [rbp-BFh]
  LONGLONG v99; // [rsp+48h] [rbp-B8h] BYREF
  __int64 v100; // [rsp+50h] [rbp-B0h] BYREF
  int v101; // [rsp+58h] [rbp-A8h]
  __int64 v102; // [rsp+60h] [rbp-A0h] BYREF
  int v103; // [rsp+68h] [rbp-98h] BYREF
  int v104; // [rsp+6Ch] [rbp-94h] BYREF
  char *EndPtr; // [rsp+70h] [rbp-90h] BYREF
  LARGE_INTEGER v106; // [rsp+78h] [rbp-88h] BYREF
  int v107; // [rsp+80h] [rbp-80h] BYREF
  size_t pcbRemaining; // [rsp+88h] [rbp-78h] BYREF
  NTSTRSAFE_PSTR ppszDestEnd; // [rsp+90h] [rbp-70h] BYREF
  __int64 v110; // [rsp+98h] [rbp-68h] BYREF
  __int128 v111; // [rsp+A0h] [rbp-60h] BYREF
  STRING v112; // [rsp+B0h] [rbp-50h] BYREF
  UNICODE_STRING DestinationString; // [rsp+C0h] [rbp-40h] BYREF
  _DWORD v114[2]; // [rsp+D0h] [rbp-30h] BYREF
  __int64 (__fastcall *v115)(); // [rsp+D8h] [rbp-28h]
  __int64 (__fastcall *v116)(); // [rsp+E0h] [rbp-20h]
  __int64 (__fastcall *v117)(); // [rsp+E8h] [rbp-18h]
  __int64 (__fastcall *v118)(int, int, int, int, __int64); // [rsp+F0h] [rbp-10h]
  __int64 (__fastcall *v119)(); // [rsp+F8h] [rbp-8h]
  __int64 (__fastcall *v120)(); // [rsp+100h] [rbp+0h]
  __int64 (__fastcall *v121)(); // [rsp+108h] [rbp+8h]
  __int64 (__fastcall *v122)(ULONG_PTR); // [rsp+110h] [rbp+10h]
  __int64 (__fastcall *v123)(); // [rsp+118h] [rbp+18h]
  __int128 v124; // [rsp+120h] [rbp+20h]
  __int128 v125; // [rsp+130h] [rbp+30h]
  __int64 v126; // [rsp+140h] [rbp+40h]
  char pszDest[24]; // [rsp+150h] [rbp+50h] BYREF

  v99 = 0;
  v106.QuadPart = 0;
  v110 = 0;
  v102 = 0;
  v100 = 0;
  v112 = 0;
  LOBYTE(v101) = 0;
  v111 = 0;
  v107 = 0;
  v103 = 0;
  v104 = 0;
  DestinationString = 0;
  v114[1] = 0;
  memset_0(v114, 0, 0x74u);
  v2 = *(_QWORD *)(PsGetCurrentServerSiloGlobals() + 1224);
  Pool2 = (char *)ExAllocatePool2(0x40u);
  if ( !Pool2 )
    KeBugCheck(0x31u);
  CurrentThread = KeGetCurrentThread();
  v98 = 0;
  LODWORD(InitializationPhase) = 1;
  KeSetPriorityThread(CurrentThread, 31);
  v5 = *(char **)(BugCheckParameter3 + 216);
  if ( v5 )
  {
    v6 = strupr(v5);
    v7 = v6;
    if ( v6 )
    {
      v8 = strstr(v6, " HYPERVISORROOTPROC=");
      if ( v8 )
      {
        v9 = strstr(v8, "=");
        if ( v9 )
          KeRootProcSpecified = atol(v9 + 1);
      }
      v10 = strstr(v7, " HYPERVISORROOTPROCNUMANODES=");
      v11 = v10;
      if ( v10 )
        v11 = strstr(v10, "=");
LABEL_10:
      while ( v11 && (unsigned int)KeRootProcNumaNodesSpecified < 0x40 )
      {
        v12 = atol(++v11);
        v13 = KeRootProcNumaNodesSpecified;
        *((_WORD *)&KeRootProcNumaNodes + (unsigned int)KeRootProcNumaNodesSpecified) = v12;
        v14 = *v11;
        KeRootProcNumaNodesSpecified = v13 + 1;
        if ( v14 != 44 )
        {
          while ( v14 != 32 && v14 )
          {
            v14 = *++v11;
            if ( *v11 == 44 )
              goto LABEL_10;
          }
          break;
        }
      }
      v15 = strstr(v7, " HYPERVISORROOTPROCNUMANODELPS=");
      v16 = v15;
      if ( v15 )
      {
        v16 = strstr(v15, "=");
        KeRootProcNumaNodeLpsSpecified = 1;
        KeRootProcNumaNodesSpecified = 0;
        KeRootProcSpecified = 0;
      }
LABEL_20:
      while ( v16 )
      {
        ++v16;
        EndPtr = 0;
        v17 = strtoul(v16, &EndPtr, 10);
        v18 = EndPtr;
        v19 = v17;
        if ( v16 == EndPtr || *EndPtr != 95 )
        {
          v21 = 0;
        }
        else
        {
          v16 = EndPtr + 1;
          v20 = strtoul(EndPtr + 1, &EndPtr, 10);
          v18 = EndPtr;
          v21 = v20;
        }
        if ( v16 != v18 && *v18 == 61 && (unsigned int)v19 < 0x40 )
        {
          v22 = 2 * v19;
          v16 = v18 + 1;
          if ( !qword_140FCBC08[v22] )
          {
            v23 = ExAllocatePool2(0x40u);
            if ( !v23 )
              KeBugCheck(0x31u);
            KeRootProcNumaNodeLps[v22] = 2048;
            qword_140FCBC08[v22] = v23;
          }
          if ( v21 < 0x20 )
            *(_QWORD *)(qword_140FCBC08[v22] + 8LL * v21) = strtoui64(v16, &EndPtr, 16);
        }
        v24 = *v16;
        if ( *v16 != 44 )
        {
          while ( v24 != 32 && v24 )
          {
            v24 = *++v16;
            if ( *v16 == 44 )
              goto LABEL_20;
          }
          break;
        }
      }
    }
  }
  else
  {
    v7 = 0;
  }
  v25 = KiSubNodeConfigBlock;
  word_140E66600 = 0;
  *(_BYTE *)(KiSubNodeConfigBlock + 5) &= 0xFCu;
  *(_BYTE *)(v25 + 4) = 0;
  KiPerformGroupConfiguration(BugCheckParameter3);
  v26 = KiSubNodeConfigBlock;
  KiCommitGroupSubNodeAssignments(*(unsigned __int16 *)(KiSubNodeConfigBlock + 6));
  v27 = (unsigned int)InitializationPhase;
  *(_QWORD *)(v26 + 16) |= 1uLL;
  if ( !(unsigned __int8)HalInitSystem(v27) )
    goto LABEL_221;
  KeInitializeClock((unsigned int)InitializationPhase);
  if ( v7 && strstr(v7, "NOGUIBOOT") )
    goto LABEL_224;
  byte_140E65C48 = 0;
  if ( byte_140E65C98 )
  {
    if ( byte_140E65CA1 )
    {
      LOBYTE(v28) = 1;
      if ( (int)BgDisplayProgressIndicator(v28) >= 0 )
        byte_140E65C99 = 1;
    }
    if ( byte_140E65C98 )
    {
      if ( byte_140E65CA1 )
      {
        LOBYTE(v28) = 1;
        if ( (int)BgDisplayBackgroundUpdate(v28) >= 0 )
          byte_140E65C61 = 1;
      }
    }
  }
  qword_140E65C40 = (__int64)DisplayFilter;
  InbvDriverInitialize(1, BugCheckParameter3, 7);
  DisplayBootBitmap(0);
  if ( v7 )
  {
LABEL_224:
    if ( strstr(v7, "MININT") )
    {
      InitIsWinPEMode = 1;
      if ( strstr(v7, "INRAM") )
        InitWinPEModeType |= 0x80000000;
      else
        InitWinPEModeType |= 1u;
    }
  }
  Message = RtlFindMessage(0x40000000u, 11, 0, 1073741950, (__int64)&v102);
  v30 = Pool2;
  ppszDestEnd = Pool2;
  v31 = Message;
  pcbRemaining = 256;
  if ( CmCSDVersionString.Length )
  {
    v32 = RtlStringCbPrintfExA(Pool2, 0xFFu, &ppszDestEnd, &pcbRemaining, 0, ": %wZ");
    if ( v32 < 0 )
      KeBugCheckEx(0x32u, v32, 7u, 0, 0);
    v30 = ppszDestEnd;
    v33 = pcbRemaining;
  }
  else
  {
    v33 = 255;
    pcbRemaining = 255;
  }
  *v30 = 0;
  v34 = v30 + 1;
  ppszDestEnd = v34;
  v35 = RtlStringCbPrintfA(pszDest, 0x18u, "%u.%u", 10, 0);
  if ( v35 < 0 )
    KeBugCheckEx(0x32u, v35, 7u, 1u, 0);
  if ( v31 < 0 )
  {
    v37 = RtlStringCbCopyA(v34, v33, "MICROSOFT (R) WINDOWS (TM)\n");
    if ( v37 < 0 )
      KeBugCheckEx(0x32u, v37, 7u, 3u, v38);
  }
  else
  {
    pszFormat = (int)Pool2;
    dwFlags[0] = (unsigned __int16)NtBuildNumber;
    v36 = RtlStringCbPrintfA(v34, v33, (NTSTRSAFE_PCSTR)(v102 + 4), pszDest, *(_QWORD *)dwFlags);
    if ( v36 < 0 )
      KeBugCheckEx(0x32u, v36, 7u, 2u, 0);
  }
  InbvDisplayString(v34);
  v39 = Pool2 + 256;
  v40 = Pool2;
  v41 = 2;
  do
  {
    *v39 = *(_OWORD *)v40;
    v39[1] = *((_OWORD *)v40 + 1);
    v39[2] = *((_OWORD *)v40 + 2);
    v39[3] = *((_OWORD *)v40 + 3);
    v39[4] = *((_OWORD *)v40 + 4);
    v39[5] = *((_OWORD *)v40 + 5);
    v39[6] = *((_OWORD *)v40 + 6);
    v39 += 8;
    v42 = *((_OWORD *)v40 + 7);
    v40 += 128;
    *(v39 - 1) = v42;
    --v41;
  }
  while ( v41 );
  if ( !(unsigned __int8)PoInitSystem(0, BugCheckParameter3) )
LABEL_220:
    KeBugCheck(0xA0u);
  if ( !ExpRealTimeIsUniversal )
  {
    v43 = *(_DWORD *)(v2 + 436);
    if ( v43 == -1 )
    {
      *(_DWORD *)(v2 + 436) = ExpAltTimeZoneBias;
      v43 = ExpAltTimeZoneBias;
      v98 = 1;
    }
    *(_QWORD *)(v2 + 440) = 600000000LL * v43;
    *(_DWORD *)(MmWriteableSharedUserData + 604) = 0;
    ExpWriteTimeZoneBias();
  }
  GetBootSystemTime(*(_QWORD *)(BugCheckParameter3 + 240), &v99);
  if ( v7 )
  {
    v44 = strstr(v7, "YEAR");
    if ( v44 )
    {
      v45 = strstr(v44, "=");
      if ( v45 )
      {
        v46 = atol(v45 + 1);
        RtlpTimeToTimeFields(&v99, &v111);
        LOWORD(v111) = v46;
        RtlpTimeFieldsToTime(&v111, &v99);
      }
    }
  }
  if ( ExpRealTimeIsUniversal )
    v47.QuadPart = v99;
  else
    v47.QuadPart = v99 - *(_QWORD *)(*(_QWORD *)(PsGetCurrentServerSiloGlobals() + 1224) + 440LL);
  v106 = v47;
  KeSetSystemTime(&v99, &v110, 4);
  CurrentServerSiloGlobals = PsGetCurrentServerSiloGlobals();
  PoNotifySystemTimeSet(
    (unsigned int)&v99,
    (unsigned int)&v110,
    0,
    (unsigned int)&v106,
    *(_DWORD *)(*(_QWORD *)(CurrentServerSiloGlobals + 1224) + 436LL),
    pszFormat,
    ExpSystemIsInCmosMode);
  RtlInitUnicodeString(&DestinationString, L"Kernel-RegisteredProcessors");
  if ( (int)ZwQueryLicenseValue(&DestinationString, &v104, &KeRegisteredProcessors, 4, &v103) < 0
    || v103 != 4
    || v104 != 4 )
  {
    KeRegisteredProcessors = 1;
  }
  if ( v7 )
  {
    v49 = strstr(v7, " BOOTPROC=");
    if ( v49 )
    {
      v50 = strstr(v49, "=");
      if ( v50 )
        KeBootprocSpecified = atol(v50 + 1);
    }
    v51 = strstr(v7, " NUMPROC=");
    if ( v51 )
    {
      v52 = strstr(v51, "=");
      if ( v52 )
        KeNumprocSpecified = atol(v52 + 1);
    }
    v53 = strstr(v7, " HYPERVISORNUMPROC=");
    if ( v53 )
    {
      v54 = strstr(v53, "=");
      if ( v54 )
        KeHypervisorNumprocSpecified = atol(v54 + 1);
    }
    if ( !KeRootProcNumaNodeLpsSpecified )
    {
      v55 = strstr(v7, " HYPERVISORROOTPROCPERNODE=");
      if ( v55 )
      {
        v56 = strstr(v55, "=");
        if ( v56 )
          KeRootProcPerNodeSpecified = atol(v56 + 1);
      }
      v57 = strstr(v7, " HYPERVISORROOTPROCPERCORE=");
      if ( v57 )
      {
        v58 = strstr(v57, "=");
        if ( v58 )
          KeRootProcPerCoreSpecified = atol(v58 + 1);
      }
    }
    if ( strstr(v7, " MAXPROC") )
      KeMaxprocSpecified = 1;
  }
  qword_1410077C8 = KeQueryPerformanceCounter(0).QuadPart;
  KeStartAllProcessors();
  qword_1410077D0 = KeQueryPerformanceCounter(0).QuadPart;
  EtwTimeProfileReset();
  KeSetAffinityProcess(KeGetCurrentThread()->ApcState.Process);
  MakeGdtReadOnly();
  v59 = (int)RtlFindMessage(0x40000000u, 11, 0, 1073741961, (__int64)&v100) < 0
      ? "MultiProcessor Kernel\r\n"
      : (const char *)(v100 + 4);
  if ( !(unsigned __int8)HalAllProcessorsStarted() )
LABEL_221:
    KeBugCheck(0x61u);
  RtlInitAnsiString(&v112, v59);
  if ( v112.Length >= 2u )
    v112.Length -= 2;
  v60 = 1073741981;
  if ( (unsigned int)KeNumberProcessors_0 <= 1 )
    v60 = 1073741960;
  v61 = RtlFindMessage(0x40000000u, 11, 0, v60, (__int64)&v102);
  v62 = 0;
  v63 = *(unsigned int *)MmPhysicalMemoryBlock;
  if ( (_DWORD)v63 )
  {
    v64 = (char *)MmPhysicalMemoryBlock + 24;
    do
    {
      v62 += *v64;
      v64 += 2;
      --v63;
    }
    while ( v63 );
  }
  if ( v61 < 0 )
    v65 = RtlStringCbPrintfA(
            Pool2,
            0x100u,
            "%u System Processor [%u MB Memory] %Z\n",
            (unsigned int)KeNumberProcessors_0,
            (unsigned __int64)(v62 + 255) >> 8,
            &v112);
  else
    v65 = RtlStringCbPrintfA(
            Pool2,
            0x100u,
            (NTSTRSAFE_PCSTR)(v102 + 4),
            (unsigned int)KeNumberProcessors_0,
            (unsigned __int64)(v62 + 255) >> 8,
            &v112);
  if ( v65 < 0 )
    KeBugCheckEx(0x32u, v65, 7u, 4u, 0);
  InbvDisplayString(Pool2);
  ExFreePoolWithTag(Pool2, 0);
  if ( !(unsigned __int8)ObInitSystem(1) )
    KeBugCheck(0x62u);
  if ( !(unsigned __int8)ExInitSystem(BugCheckParameter3) )
    KeBugCheckEx(0x32u, 0xFFFFFFFFC0000001uLL, 0, 1u, 0);
  HalReportResourceUsage(0xFFFFFFFFLL);
  if ( !(unsigned __int8)IoCreateObjectTypes() )
    KeBugCheckEx(0x32u, 0xFFFFFFFFC0000001uLL, 0, 4u, 0);
  if ( !(unsigned __int8)KeInitSystem(1) )
    KeBugCheckEx(0x32u, 0xFFFFFFFFC0000001uLL, 0, 2u, 0);
  if ( !(unsigned __int8)KdInitSystem((unsigned int)InitializationPhase) )
    KeBugCheckEx(0x32u, 0xFFFFFFFFC0000001uLL, 0, 3u, 0);
  inited = TmInitSystem(
             &TmResourceManagerObjectType,
             &TmEnlistmentObjectType,
             &TmTransactionManagerObjectType,
             &TmTransactionObjectType);
  if ( (int)(inited + 0x80000000) >= 0 && inited != -1073741637 )
    KeBugCheckEx(0x32u, 0, 0, 0, 0);
  v67 = DbgkInitialize();
  if ( v67 < 0 )
    KeBugCheckEx(0x32u, v67, 0, 0, 0);
  UcInitialize(0);
  BcdInitializeBcdSyncMutant();
  VerifierInitSystem(0);
  if ( !(unsigned __int8)SeInitSystem() )
    KeBugCheck(0x63u);
  LpcLegacyMaxMessageLength = 648;
  if ( (int)AlpcpInitSystem() < 0 )
    KeBugCheck(0x6Au);
  LpcPortObjectType = AlpcPortObjectType;
  PsInitSystem(1, BugCheckParameter3);
  ExInitLicenseCallback();
  SystemRootLink = CreateSystemRootLink(BugCheckParameter3);
  if ( SystemRootLink < 0 )
    KeBugCheckEx(0x64u, SystemRootLink, 0, 0, 0);
  qword_1410077E8 = KeQueryPerformanceCounter(0).QuadPart;
  MmInitSystem(1, BugCheckParameter3);
  qword_1410077F0 = KeQueryPerformanceCounter(0).QuadPart;
  if ( !(unsigned __int8)CcInitializeCacheManager(1) )
    KeBugCheck(0x66u);
  if ( !(unsigned __int8)CmInitSystem1(BugCheckParameter3) )
    KeBugCheck(0x67u);
  PsInitializeBootCpuPartitions();
  v69 = ExInitializeLeapSecondData();
  if ( v69 < 0 )
    KeBugCheckEx(0x32u, v69, 0xCu, 0, 0);
  v97 = 0;
  if ( (int)ExIsMultiSessionSku(&v97) >= 0 && v97 )
    *(_DWORD *)(MmWriteableSharedUserData + 752) |= 0x100u;
  if ( RtlpMultiUsersInSessionSupported )
    *(_DWORD *)(MmWriteableSharedUserData + 752) |= 0x200u;
  if ( CmStateSeparationEnabled )
    *(_DWORD *)(MmWriteableSharedUserData + 752) |= 0x400u;
  qword_1410077B8 = KeQueryPerformanceCounter(0).QuadPart;
  memset_0(v114, 0, 0x78u);
  v115 = MmMapLockedRestartPages;
  v116 = MmUnmapLockedRestartPages;
  v117 = KeRemoveEnclavePage;
  v118 = KdPullRemoteFileEx;
  v119 = CmSaveKeyToBuffer;
  v120 = KeIsBugCheckActive;
  v121 = CmOpenKeyForBugCheckRecovery;
  v122 = MiPageToNode;
  v123 = MmGetNextNode;
  v114[0] = 120;
  if ( VslVsmEnabled )
  {
    VslpIumKsrInitContext = (__int64)VslpKsrEnterIumSecureMode;
    v73 = &VslpIumKsrInitContext;
    qword_141007738 = (__int64)VslpRegisterKsrCallback;
  }
  else
  {
    v73 = 0;
  }
  DisplayContext = BgGetDisplayContext(v71, v70, v72, v73);
  v75 = (int)KsrInitSystem(BugCheckParameter3, v114, DisplayContext);
  qword_1410077C0 = KeQueryPerformanceCounter(0).QuadPart;
  if ( (int)(v75 + 0x80000000) >= 0 && (_DWORD)v75 != -1073741637 )
    KeBugCheckEx(0x32u, v75, 0, 1u, 0);
  ExKsrInterface = v124;
  qword_140EFE9E0 = v126;
  xmmword_140EFE9D0 = v125;
  v76 = EmInitSystem(0, BugCheckParameter3);
  if ( v76 < 0 )
    KeBugCheckEx(0x32u, v76, 8u, 0, 0);
  v77 = MfgInitSystem(BugCheckParameter3);
  if ( v77 < 0 )
    KeBugCheckEx(0x32u, v77, 9u, 0, 0);
  PfInitializeSuperfetch();
  v78 = SmInitSystem(0);
  if ( v78 < 0 )
    KeBugCheckEx(0x32u, v78, 0xBu, 0, 0);
  v79 = VmInitSystem(1);
  if ( v79 < 0 )
    KeBugCheckEx(0x32u, v79, 0xAu, 0, 0);
  if ( (*(_BYTE *)(*(_QWORD *)(BugCheckParameter3 + 240) + 2656LL) & 2) == 0 || strstr(v7, "FORCETIMESYNC") )
    ZwUpdateWnfStateData(&WNF_BOOT_INVALID_TIME_SOURCE, 0, 0, 0, 0, 0, 0);
  if ( (HvlpFlags & 0x2000000) != 0 )
    ZwUpdateWnfStateData(&WNF_HVL_CPU_MGMT_PARTITION, 0, 0, 0, 0, 0, 0);
  FsRtlSendModernAppTermination(&v107, 1, 1);
  ExInitializeTimeRefresh();
  ExAcquireTimeRefreshLockExclusive();
  ExInitializeUtcTimeZoneBias(&v106);
  v80 = *(_DWORD *)(v2 + 436);
  ExpRefreshTimeZoneInformation(0);
  ExReleaseTimeRefreshLockExclusive();
  if ( v98 )
  {
    v99 = *(_QWORD *)(*(_QWORD *)(PsGetCurrentServerSiloGlobals() + 1224) + 440LL) + v106.QuadPart;
    KeSetSystemTime(&v99, &v110, 4);
  }
  else if ( v80 != *(_DWORD *)(v2 + 436) )
  {
    ZwSetSystemTime(0, 0);
  }
  if ( !(unsigned __int8)FsRtlInitSystem() )
    KeBugCheck(0x68u);
  ExInitializeNPagedLookasideListInternal(
    (unsigned int)&RtlLznt1DecompressChunkLookaside,
    0,
    0,
    512,
    88,
    1667529324,
    0,
    0);
  _RAX = 1;
  __asm { cpuid }
  x86_cpu_enable_ssse3 = _RCX & 0x200;
  x86_cpu_enable_simd = (_RDX & 0x4000000) != 0 && (_RCX & 0x100002) == 1048578;
  ExInitializePagedLookasideList(&RtlpRangeListEntryLookasideList, 0, 0, 0, 0x38u, 0x656C5252u, 0x10u);
  HvlDebuggerSupportInitialize(BugCheckParameter3);
  HalReportResourceUsage(0);
  KdInitialize(1, BugCheckParameter3, &KdpContext);
  if ( !(unsigned __int8)PpInitSystem() )
    KeBugCheck(0x90u);
  if ( v7 )
  {
    v86 = strstr(v7, "SAFEBOOT:");
    if ( v86 )
    {
      v87 = v86 + 9;
      if ( !strncmp(v86 + 9, "MINIMAL", 7u) )
      {
        LODWORD(InitSafeBootMode) = 1;
      }
      else
      {
        if ( strncmp(v87, "NETWORK", 7u) )
        {
          if ( !strncmp(v87, "DSREPAIR", 8u) )
          {
            v87 += 8;
            LODWORD(InitSafeBootMode) = 3;
          }
          else
          {
            LODWORD(InitSafeBootMode) = 0;
          }
          goto LABEL_193;
        }
        LODWORD(InitSafeBootMode) = 2;
      }
      v87 += 7;
LABEL_193:
      if ( *v87 )
      {
        v88 = strncmp(v87, "(ALTERNATESHELL)", 0x10u);
        v89 = (unsigned __int8)v101;
        if ( !v88 )
          v89 = 1;
        v101 = v89;
      }
      if ( (_DWORD)InitSafeBootMode )
      {
        v100 = 0;
        v90 = 0;
        switch ( (_DWORD)InitSafeBootMode )
        {
          case 1:
            v90 = 168;
            break;
          case 2:
            v90 = 169;
            break;
          case 3:
            v90 = 170;
            break;
        }
        if ( (int)RtlFindMessage(0x40000000u, 11, 0, v90, (__int64)&v100) >= 0 )
          InbvDisplayString(v100 + 4);
      }
    }
  }
  if ( (*(_DWORD *)(*(_QWORD *)(BugCheckParameter3 + 240) + 132LL) & 0x800) != 0 )
  {
    if ( (int)RtlFindMessage(0x40000000u, 11, 0, 183, (__int64)&v102) >= 0 )
      InbvDisplayString(v102 + 4);
    IopInitializeBootLogging(BugCheckParameter3, Pool2 + 256);
  }
  ExpWatchProductTypeInitialization();
  *(_DWORD *)(MmWriteableSharedUserData + 736) = -1;
  BootApplicationPersistentDataProcess(0);
  ExpMicrocodeInitialization(2);
  if ( ExpFreeListCount > (unsigned int)KeMaximumProcessors )
    ExpFreeListCount = KeMaximumProcessors;
  LODWORD(v100) = 0;
  ExpOriginalImageVersion = 0;
  if ( (int)ExpGetOriginalImageVersionRegistryValue(&v100) >= 0 )
    ExpOriginalImageVersion = v100;
  v91 = ExpComputeCyclesPerYield();
  v92 = InitIsWinPEMode == 0;
  *(_WORD *)(MmWriteableSharedUserData + 726) = v91;
  if ( !v92 )
    CreateMiniNtBootKey();
  SymCryptEntropyAccumulatorGlobalInitFromRegistry();
  v93 = SeCodeIntegrityInitializePolicy(BugCheckParameter3);
  if ( v93 < 0 )
    KeBugCheckEx(0x32u, v93, 0x69436553u, 0, 0);
  KdpTimeSlipPending = 0;
  qword_140EFA648 = (__int64)&ExBootDeviceList;
  ExBootDeviceList = (__int64)&ExBootDeviceList;
  ExNumMissingBootDevices = 0;
  ExBootDevicesRemovedEvent.Header.WaitListHead.Blink = &ExBootDevicesRemovedEvent.Header.WaitListHead;
  ExBootDevicesRemovedEvent.Header.WaitListHead.Flink = &ExBootDevicesRemovedEvent.Header.WaitListHead;
  ExExternalBootSupportInitializationEvent.Header.WaitListHead.Blink = &ExExternalBootSupportInitializationEvent.Header.WaitListHead;
  ExExternalBootSupportInitializationEvent.Header.WaitListHead.Flink = &ExExternalBootSupportInitializationEvent.Header.WaitListHead;
  ExBootDeviceRemovalHandler = 0;
  ExBootDeviceListSpinLock = 0;
  LOWORD(ExBootDevicesRemovedEvent.Header.Lock) = 1;
  ExBootDevicesRemovedEvent.Header.Size = 6;
  ExBootDevicesRemovedEvent.Header.SignalState = 0;
  LOWORD(ExExternalBootSupportInitializationEvent.Header.Lock) = 1;
  ExExternalBootSupportInitializationEvent.Header.Size = 6;
  ExExternalBootSupportInitializationEvent.Header.SignalState = 1;
  if ( !(unsigned __int8)PoInitSystem(1, BugCheckParameter3) )
    goto LABEL_220;
  RtlInitFunctionalityCache();
  KeWaitForSingleObject(&stru_140E2FDA8, Executive, 0, 0, 0);
  return v101;
}

```

// --- Called by: Phase1Initialization at 0x1406f3aa0 (Depth: 4) ---
// Language: C/C++
```cpp
void __fastcall Phase1Initialization(ULONG_PTR StartContext)
{
  char v2; // di
  int inited; // eax
  __int64 v4; // rdx

  qword_1410077B0 = KeQueryPerformanceCounter(0).QuadPart;
  v2 = Phase1InitializationDiscard(StartContext);
  InbvSetProgressBarSubset(25);
  inited = IoInitSystem(StartContext);
  if ( inited < 0 )
    KeBugCheckEx(0x69u, (unsigned int)IopInitFailCode, (unsigned int)inited, 0, 0);
  LOBYTE(v4) = v2;
  Phase1InitializationIoReady(StartContext, v4);
  MmEnumerateSystemImages(MiFreeBootDriverInitializationCode, 0);
  byte_140E2D72D = 1;
}

```



--- Callees (Functions this one calls) ---
// --- Calls: SepInitializeCodeIntegrity at 0x1407841fc (Depth: 0) ---
// Language: C/C++
```cpp
__int64 SepInitializeCodeIntegrity()
{
  unsigned int v0; // edi
  __int64 v1; // rcx
  unsigned int *v2; // rdx
  char *v3; // rbx
  char *v4; // rcx
  __int64 v5; // rax
  __int128 v7; // [rsp+30h] [rbp-38h] BYREF
  __int128 v8; // [rsp+40h] [rbp-28h]
  __int64 v9; // [rsp+50h] [rbp-18h]

  v9 = 0;
  v7 = 0;
  v0 = 6;
  v8 = 0;
  memset_0(&unk_140F04704, 0, 0xF4u);
  SeCiCallbacks = 256;
  qword_140F047F8 = 167772176;
  if ( KeLoaderBlock_0 )
  {
    v1 = *(_QWORD *)(KeLoaderBlock_0 + 240);
    if ( v1 )
    {
      v2 = *(unsigned int **)(v1 + 2904);
      if ( v2 )
        v0 = *v2;
    }
    v3 = *(char **)(KeLoaderBlock_0 + 216);
    if ( v3 )
    {
      v4 = strstr(*(const char **)(KeLoaderBlock_0 + 216), "MINTCBIGNOREKD");
      if ( v4 )
      {
        v5 = -1;
        do
          ++v5;
        while ( aMintcbignorekd[v5] );
        if ( (v4 == v3 || *(v4 - 1) == 32) && (v4[(unsigned int)v5] & 0xDF) == 0 )
          SeCiDebugOptions |= 1u;
      }
    }
    *(_QWORD *)&v7 = KeLoaderBlock_0 + 80;
    *((_QWORD *)&v7 + 1) = KeLoaderBlock_0 + 112;
    *(_QWORD *)&v8 = KeLoaderBlock_0 + 64;
    *((_QWORD *)&v8 + 1) = KeLoaderBlock_0 + 96;
    v9 = KeLoaderBlock_0 + 48;
  }
  return CiInitialize(v0, &v7, 5, &SeCiCallbacks, SeCiPrivateApis);
}

```

// --- Calls: memset_0 at 0x1406b7440 (Depth: 1) ---
// Language: C/C++
```cpp
void *__cdecl memset_0(void *a1, int Val, size_t Size)
{
  void *result; // rax
  __int64 v4; // rdx
  __m128 v5; // xmm0
  char *v6; // r8
  __m128 *v7; // rdx
  _OWORD *v8; // r9
  size_t v9; // r8
  __m128 *v10; // r9
  size_t v11; // r8
  _DWORD *v12; // r9
  size_t v13; // r8

  result = a1;
  v4 = 0x101010101010101LL * (unsigned __int8)Val;
  v5 = _mm_movelh_ps((__m128)(unsigned __int64)v4, (__m128)(unsigned __int64)v4);
  if ( Size >= 0x40 )
  {
    if ( (_isa_info & 2) != 0 && Size >= 0x320 )
      return _memset_repmovs();
    *(__m128 *)a1 = v5;
    v6 = (char *)a1 + Size;
    a1 = (void *)(((unsigned __int64)a1 + 16) & 0xFFFFFFFFFFFFFFF0uLL);
    Size = v6 - (_BYTE *)a1;
    if ( Size >= 0x40 )
    {
      v7 = (__m128 *)((char *)a1 + Size - 16);
      v8 = (_OWORD *)(((unsigned __int64)a1 + Size - 48) & 0xFFFFFFFFFFFFFFF0uLL);
      v9 = Size >> 6;
      do
      {
        *(__m128 *)a1 = v5;
        *((__m128 *)a1 + 1) = v5;
        a1 = (char *)a1 + 64;
        --v9;
        *((__m128 *)a1 - 2) = v5;
        *((__m128 *)a1 - 1) = v5;
      }
      while ( v9 );
      *v8 = v5;
      v8[1] = v5;
      v8[2] = v5;
      *v7 = v5;
      return result;
    }
LABEL_9:
    v10 = (__m128 *)((char *)a1 + Size - 16);
    *(__m128 *)a1 = v5;
    v11 = (Size & 0x20) >> 1;
    *v10 = v5;
    *(__m128 *)((char *)a1 + v11) = v5;
    *(__m128 *)((char *)v10 - v11) = v5;
    return result;
  }
  if ( Size >= 0x10 )
    goto LABEL_9;
  if ( Size < 4 )
  {
    if ( Size )
    {
      *(_BYTE *)a1 = v4;
      if ( Size != 1 )
        *(_WORD *)((char *)a1 + Size - 2) = v4;
    }
  }
  else
  {
    v12 = (char *)a1 + Size - 4;
    *(_DWORD *)a1 = v4;
    v13 = (Size & 8) >> 1;
    *v12 = v4;
    *(_DWORD *)((char *)a1 + v13) = v4;
    *(_DWORD *)((char *)v12 - v13) = v4;
  }
  return result;
}

```

// --- Calls: strstr at 0x1404fd260 (Depth: 1) ---
// Language: C/C++
```cpp
char *__cdecl strstr(const char *Str, const char *SubStr)
{
  const char *v2; // r10
  const __m128i *v3; // r8
  int v5; // edi
  __m128i v6; // xmm4
  __m128i v7; // xmm1
  __int64 v8; // rax
  const __m128i *v9; // rdx
  const __m128i *i; // r9
  __m128i v11; // xmm2
  unsigned int v12; // eax
  __int64 v13; // rcx
  __m128i inserted; // xmm0
  char v15; // cl
  __int64 v16; // r9
  char v17; // di
  const char *v18; // rax
  __m128i v19; // xmm1
  unsigned __int8 v20; // cf
  const __m128i *v21; // rdx
  const __m128i *j; // r9
  __m128i v23; // xmm1
  __m128i v24; // xmm2
  unsigned __int8 v25; // sf

  v2 = SubStr;
  v3 = (const __m128i *)Str;
  if ( !*SubStr )
    return (char *)Str;
  if ( (_isa_info & 8) == 0 )
  {
    v5 = *(unsigned __int8 *)SubStr;
    v6 = _mm_shuffle_epi32(_mm_shufflelo_epi16(_mm_cvtsi32_si128(v5 | (unsigned int)(v5 << 8)), 0), 0);
    while ( 1 )
    {
      if ( ((unsigned __int16)v3 & 0xFFFu) > 0xFF0uLL )
        goto LABEL_9;
      v7 = _mm_loadu_si128(v3);
      LODWORD(v8) = _mm_movemask_epi8((__m128i)_mm_or_ps(
                                                 (__m128)_mm_cmpeq_epi8(v7, v6),
                                                 (__m128)_mm_cmpeq_epi8(v7, (__m128i)0LL)));
      if ( (_DWORD)v8 )
      {
        _BitScanForward((unsigned int *)&v8, v8);
        v3 = (const __m128i *)((char *)v3 + v8);
LABEL_9:
        if ( !v3->m128i_i8[0] )
          return 0;
        if ( (_BYTE)v5 == v3->m128i_i8[0] )
        {
          v9 = v3;
          for ( i = (const __m128i *)v2; ; i = (const __m128i *)((char *)i + 1) )
          {
            while ( 2 )
            {
              if ( ((unsigned __int16)i & 0xFFFu) <= 0xFF0uLL && ((unsigned __int16)v9 & 0xFFFu) <= 0xFF0uLL )
              {
                v11 = _mm_loadu_si128(i);
                v12 = _mm_movemask_epi8((__m128i)_mm_or_ps(
                                                   (__m128)_mm_cmpeq_epi8(
                                                             _mm_cmpeq_epi8(v11, _mm_loadu_si128(v9)),
                                                             (__m128i)0LL),
                                                   (__m128)_mm_cmpeq_epi8(v11, (__m128i)0LL)));
                if ( !v12 )
                {
                  ++v9;
                  ++i;
                  continue;
                }
                _BitScanForward((unsigned int *)&v13, v12);
                v9 = (const __m128i *)((char *)v9 + v13);
                i = (const __m128i *)((char *)i + v13);
              }
              break;
            }
            if ( !i->m128i_i8[0] )
              return v3->m128i_i8;
            if ( v9->m128i_i8[0] != i->m128i_i8[0] )
              break;
            v9 = (const __m128i *)((char *)v9 + 1);
          }
        }
        v3 = (const __m128i *)((char *)v3 + 1);
      }
      else
      {
        ++v3;
      }
    }
  }
  if ( ((unsigned __int16)SubStr & 0xFFFu) > 0xFF0uLL )
  {
    v15 = *SubStr;
    inserted = 0;
    v16 = 16;
    do
    {
      v17 = v15;
      inserted = _mm_insert_epi8(_mm_srli_si128(inserted, 1), v15, 15);
      v18 = SubStr + 1;
      if ( v15 )
        v15 = *v18;
      if ( !v17 )
        v18 = SubStr;
      SubStr = v18;
      --v16;
    }
    while ( v16 );
  }
  else
  {
    inserted = _mm_loadu_si128((const __m128i *)SubStr);
  }
  while ( 1 )
  {
    while ( ((unsigned __int16)v3 & 0xFFFu) > 0xFF0uLL )
    {
      if ( !v3->m128i_i8[0] )
        return 0;
      if ( v3->m128i_i8[0] == *v2 )
        goto LABEL_35;
LABEL_43:
      v3 = (const __m128i *)((char *)v3 + 1);
    }
    v19 = _mm_loadu_si128(v3);
    v20 = _mm_cmpistrc(inserted, v19, 12);
    if ( v20 | _mm_cmpistrz(inserted, v19, 12) )
      break;
    ++v3;
  }
  if ( !v20 )
    return 0;
  v3 = (const __m128i *)((char *)v3 + _mm_cmpistri(inserted, v19, 12));
LABEL_35:
  v21 = v3;
  for ( j = (const __m128i *)v2; ; ++j )
  {
    while ( ((unsigned __int16)v21 & 0xFFFu) > 0xFF0uLL || ((unsigned __int16)j & 0xFFFu) > 0xFF0uLL )
    {
      if ( !j->m128i_i8[0] )
        return v3->m128i_i8;
      if ( v21->m128i_i8[0] != j->m128i_i8[0] )
        goto LABEL_43;
      v21 = (const __m128i *)((char *)v21 + 1);
      j = (const __m128i *)((char *)j + 1);
    }
    v23 = _mm_loadu_si128(v21);
    v24 = _mm_loadu_si128(j);
    v25 = _mm_cmpistrs(v24, v23, 12);
    if ( !_mm_cmpistro(v24, v23, 12) )
      goto LABEL_43;
    if ( v25 )
      break;
    ++v21;
  }
  return v3->m128i_i8;
}

```

// --- Calls: __security_check_cookie at 0x14069ce00 (Depth: 1) ---
// Language: C/C++
```cpp
void __cdecl _security_check_cookie(uintptr_t StackCookie)
{
  __int64 v1; // rcx

  if ( StackCookie != _security_cookie )
ReportFailure:
    _report_gsfailure(StackCookie);
  v1 = __ROL8__(StackCookie, 16);
  if ( (_WORD)v1 )
  {
    StackCookie = __ROR8__(v1, 16);
    goto ReportFailure;
  }
}

```



--- Struct Member Usage & Data Cross-References ---
// No struct context could be determined for this function.

--- Decompiler Warnings ---
using guessed type __int64 (__fastcall *SeCiPrivateApis[8])();
using guessed type __int64 __fastcall CiInitialize(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD);
using guessed type int SeCiDebugOptions;
using guessed type int SeCiCallbacks;
using guessed type __int64 qword_140F047F8;
using guessed type __int64 KeLoaderBlock_0;

