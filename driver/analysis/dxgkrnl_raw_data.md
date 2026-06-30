# dxgkrnl.sys Raw IDA Data — Win10 22H2 (Build 19045.6456)

**Imagebase:** 0x1C0000000  
**Image Size:** 0x3AC000  
**MD5:** 9416d5f39cdc6708bf9bed5ad63a0c07  
**Total Functions:** 6624 (6592 named, 32 library, 0 unnamed)  
**Total Strings:** 1869  
**Segments:** 12

## Segment Layout
| Segment | Start | End | Size | Permissions |
|---------|-------|-----|------|-------------|
| FLAT | 0x1BFFFFFFF | 0x1C0000000 | 0x1 | --- |
| .text | 0x1C0001000 | 0x1C0071000 | 0x70000 (444KB) | rx |
| .dxgknpd | 0x1C0071000 | 0x1C0072000 | 0x1000 | rw |
| .rdata | 0x1C0072000 | 0x1C00B2000 | 0x40000 (256KB) | r |
| .data | 0x1C00B2000 | 0x1C00B6000 | 0x4000 | rw |
| .pdata | 0x1C00B6000 | 0x1C00D0000 | 0x1A000 | r |
| .idata | 0x1C00D0000 | 0x1C00D1140 | 0x1140 | r |
| .idata | 0x1C00D1140 | 0x1C00D6000 | 0x4EC0 | r |
| NONPAGE | 0x1C00D6000 | 0x1C00D7000 | 0x1000 | rw |
| PAGE | 0x1C00D7000 | 0x1C0303000 | 0x22C000 (2.2MB) | rx |

## Key Imports from ntoskrnl.exe
- PsGetCurrentProcess, PsGetProcessDxgProcess, PsGetCurrentProcessSessionId
- KeStackAttachProcess, KeUnstackDetachProcess
- MmUserProbeAddress (at 0x1C00D0410)
- ExTryAcquirePushLockSharedEx, ExAcquirePushLockSharedEx, ExReleasePushLockSharedEx
- ExAcquirePushLockExclusiveEx, ExTryAcquirePushLockExclusiveEx, ExReleasePushLockExclusiveEx
- ExAcquireResourceExclusiveLite, ExReleaseResourceLite
- ExReleaseRundownProtection
- KeEnterCriticalRegion, KeLeaveCriticalRegion
- KeWaitForSingleObject, KeReadStateEvent
- ObInsertObject, ObCloseHandle, ObfDereferenceObject
- PsGetThreadWin32Thread, PsGetThreadSessionId, PsGetThreadProperty

---

## TIER 1 Functions — Decompiled

### 1. DxgkLock @ 0x1C010DE40 (size 0x586 = 1414 bytes)

```c
// Alternative name is 'DxgkLock'
__int64 __fastcall DxgkLock(struct _D3DKMT_LOCK *a1, __int64 a2, __int64 a3)
{
  bool v4; // r12 — PreviousMode == UserMode
  __int64 CurrentProcess; // rax
  __int64 ProcessDxgProcess; // rax
  struct DXGPROCESS *v7; // rdi
  struct DXGPROCESS *v8; // r8
  struct _D3DKMT_LOCK *v9; // rcx
  struct DXGDEVICE *v10; // rsi
  __int64 v11; // rcx
  int v12; // edi
  struct _KEVENT *v13; // r15
  volatile signed __int64 *v14; // rdi
  __int64 v15; // rcx
  __int64 v16; // r8
  int v17; // esi
  _QWORD *p_pData; // rcx
  _DWORD *p_hAllocation; // rcx
  struct DXGADAPTER *v20; // rdi
  __int64 v21; // rcx
  __int64 v22; // r8
  __int64 v24; // rcx
  unsigned __int8 v25; // di
  __int64 v26; // r8
  struct DXGTHREAD *Current; // rax
  __int64 v28; // rax
  __int64 v29; // rcx
  __int64 v30; // r8
  __int64 v31; // rax
  struct _KEVENT *v32; // rcx
  unsigned __int8 v33; // di
  _QWORD *v34; // rax
  __int64 v35; // rcx
  __int64 v36; // r8
  struct DXGDEVICE *v37; // [rsp+30h] [rbp-178h] BYREF
  struct DXGDEVICE *v38; // [rsp+38h] [rbp-170h] BYREF
  unsigned int v39; // [rsp+40h] [rbp-168h] BYREF
  __int64 v40; // [rsp+48h] [rbp-160h]
  char v41; // [rsp+50h] [rbp-158h]
  struct _D3DKMT_LOCK *v42; // [rsp+58h] [rbp-150h]
  struct _D3DKMT_LOCK v43; // [rsp+60h] [rbp-148h] BYREF
  struct DXGDEVICE *v44; // [rsp+90h] [rbp-118h] BYREF
  int v45; // [rsp+98h] [rbp-110h]
  __int64 v46; // [rsp+B0h] [rbp-F8h] BYREF
  struct DXGADAPTER *v47; // [rsp+B8h] [rbp-F0h]
  char v48; // [rsp+C0h] [rbp-E8h]
  _BYTE v49[8]; // [rsp+D0h] [rbp-D8h] BYREF
  _BYTE v50[16]; // [rsp+D8h] [rbp-D0h] BYREF
  DXGADAPTER *v51; // [rsp+E8h] [rbp-C0h]
  char v52; // [rsp+F0h] [rbp-B8h]
  __int64 v53; // [rsp+F8h] [rbp-B0h]
  _BYTE v54[16]; // [rsp+118h] [rbp-90h] BYREF
  __int64 v55; // [rsp+128h] [rbp-80h]
  __int64 v56; // [rsp+158h] [rbp-50h]
  char v57; // [rsp+160h] [rbp-48h]

  v42 = a1;
  v39 = -1;
  v40 = 0;
  // ETW profiler entry
  if ( (qword_1C00B29B0 & 2) != 0 )
  {
    v41 = 1;
    v39 = 2011;
    if ( (Microsoft_Windows_DxgKrnlEnableBits & 0x2000) != 0 )
      McTemplateK0q_EtwWriteTransfer(a1, &EventProfilerEnter, a3, 2011);
  }
  else
  {
    v41 = 0;
  }
  DXGETWPROFILER_BASE::PushProfilerEntry(&v39, 2011);
  
  // Check PreviousMode
  v4 = (unsigned __int8)PsGetCurrentThreadPreviousMode() == 1; // UserMode
  
  // Get DXG process
  CurrentProcess = PsGetCurrentProcess();
  ProcessDxgProcess = PsGetProcessDxgProcess(CurrentProcess);
  v7 = (struct DXGPROCESS *)ProcessDxgProcess;
  if ( ProcessDxgProcess && (*(_BYTE *)(ProcessDxgProcess + 347) & 0x10) == 0
    || (Current = DXGTHREAD::GetCurrent()) == nullptr
    || (v8 = *((struct DXGPROCESS **)Current + 1)) == nullptr )
  {
    v8 = v7;
    if ( !v7 )
    {
      // ERROR: No DXG process
      v28 = WdLogNewEntry5_WdError();
      *(_QWORD *)(v28 + 24) = -1073741811;
      WdLogEvent5_WdError(v28);
      DXGETWPROFILER_BASE::PopProfilerEntry((DXGETWPROFILER_BASE *)&v39);
      if ( !v41 || (Microsoft_Windows_DxgKrnlEnableBits & 0x2000) == 0 )
        return 3221225485LL; // STATUS_INVALID_PARAMETER
      goto LABEL_63;
    }
  }
  
  // Copy D3DKMT_LOCK from user mode
  memset(&v43, 0, sizeof(v43));
  if ( v4 ) // UserMode
  {
    v9 = a1;
    if ( (unsigned __int64)a1 >= MmUserProbeAddress )
      v9 = (struct _D3DKMT_LOCK *)MmUserProbeAddress;
    v43 = *v9; // Copy struct from usermode
  }
  else
  {
    v43 = *a1; // Kernel mode — direct copy
  }
  
  // Resolve device by handle
  v37 = nullptr;
  DXGDEVICEBYHANDLE::DXGDEVICEBYHANDLE((DXGDEVICEBYHANDLE *)&v38, v43.hDevice, v8, &v37);
  v10 = v37;
  if ( !v37 )
  {
    // ERROR: Invalid device handle
    v31 = WdLogNewEntry5_WdError();
    *(_QWORD *)(v31 + 24) = v43.hDevice;
    *(_QWORD *)(v31 + 32) = -1073741811;
    WdLogEvent5_WdError(v31);
    if ( v38 && _InterlockedExchangeAdd64((volatile signed __int64 *)v38 + 8, 0xFFFFFFFFFFFFFFFFuLL) == 1 )
      ADAPTER_RENDER::DestroyDeviceNoLocks(*((ADAPTER_RENDER **)v38 + 2), v38);
    DXGETWPROFILER_BASE::PopProfilerEntry((DXGETWPROFILER_BASE *)&v39);
    if ( !v41 || (Microsoft_Windows_DxgKrnlEnableBits & 0x2000) == 0 )
      return 3221225485LL;
    goto LABEL_63;
  }
  
  // Check adapter version/flags
  v44 = v37;
  v11 = *(_QWORD *)(*((_QWORD *)v37 + 2) + 16LL);
  if ( *(int *)(v11 + 2328) >= 0x2000 || *(_BYTE *)(v11 + 2628) )
  {
    v12 = *((_DWORD *)DXGGLOBAL::GetGlobal() + 311);
    v45 = v12;
  }
  else
  {
    v12 = 0;
    v45 = 0;
  }
  
  // Wait for device event
  v13 = *((struct _KEVENT **)v10 + 2);
  if ( *((_DWORD *)v10 + 108) == 2 )
  {
    if ( KeReadStateEvent(v13 + 5) )
      goto LABEL_17;
    v32 = v13 + 5;
  }
  else
  {
    if ( KeReadStateEvent(v13 + 4) )
      goto LABEL_17;
    v32 = v13 + 4;
  }
  KeWaitForSingleObject(v32, Executive, 0, 0, nullptr);
  
LABEL_17:
  KeEnterCriticalRegion();
  
  // Acquire device lock (two paths: pushlock or ERESOURCE)
  if ( !v12 )
  {
    if ( ExAcquireResourceExclusiveLite(*((PERESOURCE *)v10 + 17), 0) )
      goto LABEL_19;
    // Block on adapter pushlock, wake from D3
    DXGPUSHLOCK::AcquireShared((DXGPUSHLOCK *)(*(_QWORD *)(*((_QWORD *)v10 + 2) + 16LL) + 104LL));
    v25 = DXGADAPTER::TryWakeUpFromD3State(*(DXGADAPTER **)(*((_QWORD *)v10 + 2) + 16LL));
    if ( bTracingEnabled && (Microsoft_Windows_DxgKrnlEnableBits & 0x40) != 0 )
      McTemplateK0q_EtwWriteTransfer(v24, &EventBlockThread, v26, 40);
    ExAcquireResourceExclusiveLite(*((PERESOURCE *)v10 + 17), 1u);
    if ( !v25 )
      goto LABEL_49;
    goto LABEL_72;
  }
  if ( (unsigned __int8)ExTryAcquirePushLockSharedEx((char *)v10 + 144, 0) )
    goto LABEL_19;
  KeLeaveCriticalRegion();
  DXGPUSHLOCK::AcquireShared((DXGPUSHLOCK *)(*(_QWORD *)(*((_QWORD *)v10 + 2) + 16LL) + 104LL));
  v33 = DXGADAPTER::TryWakeUpFromD3State(*(DXGADAPTER **)(*((_QWORD *)v10 + 2) + 16LL));
  DXGPUSHLOCK::AcquireShared((struct DXGDEVICE *)((char *)v10 + 144));
  if ( v33 )
LABEL_72:
    DXGADAPTER::EnableD3Requests(*(DXGADAPTER **)(*((_QWORD *)v10 + 2) + 16LL));
LABEL_49:
  ExReleasePushLockSharedEx(*(_QWORD *)(*((_QWORD *)v10 + 2) + 16LL) + 104LL, 0);
  KeLeaveCriticalRegion();
  
LABEL_19:
  // Increment adapter reference count
  v14 = *(volatile signed __int64 **)(*((_QWORD *)v10 + 2) + 16LL);
  v47 = (struct DXGADAPTER *)v14;
  _InterlockedIncrement64(v14 + 3);
  v46 = -1;
  
  // Acquire adapter shared pushlock
  KeEnterCriticalRegion();
  ExAcquirePushLockSharedEx(v14 + 17, 0);
  v48 = 1;
  
  // Create COREDEVICEACCESS
  COREDEVICEACCESS::COREDEVICEACCESS(v49, v37, 0);
  
  // Check for critical errors
  if ( v57 )
  {
    COREACCESS::AcquireShared((COREACCESS *)v54, nullptr);
    if ( *(_DWORD *)(v55 + 200) != 1 )
      goto LABEL_80; // Device not accessible
  }
  
  // Wait for adapter thread if not current
  if ( KeGetCurrentThread() != *((struct _KTHREAD **)v51 + 23) )
  {
    if ( !KeReadStateEvent((PRKEVENT)v51 + 2) )
    {
      KeWaitForSingleObject((char *)v51 + 48, Executive, 0, 0, nullptr);
    }
    DXGADAPTER::AcquireCoreResourceShared(v51, nullptr);
  }
  
  v53 = 0;
  v52 = 1;
  
  // Check if device state is ready (state == 1)
  if ( *(_DWORD *)(v56 + 576) == 1 )
  {
    // CALL INNER LOCK IMPLEMENTATION
    v43.hDevice = 0;
    v17 = DXGDEVICE::Lock(v37, &v43, (struct COREDEVICEACCESS *)v49);
    
    if ( v17 >= 0 )
    {
      // WRITE BACK pData AND hAllocation TO USER MODE
      p_pData = &a1->pData;
      if ( v4 ) // UserMode
      {
        if ( (unsigned __int64)p_pData >= MmUserProbeAddress )
          p_pData = (_QWORD *)MmUserProbeAddress;
        *p_pData = v43.pData;      // Write mapped CPU VA to user
        p_hAllocation = &a1->hAllocation;
        if ( (unsigned __int64)&a1->hAllocation >= MmUserProbeAddress )
          p_hAllocation = (_DWORD *)MmUserProbeAddress;
        *p_hAllocation = v43.hAllocation;
      }
      else
      {
        *p_pData = v43.pData;
        a1->hAllocation = v43.hAllocation;
      }
    }
    
    // Cleanup: release adapter ref, device lock
    COREDEVICEACCESS::~COREDEVICEACCESS((COREDEVICEACCESS *)v49);
    v20 = v47;
    ExReleasePushLockSharedEx((char *)v47 + 136, 0);
    KeLeaveCriticalRegion();
    if ( _InterlockedExchangeAdd64((volatile signed __int64 *)v20 + 3, 0xFFFFFFFFFFFFFFFFuLL) == 1 )
      DXGGLOBAL::DestroyAdapter(*((DXGGLOBAL **)v47 + 2), v47);
    if ( v45 )
      ExReleasePushLockSharedEx((char *)v37 + 144, 0);
    else
      ExReleaseResourceLite(*((PERESOURCE *)v37 + 17));
    KeLeaveCriticalRegion();
    if ( v38 && _InterlockedExchangeAdd64((volatile signed __int64 *)v38 + 8, 0xFFFFFFFFFFFFFFFFuLL) == 1 )
      ADAPTER_RENDER::DestroyDeviceNoLocks(*((ADAPTER_RENDER **)v38 + 2), v38);
    DXGETWPROFILER_BASE::PopProfilerEntry((DXGETWPROFILER_BASE *)&v39);
    if ( v41 )
    {
      if ( (Microsoft_Windows_DxgKrnlEnableBits & 0x2000) != 0 )
        McTemplateK0q_EtwWriteTransfer(v21, &EventProfilerExit, v22, v39);
    }
    return (unsigned int)v17;
  }
  
  // Device not ready
  COREACCESS::Release((COREACCESS *)v50);
  if ( v57 )
LABEL_80:
    COREACCESS::Release((COREACCESS *)v54);
  COREDEVICEACCESS::~COREDEVICEACCESS((COREDEVICEACCESS *)v49);
  DXGADAPTERSTOPRESETLOCKSHARED::Release((DXGADAPTERSTOPRESETLOCKSHARED *)&v46);
  DXGDEVICELOCKONAPPROPRIATETHREADMODEL::~DXGDEVICELOCKONAPPROPRIATETHREADMODEL((DXGDEVICELOCKONAPPROPRIATETHREADMODEL *)&v44);
  if ( v38 && _InterlockedExchangeAdd64((volatile signed __int64 *)v38 + 8, 0xFFFFFFFFFFFFFFFFuLL) == 1 )
    ADAPTER_RENDER::DestroyDeviceNoLocks(*((ADAPTER_RENDER **)v38 + 2), v38);
  DXGETWPROFILER_BASE::PopProfilerEntry((DXGETWPROFILER_BASE *)&v39);
  if ( v41 && (Microsoft_Windows_DxgKrnlEnableBits & 0x2000) != 0 )
    McTemplateK0q_EtwWriteTransfer(v35, &EventProfilerExit, v36, v39);
  return 3221226166LL; // STATUS_DEVICE_REMOVED
}
```

**Key observations:**
- DxgkLock copies the D3DKMT_LOCK struct from usermode with MmUserProbeAddress check
- Resolves device handle via DXGDEVICEBYHANDLE
- Acquires multiple locks (device ERESOURCE, adapter pushlock, core resource)
- Calls DXGDEVICE::Lock for the actual allocation lock
- Writes pData (mapped CPU VA) and hAllocation back to usermode with MmUserProbeAddress check
- PreviousMode == UserMode (v4) gates the MmUserProbeAddress probes

---

### 2. DXGDEVICE::Lock @ 0x1C010D860 (inner implementation, size ~0x580)

```c
__int64 __fastcall DXGDEVICE::Lock(DXGDEVICE *this, struct _D3DKMT_LOCK *a2, struct COREDEVICEACCESS *a3)
{
  // Check if virtual GPU (VM bus path)
  if ( (*((_BYTE *)this + 1869) & 1) != 0 )
  {
    // Virtual GPU: send via VmBus
    hAllocation = a2->hAllocation;
    memset(&v73, 0, sizeof(v73));
    v73.hAllocation = hAllocation;
    v55 = *(_QWORD *)(*((_QWORD *)this + 2) + 16LL);
    Current = DXGPROCESS::GetCurrent();
    result = DXG_GUEST_VIRTUALGPU_VMBUS::VmBusSendLock2(
               (DXG_GUEST_VIRTUALGPU_VMBUS *)(v55 + 4240),
               Current, this, &v73, 1u, v71, v72);
    if ( (int)result >= 0 )
      a2->pData = v73.pData;
    return result;
  }
  
  // Parse lock flags from a2->Flags.Value
  Value = a2->Flags.Value;
  v6 = 1;
  v74 = 1;
  
  // Validate flags < 0x800
  if ( *(unsigned int *)&Value >= 0x800 )
    goto LABEL_96; // Invalid flags
  
  while ( 1 )
  {
    // Validate NumPages / pPages consistency
    v7 = a2->NumPages == 0;
    if ( v7 != (a2->pPages == nullptr) )
      goto LABEL_97; // Inconsistent
    
    // Get allocation handle table
    v8 = *((_QWORD *)this + 5); // DXGDEVICE->allocationTable
    v9 = a2->hAllocation;
    
    // Compute lock mode flags from D3DKMT_LOCK flags
    v10 = ((*(_BYTE *)&Value & 4) == 0) | 2;  // Discard
    if ( (*(_BYTE *)&Value & 8) == 0 )
      v10 = (*(_BYTE *)&Value & 4) == 0;       // ReadOnly
    v11 = v10 | 4;                               // DoNotWait
    if ( (*(_BYTE *)&Value & 0x20) == 0 )
      v11 = v10;
    v12 = v11 | 8;                               // NotifyOnly
    if ( (*(_BYTE *)&Value & 0x40) == 0 )
      v12 = v11;
    v13 = v12 | 0x10;                            // Reserve
    if ( *(_BYTE *)&Value >= 0 )
      v13 = v12;
    v14 = v13 | 0x20;                            // NoExistingUpdate
    if ( (*(_WORD *)&Value & 0x100) == 0 )
      v14 = v13;
    v15 = v14 | 0x48;                            // additional flags
    if ( (*(_WORD *)&Value & 0x200) == 0 )
      v15 = v14;
    v16 = v15 | 0x80;
    if ( (*(_WORD *)&Value & 0x400) == 0 )
      v16 = v15;
    v17 = v16 | 0x200;
    if ( (*(_BYTE *)&Value & 1) == 0 )
      v17 = v16;
    
    // Acquire allocation table shared lock
    KeEnterCriticalRegion();
    if ( !(unsigned __int8)ExTryAcquirePushLockSharedEx(v8 + 208, 0) )
    {
      ExAcquirePushLockSharedEx(v8 + 208, 0);
    }
    
    // Look up allocation in handle table
    v20 = (v9 >> 6) & 0xFFFFFF; // Handle index
    if ( (unsigned int)v20 < *(_DWORD *)(v8 + 256) ) // Bounds check
    {
      v21 = *(_QWORD *)(v8 + 240); // Handle table base
      v22 = *(_DWORD *)(v21 + 16 * v20 + 8); // Entry metadata
      // Validate handle type/stamp
      if ( ((v9 >> 25) & 0x60) == (*(_BYTE *)(v21 + 16 * v20 + 8) & 0x60)
        && (v22 & 0x2000) == 0 && (v22 & 0x1F) != 0 )
      {
        v23 = v22 & 0x1F;
        if ( (_BYTE)v23 == 5 ) // Type 5 = allocation
        {
          v24 = *(struct DXGALLOCATION **)(v21 + 16LL * (unsigned int)v20);
          goto LABEL_27;
        }
        // Wrong type
      }
    }
    v24 = nullptr;
    
LABEL_27:
    // Create allocation reference
    DXGALLOCATIONREFERENCE::DXGALLOCATIONREFERENCE((DXGALLOCATIONREFERENCE *)&v76, v24);
    ExReleasePushLockSharedEx(v8 + 208, 0);
    KeLeaveCriticalRegion();
    
    if ( !v76 )
      goto LABEL_81; // No allocation found
    
    Count = v76[3].Count; // Allocation reference count
    if ( !Count )
      goto LABEL_81; // Zero ref count
    
    // Verify allocation belongs to this device
    if ( (DXGDEVICE *)v76[1].Count != this )
      goto LABEL_81; // Wrong device
    
    // Check allocation flags
    if ( (*(_DWORD *)(v76[6].Count + 4) & 2) == 0 )
    {
      // Check for shared/resource allocation
      v27 = v76[5].Count;
      if ( v27 )
      {
        v51 = *(_DWORD *)(v27 + 4);
        if ( (v51 & 1) != 0 && (v51 & 2) == 0 )
        {
          v25 = *(_QWORD *)(*((_QWORD *)this + 2) + 16LL);
          v52 = *(_DWORD *)(v25 + 348);
          if ( (v52 & 0x10) == 0 && (v52 & 8) == 0 )
          {
LABEL_81:
            // Error: invalid allocation
            goto LABEL_41;
          }
        }
      }
    }
    
    // *** THE ACTUAL LOCK CALL ***
    // Calls VidMm interface via function pointer table:
    // this->adapter->VidMmInterface->Lock(allocation, flags, privateData, &pData)
    LODWORD(Count) = (*(__int64 (__fastcall **)(_QWORD, ULONG_PTR, _QWORD, __int64, UINT, _QWORD, void **))
                       (*(_QWORD *)(*(_QWORD *)(*((_QWORD *)this + 2) + 640LL) + 8LL) + 264LL))(
                       *(_QWORD *)(*((_QWORD *)this + 2) + 648LL),  // VidMm context
                       Count,                                        // Allocation handle
                       a2->hAllocation & 0x3F,                      // Sub-allocation index
                       v28,                                         // Lock flags
                       a2->PrivateDriverData,                       // User-supplied private driver data
                       0,
                       &a2->pData);                                 // OUTPUT: mapped CPU VA
    
    // Post-lock: update allocation lock state in handle table
    v29 = (*(__int64 (__fastcall **)(_QWORD, ULONG_PTR))
           (*(_QWORD *)(*(_QWORD *)(*((_QWORD *)this + 2) + 640LL) + 8LL) + 280LL))(
            *(_QWORD *)(*((_QWORD *)this + 2) + 648LL),
            v76[3].Count);
    
    // Update handle table entry with lock state
    v30 = *((_QWORD *)this + 5);
    v31 = v29;
    v32 = a2->hAllocation;
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusiveEx(v30 + 208, 0);
    
    v35 = 0;
    v36 = (v32 >> 6) & 0xFFFFFF;
    *(_QWORD *)(v30 + 216) = KeGetCurrentThread();
    if ( v36 < *(_DWORD *)(v30 + 256) )
    {
      v37 = *(_QWORD *)(v30 + 240);
      v38 = *(_DWORD *)(v37 + 16LL * v36 + 8);
      if ( ((v32 >> 25) & 0x60) == (*(_BYTE *)(v37 + 16LL * v36 + 8) & 0x60)
        && (v38 & 0x2000) == 0 && (v38 & 0x1F) != 0 )
      {
        // Update lock bits in handle entry
        *(_DWORD *)(v37 + 16LL * v36 + 8) = v38 ^ ((unsigned __int16)v38 ^ (unsigned __int16)(v31 << 7)) & 0x1F80;
        v35 = (*(_DWORD *)(*(_QWORD *)(v30 + 240) + 16LL * v36 + 8) >> 7) & 0x3F
            | ((v36 | ((*(_DWORD *)(*(_QWORD *)(v30 + 240) + 16LL * v36 + 8) & 0xFFFFFFE0) << 19)) << 6);
      }
    }
    *(_QWORD *)(v30 + 216) = 0;
    ExReleasePushLockExclusiveEx(v30 + 208, 0);
    KeLeaveCriticalRegion();
    a2->hAllocation = v35;
    
    // Handle STATUS_WAS_LOCKED (retry logic)
    if ( (_DWORD)Count != -1071775484 )
      goto LABEL_41;
    
    // Retry: release core access, call unlock, re-acquire
    COREDEVICEACCESS::Release(a3);
    LODWORD(Count) = (*(...)(... + 616LL))(allocation, hAllocation, 2);
    if ( (Count & 0x80000000) != 0LL )
      goto LABEL_41;
    v53 = COREDEVICEACCESS::AcquireShared(a3, nullptr);
    if ( v53 < 0 )
      break; // Failed to re-acquire
    a2->Flags.Value &= ~0x80u;
    if ( v74 != 1 )
      goto LABEL_41;
    v6 = 2;
    v74 = 2;
    // Loop back to retry the lock
  }
  
  // ... (session/thread property logging, cleanup)
  return (unsigned int)Count;
}
```

**CRITICAL FINDINGS:**
1. The actual memory mapping happens via VidMm interface function pointer table at offset +264 (0x108) from the interface base
2. The function pointer is at: `this->adapter->VidMmInterface[8] + 0x108` — this is the VidMm lock implementation in dxgmms2.sys
3. `a2->PrivateDriverData` is user-supplied and passed directly to the VidMm lock function — potential for crafted private driver data
4. `a2->pData` receives the mapped CPU virtual address — if the VidMm function maps wrong pages, this is our kernel R/W
5. The lock has a retry path (STATUS_WAS_LOCKED = -1071775484) that releases/re-acquires core access — TOCTOU window
6. Handle table lookup uses `(v9 >> 6) & 0xFFFFFF` as index with bounds check against `*(DWORD*)(v8 + 256)`
7. Handle validation checks type bits (0x1F == 5 for allocation), stamp bits (0x60), and 0x2000 flag

---

### 3. DxgkLock2 @ 0x1C010CD80 (size 0x5CB = 1483 bytes)

DxgkLock2 is the newer variant. Key differences from DxgkLock:
- Takes ULONG64 a1 (pointer to D3DKMT_LOCK2 struct)
- Uses DXGPROCESS::GetAllocationSafe instead of manual handle table lookup
- Calls VidMm interface via function pointer at offset +816 (0x330) instead of +264 (0x108)
- Has additional checks for virtual GPU (VmBus path)
- Checks allocation flags: (v55 & 1) != 0 && (v55 & 2) == 0 — not read-only
- Checks adapter flags: (v57 & 0x10) == 0 && (v57 & 8) == 0 && (adapter+2060 & 0x80) == 0
- Writes pData back to usermode at a1+16 with MmUserProbeAddress check
- Uses ExReleaseRundownProtection on the allocation after lock

**Key call in DxgkLock2:**
```c
// Calls VidMm Lock2 via function pointer:
v26 = (*(__int64 (__fastcall **)(_QWORD, _QWORD, _QWORD, PVOID *, int))
       (*(_QWORD *)(v21[80] + 8LL) + 816LL))(
       v21[81],           // VidMm context
       *((_QWORD *)v70 + 3), // allocation internal handle
       0,
       &v9->pData,        // OUTPUT: mapped CPU VA
       Timeout);
```

---

### 4. DxgkUnlock @ 0x1C0153E60 (size 0x38F = 911 bytes)

Calls DXGDEVICE::Unlock @ 0x1C0154200. Standard unlock path — releases the CPU VA mapping. 

---

### 5. DxgkUnlock2 @ 0x1C010D360 (size 0x4EF = 1263 bytes)

Newer unlock. Calls VidMm Unlock2 via function pointer at offset +824 (0x338):
```c
v23 = (*(__int64 (__fastcall **)(_QWORD, _QWORD))
       (*(_QWORD *)(*(_QWORD *)(*((_QWORD *)v10 + 2) + 640LL) + 8LL) + 824LL))(
       *(_QWORD *)(*((_QWORD *)v10 + 2) + 648LL),  // VidMm context
       *((_QWORD *)v19 + 3));                         // allocation internal handle
```

Also has VmBus path for virtual GPUs.

**Additional feature in Unlock2:** Checks for displayed primary surface and calls UpdateDodFrontBuffer — potential for information about which allocation is being displayed.

---

### 6. DxgkDestroyAllocation @ 0x1C0116BB0 (size 0x1C8 = 456 bytes)

```c
__int64 __fastcall DxgkDestroyAllocation(ULONG64 a1)
{
  // Copy D3DKMT_DESTROYALLOCATION struct from usermode
  if ( a1 >= MmUserProbeAddress )
    a1 = MmUserProbeAddress;
  *(_OWORD *)v19 = *(_OWORD *)a1;      // hDevice, phAllocation (first 16 bytes)
  *(_QWORD *)v20 = *(_QWORD *)(a1 + 16); // Flags
  
  // Call helper
  v10 = DxgkDestroyAllocationHelper(
          v9,            // DXGPROCESS
          (unsigned int)v19[0],    // hDevice
          HIDWORD(v19[0]),         // phAllocation count?
          v19[1],                  // phAllocation array
          v20[0],                  // Flags
          0,                       // flags2 = 0 (legacy path)
          v21,                     // scenario context
          1);                      // bLockHeld = 1
  return v10;
}
```

**Note:** DxgkDestroyAllocation passes bLockHeld=1 (assumes lock already held), while DxgkDestroyAllocation2 passes the actual PreviousMode flag.

---

### 7. DxgkDestroyAllocation2 @ 0x1C0116950 (size 0x25A = 602 bytes)

Newer variant. Key difference: validates Flags bits:
```c
if ( (v27[1] & 0x7FFFFFFC) != 0 )  // Only bits 0 and 31 are valid
{
  // Invalid flags — return error
  return 3221225485LL;
}
```

Then calls same DxgkDestroyAllocationHelper with the actual PreviousMode (v4) instead of hardcoded 1.

---

### 8. DxgkCreateAllocation @ 0x1C015DAA0 (size 0x31 = 49 bytes — tiny stub)

```c
__int64 __fastcall DxgkCreateAllocation(struct _D3DKMT_CREATEALLOCATION *a1)
{
  AllocationInternal = DxgkCreateAllocationInternal(a1, nullptr);
  v2 = AllocationInternal;
  if ( (AllocationInternal == -1071775488 || AllocationInternal == -1073741801)
    && (unsigned __int8)PsGetCurrentThreadPreviousMode() == 1 )
  {
    Win32kImportTable = DxgkGetWin32kImportTable();
    if ( (*Win32kImportTable)() )
    {
      if ( byte_1C00B2FF6 )
      {
        DxgCreateLiveDumpWithWdLogs(0x193u, 0x80Fu, v2, 0, 0, 0);
        byte_1C00B2FF6 = 0;
      }
    }
  }
  return (unsigned int)v2;
}
```

Just a wrapper that calls DxgkCreateAllocationInternal @ 0x1C00FAFE0. The live dump is triggered on specific error codes (STATUS_DEVICE_REMOVED or STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT).

---

### 9. DxgkShareObjectsInternal @ 0x1C012BF60 (size 0x421 = 1057 bytes)

Handles sharing of GPU objects across processes. Key paths:
- Entry type 4: Shared resource (allocations) — calls CreateSharedResourceNtObject
- Entry type 8/0xB: Sync objects — calls CreateSharedSyncNtObject
- Entry type 0xE: Protected session — calls CreateSharedProtectedSessionNtObject

**Handle table lookup in ShareObjects:**
```c
v18 = ((unsigned int)v16 >> 6) & 0xFFFFFF;  // Handle index
if ( v18 < *((_DWORD *)v17 + 4) )            // Bounds check
{
  v36 = *(_DWORD *)(*(_QWORD *)v17 + 16LL * v18 + 8);  // Entry metadata
  if ( (unsigned int)v16 >> 30 == ((v36 >> 5) & 3)     // Stamp check
    && (v36 & 0x2000) == 0                               // Not zombie
    && (v36 & 0x1F) != 0 )                               // Not free
  {
    EntryType = HMGRTABLE::GetEntryType(v17);
  }
}
```

Uses KeStackAttachProcess/KeUnstackDetachProcess for cross-process handle insertion via ObInsertObject.

---

### 10. DxgkMapGpuVirtualAddress @ 0x1C01598D0 (size 0x61E = 1566 bytes)

Found but not yet decompiled. This is a TIER 3 target for GPU VA mapping bugs.

### 11. DxgkReserveGpuVirtualAddress @ 0x1C0175410 (size 0x44E = 1102 bytes)

Found but not yet decompiled. TIER 3 target.

---

## OpenResource Functions Found

| Function | Address | Size | Notes |
|----------|---------|------|-------|
| DxgkOpenResource | 0x1C015DAE0 | 0x128 | Wrapper |
| DxgkOpenResourceFromNtHandle | 0x1C012B660 | 0x37B | Handle-based open |
| OpenResourceObject (DXGDEVICE) | 0x1C00D7CBC | 0xE90 | Inner resource open |
| OpenResourceFromGlobalHandleOrNtObject<D3DKMT_OPENRESOURCE> | 0x1C012335C | 0x850 | Template instantiation |
| OpenResource<D3DKMT_OPENRESOURCE> (DXGDEVICE) | 0x1C0123BB4 | 0x406 | Resource open |
| OpenResourceFromGlobalHandleOrNtObject<D3DKMT_OPENRESOURCEFROMNTHANDLE> | 0x1C012ABD4 | 0x72A | NtHandle open |
| OpenResource<D3DKMT_OPENRESOURCEFROMNTHANDLE> (DXGDEVICE) | 0x1C012B320 | 0x338 | NtHandle resource open |
| OpenResourceFromSharedHandle (DXGCONTEXT) | 0x1C0282348 | 0x64B | Shared handle open |

---

## Key Data Structures (Inferred from Decompilation)

### D3DKMT_LOCK (usermode input struct)
```
Offset  Field                Type
0x00    hDevice              D3DKMT_HANDLE (UINT)
0x04    hAllocation          D3DKMT_HANDLE (UINT)
0x08    PrivateDriverData    UINT
0x0C    NumPages             UINT
0x10    pPages               UINT*
0x18    Flags                D3DKMT_LOCKFLAGS (bitfield)
0x1C    pData                void* (OUTPUT: mapped CPU VA)
```

### D3DKMT_LOCK2 (usermode input struct)
```
Offset  Field                Type
0x00    hDevice              D3DKMT_HANDLE (UINT)
0x04    hAllocation          D3DKMT_HANDLE (UINT)
0x10    pData                void* (OUTPUT: mapped CPU VA)
...     Flags                D3DKMT_LOCK2FLAGS
```

### DXGDEVICE (kernel object, inferred from access patterns)
```
Offset  Field                          Access Pattern
+0x00   vtable / type                  *(this)
+0x10   adapter (DXGADAPTER*)          *((QWORD*)this + 2)
+0x10   adapter+0x10: DXGADAPTER       *(QWORD*)(adapter + 16)
+0x10   adapter+0x280: version         *(int*)(adapter + 2328)
+0x10   adapter+0xA44: flags           *(BYTE*)(adapter + 2628)
+0x28   allocationTable                *((QWORD*)this + 5)
+0x28   allocTable+0xD0: lock          (pushlock at v8 + 208)
+0x28   allocTable+0xF0: handleTable   *(QWORD*)(v8 + 240)
+0x28   allocTable+0x100: count        *(DWORD*)(v8 + 256)
+0x28   allocTable+0xD8: lockThread    *(QWORD*)(v30 + 216)
+0x1B0  deviceLock (ERESOURCE*)        *((PERESOURCE*)this + 17)
+0x1B0  deviceLock (pushlock)          (char*)this + 144
+0x1B0  deviceType                     *((DWORD*)this + 108)  // 2 = type 2
+0x749  flags byte                     *((BYTE*)this + 1869)
```

### DXGALLOCATION (kernel object, inferred)
```
Offset  Field                          Access Pattern
+0x00   ??                             *(allocation)
+0x08   ownerDevice (DXGDEVICE*)       *((QWORD*)alloc + 1)
+0x10   ownerAdapter                   *(QWORD*)(device[1][2] + 16)
+0x18   internalHandle                 *((QWORD*)alloc + 3)
+0x28   resourceInfo                   *((QWORD*)alloc + 5)
+0x28   resourceInfo+0x04: flags       *(DWORD*)(resInfo + 4)
+0x30   ??                             allocation[6] (Count)
+0x30   +0x04: flags                   *(DWORD*)(alloc[6].Count + 4)
+0x58   rundownRef                     (EX_RUNDOWN_REF at alloc + 11*8 = +0x58)
```

### VidMm Interface (function pointer table)
```
Accessed via:
  adapter = *(QWORD*)(device + 0x10) + 0x10  // DXGADAPTER
  vidMmInterface = *(QWORD*)(adapter + 640)   // adapter + 0x280
  vidMmContext = *(QWORD*)(adapter + 648)     // adapter + 0x288
  
  Lock  = funcptr at *(QWORD*)(vidMmInterface[1] + 0x108)  // offset +264
  Lock2 = funcptr at *(QWORD*)(vidMmInterface[1] + 0x330)  // offset +816
  Unlock2 = funcptr at *(QWORD*)(vidMmInterface[1] + 0x338) // offset +824
  RetryUnlock = funcptr at offset +616 (0x268)
```

### Handle Table Entry (16 bytes each)
```
Offset  Field          Size  Notes
0x00    object pointer  8     DXGALLOCATION* / DXGSYNCOBJECT* / etc.
0x08    metadata        4     bits 0-4: type (5=allocation, 8=sync, 9=keyedmutex, 0xB=sync2, 0xE=protected)
                                 bits 5-6: stamp (matches handle bits 30-31)
                                 bit 13: zombie flag (0x2000)
                                 bits 7-12: lock state (set by lock, cleared by unlock)
```

---

## Vulnerability Hypothesis Summary

### H1: TOCTOU in DXGDEVICE::Lock retry path
The lock function has a retry loop (while(1)) that:
1. Looks up allocation from handle table (shared lock)
2. Creates allocation reference
3. Calls VidMm lock (which maps pages)
4. If STATUS_WAS_LOCKED: releases core access, calls unlock, re-acquires, loops

Between the unlock and re-acquire, another thread could destroy the allocation. The handle table lookup at the top of the loop would find a stale/freed entry.

**Window:** Between COREDEVICEACCESS::Release(a3) and COREDEVICEACCESS::AcquireShared(a3) in the retry path.

### H2: User-supplied PrivateDriverData passed to VidMm
`a2->PrivateDriverData` (offset 0x08 in D3DKMT_LOCK) is a UINT value passed directly from usermode to the VidMm lock function. If VidMm interprets this as a pointer or uses it for size calculations, crafted values could cause OOB.

### H3: Handle table race in DxgkLock vs DxgkDestroyAllocation
DxgkLock reads the handle table under a shared pushlock. DxgkDestroyAllocationHelper likely writes to the handle table under an exclusive lock. If there's a window where:
1. Thread A (Lock): reads handle entry, gets allocation pointer
2. Thread B (Destroy): destroys allocation, frees memory
3. Thread A (Lock): uses stale allocation pointer

The shared lock should prevent this, but the retry path releases locks between iterations.

### H4: Allocation reference count TOCTOU
After getting the allocation reference (DXGALLOCATIONREFERENCE), the code checks `v76[3].Count` (reference count). If this is not atomically linked to the rundown protection, a race could exist.

### H5: DxgkLock2 GetAllocationSafe + rundown protection gap
DxgkLock2 uses DXGPROCESS::GetAllocationSafe then ExReleaseRundownProtection after the lock. If the allocation is destroyed between GetAllocationSafe and the VidMm lock call, the VidMm function operates on a freed allocation.

### H6: VidMm function pointer table corruption
The VidMm interface is accessed via:
```
vidMmInterface = *(QWORD*)(adapter + 640)  // adapter + 0x280
```
If adapter+0x280 can be corrupted (e.g., via UAF on the adapter object), we control the function pointer table, potentially redirecting the lock call to our code.

### H7: Type confusion in ShareObjects
DxgkShareObjectsInternal checks entry type (4, 8, 0xB, 0xE) but the handle validation only checks `(v36 & 0x1F) != 0`. If there's a way to change the entry type after the check but before use (e.g., via handle table race), we could trigger type confusion.

---

## What Still Needs to Be Decompiled

1. **DxgkDestroyAllocationHelper** @ 0x1C0115E10 — the actual destroy logic, critical for UAF analysis
2. **DxgkCreateAllocationInternal** @ 0x1C00FAFE0 — allocation creation, size validation
3. **DXGDEVICE::Unlock** @ 0x1C0154200 — unlock path, race analysis
4. **DxgkMapGpuVirtualAddress** @ 0x1C01598D0 — GPU VA mapping bugs
5. **DxgkReserveGpuVirtualAddress** @ 0x1C0175410 — VA reservation bugs
6. **OpenResourceObject** @ 0x1C00D7CBC — resource opening, type confusion
7. **VidMm interface functions in dxgmms2.sys** — the actual lock/map implementations

## No CreateDCFromMemory Found in dxgkrnl.sys

`D3DKMTCreateDCFromMemory` was not found as a function in dxgkrnl.sys. It is likely implemented in win32kfull.sys or win32kbase.sys as a GDI operation, not dispatched through dxgkrnl. This path should be analyzed separately in the win32k modules.
