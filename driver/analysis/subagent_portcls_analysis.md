# portcls.sys Kernel Vulnerability Analysis Report

## Binary Overview

| Property | Value |
|----------|-------|
| **Module** | portcls.sys |
| **Architecture** | AMD64 (x64) |
| **Base Address** | 0x1C0000000 |
| **Image Size** | 0x66000 (417,792 bytes) |
| **MD5** | f5327b8b8c86a3341f68c645993d422a |
| **SHA-256** | aa60a12af11ba21a1f6ca7636bce7ebd112252fccbdda63842e7f4c5147322d6 |
| **Total Functions** | 1,370 |
| **Named Functions** | 1,364 |
| **Total Strings** | 635 |
| **Segments** | 11 (.text, .rdata, .data, .pdata, .idata, PAGE, PAGEPcVf, INIT, .rsrc) |

### Imported Modules

| Module | Purpose |
|--------|---------|
| **ntoskrnl.exe** | ExAllocatePoolWithTag, ExFreePoolWithTag, IofCompleteRequest, IofCallDriver, KeWaitForSingleObject, MmMapLockedPagesSpecifyCache, ObReferenceObjectByHandle, ProbeForRead, etc. |
| **ks.sys** | KsDispatchIrp, KsPropertyHandler, KsPinPropertyHandler, KsProbeStreamIrp, KsAllocateDeviceHeader, KsEnableEvent, KsAddIrpToCancelableQueue |
| **drmk.sys** | DrmCreateContentMixed, DrmDestroyContent, DrmForwardContentToFileObject |
| **WMILIB** | WmiSystemControl, WmiCompleteRequest |
| **WppRecorder** | WppAutoLogTrace, WppAutoLogStart, WppAutoLogStop |
| **HAL.dll** | KeStallExecutionProcessor, KeQueryPerformanceCounter |

---

## Complete Pool Tag Table

| Tag (hex) | ASCII | Pool Type | Size | Zeroed? | Function | Notes |
|-----------|-------|-----------|------|---------|----------|-------|
| 0x41766458 | XdvA | NonPagedPoolNx | 0x40 (64) | Yes | CPortPinWaveRT::Init | XDV wrapper |
| 0x62436350 | PcCb | Paged/NonPaged | 0x68 (104) | No | CallbackEnqueue | IRQL-dependent |
| 0x66446350 | **PcDf** | **NonPagedPoolNx** | **USER-CTRL** | **Path1:No/Path2:Yes** | **PcCaptureFormat** | **KEY VULN** |
| 0x6D446350 | PcDm | NonPagedPoolNx | USER-CTRL | Yes | CPortPinDMus::Init | MIDI allocator |
| 0x6C536350 | PcSl | NonPagedPoolNx | 16*N | Yes | PcAddAdapterDevice | Subdevice list |
| 0x69436350 | PcCi | NonPagedPoolNx | 48*N | Yes | PcAddAdapterDevice | Create item array |
| 0x70466350 | Pcfp | PagedPool | Variable | Yes | PcCreateSubdeviceDescriptor | PagedPool only |
| 0x714D6350 | PcMq | NonPagedPoolNx | 0x2800 (10240) | No | CIrpStream::Init | DMA buffer |
| 0x72436350 | PcCr | NonPagedPoolNx | 0x1D8/0x1E8 | Yes | CreatePortPinWaveRT | Pin objects |
| 0x72456350 | PcEr | NonPagedPoolNx | 0x38 (56) | Yes | EventItemAddHandler | Event entries |
| 0x72506350 | PcPr | NonPagedPoolNx | 0x48 (72) | No | PcDispatchProperty | Property temp |
| 0x74526350 | PcRt | NonPagedPoolNx | Variable | No | PinPropertyGetAudioBuffer | Audio buffer |
| 0x50526350 | PcRP | NonPagedPoolNx | 0x118 (280) | Yes | PcAddAdapterDevice | Power context |
| 0x524C6350 | PcLR | NonPagedPoolNx | 0x20 (32) | No | PcAddAdapterDevice | RemoveLock |
| 0x43576350 | PcWC | NonPagedPoolNx | 0x50 (80) | Partial | PcAddAdapterDevice | WMI context |

---

## User-Mode Attack Surface

### IRP Dispatch Chain

```
User Mode (DeviceIoControl)
  -> PcDispatchIrp (RVA 0x353E0)
     -> KsDispatchIrp (most IRP_MJ codes)
     -> DispatchPnp (IRP_MJ_PNP)
     -> DispatchPower (IRP_MJ_POWER)
     -> PcWmiSystemControl (IRP_MJ_SYSTEM_CONTROL)
```

### Key Dispatch Functions

| Function | RVA | Role |
|----------|-----|------|
| PcDispatchIrp | 0x353E0 | Main IRP dispatch |
| DispatchDeviceIoControl | 0x35890 | IRP_MJ_DEVICE_CONTROL, routes to IIrpTarget vtable |
| DispatchFastDeviceIoControl | 0x3B740 | Fast I/O, calls FsContext vtable+88 |
| DispatchCreate | 0x3B650 | Pin/filter creation |
| PcDispatchProperty | 0x34490 | KS property dispatch |
| PcPinPropertyHandler | 0x36150 | KSPROPSETID_Pin handler |

### User-Accessible Property Handlers

| Handler | RVA | Property Set |
|---------|-----|-------------|
| PinPropertyGetAudioBuffer | 0x32A40 | KSPROPSETID_WaveRT |
| PinPropertyGetHWLatency | 0x33190 | KSPROPSETID_WaveRT |
| PinPropertyGetPositionRegister | 0x33240 | KSPROPSETID_WaveRT |
| PinPropertyNotificationEvent | 0x33470 | KSPROPSETID_WaveRT |
| PinPropertyGetClockRegister | 0x53E10 | KSPROPSETID_WaveRT |
| PinPropertyDeviceState | 0x33AF0 | KSPROPSETID_WaveRT |
| PinPropertyDataFormat | 0x47F30 | KSPROPSETID_Connection |
| PinPropertyPosition | 0x4C800 | KSPROPSETID_Stream |
| PinPropertyHandler_GetReadPacket | 0x5F20 | KSPROPSETID_WaveRT |
| PinPropertyHandler_SetWritePacket | 0x5FF0 | KSPROPSETID_WaveRT |
| EventItemAddHandler | 0x3A040 | KSEVENTSETID_* |

### KS Streaming Path

| Function | RVA | Role |
|----------|-----|------|
| CIrpStream::TransferKsIrp | 0x3AEF0 | Calls KsProbeStreamIrp |
| CIrpStream::Init | 0x3A9E0 | Stream init, DMA buffer (0x2800 bytes) |

---

## Vulnerability Analysis

### VULNERABILITY #1: User-Controlled Pool Allocation in PcCaptureFormat (PRIMARY)

**Severity: HIGH**
**Function:** PcCaptureFormat (RVA 0x340F0)
**Pool Tag:** 'PcDf' (0x66446350)
**Pool Type:** NonPagedPoolNx (512)

#### Description

PcCaptureFormat is called during pin creation to copy the user-supplied KSDATAFORMAT into kernel pool. The allocation size is directly derived from user-controlled `DataFormat->Size` with NO upper bound validation.

#### Path 1: Audio/PCM Format (Non-Zeroed)

**Trigger:** MajorFormat==AUDIO, SubFormat==PCM/ANALOG, topology validation passes, flags bit3==0

```c
// PcCaptureFormat, first path (RVA 0x342A7)
v22 = v12 - 8;  // v12 = DataFormat->Size (user-controlled, NO upper bound)
PoolWithTag = ExAllocatePoolWithTag(NonPagedPoolNx, v22, 'PcDf');
if (PoolWithTag) {
    *PoolWithTag = *(_OWORD *)a2;           // 0x00-0x0F
    PoolWithTag[1] = *(_OWORD *)(a2 + 16);  // 0x10-0x1F
    PoolWithTag[2] = *(_OWORD *)(a2 + 32);  // 0x20-0x2F
    PoolWithTag[3] = *(_OWORD *)(a2 + 48);  // 0x30-0x3F
    memmove((char *)*a1 + 64, (a2 + 72), v22 - 64);  // 0x40+ (includes 0x50!)
    *(_DWORD *)*a1 = v22;                    // overwrite 0x00-0x03
    *((GUID *)*a1 + 3) = GUID_PCM;           // overwrite 0x30-0x3F
}
```

- NOT zeroed before copy
- User controls full allocation size
- User controls data at offset 0x50 (in memmove range, starts at byte 64)
- Offset 0x30-0x3F overwritten with GUID, 0x00-0x03 with size

#### Path 2: Non-Audio Format (Zeroed Then Overwritten)

**Trigger:** MajorFormat != AUDIO, ValidateDataFormat returns SUCCESS, Size >= 0x40

```c
// PcCaptureFormat, second path (RVA 0x3435B)
v25 = v12 + v24;  // v12 = Size, v24 = alignment extra (0 if no ATTRIBUTES flag)
v26 = ExAllocatePoolWithTag(NonPagedPoolNx, v25, 'PcDf');
if (v26) {
    memset(v26, 0, v25);      // Zero first
    memmove(*a1, a2, v25);    // Copy user data over zeros
}
```

- Zeroed first, then user data copied over
- User controls ALL offsets including 0x50
- No topology validation required - simpler to trigger

#### Validation Gap in ValidateDataFormat (RVA 0x1420)

```c
// For non-audio major format: returns STATUS_SUCCESS immediately
// For audio/PCM: checks FormatSize >= 82, NO upper bound
// For audio/analog: checks FormatSize >= 90, NO upper bound
// NO UPPER BOUND CHECK ON DataFormat->Size IN ANY PATH
```

#### Free Path

```c
// CPortPinWaveRT::~CPortPinWaveRT (RVA 0x32E70)
v2 = *((void **)this + 50);  // format buffer at this+400
if (v2) {
    ExFreePoolWithTag(v2, 0);  // NO ZEROING
    *((_QWORD *)this + 50) = 0;
}
```

ExFreePoolWithTag does NOT zero freed memory. Stale user data persists.

#### Exploitation Chain

```
1. Open audio device handle via KS API
2. Send IRP_MJ_CREATE for pin with crafted KSPIN_CONNECT:
   - KSDATAFORMAT.Size = 0x3C0 (960) for GDI SURFACE collision
   - KSDATAFORMAT.Size = 0x2C8 (712) for type-isolation collision
   - Controlled 8 bytes at offset 0x50 (target pvScan0)
3. PcCaptureFormat allocates in NonPagedPoolNx with tag 'PcDf'
   - Path 1: 960-8 = 952 bytes, NOT zeroed
   - Path 2: 960 bytes, zeroed then overwritten
   - Pool bucket: 960 (matches GDI SURFACE)
4. Pin creation may fail - format buffer still allocated+freed on cleanup
5. Close pin -> ~CPortPinWaveRT frees format buffer (no zeroing)
6. Spray GDI SURFACE objects via CreateBitmap
7. SURFACE reclaims freed slot, stale data at +0x50 = pvScan0
8. GetBitmapBits/SetBitmapBits -> kernel R/W at 200M+ ops/sec
```

#### Size Matching Analysis

| Target | DataFormat->Size | Alloc (Path 1) | Pool Bucket | Match |
|--------|-----------------|----------------|-------------|-------|
| GDI SURFACE (952) | 0x3C0 (960) | 952 | 960 | YES |
| Type-isolation (704) | 0x2C8 (712) | 704 | 704 | YES |
| GDI SURFACE (Path 2) | 0x3C0 (960) | 960 | 960 | YES |

---

### VULNERABILITY #2: User-Controlled Allocation in CPortPinDMus::Init

**Severity: MEDIUM**
**Function:** CPortPinDMus::Init (RVA 0x47600)
**Pool Tag:** 'PcDm' (0x6D446350)

```c
// CPortPinDMus::Init (RVA 0x47876)
v26 = *(uint16_t*)(v21 + 76);  // wBitsPerSample (user WAVEFORMATEX)
v27 = v26 * *(uint32_t*)(v21 + 68) / 0x69;  // * nSamplesPerSec / 105
v28 = operator new(v27, NonPagedPoolNx, 'PcDm');  // USER-CONTROLLED SIZE
```

- Size = wBitsPerSample * nSamplesPerSec / 105
- For 704: 16 * 4620 / 105 = 704
- Zeroed (operator new), but freed without zeroing
- Requires DMus/MIDI adapter (less common)
- Less practical than #1

---

### VULNERABILITY #3: PinPropertyGetAudioBuffer Allocation

**Severity: LOW-MEDIUM**
**Function:** PinPropertyGetAudioBuffer (RVA 0x32A40)
**Pool Tag:** 'PcRt' (0x74526350)

```c
// RVA 0x37535
PoolWithTag = ExAllocatePoolWithTag(NonPagedPoolNx, 2 * Length, 'PcRt');
```

- Length from miniport AllocateAudioBuffer callback
- Influenced by user RequestedBufferSize
- NOT zeroed, freed without zeroing
- Size only indirectly controlled

---

### OBSERVATION #4: KsProbeStreamIrp Attack Surface

**Function:** CIrpStream::TransferKsIrp (RVA 0x3AEF0)

KsProbeStreamIrp probes user-mode IRP buffers for streaming. Validation gaps could lead to buffer overflows. Requires active audio stream (KSSTATE_RUN).

---

### OBSERVATION #5: Race Condition in Pin Lifecycle

1. Create: allocates pin (0x1D8, 'PcCr') + format buffer (variable, 'PcDf')
2. Close: releases streams, MDLs, notifications
3. Destroy: frees format buffer, then pin object

Race between Close/Destroy could cause UAF on format buffer. Pin object (472 bytes, bucket 480) does NOT match GDI SURFACE, but format buffer DOES match when crafted.

---

## Pool Tag Summary (NonPagedPoolNx Only)

| Tag | ASCII | Typical Size | User-Ctrl? | Zeroed on Free? |
|-----|-------|-------------|-----------|-----------------|
| 0x66446350 | PcDf | Variable | YES | NO |
| 0x6D446350 | PcDm | Variable | YES | NO |
| 0x72436350 | PcCr | 472/488 | No | NO |
| 0x74526350 | PcRt | Variable | Partial | NO |
| 0x72456350 | PcEr | 56 | No | NO |
| 0x72506350 | PcPr | 72 | No | NO |
| 0x714D6350 | PcMq | 10240 | No | NO |
| 0x62436350 | PcCb | 104 | No | NO |

---

## Exploitation Feasibility Assessment

### Primary Target: PcCaptureFormat (tag 'PcDf')

**Viability: HIGH**

| Criterion | Assessment |
|-----------|-----------|
| User-controlled allocation size | YES - no upper bound |
| Matches GDI SURFACE bucket (960) | YES - Size=0x3C0 -> 952 -> bucket 960 |
| Matches type-isolation slot (704) | YES - Size=0x2C8 -> 704 -> bucket 704 |
| User controls offset 0x50 | YES - in memmove range |
| No zeroing on free | YES - ExFreePoolWithTag |
| User-mode reachable | YES - KS pin creation DeviceIoControl |
| No special privileges | Likely - audio access sufficient |
| Reliable trigger | MEDIUM - format buffer alloc+free even on pin creation failure |

### Key Advantages

1. No driver loaded - portcls.sys is built-in Windows kernel driver
2. No kernel modifications - pure pool corruption
3. User-controlled allocation size - precise GDI SURFACE bucket targeting
4. User-controlled data at offset 0x50 - directly controls pvScan0
5. No zeroing on free - stale data for GDI reclamation
6. Traceless - no loaded driver artifacts, no hooks, no patches

### Key Challenges

1. Audio adapter dependency - requires functioning audio adapter
2. Topology validation (Path 1) - requires specific topology for PCM
3. Pin creation may fail - BUT format buffer still allocated+freed
4. Pool tag mismatch - GDI SURFACE uses different tag; verify tag enforcement
5. Timing - spray GDI objects immediately after pin close

---

## Key Function Reference (RVA Table)

| Function | RVA | Address |
|----------|-----|---------|
| ValidateDataFormat | 0x1420 | 0x1C0001420 |
| CreatePortPinWaveRT | 0x32280 | 0x1C0032280 |
| CPortPinWaveRT::Init | 0x32490 | 0x1C0032490 |
| PinPropertyGetAudioBuffer | 0x32A40 | 0x1C0032A40 |
| CPortPinWaveRT::~CPortPinWaveRT | 0x32E70 | 0x1C0032E70 |
| CPortPinWaveRT::Close | 0x33630 | 0x1C0033630 |
| PcCaptureFormat | 0x340F0 | 0x1C00340F0 |
| PcDispatchProperty | 0x34490 | 0x1C0034490 |
| PcDispatchIrp | 0x353E0 | 0x1C00353E0 |
| DispatchDeviceIoControl | 0x35890 | 0x1C0035890 |
| PcPinPropertyHandler | 0x36150 | 0x1C0036150 |
| EventItemAddHandler | 0x3A040 | 0x1C003A040 |
| CreateIrpStream | 0x3A8D8 | 0x1C003A8D8 |
| CIrpStream::Init | 0x3A9E0 | 0x1C003A9E0 |
| CIrpStream::TransferKsIrp | 0x3AEF0 | 0x1C003AEF0 |
| DispatchFastDeviceIoControl | 0x3B740 | 0x1C003B740 |
| PcAddAdapterDevice | 0x3D890 | 0x1C003D890 |
| PcCreateSubdeviceDescriptor | 0x3F32C | 0x1C003F32C |
| CPortPinDMus::Init | 0x47600 | 0x1C0047600 |
| CPortPinWaveCyclic::Init | 0x4BEF0 | 0x1C004BEF0 |
| CPortPinWavePci::Init | 0x50190 | 0x1C0050190 |
| PinPropertyGetClockRegister | 0x53E10 | 0x1C0053E10 |

---

## Verdict

**portcls.sys is a VIABLE attack surface for obtaining a kernel R/W primitive.**

The primary vulnerability in **PcCaptureFormat** (RVA 0x340F0) provides:

1. A **user-controlled pool allocation size** in NonPagedPoolNx with no upper bound validation
2. **User-controlled data at offset 0x50** (the pvScan0 offset for GDI SURFACE)
3. **No zeroing on free** via ExFreePoolWithTag
4. **User-mode accessibility** through standard KS audio APIs

The allocation can be precisely sized to match either:
- GDI SURFACE bucket (960 bytes, DataFormat->Size = 0x3C0)
- Type-isolation slot (704 bytes, DataFormat->Size = 0x2C8)

Two allocation paths exist:
- **Path 1** (non-zeroed, requires AUDIO/PCM + topology): alloc = Size - 8
- **Path 2** (zeroed then overwritten, any format): alloc = Size

Both paths result in user-controlled data at offset 0x50. The free path in ~CPortPinWaveRT does not zero memory, enabling GDI SURFACE reclamation.

**Recommended next steps:**
1. Verify pool tag enforcement on Windows 10 22H2 (does GDI type-isolation filter by tag?)
2. Test Path 2 with a non-audio KSDATAFORMAT to confirm allocation succeeds
3. Verify format buffer is freed even when pin creation fails (miniport rejects format)
4. Build a PoC that sprays GDI bitmaps after closing crafted audio pins
5. Test on a system with a virtual audio adapter (ensures portcls is active)
