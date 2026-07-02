# KsCreatePin ERROR_INVALID_PARAMETER (0x57) Analysis

## Summary

KsCreatePin returns ERROR_INVALID_PARAMETER (0x57 / Win32 87) when one of several validation checks fails in `ks.sys` or `portcls.sys`. The Win32 error 0x57 is the user-mode mapping of kernel NTSTATUS `0xC000000D` (STATUS_INVALID_PARAMETER), returned by `KspValidateDataFormat` when the KSDATAFORMAT structure is too small or its FormatSize field is invalid. Additional KS-specific NTSTATUS codes (0xC00000EF through 0xC00000F4) may also propagate as ERROR_INVALID_PARAMETER through `RtlNtStatusToDosError`.

## IDA Instances

- **ks.sys**: PID 17220, port 13347, imagebase 0x1C0000000
- **portcls.sys**: PID 19352, port 13348, imagebase 0x1C0000000

## Key Functions Analyzed

### ks.sys

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| KsCreatePin | 0x1C0042B70 | 0x42 | User-mode API entry: builds path and calls IoCreateFile |
| KsiCreateObjectType | 0x1C0044DC0 | 0x1BB | Builds object path, calls IoCreateFile |
| KsDispatchIrp | 0x1C002BF60 | 0x1B5 | IRP dispatch: routes IRP_MJ_CREATE to DispatchCreate |
| DispatchCreate | 0x1C002C120 | 0x543 | Finds create item by name, calls dispatch |
| CKsFilter::DispatchCreatePin | 0x1C00370A0 | 0x18E | Pin create handler: calls KspValidateConnectRequest then KspCreatePin |
| KsValidateConnectRequest | 0x1C0037240 | 0x68 | Public wrapper: calls KspValidateConnectRequest then KspValidateDataFormat |
| KspValidateConnectRequest | 0x1C00372B0 | 0x171 | Internal: validates KSPIN_CONNECT fields against pin descriptor |
| KspValidateDataFormat | 0x1C0034A04 | 0x2B0 | Internal: validates KSDATAFORMAT fields and matches against data ranges |
| KsiCopyCreateParameter | 0x1C0037428 | 0xFA | Extracts create parameter buffer from IRP file object name |
| KspCreatePin | 0x1C0037528 | 0x155 | Allocates CKsPin, calls CKsPin::Init |
| AttributeIntersection | 0x1C0034CC0 | 0x151 | Matches attributes between data format and data range |

### portcls.sys

| Function | Address | Size | Purpose |
|----------|---------|------|---------|
| PcDispatchIrp | 0x1C00353E0 | 0x220 | Portcls IRP dispatch: routes to KsDispatchIrp for KS objects |
| DispatchCreate | 0x1C003B650 | 0xE9 | Portcls create dispatch: calls KsDispatchIrp |
| xDispatchCreate | 0x1C0035600 | 0x181 | IIrpTargetFactory create: calls factory's CreateNewPort |
| PcCaptureFormat | 0x1C00340F0 | 0x326 | Captures and validates data format for portcls pins |
| ValidateDataFormat | 0x1C0001420 | 0x8C | Validates KSDATAFORMAT for audio-specific formats |
| PcValidateDataFormat | 0x1C000C220 | 0x3C | Wrapper: calls ValidateDataFormat then PropertyItemPropertyHandler |

## KSPIN_CONNECT Structure Layout (x64)

Total size: **72 bytes (0x48)**

```
Offset  Size  Field                          Validation
------  ----  -----                          ----------
0       16    Interface.Set (GUID)            Must match descriptor or StandardPinInterfaces
16      4     Interface.Id (ULONG)            Must match descriptor entry Id
20      4     Interface.Flags (ULONG)         MUST BE 0 (else 0xC00000EF)
24      16    Medium.Set (GUID)               Must match descriptor or StandardPinMediums
40      4     Medium.Id (ULONG)               Must match descriptor entry Id
44      4     Medium.Flags (ULONG)            MUST BE 0 (else 0xC00000F0)
48      4     PinId (ULONG)                   Must be < DescriptorsCount (else 0xC00000F1)
52      4     (alignment padding)             --
56      8     PinToHandle (HANDLE)            NULL=sink(5), non-NULL=both(2); AND descriptor (else 0xC00000F2)
64      4     Priority.Class (ULONG)          MUST BE non-zero (else 0xC00000F3)
68      4     Priority.SubLevel (ULONG)       MUST BE non-zero (else 0xC00000F3)
```

## KSDATAFORMAT Structure Layout (follows KSPIN_CONNECT at offset 72)

Minimum size: **64 bytes (0x40)**

```
Offset  Size  Field                          Validation
------  ----  -----                          ----------
0       4     FormatSize (ULONG)             Must be >= 0x40 and <= remaining buffer (else 0xC000000D)
4       4     Flags (ULONG)                  Bit 1 (0x2) = KSDATAFORMAT_ATTRIBUTES
8       4     SampleSize (ULONG)             Not directly validated
12      4     Reserved (ULONG)               MUST BE 0 (else 0xC00000F4)
16      16    MajorFormat (GUID)             Must NOT be GUID_NULL (else 0xC00000F4)
32      16    SubFormat (GUID)               Must NOT be GUID_NULL (else 0xC00000F4)
48      16    Specifier (GUID)               Must NOT be GUID_NULL (else 0xC00000F4)
```

## GUID Constants

### ks.sys

| Name | GUID | Address |
|------|------|---------|
| GUID_NULL | {00000000-0000-0000-0000-000000000000} | 0x1C0028040 |
| KSDATAFORMAT_SPECIFIER_NONE | {0F6417D6-C318-11D0-A43F-00A0C9223196} | 0x1C0028070 |
| KSSTRING_Pin (ObjectType) | {146F1A80-4791-11D0-A5D6-28DB04C10000} | 0x1C006D870 |
| StandardPinInterfaces[0] Set | {1A8766A0-62CE-11CF-A5D6-28DB04C10000} | 0x1C006D148 |
| StandardPinInterfaces[0] Id | 0 | 0x1C006D158 |
| StandardPinMediums[0] Set | {4747B320-62CE-11CF-A5D6-28DB04C10000} | 0x1C006D160 |
| StandardPinMediums[0] Id | 0 | 0x1C006D170 |

### portcls.sys

| Name | GUID | Address |
|------|------|---------|
| KSDATAFORMAT_TYPE_AUDIO | {73647561-0000-0010-8000-00AA00389B71} | 0x1C001F010 |
| KSDATAFORMAT_SPECIFIER_WAVEFORMATEX | {05589F81-C356-11CE-BF01-00AA0055595A} | 0x1C001F000 |
| KSDATAFORMAT_SPECIFIER_DSOUND | {518590A2-A184-11D0-8522-00C04FD9BAF3} | 0x1C001F0B8 |

## Complete Validation Check Sequence

IRP_MJ_CREATE path: KsCreatePin -> KsiCreateObjectType -> IoCreateFile -> IRP_MJ_CREATE -> PcDispatchIrp -> KsDispatchIrp -> DispatchCreate -> CKsFilter::DispatchCreatePin -> KspValidateConnectRequest -> KspValidateDataFormat

### Phase 1: Buffer Extraction (KsiCopyCreateParameter)

**CHECK 1**: Total buffer size >= 136 bytes (0x88 = KSPIN_CONNECT 72 + KSDATAFORMAT min 64)
- Function: KsiCopyCreateParameter at 0x1C0037428
- Code: `*a6 = 136` (sets expected minimum), then checks IRP input buffer length
- Fail: **0xC0000206** (STATUS_INVALID_BUFFER_SIZE)

### Phase 2: KSPIN_CONNECT Validation (KspValidateConnectRequest)

**CHECK 2**: PinId < DescriptorsCount
- Offset 48 in KSPIN_CONNECT
- Code: `v11 = *(_DWORD *)(*a5 + 48); if (v11 >= a2) return 0xC00000F1`
- Fail: **0xC00000F1**

**CHECK 3**: Communication flag compatible with descriptor
- Offset 56 in KSPIN_CONNECT (PinToHandle)
- Code: `if ((*(_QWORD *)(v10 + 56) != 0 ? 2 : 5) & *(_DWORD *)(v12 + 52)) == 0`
- Rule: PinToHandle=NULL needs KSPIN_COMMUNICATION_SINK(5) in descriptor; non-NULL needs BOTH(2)
- Fail: **0xC00000F2**

**CHECK 4**: Interface.Flags == 0
- Offset 20 in KSPIN_CONNECT
- Code: `if (*(_DWORD *)(v10 + 20)) return 0xC00000EF`
- Fail: **0xC00000EF**

**CHECK 5**: Priority.Class != 0 AND Priority.SubLevel != 0
- Offsets 64 and 68 in KSPIN_CONNECT
- Code: `if (*(_DWORD *)(v10 + 64) && *(_DWORD *)(v10 + 68))` -> proceed; else fail
- **CRITICAL**: Both fields must be non-zero. Priority.SubLevel=0 is a common mistake.
- Fail: **0xC00000F3**

**CHECK 6**: Interface.Set GUID + Id match descriptor or standard
- Offsets 0-19 in KSPIN_CONNECT (Set GUID at 0, Id at 16)
- If descriptor has interfaces: searches descriptor array
- If descriptor has none: uses StandardPinInterfaces (1 entry: {1A8766A0-...}, Id=0)
- Compares: GUID (16 bytes) and Id (4 bytes)
- Fail: **0xC0000272**

**CHECK 7**: Medium.Flags == 0
- Offset 44 in KSPIN_CONNECT
- Fail: **0xC00000F0**

**CHECK 8**: Medium.Set GUID + Id match descriptor or standard
- Offsets 24-43 in KSPIN_CONNECT (Set GUID at 24, Id at 40)
- If descriptor has mediums: searches descriptor array
- If descriptor has none: uses StandardPinMediums (1 entry: {4747B320-...}, Id=0)
- Fail: **0xC0000272**

### Phase 3: KSDATAFORMAT Validation (KspValidateDataFormat)

**CHECK 9**: KSDATAFORMAT buffer size >= 64 (0x40)
- Code: `if (a3 < 0x40) return 0xC000000D`
- Fail: **0xC000000D** (STATUS_INVALID_PARAMETER) -> **ERROR_INVALID_PARAMETER (0x57)**

**CHECK 10**: KSDATAFORMAT.FormatSize >= 64 and <= buffer size
- Offset 0 in KSDATAFORMAT
- Code: `v8 = *(_DWORD *)a2; if (v8 < 0x40 || v8 > a3) return 0xC000000D`
- Fail: **0xC000000D** (STATUS_INVALID_PARAMETER) -> **ERROR_INVALID_PARAMETER (0x57)**

**CHECK 11**: KSDATAFORMAT.Reserved == 0
- Offset 12 in KSDATAFORMAT
- Fail: **0xC00000F4**

**CHECK 12**: MajorFormat != GUID_NULL
- Offset 16 in KSDATAFORMAT
- Fail: **0xC00000F4**

**CHECK 13**: SubFormat != GUID_NULL
- Offset 32 in KSDATAFORMAT
- Fail: **0xC00000F4**

**CHECK 14**: Specifier != GUID_NULL
- Offset 48 in KSDATAFORMAT
- Fail: **0xC00000F4**

**CHECK 15**: Specifier != KSDATAFORMAT_SPECIFIER_NONE when FormatSize != 64
- Fail: **0xC00000F4**

**CHECK 16**: KSDATAFORMAT attributes validation (if Flags & 0x2)
- At aligned offset (FormatSize + 7) & ~7:
  - Buffer must have >= aligned_offset + 8 bytes
  - KSMULTIPLE_ITEM.Count must equal remaining size
  - Each attribute: Size >= 0x18, Size <= remaining, Flags == 0
- Fail: **0xC000000D** (STATUS_INVALID_PARAMETER) -> **ERROR_INVALID_PARAMETER (0x57)**

**CHECK 17**: Data format matches descriptor data ranges
- Iterates descriptor data range array
- Compares MajorFormat, SubFormat, Specifier GUIDs (with GUID_NULL wildcard)
- Calls AttributeIntersection for attribute matching
- Fail: **STATUS_NO_MATCH (0xC0000222)**

### Phase 4: portcls.sys Validation (PcCaptureFormat / ValidateDataFormat)

**CHECK 18**: MajorFormat == KSDATAFORMAT_TYPE_AUDIO
- {73647561-0000-0010-8000-00AA00389B71}
- Fail: **0xC0000010** (STATUS_INVALID_DEVICE_REQUEST)

**CHECK 19**: Specifier == WAVEFORMATEX or DSOUND
- WAVEFORMATEX: {05589F81-C356-11CE-BF01-00AA0055595A}
- DSOUND: {518590A2-A184-11D0-8522-00C04FD9BAF3}
- Fail: returns 0 (no match)

**CHECK 20**: FormatSize >= specifier minimum
- WAVEFORMATEX: FormatSize >= 82 (0x52)
- DSOUND: FormatSize >= 90 (0x5A)
- Fail: **0xC0000010** (STATUS_INVALID_DEVICE_REQUEST)

**CHECK 21**: WAVEFORMATEX validation
- wFormatTag != 0xFFFE or if 0xFFFE, cbSize >= 0x16
- Fail: **0xC0000010** (STATUS_INVALID_DEVICE_REQUEST)

## NTSTATUS to Win32 Error Mapping

| NTSTATUS | Value | Win32 Error | Win32 Code |
|----------|-------|-------------|------------|
| STATUS_INVALID_PARAMETER | 0xC000000D | ERROR_INVALID_PARAMETER | 0x57 (87) |
| STATUS_INVALID_BUFFER_SIZE | 0xC0000206 | ERROR_INVALID_PARAMETER | 0x57 (87) |
| STATUS_INVALID_DEVICE_REQUEST | 0xC0000010 | ERROR_INVALID_FUNCTION | 0x1 (1) |
| STATUS_BUFFER_TOO_SMALL | 0xC0000023 | ERROR_INSUFFICIENT_BUFFER | 0x7A (122) |
| KS-specific (0xEF-0xF4) | 0xC00000Ex | ERROR_INVALID_PARAMETER | 0x57 (87) (likely) |

## Root Cause Analysis

ERROR_INVALID_PARAMETER (0x57) is returned when RtlNtStatusToDosError maps the kernel NTSTATUS to Win32 error 87. The most likely sources:

### Most Likely: CHECK 9 or CHECK 10 (0xC000000D)
KSDATAFORMAT buffer too small or FormatSize field wrong. The input buffer must be at least 72 (KSPIN_CONNECT) + KSDATAFORMAT.FormatSize bytes. If the KSDATAFORMAT portion < 64 bytes, or FormatSize < 64, or FormatSize > remaining buffer, KspValidateDataFormat returns 0xC000000D.

### Second Most Likely: CHECK 5 (0xC00000F3)
Priority.SubLevel == 0. The validation checks BOTH Priority.Class != 0 AND Priority.SubLevel != 0. Most code examples set KSPRIORITY_NORMAL (Class=1, SubLevel=0), but this ks.sys build rejects SubLevel=0.

### Third Most Likely: CHECK 16 (0xC000000D)
KSDATAFORMAT attributes validation failure when Flags & 0x2 but attribute data is malformed.

## Correct KSPIN_CONNECT Parameters

```c
KSPIN_CONNECT connect = {
    // Interface
    {
        {0x1A8766A0, 0x62CE, 0x11CF, {0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00}},
        0,   // Id = KSINTERFACE_STANDARD_STREAMING
        0    // Flags = 0 (MUST be 0)
    },
    // Medium
    {
        {0x4747B320, 0x62CE, 0x11CF, {0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00}},
        0,   // Id = KSMEDIUM_TYPE_ANYINSTANCE
        0    // Flags = 0 (MUST be 0)
    },
    PinId,          // PinId: valid pin ID from filter descriptor
    NULL,           // PinToHandle: NULL for sink pins
    {1, 1}          // Priority: Class=KSPRIORITY_NORMAL(1), SubLevel=1 (MUST be non-zero!)
};

KSDATAFORMAT_WAVEFORMATEX dataFormat = {
    {
        sizeof(KSDATAFORMAT_WAVEFORMATEX),  // FormatSize = 82 (0x52)
        0,                                   // Flags = 0
        sizeof(WAVEFORMATEX),                // SampleSize
        0,                                   // Reserved = 0
        {0x73647561, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}},
        {0x00000000, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}},
        {0x05589F81, 0xC356, 0x11CE, {0xBF, 0x01, 0x00, 0xAA, 0x00, 0x55, 0x59, 0x5A}}
    },
    {
        WAVE_FORMAT_PCM,  // wFormatTag = 1
        nChannels,        // nChannels
        nSamplesPerSec,   // nSamplesPerSec
        nAvgBytesPerSec,  // nAvgBytesPerSec
        nBlockAlign,      // nBlockAlign
        wBitsPerSample,   // wBitsPerSample
        sizeof(WAVEFORMATEX) // cbSize = 0
    }
};

// Total buffer = 72 + 82 = 154 bytes
KsCreatePin(filterHandle, (PKSPIN_CONNECT)&connect, GENERIC_READ | GENERIC_WRITE, &pinHandle);
```

### Critical Requirements Checklist

1. Buffer size >= 136 bytes (72 KSPIN_CONNECT + 64 min KSDATAFORMAT)
2. Interface.Flags == 0 (offset 20)
3. Medium.Flags == 0 (offset 44)
4. PinId < filter DescriptorsCount (offset 48)
5. PinToHandle == NULL for sink pins (offset 56)
6. Priority.Class != 0 (offset 64) -- use KSPRIORITY_NORMAL (1)
7. Priority.SubLevel != 0 (offset 68) -- use 1, NOT 0
8. Interface.Set + Id match descriptor or standard
9. Medium.Set + Id match descriptor or standard
10. KSDATAFORMAT.FormatSize >= 64 and <= remaining buffer
11. KSDATAFORMAT.Reserved == 0
12. MajorFormat/SubFormat/Specifier != GUID_NULL
13. For portcls: MajorFormat = KSDATAFORMAT_TYPE_AUDIO
14. For WAVEFORMATEX: Specifier = KSDATAFORMAT_SPECIFIER_WAVEFORMATEX
15. For WAVEFORMATEX: FormatSize >= 82 (0x52)
16. For WAVE_FORMAT_EXTENSIBLE: cbSize >= 0x16

## Complete Decompilations

### KsCreatePin (ks.sys @ 0x1C0042B70)

```c
NTSTATUS __stdcall KsCreatePin(
        HANDLE FilterHandle,
        PKSPIN_CONNECT Connect,
        ACCESS_MASK DesiredAccess,
        PHANDLE ConnectionHandle)
{
  unsigned int Data1;
  Data1 = Connect[1].Interface.Set.Data1;
  if ( (Connect[1].Interface.Alignment & 0x200000000LL) != 0 )
    Data1 = *(unsigned int *)((char *)&Connect[1].Interface.Set.Data1 + ((Data1 + 7) & 0xFFFFFFF8))
          + ((Data1 + 7) & 0xFFFFFFF8);
  return KsiCreateObjectType(
           FilterHandle,
           L"{146F1A80-4791-11D0-A5D6-28DB04C10000}",
           Connect,
           Data1 + 72,
           DesiredAccess,
           ConnectionHandle);
}
```

### KsValidateConnectRequest (ks.sys @ 0x1C0037240)

```c
NTSTATUS __stdcall KsValidateConnectRequest(
        PIRP Irp, ULONG DescriptorsCount,
        const KSPIN_DESCRIPTOR *Descriptor,
        PKSPIN_CONNECT *Connect)
{
  int v5;
  NTSTATUS result;
  _DWORD v7[6];
  v7[0] = 0;
  v5 = (int)Descriptor;
  result = KspValidateConnectRequest(
             (_DWORD)Irp, DescriptorsCount, (_DWORD)Descriptor,
             88, (__int64)Connect, (__int64)v7);
  if ( result >= 0 )
    return KspValidateDataFormat(v5 + 88 * (*Connect)->PinId,
           (unsigned int)*Connect + 72, v7[0] - 72, 0, 0);
  return result;
}
```

### KspValidateConnectRequest (ks.sys @ 0x1C00372B0)

```c
__int64 __fastcall KspValidateConnectRequest(
    __int64 a1, unsigned int a2, __int64 a3, int a4, __int64 *a5, _DWORD *a6)
{
  __int64 result, v10, v12;
  unsigned int v11;
  int v13, v16;
  char *v14, *v17;
  _DWORD *i, *v18;

  *a6 = 136;
  result = KsiCopyCreateParameter(a1, a6, a5);
  if ( (int)result >= 0 ) {
    v10 = *a5;
    v11 = *(_DWORD *)(*a5 + 48);  // PinId
    if ( v11 >= a2 )
      return 0xC00000F1;
    v12 = a4 * v11 + a3;  // descriptor[PinId]
    if ( ((*(_QWORD *)(v10 + 56) != 0 ? 2 : 5) & *(_DWORD *)(v12 + 52)) != 0 ) {
      if ( *(_DWORD *)(v10 + 20) )
        return 0xC00000EF;
      else if ( *(_DWORD *)(v10 + 64) && *(_DWORD *)(v10 + 68) ) {
        v13 = *(_DWORD *)v12;
        if ( *(_DWORD *)v12 ) v14 = *(char **)(v12 + 8);
        else { v13 = 1; v14 = (char *)&StandardPinInterfaces; }
        for ( i = v14 + 16; ; i += 6 ) {
          if ( !v13 ) return 0xC0000272;
          if ( *((_QWORD *)i - 2) == *(_QWORD *)v10
            && *((_QWORD *)i - 1) == *(_QWORD *)(v10 + 8)
            && *i == *(_DWORD *)(v10 + 16) )
            break;
          --v13;
        }
        if ( !*(_DWORD *)(v10 + 44) ) {
          v16 = *(_DWORD *)(v12 + 16);
          if ( v16 ) v17 = *(char **)(v12 + 24);
          else { v16 = 1; v17 = (char *)&StandardPinMediums; }
          v18 = v17 + 16;
          while ( v16 ) {
            if ( *((_QWORD *)v18 - 2) == *(_QWORD *)(v10 + 24)
              && *((_QWORD *)v18 - 1) == *(_QWORD *)(v10 + 32)
              && *v18 == *(_DWORD *)(v10 + 40) )
              return 0;
            --v16;
            v18 += 6;
          }
          return 0xC0000272;
        }
        return 0xC00000F0;
      } else
        return 0xC00000F3;
    } else
      return 0xC00000F2;
  }
  return result;
}
```

### KspValidateDataFormat (ks.sys @ 0x1C0034A04)

```c
__int64 __fastcall KspValidateDataFormat(
    __int64 a1, __int64 a2, unsigned int a3,
    __int64 (__fastcall *a4)(__int64, __int64, __int64, _QWORD, __int64),
    __int64 a5)
{
  unsigned int v8, v13, v14, v17, v29;
  _QWORD *v11, *v18, *v28;
  __int64 v9, v10, v15, v20, v21, v22, v23, v25, v26, v27;
  int v24;
  unsigned int v19;

  if ( a3 < 0x40 )
    return 0xC000000D;
  v8 = *(_DWORD *)a2;
  if ( v8 < 0x40 || v8 > a3 )
    return 0xC000000D;
  if ( *(_DWORD *)(a2 + 12)
    || *(_QWORD *)(a2 + 16) == *(_QWORD *)&GUID_NULL.Data1
    && *(_QWORD *)(a2 + 24) == *(_QWORD *)GUID_NULL.Data4 )
    return 0xC00000F4;
  if ( *(_QWORD *)(a2 + 32) == *(_QWORD *)&GUID_NULL.Data1
    && *(_QWORD *)(a2 + 40) == *(_QWORD *)GUID_NULL.Data4 )
    return 0xC00000F4;
  v9 = *(_QWORD *)(a2 + 48);
  if ( v9 == *(_QWORD *)&GUID_NULL.Data1
    && *(_QWORD *)(a2 + 56) == *(_QWORD *)GUID_NULL.Data4 )
    return 0xC00000F4;
  if ( v8 != 64
    && v9 == *(_QWORD *)&KSDATAFORMAT_SPECIFIER_NONE.Data1
    && *(_QWORD *)(a2 + 56) == *(_QWORD *)KSDATAFORMAT_SPECIFIER_NONE.Data4 )
    return 0xC00000F4;
  if ( (*(_DWORD *)(a2 + 4) & 2) != 0 ) {
    v10 = (v8 + 7) & 0xFFFFFFF8;
    if ( (unsigned int)v10 >= v8 ) {
      if ( a3 < (unsigned __int64)(v10 + 8) )
        return 0xC000000D;
      v11 = (_QWORD *)(v10 + a2);
      if ( *(_DWORD *)(v10 + a2) != a3 - (_DWORD)v10 )
        return 0xC000000D;
      v12 = (unsigned int *)(v11 + 1);
      v13 = HIDWORD(*v11);
      v14 = *v11 - 8;
      while ( v13 ) {
        if ( v14 < 0x18 ) return 0xC000000D;
        v15 = *v12;
        if ( (unsigned int)v15 < 0x18 ) return 0xC000000D;
        if ( (unsigned int)v15 > v14 ) return 0xC000000D;
        if ( v12[1] ) return 0xC000000D;
        if ( v13 > 1 ) {
          v15 = ((_DWORD)v15 + 7) & 0xFFFFFFF8;
          if ( (unsigned int)v15 > v14 ) return 0xC000000D;
        }
        v14 -= v15;
        v12 = (unsigned int *)((char *)v12 + v15);
        --v13;
      }
      if ( v14 ) return 0xC000000D;
      goto LABEL_30;
    }
    return 0xC0000206;
  }
  v11 = nullptr;
LABEL_30:
  v17 = *(_DWORD *)(a1 + 72);
  if ( v17 ) v18 = *(_QWORD **)(a1 + 80);
  else { v17 = *(_DWORD *)(a1 + 32); v18 = *(_QWORD **)(a1 + 40); }
  v19 = -1073741198;
  while ( v17 ) {
    v20 = *v18;
    v21 = *(_QWORD *)(*v18 + 16LL);
    if ( v21 == *(_QWORD *)&GUID_NULL.Data1
      && *(_QWORD *)(v20 + 24) == *(_QWORD *)GUID_NULL.Data4
      || v21 == *(_QWORD *)(a2 + 16)
      && *(_QWORD *)(v20 + 24) == *(_QWORD *)(a2 + 24) ) {
      if ( (v22 = *(_QWORD *)(v20 + 32), v22 == *(_QWORD *)&GUID_NULL.Data1)
        && *(_QWORD *)(v20 + 40) == *(_QWORD *)GUID_NULL.Data4
        || v22 == *(_QWORD *)(a2 + 32)
        && *(_QWORD *)(v20 + 40) == *(_QWORD *)(a2 + 40) ) {
        if ( (v23 = *(_QWORD *)(v20 + 48), v23 == *(_QWORD *)(a2 + 48))
          && *(_QWORD *)(v20 + 56) == *(_QWORD *)(a2 + 56)
          || v23 == *(_QWORD *)&GUID_NULL.Data1
          && *(_QWORD *)(v20 + 56) == *(_QWORD *)GUID_NULL.Data4 ) {
          v24 = *(_DWORD *)(v20 + 4);
          if ( (v24 & 2) != 0 ) {
            if ( v17 < 2 ) return 0xC000000D;
            v25 = v18[1];
            v26 = v24 & 4;
          } else { v26 = 0; v25 = 0; }
          if ( (unsigned int)AttributeIntersection(v25, v26, v11, 0) ) {
            if ( !a4 ) return 0;
            v19 = a4(a5, a2, v27, *v18, v25);
            if ( v19 != -1073741198 ) return v19;
          }
        }
      }
    }
    v28 = v18 + 1;
    v29 = v17 - 1;
    if ( (*(_DWORD *)(*v18 + 4LL) & 2) == 0 ) { v29 = v17; v28 = v18; }
    v17 = v29 - 1;
    v18 = v28 + 1;
  }
  return v19;
}
```

### KsiCreateObjectType (ks.sys @ 0x1C0044DC0)

```c
__int64 __fastcall KsiCreateObjectType(
    void *a1, const wchar_t *a2, const void *a3,
    unsigned int a4, int a5, void **FileHandle)
{
  size_t v6, v13;
  __int64 v7;
  unsigned __int64 v10;
  unsigned int v11, v12;
  wchar_t *PoolWithTag, *v15;
  NTSTATUS v17;
  __int128 v18;
  struct _IO_STATUS_BLOCK IoStatusBlock;
  struct _OBJECT_ATTRIBUTES ObjectAttributes;

  v6 = a4;
  v7 = -1;
  IoStatusBlock = 0; v18 = 0;
  memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
  do ++v7; while ( a2[v7] );
  v10 = 2LL * (unsigned int)v7;
  if ( v10 > 0xFFFFFFFF ) return 0xC0000095;
  v11 = v10 + 2;
  if ( (int)v10 + 2 < (unsigned int)v10 ) return 0xC0000095;
  v12 = v11 + a4;
  if ( v11 + a4 < v11 ) return 0xC0000095;
  v13 = v12;
  PoolWithTag = (wchar_t *)ExAllocatePoolWithTag(PagedPool, v12, 0x706F534Bu);
  v15 = PoolWithTag;
  if ( !PoolWithTag ) return 0xC000009A;
  v17 = RtlStringCbCopyW(PoolWithTag, v13, a2);
  if ( v17 >= 0 ) {
    v15[v10 / 2] = 92;
    memmove(&v15[(unsigned int)(v7 + 1)], a3, v6);
    ObjectAttributes.RootDirectory = a1;
    LOWORD(v18) = v6 + 2 * (v7 + 1);
    WORD1(v18) = v18;
    *((_QWORD *)&v18 + 1) = v15;
    ObjectAttributes.Length = 48;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.ObjectName = (PUNICODE_STRING)&v18;
    *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
    v17 = IoCreateFile(FileHandle, a5 & 0xFFFFFDFF,
            &ObjectAttributes, &IoStatusBlock, nullptr, 0, 0, 1u, 0,
            nullptr, 0, CreateFileTypeNone, nullptr, 0x101u);
  }
  ExFreePoolWithTag(v15, 0);
  return (unsigned int)v17;
}
```

### CKsFilter::DispatchCreatePin (ks.sys @ 0x1C00370A0)

```c
__int64 __fastcall CKsFilter::DispatchCreatePin(
    struct _DEVICE_OBJECT *a1, struct _IRP *a2)
{
  __int64 v3, v4, v7;
  NTSTATUS Pin;
  __int64 PinId;
  struct _KSPIN_DESCRIPTOR_EX *v8;
  int v10;
  struct KSPIN_CONNECT *v11;

  v3 = *(_QWORD *)(*(_QWORD *)a2->Tail.Overlay.CurrentStackLocation
        ->FileObject->RelatedFileObject->FsContext + 112LL);
  KeWaitForSingleObject((PVOID)(v3 + 304), Executive, 0, 0, nullptr);
  v4 = *(_QWORD *)(v3 + 128);
  v11 = nullptr; v10 = 0;
  Pin = KspValidateConnectRequest(
          (__int64)a2, *(_DWORD *)(v4 + 32),
          *(_QWORD *)(v4 + 40) + 16LL, *(_DWORD *)(v4 + 36),
          (__int64 *)&v11, &v10);
  if ( Pin >= 0 ) {
    PinId = v11->PinId;
    v7 = *(_QWORD *)(v3 + 368) + 88 * PinId;
    v8 = (struct _KSPIN_DESCRIPTOR_EX *)(
          *(_QWORD *)(*(_QWORD *)(v3 + 128) + 40LL)
          + (unsigned int)(*(_DWORD *)(*(_QWORD *)(v3 + 128) + 36LL) * PinId));
    if ( *(_DWORD *)v7 >= v8->InstancesPossible )
      Pin = -1073741823;
    else
      Pin = KspCreatePin(a2, (struct _KSFILTER_EXT *)v3,
            (struct _LIST_ENTRY *)(v7 + 8), v11, v10 - 72, v8,
            *(struct KSAUTOMATION_TABLE_ **)(v7 + 24),
            *(struct KSAUTOMATION_TABLE_ ***)(v3 + 272),
            *(_DWORD *)(v3 + 280), (unsigned int *)v7);
  }
  KeReleaseMutex((PRKMUTEX)(v3 + 304), 0);
  if ( Pin != 259 ) {
    a2->IoStatus.Status = Pin;
    IofCompleteRequest(a2, 0);
  }
  return (unsigned int)Pin;
}
```

### KsiCopyCreateParameter (ks.sys @ 0x1C0037428)

```c
__int64 __fastcall KsiCopyCreateParameter(
    __int64 a1, unsigned int *a2, _QWORD *a3)
{
  __int64 v5, v7, v10;
  unsigned int v8, v12;
  _WORD *v9;
  int v11;
  PVOID PoolWithTag;

  v5 = *(_QWORD *)(a1 + 184);
  v7 = *(_QWORD *)(v5 + 48);
  v8 = *(unsigned __int16 *)(v7 + 88);
  v9 = *(_WORD **)(v7 + 96);
  if ( v8 >= 2 && *v9 == 92 ) { ++v9; v8 -= 2; }
  v10 = *(unsigned __int16 *)(*(_QWORD *)(a1 + 120) + 16LL);
  if ( v8 < v10 + (unsigned __int64)*a2 + 2 )
    return 0xC0000206;
  v11 = *(_DWORD *)(a1 + 16);
  v12 = v8 - v10 - 2;
  *a2 = v12;
  if ( (v11 & 0x10) != 0 ) {
    *a3 = *(_QWORD *)(a1 + 24);
    return 0;
  }
  if ( *(_DWORD *)(v5 + 32) ) return 0xC000004F;
  PoolWithTag = ExAllocatePoolWithTag(NonPagedPoolNx, v12, 0x7063534Bu);
  *(_QWORD *)(a1 + 24) = PoolWithTag;
  if ( PoolWithTag ) {
    *(_DWORD *)(a1 + 16) |= 0x30u;
    memmove(PoolWithTag, (char *)v9 + v10 + 2, *a2);
    *a3 = *(_QWORD *)(a1 + 24);
    return 0;
  }
  return 0xC000009A;
}
```

### KsDispatchIrp (ks.sys @ 0x1C002BF60)

```c
NTSTATUS __stdcall KsDispatchIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  struct _IO_STACK_LOCATION *CurrentStackLocation;
  PFILE_OBJECT FileObject;
  __int64 *FsContext;
  __int64 v5;
  NTSTATUS result;

  CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
  FileObject = CurrentStackLocation->FileObject;
  if ( FileObject && (FsContext = (__int64 *)FileObject->FsContext) != nullptr )
    v5 = *FsContext;
  else
    v5 = 0;
  if ( CurrentStackLocation->MajorFunction == 14 ) {
    if ( v5 ) return (**(NTSTATUS (***)(void))v5)();
    else return KsDefaultForwardIrp(DeviceObject, Irp);
  } else {
    switch ( CurrentStackLocation->MajorFunction ) {
      case 0u:  // IRP_MJ_CREATE
        if ( *(_QWORD *)(*(_QWORD *)DeviceObject->DeviceExtension + 360LL) )
          result = CKsDevice::DispatchCreate(DeviceObject, Irp);
        else
          result = DispatchCreate(DeviceObject, Irp, v5);
        break;
      case 2u:  // IRP_MJ_CLOSE
        result = (*(NTSTATUS (__fastcall **)(PDEVICE_OBJECT, PIRP))(*(_QWORD *)v5 + 32LL))(DeviceObject, Irp);
        break;
      case 3u:  // IRP_MJ_READ
        result = (*(NTSTATUS (__fastcall **)(PDEVICE_OBJECT, PIRP))(*(_QWORD *)v5 + 8LL))(DeviceObject, Irp);
        break;
      // ... other cases ...
      default:
        Irp->IoStatus.Status = -1073741808;
        IofCompleteRequest(Irp, 0);
        result = -1073741808;
        break;
    }
  }
  return result;
}
```

### PcDispatchIrp (portcls.sys @ 0x1C00353E0)

```c
NTSTATUS __stdcall PcDispatchIrp(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
  unsigned int MajorFunction;
  struct DEVICE_CONTEXT *DeviceExtension;
  NTSTATUS Status, v8, v11;
  int IrpDisposition;
  __int64 v10, v12;
  PVOID Object[2];

  if ( !pDeviceObject ) {
    if ( pIrp ) {
      pIrp->IoStatus.Status = -1073741811;
      IofCompleteRequest(pIrp, 0);
    }
    return -1073741811;
  }
  if ( !pIrp ) return -1073741811;
  MajorFunction = pIrp->Tail.Overlay.CurrentStackLocation->MajorFunction;
  if ( MajorFunction < 0x16 ) goto LABEL_4;
  if ( MajorFunction == 22 ) return DispatchPower(pDeviceObject, pIrp);
  if ( MajorFunction == 23 ) return PcWmiSystemControl(pDeviceObject, pIrp);
  if ( MajorFunction != 27 ) {
LABEL_4:
    DeviceExtension = (struct DEVICE_CONTEXT *)pDeviceObject->DeviceExtension;
    if ( DeviceExtension && *((_DWORD *)DeviceExtension + 20) == 764910 ) {
      if ( (_BYTE)MajorFunction )
        return KsDispatchIrp(pDeviceObject, pIrp);
      v8 = AcquireRemoveLock((struct DEVICE_CONTEXT *)pDeviceObject->DeviceExtension, pIrp);
      Status = v8;
      if ( v8 >= 0 ) {
        AcquireDevice(DeviceExtension);
        IrpDisposition = GetIrpDisposition(pDeviceObject, 0, 1, pIrp);
        if ( IrpDisposition == 2 ) {
          Status = KsDispatchIrp(pDeviceObject, pIrp);
          ReleaseRemoveLock(DeviceExtension, pIrp);
        } else {
          Status = -1073741661;
          pIrp->IoStatus.Information = 0;
          CompleteIrp(DeviceExtension, pIrp, -1073741661);
        }
        ReleaseDevice(DeviceExtension);
        // ... power management idle code ...
        return Status;
      }
      pIrp->IoStatus.Status = v8;
    } else {
      Status = pIrp->IoStatus.Status;
    }
    IofCompleteRequest(pIrp, 0);
    return Status;
  }
  return DispatchPnp(pDeviceObject, pIrp);
}
```

### PcCaptureFormat (portcls.sys @ 0x1C00340F0)

```c
__int64 __fastcall PcCaptureFormat(
    void **a1, __int64 a2, unsigned int a3,
    __int64 a4, unsigned int a5, char a6)
{
  __int64 result, v10, v18, v21, v22;
  unsigned int v9, v11, v12, v15, v19, v25, v29;
  struct KSTOPOLOGY *v13;
  unsigned int ConnectionToPin, FromNode;
  _OWORD *PoolWithTag;
  int v24;
  PVOID v26;
  _DWORD *v27;
  struct KSTOPOLOGY_CONNECTION *v28[7];

  if ( a3 < 4 ) return 0xC000000D;
  if ( *(_DWORD *)a2 > a3 ) return 0xC0000023;
  result = ValidateDataFormat((union KSDATAFORMAT *)a2);
  v11 = result;
  if ( (int)result >= 0 ) {
    v12 = *(_DWORD *)a2;  // FormatSize
    // Audio format check: MajorFormat == KSDATAFORMAT_TYPE_AUDIO
    // and Specifier == KSDATAFORMAT_SPECIFIER_DSOUND
    if ( *(_DWORD *)a2 >= 0x5Au
      && *(_QWORD *)(a2 + 16) == *(_QWORD *)&GUID_73647561.Data1
      && *(_QWORD *)(a2 + 24) == *(_QWORD *)GUID_73647561.Data4
      && *(_QWORD *)(a2 + 48) == *(_QWORD *)&GUID_518590a2.Data1
      && *(_QWORD *)(a2 + 56) == *(_QWORD *)GUID_518590a2.Data4 )
    {
      // DSOUND format path
      if ( (*(_BYTE *)(a2 + 64) & 8) == 0 ) {
        // Topology connection validation...
        // Allocates pool, copies format, sets Specifier to WILDCARD
        v22 = v12 - 8;
        PoolWithTag = ExAllocatePoolWithTag((POOL_TYPE)512, (unsigned int)v22, 0x66446350u);
        *a1 = PoolWithTag;
        if ( PoolWithTag ) {
          // Copy and fixup format...
          *((_DWORD *)*a1 + 1) &= ~2u;
          goto LABEL_35;
        }
        return -1073741670;
      }
    } else {
      // WAVEFORMATEX or other format path
      v24 = 0;
      if ( v12 >= 0x40 ) {
        if ( a6 && (*(_DWORD *)(a2 + 4) & 2) != 0 ) {
          v12 = (v12 + 7) & 0xFFFFFFF8;
          v24 = *(_DWORD *)(v12 + a2);
        }
        v25 = v12 + v24;
        v26 = ExAllocatePoolWithTag((POOL_TYPE)512, v12 + v24, 0x66446350u);
        *a1 = v26;
        if ( v26 ) {
          memset(v26, 0, v25);
          memmove(*a1, (const void *)a2, v25);
          if ( v24 ) {
LABEL_35:
            if ( *(_DWORD *)a2 >= 0x52u ) {
              v27 = *a1;
              if ( *((_QWORD *)*a1 + 2) == GUID_73647561.Data1
                && *((_QWORD *)v27 + 3) == GUID_73647561.Data4
                && *((_QWORD *)v27 + 6) == GUID_05589f81.Data1
                && *((_QWORD *)v27 + 7) == GUID_05589f81.Data4
                && !v27[2] )
              {
                v27[2] = *((unsigned __int16 *)v27 + 38);
                return v11;
              }
            }
            return v11;
          }
LABEL_34:
          *((_DWORD *)*a1 + 1) &= ~2u;
          goto LABEL_35;
        }
        return -1073741670;
      }
    }
    return 0xC000000D;
  }
  return result;
}
```

### ValidateDataFormat (portcls.sys @ 0x1C0001420)

```c
__int64 __fastcall ValidateDataFormat(union KSDATAFORMAT *a1)
{
  unsigned int v1;
  LONGLONG v2, v3, v10;
  __int64 v4;
  ULONG v5, v8;
  _WORD *v6;
  ULONG FormatSize;

  v1 = 0;
  if ( a1 ) {
    // Check MajorFormat == KSDATAFORMAT_TYPE_AUDIO
    v2 = *(&a1->Alignment + 2) - *(_QWORD *)&GUID_73647561.Data1;
    if ( !v2 ) v2 = *(&a1->Alignment + 3) - *(_QWORD *)GUID_73647561.Data4;
    if ( v2 ) return v1;  // Not audio format, return 0 (no match)
    // Check Specifier == KSDATAFORMAT_SPECIFIER_WAVEFORMATEX
    v3 = *(&a1->Alignment + 6) - *(_QWORD *)&GUID_05589f81.Data1;
    if ( !v3 ) v3 = *(&a1->Alignment + 7) - *(_QWORD *)GUID_05589f81.Data4;
    if ( v3 ) {
      // Check Specifier == KSDATAFORMAT_SPECIFIER_DSOUND
      v10 = *(&a1->Alignment + 6) - *(_QWORD *)&GUID_518590a2.Data1;
      if ( !v10 ) v10 = *(&a1->Alignment + 7) - *(_QWORD *)GUID_518590a2.Data4;
      if ( v10 ) return v1;  // Neither WAVEFORMATEX nor DSOUND
      v4 = 72; v5 = 90;  // DSOUND: offset 72, min FormatSize 90
    } else {
      v4 = 64; v5 = 82;  // WAVEFORMATEX: offset 64, min FormatSize 82
    }
    v6 = (_WORD *)((char *)a1 + v4);
    if ( v6 ) {
      FormatSize = a1->FormatSize;
      if ( FormatSize < v5
        || *v6 == 0xFFFE && v6[8] < 0x16u )
        return 0xC0000010;  // STATUS_INVALID_DEVICE_REQUEST
      v8 = v5 + (unsigned __int16)v6[8];
      if ( FormatSize < v8 || v8 < v5 )
        return 0xC0000010;
    }
    return v1;
  }
  return 0xC000000D;
}
```

### PcValidateDataFormat (portcls.sys @ 0x1C000C220)

```c
__int64 __fastcall PcValidateDataFormat(
    struct _IRP *a1, struct KSIDENTIFIER *a2, union KSDATAFORMAT *a3)
{
  __int64 result;
  void *v5;
  struct KSIDENTIFIER *v6;

  if ( !a3 ) return 0xC000000D;
  result = ValidateDataFormat(a3);
  if ( (int)result >= 0 )
    return PropertyItemPropertyHandler(a1, v6, v5);
  return result;
}
```
