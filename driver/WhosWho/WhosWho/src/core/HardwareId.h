#pragma once

#include <ntifs.h>

#ifndef IOCTL_AIDA_GET_HWID
#define IOCTL_AIDA_GET_HWID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA1D0, METHOD_BUFFERED, FILE_READ_DATA)
#endif

#ifndef AIDA_HWID_FACTOR_COUNT
#define AIDA_HWID_FACTOR_COUNT 9
#endif

#ifndef AIDA_HWID_REPLY_MAGIC
#define AIDA_HWID_REPLY_MAGIC 0x48574944u
#endif

typedef struct _AIDA_HWID_REPLY {
    ULONG          magic;
    ULONG          version;
    UCHAR          hwid_hash[32];
    UCHAR          factor_hashes[AIDA_HWID_FACTOR_COUNT][32];
    UCHAR          hmac_signature[32];
    ULONG          factor_present_mask;
    ULONG          reserved0;
    LARGE_INTEGER  timestamp;
    LARGE_INTEGER  nonce;
} AIDA_HWID_REPLY, *PAIDA_HWID_REPLY;

NTSTATUS HardwareIdHandleIoctl(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IoStack);

NTSTATUS HardwareIdInitialize(_In_ PDRIVER_OBJECT DriverObject);

VOID HardwareIdShutdown(VOID);

NTSTATUS HardwareIdGetSessionSecret(_Out_writes_bytes_(32) PUCHAR OutSecret);
