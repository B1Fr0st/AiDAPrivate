#pragma once

#include <fltKernel.h>

extern PFLT_PORT g_shadow_server_port;
extern PFLT_PORT g_shadow_client_port;
extern volatile LONG g_shadow_client_connected;

NTSTATUS shadow_comms_init(_In_ PFLT_FILTER filter);
void shadow_comms_cleanup();

NTSTATUS FLTAPI shadow_comms_connect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

VOID FLTAPI shadow_comms_disconnect(_In_opt_ PVOID ConnectionCookie);

NTSTATUS FLTAPI shadow_comms_message(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);
