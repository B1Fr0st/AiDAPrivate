#include "Comms.h"
#include "SandboxRegistry.h"
#include "Logging.h"
#include "ShadowFSProtocol.h"
#include "MinifilterContext.h"

#include <ntstrsafe.h>

PFLT_PORT g_shadow_server_port = nullptr;
PFLT_PORT g_shadow_client_port = nullptr;
volatile LONG g_shadow_client_connected = 0;

namespace {
    NTSTATUS build_default_security(_Outptr_ PSECURITY_DESCRIPTOR* out_sd) {
        if (out_sd == nullptr) return STATUS_INVALID_PARAMETER;
        PSECURITY_DESCRIPTOR sd = nullptr;
        NTSTATUS s = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
        if (!NT_SUCCESS(s)) {
            return s;
        }
        *out_sd = sd;
        return STATUS_SUCCESS;
    }

    NTSTATUS validate_header(_In_reads_bytes_(input_bytes) PVOID input, _In_ ULONG input_bytes,
                             _Out_ const SHADOWFS_MSG_HEADER** out_hdr) {
        if (out_hdr) *out_hdr = nullptr;
        if (input == nullptr || input_bytes < sizeof(SHADOWFS_MSG_HEADER)) {
            return STATUS_INVALID_PARAMETER;
        }
        const SHADOWFS_MSG_HEADER* hdr =
            reinterpret_cast<const SHADOWFS_MSG_HEADER*>(input);
        if (hdr->magic != SHADOWFS_MSG_MAGIC) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (hdr->version != SHADOWFS_PROTOCOL_VERSION
            && hdr->version != SHADOWFS_PROTOCOL_VERSION_LEGACY) {
            return STATUS_REVISION_MISMATCH;
        }
        if (hdr->payload_bytes > input_bytes) {
            return STATUS_INVALID_PARAMETER;
        }
        if (out_hdr) *out_hdr = hdr;
        return STATUS_SUCCESS;
    }

    NTSTATUS write_reply_generic(_Out_writes_bytes_to_(out_bytes, *out_used) PVOID out,
                                 _In_ ULONG out_bytes,
                                 _Out_ PULONG out_used,
                                 _In_ NTSTATUS reply_status) {
        if (out_used) *out_used = 0;
        if (out == nullptr) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (out_bytes < sizeof(SHADOWFS_REPLY_GENERIC_V1)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SHADOWFS_REPLY_GENERIC full = {};
        full.magic = SHADOWFS_MSG_MAGIC;
        full.version = SHADOWFS_PROTOCOL_VERSION;
        full.status = static_cast<ULONG>(reply_status);
        full.pid_count = shadow_registry_active_count();
        full.denials = shadow_stats_denials();
        full.redirects = shadow_stats_redirects();
        full.copies = shadow_stats_copies();
        full.bytes_copied = shadow_stats_bytes_copied();
        full.fsctl_denials = shadow_stats_fsctl_denials();
        full.ads_denials = shadow_stats_ads_denials();
        full.mapping_denials = shadow_stats_mapping_denials();
        full.unc_denials = shadow_stats_unc_denials();
        full.raw_device_denials = shadow_stats_raw_device_denials();
        full.set_info_denials = shadow_stats_set_info_denials();
        full.dir_merge_emits = shadow_stats_dir_merge_emits();
        full.reserved0 = 0;

        if (out_bytes >= sizeof(SHADOWFS_REPLY_GENERIC)) {
            RtlCopyMemory(out, &full, sizeof(SHADOWFS_REPLY_GENERIC));
            if (out_used) *out_used = sizeof(SHADOWFS_REPLY_GENERIC);
            return STATUS_SUCCESS;
        }

        SHADOWFS_REPLY_GENERIC_V1 v1 = {};
        v1.magic = SHADOWFS_MSG_MAGIC;
        v1.version = SHADOWFS_PROTOCOL_VERSION_LEGACY;
        v1.status = static_cast<ULONG>(reply_status);
        v1.pid_count = full.pid_count;
        v1.denials = full.denials;
        v1.redirects = full.redirects;
        v1.copies = full.copies;
        RtlCopyMemory(out, &v1, sizeof(v1));
        if (out_used) *out_used = sizeof(v1);
        return STATUS_SUCCESS;
    }
}

NTSTATUS FLTAPI shadow_comms_connect(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (ConnectionPortCookie) *ConnectionPortCookie = nullptr;

    if (InterlockedCompareExchange(&g_shadow_client_connected, 1, 0) != 0) {
        SHADOW_LOG_WARN("comms_connect REJECT already_connected client=%p", ClientPort);
        return STATUS_CONNECTION_COUNT_LIMIT;
    }

    g_shadow_client_port = ClientPort;
    SHADOW_LOG_INFO("comms_connect ok port=%p caller_pid=%lu",
        ClientPort, (unsigned long)(ULONG_PTR)PsGetCurrentProcessId());
    return STATUS_SUCCESS;
}

VOID FLTAPI shadow_comms_disconnect(PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    SHADOW_LOG_INFO("comms_disconnect clearing registry caller_pid=%lu",
        (unsigned long)(ULONG_PTR)PsGetCurrentProcessId());
    if (g_shadow_client_port != nullptr) {
        FltCloseClientPort(g_shadow_filter, &g_shadow_client_port);
        g_shadow_client_port = nullptr;
    }
    InterlockedExchange(&g_shadow_client_connected, 0);
    shadow_registry_cleanup();
    shadow_registry_init();
}

NTSTATUS FLTAPI shadow_comms_message(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;

    if (InputBuffer == nullptr || InputBufferLength == 0) {
        SHADOW_LOG_WARN("comms_message empty_input");
        return write_reply_generic(OutputBuffer, OutputBufferLength,
            ReturnOutputBufferLength, STATUS_INVALID_PARAMETER);
    }

    PVOID kbuf = ExAllocatePool2(POOL_FLAG_PAGED, InputBufferLength, SHADOW_TAG_BUF);
    if (kbuf == nullptr) {
        SHADOW_LOG_ERROR("comms_message alloc_FAILED bytes=%lu", InputBufferLength);
        return write_reply_generic(OutputBuffer, OutputBufferLength,
            ReturnOutputBufferLength, STATUS_INSUFFICIENT_RESOURCES);
    }

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        ProbeForRead(InputBuffer, InputBufferLength, sizeof(UCHAR));
        RtlCopyMemory(kbuf, InputBuffer, InputBufferLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        SHADOW_LOG_WARN("comms_message ProbeForRead_FAILED status=0x%08lX", status);
        ExFreePoolWithTag(kbuf, SHADOW_TAG_BUF);
        return write_reply_generic(OutputBuffer, OutputBufferLength,
            ReturnOutputBufferLength, STATUS_ACCESS_VIOLATION);
    }

    const SHADOWFS_MSG_HEADER* hdr = nullptr;
    status = validate_header(kbuf, InputBufferLength, &hdr);
    if (!NT_SUCCESS(status) || hdr == nullptr) {
        SHADOW_LOG_WARN("comms_message validate_header_FAILED status=0x%08lX bytes=%lu",
            status, InputBufferLength);
        ExFreePoolWithTag(kbuf, SHADOW_TAG_BUF);
        return write_reply_generic(OutputBuffer, OutputBufferLength,
            ReturnOutputBufferLength, status);
    }

    NTSTATUS handler_status = STATUS_SUCCESS;
    ULONG cmd = hdr->command;
    SHADOW_LOG_INFO("comms_message recv cmd=%lu bytes=%lu caller_pid=%lu",
        cmd, InputBufferLength, (unsigned long)(ULONG_PTR)PsGetCurrentProcessId());

    switch (cmd) {
        case SHADOWFS_MSG_PING: {
            handler_status = STATUS_SUCCESS;
            SHADOW_LOG_INFO("ping ok caller_pid=%lu",
                (unsigned long)(ULONG_PTR)PsGetCurrentProcessId());
            break;
        }
        case SHADOWFS_MSG_QUERY_STATS: {
            handler_status = STATUS_SUCCESS;
            SHADOW_LOG_INFO("query_stats pids=%lu denials=%lld redirects=%lld copies=%lld bytes=%lld",
                shadow_registry_active_count(),
                shadow_stats_denials(),
                shadow_stats_redirects(),
                shadow_stats_copies(),
                shadow_stats_bytes_copied());
            break;
        }
        case SHADOWFS_MSG_REGISTER_PID: {
            if (InputBufferLength < sizeof(SHADOWFS_MSG_REGISTER)) {
                handler_status = STATUS_BUFFER_TOO_SMALL;
                SHADOW_LOG_WARN("register_pid_too_small bytes=%lu need=%lu",
                    InputBufferLength, (unsigned long)sizeof(SHADOWFS_MSG_REGISTER));
                break;
            }
            const SHADOWFS_MSG_REGISTER* req =
                reinterpret_cast<const SHADOWFS_MSG_REGISTER*>(kbuf);
            if (req->pid == 0 || req->pid == 4) {
                handler_status = STATUS_INVALID_PARAMETER;
                SHADOW_LOG_WARN("register_pid_REJECT system_pid=%lu", req->pid);
                break;
            }
            if (req->sandbox_root_chars == 0
                || req->sandbox_root_chars >= SHADOWFS_MAX_PATH_CHARS) {
                handler_status = STATUS_INVALID_PARAMETER;
                SHADOW_LOG_WARN("register_pid_REJECT root_chars=%lu pid=%lu",
                    req->sandbox_root_chars, req->pid);
                break;
            }
            UNICODE_STRING root;
            root.Buffer = const_cast<PWCHAR>(req->sandbox_root);
            root.Length = static_cast<USHORT>(req->sandbox_root_chars * sizeof(WCHAR));
            root.MaximumLength = root.Length;
            HANDLE pid_h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req->pid));
            ULONG flags = (req->flags == 0) ? SHADOWFS_DEFAULT_FLAGS : req->flags;
            bool ok = shadow_registry_add(pid_h, flags, &root);
            handler_status = ok ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        case SHADOWFS_MSG_UNREGISTER_PID: {
            if (InputBufferLength < sizeof(SHADOWFS_MSG_UNREGISTER)) {
                handler_status = STATUS_BUFFER_TOO_SMALL;
                SHADOW_LOG_WARN("unregister_pid_too_small bytes=%lu need=%lu",
                    InputBufferLength, (unsigned long)sizeof(SHADOWFS_MSG_UNREGISTER));
                break;
            }
            const SHADOWFS_MSG_UNREGISTER* req =
                reinterpret_cast<const SHADOWFS_MSG_UNREGISTER*>(kbuf);
            if (req->pid == 0 || req->pid == 4) {
                handler_status = STATUS_INVALID_PARAMETER;
                SHADOW_LOG_WARN("unregister_pid_REJECT system_pid=%lu", req->pid);
                break;
            }
            HANDLE pid_h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req->pid));
            bool ok = shadow_registry_remove(pid_h);
            handler_status = ok ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            break;
        }
        default:
            handler_status = STATUS_INVALID_DEVICE_REQUEST;
            SHADOW_LOG_WARN("comms_message unknown_cmd=%lu", cmd);
            break;
    }

    ExFreePoolWithTag(kbuf, SHADOW_TAG_BUF);

    NTSTATUS final_reply_status = write_reply_generic(OutputBuffer, OutputBufferLength,
        ReturnOutputBufferLength, handler_status);
    SHADOW_LOG_INFO("comms_message reply cmd=%lu handler_status=0x%08lX reply_write_status=0x%08lX bytes_out=%lu",
        cmd, handler_status, final_reply_status,
        ReturnOutputBufferLength ? *ReturnOutputBufferLength : 0);
    return final_reply_status;
}

NTSTATUS shadow_comms_init(PFLT_FILTER filter) {
    if (filter == nullptr) return STATUS_INVALID_PARAMETER;

    PSECURITY_DESCRIPTOR sd = nullptr;
    NTSTATUS status = build_default_security(&sd);
    if (!NT_SUCCESS(status)) {
        SHADOW_LOG_ERROR("comms_init build_default_security FAILED status=0x%08lX", status);
        return status;
    }

    UNICODE_STRING port_name;
    RtlInitUnicodeString(&port_name, SHADOWFS_PORT_NAME);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &port_name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(
        filter,
        &g_shadow_server_port,
        &oa,
        nullptr,
        shadow_comms_connect,
        shadow_comms_disconnect,
        shadow_comms_message,
        1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        SHADOW_LOG_ERROR("comms_init FltCreateCommunicationPort FAILED status=0x%08lX", status);
        return status;
    }

    SHADOW_LOG_INFO("comms_init server_port=%p name='%ws' version=0x%08lX",
        g_shadow_server_port, SHADOWFS_PORT_NAME, SHADOWFS_PROTOCOL_VERSION);
    return STATUS_SUCCESS;
}

void shadow_comms_cleanup() {
    if (g_shadow_client_port != nullptr) {
        FltCloseClientPort(g_shadow_filter, &g_shadow_client_port);
        g_shadow_client_port = nullptr;
    }
    if (g_shadow_server_port != nullptr) {
        FltCloseCommunicationPort(g_shadow_server_port);
        g_shadow_server_port = nullptr;
    }
    InterlockedExchange(&g_shadow_client_connected, 0);
    SHADOW_LOG_INFO("comms_cleanup done");
}
