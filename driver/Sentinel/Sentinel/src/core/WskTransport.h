#pragma once

#include <ntddk.h>
#include <wsk.h>
#include "KernelCrypto.h"
#include "Integrity.h"

namespace wsk_transport
{
    constexpr ULONG WSK_POOL_TAG = 'wskS';
    constexpr USHORT SERVER_PORT = 443;
    constexpr ULONG  MAX_RESPONSE_SIZE = 8192;
    constexpr ULONG  HEARTBEAT_MIN_INTERVAL_MS = 30000;
    constexpr ULONG  HEARTBEAT_MAX_INTERVAL_MS = 60000;
    constexpr ULONG  MAX_MISSED_HEARTBEATS = 3;

    inline WSK_REGISTRATION      g_wsk_registration = {};
    inline WSK_PROVIDER_NPI      g_wsk_provider_npi = {};
    inline WSK_CLIENT_NPI        g_wsk_client_npi = {};
    inline WSK_CLIENT_DISPATCH    g_wsk_dispatch = { MAKE_WSK_VERSION(1, 0), 0, nullptr };
    inline BOOLEAN               g_wsk_ready = FALSE;

    inline KTIMER                g_heartbeat_timer = {};
    inline KDPC                  g_heartbeat_dpc = {};
    inline BOOLEAN               g_heartbeat_active = FALSE;
    inline volatile LONG         g_missed_heartbeats = 0;
    inline WORK_QUEUE_ITEM       g_heartbeat_work_item = {};
    inline volatile LONG         g_work_item_queued = 0;

    struct wsk_completion_t
    {
        KEVENT event;
        IO_STATUS_BLOCK iosb;
    };

    __forceinline NTSTATUS NTAPI wsk_completion_routine(
        PDEVICE_OBJECT, PIRP irp, PVOID context)
    {
        auto* comp = static_cast<wsk_completion_t*>(context);
        comp->iosb = irp->IoStatus;
        KeSetEvent(&comp->event, IO_NO_INCREMENT, FALSE);
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    __forceinline NTSTATUS init()
    {
        SN_LOG("wsk_transport::init: starting WSK registration");
        g_wsk_client_npi.ClientContext = nullptr;
        g_wsk_client_npi.Dispatch = &g_wsk_dispatch;

        NTSTATUS status = WskRegister(&g_wsk_client_npi, &g_wsk_registration);
        if (!NT_SUCCESS(status)) {
            SN_LOG("wsk_transport::init: FAIL - WskRegister status=0x%08lx", status);
            return status;
        }
        SN_LOG("wsk_transport::init: WskRegister OK, capturing provider NPI");

        status = WskCaptureProviderNPI(
            &g_wsk_registration, WSK_INFINITE_WAIT, &g_wsk_provider_npi);
        if (!NT_SUCCESS(status))
        {
            SN_LOG("wsk_transport::init: FAIL - WskCaptureProviderNPI status=0x%08lx", status);
            WskDeregister(&g_wsk_registration);
            return status;
        }

        g_wsk_ready = TRUE;
        SN_LOG("wsk_transport::init: SUCCESS, g_wsk_ready=TRUE");
        return STATUS_SUCCESS;
    }

    __forceinline PWSK_SOCKET create_tcp_socket()
    {
        if (!g_wsk_ready) return nullptr;

        wsk_completion_t comp;
        KeInitializeEvent(&comp.event, SynchronizationEvent, FALSE);

        PIRP irp = IoAllocateIrp(1, FALSE);
        if (!irp) return nullptr;

        IoSetCompletionRoutine(irp, wsk_completion_routine, &comp, TRUE, TRUE, TRUE);

        g_wsk_provider_npi.Dispatch->WskSocket(
            g_wsk_provider_npi.Client,
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            WSK_FLAG_CONNECTION_SOCKET,
            nullptr, nullptr, nullptr, nullptr, nullptr,
            irp);

        KeWaitForSingleObject(&comp.event, Executive, KernelMode, FALSE, nullptr);

        PWSK_SOCKET result = nullptr;
        if (NT_SUCCESS(comp.iosb.Status))
            result = reinterpret_cast<PWSK_SOCKET>(comp.iosb.Information);

        IoFreeIrp(irp);
        return result;
    }

    __forceinline NTSTATUS connect_socket(PWSK_SOCKET socket, ULONG ip_addr, USHORT port)
    {
        if (!socket) return STATUS_INVALID_PARAMETER;

        SOCKADDR_IN local_addr = {};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = 0;

        wsk_completion_t bind_comp;
        KeInitializeEvent(&bind_comp.event, SynchronizationEvent, FALSE);
        PIRP irp = IoAllocateIrp(1, FALSE);
        if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

        IoSetCompletionRoutine(irp, wsk_completion_routine, &bind_comp, TRUE, TRUE, TRUE);

        auto* dispatch = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(
            socket->Dispatch);
        dispatch->WskBind(socket, reinterpret_cast<PSOCKADDR>(&local_addr), 0, irp);

        KeWaitForSingleObject(&bind_comp.event, Executive, KernelMode, FALSE, nullptr);
        NTSTATUS bind_status = bind_comp.iosb.Status;
        IoFreeIrp(irp);
        if (!NT_SUCCESS(bind_status)) return bind_status;

        SOCKADDR_IN remote_addr = {};
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = ip_addr;
        remote_addr.sin_port = RtlUshortByteSwap(port);

        wsk_completion_t conn_comp;
        KeInitializeEvent(&conn_comp.event, SynchronizationEvent, FALSE);
        irp = IoAllocateIrp(1, FALSE);
        if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

        IoSetCompletionRoutine(irp, wsk_completion_routine, &conn_comp, TRUE, TRUE, TRUE);

        dispatch->WskConnect(socket, reinterpret_cast<PSOCKADDR>(&remote_addr), 0, irp);

        LARGE_INTEGER timeout;
        timeout.QuadPart = -150000000LL;
        NTSTATUS status = KeWaitForSingleObject(
            &conn_comp.event, Executive, KernelMode, FALSE, &timeout);

        if (status == STATUS_TIMEOUT) {
            IoCancelIrp(irp);
            KeWaitForSingleObject(&conn_comp.event, Executive, KernelMode, FALSE, nullptr);
            IoFreeIrp(irp);
            return STATUS_TIMEOUT;
        }
        NTSTATUS conn_status = conn_comp.iosb.Status;
        IoFreeIrp(irp);
        return conn_status;
    }

    __forceinline NTSTATUS send_data(PWSK_SOCKET socket, const UINT8* data, ULONG len)
    {
        if (!socket || !data || len == 0) return STATUS_INVALID_PARAMETER;

        WSK_BUF wsk_buf = {};
        wsk_buf.Mdl = IoAllocateMdl(const_cast<UINT8*>(data), len, FALSE, FALSE, nullptr);
        if (!wsk_buf.Mdl) return STATUS_INSUFFICIENT_RESOURCES;

        MmBuildMdlForNonPagedPool(wsk_buf.Mdl);
        wsk_buf.Offset = 0;
        wsk_buf.Length = len;

        wsk_completion_t comp;
        KeInitializeEvent(&comp.event, SynchronizationEvent, FALSE);
        PIRP irp = IoAllocateIrp(1, FALSE);
        if (!irp) { IoFreeMdl(wsk_buf.Mdl); return STATUS_INSUFFICIENT_RESOURCES; }

        IoSetCompletionRoutine(irp, wsk_completion_routine, &comp, TRUE, TRUE, TRUE);

        auto* dispatch = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(
            socket->Dispatch);
        dispatch->WskSend(socket, &wsk_buf, 0, irp);

        KeWaitForSingleObject(&comp.event, Executive, KernelMode, FALSE, nullptr);

        IoFreeMdl(wsk_buf.Mdl);
        NTSTATUS send_status = comp.iosb.Status;
        IoFreeIrp(irp);
        return send_status;
    }

    __forceinline NTSTATUS recv_data(PWSK_SOCKET socket, UINT8* buf, ULONG buf_size, ULONG* received)
    {
        if (!socket || !buf || buf_size == 0) return STATUS_INVALID_PARAMETER;

        WSK_BUF wsk_buf = {};
        wsk_buf.Mdl = IoAllocateMdl(buf, buf_size, FALSE, FALSE, nullptr);
        if (!wsk_buf.Mdl) return STATUS_INSUFFICIENT_RESOURCES;

        MmBuildMdlForNonPagedPool(wsk_buf.Mdl);
        wsk_buf.Offset = 0;
        wsk_buf.Length = buf_size;

        wsk_completion_t comp;
        KeInitializeEvent(&comp.event, SynchronizationEvent, FALSE);
        PIRP irp = IoAllocateIrp(1, FALSE);
        if (!irp) { IoFreeMdl(wsk_buf.Mdl); return STATUS_INSUFFICIENT_RESOURCES; }

        IoSetCompletionRoutine(irp, wsk_completion_routine, &comp, TRUE, TRUE, TRUE);

        auto* dispatch = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(
            socket->Dispatch);
        dispatch->WskReceive(socket, &wsk_buf, 0, irp);

        LARGE_INTEGER timeout;
        timeout.QuadPart = -300000000LL;
        NTSTATUS status = KeWaitForSingleObject(
            &comp.event, Executive, KernelMode, FALSE, &timeout);

        if (status == STATUS_TIMEOUT) {
            IoCancelIrp(irp);
            KeWaitForSingleObject(&comp.event, Executive, KernelMode, FALSE, nullptr);
            IoFreeMdl(wsk_buf.Mdl);
            IoFreeIrp(irp);
            *received = 0;
            return STATUS_TIMEOUT;
        }

        IoFreeMdl(wsk_buf.Mdl);
        NTSTATUS recv_status = comp.iosb.Status;
        if (NT_SUCCESS(recv_status))
            *received = static_cast<ULONG>(comp.iosb.Information);
        IoFreeIrp(irp);
        return recv_status;
    }

    __forceinline void close_socket(PWSK_SOCKET socket)
    {
        if (!socket) return;

        wsk_completion_t comp;
        KeInitializeEvent(&comp.event, SynchronizationEvent, FALSE);
        PIRP irp = IoAllocateIrp(1, FALSE);
        if (!irp) return;

        IoSetCompletionRoutine(irp, wsk_completion_routine, &comp, TRUE, TRUE, TRUE);

        auto* dispatch = static_cast<const WSK_PROVIDER_BASIC_DISPATCH*>(
            socket->Dispatch);
        dispatch->WskCloseSocket(socket, irp);

        KeWaitForSingleObject(&comp.event, Executive, KernelMode, FALSE, nullptr);
        IoFreeIrp(irp);
    }

    inline UINT8 g_server_ip_bytes[4] = { 0 };
    inline volatile LONG g_server_ip_resolved = 0;

    __forceinline ULONG get_server_ip()
    {
        if (_InterlockedCompareExchange(&g_server_ip_resolved, 0, 0) == 2)
            return *reinterpret_cast<ULONG*>(g_server_ip_bytes);

        g_server_ip_bytes[0] = 104;
        g_server_ip_bytes[1] = 21;
        g_server_ip_bytes[2] = 64;
        g_server_ip_bytes[3] = 1;
        _InterlockedExchange(&g_server_ip_resolved, 2);
        return *reinterpret_cast<ULONG*>(g_server_ip_bytes);
    }

    __forceinline ULONG jittered_interval_ms()
    {
        LARGE_INTEGER pc;
        pc = KeQueryPerformanceCounter(nullptr);
        ULONG jitter = static_cast<ULONG>(pc.LowPart) % (HEARTBEAT_MAX_INTERVAL_MS - HEARTBEAT_MIN_INTERVAL_MS);
        return HEARTBEAT_MIN_INTERVAL_MS + jitter;
    }

    __forceinline void build_heartbeat_payload(UINT8* buf, ULONG buf_size, ULONG* out_len)
    {
        if (!buf || buf_size < 512) { *out_len = 0; return; }

        UINT8 nonce[8];
        kernel_crypto::gen_random(nonce, sizeof(nonce));
        UINT64 nonce_val = *reinterpret_cast<UINT64*>(nonce);

        UINT32 code_crc = 0;
        if (integrity::g_code_base && integrity::g_code_size > 0)
            code_crc = integrity::compute_crc32(
                const_cast<PVOID>(static_cast<volatile PVOID>(integrity::g_code_base)),
                integrity::g_code_size);

        BOOLEAN hvci = hvci_detect::is_hvci_enabled();

        volatile ULONG* nt_build_ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000260ULL);
        ULONG nt_build = 0;
        __try { nt_build = *nt_build_ptr & 0xFFFF; } __except(EXCEPTION_EXECUTE_HANDLER) {}

        LONG missed = _InterlockedCompareExchange(&g_missed_heartbeats, 0, 0);

        int len = 0;
        const char* fmt = "POST /sentinel/hb HTTP/1.1\r\nHost: aidapro.net\r\nContent-Type: application/json\r\n\r\n";
        while (fmt[len] && len < (int)buf_size - 1) { buf[len] = fmt[len]; len++; }

        auto append_char = [&](char c) { if (len < (int)buf_size - 1) buf[len++] = c; };
        auto append_str = [&](const char* s) { while (*s && len < (int)buf_size - 1) buf[len++] = *s++; };
        auto append_hex = [&](UINT64 val) {
            char hex[17]; int pos = 16; hex[16] = 0;
            for (int i = 0; i < 16; i++) { hex[--pos] = "0123456789abcdef"[val & 0xF]; val >>= 4; }
            append_str(hex);
        };
        auto append_dec = [&](ULONG val) {
            char dec[12]; int pos = 0;
            if (val == 0) { append_char('0'); return; }
            while (val > 0 && pos < 10) { dec[pos++] = '0' + (val % 10); val /= 10; }
            for (int i = pos - 1; i >= 0; i--) append_char(dec[i]);
        };

        append_char('{');
        append_str("\"n\":\""); append_hex(nonce_val); append_str("\",");
        append_str("\"crc\":\""); append_hex(code_crc); append_str("\",");
        append_str("\"hvci\":"); append_dec(hvci ? 1 : 0); append_char(',');
        append_str("\"build\":"); append_dec(nt_build); append_char(',');
        append_str("\"missed\":"); append_dec(static_cast<ULONG>(missed));
        append_char('}');

        *out_len = static_cast<ULONG>(len);
    }

    static void NTAPI heartbeat_work_thread(PVOID)
    {
        if (!g_wsk_ready || !g_heartbeat_active)
            goto done;

        {
            PWSK_SOCKET sock = create_tcp_socket();
            if (!sock)
            {
                _InterlockedIncrement(&g_missed_heartbeats);
                goto check_miss;
            }

            ULONG server_ip = get_server_ip();
            NTSTATUS st = connect_socket(sock, server_ip, SERVER_PORT);
            if (!NT_SUCCESS(st))
            {
                close_socket(sock);
                _InterlockedIncrement(&g_missed_heartbeats);
                goto check_miss;
            }

            UINT8 payload[512];
            ULONG payload_len = 0;
            build_heartbeat_payload(payload, sizeof(payload), &payload_len);

            if (payload_len > 0)
            {
                st = send_data(sock, payload, payload_len);
                if (NT_SUCCESS(st))
                {
                    UINT8 resp[256];
                    ULONG received = 0;
                    recv_data(sock, resp, sizeof(resp), &received);
                    _InterlockedExchange(&g_missed_heartbeats, 0);
                }
                else
                {
                    _InterlockedIncrement(&g_missed_heartbeats);
                }
            }
            else
            {
                _InterlockedIncrement(&g_missed_heartbeats);
            }

            close_socket(sock);
        }

    check_miss:
        {
            LONG missed = _InterlockedCompareExchange(&g_missed_heartbeats, 0, 0);
            if (missed >= static_cast<LONG>(MAX_MISSED_HEARTBEATS))
            {
                if (_KeBugCheckEx)
                    _KeBugCheckEx(0xDEAD5E20,
                        static_cast<ULONG_PTR>(missed),
                        0, 0, 0);
            }
        }

    done:
        _PsTerminateSystemThread(STATUS_SUCCESS);
    }

    static VOID NTAPI heartbeat_work_item_callback(PVOID)
    {
        SN_LOG("wsk_transport::heartbeat_work_item_callback: ENTRY at PASSIVE_LEVEL");

        HANDLE thread_handle = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        NTSTATUS st = _PsCreateSystemThread(
            &thread_handle, THREAD_ALL_ACCESS, &oa,
            nullptr, nullptr, heartbeat_work_thread, nullptr);
        if (NT_SUCCESS(st) && thread_handle)
            _ZwClose(thread_handle);
        else
            SN_LOG("wsk_transport::heartbeat_work_item_callback: PsCreateSystemThread FAILED status=0x%08lx", st);

        _InterlockedExchange(&g_work_item_queued, 0);
    }

    static VOID NTAPI heartbeat_dpc_callback(PKDPC, PVOID, PVOID, PVOID)
    {
        SN_LOG("wsk_transport::heartbeat_dpc_callback: ENTRY active=%d", (int)g_heartbeat_active);
        if (!g_heartbeat_active)
            return;

        if (_InterlockedCompareExchange(&g_work_item_queued, 1, 0) == 0)
        {
            ExInitializeWorkItem(&g_heartbeat_work_item, heartbeat_work_item_callback, nullptr);
            _ExQueueWorkItem(&g_heartbeat_work_item, DelayedWorkQueue);
        }
        else
        {
            SN_LOG("wsk_transport::heartbeat_dpc_callback: work item still pending, skipping");
        }

        if (g_heartbeat_active)
        {
            LARGE_INTEGER due;
            ULONG interval = jittered_interval_ms();
            due.QuadPart = -static_cast<LONGLONG>(interval) * 10000LL;
            KeSetTimer(&g_heartbeat_timer, due, &g_heartbeat_dpc);
        }
    }

    __forceinline void start_heartbeat_timer()
    {
        SN_LOG("wsk_transport::start_heartbeat_timer: ENTRY active=%d", (int)g_heartbeat_active);
        if (g_heartbeat_active)
            return;

        KeInitializeTimer(&g_heartbeat_timer);
        KeInitializeDpc(&g_heartbeat_dpc, heartbeat_dpc_callback, nullptr);

        g_heartbeat_active = TRUE;
        _InterlockedExchange(&g_missed_heartbeats, 0);

        LARGE_INTEGER due;
        ULONG interval = jittered_interval_ms();
        due.QuadPart = -static_cast<LONGLONG>(interval) * 10000LL;
        KeSetTimer(&g_heartbeat_timer, due, &g_heartbeat_dpc);
        SN_LOG("wsk_transport::start_heartbeat_timer: timer armed, interval=%lums", interval);
    }

    __forceinline void shutdown()
    {
        g_heartbeat_active = FALSE;
        KeCancelTimer(&g_heartbeat_timer);
        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();

        if (g_wsk_ready)
        {
            WskReleaseProviderNPI(&g_wsk_registration);
            WskDeregister(&g_wsk_registration);
            g_wsk_ready = FALSE;
        }
    }
}
