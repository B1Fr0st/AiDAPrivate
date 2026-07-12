#pragma once

#include <ntddk.h>
#include <wsk.h>
#include <bcrypt.h>
#include "KernelCrypto.h"
#include "Integrity.h"
#include "WitnessKey.h"
#include "peer_attest.h"
#include "ProcessNotify.h"
#include "BridgeV2.h"
#include "Heartbeat.h"
#include <core/Attestation.h>

namespace wsk_transport
{
    constexpr ULONG WSK_POOL_TAG = 'wskS';
    constexpr USHORT SERVER_PORT = 443;
    constexpr ULONG  MAX_RESPONSE_SIZE = 8192;
    constexpr ULONG  HEARTBEAT_MIN_INTERVAL_MS = 30000;
    constexpr ULONG  HEARTBEAT_MAX_INTERVAL_MS = 60000;
    constexpr ULONG  MAX_MISSED_HEARTBEATS = 3;
    constexpr ULONG  TLS_RECORD_MAX = 16384 + 256;
    constexpr ULONG  TLS_AEAD_KEY_OBJECT_CAPACITY = 8192;
    constexpr ULONG  TLS_X25519_PUBLIC_BLOB_SIZE = sizeof(BCRYPT_ECCKEY_BLOB) + 64;
    constexpr ULONG  TLS_X25519_PRIVATE_BLOB_SIZE = sizeof(BCRYPT_ECCKEY_BLOB) + 96;
    constexpr UINT16 TLS_AES_128_GCM_SHA256 = 0x1301;
    constexpr UINT16 TLS_VERSION_13 = 0x0304;
    constexpr ULONG  TLS_AES_128_GCM_KEY_LEN = 16;
    constexpr ULONG  TLS_AES_256_GCM_KEY_LEN = 32;
    constexpr ULONG  TLS_GCM_IV_LEN = 12;
    constexpr UINT8  TLS_CONTENT_CHANGE_CIPHER_SPEC = 0x14;
    constexpr UINT8  TLS_CONTENT_ALERT = 0x15;
    constexpr UINT8  TLS_CONTENT_HANDSHAKE = 0x16;
    constexpr UINT8  TLS_CONTENT_APPLICATION_DATA = 0x17;
    constexpr UINT8  TLS_HANDSHAKE_SERVER_HELLO = 0x02;
    constexpr UINT8  TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS = 0x08;
    constexpr UINT8  TLS_HANDSHAKE_CERTIFICATE = 0x0B;
    constexpr UINT8  TLS_HANDSHAKE_CERTIFICATE_VERIFY = 0x0F;
    constexpr UINT8  TLS_HANDSHAKE_FINISHED = 0x14;

#ifndef SENTINEL_PIN_DEBUG_BYPASS
#define SENTINEL_PIN_DEBUG_BYPASS 0
#endif

    constexpr ULONG SPKI_PIN_HASH_LEN = 32;
    constexpr ULONG SPKI_PIN_SLOT_COUNT = 4;
    constexpr LONG  SPKI_PIN_SLOT_NONE = -1;
    constexpr LONG  SPKI_PIN_SLOT_DEBUG_BYPASS = -2;

    inline const UINT8 g_sentinel_spki_pins[SPKI_PIN_SLOT_COUNT][SPKI_PIN_HASH_LEN] = {
        {
            0x9F, 0x8C, 0x4B, 0x77, 0xE2, 0xA4, 0x53, 0x91,
            0xD7, 0x6D, 0xC1, 0x3A, 0x14, 0x88, 0xBC, 0xE9,
            0x52, 0x71, 0x5F, 0x80, 0x6B, 0xC0, 0x47, 0x29,
            0x33, 0xEC, 0xA2, 0xCD, 0xF1, 0x8B, 0x57, 0x44
        },
        {
            0x90, 0x76, 0xD3, 0xCB, 0xAD, 0x35, 0x0E, 0xD3,
            0x9B, 0xD7, 0x24, 0xBB, 0x48, 0xF7, 0x65, 0xFE,
            0x8E, 0x3D, 0xC0, 0x9F, 0x02, 0x8B, 0xE8, 0xB4,
            0x56, 0xD6, 0x9B, 0x4B, 0x9D, 0x0B, 0x00, 0xA4
        },
        {
            0xB7, 0xC5, 0x13, 0x79, 0xA4, 0xEA, 0xFA, 0xA1,
            0x6C, 0xD5, 0x81, 0x2F, 0x91, 0x54, 0x81, 0x16,
            0xD1, 0x55, 0x58, 0xA0, 0x8E, 0x6D, 0x0B, 0x9A,
            0xE3, 0x21, 0x7D, 0x12, 0xF1, 0x7D, 0x1C, 0x26
        },
        {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        }
    };

    __forceinline BOOLEAN spki_pin_slot_is_active(ULONG slot)
    {
        UINT8 acc = 0;
        for (ULONG i = 0; i < SPKI_PIN_HASH_LEN; ++i)
            acc |= g_sentinel_spki_pins[slot][i];
        return acc != 0;
    }

    __forceinline void reverse_copy_32(UINT8 out[32], const UINT8 in[32])
    {
        for (ULONG i = 0; i < 32; ++i)
            out[i] = in[31 - i];
    }

    __forceinline BOOLEAN der_read_len(const UINT8* data, ULONG total, ULONG* offset, ULONG* out_len)
    {
        if (!data || !offset || !out_len || *offset >= total) return FALSE;
        UINT8 b = data[(*offset)++];
        if ((b & 0x80u) == 0)
        {
            *out_len = b;
            return TRUE;
        }
        ULONG count = b & 0x7Fu;
        if (count == 0 || count > sizeof(ULONG) || *offset + count > total) return FALSE;
        ULONG len = 0;
        for (ULONG i = 0; i < count; ++i)
        {
            len = (len << 8) | data[(*offset)++];
        }
        if (len > total - *offset) return FALSE;
        *out_len = len;
        return TRUE;
    }

    __forceinline BOOLEAN der_read_tlv(const UINT8* data,
                                       ULONG total,
                                       ULONG* offset,
                                       UINT8* out_tag,
                                       ULONG* out_value_off,
                                       ULONG* out_value_len,
                                       ULONG* out_full_off,
                                       ULONG* out_full_len)
    {
        if (!data || !offset || !out_tag || !out_value_off || !out_value_len ||
            !out_full_off || !out_full_len || *offset >= total) return FALSE;
        ULONG start = *offset;
        UINT8 tag = data[(*offset)++];
        ULONG len = 0;
        if (!der_read_len(data, total, offset, &len)) return FALSE;
        if (len > total - *offset) return FALSE;
        *out_tag = tag;
        *out_value_off = *offset;
        *out_value_len = len;
        *offset += len;
        *out_full_off = start;
        *out_full_len = *offset - start;
        return TRUE;
    }

    __forceinline BOOLEAN extract_leaf_spki_der(const UINT8* cert,
                                                ULONG cert_len,
                                                const UINT8** out_spki,
                                                ULONG* out_spki_len)
    {
        if (!cert || !out_spki || !out_spki_len) return FALSE;
        *out_spki = nullptr;
        *out_spki_len = 0;
        ULONG off = 0;
        UINT8 tag = 0;
        ULONG value_off = 0;
        ULONG value_len = 0;
        ULONG full_off = 0;
        ULONG full_len = 0;
        if (!der_read_tlv(cert, cert_len, &off, &tag, &value_off, &value_len, &full_off, &full_len) ||
            tag != 0x30 || value_off + value_len > cert_len)
        {
            return FALSE;
        }
        ULONG cert_end = value_off + value_len;
        off = value_off;
        ULONG tbs_value_off = 0;
        ULONG tbs_value_len = 0;
        if (!der_read_tlv(cert, cert_end, &off, &tag, &tbs_value_off, &tbs_value_len, &full_off, &full_len) ||
            tag != 0x30 || tbs_value_off + tbs_value_len > cert_end)
        {
            return FALSE;
        }
        ULONG tbs_end = tbs_value_off + tbs_value_len;
        off = tbs_value_off;
        ULONG probe = off;
        if (der_read_tlv(cert, tbs_end, &probe, &tag, &value_off, &value_len, &full_off, &full_len) &&
            tag == 0xA0)
        {
            off = probe;
        }
        for (ULONG i = 0; i < 5; ++i)
        {
            if (!der_read_tlv(cert, tbs_end, &off, &tag, &value_off, &value_len, &full_off, &full_len))
                return FALSE;
        }
        if (!der_read_tlv(cert, tbs_end, &off, &tag, &value_off, &value_len, &full_off, &full_len) ||
            tag != 0x30 || full_len == 0 || full_off + full_len > cert_len)
        {
            return FALSE;
        }
        *out_spki = cert + full_off;
        *out_spki_len = full_len;
        return TRUE;
    }

    inline const char g_server_hostname[] = "aidapro.net";
    inline constexpr ULONG g_server_hostname_len = sizeof(g_server_hostname) - 1;

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
    inline volatile LONGLONG     g_msg_seq = 0;

    struct wsk_completion_t
    {
        KEVENT event;
        IO_STATUS_BLOCK iosb;
    };

    struct tls13_session_t
    {
        UINT8  client_random[32];
        UINT8  server_random[32];
        UINT8  client_priv[32];
        UINT8  client_pub[32];
        UINT8  server_pub[32];
        UINT8  shared_secret[32];
        UINT8  handshake_secret[32];
        UINT8  master_secret[32];
        UINT8  client_hs_traffic_secret[32];
        UINT8  server_hs_traffic_secret[32];
        UINT8  client_app_traffic_secret[32];
        UINT8  server_app_traffic_secret[32];
        UINT8  client_traffic_key[32];
        UINT8  server_traffic_key[32];
        UINT8  client_traffic_iv[12];
        UINT8  server_traffic_iv[12];
        UINT8  spki_observed_sha256[32];
        ULONG  traffic_key_len;
        UINT16 cipher_suite;
        BOOLEAN spki_matched;
        ULONGLONG client_seq;
        ULONGLONG server_seq;
        UINT8  scratch_ch[512];
        UINT8  scratch_sh[2048];
        UINT8  scratch_transcript[2048];
        UINT8  scratch_cert_msg[8192];
        UINT8  scratch_cv_msg[1024];
        UINT8  scratch_fin_msg[256];
        UINT8  scratch_payload[1024];
        UINT8  scratch_resp[1024];
        UINT8  scratch_aead_keyobj[TLS_AEAD_KEY_OBJECT_CAPACITY];
    };

    struct tls13_handshake_reader_t
    {
        UINT8* record_buf;
        ULONG record_buf_len;
        ULONG record_len;
        ULONG record_pos;
        BOOLEAN encrypted;
        ULONG skipped_ccs;
        ULONG records_read;
    };

    static NTSTATUS hkdf_expand_label(const UINT8* secret, ULONG secret_len,
        const char* label, const UINT8* context, ULONG context_len,
        UINT8* out, ULONG out_len)
    {
        if (!secret || !label || !out || secret_len == 0 || out_len == 0 ||
            (context_len != 0 && !context) || context_len > 255 ||
            out_len > (255UL * 32UL))
            return STATUS_INVALID_PARAMETER;

        UINT8 info[256];
        ULONG info_len = 0;
        info[info_len++] = static_cast<UINT8>((out_len >> 8) & 0xFF);
        info[info_len++] = static_cast<UINT8>(out_len & 0xFF);
        UINT8 prefix_len = 6;
        ULONG label_len = 0;
        while (label[label_len])
        {
            ++label_len;
            if (label_len > 249)
                return STATUS_INVALID_PARAMETER;
        }
        if (3 + prefix_len + label_len + context_len > sizeof(info))
            return STATUS_BUFFER_TOO_SMALL;
        info[info_len++] = static_cast<UINT8>(prefix_len + label_len);
        const char* prefix = "tls13 ";
        for (UINT8 i = 0; i < prefix_len; ++i) info[info_len++] = prefix[i];
        for (ULONG i = 0; i < label_len; ++i) info[info_len++] = static_cast<UINT8>(label[i]);
        info[info_len++] = static_cast<UINT8>(context_len);
        for (ULONG i = 0; i < context_len; ++i) info[info_len++] = context[i];

        UINT8 t_prev[32] = {};
        ULONG t_prev_len = 0;
        ULONG written = 0;
        UINT8 counter = 1;
        while (written < out_len)
        {
            UINT8 buf[256 + 32 + 1] = {};
            ULONG bp = 0;
            for (ULONG i = 0; i < t_prev_len; ++i) buf[bp++] = t_prev[i];
            for (ULONG i = 0; i < info_len; ++i) buf[bp++] = info[i];
            buf[bp++] = counter;
            UINT8 t_next[32] = {};
            NTSTATUS st = kernel_crypto::hmac_sha256(secret, secret_len, buf, bp, t_next);
            RtlSecureZeroMemory(buf, sizeof(buf));
            if (!NT_SUCCESS(st))
            {
                RtlSecureZeroMemory(out, out_len);
                RtlSecureZeroMemory(t_prev, sizeof(t_prev));
                RtlSecureZeroMemory(t_next, sizeof(t_next));
                return st;
            }
            ULONG copy_len = (out_len - written) < 32 ? (out_len - written) : 32;
            RtlCopyMemory(out + written, t_next, copy_len);
            RtlCopyMemory(t_prev, t_next, 32);
            RtlSecureZeroMemory(t_next, sizeof(t_next));
            t_prev_len = 32;
            written += copy_len;
            ++counter;
        }
        RtlSecureZeroMemory(t_prev, sizeof(t_prev));
        RtlSecureZeroMemory(info, sizeof(info));
        return STATUS_SUCCESS;
    }

    static NTSTATUS tls13_apply_traffic_secrets(tls13_session_t* sess,
        const UINT8 client_secret[32],
        const UINT8 server_secret[32],
        ULONG key_len)
    {
        if (!sess || !client_secret || !server_secret ||
            (key_len != TLS_AES_128_GCM_KEY_LEN && key_len != TLS_AES_256_GCM_KEY_LEN))
            return STATUS_INVALID_PARAMETER;

        RtlSecureZeroMemory(sess->client_traffic_key, sizeof(sess->client_traffic_key));
        RtlSecureZeroMemory(sess->server_traffic_key, sizeof(sess->server_traffic_key));
        RtlSecureZeroMemory(sess->client_traffic_iv, sizeof(sess->client_traffic_iv));
        RtlSecureZeroMemory(sess->server_traffic_iv, sizeof(sess->server_traffic_iv));

        NTSTATUS st = hkdf_expand_label(client_secret, 32, "key", nullptr, 0,
            sess->client_traffic_key, key_len);
        if (!NT_SUCCESS(st))
        {
            sess->traffic_key_len = 0;
            return st;
        }
        st = hkdf_expand_label(server_secret, 32, "key", nullptr, 0,
            sess->server_traffic_key, key_len);
        if (!NT_SUCCESS(st))
        {
            RtlSecureZeroMemory(sess->client_traffic_key, sizeof(sess->client_traffic_key));
            sess->traffic_key_len = 0;
            return st;
        }
        st = hkdf_expand_label(client_secret, 32, "iv", nullptr, 0,
            sess->client_traffic_iv, TLS_GCM_IV_LEN);
        if (!NT_SUCCESS(st))
        {
            RtlSecureZeroMemory(sess->client_traffic_key, sizeof(sess->client_traffic_key));
            RtlSecureZeroMemory(sess->server_traffic_key, sizeof(sess->server_traffic_key));
            sess->traffic_key_len = 0;
            return st;
        }
        st = hkdf_expand_label(server_secret, 32, "iv", nullptr, 0,
            sess->server_traffic_iv, TLS_GCM_IV_LEN);
        if (!NT_SUCCESS(st))
        {
            RtlSecureZeroMemory(sess->client_traffic_key, sizeof(sess->client_traffic_key));
            RtlSecureZeroMemory(sess->server_traffic_key, sizeof(sess->server_traffic_key));
            RtlSecureZeroMemory(sess->client_traffic_iv, sizeof(sess->client_traffic_iv));
            sess->traffic_key_len = 0;
            return st;
        }

        sess->traffic_key_len = key_len;
        return STATUS_SUCCESS;
    }

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

    static PWSK_SOCKET create_tcp_socket()
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

    static NTSTATUS connect_socket(PWSK_SOCKET socket, ULONG ip_addr, USHORT port)
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

    static NTSTATUS send_data(PWSK_SOCKET socket, const UINT8* data, ULONG len)
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

    static NTSTATUS recv_data(PWSK_SOCKET socket, UINT8* buf, ULONG buf_size, ULONG* received)
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

    static NTSTATUS recv_exact(PWSK_SOCKET socket, UINT8* buf, ULONG total_len)
    {
        ULONG got_total = 0;
        while (got_total < total_len)
        {
            ULONG got = 0;
            NTSTATUS st = recv_data(socket, buf + got_total, total_len - got_total, &got);
            if (!NT_SUCCESS(st) || got == 0) return st;
            got_total += got;
        }
        return STATUS_SUCCESS;
    }

    static void close_socket(PWSK_SOCKET socket)
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
        g_server_ip_bytes[2] = 20;
        g_server_ip_bytes[3] = 46;
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

    static NTSTATUS x25519_keypair(UINT8 priv_out[32], UINT8 pub_out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(st)) return st;
        st = BCryptSetProperty(alg, BCRYPT_ECC_CURVE_NAME,
            (PUCHAR)BCRYPT_ECC_CURVE_25519,
            sizeof(BCRYPT_ECC_CURVE_25519), 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }
        BCRYPT_KEY_HANDLE key = nullptr;
        st = BCryptGenerateKeyPair(alg, &key, 255, 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }
        st = BCryptFinalizeKeyPair(key, 0);
        if (!NT_SUCCESS(st))
        {
            BCryptDestroyKey(key);
            BCryptCloseAlgorithmProvider(alg, 0);
            return st;
        }
        UINT8 blob[128] = {};
        ULONG blob_len = 0;
        st = BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB,
            blob, sizeof(blob), &blob_len, 0);
        if (NT_SUCCESS(st) && blob_len >= TLS_X25519_PRIVATE_BLOB_SIZE)
        {
            BCRYPT_ECCKEY_BLOB* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob);
            if (hdr->dwMagic != BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC || hdr->cbKey != 32)
            {
                SN_LOG("tls13_x25519: private_blob_unexpected magic=0x%08lx cbKey=%lu len=%lu",
                    hdr->dwMagic, hdr->cbKey, blob_len);
                RtlSecureZeroMemory(blob, sizeof(blob));
                BCryptDestroyKey(key);
                BCryptCloseAlgorithmProvider(alg, 0);
                return STATUS_INVALID_PARAMETER;
            }
            UINT8* keymat = blob + sizeof(BCRYPT_ECCKEY_BLOB);
            RtlCopyMemory(pub_out, keymat, 32);
            RtlCopyMemory(priv_out, keymat + 64, 32);
        }
        else
        {
            SN_LOG("tls13_x25519: private_export_failed status=0x%08lx len=%lu",
                st, blob_len);
            RtlSecureZeroMemory(blob, sizeof(blob));
            BCryptDestroyKey(key);
            BCryptCloseAlgorithmProvider(alg, 0);
            return NT_SUCCESS(st) ? STATUS_INVALID_PARAMETER : st;
        }
        RtlSecureZeroMemory(blob, sizeof(blob));
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return STATUS_SUCCESS;
    }

    static NTSTATUS x25519_shared(const UINT8 priv[32],
                                  const UINT8 own_pub[32],
                                  const UINT8 their_pub[32],
                                  UINT8 shared_out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(st)) return st;
        st = BCryptSetProperty(alg, BCRYPT_ECC_CURVE_NAME,
            (PUCHAR)BCRYPT_ECC_CURVE_25519,
            sizeof(BCRYPT_ECC_CURVE_25519), 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }

        UINT8 priv_blob[TLS_X25519_PRIVATE_BLOB_SIZE] = {};
        UINT8 pub_blob[TLS_X25519_PUBLIC_BLOB_SIZE] = {};

        BCRYPT_ECCKEY_BLOB* priv_hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(priv_blob);
        priv_hdr->dwMagic = BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
        priv_hdr->cbKey = 32;
        RtlCopyMemory(priv_blob + sizeof(BCRYPT_ECCKEY_BLOB), own_pub, 32);
        RtlCopyMemory(priv_blob + sizeof(BCRYPT_ECCKEY_BLOB) + 64, priv, 32);

        BCRYPT_ECCKEY_BLOB* pub_hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pub_blob);
        pub_hdr->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
        pub_hdr->cbKey = 32;
        RtlCopyMemory(pub_blob + sizeof(BCRYPT_ECCKEY_BLOB), their_pub, 32);

        BCRYPT_KEY_HANDLE priv_key = nullptr;
        BCRYPT_KEY_HANDLE pub_key = nullptr;
        BCRYPT_SECRET_HANDLE secret = nullptr;
        ULONG derived_len = 0;
        UINT8 cng_secret[32] = {};

        st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB,
            &priv_key, priv_blob, sizeof(priv_blob), 0);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_x25519: private_import_failed status=0x%08lx", st);
            goto cleanup;
        }

        st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
            &pub_key, pub_blob, sizeof(pub_blob), 0);
        if (!NT_SUCCESS(st))
        {
            UINT8 peer_hash[32] = {};
            UINT8 blob_hash[32] = {};
            kernel_crypto::sha256(their_pub, 32, peer_hash);
            kernel_crypto::sha256(pub_blob, sizeof(pub_blob), blob_hash);
            SN_LOG("tls13_x25519: public_import_failed status=0x%08lx irql=%lu blob_len=%lu magic=0x%08lx cbKey=%lu peer_first8=%02X%02X%02X%02X%02X%02X%02X%02X peer_last8=%02X%02X%02X%02X%02X%02X%02X%02X peer_sha256=%02X%02X%02X%02X%02X%02X%02X%02X blob_x_first8=%02X%02X%02X%02X%02X%02X%02X%02X blob_x_last8=%02X%02X%02X%02X%02X%02X%02X%02X blob_sha256=%02X%02X%02X%02X%02X%02X%02X%02X",
                st,
                KeGetCurrentIrql(),
                (ULONG)sizeof(pub_blob),
                pub_hdr->dwMagic,
                pub_hdr->cbKey,
                their_pub[0], their_pub[1], their_pub[2], their_pub[3],
                their_pub[4], their_pub[5], their_pub[6], their_pub[7],
                their_pub[24], their_pub[25], their_pub[26], their_pub[27],
                their_pub[28], their_pub[29], their_pub[30], their_pub[31],
                peer_hash[0], peer_hash[1], peer_hash[2], peer_hash[3],
                peer_hash[4], peer_hash[5], peer_hash[6], peer_hash[7],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 0],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 1],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 2],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 3],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 4],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 5],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 6],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 7],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 24],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 25],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 26],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 27],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 28],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 29],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 30],
                pub_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 31],
                blob_hash[0], blob_hash[1], blob_hash[2], blob_hash[3],
                blob_hash[4], blob_hash[5], blob_hash[6], blob_hash[7]);
            goto cleanup;
        }

        st = BCryptSecretAgreement(priv_key, pub_key, &secret, 0);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_x25519: secret_agreement_failed status=0x%08lx", st);
            goto cleanup;
        }

        st = BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr,
            cng_secret, sizeof(cng_secret), &derived_len, 0);
        if (NT_SUCCESS(st) && derived_len != 32)
            st = STATUS_DATA_ERROR;
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_x25519: derive_raw_secret_failed status=0x%08lx len=%lu",
                st, derived_len);
            RtlSecureZeroMemory(shared_out, 32);
        }
        else
        {
            reverse_copy_32(shared_out, cng_secret);
        }

    cleanup:
        if (secret)
            BCryptDestroySecret(secret);
        if (pub_key)
            BCryptDestroyKey(pub_key);
        if (priv_key)
            BCryptDestroyKey(priv_key);
        RtlSecureZeroMemory(priv_blob, sizeof(priv_blob));
        RtlSecureZeroMemory(pub_blob, sizeof(pub_blob));
        RtlSecureZeroMemory(cng_secret, sizeof(cng_secret));
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }

    static NTSTATUS aead_encrypt_aesgcm(const UINT8* key, ULONG key_len, const UINT8 iv[12],
        const UINT8* aad, ULONG aad_len,
        const UINT8* pt, ULONG pt_len,
        UINT8* ct_out, UINT8 tag_out[16],
        UINT8* keyobj, ULONG keyobj_capacity)
    {
        if (!key || !iv || !pt || !ct_out || !tag_out ||
            (key_len != TLS_AES_128_GCM_KEY_LEN && key_len != TLS_AES_256_GCM_KEY_LEN))
            return STATUS_INVALID_PARAMETER;

        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(st)) return st;
        st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }

        BCRYPT_KEY_HANDLE kh = nullptr;
        ULONG keyobj_size = 0;
        ULONG cb = 0;
        st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyobj_size, sizeof(keyobj_size), &cb, 0);
        if (!NT_SUCCESS(st) || keyobj_size == 0)
        {
            SN_LOG("tls13_aead_encrypt: key_object_len_failed status=0x%08lx size=%lu cb=%lu cap=%lu key_len=%lu",
                st, keyobj_size, cb, keyobj_capacity, key_len);
            BCryptCloseAlgorithmProvider(alg, 0);
            return NT_SUCCESS(st) ? STATUS_INVALID_PARAMETER : st;
        }
        UINT8* active_keyobj = keyobj;
        BOOLEAN allocated_keyobj = FALSE;
        if (!active_keyobj || keyobj_size > keyobj_capacity)
        {
            active_keyobj = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, keyobj_size, WSK_POOL_TAG));
            if (!active_keyobj)
            {
                SN_LOG("tls13_aead_encrypt: key_object_alloc_failed required=%lu cap=%lu key_len=%lu",
                    keyobj_size, keyobj_capacity, key_len);
                BCryptCloseAlgorithmProvider(alg, 0);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            allocated_keyobj = TRUE;
            SN_LOG("tls13_aead_encrypt: key_object_scratch_expanded required=%lu cap=%lu key_len=%lu",
                keyobj_size, keyobj_capacity, key_len);
        }
        RtlZeroMemory(active_keyobj, keyobj_size);
        st = BCryptGenerateSymmetricKey(alg, &kh, active_keyobj, keyobj_size,
            const_cast<PUCHAR>(key), key_len, 0);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_aead_encrypt: generate_key_failed status=0x%08lx keyobj_size=%lu cap=%lu key_len=%lu",
                st, keyobj_size, keyobj_capacity, key_len);
            RtlSecureZeroMemory(active_keyobj, keyobj_size);
            if (allocated_keyobj)
                ExFreePoolWithTag(active_keyobj, WSK_POOL_TAG);
            BCryptCloseAlgorithmProvider(alg, 0);
            return st;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(iv);
        info.cbNonce = 12;
        info.pbAuthData = const_cast<PUCHAR>(aad);
        info.cbAuthData = aad_len;
        info.pbTag = tag_out;
        info.cbTag = 16;

        ULONG out_len = 0;
        st = BCryptEncrypt(kh, const_cast<PUCHAR>(pt), pt_len, &info,
            nullptr, 0, ct_out, pt_len, &out_len, 0);
        if (NT_SUCCESS(st) && out_len != pt_len)
            st = STATUS_DATA_ERROR;
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_aead_encrypt: encrypt_failed status=0x%08lx pt_len=%lu out_len=%lu keyobj_size=%lu key_len=%lu",
                st, pt_len, out_len, keyobj_size, key_len);
        }
        BCryptDestroyKey(kh);
        RtlSecureZeroMemory(active_keyobj, keyobj_size);
        if (allocated_keyobj)
            ExFreePoolWithTag(active_keyobj, WSK_POOL_TAG);
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }

    static NTSTATUS aead_decrypt_aesgcm(const UINT8* key, ULONG key_len, const UINT8 iv[12],
        const UINT8* aad, ULONG aad_len,
        const UINT8* ct, ULONG ct_len,
        const UINT8 tag[16], UINT8* pt_out,
        UINT8* keyobj, ULONG keyobj_capacity)
    {
        if (!key || !iv || !ct || !tag || !pt_out ||
            (key_len != TLS_AES_128_GCM_KEY_LEN && key_len != TLS_AES_256_GCM_KEY_LEN))
            return STATUS_INVALID_PARAMETER;

        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(st)) return st;
        st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }

        BCRYPT_KEY_HANDLE kh = nullptr;
        ULONG keyobj_size = 0;
        ULONG cb = 0;
        st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyobj_size, sizeof(keyobj_size), &cb, 0);
        if (!NT_SUCCESS(st) || keyobj_size == 0)
        {
            SN_LOG("tls13_aead_decrypt: key_object_len_failed status=0x%08lx size=%lu cb=%lu cap=%lu key_len=%lu",
                st, keyobj_size, cb, keyobj_capacity, key_len);
            BCryptCloseAlgorithmProvider(alg, 0);
            return NT_SUCCESS(st) ? STATUS_INVALID_PARAMETER : st;
        }
        UINT8* active_keyobj = keyobj;
        BOOLEAN allocated_keyobj = FALSE;
        if (!active_keyobj || keyobj_size > keyobj_capacity)
        {
            active_keyobj = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, keyobj_size, WSK_POOL_TAG));
            if (!active_keyobj)
            {
                SN_LOG("tls13_aead_decrypt: key_object_alloc_failed required=%lu cap=%lu key_len=%lu",
                    keyobj_size, keyobj_capacity, key_len);
                BCryptCloseAlgorithmProvider(alg, 0);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            allocated_keyobj = TRUE;
            SN_LOG("tls13_aead_decrypt: key_object_scratch_expanded required=%lu cap=%lu key_len=%lu",
                keyobj_size, keyobj_capacity, key_len);
        }
        RtlZeroMemory(active_keyobj, keyobj_size);
        st = BCryptGenerateSymmetricKey(alg, &kh, active_keyobj, keyobj_size,
            const_cast<PUCHAR>(key), key_len, 0);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_aead_decrypt: generate_key_failed status=0x%08lx keyobj_size=%lu cap=%lu key_len=%lu",
                st, keyobj_size, keyobj_capacity, key_len);
            RtlSecureZeroMemory(active_keyobj, keyobj_size);
            if (allocated_keyobj)
                ExFreePoolWithTag(active_keyobj, WSK_POOL_TAG);
            BCryptCloseAlgorithmProvider(alg, 0);
            return st;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(iv);
        info.cbNonce = 12;
        info.pbAuthData = const_cast<PUCHAR>(aad);
        info.cbAuthData = aad_len;
        info.pbTag = const_cast<PUCHAR>(tag);
        info.cbTag = 16;

        ULONG out_len = 0;
        st = BCryptDecrypt(kh, const_cast<PUCHAR>(ct), ct_len, &info,
            nullptr, 0, pt_out, ct_len, &out_len, 0);
        if (NT_SUCCESS(st) && out_len != ct_len)
            st = STATUS_DATA_ERROR;
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_aead_decrypt: decrypt_failed status=0x%08lx ct_len=%lu out_len=%lu keyobj_size=%lu key_len=%lu",
                st, ct_len, out_len, keyobj_size, key_len);
        }
        BCryptDestroyKey(kh);
        RtlSecureZeroMemory(active_keyobj, keyobj_size);
        if (allocated_keyobj)
            ExFreePoolWithTag(active_keyobj, WSK_POOL_TAG);
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }

    __forceinline LONG spki_pin_match_slot(const UINT8 server_spki_sha256[SPKI_PIN_HASH_LEN])
    {
#if SENTINEL_PIN_DEBUG_BYPASS
        UNREFERENCED_PARAMETER(server_spki_sha256);
        return SPKI_PIN_SLOT_DEBUG_BYPASS;
#else
        for (ULONG slot = 0; slot < SPKI_PIN_SLOT_COUNT; ++slot)
        {
            if (!spki_pin_slot_is_active(slot))
                continue;
            UINT8 diff = 0;
            for (ULONG i = 0; i < SPKI_PIN_HASH_LEN; ++i)
                diff |= static_cast<UINT8>(server_spki_sha256[i] ^ g_sentinel_spki_pins[slot][i]);
            if (diff == 0)
                return static_cast<LONG>(slot);
        }
        return SPKI_PIN_SLOT_NONE;
#endif
    }

    static NTSTATUS tls13_send_record(PWSK_SOCKET sock, UINT8 content_type,
        const UINT8* payload, ULONG payload_len, tls13_session_t* sess,
        BOOLEAN encrypted)
    {
        if (encrypted)
        {
            if (sess->traffic_key_len != TLS_AES_128_GCM_KEY_LEN &&
                sess->traffic_key_len != TLS_AES_256_GCM_KEY_LEN)
            {
                SN_LOG("tls13_send_record: invalid_key_len=%lu cipher=0x%04X",
                    sess->traffic_key_len, sess->cipher_suite);
                return STATUS_INVALID_PARAMETER;
            }

            UINT8 nonce[12] = {};
            RtlCopyMemory(nonce, sess->client_traffic_iv, 12);
            for (int i = 0; i < 8; ++i)
                nonce[11 - i] ^= static_cast<UINT8>((sess->client_seq >> (i * 8)) & 0xFF);

            ULONG inner_len = payload_len + 1 + 16;
            UINT8* record = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, 5 + inner_len, WSK_POOL_TAG));
            if (!record) return STATUS_INSUFFICIENT_RESOURCES;

            record[0] = TLS_CONTENT_APPLICATION_DATA;
            record[1] = 0x03; record[2] = 0x03;
            record[3] = static_cast<UINT8>((inner_len >> 8) & 0xFF);
            record[4] = static_cast<UINT8>(inner_len & 0xFF);

            UINT8* inner = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, payload_len + 1, WSK_POOL_TAG));
            if (!inner)
            {
                ExFreePoolWithTag(record, WSK_POOL_TAG);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(inner, payload, payload_len);
            inner[payload_len] = content_type;

            UINT8 tag[16] = {};
            UINT8 aad[5];
            RtlCopyMemory(aad, record, 5);
            NTSTATUS st = aead_encrypt_aesgcm(sess->client_traffic_key, sess->traffic_key_len, nonce,
                aad, 5, inner, payload_len + 1, record + 5, tag,
                sess->scratch_aead_keyobj, sizeof(sess->scratch_aead_keyobj));
            ExFreePoolWithTag(inner, WSK_POOL_TAG);
            if (!NT_SUCCESS(st))
            {
                ExFreePoolWithTag(record, WSK_POOL_TAG);
                return st;
            }
            RtlCopyMemory(record + 5 + payload_len + 1, tag, 16);
            sess->client_seq++;

            st = send_data(sock, record, 5 + inner_len);
            ExFreePoolWithTag(record, WSK_POOL_TAG);
            return st;
        }
        else
        {
            UINT8 hdr[5];
            hdr[0] = content_type;
            hdr[1] = 0x03; hdr[2] = 0x03;
            hdr[3] = static_cast<UINT8>((payload_len >> 8) & 0xFF);
            hdr[4] = static_cast<UINT8>(payload_len & 0xFF);
            UINT8* buf = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, 5 + payload_len, WSK_POOL_TAG));
            if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
            RtlCopyMemory(buf, hdr, 5);
            RtlCopyMemory(buf + 5, payload, payload_len);
            NTSTATUS st = send_data(sock, buf, 5 + payload_len);
            ExFreePoolWithTag(buf, WSK_POOL_TAG);
            return st;
        }
    }

    static NTSTATUS tls13_recv_record(PWSK_SOCKET sock, UINT8* type_out,
        UINT8* payload_buf, ULONG payload_buf_len, ULONG* payload_len_out,
        tls13_session_t* sess, BOOLEAN encrypted)
    {
        UINT8 hdr[5];
        NTSTATUS st = recv_exact(sock, hdr, 5);
        if (!NT_SUCCESS(st)) return st;
        ULONG record_len = (static_cast<ULONG>(hdr[3]) << 8) | hdr[4];
        if (record_len > TLS_RECORD_MAX) return STATUS_DATA_OVERRUN;

        UINT8* record = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, record_len, WSK_POOL_TAG));
        if (!record) return STATUS_INSUFFICIENT_RESOURCES;
        st = recv_exact(sock, record, record_len);
        if (!NT_SUCCESS(st)) { ExFreePoolWithTag(record, WSK_POOL_TAG); return st; }

        if (!encrypted || hdr[0] != TLS_CONTENT_APPLICATION_DATA)
        {
            *type_out = hdr[0];
            if (record_len > payload_buf_len) { ExFreePoolWithTag(record, WSK_POOL_TAG); return STATUS_BUFFER_TOO_SMALL; }
            RtlCopyMemory(payload_buf, record, record_len);
            *payload_len_out = record_len;
            ExFreePoolWithTag(record, WSK_POOL_TAG);
            return STATUS_SUCCESS;
        }

        if (record_len < 17) { ExFreePoolWithTag(record, WSK_POOL_TAG); return STATUS_DATA_ERROR; }
        if (sess->traffic_key_len != TLS_AES_128_GCM_KEY_LEN &&
            sess->traffic_key_len != TLS_AES_256_GCM_KEY_LEN)
        {
            SN_LOG("tls13_recv_record: invalid_key_len=%lu cipher=0x%04X server_seq=%llu",
                sess->traffic_key_len, sess->cipher_suite, sess->server_seq);
            ExFreePoolWithTag(record, WSK_POOL_TAG);
            return STATUS_INVALID_PARAMETER;
        }
        ULONG ct_len = record_len - 16;
        UINT8 nonce[12] = {};
        RtlCopyMemory(nonce, sess->server_traffic_iv, 12);
        for (int i = 0; i < 8; ++i)
            nonce[11 - i] ^= static_cast<UINT8>((sess->server_seq >> (i * 8)) & 0xFF);

        UINT8* pt = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, ct_len, WSK_POOL_TAG));
        if (!pt) { ExFreePoolWithTag(record, WSK_POOL_TAG); return STATUS_INSUFFICIENT_RESOURCES; }
        st = aead_decrypt_aesgcm(sess->server_traffic_key, sess->traffic_key_len, nonce, hdr, 5,
            record, ct_len, record + ct_len, pt,
            sess->scratch_aead_keyobj, sizeof(sess->scratch_aead_keyobj));
        ExFreePoolWithTag(record, WSK_POOL_TAG);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_recv_record: decrypt_failed status=0x%08lx hdr_type=0x%02X record_len=%lu ct_len=%lu payload_cap=%lu server_seq=%llu cipher=0x%04X key_len=%lu",
                st, hdr[0], record_len, ct_len, payload_buf_len, sess->server_seq,
                sess->cipher_suite, sess->traffic_key_len);
            ExFreePoolWithTag(pt, WSK_POOL_TAG);
            return st;
        }
        sess->server_seq++;

        if (ct_len == 0) { ExFreePoolWithTag(pt, WSK_POOL_TAG); return STATUS_DATA_ERROR; }
        ULONG end = ct_len;
        while (end > 0 && pt[end - 1] == 0)
            --end;
        if (end == 0) { ExFreePoolWithTag(pt, WSK_POOL_TAG); return STATUS_DATA_ERROR; }
        UINT8 inner_type = pt[end - 1];
        ULONG plain_len = end - 1;
        if (plain_len > payload_buf_len)
        {
            ExFreePoolWithTag(pt, WSK_POOL_TAG);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(payload_buf, pt, plain_len);
        ExFreePoolWithTag(pt, WSK_POOL_TAG);
        *type_out = inner_type;
        *payload_len_out = plain_len;
        return STATUS_SUCCESS;
    }

    static NTSTATUS tls13_recv_handshake_message(PWSK_SOCKET sock,
        tls13_session_t* sess,
        tls13_handshake_reader_t* reader,
        UINT8 expected_handshake_type,
        UINT8* msg_buf,
        ULONG msg_buf_len,
        ULONG* msg_len_out)
    {
        if (!sock || !sess || !reader || !reader->record_buf || reader->record_buf_len == 0 ||
            !msg_buf || !msg_len_out)
            return STATUS_INVALID_PARAMETER;

        *msg_len_out = 0;
        ULONG copied = 0;
        ULONG needed = 4;
        UINT8 msg_type = 0;
        ULONG body_len = 0;

        while (copied < needed)
        {
            if (reader->record_pos >= reader->record_len)
            {
                reader->record_pos = 0;
                reader->record_len = 0;

                for (;;)
                {
                    UINT8 record_type = 0;
                    ULONG record_len = 0;
                    NTSTATUS st = tls13_recv_record(sock,
                        &record_type,
                        reader->record_buf,
                        reader->record_buf_len,
                        &record_len,
                        sess,
                        reader->encrypted);
                    if (!NT_SUCCESS(st))
                    {
                        SN_LOG("tls13_handshake: recv_msg_failed expected=0x%02X status=0x%08lx records=%lu copied=%lu needed=%lu",
                            expected_handshake_type, st, reader->records_read, copied, needed);
                        return st;
                    }

                    reader->records_read++;
                    UINT8 first = record_len ? reader->record_buf[0] : 0;
                    UINT8 second = record_len > 1 ? reader->record_buf[1] : 0;

                    if (record_type == TLS_CONTENT_CHANGE_CIPHER_SPEC &&
                        record_len == 1 &&
                        first == 0x01)
                    {
                        reader->skipped_ccs++;
                        SN_LOG("tls13_handshake: skipped_compat_ccs expected=0x%02X skipped=%lu records=%lu",
                            expected_handshake_type, reader->skipped_ccs, reader->records_read);
                        continue;
                    }

                    if (record_type == TLS_CONTENT_ALERT)
                    {
                        SN_LOG("tls13_handshake: alert_record expected=0x%02X len=%lu level=0x%02X desc=0x%02X records=%lu",
                            expected_handshake_type, record_len, first, second, reader->records_read);
                        return STATUS_DATA_ERROR;
                    }

                    if (record_type != TLS_CONTENT_HANDSHAKE)
                    {
                        SN_LOG("tls13_handshake: non_handshake_record expected=0x%02X record_type=0x%02X len=%lu first=0x%02X records=%lu",
                            expected_handshake_type, record_type, record_len, first, reader->records_read);
                        return STATUS_DATA_ERROR;
                    }

                    if (record_len == 0)
                    {
                        SN_LOG("tls13_handshake: empty_handshake_record expected=0x%02X records=%lu",
                            expected_handshake_type, reader->records_read);
                        return STATUS_DATA_ERROR;
                    }

                    reader->record_len = record_len;
                    reader->record_pos = 0;
                    break;
                }
            }

            ULONG available = reader->record_len - reader->record_pos;
            ULONG want = needed - copied;
            ULONG take = available < want ? available : want;
            if (copied + take > msg_buf_len)
            {
                SN_LOG("tls13_handshake: msg_buffer_overrun expected=0x%02X copied=%lu take=%lu cap=%lu",
                    expected_handshake_type, copied, take, msg_buf_len);
                return STATUS_BUFFER_TOO_SMALL;
            }

            RtlCopyMemory(msg_buf + copied, reader->record_buf + reader->record_pos, take);
            copied += take;
            reader->record_pos += take;

            if (copied == 4 && needed == 4)
            {
                msg_type = msg_buf[0];
                body_len = (static_cast<ULONG>(msg_buf[1]) << 16) |
                           (static_cast<ULONG>(msg_buf[2]) << 8) |
                           static_cast<ULONG>(msg_buf[3]);
                needed = body_len + 4;
                if (needed < 4 || needed > msg_buf_len)
                {
                    SN_LOG("tls13_handshake: msg_len_invalid expected=0x%02X actual=0x%02X body=%lu cap=%lu",
                        expected_handshake_type, msg_type, body_len, msg_buf_len);
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if (msg_type != expected_handshake_type)
                {
                    SN_LOG("tls13_handshake: msg_type_unexpected expected=0x%02X actual=0x%02X body=%lu record_remain=%lu ccs_skipped=%lu",
                        expected_handshake_type,
                        msg_type,
                        body_len,
                        reader->record_len - reader->record_pos,
                        reader->skipped_ccs);
                    return STATUS_DATA_ERROR;
                }
            }
        }

        *msg_len_out = copied;
        SN_LOG("tls13_handshake: msg_ok type=0x%02X len=%lu records=%lu record_remain=%lu ccs_skipped=%lu",
            expected_handshake_type,
            copied,
            reader->records_read,
            reader->record_len - reader->record_pos,
            reader->skipped_ccs);
        return STATUS_SUCCESS;
    }

    static NTSTATUS tls13_handshake(PWSK_SOCKET sock, tls13_session_t* sess)
    {
        sess->client_seq = 0;
        sess->server_seq = 0;
        sess->spki_matched = FALSE;
        kernel_crypto::gen_random(sess->client_random, 32);
        NTSTATUS st = x25519_keypair(sess->client_priv, sess->client_pub);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: x25519_keypair_failed status=0x%08lx", st);
            return st;
        }

        UINT8* ch = sess->scratch_ch;
        RtlZeroMemory(ch, sizeof(sess->scratch_ch));
        ULONG ch_len = 0;
        ch[ch_len++] = 0x01;
        ULONG ch_body_off = ch_len;
        ch_len += 3;
        ch[ch_len++] = 0x03; ch[ch_len++] = 0x03;
        RtlCopyMemory(ch + ch_len, sess->client_random, 32); ch_len += 32;
        ch[ch_len++] = 0;
        ch[ch_len++] = 0; ch[ch_len++] = 2; ch[ch_len++] = 0x13; ch[ch_len++] = 0x01;
        ch[ch_len++] = 1; ch[ch_len++] = 0;

        ULONG ext_off = ch_len;
        ch_len += 2;

        ch[ch_len++] = 0x00; ch[ch_len++] = 0x00;
        ch[ch_len++] = 0x00; ch[ch_len++] = static_cast<UINT8>(g_server_hostname_len + 5);
        ch[ch_len++] = 0x00; ch[ch_len++] = static_cast<UINT8>(g_server_hostname_len + 3);
        ch[ch_len++] = 0x00;
        ch[ch_len++] = 0x00; ch[ch_len++] = static_cast<UINT8>(g_server_hostname_len);
        for (ULONG i = 0; i < g_server_hostname_len; ++i) ch[ch_len++] = g_server_hostname[i];

        ch[ch_len++] = 0x00; ch[ch_len++] = 0x2B;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x03;
        ch[ch_len++] = 0x02; ch[ch_len++] = 0x03; ch[ch_len++] = 0x04;

        ch[ch_len++] = 0x00; ch[ch_len++] = 0x0A;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x04;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x02;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x1D;

        ch[ch_len++] = 0x00; ch[ch_len++] = 0x33;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x26;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x24;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x1D;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x20;
        RtlCopyMemory(ch + ch_len, sess->client_pub, 32); ch_len += 32;

        ch[ch_len++] = 0x00; ch[ch_len++] = 0x0D;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x06;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x04;
        ch[ch_len++] = 0x04; ch[ch_len++] = 0x03;
        ch[ch_len++] = 0x08; ch[ch_len++] = 0x04;

        ULONG ext_len = ch_len - ext_off - 2;
        ch[ext_off] = static_cast<UINT8>((ext_len >> 8) & 0xFF);
        ch[ext_off + 1] = static_cast<UINT8>(ext_len & 0xFF);

        ULONG body_len = ch_len - ch_body_off - 3;
        ch[ch_body_off] = 0;
        ch[ch_body_off + 1] = static_cast<UINT8>((body_len >> 8) & 0xFF);
        ch[ch_body_off + 2] = static_cast<UINT8>(body_len & 0xFF);

        st = tls13_send_record(sock, TLS_CONTENT_HANDSHAKE, ch, ch_len, sess, FALSE);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: client_hello_send_failed status=0x%08lx len=%lu", st, ch_len);
            return st;
        }

        UINT8* sh = sess->scratch_sh;
        RtlZeroMemory(sh, sizeof(sess->scratch_sh));
        ULONG sh_len = 0;
        UINT8 type = 0;
        st = tls13_recv_record(sock, &type, sh, sizeof(sess->scratch_sh), &sh_len, sess, FALSE);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: server_hello_recv_failed status=0x%08lx", st);
            return st;
        }
        if (type != TLS_CONTENT_HANDSHAKE || sh_len < 6 || sh[0] != TLS_HANDSHAKE_SERVER_HELLO)
        {
            SN_LOG("tls13_handshake: server_hello_unexpected type=0x%02X len=%lu first=0x%02X",
                type, sh_len, sh_len ? sh[0] : 0);
            return STATUS_DATA_ERROR;
        }
        if (sh_len < 38)
        {
            SN_LOG("tls13_handshake: server_hello_short len=%lu", sh_len);
            return STATUS_DATA_ERROR;
        }

        RtlCopyMemory(sess->server_random, sh + 6, 32);

        ULONG cur = 38;
        if (cur >= sh_len)
        {
            SN_LOG("tls13_handshake: server_hello_missing_session_id cur=%lu len=%lu", cur, sh_len);
            return STATUS_DATA_ERROR;
        }
        UINT8 ses_id_len = sh[cur++];
        cur += ses_id_len;
        if (cur + 3 > sh_len)
        {
            SN_LOG("tls13_handshake: server_hello_session_overrun sid_len=%u cur=%lu len=%lu",
                ses_id_len, cur, sh_len);
            return STATUS_DATA_ERROR;
        }
        UINT16 selected_cipher = static_cast<UINT16>((sh[cur] << 8) | sh[cur + 1]);
        cur += 2;
        UINT8 compression_method = sh[cur++];
        if (selected_cipher != TLS_AES_128_GCM_SHA256)
        {
            SN_LOG("tls13_handshake: unsupported_cipher=0x%04X len=%lu", selected_cipher, sh_len);
            return STATUS_NOT_SUPPORTED;
        }
        if (compression_method != 0)
        {
            SN_LOG("tls13_handshake: invalid_compression method=0x%02X cipher=0x%04X",
                compression_method, selected_cipher);
            return STATUS_DATA_ERROR;
        }
        sess->cipher_suite = selected_cipher;
        sess->traffic_key_len = TLS_AES_128_GCM_KEY_LEN;
        if (cur + 2 > sh_len)
        {
            SN_LOG("tls13_handshake: server_hello_missing_extensions_len cur=%lu len=%lu", cur, sh_len);
            return STATUS_DATA_ERROR;
        }
        UINT16 extensions_len = static_cast<UINT16>((sh[cur] << 8) | sh[cur + 1]);
        cur += 2;
        if (cur + extensions_len > sh_len)
        {
            SN_LOG("tls13_handshake: server_hello_extensions_overrun ext_len=%u cur=%lu len=%lu",
                extensions_len, cur, sh_len);
            return STATUS_DATA_ERROR;
        }
        ULONG extensions_end = cur + extensions_len;

        BOOLEAN got_pub = FALSE;
        BOOLEAN got_tls13_version = FALSE;
        UINT16 selected_version = 0;
        while (cur + 4 <= extensions_end)
        {
            UINT16 ext_type = static_cast<UINT16>((sh[cur] << 8) | sh[cur + 1]);
            UINT16 ext_size = static_cast<UINT16>((sh[cur + 2] << 8) | sh[cur + 3]);
            cur += 4;
            if (cur + ext_size > extensions_end)
            {
                SN_LOG("tls13_handshake: server_hello_ext_overrun ext=0x%04X size=%u cur=%lu end=%lu len=%lu",
                    ext_type, ext_size, cur, extensions_end, sh_len);
                return STATUS_DATA_ERROR;
            }
            if (ext_type == 0x33 && ext_size >= 36)
            {
                ULONG p = cur;
                UINT16 group = static_cast<UINT16>((sh[p] << 8) | sh[p + 1]);
                UINT16 ksize = static_cast<UINT16>((sh[p + 2] << 8) | sh[p + 3]);
                SN_LOG("tls13_handshake: key_share_ext size=%u group=0x%04X ksize=%u cur=%lu end=%lu",
                    ext_size, group, ksize, cur, extensions_end);
                if (group == 0x001D && ksize == 32)
                {
                    RtlCopyMemory(sess->server_pub, sh + p + 4, 32);
                    UINT8 server_pub_hash[32] = {};
                    kernel_crypto::sha256(sess->server_pub, 32, server_pub_hash);
                    SN_LOG("tls13_handshake: server_x25519_pub first8=%02X%02X%02X%02X%02X%02X%02X%02X last8=%02X%02X%02X%02X%02X%02X%02X%02X sha256=%02X%02X%02X%02X%02X%02X%02X%02X",
                        sess->server_pub[0], sess->server_pub[1], sess->server_pub[2], sess->server_pub[3],
                        sess->server_pub[4], sess->server_pub[5], sess->server_pub[6], sess->server_pub[7],
                        sess->server_pub[24], sess->server_pub[25], sess->server_pub[26], sess->server_pub[27],
                        sess->server_pub[28], sess->server_pub[29], sess->server_pub[30], sess->server_pub[31],
                        server_pub_hash[0], server_pub_hash[1], server_pub_hash[2], server_pub_hash[3],
                        server_pub_hash[4], server_pub_hash[5], server_pub_hash[6], server_pub_hash[7]);
                    got_pub = TRUE;
                }
            }
            else if (ext_type == 0x2B && ext_size == 2)
            {
                selected_version = static_cast<UINT16>((sh[cur] << 8) | sh[cur + 1]);
                got_tls13_version = (selected_version == TLS_VERSION_13);
            }
            cur += ext_size;
        }
        if (cur != extensions_end)
        {
            SN_LOG("tls13_handshake: server_hello_ext_trailing cur=%lu end=%lu len=%lu",
                cur, extensions_end, sh_len);
            return STATUS_DATA_ERROR;
        }
        if (!got_tls13_version)
        {
            SN_LOG("tls13_handshake: tls13_version_missing_or_invalid selected=0x%04X cipher=0x%04X",
                selected_version, selected_cipher);
            return STATUS_NOT_SUPPORTED;
        }
        if (!got_pub)
        {
            SN_LOG("tls13_handshake: server_hello_missing_x25519_key len=%lu", sh_len);
            return STATUS_DATA_ERROR;
        }
        SN_LOG("tls13_handshake: server_hello_ok cipher=0x%04X key_len=%lu version=0x%04X sh_len=%lu",
            selected_cipher, sess->traffic_key_len, selected_version, sh_len);

        st = x25519_shared(sess->client_priv, sess->client_pub, sess->server_pub, sess->shared_secret);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: x25519_shared_failed status=0x%08lx", st);
            return st;
        }
        UINT8 zero[32] = {};
        UINT8 empty_hkdf_input[1] = {};
        UINT8 early_secret[32] = {};
        st = kernel_crypto::hmac_sha256(zero, 32, empty_hkdf_input, 0, early_secret);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: early_secret_failed status=0x%08lx", st);
            return st;
        }
        UINT8 derived[32] = {};
        UINT8 empty_hash[32] = {};
        st = kernel_crypto::sha256(empty_hkdf_input, 0, empty_hash);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: empty_hash_failed status=0x%08lx", st);
            return st;
        }
        st = hkdf_expand_label(early_secret, 32, "derived", empty_hash, 32, derived, 32);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: early_derived_failed status=0x%08lx", st);
            return st;
        }
        st = kernel_crypto::hmac_sha256(derived, 32, sess->shared_secret, 32, sess->handshake_secret);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: handshake_secret_failed status=0x%08lx", st);
            return st;
        }

        UINT8* transcript = sess->scratch_transcript;
        RtlZeroMemory(transcript, sizeof(sess->scratch_transcript));
        ULONG tlen = 0;
        if (ch_len + sh_len > sizeof(sess->scratch_transcript))
        {
            SN_LOG("tls13_handshake: transcript_overflow ch=%lu sh=%lu cap=%lu",
                ch_len, sh_len, (ULONG)sizeof(sess->scratch_transcript));
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(transcript + tlen, ch, ch_len); tlen += ch_len;
        RtlCopyMemory(transcript + tlen, sh, sh_len); tlen += sh_len;

        UINT8 t_hash[32] = {};
        st = kernel_crypto::sha256(transcript, tlen, t_hash);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: transcript_hash_failed status=0x%08lx len=%lu", st, tlen);
            return st;
        }

        st = hkdf_expand_label(sess->handshake_secret, 32, "c hs traffic", t_hash, 32,
            sess->client_hs_traffic_secret, 32);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: client_hs_secret_failed status=0x%08lx", st);
            return st;
        }
        st = hkdf_expand_label(sess->handshake_secret, 32, "s hs traffic", t_hash, 32,
            sess->server_hs_traffic_secret, 32);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: server_hs_secret_failed status=0x%08lx", st);
            return st;
        }
        st = tls13_apply_traffic_secrets(sess,
            sess->client_hs_traffic_secret,
            sess->server_hs_traffic_secret,
            sess->traffic_key_len);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: apply_hs_keys_failed status=0x%08lx cipher=0x%04X key_len=%lu",
                st, sess->cipher_suite, sess->traffic_key_len);
            return st;
        }
        SN_LOG("tls13_handshake: traffic_keys_ready phase=handshake cipher=0x%04X key_len=%lu",
            sess->cipher_suite, sess->traffic_key_len);

        UINT8* hs_record = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, TLS_RECORD_MAX, WSK_POOL_TAG));
        if (!hs_record)
        {
            SN_LOG("tls13_handshake: hs_record_alloc_failed size=%lu", TLS_RECORD_MAX);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tls13_handshake_reader_t hs_reader = {};
        hs_reader.record_buf = hs_record;
        hs_reader.record_buf_len = TLS_RECORD_MAX;
        hs_reader.encrypted = TRUE;

        auto release_hs_reader = [&]() {
            if (hs_reader.record_buf)
            {
                ExFreePoolWithTag(hs_reader.record_buf, WSK_POOL_TAG);
                hs_reader.record_buf = nullptr;
            }
        };

        UINT8* ee_msg = sess->scratch_resp;
        RtlZeroMemory(ee_msg, sizeof(sess->scratch_resp));
        ULONG ee_len = 0;
        st = tls13_recv_handshake_message(sock, sess, &hs_reader,
            TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS,
            ee_msg,
            sizeof(sess->scratch_resp),
            &ee_len);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: encrypted_extensions_recv_failed status=0x%08lx ccs_skipped=%lu records=%lu",
                st, hs_reader.skipped_ccs, hs_reader.records_read);
            release_hs_reader();
            return st;
        }

        UINT8* cert_msg = sess->scratch_cert_msg;
        RtlZeroMemory(cert_msg, sizeof(sess->scratch_cert_msg));
        ULONG cert_len = 0;
        st = tls13_recv_handshake_message(sock, sess, &hs_reader,
            TLS_HANDSHAKE_CERTIFICATE,
            cert_msg,
            sizeof(sess->scratch_cert_msg),
            &cert_len);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: cert_recv_failed status=0x%08lx ccs_skipped=%lu records=%lu",
                st, hs_reader.skipped_ccs, hs_reader.records_read);
            release_hs_reader();
            return st;
        }

        ULONG cp = 4;
        cp += 1;
        if (cp + 3 > cert_len)
        {
            SN_LOG("tls13_handshake: cert_context_overrun cp=%lu len=%lu", cp, cert_len);
            release_hs_reader();
            return STATUS_DATA_ERROR;
        }
        cp += 3;
        if (cp + 3 > cert_len)
        {
            SN_LOG("tls13_handshake: cert_leaf_len_missing cp=%lu len=%lu", cp, cert_len);
            release_hs_reader();
            return STATUS_DATA_ERROR;
        }
        ULONG c1_len = (static_cast<ULONG>(cert_msg[cp]) << 16)
                     | (static_cast<ULONG>(cert_msg[cp + 1]) << 8)
                     |  static_cast<ULONG>(cert_msg[cp + 2]);
        cp += 3;
        if (cp + c1_len > cert_len)
        {
            SN_LOG("tls13_handshake: cert_leaf_overrun cp=%lu leaf=%lu len=%lu", cp, c1_len, cert_len);
            release_hs_reader();
            return STATUS_DATA_ERROR;
        }

        const UINT8* cert_bytes = cert_msg + cp;
        const UINT8* spki_der = nullptr;
        ULONG spki_der_len = 0;
        BOOLEAN spki_der_found = extract_leaf_spki_der(cert_bytes, c1_len, &spki_der, &spki_der_len);
        if (!spki_der_found || !spki_der || spki_der_len == 0)
        {
            SN_LOG("tls13_handshake: spki_der_extract_failed cert_len=%lu leaf_len=%lu",
                cert_len, c1_len);
            release_hs_reader();
            return STATUS_DATA_ERROR;
        }

        UINT8 spki_hash[32] = {};
        st = kernel_crypto::sha256(spki_der, spki_der_len, spki_hash);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: spki_hash_failed status=0x%08lx spki_der_len=%lu",
                st, spki_der_len);
            release_hs_reader();
            return st;
        }
        RtlCopyMemory(sess->spki_observed_sha256, spki_hash, 32);

        SN_LOG("tls13_handshake: cert_len=%lu cp=%lu c1_len=%lu spki_der_found=%u spki_der_off=%lu spki_der_len=%lu",
            cert_len, cp, c1_len, (UINT32)spki_der_found,
            (ULONG)(spki_der - cert_bytes), spki_der_len);
        SN_LOG("tls13_handshake: cert_first16=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            cert_bytes[0], cert_bytes[1], cert_bytes[2], cert_bytes[3],
            cert_bytes[4], cert_bytes[5], cert_bytes[6], cert_bytes[7],
            cert_bytes[8], cert_bytes[9], cert_bytes[10], cert_bytes[11],
            cert_bytes[12], cert_bytes[13], cert_bytes[14], cert_bytes[15]);
        SN_LOG("tls13_handshake: computed_sha256=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            spki_hash[0],  spki_hash[1],  spki_hash[2],  spki_hash[3],
            spki_hash[4],  spki_hash[5],  spki_hash[6],  spki_hash[7],
            spki_hash[8],  spki_hash[9],  spki_hash[10], spki_hash[11],
            spki_hash[12], spki_hash[13], spki_hash[14], spki_hash[15],
            spki_hash[16], spki_hash[17], spki_hash[18], spki_hash[19],
            spki_hash[20], spki_hash[21], spki_hash[22], spki_hash[23],
            spki_hash[24], spki_hash[25], spki_hash[26], spki_hash[27],
            spki_hash[28], spki_hash[29], spki_hash[30], spki_hash[31]);
        for (ULONG slot = 0; slot < SPKI_PIN_SLOT_COUNT; ++slot)
        {
            if (!spki_pin_slot_is_active(slot))
            {
                SN_LOG("tls13::spki_pin: slot%lu=<unpopulated>", slot);
                continue;
            }
            SN_LOG("tls13::spki_pin: slot%lu=%02X%02X%02X%02X%02X%02X%02X%02X..",
                slot,
                g_sentinel_spki_pins[slot][0], g_sentinel_spki_pins[slot][1],
                g_sentinel_spki_pins[slot][2], g_sentinel_spki_pins[slot][3],
                g_sentinel_spki_pins[slot][4], g_sentinel_spki_pins[slot][5],
                g_sentinel_spki_pins[slot][6], g_sentinel_spki_pins[slot][7]);
        }
        SN_LOG("tls13::spki_pin: presented=%02X%02X%02X%02X%02X%02X%02X%02X.. spki_der_len=%lu cert_chain_leaf_size=%lu cert_msg_total=%lu",
            spki_hash[0], spki_hash[1], spki_hash[2], spki_hash[3],
            spki_hash[4], spki_hash[5], spki_hash[6], spki_hash[7],
            spki_der_len, c1_len, cert_len);

        LONG matched_slot = spki_pin_match_slot(spki_hash);
        if (matched_slot == SPKI_PIN_SLOT_NONE)
        {
            SN_LOG("tls13::spki_pin: MISMATCH presented=%02X%02X%02X%02X%02X%02X%02X%02X.. matched=none - returning STATUS_INVALID_SIGNATURE",
                spki_hash[0], spki_hash[1], spki_hash[2], spki_hash[3],
                spki_hash[4], spki_hash[5], spki_hash[6], spki_hash[7]);
            sess->spki_matched = FALSE;
            release_hs_reader();
            return STATUS_INVALID_SIGNATURE;
        }
        if (matched_slot == SPKI_PIN_SLOT_DEBUG_BYPASS)
        {
            SN_LOG("tls13::spki_pin: matched=debug_bypass (SENTINEL_PIN_DEBUG_BYPASS=1) presented=%02X%02X%02X%02X%02X%02X%02X%02X..",
                spki_hash[0], spki_hash[1], spki_hash[2], spki_hash[3],
                spki_hash[4], spki_hash[5], spki_hash[6], spki_hash[7]);
        }
        else
        {
            SN_LOG("tls13::spki_pin: matched=slot%ld presented=%02X%02X%02X%02X%02X%02X%02X%02X..",
                matched_slot,
                spki_hash[0], spki_hash[1], spki_hash[2], spki_hash[3],
                spki_hash[4], spki_hash[5], spki_hash[6], spki_hash[7]);
        }
        sess->spki_matched = TRUE;

        UINT8* cv_msg = sess->scratch_cv_msg;
        RtlZeroMemory(cv_msg, sizeof(sess->scratch_cv_msg));
        ULONG cv_len = 0;
        st = tls13_recv_handshake_message(sock, sess, &hs_reader,
            TLS_HANDSHAKE_CERTIFICATE_VERIFY,
            cv_msg,
            sizeof(sess->scratch_cv_msg),
            &cv_len);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: cert_verify_recv_failed status=0x%08lx records=%lu",
                st, hs_reader.records_read);
            release_hs_reader();
            return st;
        }

        UINT8* fin_msg = sess->scratch_fin_msg;
        RtlZeroMemory(fin_msg, sizeof(sess->scratch_fin_msg));
        ULONG fin_len = 0;
        st = tls13_recv_handshake_message(sock, sess, &hs_reader,
            TLS_HANDSHAKE_FINISHED,
            fin_msg,
            sizeof(sess->scratch_fin_msg),
            &fin_len);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: server_finished_recv_failed status=0x%08lx records=%lu",
                st, hs_reader.records_read);
            release_hs_reader();
            return st;
        }
        release_hs_reader();

        UINT8 handshake_hash[32] = {};
        {
            kernel_crypto::sha256_ctx_t hctx;
            kernel_crypto::sha256_init(&hctx);
            kernel_crypto::sha256_update(&hctx, ch, ch_len);
            kernel_crypto::sha256_update(&hctx, sh, sh_len);
            kernel_crypto::sha256_update(&hctx, ee_msg, ee_len);
            kernel_crypto::sha256_update(&hctx, cert_msg, cert_len);
            kernel_crypto::sha256_update(&hctx, cv_msg, cv_len);
            kernel_crypto::sha256_update(&hctx, fin_msg, fin_len);
            kernel_crypto::sha256_final(&hctx, handshake_hash);
        }

        UINT8 client_finished_payload[36] = {};
        client_finished_payload[0] = TLS_HANDSHAKE_FINISHED;
        client_finished_payload[1] = 0; client_finished_payload[2] = 0; client_finished_payload[3] = 32;
        UINT8 finished_key[32] = {};
        st = hkdf_expand_label(sess->client_hs_traffic_secret, 32, "finished", nullptr, 0,
            finished_key, 32);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: client_finished_key_failed status=0x%08lx", st);
            return st;
        }
        st = kernel_crypto::hmac_sha256(finished_key, 32, handshake_hash, 32, client_finished_payload + 4);
        RtlSecureZeroMemory(finished_key, sizeof(finished_key));
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: client_finished_hmac_failed status=0x%08lx", st);
            return st;
        }
        st = tls13_send_record(sock, TLS_CONTENT_HANDSHAKE, client_finished_payload, 36, sess, TRUE);
        RtlSecureZeroMemory(client_finished_payload, sizeof(client_finished_payload));
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: client_finished_send_failed status=0x%08lx", st);
            return st;
        }

        st = hkdf_expand_label(sess->handshake_secret, 32, "derived", empty_hash, 32, derived, 32);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: hs_derived_failed status=0x%08lx", st);
            return st;
        }
        st = kernel_crypto::hmac_sha256(derived, 32, empty_hkdf_input, 0, sess->master_secret);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: master_secret_failed status=0x%08lx", st);
            return st;
        }
        st = hkdf_expand_label(sess->master_secret, 32, "c ap traffic", handshake_hash, 32,
            sess->client_app_traffic_secret, 32);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: client_app_secret_failed status=0x%08lx", st);
            return st;
        }
        st = hkdf_expand_label(sess->master_secret, 32, "s ap traffic", handshake_hash, 32,
            sess->server_app_traffic_secret, 32);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: server_app_secret_failed status=0x%08lx", st);
            return st;
        }
        st = tls13_apply_traffic_secrets(sess,
            sess->client_app_traffic_secret,
            sess->server_app_traffic_secret,
            sess->traffic_key_len);
        if (!NT_SUCCESS(st))
        {
            SN_LOG("tls13_handshake: apply_app_keys_failed status=0x%08lx cipher=0x%04X key_len=%lu",
                st, sess->cipher_suite, sess->traffic_key_len);
            return st;
        }
        sess->client_seq = 0;
        sess->server_seq = 0;
        SN_LOG("tls13_handshake: traffic_keys_ready phase=application cipher=0x%04X key_len=%lu",
            sess->cipher_suite, sess->traffic_key_len);

        return STATUS_SUCCESS;
    }

    static void build_heartbeat_payload(UINT8* buf, ULONG buf_size, ULONG* out_len,
        const UINT8 heartbeat_subkey[32])
    {
        if (!buf || buf_size < 1024) { *out_len = 0; return; }

        UINT8 nonce[8];
        kernel_crypto::gen_random(nonce, sizeof(nonce));
        UINT64 nonce_val = *reinterpret_cast<UINT64*>(nonce);

        UINT8 code_hmac[32] = {};
        if (integrity::g_code_base && integrity::g_code_size > 0)
        {
            kernel_crypto::hmac_sha256(heartbeat_subkey, 32,
                reinterpret_cast<const UINT8*>(const_cast<PVOID>(integrity::g_code_base)),
                integrity::g_code_size, code_hmac);
        }

        UINT8 peer_hash[32] = {};
        BOOLEAN peer_hash_present = FALSE;
        HANDLE peer_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&process_notify::g_protected_pid), 0, 0));
        if (peer_pid) {
            NTSTATUS st = peer_attest::refresh_peer_hash(peer_pid);
            if (NT_SUCCESS(st)) {
                peer_attest::snapshot_last_hash(peer_hash);
                peer_hash_present = TRUE;
                bridge_v2::publish_peer_code_hash(peer_hash);
            } else if (peer_attest::has_recent_hash()) {
                peer_attest::snapshot_last_hash(peer_hash);
                peer_hash_present = TRUE;
            }
        }

        BOOLEAN hvci = hvci_detect::is_hvci_enabled();

        volatile ULONG* nt_build_ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000260ULL);
        ULONG nt_build = 0;
        __try { nt_build = *nt_build_ptr & 0xFFFF; } __except(EXCEPTION_EXECUTE_HANDLER) {}

        LONG missed = _InterlockedCompareExchange(&g_missed_heartbeats, 0, 0);
        LONGLONG seq = _InterlockedIncrement64(&g_msg_seq);
        LARGE_INTEGER perf;
        KeQueryPerformanceCounter(&perf);

        int len = 0;
        const char* fmt = "POST /api/sentinel/hb HTTP/1.1\r\n"
                          "Host: aidapro.net\r\n"
                          "Content-Type: application/json\r\n"
                          "X-Sentinel-Token: ";
        while (fmt[len] && len < (int)buf_size - 1) { buf[len] = fmt[len]; ++len; }

        auto append_char = [&](char c) { if (len < (int)buf_size - 1) buf[len++] = c; };
        auto append_str = [&](const char* s) { while (*s && len < (int)buf_size - 1) buf[len++] = *s++; };
        auto append_hex_buf = [&](const UINT8* data, ULONG sz) {
            for (ULONG i = 0; i < sz && len < (int)buf_size - 2; ++i)
            {
                static const char* digits = "0123456789abcdef";
                buf[len++] = digits[(data[i] >> 4) & 0xF];
                buf[len++] = digits[data[i] & 0xF];
            }
        };
        auto append_hex = [&](UINT64 val) {
            char hex[17]; int pos = 16; hex[16] = 0;
            for (int i = 0; i < 16; ++i) { hex[--pos] = "0123456789abcdef"[val & 0xF]; val >>= 4; }
            append_str(hex);
        };
        auto append_dec = [&](ULONG val) {
            char dec[12]; int pos = 0;
            if (val == 0) { append_char('0'); return; }
            while (val > 0 && pos < 10) { dec[pos++] = '0' + (val % 10); val /= 10; }
            for (int i = pos - 1; i >= 0; --i) append_char(dec[i]);
        };
        auto append_dec_ll = [&](LONGLONG val) {
            char dec[24]; int pos = 0;
            if (val == 0) { append_char('0'); return; }
            ULONGLONG uv = (val < 0) ? (ULONGLONG)(-val) : (ULONGLONG)val;
            while (uv > 0 && pos < 22) { dec[pos++] = '0' + (uv % 10); uv /= 10; }
            for (int i = pos - 1; i >= 0; --i) append_char(dec[i]);
        };

        UINT8 token_input[96] = {};
        ULONG ti = 0;
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((seq >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((nonce_val >> (i * 8)) & 0xFF);
        RtlCopyMemory(token_input + ti, code_hmac, 16); ti += 16;
        if (peer_hash_present) {
            RtlCopyMemory(token_input + ti, peer_hash, 16);
            ti += 16;
        }
        UINT8 tok[32] = {};
        kernel_crypto::hmac_sha256(heartbeat_subkey, 32, token_input, ti, tok);
        append_hex_buf(tok, 16);
        append_str("\r\n\r\n");

        append_char('{');
        append_str("\"n\":\""); append_hex(nonce_val); append_str("\",");
        append_str("\"seq\":"); append_dec_ll(seq); append_char(',');
        append_str("\"qpc\":"); append_dec(static_cast<ULONG>(perf.LowPart)); append_char(',');
        append_str("\"crc\":\""); append_hex_buf(code_hmac, 32); append_str("\",");
        if (peer_hash_present) {
            append_str("\"peer_code_hash\":\""); append_hex_buf(peer_hash, 32); append_str("\",");
        }
        append_str("\"hvci\":"); append_dec(hvci ? 1 : 0); append_char(',');
        append_str("\"build\":"); append_dec(nt_build); append_char(',');
        append_str("\"missed\":"); append_dec(static_cast<ULONG>(missed)); append_char(',');
        append_str("\"dma\":\"");
        {
            UINT8 dma_state[8] = {};
            dma_state[0] = static_cast<UINT8>(_InterlockedCompareExchange(&heartbeat::g_dma_tier1_refused, 0, 0));
            dma_state[1] = static_cast<UINT8>(_InterlockedCompareExchange(&heartbeat::g_dma_tier2_bsod_armed, 0, 0));
            dma_state[2] = static_cast<UINT8>(_InterlockedCompareExchange(&heartbeat::g_dma_canary_count, 0, 0));
            ULONG canary_hits_val = static_cast<ULONG>(_InterlockedCompareExchange(&heartbeat::g_dma_canary_hits, 0, 0));
            dma_state[3] = static_cast<UINT8>(canary_hits_val & 0xFF);
            dma_state[4] = static_cast<UINT8>((canary_hits_val >> 8) & 0xFF);
            dma_state[5] = static_cast<UINT8>(_InterlockedCompareExchange(&heartbeat::g_dma_pcie_unknown_count, 0, 0));
            dma_state[6] = static_cast<UINT8>(_InterlockedCompareExchange(&heartbeat::g_dma_ept_anomaly, 0, 0));
            dma_state[7] = 0;
            append_hex_buf(dma_state, 8);
        }
        append_str("\"");
        append_char('}');

        *out_len = static_cast<ULONG>(len);
    }

    static void NTAPI heartbeat_work_thread(PVOID)
    {
        SN_LOG("heartbeat_work_thread: ENTRY wsk_ready=%u active=%u missed_so_far=%ld",
            (UINT32)g_wsk_ready, (UINT32)g_heartbeat_active,
            _InterlockedCompareExchange(&g_missed_heartbeats, 0, 0));

        if (!g_wsk_ready || !g_heartbeat_active)
        {
            SN_LOG("heartbeat_work_thread: SKIP - wsk_ready=%u active=%u",
                (UINT32)g_wsk_ready, (UINT32)g_heartbeat_active);
            goto done;
        }

        {
            PWSK_SOCKET sock = create_tcp_socket();
            if (!sock)
            {
                SN_LOG("heartbeat_work_thread: MISS reason=create_tcp_socket_failed");
                _InterlockedIncrement(&g_missed_heartbeats);
                goto check_miss;
            }
            SN_LOG("heartbeat_work_thread: socket=%p OK", sock);

            ULONG server_ip = get_server_ip();
            NTSTATUS st = connect_socket(sock, server_ip, SERVER_PORT);
            if (!NT_SUCCESS(st))
            {
                SN_LOG("heartbeat_work_thread: MISS reason=connect_socket_failed status=0x%08lx ip=0x%08lx port=%u",
                    st, server_ip, SERVER_PORT);
                close_socket(sock);
                _InterlockedIncrement(&g_missed_heartbeats);
                goto check_miss;
            }
            SN_LOG("heartbeat_work_thread: connect OK ip=0x%08lx port=%u", server_ip, SERVER_PORT);

            tls13_session_t* sess = static_cast<tls13_session_t*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(tls13_session_t), WSK_POOL_TAG));
            if (!sess)
            {
                SN_LOG("heartbeat_work_thread: MISS reason=session_alloc_failed size=%lu", (ULONG)sizeof(tls13_session_t));
                close_socket(sock);
                _InterlockedIncrement(&g_missed_heartbeats);
                goto check_miss;
            }
            RtlZeroMemory(sess, sizeof(*sess));
            SN_LOG("heartbeat_work_thread: session allocated %p size=%lu", sess, (ULONG)sizeof(tls13_session_t));

            st = tls13_handshake(sock, sess);
            SN_LOG("heartbeat_work_thread: tls13_handshake returned status=0x%08lx spki_matched=%u",
                st, (UINT32)sess->spki_matched);
            if (!NT_SUCCESS(st) || !sess->spki_matched)
            {
                if (st == STATUS_INVALID_SIGNATURE || (NT_SUCCESS(st) && !sess->spki_matched))
                {
                    SN_LOG("heartbeat_work_thread: MISS reason=spki_pin_mismatch status=0x%08lx", st);
                }
                else
                {
                    SN_LOG("heartbeat_work_thread: MISS reason=tls13_handshake_failed status=0x%08lx", st);
                }
                RtlSecureZeroMemory(sess, sizeof(*sess));
                ExFreePoolWithTag(sess, WSK_POOL_TAG);
                close_socket(sock);
                _InterlockedIncrement(&g_missed_heartbeats);
                goto check_miss;
            }
            SN_LOG("heartbeat_work_thread: TLS handshake OK");

            UINT8 hb_subkey[32] = {};
            if (!witness_key::derive_subkey("sentinel/hb/v1", hb_subkey))
            {
                SN_LOG("heartbeat_work_thread: MISS reason=witness_key_derive_subkey_failed");
                RtlSecureZeroMemory(sess, sizeof(*sess));
                ExFreePoolWithTag(sess, WSK_POOL_TAG);
                close_socket(sock);
                _InterlockedIncrement(&g_missed_heartbeats);
                goto check_miss;
            }

            ULONG payload_len = 0;
            build_heartbeat_payload(sess->scratch_payload, sizeof(sess->scratch_payload), &payload_len, hb_subkey);
            RtlSecureZeroMemory(hb_subkey, sizeof(hb_subkey));
            SN_LOG("heartbeat_work_thread: payload built len=%lu", payload_len);

            if (payload_len > 0)
            {
                st = tls13_send_record(sock, TLS_CONTENT_APPLICATION_DATA, sess->scratch_payload, payload_len, sess, TRUE);
                SN_LOG("heartbeat_work_thread: tls13_send_record returned 0x%08lx", st);
                if (NT_SUCCESS(st))
                {
                    ULONG resp_len = 0;
                    UINT8 type = 0;
                    NTSTATUS rst = tls13_recv_record(sock, &type, sess->scratch_resp, sizeof(sess->scratch_resp),
                        &resp_len, sess, TRUE);
                    SN_LOG("heartbeat_work_thread: tls13_recv_record returned 0x%08lx type=0x%02X resp_len=%lu",
                        rst, (UINT32)type, resp_len);
                    if (NT_SUCCESS(rst))
                    {
                        SN_LOG("heartbeat_work_thread: HEARTBEAT OK - resetting missed counter");
                        _InterlockedExchange(&g_missed_heartbeats, 0);
                    }
                    else
                    {
                        SN_LOG("heartbeat_work_thread: MISS reason=tls13_recv_record_failed status=0x%08lx", rst);
                        _InterlockedIncrement(&g_missed_heartbeats);
                    }
                }
                else
                {
                    SN_LOG("heartbeat_work_thread: MISS reason=tls13_send_record_failed status=0x%08lx", st);
                    _InterlockedIncrement(&g_missed_heartbeats);
                }
            }
            else
            {
                SN_LOG("heartbeat_work_thread: MISS reason=build_heartbeat_payload_returned_zero");
                _InterlockedIncrement(&g_missed_heartbeats);
            }

            RtlSecureZeroMemory(sess, sizeof(*sess));
            ExFreePoolWithTag(sess, WSK_POOL_TAG);
            close_socket(sock);
        }

    check_miss:
        {
            LONG missed = _InterlockedCompareExchange(&g_missed_heartbeats, 0, 0);
            SN_LOG("heartbeat_work_thread: check_miss missed=%ld threshold=%lu",
                missed, (ULONG)MAX_MISSED_HEARTBEATS);
            if (missed >= static_cast<LONG>(MAX_MISSED_HEARTBEATS))
            {
                SN_LOG("heartbeat_work_thread: missed=%ld >= threshold=%lu - cloud heartbeat unavailable, resetting_missed_without_bugcheck",
                    missed, (ULONG)MAX_MISSED_HEARTBEATS);
                _InterlockedExchange(&g_missed_heartbeats, 0);
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

    struct dma_report_state_t {
        volatile LONG queued;
        volatile LONG cmd;
        volatile LONG param;
    };

    inline dma_report_state_t g_dma_report = {};
    inline WORK_QUEUE_ITEM    g_dma_report_work_item = {};

    static void build_dma_report_payload(UINT8* buf, ULONG buf_size, ULONG* out_len,
        const UINT8 heartbeat_subkey[32], ULONG cmd, ULONG param)
    {
        if (!buf || buf_size < 1024) { *out_len = 0; return; }

        UINT8 nonce[8];
        kernel_crypto::gen_random(nonce, sizeof(nonce));
        UINT64 nonce_val = *reinterpret_cast<UINT64*>(nonce);

        UINT8 code_hmac[32] = {};
        if (integrity::g_code_base && integrity::g_code_size > 0)
        {
            kernel_crypto::hmac_sha256(heartbeat_subkey, 32,
                reinterpret_cast<const UINT8*>(const_cast<PVOID>(integrity::g_code_base)),
                integrity::g_code_size, code_hmac);
        }

        LONGLONG seq = _InterlockedIncrement64(&g_msg_seq);
        LARGE_INTEGER perf;
        KeQueryPerformanceCounter(&perf);

        volatile ULONG* nt_build_ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000260ULL);
        ULONG nt_build = 0;
        __try { nt_build = *nt_build_ptr & 0xFFFF; } __except(EXCEPTION_EXECUTE_HANDLER) {}

        int len = 0;
        const char* fmt = "POST /api/sentinel/dma-report HTTP/1.1\r\n"
                          "Host: aidapro.net\r\n"
                          "Content-Type: application/json\r\n"
                          "X-Sentinel-Token: ";
        while (fmt[len] && len < (int)buf_size - 1) { buf[len] = fmt[len]; ++len; }

        auto append_char = [&](char c) { if (len < (int)buf_size - 1) buf[len++] = c; };
        auto append_str = [&](const char* s) { while (*s && len < (int)buf_size - 1) buf[len++] = *s++; };
        auto append_hex_buf = [&](const UINT8* data, ULONG sz) {
            for (ULONG i = 0; i < sz && len < (int)buf_size - 2; ++i)
            {
                static const char* digits = "0123456789abcdef";
                buf[len++] = digits[(data[i] >> 4) & 0xF];
                buf[len++] = digits[data[i] & 0xF];
            }
        };
        auto append_hex = [&](UINT64 val) {
            char hex[17]; int pos = 16; hex[16] = 0;
            for (int i = 0; i < 16; ++i) { hex[--pos] = "0123456789abcdef"[val & 0xF]; val >>= 4; }
            append_str(hex);
        };
        auto append_dec = [&](ULONG val) {
            char dec[12]; int pos = 0;
            if (val == 0) { append_char('0'); return; }
            while (val > 0 && pos < 10) { dec[pos++] = '0' + (val % 10); val /= 10; }
            for (int i = pos - 1; i >= 0; --i) append_char(dec[i]);
        };
        auto append_dec_ll = [&](LONGLONG val) {
            char dec[24]; int pos = 0;
            if (val == 0) { append_char('0'); return; }
            ULONGLONG uv = (val < 0) ? (ULONGLONG)(-val) : (ULONGLONG)val;
            while (uv > 0 && pos < 22) { dec[pos++] = '0' + (uv % 10); uv /= 10; }
            for (int i = pos - 1; i >= 0; --i) append_char(dec[i]);
        };

        UINT8 token_input[96] = {};
        ULONG ti = 0;
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((seq >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((nonce_val >> (i * 8)) & 0xFF);
        RtlCopyMemory(token_input + ti, code_hmac, 16); ti += 16;
        UINT8 tok[32] = {};
        kernel_crypto::hmac_sha256(heartbeat_subkey, 32, token_input, ti, tok);
        append_hex_buf(tok, 16);
        append_str("\r\n\r\n");

        append_char('{');
        append_str("\"cmd\":\""); append_hex(static_cast<UINT64>(cmd)); append_str("\",");
        append_str("\"param\":\""); append_hex(static_cast<UINT64>(param)); append_str("\",");
        append_str("\"n\":\""); append_hex(nonce_val); append_str("\",");
        append_str("\"seq\":"); append_dec_ll(seq); append_char(',');
        append_str("\"qpc\":"); append_dec(static_cast<ULONG>(perf.LowPart)); append_char(',');
        append_str("\"crc\":\""); append_hex_buf(code_hmac, 32); append_str("\",");
        append_str("\"build\":"); append_dec(nt_build);
        append_char('}');

        *out_len = static_cast<ULONG>(len);
    }

    static void NTAPI dma_report_work_thread(PVOID)
    {
        SN_LOG("dma_report_work_thread: ENTRY wsk_ready=%u",
            (UINT32)g_wsk_ready);

        ULONG dma_cmd = static_cast<ULONG>(_InterlockedCompareExchange(&g_dma_report.cmd, 0, 0));
        ULONG dma_param = static_cast<ULONG>(_InterlockedCompareExchange(&g_dma_report.param, 0, 0));

        if (!g_wsk_ready)
        {
            SN_LOG("dma_report_work_thread: SKIP - wsk not ready");
            goto dma_done;
        }

        {
            PWSK_SOCKET sock = create_tcp_socket();
            if (!sock)
            {
                SN_LOG("dma_report_work_thread: FAIL - create_tcp_socket_failed");
                goto dma_done;
            }

            ULONG server_ip = get_server_ip();
            NTSTATUS st = connect_socket(sock, server_ip, SERVER_PORT);
            if (!NT_SUCCESS(st))
            {
                SN_LOG("dma_report_work_thread: FAIL - connect_socket_failed status=0x%08lx", st);
                close_socket(sock);
                goto dma_done;
            }

            tls13_session_t* sess = static_cast<tls13_session_t*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(tls13_session_t), WSK_POOL_TAG));
            if (!sess)
            {
                SN_LOG("dma_report_work_thread: FAIL - session_alloc_failed size=%lu", (ULONG)sizeof(tls13_session_t));
                close_socket(sock);
                goto dma_done;
            }
            RtlZeroMemory(sess, sizeof(*sess));

            st = tls13_handshake(sock, sess);
            if (!NT_SUCCESS(st) || !sess->spki_matched)
            {
                SN_LOG("dma_report_work_thread: FAIL - tls13_handshake status=0x%08lx spki=%u",
                    st, (UINT32)sess->spki_matched);
                RtlSecureZeroMemory(sess, sizeof(*sess));
                ExFreePoolWithTag(sess, WSK_POOL_TAG);
                close_socket(sock);
                goto dma_done;
            }

            UINT8 hb_subkey[32] = {};
            if (!witness_key::derive_subkey("sentinel/hb/v1", hb_subkey))
            {
                SN_LOG("dma_report_work_thread: FAIL - witness_key_derive_subkey_failed");
                RtlSecureZeroMemory(sess, sizeof(*sess));
                ExFreePoolWithTag(sess, WSK_POOL_TAG);
                close_socket(sock);
                goto dma_done;
            }

            ULONG payload_len = 0;
            build_dma_report_payload(sess->scratch_payload, sizeof(sess->scratch_payload),
                &payload_len, hb_subkey, dma_cmd, dma_param);
            RtlSecureZeroMemory(hb_subkey, sizeof(hb_subkey));

            if (payload_len > 0)
            {
                st = tls13_send_record(sock, TLS_CONTENT_APPLICATION_DATA,
                    sess->scratch_payload, payload_len, sess, TRUE);
                SN_LOG("dma_report_work_thread: send_record status=0x%08lx len=%lu cmd=0x%lx param=0x%lx",
                    st, payload_len, dma_cmd, dma_param);
            }
            else
            {
                SN_LOG("dma_report_work_thread: FAIL - build_dma_report_payload returned zero");
            }

            RtlSecureZeroMemory(sess, sizeof(*sess));
            ExFreePoolWithTag(sess, WSK_POOL_TAG);
            close_socket(sock);
        }

    dma_done:
        _PsTerminateSystemThread(STATUS_SUCCESS);
    }

    static VOID NTAPI dma_report_work_item_callback(PVOID)
    {
        SN_LOG("wsk_transport::dma_report_work_item_callback: ENTRY");

        HANDLE thread_handle = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        NTSTATUS st = _PsCreateSystemThread(
            &thread_handle, THREAD_ALL_ACCESS, &oa,
            nullptr, nullptr, dma_report_work_thread, nullptr);
        if (NT_SUCCESS(st) && thread_handle)
            _ZwClose(thread_handle);
        else
            SN_LOG("wsk_transport::dma_report_work_item_callback: PsCreateSystemThread FAILED status=0x%08lx", st);

        _InterlockedExchange(&g_dma_report.queued, 0);
    }

    __forceinline void queue_dma_report(ULONG cmd, ULONG param)
    {
        _InterlockedExchange(&g_dma_report.cmd, static_cast<LONG>(cmd));
        _InterlockedExchange(&g_dma_report.param, static_cast<LONG>(param));
        if (_InterlockedCompareExchange(&g_dma_report.queued, 1, 0) == 0)
        {
            ExInitializeWorkItem(&g_dma_report_work_item, dma_report_work_item_callback, nullptr);
            _ExQueueWorkItem(&g_dma_report_work_item, DelayedWorkQueue);
        }
        SN_LOG("wsk_transport::queue_dma_report: cmd=0x%lx param=0x%lx queued=%ld",
            cmd, param, _InterlockedCompareExchange(&g_dma_report.queued, 0, 0));
    }

    struct attest_report_state_t {
        volatile LONG queued;
        UINT8 payload[136];
    };

    inline attest_report_state_t g_attest_report = {};
    inline WORK_QUEUE_ITEM       g_attest_report_work_item = {};

    static void build_attest_payload(UINT8* buf, ULONG buf_size, ULONG* out_len,
        const UINT8 heartbeat_subkey[32],
        const UINT8* attest_raw, ULONG attest_raw_size)
    {
        if (!buf || buf_size < 2048 || !out_len || !attest_raw || attest_raw_size != 136) {
            if (out_len) *out_len = 0;
            return;
        }

        UINT8 nonce[8];
        kernel_crypto::gen_random(nonce, sizeof(nonce));
        UINT64 nonce_val = *reinterpret_cast<UINT64*>(nonce);

        LONGLONG seq = _InterlockedIncrement64(&g_msg_seq);
        LARGE_INTEGER perf;
        KeQueryPerformanceCounter(&perf);

        volatile ULONG* nt_build_ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000260ULL);
        ULONG nt_build = 0;
        __try { nt_build = *nt_build_ptr & 0xFFFF; } __except(EXCEPTION_EXECUTE_HANDLER) {}

        int len = 0;
        const char* fmt = "POST /api/sentinel/integrity-attest HTTP/1.1\r\n"
                          "Host: aidapro.net\r\n"
                          "Content-Type: application/json\r\n"
                          "X-Sentinel-Token: ";
        while (fmt[len] && len < (int)buf_size - 1) { buf[len] = fmt[len]; ++len; }

        auto append_char = [&](char c) { if (len < (int)buf_size - 1) buf[len++] = c; };
        auto append_str = [&](const char* s) { while (*s && len < (int)buf_size - 1) buf[len++] = *s++; };
        auto append_hex_buf = [&](const UINT8* data, ULONG sz) {
            for (ULONG i = 0; i < sz && len < (int)buf_size - 2; ++i)
            {
                static const char* digits = "0123456789abcdef";
                buf[len++] = digits[(data[i] >> 4) & 0xF];
                buf[len++] = digits[data[i] & 0xF];
            }
        };
        auto append_hex = [&](UINT64 val) {
            char hex[17]; int pos = 16; hex[16] = 0;
            for (int i = 0; i < 16; ++i) { hex[--pos] = "0123456789abcdef"[val & 0xF]; val >>= 4; }
            append_str(hex);
        };
        auto append_dec = [&](ULONG val) {
            char dec[12]; int pos = 0;
            if (val == 0) { append_char('0'); return; }
            while (val > 0 && pos < 10) { dec[pos++] = '0' + (val % 10); val /= 10; }
            for (int i = pos - 1; i >= 0; --i) append_char(dec[i]);
        };
        auto append_dec_ll = [&](LONGLONG val) {
            char dec[24]; int pos = 0;
            if (val == 0) { append_char('0'); return; }
            ULONGLONG uv = (val < 0) ? (ULONGLONG)(-val) : (ULONGLONG)val;
            while (uv > 0 && pos < 22) { dec[pos++] = '0' + (uv % 10); uv /= 10; }
            for (int i = pos - 1; i >= 0; --i) append_char(dec[i]);
        };

        const UINT8* p = attest_raw;
        UINT8 code_hmac[32] = {};
        kernel_crypto::hmac_sha256(heartbeat_subkey, 32, attest_raw, attest_raw_size, code_hmac);

        UINT8 token_input[96] = {};
        ULONG ti = 0;
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((seq >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((nonce_val >> (i * 8)) & 0xFF);
        RtlCopyMemory(token_input + ti, code_hmac, 16); ti += 16;
        UINT8 tok[32] = {};
        kernel_crypto::hmac_sha256(heartbeat_subkey, 32, token_input, ti, tok);
        append_hex_buf(tok, 16);
        append_str("\r\n\r\n");

        append_char('{');
        append_str("\"nonce\":\""); append_hex_buf(p + 0, 16); append_str("\",");
        append_str("\"usermode_code_hash\":\""); append_hex_buf(p + 16, 32); append_str("\",");
        append_str("\"timestamp\":"); append_dec_ll(static_cast<LONGLONG>(*reinterpret_cast<const UINT64*>(p + 48))); append_char(',');
        append_str("\"hardware_id\":\""); append_hex_buf(p + 56, 32); append_str("\",");
        append_str("\"build_id\":\""); append_hex_buf(p + 88, 16); append_str("\",");
        append_str("\"hmac\":\""); append_hex_buf(p + 104, 32); append_str("\",");
        append_str("\"n\":\""); append_hex(nonce_val); append_str("\",");
        append_str("\"seq\":"); append_dec_ll(seq); append_char(',');
        append_str("\"qpc\":"); append_dec(static_cast<ULONG>(perf.LowPart)); append_char(',');
        append_str("\"build\":"); append_dec(nt_build); append_char(',');
        append_str("\"watermark_state\":\"");
        if (attestation::g_watermark_state.verification_timestamp == 0) {
            append_str("0");
        } else if (attestation::g_watermark_state.watermark_verified) {
            append_str("1");
        } else {
            append_str("-1");
        }
        append_str("\"");
        append_char('}');

        *out_len = static_cast<ULONG>(len);
        RtlSecureZeroMemory(code_hmac, sizeof(code_hmac));
    }

    static void NTAPI attest_report_work_thread(PVOID)
    {
        SN_LOG("attest_report_work_thread: ENTRY wsk_ready=%u",
            (UINT32)g_wsk_ready);

        UINT8 attest_raw[136];
        RtlCopyMemory(attest_raw, g_attest_report.payload, 136);
        _InterlockedExchange(&g_attest_report.queued, 0);

        if (!g_wsk_ready)
        {
            SN_LOG("attest_report_work_thread: SKIP - wsk not ready");
            RtlSecureZeroMemory(attest_raw, sizeof(attest_raw));
            goto attest_done;
        }

        {
            PWSK_SOCKET sock = create_tcp_socket();
            if (!sock)
            {
                SN_LOG("attest_report_work_thread: FAIL - create_tcp_socket_failed");
                RtlSecureZeroMemory(attest_raw, sizeof(attest_raw));
                goto attest_done;
            }

            ULONG server_ip = get_server_ip();
            NTSTATUS st = connect_socket(sock, server_ip, SERVER_PORT);
            if (!NT_SUCCESS(st))
            {
                SN_LOG("attest_report_work_thread: FAIL - connect_socket_failed status=0x%08lx", st);
                close_socket(sock);
                RtlSecureZeroMemory(attest_raw, sizeof(attest_raw));
                goto attest_done;
            }

            tls13_session_t* sess = static_cast<tls13_session_t*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(tls13_session_t), WSK_POOL_TAG));
            if (!sess)
            {
                SN_LOG("attest_report_work_thread: FAIL - session_alloc_failed size=%lu", (ULONG)sizeof(tls13_session_t));
                close_socket(sock);
                RtlSecureZeroMemory(attest_raw, sizeof(attest_raw));
                goto attest_done;
            }
            RtlZeroMemory(sess, sizeof(*sess));

            st = tls13_handshake(sock, sess);
            if (!NT_SUCCESS(st) || !sess->spki_matched)
            {
                SN_LOG("attest_report_work_thread: FAIL - tls13_handshake status=0x%08lx spki=%u",
                    st, (UINT32)sess->spki_matched);
                RtlSecureZeroMemory(sess, sizeof(*sess));
                ExFreePoolWithTag(sess, WSK_POOL_TAG);
                close_socket(sock);
                RtlSecureZeroMemory(attest_raw, sizeof(attest_raw));
                goto attest_done;
            }

            UINT8 hb_subkey[32] = {};
            if (!witness_key::derive_subkey("sentinel/hb/v1", hb_subkey))
            {
                SN_LOG("attest_report_work_thread: FAIL - witness_key_derive_subkey_failed");
                RtlSecureZeroMemory(sess, sizeof(*sess));
                ExFreePoolWithTag(sess, WSK_POOL_TAG);
                close_socket(sock);
                RtlSecureZeroMemory(attest_raw, sizeof(attest_raw));
                RtlSecureZeroMemory(hb_subkey, sizeof(hb_subkey));
                goto attest_done;
            }

            ULONG payload_len = 0;
            build_attest_payload(sess->scratch_payload, sizeof(sess->scratch_payload),
                &payload_len, hb_subkey, attest_raw, 136);
            RtlSecureZeroMemory(hb_subkey, sizeof(hb_subkey));
            RtlSecureZeroMemory(attest_raw, sizeof(attest_raw));

            if (payload_len > 0)
            {
                st = tls13_send_record(sock, TLS_CONTENT_APPLICATION_DATA,
                    sess->scratch_payload, payload_len, sess, TRUE);
                SN_LOG("attest_report_work_thread: send_record status=0x%08lx len=%lu", st, payload_len);

                if (NT_SUCCESS(st))
                {
                    ULONG resp_len = 0;
                    UINT8 type = 0;
                    NTSTATUS rst = tls13_recv_record(sock, &type, sess->scratch_resp,
                        sizeof(sess->scratch_resp), &resp_len, sess, TRUE);
                    SN_LOG("attest_report_work_thread: recv_record status=0x%08lx type=0x%02X resp_len=%lu",
                        rst, (UINT32)type, resp_len);

                    if (NT_SUCCESS(rst) && resp_len > 0 && resp_len <= sizeof(sess->scratch_resp))
                    {
                        const UINT8* resp = sess->scratch_resp;
                        ULONG resp_sz = resp_len;

                        const UINT8* body = resp;
                        ULONG body_len = resp_sz;
                        for (ULONG i = 0; i + 3 < resp_sz; ++i) {
                            if (resp[i] == '\r' && resp[i + 1] == '\n' && resp[i + 2] == '\r' && resp[i + 3] == '\n') {
                                body = resp + i + 4;
                                body_len = resp_sz - (i + 4);
                                break;
                            }
                        }

                        if (body_len > 0) {
                            const char* needle_wm = "\"expected_watermark\":\"";
                            ULONG needle_wm_len = 22;
                            for (ULONG i = 0; i + needle_wm_len <= body_len; ++i) {
                                BOOLEAN match = TRUE;
                                for (ULONG j = 0; j < needle_wm_len; ++j) {
                                    if (static_cast<char>(body[i + j]) != needle_wm[j]) { match = FALSE; break; }
                                }
                                if (match) {
                                    ULONG val_start = i + needle_wm_len;
                                    ULONG val_end = val_start;
                                    while (val_end < body_len && body[val_end] != '"' && (val_end - val_start) < 64) {
                                        ++val_end;
                                    }
                                    ULONG hex_len = val_end - val_start;
                                    if (hex_len > 0 && hex_len <= 32 && (hex_len % 2) == 0) {
                                        UINT8 wm_bytes[16] = {};
                                        BOOLEAN hex_ok = TRUE;
                                        for (ULONG k = 0; k < hex_len; k += 2) {
                                            char hi = static_cast<char>(body[val_start + k]);
                                            char lo = static_cast<char>(body[val_start + k + 1]);
                                            auto hex_val = [](char c) -> int {
                                                if (c >= '0' && c <= '9') return c - '0';
                                                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                                                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                                                return -1;
                                            };
                                            int hv = hex_val(hi);
                                            int lv = hex_val(lo);
                                            if (hv < 0 || lv < 0) { hex_ok = FALSE; break; }
                                            wm_bytes[k / 2] = static_cast<UINT8>((hv << 4) | lv);
                                        }
                                        if (hex_ok) {
                                            RtlCopyMemory(attestation::g_watermark_state.expected_watermark, wm_bytes, hex_len / 2);
                                            SN_LOG("attest_report_work_thread: parsed expected_watermark hex_len=%lu bytes=%lu",
                                                hex_len, hex_len / 2);
                                        }
                                    }
                                    break;
                                }
                            }

                            const char* needle_rva = "\"watermark_rva\":";
                            ULONG needle_rva_len = 16;
                            for (ULONG i = 0; i + needle_rva_len <= body_len; ++i) {
                                BOOLEAN match = TRUE;
                                for (ULONG j = 0; j < needle_rva_len; ++j) {
                                    if (static_cast<char>(body[i + j]) != needle_rva[j]) { match = FALSE; break; }
                                }
                                if (match) {
                                    ULONG val_start = i + needle_rva_len;
                                    ULONG val_end = val_start;
                                    while (val_end < body_len && body[val_end] >= '0' && body[val_end] <= '9' && (val_end - val_start) < 12) {
                                        ++val_end;
                                    }
                                    if (val_end > val_start) {
                                        UINT32 rva_val = 0;
                                        for (ULONG k = val_start; k < val_end; ++k) {
                                            rva_val = rva_val * 10 + (body[k] - '0');
                                        }
                                        if (rva_val > 0) {
                                            attestation::g_watermark_state.watermark_rva = rva_val;
                                            SN_LOG("attest_report_work_thread: parsed watermark_rva=%lu", rva_val);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                SN_LOG("attest_report_work_thread: FAIL - build_attest_payload returned zero");
            }

            RtlSecureZeroMemory(sess, sizeof(*sess));
            ExFreePoolWithTag(sess, WSK_POOL_TAG);
            close_socket(sock);
        }

    attest_done:
        _PsTerminateSystemThread(STATUS_SUCCESS);
    }

    static VOID NTAPI attest_report_work_item_callback(PVOID)
    {
        SN_LOG("wsk_transport::attest_report_work_item_callback: ENTRY");

        HANDLE thread_handle = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        NTSTATUS st = _PsCreateSystemThread(
            &thread_handle, THREAD_ALL_ACCESS, &oa,
            nullptr, nullptr, attest_report_work_thread, nullptr);
        if (NT_SUCCESS(st) && thread_handle)
            _ZwClose(thread_handle);
        else
            SN_LOG("wsk_transport::attest_report_work_item_callback: PsCreateSystemThread FAILED status=0x%08lx", st);
    }

    __forceinline void send_attestation(const void* attest_data, ULONG attest_size)
    {
        if (!attest_data || attest_size != 136) {
            SN_LOG("wsk_transport::send_attestation: invalid size=%lu expected=136", attest_size);
            return;
        }
        RtlCopyMemory(g_attest_report.payload, attest_data, 136);
        if (_InterlockedCompareExchange(&g_attest_report.queued, 1, 0) == 0)
        {
            ExInitializeWorkItem(&g_attest_report_work_item, attest_report_work_item_callback, nullptr);
            _ExQueueWorkItem(&g_attest_report_work_item, DelayedWorkQueue);
        }
        SN_LOG("wsk_transport::send_attestation: queued=%ld",
            _InterlockedCompareExchange(&g_attest_report.queued, 0, 0));
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
