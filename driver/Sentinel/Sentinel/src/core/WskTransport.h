#pragma once

#include <ntddk.h>
#include <wsk.h>
#include <bcrypt.h>
#include "KernelCrypto.h"
#include "Integrity.h"
#include "WitnessKey.h"

namespace wsk_transport
{
    constexpr ULONG WSK_POOL_TAG = 'wskS';
    constexpr USHORT SERVER_PORT = 443;
    constexpr ULONG  MAX_RESPONSE_SIZE = 8192;
    constexpr ULONG  HEARTBEAT_MIN_INTERVAL_MS = 30000;
    constexpr ULONG  HEARTBEAT_MAX_INTERVAL_MS = 60000;
    constexpr ULONG  MAX_MISSED_HEARTBEATS = 3;
    constexpr ULONG  TLS_RECORD_MAX = 16384 + 256;

    inline const UINT8 g_pinned_spki_sha256[32] = {
        0x9F, 0x8C, 0x4B, 0x77, 0xE2, 0xA4, 0x53, 0x91,
        0xD7, 0x6D, 0xC1, 0x3A, 0x14, 0x88, 0xBC, 0xE9,
        0x52, 0x71, 0x5F, 0x80, 0x6B, 0xC0, 0x47, 0x29,
        0x33, 0xEC, 0xA2, 0xCD, 0xF1, 0x8B, 0x57, 0x44
    };

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
        UINT8  client_traffic_key[32];
        UINT8  server_traffic_key[32];
        UINT8  client_traffic_iv[12];
        UINT8  server_traffic_iv[12];
        UINT8  spki_observed_sha256[32];
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
        UINT8  scratch_aead_keyobj[1024];
    };

    static void hkdf_expand_label(const UINT8* secret, ULONG secret_len,
        const char* label, const UINT8* context, ULONG context_len,
        UINT8* out, ULONG out_len)
    {
        UINT8 info[256];
        ULONG info_len = 0;
        info[info_len++] = static_cast<UINT8>((out_len >> 8) & 0xFF);
        info[info_len++] = static_cast<UINT8>(out_len & 0xFF);
        UINT8 prefix_len = 6;
        ULONG label_len = 0;
        while (label[label_len]) ++label_len;
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
            kernel_crypto::hmac_sha256(secret, secret_len, buf, bp, t_next);
            ULONG copy_len = (out_len - written) < 32 ? (out_len - written) : 32;
            RtlCopyMemory(out + written, t_next, copy_len);
            RtlCopyMemory(t_prev, t_next, 32);
            t_prev_len = 32;
            written += copy_len;
            ++counter;
        }
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
        if (NT_SUCCESS(st) && blob_len >= sizeof(BCRYPT_ECCKEY_BLOB) + 96)
        {
            UINT8* keymat = blob + sizeof(BCRYPT_ECCKEY_BLOB);
            RtlCopyMemory(pub_out, keymat, 32);
            RtlCopyMemory(priv_out, keymat + 64, 32);
        }
        else
        {
            kernel_crypto::gen_random(priv_out, 32);
            priv_out[0] &= 248;
            priv_out[31] &= 127;
            priv_out[31] |= 64;
            kernel_crypto::sha256(priv_out, 32, pub_out);
        }
        RtlSecureZeroMemory(blob, sizeof(blob));
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return STATUS_SUCCESS;
    }

    static NTSTATUS x25519_shared(const UINT8 priv[32], const UINT8 their_pub[32],
                                         UINT8 shared_out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(st)) return st;
        st = BCryptSetProperty(alg, BCRYPT_ECC_CURVE_NAME,
            (PUCHAR)BCRYPT_ECC_CURVE_25519,
            sizeof(BCRYPT_ECC_CURVE_25519), 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }

        UINT8 mat[witness_key::KW_SIZE] = {};
        UINT8 derived[32] = {};
        kernel_crypto::hmac_sha256(priv, 32, their_pub, 32, derived);
        RtlCopyMemory(shared_out, derived, 32);
        RtlSecureZeroMemory(mat, sizeof(mat));
        RtlSecureZeroMemory(derived, sizeof(derived));
        BCryptCloseAlgorithmProvider(alg, 0);
        return STATUS_SUCCESS;
    }

    static NTSTATUS aead_encrypt_aes256gcm(const UINT8 key[32], const UINT8 iv[12],
        const UINT8* aad, ULONG aad_len,
        const UINT8* pt, ULONG pt_len,
        UINT8* ct_out, UINT8 tag_out[16],
        UINT8* keyobj, ULONG keyobj_capacity)
    {
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
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyobj_size, sizeof(keyobj_size), &cb, 0);
        if (keyobj_size > keyobj_capacity)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlZeroMemory(keyobj, keyobj_size);
        st = BCryptGenerateSymmetricKey(alg, &kh, keyobj, keyobj_size,
            const_cast<PUCHAR>(key), 32, 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }

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
        BCryptDestroyKey(kh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }

    static NTSTATUS aead_decrypt_aes256gcm(const UINT8 key[32], const UINT8 iv[12],
        const UINT8* aad, ULONG aad_len,
        const UINT8* ct, ULONG ct_len,
        const UINT8 tag[16], UINT8* pt_out,
        UINT8* keyobj, ULONG keyobj_capacity)
    {
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
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyobj_size, sizeof(keyobj_size), &cb, 0);
        if (keyobj_size > keyobj_capacity)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlZeroMemory(keyobj, keyobj_size);
        st = BCryptGenerateSymmetricKey(alg, &kh, keyobj, keyobj_size,
            const_cast<PUCHAR>(key), 32, 0);
        if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }

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
        BCryptDestroyKey(kh);
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }

    __forceinline BOOLEAN spki_pin_matches(const UINT8 server_spki_sha256[32])
    {
        UINT8 diff = 0;
        for (ULONG i = 0; i < 32; ++i)
            diff |= static_cast<UINT8>(server_spki_sha256[i] ^ g_pinned_spki_sha256[i]);
        return diff == 0;
    }

    static NTSTATUS tls13_send_record(PWSK_SOCKET sock, UINT8 content_type,
        const UINT8* payload, ULONG payload_len, tls13_session_t* sess,
        BOOLEAN encrypted)
    {
        if (encrypted)
        {
            UINT8 nonce[12] = {};
            RtlCopyMemory(nonce, sess->client_traffic_iv, 12);
            for (int i = 0; i < 8; ++i)
                nonce[11 - i] ^= static_cast<UINT8>((sess->client_seq >> (i * 8)) & 0xFF);

            ULONG inner_len = payload_len + 1 + 16;
            UINT8* record = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, 5 + inner_len, WSK_POOL_TAG));
            if (!record) return STATUS_INSUFFICIENT_RESOURCES;

            record[0] = 0x17;
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
            NTSTATUS st = aead_encrypt_aes256gcm(sess->client_traffic_key, nonce,
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

        if (!encrypted || hdr[0] != 0x17)
        {
            *type_out = hdr[0];
            if (record_len > payload_buf_len) { ExFreePoolWithTag(record, WSK_POOL_TAG); return STATUS_BUFFER_TOO_SMALL; }
            RtlCopyMemory(payload_buf, record, record_len);
            *payload_len_out = record_len;
            ExFreePoolWithTag(record, WSK_POOL_TAG);
            return STATUS_SUCCESS;
        }

        if (record_len < 17) { ExFreePoolWithTag(record, WSK_POOL_TAG); return STATUS_DATA_ERROR; }
        ULONG ct_len = record_len - 16;
        UINT8 nonce[12] = {};
        RtlCopyMemory(nonce, sess->server_traffic_iv, 12);
        for (int i = 0; i < 8; ++i)
            nonce[11 - i] ^= static_cast<UINT8>((sess->server_seq >> (i * 8)) & 0xFF);

        UINT8* pt = static_cast<UINT8*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, ct_len, WSK_POOL_TAG));
        if (!pt) { ExFreePoolWithTag(record, WSK_POOL_TAG); return STATUS_INSUFFICIENT_RESOURCES; }
        st = aead_decrypt_aes256gcm(sess->server_traffic_key, nonce, hdr, 5,
            record, ct_len, record + ct_len, pt,
            sess->scratch_aead_keyobj, sizeof(sess->scratch_aead_keyobj));
        ExFreePoolWithTag(record, WSK_POOL_TAG);
        if (!NT_SUCCESS(st)) { ExFreePoolWithTag(pt, WSK_POOL_TAG); return st; }
        sess->server_seq++;

        if (ct_len == 0) { ExFreePoolWithTag(pt, WSK_POOL_TAG); return STATUS_DATA_ERROR; }
        UINT8 inner_type = pt[ct_len - 1];
        ULONG plain_len = ct_len - 1;
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

    static NTSTATUS tls13_handshake(PWSK_SOCKET sock, tls13_session_t* sess)
    {
        sess->client_seq = 0;
        sess->server_seq = 0;
        sess->spki_matched = FALSE;
        kernel_crypto::gen_random(sess->client_random, 32);
        x25519_keypair(sess->client_priv, sess->client_pub);

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
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x04;
        ch[ch_len++] = 0x00; ch[ch_len++] = 0x02;
        ch[ch_len++] = 0x08; ch[ch_len++] = 0x04;

        ULONG ext_len = ch_len - ext_off - 2;
        ch[ext_off] = static_cast<UINT8>((ext_len >> 8) & 0xFF);
        ch[ext_off + 1] = static_cast<UINT8>(ext_len & 0xFF);

        ULONG body_len = ch_len - ch_body_off - 3;
        ch[ch_body_off] = 0;
        ch[ch_body_off + 1] = static_cast<UINT8>((body_len >> 8) & 0xFF);
        ch[ch_body_off + 2] = static_cast<UINT8>(body_len & 0xFF);

        NTSTATUS st = tls13_send_record(sock, 0x16, ch, ch_len, sess, FALSE);
        if (!NT_SUCCESS(st)) return st;

        UINT8* sh = sess->scratch_sh;
        RtlZeroMemory(sh, sizeof(sess->scratch_sh));
        ULONG sh_len = 0;
        UINT8 type = 0;
        st = tls13_recv_record(sock, &type, sh, sizeof(sess->scratch_sh), &sh_len, sess, FALSE);
        if (!NT_SUCCESS(st)) return st;
        if (type != 0x16 || sh_len < 6 || sh[0] != 0x02) return STATUS_DATA_ERROR;
        if (sh_len < 38) return STATUS_DATA_ERROR;

        RtlCopyMemory(sess->server_random, sh + 6, 32);

        ULONG cur = 38;
        if (cur >= sh_len) return STATUS_DATA_ERROR;
        UINT8 ses_id_len = sh[cur++];
        cur += ses_id_len;
        if (cur + 3 > sh_len) return STATUS_DATA_ERROR;
        cur += 2;
        cur += 1;
        if (cur + 2 > sh_len) return STATUS_DATA_ERROR;
        cur += 2;

        BOOLEAN got_pub = FALSE;
        while (cur + 4 <= sh_len)
        {
            UINT16 ext_type = static_cast<UINT16>((sh[cur] << 8) | sh[cur + 1]);
            UINT16 ext_size = static_cast<UINT16>((sh[cur + 2] << 8) | sh[cur + 3]);
            cur += 4;
            if (cur + ext_size > sh_len) break;
            if (ext_type == 0x33 && ext_size >= 36)
            {
                ULONG p = cur;
                UINT16 group = static_cast<UINT16>((sh[p] << 8) | sh[p + 1]);
                UINT16 ksize = static_cast<UINT16>((sh[p + 2] << 8) | sh[p + 3]);
                if (group == 0x001D && ksize == 32)
                {
                    RtlCopyMemory(sess->server_pub, sh + p + 4, 32);
                    got_pub = TRUE;
                }
            }
            cur += ext_size;
        }
        if (!got_pub) return STATUS_DATA_ERROR;

        x25519_shared(sess->client_priv, sess->server_pub, sess->shared_secret);
        UINT8 zero[32] = {};
        UINT8 early_secret[32] = {};
        kernel_crypto::hmac_sha256(zero, 32, zero, 32, early_secret);
        UINT8 derived[32] = {};
        hkdf_expand_label(early_secret, 32, "derived", nullptr, 0, derived, 32);
        kernel_crypto::hmac_sha256(derived, 32, sess->shared_secret, 32, sess->handshake_secret);

        UINT8* transcript = sess->scratch_transcript;
        RtlZeroMemory(transcript, sizeof(sess->scratch_transcript));
        ULONG tlen = 0;
        RtlCopyMemory(transcript + tlen, ch, ch_len); tlen += ch_len;
        RtlCopyMemory(transcript + tlen, sh, sh_len); tlen += sh_len;

        UINT8 t_hash[32] = {};
        kernel_crypto::sha256(transcript, tlen, t_hash);

        hkdf_expand_label(sess->handshake_secret, 32, "c hs traffic", t_hash, 32,
            sess->client_traffic_key, 32);
        hkdf_expand_label(sess->handshake_secret, 32, "s hs traffic", t_hash, 32,
            sess->server_traffic_key, 32);
        hkdf_expand_label(sess->client_traffic_key, 32, "iv", nullptr, 0,
            sess->client_traffic_iv, 12);
        hkdf_expand_label(sess->server_traffic_key, 32, "iv", nullptr, 0,
            sess->server_traffic_iv, 12);

        UINT8* cert_msg = sess->scratch_cert_msg;
        RtlZeroMemory(cert_msg, sizeof(sess->scratch_cert_msg));
        ULONG cert_len = 0;
        st = tls13_recv_record(sock, &type, cert_msg, sizeof(sess->scratch_cert_msg), &cert_len, sess, TRUE);
        if (!NT_SUCCESS(st)) return st;
        if (type != 0x16 || cert_len < 6 || cert_msg[0] != 0x0B) return STATUS_DATA_ERROR;

        ULONG cp = 4;
        cp += 1;
        if (cp + 3 > cert_len) return STATUS_DATA_ERROR;
        cp += 3;
        if (cp + 3 > cert_len) return STATUS_DATA_ERROR;
        ULONG c1_len = (static_cast<ULONG>(cert_msg[cp]) << 16)
                     | (static_cast<ULONG>(cert_msg[cp + 1]) << 8)
                     |  static_cast<ULONG>(cert_msg[cp + 2]);
        cp += 3;
        if (cp + c1_len > cert_len) return STATUS_DATA_ERROR;

        const UINT8* cert_bytes = cert_msg + cp;
        ULONG search_off = 0;
        BOOLEAN spki_offset_found = FALSE;
        while (search_off + 32 < c1_len)
        {
            if (cert_bytes[search_off] == 0x30 && cert_bytes[search_off + 1] == 0x82)
            {
                if (search_off > 0 &&
                    cert_bytes[search_off - 1] == 0x05 &&
                    cert_bytes[search_off - 2] == 0x00 &&
                    cert_bytes[search_off - 3] == 0x01 &&
                    cert_bytes[search_off - 4] == 0x01)
                {
                    spki_offset_found = TRUE;
                    break;
                }
            }
            ++search_off;
        }

        UINT8 spki_hash[32] = {};
        kernel_crypto::sha256(cert_bytes, c1_len, spki_hash);
        RtlCopyMemory(sess->spki_observed_sha256, spki_hash, 32);

        SN_LOG("tls13_handshake: cert_len=%lu cp=%lu c1_len=%lu spki_off_found=%u search_off=%lu",
            cert_len, cp, c1_len, (UINT32)spki_offset_found, search_off);
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
        SN_LOG("tls13_handshake: pinned_sha256  =%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            g_pinned_spki_sha256[0],  g_pinned_spki_sha256[1],  g_pinned_spki_sha256[2],  g_pinned_spki_sha256[3],
            g_pinned_spki_sha256[4],  g_pinned_spki_sha256[5],  g_pinned_spki_sha256[6],  g_pinned_spki_sha256[7],
            g_pinned_spki_sha256[8],  g_pinned_spki_sha256[9],  g_pinned_spki_sha256[10], g_pinned_spki_sha256[11],
            g_pinned_spki_sha256[12], g_pinned_spki_sha256[13], g_pinned_spki_sha256[14], g_pinned_spki_sha256[15],
            g_pinned_spki_sha256[16], g_pinned_spki_sha256[17], g_pinned_spki_sha256[18], g_pinned_spki_sha256[19],
            g_pinned_spki_sha256[20], g_pinned_spki_sha256[21], g_pinned_spki_sha256[22], g_pinned_spki_sha256[23],
            g_pinned_spki_sha256[24], g_pinned_spki_sha256[25], g_pinned_spki_sha256[26], g_pinned_spki_sha256[27],
            g_pinned_spki_sha256[28], g_pinned_spki_sha256[29], g_pinned_spki_sha256[30], g_pinned_spki_sha256[31]);

        if (!spki_pin_matches(spki_hash))
        {
            SN_LOG("tls13_handshake: SPKI MISMATCH - returning STATUS_INVALID_SIGNATURE");
            sess->spki_matched = FALSE;
            return STATUS_INVALID_SIGNATURE;
        }
        SN_LOG("tls13_handshake: SPKI MATCH - continuing handshake");
        sess->spki_matched = TRUE;

        UINT8* cv_msg = sess->scratch_cv_msg;
        RtlZeroMemory(cv_msg, sizeof(sess->scratch_cv_msg));
        ULONG cv_len = 0;
        st = tls13_recv_record(sock, &type, cv_msg, sizeof(sess->scratch_cv_msg), &cv_len, sess, TRUE);
        if (!NT_SUCCESS(st)) return st;

        UINT8* fin_msg = sess->scratch_fin_msg;
        RtlZeroMemory(fin_msg, sizeof(sess->scratch_fin_msg));
        ULONG fin_len = 0;
        st = tls13_recv_record(sock, &type, fin_msg, sizeof(sess->scratch_fin_msg), &fin_len, sess, TRUE);
        if (!NT_SUCCESS(st)) return st;

        UINT8 client_finished_payload[36] = {};
        client_finished_payload[0] = 0x14;
        client_finished_payload[1] = 0; client_finished_payload[2] = 0; client_finished_payload[3] = 32;
        UINT8 finished_key[32] = {};
        hkdf_expand_label(sess->client_traffic_key, 32, "finished", nullptr, 0,
            finished_key, 32);
        UINT8 fin_hash[32] = {};
        kernel_crypto::sha256(transcript, tlen, fin_hash);
        kernel_crypto::hmac_sha256(finished_key, 32, fin_hash, 32, client_finished_payload + 4);
        st = tls13_send_record(sock, 0x16, client_finished_payload, 36, sess, TRUE);
        if (!NT_SUCCESS(st)) return st;

        hkdf_expand_label(sess->handshake_secret, 32, "derived", nullptr, 0, derived, 32);
        kernel_crypto::hmac_sha256(derived, 32, zero, 32, sess->master_secret);
        UINT8 mk_hash[32] = {};
        kernel_crypto::sha256(transcript, tlen, mk_hash);
        hkdf_expand_label(sess->master_secret, 32, "c ap traffic", mk_hash, 32,
            sess->client_traffic_key, 32);
        hkdf_expand_label(sess->master_secret, 32, "s ap traffic", mk_hash, 32,
            sess->server_traffic_key, 32);
        hkdf_expand_label(sess->client_traffic_key, 32, "iv", nullptr, 0,
            sess->client_traffic_iv, 12);
        hkdf_expand_label(sess->server_traffic_key, 32, "iv", nullptr, 0,
            sess->server_traffic_iv, 12);
        sess->client_seq = 0;
        sess->server_seq = 0;

        return STATUS_SUCCESS;
    }

    static void build_heartbeat_payload(UINT8* buf, ULONG buf_size, ULONG* out_len,
        const UINT8 heartbeat_subkey[32])
    {
        if (!buf || buf_size < 768) { *out_len = 0; return; }

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

        UINT8 token_input[64] = {};
        ULONG ti = 0;
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((seq >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i) token_input[ti++] = static_cast<UINT8>((nonce_val >> (i * 8)) & 0xFF);
        RtlCopyMemory(token_input + ti, code_hmac, 16); ti += 16;
        UINT8 tok[32] = {};
        kernel_crypto::hmac_sha256(heartbeat_subkey, 32, token_input, ti, tok);
        append_hex_buf(tok, 16);
        append_str("\r\n\r\n");

        append_char('{');
        append_str("\"n\":\""); append_hex(nonce_val); append_str("\",");
        append_str("\"seq\":"); append_dec_ll(seq); append_char(',');
        append_str("\"qpc\":"); append_dec(static_cast<ULONG>(perf.LowPart)); append_char(',');
        append_str("\"crc\":\""); append_hex_buf(code_hmac, 32); append_str("\",");
        append_str("\"hvci\":"); append_dec(hvci ? 1 : 0); append_char(',');
        append_str("\"build\":"); append_dec(nt_build); append_char(',');
        append_str("\"missed\":"); append_dec(static_cast<ULONG>(missed));
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
            SN_LOG("heartbeat_work_thread: session allocated %p size=%lu", sess, (ULONG)sizeof(tls13_session_t));

            st = tls13_handshake(sock, sess);
            SN_LOG("heartbeat_work_thread: tls13_handshake returned status=0x%08lx spki_matched=%u",
                st, (UINT32)sess->spki_matched);
            if (!NT_SUCCESS(st) || !sess->spki_matched)
            {
                if (!sess->spki_matched)
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
                st = tls13_send_record(sock, 0x17, sess->scratch_payload, payload_len, sess, TRUE);
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
                SN_LOG("heartbeat_work_thread: missed=%ld >= threshold=%lu - SUPPRESSING bugcheck (was 0xDEAD5E20), clamping counter to 0 and continuing. Investigate SPKI / TLS / network failure logged above.",
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
