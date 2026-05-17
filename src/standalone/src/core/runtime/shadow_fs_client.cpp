#include "shadow_fs_client.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winternl.h>
#include <fltUser.h>
#include <mutex>
#include <atomic>
#include <cstring>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include "../../../../driver/AiDAShadowFS/AiDAShadowFS/src/ShadowFSProtocol.h"
#include "../../helpers/diag_log.hpp"

#pragma comment(lib, "fltlib.lib")

namespace {

std::mutex g_mtx;
HANDLE g_port = INVALID_HANDLE_VALUE;
std::atomic<bool> g_initialized{false};
std::string s_last_error;

void set_last_error_locked(const char* msg) {
    s_last_error.assign(msg ? msg : "");
}

void set_last_error_hr(const char* prefix, HRESULT hr) {
    char buf[256];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%s hr=0x%08lX gle=%lu",
        prefix ? prefix : "",
        static_cast<unsigned long>(hr),
        static_cast<unsigned long>(HRESULT_CODE(hr)));
    s_last_error.assign(buf);
}

bool connect_locked() {
    if (g_port != INVALID_HANDLE_VALUE) return true;
    HANDLE port = INVALID_HANDLE_VALUE;
    HRESULT hr = ::FilterConnectCommunicationPort(
        SHADOWFS_PORT_NAME,
        0,
        nullptr,
        0,
        nullptr,
        &port);
    if (FAILED(hr) || port == nullptr || port == INVALID_HANDLE_VALUE) {
        set_last_error_hr("FilterConnectCommunicationPort failed", hr);
        diag::log_tagged_critical_fmt("shadow_fs",
            "connect_FAILED hr=0x%08lX",
            static_cast<unsigned long>(hr));
        return false;
    }
    g_port = port;
    diag::log_tagged_critical_fmt("shadow_fs", "connect ok port=%p", port);
    return true;
}

bool ensure_connected_locked() {
    if (!connect_locked()) return false;
    return true;
}

bool dos_to_nt_path(const std::wstring& dos_path, std::wstring& nt_path) {
    nt_path.clear();
    if (dos_path.size() < 3) return false;
    if (dos_path[1] != L':' || dos_path[2] != L'\\') return false;
    wchar_t drive_letter[3] = { dos_path[0], L':', L'\0' };
    wchar_t target[MAX_PATH] = {};
    DWORD got = QueryDosDeviceW(drive_letter, target, MAX_PATH);
    if (got == 0) return false;
    std::wstring root(target);
    nt_path = root + std::wstring(dos_path.c_str() + 2);
    return true;
}

bool send_locked(const void* in, ULONG in_bytes,
                 void* out, ULONG out_bytes, ULONG* out_used)
{
    if (out_used) *out_used = 0;
    if (g_port == INVALID_HANDLE_VALUE) {
        set_last_error_locked("Shadow FS port not connected");
        return false;
    }
    DWORD got = 0;
    HRESULT hr = ::FilterSendMessage(
        g_port,
        const_cast<void*>(in),
        in_bytes,
        out,
        out_bytes,
        &got);
    if (FAILED(hr)) {
        set_last_error_hr("FilterSendMessage failed", hr);
        return false;
    }
    if (out_used) *out_used = got;
    return true;
}

void init_header(SHADOWFS_MSG_HEADER& h, ULONG command, ULONG payload_bytes) {
    h.magic = SHADOWFS_MSG_MAGIC;
    h.version = SHADOWFS_PROTOCOL_VERSION;
    h.command = command;
    h.payload_bytes = payload_bytes;
}

bool reply_validate_basic(unsigned long magic, unsigned long version, unsigned long status_code) {
    if (magic != SHADOWFS_MSG_MAGIC) return false;
    if (version != SHADOWFS_PROTOCOL_VERSION
        && version != SHADOWFS_PROTOCOL_VERSION_LEGACY) {
        return false;
    }
    NTSTATUS s = static_cast<NTSTATUS>(status_code);
    return NT_SUCCESS(s);
}

bool reply_is_ok(const SHADOWFS_REPLY_GENERIC& reply) {
    return reply_validate_basic(reply.magic, reply.version, reply.status);
}

bool reply_is_ok_or_logged(const SHADOWFS_REPLY_GENERIC& reply, const char* tag) {
    if (reply.magic != SHADOWFS_MSG_MAGIC) {
        diag::log_tagged_critical_fmt("shadow_fs",
            "%s reply_bad_magic 0x%08lX", tag ? tag : "?",
            static_cast<unsigned long>(reply.magic));
        return false;
    }
    if (reply.version != SHADOWFS_PROTOCOL_VERSION
        && reply.version != SHADOWFS_PROTOCOL_VERSION_LEGACY) {
        diag::log_tagged_critical_fmt("shadow_fs",
            "%s reply_bad_version 0x%08lX", tag ? tag : "?",
            static_cast<unsigned long>(reply.version));
        return false;
    }
    NTSTATUS s = static_cast<NTSTATUS>(reply.status);
    if (!NT_SUCCESS(s)) {
        diag::log_tagged_critical_fmt("shadow_fs",
            "%s reply_status=0x%08lX denials=%lld redirects=%lld copies=%lld",
            tag ? tag : "?",
            static_cast<unsigned long>(s),
            static_cast<long long>(reply.denials),
            static_cast<long long>(reply.redirects),
            static_cast<long long>(reply.copies));
        return false;
    }
    return true;
}

}

namespace shadow_fs_client {

bool initialize() {
    if (g_initialized.load(std::memory_order_acquire)) return true;
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_initialized.load(std::memory_order_relaxed)) return true;
    s_last_error.clear();
    bool ok = connect_locked();
    if (ok) {
        g_initialized.store(true, std::memory_order_release);
        diag::log_tagged_critical("shadow_fs", "initialized");
    }
    return ok;
}

void shutdown() {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_port != INVALID_HANDLE_VALUE) {
        CloseHandle(g_port);
        g_port = INVALID_HANDLE_VALUE;
    }
    g_initialized.store(false, std::memory_order_release);
    diag::log_tagged_critical("shadow_fs", "shutdown");
}

bool is_connected() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_port != INVALID_HANDLE_VALUE;
}

bool register_sandbox_pid(uint32_t pid, uint32_t flags, const std::wstring& sandbox_root) {
    if (pid == 0 || pid == 4) {
        std::lock_guard<std::mutex> lk(g_mtx);
        set_last_error_locked("Invalid PID");
        return false;
    }
    if (sandbox_root.empty()) {
        std::lock_guard<std::mutex> lk(g_mtx);
        set_last_error_locked("Empty sandbox root");
        return false;
    }

    std::wstring nt_root;
    if (!dos_to_nt_path(sandbox_root, nt_root)) {
        std::lock_guard<std::mutex> lk(g_mtx);
        set_last_error_locked("Failed to convert sandbox root to NT path");
        diag::log_tagged_critical_fmt("shadow_fs",
            "register_dos_to_nt_FAILED dos_root='%ls'", sandbox_root.c_str());
        return false;
    }
    if (nt_root.size() >= SHADOWFS_MAX_PATH_CHARS) {
        std::lock_guard<std::mutex> lk(g_mtx);
        set_last_error_locked("Sandbox root path too long");
        return false;
    }

    SHADOWFS_MSG_REGISTER req = {};
    init_header(req.header, SHADOWFS_MSG_REGISTER_PID, sizeof(req));
    req.pid = pid;
    req.flags = flags;
    req.sandbox_root_chars = static_cast<unsigned long>(nt_root.size());
    memcpy(req.sandbox_root,
           nt_root.data(),
           nt_root.size() * sizeof(wchar_t));
    req.sandbox_root[nt_root.size()] = L'\0';

    SHADOWFS_REPLY_GENERIC reply = {};
    ULONG used = 0;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_connected_locked()) return false;

    bool ok = send_locked(&req, sizeof(req), &reply, sizeof(reply), &used);
    if (!ok) {
        diag::log_tagged_critical_fmt("shadow_fs",
            "register_FAILED pid=%lu err='%s'",
            static_cast<unsigned long>(pid),
            s_last_error.c_str());
        return false;
    }
    if (used < sizeof(SHADOWFS_REPLY_GENERIC_V1)) {
        set_last_error_locked("FilterSendMessage returned short reply");
        diag::log_tagged_critical_fmt("shadow_fs",
            "register_short_reply pid=%lu used=%lu", pid, used);
        return false;
    }
    if (!reply_is_ok_or_logged(reply, "register")) {
        set_last_error_locked("Shadow FS minifilter rejected REGISTER");
        return false;
    }
    diag::log_tagged_critical_fmt("shadow_fs",
        "register ok pid=%lu flags=0x%08lX active=%lu nt_root='%ls'",
        pid, flags, static_cast<unsigned long>(reply.pid_count), nt_root.c_str());
    return true;
}

bool unregister_sandbox_pid(uint32_t pid) {
    if (pid == 0 || pid == 4) {
        std::lock_guard<std::mutex> lk(g_mtx);
        set_last_error_locked("Invalid PID");
        return false;
    }

    SHADOWFS_MSG_UNREGISTER req = {};
    init_header(req.header, SHADOWFS_MSG_UNREGISTER_PID, sizeof(req));
    req.pid = pid;

    SHADOWFS_REPLY_GENERIC reply = {};
    ULONG used = 0;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_connected_locked()) return false;

    bool ok = send_locked(&req, sizeof(req), &reply, sizeof(reply), &used);
    if (!ok) return false;
    if (used < sizeof(SHADOWFS_REPLY_GENERIC_V1)) {
        set_last_error_locked("FilterSendMessage returned short reply (unreg)");
        return false;
    }
    if (!reply_is_ok_or_logged(reply, "unregister")) {
        return false;
    }
    diag::log_tagged_critical_fmt("shadow_fs",
        "unregister ok pid=%lu active=%lu",
        pid, static_cast<unsigned long>(reply.pid_count));
    return true;
}

bool ping() {
    SHADOWFS_MSG_PING_REQ req = {};
    init_header(req.header, SHADOWFS_MSG_PING, sizeof(req));
    req.client_token = static_cast<unsigned long>(GetCurrentProcessId());

    SHADOWFS_REPLY_GENERIC reply = {};
    ULONG used = 0;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_connected_locked()) return false;

    bool ok = send_locked(&req, sizeof(req), &reply, sizeof(reply), &used);
    if (!ok) return false;
    if (used < sizeof(SHADOWFS_REPLY_GENERIC_V1)) return false;
    return reply_is_ok(reply);
}

bool query_stats(shadow_stats_t& out) {
    out = {};

    SHADOWFS_MSG_QUERY_STATS_T req = {};
    init_header(req.header, SHADOWFS_MSG_QUERY_STATS, sizeof(req));

    SHADOWFS_REPLY_GENERIC reply = {};
    ULONG used = 0;

    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_connected_locked()) return false;

    bool ok = send_locked(&req, sizeof(req), &reply, sizeof(reply), &used);
    if (!ok) return false;
    if (used < sizeof(SHADOWFS_REPLY_GENERIC_V1)) return false;
    if (!reply_is_ok(reply)) return false;
    out.active_pid_count = reply.pid_count;
    out.denials = reply.denials;
    out.redirects = reply.redirects;
    out.copies = reply.copies;
    if (used >= sizeof(SHADOWFS_REPLY_GENERIC)) {
        out.bytes_copied = reply.bytes_copied;
        out.fsctl_denials = reply.fsctl_denials;
        out.ads_denials = reply.ads_denials;
        out.mapping_denials = reply.mapping_denials;
        out.unc_denials = reply.unc_denials;
        out.raw_device_denials = reply.raw_device_denials;
        out.set_info_denials = reply.set_info_denials;
        out.dir_merge_emits = reply.dir_merge_emits;
    }
    return true;
}

const std::string& last_error() {
    return s_last_error;
}

}
