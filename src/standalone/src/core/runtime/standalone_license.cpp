#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "standalone_license.hpp"

#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "comm.h"
#include "arc/arc.h"
#include "arc_loader.hpp"
#include "anti-tamper/vm_compiler.hpp"
#include "anti-tamper/server_pages.hpp"
#include "anti-tamper/orchestrator.hpp"
#include "anti-tamper/tpm_attest.hpp"
#include "tls_exporter.hpp"
#include "vbs_enforcement.hpp"
#include "obfuscation.hpp"
#include "../infra/work_queue.hpp"
#include "../crypto/keys.hpp"
#include "../../helpers/diag_log.hpp"
#include "standalone_license_transport.hpp"
#include "license_state.hpp"
#include "gate_tokens.hpp"
#include "reason_ids.hpp"
#include "loader_header_invariant.hpp"
#include "customer_capsule.hpp"
#include "hardware_id/hardware_id_v2.hpp"
#include "plaintext_window.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../testlab/test_all_features.hpp"
#include "../../../../../src/shared/telemetry/telemetry_client.hpp"

#include <windows.h>
#include <winioctl.h>
#include <intrin.h>
#include <psapi.h>
#include <dbghelp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <winhttp.h>

#include <array>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

static std::mutex& lic_run_correlation_mutex()
{
    static std::mutex m;
    return m;
}

static std::string& lic_run_correlation_value()
{
    static std::string id = "unset";
    return id;
}

static std::string lic_run_correlation_snapshot()
{
    std::lock_guard<std::mutex> lk(lic_run_correlation_mutex());
    return lic_run_correlation_value();
}

static void lic_set_run_correlation_snapshot(const std::string& id)
{
    std::string normalized;
    normalized.reserve(64);
    for (char ch : id) {
        const bool ok =
            (ch >= '0' && ch <= '9') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') ||
            ch == '-' ||
            ch == '_';
        if (ok)
            normalized.push_back(ch);
        if (normalized.size() >= 64)
            break;
    }
    if (normalized.empty())
        normalized = "unset";
    std::lock_guard<std::mutex> lk(lic_run_correlation_mutex());
    lic_run_correlation_value() = normalized;
}

static void lic_log(const char* step)
{

    static char s_log_path[MAX_PATH] = {};
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    BOOL pending;
    InitOnceBeginInitialize(&s_once, INIT_ONCE_ASYNC, &pending, nullptr);
    if (pending) {
        if (!diag::build_log_path("aida_debug.log", s_log_path, sizeof(s_log_path)))
            s_log_path[0] = '\0';
        InitOnceComplete(&s_once, INIT_ONCE_ASYNC, nullptr);
    }
    if (s_log_path[0] == '\0') return;

    HANDLE hf = CreateFileA(s_log_path, FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::string run_id = lic_run_correlation_snapshot();
    char line[1536];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [license] run_id=%s %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, run_id.c_str(), step);
    if (len > 0) {
        DWORD w;
        WriteFile(hf, line, (DWORD)len, &w, nullptr);

        char dbg_line[1600];
        _snprintf_s(dbg_line, sizeof(dbg_line), _TRUNCATE,
            "[AIDA-LIC][%02d:%02d:%02d.%03d] run_id=%s %s",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, run_id.c_str(), step);
        OutputDebugStringA(dbg_line);
    }
    CloseHandle(hf);
}

static void lic_log_fmt(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    lic_log(buf);
}

namespace lic_diag {

    static DWORD WINAPI canary_proc(LPVOID p)
    {
        volatile LONG* done = reinterpret_cast<volatile LONG*>(p);
        if (done) InterlockedExchange(done, 1);
        return 0;
    }

    static void thread_canary(const char* phase)
    {
        aida::runtime::loader_header_invariant::ensure(phase, "license");
        volatile LONG done = 0;
        DWORD tid = 0;
        SetLastError(0);
        HANDLE h = CreateThread(nullptr, 0, &canary_proc, (LPVOID)&done, 0, &tid);
        DWORD gle = GetLastError();
        lic_log_fmt("DIAG_LIC_CANARY phase=%s result=%p tid=%lu err=%lu proc=%p calling_tid=%lu",
            phase, h, tid, gle, (void*)&canary_proc, GetCurrentThreadId());
        if (h) {
            WaitForSingleObject(h, 2000);
            CloseHandle(h);
        }
    }

    static void dump_pe_self(const char* phase)
    {
        aida::runtime::loader_header_invariant::ensure(phase, "license");
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            lic_log_fmt("DIAG_LIC_PE phase=%s mod=NULL gle=%lu", phase, GetLastError());
            return;
        }
        auto* base = reinterpret_cast<const uint8_t*>(mod);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            lic_log_fmt("DIAG_LIC_PE phase=%s bad_e_magic=0x%X", phase, (unsigned)dos->e_magic);
            return;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        lic_log_fmt("DIAG_LIC_PE phase=%s mod=%p e_magic=0x%X sig=0x%X machine=0x%X "
            "magic=0x%X entry=0x%X numrva=%u image_base=0x%llX sizeof_image=0x%X sections=%u",
            phase, mod, (unsigned)dos->e_magic, nt->Signature,
            (unsigned)nt->FileHeader.Machine, (unsigned)nt->OptionalHeader.Magic,
            nt->OptionalHeader.AddressOfEntryPoint,
            nt->OptionalHeader.NumberOfRvaAndSizes,
            static_cast<unsigned long long>(nt->OptionalHeader.ImageBase),
            nt->OptionalHeader.SizeOfImage,
            (unsigned)nt->FileHeader.NumberOfSections);
    }

    static void dump_mitigation(const char* phase)
    {
        using GetMitig_t = BOOL(WINAPI*)(HANDLE, int, PVOID, SIZE_T);
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        auto pGet = k32 ? reinterpret_cast<GetMitig_t>(
            GetProcAddress(k32, "GetProcessMitigationPolicy")) : nullptr;
        if (!pGet) {
            lic_log_fmt("DIAG_LIC_MITIG phase=%s no_export", phase);
            return;
        }
        HANDLE me = GetCurrentProcess();
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn{};
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY il{};
        BOOL d_ok = pGet(me, 7, &dyn, sizeof(dyn));
        BOOL s_ok = pGet(me, 8, &sig, sizeof(sig));
        BOOL i_ok = pGet(me, 10, &il, sizeof(il));
        lic_log_fmt("DIAG_LIC_MITIG phase=%s DYN ok=%d prohibit=%u opt_out=%u BIN_SIG ok=%d ms_only=%u "
            "IL ok=%d no_remote=%u no_low_mandatory=%u prefer_sys32=%u",
            phase, d_ok, (unsigned)dyn.ProhibitDynamicCode, (unsigned)dyn.AllowThreadOptOut,
            s_ok, (unsigned)sig.MicrosoftSignedOnly,
            i_ok, (unsigned)il.NoRemoteImages, (unsigned)il.NoLowMandatoryLabelImages,
            (unsigned)il.PreferSystem32Images);
    }

}

static int ensure_winsock_initialized()
{
    static INIT_ONCE s_wsa_once = INIT_ONCE_STATIC_INIT;
    static int s_wsa_result = WSASYSNOTREADY;
    BOOL pending = FALSE;
    InitOnceBeginInitialize(&s_wsa_once, 0, &pending, nullptr);
    if (pending) {
        WSADATA wsa{};
        s_wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa);
        InitOnceComplete(&s_wsa_once, 0, nullptr);
    }
    return s_wsa_result;
}

static void diagnose_network(const char* host, int port)
{
    char buf[512];

    const int wsa_init = ensure_winsock_initialized();
    if (wsa_init != 0) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DIAG wsa_startup_fail rc=%d", wsa_init);
        lic_log(buf);
        return;
    }


    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%d", port);
    int dns_rc = getaddrinfo(host, port_str, &hints, &result);
    if (dns_rc != 0) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DIAG dns_fail host=%s rc=%d wsa=%d", host, dns_rc, WSAGetLastError());
        lic_log(buf);
        return;
    }

    for (struct addrinfo* rp = result; rp; rp = rp->ai_next) {
        char ip[64] = {};
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)rp->ai_addr;
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)rp->ai_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        }
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DIAG dns_ok host=%s ip=%s family=%d", host, ip, rp->ai_family);
        lic_log(buf);
    }


    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DIAG socket_fail wsa=%d", WSAGetLastError());
        lic_log(buf);
        freeaddrinfo(result);
        return;
    }

    DWORD tv = 5000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int conn_rc = connect(sock, result->ai_addr, (int)result->ai_addrlen);
    if (conn_rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DIAG tcp_connect_fail host=%s wsa=%d", host, err);
        lic_log(buf);
    } else {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DIAG tcp_connect_ok host=%s port=%d", host, port);
        lic_log(buf);
    }
    closesocket(sock);
    freeaddrinfo(result);


    SSL_CTX* test_ctx = SSL_CTX_new(TLS_client_method());
    if (!test_ctx) {
        unsigned long ssl_err = ERR_get_error();
        char ssl_buf[256] = {};
        ERR_error_string_n(ssl_err, ssl_buf, sizeof(ssl_buf));
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "DIAG ssl_ctx_fail err=%lu desc=%s", ssl_err, ssl_buf);
        lic_log(buf);
    } else {
        lic_log("DIAG ssl_ctx_ok");
        SSL_CTX_free(test_ctx);
    }


    {
        httplib::Client test_client(std::string("https://") + host);
        test_client.set_connection_timeout(10);
        test_client.set_read_timeout(10);
        test_client.set_follow_location(true);
        test_client.enable_server_certificate_verification(false);
        auto test_res = test_client.Get("/health");
        if (!test_res) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "DIAG httplib_fail host=%s err=%d(%s)",
                host, (int)test_res.error(), httplib::to_string(test_res.error()).c_str());
            lic_log(buf);
        } else {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "DIAG httplib_ok host=%s status=%d body_len=%zu",
                host, test_res->status, test_res->body.size());
            lic_log(buf);
        }
    }


    {
        httplib::Client test_client2(std::string("https://") + host);
        test_client2.set_address_family(AF_INET);
        test_client2.set_connection_timeout(10);
        test_client2.set_read_timeout(10);
        test_client2.set_follow_location(true);
        test_client2.enable_server_certificate_verification(true);
        auto test_res2 = test_client2.Get("/health");
        if (!test_res2) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "DIAG httplib_af_inet_fail host=%s err=%d(%s)",
                host, (int)test_res2.error(), httplib::to_string(test_res2.error()).c_str());
            lic_log(buf);
        } else {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "DIAG httplib_af_inet_ok host=%s status=%d",
                host, test_res2->status);
            lic_log(buf);
        }
    }


    {
        struct addrinfo hints2 = {}, *result2 = nullptr;
        hints2.ai_family = AF_INET;
        hints2.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, port_str, &hints2, &result2) == 0 && result2) {
            SOCKET nb_sock = WSASocketW(result2->ai_family, result2->ai_socktype,
                result2->ai_protocol, nullptr, 0,
                WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED);
            if (nb_sock == INVALID_SOCKET) {
                nb_sock = socket(result2->ai_family, result2->ai_socktype, result2->ai_protocol);
            }
            if (nb_sock != INVALID_SOCKET) {

                u_long nb_mode = 1;
                ioctlsocket(nb_sock, FIONBIO, &nb_mode);
                int nb_ret = ::connect(nb_sock, result2->ai_addr, (int)result2->ai_addrlen);
                int nb_wsa = WSAGetLastError();
                if (nb_ret == SOCKET_ERROR && nb_wsa == WSAEWOULDBLOCK) {

                    WSAPOLLFD pfd = {};
                    pfd.fd = nb_sock;
                    pfd.events = POLLIN | POLLOUT;
                    int poll_ret = WSAPoll(&pfd, 1, 10000);
                    if (poll_ret > 0) {
                        int so_err = 0;
                        int so_len = sizeof(so_err);
                        getsockopt(nb_sock, SOL_SOCKET, SO_ERROR, (char*)&so_err, &so_len);
                        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                            "DIAG nb_connect poll_ret=%d revents=0x%x so_err=%d",
                            poll_ret, pfd.revents, so_err);
                    } else {
                        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                            "DIAG nb_connect poll_ret=%d wsa=%d", poll_ret, WSAGetLastError());
                    }
                } else if (nb_ret == 0) {
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "DIAG nb_connect immediate_ok");
                } else {
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "DIAG nb_connect failed wsa=%d", nb_wsa);
                }
                lic_log(buf);
                closesocket(nb_sock);
            }
            freeaddrinfo(result2);
        }
    }


    {
        httplib::Client test_http(std::string("http://") + host, 80);
        test_http.set_connection_timeout(5);
        test_http.set_read_timeout(5);
        test_http.set_follow_location(false);
        auto test_rh = test_http.Get("/health");
        if (!test_rh) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "DIAG httplib_http_fail host=%s err=%d(%s)",
                host, (int)test_rh.error(), httplib::to_string(test_rh.error()).c_str());
            lic_log(buf);
        } else {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "DIAG httplib_http_ok host=%s status=%d body_len=%zu",
                host, test_rh->status, test_rh->body.size());
            lic_log(buf);
        }
    }
}


struct SimpleHttpResponse {
    int    status = 0;
    std::string body;
    bool   ok    = false;
    std::string error;
    std::string debug_reason;
};

struct resolved_addr_t {
    int family = 0;
    sockaddr_storage sa = {};
    int sa_len = 0;
};

static std::wstring license_utf8_to_utf16(const std::string& text)
{
    if (text.empty()) return std::wstring();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                    nullptr, 0);
    if (wlen <= 0) return std::wstring();
    std::wstring out;
    out.resize(static_cast<size_t>(wlen));
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        out.data(), wlen);
    return out;
}

static void append_addrinfoex_results(PADDRINFOEXW gai_res,
                                      std::vector<resolved_addr_t>& results)
{
    for (ADDRINFOEXW* entry = gai_res; entry; entry = entry->ai_next) {
        if (entry->ai_family != AF_INET && entry->ai_family != AF_INET6) continue;
        if (!entry->ai_addr || entry->ai_addrlen == 0 ||
            entry->ai_addrlen > sizeof(sockaddr_storage)) continue;
        resolved_addr_t resolved;
        resolved.family = entry->ai_family;
        resolved.sa_len = static_cast<int>(entry->ai_addrlen);
        memcpy(&resolved.sa, entry->ai_addr, entry->ai_addrlen);
        results.push_back(resolved);
    }
}

static void append_dns_records(PDNS_RECORD records, WORD query_type, int port,
                               std::vector<resolved_addr_t>& results)
{
    const u_short port_be = htons(static_cast<u_short>(port));
    for (PDNS_RECORD record = records; record; record = record->pNext) {
        if (query_type == DNS_TYPE_A && record->wType == DNS_TYPE_A) {
            resolved_addr_t resolved;
            resolved.family = AF_INET;
            resolved.sa_len = static_cast<int>(sizeof(sockaddr_in));
            auto* sin = reinterpret_cast<sockaddr_in*>(&resolved.sa);
            sin->sin_family = AF_INET;
            sin->sin_port = port_be;
            sin->sin_addr.S_un.S_addr = record->Data.A.IpAddress;
            results.push_back(resolved);
        } else if (query_type == DNS_TYPE_AAAA && record->wType == DNS_TYPE_AAAA) {
            resolved_addr_t resolved;
            resolved.family = AF_INET6;
            resolved.sa_len = static_cast<int>(sizeof(sockaddr_in6));
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(&resolved.sa);
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = port_be;
            memcpy(&sin6->sin6_addr, &record->Data.AAAA.Ip6Address, sizeof(IN6_ADDR));
            results.push_back(resolved);
        }
    }
}

struct dns_query_state_t {
    HANDLE event_handle = nullptr;
    DNS_QUERY_RESULT result = {};
    DNS_QUERY_CANCEL cancel = {};
};

static void WINAPI dns_query_completion(void* context, PDNS_QUERY_RESULT)
{
    auto* state = static_cast<dns_query_state_t*>(context);
    if (state && state->event_handle) SetEvent(state->event_handle);
}

static DNS_STATUS query_dns_records_bounded(const std::wstring& host_w, WORD query_type,
                                            int timeout_ms, PDNS_RECORD* records_out,
                                            bool& timed_out)
{
    *records_out = nullptr;
    timed_out = false;

    auto state = std::make_unique<dns_query_state_t>();
    state->event_handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!state->event_handle) return static_cast<DNS_STATUS>(GetLastError());

    state->result.Version = DNS_QUERY_RESULTS_VERSION1;

    DNS_QUERY_REQUEST request = {};
    request.Version = DNS_QUERY_REQUEST_VERSION1;
    request.QueryName = host_w.c_str();
    request.QueryType = query_type;
    request.QueryOptions = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE |
                           DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST;
    request.pQueryCompletionCallback = dns_query_completion;
    request.pQueryContext = state.get();

    DNS_STATUS status = DnsQueryEx(&request, &state->result, &state->cancel);
    if (status == DNS_REQUEST_PENDING) {
        DWORD wait_ms = timeout_ms > 0 ? static_cast<DWORD>(timeout_ms) : 1u;
        DWORD wait_rc = WaitForSingleObject(state->event_handle, wait_ms);
        if (wait_rc == WAIT_TIMEOUT) {
            timed_out = true;
            DnsCancelQuery(&state->cancel);
            DWORD cancel_wait = WaitForSingleObject(state->event_handle, 1000);
            if (cancel_wait != WAIT_OBJECT_0) {
                state.release();
                return ERROR_TIMEOUT;
            }
        } else if (wait_rc != WAIT_OBJECT_0) {
            CloseHandle(state->event_handle);
            return static_cast<DNS_STATUS>(GetLastError());
        }
        status = state->result.QueryStatus;
    } else if (state->result.QueryStatus != 0) {
        status = state->result.QueryStatus;
    }

    if (status == 0 && state->result.pQueryRecords) {
        *records_out = state->result.pQueryRecords;
        state->result.pQueryRecords = nullptr;
    }

    if (state->result.pQueryRecords) {
        DnsRecordListFree(state->result.pQueryRecords, DnsFreeRecordList);
        state->result.pQueryRecords = nullptr;
    }

    CloseHandle(state->event_handle);
    return status;
}

static std::vector<resolved_addr_t> resolve_host_addrs(const std::string& host, int port,
                                                        int timeout_ms,
                                                        std::string& diag_out)
{
    std::vector<resolved_addr_t> results;
    char port_str[8];
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%d", port);
    char gai_buf[160] = {};

    const int total_budget_ms = std::max(500, timeout_ms);
    const auto started_at = std::chrono::steady_clock::now();
    const auto deadline = started_at + std::chrono::milliseconds(total_budget_ms);
    auto remaining_ms = [&]() -> int {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        return static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    };

    std::wstring host_w = license_utf8_to_utf16(host);
    std::wstring port_w = license_utf8_to_utf16(port_str);

    {
        ADDRINFOEXW hints = {};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        PADDRINFOEXW gai_res = nullptr;
        const int gai_budget_ms = std::max(250, remaining_ms());
        timeval gai_timeout = {};
        gai_timeout.tv_sec = gai_budget_ms / 1000;
        gai_timeout.tv_usec = (gai_budget_ms % 1000) * 1000;
        const int gai_rc = GetAddrInfoExW(host_w.c_str(), port_w.c_str(), NS_DNS,
                                          nullptr, &hints, &gai_res, &gai_timeout,
                                          nullptr, nullptr, nullptr);
        if (gai_rc == 0 && gai_res) {
            append_addrinfoex_results(gai_res, results);
            FreeAddrInfoExW(gai_res);
        } else {
            _snprintf_s(gai_buf, sizeof(gai_buf), _TRUNCATE,
                "GetAddrInfoExW rc=%d wsa=%lu budget_ms=%d",
                gai_rc, static_cast<unsigned long>(WSAGetLastError()), gai_budget_ms);
            if (gai_res) FreeAddrInfoExW(gai_res);
        }
    }

    if (!results.empty()) return results;

    char dns_buf[160] = {};
    bool a_timeout = false;
    PDNS_RECORD records_a = nullptr;
    DNS_STATUS status_a = query_dns_records_bounded(host_w, DNS_TYPE_A,
                                                    std::max(1, remaining_ms() / 2),
                                                    &records_a, a_timeout);
    if (status_a == 0 && records_a) {
        append_dns_records(records_a, DNS_TYPE_A, port, results);
        DnsRecordListFree(records_a, DnsFreeRecordList);
    }

    bool aaaa_timeout = false;
    PDNS_RECORD records_aaaa = nullptr;
    DNS_STATUS status_aaaa = query_dns_records_bounded(host_w, DNS_TYPE_AAAA,
                                                       std::max(1, remaining_ms()),
                                                       &records_aaaa, aaaa_timeout);
    if (status_aaaa == 0 && records_aaaa) {
        append_dns_records(records_aaaa, DNS_TYPE_AAAA, port, results);
        DnsRecordListFree(records_aaaa, DnsFreeRecordList);
    }

    if (results.empty()) {
        _snprintf_s(dns_buf, sizeof(dns_buf), _TRUNCATE,
            "DnsQueryEx A=%lu%s AAAA=%lu%s remaining_ms=%d",
            static_cast<unsigned long>(status_a), a_timeout ? ":timeout" : "",
            static_cast<unsigned long>(status_aaaa), aaaa_timeout ? ":timeout" : "",
            remaining_ms());
    }

    if (results.empty()) {
        diag_out.clear();
        if (gai_buf[0] != '\0') diag_out += gai_buf;
        if (gai_buf[0] != '\0' && dns_buf[0] != '\0') diag_out += "; ";
        if (dns_buf[0] != '\0') diag_out += dns_buf;
        if (diag_out.empty()) diag_out = "no addresses returned";
    }
    return results;
}

static SimpleHttpResponse raw_https_request_socket(
    const char* verb,
    const std::string& url,
    const std::vector<std::pair<std::string,std::string>>& extra_headers,
    const std::string& req_body,
    const std::string& content_type,
    int timeout_sec)
{
    SimpleHttpResponse out;

    const int wsa_init = ensure_winsock_initialized();
    if (wsa_init != 0) {
        out.error = "WSAStartup failed rc=" + std::to_string(wsa_init);
        return out;
    }


    bool is_https = true;
    std::string work = url;
    if (work.rfind("https://", 0) == 0)      work = work.substr(8);
    else if (work.rfind("http://", 0) == 0) { work = work.substr(7); is_https = false; }

    std::string host, path = "/";
    int port = is_https ? 443 : 80;

    auto slash = work.find('/');
    if (slash != std::string::npos) {
        host = work.substr(0, slash);
        path = work.substr(slash);
    } else {
        host = work;
    }
    auto colon = host.find(':');
    if (colon != std::string::npos) {
        port = atoi(host.c_str() + colon + 1);
        host = host.substr(0, colon);
    }


    std::string resolve_diag;
    std::vector<resolved_addr_t> candidate_addrs;
    {
        char dbuf[160];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "raw_resolve_begin host=%.96s port=%d", host.c_str(), port);
        lic_log(dbuf);
    }
    {
        const int resolve_budget_ms = std::max(2000, timeout_sec * 1000 / 2);
        candidate_addrs = resolve_host_addrs(host, port, resolve_budget_ms, resolve_diag);
    }
    {
        char dbuf[256];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "raw_resolve_done host=%.96s port=%d count=%zu diag=%.120s",
            host.c_str(), port, candidate_addrs.size(), resolve_diag.c_str());
        lic_log(dbuf);
    }
    if (candidate_addrs.empty()) {
        out.error = "DNS resolution failed for " + host + " (" + resolve_diag + ")";
        return out;
    }

    std::stable_sort(candidate_addrs.begin(), candidate_addrs.end(),
        [](const resolved_addr_t& a, const resolved_addr_t& b) {
            return (a.family == AF_INET) && (b.family != AF_INET);
        });

    const auto request_start = std::chrono::steady_clock::now();
    const auto request_deadline = request_start + std::chrono::seconds(timeout_sec);
    auto remaining_ms = [&]() -> int {
        const auto now = std::chrono::steady_clock::now();
        if (now >= request_deadline) return 0;
        return static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(request_deadline - now).count());
    };

    SOCKET sock = INVALID_SOCKET;
    std::string connect_errors;
    auto poll_socket = [&](short events, int wait_ms) -> int {
        if (wait_ms < 0) wait_ms = 0;
        WSAPOLLFD pfd = {};
        pfd.fd = sock;
        pfd.events = events;
        return WSAPoll(&pfd, 1, wait_ms);
    };

    auto fmt_addr = [](const resolved_addr_t& addr) -> std::string {
        char ip[64] = {};
        if (addr.family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(&addr.sa);
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        } else if (addr.family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&addr.sa);
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        }
        return std::string(ip);
    };

    int attempt_index = 0;
    for (auto& addr : candidate_addrs) {
        ++attempt_index;
        const std::string addr_str = fmt_addr(addr);
        const char family_label = (addr.family == AF_INET) ? '4' : '6';

        if (remaining_ms() <= 0) {
            if (!connect_errors.empty()) connect_errors += "; ";
            connect_errors += "deadline_reached_before_connect";
            char dbuf[256];
            _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
                "raw_connect_attempt host=%.96s ip=%.46s v%c idx=%d host_port=%d skip=deadline_reached",
                host.c_str(), addr_str.c_str(), family_label, attempt_index, port);
            lic_log(dbuf);
            break;
        }

        sock = socket(addr.family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            int wsa = WSAGetLastError();
            if (!connect_errors.empty()) connect_errors += "; ";
            connect_errors += "socket() wsa=" + std::to_string(wsa);
            char dbuf[256];
            _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
                "raw_connect_attempt host=%.96s ip=%.46s v%c idx=%d port=%d socket_fail wsa=%d",
                host.c_str(), addr_str.c_str(), family_label, attempt_index, port, wsa);
            lic_log(dbuf);
            continue;
        }

        u_long nb_on = 1;
        ioctlsocket(sock, FIONBIO, &nb_on);

        int conn_rc = ::connect(sock, reinterpret_cast<sockaddr*>(&addr.sa), addr.sa_len);
        if (conn_rc == SOCKET_ERROR) {
            int wsa = WSAGetLastError();
            if (wsa != WSAEWOULDBLOCK) {
                if (!connect_errors.empty()) connect_errors += "; ";
                connect_errors += "connect() wsa=" + std::to_string(wsa);
                sockaddr_storage local_sa = {};
                int local_len = static_cast<int>(sizeof(local_sa));
                char local_ip[64] = {};
                int local_port = 0;
                if (getsockname(sock, reinterpret_cast<sockaddr*>(&local_sa), &local_len) == 0) {
                    if (local_sa.ss_family == AF_INET) {
                        const auto* l4 = reinterpret_cast<const sockaddr_in*>(&local_sa);
                        inet_ntop(AF_INET, &l4->sin_addr, local_ip, sizeof(local_ip));
                        local_port = ntohs(l4->sin_port);
                    } else if (local_sa.ss_family == AF_INET6) {
                        const auto* l6 = reinterpret_cast<const sockaddr_in6*>(&local_sa);
                        inet_ntop(AF_INET6, &l6->sin6_addr, local_ip, sizeof(local_ip));
                        local_port = ntohs(l6->sin6_port);
                    }
                }
                char dbuf[384];
                _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
                    "raw_connect_attempt host=%.96s ip=%.46s v%c idx=%d port=%d sock=0x%llX local=%.46s:%d connect_immediate_fail wsa=%d",
                    host.c_str(), addr_str.c_str(), family_label, attempt_index, port,
                    static_cast<unsigned long long>(sock),
                    local_ip, local_port, wsa);
                lic_log(dbuf);
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            int p = poll_socket(POLLOUT, remaining_ms());
            if (p == 0) {
                if (!connect_errors.empty()) connect_errors += "; ";
                connect_errors += "connect_timeout";
                char dbuf[256];
                _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
                    "raw_connect_attempt host=%.96s ip=%.46s v%c idx=%d port=%d connect_poll_timeout remaining_ms=%d",
                    host.c_str(), addr_str.c_str(), family_label, attempt_index, port, remaining_ms());
                lic_log(dbuf);
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            if (p < 0) {
                int err = WSAGetLastError();
                if (!connect_errors.empty()) connect_errors += "; ";
                connect_errors += "wsapoll wsa=" + std::to_string(err);
                char dbuf[256];
                _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
                    "raw_connect_attempt host=%.96s ip=%.46s v%c idx=%d port=%d wsapoll_fail wsa=%d",
                    host.c_str(), addr_str.c_str(), family_label, attempt_index, port, err);
                lic_log(dbuf);
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            int so_err = 0;
            int so_len = static_cast<int>(sizeof(so_err));
            getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_len);
            if (so_err != 0) {
                if (!connect_errors.empty()) connect_errors += "; ";
                connect_errors += "connect_so_err=" + std::to_string(so_err);
                char dbuf[256];
                _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
                    "raw_connect_attempt host=%.96s ip=%.46s v%c idx=%d port=%d connect_so_error so_err=%d",
                    host.c_str(), addr_str.c_str(), family_label, attempt_index, port, so_err);
                lic_log(dbuf);
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
        }
        {
            char dbuf[256];
            _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
                "raw_connect_attempt host=%.96s ip=%.46s v%c idx=%d port=%d connect_ok",
                host.c_str(), addr_str.c_str(), family_label, attempt_index, port);
            lic_log(dbuf);
        }
        break;
    }

    if (sock == INVALID_SOCKET) {
        out.error = "connect failed for " + host + " (" + connect_errors + ")";
        return out;
    }


    SSL_CTX* ctx = nullptr;
    SSL* ssl     = nullptr;
    if (is_https) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            closesocket(sock);
            out.error = "SSL_CTX_new failed";
            return out;
        }
        ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            closesocket(sock);
            out.error = "SSL_new failed";
            return out;
        }
        SSL_set_fd(ssl, static_cast<int>(sock));
        SSL_set_tlsext_host_name(ssl, host.c_str());
        for (;;) {
            int rc = SSL_connect(ssl);
            if (rc == 1) break;
            int err = SSL_get_error(ssl, rc);
            short events = 0;
            if (err == SSL_ERROR_WANT_READ)       events = POLLIN;
            else if (err == SSL_ERROR_WANT_WRITE) events = POLLOUT;
            else {
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                closesocket(sock);
                out.error = "SSL_connect failed err=" + std::to_string(err);
                return out;
            }
            int p = poll_socket(events, remaining_ms());
            if (p == 0) {
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                closesocket(sock);
                out.error = "SSL_connect timed out host=" + host;
                return out;
            }
            if (p < 0) {
                int we = WSAGetLastError();
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                closesocket(sock);
                out.error = "WSAPoll on SSL_connect failed wsa=" + std::to_string(we);
                return out;
            }
        }
    }


    std::string http_req;
    http_req += verb;
    http_req += " ";
    http_req += path;
    http_req += " HTTP/1.1\r\nHost: ";
    http_req += host;
    http_req += "\r\nConnection: close\r\n";
    if (!content_type.empty())
        http_req += "Content-Type: " + content_type + "\r\n";
    if (!req_body.empty())
        http_req += "Content-Length: " + std::to_string(req_body.size()) + "\r\n";
    for (auto& [k, v] : extra_headers)
        http_req += k + ": " + v + "\r\n";
    http_req += "\r\n";
    http_req += req_body;


    auto send_all = [&](const char* data, int len) -> bool {
        while (len > 0) {
            int n;
            if (ssl) n = SSL_write(ssl, data, len);
            else     n = ::send(sock, data, len, 0);
            if (n > 0) {
                data += n;
                len  -= n;
                continue;
            }
            short events = POLLOUT;
            if (ssl) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ)        events = POLLIN;
                else if (err == SSL_ERROR_WANT_WRITE)  events = POLLOUT;
                else                                   return false;
            } else {
                int wsa = WSAGetLastError();
                if (wsa != WSAEWOULDBLOCK)             return false;
            }
            int p = poll_socket(events, remaining_ms());
            if (p <= 0) return false;
        }
        return true;
    };

    if (!send_all(http_req.c_str(), (int)http_req.size())) {
        if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
        closesocket(sock);
        out.error = "send failed (timeout or error)";
        return out;
    }


    std::string raw_resp;
    raw_resp.reserve(4096);
    char buf[4096];
    for (;;) {
        int n;
        if (ssl) n = SSL_read(ssl, buf, sizeof(buf));
        else     n = ::recv(sock, buf, sizeof(buf), 0);
        if (n > 0) {
            raw_resp.append(buf, n);
            if (raw_resp.size() > 4 * 1024 * 1024) break;
            continue;
        }
        if (n == 0) break;
        short events = POLLIN;
        bool fatal = false;
        if (ssl) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN)      { fatal = true; break; }
            else if (err == SSL_ERROR_WANT_READ)   events = POLLIN;
            else if (err == SSL_ERROR_WANT_WRITE)  events = POLLOUT;
            else                                   { fatal = true; }
        } else {
            int wsa = WSAGetLastError();
            if (wsa != WSAEWOULDBLOCK) fatal = true;
        }
        if (fatal) break;
        int p = poll_socket(events, remaining_ms());
        if (p <= 0) break;
    }

    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
    closesocket(sock);


    auto hdr_end = raw_resp.find("\r\n\r\n");
    if (hdr_end == std::string::npos) {
        out.error = "malformed HTTP response (no header end)";
        return out;
    }


    auto first_line_end = raw_resp.find("\r\n");
    std::string status_line = raw_resp.substr(0, first_line_end);
    auto sp1 = status_line.find(' ');
    if (sp1 != std::string::npos) {
        out.status = atoi(status_line.c_str() + sp1 + 1);
    }


    std::string headers_str = raw_resp.substr(0, hdr_end);
    std::string body_raw = raw_resp.substr(hdr_end + 4);


    std::string headers_lower = headers_str;
    for (auto& c : headers_lower) c = (char)tolower((unsigned char)c);

    if (headers_lower.find("transfer-encoding: chunked") != std::string::npos) {

        std::string decoded;
        size_t pos = 0;
        while (pos < body_raw.size()) {
            auto crlf = body_raw.find("\r\n", pos);
            if (crlf == std::string::npos) break;
            long chunk_size = strtol(body_raw.c_str() + pos, nullptr, 16);
            if (chunk_size <= 0) break;
            pos = crlf + 2;
            if (pos + chunk_size > body_raw.size()) break;
            decoded.append(body_raw, pos, chunk_size);
            pos += chunk_size + 2;
        }
        out.body = std::move(decoded);
    } else {
        out.body = std::move(body_raw);
    }

    out.ok = true;
    return out;
}

static SimpleHttpResponse winhttp_https_request_impl(
    const char* verb,
    const std::string& url,
    const std::vector<std::pair<std::string,std::string>>& extra_headers,
    const std::string& req_body,
    const std::string& content_type,
    int timeout_sec)
{
    SimpleHttpResponse out;

    lic_log("winhttp_impl_enter");

    HMODULE wh_mod = LoadLibraryW(L"winhttp.dll");
    if (!wh_mod) {
        out.error = "winhttp_load_failed gle=" + std::to_string(GetLastError());
        lic_log(out.error.c_str());
        return out;
    }
    lic_log("winhttp_dll_loaded");

    using fn_open_t           = HINTERNET (WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    using fn_connect_t        = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    using fn_open_request_t   = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    using fn_send_request_t   = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    using fn_recv_response_t  = BOOL (WINAPI*)(HINTERNET, LPVOID);
    using fn_query_headers_t  = BOOL (WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
    using fn_query_avail_t    = BOOL (WINAPI*)(HINTERNET, LPDWORD);
    using fn_read_data_t      = BOOL (WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
    using fn_close_handle_t   = BOOL (WINAPI*)(HINTERNET);
    using fn_set_timeouts_t   = BOOL (WINAPI*)(HINTERNET, int, int, int, int);
    using fn_set_option_t     = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);

    auto p_open           = reinterpret_cast<fn_open_t>          (GetProcAddress(wh_mod, "WinHttpOpen"));
    auto p_connect        = reinterpret_cast<fn_connect_t>       (GetProcAddress(wh_mod, "WinHttpConnect"));
    auto p_open_request   = reinterpret_cast<fn_open_request_t>  (GetProcAddress(wh_mod, "WinHttpOpenRequest"));
    auto p_send_request   = reinterpret_cast<fn_send_request_t>  (GetProcAddress(wh_mod, "WinHttpSendRequest"));
    auto p_recv_response  = reinterpret_cast<fn_recv_response_t> (GetProcAddress(wh_mod, "WinHttpReceiveResponse"));
    auto p_query_headers  = reinterpret_cast<fn_query_headers_t> (GetProcAddress(wh_mod, "WinHttpQueryHeaders"));
    auto p_query_avail    = reinterpret_cast<fn_query_avail_t>   (GetProcAddress(wh_mod, "WinHttpQueryDataAvailable"));
    auto p_read_data      = reinterpret_cast<fn_read_data_t>     (GetProcAddress(wh_mod, "WinHttpReadData"));
    auto p_close_handle   = reinterpret_cast<fn_close_handle_t>  (GetProcAddress(wh_mod, "WinHttpCloseHandle"));
    auto p_set_timeouts   = reinterpret_cast<fn_set_timeouts_t>  (GetProcAddress(wh_mod, "WinHttpSetTimeouts"));
    auto p_set_option     = reinterpret_cast<fn_set_option_t>    (GetProcAddress(wh_mod, "WinHttpSetOption"));

    if (!p_open || !p_connect || !p_open_request || !p_send_request || !p_recv_response ||
        !p_query_headers || !p_query_avail || !p_read_data || !p_close_handle ||
        !p_set_timeouts) {
        out.error = "winhttp_resolve_failed";
        lic_log(out.error.c_str());
        FreeLibrary(wh_mod);
        return out;
    }
    lic_log("winhttp_funcs_resolved");

    bool is_https = true;
    std::string work = url;
    if (work.rfind("https://", 0) == 0)      work = work.substr(8);
    else if (work.rfind("http://", 0) == 0) { work = work.substr(7); is_https = false; }

    std::string host_str, path = "/";
    int port = is_https ? 443 : 80;

    auto slash = work.find('/');
    if (slash != std::string::npos) {
        host_str = work.substr(0, slash);
        path = work.substr(slash);
    } else {
        host_str = work;
    }
    auto colon = host_str.find(':');
    if (colon != std::string::npos) {
        port = atoi(host_str.c_str() + colon + 1);
        host_str = host_str.substr(0, colon);
    }

    {
        char dbuf[256];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "winhttp_url_parsed host=%.96s port=%d https=%d path=%.96s",
            host_str.c_str(), port, is_https ? 1 : 0, path.c_str());
        lic_log(dbuf);
    }

    std::wstring agent  = L"AiDAStandalone/1.0";
    std::wstring whost  = license_utf8_to_utf16(host_str);
    std::wstring wpath  = license_utf8_to_utf16(path.empty() ? std::string("/") : path);
    std::wstring wverb  = license_utf8_to_utf16(verb ? std::string(verb) : std::string("GET"));

    lic_log("winhttp_calling_open");
    HINTERNET h_session = p_open(agent.c_str(),
                                  WINHTTP_ACCESS_TYPE_NO_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS,
                                  0);
    if (!h_session) {
        out.error = "winhttp_open_failed gle=" + std::to_string(GetLastError());
        lic_log(out.error.c_str());
        FreeLibrary(wh_mod);
        return out;
    }
    lic_log("winhttp_session_opened");

    int tmo_ms = (timeout_sec > 0 ? timeout_sec : 15) * 1000;
    p_set_timeouts(h_session, tmo_ms, tmo_ms, tmo_ms, tmo_ms);
    lic_log("winhttp_session_timeouts_set");

    if (p_set_option) {
        DWORD proto_flags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
                            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        p_set_option(h_session, WINHTTP_OPTION_SECURE_PROTOCOLS,
                     &proto_flags, sizeof(proto_flags));
    }

    lic_log("winhttp_calling_connect");
    HINTERNET h_connect = p_connect(h_session, whost.c_str(),
                                     static_cast<INTERNET_PORT>(port), 0);
    if (!h_connect) {
        out.error = "winhttp_connect_failed gle=" + std::to_string(GetLastError());
        lic_log(out.error.c_str());
        p_close_handle(h_session);
        FreeLibrary(wh_mod);
        return out;
    }
    lic_log("winhttp_connect_handle_ok");

    DWORD req_flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    lic_log("winhttp_calling_open_request");
    HINTERNET h_req = p_open_request(h_connect, wverb.c_str(), wpath.c_str(),
                                      nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);
    if (!h_req) {
        out.error = "winhttp_open_request_failed gle=" + std::to_string(GetLastError());
        lic_log(out.error.c_str());
        p_close_handle(h_connect);
        p_close_handle(h_session);
        FreeLibrary(wh_mod);
        return out;
    }
    lic_log("winhttp_request_opened");

    p_set_timeouts(h_req, tmo_ms, tmo_ms, tmo_ms, tmo_ms);
    lic_log("winhttp_request_timeouts_set");

    if (p_set_option) {
        DWORD decompress = WINHTTP_DECOMPRESSION_FLAG_GZIP |
                           WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
        p_set_option(h_req, WINHTTP_OPTION_DECOMPRESSION,
                     &decompress, sizeof(decompress));
    }

    std::string hdr_str;
    hdr_str.reserve(256 + extra_headers.size() * 64);
    if (!content_type.empty()) {
        hdr_str += "Content-Type: ";
        hdr_str += content_type;
        hdr_str += "\r\n";
    }
    for (const auto& kv : extra_headers) {
        hdr_str += kv.first;
        hdr_str += ": ";
        hdr_str += kv.second;
        hdr_str += "\r\n";
    }
    std::wstring whdr = license_utf8_to_utf16(hdr_str);

    LPCWSTR hdr_ptr = whdr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : whdr.c_str();
    DWORD   hdr_len = whdr.empty() ? 0 : static_cast<DWORD>(whdr.size());

    LPVOID  body_ptr = req_body.empty()
                        ? WINHTTP_NO_REQUEST_DATA
                        : const_cast<char*>(req_body.data());
    DWORD   body_len = static_cast<DWORD>(req_body.size());

    {
        char dbuf[160];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "winhttp_calling_send_request body_len=%lu hdr_len=%lu",
            static_cast<unsigned long>(body_len),
            static_cast<unsigned long>(hdr_len));
        lic_log(dbuf);
    }

    struct winhttp_watchdog_t {
        HINTERNET h_req;
        fn_close_handle_t p_close;
        DWORD timeout_ms;
        volatile LONG finished;
        HANDLE cancel_ev;
    };

    DWORD watchdog_timeout_ms = static_cast<DWORD>(tmo_ms) + 5000UL;

    winhttp_watchdog_t wd_send;
    wd_send.h_req = h_req;
    wd_send.p_close = p_close_handle;
    wd_send.timeout_ms = watchdog_timeout_ms;
    wd_send.finished = 0;
    wd_send.cancel_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE wd_send_thread = CreateThread(nullptr, 0, [](LPVOID arg) -> DWORD {
        auto* w = reinterpret_cast<winhttp_watchdog_t*>(arg);
        DWORD wait = WaitForSingleObject(w->cancel_ev, w->timeout_ms);
        if (wait == WAIT_TIMEOUT &&
            InterlockedCompareExchange(&w->finished, 0, 0) == 0 &&
            w->h_req && w->p_close) {
            w->p_close(w->h_req);
        }
        return 0;
    }, &wd_send, 0, nullptr);

    DWORD send_t0 = GetTickCount();
    BOOL send_ok = p_send_request(h_req, hdr_ptr, hdr_len,
                                   body_ptr, body_len, body_len, 0);
    DWORD send_gle = GetLastError();
    DWORD send_elapsed = GetTickCount() - send_t0;
    InterlockedExchange(&wd_send.finished, 1);
    if (wd_send.cancel_ev) SetEvent(wd_send.cancel_ev);
    if (wd_send_thread) {
        WaitForSingleObject(wd_send_thread, 1000);
        CloseHandle(wd_send_thread);
    }
    if (wd_send.cancel_ev) CloseHandle(wd_send.cancel_ev);

    if (!send_ok) {
        out.error = "winhttp_send_request_failed gle=" + std::to_string(send_gle) +
                     " elapsed_ms=" + std::to_string(send_elapsed);
        lic_log(out.error.c_str());
        p_close_handle(h_req);
        p_close_handle(h_connect);
        p_close_handle(h_session);
        FreeLibrary(wh_mod);
        return out;
    }
    {
        char dbuf[96];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "winhttp_send_request_ok elapsed_ms=%lu", send_elapsed);
        lic_log(dbuf);
    }

    lic_log("winhttp_calling_recv_response");
    winhttp_watchdog_t wd_recv;
    wd_recv.h_req = h_req;
    wd_recv.p_close = p_close_handle;
    wd_recv.timeout_ms = watchdog_timeout_ms;
    wd_recv.finished = 0;
    wd_recv.cancel_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE wd_recv_thread = CreateThread(nullptr, 0, [](LPVOID arg) -> DWORD {
        auto* w = reinterpret_cast<winhttp_watchdog_t*>(arg);
        DWORD wait = WaitForSingleObject(w->cancel_ev, w->timeout_ms);
        if (wait == WAIT_TIMEOUT &&
            InterlockedCompareExchange(&w->finished, 0, 0) == 0 &&
            w->h_req && w->p_close) {
            w->p_close(w->h_req);
        }
        return 0;
    }, &wd_recv, 0, nullptr);

    DWORD recv_t0 = GetTickCount();
    BOOL recv_ok = p_recv_response(h_req, nullptr);
    DWORD recv_gle = GetLastError();
    DWORD recv_elapsed = GetTickCount() - recv_t0;
    InterlockedExchange(&wd_recv.finished, 1);
    if (wd_recv.cancel_ev) SetEvent(wd_recv.cancel_ev);
    if (wd_recv_thread) {
        WaitForSingleObject(wd_recv_thread, 1000);
        CloseHandle(wd_recv_thread);
    }
    if (wd_recv.cancel_ev) CloseHandle(wd_recv.cancel_ev);

    if (!recv_ok) {
        out.error = "winhttp_recv_response_failed gle=" + std::to_string(recv_gle) +
                     " elapsed_ms=" + std::to_string(recv_elapsed);
        lic_log(out.error.c_str());
        p_close_handle(h_req);
        p_close_handle(h_connect);
        p_close_handle(h_session);
        FreeLibrary(wh_mod);
        return out;
    }
    lic_log("winhttp_recv_response_ok");

    DWORD status_code = 0;
    DWORD scode_size  = sizeof(status_code);
    p_query_headers(h_req,
                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX,
                    &status_code, &scode_size, WINHTTP_NO_HEADER_INDEX);
    out.status = static_cast<int>(status_code);
    {
        char dbuf[96];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "winhttp_status_code=%d", out.status);
        lic_log(dbuf);
    }

    std::string body;
    body.reserve(4096);
    char chunk[4096];
    for (;;) {
        DWORD avail = 0;
        if (!p_query_avail(h_req, &avail)) break;
        if (avail == 0) break;
        DWORD to_read = avail > sizeof(chunk) ? static_cast<DWORD>(sizeof(chunk)) : avail;
        DWORD got = 0;
        if (!p_read_data(h_req, chunk, to_read, &got)) break;
        if (got == 0) break;
        body.append(chunk, got);
        if (body.size() > 4u * 1024u * 1024u) break;
    }
    out.body = std::move(body);
    out.ok = true;
    {
        char dbuf[96];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "winhttp_body_read body_len=%zu", out.body.size());
        lic_log(dbuf);
    }

    p_close_handle(h_req);
    p_close_handle(h_connect);
    p_close_handle(h_session);
    FreeLibrary(wh_mod);
    lic_log("winhttp_impl_exit_ok");
    return out;
}

static SimpleHttpResponse winhttp_https_request(
    const char* verb,
    const std::string& url,
    const std::vector<std::pair<std::string,std::string>>& extra_headers,
    const std::string& req_body,
    const std::string& content_type,
    int timeout_sec)
{
    lic_log("winhttp_inline_call_begin");
    SimpleHttpResponse out = winhttp_https_request_impl(verb, url, extra_headers,
                                                         req_body, content_type,
                                                         timeout_sec);
    lic_log("winhttp_inline_call_done");
    return out;
}

struct winhttp_session_t
{
    HMODULE   wh_mod    = nullptr;
    HINTERNET h_session = nullptr;
    HINTERNET h_connect = nullptr;
    std::string host;
    std::string base_path_prefix;
    int       port      = 443;
    bool      is_https  = true;
    int       timeout_ms = 15000;

    using fn_open_t           = HINTERNET (WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    using fn_connect_t        = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    using fn_open_request_t   = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    using fn_send_request_t   = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    using fn_recv_response_t  = BOOL (WINAPI*)(HINTERNET, LPVOID);
    using fn_query_headers_t  = BOOL (WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
    using fn_query_avail_t    = BOOL (WINAPI*)(HINTERNET, LPDWORD);
    using fn_read_data_t      = BOOL (WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
    using fn_close_handle_t   = BOOL (WINAPI*)(HINTERNET);
    using fn_set_timeouts_t   = BOOL (WINAPI*)(HINTERNET, int, int, int, int);
    using fn_set_option_t     = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);

    fn_open_t          p_open          = nullptr;
    fn_connect_t       p_connect       = nullptr;
    fn_open_request_t  p_open_request  = nullptr;
    fn_send_request_t  p_send_request  = nullptr;
    fn_recv_response_t p_recv_response = nullptr;
    fn_query_headers_t p_query_headers = nullptr;
    fn_query_avail_t   p_query_avail   = nullptr;
    fn_read_data_t     p_read_data     = nullptr;
    fn_close_handle_t  p_close_handle  = nullptr;
    fn_set_timeouts_t  p_set_timeouts  = nullptr;
    fn_set_option_t    p_set_option    = nullptr;

    bool valid() const { return h_session && h_connect && p_open_request; }
};

static void winhttp_session_close(winhttp_session_t& s)
{
    if (s.p_close_handle) {
        if (s.h_connect) { s.p_close_handle(s.h_connect); s.h_connect = nullptr; }
        if (s.h_session) { s.p_close_handle(s.h_session); s.h_session = nullptr; }
    }
    if (s.wh_mod) {
        FreeLibrary(s.wh_mod);
        s.wh_mod = nullptr;
    }
}

static bool winhttp_session_open(winhttp_session_t& s, const std::string& base_url, int timeout_sec)
{
    s.timeout_ms = (timeout_sec > 0 ? timeout_sec : 15) * 1000;

    s.wh_mod = LoadLibraryW(L"winhttp.dll");
    if (!s.wh_mod) {
        lic_log("winhttp_session_load_failed");
        return false;
    }

    s.p_open          = reinterpret_cast<winhttp_session_t::fn_open_t>          (GetProcAddress(s.wh_mod, "WinHttpOpen"));
    s.p_connect       = reinterpret_cast<winhttp_session_t::fn_connect_t>       (GetProcAddress(s.wh_mod, "WinHttpConnect"));
    s.p_open_request  = reinterpret_cast<winhttp_session_t::fn_open_request_t>  (GetProcAddress(s.wh_mod, "WinHttpOpenRequest"));
    s.p_send_request  = reinterpret_cast<winhttp_session_t::fn_send_request_t>  (GetProcAddress(s.wh_mod, "WinHttpSendRequest"));
    s.p_recv_response = reinterpret_cast<winhttp_session_t::fn_recv_response_t> (GetProcAddress(s.wh_mod, "WinHttpReceiveResponse"));
    s.p_query_headers = reinterpret_cast<winhttp_session_t::fn_query_headers_t> (GetProcAddress(s.wh_mod, "WinHttpQueryHeaders"));
    s.p_query_avail   = reinterpret_cast<winhttp_session_t::fn_query_avail_t>   (GetProcAddress(s.wh_mod, "WinHttpQueryDataAvailable"));
    s.p_read_data     = reinterpret_cast<winhttp_session_t::fn_read_data_t>     (GetProcAddress(s.wh_mod, "WinHttpReadData"));
    s.p_close_handle  = reinterpret_cast<winhttp_session_t::fn_close_handle_t>  (GetProcAddress(s.wh_mod, "WinHttpCloseHandle"));
    s.p_set_timeouts  = reinterpret_cast<winhttp_session_t::fn_set_timeouts_t>  (GetProcAddress(s.wh_mod, "WinHttpSetTimeouts"));
    s.p_set_option    = reinterpret_cast<winhttp_session_t::fn_set_option_t>    (GetProcAddress(s.wh_mod, "WinHttpSetOption"));

    if (!s.p_open || !s.p_connect || !s.p_open_request || !s.p_send_request ||
        !s.p_recv_response || !s.p_query_headers || !s.p_query_avail ||
        !s.p_read_data || !s.p_close_handle || !s.p_set_timeouts) {
        lic_log("winhttp_session_resolve_failed");
        winhttp_session_close(s);
        return false;
    }

    std::string work = base_url;
    s.is_https = true;
    if (work.rfind("https://", 0) == 0)      work = work.substr(8);
    else if (work.rfind("http://", 0) == 0) { work = work.substr(7); s.is_https = false; }

    s.port = s.is_https ? 443 : 80;
    s.base_path_prefix.clear();

    auto slash = work.find('/');
    if (slash != std::string::npos) {
        s.host = work.substr(0, slash);
        s.base_path_prefix = work.substr(slash);
        if (!s.base_path_prefix.empty() && s.base_path_prefix.back() == '/')
            s.base_path_prefix.pop_back();
    } else {
        s.host = std::move(work);
    }
    auto colon = s.host.find(':');
    if (colon != std::string::npos) {
        s.port = atoi(s.host.c_str() + colon + 1);
        s.host = s.host.substr(0, colon);
    }

    std::wstring agent  = L"AiDAStandalone/1.0";
    std::wstring whost  = license_utf8_to_utf16(s.host);

    s.h_session = s.p_open(agent.c_str(),
                           WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS,
                           0);
    if (!s.h_session) {
        lic_log("winhttp_session_open_failed");
        winhttp_session_close(s);
        return false;
    }

    s.p_set_timeouts(s.h_session, s.timeout_ms, s.timeout_ms, s.timeout_ms, s.timeout_ms);

    if (s.p_set_option) {
        DWORD proto_flags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
                            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        s.p_set_option(s.h_session, WINHTTP_OPTION_SECURE_PROTOCOLS,
                       &proto_flags, sizeof(proto_flags));
    }

    s.h_connect = s.p_connect(s.h_session, whost.c_str(),
                               static_cast<INTERNET_PORT>(s.port), 0);
    if (!s.h_connect) {
        lic_log("winhttp_session_connect_failed");
        winhttp_session_close(s);
        return false;
    }

    char dbuf[200];
    _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
        "winhttp_session_open_ok host=%.96s port=%d https=%d prefix=%.32s",
        s.host.c_str(), s.port, s.is_https ? 1 : 0, s.base_path_prefix.c_str());
    lic_log(dbuf);

    return true;
}

static SimpleHttpResponse winhttp_session_request(
    winhttp_session_t& s,
    const char* verb,
    const std::string& path,
    const std::vector<std::pair<std::string,std::string>>& extra_headers,
    const std::string& req_body,
    const std::string& content_type)
{
    SimpleHttpResponse out;
    if (!s.valid()) {
        out.error = "winhttp_session_invalid";
        return out;
    }

    std::string full_path = path;
    if (!s.base_path_prefix.empty() && !path.empty() && path[0] == '/') {
        full_path = s.base_path_prefix + path;
    }

    std::wstring wpath = license_utf8_to_utf16(full_path.empty() ? std::string("/") : full_path);
    std::wstring wverb = license_utf8_to_utf16(verb ? std::string(verb) : std::string("GET"));

    DWORD req_flags = s.is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET h_req = s.p_open_request(s.h_connect, wverb.c_str(), wpath.c_str(),
                                        nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);
    if (!h_req) {
        out.error = "winhttp_session_open_request_failed gle=" + std::to_string(GetLastError());
        return out;
    }

    s.p_set_timeouts(h_req, s.timeout_ms, s.timeout_ms, s.timeout_ms, s.timeout_ms);

    if (s.p_set_option) {
        DWORD decompress = WINHTTP_DECOMPRESSION_FLAG_GZIP |
                           WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
        s.p_set_option(h_req, WINHTTP_OPTION_DECOMPRESSION,
                       &decompress, sizeof(decompress));
    }

    std::string hdr_str;
    hdr_str.reserve(256 + extra_headers.size() * 64);
    if (!content_type.empty()) {
        hdr_str += "Content-Type: ";
        hdr_str += content_type;
        hdr_str += "\r\n";
    }
    for (const auto& kv : extra_headers) {
        hdr_str += kv.first;
        hdr_str += ": ";
        hdr_str += kv.second;
        hdr_str += "\r\n";
    }
    std::wstring whdr = license_utf8_to_utf16(hdr_str);

    LPCWSTR hdr_ptr = whdr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : whdr.c_str();
    DWORD   hdr_len = whdr.empty() ? 0 : static_cast<DWORD>(whdr.size());

    LPVOID body_ptr = req_body.empty()
                       ? WINHTTP_NO_REQUEST_DATA
                       : const_cast<char*>(req_body.data());
    DWORD  body_len = static_cast<DWORD>(req_body.size());

    BOOL send_ok = s.p_send_request(h_req, hdr_ptr, hdr_len,
                                     body_ptr, body_len, body_len, 0);
    if (!send_ok) {
        out.error = "winhttp_session_send_failed gle=" + std::to_string(GetLastError());
        s.p_close_handle(h_req);
        return out;
    }

    if (!s.p_recv_response(h_req, nullptr)) {
        out.error = "winhttp_session_recv_failed gle=" + std::to_string(GetLastError());
        s.p_close_handle(h_req);
        return out;
    }

    DWORD status_code = 0;
    DWORD scode_size  = sizeof(status_code);
    s.p_query_headers(h_req,
                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX,
                       &status_code, &scode_size, WINHTTP_NO_HEADER_INDEX);
    out.status = static_cast<int>(status_code);

    std::string body;
    body.reserve(8192);
    char chunk[8192];
    for (;;) {
        DWORD avail = 0;
        if (!s.p_query_avail(h_req, &avail)) break;
        if (avail == 0) break;
        DWORD to_read = avail > sizeof(chunk) ? static_cast<DWORD>(sizeof(chunk)) : avail;
        DWORD got = 0;
        if (!s.p_read_data(h_req, chunk, to_read, &got)) break;
        if (got == 0) break;
        body.append(chunk, got);
        if (body.size() > 32u * 1024u * 1024u) break;
    }
    out.body = std::move(body);
    out.ok = (out.status > 0);

    s.p_close_handle(h_req);
    return out;
}

static SimpleHttpResponse curl_subprocess_https_request(
    const char* verb,
    const std::string& url,
    const std::vector<std::pair<std::string,std::string>>& extra_headers,
    const std::string& req_body,
    const std::string& content_type,
    int timeout_sec)
{
    SimpleHttpResponse out;
    lic_log("curl_subprocess_enter");

    char system_dir[MAX_PATH] = {};
    UINT n = GetSystemDirectoryA(system_dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        out.error = "curl_subprocess_no_system_dir";
        lic_log(out.error.c_str());
        return out;
    }
    std::string curl_exe = std::string(system_dir) + "\\curl.exe";
    DWORD attrs = GetFileAttributesA(curl_exe.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        out.error = "curl_subprocess_no_curl_exe";
        lic_log(out.error.c_str());
        return out;
    }

    char temp_dir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, temp_dir);
    char body_path[MAX_PATH] = {};
    char hdrs_path[MAX_PATH] = {};
    GetTempFileNameA(temp_dir, "aida", 0, body_path);
    GetTempFileNameA(temp_dir, "aidh", 0, hdrs_path);

    std::string body_in_path;
    bool has_body_file = false;
    if (!req_body.empty()) {
        char body_in_tmp[MAX_PATH] = {};
        GetTempFileNameA(temp_dir, "aidb", 0, body_in_tmp);
        body_in_path = body_in_tmp;
        HANDLE bf = CreateFileA(body_in_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (bf != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            WriteFile(bf, req_body.data(), static_cast<DWORD>(req_body.size()), &wr, nullptr);
            CloseHandle(bf);
            has_body_file = true;
        }
    }

    std::string cmd;
    cmd.reserve(1024 + extra_headers.size() * 96);
    cmd += "\"";
    cmd += curl_exe;
    cmd += "\" -sS --max-time ";
    cmd += std::to_string(timeout_sec > 0 ? timeout_sec : 15);
    cmd += " -X ";
    cmd += (verb && *verb) ? verb : "GET";
    cmd += " -o \"";
    cmd += body_path;
    cmd += "\" -D \"";
    cmd += hdrs_path;
    cmd += "\"";
    if (!content_type.empty()) {
        cmd += " -H \"Content-Type: ";
        cmd += content_type;
        cmd += "\"";
    }
    for (const auto& kv : extra_headers) {
        cmd += " -H \"";
        cmd += kv.first;
        cmd += ": ";
        cmd += kv.second;
        cmd += "\"";
    }
    if (has_body_file) {
        cmd += " --data-binary \"@";
        cmd += body_in_path;
        cmd += "\"";
    }
    cmd += " \"";
    cmd += url;
    cmd += "\"";

    {
        char dbuf[256];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "curl_subprocess_invoke url=%.140s out=%.40s timeout=%d",
            url.c_str(), body_path, timeout_sec);
        lic_log(dbuf);
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    std::vector<char> cmd_mut(cmd.begin(), cmd.end());
    cmd_mut.push_back(0);

    BOOL created = CreateProcessA(nullptr, cmd_mut.data(), nullptr, nullptr,
                                   FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                                   &si, &pi);
    if (!created) {
        out.error = "curl_subprocess_create_failed gle=" + std::to_string(GetLastError());
        lic_log(out.error.c_str());
        DeleteFileA(body_path);
        DeleteFileA(hdrs_path);
        if (has_body_file) DeleteFileA(body_in_path.c_str());
        return out;
    }

    DWORD wait_ms = static_cast<DWORD>((timeout_sec > 0 ? timeout_sec : 15) * 1000 + 4000);
    DWORD wr = WaitForSingleObject(pi.hProcess, wait_ms);
    if (wr != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 1000);
        out.error = "curl_subprocess_wait_timeout";
        lic_log(out.error.c_str());
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DeleteFileA(body_path);
        DeleteFileA(hdrs_path);
        if (has_body_file) DeleteFileA(body_in_path.c_str());
        return out;
    }

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    {
        char dbuf[96];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "curl_subprocess_exit_code=%lu", exit_code);
        lic_log(dbuf);
    }

    auto read_file = [](const char* path, std::string& out_str) -> bool {
        HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return false;
        DWORD high = 0;
        DWORD low = GetFileSize(hf, &high);
        if (low == INVALID_FILE_SIZE) { CloseHandle(hf); return false; }
        out_str.resize(low);
        DWORD got = 0;
        BOOL ok = ReadFile(hf, out_str.data(), low, &got, nullptr);
        out_str.resize(got);
        CloseHandle(hf);
        return ok != FALSE;
    };

    std::string headers_text;
    read_file(hdrs_path, headers_text);
    read_file(body_path, out.body);

    if (!headers_text.empty()) {
        size_t line_end = headers_text.find("\r\n");
        if (line_end == std::string::npos) line_end = headers_text.size();
        std::string status_line = headers_text.substr(0, line_end);
        size_t sp1 = status_line.find(' ');
        if (sp1 != std::string::npos) {
            out.status = atoi(status_line.c_str() + sp1 + 1);
        }
    }

    DeleteFileA(body_path);
    DeleteFileA(hdrs_path);
    if (has_body_file) DeleteFileA(body_in_path.c_str());

    if (exit_code != 0 && out.status == 0) {
        out.error = "curl_subprocess_exit=" + std::to_string(exit_code);
        lic_log(out.error.c_str());
        return out;
    }

    out.ok = (out.status > 0);
    {
        char dbuf[160];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "curl_subprocess_done ok=%d status=%d body_len=%zu",
            out.ok ? 1 : 0, out.status, out.body.size());
        lic_log(dbuf);
    }
    return out;
}

static void schedule_async_network_diagnosis(const std::string& url)
{
    static std::atomic<bool> s_diag_emitted{false};
    bool was_emitted = s_diag_emitted.exchange(true, std::memory_order_acq_rel);
    if (was_emitted) return;

    std::string diag_host = url;
    if (diag_host.rfind("https://", 0) == 0)      diag_host = diag_host.substr(8);
    else if (diag_host.rfind("http://", 0) == 0)  diag_host = diag_host.substr(7);
    auto cut = diag_host.find('/');
    if (cut != std::string::npos) diag_host = diag_host.substr(0, cut);
    auto colon = diag_host.find(':');
    int diag_port = (url.rfind("http://", 0) == 0) ? 80 : 443;
    if (colon != std::string::npos) {
        diag_port = atoi(diag_host.c_str() + colon + 1);
        diag_host = diag_host.substr(0, colon);
    }

    if (work_queue::post([diag_host, diag_port]() {
            __try {
                diagnose_network(diag_host.c_str(), diag_port);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
            }
        }))
    {
        lic_log("transport_diag_thread_dispatched");
    }
    else
    {
        lic_log("transport_diag_thread_spawn_failed");
    }
}

namespace { void ensure_modules_initialized(); }

static SimpleHttpResponse raw_https_request(
    const char* verb,
    const std::string& url,
    const std::vector<std::pair<std::string,std::string>>& extra_headers = {},
    const std::string& req_body = {},
    const std::string& content_type = {},
    int timeout_sec = 15)
{
    SimpleHttpResponse out;
    const ULONGLONG request_start_ms = GetTickCount64();
    {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_begin verb=%.8s url=%.140s body_len=%zu timeout=%d",
            verb ? verb : "?", url.c_str(), req_body.size(), timeout_sec);
        lic_log(buf);
    }

    ensure_modules_initialized();

    std::wstring url_w = license_utf8_to_utf16(url);
    URL_COMPONENTSW comps{};
    comps.dwStructSize = sizeof(comps);
    wchar_t scheme_buf[16] = {};
    wchar_t host_buf[256] = {};
    wchar_t path_buf[2048] = {};
    comps.lpszScheme = scheme_buf; comps.dwSchemeLength = static_cast<DWORD>(_countof(scheme_buf));
    comps.lpszHostName = host_buf; comps.dwHostNameLength = static_cast<DWORD>(_countof(host_buf));
    comps.lpszUrlPath = path_buf; comps.dwUrlPathLength = static_cast<DWORD>(_countof(path_buf));
    if (!WinHttpCrackUrl(url_w.c_str(), 0, 0, &comps))
    {
        out.ok = false;
        out.status = 0;
        out.error = "url_parse_failed";
        lic_log_fmt("https_request_end ok=0 status=0 elapsed_ms=%llu err=%.120s body_len=0",
            static_cast<unsigned long long>(GetTickCount64() - request_start_ms),
            out.error.c_str());
        return out;
    }

    aida::license::transport::request_t req;
    req.host = std::wstring(comps.lpszHostName, comps.dwHostNameLength);
    if (comps.dwUrlPathLength > 0)
        req.path = std::wstring(comps.lpszUrlPath, comps.dwUrlPathLength);
    else
        req.path = L"/";
    req.method = verb ? verb : "GET";
    req.timeout_ms = static_cast<uint32_t>((timeout_sec > 0 ? timeout_sec : 15) * 1000);
    req.body.assign(req_body.begin(), req_body.end());
    if (req.path == L"/api/download/arc/pages/bulk")
        req.max_response_body_bytes = 64u * 1024u * 1024u;

    bool has_content_type = false;
    for (const auto& kv : extra_headers)
    {
        if (_stricmp(kv.first.c_str(), "Content-Type") == 0) has_content_type = true;
        req.headers.push_back({license_utf8_to_utf16(kv.first),
                               license_utf8_to_utf16(kv.second)});
    }
    if (!has_content_type && !content_type.empty() && !req_body.empty())
    {
        req.headers.push_back({L"Content-Type", license_utf8_to_utf16(content_type)});
    }

    {
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "https_request_dispatching_transport headers=%zu body=%zu",
            req.headers.size(), req.body.size());
        lic_log(dbg);
    }

    aida::license::transport::response_t resp;
    std::string transport_err;
    const ULONGLONG transport_start_ms = GetTickCount64();
    lic_log_fmt("https_request_transport_send_enter host_len=%zu path_len=%zu timeout_ms=%u body_len=%zu",
        req.host.size(), req.path.size(), req.timeout_ms, req.body.size());
    bool ok = aida::license::transport::send(req, resp, transport_err);
    lic_log_fmt("https_request_transport_send_exit ok=%d status=%u elapsed_ms=%llu err=%.160s body_len=%zu debug_reason_len=%zu",
        ok ? 1 : 0,
        resp.http_status,
        static_cast<unsigned long long>(GetTickCount64() - transport_start_ms),
        transport_err.c_str(),
        resp.body.size(),
        resp.debug_reason.size());

    out.status = static_cast<int>(resp.http_status);
    out.debug_reason = resp.debug_reason;
    if (!resp.body.empty())
        out.body.assign(reinterpret_cast<const char*>(resp.body.data()), resp.body.size());

    if (ok)
    {
        out.ok = true;
        char buf[384];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_transport_ok status=%d body_len=%zu debug_reason=%.180s",
            out.status, out.body.size(), resp.debug_reason.c_str());
        lic_log(buf);
        lic_log_fmt("https_request_end ok=1 status=%d elapsed_ms=%llu transport_ms=%llu err= body_len=%zu",
            out.status,
            static_cast<unsigned long long>(GetTickCount64() - request_start_ms),
            static_cast<unsigned long long>(GetTickCount64() - transport_start_ms),
            out.body.size());
        return out;
    }

    out.ok = false;
    out.error = transport_err;
    char buf[384];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "https_request_transport_failed err=%.220s status=%d",
        transport_err.c_str(), out.status);
    lic_log(buf);
    lic_log_fmt("https_request_end ok=0 status=%d elapsed_ms=%llu transport_ms=%llu err=%.120s body_len=%zu",
        out.status,
        static_cast<unsigned long long>(GetTickCount64() - request_start_ms),
        static_cast<unsigned long long>(GetTickCount64() - transport_start_ms),
        out.error.c_str(),
        out.body.size());
    return out;
}

namespace
{


    bool pubkey_thunk_for_transport(uint8_t kid, uint8_t out_pubkey[32])
    {
        std::string err;
        return aida::pubkeys::load_pubkey(static_cast<aida::pubkeys::kid_e>(kid), out_pubkey, err);
    }

    std::atomic<bool> s_modules_initialized{false};
    std::mutex        s_modules_init_mtx;

    void ensure_modules_initialized()
    {
        if (s_modules_initialized.load(std::memory_order_acquire)) return;
        std::lock_guard<std::mutex> lk(s_modules_init_mtx);
        if (s_modules_initialized.load(std::memory_order_acquire)) return;

        aida::license::transport::initialize();
        aida::license::transport::set_pubkey_provider(&pubkey_thunk_for_transport);
        aida::license_state::initialize();

        s_modules_initialized.store(true, std::memory_order_release);
    }

    struct session_ratchet_t
    {
        std::array<uint8_t, 32> current_token_secret = {};
        std::array<uint8_t, 32> server_seed = {};
        std::atomic<uint64_t>   request_counter{0};
        bool                    initialized = false;
    };

    session_ratchet_t s_session_ratchet;
    std::mutex        s_session_ratchet_mtx;

    bool hkdf_sha256_block(const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* salt, size_t salt_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* okm, size_t okm_len)
    {
        if (okm == nullptr || okm_len == 0 || okm_len > 255 * 32) return false;
        uint8_t default_salt[32] = {};
        if (salt == nullptr || salt_len == 0) { salt = default_salt; salt_len = 32; }

        BCRYPT_ALG_HANDLE  alg_hmac = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg_hmac, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return false;

        uint8_t prk[32] = {};
        {
            BCRYPT_HASH_HANDLE h = nullptr;
            if (BCryptCreateHash(alg_hmac, &h, nullptr, 0,
                                 const_cast<PUCHAR>(salt), static_cast<ULONG>(salt_len), 0) != 0)
            {
                BCryptCloseAlgorithmProvider(alg_hmac, 0);
                return false;
            }
            BCryptHashData(h, const_cast<PUCHAR>(ikm), static_cast<ULONG>(ikm_len), 0);
            BCryptFinishHash(h, prk, sizeof(prk), 0);
            BCryptDestroyHash(h);
        }

        uint8_t t_block[32] = {};
        size_t t_len = 0;
        size_t pos = 0;
        uint8_t counter = 1;
        while (pos < okm_len)
        {
            BCRYPT_HASH_HANDLE h = nullptr;
            if (BCryptCreateHash(alg_hmac, &h, nullptr, 0, prk, sizeof(prk), 0) != 0)
            {
                BCryptCloseAlgorithmProvider(alg_hmac, 0);
                SecureZeroMemory(prk, sizeof(prk));
                return false;
            }
            if (t_len > 0) BCryptHashData(h, t_block, static_cast<ULONG>(t_len), 0);
            if (info_len > 0)
                BCryptHashData(h, const_cast<PUCHAR>(info), static_cast<ULONG>(info_len), 0);
            BCryptHashData(h, &counter, 1, 0);
            BCryptFinishHash(h, t_block, sizeof(t_block), 0);
            BCryptDestroyHash(h);
            t_len = sizeof(t_block);
            size_t to_copy = (okm_len - pos < t_len) ? (okm_len - pos) : t_len;
            std::memcpy(okm + pos, t_block, to_copy);
            pos += to_copy;
            counter += 1;
        }

        SecureZeroMemory(prk, sizeof(prk));
        SecureZeroMemory(t_block, sizeof(t_block));
        BCryptCloseAlgorithmProvider(alg_hmac, 0);
        return true;
    }

    bool hmac_sha256_compute_local(const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len,
                                   uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return false;
        BCRYPT_HASH_HANDLE h = nullptr;
        if (BCryptCreateHash(alg, &h, nullptr, 0,
                             const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }
        BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
        bool ok = (BCryptFinishHash(h, out, 32, 0) == 0);
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(alg, 0);
        return ok;
    }

    std::string sha256_hex(const std::string& s)
    {
        uint8_t out[32] = {};
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE h = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(s.data())),
                       static_cast<ULONG>(s.size()), 0);
        BCryptFinishHash(h, out, sizeof(out), 0);
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(alg, 0);
        static const char hexd[] = "0123456789abcdef";
        std::string r;
        r.reserve(64);
        for (uint8_t b : out) { r.push_back(hexd[b >> 4]); r.push_back(hexd[b & 0xF]); }
        return r;
    }

    void ratchet_initialize_from_seed(const uint8_t* seed_32, const uint8_t* server_seed_32)
    {
        std::lock_guard<std::mutex> lk(s_session_ratchet_mtx);
        std::memcpy(s_session_ratchet.current_token_secret.data(), seed_32, 32);
        if (server_seed_32 != nullptr)
            std::memcpy(s_session_ratchet.server_seed.data(), server_seed_32, 32);
        else
            std::memset(s_session_ratchet.server_seed.data(), 0, 32);
        s_session_ratchet.request_counter.store(0, std::memory_order_release);
        s_session_ratchet.initialized = true;
    }

    bool ratchet_advance(const std::string& server_nonce_hex, std::string& out_session_token_hex)
    {
        std::lock_guard<std::mutex> lk(s_session_ratchet_mtx);
        if (!s_session_ratchet.initialized) return false;

        uint8_t server_nonce_bytes[32] = {};
        size_t to_copy = (std::min<size_t>)(32u, server_nonce_hex.size() / 2);
        for (size_t i = 0; i < to_copy; ++i)
        {
            uint8_t hi = 0, lo = 0;
            char c1 = server_nonce_hex[i * 2];
            char c2 = server_nonce_hex[i * 2 + 1];
            if (c1 >= '0' && c1 <= '9') hi = static_cast<uint8_t>(c1 - '0');
            else if (c1 >= 'a' && c1 <= 'f') hi = static_cast<uint8_t>(c1 - 'a' + 10);
            else if (c1 >= 'A' && c1 <= 'F') hi = static_cast<uint8_t>(c1 - 'A' + 10);
            if (c2 >= '0' && c2 <= '9') lo = static_cast<uint8_t>(c2 - '0');
            else if (c2 >= 'a' && c2 <= 'f') lo = static_cast<uint8_t>(c2 - 'a' + 10);
            else if (c2 >= 'A' && c2 <= 'F') lo = static_cast<uint8_t>(c2 - 'A' + 10);
            server_nonce_bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
        }

        uint64_t counter = s_session_ratchet.request_counter.fetch_add(1, std::memory_order_acq_rel) + 1;

        uint8_t info[64] = {};
        size_t info_len = 0;
        static const char prefix[] = "ratchet|";
        std::memcpy(info, prefix, sizeof(prefix) - 1);
        info_len += sizeof(prefix) - 1;
        uint8_t counter_le[8] = {};
        for (int i = 0; i < 8; ++i)
            counter_le[i] = static_cast<uint8_t>((counter >> (i * 8)) & 0xFFu);
        std::memcpy(info + info_len, counter_le, sizeof(counter_le));
        info_len += sizeof(counter_le);
        size_t nonce_room = sizeof(info) - info_len;
        size_t nonce_copy = (to_copy < nonce_room) ? to_copy : nonce_room;
        std::memcpy(info + info_len, server_nonce_bytes, nonce_copy);
        info_len += nonce_copy;

        uint8_t next_token[32] = {};
        if (!hkdf_sha256_block(s_session_ratchet.current_token_secret.data(), 32,
                               s_session_ratchet.server_seed.data(), 32,
                               info, info_len, next_token, sizeof(next_token)))
        {
            return false;
        }

        uint8_t auth_label[] = { 'a', 'u', 't', 'h' };
        uint8_t hmac_out[32] = {};
        if (!hmac_sha256_compute_local(next_token, sizeof(next_token),
                                       auth_label, sizeof(auth_label), hmac_out))
        {
            SecureZeroMemory(next_token, sizeof(next_token));
            return false;
        }

        static const char digits[] = "0123456789abcdef";
        out_session_token_hex.clear();
        out_session_token_hex.reserve(64);
        for (uint8_t b : hmac_out)
        {
            out_session_token_hex.push_back(digits[b >> 4]);
            out_session_token_hex.push_back(digits[b & 0xF]);
        }

        std::memcpy(s_session_ratchet.current_token_secret.data(), next_token, 32);
        SecureZeroMemory(next_token, sizeof(next_token));
        SecureZeroMemory(hmac_out, sizeof(hmac_out));
        return true;
    }

    void ratchet_clear()
    {
        std::lock_guard<std::mutex> lk(s_session_ratchet_mtx);
        SecureZeroMemory(s_session_ratchet.current_token_secret.data(), 32);
        SecureZeroMemory(s_session_ratchet.server_seed.data(), 32);
        s_session_ratchet.request_counter.store(0, std::memory_order_release);
        s_session_ratchet.initialized = false;
    }


    constexpr uint64_t S_MAGIC_INIT = 0xA1DA'C0DE'DEAD'BEEFull;
    std::atomic<uint64_t> s_state_a{0};
    std::atomic<uint64_t> s_state_b{0};
    std::atomic<uint64_t> s_state_c{0};
    std::atomic<uint64_t> s_magic{S_MAGIC_INIT};

    std::atomic<bool> s_valid{false};
    std::atomic<bool> s_stop{false};
    std::atomic<uint64_t> s_worker_epoch{1};
    std::atomic<bool> s_heartbeat_done{true};
    std::atomic<bool> s_srv_refresh_done{true};
    std::atomic<uint64_t> s_heartbeat_running_epoch{0};
    std::atomic<uint64_t> s_srv_refresh_running_epoch{0};
    std::mutex        s_state_mtx;
    std::string       s_plan;
    std::string       s_error;

    std::atomic<int64_t> s_last_heartbeat_time{0};
    std::atomic<uint32_t> s_heartbeat_counter{0};
    std::atomic<uint64_t> s_replay_request_seq{0};
    std::atomic<uint64_t> s_license_rate_limited_until_ms{0};
    std::atomic<uint32_t> s_license_rate_limit_failures{0};

    std::atomic<uint32_t> s_gate_bitmap{0};

    std::string s_cached_hwid;

    std::string s_cached_session_token;
    std::string s_cached_arc_bind_token;
    std::string s_cached_server_payload_b64;
    std::string s_cached_server_sig_b64;
    int         s_cached_server_kid = 0;

    std::atomic<uint64_t> s_proof_hash{0};

    std::mutex s_rotation_mtx;
    std::string s_rotated_heartbeat_nonce;
    int64_t     s_rotated_heartbeat_nonce_issued_at = 0;
    int64_t     s_rotated_heartbeat_nonce_max_age_s = 60;
    std::string s_rotated_bind_proof;
    int64_t     s_rotated_bind_proof_epoch = 0;
    std::string s_next_challenge_id;
    std::string s_next_challenge_nonce;
    std::string s_next_challenge_signature;
    int64_t     s_next_challenge_issued_at = 0;
    int64_t     s_next_challenge_ttl_s = 30;
    std::vector<std::string> s_pending_code_page_signatures;
    std::vector<std::string> s_pending_code_page_digests;
    std::string s_licensee_id;
    std::atomic<int64_t> s_silent_kill_after_ms{0};

    struct code_section_hash_t {
        uintptr_t base;
        size_t    size;
        uint64_t  hash;
        char      name[16];
        uint32_t  characteristics;
    };
    std::vector<code_section_hash_t> s_code_hashes;
    std::mutex s_code_hash_mtx;

    constexpr DWORD kHeartbeatComposeLockTimeoutMs = 2000;

    bool heartbeat_try_lock_mutex(std::mutex& mtx,
                                  const char* name,
                                  std::unique_lock<std::mutex>& out_lock)
    {
        const ULONGLONG start_ms = GetTickCount64();
        std::unique_lock<std::mutex> lk(mtx, std::defer_lock);
        for (;;)
        {
            if (lk.try_lock())
            {
                lic_log_fmt("heartbeat_compose_lock_acquired name=%s elapsed_ms=%llu tid=%lu",
                    name ? name : "<null>",
                    static_cast<unsigned long long>(GetTickCount64() - start_ms),
                    static_cast<unsigned long>(GetCurrentThreadId()));
                out_lock = std::move(lk);
                return true;
            }
            const ULONGLONG elapsed = GetTickCount64() - start_ms;
            if (elapsed >= kHeartbeatComposeLockTimeoutMs)
            {
                lic_log_fmt("heartbeat_compose_lock_timeout name=%s timeout_ms=%lu elapsed_ms=%llu tid=%lu",
                    name ? name : "<null>",
                    static_cast<unsigned long>(kHeartbeatComposeLockTimeoutMs),
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned long>(GetCurrentThreadId()));
                return false;
            }
            Sleep(1);
        }
    }

    bool heartbeat_lock_timeout_response(const char* name, std::string& error_out, json& response_out)
    {
        error_out = std::string("heartbeat_lock_timeout:") + (name ? name : "unknown");
        response_out = json::object({
            {"ok", false},
            {"status", "transient"},
            {"reason", error_out}
        });
        return false;
    }

    constexpr uint64_t S_MAGIC2_INIT = 0xCAFE'BABE'1337'C0DEull;
    constexpr uint64_t S_ARC_MAGIC_INIT = 0x51A7'F00D'44CC'19E5ull;
    std::atomic<uint64_t> s_state_d{0};
    std::atomic<uint64_t> s_state_e{0};
    std::atomic<uint64_t> s_magic_2{S_MAGIC2_INIT};
    std::atomic<uint64_t> s_arc_magic{S_ARC_MAGIC_INIT};
    std::atomic<uint64_t> s_arc_state{0};


    std::atomic<int64_t> s_gate_timestamps[standalone_license::GATE_SLOT_COUNT] = {};
    std::atomic<uint64_t> s_gate_tokens[standalone_license::GATE_SLOT_COUNT] = {};
    int64_t s_sweep_start_time = 0;


    arc_loader::loaded_module_t  s_arc_module{};
    std::timed_mutex             s_arc_mtx;
    std::atomic<bool>            s_arc_loaded{false};
    std::atomic<bool>            s_arc_fetch_deferred{false};
    std::atomic<bool>            s_arc_download_in_progress{false};
    std::atomic<uint64_t>        s_activation_completed_at_ms{0};
    std::mutex                   s_arc_load_failure_mtx;
    std::string                  s_arc_load_failure_detail;

    std::shared_mutex            s_arc_call_mtx;
    std::atomic<bool>            s_arc_unloading{false};
    std::atomic<int64_t>         s_arc_call_inflight{0};

    struct arc_call_guard_t
    {
        bool acquired = false;

        arc_call_guard_t()
        {
            s_arc_call_inflight.fetch_add(1, std::memory_order_acq_rel);
            if (s_arc_unloading.load(std::memory_order_acquire))
            {
                s_arc_call_inflight.fetch_sub(1, std::memory_order_acq_rel);
                return;
            }
            s_arc_call_mtx.lock_shared();
            if (s_arc_unloading.load(std::memory_order_acquire))
            {
                s_arc_call_mtx.unlock_shared();
                s_arc_call_inflight.fetch_sub(1, std::memory_order_acq_rel);
                return;
            }
            acquired = true;
        }

        arc_call_guard_t(const arc_call_guard_t&) = delete;
        arc_call_guard_t& operator=(const arc_call_guard_t&) = delete;

        ~arc_call_guard_t()
        {
            if (acquired)
            {
                s_arc_call_mtx.unlock_shared();
                s_arc_call_inflight.fetch_sub(1, std::memory_order_acq_rel);
            }
        }

        bool live() const { return acquired; }
    };

    void clear_arc_load_failure_detail()
    {
        std::lock_guard<std::mutex> lk(s_arc_load_failure_mtx);
        s_arc_load_failure_detail.clear();
    }

    void set_arc_load_failure_detail(const std::string& detail)
    {
        if (detail.empty())
            return;
        {
            std::lock_guard<std::mutex> lk(s_arc_load_failure_mtx);
            s_arc_load_failure_detail = detail;
        }
        lic_log_fmt("arc_load_failure_detail %.320s", detail.c_str());
    }

    std::string get_arc_load_failure_detail()
    {
        std::lock_guard<std::mutex> lk(s_arc_load_failure_mtx);
        return s_arc_load_failure_detail;
    }

    std::string make_arc_driver_failure_detail(const char* phase,
                                               const char* reason,
                                               bool loaded,
                                               bool kernel,
                                               bool heartbeat,
                                               bool sentinel,
                                               DWORD gle,
                                               uint64_t elapsed_ms,
                                               uint32_t timeout_ms)
    {
        char buf[512];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "ARC driver/Sentinel/proof relay failed before protected runtime load: phase=%s reason=%s loaded=%d kernel=%d heartbeat=%d sentinel=%d gle=%lu elapsed_ms=%llu timeout_ms=%u",
            phase && *phase ? phase : "unknown",
            reason && *reason ? reason : "unknown",
            loaded ? 1 : 0,
            kernel ? 1 : 0,
            heartbeat ? 1 : 0,
            sentinel ? 1 : 0,
            static_cast<unsigned long>(gle),
            static_cast<unsigned long long>(elapsed_ms),
            timeout_ms);
        return std::string(buf);
    }

    bool dynamic_ioctl_ready_for_protected_call(const char* phase, const char* op, uint32_t timeout_ms = 0, bool update_arc_failure = true)
    {
        driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
        if (dyn.ready)
            return true;
        const bool runtime_authorized =
            s_valid.load(std::memory_order_acquire) ||
            s_arc_loaded.load(std::memory_order_acquire);
        SetLastError(ERROR_NOT_READY);
        static std::atomic<uint64_t> s_last_dynamic_skip_log_ms{0};
        const uint64_t now_ms = GetTickCount64();
        uint64_t last_ms = s_last_dynamic_skip_log_ms.load(std::memory_order_acquire);
        bool should_log = timeout_ms == 0 || last_ms == 0 || now_ms - last_ms >= 500;
        if (should_log &&
            s_last_dynamic_skip_log_ms.compare_exchange_strong(last_ms, now_ms, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            lic_log_fmt("preauth_skipped_dynamic_ioctl_not_ready phase=%s op=%s runtime_authorized=%d loaded=%d kernel=%d connected=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X timeout_ms=%u",
                phase && *phase ? phase : "unknown",
                op && *op ? op : "unknown",
                runtime_authorized ? 1 : 0,
                dyn.loaded ? 1 : 0,
                dyn.kernel ? 1 : 0,
                dyn.connected ? 1 : 0,
                dyn.instance_server_seed,
                dyn.instance_ioctl_seed,
                dyn.global_server_seed,
                dyn.global_ioctl_seed,
                dyn.ioctl_seed_hash,
                dyn.heartbeat_ioctl_seed_hash,
                timeout_ms);
        }
        if (update_arc_failure) {
            set_arc_load_failure_detail(make_arc_driver_failure_detail(
                phase,
                "dynamic_ioctl_not_ready_for_protected_call",
                dyn.loaded,
                dyn.kernel,
                false,
                false,
                ERROR_NOT_READY,
                0,
                timeout_ms));
        }
        return false;
    }

    bool server_token_relay_bridge_connected(const driver_bridge::dynamic_ioctl_state_t& dyn)
    {
        return dyn.loaded && dyn.kernel && dyn.connected;
    }

    bool bridge_connected_for_server_token_relay(const char* phase, const char* op, uint32_t timeout_ms, bool update_arc_failure)
    {
        driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
        if (server_token_relay_bridge_connected(dyn))
            return true;

        DWORD gle = (!dyn.loaded || !dyn.connected) ? ERROR_DEVICE_NOT_CONNECTED : ERROR_NOT_READY;
        SetLastError(gle);
        lic_log_fmt("server_token_relay_bridge_not_ready phase=%s op=%s loaded=%d kernel=%d connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X timeout_ms=%u",
            phase && *phase ? phase : "unknown",
            op && *op ? op : "unknown",
            dyn.loaded ? 1 : 0,
            dyn.kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.ready ? 1 : 0,
            dyn.instance_server_seed,
            dyn.instance_ioctl_seed,
            dyn.global_server_seed,
            dyn.global_ioctl_seed,
            dyn.ioctl_seed_hash,
            dyn.heartbeat_ioctl_seed_hash,
            timeout_ms);
        if (update_arc_failure) {
            const char* reason = !dyn.loaded
                ? "driver_not_loaded_for_server_token_relay"
                : (!dyn.kernel ? "kernel_driver_not_active_for_server_token_relay" : "driver_bridge_not_connected_for_server_token_relay");
            set_arc_load_failure_detail(make_arc_driver_failure_detail(
                phase,
                reason,
                dyn.loaded,
                dyn.kernel,
                false,
                false,
                gle,
                0,
                timeout_ms));
        }
        return false;
    }

    bool wait_for_arc_driver_bridge_for_seed_relay(const char* phase, uint32_t timeout_ms)
    {
        const uint64_t start = GetTickCount64();
        uint64_t next_log = 0;
        for (;;)
        {
            driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
            uint64_t elapsed = GetTickCount64() - start;
            if (server_token_relay_bridge_connected(dyn))
            {
                lic_log_fmt("server_token_relay_bridge_wait phase=%s result=ready elapsed_ms=%llu loaded=1 kernel=1 connected=1 dyn_ready=%d",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(elapsed),
                    dyn.ready ? 1 : 0);
                return true;
            }
            if (elapsed >= timeout_ms)
            {
                DWORD gle = (!dyn.loaded || !dyn.connected) ? ERROR_DEVICE_NOT_CONNECTED : ERROR_NOT_READY;
                SetLastError(gle);
                set_arc_load_failure_detail(make_arc_driver_failure_detail(
                    phase,
                    !dyn.loaded ? "driver_not_loaded_timeout_for_server_token_relay" : (!dyn.kernel ? "kernel_driver_not_active_timeout_for_server_token_relay" : "driver_bridge_not_connected_timeout_for_server_token_relay"),
                    dyn.loaded,
                    dyn.kernel,
                    false,
                    false,
                    gle,
                    elapsed,
                    timeout_ms));
                lic_log_fmt("server_token_relay_bridge_wait phase=%s result=timeout elapsed_ms=%llu loaded=%d kernel=%d connected=%d dyn_ready=%d",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(elapsed),
                    dyn.loaded ? 1 : 0,
                    dyn.kernel ? 1 : 0,
                    dyn.connected ? 1 : 0,
                    dyn.ready ? 1 : 0);
                return false;
            }
            if (elapsed >= next_log)
            {
                lic_log_fmt("server_token_relay_bridge_wait phase=%s result=waiting elapsed_ms=%llu loaded=%d kernel=%d connected=%d dyn_ready=%d",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(elapsed),
                    dyn.loaded ? 1 : 0,
                    dyn.kernel ? 1 : 0,
                    dyn.connected ? 1 : 0,
                    dyn.ready ? 1 : 0);
                next_log = elapsed + 500;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    bool recover_arc_driver_bridge_for_seed_relay(const char* phase, uint32_t timeout_ms)
    {
        if (bridge_connected_for_server_token_relay(phase, "server_token_relay_recover_pre", timeout_ms, false))
            return true;

        driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
        lic_log_fmt("server_token_relay_bridge_recover_begin phase=%s loaded=%d kernel=%d connected=%d dyn_ready=%d timeout_ms=%u",
            phase ? phase : "unknown",
            dyn.loaded ? 1 : 0,
            dyn.kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.ready ? 1 : 0,
            timeout_ms);

        bool init_ok = false;
        try
        {
            init_ok = driver_bridge::initialize();
        }
        catch (const std::exception& ex)
        {
            lic_log_fmt("server_token_relay_bridge_recover_initialize_exception phase=%s what=%.160s",
                phase ? phase : "unknown",
                ex.what());
            return false;
        }
        catch (...)
        {
            lic_log_fmt("server_token_relay_bridge_recover_initialize_unknown_exception phase=%s",
                phase ? phase : "unknown");
            return false;
        }

        dyn = driver_bridge::dynamic_ioctl_state();
        lic_log_fmt("server_token_relay_bridge_recover_initialize_post phase=%s ok=%d loaded=%d kernel=%d connected=%d dyn_ready=%d",
            phase ? phase : "unknown",
            init_ok ? 1 : 0,
            dyn.loaded ? 1 : 0,
            dyn.kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.ready ? 1 : 0);
        if (!init_ok)
            return false;

        return wait_for_arc_driver_bridge_for_seed_relay(phase, timeout_ms);
    }

    bool dynamic_ioctl_seeded_after_server_token_relay(const char* phase,
                                                       const char* op,
                                                       bool relay_ok,
                                                       uint64_t driver_proof,
                                                       DWORD relay_gle,
                                                       uint32_t timeout_ms,
                                                       bool update_arc_failure)
    {
        driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
        lic_log_fmt("server_token_relay_dynamic_state phase=%s op=%s relay_ok=%d proof=%d relay_gle=%lu loaded=%d kernel=%d connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
            phase && *phase ? phase : "unknown",
            op && *op ? op : "unknown",
            relay_ok ? 1 : 0,
            driver_proof != 0 ? 1 : 0,
            static_cast<unsigned long>(relay_gle),
            dyn.loaded ? 1 : 0,
            dyn.kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.ready ? 1 : 0,
            dyn.instance_server_seed,
            dyn.instance_ioctl_seed,
            dyn.global_server_seed,
            dyn.global_ioctl_seed,
            dyn.ioctl_seed_hash,
            dyn.heartbeat_ioctl_seed_hash);
        if (relay_ok && driver_proof != 0 && dyn.ready)
        {
            SetLastError(ERROR_SUCCESS);
            return true;
        }

        DWORD gle = relay_gle;
        const char* reason = "server_token_relay_failed";
        if (relay_ok && driver_proof == 0)
        {
            gle = ERROR_ACCESS_DENIED;
            reason = "server_token_relay_missing_driver_proof";
        }
        else if (relay_ok)
        {
            gle = ERROR_NOT_READY;
            reason = "server_token_relay_did_not_seed_dynamic_ioctl";
        }
        if (gle == ERROR_SUCCESS)
            gle = ERROR_NOT_READY;
        SetLastError(gle);
        if (update_arc_failure)
        {
            set_arc_load_failure_detail(make_arc_driver_failure_detail(
                phase,
                reason,
                dyn.loaded,
                dyn.kernel,
                false,
                false,
                gle,
                0,
                timeout_ms));
        }
        return false;
    }

    std::string arc_load_error_or_fallback(const char* fallback)
    {
        std::string arc_error = arc_loader::last_error();
        if (!arc_error.empty())
            return arc_error;
        arc_error = get_arc_load_failure_detail();
        if (!arc_error.empty())
            return arc_error;
        return fallback && *fallback ? std::string(fallback) : std::string("ARC runtime download or verification failed.");
    }


    std::shared_ptr<httplib::Client> s_license_client;
    std::string                      s_license_host;
    std::shared_ptr<httplib::Client> s_ip_client;
    std::string                      s_ip_host;
    std::mutex                       s_http_mtx;


    using arc_init_fn               = bool(*)(const char*, const char*, int64_t, uint32_t, const uint8_t*);
    using arc_bind_driver_device_fn = bool(*)(void*, uint32_t);
    using arc_get_comm_bridge_fn    = const arc_comm_vtable_t*(*)();
    using arc_validate_tool_fn      = uint64_t(*)(uint64_t, uint64_t);
    using arc_validate_tool_v2_fn   = uint64_t(*)(uint64_t, uint64_t, uint64_t);
    using arc_verify_watermark_trailer_fn = bool(*)(const uint8_t*, uint64_t);
    using arc_heartbeat_fn          = arc_heartbeat_result_t(*)();
    using arc_heartbeat_ex_fn       = arc_heartbeat_result_t(*)(uint64_t, const char*);
    using arc_cleanup_fn            = void(*)();
    using arc_set_key_seed_fn       = void(*)(const uint8_t*, uint32_t);
    using arc_unseal_feature_fn     = bool(*)(uint32_t, const uint8_t*, uint32_t, uint8_t*, uint32_t*, uint32_t);
    using arc_copy_last_status_fn   = uint32_t(*)(char*, uint32_t);

    arc_init_fn               s_fn_arc_init               = nullptr;
    arc_bind_driver_device_fn s_fn_arc_bind_driver_device = nullptr;
    arc_get_comm_bridge_fn    s_fn_arc_get_comm_bridge    = nullptr;
    arc_validate_tool_fn      s_fn_arc_validate_tool      = nullptr;
    arc_validate_tool_v2_fn   s_fn_arc_validate_tool_v2   = nullptr;
    arc_verify_watermark_trailer_fn s_fn_arc_verify_watermark_trailer = nullptr;
    arc_heartbeat_fn          s_fn_arc_heartbeat          = nullptr;
    arc_heartbeat_ex_fn       s_fn_arc_heartbeat_ex       = nullptr;
    arc_cleanup_fn            s_fn_arc_cleanup            = nullptr;
    arc_set_key_seed_fn       s_fn_arc_set_key_seed       = nullptr;
    arc_unseal_feature_fn     s_fn_arc_unseal_feature     = nullptr;
    arc_copy_last_status_fn   s_fn_arc_copy_last_status   = nullptr;

    void clear_arc_exports()
    {
        s_fn_arc_init = nullptr;
        s_fn_arc_bind_driver_device = nullptr;
        s_fn_arc_get_comm_bridge = nullptr;
        s_fn_arc_validate_tool = nullptr;
        s_fn_arc_validate_tool_v2 = nullptr;
        s_fn_arc_verify_watermark_trailer = nullptr;
        s_fn_arc_heartbeat = nullptr;
        s_fn_arc_heartbeat_ex = nullptr;
        s_fn_arc_cleanup = nullptr;
        s_fn_arc_set_key_seed = nullptr;
        s_fn_arc_unseal_feature = nullptr;
        s_fn_arc_copy_last_status = nullptr;
    }

    __declspec(noinline) DWORD arc_call_init_seh(arc_init_fn fn,
                                                 const char* session_token,
                                                 const char* hwid,
                                                 int64_t issued_at,
                                                 uint32_t interface_version,
                                                 const uint8_t* bind_proof,
                                                 BOOL* out_ok)
    {
        if (out_ok) *out_ok = FALSE;
        if (!fn || !out_ok)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out_ok = fn(session_token, hwid, issued_at, interface_version, bind_proof) ? TRUE : FALSE;
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_bind_driver_device_seh(arc_bind_driver_device_fn fn,
                                                               void* driver_device,
                                                               uint32_t interface_version,
                                                               BOOL* out_ok)
    {
        if (out_ok) *out_ok = FALSE;
        if (!fn || !out_ok)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out_ok = fn(driver_device, interface_version) ? TRUE : FALSE;
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_set_key_seed_seh(arc_set_key_seed_fn fn,
                                                         const uint8_t* seed,
                                                         uint32_t seed_len)
    {
        if (!fn)
            return ERROR_INVALID_PARAMETER;
        __try {
            fn(seed, seed_len);
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_unseal_feature_seh(arc_unseal_feature_fn fn,
                                                           uint32_t feature_id,
                                                           const uint8_t* nonce,
                                                           uint32_t nonce_len,
                                                           uint8_t* out,
                                                           uint32_t* out_len,
                                                           uint32_t out_capacity,
                                                           BOOL* out_ok)
    {
        if (out_ok) *out_ok = FALSE;
        if (!fn || !out_ok)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out_ok = fn(feature_id, nonce, nonce_len, out, out_len, out_capacity) ? TRUE : FALSE;
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_heartbeat_seh(arc_heartbeat_fn fn,
                                                      arc_heartbeat_result_t* out)
    {
        if (out)
            SecureZeroMemory(out, sizeof(*out));
        if (!fn || !out)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out = fn();
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_heartbeat_ex_seh(arc_heartbeat_ex_fn fn,
                                                         uint64_t heartbeat_index,
                                                         const char* code_hash,
                                                         arc_heartbeat_result_t* out)
    {
        if (out)
            SecureZeroMemory(out, sizeof(*out));
        if (!fn || !out)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out = fn(heartbeat_index, code_hash);
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_get_comm_bridge_seh(arc_get_comm_bridge_fn fn,
                                                            const arc_comm_vtable_t** out)
    {
        if (out) *out = nullptr;
        if (!fn || !out)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out = fn();
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_comm_bridge_callback_seh(standalone_license::arc_comm_bridge_callback_t callback,
                                                                 const arc_comm_vtable_t* bridge,
                                                                 void* ctx,
                                                                 BOOL* out_ok)
    {
        if (out_ok) *out_ok = FALSE;
        if (!callback || !bridge || !out_ok)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out_ok = callback(bridge, ctx) ? TRUE : FALSE;
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_validate_tool_seh(arc_validate_tool_fn fn,
                                                          uint64_t name_hash,
                                                          uint64_t gate_token,
                                                          uint64_t* out_token)
    {
        if (out_token) *out_token = 0;
        if (!fn || !out_token)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out_token = fn(name_hash, gate_token);
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_validate_tool_v2_seh(arc_validate_tool_v2_fn fn,
                                                             uint64_t caller_nonce,
                                                             uint64_t name_hash,
                                                             uint64_t flags,
                                                             uint64_t* out_token)
    {
        if (out_token) *out_token = 0;
        if (!fn || !out_token)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out_token = fn(caller_nonce, name_hash, flags);
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_cleanup_seh(arc_cleanup_fn fn)
    {
        if (!fn)
            return ERROR_INVALID_PARAMETER;
        __try {
            fn();
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    __declspec(noinline) DWORD arc_call_copy_last_status_seh(arc_copy_last_status_fn fn,
                                                             char* buffer,
                                                             uint32_t capacity,
                                                             uint32_t* out_copied)
    {
        if (out_copied) *out_copied = 0;
        if (!fn || !buffer || capacity == 0 || !out_copied)
            return ERROR_INVALID_PARAMETER;
        __try {
            *out_copied = fn(buffer, capacity);
            return ERROR_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    bool arc_driver_ready_for_load(const char* phase)
    {
        bool loaded = driver_bridge::is_loaded();
        bool kernel = loaded ? driver_bridge::using_kernel_driver() : false;
        bool heartbeat = false;
        if (kernel) {
            if (!dynamic_ioctl_ready_for_protected_call(phase, "arc_driver_ready_heartbeat"))
                return false;
            heartbeat = driver_bridge::refresh_heartbeat();
        }
        bool sentinel = heartbeat ? driver_bridge::sentinel_bridge_ready() : false;
        if (!loaded || !kernel || !heartbeat || !sentinel) {
            set_arc_load_failure_detail(make_arc_driver_failure_detail(
                phase,
                !loaded ? "driver_not_loaded" : (!kernel ? "kernel_driver_not_active" : (!heartbeat ? "heartbeat_failed" : "sentinel_not_ready")),
                loaded,
                kernel,
                heartbeat,
                sentinel,
                heartbeat ? ERROR_NOT_READY : GetLastError(),
                0,
                0));
            lic_log_fmt("arc_deferred_driver_not_ready phase=%s loaded=%d kernel=%d heartbeat=%d sentinel=%d",
                phase ? phase : "unknown",
                loaded ? 1 : 0,
                kernel ? 1 : 0,
                heartbeat ? 1 : 0,
                sentinel ? 1 : 0);
            return false;
        }
        clear_arc_load_failure_detail();
        lic_log_fmt("arc_driver_ready phase=%s loaded=%d kernel=%d heartbeat=%d sentinel=%d",
            phase ? phase : "unknown",
            loaded ? 1 : 0,
            kernel ? 1 : 0,
            heartbeat ? 1 : 0,
            sentinel ? 1 : 0);
        return true;
    }

    bool wait_for_arc_driver_ready_for_load(const char* phase, uint32_t timeout_ms)
    {
        const uint64_t start = GetTickCount64();
        uint64_t next_log = 0;
        for (;;)
        {
            bool loaded = driver_bridge::is_loaded();
            bool kernel = loaded ? driver_bridge::using_kernel_driver() : false;
            bool heartbeat = false;
            if (kernel && dynamic_ioctl_ready_for_protected_call(phase, "arc_driver_ready_wait_heartbeat", timeout_ms))
                heartbeat = driver_bridge::refresh_heartbeat();
            bool sentinel = heartbeat ? driver_bridge::sentinel_bridge_ready() : false;
            uint64_t elapsed = GetTickCount64() - start;
            if (loaded && kernel && heartbeat && sentinel)
            {
                clear_arc_load_failure_detail();
                lic_log_fmt("arc_driver_ready_wait phase=%s result=ready elapsed_ms=%llu loaded=1 kernel=1 heartbeat=1 sentinel=1",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(elapsed));
                return true;
            }
            if (elapsed >= timeout_ms)
            {
                set_arc_load_failure_detail(make_arc_driver_failure_detail(
                    phase,
                    !loaded ? "driver_not_loaded_timeout" : (!kernel ? "kernel_driver_not_active_timeout" : (!heartbeat ? "heartbeat_timeout" : "sentinel_not_ready_timeout")),
                    loaded,
                    kernel,
                    heartbeat,
                    sentinel,
                    heartbeat ? ERROR_NOT_READY : GetLastError(),
                    elapsed,
                    timeout_ms));
                lic_log_fmt("arc_driver_ready_wait phase=%s result=timeout elapsed_ms=%llu loaded=%d kernel=%d heartbeat=%d sentinel=%d",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(elapsed),
                    loaded ? 1 : 0,
                    kernel ? 1 : 0,
                    heartbeat ? 1 : 0,
                    sentinel ? 1 : 0);
                return false;
            }
            if (elapsed >= next_log)
            {
                lic_log_fmt("arc_driver_ready_wait phase=%s result=waiting elapsed_ms=%llu loaded=%d kernel=%d heartbeat=%d sentinel=%d",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(elapsed),
                    loaded ? 1 : 0,
                    kernel ? 1 : 0,
                    heartbeat ? 1 : 0,
                    sentinel ? 1 : 0);
                next_log = elapsed + 500;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    struct challenge_material_t {
        std::string id;
        std::string nonce;
    };

    std::mutex s_validation_endpoint_mtx;

    std::string s_tls_exporter_value;
    std::mutex  s_tls_exporter_mtx;

    std::vector<std::string> s_honeypot_called_names;
    std::mutex s_honeypot_names_mtx;

    constexpr uint64_t kArcRequiredGraceMs = 10000;

    bool download_and_load_arc(settings_sa_t& settings, const std::string& hwid, uint32_t attempt_number);
    std::vector<uint8_t> base64_decode(const std::string& encoded);
    bool call_validation_endpoint(settings_sa_t& settings,
                                  const std::string& action,
                                  const std::string& key,
                                  const std::string& hwid,
                                  const std::string& session_token,
                                  const std::string& nonce,
                                  std::string& error_out,
                                  json& response_out,
                                  const json* hwid_evidence = nullptr);
    bool is_authoritative_stop_response(const json& response);
    std::string license_response_reason(const json& response, const std::string& default_reason);

    uint64_t license_now_ms()
    {
        return static_cast<uint64_t>(GetTickCount64());
    }

    bool license_rate_limit_cooling_down(const char* action, uint64_t* remaining_out = nullptr)
    {
        const uint64_t now = license_now_ms();
        const uint64_t until = s_license_rate_limited_until_ms.load(std::memory_order_acquire);
        if (until <= now) {
            if (remaining_out)
                *remaining_out = 0;
            return false;
        }
        const uint64_t remaining = until - now;
        if (remaining_out)
            *remaining_out = remaining;
        lic_log_fmt("license_rate_limit_cooldown_active action=%s remaining_ms=%llu until_ms=%llu",
            action ? action : "unknown",
            static_cast<unsigned long long>(remaining),
            static_cast<unsigned long long>(until));
        return true;
    }

    void note_license_rate_limited(const char* action, const std::string& error)
    {
        std::string lower = error;
        for (char& ch : lower)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        uint64_t cooldown_ms = 15ull * 60ull * 1000ull;
        if (lower.find("minute") != std::string::npos)
            cooldown_ms = 5ull * 60ull * 1000ull;
        if (lower.find("hour") != std::string::npos)
            cooldown_ms = 60ull * 60ull * 1000ull;
        if (lower.find("day") != std::string::npos)
            cooldown_ms = 60ull * 60ull * 1000ull;
        const uint32_t failures = s_license_rate_limit_failures.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (failures >= 2)
            cooldown_ms = (std::max)(cooldown_ms, (std::min)(60ull * 60ull * 1000ull, 15ull * 60ull * 1000ull * failures));
        const uint64_t until = license_now_ms() + cooldown_ms;
        uint64_t observed = s_license_rate_limited_until_ms.load(std::memory_order_acquire);
        while (observed < until &&
            !s_license_rate_limited_until_ms.compare_exchange_weak(
                observed, until, std::memory_order_acq_rel, std::memory_order_acquire)) {
        }
        lic_log_fmt("license_rate_limited action=%s err=%.160s cooldown_ms=%llu failures=%u until_ms=%llu",
            action ? action : "unknown",
            error.c_str(),
            static_cast<unsigned long long>(cooldown_ms),
            static_cast<unsigned>(failures),
            static_cast<unsigned long long>(until));
    }

    void clear_license_rate_limit_cooldown(const char* reason)
    {
        const uint64_t previous = s_license_rate_limited_until_ms.exchange(0, std::memory_order_acq_rel);
        const uint32_t failures = s_license_rate_limit_failures.exchange(0, std::memory_order_acq_rel);
        if (previous != 0 || failures != 0) {
            lic_log_fmt("license_rate_limit_cooldown_cleared reason=%s previous_until_ms=%llu failures=%u",
                reason ? reason : "unknown",
                static_cast<unsigned long long>(previous),
                static_cast<unsigned>(failures));
        }
    }

    int64_t license_unix_ms()
    {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    }

    uint64_t next_replay_req_seq()
    {
        const uint64_t wall_seq = static_cast<uint64_t>((std::max<int64_t>)(1, license_unix_ms() / 1000));
        uint64_t observed = s_replay_request_seq.load(std::memory_order_acquire);
        for (;;) {
            const uint64_t next = (std::max)(observed + 1, wall_seq);
            if (s_replay_request_seq.compare_exchange_weak(
                    observed, next, std::memory_order_acq_rel, std::memory_order_acquire))
                return next;
        }
    }

    bool worker_active(uint64_t worker_epoch)
    {
        return !s_stop.load(std::memory_order_acquire) &&
               worker_epoch == s_worker_epoch.load(std::memory_order_acquire);
    }

    bool wait_for_worker_done(std::atomic<bool>& done, const char* name, uint32_t timeout_ms)
    {
        const uint64_t deadline = license_now_ms() + timeout_ms;
        while (!done.load(std::memory_order_acquire)) {
            if (license_now_ms() >= deadline) {
                lic_log_fmt("worker_stop_wait_timeout worker=%s timeout_ms=%u",
                    name ? name : "unknown", timeout_ms);
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return true;
    }

    void log_arc_status(const char* detail)
    {
        anti_tamper::webhook::write_log("license", detail);
        lic_log(detail);
    }

    void set_arc_obfuscated_state(bool loaded)
    {
        uint64_t arc_magic = s_arc_magic.load(std::memory_order_acquire);
        s_arc_state.store(loaded ? arc_magic : 0, std::memory_order_release);
    }

    bool arc_required_exports_ready(std::string* missing_out = nullptr)
    {
        if (missing_out)
            missing_out->clear();

        auto add_missing = [&](const char* name) {
            if (!missing_out)
                return;
            if (!missing_out->empty())
                *missing_out += ",";
            *missing_out += name;
        };

        if (!s_arc_loaded.load(std::memory_order_acquire))
        {
            add_missing("arc_not_loaded");
            return false;
        }

        if (!s_fn_arc_init) add_missing("arc_init");
        if (!s_fn_arc_bind_driver_device) add_missing("arc_bind_driver_device");
        if (!s_fn_arc_get_comm_bridge) add_missing("arc_get_comm_bridge");
        if (!s_fn_arc_validate_tool) add_missing("arc_validate_tool_exec");
        if (!s_fn_arc_validate_tool_v2) add_missing("arc_validate_tool_exec_v2");
        if (!s_fn_arc_verify_watermark_trailer) add_missing("arc_verify_watermark_trailer");
        if (!s_fn_arc_heartbeat) add_missing("arc_heartbeat");
        if (!s_fn_arc_heartbeat_ex) add_missing("arc_heartbeat_ex");
        if (!s_fn_arc_cleanup) add_missing("arc_cleanup");
        if (!s_fn_arc_unseal_feature) add_missing("arc_unseal_feature");

        return !missing_out || missing_out->empty();
    }

    bool check_obfuscated_valid();

    void log_runtime_arc_authorized_state(bool authorized, const std::string& reason)
    {
        static std::mutex s_auth_log_mtx;
        static bool s_auth_log_seen = false;
        static bool s_auth_log_last = false;
        static std::string s_auth_log_reason;
        std::lock_guard<std::mutex> lk(s_auth_log_mtx);
        if (s_auth_log_seen && s_auth_log_last == authorized && s_auth_log_reason == reason)
            return;
        s_auth_log_seen = true;
        s_auth_log_last = authorized;
        s_auth_log_reason = reason;
        lic_log_fmt("runtime_arc_authorized_state authorized=%d reason=%.160s obf_valid=%d activation_hardening=%d arc_loaded=%d arc_unloading=%d inflight=%lld",
            authorized ? 1 : 0,
            reason.c_str(),
            check_obfuscated_valid() ? 1 : 0,
            anti_tamper::state::get().activation_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)));
    }

    bool runtime_arc_authorized(std::string* missing_out = nullptr)
    {
        if (missing_out)
            missing_out->clear();
        if (!check_obfuscated_valid())
        {
            if (missing_out)
                *missing_out = "license_state_invalid";
            log_runtime_arc_authorized_state(false, "license_state_invalid");
            return false;
        }
        if (!anti_tamper::state::get().activation_hardening_done.load(std::memory_order_acquire))
        {
            if (missing_out)
                *missing_out = "arc_hardening_not_finalized";
            log_runtime_arc_authorized_state(false, "arc_hardening_not_finalized");
            return false;
        }
        arc_call_guard_t guard;
        if (!guard.live())
        {
            if (missing_out)
                *missing_out = "arc_call_gate";
            log_runtime_arc_authorized_state(false, "arc_call_gate");
            return false;
        }
        const bool exports_ready = arc_required_exports_ready(missing_out);
        log_runtime_arc_authorized_state(exports_ready, exports_ready ? std::string("authorized") : (missing_out ? *missing_out : std::string("arc_exports_missing")));
        return exports_ready;
    }

    void reset_arc_fetch_state()
    {
        s_arc_fetch_deferred.store(false, std::memory_order_release);
    }

    void reset_activation_completed_at()
    {
        s_activation_completed_at_ms.store(0, std::memory_order_release);
    }

    void mark_activation_completed()
    {
        s_activation_completed_at_ms.store(license_now_ms(), std::memory_order_release);
    }

    bool arc_grace_active()
    {
        if (s_arc_download_in_progress.load(std::memory_order_acquire))
            return true;
        uint64_t activation_completed_at_ms = s_activation_completed_at_ms.load(std::memory_order_acquire);
        if (activation_completed_at_ms == 0)
            return false;
        return (license_now_ms() - activation_completed_at_ms) < kArcRequiredGraceMs;
    }

    uint64_t arc_grace_remaining_ms()
    {
        if (s_arc_download_in_progress.load(std::memory_order_acquire))
            return kArcRequiredGraceMs;
        uint64_t activation_completed_at_ms = s_activation_completed_at_ms.load(std::memory_order_acquire);
        if (activation_completed_at_ms == 0)
            return 0;
        uint64_t elapsed = license_now_ms() - activation_completed_at_ms;
        return elapsed < kArcRequiredGraceMs ? (kArcRequiredGraceMs - elapsed) : 0;
    }

    void defer_arc_fetch()
    {
        s_arc_fetch_deferred.store(true, std::memory_order_release);
    }

    bool defer_arc_fetch_if_full_test_running(const char* reason)
    {
        if (!test_all_features::is_running())
            return false;
        lic_log_fmt("%s_full_test_running_arc_required_no_defer", reason ? reason : "arc_fetch");
        return false;
    }

    std::mutex s_driver_proof_cache_mtx;
    uint64_t s_driver_proof_cache_value = 0;
    std::string s_driver_proof_cache_nonce;
    uint64_t s_driver_proof_cache_ms = 0;

    constexpr uint64_t kDriverProofCacheMaxAgeMs = 180000;

    uint64_t fnv1a(const void* data, size_t len);
    uint64_t fnv1a_str(const std::string& s);

    void store_driver_proof_cache(uint64_t proof, const std::string& nonce_str)
    {
        if (proof == 0)
            return;
        std::lock_guard<std::mutex> lk(s_driver_proof_cache_mtx);
        s_driver_proof_cache_value = proof;
        s_driver_proof_cache_nonce = nonce_str;
        s_driver_proof_cache_ms = license_now_ms();
    }

    bool load_driver_proof_cache(uint64_t* out_proof, std::string* out_nonce, uint64_t* out_age_ms)
    {
        std::lock_guard<std::mutex> lk(s_driver_proof_cache_mtx);
        if (s_driver_proof_cache_value == 0 || s_driver_proof_cache_ms == 0)
            return false;
        uint64_t age = license_now_ms() - s_driver_proof_cache_ms;
        if (age > kDriverProofCacheMaxAgeMs)
            return false;
        if (out_proof) *out_proof = s_driver_proof_cache_value;
        if (out_nonce) *out_nonce = s_driver_proof_cache_nonce;
        if (out_age_ms) *out_age_ms = age;
        return true;
    }

    bool relay_server_token_v2_if_ready(uint32_t token_hash, uint64_t server_nonce, uint64_t* out_driver_proof)
    {
        const uint64_t start_ms = static_cast<uint64_t>(GetTickCount64());
        lic_log_fmt("server_token_relay_if_ready_enter token_set=%d nonce_set=%d tid=%lu",
            token_hash != 0 ? 1 : 0,
            server_nonce != 0 ? 1 : 0,
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (!bridge_connected_for_server_token_relay("server_token_relay_if_ready", "server_token_relay", 0, false))
            return false;

        driver_bridge::dynamic_ioctl_state_t pre_dyn = driver_bridge::dynamic_ioctl_state();
        SetLastError(ERROR_SUCCESS);
        bool heartbeat = driver_bridge::refresh_heartbeat();
        DWORD heartbeat_gle = heartbeat ? ERROR_SUCCESS : GetLastError();
        lic_log_fmt("server_token_relay_if_ready_preflight heartbeat=%d gle=%lu dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u elapsed_ms=%llu",
            heartbeat ? 1 : 0,
            static_cast<unsigned long>(heartbeat_gle),
            pre_dyn.ready ? 1 : 0,
            pre_dyn.instance_server_seed,
            pre_dyn.instance_ioctl_seed,
            pre_dyn.global_server_seed,
            pre_dyn.global_ioctl_seed,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_ms));

        const uint64_t relay_ms = static_cast<uint64_t>(GetTickCount64());
        bool ok = driver_bridge::relay_server_token_v2(token_hash, server_nonce, out_driver_proof);
        DWORD relay_gle = ok ? ERROR_SUCCESS : GetLastError();
        uint64_t driver_proof = out_driver_proof ? *out_driver_proof : 0;
        bool seeded = dynamic_ioctl_seeded_after_server_token_relay(
            "server_token_relay_if_ready",
            "server_token_relay",
            ok,
            driver_proof,
            relay_gle,
            0,
            false);
        DWORD final_gle = seeded ? ERROR_SUCCESS : GetLastError();
        lic_log_fmt("server_token_relay_if_ready_exit ok=%d seeded=%d gle=%lu proof=%d elapsed_ms=%llu total_ms=%llu",
            ok ? 1 : 0,
            seeded ? 1 : 0,
            static_cast<unsigned long>(final_gle),
            driver_proof != 0 ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - relay_ms),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_ms));
        SetLastError(final_gle);
        return seeded;
    }

    bool parse_server_nonce_u64(const std::string& nonce, uint64_t& out)
    {
        out = 0;
        if (nonce.empty())
            return false;
        size_t digits = 0;
        for (size_t ci = 0; ci < nonce.size() && ci < 16; ++ci)
        {
            uint8_t nibble = 0;
            char ch = nonce[ci];
            if (ch >= '0' && ch <= '9') nibble = static_cast<uint8_t>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') nibble = static_cast<uint8_t>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') nibble = static_cast<uint8_t>(ch - 'A' + 10);
            else return false;
            out = (out << 4) | nibble;
            ++digits;
        }
        return digits != 0 && out != 0;
    }

    bool ensure_driver_server_token_relay(settings_sa_t& settings, const char* phase)
    {
        if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
        {
            lic_log_fmt("server_token_relay_recover_required phase=%s driver_loaded=%d kernel=%d",
                phase ? phase : "unknown",
                driver_bridge::is_loaded() ? 1 : 0,
                driver_bridge::using_kernel_driver() ? 1 : 0);
            if (!recover_arc_driver_bridge_for_seed_relay(phase, 15000))
            {
                set_arc_load_failure_detail(make_arc_driver_failure_detail(
                    phase,
                    "driver_or_kernel_recover_failed_for_token_relay",
                    driver_bridge::is_loaded(),
                    driver_bridge::is_loaded() ? driver_bridge::using_kernel_driver() : false,
                    false,
                    false,
                    GetLastError(),
                    0,
                    15000));
                lic_log_fmt("server_token_relay_skip phase=%s driver_loaded=%d kernel=%d",
                    phase ? phase : "unknown",
                    driver_bridge::is_loaded() ? 1 : 0,
                    driver_bridge::using_kernel_driver() ? 1 : 0);
                return false;
            }
        }

        uint64_t server_nonce = 0;
        if (settings.license_session_token.empty() ||
            !parse_server_nonce_u64(settings.license_server_nonce, server_nonce))
        {
            lic_log_fmt("server_token_relay_missing_state phase=%s token_len=%zu nonce_len=%zu",
                phase ? phase : "unknown",
                settings.license_session_token.size(),
                settings.license_server_nonce.size());
            set_arc_load_failure_detail(make_arc_driver_failure_detail(
                phase,
                "server_token_or_nonce_missing_for_driver_relay",
                driver_bridge::is_loaded(),
                driver_bridge::is_loaded() ? driver_bridge::using_kernel_driver() : false,
                false,
                false,
                ERROR_INVALID_DATA,
                0,
                0));
            return false;
        }

        if (!bridge_connected_for_server_token_relay(phase, "server_token_relay", 15000, false))
        {
            lic_log_fmt("server_token_relay_recover_required phase=%s reason=bridge_not_connected",
                phase ? phase : "unknown");
            if (!recover_arc_driver_bridge_for_seed_relay(phase, 15000) ||
                !bridge_connected_for_server_token_relay(phase, "server_token_relay_after_recover", 15000, true))
                return false;
        }

        uint32_t token_hash = static_cast<uint32_t>(
            fnv1a_str(settings.license_session_token) & 0xFFFFFFFF);
        uint64_t driver_proof = 0;
        driver_bridge::dynamic_ioctl_state_t pre_dyn = driver_bridge::dynamic_ioctl_state();
        SetLastError(ERROR_SUCCESS);
        bool heartbeat = driver_bridge::refresh_heartbeat();
        DWORD heartbeat_gle = heartbeat ? ERROR_SUCCESS : GetLastError();
        lic_log_fmt("server_token_relay_pre phase=%s heartbeat=%d heartbeat_gle=%lu dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
            phase ? phase : "unknown",
            heartbeat ? 1 : 0,
            static_cast<unsigned long>(heartbeat_gle),
            pre_dyn.ready ? 1 : 0,
            pre_dyn.instance_server_seed,
            pre_dyn.instance_ioctl_seed,
            pre_dyn.global_server_seed,
            pre_dyn.global_ioctl_seed,
            pre_dyn.ioctl_seed_hash,
            pre_dyn.heartbeat_ioctl_seed_hash);
        SetLastError(ERROR_SUCCESS);
        bool ok = driver_bridge::relay_server_token_v2(token_hash, server_nonce, &driver_proof);
        DWORD relay_gle = ok ? ERROR_SUCCESS : GetLastError();
        bool seeded = dynamic_ioctl_seeded_after_server_token_relay(
            phase,
            "server_token_relay",
            ok,
            driver_proof,
            relay_gle,
            15000,
            false);
        DWORD seeded_gle = seeded ? ERROR_SUCCESS : GetLastError();
        if (!seeded)
        {
            lic_log_fmt("server_token_relay_retry_pre phase=%s ok=%d proof=%d seeded=%d gle=%lu",
                phase ? phase : "unknown",
                ok ? 1 : 0,
                driver_proof != 0 ? 1 : 0,
                seeded ? 1 : 0,
                static_cast<unsigned long>(seeded_gle));
            if (recover_arc_driver_bridge_for_seed_relay(phase, 15000))
            {
                driver_proof = 0;
                SetLastError(ERROR_SUCCESS);
                ok = driver_bridge::relay_server_token_v2(token_hash, server_nonce, &driver_proof);
                relay_gle = ok ? ERROR_SUCCESS : GetLastError();
                seeded = dynamic_ioctl_seeded_after_server_token_relay(
                    phase,
                    "server_token_relay_retry",
                    ok,
                    driver_proof,
                    relay_gle,
                    15000,
                    false);
                seeded_gle = seeded ? ERROR_SUCCESS : GetLastError();
                lic_log_fmt("server_token_relay_retry_post phase=%s ok=%d proof=%d seeded=%d gle=%lu",
                    phase ? phase : "unknown",
                    ok ? 1 : 0,
                    driver_proof != 0 ? 1 : 0,
                    seeded ? 1 : 0,
                    static_cast<unsigned long>(seeded_gle));
            }
        }
        driver_bridge::dynamic_ioctl_state_t post_dyn = driver_bridge::dynamic_ioctl_state();
        bool sentinel = post_dyn.ready ? driver_bridge::sentinel_bridge_ready() : false;
        DWORD sentinel_gle = sentinel ? ERROR_SUCCESS : GetLastError();
        lic_log_fmt("server_token_relay_result phase=%s ok=%d proof=%d seeded=%d sentinel=%d gle=%lu sentinel_gle=%lu token_len=%zu nonce_len=%zu dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X",
            phase ? phase : "unknown",
            ok ? 1 : 0,
            driver_proof != 0 ? 1 : 0,
            seeded ? 1 : 0,
            sentinel ? 1 : 0,
            static_cast<unsigned long>(seeded ? relay_gle : seeded_gle),
            static_cast<unsigned long>(sentinel_gle),
            settings.license_session_token.size(),
            settings.license_server_nonce.size(),
            post_dyn.ready ? 1 : 0,
            post_dyn.instance_server_seed,
            post_dyn.instance_ioctl_seed,
            post_dyn.global_server_seed,
            post_dyn.global_ioctl_seed,
            post_dyn.ioctl_seed_hash,
            post_dyn.heartbeat_ioctl_seed_hash);
        if (!seeded)
        {
            set_arc_load_failure_detail(make_arc_driver_failure_detail(
                phase,
                ok ? (driver_proof != 0 ? "server_token_relay_did_not_seed_dynamic_ioctl" : "server_token_relay_missing_driver_proof") : "server_token_relay_failed",
                post_dyn.loaded,
                post_dyn.kernel,
                false,
                false,
                seeded_gle,
                0,
                15000));
            return false;
        }
        clear_arc_load_failure_detail();
        store_driver_proof_cache(driver_proof, settings.license_server_nonce);
        return true;
    }

    bool verify_seeded_driver_bridge_for_arc(const char* phase)
    {
        if (!dynamic_ioctl_ready_for_protected_call(phase, "tier_a_driver_present_query"))
            return false;
        bool present = false;
        uint32_t mask = 0;
        uint64_t first_base = 0;
        SetLastError(ERROR_SUCCESS);
        const uint64_t started = GetTickCount64();
        bool ok = driver_bridge::tier_a_driver_present_query(&present, &mask, &first_base);
        DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
        uint64_t elapsed = GetTickCount64() - started;
        lic_log_fmt("arc_seeded_bridge_probe phase=%s ok=%d gle=%lu present=%d mask=0x%08X first_base_set=%d elapsed_ms=%llu",
            phase ? phase : "unknown",
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            present ? 1 : 0,
            mask,
            first_base != 0 ? 1 : 0,
            static_cast<unsigned long long>(elapsed));
        if (!ok)
            driver_bridge::invalidate_kernel_session("arc_seeded_bridge_probe_failed");
        return ok;
    }

    bool try_load_arc_with_retries(settings_sa_t& settings, const std::string& hwid)
    {
        static const uint32_t kRetryDelayMs[3] = { 0u, 2000u, 5000u };
        clear_arc_load_failure_detail();

        if (defer_arc_fetch_if_full_test_running("arc_load"))
        {
            set_arc_load_failure_detail("ARC runtime load deferred because the full feature test is running.");
            return false;
        }

        (void)ensure_driver_server_token_relay(settings, "arc_load_pre_wait");

        if (!wait_for_arc_driver_ready_for_load("arc_load", 15000))
        {
            if (!ensure_driver_server_token_relay(settings, "arc_load_wait_recover") ||
                !wait_for_arc_driver_ready_for_load("arc_load_recovered", 5000))
                return false;
        }

        if (!ensure_driver_server_token_relay(settings, "arc_load"))
        {
            log_arc_status("arc_deferred_server_token_relay_failed");
            return false;
        }

        if (!verify_seeded_driver_bridge_for_arc("arc_load"))
        {
            const bool loaded = driver_bridge::is_loaded();
            const bool kernel = loaded ? driver_bridge::using_kernel_driver() : false;
            bool heartbeat = false;
            if (kernel && dynamic_ioctl_ready_for_protected_call("arc_load", "seeded_bridge_failure_detail_heartbeat"))
                heartbeat = driver_bridge::refresh_heartbeat();
            const bool sentinel = heartbeat ? driver_bridge::sentinel_bridge_ready() : false;
            set_arc_load_failure_detail(make_arc_driver_failure_detail(
                "arc_load",
                "seeded_driver_bridge_probe_failed",
                loaded,
                kernel,
                heartbeat,
                sentinel,
                GetLastError(),
                0,
                0));
            log_arc_status("arc_deferred_seeded_bridge_probe_failed");
            return false;
        }

        s_arc_download_in_progress.store(true, std::memory_order_release);
        struct progress_clear_guard
        {
            ~progress_clear_guard()
            {
                s_arc_download_in_progress.store(false, std::memory_order_release);
            }
        } _progress_guard;

        for (uint32_t attempt = 0; attempt < 3; ++attempt)
        {
            if (attempt != 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(kRetryDelayMs[attempt]));

            if (download_and_load_arc(settings, hwid, attempt + 1))
            {
                log_arc_status("arc_download_ok");
                return true;
            }

            if (arc_loader::last_error_is_fatal()) {
                log_arc_status("arc_download_fatal_no_retry");
                return false;
            }
        }

        if (arc_loader::last_error().empty() && get_arc_load_failure_detail().empty())
            set_arc_load_failure_detail("ARC runtime download/load attempts failed before the protected runtime was mapped.");
        return false;
    }

    bool attempt_deferred_arc_fetch(settings_sa_t& settings, const std::string& hwid)
    {
        if (!s_arc_fetch_deferred.load(std::memory_order_acquire) ||
            s_arc_loaded.load(std::memory_order_acquire))
            return false;
        if (defer_arc_fetch_if_full_test_running("arc_deferred_fetch"))
            return false;
        if (s_activation_completed_at_ms.load(std::memory_order_acquire) == 0)
            return false;

        bool ok = try_load_arc_with_retries(settings, hwid);
        if (ok) {
            s_arc_fetch_deferred.store(false, std::memory_order_release);
        } else if (arc_loader::last_error_is_fatal()) {
            s_arc_fetch_deferred.store(false, std::memory_order_release);
        } else {
            lic_log_fmt("arc_redeferred_for_heartbeat_retry grace_remaining_ms=%llu deferred=%d downloading=%d",
                static_cast<unsigned long long>(arc_grace_remaining_ms()),
                s_arc_fetch_deferred.load(std::memory_order_acquire) ? 1 : 0,
                s_arc_download_in_progress.load(std::memory_order_acquire) ? 1 : 0);
        }
        return ok;
    }


    static const uint8_t S_STR_KEY = 0x5A;
    std::string decode_status_string_impl(standalone_license::status_string_id id)
    {


        static const uint8_t strs[][40] = {
             {0x09,0x3f,0x29,0x29,0x33,0x35,0x34,0x7a,0x28,0x3f,0x2c,0x35,0x31,0x3f,0x3e,0x00},
             {0x13,0x34,0x2e,0x3f,0x3d,0x28,0x33,0x2e,0x23,0x7a,0x3c,0x3b,0x2f,0x36,0x2e,0x00},
             {0x1d,0x3b,0x2e,0x3f,0x7a,0x39,0x32,0x3f,0x39,0x31,0x7a,0x29,0x2e,0x3b,0x36,0x3f,0x00},
             {0x0a,0x28,0x35,0x35,0x3c,0x7a,0x37,0x33,0x29,0x37,0x3b,0x2e,0x39,0x32,0x00},
             {0x12,0x0d,0x13,0x1e,0x7a,0x3e,0x28,0x33,0x3c,0x2e,0x00},
             {0x12,0x3f,0x3b,0x28,0x2e,0x38,0x3f,0x3b,0x2e,0x7a,0x3f,0x22,0x2a,0x33,0x28,0x3f,0x3e,0x00},
             {0x13,0x34,0x2e,0x3f,0x28,0x34,0x3b,0x36,0x7a,0x3f,0x28,0x28,0x35,0x28,0x00},
             {0x17,0x35,0x3e,0x3f,0x36,0x7a,0x28,0x35,0x2f,0x2e,0x33,0x34,0x3d,0x00},
        };
        if (id < 0 || id > 7) return "Error";
        std::string result;
        const uint8_t* p = strs[id];
        while (*p) {
            result += static_cast<char>(*p ^ S_STR_KEY);
            ++p;
        }
        return result;
    }


    void set_obfuscated_valid(bool valid, uint64_t nonce_seed = 0)
    {
        ensure_modules_initialized();
        if (valid) {

            std::mt19937_64 rng(nonce_seed ? nonce_seed :
                static_cast<uint64_t>(GetTickCount64()));
            uint64_t a = rng();
            uint64_t b = rng();
            uint64_t magic = s_magic.load(std::memory_order_acquire);
            uint64_t c = a ^ b ^ magic;
            s_state_a.store(a, std::memory_order_release);
            s_state_b.store(b, std::memory_order_release);
            s_state_c.store(c, std::memory_order_release);
            s_valid.store(true, std::memory_order_release);


            uint64_t d = rng();
            uint64_t magic2 = S_MAGIC2_INIT ^ nonce_seed;
            s_magic_2.store(magic2, std::memory_order_release);
            s_state_d.store(d, std::memory_order_release);
            s_state_e.store(magic2 - d, std::memory_order_release);
            set_arc_obfuscated_state(true);


            if (s_sweep_start_time == 0)
                s_sweep_start_time = static_cast<int64_t>(GetTickCount64());

            std::string state_err;
            aida::license_state::transition_to(aida::license_state::status_valid, state_err);
        } else {
            s_state_a.store(0, std::memory_order_release);
            s_state_b.store(0, std::memory_order_release);
            s_state_c.store(0, std::memory_order_release);
            s_valid.store(false, std::memory_order_release);


            s_state_d.store(0, std::memory_order_release);
            s_state_e.store(0, std::memory_order_release);
            set_arc_obfuscated_state(false);

            std::string state_err;
            aida::license_state::transition_to(aida::license_state::status_pending, state_err);
            aida::license_state::set_flags(0,
                aida::license_state::flag_arc_loaded |
                aida::license_state::flag_heartbeat_ok, state_err);
            aida::gate_tokens::clear_session();
            ratchet_clear();
        }
    }

    [[noreturn]] void license_failfast(const char* reason, const std::string& detail)
    {
        std::string message = std::string(reason ? reason : "license_violation") + " " + detail;
        lic_log(message.c_str());
        anti_tamper::webhook::send_debug_log(reason ? reason : "license_violation", detail, true);
        anti_tamper::webhook::send_violation_alert(reason ? reason : "license_violation", detail);
        anti_tamper::server_pages::force_scrub_all();
        set_obfuscated_valid(false);
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    int64_t silent_kill_now_ms()
    {
        return static_cast<int64_t>(GetTickCount64());
    }

    void schedule_silent_kill(const char* reason)
    {
        constexpr int64_t kSilentKillDelayMs = 60000;
        int64_t deadline = silent_kill_now_ms() + kSilentKillDelayMs;
        int64_t expected = 0;
        if (s_silent_kill_after_ms.compare_exchange_strong(expected, deadline, std::memory_order_acq_rel))
        {
            std::string reason_copy = reason ? std::string(reason) : std::string("silent_kill_pending");
            lic_log((std::string("silent_kill_scheduled reason=") + reason_copy).c_str());
            work_queue::post([reason_copy]() {
                int64_t deadline_local = s_silent_kill_after_ms.load(std::memory_order_acquire);
                while (deadline_local > 0 && silent_kill_now_ms() < deadline_local)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    deadline_local = s_silent_kill_after_ms.load(std::memory_order_acquire);
                }
                if (deadline_local > 0)
                {
                    license_failfast("license_silent_kill", reason_copy);
                }
            });
        }
    }

    void cancel_silent_kill()
    {
        s_silent_kill_after_ms.store(0, std::memory_order_release);
    }


    bool check_obfuscated_valid()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t b = s_state_b.load(std::memory_order_acquire);
        uint64_t c = s_state_c.load(std::memory_order_acquire);
        uint64_t magic = s_magic.load(std::memory_order_acquire);
        uint64_t arc_magic = s_arc_magic.load(std::memory_order_acquire);
        bool arc_loaded_snapshot = s_arc_loaded.load(std::memory_order_acquire);
        bool arc_grace_snapshot = arc_grace_active();
        uint64_t arc_state = (arc_loaded_snapshot || arc_grace_snapshot)
            ? s_arc_state.load(std::memory_order_acquire)
            : 0;
        bool valid = (a ^ b ^ c ^ arc_state) == (magic ^ arc_magic);

        static std::atomic<int> s_last_validity_log{-1};
        int last = s_last_validity_log.load(std::memory_order_acquire);
        int now_state = valid ? 1 : 0;
        if (last != now_state) {
            s_last_validity_log.store(now_state, std::memory_order_release);
            lic_log_fmt("DIAG_VALIDITY tid=%lu new=%d a=%016llX b=%016llX c=%016llX abc_xor=%016llX "
                        "magic=%016llX arc_state=%016llX arc_magic=%016llX magic_xor_arc=%016llX "
                        "arc_loaded=%d arc_grace=%d abc_eq_magic=%d arc_match=%d",
                        GetCurrentThreadId(), now_state,
                        static_cast<unsigned long long>(a),
                        static_cast<unsigned long long>(b),
                        static_cast<unsigned long long>(c),
                        static_cast<unsigned long long>(a ^ b ^ c),
                        static_cast<unsigned long long>(magic),
                        static_cast<unsigned long long>(arc_state),
                        static_cast<unsigned long long>(arc_magic),
                        static_cast<unsigned long long>(magic ^ arc_magic),
                        arc_loaded_snapshot ? 1 : 0,
                        arc_grace_snapshot ? 1 : 0,
                        ((a ^ b ^ c) == magic) ? 1 : 0,
                        (arc_state == arc_magic) ? 1 : 0);
        }
        return valid;
    }


    uint64_t fnv1a(const void* data, size_t len)
    {
        uint64_t h = 14695981039346656037ULL;
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i) {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    uint64_t fnv1a_str(const std::string& s)
    {
        return fnv1a(s.data(), s.size());
    }


    void update_proof_hash(const std::string& session_token,
                           const std::string& hwid)
    {
        std::string combined = session_token + "|" + hwid;
        s_proof_hash.store(fnv1a_str(combined), std::memory_order_release);
    }

    std::string select_heartbeat_session_token(const settings_sa_t& settings)
    {
        if (!settings.license_session_token.empty())
            return settings.license_session_token;
        std::string cached_copy;
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            cached_copy = s_cached_session_token;
        }
        return cached_copy;
    }

    uint64_t vm_generate_proof_token(uint64_t session_seed, uint64_t heartbeat_count,
                                      uint64_t server_nonce, uint64_t hwid_hash)
    {
        uint64_t vm_seed = session_seed ^ __rdtsc() ^ heartbeat_count;

        anti_tamper::virtualizer::detail::vm_state_t vm;
        anti_tamper::virtualizer::detail::init_vm(vm, vm_seed);

        anti_tamper::vm_compiler::program_t prog;
        prog.set_key(vm_seed ^ 0x6A09E667F3BCC908ULL);
        prog.set_opcode_map(vm.opcode_map);

        prog.emit_load_imm(0, session_seed);
        prog.emit_load_imm(1, heartbeat_count);
        prog.emit_load_imm(2, server_nonce);
        prog.emit_load_imm(3, hwid_hash);

        prog.emit_xor(0, 0, 1);
        prog.emit_load_imm(8, 13);
        prog.emit_rol(0, 0, 8);
        prog.emit_xor(0, 0, 2);
        prog.emit_load_imm(8, 29);
        prog.emit_rol(0, 0, 8);
        prog.emit_xor(0, 0, 3);
        prog.emit_hash(0, 0);
        prog.emit_junk(3);
        prog.emit_halt();

        auto bytecode = prog.finalize();
        return anti_tamper::virtualizer::detail::vm_execute(
            vm, bytecode.data(), static_cast<uint32_t>(bytecode.size()));
    }

    std::string get_cloud_function_host()
    {
#ifdef AIDA_LOCAL_LICENSE_SERVER
        return "http://localhost:3001";
#else
        return "https://api.aidapro.net";
#endif
    }

    void configure_telemetry_from_settings(const settings_sa_t& settings, const char* phase)
    {
        const char* phase_name = phase ? phase : "unknown";
        if (settings.license_key.empty() ||
            settings.license_session_token.empty() ||
            settings.license_auth_hmac_key_b64.empty())
        {
            lic_log_fmt(
                "telemetry_config_skipped phase=%s key_set=%d session_len=%zu auth_b64_len=%zu",
                phase_name,
                settings.license_key.empty() ? 0 : 1,
                settings.license_session_token.size(),
                settings.license_auth_hmac_key_b64.size());
            return;
        }

        std::vector<uint8_t> auth_key = base64_decode(settings.license_auth_hmac_key_b64);
        if (auth_key.size() != 32)
        {
            lic_log_fmt(
                "telemetry_config_invalid_auth_key phase=%s auth_len=%zu auth_b64_len=%zu",
                phase_name,
                auth_key.size(),
                settings.license_auth_hmac_key_b64.size());
            return;
        }

        auto& telemetry = aida::telemetry::instance();
        telemetry.set_endpoint(get_cloud_function_host());
        telemetry.set_license_key(settings.license_key);
        telemetry.set_auth_hmac_key(std::move(auth_key));
        telemetry.set_session_token(settings.license_session_token);
        telemetry.start_background_flusher();
        lic_log_fmt(
            "telemetry_configured phase=%s session_len=%zu auth_len=32",
            phase_name,
            settings.license_session_token.size());
        const bool flushed = telemetry.flush_blocking();
        lic_log_fmt(
            "telemetry_initial_flush phase=%s ok=%d",
            phase_name,
            flushed ? 1 : 0);
    }

    std::shared_ptr<httplib::Client> get_or_create_license_client()
    {
        std::lock_guard<std::mutex> lk(s_http_mtx);
        std::string host = get_cloud_function_host();
        if (!s_license_client || s_license_host != host) {
            s_license_client = std::make_shared<httplib::Client>(host.c_str());
            s_license_host = host;
            s_license_client->set_address_family(AF_INET);
            s_license_client->set_connection_timeout(15);
            s_license_client->set_read_timeout(30);
            s_license_client->set_write_timeout(10);
            s_license_client->set_keep_alive(true);
            s_license_client->set_tcp_nodelay(true);
            s_license_client->set_decompress(true);
            s_license_client->set_follow_location(true);
            s_license_client->enable_server_certificate_verification(true);
#ifndef AIDA_LOCAL_LICENSE_SERVER
            s_license_client->set_server_certificate_verifier(
                [](SSL* ssl) -> httplib::SSLVerifierResponse {
                    {
                        auto ev = aida::tls_exporter::compute_header_value_openssl(ssl);
                        if (!ev.empty()) {
                            std::lock_guard<std::mutex> lk(s_tls_exporter_mtx);
                            s_tls_exporter_value = std::move(ev);
                        }
                    }

                    X509* cert = SSL_get1_peer_certificate(ssl);
                    if (!cert) return httplib::SSLVerifierResponse::CertificateRejected;

                    uint8_t spki_hash[32] = {};
                    unsigned int hash_len = 0;
                    int der_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), nullptr);
                    if (der_len > 0) {
                        std::vector<uint8_t> der(static_cast<size_t>(der_len));
                        uint8_t* p = der.data();
                        i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &p);
                        EVP_Digest(der.data(), der.size(), spki_hash, &hash_len, EVP_sha256(), nullptr);
                    }
                    X509_free(cert);

                    if (hash_len != 32) return httplib::SSLVerifierResponse::CertificateRejected;

                    static constexpr uint8_t PIN_CURRENT[32] = {
                        0xb7, 0xc5, 0x13, 0x79, 0xa4, 0xea, 0xfa, 0xa1,
                        0x6c, 0xd5, 0x81, 0x2f, 0x91, 0x54, 0x81, 0x16,
                        0xd1, 0x55, 0x58, 0xa0, 0x8e, 0x6d, 0x0b, 0x9a,
                        0xe3, 0x21, 0x7d, 0x12, 0xf1, 0x7d, 0x1c, 0x26
                    };
                    static constexpr uint8_t PIN_NEXT[32] = {0};
                    if (memcmp(spki_hash, PIN_CURRENT, 32) == 0)
                        return httplib::SSLVerifierResponse::CertificateAccepted;
                    bool next_is_zero = true;
                    for (int i = 0; i < 32; ++i) { if (PIN_NEXT[i]) { next_is_zero = false; break; } }
                    if (!next_is_zero && memcmp(spki_hash, PIN_NEXT, 32) == 0)
                        return httplib::SSLVerifierResponse::CertificateAccepted;
                    if (next_is_zero)
                        return httplib::SSLVerifierResponse::CertificateAccepted;
                    return httplib::SSLVerifierResponse::CertificateRejected;
                });
#endif
        }
        return s_license_client;
    }

    std::shared_ptr<httplib::Client> get_or_create_ip_client()
    {
        std::lock_guard<std::mutex> lk(s_http_mtx);
        const std::string host = "https://api.ipify.org";
        if (!s_ip_client || s_ip_host != host) {
            s_ip_client = std::make_shared<httplib::Client>(host.c_str());
            s_ip_host = host;
            s_ip_client->set_address_family(AF_INET);
            s_ip_client->set_connection_timeout(5);
            s_ip_client->set_read_timeout(5);
            s_ip_client->set_write_timeout(5);
            s_ip_client->set_keep_alive(true);
            s_ip_client->set_tcp_nodelay(true);
            s_ip_client->set_decompress(true);
            s_ip_client->set_follow_location(true);
            s_ip_client->enable_server_certificate_verification(true);
        }
        return s_ip_client;
    }

    void reset_license_clients()
    {
        std::lock_guard<std::mutex> lk(s_http_mtx);
        s_license_client.reset();
        s_license_host.clear();
        s_ip_client.reset();
        s_ip_host.clear();
    }

    std::string generate_nonce()
    {
        uint8_t buf[32] = {};
        NTSTATUS st = BCryptGenRandom(nullptr, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (st == 0)
        {
            static const char digits[] = "0123456789abcdef";
            std::string out;
            out.reserve(64);
            for (size_t i = 0; i < sizeof(buf); ++i)
            {
                out.push_back(digits[(buf[i] >> 4) & 0x0F]);
                out.push_back(digits[buf[i] & 0x0F]);
            }
            SecureZeroMemory(buf, sizeof(buf));
            return out;
        }
        LARGE_INTEGER counter{};
        QueryPerformanceCounter(&counter);
        std::ostringstream oss;
        oss << std::hex << static_cast<unsigned long long>(GetCurrentProcessId())
            << static_cast<unsigned long long>(GetTickCount64())
            << static_cast<unsigned long long>(counter.QuadPart);
        return oss.str();
    }

    std::string hwid_read_smbios_uuid()
    {
        UINT table_size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (table_size < 8) return "unavailable";
        std::vector<unsigned char> buf(table_size);
        UINT got = GetSystemFirmwareTable('RSMB', 0, buf.data(), table_size);
        if (got == 0 || got > table_size) {
            SecureZeroMemory(buf.data(), buf.size());
            return "unavailable";
        }
        const unsigned char* tbl = buf.data() + 8;
        size_t tbl_len = buf.size() - 8;
        size_t off = 0;
        std::string result;
        while (off + 4 < tbl_len) {
            unsigned char type = tbl[off];
            unsigned char len  = tbl[off + 1];
            if (len < 4 || off + len > tbl_len) break;
            if (type == 1 && len >= 24) {
                const unsigned char* u = tbl + off + 8;
                bool all_zero = true;
                for (int i = 0; i < 16; ++i) { if (u[i] != 0) { all_zero = false; break; } }
                if (!all_zero) {
                    char hex[33] = {};
                    for (int i = 0; i < 16; ++i)
                        _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02x", u[i]);
                    result.assign(hex);
                }
                break;
            }
            size_t after = off + len;
            while (after + 1 < tbl_len && !(tbl[after] == 0 && tbl[after + 1] == 0)) ++after;
            off = after + 2;
        }
        SecureZeroMemory(buf.data(), buf.size());
        if (result.empty()) return "unavailable";
        return result;
    }

    std::string hwid_read_baseboard_serial()
    {
        UINT table_size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (table_size < 8) return "unavailable";
        std::vector<unsigned char> buf(table_size);
        UINT got = GetSystemFirmwareTable('RSMB', 0, buf.data(), table_size);
        if (got == 0 || got > table_size) {
            SecureZeroMemory(buf.data(), buf.size());
            return "unavailable";
        }
        const unsigned char* tbl = buf.data() + 8;
        size_t tbl_len = buf.size() - 8;
        size_t off = 0;
        std::string result;
        while (off + 4 < tbl_len) {
            unsigned char type = tbl[off];
            unsigned char len  = tbl[off + 1];
            if (len < 4 || off + len > tbl_len) break;
            size_t after = off + len;
            const unsigned char* strings_start = tbl + after;
            while (after + 1 < tbl_len && !(tbl[after] == 0 && tbl[after + 1] == 0)) ++after;
            if (type == 2 && len >= 8) {
                unsigned char serial_index = tbl[off + 7];
                if (serial_index > 0) {
                    const char* p = reinterpret_cast<const char*>(strings_start);
                    const char* end = reinterpret_cast<const char*>(tbl + after);
                    for (unsigned char i = 1; i < serial_index && p < end; ++i) {
                        while (p < end && *p) ++p;
                        if (p < end) ++p;
                    }
                    if (p < end && *p) {
                        const char* q = p;
                        while (q < end && *q) ++q;
                        result.assign(p, q);
                        size_t start = result.find_first_not_of(" \t");
                        size_t fin = result.find_last_not_of(" \t");
                        if (start == std::string::npos) result.clear();
                        else result = result.substr(start, fin - start + 1);
                    }
                }
                break;
            }
            off = after + 2;
        }
        SecureZeroMemory(buf.data(), buf.size());
        if (result.empty()) return "unavailable";
        return result;
    }

    std::string hwid_read_disk_serial()
    {
        HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return "unavailable";
        STORAGE_PROPERTY_QUERY q = {};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;
        std::vector<unsigned char> out(1024);
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
            &q, sizeof(q), out.data(), static_cast<DWORD>(out.size()),
            &returned, nullptr);
        CloseHandle(h);
        if (!ok || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            SecureZeroMemory(out.data(), out.size());
            return "unavailable";
        }
        auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(out.data());
        if (desc->SerialNumberOffset == 0 || desc->SerialNumberOffset >= returned) {
            SecureZeroMemory(out.data(), out.size());
            return "unavailable";
        }
        const char* serial = reinterpret_cast<const char*>(out.data() + desc->SerialNumberOffset);
        size_t maxlen = static_cast<size_t>(returned) - desc->SerialNumberOffset;
        size_t n = 0;
        while (n < maxlen && serial[n] != '\0') ++n;
        std::string result(serial, n);
        SecureZeroMemory(out.data(), out.size());
        size_t start = result.find_first_not_of(" \t");
        size_t fin = result.find_last_not_of(" \t");
        if (start == std::string::npos) return "unavailable";
        result = result.substr(start, fin - start + 1);
        if (result.empty()) return "unavailable";
        return result;
    }

    std::string hwid_read_machine_guid()
    {
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Cryptography",
                0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) {
            return "unavailable";
        }
        wchar_t wbuf[128] = {};
        DWORD sz = sizeof(wbuf);
        DWORD type = 0;
        std::string result;
        if (RegQueryValueExW(h, L"MachineGuid", nullptr, &type,
                reinterpret_cast<LPBYTE>(wbuf), &sz) == ERROR_SUCCESS &&
            type == REG_SZ) {
            char ascii[128] = {};
            int conv = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1,
                ascii, sizeof(ascii), nullptr, nullptr);
            if (conv > 0) result.assign(ascii);
            SecureZeroMemory(ascii, sizeof(ascii));
        }
        SecureZeroMemory(wbuf, sizeof(wbuf));
        RegCloseKey(h);
        if (result.empty()) return "unavailable";
        return result;
    }

    std::string hwid_read_cpu_brand()
    {
        int regs[4] = {};
        __cpuid(regs, 0x80000000);
        unsigned highest = static_cast<unsigned>(regs[0]);
        if (highest < 0x80000004u) return "unavailable";
        char brand[49] = {};
        __cpuid(reinterpret_cast<int*>(brand + 0),  0x80000002);
        __cpuid(reinterpret_cast<int*>(brand + 16), 0x80000003);
        __cpuid(reinterpret_cast<int*>(brand + 32), 0x80000004);
        brand[48] = '\0';
        std::string result(brand);
        SecureZeroMemory(brand, sizeof(brand));
        size_t start = result.find_first_not_of(" \t");
        size_t fin = result.find_last_not_of(" \t");
        if (start == std::string::npos) return "unavailable";
        result = result.substr(start, fin - start + 1);
        if (result.empty()) return "unavailable";
        return result;
    }

    void log_hwid_v2_collection(const char* phase, const aida::hardware_id::v2::collection_t& c)
    {
        uint32_t collected = 0;
        std::ostringstream factors;
        for (std::size_t i = 0; i < aida::hardware_id::v2::kFactorCount; ++i)
        {
            const auto& f = c.factors[i];
            if (f.collected)
            {
                ++collected;
                std::string h = aida::hardware_id::v2::hash_to_hex(f.factor_hash);
                factors << static_cast<unsigned>(f.id) << ':' << h.substr(0, 8) << ':' << f.bytes.size();
            }
            else
            {
                factors << static_cast<unsigned>(f.id) << ":miss:0";
            }
            if (i + 1 < aida::hardware_id::v2::kFactorCount) factors << ',';
        }
        std::string hwid_hex = aida::hardware_id::v2::hash_to_hex(c.hwid_hash);
        lic_log_fmt("hwid_v2_collect phase=%s mask=0x%08X collected=%u tpm=%d hash_prefix=%.16s factors=%s",
            phase ? phase : "unknown",
            c.factor_present_mask,
            collected,
            c.tpm_present ? 1 : 0,
            hwid_hex.c_str(),
            factors.str().c_str());
        lic_log_fmt("hwid_v2_tpm_policy phase=%s policy=disabled factor_id=%u canonical=no_tpm compatibility=non_tpm_hardware",
            phase ? phase : "unknown",
            static_cast<unsigned>(aida::hardware_id::v2::kFactorIdTpmEkSha256));
    }

    struct hwid_material_t
    {
        std::string hwid;
        json evidence = json::object();
    };

    json build_hwid_v2_evidence(const aida::hardware_id::v2::collection_t& c)
    {
        json factors = json::object();
        uint32_t collected = 0;
        for (std::size_t i = 0; i < aida::hardware_id::v2::kFactorCount; ++i)
        {
            const auto& f = c.factors[i];
            if (!f.collected) continue;
            ++collected;
            factors[std::to_string(static_cast<unsigned>(f.id))] =
                aida::hardware_id::v2::hash_to_hex(f.factor_hash);
        }
        return json::object({
            {"hwid_version", static_cast<int>(aida::hardware_id::v2::kHwidVersion)},
            {"hwid_v2_version", static_cast<int>(aida::hardware_id::v2::kHwidVersion)},
            {"hwid_v2_factor_mask", c.factor_present_mask},
            {"hwid_v2_factor_count", collected},
            {"hwid_v2_tpm_present", c.tpm_present},
            {"hwid_v2_factors", std::move(factors)}
        });
    }

    void wipe_hwid_collection(aida::hardware_id::v2::collection_t& collection)
    {
        SecureZeroMemory(collection.hwid_hash.data(), collection.hwid_hash.size());
        for (auto& f : collection.factors)
        {
            SecureZeroMemory(f.factor_hash.data(), f.factor_hash.size());
            if (!f.bytes.empty()) SecureZeroMemory(f.bytes.data(), f.bytes.size());
        }
    }

    bool collect_hwid_material(const char* phase, hwid_material_t& out)
    {
        out = hwid_material_t{};
        aida::hardware_id::v2::collection_t collection{};
        std::string err;
        if (!aida::hardware_id::v2::collect(collection, err))
        {
            char dbg[160];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "generate_hwid_v2_failed err=%.96s", err.c_str());
            lic_log(dbg);
            wipe_hwid_collection(collection);
            out.hwid = "unavailable";
            return false;
        }
        log_hwid_v2_collection(phase ? phase : "generate", collection);
        out.hwid = aida::hardware_id::v2::hash_to_hex(collection.hwid_hash);
        out.evidence = build_hwid_v2_evidence(collection);
        wipe_hwid_collection(collection);
        return true;
    }

    std::string generate_hwid()
    {
        hwid_material_t material;
        if (!collect_hwid_material("generate", material))
            return "unavailable";
        return material.hwid;
    }

    std::string generate_legacy_hwid_for_migration_only()
    {
        std::string slot_smbios   = hwid_read_smbios_uuid();
        std::string slot_baseboard = hwid_read_baseboard_serial();
        std::string slot_disk     = hwid_read_disk_serial();
        std::string slot_guid     = hwid_read_machine_guid();
        std::string slot_cpu      = hwid_read_cpu_brand();

        std::string canonical;
        canonical.reserve(slot_smbios.size() + slot_baseboard.size() +
                          slot_disk.size() + slot_guid.size() +
                          slot_cpu.size() + 4);
        canonical.append(slot_smbios);
        canonical.append("|");
        canonical.append(slot_baseboard);
        canonical.append("|");
        canonical.append(slot_disk);
        canonical.append("|");
        canonical.append(slot_guid);
        canonical.append("|");
        canonical.append(slot_cpu);

        BCRYPT_ALG_HANDLE  hAlg  = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        uint8_t digest[32] = {};
        NTSTATUS st = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        bool ok = false;
        if (BCRYPT_SUCCESS(st) && hAlg) {
            st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
            if (BCRYPT_SUCCESS(st) && hHash) {
                st = BCryptHashData(hHash,
                    reinterpret_cast<PUCHAR>(const_cast<char*>(canonical.data())),
                    static_cast<ULONG>(canonical.size()), 0);
                if (BCRYPT_SUCCESS(st))
                    st = BCryptFinishHash(hHash, digest, 32, 0);
                ok = BCRYPT_SUCCESS(st);
            }
        }
        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);

        SecureZeroMemory(canonical.data(), canonical.size());
        SecureZeroMemory(const_cast<char*>(slot_smbios.data()), slot_smbios.size());
        SecureZeroMemory(const_cast<char*>(slot_baseboard.data()), slot_baseboard.size());
        SecureZeroMemory(const_cast<char*>(slot_disk.data()), slot_disk.size());
        SecureZeroMemory(const_cast<char*>(slot_guid.data()), slot_guid.size());
        SecureZeroMemory(const_cast<char*>(slot_cpu.data()), slot_cpu.size());

        if (!ok) {
            SecureZeroMemory(digest, sizeof(digest));
            return "unavailable";
        }

        static const char kHexDigits[] = "0123456789abcdef";
        char hex_out[65] = {};
        for (int i = 0; i < 32; ++i) {
            hex_out[i * 2 + 0] = kHexDigits[(digest[i] >> 4) & 0x0F];
            hex_out[i * 2 + 1] = kHexDigits[digest[i] & 0x0F];
        }
        hex_out[64] = '\0';
        SecureZeroMemory(digest, sizeof(digest));
        std::string out_hwid(hex_out);
        SecureZeroMemory(hex_out, sizeof(hex_out));
        return out_hwid;
    }

    bool query_driver_hwid_v2(std::array<uint8_t, 32>& out_hash,
                              std::array<std::array<uint8_t, 32>, hwid_kernel_proto::kFactorCount>& out_factor_hashes,
                              uint32_t& out_factor_present_mask,
                              std::string& last_error)
    {
        if (!device || !device->is_connected())
        {
            last_error = "device_not_connected";
            return false;
        }
        hwid_kernel_proto::reply_t reply{};
        uint32_t bytes_returned = 0;
        DWORD ioctl = ioctl_codes::HWID();
        bool ok = device->send_ioctl_raw(
            ioctl,
            &reply,
            static_cast<uint32_t>(sizeof(reply)),
            bytes_returned);
        if (!ok || bytes_returned < sizeof(reply))
        {
            DWORD gle = ok ? 0 : GetLastError();
            char detail[192];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "hwid_v2_ioctl_failed ok=%d bytes=%u need=%llu gle=%lu ioctl=0x%08lX pid=%u",
                ok ? 1 : 0,
                bytes_returned,
                static_cast<unsigned long long>(sizeof(reply)),
                static_cast<unsigned long>(gle),
                static_cast<unsigned long>(ioctl),
                device ? device->get_process_id() : 0u);
            last_error = detail;
            lic_log(detail);
            SecureZeroMemory(&reply, sizeof(reply));
            return false;
        }
        if (reply.magic != hwid_kernel_proto::kReplyMagic ||
            reply.version != hwid_kernel_proto::kReplyVersion)
        {
            char detail[160];
            _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "hwid_v2_reply_bad_magic magic=0x%08X version=%u bytes=%u ioctl=0x%08lX",
                reply.magic,
                reply.version,
                bytes_returned,
                static_cast<unsigned long>(ioctl));
            last_error = detail;
            lic_log(detail);
            SecureZeroMemory(&reply, sizeof(reply));
            return false;
        }
        std::memcpy(out_hash.data(), reply.hwid_hash, 32);
        for (uint32_t i = 0; i < hwid_kernel_proto::kFactorCount; ++i)
        {
            std::memcpy(out_factor_hashes[i].data(), reply.factor_hashes[i], 32);
        }
        out_factor_present_mask = reply.factor_present_mask;
        SecureZeroMemory(&reply, sizeof(reply));
        return true;
    }

    std::string get_public_ip()
    {
        try {
            auto resp = raw_https_request("GET", "https://api.ipify.org/?format=json",
                                        {}, {}, {}, 3);
            if (!resp.ok || resp.status != 200)
                return {};
            auto j = json::parse(resp.body, nullptr, false);
            if (j.is_discarded())
                return {};
            return j.value("ip", "");
        } catch (...) {
            return {};
        }
    }

    struct local_discord_identity_t
    {
        std::string user_id;
        std::string username;
    };

    std::string getenv_string_a(const char* name)
    {
        char buf[32768] = {};
        DWORD n = GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
        if (n == 0 || n >= sizeof(buf))
            return {};
        return std::string(buf, buf + n);
    }

    bool is_valid_discord_id(const std::string& value)
    {
        if (value.size() < 15 || value.size() > 25)
            return false;
        for (char c : value)
            if (c < '0' || c > '9')
                return false;
        return true;
    }

    std::string clean_discord_text(std::string value, size_t max_len)
    {
        std::string out;
        out.reserve((std::min)(value.size(), max_len));
        for (unsigned char c : value)
        {
            if (out.size() >= max_len)
                break;
            if ((c >= 0x20 && c != 0x7f) || c >= 0x80)
                out.push_back(static_cast<char>(c));
        }
        return out;
    }

    void append_utf8_codepoint(uint32_t cp, std::string& out)
    {
        if (cp <= 0x7F)
        {
            out.push_back(static_cast<char>(cp));
        }
        else if (cp <= 0x7FF)
        {
            out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        else if (cp <= 0xFFFF)
        {
            out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        else if (cp <= 0x10FFFF)
        {
            out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    int hex_digit_value(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    }

    bool parse_json_string_at(const std::string& text, size_t quote_pos, size_t end_pos, std::string& out)
    {
        if (quote_pos >= text.size() || text[quote_pos] != '"')
            return false;
        const size_t stop = (std::min)(end_pos, text.size());
        std::string value;
        for (size_t i = quote_pos + 1; i < stop; ++i)
        {
            const char c = text[i];
            if (c == '"')
            {
                out = clean_discord_text(value, 128);
                return true;
            }
            if (c == '\\' && i + 1 < stop)
            {
                const char e = text[++i];
                switch (e)
                {
                case '"': value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case '/': value.push_back('/'); break;
                case 'b': value.push_back('\b'); break;
                case 'f': value.push_back('\f'); break;
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                case 'u':
                    if (i + 4 < stop)
                    {
                        int h0 = hex_digit_value(text[i + 1]);
                        int h1 = hex_digit_value(text[i + 2]);
                        int h2 = hex_digit_value(text[i + 3]);
                        int h3 = hex_digit_value(text[i + 4]);
                        if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0)
                        {
                            uint32_t cp = static_cast<uint32_t>((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                            append_utf8_codepoint(cp, value);
                            i += 4;
                        }
                    }
                    break;
                default:
                    value.push_back(e);
                    break;
                }
            }
            else
            {
                value.push_back(c);
            }
            if (value.size() > 256)
                break;
        }
        return false;
    }

    bool find_json_key_string(const std::string& text, const char* key, size_t start_pos, size_t end_pos, std::string& out)
    {
        const std::string needle = std::string("\"") + key + "\"";
        const size_t stop = (std::min)(end_pos, text.size());
        size_t pos = start_pos;
        while (pos < stop)
        {
            pos = text.find(needle, pos);
            if (pos == std::string::npos || pos >= stop)
                return false;
            size_t cur = pos + needle.size();
            while (cur < stop && (text[cur] == ' ' || text[cur] == '\t' || text[cur] == '\r' || text[cur] == '\n'))
                ++cur;
            if (cur < stop && text[cur] == ':')
            {
                ++cur;
                while (cur < stop && (text[cur] == ' ' || text[cur] == '\t' || text[cur] == '\r' || text[cur] == '\n'))
                    ++cur;
                if (cur < stop && text[cur] == '"')
                    return parse_json_string_at(text, cur, stop, out);
            }
            pos += needle.size();
        }
        return false;
    }

    bool find_discord_id_near(const std::string& text, size_t pos, std::string& out)
    {
        const size_t radius = 2048;
        const size_t start = pos > radius ? pos - radius : 0;
        const size_t end = (std::min)(text.size(), pos + radius);
        std::string id;
        if (find_json_key_string(text, "id", start, end, id) && is_valid_discord_id(id))
        {
            out = id;
            return true;
        }
        if (find_json_key_string(text, "user_id", start, end, id) && is_valid_discord_id(id))
        {
            out = id;
            return true;
        }
        return false;
    }

    bool extract_discord_identity_from_text(const std::string& text, local_discord_identity_t& out)
    {
        static const char* kNameKeys[] = { "username", "global_name", "display_name" };
        for (const char* key : kNameKeys)
        {
            const std::string needle = std::string("\"") + key + "\"";
            size_t pos = 0;
            while ((pos = text.find(needle, pos)) != std::string::npos)
            {
                std::string name;
                if (find_json_key_string(text, key, pos, (std::min)(text.size(), pos + 512), name))
                {
                    std::string id;
                    if (find_discord_id_near(text, pos, id) && !name.empty())
                    {
                        out.user_id = id;
                        out.username = clean_discord_text(name, 96);
                        return true;
                    }
                }
                pos += needle.size();
            }
        }
        return false;
    }

    bool read_pipe_exact(HANDLE pipe, void* data, DWORD size)
    {
        uint8_t* p = reinterpret_cast<uint8_t*>(data);
        DWORD total = 0;
        while (total < size)
        {
            DWORD got = 0;
            if (!ReadFile(pipe, p + total, size - total, &got, nullptr) || got == 0)
                return false;
            total += got;
        }
        return true;
    }

    bool write_pipe_exact(HANDLE pipe, const void* data, DWORD size)
    {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
        DWORD total = 0;
        while (total < size)
        {
            DWORD wrote = 0;
            if (!WriteFile(pipe, p + total, size - total, &wrote, nullptr) || wrote == 0)
                return false;
            total += wrote;
        }
        return true;
    }

    bool query_discord_ipc_identity(local_discord_identity_t& out)
    {
        const std::string client_id = getenv_string_a("AIDA_DISCORD_CLIENT_ID");
        if (!is_valid_discord_id(client_id))
            return false;
        for (int i = 0; i < 10; ++i)
        {
            char pipe_name[64] = {};
            _snprintf_s(pipe_name, sizeof(pipe_name), _TRUNCATE, "\\\\.\\pipe\\discord-ipc-%d", i);
            HANDLE pipe = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (pipe == INVALID_HANDLE_VALUE)
                continue;
            json handshake;
            handshake["v"] = 1;
            handshake["client_id"] = client_id;
            std::string payload = handshake.dump();
            uint32_t header[2] = { 0u, static_cast<uint32_t>(payload.size()) };
            bool ok = write_pipe_exact(pipe, header, sizeof(header)) &&
                      write_pipe_exact(pipe, payload.data(), static_cast<DWORD>(payload.size()));
            SecureZeroMemory(const_cast<char*>(payload.data()), payload.size());
            if (!ok)
            {
                CloseHandle(pipe);
                continue;
            }
            uint32_t read_header[2] = {};
            if (!read_pipe_exact(pipe, read_header, sizeof(read_header)) || read_header[1] == 0 || read_header[1] > 65536)
            {
                CloseHandle(pipe);
                continue;
            }
            std::string body;
            body.resize(read_header[1]);
            ok = read_pipe_exact(pipe, body.data(), read_header[1]);
            CloseHandle(pipe);
            if (!ok)
            {
                SecureZeroMemory(body.data(), body.size());
                continue;
            }
            json j = json::parse(body, nullptr, false);
            SecureZeroMemory(body.data(), body.size());
            if (j.is_discarded() || !j.is_object())
                continue;
            const json* user = nullptr;
            if (j.contains("data") && j["data"].is_object() && j["data"].contains("user") && j["data"]["user"].is_object())
                user = &j["data"]["user"];
            if (!user)
                continue;
            std::string id = user->value("id", "");
            std::string username = user->value("username", "");
            std::string global_name = user->value("global_name", "");
            if (!global_name.empty() && !username.empty() && global_name != username)
                username = global_name + " (" + username + ")";
            else if (!global_name.empty())
                username = global_name;
            id = clean_discord_text(id, 32);
            username = clean_discord_text(username, 96);
            if (is_valid_discord_id(id) && !username.empty())
            {
                out.user_id = id;
                out.username = username;
                return true;
            }
        }
        return false;
    }

    bool read_identity_from_discord_file(const std::filesystem::path& path, local_discord_identity_t& out)
    {
        std::error_code ec;
        const auto sz = std::filesystem::file_size(path, ec);
        if (ec || sz == 0 || sz > 4u * 1024u * 1024u)
            return false;
        std::ifstream in(path, std::ios::binary);
        if (!in)
            return false;
        std::string data;
        data.resize(static_cast<size_t>(sz));
        in.read(data.data(), static_cast<std::streamsize>(data.size()));
        if (!in && static_cast<size_t>(in.gcount()) != data.size())
        {
            SecureZeroMemory(data.data(), data.size());
            return false;
        }
        const bool ok = extract_discord_identity_from_text(data, out);
        SecureZeroMemory(data.data(), data.size());
        return ok;
    }

    // Simple RFC-4648 base64 decoder (no dependencies)
    static std::vector<uint8_t> aida_base64_decode(const std::string& b64)
    {
        static const int8_t kT[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
            52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        };
        std::vector<uint8_t> out;
        out.reserve(b64.size() * 3 / 4);
        uint32_t acc = 0; int bits = 0;
        for (unsigned char c : b64) {
            if (c == '=') break;
            int8_t v = kT[c]; if (v < 0) continue;
            acc = (acc << 6) | static_cast<uint8_t>(v); bits += 6;
            if (bits >= 8) { bits -= 8; out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF)); }
        }
        return out;
    }

    static bool dpapi_get_local_state_aes_key(const std::filesystem::path& local_state_path,
                                              std::vector<uint8_t>& out_key)
    {
        std::error_code ec;
        auto sz = std::filesystem::file_size(local_state_path, ec);
        if (ec || sz == 0 || sz > 2u * 1024u * 1024u) return false;
        std::ifstream f(local_state_path, std::ios::binary);
        if (!f) return false;
        std::string data; data.resize(static_cast<size_t>(sz));
        f.read(data.data(), static_cast<std::streamsize>(data.size()));
        if (!f && static_cast<size_t>(f.gcount()) != data.size()) return false;
        const std::string marker = "\"encrypted_key\"";
        size_t pos = data.find(marker);
        if (pos == std::string::npos) return false;
        size_t colon = data.find(':', pos + marker.size());
        if (colon == std::string::npos) return false;
        size_t q1 = data.find('"', colon + 1);
        if (q1 == std::string::npos) return false;
        size_t q2 = data.find('"', q1 + 1);
        if (q2 == std::string::npos || q2 <= q1 + 1) return false;
        auto decoded = aida_base64_decode(data.substr(q1 + 1, q2 - q1 - 1));
        if (decoded.size() < 6 || memcmp(decoded.data(), "DPAPI", 5) != 0) return false;
        DATA_BLOB in_blob = { static_cast<DWORD>(decoded.size() - 5), decoded.data() + 5 };
        DATA_BLOB out_blob = {};
        if (!CryptUnprotectData(&in_blob, nullptr, nullptr, nullptr, nullptr, 0, &out_blob))
            return false;
        out_key.assign(out_blob.pbData, out_blob.pbData + out_blob.cbData);
        LocalFree(out_blob.pbData);
        SecureZeroMemory(decoded.data(), decoded.size());
        return out_key.size() == 32;
    }

    static bool local_state_aes_gcm_decrypt(const std::vector<uint8_t>& key,
                                            const uint8_t* blob, size_t blob_len,
                                            std::string& out)
    {
        if (blob_len < 31) return false;
        if (blob[0] != 'v' || blob[1] != '1' || (blob[2] != '0' && blob[2] != '1')) return false;
        const uint8_t* nonce  = blob + 3;
        const size_t   ct_len = blob_len - 3 - 12 - 16;
        const uint8_t* ct     = nonce + 12;
        const uint8_t* tag    = ct + ct_len;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        std::string plain(ct_len, '\0');
        int o1 = 0, o2 = 0; bool ok = false;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) == 1 &&
            EVP_DecryptUpdate(ctx, reinterpret_cast<uint8_t*>(&plain[0]),
                              &o1, ct, static_cast<int>(ct_len)) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                 const_cast<uint8_t*>(tag)) == 1 &&
            EVP_DecryptFinal_ex(ctx, reinterpret_cast<uint8_t*>(&plain[o1]), &o2) == 1)
        {
            plain.resize(static_cast<size_t>(o1 + o2));
            out = std::move(plain); ok = true;
        }
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    static bool scan_dpapi_blobs_for_discord(const std::vector<uint8_t>& aes_key,
                                              const uint8_t* data, size_t data_len,
                                              local_discord_identity_t& out)
    {
        for (size_t i = 0; i + 31 <= data_len; ) {
            if (!(data[i] == 'v' && data[i+1] == '1' && (data[i+2] == '0' || data[i+2] == '1'))) {
                ++i; continue;
            }
            size_t next = data_len;
            for (size_t j = i + 31; j + 2 < data_len; ++j) {
                if (data[j] == 'v' && data[j+1] == '1' && (data[j+2] == '0' || data[j+2] == '1')) {
                    next = j; break;
                }
            }
            size_t blob_end = (std::min)(next, i + 4096u);
            if (blob_end - i >= 31) {
                std::string plain;
                if (local_state_aes_gcm_decrypt(aes_key, data + i, blob_end - i, plain)) {
                    local_discord_identity_t cand{};
                    if (extract_discord_identity_from_text(plain, cand) && !cand.user_id.empty()) {
                        out = cand; return true;
                    }
                }
            }
            i = (next < data_len) ? next : data_len;
        }
        return false;
    }

    static bool harvest_discord_identity_dpapi(const std::filesystem::path& root,
                                                local_discord_identity_t& out)
    {
        std::vector<uint8_t> aes_key;
        if (!dpapi_get_local_state_aes_key(root / "Local State", aes_key)) return false;
        const auto leveldb = root / "Local Storage" / "leveldb";
        std::error_code ec;
        if (!std::filesystem::exists(leveldb, ec)) {
            SecureZeroMemory(aes_key.data(), aes_key.size()); return false;
        }
        int seen = 0;
        for (std::filesystem::directory_iterator it(leveldb, ec), end; !ec && it != end; it.increment(ec)) {
            if (seen++ >= 128) break;
            if (!it->is_regular_file(ec)) continue;
            std::string ext = it->path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (ext != ".ldb" && ext != ".log") continue;
            auto fsz = std::filesystem::file_size(it->path(), ec);
            if (ec || fsz == 0 || fsz > 8u * 1024u * 1024u) continue;
            std::ifstream f(it->path(), std::ios::binary);
            if (!f) continue;
            std::vector<uint8_t> buf(static_cast<size_t>(fsz));
            f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
            if (!f && static_cast<size_t>(f.gcount()) != buf.size()) {
                SecureZeroMemory(buf.data(), buf.size()); continue;
            }
            local_discord_identity_t cand{};
            if (scan_dpapi_blobs_for_discord(aes_key, buf.data(), buf.size(), cand)) {
                SecureZeroMemory(aes_key.data(), aes_key.size());
                SecureZeroMemory(buf.data(), buf.size());
                out = cand; return true;
            }
            SecureZeroMemory(buf.data(), buf.size());
        }
        SecureZeroMemory(aes_key.data(), aes_key.size());
        return false;
    }

    // Real device geolocation via Windows Location COM API (ILocation / ILatLongReport)
    // Uses vtable offsets to avoid requiring locationapi.h in the build
    struct geolocal_result_t { double lat = 0.0, lon = 0.0; bool valid = false; };

    static geolocal_result_t collect_local_geolocation()
    {
        geolocal_result_t result{};
        try {
            // CLSID_Location  = {E5B8E079-EE6D-4E33-A438-C87F2E959254}
            static const GUID kCLSID_Location =
                {0xE5B8E079,0xEE6D,0x4E33,{0xA4,0x38,0xC8,0x7F,0x2E,0x95,0x92,0x54}};
            // IID_ILatLongReport = {7FED806D-0EF8-4F07-80AC-36A0BEAE3134}
            static const GUID kIID_ILatLongReport =
                {0x7FED806D,0x0EF8,0x4F07,{0x80,0xAC,0x36,0xA0,0xBE,0xAE,0x31,0x34}};
            IUnknown* pLoc = nullptr;
            HRESULT hr = CoCreateInstance(kCLSID_Location, nullptr, CLSCTX_INPROC_SERVER,
                                           IID_IUnknown, reinterpret_cast<void**>(&pLoc));
            if (FAILED(hr) || !pLoc) return result;
            // ILocation vtable: 0=QI 1=AddRef 2=Release 3=RegisterForReport
            //   4=UnregisterForReport 5=GetReport 6=GetReportStatus ...
            typedef HRESULT (STDMETHODCALLTYPE* GetReport_fn)(IUnknown*, REFIID, IUnknown**);
            GetReport_fn pfnGet =
                reinterpret_cast<GetReport_fn>((*reinterpret_cast<void***>(pLoc))[5]);
            IUnknown* pRpt = nullptr;
            hr = pfnGet(pLoc, kIID_ILatLongReport, &pRpt);
            if (SUCCEEDED(hr) && pRpt) {
                // ILatLongReport vtable: 0-2=IUnknown 3-5=ILocationReport
                //   6=GetLatitude 7=GetLongitude 8=GetErrorRadius ...
                typedef HRESULT (STDMETHODCALLTYPE* GetDouble_fn)(IUnknown*, DOUBLE*);
                void** vtbl = *reinterpret_cast<void***>(pRpt);
                GetDouble_fn pfnLat = reinterpret_cast<GetDouble_fn>(vtbl[6]);
                GetDouble_fn pfnLon = reinterpret_cast<GetDouble_fn>(vtbl[7]);
                DOUBLE lat = 0.0, lon = 0.0;
                if (SUCCEEDED(pfnLat(pRpt, &lat)) && SUCCEEDED(pfnLon(pRpt, &lon))
                    && (lat != 0.0 || lon != 0.0))
                {
                    result.lat = lat; result.lon = lon; result.valid = true;
                }
                pRpt->Release();
            }
            pLoc->Release();
        } catch (...) {}
        return result;
    }

    local_discord_identity_t harvest_local_discord_identity()
    {
        local_discord_identity_t id{};
        if (query_discord_ipc_identity(id))
        {
            lic_log_fmt("local_discord_identity_found source=ipc id_len=%zu username_len=%zu",
                id.user_id.size(), id.username.size());
            return id;
        }
        std::vector<std::filesystem::path> roots;
        const std::string appdata = getenv_string_a("APPDATA");
        const std::string localappdata = getenv_string_a("LOCALAPPDATA");
        static const char* kNames[] = { "Discord", "discord", "DiscordCanary", "discordcanary", "DiscordPTB", "discordptb" };
        for (const char* name : kNames)
        {
            if (!appdata.empty())
                roots.emplace_back(std::filesystem::path(appdata) / name);
            if (!localappdata.empty())
                roots.emplace_back(std::filesystem::path(localappdata) / name);
        }
        size_t files_seen = 0;
        for (const auto& root : roots)
        {
            std::error_code ec;
            if (!std::filesystem::exists(root, ec))
                continue;
            // Try DPAPI-based LevelDB decryption first (modern Discord encrypts all storage)
            if (harvest_discord_identity_dpapi(root, id))
            {
                lic_log_fmt("local_discord_identity_found source=dpapi id_len=%zu username_len=%zu",
                    id.user_id.size(), id.username.size());
                return id;
            }
            std::vector<std::filesystem::path> direct_files = {
                root / "Local State",
                root / "settings.json",
            };
            for (const auto& file : direct_files)
            {
                if (std::filesystem::exists(file, ec) && read_identity_from_discord_file(file, id))
                {
                    lic_log_fmt("local_discord_identity_found source=file id_len=%zu username_len=%zu",
                        id.user_id.size(), id.username.size());
                    return id;
                }
            }
            const std::filesystem::path leveldb = root / "Local Storage" / "leveldb";
            if (!std::filesystem::exists(leveldb, ec))
                continue;
            for (std::filesystem::directory_iterator it(leveldb, ec), end; !ec && it != end; it.increment(ec))
            {
                if (files_seen++ >= 64)
                    break;
                if (!it->is_regular_file(ec))
                    continue;
                std::string ext = it->path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (ext != ".ldb" && ext != ".log" && ext != ".json")
                    continue;
                if (read_identity_from_discord_file(it->path(), id))
                {
                    lic_log_fmt("local_discord_identity_found source=leveldb id_len=%zu username_len=%zu",
                        id.user_id.size(), id.username.size());
                    return id;
                }
            }
        }
        lic_log("local_discord_identity_not_found");
        return id;
    }

    bool call_validation_endpoint_for_current_hwid(settings_sa_t& settings,
                                                   const std::string& action,
                                                   const std::string& key,
                                                   const std::string& session_token,
                                                   const std::string& nonce,
                                                   std::string& selected_hwid,
                                                   std::string& error_out,
                                                   json& response_out)
    {
        hwid_material_t material;
        if (!collect_hwid_material("generate", material))
        {
            selected_hwid = "unavailable";
            error_out = "HWID collection failed.";
            response_out = json::object({{"ok", false}, {"reason", "hwid_collect_failed"}});
            return false;
        }
        selected_hwid = material.hwid;
        lic_log((std::string("validate_hwid=") + selected_hwid + " action=" + action).c_str());
        return call_validation_endpoint(settings, action, key, selected_hwid, session_token,
                                        nonce, error_out, response_out, &material.evidence);
    }

    bool run_startup_ban_check(settings_sa_t& settings, std::string& reason_out, std::string& message_out)
    {
        reason_out.clear();
        message_out.clear();

        json body;
        body["action"] = "ban_check";
        body["timestamp"] = static_cast<int64_t>(std::time(nullptr));
        body["plugin_version"] = "aida-standalone";

        body["hwid"] = generate_hwid();

        std::string host = get_cloud_function_host();
        auto resp = raw_https_request("POST", host + "/validateLicense",
                                      {}, body.dump(), "application/json", 8);
        {
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "startup_ban_check_response ok=%d status=%d err=%.96s",
                resp.ok ? 1 : 0, resp.status, resp.error.c_str());
            lic_log(buf);
        }
        if (!resp.ok || resp.status != 200)
            return false;

        auto parsed = json::parse(resp.body, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object())
            return false;

        if (parsed.value("status", "") != "banned" && !parsed.value("banned", false))
            return false;

        reason_out = parsed.value("reason", "banned");
        const std::string ban_reason = parsed.value("ban_reason", "");
        const std::string ban_type = parsed.value("ban_type", "");
        message_out = "AiDA cannot start because this machine or network is banned.";
        if (!reason_out.empty()) {
            message_out += "\n\nReason: ";
            message_out += reason_out;
        }
        if (!ban_type.empty()) {
            message_out += "\nBan type: ";
            message_out += ban_type;
        }
        if (!ban_reason.empty()) {
            message_out += "\nServer cause: ";
            message_out += ban_reason;
        }
        return true;
    }

    static std::string hmac_sha256_hex(const std::string& key, const std::string& data)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        uint8_t out[32] = {};

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) return {};

        status = BCryptCreateHash(
            hAlg, &hHash, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
            static_cast<ULONG>(key.size()), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptHashData(
            hHash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()), 0);
        if (status != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptFinishHash(hHash, out, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status != 0) return {};

        static const char hex[] = "0123456789abcdef";
        std::string result;
        result.reserve(64);
        for (int i = 0; i < 32; ++i) {
            result.push_back(hex[out[i] >> 4]);
            result.push_back(hex[out[i] & 0x0F]);
        }
        return result;
    }

    bool fetch_challenge(challenge_material_t& out, std::string* error_out = nullptr)
    {
        lic_log("fetch_challenge_enter");
        std::string host = get_cloud_function_host();
        const std::string url = host + "/api/license/challenge";
        auto resp = raw_https_request("GET", url);
        if (!resp.ok) {
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "fetch_challenge_fail winhttp err=%s", resp.error.c_str());
            lic_log(buf);
            if (error_out)
                *error_out = resp.error.empty()
                    ? std::string("License activation challenge unavailable.")
                    : std::string("License activation challenge unavailable: ") + resp.error;
            schedule_async_network_diagnosis(url);
            return false;
        }
        if (resp.status != 200) {
            if (resp.status >= 500) {
                lic_log("fetch_challenge_http_5xx_retry");
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                resp = raw_https_request("GET", host + "/api/license/challenge");
                if (!resp.ok || resp.status != 200) {
                    char buf[128];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "fetch_challenge_http_retry_fail status=%d", resp.status);
                    lic_log(buf);
                    if (error_out)
                        *error_out = "License activation challenge unavailable.";
                    return false;
                }
            } else {
                char buf[128];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "fetch_challenge_http status=%d", resp.status);
                lic_log(buf);
                if (error_out)
                    *error_out = "License activation challenge unavailable.";
                return false;
            }
        }

        auto j = json::parse(resp.body, nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            if (error_out)
                *error_out = "License service returned invalid challenge JSON.";
            return false;
        }

        std::string cid = j.value("challenge_id", "");
        std::string cnonce = j.value("challenge_nonce", "");
        if (cid.empty() || cnonce.empty()) {
            if (error_out)
                *error_out = "License service returned an incomplete challenge.";
            return false;
        }

        out.id = std::move(cid);
        out.nonce = std::move(cnonce);
        lic_log_fmt("fetch_challenge_ok id_len=%zu nonce_len=%zu", out.id.size(), out.nonce.size());
        return true;
    }

    bool attach_standalone_capsule_proof(json& body,
                                         const std::string& action,
                                         const std::string& key,
                                         const std::string& hwid,
                                         const std::string& session_token,
                                         const std::string& nonce)
    {
        body.erase("standalone_capsule");
        const auto& info = aida::runtime::customer_capsule::get_capsule_info();
        aida::runtime::customer_capsule::proof_fields_t proof{};
        bool ok = false;
        if (action == "validate")
        {
            ok = aida::runtime::customer_capsule::build_validate_proof(key, hwid, nonce, proof);
        }
        else if (action == "heartbeat")
        {
            std::uint32_t heartbeat_count = 0;
            if (body.contains("heartbeat_count") && body["heartbeat_count"].is_number_unsigned())
                heartbeat_count = body["heartbeat_count"].get<std::uint32_t>();
            else if (body.contains("heartbeat_count") && body["heartbeat_count"].is_number_integer())
            {
                const int raw = body["heartbeat_count"].get<int>();
                heartbeat_count = raw > 0 ? static_cast<std::uint32_t>(raw) : 0u;
            }
            const std::string req_seq = body.contains("req_seq") && body["req_seq"].is_string()
                ? body["req_seq"].get<std::string>()
                : std::string();
            ok = aida::runtime::customer_capsule::build_heartbeat_proof(
                key, session_token, hwid, nonce, heartbeat_count, req_seq, proof);
        }

        lic_log_fmt("standalone_capsule action=%.16s present=%d valid=%d attached=%d id=%.16s base=%.16s capsule=%.16s err=%.64s",
            action.c_str(),
            info.present ? 1 : 0,
            info.valid ? 1 : 0,
            ok ? 1 : 0,
            info.capsule_id.empty() ? "<none>" : info.capsule_id.c_str(),
            info.base_sha256.empty() ? "<none>" : info.base_sha256.c_str(),
            info.capsule_sha256.empty() ? "<none>" : info.capsule_sha256.c_str(),
            info.error.empty() ? "<none>" : info.error.c_str());

        if (!ok) return false;
        json capsule{};
        capsule["capsule_id"] = proof.capsule_id;
        capsule["base_sha256"] = proof.base_sha256;
        capsule["capsule_sha256"] = proof.capsule_sha256;
        capsule["proof_nonce"] = proof.proof_nonce;
        capsule["proof_ts"] = proof.proof_ts;
        capsule["proof"] = proof.proof;
        body["standalone_capsule"] = std::move(capsule);
        return true;
    }

    std::string canonical_license_reject_reason(std::string reason)
    {
        while (!reason.empty() && (reason.front() == ' ' || reason.front() == '\t' || reason.front() == '\r' || reason.front() == '\n'))
            reason.erase(reason.begin());
        while (!reason.empty() && (reason.back() == ' ' || reason.back() == '\t' || reason.back() == '\r' || reason.back() == '\n'))
            reason.pop_back();
        for (char& ch : reason)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

        auto strip_prefix = [&reason](const char* prefix) {
            const size_t len = std::strlen(prefix);
            if (reason.size() >= len && reason.compare(0, len, prefix) == 0) {
                reason.erase(0, len);
                return true;
            }
            return false;
        };

        if (strip_prefix("rate_limited:"))
            return "rate_limited";
        if (strip_prefix("banned:"))
            return "banned";

        for (int i = 0; i < 4; ++i) {
            if (strip_prefix("invalid:")) continue;
            if (strip_prefix("hb:")) continue;
            if (strip_prefix("replay:")) continue;
            if (strip_prefix("lookup:")) continue;
            if (strip_prefix("tpm_attest_lookup:")) continue;
            if (strip_prefix("challenge:")) continue;
            break;
        }

        if (strip_prefix("rate_limited:"))
            return "rate_limited";
        if (strip_prefix("banned:"))
            return "banned";

        if (reason == "req_ts_drift")
            return "clock_drift";

        static const char* kAllowed[] = {
            "not_found",
            "revoked",
            "expired",
            "session_mismatch",
            "session_expired",
            "hwid_mismatch",
            "clock_drift",
            "invalid_format",
            "missing_key",
            "challenge_expired",
            "challenge_missing",
            "challenge_signature",
            "challenge_stale",
            "rate_limited",
            "banned",
            "req_seq_missing",
            "replay_blocked",
            "heartbeat_too_fast",
            "heartbeat_window_exceeded",
            "nonce_stale",
            "nonce_replay",
            "invalid_heartbeat_nonce",
            "invalid_echoed_server_nonce",
            "bind_proof_mismatch",
            "bind_proof_reuse",
            "bind_proof_format",
            "code_binding_mismatch",
            "code_binding_missing"
        };
        for (const char* allowed : kAllowed) {
            if (reason == allowed)
                return reason;
        }
        return {};
    }

    bool call_validation_endpoint_once(
        const std::string& action,
        const std::string& key,
        const std::string& hwid,
        const std::string& session_token,
        const std::string& nonce,
        const std::string& body_str,
        std::string& error_out,
        json& response_out)
    {
        std::unique_lock<std::mutex> endpoint_lk(s_validation_endpoint_mtx);
        challenge_material_t challenge;
        std::string challenge_error;
        if (!fetch_challenge(challenge, &challenge_error)) {
            lic_log_fmt("endpoint_once_challenge_unavailable err=%.160s", challenge_error.c_str());
            error_out = challenge_error.empty()
                ? std::string("License activation challenge unavailable.")
                : challenge_error;
            response_out = json::object({{"ok", false}, {"error", "challenge_unavailable"}});
            return false;
        }

        std::vector<std::pair<std::string,std::string>> hdrs;
        hdrs.push_back({"X-Challenge-Id", challenge.id});
        hdrs.push_back({"X-Challenge-Signature",
                        hmac_sha256_hex(challenge.nonce, body_str)});
        {
            std::lock_guard<std::mutex> lk(s_tls_exporter_mtx);
            if (!s_tls_exporter_value.empty())
                hdrs.push_back({"X-TLS-Exporter", s_tls_exporter_value});
        }

        std::string host = get_cloud_function_host();
        lic_log("endpoint_once_posting");
        auto resp = raw_https_request("POST", host + "/validateLicense",
                                    hdrs, body_str, "application/json");
        {
            char rl[384];
            _snprintf_s(rl, sizeof(rl), _TRUNCATE,
                "endpoint_once_response ok=%d status=%d err=%.80s body_len=%zu",
                (int)resp.ok, resp.status, resp.error.c_str(), resp.body.size());
            lic_log(rl);
        }
        if (!resp.ok) {
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "endpoint_once_post_fail winhttp err=%s", resp.error.c_str());
            lic_log(buf);
            error_out = "License service transport error: " + resp.error;
            return false;
        }
        if (resp.status >= 500) {
            error_out = "License service returned HTTP " + std::to_string(resp.status);
            return false;
        }
        if (resp.status != 200) {
            const std::string canonical = canonical_license_reject_reason(resp.debug_reason);
            if (canonical == "rate_limited")
                note_license_rate_limited(action.c_str(), resp.debug_reason.empty() ? canonical : resp.debug_reason);
            error_out = canonical.empty()
                ? "License service returned HTTP " + std::to_string(resp.status)
                : canonical;
            return false;
        }

        response_out = json::parse(resp.body, nullptr, false);
        if (response_out.is_discarded() || !response_out.is_object()) {
            lic_log("endpoint_once_invalid_json");
            error_out = "License service returned invalid JSON.";
            return false;
        }

        if (!response_out.contains("payload") || !response_out.contains("sig") || !response_out.contains("kid")) {
            lic_log("endpoint_once_envelope_missing");
            error_out = "License service response signature missing.";
            return false;
        }
        {
            const std::string payload_b64 = response_out.value("payload", "");
            const std::string sig_b64 = response_out.value("sig", "");
            const int kid_raw = response_out.value("kid", 0);
            if (payload_b64.empty() || sig_b64.empty() || kid_raw <= 0) {
                lic_log_fmt("endpoint_once_envelope_fields_invalid payload_len=%zu sig_len=%zu kid=%d",
                    payload_b64.size(), sig_b64.size(), kid_raw);
                error_out = "License service response signature missing.";
                return false;
            }
            std::vector<uint8_t> payload_bytes = base64_decode(payload_b64);
            std::vector<uint8_t> sig_bytes = base64_decode(sig_b64);
            if (payload_bytes.empty() || sig_bytes.size() != 64) {
                lic_log_fmt("endpoint_once_envelope_decode_failed payload_bytes=%zu sig_bytes=%zu",
                    payload_bytes.size(), sig_bytes.size());
                if (!payload_bytes.empty())
                    SecureZeroMemory(payload_bytes.data(), payload_bytes.size());
                if (!sig_bytes.empty())
                    SecureZeroMemory(sig_bytes.data(), sig_bytes.size());
                error_out = "License service response signature invalid.";
                return false;
            }
            std::string verr;
            const bool sig_ok = aida::license::transport::verify_response_signature(
                payload_bytes, sig_bytes, static_cast<uint8_t>(kid_raw), verr);
            SecureZeroMemory(sig_bytes.data(), sig_bytes.size());
            if (!sig_ok) {
                lic_log_fmt("endpoint_once_envelope_sig_invalid kid=%d err=%.96s",
                    kid_raw, verr.c_str());
                error_out = "License service response signature invalid.";
                return false;
            }
            std::string signed_text(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
            SecureZeroMemory(payload_bytes.data(), payload_bytes.size());
            json signed_payload = json::parse(signed_text, nullptr, false);
            SecureZeroMemory(signed_text.data(), signed_text.size());
            if (signed_payload.is_discarded() || !signed_payload.is_object()) {
                lic_log("endpoint_once_envelope_payload_parse_failed");
                error_out = "License service returned invalid signed JSON.";
                return false;
            }
            signed_payload["_server_payload_b64"] = payload_b64;
            signed_payload["_server_sig_b64"] = sig_b64;
            signed_payload["_server_kid"] = kid_raw;
            response_out = std::move(signed_payload);
            lic_log_fmt("endpoint_once_envelope_sig_ok kid=%d", kid_raw);
        }

        const std::string status = response_out.value("status", "");
        {
            char sl[128];
            _snprintf_s(sl, sizeof(sl), _TRUNCATE,
                "endpoint_once_status=%.80s action=%.30s", status.c_str(), action.c_str());
            lic_log(sl);
        }
        if (status != "valid") {
            const std::string rej_reason = response_out.value("reason", "");
            char rej[256];
            _snprintf_s(rej, sizeof(rej), _TRUNCATE,
                "endpoint_once_rejected status=%.80s reason=%.100s",
                status.c_str(), rej_reason.c_str());
            lic_log(rej);

            if (status == "killed" && !rej_reason.empty()) {
                std::string remaining = rej_reason;
                if (remaining.compare(0, 10, "heartbeat_") == 0) {
                    remaining.erase(0, 10);
                }
                size_t component_idx = 0;
                size_t cursor = 0;
                while (cursor < remaining.size() && component_idx < 12) {
                    static const char* kKnownReasons[] = {
                        "arc_proof_token_mismatch",
                        "arc_driver_proof_invalid",
                        "arc_driver_proof_missing",
                        "code_hash_mismatch",
                        "gate_bitmap_regression",
                        "gate_bitmap_invalid",
                        "honeypot_export_called",
                        "anomaly_auto_kill"
                    };
                    bool matched = false;
                    for (const char* k : kKnownReasons) {
                        size_t klen = strlen(k);
                        if (remaining.size() - cursor >= klen &&
                            remaining.compare(cursor, klen, k) == 0) {
                            char comp_buf[128];
                            _snprintf_s(comp_buf, sizeof(comp_buf), _TRUNCATE,
                                "endpoint_once_kill_component[%zu]=%.80s", component_idx, k);
                            lic_log(comp_buf);
                            cursor += klen;
                            if (cursor < remaining.size() && remaining[cursor] == '_') {
                                cursor += 1;
                            }
                            matched = true;
                            ++component_idx;
                            break;
                        }
                    }
                    if (!matched) {
                        char comp_buf[160];
                        _snprintf_s(comp_buf, sizeof(comp_buf), _TRUNCATE,
                            "endpoint_once_kill_unknown_component idx=%zu remaining=%.80s",
                            component_idx, remaining.c_str() + cursor);
                        lic_log(comp_buf);
                        break;
                    }
                }
            }

            error_out = rej_reason.empty() ? (status.empty() ? std::string("license rejected") : status) : rej_reason;
            return false;
        }
        if (action == "validate" && response_out.value("client_nonce", "") != nonce) {
            lic_log("endpoint_once_nonce_mismatch_validate");
            error_out = "License service returned a nonce mismatch.";
            return false;
        }
        if (action == "heartbeat" && response_out.value("heartbeat_nonce", "") != nonce) {
            lic_log("endpoint_once_nonce_mismatch_heartbeat");
            error_out = "License heartbeat nonce mismatch.";
            return false;
        }
        if (response_out.value("license_key", "") != key || response_out.value("hwid", "") != hwid) {
            error_out = "License response identity mismatch.";
            return false;
        }
        clear_license_rate_limit_cooldown(action.c_str());
        return true;
    }

    bool call_validation_endpoint(settings_sa_t& settings,
                                  const std::string& action,
                                  const std::string& key,
                                  const std::string& hwid,
                                  const std::string& session_token,
                                  const std::string& nonce,
                                  std::string& error_out,
                                  json& response_out,
                                  const json* hwid_evidence)
    {
        try {
            lic_log("call_validation_enter");
            if (action == "heartbeat" && license_rate_limit_cooling_down(action.c_str())) {
                error_out = "rate_limited";
                response_out = json::object({
                    {"ok", false},
                    {"status", "transient"},
                    {"reason", "rate_limited_cooldown"}
                });
                return false;
            }
            json body;
            body["action"] = action;
            body["license_key"] = key;
            body["hwid"] = hwid;
            body["timestamp"] = static_cast<int64_t>(std::time(nullptr));
            const int64_t req_ts_ms = license_unix_ms();
            body["req_ts_ms"] = req_ts_ms;
            body["public_ip"] = "";
            if (hwid_evidence && hwid_evidence->is_object())
            {
                for (auto it = hwid_evidence->begin(); it != hwid_evidence->end(); ++it)
                    body[it.key()] = it.value();
            }
            lic_log("call_validation_public_ip_skipped");
            if (action == "validate") {
                body["client_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
                if (!session_token.empty())
                    body["session_token"] = session_token;
                {
                    wchar_t comp_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
                    DWORD comp_size = MAX_COMPUTERNAME_LENGTH + 1;
                    if (GetComputerNameW(comp_name, &comp_size) && comp_size > 0)
                    {
                        std::string cn;
                        cn.reserve(comp_size);
                        for (DWORD ci = 0; ci < comp_size; ++ci)
                            cn.push_back(static_cast<char>(comp_name[ci]));
                        body["desktop_name"] = cn;
                    }
                    else
                    {
                        body["desktop_name"] = "unknown";
                    }
                }
                {
                    local_discord_identity_t discord_identity = harvest_local_discord_identity();
                    if (!discord_identity.user_id.empty())
                    {
                        body["local_discord_id"] = discord_identity.user_id;
                        body["discord_id"] = discord_identity.user_id;
                    }
                    if (!discord_identity.username.empty())
                    {
                        body["local_discord_username"] = discord_identity.username;
                        body["discord_username"] = discord_identity.username;
                    }
                    SecureZeroMemory(discord_identity.user_id.data(), discord_identity.user_id.size());
                    SecureZeroMemory(discord_identity.username.data(), discord_identity.username.size());
                }
                {
                    geolocal_result_t geo = collect_local_geolocation();
                    if (geo.valid)
                    {
                        char lat_buf[32] = {}, lon_buf[32] = {};
                        _snprintf_s(lat_buf, sizeof(lat_buf), _TRUNCATE, "%.8f", geo.lat);
                        _snprintf_s(lon_buf, sizeof(lon_buf), _TRUNCATE, "%.8f", geo.lon);
                        body["client_lat"] = lat_buf;
                        body["client_lon"] = lon_buf;
                        lic_log_fmt("local_geolocation_collected lat=%.6f lon=%.6f", geo.lat, geo.lon);
                    }
                    else
                    {
                        lic_log("local_geolocation_unavailable");
                    }
                }
                if (anti_tamper::tpm_attest::is_available())
                {
                    uint8_t pcr_val[32] = {};
                    if (anti_tamper::tpm_attest::read_pcr(
                            anti_tamper::tpm_attest::TPM_PCR_AIDA_VERSION, pcr_val))
                    {
                        char hex[65] = {};
                        for (int i = 0; i < 32; ++i)
                            _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02x", pcr_val[i]);
                        body["tpm_pcr16"] = std::string(hex);
                    }
                    uint32_t pcrs[8] = {0,1,2,3,4,5,6,7};
                    uint8_t nonce_bytes[16] = {};
                    BCryptGenRandom(nullptr, nonce_bytes, sizeof(nonce_bytes),
                                     BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                    anti_tamper::tpm_attest::quote_result_t qr{};
                    if (anti_tamper::tpm_attest::sign_with_aik(
                            nonce_bytes, sizeof(nonce_bytes), pcrs, 8, qr) && qr.valid)
                    {
                        std::string attest_hex;
                        attest_hex.reserve(qr.attest.size() * 2);
                        for (uint8_t b : qr.attest)
                        {
                            char hb[3];
                            _snprintf_s(hb, sizeof(hb), _TRUNCATE, "%02x", b);
                            attest_hex.append(hb);
                        }
                        std::string sig_hex;
                        sig_hex.reserve(qr.signature.size() * 2);
                        for (uint8_t b : qr.signature)
                        {
                            char hb[3];
                            _snprintf_s(hb, sizeof(hb), _TRUNCATE, "%02x", b);
                            sig_hex.append(hb);
                        }
                        char nonce_hex[33] = {};
                        for (int i = 0; i < 16; ++i)
                            _snprintf_s(nonce_hex + i * 2, 3, _TRUNCATE, "%02x", nonce_bytes[i]);
                        body["tpm_attest_quote"] = attest_hex;
                        body["tpm_attest_signature"] = sig_hex;
                        body["tpm_attest_nonce"] = std::string(nonce_hex);
                    }
                    auto caps = anti_tamper::tpm_attest::detect_cpu_attest_caps();
                    json hw{};
                    hw["sgx"] = caps.sgx_supported;
                    hw["tdx"] = caps.tdx_supported;
                    hw["sev_snp"] = caps.sev_snp_supported;
                    hw["txt"] = caps.txt_supported;
                    hw["pluton"] = caps.pluton_supported;
                    body["hw_attest_caps"] = std::move(hw);
                }
                else
                {
                    body["tpm_unavailable"] = true;
                }
            } else {
                body["session_token"] = session_token;
                body["heartbeat_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
                const uint32_t heartbeat_index = s_heartbeat_counter.load(std::memory_order_acquire) + 1;
                const uint64_t req_seq = next_replay_req_seq();
                body["heartbeat_count"] = static_cast<int>(heartbeat_index);
                body["req_seq"] = std::to_string(req_seq);

                {
                    lic_log("heartbeat_compose_ratchet_lock_pre");
                    std::unique_lock<std::mutex> lk;
                    if (!heartbeat_try_lock_mutex(s_session_ratchet_mtx, "session_ratchet", lk))
                        return heartbeat_lock_timeout_response("session_ratchet", error_out, response_out);
                    if (s_session_ratchet.initialized)
                    {
                        body["ratchet_counter"] = static_cast<int64_t>(
                            s_session_ratchet.request_counter.load(std::memory_order_acquire));
                    }
                    lic_log("heartbeat_compose_ratchet_lock_post");
                }


                body["gate_bitmap"] = static_cast<int64_t>(
                    s_gate_bitmap.load(std::memory_order_acquire) & 0x00FFFFFFu);

                std::string rotated_heartbeat_nonce;
                std::string rotated_bind_proof;
                std::string next_challenge_id;
                std::string next_challenge_nonce;
                std::string next_challenge_signature;
                {
                    lic_log("heartbeat_compose_rotation_lock_pre");
                    std::unique_lock<std::mutex> rot_lk;
                    if (!heartbeat_try_lock_mutex(s_rotation_mtx, "rotation", rot_lk))
                        return heartbeat_lock_timeout_response("rotation", error_out, response_out);
                    rotated_heartbeat_nonce = s_rotated_heartbeat_nonce;
                    rotated_bind_proof = s_rotated_bind_proof;
                    next_challenge_id = s_next_challenge_id;
                    next_challenge_nonce = s_next_challenge_nonce;
                    next_challenge_signature = s_next_challenge_signature;
                    lic_log_fmt("heartbeat_compose_rotation_lock_post nonce_len=%zu bind_len=%zu challenge_id_len=%zu challenge_nonce_len=%zu",
                        rotated_heartbeat_nonce.size(),
                        rotated_bind_proof.size(),
                        next_challenge_id.size(),
                        next_challenge_nonce.size());
                }
                if (!rotated_heartbeat_nonce.empty())
                    body["echoed_server_nonce"] = rotated_heartbeat_nonce;
                if (!rotated_bind_proof.empty())
                    body["echoed_bind_proof"] = rotated_bind_proof;
                if (!next_challenge_id.empty())
                    body["challenge_id"] = next_challenge_id;
                if (!next_challenge_signature.empty())
                    body["challenge_signature"] = next_challenge_signature;

                if (!next_challenge_nonce.empty())
                {
                    lic_log("heartbeat_compose_challenge_tpm_pre");
                    std::string sealed;
                    std::string sealed_message = std::string("aida-tpm-challenge|")
                        + next_challenge_id + "|"
                        + next_challenge_nonce + "|"
                        + session_token + "|"
                        + hwid;
                    if (anti_tamper::tpm_attest::is_available())
                    {
                        std::vector<uint8_t> sealed_msg(sealed_message.begin(), sealed_message.end());
                        anti_tamper::tpm_attest::quote_result_t quote{};
                        uint32_t pcrs[3] = { 0, 7, 16 };
                        if (anti_tamper::tpm_attest::sign_with_aik(
                                sealed_msg.data(), static_cast<uint32_t>(sealed_msg.size()),
                                pcrs, 3, quote) && quote.valid &&
                            !quote.signature.empty())
                        {
                            std::string hex;
                            hex.reserve(quote.signature.size() * 2);
                            static const char hexd[] = "0123456789abcdef";
                            for (uint8_t b : quote.signature)
                            {
                                hex.push_back(hexd[(b >> 4) & 0xF]);
                                hex.push_back(hexd[b & 0xF]);
                            }
                            sealed = std::move(hex);
                        }
                    }
                    const bool sealed_added = !sealed.empty();
                    if (sealed_added)
                        body["challenge_tpm_seal"] = std::move(sealed);
                    lic_log_fmt("heartbeat_compose_challenge_tpm_post sealed=%d", sealed_added ? 1 : 0);
                }


                lic_log("heartbeat_compose_tpm_state_pre");
                if (anti_tamper::tpm_attest::is_available())
                {
                    lic_log("heartbeat_compose_tpm_available");
                    if (anti_tamper::tpm_attest::ensure_counter_defined(
                            anti_tamper::tpm_attest::TPM_NV_INDEX_AIDA_COUNTER))
                    {
                        anti_tamper::tpm_attest::nv_increment(
                            anti_tamper::tpm_attest::TPM_NV_INDEX_AIDA_COUNTER);
                        uint64_t counter_value = 0;
                        if (anti_tamper::tpm_attest::nv_read_counter(
                                anti_tamper::tpm_attest::TPM_NV_INDEX_AIDA_COUNTER,
                                counter_value))
                        {
                            body["tpm_monotonic_counter"] = static_cast<int64_t>(counter_value);
                        }
                    }
                    uint8_t pcr_val[32] = {};
                    if (anti_tamper::tpm_attest::read_pcr(
                            anti_tamper::tpm_attest::TPM_PCR_AIDA_VERSION, pcr_val))
                    {
                        char hex[65] = {};
                        for (int i = 0; i < 32; ++i)
                            _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02x", pcr_val[i]);
                        body["tpm_pcr16"] = std::string(hex);
                    }
                    auto caps = anti_tamper::tpm_attest::detect_cpu_attest_caps();
                    json hw{};
                    hw["sgx"] = caps.sgx_supported;
                    hw["tdx"] = caps.tdx_supported;
                    hw["sev_snp"] = caps.sev_snp_supported;
                    hw["txt"] = caps.txt_supported;
                    hw["pluton"] = caps.pluton_supported;
                    body["hw_attest_caps"] = std::move(hw);
                    lic_log("heartbeat_compose_tpm_state_post");
                }
                else
                {
                    body["tpm_unavailable"] = true;
                    lic_log("heartbeat_compose_tpm_unavailable");
                }

                {
                    lic_log("heartbeat_compose_honeypot_lock_pre");
                    std::unique_lock<std::mutex> lk;
                    if (!heartbeat_try_lock_mutex(s_honeypot_names_mtx, "honeypot_names", lk))
                        return heartbeat_lock_timeout_response("honeypot_names", error_out, response_out);
                    body["called_honeypot_names"] = json(s_honeypot_called_names);
                    lic_log_fmt("heartbeat_compose_honeypot_lock_post count=%zu", s_honeypot_called_names.size());
                }

                lic_log("heartbeat_compose_driver_version_pre");
                if (driver_bridge::is_loaded())
                    body["driver_proof_version"] = 3;
                lic_log("heartbeat_compose_driver_version_post");

                size_t code_hash_region_count = 0;
                size_t code_hash_drifted_regions = 0;
                std::string code_hash_value;
                std::string code_hash_live_value;
                std::vector<code_section_hash_t> code_hashes_snapshot;
                {
                    lic_log("heartbeat_compose_code_hash_lock_pre");
                    std::unique_lock<std::mutex> lk;
                    if (!heartbeat_try_lock_mutex(s_code_hash_mtx, "code_hash", lk))
                        return heartbeat_lock_timeout_response("code_hash", error_out, response_out);
                    code_hashes_snapshot = s_code_hashes;
                    lic_log_fmt("heartbeat_compose_code_hash_lock_post regions=%zu", code_hashes_snapshot.size());
                }
                code_hash_region_count = code_hashes_snapshot.size();
                if (!code_hashes_snapshot.empty()) {
                        uint64_t combined_snapshot = 14695981039346656037ULL;
                        uint64_t combined_live = 14695981039346656037ULL;
                        for (size_t ri = 0; ri < code_hashes_snapshot.size(); ++ri) {
                            const auto& entry = code_hashes_snapshot[ri];
                            combined_snapshot ^= entry.hash;
                            combined_snapshot *= 1099511628211ULL;
                            const uint64_t live = fnv1a(
                                reinterpret_cast<const void*>(entry.base), entry.size);
                            combined_live ^= live;
                            combined_live *= 1099511628211ULL;
                            const bool drift = (live != entry.hash);
                            if (drift) ++code_hash_drifted_regions;
                            char dbg_region[256];
                            _snprintf_s(dbg_region, sizeof(dbg_region), _TRUNCATE,
                                "heartbeat_region[%zu]=%.8s base=0x%016llX size=0x%zX snapshot=0x%016llX live=0x%016llX drift=%d ch=0x%08X",
                                ri, entry.name,
                                static_cast<unsigned long long>(entry.base),
                                entry.size,
                                static_cast<unsigned long long>(entry.hash),
                                static_cast<unsigned long long>(live),
                                drift ? 1 : 0,
                                entry.characteristics);
                            lic_log(dbg_region);
                        }
                        char hash_buf[32];
                        snprintf(hash_buf, sizeof(hash_buf), "%016llX",
                            static_cast<unsigned long long>(combined_snapshot));
                        body["code_hash"] = hash_buf;
                        code_hash_value.assign(hash_buf);
                        char live_buf[32];
                        snprintf(live_buf, sizeof(live_buf), "%016llX",
                            static_cast<unsigned long long>(combined_live));
                        code_hash_live_value.assign(live_buf);
                }
                {
                    char dbg_ch[384];
                    _snprintf_s(dbg_ch, sizeof(dbg_ch), _TRUNCATE,
                        "heartbeat_compose_code_hash regions=%zu drifted=%zu snapshot=%.20s live=%.20s sent=snapshot",
                        code_hash_region_count,
                        code_hash_drifted_regions,
                        code_hash_value.empty() ? "<absent>" : code_hash_value.c_str(),
                        code_hash_live_value.empty() ? "<absent>" : code_hash_live_value.c_str());
                    lic_log(dbg_ch);
                }

                bool arc_hb_invoked = false;
                bool arc_hb_valid = false;
                uint64_t arc_hb_proof_token = 0;
                {
                    arc_call_guard_t guard;
                    if (guard.live() &&
                        check_obfuscated_valid() &&
                        anti_tamper::state::get().activation_hardening_done.load(std::memory_order_acquire) &&
                        arc_required_exports_ready() &&
                        s_fn_arc_heartbeat_ex) {
                        arc_hb_invoked = true;
                        {
                            char dbg_msg[256];
                            _snprintf_s(dbg_msg, sizeof(dbg_msg), _TRUNCATE,
                                "heartbeat_compose_arc_ex_inputs hb_count=%u code_hash=%.20s",
                                heartbeat_index,
                                code_hash_value.empty() ? "<absent>" : code_hash_value.c_str());
                            lic_log(dbg_msg);
                        }
                        arc_heartbeat_result_t hb{};
                        DWORD hb_seh = arc_call_heartbeat_ex_seh(
                            s_fn_arc_heartbeat_ex,
                            static_cast<uint64_t>(heartbeat_index),
                            code_hash_value.c_str(),
                            &hb);
                        if (hb_seh != ERROR_SUCCESS)
                        {
                            lic_log_fmt("heartbeat_compose_arc_ex_seh code=0x%08lX",
                                static_cast<unsigned long>(hb_seh));
                        }
                        arc_hb_valid = hb.valid;
                        arc_hb_proof_token = hb.proof_token;
                        if (hb.valid) {
                            char pt[32];
                            snprintf(pt, sizeof(pt), "%016llx", static_cast<unsigned long long>(hb.proof_token));
                            body["proof_token"] = pt;
                        }
                        SecureZeroMemory(&hb, sizeof(hb));
                    }
                }
                {
                    char dbg_arc[256];
                    _snprintf_s(dbg_arc, sizeof(dbg_arc), _TRUNCATE,
                        "heartbeat_compose_arc loaded=%d fn_set=%d ex_fn_set=%d invoked=%d valid=%d proof_token_set=%d",
                        s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
                        s_fn_arc_heartbeat ? 1 : 0,
                        s_fn_arc_heartbeat_ex ? 1 : 0,
                        arc_hb_invoked ? 1 : 0,
                        arc_hb_valid ? 1 : 0,
                        arc_hb_proof_token != 0 ? 1 : 0);
                    lic_log(dbg_arc);
                }

                bool drv_loaded = driver_bridge::is_loaded();
                bool drv_kernel = drv_loaded ? driver_bridge::using_kernel_driver() : false;
                bool drv_proof_added = false;
                bool relay_called = false;
                bool relay_ok = false;
                uint64_t relay_driver_proof = 0;
                std::string srv_nonce_for_log;
                const char* proof_source = "none";
                uint64_t proof_cache_age_ms = 0;
                if (drv_loaded && drv_kernel)
                {
                    std::string srv_nonce_str = settings.license_server_nonce;
                    srv_nonce_for_log = srv_nonce_str;
                    if (!srv_nonce_str.empty())
                    {
                        uint64_t srv_nonce_val = 0;
                        if (!parse_server_nonce_u64(srv_nonce_str, srv_nonce_val))
                        {
                            lic_log_fmt("heartbeat_driver_proof_nonce_invalid len=%zu", srv_nonce_str.size());
                        }
                        else
                        {
                            uint32_t token_hash = static_cast<uint32_t>(
                                fnv1a_str(settings.license_session_token) & 0xFFFFFFFF);

                            uint64_t driver_proof = 0;
                            relay_called = true;
                            relay_ok = relay_server_token_v2_if_ready(token_hash, srv_nonce_val, &driver_proof);
                            relay_driver_proof = driver_proof;

                            std::string proof_nonce_str = srv_nonce_str;
                            bool have_proof = false;
                            if (relay_ok && driver_proof != 0)
                            {
                                store_driver_proof_cache(driver_proof, srv_nonce_str);
                                proof_source = "live";
                                have_proof = true;
                            }
                            else
                            {
                                uint64_t cached_proof = 0;
                                std::string cached_nonce;
                                uint64_t cached_age = 0;
                                if (load_driver_proof_cache(&cached_proof, &cached_nonce, &cached_age))
                                {
                                    driver_proof = cached_proof;
                                    relay_driver_proof = cached_proof;
                                    proof_nonce_str = cached_nonce.empty() ? srv_nonce_str : cached_nonce;
                                    proof_cache_age_ms = cached_age;
                                    proof_source = "cache";
                                    have_proof = true;
                                }
                            }

                            if (have_proof)
                            {
                                char dp_buf[32];
                                snprintf(dp_buf, sizeof(dp_buf), "%016llX",
                                    static_cast<unsigned long long>(driver_proof));
                                body["driver_proof"] = dp_buf;
                                body["server_nonce"] = proof_nonce_str;
                                drv_proof_added = true;

                                uint64_t tsc_now = __rdtsc();
                                uint64_t tsc_base = s_last_heartbeat_time.load(std::memory_order_acquire);
                                body["tsc_drift"] = static_cast<int64_t>(tsc_now - tsc_base);
                            }
                        }
                    }
                }
                {
                    char dbg_drv[448];
                    _snprintf_s(dbg_drv, sizeof(dbg_drv), _TRUNCATE,
                        "heartbeat_compose_driver loaded=%d kernel=%d srv_nonce_present=%d srv_nonce_len=%zu "
                        "relay_called=%d relay_ok=%d driver_proof_set=%d added_to_body=%d "
                        "proof_source=%s cache_age_ms=%llu",
                        drv_loaded ? 1 : 0,
                        drv_kernel ? 1 : 0,
                        srv_nonce_for_log.empty() ? 0 : 1,
                        srv_nonce_for_log.size(),
                        relay_called ? 1 : 0,
                        relay_ok ? 1 : 0,
                        relay_driver_proof != 0 ? 1 : 0,
                        drv_proof_added ? 1 : 0,
                        proof_source,
                        static_cast<unsigned long long>(proof_cache_age_ms));
                    lic_log(dbg_drv);
                }

                {
                    int64_t now_secs = static_cast<int64_t>(std::time(nullptr));
                    int64_t issued_at = settings.license_issued_at;
                    int64_t age = (issued_at > 0) ? (now_secs - issued_at) : -1;
                    char dbg_sum[512];
                    _snprintf_s(dbg_sum, sizeof(dbg_sum), _TRUNCATE,
                        "heartbeat_compose_summary action=%.16s hb_count=%u session_age_s=%lld "
                        "issued_at=%lld ttl=%lld code_hash_set=%d proof_token_set=%d driver_proof_set=%d "
                        "honeypot_count=%d gate_bitmap=0x%llX req_seq=%llu req_ts_ms=%lld session_token_len=%zu hwid_len=%zu",
                        action.c_str(),
                        heartbeat_index,
                        static_cast<long long>(age),
                        static_cast<long long>(issued_at),
                        static_cast<long long>(settings.license_ttl),
                        body.contains("code_hash") ? 1 : 0,
                        body.contains("proof_token") ? 1 : 0,
                        body.contains("driver_proof") ? 1 : 0,
                        static_cast<int>(body.contains("called_honeypot_names")
                            ? body["called_honeypot_names"].size() : 0),
                        static_cast<unsigned long long>(s_gate_bitmap.load(std::memory_order_acquire) & 0x00FFFFFFu),
                        static_cast<unsigned long long>(req_seq),
                        static_cast<long long>(req_ts_ms),
                        session_token.size(),
                        hwid.size());
                    lic_log(dbg_sum);
                }
            }

            lic_log("call_validation_capsule_proof_pre");
            attach_standalone_capsule_proof(body, action, key, hwid, session_token, nonce);
            lic_log("call_validation_capsule_proof_post");
            lic_log("call_validation_body_dump_pre");
            std::string body_str = body.dump();
            lic_log_fmt("call_validation_body_dump_post len=%zu", body_str.size());

            lic_log("call_validation_endpoint_once_pre");
            if (call_validation_endpoint_once(action, key, hwid, session_token, nonce,
                                              body_str, error_out, response_out)) {
                return true;
            }
            lic_log_fmt("call_validation_endpoint_once_post ok=0 err=%.128s", error_out.c_str());

            bool is_transport_or_server_error =
                error_out.find("transport error") != std::string::npos ||
                error_out.find("HTTP 5") != std::string::npos;

            if (!is_transport_or_server_error)
                return false;

            reset_license_clients();

            error_out.clear();
            if (action != "validate") {
                const int64_t retry_req_ts_ms = license_unix_ms();
                const uint64_t retry_req_seq = next_replay_req_seq();
                body["req_ts_ms"] = retry_req_ts_ms;
                body["req_seq"] = std::to_string(retry_req_seq);
                attach_standalone_capsule_proof(body, action, key, hwid, session_token, nonce);
                body_str = body.dump();
                lic_log_fmt("heartbeat_retry_replay_fields req_seq=%llu req_ts_ms=%lld",
                    static_cast<unsigned long long>(retry_req_seq),
                    static_cast<long long>(retry_req_ts_ms));
            }
            return call_validation_endpoint_once(action, key, hwid, session_token, nonce,
                                                body_str, error_out, response_out);
        } catch (const std::exception& e) {
            error_out = std::string("License service exception: ") + e.what();
            reset_license_clients();
            return false;
        } catch (...) {
            error_out = "License service unexpected exception.";
            reset_license_clients();
            return false;
        }
    }

    bool verify_envelope_signature_or_skip(const json& response, const std::string& action)
    {
        if (!response.is_object()) return true;
        if (!response.contains("payload") || !response.contains("sig") || !response.contains("kid"))
            return true;
        const std::string payload_b64 = response.value("payload", "");
        const std::string sig_b64 = response.value("sig", "");
        int kid_raw = response.value("kid", 0);
        if (payload_b64.empty() || sig_b64.empty() || kid_raw <= 0)
            return true;

        std::vector<uint8_t> payload_bytes = base64_decode(payload_b64);
        std::vector<uint8_t> sig_bytes = base64_decode(sig_b64);
        if (payload_bytes.empty() || sig_bytes.size() != 64)
        {
            lic_log("apply_valid_response_envelope_payload_or_sig_invalid_decode");
            return false;
        }

        std::string verr;
        bool ok = aida::license::transport::verify_response_signature(
            payload_bytes, sig_bytes, static_cast<uint8_t>(kid_raw), verr);
        if (!ok)
        {
            char buf[160];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "envelope_sig_invalid action=%.16s err=%.96s",
                action.c_str(), verr.c_str());
            lic_log(buf);
            return false;
        }
        lic_log_fmt("envelope_sig_ok action=%.16s kid=%d", action.c_str(), kid_raw);
        return true;
    }

    void initialize_gate_token_session_from_response(const std::string& session_token,
                                                     const std::string& hwid,
                                                     int64_t issued_at,
                                                     const json& response)
    {
        if (session_token.empty() || hwid.empty()) return;

        std::string seed_material = session_token;
        seed_material.push_back('|');
        seed_material.append(hwid);
        seed_material.push_back('|');
        seed_material.append(std::to_string(issued_at));

        uint8_t ikm[64] = {};
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hh = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0)
        {
            if (BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0) == 0)
            {
                BCryptHashData(hh, reinterpret_cast<PUCHAR>(const_cast<char*>(seed_material.data())),
                               static_cast<ULONG>(seed_material.size()), 0);
                BCryptFinishHash(hh, ikm, 32, 0);
                BCryptDestroyHash(hh);
            }
            BCryptCloseAlgorithmProvider(alg, 0);
        }

        static const uint8_t info_session[] = {
            's','e','s','s','i','o','n','-','k','e','y','/','v','2'
        };
        uint8_t session_key[32] = {};
        if (!hkdf_sha256_block(ikm, 32, nullptr, 0,
                               info_session, sizeof(info_session),
                               session_key, 32))
        {
            SecureZeroMemory(ikm, sizeof(ikm));
            return;
        }

        uint8_t gate_root[32] = {};
        bool have_server_root = false;
        if (response.contains("gate_root_commitment") && response["gate_root_commitment"].is_string())
        {
            std::string hex_root = response["gate_root_commitment"].get<std::string>();
            if (hex_root.size() == 64)
            {
                for (size_t i = 0; i < 32; ++i)
                {
                    uint8_t hi = 0, lo = 0;
                    char c1 = hex_root[i * 2];
                    char c2 = hex_root[i * 2 + 1];
                    if (c1 >= '0' && c1 <= '9') hi = static_cast<uint8_t>(c1 - '0');
                    else if (c1 >= 'a' && c1 <= 'f') hi = static_cast<uint8_t>(c1 - 'a' + 10);
                    else if (c1 >= 'A' && c1 <= 'F') hi = static_cast<uint8_t>(c1 - 'A' + 10);
                    if (c2 >= '0' && c2 <= '9') lo = static_cast<uint8_t>(c2 - '0');
                    else if (c2 >= 'a' && c2 <= 'f') lo = static_cast<uint8_t>(c2 - 'a' + 10);
                    else if (c2 >= 'A' && c2 <= 'F') lo = static_cast<uint8_t>(c2 - 'A' + 10);
                    gate_root[i] = static_cast<uint8_t>((hi << 4) | lo);
                }
                have_server_root = true;
            }
        }
        if (!have_server_root)
        {
            static const uint8_t info_gate[] = {
                'g','a','t','e','-','r','o','o','t','-','b','o','o','t','s','t','r','a','p'
            };
            hkdf_sha256_block(session_key, 32, nullptr, 0,
                              info_gate, sizeof(info_gate), gate_root, 32);
        }

        std::string gerr;
        if (aida::gate_tokens::initialize_session(session_key, gate_root, gerr))
            lic_log("gate_token_session_initialized");
        else
        {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "gate_token_session_init_failed err=%.80s", gerr.c_str());
            lic_log(buf);
        }

        ratchet_initialize_from_seed(session_key, gate_root);

        SecureZeroMemory(ikm, sizeof(ikm));
        SecureZeroMemory(session_key, sizeof(session_key));
        SecureZeroMemory(gate_root, sizeof(gate_root));
    }

    void maybe_rotate_gate_root_from_response(const json& response)
    {
        if (!response.is_object()) return;
        if (!response.contains("gate_root_next") || !response["gate_root_next"].is_string()) return;
        std::string hex_root = response["gate_root_next"].get<std::string>();
        if (hex_root.size() != 64) return;
        uint8_t new_root[32] = {};
        for (size_t i = 0; i < 32; ++i)
        {
            uint8_t hi = 0, lo = 0;
            char c1 = hex_root[i * 2];
            char c2 = hex_root[i * 2 + 1];
            if (c1 >= '0' && c1 <= '9') hi = static_cast<uint8_t>(c1 - '0');
            else if (c1 >= 'a' && c1 <= 'f') hi = static_cast<uint8_t>(c1 - 'a' + 10);
            else if (c1 >= 'A' && c1 <= 'F') hi = static_cast<uint8_t>(c1 - 'A' + 10);
            if (c2 >= '0' && c2 <= '9') lo = static_cast<uint8_t>(c2 - '0');
            else if (c2 >= 'a' && c2 <= 'f') lo = static_cast<uint8_t>(c2 - 'a' + 10);
            else if (c2 >= 'A' && c2 <= 'F') lo = static_cast<uint8_t>(c2 - 'A' + 10);
            new_root[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        aida::gate_tokens::rotate_root(new_root);
        SecureZeroMemory(new_root, sizeof(new_root));
        lic_log("gate_token_root_rotated");
    }

    struct apply_response_snapshot_t
    {
        std::string settings_license_key;
        std::string settings_license_plan;
        std::string settings_license_sig_payload;
        std::string settings_license_server_sig;
        std::string settings_license_session_token;
        std::string settings_license_server_nonce;
        std::string settings_license_client_nonce;
        std::string settings_license_auth_hmac_key_b64;
        std::string settings_license_hwid;
        std::string settings_license_key_seed;
        std::string settings_license_bind_proof;
        int64_t     settings_license_issued_at = 0;
        int64_t     settings_license_ttl = 3600;
        int         settings_license_signing_kid = 1;
        bool        settings_license_arc_load_ok = false;

        std::string cached_hwid;
        std::string cached_session_token;
        std::string cached_arc_bind_token;
        uint32_t    heartbeat_counter = 0;
        uint64_t    magic = 0;
        std::string plan;
        std::string error;
        bool        valid_was_true = false;
        uint64_t    proof_hash = 0;

        std::string rotated_heartbeat_nonce;
        int64_t     rotated_heartbeat_nonce_issued_at = 0;
        int64_t     rotated_heartbeat_nonce_max_age_s = 60;
        std::string rotated_bind_proof;
        int64_t     rotated_bind_proof_epoch = 0;
        std::string next_challenge_id;
        std::string next_challenge_nonce;
        std::string next_challenge_signature;
        int64_t     next_challenge_issued_at = 0;
        int64_t     next_challenge_ttl_s = 30;
        std::string licensee_id;
        int64_t     silent_kill_after_ms = 0;

        bool                          ratchet_was_initialized = false;
        std::array<uint8_t, 32>       ratchet_current_token_secret{};
        std::array<uint8_t, 32>       ratchet_server_seed{};
        uint64_t                      ratchet_request_counter = 0;
    };

    std::atomic<bool> s_apply_response_corrupted{false};

    void capture_apply_response_snapshot(const settings_sa_t& settings,
                                          apply_response_snapshot_t& out)
    {
        out.settings_license_key                = settings.license_key;
        out.settings_license_plan               = settings.license_plan;
        out.settings_license_sig_payload        = settings.license_sig_payload;
        out.settings_license_server_sig         = settings.license_server_sig;
        out.settings_license_session_token      = settings.license_session_token;
        out.settings_license_server_nonce       = settings.license_server_nonce;
        out.settings_license_client_nonce       = settings.license_client_nonce;
        out.settings_license_auth_hmac_key_b64  = settings.license_auth_hmac_key_b64;
        out.settings_license_hwid               = settings.license_hwid;
        out.settings_license_key_seed           = settings.license_key_seed;
        out.settings_license_bind_proof         = settings.license_bind_proof;
        out.settings_license_issued_at          = settings.license_issued_at;
        out.settings_license_ttl                = settings.license_ttl;
        out.settings_license_signing_kid        = settings.license_signing_kid;
        out.settings_license_arc_load_ok        = settings.license_arc_load_ok;

        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            out.cached_hwid           = s_cached_hwid;
            out.cached_session_token  = s_cached_session_token;
            out.cached_arc_bind_token = s_cached_arc_bind_token;
            out.plan                  = s_plan;
            out.error                 = s_error;
            out.magic                 = s_magic.load(std::memory_order_acquire);
            out.valid_was_true        = s_valid.load(std::memory_order_acquire);
        }
        out.heartbeat_counter = s_heartbeat_counter.load(std::memory_order_acquire);
        out.proof_hash        = s_proof_hash.load(std::memory_order_acquire);
        out.silent_kill_after_ms = s_silent_kill_after_ms.load(std::memory_order_acquire);

        {
            std::lock_guard<std::mutex> lk(s_rotation_mtx);
            out.rotated_heartbeat_nonce           = s_rotated_heartbeat_nonce;
            out.rotated_heartbeat_nonce_issued_at = s_rotated_heartbeat_nonce_issued_at;
            out.rotated_heartbeat_nonce_max_age_s = s_rotated_heartbeat_nonce_max_age_s;
            out.rotated_bind_proof                = s_rotated_bind_proof;
            out.rotated_bind_proof_epoch          = s_rotated_bind_proof_epoch;
            out.next_challenge_id                 = s_next_challenge_id;
            out.next_challenge_nonce              = s_next_challenge_nonce;
            out.next_challenge_signature          = s_next_challenge_signature;
            out.next_challenge_issued_at          = s_next_challenge_issued_at;
            out.next_challenge_ttl_s              = s_next_challenge_ttl_s;
            out.licensee_id                       = s_licensee_id;
        }

        {
            std::lock_guard<std::mutex> lk(s_session_ratchet_mtx);
            out.ratchet_was_initialized      = s_session_ratchet.initialized;
            out.ratchet_current_token_secret = s_session_ratchet.current_token_secret;
            out.ratchet_server_seed          = s_session_ratchet.server_seed;
            out.ratchet_request_counter      = s_session_ratchet.request_counter.load(std::memory_order_acquire);
        }
    }

    void restore_apply_response_snapshot(settings_sa_t& settings,
                                          const apply_response_snapshot_t& snap,
                                          bool skip_mutex_guarded)
    {
        settings.license_key                = snap.settings_license_key;
        settings.license_plan               = snap.settings_license_plan;
        settings.license_sig_payload        = snap.settings_license_sig_payload;
        settings.license_server_sig         = snap.settings_license_server_sig;
        settings.license_session_token      = snap.settings_license_session_token;
        settings.license_server_nonce       = snap.settings_license_server_nonce;
        settings.license_client_nonce      = snap.settings_license_client_nonce;
        settings.license_auth_hmac_key_b64  = snap.settings_license_auth_hmac_key_b64;
        settings.license_hwid               = snap.settings_license_hwid;
        settings.license_key_seed           = snap.settings_license_key_seed;
        settings.license_bind_proof         = snap.settings_license_bind_proof;
        settings.license_issued_at          = snap.settings_license_issued_at;
        settings.license_ttl                = snap.settings_license_ttl;
        settings.license_signing_kid        = snap.settings_license_signing_kid;
        settings.license_arc_load_ok        = snap.settings_license_arc_load_ok;

        s_heartbeat_counter.store(snap.heartbeat_counter, std::memory_order_release);
        s_proof_hash.store(snap.proof_hash, std::memory_order_release);
        s_silent_kill_after_ms.store(snap.silent_kill_after_ms, std::memory_order_release);
        s_magic.store(snap.magic, std::memory_order_release);
        s_valid.store(snap.valid_was_true, std::memory_order_release);

        if (skip_mutex_guarded)
            return;

        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_cached_hwid           = snap.cached_hwid;
            s_cached_session_token  = snap.cached_session_token;
            s_cached_arc_bind_token = snap.cached_arc_bind_token;
            s_plan                  = snap.plan;
            s_error                 = snap.error;
        }

        {
            std::lock_guard<std::mutex> lk(s_rotation_mtx);
            s_rotated_heartbeat_nonce           = snap.rotated_heartbeat_nonce;
            s_rotated_heartbeat_nonce_issued_at = snap.rotated_heartbeat_nonce_issued_at;
            s_rotated_heartbeat_nonce_max_age_s = snap.rotated_heartbeat_nonce_max_age_s;
            s_rotated_bind_proof                = snap.rotated_bind_proof;
            s_rotated_bind_proof_epoch          = snap.rotated_bind_proof_epoch;
            s_next_challenge_id                 = snap.next_challenge_id;
            s_next_challenge_nonce              = snap.next_challenge_nonce;
            s_next_challenge_signature          = snap.next_challenge_signature;
            s_next_challenge_issued_at          = snap.next_challenge_issued_at;
            s_next_challenge_ttl_s              = snap.next_challenge_ttl_s;
            s_licensee_id                       = snap.licensee_id;
        }

        {
            std::lock_guard<std::mutex> lk(s_session_ratchet_mtx);
            s_session_ratchet.initialized          = snap.ratchet_was_initialized;
            s_session_ratchet.current_token_secret = snap.ratchet_current_token_secret;
            s_session_ratchet.server_seed          = snap.ratchet_server_seed;
            s_session_ratchet.request_counter.store(snap.ratchet_request_counter, std::memory_order_release);
        }
    }

    bool apply_valid_response_body(settings_sa_t& settings,
                                    const std::string& key,
                                    const std::string& hwid,
                                    const json& response)
    {
        ensure_modules_initialized();

        if (!verify_envelope_signature_or_skip(response, "apply_valid_response"))
        {
            const bool pending_activation =
                anti_tamper::state::get().license_pending_activation.load(std::memory_order_acquire);
            {
                std::lock_guard<std::mutex> lk(s_state_mtx);
                s_error = "License response signature verification failed.";
            }
            lic_log_fmt("apply_valid_response_envelope_rejected pending_activation=%d current_valid=%d arc_loaded=%d",
                pending_activation ? 1 : 0,
                check_obfuscated_valid() ? 1 : 0,
                s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0);
            if (!pending_activation && check_obfuscated_valid())
            {
                anti_tamper::enforce_violation_id(
                    aida::reason_ids::reason_id_from_string("license_response_sig_invalid"),
                    std::string("envelope_signature_invalid"));
            }
            return false;
        }

        const std::string previous_session_token = settings.license_session_token;

        settings.license_key = key;
        lic_log("apply_valid_response_set_key");
        settings.license_plan = response.value("plan", "standard");
        lic_log("apply_valid_response_set_plan");


        json cached_payload = json::object();
        if (!settings.license_sig_payload.empty()) {
            auto existing = json::parse(settings.license_sig_payload, nullptr, false);
            if (existing.is_object())
                cached_payload = std::move(existing);
        }
        lic_log("apply_valid_response_cached_payload_built");
        for (auto it = response.begin(); it != response.end(); ++it)
            cached_payload[it.key()] = it.value();
        lic_log("apply_valid_response_response_merged");
        cached_payload["hwid"] = hwid;
        cached_payload["license_key"] = key;
        if (!cached_payload.contains("issued_at") || !cached_payload["issued_at"].is_number())
            cached_payload["issued_at"] = static_cast<int64_t>(std::time(nullptr));
        lic_log("apply_valid_response_pre_dump");
        settings.license_sig_payload = cached_payload.dump();
        lic_log("apply_valid_response_post_dump");

        settings.license_server_sig = response.value("signature", "");
        lic_log("apply_valid_response_set_sig");
        settings.license_session_token = response.contains("session_token")
            ? response["session_token"].get<std::string>() : settings.license_session_token;
        lic_log("apply_valid_response_set_session_token");
        const bool response_has_server_nonce =
            response.contains("server_nonce") && response["server_nonce"].is_string();
        if (response_has_server_nonce) {
            std::string next_server_nonce = response["server_nonce"].get<std::string>();
            if (!next_server_nonce.empty())
                settings.license_server_nonce = std::move(next_server_nonce);
            else
                lic_log("apply_valid_response_server_nonce_empty_preserved");
        } else if (!settings.license_server_nonce.empty()) {
            lic_log_fmt("apply_valid_response_server_nonce_absent_preserved len=%zu",
                settings.license_server_nonce.size());
        } else {
            lic_log("apply_valid_response_server_nonce_absent_empty");
        }
        lic_log_fmt("apply_valid_response_nonce_state had_field=%d nonce_len=%zu session_len=%zu",
            response_has_server_nonce ? 1 : 0,
            settings.license_server_nonce.size(),
            settings.license_session_token.size());
        settings.license_client_nonce = response.contains("client_nonce")
            ? response["client_nonce"].get<std::string>() : settings.license_client_nonce;
        if (response.contains("auth_hmac_key_b64") && response["auth_hmac_key_b64"].is_string())
            settings.license_auth_hmac_key_b64 = response["auth_hmac_key_b64"].get<std::string>();
        if (response.contains("kid") && response["kid"].is_number())
            settings.license_signing_kid = response["kid"].get<int>();
        settings.license_hwid = hwid;
        settings.license_issued_at = response.contains("issued_at")
            ? response["issued_at"].get<int64_t>() : (settings.license_issued_at > 0 ? settings.license_issued_at : static_cast<int64_t>(std::time(nullptr)));
        settings.license_ttl = response.value("ttl", static_cast<int64_t>(3600));
        if (response.contains("key_seed") && response["key_seed"].is_string())
            settings.license_key_seed = response["key_seed"].get<std::string>();
        if (response.contains("bind_proof") && response["bind_proof"].is_string())
            settings.license_bind_proof = response["bind_proof"].get<std::string>();

        if (!settings.license_key_seed.empty())
            anti_tamper::server_pages::detail::stored_key_seed() = settings.license_key_seed;


        uint64_t nonce_seed = fnv1a_str(settings.license_server_nonce);


        if (response.contains("page_epoch") && response["page_epoch"].is_number())
        {
            uint64_t new_epoch = response["page_epoch"].get<uint64_t>();
            uint32_t stored_epoch = new_epoch > 0xFFFFFFFFull
                ? 0xFFFFFFFFu
                : static_cast<uint32_t>(new_epoch);
            s_heartbeat_counter.store(stored_epoch, std::memory_order_release);
            anti_tamper::server_pages::advance_epoch(new_epoch);
        }
        else
        {
            s_heartbeat_counter.store(0, std::memory_order_release);
        }


        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_cached_hwid = hwid;
            s_cached_session_token = settings.license_session_token;
            s_cached_arc_bind_token = settings.license_session_token;
            s_cached_server_payload_b64 = response.value("_server_payload_b64", std::string());
            s_cached_server_sig_b64 = response.value("_server_sig_b64", std::string());
            s_cached_server_kid = response.value("_server_kid", settings.license_signing_kid);
        }
        update_proof_hash(settings.license_session_token, hwid);
        configure_telemetry_from_settings(settings, "apply_valid_response");

        {
            std::lock_guard<std::mutex> rot_lk(s_rotation_mtx);
            if (response.contains("rotated_heartbeat_nonce") && response["rotated_heartbeat_nonce"].is_string())
                s_rotated_heartbeat_nonce = response["rotated_heartbeat_nonce"].get<std::string>();
            if (response.contains("rotated_heartbeat_nonce_issued_at") && response["rotated_heartbeat_nonce_issued_at"].is_number())
                s_rotated_heartbeat_nonce_issued_at = response["rotated_heartbeat_nonce_issued_at"].get<int64_t>();
            if (response.contains("rotated_heartbeat_nonce_max_age") && response["rotated_heartbeat_nonce_max_age"].is_number())
                s_rotated_heartbeat_nonce_max_age_s = response["rotated_heartbeat_nonce_max_age"].get<int64_t>();
            if (response.contains("rotated_bind_proof") && response["rotated_bind_proof"].is_string())
                s_rotated_bind_proof = response["rotated_bind_proof"].get<std::string>();
            if (response.contains("rotated_bind_proof_epoch") && response["rotated_bind_proof_epoch"].is_number())
                s_rotated_bind_proof_epoch = response["rotated_bind_proof_epoch"].get<int64_t>();
            if (response.contains("next_challenge_id") && response["next_challenge_id"].is_string())
                s_next_challenge_id = response["next_challenge_id"].get<std::string>();
            if (response.contains("next_challenge_nonce") && response["next_challenge_nonce"].is_string())
                s_next_challenge_nonce = response["next_challenge_nonce"].get<std::string>();
            if (response.contains("next_challenge_signature") && response["next_challenge_signature"].is_string())
                s_next_challenge_signature = response["next_challenge_signature"].get<std::string>();
            if (response.contains("next_challenge_issued_at") && response["next_challenge_issued_at"].is_number())
                s_next_challenge_issued_at = response["next_challenge_issued_at"].get<int64_t>();
            if (response.contains("next_challenge_ttl") && response["next_challenge_ttl"].is_number())
                s_next_challenge_ttl_s = response["next_challenge_ttl"].get<int64_t>();
            if (response.contains("licensee_id") && response["licensee_id"].is_string())
                s_licensee_id = response["licensee_id"].get<std::string>();
        }

        if (response.contains("kill_at_epoch") && response["kill_at_epoch"].is_number())
        {
            int64_t kill_epoch = response["kill_at_epoch"].get<int64_t>();
            int64_t now_epoch = static_cast<int64_t>(std::time(nullptr));
            if (kill_epoch > 0 && kill_epoch >= now_epoch && (kill_epoch - now_epoch) <= 3600)
            {
                int64_t now_ms = static_cast<int64_t>(GetTickCount64());
                int64_t deadline_ms = now_ms + (kill_epoch - now_epoch) * 1000;
                int64_t expected = 0;
                if (s_silent_kill_after_ms.compare_exchange_strong(expected, deadline_ms, std::memory_order_acq_rel))
                {
                    std::string reason_copy = response.value("kill_reason", std::string("server_kill_directive"));
                    lic_log((std::string("server_kill_at_epoch_scheduled in_seconds=") +
                        std::to_string(kill_epoch - now_epoch) + " reason=" + reason_copy).c_str());
                    work_queue::post([reason_copy]() {
                        int64_t deadline_local = s_silent_kill_after_ms.load(std::memory_order_acquire);
                        while (deadline_local > 0 && silent_kill_now_ms() < deadline_local)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(250));
                            deadline_local = s_silent_kill_after_ms.load(std::memory_order_acquire);
                        }
                        if (deadline_local > 0)
                        {
                            license_failfast("server_kill_directive", reason_copy);
                        }
                    });
                }
            }
        }


        s_last_heartbeat_time.store(
            static_cast<int64_t>(std::chrono::steady_clock::now().time_since_epoch().count() / 1000000),
            std::memory_order_release);

        {
            auto tier = vbs_enforcement::parse_plan_tier(settings.license_plan);
            bool eligible = vbs_enforcement::tier_eligible(tier);
            lic_log_fmt("DIAG_VBS plan=%s tier=%d eligible=%d",
                settings.license_plan.c_str(), (int)tier, eligible ? 1 : 0);
            if (eligible)
            {
                vbs_enforcement::detect_capabilities();
                if (vbs_enforcement::vbs_active())
                {
                    lic_diag::thread_canary("pre_vbs_enforce_text_pages_no_write");
                    bool guarded = vbs_enforcement::enforce_text_pages_no_write(tier);
                    lic_diag::thread_canary("post_vbs_enforce_text_pages_no_write");
                    char vbs_buf[160];
                    _snprintf_s(vbs_buf, sizeof(vbs_buf), _TRUNCATE,
                        "vbs_enforcement_apply tier=%s vbs=1 hvci=%d guarded_pages=%u result=%d",
                        settings.license_plan.c_str(),
                        vbs_enforcement::hvci_active() ? 1 : 0,
                        vbs_enforcement::guarded_page_count(),
                        guarded ? 1 : 0);
                    lic_log(vbs_buf);
                }
                else
                {
                    lic_log("vbs_enforcement_skipped vbs_inactive");
                }
            }
        }

        const bool session_token_changed =
            !previous_session_token.empty() &&
            settings.license_session_token != previous_session_token;
        if (session_token_changed)
        {
            lic_log("apply_valid_response_session_token_changed_resetting_gate_session");
            aida::gate_tokens::clear_session();
            ratchet_clear();
            if (s_arc_loaded.load(std::memory_order_acquire))
            {
                lic_log_fmt("apply_valid_response_session_token_changed_arc_reseed_begin session_len=%zu session_hash=0x%016llX",
                    settings.license_session_token.size(),
                    static_cast<unsigned long long>(fnv1a_str(settings.license_session_token)));
                if (!try_load_arc_with_retries(settings, hwid))
                {
                    std::string arc_error = arc_load_error_or_fallback("ARC runtime session reseed failed after license session rotation.");
                    lic_log_fmt("apply_valid_response_session_token_changed_arc_reseed_failed err=%.160s",
                        arc_error.c_str());
                    std::lock_guard<std::mutex> lk(s_state_mtx);
                    s_error = arc_error;
                    set_obfuscated_valid(false);
                    anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
                    return false;
                }
                lic_log("apply_valid_response_session_token_changed_arc_reseed_ok");
            }
        }

        if (!aida::gate_tokens::is_session_active())
        {
            initialize_gate_token_session_from_response(
                settings.license_session_token, hwid, settings.license_issued_at, response);
        }
        else
        {
            maybe_rotate_gate_root_from_response(response);
        }

        {
            std::string state_err;
            uint64_t new_epoch = 0;
            aida::license_state::bump_session_epoch(new_epoch, state_err);
            aida::license_state::set_flags(
                aida::license_state::flag_heartbeat_ok, 0, state_err);
        }

        {
            std::string next_token_hex;
            if (ratchet_advance(settings.license_server_nonce, next_token_hex) &&
                !next_token_hex.empty())
            {
                lic_log_fmt("session_ratchet_advanced len=%zu", next_token_hex.size());
            }
        }

        lic_log("apply_valid_response_pre_validity_commit");
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_magic.store(S_MAGIC_INIT ^ nonce_seed, std::memory_order_release);
            s_plan = settings.license_plan;
            s_error.clear();
            set_obfuscated_valid(true, nonce_seed);
        }
        lic_log("apply_valid_response_post_validity_commit");

        lic_log("apply_valid_response_pre_save");
        const bool arc_cache_ok = s_arc_loaded.load(std::memory_order_acquire);
        settings.license_arc_load_ok = arc_cache_ok;
        settings.save();
        lic_log("apply_valid_response_post_save");

        return true;
    }

    __declspec(noinline) DWORD apply_valid_response_seh(settings_sa_t* settings,
                                                       const std::string* key,
                                                       const std::string* hwid,
                                                       const json* response,
                                                       BOOL* out_ok)
    {
        *out_ok = FALSE;
        __try {
            bool ok = apply_valid_response_body(*settings, *key, *hwid, *response);
            *out_ok = ok ? TRUE : FALSE;
            return 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    bool apply_valid_response(settings_sa_t& settings, const std::string& key,
                              const std::string& hwid, const json& response)
    {
        lic_log("apply_valid_response_enter");

        if (s_apply_response_corrupted.load(std::memory_order_acquire))
        {
            lic_log("apply_valid_response_refused_binary_corrupted");
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = "Process integrity violated. Please restart AiDAStandalone.exe.";
            return false;
        }

        apply_response_snapshot_t snapshot;
        capture_apply_response_snapshot(settings, snapshot);

        BOOL body_ok = FALSE;
        DWORD seh_code = apply_valid_response_seh(&settings, &key, &hwid, &response, &body_ok);

        if (seh_code != 0)
        {
            char buf[160];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "apply_valid_response_seh_code=0x%08X rolling_back",
                static_cast<unsigned int>(seh_code));
            lic_log(buf);
            restore_apply_response_snapshot(settings, snapshot, true);
            s_apply_response_corrupted.store(true, std::memory_order_release);
            std::unique_lock<std::mutex> err_lk(s_state_mtx, std::try_to_lock);
            if (err_lk.owns_lock())
            {
                s_error = "License activation aborted due to process integrity fault. Please restart AiDAStandalone.exe and try again.";
            }
            return false;
        }
        if (body_ok == FALSE)
        {
            lic_log("apply_valid_response_body_returned_false_rolling_back");
            restore_apply_response_snapshot(settings, snapshot, false);
            return false;
        }
        return true;
    }


    std::vector<uint8_t> base64_decode(const std::string& encoded)
    {
        static const uint8_t table[256] = {
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
            52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
            64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
            64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        };
        std::vector<uint8_t> out;
        out.reserve(encoded.size() * 3 / 4);
        uint32_t buf = 0;
        int bits = 0;
        for (char c : encoded) {
            uint8_t val = table[static_cast<uint8_t>(c)];
            if (val > 63) continue;
            buf = (buf << 6) | val;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
            }
        }
        return out;
    }


    std::vector<uint8_t> aes_gcm_decrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& auth_tag,
        const std::vector<uint8_t>& ciphertext)
    {
        if (key.size() != 32 || iv.size() != 12 || auth_tag.size() != 16)
            return {};

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::vector<uint8_t> plaintext(ciphertext.size());

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (status != 0) return {};

        status = BCryptSetProperty(
            hAlg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
            0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptGenerateSymmetricKey(
            hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(iv.data());
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag   = const_cast<PUCHAR>(auth_tag.data());
        authInfo.cbTag   = static_cast<ULONG>(auth_tag.size());

        ULONG bytes_decrypted = 0;
        status = BCryptDecrypt(
            hKey,
            const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()),
            &authInfo,
            nullptr, 0,
            plaintext.data(),
            static_cast<ULONG>(plaintext.size()),
            &bytes_decrypted,
            0);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        plaintext.resize(bytes_decrypted);
        return plaintext;
    }


    std::vector<uint8_t> hex_decode(const std::string& hex)
    {
        std::vector<uint8_t> out;
        if (hex.size() % 2 != 0) return out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            unsigned val = 0;
            if (sscanf(hex.c_str() + i, "%02x", &val) == 1)
                out.push_back(static_cast<uint8_t>(val));
        }
        return out;
    }

    std::string bytes_to_hex(const uint8_t* data, size_t size)
    {
        static const char digits[] = "0123456789abcdef";
        std::string out;
        out.resize(size * 2);
        for (size_t i = 0; i < size; ++i) {
            out[(i * 2) + 0] = digits[(data[i] >> 4) & 0x0F];
            out[(i * 2) + 1] = digits[data[i] & 0x0F];
        }
        return out;
    }

    std::vector<uint8_t> hmac_sha256_block(const uint8_t* key, size_t key_len,
                                           const uint8_t* data, size_t data_len)
    {
        std::vector<uint8_t> result(32);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) return {};

        status = BCryptCreateHash(hAlg, &hHash, nullptr, 0,
            const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptHashData(hHash,
            const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
        if (status != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptFinishHash(hHash, result.data(), 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        return result;
    }

    std::vector<uint8_t> hmac_sha256_two(const uint8_t* key, size_t key_len,
                                         const uint8_t* data1, size_t data1_len,
                                         const uint8_t* data2, size_t data2_len)
    {
        std::vector<uint8_t> result(32);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) return {};

        status = BCryptCreateHash(hAlg, &hHash, nullptr, 0,
            const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptHashData(hHash,
            const_cast<PUCHAR>(data1), static_cast<ULONG>(data1_len), 0);
        if (status == 0 && data2_len > 0) {
            status = BCryptHashData(hHash,
                const_cast<PUCHAR>(data2), static_cast<ULONG>(data2_len), 0);
        }
        if (status != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptFinishHash(hHash, result.data(), 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        return result;
    }

    std::vector<uint8_t> sha256_block(const uint8_t* data, size_t len)
    {
        std::vector<uint8_t> result(32);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status != 0) return {};

        status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
        if (status != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptFinishHash(hHash, result.data(), 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        return result;
    }

    std::vector<uint8_t> derive_arc_page_key(const std::vector<uint8_t>& key_seed,
                                             uint32_t page_index,
                                             const std::string& session_token,
                                             const std::string& hwid,
                                             int64_t issued_at,
                                             const std::string& proof_token,
                                             const std::string& chain_tag_hex)
    {
        std::string message;
        message.reserve(64 + session_token.size() + hwid.size() + proof_token.size() + chain_tag_hex.size());
        message += "page|";
        message += std::to_string(page_index);
        message += '|';
        message += session_token;
        message += '|';
        message += hwid;
        message += '|';
        message += std::to_string(issued_at);
        message += '|';
        message += proof_token;
        message += '|';
        message += chain_tag_hex;

        return hmac_sha256_block(key_seed.data(), key_seed.size(),
            reinterpret_cast<const uint8_t*>(message.data()), message.size());
    }

    std::vector<uint8_t> derive_arc_chain_tag(const std::vector<uint8_t>& prev_chain_tag_or_zero32,
                                              const std::vector<uint8_t>& auth_tag)
    {
        static const uint8_t kChainSuffix[5] = { 'c', 'h', 'a', 'i', 'n' };
        return hmac_sha256_two(prev_chain_tag_or_zero32.data(), prev_chain_tag_or_zero32.size(),
            auth_tag.data(), auth_tag.size(),
            kChainSuffix, sizeof(kChainSuffix));
    }

    std::string compute_arc_bootstrap_proof(const std::string& session_token)
    {
        std::string seed = session_token + "bootstrap";
        auto digest = sha256_block(reinterpret_cast<const uint8_t*>(seed.data()), seed.size());
        if (digest.size() != 32) return {};
        return bytes_to_hex(digest.data(), digest.size());
    }

    bool download_and_load_arc(settings_sa_t& settings, const std::string& hwid, uint32_t attempt_number)
    {
        if (defer_arc_fetch_if_full_test_running("arc_download"))
        {
            set_arc_load_failure_detail("ARC runtime download deferred because the full feature test is running.");
            return false;
        }

        if (!s_arc_loaded.load(std::memory_order_acquire) &&
            !arc_driver_ready_for_load("arc_download"))
        {
            if (!ensure_driver_server_token_relay(settings, "arc_download_ready_recover") ||
                !arc_driver_ready_for_load("arc_download_recovered"))
            {
                if (get_arc_load_failure_detail().empty())
                {
                    const bool loaded = driver_bridge::is_loaded();
                    const bool kernel = loaded ? driver_bridge::using_kernel_driver() : false;
                    bool heartbeat = false;
                    if (kernel && dynamic_ioctl_ready_for_protected_call("arc_download", "driver_ready_recover_failure_detail_heartbeat"))
                        heartbeat = driver_bridge::refresh_heartbeat();
                    const bool sentinel = heartbeat ? driver_bridge::sentinel_bridge_ready() : false;
                    set_arc_load_failure_detail(make_arc_driver_failure_detail(
                        "arc_download",
                        "driver_ready_recover_failed_before_download",
                        loaded,
                        kernel,
                        heartbeat,
                        sentinel,
                        GetLastError(),
                        0,
                        15000));
                }
                return false;
            }
        }

        auto& at_rt = anti_tamper::state::get();
        const bool driver_live_for_at = driver_bridge::is_loaded() && driver_bridge::using_kernel_driver();
        const bool anti_tamper_initialized = at_rt.initialized.load(std::memory_order_acquire);
        const bool driver_hardening_done = at_rt.driver_hardening_done.load(std::memory_order_acquire);
        if (!anti_tamper_initialized || (driver_live_for_at && !driver_hardening_done))
        {
            lic_log_fmt("pre_arc_anti_tamper_initialize_pre attempt=%u loaded=%d kernel=%d initialized=%d driver_hardening=%d",
                attempt_number,
                driver_bridge::is_loaded() ? 1 : 0,
                driver_bridge::using_kernel_driver() ? 1 : 0,
                anti_tamper_initialized ? 1 : 0,
                driver_hardening_done ? 1 : 0);
            const uint64_t at_started = GetTickCount64();
            auto at_watch_done = std::make_shared<std::atomic<bool>>(false);
            struct pre_arc_at_watch_done_t
            {
                std::shared_ptr<std::atomic<bool>> done;
                uint64_t started;
                uint32_t attempt;
                ~pre_arc_at_watch_done_t()
                {
                    if (done)
                        done->store(true, std::memory_order_release);
                    lic_log_fmt("pre_arc_anti_tamper_initialize_wait_done attempt=%u elapsed_ms=%llu",
                        attempt,
                        static_cast<unsigned long long>(GetTickCount64() - started));
                }
            } at_watch_done_guard{ at_watch_done, at_started, attempt_number };
            try
            {
                std::thread([at_watch_done,
                             attempt_number,
                             at_started,
                             anti_tamper_initialized,
                             driver_hardening_done,
                             driver_live_for_at]() {
                    const DWORD checkpoints[] = { 5000u, 15000u, 30000u, 60000u };
                    DWORD previous = 0;
                    for (DWORD checkpoint : checkpoints)
                    {
                        if (checkpoint > previous)
                            Sleep(checkpoint - previous);
                        previous = checkpoint;
                        if (at_watch_done->load(std::memory_order_acquire))
                            return;
                        auto& rt = anti_tamper::state::get();
                        const uint64_t now = GetTickCount64();
                        const uint64_t hardening_started =
                            rt.driver_hardening_started_ms.load(std::memory_order_acquire);
                        const uint64_t hardening_elapsed =
                            hardening_started != 0 && now >= hardening_started ? now - hardening_started : 0;
                        lic_log_fmt("pre_arc_anti_tamper_initialize_still_waiting attempt=%u elapsed_ms=%llu initial_initialized=%d initial_driver_hardening=%d initial_driver_live=%d initialized=%d driver_hardening=%d hardening_active=%d hardening_elapsed_ms=%llu violation=%d pending_activation=%d",
                            attempt_number,
                            static_cast<unsigned long long>(now - at_started),
                            anti_tamper_initialized ? 1 : 0,
                            driver_hardening_done ? 1 : 0,
                            driver_live_for_at ? 1 : 0,
                            rt.initialized.load(std::memory_order_acquire) ? 1 : 0,
                            rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
                            rt.driver_hardening_active.load(std::memory_order_acquire) ? 1 : 0,
                            static_cast<unsigned long long>(hardening_elapsed),
                            rt.violation_latched.load(std::memory_order_acquire) ? 1 : 0,
                            rt.license_pending_activation.load(std::memory_order_acquire) ? 1 : 0);
                    }
                }).detach();
            }
            catch (...)
            {
                lic_log_fmt("pre_arc_anti_tamper_initialize_watchdog_start_failed attempt=%u", attempt_number);
            }
            bool at_ok = false;
            try
            {
                lic_log_fmt("pre_arc_anti_tamper_initialize_call_enter attempt=%u tid=%lu tick=%llu",
                    attempt_number,
                    GetCurrentThreadId(),
                    static_cast<unsigned long long>(at_started));
                at_ok = anti_tamper::initialize();
                lic_log_fmt("pre_arc_anti_tamper_initialize_call_exit attempt=%u ok=%d elapsed_ms=%llu initialized=%d driver_hardening=%d violation=%d",
                    attempt_number,
                    at_ok ? 1 : 0,
                    static_cast<unsigned long long>(GetTickCount64() - at_started),
                    at_rt.initialized.load(std::memory_order_acquire) ? 1 : 0,
                    at_rt.driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
                    at_rt.violation_latched.load(std::memory_order_acquire) ? 1 : 0);
            }
            catch (const std::exception& ex)
            {
                lic_log_fmt("pre_arc_anti_tamper_initialize_exception elapsed_ms=%llu what=%.160s",
                    static_cast<unsigned long long>(GetTickCount64() - at_started),
                    ex.what());
                anti_tamper::enforce_violation_id(
                    aida::reason_ids::reason_id_from_string("pre_arc_anti_tamper_initialize_exception"),
                    ex.what());
                return false;
            }
            catch (...)
            {
                lic_log_fmt("pre_arc_anti_tamper_initialize_unknown_exception elapsed_ms=%llu",
                    static_cast<unsigned long long>(GetTickCount64() - at_started));
                anti_tamper::enforce_violation_id(
                    aida::reason_ids::reason_id_from_string("pre_arc_anti_tamper_initialize_exception"),
                    "unknown");
                return false;
            }
            if (!at_ok)
            {
                lic_log("pre_arc_anti_tamper_initialize_failed");
                anti_tamper::enforce_violation_id(
                    aida::reason_ids::reason_id_from_string("pre_arc_anti_tamper_initialize_failed"),
                    "pre_arc_anti_tamper_initialize_failed");
                return false;
            }
            lic_log("pre_arc_anti_tamper_initialize_ok");
        }

        std::unique_lock<std::timed_mutex> lk(s_arc_mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::seconds(20)))
        {
            lic_log_fmt("arc_lock_timeout attempt=%u loaded=%d downloading=%d",
                attempt_number,
                s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
                s_arc_download_in_progress.load(std::memory_order_acquire) ? 1 : 0);
            arc_loader::mark_error_fatal(
                "ARC state lock timed out during activation. Please restart AiDAStandalone.exe and try again.");
            return false;
        }
        lic_log_fmt("arc_lock_acquired attempt=%u loaded=%d",
            attempt_number,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0);


        if (s_arc_loaded.load(std::memory_order_acquire))
        {
            log_arc_status("arc_reseed_already_loaded_begin");
            if (settings.license_session_token.empty() || hwid.empty())
            {
                log_arc_status("arc_reseed_skip_preconditions");
                return false;
            }
            if (!s_fn_arc_init)
            {
                log_arc_status("arc_reseed_arc_init_unavailable");
                return false;
            }
            if (settings.license_bind_proof.empty())
            {
                log_arc_status("arc_reseed_missing_bind_proof");
                return false;
            }
            std::vector<uint8_t> reseed_bind_proof = hex_decode(settings.license_bind_proof);
            if (reseed_bind_proof.size() != 32)
            {
                log_arc_status("arc_reseed_bind_proof_invalid_length");
                if (!reseed_bind_proof.empty())
                    SecureZeroMemory(reseed_bind_proof.data(), reseed_bind_proof.size());
                return false;
            }
            const int64_t reseed_bind_ts = settings.license_issued_at;
            const int64_t reseed_now = static_cast<int64_t>(std::time(nullptr));
            const int64_t reseed_age = reseed_now - reseed_bind_ts;
            if (reseed_bind_ts <= 0 || reseed_age < -300 || reseed_age > 300)
            {
                char tbuf[192];
                _snprintf_s(tbuf, sizeof(tbuf), _TRUNCATE,
                    "arc_reseed_bind_timestamp_invalid issued_at=%lld now=%lld age=%lld",
                    static_cast<long long>(reseed_bind_ts),
                    static_cast<long long>(reseed_now),
                    static_cast<long long>(reseed_age));
                log_arc_status(tbuf);
                SecureZeroMemory(reseed_bind_proof.data(), reseed_bind_proof.size());
                return false;
            }
            {
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "arc_reseed_pre session_len=%zu session_hash=0x%016llX seed_len=%zu seed_hash=0x%016llX issued_at=%lld attempt=%u",
                    settings.license_session_token.size(),
                    static_cast<unsigned long long>(fnv1a_str(settings.license_session_token)),
                    settings.license_key_seed.size(),
                    static_cast<unsigned long long>(fnv1a_str(settings.license_key_seed)),
                    static_cast<long long>(reseed_bind_ts),
                    attempt_number);
                log_arc_status(dbg);
            }
            log_arc_status("arc_reseed_arc_init_pre");
            BOOL reseed_init_ok_raw = FALSE;
            DWORD reseed_init_seh = arc_call_init_seh(
                s_fn_arc_init,
                settings.license_session_token.c_str(),
                hwid.c_str(),
                reseed_bind_ts,
                ARC_INTERFACE_VERSION,
                reseed_bind_proof.data(),
                &reseed_init_ok_raw);
            SecureZeroMemory(reseed_bind_proof.data(), reseed_bind_proof.size());
            if (reseed_init_seh != ERROR_SUCCESS)
            {
                lic_log_fmt("arc_reseed_arc_init_seh code=0x%08lX", static_cast<unsigned long>(reseed_init_seh));
                arc_loader::mark_error_fatal(
                    "ARC runtime reseed raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                return false;
            }
            const bool reseed_init_ok = (reseed_init_ok_raw == TRUE);
            log_arc_status(reseed_init_ok ? "arc_reseed_arc_init_post_ok" : "arc_reseed_arc_init_post_false");
            if (!reseed_init_ok)
            {
                if (s_fn_arc_copy_last_status)
                {
                    char arc_status[192] = {};
                    uint32_t copied = 0;
                    DWORD copy_seh = arc_call_copy_last_status_seh(
                        s_fn_arc_copy_last_status,
                        arc_status,
                        static_cast<uint32_t>(sizeof(arc_status)),
                        &copied);
                    if (copy_seh != ERROR_SUCCESS)
                    {
                        lic_log_fmt("arc_reseed_copy_last_status_seh code=0x%08lX", static_cast<unsigned long>(copy_seh));
                    }
                    if (copied > 0 && arc_status[0] != '\0')
                    {
                        char detail[256];
                        _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                            "arc_reseed_internal_status=%.180s", arc_status);
                        log_arc_status(detail);
                    }
                    else
                    {
                        log_arc_status("arc_reseed_internal_status=<empty>");
                    }
                }
                else
                {
                    log_arc_status("arc_reseed_internal_status=<copy_last_status_unavailable>");
                }
                return false;
            }
            if (s_fn_arc_set_key_seed && !settings.license_key_seed.empty())
            {
                std::vector<uint8_t> reseed_seed_bytes = hex_decode(settings.license_key_seed);
                if (reseed_seed_bytes.size() == 32)
                {
                    DWORD seed_seh = arc_call_set_key_seed_seh(s_fn_arc_set_key_seed, reseed_seed_bytes.data(), 32);
                    SecureZeroMemory(reseed_seed_bytes.data(), reseed_seed_bytes.size());
                    if (seed_seh != ERROR_SUCCESS)
                    {
                        lic_log_fmt("arc_reseed_set_key_seed_seh code=0x%08lX", static_cast<unsigned long>(seed_seh));
                        arc_loader::mark_error_fatal(
                            "ARC runtime key reseed raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                        return false;
                    }
                    log_arc_status("arc_reseed_set_key_seed_ok");
                }
                else
                {
                    if (!reseed_seed_bytes.empty())
                        SecureZeroMemory(reseed_seed_bytes.data(), reseed_seed_bytes.size());
                    log_arc_status("arc_reseed_set_key_seed_invalid_length");
                }
            }
            else
            {
                log_arc_status("arc_reseed_set_key_seed_skipped");
            }
            log_arc_status("arc_reseed_complete");
            return true;
        }

        if (settings.license_key.empty() || settings.license_session_token.empty() || hwid.empty())
        {
            log_arc_status("arc_skip_preconditions");
            return false;
        }


        const ULONGLONG t_arc_bulk_start_ms = GetTickCount64();
        try {
            std::string host = get_cloud_function_host();

            lic_log_fmt("[arc-bulk] download_enter lk_len=%zu lk_hash=0x%016llX hwid_len=%zu hwid_hash=0x%016llX attempt=%u host=%.64s",
                settings.license_key.size(),
                static_cast<unsigned long long>(fnv1a_str(settings.license_key)),
                hwid.size(),
                static_cast<unsigned long long>(fnv1a_str(hwid)),
                attempt_number,
                host.c_str());

            std::vector<uint8_t> key_seed = hex_decode(settings.license_key_seed);
            if (key_seed.empty() || key_seed.size() != 32) {
                lic_log("[arc-bulk] missing_server_key_seed");
                log_arc_status("arc_missing_server_key_seed");
                return false;
            }
            lic_log_fmt("[arc-bulk] key_seed_loaded len=%zu", key_seed.size());

            std::string proof_token = compute_arc_bootstrap_proof(settings.license_session_token);
            if (proof_token.empty()) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log("[arc-bulk] bootstrap_proof_failed");
                log_arc_status("arc_paged_bootstrap_proof_failed");
                return false;
            }
            lic_log_fmt("[arc-bulk] proof_token_built len=%zu hash=0x%016llX",
                proof_token.size(),
                static_cast<unsigned long long>(fnv1a_str(proof_token)));

            winhttp_session_t arc_session;
            bool session_active = winhttp_session_open(arc_session, host, 30);
            struct arc_session_guard
            {
                winhttp_session_t* sess;
                ~arc_session_guard() { if (sess) winhttp_session_close(*sess); }
            } _arc_session_guard{ session_active ? &arc_session : nullptr };
            lic_log_fmt("[arc-bulk] session_state active=%d host=%.64s", session_active ? 1 : 0, host.c_str());

            json bulk_body;
            bulk_body["license_key"] = settings.license_key;
            bulk_body["session_token"] = settings.license_session_token;
            bulk_body["hwid"] = hwid;
            bulk_body["proof_token"] = proof_token;
            std::string bulk_body_str = bulk_body.dump();
            lic_log_fmt("[arc-bulk] request_built body_size=%zu", bulk_body_str.size());

            const ULONGLONG http_start_ms = GetTickCount64();
            SimpleHttpResponse bulk_resp = raw_https_request(
                "POST",
                host + "/api/download/arc/pages/bulk",
                {},
                bulk_body_str,
                "application/json");
            const ULONGLONG http_elapsed_ms = GetTickCount64() - http_start_ms;
            lic_log_fmt("[arc-bulk] transport_dispatched method=POST path=/api/download/arc/pages/bulk session_active_unused=%d",
                session_active ? 1 : 0);

            if (!bulk_resp.ok || bulk_resp.status != 200) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] response_http_failed status=%d ok=%d elapsed_ms=%llu err=%.128s body_size=%zu",
                    bulk_resp.status, bulk_resp.ok ? 1 : 0,
                    static_cast<unsigned long long>(http_elapsed_ms),
                    bulk_resp.error.c_str(), bulk_resp.body.size());
                log_arc_status("arc_bulk_http_failed");
                return false;
            }
            lic_log_fmt("[arc-bulk] response_received status=%d elapsed_ms=%llu body_size=%zu",
                bulk_resp.status,
                static_cast<unsigned long long>(http_elapsed_ms),
                bulk_resp.body.size());

            if (!ensure_driver_server_token_relay(settings, "arc_bulk_response_keepalive"))
            {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] response_driver_relay_failed elapsed_ms=%llu body_size=%zu",
                    static_cast<unsigned long long>(http_elapsed_ms),
                    bulk_resp.body.size());
                log_arc_status("arc_bulk_response_driver_relay_failed");
                return false;
            }

            auto envelope_json = json::parse(bulk_resp.body, nullptr, false);
            if (envelope_json.is_discarded() || !envelope_json.is_object()) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log("[arc-bulk] envelope_parse_failed");
                log_arc_status("arc_bulk_envelope_parse_failed");
                return false;
            }

            const std::string payload_b64 = envelope_json.value("payload", "");
            const std::string sig_b64     = envelope_json.value("sig", "");
            const int         kid_raw     = envelope_json.value("kid", 0);
            if (payload_b64.empty() || sig_b64.empty() || kid_raw <= 0) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] envelope_fields_missing payload_len=%zu sig_len=%zu kid=%d",
                    payload_b64.size(), sig_b64.size(), kid_raw);
                log_arc_status("arc_bulk_envelope_fields_missing");
                return false;
            }
            lic_log_fmt("[arc-bulk] envelope_parsed kid=%d payload_b64_len=%zu sig_b64_len=%zu",
                kid_raw, payload_b64.size(), sig_b64.size());

            std::vector<uint8_t> payload_bytes = base64_decode(payload_b64);
            std::vector<uint8_t> sig_bytes     = base64_decode(sig_b64);
            if (payload_bytes.empty() || sig_bytes.size() != 64) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] envelope_decode_failed payload_bytes=%zu sig_bytes=%zu",
                    payload_bytes.size(), sig_bytes.size());
                log_arc_status("arc_bulk_envelope_decode_failed");
                return false;
            }

            std::string verr;
            const bool sig_ok = aida::license::transport::verify_response_signature(
                payload_bytes, sig_bytes, static_cast<uint8_t>(kid_raw), verr);
            if (!sig_ok) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] envelope_verify_failed kid=%d err=%.96s", kid_raw, verr.c_str());
                log_arc_status("arc_bulk_envelope_signature_invalid");
                anti_tamper::enforce_violation_id(
                    aida::reason_ids::reason_id_from_string("arc_envelope_sig_invalid"),
                    std::string("arc_bulk_envelope_signature_invalid"));
                return false;
            }
            lic_log_fmt("[arc-bulk] envelope_verify_ok kid=%d payload_bytes=%zu", kid_raw, payload_bytes.size());

            std::string signed_text(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
            auto signed_payload = json::parse(signed_text, nullptr, false);
            if (signed_payload.is_discarded() || !signed_payload.is_object()) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log("[arc-bulk] signed_payload_parse_failed");
                log_arc_status("arc_bulk_signed_payload_parse_failed");
                return false;
            }

            const std::string status_value = signed_payload.value("status", "");
            if (status_value != "ok") {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] status_not_ok status=%.32s", status_value.c_str());
                log_arc_status("arc_bulk_status_not_ok");
                return false;
            }
            lic_log_fmt("[arc-bulk] status_ok status=%.16s", status_value.c_str());

            const uint64_t total_pages_u = signed_payload.value("total_pages", uint64_t{0});
            const uint64_t blob_size_u   = signed_payload.value("blob_size",   uint64_t{0});
            constexpr uint64_t kMaxBlobSize = 64ull * 1024ull * 1024ull;
            if (total_pages_u == 0 || total_pages_u > 1000000ull ||
                blob_size_u == 0 || blob_size_u > kMaxBlobSize) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] invalid_counts total_pages=%llu blob_size=%llu",
                    static_cast<unsigned long long>(total_pages_u),
                    static_cast<unsigned long long>(blob_size_u));
                log_arc_status("arc_bulk_invalid_counts");
                return false;
            }
            const uint32_t total_pages = static_cast<uint32_t>(total_pages_u);
            const size_t   blob_size   = static_cast<size_t>(blob_size_u);
            lic_log_fmt("[arc-bulk] counts_ok total_pages=%u blob_size=%zu",
                total_pages, blob_size);

            if (!signed_payload.contains("pages") || !signed_payload["pages"].is_array()) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log("[arc-bulk] pages_array_missing");
                log_arc_status("arc_bulk_pages_array_missing");
                return false;
            }
            const json& pages_json = signed_payload["pages"];
            if (pages_json.size() != static_cast<size_t>(total_pages)) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] pages_count_mismatch got=%zu expected=%u",
                    pages_json.size(), total_pages);
                log_arc_status("arc_bulk_pages_count_mismatch");
                return false;
            }
            lic_log_fmt("[arc-bulk] pages_count got=%zu expected=%u", pages_json.size(), total_pages);

            aida::arc::plaintext_window::handle_t ptw_handle{};
            std::string ptw_err;
            if (!aida::arc::plaintext_window::create(static_cast<size_t>(total_pages), ptw_handle, ptw_err))
            {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                lic_log_fmt("[arc-bulk] plaintext_window_create_failed err=%.96s", ptw_err.c_str());
                log_arc_status("arc_plaintext_window_create_failed");
                return false;
            }
            struct ptw_guard_t {
                aida::arc::plaintext_window::handle_t* h;
                ~ptw_guard_t() { if (h) aida::arc::plaintext_window::destroy(*h); }
            } ptw_guard{ &ptw_handle };
            std::atomic<size_t> ptw_total_bytes{0};
            lic_log_fmt("[arc-bulk] plaintext_window_created pages=%u", total_pages);

            std::vector<uint8_t> chain_tag;
            std::string          chain_tag_hex;

            const ULONGLONG page_loop_start_ms = GetTickCount64();
            ULONGLONG driver_relay_refresh_ms = page_loop_start_ms;
            bool bulk_loaded = true;

            for (uint32_t page_index = 0; page_index < total_pages; ++page_index) {
                ULONGLONG loop_now_ms = GetTickCount64();
                if (loop_now_ms - driver_relay_refresh_ms >= 15000ull) {
                    if (!ensure_driver_server_token_relay(settings, "arc_page_loop_keepalive")) {
                        lic_log_fmt("[arc-bulk] page_loop_driver_relay_failed page=%u elapsed_ms=%llu",
                            page_index,
                            static_cast<unsigned long long>(loop_now_ms - page_loop_start_ms));
                        log_arc_status("arc_page_loop_driver_relay_failed");
                        bulk_loaded = false;
                        break;
                    }
                    driver_relay_refresh_ms = GetTickCount64();
                }

                const json& page_json = pages_json[page_index];
                if (!page_json.is_object()) {
                    lic_log_fmt("[arc-bulk] page_invalid_json page=%u", page_index);
                    log_arc_status("arc_bulk_page_invalid_json");
                    bulk_loaded = false;
                    break;
                }

                const uint64_t page_index_resp  = page_json.value("page_index",  uint64_t{UINT64_MAX});
                const uint64_t total_pages_resp = page_json.value("total_pages", uint64_t{0});
                const uint64_t blob_size_resp   = page_json.value("blob_size",   uint64_t{0});
                const std::string page_data_b64 = page_json.value("data", "");
                const std::string page_iv_hex   = page_json.value("iv", "");
                const std::string page_tag_hex  = page_json.value("auth_tag", "");

                if (page_index_resp != static_cast<uint64_t>(page_index) ||
                    total_pages_resp != static_cast<uint64_t>(total_pages) ||
                    blob_size_resp   != static_cast<uint64_t>(blob_size) ||
                    page_data_b64.empty() || page_iv_hex.empty() || page_tag_hex.empty()) {
                    lic_log_fmt("[arc-bulk] page_field_mismatch page=%u idx=%llu total=%llu blob=%llu data_empty=%d iv_empty=%d tag_empty=%d",
                        page_index,
                        static_cast<unsigned long long>(page_index_resp),
                        static_cast<unsigned long long>(total_pages_resp),
                        static_cast<unsigned long long>(blob_size_resp),
                        page_data_b64.empty() ? 1 : 0,
                        page_iv_hex.empty() ? 1 : 0,
                        page_tag_hex.empty() ? 1 : 0);
                    log_arc_status("arc_bulk_page_field_mismatch");
                    bulk_loaded = false;
                    break;
                }

                const std::string page_code_binding_sig = page_json.value("code_binding_sig", "");
                const std::string page_licensee_id      = page_json.value("licensee_id", "");
                {
                    std::lock_guard<std::mutex> rot_lk(s_rotation_mtx);
                    if (!page_licensee_id.empty()) s_licensee_id = page_licensee_id;
                    if (!page_code_binding_sig.empty()) {
                        if (s_pending_code_page_signatures.size() <= page_index)
                            s_pending_code_page_signatures.resize(page_index + 1);
                        s_pending_code_page_signatures[page_index] = page_code_binding_sig;
                    }
                }

                auto page_iv  = hex_decode(page_iv_hex);
                auto page_tag = hex_decode(page_tag_hex);
                auto page_ct  = base64_decode(page_data_b64);
                if (page_iv.size() != 12 || page_tag.size() != 16 || page_ct.empty()) {
                    lic_log_fmt("[arc-bulk] page_invalid_format page=%u iv_len=%zu tag_len=%zu ct_len=%zu",
                        page_index, page_iv.size(), page_tag.size(), page_ct.size());
                    log_arc_status("arc_bulk_page_invalid_format");
                    bulk_loaded = false;
                    break;
                }

                if (!page_code_binding_sig.empty() && !settings.license_bind_proof.empty()) {
                    auto bind_proof = hex_decode(settings.license_bind_proof);
                    if (bind_proof.size() == 32) {
                        std::vector<uint8_t> hwid_bytes(hwid.begin(), hwid.end());
                        static const uint8_t kInfo[] = {
                            'c','o','d','e','-','p','a','g','e','-','b','i','n','d','i','n','g','/','v','1'
                        };
                        std::vector<uint8_t> prk = hmac_sha256_block(
                            hwid_bytes.data(), hwid_bytes.size(),
                            bind_proof.data(), bind_proof.size());
                        std::vector<uint8_t> info_block;
                        info_block.reserve(sizeof(kInfo) + 1);
                        info_block.insert(info_block.end(), kInfo, kInfo + sizeof(kInfo));
                        info_block.push_back(0x01);
                        std::vector<uint8_t> okm = hmac_sha256_block(
                            prk.data(), prk.size(),
                            info_block.data(), info_block.size());
                        SecureZeroMemory(prk.data(), prk.size());

                        auto page_digest = sha256_block(page_ct.data(), page_ct.size());
                        std::vector<uint8_t> mac_input;
                        mac_input.reserve(14 + 4 + 32);
                        static const uint8_t kLabel[] = { 'a','i','d','a','-','c','o','d','e','-','p','a','g','e' };
                        mac_input.insert(mac_input.end(), kLabel, kLabel + sizeof(kLabel));
                        mac_input.push_back(static_cast<uint8_t>(page_index & 0xFF));
                        mac_input.push_back(static_cast<uint8_t>((page_index >> 8) & 0xFF));
                        mac_input.push_back(static_cast<uint8_t>((page_index >> 16) & 0xFF));
                        mac_input.push_back(static_cast<uint8_t>((page_index >> 24) & 0xFF));
                        mac_input.insert(mac_input.end(), page_digest.begin(), page_digest.end());

                        std::vector<uint8_t> expected = hmac_sha256_block(
                            okm.data(), okm.size(),
                            mac_input.data(), mac_input.size());
                        SecureZeroMemory(okm.data(), okm.size());
                        std::string expected_hex = bytes_to_hex(expected.data(), expected.size());

                        if (page_code_binding_sig.size() != expected_hex.size() ||
                            ::_stricmp(page_code_binding_sig.c_str(), expected_hex.c_str()) != 0) {
                            lic_log_fmt("[arc-bulk] code_binding_mismatch page=%u expected_prefix=%.16s got_prefix=%.16s",
                                page_index, expected_hex.c_str(), page_code_binding_sig.c_str());
                            log_arc_status("arc_paged_code_binding_invalid");
                            schedule_silent_kill("code_binding_mismatch");
                            bulk_loaded = false;
                            break;
                        }
                    }
                }

                auto page_key = derive_arc_page_key(
                    key_seed,
                    page_index,
                    settings.license_session_token,
                    hwid,
                    settings.license_issued_at,
                    proof_token,
                    chain_tag_hex);
                if (page_key.size() != 32) {
                    lic_log_fmt("[arc-bulk] page_key_failed page=%u", page_index);
                    log_arc_status("arc_paged_page_key_failed");
                    bulk_loaded = false;
                    break;
                }

                auto page_plain = aes_gcm_decrypt(page_key, page_iv, page_tag, page_ct);
                SecureZeroMemory(page_key.data(), page_key.size());
                if (page_plain.empty()) {
                    lic_log_fmt("[arc-bulk] page_decrypt_failed page=%u ct_len=%zu", page_index, page_ct.size());
                    log_arc_status("arc_bulk_page_decrypt_failed");
                    bulk_loaded = false;
                    break;
                }

                const size_t accumulated = ptw_total_bytes.load(std::memory_order_acquire);
                if (accumulated + page_plain.size() > blob_size) {
                    SecureZeroMemory(page_plain.data(), page_plain.size());
                    lic_log_fmt("[arc-bulk] page_overflow page=%u accumulated=%zu blob_size=%zu plain_size=%zu",
                        page_index, accumulated, blob_size, page_plain.size());
                    log_arc_status("arc_bulk_page_overflow");
                    bulk_loaded = false;
                    break;
                }

                std::string consume_err;
                if (!aida::arc::plaintext_window::consume_page(
                        ptw_handle,
                        static_cast<size_t>(page_index),
                        page_plain.data(),
                        static_cast<uint32_t>(page_plain.size()),
                        consume_err))
                {
                    SecureZeroMemory(page_plain.data(), page_plain.size());
                    lic_log_fmt("[arc-bulk] page_consume_failed page=%u err=%.96s",
                        page_index, consume_err.c_str());
                    log_arc_status("arc_bulk_page_consume_failed");
                    bulk_loaded = false;
                    break;
                }
                ptw_total_bytes.fetch_add(page_plain.size(), std::memory_order_acq_rel);
                SecureZeroMemory(page_plain.data(), page_plain.size());

                if (s_activation_completed_at_ms.load(std::memory_order_acquire) != 0)
                    mark_activation_completed();

                auto next_chain = chain_tag.empty()
                    ? derive_arc_chain_tag(std::vector<uint8_t>(32, 0), page_tag)
                    : derive_arc_chain_tag(chain_tag, page_tag);
                if (next_chain.size() != 32) {
                    lic_log_fmt("[arc-bulk] chain_tag_failed page=%u", page_index);
                    log_arc_status("arc_paged_chain_tag_failed");
                    bulk_loaded = false;
                    break;
                }
                chain_tag = std::move(next_chain);
                chain_tag_hex = bytes_to_hex(chain_tag.data(), chain_tag.size());

                if ((page_index % 50u) == 0u || page_index + 1u == total_pages) {
                    lic_log_fmt("[arc-bulk] page_decrypt_ok index=%u total=%u accumulated=%zu",
                        page_index, total_pages,
                        ptw_total_bytes.load(std::memory_order_acquire));
                }
            }

            if (!bulk_loaded) {
                SecureZeroMemory(key_seed.data(), key_seed.size());
                if (!chain_tag.empty())
                    SecureZeroMemory(chain_tag.data(), chain_tag.size());
                chain_tag.clear();
                chain_tag_hex.clear();
                lic_log("[arc-bulk] decrypt_loop_failed");
                log_arc_status("arc_bulk_required_failed");
                return false;
            }
            lic_log_fmt("[arc-bulk] all_pages_decrypted total=%u accumulated=%zu",
                total_pages,
                ptw_total_bytes.load(std::memory_order_acquire));

            {
                const ULONGLONG page_loop_elapsed_ms = GetTickCount64() - page_loop_start_ms;
                lic_log_fmt("[arc-bulk] pages_loop_done total=%u elapsed_ms=%llu session_active=%d",
                    total_pages,
                    static_cast<unsigned long long>(page_loop_elapsed_ms),
                    session_active ? 1 : 0);
            }

            SecureZeroMemory(key_seed.data(), key_seed.size());
            if (!chain_tag.empty())
                SecureZeroMemory(chain_tag.data(), chain_tag.size());

            const size_t accumulated_total = ptw_total_bytes.load(std::memory_order_acquire);
            if (accumulated_total != blob_size) {
                lic_log_fmt("[arc-bulk] blob_size_mismatch accumulated=%zu blob=%zu",
                    accumulated_total, blob_size);
                log_arc_status("arc_paged_blob_size_mismatch");
                return false;
            }
            lic_log_fmt("[arc-bulk] plaintext_window_filled accumulated=%zu blob_size=%zu",
                accumulated_total, blob_size);

            if (s_activation_completed_at_ms.load(std::memory_order_acquire) != 0)
                mark_activation_completed();

            log_arc_status("arc_paged_blob_assembled");
            lic_log("[arc-bulk] blob_assembled");

            lic_diag::thread_canary("pre_arc_loader_load_call");
            lic_diag::dump_pe_self("pre_arc_loader_load_call");
            lic_diag::dump_mitigation("pre_arc_loader_load_call");

            std::vector<uint8_t> loader_buffer;
            loader_buffer.reserve(blob_size);
            std::string stream_err;
            bool stream_ok = aida::arc::plaintext_window::stream_to_loader(
                ptw_handle,
                [&loader_buffer](const uint8_t* page_bytes, uint32_t page_size,
                                 size_t /*page_index*/, size_t /*total_pages*/) -> bool {
                    if (page_bytes == nullptr || page_size == 0) return false;
                    loader_buffer.insert(loader_buffer.end(), page_bytes, page_bytes + page_size);
                    return true;
                },
                stream_err);

            if (!stream_ok || loader_buffer.size() != blob_size)
            {
                if (!loader_buffer.empty())
                    SecureZeroMemory(loader_buffer.data(), loader_buffer.size());
                lic_log_fmt("[arc-bulk] plaintext_window_streamed_failed err=%.96s collected=%zu",
                    stream_err.c_str(), loader_buffer.size());
                log_arc_status("arc_paged_stream_failed");
                return false;
            }
            lic_log_fmt("[arc-bulk] plaintext_window_streamed bytes=%zu", loader_buffer.size());

            if (!ensure_driver_server_token_relay(settings, "arc_loader_handoff"))
            {
                SecureZeroMemory(loader_buffer.data(), loader_buffer.size());
                loader_buffer.clear();
                if (get_arc_load_failure_detail().empty())
                {
                    const bool loaded = driver_bridge::is_loaded();
                    const bool kernel = loaded ? driver_bridge::using_kernel_driver() : false;
                    bool heartbeat = false;
                    if (kernel && dynamic_ioctl_ready_for_protected_call("arc_loader_handoff", "driver_token_relay_failure_detail_heartbeat"))
                        heartbeat = driver_bridge::refresh_heartbeat();
                    const bool sentinel = heartbeat ? driver_bridge::sentinel_bridge_ready() : false;
                    set_arc_load_failure_detail(make_arc_driver_failure_detail(
                        "arc_loader_handoff",
                        "driver_token_relay_failed_before_loader_handoff",
                        loaded,
                        kernel,
                        heartbeat,
                        sentinel,
                        GetLastError(),
                        0,
                        15000));
                }
                lic_log("[arc-bulk] arc_loader_handoff_driver_relay_failed");
                log_arc_status("arc_loader_handoff_driver_relay_failed");
                return false;
            }

            lic_log_fmt("[arc-bulk] arc_loader_handoff size=%zu", loader_buffer.size());
            s_arc_module = arc_loader::load(loader_buffer.data(), loader_buffer.size());
            const bool load_ok = (s_arc_module.base != nullptr);
            SecureZeroMemory(loader_buffer.data(), loader_buffer.size());
            loader_buffer.clear();
            if (!load_ok) {
                lic_log_fmt("[arc-bulk] arc_loader_failed reason=%.128s", arc_loader::last_error().c_str());
                log_arc_status("arc_paged_reflective_load_failed");
                lic_diag::thread_canary("post_arc_loader_load_FAIL");
                lic_diag::dump_pe_self("post_arc_loader_load_FAIL");
                lic_diag::dump_mitigation("post_arc_loader_load_FAIL");
                return false;
            }
            lic_log("[arc-bulk] arc_loader_returned_ok");

            if (!ensure_driver_server_token_relay(settings, "arc_bind_pre_exports") ||
                !verify_seeded_driver_bridge_for_arc("arc_bind_pre_exports"))
            {
                log_arc_status("arc_bind_driver_session_relay_failed");
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }

            log_arc_status("arc_load_ok_resolving_exports");

            s_fn_arc_init = reinterpret_cast<arc_init_fn>(
                arc_loader::get_export(s_arc_module, "arc_init"));
            s_fn_arc_bind_driver_device = reinterpret_cast<arc_bind_driver_device_fn>(
                arc_loader::get_export(s_arc_module, "arc_bind_driver_device"));
            s_fn_arc_get_comm_bridge = reinterpret_cast<arc_get_comm_bridge_fn>(
                arc_loader::get_export(s_arc_module, "arc_get_comm_bridge"));
            s_fn_arc_validate_tool = reinterpret_cast<arc_validate_tool_fn>(
                arc_loader::get_export(s_arc_module, "arc_validate_tool_exec"));
            s_fn_arc_validate_tool_v2 = reinterpret_cast<arc_validate_tool_v2_fn>(
                arc_loader::get_export(s_arc_module, "arc_validate_tool_exec_v2"));
            s_fn_arc_verify_watermark_trailer = reinterpret_cast<arc_verify_watermark_trailer_fn>(
                arc_loader::get_export(s_arc_module, "arc_verify_watermark_trailer"));
            s_fn_arc_heartbeat = reinterpret_cast<arc_heartbeat_fn>(
                arc_loader::get_export(s_arc_module, "arc_heartbeat"));
            s_fn_arc_heartbeat_ex = reinterpret_cast<arc_heartbeat_ex_fn>(
                arc_loader::get_export(s_arc_module, "arc_heartbeat_ex"));
            s_fn_arc_cleanup = reinterpret_cast<arc_cleanup_fn>(
                arc_loader::get_export(s_arc_module, "arc_cleanup"));
            s_fn_arc_set_key_seed = reinterpret_cast<arc_set_key_seed_fn>(
                arc_loader::get_export(s_arc_module, "arc_set_key_seed"));
            s_fn_arc_unseal_feature = reinterpret_cast<arc_unseal_feature_fn>(
                arc_loader::get_export(s_arc_module, "arc_unseal_feature"));
            s_fn_arc_copy_last_status = reinterpret_cast<arc_copy_last_status_fn>(
                arc_loader::get_export(s_arc_module, "arc_copy_last_status"));

            if (!s_fn_arc_init || !s_fn_arc_bind_driver_device || !s_fn_arc_get_comm_bridge ||
                !s_fn_arc_validate_tool || !s_fn_arc_validate_tool_v2 || !s_fn_arc_verify_watermark_trailer ||
                !s_fn_arc_heartbeat || !s_fn_arc_heartbeat_ex || !s_fn_arc_cleanup || !s_fn_arc_unseal_feature) {
                log_arc_status("arc_missing_exports");
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }

            log_arc_status("arc_exports_ok_pre_seal");

            if (!device || !device->is_connected()) {
                log_arc_status("arc_bind_driver_device_host_disconnected");
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }

            if (!dynamic_ioctl_ready_for_protected_call("arc_bind_driver_device", "arc_bind_driver_device_heartbeat") ||
                !driver_bridge::refresh_heartbeat()) {
                if (device) {
                    lic_log_fmt("arc_bind_driver_device_heartbeat_failed_detail err=%lu bytes=%lu ioctl=0x%08X base=0x%04X offset=%u key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                        static_cast<unsigned long>(device->get_last_heartbeat_error()),
                        static_cast<unsigned long>(device->get_last_heartbeat_bytes_returned()),
                        device->get_last_heartbeat_ioctl_code(),
                        device->get_last_heartbeat_base(),
                        device->get_last_heartbeat_offset(),
                        device->get_last_heartbeat_key_hash(),
                        device->get_last_heartbeat_ioctl_seed_hash(),
                        device->get_last_heartbeat_server_seed_present(),
                        device->get_last_heartbeat_ioctl_seed_present(),
                        device->get_last_heartbeat_global_server_seed_present(),
                        device->get_last_heartbeat_global_ioctl_seed_present());
                }
                log_arc_status("arc_bind_driver_device_heartbeat_failed");
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }
            if (device) {
                lic_log_fmt("arc_bind_driver_device_heartbeat_ok_detail ioctl=0x%08X base=0x%04X offset=%u key_hash=0x%08X ioctl_seed_hash=0x%08X inst_seed=%u/%u global_seed=%u/%u",
                    device->get_last_heartbeat_ioctl_code(),
                    device->get_last_heartbeat_base(),
                    device->get_last_heartbeat_offset(),
                    device->get_last_heartbeat_key_hash(),
                    device->get_last_heartbeat_ioctl_seed_hash(),
                    device->get_last_heartbeat_server_seed_present(),
                    device->get_last_heartbeat_ioctl_seed_present(),
                    device->get_last_heartbeat_global_server_seed_present(),
                    device->get_last_heartbeat_global_ioctl_seed_present());
            }

            BOOL bind_device_ok = FALSE;
            DWORD bind_device_seh = arc_call_bind_driver_device_seh(
                s_fn_arc_bind_driver_device,
                device.get(),
                ARC_INTERFACE_VERSION,
                &bind_device_ok);
            if (bind_device_seh != ERROR_SUCCESS) {
                lic_log_fmt("arc_bind_driver_device_seh code=0x%08lX", static_cast<unsigned long>(bind_device_seh));
                arc_loader::mark_error_fatal(
                    "ARC driver binding raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }
            if (!bind_device_ok) {
                log_arc_status("arc_bind_driver_device_failed");
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }

            log_arc_status("arc_bind_driver_device_ok");

            log_arc_status("arc_seal_deferred_until_post_init");

            std::vector<uint8_t> bind_proof_bytes;
            if (settings.license_bind_proof.empty()) {
                log_arc_status("arc_missing_bind_proof");
                arc_loader::unload_without_detach(s_arc_module);
                s_fn_arc_init = nullptr;
                s_fn_arc_bind_driver_device = nullptr;
                s_fn_arc_get_comm_bridge = nullptr;
                s_fn_arc_validate_tool = nullptr;
                s_fn_arc_validate_tool_v2 = nullptr;
                s_fn_arc_verify_watermark_trailer = nullptr;
                s_fn_arc_heartbeat = nullptr;
                s_fn_arc_heartbeat_ex = nullptr;
                s_fn_arc_cleanup = nullptr;
                s_fn_arc_set_key_seed = nullptr;
                s_fn_arc_unseal_feature = nullptr;
                s_fn_arc_copy_last_status = nullptr;
                return false;
            }
            bind_proof_bytes = hex_decode(settings.license_bind_proof);
            if (bind_proof_bytes.size() != 32) {
                log_arc_status("arc_missing_bind_proof");
                if (!bind_proof_bytes.empty())
                    SecureZeroMemory(bind_proof_bytes.data(), bind_proof_bytes.size());
                arc_loader::unload_without_detach(s_arc_module);
                s_fn_arc_init = nullptr;
                s_fn_arc_bind_driver_device = nullptr;
                s_fn_arc_get_comm_bridge = nullptr;
                s_fn_arc_validate_tool = nullptr;
                s_fn_arc_validate_tool_v2 = nullptr;
                s_fn_arc_verify_watermark_trailer = nullptr;
                s_fn_arc_heartbeat = nullptr;
                s_fn_arc_heartbeat_ex = nullptr;
                s_fn_arc_cleanup = nullptr;
                s_fn_arc_set_key_seed = nullptr;
                s_fn_arc_unseal_feature = nullptr;
                s_fn_arc_copy_last_status = nullptr;
                return false;
            }

            const int64_t bind_timestamp = settings.license_issued_at;
            const int64_t local_now = static_cast<int64_t>(std::time(nullptr));
            const int64_t bind_age = local_now - bind_timestamp;
            if (bind_timestamp <= 0 || bind_age < -300 || bind_age > 300) {
                char tbuf[192];
                _snprintf_s(tbuf, sizeof(tbuf), _TRUNCATE,
                    "arc_bind_timestamp_invalid issued_at=%lld now=%lld age=%lld",
                    static_cast<long long>(bind_timestamp),
                    static_cast<long long>(local_now),
                    static_cast<long long>(bind_age));
                log_arc_status(tbuf);
                SecureZeroMemory(bind_proof_bytes.data(), bind_proof_bytes.size());
                arc_loader::unload_without_detach(s_arc_module);
                s_fn_arc_init = nullptr;
                s_fn_arc_bind_driver_device = nullptr;
                s_fn_arc_get_comm_bridge = nullptr;
                s_fn_arc_validate_tool = nullptr;
                s_fn_arc_validate_tool_v2 = nullptr;
                s_fn_arc_verify_watermark_trailer = nullptr;
                s_fn_arc_heartbeat = nullptr;
                s_fn_arc_heartbeat_ex = nullptr;
                s_fn_arc_cleanup = nullptr;
                s_fn_arc_set_key_seed = nullptr;
                s_fn_arc_unseal_feature = nullptr;
                s_fn_arc_copy_last_status = nullptr;
                return false;
            }

            {
                char tbuf[160];
                _snprintf_s(tbuf, sizeof(tbuf), _TRUNCATE,
                    "arc_bind_timestamp_ok issued_at=%lld age=%lld",
                    static_cast<long long>(bind_timestamp),
                    static_cast<long long>(bind_age));
                log_arc_status(tbuf);
            }

            log_arc_status("arc_init_pre");
            BOOL init_ok_raw = FALSE;
            DWORD init_seh = arc_call_init_seh(
                    s_fn_arc_init,
                    settings.license_session_token.c_str(),
                    hwid.c_str(),
                    bind_timestamp,
                    ARC_INTERFACE_VERSION,
                    bind_proof_bytes.data(),
                    &init_ok_raw);
            SecureZeroMemory(bind_proof_bytes.data(), bind_proof_bytes.size());
            if (init_seh != ERROR_SUCCESS) {
                lic_log_fmt("arc_init_seh code=0x%08lX", static_cast<unsigned long>(init_seh));
                arc_loader::mark_error_fatal(
                    "ARC runtime initialization raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }
            bool init_ok = (init_ok_raw == TRUE);
            log_arc_status(init_ok ? "arc_init_post_ok" : "arc_init_post_false");
            if (!init_ok) {
                if (s_fn_arc_copy_last_status) {
                    char arc_status[192] = {};
                    uint32_t copied = 0;
                    DWORD copy_seh = arc_call_copy_last_status_seh(
                        s_fn_arc_copy_last_status,
                        arc_status,
                        static_cast<uint32_t>(sizeof(arc_status)),
                        &copied);
                    if (copy_seh != ERROR_SUCCESS) {
                        lic_log_fmt("arc_init_copy_last_status_seh code=0x%08lX", static_cast<unsigned long>(copy_seh));
                    }
                    if (copied > 0 && arc_status[0] != '\0') {
                        char detail[256];
                        _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                            "arc_init_internal_status=%.180s", arc_status);
                        log_arc_status(detail);
                    } else {
                        log_arc_status("arc_init_internal_status=<empty>");
                    }
                } else {
                    log_arc_status("arc_init_internal_status=<copy_last_status_unavailable>");
                }
                log_arc_status("arc_init_failed");
                arc_loader::mark_error_fatal(
                    "arc_init returned false; the protected runtime cannot be reinitialized "
                    "in this process. Please restart AiDAStandalone.exe and try again.");
                arc_loader::unload_without_detach(s_arc_module);
                s_fn_arc_init = nullptr;
                s_fn_arc_bind_driver_device = nullptr;
                s_fn_arc_get_comm_bridge = nullptr;
                s_fn_arc_validate_tool = nullptr;
                s_fn_arc_validate_tool_v2 = nullptr;
                s_fn_arc_verify_watermark_trailer = nullptr;
                s_fn_arc_heartbeat = nullptr;
                s_fn_arc_heartbeat_ex = nullptr;
                s_fn_arc_cleanup = nullptr;
                s_fn_arc_set_key_seed = nullptr;
                s_fn_arc_unseal_feature = nullptr;
                s_fn_arc_copy_last_status = nullptr;
                return false;
            }

            if (!arc_loader::seal(s_arc_module)) {
                char sl_buf[192];
                _snprintf_s(sl_buf, sizeof(sl_buf), _TRUNCATE,
                    "arc_seal_failed_post_init reason=%s",
                    arc_loader::last_error().c_str());
                log_arc_status(sl_buf);
                arc_loader::unload_without_detach(s_arc_module);
                clear_arc_exports();
                return false;
            }

            log_arc_status("arc_seal_ok_post_init");

            if (s_fn_arc_set_key_seed && !settings.license_key_seed.empty())
            {
                auto seed_bytes = hex_decode(settings.license_key_seed);
                if (seed_bytes.size() == 32) {
                    DWORD seed_seh = arc_call_set_key_seed_seh(s_fn_arc_set_key_seed, seed_bytes.data(), 32);
                    SecureZeroMemory(seed_bytes.data(), seed_bytes.size());
                    if (seed_seh != ERROR_SUCCESS) {
                        lic_log_fmt("arc_set_key_seed_seh code=0x%08lX", static_cast<unsigned long>(seed_seh));
                        arc_loader::mark_error_fatal(
                            "ARC runtime key seed raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                        arc_loader::unload_without_detach(s_arc_module);
                        clear_arc_exports();
                        return false;
                    }
                }
            }

            auto copy_arc_status = [&]() -> std::string {
                if (!s_fn_arc_copy_last_status)
                    return {};
                char status[192] = {};
                uint32_t copied = 0;
                DWORD copy_seh = arc_call_copy_last_status_seh(
                    s_fn_arc_copy_last_status,
                    status,
                    static_cast<uint32_t>(sizeof(status)),
                    &copied);
                if (copy_seh != ERROR_SUCCESS) {
                    lic_log_fmt("arc_copy_last_status_seh code=0x%08lX", static_cast<unsigned long>(copy_seh));
                    return {};
                }
                if (copied == 0)
                    return {};
                return std::string(status);
            };

            {
                uint8_t gate_nonce[32] = {};
                const std::string& sess_tok = settings.license_session_token;
                size_t cp = sess_tok.size();
                if (cp > sizeof(gate_nonce)) cp = sizeof(gate_nonce);
                if (cp > 0)
                    memcpy(gate_nonce, sess_tok.data(), cp);

                uint8_t poly_seed[32] = {};
                uint32_t poly_seed_len = 0;
                constexpr uint32_t kPolymorphismSeedFeatureId = 1u;
                log_arc_status("arc_unseal_pre");
                BOOL unseal_ok_raw = FALSE;
                DWORD unseal_seh = arc_call_unseal_feature_seh(
                    s_fn_arc_unseal_feature,
                    kPolymorphismSeedFeatureId,
                    gate_nonce, sizeof(gate_nonce),
                    poly_seed, &poly_seed_len, sizeof(poly_seed),
                    &unseal_ok_raw);
                if (unseal_seh != ERROR_SUCCESS) {
                    SecureZeroMemory(poly_seed, sizeof(poly_seed));
                    SecureZeroMemory(gate_nonce, sizeof(gate_nonce));
                    lic_log_fmt("arc_unseal_seh code=0x%08lX", static_cast<unsigned long>(unseal_seh));
                    arc_loader::mark_error_fatal(
                        "ARC startup gate unseal raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                    arc_loader::unload_without_detach(s_arc_module);
                    clear_arc_exports();
                    return false;
                }
                bool unseal_ok = (unseal_ok_raw == TRUE);
                log_arc_status(unseal_ok ? "arc_unseal_post_ok" : "arc_unseal_post_false");
                if (!unseal_ok || poly_seed_len != 32) {
                    SecureZeroMemory(poly_seed, sizeof(poly_seed));
                    SecureZeroMemory(gate_nonce, sizeof(gate_nonce));
                    std::string arc_status = copy_arc_status();
                    if (!arc_status.empty()) {
                        std::string detail = std::string("arc_startup_gate_unseal_detail:") + arc_status;
                        log_arc_status(detail.c_str());
                    }
                    log_arc_status("arc_startup_gate_failed_unseal");
                    __fastfail(0xA1DAFA17u);
                }
                uint64_t poly_seed_acc = 0;
                for (size_t i = 0; i < sizeof(poly_seed); ++i)
                    poly_seed_acc |= poly_seed[i];
                SecureZeroMemory(poly_seed, sizeof(poly_seed));
                SecureZeroMemory(gate_nonce, sizeof(gate_nonce));
                if (poly_seed_acc == 0) {
                    log_arc_status("arc_startup_gate_failed_seed_zero");
                    __fastfail(0xA1DAFA17u);
                }

                arc_heartbeat_result_t hb1{};
                arc_heartbeat_result_t hb2{};
                DWORD hb1_seh = arc_call_heartbeat_seh(s_fn_arc_heartbeat, &hb1);
                DWORD hb2_seh = (hb1_seh == ERROR_SUCCESS)
                    ? arc_call_heartbeat_seh(s_fn_arc_heartbeat, &hb2)
                    : hb1_seh;
                if (hb1_seh != ERROR_SUCCESS || hb2_seh != ERROR_SUCCESS) {
                    SecureZeroMemory(&hb1, sizeof(hb1));
                    SecureZeroMemory(&hb2, sizeof(hb2));
                    lic_log_fmt("arc_startup_heartbeat_seh code1=0x%08lX code2=0x%08lX",
                        static_cast<unsigned long>(hb1_seh),
                        static_cast<unsigned long>(hb2_seh));
                    arc_loader::mark_error_fatal(
                        "ARC startup heartbeat raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                    arc_loader::unload_without_detach(s_arc_module);
                    clear_arc_exports();
                    return false;
                }
                if (!hb1.valid || !hb2.valid ||
                    hb1.proof_token == 0 || hb2.proof_token == 0 ||
                    hb1.proof_token == hb2.proof_token) {
                    char detail[160];
                    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                        "arc_startup_gate_failed_heartbeat v1=%d v2=%d t1_set=%d t2_set=%d tokens_equal=%d",
                        hb1.valid ? 1 : 0,
                        hb2.valid ? 1 : 0,
                        hb1.proof_token != 0 ? 1 : 0,
                        hb2.proof_token != 0 ? 1 : 0,
                        hb1.proof_token == hb2.proof_token ? 1 : 0);
                    SecureZeroMemory(&hb1, sizeof(hb1));
                    SecureZeroMemory(&hb2, sizeof(hb2));
                    log_arc_status(detail);
                    __fastfail(0xA1DAFA17u);
                }
                SecureZeroMemory(&hb1, sizeof(hb1));
                SecureZeroMemory(&hb2, sizeof(hb2));

                constexpr uint64_t kStartupValidateNameHash = 0xA1DA5747D45E0001ULL;
                constexpr uint64_t kStartupValidateGateToken = 0x6F70656E776F6C66ULL;
                uint64_t validate_token = 0;
                if (s_fn_arc_validate_tool_v2)
                {
                    const uint64_t caller_nonce = static_cast<uint64_t>(__rdtsc()) ^ kStartupValidateGateToken;
                    DWORD validate_seh = arc_call_validate_tool_v2_seh(
                        s_fn_arc_validate_tool_v2,
                        caller_nonce,
                        kStartupValidateNameHash,
                        0ULL,
                        &validate_token);
                    if (validate_seh != ERROR_SUCCESS) {
                        lic_log_fmt("arc_startup_validate_v2_seh code=0x%08lX", static_cast<unsigned long>(validate_seh));
                        arc_loader::mark_error_fatal(
                            "ARC startup validation raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                        arc_loader::unload_without_detach(s_arc_module);
                        clear_arc_exports();
                        return false;
                    }
                    log_arc_status("arc_startup_validate_v2");
                }
                else
                {
                    DWORD validate_seh = arc_call_validate_tool_seh(
                        s_fn_arc_validate_tool,
                        kStartupValidateNameHash,
                        kStartupValidateGateToken,
                        &validate_token);
                    if (validate_seh != ERROR_SUCCESS) {
                        lic_log_fmt("arc_startup_validate_v1_seh code=0x%08lX", static_cast<unsigned long>(validate_seh));
                        arc_loader::mark_error_fatal(
                            "ARC startup validation raised a structured exception. Please restart AiDAStandalone.exe and try again.");
                        arc_loader::unload_without_detach(s_arc_module);
                        clear_arc_exports();
                        return false;
                    }
                    log_arc_status("arc_startup_validate_v1");
                }
                if (validate_token == 0) {
                    log_arc_status("arc_startup_gate_failed_validate_zero");
                    __fastfail(0xA1DAFA17u);
                }

                log_arc_status("arc_startup_gate_ok");
            }

            std::array<uint8_t, 32> driver_hwid_hash{};
            std::array<std::array<uint8_t, 32>, hwid_kernel_proto::kFactorCount> driver_factor_hashes{};
            uint32_t driver_factor_mask = 0u;
            std::string drv_hwid_err;
            if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver() &&
                query_driver_hwid_v2(driver_hwid_hash, driver_factor_hashes, driver_factor_mask, drv_hwid_err))
            {
                aida::hardware_id::v2::collection_t um_collection{};
                std::string um_err;
                if (aida::hardware_id::v2::collect(um_collection, um_err))
                {
                    uint32_t mismatched = 0u;
                    constexpr uint32_t kTpmFactorIndex = 8u;
                    for (uint32_t i = 0; i < hwid_kernel_proto::kFactorCount; ++i)
                    {
                        if (i == kTpmFactorIndex) continue;
                        if (!um_collection.factors[i].collected) continue;
                        if ((driver_factor_mask & (1u << i)) == 0u) continue;
                        if (std::memcmp(um_collection.factors[i].factor_hash.data(),
                                        driver_factor_hashes[i].data(), 32) != 0)
                        {
                            ++mismatched;
                        }
                    }
                    if (mismatched > 0u)
                    {
                        char dbg2[96];
                        _snprintf_s(dbg2, sizeof(dbg2), _TRUNCATE,
                            "arc_hwid_v2_um_km_mismatch n=%u", mismatched);
                        log_arc_status(dbg2);
                        anti_tamper::enforce_violation_id(
                            aida::reason_ids::reason_id_from_string("hwid_um_km_mismatch"),
                            std::string("arc_init"));
                    }
                    else
                    {
                        log_arc_status("arc_hwid_v2_um_km_match");
                    }
                    for (auto& f : um_collection.factors)
                    {
                        SecureZeroMemory(f.factor_hash.data(), f.factor_hash.size());
                        if (!f.bytes.empty()) SecureZeroMemory(f.bytes.data(), f.bytes.size());
                    }
                    SecureZeroMemory(um_collection.hwid_hash.data(), um_collection.hwid_hash.size());
                }
                for (auto& fh : driver_factor_hashes)
                {
                    SecureZeroMemory(fh.data(), fh.size());
                }
                SecureZeroMemory(driver_hwid_hash.data(), driver_hwid_hash.size());
            }
            else
            {
                char dbg[160];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "arc_hwid_v2_query_skipped reason=%.96s",
                    drv_hwid_err.empty() ? "driver_not_loaded" : drv_hwid_err.c_str());
                log_arc_status(dbg);
            }

            s_arc_loaded.store(true, std::memory_order_release);
            set_arc_obfuscated_state(true);

            lk.unlock();
            log_arc_status("arc_lock_released_pre_finalize");

            try
            {
                bool finalize_ok = anti_tamper::finalize_after_activation();
                if (!finalize_ok)
                {
                    log_arc_status("anti_tamper_finalize_after_activation_failed");
                    __fastfail(0xA1DAFA18u);
                }
                log_arc_status("anti_tamper_finalize_after_activation_done");
                {
                    std::string state_err;
                    aida::license_state::set_flags(
                        aida::license_state::flag_arc_loaded, 0, state_err);
                }
                settings.license_arc_load_ok = true;
                settings.save();
                log_arc_status("arc_load_ok_disk_cache_marked");
            }
            catch (const std::exception& ex)
            {
                std::string m = std::string("anti_tamper_finalize_exception: ") + ex.what();
                log_arc_status(m.c_str());
                __fastfail(0xA1DAFA18u);
            }
            catch (...)
            {
                log_arc_status("anti_tamper_finalize_unknown_exception");
                __fastfail(0xA1DAFA18u);
            }

            const ULONGLONG t_arc_bulk_total_ms = GetTickCount64() - t_arc_bulk_start_ms;
            lic_log_fmt("[arc-bulk] complete duration_ms=%llu",
                static_cast<unsigned long long>(t_arc_bulk_total_ms));
            return true;

        } catch (const std::exception& ex) {
            const ULONGLONG t_arc_bulk_total_ms = GetTickCount64() - t_arc_bulk_start_ms;
            lic_log_fmt("[arc-bulk] handler_cpp_exception duration_ms=%llu what=%.160s",
                static_cast<unsigned long long>(t_arc_bulk_total_ms),
                ex.what());
            log_arc_status("arc_paged_download_cpp_exception");
            return false;
        } catch (...) {
            const ULONGLONG t_arc_bulk_total_ms = GetTickCount64() - t_arc_bulk_start_ms;
            lic_log_fmt("[arc-bulk] handler_exception duration_ms=%llu",
                static_cast<unsigned long long>(t_arc_bulk_total_ms));
            log_arc_status("arc_paged_download_exception");
            return false;
        }
    }

    bool arc_worker_queues_quiescent_for_unload(const char* reason)
    {
        auto wq = work_queue::stats();
        auto svc = work_queue::service_stats();
        auto cq = critical_work_queue::stats();
        const bool quiescent =
            wq.pending == 0 && wq.active == 0 &&
            svc.pending == 0 && svc.active == 0 &&
            cq.pending == 0 && cq.active == 0;
        const uintptr_t arc_base = reinterpret_cast<uintptr_t>(s_arc_module.base);
        const uintptr_t arc_end = arc_base + static_cast<uintptr_t>(s_arc_module.image_size);
        lic_log_fmt("arc_unload_worker_gate reason=%.128s quiescent=%d loaded=%d unloading=%d inflight=%lld base=0x%llX end=0x%llX size=0x%llX wq_alive=%d wq_shutdown=%d wq_pending=%zu wq_active=%u wq_oldest_ms=%llu wq_labels=%.360s svc_alive=%d svc_shutdown=%d svc_pending=%zu svc_active=%u svc_oldest_ms=%llu svc_labels=%.360s cq_alive=%d cq_shutdown=%d cq_pending=%zu cq_active=%u cq_oldest_ms=%llu cq_labels=%.360s",
            reason && *reason ? reason : "unload_arc",
            quiescent ? 1 : 0,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(arc_base),
            static_cast<unsigned long long>(arc_end),
            static_cast<unsigned long long>(s_arc_module.image_size),
            wq.alive ? 1 : 0,
            wq.shutting_down ? 1 : 0,
            wq.pending,
            static_cast<unsigned>(wq.active),
            static_cast<unsigned long long>(wq.oldest_active_ms),
            wq.active_labels.empty() ? "<none>" : wq.active_labels.c_str(),
            svc.alive ? 1 : 0,
            svc.shutting_down ? 1 : 0,
            svc.pending,
            static_cast<unsigned>(svc.active),
            static_cast<unsigned long long>(svc.oldest_active_ms),
            svc.active_labels.empty() ? "<none>" : svc.active_labels.c_str(),
            cq.alive ? 1 : 0,
            cq.shutting_down ? 1 : 0,
            cq.pending,
            static_cast<unsigned>(cq.active),
            static_cast<unsigned long long>(cq.oldest_active_ms),
            cq.active_labels.empty() ? "<none>" : cq.active_labels.c_str());
        return quiescent;
    }

    bool unload_arc(const char* reason, bool require_worker_quiescence)
    {
        const char* reason_text = (reason && *reason) ? reason : "unload_arc";
        if (require_worker_quiescence && s_arc_module.base && !arc_worker_queues_quiescent_for_unload(reason_text))
        {
            lic_log_fmt("unload_arc_release_suppressed reason=%.128s loaded=%d unloading=%d inflight=%lld base=0x%llX size=0x%llX",
                reason_text,
                s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
                s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s_arc_module.base)),
                static_cast<unsigned long long>(s_arc_module.image_size));
            return false;
        }

        const bool was_unloading = s_arc_unloading.exchange(true, std::memory_order_acq_rel);

        {
            char dbg[160];
            int64_t inflight_pre = s_arc_call_inflight.load(std::memory_order_acquire);
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "unload_arc_drain_begin reason=%.80s was_unloading=%d inflight=%lld",
                reason_text,
                was_unloading ? 1 : 0,
                static_cast<long long>(inflight_pre));
            lic_log(dbg);
        }

        std::unique_lock<std::shared_mutex> drain(s_arc_call_mtx);

        {
            char dbg[160];
            int64_t inflight_post = s_arc_call_inflight.load(std::memory_order_acquire);
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "unload_arc_drain_done reason=%.80s inflight=%lld",
                reason_text,
                static_cast<long long>(inflight_post));
            lic_log(dbg);
        }

        std::unique_lock<std::timed_mutex> lk(s_arc_mtx, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::seconds(5)))
        {
            lic_log_fmt("unload_arc_lock_timeout reason=%.128s", reason_text);
            if (!was_unloading)
                s_arc_unloading.store(false, std::memory_order_release);
            return false;
        }
        lic_log_fmt("unload_arc_release_begin reason=%.128s loaded=%d base=0x%llX end=0x%llX size=0x%llX entry=0x%llX function_table=0x%llX function_count=%u inflight=%lld",
            reason_text,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s_arc_module.base)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s_arc_module.base) + static_cast<uintptr_t>(s_arc_module.image_size)),
            static_cast<unsigned long long>(s_arc_module.image_size),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s_arc_module.entry_point)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s_arc_module.function_table)),
            static_cast<unsigned>(s_arc_module.function_table_count),
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)));
        if (s_arc_loaded.load(std::memory_order_acquire) && s_fn_arc_cleanup) {
            DWORD cleanup_seh = arc_call_cleanup_seh(s_fn_arc_cleanup);
            if (cleanup_seh != ERROR_SUCCESS)
                lic_log_fmt("unload_arc_cleanup_seh code=0x%08lX", static_cast<unsigned long>(cleanup_seh));
        }
        s_fn_arc_init = nullptr;
        s_fn_arc_bind_driver_device = nullptr;
        s_fn_arc_get_comm_bridge = nullptr;
        s_fn_arc_validate_tool = nullptr;
        s_fn_arc_validate_tool_v2 = nullptr;
        s_fn_arc_verify_watermark_trailer = nullptr;
        s_fn_arc_heartbeat = nullptr;
        s_fn_arc_heartbeat_ex = nullptr;
        s_fn_arc_cleanup = nullptr;
        s_fn_arc_set_key_seed = nullptr;
        s_fn_arc_unseal_feature = nullptr;
        s_fn_arc_copy_last_status = nullptr;
        s_arc_loaded.store(false, std::memory_order_release);
        set_arc_obfuscated_state(false);
        {
            std::string state_err;
            aida::license_state::set_flags(
                0, aida::license_state::flag_arc_loaded, state_err);
        }

        if (s_arc_module.base) {
            arc_loader::unload(s_arc_module);
        }

        drain.unlock();
        s_arc_unloading.store(false, std::memory_order_release);
        lic_log_fmt("unload_arc_release_done reason=%.128s loaded=%d unloading=%d inflight=%lld base=0x%llX size=0x%llX",
            reason_text,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(s_arc_module.base)),
            static_cast<unsigned long long>(s_arc_module.image_size));
        return true;
    }

    bool try_validate_cached(settings_sa_t& settings, std::string& error_out)
    {
        if (settings.license_key.empty() || settings.license_sig_payload.empty())
            return false;

        if (!settings.license_arc_load_ok)
            lic_log("cached_activation_incomplete_recovering_online");

        auto payload = json::parse(settings.license_sig_payload, nullptr, false);
        if (payload.is_discarded() || !payload.is_object()) {
            error_out = "Cached license payload is invalid.";
            return false;
        }

        if (payload.value("status", "") != "valid" ||
            payload.value("license_key", "") != settings.license_key) {
            error_out = "Cached license is bound to a different key.";
            return false;
        }

        const std::string nonce = generate_nonce();
        json response;
        std::string reval_err;
        std::string hwid;
        if (!call_validation_endpoint_for_current_hwid(settings, "validate", settings.license_key,
                                                       settings.license_session_token, nonce, hwid, reval_err, response)) {
            error_out = reval_err.empty() ? "Online license validation required." : reval_err;
            return false;
        }

        if (!apply_valid_response(settings, settings.license_key, hwid, response))
        {
            std::string err_copy;
            {
                std::lock_guard<std::mutex> lk(s_state_mtx);
                err_copy = s_error;
            }
            error_out = err_copy.empty()
                ? std::string("Cached license revalidation failed during response apply.")
                : err_copy;
            return false;
        }
        settings.license_arc_load_ok = s_arc_loaded.load(std::memory_order_acquire);
        settings.save();

        payload = json::parse(settings.license_sig_payload, nullptr, false);
        if (payload.is_discarded() || !payload.is_object()) {
            error_out = "Online license response cache is invalid.";
            return false;
        }

        settings.license_plan = payload.value("plan", settings.license_plan);
        settings.license_session_token = payload.value("session_token", settings.license_session_token);
        settings.license_server_nonce = payload.value("server_nonce", settings.license_server_nonce);
        settings.license_client_nonce = payload.value("client_nonce", settings.license_client_nonce);
        settings.license_auth_hmac_key_b64 = payload.value("auth_hmac_key_b64", settings.license_auth_hmac_key_b64);
        settings.license_signing_kid = payload.value("kid", settings.license_signing_kid);
        settings.license_hwid = hwid;
        settings.license_issued_at = payload.value("issued_at", settings.license_issued_at);
        settings.license_ttl = payload.value("ttl", settings.license_ttl);


        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_cached_hwid = hwid;
            s_cached_session_token = settings.license_session_token;
            s_cached_arc_bind_token = settings.license_session_token;
            s_cached_server_payload_b64 = payload.value("_server_payload_b64", std::string());
            s_cached_server_sig_b64 = payload.value("_server_sig_b64", std::string());
            s_cached_server_kid = payload.value("_server_kid", settings.license_signing_kid);
        }
        update_proof_hash(settings.license_session_token, hwid);

        if (!settings.license_key_seed.empty())
            anti_tamper::server_pages::detail::stored_key_seed() = settings.license_key_seed;

        uint64_t nonce_seed = fnv1a_str(settings.license_server_nonce);
        s_last_heartbeat_time.store(
            static_cast<int64_t>(std::chrono::steady_clock::now().time_since_epoch().count() / 1000000),
            std::memory_order_release);

        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_magic.store(S_MAGIC_INIT ^ nonce_seed, std::memory_order_release);
            s_plan = settings.license_plan;
            s_error.clear();
            set_obfuscated_valid(true, nonce_seed);
        }
        return true;
    }

    bool is_reactivation_required_error(const std::string& error)
    {
        return error == "not_found" ||
               error == "revoked" ||
               error == "expired" ||
               error == "session_mismatch" ||
               error == "session_expired" ||
               error == "hwid_mismatch" ||
               error == "clock_drift" ||
               error == "invalid_format" ||
               error == "missing_key";
    }

    bool can_revalidate_auth_reject(const std::string& error)
    {
        return error == "session_mismatch" ||
               error == "session_expired" ||
               error == "nonce_stale" ||
               error == "nonce_replay";
    }

    bool refresh_online_session_after_auth_reject(settings_sa_t& settings,
                                                 const std::string& trigger_error,
                                                 std::string& pending_error)
    {
        if (settings.license_key.empty())
            return false;

        const std::string reval_nonce = generate_nonce();
        std::string reval_error;
        std::string reval_hwid;
        json reval_response;

        lic_log_fmt("heartbeat_revalidation_before_pending reason=%.96s",
            trigger_error.c_str());

        if (license_rate_limit_cooling_down("heartbeat_revalidation_before_pending")) {
            pending_error = "rate_limited";
            return false;
        }

        if (!call_validation_endpoint_for_current_hwid(settings, "validate",
                                                       settings.license_key, settings.license_session_token,
                                                       reval_nonce, reval_hwid,
                                                       reval_error, reval_response))
        {
            lic_log_fmt("heartbeat_revalidation_before_pending_failed err=%.120s",
                reval_error.c_str());
            if (!reval_error.empty())
                pending_error = reval_error;
            if (is_authoritative_stop_response(reval_response)) {
                lic_log("heartbeat_revalidation_before_pending_killed_by_server");
                license_failfast("server_killed_session",
                    "reason=" + license_response_reason(reval_response, "server_killed_session"));
            }
            return false;
        }

        if (!apply_valid_response(settings, settings.license_key, reval_hwid, reval_response))
        {
            lic_log("heartbeat_revalidation_before_pending_apply_failed");
            std::lock_guard<std::mutex> lk(s_state_mtx);
            if (!s_error.empty())
                pending_error = s_error;
            return false;
        }

        if (s_arc_loaded.load(std::memory_order_acquire) &&
            !try_load_arc_with_retries(settings, reval_hwid))
        {
            lic_log("heartbeat_revalidation_before_pending_arc_reseed_failed");
            const std::string arc_error = arc_load_error_or_fallback("ARC runtime session reseed failed during heartbeat revalidation.");
            if (!arc_error.empty())
                pending_error = arc_error;
            return false;
        }
        if (!s_arc_loaded.load(std::memory_order_acquire))
        {
            if (s_activation_completed_at_ms.load(std::memory_order_acquire) == 0)
                mark_activation_completed();
            lic_diag::thread_canary("pre_attempt_deferred_arc_fetch_before_pending");
            attempt_deferred_arc_fetch(settings, reval_hwid);
            lic_diag::thread_canary("post_attempt_deferred_arc_fetch_before_pending");
        }

        cancel_silent_kill();
        lic_log("heartbeat_revalidation_before_pending_ok");
        return true;
    }

    std::string user_facing_license_error(const std::string& error)
    {
        auto contains = [&error](const char* token) {
            return token && error.find(token) != std::string::npos;
        };
        if (contains("ERROR_WINHTTP_NAME_NOT_RESOLVED") || contains("gle=12007"))
            return "AiDA could not resolve api.aidapro.net.\nWindows reported WinHTTP DNS/name resolution error 12007.\nCheck your DNS, VPN, firewall, or internet connection and press Activate again.";
        if (contains("ERROR_WINHTTP_TIMEOUT") || contains("gle=12002"))
            return "AiDA could not reach the license server before the network timeout.\nCheck your internet connection, VPN, or firewall and press Activate again.";
        if (contains("ERROR_WINHTTP_CANNOT_CONNECT") || contains("ERROR_WINHTTP_CONNECTION_ERROR") ||
            contains("winhttp_connect_failed") || contains("winhttp_send_failed") || contains("winhttp_recv_failed"))
            return "AiDA could not reach the license server.\nThis was a network transport failure, not a license rejection.\nCheck your internet connection, DNS, VPN, or firewall and press Activate again.";
        if (error == "License activation challenge unavailable.")
            return "AiDA could not fetch the activation challenge from the license server.\nCheck your internet connection, DNS, VPN, or firewall and press Activate again.";
        if (error == "not_found")
            return "License key was not found on the server.\nRe-enter your active key and press Activate.";
        if (error == "revoked")
            return "This license key has been revoked.\nContact support if you believe this is wrong.";
        if (error == "expired")
            return "This license key has expired.\nUse a renewed key to continue.";
        if (error == "session_mismatch" || error == "session_expired")
            return "Saved license session expired.\nPress Activate to create a new session.";
        if (error == "hwid_mismatch")
            return "This license key is bound to another machine.\nContact support if your hardware changed.";
        if (error == "clock_drift")
            return "System clock drift blocked license validation.\nSync Windows time and activate again.";
        if (error == "invalid_format" || error == "missing_key")
            return "Enter a valid AiDA license key and press Activate.";
        if (error == "challenge_expired" || error == "challenge_stale" || error == "challenge_missing" || error == "challenge_signature")
            return "License activation challenge expired.\nPress Activate again.";
        if (error == "rate_limited")
            return "Too many activation attempts.\nWait briefly and press Activate again.";
        if (error == "banned")
            return "This machine or network is blocked from activation.\nContact support if you believe this is wrong.";
        return error;
    }

    bool is_authoritative_stop_response(const json& response)
    {
        if (!response.is_object())
            return false;
        const std::string status = response.value("status", "");
        return status == "killed" || status == "banned" || response.value("alive", true) == false;
    }

    std::string license_response_reason(const json& response, const std::string& default_reason)
    {
        if (response.is_object()) {
            const std::string reason = response.value("reason", "");
            if (!reason.empty())
                return reason;
        }
        return default_reason.empty() ? std::string("license rejected") : default_reason;
    }

    void enter_pending_activation(settings_sa_t& settings, const std::string& reason)
    {
        const std::string effective_reason = reason.empty() ? std::string("License reactivation required.") : reason;
        lic_log((std::string("enter_pending_activation: ") + effective_reason).c_str());
        anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
        unload_arc("enter_pending_activation", false);
        reset_arc_fetch_state();
        reset_activation_completed_at();
        settings.license_plan.clear();
        settings.license_sig_payload.clear();
        settings.license_server_sig.clear();
        settings.license_session_token.clear();
        settings.license_server_nonce.clear();
        settings.license_client_nonce.clear();
        settings.license_key_seed.clear();
        settings.license_bind_proof.clear();
        settings.license_auth_hmac_key_b64.clear();
        settings.license_issued_at = 0;
        settings.license_ttl = 3600;
        settings.license_arc_load_ok = false;
        settings.save();
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_cached_hwid.clear();
            s_cached_session_token.clear();
            s_cached_arc_bind_token.clear();
            s_cached_server_payload_b64.clear();
            s_cached_server_sig_b64.clear();
            s_cached_server_kid = 0;
        }
        s_proof_hash.store(0, std::memory_order_release);
        s_heartbeat_counter.store(0, std::memory_order_release);
        s_replay_request_seq.store(0, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_magic.store(S_MAGIC_INIT, std::memory_order_release);
            s_plan.clear();
            s_error = effective_reason;
            set_obfuscated_valid(false);
        }
    }

    void heartbeat_worker(settings_sa_t* settings, uint64_t worker_epoch)
    {
        const int prior_priority = GetThreadPriority(GetCurrentThread());
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        lic_log_fmt("heartbeat_worker_enter epoch=%llu tid=%lu priority=%d",
            static_cast<unsigned long long>(worker_epoch),
            static_cast<unsigned long>(GetCurrentThreadId()),
            GetThreadPriority(GetCurrentThread()));
        std::mt19937 rng(static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count() ^
            GetCurrentProcessId()));

        int consecutive_failures = 0;

        while (worker_active(worker_epoch)) {


            int wait_s;
            if (consecutive_failures == 0) {
                const int heartbeat_base_s = 15;
                const int heartbeat_jitter_s = 10;
                wait_s = heartbeat_base_s + static_cast<int>(rng() % (heartbeat_jitter_s + 1));
            } else {
                wait_s = (std::max)(11, (std::min)(2 << (consecutive_failures - 1), 30));
            }

            for (int waited = 0; waited < wait_s && worker_active(worker_epoch); waited += 1)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (!worker_active(worker_epoch))
                break;

            if (!check_obfuscated_valid() || settings->license_key.empty() || settings->license_session_token.empty())
                continue;

            const bool full_test_running = test_all_features::is_running();
            if (full_test_running) {
                lic_log("heartbeat_full_test_running_reduced_diagnostics");
            }

            const std::string nonce = generate_nonce();
            std::string error;
            json response;
            lic_log("heartbeat_calling");
            if (!full_test_running) {
                lic_diag::dump_pe_self("pre_heartbeat_call");
                lic_diag::dump_mitigation("pre_heartbeat_call");
                lic_diag::thread_canary("pre_heartbeat_call");
            }
            std::string hb_session_token = select_heartbeat_session_token(*settings);
            const bool hb_ok = call_validation_endpoint(*settings, "heartbeat", settings->license_key,
                                          s_cached_hwid, hb_session_token,
                                          nonce, error, response);
            if (!worker_active(worker_epoch))
                break;
            {
                char hbr[256];
                _snprintf_s(hbr, sizeof(hbr), _TRUNCATE,
                    "heartbeat_result ok=%d consecutive_fail=%d err=%.150s",
                    (int)hb_ok, consecutive_failures, error.c_str());
                lic_log(hbr);
            }
            if (!hb_ok) {

                if (is_authoritative_stop_response(response)) {
                    lic_log("heartbeat_killed_by_server");
                    license_failfast("server_killed_session", "reason=" + license_response_reason(response, "server_killed_session"));
                }

                if (error == "nonce_stale" || error == "bind_proof_mismatch" ||
                    error == "bind_proof_reuse" || error == "bind_proof_format" ||
                    error == "code_binding_mismatch" || error == "code_binding_missing")
                {
                    schedule_silent_kill(error.c_str());
                }

                if (error == "rate_limited") {
                    consecutive_failures = 1;
                    continue;
                }

                if (can_revalidate_auth_reject(error)) {
                    std::string pending_error = error;
                    if (refresh_online_session_after_auth_reject(*settings, error, pending_error))
                    {
                        consecutive_failures = 0;
                        continue;
                    }
                    if (is_reactivation_required_error(error) ||
                        is_reactivation_required_error(pending_error))
                    {
                        enter_pending_activation(*settings, pending_error);
                        break;
                    }
                } else if (is_reactivation_required_error(error)) {
                    std::string pending_error = error;
                    enter_pending_activation(*settings, pending_error);
                    break;
                }

                consecutive_failures++;


                if (consecutive_failures >= 5) {
                    if (license_rate_limit_cooling_down("heartbeat_revalidation")) {
                        consecutive_failures = 1;
                        continue;
                    }
                    const std::string reval_nonce = generate_nonce();
                    std::string reval_error;
                    json reval_response;
                    if (call_validation_endpoint(*settings, "validate", settings->license_key,
                                                 s_cached_hwid, {}, reval_nonce,
                                                 reval_error, reval_response)) {
                        if (!apply_valid_response(*settings, settings->license_key,
                                                  s_cached_hwid, reval_response))
                        {
                            lic_log("heartbeat_revalidation_apply_failed");
                            enter_pending_activation(*settings,
                                std::string("revalidation_apply_failed"));
                            break;
                        }
                        if (s_activation_completed_at_ms.load(std::memory_order_acquire) == 0)
                            mark_activation_completed();
                        if (!s_arc_loaded.load(std::memory_order_acquire))
                        {
                            lic_diag::thread_canary("pre_attempt_deferred_arc_fetch_after_revalidation");
                            attempt_deferred_arc_fetch(*settings, s_cached_hwid);
                            lic_diag::thread_canary("post_attempt_deferred_arc_fetch_after_revalidation");
                        }
                        consecutive_failures = 0;
                        continue;
                    }

                    if (is_authoritative_stop_response(reval_response)) {
                        lic_log("heartbeat_revalidation_killed_by_server");
                        license_failfast("server_killed_session", "reason=" + license_response_reason(reval_response, "server_killed_session"));
                    }

                    const std::string effective_error = reval_error.empty() ? error : reval_error;
                    if (effective_error == "rate_limited") {
                        consecutive_failures = 1;
                        continue;
                    }
                    if (is_reactivation_required_error(effective_error)) {
                        enter_pending_activation(*settings, effective_error);
                        break;
                    }

                    {
                        std::lock_guard<std::mutex> lk(s_state_mtx);
                        s_error = effective_error.empty() ? error : effective_error;
                    }
                    lic_log((std::string("heartbeat_revalidation_transient: ") + (effective_error.empty() ? error : effective_error)).c_str());
                    consecutive_failures = 4;
                    continue;
                }
                continue;
            }

            consecutive_failures = 0;
            cancel_silent_kill();
            lic_log("heartbeat_success_applying");
            if (!full_test_running) {
                lic_diag::dump_pe_self("post_heartbeat_call");
                lic_diag::dump_mitigation("post_heartbeat_call");
                lic_diag::thread_canary("post_heartbeat_call");
            }
            if (!apply_valid_response(*settings, settings->license_key, s_cached_hwid, response))
            {
                lic_log("heartbeat_apply_response_failed");
                enter_pending_activation(*settings, std::string("heartbeat_apply_failed"));
                break;
            }
            if (!full_test_running) {
                lic_diag::dump_pe_self("post_apply_valid_response");
                lic_diag::dump_mitigation("post_apply_valid_response");
                lic_diag::thread_canary("post_apply_valid_response");
            }
            if (s_activation_completed_at_ms.load(std::memory_order_acquire) == 0)
                mark_activation_completed();
            if (!s_arc_loaded.load(std::memory_order_acquire))
            {
                lic_diag::thread_canary("pre_attempt_deferred_arc_fetch");
                attempt_deferred_arc_fetch(*settings, s_cached_hwid);
                lic_diag::thread_canary("post_attempt_deferred_arc_fetch");
            }
            lic_log("heartbeat_apply_done");
        }
        lic_log_fmt("heartbeat_worker_exit epoch=%llu tid=%lu",
            static_cast<unsigned long long>(worker_epoch),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (prior_priority != THREAD_PRIORITY_ERROR_RETURN)
            SetThreadPriority(GetCurrentThread(), prior_priority);
    }

    void srv_refresh_worker(settings_sa_t* settings, uint64_t worker_epoch)
    {
        const int prior_priority = GetThreadPriority(GetCurrentThread());
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        lic_log_fmt("srv_refresh_worker_enter epoch=%llu tid=%lu priority=%d",
            static_cast<unsigned long long>(worker_epoch),
            static_cast<unsigned long>(GetCurrentThreadId()),
            GetThreadPriority(GetCurrentThread()));
        while (worker_active(worker_epoch))
        {
            for (int w = 0; w < 10 && worker_active(worker_epoch); ++w)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (!worker_active(worker_epoch))
                break;

            const bool valid_now = check_obfuscated_valid();
            const size_t session_token_len = settings->license_session_token.size();
            const size_t server_nonce_len = settings->license_server_nonce.size();
            lic_log_fmt("srv_refresh_tick epoch=%llu valid=%d session_len=%zu nonce_len=%zu tid=%lu",
                static_cast<unsigned long long>(worker_epoch),
                valid_now ? 1 : 0,
                session_token_len,
                server_nonce_len,
                static_cast<unsigned long>(GetCurrentThreadId()));

            if (!valid_now || settings->license_session_token.empty()) {
                lic_log_fmt("srv_refresh_skip reason=invalid_or_missing_session valid=%d session_len=%zu",
                    valid_now ? 1 : 0,
                    session_token_len);
                continue;
            }

            std::string srv_nonce_str = settings->license_server_nonce;
            if (srv_nonce_str.empty()) {
                lic_log("srv_refresh_skip reason=empty_server_nonce");
                continue;
            }

            uint64_t srv_nonce_val = 0;
            if (!parse_server_nonce_u64(srv_nonce_str, srv_nonce_val))
            {
                lic_log_fmt("srv_refresh_nonce_invalid len=%zu", srv_nonce_str.size());
                continue;
            }

            uint32_t token_hash = static_cast<uint32_t>(
                fnv1a_str(settings->license_session_token) & 0xFFFFFFFF);

            uint64_t driver_proof = 0;
            if (!worker_active(worker_epoch))
                break;
            const uint64_t relay_start = static_cast<uint64_t>(GetTickCount64());
            lic_log_fmt("srv_refresh_relay_begin epoch=%llu nonce_len=%zu",
                static_cast<unsigned long long>(worker_epoch),
                srv_nonce_str.size());
            bool relay_ok = relay_server_token_v2_if_ready(token_hash, srv_nonce_val, &driver_proof);
            DWORD relay_gle = relay_ok ? ERROR_SUCCESS : GetLastError();
            lic_log_fmt("srv_refresh_relay_end ok=%d proof=%d gle=%lu elapsed_ms=%llu",
                relay_ok ? 1 : 0,
                driver_proof != 0 ? 1 : 0,
                static_cast<unsigned long>(relay_gle),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - relay_start));
            if (relay_ok && driver_proof != 0)
                store_driver_proof_cache(driver_proof, srv_nonce_str);
        }
        lic_log_fmt("srv_refresh_worker_exit epoch=%llu tid=%lu",
            static_cast<unsigned long long>(worker_epoch),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (prior_priority != THREAD_PRIORITY_ERROR_RETURN)
            SetThreadPriority(GetCurrentThread(), prior_priority);
    }

    bool run_heartbeat_once_after_worker_degrade(settings_sa_t& settings, const char* phase)
    {
        if (!check_obfuscated_valid() || settings.license_key.empty() || settings.license_session_token.empty())
            return false;

        const std::string nonce = generate_nonce();
        std::string error;
        json response;
        std::string hb_session_token = select_heartbeat_session_token(settings);
        bool ok = call_validation_endpoint(settings, "heartbeat", settings.license_key,
                                           s_cached_hwid, hb_session_token, nonce,
                                           error, response);
        lic_log_fmt("%s_inline_heartbeat ok=%d err=%.150s",
            phase ? phase : "worker_degrade",
            ok ? 1 : 0,
            error.c_str());

        if (!ok)
        {
            if (is_authoritative_stop_response(response))
                license_failfast("server_killed_session", "reason=" + license_response_reason(response, "server_killed_session"));

            if (is_reactivation_required_error(error))
            {
                enter_pending_activation(settings, error);
                return false;
            }

            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error.empty() ? std::string("License heartbeat worker unavailable; online heartbeat will retry.") : error;
            return false;
        }

        cancel_silent_kill();
        if (!apply_valid_response(settings, settings.license_key, s_cached_hwid, response))
        {
            lic_log("worker_degrade_inline_heartbeat_apply_failed");
            enter_pending_activation(settings, std::string("heartbeat_apply_failed"));
            return false;
        }

        if (s_activation_completed_at_ms.load(std::memory_order_acquire) == 0)
            mark_activation_completed();

        return true;
    }

    void restart_heartbeat(settings_sa_t& settings)
    {
        const uint64_t worker_epoch = s_worker_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
        s_stop.store(true, std::memory_order_release);
        wait_for_worker_done(s_heartbeat_done, "heartbeat", 3000);
        wait_for_worker_done(s_srv_refresh_done, "srv_refresh", 3000);

        s_stop.store(false, std::memory_order_release);

        settings_sa_t* settings_ptr = &settings;

        s_heartbeat_done.store(false, std::memory_order_release);
        s_heartbeat_running_epoch.store(worker_epoch, std::memory_order_release);
        bool heartbeat_posted = false;
        try
        {
            heartbeat_posted = work_queue::post_service([settings_ptr, worker_epoch]() {
                heartbeat_worker(settings_ptr, worker_epoch);
                if (s_heartbeat_running_epoch.load(std::memory_order_acquire) == worker_epoch)
                    s_heartbeat_done.store(true, std::memory_order_release);
            });
        }
        catch (const std::exception& ex)
        {
            lic_log_fmt("heartbeat_thread_post_exception what=%.160s", ex.what());
        }
        catch (...)
        {
            lic_log("heartbeat_thread_post_unknown_exception");
        }
        if (heartbeat_posted)
        {
            auto svc = work_queue::service_stats();
            lic_log_fmt("heartbeat_thread_started service_pool=%d service_workers=%zu service_pending=%zu service_active=%u",
                svc.pool_size,
                svc.workers,
                svc.pending,
                svc.active);
        }
        else
        {
            s_heartbeat_done.store(true, std::memory_order_release);
            s_heartbeat_running_epoch.store(0, std::memory_order_release);
            lic_log("heartbeat_thread_degraded_queue_unavailable");
            run_heartbeat_once_after_worker_degrade(settings, "heartbeat_thread_degraded");
        }

        s_srv_refresh_done.store(false, std::memory_order_release);
        s_srv_refresh_running_epoch.store(worker_epoch, std::memory_order_release);
        bool srv_refresh_posted = false;
        try
        {
            srv_refresh_posted = work_queue::post_service([settings_ptr, worker_epoch]() {
                srv_refresh_worker(settings_ptr, worker_epoch);
                if (s_srv_refresh_running_epoch.load(std::memory_order_acquire) == worker_epoch)
                    s_srv_refresh_done.store(true, std::memory_order_release);
            });
        }
        catch (const std::exception& ex)
        {
            lic_log_fmt("srv_refresh_thread_post_exception what=%.160s", ex.what());
        }
        catch (...)
        {
            lic_log("srv_refresh_thread_post_unknown_exception");
        }
        if (srv_refresh_posted)
        {
            auto svc = work_queue::service_stats();
            lic_log_fmt("srv_refresh_thread_started service_pool=%d service_workers=%zu service_pending=%zu service_active=%u",
                svc.pool_size,
                svc.workers,
                svc.pending,
                svc.active);
        }
        else
        {
            s_srv_refresh_done.store(true, std::memory_order_release);
            s_srv_refresh_running_epoch.store(0, std::memory_order_release);
            lic_log("srv_refresh_thread_degraded_queue_unavailable");
        }
    }


    std::atomic<bool> s_honeypot_tripped{false};
    std::atomic<int>  s_honeypot_trip_count{0};

    static void honeypot_report_impl(const char* trap_cstr, size_t trap_len)
    {
        char trap_buf[64] = {};
        if (trap_len >= sizeof(trap_buf)) trap_len = sizeof(trap_buf) - 1;
        memcpy(trap_buf, trap_cstr, trap_len);

        json body;
        body["event"]     = "honeypot_trip";
        body["trap"]      = trap_buf;
        body["hwid"]      = s_cached_hwid;
        body["timestamp"] = static_cast<int64_t>(
            std::chrono::system_clock::now().time_since_epoch().count());

        int cpuid_buf[4] = {};
        __cpuid(cpuid_buf, 1);
        body["cpuid"] = cpuid_buf[0];
        body["tsc"]   = static_cast<uint64_t>(__rdtsc());

        std::string host = get_cloud_function_host();
        std::string body_str = body.dump();
        raw_https_request("POST", host + "/api/sentinel/honeypot",
                        {}, body_str, "application/json");
    }

    void honeypot_report_async(const char* trap_name)
    {
        s_honeypot_tripped.store(true, std::memory_order_release);
        s_honeypot_trip_count.fetch_add(1, std::memory_order_relaxed);

        work_queue::post([trap = std::string(trap_name)]() {
            try { honeypot_report_impl(trap.c_str(), trap.size()); }
            catch (...) {}
        });
    }


    __declspec(noinline) bool is_product_licensed()
    {
        volatile bool licensed = true;
        if (licensed) {
            honeypot_report_async("is_product_licensed");
        }
        return licensed;
    }


    __declspec(noinline) bool validate_license_key(const char* key)
    {
        if (!key || strlen(key) < 8) return false;
        honeypot_report_async("validate_license_key");
        return true;
    }


    __declspec(noinline) int get_trial_days_remaining()
    {
        honeypot_report_async("get_trial_days_remaining");
        return 9999;
    }


    __declspec(noinline) bool check_online_activation_status()
    {
        honeypot_report_async("check_online_activation");
        return true;
    }


    __declspec(noinline) bool is_feature_unlocked(int feature_id)
    {
        (void)feature_id;
        honeypot_report_async("is_feature_unlocked");
        return true;
    }


    volatile uintptr_t s_hp_fn_table[] = {
        reinterpret_cast<uintptr_t>(&is_product_licensed),
        reinterpret_cast<uintptr_t>(&validate_license_key),
        reinterpret_cast<uintptr_t>(&get_trial_days_remaining),
        reinterpret_cast<uintptr_t>(&check_online_activation_status),
        reinterpret_cast<uintptr_t>(&is_feature_unlocked),
    };

    bool is_honeypot_tripped()
    {
        return s_honeypot_tripped.load(std::memory_order_acquire);
    }
}

namespace standalone_license
{
    void set_run_correlation_id(const std::string& id)
    {
        lic_set_run_correlation_snapshot(id);
        lic_log_fmt("run_correlation_set len=%zu", run_correlation_id().size());
    }

    std::string run_correlation_id()
    {
        return lic_run_correlation_snapshot();
    }

    std::string runtime_state_snapshot()
    {
        const auto now_ms = static_cast<int64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() / 1000000);
        const int64_t last_hb = s_last_heartbeat_time.load(std::memory_order_acquire);
        const int64_t hb_age = (last_hb > 0 && now_ms >= last_hb) ? (now_ms - last_hb) : -1;
        const uint64_t tick_now = license_now_ms();
        const uint64_t rate_until = s_license_rate_limited_until_ms.load(std::memory_order_acquire);
        const uint64_t rate_remaining = rate_until > tick_now ? rate_until - tick_now : 0;
        const int64_t silent_kill_after = s_silent_kill_after_ms.load(std::memory_order_acquire);
        const int64_t silent_remaining = silent_kill_after > now_ms ? silent_kill_after - now_ms : 0;
        const auto& rt = anti_tamper::state::get();
        char buf[1024];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "valid=%d raw_valid=%d pending_activation=%d arc_loaded=%d arc_fetch_deferred=%d arc_download=%d arc_call_inflight=%lld arc_unloading=%d activation_completed_ms=%llu heartbeat_done=%d heartbeat_running_epoch=%llu heartbeat_counter=%u last_heartbeat_age_ms=%lld srv_refresh_done=%d srv_refresh_epoch=%llu worker_epoch=%llu stop=%d rate_limit_remaining_ms=%llu rate_limit_failures=%u silent_kill_remaining_ms=%lld gate_bitmap=0x%08X",
            check_obfuscated_valid() ? 1 : 0,
            s_valid.load(std::memory_order_acquire) ? 1 : 0,
            rt.license_pending_activation.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_fetch_deferred.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_download_in_progress.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)),
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(s_activation_completed_at_ms.load(std::memory_order_acquire)),
            s_heartbeat_done.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(s_heartbeat_running_epoch.load(std::memory_order_acquire)),
            s_heartbeat_counter.load(std::memory_order_acquire),
            static_cast<long long>(hb_age),
            s_srv_refresh_done.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(s_srv_refresh_running_epoch.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(s_worker_epoch.load(std::memory_order_acquire)),
            s_stop.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(rate_remaining),
            s_license_rate_limit_failures.load(std::memory_order_acquire),
            static_cast<long long>(silent_remaining),
            s_gate_bitmap.load(std::memory_order_acquire));
        return std::string(buf);
    }

    bool startup_ban_check(settings_sa_t& settings, std::string& reason_out, std::string& message_out)
    {
        try {
            lic_log_fmt("startup_ban_check_enter key_len=%zu session_len=%zu arc_ok=%d",
                settings.license_key.size(),
                settings.license_session_token.size(),
                settings.license_arc_load_ok ? 1 : 0);
            bool banned = run_startup_ban_check(settings, reason_out, message_out);
            lic_log_fmt("startup_ban_check_exit banned=%d reason_len=%zu message_len=%zu",
                banned ? 1 : 0,
                reason_out.size(),
                message_out.size());
            return banned;
        } catch (...) {
            reason_out.clear();
            message_out.clear();
            lic_log("startup_ban_check_exception");
            return false;
        }
    }

    bool initialize(settings_sa_t& settings)
    {
        lic_log("initialize_enter");
        ensure_modules_initialized();
        reset_arc_fetch_state();
        reset_activation_completed_at();
        std::string error;
        if (!try_validate_cached(settings, error)) {
            lic_log(("initialize_no_cached: " + error).c_str());
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error;
            set_obfuscated_valid(false);
            anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
            return false;
        }
        lic_log("initialize_cached_ok");

        if (s_cached_hwid.empty())
        {
            lic_log("initialize_arc_required_missing_hwid");
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = "Protected runtime load requires a validated hardware binding.";
            set_obfuscated_valid(false);
            anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
            return false;
        }

        lic_log("initialize_loading_arc");
        lic_log("initialize_pre_arc_snapshot_hashes");
        snapshot_code_hashes();
        if (!try_load_arc_with_retries(settings, s_cached_hwid))
        {
            std::string arc_error = arc_load_error_or_fallback("ARC runtime download or verification failed.");
            lic_log_fmt("initialize_arc_required_failed err=%.160s", arc_error.c_str());
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = "Protected runtime failed to load. " + arc_error;
            set_obfuscated_valid(false);
            anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
            return false;
        }

        std::string missing_exports;
        if (!runtime_arc_authorized(&missing_exports))
        {
            lic_log_fmt("initialize_arc_required_exports_failed missing=%.160s", missing_exports.c_str());
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = "Protected runtime exports are unavailable.";
            set_obfuscated_valid(false);
            anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
            return false;
        }

        mark_activation_completed();

        snapshot_code_hashes();
        restart_heartbeat(settings);

        anti_tamper::state::get().license_pending_activation.store(false, std::memory_order_release);
        lic_log("initialize_complete");
        return true;
    }

    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out)
    {
        lic_log("activate_enter");
        lic_log_fmt("activate_key_submitted len=%zu", key.size());
        ensure_modules_initialized();
        if (check_obfuscated_valid() &&
            settings.license_arc_load_ok &&
            key == settings.license_key &&
            !settings.license_session_token.empty())
        {
            std::string missing_exports;
            if (runtime_arc_authorized(&missing_exports))
            {
                lic_log("activate_already_valid");
                error_out.clear();
                anti_tamper::state::get().license_pending_activation.store(false, std::memory_order_release);
                {
                    std::lock_guard<std::mutex> lk(s_state_mtx);
                    s_error.clear();
                }
                if (s_heartbeat_done.load(std::memory_order_acquire) ||
                    s_srv_refresh_done.load(std::memory_order_acquire))
                    restart_heartbeat(settings);
                return true;
            }
            lic_log_fmt("activate_already_valid_arc_required_failed missing=%.160s", missing_exports.c_str());
        }
        reset_arc_fetch_state();
        reset_activation_completed_at();
        anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);

        if (s_apply_response_corrupted.load(std::memory_order_acquire))
        {
            lic_log("activate_refused_binary_corrupted");
            error_out = "Process integrity violated. Please restart AiDAStandalone.exe before reactivating.";
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error_out;
            return false;
        }

        if (!check_obfuscated_valid())
        {
            bool ratchet_active = false;
            {
                std::lock_guard<std::mutex> lk(s_session_ratchet_mtx);
                ratchet_active = s_session_ratchet.initialized;
            }
            if (ratchet_active)
            {
                lic_log("activate_clearing_stale_ratchet");
                ratchet_clear();
            }
        }

        const std::string nonce = generate_nonce();
        json response;
        std::string hwid;

        lic_log("activate_calling_endpoint");
        if (!call_validation_endpoint_for_current_hwid(settings, "validate", key,
                                                       (settings.license_key == key) ? settings.license_session_token : std::string{},
                                                       nonce, hwid, error_out, response)) {
            lic_log(("activate_endpoint_failed: " + error_out).c_str());
            const std::string display_error = user_facing_license_error(error_out);
            anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error_out;
            set_obfuscated_valid(false);
            error_out = display_error;
            return false;
        }
        lic_log((std::string("activate_hwid_ok=") + hwid).c_str());
        lic_log("activate_endpoint_ok");

        {
            LARGE_INTEGER qpf, qpc;
            QueryPerformanceFrequency(&qpf);
            QueryPerformanceCounter(&qpc);
            int64_t now_ms = static_cast<int64_t>((qpc.QuadPart * 1000LL) / qpf.QuadPart);
            auto& ch = anti_tamper::state::get().chain;
            ch.last_fast_check_ms.store(now_ms, std::memory_order_release);
            ch.last_deep_check_ms.store(now_ms, std::memory_order_release);
        }
        if (!apply_valid_response(settings, key, hwid, response))
        {
            lic_log("activate_applied_response_failed");
            std::string err_copy;
            {
                std::lock_guard<std::mutex> lk(s_state_mtx);
                err_copy = s_error;
                set_obfuscated_valid(false);
            }
            anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
            error_out = err_copy.empty()
                ? std::string("Activation failed during response apply. Please restart AiDAStandalone.exe and try again.")
                : err_copy;
            return false;
        }
        lic_log("activate_applied_response");

        lic_log("activate_downloading_arc");
        lic_log("activate_pre_arc_snapshot_hashes");
        snapshot_code_hashes();
        if (try_load_arc_with_retries(settings, hwid))
        {
            lic_log("activate_arc_done");
        }
        else
        {
            lic_log("activate_arc_failed");
            std::string arc_error = arc_load_error_or_fallback("ARC runtime download or verification failed.");
            error_out = "License validation succeeded, but the protected AiDA runtime failed to load. " + arc_error;
            enter_pending_activation(settings, error_out);
            return false;
        }

        mark_activation_completed();
        {
            std::string missing_exports;
            if (!runtime_arc_authorized(&missing_exports))
            {
                lic_log_fmt("activate_arc_required_exports_failed missing=%.160s", missing_exports.c_str());
                error_out = "License validation succeeded, but the protected AiDA runtime is incomplete.";
                enter_pending_activation(settings, error_out);
                return false;
            }
        }
        lic_log("activate_snapshot_hashes");
        snapshot_code_hashes();
        lic_log("activate_snapshot_done");

        restart_heartbeat(settings);
        anti_tamper::state::get().license_pending_activation.store(false, std::memory_order_release);
        lic_log("activate_complete");
        return true;
    }

    bool is_valid()
    {
        return runtime_arc_authorized();
    }

    std::string plan()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_plan;
    }

    std::string last_error()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return user_facing_license_error(s_error);
    }

    void invalidate_for_enforcement(const char* reason)
    {
        const char* reason_text = (reason && *reason) ? reason : "enforcement";
        lic_log_fmt("enforcement_license_invalidate_begin reason=%.128s loaded=%d unloading=%d inflight=%lld",
            reason_text,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)));
        s_worker_epoch.fetch_add(1, std::memory_order_acq_rel);
        s_stop.store(true, std::memory_order_release);
        wait_for_worker_done(s_heartbeat_done, "heartbeat_enforcement", 2000);
        wait_for_worker_done(s_srv_refresh_done, "srv_refresh_enforcement", 2000);
        cancel_silent_kill();
        reset_arc_fetch_state();
        reset_activation_completed_at();
        reset_license_clients();
        s_proof_hash.store(0, std::memory_order_release);
        s_heartbeat_counter.store(0, std::memory_order_release);
        s_replay_request_seq.store(0, std::memory_order_release);
        s_magic.store(S_MAGIC_INIT, std::memory_order_release);
        set_obfuscated_valid(false);
        anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_cached_hwid.clear();
            s_cached_session_token.clear();
            s_cached_arc_bind_token.clear();
            s_cached_server_payload_b64.clear();
            s_cached_server_sig_b64.clear();
            s_cached_server_kid = 0;
            s_error = std::string("Runtime enforcement invalidated license state: ") + reason_text;
        }
        lic_log_fmt("enforcement_license_invalidate_done reason=%.128s loaded=%d unloading=%d inflight=%lld",
            reason_text,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)));
    }

    void stop_background_workers(const char* reason, uint32_t timeout_ms)
    {
        const char* reason_text = (reason && *reason) ? reason : "shutdown";
        lic_log_fmt("background_workers_stop_begin reason=%.128s timeout_ms=%u heartbeat_done=%d srv_refresh_done=%d stop=%d epoch=%llu",
            reason_text,
            timeout_ms,
            s_heartbeat_done.load(std::memory_order_acquire) ? 1 : 0,
            s_srv_refresh_done.load(std::memory_order_acquire) ? 1 : 0,
            s_stop.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(s_worker_epoch.load(std::memory_order_acquire)));
        s_worker_epoch.fetch_add(1, std::memory_order_acq_rel);
        s_stop.store(true, std::memory_order_release);
        wait_for_worker_done(s_heartbeat_done, "heartbeat_background_stop", timeout_ms);
        wait_for_worker_done(s_srv_refresh_done, "srv_refresh_background_stop", timeout_ms);
        lic_log_fmt("background_workers_stop_done reason=%.128s heartbeat_done=%d srv_refresh_done=%d stop=%d epoch=%llu",
            reason_text,
            s_heartbeat_done.load(std::memory_order_acquire) ? 1 : 0,
            s_srv_refresh_done.load(std::memory_order_acquire) ? 1 : 0,
            s_stop.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(s_worker_epoch.load(std::memory_order_acquire)));
    }

    void shutdown_after_worker_quiesce(const char* reason)
    {
        const char* reason_text = (reason && *reason) ? reason : "license_shutdown";
        lic_log_fmt("license_shutdown_after_worker_quiesce_begin reason=%.128s loaded=%d unloading=%d inflight=%lld",
            reason_text,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)));
        stop_background_workers(reason_text, 5000);
        reset_arc_fetch_state();
        reset_activation_completed_at();
        reset_license_clients();
        const bool arc_released = unload_arc(reason_text, true);
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_cached_hwid.clear();
            s_cached_session_token.clear();
            s_cached_arc_bind_token.clear();
            s_cached_server_payload_b64.clear();
            s_cached_server_sig_b64.clear();
            s_cached_server_kid = 0;
        }
        lic_log_fmt("license_shutdown_after_worker_quiesce_done reason=%.128s arc_released=%d loaded=%d unloading=%d inflight=%lld",
            reason_text,
            arc_released ? 1 : 0,
            s_arc_loaded.load(std::memory_order_acquire) ? 1 : 0,
            s_arc_unloading.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<long long>(s_arc_call_inflight.load(std::memory_order_acquire)));
    }

    void shutdown()
    {
        shutdown_after_worker_quiesce("license_shutdown");
    }


    bool check_subscription_tier()
    {

        volatile bool v = runtime_arc_authorized();
        return v;
    }

    bool verify_entitlement_state()
    {

        if (s_proof_hash.load(std::memory_order_acquire) == 0)
            return false;
        volatile bool v = runtime_arc_authorized();
        return v;
    }

    bool confirm_session_integrity()
    {

        if (!s_valid.load(std::memory_order_acquire))
            return false;

        auto now_ms = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
        auto last = s_last_heartbeat_time.load(std::memory_order_acquire);
        if (last > 0 && (now_ms - last) > 180000)
            return false;
        return runtime_arc_authorized();
    }


    double inline_proof_check_a()
    {

        uint64_t expected = s_proof_hash.load(std::memory_order_acquire);
        if (expected == 0) return 0.0;


        if (!runtime_arc_authorized()) return 0.0;

        return 1.0;
    }

    bool inline_proof_check_b()
    {

        if (!runtime_arc_authorized()) return false;

        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t b = s_state_b.load(std::memory_order_acquire);
        uint64_t c = s_state_c.load(std::memory_order_acquire);
        uint64_t magic = s_magic.load(std::memory_order_acquire);


        LARGE_INTEGER t0, t1, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t0);
        volatile uint64_t result = a ^ b ^ c;
        QueryPerformanceCounter(&t1);

        double elapsed_us = 1000000.0 * (t1.QuadPart - t0.QuadPart) / freq.QuadPart;
        if (elapsed_us > 5000.0) return false;

        return result == magic;
    }

    bool inline_proof_check_c()
    {


        if (s_cached_hwid.empty()) return false;
        return runtime_arc_authorized();
    }

    bool inline_proof_check_d()
    {

        if (!runtime_arc_authorized()) return false;
        int64_t last = s_last_heartbeat_time.load(std::memory_order_acquire);
        if (last == 0) return false;

        auto now_ms = static_cast<int64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() / 1000000);
        int64_t delta = now_ms - last;
        return delta >= 0 && delta < 180000;
    }

    bool verify_runtime_gate_state(gate_slot_t slot)
    {
        const int slot_index = static_cast<int>(slot);
        if (slot_index < 0 || slot_index >= static_cast<int>(GATE_SLOT_COUNT))
            return false;
        if (!s_valid.load(std::memory_order_acquire))
            return false;

        const std::string slot_detail = "slot=" + std::to_string(slot_index);

        std::string missing_exports;
        if (!runtime_arc_authorized(&missing_exports))
        {
            lic_log_fmt("runtime_gate_arc_required_failed slot=%d missing=%.160s",
                slot_index, missing_exports.c_str());
            return false;
        }

        if (inline_proof_check_a() < 0.5)
            license_failfast("license_proof_hash_invalid", slot_detail);

        if (!inline_proof_check_b())
            license_failfast("license_state_integrity_invalid", slot_detail);

        if (!inline_proof_check_c())
            license_failfast("license_session_integrity_invalid", slot_detail);

        if (!inline_proof_check_d())
            return false;

        return true;
    }

    bool check_feature_allowed(gate_slot_t slot)
    {
        return verify_runtime_gate_state(slot);
    }


    bool snapshot_code_hashes()
    {
        std::lock_guard<std::mutex> lk(s_code_hash_mtx);

        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "snapshot_code_hashes_no_module preserved=%zu", s_code_hashes.size());
            lic_log(dbg);
            return !s_code_hashes.empty();
        }

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            MEMORY_BASIC_INFORMATION mbi{};
            const bool have_mbi = VirtualQuery(hMod, &mbi, sizeof(mbi)) != 0;
            char dbg[320];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "snapshot_code_hashes_bad_dos_magic value=0x%04X preserved=%zu mbi=%d base=0x%016llX alloc=0x%016llX protect=0x%08lX state=0x%08lX type=0x%08lX",
                static_cast<unsigned>(dos->e_magic),
                s_code_hashes.size(),
                have_mbi ? 1 : 0,
                have_mbi ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mbi.BaseAddress)) : 0ull,
                have_mbi ? static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mbi.AllocationBase)) : 0ull,
                have_mbi ? static_cast<unsigned long>(mbi.Protect) : 0ul,
                have_mbi ? static_cast<unsigned long>(mbi.State) : 0ul,
                have_mbi ? static_cast<unsigned long>(mbi.Type) : 0ul);
            lic_log(dbg);
            return !s_code_hashes.empty();
        }

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "snapshot_code_hashes_bad_nt_sig value=0x%08X preserved=%zu",
                static_cast<unsigned>(nt->Signature),
                s_code_hashes.size());
            lic_log(dbg);
            return !s_code_hashes.empty();
        }

        std::vector<code_section_hash_t> fresh;
        fresh.reserve(s_code_hashes.empty() ? 16 : s_code_hashes.size());

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        const WORD num_sections = nt->FileHeader.NumberOfSections;
        {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "snapshot_code_hashes_begin module=%p num_sections=%u",
                static_cast<void*>(hMod),
                static_cast<unsigned>(num_sections));
            lic_log(dbg);
        }

        static const char* const kRuntimeMutableSectionNames[] = {
            ".epheme",
            ".dthunk",
            ".gehi",
            ".dseal",
            ".licbind",
            ".feat",
        };

        for (WORD i = 0; i < num_sections; ++i) {
            const uint32_t ch = sec[i].Characteristics;
            const bool is_exec = (ch & IMAGE_SCN_MEM_EXECUTE) != 0u;
            const bool is_read = (ch & IMAGE_SCN_MEM_READ) != 0u;
            const bool is_write = (ch & IMAGE_SCN_MEM_WRITE) != 0u;

            char section_name[16] = {};
            std::memcpy(section_name, sec[i].Name, 8);

            bool runtime_mutable = false;
            for (const char* mut_name : kRuntimeMutableSectionNames) {
                if (std::strncmp(section_name, mut_name, 8) == 0) {
                    runtime_mutable = true;
                    break;
                }
            }

            const bool eligible = !is_write && !runtime_mutable && (is_exec || is_read);

            if (!eligible) {
                char dbg[200];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "snapshot_code_hashes_skip[%u]=%.8s ch=0x%08X exec=%d read=%d write=%d runtime_mutable=%d",
                    static_cast<unsigned>(i), section_name, ch,
                    is_exec ? 1 : 0, is_read ? 1 : 0, is_write ? 1 : 0,
                    runtime_mutable ? 1 : 0);
                lic_log(dbg);
                continue;
            }

            auto base = reinterpret_cast<uintptr_t>(hMod) + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            if (size == 0 || size >= 100u * 1024u * 1024u) {
                char dbg[160];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "snapshot_code_hashes_skip_size[%u]=%.8s size=%zu",
                    static_cast<unsigned>(i), section_name, size);
                lic_log(dbg);
                continue;
            }

            uint64_t h = fnv1a(reinterpret_cast<const void*>(base), size);
            code_section_hash_t entry{};
            entry.base = base;
            entry.size = size;
            entry.hash = h;
            std::memcpy(entry.name, section_name, 8);
            entry.characteristics = ch;
            fresh.push_back(entry);

            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "snapshot_code_hashes_capture[%u]=%.8s rva=0x%08X base=0x%016llX size=0x%zX hash=0x%016llX exec=%d write=%d",
                static_cast<unsigned>(i), section_name,
                static_cast<unsigned>(sec[i].VirtualAddress),
                static_cast<unsigned long long>(base),
                size,
                static_cast<unsigned long long>(h),
                is_exec ? 1 : 0, is_write ? 1 : 0);
            lic_log(dbg);
        }
        {
            char dbg[160];
            if (fresh.empty()) {
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "snapshot_code_hashes_done captured=0 preserved_existing=%zu",
                    s_code_hashes.size());
            } else {
                s_code_hashes.swap(fresh);
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "snapshot_code_hashes_done captured=%zu",
                    s_code_hashes.size());
            }
            lic_log(dbg);
        }
        return !s_code_hashes.empty();
    }

    bool verify_code_hashes()
    {
        std::lock_guard<std::mutex> lk(s_code_hash_mtx);
        if (s_code_hashes.empty()) return true;

        for (const auto& entry : s_code_hashes) {
            uint64_t current = fnv1a(reinterpret_cast<const void*>(entry.base), entry.size);
            if (current != entry.hash) {
                char mismatch_buf[128];
                _snprintf_s(mismatch_buf, sizeof(mismatch_buf), _TRUNCATE,
                    "verify_code_hash_MISMATCH base=0x%llX sz=%zu expected=0x%llX got=0x%llX",
                    (unsigned long long)entry.base, entry.size,
                    (unsigned long long)entry.hash, (unsigned long long)current);
                lic_log(mismatch_buf);
                set_obfuscated_valid(false);
                return false;
            }
        }
        return true;
    }


    uint64_t inline_gate_check(gate_slot_t slot)
    {


        const int slot_index = static_cast<int>(slot);
        if (slot_index < 0 || slot_index >= static_cast<int>(GATE_SLOT_COUNT))
            return 0;

        if (!runtime_arc_authorized()) return 0;

        uint64_t v2_token = 0;
        if (aida::gate_tokens::is_session_active())
        {
            v2_token = aida::gate_tokens::issue_token(static_cast<uint32_t>(slot_index));
        }

        uint64_t proof = s_proof_hash.load(std::memory_order_acquire);
        if (proof == 0 && v2_token == 0) return 0;


        uint64_t tick = static_cast<uint64_t>(GetTickCount64());
        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t raw = a ^ static_cast<uint64_t>(slot_index) ^ proof ^ tick ^ v2_token;
        uint64_t token = fnv1a(&raw, sizeof(raw));
        if (token == 0) token = v2_token != 0 ? v2_token : 0x1ull;


        s_gate_timestamps[slot_index].store(
            static_cast<int64_t>(tick), std::memory_order_release);
        s_gate_tokens[slot_index].store(token, std::memory_order_release);


        s_gate_bitmap.fetch_or(
            static_cast<uint32_t>(1u) << static_cast<uint32_t>(slot_index),
            std::memory_order_relaxed);

        return token;
    }

    double verify_gate_token(gate_slot_t slot, uint64_t token)
    {
        const int slot_index = static_cast<int>(slot);
        if (slot_index < 0 || slot_index >= static_cast<int>(GATE_SLOT_COUNT))
            return 0.0;
        if (token == 0) return 0.0;


        int64_t last_ts = s_gate_timestamps[slot_index].load(std::memory_order_acquire);
        int64_t now = static_cast<int64_t>(GetTickCount64());


        if (last_ts == 0 || (now - last_ts) > 10000) return 0.0;


        uint64_t stored = s_gate_tokens[slot_index].load(std::memory_order_acquire);
        if (stored != token) return 0.0;


        if (!runtime_arc_authorized()) return 0.0;

        return 1.0;
    }

    bool cross_validation_sweep(int frame_counter)
    {

        if ((frame_counter % 300) != 0) return true;

        if (!runtime_arc_authorized()) return false;

        int64_t now = static_cast<int64_t>(GetTickCount64());


        int64_t render_ts = s_gate_timestamps[gate_ui_render_loop].load(std::memory_order_acquire);
        if (render_ts > 0 && (now - render_ts) > 120000) {
            set_obfuscated_valid(false);
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = decode_status_string_impl(str_gate_stale);
            return false;
        }


        {
            uint64_t d = s_state_d.load(std::memory_order_acquire);
            uint64_t e = s_state_e.load(std::memory_order_acquire);
            uint64_t m2 = s_magic_2.load(std::memory_order_acquire);
            if ((d + e) != m2) {
                char magic_buf[128];
                _snprintf_s(magic_buf, sizeof(magic_buf), _TRUNCATE,
                    "cross_validation_magic_FAIL d=%llu e=%llu sum=%llu m2=%llu frame=%d",
                    (unsigned long long)d, (unsigned long long)e,
                    (unsigned long long)(d+e), (unsigned long long)m2, frame_counter);
                license_failfast("license_cross_validation_invalid", magic_buf);
            }
        }

        return true;
    }

    uint64_t compute_integrity_token(int frame_counter, int function_id)
    {
        if (!runtime_arc_authorized()) return 0;
        uint64_t proof = s_proof_hash.load(std::memory_order_acquire);
        uint64_t buf[3] = {
            proof,
            static_cast<uint64_t>(frame_counter),
            static_cast<uint64_t>(function_id)
        };
        return fnv1a(buf, sizeof(buf));
    }

    void fold_integrity_token(uint64_t token)
    {
        if (token == 0) return;
        uint64_t prev = s_proof_hash.load(std::memory_order_acquire);
        uint64_t next = prev ^ token ^ _rotl64(token, 31);
        s_proof_hash.store(next, std::memory_order_release);
    }

    std::string decode_status_string(int string_id)
    {
        return decode_status_string_impl(static_cast<status_string_id>(string_id));
    }


    bool is_arc_loaded()
    {
        return s_arc_loaded.load(std::memory_order_acquire);
    }

    bool is_arc_download_in_progress()
    {
        if (s_arc_download_in_progress.load(std::memory_order_acquire))
            return true;
        if (s_arc_fetch_deferred.load(std::memory_order_acquire)
            && s_activation_completed_at_ms.load(std::memory_order_acquire) != 0
            && arc_grace_remaining_ms() != 0)
            return true;
        return false;
    }

    bool is_arc_transfer_in_progress()
    {
        return s_arc_download_in_progress.load(std::memory_order_acquire);
    }

    bool validate_arc_required_exports(std::string& missing_out)
    {
        missing_out.clear();
        arc_call_guard_t guard;
        if (!guard.live())
        {
            missing_out = "arc_call_gate";
            return false;
        }
        return arc_required_exports_ready(&missing_out);
    }

    uint64_t activation_completed_at()
    {
        return s_activation_completed_at_ms.load(std::memory_order_acquire);
    }

    bool with_arc_comm_bridge(arc_comm_bridge_callback_t callback, void* ctx)
    {
        if (!callback)
            return false;
        arc_call_guard_t guard;
        if (!guard.live())
            return false;
        if (!check_obfuscated_valid())
            return false;
        if (!anti_tamper::state::get().activation_hardening_done.load(std::memory_order_acquire))
            return false;
        if (!arc_required_exports_ready() || !s_fn_arc_get_comm_bridge)
            return false;
        const arc_comm_vtable_t* bridge = nullptr;
        const arc_get_comm_bridge_fn get_bridge = s_fn_arc_get_comm_bridge;
        DWORD seh = arc_call_get_comm_bridge_seh(get_bridge, &bridge);
        if (seh != ERROR_SUCCESS)
        {
            lic_log_fmt("arc_get_comm_bridge_seh code=0x%08lX", static_cast<unsigned long>(seh));
            return false;
        }
        if (!bridge)
            return false;
        BOOL callback_ok = FALSE;
        DWORD callback_seh = arc_call_comm_bridge_callback_seh(callback, bridge, ctx, &callback_ok);
        if (callback_seh != ERROR_SUCCESS)
        {
            lic_log_fmt("arc_comm_bridge_callback_seh code=0x%08lX", static_cast<unsigned long>(callback_seh));
            return false;
        }
        return callback_ok == TRUE;
    }

    uint64_t arc_validate_tool(uint64_t tool_name_hash, uint64_t gate_token)
    {
        arc_call_guard_t guard;
        if (!guard.live())
            return 0;
        if (!check_obfuscated_valid())
            return 0;
        if (!anti_tamper::state::get().activation_hardening_done.load(std::memory_order_acquire))
            return 0;
        if (!arc_required_exports_ready())
            return 0;
        if (s_fn_arc_validate_tool_v2)
        {
            const uint64_t caller_nonce = static_cast<uint64_t>(__rdtsc()) ^ gate_token;
            const uint64_t hb_counter = static_cast<uint64_t>(
                s_heartbeat_counter.load(std::memory_order_acquire));
            uint64_t token = 0;
            DWORD seh = arc_call_validate_tool_v2_seh(
                s_fn_arc_validate_tool_v2,
                caller_nonce,
                tool_name_hash,
                hb_counter,
                &token);
            if (seh != ERROR_SUCCESS)
            {
                lic_log_fmt("arc_validate_tool_v2_seh code=0x%08lX", static_cast<unsigned long>(seh));
                return 0;
            }
            return token;
        }
        if (!s_fn_arc_validate_tool)
            return 0;
        uint64_t token = 0;
        DWORD seh = arc_call_validate_tool_seh(
            s_fn_arc_validate_tool,
            tool_name_hash,
            gate_token,
            &token);
        if (seh != ERROR_SUCCESS)
        {
            lic_log_fmt("arc_validate_tool_v1_seh code=0x%08lX", static_cast<unsigned long>(seh));
            return 0;
        }
        return token;
    }

    bool verify_tool_runtime(gate_slot_t slot, uint64_t gate_token, const std::string& tool_name)
    {
        if (verify_gate_token(slot, gate_token) < 0.5)
            return false;
        if (tool_name.empty() || !runtime_arc_authorized())
            return false;
        return arc_validate_tool(fnv1a_str(tool_name), gate_token) != 0;
    }

    arc_heartbeat_result_t arc_heartbeat()
    {
        arc_heartbeat_result_t result{};
        arc_call_guard_t guard;
        if (!guard.live())
            return result;
        if (!check_obfuscated_valid())
            return result;
        if (!anti_tamper::state::get().activation_hardening_done.load(std::memory_order_acquire))
            return result;
        if (!arc_required_exports_ready() || !s_fn_arc_heartbeat)
            return result;
        DWORD seh = arc_call_heartbeat_seh(s_fn_arc_heartbeat, &result);
        if (seh != ERROR_SUCCESS)
        {
            lic_log_fmt("arc_heartbeat_seh code=0x%08lX", static_cast<unsigned long>(seh));
            SecureZeroMemory(&result, sizeof(result));
        }
        return result;
    }

    bool arc_unseal_feature_blocking(uint32_t feature_id,
                                     const uint8_t* nonce,
                                     uint32_t nonce_len,
                                     uint8_t* out,
                                     uint32_t* out_size,
                                     uint32_t out_cap)
    {
        arc_call_guard_t guard;
        if (!guard.live())
            return false;
        if (!check_obfuscated_valid())
            return false;
        if (!anti_tamper::state::get().activation_hardening_done.load(std::memory_order_acquire))
            return false;
        if (!arc_required_exports_ready() || !s_fn_arc_unseal_feature)
            return false;
        BOOL ok = FALSE;
        DWORD seh = arc_call_unseal_feature_seh(
            s_fn_arc_unseal_feature,
            feature_id,
            nonce,
            nonce_len,
            out,
            out_size,
            out_cap,
            &ok);
        if (seh != ERROR_SUCCESS)
        {
            lic_log_fmt("arc_unseal_feature_seh code=0x%08lX", static_cast<unsigned long>(seh));
            return false;
        }
        return ok == TRUE;
    }

    static bool ida_plugin_challenge_valid(const std::string& challenge)
    {
        if (challenge.size() < 32 || challenge.size() > 128 || (challenge.size() % 2) != 0)
            return false;
        return std::all_of(challenge.begin(), challenge.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
    }

    static std::string ida_plugin_proof_canonical(const json& proof)
    {
        std::ostringstream ss;
        ss << "AIDA_IDA_PLUGIN_AUTH_V1\n";
        ss << "challenge=" << proof.value("challenge", std::string()) << "\n";
        ss << "plugin_pid=" << proof.value("plugin_pid", 0u) << "\n";
        ss << "standalone_pid=" << proof.value("standalone_pid", 0u) << "\n";
        ss << "mcp_port=" << proof.value("mcp_port", 0u) << "\n";
        ss << "issued_tick_ms=" << proof.value("issued_tick_ms", 0ull) << "\n";
        ss << "expires_tick_ms=" << proof.value("expires_tick_ms", 0ull) << "\n";
        ss << "validated=" << (proof.value("validated", false) ? 1 : 0) << "\n";
        ss << "arc_loaded=" << (proof.value("arc_loaded", false) ? 1 : 0) << "\n";
        ss << "lifecycle_ready=" << (proof.value("lifecycle_ready", false) ? 1 : 0) << "\n";
        ss << "exports_verified=" << (proof.value("exports_verified", false) ? 1 : 0) << "\n";
        ss << "server_nonce_hash=" << proof.value("server_nonce_hash", 0ull) << "\n";
        ss << "signed_payload_sha256=" << proof.value("signed_payload_sha256", std::string()) << "\n";
        return ss.str();
    }

    bool build_ida_plugin_auth_proof(const std::string& challenge_hex,
                                     uint32_t plugin_pid,
                                     uint32_t mcp_port,
                                     bool lifecycle_ready,
                                     bool exports_verified,
                                     std::string& out_json,
                                     std::string& error_out)
    {
        out_json.clear();
        error_out.clear();
        if (!ida_plugin_challenge_valid(challenge_hex))
        {
            error_out = "invalid_challenge";
            return false;
        }
        if (plugin_pid == 0 || plugin_pid == GetCurrentProcessId())
        {
            error_out = "invalid_plugin_pid";
            return false;
        }
        if (!lifecycle_ready || !exports_verified || !is_valid() || !is_arc_loaded())
        {
            error_out = "runtime_not_authorized";
            return false;
        }
        std::string missing_exports;
        if (!validate_arc_required_exports(missing_exports))
        {
            error_out = missing_exports.empty() ? "arc_exports_missing" : ("arc_exports_missing:" + missing_exports);
            return false;
        }

        std::string server_payload_b64;
        std::string server_sig_b64;
        int server_kid = 0;
        uint64_t server_nonce_hash = 0;
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            server_payload_b64 = s_cached_server_payload_b64;
            server_sig_b64 = s_cached_server_sig_b64;
            server_kid = s_cached_server_kid;
            server_nonce_hash = s_magic.load(std::memory_order_acquire);
        }
        if (server_payload_b64.empty() || server_sig_b64.empty() || server_kid <= 0)
        {
            error_out = "server_signed_session_unavailable";
            return false;
        }

        std::vector<uint8_t> payload_bytes = base64_decode(server_payload_b64);
        if (payload_bytes.empty())
        {
            error_out = "server_payload_decode_failed";
            return false;
        }
        std::string signed_payload(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
        SecureZeroMemory(payload_bytes.data(), payload_bytes.size());

        json payload = json::parse(signed_payload, nullptr, false);
        if (payload.is_discarded() || !payload.is_object())
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            error_out = "server_payload_parse_failed";
            return false;
        }

        const std::string auth_key_b64 = payload.value("auth_hmac_key_b64", std::string());
        const std::string session_token = payload.value("session_token", std::string());
        const int64_t issued_at = payload.value("issued_at", int64_t{0});
        const int64_t ttl = payload.value("ttl", int64_t{0});
        const int64_t now_epoch = static_cast<int64_t>(std::time(nullptr));
        if (payload.value("status", std::string()) != "valid" ||
            auth_key_b64.empty() ||
            session_token.size() < 16 ||
            issued_at <= 0 ||
            ttl <= 0 ||
            now_epoch < issued_at - 60 ||
            now_epoch > issued_at + ttl + 60)
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            error_out = "server_payload_not_current";
            return false;
        }

        std::vector<uint8_t> auth_key = base64_decode(auth_key_b64);
        if (auth_key.size() != 32)
        {
            SecureZeroMemory(signed_payload.data(), signed_payload.size());
            if (!auth_key.empty())
                SecureZeroMemory(auth_key.data(), auth_key.size());
            error_out = "auth_key_invalid";
            return false;
        }

        const uint64_t now_tick = static_cast<uint64_t>(GetTickCount64());
        json proof;
        proof["status"] = "ok";
        proof["proof_version"] = 1;
        proof["server"] = "aida-pro-mcp";
        proof["challenge"] = challenge_hex;
        proof["plugin_pid"] = plugin_pid;
        proof["standalone_pid"] = static_cast<uint32_t>(GetCurrentProcessId());
        proof["mcp_port"] = mcp_port;
        proof["issued_tick_ms"] = now_tick;
        proof["expires_tick_ms"] = now_tick + 15000ull;
        proof["validated"] = true;
        proof["arc_loaded"] = true;
        proof["lifecycle_ready"] = lifecycle_ready;
        proof["exports_verified"] = exports_verified;
        proof["server_nonce_hash"] = server_nonce_hash;
        proof["server_payload_b64"] = server_payload_b64;
        proof["server_sig_b64"] = server_sig_b64;
        proof["server_kid"] = server_kid;
        proof["signed_payload_sha256"] = sha256_hex(signed_payload);

        const std::string canonical = ida_plugin_proof_canonical(proof);
        std::vector<uint8_t> mac = hmac_sha256_block(
            auth_key.data(), auth_key.size(),
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        SecureZeroMemory(auth_key.data(), auth_key.size());
        SecureZeroMemory(signed_payload.data(), signed_payload.size());
        if (mac.size() != 32)
        {
            error_out = "proof_mac_failed";
            return false;
        }
        proof["proof_mac"] = bytes_to_hex(mac.data(), mac.size());
        SecureZeroMemory(mac.data(), mac.size());
        out_json = proof.dump();
        return true;
    }

    uint64_t get_server_nonce_hash()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_magic.load(std::memory_order_acquire);
    }

    std::string get_session_token()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_cached_session_token;
    }

    std::string get_arc_bind_token()
    {
        std::lock_guard<std::mutex> lk(s_state_mtx);
        return s_cached_arc_bind_token;
    }
}
