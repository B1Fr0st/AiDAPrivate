#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "standalone_license.hpp"

#include "standalone_settings.hpp"
#include "standalone_driver.hpp"
#include "arc/arc.h"
#include "arc_loader.hpp"
#include "anti-tamper/vm_compiler.hpp"
#include "anti-tamper/server_pages.hpp"
#include "tls_exporter.hpp"
#include "obfuscation.hpp"

#include <windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <psapi.h>
#include <dbghelp.h>
#include <bcrypt.h>

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

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "dnsapi.lib")

using json = nlohmann::json;

static void lic_log(const char* step)
{

    static char s_log_path[MAX_PATH] = {};
    static INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;
    BOOL pending;
    InitOnceBeginInitialize(&s_once, INIT_ONCE_ASYNC, &pending, nullptr);
    if (pending || s_log_path[0] == '\0') {
        DWORD n = GetModuleFileNameA(nullptr, s_log_path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) {
            strcpy_s(s_log_path, "aida_debug.log");
        } else {
            char* last = strrchr(s_log_path, '\\');
            if (last) *(last + 1) = '\0'; else s_log_path[0] = '\0';
            strcat_s(s_log_path, "aida_debug.log");
        }
        InitOnceComplete(&s_once, INIT_ONCE_ASYNC, nullptr);
    }

    HANDLE hf = CreateFileA(s_log_path, FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[1024];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [license] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, step);
    if (len > 0) { DWORD w; WriteFile(hf, line, (DWORD)len, &w, nullptr); }
    CloseHandle(hf);
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

    lic_log("winhttp_calling_send_request");
    BOOL send_ok = p_send_request(h_req, hdr_ptr, hdr_len,
                                   body_ptr, body_len, body_len, 0);
    if (!send_ok) {
        out.error = "winhttp_send_request_failed gle=" + std::to_string(GetLastError());
        lic_log(out.error.c_str());
        p_close_handle(h_req);
        p_close_handle(h_connect);
        p_close_handle(h_session);
        FreeLibrary(wh_mod);
        return out;
    }
    lic_log("winhttp_send_request_ok");

    lic_log("winhttp_calling_recv_response");
    if (!p_recv_response(h_req, nullptr)) {
        out.error = "winhttp_recv_response_failed gle=" + std::to_string(GetLastError());
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
    static std::atomic<bool> s_winhttp_disabled{false};
    SimpleHttpResponse out;

    if (s_winhttp_disabled.load(std::memory_order_acquire)) {
        out.error = "winhttp skipped after prior bounded timeout";
        lic_log("winhttp_outer_skipped_disabled");
        return out;
    }

    const int budget_sec = timeout_sec > 0 ? timeout_sec : 15;
    const int budget_ms_total = std::max(1000, budget_sec * 1000 + 500);

    auto out_shared = std::make_shared<SimpleHttpResponse>();
    auto done_flag = std::make_shared<std::atomic<bool>>(false);
    const std::string verb_copy = verb ? verb : "GET";
    const std::string url_copy = url;
    const std::string body_copy = req_body;
    const std::string ct_copy = content_type;
    const auto hdr_copy = extra_headers;
    const int tmo_copy = budget_sec;

    try {
        std::thread([out_shared, done_flag, verb_copy, url_copy, hdr_copy,
                      body_copy, ct_copy, tmo_copy]() {
            lic_log("winhttp_outer_thread_begin");
            *out_shared = winhttp_https_request_impl(verb_copy.c_str(), url_copy,
                                                     hdr_copy, body_copy, ct_copy,
                                                     tmo_copy);
            lic_log("winhttp_outer_thread_done");
            done_flag->store(true, std::memory_order_release);
        }).detach();
    } catch (...) {
        s_winhttp_disabled.store(true, std::memory_order_release);
        out.error = "winhttp worker spawn failed";
        lic_log("winhttp_outer_thread_spawn_failed");
        return out;
    }

    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(budget_ms_total);
    while (!done_flag->load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!done_flag->load(std::memory_order_acquire)) {
        s_winhttp_disabled.store(true, std::memory_order_release);
        char dbuf[192];
        _snprintf_s(dbuf, sizeof(dbuf), _TRUNCATE,
            "winhttp_outer_total_timeout budget_ms=%d url=%.120s",
            budget_ms_total, url_copy.c_str());
        lic_log(dbuf);
        out.error = "winhttp_total_timeout";
        return out;
    }
    return *out_shared;
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

    try {
        std::thread([diag_host, diag_port]() {
            __try {
                diagnose_network(diag_host.c_str(), diag_port);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
            }
        }).detach();
        lic_log("transport_diag_thread_dispatched");
    } catch (...) {
        lic_log("transport_diag_thread_spawn_failed");
    }
}

static SimpleHttpResponse raw_https_request(
    const char* verb,
    const std::string& url,
    const std::vector<std::pair<std::string,std::string>>& extra_headers = {},
    const std::string& req_body = {},
    const std::string& content_type = {},
    int timeout_sec = 15)
{
    static std::atomic<bool> s_curl_preferred{false};
    {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_begin verb=%.8s url=%.140s body_len=%zu timeout=%d",
            verb ? verb : "?", url.c_str(), req_body.size(), timeout_sec);
        lic_log(buf);
    }

    SimpleHttpResponse winhttp_out = winhttp_https_request(verb, url, extra_headers,
                                                            req_body, content_type,
                                                            timeout_sec);
    if (winhttp_out.ok || winhttp_out.status > 0) {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_winhttp_ok status=%d body_len=%zu",
            winhttp_out.status, winhttp_out.body.size());
        lic_log(buf);
        return winhttp_out;
    }

    {
        char buf[384];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_winhttp_failed err=%.220s falling_back_to_raw",
            winhttp_out.error.c_str());
        lic_log(buf);
    }

    const bool curl_first = s_curl_preferred.load(std::memory_order_acquire) ||
        winhttp_out.error.find("worker spawn failed") != std::string::npos;
    SimpleHttpResponse curl_out;
    bool curl_attempted = false;
    if (curl_first) {
        lic_log("https_request_preferring_curl");
        curl_attempted = true;
        curl_out = curl_subprocess_https_request(verb, url, extra_headers,
                                                 req_body, content_type,
                                                 timeout_sec);
        if (curl_out.ok || curl_out.status > 0) {
            s_curl_preferred.store(true, std::memory_order_release);
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "https_request_curl_ok status=%d body_len=%zu",
                curl_out.status, curl_out.body.size());
            lic_log(buf);
            return curl_out;
        }
        {
            char buf[384];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "https_request_curl_failed err=%.220s falling_back_to_raw",
                curl_out.error.c_str());
            lic_log(buf);
        }
    }

    SimpleHttpResponse raw_out = raw_https_request_socket(verb, url, extra_headers,
                                                           req_body, content_type,
                                                           timeout_sec);
    if (raw_out.ok || raw_out.status > 0) {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_raw_ok status=%d body_len=%zu",
            raw_out.status, raw_out.body.size());
        lic_log(buf);
        return raw_out;
    }

    if (raw_out.error.find("DNS resolution failed") != std::string::npos ||
        raw_out.error.find("resolve_timeout") != std::string::npos) {
        s_curl_preferred.store(true, std::memory_order_release);
    }

    {
        char buf[384];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            curl_attempted ? "https_request_raw_failed err=%.220s" :
                             "https_request_raw_failed err=%.220s falling_back_to_curl",
            raw_out.error.c_str());
        lic_log(buf);
    }

    if (curl_attempted) {
        if (!winhttp_out.error.empty()) {
            raw_out.error += " | winhttp_primary: ";
            raw_out.error += winhttp_out.error;
        }
        if (!curl_out.error.empty()) {
            raw_out.error += " | curl_subprocess: ";
            raw_out.error += curl_out.error;
        }
        schedule_async_network_diagnosis(url);
        return raw_out;
    }

    curl_out = curl_subprocess_https_request(verb, url, extra_headers,
                                             req_body, content_type,
                                             timeout_sec);
    if (curl_out.ok || curl_out.status > 0) {
        s_curl_preferred.store(true, std::memory_order_release);
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_curl_ok status=%d body_len=%zu",
            curl_out.status, curl_out.body.size());
        lic_log(buf);
        return curl_out;
    }

    {
        char buf[384];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "https_request_curl_failed err=%.220s",
            curl_out.error.c_str());
        lic_log(buf);
    }

    schedule_async_network_diagnosis(url);

    if (!winhttp_out.error.empty()) {
        raw_out.error += " | winhttp_primary: ";
        raw_out.error += winhttp_out.error;
    }
    if (!curl_out.error.empty()) {
        raw_out.error += " | curl_subprocess: ";
        raw_out.error += curl_out.error;
    }
    return raw_out;
}

namespace
{


    constexpr uint64_t S_MAGIC_INIT = 0xA1DA'C0DE'DEAD'BEEFull;
    std::atomic<uint64_t> s_state_a{0};
    std::atomic<uint64_t> s_state_b{0};
    std::atomic<uint64_t> s_state_c{0};
    std::atomic<uint64_t> s_magic{S_MAGIC_INIT};

    /* Legacy atomic kept for backward-compat with existing checks */
    std::atomic<bool> s_valid{false};
    std::atomic<bool> s_stop{false};
    std::thread       s_heartbeat_thread;
    std::thread       s_srv_refresh_thread;
    std::mutex        s_state_mtx;
    std::string       s_plan;
    std::string       s_error;

    /* Heartbeat freshness tracking */
    std::atomic<int64_t> s_last_heartbeat_time{0};
    std::atomic<uint32_t> s_heartbeat_counter{0};

    /* Phase 5.2: 24-bit gate bitmap. Each bit = one anti-tamper gate has
       fired at least once this session. Monotonic; server rejects shrinks. */
    std::atomic<uint32_t> s_gate_bitmap{0};

    /* Cached HWID for inline re-derivation check */
    std::string s_cached_hwid;

    std::string s_cached_session_token;

    /* Proof hash: FNV-1a of (session_token + hwid) */
    std::atomic<uint64_t> s_proof_hash{0};

    /* Code integrity hashes (populated at startup) */
    struct code_section_hash_t {
        uintptr_t base;
        size_t    size;
        uint64_t  hash;
    };
    std::vector<code_section_hash_t> s_code_hashes;
    std::mutex s_code_hash_mtx;

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
    std::mutex                   s_arc_mtx;
    bool                         s_arc_loaded = false;
    std::atomic<bool>            s_arc_fetch_deferred{false};
    std::atomic<uint64_t>        s_activation_completed_at_ms{0};


    std::shared_ptr<httplib::Client> s_license_client;
    std::string                      s_license_host;
    std::shared_ptr<httplib::Client> s_ip_client;
    std::string                      s_ip_host;
    std::mutex                       s_http_mtx;


    using arc_init_fn           = bool(*)(const char*, const char*, int64_t, uint32_t);
    using arc_get_comm_bridge_fn = const arc_comm_vtable_t*(*)();
    using arc_validate_tool_fn  = uint64_t(*)(uint64_t, uint64_t);
    using arc_heartbeat_fn      = arc_heartbeat_result_t(*)();
    using arc_cleanup_fn        = void(*)();
    using arc_set_key_seed_fn   = void(*)(const uint8_t*, uint32_t);

    arc_init_fn           s_fn_arc_init            = nullptr;
    arc_get_comm_bridge_fn s_fn_arc_get_comm_bridge = nullptr;
    arc_validate_tool_fn  s_fn_arc_validate_tool   = nullptr;
    arc_heartbeat_fn      s_fn_arc_heartbeat       = nullptr;
    arc_cleanup_fn        s_fn_arc_cleanup          = nullptr;
    arc_set_key_seed_fn   s_fn_arc_set_key_seed    = nullptr;

    std::string s_challenge_id;
    std::string s_challenge_nonce;
    std::mutex  s_challenge_mtx;

    std::string s_tls_exporter_value;
    std::mutex  s_tls_exporter_mtx;

    std::vector<std::string> s_honeypot_called_names;
    std::mutex s_honeypot_names_mtx;

    constexpr uint64_t kArcRequiredGraceMs = 60000;

    bool download_and_load_arc(settings_sa_t& settings, const std::string& hwid, uint32_t attempt_number);
    bool call_validation_endpoint(settings_sa_t& settings,
                                  const std::string& action,
                                  const std::string& key,
                                  const std::string& hwid,
                                  const std::string& session_token,
                                  const std::string& nonce,
                                  std::string& error_out,
                                  json& response_out);

    uint64_t license_now_ms()
    {
        return static_cast<uint64_t>(GetTickCount64());
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
        uint64_t activation_completed_at_ms = s_activation_completed_at_ms.load(std::memory_order_acquire);
        if (activation_completed_at_ms == 0)
            return s_arc_fetch_deferred.load(std::memory_order_acquire);
        return (license_now_ms() - activation_completed_at_ms) < kArcRequiredGraceMs;
    }

    void defer_arc_fetch()
    {
        s_arc_fetch_deferred.store(true, std::memory_order_release);
    }

    bool relay_server_token_v2_if_ready(uint32_t token_hash, uint64_t server_nonce, uint64_t* out_driver_proof)
    {
        if (!driver_bridge::sentinel_bridge_ready())
            return false;
        return driver_bridge::relay_server_token_v2(token_hash, server_nonce, out_driver_proof);
    }

    bool try_load_arc_with_retries(settings_sa_t& settings, const std::string& hwid)
    {
        static const uint32_t kRetryDelayMs[3] = { 0u, 2000u, 5000u };
        for (uint32_t attempt = 0; attempt < 3; ++attempt)
        {
            if (attempt != 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(kRetryDelayMs[attempt]));

            if (download_and_load_arc(settings, hwid, attempt + 1))
            {
                log_arc_status("arc_download_ok");
                return true;
            }
        }

        return false;
    }

    bool attempt_deferred_arc_fetch(settings_sa_t& settings, const std::string& hwid)
    {
        if (!s_arc_fetch_deferred.load(std::memory_order_acquire) || s_arc_loaded)
            return false;
        if (s_activation_completed_at_ms.load(std::memory_order_acquire) == 0)
            return false;

        s_arc_fetch_deferred.store(false, std::memory_order_release);
        return try_load_arc_with_retries(settings, hwid);
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
        };
        if (id < 0 || id > 5) return "Error";
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
        } else {
            s_state_a.store(0, std::memory_order_release);
            s_state_b.store(0, std::memory_order_release);
            s_state_c.store(0, std::memory_order_release);
            s_valid.store(false, std::memory_order_release);


            s_state_d.store(0, std::memory_order_release);
            s_state_e.store(0, std::memory_order_release);
            set_arc_obfuscated_state(false);
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


    bool check_obfuscated_valid()
    {
        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t b = s_state_b.load(std::memory_order_acquire);
        uint64_t c = s_state_c.load(std::memory_order_acquire);
        uint64_t magic = s_magic.load(std::memory_order_acquire);
        uint64_t arc_magic = s_arc_magic.load(std::memory_order_acquire);
        uint64_t arc_state = (s_arc_loaded || arc_grace_active())
            ? s_arc_state.load(std::memory_order_acquire)
            : 0;
        return (a ^ b ^ c ^ arc_state) == (magic ^ arc_magic);
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

    std::string get_arc_master_secret()
    {
        std::string secret;
        char* env_val = nullptr;
        size_t len = 0;
        if (_dupenv_s(&env_val, &len, "ARC_MASTER_SECRET") == 0 && env_val)
        {
            secret.assign(env_val);
            free(env_val);
        }
        return secret;
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
                        auto ev = aida::tls_exporter::compute_header_value_schannel(ssl);
                        if (!ev.empty()) {
                            std::lock_guard<std::mutex> lk(s_tls_exporter_mtx);
                            s_tls_exporter_value = std::move(ev);
                        }
                    }

                    X509* cert = SSL_get_peer_certificate(ssl);
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
        LARGE_INTEGER counter{};
        QueryPerformanceCounter(&counter);
        std::ostringstream oss;
        oss << std::hex << static_cast<unsigned long long>(GetCurrentProcessId())
            << static_cast<unsigned long long>(GetTickCount64())
            << static_cast<unsigned long long>(counter.QuadPart);
        return oss.str();
    }

    void fnv_mix_u64(uint64_t& hash, uint64_t value)
    {
        for (int i = 0; i < 8; ++i) {
            hash ^= (value >> (i * 8)) & 0xFF;
            hash *= 1099511628211ULL;
        }
    }

    std::string generate_legacy_hwid()
    {
        uint64_t hash = 14695981039346656037ULL;
        auto mix = [&](uint64_t value) {
            hash ^= value;
            hash *= 1099511628211ULL;
        };

        wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(computer_name, &name_size)) {
            for (DWORD i = 0; i < name_size; ++i)
                mix(static_cast<uint64_t>(computer_name[i]));
        } else {
            mix(0xDEADBEEF00000001ULL);
        }

        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        mix((static_cast<uint64_t>(cpu_info[0]) << 32) | static_cast<unsigned>(cpu_info[1]));
        mix((static_cast<uint64_t>(cpu_info[2]) << 32) | static_cast<unsigned>(cpu_info[3]));

        DWORD volume_serial = 0;
        if (GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0)
            && volume_serial != 0) {
            mix(volume_serial);
        } else {
            mix(0xDEADBEEF00000002ULL);
        }

        bool got_guid = false;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Cryptography",
                0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            wchar_t guid[128] = {};
            DWORD size = sizeof(guid);
            DWORD type = 0;
            if (RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                    reinterpret_cast<BYTE*>(guid), &size) == ERROR_SUCCESS
                && type == REG_SZ && guid[0] != L'\0') {
                for (size_t i = 0; guid[i] != L'\0'; ++i)
                    mix(static_cast<uint64_t>(guid[i]));
                got_guid = true;
            }
            RegCloseKey(hKey);
        }
        if (!got_guid) {
            mix(0xDEADBEEF00000003ULL);
        }

        char out[17];
        snprintf(out, sizeof(out), "%016llX", static_cast<unsigned long long>(hash));
        return out;
    }

    std::string generate_hwid()
    {
        uint64_t hash = 14695981039346656037ULL;
        auto mix = [&](uint64_t value) {
            fnv_mix_u64(hash, value);
        };

        DWORD volume_serial = 0;
        GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0);

        wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
        GetComputerNameW(computer_name, &name_size);

        int cpu_info[4] = {};
        __cpuid(cpu_info, 0);
        int cpu_info_ext[4] = {};
        __cpuid(cpu_info_ext, 1);

        mix(static_cast<uint64_t>(volume_serial));
        mix((static_cast<uint64_t>(cpu_info[0]) << 32) | static_cast<unsigned>(cpu_info[1]));
        mix((static_cast<uint64_t>(cpu_info[2]) << 32) | static_cast<unsigned>(cpu_info[3]));
        mix((static_cast<uint64_t>(cpu_info_ext[0]) << 32) | static_cast<unsigned>(cpu_info_ext[3]));
        for (DWORD i = 0; i < name_size; ++i)
            mix(static_cast<uint64_t>(computer_name[i]));

        ULONG len = 0;
        GetAdaptersInfo(nullptr, &len);
        if (len > 0) {
            std::vector<unsigned char> buffer(len);
            auto* adapter = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
            if (GetAdaptersInfo(adapter, &len) == NO_ERROR && adapter) {
                for (UINT i = 0; i < adapter->AddressLength; ++i)
                    mix(static_cast<uint64_t>(adapter->Address[i]));
            }
        }

        char out[17];
        snprintf(out, sizeof(out), "%016llX", static_cast<unsigned long long>(hash));
        return out;
    }

    std::string get_mac_address()
    {
        ULONG len = 0;
        GetAdaptersInfo(nullptr, &len);
        if (len == 0)
            return {};

        std::vector<unsigned char> buffer(len);
        auto* info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        if (GetAdaptersInfo(info, &len) != NO_ERROR || !info || info->AddressLength == 0)
            return {};

        char out[32];
        snprintf(out, sizeof(out), "%02X:%02X:%02X:%02X:%02X:%02X",
                 info->Address[0], info->Address[1], info->Address[2],
                 info->Address[3], info->Address[4], info->Address[5]);
        return out;
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

    void append_hwid_candidate(std::vector<std::string>& candidates, const std::string& hwid)
    {
        if (hwid.empty())
            return;
        if (std::find(candidates.begin(), candidates.end(), hwid) == candidates.end())
            candidates.push_back(hwid);
    }

    std::vector<std::string> collect_hwid_candidates(const settings_sa_t& settings)
    {
        std::vector<std::string> candidates;
        candidates.reserve(3);
        append_hwid_candidate(candidates, generate_hwid());
        append_hwid_candidate(candidates, generate_legacy_hwid());
        append_hwid_candidate(candidates, settings.license_hwid);
        return candidates;
    }

    std::string match_local_hwid(const std::string& hwid, const std::vector<std::string>& candidates)
    {
        if (hwid.empty())
            return {};
        const auto it = std::find(candidates.begin(), candidates.end(), hwid);
        return it == candidates.end() ? std::string() : *it;
    }

    bool call_validation_endpoint_with_hwid_fallback(settings_sa_t& settings,
                                                     const std::string& action,
                                                     const std::string& key,
                                                     const std::string& session_token,
                                                     const std::string& nonce,
                                                     std::string& selected_hwid,
                                                     std::string& error_out,
                                                     json& response_out)
    {
        const auto candidates = collect_hwid_candidates(settings);
        std::string last_error;
        for (const auto& candidate_hwid : candidates) {
            lic_log((std::string("validate_hwid_candidate=") + candidate_hwid + " action=" + action).c_str());
            json candidate_response;
            std::string candidate_error;
            if (call_validation_endpoint(settings, action, key, candidate_hwid, session_token,
                                         nonce, candidate_error, candidate_response)) {
                selected_hwid = candidate_hwid;
                error_out.clear();
                response_out = std::move(candidate_response);
                return true;
            }
            if (!(action == "validate" && candidate_error == "hwid_mismatch")) {
                error_out = std::move(candidate_error);
                return false;
            }
            last_error = std::move(candidate_error);
        }
        error_out = last_error.empty() ? "hwid_mismatch" : last_error;
        return false;
    }

    bool run_startup_ban_check(settings_sa_t& settings, std::string& reason_out, std::string& message_out)
    {
        reason_out.clear();
        message_out.clear();

        json body;
        body["action"] = "ban_check";
        body["timestamp"] = static_cast<int64_t>(std::time(nullptr));
        body["plugin_version"] = "aida-standalone";
        body["mac_address"] = get_mac_address();

        const auto candidates = collect_hwid_candidates(settings);
        body["hwids"] = json::array();
        for (const auto& hwid : candidates)
            body["hwids"].push_back(hwid);
        if (!candidates.empty())
            body["hwid"] = candidates.front();

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

    bool fetch_challenge()
    {
        lic_log("fetch_challenge_enter");
        std::string host = get_cloud_function_host();
        auto resp = raw_https_request("GET", host + "/api/license/challenge");
        if (!resp.ok) {
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "fetch_challenge_fail winhttp err=%s", resp.error.c_str());
            lic_log(buf);
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
                    return false;
                }
            } else {
                char buf[128];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "fetch_challenge_http status=%d", resp.status);
                lic_log(buf);
                return false;
            }
        }

        auto j = json::parse(resp.body, nullptr, false);
        if (j.is_discarded() || !j.is_object()) return false;

        std::string cid = j.value("challenge_id", "");
        std::string cnonce = j.value("challenge_nonce", "");
        if (cid.empty() || cnonce.empty()) return false;

        std::lock_guard<std::mutex> lk(s_challenge_mtx);
        s_challenge_id = std::move(cid);
        s_challenge_nonce = std::move(cnonce);
        return true;
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
        fetch_challenge();

        std::vector<std::pair<std::string,std::string>> hdrs;
        {
            std::lock_guard<std::mutex> lk(s_challenge_mtx);
            if (!s_challenge_id.empty() && !s_challenge_nonce.empty()) {
                hdrs.push_back({"X-Challenge-Id", s_challenge_id});
                hdrs.push_back({"X-Challenge-Signature",
                                hmac_sha256_hex(s_challenge_nonce, body_str)});
            }
        }
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
                "endpoint_once_response ok=%d status=%d err=%.80s body=%.150s",
                (int)resp.ok, resp.status, resp.error.c_str(), resp.body.c_str());
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
            error_out = "License service returned HTTP " + std::to_string(resp.status);
            return false;
        }

        response_out = json::parse(resp.body, nullptr, false);
        if (response_out.is_discarded() || !response_out.is_object()) {
            lic_log("endpoint_once_invalid_json");
            error_out = "License service returned invalid JSON.";
            return false;
        }

        const std::string status = response_out.value("status", "");
        {
            char sl[128];
            _snprintf_s(sl, sizeof(sl), _TRUNCATE,
                "endpoint_once_status=%.80s action=%.30s", status.c_str(), action.c_str());
            lic_log(sl);
        }
        if (status != "valid") {
            char rej[256];
            _snprintf_s(rej, sizeof(rej), _TRUNCATE,
                "endpoint_once_rejected status=%.80s reason=%.100s",
                status.c_str(), response_out.value("reason", "").c_str());
            lic_log(rej);
            error_out = response_out.value("reason", status.empty() ? std::string("license rejected") : status);
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
        return true;
    }

    bool call_validation_endpoint(settings_sa_t& settings,
                                  const std::string& action,
                                  const std::string& key,
                                  const std::string& hwid,
                                  const std::string& session_token,
                                  const std::string& nonce,
                                  std::string& error_out,
                                  json& response_out)
    {
        try {
            lic_log("call_validation_enter");
            json body;
            body["action"] = action;
            body["license_key"] = key;
            body["hwid"] = hwid;
            body["timestamp"] = static_cast<int64_t>(std::time(nullptr));
            body["public_ip"] = "";
            lic_log("call_validation_public_ip_skipped");
            body["mac_address"] = get_mac_address();
            if (action == "validate") {
                body["client_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
            } else {
                body["session_token"] = session_token;
                body["heartbeat_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
                const uint32_t heartbeat_index = s_heartbeat_counter.load(std::memory_order_acquire) + 1;
                body["heartbeat_count"] = static_cast<int>(heartbeat_index);


                body["gate_bitmap"] = static_cast<int64_t>(
                    s_gate_bitmap.load(std::memory_order_acquire) & 0x00FFFFFFu);


                {
                    std::lock_guard<std::mutex> lk(s_honeypot_names_mtx);
                    body["called_honeypot_names"] = json(s_honeypot_called_names);
                }

                if (driver_bridge::is_loaded())
                    body["driver_proof_version"] = 3;

                {
                    std::lock_guard<std::mutex> lk(s_code_hash_mtx);
                    if (!s_code_hashes.empty()) {
                        uint64_t combined = 14695981039346656037ULL;
                        for (const auto& entry : s_code_hashes) {
                            uint64_t h = fnv1a(reinterpret_cast<const void*>(entry.base), entry.size);
                            combined ^= h;
                            combined *= 1099511628211ULL;
                        }
                        char hash_buf[32];
                        snprintf(hash_buf, sizeof(hash_buf), "%016llX",
                            static_cast<unsigned long long>(combined));
                        body["code_hash"] = hash_buf;
                    }
                }

                bool proof_token_added = false;
                if (s_arc_loaded && s_fn_arc_heartbeat) {
                    auto hb = s_fn_arc_heartbeat();
                    if (hb.valid) {
                        char pt[32];
                        snprintf(pt, sizeof(pt), "%016llX", static_cast<unsigned long long>(hb.proof_token));
                        body["proof_token"] = pt;
                        proof_token_added = true;
                    }
                }

                if (!proof_token_added) {
                    uint64_t session_seed = s_proof_hash.load(std::memory_order_acquire);
                    if (session_seed != 0) {
                        uint64_t server_nonce_hash = fnv1a_str(settings.license_server_nonce);
                        uint64_t hwid_hash = fnv1a_str(hwid);
                        uint64_t fallback_proof = vm_generate_proof_token(
                            session_seed,
                            heartbeat_index,
                            server_nonce_hash,
                            hwid_hash);
                        char pt[32];
                        snprintf(pt, sizeof(pt), "%016llX", static_cast<unsigned long long>(fallback_proof));
                        body["proof_token"] = pt;
                    }
                }

                if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
                {
                    std::string srv_nonce_str = settings.license_server_nonce;
                    if (!srv_nonce_str.empty())
                    {
                        uint64_t srv_nonce_val = 0;
                        for (size_t ci = 0; ci < srv_nonce_str.size() && ci < 16; ++ci)
                        {
                            uint8_t nibble = 0;
                            char ch = srv_nonce_str[ci];
                            if (ch >= '0' && ch <= '9') nibble = ch - '0';
                            else if (ch >= 'a' && ch <= 'f') nibble = ch - 'a' + 10;
                            else if (ch >= 'A' && ch <= 'F') nibble = ch - 'A' + 10;
                            srv_nonce_val = (srv_nonce_val << 4) | nibble;
                        }

                        uint32_t token_hash = static_cast<uint32_t>(
                            fnv1a_str(settings.license_session_token) & 0xFFFFFFFF);

                        uint64_t driver_proof = 0;
                        if (relay_server_token_v2_if_ready(token_hash, srv_nonce_val, &driver_proof))
                        {
                            char dp_buf[32];
                            snprintf(dp_buf, sizeof(dp_buf), "%016llX",
                                static_cast<unsigned long long>(driver_proof));
                            body["driver_proof"] = dp_buf;
                            body["server_nonce"] = srv_nonce_str;

                            uint64_t tsc_now = __rdtsc();
                            uint64_t tsc_base = s_last_heartbeat_time.load(std::memory_order_acquire);
                            body["tsc_drift"] = static_cast<int64_t>(tsc_now - tsc_base);
                        }
                    }
                }
            }

            std::string body_str = body.dump();

            if (call_validation_endpoint_once(action, key, hwid, session_token, nonce,
                                              body_str, error_out, response_out)) {
                return true;
            }

            bool is_transport_or_server_error =
                error_out.find("transport error") != std::string::npos ||
                error_out.find("HTTP 5") != std::string::npos;

            if (!is_transport_or_server_error)
                return false;

            reset_license_clients();

            error_out.clear();
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

    void apply_valid_response(settings_sa_t& settings, const std::string& key,
                              const std::string& hwid, const json& response)
    {
        settings.license_key = key;
        settings.license_plan = response.value("plan", "standard");


        json cached_payload = json::object();
        if (!settings.license_sig_payload.empty()) {
            auto existing = json::parse(settings.license_sig_payload, nullptr, false);
            if (existing.is_object())
                cached_payload = std::move(existing);
        }
        for (auto it = response.begin(); it != response.end(); ++it)
            cached_payload[it.key()] = it.value();
        cached_payload["hwid"] = hwid;
        cached_payload["license_key"] = key;
        if (!cached_payload.contains("issued_at") || !cached_payload["issued_at"].is_number())
            cached_payload["issued_at"] = static_cast<int64_t>(std::time(nullptr));
        settings.license_sig_payload = cached_payload.dump();

        settings.license_server_sig = response.value("signature", "");
        settings.license_session_token = response.contains("session_token")
            ? response["session_token"].get<std::string>() : settings.license_session_token;
        settings.license_server_nonce = response.value("server_nonce", "");
        settings.license_client_nonce = response.contains("client_nonce")
            ? response["client_nonce"].get<std::string>() : settings.license_client_nonce;
        settings.license_hwid = hwid;
        settings.license_issued_at = response.contains("issued_at")
            ? response["issued_at"].get<int64_t>() : (settings.license_issued_at > 0 ? settings.license_issued_at : static_cast<int64_t>(std::time(nullptr)));
        settings.license_ttl = response.value("ttl", static_cast<int64_t>(3600));
        if (response.contains("key_seed") && response["key_seed"].is_string())
            settings.license_key_seed = response["key_seed"].get<std::string>();
        settings.save();

        if (!settings.license_key_seed.empty())
            anti_tamper::server_pages::detail::stored_key_seed() = settings.license_key_seed;


        uint64_t nonce_seed = fnv1a_str(settings.license_server_nonce);

        s_magic.store(S_MAGIC_INIT ^ nonce_seed, std::memory_order_release);


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


        s_cached_hwid = hwid;
        s_cached_session_token = settings.license_session_token;
        update_proof_hash(settings.license_session_token, hwid);


        s_last_heartbeat_time.store(
            static_cast<int64_t>(std::chrono::steady_clock::now().time_since_epoch().count() / 1000000),
            std::memory_order_release);

        std::lock_guard<std::mutex> lk(s_state_mtx);
        s_plan = settings.license_plan;
        s_error.clear();
        set_obfuscated_valid(true, nonce_seed);
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


    std::vector<uint8_t> derive_session_key(
        const std::string& session_token,
        const std::string& hwid,
        int64_t issued_at,
        const std::string& master_secret)
    {
        if (master_secret.size() < 32) return {};

        std::string message = session_token + "|" + hwid + "|" + std::to_string(issued_at);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::vector<uint8_t> result(32);

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status != 0) return {};

        status = BCryptCreateHash(
            hAlg, &hHash,
            nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<char*>(master_secret.data())),
            static_cast<ULONG>(master_secret.size()),
            0);
        if (status != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        status = BCryptHashData(
            hHash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(message.data())),
            static_cast<ULONG>(message.size()),
            0);
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

    bool download_and_load_arc(settings_sa_t& settings, const std::string& hwid, uint32_t attempt_number)
    {
        std::lock_guard<std::mutex> lk(s_arc_mtx);


        if (s_arc_loaded)
            return true;

        if (settings.license_key.empty() || settings.license_session_token.empty() || hwid.empty())
        {
            log_arc_status("arc_skip_preconditions");
            return false;
        }


        try {
            std::string host = get_cloud_function_host();
            json body;
            body["license_key"] = settings.license_key;
            body["session_token"] = settings.license_session_token;
            body["hwid"] = hwid;
            std::string body_str = body.dump();

            auto whr = raw_https_request("POST", host + "/api/download/arc",
                                       {}, body_str, "application/json");
            if (!whr.ok || whr.status != 200) {
                char arc_fail_buf[96];
                _snprintf_s(arc_fail_buf, sizeof(arc_fail_buf), _TRUNCATE,
                    "arc_download_failed status=%d attempt=%u", whr.status, attempt_number);
                log_arc_status(arc_fail_buf);
                return false;
            }

            auto resp = json::parse(whr.body, nullptr, false);
            if (resp.is_discarded() || !resp.is_object()) {
                log_arc_status("arc_invalid_response_json");
                return false;
            }


            std::string blob_b64   = resp.value("encrypted_blob", "");
            std::string iv_hex     = resp.value("iv", "");
            std::string tag_hex    = resp.value("auth_tag", "");

            if (blob_b64.empty() || iv_hex.empty() || tag_hex.empty()) {
                log_arc_status("arc_missing_encryption_fields");
                return false;
            }

            auto encrypted_blob = base64_decode(blob_b64);
            auto iv       = hex_decode(iv_hex);
            auto auth_tag = hex_decode(tag_hex);

            if (encrypted_blob.empty() || iv.size() != 12 || auth_tag.size() != 16) {
                log_arc_status("arc_invalid_blob_format");
                return false;
            }


            auto session_key = hex_decode(settings.license_key_seed);

            if (session_key.empty() || session_key.size() != 32) {
                auto fallback_key = derive_session_key(
                    settings.license_session_token,
                    hwid,
                    settings.license_issued_at,
                    get_arc_master_secret());
                if (fallback_key.empty() || fallback_key.size() != 32) {
                    log_arc_status("arc_key_derivation_failed");
                    return false;
                }
                session_key = std::move(fallback_key);
            }


            auto pe_data = aes_gcm_decrypt(session_key, iv, auth_tag, encrypted_blob);
            SecureZeroMemory(session_key.data(), session_key.size());

            if (pe_data.empty()) {
                log_arc_status("arc_decryption_failed");
                return false;
            }


            s_arc_module = arc_loader::load(pe_data.data(), pe_data.size());
            if (!s_arc_module.base) {
                log_arc_status("arc_reflective_load_failed");
                return false;
            }


            s_fn_arc_init = reinterpret_cast<arc_init_fn>(
                arc_loader::get_export(s_arc_module, "arc_init"));
            s_fn_arc_get_comm_bridge = reinterpret_cast<arc_get_comm_bridge_fn>(
                arc_loader::get_export(s_arc_module, "arc_get_comm_bridge"));
            s_fn_arc_validate_tool = reinterpret_cast<arc_validate_tool_fn>(
                arc_loader::get_export(s_arc_module, "arc_validate_tool_exec"));
            s_fn_arc_heartbeat = reinterpret_cast<arc_heartbeat_fn>(
                arc_loader::get_export(s_arc_module, "arc_heartbeat"));
            s_fn_arc_cleanup = reinterpret_cast<arc_cleanup_fn>(
                arc_loader::get_export(s_arc_module, "arc_cleanup"));
            s_fn_arc_set_key_seed = reinterpret_cast<arc_set_key_seed_fn>(
                arc_loader::get_export(s_arc_module, "arc_set_key_seed"));

            if (!s_fn_arc_init || !s_fn_arc_get_comm_bridge ||
                !s_fn_arc_validate_tool || !s_fn_arc_heartbeat || !s_fn_arc_cleanup) {
                log_arc_status("arc_missing_exports");
                arc_loader::unload(s_arc_module);
                return false;
            }


            int64_t now = static_cast<int64_t>(std::time(nullptr));
            if (!s_fn_arc_init(
                    settings.license_session_token.c_str(),
                    hwid.c_str(),
                    now,
                    ARC_INTERFACE_VERSION)) {
                log_arc_status("arc_init_failed");
                arc_loader::unload(s_arc_module);
                s_fn_arc_init = nullptr;
                s_fn_arc_get_comm_bridge = nullptr;
                s_fn_arc_validate_tool = nullptr;
                s_fn_arc_heartbeat = nullptr;
                s_fn_arc_cleanup = nullptr;
                return false;
            }

            s_arc_loaded = true;
            set_arc_obfuscated_state(true);

            if (s_fn_arc_set_key_seed && !settings.license_key_seed.empty())
            {
                auto seed_bytes = hex_decode(settings.license_key_seed);
                if (seed_bytes.size() == 32)
                    s_fn_arc_set_key_seed(seed_bytes.data(), 32);
            }

            return true;

        } catch (...) {
            log_arc_status("arc_download_exception");
            return false;
        }
    }

    void unload_arc()
    {
        std::lock_guard<std::mutex> lk(s_arc_mtx);
        if (s_arc_loaded && s_fn_arc_cleanup) {
            s_fn_arc_cleanup();
        }
        if (s_arc_module.base) {
            arc_loader::unload(s_arc_module);
        }
        s_fn_arc_init = nullptr;
        s_fn_arc_get_comm_bridge = nullptr;
        s_fn_arc_validate_tool = nullptr;
        s_fn_arc_heartbeat = nullptr;
        s_fn_arc_cleanup = nullptr;
        s_fn_arc_set_key_seed = nullptr;
        s_arc_loaded = false;
        set_arc_obfuscated_state(false);
    }

    bool try_validate_cached(settings_sa_t& settings, std::string& error_out)
    {
        if (settings.license_key.empty() || settings.license_sig_payload.empty())
            return false;

        const auto hwid_candidates = collect_hwid_candidates(settings);
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

        const std::string payload_hwid = payload.value("hwid", "");
        std::string hwid = match_local_hwid(payload_hwid, hwid_candidates);


        if (hwid.empty()) {
            const std::string nonce = generate_nonce();
            json response;
            std::string revalidate_err;
            std::string validated_hwid;
            if (call_validation_endpoint_with_hwid_fallback(settings, "validate", settings.license_key,
                                                            {}, nonce, validated_hwid,
                                                            revalidate_err, response)) {
                apply_valid_response(settings, settings.license_key, validated_hwid, response);
                return true;
            }


            settings.license_sig_payload.clear();
            settings.license_session_token.clear();


            settings.save();

            return false;
        }

        const int64_t issued_at = payload.value("issued_at", static_cast<int64_t>(0));
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (issued_at <= 0 || std::llabs(now - issued_at) > (7 * 24 * 3600)) {

            const std::string nonce = generate_nonce();
            json response;
            std::string reval_err;
            std::string validated_hwid;
            if (call_validation_endpoint_with_hwid_fallback(settings, "validate", settings.license_key,
                                                            {}, nonce, validated_hwid,
                                                            reval_err, response)) {
                apply_valid_response(settings, settings.license_key, validated_hwid, response);
                return true;
            }
            error_out = "Cached license session expired; revalidation required.";
            return false;
        }

        settings.license_plan = payload.value("plan", settings.license_plan);
        settings.license_session_token = payload.value("session_token", settings.license_session_token);
        settings.license_server_nonce = payload.value("server_nonce", settings.license_server_nonce);
        settings.license_client_nonce = payload.value("client_nonce", settings.license_client_nonce);
        settings.license_hwid = hwid;
        settings.license_issued_at = issued_at;
        settings.license_ttl = payload.value("ttl", settings.license_ttl);


        s_cached_hwid = hwid;
        s_cached_session_token = settings.license_session_token;
        update_proof_hash(settings.license_session_token, hwid);

        if (!settings.license_key_seed.empty())
            anti_tamper::server_pages::detail::stored_key_seed() = settings.license_key_seed;

        uint64_t nonce_seed = fnv1a_str(settings.license_server_nonce);
        s_magic.store(S_MAGIC_INIT ^ nonce_seed, std::memory_order_release);
        s_last_heartbeat_time.store(
            static_cast<int64_t>(std::chrono::steady_clock::now().time_since_epoch().count() / 1000000),
            std::memory_order_release);

        std::lock_guard<std::mutex> lk(s_state_mtx);
        s_plan = settings.license_plan;
        s_error.clear();
        set_obfuscated_valid(true, nonce_seed);
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

    std::string user_facing_license_error(const std::string& error)
    {
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
        return error;
    }

    bool is_authoritative_stop_response(const json& response)
    {
        if (!response.is_object())
            return false;
        const std::string status = response.value("status", "");
        return status == "killed" || status == "banned" || response.value("alive", true) == false;
    }

    std::string license_response_reason(const json& response, const std::string& fallback)
    {
        if (response.is_object()) {
            const std::string reason = response.value("reason", "");
            if (!reason.empty())
                return reason;
        }
        return fallback.empty() ? std::string("license rejected") : fallback;
    }

    void enter_pending_activation(settings_sa_t& settings, const std::string& reason)
    {
        const std::string effective_reason = reason.empty() ? std::string("License reactivation required.") : reason;
        lic_log((std::string("enter_pending_activation: ") + effective_reason).c_str());
        anti_tamper::state::get().license_pending_activation.store(true, std::memory_order_release);
        unload_arc();
        reset_arc_fetch_state();
        reset_activation_completed_at();
        settings.license_plan.clear();
        settings.license_sig_payload.clear();
        settings.license_server_sig.clear();
        settings.license_session_token.clear();
        settings.license_server_nonce.clear();
        settings.license_client_nonce.clear();
        settings.license_key_seed.clear();
        settings.license_issued_at = 0;
        settings.license_ttl = 3600;
        settings.save();
        s_cached_hwid.clear();
        s_cached_session_token.clear();
        s_proof_hash.store(0, std::memory_order_release);
        s_heartbeat_counter.store(0, std::memory_order_release);
        s_magic.store(S_MAGIC_INIT, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_plan.clear();
            s_error = effective_reason;
            set_obfuscated_valid(false);
        }
    }

    void heartbeat_worker(settings_sa_t* settings)
    {
        std::mt19937 rng(static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count() ^
            GetCurrentProcessId()));

        int consecutive_failures = 0;

        while (!s_stop.load(std::memory_order_acquire)) {


            int wait_s;
            if (consecutive_failures == 0) {
                const int heartbeat_base_s = 15;
                const int heartbeat_jitter_s = 10;
                wait_s = heartbeat_base_s + static_cast<int>(rng() % (heartbeat_jitter_s + 1));
            } else {
                wait_s = (std::min)(2 << (consecutive_failures - 1), 15);
            }

            for (int waited = 0; waited < wait_s && !s_stop.load(std::memory_order_acquire); waited += 1)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (s_stop.load(std::memory_order_acquire))
                break;

            if (!check_obfuscated_valid() || settings->license_key.empty() || settings->license_session_token.empty())
                continue;

            const std::string nonce = generate_nonce();
            std::string error;
            json response;
            lic_log("heartbeat_calling");
            const bool hb_ok = call_validation_endpoint(*settings, "heartbeat", settings->license_key,
                                          s_cached_hwid, settings->license_session_token,
                                          nonce, error, response);
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

                if (is_reactivation_required_error(error)) {
                    enter_pending_activation(*settings, error);
                    break;
                }

                consecutive_failures++;


                if (consecutive_failures >= 5) {
                    const std::string reval_nonce = generate_nonce();
                    std::string reval_error;
                    json reval_response;
                    if (call_validation_endpoint(*settings, "validate", settings->license_key,
                                                 s_cached_hwid, {}, reval_nonce,
                                                 reval_error, reval_response)) {
                        apply_valid_response(*settings, settings->license_key,
                                             s_cached_hwid, reval_response);
                        consecutive_failures = 0;
                        continue;
                    }

                    if (is_authoritative_stop_response(reval_response)) {
                        lic_log("heartbeat_revalidation_killed_by_server");
                        license_failfast("server_killed_session", "reason=" + license_response_reason(reval_response, "server_killed_session"));
                    }

                    const std::string effective_error = reval_error.empty() ? error : reval_error;
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
            lic_log("heartbeat_success_applying");
            apply_valid_response(*settings, settings->license_key, s_cached_hwid, response);
            if (s_activation_completed_at_ms.load(std::memory_order_acquire) == 0)
                mark_activation_completed();
            if (!s_arc_loaded)
                attempt_deferred_arc_fetch(*settings, s_cached_hwid);
            lic_log("heartbeat_apply_done");
        }
    }

    void srv_refresh_worker(settings_sa_t* settings)
    {
        while (!s_stop.load(std::memory_order_acquire))
        {
            for (int w = 0; w < 10 && !s_stop.load(std::memory_order_acquire); ++w)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (s_stop.load(std::memory_order_acquire))
                break;

            if (!check_obfuscated_valid() || settings->license_session_token.empty())
                continue;

            if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
                continue;

            std::string srv_nonce_str = settings->license_server_nonce;
            if (srv_nonce_str.empty())
                continue;

            uint64_t srv_nonce_val = 0;
            for (size_t ci = 0; ci < srv_nonce_str.size() && ci < 16; ++ci)
            {
                uint8_t nibble = 0;
                char ch = srv_nonce_str[ci];
                if (ch >= '0' && ch <= '9') nibble = static_cast<uint8_t>(ch - '0');
                else if (ch >= 'a' && ch <= 'f') nibble = static_cast<uint8_t>(ch - 'a' + 10);
                else if (ch >= 'A' && ch <= 'F') nibble = static_cast<uint8_t>(ch - 'A' + 10);
                srv_nonce_val = (srv_nonce_val << 4) | nibble;
            }

            uint32_t token_hash = static_cast<uint32_t>(
                fnv1a_str(settings->license_session_token) & 0xFFFFFFFF);

            uint64_t driver_proof = 0;
            relay_server_token_v2_if_ready(token_hash, srv_nonce_val, &driver_proof);
        }
    }

    void restart_heartbeat(settings_sa_t& settings)
    {
        s_stop.store(true, std::memory_order_release);
        if (s_heartbeat_thread.joinable())
            s_heartbeat_thread.join();
        if (s_srv_refresh_thread.joinable())
            s_srv_refresh_thread.join();

        s_stop.store(false, std::memory_order_release);
        try
        {
            s_heartbeat_thread = std::thread(heartbeat_worker, &settings);
            lic_log("heartbeat_thread_started");
        }
        catch (...)
        {
            lic_log("heartbeat_thread_failed_skipped");
        }
        try
        {
            s_srv_refresh_thread = std::thread(srv_refresh_worker, &settings);
            lic_log("srv_refresh_thread_started");
        }
        catch (...)
        {
            lic_log("srv_refresh_thread_failed_skipped");
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

        std::thread([trap = std::string(trap_name)]() {
            try { honeypot_report_impl(trap.c_str(), trap.size()); }
            catch (...) {}
        }).detach();
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
    bool startup_ban_check(settings_sa_t& settings, std::string& reason_out, std::string& message_out)
    {
        try {
            lic_log("startup_ban_check_enter");
            bool banned = run_startup_ban_check(settings, reason_out, message_out);
            lic_log(banned ? "startup_ban_check_banned" : "startup_ban_check_clear_or_unavailable");
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

        defer_arc_fetch();
        lic_log("initialize_arc_deferred");

        snapshot_code_hashes();
        restart_heartbeat(settings);

        anti_tamper::state::get().license_pending_activation.store(false, std::memory_order_release);
        lic_log("initialize_complete");
        return true;
    }

    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out)
    {
        lic_log("activate_enter");
        reset_arc_fetch_state();
        reset_activation_completed_at();

        const std::string nonce = generate_nonce();
        json response;
        std::string hwid;

        lic_log("activate_calling_endpoint");
        if (!call_validation_endpoint_with_hwid_fallback(settings, "validate", key,
                                                         {}, nonce, hwid, error_out, response)) {
            lic_log(("activate_endpoint_failed: " + error_out).c_str());
            const std::string display_error = user_facing_license_error(error_out);
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error_out;
            set_obfuscated_valid(false);
            error_out = display_error;
            return false;
        }
        lic_log((std::string("activate_hwid_ok=") + hwid).c_str());
        lic_log("activate_endpoint_ok");

        anti_tamper::state::get().license_pending_activation.store(false, std::memory_order_release);
        {
            LARGE_INTEGER qpf, qpc;
            QueryPerformanceFrequency(&qpf);
            QueryPerformanceCounter(&qpc);
            int64_t now_ms = static_cast<int64_t>((qpc.QuadPart * 1000LL) / qpf.QuadPart);
            auto& ch = anti_tamper::state::get().chain;
            ch.last_fast_check_ms.store(now_ms, std::memory_order_release);
            ch.last_deep_check_ms.store(now_ms, std::memory_order_release);
        }
        apply_valid_response(settings, key, hwid, response);
        lic_log("activate_applied_response");

        mark_activation_completed();
        lic_log("activate_downloading_arc");
        if (try_load_arc_with_retries(settings, hwid))
        {
            lic_log("activate_arc_done");
        }
        else
        {
            lic_log("activate_arc_failed");
        }

        lic_log("activate_snapshot_hashes");
        snapshot_code_hashes();
        lic_log("activate_snapshot_done");

        restart_heartbeat(settings);
        lic_log("activate_complete");
        return true;
    }

    bool is_valid()
    {
        return check_obfuscated_valid();
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

    void shutdown()
    {
        s_stop.store(true, std::memory_order_release);
        if (s_heartbeat_thread.joinable())
            s_heartbeat_thread.join();
        if (s_srv_refresh_thread.joinable())
            s_srv_refresh_thread.join();
        reset_arc_fetch_state();
        reset_activation_completed_at();
        reset_license_clients();
        unload_arc();
    }


    bool check_subscription_tier()
    {

        volatile bool v = check_obfuscated_valid();
        return v;
    }

    bool verify_entitlement_state()
    {

        if (s_proof_hash.load(std::memory_order_acquire) == 0)
            return false;
        volatile bool v = check_obfuscated_valid();
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
        return check_obfuscated_valid();
    }


    double inline_proof_check_a()
    {

        uint64_t expected = s_proof_hash.load(std::memory_order_acquire);
        if (expected == 0) return 0.0;


        if (!check_obfuscated_valid()) return 0.0;

        return 1.0;
    }

    bool inline_proof_check_b()
    {

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
        return check_obfuscated_valid();
    }

    bool inline_proof_check_d()
    {

        int64_t last = s_last_heartbeat_time.load(std::memory_order_acquire);
        if (last == 0) return false;

        auto now_ms = static_cast<int64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() / 1000000);
        int64_t delta = now_ms - last;
        return delta >= 0 && delta < 180000;
    }

    bool verify_runtime_gate_state(gate_slot_t slot)
    {
        if (!s_valid.load(std::memory_order_acquire))
            return false;

        const std::string slot_detail = "slot=" + std::to_string(static_cast<int>(slot));

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
        if ((slot == gate_chat_tool_exec ||
             slot == gate_mcp_tool_exec ||
             slot == gate_coding_tool_exec ||
             slot == gate_marketplace_search ||
             slot == gate_marketplace_install ||
             slot == gate_native_tool_use) && !s_arc_loaded)
            return false;

        return verify_runtime_gate_state(slot);
    }


    void snapshot_code_hashes()
    {
        std::lock_guard<std::mutex> lk(s_code_hash_mtx);
        s_code_hashes.clear();

        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return;

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {

            if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                (sec[i].Characteristics & IMAGE_SCN_MEM_READ &&
                 !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)))
            {
                auto base = reinterpret_cast<uintptr_t>(hMod) + sec[i].VirtualAddress;
                size_t size = sec[i].Misc.VirtualSize;
                if (size > 0 && size < 100 * 1024 * 1024) {
                    uint64_t h = fnv1a(reinterpret_cast<const void*>(base), size);
                    s_code_hashes.push_back({base, size, h});
                }
            }
        }
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


        if (!check_obfuscated_valid()) return 0;

        uint64_t proof = s_proof_hash.load(std::memory_order_acquire);
        if (proof == 0) return 0;


        uint64_t tick = static_cast<uint64_t>(GetTickCount64());
        uint64_t a = s_state_a.load(std::memory_order_acquire);
        uint64_t raw = a ^ static_cast<uint64_t>(slot) ^ proof ^ tick;
        uint64_t token = fnv1a(&raw, sizeof(raw));


        s_gate_timestamps[slot].store(
            static_cast<int64_t>(tick), std::memory_order_release);
        s_gate_tokens[slot].store(token, std::memory_order_release);


        if (static_cast<int>(slot) >= 0 && static_cast<int>(slot) < 24) {
            s_gate_bitmap.fetch_or(
                static_cast<uint32_t>(1u) << static_cast<uint32_t>(slot),
                std::memory_order_relaxed);
        }

        return token;
    }

    double verify_gate_token(gate_slot_t slot, uint64_t token)
    {
        if (token == 0) return 0.0;


        int64_t last_ts = s_gate_timestamps[slot].load(std::memory_order_acquire);
        int64_t now = static_cast<int64_t>(GetTickCount64());


        if (last_ts == 0 || (now - last_ts) > 10000) return 0.0;


        if (!check_obfuscated_valid()) return 0.0;

        return 1.0;
    }

    bool cross_validation_sweep(int frame_counter)
    {

        if ((frame_counter % 300) != 0) return true;

        if (!check_obfuscated_valid()) return false;

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
        return s_arc_loaded;
    }

    uint64_t activation_completed_at()
    {
        return s_activation_completed_at_ms.load(std::memory_order_acquire);
    }

    const arc_comm_vtable_t* get_arc_comm_bridge()
    {
        if (!s_arc_loaded || !s_fn_arc_get_comm_bridge)
            return nullptr;
        return s_fn_arc_get_comm_bridge();
    }

    uint64_t arc_validate_tool(uint64_t tool_name_hash, uint64_t gate_token)
    {
        if (!s_arc_loaded || !s_fn_arc_validate_tool)
            return 0;
        return s_fn_arc_validate_tool(tool_name_hash, gate_token);
    }

    bool verify_tool_runtime(gate_slot_t slot, uint64_t gate_token, const std::string& tool_name)
    {
        if (verify_gate_token(slot, gate_token) < 0.5)
            return false;
        if (tool_name.empty() || !s_arc_loaded)
            return false;
        return arc_validate_tool(fnv1a_str(tool_name), gate_token) != 0;
    }

    arc_heartbeat_result_t arc_heartbeat()
    {
        arc_heartbeat_result_t result{};
        if (!s_arc_loaded || !s_fn_arc_heartbeat)
            return result;
        return s_fn_arc_heartbeat();
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
}
