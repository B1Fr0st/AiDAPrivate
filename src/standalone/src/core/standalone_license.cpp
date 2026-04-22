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

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "bcrypt.lib")

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

    HANDLE hf = CreateFileA(s_log_path, GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hf, 0, nullptr, FILE_END);
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

static SimpleHttpResponse raw_https_request(
    const char* verb,
    const std::string& url,
    const std::vector<std::pair<std::string,std::string>>& extra_headers = {},
    const std::string& req_body = {},
    const std::string& content_type = {},
    int timeout_sec = 15)
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


    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%d", port);
    const int gai_rc = getaddrinfo(host.c_str(), port_str, &hints, &result);
    if (gai_rc != 0 || !result) {
        out.error = "DNS resolution failed for " + host + " rc=" + std::to_string(gai_rc)
                  + " wsa=" + std::to_string(WSAGetLastError());
        return out;
    }


    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        out.error = "socket() failed wsa=" + std::to_string(WSAGetLastError());
        return out;
    }


    DWORD tv = static_cast<DWORD>(timeout_sec * 1000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    if (::connect(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        int wsa = WSAGetLastError();
        closesocket(sock);
        freeaddrinfo(result);
        out.error = "connect() failed wsa=" + std::to_string(wsa);
        return out;
    }
    freeaddrinfo(result);


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
        SSL_set_fd(ssl, (int)sock);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            closesocket(sock);
            out.error = "SSL_connect failed";
            return out;
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
            if (n <= 0) return false;
            data += n;
            len  -= n;
        }
        return true;
    };

    if (!send_all(http_req.c_str(), (int)http_req.size())) {
        if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
        closesocket(sock);
        out.error = "send failed";
        return out;
    }


    std::string raw_resp;
    raw_resp.reserve(4096);
    char buf[4096];
    for (;;) {
        int n;
        if (ssl) n = SSL_read(ssl, buf, sizeof(buf));
        else     n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw_resp.append(buf, n);
        if (raw_resp.size() > 4 * 1024 * 1024) break;
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

    /* ── Step-up nonce (server-initiated re-proof) ──────── */
    std::string s_pending_step_up_nonce;
    std::atomic<bool> s_step_up_pending{false};
    std::mutex s_step_up_mtx;

    /* ── Phase-2 hardening state ─────────────────────────── */

    /* Additional obfuscated state pair: d + e == magic_2 */
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
            lic_log("call_validation_getting_ip");
            body["public_ip"] = get_public_ip();
            lic_log(("call_validation_got_ip ip=" + body["public_ip"].get<std::string>()).c_str());
            body["mac_address"] = get_mac_address();
            if (action == "validate") {
                body["client_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
            } else {
                body["session_token"] = session_token;
                body["heartbeat_nonce"] = nonce;
                body["plugin_version"] = "aida-standalone";
                body["heartbeat_count"] = static_cast<int>(s_heartbeat_counter.load(std::memory_order_acquire));


                body["gate_bitmap"] = static_cast<int64_t>(
                    s_gate_bitmap.load(std::memory_order_acquire) & 0x00FFFFFFu);


                if (s_step_up_pending.load(std::memory_order_acquire))
                {
                    std::lock_guard<std::mutex> sul(s_step_up_mtx);
                    if (!s_pending_step_up_nonce.empty())
                    {
                        uint64_t su_nonce = fnv1a_str(s_pending_step_up_nonce);
                        uint64_t su_tsc = __rdtsc();
                        uint64_t su_proof = s_proof_hash.load(std::memory_order_acquire);
                        uint64_t su_gates = s_gate_bitmap.load(std::memory_order_acquire);

                        uint64_t combined = su_nonce ^ _rotl64(su_proof, 17)
                                          ^ _rotl64(su_tsc, 31) ^ su_gates;
                        combined *= 0x9E3779B97F4A7C15ULL;
                        combined ^= combined >> 33;

                        char su_buf[32];
                        snprintf(su_buf, sizeof(su_buf), "%016llX",
                            static_cast<unsigned long long>(combined));
                        body["step_up_nonce"] = s_pending_step_up_nonce;
                        body["step_up_proof"] = su_buf;

                        s_pending_step_up_nonce.clear();
                        s_step_up_pending.store(false, std::memory_order_release);
                    }
                }

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

                if (s_arc_loaded && s_fn_arc_heartbeat) {
                    auto hb = s_fn_arc_heartbeat();
                    if (hb.valid) {
                        char pt[32];
                        snprintf(pt, sizeof(pt), "%016llX", static_cast<unsigned long long>(hb.proof_token));
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


        s_heartbeat_counter.fetch_add(1, std::memory_order_relaxed);

        if (response.contains("page_epoch") && response["page_epoch"].is_number())
        {
            uint64_t new_epoch = response["page_epoch"].get<uint64_t>();
            anti_tamper::server_pages::advance_epoch(new_epoch);
        }


        if (response.contains("step_up_nonce") && response["step_up_nonce"].is_string())
        {
            std::lock_guard<std::mutex> sul(s_step_up_mtx);
            s_pending_step_up_nonce = response["step_up_nonce"].get<std::string>();
            s_step_up_pending.store(true, std::memory_order_release);
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

                if (response.is_object() &&
                    (response.value("status", "") == "killed" ||
                     response.value("alive", true) == false)) {
                    lic_log("heartbeat_killed_by_server");
                    anti_tamper::server_pages::force_scrub_all();
                    std::lock_guard<std::mutex> lk(s_state_mtx);
                    s_error = "session_terminated";
                    set_obfuscated_valid(false);
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

                    std::lock_guard<std::mutex> lk(s_state_mtx);
                    s_error = error;
                    set_obfuscated_valid(false);
                    break;
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
            std::lock_guard<std::mutex> lk(s_state_mtx);
            s_error = error_out;
            set_obfuscated_valid(false);
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
        return s_error;
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

    double compute_degradation_factor()
    {
        double factor = 1.0;


        double a = inline_proof_check_a();
        if (a < 0.5) factor *= 0.1;
        else factor *= a;


        if (!inline_proof_check_b()) factor *= 0.05;


        if (!inline_proof_check_c()) factor *= 0.0;


        if (!inline_proof_check_d()) factor *= 0.3;

        return factor;
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

        double factor = compute_degradation_factor();


        if (slot == gate_ui_render_loop || slot == gate_ui_bottom_panel ||
            slot == gate_settings_save)
            return factor > 0.0;


        if (slot == gate_file_browser_open || slot == gate_workspace_search ||
            slot == gate_terminal_exec || slot == gate_ui_command_palette)
            return factor >= 0.3;


        if (slot == gate_ai_chat_async || slot == gate_ai_generate ||
            slot == gate_ai_stream_cb || slot == gate_agentic_loop_iter ||
            slot == gate_mcp_tool_exec || slot == gate_coding_tool_exec ||
            slot == gate_native_tool_use)
            return factor >= 0.6;


        if (slot == gate_driver_attach || slot == gate_driver_read_mem)
            return factor >= 0.8;


        return factor >= 0.5;
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
                lic_log(magic_buf);
                set_obfuscated_valid(false);
                return false;
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
