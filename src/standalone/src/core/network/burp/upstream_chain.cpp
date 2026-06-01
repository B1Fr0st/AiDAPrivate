#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>

#pragma comment(lib, "ws2_32.lib")

#ifdef small
#undef small
#endif

#include "upstream_chain.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace upstream {

namespace {

struct wsa_guard_t
{
    WSADATA data{};
    bool    ok = false;
    wsa_guard_t() { ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0); }
    ~wsa_guard_t() { if (ok) WSACleanup(); }
};

static wsa_guard_t s_wsa_guard;

struct state_t
{
    std::mutex                     mtx;
    std::vector<upstream_chain_t>  chains;
    std::atomic<uint64_t>          next_id{1};
    std::atomic<uint64_t>          active_id{0};
    std::atomic<bool>              initialized{false};
    std::mutex                     err_mtx;
    std::string                    last_err;
};

state_t& s()
{
    static state_t st;
    return st;
}

void set_err(const std::string& m)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = m;
}

uint64_t now_ms_steady()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

bool set_nonblocking(SOCKET sock, bool nb)
{
    u_long mode = nb ? 1u : 0u;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
}

bool poll_wait(SOCKET sock, int timeout_ms, bool for_write)
{
    if (timeout_ms <= 0) return false;
    WSAPOLLFD pfd{};
    pfd.fd = sock;
    pfd.events = static_cast<short>(for_write ? POLLOUT : POLLIN);
    int rc = WSAPoll(&pfd, 1, timeout_ms);
    if (rc <= 0 || (pfd.revents & POLLNVAL) != 0) return false;
    const short wanted = static_cast<short>(for_write ? POLLOUT : (POLLIN | POLLRDNORM));
    return (pfd.revents & wanted) != 0 && (pfd.revents & POLLERR) == 0;
}

bool tcp_connect_timeout(SOCKET sock, const sockaddr* sa, int sa_len, int timeout_ms)
{
    if (!set_nonblocking(sock, true)) return false;
    int rc = connect(sock, sa, sa_len);
    if (rc == 0) return true;
    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) return false;
    if (!poll_wait(sock, timeout_ms, true)) return false;
    int so_err = 0;
    int len = sizeof(so_err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &len) != 0) return false;
    return so_err == 0;
}

bool send_all_timeout(SOCKET sock, const uint8_t* data, size_t len, int timeout_ms)
{
    uint64_t deadline = now_ms_steady() + static_cast<uint64_t>(timeout_ms);
    size_t off = 0;
    while (off < len) {
        int remaining_ms = static_cast<int>(deadline - now_ms_steady());
        if (remaining_ms <= 0) return false;
        if (!poll_wait(sock, remaining_ms, true)) return false;
        int n = send(sock, reinterpret_cast<const char*>(data + off), static_cast<int>(len - off), 0);
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

bool recv_some_timeout(SOCKET sock, uint8_t* buf, size_t len, size_t& out_n, int timeout_ms)
{
    out_n = 0;
    if (!poll_wait(sock, timeout_ms, false)) return false;
    int n = recv(sock, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
    if (n <= 0) return false;
    out_n = static_cast<size_t>(n);
    return true;
}

bool recv_exact_timeout(SOCKET sock, uint8_t* buf, size_t len, int timeout_ms)
{
    uint64_t deadline = now_ms_steady() + static_cast<uint64_t>(timeout_ms);
    size_t off = 0;
    while (off < len) {
        int remaining = static_cast<int>(deadline - now_ms_steady());
        if (remaining <= 0) return false;
        if (!poll_wait(sock, remaining, false)) return false;
        int n = recv(sock, reinterpret_cast<char*>(buf + off), static_cast<int>(len - off), 0);
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

bool resolve_target_address(const std::string& host, uint16_t port,
                            sockaddr_storage& out_addr, int& out_len)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char port_str[16];
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", static_cast<unsigned>(port));
    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str, &hints, &res);
    if (rc != 0 || !res) return false;
    std::memcpy(&out_addr, res->ai_addr, res->ai_addrlen);
    out_len = static_cast<int>(res->ai_addrlen);
    freeaddrinfo(res);
    return true;
}

std::string base64_encode(const std::string& src)
{
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((src.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= src.size()) {
        uint32_t v = (static_cast<uint8_t>(src[i]) << 16) |
                     (static_cast<uint8_t>(src[i + 1]) << 8) |
                     (static_cast<uint8_t>(src[i + 2]));
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back(tbl[(v >> 6) & 0x3F]);
        out.push_back(tbl[v & 0x3F]);
        i += 3;
    }
    if (i < src.size()) {
        uint32_t v = static_cast<uint8_t>(src[i]) << 16;
        if (i + 1 < src.size()) v |= static_cast<uint8_t>(src[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        if (i + 1 < src.size()) {
            out.push_back(tbl[(v >> 6) & 0x3F]);
            out.push_back('=');
        } else {
            out.push_back('=');
            out.push_back('=');
        }
    }
    return out;
}

bool http_connect_through(SOCKET sock,
                          const std::string& target_host,
                          uint16_t target_port,
                          const std::string& proxy_user,
                          const std::string& proxy_pass,
                          int timeout_ms,
                          std::string& err_out)
{
    diag::log_tagged_fmt("upstream", "http_connect_through entry target=%s port=%u auth=%d timeout_ms=%d",
        target_host.c_str(), static_cast<unsigned>(target_port),
        static_cast<int>(!proxy_user.empty()), timeout_ms);
    std::string req;
    req += "CONNECT "; req += target_host; req += ":";
    req += std::to_string(static_cast<unsigned>(target_port));
    req += " HTTP/1.1\r\n";
    req += "Host: "; req += target_host; req += ":";
    req += std::to_string(static_cast<unsigned>(target_port));
    req += "\r\n";
    req += "Proxy-Connection: Keep-Alive\r\n";
    req += "User-Agent: AiDA-Burp/1.0\r\n";
    if (!proxy_user.empty()) {
        std::string ub = proxy_user; ub += ":"; ub += proxy_pass;
        req += "Proxy-Authorization: Basic "; req += base64_encode(ub); req += "\r\n";
        diag::log_tagged_fmt("upstream", "http_connect_through added_proxy_auth user=%s",
            proxy_user.c_str());
    }
    req += "\r\n";

    diag::log_tagged_fmt("upstream", "http_connect_through sending_request bytes=%zu", req.size());
    if (!send_all_timeout(sock, reinterpret_cast<const uint8_t*>(req.data()), req.size(), timeout_ms)) {
        diag::log_tagged_fmt("upstream", "http_connect_through send_failed");
        err_out = "http_connect_send_failed";
        return false;
    }

    diag::log_tagged_fmt("upstream", "http_connect_through reading_response");
    std::string acc;
    uint64_t deadline = now_ms_steady() + static_cast<uint64_t>(timeout_ms);
    uint8_t tmp[1024];
    while (true) {
        int remaining = static_cast<int>(deadline - now_ms_steady());
        if (remaining <= 0) {
            diag::log_tagged_fmt("upstream", "http_connect_through timeout acc_size=%zu", acc.size());
            err_out = "http_connect_timeout";
            return false;
        }
        size_t got = 0;
        if (!recv_some_timeout(sock, tmp, sizeof(tmp), got, remaining)) {
            diag::log_tagged_fmt("upstream", "http_connect_through recv_failed acc_size=%zu", acc.size());
            err_out = "http_connect_recv_failed";
            return false;
        }
        acc.append(reinterpret_cast<const char*>(tmp), got);
        if (acc.find("\r\n\r\n") != std::string::npos) break;
        if (acc.size() > 32 * 1024) {
            diag::log_tagged_fmt("upstream", "http_connect_through response_too_large acc_size=%zu", acc.size());
            err_out = "http_connect_response_too_large";
            return false;
        }
    }

    diag::log_tagged_fmt("upstream", "http_connect_through parsing_status response_size=%zu", acc.size());
    size_t eol = acc.find("\r\n");
    if (eol == std::string::npos) {
        diag::log_tagged_fmt("upstream", "http_connect_through no_status_line");
        err_out = "http_connect_no_status_line";
        return false;
    }
    std::string status_line = acc.substr(0, eol);
    if (status_line.size() < 12 || status_line.compare(0, 5, "HTTP/") != 0) {
        diag::log_tagged_fmt("upstream", "http_connect_through bad_status_format line_len=%zu",
            status_line.size());
        err_out = "http_connect_bad_status";
        return false;
    }
    size_t sp = status_line.find(' ');
    if (sp == std::string::npos) {
        diag::log_tagged_fmt("upstream", "http_connect_through no_space_in_status");
        err_out = "http_connect_bad_status";
        return false;
    }
    int code = 0;
    while (sp < status_line.size() && (status_line[sp] == ' ' || status_line[sp] == '\t')) ++sp;
    size_t cs = sp;
    while (cs < status_line.size() && status_line[cs] >= '0' && status_line[cs] <= '9') {
        code = code * 10 + (status_line[cs] - '0');
        ++cs;
    }
    diag::log_tagged_fmt("upstream", "http_connect_through parsed_status_code=%d", code);
    if (code < 200 || code >= 300) {
        char msg[160];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "http_connect_status=%d", code);
        diag::log_tagged_fmt("upstream", "http_connect_through non_2xx err=%s", msg);
        err_out = msg;
        return false;
    }
    diag::log_tagged_fmt("upstream", "http_connect_through ok code=%d target=%s:%u",
        code, target_host.c_str(), static_cast<unsigned>(target_port));
    return true;
}

bool socks5_through(SOCKET sock,
                    const std::string& target_host,
                    uint16_t target_port,
                    const std::string& user,
                    const std::string& pass,
                    int timeout_ms,
                    std::string& err_out)
{
    diag::log_tagged_fmt("upstream", "socks5_through entry target=%s port=%u have_auth=%d timeout_ms=%d",
        target_host.c_str(), static_cast<unsigned>(target_port),
        static_cast<int>(!user.empty()), timeout_ms);
    uint8_t greet[4];
    greet[0] = 0x05;
    bool have_auth = !user.empty();
    if (have_auth) {
        greet[1] = 2;
        greet[2] = 0x00;
        greet[3] = 0x02;
        diag::log_tagged_fmt("upstream", "socks5_through greeting with_auth user=%s", user.c_str());
    } else {
        greet[1] = 1;
        greet[2] = 0x00;
        greet[3] = 0x00;
        diag::log_tagged_fmt("upstream", "socks5_through greeting no_auth");
    }
    size_t greet_len = have_auth ? 4u : 3u;
    if (!send_all_timeout(sock, greet, greet_len, timeout_ms)) {
        diag::log_tagged_fmt("upstream", "socks5_through greet_send_failed");
        err_out = "socks5_greet_send_failed";
        return false;
    }

    uint8_t selection[2];
    if (!recv_exact_timeout(sock, selection, 2, timeout_ms)) {
        diag::log_tagged_fmt("upstream", "socks5_through greet_recv_failed");
        err_out = "socks5_greet_recv_failed";
        return false;
    }
    if (selection[0] != 0x05) {
        diag::log_tagged_fmt("upstream", "socks5_through bad_ver ver=0x%02x", static_cast<unsigned>(selection[0]));
        err_out = "socks5_bad_ver";
        return false;
    }
    uint8_t method = selection[1];
    diag::log_tagged_fmt("upstream", "socks5_through server_method=0x%02x", static_cast<unsigned>(method));
    if (method == 0xFF) {
        diag::log_tagged_fmt("upstream", "socks5_through no_acceptable_method");
        err_out = "socks5_no_acceptable_method";
        return false;
    }

    if (method == 0x02) {
        diag::log_tagged_fmt("upstream", "socks5_through server_requires_userpass_auth");
        if (!have_auth) {
            diag::log_tagged_fmt("upstream", "socks5_through server_requires_auth_but_no_creds");
            err_out = "socks5_server_requires_auth";
            return false;
        }
        if (user.size() > 255 || pass.size() > 255) {
            diag::log_tagged_fmt("upstream", "socks5_through userpass_too_long user_len=%zu pass_len=%zu",
                user.size(), pass.size());
            err_out = "socks5_userpass_too_long";
            return false;
        }
        std::vector<uint8_t> req_a;
        req_a.push_back(0x01);
        req_a.push_back(static_cast<uint8_t>(user.size()));
        req_a.insert(req_a.end(), user.begin(), user.end());
        req_a.push_back(static_cast<uint8_t>(pass.size()));
        req_a.insert(req_a.end(), pass.begin(), pass.end());
        diag::log_tagged_fmt("upstream", "socks5_through sending_auth_request bytes=%zu", req_a.size());
        if (!send_all_timeout(sock, req_a.data(), req_a.size(), timeout_ms)) {
            diag::log_tagged_fmt("upstream", "socks5_through auth_send_failed");
            err_out = "socks5_auth_send_failed";
            return false;
        }
        uint8_t auth_resp[2];
        if (!recv_exact_timeout(sock, auth_resp, 2, timeout_ms)) {
            diag::log_tagged_fmt("upstream", "socks5_through auth_recv_failed");
            err_out = "socks5_auth_recv_failed";
            return false;
        }
        if (auth_resp[0] != 0x01) {
            diag::log_tagged_fmt("upstream", "socks5_through auth_bad_ver ver=0x%02x",
                static_cast<unsigned>(auth_resp[0]));
            err_out = "socks5_auth_bad_ver";
            return false;
        }
        if (auth_resp[1] != 0x00) {
            diag::log_tagged_fmt("upstream", "socks5_through auth_failed code=0x%02x",
                static_cast<unsigned>(auth_resp[1]));
            err_out = "socks5_auth_failed";
            return false;
        }
        diag::log_tagged_fmt("upstream", "socks5_through auth_ok");
    } else if (method != 0x00) {
        diag::log_tagged_fmt("upstream", "socks5_through unsupported_method method=0x%02x",
            static_cast<unsigned>(method));
        err_out = "socks5_unsupported_method";
        return false;
    } else {
        diag::log_tagged_fmt("upstream", "socks5_through no_auth_method accepted");
    }

    std::vector<uint8_t> req;
    req.push_back(0x05);
    req.push_back(0x01);
    req.push_back(0x00);

    in_addr v4{};
    in6_addr v6{};
    bool is_v4 = false;
    bool is_v6 = false;
    if (inet_pton(AF_INET, target_host.c_str(), &v4) == 1) is_v4 = true;
    else if (inet_pton(AF_INET6, target_host.c_str(), &v6) == 1) is_v6 = true;

    if (is_v4) {
        diag::log_tagged_fmt("upstream", "socks5_through target_is_ipv4");
        req.push_back(0x01);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v4.s_addr);
        req.insert(req.end(), p, p + 4);
    } else if (is_v6) {
        diag::log_tagged_fmt("upstream", "socks5_through target_is_ipv6");
        req.push_back(0x04);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v6);
        req.insert(req.end(), p, p + 16);
    } else {
        diag::log_tagged_fmt("upstream", "socks5_through target_is_domain len=%zu", target_host.size());
        if (target_host.size() > 255) {
            diag::log_tagged_fmt("upstream", "socks5_through domain_too_long len=%zu", target_host.size());
            err_out = "socks5_domain_too_long";
            return false;
        }
        req.push_back(0x03);
        req.push_back(static_cast<uint8_t>(target_host.size()));
        req.insert(req.end(), target_host.begin(), target_host.end());
    }
    req.push_back(static_cast<uint8_t>((target_port >> 8) & 0xFF));
    req.push_back(static_cast<uint8_t>(target_port & 0xFF));

    diag::log_tagged_fmt("upstream", "socks5_through sending_connect_request bytes=%zu", req.size());
    if (!send_all_timeout(sock, req.data(), req.size(), timeout_ms)) {
        diag::log_tagged_fmt("upstream", "socks5_through req_send_failed");
        err_out = "socks5_req_send_failed";
        return false;
    }

    uint8_t hdr[4];
    if (!recv_exact_timeout(sock, hdr, 4, timeout_ms)) {
        diag::log_tagged_fmt("upstream", "socks5_through reply_hdr_recv_failed");
        err_out = "socks5_reply_hdr_recv_failed";
        return false;
    }
    if (hdr[0] != 0x05) {
        diag::log_tagged_fmt("upstream", "socks5_through reply_bad_ver ver=0x%02x",
            static_cast<unsigned>(hdr[0]));
        err_out = "socks5_reply_bad_ver";
        return false;
    }
    if (hdr[1] != 0x00) {
        char msg[128];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "socks5_reply_code=%u", static_cast<unsigned>(hdr[1]));
        diag::log_tagged_fmt("upstream", "socks5_through reply_error code=%u", static_cast<unsigned>(hdr[1]));
        err_out = msg;
        return false;
    }
    diag::log_tagged_fmt("upstream", "socks5_through reply_ok reading_bind_addr atyp=0x%02x",
        static_cast<unsigned>(hdr[3]));
    uint8_t atyp = hdr[3];
    size_t bnd_len = 0;
    if (atyp == 0x01) bnd_len = 4;
    else if (atyp == 0x04) bnd_len = 16;
    else if (atyp == 0x03) {
        uint8_t l;
        if (!recv_exact_timeout(sock, &l, 1, timeout_ms)) {
            diag::log_tagged_fmt("upstream", "socks5_through reply_dom_len_recv_failed");
            err_out = "socks5_reply_dom_len_recv_failed";
            return false;
        }
        bnd_len = l;
    } else {
        diag::log_tagged_fmt("upstream", "socks5_through reply_bad_atyp atyp=0x%02x",
            static_cast<unsigned>(atyp));
        err_out = "socks5_reply_bad_atyp";
        return false;
    }
    std::vector<uint8_t> tail(bnd_len + 2);
    if (!recv_exact_timeout(sock, tail.data(), tail.size(), timeout_ms)) {
        diag::log_tagged_fmt("upstream", "socks5_through reply_tail_recv_failed bnd_len=%zu", bnd_len);
        err_out = "socks5_reply_tail_recv_failed";
        return false;
    }
    diag::log_tagged_fmt("upstream", "socks5_through ok target=%s:%u",
        target_host.c_str(), static_cast<unsigned>(target_port));
    return true;
}

SOCKET connect_first_hop(const upstream_hop_t& hop, int timeout_ms, std::string& err_out)
{
    diag::log_tagged_fmt("upstream", "connect_first_hop entry host=%s port=%u type=%s timeout_ms=%d",
        hop.host.c_str(), static_cast<unsigned>(hop.port), hop.type.c_str(), timeout_ms);
    sockaddr_storage addr{};
    int len = 0;
    if (!resolve_target_address(hop.host, hop.port, addr, len)) {
        diag::log_tagged_fmt("upstream", "connect_first_hop resolve_failed host=%s", hop.host.c_str());
        err_out = "first_hop_resolve_failed";
        return INVALID_SOCKET;
    }
    diag::log_tagged_fmt("upstream", "connect_first_hop resolved host=%s family=%d", hop.host.c_str(), static_cast<int>(addr.ss_family));
    SOCKET sock = socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        diag::log_tagged_fmt("upstream", "connect_first_hop socket_create_failed wsa_err=%d", WSAGetLastError());
        err_out = "first_hop_socket_failed";
        return INVALID_SOCKET;
    }
    diag::log_tagged_fmt("upstream", "connect_first_hop connecting timeout_ms=%d", timeout_ms);
    if (!tcp_connect_timeout(sock, reinterpret_cast<sockaddr*>(&addr), len, timeout_ms)) {
        diag::log_tagged_fmt("upstream", "connect_first_hop connect_failed host=%s port=%u",
            hop.host.c_str(), static_cast<unsigned>(hop.port));
        closesocket(sock);
        err_out = "first_hop_connect_failed";
        return INVALID_SOCKET;
    }
    diag::log_tagged_fmt("upstream", "connect_first_hop ok host=%s port=%u",
        hop.host.c_str(), static_cast<unsigned>(hop.port));
    return sock;
}

uintptr_t open_chain_internal(const upstream_chain_t& chain,
                              const std::string& target_host,
                              uint16_t target_port,
                              std::string& err_out)
{
    diag::log_tagged_fmt("upstream", "open_chain_internal entry chain=%s hops=%zu target=%s port=%u",
        chain.label.c_str(), chain.hops.size(), target_host.c_str(),
        static_cast<unsigned>(target_port));
    if (!s_wsa_guard.ok) {
        diag::log_tagged_fmt("upstream", "open_chain_internal wsa_not_initialized");
        err_out = "wsa_not_initialized";
        return static_cast<uintptr_t>(INVALID_SOCKET);
    }
    if (chain.hops.empty()) {
        diag::log_tagged_fmt("upstream", "open_chain_internal empty_chain");
        err_out = "empty_chain";
        return static_cast<uintptr_t>(INVALID_SOCKET);
    }
    constexpr int kHopTimeoutMs = 15000;

    diag::log_tagged_fmt("upstream", "open_chain_internal connecting_first_hop host=%s port=%u",
        chain.hops.front().host.c_str(), static_cast<unsigned>(chain.hops.front().port));
    SOCKET sock = connect_first_hop(chain.hops.front(), kHopTimeoutMs, err_out);
    if (sock == INVALID_SOCKET) {
        diag::log_tagged_fmt("upstream", "open_chain_internal first_hop_failed err=%s", err_out.c_str());
        return static_cast<uintptr_t>(INVALID_SOCKET);
    }
    diag::log_tagged_fmt("upstream", "open_chain_internal first_hop_ok iterating hops=%zu", chain.hops.size());

    for (size_t i = 0; i < chain.hops.size(); ++i) {
        const auto& cur = chain.hops[i];
        std::string next_host;
        uint16_t    next_port = 0;
        if (i + 1 < chain.hops.size()) {
            next_host = chain.hops[i + 1].host;
            next_port = chain.hops[i + 1].port;
        } else {
            next_host = target_host;
            next_port = target_port;
        }
        diag::log_tagged_fmt("upstream", "open_chain_internal hop[%zu] type=%s next=%s:%u",
            i, cur.type.c_str(), next_host.c_str(), static_cast<unsigned>(next_port));
        bool ok = false;
        if (cur.type == "http_connect" || cur.type == "http" || cur.type == "https_connect" || cur.type == "https") {
            diag::log_tagged_fmt("upstream", "open_chain_internal using http_connect for hop[%zu]", i);
            ok = http_connect_through(sock, next_host, next_port, cur.username, cur.password, kHopTimeoutMs, err_out);
        } else if (cur.type == "socks5" || cur.type == "socks" || cur.type == "socks5h") {
            diag::log_tagged_fmt("upstream", "open_chain_internal using socks5 for hop[%zu]", i);
            ok = socks5_through(sock, next_host, next_port, cur.username, cur.password, kHopTimeoutMs, err_out);
        } else {
            err_out = "unsupported_hop_type=" + cur.type;
            diag::log_tagged_fmt("upstream", "open_chain_internal unsupported_hop_type=%s at hop[%zu]",
                cur.type.c_str(), i);
            ok = false;
        }
        if (!ok) {
            diag::log_tagged_fmt("upstream", "open_chain_internal hop[%zu] failed err=%s closing socket",
                i, err_out.c_str());
            closesocket(sock);
            return static_cast<uintptr_t>(INVALID_SOCKET);
        }
        diag::log_tagged_fmt("upstream", "open_chain_internal hop[%zu] ok", i);
    }
    set_nonblocking(sock, false);
    diag::log_tagged_fmt("upstream", "open_chain_internal done chain=%s target=%s:%u",
        chain.label.c_str(), target_host.c_str(), static_cast<unsigned>(target_port));
    return static_cast<uintptr_t>(sock);
}

std::string appdata_dir()
{
    PWSTR known = nullptr;
    std::string out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &known)) && known) {
        int needed = WideCharToMultiByte(CP_UTF8, 0, known, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            out.assign(static_cast<size_t>(needed - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, known, -1, out.data(), needed, nullptr, nullptr);
        }
        CoTaskMemFree(known);
    }
    if (out.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("APPDATA", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) out.assign(buf, len);
    }
    if (out.empty()) out = "C:\\Users\\Public";
    return out;
}

nlohmann::json hop_to_json(const upstream_hop_t& h)
{
    nlohmann::json j;
    j["type"]     = h.type;
    j["host"]     = h.host;
    j["port"]     = h.port;
    j["username"] = h.username;
    j["password"] = h.password;
    return j;
}

bool hop_from_json(const nlohmann::json& j, upstream_hop_t& out)
{
    if (!j.is_object()) return false;
    out = upstream_hop_t{};
    if (j.contains("type") && j["type"].is_string()) out.type = j["type"].get<std::string>();
    if (j.contains("host") && j["host"].is_string()) out.host = j["host"].get<std::string>();
    if (j.contains("port") && j["port"].is_number_unsigned()) {
        uint32_t p = j["port"].get<uint32_t>();
        if (p > 0 && p <= 65535) out.port = static_cast<uint16_t>(p);
    }
    if (j.contains("username") && j["username"].is_string()) out.username = j["username"].get<std::string>();
    if (j.contains("password") && j["password"].is_string()) out.password = j["password"].get<std::string>();
    return !out.host.empty() && out.port > 0 && !out.type.empty();
}

nlohmann::json chain_to_json(const upstream_chain_t& c)
{
    nlohmann::json j;
    j["id"]     = c.id;
    j["label"]  = c.label;
    j["active"] = c.active;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& h : c.hops) arr.push_back(hop_to_json(h));
    j["hops"]   = arr;
    return j;
}

bool chain_from_json(const nlohmann::json& j, upstream_chain_t& out)
{
    if (!j.is_object()) return false;
    out = upstream_chain_t{};
    if (j.contains("id") && j["id"].is_number_unsigned()) out.id = j["id"].get<uint64_t>();
    if (j.contains("label") && j["label"].is_string()) out.label = j["label"].get<std::string>();
    if (j.contains("active") && j["active"].is_boolean()) out.active = j["active"].get<bool>();
    if (j.contains("hops") && j["hops"].is_array()) {
        for (const auto& h : j["hops"]) {
            upstream_hop_t hop;
            if (hop_from_json(h, hop)) out.hops.push_back(hop);
        }
    }
    return !out.hops.empty();
}

}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("upstream", "initialize already_initialized");
        return true;
    }
    diag::log_tagged_fmt("upstream", "initialize loading_from_disk");
    load_from_disk();
    diag::log_tagged("burp_upstream", "initialized");
    diag::log_tagged_fmt("upstream", "initialize done chains=%zu active_id=%llu",
        s().chains.size(), static_cast<unsigned long long>(s().active_id.load()));
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("upstream", "shutdown entry");
    auto& st = s();
    if (!st.initialized.exchange(false)) {
        diag::log_tagged_fmt("upstream", "shutdown not_initialized skipping");
        return;
    }
    diag::log_tagged_fmt("upstream", "shutdown saving_to_disk");
    save_to_disk();
    diag::log_tagged_fmt("upstream", "shutdown done");
}

uint64_t add_chain(const upstream_chain_t& c)
{
    diag::log_tagged_fmt("upstream", "add_chain entry label=%s hops=%zu",
        c.label.c_str(), c.hops.size());
    auto& st = s();
    upstream_chain_t copy = c;
    if (copy.id == 0) copy.id = st.next_id.fetch_add(1);
    diag::log_tagged_fmt("upstream", "add_chain assigned id=%llu",
        static_cast<unsigned long long>(copy.id));
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.chains.push_back(copy);
    }
    save_to_disk();
    diag::log_tagged_fmt("upstream", "add_chain ok id=%llu total_chains=%zu",
        static_cast<unsigned long long>(copy.id), st.chains.size());
    return copy.id;
}

bool remove_chain(uint64_t id)
{
    diag::log_tagged_fmt("upstream", "remove_chain entry id=%llu",
        static_cast<unsigned long long>(id));
    if (id == 0) {
        diag::log_tagged_fmt("upstream", "remove_chain id_zero rejected");
        return false;
    }
    auto& st = s();
    bool removed = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto it = st.chains.begin(); it != st.chains.end(); ++it) {
            if (it->id == id) { st.chains.erase(it); removed = true; break; }
        }
    }
    if (st.active_id.load() == id) {
        diag::log_tagged_fmt("upstream", "remove_chain clearing active_id was=%llu",
            static_cast<unsigned long long>(id));
        st.active_id.store(0);
    }
    if (removed) {
        save_to_disk();
        diag::log_tagged_fmt("upstream", "remove_chain ok id=%llu",
            static_cast<unsigned long long>(id));
    } else {
        diag::log_tagged_fmt("upstream", "remove_chain not_found id=%llu",
            static_cast<unsigned long long>(id));
    }
    return removed;
}

std::vector<upstream_chain_t> list_chains()
{
    diag::log_tagged_fmt("upstream", "list_chains entry");
    auto& st = s();
    std::vector<upstream_chain_t> out;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        out = st.chains;
    }
    uint64_t a = st.active_id.load();
    for (auto& c : out) c.active = (c.id == a);
    diag::log_tagged_fmt("upstream", "list_chains result count=%zu active_id=%llu",
        out.size(), static_cast<unsigned long long>(a));
    return out;
}

bool get_chain(uint64_t id, upstream_chain_t& out)
{
    diag::log_tagged_fmt("upstream", "get_chain entry id=%llu",
        static_cast<unsigned long long>(id));
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.mtx);
    for (const auto& c : st.chains) {
        if (c.id == id) {
            out = c;
            out.active = (c.id == st.active_id.load());
            diag::log_tagged_fmt("upstream", "get_chain found id=%llu label=%s active=%d hops=%zu",
                static_cast<unsigned long long>(id), out.label.c_str(),
                static_cast<int>(out.active), out.hops.size());
            return true;
        }
    }
    diag::log_tagged_fmt("upstream", "get_chain not_found id=%llu",
        static_cast<unsigned long long>(id));
    return false;
}

bool set_active_chain(uint64_t id)
{
    diag::log_tagged_fmt("upstream", "set_active_chain entry id=%llu",
        static_cast<unsigned long long>(id));
    auto& st = s();
    if (id == 0) {
        diag::log_tagged_fmt("upstream", "set_active_chain clearing active");
        st.active_id.store(0);
        save_to_disk();
        return true;
    }
    bool found = false;
    std::string label;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (const auto& c : st.chains) {
            if (c.id == id) {
                found = true;
                label = c.label;
                break;
            }
        }
    }
    if (found) {
        diag::log_tagged_fmt("upstream", "set_active_chain ok id=%llu label=%s",
            static_cast<unsigned long long>(id), label.c_str());
        st.active_id.store(id);
        save_to_disk();
        return true;
    }
    diag::log_tagged_fmt("upstream", "set_active_chain not_found id=%llu",
        static_cast<unsigned long long>(id));
    set_err("chain_id_not_found");
    return false;
}

uint64_t get_active_chain_id()
{
    uint64_t id = s().active_id.load();
    diag::log_tagged_fmt("upstream", "get_active_chain_id result=%llu",
        static_cast<unsigned long long>(id));
    return id;
}

bool update_chain(const upstream_chain_t& c)
{
    diag::log_tagged_fmt("upstream", "update_chain entry id=%llu label=%s hops=%zu",
        static_cast<unsigned long long>(c.id), c.label.c_str(), c.hops.size());
    if (c.id == 0) {
        diag::log_tagged_fmt("upstream", "update_chain id_zero rejected");
        return false;
    }
    auto& st = s();
    bool updated = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (auto& cur : st.chains) {
            if (cur.id == c.id) {
                cur.label = c.label;
                cur.hops  = c.hops;
                updated = true;
                break;
            }
        }
    }
    if (updated) {
        save_to_disk();
        diag::log_tagged_fmt("upstream", "update_chain ok id=%llu",
            static_cast<unsigned long long>(c.id));
    } else {
        diag::log_tagged_fmt("upstream", "update_chain not_found id=%llu",
            static_cast<unsigned long long>(c.id));
    }
    return updated;
}

uintptr_t open_through_chain(const std::string& target_host, uint16_t target_port, std::string& err_out)
{
    diag::log_tagged_fmt("upstream", "open_through_chain entry target=%s port=%u",
        target_host.c_str(), static_cast<unsigned>(target_port));
    uint64_t id = s().active_id.load();
    if (id == 0) {
        diag::log_tagged_fmt("upstream", "open_through_chain no_active_chain");
        err_out = "no_active_chain";
        return static_cast<uintptr_t>(INVALID_SOCKET);
    }
    diag::log_tagged_fmt("upstream", "open_through_chain delegating active_id=%llu",
        static_cast<unsigned long long>(id));
    return open_through_chain_id(id, target_host, target_port, err_out);
}

uintptr_t open_through_chain_id(uint64_t chain_id, const std::string& target_host, uint16_t target_port, std::string& err_out)
{
    diag::log_tagged_fmt("upstream", "open_through_chain_id entry chain_id=%llu target=%s port=%u",
        static_cast<unsigned long long>(chain_id), target_host.c_str(),
        static_cast<unsigned>(target_port));
    upstream_chain_t c;
    if (!get_chain(chain_id, c)) {
        diag::log_tagged_fmt("upstream", "open_through_chain_id chain_not_found id=%llu",
            static_cast<unsigned long long>(chain_id));
        err_out = "chain_id_not_found";
        return static_cast<uintptr_t>(INVALID_SOCKET);
    }
    diag::log_tagged_fmt("upstream", "open_through_chain_id opening chain=%s hops=%zu",
        c.label.c_str(), c.hops.size());
    uintptr_t result = open_chain_internal(c, target_host, target_port, err_out);
    if (result == static_cast<uintptr_t>(INVALID_SOCKET)) {
        diag::log_tagged_fmt("upstream", "open_through_chain_id failed err=%s", err_out.c_str());
    } else {
        diag::log_tagged_fmt("upstream", "open_through_chain_id ok sock=%llu",
            static_cast<unsigned long long>(result));
    }
    return result;
}

bool test_chain(uint64_t chain_id, const std::string& target_host, uint16_t target_port, std::string& err_out)
{
    diag::log_tagged_fmt("upstream", "test_chain entry chain_id=%llu target=%s port=%u",
        static_cast<unsigned long long>(chain_id), target_host.c_str(),
        static_cast<unsigned>(target_port));
    uintptr_t sock = open_through_chain_id(chain_id, target_host, target_port, err_out);
    if (sock == static_cast<uintptr_t>(INVALID_SOCKET)) {
        diag::log_tagged_fmt("upstream", "test_chain failed err=%s", err_out.c_str());
        return false;
    }
    closesocket(static_cast<SOCKET>(sock));
    diag::log_tagged_fmt("upstream", "test_chain ok chain_id=%llu target=%s:%u",
        static_cast<unsigned long long>(chain_id), target_host.c_str(),
        static_cast<unsigned>(target_port));
    return true;
}

std::string storage_path()
{
    std::string base = appdata_dir();
    base += "\\AiDA\\Standalone\\burp";
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    base += "\\upstream_chains.json";
    diag::log_tagged_fmt("upstream", "storage_path result=%s", base.c_str());
    return base;
}

bool save_to_disk()
{
    diag::log_tagged_fmt("upstream", "save_to_disk entry");
    auto& st = s();
    nlohmann::json arr = nlohmann::json::array();
    uint64_t active = st.active_id.load();
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        for (const auto& c : st.chains) { arr.push_back(chain_to_json(c)); ++count; }
    }
    nlohmann::json out;
    out["chains"]    = arr;
    out["active_id"] = active;
    std::ofstream o(storage_path(), std::ios::binary | std::ios::trunc);
    if (!o) {
        diag::log_tagged_fmt("upstream", "save_to_disk open_failed");
        set_err("upstream_chains_write_open_failed");
        return false;
    }
    std::string s_dump = out.dump(2);
    o.write(s_dump.data(), static_cast<std::streamsize>(s_dump.size()));
    diag::log_tagged_fmt("upstream", "save_to_disk ok chains=%zu active_id=%llu bytes=%zu",
        count, static_cast<unsigned long long>(active), s_dump.size());
    return true;
}

bool load_from_disk()
{
    diag::log_tagged_fmt("upstream", "load_from_disk entry");
    const std::string path = storage_path();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        diag::log_tagged_fmt("upstream", "load_from_disk new_store path=%s", path.c_str());
        return save_to_disk();
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string data = ss.str();
    if (data.empty()) {
        diag::log_tagged_fmt("upstream", "load_from_disk file_empty");
        return false;
    }
    diag::log_tagged_fmt("upstream", "load_from_disk parsing bytes=%zu", data.size());
    nlohmann::json root;
    try { root = nlohmann::json::parse(data, nullptr, false); } catch (...) {
        diag::log_tagged_fmt("upstream", "load_from_disk parse_exception");
        set_err("parse_failed");
        return false;
    }
    if (root.is_discarded() || !root.is_object()) {
        diag::log_tagged_fmt("upstream", "load_from_disk not_object discarded=%d",
            static_cast<int>(root.is_discarded()));
        set_err("not_object");
        return false;
    }

    auto& st = s();
    std::vector<upstream_chain_t> loaded;
    uint64_t max_id = 0;
    if (root.contains("chains") && root["chains"].is_array()) {
        for (const auto& j : root["chains"]) {
            upstream_chain_t c;
            if (!chain_from_json(j, c)) {
                diag::log_tagged_fmt("upstream", "load_from_disk chain_parse_failed skipping");
                continue;
            }
            if (c.id > max_id) max_id = c.id;
            loaded.push_back(c);
        }
    }
    diag::log_tagged_fmt("upstream", "load_from_disk loaded chains=%zu max_id=%llu",
        loaded.size(), static_cast<unsigned long long>(max_id));
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.chains = std::move(loaded);
    }
    st.next_id.store(max_id + 1);
    if (root.contains("active_id") && root["active_id"].is_number_unsigned()) {
        uint64_t aid = root["active_id"].get<uint64_t>();
        st.active_id.store(aid);
        diag::log_tagged_fmt("upstream", "load_from_disk restored active_id=%llu",
            static_cast<unsigned long long>(aid));
    }
    diag::log_tagged_fmt("upstream", "load_from_disk done next_id=%llu",
        static_cast<unsigned long long>(st.next_id.load()));
    return true;
}

std::string last_error()
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    diag::log_tagged_fmt("upstream", "last_error queried val=%s", st.last_err.c_str());
    return st.last_err;
}

}
}
}
