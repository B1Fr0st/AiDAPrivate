#include "mitm_proxy.hpp"
#include "cert_generator.hpp"
#include "standalone_driver.hpp"
#include "protocol_parser.hpp"
#include "http_parser_engine.hpp"
#include "http2_session.hpp"
#include "script_engine.hpp"
#include "../infra/work_queue.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

namespace mitm_proxy {

struct wsa_guard_t {
    WSADATA data{};
    bool ok = false;
    wsa_guard_t() { ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0); }
    ~wsa_guard_t() { if (ok) WSACleanup(); }
};

static wsa_guard_t s_wsa_guard;


static std::string addr_to_string(const sockaddr_in& addr) {
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    return buf;
}

static void close_socket(SOCKET s) {
    if (s != INVALID_SOCKET) {
        ::shutdown(s, SD_BOTH);
        closesocket(s);
    }
}


struct hold_outcome_t {
    hold_decision_t       decision = hold_decision_t::forward;
    std::vector<uint8_t>  modified_request;
};

static hold_outcome_t hold_until_decision(state_t& state, http_exchange exchange) {
    auto wait = std::make_shared<held_wait_t>();
    uint64_t exchange_id = exchange.id;

    http_exchange* held_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lock(state.held_mutex);
        state.held_storage.push_back(std::move(exchange));
        held_ptr = &state.held_storage.back();
        state.held_exchanges.push_back(held_ptr);
        state.held_waits.emplace(exchange_id, wait);
    }
    state.held_cv.notify_all();

    bool released = false;
    hold_decision_t decision = hold_decision_t::forward;
    std::vector<uint8_t> modified;
    {
        std::unique_lock<std::mutex> wlock(wait->mtx);
        wait->cv.wait(wlock, [&wait, &state]() {
            return wait->released || !state.running.load() || !state.proxy_alive.load();
        });
        released = wait->released;
        decision = wait->decision;
        modified = std::move(wait->modified_request);
    }

    {
        std::lock_guard<std::mutex> lock(state.held_mutex);
        if (held_ptr) {
            auto vit = std::find(state.held_exchanges.begin(), state.held_exchanges.end(), held_ptr);
            if (vit != state.held_exchanges.end())
                state.held_exchanges.erase(vit);

            auto wit = state.held_waits.find(exchange_id);
            if (wit != state.held_waits.end())
                state.held_waits.erase(wit);

            for (auto it = state.held_storage.begin(); it != state.held_storage.end(); ++it) {
                if (&(*it) == held_ptr) {
                    state.held_storage.erase(it);
                    break;
                }
            }
        }
    }

    hold_outcome_t outcome;
    if (!released) {
        outcome.decision = hold_decision_t::drop;
    } else if (decision == hold_decision_t::pending) {
        outcome.decision = hold_decision_t::forward;
    } else {
        outcome.decision = decision;
    }
    outcome.modified_request = std::move(modified);
    return outcome;
}

static constexpr uint8_t kCrlfCrlf[4] = { '\r', '\n', '\r', '\n' };

static bool recv_all(SOCKET s, std::vector<uint8_t>& out, size_t max_size, int timeout_ms = 5000) {
    fd_set fds;
    timeval tv;

    out.clear();
    out.reserve(4096);

    while (out.size() < max_size) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        FD_ZERO(&fds);
        FD_SET(s, &fds);

        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) break;

        uint8_t buf[8192];
        int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n <= 0) break;
        out.insert(out.end(), buf, buf + n);


        if (out.size() >= 4) {
            auto it = std::search(out.begin(), out.end(), kCrlfCrlf, kCrlfCrlf + 4);
            if (it != out.end()) break;
        }
    }
    return !out.empty();
}

static bool recv_ssl_all(SSL* ssl, std::vector<uint8_t>& out, size_t max_size) {
    out.clear();
    out.reserve(4096);

    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    while (out.size() < max_size) {
        uint8_t buf[8192];
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                WSAPOLLFD pfd{};
                pfd.fd = fd;
                pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
                int pr = WSAPoll(&pfd, 1, 30000);
                if (pr <= 0) break;
                continue;
            }
            break;
        }
        out.insert(out.end(), buf, buf + n);


        if (out.size() >= 4) {
            auto it = std::search(out.begin(), out.end(), kCrlfCrlf, kCrlfCrlf + 4);
            if (it != out.end()) break;
        }
    }
    return !out.empty();
}


static size_t parse_content_length(const std::string& headers) {
    auto find_ci = [](const std::string& h, const char* needle, size_t needle_len) -> size_t {
        if (needle_len == 0 || h.size() < needle_len) return std::string::npos;
        for (size_t i = 0; i + needle_len <= h.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle_len; ++j) {
                char a = static_cast<char>(::tolower(static_cast<unsigned char>(h[i + j])));
                char b = static_cast<char>(::tolower(static_cast<unsigned char>(needle[j])));
                if (a != b) { match = false; break; }
            }
            if (match) return i;
        }
        return std::string::npos;
    };
    static const char kCl[] = "content-length:";
    size_t cl_pos = find_ci(headers, kCl, sizeof(kCl) - 1);
    if (cl_pos == std::string::npos) return 0;
    size_t val_start = cl_pos + (sizeof(kCl) - 1);
    while (val_start < headers.size() && (headers[val_start] == ' ' || headers[val_start] == '\t')) val_start++;
    size_t val_end = headers.find("\r\n", val_start);
    if (val_end == std::string::npos) return 0;
    std::string val_str = headers.substr(val_start, val_end - val_start);
    char* end = nullptr;
    errno = 0;
    unsigned long long v = strtoull(val_str.c_str(), &end, 10);
    if (errno != 0 || end == val_str.c_str() || v > static_cast<unsigned long long>(SIZE_MAX)) return 0;
    return static_cast<size_t>(v);
}

static void read_remaining_body_ssl(SSL* ssl, std::vector<uint8_t>& data, size_t max_size) {
    auto hdr_end = std::search(data.begin(), data.end(), kCrlfCrlf, kCrlfCrlf + 4);
    if (hdr_end == data.end()) return;

    size_t hdr_size = static_cast<size_t>(std::distance(data.begin(), hdr_end)) + 4;
    std::string headers(data.begin(), data.begin() + static_cast<ptrdiff_t>(hdr_size));


    bool is_chunked = false;
    {
        std::string headers_lower = headers;
        std::transform(headers_lower.begin(), headers_lower.end(), headers_lower.begin(),
            [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
        is_chunked = (headers_lower.find("transfer-encoding: chunked") != std::string::npos);
    }

    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));

    auto ssl_read_one = [&](uint8_t* buf, int max_n) -> int {
        while (true) {
            int n = SSL_read(ssl, buf, max_n);
            if (n > 0) return n;
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                WSAPOLLFD pfd{};
                pfd.fd = fd;
                pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
                int pr = WSAPoll(&pfd, 1, 30000);
                if (pr <= 0) return -1;
                continue;
            }
            return -1;
        }
    };

    if (is_chunked) {

        while (data.size() < max_size) {

            if (data.size() >= hdr_size + 5) {
                std::string body_str(data.begin() + static_cast<ptrdiff_t>(hdr_size), data.end());
                if (body_str.find("\r\n0\r\n\r\n") != std::string::npos ||
                    (body_str.size() >= 5 && body_str.compare(0, 5, "0\r\n\r\n") == 0)) break;
            }

            uint8_t buf[8192];
            int n = ssl_read_one(buf, sizeof(buf));
            if (n <= 0) break;
            data.insert(data.end(), buf, buf + n);
        }
    } else {

        size_t content_length = parse_content_length(headers);
        if (content_length > 0) {
            size_t total_needed = hdr_size + content_length;
            if (total_needed > max_size) total_needed = max_size;

            while (data.size() < total_needed) {
                uint8_t buf[8192];
                int remaining = static_cast<int>(std::min(sizeof(buf), total_needed - data.size()));
                int n = ssl_read_one(buf, remaining);
                if (n <= 0) break;
                data.insert(data.end(), buf, buf + n);
            }
        }
    }
}

static void read_remaining_body(SOCKET s, std::vector<uint8_t>& data, size_t max_size, int timeout_ms = 5000) {
    auto hdr_end = std::search(data.begin(), data.end(), kCrlfCrlf, kCrlfCrlf + 4);
    if (hdr_end == data.end()) return;

    size_t hdr_size = static_cast<size_t>(std::distance(data.begin(), hdr_end)) + 4;
    std::string headers(data.begin(), data.begin() + static_cast<ptrdiff_t>(hdr_size));


    bool is_chunked = false;
    {
        std::string headers_lower = headers;
        std::transform(headers_lower.begin(), headers_lower.end(), headers_lower.begin(),
            [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
        is_chunked = (headers_lower.find("transfer-encoding: chunked") != std::string::npos);
    }

    fd_set fds;
    timeval tv;

    if (is_chunked) {
        while (data.size() < max_size) {
            if (data.size() >= hdr_size + 5) {
                std::string body_str(data.begin() + static_cast<ptrdiff_t>(hdr_size), data.end());
                if (body_str.find("\r\n0\r\n\r\n") != std::string::npos ||
                    (body_str.size() >= 5 && body_str.compare(0, 5, "0\r\n\r\n") == 0)) break;
            }

            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            FD_ZERO(&fds);
            FD_SET(s, &fds);
            int sel = select(0, &fds, nullptr, nullptr, &tv);
            if (sel <= 0) break;

            uint8_t buf[8192];
            int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
            if (n <= 0) break;
            data.insert(data.end(), buf, buf + n);
        }
    } else {
        size_t content_length = parse_content_length(headers);
        if (content_length > 0) {
            size_t total_needed = hdr_size + content_length;
            if (total_needed > max_size) total_needed = max_size;

            while (data.size() < total_needed) {
                tv.tv_sec = timeout_ms / 1000;
                tv.tv_usec = (timeout_ms % 1000) * 1000;
                FD_ZERO(&fds);
                FD_SET(s, &fds);
                int sel = select(0, &fds, nullptr, nullptr, &tv);
                if (sel <= 0) break;

                uint8_t buf[8192];
                int n = recv(s, reinterpret_cast<char*>(buf),
                    static_cast<int>(std::min(sizeof(buf), total_needed - data.size())), 0);
                if (n <= 0) break;
                data.insert(data.end(), buf, buf + n);
            }
        }
    }
}


static bool parse_uint16(const std::string& s, uint16_t& out) {
    if (s.empty()) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long v = strtoul(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || v == 0 || v > 65535) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

static void parse_connect_target(const std::string& line, std::string& host, uint16_t& port) {

    size_t sp = line.find(' ');
    if (sp == std::string::npos) return;
    size_t sp2 = line.find(' ', sp + 1);
    std::string target = (sp2 != std::string::npos) ? line.substr(sp + 1, sp2 - sp - 1) : line.substr(sp + 1);

    size_t colon = target.rfind(':');
    if (colon != std::string::npos) {
        host = target.substr(0, colon);
        uint16_t parsed_port = 0;
        if (!parse_uint16(target.substr(colon + 1), parsed_port)) {
            port = 443;
            return;
        }
        port = parsed_port;
    } else {
        host = target;
        port = 443;
    }
}


static SOCKET try_connect_address(const sockaddr* addr, int addr_len, int family, int socktype, int proto) {
    SOCKET s = socket(family, socktype, proto);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    u_long nonblocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonblocking) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    constexpr int kConnectTimeoutMs = 10000;
    int cr = connect(s, addr, addr_len);
    if (cr != 0) {
        int werr = WSAGetLastError();
        if (werr != WSAEWOULDBLOCK && werr != WSAEINPROGRESS) {
            closesocket(s);
            return INVALID_SOCKET;
        }

        WSAPOLLFD pfd{};
        pfd.fd = s;
        pfd.events = POLLOUT;
        int pr = WSAPoll(&pfd, 1, kConnectTimeoutMs);
        if (pr <= 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }

        int so_err = 0;
        int so_err_len = sizeof(so_err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_err_len) != 0 || so_err != 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }

    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);
    DWORD io_timeout_ms = 30000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
    return s;
}

static SOCKET connect_tcp(const std::string& host, uint16_t port) {
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);

    SOCKET connected = INVALID_SOCKET;
    if (rc == 0 && result) {
        for (addrinfo* ai = result; ai != nullptr && connected == INVALID_SOCKET; ai = ai->ai_next) {
            connected = try_connect_address(ai->ai_addr, static_cast<int>(ai->ai_addrlen),
                                            ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        }
        freeaddrinfo(result);
        if (connected != INVALID_SOCKET) return connected;
    }

    PDNS_RECORD dns_rec = nullptr;
    DNS_STATUS ds = DnsQuery_A(host.c_str(), DNS_TYPE_A,
                               DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                               nullptr, &dns_rec, nullptr);
    if (ds == 0 && dns_rec) {
        for (PDNS_RECORD r = dns_rec; r != nullptr && connected == INVALID_SOCKET; r = r->pNext) {
            if (r->wType != DNS_TYPE_A) continue;
            sockaddr_in sin = {};
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port);
            sin.sin_addr.s_addr = r->Data.A.IpAddress;
            connected = try_connect_address(reinterpret_cast<const sockaddr*>(&sin), sizeof(sin),
                                            AF_INET, SOCK_STREAM, IPPROTO_TCP);
        }
        DnsRecordListFree(dns_rec, DnsFreeRecordList);
        if (connected != INVALID_SOCKET) return connected;
    }

    PDNS_RECORD dns_rec6 = nullptr;
    ds = DnsQuery_A(host.c_str(), DNS_TYPE_AAAA,
                    DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                    nullptr, &dns_rec6, nullptr);
    if (ds == 0 && dns_rec6) {
        for (PDNS_RECORD r = dns_rec6; r != nullptr && connected == INVALID_SOCKET; r = r->pNext) {
            if (r->wType != DNS_TYPE_AAAA) continue;
            sockaddr_in6 sin6 = {};
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = htons(port);
            memcpy(&sin6.sin6_addr, &r->Data.AAAA.Ip6Address, sizeof(sin6.sin6_addr));
            connected = try_connect_address(reinterpret_cast<const sockaddr*>(&sin6), sizeof(sin6),
                                            AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        }
        DnsRecordListFree(dns_rec6, DnsFreeRecordList);
    }
    return connected;
}


static bool recv_exact(SOCKET s, uint8_t* buf, size_t need) {
    size_t got = 0;
    while (got < need) {
        int n = recv(s, reinterpret_cast<char*>(buf + got), static_cast<int>(need - got), 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

static bool send_exact(SOCKET s, const uint8_t* buf, size_t need) {
    size_t sent = 0;
    while (sent < need) {
        int n = send(s, reinterpret_cast<const char*>(buf + sent), static_cast<int>(need - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static bool socks5_handshake(SOCKET s, const std::string& target_host, uint16_t target_port,
                              const std::string& username, const std::string& password) {
    if (target_host.empty() || target_host.size() > 255) return false;
    if (username.size() > 255 || password.size() > 255) return false;

    bool use_auth = !username.empty();


    uint8_t greeting[4];
    greeting[0] = 0x05;
    if (use_auth) {
        greeting[1] = 0x02;
        greeting[2] = 0x00;
        greeting[3] = 0x02;
        if (!send_exact(s, greeting, 4)) return false;
    } else {
        greeting[1] = 0x01;
        greeting[2] = 0x00;
        if (!send_exact(s, greeting, 3)) return false;
    }


    uint8_t choice[2];
    if (!recv_exact(s, choice, 2)) return false;
    if (choice[0] != 0x05) return false;


    if (choice[1] == 0x02) {
        if (!use_auth) return false;
        std::vector<uint8_t> auth_req;
        auth_req.reserve(3 + username.size() + password.size());
        auth_req.push_back(0x01);
        auth_req.push_back(static_cast<uint8_t>(username.size()));
        auth_req.insert(auth_req.end(), username.begin(), username.end());
        auth_req.push_back(static_cast<uint8_t>(password.size()));
        auth_req.insert(auth_req.end(), password.begin(), password.end());
        if (!send_exact(s, auth_req.data(), auth_req.size())) return false;

        uint8_t auth_resp[2];
        if (!recv_exact(s, auth_resp, 2)) return false;
        if (auth_resp[1] != 0x00) return false;
    } else if (choice[1] != 0x00) {
        return false;
    }


    std::vector<uint8_t> conn_req;
    conn_req.reserve(7 + target_host.size());
    conn_req.push_back(0x05);
    conn_req.push_back(0x01);
    conn_req.push_back(0x00);
    conn_req.push_back(0x03);
    conn_req.push_back(static_cast<uint8_t>(target_host.size()));
    conn_req.insert(conn_req.end(), target_host.begin(), target_host.end());
    conn_req.push_back(static_cast<uint8_t>((target_port >> 8) & 0xFF));
    conn_req.push_back(static_cast<uint8_t>(target_port & 0xFF));

    if (!send_exact(s, conn_req.data(), conn_req.size())) return false;


    uint8_t resp[4];
    if (!recv_exact(s, resp, 4)) return false;
    if (resp[0] != 0x05 || resp[1] != 0x00) return false;


    if (resp[3] == 0x01) {
        uint8_t drain[6];
        if (!recv_exact(s, drain, 6)) return false;
    } else if (resp[3] == 0x04) {
        uint8_t drain[18];
        if (!recv_exact(s, drain, 18)) return false;
    } else if (resp[3] == 0x03) {
        uint8_t dlen;
        if (!recv_exact(s, &dlen, 1)) return false;
        std::vector<uint8_t> drain(static_cast<size_t>(dlen) + 2);
        if (!recv_exact(s, drain.data(), drain.size())) return false;
    } else {
        return false;
    }

    return true;
}


static bool http_connect_handshake(SOCKET s, const std::string& target_host, uint16_t target_port,
                                    const std::string& username, const std::string& password) {
    std::string req = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\n"
                      "Host: " + target_host + ":" + std::to_string(target_port) + "\r\n";


    if (!username.empty()) {
        std::string creds = username + ":" + password;

        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        encoded.reserve(((creds.size() + 2) / 3) * 4);
        for (size_t i = 0; i < creds.size(); i += 3) {
            uint32_t n = static_cast<uint32_t>(static_cast<uint8_t>(creds[i])) << 16;
            if (i + 1 < creds.size()) n |= static_cast<uint32_t>(static_cast<uint8_t>(creds[i + 1])) << 8;
            if (i + 2 < creds.size()) n |= static_cast<uint32_t>(static_cast<uint8_t>(creds[i + 2]));
            encoded.push_back(b64[(n >> 18) & 0x3F]);
            encoded.push_back(b64[(n >> 12) & 0x3F]);
            encoded.push_back((i + 1 < creds.size()) ? b64[(n >> 6) & 0x3F] : '=');
            encoded.push_back((i + 2 < creds.size()) ? b64[n & 0x3F] : '=');
        }
        req += "Proxy-Authorization: Basic " + encoded + "\r\n";
    }
    req += "\r\n";

    if (!send_exact(s, reinterpret_cast<const uint8_t*>(req.data()), req.size())) return false;


    std::string response;
    char buf[1];
    while (response.size() < 4096) {
        int n = recv(s, buf, 1, 0);
        if (n <= 0) return false;
        response.push_back(buf[0]);
        if (response.size() >= 4 && response.compare(response.size() - 4, 4, "\r\n\r\n") == 0)
            break;
    }


    size_t sp = response.find(' ');
    if (sp == std::string::npos) return false;
    size_t sp2 = response.find(' ', sp + 1);
    std::string code = (sp2 == std::string::npos)
        ? response.substr(sp + 1)
        : response.substr(sp + 1, sp2 - sp - 1);
    return code.size() >= 3 && code[0] == '2' && code[1] == '0' && code[2] == '0';
}

static SOCKET connect_to_target(const std::string& host, uint16_t port) {
    const auto& upstream = g_state.config.upstream;

    if (upstream.type == upstream_proxy_config::type_t::none) {

        return connect_tcp(host, port);
    }


    SOCKET s = connect_tcp(upstream.host, upstream.port);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    bool ok = false;
    if (upstream.type == upstream_proxy_config::type_t::socks5) {
        ok = socks5_handshake(s, host, port, upstream.username, upstream.password);
    } else if (upstream.type == upstream_proxy_config::type_t::http_connect) {
        ok = http_connect_handshake(s, host, port, upstream.username, upstream.password);
    }

    if (!ok) {
        close_socket(s);
        return INVALID_SOCKET;
    }
    return s;
}


static bool ssl_handshake_with_timeout(SSL* ssl, int (*op)(SSL*), int timeout_ms_total = 30000) {
    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    u_long nonblocking = 1;
    if (ioctlsocket(fd, FIONBIO, &nonblocking) != 0) return false;

    uint64_t deadline = GetTickCount64() + static_cast<uint64_t>(timeout_ms_total);
    bool success = false;

    while (true) {
        int rc = op(ssl);
        if (rc == 1) { success = true; break; }
        int err = SSL_get_error(ssl, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) break;

        uint64_t now = GetTickCount64();
        if (now >= deadline) break;
        int remaining = static_cast<int>(deadline - now);

        WSAPOLLFD pfd{};
        pfd.fd = fd;
        pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
        int pr = WSAPoll(&pfd, 1, remaining);
        if (pr <= 0) break;
    }

    u_long blocking = 0;
    ioctlsocket(fd, FIONBIO, &blocking);
    return success;
}

static void websocket_relay(SSL* client_ssl, SSL* target_ssl, http_exchange& exchange, state_t& state) {
    exchange.is_websocket = true;
    fd_set fds;
    bool done = false;

    SOCKET client_fd = static_cast<SOCKET>(SSL_get_fd(client_ssl));
    SOCKET target_fd = static_cast<SOCKET>(SSL_get_fd(target_ssl));


    std::vector<uint8_t> client_buf;
    std::vector<uint8_t> target_buf;
    client_buf.reserve(65536);
    target_buf.reserve(65536);

    auto process_frames = [&](std::vector<uint8_t>& buf, bool outbound,
                              SSL* from_ssl, SSL* to_ssl) {
        while (buf.size() >= 2) {
            auto frame = protocol_parser::parse_ws_frame(buf.data(), buf.size());
            if (!frame.valid || frame.total_consumed == 0) break;


            std::vector<uint8_t> payload;
            if (frame.masked) {
                payload = protocol_parser::unmask_payload(frame);
            } else {
                payload = std::move(frame.payload);
            }


            http_exchange::ws_frame_entry entry;
            entry.timestamp = GetTickCount64();
            entry.outbound = outbound;
            entry.opcode = frame.opcode;
            entry.payload = payload;
            {
                std::lock_guard<std::mutex> lock(state.history_mutex);
                exchange.ws_frames.push_back(std::move(entry));
            }


            bool should_forward = true;
            std::vector<uint8_t> forward_payload = payload;
            if (script_engine::is_initialized()) {
                script_engine::hook_ws_frame_data ws_data;
                ws_data.host = exchange.target_host;
                ws_data.port = exchange.target_port;
                ws_data.is_outbound = outbound;
                ws_data.payload = payload;
                ws_data.is_text = (frame.opcode == protocol_parser::ws_opcode::text);
                script_engine::invoke_hook(script_engine::hook_type::on_websocket_frame, ws_data);
                if (ws_data.dropped) { should_forward = false; }
                if (ws_data.modified) { forward_payload = std::move(ws_data.payload); }
            }

            if (should_forward) {

                std::vector<uint8_t> out_frame;
                uint8_t b0 = static_cast<uint8_t>((frame.fin ? 0x80 : 0x00) |
                             (static_cast<uint8_t>(frame.opcode) & 0x0F));
                out_frame.push_back(b0);

                uint8_t mask_bit = outbound ? 0x80 : 0x00;

                if (forward_payload.size() < 126) {
                    out_frame.push_back(static_cast<uint8_t>(forward_payload.size()) | mask_bit);
                } else if (forward_payload.size() <= 0xFFFF) {
                    out_frame.push_back(static_cast<uint8_t>(126) | mask_bit);
                    uint16_t len16 = static_cast<uint16_t>(forward_payload.size());
                    out_frame.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFF));
                    out_frame.push_back(static_cast<uint8_t>(len16 & 0xFF));
                } else {
                    out_frame.push_back(static_cast<uint8_t>(127) | mask_bit);
                    uint64_t len64 = forward_payload.size();
                    for (int i = 7; i >= 0; i--) {
                        out_frame.push_back(static_cast<uint8_t>((len64 >> (i * 8)) & 0xFF));
                    }
                }

                if (outbound) {
                    uint8_t mask_key[4];
                    if (RAND_bytes(mask_key, 4) != 1) {
                        uint64_t tk = GetTickCount64();
                        for (int i = 0; i < 4; i++) mask_key[i] = static_cast<uint8_t>((tk >> (i * 8)) & 0xFF);
                    }
                    out_frame.push_back(mask_key[0]);
                    out_frame.push_back(mask_key[1]);
                    out_frame.push_back(mask_key[2]);
                    out_frame.push_back(mask_key[3]);
                    size_t mask_off = out_frame.size();
                    out_frame.insert(out_frame.end(), forward_payload.begin(), forward_payload.end());
                    for (size_t i = 0; i < forward_payload.size(); ++i) {
                        out_frame[mask_off + i] ^= mask_key[i & 3];
                    }
                } else {
                    out_frame.insert(out_frame.end(), forward_payload.begin(), forward_payload.end());
                }
                SSL_write(to_ssl, out_frame.data(), static_cast<int>(out_frame.size()));
            }

            if (outbound) {
                exchange.ws_frames_sent++;
                state.total_bytes_in.fetch_add(frame.total_consumed);
            } else {
                exchange.ws_frames_recv++;
                state.total_bytes_out.fetch_add(frame.total_consumed);
            }


            if (frame.opcode == protocol_parser::ws_opcode::close) {
                done = true;
                break;
            }

            buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(frame.total_consumed));
        }
    };

    uint8_t read_buf[65536];
    while (!done && state.running.load()) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(target_fd, &fds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        SOCKET max_fd = (client_fd > target_fd) ? client_fd : target_fd;
        int sel = select(static_cast<int>(max_fd + 1), &fds, nullptr, nullptr, &tv);
        if (sel <= 0) { if (sel < 0) done = true; continue; }

        if (FD_ISSET(client_fd, &fds)) {
            int n = SSL_read(client_ssl, read_buf, sizeof(read_buf));
            if (n <= 0) { done = true; break; }
            client_buf.insert(client_buf.end(), read_buf, read_buf + n);
            process_frames(client_buf, true, client_ssl, target_ssl);
        }

        if (FD_ISSET(target_fd, &fds)) {
            int n = SSL_read(target_ssl, read_buf, sizeof(read_buf));
            if (n <= 0) { done = true; break; }
            target_buf.insert(target_buf.end(), read_buf, read_buf + n);
            process_frames(target_buf, false, target_ssl, client_ssl);
        }
    }
}


static bool is_websocket_upgrade(const protocol_parser::http_response& resp) {
    if (resp.status_code != 101) return false;
    auto iequal = [](const std::string& a, const char* b) -> bool {
        size_t blen = strlen(b);
        if (a.size() != blen) return false;
        for (size_t i = 0; i < blen; ++i) {
            char ca = static_cast<char>(::tolower(static_cast<unsigned char>(a[i])));
            char cb = static_cast<char>(::tolower(static_cast<unsigned char>(b[i])));
            if (ca != cb) return false;
        }
        return true;
    };
    for (const auto& h : resp.headers) {
        if (iequal(h.name, "Upgrade")) {
            std::string val = h.value;
            std::transform(val.begin(), val.end(), val.begin(),
                [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
            if (val == "websocket") return true;
        }
    }
    return false;
}


static void handle_h2_session(SSL* client_ssl, SSL* target_ssl,
                               const std::string& target_host, uint16_t target_port,
                               const std::string& client_addr, uint16_t client_port,
                               state_t& state) {
    h2_session::session client_session(h2_session::session::role::server);
    h2_session::session target_session(h2_session::session::role::client);


    bool init_ok = client_session.initialize([&](const uint8_t* data, size_t len) -> ssize_t {
        return static_cast<ssize_t>(SSL_write(client_ssl, data, static_cast<int>(len)));
    }) && target_session.initialize([&](const uint8_t* data, size_t len) -> ssize_t {
        return static_cast<ssize_t>(SSL_write(target_ssl, data, static_cast<int>(len)));
    });
    if (!init_ok) return;


    client_session.set_on_request([&](const h2_session::stream_data& sd) {

        http_exchange exchange;
        exchange.id = state.next_id++;
        exchange.timestamp = GetTickCount64();
        exchange.client_addr = client_addr;
        exchange.client_port = client_port;
        exchange.target_host = target_host;
        exchange.target_port = target_port;
        exchange.is_tls = true;
        exchange.tls_sni = target_host;
        exchange.alpn_protocol = "h2";
        exchange.is_h2 = true;
        exchange.h2_stream_id = sd.stream_id;
        exchange.request_time = GetTickCount64();
        exchange.request.valid = true;
        exchange.request.method = sd.method;
        exchange.request.uri = sd.path;
        exchange.request.version = "HTTP/2";
        for (const auto& h : sd.request_headers) {
            exchange.request.headers.push_back({h.name, h.value});
        }
        exchange.request_size = sd.request_body.size();
        exchange.raw_request = sd.request_body;


        if (script_engine::is_initialized()) {
            script_engine::hook_request_data hook_data;
            hook_data.method = sd.method;
            hook_data.uri = sd.path;
            hook_data.host = target_host;
            hook_data.port = target_port;
            hook_data.is_tls = true;
            for (const auto& h : sd.request_headers)
                hook_data.headers[h.name] = h.value;
            hook_data.body = sd.request_body;
            script_engine::invoke_hook(script_engine::hook_type::on_request, hook_data);
            if (hook_data.dropped) {
                exchange.state = http_exchange::state_t::dropped;
                std::lock_guard<std::mutex> lock(state.history_mutex);
                state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
                return;
            }
        }

        state.total_requests.fetch_add(1);
        state.total_bytes_in.fetch_add(sd.request_body.size());
        exchange.state = http_exchange::state_t::forwarding;


        target_session.submit_request(sd.method, sd.path, sd.authority, sd.scheme, sd.request_headers, sd.request_body);


        std::lock_guard<std::mutex> lock(state.history_mutex);
        state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
        while (state.history.size() > state.config.max_history)
            state.history.pop_front();
    });


    target_session.set_on_response([&](const h2_session::stream_data& sd) {

        if (script_engine::is_initialized()) {
            script_engine::hook_response_data hook_data;
            hook_data.status_code = sd.status_code;
            hook_data.host = target_host;
            hook_data.port = target_port;
            for (const auto& h : sd.response_headers)
                hook_data.headers[h.name] = h.value;
            hook_data.body = sd.response_body;
            script_engine::invoke_hook(script_engine::hook_type::on_response, hook_data);
            if (hook_data.dropped) return;
        }

        state.total_bytes_out.fetch_add(sd.response_body.size());


        client_session.submit_response(sd.stream_id, sd.status_code, sd.response_headers, sd.response_body);


        std::lock_guard<std::mutex> lock(state.history_mutex);
        for (auto it = state.history.rbegin(); it != state.history.rend(); ++it) {
            auto& ex_ref = **it;
            if (ex_ref.is_h2 && ex_ref.target_host == target_host &&
                ex_ref.target_port == target_port && ex_ref.h2_stream_id == sd.stream_id) {
                ex_ref.response.valid = true;
                ex_ref.response.status_code = sd.status_code;
                for (const auto& h : sd.response_headers)
                    ex_ref.response.headers.push_back({h.name, h.value});
                ex_ref.raw_response = sd.response_body;
                ex_ref.response_size = sd.response_body.size();
                ex_ref.response_time = GetTickCount64();
                ex_ref.latency_ms = ex_ref.response_time - ex_ref.request_time;
                ex_ref.state = http_exchange::state_t::complete;
                break;
            }
        }
    });


    SOCKET client_fd = static_cast<SOCKET>(SSL_get_fd(client_ssl));
    SOCKET target_fd = static_cast<SOCKET>(SSL_get_fd(target_ssl));
    fd_set fds;
    uint8_t buf[16384];
    bool done = false;

    while (!done && state.running.load()) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(target_fd, &fds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        SOCKET max_fd = (client_fd > target_fd) ? client_fd : target_fd;
        int sel = select(static_cast<int>(max_fd + 1), &fds, nullptr, nullptr, &tv);
        if (sel <= 0) { if (sel < 0) done = true; continue; }

        if (FD_ISSET(client_fd, &fds)) {
            int n = SSL_read(client_ssl, buf, sizeof(buf));
            if (n <= 0) { done = true; break; }
            client_session.feed(buf, static_cast<size_t>(n));
        }

        if (FD_ISSET(target_fd, &fds)) {
            int n = SSL_read(target_ssl, buf, sizeof(buf));
            if (n <= 0) { done = true; break; }
            target_session.feed(buf, static_cast<size_t>(n));
        }
    }
}


static void handle_tls_connection(SOCKET client_sock, const std::string& target_host,
                                   uint16_t target_port, const std::string& client_addr,
                                   uint16_t client_port, state_t& state) {

    const auto& ca = cert_generator::get_root_ca();
    if (!ca.valid) {
        close_socket(client_sock);
        return;
    }

    SSL_CTX* ctx = cert_generator::get_ssl_ctx_for_domain(target_host, ca);
    if (!ctx) {
        close_socket(client_sock);
        return;
    }


    static const unsigned char alpn_h2_h1[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };

    if (state.config.enable_h2) {

        SSL_CTX_set_alpn_select_cb(ctx,
            [](SSL*, const unsigned char** out, unsigned char* outlen,
               const unsigned char* in, unsigned int inlen, void*) -> int {
                if (SSL_select_next_proto(
                        const_cast<unsigned char**>(out), outlen,
                        alpn_h2_h1, sizeof(alpn_h2_h1),
                        in, inlen) != OPENSSL_NPN_NEGOTIATED) {
                    return SSL_TLSEXT_ERR_NOACK;
                }
                return SSL_TLSEXT_ERR_OK;
            }, nullptr);
    }


    SSL* client_ssl = SSL_new(ctx);
    if (!client_ssl) {
        close_socket(client_sock);
        return;
    }
    SSL_set_fd(client_ssl, static_cast<int>(client_sock));

    if (!ssl_handshake_with_timeout(client_ssl, SSL_accept)) {
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }


    const unsigned char* alpn_data = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(client_ssl, &alpn_data, &alpn_len);
    std::string client_alpn;
    if (alpn_data && alpn_len > 0)
        client_alpn.assign(reinterpret_cast<const char*>(alpn_data), alpn_len);


    SOCKET target_sock = connect_to_target(target_host, target_port);
    if (target_sock == INVALID_SOCKET) {
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }


    SSL_CTX* target_ctx = SSL_CTX_new(TLS_client_method());
    if (!target_ctx) {
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }


    if (state.config.enable_h2) {
        SSL_CTX_set_alpn_protos(target_ctx, alpn_h2_h1, sizeof(alpn_h2_h1));
    }

    SSL* target_ssl = SSL_new(target_ctx);
    if (!target_ssl) {
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }
    SSL_set_fd(target_ssl, static_cast<int>(target_sock));
    SSL_set_tlsext_host_name(target_ssl, target_host.c_str());

    if (!ssl_handshake_with_timeout(target_ssl, SSL_connect)) {
        SSL_free(target_ssl);
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }


    const unsigned char* target_alpn_data = nullptr;
    unsigned int target_alpn_len = 0;
    SSL_get0_alpn_selected(target_ssl, &target_alpn_data, &target_alpn_len);
    std::string target_alpn;
    if (target_alpn_data && target_alpn_len > 0)
        target_alpn.assign(reinterpret_cast<const char*>(target_alpn_data), target_alpn_len);

    state.active_connections.fetch_add(1);


    if (target_alpn == "h2" && state.config.enable_h2) {
        handle_h2_session(client_ssl, target_ssl, target_host, target_port,
                          client_addr, client_port, state);
    }

    else {

        std::vector<uint8_t> request_data;
        if (recv_ssl_all(client_ssl, request_data, state.config.max_body_size)) {
            read_remaining_body_ssl(client_ssl, request_data, state.config.max_body_size);


            http_exchange exchange;
            exchange.id = state.next_id++;
            exchange.timestamp = GetTickCount64();
            exchange.client_addr = client_addr;
            exchange.client_port = client_port;
            exchange.target_host = target_host;
            exchange.target_port = target_port;
            exchange.is_tls = true;
            exchange.tls_sni = target_host;
            exchange.alpn_protocol = target_alpn.empty() ? "http/1.1" : target_alpn;
            exchange.raw_request = request_data;
            exchange.request_size = request_data.size();
            exchange.request_time = GetTickCount64();
            exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
            exchange.state = http_exchange::state_t::pending;

            state.total_requests.fetch_add(1);
            state.total_bytes_in.fetch_add(request_data.size());


            if (script_engine::is_initialized()) {
                script_engine::hook_request_data hook_data;
                hook_data.method = exchange.request.method;
                hook_data.uri = exchange.request.uri;
                hook_data.host = target_host;
                hook_data.port = target_port;
                hook_data.is_tls = true;
                for (const auto& h : exchange.request.headers)
                    hook_data.headers[h.name] = h.value;
                hook_data.body = request_data;
                script_engine::invoke_hook(script_engine::hook_type::on_request, hook_data);
                if (hook_data.dropped) {
                    exchange.state = http_exchange::state_t::dropped;
                    std::lock_guard<std::mutex> lock(state.history_mutex);
                    state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
                    goto cleanup;
                }
                if (hook_data.modified)
                    request_data = hook_data.body;
            }


            bool should_forward = true;
            if (state.config.intercept_enabled) {
                bool cb_decided = false;
                if (state.intercept_cb) {
                    intercept_action action = state.intercept_cb(exchange);
                    if (action == intercept_action::drop) {
                        exchange.state = http_exchange::state_t::dropped;
                        should_forward = false;
                        cb_decided = true;
                    } else if (action == intercept_action::modify) {
                        request_data = exchange.raw_request;
                        cb_decided = true;
                    } else if (action == intercept_action::forward) {
                        cb_decided = true;
                    }
                }
                if (!cb_decided && should_forward) {
                    exchange.raw_request = request_data;
                    exchange.request_size = request_data.size();
                    hold_outcome_t outcome = hold_until_decision(state, exchange);
                    if (outcome.decision == hold_decision_t::drop) {
                        exchange.state = http_exchange::state_t::dropped;
                        should_forward = false;
                    } else if (outcome.decision == hold_decision_t::modified) {
                        request_data = std::move(outcome.modified_request);
                        exchange.raw_request = request_data;
                        exchange.request_size = request_data.size();
                        exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
                    }
                }
            }

            if (should_forward) {
                exchange.state = http_exchange::state_t::forwarding;


                int sent = SSL_write(target_ssl, request_data.data(), static_cast<int>(request_data.size()));
                if (sent > 0) {

                    std::vector<uint8_t> response_data;
                    if (recv_ssl_all(target_ssl, response_data, state.config.max_body_size)) {
                        read_remaining_body_ssl(target_ssl, response_data, state.config.max_body_size);

                        exchange.raw_response = response_data;
                        exchange.response_size = response_data.size();
                        exchange.response_time = GetTickCount64();
                        exchange.latency_ms = exchange.response_time - exchange.request_time;
                        exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                        exchange.state = http_exchange::state_t::complete;

                        state.total_bytes_out.fetch_add(response_data.size());


                        if (script_engine::is_initialized()) {
                            script_engine::hook_response_data hook_data;
                            hook_data.status_code = exchange.response.status_code;
                            hook_data.host = target_host;
                            hook_data.port = target_port;
                            for (const auto& h : exchange.response.headers)
                                hook_data.headers[h.name] = h.value;
                            hook_data.body = response_data;
                            script_engine::invoke_hook(script_engine::hook_type::on_response, hook_data);
                            if (hook_data.dropped) {
                                exchange.state = http_exchange::state_t::dropped;
                            } else if (hook_data.modified) {
                                response_data = hook_data.body;
                            }
                        }


                        if (exchange.state != http_exchange::state_t::dropped)
                            SSL_write(client_ssl, response_data.data(), static_cast<int>(response_data.size()));


                        if (state.config.enable_websocket && is_websocket_upgrade(exchange.response)) {
                            std::shared_ptr<http_exchange> ws_exchange;
                            {
                                std::lock_guard<std::mutex> lock(state.history_mutex);
                                ws_exchange = std::make_shared<http_exchange>(exchange);
                                state.history.push_back(ws_exchange);
                                while (state.history.size() > state.config.max_history)
                                    state.history.pop_front();
                            }

                            websocket_relay(client_ssl, target_ssl, *ws_exchange, state);
                            goto cleanup_no_history;
                        }
                    } else {
                        exchange.state = http_exchange::state_t::error;
                        exchange.error_msg = "No response from target";
                    }
                } else {
                    exchange.state = http_exchange::state_t::error;
                    exchange.error_msg = "Failed to send to target";
                }
            }


            {
                std::lock_guard<std::mutex> lock(state.history_mutex);
                state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
                while (state.history.size() > state.config.max_history)
                    state.history.pop_front();
            }
        }
    }

cleanup:
cleanup_no_history:
    state.active_connections.fetch_sub(1);


    SSL_shutdown(target_ssl);
    SSL_free(target_ssl);
    SSL_CTX_free(target_ctx);
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close_socket(target_sock);
    close_socket(client_sock);
}


static void handle_plain_connection(SOCKET client_sock, const std::string& client_addr,
                                     uint16_t client_port, state_t& state) {
    state.active_connections.fetch_add(1);


    std::vector<uint8_t> request_data;
    if (!recv_all(client_sock, request_data, state.config.max_body_size)) {
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }
    read_remaining_body(client_sock, request_data, state.config.max_body_size);

    auto req = protocol_parser::parse_http_request(request_data.data(), request_data.size());
    if (!req.valid) {
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }


    std::string target_host = protocol_parser::find_header(req.headers, "Host");
    uint16_t target_port = 80;
    size_t colon = target_host.rfind(':');
    if (colon != std::string::npos) {
        uint16_t parsed_port = 0;
        if (parse_uint16(target_host.substr(colon + 1), parsed_port))
            target_port = parsed_port;
        target_host = target_host.substr(0, colon);
    }

    if (target_host.empty()) {
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }

    http_exchange exchange;
    exchange.id = state.next_id++;
    exchange.timestamp = GetTickCount64();
    exchange.client_addr = client_addr;
    exchange.client_port = client_port;
    exchange.target_host = target_host;
    exchange.target_port = target_port;
    exchange.is_tls = false;
    exchange.raw_request = request_data;
    exchange.request_size = request_data.size();
    exchange.request_time = GetTickCount64();
    exchange.request = req;
    exchange.state = http_exchange::state_t::pending;

    state.total_requests.fetch_add(1);
    state.total_bytes_in.fetch_add(request_data.size());


    if (script_engine::is_initialized()) {
        script_engine::hook_request_data hook_data;
        hook_data.method = req.method;
        hook_data.uri = req.uri;
        hook_data.host = target_host;
        hook_data.port = target_port;
        hook_data.is_tls = false;
        for (const auto& h : req.headers)
            hook_data.headers[h.name] = h.value;
        hook_data.body = request_data;
        script_engine::invoke_hook(script_engine::hook_type::on_request, hook_data);
        if (hook_data.dropped) {
            exchange.state = http_exchange::state_t::dropped;
            std::lock_guard<std::mutex> lock(state.history_mutex);
            state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
            state.active_connections.fetch_sub(1);
            close_socket(client_sock);
            return;
        }
        if (hook_data.modified)
            request_data = hook_data.body;
    }

    bool should_forward = true;
    if (state.config.intercept_enabled) {
        bool cb_decided = false;
        if (state.intercept_cb) {
            intercept_action action = state.intercept_cb(exchange);
            if (action == intercept_action::drop) {
                exchange.state = http_exchange::state_t::dropped;
                should_forward = false;
                cb_decided = true;
            } else if (action == intercept_action::modify) {
                request_data = exchange.raw_request;
                cb_decided = true;
            } else if (action == intercept_action::forward) {
                cb_decided = true;
            }
        }
        if (!cb_decided && should_forward) {
            exchange.raw_request = request_data;
            exchange.request_size = request_data.size();
            hold_outcome_t outcome = hold_until_decision(state, exchange);
            if (outcome.decision == hold_decision_t::drop) {
                exchange.state = http_exchange::state_t::dropped;
                should_forward = false;
            } else if (outcome.decision == hold_decision_t::modified) {
                request_data = std::move(outcome.modified_request);
                exchange.raw_request = request_data;
                exchange.request_size = request_data.size();
                exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
            }
        }
    }

    if (should_forward) {
        exchange.state = http_exchange::state_t::forwarding;
        SOCKET target_sock = connect_to_target(target_host, target_port);
        if (target_sock != INVALID_SOCKET) {
            int sent = send(target_sock, reinterpret_cast<const char*>(request_data.data()),
                            static_cast<int>(request_data.size()), 0);
            if (sent > 0) {
                std::vector<uint8_t> response_data;
                if (recv_all(target_sock, response_data, state.config.max_body_size)) {
                    read_remaining_body(target_sock, response_data, state.config.max_body_size);

                    exchange.raw_response = response_data;
                    exchange.response_size = response_data.size();
                    exchange.response_time = GetTickCount64();
                    exchange.latency_ms = exchange.response_time - exchange.request_time;
                    exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                    exchange.state = http_exchange::state_t::complete;

                    state.total_bytes_out.fetch_add(response_data.size());


                    if (script_engine::is_initialized()) {
                        script_engine::hook_response_data hook_data;
                        hook_data.status_code = exchange.response.status_code;
                        hook_data.host = target_host;
                        hook_data.port = target_port;
                        for (const auto& h : exchange.response.headers)
                            hook_data.headers[h.name] = h.value;
                        hook_data.body = response_data;
                        script_engine::invoke_hook(script_engine::hook_type::on_response, hook_data);
                        if (hook_data.dropped) {
                            exchange.state = http_exchange::state_t::dropped;
                        } else if (hook_data.modified) {
                            response_data = hook_data.body;
                        }
                    }

                    if (exchange.state != http_exchange::state_t::dropped)
                        send(client_sock, reinterpret_cast<const char*>(response_data.data()),
                             static_cast<int>(response_data.size()), 0);
                } else {
                    exchange.state = http_exchange::state_t::error;
                    exchange.error_msg = "No response from target";
                }
            } else {
                exchange.state = http_exchange::state_t::error;
                exchange.error_msg = "Failed to send to target";
            }
            close_socket(target_sock);
        } else {
            exchange.state = http_exchange::state_t::error;
            exchange.error_msg = "Cannot connect to target";
        }
    }

    {
        std::lock_guard<std::mutex> lock(state.history_mutex);
        state.history.push_back(std::make_shared<http_exchange>(std::move(exchange)));
        while (state.history.size() > state.config.max_history)
            state.history.pop_front();
    }

    state.active_connections.fetch_sub(1);
    close_socket(client_sock);
}


static void handle_client(SOCKET client_sock, sockaddr_in client_addr_in, state_t& state) {
    std::string client_addr = addr_to_string(client_addr_in);
    uint16_t client_port = ntohs(client_addr_in.sin_port);


    uint8_t peek_buf[16] = {};
    int peeked = recv(client_sock, reinterpret_cast<char*>(peek_buf), sizeof(peek_buf), MSG_PEEK);
    if (peeked <= 0) {
        close_socket(client_sock);
        return;
    }


    if (peeked >= 7 && memcmp(peek_buf, "CONNECT", 7) == 0) {

        std::vector<uint8_t> connect_req;
        if (!recv_all(client_sock, connect_req, 8192)) {
            close_socket(client_sock);
            return;
        }

        std::string first_line(connect_req.begin(),
            std::find(connect_req.begin(), connect_req.end(), '\r'));
        std::string target_host;
        uint16_t target_port = 443;
        parse_connect_target(first_line, target_host, target_port);

        if (target_host.empty()) {
            close_socket(client_sock);
            return;
        }


        const char* ok_resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(client_sock, ok_resp, static_cast<int>(strlen(ok_resp)), 0);

        if (state.config.decode_tls) {

            handle_tls_connection(client_sock, target_host, target_port, client_addr, client_port, state);
        } else {

            SOCKET target_sock = connect_to_target(target_host, target_port);
            if (target_sock == INVALID_SOCKET) {
                close_socket(client_sock);
                return;
            }

            state.active_connections.fetch_add(1);


            fd_set fds;
            uint8_t buf[8192];
            bool done = false;
            while (!done && state.running.load()) {
                FD_ZERO(&fds);
                FD_SET(client_sock, &fds);
                FD_SET(target_sock, &fds);

                timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                SOCKET max_fd = (client_sock > target_sock) ? client_sock : target_sock;
                int sel = select(static_cast<int>(max_fd + 1), &fds, nullptr, nullptr, &tv);
                if (sel <= 0) { if (sel < 0) done = true; continue; }

                if (FD_ISSET(client_sock, &fds)) {
                    int n = recv(client_sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
                    if (n <= 0) { done = true; break; }
                    send(target_sock, reinterpret_cast<const char*>(buf), n, 0);
                    state.total_bytes_in.fetch_add(static_cast<uint64_t>(n));
                }
                if (FD_ISSET(target_sock, &fds)) {
                    int n = recv(target_sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
                    if (n <= 0) { done = true; break; }
                    send(client_sock, reinterpret_cast<const char*>(buf), n, 0);
                    state.total_bytes_out.fetch_add(static_cast<uint64_t>(n));
                }
            }

            state.active_connections.fetch_sub(1);
            close_socket(target_sock);
            close_socket(client_sock);
        }
    } else {

        handle_plain_connection(client_sock, client_addr, client_port, state);
    }
}


static void worker_thread_func(state_t& state) {
    while (state.proxy_alive.load()) {
        {
            std::unique_lock<std::mutex> lk(state.proxy_start_mtx);
            state.proxy_start_cv.wait(lk, [&state]() {
                return state.running.load() || !state.proxy_alive.load();
            });
        }
        while (state.running.load()) {
            work_item item;
            {
                std::unique_lock<std::mutex> lock(state.work_mutex);
                state.work_cv.wait(lock, [&] {
                    return !state.work_queue.empty() || !state.running.load() || !state.proxy_alive.load();
                });
                if (!state.running.load() && state.work_queue.empty()) break;
                if (state.work_queue.empty()) continue;
                item = state.work_queue.front();
                state.work_queue.pop();
            }

            sockaddr_in client_addr_in = {};
            client_addr_in.sin_family = AF_INET;
            client_addr_in.sin_addr.s_addr = item.client_ip;
            client_addr_in.sin_port = htons(item.client_port);
            handle_client(static_cast<SOCKET>(item.client_socket), client_addr_in, state);
        }
    }
}

static void listener_thread_func(state_t& state) {
    while (state.proxy_alive.load()) {
        {
            std::unique_lock<std::mutex> lk(state.proxy_start_mtx);
            state.proxy_start_cv.wait(lk, [&state]() {
                return state.running.load() || !state.proxy_alive.load();
            });
        }
        while (state.running.load()) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(static_cast<SOCKET>(state.listen_socket), &fds);

            timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int sel = select(0, &fds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;

            sockaddr_in client_addr = {};
            int addr_len = sizeof(client_addr);
            SOCKET client_sock = accept(static_cast<SOCKET>(state.listen_socket),
                reinterpret_cast<sockaddr*>(&client_addr), &addr_len);

            if (client_sock == INVALID_SOCKET) continue;

            work_item item;
            item.client_socket = static_cast<uintptr_t>(client_sock);
            item.client_ip = client_addr.sin_addr.s_addr;
            item.client_port = ntohs(client_addr.sin_port);
            {
                std::lock_guard<std::mutex> lock(state.work_mutex);
                state.work_queue.push(item);
            }
            state.work_cv.notify_one();
        }
    }
}


bool start(const proxy_config& config) {
    if (g_state.running.load()) return false;

    if (!s_wsa_guard.ok) return false;

    if (config.decode_tls && !cert_generator::is_ready()) {
        if (!cert_generator::initialize()) return false;
    }

    g_state.config = config;


    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) return false;


    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(config.bind_port);
    inet_pton(AF_INET, config.bind_addr.c_str(), &bind_addr.sin_addr);

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        closesocket(listen_sock);
        return false;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_sock);
        return false;
    }

    g_state.listen_socket = static_cast<uintptr_t>(listen_sock);
    g_state.running.store(true);
    g_state.proxy_start_cv.notify_all();


    if (config.use_wfp_redirect) {
        if (driver_bridge::using_kernel_driver()) {
            uint8_t local_addr[16] = {};
            inet_pton(AF_INET, config.bind_addr.c_str(), local_addr);

            uint32_t rule_id = 0;
            uint32_t own_pid = static_cast<uint32_t>(GetCurrentProcessId());

            bool ok = driver_bridge::traffic_redirect_op(
                0,
                0,
                6,
                config.redirect_target_port,
                nullptr,
                config.bind_port,
                local_addr,
                2,
                &rule_id,
                own_pid);
            if (ok) {
                g_state.config.wfp_rule_id = rule_id;
            }
        }
    }

    return true;
}

void stop() {
    if (!g_state.running.load()) return;


    if (g_state.config.wfp_rule_id != 0) {
        if (driver_bridge::using_kernel_driver()) {

            driver_bridge::traffic_redirect_op(1, g_state.config.wfp_rule_id);
        }
        g_state.config.wfp_rule_id = 0;
    }

    g_state.running.store(false);


    g_state.work_cv.notify_all();
    g_state.held_cv.notify_all();

    std::vector<std::shared_ptr<held_wait_t>> waits;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        waits.reserve(g_state.held_waits.size());
        for (auto& kv : g_state.held_waits)
            waits.push_back(kv.second);
    }
    for (auto& wait : waits) {
        {
            std::lock_guard<std::mutex> wlock(wait->mtx);
            if (!wait->released) {
                wait->decision = hold_decision_t::drop;
                wait->released = true;
            }
        }
        wait->cv.notify_all();
    }


    if (g_state.listen_socket != ~static_cast<uintptr_t>(0)) {
        closesocket(static_cast<SOCKET>(g_state.listen_socket));
        g_state.listen_socket = ~static_cast<uintptr_t>(0);
    }
}

bool is_running() {
    return g_state.running.load();
}

void pre_initialize() {
    auto& st = g_state;
    st.proxy_alive.store(true);

    state_t* st_ptr = &st;

    st.listener_done.store(false, std::memory_order_release);
    if (!work_queue::post([st_ptr]() {
            listener_thread_func(*st_ptr);
            st_ptr->listener_done.store(true, std::memory_order_release);
        }))
    {
        st.listener_done.store(true, std::memory_order_release);
    }

    for (uint32_t i = 0; i < WORKER_POOL_SIZE; ++i) {
        st.active_worker_count.fetch_add(1, std::memory_order_acq_rel);
        if (!work_queue::post([st_ptr]() {
                worker_thread_func(*st_ptr);
                st_ptr->active_worker_count.fetch_sub(1, std::memory_order_acq_rel);
            }))
        {
            st.active_worker_count.fetch_sub(1, std::memory_order_acq_rel);
        }
    }
}

void shutdown() {
    auto& st = g_state;
    stop();
    st.proxy_alive.store(false);
    st.work_cv.notify_all();
    st.proxy_start_cv.notify_all();
    while (st.active_worker_count.load(std::memory_order_acquire) > 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    while (!st.listener_done.load(std::memory_order_acquire))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

std::vector<http_exchange> get_history(size_t max_count) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    std::vector<http_exchange> result;
    size_t count = g_state.history.size();
    size_t take = (max_count == 0 || max_count >= count) ? count : max_count;
    result.reserve(take);
    size_t skip = count - take;
    size_t i = 0;
    for (const auto& ex_ptr : g_state.history) {
        if (i++ < skip) continue;
        if (ex_ptr) result.push_back(*ex_ptr);
    }
    return result;
}

const http_exchange* find_exchange(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (const auto& ex_ptr : g_state.history) {
        if (ex_ptr && ex_ptr->id == id) return ex_ptr.get();
    }
    return nullptr;
}

void clear_history() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    g_state.history.clear();
    g_state.next_id.store(1);
}

size_t history_count() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    return g_state.history.size();
}

void set_intercept_enabled(bool enabled) {
    g_state.config.intercept_enabled = enabled;
}

bool is_intercept_enabled() {
    return g_state.config.intercept_enabled;
}

void set_intercept_callback(intercept_callback_t cb) {
    g_state.intercept_cb = std::move(cb);
}

static std::shared_ptr<held_wait_t> lookup_wait_locked(uint64_t id) {
    auto it = g_state.held_waits.find(id);
    if (it == g_state.held_waits.end()) return nullptr;
    return it->second;
}

void forward_exchange(uint64_t id) {
    std::shared_ptr<held_wait_t> wait;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        wait = lookup_wait_locked(id);
    }
    if (!wait) return;
    {
        std::lock_guard<std::mutex> wlock(wait->mtx);
        if (wait->released) return;
        wait->decision = hold_decision_t::forward;
        wait->released = true;
    }
    wait->cv.notify_all();
}

void forward_modified(uint64_t id, const std::vector<uint8_t>& modified_request) {
    std::shared_ptr<held_wait_t> wait;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        wait = lookup_wait_locked(id);
    }
    if (!wait) return;
    {
        std::lock_guard<std::mutex> wlock(wait->mtx);
        if (wait->released) return;
        wait->modified_request = modified_request;
        wait->decision = hold_decision_t::modified;
        wait->released = true;
    }
    wait->cv.notify_all();
}

void drop_exchange(uint64_t id) {
    std::shared_ptr<held_wait_t> wait;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        wait = lookup_wait_locked(id);
    }
    if (!wait) return;
    {
        std::lock_guard<std::mutex> wlock(wait->mtx);
        if (wait->released) return;
        wait->decision = hold_decision_t::drop;
        wait->released = true;
    }
    wait->cv.notify_all();
}

void forward_all() {
    std::vector<std::shared_ptr<held_wait_t>> waits;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        waits.reserve(g_state.held_waits.size());
        for (auto& kv : g_state.held_waits)
            waits.push_back(kv.second);
    }
    for (auto& wait : waits) {
        {
            std::lock_guard<std::mutex> wlock(wait->mtx);
            if (wait->released) continue;
            wait->decision = hold_decision_t::forward;
            wait->released = true;
        }
        wait->cv.notify_all();
    }
}

void drop_all() {
    std::vector<std::shared_ptr<held_wait_t>> waits;
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        waits.reserve(g_state.held_waits.size());
        for (auto& kv : g_state.held_waits)
            waits.push_back(kv.second);
    }
    for (auto& wait : waits) {
        {
            std::lock_guard<std::mutex> wlock(wait->mtx);
            if (wait->released) continue;
            wait->decision = hold_decision_t::drop;
            wait->released = true;
        }
        wait->cv.notify_all();
    }
}

std::vector<http_exchange> get_held_exchanges() {
    std::lock_guard<std::mutex> lock(g_state.held_mutex);
    std::vector<http_exchange> result;
    result.reserve(g_state.held_exchanges.size());
    for (const auto* ex : g_state.held_exchanges) {
        if (ex) result.push_back(*ex);
    }
    return result;
}

repeat_result repeat_request(const std::string& host, uint16_t port, bool use_tls,
                             const std::vector<uint8_t>& raw_request) {
    repeat_result result;

    if (!s_wsa_guard.ok) {
        result.error = "WSAStartup failed";
        return result;
    }

    SOCKET sock = connect_to_target(host, port);
    if (sock == INVALID_SOCKET) {
        result.error = "Cannot connect to " + host + ":" + std::to_string(port);
        return result;
    }

    result.exchange.target_host = host;
    result.exchange.target_port = port;
    result.exchange.is_tls = use_tls;
    result.exchange.raw_request = raw_request;
    result.exchange.request_size = raw_request.size();
    result.exchange.request = protocol_parser::parse_http_request(raw_request.data(), raw_request.size());
    result.exchange.request_time = GetTickCount64();

    if (use_tls) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            close_socket(sock);
            result.error = "SSL_CTX_new failed";
            return result;
        }

        SSL* ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "SSL_new failed";
            return result;
        }
        SSL_set_fd(ssl, static_cast<int>(sock));
        SSL_set_tlsext_host_name(ssl, host.c_str());

        if (!ssl_handshake_with_timeout(ssl, SSL_connect)) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "TLS handshake failed";
            return result;
        }

        SSL_write(ssl, raw_request.data(), static_cast<int>(raw_request.size()));

        std::vector<uint8_t> response_data;
        if (recv_ssl_all(ssl, response_data, 16 * 1024 * 1024)) {
            read_remaining_body_ssl(ssl, response_data, 16 * 1024 * 1024);
            result.exchange.raw_response = response_data;
            result.exchange.response_size = response_data.size();
            result.exchange.response_time = GetTickCount64();
            result.exchange.latency_ms = result.exchange.response_time - result.exchange.request_time;
            result.exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
            result.exchange.state = http_exchange::state_t::complete;
            result.success = true;
        } else {
            result.error = "No response from server";
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        send(sock, reinterpret_cast<const char*>(raw_request.data()),
             static_cast<int>(raw_request.size()), 0);

        std::vector<uint8_t> response_data;
        if (recv_all(sock, response_data, 16 * 1024 * 1024)) {
            read_remaining_body(sock, response_data, 16 * 1024 * 1024);
            result.exchange.raw_response = response_data;
            result.exchange.response_size = response_data.size();
            result.exchange.response_time = GetTickCount64();
            result.exchange.latency_ms = result.exchange.response_time - result.exchange.request_time;
            result.exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
            result.exchange.state = http_exchange::state_t::complete;
            result.success = true;
        } else {
            result.error = "No response from server";
        }
    }

    close_socket(sock);
    return result;
}

proxy_stats get_stats() {
    proxy_stats stats;
    stats.running = g_state.running.load();
    stats.total_requests = g_state.total_requests.load();
    stats.total_bytes_in = g_state.total_bytes_in.load();
    stats.total_bytes_out = g_state.total_bytes_out.load();
    stats.active_connections = g_state.active_connections.load();

    {
        std::lock_guard<std::mutex> lock(g_state.history_mutex);
        stats.history_size = g_state.history.size();
    }
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        stats.held_count = g_state.held_exchanges.size();
    }
    return stats;
}

}
