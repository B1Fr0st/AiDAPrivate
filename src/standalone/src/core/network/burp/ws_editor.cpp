#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#ifdef small
#undef small
#endif

#include "ws_editor.hpp"

#include "../../infra/work_queue.hpp"
#include "../../../helpers/diag_log.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace aida {
namespace burp {
namespace ws_editor {

namespace {

std::mutex& err_mtx()  { static std::mutex m; return m; }
std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& m)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = m;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t now_steady_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

std::string lower_ascii(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool is_loopback_host(const std::string& host)
{
    std::string h = lower_ascii(host);
    if (h == "localhost" || h == "::1" || h == "[::1]") return true;
    return h.rfind("127.", 0) == 0;
}

struct wsa_guard_t
{
    bool ok = false;
    wsa_guard_t()
    {
        WSADATA d{};
        ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0);
    }
    ~wsa_guard_t()
    {
        if (ok) WSACleanup();
    }
};

static wsa_guard_t s_wsa_guard;

struct openssl_init_t
{
    openssl_init_t()
    {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    }
};

void ensure_openssl()
{
    static openssl_init_t s_init;
    (void)s_init;
}

std::string base64_encode(const uint8_t* data, size_t len)
{
    static const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t a = data[i];
        uint32_t b = (i + 1 < len) ? data[i + 1] : 0;
        uint32_t c = (i + 2 < len) ? data[i + 2] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out.push_back(alpha[(triple >> 18) & 0x3F]);
        out.push_back(alpha[(triple >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? alpha[(triple >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? alpha[triple & 0x3F]        : '=');
    }
    return out;
}

bool bcrypt_random(uint8_t* out, size_t len)
{
    NTSTATUS s = BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return s == 0;
}

struct connection_t
{
    uint64_t                         id = 0;
    ws_connection_config_t           cfg;
    std::atomic<bool>                running{false};
    std::atomic<bool>                connected{false};
    std::atomic<size_t>              frames_sent{0};
    std::atomic<size_t>              frames_received{0};
    uint64_t                         opened_ms = 0;
    SOCKET                           sock = INVALID_SOCKET;
    SSL_CTX*                         ssl_ctx = nullptr;
    SSL*                             ssl     = nullptr;
    std::mutex                       send_mtx;
    std::mutex                       frames_mtx;
    std::deque<ws_frame_log_t>       frames;
    size_t                           frames_max = 4096;
    std::string                      last_error;
    std::atomic<bool>                recv_worker_alive{false};
    std::atomic<DWORD>               recv_worker_tid{0};
    std::mutex                       recv_worker_mtx;
    std::condition_variable          recv_worker_cv;
    std::mutex                       err_mtx;
};

struct registry_t
{
    std::mutex                                            mtx;
    std::unordered_map<uint64_t, std::shared_ptr<connection_t>> by_id;
    std::atomic<uint64_t>                                 next_id{1};
};

registry_t& registry()
{
    static registry_t r;
    return r;
}

void set_conn_err(connection_t& c, const std::string& msg)
{
    std::lock_guard<std::mutex> lk(c.err_mtx);
    c.last_error = msg;
}

std::string get_conn_err(connection_t& c)
{
    std::lock_guard<std::mutex> lk(c.err_mtx);
    return c.last_error;
}

void mark_recv_worker_started(connection_t& c)
{
    {
        std::lock_guard<std::mutex> lk(c.recv_worker_mtx);
        c.recv_worker_tid.store(GetCurrentThreadId(), std::memory_order_release);
        c.recv_worker_alive.store(true, std::memory_order_release);
    }
    c.recv_worker_cv.notify_all();
}

void mark_recv_worker_stopped(connection_t& c)
{
    {
        std::lock_guard<std::mutex> lk(c.recv_worker_mtx);
        c.recv_worker_alive.store(false, std::memory_order_release);
        c.recv_worker_tid.store(0, std::memory_order_release);
    }
    c.recv_worker_cv.notify_all();
}

struct recv_worker_lifetime_t
{
    connection_t& c;
    explicit recv_worker_lifetime_t(connection_t& conn) : c(conn) { mark_recv_worker_started(c); }
    ~recv_worker_lifetime_t() { mark_recv_worker_stopped(c); }
};

void close_transport_for_stop(connection_t& c)
{
    diag::log_tagged_fmt("ws_edit", "close_transport begin sock=0x%llX ssl=%p connected=%d running=%d",
        static_cast<unsigned long long>(c.sock),
        c.ssl,
        c.connected.load() ? 1 : 0,
        c.running.load() ? 1 : 0);
    c.running.store(false);
    c.connected.store(false);
    if (c.sock != INVALID_SOCKET) {
        DWORD timeout = 250;
        setsockopt(c.sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(c.sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        u_long mode = 1;
        ioctlsocket(c.sock, FIONBIO, &mode);
        ::shutdown(c.sock, SD_BOTH);
        closesocket(c.sock);
        c.sock = INVALID_SOCKET;
    }
    if (c.ssl) {
        SSL_set_shutdown(c.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_set_quiet_shutdown(c.ssl, 1);
    }
    diag::log_tagged("ws_edit", "close_transport end");
}

void cleanup_connection(connection_t& c)
{
    const uint64_t t0 = now_steady_ms();
    diag::log_tagged_fmt("ws_edit", "cleanup_connection begin sock=0x%llX ssl=%p connected=%d running=%d",
        static_cast<unsigned long long>(c.sock),
        c.ssl,
        c.connected.load() ? 1 : 0,
        c.running.load() ? 1 : 0);
    close_transport_for_stop(c);
    if (c.ssl) {
        SSL_free(c.ssl);
        c.ssl = nullptr;
    }
    if (c.ssl_ctx) { SSL_CTX_free(c.ssl_ctx); c.ssl_ctx = nullptr; }
    diag::log_tagged_fmt("ws_edit", "cleanup_connection end elapsed_ms=%llu",
        static_cast<unsigned long long>(now_steady_ms() - t0));
}

bool set_nonblocking(SOCKET s, bool nb)
{
    u_long mode = nb ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
}

bool wait_socket(SOCKET s, int timeout_ms, bool for_write)
{
    if (timeout_ms <= 0) return false;
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = static_cast<short>(for_write ? POLLOUT : POLLIN);
    int rc = WSAPoll(&pfd, 1, timeout_ms);
    if (rc <= 0 || (pfd.revents & POLLNVAL) != 0) return false;
    const short wanted = static_cast<short>(for_write ? POLLOUT : (POLLIN | POLLRDNORM));
    return (pfd.revents & wanted) != 0 && (pfd.revents & POLLERR) == 0;
}

bool resolve_target(const std::string& host, uint16_t port, sockaddr_storage& sa_out, int& sa_len_out)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char port_str[16];
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", port);
    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str, &hints, &res);
    if (rc != 0 || !res) return false;
    std::memcpy(&sa_out, res->ai_addr, res->ai_addrlen);
    sa_len_out = static_cast<int>(res->ai_addrlen);
    freeaddrinfo(res);
    return true;
}

bool tcp_connect_with_timeout(SOCKET s, const sockaddr* sa, int sa_len, int timeout_ms, int& connect_err, int& poll_rc, short& revents, int& poll_wsa)
{
    connect_err = 0;
    poll_rc = 0;
    revents = 0;
    poll_wsa = 0;
    if (!set_nonblocking(s, true)) {
        connect_err = WSAGetLastError();
        return false;
    }
    int rc = ::connect(s, sa, sa_len);
    if (rc == 0) return true;
    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        connect_err = err;
        return false;
    }
    if (timeout_ms <= 0) {
        connect_err = WSAETIMEDOUT;
        return false;
    }
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = POLLOUT;
    poll_rc = WSAPoll(&pfd, 1, timeout_ms);
    revents = pfd.revents;
    if (poll_rc <= 0 || (pfd.revents & POLLNVAL) != 0) {
        poll_wsa = poll_rc < 0 ? WSAGetLastError() : 0;
        connect_err = poll_rc == 0 ? WSAETIMEDOUT : poll_wsa;
        return false;
    }
    int so_err = 0; int len = sizeof(so_err);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &len) != 0) {
        connect_err = WSAGetLastError();
        return false;
    }
    connect_err = so_err;
    return so_err == 0;
}

bool tcp_connect_blocking_loopback(SOCKET s, const sockaddr* sa, int sa_len, int timeout_ms, int& connect_err)
{
    connect_err = 0;
    if (!set_nonblocking(s, false)) {
        connect_err = WSAGetLastError();
        return false;
    }
    DWORD tv = static_cast<DWORD>(std::max(timeout_ms, 1));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    int rc = ::connect(s, sa, sa_len);
    if (rc != 0) {
        connect_err = WSAGetLastError();
        return false;
    }
    if (!set_nonblocking(s, true)) {
        connect_err = WSAGetLastError();
        return false;
    }
    return true;
}

bool sock_send_all(SOCKET s, const uint8_t* data, size_t len, int timeout_ms)
{
    uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(timeout_ms);
    size_t off = 0;
    while (off < len) {
        if (now_steady_ms() >= deadline) return false;
        if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), true)) return false;
        int n = send(s, reinterpret_cast<const char*>(data + off), static_cast<int>(len - off), 0);
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

bool ssl_send_all(SSL* ssl, SOCKET s, const uint8_t* data, size_t len, int timeout_ms)
{
    uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(timeout_ms);
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, data + off, static_cast<int>(len - off));
        if (n > 0) { off += static_cast<size_t>(n); continue; }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ) {
            if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), false)) return false;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), true)) return false;
        } else return false;
        if (now_steady_ms() >= deadline) return false;
    }
    return true;
}

bool stream_write(connection_t& c, const uint8_t* data, size_t len)
{
    std::lock_guard<std::mutex> lk(c.send_mtx);
    if (c.ssl) return ssl_send_all(c.ssl, c.sock, data, len, c.cfg.read_timeout_ms);
    return sock_send_all(c.sock, data, len, c.cfg.read_timeout_ms);
}

bool stream_read_some(connection_t& c, uint8_t* buf, size_t cap, size_t& out_n, int timeout_ms)
{
    out_n = 0;
    if (c.ssl) {
        int n = SSL_read(c.ssl, buf, static_cast<int>(cap));
        if (n > 0) { out_n = static_cast<size_t>(n); return true; }
        int err = SSL_get_error(c.ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN) return false;
        if (err == SSL_ERROR_WANT_READ) {
            if (!wait_socket(c.sock, timeout_ms, false)) return false;
            int n2 = SSL_read(c.ssl, buf, static_cast<int>(cap));
            if (n2 > 0) { out_n = static_cast<size_t>(n2); return true; }
            return false;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            if (!wait_socket(c.sock, timeout_ms, true)) return false;
            int n2 = SSL_read(c.ssl, buf, static_cast<int>(cap));
            if (n2 > 0) { out_n = static_cast<size_t>(n2); return true; }
            return false;
        }
        return false;
    }
    if (!wait_socket(c.sock, timeout_ms, false)) return false;
    int n = recv(c.sock, reinterpret_cast<char*>(buf), static_cast<int>(cap), 0);
    if (n <= 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return true;
        return false;
    }
    out_n = static_cast<size_t>(n);
    return true;
}

std::string compute_sec_websocket_accept(const std::string& client_key)
{
    static const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = client_key + magic;
    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const uint8_t*>(combined.data()), combined.size(), hash);
    return base64_encode(hash, SHA_DIGEST_LENGTH);
}

bool perform_handshake(connection_t& c)
{
    uint8_t key_bytes[16];
    if (!bcrypt_random(key_bytes, 16)) return false;
    std::string client_key = base64_encode(key_bytes, 16);

    std::string req;
    req += "GET " + (c.cfg.path.empty() ? std::string("/") : c.cfg.path) + " HTTP/1.1\r\n";
    std::string host_h = c.cfg.host;
    if ((c.cfg.scheme == "wss" && c.cfg.port != 443) || (c.cfg.scheme == "ws" && c.cfg.port != 80))
        host_h += ":" + std::to_string(c.cfg.port);
    req += "Host: " + host_h + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + client_key + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    if (!c.cfg.subprotocol.empty()) req += "Sec-WebSocket-Protocol: " + c.cfg.subprotocol + "\r\n";
    if (!c.cfg.origin.empty()) req += "Origin: " + c.cfg.origin + "\r\n";
    for (const auto& h : c.cfg.headers) {
        std::string lc = h.first;
        std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (lc == "host" || lc == "upgrade" || lc == "connection" || lc == "sec-websocket-key"
            || lc == "sec-websocket-version" || lc == "sec-websocket-protocol") continue;
        req += h.first + ": " + h.second + "\r\n";
    }
    req += "User-Agent: AiDAStandalone/1.0\r\n";
    req += "\r\n";

    if (!stream_write(c, reinterpret_cast<const uint8_t*>(req.data()), req.size())) {
        set_conn_err(c, "ws_editor: send handshake failed");
        return false;
    }

    std::string response;
    uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(c.cfg.connect_timeout_ms);
    uint8_t buf[4096];
    while (response.find("\r\n\r\n") == std::string::npos) {
        if (now_steady_ms() >= deadline) { set_conn_err(c, "ws_editor: handshake timeout"); return false; }
        size_t got = 0;
        bool ok = stream_read_some(c, buf, sizeof(buf), got, static_cast<int>(deadline - now_steady_ms()));
        if (!ok) { set_conn_err(c, "ws_editor: handshake read failed"); return false; }
        if (got > 0) response.append(reinterpret_cast<const char*>(buf), got);
        if (response.size() > 64 * 1024) { set_conn_err(c, "ws_editor: handshake oversize"); return false; }
    }

    auto eol = response.find("\r\n");
    if (eol == std::string::npos) { set_conn_err(c, "ws_editor: handshake malformed"); return false; }
    std::string status_line = response.substr(0, eol);
    if (status_line.find("101") == std::string::npos) {
        set_conn_err(c, "ws_editor: handshake non-101 (" + status_line + ")");
        return false;
    }

    std::string lc = response;
    std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    auto acc = lc.find("sec-websocket-accept:");
    if (acc == std::string::npos) { set_conn_err(c, "ws_editor: missing accept"); return false; }
    size_t vs = acc + 21;
    while (vs < response.size() && (response[vs] == ' ' || response[vs] == '\t')) ++vs;
    size_t ve = response.find("\r\n", vs);
    std::string accept_value = response.substr(vs, ve - vs);
    std::string expected = compute_sec_websocket_accept(client_key);
    if (accept_value != expected) {
        set_conn_err(c, "ws_editor: Sec-WebSocket-Accept mismatch");
        return false;
    }
    return true;
}

bool build_frame(uint8_t opcode, bool fin, bool masked,
                 const std::vector<uint8_t>& payload, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve(payload.size() + 14);
    uint8_t b0 = (fin ? 0x80 : 0x00) | (opcode & 0x0F);
    out.push_back(b0);
    uint8_t mask_bit = masked ? 0x80 : 0x00;
    size_t len = payload.size();
    if (len < 126) {
        out.push_back(static_cast<uint8_t>(len) | mask_bit);
    } else if (len <= 0xFFFF) {
        out.push_back(static_cast<uint8_t>(126) | mask_bit);
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        out.push_back(static_cast<uint8_t>(127) | mask_bit);
        uint64_t l64 = static_cast<uint64_t>(len);
        for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>((l64 >> (i * 8)) & 0xFF));
    }
    if (masked) {
        uint8_t mk[4];
        if (!bcrypt_random(mk, 4)) {
            uint64_t t = now_steady_ms();
            for (int i = 0; i < 4; ++i) mk[i] = static_cast<uint8_t>((t >> (i * 8)) & 0xFF);
        }
        out.push_back(mk[0]); out.push_back(mk[1]); out.push_back(mk[2]); out.push_back(mk[3]);
        size_t off = out.size();
        out.insert(out.end(), payload.begin(), payload.end());
        for (size_t i = 0; i < payload.size(); ++i) out[off + i] ^= mk[i & 3];
    } else {
        out.insert(out.end(), payload.begin(), payload.end());
    }
    return true;
}

bool send_frame_internal(connection_t& c, uint8_t opcode, bool fin, bool masked,
                          const std::vector<uint8_t>& payload)
{
    if (!c.connected.load()) {
        set_conn_err(c, "ws_editor: not connected");
        return false;
    }
    std::vector<uint8_t> frame;
    build_frame(opcode, fin, masked, payload, frame);
    if (!stream_write(c, frame.data(), frame.size())) {
        set_conn_err(c, "ws_editor: send_frame stream_write failed");
        return false;
    }
    {
        ws_frame_log_t row;
        row.ts_ms    = now_ms();
        row.outbound = true;
        row.opcode   = opcode;
        row.payload  = payload;
        if (opcode == 0x1) {
            std::string p(reinterpret_cast<const char*>(payload.data()), payload.size());
            row.preview = p.substr(0, std::min<size_t>(p.size(), 160));
        } else {
            char buf[16];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "(%zu bytes)", payload.size());
            row.preview = buf;
        }
        std::lock_guard<std::mutex> lk(c.frames_mtx);
        c.frames.push_back(std::move(row));
        while (c.frames.size() > c.frames_max) c.frames.pop_front();
    }
    c.frames_sent.fetch_add(1);
    return true;
}

void receive_loop(std::shared_ptr<connection_t> cptr)
{
    auto& c = *cptr;
    const uint64_t t0 = now_steady_ms();
    recv_worker_lifetime_t worker(c);
    diag::log_tagged_fmt("ws_edit", "receive_loop entry mode=work_queue conn_id=%llu sock=0x%llX ssl=%p tid=%lu",
        static_cast<unsigned long long>(c.id),
        static_cast<unsigned long long>(c.sock),
        c.ssl,
        static_cast<unsigned long>(GetCurrentThreadId()));
    std::vector<uint8_t> buf;
    buf.reserve(65536);
    uint8_t tmp[16384];
    while (c.running.load()) {
        size_t got = 0;
        bool ok = stream_read_some(c, tmp, sizeof(tmp), got, 500);
        if (!ok) {
            if (c.running.load()) set_conn_err(c, "ws_editor: read closed");
            break;
        }
        if (got > 0) buf.insert(buf.end(), tmp, tmp + got);

        while (buf.size() >= 2) {
            uint8_t b0 = buf[0];
            uint8_t b1 = buf[1];
            bool fin = (b0 & 0x80) != 0;
            uint8_t opcode = b0 & 0x0F;
            bool masked = (b1 & 0x80) != 0;
            uint64_t len = b1 & 0x7F;
            size_t pos = 2;
            if (len == 126) {
                if (buf.size() < pos + 2) break;
                len = (static_cast<uint64_t>(buf[pos]) << 8) | buf[pos + 1];
                pos += 2;
            } else if (len == 127) {
                if (buf.size() < pos + 8) break;
                len = 0;
                for (int i = 0; i < 8; ++i) len = (len << 8) | buf[pos + i];
                pos += 8;
            }
            uint8_t mk[4] = {0,0,0,0};
            if (masked) {
                if (buf.size() < pos + 4) break;
                mk[0] = buf[pos]; mk[1] = buf[pos + 1]; mk[2] = buf[pos + 2]; mk[3] = buf[pos + 3];
                pos += 4;
            }
            if (buf.size() < pos + len) break;
            std::vector<uint8_t> payload(buf.begin() + static_cast<ptrdiff_t>(pos),
                                          buf.begin() + static_cast<ptrdiff_t>(pos + len));
            if (masked) {
                for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= mk[i & 3];
            }
            ws_frame_log_t row;
            row.ts_ms    = now_ms();
            row.outbound = false;
            row.opcode   = opcode;
            row.payload  = payload;
            if (opcode == 0x1) {
                std::string p(reinterpret_cast<const char*>(payload.data()), payload.size());
                row.preview = p.substr(0, std::min<size_t>(p.size(), 160));
            } else {
                char b[16];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "(%zu bytes)", payload.size());
                row.preview = b;
            }
            {
                std::lock_guard<std::mutex> lk(c.frames_mtx);
                c.frames.push_back(std::move(row));
                while (c.frames.size() > c.frames_max) c.frames.pop_front();
            }
            c.frames_received.fetch_add(1);
            (void)fin;
            buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(pos + len));
            if (opcode == 0x9) {
                send_frame_internal(c, 0xA, true, true, payload);
            }
            if (opcode == 0x8) {
                c.running.store(false);
                c.connected.store(false);
                break;
            }
        }
    }
    c.connected.store(false);
    diag::log_tagged_fmt("ws_edit", "receive_loop exit conn_id=%llu running=%d connected=%d sent=%zu received=%zu elapsed_ms=%llu tid=%lu",
        static_cast<unsigned long long>(c.id),
        c.running.load() ? 1 : 0,
        c.connected.load() ? 1 : 0,
        c.frames_sent.load(),
        c.frames_received.load(),
        static_cast<unsigned long long>(now_steady_ms() - t0),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

std::shared_ptr<connection_t> find_conn(uint64_t id)
{
    auto& r = registry();
    std::lock_guard<std::mutex> lk(r.mtx);
    auto it = r.by_id.find(id);
    return it == r.by_id.end() ? nullptr : it->second;
}

}

bool initialize() {
    diag::log_tagged_fmt("ws_edit", "initialize entry wsa_ok=%d", static_cast<int>(s_wsa_guard.ok));
    return s_wsa_guard.ok;
}

void shutdown()
{
    diag::log_tagged_fmt("ws_edit", "shutdown entry");
    disconnect_all();
    diag::log_tagged_fmt("ws_edit", "shutdown done");
}

uint64_t connect(const ws_connection_config_t& cfg)
{
    diag::log_tagged_fmt("ws_edit", "connect entry scheme=%s host=%s port=%u path=%s tls_verify=%d",
        cfg.scheme.c_str(), cfg.host.c_str(), static_cast<unsigned>(cfg.port),
        cfg.path.c_str(), static_cast<int>(cfg.verify_tls));
    if (!s_wsa_guard.ok) {
        diag::log_tagged_fmt("ws_edit", "connect wsa_not_initialized");
        set_err("ws_editor: WSAStartup failed");
        return 0;
    }
    ensure_openssl();
    if (cfg.host.empty() || cfg.port == 0) {
        diag::log_tagged_fmt("ws_edit", "connect empty_host_or_port host=%s port=%u",
            cfg.host.c_str(), static_cast<unsigned>(cfg.port));
        set_err("ws_editor: empty host or port");
        return 0;
    }
    bool tls = (cfg.scheme == "wss");
    diag::log_tagged_fmt("ws_edit", "connect tls=%d host=%s port=%u", static_cast<int>(tls),
        cfg.host.c_str(), static_cast<unsigned>(cfg.port));

    sockaddr_storage sa{}; int sa_len = 0;
    diag::log_tagged_fmt("ws_edit", "connect resolving host=%s port=%u", cfg.host.c_str(), static_cast<unsigned>(cfg.port));
    if (!resolve_target(cfg.host, cfg.port, sa, sa_len)) {
        diag::log_tagged_fmt("ws_edit", "connect dns_failed host=%s", cfg.host.c_str());
        set_err("ws_editor: DNS failed");
        return 0;
    }
    SOCKET s = INVALID_SOCKET;
    const bool loopback = is_loopback_host(cfg.host);
    const int effective_timeout_ms = std::max(cfg.connect_timeout_ms, 1);
    const int max_attempts = loopback ? 16 : 1;
    const uint64_t connect_started = now_steady_ms();
    int last_connect_err = 0;
    int last_poll_rc = 0;
    short last_revents = 0;
    int last_poll_wsa = 0;

    diag::log_tagged_fmt("ws_edit", "connect tcp_connecting timeout_ms=%d loopback=%d attempts=%d",
        cfg.connect_timeout_ms, loopback ? 1 : 0, max_attempts);
    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        const uint64_t now = now_steady_ms();
        const uint64_t elapsed = now > connect_started ? now - connect_started : 0;
        if (elapsed >= static_cast<uint64_t>(effective_timeout_ms)) break;
        const int remaining_ms = effective_timeout_ms - static_cast<int>(elapsed);
        const int attempt_timeout_ms = loopback ? std::min(remaining_ms, 250) : remaining_ms;

        SOCKET candidate = socket(sa.ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (candidate == INVALID_SOCKET) {
            last_connect_err = WSAGetLastError();
            diag::log_tagged_fmt("ws_edit", "connect socket_create_failed host=%s port=%u attempt=%d err=%d",
                cfg.host.c_str(), static_cast<unsigned>(cfg.port), attempt, last_connect_err);
            break;
        }
        BOOL nodelay = TRUE;
        setsockopt(candidate, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

        if (loopback) {
            int blocking_err = 0;
            if (tcp_connect_blocking_loopback(candidate, reinterpret_cast<const sockaddr*>(&sa), sa_len, attempt_timeout_ms, blocking_err)) {
                s = candidate;
                diag::log_tagged_fmt("ws_edit", "connect tcp_ok_blocking host=%s port=%u attempts=%d",
                    cfg.host.c_str(), static_cast<unsigned>(cfg.port), attempt);
                break;
            }
            last_connect_err = blocking_err;
            diag::log_tagged_fmt("ws_edit", "connect tcp_blocking_failed host=%s port=%u attempt=%d/%d timeout_ms=%d err=%d elapsed_ms=%llu",
                cfg.host.c_str(), static_cast<unsigned>(cfg.port), attempt, max_attempts,
                attempt_timeout_ms, blocking_err,
                static_cast<unsigned long long>(now_steady_ms() - connect_started));
            ::shutdown(candidate, SD_BOTH);
            closesocket(candidate);
            if (attempt == max_attempts) break;
            Sleep(static_cast<DWORD>(std::min(100, 10 * attempt)));
            continue;
        }

        int connect_err = 0;
        int poll_rc = 0;
        short revents = 0;
        int poll_wsa = 0;
        if (tcp_connect_with_timeout(candidate, reinterpret_cast<const sockaddr*>(&sa), sa_len, attempt_timeout_ms, connect_err, poll_rc, revents, poll_wsa)) {
            s = candidate;
            diag::log_tagged_fmt("ws_edit", "connect tcp_ok host=%s port=%u attempts=%d loopback=%d",
                cfg.host.c_str(), static_cast<unsigned>(cfg.port), attempt, loopback ? 1 : 0);
            break;
        }

        last_connect_err = connect_err;
        last_poll_rc = poll_rc;
        last_revents = revents;
        last_poll_wsa = poll_wsa;
        diag::log_tagged_fmt("ws_edit", "connect tcp_failed host=%s port=%u attempt=%d/%d timeout_ms=%d connect_err=%d poll_rc=%d revents=0x%04X poll_wsa=%d elapsed_ms=%llu",
            cfg.host.c_str(), static_cast<unsigned>(cfg.port), attempt, max_attempts, attempt_timeout_ms,
            connect_err, poll_rc, static_cast<unsigned>(revents), poll_wsa,
            static_cast<unsigned long long>(now_steady_ms() - connect_started));
        ::shutdown(candidate, SD_BOTH);
        closesocket(candidate);
        if (!loopback || attempt == max_attempts) break;
        Sleep(static_cast<DWORD>(std::min(100, 10 * attempt)));
    }

    if (s == INVALID_SOCKET) {
        diag::log_tagged_fmt("ws_edit", "connect tcp_exhausted host=%s port=%u attempts=%d loopback=%d last_connect_err=%d last_poll_rc=%d last_revents=0x%04X last_poll_wsa=%d elapsed_ms=%llu",
            cfg.host.c_str(), static_cast<unsigned>(cfg.port), max_attempts, loopback ? 1 : 0,
            last_connect_err, last_poll_rc, static_cast<unsigned>(last_revents), last_poll_wsa,
            static_cast<unsigned long long>(now_steady_ms() - connect_started));
        set_err("ws_editor: TCP connect failed");
        return 0;
    }

    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    if (tls) {
        diag::log_tagged_fmt("ws_edit", "connect tls_handshake host=%s verify=%d", cfg.host.c_str(), static_cast<int>(cfg.verify_tls));
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            ::shutdown(s, SD_BOTH); closesocket(s);
            diag::log_tagged_fmt("ws_edit", "connect ssl_ctx_new_failed");
            set_err("ws_editor: SSL_CTX_new failed");
            return 0;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        if (cfg.verify_tls) SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        else                  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);
        ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            ::shutdown(s, SD_BOTH); closesocket(s);
            diag::log_tagged_fmt("ws_edit", "connect ssl_new_failed");
            set_err("ws_editor: SSL_new failed");
            return 0;
        }
        SSL_set_tlsext_host_name(ssl, cfg.host.c_str());
        SSL_set_fd(ssl, static_cast<int>(s));
        uint64_t deadline = now_steady_ms() + static_cast<uint64_t>(cfg.connect_timeout_ms);
        while (true) {
            int r = SSL_connect(ssl);
            if (r == 1) {
                diag::log_tagged_fmt("ws_edit", "connect tls_ok host=%s", cfg.host.c_str());
                break;
            }
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ) {
                if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), false)) {
                    SSL_free(ssl); SSL_CTX_free(ctx);
                    ::shutdown(s, SD_BOTH); closesocket(s);
                    diag::log_tagged_fmt("ws_edit", "connect tls_timeout_read host=%s", cfg.host.c_str());
                    set_err("ws_editor: TLS handshake timeout (read)");
                    return 0;
                }
            } else if (err == SSL_ERROR_WANT_WRITE) {
                if (!wait_socket(s, static_cast<int>(deadline - now_steady_ms()), true)) {
                    SSL_free(ssl); SSL_CTX_free(ctx);
                    ::shutdown(s, SD_BOTH); closesocket(s);
                    diag::log_tagged_fmt("ws_edit", "connect tls_timeout_write host=%s", cfg.host.c_str());
                    set_err("ws_editor: TLS handshake timeout (write)");
                    return 0;
                }
            } else {
                SSL_free(ssl); SSL_CTX_free(ctx);
                ::shutdown(s, SD_BOTH); closesocket(s);
                diag::log_tagged_fmt("ws_edit", "connect tls_handshake_failed ssl_err=%d host=%s", err, cfg.host.c_str());
                set_err("ws_editor: TLS handshake failed");
                return 0;
            }
        }
    }

    auto cptr = std::make_shared<connection_t>();
    cptr->cfg       = cfg;
    cptr->sock      = s;
    cptr->ssl_ctx   = ctx;
    cptr->ssl       = ssl;
    cptr->opened_ms = now_ms();
    diag::log_tagged_fmt("ws_edit", "connect ws_handshake host=%s path=%s", cfg.host.c_str(), cfg.path.c_str());
    if (!perform_handshake(*cptr)) {
        std::string e = get_conn_err(*cptr);
        cleanup_connection(*cptr);
        diag::log_tagged_fmt("ws_edit", "connect ws_handshake_failed err=%s", e.c_str());
        set_err(e.empty() ? std::string("ws_editor: handshake failed") : e);
        return 0;
    }
    cptr->connected.store(true);
    cptr->running.store(true);
    {
        auto& r = registry();
        std::lock_guard<std::mutex> lk(r.mtx);
        cptr->id = r.next_id.fetch_add(1);
        r.by_id.emplace(cptr->id, cptr);
    }
    cptr->recv_worker_alive.store(true, std::memory_order_release);
    bool recv_posted = false;
    try {
        recv_posted = work_queue::post([cptr]() { receive_loop(cptr); });
    } catch (...) {
        recv_posted = false;
    }
    if (!recv_posted) {
        cptr->recv_worker_alive.store(false, std::memory_order_release);
        diag::log_tagged_fmt("ws_edit", "recv_worker_post_failed id=%llu",
            static_cast<unsigned long long>(cptr->id));
        cptr->running.store(false);
        cptr->connected.store(false);
        cleanup_connection(*cptr);
        {
            auto& r = registry();
            std::lock_guard<std::mutex> lk(r.mtx);
            r.by_id.erase(cptr->id);
        }
        set_err("ws_editor: receive worker unavailable");
        return 0;
    }
    {
        std::unique_lock<std::mutex> lk(cptr->recv_worker_mtx);
        const bool entered = cptr->recv_worker_cv.wait_for(
            lk,
            std::chrono::milliseconds(1000),
            [&cptr]() {
                return cptr->recv_worker_tid.load(std::memory_order_acquire) != 0 ||
                       !cptr->recv_worker_alive.load(std::memory_order_acquire);
            });
        if (!entered || !cptr->recv_worker_alive.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("ws_edit", "recv_worker_enter_wait_failed id=%llu entered=%d alive=%d tid=%lu",
                static_cast<unsigned long long>(cptr->id),
                entered ? 1 : 0,
                cptr->recv_worker_alive.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long>(cptr->recv_worker_tid.load(std::memory_order_acquire)));
            lk.unlock();
            cptr->running.store(false);
            cptr->connected.store(false);
            if (cptr->recv_worker_alive.load(std::memory_order_acquire))
                close_transport_for_stop(*cptr);
            else
                cleanup_connection(*cptr);
            {
                auto& r = registry();
                std::lock_guard<std::mutex> reg_lk(r.mtx);
                r.by_id.erase(cptr->id);
            }
            set_err("ws_editor: receive worker did not enter");
            return 0;
        }
    }
    diag::log_tagged_fmt("burp.ws_editor", "connected id=%llu host=%s:%u path=%s",
        static_cast<unsigned long long>(cptr->id), cptr->cfg.host.c_str(), cptr->cfg.port, cptr->cfg.path.c_str());
    diag::log_tagged_fmt("ws_edit", "connect ok id=%llu host=%s",
        static_cast<unsigned long long>(cptr->id), cfg.host.c_str());
    return cptr->id;
}

bool disconnect(uint64_t conn_id)
{
    const uint64_t t0 = now_steady_ms();
    diag::log_tagged_fmt("ws_edit", "disconnect entry conn_id=%llu",
        static_cast<unsigned long long>(conn_id));
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "disconnect not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        set_err("ws_editor.disconnect: not found");
        return false;
    }
    cptr->running.store(false);
    const bool was_connected = cptr->connected.exchange(false);
    diag::log_tagged_fmt("ws_edit", "disconnect closing_transport conn_id=%llu was_connected=%d sock=0x%llX ssl=%p elapsed_ms=%llu",
        static_cast<unsigned long long>(conn_id),
        was_connected ? 1 : 0,
        static_cast<unsigned long long>(cptr->sock),
        cptr->ssl,
        static_cast<unsigned long long>(now_steady_ms() - t0));
    close_transport_for_stop(*cptr);
    bool stopped = true;
    if (cptr->recv_worker_alive.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("ws_edit", "disconnect recv_wait_begin conn_id=%llu tid=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(conn_id),
            static_cast<unsigned long>(cptr->recv_worker_tid.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(now_steady_ms() - t0));
        std::unique_lock<std::mutex> lk(cptr->recv_worker_mtx);
        stopped = cptr->recv_worker_cv.wait_for(
            lk,
            std::chrono::milliseconds(1000),
            [&cptr]() { return !cptr->recv_worker_alive.load(std::memory_order_acquire); });
        if (stopped) {
            diag::log_tagged_fmt("ws_edit", "disconnect recv_wait_done conn_id=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(conn_id),
                static_cast<unsigned long long>(now_steady_ms() - t0));
        } else {
            set_conn_err(*cptr, "ws_editor.disconnect: receive worker did not stop within timeout");
            diag::log_tagged_fmt("ws_edit", "disconnect recv_wait_timeout conn_id=%llu tid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(conn_id),
                static_cast<unsigned long>(cptr->recv_worker_tid.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(now_steady_ms() - t0));
        }
    }
    if (stopped)
        cleanup_connection(*cptr);
    auto& r = registry();
    std::lock_guard<std::mutex> lk(r.mtx);
    r.by_id.erase(conn_id);
    diag::log_tagged_fmt("ws_edit", "disconnect ok conn_id=%llu remaining=%zu elapsed_ms=%llu",
        static_cast<unsigned long long>(conn_id), r.by_id.size(),
        static_cast<unsigned long long>(now_steady_ms() - t0));
    return true;
}

bool disconnect_all()
{
    diag::log_tagged_fmt("ws_edit", "disconnect_all entry");
    std::vector<uint64_t> ids;
    {
        auto& r = registry();
        std::lock_guard<std::mutex> lk(r.mtx);
        ids.reserve(r.by_id.size());
        for (const auto& kv : r.by_id) ids.push_back(kv.first);
    }
    diag::log_tagged_fmt("ws_edit", "disconnect_all disconnecting count=%zu", ids.size());
    for (uint64_t id : ids) disconnect(id);
    diag::log_tagged_fmt("ws_edit", "disconnect_all done");
    return true;
}

std::vector<ws_status_t> list_connections()
{
    diag::log_tagged_fmt("ws_edit", "list_connections entry");
    std::vector<ws_status_t> out;
    auto& r = registry();
    std::lock_guard<std::mutex> lk(r.mtx);
    for (const auto& kv : r.by_id) {
        ws_status_t st;
        st.id              = kv.first;
        st.connected       = kv.second->connected.load();
        st.frames_sent     = kv.second->frames_sent.load();
        st.frames_received = kv.second->frames_received.load();
        st.opened_ms       = kv.second->opened_ms;
        st.url             = kv.second->cfg.scheme + "://" + kv.second->cfg.host + ":" + std::to_string(kv.second->cfg.port) + kv.second->cfg.path;
        st.last_error      = get_conn_err(*kv.second);
        out.push_back(std::move(st));
    }
    diag::log_tagged_fmt("ws_edit", "list_connections result count=%zu", out.size());
    return out;
}

bool get_status(uint64_t conn_id, ws_status_t& out)
{
    diag::log_tagged_fmt("ws_edit", "get_status entry conn_id=%llu",
        static_cast<unsigned long long>(conn_id));
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "get_status not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        return false;
    }
    out.id              = cptr->id;
    out.connected       = cptr->connected.load();
    out.frames_sent     = cptr->frames_sent.load();
    out.frames_received = cptr->frames_received.load();
    out.opened_ms       = cptr->opened_ms;
    out.url             = cptr->cfg.scheme + "://" + cptr->cfg.host + ":" + std::to_string(cptr->cfg.port) + cptr->cfg.path;
    out.last_error      = get_conn_err(*cptr);
    diag::log_tagged_fmt("ws_edit", "get_status conn_id=%llu connected=%d sent=%zu recv=%zu",
        static_cast<unsigned long long>(conn_id), static_cast<int>(out.connected),
        out.frames_sent, out.frames_received);
    return true;
}

bool send_text(uint64_t conn_id, const std::string& msg)
{
    diag::log_tagged_fmt("ws_edit", "send_text conn_id=%llu msg_len=%zu",
        static_cast<unsigned long long>(conn_id), msg.size());
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "send_text not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        set_err("ws_editor.send_text: not found");
        return false;
    }
    std::vector<uint8_t> payload(msg.begin(), msg.end());
    bool ok = send_frame_internal(*cptr, 0x1, true, true, payload);
    diag::log_tagged_fmt("ws_edit", "send_text result=%d conn_id=%llu",
        static_cast<int>(ok), static_cast<unsigned long long>(conn_id));
    return ok;
}

bool send_binary(uint64_t conn_id, const std::vector<uint8_t>& data)
{
    diag::log_tagged_fmt("ws_edit", "send_binary conn_id=%llu bytes=%zu",
        static_cast<unsigned long long>(conn_id), data.size());
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "send_binary not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        set_err("ws_editor.send_binary: not found");
        return false;
    }
    bool ok = send_frame_internal(*cptr, 0x2, true, true, data);
    diag::log_tagged_fmt("ws_edit", "send_binary result=%d conn_id=%llu",
        static_cast<int>(ok), static_cast<unsigned long long>(conn_id));
    return ok;
}

bool send_raw_frame(uint64_t conn_id, uint8_t opcode, bool fin, bool masked, const std::vector<uint8_t>& payload)
{
    diag::log_tagged_fmt("ws_edit", "send_raw_frame conn_id=%llu opcode=0x%02x fin=%d masked=%d payload=%zu",
        static_cast<unsigned long long>(conn_id), static_cast<unsigned>(opcode),
        static_cast<int>(fin), static_cast<int>(masked), payload.size());
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "send_raw_frame not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        set_err("ws_editor.send_raw_frame: not found");
        return false;
    }
    bool ok = send_frame_internal(*cptr, opcode, fin, masked, payload);
    diag::log_tagged_fmt("ws_edit", "send_raw_frame result=%d conn_id=%llu",
        static_cast<int>(ok), static_cast<unsigned long long>(conn_id));
    return ok;
}

bool send_ping(uint64_t conn_id, const std::vector<uint8_t>& payload)
{
    diag::log_tagged_fmt("ws_edit", "send_ping conn_id=%llu payload=%zu",
        static_cast<unsigned long long>(conn_id), payload.size());
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "send_ping not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        set_err("ws_editor.send_ping: not found");
        return false;
    }
    bool ok = send_frame_internal(*cptr, 0x9, true, true, payload);
    diag::log_tagged_fmt("ws_edit", "send_ping result=%d conn_id=%llu",
        static_cast<int>(ok), static_cast<unsigned long long>(conn_id));
    return ok;
}

bool send_pong(uint64_t conn_id, const std::vector<uint8_t>& payload)
{
    diag::log_tagged_fmt("ws_edit", "send_pong conn_id=%llu payload=%zu",
        static_cast<unsigned long long>(conn_id), payload.size());
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "send_pong not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        set_err("ws_editor.send_pong: not found");
        return false;
    }
    bool ok = send_frame_internal(*cptr, 0xA, true, true, payload);
    diag::log_tagged_fmt("ws_edit", "send_pong result=%d conn_id=%llu",
        static_cast<int>(ok), static_cast<unsigned long long>(conn_id));
    return ok;
}

bool send_close(uint64_t conn_id, uint16_t code, const std::string& reason)
{
    diag::log_tagged_fmt("ws_edit", "send_close conn_id=%llu code=%u reason=%s",
        static_cast<unsigned long long>(conn_id), static_cast<unsigned>(code), reason.c_str());
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "send_close not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        set_err("ws_editor.send_close: not found");
        return false;
    }
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>((code >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(code & 0xFF));
    for (char ch : reason) payload.push_back(static_cast<uint8_t>(ch));
    bool ok = send_frame_internal(*cptr, 0x8, true, true, payload);
    diag::log_tagged_fmt("ws_edit", "send_close result=%d conn_id=%llu",
        static_cast<int>(ok), static_cast<unsigned long long>(conn_id));
    return ok;
}

std::vector<ws_frame_log_t> frames(uint64_t conn_id, size_t start, size_t max)
{
    diag::log_tagged_fmt("ws_edit", "frames conn_id=%llu start=%zu max=%zu",
        static_cast<unsigned long long>(conn_id), start, max);
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "frames not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        return {};
    }
    std::lock_guard<std::mutex> lk(cptr->frames_mtx);
    std::vector<ws_frame_log_t> out;
    if (start >= cptr->frames.size()) {
        diag::log_tagged_fmt("ws_edit", "frames start_out_of_range start=%zu total=%zu",
            start, cptr->frames.size());
        return out;
    }
    size_t count = std::min(max == 0 ? cptr->frames.size() : max, cptr->frames.size() - start);
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) out.push_back(cptr->frames[start + i]);
    diag::log_tagged_fmt("ws_edit", "frames result count=%zu conn_id=%llu",
        out.size(), static_cast<unsigned long long>(conn_id));
    return out;
}

size_t frame_count(uint64_t conn_id)
{
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "frame_count not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        return 0;
    }
    std::lock_guard<std::mutex> lk(cptr->frames_mtx);
    size_t n = cptr->frames.size();
    diag::log_tagged_fmt("ws_edit", "frame_count conn_id=%llu count=%zu",
        static_cast<unsigned long long>(conn_id), n);
    return n;
}

void clear_frames(uint64_t conn_id)
{
    diag::log_tagged_fmt("ws_edit", "clear_frames conn_id=%llu",
        static_cast<unsigned long long>(conn_id));
    auto cptr = find_conn(conn_id);
    if (!cptr) {
        diag::log_tagged_fmt("ws_edit", "clear_frames not_found conn_id=%llu",
            static_cast<unsigned long long>(conn_id));
        return;
    }
    std::lock_guard<std::mutex> lk(cptr->frames_mtx);
    size_t n = cptr->frames.size();
    cptr->frames.clear();
    diag::log_tagged_fmt("ws_edit", "clear_frames done conn_id=%llu cleared=%zu",
        static_cast<unsigned long long>(conn_id), n);
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("ws_edit", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
