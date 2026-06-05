#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "intruder_engine.hpp"

#include "../../infra/work_queue.hpp"
#include "../protocol_parser.hpp"
#include "../../../helpers/diag_log.hpp"

#ifdef _WIN32
#  include <BaseTsd.h>
   typedef SSIZE_T ssize_t;
#endif

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace aida {
namespace burp {
namespace intruder {

namespace {

struct wsa_guard_t
{
    WSADATA data{};
    bool    ok = false;
    wsa_guard_t() { ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0); }
    ~wsa_guard_t() { if (ok) WSACleanup(); }
};

static wsa_guard_t s_wsa_guard;

struct ssl_ctx_holder_t
{
    SSL_CTX* ctx = nullptr;
    std::mutex mtx;
};

static ssl_ctx_holder_t& ssl_holder()
{
    static ssl_ctx_holder_t h;
    return h;
}

static SSL_CTX* ensure_ssl_ctx()
{
    auto& h = ssl_holder();
    std::lock_guard<std::mutex> lk(h.mtx);
    if (h.ctx) return h.ctx;
    static std::atomic<bool> initialized{false};
    bool exp = false;
    if (initialized.compare_exchange_strong(exp, true)) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }
    const SSL_METHOD* m = TLS_client_method();
    h.ctx = SSL_CTX_new(m);
    if (!h.ctx) return nullptr;
    SSL_CTX_set_min_proto_version(h.ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(h.ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_options(h.ctx, SSL_OP_NO_COMPRESSION);
    return h.ctx;
}

static std::mutex&  err_mtx() { static std::mutex m; return m; }
static std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = msg;
}

static uint64_t unix_ms_now()
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

static std::string ip_for_host(const std::string& host)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return {};
    char buf[64] = {};
    if (res->ai_family == AF_INET) {
        sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    } else if (res->ai_family == AF_INET6) {
        sockaddr_in6* sin6 = reinterpret_cast<sockaddr_in6*>(res->ai_addr);
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
    }
    freeaddrinfo(res);
    return buf;
}

static SOCKET tcp_connect(const std::string& host, uint16_t port, int timeout_ms)
{
    std::string ip = ip_for_host(host);
    if (ip.empty()) return INVALID_SOCKET;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ports[16];
    snprintf(ports, sizeof(ports), "%u", static_cast<unsigned>(port));
    addrinfo* res = nullptr;
    if (getaddrinfo(ip.c_str(), ports, &hints, &res) != 0 || !res) return INVALID_SOCKET;

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return INVALID_SOCKET; }

    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    int cr = connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    if (cr == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s); freeaddrinfo(res); return INVALID_SOCKET;
    }

    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = POLLOUT;
    int pr = WSAPoll(&pfd, 1, timeout_ms);
    if (pr <= 0) { closesocket(s); freeaddrinfo(res); return INVALID_SOCKET; }

    int err = 0;
    int err_sz = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &err_sz);
    if (err != 0) { closesocket(s); freeaddrinfo(res); return INVALID_SOCKET; }

    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);

    DWORD tmo = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));

    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    freeaddrinfo(res);
    return s;
}

struct ssl_conn_t
{
    SOCKET sock = INVALID_SOCKET;
    SSL*   ssl = nullptr;
    bool   alpn_is_h2 = false;
};

static void close_ssl(ssl_conn_t& c)
{
    if (c.ssl) {
        SSL_shutdown(c.ssl);
        SSL_free(c.ssl);
        c.ssl = nullptr;
    }
    if (c.sock != INVALID_SOCKET) {
        shutdown(c.sock, SD_BOTH);
        closesocket(c.sock);
        c.sock = INVALID_SOCKET;
    }
}

static bool ssl_connect(ssl_conn_t& c, const std::string& host, uint16_t port,
                        int timeout_ms, const std::vector<std::string>& alpn_protos)
{
    SSL_CTX* ctx = ensure_ssl_ctx();
    if (!ctx) return false;
    c.sock = tcp_connect(host, port, timeout_ms);
    if (c.sock == INVALID_SOCKET) return false;

    c.ssl = SSL_new(ctx);
    if (!c.ssl) { close_ssl(c); return false; }
    SSL_set_fd(c.ssl, static_cast<int>(c.sock));
    SSL_set_tlsext_host_name(c.ssl, host.c_str());

    if (!alpn_protos.empty()) {
        std::vector<uint8_t> alpn_buf;
        for (auto& p : alpn_protos) {
            if (p.empty() || p.size() > 255) continue;
            alpn_buf.push_back(static_cast<uint8_t>(p.size()));
            alpn_buf.insert(alpn_buf.end(), p.begin(), p.end());
        }
        if (!alpn_buf.empty()) {
            SSL_set_alpn_protos(c.ssl, alpn_buf.data(), static_cast<unsigned int>(alpn_buf.size()));
        }
    }

    u_long nb = 1;
    ioctlsocket(c.sock, FIONBIO, &nb);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        int r = SSL_connect(c.ssl);
        if (r == 1) break;
        int err = SSL_get_error(c.ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) { close_ssl(c); return false; }
            int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            WSAPOLLFD pfd{};
            pfd.fd = c.sock;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
            int pr = WSAPoll(&pfd, 1, rem_ms);
            if (pr <= 0) { close_ssl(c); return false; }
            continue;
        }
        close_ssl(c);
        return false;
    }

    const unsigned char* selected = nullptr;
    unsigned int selected_len = 0;
    SSL_get0_alpn_selected(c.ssl, &selected, &selected_len);
    if (selected && selected_len == 2 && selected[0] == 'h' && selected[1] == '2') {
        c.alpn_is_h2 = true;
    }

    nb = 0;
    ioctlsocket(c.sock, FIONBIO, &nb);
    return true;
}

static bool plain_send_all(SOCKET s, const uint8_t* data, size_t len, int timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t sent = 0;
    while (sent < len) {
        int n = ::send(s, reinterpret_cast<const char*>(data + sent),
                       static_cast<int>(len - sent), 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK) {
                auto now = std::chrono::steady_clock::now();
                if (now >= deadline) return false;
                WSAPOLLFD pfd{};
                pfd.fd = s;
                pfd.events = POLLOUT;
                int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
                if (WSAPoll(&pfd, 1, rem_ms) <= 0) return false;
                continue;
            }
            return false;
        }
        if (n == 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static bool ssl_send_all(SSL* ssl, const uint8_t* data, size_t len, int timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, data + sent, static_cast<int>(len - sent));
        if (n > 0) { sent += static_cast<size_t>(n); continue; }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return false;
            WSAPOLLFD pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
            int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            if (WSAPoll(&pfd, 1, rem_ms) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

static int plain_recv_some(SOCKET s, uint8_t* buf, int buflen, int timeout_ms)
{
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = POLLIN;
    int pr = WSAPoll(&pfd, 1, timeout_ms);
    if (pr <= 0) return -1;
    int n = ::recv(s, reinterpret_cast<char*>(buf), buflen, 0);
    return n;
}

static int ssl_recv_some(SSL* ssl, uint8_t* buf, int buflen, int timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    while (true) {
        int n = SSL_read(ssl, buf, buflen);
        if (n > 0) return n;
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return -1;
            WSAPOLLFD pfd{};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
            int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            if (WSAPoll(&pfd, 1, rem_ms) <= 0) return -1;
            continue;
        }
        if (n == 0) return 0;
        return -1;
    }
}

static std::string ascii_lower(const std::string& v)
{
    std::string r;
    r.reserve(v.size());
    for (char c : v) {
        r.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c);
    }
    return r;
}

static std::string preview_string(const std::vector<uint8_t>& body, size_t cap)
{
    size_t n = body.size() < cap ? body.size() : cap;
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = body[i];
        if (b == '\r' || b == '\n' || b == '\t' || (b >= 0x20 && b < 0x7f)) {
            out.push_back(static_cast<char>(b));
        } else {
            out.push_back('.');
        }
    }
    return out;
}

static std::vector<uint8_t> apply_payload_replacements(
    const std::vector<uint8_t>& base,
    const std::vector<std::pair<size_t, size_t>>& positions,
    const std::vector<std::string>& payloads)
{
    if (positions.empty() || payloads.empty()) return base;
    std::vector<std::pair<size_t, size_t>> sorted = positions;
    std::sort(sorted.begin(), sorted.end(),
              [](const std::pair<size_t,size_t>& a, const std::pair<size_t,size_t>& b) {
                  return a.first < b.first;
              });
    std::vector<uint8_t> out;
    out.reserve(base.size() + 64);
    size_t cursor = 0;
    for (size_t i = 0; i < sorted.size(); ++i) {
        const auto& p = sorted[i];
        if (p.first > base.size() || p.first < cursor) continue;
        out.insert(out.end(), base.begin() + cursor, base.begin() + p.first);
        const std::string& payload = i < payloads.size() ? payloads[i]
                                                         : (payloads.empty() ? std::string() : payloads.back());
        out.insert(out.end(), payload.begin(), payload.end());
        cursor = p.first + p.second;
        if (cursor > base.size()) cursor = base.size();
    }
    if (cursor < base.size()) {
        out.insert(out.end(), base.begin() + cursor, base.end());
    }
    return out;
}

static std::vector<uint8_t> rewrite_content_length(const std::vector<uint8_t>& req)
{
    size_t header_end = std::string::npos;
    for (size_t i = 0; i + 3 < req.size(); ++i) {
        if (req[i] == '\r' && req[i + 1] == '\n' && req[i + 2] == '\r' && req[i + 3] == '\n') {
            header_end = i;
            break;
        }
    }
    if (header_end == std::string::npos) return req;
    size_t body_len = req.size() - (header_end + 4);

    std::string headers(reinterpret_cast<const char*>(req.data()), header_end);
    std::string lowered = ascii_lower(headers);

    size_t pos = lowered.find("\ncontent-length:");
    size_t line_start = std::string::npos;
    size_t line_end = std::string::npos;
    if (pos != std::string::npos) {
        line_start = pos + 1;
        line_end = headers.find("\r\n", line_start);
    }

    if (line_start != std::string::npos && line_end != std::string::npos) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Content-Length: %zu", body_len);
        std::string new_headers = headers.substr(0, line_start) + buf
                                + headers.substr(line_end);
        std::vector<uint8_t> out;
        out.reserve(new_headers.size() + 4 + body_len);
        out.insert(out.end(), new_headers.begin(), new_headers.end());
        out.insert(out.end(), { '\r', '\n', '\r', '\n' });
        out.insert(out.end(), req.begin() + header_end + 4, req.end());
        return out;
    }
    return req;
}

static bool parse_status_line(const std::vector<uint8_t>& buf, int& status_code)
{
    if (buf.size() < 12) return false;
    if (buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' || buf[3] != 'P') return false;
    size_t i = 0;
    while (i < buf.size() && buf[i] != ' ') ++i;
    if (i >= buf.size()) return false;
    ++i;
    while (i < buf.size() && buf[i] == ' ') ++i;
    if (i + 3 > buf.size()) return false;
    if (buf[i] < '0' || buf[i] > '9') return false;
    status_code = (buf[i] - '0') * 100 + (buf[i + 1] - '0') * 10 + (buf[i + 2] - '0');
    return true;
}

static bool find_header_end(const std::vector<uint8_t>& buf, size_t& end_out)
{
    for (size_t i = 0; i + 3 < buf.size(); ++i) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end_out = i + 4;
            return true;
        }
    }
    return false;
}

static bool parse_content_length_header(const std::vector<uint8_t>& buf, size_t header_end, size_t& cl_out, bool& chunked_out)
{
    cl_out = SIZE_MAX;
    chunked_out = false;
    std::string headers_s(reinterpret_cast<const char*>(buf.data()), header_end);
    std::string lowered = ascii_lower(headers_s);
    size_t p = 0;
    while (p < lowered.size()) {
        size_t eol = lowered.find("\r\n", p);
        if (eol == std::string::npos) break;
        if (lowered.compare(p, 16, "content-length: ") == 0
            || lowered.compare(p, 15, "content-length:") == 0) {
            size_t v = p + (lowered[p + 15] == ' ' ? 16 : 15);
            while (v < eol && lowered[v] == ' ') ++v;
            size_t n = 0;
            bool any = false;
            while (v < eol && lowered[v] >= '0' && lowered[v] <= '9') {
                n = n * 10 + static_cast<size_t>(lowered[v] - '0');
                ++v;
                any = true;
            }
            if (any) cl_out = n;
        } else if (lowered.compare(p, 18, "transfer-encoding:") == 0) {
            size_t v = p + 18;
            std::string val = lowered.substr(v, eol - v);
            if (val.find("chunked") != std::string::npos) chunked_out = true;
        }
        p = eol + 2;
    }
    return cl_out != SIZE_MAX || chunked_out;
}

static bool read_full_response(SOCKET s, SSL* ssl, std::vector<uint8_t>& out,
                               size_t cap, int timeout_ms)
{
    out.clear();
    out.reserve(4096);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    uint8_t tmp[8192];

    size_t header_end = 0;
    bool have_header_end = false;
    size_t content_length = SIZE_MAX;
    bool chunked = false;
    size_t expected_total = SIZE_MAX;

    while (true) {
        if (out.size() >= cap) break;
        if (expected_total != SIZE_MAX && out.size() >= expected_total) break;
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (rem_ms <= 0) break;
        int n;
        if (ssl) n = ssl_recv_some(ssl, tmp, sizeof(tmp), rem_ms);
        else     n = plain_recv_some(s, tmp, sizeof(tmp), rem_ms);
        if (n <= 0) break;
        size_t take = static_cast<size_t>(n);
        if (out.size() + take > cap) take = cap - out.size();
        out.insert(out.end(), tmp, tmp + take);
        if (!have_header_end && find_header_end(out, header_end)) {
            have_header_end = true;
            parse_content_length_header(out, header_end, content_length, chunked);
            if (!chunked && content_length != SIZE_MAX) {
                expected_total = header_end + content_length;
                if (expected_total > cap) expected_total = cap;
            }
        }
        if (chunked && have_header_end) {
            if (out.size() >= header_end + 5) {
                if (std::search(out.begin() + header_end, out.end(),
                                std::initializer_list<uint8_t>{'0','\r','\n','\r','\n'}.begin(),
                                std::initializer_list<uint8_t>{'0','\r','\n','\r','\n'}.end())
                    != out.end()) {
                    break;
                }
            }
        }
    }
    return !out.empty();
}

struct job_t;

struct h2_response_capture_t
{
    int                                        status = 0;
    std::vector<protocol_parser::http_header>  headers;
    std::vector<uint8_t>                       body;
    bool                                       complete = false;
    bool                                       errored = false;
    size_t                                     cap = 65536;
};

struct h2_body_src_t
{
    std::vector<uint8_t> data;
    size_t               pos = 0;
};

struct h2_session_state_t
{
    nghttp2_session*                                            session = nullptr;
    std::unordered_map<int32_t, h2_response_capture_t>          streams;
    std::unordered_map<int32_t, std::shared_ptr<h2_body_src_t>> bodies;
    std::vector<uint8_t>                                        pending_out;
    std::mutex                                                  mtx;
    std::atomic<bool>                                           goaway{false};
    size_t                                                      body_cap = 65536;
};

static ssize_t h2_send_buffer_callback(nghttp2_session*, const uint8_t* data, size_t length,
                                       int, void* user_data)
{
    auto* st = static_cast<h2_session_state_t*>(user_data);
    st->pending_out.insert(st->pending_out.end(), data, data + length);
    return static_cast<ssize_t>(length);
}

static int h2_on_header_callback(nghttp2_session*, const nghttp2_frame* frame,
                                 const uint8_t* name, size_t namelen,
                                 const uint8_t* value, size_t valuelen,
                                 uint8_t, void* user_data)
{
    auto* st = static_cast<h2_session_state_t*>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    auto& cap = st->streams[frame->hd.stream_id];
    std::string n(reinterpret_cast<const char*>(name), namelen);
    std::string v(reinterpret_cast<const char*>(value), valuelen);
    if (n == ":status") {
        cap.status = atoi(v.c_str());
    } else {
        protocol_parser::http_header h;
        h.name = std::move(n);
        h.value = std::move(v);
        cap.headers.push_back(std::move(h));
    }
    return 0;
}

static int h2_on_data_chunk_callback(nghttp2_session*, uint8_t,
                                     int32_t stream_id, const uint8_t* data,
                                     size_t len, void* user_data)
{
    auto* st = static_cast<h2_session_state_t*>(user_data);
    auto it = st->streams.find(stream_id);
    if (it == st->streams.end()) return 0;
    auto& cap = it->second;
    size_t room = cap.cap > cap.body.size() ? cap.cap - cap.body.size() : 0;
    size_t take = len < room ? len : room;
    if (take > 0) cap.body.insert(cap.body.end(), data, data + take);
    return 0;
}

static int h2_on_frame_recv_callback(nghttp2_session*, const nghttp2_frame* frame, void* user_data)
{
    auto* st = static_cast<h2_session_state_t*>(user_data);
    if (frame->hd.type == NGHTTP2_GOAWAY) {
        st->goaway.store(true);
        return 0;
    }
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA)
        && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        auto it = st->streams.find(frame->hd.stream_id);
        if (it != st->streams.end()) it->second.complete = true;
    }
    return 0;
}

static int h2_on_stream_close_callback(nghttp2_session*, int32_t stream_id,
                                       uint32_t error_code, void* user_data)
{
    auto* st = static_cast<h2_session_state_t*>(user_data);
    auto it = st->streams.find(stream_id);
    if (it != st->streams.end()) {
        if (error_code != 0) it->second.errored = true;
        it->second.complete = true;
    }
    auto bit = st->bodies.find(stream_id);
    if (bit != st->bodies.end()) st->bodies.erase(bit);
    return 0;
}

static bool h2_session_init_client(h2_session_state_t& st, size_t body_cap)
{
    diag::log_tagged_fmt("intruder", "h2_session_init_client body_cap=%zu", body_cap);
    st.body_cap = body_cap;
    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback(cbs, h2_send_buffer_callback);
    nghttp2_session_callbacks_set_on_header_callback(cbs, h2_on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, h2_on_data_chunk_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, h2_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, h2_on_stream_close_callback);

    int rv = nghttp2_session_client_new(&st.session, cbs, &st);
    nghttp2_session_callbacks_del(cbs);
    if (rv != 0) {
        diag::log_tagged_fmt("intruder", "h2_session_init_client session_new_failed rv=%d", rv);
        return false;
    }

    nghttp2_settings_entry iv[2] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1024 },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1u << 24 }
    };
    if (nghttp2_submit_settings(st.session, NGHTTP2_FLAG_NONE, iv, 2) != 0) {
        diag::log_tagged("intruder", "h2_session_init_client submit_settings_failed");
        return false;
    }
    diag::log_tagged("intruder", "h2_session_init_client ok");
    return true;
}

static void h2_session_term(h2_session_state_t& st)
{
    diag::log_tagged("intruder", "h2_session_term");
    if (st.session) {
        nghttp2_session_del(st.session);
        st.session = nullptr;
    }
    st.bodies.clear();
}

struct parsed_h2_target_t
{
    std::string method;
    std::string scheme;
    std::string authority;
    std::string path;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
};

static parsed_h2_target_t parse_http1_for_h2(const std::vector<uint8_t>& raw,
                                             const std::string& fallback_scheme,
                                             const std::string& fallback_authority)
{
    parsed_h2_target_t out;
    out.scheme = fallback_scheme;
    out.authority = fallback_authority;
    out.method = "GET";
    out.path = "/";

    size_t header_end = 0;
    bool have_he = find_header_end(raw, header_end);
    if (!have_he) return out;

    std::string headers_s(reinterpret_cast<const char*>(raw.data()), header_end - 4);
    size_t first_eol = headers_s.find("\r\n");
    if (first_eol == std::string::npos) return out;
    std::string req_line = headers_s.substr(0, first_eol);
    size_t sp1 = req_line.find(' ');
    size_t sp2 = req_line.find(' ', sp1 == std::string::npos ? 0 : sp1 + 1);
    if (sp1 != std::string::npos) out.method = req_line.substr(0, sp1);
    if (sp1 != std::string::npos && sp2 != std::string::npos) {
        out.path = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
    }

    size_t pos = first_eol + 2;
    while (pos < headers_s.size()) {
        size_t eol = headers_s.find("\r\n", pos);
        if (eol == std::string::npos) eol = headers_s.size();
        std::string line = headers_s.substr(pos, eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) value.pop_back();
            std::string lname = ascii_lower(name);
            if (lname == "host") {
                out.authority = value;
            } else if (lname == "connection" || lname == "proxy-connection"
                       || lname == "keep-alive" || lname == "transfer-encoding"
                       || lname == "upgrade" || lname == "http2-settings") {
                pos = eol + 2;
                continue;
            } else {
                out.headers.push_back({ lname, value });
            }
        }
        pos = eol + 2;
    }

    if (raw.size() > header_end) {
        out.body.assign(raw.begin() + header_end, raw.end());
    }
    return out;
}

struct token_bucket_t
{
    double tokens = 0.0;
    double rate = 0.0;
    std::chrono::steady_clock::time_point last;
};

static void bucket_init(token_bucket_t& b, size_t rps_cap)
{
    b.rate = static_cast<double>(rps_cap);
    b.tokens = b.rate;
    b.last = std::chrono::steady_clock::now();
}

static void bucket_wait(token_bucket_t& b, std::atomic<bool>& cancel)
{
    if (b.rate <= 0.0) return;
    for (;;) {
        if (cancel.load()) return;
        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration_cast<std::chrono::duration<double>>(now - b.last).count();
        b.last = now;
        b.tokens += dt * b.rate;
        if (b.tokens > b.rate) b.tokens = b.rate;
        if (b.tokens >= 1.0) { b.tokens -= 1.0; return; }
        double need = (1.0 - b.tokens) / b.rate;
        int sleep_ms = static_cast<int>(need * 1000.0) + 1;
        if (sleep_ms > 100) sleep_ms = 100;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
}

struct job_t
{
    uint64_t                      id = 0;
    config_t                      cfg;
    std::atomic<bool>             running{false};
    std::atomic<bool>             cancel{false};
    std::atomic<size_t>           sent{0};
    std::atomic<size_t>           errors{0};
    std::atomic<size_t>           total{0};
    std::atomic<uint64_t>         started_ms{0};
    std::atomic<uint64_t>         finished_ms{0};

    std::mutex                    results_mtx;
    std::deque<result_t>          results;

    std::vector<std::thread>      workers;
    std::mutex                    worker_mtx;

    std::mutex                    feed_mtx;
    size_t                        feed_pos = 0;

    token_bucket_t                bucket;
};

struct registry_t
{
    std::mutex                                              mtx;
    std::unordered_map<uint64_t, std::shared_ptr<job_t>>    jobs;
    std::atomic<uint64_t>                                   next_id{1};
};

static registry_t& reg() { static registry_t r; return r; }

static void store_result(job_t& job, result_t r)
{
    std::lock_guard<std::mutex> lk(job.results_mtx);
    job.results.push_back(std::move(r));
}

struct payload_iter_t
{
    attack_mode_t                                   mode = attack_mode_t::sniper;
    const std::vector<std::pair<size_t, size_t>>*   positions = nullptr;
    const std::vector<std::vector<std::string>>*    sets = nullptr;
    size_t                                          total = 0;

    std::vector<std::string> resolve(size_t index) const
    {
        std::vector<std::string> out;
        if (!positions || positions->empty() || !sets || sets->empty()) {
            return out;
        }
        const size_t n_pos = positions->size();
        out.assign(n_pos, std::string());

        switch (mode) {
            case attack_mode_t::sniper: {
                size_t per_pos = (*sets)[0].size();
                if (per_pos == 0) return out;
                size_t pos_idx = index / per_pos;
                size_t pay_idx = index % per_pos;
                if (pos_idx >= n_pos) pos_idx = n_pos - 1;
                for (size_t i = 0; i < n_pos; ++i) {
                    if (i == pos_idx) out[i] = (*sets)[0][pay_idx];
                    else {
                        size_t start = (*positions)[i].first;
                        size_t len = (*positions)[i].second;
                        out[i] = std::string();
                        (void)start; (void)len;
                    }
                }
                break;
            }
            case attack_mode_t::battering_ram: {
                size_t per = (*sets)[0].size();
                if (per == 0) return out;
                size_t pi = index % per;
                std::string v = (*sets)[0][pi];
                for (size_t i = 0; i < n_pos; ++i) out[i] = v;
                break;
            }
            case attack_mode_t::pitchfork: {
                size_t per = SIZE_MAX;
                for (size_t i = 0; i < n_pos && i < sets->size(); ++i) {
                    size_t s = (*sets)[i].size();
                    if (s < per) per = s;
                }
                if (per == SIZE_MAX || per == 0) return out;
                size_t pi = index % per;
                for (size_t i = 0; i < n_pos; ++i) {
                    if (i < sets->size() && pi < (*sets)[i].size())
                        out[i] = (*sets)[i][pi];
                }
                break;
            }
            case attack_mode_t::clusterbomb: {
                size_t remaining = index;
                for (size_t i = 0; i < n_pos; ++i) {
                    size_t s = (i < sets->size()) ? (*sets)[i].size() : 0;
                    if (s == 0) { out[i] = std::string(); continue; }
                    size_t pi = remaining % s;
                    remaining /= s;
                    out[i] = (*sets)[i][pi];
                }
                break;
            }
            case attack_mode_t::turbo:
            case attack_mode_t::race: {
                size_t per = (*sets)[0].size();
                if (per == 0) return out;
                size_t pi = index % per;
                std::string v = (*sets)[0][pi];
                for (size_t i = 0; i < n_pos; ++i) out[i] = v;
                break;
            }
        }
        return out;
    }
};

static size_t compute_total(const payload_iter_t& it, const config_t& cfg)
{
    diag::log_tagged_fmt("intruder", "compute_total mode=%s positions=%zu sets=%zu cap=%zu",
        attack_mode_name(it.mode),
        it.positions ? it.positions->size() : 0,
        it.sets ? it.sets->size() : 0,
        cfg.total_requests_cap);
    if (!it.sets || it.sets->empty() || !it.positions || it.positions->empty()) {
        diag::log_tagged("intruder", "compute_total empty_sets_or_positions result=0");
        return 0;
    }
    size_t total = 0;
    switch (it.mode) {
        case attack_mode_t::sniper:
            total = (*it.sets)[0].size() * it.positions->size();
            break;
        case attack_mode_t::battering_ram:
            total = (*it.sets)[0].size();
            break;
        case attack_mode_t::pitchfork: {
            size_t m = SIZE_MAX;
            for (size_t i = 0; i < it.positions->size() && i < it.sets->size(); ++i) {
                size_t s = (*it.sets)[i].size();
                if (s < m) m = s;
            }
            total = (m == SIZE_MAX) ? 0 : m;
            break;
        }
        case attack_mode_t::clusterbomb: {
            total = 1;
            bool any = false;
            for (size_t i = 0; i < it.positions->size(); ++i) {
                size_t s = (i < it.sets->size()) ? (*it.sets)[i].size() : 0;
                if (s == 0) { total = 0; break; }
                if (total > (SIZE_MAX / s)) { total = SIZE_MAX; break; }
                total *= s;
                any = true;
            }
            if (!any) total = 0;
            break;
        }
        case attack_mode_t::turbo:
        case attack_mode_t::race:
            total = (*it.sets)[0].size();
            break;
    }
    if (cfg.total_requests_cap > 0 && total > cfg.total_requests_cap) {
        diag::log_tagged_fmt("intruder", "compute_total capped raw=%zu cap=%zu", total, cfg.total_requests_cap);
        total = cfg.total_requests_cap;
    }
    diag::log_tagged_fmt("intruder", "compute_total result=%zu", total);
    return total;
}

static bool send_one_request_h1(const std::string& host, uint16_t port, bool tls,
                                const std::vector<uint8_t>& req,
                                const config_t& cfg,
                                result_t& out_result)
{
    diag::log_tagged_fmt("intruder", "send_one_request_h1 host=%s port=%u tls=%d req_len=%zu",
        host.c_str(), static_cast<unsigned>(port), tls ? 1 : 0, req.size());
    auto t0 = std::chrono::steady_clock::now();
    if (tls) {
        ssl_conn_t c;
        std::vector<std::string> alpn = { "http/1.1" };
        if (!ssl_connect(c, host, port, cfg.timeout_ms, alpn)) {
            diag::log_tagged_fmt("intruder", "send_one_request_h1 tls_connect_failed host=%s port=%u", host.c_str(), static_cast<unsigned>(port));
            out_result.error = true;
            out_result.error_msg = "tls_connect_failed";
            return false;
        }
        if (!ssl_send_all(c.ssl, req.data(), req.size(), cfg.timeout_ms)) {
            diag::log_tagged("intruder", "send_one_request_h1 tls_send_failed");
            close_ssl(c);
            out_result.error = true;
            out_result.error_msg = "tls_send_failed";
            return false;
        }
        std::vector<uint8_t> resp;
        bool ok = read_full_response(INVALID_SOCKET, c.ssl, resp,
                                     cfg.max_response_body_bytes, cfg.timeout_ms);
        close_ssl(c);
        if (!ok) {
            diag::log_tagged("intruder", "send_one_request_h1 tls_recv_failed");
            out_result.error = true;
            out_result.error_msg = "tls_recv_failed";
            return false;
        }
        int sc = 0;
        parse_status_line(resp, sc);
        out_result.status_code = sc;
        out_result.response_size = resp.size();
        out_result.response_preview = preview_string(resp, 4096);
        out_result.response_raw = std::move(resp);
        auto t1 = std::chrono::steady_clock::now();
        out_result.latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        diag::log_tagged_fmt("intruder", "send_one_request_h1 tls_ok status=%d resp_size=%zu latency_ms=%llu",
            sc, out_result.response_size, static_cast<unsigned long long>(out_result.latency_ms));
        return true;
    } else {
        SOCKET s = tcp_connect(host, port, cfg.timeout_ms);
        if (s == INVALID_SOCKET) {
            diag::log_tagged_fmt("intruder", "send_one_request_h1 tcp_connect_failed host=%s port=%u", host.c_str(), static_cast<unsigned>(port));
            out_result.error = true;
            out_result.error_msg = "tcp_connect_failed";
            return false;
        }
        if (!plain_send_all(s, req.data(), req.size(), cfg.timeout_ms)) {
            diag::log_tagged("intruder", "send_one_request_h1 tcp_send_failed");
            shutdown(s, SD_BOTH); closesocket(s);
            out_result.error = true;
            out_result.error_msg = "tcp_send_failed";
            return false;
        }
        std::vector<uint8_t> resp;
        bool ok = read_full_response(s, nullptr, resp,
                                     cfg.max_response_body_bytes, cfg.timeout_ms);
        shutdown(s, SD_BOTH); closesocket(s);
        if (!ok) {
            diag::log_tagged("intruder", "send_one_request_h1 tcp_recv_failed");
            out_result.error = true;
            out_result.error_msg = "tcp_recv_failed";
            return false;
        }
        int sc = 0;
        parse_status_line(resp, sc);
        out_result.status_code = sc;
        out_result.response_size = resp.size();
        out_result.response_preview = preview_string(resp, 4096);
        out_result.response_raw = std::move(resp);
        auto t1 = std::chrono::steady_clock::now();
        out_result.latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        diag::log_tagged_fmt("intruder", "send_one_request_h1 tcp_ok status=%d resp_size=%zu latency_ms=%llu",
            sc, out_result.response_size, static_cast<unsigned long long>(out_result.latency_ms));
        return true;
    }
}

static void worker_pooled_h1(std::shared_ptr<job_t> job)
{
    diag::log_tagged_fmt("intruder", "worker_pooled_h1 job_id=%llu total=%zu",
        static_cast<unsigned long long>(job->id), job->total.load());
    payload_iter_t it;
    it.mode = job->cfg.attack_mode;
    it.positions = &job->cfg.positions;
    it.sets = &job->cfg.payload_sets;
    bool tls = (job->cfg.scheme == "https");
    while (!job->cancel.load()) {
        size_t idx;
        {
            std::lock_guard<std::mutex> lk(job->feed_mtx);
            if (job->feed_pos >= job->total.load()) break;
            idx = job->feed_pos++;
        }
        if (job->cfg.requests_per_second_cap > 0) bucket_wait(job->bucket, job->cancel);
        if (job->cancel.load()) break;

        std::vector<std::string> payloads = it.resolve(idx);
        std::vector<uint8_t> req_raw =
            apply_payload_replacements(job->cfg.base_request, job->cfg.positions, payloads);
        req_raw = rewrite_content_length(req_raw);

        result_t r;
        r.job_id = job->id;
        r.index  = idx;
        r.payloads = payloads;
        send_one_request_h1(job->cfg.host, job->cfg.port, tls, req_raw, job->cfg, r);
        if (r.error) {
            job->errors.fetch_add(1);
            diag::log_tagged_fmt("intruder", "worker_pooled_h1 idx=%zu error=%s", idx, r.error_msg.c_str());
        } else {
            diag::log_tagged_fmt("intruder", "worker_pooled_h1 idx=%zu status=%d resp_size=%zu latency_ms=%llu",
                idx, r.status_code, r.response_size, static_cast<unsigned long long>(r.latency_ms));
        }
        job->sent.fetch_add(1);
        store_result(*job, std::move(r));
    }
    diag::log_tagged_fmt("intruder", "worker_pooled_h1 done job_id=%llu sent=%zu errors=%zu",
        static_cast<unsigned long long>(job->id), job->sent.load(), job->errors.load());
}

static void run_pipelined_h1(std::shared_ptr<job_t> job)
{
    diag::log_tagged_fmt("intruder", "run_pipelined_h1 job_id=%llu host=%s port=%u total=%zu",
        static_cast<unsigned long long>(job->id), job->cfg.host.c_str(), static_cast<unsigned>(job->cfg.port), job->total.load());
    payload_iter_t it;
    it.mode = job->cfg.attack_mode;
    it.positions = &job->cfg.positions;
    it.sets = &job->cfg.payload_sets;
    bool tls = (job->cfg.scheme == "https");
    size_t total = job->total.load();
    size_t batch = job->cfg.concurrency > 0 ? job->cfg.concurrency : 16;

    size_t cursor = 0;
    while (cursor < total && !job->cancel.load()) {
        size_t this_batch = (total - cursor);
        if (this_batch > batch) this_batch = batch;

        diag::log_tagged_fmt("intruder", "run_pipelined_h1 batch cursor=%zu batch_size=%zu tls=%d", cursor, this_batch, tls ? 1 : 0);
        ssl_conn_t sc;
        SOCKET plain_s = INVALID_SOCKET;
        if (tls) {
            std::vector<std::string> alpn = { "http/1.1" };
            if (!ssl_connect(sc, job->cfg.host, job->cfg.port, job->cfg.timeout_ms, alpn)) {
                diag::log_tagged_fmt("intruder", "run_pipelined_h1 tls_connect_failed cursor=%zu batch=%zu", cursor, this_batch);
                for (size_t i = 0; i < this_batch; ++i) {
                    result_t r;
                    r.job_id = job->id;
                    r.index = cursor + i;
                    r.payloads = it.resolve(cursor + i);
                    r.error = true;
                    r.error_msg = "tls_connect_failed";
                    job->errors.fetch_add(1);
                    job->sent.fetch_add(1);
                    store_result(*job, std::move(r));
                }
                cursor += this_batch;
                continue;
            }
        } else {
            plain_s = tcp_connect(job->cfg.host, job->cfg.port, job->cfg.timeout_ms);
            if (plain_s == INVALID_SOCKET) {
                diag::log_tagged_fmt("intruder", "run_pipelined_h1 tcp_connect_failed cursor=%zu batch=%zu", cursor, this_batch);
                for (size_t i = 0; i < this_batch; ++i) {
                    result_t r;
                    r.job_id = job->id;
                    r.index = cursor + i;
                    r.payloads = it.resolve(cursor + i);
                    r.error = true;
                    r.error_msg = "tcp_connect_failed";
                    job->errors.fetch_add(1);
                    job->sent.fetch_add(1);
                    store_result(*job, std::move(r));
                }
                cursor += this_batch;
                continue;
            }
        }

        std::vector<std::vector<uint8_t>> reqs(this_batch);
        std::vector<std::vector<std::string>> payloads_v(this_batch);
        std::vector<uint8_t> combined;
        for (size_t i = 0; i < this_batch; ++i) {
            payloads_v[i] = it.resolve(cursor + i);
            std::vector<uint8_t> req =
                apply_payload_replacements(job->cfg.base_request, job->cfg.positions, payloads_v[i]);
            req = rewrite_content_length(req);
            std::string lowered_h;
            size_t he = 0;
            if (find_header_end(req, he)) {
                lowered_h = ascii_lower(std::string(reinterpret_cast<const char*>(req.data()), he));
                if (lowered_h.find("\nconnection:") == std::string::npos) {
                    std::string insertion = "Connection: keep-alive\r\n";
                    req.insert(req.begin() + (he - 2), insertion.begin(), insertion.end());
                }
            }
            reqs[i] = req;
            combined.insert(combined.end(), req.begin(), req.end());
        }

        diag::log_tagged_fmt("intruder", "run_pipelined_h1 sending combined_len=%zu batch=%zu", combined.size(), this_batch);
        auto t0 = std::chrono::steady_clock::now();
        bool sent_ok = tls ? ssl_send_all(sc.ssl, combined.data(), combined.size(), job->cfg.timeout_ms)
                           : plain_send_all(plain_s, combined.data(), combined.size(), job->cfg.timeout_ms);
        if (!sent_ok) {
            diag::log_tagged_fmt("intruder", "run_pipelined_h1 pipelined_send_failed cursor=%zu batch=%zu", cursor, this_batch);
            for (size_t i = 0; i < this_batch; ++i) {
                result_t r;
                r.job_id = job->id;
                r.index = cursor + i;
                r.payloads = payloads_v[i];
                r.error = true;
                r.error_msg = "pipelined_send_failed";
                job->errors.fetch_add(1);
                job->sent.fetch_add(1);
                store_result(*job, std::move(r));
            }
            if (tls) close_ssl(sc);
            else { shutdown(plain_s, SD_BOTH); closesocket(plain_s); }
            cursor += this_batch;
            continue;
        }

        std::vector<uint8_t> recv_buf;
        recv_buf.reserve(this_batch * 4096);
        size_t parsed_count = 0;
        size_t parsed_offset = 0;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(job->cfg.timeout_ms * (int)this_batch);
        uint8_t tmp[8192];

        while (parsed_count < this_batch && !job->cancel.load()) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            int n = tls ? ssl_recv_some(sc.ssl, tmp, sizeof(tmp), rem_ms)
                        : plain_recv_some(plain_s, tmp, sizeof(tmp), rem_ms);
            if (n <= 0) break;
            recv_buf.insert(recv_buf.end(), tmp, tmp + n);

            while (parsed_count < this_batch) {
                if (recv_buf.size() < parsed_offset + 16) break;
                size_t local_he = 0;
                bool have_he = false;
                for (size_t i = parsed_offset; i + 3 < recv_buf.size(); ++i) {
                    if (recv_buf[i] == '\r' && recv_buf[i + 1] == '\n'
                        && recv_buf[i + 2] == '\r' && recv_buf[i + 3] == '\n') {
                        local_he = i + 4;
                        have_he = true;
                        break;
                    }
                }
                if (!have_he) break;
                size_t cl = SIZE_MAX;
                bool chunked = false;
                std::vector<uint8_t> hdrs_view(recv_buf.begin() + parsed_offset, recv_buf.begin() + local_he);
                parse_content_length_header(hdrs_view, local_he - parsed_offset, cl, chunked);
                size_t body_start = local_he;
                size_t need_total;
                if (chunked) {
                    auto term_it = std::search(recv_buf.begin() + body_start, recv_buf.end(),
                                               std::initializer_list<uint8_t>{'0','\r','\n','\r','\n'}.begin(),
                                               std::initializer_list<uint8_t>{'0','\r','\n','\r','\n'}.end());
                    if (term_it == recv_buf.end()) break;
                    need_total = (term_it - recv_buf.begin()) + 5;
                } else if (cl != SIZE_MAX) {
                    if (recv_buf.size() < body_start + cl) break;
                    need_total = body_start + cl;
                } else {
                    need_total = body_start;
                }

                std::vector<uint8_t> piece(recv_buf.begin() + parsed_offset, recv_buf.begin() + need_total);
                int sc_code = 0;
                parse_status_line(piece, sc_code);
                result_t r;
                r.job_id = job->id;
                r.index = cursor + parsed_count;
                r.payloads = payloads_v[parsed_count];
                r.status_code = sc_code;
                r.response_size = piece.size();
                if (piece.size() > job->cfg.max_response_body_bytes) {
                    piece.resize(job->cfg.max_response_body_bytes);
                }
                r.response_preview = preview_string(piece, 4096);
                auto t1 = std::chrono::steady_clock::now();
                r.latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
                r.response_raw = std::move(piece);
                job->sent.fetch_add(1);
                store_result(*job, std::move(r));
                parsed_offset = need_total;
                ++parsed_count;
            }
        }

        if (parsed_count < this_batch) {
            diag::log_tagged_fmt("intruder", "run_pipelined_h1 pipelined_response_missing cursor=%zu parsed=%zu expected=%zu",
                cursor, parsed_count, this_batch);
        }
        for (size_t i = parsed_count; i < this_batch; ++i) {
            result_t r;
            r.job_id = job->id;
            r.index = cursor + i;
            r.payloads = payloads_v[i];
            r.error = true;
            r.error_msg = "pipelined_response_missing";
            job->errors.fetch_add(1);
            job->sent.fetch_add(1);
            store_result(*job, std::move(r));
        }

        diag::log_tagged_fmt("intruder", "run_pipelined_h1 batch_done cursor=%zu parsed=%zu", cursor, parsed_count);
        if (tls) close_ssl(sc);
        else { shutdown(plain_s, SD_BOTH); closesocket(plain_s); }
        cursor += this_batch;
    }
    diag::log_tagged_fmt("intruder", "run_pipelined_h1 complete job_id=%llu sent=%zu errors=%zu",
        static_cast<unsigned long long>(job->id), job->sent.load(), job->errors.load());
}

static bool h2_flush_out(ssl_conn_t& sc, h2_session_state_t& st, int timeout_ms)
{
    if (st.pending_out.empty()) return true;
    bool ok = ssl_send_all(sc.ssl, st.pending_out.data(), st.pending_out.size(), timeout_ms);
    st.pending_out.clear();
    return ok;
}

static bool h2_pump_session_input(ssl_conn_t& sc, h2_session_state_t& st, int timeout_ms,
                                  bool until_streams_complete)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    uint8_t tmp[16384];
    while (true) {
        bool all_done = true;
        for (auto& kv : st.streams) {
            if (!kv.second.complete) { all_done = false; break; }
        }
        if (until_streams_complete && all_done) {
            (void)nghttp2_session_send(st.session);
            return true;
        }
        if (nghttp2_session_want_write(st.session) || !st.pending_out.empty()) {
            (void)nghttp2_session_send(st.session);
            if (!h2_flush_out(sc, st, timeout_ms)) return false;
        }
        if (st.goaway.load()) return true;
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (rem_ms < 50) rem_ms = 50;
        int n = ssl_recv_some(sc.ssl, tmp, sizeof(tmp), rem_ms);
        if (n <= 0) return false;
        ssize_t rv = nghttp2_session_mem_recv(st.session, tmp, static_cast<size_t>(n));
        if (rv < 0) return false;
    }
}

static int32_t h2_submit(h2_session_state_t& st, const parsed_h2_target_t& p)
{
    diag::log_tagged_fmt("intruder", "h2_submit method=%s scheme=%s authority=%s path=%s body_len=%zu",
        p.method.c_str(), p.scheme.c_str(), p.authority.c_str(), p.path.c_str(), p.body.size());
    std::vector<nghttp2_nv> nva;
    nva.reserve(p.headers.size() + 4);
    auto push = [&](const std::string& n, const std::string& v) {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(n.data()));
        nv.namelen = n.size();
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(v.data()));
        nv.valuelen = v.size();
        nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
        nva.push_back(nv);
    };
    push(":method", p.method);
    push(":scheme", p.scheme);
    push(":path", p.path);
    push(":authority", p.authority);
    for (auto& h : p.headers) push(h.first, h.second);

    if (p.body.empty()) {
        int32_t sid = nghttp2_submit_request(st.session, nullptr, nva.data(), nva.size(),
                                             nullptr, nullptr);
        diag::log_tagged_fmt("intruder", "h2_submit no_body sid=%d", sid);
        return sid;
    }

    auto body = std::make_shared<h2_body_src_t>();
    body->data = p.body;
    body->pos = 0;

    nghttp2_data_provider prd{};
    prd.source.ptr = body.get();
    prd.read_callback = [](nghttp2_session* sess, int32_t, uint8_t* buf, size_t length,
                           uint32_t* data_flags, nghttp2_data_source* source, void*) -> ssize_t {
        (void)sess;
        auto* s = static_cast<h2_body_src_t*>(source->ptr);
        size_t rem = s->data.size() - s->pos;
        size_t take = rem < length ? rem : length;
        if (take) { memcpy(buf, s->data.data() + s->pos, take); s->pos += take; }
        if (s->pos >= s->data.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return static_cast<ssize_t>(take);
    };

    int32_t sid = nghttp2_submit_request(st.session, nullptr, nva.data(), nva.size(),
                                         &prd, nullptr);
    if (sid >= 0) {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.bodies[sid] = body;
    }
    diag::log_tagged_fmt("intruder", "h2_submit with_body sid=%d", sid);
    return sid;
}

static void run_h2_multiplexed(std::shared_ptr<job_t> job)
{
    diag::log_tagged_fmt("intruder", "run_h2_multiplexed job_id=%llu host=%s port=%u total=%zu",
        static_cast<unsigned long long>(job->id), job->cfg.host.c_str(), static_cast<unsigned>(job->cfg.port), job->total.load());
    payload_iter_t it;
    it.mode = job->cfg.attack_mode;
    it.positions = &job->cfg.positions;
    it.sets = &job->cfg.payload_sets;

    ssl_conn_t sc;
    std::vector<std::string> alpn = { "h2" };
    if (!ssl_connect(sc, job->cfg.host, job->cfg.port, job->cfg.timeout_ms, alpn)) {
        diag::log_tagged_fmt("intruder", "run_h2_multiplexed h2_tls_failed host=%s", job->cfg.host.c_str());
        size_t t = job->total.load();
        for (size_t i = 0; i < t; ++i) {
            result_t r; r.job_id = job->id; r.index = i;
            r.payloads = it.resolve(i);
            r.error = true; r.error_msg = "h2_tls_failed";
            job->errors.fetch_add(1); job->sent.fetch_add(1);
            store_result(*job, std::move(r));
        }
        return;
    }
    if (!sc.alpn_is_h2) {
        diag::log_tagged_fmt("intruder", "run_h2_multiplexed alpn_not_h2 host=%s", job->cfg.host.c_str());
        size_t t = job->total.load();
        for (size_t i = 0; i < t; ++i) {
            result_t r; r.job_id = job->id; r.index = i;
            r.payloads = it.resolve(i);
            r.error = true; r.error_msg = "alpn_not_h2";
            job->errors.fetch_add(1); job->sent.fetch_add(1);
            store_result(*job, std::move(r));
        }
        close_ssl(sc);
        return;
    }

    h2_session_state_t st;
    st.body_cap = job->cfg.max_response_body_bytes;
    if (!h2_session_init_client(st, job->cfg.max_response_body_bytes)) {
        diag::log_tagged("intruder", "run_h2_multiplexed session_init_failed");
        close_ssl(sc);
        return;
    }

    static const uint8_t kPreface[] = {
        'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n','\r','\n',
        'S','M','\r','\n','\r','\n'
    };
    if (!ssl_send_all(sc.ssl, kPreface, sizeof(kPreface), job->cfg.timeout_ms)) {
        diag::log_tagged("intruder", "run_h2_multiplexed preface_send_failed");
        close_ssl(sc); h2_session_term(st);
        return;
    }

    size_t total = job->total.load();
    size_t inflight_cap = job->cfg.concurrency > 0 ? job->cfg.concurrency : 32;
    if (inflight_cap > 256) inflight_cap = 256;
    diag::log_tagged_fmt("intruder", "run_h2_multiplexed tls_ok total=%zu inflight_cap=%zu", total, inflight_cap);

    std::unordered_map<int32_t, std::pair<size_t, std::vector<std::string>>> stream_to_idx;
    auto t_start = std::chrono::steady_clock::now();

    size_t cursor = 0;
    while (cursor < total && !job->cancel.load()) {
        while (cursor < total && stream_to_idx.size() < inflight_cap) {
            if (job->cfg.requests_per_second_cap > 0) bucket_wait(job->bucket, job->cancel);
            if (job->cancel.load()) break;
            auto payloads = it.resolve(cursor);
            std::vector<uint8_t> req =
                apply_payload_replacements(job->cfg.base_request, job->cfg.positions, payloads);
            std::string scheme = job->cfg.scheme.empty() ? "https" : job->cfg.scheme;
            std::string auth = job->cfg.host;
            parsed_h2_target_t p = parse_http1_for_h2(req, scheme, auth);
            int32_t sid = h2_submit(st, p);
            if (sid < 0) {
                diag::log_tagged_fmt("intruder", "run_h2_multiplexed h2_submit_failed cursor=%zu", cursor);
                result_t r;
                r.job_id = job->id; r.index = cursor; r.payloads = payloads;
                r.error = true; r.error_msg = "h2_submit_failed";
                job->errors.fetch_add(1); job->sent.fetch_add(1);
                store_result(*job, std::move(r));
                ++cursor;
                continue;
            }
            stream_to_idx[sid] = { cursor, std::move(payloads) };
            ++cursor;
        }

        (void)nghttp2_session_send(st.session);
        if (!h2_flush_out(sc, st, job->cfg.timeout_ms)) break;

        std::vector<int32_t> completed;
        for (auto& kv : st.streams) {
            if (kv.second.complete) completed.push_back(kv.first);
        }
        for (auto sid : completed) {
            auto it_si = stream_to_idx.find(sid);
            if (it_si == stream_to_idx.end()) continue;
            auto& cap = st.streams[sid];
            result_t r;
            r.job_id = job->id;
            r.index = it_si->second.first;
            r.payloads = it_si->second.second;
            r.status_code = cap.status;
            r.response_size = cap.body.size();
            r.response_preview = preview_string(cap.body, 4096);
            r.response_raw = std::move(cap.body);
            auto t1 = std::chrono::steady_clock::now();
            r.latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t_start).count());
            if (cap.errored) {
                diag::log_tagged_fmt("intruder", "run_h2_multiplexed stream_errored sid=%d idx=%zu", sid, r.index);
                r.error = true; r.error_msg = "h2_stream_errored"; job->errors.fetch_add(1);
            } else {
                diag::log_tagged_fmt("intruder", "run_h2_multiplexed stream_ok sid=%d idx=%zu status=%d resp_size=%zu latency_ms=%llu",
                    sid, r.index, r.status_code, r.response_size, static_cast<unsigned long long>(r.latency_ms));
            }
            job->sent.fetch_add(1);
            store_result(*job, std::move(r));
            stream_to_idx.erase(it_si);
            st.streams.erase(sid);
        }

        if (st.goaway.load()) break;

        if (stream_to_idx.empty() && cursor >= total) break;

        uint8_t tmp[16384];
        int rem_ms = job->cfg.timeout_ms;
        int n = ssl_recv_some(sc.ssl, tmp, sizeof(tmp), rem_ms);
        if (n <= 0) break;
        ssize_t rv = nghttp2_session_mem_recv(st.session, tmp, static_cast<size_t>(n));
        if (rv < 0) break;
    }

    if (!stream_to_idx.empty()) {
        h2_pump_session_input(sc, st, job->cfg.timeout_ms, true);
        std::vector<int32_t> remaining;
        for (auto& kv : stream_to_idx) remaining.push_back(kv.first);
        for (auto sid : remaining) {
            auto it_si = stream_to_idx.find(sid);
            auto it_cap = st.streams.find(sid);
            result_t r;
            r.job_id = job->id;
            r.index = it_si->second.first;
            r.payloads = it_si->second.second;
            if (it_cap != st.streams.end()) {
                auto& cap = it_cap->second;
                r.status_code = cap.status;
                r.response_size = cap.body.size();
                r.response_preview = preview_string(cap.body, 4096);
                r.response_raw = std::move(cap.body);
                if (!cap.complete) { r.error = true; r.error_msg = "h2_stream_incomplete"; job->errors.fetch_add(1); }
            } else {
                r.error = true; r.error_msg = "h2_stream_missing";
                job->errors.fetch_add(1);
            }
            job->sent.fetch_add(1);
            store_result(*job, std::move(r));
        }
    }

    diag::log_tagged_fmt("intruder", "run_h2_multiplexed complete job_id=%llu sent=%zu errors=%zu",
        static_cast<unsigned long long>(job->id), job->sent.load(), job->errors.load());
    close_ssl(sc);
    h2_session_term(st);
}

static void run_h2_single_packet(std::shared_ptr<job_t> job)
{
    diag::log_tagged_fmt("intruder", "run_h2_single_packet job_id=%llu host=%s port=%u total=%zu warmup=%d gate=%d",
        static_cast<unsigned long long>(job->id), job->cfg.host.c_str(), static_cast<unsigned>(job->cfg.port),
        job->total.load(), job->cfg.race_warmup_count, job->cfg.race_gate_size);
    payload_iter_t it;
    it.mode = job->cfg.attack_mode;
    it.positions = &job->cfg.positions;
    it.sets = &job->cfg.payload_sets;

    ssl_conn_t sc;
    std::vector<std::string> alpn = { "h2" };
    if (!ssl_connect(sc, job->cfg.host, job->cfg.port, job->cfg.timeout_ms, alpn)) {
        diag::log_tagged_fmt("intruder", "run_h2_single_packet h2_tls_failed host=%s", job->cfg.host.c_str());
        size_t t = job->total.load();
        for (size_t i = 0; i < t; ++i) {
            result_t r; r.job_id = job->id; r.index = i;
            r.payloads = it.resolve(i);
            r.error = true; r.error_msg = "h2_tls_failed";
            job->errors.fetch_add(1); job->sent.fetch_add(1);
            store_result(*job, std::move(r));
        }
        return;
    }
    if (!sc.alpn_is_h2) {
        diag::log_tagged_fmt("intruder", "run_h2_single_packet alpn_not_h2 host=%s", job->cfg.host.c_str());
        size_t t = job->total.load();
        for (size_t i = 0; i < t; ++i) {
            result_t r; r.job_id = job->id; r.index = i;
            r.payloads = it.resolve(i);
            r.error = true; r.error_msg = "alpn_not_h2";
            job->errors.fetch_add(1); job->sent.fetch_add(1);
            store_result(*job, std::move(r));
        }
        close_ssl(sc);
        return;
    }

    h2_session_state_t st;
    st.body_cap = job->cfg.max_response_body_bytes;
    if (!h2_session_init_client(st, job->cfg.max_response_body_bytes)) {
        diag::log_tagged("intruder", "run_h2_single_packet session_init_failed");
        close_ssl(sc);
        return;
    }

    size_t warmup = static_cast<size_t>(job->cfg.race_warmup_count > 0 ? job->cfg.race_warmup_count : 0);
    size_t gate = job->cfg.race_gate_size > 0 ? job->cfg.race_gate_size : 30;
    size_t total = job->total.load();
    if (gate > total) gate = total;

    static const uint8_t kPreface[] = {
        'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n','\r','\n',
        'S','M','\r','\n','\r','\n'
    };
    if (!ssl_send_all(sc.ssl, kPreface, sizeof(kPreface), job->cfg.timeout_ms)) {
        diag::log_tagged("intruder", "run_h2_single_packet preface_send_failed");
        close_ssl(sc); h2_session_term(st);
        return;
    }

    diag::log_tagged_fmt("intruder", "run_h2_single_packet tls_ok total=%zu warmup=%zu gate=%zu", total, warmup, gate);
    if (warmup > 0) {
        diag::log_tagged_fmt("intruder", "run_h2_single_packet warmup_phase count=%zu", warmup);
        std::unordered_map<int32_t, std::pair<size_t, std::vector<std::string>>> warm_map;
        size_t w_used = warmup < total ? warmup : total;
        for (size_t i = 0; i < w_used; ++i) {
            auto payloads = it.resolve(i);
            std::vector<uint8_t> req =
                apply_payload_replacements(job->cfg.base_request, job->cfg.positions, payloads);
            std::string scheme = job->cfg.scheme.empty() ? "https" : job->cfg.scheme;
            parsed_h2_target_t p = parse_http1_for_h2(req, scheme, job->cfg.host);
            int32_t sid = h2_submit(st, p);
            if (sid >= 0) warm_map[sid] = { i, std::move(payloads) };
        }
        (void)nghttp2_session_send(st.session);
        if (!h2_flush_out(sc, st, job->cfg.timeout_ms)) {
            close_ssl(sc); h2_session_term(st);
            return;
        }
        h2_pump_session_input(sc, st, job->cfg.timeout_ms, true);
        for (auto& kv : warm_map) {
            auto& cap = st.streams[kv.first];
            result_t r;
            r.job_id = job->id;
            r.index = kv.second.first;
            r.payloads = kv.second.second;
            r.status_code = cap.status;
            r.response_size = cap.body.size();
            r.response_preview = preview_string(cap.body, 4096);
            r.response_raw = std::move(cap.body);
            if (cap.errored) {
                diag::log_tagged_fmt("intruder", "run_h2_single_packet warmup_errored sid=%d idx=%zu", kv.first, r.index);
                r.error = true; r.error_msg = "h2_warmup_errored"; job->errors.fetch_add(1);
            } else {
                diag::log_tagged_fmt("intruder", "run_h2_single_packet warmup_ok sid=%d idx=%zu status=%d", kv.first, r.index, r.status_code);
            }
            job->sent.fetch_add(1);
            store_result(*job, std::move(r));
            st.streams.erase(kv.first);
        }
        diag::log_tagged("intruder", "run_h2_single_packet warmup_phase_done");
    }

    std::unordered_map<int32_t, std::pair<size_t, std::vector<std::string>>> gate_map;
    size_t gate_start_idx = warmup;
    size_t gate_end_idx = gate_start_idx + gate;
    if (gate_end_idx > total) gate_end_idx = total;
    diag::log_tagged_fmt("intruder", "run_h2_single_packet gate_phase start=%zu end=%zu", gate_start_idx, gate_end_idx);
    for (size_t i = gate_start_idx; i < gate_end_idx; ++i) {
        auto payloads = it.resolve(i);
        std::vector<uint8_t> req =
            apply_payload_replacements(job->cfg.base_request, job->cfg.positions, payloads);
        std::string scheme = job->cfg.scheme.empty() ? "https" : job->cfg.scheme;
        parsed_h2_target_t p = parse_http1_for_h2(req, scheme, job->cfg.host);
        int32_t sid = h2_submit(st, p);
        if (sid < 0) {
            diag::log_tagged_fmt("intruder", "run_h2_single_packet gate_submit_failed idx=%zu", i);
            result_t r;
            r.job_id = job->id; r.index = i; r.payloads = payloads;
            r.error = true; r.error_msg = "h2_submit_failed";
            job->errors.fetch_add(1); job->sent.fetch_add(1);
            store_result(*job, std::move(r));
            continue;
        }
        gate_map[sid] = { i, std::move(payloads) };
    }
    diag::log_tagged_fmt("intruder", "run_h2_single_packet gate_submitted streams=%zu", gate_map.size());

    while (nghttp2_session_want_write(st.session)) {
        (void)nghttp2_session_send(st.session);
    }
    auto t_send_start = std::chrono::steady_clock::now();
    if (!st.pending_out.empty()) {
        diag::log_tagged_fmt("intruder", "run_h2_single_packet sending_gate_packet bytes=%zu streams=%zu",
            st.pending_out.size(), gate_map.size());
        if (!ssl_send_all(sc.ssl, st.pending_out.data(), st.pending_out.size(), job->cfg.timeout_ms)) {
            diag::log_tagged("intruder", "run_h2_single_packet gate_packet_send_failed");
            for (auto& kv : gate_map) {
                result_t r;
                r.job_id = job->id;
                r.index = kv.second.first;
                r.payloads = kv.second.second;
                r.error = true; r.error_msg = "h2_single_packet_send_failed";
                job->errors.fetch_add(1); job->sent.fetch_add(1);
                store_result(*job, std::move(r));
            }
            close_ssl(sc); h2_session_term(st);
            return;
        }
        st.pending_out.clear();
        diag::log_tagged("intruder", "run_h2_single_packet gate_packet_sent");
    }

    h2_pump_session_input(sc, st, job->cfg.timeout_ms, true);

    for (auto& kv : gate_map) {
        auto it_cap = st.streams.find(kv.first);
        result_t r;
        r.job_id = job->id;
        r.index = kv.second.first;
        r.payloads = kv.second.second;
        if (it_cap != st.streams.end()) {
            auto& cap = it_cap->second;
            r.status_code = cap.status;
            r.response_size = cap.body.size();
            r.response_preview = preview_string(cap.body, 4096);
            r.response_raw = std::move(cap.body);
            if (!cap.complete) {
                diag::log_tagged_fmt("intruder", "run_h2_single_packet gate_incomplete sid=%d idx=%zu", kv.first, r.index);
                r.error = true; r.error_msg = "h2_gate_incomplete"; job->errors.fetch_add(1);
            } else {
                diag::log_tagged_fmt("intruder", "run_h2_single_packet gate_ok sid=%d idx=%zu status=%d resp_size=%zu",
                    kv.first, r.index, r.status_code, r.response_size);
            }
        } else {
            diag::log_tagged_fmt("intruder", "run_h2_single_packet gate_stream_missing sid=%d idx=%zu", kv.first, r.index);
            r.error = true; r.error_msg = "h2_gate_stream_missing";
            job->errors.fetch_add(1);
        }
        auto t1 = std::chrono::steady_clock::now();
        r.latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t_send_start).count());
        job->sent.fetch_add(1);
        store_result(*job, std::move(r));
    }

    if (gate_end_idx < total) {
        for (size_t i = gate_end_idx; i < total && !job->cancel.load(); ++i) {
            auto payloads = it.resolve(i);
            std::vector<uint8_t> req =
                apply_payload_replacements(job->cfg.base_request, job->cfg.positions, payloads);
            std::string scheme = job->cfg.scheme.empty() ? "https" : job->cfg.scheme;
            parsed_h2_target_t p = parse_http1_for_h2(req, scheme, job->cfg.host);
            int32_t sid = h2_submit(st, p);
            (void)sid;
            (void)nghttp2_session_send(st.session);
            if (!h2_flush_out(sc, st, job->cfg.timeout_ms)) break;
            h2_pump_session_input(sc, st, job->cfg.timeout_ms, true);
            auto it_cap = st.streams.begin();
            if (it_cap != st.streams.end()) {
                auto& cap = it_cap->second;
                result_t r;
                r.job_id = job->id; r.index = i; r.payloads = std::move(payloads);
                r.status_code = cap.status;
                r.response_size = cap.body.size();
                r.response_preview = preview_string(cap.body, 4096);
                r.response_raw = std::move(cap.body);
                job->sent.fetch_add(1);
                store_result(*job, std::move(r));
                st.streams.erase(it_cap);
            }
        }
    }

    diag::log_tagged_fmt("intruder", "run_h2_single_packet complete job_id=%llu sent=%zu errors=%zu",
        static_cast<unsigned long long>(job->id), job->sent.load(), job->errors.load());
    close_ssl(sc); h2_session_term(st);
}

static void run_serial_h1(std::shared_ptr<job_t> job)
{
    diag::log_tagged_fmt("intruder", "run_serial_h1 job_id=%llu host=%s port=%u total=%zu",
        static_cast<unsigned long long>(job->id), job->cfg.host.c_str(), static_cast<unsigned>(job->cfg.port), job->total.load());
    payload_iter_t it;
    it.mode = job->cfg.attack_mode;
    it.positions = &job->cfg.positions;
    it.sets = &job->cfg.payload_sets;
    bool tls = (job->cfg.scheme == "https");

    size_t total = job->total.load();
    for (size_t i = 0; i < total && !job->cancel.load(); ++i) {
        if (job->cfg.requests_per_second_cap > 0) bucket_wait(job->bucket, job->cancel);
        if (job->cancel.load()) {
            diag::log_tagged_fmt("intruder", "run_serial_h1 cancelled at idx=%zu", i);
            break;
        }
        auto payloads = it.resolve(i);
        std::vector<uint8_t> req =
            apply_payload_replacements(job->cfg.base_request, job->cfg.positions, payloads);
        req = rewrite_content_length(req);
        result_t r;
        r.job_id = job->id; r.index = i; r.payloads = payloads;
        send_one_request_h1(job->cfg.host, job->cfg.port, tls, req, job->cfg, r);
        if (r.error) {
            diag::log_tagged_fmt("intruder", "run_serial_h1 error idx=%zu msg=%s", i, r.error_msg.c_str());
            job->errors.fetch_add(1);
        } else {
            diag::log_tagged_fmt("intruder", "run_serial_h1 ok idx=%zu status=%d resp_size=%zu latency_ms=%llu",
                i, r.status_code, r.response_size, static_cast<unsigned long long>(r.latency_ms));
        }
        job->sent.fetch_add(1);
        store_result(*job, std::move(r));
    }
    diag::log_tagged_fmt("intruder", "run_serial_h1 complete job_id=%llu sent=%zu errors=%zu",
        static_cast<unsigned long long>(job->id), job->sent.load(), job->errors.load());
}

static void job_main(std::shared_ptr<job_t> job)
{
    diag::log_tagged_fmt("intruder", "job_main start job_id=%llu host=%s port=%u scheme=%s attack=%s engine=%s",
        static_cast<unsigned long long>(job->id),
        job->cfg.host.c_str(),
        static_cast<unsigned>(job->cfg.port),
        job->cfg.scheme.c_str(),
        attack_mode_name(job->cfg.attack_mode),
        engine_mode_name(job->cfg.engine_mode));
    job->started_ms.store(unix_ms_now());

    payload_iter_t pit;
    pit.mode = job->cfg.attack_mode;
    pit.positions = &job->cfg.positions;
    pit.sets = &job->cfg.payload_sets;
    pit.total = compute_total(pit, job->cfg);
    job->total.store(pit.total);
    diag::log_tagged_fmt("intruder", "job_main total=%zu rps_cap=%zu", pit.total, job->cfg.requests_per_second_cap);

    if (job->cfg.requests_per_second_cap > 0) {
        bucket_init(job->bucket, job->cfg.requests_per_second_cap);
        diag::log_tagged_fmt("intruder", "job_main rps_bucket_init rate=%zu", job->cfg.requests_per_second_cap);
    }

    switch (job->cfg.engine_mode) {
        case engine_mode_t::http1_serial: {
            diag::log_tagged_fmt("intruder", "job_main dispatching http1_serial job_id=%llu", static_cast<unsigned long long>(job->id));
            run_serial_h1(job);
            break;
        }
        case engine_mode_t::http1_pipelined: {
            diag::log_tagged_fmt("intruder", "job_main dispatching http1_pipelined job_id=%llu", static_cast<unsigned long long>(job->id));
            run_pipelined_h1(job);
            break;
        }
        case engine_mode_t::http1_pooled: {
            size_t pool = job->cfg.concurrency > 0 ? job->cfg.concurrency : 16;
            if (pool > 128) pool = 128;
            diag::log_tagged_fmt("intruder", "job_main dispatching http1_pooled pool=%zu job_id=%llu", pool, static_cast<unsigned long long>(job->id));
            if (pool <= 1) {
                worker_pooled_h1(job);
            } else {
                std::vector<std::thread> ws;
                try {
                    ws.reserve(pool);
                    for (size_t i = 0; i < pool; ++i) {
                        ws.emplace_back([job]() { worker_pooled_h1(job); });
                    }
                } catch (const std::exception& ex) {
                    set_err(std::string("intruder: pooled worker start failed: ") + ex.what());
                    diag::log_tagged_fmt("intruder", "pooled_worker_start_failed job_id=%llu started=%zu err=%s",
                        static_cast<unsigned long long>(job->id), ws.size(), ex.what());
                    job->running.store(false);
                } catch (...) {
                    set_err("intruder: pooled worker start failed");
                    diag::log_tagged_fmt("intruder", "pooled_worker_start_failed job_id=%llu started=%zu",
                        static_cast<unsigned long long>(job->id), ws.size());
                    job->running.store(false);
                }
                for (auto& t : ws) if (t.joinable()) t.join();
            }
            break;
        }
        case engine_mode_t::http2_multiplexed: {
            diag::log_tagged_fmt("intruder", "job_main dispatching http2_multiplexed job_id=%llu", static_cast<unsigned long long>(job->id));
            run_h2_multiplexed(job);
            break;
        }
        case engine_mode_t::http2_single_packet: {
            diag::log_tagged_fmt("intruder", "job_main dispatching http2_single_packet job_id=%llu", static_cast<unsigned long long>(job->id));
            run_h2_single_packet(job);
            break;
        }
    }

    job->finished_ms.store(unix_ms_now());
    job->running.store(false);
    diag::log_tagged_fmt("intruder", "job_main done job_id=%llu sent=%zu errors=%zu total=%zu",
        static_cast<unsigned long long>(job->id), job->sent.load(), job->errors.load(), job->total.load());
}

}

uint64_t start(config_t cfg)
{
    diag::log_tagged_fmt("intruder", "start host=%s port=%u scheme=%s attack=%s engine=%s positions=%zu sets=%zu",
        cfg.host.c_str(), static_cast<unsigned>(cfg.port), cfg.scheme.c_str(),
        attack_mode_name(cfg.attack_mode), engine_mode_name(cfg.engine_mode),
        cfg.positions.size(), cfg.payload_sets.size());
    if (cfg.host.empty() || cfg.port == 0) {
        diag::log_tagged("intruder", "start rejected invalid_host_or_port");
        set_err("intruder: invalid host/port");
        return 0;
    }
    if (cfg.base_request.empty()) {
        diag::log_tagged("intruder", "start rejected empty_base_request");
        set_err("intruder: empty base_request");
        return 0;
    }
    if (cfg.scheme.empty()) cfg.scheme = (cfg.port == 443) ? "https" : "http";
    if (cfg.engine_mode == engine_mode_t::http2_multiplexed
        || cfg.engine_mode == engine_mode_t::http2_single_packet) {
        cfg.scheme = "https";
        diag::log_tagged("intruder", "start forced scheme=https for h2 engine");
    }
    if (cfg.payload_sets.empty()) {
        cfg.payload_sets.push_back({ std::string() });
        diag::log_tagged("intruder", "start added default_empty_payload_set");
    }
    if (cfg.positions.empty() && cfg.attack_mode != attack_mode_t::turbo) {
        cfg.positions.push_back({ 0, 0 });
        diag::log_tagged("intruder", "start added default_position_0");
    }
    if (cfg.concurrency == 0) cfg.concurrency = 32;
    if (cfg.timeout_ms <= 0) cfg.timeout_ms = 15000;
    if (cfg.max_response_body_bytes == 0) cfg.max_response_body_bytes = 65536;

    auto job = std::make_shared<job_t>();
    job->id = reg().next_id.fetch_add(1);
    job->cfg = std::move(cfg);
    job->running.store(true);

    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().jobs[job->id] = job;
    }

    diag::log_tagged_fmt("intruder", "start job_id=%llu concurrency=%zu timeout_ms=%d max_resp_bytes=%zu",
        static_cast<unsigned long long>(job->id), job->cfg.concurrency,
        job->cfg.timeout_ms, job->cfg.max_response_body_bytes);
    const bool posted = work_queue::post([job]() {
        try {
            job_main(job);
        } catch (const std::exception& ex) {
            set_err(std::string("intruder: job worker exception: ") + ex.what());
            diag::log_tagged_fmt("intruder", "job_worker_exception job_id=%llu err=%s",
                static_cast<unsigned long long>(job->id), ex.what());
            job->running.store(false);
        } catch (...) {
            set_err("intruder: job worker exception");
            diag::log_tagged_fmt("intruder", "job_worker_exception job_id=%llu",
                static_cast<unsigned long long>(job->id));
            job->running.store(false);
        }
    });
    if (!posted) {
        diag::log_tagged_fmt("intruder", "start_work_queue_rejected job_id=%llu",
            static_cast<unsigned long long>(job->id));
        set_err("intruder: work queue rejected job start");
        job->running.store(false);
        std::lock_guard<std::mutex> lk(reg().mtx);
        reg().jobs.erase(job->id);
        return 0;
    }
    return job->id;
}

bool stop(uint64_t job_id)
{
    diag::log_tagged_fmt("intruder", "stop job_id=%llu", static_cast<unsigned long long>(job_id));
    std::shared_ptr<job_t> job;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().jobs.find(job_id);
        if (it == reg().jobs.end()) {
            diag::log_tagged_fmt("intruder", "stop not_found job_id=%llu", static_cast<unsigned long long>(job_id));
            return false;
        }
        job = it->second;
    }
    job->cancel.store(true);
    diag::log_tagged_fmt("intruder", "stop cancel_set job_id=%llu", static_cast<unsigned long long>(job_id));
    return true;
}

status_t status(uint64_t job_id)
{
    diag::log_tagged_fmt("intruder", "status job_id=%llu", static_cast<unsigned long long>(job_id));
    status_t s;
    std::shared_ptr<job_t> job;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().jobs.find(job_id);
        if (it == reg().jobs.end()) {
            diag::log_tagged_fmt("intruder", "status not_found job_id=%llu", static_cast<unsigned long long>(job_id));
            return s;
        }
        job = it->second;
    }
    s.job_id = job->id;
    s.total = job->total.load();
    s.sent = job->sent.load();
    s.errors = job->errors.load();
    s.running = job->running.load();
    s.started_unix_ms = job->started_ms.load();
    s.finished_unix_ms = job->finished_ms.load();
    uint64_t elapsed = 0;
    if (s.finished_unix_ms > 0 && s.started_unix_ms > 0 && s.finished_unix_ms > s.started_unix_ms) {
        elapsed = s.finished_unix_ms - s.started_unix_ms;
    } else if (s.started_unix_ms > 0) {
        elapsed = unix_ms_now() - s.started_unix_ms;
    }
    if (elapsed > 0) s.current_rps = static_cast<double>(s.sent) * 1000.0 / static_cast<double>(elapsed);
    diag::log_tagged_fmt("intruder", "status result job_id=%llu running=%d sent=%zu total=%zu errors=%zu rps=%.1f",
        static_cast<unsigned long long>(job_id), s.running ? 1 : 0, s.sent, s.total, s.errors, s.current_rps);
    return s;
}

std::vector<result_t> results(uint64_t job_id, size_t start_idx, size_t max)
{
    diag::log_tagged_fmt("intruder", "results job_id=%llu start_idx=%zu max=%zu",
        static_cast<unsigned long long>(job_id), start_idx, max);
    std::vector<result_t> out;
    std::shared_ptr<job_t> job;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        auto it = reg().jobs.find(job_id);
        if (it == reg().jobs.end()) {
            diag::log_tagged_fmt("intruder", "results not_found job_id=%llu", static_cast<unsigned long long>(job_id));
            return out;
        }
        job = it->second;
    }
    std::lock_guard<std::mutex> lk(job->results_mtx);
    if (start_idx >= job->results.size()) {
        diag::log_tagged_fmt("intruder", "results start_idx_oob start_idx=%zu total_results=%zu", start_idx, job->results.size());
        return out;
    }
    size_t available = job->results.size() - start_idx;
    size_t take = (max == 0) ? available : (max < available ? max : available);
    out.reserve(take);
    for (size_t i = 0; i < take; ++i) {
        out.push_back(job->results[start_idx + i]);
    }
    diag::log_tagged_fmt("intruder", "results returning %zu results job_id=%llu", take, static_cast<unsigned long long>(job_id));
    return out;
}

bool clear(uint64_t job_id)
{
    diag::log_tagged_fmt("intruder", "clear job_id=%llu", static_cast<unsigned long long>(job_id));
    std::lock_guard<std::mutex> lk(reg().mtx);
    auto it = reg().jobs.find(job_id);
    if (it == reg().jobs.end()) {
        diag::log_tagged_fmt("intruder", "clear not_found job_id=%llu", static_cast<unsigned long long>(job_id));
        return false;
    }
    if (it->second->running.load()) {
        it->second->cancel.store(true);
        diag::log_tagged_fmt("intruder", "clear cancel_running job_id=%llu", static_cast<unsigned long long>(job_id));
    }
    reg().jobs.erase(it);
    diag::log_tagged_fmt("intruder", "clear erased job_id=%llu", static_cast<unsigned long long>(job_id));
    return true;
}

std::vector<status_t> list_jobs()
{
    std::vector<status_t> out;
    std::vector<std::shared_ptr<job_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(reg().mtx);
        snapshot.reserve(reg().jobs.size());
        for (auto& kv : reg().jobs) snapshot.push_back(kv.second);
    }
    diag::log_tagged_fmt("intruder", "list_jobs count=%zu", snapshot.size());
    out.reserve(snapshot.size());
    for (auto& j : snapshot) {
        out.push_back(status(j->id));
    }
    return out;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("intruder", "last_error=%s", e.c_str());
    return e;
}

const char* attack_mode_name(attack_mode_t m)
{
    switch (m) {
        case attack_mode_t::sniper:        return "sniper";
        case attack_mode_t::battering_ram: return "battering_ram";
        case attack_mode_t::pitchfork:     return "pitchfork";
        case attack_mode_t::clusterbomb:   return "clusterbomb";
        case attack_mode_t::turbo:         return "turbo";
        case attack_mode_t::race:          return "race";
    }
    return "unknown";
}

const char* engine_mode_name(engine_mode_t m)
{
    switch (m) {
        case engine_mode_t::http1_serial:        return "http1_serial";
        case engine_mode_t::http1_pipelined:     return "http1_pipelined";
        case engine_mode_t::http1_pooled:        return "http1_pooled";
        case engine_mode_t::http2_multiplexed:   return "http2_multiplexed";
        case engine_mode_t::http2_single_packet: return "http2_single_packet";
    }
    return "unknown";
}

bool parse_attack_mode(const std::string& s, attack_mode_t& out)
{
    diag::log_tagged_fmt("intruder", "parse_attack_mode input=%s", s.c_str());
    if (s == "sniper") { out = attack_mode_t::sniper; diag::log_tagged("intruder", "parse_attack_mode result=sniper"); return true; }
    if (s == "battering_ram" || s == "ram") { out = attack_mode_t::battering_ram; diag::log_tagged("intruder", "parse_attack_mode result=battering_ram"); return true; }
    if (s == "pitchfork") { out = attack_mode_t::pitchfork; diag::log_tagged("intruder", "parse_attack_mode result=pitchfork"); return true; }
    if (s == "clusterbomb" || s == "cluster_bomb") { out = attack_mode_t::clusterbomb; diag::log_tagged("intruder", "parse_attack_mode result=clusterbomb"); return true; }
    if (s == "turbo") { out = attack_mode_t::turbo; diag::log_tagged("intruder", "parse_attack_mode result=turbo"); return true; }
    if (s == "race") { out = attack_mode_t::race; diag::log_tagged("intruder", "parse_attack_mode result=race"); return true; }
    diag::log_tagged_fmt("intruder", "parse_attack_mode unknown=%s", s.c_str());
    return false;
}

bool parse_engine_mode(const std::string& s, engine_mode_t& out)
{
    diag::log_tagged_fmt("intruder", "parse_engine_mode input=%s", s.c_str());
    if (s == "http1_serial" || s == "h1_serial") { out = engine_mode_t::http1_serial; diag::log_tagged("intruder", "parse_engine_mode result=http1_serial"); return true; }
    if (s == "http1_pipelined" || s == "h1_pipelined") { out = engine_mode_t::http1_pipelined; diag::log_tagged("intruder", "parse_engine_mode result=http1_pipelined"); return true; }
    if (s == "http1_pooled" || s == "h1_pooled") { out = engine_mode_t::http1_pooled; diag::log_tagged("intruder", "parse_engine_mode result=http1_pooled"); return true; }
    if (s == "http2_multiplexed" || s == "h2_multiplexed" || s == "h2") { out = engine_mode_t::http2_multiplexed; diag::log_tagged("intruder", "parse_engine_mode result=http2_multiplexed"); return true; }
    if (s == "http2_single_packet" || s == "h2_single_packet" || s == "single_packet") { out = engine_mode_t::http2_single_packet; diag::log_tagged("intruder", "parse_engine_mode result=http2_single_packet"); return true; }
    diag::log_tagged_fmt("intruder", "parse_engine_mode unknown=%s", s.c_str());
    return false;
}

}
}
}
