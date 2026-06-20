#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "h2_editor.hpp"

#include "../../../helpers/diag_log.hpp"
#include "../protocol_parser.hpp"

#ifdef _WIN32
#  include <BaseTsd.h>
   typedef SSIZE_T ssize_t;
#endif

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace aida {
namespace burp {
namespace h2_editor {

namespace {

static std::mutex&  err_mtx() { static std::mutex m; return m; }
static std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& v)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = v;
}

struct ctx_holder_t { SSL_CTX* ctx = nullptr; std::mutex mtx; };

static SSL_CTX* ensure_ctx()
{
    static ctx_holder_t h;
    std::lock_guard<std::mutex> lk(h.mtx);
    if (h.ctx) return h.ctx;
    static std::atomic<bool> init{false};
    bool e = false;
    if (init.compare_exchange_strong(e, true)) {
        SSL_library_init();
        SSL_load_error_strings();
    }
    const SSL_METHOD* m = TLS_client_method();
    h.ctx = SSL_CTX_new(m);
    if (!h.ctx) return nullptr;
    SSL_CTX_set_min_proto_version(h.ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(h.ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_options(h.ctx, SSL_OP_NO_COMPRESSION);
    return h.ctx;
}

std::string openssl_error_queue()
{
    std::ostringstream os;
    bool first = true;
    unsigned long e = 0;
    while ((e = ERR_get_error()) != 0) {
        char buf[256] = {};
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!first) os << "|";
        first = false;
        os << buf;
    }
    return os.str();
}

std::string bytes_hex(const unsigned char* data, unsigned int len)
{
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(h[(data[i] >> 4) & 0xf]);
        out.push_back(h[data[i] & 0xf]);
    }
    return out;
}

std::string alpn_string(const unsigned char* data, unsigned int len)
{
    std::string out;
    out.reserve(len);
    for (unsigned int i = 0; i < len; ++i) {
        unsigned char c = data[i];
        out.push_back((c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.');
    }
    return out;
}

std::string sockaddr_to_text(const sockaddr* sa)
{
    char buf[INET6_ADDRSTRLEN] = {};
    if (!sa) return {};
    if (sa->sa_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        if (inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf))) return buf;
    } else if (sa->sa_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
        if (inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf))) return buf;
    }
    return {};
}

struct tcp_connect_result_t
{
    SOCKET sock = INVALID_SOCKET;
    int wsa_error = 0;
    int poll_rc = 0;
    short revents = 0;
    int poll_wsa = 0;
    std::string stage;
    std::string ip;
    std::string family;
};

static tcp_connect_result_t tcp_connect(const std::string& host, uint16_t port, int timeout_ms)
{
    tcp_connect_result_t out;
    out.stage = "getaddrinfo";
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ports[16];
    snprintf(ports, sizeof(ports), "%u", static_cast<unsigned>(port));
    addrinfo* res = nullptr;
    int gai = getaddrinfo(host.c_str(), ports, &hints, &res);
    if (gai != 0 || !res) {
        out.wsa_error = gai;
        return out;
    }
    out.ip = sockaddr_to_text(res->ai_addr);
    out.family = res->ai_family == AF_INET ? "AF_INET" : (res->ai_family == AF_INET6 ? "AF_INET6" : "AF_OTHER");
    out.stage = "socket";
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        out.wsa_error = WSAGetLastError();
        freeaddrinfo(res);
        return out;
    }
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    out.stage = "connect";
    int cr = connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    if (cr == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        out.wsa_error = WSAGetLastError();
        closesocket(s); freeaddrinfo(res); return out;
    }
    WSAPOLLFD pfd{}; pfd.fd = s; pfd.events = POLLOUT;
    out.stage = "poll_connect";
    int pr = WSAPoll(&pfd, 1, timeout_ms);
    out.poll_rc = pr;
    out.revents = pfd.revents;
    if (pr <= 0) {
        out.poll_wsa = WSAGetLastError();
        out.stage = pr == 0 ? "poll_connect_timeout" : "poll_connect_failed";
        closesocket(s); freeaddrinfo(res); return out;
    }
    int err = 0; int sz = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &sz);
    if (err != 0) {
        out.wsa_error = err;
        out.stage = "connect_so_error";
        closesocket(s); freeaddrinfo(res); return out;
    }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    DWORD tmo = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    BOOL nd = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nd), sizeof(nd));
    freeaddrinfo(res);
    out.stage = "tcp_connected";
    out.sock = s;
    return out;
}

struct conn_t
{
    SOCKET sock = INVALID_SOCKET;
    SSL*   ssl = nullptr;
};

static void close_conn(conn_t& c)
{
    if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); c.ssl = nullptr; }
    if (c.sock != INVALID_SOCKET) { shutdown(c.sock, SD_BOTH); closesocket(c.sock); c.sock = INVALID_SOCKET; }
}

static bool tls_connect(conn_t& c, const std::string& host, uint16_t port, int timeout_ms, std::string& error_msg)
{
    SSL_CTX* ctx = ensure_ctx();
    if (!ctx) {
        error_msg = "ssl_ctx_unavailable: " + openssl_error_queue();
        set_err(error_msg);
        return false;
    }
    auto tcp = tcp_connect(host, port, timeout_ms);
    diag::log_tagged_fmt("h2_edit", "tcp_connect_result host=%s port=%u stage=%s socket=%llu wsa_error=%d poll_rc=%d revents=0x%04X poll_wsa=%d family=%s ip=%s",
        host.c_str(), static_cast<unsigned>(port), tcp.stage.c_str(), static_cast<unsigned long long>(tcp.sock),
        tcp.wsa_error, tcp.poll_rc, static_cast<unsigned>(tcp.revents), tcp.poll_wsa, tcp.family.c_str(), tcp.ip.c_str());
    c.sock = tcp.sock;
    if (c.sock == INVALID_SOCKET) {
        std::ostringstream os;
        os << "tcp_connect_failed stage=" << tcp.stage
           << " wsa_error=" << tcp.wsa_error
           << " poll_rc=" << tcp.poll_rc
           << " revents=0x" << std::hex << static_cast<unsigned>(tcp.revents) << std::dec
           << " poll_wsa=" << tcp.poll_wsa
           << " ip=" << tcp.ip;
        error_msg = os.str();
        set_err(error_msg);
        return false;
    }
    c.ssl = SSL_new(ctx);
    if (!c.ssl) {
        error_msg = "ssl_new_failed: " + openssl_error_queue();
        set_err(error_msg);
        close_conn(c);
        return false;
    }
    SSL_set_fd(c.ssl, static_cast<int>(c.sock));
    SSL_set_tlsext_host_name(c.ssl, host.c_str());
    static const uint8_t alpn[] = { 0x02, 'h', '2' };
    ERR_clear_error();
    int alpn_rc = SSL_set_alpn_protos(c.ssl, alpn, sizeof(alpn));
    diag::log_tagged_fmt("h2_edit", "tls_alpn_config rc=%d requested=%s requested_hex=%s openssl_errors=%s",
        alpn_rc, "h2", bytes_hex(alpn, sizeof(alpn)).c_str(), openssl_error_queue().c_str());
    if (alpn_rc != 0) {
        error_msg = "alpn_config_failed";
        set_err(error_msg);
        close_conn(c);
        return false;
    }

    u_long nb = 1; ioctlsocket(c.sock, FIONBIO, &nb);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    int last_ssl_err = 0;
    int last_poll_rc = 0;
    short last_revents = 0;
    int last_poll_wsa = 0;
    std::string last_stage = "ssl_connect";
    while (true) {
        ERR_clear_error();
        int r = SSL_connect(c.ssl);
        if (r == 1) break;
        int err = SSL_get_error(c.ssl, r);
        last_ssl_err = err;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                error_msg = std::string("tls_handshake_timeout stage=") + last_stage + " ssl_error=" + std::to_string(last_ssl_err);
                set_err(error_msg);
                diag::log_tagged_fmt("h2_edit", "tls_handshake_timeout ssl_error=%d", last_ssl_err);
                close_conn(c);
                return false;
            }
            int rem = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            WSAPOLLFD pfd{}; pfd.fd = c.sock;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
            last_stage = (err == SSL_ERROR_WANT_WRITE) ? "ssl_want_write_poll" : "ssl_want_read_poll";
            int pr = WSAPoll(&pfd, 1, rem);
            last_poll_rc = pr;
            last_revents = pfd.revents;
            if (pr <= 0) {
                last_poll_wsa = WSAGetLastError();
                std::ostringstream os;
                os << "tls_handshake_poll_failed stage=" << last_stage
                   << " ssl_error=" << last_ssl_err
                   << " poll_rc=" << last_poll_rc
                   << " revents=0x" << std::hex << static_cast<unsigned>(last_revents) << std::dec
                   << " poll_wsa=" << last_poll_wsa;
                error_msg = os.str();
                set_err(error_msg);
                diag::log_tagged_fmt("h2_edit", "tls_handshake_poll_failed stage=%s ssl_error=%d poll_rc=%d revents=0x%04X poll_wsa=%d",
                    last_stage.c_str(), last_ssl_err, last_poll_rc, static_cast<unsigned>(last_revents), last_poll_wsa);
                close_conn(c);
                return false;
            }
            continue;
        }
        std::string ossl = openssl_error_queue();
        std::ostringstream os;
        os << "tls_handshake_failed ssl_error=" << err << " openssl_errors=" << ossl;
        error_msg = os.str();
        set_err(error_msg);
        diag::log_tagged_fmt("h2_edit", "tls_handshake_failed ssl_error=%d openssl_errors=%s", err, ossl.c_str());
        close_conn(c);
        return false;
    }
    nb = 0; ioctlsocket(c.sock, FIONBIO, &nb);
    const SSL_CIPHER* cipher = SSL_get_current_cipher(c.ssl);
    const char* cipher_name = cipher ? SSL_CIPHER_get_name(cipher) : "";
    const char* tls_version = SSL_get_version(c.ssl);

    const unsigned char* sel = nullptr;
    unsigned int sel_len = 0;
    SSL_get0_alpn_selected(c.ssl, &sel, &sel_len);
    std::string selected = sel ? alpn_string(sel, sel_len) : std::string();
    std::string selected_hex = sel ? bytes_hex(sel, sel_len) : std::string();
    diag::log_tagged_fmt("h2_edit", "tls_handshake_ok host=%s tls_version=%s cipher=%s selected_alpn=%s selected_alpn_hex=%s selected_alpn_len=%u",
        host.c_str(), tls_version ? tls_version : "", cipher_name, selected.c_str(), selected_hex.c_str(), sel_len);
    if (!(sel && sel_len == 2 && sel[0] == 'h' && sel[1] == '2')) {
        if (!sel || sel_len == 0) error_msg = "alpn_not_selected";
        else error_msg = "wrong_alpn_selected selected=" + selected + " selected_hex=" + selected_hex;
        set_err(error_msg);
        close_conn(c);
        return false;
    }
    return true;
}

static bool ssl_send_all(SSL* ssl, const uint8_t* d, size_t n, int timeout_ms)
{
    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t sent = 0;
    while (sent < n) {
        int rv = SSL_write(ssl, d + sent, static_cast<int>(n - sent));
        if (rv > 0) { sent += static_cast<size_t>(rv); continue; }
        int err = SSL_get_error(ssl, rv);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return false;
            int rem = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            WSAPOLLFD pfd{}; pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
            if (WSAPoll(&pfd, 1, rem) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

static int ssl_recv_some(SSL* ssl, uint8_t* d, int n, int timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    SOCKET fd = static_cast<SOCKET>(SSL_get_fd(ssl));
    while (true) {
        int rv = SSL_read(ssl, d, n);
        if (rv > 0) return rv;
        int err = SSL_get_error(ssl, rv);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return -1;
            int rem = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            WSAPOLLFD pfd{}; pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
            if (WSAPoll(&pfd, 1, rem) <= 0) return -1;
            continue;
        }
        if (rv == 0) return 0;
        return -1;
    }
}

struct stream_cap_t
{
    int                                              status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t>                             body;
    bool                                             complete = false;
    bool                                             errored = false;
    size_t                                           body_cap = 4 * 1024 * 1024;
};

struct session_state_t
{
    nghttp2_session*                            session = nullptr;
    std::unordered_map<int32_t, stream_cap_t>   streams;
    std::vector<uint8_t>                        out_buf;
    std::atomic<bool>                           goaway{false};
    uint64_t                                    frames_seen = 0;
    uint64_t                                    headers_seen = 0;
    uint64_t                                    data_chunks_seen = 0;
};

static ssize_t s_send_cb(nghttp2_session*, const uint8_t* data, size_t length, int, void* ud)
{
    auto* st = static_cast<session_state_t*>(ud);
    st->out_buf.insert(st->out_buf.end(), data, data + length);
    return static_cast<ssize_t>(length);
}

static int s_on_header_cb(nghttp2_session*, const nghttp2_frame* frame,
                          const uint8_t* name, size_t nl,
                          const uint8_t* value, size_t vl, uint8_t, void* ud)
{
    auto* st = static_cast<session_state_t*>(ud);
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    auto& cap = st->streams[frame->hd.stream_id];
    std::string n(reinterpret_cast<const char*>(name), nl);
    std::string v(reinterpret_cast<const char*>(value), vl);
    if (n == ":status") cap.status = atoi(v.c_str());
    else cap.headers.push_back({ n, v });
    ++st->headers_seen;
    diag::log_tagged_fmt("h2_edit",
        "recv_header sid=%d name=%s value_len=%zu status=%d total_headers=%llu",
        frame->hd.stream_id,
        n.c_str(),
        v.size(),
        cap.status,
        static_cast<unsigned long long>(st->headers_seen));
    return 0;
}

static int s_on_data_cb(nghttp2_session*, uint8_t, int32_t sid,
                        const uint8_t* data, size_t len, void* ud)
{
    auto* st = static_cast<session_state_t*>(ud);
    auto it = st->streams.find(sid);
    if (it == st->streams.end()) return 0;
    auto& cap = it->second;
    size_t room = cap.body_cap > cap.body.size() ? cap.body_cap - cap.body.size() : 0;
    size_t take = len < room ? len : room;
    if (take > 0) cap.body.insert(cap.body.end(), data, data + take);
    ++st->data_chunks_seen;
    diag::log_tagged_fmt("h2_edit",
        "recv_data sid=%d len=%zu take=%zu body=%zu chunks=%llu",
        sid, len, take, cap.body.size(),
        static_cast<unsigned long long>(st->data_chunks_seen));
    return 0;
}

static int s_on_frame_cb(nghttp2_session*, const nghttp2_frame* frame, void* ud)
{
    auto* st = static_cast<session_state_t*>(ud);
    ++st->frames_seen;
    diag::log_tagged_fmt("h2_edit",
        "recv_frame type=%u flags=0x%02x sid=%d len=%u frames=%llu",
        static_cast<unsigned>(frame->hd.type),
        static_cast<unsigned>(frame->hd.flags),
        frame->hd.stream_id,
        static_cast<unsigned>(frame->hd.length),
        static_cast<unsigned long long>(st->frames_seen));
    if (frame->hd.type == NGHTTP2_GOAWAY) { st->goaway.store(true); return 0; }
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA)
        && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        auto it = st->streams.find(frame->hd.stream_id);
        if (it != st->streams.end()) it->second.complete = true;
    }
    return 0;
}

static int s_on_close_cb(nghttp2_session*, int32_t sid, uint32_t ec, void* ud)
{
    auto* st = static_cast<session_state_t*>(ud);
    auto it = st->streams.find(sid);
    if (it != st->streams.end()) {
        if (ec != 0) it->second.errored = true;
        it->second.complete = true;
    }
    diag::log_tagged_fmt("h2_edit",
        "stream_close sid=%d ec=%u found=%d",
        sid, ec, it != st->streams.end() ? 1 : 0);
    return 0;
}

std::string path_without_query(std::string path)
{
    size_t q = path.find('?');
    size_t f = path.find('#');
    size_t end = path.size();
    if (q != std::string::npos) end = q;
    if (f != std::string::npos && f < end) end = f;
    path.resize(end);
    if (path.empty()) path = "/";
    if (path.size() > 240)
    {
        path.resize(240);
        path += "...";
    }
    return path;
}

}

std::vector<uint8_t> encode_frame(const frame_t& f)
{
    diag::log_tagged_fmt("h2_edit", "encode_frame entry type=0x%02x flags=0x%02x stream=%u payload=%zu",
        static_cast<unsigned>(f.type), static_cast<unsigned>(f.flags),
        static_cast<unsigned>(f.stream_id), f.payload.size());
    std::vector<uint8_t> out;
    out.reserve(9 + f.payload.size());
    uint32_t len = static_cast<uint32_t>(f.payload.size()) & 0xFFFFFFu;
    out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(len & 0xFF));
    out.push_back(f.type);
    out.push_back(f.flags);
    uint32_t stream = f.stream_id & 0x7FFFFFFFu;
    if (f.r_bit) stream |= 0x80000000u;
    out.push_back(static_cast<uint8_t>((stream >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((stream >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((stream >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(stream & 0xFF));
    out.insert(out.end(), f.payload.begin(), f.payload.end());
    return out;
}

bool decode_frames(const std::vector<uint8_t>& data, std::vector<frame_t>& out)
{
    diag::log_tagged_fmt("h2_edit", "decode_frames entry data_len=%zu", data.size());
    out.clear();
    size_t i = 0;
    while (i + 9 <= data.size()) {
        frame_t f;
        f.length = (static_cast<uint32_t>(data[i]) << 16)
                 | (static_cast<uint32_t>(data[i + 1]) << 8)
                 | static_cast<uint32_t>(data[i + 2]);
        f.type  = data[i + 3];
        f.flags = data[i + 4];
        uint32_t sid = (static_cast<uint32_t>(data[i + 5]) << 24)
                     | (static_cast<uint32_t>(data[i + 6]) << 16)
                     | (static_cast<uint32_t>(data[i + 7]) << 8)
                     | static_cast<uint32_t>(data[i + 8]);
        f.r_bit = (sid & 0x80000000u) != 0;
        f.stream_id = sid & 0x7FFFFFFFu;
        if (i + 9 + f.length > data.size()) return false;
        f.payload.assign(data.begin() + i + 9, data.begin() + i + 9 + f.length);
        out.push_back(std::move(f));
        i += 9 + f.length;
    }
    diag::log_tagged_fmt("h2_edit", "decode_frames done frames=%zu", out.size());
    return true;
}

response_t send(const request_t& req)
{
    const std::string safe_path = path_without_query(req.pseudo.path.empty() ? std::string("/") : req.pseudo.path);
    diag::log_tagged_fmt("h2_edit", "send entry host=%s port=%u method=%s path=%s query=%d body=%zu use_raw=%d raw_frames=%zu timeout_ms=%d",
        req.host.c_str(), static_cast<unsigned>(req.port),
        req.pseudo.method.c_str(), safe_path.c_str(), (int)(req.pseudo.path.find('?') != std::string::npos),
        req.body.size(), static_cast<int>(req.use_raw_frames), req.raw_frames.size(), req.timeout_ms);
    response_t r;
    conn_t c;
    diag::log_tagged_fmt("h2_edit", "send tls_connecting host=%s port=%u", req.host.c_str(), static_cast<unsigned>(req.port));
    std::string connect_error;
    if (!tls_connect(c, req.host, req.port, req.timeout_ms, connect_error)) {
        diag::log_tagged_fmt("h2_edit", "send connect_failed host=%s port=%u error=%s",
            req.host.c_str(), static_cast<unsigned>(req.port), connect_error.c_str());
        r.error_msg = connect_error.empty() ? "connect_failed" : connect_error;
        return r;
    }
    diag::log_tagged_fmt("h2_edit", "send tls_ok host=%s", req.host.c_str());

    if (req.use_raw_frames) {
        static const uint8_t kPreface[] = {
            'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n','\r','\n',
            'S','M','\r','\n','\r','\n'
        };
        diag::log_tagged_fmt("h2_edit", "send raw_frames_sending_preface");
        if (!ssl_send_all(c.ssl, kPreface, sizeof(kPreface), req.timeout_ms)) {
            diag::log_tagged_fmt("h2_edit", "send raw_preface_send_failed host=%s", req.host.c_str());
            r.error_msg = "preface_send_failed";
            close_conn(c);
            return r;
        }
        r.raw_wire_out.insert(r.raw_wire_out.end(), kPreface, kPreface + sizeof(kPreface));
        diag::log_tagged_fmt("h2_edit", "send raw_preface_ok");
        diag::log_tagged_fmt("h2_edit", "send raw_frames_mode frames=%zu", req.raw_frames.size());
        for (auto& f : req.raw_frames) {
            std::vector<uint8_t> enc = encode_frame(f);
            r.raw_wire_out.insert(r.raw_wire_out.end(), enc.begin(), enc.end());
            if (!ssl_send_all(c.ssl, enc.data(), enc.size(), req.timeout_ms)) {
                diag::log_tagged_fmt("h2_edit", "send raw_frame_send_failed type=0x%02x", static_cast<unsigned>(f.type));
                r.error_msg = "raw_frame_send_failed";
                close_conn(c);
                return r;
            }
        }
        diag::log_tagged_fmt("h2_edit", "send raw_frames_sent reading_response");
        auto t0 = std::chrono::steady_clock::now();
        uint8_t tmp[8192];
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(req.timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            int rem = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
            if (rem <= 0) break;
            int n = ssl_recv_some(c.ssl, tmp, sizeof(tmp), rem);
            if (n <= 0) break;
            r.raw_wire_in.insert(r.raw_wire_in.end(), tmp, tmp + n);
            if (r.raw_wire_in.size() > 256 * 1024) break;
        }
        auto t1 = std::chrono::steady_clock::now();
        r.latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        r.ok = !r.raw_wire_in.empty();
        if (!r.ok) r.error_msg = "no_response_to_raw_frames";
        diag::log_tagged_fmt("h2_edit", "send raw_frames_done ok=%d latency_ms=%llu wire_in=%zu",
            static_cast<int>(r.ok), static_cast<unsigned long long>(r.latency_ms), r.raw_wire_in.size());
        close_conn(c);
        return r;
    }

    diag::log_tagged_fmt("h2_edit", "send creating_h2_session");
    session_state_t st;
    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback(cbs, s_send_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, s_on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, s_on_data_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, s_on_frame_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, s_on_close_cb);
    int nrv = nghttp2_session_client_new(&st.session, cbs, &st);
    nghttp2_session_callbacks_del(cbs);
    if (nrv != 0) {
        diag::log_tagged_fmt("h2_edit", "send h2_session_create_failed rv=%d", nrv);
        r.error_msg = "h2_session_create_failed";
        close_conn(c);
        return r;
    }
    diag::log_tagged_fmt("h2_edit", "send h2_session_ok submitting_settings");

    nghttp2_settings_entry iv[2] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1u << 24 }
    };
    if (nghttp2_submit_settings(st.session, NGHTTP2_FLAG_NONE, iv, 2) != 0) {
        diag::log_tagged_fmt("h2_edit", "send settings_failed");
        r.error_msg = "settings_failed";
        nghttp2_session_del(st.session);
        close_conn(c);
        return r;
    }
    diag::log_tagged_fmt("h2_edit", "send settings_ok");

    std::vector<std::pair<std::string, std::string>> header_storage;
    header_storage.reserve(req.headers.size() + 4);
    std::string authority = req.pseudo.authority.empty() ? req.host : req.pseudo.authority;
    header_storage.emplace_back(":method", req.pseudo.method.empty() ? std::string("GET") : req.pseudo.method);
    header_storage.emplace_back(":scheme", req.pseudo.scheme.empty() ? std::string("https") : req.pseudo.scheme);
    header_storage.emplace_back(":path", req.pseudo.path.empty() ? std::string("/") : req.pseudo.path);
    header_storage.emplace_back(":authority", authority);
    for (auto& h : req.headers) header_storage.emplace_back(h.first, h.second);

    std::vector<nghttp2_nv> nva;
    nva.reserve(header_storage.size());
    for (auto& hv : header_storage) {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(hv.first.data()));
        nv.namelen = hv.first.size();
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(hv.second.data()));
        nv.valuelen = hv.second.size();
        nv.flags = NGHTTP2_NV_FLAG_NONE;
        nva.push_back(nv);
        diag::log_tagged_fmt("h2_edit",
            "send_header_prepared name=%s value_len=%zu",
            hv.first.c_str(),
            hv.second.size());
    }

    nghttp2_data_provider prd{};
    struct src_t { const uint8_t* data; size_t len; size_t pos; };
    src_t src{ req.body.data(), req.body.size(), 0 };
    prd.source.ptr = &src;
    prd.read_callback = [](nghttp2_session*, int32_t, uint8_t* buf, size_t length,
                           uint32_t* flags, nghttp2_data_source* source, void*) -> ssize_t {
        auto* s = static_cast<src_t*>(source->ptr);
        size_t rem = s->len - s->pos;
        size_t take = rem < length ? rem : length;
        if (take) { memcpy(buf, s->data + s->pos, take); s->pos += take; }
        if (s->pos >= s->len) *flags |= NGHTTP2_DATA_FLAG_EOF;
        return static_cast<ssize_t>(take);
    };

    diag::log_tagged_fmt("h2_edit", "send submitting_request headers=%zu body=%zu authority_len=%zu path=%s",
        nva.size(), req.body.size(), authority.size(), safe_path.c_str());
    int32_t sid = nghttp2_submit_request(st.session, nullptr, nva.data(), nva.size(),
                                         req.body.empty() ? nullptr : &prd, nullptr);
    if (sid < 0) {
        diag::log_tagged_fmt("h2_edit", "send submit_request_failed sid=%d", sid);
        r.error_msg = "submit_request_failed";
        nghttp2_session_del(st.session);
        close_conn(c);
        return r;
    }
    diag::log_tagged_fmt("h2_edit", "send stream_id=%d sending", sid);
    st.streams.emplace(sid, stream_cap_t{});

    auto t0 = std::chrono::steady_clock::now();
    int rv = nghttp2_session_send(st.session);
    diag::log_tagged_fmt("h2_edit", "send initial_session_send rv=%d out_buf=%zu", rv, st.out_buf.size());
    if (!st.out_buf.empty()) {
        r.raw_wire_out.insert(r.raw_wire_out.end(), st.out_buf.begin(), st.out_buf.end());
        if (!ssl_send_all(c.ssl, st.out_buf.data(), st.out_buf.size(), req.timeout_ms)) {
            diag::log_tagged_fmt("h2_edit", "send h2_send_failed out_buf=%zu", st.out_buf.size());
            r.error_msg = "h2_send_failed";
            nghttp2_session_del(st.session);
            close_conn(c);
            return r;
        }
        st.out_buf.clear();
    }
    diag::log_tagged_fmt("h2_edit", "send request_sent waiting_for_response sid=%d", sid);

    uint8_t tmp[16384];
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(req.timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto it = st.streams.find(sid);
        if (it != st.streams.end() && it->second.complete) {
            diag::log_tagged_fmt("h2_edit", "send stream_complete sid=%d", sid);
            break;
        }
        if (st.goaway.load()) {
            diag::log_tagged_fmt("h2_edit", "send goaway_received sid=%d", sid);
            break;
        }
        int rem = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
        if (rem <= 0) {
            diag::log_tagged_fmt("h2_edit", "send recv_timeout sid=%d", sid);
            break;
        }
        int n = ssl_recv_some(c.ssl, tmp, sizeof(tmp), rem);
        if (n <= 0) {
            diag::log_tagged_fmt("h2_edit", "send recv_closed n=%d sid=%d", n, sid);
            break;
        }
        r.raw_wire_in.insert(r.raw_wire_in.end(), tmp, tmp + n);
        diag::log_tagged_fmt("h2_edit",
            "send recv_bytes n=%d wire_in=%zu want_read=%d want_write=%d",
            n,
            r.raw_wire_in.size(),
            nghttp2_session_want_read(st.session) ? 1 : 0,
            nghttp2_session_want_write(st.session) ? 1 : 0);
        ssize_t mr = nghttp2_session_mem_recv(st.session, tmp, static_cast<size_t>(n));
        if (mr < 0) {
            diag::log_tagged_fmt("h2_edit", "send mem_recv_failed mr=%d sid=%d", static_cast<int>(mr), sid);
            break;
        }
        rv = nghttp2_session_send(st.session);
        diag::log_tagged_fmt("h2_edit", "send loop_session_send rv=%d out_buf=%zu", rv, st.out_buf.size());
        if (!st.out_buf.empty()) {
            r.raw_wire_out.insert(r.raw_wire_out.end(), st.out_buf.begin(), st.out_buf.end());
            if (!ssl_send_all(c.ssl, st.out_buf.data(), st.out_buf.size(), req.timeout_ms)) {
                diag::log_tagged_fmt("h2_edit", "send loop_write_failed out_buf=%zu", st.out_buf.size());
                break;
            }
            st.out_buf.clear();
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    auto it = st.streams.find(sid);
    if (it != st.streams.end()) {
        r.ok = it->second.complete && !it->second.errored;
        r.status_code = it->second.status;
        r.headers = it->second.headers;
        r.body = std::move(it->second.body);
        if (it->second.errored) r.error_msg = "h2_stream_errored";
        else if (!it->second.complete) r.error_msg = "h2_stream_incomplete";
    } else {
        diag::log_tagged_fmt("h2_edit", "send stream_missing sid=%d", sid);
        r.error_msg = "h2_stream_missing";
    }
    r.latency_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    diag::log_tagged_fmt("h2_edit", "send done ok=%d status=%d latency_ms=%llu body=%zu err=%s frames=%llu headers=%llu data_chunks=%llu streams=%zu",
        static_cast<int>(r.ok), r.status_code, static_cast<unsigned long long>(r.latency_ms),
        r.body.size(), r.error_msg.c_str(),
        static_cast<unsigned long long>(st.frames_seen),
        static_cast<unsigned long long>(st.headers_seen),
        static_cast<unsigned long long>(st.data_chunks_seen),
        st.streams.size());

    nghttp2_session_del(st.session);
    close_conn(c);
    return r;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("h2_edit", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
