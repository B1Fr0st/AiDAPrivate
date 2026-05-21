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

static SOCKET tcp_connect(const std::string& host, uint16_t port, int timeout_ms)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ports[16];
    snprintf(ports, sizeof(ports), "%u", static_cast<unsigned>(port));
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), ports, &hints, &res) != 0 || !res) return INVALID_SOCKET;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return INVALID_SOCKET; }
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int cr = connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    if (cr == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s); freeaddrinfo(res); return INVALID_SOCKET;
    }
    WSAPOLLFD pfd{}; pfd.fd = s; pfd.events = POLLOUT;
    int pr = WSAPoll(&pfd, 1, timeout_ms);
    if (pr <= 0) { closesocket(s); freeaddrinfo(res); return INVALID_SOCKET; }
    int err = 0; int sz = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &sz);
    if (err != 0) { closesocket(s); freeaddrinfo(res); return INVALID_SOCKET; }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    DWORD tmo = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    BOOL nd = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nd), sizeof(nd));
    freeaddrinfo(res);
    return s;
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

static bool tls_connect(conn_t& c, const std::string& host, uint16_t port, int timeout_ms)
{
    SSL_CTX* ctx = ensure_ctx();
    if (!ctx) return false;
    c.sock = tcp_connect(host, port, timeout_ms);
    if (c.sock == INVALID_SOCKET) return false;
    c.ssl = SSL_new(ctx);
    if (!c.ssl) { close_conn(c); return false; }
    SSL_set_fd(c.ssl, static_cast<int>(c.sock));
    SSL_set_tlsext_host_name(c.ssl, host.c_str());
    static const uint8_t alpn[] = { 0x02, 'h', '2' };
    SSL_set_alpn_protos(c.ssl, alpn, sizeof(alpn));

    u_long nb = 1; ioctlsocket(c.sock, FIONBIO, &nb);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        int r = SSL_connect(c.ssl);
        if (r == 1) break;
        int err = SSL_get_error(c.ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) { close_conn(c); return false; }
            int rem = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            WSAPOLLFD pfd{}; pfd.fd = c.sock;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
            int pr = WSAPoll(&pfd, 1, rem);
            if (pr <= 0) { close_conn(c); return false; }
            continue;
        }
        close_conn(c);
        return false;
    }
    nb = 0; ioctlsocket(c.sock, FIONBIO, &nb);

    const unsigned char* sel = nullptr;
    unsigned int sel_len = 0;
    SSL_get0_alpn_selected(c.ssl, &sel, &sel_len);
    if (!(sel && sel_len == 2 && sel[0] == 'h' && sel[1] == '2')) {
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
    return 0;
}

static int s_on_frame_cb(nghttp2_session*, const nghttp2_frame* frame, void* ud)
{
    auto* st = static_cast<session_state_t*>(ud);
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
    return 0;
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
    diag::log_tagged_fmt("h2_edit", "send entry host=%s port=%u method=%s path=%s body=%zu use_raw=%d timeout_ms=%d",
        req.host.c_str(), static_cast<unsigned>(req.port),
        req.pseudo.method.c_str(), req.pseudo.path.c_str(),
        req.body.size(), static_cast<int>(req.use_raw_frames), req.timeout_ms);
    response_t r;
    conn_t c;
    diag::log_tagged_fmt("h2_edit", "send tls_connecting host=%s port=%u", req.host.c_str(), static_cast<unsigned>(req.port));
    if (!tls_connect(c, req.host, req.port, req.timeout_ms)) {
        diag::log_tagged_fmt("h2_edit", "send tls_connect_failed host=%s", req.host.c_str());
        r.error_msg = "tls_connect_failed (ALPN must be h2)";
        return r;
    }
    diag::log_tagged_fmt("h2_edit", "send tls_ok host=%s sending_preface", req.host.c_str());

    static const uint8_t kPreface[] = {
        'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n','\r','\n',
        'S','M','\r','\n','\r','\n'
    };
    if (!ssl_send_all(c.ssl, kPreface, sizeof(kPreface), req.timeout_ms)) {
        diag::log_tagged_fmt("h2_edit", "send preface_send_failed host=%s", req.host.c_str());
        r.error_msg = "preface_send_failed";
        close_conn(c);
        return r;
    }
    r.raw_wire_out.insert(r.raw_wire_out.end(), kPreface, kPreface + sizeof(kPreface));
    diag::log_tagged_fmt("h2_edit", "send preface_ok");

    if (req.use_raw_frames) {
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

    std::vector<nghttp2_nv> nva;
    nva.reserve(req.headers.size() + 4);
    auto push = [&](const std::string& n, const std::string& v) {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(n.data()));
        nv.namelen = n.size();
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(v.data()));
        nv.valuelen = v.size();
        nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
        nva.push_back(nv);
    };
    std::string authority = req.pseudo.authority.empty() ? req.host : req.pseudo.authority;
    push(":method", req.pseudo.method.empty() ? std::string("GET") : req.pseudo.method);
    push(":scheme", req.pseudo.scheme.empty() ? std::string("https") : req.pseudo.scheme);
    push(":path", req.pseudo.path.empty() ? std::string("/") : req.pseudo.path);
    push(":authority", authority);
    for (auto& h : req.headers) push(h.first, h.second);

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

    diag::log_tagged_fmt("h2_edit", "send submitting_request headers=%zu body=%zu",
        nva.size(), req.body.size());
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

    auto t0 = std::chrono::steady_clock::now();
    int rv = nghttp2_session_send(st.session);
    (void)rv;
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
        ssize_t mr = nghttp2_session_mem_recv(st.session, tmp, static_cast<size_t>(n));
        if (mr < 0) {
            diag::log_tagged_fmt("h2_edit", "send mem_recv_failed mr=%d sid=%d", static_cast<int>(mr), sid);
            break;
        }
        rv = nghttp2_session_send(st.session);
        (void)rv;
        if (!st.out_buf.empty()) {
            ssl_send_all(c.ssl, st.out_buf.data(), st.out_buf.size(), req.timeout_ms);
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
    diag::log_tagged_fmt("h2_edit", "send done ok=%d status=%d latency_ms=%llu body=%zu err=%s",
        static_cast<int>(r.ok), r.status_code, static_cast<unsigned long long>(r.latency_ms),
        r.body.size(), r.error_msg.c_str());

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
