#include "traffic_generator.h"
#include "test_log.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace test_target {
namespace traffic {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[net] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static std::atomic<bool>  s_external_ok{ true };
static std::atomic<bool>* s_running = nullptr;
static config_t           s_cfg{};

static const int kThreadCount = 8;
static HANDLE s_threads[kThreadCount] = { nullptr };
static int    s_thread_used = 0;

static bool running_now() {
    return s_running && s_running->load();
}

static void interruptible_sleep(uint32_t ms) {
    uint32_t slept = 0;
    while (slept < ms && running_now()) {
        uint32_t step = ms - slept;
        if (step > 200) step = 200;
        Sleep(step);
        slept += step;
    }
}

static bool ensure_wsa_thread() {
    WSADATA wsa{};
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

static void describe_socket(SOCKET s, const char* tag) {
    struct sockaddr_in local{};
    int len = sizeof(local);
    if (getsockname(s, (struct sockaddr*)&local, &len) == 0) {
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
        log("%s local endpoint %s:%u", tag, ip, ntohs(local.sin_port));
    }
}

struct sha1_ctx {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buffer[64];
};

static uint32_t sha1_rol(uint32_t value, int bits) {
    return (value << bits) | (value >> (32 - bits));
}

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)buffer[i * 4] << 24) | ((uint32_t)buffer[i * 4 + 1] << 16) |
               ((uint32_t)buffer[i * 4 + 2] << 8) | ((uint32_t)buffer[i * 4 + 3]);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = sha1_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t temp = sha1_rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = sha1_rol(b, 30); b = a; a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(sha1_ctx* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static void sha1_update(sha1_ctx* ctx, const uint8_t* data, size_t len) {
    size_t fill = (size_t)(ctx->count % 64);
    ctx->count += len;
    while (len > 0) {
        ctx->buffer[fill++] = *data++;
        --len;
        if (fill == 64) {
            sha1_transform(ctx->state, ctx->buffer);
            fill = 0;
        }
    }
}

static void sha1_final(sha1_ctx* ctx, uint8_t out[20]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    uint8_t zero = 0x00;
    while ((ctx->count % 64) != 56) {
        sha1_update(ctx, &zero, 1);
    }
    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i) {
        len_be[i] = (uint8_t)(bits >> (56 - i * 8));
    }
    sha1_update(ctx, len_be, 8);
    for (int i = 0; i < 5; ++i) {
        out[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static std::string base64_encode(const uint8_t* data, size_t len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += tbl[(n >> 18) & 0x3F];
        out += tbl[(n >> 12) & 0x3F];
        out += tbl[(n >> 6) & 0x3F];
        out += tbl[n & 0x3F];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t n = data[i] << 16;
        out += tbl[(n >> 18) & 0x3F];
        out += tbl[(n >> 12) & 0x3F];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out += tbl[(n >> 18) & 0x3F];
        out += tbl[(n >> 12) & 0x3F];
        out += tbl[(n >> 6) & 0x3F];
        out += "=";
    }
    return out;
}

static std::string ws_accept_key(const std::string& client_key) {
    std::string concat = client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)concat.data(), concat.size());
    uint8_t digest[20];
    sha1_final(&ctx, digest);
    return base64_encode(digest, 20);
}

static int send_all(SOCKET s, const char* data, int len) {
    int total = 0;
    while (total < len) {
        int n = send(s, data + total, len - total, 0);
        if (n <= 0) return total;
        total += n;
    }
    return total;
}

static SOCKET make_loopback_listener(uint16_t port) {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return INVALID_SOCKET;
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listener);
        return INVALID_SOCKET;
    }
    if (listen(listener, 8) == SOCKET_ERROR) {
        closesocket(listener);
        return INVALID_SOCKET;
    }
    return listener;
}

static SOCKET connect_loopback(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    DWORD timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static SOCKET accept_with_timeout(SOCKET listener, int timeout_sec) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(listener, &readfds);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    int sel = select(0, &readfds, nullptr, nullptr, &tv);
    if (sel <= 0) return INVALID_SOCKET;
    struct sockaddr_in client_addr{};
    int client_len = sizeof(client_addr);
    return accept(listener, (struct sockaddr*)&client_addr, &client_len);
}

static DWORD WINAPI tcp_echo_pair_thread(LPVOID param) {
    if (!ensure_wsa_thread()) return 1;
    log("tcp-echo worker started");

    uint16_t port_cursor = (uint16_t)(s_cfg.base_port + 100);
    uint32_t round = 0;
    const int payload_sizes[] = { 64, 512, 4096, 16384, 65536 };

    while (running_now()) {
        uint16_t port = port_cursor;
        port_cursor++;
        if (port_cursor > (uint16_t)(s_cfg.base_port + 180)) {
            port_cursor = (uint16_t)(s_cfg.base_port + 100);
        }

        SOCKET listener = make_loopback_listener(port);
        if (listener == INVALID_SOCKET) {
            interruptible_sleep(s_cfg.rate_ms);
            continue;
        }

        int payload_len = payload_sizes[round % 5];
        round++;

        SOCKET client = connect_loopback(port);
        if (client == INVALID_SOCKET) {
            closesocket(listener);
            interruptible_sleep(s_cfg.rate_ms);
            continue;
        }

        SOCKET server = accept_with_timeout(listener, 2);
        if (server == INVALID_SOCKET) {
            closesocket(client);
            closesocket(listener);
            interruptible_sleep(s_cfg.rate_ms);
            continue;
        }

        char client_ip[INET_ADDRSTRLEN]{};
        struct sockaddr_in peer{};
        int peer_len = sizeof(peer);
        if (getpeername(server, (struct sockaddr*)&peer, &peer_len) == 0) {
            inet_ntop(AF_INET, &peer.sin_addr, client_ip, sizeof(client_ip));
        }
        log("tcp-echo connection open port=%u peer=%s payload=%d", port, client_ip, payload_len);

        std::vector<char> payload(payload_len);
        for (int i = 0; i < payload_len; ++i) payload[i] = (char)('A' + (i % 26));

        int sent = send_all(client, payload.data(), payload_len);
        log("tcp-echo sent %d bytes on port %u", sent, port);

        std::vector<char> rxbuf(payload_len);
        int got = 0;
        while (got < payload_len) {
            int n = recv(server, rxbuf.data() + got, payload_len - got, 0);
            if (n <= 0) break;
            got += n;
        }
        log("tcp-echo server received %d bytes on port %u", got, port);

        int echoed = send_all(server, rxbuf.data(), got);
        std::vector<char> echo_rx(payload_len);
        int echo_got = 0;
        while (echo_got < echoed) {
            int n = recv(client, echo_rx.data() + echo_got, echoed - echo_got, 0);
            if (n <= 0) break;
            echo_got += n;
        }
        log("tcp-echo client received echo %d bytes on port %u", echo_got, port);

        closesocket(client);
        closesocket(server);
        closesocket(listener);
        log("tcp-echo connection close port=%u", port);

        interruptible_sleep(s_cfg.rate_ms);
    }

    log("tcp-echo worker stopped");
    return 0;
}

static DWORD WINAPI udp_loopback_thread(LPVOID param) {
    if (!ensure_wsa_thread()) return 1;
    log("udp-loopback worker started");

    SOCKET rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (rx == INVALID_SOCKET || tx == INVALID_SOCKET) {
        if (rx != INVALID_SOCKET) closesocket(rx);
        if (tx != INVALID_SOCKET) closesocket(tx);
        return 1;
    }

    struct sockaddr_in rx_addr{};
    rx_addr.sin_family = AF_INET;
    rx_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rx_addr.sin_port = htons((uint16_t)(s_cfg.base_port + 200));
    if (bind(rx, (struct sockaddr*)&rx_addr, sizeof(rx_addr)) == SOCKET_ERROR) {
        log("udp-loopback bind failed: %d", WSAGetLastError());
        closesocket(rx);
        closesocket(tx);
        return 1;
    }

    DWORD timeout = 1000;
    setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    uint32_t seq = 0;
    while (running_now()) {
        char msg[512];
        int sizes[] = { 32, 256, 1400 };
        int want = sizes[seq % 3];
        int hdr = sprintf_s(msg, sizeof(msg), "AIDA_UDP seq=%u pid=%lu len=%d ", seq, GetCurrentProcessId(), want);
        for (int i = hdr; i < want && i < (int)sizeof(msg); ++i) msg[i] = (char)('0' + (i % 10));
        int datalen = want < (int)sizeof(msg) ? want : (int)sizeof(msg);

        int sent = sendto(tx, msg, datalen, 0, (struct sockaddr*)&rx_addr, sizeof(rx_addr));
        log("udp-loopback sent %d bytes to 127.0.0.1:%u seq=%u", sent, ntohs(rx_addr.sin_port), seq);

        char rbuf[1600]{};
        struct sockaddr_in from{};
        int fromlen = sizeof(from);
        int recvd = recvfrom(rx, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&from, &fromlen);
        if (recvd > 0) {
            char fip[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &from.sin_addr, fip, sizeof(fip));
            log("udp-loopback received %d bytes from %s:%u", recvd, fip, ntohs(from.sin_port));
        }
        seq++;
        interruptible_sleep(s_cfg.rate_ms);
    }

    closesocket(rx);
    closesocket(tx);
    log("udp-loopback worker stopped (sent %u datagrams)", seq);
    return 0;
}

static void build_dns_query(std::vector<uint8_t>& out, uint16_t id, const char* host, uint16_t qtype) {
    out.clear();
    out.push_back((uint8_t)(id >> 8));
    out.push_back((uint8_t)(id & 0xFF));
    out.push_back(0x01); out.push_back(0x00);
    out.push_back(0x00); out.push_back(0x01);
    out.push_back(0x00); out.push_back(0x00);
    out.push_back(0x00); out.push_back(0x00);
    out.push_back(0x00); out.push_back(0x00);
    const char* p = host;
    while (*p) {
        const char* dot = strchr(p, '.');
        size_t seg = dot ? (size_t)(dot - p) : strlen(p);
        out.push_back((uint8_t)seg);
        for (size_t i = 0; i < seg; ++i) out.push_back((uint8_t)p[i]);
        if (!dot) break;
        p = dot + 1;
    }
    out.push_back(0x00);
    out.push_back((uint8_t)(qtype >> 8));
    out.push_back((uint8_t)(qtype & 0xFF));
    out.push_back(0x00); out.push_back(0x01);
}

static DWORD WINAPI dns_query_thread(LPVOID param) {
    if (!ensure_wsa_thread()) return 1;
    log("dns worker started");

    struct { const char* host; uint16_t type; const char* tname; } queries[] = {
        { "google.com",       0x0001, "A" },
        { "github.com",       0x001C, "AAAA" },
        { "cloudflare.com",   0x0010, "TXT" },
        { "example.com",      0x0001, "A" },
        { "wikipedia.org",    0x001C, "AAAA" },
        { "microsoft.com",    0x0010, "TXT" },
        { "amazon.com",       0x0001, "A" },
        { "openai.com",       0x0001, "A" },
    };
    const char* servers[] = { "8.8.8.8", "1.1.1.1" };

    uint16_t qid = 0x4100;
    uint32_t idx = 0;
    while (running_now()) {
        const char* host = queries[idx % 8].host;
        uint16_t qtype = queries[idx % 8].type;
        const char* tname = queries[idx % 8].tname;
        const bool loopback_mode = s_cfg.no_external || !s_external_ok.load();
        const char* server = loopback_mode ? "127.0.0.1" : servers[idx % 2];
        idx++;

        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) { interruptible_sleep(s_cfg.rate_ms); continue; }

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        inet_pton(AF_INET, server, &dest.sin_addr);

        std::vector<uint8_t> q;
        build_dns_query(q, qid++, host, qtype);

        int sent = sendto(s, (const char*)q.data(), (int)q.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
        log("dns query %s/%s id=%u -> %s:53 mode=%s (%d bytes)",
            host, tname, qid - 1, server, loopback_mode ? "loopback" : "external", sent);

        DWORD timeout = loopback_mode ? 100 : 2000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        uint8_t rbuf[1024]{};
        struct sockaddr_in from{};
        int fromlen = sizeof(from);
        int recvd = recvfrom(s, (char*)rbuf, sizeof(rbuf), 0, (struct sockaddr*)&from, &fromlen);
        if (recvd >= 12) {
            uint16_t ancount = (uint16_t)((rbuf[6] << 8) | rbuf[7]);
            log("dns response %s/%s answers=%u (%d bytes)", host, tname, ancount, recvd);
        } else if (loopback_mode) {
            log("dns response %s/%s loopback probe sent no listener", host, tname);
        } else {
            log("dns response %s/%s timeout/offline", host, tname);
            s_external_ok.store(false);
        }
        closesocket(s);
        interruptible_sleep(s_cfg.rate_ms);
    }

    log("dns worker stopped");
    return 0;
}

static int http_request_local(const char* method, const char* path, const char* ctype,
                              const char* body, bool chunked) {
    SOCKET s = connect_loopback(s_cfg.http_port);
    if (s == INVALID_SOCKET) {
        log("http %s %s -> connect failed port=%u", method, path, s_cfg.http_port);
        return -1;
    }
    describe_socket(s, "http");

    std::string req = method;
    req += " ";
    req += path;
    req += " HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: AiDA-TrafficGen/1.0\r\n";
    req += "Accept: */*\r\nX-AiDA-Trace: traffic-generator\r\nConnection: close\r\n";

    if (body && *body) {
        if (chunked) {
            req += "Transfer-Encoding: chunked\r\n";
            if (ctype) { req += "Content-Type: "; req += ctype; req += "\r\n"; }
            req += "\r\n";
            size_t blen = strlen(body);
            char sizebuf[32];
            sprintf_s(sizebuf, sizeof(sizebuf), "%zX\r\n", blen);
            req += sizebuf;
            req += body;
            req += "\r\n0\r\n\r\n";
        } else {
            char clbuf[64];
            sprintf_s(clbuf, sizeof(clbuf), "Content-Length: %zu\r\n", strlen(body));
            req += clbuf;
            if (ctype) { req += "Content-Type: "; req += ctype; req += "\r\n"; }
            req += "\r\n";
            req += body;
        }
    } else {
        req += "\r\n";
    }

    send_all(s, req.data(), (int)req.size());

    std::string resp;
    char buf[2048];
    int total = 0;
    int n;
    while ((n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        resp += buf;
        total += n;
        if (total > 200000) break;
    }
    closesocket(s);

    int status = 0;
    if (resp.size() > 12 && resp.compare(0, 5, "HTTP/") == 0) {
        status = atoi(resp.c_str() + 9);
    }
    log("http %s %s -> %d (%d bytes %s)", method, path, status, total, chunked ? "chunked" : "plain");
    return status;
}

static DWORD WINAPI http_client_thread(LPVOID param) {
    if (!ensure_wsa_thread()) return 1;
    log("http-client worker started");

    interruptible_sleep(500);

    const char* get_paths[] = {
        "/api/status", "/api/headers", "/api/cookies", "/api/xml",
        "/api/jwt", "/api/large", "/api/csp", "/api/cors",
        "/api/set-cookie", "/api/xss?input=traffic", "/api/sqli?id=1%27%20OR%201=1--",
    };

    uint32_t idx = 0;
    while (running_now()) {
        const char* path = get_paths[idx % 11];
        http_request_local("GET", path, nullptr, nullptr, false);

        if (idx % 3 == 0) {
            const char* json = "{\"tool\":\"AiDA\",\"gen\":\"traffic\",\"seq\":1,\"nested\":{\"a\":[1,2,3]}}";
            http_request_local("POST", "/api/echo", "application/json", json, false);
        }
        if (idx % 5 == 0) {
            const char* form = "username=testuser&password=testpass&note=traffic-generator-body";
            http_request_local("POST", "/api/login", "application/x-www-form-urlencoded", form, false);
        }
        if (idx % 4 == 0) {
            const char* big = "{\"chunk\":\"this body is delivered using HTTP chunked transfer encoding to exercise the parser\"}";
            http_request_local("POST", "/api/echo", "application/json", big, true);
        }

        if (!s_cfg.no_external && s_external_ok.load() && (idx % 7 == 0)) {
            struct addrinfo hints{}, *result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            int rc = getaddrinfo("example.com", "80", &hints, &result);
            if (rc == 0 && result) {
                SOCKET es = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
                if (es != INVALID_SOCKET) {
                    DWORD to = 3000;
                    setsockopt(es, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
                    setsockopt(es, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
                    if (connect(es, result->ai_addr, (int)result->ai_addrlen) == 0) {
                        const char* hreq = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: AiDA-TrafficGen/1.0\r\nConnection: close\r\n\r\n";
                        send_all(es, hreq, (int)strlen(hreq));
                        char hb[512]{};
                        int hn = recv(es, hb, sizeof(hb) - 1, 0);
                        if (hn > 0) {
                            char* nl = strchr(hb, '\r');
                            if (nl) *nl = '\0';
                            log("http external example.com -> %s", hb);
                        } else {
                            log("http external example.com -> no response");
                            s_external_ok.store(false);
                        }
                    } else {
                        log("http external example.com -> connect failed");
                        s_external_ok.store(false);
                    }
                    closesocket(es);
                }
            } else {
                log("http external example.com -> resolve failed");
                s_external_ok.store(false);
            }
            if (result) freeaddrinfo(result);
        }

        idx++;
        interruptible_sleep(s_cfg.rate_ms);
    }

    log("http-client worker stopped");
    return 0;
}

static DWORD WINAPI throughput_thread(LPVOID param) {
    if (!ensure_wsa_thread()) return 1;
    log("throughput worker started");

    uint16_t port = (uint16_t)(s_cfg.base_port + 250);
    const int burst_total = 4 * 1024 * 1024;
    const int chunk = 65536;

    uint32_t round = 0;
    while (running_now()) {
        SOCKET listener = make_loopback_listener(port);
        if (listener == INVALID_SOCKET) {
            interruptible_sleep(s_cfg.rate_ms * 4);
            continue;
        }

        SOCKET client = connect_loopback(port);
        if (client == INVALID_SOCKET) {
            closesocket(listener);
            interruptible_sleep(s_cfg.rate_ms * 4);
            continue;
        }
        SOCKET server = accept_with_timeout(listener, 2);
        if (server == INVALID_SOCKET) {
            closesocket(client);
            closesocket(listener);
            interruptible_sleep(s_cfg.rate_ms * 4);
            continue;
        }

        log("throughput burst start port=%u total=%d", port, burst_total);
        std::vector<char> block(chunk);
        for (int i = 0; i < chunk; ++i) block[i] = (char)(round + i);

        ULONGLONG t0 = GetTickCount64();
        int sent_total = 0;
        std::vector<char> drain(chunk);
        while (sent_total < burst_total && running_now()) {
            int s_n = send(client, block.data(), chunk, 0);
            if (s_n <= 0) break;
            sent_total += s_n;
            int drained = 0;
            while (drained < s_n) {
                int r_n = recv(server, drain.data(), chunk, 0);
                if (r_n <= 0) break;
                drained += r_n;
            }
        }
        ULONGLONG dt = GetTickCount64() - t0;
        if (dt == 0) dt = 1;
        double mbps = ((double)sent_total / (1024.0 * 1024.0)) / ((double)dt / 1000.0);
        log("throughput burst done port=%u bytes=%d ms=%llu rate=%.2f MB/s", port, sent_total, dt, mbps);

        closesocket(client);
        closesocket(server);
        closesocket(listener);

        round++;
        interruptible_sleep(s_cfg.rate_ms * 6);
    }

    log("throughput worker stopped");
    return 0;
}

static void ws_send_frame(SOCKET s, uint8_t opcode, const uint8_t* payload, size_t len, bool mask) {
    std::vector<uint8_t> frame;
    frame.push_back(0x80 | (opcode & 0x0F));
    uint8_t mask_bit = mask ? 0x80 : 0x00;
    if (len < 126) {
        frame.push_back(mask_bit | (uint8_t)len);
    } else if (len <= 0xFFFF) {
        frame.push_back(mask_bit | 126);
        frame.push_back((uint8_t)(len >> 8));
        frame.push_back((uint8_t)(len & 0xFF));
    } else {
        frame.push_back(mask_bit | 127);
        for (int i = 7; i >= 0; --i) frame.push_back((uint8_t)((uint64_t)len >> (i * 8)));
    }
    uint8_t mk[4] = { 0x12, 0x34, 0x56, 0x78 };
    if (mask) {
        for (int i = 0; i < 4; ++i) frame.push_back(mk[i]);
    }
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = payload[i];
        if (mask) b ^= mk[i % 4];
        frame.push_back(b);
    }
    send_all(s, (const char*)frame.data(), (int)frame.size());
}

static int ws_recv_frame(SOCKET s, uint8_t* opcode_out, std::vector<uint8_t>& payload) {
    uint8_t hdr[2];
    int got = recv(s, (char*)hdr, 2, MSG_WAITALL);
    if (got != 2) return -1;
    *opcode_out = hdr[0] & 0x0F;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t len = hdr[1] & 0x7F;
    if (len == 126) {
        uint8_t ext[2];
        if (recv(s, (char*)ext, 2, MSG_WAITALL) != 2) return -1;
        len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (len == 127) {
        uint8_t ext[8];
        if (recv(s, (char*)ext, 8, MSG_WAITALL) != 8) return -1;
        len = 0;
        for (int i = 0; i < 8; ++i) len = (len << 8) | ext[i];
    }
    uint8_t mk[4] = { 0, 0, 0, 0 };
    if (masked) {
        if (recv(s, (char*)mk, 4, MSG_WAITALL) != 4) return -1;
    }
    payload.resize((size_t)len);
    uint64_t received = 0;
    while (received < len) {
        int n = recv(s, (char*)payload.data() + received, (int)(len - received), 0);
        if (n <= 0) return -1;
        received += n;
    }
    if (masked) {
        for (uint64_t i = 0; i < len; ++i) payload[(size_t)i] ^= mk[i % 4];
    }
    return (int)len;
}

static DWORD WINAPI websocket_thread(LPVOID param) {
    if (!ensure_wsa_thread()) return 1;
    log("websocket worker started");

    uint16_t port = (uint16_t)(s_cfg.base_port + 300);
    uint32_t round = 0;

    while (running_now()) {
        SOCKET listener = make_loopback_listener(port);
        if (listener == INVALID_SOCKET) {
            interruptible_sleep(s_cfg.rate_ms * 2);
            continue;
        }

        SOCKET client = connect_loopback(port);
        if (client == INVALID_SOCKET) {
            closesocket(listener);
            interruptible_sleep(s_cfg.rate_ms * 2);
            continue;
        }
        SOCKET server = accept_with_timeout(listener, 2);
        if (server == INVALID_SOCKET) {
            closesocket(client);
            closesocket(listener);
            interruptible_sleep(s_cfg.rate_ms * 2);
            continue;
        }

        std::string client_key = base64_encode((const uint8_t*)"AIDATESTKEY01234", 16);
        std::string handshake =
            "GET /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: " + client_key +
            "\r\nSec-WebSocket-Version: 13\r\n\r\n";
        send_all(client, handshake.data(), (int)handshake.size());
        log("websocket handshake request sent port=%u", port);

        char reqbuf[1024]{};
        int rn = recv(server, reqbuf, sizeof(reqbuf) - 1, 0);
        std::string accept_key;
        if (rn > 0) {
            reqbuf[rn] = '\0';
            const char* kh = strstr(reqbuf, "Sec-WebSocket-Key:");
            if (kh) {
                kh += 18;
                while (*kh == ' ') kh++;
                const char* ke = strstr(kh, "\r\n");
                if (ke) accept_key = ws_accept_key(std::string(kh, ke));
            }
        }
        std::string resp =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept_key + "\r\n\r\n";
        send_all(server, resp.data(), (int)resp.size());
        log("websocket handshake response sent (accept=%s)", accept_key.c_str());

        char hsresp[1024]{};
        int hn = recv(client, hsresp, sizeof(hsresp) - 1, 0);
        if (hn > 0) {
            hsresp[hn] = '\0';
            bool ok = strstr(hsresp, "101") != nullptr;
            log("websocket client handshake %s", ok ? "accepted" : "rejected");
        }

        const char* text = "AiDA websocket text frame round-trip";
        ws_send_frame(client, 0x01, (const uint8_t*)text, strlen(text), true);
        log("websocket client sent TEXT frame (%zu bytes)", strlen(text));

        uint8_t opcode = 0;
        std::vector<uint8_t> payload;
        if (ws_recv_frame(server, &opcode, payload) >= 0) {
            log("websocket server recv frame opcode=0x%X len=%zu", opcode, payload.size());
            ws_send_frame(server, opcode, payload.data(), payload.size(), false);
        }
        if (ws_recv_frame(client, &opcode, payload) >= 0) {
            log("websocket client recv echo opcode=0x%X len=%zu", opcode, payload.size());
        }

        uint8_t bin[256];
        for (int i = 0; i < 256; ++i) bin[i] = (uint8_t)(i ^ round);
        ws_send_frame(client, 0x02, bin, sizeof(bin), true);
        log("websocket client sent BINARY frame (%zu bytes)", sizeof(bin));
        if (ws_recv_frame(server, &opcode, payload) >= 0) {
            log("websocket server recv BINARY opcode=0x%X len=%zu", opcode, payload.size());
        }

        uint8_t ping[4] = { 'p', 'i', 'n', 'g' };
        ws_send_frame(client, 0x09, ping, sizeof(ping), true);
        log("websocket client sent PING");
        if (ws_recv_frame(server, &opcode, payload) >= 0) {
            log("websocket server recv control opcode=0x%X", opcode);
            ws_send_frame(server, 0x0A, payload.data(), payload.size(), false);
        }

        ws_send_frame(client, 0x08, nullptr, 0, true);
        log("websocket client sent CLOSE");

        closesocket(client);
        closesocket(server);
        closesocket(listener);
        log("websocket round %u complete port=%u", round, port);

        round++;
        interruptible_sleep(s_cfg.rate_ms * 3);
    }

    log("websocket worker stopped");
    return 0;
}

static DWORD multiport_thread_impl(LPVOID param) {
    (void)param;
    if (!ensure_wsa_thread()) {
        log("multiport WSAStartup failed err=%d", WSAGetLastError());
        return 1;
    }
    log("multiport worker started");

    uint32_t round = 0;
    while (running_now()) {
        const int kPairs = 5;
        SOCKET listeners[kPairs];
        SOCKET clients[kPairs];
        SOCKET servers[kPairs];
        uint16_t ports[kPairs];

        int active = 0;
        for (int i = 0; i < kPairs; ++i) {
            ports[i] = (uint16_t)(s_cfg.base_port + 400 + i + (round % 10) * kPairs);
            listeners[i] = make_loopback_listener(ports[i]);
            clients[i] = INVALID_SOCKET;
            servers[i] = INVALID_SOCKET;
            if (listeners[i] != INVALID_SOCKET) {
                clients[i] = connect_loopback(ports[i]);
                if (clients[i] != INVALID_SOCKET) {
                    servers[i] = accept_with_timeout(listeners[i], 1);
                    if (servers[i] != INVALID_SOCKET) {
                        active++;
                    } else {
                        log("multiport round=%u idx=%d port=%u accept failed err=%d",
                            round, i, ports[i], WSAGetLastError());
                    }
                } else {
                    log("multiport round=%u idx=%d port=%u connect failed err=%d",
                        round, i, ports[i], WSAGetLastError());
                }
            } else {
                log("multiport round=%u idx=%d port=%u listen failed err=%d",
                    round, i, ports[i], WSAGetLastError());
            }
        }
        log("multiport round=%u opened %d concurrent connections", round, active);

        for (int i = 0; i < kPairs; ++i) {
            if (clients[i] != INVALID_SOCKET && servers[i] != INVALID_SOCKET) {
                char msg[128];
                int len = sprintf_s(msg, sizeof(msg), "AIDA_MULTIPORT port=%u idx=%d round=%u", ports[i], i, round);
                int sent = send_all(clients[i], msg, len);
                char rb[128]{};
                int n = recv(servers[i], rb, sizeof(rb) - 1, 0);
                if (n > 0) {
                    log("multiport round=%u port=%u sent=%d/%d recv=%d bytes",
                        round, ports[i], sent, len, n);
                } else {
                    log("multiport round=%u port=%u sent=%d/%d recv=%d err=%d",
                        round, ports[i], sent, len, n, WSAGetLastError());
                }
            }
        }

        for (int i = 0; i < kPairs; ++i) {
            if (clients[i] != INVALID_SOCKET) closesocket(clients[i]);
            if (servers[i] != INVALID_SOCKET) closesocket(servers[i]);
            if (listeners[i] != INVALID_SOCKET) closesocket(listeners[i]);
        }
        log("multiport round=%u closed %d connections", round, active);

        round++;
        log("multiport before sleep next_round=%u sleep_ms=%u", round, s_cfg.rate_ms * 2);
        interruptible_sleep(s_cfg.rate_ms * 2);
        log("multiport after sleep round=%u running=%d", round, running_now() ? 1 : 0);
    }

    log("multiport worker stopped");
    return 0;
}

static DWORD WINAPI multiport_thread(LPVOID param) {
    __try {
        return multiport_thread_impl(param);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        log("multiport worker crashed code=0x%08lX", static_cast<unsigned long>(code));
        return code;
    }
}

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    s_cfg = cfg;
    s_running = &running;
    s_external_ok.store(!cfg.no_external);

    log("=== traffic generator starting ===");

    if (cfg.skip_network) {
        log("traffic generator skipped (--skip-network)");
        return;
    }

    log("config base_port=%u http_port=%u rate_ms=%u no_external=%s",
        cfg.base_port, cfg.http_port, cfg.rate_ms, cfg.no_external ? "true" : "false");

    LPTHREAD_START_ROUTINE workers[] = {
        tcp_echo_pair_thread,
        udp_loopback_thread,
        dns_query_thread,
        http_client_thread,
        throughput_thread,
        websocket_thread,
        multiport_thread,
    };
    const char* names[] = {
        "tcp-echo", "udp-loopback", "dns", "http-client",
        "throughput", "websocket", "multiport",
    };

    s_thread_used = 0;
    for (int i = 0; i < 7 && s_thread_used < kThreadCount; ++i) {
        HANDLE h = CreateThread(nullptr, 0, workers[i], nullptr, 0, nullptr);
        if (h) {
            s_threads[s_thread_used++] = h;
            log("worker '%s' started", names[i]);
        } else {
            log("worker '%s' failed to start: %lu", names[i], GetLastError());
        }
    }

    log("=== traffic generator initialized (%d workers running) ===", s_thread_used);
}

void shutdown_all() {
    log("shutting down traffic generator workers...");

    if (s_thread_used > 0) {
        DWORD wr = WaitForMultipleObjects(s_thread_used, s_threads, TRUE, 8000);
        log("traffic generator wait result=0x%08lX workers=%d err=%lu",
            static_cast<unsigned long>(wr), s_thread_used,
            wr == WAIT_FAILED ? static_cast<unsigned long>(GetLastError()) : 0UL);
    }
    for (int i = 0; i < s_thread_used; ++i) {
        if (s_threads[i]) {
            DWORD exit_code = STILL_ACTIVE;
            BOOL got_exit = GetExitCodeThread(s_threads[i], &exit_code);
            log("traffic worker[%d] exit_code_known=%d exit_code=0x%08lX",
                i, got_exit ? 1 : 0, static_cast<unsigned long>(exit_code));
            CloseHandle(s_threads[i]);
            s_threads[i] = nullptr;
        }
    }
    s_thread_used = 0;

    log("traffic generator workers shut down");
}

}
}
