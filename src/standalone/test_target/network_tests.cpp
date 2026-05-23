#include "network_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

namespace test_target {
namespace network {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[NET] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static bool s_wsa_ready = false;

static bool ensure_wsa() {
    if (s_wsa_ready) return true;
    WSADATA wsa{};
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        log("WSAStartup failed: %d", rc);
        return false;
    }
    s_wsa_ready = true;
    return true;
}

void test_tcp_connect(const config_t& cfg) {
    if (!ensure_wsa()) return;

    log("TCP connect test starting...");

    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int rc = getaddrinfo("httpbin.org", "80", &hints, &result);
    if (rc != 0) {
        log("TCP getaddrinfo failed: %d", rc);
        return;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(result);
        log("TCP socket creation failed: %d", WSAGetLastError());
        return;
    }

    DWORD sock_timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));

    u_long nonblocking = 1;
    ioctlsocket(s, FIONBIO, &nonblocking);

    rc = connect(s, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        int sel = select(0, nullptr, &wfds, nullptr, &tv);
        if (sel <= 0) {
            log("TCP connect timeout: %d", WSAGetLastError());
            closesocket(s);
            return;
        }
        int so_err = 0;
        int so_len = (int)sizeof(so_err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &so_len);
        if (so_err != 0) {
            log("TCP connect failed so_error=%d", so_err);
            closesocket(s);
            return;
        }
    } else if (rc == SOCKET_ERROR) {
        log("TCP connect failed: %d", WSAGetLastError());
        closesocket(s);
        return;
    }

    u_long nb_off = 0;
    ioctlsocket(s, FIONBIO, &nb_off);

    log("TCP connected to httpbin.org:80");

    const char* req = "HEAD / HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
    send(s, req, (int)strlen(req), 0);

    char buf[512]{};
    int bytes = recv(s, buf, sizeof(buf) - 1, 0);
    if (bytes > 0) {
        buf[bytes] = '\0';
        char* nl = strchr(buf, '\r');
        if (nl) *nl = '\0';
        log("TCP response status: %s", buf);
    }

    closesocket(s);
    log("TCP connect test complete");
}

void test_udp_send(const config_t& cfg) {
    if (!ensure_wsa()) return;

    log("UDP send test starting...");

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        log("UDP socket creation failed: %d", WSAGetLastError());
        return;
    }

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);

    const uint8_t dns_query[] = {
        0xAA, 0xBB,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    };

    int sent = sendto(s, (const char*)dns_query, sizeof(dns_query), 0,
                      (struct sockaddr*)&dest, sizeof(dest));
    if (sent == SOCKET_ERROR) {
        log("UDP sendto failed: %d", WSAGetLastError());
    } else {
        log("UDP sent %d bytes to 8.8.8.8:53 (DNS query)", sent);
    }

    DWORD timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    char rbuf[512]{};
    struct sockaddr_in from{};
    int fromlen = sizeof(from);
    int recvd = recvfrom(s, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&from, &fromlen);
    if (recvd > 0) {
        log("UDP received %d bytes DNS response", recvd);
    } else {
        log("UDP recv timed out or failed: %d", WSAGetLastError());
    }

    closesocket(s);
    log("UDP send test complete");
}

void test_dns_lookup(const config_t& cfg) {
    if (!ensure_wsa()) return;

    log("DNS lookup test starting...");

    const char* hosts[] = {
        "google.com",
        "example.com"
    };

    for (int i = 0; i < 2; ++i) {
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int rc = getaddrinfo(hosts[i], nullptr, &hints, &result);
        if (rc != 0) {
            log("DNS lookup '%s' failed: %d", hosts[i], rc);
            continue;
        }

        char ip[INET6_ADDRSTRLEN]{};
        if (result->ai_family == AF_INET) {
            struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        } else if (result->ai_family == AF_INET6) {
            struct sockaddr_in6* addr = (struct sockaddr_in6*)result->ai_addr;
            inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
        }

        log("DNS '%s' -> %s", hosts[i], ip);
        freeaddrinfo(result);
    }

    log("DNS lookup test complete");
}

void test_http_get(const config_t& cfg) {
    if (!ensure_wsa()) return;

    log("HTTP GET test starting...");

    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo("httpbin.org", "80", &hints, &result);
    if (rc != 0) {
        log("HTTP GET getaddrinfo failed: %d", rc);
        return;
    }

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(result);
        log("HTTP GET socket failed: %d", WSAGetLastError());
        return;
    }

    DWORD sock_timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));

    u_long nonblocking = 1;
    ioctlsocket(s, FIONBIO, &nonblocking);

    rc = connect(s, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        int sel = select(0, nullptr, &wfds, nullptr, &tv);
        if (sel <= 0) {
            log("HTTP GET connect timeout: %d", WSAGetLastError());
            closesocket(s);
            return;
        }
        int so_err = 0;
        int so_len = (int)sizeof(so_err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &so_len);
        if (so_err != 0) {
            log("HTTP GET connect failed so_error=%d", so_err);
            closesocket(s);
            return;
        }
    } else if (rc == SOCKET_ERROR) {
        log("HTTP GET connect failed: %d", WSAGetLastError());
        closesocket(s);
        return;
    }

    u_long nb_off = 0;
    ioctlsocket(s, FIONBIO, &nb_off);

    const char* request =
        "GET /get?test=aida_target HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "User-Agent: AiDA-TestTarget/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n";

    send(s, request, (int)strlen(request), 0);

    std::string response;
    char buf[1024];
    int bytes;
    while ((bytes = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[bytes] = '\0';
        response += buf;
    }

    closesocket(s);

    if (cfg.verbose && !response.empty()) {
        log("HTTP GET response length: %zu bytes", response.size());
        char* first_line = (char*)response.c_str();
        char* nl = strchr(first_line, '\r');
        if (nl) {
            std::string status(first_line, nl);
            log("HTTP GET status: %s", status.c_str());
        }
    } else {
        log("HTTP GET response: %zu bytes", response.size());
    }

    log("HTTP GET test complete");
}

void test_http_post(const config_t& cfg) {
    if (!ensure_wsa()) return;

    log("HTTP POST test starting...");

    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo("httpbin.org", "80", &hints, &result);
    if (rc != 0) {
        log("HTTP POST getaddrinfo failed: %d", rc);
        return;
    }

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(result);
        log("HTTP POST socket failed: %d", WSAGetLastError());
        return;
    }

    DWORD sock_timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));

    u_long nonblocking = 1;
    ioctlsocket(s, FIONBIO, &nonblocking);

    rc = connect(s, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        int sel = select(0, nullptr, &wfds, nullptr, &tv);
        if (sel <= 0) {
            log("HTTP POST connect timeout: %d", WSAGetLastError());
            closesocket(s);
            return;
        }
        int so_err = 0;
        int so_len = (int)sizeof(so_err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &so_len);
        if (so_err != 0) {
            log("HTTP POST connect failed so_error=%d", so_err);
            closesocket(s);
            return;
        }
    } else if (rc == SOCKET_ERROR) {
        log("HTTP POST connect failed: %d", WSAGetLastError());
        closesocket(s);
        return;
    }

    u_long nb_off = 0;
    ioctlsocket(s, FIONBIO, &nb_off);

    const char* body = "{\"tool\":\"AiDA\",\"test\":\"target\",\"version\":1}";
    int body_len = (int)strlen(body);

    char request[1024];
    int req_len = sprintf_s(request, sizeof(request),
        "POST /post HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "User-Agent: AiDA-TestTarget/1.0\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, body);

    send(s, request, req_len, 0);

    std::string response;
    char buf[1024];
    int bytes;
    while ((bytes = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[bytes] = '\0';
        response += buf;
    }

    closesocket(s);
    log("HTTP POST response: %zu bytes", response.size());
    log("HTTP POST test complete");
}

void test_listen_socket(const config_t& cfg, std::atomic<bool>& running) {
    if (!ensure_wsa()) return;

    log("Listen socket test starting on port %u...", cfg.listen_port);

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        log("Listen socket creation failed: %d", WSAGetLastError());
        return;
    }

    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(cfg.listen_port);

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log("Listen bind failed on port %u: %d", cfg.listen_port, WSAGetLastError());
        closesocket(listener);
        return;
    }

    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        log("Listen failed: %d", WSAGetLastError());
        closesocket(listener);
        return;
    }

    log("Listening on 0.0.0.0:%u (TCP)", cfg.listen_port);

    u_long nonblocking = 1;
    ioctlsocket(listener, FIONBIO, &nonblocking);

    while (running.load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(0, &readfds, nullptr, nullptr, &tv);
        if (sel > 0 && FD_ISSET(listener, &readfds)) {
            struct sockaddr_in client_addr{};
            int client_len = sizeof(client_addr);
            SOCKET client = accept(listener, (struct sockaddr*)&client_addr, &client_len);
            if (client != INVALID_SOCKET) {
                char client_ip[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                log("Accepted connection from %s:%u", client_ip, ntohs(client_addr.sin_port));

                const char* response = "AIDA_TEST_TARGET_RESPONSE\r\n";
                send(client, response, (int)strlen(response), 0);
                closesocket(client);
            }
        }
    }

    closesocket(listener);
    log("Listen socket test complete");
}

void test_multiport_io(const config_t& cfg) {
    if (!ensure_wsa()) return;

    log("Multi-port I/O test starting...");

    uint16_t ports[] = { 80, 443, 8080, 53 };
    const char* port_names[] = { "HTTP", "HTTPS", "Alt-HTTP", "DNS" };

    for (int i = 0; i < 4; ++i) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;

        DWORD timeout = 2000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);

        u_long nonblocking = 1;
        ioctlsocket(s, FIONBIO, &nonblocking);

        int rc = connect(s, (struct sockaddr*)&addr, sizeof(addr));
        if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(s, &writefds);
            struct timeval tv = { 2, 0 };
            int sel = select(0, nullptr, &writefds, nullptr, &tv);
            if (sel > 0) {
                log("Port %u (%s) connected to 1.1.1.1", ports[i], port_names[i]);
            } else {
                log("Port %u (%s) connect timeout", ports[i], port_names[i]);
            }
        } else if (rc == 0) {
            log("Port %u (%s) connected to 1.1.1.1", ports[i], port_names[i]);
        } else {
            log("Port %u (%s) connect failed: %d", ports[i], port_names[i], WSAGetLastError());
        }

        closesocket(s);
    }

    SOCKET udp1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET udp2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (udp1 != INVALID_SOCKET && udp2 != INVALID_SOCKET) {
        struct sockaddr_in bind1{}, bind2{};
        bind1.sin_family = AF_INET;
        bind1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind1.sin_port = htons(cfg.listen_port + 1);

        bind2.sin_family = AF_INET;
        bind2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind2.sin_port = htons(cfg.listen_port + 2);

        if (bind(udp1, (struct sockaddr*)&bind1, sizeof(bind1)) == 0 &&
            bind(udp2, (struct sockaddr*)&bind2, sizeof(bind2)) == 0) {

            const char* msg = "AIDA_MULTIPORT_TEST";
            sendto(udp1, msg, (int)strlen(msg), 0, (struct sockaddr*)&bind2, sizeof(bind2));

            DWORD timeout = 1000;
            setsockopt(udp2, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

            char rbuf[64]{};
            int recvd = recvfrom(udp2, rbuf, sizeof(rbuf) - 1, 0, nullptr, nullptr);
            if (recvd > 0) {
                rbuf[recvd] = '\0';
                log("UDP loopback received: '%s' (%d bytes)", rbuf, recvd);
            }
        }
    }

    if (udp1 != INVALID_SOCKET) closesocket(udp1);
    if (udp2 != INVALID_SOCKET) closesocket(udp2);

    log("Multi-port I/O test complete");
}

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Network tests starting ===");

    if (running.load()) test_dns_lookup(cfg);
    if (running.load()) test_tcp_connect(cfg);
    if (running.load()) test_udp_send(cfg);
    if (running.load()) test_http_get(cfg);
    if (running.load()) test_http_post(cfg);
    if (running.load()) test_multiport_io(cfg);

    log("=== Network tests complete ===");
}

}
}
