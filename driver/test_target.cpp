

/*
 * test_target.cpp — Comprehensive network traffic generator for WhosWho driver testing.
 *
 * WHY THIS REWRITE:
 * The original test_target had 5 network threads that each performed ONE operation
 * then idled for 30-80 seconds.  By the time test_driver started packet capture,
 * the initial traffic burst was already over — resulting in 0 captured packets,
 * 0 DNS queries, 0 DPI results, 0 bandwidth growth, etc.  (17 of 97 tests FAILED.)
 *
 * This version generates CONTINUOUS traffic on tight loops (1-3 second intervals)
 * across all protocols (HTTP, DNS, TLS, loopback TCP, loopback UDP) so the driver's
 * WFP classify callbacks have ample data to capture at any point in time.
 *
 * Key changes:
 *   1. All network threads loop with 1-3 second intervals instead of 30-80s.
 *   2. Added loopback TCP echo server+client on fixed port 44444 for deterministic
 *      local traffic that doesn't depend on internet connectivity.
 *   3. Added loopback UDP traffic on port 44445 for non-TCP protocol diversity.
 *   4. DNS thread now uses getaddrinfo() (goes through Windows DNS service, visible
 *      to WFP ALE hooks) in addition to raw UDP queries.
 *   5. Added Global\\WhosWhoTestReady event — signaled after at least one network
 *      thread succeeds, so test_driver can synchronize instead of sleeping 3s.
 *   6. HTTP and TLS threads reconnect faster, providing sustained traffic flow.
 *   7. Exported test functions (TestAddNumbers, etc.) are unchanged.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <thread>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

/* ========== Exported test functions for remote call testing ========== */
/*
 * WHY unchanged: These 4 functions are called by the driver's shellcode injection
 * mechanism (RemoteCall.cpp).  Their signatures use __stdcall with 4 uint64 params
 * to match the CALL_CONTEXT layout.  The export names must be stable.
 */
extern "C" {
    __declspec(dllexport) std::uint64_t __stdcall TestAddNumbers(
        std::uint64_t a, std::uint64_t b, std::uint64_t , std::uint64_t )
    {
        return a + b;
    }

    __declspec(dllexport) std::uint64_t __stdcall TestGetTickCount(
        std::uint64_t , std::uint64_t , std::uint64_t , std::uint64_t )
    {
        return static_cast<std::uint64_t>(GetTickCount64());
    }

    __declspec(dllexport) std::uint64_t __stdcall TestReturnMagic(
        std::uint64_t , std::uint64_t , std::uint64_t , std::uint64_t )
    {
        return 0xDEADC0DE12345678ULL;
    }

    __declspec(dllexport) std::uint64_t __stdcall TestNoOp(
        std::uint64_t , std::uint64_t , std::uint64_t , std::uint64_t )
    {
        return 0;
    }
}

/* ========== Global state ========== */

static std::atomic<bool> g_shutdown{false};
static HANDLE g_done_event  = nullptr;          /* signaled by test_driver to shut us down */
static HANDLE g_ready_event = nullptr;          /* signaled by us when network is flowing   */
static std::atomic<int> g_ready_count{0};       /* how many threads reported "ready"        */

/*
 * Shared test buffers for memory read/write tests by the driver.
 * WHY volatile: prevents compiler from optimizing away the writes so the
 * driver can reliably read known patterns from our address space.
 */
static volatile std::uint8_t  g_test_buffer[4096] = {};
static volatile std::uint64_t g_test_value = 0xCAFEBABE00000000ULL;

/* Fixed ports for loopback traffic — test_driver knows these. */
static constexpr int LOOPBACK_TCP_PORT = 44444;
static constexpr int LOOPBACK_UDP_PORT = 44445;

/* ========== Utility ========== */

/*
 * WHY: A thread signals "I've completed at least one network operation" by
 * calling this.  Once enough threads report ready (>=2 — one TCP and one UDP
 * minimum), we set the Global\\WhosWhoTestReady event so test_driver can start.
 */
static void signal_ready() {
    int prev = g_ready_count.fetch_add(1, std::memory_order_relaxed);
    if (prev >= 1 && g_ready_event) {
        SetEvent(g_ready_event);
    }
}

static bool check_shutdown() {
    return g_shutdown.load(std::memory_order_relaxed);
}

/* Small sleep that checks shutdown every 100ms */
static void interruptible_sleep(int ms) {
    int elapsed = 0;
    while (elapsed < ms && !check_shutdown()) {
        int chunk = (ms - elapsed < 100) ? (ms - elapsed) : 100;
        Sleep(static_cast<DWORD>(chunk));
        elapsed += chunk;
    }
}

/* ========== Worker threads (non-network) ========== */
/*
 * WHY these exist: the driver's thread enumeration, context get/set,
 * suspend/resume, and hardware breakpoint tests need threads in various
 * states (running, sleeping, waiting).
 */

static DWORD WINAPI worker_thread_cpu(LPVOID) {
    volatile std::uint64_t counter = 0;
    while (!check_shutdown()) {
        counter++;
        if ((counter & 0xFFFF) == 0)
            SwitchToThread();
    }
    return 0;
}

static DWORD WINAPI worker_thread_sleep(LPVOID) {
    while (!check_shutdown()) {
        Sleep(200);
    }
    return 0;
}

static DWORD WINAPI worker_thread_waitable(LPVOID param) {
    HANDLE evt = static_cast<HANDLE>(param);
    while (!check_shutdown()) {
        WaitForSingleObject(evt, 500);
    }
    return 0;
}

/* ========== Network thread: TCP HTTP to example.com ========== */
/*
 * WHY 2-second loop: the original 30-second idle meant only ~1 HTTP request
 * per test run.  Now the driver sees continuous outbound TCP:80 traffic,
 * enabling DPI (HTTP detection), packet capture, bandwidth growth, and
 * connection enumeration for real internet connections.
 */
static DWORD WINAPI net_thread_tcp_http(LPVOID) {
    bool first = true;
    while (!check_shutdown()) {
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        int rc = getaddrinfo("example.com", "80", &hints, &result);
        if (rc != 0 || !result) {
            interruptible_sleep(2000);
            continue;
        }

        SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == INVALID_SOCKET) {
            freeaddrinfo(result);
            interruptible_sleep(2000);
            continue;
        }

        /* 3-second connect timeout */
        DWORD tv = 3000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

        rc = connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen));
        freeaddrinfo(result);

        if (rc == SOCKET_ERROR) {
            closesocket(sock);
            interruptible_sleep(2000);
            continue;
        }

        const char* http_req =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n"
            "User-Agent: WhosWho-TestTarget/2.0\r\n"
            "\r\n";
        send(sock, http_req, static_cast<int>(strlen(http_req)), 0);

        char buf[4096];
        int total = 0;
        while (total < static_cast<int>(sizeof(buf) - 1)) {
            int n = recv(sock, buf + total, static_cast<int>(sizeof(buf) - 1 - total), 0);
            if (n <= 0) break;
            total += n;
        }

        closesocket(sock);

        if (first && total > 0) {
            signal_ready();
            first = false;
        }

        /* Short interval — continuous traffic */
        interruptible_sleep(2000);
    }
    return 0;
}

/* ========== Network thread: DNS via getaddrinfo + raw UDP ========== */
/*
 * WHY two methods:
 *   1. getaddrinfo() goes through the Windows DNS client service, generating
 *      traffic visible to WFP's ALE hooks (classify_ale_connect) which is how
 *      the driver maps PID→port for DNS flows.
 *   2. Raw UDP to 8.8.8.8:53 generates explicit UDP packets for the transport-
 *      layer classify callbacks.
 * The original only used raw UDP, which bypassed Windows DNS and made DNS
 * capture unreliable.
 */
static DWORD WINAPI net_thread_dns(LPVOID) {
    /* List of domains to resolve — ensures continuous DNS traffic */
    static const char* domains[] = {
        "example.com", "example.org", "example.net",
        "dns.google", "one.one.one.one",
        "cloudflare.com", "github.com", "microsoft.com"
    };
    static constexpr int num_domains = sizeof(domains) / sizeof(domains[0]);
    int domain_idx = 0;
    bool first = true;

    while (!check_shutdown()) {
        const char* domain = domains[domain_idx % num_domains];
        domain_idx++;

        /* Method 1: getaddrinfo — visible to WFP ALE layer */
        {
            struct addrinfo hints{}, *result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            int rc = getaddrinfo(domain, "80", &hints, &result);
            if (rc == 0 && result) {
                freeaddrinfo(result);
                if (first) {
                    signal_ready();
                    first = false;
                }
            }
        }

        /* Method 2: raw UDP DNS query to 8.8.8.8 — visible to transport layer */
        {
            SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock != INVALID_SOCKET) {
                sockaddr_in dest{};
                dest.sin_family = AF_INET;
                dest.sin_port = htons(53);
                inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);

                /* Build minimal DNS query for current domain */
                std::uint8_t dns_query[512];
                int qlen = 0;

                /* Transaction ID */
                dns_query[qlen++] = static_cast<std::uint8_t>((domain_idx >> 8) & 0xFF);
                dns_query[qlen++] = static_cast<std::uint8_t>(domain_idx & 0xFF);
                /* Flags: standard query */
                dns_query[qlen++] = 0x01; dns_query[qlen++] = 0x00;
                /* QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 */
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x01;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x00;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x00;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x00;

                /* Encode domain name as DNS labels */
                const char* p = domain;
                while (*p) {
                    const char* dot = strchr(p, '.');
                    int label_len = dot ? static_cast<int>(dot - p) : static_cast<int>(strlen(p));
                    if (label_len > 63 || qlen + label_len + 1 > 500) break;
                    dns_query[qlen++] = static_cast<std::uint8_t>(label_len);
                    memcpy(&dns_query[qlen], p, static_cast<size_t>(label_len));
                    qlen += label_len;
                    p = dot ? dot + 1 : p + label_len;
                }
                dns_query[qlen++] = 0x00; /* root label */
                /* QTYPE=A, QCLASS=IN */
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x01;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x01;

                sendto(sock, reinterpret_cast<const char*>(dns_query), qlen, 0,
                       reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));

                /* Wait up to 1 second for response */
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(sock, &readfds);
                timeval tv_sel{1, 0};
                if (select(0, &readfds, nullptr, nullptr, &tv_sel) > 0) {
                    char resp[512];
                    recvfrom(sock, resp, sizeof(resp), 0, nullptr, nullptr);
                }
                closesocket(sock);
            }
        }

        interruptible_sleep(2000);
    }
    return 0;
}

/* ========== Network thread: TLS handshake ========== */
/*
 * WHY 5-second loop: the original 80-second idle meant TLS traffic was almost
 * never present during test windows.  The driver's DPI engine checks for TLS
 * ClientHello SNI fields — it needs actual TLS-looking data on port 443.
 */
static DWORD WINAPI net_thread_tls(LPVOID) {
    bool first = true;
    while (!check_shutdown()) {
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        int rc = getaddrinfo("dns.google", "443", &hints, &result);
        if (rc != 0 || !result) {
            interruptible_sleep(5000);
            continue;
        }

        SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == INVALID_SOCKET) {
            freeaddrinfo(result);
            interruptible_sleep(5000);
            continue;
        }

        DWORD tv = 3000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

        rc = connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen));
        freeaddrinfo(result);

        if (rc == SOCKET_ERROR) {
            closesocket(sock);
            interruptible_sleep(5000);
            continue;
        }

        /*
         * Minimal TLS 1.0 ClientHello with SNI extension.
         * WHY we construct this manually: we don't want an OpenSSL dependency
         * in the test target.  The driver's DPI only looks at the record layer
         * (content type 0x16) and SNI extension, so a minimal handshake suffices.
         */
        const std::uint8_t client_hello[] = {
            0x16,                   /* ContentType: Handshake */
            0x03, 0x01,             /* ProtocolVersion: TLS 1.0 */
            0x00, 0x45,             /* Length */
            /* Handshake */
            0x01,                   /* HandshakeType: ClientHello */
            0x00, 0x00, 0x41,       /* Length */
            0x03, 0x03,             /* ClientVersion: TLS 1.2 */
            /* Random (32 bytes) */
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x00,                   /* SessionID Length: 0 */
            0x00, 0x02,             /* CipherSuites Length: 2 */
            0x00, 0x2F,             /* TLS_RSA_WITH_AES_128_CBC_SHA */
            0x01,                   /* CompressionMethods Length: 1 */
            0x00,                   /* null compression */
            /* Extensions */
            0x00, 0x16,             /* Extensions Length: 22 */
            /* SNI extension */
            0x00, 0x00,             /* ExtensionType: server_name */
            0x00, 0x12,             /* Length: 18 */
            0x00, 0x10,             /* ServerNameList Length: 16 */
            0x00,                   /* NameType: host_name */
            0x00, 0x0D,             /* Name Length: 13 */
            /* "test.invalid\0" */
            't', 'e', 's', 't', '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd', '\0'
        };

        send(sock, reinterpret_cast<const char*>(client_hello), sizeof(client_hello), 0);

        /* Read server response (we don't care about content) */
        char buf[4096];
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeval timeout{2, 0};
        if (select(0, &readfds, nullptr, nullptr, &timeout) > 0) {
            recv(sock, buf, sizeof(buf), 0);
        }

        closesocket(sock);

        if (first) {
            signal_ready();
            first = false;
        }

        interruptible_sleep(5000);
    }
    return 0;
}

/* ========== Network thread: Loopback TCP echo server ========== */
/*
 * WHY: Provides deterministic local TCP traffic on a KNOWN port (44444) that
 * doesn't depend on internet connectivity.  The driver's packet capture should
 * see both the client's send and the server's echo on loopback.
 * The original test_target had a TCP listener on an ephemeral port that nothing
 * ever connected to — completely useless for testing.
 */
static DWORD WINAPI net_thread_tcp_echo_server(LPVOID) {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return 1;

    /* Allow address reuse in case of rapid restarts */
    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(LOOPBACK_TCP_PORT);

    if (bind(listener, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listener);
        return 1;
    }

    listen(listener, 5);

    while (!check_shutdown()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);
        timeval tv{1, 0};

        if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
            SOCKET client = accept(listener, nullptr, nullptr);
            if (client != INVALID_SOCKET) {
                /* Echo received data back */
                char buf[1024];
                int n = recv(client, buf, sizeof(buf), 0);
                if (n > 0) {
                    send(client, buf, n, 0);
                }
                closesocket(client);
            }
        }
    }

    closesocket(listener);
    return 0;
}

/* ========== Network thread: Loopback TCP echo client ========== */
/*
 * WHY: Pairs with the echo server to create continuous bidirectional TCP
 * traffic on port 44444.  This ensures store_packet() in the driver always
 * has loopback TCP data to capture, regardless of internet availability.
 */
static DWORD WINAPI net_thread_tcp_echo_client(LPVOID) {
    /* Give server a moment to start listening */
    interruptible_sleep(500);
    bool first = true;

    while (!check_shutdown()) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            interruptible_sleep(1000);
            continue;
        }

        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(LOOPBACK_TCP_PORT);
        inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

        DWORD tv = 2000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

        if (connect(sock, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest)) != SOCKET_ERROR) {
            const char payload[] = "WhosWho-Echo-Test-Payload-12345678";
            send(sock, payload, static_cast<int>(strlen(payload)), 0);

            char echo_buf[256];
            recv(sock, echo_buf, sizeof(echo_buf), 0);

            if (first) {
                signal_ready();
                first = false;
            }
        }

        closesocket(sock);
        interruptible_sleep(1000);
    }
    return 0;
}

/* ========== Network thread: Loopback UDP traffic ========== */
/*
 * WHY: Generates continuous UDP traffic on port 44445 for protocol diversity.
 * The driver's classify_inbound/classify_outbound handle TCP and UDP differently
 * (UDP uses net_udp_cache for PID tracking).  We need UDP traffic to test:
 *   - UDP PID resolution
 *   - UDP packet capture
 *   - UDP bandwidth tracking
 *   - Protocol field correctness in connection enumeration
 */
static DWORD WINAPI net_thread_udp_loopback(LPVOID) {
    SOCKET server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_sock == INVALID_SOCKET) return 1;

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = htons(LOOPBACK_UDP_PORT);

    if (bind(server_sock, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        closesocket(server_sock);
        return 1;
    }

    SOCKET client_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_sock == INVALID_SOCKET) {
        closesocket(server_sock);
        return 1;
    }

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dest.sin_port = htons(LOOPBACK_UDP_PORT);

    bool first = true;
    std::uint32_t seq = 0;

    while (!check_shutdown()) {
        /* Build a packet with a sequence number so we can verify ordering */
        char payload[64];
        int len = snprintf(payload, sizeof(payload), "WW-UDP-SEQ-%08u", seq++);

        sendto(client_sock, payload, len, 0,
               reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));

        /* Read it back from the server socket */
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        timeval tv{0, 500000};  /* 500ms */
        if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
            char recv_buf[128];
            recvfrom(server_sock, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr);
        }

        if (first) {
            signal_ready();
            first = false;
        }

        interruptible_sleep(500);
    }

    closesocket(client_sock);
    closesocket(server_sock);
    return 0;
}

/* ========== Network thread: external TCP to well-known ports ========== */
/*
 * WHY: Generates outbound TCP connections to various ports (HTTP:80, HTTPS:443)
 * so the driver sees real SYN/ACK/FIN sequences for OS fingerprinting,
 * connection enumeration, and TCP state tracking.
 */
static DWORD WINAPI net_thread_tcp_outbound(LPVOID) {
    while (!check_shutdown()) {
        /* Connect to example.com:443 (HTTPS) — different from the HTTP thread's port 80 */
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        int rc = getaddrinfo("example.com", "443", &hints, &result);
        if (rc == 0 && result) {
            SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
            if (sock != INVALID_SOCKET) {
                DWORD tv = 3000;
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

                if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) != SOCKET_ERROR) {
                    /* Send minimal data to generate traffic */
                    const char data[] = "GET / HTTP/1.0\r\n\r\n";
                    send(sock, data, static_cast<int>(strlen(data)), 0);
                    char buf[1024];
                    recv(sock, buf, sizeof(buf), 0);
                }
                closesocket(sock);
            }
            freeaddrinfo(result);
        }

        interruptible_sleep(3000);
    }
    return 0;
}

/* ========== Main ========== */

int main() {
    printf("[test_target] Starting (pid=%u)\n", GetCurrentProcessId());

    WSADATA wsa_data{};
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_rc != 0) {
        printf("[test_target] WSAStartup failed: %d\n", wsa_rc);
        return 1;
    }

    /* Create shutdown event — test_driver signals this to terminate us */
    g_done_event = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestDone");
    if (!g_done_event) {
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestDone");
    }
    if (!g_done_event) {
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    /*
     * WHY: Create readiness event so test_driver can wait until we have
     * active network traffic instead of using a fixed sleep.
     */
    g_ready_event = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestReady");
    if (!g_ready_event) {
        g_ready_event = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestReady");
    }

    /* Populate test buffer with known pattern (for driver memory read tests) */
    for (int i = 0; i < static_cast<int>(sizeof(g_test_buffer)); i++) {
        g_test_buffer[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    /*
     * WHY VirtualAlloc blocks: the driver's memory read/write, query_memory,
     * protect_memory, and enumerate_memory_regions tests need committed pages.
     */
    std::vector<void*> heap_allocs;
    for (int i = 0; i < 8; i++) {
        void* p = VirtualAlloc(nullptr, 0x10000 * (i + 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p) {
            memset(p, 0xCC + i, 0x10000 * (i + 1));
            heap_allocs.push_back(p);
        }
    }

    std::vector<HANDLE> threads;

    /* Non-network worker threads */
    threads.push_back(CreateThread(nullptr, 0, worker_thread_cpu, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_cpu, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_sleep, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_waitable, g_done_event, 0, nullptr));

    /* Network threads — all run continuous loops */
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_http, nullptr, 0, nullptr));        /* HTTP :80 */
    threads.push_back(CreateThread(nullptr, 0, net_thread_dns, nullptr, 0, nullptr));             /* DNS via getaddrinfo + raw UDP */
    threads.push_back(CreateThread(nullptr, 0, net_thread_tls, nullptr, 0, nullptr));             /* TLS :443 */
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_echo_server, nullptr, 0, nullptr)); /* loopback TCP server :44444 */
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_echo_client, nullptr, 0, nullptr)); /* loopback TCP client :44444 */
    threads.push_back(CreateThread(nullptr, 0, net_thread_udp_loopback, nullptr, 0, nullptr));    /* loopback UDP :44445 */
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_outbound, nullptr, 0, nullptr));    /* outbound TCP :443 */

    printf("[test_target] %llu threads started, waiting for shutdown signal...\n",
           static_cast<unsigned long long>(threads.size()));

    /* Wait for either the done event (from test_driver) or 10-minute timeout */
    WaitForSingleObject(g_done_event, 10 * 60 * 1000);

    /* Signal all threads to stop */
    g_shutdown.store(true, std::memory_order_release);

    if (g_done_event) SetEvent(g_done_event);

    /* Wait for threads to finish */
    if (!threads.empty()) {
        WaitForMultipleObjects(static_cast<DWORD>(threads.size()),
                               threads.data(), TRUE, 5000);
        for (HANDLE h : threads) {
            CloseHandle(h);
        }
    }

    /* Free memory */
    for (void* p : heap_allocs) {
        VirtualFree(p, 0, MEM_RELEASE);
    }

    if (g_ready_event) CloseHandle(g_ready_event);
    if (g_done_event) CloseHandle(g_done_event);

    WSACleanup();

    printf("[test_target] Shut down cleanly.\n");
    return 0;
}
