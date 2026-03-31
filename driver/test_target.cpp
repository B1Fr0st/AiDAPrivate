// ============================================================================
// WhosWho Driver Test Target Application
// ============================================================================
// Purpose: A purpose-built target process that generates real network traffic,
// has multiple threads, exports functions, and allocates various memory regions
// so that EVERY driver feature can be exercised by test_driver.exe.
//
// It stays alive until the named event "Global\\WhosWhoTestDone" is signaled,
// or until the user presses Enter.
// ============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <thread>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

// ── Exported functions (so resolve_export can find them) ─────────────────────
// These are real, callable functions the driver's call_function can invoke.

extern "C" {
    __declspec(dllexport) std::uint64_t __stdcall TestAddNumbers(
        std::uint64_t a, std::uint64_t b, std::uint64_t /*unused1*/, std::uint64_t /*unused2*/)
    {
        return a + b;
    }

    __declspec(dllexport) std::uint64_t __stdcall TestGetTickCount(
        std::uint64_t /*a*/, std::uint64_t /*b*/, std::uint64_t /*c*/, std::uint64_t /*d*/)
    {
        return static_cast<std::uint64_t>(GetTickCount64());
    }

    __declspec(dllexport) std::uint64_t __stdcall TestReturnMagic(
        std::uint64_t /*a*/, std::uint64_t /*b*/, std::uint64_t /*c*/, std::uint64_t /*d*/)
    {
        return 0xDEADC0DE12345678ULL;
    }

    __declspec(dllexport) std::uint64_t __stdcall TestNoOp(
        std::uint64_t /*a*/, std::uint64_t /*b*/, std::uint64_t /*c*/, std::uint64_t /*d*/)
    {
        return 0;
    }
}

// ── Globals ─────────────────────────────────────────────────────────────────

static std::atomic<bool> g_shutdown{false};
static HANDLE g_done_event = nullptr;

// We keep some memory around for the driver to read/write
static volatile std::uint8_t g_test_buffer[4096] = {};
static volatile std::uint64_t g_test_value = 0xCAFEBABE00000000ULL;

// ── Worker threads (so enumerate_threads returns multiple) ──────────────────

static DWORD WINAPI worker_thread_cpu(LPVOID param) {
    (void)param;
    volatile std::uint64_t counter = 0;
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        counter++;
        // Light spin with yield so thread is visible but not burning 100% CPU
        if ((counter & 0xFFFF) == 0)
            SwitchToThread();
    }
    return 0;
}

static DWORD WINAPI worker_thread_sleep(LPVOID param) {
    (void)param;
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        Sleep(200);
    }
    return 0;
}

static DWORD WINAPI worker_thread_waitable(LPVOID param) {
    HANDLE evt = static_cast<HANDLE>(param);
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        WaitForSingleObject(evt, 500);
    }
    return 0;
}

// ── Networking threads ──────────────────────────────────────────────────────

// Thread 1: TCP HTTP connections (generates TCP traffic)
static DWORD WINAPI net_thread_tcp_http(LPVOID /*param*/) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        // Connect to example.com:80 and send a simple HTTP GET
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        int rc = getaddrinfo("example.com", "80", &hints, &result);
        if (rc != 0 || !result) {
            fprintf(stderr, "[target] DNS resolve failed for example.com: %d\n", rc);
            Sleep(5000);
            continue;
        }

        SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == INVALID_SOCKET) {
            freeaddrinfo(result);
            Sleep(5000);
            continue;
        }

        // Non-blocking connect with timeout
        rc = connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen));
        freeaddrinfo(result);

        if (rc == SOCKET_ERROR) {
            closesocket(sock);
            Sleep(5000);
            continue;
        }

        // Send HTTP GET request
        const char* http_req =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n"
            "User-Agent: WhosWho-TestTarget/1.0\r\n"
            "\r\n";
        send(sock, http_req, static_cast<int>(strlen(http_req)), 0);

        // Read response (up to 8KB)
        char buf[8192];
        int total = 0;
        while (total < static_cast<int>(sizeof(buf) - 1)) {
            int n = recv(sock, buf + total, static_cast<int>(sizeof(buf) - 1 - total), 0);
            if (n <= 0) break;
            total += n;
        }
        buf[total] = '\0';

        if (total > 0) {
            fprintf(stderr, "[target] TCP HTTP received %d bytes from example.com\n", total);
        }

        closesocket(sock);

        // Wait 3 seconds before next request
        for (int i = 0; i < 30 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}

// Thread 2: UDP DNS-like traffic (generates UDP packets)
static DWORD WINAPI net_thread_udp(LPVOID /*param*/) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            Sleep(5000);
            continue;
        }

        // Send a UDP packet to Google DNS 8.8.8.8:53
        // This is a minimal DNS query for "example.com" type A
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);

        // Minimal valid DNS query for example.com (type A)
        const std::uint8_t dns_query[] = {
            0x12, 0x34,             // Transaction ID
            0x01, 0x00,             // Flags: standard query
            0x00, 0x01,             // Questions: 1
            0x00, 0x00,             // Answer RRs: 0
            0x00, 0x00,             // Authority RRs: 0
            0x00, 0x00,             // Additional RRs: 0
            // Query: example.com
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,                   // End of name
            0x00, 0x01,             // Type: A
            0x00, 0x01              // Class: IN
        };

        sendto(sock, reinterpret_cast<const char*>(dns_query), sizeof(dns_query), 0,
               reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));

        // Wait for response
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeval tv{2, 0}; // 2 second timeout

        if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
            char resp[512];
            int n = recvfrom(sock, resp, sizeof(resp), 0, nullptr, nullptr);
            if (n > 0) {
                fprintf(stderr, "[target] UDP DNS response: %d bytes from 8.8.8.8\n", n);
            }
        }

        closesocket(sock);

        // Wait 4 seconds
        for (int i = 0; i < 40 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}

// Thread 3: TCP listener (so we have a listening socket for socket handle enumeration)
static DWORD WINAPI net_thread_tcp_listener(LPVOID /*param*/) {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return 1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0); // Let OS pick a port

    if (bind(listener, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listener);
        return 1;
    }

    int addrlen = sizeof(addr);
    getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addrlen);
    fprintf(stderr, "[target] TCP listener on port %u\n", ntohs(addr.sin_port));

    listen(listener, 5);

    while (!g_shutdown.load(std::memory_order_relaxed)) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);
        timeval tv{1, 0};

        if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
            SOCKET client = accept(listener, nullptr, nullptr);
            if (client != INVALID_SOCKET) {
                // Echo back anything received, then close
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

// Thread 4: Periodic TCP connections to localhost echo server
// (Generates local connections visible in connection enumeration)
static DWORD WINAPI net_thread_tcp_local(LPVOID /*param*/) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            Sleep(2000);
            continue;
        }

        // Connect to a common service that's likely running (or just attempt)
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(445); // SMB - usually open on Windows
        inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

        // Set a short connect timeout via non-blocking socket
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        connect(sock, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));

        // Wait briefly for connection
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        timeval tv{1, 0};
        select(0, nullptr, &writefds, nullptr, &tv);

        closesocket(sock);

        // Wait 5 seconds
        for (int i = 0; i < 50 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}

// Thread 5: HTTPS/TLS connection (generates TLS traffic for DPI)
static DWORD WINAPI net_thread_tls(LPVOID /*param*/) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        int rc = getaddrinfo("dns.google", "443", &hints, &result);
        if (rc != 0 || !result) {
            Sleep(8000);
            continue;
        }

        SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == INVALID_SOCKET) {
            freeaddrinfo(result);
            Sleep(8000);
            continue;
        }

        rc = connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen));
        freeaddrinfo(result);

        if (rc == SOCKET_ERROR) {
            closesocket(sock);
            Sleep(8000);
            continue;
        }

        // Send a TLS ClientHello-like payload (just the TCP connect is enough
        // to generate a connection entry; the raw bytes will be visible in DPI)
        // We send a minimal TLS 1.0 ClientHello to trigger TLS detection
        const std::uint8_t client_hello[] = {
            0x16,                   // ContentType: Handshake
            0x03, 0x01,             // ProtocolVersion: TLS 1.0
            0x00, 0x45,             // Length: 69 bytes
            // Handshake
            0x01,                   // HandshakeType: ClientHello
            0x00, 0x00, 0x41,       // Length: 65
            0x03, 0x03,             // ClientVersion: TLS 1.2
            // Random (32 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x00,                   // SessionID length: 0
            0x00, 0x02,             // CipherSuites length: 2
            0x00, 0x2F,             // TLS_RSA_WITH_AES_128_CBC_SHA
            0x01,                   // CompressionMethods length: 1
            0x00,                   // CompressionMethod: null
            // Extensions
            0x00, 0x16,             // Extensions length: 22
            // SNI extension
            0x00, 0x00,             // Type: server_name
            0x00, 0x12,             // Length: 18
            0x00, 0x10,             // ServerNameList length: 16
            0x00,                   // NameType: host_name
            0x00, 0x0D,             // Name length: 13
            // "test.invalid" (13 bytes)
            't', 'e', 's', 't', '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd', '\0'
        };

        send(sock, reinterpret_cast<const char*>(client_hello), sizeof(client_hello), 0);

        // Read response (even if it's a TLS alert, it generates traffic)
        char buf[4096];
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeval tv{2, 0};
        if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
            int n = recv(sock, buf, sizeof(buf), 0);
            if (n > 0) {
                fprintf(stderr, "[target] TLS response: %d bytes from dns.google:443\n", n);
            }
        }

        closesocket(sock);

        // Wait 8 seconds
        for (int i = 0; i < 80 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}

// ── Main ────────────────────────────────────────────────────────────────────

int main() {
    fprintf(stderr, "=== WhosWho Test Target Process ===\n");
    fprintf(stderr, "PID: %lu\n", GetCurrentProcessId());
    fprintf(stderr, "Image Base: 0x%p\n", GetModuleHandleW(nullptr));
    fprintf(stderr, "Generating network traffic for driver testing...\n");
    fprintf(stderr, "Press Enter or signal Global\\WhosWhoTestDone to exit.\n\n");

    // Initialize Winsock
    WSADATA wsa_data{};
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_rc != 0) {
        fprintf(stderr, "[FATAL] WSAStartup failed: %d\n", wsa_rc);
        return 1;
    }

    // Create the named event (manual-reset, initially non-signaled)
    g_done_event = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestDone");
    if (!g_done_event) {
        // Fall back to local event
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    // Fill test buffer with a recognizable pattern
    for (int i = 0; i < static_cast<int>(sizeof(g_test_buffer)); i++) {
        g_test_buffer[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    // Allocate some heap memory (for enumerate_memory_regions to find)
    std::vector<void*> heap_allocs;
    for (int i = 0; i < 8; i++) {
        void* p = VirtualAlloc(nullptr, 0x10000 * (i + 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p) {
            memset(p, 0xCC + i, 0x10000 * (i + 1));
            heap_allocs.push_back(p);
        }
    }

    // ── Launch threads ──
    std::vector<HANDLE> threads;

    // Worker threads (non-network)
    threads.push_back(CreateThread(nullptr, 0, worker_thread_cpu, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_cpu, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_sleep, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_waitable, g_done_event, 0, nullptr));

    // Network threads
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_http, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_udp, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_listener, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_local, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tls, nullptr, 0, nullptr));

    fprintf(stderr, "[target] %llu threads launched (4 workers + 5 network)\n",
            static_cast<unsigned long long>(threads.size()));

    // ── Wait for shutdown ──
    // Wait on either: Enter key, named event, or 10 minutes max
    HANDLE stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE wait_handles[2] = { g_done_event, stdin_handle };

    DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, 10 * 60 * 1000);

    if (wait_result == WAIT_OBJECT_0) {
        fprintf(stderr, "\n[target] Shutdown signaled via event.\n");
    } else if (wait_result == WAIT_OBJECT_0 + 1) {
        // Consume the input
        FlushConsoleInputBuffer(stdin_handle);
        fprintf(stderr, "\n[target] Shutdown via console input.\n");
    } else {
        fprintf(stderr, "\n[target] Timeout reached, shutting down.\n");
    }

    // ── Cleanup ──
    g_shutdown.store(true, std::memory_order_release);

    // Signal the event so waitable thread wakes up
    if (g_done_event) SetEvent(g_done_event);

    // Wait for all threads to finish (5 second timeout)
    if (!threads.empty()) {
        WaitForMultipleObjects(static_cast<DWORD>(threads.size()),
                               threads.data(), TRUE, 5000);
        for (HANDLE h : threads) {
            CloseHandle(h);
        }
    }

    // Free heap allocations
    for (void* p : heap_allocs) {
        VirtualFree(p, 0, MEM_RELEASE);
    }

    if (g_done_event) CloseHandle(g_done_event);

    WSACleanup();

    fprintf(stderr, "[target] Clean shutdown complete.\n");
    return 0;
}
