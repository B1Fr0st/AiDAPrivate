

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


static std::atomic<bool> g_shutdown{false};
static HANDLE g_done_event = nullptr;


static volatile std::uint8_t g_test_buffer[4096] = {};
static volatile std::uint64_t g_test_value = 0xCAFEBABE00000000ULL;


static DWORD WINAPI worker_thread_cpu(LPVOID param) {
    (void)param;
    volatile std::uint64_t counter = 0;
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        counter++;

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


static DWORD WINAPI net_thread_tcp_http(LPVOID ) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {

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


        rc = connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen));
        freeaddrinfo(result);

        if (rc == SOCKET_ERROR) {
            closesocket(sock);
            Sleep(5000);
            continue;
        }


        const char* http_req =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n"
            "User-Agent: WhosWho-TestTarget/1.0\r\n"
            "\r\n";
        send(sock, http_req, static_cast<int>(strlen(http_req)), 0);


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


        for (int i = 0; i < 30 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}


static DWORD WINAPI net_thread_udp(LPVOID ) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            Sleep(5000);
            continue;
        }


        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);


        const std::uint8_t dns_query[] = {
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,

            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,
            0x00, 0x01,
            0x00, 0x01
        };

        sendto(sock, reinterpret_cast<const char*>(dns_query), sizeof(dns_query), 0,
               reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));


        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeval tv{2, 0};

        if (select(0, &readfds, nullptr, nullptr, &tv) > 0) {
            char resp[512];
            int n = recvfrom(sock, resp, sizeof(resp), 0, nullptr, nullptr);
            if (n > 0) {
                fprintf(stderr, "[target] UDP DNS response: %d bytes from 8.8.8.8\n", n);
            }
        }

        closesocket(sock);


        for (int i = 0; i < 40 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}


static DWORD WINAPI net_thread_tcp_listener(LPVOID ) {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return 1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

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


static DWORD WINAPI net_thread_tcp_local(LPVOID ) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            Sleep(2000);
            continue;
        }


        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(445);
        inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);


        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        connect(sock, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));


        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        timeval tv{1, 0};
        select(0, nullptr, &writefds, nullptr, &tv);

        closesocket(sock);


        for (int i = 0; i < 50 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}


static DWORD WINAPI net_thread_tls(LPVOID ) {
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


        const std::uint8_t client_hello[] = {
            0x16,
            0x03, 0x01,
            0x00, 0x45,

            0x01,
            0x00, 0x00, 0x41,
            0x03, 0x03,

            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x00,
            0x00, 0x02,
            0x00, 0x2F,
            0x01,
            0x00,

            0x00, 0x16,

            0x00, 0x00,
            0x00, 0x12,
            0x00, 0x10,
            0x00,
            0x00, 0x0D,

            't', 'e', 's', 't', '.', 'i', 'n', 'v', 'a', 'l', 'i', 'd', '\0'
        };

        send(sock, reinterpret_cast<const char*>(client_hello), sizeof(client_hello), 0);


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


        for (int i = 0; i < 80 && !g_shutdown.load(std::memory_order_relaxed); i++)
            Sleep(100);
    }
    return 0;
}


int main() {
    fprintf(stderr, "=== WhosWho Test Target Process ===\n");
    fprintf(stderr, "PID: %lu\n", GetCurrentProcessId());
    fprintf(stderr, "Image Base: 0x%p\n", GetModuleHandleW(nullptr));
    fprintf(stderr, "Generating network traffic for driver testing...\n");
    fprintf(stderr, "Signal Global\\WhosWhoTestDone or wait for timeout to exit.\n\n");


    WSADATA wsa_data{};
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_rc != 0) {
        fprintf(stderr, "[FATAL] WSAStartup failed: %d\n", wsa_rc);
        return 1;
    }


    g_done_event = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestDone");
    if (!g_done_event) {
        DWORD err = GetLastError();
        fprintf(stderr, "[target] CreateEvent Global\\ failed err=%lu, trying Local\\\n", err);
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestDone");
    }
    if (!g_done_event) {
        fprintf(stderr, "[target] CreateEvent Local\\ also failed, using unnamed event\n");
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }


    for (int i = 0; i < static_cast<int>(sizeof(g_test_buffer)); i++) {
        g_test_buffer[i] = static_cast<std::uint8_t>(i & 0xFF);
    }


    std::vector<void*> heap_allocs;
    for (int i = 0; i < 8; i++) {
        void* p = VirtualAlloc(nullptr, 0x10000 * (i + 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p) {
            memset(p, 0xCC + i, 0x10000 * (i + 1));
            heap_allocs.push_back(p);
        }
    }


    std::vector<HANDLE> threads;


    threads.push_back(CreateThread(nullptr, 0, worker_thread_cpu, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_cpu, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_sleep, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, worker_thread_waitable, g_done_event, 0, nullptr));


    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_http, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_udp, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_listener, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_local, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tls, nullptr, 0, nullptr));

    fprintf(stderr, "[target] %llu threads launched (4 workers + 5 network)\n",
            static_cast<unsigned long long>(threads.size()));


    DWORD wait_result = WaitForSingleObject(g_done_event, 10 * 60 * 1000);

    if (wait_result == WAIT_OBJECT_0) {
        fprintf(stderr, "\n[target] Shutdown signaled via event.\n");
    } else {
        fprintf(stderr, "\n[target] Timeout reached, shutting down.\n");
    }


    g_shutdown.store(true, std::memory_order_release);


    if (g_done_event) SetEvent(g_done_event);


    if (!threads.empty()) {
        WaitForMultipleObjects(static_cast<DWORD>(threads.size()),
                               threads.data(), TRUE, 5000);
        for (HANDLE h : threads) {
            CloseHandle(h);
        }
    }


    for (void* p : heap_allocs) {
        VirtualFree(p, 0, MEM_RELEASE);
    }

    if (g_done_event) CloseHandle(g_done_event);

    WSACleanup();

    fprintf(stderr, "[target] Clean shutdown complete.\n");
    return 0;
}
