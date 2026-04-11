

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
static HANDLE g_done_event  = nullptr;
static HANDLE g_ready_event = nullptr;
static std::atomic<int> g_ready_count{0};


static volatile std::uint8_t  g_test_buffer[4096] = {};
static volatile std::uint64_t g_test_value = 0xCAFEBABE00000000ULL;


static constexpr int LOOPBACK_TCP_PORT = 44444;
static constexpr int LOOPBACK_UDP_PORT = 44445;


static void signal_ready() {
    int prev = g_ready_count.fetch_add(1, std::memory_order_relaxed);
    if (prev >= 1 && g_ready_event) {
        SetEvent(g_ready_event);
    }
}

static bool check_shutdown() {
    return g_shutdown.load(std::memory_order_relaxed);
}


static void interruptible_sleep(int ms) {
    int elapsed = 0;
    while (elapsed < ms && !check_shutdown()) {
        int chunk = (ms - elapsed < 100) ? (ms - elapsed) : 100;
        Sleep(static_cast<DWORD>(chunk));
        elapsed += chunk;
    }
}


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


        interruptible_sleep(2000);
    }
    return 0;
}


static DWORD WINAPI net_thread_dns(LPVOID) {

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


        {
            SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock != INVALID_SOCKET) {
                sockaddr_in dest{};
                dest.sin_family = AF_INET;
                dest.sin_port = htons(53);
                inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);


                std::uint8_t dns_query[512];
                int qlen = 0;


                dns_query[qlen++] = static_cast<std::uint8_t>((domain_idx >> 8) & 0xFF);
                dns_query[qlen++] = static_cast<std::uint8_t>(domain_idx & 0xFF);

                dns_query[qlen++] = 0x01; dns_query[qlen++] = 0x00;

                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x01;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x00;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x00;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x00;


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
                dns_query[qlen++] = 0x00;

                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x01;
                dns_query[qlen++] = 0x00; dns_query[qlen++] = 0x01;

                sendto(sock, reinterpret_cast<const char*>(dns_query), qlen, 0,
                       reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));


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


static DWORD WINAPI net_thread_tcp_echo_server(LPVOID) {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return 1;


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


static DWORD WINAPI net_thread_tcp_echo_client(LPVOID) {

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

        char payload[64];
        int len = snprintf(payload, sizeof(payload), "WW-UDP-SEQ-%08u", seq++);

        sendto(client_sock, payload, len, 0,
               reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));


        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        timeval tv{0, 500000};
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


static DWORD WINAPI net_thread_tcp_outbound(LPVOID) {
    while (!check_shutdown()) {

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


int main() {
    printf("[test_target] Starting (pid=%u)\n", GetCurrentProcessId());

    WSADATA wsa_data{};
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_rc != 0) {
        printf("[test_target] WSAStartup failed: %d\n", wsa_rc);
        return 1;
    }


    g_done_event = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestDone");
    if (!g_done_event) {
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestDone");
    }
    if (!g_done_event) {
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }


    g_ready_event = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestReady");
    if (!g_ready_event) {
        g_ready_event = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestReady");
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
    threads.push_back(CreateThread(nullptr, 0, net_thread_dns, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tls, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_echo_server, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_echo_client, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_udp_loopback, nullptr, 0, nullptr));
    threads.push_back(CreateThread(nullptr, 0, net_thread_tcp_outbound, nullptr, 0, nullptr));

    printf("[test_target] %llu threads started, waiting for shutdown signal...\n",
           static_cast<unsigned long long>(threads.size()));


    WaitForSingleObject(g_done_event, 10 * 60 * 1000);


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

    if (g_ready_event) CloseHandle(g_ready_event);
    if (g_done_event) CloseHandle(g_done_event);

    WSACleanup();

    printf("[test_target] Shut down cleanly.\n");
    return 0;
}
