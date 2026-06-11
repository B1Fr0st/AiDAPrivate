#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

constexpr DWORD k_default_wait_ms = 60000;
constexpr DWORD k_default_interval_ms = 200;
constexpr int k_default_iterations = 8;
constexpr SIZE_T k_guard_region_size = 0x1000;

struct config_t {
    std::wstring event_prefix = L"Local\\AiDANetworkHookSidecar";
    DWORD wait_ms = k_default_wait_ms;
    DWORD interval_ms = k_default_interval_ms;
    int iterations = k_default_iterations;
    bool no_wait = false;
    bool verbose = false;
    std::string requested_mode;
};

struct handles_t {
    HANDLE ready = nullptr;
    HANDLE go = nullptr;
    HANDLE done = nullptr;
};

struct socket_pair_t {
    std::atomic<SOCKET> listener{INVALID_SOCKET};
    std::atomic<SOCKET> client{INVALID_SOCKET};
    std::atomic<SOCKET> accepted{INVALID_SOCKET};
    HANDLE accept_thread = nullptr;
    std::atomic<bool> stop{false};
    std::atomic<bool> accept_exited{false};
    unsigned short port = 0;
};

using socket_pair_ptr = std::shared_ptr<socket_pair_t>;

volatile LONG g_stop = 0;

std::wstring widen(const char* s) {
    if (!s || !*s)
        return {};
    const int need = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (need <= 0)
        return {};
    std::wstring out(static_cast<size_t>(need), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), need);
    if (!out.empty())
        out.pop_back();
    return out;
}

std::string narrow(const std::wstring& s) {
    if (s.empty())
        return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (need <= 0)
        return {};
    std::string out(static_cast<size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), need, nullptr, nullptr);
    if (!out.empty())
        out.pop_back();
    return out;
}

std::wstring event_name(const config_t& cfg, const wchar_t* suffix) {
    std::wstring name = cfg.event_prefix;
    name += suffix;
    return name;
}

void log_line(const char* tag, const char* msg) {
    std::printf("[%s] %s\n", tag, msg);
    std::fflush(stdout);
}

void print_usage() {
    std::printf("AiDA network hook sidecar\n");
    std::printf("Usage: AiDA_NetworkHookSidecar.exe [options]\n");
    std::printf("  --event-prefix <name>       Base name for Ready/Go/Done events\n");
    std::printf("  --wait-ms <n>               Go-event wait timeout, 0 for infinite\n");
    std::printf("  --no-wait                   Do not wait for Go event\n");
    std::printf("  --iterations <n>            Network and buffer mutation count\n");
    std::printf("  --interval-ms <n>           Delay between iterations\n");
    std::printf("  --mode plain|protected      Requested harness mode label\n");
    std::printf("  --verbose                   Emit per-iteration diagnostics\n");
    std::fflush(stdout);
}

bool parse_u32(const char* s, DWORD& out) {
    if (!s || !*s)
        return false;
    char* end = nullptr;
    const unsigned long v = std::strtoul(s, &end, 10);
    if (end == s || *end != '\0')
        return false;
    out = static_cast<DWORD>(v);
    return true;
}

bool parse_int(const char* s, int& out) {
    if (!s || !*s)
        return false;
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0')
        return false;
    out = static_cast<int>(v);
    return true;
}

config_t parse_args(int argc, char** argv) {
    config_t cfg;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--event-prefix") == 0 && i + 1 < argc) {
            cfg.event_prefix = widen(argv[++i]);
        } else if (std::strcmp(argv[i], "--wait-ms") == 0 && i + 1 < argc) {
            parse_u32(argv[++i], cfg.wait_ms);
        } else if (std::strcmp(argv[i], "--no-wait") == 0) {
            cfg.no_wait = true;
        } else if (std::strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            parse_int(argv[++i], cfg.iterations);
        } else if (std::strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            parse_u32(argv[++i], cfg.interval_ms);
        } else if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            cfg.requested_mode = argv[++i];
        } else if (std::strcmp(argv[i], "--verbose") == 0) {
            cfg.verbose = true;
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage();
            ExitProcess(0);
        }
    }
    if (cfg.event_prefix.empty())
        cfg.event_prefix = L"Local\\AiDANetworkHookSidecar";
    if (cfg.iterations < 1)
        cfg.iterations = 1;
    if (cfg.iterations > 128)
        cfg.iterations = 128;
    if (cfg.interval_ms < 10)
        cfg.interval_ms = 10;
    if (cfg.interval_ms > 10000)
        cfg.interval_ms = 10000;
    return cfg;
}

BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        InterlockedExchange(&g_stop, 1);
        return TRUE;
    }
    return FALSE;
}

bool create_events(const config_t& cfg, handles_t& h) {
    const std::wstring ready = event_name(cfg, L"Ready");
    const std::wstring go = event_name(cfg, L"Go");
    const std::wstring done = event_name(cfg, L"Done");
    h.ready = CreateEventW(nullptr, TRUE, FALSE, ready.c_str());
    h.go = CreateEventW(nullptr, TRUE, FALSE, go.c_str());
    h.done = CreateEventW(nullptr, TRUE, FALSE, done.c_str());
    if (h.ready)
        ResetEvent(h.ready);
    if (h.done)
        ResetEvent(h.done);
    std::printf("[sync] ready=%s go=%s done=%s handles=%p/%p/%p\n",
        narrow(ready).c_str(),
        narrow(go).c_str(),
        narrow(done).c_str(),
        h.ready,
        h.go,
        h.done);
    std::fflush(stdout);
    return h.ready && h.go && h.done;
}

void close_events(handles_t& h) {
    if (h.ready)
        CloseHandle(h.ready);
    if (h.go)
        CloseHandle(h.go);
    if (h.done)
        CloseHandle(h.done);
    h = {};
}

void close_socket_slot(std::atomic<SOCKET>& slot) {
    const SOCKET s = slot.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
}

DWORD WINAPI accept_thread_proc(void* p) {
    std::unique_ptr<socket_pair_ptr> owner(static_cast<socket_pair_ptr*>(p));
    socket_pair_ptr pair;
    if (owner)
        pair = std::move(*owner);
    if (!pair)
        return 1;
    const SOCKET listener = pair->listener.load(std::memory_order_acquire);
    SOCKET accepted = INVALID_SOCKET;
    if (listener != INVALID_SOCKET)
        accepted = accept(listener, nullptr, nullptr);
    pair->accepted.store(accepted, std::memory_order_release);
    if (accepted == INVALID_SOCKET) {
        const int err = listener == INVALID_SOCKET ? WSAENOTSOCK : WSAGetLastError();
        pair->accept_exited.store(true, std::memory_order_release);
        std::printf("[loopback] accept_failed err=%d stop=%d\n",
            err,
            pair->stop.load(std::memory_order_acquire) ? 1 : 0);
        std::fflush(stdout);
        return 1;
    }
    char buf[512];
    while (!pair->stop.load(std::memory_order_acquire)) {
        const int n = recv(accepted, buf, static_cast<int>(sizeof(buf)), 0);
        if (n == 0)
            break;
        if (n == SOCKET_ERROR) {
            const int e = WSAGetLastError();
            if (e == WSAEINTR || e == WSAEWOULDBLOCK)
                continue;
            break;
        }
    }
    close_socket_slot(pair->accepted);
    pair->accept_exited.store(true, std::memory_order_release);
    return 0;
}

bool setup_loopback(const socket_pair_ptr& pair) {
    if (!pair)
        return false;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    pair->listener.store(listener, std::memory_order_release);
    if (listener == INVALID_SOCKET)
        return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        return false;
    if (listen(listener, 1) == SOCKET_ERROR)
        return false;

    int len = sizeof(addr);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len) == SOCKET_ERROR)
        return false;
    pair->port = ntohs(addr.sin_port);
    auto* thread_state = new (std::nothrow) socket_pair_ptr(pair);
    if (!thread_state)
        return false;
    pair->accept_thread = CreateThread(nullptr, 0, accept_thread_proc, thread_state, 0, nullptr);
    if (!pair->accept_thread) {
        delete thread_state;
        return false;
    }

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    pair->client.store(client, std::memory_order_release);
    if (client == INVALID_SOCKET)
        return false;
    if (connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        return false;
    return true;
}

void close_socket_pair(const socket_pair_ptr& pair) {
    if (!pair)
        return;
    pair->stop.store(true, std::memory_order_release);
    close_socket_slot(pair->client);
    close_socket_slot(pair->accepted);
    close_socket_slot(pair->listener);
    if (pair->accept_thread) {
        const DWORD wr = WaitForSingleObject(pair->accept_thread, 2000);
        const DWORD wait_err = wr == WAIT_FAILED ? GetLastError() : 0;
        const bool exited = wr == WAIT_OBJECT_0 || pair->accept_exited.load(std::memory_order_acquire);
        std::printf("[loopback] accept_thread_wait result=0x%08lX exited=%d stop=%d err=%lu listener=0x%llX client=0x%llX accepted=0x%llX retained=%d\n",
            static_cast<unsigned long>(wr),
            exited ? 1 : 0,
            pair->stop.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long>(wait_err),
            static_cast<unsigned long long>(pair->listener.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(pair->client.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(pair->accepted.load(std::memory_order_acquire)),
            exited ? 0 : 1);
        std::fflush(stdout);
        CloseHandle(pair->accept_thread);
        pair->accept_thread = nullptr;
    }
}

void mutate_guard_region(std::uint8_t* region, int iteration) {
    const char* prefix = "AIDA_PG_SNIFF_DETERMINISTIC_BUFFER";
    const int written = std::snprintf(reinterpret_cast<char*>(region), 256,
        "%s iteration=%03d pid=%lu tick=%08lu",
        prefix,
        iteration,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(iteration * 1111));
    if (written > 0) {
        const size_t off = 512 + static_cast<size_t>((iteration * 37) % 256);
        region[off] = static_cast<std::uint8_t>(0x41 + (iteration % 26));
        region[off + 1] = static_cast<std::uint8_t>(0x61 + (iteration % 26));
    }
    volatile std::uint8_t sink = region[static_cast<size_t>((iteration * 53) % 768)];
    (void)sink;
}

bool emit_send_payloads(SOCKET s, int iteration) {
    char send_payload[160]{};
    const int send_len = std::snprintf(send_payload, sizeof(send_payload),
        "AIDA_PRE_ENCRYPT_SEND iteration=%03d pid=%lu\r\n",
        iteration,
        static_cast<unsigned long>(GetCurrentProcessId()));
    if (send_len <= 0)
        return false;
    const int sent = send(s, send_payload, send_len, 0);
    if (sent == SOCKET_ERROR)
        return false;

    char wsa_payload_a[96]{};
    char wsa_payload_b[96]{};
    const int len_a = std::snprintf(wsa_payload_a, sizeof(wsa_payload_a),
        "AIDA_PRE_ENCRYPT_WSASEND_A iteration=%03d ", iteration);
    const int len_b = std::snprintf(wsa_payload_b, sizeof(wsa_payload_b),
        "AIDA_PRE_ENCRYPT_WSASEND_B pid=%lu\r\n",
        static_cast<unsigned long>(GetCurrentProcessId()));
    if (len_a <= 0 || len_b <= 0)
        return false;
    WSABUF bufs[2]{};
    bufs[0].buf = wsa_payload_a;
    bufs[0].len = static_cast<ULONG>(len_a);
    bufs[1].buf = wsa_payload_b;
    bufs[1].len = static_cast<ULONG>(len_b);
    DWORD bytes = 0;
    return WSASend(s, bufs, 2, &bytes, 0, nullptr, nullptr) != SOCKET_ERROR;
}

const char* build_mode() {
#ifdef AIDA_SIDECAR_PROTECTED_BUILD
    return "protected";
#else
    return "plain";
#endif
}

int run_sidecar(const config_t& cfg) {
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_line("error", "WSAStartup failed");
        return 10;
    }

    auto* region = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, k_guard_region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!region) {
        WSACleanup();
        log_line("error", "VirtualAlloc failed");
        return 11;
    }

    std::memset(region, 0, k_guard_region_size);
    std::memcpy(region, "AIDA_PG_SNIFF_READY", 19);

    auto sockets = std::make_shared<socket_pair_t>();
    if (!setup_loopback(sockets)) {
        close_socket_pair(sockets);
        VirtualFree(region, 0, MEM_RELEASE);
        WSACleanup();
        log_line("error", "loopback setup failed");
        return 12;
    }

    handles_t events{};
    if (!create_events(cfg, events)) {
        close_socket_pair(sockets);
        VirtualFree(region, 0, MEM_RELEASE);
        WSACleanup();
        log_line("error", "event setup failed");
        return 13;
    }

    std::printf("[sidecar] pid=%lu build_mode=%s requested_mode=%s iterations=%d interval_ms=%lu wait_ms=%lu\n",
        static_cast<unsigned long>(GetCurrentProcessId()),
        build_mode(),
        cfg.requested_mode.empty() ? "default" : cfg.requested_mode.c_str(),
        cfg.iterations,
        static_cast<unsigned long>(cfg.interval_ms),
        static_cast<unsigned long>(cfg.wait_ms));
    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    std::printf("[sidecar] module_base=%p ws2_32=%p send=%p WSASend=%p\n",
        GetModuleHandleW(nullptr),
        ws2,
        ws2 ? reinterpret_cast<void*>(GetProcAddress(ws2, "send")) : nullptr,
        ws2 ? reinterpret_cast<void*>(GetProcAddress(ws2, "WSASend")) : nullptr);
    std::printf("[sidecar] pg_buffer=0x%llX pg_size=%llu loopback_port=%u\n",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(region)),
        static_cast<unsigned long long>(k_guard_region_size),
        static_cast<unsigned>(sockets->port));
    std::fflush(stdout);

    SetEvent(events.ready);
    log_line("sync", "ready signaled");

    if (!cfg.no_wait) {
        const DWORD timeout = cfg.wait_ms == 0 ? INFINITE : cfg.wait_ms;
        const DWORD wr = WaitForSingleObject(events.go, timeout);
        if (wr != WAIT_OBJECT_0) {
            std::printf("[sync] go wait failed result=0x%08lX err=%lu\n",
                static_cast<unsigned long>(wr),
                static_cast<unsigned long>(GetLastError()));
            SetEvent(events.done);
            close_events(events);
            close_socket_pair(sockets);
            VirtualFree(region, 0, MEM_RELEASE);
            WSACleanup();
            return 14;
        }
    }

    log_line("sync", "go observed");

    int network_failures = 0;
    for (int i = 0; i < cfg.iterations && !g_stop; ++i) {
        mutate_guard_region(region, i);
        if (!emit_send_payloads(sockets->client.load(std::memory_order_acquire), i))
            ++network_failures;
        if (cfg.verbose) {
            std::printf("[sidecar] iteration=%d guard_first=\"%.64s\" send_marker=AIDA_PRE_ENCRYPT_SEND wsasend_marker=AIDA_PRE_ENCRYPT_WSASEND_A network_failures=%d\n",
                i,
                reinterpret_cast<const char*>(region),
                network_failures);
            std::fflush(stdout);
        }
        Sleep(cfg.interval_ms);
    }

    std::printf("[sidecar] complete iterations=%d network_failures=%d\n", cfg.iterations, network_failures);
    std::fflush(stdout);
    SetEvent(events.done);
    close_events(events);
    close_socket_pair(sockets);
    VirtualFree(region, 0, MEM_RELEASE);
    WSACleanup();
    return network_failures == 0 ? 0 : 20;
}

}

int main(int argc, char** argv) {
    config_t cfg = parse_args(argc, argv);
    return run_sidecar(cfg);
}
