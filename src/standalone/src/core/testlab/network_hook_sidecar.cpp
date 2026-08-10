#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
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
ULONGLONG g_started_ms = 0;

ULONGLONG elapsed_ms() {
    const ULONGLONG now = GetTickCount64();
    return g_started_ms == 0 ? 0 : now - g_started_ms;
}

void log_phase_fmt(const char* phase, const char* fmt, ...) {
    std::printf("[sidecar] phase=%s pid=%lu tid=%lu elapsed_ms=%llu ",
        phase ? phase : "",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(elapsed_ms()));
    va_list args;
    va_start(args, fmt);
    if (fmt)
        std::vprintf(fmt, args);
    va_end(args);
    std::printf("\n");
    std::fflush(stdout);
}

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

void log_process_args(int argc, char** argv) {
    const char* cmd = GetCommandLineA();
    log_phase_fmt("process_entry", "argc=%d command_line=%s", argc, cmd ? cmd : "");
    for (int i = 0; i < argc; ++i)
        log_phase_fmt("arg", "index=%d value=%s", i, argv && argv[i] ? argv[i] : "");
}

void print_usage() {
    std::printf("AiDA network hook sidecar\n");
    std::printf("Usage: AiDA_NetworkHookSidecar.exe [options]\n");
    std::printf("  --event-prefix <name>       Base name for Ready/Go/Done events\n");
    std::printf("  --wait-ms <n>               Go-event wait timeout, 0 for infinite\n");
    std::printf("  --no-wait                   Do not wait for Go event\n");
    std::printf("  --iterations <n>            Network and buffer mutation count\n");
    std::printf("  --interval-ms <n>           Delay between iterations\n");
    std::printf("  --mode plain                Requested harness mode label\n");
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
    log_phase_fmt("events_create_begin", "ready=%s go=%s done=%s",
        narrow(ready).c_str(),
        narrow(go).c_str(),
        narrow(done).c_str());
    SetLastError(ERROR_SUCCESS);
    h.ready = CreateEventW(nullptr, TRUE, FALSE, ready.c_str());
    const DWORD ready_err = h.ready ? ERROR_SUCCESS : GetLastError();
    SetLastError(ERROR_SUCCESS);
    h.go = CreateEventW(nullptr, TRUE, FALSE, go.c_str());
    const DWORD go_err = h.go ? ERROR_SUCCESS : GetLastError();
    SetLastError(ERROR_SUCCESS);
    h.done = CreateEventW(nullptr, TRUE, FALSE, done.c_str());
    const DWORD done_err = h.done ? ERROR_SUCCESS : GetLastError();
    BOOL reset_ready = FALSE;
    DWORD reset_ready_err = ERROR_SUCCESS;
    BOOL reset_done = FALSE;
    DWORD reset_done_err = ERROR_SUCCESS;
    if (h.ready) {
        SetLastError(ERROR_SUCCESS);
        reset_ready = ResetEvent(h.ready);
        reset_ready_err = reset_ready ? ERROR_SUCCESS : GetLastError();
    }
    if (h.done) {
        SetLastError(ERROR_SUCCESS);
        reset_done = ResetEvent(h.done);
        reset_done_err = reset_done ? ERROR_SUCCESS : GetLastError();
    }
    std::printf("[sync] ready=%s go=%s done=%s handles=%p/%p/%p\n",
        narrow(ready).c_str(),
        narrow(go).c_str(),
        narrow(done).c_str(),
        h.ready,
        h.go,
        h.done);
    std::fflush(stdout);
    log_phase_fmt("events_create_end",
        "ready_handle=%p ready_err=%lu go_handle=%p go_err=%lu done_handle=%p done_err=%lu reset_ready=%d reset_ready_err=%lu reset_done=%d reset_done_err=%lu",
        h.ready,
        static_cast<unsigned long>(ready_err),
        h.go,
        static_cast<unsigned long>(go_err),
        h.done,
        static_cast<unsigned long>(done_err),
        reset_ready ? 1 : 0,
        static_cast<unsigned long>(reset_ready_err),
        reset_done ? 1 : 0,
        static_cast<unsigned long>(reset_done_err));
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
    log_phase_fmt("accept_thread_enter", "state_ptr=%p", p);
    std::unique_ptr<socket_pair_ptr> owner(static_cast<socket_pair_ptr*>(p));
    socket_pair_ptr pair;
    if (owner)
        pair = std::move(*owner);
    if (!pair) {
        log_phase_fmt("accept_thread_exit", "exit_code=1 reason=no_pair");
        return 1;
    }
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
        log_phase_fmt("accept_thread_exit", "exit_code=1 listener=0x%llX accepted=0x%llX err=%d stop=%d",
            static_cast<unsigned long long>(listener),
            static_cast<unsigned long long>(accepted),
            err,
            pair->stop.load(std::memory_order_acquire) ? 1 : 0);
        return 1;
    }
    log_phase_fmt("accept_thread_accepted", "listener=0x%llX accepted=0x%llX",
        static_cast<unsigned long long>(listener),
        static_cast<unsigned long long>(accepted));
    char buf[512];
    unsigned long long recv_calls = 0;
    unsigned long long recv_bytes = 0;
    int last_recv_error = 0;
    while (!pair->stop.load(std::memory_order_acquire)) {
        const int n = recv(accepted, buf, static_cast<int>(sizeof(buf)), 0);
        if (n == 0) {
            last_recv_error = 0;
            break;
        }
        if (n == SOCKET_ERROR) {
            const int e = WSAGetLastError();
            last_recv_error = e;
            if (e == WSAEINTR || e == WSAEWOULDBLOCK)
                continue;
            break;
        }
        ++recv_calls;
        recv_bytes += static_cast<unsigned long long>(n);
    }
    close_socket_slot(pair->accepted);
    pair->accept_exited.store(true, std::memory_order_release);
    log_phase_fmt("accept_thread_exit", "exit_code=0 recv_calls=%llu recv_bytes=%llu last_recv_error=%d stop=%d",
        recv_calls,
        recv_bytes,
        last_recv_error,
        pair->stop.load(std::memory_order_acquire) ? 1 : 0);
    return 0;
}

bool setup_loopback(const socket_pair_ptr& pair) {
    if (!pair)
        return false;
    log_phase_fmt("socket_setup_begin", "pair=%p", pair.get());
    SetLastError(ERROR_SUCCESS);
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int wsa_err = listener == INVALID_SOCKET ? WSAGetLastError() : 0;
    pair->listener.store(listener, std::memory_order_release);
    log_phase_fmt("socket_listener", "socket=0x%llX err=%d",
        static_cast<unsigned long long>(listener),
        wsa_err);
    if (listener == INVALID_SOCKET)
        return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    const int bind_rc = bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    wsa_err = bind_rc == SOCKET_ERROR ? WSAGetLastError() : 0;
    log_phase_fmt("socket_bind", "socket=0x%llX rc=%d err=%d",
        static_cast<unsigned long long>(listener),
        bind_rc,
        wsa_err);
    if (bind_rc == SOCKET_ERROR)
        return false;
    const int listen_rc = listen(listener, 1);
    wsa_err = listen_rc == SOCKET_ERROR ? WSAGetLastError() : 0;
    log_phase_fmt("socket_listen", "socket=0x%llX rc=%d err=%d backlog=1",
        static_cast<unsigned long long>(listener),
        listen_rc,
        wsa_err);
    if (listen_rc == SOCKET_ERROR)
        return false;

    int len = sizeof(addr);
    const int name_rc = getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
    wsa_err = name_rc == SOCKET_ERROR ? WSAGetLastError() : 0;
    log_phase_fmt("socket_getsockname_listener", "socket=0x%llX rc=%d err=%d port=%u",
        static_cast<unsigned long long>(listener),
        name_rc,
        wsa_err,
        name_rc == SOCKET_ERROR ? 0u : static_cast<unsigned>(ntohs(addr.sin_port)));
    if (name_rc == SOCKET_ERROR)
        return false;
    pair->port = ntohs(addr.sin_port);
    auto* thread_state = new (std::nothrow) socket_pair_ptr(pair);
    if (!thread_state)
        return false;
    SetLastError(ERROR_SUCCESS);
    pair->accept_thread = CreateThread(nullptr, 0, accept_thread_proc, thread_state, 0, nullptr);
    const DWORD thread_err = pair->accept_thread ? ERROR_SUCCESS : GetLastError();
    log_phase_fmt("socket_accept_thread", "handle=%p err=%lu",
        pair->accept_thread,
        static_cast<unsigned long>(thread_err));
    if (!pair->accept_thread) {
        delete thread_state;
        return false;
    }

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wsa_err = client == INVALID_SOCKET ? WSAGetLastError() : 0;
    pair->client.store(client, std::memory_order_release);
    log_phase_fmt("socket_client", "socket=0x%llX err=%d",
        static_cast<unsigned long long>(client),
        wsa_err);
    if (client == INVALID_SOCKET)
        return false;
    const int connect_rc = connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    wsa_err = connect_rc == SOCKET_ERROR ? WSAGetLastError() : 0;
    log_phase_fmt("socket_connect", "socket=0x%llX rc=%d err=%d port=%u",
        static_cast<unsigned long long>(client),
        connect_rc,
        wsa_err,
        static_cast<unsigned>(pair->port));
    if (connect_rc == SOCKET_ERROR)
        return false;
    log_phase_fmt("socket_setup_end", "listener=0x%llX client=0x%llX accepted=0x%llX port=%u",
        static_cast<unsigned long long>(pair->listener.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(pair->client.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(pair->accepted.load(std::memory_order_acquire)),
        static_cast<unsigned>(pair->port));
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
    log_phase_fmt("network_send_begin", "iteration=%d socket=0x%llX",
        iteration,
        static_cast<unsigned long long>(s));
    char send_payload[160]{};
    const int send_len = std::snprintf(send_payload, sizeof(send_payload),
        "AIDA_PRE_ENCRYPT_SEND iteration=%03d pid=%lu\r\n",
        iteration,
        static_cast<unsigned long>(GetCurrentProcessId()));
    if (send_len <= 0) {
        log_phase_fmt("network_send_end", "iteration=%d socket=0x%llX send_len=%d sent=%d err=%d wsasend_rc=%d wsasend_err=%d bytes=%lu ok=0",
            iteration,
            static_cast<unsigned long long>(s),
            send_len,
            0,
            WSAEINVAL,
            0,
            WSAEINVAL,
            0ul);
        return false;
    }
    const int sent = send(s, send_payload, send_len, 0);
    const int send_err = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (sent == SOCKET_ERROR) {
        log_phase_fmt("network_send_end", "iteration=%d socket=0x%llX send_len=%d sent=%d err=%d wsasend_rc=%d wsasend_err=%d bytes=%lu ok=0",
            iteration,
            static_cast<unsigned long long>(s),
            send_len,
            sent,
            send_err,
            0,
            0,
            0ul);
        return false;
    }

    char wsa_payload_a[96]{};
    char wsa_payload_b[96]{};
    const int len_a = std::snprintf(wsa_payload_a, sizeof(wsa_payload_a),
        "AIDA_PRE_ENCRYPT_WSASEND_A iteration=%03d ", iteration);
    const int len_b = std::snprintf(wsa_payload_b, sizeof(wsa_payload_b),
        "AIDA_PRE_ENCRYPT_WSASEND_B pid=%lu\r\n",
        static_cast<unsigned long>(GetCurrentProcessId()));
    if (len_a <= 0 || len_b <= 0) {
        log_phase_fmt("network_send_end", "iteration=%d socket=0x%llX send_len=%d sent=%d err=%d wsasend_len_a=%d wsasend_len_b=%d wsasend_rc=%d wsasend_err=%d bytes=%lu ok=0",
            iteration,
            static_cast<unsigned long long>(s),
            send_len,
            sent,
            send_err,
            len_a,
            len_b,
            0,
            WSAEINVAL,
            0ul);
        return false;
    }
    WSABUF bufs[2]{};
    bufs[0].buf = wsa_payload_a;
    bufs[0].len = static_cast<ULONG>(len_a);
    bufs[1].buf = wsa_payload_b;
    bufs[1].len = static_cast<ULONG>(len_b);
    DWORD bytes = 0;
    const int wsa_send_rc = WSASend(s, bufs, 2, &bytes, 0, nullptr, nullptr);
    const int wsa_send_err = wsa_send_rc == SOCKET_ERROR ? WSAGetLastError() : 0;
    const bool ok = wsa_send_rc != SOCKET_ERROR;
    log_phase_fmt("network_send_end", "iteration=%d socket=0x%llX send_len=%d sent=%d err=%d wsasend_len_a=%d wsasend_len_b=%d wsasend_rc=%d wsasend_err=%d bytes=%lu ok=%d",
        iteration,
        static_cast<unsigned long long>(s),
        send_len,
        sent,
        send_err,
        len_a,
        len_b,
        wsa_send_rc,
        wsa_send_err,
        static_cast<unsigned long>(bytes),
        ok ? 1 : 0);
    return ok;
}

const char* build_mode() {
    return "plain";
}

int run_sidecar(const config_t& cfg) {
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    log_phase_fmt("run_entry", "build_mode=%s requested_mode=%s no_wait=%d iterations=%d interval_ms=%lu wait_ms=%lu event_prefix=%s",
        build_mode(),
        cfg.requested_mode.empty() ? "default" : cfg.requested_mode.c_str(),
        cfg.no_wait ? 1 : 0,
        cfg.iterations,
        static_cast<unsigned long>(cfg.interval_ms),
        static_cast<unsigned long>(cfg.wait_ms),
        narrow(cfg.event_prefix).c_str());

    WSADATA wsa{};
    const int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    log_phase_fmt("wsa_startup", "rc=%d version=0x%04X high_version=0x%04X description=%s status=%s",
        wsa_rc,
        static_cast<unsigned>(wsa.wVersion),
        static_cast<unsigned>(wsa.wHighVersion),
        wsa.szDescription,
        wsa.szSystemStatus);
    if (wsa_rc != 0) {
        log_line("error", "WSAStartup failed");
        return 10;
    }

    SetLastError(ERROR_SUCCESS);
    auto* region = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, k_guard_region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    const DWORD alloc_err = region ? ERROR_SUCCESS : GetLastError();
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T mbi_size = 0;
    if (region)
        mbi_size = VirtualQuery(region, &mbi, sizeof(mbi));
    log_phase_fmt("guard_alloc", "va=0x%llX size=%llu err=%lu query_size=%llu alloc_base=0x%llX region_size=%llu state=0x%lX protect=0x%lX type=0x%lX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(region)),
        static_cast<unsigned long long>(k_guard_region_size),
        static_cast<unsigned long>(alloc_err),
        static_cast<unsigned long long>(mbi_size),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mbi.AllocationBase)),
        static_cast<unsigned long long>(mbi.RegionSize),
        static_cast<unsigned long>(mbi.State),
        static_cast<unsigned long>(mbi.Protect),
        static_cast<unsigned long>(mbi.Type));
    if (!region) {
        WSACleanup();
        log_line("error", "VirtualAlloc failed");
        return 11;
    }

    std::memset(region, 0, k_guard_region_size);
    std::memcpy(region, "AIDA_PG_SNIFF_READY", 19);

    auto sockets = std::make_shared<socket_pair_t>();
    if (!setup_loopback(sockets)) {
        log_phase_fmt("socket_setup_failed", "last_wsa_error=%d listener=0x%llX client=0x%llX accepted=0x%llX",
            WSAGetLastError(),
            static_cast<unsigned long long>(sockets ? sockets->listener.load(std::memory_order_acquire) : INVALID_SOCKET),
            static_cast<unsigned long long>(sockets ? sockets->client.load(std::memory_order_acquire) : INVALID_SOCKET),
            static_cast<unsigned long long>(sockets ? sockets->accepted.load(std::memory_order_acquire) : INVALID_SOCKET));
        close_socket_pair(sockets);
        VirtualFree(region, 0, MEM_RELEASE);
        WSACleanup();
        log_line("error", "loopback setup failed");
        return 12;
    }

    handles_t events{};
    if (!create_events(cfg, events)) {
        log_phase_fmt("events_create_failed", "ready=%p go=%p done=%p gle=%lu",
            events.ready,
            events.go,
            events.done,
            static_cast<unsigned long>(GetLastError()));
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

    SetLastError(ERROR_SUCCESS);
    const BOOL ready_set = SetEvent(events.ready);
    const DWORD ready_set_err = ready_set ? ERROR_SUCCESS : GetLastError();
    log_phase_fmt("ready_setevent", "handle=%p result=%d err=%lu",
        events.ready,
        ready_set ? 1 : 0,
        static_cast<unsigned long>(ready_set_err));
    log_line("sync", "ready signaled");

    if (!cfg.no_wait) {
        const DWORD timeout = cfg.wait_ms == 0 ? INFINITE : cfg.wait_ms;
        log_phase_fmt("go_wait_begin", "handle=%p timeout_ms=%lu",
            events.go,
            static_cast<unsigned long>(timeout));
        const ULONGLONG wait_start = GetTickCount64();
        ULONGLONG next_progress = wait_start + 1000;
        DWORD wr = WAIT_TIMEOUT;
        for (;;) {
            DWORD slice = 250;
            if (timeout != INFINITE) {
                const ULONGLONG now = GetTickCount64();
                const ULONGLONG elapsed = now - wait_start;
                if (elapsed >= timeout) {
                    wr = WAIT_TIMEOUT;
                    break;
                }
                const ULONGLONG remaining = timeout - elapsed;
                if (remaining < slice)
                    slice = static_cast<DWORD>(remaining);
            }
            wr = WaitForSingleObject(events.go, slice);
            if (wr != WAIT_TIMEOUT)
                break;
            const ULONGLONG now = GetTickCount64();
            if (now >= next_progress) {
                const DWORD instant = WaitForSingleObject(events.go, 0);
                log_phase_fmt("go_wait_progress", "handle=%p elapsed_ms=%llu timeout_ms=%lu instant=0x%08lX stop=%ld",
                    events.go,
                    static_cast<unsigned long long>(now - wait_start),
                    static_cast<unsigned long>(timeout),
                    static_cast<unsigned long>(instant),
                    static_cast<long>(InterlockedCompareExchange(&g_stop, 0, 0)));
                next_progress = now + 1000;
            }
        }
        const DWORD wait_err = wr == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
        log_phase_fmt("go_wait_end", "handle=%p result=0x%08lX err=%lu elapsed_ms=%llu",
            events.go,
            static_cast<unsigned long>(wr),
            static_cast<unsigned long>(wait_err),
            static_cast<unsigned long long>(GetTickCount64() - wait_start));
        if (wr != WAIT_OBJECT_0) {
            std::printf("[sync] go wait failed result=0x%08lX err=%lu\n",
                static_cast<unsigned long>(wr),
                static_cast<unsigned long>(wait_err));
            SetLastError(ERROR_SUCCESS);
            const BOOL done_set = SetEvent(events.done);
            const DWORD done_set_err = done_set ? ERROR_SUCCESS : GetLastError();
            log_phase_fmt("done_setevent", "handle=%p result=%d err=%lu reason=go_wait_failed",
                events.done,
                done_set ? 1 : 0,
                static_cast<unsigned long>(done_set_err));
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
    SetLastError(ERROR_SUCCESS);
    const BOOL done_set = SetEvent(events.done);
    const DWORD done_set_err = done_set ? ERROR_SUCCESS : GetLastError();
    log_phase_fmt("done_setevent", "handle=%p result=%d err=%lu reason=complete",
        events.done,
        done_set ? 1 : 0,
        static_cast<unsigned long>(done_set_err));
    close_events(events);
    close_socket_pair(sockets);
    VirtualFree(region, 0, MEM_RELEASE);
    WSACleanup();
    return network_failures == 0 ? 0 : 20;
}

int run_sidecar_guarded(const config_t& cfg) {
    int rc = 255;
    __try {
        rc = run_sidecar(cfg);
        log_phase_fmt("run_exit", "exit_code=%d", rc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const DWORD code = GetExceptionCode();
        log_phase_fmt("seh_exception", "code=0x%08lX exit_code=%d", static_cast<unsigned long>(code), 221);
        rc = 221;
    }
    return rc;
}

}

int main(int argc, char** argv) {
    g_started_ms = GetTickCount64();
    log_process_args(argc, argv);
    try {
        config_t cfg = parse_args(argc, argv);
        log_phase_fmt("args_parsed", "build_mode=%s requested_mode=%s no_wait=%d iterations=%d interval_ms=%lu wait_ms=%lu event_prefix=%s",
            build_mode(),
            cfg.requested_mode.empty() ? "default" : cfg.requested_mode.c_str(),
            cfg.no_wait ? 1 : 0,
            cfg.iterations,
            static_cast<unsigned long>(cfg.interval_ms),
            static_cast<unsigned long>(cfg.wait_ms),
            narrow(cfg.event_prefix).c_str());
        const int rc = run_sidecar_guarded(cfg);
        log_phase_fmt("process_exit", "exit_code=%d", rc);
        return rc;
    } catch (const std::exception& ex) {
        log_phase_fmt("cpp_exception", "what=%s exit_code=%d", ex.what(), 222);
        log_phase_fmt("process_exit", "exit_code=%d", 222);
        return 222;
    } catch (...) {
        log_phase_fmt("cpp_exception", "what=unknown exit_code=%d", 223);
        log_phase_fmt("process_exit", "exit_code=%d", 223);
        return 223;
    }
}
