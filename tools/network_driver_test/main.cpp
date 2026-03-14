#include "../../driver/comm.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "winhttp.lib")

namespace {

extern "C" long do_syscall_4(std::uint32_t, std::uint8_t*, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t) {
    return static_cast<long>(0xC0000002L);
}

enum class Outcome {
    pass,
    fail,
    skip
};

struct TestCaseResult {
    std::string name;
    Outcome outcome = Outcome::fail;
    std::string detail;
};

struct Config {
    std::string pcap_out = "network_driver_test_capture.pcap";
    std::string target_exe;
    std::uint32_t target_pid = 0;
    bool strict = true;

    bool sniff_enabled = false;
    std::uint64_t sniff_address = 0;
    std::uint32_t sniff_buf_reg = 2;
    std::uint32_t sniff_size_reg = 8;
    std::uint32_t sniff_tid = 0;
    std::uint32_t sniff_bp_index = 0;
};

class TargetProcessSession {
public:
    ~TargetProcessSession() {
        stop();
    }

    bool launch(const std::filesystem::path& exe_path) {
        if (launched_) {
            return true;
        }

        if (exe_path.empty() || !std::filesystem::exists(exe_path)) {
            return false;
        }

        std::wstring exe = exe_path.wstring();
        std::wstring cmd = L"\"" + exe + L"\"";
        std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
        cmdline.push_back(L'\0');

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};

        std::wstring work_dir = exe_path.parent_path().wstring();
        BOOL ok = CreateProcessW(
            exe.c_str(),
            cmdline.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_PROCESS_GROUP,
            nullptr,
            work_dir.empty() ? nullptr : work_dir.c_str(),
            &si,
            &pi
        );

        if (!ok) {
            return false;
        }

        CloseHandle(pi.hThread);
        pi_ = pi;
        launched_ = true;
        return true;
    }

    void stop() {
        if (!launched_) {
            return;
        }

        if (pi_.hProcess) {
            DWORD exit_code = 0;
            if (GetExitCodeProcess(pi_.hProcess, &exit_code) && exit_code == STILL_ACTIVE) {
                TerminateProcess(pi_.hProcess, 0);
                WaitForSingleObject(pi_.hProcess, 3000);
            }
            CloseHandle(pi_.hProcess);
            pi_.hProcess = nullptr;
        }

        launched_ = false;
    }

    bool launched() const {
        return launched_;
    }

    bool is_running(DWORD* out_exit_code = nullptr) const {
        if (!launched_ || !pi_.hProcess) {
            if (out_exit_code) {
                *out_exit_code = 0;
            }
            return false;
        }

        DWORD exit_code = 0;
        if (!GetExitCodeProcess(pi_.hProcess, &exit_code)) {
            if (out_exit_code) {
                *out_exit_code = 0xFFFFFFFFu;
            }
            return false;
        }

        if (out_exit_code) {
            *out_exit_code = exit_code;
        }
        return exit_code == STILL_ACTIVE;
    }

    DWORD process_id() const {
        return pi_.dwProcessId;
    }

private:
    PROCESS_INFORMATION pi_{};
    bool launched_ = false;
};

struct SocketGuard {
    SOCKET s = INVALID_SOCKET;
    ~SocketGuard() {
        if (s != INVALID_SOCKET) {
            closesocket(s);
            s = INVALID_SOCKET;
        }
    }
};

std::string outcome_to_string(Outcome o) {
    switch (o) {
    case Outcome::pass: return "PASS";
    case Outcome::fail: return "FAIL";
    case Outcome::skip: return "SKIP";
    }
    return "FAIL";
}

std::array<std::uint8_t, 16> ipv4_to_16(const char* ip) {
    std::array<std::uint8_t, 16> out{};
    in_addr addr{};
    if (InetPtonA(AF_INET, ip, &addr) == 1) {
        std::memcpy(out.data(), &addr, sizeof(addr));
    }
    return out;
}

std::string ipv4_bytes_to_string(const std::uint8_t* bytes) {
    char buf[INET_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET, const_cast<void*>(reinterpret_cast<const void*>(bytes)), buf, sizeof(buf))) {
        return buf;
    }
    return "0.0.0.0";
}

bool parse_u64(const std::string& s, std::uint64_t& out) {
    try {
        size_t idx = 0;
        out = std::stoull(s, &idx, 0);
        return idx == s.size();
    } catch (...) {
        return false;
    }
}

bool parse_u32(const std::string& s, std::uint32_t& out) {
    std::uint64_t v = 0;
    if (!parse_u64(s, v) || v > 0xFFFFFFFFull) {
        return false;
    }
    out = static_cast<std::uint32_t>(v);
    return true;
}

std::filesystem::path find_repo_root() {
    std::filesystem::path cur = std::filesystem::current_path();
    while (true) {
        if (std::filesystem::exists(cur / "CMakeLists.txt") &&
            std::filesystem::exists(cur / "tools")) {
            return cur;
        }

        std::filesystem::path parent = cur.parent_path();
        if (parent.empty() || parent == cur) {
            break;
        }
        cur = parent;
    }
    return {};
}

std::filesystem::path default_target_exe_path() {
    std::filesystem::path repo_root = find_repo_root();
    if (repo_root.empty()) {
        return {};
    }

    return repo_root / "tools" / "netlab_target" / "bin" / "Release" / "net8.0" / "win-x64" / "publish" / "NetLabTarget.exe";
}

bool can_connect_local_tcp(std::uint16_t port, int* out_wsa_error = nullptr) {
    if (out_wsa_error) {
        *out_wsa_error = 0;
    }

    SocketGuard s;
    s.s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s.s == INVALID_SOCKET) {
        if (out_wsa_error) {
            *out_wsa_error = WSAGetLastError();
        }
        return false;
    }

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    InetPtonA(AF_INET, "127.0.0.1", &sa.sin_addr);

    if (connect(s.s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0) {
        return true;
    }

    if (out_wsa_error) {
        *out_wsa_error = WSAGetLastError();
    }
    return false;
}

bool wait_for_target_ready(std::uint16_t tcp_port,
                           std::chrono::milliseconds timeout,
                           const TargetProcessSession* target_process = nullptr,
                           int* out_last_wsa_error = nullptr,
                           DWORD* out_target_exit_code = nullptr) {
    int last_wsa_error = 0;

    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        int wsa_error = 0;
        if (can_connect_local_tcp(tcp_port, &wsa_error)) {
            if (out_last_wsa_error) {
                *out_last_wsa_error = 0;
            }
            if (out_target_exit_code) {
                *out_target_exit_code = STILL_ACTIVE;
            }
            return true;
        }

        if (wsa_error != 0) {
            last_wsa_error = wsa_error;
        }

        if (target_process && target_process->launched()) {
            DWORD exit_code = STILL_ACTIVE;
            if (!target_process->is_running(&exit_code)) {
                if (out_last_wsa_error) {
                    *out_last_wsa_error = last_wsa_error;
                }
                if (out_target_exit_code) {
                    *out_target_exit_code = exit_code;
                }
                return false;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }

    if (out_last_wsa_error) {
        *out_last_wsa_error = last_wsa_error;
    }
    if (out_target_exit_code) {
        *out_target_exit_code = STILL_ACTIVE;
    }
    return false;
}

void reset_driver_network_state(voyager::device_t& dev) {
    dev.stop_capture();
    dev.clear_filter_rules();
    dev.packet_mod_rule_op(3);
    dev.traffic_redirect_op(3);
    dev.intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
    dev.dns_spoof_op(3, 0, nullptr, nullptr, AF_INET, 0, nullptr);
    dev.bw_monitor_op(1, 0, nullptr);
    dev.bw_monitor_op(3, 0, nullptr);
    dev.fingerprint_op(1);
}

class LocalTrafficHarness {
public:
    LocalTrafficHarness(std::uint16_t tcp_port, std::uint16_t udp_port, bool external_target)
        : tcp_port_(tcp_port), udp_port_(udp_port), external_target_(external_target) {}

    ~LocalTrafficHarness() {
        stop();
    }

    bool start() {
        if (running_) {
            return true;
        }

        if (external_target_) {
            running_ = true;
            return true;
        }

        stop_flag_.store(false);
        tcp_thread_ = std::thread([this]() { tcp_echo_server(); });
        udp_thread_ = std::thread([this]() { udp_sink_server(); });

        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        running_ = true;
        return true;
    }

    void stop() {
        if (!running_) {
            return;
        }

        if (external_target_) {
            running_ = false;
            return;
        }

        stop_flag_.store(true);

        if (tcp_thread_.joinable()) {
            tcp_thread_.join();
        }
        if (udp_thread_.joinable()) {
            udp_thread_.join();
        }

        running_ = false;
    }

    std::uint16_t tcp_port() const { return tcp_port_; }
    std::uint16_t udp_port() const { return udp_port_; }

    bool generate_dns() {
        PDNS_RECORDA rec = nullptr;
        DNS_STATUS st = DnsQuery_A("example.com", DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &rec, nullptr);
        if (rec) {
            DnsRecordListFree(rec, DnsFreeRecordList);
        }
        return st == 0;
    }

    bool generate_tcp(bool chunked = false) {
        SocketGuard client;
        client.s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client.s == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(tcp_port_);
        InetPtonA(AF_INET, "127.0.0.1", &sa.sin_addr);

        if (connect(client.s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) {
            return false;
        }

        if (chunked) {
            const char* chunks[] = {
                "REASM_TEST_CHUNK_1\n",
                "REASM_TEST_CHUNK_2\n",
                "REASM_TEST_CHUNK_3\n",
                "REASM_TEST_CHUNK_4\n"
            };
            for (const char* c : chunks) {
                int n = static_cast<int>(std::strlen(c));
                if (send(client.s, c, n, 0) == SOCKET_ERROR) {
                    return false;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        } else {
            const char* msg = "MAGIC_PATTERN_DEADBEEF_TEST_PAYLOAD_1234567890";
            int n = static_cast<int>(std::strlen(msg));
            if (send(client.s, msg, n, 0) == SOCKET_ERROR) {
                return false;
            }
        }

        char recv_buf[512] = {};
        int r = recv(client.s, recv_buf, static_cast<int>(sizeof(recv_buf)), 0);
        return r > 0;
    }

    bool generate_udp() {
        SocketGuard sock;
        sock.s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock.s == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(udp_port_);
        InetPtonA(AF_INET, "127.0.0.1", &sa.sin_addr);

        const char* payload = "UDP_TEST_PACKET_PAYLOAD_DEADBEEF";
        int n = static_cast<int>(std::strlen(payload));
        int sent = sendto(sock.s, payload, n, 0, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
        return sent == n;
    }

    bool generate_http_https() {
        bool ok_http = http_get(L"http://example.com/");
        bool ok_https = http_get(L"https://example.com/");
        return ok_http || ok_https;
    }

    bool generate_all() {
        bool ok = true;
        ok = generate_dns() && ok;
        ok = generate_http_https() && ok;
        ok = generate_tcp() && ok;
        ok = generate_udp() && ok;
        return ok;
    }

    SOCKET open_long_lived_tcp(std::uint16_t& out_local_port) {
        out_local_port = 0;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            return INVALID_SOCKET;
        }

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(tcp_port_);
        InetPtonA(AF_INET, "127.0.0.1", &sa.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) {
            closesocket(s);
            return INVALID_SOCKET;
        }

        sockaddr_in local{};
        int local_len = sizeof(local);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &local_len) == 0) {
            out_local_port = ntohs(local.sin_port);
        }

        const char* msg = "LONG_LIVED_CONNECTION_PAYLOAD";
        send(s, msg, static_cast<int>(std::strlen(msg)), 0);
        return s;
    }

private:
    static bool http_get(const wchar_t* url) {
        URL_COMPONENTS uc{};
        uc.dwStructSize = sizeof(uc);

        wchar_t host[256] = {};
        wchar_t path[1024] = {};
        uc.lpszHostName = host;
        uc.dwHostNameLength = static_cast<DWORD>(std::size(host));
        uc.lpszUrlPath = path;
        uc.dwUrlPathLength = static_cast<DWORD>(std::size(path));

        if (!WinHttpCrackUrl(url, 0, 0, &uc)) {
            return false;
        }

        std::wstring host_ws(host, uc.dwHostNameLength);
        std::wstring path_ws;
        if (uc.dwUrlPathLength > 0) {
            path_ws.assign(path, uc.dwUrlPathLength);
        } else {
            path_ws = L"/";
        }

        HINTERNET h_session = WinHttpOpen(L"NetworkDriverTestTool/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!h_session) {
            return false;
        }

        HINTERNET h_connect = WinHttpConnect(h_session, host_ws.c_str(), uc.nPort, 0);
        if (!h_connect) {
            WinHttpCloseHandle(h_session);
            return false;
        }

        DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET h_request = WinHttpOpenRequest(h_connect, L"GET", path_ws.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!h_request) {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return false;
        }

        bool ok = false;
        if (WinHttpSendRequest(h_request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(h_request, nullptr)) {
            DWORD avail = 0;
            if (WinHttpQueryDataAvailable(h_request, &avail)) {
                ok = true;
            }
        }

        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return ok;
    }

    void tcp_echo_server() {
        SocketGuard listener;
        listener.s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener.s == INVALID_SOCKET) {
            return;
        }

        BOOL reuse = TRUE;
        setsockopt(listener.s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(tcp_port_);
        InetPtonA(AF_INET, "127.0.0.1", &sa.sin_addr);

        if (bind(listener.s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) {
            return;
        }
        if (listen(listener.s, 16) == SOCKET_ERROR) {
            return;
        }

        while (!stop_flag_.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listener.s, &rfds);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
            int sel = select(0, &rfds, nullptr, nullptr, &tv);
            if (sel <= 0 || !FD_ISSET(listener.s, &rfds)) {
                continue;
            }

            SOCKET client = accept(listener.s, nullptr, nullptr);
            if (client == INVALID_SOCKET) {
                continue;
            }

            char buf[4096] = {};
            while (!stop_flag_.load()) {
                int r = recv(client, buf, static_cast<int>(sizeof(buf)), 0);
                if (r <= 0) {
                    break;
                }
                if (send(client, buf, r, 0) == SOCKET_ERROR) {
                    break;
                }
            }
            closesocket(client);
        }
    }

    void udp_sink_server() {
        SocketGuard sock;
        sock.s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock.s == INVALID_SOCKET) {
            return;
        }

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(udp_port_);
        InetPtonA(AF_INET, "127.0.0.1", &sa.sin_addr);

        if (bind(sock.s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) {
            return;
        }

        while (!stop_flag_.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock.s, &rfds);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
            int sel = select(0, &rfds, nullptr, nullptr, &tv);
            if (sel <= 0 || !FD_ISSET(sock.s, &rfds)) {
                continue;
            }

            char buf[2048];
            sockaddr_in from{};
            int from_len = sizeof(from);
            recvfrom(sock.s, buf, static_cast<int>(sizeof(buf)), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
        }
    }

private:
    std::uint16_t tcp_port_;
    std::uint16_t udp_port_;
    std::atomic<bool> stop_flag_{false};
    bool running_ = false;
    bool external_target_ = false;
    std::thread tcp_thread_;
    std::thread udp_thread_;
};

void print_case(const TestCaseResult& r) {
    std::cout << "[" << outcome_to_string(r.outcome) << "] " << r.name;
    if (!r.detail.empty()) {
        std::cout << " - " << r.detail;
    }
    std::cout << "\n";
}

bool write_pcap_file(const std::string& path, const voyager::device_t::pcap_export_result& pcap) {
    std::filesystem::path outp(path);
    if (outp.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(outp.parent_path(), ec);
    }

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(&pcap.header), sizeof(pcap.header));

    struct pcap_record_hdr {
        std::uint32_t ts_sec;
        std::uint32_t ts_usec;
        std::uint32_t incl_len;
        std::uint32_t orig_len;
    };

    for (const auto& pkt : pcap.packets) {
        pcap_record_hdr hdr{};
        hdr.ts_sec = pkt.ts_sec;
        hdr.ts_usec = pkt.ts_usec;
        hdr.incl_len = static_cast<std::uint32_t>(pkt.data.size());
        hdr.orig_len = static_cast<std::uint32_t>(pkt.data.size());
        ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        if (!pkt.data.empty()) {
            ofs.write(reinterpret_cast<const char*>(pkt.data.data()), static_cast<std::streamsize>(pkt.data.size()));
        }
    }

    return ofs.good();
}

Config parse_args(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "--pcap-out" && i + 1 < argc) {
            cfg.pcap_out = argv[++i];
            continue;
        }
        if (a == "--target-exe" && i + 1 < argc) {
            cfg.target_exe = argv[++i];
            continue;
        }
        if (a == "--target-pid" && i + 1 < argc) {
            std::uint32_t v = 0;
            if (parse_u32(argv[++i], v)) cfg.target_pid = v;
            continue;
        }
        if (a == "--non-strict") {
            cfg.strict = false;
            continue;
        }
        if (a == "--sniff-address" && i + 1 < argc) {
            std::uint64_t v = 0;
            if (parse_u64(argv[++i], v)) {
                cfg.sniff_address = v;
                cfg.sniff_enabled = true;
            }
            continue;
        }
        if (a == "--sniff-buffer-reg" && i + 1 < argc) {
            std::uint32_t v = 0;
            if (parse_u32(argv[++i], v)) cfg.sniff_buf_reg = v;
            continue;
        }
        if (a == "--sniff-size-reg" && i + 1 < argc) {
            std::uint32_t v = 0;
            if (parse_u32(argv[++i], v)) cfg.sniff_size_reg = v;
            continue;
        }
        if (a == "--sniff-tid" && i + 1 < argc) {
            std::uint32_t v = 0;
            if (parse_u32(argv[++i], v)) cfg.sniff_tid = v;
            continue;
        }
        if (a == "--sniff-bp-index" && i + 1 < argc) {
            std::uint32_t v = 0;
            if (parse_u32(argv[++i], v)) cfg.sniff_bp_index = v;
            continue;
        }
    }
    return cfg;
}

} // namespace

int main(int argc, char** argv) {
    Config cfg = parse_args(argc, argv);

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    voyager::device_t dev;
    if (!dev.connect()) {
        std::cerr << "Driver connect failed\n";
        WSACleanup();
        return 2;
    }

    reset_driver_network_state(dev);

    TargetProcessSession target_process;
    std::filesystem::path target_exe = cfg.target_exe.empty() ? default_target_exe_path() : std::filesystem::path(cfg.target_exe);

    std::uint32_t target_pid = cfg.target_pid;
    if (target_pid == 0) {
        target_pid = dev.find_process("NetLabTarget.exe");
    }

    if (target_pid == 0) {
        if (!target_process.launch(target_exe)) {
            std::error_code ec;
            std::filesystem::path abs_target = std::filesystem::absolute(target_exe, ec);
            std::cerr << "Failed to launch NetLabTarget.exe. "
                << "Use --target-exe <path> or start NetLabTarget.exe manually. "
                << "Resolved path=" << (ec ? target_exe.string() : abs_target.string()) << "\n";
            dev.disconnect();
            WSACleanup();
            return 4;
        }

        int last_wsa_error = 0;
        DWORD target_exit_code = STILL_ACTIVE;
        if (!wait_for_target_ready(7777, std::chrono::seconds(12), &target_process, &last_wsa_error, &target_exit_code)) {
            std::cerr << "NetLabTarget.exe did not become ready on 127.0.0.1:7777"
                << " (pid=" << target_process.process_id()
                << ", last_wsa_error=" << last_wsa_error;
            if (target_exit_code != STILL_ACTIVE) {
                std::cerr << ", target_exit_code=" << target_exit_code;
            }
            std::cerr << ")\n";
            dev.disconnect();
            WSACleanup();
            return 5;
        }

        target_pid = dev.find_process("NetLabTarget.exe");
    }

    if (target_pid == 0) {
        std::cerr << "Could not resolve target PID for NetLabTarget.exe\n";
        dev.disconnect();
        WSACleanup();
        return 6;
    }

    int last_wsa_error = 0;
    if (!wait_for_target_ready(7777, std::chrono::seconds(6), nullptr, &last_wsa_error, nullptr)) {
        std::cerr << "Target process is not accepting TCP traffic on 127.0.0.1:7777"
            << " (last_wsa_error=" << last_wsa_error << ")\n";
        dev.disconnect();
        WSACleanup();
        return 7;
    }

    LocalTrafficHarness harness(7777, 9001, true);
    if (!harness.start()) {
        std::cerr << "Failed to start traffic harness\n";
        dev.disconnect();
        WSACleanup();
        return 8;
    }

    dev.set_process_id(target_pid);

    std::vector<TestCaseResult> results;
    auto add_result = [&](const std::string& name, Outcome o, const std::string& d) {
        results.push_back(TestCaseResult{name, o, d});
        print_case(results.back());
    };

    std::cout << "Running full driver end-to-end tests...\n";
    std::cout << "Target process: NetLabTarget.exe pid=" << target_pid;
    if (target_process.launched()) {
        std::cout << " launched_at=" << target_exe.string();
    }
    std::cout << "\n";

    // ================================================================
    // Core driver tests (IOCTLs 0-8): heartbeat, DTB, base, R/W, alloc
    // ================================================================
    std::cout << "\n=== Core Driver Tests ===\n";

    {
        bool ok = dev.send_heartbeat();
        add_result("heartbeat", ok ? Outcome::pass : Outcome::fail,
            ok ? "Heartbeat acknowledged" : "Heartbeat failed");
    }

    {
        dev.solve_dtb();
        std::uint64_t dtb = dev.get_dtb();
        bool ok = (dtb != 0);
        std::ostringstream oss;
        oss << "dtb=0x" << std::hex << dtb;
        add_result("dtb_solve", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        std::uint64_t base = dev.find_image();
        bool ok = (base != 0);
        std::ostringstream oss;
        oss << "base=0x" << std::hex << base;
        add_result("find_image", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        std::uint64_t base = dev.get_base_address();
        bool ok = false;
        std::uint16_t mz = 0;
        if (base != 0) {
            mz = dev.read<std::uint16_t>(base);
            ok = (mz == 0x5A4D);
        }
        std::ostringstream oss;
        oss << "magic=0x" << std::hex << mz << " expected=0x5A4D";
        add_result("physical_read_mz", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        std::uint64_t addr = dev.allocate_memory(4096);
        bool alloc_ok = (addr != 0);
        bool write_ok = false;
        bool read_ok = false;
        bool free_ok = false;
        if (alloc_ok) {
            const std::uint64_t sentinel = 0xDEAD'BEEF'CAFE'BABEull;
            dev.write<std::uint64_t>(addr, sentinel);
            write_ok = true;
            std::uint64_t readback = dev.read<std::uint64_t>(addr);
            read_ok = (readback == sentinel);
            free_ok = dev.free_memory(addr);
        }
        std::ostringstream oss;
        oss << "alloc=0x" << std::hex << addr
            << " write=" << write_ok
            << " readback=" << read_ok
            << " free=" << free_ok;
        add_result("memory_alloc_rw_free", alloc_ok && write_ok && read_ok && free_ok
            ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        std::uint64_t base = dev.get_base_address();
        bool ok = false;
        if (base != 0) {
            std::uint8_t buf[64] = {};
            std::size_t n = dev.read_raw(base, buf, sizeof(buf));
            ok = (n == sizeof(buf)) && (buf[0] == 'M') && (buf[1] == 'Z');
        }
        add_result("read_raw", ok ? Outcome::pass : Outcome::fail,
            ok ? "Read 64 bytes from image base, MZ verified" : "read_raw failed or MZ mismatch");
    }

    // ================================================================
    // Thread tests (IOCTLs 9-11): enumerate, context, suspend/resume
    // ================================================================
    std::cout << "\n=== Thread Tests ===\n";

    {
        auto threads = dev.enumerate_threads();
        bool ok = !threads.empty();
        std::ostringstream oss;
        oss << "count=" << threads.size();
        if (!threads.empty()) {
            oss << " first_tid=" << threads.front().tid
                << " first_rip=0x" << std::hex << threads.front().rip;
        }
        add_result("enumerate_threads", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    std::uint32_t test_tid = 0;
    {
        auto threads = dev.enumerate_threads();
        bool ok = false;
        std::ostringstream oss;
        if (!threads.empty()) {
            test_tid = threads.front().tid;
            voyager::device_t::thread_context ctx{};
            ok = dev.get_thread_context(test_tid, ctx);
            oss << "tid=" << test_tid
                << " rip=0x" << std::hex << ctx.rip
                << " rsp=0x" << ctx.rsp
                << " rflags=0x" << ctx.rflags;
        } else {
            oss << "no threads to test";
        }
        add_result("get_thread_context", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        bool ok = false;
        std::ostringstream oss;
        if (test_tid != 0) {
            std::uint32_t prev_suspend = 0;
            bool suspend_ok = dev.suspend_thread(test_tid, &prev_suspend);
            std::uint32_t prev_resume = 0;
            bool resume_ok = dev.resume_thread(test_tid, &prev_resume);
            ok = suspend_ok && resume_ok;
            oss << "tid=" << test_tid
                << " suspend=" << suspend_ok << " prev_suspend=" << prev_suspend
                << " resume=" << resume_ok << " prev_resume=" << prev_resume;
        } else {
            oss << "no thread available";
        }
        add_result("suspend_resume_thread", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    // ================================================================
    // Memory tests (IOCTLs 12-18): query, protect, enum, PEB, debug, export, v2p
    // ================================================================
    std::cout << "\n=== Memory Tests ===\n";

    {
        std::uint64_t base = dev.get_base_address();
        voyager::device_t::memory_region_info info{};
        bool ok = (base != 0) && dev.query_memory(base, info);
        std::ostringstream oss;
        oss << "base=0x" << std::hex << info.base
            << " size=0x" << info.size
            << " state=0x" << info.state
            << " protect=0x" << info.protect
            << " type=0x" << info.type;
        add_result("query_memory", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        std::uint64_t addr = dev.allocate_memory(4096);
        bool ok = false;
        std::ostringstream oss;
        if (addr != 0) {
            std::uint32_t old_prot = 0;
            bool prot_ok = dev.protect_memory(addr, 4096, 0x04 /*PAGE_READWRITE*/, &old_prot);
            ok = prot_ok;
            oss << "addr=0x" << std::hex << addr
                << " protect_ok=" << prot_ok
                << " old_prot=0x" << old_prot;
            dev.free_memory(addr);
        } else {
            oss << "alloc failed";
        }
        add_result("protect_memory", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        auto regions = dev.enumerate_memory_regions();
        bool ok = !regions.empty();
        std::ostringstream oss;
        oss << "regions=" << regions.size();
        if (!regions.empty()) {
            oss << " first_base=0x" << std::hex << regions.front().base
                << " first_size=0x" << regions.front().size;
        }
        add_result("enumerate_memory_regions", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        voyager::device_t::peb_info peb{};
        bool ok = dev.read_peb(peb);
        std::uint64_t base = dev.get_base_address();
        bool base_match = (peb.image_base == base);
        std::ostringstream oss;
        oss << "peb=0x" << std::hex << peb.peb_address
            << " image_base=0x" << peb.image_base
            << " ldr=0x" << peb.ldr_address
            << " heap=0x" << peb.process_heap
            << " match=" << base_match;
        add_result("read_peb", (ok && base_match) ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        std::uint32_t flags = 0;
        bool ok = dev.spoof_debug_flags(&flags);
        std::ostringstream oss;
        oss << "result_flags=0x" << std::hex << flags;
        add_result("spoof_debug_flags", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        HMODULE ntdll_local = GetModuleHandleA("ntdll.dll");
        std::uint64_t ntdll_base = reinterpret_cast<std::uint64_t>(ntdll_local);
        std::uint64_t resolved = 0;
        bool ok = false;
        if (ntdll_base != 0) {
            resolved = dev.resolve_export(ntdll_base, "RtlInitUnicodeString");
            ok = (resolved != 0);
        }
        std::ostringstream oss;
        oss << "ntdll=0x" << std::hex << ntdll_base
            << " resolved=0x" << resolved;
        add_result("resolve_export", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        std::uint64_t base = dev.get_base_address();
        std::uint64_t phys = 0;
        bool ok = false;
        if (base != 0) {
            phys = dev.virtual_to_physical(base);
            ok = (phys != 0);
        }
        std::ostringstream oss;
        oss << "virt=0x" << std::hex << base
            << " phys=0x" << phys;
        add_result("virtual_to_physical", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    // ================================================================
    // Remote call test (IOCTLs 4-7): call_function via thread hijack
    // ================================================================
    std::cout << "\n=== Remote Call Tests ===\n";

    {
        HMODULE ntdll_local = GetModuleHandleA("ntdll.dll");
        std::uint64_t ntdll_base = reinterpret_cast<std::uint64_t>(ntdll_local);
        std::uint64_t fn_addr = 0;
        bool ok = false;
        std::ostringstream oss;
        if (ntdll_base != 0) {
            fn_addr = dev.resolve_export(ntdll_base, "RtlGetCurrentProcessorNumber");
            if (fn_addr != 0) {
                std::uint64_t result = dev.call_function(fn_addr);
                ok = true;
                oss << "fn=0x" << std::hex << fn_addr
                    << " returned=" << std::dec << result;
            } else {
                oss << "resolve RtlGetCurrentProcessorNumber failed";
            }
        } else {
            oss << "ntdll not found";
        }
        add_result("remote_call_function", ok ? Outcome::pass : Outcome::fail, oss.str());
    }

    // ================================================================
    // Input simulation test (IOCTL 3): mouse movement
    // ================================================================
    std::cout << "\n=== Input Tests ===\n";

    {
        bool ok = false;
        try {
            dev.move_mouse(0, 0, 0);
            ok = true;
        } catch (...) {
            ok = false;
        }
        add_result("mouse_movement", ok ? Outcome::pass : Outcome::fail,
            ok ? "move_mouse(0,0,0) succeeded (no-op delta)" : "move_mouse threw or failed");
    }

    // ================================================================
    // Network tests (IOCTLs 19-40)
    // ================================================================
    std::cout << "\n=== Network Tests ===\n";

    bool generated = harness.generate_all();
    add_result("traffic_baseline", generated ? Outcome::pass : Outcome::fail,
        generated ? "Generated loopback TCP/UDP + DNS + HTTP(S)" : "Traffic generation failed");

    {
        bool start_ok = dev.start_capture(target_pid, 0, 0, nullptr, 1500);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        bool active = false;
        std::uint32_t captured = 0;
        std::uint32_t dropped = 0;
        bool status_ok = dev.get_capture_status(active, captured, dropped);

        harness.generate_all();
        std::this_thread::sleep_for(std::chrono::milliseconds(400));

        auto packets = dev.get_captured_packets(64);
        auto dns = dev.get_dns_queries(target_pid);
        voyager::device_t::network_stats stats{};
        bool stats_ok = dev.get_network_stats(stats);
        auto conns = dev.enumerate_connections(target_pid, 0);

        bool stop_ok = dev.stop_capture();

        bool pass = start_ok && status_ok && active && stats_ok && stop_ok;
        if (cfg.strict) {
            pass = pass && !packets.empty();
        }

        std::ostringstream oss;
        oss << "active=" << active
            << " captured=" << captured
            << " dropped=" << dropped
            << " packets=" << packets.size()
            << " dns=" << dns.size()
            << " conns=" << conns.size();
        add_result("capture_pipeline", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        auto callouts = dev.enumerate_wfp_callouts();
        bool pass = cfg.strict ? !callouts.empty() : true;
        add_result("driver_enumerate_wfp_callouts", pass ? Outcome::pass : Outcome::fail,
            "count=" + std::to_string(callouts.size()));
    }

    {
        auto socks = dev.get_socket_handles(target_pid);
        bool pass = cfg.strict ? !socks.empty() : true;
        add_result("driver_get_socket_handles", pass ? Outcome::pass : Outcome::fail,
            "count=" + std::to_string(socks.size()));
    }

    {
        auto tcps = dev.dump_tcpip_connections(target_pid, 0);
        bool pass = cfg.strict ? !tcps.empty() : true;
        add_result("driver_dump_tcpip_connections", pass ? Outcome::pass : Outcome::fail,
            "count=" + std::to_string(tcps.size()));
    }

    {
        std::uint32_t rid = 0;
        bool add_ok = dev.add_filter_rule(1, 2, IPPROTO_TCP, target_pid, harness.tcp_port(), nullptr, nullptr, &rid);
        bool rm_ok = dev.remove_filter_rule(rid);
        bool clr_ok = dev.clear_filter_rules();
        bool pass = add_ok && rm_ok && clr_ok;
        add_result("filter_rules_basic", pass ? Outcome::pass : Outcome::fail,
            "rule_id=" + std::to_string(rid));
    }

    {
        auto loop = ipv4_to_16("127.0.0.1");
        const char payload[] = "INJECT_UDP_PAYLOAD";
        bool ok = dev.inject_packet(1, IPPROTO_UDP, AF_INET, 54321, harness.udp_port(),
            loop.data(), loop.data(), reinterpret_cast<const std::uint8_t*>(payload),
            static_cast<std::uint32_t>(std::strlen(payload)));
        add_result("driver_inject_packet", ok ? Outcome::pass : Outcome::fail,
            ok ? "Injected UDP packet" : "Injection failed");
    }

    {
        const std::uint8_t pattern[] = { 0x44, 0x45, 0x41, 0x44, 0x42, 0x45, 0x45, 0x46 };
        const std::uint8_t repl[] = { 0x46, 0x45, 0x45, 0x44, 0x46, 0x41, 0x43, 0x45 };
        std::uint32_t rule_id = 0;

        bool add_ok = dev.packet_mod_rule_op(0, 0, 2, IPPROTO_TCP, harness.tcp_port(), 0,
            pattern, static_cast<std::uint32_t>(sizeof(pattern)),
            repl, static_cast<std::uint32_t>(sizeof(repl)), &rule_id);
        harness.generate_tcp();
        auto rules = dev.list_packet_mod_rules();
        bool remove_ok = dev.packet_mod_rule_op(1, rule_id);
        bool clear_ok = dev.packet_mod_rule_op(3);

        bool pass = add_ok && remove_ok && clear_ok;
        if (cfg.strict) {
            pass = pass && !rules.empty();
        }

        std::ostringstream oss;
        oss << "rule_id=" << rule_id << " listed=" << rules.size();
        add_result("driver_modify_packet_rule", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        auto loop = ipv4_to_16("127.0.0.1");
        std::uint32_t rule_id = 0;

        bool add_ok = dev.traffic_redirect_op(0, 0, IPPROTO_TCP,
            harness.tcp_port(), loop.data(), harness.tcp_port(), loop.data(), AF_INET, &rule_id);
        auto rules = dev.list_redirect_rules();
        bool remove_ok = dev.traffic_redirect_op(1, rule_id, IPPROTO_TCP,
            harness.tcp_port(), loop.data(), harness.tcp_port(), loop.data(), AF_INET, nullptr);
        bool clear_ok = dev.traffic_redirect_op(3);

        bool pass = add_ok && remove_ok && clear_ok;
        if (cfg.strict) {
            pass = pass && !rules.empty();
        }

        std::ostringstream oss;
        oss << "rule_id=" << rule_id << " listed=" << rules.size();
        add_result("driver_redirect_traffic", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        bool start_ok = dev.stream_reassemble_op(0, 0, harness.tcp_port(), target_pid, nullptr, nullptr, nullptr, nullptr, nullptr);
        harness.generate_tcp(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        std::vector<std::uint8_t> stream;
        std::uint32_t packets = 0;
        std::uint32_t truncated = 0;
        bool get_ok = dev.stream_reassemble_op(2, 0, harness.tcp_port(), target_pid, nullptr, nullptr, &stream, &packets, &truncated);
        bool stop_ok = dev.stream_reassemble_op(1, 0, harness.tcp_port(), target_pid, nullptr, nullptr, nullptr, nullptr, nullptr);

        bool pass = start_ok && get_ok && stop_ok;
        if (cfg.strict) {
            pass = pass && !stream.empty();
        }

        std::ostringstream oss;
        oss << "bytes=" << stream.size() << " packets=" << packets << " truncated=" << truncated;
        add_result("driver_reassemble_stream", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        harness.generate_all();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        auto dpi = dev.get_dpi_results(target_pid, 0, 0, 0);
        bool pass = cfg.strict ? !dpi.empty() : true;

        std::ostringstream oss;
        oss << "results=" << dpi.size();
        if (!dpi.empty()) {
            oss << " first.src=" << ipv4_bytes_to_string(dpi.front().src_addr)
                << ":" << dpi.front().src_port
                << " dst=" << ipv4_bytes_to_string(dpi.front().dst_addr)
                << ":" << dpi.front().dst_port;
        }
        add_result("driver_deep_inspect", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        bool enable_ok = dev.intercept_op(0, target_pid, harness.tcp_port(), IPPROTO_TCP, 0, nullptr, 0, nullptr, nullptr);
        harness.generate_tcp();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        auto held = dev.get_held_packets();

        bool release_ok = true;
        if (!held.empty()) {
            release_ok = dev.intercept_op(3, 0, 0, 0, held.front().hold_id, nullptr, 0, nullptr, nullptr);
        }
        bool disable_ok = dev.intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);

        bool pass = enable_ok && disable_ok && release_ok;
        if (cfg.strict) {
            pass = pass && !held.empty();
        }

        add_result("driver_intercept_hold", pass ? Outcome::pass : Outcome::fail,
            "held=" + std::to_string(held.size()));
    }

    {
        std::uint16_t local_port = 0;
        SOCKET s = harness.open_long_lived_tcp(local_port);
        bool pass = false;
        if (s != INVALID_SOCKET && local_port != 0) {
            auto loop = ipv4_to_16("127.0.0.1");
            bool kill_ok = dev.kill_connection(IPPROTO_TCP, AF_INET, local_port, harness.tcp_port(),
                loop.data(), loop.data(), 0);

            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            char x = 'X';
            int sr = send(s, &x, 1, 0);
            bool dropped = (sr == SOCKET_ERROR);
            if (!dropped) {
                int rr = recv(s, &x, 1, 0);
                dropped = (rr <= 0);
            }
            pass = kill_ok && dropped;
            closesocket(s);
        }

        add_result("driver_kill_connection", pass ? Outcome::pass : Outcome::fail,
            "local_port=" + std::to_string(local_port));
    }

    {
        auto loop = ipv4_to_16("127.0.0.1");
        std::uint32_t rule_id = 0;
        bool add_ok = dev.dns_spoof_op(0, 0, "example.com", loop.data(), AF_INET, 60, &rule_id);
        auto rules = dev.list_dns_spoof_rules();
        bool remove_ok = dev.dns_spoof_op(1, rule_id, nullptr, nullptr, AF_INET, 0, nullptr);
        bool clear_ok = dev.dns_spoof_op(3, 0, nullptr, nullptr, AF_INET, 0, nullptr);

        bool pass = add_ok && remove_ok && clear_ok;
        if (cfg.strict) {
            pass = pass && !rules.empty();
        }

        std::ostringstream oss;
        oss << "rule_id=" << rule_id << " listed=" << rules.size();
        add_result("driver_spoof_dns", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        bool start_ok = dev.bw_monitor_op(0, 0, nullptr);
        harness.generate_all();
        harness.generate_all();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        voyager::device_t::bw_stats stats{};
        bool get_ok = dev.bw_monitor_op(2, 0, &stats);
        auto procs = dev.get_bw_per_process(target_pid);
        bool stop_ok = dev.bw_monitor_op(1, 0, nullptr);
        bool reset_ok = dev.bw_monitor_op(3, 0, nullptr);

        bool pass = start_ok && get_ok && stop_ok && reset_ok;
        if (cfg.strict) {
            pass = pass && ((stats.total_bytes_recv + stats.total_bytes_sent) > 0 || !procs.empty());
        }

        std::ostringstream oss;
        oss << "bytes_in=" << stats.total_bytes_recv
            << " bytes_out=" << stats.total_bytes_sent
            << " per_process=" << procs.size();
        add_result("driver_bandwidth_monitor", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        auto ifaces = dev.enumerate_interfaces();
        bool pass = !ifaces.empty();
        add_result("driver_list_interfaces", pass ? Outcome::pass : Outcome::fail,
            "interfaces=" + std::to_string(ifaces.size()));
    }

    {
        harness.generate_all();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        voyager::device_t::pcap_export_result out{};
        bool ok = dev.export_pcap(target_pid, 0, 256, &out);
        bool write_ok = ok ? write_pcap_file(cfg.pcap_out, out) : false;

        bool pass = ok && write_ok;
        if (cfg.strict) {
            pass = pass && !out.packets.empty();
        }

        std::ostringstream oss;
        oss << "packets=" << out.packets.size() << " file=" << cfg.pcap_out;
        add_result("driver_export_pcap", pass ? Outcome::pass : Outcome::fail, oss.str());
    }

    {
        bool enable_ok = dev.fingerprint_op(0);
        harness.generate_http_https();
        harness.generate_all();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        auto fp = dev.get_fingerprints();
        bool disable_ok = dev.fingerprint_op(1);

        bool pass = enable_ok && disable_ok;
        if (cfg.strict) {
            pass = pass && !fp.empty();
        }

        add_result("driver_network_fingerprint", pass ? Outcome::pass : Outcome::fail,
            "fingerprints=" + std::to_string(fp.size()));
    }

    {
        if (!cfg.sniff_enabled) {
            add_result("driver_sniff_network_buffers", Outcome::skip,
                "Provide --sniff-address 0xADDR and register indexes for a true end-to-end sniff test");
        } else {
            bool start_ok = dev.sniff_net_buffers_start(cfg.sniff_address, cfg.sniff_buf_reg, cfg.sniff_size_reg,
                8, cfg.sniff_tid, cfg.sniff_bp_index);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            bool active = false;
            auto captures = dev.sniff_net_buffers_get(active);
            bool stop_ok = dev.sniff_net_buffers_stop();

            bool pass = start_ok && stop_ok;
            if (cfg.strict) {
                pass = pass && !captures.empty();
            }

            std::ostringstream oss;
            oss << "active=" << active << " captures=" << captures.size();
            add_result("driver_sniff_network_buffers", pass ? Outcome::pass : Outcome::fail, oss.str());
        }
    }

    dev.disconnect();
    harness.stop();
    WSACleanup();

    std::size_t passed = 0;
    std::size_t failed = 0;
    std::size_t skipped = 0;
    for (const auto& r : results) {
        if (r.outcome == Outcome::pass) ++passed;
        else if (r.outcome == Outcome::fail) ++failed;
        else ++skipped;
    }

    std::cout << "\nSummary: passed=" << passed << " failed=" << failed << " skipped=" << skipped << "\n";
    if (failed != 0) {
        std::cout << "FAILED test cases:\n";
        for (const auto& r : results) {
            if (r.outcome == Outcome::fail) {
                std::cout << "  - " << r.name << "\n";
            }
        }
    }

    return failed == 0 ? 0 : 3;
}
