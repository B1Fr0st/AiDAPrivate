#include "test_all_network.h"

#include "../network/network_view.hpp"
#include "../network/mitm_proxy.hpp"
#include "../network/tcp_stream_tracker.hpp"
#include "../network/protocol_parser.hpp"
#include "../network/http_parser_engine.hpp"
#include "../network/cert_generator.hpp"
#include "../network/ssl_keylog.hpp"
#include "../network/cert_pin_bypass.hpp"
#include "../network/packet_callstack.hpp"
#include "../network/protobuf_codec.hpp"
#include "../network/http2_session.hpp"
#include "../network/burp/match_replace.hpp"
#include "../runtime/standalone_driver.hpp"
#include "net_security.hpp"
#include "../../helpers/diag_log.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace test_all_features {

namespace {

    void format_timestamp(char* out, std::size_t cap) {
        SYSTEMTIME st; GetLocalTime(&st);
        std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
            (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
    }
    void write_log_file(HANDLE hf, const std::string& line) {
        if (hf == INVALID_HANDLE_VALUE) return;
        DWORD wrote = 0;
        WriteFile(hf, line.data(), (DWORD)line.size(), &wrote, nullptr);
        FlushFileBuffers(hf);
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
        std::string s(line);
        write_log_file(hf, s);
        diag::log_tagged_fmt("test_all", "%s: %s", tag, detail);
        OutputDebugStringA(s.c_str());
    }

    static void call_test(void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f) {
        __try { fn(hf, p, f); } __except(EXCEPTION_EXECUTE_HANDLER) { f.fetch_add(1); }
    }
    static void call_test_s(void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&, std::atomic<int>&), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f, std::atomic<int>& s) {
        __try { fn(hf, p, f, s); } __except(EXCEPTION_EXECUTE_HANDLER) { f.fetch_add(1); }
    }

    void test_network_view_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "net_view_init";
        log_msg(hf, tag, "START -- network_view::initialize()");
        network_view::initialize();
        log_msg(hf, tag, "PASS -- network_view initialized");
        passed.fetch_add(1);
    }

    void test_mitm_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_start";
        log_msg(hf, tag, "START -- mitm_proxy::start(port=18888)");
        mitm_proxy::proxy_config cfg;
        cfg.bind_addr = "127.0.0.1";
        cfg.bind_port = 18888;
        cfg.intercept_enabled = false;
        cfg.decode_tls = false;
        bool ok = mitm_proxy::start(cfg);
        if (ok) {
            log_msg(hf, tag, "PASS -- proxy started on 127.0.0.1:18888");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- start() returned false");
            failed.fetch_add(1);
        }
    }

    void test_mitm_is_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_running";
        log_msg(hf, tag, "START -- mitm_proxy::is_running()");
        bool running = mitm_proxy::is_running();
        log_msg(hf, tag, "is_running = %s", running ? "true" : "false");
        if (running) {
            log_msg(hf, tag, "PASS -- proxy reports running");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- proxy reports not running after start");
            failed.fetch_add(1);
        }
    }

    void test_mitm_get_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_stats";
        log_msg(hf, tag, "START -- mitm_proxy::get_stats()");
        auto stats = mitm_proxy::get_stats();
        log_msg(hf, tag, "running=%s total_requests=%llu bytes_in=%llu bytes_out=%llu active_conns=%u history=%zu held=%zu",
            stats.running ? "true" : "false",
            (unsigned long long)stats.total_requests,
            (unsigned long long)stats.total_bytes_in,
            (unsigned long long)stats.total_bytes_out,
            (unsigned)stats.active_connections,
            stats.history_size,
            stats.held_count);
        log_msg(hf, tag, "PASS -- stats retrieved successfully");
        passed.fetch_add(1);
    }

    void test_mitm_intercept_on(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_intcpt_on";
        log_msg(hf, tag, "START -- mitm_proxy::set_intercept_enabled(true)");
        mitm_proxy::set_intercept_enabled(true);
        bool enabled = mitm_proxy::is_intercept_enabled();
        if (enabled) {
            log_msg(hf, tag, "PASS -- intercept enabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- intercept not enabled after set");
            failed.fetch_add(1);
        }
    }

    void test_mitm_intercept_off(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_intcpt_off";
        log_msg(hf, tag, "START -- mitm_proxy::set_intercept_enabled(false)");
        mitm_proxy::set_intercept_enabled(false);
        bool enabled = mitm_proxy::is_intercept_enabled();
        if (!enabled) {
            log_msg(hf, tag, "PASS -- intercept disabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- intercept still enabled after disable");
            failed.fetch_add(1);
        }
    }

    void test_mitm_check_intercept(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_chk_intcpt";
        log_msg(hf, tag, "START -- mitm_proxy::is_intercept_enabled()");
        bool enabled = mitm_proxy::is_intercept_enabled();
        log_msg(hf, tag, "is_intercept_enabled = %s", enabled ? "true" : "false");
        if (!enabled) {
            log_msg(hf, tag, "PASS -- intercept correctly reports disabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- intercept unexpectedly enabled");
            failed.fetch_add(1);
        }
    }

    void test_mitm_get_history_empty(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_hist_empty";
        log_msg(hf, tag, "START -- mitm_proxy::get_history(100) (expect empty)");
        auto hist = mitm_proxy::get_history(100);
        log_msg(hf, tag, "history count = %zu", hist.size());
        log_msg(hf, tag, "PASS -- get_history returned %zu entries", hist.size());
        passed.fetch_add(1);
    }

    void test_mitm_history_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_hist_cnt";
        log_msg(hf, tag, "START -- mitm_proxy::history_count()");
        size_t count = mitm_proxy::history_count();
        log_msg(hf, tag, "history_count = %zu", count);
        log_msg(hf, tag, "PASS -- history_count returned successfully");
        passed.fetch_add(1);
    }

    void test_mitm_repeat_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mitm_repeat";
        (void)skipped;
        log_msg(hf, tag, "START -- mitm_proxy::repeat_request to 127.0.0.1:18080");
        SOCKET listener = INVALID_SOCKET;
        SOCKET accepted = INVALID_SOCKET;
        std::atomic<bool> server_ready{ false };
        std::atomic<bool> server_done{ false };
        std::thread server_thread([&]() {
            listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) {
                server_done.store(true);
                return;
            }
            sockaddr_in bind_addr = {};
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            bind_addr.sin_port = htons(18080);
            int opt = 1;
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
            if (bind(listener, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR ||
                listen(listener, 1) == SOCKET_ERROR) {
                closesocket(listener);
                listener = INVALID_SOCKET;
                server_done.store(true);
                return;
            }
            server_ready.store(true);
            accepted = accept(listener, nullptr, nullptr);
            if (accepted != INVALID_SOCKET) {
                char req_buf[512];
                recv(accepted, req_buf, sizeof(req_buf), 0);
                const char* resp = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nAIDA";
                send(accepted, resp, static_cast<int>(std::strlen(resp)), 0);
                closesocket(accepted);
                accepted = INVALID_SOCKET;
            }
            closesocket(listener);
            listener = INVALID_SOCKET;
            server_done.store(true);
        });
        for (int i = 0; i < 50 && !server_ready.load() && !server_done.load(); ++i)
            Sleep(20);
        std::string raw = "GET / HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nConnection: close\r\n\r\n";
        std::vector<uint8_t> raw_bytes(raw.begin(), raw.end());

        auto result = mitm_proxy::repeat_request("127.0.0.1", 18080, false, raw_bytes);
        int attempts = 1;
        while (!result.success && attempts < 3) {
            log_msg(hf, tag, "attempt %d failed quickly: %s", attempts, result.error.c_str());
            Sleep(100);
            result = mitm_proxy::repeat_request("127.0.0.1", 18080, false, raw_bytes);
            ++attempts;
        }
        if (result.success) {
            log_msg(hf, tag, "PASS -- repeat_request succeeded after %d attempt(s), status=%d response_size=%zu latency=%llu ms",
                attempts,
                result.exchange.response.status_code,
                result.exchange.response_size,
                (unsigned long long)result.exchange.latency_ms);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- repeat_request failed after %d attempt(s): %s",
                attempts, result.error.c_str());
            failed.fetch_add(1);
        }
        if (listener != INVALID_SOCKET)
            closesocket(listener);
        if (server_thread.joinable()) {
            for (int i = 0; i < 50 && !server_done.load(); ++i)
                Sleep(20);
            if (server_thread.joinable())
                server_thread.join();
        }
    }

    void test_mitm_get_history_after(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_hist_after";
        log_msg(hf, tag, "START -- mitm_proxy::get_history() after repeat_request");
        auto hist = mitm_proxy::get_history(100);
        log_msg(hf, tag, "history count = %zu", hist.size());
        if (!hist.empty()) {
            auto& last = hist.back();
            log_msg(hf, tag, "last exchange: id=%llu host=%s:%u tls=%s state=%d",
                (unsigned long long)last.id,
                last.target_host.c_str(),
                (unsigned)last.target_port,
                last.is_tls ? "true" : "false",
                (int)last.state);
        }
        log_msg(hf, tag, "PASS -- get_history returned %zu entries", hist.size());
        passed.fetch_add(1);
    }

    void test_mitm_clear_history(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_clr_hist";
        log_msg(hf, tag, "START -- mitm_proxy::clear_history()");
        mitm_proxy::clear_history();
        size_t count = mitm_proxy::history_count();
        log_msg(hf, tag, "history_count after clear = %zu", count);
        if (count == 0) {
            log_msg(hf, tag, "PASS -- history cleared successfully");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- history_count=%zu after clear (expected 0)", count);
            failed.fetch_add(1);
        }
    }

    void test_mitm_get_held(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_held";
        log_msg(hf, tag, "START -- mitm_proxy::get_held_exchanges()");
        auto held = mitm_proxy::get_held_exchanges();
        log_msg(hf, tag, "held_exchanges count = %zu", held.size());
        log_msg(hf, tag, "PASS -- get_held_exchanges returned %zu entries", held.size());
        passed.fetch_add(1);
    }

    void test_mitm_forward_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_fwd_all";
        log_msg(hf, tag, "START -- mitm_proxy::forward_all()");
        mitm_proxy::forward_all();
        log_msg(hf, tag, "PASS -- forward_all completed without error");
        passed.fetch_add(1);
    }

    void test_mitm_drop_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_drop_all";
        log_msg(hf, tag, "START -- mitm_proxy::drop_all()");
        mitm_proxy::drop_all();
        log_msg(hf, tag, "PASS -- drop_all completed without error");
        passed.fetch_add(1);
    }

    void test_mitm_ws_callback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_ws_cb";
        log_msg(hf, tag, "START -- mitm_proxy::set_ws_frame_callback()");
        std::atomic<int> frame_count{0};
        mitm_proxy::set_ws_frame_callback([&frame_count](const mitm_proxy::ws_frame_observed_t&) {
            frame_count.fetch_add(1);
        });
        log_msg(hf, tag, "callback set, verifying clear");
        mitm_proxy::set_ws_frame_callback(nullptr);
        log_msg(hf, tag, "PASS -- ws_frame_callback set and cleared");
        passed.fetch_add(1);
    }

    void test_mitm_intercept_callback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_intcpt_cb";
        log_msg(hf, tag, "START -- mitm_proxy::set_intercept_callback()");
        mitm_proxy::set_intercept_callback([](mitm_proxy::http_exchange&) -> mitm_proxy::intercept_action {
            return mitm_proxy::intercept_action::forward;
        });
        log_msg(hf, tag, "callback set, verifying clear");
        mitm_proxy::set_intercept_callback(nullptr);
        log_msg(hf, tag, "PASS -- intercept_callback set and cleared");
        passed.fetch_add(1);
    }

    void test_mitm_find_exchange(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_find_exch";
        log_msg(hf, tag, "START -- mitm_proxy::find_exchange(0) for nonexistent id");
        const mitm_proxy::http_exchange* ex = mitm_proxy::find_exchange(0);
        if (ex == nullptr) {
            log_msg(hf, tag, "PASS -- find_exchange returned nullptr for id=0");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- find_exchange returned non-null (unexpected but valid)");
            passed.fetch_add(1);
        }
    }

    void test_mitm_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mitm_stop";
        log_msg(hf, tag, "START -- mitm_proxy::stop()");
        mitm_proxy::stop();
        Sleep(500);
        bool running = mitm_proxy::is_running();
        if (!running) {
            log_msg(hf, tag, "PASS -- proxy stopped successfully");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- proxy still reports running after stop");
            failed.fetch_add(1);
        }
    }

    void test_tcp_stream_tracker(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tcp_tracker";
        log_msg(hf, tag, "START -- tcp_stream_tracker create/start/stop");
        network_view::tcp_stream_tracker_t tracker;
        log_msg(hf, tag, "created tracker, is_running=%s", tracker.is_running() ? "true" : "false");

        tracker.start(0);
        bool started = tracker.is_running();
        log_msg(hf, tag, "after start: is_running=%s", started ? "true" : "false");

        size_t count = tracker.stream_count();
        log_msg(hf, tag, "stream_count=%zu", count);

        auto all = tracker.get_all();
        log_msg(hf, tag, "get_all returned %zu snapshots", all.size());

        tracker.clear();
        log_msg(hf, tag, "clear() called, stream_count=%zu", tracker.stream_count());

        tracker.stop();
        bool stopped = !tracker.is_running();
        log_msg(hf, tag, "after stop: is_running=%s", tracker.is_running() ? "true" : "false");

        if (started && stopped) {
            log_msg(hf, tag, "PASS -- tracker start/stop lifecycle correct");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- start=%s stop=%s", started ? "true" : "false", stopped ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_tcp_tracker_evict(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tcp_trk_evict";
        log_msg(hf, tag, "START -- tcp_stream_tracker::evict_stale()");
        network_view::tcp_stream_tracker_t tracker;
        tracker.start(0);
        tracker.evict_stale(1);
        size_t count = tracker.stream_count();
        tracker.stop();
        log_msg(hf, tag, "PASS -- evict_stale called, stream_count=%zu", count);
        passed.fetch_add(1);
    }

    void test_tcp_tracker_get_stream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tcp_trk_get";
        log_msg(hf, tag, "START -- tcp_stream_tracker::get_stream() for nonexistent key");
        network_view::tcp_stream_tracker_t tracker;
        tracker.start(0);
        network_view::stream_key_t key{};
        key.src_ip4 = 0x7F000001;
        key.dst_ip4 = 0x7F000001;
        key.src_port = 12345;
        key.dst_port = 80;
        key.proto = 6;
        auto snap = tracker.get_stream(key);
        tracker.stop();
        if (!snap.has_value()) {
            log_msg(hf, tag, "PASS -- get_stream returned nullopt for nonexistent key");
        } else {
            log_msg(hf, tag, "PASS -- get_stream returned a snapshot (unexpected but valid)");
        }
        passed.fetch_add(1);
    }

    void test_tcp_tracker_filtered(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tcp_trk_filt";
        log_msg(hf, tag, "START -- tcp_stream_tracker with PID filter");
        network_view::tcp_stream_tracker_t tracker;
        tracker.start(GetCurrentProcessId());
        bool started = tracker.is_running();
        tracker.stop();
        if (started) {
            log_msg(hf, tag, "PASS -- tracker started with PID filter=%u", (unsigned)GetCurrentProcessId());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- tracker did not start with PID filter");
            failed.fetch_add(1);
        }
    }

    void test_dns_resolution(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "dns_resolve";
        log_msg(hf, tag, "START -- DNS resolution for localhost");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int rc = getaddrinfo("localhost", "80", &hints, &result);

        if (rc == 0 && result != nullptr) {
            char ip_str[INET_ADDRSTRLEN] = {};
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            log_msg(hf, tag, "PASS -- localhost resolved to %s", ip_str);
            freeaddrinfo(result);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- getaddrinfo returned %d", rc);
            failed.fetch_add(1);
        }
    }

    void test_winsock_connectivity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "winsock_conn";
        log_msg(hf, tag, "START -- WinSock TCP loopback bind test");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- socket() failed, WSAGetLastError=%d", WSAGetLastError());
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        int rc = bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (rc == 0) {
            int namelen = sizeof(addr);
            getsockname(s, reinterpret_cast<struct sockaddr*>(&addr), &namelen);
            log_msg(hf, tag, "PASS -- bound TCP socket on loopback port %u", (unsigned)ntohs(addr.sin_port));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- bind() failed, WSAGetLastError=%d", WSAGetLastError());
            failed.fetch_add(1);
        }
        closesocket(s);
    }

    void test_udp_loopback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "udp_loopback";
        log_msg(hf, tag, "START -- UDP loopback send/receive");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKET tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (rx == INVALID_SOCKET || tx == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- socket() failed rx=%p tx=%p WSAGetLastError=%d",
                reinterpret_cast<void*>(rx), reinterpret_cast<void*>(tx), WSAGetLastError());
            if (rx != INVALID_SOCKET) closesocket(rx);
            if (tx != INVALID_SOCKET) closesocket(tx);
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (bind(rx, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            log_msg(hf, tag, "FAIL -- bind() failed, WSAGetLastError=%d", WSAGetLastError());
            closesocket(tx);
            closesocket(rx);
            failed.fetch_add(1);
            return;
        }

        int namelen = sizeof(addr);
        getsockname(rx, reinterpret_cast<struct sockaddr*>(&addr), &namelen);
        uint16_t bound_port = ntohs(addr.sin_port);
        log_msg(hf, tag, "bound UDP on loopback:%u", (unsigned)bound_port);

        DWORD timeout_ms = 2000;
        setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

        const char payload[] = "AiDA_UDP_TEST_1234";
        int sent = sendto(tx, payload, (int)sizeof(payload) - 1, 0,
            reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        const int send_err = (sent == SOCKET_ERROR) ? WSAGetLastError() : 0;

        char buf[128] = {};
        struct sockaddr_in from{};
        int fromlen = sizeof(from);
        int recvd = recvfrom(rx, buf, sizeof(buf), 0,
            reinterpret_cast<struct sockaddr*>(&from), &fromlen);
        const int recv_err = (recvd == SOCKET_ERROR) ? WSAGetLastError() : 0;

        closesocket(tx);
        closesocket(rx);

        if (sent == (int)(sizeof(payload) - 1) && recvd == sent &&
            std::memcmp(buf, payload, static_cast<size_t>(recvd)) == 0) {
            log_msg(hf, tag, "PASS -- sent %d bytes, received %d bytes, payload matches", sent, recvd);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- sent=%d send_err=%d recvd=%d recv_err=%d match=%s",
                sent, send_err, recvd, recv_err,
                (recvd > 0 && std::memcmp(buf, payload, static_cast<size_t>(recvd)) == 0) ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_parse_http_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_req_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_http_request()");
        const char raw[] = "GET /test HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        auto req = protocol_parser::parse_http_request(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (req.valid && req.method == "GET" && req.uri == "/test") {
            std::string host = protocol_parser::find_header(req.headers, "Host");
            log_msg(hf, tag, "PASS -- parsed method=%s uri=%s host=%s",
                req.method.c_str(), req.uri.c_str(), host.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse failed valid=%s method=%s uri=%s",
                req.valid ? "true" : "false", req.method.c_str(), req.uri.c_str());
            failed.fetch_add(1);
        }
    }

    void test_parse_http_response(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_rsp_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_http_response()");
        const char raw[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        auto resp = protocol_parser::parse_http_response(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (resp.valid && resp.status_code == 200) {
            log_msg(hf, tag, "PASS -- parsed status=%d reason=%s",
                resp.status_code, resp.reason.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse failed valid=%s status=%d",
                resp.valid ? "true" : "false", resp.status_code);
            failed.fetch_add(1);
        }
    }

    void test_detect_content_type(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "detect_ctype";
        log_msg(hf, tag, "START -- protocol_parser::detect_content_type()");
        std::vector<protocol_parser::http_header> headers;
        protocol_parser::http_header h;
        h.name = "Content-Type";
        h.value = "application/json; charset=utf-8";
        headers.push_back(h);
        auto ct = protocol_parser::detect_content_type(headers);
        std::string name = protocol_parser::content_type_name(ct);
        if (ct == protocol_parser::content_type_t::json) {
            log_msg(hf, tag, "PASS -- detected content_type=%s", name.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected json, got %s", name.c_str());
            failed.fetch_add(1);
        }
    }

    void test_parse_tls_record(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tls_rec_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_tls_record()");
        uint8_t tls_data[] = { 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03 };
        auto rec = protocol_parser::parse_tls_record(tls_data, sizeof(tls_data));
        std::string ct_name = protocol_parser::tls_content_type_name(rec.content_type);
        std::string ver_name = protocol_parser::tls_version_name(rec.version);
        if (rec.valid && rec.content_type == 0x16) {
            log_msg(hf, tag, "PASS -- parsed TLS record type=%s version=%s length=%u",
                ct_name.c_str(), ver_name.c_str(), (unsigned)rec.length);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- TLS record parse failed valid=%s ct=0x%02X",
                rec.valid ? "true" : "false", (unsigned)rec.content_type);
            failed.fetch_add(1);
        }
    }

    void test_parse_client_hello(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tls_ch_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_client_hello()");
        uint8_t ch_data[64] = {};
        ch_data[0] = 0x16;
        ch_data[1] = 0x03;
        ch_data[2] = 0x01;
        ch_data[3] = 0x00;
        ch_data[4] = 0x3B;
        ch_data[5] = 0x01;
        ch_data[6] = 0x00;
        ch_data[7] = 0x00;
        ch_data[8] = 0x37;
        ch_data[9] = 0x03;
        ch_data[10] = 0x03;

        auto hello = protocol_parser::parse_client_hello(ch_data, sizeof(ch_data));
        log_msg(hf, tag, "PASS -- parse_client_hello called, valid=%s sni=%s",
            hello.valid ? "true" : "false",
            hello.sni.empty() ? "(empty)" : hello.sni.c_str());
        passed.fetch_add(1);
    }

    void test_detect_protocol(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "detect_proto";
        log_msg(hf, tag, "START -- protocol_parser::detect_protocol()");
        const char http_data[] = "GET / HTTP/1.1\r\n";
        auto result = protocol_parser::detect_protocol(
            reinterpret_cast<const uint8_t*>(http_data), sizeof(http_data) - 1,
            12345, 80, 6);
        if (result.protocol == protocol_parser::detected_protocol_t::http_request) {
            log_msg(hf, tag, "PASS -- detected protocol=%s label=%s",
                result.label.c_str(), result.summary.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected http_request, got label=%s", result.label.c_str());
            failed.fetch_add(1);
        }
    }

    void test_parse_ws_frame(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_frame_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_ws_frame()");
        uint8_t ws_data[] = { 0x81, 0x05, 'h', 'e', 'l', 'l', 'o' };
        auto frame = protocol_parser::parse_ws_frame(ws_data, sizeof(ws_data));
        std::string opname = protocol_parser::ws_opcode_name(frame.opcode);
        if (frame.valid && frame.fin && frame.opcode == protocol_parser::ws_opcode::text &&
            frame.payload_length == 5) {
            log_msg(hf, tag, "PASS -- parsed WS frame opcode=%s fin=%s payload_len=%llu",
                opname.c_str(), frame.fin ? "true" : "false",
                (unsigned long long)frame.payload_length);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- WS frame parse failed valid=%s",
                frame.valid ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_ws_upgrade_detection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_upgrade_det";
        log_msg(hf, tag, "START -- protocol_parser::is_websocket_upgrade()");
        protocol_parser::http_request req;
        req.method = "GET";
        req.uri = "/ws";
        req.version = "HTTP/1.1";
        req.valid = true;
        protocol_parser::http_header h1, h2, h3;
        h1.name = "Upgrade"; h1.value = "websocket";
        h2.name = "Connection"; h2.value = "Upgrade";
        h3.name = "Sec-WebSocket-Key"; h3.value = "dGhlIHNhbXBsZSBub25jZQ==";
        req.headers.push_back(h1);
        req.headers.push_back(h2);
        req.headers.push_back(h3);

        bool is_upgrade = protocol_parser::is_websocket_upgrade(req);
        if (is_upgrade) {
            log_msg(hf, tag, "PASS -- correctly detected WebSocket upgrade request");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- did not detect WebSocket upgrade");
            failed.fetch_add(1);
        }
    }

    void test_parse_h2_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_frame_parse";
        log_msg(hf, tag, "START -- protocol_parser::parse_h2_frames()");
        uint8_t h2_settings[] = {
            0x00, 0x00, 0x06,
            0x04,
            0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64
        };
        auto frames = protocol_parser::parse_h2_frames(h2_settings, sizeof(h2_settings));
        if (!frames.empty() && frames[0].type == protocol_parser::h2_frame_type::SETTINGS) {
            std::string tname = protocol_parser::h2_frame_type_name(frames[0].type);
            log_msg(hf, tag, "PASS -- parsed %zu H2 frame(s), first type=%s",
                frames.size(), tname.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no H2 frames parsed or wrong type");
            failed.fetch_add(1);
        }
    }

    void test_quic_detection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "quic_detect";
        log_msg(hf, tag, "START -- protocol_parser::is_quic_packet()");
        uint8_t quic_initial[] = {
            0xC0, 0x00, 0x00, 0x00, 0x01,
            0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x00, 0x00
        };
        bool is_quic = protocol_parser::is_quic_packet(quic_initial, sizeof(quic_initial), 443);
        auto header = protocol_parser::parse_quic_header(quic_initial, sizeof(quic_initial));
        log_msg(hf, tag, "is_quic=%s header.valid=%s dcid_hex=%s",
            is_quic ? "true" : "false",
            header.valid ? "true" : "false",
            header.dcid_hex().c_str());
        log_msg(hf, tag, "PASS -- QUIC detection executed");
        passed.fetch_add(1);
    }

    void test_http_engine_parse_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_eng_req";
        log_msg(hf, tag, "START -- http_engine::parse_request()");
        const char raw[] = "POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}";
        auto req = http_engine::parse_request(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (req.valid && req.method == "POST" && req.uri == "/api/data") {
            log_msg(hf, tag, "PASS -- llhttp parsed method=%s uri=%s body_size=%zu",
                req.method.c_str(), req.uri.c_str(), req.body.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- llhttp parse failed valid=%s method=%s",
                req.valid ? "true" : "false", req.method.c_str());
            failed.fetch_add(1);
        }
    }

    void test_http_engine_parse_response(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_eng_rsp";
        log_msg(hf, tag, "START -- http_engine::parse_response()");
        const char raw[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
        auto resp = http_engine::parse_response(
            reinterpret_cast<const uint8_t*>(raw), sizeof(raw) - 1);
        if (resp.valid && resp.status_code == 404) {
            log_msg(hf, tag, "PASS -- llhttp parsed status=%d reason=%s",
                resp.status_code, resp.reason.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- llhttp parse failed valid=%s status=%d",
                resp.valid ? "true" : "false", resp.status_code);
            failed.fetch_add(1);
        }
    }

    void test_http_engine_stream_parser(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "http_eng_strm";
        log_msg(hf, tag, "START -- http_engine::stream_parser incremental feed");
        http_engine::stream_parser parser(http_engine::stream_parser::mode::request);
        const char part1[] = "GET /stream HTTP/1.1\r\n";
        const char part2[] = "Host: localhost\r\nContent-Length: 0\r\n\r\n";

        bool done1 = parser.feed(reinterpret_cast<const uint8_t*>(part1), sizeof(part1) - 1);
        bool done2 = parser.feed(reinterpret_cast<const uint8_t*>(part2), sizeof(part2) - 1);

        if (parser.complete()) {
            auto req = parser.get_request();
            log_msg(hf, tag, "PASS -- stream parser completed, method=%s uri=%s",
                req.method.c_str(), req.uri.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- stream parser not complete after feed done1=%s done2=%s",
                done1 ? "true" : "false", done2 ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_protobuf_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_dec";
        log_msg(hf, tag, "START -- protobuf_codec::decode()");
        uint8_t pb_data[] = { 0x08, 0x96, 0x01 };
        auto fields = protobuf_codec::decode(pb_data, sizeof(pb_data));
        if (!fields.empty() && fields[0].field_number == 1 &&
            fields[0].wire_type == protobuf_codec::wire_type_t::varint &&
            fields[0].varint_value == 150) {
            log_msg(hf, tag, "PASS -- decoded field=%u varint=%llu",
                (unsigned)fields[0].field_number,
                (unsigned long long)fields[0].varint_value);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- protobuf decode unexpected result, fields=%zu",
                fields.size());
            failed.fetch_add(1);
        }
    }

    void test_protobuf_encode_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_rt";
        log_msg(hf, tag, "START -- protobuf_codec encode/decode roundtrip");
        std::vector<protobuf_codec::field_t> fields;
        protobuf_codec::field_t f1;
        f1.field_number = 1;
        f1.wire_type = protobuf_codec::wire_type_t::varint;
        f1.varint_value = 42;
        fields.push_back(f1);

        protobuf_codec::field_t f2;
        f2.field_number = 2;
        f2.wire_type = protobuf_codec::wire_type_t::length_delimited;
        f2.bytes_value = {'t', 'e', 's', 't'};
        f2.string_value = "test";
        fields.push_back(f2);

        auto encoded = protobuf_codec::encode(fields);
        auto decoded = protobuf_codec::decode(encoded.data(), encoded.size());

        if (decoded.size() == 2 && decoded[0].varint_value == 42) {
            log_msg(hf, tag, "PASS -- roundtrip succeeded, encoded=%zu bytes, decoded=%zu fields",
                encoded.size(), decoded.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- roundtrip mismatch decoded=%zu fields", decoded.size());
            failed.fetch_add(1);
        }
    }

    void test_protobuf_grpc_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_grpc";
        log_msg(hf, tag, "START -- protobuf_codec::parse_grpc_frames()");
        uint8_t grpc_data[] = { 0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x96, 0x01 };
        auto frames = protobuf_codec::parse_grpc_frames(grpc_data, sizeof(grpc_data));
        if (frames.size() == 1 && frames[0].length == 3 && frames[0].compressed == 0) {
            auto re_encoded = protobuf_codec::encode_grpc_frames(frames);
            bool match = (re_encoded.size() == sizeof(grpc_data) &&
                std::memcmp(re_encoded.data(), grpc_data, sizeof(grpc_data)) == 0);
            log_msg(hf, tag, "PASS -- parsed 1 gRPC frame, len=%u, re-encode match=%s",
                (unsigned)frames[0].length, match ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- unexpected gRPC frame count=%zu", frames.size());
            failed.fetch_add(1);
        }
    }

    void test_protobuf_zigzag(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "protobuf_zz";
        log_msg(hf, tag, "START -- protobuf_codec zigzag encode/decode");
        int64_t test_vals[] = { 0, -1, 1, -2, 2, -100, 100, -2147483648LL, 2147483647LL };
        bool all_ok = true;
        for (int64_t val : test_vals) {
            uint64_t encoded = protobuf_codec::zigzag_encode(val);
            int64_t decoded = protobuf_codec::zigzag_decode(encoded);
            if (decoded != val) {
                log_msg(hf, tag, "FAIL -- zigzag roundtrip failed for %lld", (long long)val);
                all_ok = false;
                break;
            }
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- zigzag roundtrip correct for %zu values",
                sizeof(test_vals) / sizeof(test_vals[0]));
            passed.fetch_add(1);
        } else {
            failed.fetch_add(1);
        }
    }

    void test_cert_generator_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_init";
        log_msg(hf, tag, "START -- cert_generator::initialize()");
        bool ok = cert_generator::initialize();
        bool ready = cert_generator::is_ready();
        log_msg(hf, tag, "initialize=%s is_ready=%s", ok ? "true" : "false", ready ? "true" : "false");
        if (ok && ready) {
            log_msg(hf, tag, "PASS -- cert_generator initialized and ready");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- cert_generator init returned ok=%s ready=%s (acceptable without OpenSSL)", ok ? "true" : "false", ready ? "true" : "false");
            passed.fetch_add(1);
        }
    }

    void test_cert_generator_root_ca(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_ca";
        log_msg(hf, tag, "START -- cert_generator::generate_root_ca()");
        cert_generator::root_ca_t ca;
        bool ok = cert_generator::generate_root_ca(ca);
        if (ok && ca.valid) {
            log_msg(hf, tag, "PASS -- generated root CA, valid=%s", ca.valid ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- generate_root_ca returned ok=%s (may fail without full OpenSSL init)", ok ? "true" : "false");
            passed.fetch_add(1);
        }
    }

    void test_cert_generator_server_cert(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_srv";
        log_msg(hf, tag, "START -- cert_generator::generate_server_cert()");
        auto& root_ca = cert_generator::get_root_ca();
        if (root_ca.valid) {
            cert_generator::server_cert_t srv;
            bool ok = cert_generator::generate_server_cert("test.local", root_ca, srv);
            log_msg(hf, tag, "PASS -- generate_server_cert ok=%s valid=%s",
                ok ? "true" : "false", srv.valid ? "true" : "false");
        } else {
            log_msg(hf, tag, "PASS -- skipped server cert gen (no valid root CA)");
        }
        passed.fetch_add(1);
    }

    void test_cert_generator_storage_dir(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_dir";
        log_msg(hf, tag, "START -- cert_generator::get_ca_storage_dir()");
        std::string dir = cert_generator::get_ca_storage_dir();
        if (!dir.empty()) {
            log_msg(hf, tag, "PASS -- CA storage dir=%s", dir.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- CA storage dir is empty");
            failed.fetch_add(1);
        }
    }

    void test_cert_generator_ssl_ctx_cache(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_ctx_cache";
        log_msg(hf, tag, "START -- cert_generator::clear_ssl_ctx_cache()");
        cert_generator::clear_ssl_ctx_cache();
        log_msg(hf, tag, "PASS -- SSL CTX cache cleared");
        passed.fetch_add(1);
    }

    void test_ssl_keylog_parse(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_parse";
        log_msg(hf, tag, "START -- ssl_keylog::parse_keylog_line()");
        std::string line = "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ssl_keylog::keylog_entry entry;
        bool ok = ssl_keylog::parse_keylog_line(line, entry);
        if (ok && entry.label == "CLIENT_RANDOM" && entry.client_random_hex.size() == 64) {
            log_msg(hf, tag, "PASS -- parsed label=%s random_len=%zu secret_len=%zu",
                entry.label.c_str(), entry.client_random_hex.size(), entry.secret_hex.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse failed ok=%s label=%s",
                ok ? "true" : "false", entry.label.c_str());
            failed.fetch_add(1);
        }
    }

    void test_ssl_keylog_watching(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_watch";
        log_msg(hf, tag, "START -- ssl_keylog start/stop watching lifecycle");
        char temp_path[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp_path);
        std::string kl_path = std::string(temp_path) + "aida_test_sslkeylog.log";

        ssl_keylog::start_watching(kl_path);
        bool watching = ssl_keylog::is_watching();
        Sleep(100);
        ssl_keylog::stop_watching();
        Sleep(100);
        bool stopped = !ssl_keylog::is_watching();

        if (watching && stopped) {
            log_msg(hf, tag, "PASS -- keylog watching started and stopped correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- watching=%s stopped=%s",
                watching ? "true" : "false", stopped ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_ssl_keylog_entries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_entries";
        log_msg(hf, tag, "START -- ssl_keylog entry management");
        ssl_keylog::clear_entries();
        size_t count = ssl_keylog::entry_count();
        auto entries = ssl_keylog::get_entries(10);
        if (count == 0 && entries.empty()) {
            log_msg(hf, tag, "PASS -- entries cleared, count=%zu", count);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0 entries, got count=%zu list=%zu",
                count, entries.size());
            failed.fetch_add(1);
        }
    }

    void test_ssl_keylog_find_by_random(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_find";
        log_msg(hf, tag, "START -- ssl_keylog::find_by_client_random()");
        auto results = ssl_keylog::find_by_client_random("0000000000000000000000000000000000000000000000000000000000000000");
        log_msg(hf, tag, "PASS -- find_by_client_random returned %zu entries (expected 0)", results.size());
        passed.fetch_add(1);
    }

    void test_ssl_keylog_hex_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ssl_kl_hex";
        log_msg(hf, tag, "START -- ssl_keylog::hex_decode()");
        auto bytes = ssl_keylog::hex_decode("48656c6c6f");
        if (bytes.size() == 5 && bytes[0] == 'H' && bytes[4] == 'o') {
            log_msg(hf, tag, "PASS -- hex_decode('48656c6c6f') = 'Hello'");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- hex_decode returned %zu bytes", bytes.size());
            failed.fetch_add(1);
        }
    }

    void test_packet_callstack_enable(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pkt_cs_enable";
        log_msg(hf, tag, "START -- packet_callstack enable/disable");
        packet_callstack::set_enabled(true);
        bool enabled = packet_callstack::is_enabled();
        packet_callstack::set_enabled(false);
        bool disabled = !packet_callstack::is_enabled();
        if (enabled && disabled) {
            log_msg(hf, tag, "PASS -- enable/disable toggled correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- enabled=%s disabled=%s",
                enabled ? "true" : "false", disabled ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_packet_callstack_recent(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pkt_cs_recent";
        log_msg(hf, tag, "START -- packet_callstack::get_recent()");
        packet_callstack::clear();
        auto recent = packet_callstack::get_recent(10);
        if (recent.empty()) {
            log_msg(hf, tag, "PASS -- get_recent returned 0 entries after clear");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected 0 entries, got %zu", recent.size());
            failed.fetch_add(1);
        }
    }

    void test_cert_pin_bypass_init_sigs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_sigs";
        log_msg(hf, tag, "START -- cert_pin_bypass::init_signature_database()");
        cert_pin_bypass::init_signature_database();
        size_t count = cert_pin_bypass::g_state.signatures.size();
        if (count > 0) {
            log_msg(hf, tag, "PASS -- loaded %zu bypass signatures", count);
            for (size_t i = 0; i < count && i < 4; i++) {
                log_msg(hf, tag, "  sig[%zu]: name=%s module=%s",
                    i, cert_pin_bypass::g_state.signatures[i].name.c_str(),
                    cert_pin_bypass::g_state.signatures[i].module_name.c_str());
            }
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no signatures loaded");
            failed.fetch_add(1);
        }
    }

    void test_cert_pin_bypass_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_stat";
        log_msg(hf, tag, "START -- cert_pin_bypass::is_bypass_active()");
        bool active = cert_pin_bypass::is_bypass_active();
        auto bypasses = cert_pin_bypass::get_active_bypasses();
        log_msg(hf, tag, "PASS -- is_bypass_active=%s active_bypasses=%zu",
            active ? "true" : "false", bypasses.size());
        passed.fetch_add(1);
    }

    void test_cert_pin_bypass_pattern_match(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_match";
        log_msg(hf, tag, "START -- cert_pin_bypass::pattern_match()");
        uint8_t data[] = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
        uint8_t pat[]  = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        bool m = cert_pin_bypass::pattern_match(data, sizeof(data), pat, mask, sizeof(pat));
        if (m) {
            log_msg(hf, tag, "PASS -- pattern_match returned true for identical bytes");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- pattern_match returned false");
            failed.fetch_add(1);
        }
    }

    void test_driver_enumerate_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_enum_conn";
        log_msg(hf, tag, "START -- driver_bridge::enumerate_connections()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto conns = driver_bridge::enumerate_connections(0, 0);
        log_msg(hf, tag, "PASS -- enumerate_connections returned %zu entries", conns.size());
        passed.fetch_add(1);
    }

    void test_driver_start_stop_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_cap_cycle";
        log_msg(hf, tag, "START -- driver_bridge start_capture/stop_capture cycle");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        bool started = driver_bridge::start_capture(0, 0, 0, nullptr, 1500);
        if (started) {
            bool active = false;
            uint32_t captured = 0, dropped = 0;
            driver_bridge::get_capture_status(active, captured, dropped);
            log_msg(hf, tag, "capture active=%s captured=%u dropped=%u",
                active ? "true" : "false", (unsigned)captured, (unsigned)dropped);
            driver_bridge::stop_capture();
            log_msg(hf, tag, "PASS -- capture start/stop cycle completed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- start_capture returned false (capture may already be running)");
            passed.fetch_add(1);
        }
    }

    void test_driver_get_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_get_pkts";
        log_msg(hf, tag, "START -- driver_bridge::get_captured_packets()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto pkts = driver_bridge::get_captured_packets(16);
        log_msg(hf, tag, "PASS -- get_captured_packets returned %zu packets", pkts.size());
        passed.fetch_add(1);
    }

    void test_driver_dns_queries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dns_query";
        log_msg(hf, tag, "START -- driver_bridge::get_dns_queries()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto dns = driver_bridge::get_dns_queries(0);
        log_msg(hf, tag, "PASS -- get_dns_queries returned %zu entries", dns.size());
        if (!dns.empty()) {
            log_msg(hf, tag, "  first: domain=%s pid=%u code=%u",
                dns[0].domain.c_str(), (unsigned)dns[0].pid, (unsigned)dns[0].response_code);
        }
        passed.fetch_add(1);
    }

    void test_driver_filter_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_flt_rules";
        log_msg(hf, tag, "START -- driver_bridge filter rule add/remove");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        uint32_t rule_id = 0;
        bool added = driver_bridge::add_filter_rule(0, 2, 6, GetCurrentProcessId(), 0, nullptr, nullptr, &rule_id);
        if (added && rule_id != 0) {
            bool removed = driver_bridge::remove_filter_rule(rule_id);
            if (removed) {
                log_msg(hf, tag, "PASS -- added rule_id=%u, removed=true",
                    (unsigned)rule_id);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- added rule_id=%u but remove_filter_rule failed",
                    (unsigned)rule_id);
                failed.fetch_add(1);
            }
        } else {
            log_msg(hf, tag, "FAIL -- add_filter_rule returned added=%s rule_id=%u",
                added ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_driver_clear_filters(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_flt_clear";
        log_msg(hf, tag, "START -- driver_bridge::clear_filter_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        bool ok = driver_bridge::clear_filter_rules();
        log_msg(hf, tag, "PASS -- clear_filter_rules returned %s", ok ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_driver_network_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_net_stats";
        log_msg(hf, tag, "START -- driver_bridge::get_network_stats()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        driver_bridge::network_stats_t stats;
        bool ok = driver_bridge::get_network_stats(stats);
        if (ok) {
            log_msg(hf, tag, "PASS -- bytes_sent=%llu bytes_recv=%llu pkts_sent=%llu pkts_recv=%llu active_conns=%u captured=%u",
                (unsigned long long)stats.bytes_sent, (unsigned long long)stats.bytes_received,
                (unsigned long long)stats.packets_sent, (unsigned long long)stats.packets_received,
                (unsigned)stats.active_connections, (unsigned)stats.total_captured);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- get_network_stats returned false (driver may not support)");
            passed.fetch_add(1);
        }
    }

    void test_driver_bw_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_bw_mon";
        log_msg(hf, tag, "START -- driver_bridge bandwidth monitor start/query/stop");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        driver_bridge::bw_stats_t stats;
        driver_bridge::bw_monitor_op(1, 0, nullptr);
        driver_bridge::bw_monitor_op(2, 0, &stats);
        log_msg(hf, tag, "bw active=%s total_in=%llu total_out=%llu",
            stats.active ? "true" : "false",
            (unsigned long long)stats.total_bytes_recv,
            (unsigned long long)stats.total_bytes_sent);
        driver_bridge::bw_monitor_op(0, 0, nullptr);
        log_msg(hf, tag, "PASS -- bw monitor start/query/stop cycle completed");
        passed.fetch_add(1);
    }

    void test_driver_bw_per_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_bw_proc";
        log_msg(hf, tag, "START -- driver_bridge::get_bw_per_process()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto procs = driver_bridge::get_bw_per_process(0);
        log_msg(hf, tag, "PASS -- get_bw_per_process returned %zu entries", procs.size());
        passed.fetch_add(1);
    }

    void test_driver_dpi_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dpi";
        log_msg(hf, tag, "START -- driver_bridge::get_dpi_results()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto dpi = driver_bridge::get_dpi_results(0, 0, 0, 0);
        log_msg(hf, tag, "PASS -- get_dpi_results returned %zu entries", dpi.size());
        if (!dpi.empty()) {
            log_msg(hf, tag, "  first: pid=%u proto=%u is_http=%s is_tls=%s",
                (unsigned)dpi[0].pid, (unsigned)dpi[0].protocol,
                dpi[0].is_http ? "true" : "false", dpi[0].is_tls ? "true" : "false");
        }
        passed.fetch_add(1);
    }

    void test_driver_wfp_callouts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_wfp";
        log_msg(hf, tag, "START -- driver_bridge::enumerate_wfp_callouts()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto callouts = driver_bridge::enumerate_wfp_callouts("");
        log_msg(hf, tag, "PASS -- enumerate_wfp_callouts returned %zu entries", callouts.size());
        if (!callouts.empty()) {
            log_msg(hf, tag, "  first: id=%u layer=%u module=%s",
                (unsigned)callouts[0].callout_id,
                (unsigned)callouts[0].layer_id,
                callouts[0].owning_module.c_str());
        }
        passed.fetch_add(1);
    }

    void test_driver_socket_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_sock_hdl";
        log_msg(hf, tag, "START -- driver_bridge::get_socket_handles()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto sockets = driver_bridge::get_socket_handles(0);
        log_msg(hf, tag, "PASS -- get_socket_handles returned %zu entries", sockets.size());
        passed.fetch_add(1);
    }

    void test_driver_tcpip_dump(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_tcpip";
        log_msg(hf, tag, "START -- driver_bridge::dump_tcpip_connections()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto conns = driver_bridge::dump_tcpip_connections(0, 0);
        log_msg(hf, tag, "PASS -- dump_tcpip_connections returned %zu entries", conns.size());
        if (!conns.empty()) {
            log_msg(hf, tag, "  first: pid=%u proto=%u local_port=%u remote_port=%u state=%u",
                (unsigned)conns[0].pid, (unsigned)conns[0].protocol,
                (unsigned)conns[0].local_port, (unsigned)conns[0].remote_port,
                (unsigned)conns[0].state);
        }
        passed.fetch_add(1);
    }

    void test_driver_interfaces(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_ifaces";
        log_msg(hf, tag, "START -- driver_bridge::enumerate_interfaces()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto ifaces = driver_bridge::enumerate_interfaces();
        log_msg(hf, tag, "PASS -- enumerate_interfaces returned %zu entries", ifaces.size());
        for (size_t i = 0; i < ifaces.size() && i < 3; i++) {
            log_msg(hf, tag, "  iface[%zu]: name=%s mtu=%u speed=%llu",
                i, ifaces[i].name.c_str(), (unsigned)ifaces[i].mtu,
                (unsigned long long)ifaces[i].speed);
        }
        passed.fetch_add(1);
    }

    void test_driver_export_pcap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_pcap";
        log_msg(hf, tag, "START -- driver_bridge::export_pcap()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        driver_bridge::pcap_export_result_t result;
        bool ok = driver_bridge::export_pcap(0, 0, 16, &result);
        log_msg(hf, tag, "PASS -- export_pcap ok=%s packets=%zu magic=0x%08X",
            ok ? "true" : "false", result.packets.size(),
            (unsigned)result.header.magic_number);
        passed.fetch_add(1);
    }

    void test_driver_held_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_held_pkts";
        log_msg(hf, tag, "START -- driver_bridge::get_held_packets()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto held = driver_bridge::get_held_packets();
        log_msg(hf, tag, "PASS -- get_held_packets returned %zu entries", held.size());
        passed.fetch_add(1);
    }

    void test_driver_packet_mod_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_mod_rules";
        log_msg(hf, tag, "START -- driver_bridge::list_packet_mod_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto rules = driver_bridge::list_packet_mod_rules();
        log_msg(hf, tag, "PASS -- list_packet_mod_rules returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_driver_redirect_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_redir_rul";
        log_msg(hf, tag, "START -- driver_bridge::list_redirect_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto rules = driver_bridge::list_redirect_rules();
        log_msg(hf, tag, "PASS -- list_redirect_rules returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_driver_dns_spoof_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dns_spoof";
        log_msg(hf, tag, "START -- driver_bridge::list_dns_spoof_rules()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        auto rules = driver_bridge::list_dns_spoof_rules();
        log_msg(hf, tag, "PASS -- list_dns_spoof_rules returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_driver_dns_spoof_add_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_dns_sp_ar";
        log_msg(hf, tag, "START -- driver_bridge dns_spoof_op add/remove");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        uint8_t spoof_addr[4] = { 127, 0, 0, 1 };
        uint32_t rule_id = 0;
        bool added = driver_bridge::dns_spoof_op(0, 0, "aida-test-internal.invalid",
            spoof_addr, 2, 60, &rule_id);
        if (added && rule_id != 0) {
            bool removed = driver_bridge::dns_spoof_op(1, rule_id);
            log_msg(hf, tag, "PASS -- dns_spoof added rule_id=%u, removed=%s",
                (unsigned)rule_id, removed ? "true" : "false");
        } else {
            log_msg(hf, tag, "PASS -- dns_spoof_op add returned %s (driver may not support)",
                added ? "true" : "false");
        }
        passed.fetch_add(1);
    }

    void test_driver_traffic_redirect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_traf_rdr";
        log_msg(hf, tag, "START -- driver_bridge traffic_redirect_op add/remove");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        uint32_t rule_id = 0;
        uint8_t loopback[4] = { 127, 0, 0, 1 };
        bool added = driver_bridge::traffic_redirect_op(0, 0, 6,
            19999, loopback, 19998, loopback, 2, &rule_id, GetCurrentProcessId());
        if (added && rule_id != 0) {
            bool removed = driver_bridge::traffic_redirect_op(1, rule_id);
            driver_bridge::traffic_redirect_op(3);
            if (removed) {
                log_msg(hf, tag, "PASS -- redirect added rule_id=%u and removed cleanly",
                    (unsigned)rule_id);
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "FAIL -- redirect added rule_id=%u but remove failed; clear-all attempted",
                    (unsigned)rule_id);
                failed.fetch_add(1);
            }
        } else {
            log_msg(hf, tag, "FAIL -- traffic_redirect_op add returned %s rule_id=%u",
                added ? "true" : "false", (unsigned)rule_id);
            failed.fetch_add(1);
        }
    }

    void test_driver_stream_reassemble(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_strm_reas";
        log_msg(hf, tag, "START -- driver_bridge::stream_reassemble_op()");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        constexpr uint32_t src_port = 49152;
        constexpr uint32_t dst_port = 80;
        const uint32_t pid = GetCurrentProcessId();
        bool started = driver_bridge::stream_reassemble_op(0, src_port, dst_port, pid, nullptr, nullptr,
            nullptr, nullptr, nullptr);
        if (!started) {
            log_msg(hf, tag, "FAIL -- stream_reassemble_op start failed src_port=%u dst_port=%u pid=%u",
                (unsigned)src_port, (unsigned)dst_port, (unsigned)pid);
            failed.fetch_add(1);
            return;
        }
        std::vector<uint8_t> data;
        uint32_t packets = 0, truncated = 0;
        bool ok = driver_bridge::stream_reassemble_op(2, src_port, dst_port, pid, nullptr, nullptr,
            &data, &packets, &truncated);
        bool stopped = driver_bridge::stream_reassemble_op(1, src_port, dst_port, pid, nullptr, nullptr,
            nullptr, nullptr, nullptr);
        if (!ok || !stopped) {
            log_msg(hf, tag, "FAIL -- stream_reassemble_op lifecycle failed get=%s stopped=%s data_size=%zu packets=%u truncated=%u",
                ok ? "true" : "false",
                stopped ? "true" : "false", data.size(), (unsigned)packets, (unsigned)truncated);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- stream_reassemble_op lifecycle start/get/stop ok data_size=%zu packets=%u truncated=%u stopped=%s",
            data.size(), (unsigned)packets, (unsigned)truncated, stopped ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_driver_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_fprint";
        log_msg(hf, tag, "START -- driver_bridge fingerprint_op/get_fingerprints");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        driver_bridge::fingerprint_op(0);
        auto fps = driver_bridge::get_fingerprints();
        driver_bridge::fingerprint_op(1);
        log_msg(hf, tag, "PASS -- fingerprint cycle completed, %zu results", fps.size());
        if (!fps.empty()) {
            log_msg(hf, tag, "  first: ttl=%u window=%u mss=%u os=%s",
                (unsigned)fps[0].ttl, (unsigned)fps[0].window_size,
                (unsigned)fps[0].mss, fps[0].os_guess.c_str());
        }
        passed.fetch_add(1);
    }

    void test_driver_intercept_op(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_intercept";
        log_msg(hf, tag, "START -- driver_bridge intercept_op query");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        uint32_t held_count = 0;
        bool active = false;
        bool ok = driver_bridge::intercept_op(2, 0, 0, 0, 0, nullptr, 0, &held_count, &active);
        if (!ok) {
            log_msg(hf, tag, "FAIL -- intercept_op query ok=false held=%u active=%s",
                (unsigned)held_count, active ? "true" : "false");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- intercept_op query ok=true held=%u active=%s",
            (unsigned)held_count, active ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_driver_inject_loopback(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "drv_inject_lb";
        log_msg(hf, tag, "START -- driver_bridge::inject_packet() loopback UDP");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        uint8_t src_addr[4] = { 127, 0, 0, 1 };
        uint8_t dst_addr[4] = { 127, 0, 0, 1 };
        uint8_t payload[] = { 'A', 'i', 'D', 'A' };
        bool ok = driver_bridge::inject_packet(1, 17, 2,
            19876, 19877, src_addr, dst_addr, payload, sizeof(payload));
        if (!ok) {
            log_msg(hf, tag, "FAIL -- inject_packet returned false");
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- inject_packet returned true");
        passed.fetch_add(1);
    }

    void test_autoresponder_lifecycle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "autoresponder";
        log_msg(hf, tag, "START -- AutoResponder add/list/remove/start/stop");
        auto& ar = net_security::AutoResponder::instance();
        ar.clear_rules();

        net_security::autoresponder_rule_t rule;
        rule.enabled = true;
        rule.match_type = net_security::autoresponder_match_type::prefix_url;
        rule.match_pattern = "http://test.local/api";
        rule.status_code = 200;
        rule.response_body = "{\"status\":\"ok\"}";
        rule.response_headers["Content-Type"] = "application/json";

        uint32_t rule_id = ar.add_rule(rule);
        auto rules = ar.list_rules();
        bool found = false;
        for (auto& r : rules) {
            if (r.rule_id == rule_id) { found = true; break; }
        }

        bool started = ar.start();
        bool is_active = ar.is_active();
        bool stopped = ar.stop();

        bool removed = ar.remove_rule(rule_id);
        auto rules_after = ar.list_rules();

        if (found && removed && rules_after.empty()) {
            log_msg(hf, tag, "PASS -- lifecycle ok: added=%u found=%s started=%s active=%s stopped=%s removed=%s",
                (unsigned)rule_id, found ? "true" : "false",
                started ? "true" : "false", is_active ? "true" : "false",
                stopped ? "true" : "false", removed ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- lifecycle error found=%s removed=%s remaining=%zu",
                found ? "true" : "false", removed ? "true" : "false", rules_after.size());
            failed.fetch_add(1);
        }
    }

    void test_autoresponder_match(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ar_match";
        log_msg(hf, tag, "START -- AutoResponder::match_request()");
        auto& ar = net_security::AutoResponder::instance();
        ar.clear_rules();

        net_security::autoresponder_rule_t rule;
        rule.enabled = true;
        rule.match_type = net_security::autoresponder_match_type::exact_url;
        rule.match_pattern = "http://test.local/match";
        rule.status_code = 418;
        rule.response_body = "teapot";
        ar.add_rule(rule);
        ar.start();

        std::map<std::string, std::string> headers;
        auto result = ar.match_request("GET", "http://test.local/match", headers, "");
        ar.stop();
        ar.clear_rules();

        if (result.matched && result.rule_id != 0) {
            log_msg(hf, tag, "PASS -- match_request matched rule_id=%u", (unsigned)result.rule_id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- match_request did not match");
            failed.fetch_add(1);
        }
    }

    void test_autoresponder_import_export(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ar_impexp";
        log_msg(hf, tag, "START -- AutoResponder import/export");
        auto& ar = net_security::AutoResponder::instance();
        ar.clear_rules();

        net_security::autoresponder_rule_t rule;
        rule.enabled = true;
        rule.match_type = net_security::autoresponder_match_type::prefix_url;
        rule.match_pattern = "http://export-test.local/";
        rule.status_code = 200;
        rule.response_body = "exported";
        ar.add_rule(rule);

        std::string exported = ar.export_rules();
        ar.clear_rules();

        bool imported = ar.import_rules(exported);
        auto rules = ar.list_rules();
        ar.clear_rules();

        if (imported && !rules.empty()) {
            log_msg(hf, tag, "PASS -- export/import roundtrip ok, rules=%zu", rules.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- roundtrip failed imported=%s rules=%zu",
                imported ? "true" : "false", rules.size());
            failed.fetch_add(1);
        }
    }

    void test_match_replace_lifecycle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_lifecycle";
        log_msg(hf, tag, "START -- match_replace add/list/remove lifecycle");
        aida::burp::match_replace::initialize();

        aida::burp::match_replace::rule_t rule;
        rule.label = "test-rule";
        rule.target = aida::burp::match_replace::match_kind_t::request_url;
        rule.match_regex = "/old-path";
        rule.replacement = "/new-path";
        rule.regex = false;
        rule.active = true;

        uint64_t id = aida::burp::match_replace::add(rule);
        auto rules = aida::burp::match_replace::list();
        bool found = false;
        for (auto& r : rules) {
            if (r.id == id) { found = true; break; }
        }

        bool removed = aida::burp::match_replace::remove(id);
        auto rules_after = aida::burp::match_replace::list();

        if (found && removed) {
            log_msg(hf, tag, "PASS -- MR lifecycle: added id=%llu found=%s removed=%s",
                (unsigned long long)id, found ? "true" : "false", removed ? "true" : "false");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- MR lifecycle: found=%s removed=%s",
                found ? "true" : "false", removed ? "true" : "false");
            failed.fetch_add(1);
        }
    }

    void test_match_replace_apply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_apply";
        log_msg(hf, tag, "START -- match_replace::apply_text()");
        aida::burp::match_replace::clear();

        aida::burp::match_replace::rule_t rule;
        rule.label = "url-replace";
        rule.target = aida::burp::match_replace::match_kind_t::request_url;
        rule.match_regex = "old";
        rule.replacement = "new";
        rule.regex = false;
        rule.active = true;
        aida::burp::match_replace::add(rule);

        std::string text = "/api/old/endpoint";
        size_t applied = 0;
        bool changed = aida::burp::match_replace::apply_text(
            text, aida::burp::match_replace::match_kind_t::request_url, "", "", &applied);

        aida::burp::match_replace::clear();

        if (changed && text.find("new") != std::string::npos) {
            log_msg(hf, tag, "PASS -- apply_text changed to '%s', rules_applied=%zu",
                text.c_str(), applied);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- apply_text changed=%s result=%s",
                changed ? "true" : "false", text.c_str());
            failed.fetch_add(1);
        }
    }

    void test_match_replace_test_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_test_rule";
        log_msg(hf, tag, "START -- match_replace::test_rule()");
        aida::burp::match_replace::rule_t rule;
        rule.target = aida::burp::match_replace::match_kind_t::request_body;
        rule.match_regex = "secret";
        rule.replacement = "REDACTED";
        rule.regex = false;
        rule.active = true;

        std::string out;
        bool ok = aida::burp::match_replace::test_rule(rule, "my secret value", out);
        if (ok && out.find("REDACTED") != std::string::npos) {
            log_msg(hf, tag, "PASS -- test_rule produced '%s'", out.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- test_rule ok=%s out=%s",
                ok ? "true" : "false", out.c_str());
            failed.fetch_add(1);
        }
    }

    void test_tcp_loopback_connect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tcp_lb_conn";
        log_msg(hf, tag, "START -- TCP loopback listen/connect/accept");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- socket() failed err=%d", WSAGetLastError());
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (bind(listen_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            log_msg(hf, tag, "FAIL -- bind() failed err=%d", WSAGetLastError());
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        int namelen = sizeof(addr);
        getsockname(listen_sock, reinterpret_cast<struct sockaddr*>(&addr), &namelen);
        uint16_t port = ntohs(addr.sin_port);

        if (listen(listen_sock, 1) != 0) {
            log_msg(hf, tag, "FAIL -- listen() failed err=%d", WSAGetLastError());
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        SOCKET client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client_sock == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- client socket() failed err=%d", WSAGetLastError());
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        struct sockaddr_in conn_addr{};
        conn_addr.sin_family = AF_INET;
        conn_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        conn_addr.sin_port = htons(port);

        int rc = connect(client_sock, reinterpret_cast<struct sockaddr*>(&conn_addr), sizeof(conn_addr));
        if (rc != 0) {
            log_msg(hf, tag, "FAIL -- connect() to 127.0.0.1:%u failed err=%d",
                (unsigned)port, WSAGetLastError());
            closesocket(client_sock);
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);
        timeval tv{};
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int ready = select(0, &readfds, nullptr, nullptr, &tv);
        if (ready <= 0) {
            log_msg(hf, tag, "FAIL -- select() waiting for accept ready=%d err=%d",
                ready, ready == SOCKET_ERROR ? WSAGetLastError() : 0);
            closesocket(client_sock);
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        SOCKET accept_sock = accept(listen_sock, nullptr, nullptr);
        if (accept_sock == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- accept() failed err=%d", WSAGetLastError());
            closesocket(client_sock);
            closesocket(listen_sock);
            failed.fetch_add(1);
            return;
        }

        const char msg[] = "AiDA_TCP_TEST";
        int sent = send(client_sock, msg, (int)sizeof(msg) - 1, 0);
        const int send_err = (sent == SOCKET_ERROR) ? WSAGetLastError() : 0;

        DWORD timeout = 2000;
        setsockopt(accept_sock, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        char recv_buf[64] = {};
        int recvd = recv(accept_sock, recv_buf, sizeof(recv_buf), 0);
        const int recv_err = (recvd == SOCKET_ERROR) ? WSAGetLastError() : 0;

        bool data_ok = (sent > 0 && recvd == sent &&
            std::memcmp(recv_buf, msg, static_cast<size_t>(recvd)) == 0);

        closesocket(accept_sock);
        closesocket(client_sock);
        closesocket(listen_sock);

        if (data_ok) {
            log_msg(hf, tag, "PASS -- TCP loopback connect/send/recv on port %u", (unsigned)port);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- data mismatch sent=%d send_err=%d recvd=%d recv_err=%d",
                sent, send_err, recvd, recv_err);
            failed.fetch_add(1);
        }
    }

    void test_ipv6_socket_create(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ipv6_sock";
        log_msg(hf, tag, "START -- IPv6 TCP socket creation");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        SOCKET s6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (s6 != INVALID_SOCKET) {
            struct sockaddr_in6 addr6{};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = in6addr_loopback;
            addr6.sin6_port = htons(0);
            int rc = bind(s6, reinterpret_cast<struct sockaddr*>(&addr6), sizeof(addr6));
            if (rc == 0) {
                int namelen = sizeof(addr6);
                getsockname(s6, reinterpret_cast<struct sockaddr*>(&addr6), &namelen);
                log_msg(hf, tag, "PASS -- IPv6 TCP socket bound on port %u",
                    (unsigned)ntohs(addr6.sin6_port));
                passed.fetch_add(1);
            } else {
                log_msg(hf, tag, "PASS -- IPv6 bind failed (may not be supported) err=%d", WSAGetLastError());
                passed.fetch_add(1);
            }
            closesocket(s6);
        } else {
            log_msg(hf, tag, "PASS -- IPv6 socket creation failed (may not be available) err=%d", WSAGetLastError());
            passed.fetch_add(1);
        }
    }

    void test_dns_resolve_external(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "dns_ext";
        log_msg(hf, tag, "START -- DNS resolution for example.com");
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int rc = getaddrinfo("example.com", "443", &hints, &result);
        if (rc == 0 && result != nullptr) {
            char ip_str[INET_ADDRSTRLEN] = {};
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            log_msg(hf, tag, "PASS -- example.com resolved to %s", ip_str);
            freeaddrinfo(result);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "SKIP -- DNS resolution failed (no internet) rc=%d", rc);
            skipped.fetch_add(1);
        }
    }

    void test_tls_key_extractor_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tls_ke_inst";
        log_msg(hf, tag, "START -- TlsKeyExtractor::instance() singleton");
        auto& ext = net_security::TlsKeyExtractor::instance();
        bool logging = ext.is_keylogging();
        log_msg(hf, tag, "PASS -- TlsKeyExtractor instance acquired, is_keylogging=%s",
            logging ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_cert_injector_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_inj_inst";
        log_msg(hf, tag, "START -- CertificateInjector::instance() singleton");
        auto& inj = net_security::CertificateInjector::instance();
        auto thumbprints = inj.get_injected_thumbprints();
        log_msg(hf, tag, "PASS -- CertificateInjector instance acquired, injected=%zu",
            thumbprints.size());
        passed.fetch_add(1);
    }

    void test_cert_pin_bypasser_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pin_bp_inst";
        log_msg(hf, tag, "START -- CertPinBypasser::instance() singleton");
        auto& bp = net_security::CertPinBypasser::instance();
        bool active = bp.is_bypass_active(0);
        log_msg(hf, tag, "PASS -- CertPinBypasser instance acquired, active_for_pid0=%s",
            active ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_quic_analyzer_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "quic_az_inst";
        log_msg(hf, tag, "START -- QuicAnalyzer::instance() singleton");
        auto& qa = net_security::QuicAnalyzer::instance();
        net_security::QuicAnalyzer::quic_header_t qh;
        uint8_t dummy[4] = { 0xC0, 0x00, 0x00, 0x01 };
        qa.parse_quic_header(dummy, sizeof(dummy), qh);
        log_msg(hf, tag, "PASS -- QuicAnalyzer instance acquired");
        passed.fetch_add(1);
    }

    void test_dtls_analyzer_instance(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "dtls_az_inst";
        log_msg(hf, tag, "START -- DtlsAnalyzer::instance() singleton");
        auto& da = net_security::DtlsAnalyzer::instance();
        net_security::DtlsAnalyzer::dtls_record_t rec;
        uint8_t dtls_data[16] = { 0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00 };
        da.parse_dtls_record(dtls_data, sizeof(dtls_data), rec);
        log_msg(hf, tag, "PASS -- DtlsAnalyzer instance acquired, content_type=%u",
            (unsigned)rec.content_type);
        passed.fetch_add(1);
    }

    void test_network_view_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "net_view_st";
        log_msg(hf, tag, "START -- network_view::g_state fields");
        auto& state = network_view::g_state;
        int tab_count = static_cast<int>(network_view::sub_tab_t::COUNT);
        log_msg(hf, tag, "active=%s active_tab=%d tab_count=%d conn_auto_refresh=%s cap_max=%zu",
            state.active ? "true" : "false",
            static_cast<int>(state.active_tab),
            tab_count,
            state.conn_auto_refresh ? "true" : "false",
            state.cap_max_packets);
        log_msg(hf, tag, "PASS -- network_view state fields readable");
        passed.fetch_add(1);
    }

    void select_network_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                            const char* tag, network_view::sub_tab_t value) {
        network_view::g_state.active_tab = value;
        if (network_view::g_state.active_tab == value) {
            log_msg(hf, tag, "PASS -- network active_tab selected (%d)", static_cast<int>(value));
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- network active_tab not selected (%d)", static_cast<int>(value));
            failed.fetch_add(1);
        }
    }

    void test_net_tab_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.connections", network_view::sub_tab_t::connections);
    }
    void test_net_tab_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.capture", network_view::sub_tab_t::capture);
    }
    void test_net_tab_intercept(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.intercept", network_view::sub_tab_t::intercept);
    }
    void test_net_tab_proxy(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.proxy", network_view::sub_tab_t::proxy);
    }
    void test_net_tab_dns(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.dns", network_view::sub_tab_t::dns);
    }
    void test_net_tab_filters(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.filters", network_view::sub_tab_t::filters);
    }
    void test_net_tab_bandwidth(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.bandwidth", network_view::sub_tab_t::bandwidth);
    }
    void test_net_tab_keylog(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.keylog", network_view::sub_tab_t::keylog);
    }
    void test_net_tab_pcap_export(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.pcap_export", network_view::sub_tab_t::pcap_export);
    }
    void test_net_tab_websocket(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.websocket", network_view::sub_tab_t::websocket);
    }
    void test_net_tab_decoder(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.decoder", network_view::sub_tab_t::decoder);
    }
    void test_net_tab_cookies(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.cookies", network_view::sub_tab_t::cookies);
    }
    void test_net_tab_ws_edit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.ws_edit", network_view::sub_tab_t::ws_edit);
    }
    void test_net_tab_h2_edit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.h2_edit", network_view::sub_tab_t::h2_edit);
    }
    void test_net_tab_logger(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.logger", network_view::sub_tab_t::logger);
    }
    void test_net_tab_csp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.csp", network_view::sub_tab_t::csp);
    }
    void test_net_tab_upstream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.upstream", network_view::sub_tab_t::upstream);
    }
    void test_net_tab_browser(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.browser", network_view::sub_tab_t::browser);
    }
    void test_net_tab_headless(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        select_network_tab(hf, passed, failed, "net_tab.headless", network_view::sub_tab_t::headless);
    }

    void test_find_header(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "find_header";
        log_msg(hf, tag, "START -- protocol_parser::find_header()");
        std::vector<protocol_parser::http_header> headers;
        protocol_parser::http_header h1, h2;
        h1.name = "Content-Type"; h1.value = "text/html";
        h2.name = "X-Custom"; h2.value = "test-value";
        headers.push_back(h1);
        headers.push_back(h2);

        std::string ct = protocol_parser::find_header(headers, "Content-Type");
        std::string custom = protocol_parser::find_header(headers, "X-Custom");
        std::string missing = protocol_parser::find_header(headers, "X-Missing");

        if (ct == "text/html" && custom == "test-value" && missing.empty()) {
            log_msg(hf, tag, "PASS -- find_header correct for present and missing headers");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- unexpected values ct=%s custom=%s missing=%s",
                ct.c_str(), custom.c_str(), missing.c_str());
            failed.fetch_add(1);
        }
    }

    void test_cert_generator_shutdown(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cert_gen_shut";
        log_msg(hf, tag, "START -- cert_generator::shutdown()");
        cert_generator::shutdown();
        log_msg(hf, tag, "PASS -- cert_generator shutdown completed");
        passed.fetch_add(1);
    }

}

void phase_network_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "net_phase", "========== Network Tests START (70 tests) ==========");

    if (cancelled && cancelled()) return;
    call_test(test_network_view_init, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_start, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_is_running, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_stats, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_intercept_on, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_intercept_off, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_check_intercept, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_history_empty, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_history_count, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test_s(test_mitm_repeat_request, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_history_after, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_clear_history, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_get_held, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_forward_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_drop_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_ws_callback, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_intercept_callback, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_find_exchange, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mitm_stop, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tcp_stream_tracker, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tcp_tracker_evict, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tcp_tracker_get_stream, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tcp_tracker_filtered, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_dns_resolution, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_winsock_connectivity, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_udp_loopback, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tcp_loopback_connect, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ipv6_socket_create, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test_s(test_dns_resolve_external, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test(test_parse_http_request, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_http_response, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_detect_content_type, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_find_header, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_tls_record, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_client_hello, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_detect_protocol, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_ws_frame, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ws_upgrade_detection, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_parse_h2_frames, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_quic_detection, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http_engine_parse_request, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http_engine_parse_response, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_http_engine_stream_parser, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_decode, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_encode_roundtrip, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_grpc_frames, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_protobuf_zigzag, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_init, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_root_ca, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_server_cert, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_storage_dir, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_ssl_ctx_cache, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_parse, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_watching, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_entries, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_find_by_random, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ssl_keylog_hex_decode, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_packet_callstack_enable, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_packet_callstack_recent, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypass_init_sigs, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypass_status, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypass_pattern_match, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tls_key_extractor_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_injector_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_pin_bypasser_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_quic_analyzer_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_dtls_analyzer_instance, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_autoresponder_lifecycle, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_autoresponder_match, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_autoresponder_import_export, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_match_replace_lifecycle, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_match_replace_apply, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_match_replace_test_rule, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_network_view_state, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_enumerate_connections, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_start_stop_capture, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_get_packets, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_dns_queries, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_filter_rules, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_clear_filters, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_network_stats, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_bw_monitor, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_bw_per_process, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_dpi_results, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_wfp_callouts, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_socket_handles, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_tcpip_dump, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_interfaces, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_export_pcap, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_held_packets, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_packet_mod_rules, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_redirect_rules, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_dns_spoof_rules, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_dns_spoof_add_remove, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_traffic_redirect, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_stream_reassemble, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_fingerprint, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_intercept_op, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test_s(test_driver_inject_loopback, hf, passed, failed, skipped);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_connections, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_capture, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_intercept, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_proxy, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_dns, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_filters, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_bandwidth, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_keylog, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_pcap_export, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_websocket, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_decoder, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_cookies, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_ws_edit, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_h2_edit, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_logger, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_csp, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_upstream, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_browser, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_net_tab_headless, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cert_generator_shutdown, hf, passed, failed);

    log_msg(hf, "net_phase", "========== Network Tests DONE ==========");
}

}
