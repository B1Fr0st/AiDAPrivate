#include "mitm_proxy.hpp"
#include "cert_generator.hpp"
#include "protocol_parser.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace mitm_proxy {

// ─── Utility ──────────────────────────────────────────────────────

static std::string addr_to_string(const sockaddr_in& addr) {
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    return buf;
}

static void close_socket(SOCKET s) {
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
}

static bool recv_all(SOCKET s, std::vector<uint8_t>& out, size_t max_size, int timeout_ms = 5000) {
    fd_set fds;
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    out.clear();
    out.reserve(4096);

    while (out.size() < max_size) {
        FD_ZERO(&fds);
        FD_SET(s, &fds);

        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) break;

        uint8_t buf[8192];
        int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n <= 0) break;
        out.insert(out.end(), buf, buf + n);

        // For HTTP, check if we have complete headers
        if (out.size() >= 4) {
            // Look for \r\n\r\n
            auto it = std::search(out.begin(), out.end(),
                std::begin("\r\n\r\n") - 1, std::end("\r\n\r\n") - 2);
            if (it != out.end()) break;
        }
    }
    return !out.empty();
}

static bool recv_ssl_all(SSL* ssl, std::vector<uint8_t>& out, size_t max_size) {
    out.clear();
    out.reserve(4096);

    while (out.size() < max_size) {
        uint8_t buf[8192];
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            break;
        }
        out.insert(out.end(), buf, buf + n);

        // Check for complete HTTP headers
        if (out.size() >= 4) {
            auto it = std::search(out.begin(), out.end(),
                std::begin("\r\n\r\n") - 1, std::end("\r\n\r\n") - 2);
            if (it != out.end()) break;
        }
    }
    return !out.empty();
}

// Read HTTP body based on Content-Length or chunked transfer
static void read_remaining_body_ssl(SSL* ssl, std::vector<uint8_t>& data, size_t max_size) {
    // Parse what we have to check Content-Length
    auto hdr_end = std::search(data.begin(), data.end(),
        std::begin("\r\n\r\n") - 1, std::end("\r\n\r\n") - 2);
    if (hdr_end == data.end()) return;

    size_t hdr_size = static_cast<size_t>(std::distance(data.begin(), hdr_end)) + 4;
    std::string headers(data.begin(), data.begin() + static_cast<ptrdiff_t>(hdr_size));

    // Find Content-Length
    size_t cl_pos = headers.find("Content-Length:");
    if (cl_pos == std::string::npos) cl_pos = headers.find("content-length:");
    if (cl_pos != std::string::npos) {
        size_t val_start = cl_pos + 15;
        while (val_start < headers.size() && headers[val_start] == ' ') val_start++;
        size_t val_end = headers.find("\r\n", val_start);
        if (val_end != std::string::npos) {
            size_t content_length = static_cast<size_t>(std::stoull(headers.substr(val_start, val_end - val_start)));
            size_t total_needed = hdr_size + content_length;
            if (total_needed > max_size) total_needed = max_size;

            while (data.size() < total_needed) {
                uint8_t buf[8192];
                int n = SSL_read(ssl, buf, static_cast<int>(std::min(sizeof(buf), total_needed - data.size())));
                if (n <= 0) break;
                data.insert(data.end(), buf, buf + n);
            }
        }
    }
}

static void read_remaining_body(SOCKET s, std::vector<uint8_t>& data, size_t max_size, int timeout_ms = 5000) {
    auto hdr_end = std::search(data.begin(), data.end(),
        std::begin("\r\n\r\n") - 1, std::end("\r\n\r\n") - 2);
    if (hdr_end == data.end()) return;

    size_t hdr_size = static_cast<size_t>(std::distance(data.begin(), hdr_end)) + 4;
    std::string headers(data.begin(), data.begin() + static_cast<ptrdiff_t>(hdr_size));

    size_t cl_pos = headers.find("Content-Length:");
    if (cl_pos == std::string::npos) cl_pos = headers.find("content-length:");
    if (cl_pos != std::string::npos) {
        size_t val_start = cl_pos + 15;
        while (val_start < headers.size() && headers[val_start] == ' ') val_start++;
        size_t val_end = headers.find("\r\n", val_start);
        if (val_end != std::string::npos) {
            size_t content_length = static_cast<size_t>(std::stoull(headers.substr(val_start, val_end - val_start)));
            size_t total_needed = hdr_size + content_length;
            if (total_needed > max_size) total_needed = max_size;

            fd_set fds;
            timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            while (data.size() < total_needed) {
                FD_ZERO(&fds);
                FD_SET(s, &fds);
                int sel = select(0, &fds, nullptr, nullptr, &tv);
                if (sel <= 0) break;

                uint8_t buf[8192];
                int n = recv(s, reinterpret_cast<char*>(buf),
                    static_cast<int>(std::min(sizeof(buf), total_needed - data.size())), 0);
                if (n <= 0) break;
                data.insert(data.end(), buf, buf + n);
            }
        }
    }
}

// ─── SNI Extraction from ClientHello ──────────────────────────────

static std::string extract_sni_from_client_hello(const uint8_t* data, size_t len) {
    auto hello = protocol_parser::parse_client_hello(data, len);
    if (hello.valid && !hello.sni.empty()) return hello.sni;
    return {};
}

// ─── CONNECT Tunnel Handler ───────────────────────────────────────

static void parse_connect_target(const std::string& line, std::string& host, uint16_t& port) {
    // CONNECT host:port HTTP/1.1
    size_t sp = line.find(' ');
    if (sp == std::string::npos) return;
    size_t sp2 = line.find(' ', sp + 1);
    std::string target = (sp2 != std::string::npos) ? line.substr(sp + 1, sp2 - sp - 1) : line.substr(sp + 1);

    size_t colon = target.rfind(':');
    if (colon != std::string::npos) {
        host = target.substr(0, colon);
        port = static_cast<uint16_t>(std::stoi(target.substr(colon + 1)));
    } else {
        host = target;
        port = 443;
    }
}

// ─── Connect to Target ────────────────────────────────────────────

static SOCKET connect_to_target(const std::string& host, uint16_t port) {
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0 || !result) return INVALID_SOCKET;

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }

    // Set connect timeout
    DWORD timeout_ms = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    rc = connect(s, result->ai_addr, static_cast<int>(result->ai_addrlen));
    freeaddrinfo(result);

    if (rc == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

// ─── TLS MITM Connection Handler ──────────────────────────────────

static void handle_tls_connection(SOCKET client_sock, const std::string& target_host,
                                   uint16_t target_port, const std::string& client_addr,
                                   uint16_t client_port, state_t& state) {
    // Get SSL_CTX for this domain
    const auto& ca = cert_generator::get_root_ca();
    if (!ca.valid) {
        close_socket(client_sock);
        return;
    }

    SSL_CTX* ctx = cert_generator::get_ssl_ctx_for_domain(target_host, ca);
    if (!ctx) {
        close_socket(client_sock);
        return;
    }

    // Accept TLS from client
    SSL* client_ssl = SSL_new(ctx);
    if (!client_ssl) {
        close_socket(client_sock);
        return;
    }
    SSL_set_fd(client_ssl, static_cast<int>(client_sock));

    if (SSL_accept(client_ssl) <= 0) {
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }

    // Connect to real target
    SOCKET target_sock = connect_to_target(target_host, target_port);
    if (target_sock == INVALID_SOCKET) {
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }

    // TLS connect to target
    SSL_CTX* target_ctx = SSL_CTX_new(TLS_client_method());
    if (!target_ctx) {
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }

    SSL* target_ssl = SSL_new(target_ctx);
    SSL_set_fd(target_ssl, static_cast<int>(target_sock));
    SSL_set_tlsext_host_name(target_ssl, target_host.c_str());

    if (SSL_connect(target_ssl) <= 0) {
        SSL_free(target_ssl);
        SSL_CTX_free(target_ctx);
        close_socket(target_sock);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
        close_socket(client_sock);
        return;
    }

    state.active_connections.fetch_add(1);

    // Read request from client
    std::vector<uint8_t> request_data;
    if (recv_ssl_all(client_ssl, request_data, state.config.max_body_size)) {
        read_remaining_body_ssl(client_ssl, request_data, state.config.max_body_size);

        // Build exchange record
        http_exchange exchange;
        exchange.id = state.next_id++;
        exchange.timestamp = GetTickCount64();
        exchange.client_addr = client_addr;
        exchange.client_port = client_port;
        exchange.target_host = target_host;
        exchange.target_port = target_port;
        exchange.is_tls = true;
        exchange.tls_sni = target_host;
        exchange.raw_request = request_data;
        exchange.request_size = request_data.size();
        exchange.request_time = GetTickCount64();
        exchange.request = protocol_parser::parse_http_request(request_data.data(), request_data.size());
        exchange.state = http_exchange::state_t::pending;

        state.total_requests.fetch_add(1);
        state.total_bytes_in.fetch_add(request_data.size());

        // Check intercept
        bool should_forward = true;
        if (state.config.intercept_enabled && state.intercept_cb) {
            intercept_action action = state.intercept_cb(exchange);
            if (action == intercept_action::drop) {
                exchange.state = http_exchange::state_t::dropped;
                should_forward = false;
            } else if (action == intercept_action::modify) {
                request_data = exchange.raw_request; // may have been modified by callback
            }
        }

        if (should_forward) {
            exchange.state = http_exchange::state_t::forwarding;

            // Forward to target
            int sent = SSL_write(target_ssl, request_data.data(), static_cast<int>(request_data.size()));
            if (sent > 0) {
                // Read response
                std::vector<uint8_t> response_data;
                if (recv_ssl_all(target_ssl, response_data, state.config.max_body_size)) {
                    read_remaining_body_ssl(target_ssl, response_data, state.config.max_body_size);

                    exchange.raw_response = response_data;
                    exchange.response_size = response_data.size();
                    exchange.response_time = GetTickCount64();
                    exchange.latency_ms = exchange.response_time - exchange.request_time;
                    exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                    exchange.state = http_exchange::state_t::complete;

                    state.total_bytes_out.fetch_add(response_data.size());

                    // Send response back to client
                    SSL_write(client_ssl, response_data.data(), static_cast<int>(response_data.size()));
                } else {
                    exchange.state = http_exchange::state_t::error;
                    exchange.error_msg = "No response from target";
                }
            } else {
                exchange.state = http_exchange::state_t::error;
                exchange.error_msg = "Failed to send to target";
            }
        }

        // Store in history
        {
            std::lock_guard<std::mutex> lock(state.history_mutex);
            state.history.push_back(std::move(exchange));
            while (state.history.size() > state.config.max_history)
                state.history.pop_front();
        }
    }

    state.active_connections.fetch_sub(1);

    // Cleanup
    SSL_shutdown(target_ssl);
    SSL_free(target_ssl);
    SSL_CTX_free(target_ctx);
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close_socket(target_sock);
    close_socket(client_sock);
}

// ─── Plain HTTP Connection Handler ────────────────────────────────

static void handle_plain_connection(SOCKET client_sock, const std::string& client_addr,
                                     uint16_t client_port, state_t& state) {
    state.active_connections.fetch_add(1);

    // Read request
    std::vector<uint8_t> request_data;
    if (!recv_all(client_sock, request_data, state.config.max_body_size)) {
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }
    read_remaining_body(client_sock, request_data, state.config.max_body_size);

    auto req = protocol_parser::parse_http_request(request_data.data(), request_data.size());
    if (!req.valid) {
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }

    // Extract target host
    std::string target_host = protocol_parser::find_header(req.headers, "Host");
    uint16_t target_port = 80;
    size_t colon = target_host.rfind(':');
    if (colon != std::string::npos) {
        target_port = static_cast<uint16_t>(std::stoi(target_host.substr(colon + 1)));
        target_host = target_host.substr(0, colon);
    }

    if (target_host.empty()) {
        state.active_connections.fetch_sub(1);
        close_socket(client_sock);
        return;
    }

    http_exchange exchange;
    exchange.id = state.next_id++;
    exchange.timestamp = GetTickCount64();
    exchange.client_addr = client_addr;
    exchange.client_port = client_port;
    exchange.target_host = target_host;
    exchange.target_port = target_port;
    exchange.is_tls = false;
    exchange.raw_request = request_data;
    exchange.request_size = request_data.size();
    exchange.request_time = GetTickCount64();
    exchange.request = req;
    exchange.state = http_exchange::state_t::pending;

    state.total_requests.fetch_add(1);
    state.total_bytes_in.fetch_add(request_data.size());

    bool should_forward = true;
    if (state.config.intercept_enabled && state.intercept_cb) {
        intercept_action action = state.intercept_cb(exchange);
        if (action == intercept_action::drop) {
            exchange.state = http_exchange::state_t::dropped;
            should_forward = false;
        } else if (action == intercept_action::modify) {
            request_data = exchange.raw_request;
        }
    }

    if (should_forward) {
        exchange.state = http_exchange::state_t::forwarding;
        SOCKET target_sock = connect_to_target(target_host, target_port);
        if (target_sock != INVALID_SOCKET) {
            int sent = send(target_sock, reinterpret_cast<const char*>(request_data.data()),
                            static_cast<int>(request_data.size()), 0);
            if (sent > 0) {
                std::vector<uint8_t> response_data;
                if (recv_all(target_sock, response_data, state.config.max_body_size)) {
                    read_remaining_body(target_sock, response_data, state.config.max_body_size);

                    exchange.raw_response = response_data;
                    exchange.response_size = response_data.size();
                    exchange.response_time = GetTickCount64();
                    exchange.latency_ms = exchange.response_time - exchange.request_time;
                    exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
                    exchange.state = http_exchange::state_t::complete;

                    state.total_bytes_out.fetch_add(response_data.size());
                    send(client_sock, reinterpret_cast<const char*>(response_data.data()),
                         static_cast<int>(response_data.size()), 0);
                } else {
                    exchange.state = http_exchange::state_t::error;
                    exchange.error_msg = "No response from target";
                }
            } else {
                exchange.state = http_exchange::state_t::error;
                exchange.error_msg = "Failed to send to target";
            }
            close_socket(target_sock);
        } else {
            exchange.state = http_exchange::state_t::error;
            exchange.error_msg = "Cannot connect to target";
        }
    }

    {
        std::lock_guard<std::mutex> lock(state.history_mutex);
        state.history.push_back(std::move(exchange));
        while (state.history.size() > state.config.max_history)
            state.history.pop_front();
    }

    state.active_connections.fetch_sub(1);
    close_socket(client_sock);
}

// ─── Connection Dispatcher ────────────────────────────────────────

static void handle_client(SOCKET client_sock, sockaddr_in client_addr_in, state_t& state) {
    std::string client_addr = addr_to_string(client_addr_in);
    uint16_t client_port = ntohs(client_addr_in.sin_port);

    // Peek at the first bytes to determine if CONNECT or plain HTTP
    uint8_t peek_buf[16] = {};
    int peeked = recv(client_sock, reinterpret_cast<char*>(peek_buf), sizeof(peek_buf), MSG_PEEK);
    if (peeked <= 0) {
        close_socket(client_sock);
        return;
    }

    // Check for CONNECT method (HTTPS proxy tunnel)
    if (peeked >= 7 && memcmp(peek_buf, "CONNECT", 7) == 0) {
        // Read the full CONNECT request
        std::vector<uint8_t> connect_req;
        if (!recv_all(client_sock, connect_req, 8192)) {
            close_socket(client_sock);
            return;
        }

        std::string first_line(connect_req.begin(),
            std::find(connect_req.begin(), connect_req.end(), '\r'));
        std::string target_host;
        uint16_t target_port = 443;
        parse_connect_target(first_line, target_host, target_port);

        if (target_host.empty()) {
            close_socket(client_sock);
            return;
        }

        // Send 200 Connection Established
        const char* ok_resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(client_sock, ok_resp, static_cast<int>(strlen(ok_resp)), 0);

        if (state.config.decode_tls) {
            // MITM the TLS connection
            handle_tls_connection(client_sock, target_host, target_port, client_addr, client_port, state);
        } else {
            // Blind tunnel - just relay bytes
            SOCKET target_sock = connect_to_target(target_host, target_port);
            if (target_sock == INVALID_SOCKET) {
                close_socket(client_sock);
                return;
            }

            state.active_connections.fetch_add(1);

            // Simple bidirectional relay
            fd_set fds;
            uint8_t buf[8192];
            bool done = false;
            while (!done && state.running.load()) {
                FD_ZERO(&fds);
                FD_SET(client_sock, &fds);
                FD_SET(target_sock, &fds);

                timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                SOCKET max_fd = (client_sock > target_sock) ? client_sock : target_sock;
                int sel = select(static_cast<int>(max_fd + 1), &fds, nullptr, nullptr, &tv);
                if (sel <= 0) { if (sel < 0) done = true; continue; }

                if (FD_ISSET(client_sock, &fds)) {
                    int n = recv(client_sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
                    if (n <= 0) { done = true; break; }
                    send(target_sock, reinterpret_cast<const char*>(buf), n, 0);
                    state.total_bytes_in.fetch_add(static_cast<uint64_t>(n));
                }
                if (FD_ISSET(target_sock, &fds)) {
                    int n = recv(target_sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
                    if (n <= 0) { done = true; break; }
                    send(client_sock, reinterpret_cast<const char*>(buf), n, 0);
                    state.total_bytes_out.fetch_add(static_cast<uint64_t>(n));
                }
            }

            state.active_connections.fetch_sub(1);
            close_socket(target_sock);
            close_socket(client_sock);
        }
    } else {
        // Plain HTTP proxy request
        handle_plain_connection(client_sock, client_addr, client_port, state);
    }
}

// ─── Listener Thread ──────────────────────────────────────────────

static void listener_thread_func(state_t& state) {
    while (state.running.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(static_cast<SOCKET>(state.listen_socket), &fds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        sockaddr_in client_addr = {};
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(static_cast<SOCKET>(state.listen_socket),
            reinterpret_cast<sockaddr*>(&client_addr), &addr_len);

        if (client_sock == INVALID_SOCKET) continue;

        // Handle each connection in its own thread
        std::thread(handle_client, client_sock, client_addr, std::ref(state)).detach();
    }
}

// ─── Public API ───────────────────────────────────────────────────

bool start(const proxy_config& config) {
    if (g_state.running.load()) return false;

    // Initialize Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // Initialize cert generator for TLS MITM
    if (config.decode_tls && !cert_generator::is_ready()) {
        if (!cert_generator::initialize()) return false;
    }

    g_state.config = config;

    // Create listening socket
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) return false;

    // Allow address reuse
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(config.bind_port);
    inet_pton(AF_INET, config.bind_addr.c_str(), &bind_addr.sin_addr);

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        closesocket(listen_sock);
        return false;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_sock);
        return false;
    }

    g_state.listen_socket = static_cast<uintptr_t>(listen_sock);
    g_state.running.store(true);
    g_state.listener_thread = std::thread(listener_thread_func, std::ref(g_state));

    return true;
}

void stop() {
    if (!g_state.running.load()) return;

    g_state.running.store(false);

    // Close listening socket to unblock accept
    if (g_state.listen_socket != ~static_cast<uintptr_t>(0)) {
        closesocket(static_cast<SOCKET>(g_state.listen_socket));
        g_state.listen_socket = ~static_cast<uintptr_t>(0);
    }

    if (g_state.listener_thread.joinable())
        g_state.listener_thread.join();
}

bool is_running() {
    return g_state.running.load();
}

std::vector<http_exchange> get_history(size_t max_count) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    std::vector<http_exchange> result;
    if (max_count == 0 || max_count >= g_state.history.size()) {
        result.assign(g_state.history.begin(), g_state.history.end());
    } else {
        auto start = g_state.history.end() - static_cast<ptrdiff_t>(max_count);
        result.assign(start, g_state.history.end());
    }
    return result;
}

const http_exchange* find_exchange(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto& ex : g_state.history) {
        if (ex.id == id) return &ex;
    }
    return nullptr;
}

void clear_history() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    g_state.history.clear();
    g_state.next_id = 1;
}

size_t history_count() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    return g_state.history.size();
}

void set_intercept_enabled(bool enabled) {
    g_state.config.intercept_enabled = enabled;
}

bool is_intercept_enabled() {
    return g_state.config.intercept_enabled;
}

void set_intercept_callback(intercept_callback_t cb) {
    g_state.intercept_cb = std::move(cb);
}

void forward_exchange(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_state.held_mutex);
    auto it = std::find_if(g_state.held_exchanges.begin(), g_state.held_exchanges.end(),
        [id](const http_exchange* ex) { return ex->id == id; });
    if (it != g_state.held_exchanges.end()) {
        (*it)->state = http_exchange::state_t::forwarding;
        g_state.held_exchanges.erase(it);
    }
}

void forward_modified(uint64_t id, const std::vector<uint8_t>& modified_request) {
    std::lock_guard<std::mutex> lock(g_state.held_mutex);
    auto it = std::find_if(g_state.held_exchanges.begin(), g_state.held_exchanges.end(),
        [id](const http_exchange* ex) { return ex->id == id; });
    if (it != g_state.held_exchanges.end()) {
        (*it)->raw_request = modified_request;
        (*it)->state = http_exchange::state_t::forwarding;
        g_state.held_exchanges.erase(it);
    }
}

void drop_exchange(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_state.held_mutex);
    auto it = std::find_if(g_state.held_exchanges.begin(), g_state.held_exchanges.end(),
        [id](const http_exchange* ex) { return ex->id == id; });
    if (it != g_state.held_exchanges.end()) {
        (*it)->state = http_exchange::state_t::dropped;
        g_state.held_exchanges.erase(it);
    }
}

void forward_all() {
    std::lock_guard<std::mutex> lock(g_state.held_mutex);
    for (auto* ex : g_state.held_exchanges)
        ex->state = http_exchange::state_t::forwarding;
    g_state.held_exchanges.clear();
}

void drop_all() {
    std::lock_guard<std::mutex> lock(g_state.held_mutex);
    for (auto* ex : g_state.held_exchanges)
        ex->state = http_exchange::state_t::dropped;
    g_state.held_exchanges.clear();
}

repeat_result repeat_request(const std::string& host, uint16_t port, bool use_tls,
                             const std::vector<uint8_t>& raw_request) {
    repeat_result result;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET sock = connect_to_target(host, port);
    if (sock == INVALID_SOCKET) {
        result.error = "Cannot connect to " + host + ":" + std::to_string(port);
        return result;
    }

    result.exchange.target_host = host;
    result.exchange.target_port = port;
    result.exchange.is_tls = use_tls;
    result.exchange.raw_request = raw_request;
    result.exchange.request_size = raw_request.size();
    result.exchange.request = protocol_parser::parse_http_request(raw_request.data(), raw_request.size());
    result.exchange.request_time = GetTickCount64();

    if (use_tls) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            close_socket(sock);
            result.error = "SSL_CTX_new failed";
            return result;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, static_cast<int>(sock));
        SSL_set_tlsext_host_name(ssl, host.c_str());

        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close_socket(sock);
            result.error = "TLS handshake failed";
            return result;
        }

        SSL_write(ssl, raw_request.data(), static_cast<int>(raw_request.size()));

        std::vector<uint8_t> response_data;
        if (recv_ssl_all(ssl, response_data, 16 * 1024 * 1024)) {
            read_remaining_body_ssl(ssl, response_data, 16 * 1024 * 1024);
            result.exchange.raw_response = response_data;
            result.exchange.response_size = response_data.size();
            result.exchange.response_time = GetTickCount64();
            result.exchange.latency_ms = result.exchange.response_time - result.exchange.request_time;
            result.exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
            result.exchange.state = http_exchange::state_t::complete;
            result.success = true;
        } else {
            result.error = "No response from server";
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        send(sock, reinterpret_cast<const char*>(raw_request.data()),
             static_cast<int>(raw_request.size()), 0);

        std::vector<uint8_t> response_data;
        if (recv_all(sock, response_data, 16 * 1024 * 1024)) {
            read_remaining_body(sock, response_data, 16 * 1024 * 1024);
            result.exchange.raw_response = response_data;
            result.exchange.response_size = response_data.size();
            result.exchange.response_time = GetTickCount64();
            result.exchange.latency_ms = result.exchange.response_time - result.exchange.request_time;
            result.exchange.response = protocol_parser::parse_http_response(response_data.data(), response_data.size());
            result.exchange.state = http_exchange::state_t::complete;
            result.success = true;
        } else {
            result.error = "No response from server";
        }
    }

    close_socket(sock);
    return result;
}

proxy_stats get_stats() {
    proxy_stats stats;
    stats.running = g_state.running.load();
    stats.total_requests = g_state.total_requests.load();
    stats.total_bytes_in = g_state.total_bytes_in.load();
    stats.total_bytes_out = g_state.total_bytes_out.load();
    stats.active_connections = g_state.active_connections.load();

    {
        std::lock_guard<std::mutex> lock(g_state.history_mutex);
        stats.history_size = g_state.history.size();
    }
    {
        std::lock_guard<std::mutex> lock(g_state.held_mutex);
        stats.held_count = g_state.held_exchanges.size();
    }
    return stats;
}

} // namespace mitm_proxy
