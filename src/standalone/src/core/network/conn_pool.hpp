#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace mitm_proxy {
namespace conn_pool {

static constexpr uintptr_t invalid_socket_handle = ~static_cast<uintptr_t>(0);

struct connection_pool_config {
    size_t max_idle_total = 32;
    size_t max_idle_per_key = 4;
    uint64_t idle_timeout_ms = 30000;
    uint64_t max_age_ms = 300000;
};

struct connection_pool_key {
    std::string host;
    uint16_t port = 0;
    bool tls = false;
    std::string alpn;
    std::string upstream_fingerprint;
};

struct connection_handle {
    uintptr_t socket = invalid_socket_handle;
    SSL* ssl = nullptr;
    SSL_CTX* ssl_ctx = nullptr;
    connection_pool_key key;
    bool reusable = false;
    bool from_pool = false;

    connection_handle() = default;
    connection_handle(const connection_handle&) = delete;
    connection_handle& operator=(const connection_handle&) = delete;
    connection_handle(connection_handle&& other) noexcept;
    connection_handle& operator=(connection_handle&& other) noexcept;
    ~connection_handle();
    explicit operator bool() const;
    void reset();
    uintptr_t release_socket();
};

struct connection_pool_stats {
    size_t idle_total = 0;
    size_t idle_tcp = 0;
    size_t idle_tls = 0;
    uint64_t acquired = 0;
    uint64_t reused = 0;
    uint64_t released = 0;
    uint64_t closed = 0;
    uint64_t evicted = 0;
    uint64_t failed_reuse = 0;
    uint64_t tcp_reused = 0;
    uint64_t tls_reused = 0;
    size_t max_idle_total = 0;
    size_t max_idle_per_key = 0;
    uint64_t idle_timeout_ms = 0;
    uint64_t max_age_ms = 0;
};

void configure(const connection_pool_config& config);
connection_pool_config get_config();
connection_handle acquire(const connection_pool_key& key);
void release(connection_handle&& handle);
void discard(connection_handle&& handle);
void clear();
connection_pool_stats get_stats();

}
}
