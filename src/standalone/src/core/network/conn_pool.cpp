#include "conn_pool.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

#include <openssl/ssl.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <utility>
#include <vector>

namespace mitm_proxy {
namespace conn_pool {

namespace {

struct idle_connection {
    connection_handle handle;
    uint64_t created_ms = 0;
    uint64_t last_used_ms = 0;
};

std::mutex g_mutex;
connection_pool_config g_config;
std::vector<idle_connection> g_idle;
connection_pool_stats g_stats;

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool same_key(const connection_pool_key& a, const connection_pool_key& b)
{
    return a.host == b.host &&
           a.port == b.port &&
           a.tls == b.tls &&
           a.alpn == b.alpn &&
           a.upstream_fingerprint == b.upstream_fingerprint;
}

void close_handle(connection_handle& handle)
{
    if (handle.ssl) {
        SSL_shutdown(handle.ssl);
        SSL_free(handle.ssl);
        handle.ssl = nullptr;
    }
    if (handle.ssl_ctx) {
        SSL_CTX_free(handle.ssl_ctx);
        handle.ssl_ctx = nullptr;
    }
    if (handle.socket != invalid_socket_handle) {
        closesocket(static_cast<SOCKET>(handle.socket));
        handle.socket = invalid_socket_handle;
    }
    handle.reusable = false;
    handle.from_pool = false;
}

bool socket_alive(uintptr_t socket_handle)
{
    if (socket_handle == invalid_socket_handle)
        return false;
    SOCKET s = static_cast<SOCKET>(socket_handle);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{};
    int sr = select(0, &fds, nullptr, nullptr, &tv);
    if (sr == SOCKET_ERROR)
        return false;
    if (sr == 0)
        return true;
    char b = 0;
    int r = recv(s, &b, 1, MSG_PEEK);
    if (r > 0)
        return true;
    if (r == 0)
        return false;
    const int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY;
}

void evict_expired_locked(uint64_t t)
{
    for (auto it = g_idle.begin(); it != g_idle.end();) {
        const bool idle_expired = g_config.idle_timeout_ms > 0 && t - it->last_used_ms > g_config.idle_timeout_ms;
        const bool age_expired = g_config.max_age_ms > 0 && t - it->created_ms > g_config.max_age_ms;
        if (idle_expired || age_expired || !socket_alive(it->handle.socket)) {
            close_handle(it->handle);
            ++g_stats.evicted;
            ++g_stats.closed;
            it = g_idle.erase(it);
        } else {
            ++it;
        }
    }
}

void enforce_limits_locked(uint64_t t)
{
    evict_expired_locked(t);
    while (g_idle.size() > g_config.max_idle_total) {
        auto oldest = std::min_element(g_idle.begin(), g_idle.end(), [](const idle_connection& a, const idle_connection& b) {
            return a.last_used_ms < b.last_used_ms;
        });
        if (oldest == g_idle.end())
            break;
        close_handle(oldest->handle);
        ++g_stats.evicted;
        ++g_stats.closed;
        g_idle.erase(oldest);
    }
}

size_t count_key_locked(const connection_pool_key& key)
{
    size_t n = 0;
    for (const auto& item : g_idle) {
        if (same_key(item.handle.key, key))
            ++n;
    }
    return n;
}

}

connection_handle::connection_handle(connection_handle&& other) noexcept
{
    socket = other.socket;
    ssl = other.ssl;
    ssl_ctx = other.ssl_ctx;
    key = std::move(other.key);
    reusable = other.reusable;
    from_pool = other.from_pool;
    other.socket = invalid_socket_handle;
    other.ssl = nullptr;
    other.ssl_ctx = nullptr;
    other.reusable = false;
    other.from_pool = false;
}

connection_handle& connection_handle::operator=(connection_handle&& other) noexcept
{
    if (this != &other) {
        reset();
        socket = other.socket;
        ssl = other.ssl;
        ssl_ctx = other.ssl_ctx;
        key = std::move(other.key);
        reusable = other.reusable;
        from_pool = other.from_pool;
        other.socket = invalid_socket_handle;
        other.ssl = nullptr;
        other.ssl_ctx = nullptr;
        other.reusable = false;
        other.from_pool = false;
    }
    return *this;
}

connection_handle::~connection_handle()
{
    reset();
}

connection_handle::operator bool() const
{
    return socket != invalid_socket_handle;
}

void connection_handle::reset()
{
    close_handle(*this);
}

uintptr_t connection_handle::release_socket()
{
    uintptr_t out = socket;
    socket = invalid_socket_handle;
    reusable = false;
    from_pool = false;
    return out;
}

void configure(const connection_pool_config& config)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_config = config;
    if (g_config.max_idle_per_key == 0)
        g_config.max_idle_per_key = 1;
    if (g_config.max_idle_total < g_config.max_idle_per_key)
        g_config.max_idle_total = g_config.max_idle_per_key;
    enforce_limits_locked(now_ms());
}

connection_pool_config get_config()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_config;
}

connection_handle acquire(const connection_pool_key& key)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    ++g_stats.acquired;
    const uint64_t t = now_ms();
    evict_expired_locked(t);
    for (auto it = g_idle.begin(); it != g_idle.end(); ++it) {
        if (!same_key(it->handle.key, key))
            continue;
        if (!socket_alive(it->handle.socket)) {
            close_handle(it->handle);
            ++g_stats.failed_reuse;
            ++g_stats.closed;
            g_idle.erase(it);
            return {};
        }
        connection_handle out = std::move(it->handle);
        out.from_pool = true;
        out.reusable = false;
        g_idle.erase(it);
        ++g_stats.reused;
        if (key.tls)
            ++g_stats.tls_reused;
        else
            ++g_stats.tcp_reused;
        return out;
    }
    return {};
}

void release(connection_handle&& handle)
{
    if (!handle)
        return;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!handle.reusable || !socket_alive(handle.socket)) {
        close_handle(handle);
        ++g_stats.closed;
        return;
    }
    const uint64_t t = now_ms();
    evict_expired_locked(t);
    if (g_idle.size() >= g_config.max_idle_total || count_key_locked(handle.key) >= g_config.max_idle_per_key) {
        close_handle(handle);
        ++g_stats.closed;
        ++g_stats.evicted;
        return;
    }
    idle_connection item;
    item.created_ms = t;
    item.last_used_ms = t;
    item.handle = std::move(handle);
    item.handle.from_pool = false;
    g_idle.push_back(std::move(item));
    ++g_stats.released;
    enforce_limits_locked(t);
}

void discard(connection_handle&& handle)
{
    if (!handle)
        return;
    std::lock_guard<std::mutex> lock(g_mutex);
    close_handle(handle);
    ++g_stats.closed;
}

void clear()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& item : g_idle) {
        close_handle(item.handle);
        ++g_stats.closed;
    }
    g_idle.clear();
}

connection_pool_stats get_stats()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    evict_expired_locked(now_ms());
    connection_pool_stats out = g_stats;
    out.idle_total = g_idle.size();
    for (const auto& item : g_idle) {
        if (item.handle.key.tls)
            ++out.idle_tls;
        else
            ++out.idle_tcp;
    }
    out.max_idle_total = g_config.max_idle_total;
    out.max_idle_per_key = g_config.max_idle_per_key;
    out.idle_timeout_ms = g_config.idle_timeout_ms;
    out.max_age_ms = g_config.max_age_ms;
    return out;
}

}
}
