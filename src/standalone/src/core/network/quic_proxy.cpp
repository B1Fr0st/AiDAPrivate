#include "quic_proxy.hpp"

#include "helpers/diag_log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>

#include "../infra/win_thread.hpp"

namespace mitm_proxy {
namespace quic_proxy {

namespace {

struct listener_runtime {
    uint64_t id = 0;
    quic_proxy_config config;
    SOCKET socket = INVALID_SOCKET;
    std::atomic<bool> running{false};
    aida::infra::win_thread::joinable_thread_t worker;
};

std::mutex g_mutex;
std::vector<std::shared_ptr<listener_runtime>> g_listeners;
std::deque<quic_observation> g_observations;
quic_proxy_stats g_stats;
uint64_t g_next_listener_id = 1;

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool read_quic_varint(const uint8_t* data, size_t len, size_t& pos, uint64_t& value)
{
    if (pos >= len)
        return false;
    const uint8_t first = data[pos];
    const uint8_t prefix = first >> 6;
    const size_t bytes = size_t{1} << prefix;
    if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
        return false;
    if (pos + bytes > len)
        return false;
    value = first & 0x3f;
    for (size_t i = 1; i < bytes; ++i)
        value = (value << 8) | data[pos + i];
    pos += bytes;
    return true;
}

void record_observation(const quic_observation& obs, size_t cap)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_observations.push_back(obs);
    while (g_observations.size() > cap)
        g_observations.pop_front();
    ++g_stats.datagrams;
    g_stats.bytes_in += obs.datagram_size;
    if (obs.is_quic) {
        ++g_stats.quic_packets;
        g_stats.last_packet_type = obs.header.packet_type;
        g_stats.last_version = obs.header.version_name;
    } else {
        ++g_stats.non_quic_packets;
    }
    if (!obs.unsupported_reason.empty())
        ++g_stats.dropped_unsupported;
    if (!obs.header.valid && obs.is_quic)
        ++g_stats.parse_errors;
    if (obs.tls_client_hello_available)
        g_stats.last_sni = obs.client_hello.sni;
    g_stats.http3_frames += obs.http3_frames.size();
}

void listener_loop(std::shared_ptr<listener_runtime> rt)
{
    diag::log_tagged_fmt("quic_proxy", "listener_start id=%llu bind=%s:%u",
        static_cast<unsigned long long>(rt->id), rt->config.bind_addr.c_str(), rt->config.bind_port);
    std::vector<uint8_t> buffer(rt->config.max_datagram_size == 0 ? 65535 : rt->config.max_datagram_size);
    while (rt->running.load()) {
        sockaddr_in from{};
        int from_len = sizeof(from);
        int n = recvfrom(rt->socket,
                         reinterpret_cast<char*>(buffer.data()),
                         static_cast<int>(buffer.size()),
                         0,
                         reinterpret_cast<sockaddr*>(&from),
                         &from_len);
        if (n == SOCKET_ERROR) {
            const int err = WSAGetLastError();
            if (!rt->running.load())
                break;
            if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT)
                continue;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_stats.last_error = "recvfrom failed: " + std::to_string(err);
            }
            continue;
        }
        if (n <= 0)
            continue;
        char addr_buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &from.sin_addr, addr_buf, sizeof(addr_buf));
        auto obs = classify_datagram(buffer.data(),
                                     static_cast<size_t>(n),
                                     rt->config.expected_origin_port,
                                     addr_buf,
                                     ntohs(from.sin_port),
                                     rt->id);
        obs.local_port = rt->config.bind_port;
        if (obs.is_quic && rt->config.fail_closed_without_tls_keys && obs.unsupported_reason.empty())
            obs.unsupported_reason = "quic_payload_encrypted_tls_keys_unavailable";
        obs.decrypted = false;
        obs.http3_frames_available = false;
        record_observation(obs, rt->config.max_observations == 0 ? 512 : rt->config.max_observations);
        diag::log_tagged_fmt("quic_proxy", "datagram id=%llu client=%s:%u bytes=%zu is_quic=%d type=%s version=%s decrypted=%d unsupported=%s",
            static_cast<unsigned long long>(rt->id),
            obs.client_addr.c_str(),
            obs.client_port,
            obs.datagram_size,
            obs.is_quic ? 1 : 0,
            obs.header.packet_type.c_str(),
            obs.header.version_name.c_str(),
            obs.decrypted ? 1 : 0,
            obs.unsupported_reason.c_str());
    }
    diag::log_tagged_fmt("quic_proxy", "listener_stop id=%llu", static_cast<unsigned long long>(rt->id));
}

}

std::vector<http3_frame> parse_http3_frames(const uint8_t* data, size_t len)
{
    std::vector<http3_frame> frames;
    size_t pos = 0;
    while (pos < len && frames.size() < 256) {
        http3_frame f;
        if (!read_quic_varint(data, len, pos, f.type))
            break;
        if (!read_quic_varint(data, len, pos, f.length))
            break;
        if (f.length > len - pos)
            break;
        f.payload_offset = pos;
        f.valid = true;
        frames.push_back(f);
        pos += static_cast<size_t>(f.length);
    }
    return frames;
}

quic_observation classify_datagram(const uint8_t* data,
                                   size_t len,
                                   uint16_t dst_port,
                                   const std::string& client_addr,
                                   uint16_t client_port,
                                   uint64_t listener_id)
{
    quic_observation obs;
    obs.timestamp = now_ms();
    obs.listener_id = listener_id;
    obs.client_addr = client_addr;
    obs.client_port = client_port;
    obs.local_port = dst_port;
    obs.datagram_size = len;
    if (!data || len == 0) {
        obs.unsupported_reason = "empty_datagram";
        return obs;
    }
    obs.is_quic = protocol_parser::is_quic_packet(data, len, dst_port);
    if (!obs.is_quic) {
        auto hello = protocol_parser::parse_client_hello(data, len);
        if (hello.valid) {
            obs.tls_client_hello_available = true;
            obs.client_hello = std::move(hello);
        }
        return obs;
    }
    obs.header = protocol_parser::parse_quic_header(data, len);
    if (!obs.header.valid) {
        obs.unsupported_reason = "quic_header_parse_failed";
        return obs;
    }
    if (obs.header.payload_offset < len) {
        const uint8_t* payload = data + obs.header.payload_offset;
        const size_t payload_len = len - obs.header.payload_offset;
        if (payload_len >= 5 && payload[0] == 0x16 && payload[1] == 0x03) {
            auto hello = protocol_parser::parse_client_hello(payload, payload_len);
            if (hello.valid) {
                obs.tls_client_hello_available = true;
                obs.client_hello = std::move(hello);
            }
        }
    }
    obs.unsupported_reason = "quic_payload_encrypted_tls_keys_unavailable";
    return obs;
}

bool start(const quic_proxy_config& config, uint64_t* listener_id)
{
    if (!config.observation_only) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_stats.last_error = "quic_full_mitm_not_supported_observation_only";
        g_stats.observation_only = true;
        g_stats.mitm_supported = false;
        g_stats.contract = "observation_only_no_decryption_no_forwarding_no_modification";
        return false;
    }
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_stats.last_error = "socket failed: " + std::to_string(WSAGetLastError());
        return false;
    }

    int recv_timeout = 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recv_timeout), sizeof(recv_timeout));
    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(config.bind_port);
    if (inet_pton(AF_INET, config.bind_addr.c_str(), &bind_addr.sin_addr) != 1) {
        closesocket(s);
        std::lock_guard<std::mutex> lock(g_mutex);
        g_stats.last_error = "invalid bind address";
        return false;
    }
    if (bind(s, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        closesocket(s);
        std::lock_guard<std::mutex> lock(g_mutex);
        g_stats.last_error = "bind failed: " + std::to_string(err);
        return false;
    }

    auto rt = std::make_shared<listener_runtime>();
    rt->config = config;
    rt->socket = s;
    rt->running.store(true);
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        rt->id = g_next_listener_id++;
        g_listeners.push_back(rt);
        g_stats.running = true;
        g_stats.listener_count = g_listeners.size();
        g_stats.observation_only = true;
        g_stats.mitm_supported = false;
        g_stats.contract = "observation_only_no_decryption_no_forwarding_no_modification";
        if (listener_id)
            *listener_id = rt->id;
    }
    auto rt_for_thread = rt;
    std::string start_err;
    if (!rt->worker.start([rt_for_thread]() { listener_loop(rt_for_thread); }, &start_err,
            aida::infra::win_thread::default_stack_reserve, "quic_proxy.listener")) {
        diag::log_tagged_fmt("quic_proxy", "listener_thread_start_failed err=%s", start_err.c_str());
        rt->running.store(false);
        if (rt->socket != INVALID_SOCKET) { closesocket(rt->socket); rt->socket = INVALID_SOCKET; }
        std::lock_guard<std::mutex> lock(g_mutex);
        g_listeners.erase(std::remove_if(g_listeners.begin(), g_listeners.end(),
            [&rt](const std::shared_ptr<listener_runtime>& item) { return item == rt; }), g_listeners.end());
        g_stats.running = !g_listeners.empty();
        g_stats.listener_count = g_listeners.size();
        return false;
    }
    return true;
}

bool stop(uint64_t listener_id)
{
    std::shared_ptr<listener_runtime> rt;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = std::find_if(g_listeners.begin(), g_listeners.end(), [listener_id](const std::shared_ptr<listener_runtime>& item) {
            return item && item->id == listener_id;
        });
        if (it == g_listeners.end())
            return false;
        rt = *it;
        g_listeners.erase(it);
        g_stats.listener_count = g_listeners.size();
        g_stats.running = !g_listeners.empty();
    }
    rt->running.store(false);
    if (rt->socket != INVALID_SOCKET) {
        closesocket(rt->socket);
        rt->socket = INVALID_SOCKET;
    }
    rt->worker.join_for(10000);
    return true;
}

void stop_all()
{
    std::vector<uint64_t> ids;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ids.reserve(g_listeners.size());
        for (const auto& rt : g_listeners) {
            if (rt)
                ids.push_back(rt->id);
        }
    }
    for (uint64_t id : ids)
        stop(id);
}

bool is_running()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return !g_listeners.empty();
}

quic_proxy_stats get_stats()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    quic_proxy_stats out = g_stats;
    out.listener_count = g_listeners.size();
    out.running = !g_listeners.empty();
    out.observation_only = true;
    out.mitm_supported = false;
    if (out.contract.empty())
        out.contract = "observation_only_no_decryption_no_forwarding_no_modification";
    return out;
}

std::vector<quic_observation> get_observations(size_t max_count)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<quic_observation> out;
    const size_t count = g_observations.size();
    const size_t take = (max_count == 0 || max_count > count) ? count : max_count;
    out.reserve(take);
    const size_t skip = count - take;
    size_t i = 0;
    for (const auto& obs : g_observations) {
        if (i++ < skip)
            continue;
        out.push_back(obs);
    }
    return out;
}

}
}
