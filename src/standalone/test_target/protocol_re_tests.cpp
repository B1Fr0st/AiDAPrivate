#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <Ws2tcpip.h>

#define AIDA_TEST_TARGET_FIXTURE_API __declspec(dllexport)
#include "protocol_re_tests.h"
#include "test_log.h"

#include <cstdio>
#include <cstring>

namespace test_target {
namespace protocol_re {

namespace {

constexpr std::uint32_t kMagic = 0x41505245u;
constexpr std::uint16_t kVersion = 1;
constexpr char kMarker[] = "AiDA_PROTO_RE";
constexpr std::uint32_t kContextMagic = 0xA1DA7701u;
constexpr std::uint32_t kMaxPacket = 512;

struct context_t {
    std::uint32_t magic;
    std::uint32_t sequence;
    std::uint64_t last_tick;
    std::uint32_t flags;
    std::uint32_t checksum;
};

std::atomic<bool>* g_running = nullptr;
std::atomic<bool> g_local_running{false};
config_t g_cfg{};
context_t g_context{ kContextMagic, 1u, 0u, 0x51u, 0u };
SOCKET g_receiver = INVALID_SOCKET;
SOCKET g_sender = INVALID_SOCKET;
HANDLE g_worker = nullptr;
DWORD g_worker_tid = 0;
bool g_wsa_started = false;
std::uint64_t g_last_send_tick = 0;
std::uint64_t g_last_recv_tick = 0;

bool running_now()
{
    return g_local_running.load(std::memory_order_acquire) && g_running && g_running->load(std::memory_order_acquire);
}

void put_u16le(std::uint8_t* p, std::uint16_t v)
{
    p[0] = static_cast<std::uint8_t>(v & 0xFFu);
    p[1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
}

void put_u32le(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>(v & 0xFFu);
    p[1] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    p[2] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    p[3] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
}

void put_u64le(std::uint8_t* p, std::uint64_t v)
{
    for (std::uint32_t i = 0; i < 8; ++i)
        p[i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
}

std::uint32_t checksum_bytes(const std::uint8_t* data, std::uint32_t size)
{
    std::uint32_t h = 2166136261u;
    for (std::uint32_t i = 0; i < size; ++i) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

std::uint32_t emit_capture_impl(void* raw_ctx, std::uint8_t* buffer, std::uint32_t size) noexcept
{
    if (!buffer || size < 96)
        return 0;

    context_t* ctx = &g_context;
    if (raw_ctx) {
        context_t* candidate = static_cast<context_t*>(raw_ctx);
        __try {
            if (candidate->magic == kContextMagic)
                ctx = candidate;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ctx = &g_context;
        }
    }

    std::uint8_t payload[128] = {};
    std::uint32_t off = 0;
    std::memcpy(payload + off, kMarker, sizeof(kMarker) - 1u);
    off += static_cast<std::uint32_t>(sizeof(kMarker) - 1u);
    payload[off++] = 0x01u;
    payload[off++] = 0x10u;
    put_u32le(payload + off, ctx->sequence);
    off += 4;
    const std::uint64_t tick = GetTickCount64();
    put_u64le(payload + off, tick);
    off += 8;
    put_u32le(payload + off, ctx->flags);
    off += 4;
    const float position[3] = {
        static_cast<float>((ctx->sequence % 97u) * 3u),
        static_cast<float>((ctx->sequence % 53u) * 5u),
        static_cast<float>((ctx->sequence % 31u) * 7u)
    };
    std::memcpy(payload + off, position, sizeof(position));
    off += static_cast<std::uint32_t>(sizeof(position));
    const char label[] = "proto_fixture";
    std::memcpy(payload + off, label, sizeof(label));
    off += static_cast<std::uint32_t>(sizeof(label));
    const std::uint32_t crc = checksum_bytes(payload, off);
    put_u32le(payload + off, crc);
    off += 4;

    if (size < off + 2u)
        return 0;

    put_u16le(buffer, static_cast<std::uint16_t>(off));
    std::memcpy(buffer + 2, payload, off);

    ctx->last_tick = tick;
    ctx->checksum = crc;
    ++ctx->sequence;
    return off + 2u;
}

std::uint32_t serialize_frame_impl(void* ctx, std::uint8_t* buffer, std::uint32_t size) noexcept
{
    return emit_capture_impl(ctx, buffer, size);
}

std::uint32_t build_enet_packet(std::uint8_t* buffer, std::uint32_t size, std::uint32_t sequence)
{
    if (!buffer || size < 96)
        return 0;

    std::uint8_t payload[96] = {};
    std::uint32_t poff = 0;
    std::memcpy(payload + poff, kMarker, sizeof(kMarker) - 1u);
    poff += static_cast<std::uint32_t>(sizeof(kMarker) - 1u);
    payload[poff++] = 0xE1u;
    payload[poff++] = 0x01u;
    put_u32le(payload + poff, sequence);
    poff += 4;
    put_u64le(payload + poff, GetTickCount64());
    poff += 8;
    for (std::uint32_t i = 0; i < 24; ++i)
        payload[poff++] = static_cast<std::uint8_t>((sequence * 11u + i * 19u) & 0xFFu);

    const std::uint32_t total = 10u + poff;
    if (size < total)
        return 0;

    buffer[0] = 0x00u;
    buffer[1] = 0x21u;
    buffer[2] = static_cast<std::uint8_t>((sequence >> 8u) & 0xFFu);
    buffer[3] = static_cast<std::uint8_t>(sequence & 0xFFu);
    buffer[4] = 0x86u;
    buffer[5] = 0x02u;
    buffer[6] = static_cast<std::uint8_t>((sequence >> 8u) & 0xFFu);
    buffer[7] = static_cast<std::uint8_t>(sequence & 0xFFu);
    buffer[8] = static_cast<std::uint8_t>((poff >> 8u) & 0xFFu);
    buffer[9] = static_cast<std::uint8_t>(poff & 0xFFu);
    std::memcpy(buffer + 10, payload, poff);
    return total;
}

void drain_receiver()
{
    if (g_receiver == INVALID_SOCKET)
        return;

    std::uint8_t scratch[768];
    for (;;) {
        const int got = aida_test_proto_recv_wrapper(static_cast<std::uintptr_t>(g_receiver), scratch, static_cast<std::uint32_t>(sizeof(scratch)));
        if (got <= 0)
            break;
    }
}

void interruptible_sleep(std::uint32_t ms)
{
    std::uint32_t slept = 0;
    while (running_now() && slept < ms) {
        std::uint32_t step = ms - slept;
        if (step > 50)
            step = 50;
        Sleep(step);
        slept += step;
    }
}

DWORD WINAPI worker_thread(LPVOID)
{
    std::uint8_t buffer[kMaxPacket] = {};
    while (running_now()) {
        std::uint32_t emitted = aida_test_proto_serialize_frame(&g_context, buffer, sizeof(buffer));
        if (emitted != 0) {
            const int sent = aida_test_proto_send_wrapper(static_cast<std::uintptr_t>(g_sender), buffer, emitted, aida_test_proto_re_descriptor.listen_port);
            if (sent > 0) {
                ++aida_test_proto_re_descriptor.framed_packets_sent;
            }
        }

        emitted = build_enet_packet(buffer, sizeof(buffer), g_context.sequence);
        if (emitted != 0) {
            const int sent = aida_test_proto_send_wrapper(static_cast<std::uintptr_t>(g_sender), buffer, emitted, aida_test_proto_re_descriptor.listen_port);
            if (sent > 0) {
                ++aida_test_proto_re_descriptor.enet_packets_sent;
            }
        }

        drain_receiver();
        interruptible_sleep(g_cfg.rate_ms);
    }

    drain_receiver();
    return 0;
}

void reset_descriptor()
{
    aida_test_proto_re_descriptor.magic = kMagic;
    aida_test_proto_re_descriptor.version = kVersion;
    aida_test_proto_re_descriptor.size = sizeof(aida_test_proto_re_descriptor);
    aida_test_proto_re_descriptor.descriptor_va = reinterpret_cast<std::uint64_t>(&aida_test_proto_re_descriptor);
    aida_test_proto_re_descriptor.context_va = reinterpret_cast<std::uint64_t>(&g_context);
    aida_test_proto_re_descriptor.marker_va = reinterpret_cast<std::uint64_t>(kMarker);
    aida_test_proto_re_descriptor.marker_size = static_cast<std::uint32_t>(sizeof(kMarker) - 1u);
    aida_test_proto_re_descriptor.emit_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_proto_emit_capture);
    aida_test_proto_re_descriptor.packets_sent = 0;
    aida_test_proto_re_descriptor.framed_packets_sent = 0;
    aida_test_proto_re_descriptor.enet_packets_sent = 0;
    aida_test_proto_re_descriptor.bytes_sent = 0;
    aida_test_proto_re_descriptor.packets_received = 0;
    aida_test_proto_re_descriptor.bytes_received = 0;
    aida_test_proto_re_descriptor.send_wrapper_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_proto_send_wrapper);
    aida_test_proto_re_descriptor.recv_wrapper_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_proto_recv_wrapper);
    aida_test_proto_re_descriptor.serializer_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_proto_serialize_frame);
    aida_test_proto_re_descriptor.deserializer_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_proto_recv_wrapper);
    aida_test_proto_re_descriptor.deterministic_emit_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_proto_emit_deterministic);
    std::uint64_t lo = aida_test_proto_re_descriptor.send_wrapper_fn_va;
    if (aida_test_proto_re_descriptor.recv_wrapper_fn_va < lo)
        lo = aida_test_proto_re_descriptor.recv_wrapper_fn_va;
    if (aida_test_proto_re_descriptor.serializer_fn_va < lo)
        lo = aida_test_proto_re_descriptor.serializer_fn_va;
    if (aida_test_proto_re_descriptor.deterministic_emit_fn_va < lo)
        lo = aida_test_proto_re_descriptor.deterministic_emit_fn_va;
    std::uint64_t hi = aida_test_proto_re_descriptor.send_wrapper_fn_va;
    if (aida_test_proto_re_descriptor.recv_wrapper_fn_va > hi)
        hi = aida_test_proto_re_descriptor.recv_wrapper_fn_va;
    if (aida_test_proto_re_descriptor.serializer_fn_va > hi)
        hi = aida_test_proto_re_descriptor.serializer_fn_va;
    if (aida_test_proto_re_descriptor.deterministic_emit_fn_va > hi)
        hi = aida_test_proto_re_descriptor.deterministic_emit_fn_va;
    aida_test_proto_re_descriptor.scan_range_va = lo;
    aida_test_proto_re_descriptor.scan_range_size = hi >= lo ? static_cast<std::uint32_t>((hi - lo) + 768u) : 0u;
    aida_test_proto_re_descriptor.expected_packets_per_emit = 2;
    g_last_send_tick = 0;
    g_last_recv_tick = 0;
    aida_test_proto_re_descriptor.last_send_tick_va = reinterpret_cast<std::uint64_t>(&g_last_send_tick);
    aida_test_proto_re_descriptor.last_recv_tick_va = reinterpret_cast<std::uint64_t>(&g_last_recv_tick);
}

}

void init(const config_t& cfg, std::atomic<bool>& running)
{
    g_cfg = cfg;
    if (g_cfg.rate_ms < 50)
        g_cfg.rate_ms = 50;
    if (g_cfg.rate_ms > 50)
        g_cfg.rate_ms = 50;
    g_running = &running;
    reset_descriptor();
    aida_test_proto_re_descriptor.rate_ms = g_cfg.rate_ms;

    if (!cfg.enabled)
        return;

    WSADATA wsa{};
    if (!g_wsa_started) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            if (cfg.verbose) {
                printf("[proto-re] WSAStartup failed err=%d\n", WSAGetLastError());
                fflush(stdout);
            }
            return;
        }
        g_wsa_started = true;
    }

    g_receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    g_sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_receiver == INVALID_SOCKET || g_sender == INVALID_SOCKET) {
        shutdown_all();
        return;
    }

    sockaddr_in recv_addr{};
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    recv_addr.sin_port = 0;
    if (bind(g_receiver, reinterpret_cast<const sockaddr*>(&recv_addr), sizeof(recv_addr)) == SOCKET_ERROR) {
        shutdown_all();
        return;
    }

    sockaddr_in actual{};
    int actual_len = sizeof(actual);
    if (getsockname(g_receiver, reinterpret_cast<sockaddr*>(&actual), &actual_len) == SOCKET_ERROR) {
        shutdown_all();
        return;
    }

    sockaddr_in send_addr{};
    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    send_addr.sin_port = 0;
    if (bind(g_sender, reinterpret_cast<const sockaddr*>(&send_addr), sizeof(send_addr)) == SOCKET_ERROR) {
        shutdown_all();
        return;
    }
    sockaddr_in send_actual{};
    int send_actual_len = sizeof(send_actual);
    if (getsockname(g_sender, reinterpret_cast<sockaddr*>(&send_actual), &send_actual_len) == SOCKET_ERROR) {
        shutdown_all();
        return;
    }

    u_long nonblock = 1;
    if (ioctlsocket(g_receiver, FIONBIO, &nonblock) == SOCKET_ERROR) {
        shutdown_all();
        return;
    }

    aida_test_proto_re_descriptor.listen_port = ntohs(actual.sin_port);
    aida_test_proto_re_descriptor.send_port = ntohs(send_actual.sin_port);
    g_local_running.store(true, std::memory_order_release);
    (void)aida_test_proto_emit_deterministic(3);
    g_worker = CreateThread(nullptr, 0, worker_thread, nullptr, 0, &g_worker_tid);
    if (g_worker)
        aida_test_proto_re_descriptor.worker_thread_id = g_worker_tid;

    if (cfg.verbose) {
        printf("[proto-re] descriptor=%p ctx=%p listen=127.0.0.1:%u sender_port=%u worker=%lu send_wrapper=%p recv_wrapper=%p serializer=%p scan=0x%llX/%u packets=%llu recv=%llu\n",
               &aida_test_proto_re_descriptor,
               &g_context,
               aida_test_proto_re_descriptor.listen_port,
               aida_test_proto_re_descriptor.send_port,
               static_cast<unsigned long>(g_worker_tid),
               reinterpret_cast<void*>(aida_test_proto_re_descriptor.send_wrapper_fn_va),
               reinterpret_cast<void*>(aida_test_proto_re_descriptor.recv_wrapper_fn_va),
               reinterpret_cast<void*>(aida_test_proto_re_descriptor.serializer_fn_va),
               static_cast<unsigned long long>(aida_test_proto_re_descriptor.scan_range_va),
               aida_test_proto_re_descriptor.scan_range_size,
               static_cast<unsigned long long>(aida_test_proto_re_descriptor.packets_sent),
               static_cast<unsigned long long>(aida_test_proto_re_descriptor.packets_received));
        fflush(stdout);
    }
}

void shutdown_all()
{
    g_local_running.store(false, std::memory_order_release);

    if (g_worker) {
        WaitForSingleObject(g_worker, 2000);
        CloseHandle(g_worker);
        g_worker = nullptr;
        g_worker_tid = 0;
    }

    if (g_receiver != INVALID_SOCKET) {
        closesocket(g_receiver);
        g_receiver = INVALID_SOCKET;
    }
    if (g_sender != INVALID_SOCKET) {
        closesocket(g_sender);
        g_sender = INVALID_SOCKET;
    }

    if (g_wsa_started) {
        WSACleanup();
        g_wsa_started = false;
    }

    aida_test_proto_re_descriptor.worker_thread_id = 0;
}

std::uint32_t emit_capture_public_impl(void* ctx, std::uint8_t* buffer, std::uint32_t size) noexcept
{
    return emit_capture_impl(ctx, buffer, size);
}

std::uint32_t emit_deterministic_impl(std::uint32_t burst_count) noexcept
{
    if (g_sender == INVALID_SOCKET || g_receiver == INVALID_SOCKET)
        return 0;
    if (burst_count == 0)
        burst_count = 1;
    if (burst_count > 64)
        burst_count = 64;

    std::uint32_t sent_packets = 0;
    std::uint8_t buffer[kMaxPacket] = {};
    for (std::uint32_t i = 0; i < burst_count; ++i) {
        std::uint32_t emitted = aida_test_proto_serialize_frame(&g_context, buffer, sizeof(buffer));
        if (emitted != 0) {
            const int sent = aida_test_proto_send_wrapper(static_cast<std::uintptr_t>(g_sender), buffer, emitted, aida_test_proto_re_descriptor.listen_port);
            if (sent > 0) {
                ++aida_test_proto_re_descriptor.framed_packets_sent;
                ++sent_packets;
            }
        }
        emitted = build_enet_packet(buffer, sizeof(buffer), g_context.sequence + i);
        if (emitted != 0) {
            const int sent = aida_test_proto_send_wrapper(static_cast<std::uintptr_t>(g_sender), buffer, emitted, aida_test_proto_re_descriptor.listen_port);
            if (sent > 0) {
                ++aida_test_proto_re_descriptor.enet_packets_sent;
                ++sent_packets;
            }
        }
        drain_receiver();
    }
    return sent_packets;
}

}
}

extern "C" __declspec(dllexport) test_target::protocol_re::descriptor_t aida_test_proto_re_descriptor = {
    0x41505245u,
    1,
    sizeof(test_target::protocol_re::descriptor_t)
};

extern "C" __declspec(dllexport) __declspec(noinline) const test_target::protocol_re::descriptor_t* aida_test_proto_re_get_descriptor() noexcept
{
    return &aida_test_proto_re_descriptor;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_proto_emit_capture(void* ctx, std::uint8_t* buffer, std::uint32_t size) noexcept
{
    return test_target::protocol_re::emit_capture_public_impl(ctx, buffer, size);
}

#pragma code_seg(push, ".text$aa")
extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_proto_serialize_frame(void* ctx, std::uint8_t* buffer, std::uint32_t size) noexcept
{
    return test_target::protocol_re::serialize_frame_impl(ctx, buffer, size);
}

extern "C" __declspec(dllexport) __declspec(noinline) int aida_test_proto_send_wrapper(std::uintptr_t socket_value, const std::uint8_t* buffer, std::uint32_t size, std::uint32_t port) noexcept
{
    const SOCKET s = static_cast<SOCKET>(socket_value);
    if (s == INVALID_SOCKET || !buffer || size == 0)
        return SOCKET_ERROR;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(static_cast<u_short>(port));
    const int sent = sendto(s, reinterpret_cast<const char*>(buffer), static_cast<int>(size), 0, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    if (sent > 0) {
        ++aida_test_proto_re_descriptor.packets_sent;
        aida_test_proto_re_descriptor.bytes_sent += static_cast<std::uint64_t>(sent);
        test_target::protocol_re::g_last_send_tick = GetTickCount64();
    }
    return sent;
}

extern "C" __declspec(dllexport) __declspec(noinline) int aida_test_proto_recv_wrapper(std::uintptr_t socket_value, std::uint8_t* buffer, std::uint32_t size) noexcept
{
    const SOCKET s = static_cast<SOCKET>(socket_value);
    if (s == INVALID_SOCKET || !buffer || size == 0)
        return SOCKET_ERROR;
    sockaddr_in from{};
    int from_len = sizeof(from);
    const int got = recvfrom(s, reinterpret_cast<char*>(buffer), static_cast<int>(size), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
    if (got > 0) {
        ++aida_test_proto_re_descriptor.packets_received;
        aida_test_proto_re_descriptor.bytes_received += static_cast<std::uint64_t>(got);
        test_target::protocol_re::g_last_recv_tick = GetTickCount64();
    }
    return got;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_proto_emit_deterministic(std::uint32_t burst_count) noexcept
{
    return test_target::protocol_re::emit_deterministic_impl(burst_count);
}
#pragma code_seg(pop)
