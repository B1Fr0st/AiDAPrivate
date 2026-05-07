#include "aida_ipc.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    using namespace aida_manual_map;

    constexpr DWORD kConnectAttemptTimeoutMs   = 5000;
    constexpr DWORD kConnectRetryBackoffMs     = 250;
    constexpr DWORD kHeartbeatIntervalMs       = 2000;
    constexpr DWORD kReadTimeoutMs             = 6000;
    constexpr int   kMaxConsecutiveFailures    = 5;
    constexpr DWORD kKillFastFailCode          = 0xA1DAB1FFu;

    std::mutex                         g_mutex;
    HANDLE                             g_pipe = INVALID_HANDLE_VALUE;
    std::atomic<bool>                  g_running{false};
    std::atomic<bool>                  g_authenticated{false};
    std::atomic<bool>                  g_thread_started{false};
    std::atomic<uint64_t>              g_last_heartbeat_ack_tick{0};
    std::vector<uint8_t>               g_pipe_secret;
    proof_buffer_t                     g_proof{};

    bool compute_hmac_sha256(const uint8_t* key, size_t key_len,
                              const uint8_t* data, size_t data_len,
                              uint8_t out_mac[32])
    {
        unsigned int mac_len = 0;
        unsigned char mac_buf[EVP_MAX_MD_SIZE] = {};
        if (HMAC(EVP_sha256(), key, static_cast<int>(key_len),
                 data, data_len, mac_buf, &mac_len) == nullptr)
            return false;
        if (mac_len != 32)
            return false;
        std::memcpy(out_mac, mac_buf, 32);
        return true;
    }

    bool constant_time_eq(const uint8_t* a, const uint8_t* b, size_t n)
    {
        uint8_t diff = 0;
        for (size_t i = 0; i < n; ++i)
            diff |= static_cast<uint8_t>(a[i] ^ b[i]);
        return diff == 0;
    }

    bool write_all(HANDLE pipe, const void* data, size_t n)
    {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        size_t total = 0;
        while (total < n)
        {
            DWORD wrote = 0;
            if (!WriteFile(pipe, p + total,
                           static_cast<DWORD>(n - total), &wrote, nullptr))
                return false;
            if (wrote == 0)
                return false;
            total += wrote;
        }
        return true;
    }

    bool read_all_with_timeout(HANDLE pipe, void* data, size_t n, DWORD timeout_ms)
    {
        uint8_t* p = static_cast<uint8_t*>(data);
        size_t total = 0;
        ULONGLONG deadline = GetTickCount64() + timeout_ms;
        while (total < n)
        {
            DWORD avail = 0;
            if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr))
                return false;
            if (avail == 0)
            {
                if (GetTickCount64() >= deadline)
                    return false;
                Sleep(20);
                continue;
            }
            DWORD got = 0;
            DWORD want = static_cast<DWORD>(n - total);
            if (avail < want)
                want = avail;
            if (!ReadFile(pipe, p + total, want, &got, nullptr))
                return false;
            if (got == 0)
                return false;
            total += got;
        }
        return true;
    }

    bool send_frame(HANDLE pipe, uint32_t verb,
                    const uint8_t* payload, size_t payload_len)
    {
        if (payload_len > kFrameMaxPayload)
            return false;
        frame_header_t header{};
        header.verb = verb;
        header.payload_len = static_cast<uint32_t>(payload_len);
        if (!write_all(pipe, &header, sizeof(header)))
            return false;
        if (payload_len > 0)
            if (!write_all(pipe, payload, payload_len))
                return false;
        return true;
    }

    bool recv_frame(HANDLE pipe, uint32_t& out_verb,
                    std::vector<uint8_t>& out_payload, DWORD timeout_ms)
    {
        frame_header_t header{};
        if (!read_all_with_timeout(pipe, &header, sizeof(header), timeout_ms))
            return false;
        if (header.payload_len > kFrameMaxPayload)
            return false;
        out_verb = header.verb;
        out_payload.resize(header.payload_len);
        if (header.payload_len > 0)
            if (!read_all_with_timeout(pipe, out_payload.data(),
                                        header.payload_len, timeout_ms))
                return false;
        return true;
    }

    HANDLE open_pipe_with_timeout(const std::wstring& pipe_path, DWORD timeout_ms)
    {
        ULONGLONG deadline = GetTickCount64() + timeout_ms;
        for (;;)
        {
            HANDLE h = CreateFileW(pipe_path.c_str(),
                                    GENERIC_READ | GENERIC_WRITE,
                                    0, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_OVERLAPPED == 0 ? 0 : 0, nullptr);
            if (h != INVALID_HANDLE_VALUE)
            {
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
                return h;
            }
            DWORD err = GetLastError();
            if (err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND)
                return INVALID_HANDLE_VALUE;
            ULONGLONG now = GetTickCount64();
            if (now >= deadline)
                return INVALID_HANDLE_VALUE;
            DWORD remaining = static_cast<DWORD>(deadline - now);
            if (remaining > 1000)
                remaining = 1000;
            if (err == ERROR_PIPE_BUSY)
            {
                if (!WaitNamedPipeW(pipe_path.c_str(), remaining))
                    Sleep(kConnectRetryBackoffMs);
            }
            else
            {
                Sleep(kConnectRetryBackoffMs);
            }
        }
    }

    bool perform_handshake(HANDLE pipe)
    {
        uint8_t hello_payload[16 + 32] = {};
        if (BCryptGenRandom(nullptr, hello_payload, 16,
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return false;
        uint8_t auth_input[5 + 16] = { 'H','E','L','L','O' };
        std::memcpy(auth_input + 5, hello_payload, 16);
        if (!compute_hmac_sha256(g_pipe_secret.data(), g_pipe_secret.size(),
                                  auth_input, sizeof(auth_input),
                                  hello_payload + 16))
            return false;

        if (!send_frame(pipe, verb_hello, hello_payload, sizeof(hello_payload)))
            return false;

        uint32_t verb = 0;
        std::vector<uint8_t> payload;
        if (!recv_frame(pipe, verb, payload, kReadTimeoutMs))
            return false;
        if (verb != verb_hello_ack || payload.size() != 32)
            return false;

        uint8_t ack_input[9 + 16] = { 'H','E','L','L','O','_','A','C','K' };
        std::memcpy(ack_input + 9, hello_payload, 16);
        uint8_t expected_mac[32] = {};
        if (!compute_hmac_sha256(g_pipe_secret.data(), g_pipe_secret.size(),
                                  ack_input, sizeof(ack_input), expected_mac))
            return false;
        if (!constant_time_eq(payload.data(), expected_mac, 32))
            return false;

        return true;
    }

    bool send_status(HANDLE pipe, uint32_t code, const char* msg)
    {
        std::vector<uint8_t> payload;
        size_t msg_len = msg ? std::strlen(msg) : 0;
        if (msg_len > kFrameMaxPayload - 4 - 32)
            msg_len = kFrameMaxPayload - 4 - 32;
        payload.resize(4 + msg_len + 32);
        std::memcpy(payload.data(), &code, 4);
        if (msg_len > 0)
            std::memcpy(payload.data() + 4, msg, msg_len);
        std::vector<uint8_t> hmac_in;
        hmac_in.resize(6 + 4 + msg_len);
        std::memcpy(hmac_in.data(), "STATUS", 6);
        std::memcpy(hmac_in.data() + 6, &code, 4);
        if (msg_len > 0)
            std::memcpy(hmac_in.data() + 10, msg, msg_len);
        uint8_t mac[32] = {};
        if (!compute_hmac_sha256(g_pipe_secret.data(), g_pipe_secret.size(),
                                  hmac_in.data(), hmac_in.size(), mac))
            return false;
        std::memcpy(payload.data() + 4 + msg_len, mac, 32);
        return send_frame(pipe, verb_status, payload.data(), payload.size());
    }

    bool send_heartbeat(HANDLE pipe)
    {
        uint8_t payload[8 + 32] = {};
        uint64_t ts = static_cast<uint64_t>(GetTickCount64());
        std::memcpy(payload, &ts, 8);
        uint8_t hmac_in[9 + 8] = { 'H','E','A','R','T','B','E','A','T' };
        std::memcpy(hmac_in + 9, &ts, 8);
        if (!compute_hmac_sha256(g_pipe_secret.data(), g_pipe_secret.size(),
                                  hmac_in, sizeof(hmac_in), payload + 8))
            return false;
        return send_frame(pipe, verb_heartbeat, payload, sizeof(payload));
    }

    bool verify_kill(const std::vector<uint8_t>& payload)
    {
        if (payload.size() != 32)
            return false;
        uint8_t mac[32] = {};
        if (!compute_hmac_sha256(g_pipe_secret.data(), g_pipe_secret.size(),
                                  reinterpret_cast<const uint8_t*>("KILL"), 4,
                                  mac))
            return false;
        return constant_time_eq(payload.data(), mac, 32);
    }

    void close_pipe_locked()
    {
        if (g_pipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_pipe);
            g_pipe = INVALID_HANDLE_VALUE;
        }
    }

    void worker_thread()
    {
        wchar_t pipe_path[64] = {};
        std::swprintf(pipe_path, 64, L"%s%llu",
                      kPipePrefix,
                      static_cast<unsigned long long>(GetCurrentProcessId()));

        HANDLE pipe = open_pipe_with_timeout(pipe_path, kConnectAttemptTimeoutMs);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            g_running.store(false, std::memory_order_release);
            return;
        }

        if (!perform_handshake(pipe))
        {
            CloseHandle(pipe);
            g_running.store(false, std::memory_order_release);
            return;
        }

        {
            std::lock_guard<std::mutex> lk(g_mutex);
            g_pipe = pipe;
        }
        g_authenticated.store(true, std::memory_order_release);
        g_last_heartbeat_ack_tick.store(GetTickCount64(),
                                         std::memory_order_release);

        send_status(pipe, 0, "init_ok");

        int consecutive_failures = 0;
        while (g_running.load(std::memory_order_acquire))
        {
            DWORD avail = 0;
            BOOL peek_ok = PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr);
            if (!peek_ok)
            {
                ++consecutive_failures;
                if (consecutive_failures >= kMaxConsecutiveFailures)
                    break;
                Sleep(100);
                continue;
            }

            if (avail >= sizeof(frame_header_t))
            {
                uint32_t verb = 0;
                std::vector<uint8_t> payload;
                if (!recv_frame(pipe, verb, payload, kReadTimeoutMs))
                {
                    ++consecutive_failures;
                    if (consecutive_failures >= kMaxConsecutiveFailures)
                        break;
                    continue;
                }
                consecutive_failures = 0;
                switch (verb)
                {
                    case verb_kill:
                        if (verify_kill(payload))
                        {
                            send_frame(pipe,
                                       verb_bye, nullptr, 0);
                            close_pipe_locked();
                            ExitProcess(kKillFastFailCode);
                        }
                        break;
                    case verb_heartbeat:
                        g_last_heartbeat_ack_tick.store(GetTickCount64(),
                                                         std::memory_order_release);
                        break;
                    default:
                        break;
                }
            }

            ULONGLONG now = GetTickCount64();
            static ULONGLONG last_hb_sent = 0;
            if (now - last_hb_sent >= kHeartbeatIntervalMs)
            {
                if (!send_heartbeat(pipe))
                {
                    ++consecutive_failures;
                    if (consecutive_failures >= kMaxConsecutiveFailures)
                        break;
                }
                last_hb_sent = now;
            }
            Sleep(50);
        }

        {
            std::lock_guard<std::mutex> lk(g_mutex);
            close_pipe_locked();
        }
        g_running.store(false, std::memory_order_release);
        g_authenticated.store(false, std::memory_order_release);
    }
}

namespace aida_ipc
{
    bool start_if_manual_mapped(const aida_manual_map::proof_buffer_t& proof)
    {
        bool expected = false;
        if (!g_thread_started.compare_exchange_strong(expected, true))
            return g_running.load(std::memory_order_acquire);

        g_proof = proof;
        g_pipe_secret.assign(proof.pipe_secret,
                              proof.pipe_secret + aida_manual_map::kPipeSecretLen);
        g_running.store(true, std::memory_order_release);
        std::thread(worker_thread).detach();
        return true;
    }

    void shutdown()
    {
        g_running.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lk(g_mutex);
        if (g_pipe != INVALID_HANDLE_VALUE)
        {
            send_frame(g_pipe, verb_bye, nullptr, 0);
            CloseHandle(g_pipe);
            g_pipe = INVALID_HANDLE_VALUE;
        }
    }

    bool is_pipe_alive()
    {
        return g_running.load(std::memory_order_acquire)
            && g_authenticated.load(std::memory_order_acquire);
    }
}
