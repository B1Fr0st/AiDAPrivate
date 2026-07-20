#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#include "telemetry_client.hpp"

#include "../../../libs/cpp-httplib/httplib.h"
#include "../../../libs/nlohmann/json.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <mutex>
#include <chrono>
#include <ctime>
#include <thread>
#include <atomic>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

namespace aida::telemetry
{
    namespace
    {
        std::mutex         g_mutex;
        telemetry_client_t g_instance;
        std::atomic<bool>  g_thread_alive{false};

        const char* to_sev_string(severity_t s)
        {
            switch (s) {
                case severity_t::debug:    return "debug";
                case severity_t::info:     return "info";
                case severity_t::warn:     return "warn";
                case severity_t::critical: return "critical";
            }
            return "info";
        }

        std::string hex_encode_b(const std::uint8_t* d, size_t n)
        {
            static const char dig[] = "0123456789abcdef";
            std::string out; out.resize(n * 2);
            for (size_t i = 0; i < n; ++i) {
                out[i*2+0] = dig[(d[i] >> 4) & 0xF];
                out[i*2+1] = dig[d[i] & 0xF];
            }
            return out;
        }

        std::string hmac_sha256_hex_b(const std::uint8_t* key, size_t key_len,
                                       const std::uint8_t* data, size_t data_len)
        {
            std::uint8_t out[32] = {};
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
                return std::string();
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) != 0) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return std::string();
            }
            BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
            BCryptFinishHash(hHash, out, 32, 0);
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return hex_encode_b(out, 32);
        }

        std::string make_random_nonce_b(size_t n)
        {
            std::uint8_t buf[64];
            if (n > sizeof(buf)) n = sizeof(buf);
            BCryptGenRandom(nullptr, buf, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            return hex_encode_b(buf, n);
        }

        bool http_post_json_authed(const std::string& base_url,
                                   const std::string& path,
                                   const std::string& body,
                                   const std::vector<std::uint8_t>& auth_key,
                                   const std::string& session_token,
                                   std::string& response_out)
        {
            try {
                if (auth_key.empty() || session_token.empty()) return false;
                httplib::Client cli(base_url.c_str());
                if (!cli.is_valid()) return false;
                cli.set_connection_timeout(5);
                cli.set_read_timeout(10);
                cli.enable_server_certificate_verification(true);
                cli.enable_server_hostname_verification(true);

                std::string nonce = make_random_nonce_b(16);
                std::int64_t ts = static_cast<std::int64_t>(std::time(nullptr));
                std::string ts_str = std::to_string(ts);

                std::string canonical = nonce + "|" + ts_str + "|" + body;
                std::string sig = hmac_sha256_hex_b(auth_key.data(), auth_key.size(),
                                                     reinterpret_cast<const std::uint8_t*>(canonical.data()),
                                                     canonical.size());

                httplib::Headers headers = {
                    { "Content-Type",   "application/json" },
                    { "X-Aida-Auth",    sig },
                    { "X-Aida-Nonce",   nonce },
                    { "X-Aida-Ts",      ts_str },
                    { "X-Aida-Session", session_token },
                };
                auto res = cli.Post(path.c_str(), headers, body, "application/json");
                if (!res) return false;
                response_out = res->body;
                return res->status >= 200 && res->status < 300;
            } catch (...) {
                return false;
            }
        }
    }

    void telemetry_client_t::set_endpoint(std::string base_url) noexcept
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        m_base_url = std::move(base_url);
    }

    void telemetry_client_t::set_license_key(std::string license_key) noexcept
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        m_license_key = std::move(license_key);
    }

    void telemetry_client_t::set_signing_key(std::vector<std::uint8_t> priv_key_32b) noexcept
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        m_signing_key = std::move(priv_key_32b);
    }

    void telemetry_client_t::set_auth_hmac_key(std::vector<std::uint8_t> auth_key_32b) noexcept
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        m_auth_hmac_key = std::move(auth_key_32b);
    }

    void telemetry_client_t::set_session_token(std::string token) noexcept
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        m_session_token = std::move(token);
    }

    void telemetry_client_t::enqueue(const event_t& ev) noexcept
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (m_queue.size() > 4096) return;
        m_queue.push_back(ev);
    }

    bool telemetry_client_t::flush_blocking() noexcept
    {
        std::vector<event_t> drained;
        std::string          base_url;
        std::string          license_key;
        std::vector<std::uint8_t> auth_key;
        std::string          session_token;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (m_base_url.empty() || m_license_key.empty() ||
                m_auth_hmac_key.empty() || m_session_token.empty()) return false;
            drained.swap(m_queue);
            base_url    = m_base_url;
            license_key = m_license_key;
            auth_key = m_auth_hmac_key;
            session_token = m_session_token;
        }
        if (drained.empty()) return true;

        try {
            nlohmann::json events = nlohmann::json::array();
            for (const auto& ev : drained) {
                nlohmann::json one;
                one["type"]     = ev.type;
                one["severity"] = to_sev_string(ev.severity);
                try {
                    one["payload"] = ev.payload_json.empty()
                        ? nlohmann::json::object()
                        : nlohmann::json::parse(ev.payload_json);
                } catch (...) {
                    one["payload"] = { { "raw", ev.payload_json } };
                }
                events.push_back(one);
            }

            nlohmann::json body;
            body["license_key"] = license_key;
            body["events"]      = events;

            std::string resp;
            const bool ok = http_post_json_authed(
                base_url, "/api/telemetry", body.dump(), auth_key, session_token, resp);
            if (!ok) {
                std::lock_guard<std::mutex> lock(g_mutex);
                const size_t room = m_queue.size() < 4096 ? 4096 - m_queue.size() : 0;
                const size_t keep = std::min(room, drained.size());
                if (keep > 0)
                    m_queue.insert(m_queue.begin(), drained.begin(), drained.begin() + keep);
                return false;
            }
        } catch (...) {
            return false;
        }
        return true;
    }

    void telemetry_client_t::start_background_flusher() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (m_running) return;
            m_running = true;
        }
        if (g_thread_alive.exchange(true)) return;
        try
        {
            std::thread([this]() {
                while (m_running) {
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                    flush_blocking();
                }
                g_thread_alive = false;
            }).detach();
        }
        catch (...)
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            m_running = false;
            g_thread_alive = false;
        }
    }

    void telemetry_client_t::stop() noexcept
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        m_running = false;
    }

    telemetry_client_t& instance() noexcept
    {
        return g_instance;
    }
}
