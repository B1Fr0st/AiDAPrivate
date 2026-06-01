#include "telemetry_client.hpp"

#include "../../../libs/cpp-httplib/httplib.h"
#include "../../../libs/nlohmann/json.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <mutex>
#include <chrono>
#include <exception>
#include <thread>
#include <atomic>
#include <random>

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

        bool http_post_json(const std::string& base_url,
                            const std::string& path,
                            const std::string& body,
                            std::string& response_out)
        {
            try {
                httplib::Client cli(base_url.c_str());
                cli.set_connection_timeout(5);
                cli.set_read_timeout(10);
                cli.enable_server_certificate_verification(false);
                auto res = cli.Post(path.c_str(), body, "application/json");
                if (!res) return false;
                response_out = res->body;
                return res->status >= 200 && res->status < 300;
            } catch (...) {
                return false;
            }
        }

        std::vector<std::uint8_t> base64_decode_b(const std::string& s)
        {
            static const int8_t lut[128] = {
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
                52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
                15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
                -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
                41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            };
            std::vector<std::uint8_t> out;
            int val = 0, bits = 0;
            for (char c : s) {
                if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
                if (static_cast<unsigned char>(c) > 127 || lut[static_cast<unsigned char>(c)] < 0) continue;
                val = (val << 6) | lut[static_cast<unsigned char>(c)];
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out.push_back(static_cast<std::uint8_t>((val >> bits) & 0xFF));
                }
            }
            return out;
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
                cli.set_connection_timeout(5);
                cli.set_read_timeout(10);
                cli.enable_server_certificate_verification(false);

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
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (m_base_url.empty() || m_license_key.empty()) return false;
            drained.swap(m_queue);
            base_url    = m_base_url;
            license_key = m_license_key;
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
            (void)http_post_json(base_url, "/api/telemetry", body.dump(), resp);
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
