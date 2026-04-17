#include "telemetry_client.hpp"

#include "../../../libs/cpp-httplib/httplib.h"
#include "../../../libs/nlohmann/json.hpp"

#include <windows.h>
#include <mutex>
#include <chrono>
#include <thread>
#include <atomic>

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
        std::thread([this]() {
            while (m_running) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                flush_blocking();
            }
            g_thread_alive = false;
        }).detach();
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
