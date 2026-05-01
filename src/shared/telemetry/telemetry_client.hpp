#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace aida::telemetry
{
    enum class severity_t : int
    {
        debug    = 0,
        info     = 1,
        warn     = 2,
        critical = 3,
    };

    struct event_t
    {
        std::string        type;
        severity_t         severity = severity_t::info;
        std::string        payload_json;
    };

    class telemetry_client_t
    {
    public:
        telemetry_client_t() = default;
        ~telemetry_client_t() = default;

        void set_endpoint(std::string base_url) noexcept;
        void set_license_key(std::string license_key) noexcept;
        void set_signing_key(std::vector<std::uint8_t> ed25519_priv_key_32b) noexcept;
        void set_auth_hmac_key(std::vector<std::uint8_t> auth_key_32b) noexcept;
        void set_session_token(std::string token) noexcept;

        void enqueue(const event_t& ev) noexcept;

        bool flush_blocking() noexcept;

        void start_background_flusher() noexcept;
        void stop() noexcept;

    private:
        std::string                m_base_url;
        std::string                m_license_key;
        std::vector<std::uint8_t>  m_signing_key;
        std::vector<event_t>       m_queue;
        bool                       m_running = false;
    };

    telemetry_client_t& instance() noexcept;
}
