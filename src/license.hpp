#pragma once

#include <string>
#include <atomic>
#include <cstdint>

class license_manager_t
{
public:
    static license_manager_t& instance();
    bool validate();
    bool is_valid() const;
    bool show_activation_dialog();

private:
    license_manager_t() = default;
    license_manager_t(const license_manager_t&) = delete;
    license_manager_t& operator=(const license_manager_t&) = delete;
    std::string generate_hwid() const;
    bool validate_with_server(const std::string& key);
    bool bind_hwid_to_license(const std::string& key, const std::string& hwid);
    bool is_cache_valid(int64_t validated_at) const;
    nlohmann::json read_license_config() const;
    bool write_license_config(const nlohmann::json& config) const;

    std::atomic<bool> m_valid{false};
};
