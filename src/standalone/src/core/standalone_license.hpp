#pragma once

#include <atomic>
#include <string>

struct settings_sa_t;

namespace standalone_license
{
    bool initialize(settings_sa_t& settings);
    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out);
    bool is_valid();
    std::string plan();
    std::string last_error();
    void shutdown();
}
