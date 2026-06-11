#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace thread_intel {

struct classify_options_t {
    std::uint32_t process_id = 0;
    std::uint32_t sample_ms = 2000;
    std::uint32_t interval_ms = 100;
    std::uint32_t max_threads = 128;
};

struct watch_options_t {
    std::uint32_t process_id = 0;
    std::uint32_t tid = 0;
    std::uint32_t samples = 50;
    std::uint32_t interval_ms = 20;
};

bool classify_threads(const classify_options_t& options,
                      nlohmann::json& out,
                      std::string& error);
bool watch_rip(const watch_options_t& options,
               nlohmann::json& out,
               std::string& error);

}
