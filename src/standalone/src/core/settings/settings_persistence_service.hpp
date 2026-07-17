#pragma once

#include <cstdint>
#include <string>
#include <string_view>

struct settings_sa_t;

namespace aida::settings_persistence {

enum class request_result_t : std::uint8_t {
    queued,
    coalesced,
    preview_recorded,
    rejected,
    capture_failed
};

struct status_t {
    std::uint64_t generation = 0;
    std::uint64_t committed_generation = 0;
    bool pending = false;
    bool failed = false;
    std::string stage;
    std::string error;
};

request_result_t request_save(const settings_sa_t& settings,
    std::uint64_t* generation = nullptr) noexcept;
inline bool accepted(request_result_t result) noexcept
{
    return result == request_result_t::queued ||
        result == request_result_t::coalesced ||
        result == request_result_t::preview_recorded;
}
bool commit_lifecycle(const settings_sa_t& settings, std::string& error) noexcept;
bool shutdown_commit(const settings_sa_t& settings, std::string& error) noexcept;
status_t status() noexcept;

}
