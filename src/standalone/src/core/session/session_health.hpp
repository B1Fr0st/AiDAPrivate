#pragma once

#include "../analysis/workspace/analysis_workspace.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace aida::analysis {
class analysis_workspace_t;
}

namespace session_health {

struct session_health_t {
    bool alive = false;
    bool ready = false;
    bool failed = false;
    bool closing = false;
    bool closed = false;
    aida::analysis::workspace_readiness_t readiness =
        aida::analysis::workspace_readiness_t::created;
    std::optional<aida::analysis::workspace_error_t> error;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    float progress_fraction = 0.0f;
    std::string phase;
    std::string binary_id;
    std::string bin_name;
    std::uint32_t pid = 0;
    std::uint64_t process_creation_time_100ns = 0;
};

bool initialize();
void shutdown();
bool shutdown_and_wait(uint32_t timeout_ms);

bool is_alive(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);
bool is_alive(uint32_t pid);

session_health_t query_health(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace);

}
