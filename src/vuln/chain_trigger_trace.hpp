#pragma once

#include "chain_path_trace.hpp"

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

struct trigger_root_t
{
    std::string kind = "api";
    std::uint64_t ea = 0;
    std::string name;
    std::string evidence;
};

struct trigger_attempt_t
{
    trigger_root_t root;
    address_identity_t resolved_entry;
    bool root_resolved = false;
    bool target_reached = false;
    std::string reason;
    path_trace_t path;
};

struct trigger_trace_t
{
    address_identity_t target;
    bool reached = false;
    bool complete = false;
    std::string reason;
    std::vector<trigger_attempt_t> attempts;
    std::vector<unresolved_edge_t> unresolved_edges;
    std::vector<branch_blocker_t> branch_blockers;
    std::vector<layer_status_t> statuses;
};

trigger_trace_t trace_trigger_to_target(const function_snapshot_t& snapshot,
                                        const std::vector<trigger_root_t>& roots,
                                        std::uint64_t target_ea,
                                        const path_trace_options_t& options = {});

nlohmann::json to_json(const trigger_root_t& root);
nlohmann::json to_json(const trigger_attempt_t& attempt);
nlohmann::json to_json(const trigger_trace_t& trace);

}
}
}
