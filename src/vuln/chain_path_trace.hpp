#pragma once

#include "chain_extraction.hpp"
#include "chain_side_effects.hpp"

#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

struct path_trace_options_t
{
    std::size_t max_blocks = 1024;
    std::size_t max_steps = 8192;
    std::size_t max_unresolved_edges = 512;
};

struct path_step_t
{
    std::size_t index = 0;
    std::size_t block_id = 0;
    address_identity_t location;
    std::string kind;
    std::string text;
    std::vector<branch_fact_t> branches;
    std::vector<call_fact_t> calls;
    std::vector<extracted_side_effect_t> side_effects;
    bool before_target = true;
    bool terminal = false;
};

struct unresolved_edge_t
{
    address_identity_t location;
    std::string kind;
    std::string reason;
    std::string evidence;
};

struct branch_blocker_t
{
    address_identity_t branch;
    std::string predicate_text;
    std::vector<address_identity_t> alternatives;
    std::string required_edge;
    std::string reason;
};

struct path_trace_t
{
    address_identity_t entry;
    address_identity_t target;
    bool reached = false;
    bool complete = false;
    std::string reason;
    std::vector<std::size_t> block_path;
    std::vector<path_step_t> steps;
    std::vector<unresolved_edge_t> unresolved_edges;
    std::vector<branch_blocker_t> branch_blockers;
    std::vector<layer_status_t> statuses;
};

path_trace_t trace_path_corridor(const function_snapshot_t& snapshot,
                                 std::uint64_t entry_ea,
                                 std::uint64_t target_ea,
                                 const path_trace_options_t& options = {});

nlohmann::json to_json(const path_step_t& step);
nlohmann::json to_json(const unresolved_edge_t& edge);
nlohmann::json to_json(const branch_blocker_t& blocker);
nlohmann::json to_json(const path_trace_t& trace);

}
}
}
