#pragma once

#include "analysis_workspace.hpp"
#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint64_t advanced_cfg_max_blocks = 65536;
inline constexpr std::uint64_t advanced_cfg_max_edges = 524288;
inline constexpr std::uint64_t advanced_cfg_max_instructions = 1048576;
inline constexpr std::uint64_t advanced_cfg_max_evidence = 262144;
inline constexpr std::uint32_t advanced_cfg_max_dominator_iterations = 256;

struct advanced_cfg_budget_t {
    std::uint64_t max_blocks = advanced_cfg_max_blocks;
    std::uint64_t max_edges = advanced_cfg_max_edges;
    std::uint64_t max_instructions = advanced_cfg_max_instructions;
    std::uint64_t max_evidence = advanced_cfg_max_evidence;
    std::uint32_t max_dominator_iterations = advanced_cfg_max_dominator_iterations;
};

struct advanced_cfg_key_t {
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    address_t function_address;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    address_space_id_t address_space = address_space_id_t::relative_virtual;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
};

struct advanced_cfg_quality_t {
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint32_t contributor_count = 0;
    bool conflicted = false;
};

enum class advanced_cfg_conflict_kind_t : std::uint8_t {
    entry_block_missing = 0,
    overlapping_blocks = 1,
    conflicting_edge_kind = 2,
    unresolved_internal_target = 3,
    switch_target_missing = 4,
    dominance_iteration_limit = 5,
    post_dominance_without_exit = 6,
    truncated_input = 7
};

struct advanced_cfg_conflict_t {
    advanced_cfg_conflict_kind_t kind = advanced_cfg_conflict_kind_t::entry_block_missing;
    std::uint64_t rva = 0;
    entity_id_t source_entity = 0;
    entity_id_t target_entity = 0;
    edge_kind_t existing_edge_kind = edge_kind_t::fallthrough;
    edge_kind_t candidate_edge_kind = edge_kind_t::fallthrough;
    advanced_cfg_quality_t existing_quality;
    advanced_cfg_quality_t candidate_quality;
};

struct basic_block_fact_t {
    entity_id_t id = 0;
    entity_id_t function_id = 0;
    address_t start;
    address_t end;
    std::uint32_t instruction_count = 0;
    advanced_cfg_quality_t quality;
    bool reachable = false;
    bool terminal = false;
    bool noreturn_terminator = false;
};

struct cfg_edge_fact_t {
    entity_id_t source_block_id = 0;
    std::optional<entity_id_t> target_block_id;
    std::optional<entity_id_t> target_function_id;
    address_t source;
    address_t target;
    edge_kind_t kind = edge_kind_t::fallthrough;
    advanced_cfg_quality_t quality;
    bool derived = false;
    bool external_target = false;
};

struct dominator_tree_t {
    std::vector<entity_id_t> block_ids;
    std::vector<entity_id_t> immediate_dominators;
    std::vector<std::vector<entity_id_t>> children;
    std::vector<std::uint32_t> reverse_post_order;
    std::vector<bool> reachable;
    std::uint64_t block_count = 0;
    bool post_dominator = false;
    bool complete = true;
};

struct loop_info_t {
    entity_id_t header_block_id = 0;
    entity_id_t back_edge_source_id = 0;
    std::vector<entity_id_t> body_blocks;
    std::uint32_t nesting_depth = 0;
    std::uint64_t header_rva = 0;
    std::uint64_t back_edge_source_rva = 0;
    advanced_cfg_quality_t quality;
    bool is_infinite = false;
    bool reducible = true;
};

struct loop_depth_fact_t {
    entity_id_t block_id = 0;
    std::uint32_t depth = 0;
};

struct reducibility_component_t {
    std::vector<entity_id_t> block_ids;
    std::vector<entity_id_t> entry_block_ids;
    advanced_cfg_quality_t quality;
    bool cyclic = false;
    bool reducible = true;
};

struct switch_case_t {
    std::uint64_t case_value = 0;
    std::uint64_t target_rva = 0;
    entity_id_t target_block_id = 0;
    bool is_default = false;
    bool case_value_known = false;
    advanced_cfg_quality_t quality;
};

struct recovered_switch_t {
    entity_id_t dispatch_block_id = 0;
    std::uint64_t dispatch_rva = 0;
    std::optional<std::uint64_t> table_rva;
    std::uint8_t entry_size = 0;
    std::uint64_t entry_count = 0;
    bool relative_entries = false;
    bool complete = false;
    advanced_cfg_quality_t quality;
    std::vector<switch_case_t> cases;
    std::optional<std::uint64_t> default_target_rva;
};

enum class exception_region_kind_t : std::uint8_t {
    c_specific_scope = 0,
    cfg_exception_edge = 1
};

struct exception_region_t {
    std::uint64_t try_start_rva = 0;
    std::uint64_t try_end_rva = 0;
    std::uint64_t handler_rva = 0;
    std::uint64_t jump_target_rva = 0;
    exception_region_kind_t region_kind = exception_region_kind_t::c_specific_scope;
    advanced_cfg_quality_t quality;
};

struct thunk_info_t {
    std::uint64_t thunk_rva = 0;
    std::uint64_t target_rva = 0;
    std::uint64_t thunk_size = 0;
    entity_id_t target_function_id = 0;
    advanced_cfg_quality_t quality;
    bool is_tail_call = false;
    bool is_import_thunk = false;
    bool inferred = false;
};

struct tail_call_info_t {
    std::uint64_t call_site_rva = 0;
    std::uint64_t target_rva = 0;
    entity_id_t source_block_id = 0;
    entity_id_t target_function_id = 0;
    advanced_cfg_quality_t quality;
    bool is_direct = false;
    bool is_indirect = false;
    bool external_target = false;
};

struct noreturn_effect_t {
    entity_id_t source_block_id = 0;
    entity_id_t target_function_id = 0;
    std::uint64_t call_site_rva = 0;
    std::uint64_t target_rva = 0;
    advanced_cfg_quality_t quality;
    bool suppresses_fallthrough = false;
};

struct callgraph_edge_t {
    entity_id_t source_function_id = 0;
    entity_id_t source_block_id = 0;
    std::optional<entity_id_t> target_function_id;
    std::uint64_t call_site_rva = 0;
    std::uint64_t target_rva = 0;
    advanced_cfg_quality_t quality;
    bool is_tail_call = false;
    bool is_indirect = false;
    bool external_target = false;
    bool target_noreturn = false;
};

struct cfg_analysis_result_t {
    advanced_cfg_key_t key;
    std::vector<basic_block_fact_t> basic_blocks;
    std::vector<cfg_edge_fact_t> cfg_edges;
    dominator_tree_t dominator_tree;
    dominator_tree_t post_dominator_tree;
    std::vector<loop_info_t> loops;
    std::vector<loop_depth_fact_t> loop_depths;
    std::vector<reducibility_component_t> reducibility_components;
    std::vector<recovered_switch_t> switches;
    std::vector<exception_region_t> exception_regions;
    std::vector<thunk_info_t> thunks;
    std::vector<tail_call_info_t> tail_calls;
    std::vector<noreturn_effect_t> noreturn_effects;
    std::vector<callgraph_edge_t> callgraph_edges;
    std::vector<advanced_cfg_conflict_t> conflicts;
    std::uint64_t function_rva = 0;
    std::uint64_t input_block_count = 0;
    std::uint64_t input_edge_count = 0;
    std::uint64_t block_count = 0;
    std::uint64_t edge_count = 0;
    std::uint64_t loops_found = 0;
    std::uint64_t switches_found = 0;
    std::uint64_t thunks_found = 0;
    std::uint64_t tail_calls_found = 0;
    std::uint64_t callgraph_edges_found = 0;
    bool function_noreturn = false;
    bool reducible = true;
    bool bounded = false;
    bool cancelled = false;
};

workspace_result_t<cfg_analysis_result_t>
    analyze_advanced_cfg(const analysis_workspace_t& workspace,
                         std::uint64_t function_rva,
                         const advanced_cfg_budget_t& budget,
                         const cancellation_token_t& cancel);

workspace_result_t<cfg_analysis_result_t>
    analyze_advanced_cfg(const analysis_workspace_t& workspace,
                         std::uint64_t function_rva,
                         const cancellation_token_t& cancel);

}
