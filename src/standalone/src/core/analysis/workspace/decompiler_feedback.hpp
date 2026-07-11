#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace aida::analysis {

enum class decompiler_feedback_fact_kind_t : std::uint8_t {
    function_boundary,
    cfg,
    switch_table,
    prototype,
    stack_variable,
    local_variable,
    global_reference,
    type_assignment,
    name,
    comment,
    source_mapping,
    abstention,
    error
};

enum class decompiler_feedback_validation_grade_t : std::uint8_t {
    unverified,
    validated,
    proven
};

enum class decompiler_feedback_authority_t : std::uint8_t {
    imported,
    decompiler,
    baseline_graph,
    trusted_recovery
};

enum class decompiler_feedback_abstention_reason_t : std::uint8_t {
    unsupported_architecture,
    unsupported_encoding,
    opaque_control_flow,
    insufficient_bytes,
    contradictory_evidence,
    resource_budget,
    cancelled,
    deadline_exceeded
};

enum class decompiler_feedback_error_class_t : std::uint8_t {
    decoder,
    ir_lift,
    cfg_reconstruction,
    type_recovery,
    source_mapping,
    persistence,
    integration
};

enum class decompiler_feedback_cache_domain_t : std::uint8_t {
    function_boundaries,
    control_flow,
    switch_metadata,
    prototype,
    storage_layout,
    type_graph,
    symbols,
    annotations,
    source_map,
    decompiler_output,
    baseline_graph
};

enum class decompiler_feedback_fixed_point_status_t : std::uint8_t {
    active,
    converged,
    round_budget_exhausted,
    cancelled,
    deadline_exceeded
};

enum class decompiler_feedback_publication_status_t : std::uint8_t {
    published,
    no_change,
    invalid_scope,
    publication_capacity,
    fixed_point_closed,
    cancelled,
    deadline_exceeded,
    internal_failure
};

enum class decompiler_feedback_rejection_reason_t : std::uint8_t {
    invalid_fact,
    conflict_lost,
    incompatible_conflict,
    publication_capacity,
    active_capacity,
    affected_range_capacity,
    cache_invalidation_capacity,
    isolated_failure
};

enum class decompiler_feedback_conflict_decision_t : std::uint8_t {
    candidate_replaces_incumbent,
    incumbent_retained,
    duplicate,
    incompatible
};

struct decompiler_feedback_scope_key_t {
    std::string workspace_id;
    std::string binary_id;
    std::string address_space_id;
    std::string architecture_id;
    std::uint64_t generation = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t type_revision = 0;

    bool operator==(const decompiler_feedback_scope_key_t& other) const noexcept;
    bool operator<(const decompiler_feedback_scope_key_t& other) const noexcept;
};

struct decompiler_feedback_range_t {
    std::uint64_t begin = 0;
    std::uint64_t size = 0;

    bool end(std::uint64_t& out) const noexcept;
    bool valid() const noexcept;
    bool contains(std::uint64_t address) const noexcept;
    bool contains(const decompiler_feedback_range_t& other) const noexcept;
    bool overlaps(const decompiler_feedback_range_t& other) const noexcept;
    bool operator==(const decompiler_feedback_range_t& other) const noexcept;
    bool operator<(const decompiler_feedback_range_t& other) const noexcept;
};

struct decompiler_feedback_validation_t {
    decompiler_feedback_validation_grade_t grade = decompiler_feedback_validation_grade_t::unverified;
    std::string validator_id;
    std::string evidence_id;
    std::uint64_t evidence_revision = 0;
};

struct decompiler_feedback_function_boundary_t {
    std::uint64_t entry = 0;
    std::uint64_t end = 0;
};

struct decompiler_feedback_cfg_block_t {
    decompiler_feedback_range_t range;
    bool terminal = false;
};

struct decompiler_feedback_cfg_edge_t {
    std::uint64_t source = 0;
    std::uint64_t target = 0;
};

struct decompiler_feedback_cfg_t {
    std::vector<decompiler_feedback_cfg_block_t> blocks;
    std::vector<decompiler_feedback_cfg_edge_t> edges;
};

struct decompiler_feedback_switch_case_t {
    std::int64_t value = 0;
    std::uint64_t target = 0;
};

struct decompiler_feedback_switch_t {
    std::uint64_t dispatch = 0;
    std::vector<decompiler_feedback_switch_case_t> cases;
    std::optional<std::uint64_t> default_target;
};

struct decompiler_feedback_prototype_t {
    std::uint64_t function = 0;
    std::string declaration;
    std::string calling_convention;
};

struct decompiler_feedback_storage_t {
    std::uint64_t address = 0;
    std::int64_t stack_offset = 0;
    std::uint64_t byte_size = 0;
    std::string identifier;
    std::string type_name;
};

struct decompiler_feedback_type_assignment_t {
    std::uint64_t address = 0;
    std::string type_name;
};

struct decompiler_feedback_name_t {
    std::uint64_t address = 0;
    std::string identifier;
};

struct decompiler_feedback_comment_t {
    std::uint64_t address = 0;
    std::string text;
};

struct decompiler_feedback_source_mapping_t {
    decompiler_feedback_range_t mapped_range;
    std::string source_path;
    std::uint32_t first_line = 0;
    std::uint32_t first_column = 0;
    std::uint32_t last_line = 0;
    std::uint32_t last_column = 0;
};

struct decompiler_feedback_abstention_t {
    decompiler_feedback_abstention_reason_t reason =
        decompiler_feedback_abstention_reason_t::unsupported_architecture;
    std::string detail;
};

struct decompiler_feedback_error_t {
    decompiler_feedback_error_class_t error_class = decompiler_feedback_error_class_t::decoder;
    std::string detail;
    bool retryable = false;
};

using decompiler_feedback_payload_t = std::variant<
    decompiler_feedback_function_boundary_t,
    decompiler_feedback_cfg_t,
    decompiler_feedback_switch_t,
    decompiler_feedback_prototype_t,
    decompiler_feedback_storage_t,
    decompiler_feedback_type_assignment_t,
    decompiler_feedback_name_t,
    decompiler_feedback_comment_t,
    decompiler_feedback_source_mapping_t,
    decompiler_feedback_abstention_t,
    decompiler_feedback_error_t>;

struct decompiler_feedback_fact_t {
    std::string fact_id;
    std::string logical_key;
    std::string publisher_id;
    decompiler_feedback_fact_kind_t kind = decompiler_feedback_fact_kind_t::function_boundary;
    decompiler_feedback_authority_t authority = decompiler_feedback_authority_t::decompiler;
    decompiler_feedback_validation_t validation;
    std::uint64_t source_revision = 0;
    decompiler_feedback_range_t affected_range;
    decompiler_feedback_payload_t payload;
};

struct decompiler_feedback_limits_t {
    std::size_t max_facts_per_publication = 1024;
    std::size_t max_active_facts_per_scope = 16384;
    std::size_t max_identifier_bytes = 4096;
    std::size_t max_payload_bytes = 65536;
    std::size_t max_publication_payload_bytes = 8ULL << 20;
    std::size_t max_cfg_blocks = 4096;
    std::size_t max_cfg_edges = 8192;
    std::size_t max_switch_cases = 4096;
    std::size_t max_affected_ranges = 256;
    std::uint64_t max_affected_bytes = 64ULL << 20;
    std::size_t max_cache_invalidation_keys = 4096;
    std::uint32_t max_fixed_point_rounds = 8;
    std::uint32_t convergence_rounds = 1;
    std::size_t poll_interval = 16;
};

struct decompiler_feedback_validation_result_t {
    bool valid = false;
    std::string code;
    std::string message;
};

struct decompiler_feedback_fixed_point_state_t {
    decompiler_feedback_fixed_point_status_t status = decompiler_feedback_fixed_point_status_t::active;
    std::uint32_t rounds = 0;
    std::uint32_t stable_rounds = 0;
    std::uint64_t accepted_facts = 0;
    std::uint64_t rejected_facts = 0;
    std::uint64_t conflict_count = 0;
};

struct decompiler_feedback_rejection_t {
    std::size_t input_index = 0;
    std::string fact_id;
    decompiler_feedback_rejection_reason_t reason = decompiler_feedback_rejection_reason_t::invalid_fact;
    std::string code;
    std::string message;
};

struct decompiler_feedback_conflict_resolution_t {
    decompiler_feedback_conflict_decision_t decision =
        decompiler_feedback_conflict_decision_t::incompatible;
    std::string winner_fact_id;
    std::string loser_fact_id;
    std::string reason;
};

struct decompiler_feedback_conflict_t {
    std::string logical_key;
    std::string incumbent_fact_id;
    std::string candidate_fact_id;
    decompiler_feedback_conflict_resolution_t resolution;
};

struct decompiler_feedback_cache_invalidation_key_t {
    decompiler_feedback_scope_key_t scope;
    decompiler_feedback_cache_domain_t domain = decompiler_feedback_cache_domain_t::decompiler_output;
    decompiler_feedback_range_t range;
    std::uint64_t anchor_address = 0;

    bool operator==(const decompiler_feedback_cache_invalidation_key_t& other) const noexcept;
    bool operator<(const decompiler_feedback_cache_invalidation_key_t& other) const noexcept;
};

struct decompiler_feedback_range_plan_t {
    bool bounded = false;
    std::vector<decompiler_feedback_range_t> ranges;
    std::uint64_t total_bytes = 0;
    std::string code;
    std::string message;
};

struct decompiler_feedback_cache_plan_t {
    bool bounded = false;
    std::vector<decompiler_feedback_cache_invalidation_key_t> keys;
    std::string code;
    std::string message;
};

struct decompiler_feedback_publication_request_t {
    decompiler_feedback_scope_key_t scope;
    std::vector<decompiler_feedback_fact_t> facts;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::function<bool()> is_cancelled;
};

struct decompiler_feedback_publication_result_t {
    decompiler_feedback_publication_status_t status = decompiler_feedback_publication_status_t::no_change;
    decompiler_feedback_fixed_point_state_t fixed_point;
    std::vector<std::string> accepted_fact_ids;
    std::vector<decompiler_feedback_rejection_t> rejections;
    std::vector<decompiler_feedback_conflict_t> conflicts;
    decompiler_feedback_range_plan_t affected_ranges;
    decompiler_feedback_cache_plan_t cache_invalidations;
    std::string code;
    std::string message;
};

struct decompiler_feedback_scope_snapshot_t {
    bool exists = false;
    decompiler_feedback_fixed_point_state_t fixed_point;
    std::vector<decompiler_feedback_fact_t> facts;
};

class decompiler_feedback_model_t final {
public:
    explicit decompiler_feedback_model_t(decompiler_feedback_limits_t limits = {});
    ~decompiler_feedback_model_t();

    decompiler_feedback_model_t(const decompiler_feedback_model_t&) = delete;
    decompiler_feedback_model_t& operator=(const decompiler_feedback_model_t&) = delete;

    decompiler_feedback_publication_result_t publish(
        const decompiler_feedback_publication_request_t& request);
    decompiler_feedback_scope_snapshot_t snapshot(const decompiler_feedback_scope_key_t& scope) const;

    const decompiler_feedback_limits_t& limits() const noexcept;

    static decompiler_feedback_validation_result_t validate_scope(
        const decompiler_feedback_scope_key_t& scope,
        const decompiler_feedback_limits_t& limits = {});
    static decompiler_feedback_validation_result_t validate_fact(
        const decompiler_feedback_fact_t& fact,
        const decompiler_feedback_limits_t& limits = {});
    static decompiler_feedback_conflict_resolution_t resolve_conflict(
        const decompiler_feedback_fact_t& incumbent,
        const decompiler_feedback_fact_t& candidate);
    static decompiler_feedback_range_plan_t compose_affected_ranges(
        std::vector<decompiler_feedback_range_t> ranges,
        const decompiler_feedback_limits_t& limits = {});
    static decompiler_feedback_cache_plan_t derive_cache_invalidations(
        const decompiler_feedback_scope_key_t& scope,
        const std::vector<decompiler_feedback_fact_t>& facts,
        const decompiler_feedback_limits_t& limits = {});
    static bool should_stop(const decompiler_feedback_publication_request_t& request,
                            decompiler_feedback_publication_status_t& status) noexcept;

private:
    struct state_t;

    decompiler_feedback_limits_t limits_;
    std::unique_ptr<state_t> state_;
};

}
