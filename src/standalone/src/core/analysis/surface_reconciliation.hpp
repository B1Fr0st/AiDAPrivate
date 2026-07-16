#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {

enum class surface_error_code_t : std::uint8_t {
    none = 0,
    dead_replaced_path_detected = 1,
    duplicate_store_detected = 2,
    stale_registration_detected = 3,
    old_schema_v8_writer_detected = 4,
    legacy_invalid_ast_flow_detected = 5,
    unsupported_alias_detected = 6,
    security_regression_detected = 7,
    unexplained_removal_detected = 8,
    baseline_mismatch = 9,
    internal_error = 10,
    invalid_limit_contract = 11,
    baseline_entry_cap_exceeded = 12,
    actual_entry_cap_exceeded = 13,
    finding_cap_exceeded = 14,
    duplicate_baseline_identifier_detected = 15,
    duplicate_actual_identifier_detected = 16,
    invalid_surface_entry = 17,
    invalid_surface_marker = 18,
    auxiliary_marker_cap_exceeded = 19
};

enum class surface_entry_kind_t : std::uint8_t {
    source_file = 0,
    contract_registration = 1,
    handler_registration = 2,
    tool_registration = 3,
    schema_writer = 4,
    ast_path = 5,
    alias_mapping = 6,
    security_guard = 7,
    store_definition = 8,
    test_harness = 9
};

enum class surface_finding_semantic_t : std::uint8_t {
    ordinary = 0,
    finding_capacity = 1,
    metrics_saturation = 2,
    auxiliary_security_incomplete = 3
};

struct surface_entry_t final {
    std::string identifier;
    std::string canonical_path;
    surface_entry_kind_t kind = surface_entry_kind_t::source_file;
    std::string schema_version;
    bool is_active = true;
    bool is_replaced = false;
    std::string replaced_by;
    std::string security_note;
};

struct surface_finding_t final {
    surface_error_code_t code = surface_error_code_t::none;
    std::string_view stable_code;
    surface_finding_semantic_t semantic = surface_finding_semantic_t::ordinary;
    std::string identifier;
    std::string detail;
    std::string canonical_path;
    surface_entry_kind_t kind = surface_entry_kind_t::source_file;
    std::uint64_t severity = 0;
};

struct surface_reconciliation_result_t final {
    std::vector<surface_finding_t> findings;
    std::uint64_t total_entries_checked = 0;
    std::uint64_t baseline_entry_count = 0;
    std::uint64_t actual_entry_count = 0;
    std::uint64_t unexplained_removals = 0;
    std::uint64_t attempted_baseline_entries = 0;
    std::uint64_t attempted_actual_entries = 0;
    std::uint64_t rejected_baseline_entries = 0;
    std::uint64_t rejected_actual_entries = 0;
    std::uint64_t attempted_auxiliary_markers = 0;
    std::uint64_t rejected_auxiliary_markers = 0;
    std::uint64_t findings_produced = 0;
    std::uint64_t findings_discarded = 0;
    std::uint64_t malformed_entries = 0;
    std::uint64_t malformed_markers = 0;
    bool limits_invalid = false;
    bool baseline_cap_exceeded = false;
    bool actual_cap_exceeded = false;
    bool auxiliary_cap_exceeded = false;
    bool finding_cap_exceeded = false;
    bool metrics_saturated = false;
    bool clean = false;
};

struct surface_reconciliation_limits_t final {
    std::size_t maximum_entries = 100000;
    std::size_t maximum_findings = 10000;
    std::uint64_t maximum_severity = 1000;
    std::size_t maximum_identifier_bytes = 512;
    std::size_t maximum_text_bytes = 4096;
    std::uint64_t maximum_metric_value =
        std::numeric_limits<std::uint64_t>::max();
};

class surface_reconciliation_t final {
public:
    surface_reconciliation_t(surface_reconciliation_limits_t limits = {});

    surface_reconciliation_t(const surface_reconciliation_t&) = delete;
    surface_reconciliation_t& operator=(const surface_reconciliation_t&) = delete;
    surface_reconciliation_t(surface_reconciliation_t&&) = delete;
    surface_reconciliation_t& operator=(surface_reconciliation_t&&) = delete;

    void register_baseline_entry(const surface_entry_t& entry);
    void register_actual_entry(const surface_entry_t& entry);

    void mark_dead_replaced_path(std::string_view identifier, std::string_view replaced_by);
    void mark_duplicate_store(std::string_view identifier, std::string_view other_path);
    void mark_stale_registration(std::string_view identifier);
    void mark_old_schema_v8_writer(std::string_view identifier, std::string_view canonical_path);
    void mark_legacy_invalid_ast_flow(std::string_view identifier);
    void mark_unsupported_alias(std::string_view alias, std::string_view canonical_name);
    void mark_security_regression(std::string_view identifier, std::string_view detail);

    surface_reconciliation_result_t reconcile() const;

    std::size_t baseline_entry_count() const noexcept;
    std::size_t actual_entry_count() const noexcept;
    std::uint64_t reconciliations_performed() const noexcept;
    std::uint64_t total_findings() const noexcept;

    static std::string_view stable_code_for(surface_error_code_t code) noexcept;
    static std::string_view entry_kind_name(surface_entry_kind_t kind) noexcept;

private:
    struct marker_target_proof_t;

    enum class auxiliary_marker_collection_t : std::uint8_t {
        dead_replaced_paths = 0,
        duplicate_stores = 1,
        stale_registrations = 2,
        old_schema_v8_writers = 3,
        legacy_ast_flows = 4,
        unsupported_aliases = 5,
        security_regressions = 6
    };

    struct auxiliary_value_less_t final {
        using is_transparent = void;

        bool operator()(const std::string& left,
                        const std::string& right) const noexcept {
            return left < right;
        }

        bool operator()(const std::string& left,
                        std::string_view right) const noexcept {
            return std::string_view(left.data(), left.size()) < right;
        }

        bool operator()(std::string_view left,
                        const std::string& right) const noexcept {
            return left < std::string_view(right.data(), right.size());
        }
    };

    struct auxiliary_marker_history_t final {
        std::string canonical_value;
        std::set<std::string, auxiliary_value_less_t> distinct_values;

        bool conflicting() const noexcept {
            return distinct_values.size() > 1;
        }
    };

    struct auxiliary_marker_observation_t final {
        const auxiliary_marker_history_t* state = nullptr;
        bool conflict_started = false;
    };

    surface_finding_t make_finding(
        surface_error_code_t code, std::string_view identifier,
        std::string detail, std::string canonical_path,
        surface_entry_kind_t kind, std::uint64_t severity,
        surface_finding_semantic_t semantic =
            surface_finding_semantic_t::ordinary) const;

    bool valid_identifier(std::string_view value) const noexcept;
    bool valid_path(std::string_view value) const noexcept;
    bool valid_text(std::string_view value, bool allow_empty) const noexcept;
    bool valid_entry(const surface_entry_t& entry, std::string_view& reason) const noexcept;
    void record_invalid_entry(bool baseline, const surface_entry_t& entry,
        std::string_view reason);
    void record_invalid_marker(std::string_view collection,
        std::string_view identifier, std::string_view reason) noexcept;
    auxiliary_marker_observation_t observe_auxiliary_marker(
        auxiliary_marker_collection_t collection,
        std::string_view identifier, std::string_view value) noexcept;
    void enter_auxiliary_history_incomplete() noexcept;
    void admit_auxiliary_marker() noexcept;
    bool retained_auxiliary_marker(
        auxiliary_marker_collection_t collection,
        const std::string& identifier) const noexcept;
    std::uint64_t auxiliary_capacity_rejections(bool& saturated) const noexcept;
    std::string_view auxiliary_overflow_collection() const noexcept;
    static std::string_view auxiliary_collection_name(
        auxiliary_marker_collection_t collection) noexcept;
    void append_finding(surface_reconciliation_result_t& result,
        surface_finding_t finding) const;
    void append_input_contract_findings(surface_reconciliation_result_t& result) const;
    void append_metrics_saturation_finding(surface_reconciliation_result_t& result) const;
    void finalize_finding_cap(surface_reconciliation_result_t& result) const;
    marker_target_proof_t validate_marker_targets(
        surface_reconciliation_result_t& result) const;

    void check_duplicate_identifiers(surface_reconciliation_result_t& result) const;
    void check_baseline_mismatches(surface_reconciliation_result_t& result,
        const marker_target_proof_t& target_proof) const;
    void check_inactive_actual_entries(surface_reconciliation_result_t& result,
        const marker_target_proof_t& target_proof) const;
    void check_dead_replaced_paths(surface_reconciliation_result_t& result,
        const marker_target_proof_t& target_proof) const;
    void check_duplicate_stores(surface_reconciliation_result_t& result) const;
    void check_stale_registrations(surface_reconciliation_result_t& result,
        const marker_target_proof_t& target_proof) const;
    void check_old_schema_v8_writers(surface_reconciliation_result_t& result) const;
    void check_legacy_invalid_ast_flows(surface_reconciliation_result_t& result,
        const marker_target_proof_t& target_proof) const;
    void check_unsupported_aliases(surface_reconciliation_result_t& result,
        const marker_target_proof_t& target_proof) const;
    void check_security_regressions(surface_reconciliation_result_t& result) const;
    void check_unexplained_removals(surface_reconciliation_result_t& result) const;

    surface_reconciliation_limits_t limits_;
    bool limit_contract_valid_ = true;
    std::vector<surface_entry_t> baseline_;
    std::vector<surface_entry_t> actual_;
    std::unordered_map<std::string, std::pair<std::string, bool>> dead_replaced_paths_;
    std::unordered_map<std::string, std::pair<std::string, bool>> duplicate_stores_;
    std::unordered_set<std::string> stale_registrations_;
    std::unordered_map<std::string, std::pair<std::string, bool>> old_schema_v8_writers_;
    std::unordered_set<std::string> legacy_ast_flows_;
    std::unordered_map<std::string, std::pair<std::string, bool>> unsupported_aliases_;
    std::unordered_set<std::string> security_regressions_;
    std::map<
        std::pair<auxiliary_marker_collection_t, std::string>,
        auxiliary_marker_history_t> auxiliary_marker_history_;

    std::uint64_t attempted_baseline_entries_ = 0;
    std::uint64_t attempted_actual_entries_ = 0;
    std::uint64_t rejected_baseline_entries_ = 0;
    std::uint64_t rejected_actual_entries_ = 0;
    std::uint64_t attempted_auxiliary_markers_ = 0;
    std::uint64_t rejected_auxiliary_markers_ = 0;
    std::uint64_t malformed_entries_ = 0;
    std::uint64_t malformed_markers_ = 0;
    std::size_t auxiliary_marker_count_ = 0;
    std::size_t auxiliary_history_value_count_ = 0;
    bool baseline_cap_exceeded_ = false;
    bool actual_cap_exceeded_ = false;
    bool auxiliary_cap_exceeded_ = false;
    bool auxiliary_capacity_incomplete_ = false;
    bool auxiliary_history_incomplete_ = false;
    bool security_marker_observed_ = false;
    std::string first_invalid_entry_identifier_;
    std::string_view first_invalid_entry_reason_;
    bool first_invalid_entry_is_baseline_ = true;
    std::string first_invalid_marker_identifier_;
    std::string_view first_invalid_marker_collection_;
    std::string_view first_invalid_marker_reason_;

    mutable std::atomic_uint64_t reconciliations_{0};
    mutable std::atomic_uint64_t total_findings_{0};
    mutable std::atomic_bool metrics_saturated_{false};
};

}
