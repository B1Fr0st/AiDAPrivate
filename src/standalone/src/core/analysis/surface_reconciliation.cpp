#include "surface_reconciliation.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace aida::analysis::c03 {

namespace {

struct stable_code_entry_t {
    surface_error_code_t code;
    std::string_view name;
};

constexpr stable_code_entry_t k_stable_codes[] = {
    {surface_error_code_t::none,                              "none"},
    {surface_error_code_t::dead_replaced_path_detected,       "dead_replaced_path_detected"},
    {surface_error_code_t::duplicate_store_detected,          "duplicate_store_detected"},
    {surface_error_code_t::stale_registration_detected,       "stale_registration_detected"},
    {surface_error_code_t::old_schema_v8_writer_detected,     "old_schema_v8_writer_detected"},
    {surface_error_code_t::legacy_invalid_ast_flow_detected,  "legacy_invalid_ast_flow_detected"},
    {surface_error_code_t::unsupported_alias_detected,        "unsupported_alias_detected"},
    {surface_error_code_t::security_regression_detected,      "security_regression_detected"},
    {surface_error_code_t::unexplained_removal_detected,      "unexplained_removal_detected"},
    {surface_error_code_t::baseline_mismatch,                 "baseline_mismatch"},
    {surface_error_code_t::internal_error,                    "internal_error"},
};

constexpr std::size_t k_stable_code_count = sizeof(k_stable_codes) / sizeof(k_stable_codes[0]);

struct entry_kind_name_t {
    surface_entry_kind_t kind;
    std::string_view name;
};

constexpr entry_kind_name_t k_kind_names[] = {
    {surface_entry_kind_t::source_file,            "source_file"},
    {surface_entry_kind_t::contract_registration,  "contract_registration"},
    {surface_entry_kind_t::handler_registration,   "handler_registration"},
    {surface_entry_kind_t::tool_registration,      "tool_registration"},
    {surface_entry_kind_t::schema_writer,          "schema_writer"},
    {surface_entry_kind_t::ast_path,               "ast_path"},
    {surface_entry_kind_t::alias_mapping,          "alias_mapping"},
    {surface_entry_kind_t::security_guard,         "security_guard"},
    {surface_entry_kind_t::store_definition,       "store_definition"},
    {surface_entry_kind_t::test_harness,           "test_harness"},
};

constexpr std::size_t k_kind_name_count = sizeof(k_kind_names) / sizeof(k_kind_names[0]);

}

std::string_view surface_reconciliation_t::stable_code_for(
    surface_error_code_t code) noexcept {
    for (std::size_t i = 0; i < k_stable_code_count; ++i) {
        if (k_stable_codes[i].code == code)
            return k_stable_codes[i].name;
    }
    return "unknown";
}

std::string_view surface_reconciliation_t::entry_kind_name(
    surface_entry_kind_t kind) noexcept {
    for (std::size_t i = 0; i < k_kind_name_count; ++i) {
        if (k_kind_names[i].kind == kind)
            return k_kind_names[i].name;
    }
    return "unknown";
}

surface_finding_t surface_reconciliation_t::make_finding(
    surface_error_code_t code, std::string_view identifier,
    std::string detail, std::string canonical_path,
    surface_entry_kind_t kind, std::uint64_t severity) {
    surface_finding_t finding;
    finding.code = code;
    finding.stable_code = stable_code_for(code);
    finding.identifier = std::string(identifier);
    finding.detail = std::move(detail);
    finding.canonical_path = std::move(canonical_path);
    finding.kind = kind;
    finding.severity = severity;
    return finding;
}

surface_reconciliation_t::surface_reconciliation_t(
    surface_reconciliation_limits_t limits)
    : limits_(limits) {}

void surface_reconciliation_t::register_baseline_entry(const surface_entry_t& entry) {
    if (baseline_.size() < limits_.maximum_entries)
        baseline_.push_back(entry);
}

void surface_reconciliation_t::register_actual_entry(const surface_entry_t& entry) {
    if (actual_.size() < limits_.maximum_entries)
        actual_.push_back(entry);
}

void surface_reconciliation_t::mark_dead_replaced_path(
    std::string_view identifier, std::string_view replaced_by) {
    dead_replaced_paths_[std::string(identifier)] = std::string(replaced_by);
}

void surface_reconciliation_t::mark_duplicate_store(
    std::string_view identifier, std::string_view other_path) {
    duplicate_stores_[std::string(identifier)] = std::string(other_path);
}

void surface_reconciliation_t::mark_stale_registration(std::string_view identifier) {
    stale_registrations_.insert(std::string(identifier));
}

void surface_reconciliation_t::mark_old_schema_v8_writer(
    std::string_view identifier, std::string_view canonical_path) {
    old_schema_v8_writers_[std::string(identifier)] = std::string(canonical_path);
}

void surface_reconciliation_t::mark_legacy_invalid_ast_flow(std::string_view identifier) {
    legacy_ast_flows_.insert(std::string(identifier));
}

void surface_reconciliation_t::mark_unsupported_alias(
    std::string_view alias, std::string_view canonical_name) {
    unsupported_aliases_[std::string(alias)] = std::string(canonical_name);
}

void surface_reconciliation_t::mark_security_regression(
    std::string_view identifier, std::string_view detail) {
    security_regressions_[std::string(identifier)] = std::string(detail);
}

void surface_reconciliation_t::check_dead_replaced_paths(
    surface_reconciliation_result_t& result) const {
    for (const auto& [identifier, replaced_by] : dead_replaced_paths_) {
        bool found_in_actual = false;
        for (const auto& entry : actual_) {
            if (entry.identifier == identifier && entry.is_active) {
                found_in_actual = true;
                break;
            }
        }
        if (found_in_actual) {
            result.findings.push_back(make_finding(
                surface_error_code_t::dead_replaced_path_detected,
                identifier,
                "path marked as replaced by " + replaced_by + " but still active in actual surface",
                "",
                surface_entry_kind_t::source_file,
                500));
        }
    }
}

void surface_reconciliation_t::check_duplicate_stores(
    surface_reconciliation_result_t& result) const {
    std::unordered_map<std::string, std::vector<std::string>> store_paths;
    for (const auto& entry : actual_) {
        if (entry.kind == surface_entry_kind_t::store_definition) {
            store_paths[entry.identifier].push_back(entry.canonical_path);
        }
    }
    for (const auto& [identifier, paths] : store_paths) {
        if (paths.size() > 1) {
            std::string detail = "store '" + identifier + "' defined in multiple paths: ";
            for (std::size_t i = 0; i < paths.size(); ++i) {
                if (i > 0) detail += ", ";
                detail += paths[i];
            }
            result.findings.push_back(make_finding(
                surface_error_code_t::duplicate_store_detected,
                identifier,
                std::move(detail),
                paths.front(),
                surface_entry_kind_t::store_definition,
                600));
        }
    }
    for (const auto& [identifier, other_path] : duplicate_stores_) {
        result.findings.push_back(make_finding(
            surface_error_code_t::duplicate_store_detected,
            identifier,
            "duplicate store also at " + other_path,
            other_path,
            surface_entry_kind_t::store_definition,
            550));
    }
}

void surface_reconciliation_t::check_stale_registrations(
    surface_reconciliation_result_t& result) const {
    for (const auto& identifier : stale_registrations_) {
        bool found_in_actual = false;
        for (const auto& entry : actual_) {
            if (entry.identifier == identifier && entry.is_active) {
                found_in_actual = true;
                break;
            }
        }
        if (found_in_actual) {
            result.findings.push_back(make_finding(
                surface_error_code_t::stale_registration_detected,
                identifier,
                "registration is stale but still active in actual surface",
                "",
                surface_entry_kind_t::handler_registration,
                400));
        }
    }

    std::unordered_set<std::string> actual_ids;
    for (const auto& entry : actual_) {
        if (entry.kind == surface_entry_kind_t::handler_registration ||
            entry.kind == surface_entry_kind_t::tool_registration) {
            actual_ids.insert(entry.identifier);
        }
    }
    for (const auto& entry : baseline_) {
        if ((entry.kind == surface_entry_kind_t::handler_registration ||
             entry.kind == surface_entry_kind_t::tool_registration) &&
            entry.is_active) {
            if (actual_ids.find(entry.identifier) == actual_ids.end()) {
                result.findings.push_back(make_finding(
                    surface_error_code_t::stale_registration_detected,
                    entry.identifier,
                    "baseline registration not found in actual surface",
                    entry.canonical_path,
                    entry.kind,
                    350));
            }
        }
    }
}

void surface_reconciliation_t::check_old_schema_v8_writers(
    surface_reconciliation_result_t& result) const {
    for (const auto& entry : actual_) {
        if (entry.kind == surface_entry_kind_t::schema_writer &&
            entry.schema_version == "v8" && entry.is_active) {
            result.findings.push_back(make_finding(
                surface_error_code_t::old_schema_v8_writer_detected,
                entry.identifier,
                "active schema writer using deprecated v8 schema; must migrate to v9",
                entry.canonical_path,
                surface_entry_kind_t::schema_writer,
                700));
        }
    }
    for (const auto& [identifier, canonical_path] : old_schema_v8_writers_) {
        result.findings.push_back(make_finding(
            surface_error_code_t::old_schema_v8_writer_detected,
            identifier,
            "schema v8 writer detected at " + canonical_path,
            canonical_path,
            surface_entry_kind_t::schema_writer,
            700));
    }
}

void surface_reconciliation_t::check_legacy_invalid_ast_flows(
    surface_reconciliation_result_t& result) const {
    for (const auto& identifier : legacy_ast_flows_) {
        bool found_in_actual = false;
        for (const auto& entry : actual_) {
            if (entry.identifier == identifier && entry.is_active &&
                entry.kind == surface_entry_kind_t::ast_path) {
                found_in_actual = true;
                break;
            }
        }
        if (found_in_actual) {
            result.findings.push_back(make_finding(
                surface_error_code_t::legacy_invalid_ast_flow_detected,
                identifier,
                "legacy invalid AST flow is still active in actual surface",
                "",
                surface_entry_kind_t::ast_path,
                650));
        }
    }
}

void surface_reconciliation_t::check_unsupported_aliases(
    surface_reconciliation_result_t& result) const {
    for (const auto& [alias, canonical_name] : unsupported_aliases_) {
        bool alias_active = false;
        for (const auto& entry : actual_) {
            if (entry.identifier == alias && entry.is_active &&
                entry.kind == surface_entry_kind_t::alias_mapping) {
                alias_active = true;
                break;
            }
        }
        if (alias_active) {
            result.findings.push_back(make_finding(
                surface_error_code_t::unsupported_alias_detected,
                alias,
                "unsupported alias still active; canonical name is " + canonical_name,
                "",
                surface_entry_kind_t::alias_mapping,
                300));
        }
    }
}

void surface_reconciliation_t::check_security_regressions(
    surface_reconciliation_result_t& result) const {
    for (const auto& entry : actual_) {
        if (entry.kind == surface_entry_kind_t::security_guard && !entry.is_active) {
            result.findings.push_back(make_finding(
                surface_error_code_t::security_regression_detected,
                entry.identifier,
                "security guard is inactive in actual surface: " + entry.security_note,
                entry.canonical_path,
                surface_entry_kind_t::security_guard,
                900));
        }
    }
    for (const auto& [identifier, detail] : security_regressions_) {
        result.findings.push_back(make_finding(
            surface_error_code_t::security_regression_detected,
            identifier,
            "security regression: " + detail,
            "",
            surface_entry_kind_t::security_guard,
            900));
    }

    for (const auto& entry : baseline_) {
        if (entry.kind == surface_entry_kind_t::security_guard && entry.is_active) {
            bool found_in_actual = false;
            for (const auto& actual_entry : actual_) {
                if (actual_entry.identifier == entry.identifier &&
                    actual_entry.kind == surface_entry_kind_t::security_guard &&
                    actual_entry.is_active) {
                    found_in_actual = true;
                    break;
                }
            }
            if (!found_in_actual) {
                result.findings.push_back(make_finding(
                    surface_error_code_t::security_regression_detected,
                    entry.identifier,
                    "baseline security guard missing from actual surface",
                    entry.canonical_path,
                    surface_entry_kind_t::security_guard,
                    950));
            }
        }
    }
}

void surface_reconciliation_t::check_unexplained_removals(
    surface_reconciliation_result_t& result) const {

    std::unordered_set<std::string> dead_replaced_ids;
    for (const auto& [id, _] : dead_replaced_paths_) {
        dead_replaced_ids.insert(id);
    }
    std::unordered_set<std::string> stale_ids;
    for (const auto& id : stale_registrations_) {
        stale_ids.insert(id);
    }

    std::unordered_set<std::string> actual_ids;
    for (const auto& entry : actual_) {
        actual_ids.insert(entry.identifier);
    }

    std::uint64_t removals = 0;
    for (const auto& entry : baseline_) {
        if (!entry.is_active)
            continue;

        if (actual_ids.find(entry.identifier) == actual_ids.end()) {
            bool explained = dead_replaced_ids.count(entry.identifier) > 0 ||
                             stale_ids.count(entry.identifier) > 0;
            if (!explained) {
                ++removals;
                result.findings.push_back(make_finding(
                    surface_error_code_t::unexplained_removal_detected,
                    entry.identifier,
                    "baseline entry absent from actual surface with no explanation",
                    entry.canonical_path,
                    entry.kind,
                    800));
            }
        }
    }

    result.unexplained_removals = removals;
}

surface_reconciliation_result_t surface_reconciliation_t::reconcile() const {
    surface_reconciliation_result_t result;
    result.baseline_entry_count = static_cast<std::uint64_t>(baseline_.size());
    result.actual_entry_count = static_cast<std::uint64_t>(actual_.size());
    result.total_entries_checked = result.baseline_entry_count + result.actual_entry_count;

    check_dead_replaced_paths(result);
    check_duplicate_stores(result);
    check_stale_registrations(result);
    check_old_schema_v8_writers(result);
    check_legacy_invalid_ast_flows(result);
    check_unsupported_aliases(result);
    check_security_regressions(result);
    check_unexplained_removals(result);

    if (result.findings.size() > limits_.maximum_findings) {
        result.findings.resize(limits_.maximum_findings);
    }

    result.clean = result.findings.empty() && result.unexplained_removals == 0;

    reconciliations_.fetch_add(1, std::memory_order_acq_rel);
    total_findings_.fetch_add(result.findings.size(), std::memory_order_acq_rel);

    return result;
}

std::size_t surface_reconciliation_t::baseline_entry_count() const noexcept {
    return baseline_.size();
}

std::size_t surface_reconciliation_t::actual_entry_count() const noexcept {
    return actual_.size();
}

std::uint64_t surface_reconciliation_t::reconciliations_performed() const noexcept {
    return reconciliations_.load(std::memory_order_acquire);
}

std::uint64_t surface_reconciliation_t::total_findings() const noexcept {
    return total_findings_.load(std::memory_order_acquire);
}

}
