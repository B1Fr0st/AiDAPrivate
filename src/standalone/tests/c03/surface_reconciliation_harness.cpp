#include "surface_reconciliation_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/surface_reconciliation.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using namespace aida::analysis::c03;

void require(bool condition, std::string_view message) {
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

surface_entry_t make_entry(
    std::string identifier, std::string path, surface_entry_kind_t kind,
    bool active = true, std::string schema = {}) {
    surface_entry_t entry;
    entry.identifier = std::move(identifier);
    entry.canonical_path = std::move(path);
    entry.kind = kind;
    entry.is_active = active;
    entry.schema_version = std::move(schema);
    if (entry.kind == surface_entry_kind_t::schema_writer &&
        entry.schema_version.empty()) {
        entry.schema_version = "v9";
    }
    if (entry.kind == surface_entry_kind_t::security_guard && !entry.is_active)
        entry.security_note = "guard disabled in adverse fixture";
    return entry;
}

surface_entry_t retired(surface_entry_t entry, std::string replacement) {
    entry.is_active = false;
    entry.is_replaced = true;
    entry.replaced_by = std::move(replacement);
    return entry;
}

surface_entry_t inactive(surface_entry_t entry) {
    entry.is_active = false;
    entry.is_replaced = false;
    entry.replaced_by.clear();
    if (entry.kind == surface_entry_kind_t::security_guard &&
        entry.security_note.empty()) {
        entry.security_note = "guard disabled in adverse fixture";
    }
    return entry;
}

std::size_t finding_count(
    const surface_reconciliation_result_t& result,
    surface_error_code_t code, std::string_view identifier = {}) {
    return static_cast<std::size_t>(std::count_if(
        result.findings.begin(), result.findings.end(),
        [code, identifier](const auto& finding) {
            return finding.code == code &&
                   (identifier.empty() || finding.identifier == identifier);
        }));
}

std::size_t semantic_finding_count(
    const surface_reconciliation_result_t& result,
    surface_finding_semantic_t semantic) {
    return static_cast<std::size_t>(std::count_if(
        result.findings.begin(), result.findings.end(),
        [semantic](const auto& finding) {
            return finding.semantic == semantic;
        }));
}

const surface_finding_t& require_semantic_finding(
    const surface_reconciliation_result_t& result,
    surface_finding_semantic_t semantic) {
    const auto found = std::find_if(
        result.findings.begin(), result.findings.end(),
        [semantic](const auto& finding) {
            return finding.semantic == semantic;
        });
    require(found != result.findings.end(),
            "required reconciliation semantic finding is absent");
    return *found;
}

const surface_finding_t& require_finding(
    const surface_reconciliation_result_t& result,
    surface_error_code_t code, std::string_view identifier) {
    const auto found = std::find_if(
        result.findings.begin(), result.findings.end(),
        [code, identifier](const auto& finding) {
            return finding.code == code && finding.identifier == identifier;
        });
    require(found != result.findings.end(), "required reconciliation finding is absent");
    return *found;
}

void require_no_finding(
    const surface_reconciliation_result_t& result,
    surface_error_code_t code, std::string_view identifier = {}) {
    require(finding_count(result, code, identifier) == 0,
            "unexpected reconciliation finding is present");
}

void require_detail(
    const surface_finding_t& finding, std::string_view expected) {
    require(finding.detail == expected, "reconciliation finding detail mismatch");
}

void require_contains(
    const surface_finding_t& finding, std::string_view expected) {
    require(finding.detail.find(expected) != std::string::npos,
            "reconciliation finding detail token is absent");
}

void require_replacement_reason(
    const surface_reconciliation_result_t& result,
    std::string_view collection, std::string_view identifier,
    std::string_view target, std::string_view reason);

bool equal_results(
    const surface_reconciliation_result_t& left,
    const surface_reconciliation_result_t& right) {
    if (left.total_entries_checked != right.total_entries_checked ||
        left.baseline_entry_count != right.baseline_entry_count ||
        left.actual_entry_count != right.actual_entry_count ||
        left.unexplained_removals != right.unexplained_removals ||
        left.attempted_baseline_entries != right.attempted_baseline_entries ||
        left.attempted_actual_entries != right.attempted_actual_entries ||
        left.rejected_baseline_entries != right.rejected_baseline_entries ||
        left.rejected_actual_entries != right.rejected_actual_entries ||
        left.attempted_auxiliary_markers != right.attempted_auxiliary_markers ||
        left.rejected_auxiliary_markers != right.rejected_auxiliary_markers ||
        left.findings_produced != right.findings_produced ||
        left.findings_discarded != right.findings_discarded ||
        left.malformed_entries != right.malformed_entries ||
        left.malformed_markers != right.malformed_markers ||
        left.limits_invalid != right.limits_invalid ||
        left.baseline_cap_exceeded != right.baseline_cap_exceeded ||
        left.actual_cap_exceeded != right.actual_cap_exceeded ||
        left.auxiliary_cap_exceeded != right.auxiliary_cap_exceeded ||
        left.finding_cap_exceeded != right.finding_cap_exceeded ||
        left.metrics_saturated != right.metrics_saturated ||
        left.clean != right.clean || left.findings.size() != right.findings.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.findings.size(); ++index) {
        const auto& a = left.findings[index];
        const auto& b = right.findings[index];
        if (a.code != b.code || a.stable_code != b.stable_code ||
            a.semantic != b.semantic ||
            a.identifier != b.identifier || a.detail != b.detail ||
            a.canonical_path != b.canonical_path || a.kind != b.kind ||
            a.severity != b.severity) {
            return false;
        }
    }
    return true;
}

void verify_stable_protocol() {
    constexpr std::array<std::string_view, 20> codes = {
        "none",
        "dead_replaced_path_detected",
        "duplicate_store_detected",
        "stale_registration_detected",
        "old_schema_v8_writer_detected",
        "legacy_invalid_ast_flow_detected",
        "unsupported_alias_detected",
        "security_regression_detected",
        "unexplained_removal_detected",
        "baseline_mismatch",
        "internal_error",
        "invalid_limit_contract",
        "baseline_entry_cap_exceeded",
        "actual_entry_cap_exceeded",
        "finding_cap_exceeded",
        "duplicate_baseline_identifier_detected",
        "duplicate_actual_identifier_detected",
        "invalid_surface_entry",
        "invalid_surface_marker",
        "auxiliary_marker_cap_exceeded"
    };
    for (std::size_t index = 0; index < codes.size(); ++index) {
        const auto code = static_cast<surface_error_code_t>(index);
        require(static_cast<std::uint8_t>(code) == index,
                "surface error ordinal changed");
        require(surface_reconciliation_t::stable_code_for(code) == codes[index],
                "surface error stable code changed");
    }
    require(surface_reconciliation_t::stable_code_for(
                static_cast<surface_error_code_t>(0xff)) == "unknown",
            "unknown surface error code did not fail closed");

    constexpr std::array<std::string_view, 10> kinds = {
        "source_file", "contract_registration", "handler_registration",
        "tool_registration", "schema_writer", "ast_path", "alias_mapping",
        "security_guard", "store_definition", "test_harness"
    };
    for (std::size_t index = 0; index < kinds.size(); ++index) {
        const auto kind = static_cast<surface_entry_kind_t>(index);
        require(static_cast<std::uint8_t>(kind) == index,
                "surface entry kind ordinal changed");
        require(surface_reconciliation_t::entry_kind_name(kind) == kinds[index],
                "surface entry kind stable name changed");
    }
    require(surface_reconciliation_t::entry_kind_name(
                static_cast<surface_entry_kind_t>(0xff)) == "unknown",
            "unknown surface entry kind did not fail closed");

    constexpr std::array<surface_finding_semantic_t, 4> semantics = {
        surface_finding_semantic_t::ordinary,
        surface_finding_semantic_t::finding_capacity,
        surface_finding_semantic_t::metrics_saturation,
        surface_finding_semantic_t::auxiliary_security_incomplete
    };
    for (std::size_t index = 0; index < semantics.size(); ++index) {
        require(static_cast<std::uint8_t>(semantics[index]) == index,
                "surface finding semantic ordinal changed");
    }
}

void verify_clean_boundaries_and_determinism() {
    surface_reconciliation_t reconciliation;
    auto boundary = make_entry(
        std::string(512, 'I'), std::string(4096, 'p'),
        surface_entry_kind_t::source_file);
    reconciliation.register_baseline_entry(boundary);
    reconciliation.register_actual_entry(boundary);
    const auto first = reconciliation.reconcile();
    const auto second = reconciliation.reconcile();
    require(first.clean && first.findings.empty(),
            "maximum-valid surface entry did not reconcile cleanly");
    require(first.total_entries_checked == 2 &&
                first.baseline_entry_count == 1 && first.actual_entry_count == 1,
            "clean boundary metrics are incorrect");
    require(equal_results(first, second),
            "repeated clean reconciliation is nondeterministic");
    require(reconciliation.baseline_entry_count() == 1 &&
                reconciliation.actual_entry_count() == 1 &&
                reconciliation.reconciliations_performed() == 2 &&
                reconciliation.total_findings() == 0,
            "clean reconciliation lifetime counters are incorrect");
}

void verify_semantic_drift_and_security_precedence() {
    surface_reconciliation_t reconciliation;
    const auto add = [&reconciliation](surface_entry_t baseline,
                                       surface_entry_t actual) {
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
    };

    auto kind_before = make_entry(
        "kind_drift", "surface/kind.cpp", surface_entry_kind_t::source_file);
    auto kind_after = kind_before;
    kind_after.kind = surface_entry_kind_t::test_harness;
    add(kind_before, kind_after);

    auto path_before = make_entry(
        "path_drift", "surface/old.cpp", surface_entry_kind_t::source_file);
    auto path_after = path_before;
    path_after.canonical_path = "surface/new.cpp";
    add(path_before, path_after);

    auto active_before = make_entry(
        "active_drift", "surface/active.cpp", surface_entry_kind_t::source_file);
    auto active_after = active_before;
    active_after.is_active = false;
    add(active_before, active_after);

    auto state_before = make_entry(
        "state_drift", "surface/state.cpp", surface_entry_kind_t::source_file);
    add(state_before, retired(state_before, "state_target"));
    reconciliation.register_actual_entry(make_entry(
        "state_target", "surface/state_target.cpp",
        surface_entry_kind_t::source_file));

    auto replacement_before = retired(make_entry(
        "replacement_drift", "surface/replacement.cpp",
        surface_entry_kind_t::source_file), "target_a");
    auto replacement_after = replacement_before;
    replacement_after.replaced_by = "target_b";
    add(replacement_before, replacement_after);

    auto schema_before = make_entry(
        "schema_drift", "surface/schema.cpp",
        surface_entry_kind_t::schema_writer, true, "v8");
    auto schema_after = schema_before;
    schema_after.schema_version = "v9";
    add(schema_before, schema_after);

    auto note_before = make_entry(
        "note_drift", "surface/guard.cpp",
        surface_entry_kind_t::security_guard);
    note_before.security_note = "strict baseline";
    auto note_after = note_before;
    note_after.security_note = "changed guard policy";
    add(note_before, note_after);

    auto guard_kind_before = make_entry(
        "guard_kind_drift", "surface/guard_kind.cpp",
        surface_entry_kind_t::source_file);
    auto guard_kind_after = guard_kind_before;
    guard_kind_after.kind = surface_entry_kind_t::security_guard;
    add(guard_kind_before, guard_kind_after);

    const auto result = reconciliation.reconcile();
    require(!result.clean, "semantic drift reconciled cleanly");
    require_detail(require_finding(result, surface_error_code_t::baseline_mismatch,
                                   "kind_drift"),
                   "baseline and actual surface differ in fields: kind");
    require_detail(require_finding(result, surface_error_code_t::baseline_mismatch,
                                   "path_drift"),
                   "baseline and actual surface differ in fields: canonical_path");
    require_detail(require_finding(result, surface_error_code_t::baseline_mismatch,
                                   "active_drift"),
                   "baseline and actual surface differ in fields: is_active");
    require_detail(require_finding(result, surface_error_code_t::baseline_mismatch,
                                   "state_drift"),
                   "baseline and actual surface differ in fields: is_active,is_replaced,replaced_by");
    require_detail(require_finding(result, surface_error_code_t::baseline_mismatch,
                                   "replacement_drift"),
                   "baseline and actual surface differ in fields: replaced_by");
    require_detail(require_finding(result, surface_error_code_t::baseline_mismatch,
                                   "schema_drift"),
                   "baseline and actual surface differ in fields: schema_version");
    require_detail(require_finding(result, surface_error_code_t::security_regression_detected,
                                   "note_drift"),
                   "security-relevant baseline drift in fields: security_note");
    require_detail(require_finding(result, surface_error_code_t::security_regression_detected,
                                   "guard_kind_drift"),
                   "security-relevant baseline drift in fields: kind");
    require_no_finding(result, surface_error_code_t::baseline_mismatch, "note_drift");
    require_no_finding(result, surface_error_code_t::baseline_mismatch,
                       "guard_kind_drift");
}

void verify_lawful_migrations() {
    surface_reconciliation_t reconciliation;

    auto old_source = make_entry(
        "old_source", "surface/old_source.cpp",
        surface_entry_kind_t::source_file);
    reconciliation.register_baseline_entry(old_source);
    reconciliation.register_actual_entry(retired(old_source, "new_source"));
    reconciliation.register_actual_entry(make_entry(
        "new_source", "surface/new_source.cpp",
        surface_entry_kind_t::source_file));
    reconciliation.mark_dead_replaced_path("old_source", "new_source");

    auto stale = make_entry(
        "stale_handler", "surface/stale_handler.cpp",
        surface_entry_kind_t::handler_registration);
    reconciliation.register_baseline_entry(stale);
    auto inactive_stale = stale;
    inactive_stale.is_active = false;
    reconciliation.register_actual_entry(inactive_stale);
    reconciliation.mark_stale_registration("stale_handler");

    auto alias = make_entry(
        "old_alias", "surface/old_alias.cpp",
        surface_entry_kind_t::alias_mapping);
    reconciliation.register_baseline_entry(alias);
    reconciliation.register_actual_entry(retired(alias, "canonical_handler"));
    reconciliation.register_actual_entry(make_entry(
        "canonical_handler", "surface/canonical_handler.cpp",
        surface_entry_kind_t::handler_registration));
    reconciliation.mark_unsupported_alias("old_alias", "canonical_handler");

    auto schema_v8 = make_entry(
        "workspace_schema", "surface/schema_v8.cpp",
        surface_entry_kind_t::schema_writer, true, "v8");
    auto schema_v9 = schema_v8;
    schema_v9.schema_version = "v9";
    reconciliation.register_baseline_entry(schema_v8);
    reconciliation.register_actual_entry(schema_v9);
    reconciliation.mark_old_schema_v8_writer(
        "workspace_schema", "surface/schema_v8.cpp");

    const auto result = reconciliation.reconcile();
    require(result.clean && result.findings.empty(),
            "explicit source, stale, alias, or schema migration was rejected");
}

void verify_inactive_actual_proof_closure() {
    {
        surface_reconciliation_t reconciliation;

        auto actual_dead = retired(make_entry(
            "actual_dead", "surface/actual_dead.cpp",
            surface_entry_kind_t::source_file), "actual_dead_target");
        reconciliation.register_actual_entry(actual_dead);
        reconciliation.register_actual_entry(make_entry(
            "actual_dead_target", "surface/actual_dead_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            "actual_dead", "actual_dead_target");

        auto matched_dead = retired(make_entry(
            "matched_dead", "surface/matched_dead.cpp",
            surface_entry_kind_t::test_harness), "matched_dead_target");
        reconciliation.register_baseline_entry(matched_dead);
        reconciliation.register_actual_entry(matched_dead);
        reconciliation.register_actual_entry(make_entry(
            "matched_dead_target", "surface/matched_dead_target.cpp",
            surface_entry_kind_t::test_harness));
        reconciliation.mark_dead_replaced_path(
            "matched_dead", "matched_dead_target");

        auto actual_alias = retired(make_entry(
            "actual_alias", "surface/actual_alias.cpp",
            surface_entry_kind_t::alias_mapping), "actual_alias_target");
        reconciliation.register_actual_entry(actual_alias);
        reconciliation.register_actual_entry(make_entry(
            "actual_alias_target", "surface/actual_alias_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            "actual_alias", "actual_alias_target");

        auto matched_alias = retired(make_entry(
            "matched_alias", "surface/matched_alias.cpp",
            surface_entry_kind_t::alias_mapping), "matched_alias_target");
        reconciliation.register_baseline_entry(matched_alias);
        reconciliation.register_actual_entry(matched_alias);
        reconciliation.register_actual_entry(make_entry(
            "matched_alias_target", "surface/matched_alias_target.cpp",
            surface_entry_kind_t::tool_registration));
        reconciliation.mark_unsupported_alias(
            "matched_alias", "matched_alias_target");

        auto actual_stale = inactive(make_entry(
            "actual_stale", "surface/actual_stale.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.register_actual_entry(actual_stale);
        reconciliation.mark_stale_registration("actual_stale");

        auto matched_stale = inactive(make_entry(
            "matched_stale", "surface/matched_stale.cpp",
            surface_entry_kind_t::tool_registration));
        reconciliation.register_baseline_entry(matched_stale);
        reconciliation.register_actual_entry(matched_stale);
        reconciliation.mark_stale_registration("matched_stale");

        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(first.clean && first.findings.empty() &&
                    first.unexplained_removals == 0,
                "lawful inactive actual proofs did not reconcile cleanly");
        require(equal_results(first, second),
                "lawful inactive actual proof reconciliation is nondeterministic");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto entry = inactive(make_entry(
            "actual_unproved", "surface/actual_unproved.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.register_actual_entry(entry);
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        const auto& finding = require_finding(
            first, surface_error_code_t::unexplained_removal_detected,
            "actual_unproved");
        require_detail(
            finding,
            "inactive actual entry has no exact lawful retirement proof");
        require(finding.canonical_path == entry.canonical_path &&
                    finding.kind == entry.kind && finding.severity == 800 &&
                    first.unexplained_removals == 1 && !first.clean,
                "actual-only inactive proof failure lost exact evidence");
        require(equal_results(first, second),
                "actual-only inactive proof failure is nondeterministic");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto entry = inactive(make_entry(
            "matched_unproved", "surface/matched_unproved.cpp",
            surface_entry_kind_t::tool_registration));
        reconciliation.register_baseline_entry(entry);
        reconciliation.register_actual_entry(entry);
        const auto result = reconciliation.reconcile();
        require_detail(require_finding(
                           result,
                           surface_error_code_t::unexplained_removal_detected,
                           "matched_unproved"),
                       "inactive actual registration has no exact stale proof");
        require_no_finding(
            result, surface_error_code_t::baseline_mismatch,
            "matched_unproved");
        require(result.unexplained_removals == 1 && !result.clean,
                "matching inactive registration bypassed proof closure");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto entry = retired(make_entry(
            "replacement_without_marker",
            "surface/replacement_without_marker.cpp",
            surface_entry_kind_t::source_file), "unbound_replacement_target");
        reconciliation.register_actual_entry(entry);
        const auto result = reconciliation.reconcile();
        require_detail(require_finding(
                           result,
                           surface_error_code_t::unexplained_removal_detected,
                           "replacement_without_marker"),
                       "inactive actual entry replacement has no exact lawful proof; target=unbound_replacement_target");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(inactive(make_entry(
            "dead_marker_without_replacement",
            "surface/dead_marker_without_replacement.cpp",
            surface_entry_kind_t::source_file)));
        reconciliation.register_actual_entry(make_entry(
            "dead_marker_target", "surface/dead_marker_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            "dead_marker_without_replacement", "dead_marker_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "dead_marker_without_replacement",
            "dead_marker_target", "inactive_source_without_replacement_state");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "dead_marker_without_replacement");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(retired(make_entry(
            "stale_marker_with_replacement",
            "surface/stale_marker_with_replacement.cpp",
            surface_entry_kind_t::handler_registration),
            "stale_marker_target"));
        reconciliation.mark_stale_registration("stale_marker_with_replacement");
        const auto result = reconciliation.reconcile();
        require_contains(require_finding(
                             result, surface_error_code_t::invalid_surface_marker,
                             "stale_marker_with_replacement"),
                         "collection=stale_registrations, reason=stale_source_has_replacement");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "stale_marker_with_replacement");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto baseline = make_entry(
            "stale_source_identity", "surface/stale_source_baseline.cpp",
            surface_entry_kind_t::tool_registration);
        auto actual = inactive(baseline);
        actual.canonical_path = "surface/stale_source_actual.cpp";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.mark_stale_registration("stale_source_identity");
        const auto result = reconciliation.reconcile();
        require_contains(require_finding(
                             result, surface_error_code_t::invalid_surface_marker,
                             "stale_source_identity"),
                         "collection=stale_registrations, reason=conflicting_source_identity");
        require_finding(
            result, surface_error_code_t::baseline_mismatch,
            "stale_source_identity");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "stale_source_identity");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto source = retired(make_entry(
            "mismatched_replacement", "surface/mismatched_replacement.cpp",
            surface_entry_kind_t::source_file), "declared_target");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "declared_target", "surface/declared_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.register_actual_entry(make_entry(
            "marker_target", "surface/marker_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            "mismatched_replacement", "marker_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "mismatched_replacement",
            "marker_target", "source_replacement_target_mismatch");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "mismatched_replacement");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto source = retired(make_entry(
            "missing_replacement_target",
            "surface/missing_replacement_target.cpp",
            surface_entry_kind_t::source_file), "missing_target");
        reconciliation.register_actual_entry(source);
        reconciliation.mark_dead_replaced_path(
            "missing_replacement_target", "missing_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "missing_replacement_target",
            "missing_target", "missing_actual_target");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "missing_replacement_target");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto source = retired(make_entry(
            "inactive_replacement_source",
            "surface/inactive_replacement_source.cpp",
            surface_entry_kind_t::source_file), "inactive_replacement_target");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(inactive(make_entry(
            "inactive_replacement_target",
            "surface/inactive_replacement_target.cpp",
            surface_entry_kind_t::source_file)));
        reconciliation.mark_dead_replaced_path(
            "inactive_replacement_source", "inactive_replacement_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "inactive_replacement_source",
            "inactive_replacement_target", "inactive_actual_target");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "inactive_replacement_source");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "inactive_replacement_target");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto source = retired(make_entry(
            "duplicate_replacement_source",
            "surface/duplicate_replacement_source.cpp",
            surface_entry_kind_t::source_file), "duplicate_replacement_target");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "duplicate_replacement_target",
            "surface/duplicate_replacement_target_a.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.register_actual_entry(make_entry(
            "duplicate_replacement_target",
            "surface/duplicate_replacement_target_b.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            "duplicate_replacement_source", "duplicate_replacement_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "duplicate_replacement_source",
            "duplicate_replacement_target", "ambiguous_actual_target");
        require_finding(
            result, surface_error_code_t::duplicate_actual_identifier_detected,
            "duplicate_replacement_target");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "duplicate_replacement_source");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto source = retired(make_entry(
            "wrong_kind_replacement", "surface/wrong_kind_replacement.cpp",
            surface_entry_kind_t::source_file), "wrong_kind_target");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "wrong_kind_target", "surface/wrong_kind_target.cpp",
            surface_entry_kind_t::test_harness));
        reconciliation.mark_dead_replaced_path(
            "wrong_kind_replacement", "wrong_kind_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "wrong_kind_replacement",
            "wrong_kind_target", "incompatible_actual_target_kind");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "wrong_kind_replacement");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(inactive(make_entry(
            "self_proof", "surface/self_proof.cpp",
            surface_entry_kind_t::source_file)));
        reconciliation.mark_dead_replaced_path("self_proof", "self_proof");
        const auto result = reconciliation.reconcile();
        require_contains(require_finding(
                             result, surface_error_code_t::invalid_surface_marker,
                             "self_proof"),
                         "reason=self_replacement");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "self_proof");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(retired(make_entry(
            "inactive_cycle_a", "surface/inactive_cycle_a.cpp",
            surface_entry_kind_t::source_file), "inactive_cycle_b"));
        reconciliation.register_actual_entry(retired(make_entry(
            "inactive_cycle_b", "surface/inactive_cycle_b.cpp",
            surface_entry_kind_t::source_file), "inactive_cycle_a"));
        reconciliation.mark_dead_replaced_path(
            "inactive_cycle_a", "inactive_cycle_b");
        reconciliation.mark_dead_replaced_path(
            "inactive_cycle_b", "inactive_cycle_a");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "inactive_cycle_a",
            "inactive_cycle_b", "cyclic_replacement_graph");
        require_replacement_reason(
            result, "dead_replaced_paths", "inactive_cycle_b",
            "inactive_cycle_a", "cyclic_replacement_graph");
        require(finding_count(
                    result, surface_error_code_t::unexplained_removal_detected) == 2,
                "inactive replacement cycle did not fail every unproved entry");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(retired(make_entry(
            "conflicting_proofs", "surface/conflicting_proofs.cpp",
            surface_entry_kind_t::handler_registration),
            "conflicting_proofs_target"));
        reconciliation.register_actual_entry(make_entry(
            "conflicting_proofs_target",
            "surface/conflicting_proofs_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_dead_replaced_path(
            "conflicting_proofs", "conflicting_proofs_target");
        reconciliation.mark_stale_registration("conflicting_proofs");
        const auto result = reconciliation.reconcile();
        require_detail(require_finding(
                           result, surface_error_code_t::invalid_surface_marker,
                           "conflicting_proofs"),
                       "surface marker rejected; collection=inactive_entry_proofs, reason=conflicting_proof_markers");
        require(result.attempted_auxiliary_markers == 2 &&
                    result.rejected_auxiliary_markers == 2 &&
                    result.malformed_markers == 2,
                "conflicting inactive proofs lost per-marker accounting");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "conflicting_proofs");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto baseline = make_entry(
            "inexact_source", "surface/inexact_source_baseline.cpp",
            surface_entry_kind_t::source_file);
        auto actual = retired(baseline, "inexact_source_target");
        actual.canonical_path = "surface/inexact_source_actual.cpp";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.register_actual_entry(make_entry(
            "inexact_source_target", "surface/inexact_source_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            "inexact_source", "inexact_source_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "inexact_source",
            "inexact_source_target", "conflicting_source_identity");
        require_finding(
            result, surface_error_code_t::baseline_mismatch,
            "inexact_source");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "inexact_source");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto guard = make_entry(
            "inactive_protected_guard", "surface/inactive_protected_guard.cpp",
            surface_entry_kind_t::security_guard, false);
        reconciliation.register_actual_entry(guard);
        reconciliation.register_actual_entry(make_entry(
            "guard_replacement_target", "surface/guard_replacement_target.cpp",
            surface_entry_kind_t::security_guard));
        reconciliation.mark_dead_replaced_path(
            "inactive_protected_guard", "guard_replacement_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "inactive_protected_guard",
            "guard_replacement_target", "security_guard_replacement_forbidden");
        const auto& finding = require_finding(
            result, surface_error_code_t::security_regression_detected,
            "inactive_protected_guard");
        require(finding.canonical_path == guard.canonical_path &&
                    finding.kind == surface_entry_kind_t::security_guard &&
                    finding.severity == 900,
                "inactive security proof failure lost strongest exact evidence");
        require_no_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "inactive_protected_guard");
    }
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_findings = 2;
        surface_reconciliation_t reconciliation(limits);
        for (int index = 0; index < 6; ++index) {
            reconciliation.register_actual_entry(inactive(make_entry(
                "bounded_inactive_" + std::to_string(index),
                "surface/bounded_inactive_" + std::to_string(index) + ".cpp",
                surface_entry_kind_t::source_file)));
        }
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(first.finding_cap_exceeded && first.findings.size() == 2 &&
                    first.unexplained_removals == 6 && !first.clean,
                "inactive proof findings escaped the bounded finding contract");
        require_finding(
            first, surface_error_code_t::finding_cap_exceeded,
            "surface_findings");
        require(equal_results(first, second),
                "bounded inactive proof reconciliation is nondeterministic");
    }
}

void verify_schema_migration_predicate() {
    surface_reconciliation_t reconciliation;
    auto baseline = make_entry(
        "relocated_schema", "surface/relocated_schema_v8.cpp",
        surface_entry_kind_t::schema_writer, true, "v8");
    auto actual = baseline;
    actual.canonical_path = "surface/relocated_schema_v9.cpp";
    actual.schema_version = "v9";
    reconciliation.register_baseline_entry(baseline);
    reconciliation.register_actual_entry(actual);
    reconciliation.mark_old_schema_v8_writer(
        "relocated_schema", "surface/relocated_schema_v8.cpp");
    const auto result = reconciliation.reconcile();
    require_detail(require_finding(
                       result, surface_error_code_t::baseline_mismatch,
                       "relocated_schema"),
                   "baseline and actual surface differ in fields: canonical_path,schema_version");
    require(!result.clean,
            "simultaneous schema version and canonical-path drift was hidden");
}

void verify_stale_registration_proofs() {
    for (const auto kind : {surface_entry_kind_t::handler_registration,
                            surface_entry_kind_t::tool_registration}) {
        surface_reconciliation_t missing;
        auto baseline = make_entry(
            kind == surface_entry_kind_t::handler_registration
                ? "missing_handler" : "missing_tool",
            kind == surface_entry_kind_t::handler_registration
                ? "surface/missing_handler.cpp" : "surface/missing_tool.cpp",
            kind);
        missing.register_baseline_entry(baseline);
        missing.mark_stale_registration(baseline.identifier);
        const auto missing_result = missing.reconcile();
        require(!missing_result.clean && missing_result.unexplained_removals == 1,
                "baseline-only registration retirement reconciled cleanly");
        require_contains(require_finding(
                             missing_result,
                             surface_error_code_t::invalid_surface_marker,
                             baseline.identifier),
                         "collection=stale_registrations, reason=missing_actual_source_identity");
        require_finding(
            missing_result, surface_error_code_t::unexplained_removal_detected,
            baseline.identifier);

        surface_reconciliation_t inactive;
        inactive.register_baseline_entry(baseline);
        auto actual = baseline;
        actual.is_active = false;
        inactive.register_actual_entry(actual);
        inactive.mark_stale_registration(baseline.identifier);
        require(inactive.reconcile().clean,
                "lawful same-identity inactive registration retirement was rejected");

        surface_reconciliation_t active;
        active.register_baseline_entry(baseline);
        auto active_actual = baseline;
        active_actual.canonical_path =
            kind == surface_entry_kind_t::handler_registration
                ? "surface/actual_active_handler.cpp"
                : "surface/actual_active_tool.cpp";
        active.register_actual_entry(active_actual);
        active.mark_stale_registration(baseline.identifier);
        const auto result = active.reconcile();
        const auto& finding = require_finding(
            result, surface_error_code_t::stale_registration_detected,
            baseline.identifier);
        require(finding.kind == kind &&
                    finding.canonical_path == active_actual.canonical_path &&
                    finding.severity == 400,
                "active stale finding lost exact registration source evidence");
    }

    constexpr std::array<surface_entry_kind_t, 8> forbidden = {
        surface_entry_kind_t::source_file,
        surface_entry_kind_t::contract_registration,
        surface_entry_kind_t::schema_writer,
        surface_entry_kind_t::ast_path,
        surface_entry_kind_t::alias_mapping,
        surface_entry_kind_t::security_guard,
        surface_entry_kind_t::store_definition,
        surface_entry_kind_t::test_harness
    };
    for (std::size_t index = 0; index < forbidden.size(); ++index) {
        surface_reconciliation_t reconciliation;
        const auto identifier = "forbidden_stale_" + std::to_string(index);
        auto baseline = make_entry(
            identifier, "surface/forbidden_" + std::to_string(index) + ".cpp",
            forbidden[index]);
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(inactive(baseline));
        reconciliation.mark_stale_registration(identifier);
        const auto result = reconciliation.reconcile();
        const auto reason = forbidden[index] == surface_entry_kind_t::security_guard
            ? "security_guard_stale_forbidden"
            : "stale_marker_on_incompatible_source_kind";
        require_detail(require_finding(
                           result, surface_error_code_t::invalid_surface_marker,
                           identifier),
                       "surface marker rejected; collection=stale_registrations, reason=" +
                           std::string(reason));
        require(!result.clean, "forbidden stale marker reconciled cleanly");
        if (forbidden[index] == surface_entry_kind_t::security_guard) {
            require_finding(result, surface_error_code_t::security_regression_detected,
                            identifier);
        } else {
            require(result.unexplained_removals == 1,
                    "forbidden stale marker hid an unexplained removal");
            require_finding(result, surface_error_code_t::unexplained_removal_detected,
                            identifier);
        }
    }

    {
        surface_reconciliation_t reconciliation;
        reconciliation.mark_stale_registration("missing_stale_identity");
        const auto result = reconciliation.reconcile();
        require_detail(require_finding(
                           result, surface_error_code_t::invalid_surface_marker,
                           "missing_stale_identity"),
                       "surface marker rejected; collection=stale_registrations, reason=missing_actual_source_identity");
        require(!result.clean, "missing stale source identity reconciled cleanly");
    }
    {
        surface_reconciliation_t reconciliation;
        auto entry = make_entry(
            "ambiguous_stale", "surface/ambiguous_a.cpp",
            surface_entry_kind_t::handler_registration);
        reconciliation.register_baseline_entry(entry);
        entry.canonical_path = "surface/ambiguous_b.cpp";
        reconciliation.register_baseline_entry(entry);
        reconciliation.mark_stale_registration("ambiguous_stale");
        const auto result = reconciliation.reconcile();
        require_detail(require_finding(
                           result, surface_error_code_t::invalid_surface_marker,
                           "ambiguous_stale"),
                       "surface marker rejected; collection=stale_registrations, reason=ambiguous_source_identity");
        require_finding(result,
                        surface_error_code_t::duplicate_baseline_identifier_detected,
                        "ambiguous_stale");
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "conflicting_stale", "surface/conflicting_baseline.cpp",
            surface_entry_kind_t::handler_registration);
        auto actual = make_entry(
            "conflicting_stale", "surface/conflicting_actual.cpp",
            surface_entry_kind_t::tool_registration);
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.mark_stale_registration("conflicting_stale");
        const auto result = reconciliation.reconcile();
        require_detail(require_finding(
                           result, surface_error_code_t::invalid_surface_marker,
                           "conflicting_stale"),
                       "surface marker rejected; collection=stale_registrations, reason=conflicting_source_kind");
        require_finding(result, surface_error_code_t::baseline_mismatch,
                        "conflicting_stale");
    }
}

void require_replacement_reason(
    const surface_reconciliation_result_t& result,
    std::string_view collection, std::string_view identifier,
    std::string_view target, std::string_view reason) {
    const auto expected =
        "replacement marker rejected; collection=" + std::string(collection) +
        ", target=" + std::string(target) + ", reason=" + std::string(reason);
    const auto& finding = require_finding(
        result, surface_error_code_t::invalid_surface_marker, identifier);
    require_detail(finding, expected);
    require(finding.kind == surface_entry_kind_t::contract_registration &&
                finding.severity == 950,
            "replacement proof failure metadata is incorrect");
}

void require_marker_reason(
    const surface_reconciliation_result_t& result,
    std::string_view collection, std::string_view identifier,
    std::string_view reason) {
    const auto expected =
        "surface marker rejected; collection=" + std::string(collection) +
        ", reason=" + std::string(reason);
    const auto& finding = require_finding(
        result, surface_error_code_t::invalid_surface_marker, identifier);
    require_detail(finding, expected);
    require(finding.kind == surface_entry_kind_t::contract_registration &&
                finding.severity == 950,
            "surface proof failure metadata is incorrect");
}

void verify_replacement_target_graph() {
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "orphan_target", "surface/orphan_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path("orphan_source", "orphan_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(result, "dead_replaced_paths", "orphan_source",
                                   "orphan_target", "missing_actual_source_identity");
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = make_entry(
            "ambiguous_source", "surface/ambiguous_source_a.cpp",
            surface_entry_kind_t::source_file);
        reconciliation.register_baseline_entry(source);
        source.canonical_path = "surface/ambiguous_source_b.cpp";
        reconciliation.register_baseline_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "ambiguous_target", "surface/ambiguous_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            "ambiguous_source", "ambiguous_target");
        require_replacement_reason(
            reconciliation.reconcile(), "dead_replaced_paths", "ambiguous_source",
            "ambiguous_target", "ambiguous_source_identity");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_baseline_entry(make_entry(
            "conflicting_source", "surface/conflicting_source.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.register_actual_entry(make_entry(
            "conflicting_source", "surface/conflicting_source_test.cpp",
            surface_entry_kind_t::test_harness));
        reconciliation.register_actual_entry(make_entry(
            "conflicting_target", "surface/conflicting_target.cpp",
            surface_entry_kind_t::test_harness));
        reconciliation.mark_dead_replaced_path(
            "conflicting_source", "conflicting_target");
        require_replacement_reason(
            reconciliation.reconcile(), "dead_replaced_paths", "conflicting_source",
            "conflicting_target", "conflicting_source_kind");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "wrong_alias_source", "surface/wrong_alias_source.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.register_actual_entry(make_entry(
            "alias_target", "surface/alias_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias("wrong_alias_source", "alias_target");
        require_replacement_reason(
            reconciliation.reconcile(), "unsupported_aliases", "wrong_alias_source",
            "alias_target", "alias_marker_on_incompatible_source_kind");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "alias_as_dead", "surface/alias_as_dead.cpp",
            surface_entry_kind_t::alias_mapping));
        reconciliation.register_actual_entry(make_entry(
            "alias_dead_target", "surface/alias_dead_target.cpp",
            surface_entry_kind_t::alias_mapping));
        reconciliation.mark_dead_replaced_path("alias_as_dead", "alias_dead_target");
        require_replacement_reason(
            reconciliation.reconcile(), "dead_replaced_paths", "alias_as_dead",
            "alias_dead_target", "dead_path_marker_on_alias_source");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "guard_source", "surface/guard_source.cpp",
            surface_entry_kind_t::security_guard));
        reconciliation.register_actual_entry(make_entry(
            "guard_target", "surface/guard_target.cpp",
            surface_entry_kind_t::security_guard));
        reconciliation.mark_dead_replaced_path("guard_source", "guard_target");
        require_replacement_reason(
            reconciliation.reconcile(), "dead_replaced_paths", "guard_source",
            "guard_target", "security_guard_replacement_forbidden");
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = make_entry(
            "missing_target_source", "surface/missing_target.cpp",
            surface_entry_kind_t::source_file);
        reconciliation.register_baseline_entry(source);
        reconciliation.register_actual_entry(retired(source, "absent_target"));
        reconciliation.mark_dead_replaced_path(
            "missing_target_source", "absent_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", "missing_target_source",
            "absent_target", "missing_actual_target");
        require(result.unexplained_removals == 1,
                "invalid dead replacement hid an unexplained removal");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(retired(make_entry(
            "ambiguous_target_source", "surface/ambiguous_target_source.cpp",
            surface_entry_kind_t::source_file), "duplicated_target"));
        reconciliation.register_actual_entry(make_entry(
            "duplicated_target", "surface/duplicated_target_a.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.register_actual_entry(make_entry(
            "duplicated_target", "surface/duplicated_target_b.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            "ambiguous_target_source", "duplicated_target");
        require_replacement_reason(
            reconciliation.reconcile(), "dead_replaced_paths",
            "ambiguous_target_source", "duplicated_target",
            "ambiguous_actual_target");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(retired(make_entry(
            "inactive_target_source", "surface/inactive_target_source.cpp",
            surface_entry_kind_t::source_file), "inactive_target"));
        reconciliation.register_actual_entry(make_entry(
            "inactive_target", "surface/inactive_target.cpp",
            surface_entry_kind_t::source_file, false));
        reconciliation.mark_dead_replaced_path(
            "inactive_target_source", "inactive_target");
        require_replacement_reason(
            reconciliation.reconcile(), "dead_replaced_paths",
            "inactive_target_source", "inactive_target", "inactive_actual_target");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(retired(make_entry(
            "wrong_target_source", "surface/wrong_target_source.cpp",
            surface_entry_kind_t::source_file), "wrong_target"));
        reconciliation.register_actual_entry(make_entry(
            "wrong_target", "surface/wrong_target.cpp",
            surface_entry_kind_t::test_harness));
        reconciliation.mark_dead_replaced_path(
            "wrong_target_source", "wrong_target");
        require_replacement_reason(
            reconciliation.reconcile(), "dead_replaced_paths",
            "wrong_target_source", "wrong_target",
            "incompatible_actual_target_kind");
    }
    {
        surface_reconciliation_t reconciliation;
        for (const auto* identifier : {"cycle_a", "cycle_b", "cycle_predecessor"}) {
            reconciliation.register_actual_entry(make_entry(
                identifier, "surface/" + std::string(identifier) + ".cpp",
                surface_entry_kind_t::source_file));
        }
        reconciliation.mark_dead_replaced_path("cycle_a", "cycle_b");
        reconciliation.mark_dead_replaced_path("cycle_b", "cycle_a");
        reconciliation.mark_dead_replaced_path("cycle_predecessor", "cycle_a");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(result, "dead_replaced_paths", "cycle_a",
                                   "cycle_b", "cyclic_replacement_graph");
        require_replacement_reason(result, "dead_replaced_paths", "cycle_b",
                                   "cycle_a", "cyclic_replacement_graph");
        require_replacement_reason(result, "dead_replaced_paths", "cycle_predecessor",
                                   "cycle_a", "cyclic_replacement_graph");
    }
}

void verify_baseline_only_retirement_rejection() {
    {
        surface_reconciliation_t reconciliation;
        const auto baseline = make_entry(
            "baseline_only_dead", "surface/baseline_only_dead.cpp",
            surface_entry_kind_t::source_file);
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(make_entry(
            "baseline_only_dead_target", "surface/baseline_only_dead_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_dead_replaced_path(
            baseline.identifier, "baseline_only_dead_target");
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require_replacement_reason(
            first, "dead_replaced_paths", baseline.identifier,
            "baseline_only_dead_target", "missing_actual_source_identity");
        require_finding(
            first, surface_error_code_t::unexplained_removal_detected,
            baseline.identifier);
        require(first.unexplained_removals == 1 && equal_results(first, second),
                "baseline-only dead proof was accepted or nondeterministic");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto baseline = make_entry(
            "baseline_only_alias", "surface/baseline_only_alias.cpp",
            surface_entry_kind_t::alias_mapping);
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(make_entry(
            "baseline_only_alias_target", "surface/baseline_only_alias_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            baseline.identifier, "baseline_only_alias_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "unsupported_aliases", baseline.identifier,
            "baseline_only_alias_target", "missing_actual_source_identity");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            baseline.identifier);
        require(result.unexplained_removals == 1,
                "baseline-only alias proof hid a removed public entry");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto baseline = make_entry(
            "baseline_only_stale", "surface/baseline_only_stale.cpp",
            surface_entry_kind_t::tool_registration);
        reconciliation.register_baseline_entry(baseline);
        reconciliation.mark_stale_registration(baseline.identifier);
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "stale_registrations", baseline.identifier,
            "missing_actual_source_identity");
        require_finding(
            result, surface_error_code_t::stale_registration_detected,
            baseline.identifier);
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            baseline.identifier);
        require(result.unexplained_removals == 1,
                "baseline-only stale proof hid a removed registration");
    }
}

void verify_schema_identity_and_proof_matrix() {
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "schema_new_actual", "surface/schema_new_actual.cpp",
            surface_entry_kind_t::schema_writer, true, "v9"));
        require(reconciliation.reconcile().clean,
                "new actual-only schema writer with explicit identity was rejected");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto schema = make_entry(
            "schema_matching", "surface/schema_matching.cpp",
            surface_entry_kind_t::schema_writer, true, "v9");
        reconciliation.register_baseline_entry(schema);
        reconciliation.register_actual_entry(schema);
        require(reconciliation.reconcile().clean,
                "matching schema identities did not reconcile cleanly");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "schema_actual_only", "surface/schema_actual_only.cpp",
            surface_entry_kind_t::schema_writer, true, "v9"));
        reconciliation.mark_old_schema_v8_writer(
            "schema_actual_only", "surface/schema_actual_only.cpp");
        require_marker_reason(
            reconciliation.reconcile(), "old_schema_v8_writers",
            "schema_actual_only", "missing_baseline_schema_writer");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_baseline_entry(make_entry(
            "schema_baseline_only", "surface/schema_baseline_only.cpp",
            surface_entry_kind_t::schema_writer, true, "v8"));
        reconciliation.mark_old_schema_v8_writer(
            "schema_baseline_only", "surface/schema_baseline_only.cpp");
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "old_schema_v8_writers", "schema_baseline_only",
            "missing_actual_schema_writer");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "schema_baseline_only");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.mark_old_schema_v8_writer(
            "schema_missing", "surface/schema_missing.cpp");
        require_marker_reason(
            reconciliation.reconcile(), "old_schema_v8_writers",
            "schema_missing", "missing_baseline_schema_writer");
    }
    {
        surface_reconciliation_t reconciliation;
        const auto baseline = make_entry(
            "schema_wrong_kind", "surface/schema_wrong_kind.cpp",
            surface_entry_kind_t::source_file);
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(baseline);
        reconciliation.mark_old_schema_v8_writer(
            baseline.identifier, baseline.canonical_path);
        require_marker_reason(
            reconciliation.reconcile(), "old_schema_v8_writers",
            baseline.identifier, "schema_marker_on_incompatible_source_kind");
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "schema_wrong_old", "surface/schema_wrong_old.cpp",
            surface_entry_kind_t::schema_writer, true, "v7");
        auto actual = baseline;
        actual.schema_version = "v9";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.mark_old_schema_v8_writer(
            baseline.identifier, baseline.canonical_path);
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "old_schema_v8_writers", baseline.identifier,
            "wrong_old_schema_version");
        require_finding(result, surface_error_code_t::baseline_mismatch,
                        baseline.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "schema_wrong_current", "surface/schema_wrong_current.cpp",
            surface_entry_kind_t::schema_writer, true, "v8");
        auto actual = baseline;
        actual.schema_version = "v10";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.mark_old_schema_v8_writer(
            baseline.identifier, baseline.canonical_path);
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "old_schema_v8_writers", baseline.identifier,
            "wrong_current_schema_version");
        require_finding(result, surface_error_code_t::baseline_mismatch,
                        baseline.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "schema_wrong_path", "surface/schema_wrong_path.cpp",
            surface_entry_kind_t::schema_writer, true, "v8");
        auto actual = baseline;
        actual.schema_version = "v9";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.mark_old_schema_v8_writer(
            baseline.identifier, "surface/schema_unrelated.cpp");
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "old_schema_v8_writers", baseline.identifier,
            "schema_marker_path_mismatch");
        require_finding(result, surface_error_code_t::baseline_mismatch,
                        baseline.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "schema_still_v8", "surface/schema_still_v8.cpp",
            surface_entry_kind_t::schema_writer, true, "v8");
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(baseline);
        reconciliation.mark_old_schema_v8_writer(
            baseline.identifier, baseline.canonical_path);
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "old_schema_v8_writers", baseline.identifier,
            "wrong_current_schema_version");
        require_finding(
            result, surface_error_code_t::old_schema_v8_writer_detected,
            baseline.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "schema_inactive_current", "surface/schema_inactive_current.cpp",
            surface_entry_kind_t::schema_writer, true, "v8");
        auto actual = inactive(baseline);
        actual.schema_version = "v9";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.mark_old_schema_v8_writer(
            baseline.identifier, baseline.canonical_path);
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "old_schema_v8_writers", baseline.identifier,
            "schema_writer_not_active_canonical_state");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            baseline.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto invalid_baseline = make_entry(
            "schema_empty_baseline", "surface/schema_empty_baseline.cpp",
            surface_entry_kind_t::schema_writer, true, "v8");
        invalid_baseline.schema_version.clear();
        auto invalid_actual = make_entry(
            "schema_empty_actual", "surface/schema_empty_actual.cpp",
            surface_entry_kind_t::schema_writer, false, "v9");
        invalid_actual.schema_version.clear();
        reconciliation.register_baseline_entry(invalid_baseline);
        reconciliation.register_actual_entry(invalid_actual);
        const auto result = reconciliation.reconcile();
        require(result.malformed_entries == 2 &&
                    result.rejected_baseline_entries == 1 &&
                    result.rejected_actual_entries == 1,
                "empty active or inactive schema identity was accepted");
        require_finding(
            result, surface_error_code_t::invalid_surface_entry,
            "schema_empty_baseline");
    }
    {
        surface_reconciliation_t reconciliation;
        auto unknown_baseline = make_entry(
            "schema_unknown_baseline", "surface/schema_unknown_baseline.cpp",
            surface_entry_kind_t::schema_writer, true, "UNKNOWN");
        auto unknown_actual = make_entry(
            "schema_unknown_actual", "surface/schema_unknown_actual.cpp",
            surface_entry_kind_t::schema_writer, false, "unspecified");
        reconciliation.register_baseline_entry(unknown_baseline);
        reconciliation.register_actual_entry(unknown_actual);
        const auto result = reconciliation.reconcile();
        require(result.malformed_entries == 2 &&
                    result.rejected_baseline_entries == 1 &&
                    result.rejected_actual_entries == 1,
                "unknown schema identity was accepted");
        const auto& finding = require_finding(
            result, surface_error_code_t::invalid_surface_entry,
            unknown_baseline.identifier);
        require_contains(finding, "reason=unknown_schema_version");
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "schema_dead_lawful", "surface/schema_dead_lawful.cpp",
            surface_entry_kind_t::schema_writer, true, "v9");
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(retired(
            baseline, "schema_dead_lawful_target"));
        reconciliation.register_actual_entry(make_entry(
            "schema_dead_lawful_target",
            "surface/schema_dead_lawful_target.cpp",
            surface_entry_kind_t::schema_writer, true, "v9"));
        reconciliation.mark_dead_replaced_path(
            baseline.identifier, "schema_dead_lawful_target");
        const auto result = reconciliation.reconcile();
        require(result.clean && result.findings.empty(),
                "schema-writer replacement with bound identity was rejected");
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = make_entry(
            "schema_target_mismatch", "surface/schema_target_mismatch.cpp",
            surface_entry_kind_t::schema_writer, true, "v9");
        reconciliation.register_baseline_entry(source);
        reconciliation.register_actual_entry(retired(
            source, "schema_target_mismatch_target"));
        reconciliation.register_actual_entry(make_entry(
            "schema_target_mismatch_target",
            "surface/schema_target_mismatch_target.cpp",
            surface_entry_kind_t::schema_writer, true, "v10"));
        reconciliation.mark_dead_replaced_path(
            source.identifier, "schema_target_mismatch_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", source.identifier,
            "schema_target_mismatch_target",
            "replacement_target_schema_mismatch");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            source.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = make_entry(
            "schema_target_empty", "surface/schema_target_empty.cpp",
            surface_entry_kind_t::schema_writer, true, "v9");
        reconciliation.register_baseline_entry(source);
        reconciliation.register_actual_entry(retired(
            source, "schema_target_empty_value"));
        auto target = make_entry(
            "schema_target_empty_value", "surface/schema_target_empty_value.cpp",
            surface_entry_kind_t::schema_writer, true, "v9");
        target.schema_version.clear();
        reconciliation.register_actual_entry(target);
        reconciliation.mark_dead_replaced_path(
            source.identifier, target.identifier);
        const auto result = reconciliation.reconcile();
        require_finding(
            result, surface_error_code_t::invalid_surface_entry,
            target.identifier);
        require_replacement_reason(
            result, "dead_replaced_paths", source.identifier, target.identifier,
            "missing_actual_target");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            source.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "schema_source_drift", "surface/schema_source_drift.cpp",
            surface_entry_kind_t::schema_writer, true, "v8");
        auto actual = retired(baseline, "schema_source_drift_target");
        actual.schema_version = "v9";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.register_actual_entry(make_entry(
            "schema_source_drift_target",
            "surface/schema_source_drift_target.cpp",
            surface_entry_kind_t::schema_writer, true, "v9"));
        reconciliation.mark_dead_replaced_path(
            baseline.identifier, "schema_source_drift_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "dead_replaced_paths", baseline.identifier,
            "schema_source_drift_target", "conflicting_source_schema");
        require_finding(result, surface_error_code_t::baseline_mismatch,
                        baseline.identifier);
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            baseline.identifier);
    }
}

void verify_alias_proof_matrix() {
    {
        surface_reconciliation_t reconciliation;
        auto source = inactive(make_entry(
            "alias_without_state", "surface/alias_without_state.cpp",
            surface_entry_kind_t::alias_mapping));
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "alias_without_state_target", "surface/alias_without_state_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            source.identifier, "alias_without_state_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "unsupported_aliases", source.identifier,
            "alias_without_state_target",
            "inactive_source_without_replacement_state");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            source.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = retired(make_entry(
            "alias_target_drift", "surface/alias_target_drift.cpp",
            surface_entry_kind_t::alias_mapping), "alias_declared_target");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "alias_declared_target", "surface/alias_declared_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.register_actual_entry(make_entry(
            "alias_marker_target", "surface/alias_marker_target.cpp",
            surface_entry_kind_t::tool_registration));
        reconciliation.mark_unsupported_alias(
            source.identifier, "alias_marker_target");
        require_replacement_reason(
            reconciliation.reconcile(), "unsupported_aliases", source.identifier,
            "alias_marker_target", "source_replacement_target_mismatch");
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = retired(make_entry(
            "alias_missing_target", "surface/alias_missing_target.cpp",
            surface_entry_kind_t::alias_mapping), "alias_missing_target_value");
        reconciliation.register_actual_entry(source);
        reconciliation.mark_unsupported_alias(
            source.identifier, "alias_missing_target_value");
        require_replacement_reason(
            reconciliation.reconcile(), "unsupported_aliases", source.identifier,
            "alias_missing_target_value", "missing_actual_target");
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = retired(make_entry(
            "alias_duplicate_target", "surface/alias_duplicate_target.cpp",
            surface_entry_kind_t::alias_mapping), "alias_duplicate_target_value");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "alias_duplicate_target_value", "surface/alias_duplicate_target_a.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.register_actual_entry(make_entry(
            "alias_duplicate_target_value", "surface/alias_duplicate_target_b.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            source.identifier, "alias_duplicate_target_value");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "unsupported_aliases", source.identifier,
            "alias_duplicate_target_value", "ambiguous_actual_target");
        require_finding(
            result, surface_error_code_t::duplicate_actual_identifier_detected,
            "alias_duplicate_target_value");
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = retired(make_entry(
            "alias_inactive_target", "surface/alias_inactive_target.cpp",
            surface_entry_kind_t::alias_mapping), "alias_inactive_target_value");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(inactive(make_entry(
            "alias_inactive_target_value", "surface/alias_inactive_target_value.cpp",
            surface_entry_kind_t::tool_registration)));
        reconciliation.mark_unsupported_alias(
            source.identifier, "alias_inactive_target_value");
        require_replacement_reason(
            reconciliation.reconcile(), "unsupported_aliases", source.identifier,
            "alias_inactive_target_value", "inactive_actual_target");
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = retired(make_entry(
            "alias_wrong_kind_target", "surface/alias_wrong_kind_target.cpp",
            surface_entry_kind_t::alias_mapping), "alias_wrong_kind_target_value");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "alias_wrong_kind_target_value",
            "surface/alias_wrong_kind_target_value.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.mark_unsupported_alias(
            source.identifier, "alias_wrong_kind_target_value");
        require_replacement_reason(
            reconciliation.reconcile(), "unsupported_aliases", source.identifier,
            "alias_wrong_kind_target_value",
            "incompatible_actual_target_kind");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(inactive(make_entry(
            "alias_self", "surface/alias_self.cpp",
            surface_entry_kind_t::alias_mapping)));
        reconciliation.mark_unsupported_alias("alias_self", "alias_self");
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "unsupported_aliases", "alias_self", "self_replacement");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "alias_self");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(retired(make_entry(
            "alias_cycle_a", "surface/alias_cycle_a.cpp",
            surface_entry_kind_t::alias_mapping), "alias_cycle_b"));
        reconciliation.register_actual_entry(retired(make_entry(
            "alias_cycle_b", "surface/alias_cycle_b.cpp",
            surface_entry_kind_t::alias_mapping), "alias_cycle_a"));
        reconciliation.register_actual_entry(retired(make_entry(
            "alias_cycle_predecessor", "surface/alias_cycle_predecessor.cpp",
            surface_entry_kind_t::alias_mapping), "alias_cycle_a"));
        reconciliation.mark_unsupported_alias("alias_cycle_a", "alias_cycle_b");
        reconciliation.mark_unsupported_alias("alias_cycle_b", "alias_cycle_a");
        reconciliation.mark_unsupported_alias(
            "alias_cycle_predecessor", "alias_cycle_a");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "unsupported_aliases", "alias_cycle_a", "alias_cycle_b",
            "cyclic_replacement_graph");
        require_replacement_reason(
            result, "unsupported_aliases", "alias_cycle_b", "alias_cycle_a",
            "cyclic_replacement_graph");
        require_replacement_reason(
            result, "unsupported_aliases", "alias_cycle_predecessor",
            "alias_cycle_a", "cyclic_replacement_graph");
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "alias_path_drift", "surface/alias_path_baseline.cpp",
            surface_entry_kind_t::alias_mapping);
        auto actual = retired(baseline, "alias_path_target");
        actual.canonical_path = "surface/alias_path_actual.cpp";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.register_actual_entry(make_entry(
            "alias_path_target", "surface/alias_path_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            baseline.identifier, "alias_path_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "unsupported_aliases", baseline.identifier,
            "alias_path_target", "conflicting_source_identity");
        require_finding(result, surface_error_code_t::baseline_mismatch,
                        baseline.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "alias_kind_drift", "surface/alias_kind_drift.cpp",
            surface_entry_kind_t::alias_mapping);
        auto actual = retired(make_entry(
            baseline.identifier, baseline.canonical_path,
            surface_entry_kind_t::handler_registration), "alias_kind_target");
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.register_actual_entry(make_entry(
            "alias_kind_target", "surface/alias_kind_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            baseline.identifier, "alias_kind_target");
        const auto result = reconciliation.reconcile();
        require_replacement_reason(
            result, "unsupported_aliases", baseline.identifier,
            "alias_kind_target", "conflicting_source_kind");
        require_finding(result, surface_error_code_t::baseline_mismatch,
                        baseline.identifier);
    }
    {
        surface_reconciliation_t reconciliation;
        auto source = retired(make_entry(
            "alias_actual_lawful", "surface/alias_actual_lawful.cpp",
            surface_entry_kind_t::alias_mapping), "alias_actual_lawful_target");
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "alias_actual_lawful_target",
            "surface/alias_actual_lawful_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            source.identifier, "alias_actual_lawful_target");
        require(reconciliation.reconcile().clean,
                "actual-only exact alias tombstone was rejected");
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "alias_matching_lawful", "surface/alias_matching_lawful.cpp",
            surface_entry_kind_t::alias_mapping);
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(retired(
            baseline, "alias_matching_lawful_target"));
        reconciliation.register_actual_entry(make_entry(
            "alias_matching_lawful_target",
            "surface/alias_matching_lawful_target.cpp",
            surface_entry_kind_t::tool_registration));
        reconciliation.mark_unsupported_alias(
            baseline.identifier, "alias_matching_lawful_target");
        require(reconciliation.reconcile().clean,
                "matching exact alias tombstone was rejected");
    }
}

void verify_cross_proof_exclusion_matrix() {
    constexpr std::array<std::uint8_t, 11> masks = {
        0x3, 0x5, 0x9, 0x6, 0xa, 0xc,
        0x7, 0xb, 0xd, 0xe, 0xf
    };
    for (const bool include_baseline : {false, true}) {
        for (std::size_t index = 0; index < masks.size(); ++index) {
            const auto identifier =
                "cross_proof_" + std::to_string(include_baseline ? 1 : 0) +
                "_" + std::to_string(index);
            const auto target = identifier + "_target";
            std::uint64_t proof_count = 0;
            for (const auto bit : {0x1U, 0x2U, 0x4U, 0x8U}) {
                if ((masks[index] & bit) != 0)
                    ++proof_count;
            }
            const auto exercise = [&](bool reverse) {
                surface_reconciliation_t reconciliation;
                auto source = retired(make_entry(
                    identifier, "surface/" + identifier + ".cpp",
                    surface_entry_kind_t::alias_mapping), target);
                if (include_baseline)
                    reconciliation.register_baseline_entry(source);
                reconciliation.register_actual_entry(source);
                reconciliation.register_actual_entry(make_entry(
                    target, "surface/" + target + ".cpp",
                    surface_entry_kind_t::handler_registration));
                constexpr std::array<std::uint8_t, 4> bits = {
                    0x1U, 0x2U, 0x4U, 0x8U
                };
                const auto add = [&](std::uint8_t bit) {
                    if ((masks[index] & bit) == 0)
                        return;
                    if (bit == 0x1U) {
                        reconciliation.mark_dead_replaced_path(
                            identifier, target);
                    } else if (bit == 0x2U) {
                        reconciliation.mark_unsupported_alias(
                            identifier, target);
                    } else if (bit == 0x4U) {
                        reconciliation.mark_stale_registration(identifier);
                    } else {
                        reconciliation.mark_old_schema_v8_writer(
                            identifier, source.canonical_path);
                    }
                };
                if (reverse) {
                    for (auto bit = bits.rbegin(); bit != bits.rend(); ++bit)
                        add(*bit);
                } else {
                    for (const auto bit : bits)
                        add(bit);
                }
                const auto first = reconciliation.reconcile();
                const auto second = reconciliation.reconcile();
                require(equal_results(first, second),
                        "cross-proof repeated reconciliation is nondeterministic");
                return first;
            };
            const auto first = exercise(false);
            const auto reverse = exercise(true);
            require_marker_reason(
                first, "inactive_entry_proofs", identifier,
                "conflicting_proof_markers");
            require(first.rejected_auxiliary_markers == proof_count &&
                        first.malformed_markers == proof_count &&
                        first.unexplained_removals == 1,
                    "cross-proof conflict lost exact marker accounting");
            require_finding(
                first, surface_error_code_t::unexplained_removal_detected,
                identifier);
            require(equal_results(first, reverse),
                    "cross-proof exclusion depends on marker order");
        }
    }
    {
        surface_reconciliation_t reconciliation;
        const auto guard = make_entry(
            "cross_proof_security", "surface/cross_proof_security.cpp",
            surface_entry_kind_t::security_guard);
        reconciliation.register_baseline_entry(guard);
        reconciliation.mark_dead_replaced_path(
            guard.identifier, "cross_proof_security_target");
        reconciliation.mark_old_schema_v8_writer(
            guard.identifier, guard.canonical_path);
        reconciliation.mark_security_regression(
            guard.identifier, "explicit lower-priority marker");
        const auto result = reconciliation.reconcile();
        require_marker_reason(
            result, "inactive_entry_proofs", guard.identifier,
            "conflicting_proof_markers");
        const auto& security = require_finding(
            result, surface_error_code_t::security_regression_detected,
            guard.identifier);
        require(security.severity == 1000 &&
                    security.canonical_path == guard.canonical_path,
                "cross-proof finding suppressed strongest security evidence");
        require_detail(
            security,
            "baseline security guard is missing or inactive in actual surface");
    }
}

void verify_same_key_conflict_invalidation() {
    for (const bool include_baseline : {false, true}) {
        const auto exercise_dead = [include_baseline](bool reverse) {
            surface_reconciliation_t reconciliation;
            const auto identifier = std::string("same_key_dead_") +
                (include_baseline ? "both" : "actual");
            const auto correct_target = identifier + "_correct";
            const auto wrong_target = identifier + "_wrong";
            const auto source = make_entry(
                identifier, "surface/" + identifier + ".cpp",
                surface_entry_kind_t::source_file);
            if (include_baseline)
                reconciliation.register_baseline_entry(source);
            reconciliation.register_actual_entry(retired(source, correct_target));
            reconciliation.register_actual_entry(make_entry(
                correct_target, "surface/" + correct_target + ".cpp",
                surface_entry_kind_t::source_file));
            reconciliation.register_actual_entry(make_entry(
                wrong_target, "surface/" + wrong_target + ".cpp",
                surface_entry_kind_t::source_file));
            const auto add = [&](std::string_view target) {
                reconciliation.mark_dead_replaced_path(identifier, target);
            };
            if (reverse) {
                add(wrong_target);
                add(correct_target);
                add(wrong_target);
                add(correct_target);
            } else {
                add(correct_target);
                add(wrong_target);
                add(correct_target);
                add(wrong_target);
            }
            return reconciliation.reconcile();
        };
        const auto forward = exercise_dead(false);
        const auto reverse = exercise_dead(true);
        require_detail(
            require_finding(
                forward, surface_error_code_t::invalid_surface_marker,
                include_baseline
                    ? "same_key_dead_both" : "same_key_dead_actual"),
            "surface marker rejected; collection=dead_replaced_paths, reason=conflicting_duplicate_marker, malformed=1");
        require(forward.attempted_auxiliary_markers == 4 &&
                    forward.rejected_auxiliary_markers == 1 &&
                    forward.malformed_markers == 1 &&
                    forward.unexplained_removals == 1,
                "same-key dead proof conflict accounting is incorrect");
        require_finding(
            forward, surface_error_code_t::unexplained_removal_detected,
            include_baseline ? "same_key_dead_both" : "same_key_dead_actual");
        if (include_baseline) {
            require_finding(
                forward, surface_error_code_t::baseline_mismatch,
                "same_key_dead_both");
        }
        require(equal_results(forward, reverse),
                "same-key dead conflict depends on marker order");

        const auto exercise_alias = [include_baseline](bool reverse_order) {
            surface_reconciliation_t reconciliation;
            const auto identifier = std::string("same_key_alias_") +
                (include_baseline ? "both" : "actual");
            const auto correct_target = identifier + "_correct";
            const auto wrong_target = identifier + "_wrong";
            const auto source = make_entry(
                identifier, "surface/" + identifier + ".cpp",
                surface_entry_kind_t::alias_mapping);
            if (include_baseline)
                reconciliation.register_baseline_entry(source);
            reconciliation.register_actual_entry(retired(source, correct_target));
            reconciliation.register_actual_entry(make_entry(
                correct_target, "surface/" + correct_target + ".cpp",
                surface_entry_kind_t::handler_registration));
            reconciliation.register_actual_entry(make_entry(
                wrong_target, "surface/" + wrong_target + ".cpp",
                surface_entry_kind_t::tool_registration));
            const auto add = [&](std::string_view target) {
                reconciliation.mark_unsupported_alias(identifier, target);
            };
            if (reverse_order) {
                add(wrong_target);
                add(correct_target);
                add(wrong_target);
                add(correct_target);
            } else {
                add(correct_target);
                add(wrong_target);
                add(correct_target);
                add(wrong_target);
            }
            return reconciliation.reconcile();
        };
        const auto alias_forward = exercise_alias(false);
        const auto alias_reverse = exercise_alias(true);
        const auto alias_identifier = include_baseline
            ? "same_key_alias_both" : "same_key_alias_actual";
        require_detail(
            require_finding(
                alias_forward, surface_error_code_t::invalid_surface_marker,
                alias_identifier),
            "surface marker rejected; collection=unsupported_aliases, reason=conflicting_duplicate_marker, malformed=1");
        require(alias_forward.attempted_auxiliary_markers == 4 &&
                    alias_forward.rejected_auxiliary_markers == 1 &&
                    alias_forward.malformed_markers == 1 &&
                    alias_forward.unexplained_removals == 1,
                "same-key alias proof conflict accounting is incorrect");
        require_finding(
            alias_forward, surface_error_code_t::unexplained_removal_detected,
            alias_identifier);
        if (include_baseline) {
            require_finding(
                alias_forward, surface_error_code_t::baseline_mismatch,
                alias_identifier);
        }
        require(equal_results(alias_forward, alias_reverse),
                "same-key alias conflict depends on marker order");

        surface_reconciliation_t stale;
        const auto stale_identifier = std::string("same_key_stale_") +
            (include_baseline ? "both" : "actual");
        const auto stale_entry = make_entry(
            stale_identifier, "surface/" + stale_identifier + ".cpp",
            surface_entry_kind_t::handler_registration);
        if (include_baseline)
            stale.register_baseline_entry(stale_entry);
        stale.register_actual_entry(inactive(stale_entry));
        for (int repeat = 0; repeat < 4; ++repeat)
            stale.mark_stale_registration(stale_identifier);
        const auto stale_result = stale.reconcile();
        require(stale_result.clean &&
                    stale_result.attempted_auxiliary_markers == 4 &&
                    stale_result.rejected_auxiliary_markers == 0 &&
                    stale_result.malformed_markers == 0,
                "identical stale proof repetition was not idempotent");
    }

    const auto exercise_schema = [](bool reverse) {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "same_key_schema", "surface/same_key_schema.cpp",
            surface_entry_kind_t::schema_writer, true, "v8");
        auto actual = baseline;
        actual.schema_version = "v9";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        const auto add = [&](std::string_view path) {
            reconciliation.mark_old_schema_v8_writer(
                baseline.identifier, path);
        };
        if (reverse) {
            add("surface/same_key_schema_wrong.cpp");
            add(baseline.canonical_path);
            add("surface/same_key_schema_wrong.cpp");
            add(baseline.canonical_path);
        } else {
            add(baseline.canonical_path);
            add("surface/same_key_schema_wrong.cpp");
            add(baseline.canonical_path);
            add("surface/same_key_schema_wrong.cpp");
        }
        return reconciliation.reconcile();
    };
    const auto schema_forward = exercise_schema(false);
    const auto schema_reverse = exercise_schema(true);
    require_detail(
        require_finding(
            schema_forward, surface_error_code_t::invalid_surface_marker,
            "same_key_schema"),
        "surface marker rejected; collection=old_schema_v8_writers, reason=conflicting_duplicate_marker, malformed=1");
    require_finding(
        schema_forward, surface_error_code_t::baseline_mismatch,
        "same_key_schema");
    require(schema_forward.attempted_auxiliary_markers == 4 &&
                schema_forward.rejected_auxiliary_markers == 1 &&
                schema_forward.malformed_markers == 1 &&
                equal_results(schema_forward, schema_reverse),
            "same-key schema conflict was eligible or order-dependent");

    const auto exercise_mixed_conflict = [](bool reverse) {
        surface_reconciliation_t reconciliation;
        const auto source = make_entry(
            "same_key_mixed_conflict",
            "surface/same_key_mixed_conflict.cpp",
            surface_entry_kind_t::alias_mapping);
        reconciliation.register_actual_entry(retired(
            source, "same_key_mixed_target"));
        reconciliation.register_actual_entry(make_entry(
            "same_key_mixed_target", "surface/same_key_mixed_target.cpp",
            surface_entry_kind_t::handler_registration));
        const auto add_dead_conflict = [&] {
            reconciliation.mark_dead_replaced_path(
                source.identifier, "same_key_mixed_target");
            reconciliation.mark_dead_replaced_path(
                source.identifier, "same_key_mixed_wrong");
        };
        const auto add_alias = [&] {
            reconciliation.mark_unsupported_alias(
                source.identifier, "same_key_mixed_target");
        };
        if (reverse) {
            add_alias();
            add_dead_conflict();
        } else {
            add_dead_conflict();
            add_alias();
        }
        return reconciliation.reconcile();
    };
    const auto mixed_forward = exercise_mixed_conflict(false);
    const auto mixed_reverse = exercise_mixed_conflict(true);
    require_marker_reason(
        mixed_forward, "dead_replaced_paths", "same_key_mixed_conflict",
        "conflicting_duplicate_marker");
    require(mixed_forward.attempted_auxiliary_markers == 3 &&
                mixed_forward.rejected_auxiliary_markers == 1 &&
                mixed_forward.malformed_markers == 1 &&
                mixed_forward.unexplained_removals == 1,
            "internally conflicted proof did not invalidate sibling proof eligibility");
    require_finding(
        mixed_forward, surface_error_code_t::unexplained_removal_detected,
        "same_key_mixed_conflict");
    require(equal_results(mixed_forward, mixed_reverse),
            "mixed internal proof conflict depends on marker order");

    const auto exercise_duplicate = [](bool reverse) {
        surface_reconciliation_t reconciliation;
        const auto add = [&](std::string_view path) {
            reconciliation.mark_duplicate_store("same_key_store", path);
        };
        if (reverse) {
            add("surface/same_key_store_b.cpp");
            add("surface/same_key_store_a.cpp");
            add("surface/same_key_store_b.cpp");
            add("surface/same_key_store_a.cpp");
        } else {
            add("surface/same_key_store_a.cpp");
            add("surface/same_key_store_b.cpp");
            add("surface/same_key_store_a.cpp");
            add("surface/same_key_store_b.cpp");
        }
        return reconciliation.reconcile();
    };
    const auto store_forward = exercise_duplicate(false);
    const auto store_reverse = exercise_duplicate(true);
    require_detail(
        require_finding(
            store_forward, surface_error_code_t::invalid_surface_marker,
            "same_key_store"),
        "surface marker rejected; collection=duplicate_stores, reason=conflicting_duplicate_marker, malformed=1");
    require_no_finding(
        store_forward, surface_error_code_t::duplicate_store_detected,
        "same_key_store");
    require(store_forward.rejected_auxiliary_markers == 1 &&
                store_forward.malformed_markers == 1 &&
                equal_results(store_forward, store_reverse),
            "same-key duplicate-store conflict remained order-dependent");
}

void verify_security_evidence_deduplication() {
    surface_reconciliation_result_t forward;
    surface_reconciliation_result_t reverse;
    for (const bool marker_first : {false, true}) {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "security_missing_guard", "surface/security_missing_guard.cpp",
            surface_entry_kind_t::security_guard);
        baseline.security_note = "strict baseline guard";
        auto actual = inactive(baseline);
        actual.security_note = "disabled actual guard";
        if (marker_first)
            reconciliation.mark_security_regression(
                baseline.identifier, "explicit lower-priority marker");
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        if (!marker_first)
            reconciliation.mark_security_regression(
                baseline.identifier, "explicit lower-priority marker");
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(finding_count(
                    first, surface_error_code_t::security_regression_detected,
                    baseline.identifier) == 1,
                "security evidence was not canonically deduplicated");
        const auto& finding = require_finding(
            first, surface_error_code_t::security_regression_detected,
            baseline.identifier);
        require(finding.severity == 1000 &&
                    finding.canonical_path == baseline.canonical_path &&
                    finding.kind == surface_entry_kind_t::security_guard,
                "missing guard did not retain strongest security disposition");
        require_detail(
            finding,
            "baseline security guard is missing or inactive in actual surface");
        require(equal_results(first, second),
                "security evidence deduplication is nondeterministic");
        if (marker_first)
            reverse = first;
        else
            forward = first;
    }
    require(equal_results(forward, reverse),
            "security marker insertion order changed canonical evidence");

    {
        surface_reconciliation_t reconciliation;
        auto actual = inactive(make_entry(
            "security_equal_tie", "surface/security_equal_tie.cpp",
            surface_entry_kind_t::security_guard));
        actual.security_note = "inactive exact guard evidence";
        reconciliation.mark_security_regression(
            actual.identifier, "equal-severity marker evidence");
        reconciliation.register_actual_entry(actual);
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        const auto& finding = require_finding(
            first, surface_error_code_t::security_regression_detected,
            actual.identifier);
        require(finding.severity == 900 &&
                    finding.canonical_path == actual.canonical_path,
                "equal-severity security tie discarded path-bound evidence");
        require_contains(finding, "security guard is inactive in actual surface");
        require(equal_results(first, second),
                "equal-severity security tie is nondeterministic");
    }
    {
        surface_reconciliation_t reconciliation;
        auto baseline = make_entry(
            "security_drift_marker", "surface/security_drift_marker.cpp",
            surface_entry_kind_t::security_guard);
        baseline.security_note = "strict baseline";
        auto actual = baseline;
        actual.security_note = "drifted actual";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(actual);
        reconciliation.mark_security_regression(
            baseline.identifier, "explicit lower-priority marker");
        const auto result = reconciliation.reconcile();
        require(finding_count(
                    result, surface_error_code_t::security_regression_detected,
                    baseline.identifier) == 1,
                "marker and drift emitted duplicate security dispositions");
        const auto& finding = require_finding(
            result, surface_error_code_t::security_regression_detected,
            baseline.identifier);
        require(finding.severity == 950 &&
                    finding.canonical_path == baseline.canonical_path,
                "explicit marker suppressed stronger security drift evidence");
        require_detail(
            finding,
            "security-relevant baseline drift in fields: security_note");
    }
}

void verify_security_conflict_and_intrinsic_priority() {
    const auto exercise_conflict = [](bool reverse) {
        surface_reconciliation_t reconciliation;
        constexpr std::string_view weak = "short evidence";
        constexpr std::string_view strong =
            "deterministically stronger explicit security evidence";
        const auto add = [&](std::string_view detail) {
            reconciliation.mark_security_regression(
                "security_conflicting_reason", detail);
        };
        if (reverse) {
            add(strong);
            add(weak);
            add(strong);
            add(weak);
        } else {
            add(weak);
            add(strong);
            add(weak);
            add(strong);
        }
        return reconciliation.reconcile();
    };
    const auto conflict_forward = exercise_conflict(false);
    const auto conflict_reverse = exercise_conflict(true);
    require_detail(
        require_finding(
            conflict_forward, surface_error_code_t::invalid_surface_marker,
            "security_conflicting_reason"),
        "surface marker rejected; collection=security_regressions, reason=conflicting_duplicate_marker, malformed=1");
    const auto& conflict_finding = require_finding(
        conflict_forward, surface_error_code_t::security_regression_detected,
        "security_conflicting_reason");
    require_detail(
        conflict_finding,
        "security regression: deterministically stronger explicit security evidence");
    require(conflict_forward.attempted_auxiliary_markers == 4 &&
                conflict_forward.rejected_auxiliary_markers == 1 &&
                conflict_forward.malformed_markers == 1 &&
                equal_results(conflict_forward, conflict_reverse),
            "security reason conflict merge is order-dependent");

    const auto exercise_tie = [](bool reverse) {
        surface_reconciliation_t reconciliation;
        const auto add = [&](std::string_view detail) {
            reconciliation.mark_security_regression(
                "security_equal_reason", detail);
        };
        if (reverse) {
            add("bbbb");
            add("aaaa");
            add("bbbb");
            add("aaaa");
        } else {
            add("aaaa");
            add("bbbb");
            add("aaaa");
            add("bbbb");
        }
        return reconciliation.reconcile();
    };
    const auto tie_forward = exercise_tie(false);
    const auto tie_reverse = exercise_tie(true);
    require_detail(
        require_finding(
            tie_forward, surface_error_code_t::security_regression_detected,
            "security_equal_reason"),
        "security regression: aaaa");
    require(tie_forward.rejected_auxiliary_markers == 1 &&
                tie_forward.malformed_markers == 1 &&
                equal_results(tie_forward, tie_reverse),
            "equal-priority security reason tie is order-dependent");

    for (std::uint64_t visible_limit = 1; visible_limit <= 1000;
         ++visible_limit) {
        const auto exercise = [visible_limit](bool reverse) {
            surface_reconciliation_limits_t limits;
            limits.maximum_severity = visible_limit;
            surface_reconciliation_t reconciliation(limits);
            auto baseline = make_entry(
                "security_intrinsic_priority",
                "surface/security_intrinsic_priority.cpp",
                surface_entry_kind_t::security_guard);
            baseline.security_note = "strict baseline guard";
            auto actual = inactive(baseline);
            actual.security_note = std::string(3000, 'z');
            const auto add_markers = [&](bool reverse_markers) {
                const auto weak = std::string(2500, 'x');
                const auto strong = std::string(3500, 'y');
                if (reverse_markers) {
                    reconciliation.mark_security_regression(
                        baseline.identifier, strong);
                    reconciliation.mark_security_regression(
                        baseline.identifier, weak);
                } else {
                    reconciliation.mark_security_regression(
                        baseline.identifier, weak);
                    reconciliation.mark_security_regression(
                        baseline.identifier, strong);
                }
            };
            if (reverse) {
                add_markers(true);
                reconciliation.register_actual_entry(actual);
                reconciliation.register_baseline_entry(baseline);
            } else {
                reconciliation.register_baseline_entry(baseline);
                reconciliation.register_actual_entry(actual);
                add_markers(false);
            }
            return reconciliation.reconcile();
        };
        const auto forward = exercise(false);
        const auto reverse = exercise(true);
        const auto& strongest = require_finding(
            forward, surface_error_code_t::security_regression_detected,
            "security_intrinsic_priority");
        require_detail(
            strongest,
            "baseline security guard is missing or inactive in actual surface");
        require(strongest.canonical_path ==
                    "surface/security_intrinsic_priority.cpp" &&
                    strongest.severity == visible_limit &&
                    finding_count(
                        forward,
                        surface_error_code_t::security_regression_detected,
                        "security_intrinsic_priority") == 1 &&
                    forward.rejected_auxiliary_markers == 1 &&
                    forward.malformed_markers == 1 &&
                    equal_results(forward, reverse),
                "visible severity clamp changed intrinsic security precedence");
    }
}

void verify_security_priority_finding_caps() {
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_findings = 2;
        surface_reconciliation_t reconciliation(limits);
        reconciliation.mark_stale_registration("invalid marker identity");
        reconciliation.mark_duplicate_store(
            "cap_low_priority", "surface/cap_low_priority.cpp");
        reconciliation.mark_security_regression(
            "cap_security", "late security evidence");
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(first.finding_cap_exceeded && first.findings.size() == 2,
                "minimum valid finding cap did not remain bounded");
        require_finding(
            first, surface_error_code_t::finding_cap_exceeded,
            "surface_findings");
        require_finding(
            first, surface_error_code_t::security_regression_detected,
            "cap_security");
        require_no_finding(
            first, surface_error_code_t::invalid_surface_marker);
        require_no_finding(
            first, surface_error_code_t::duplicate_store_detected);
        require(first.findings_discarded != 0 && equal_results(first, second),
                "security-priority minimum cap retention is nondeterministic");
    }
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_findings = 3;
        surface_reconciliation_t reconciliation(limits);
        for (const auto* identifier : {
                 "security_cap_4", "security_cap_1", "security_cap_3",
                 "security_cap_0", "security_cap_2"}) {
            reconciliation.mark_security_regression(
                identifier, "equal-priority security evidence");
        }
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(first.finding_cap_exceeded && first.findings.size() == 3,
                "multi-security finding cap did not remain bounded");
        require_finding(
            first, surface_error_code_t::finding_cap_exceeded,
            "surface_findings");
        require_finding(
            first, surface_error_code_t::security_regression_detected,
            "security_cap_0");
        require_finding(
            first, surface_error_code_t::security_regression_detected,
            "security_cap_1");
        require_no_finding(
            first, surface_error_code_t::security_regression_detected,
            "security_cap_2");
        require_no_finding(
            first, surface_error_code_t::security_regression_detected,
            "security_cap_3");
        require_no_finding(
            first, surface_error_code_t::security_regression_detected,
            "security_cap_4");
        require(equal_results(first, second),
                "equal-priority security cap tie is nondeterministic");
    }
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_findings = 3;
        surface_reconciliation_t ascending(limits);
        surface_reconciliation_t descending(limits);
        for (int index = 0; index < 6; ++index) {
            ascending.mark_security_regression(
                "permuted_security_" + std::to_string(index),
                "equal-priority security evidence");
            descending.mark_security_regression(
                "permuted_security_" + std::to_string(5 - index),
                "equal-priority security evidence");
        }
        const auto ascending_result = ascending.reconcile();
        const auto descending_result = descending.reconcile();
        require(equal_results(ascending_result, descending_result),
                "finding retention changed under input order permutation");
    }
}

void verify_finding_source_fidelity() {
    for (const auto kind : {surface_entry_kind_t::source_file,
                            surface_entry_kind_t::handler_registration}) {
        surface_reconciliation_t reconciliation;
        const auto identifier = kind == surface_entry_kind_t::source_file
            ? "active_dead_source" : "active_dead_handler";
        const auto path = kind == surface_entry_kind_t::source_file
            ? "surface/active_dead_source.cpp" : "surface/active_dead_handler.cpp";
        auto source = make_entry(identifier, path, kind);
        auto baseline = source;
        baseline.canonical_path =
            kind == surface_entry_kind_t::source_file
                ? "surface/baseline_dead_source.cpp"
                : "surface/baseline_dead_handler.cpp";
        reconciliation.register_baseline_entry(baseline);
        reconciliation.register_actual_entry(source);
        reconciliation.register_actual_entry(make_entry(
            "dead_replacement_target_" + std::to_string(static_cast<int>(kind)),
            "surface/dead_replacement_target_" +
                std::to_string(static_cast<int>(kind)) + ".cpp",
            kind));
        const auto target =
            "dead_replacement_target_" + std::to_string(static_cast<int>(kind));
        reconciliation.mark_dead_replaced_path(identifier, target);
        const auto result = reconciliation.reconcile();
        const auto& finding = require_finding(
            result,
            surface_error_code_t::dead_replaced_path_detected, identifier);
        require(finding.kind == kind && finding.canonical_path == path,
                "active dead-path finding lost exact source evidence");
    }

    {
        surface_reconciliation_t reconciliation;
        auto ast = make_entry(
            "legacy_ast", "surface/exact_legacy_ast.cpp",
            surface_entry_kind_t::ast_path);
        reconciliation.register_actual_entry(ast);
        reconciliation.mark_legacy_invalid_ast_flow("legacy_ast");
        const auto result = reconciliation.reconcile();
        const auto& finding = require_finding(
            result,
            surface_error_code_t::legacy_invalid_ast_flow_detected,
            "legacy_ast");
        require(finding.kind == surface_entry_kind_t::ast_path &&
                    finding.canonical_path == ast.canonical_path,
                "legacy AST finding lost unique actual source evidence");
    }
    {
        surface_reconciliation_t reconciliation;
        auto alias = make_entry(
            "active_alias", "surface/exact_alias.cpp",
            surface_entry_kind_t::alias_mapping);
        reconciliation.register_actual_entry(alias);
        reconciliation.register_actual_entry(make_entry(
            "active_alias_target", "surface/exact_alias_target.cpp",
            surface_entry_kind_t::tool_registration));
        reconciliation.mark_unsupported_alias(
            "active_alias", "active_alias_target");
        const auto result = reconciliation.reconcile();
        const auto& finding = require_finding(
            result,
            surface_error_code_t::unsupported_alias_detected,
            "active_alias");
        require(finding.kind == surface_entry_kind_t::alias_mapping &&
                    finding.canonical_path == alias.canonical_path,
                "unsupported-alias finding lost unique actual source evidence");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "ambiguous_ast", "surface/ambiguous_ast_a.cpp",
            surface_entry_kind_t::ast_path));
        reconciliation.register_actual_entry(make_entry(
            "ambiguous_ast", "surface/ambiguous_ast_b.cpp",
            surface_entry_kind_t::ast_path));
        reconciliation.mark_legacy_invalid_ast_flow("ambiguous_ast");
        const auto result = reconciliation.reconcile();
        require_no_finding(result,
                           surface_error_code_t::legacy_invalid_ast_flow_detected,
                           "ambiguous_ast");
        require_finding(result,
                        surface_error_code_t::duplicate_actual_identifier_detected,
                        "ambiguous_ast");
    }
    {
        surface_reconciliation_t reconciliation;
        reconciliation.register_actual_entry(make_entry(
            "ambiguous_alias", "surface/ambiguous_alias_a.cpp",
            surface_entry_kind_t::alias_mapping));
        reconciliation.register_actual_entry(make_entry(
            "ambiguous_alias", "surface/ambiguous_alias_b.cpp",
            surface_entry_kind_t::alias_mapping));
        reconciliation.register_actual_entry(make_entry(
            "ambiguous_alias_target", "surface/ambiguous_alias_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.mark_unsupported_alias(
            "ambiguous_alias", "ambiguous_alias_target");
        const auto result = reconciliation.reconcile();
        require_no_finding(result, surface_error_code_t::unsupported_alias_detected,
                           "ambiguous_alias");
        require_finding(result, surface_error_code_t::invalid_surface_marker,
                        "ambiguous_alias");
        require_finding(result,
                        surface_error_code_t::duplicate_actual_identifier_detected,
                        "ambiguous_alias");
    }
}

void verify_duplicate_identity_contract() {
    surface_reconciliation_t reconciliation;
    auto baseline_duplicate = make_entry(
        "baseline_duplicate", "surface/baseline_duplicate_a.cpp",
        surface_entry_kind_t::store_definition);
    reconciliation.register_baseline_entry(baseline_duplicate);
    baseline_duplicate.canonical_path = "surface/baseline_duplicate_b.cpp";
    reconciliation.register_baseline_entry(baseline_duplicate);

    auto actual_duplicate = make_entry(
        "actual_duplicate", "surface/actual_duplicate_a.cpp",
        surface_entry_kind_t::source_file);
    reconciliation.register_actual_entry(actual_duplicate);
    actual_duplicate.canonical_path = "surface/actual_duplicate_b.cpp";
    reconciliation.register_actual_entry(actual_duplicate);

    auto store_duplicate = make_entry(
        "store_duplicate", "surface/store_duplicate_a.cpp",
        surface_entry_kind_t::store_definition);
    reconciliation.register_actual_entry(store_duplicate);
    store_duplicate.canonical_path = "surface/store_duplicate_b.cpp";
    reconciliation.register_actual_entry(store_duplicate);

    reconciliation.register_actual_entry(make_entry(
        "mixed_duplicate", "surface/mixed_duplicate_store.cpp",
        surface_entry_kind_t::store_definition));
    reconciliation.register_actual_entry(make_entry(
        "mixed_duplicate", "surface/mixed_duplicate_source.cpp",
        surface_entry_kind_t::source_file));

    const auto result = reconciliation.reconcile();
    require_finding(result,
                    surface_error_code_t::duplicate_baseline_identifier_detected,
                    "baseline_duplicate");
    require_finding(result,
                    surface_error_code_t::duplicate_actual_identifier_detected,
                    "actual_duplicate");
    require_finding(result, surface_error_code_t::duplicate_store_detected,
                    "store_duplicate");
    require_no_finding(result,
                       surface_error_code_t::duplicate_actual_identifier_detected,
                       "store_duplicate");
    require_finding(result,
                    surface_error_code_t::duplicate_actual_identifier_detected,
                    "mixed_duplicate");
    require_no_finding(result, surface_error_code_t::duplicate_store_detected,
                       "mixed_duplicate");
    require_no_finding(result, surface_error_code_t::baseline_mismatch,
                       "baseline_duplicate");
    require_no_finding(result, surface_error_code_t::baseline_mismatch,
                       "actual_duplicate");
}

void verify_limits_and_finding_cap() {
    std::vector<surface_reconciliation_limits_t> invalid;
    auto add = [&invalid](surface_reconciliation_limits_t limits) {
        invalid.push_back(limits);
    };
    {
        surface_reconciliation_limits_t value;
        value.maximum_entries = 0;
        add(value);
        value.maximum_entries = 100001;
        add(value);
    }
    {
        surface_reconciliation_limits_t value;
        value.maximum_findings = 0;
        add(value);
        value.maximum_findings = 10001;
        add(value);
    }
    {
        surface_reconciliation_limits_t value;
        value.maximum_severity = 0;
        add(value);
        value.maximum_severity = 1001;
        add(value);
    }
    {
        surface_reconciliation_limits_t value;
        value.maximum_identifier_bytes = 0;
        add(value);
        value.maximum_identifier_bytes = 513;
        add(value);
    }
    {
        surface_reconciliation_limits_t value;
        value.maximum_text_bytes = 0;
        add(value);
        value.maximum_text_bytes = 4097;
        add(value);
    }
    {
        surface_reconciliation_limits_t value;
        value.maximum_identifier_bytes = 128;
        value.maximum_text_bytes = 64;
        add(value);
    }
    {
        surface_reconciliation_limits_t value;
        value.maximum_metric_value = 0;
        add(value);
    }
    for (const auto& limits : invalid) {
        surface_reconciliation_t reconciliation(limits);
        const auto result = reconciliation.reconcile();
        require(result.limits_invalid && !result.clean,
                "invalid reconciliation limits did not fail closed");
        require_finding(result, surface_error_code_t::invalid_limit_contract,
                        "surface_reconciliation_limits");
    }

    {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 1;
        surface_reconciliation_t reconciliation(limits);
        auto first = make_entry(
            "first", "surface/first.cpp", surface_entry_kind_t::source_file);
        auto second = make_entry(
            "second", "surface/second.cpp", surface_entry_kind_t::source_file);
        reconciliation.register_baseline_entry(first);
        reconciliation.register_baseline_entry(second);
        reconciliation.register_actual_entry(first);
        reconciliation.register_actual_entry(second);
        const auto result = reconciliation.reconcile();
        require(result.baseline_cap_exceeded && result.actual_cap_exceeded &&
                    result.attempted_baseline_entries == 2 &&
                    result.attempted_actual_entries == 2 &&
                    result.rejected_baseline_entries == 1 &&
                    result.rejected_actual_entries == 1,
                "entry capacity contract metrics are incorrect");
        require_finding(result, surface_error_code_t::baseline_entry_cap_exceeded,
                        "baseline_entries");
        require_finding(result, surface_error_code_t::actual_entry_cap_exceeded,
                        "actual_entries");
    }
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_severity = 123;
        surface_reconciliation_t reconciliation(limits);
        reconciliation.mark_security_regression("severity_clamp", "adverse fixture");
        const auto result = reconciliation.reconcile();
        const auto& finding = require_finding(
            result,
            surface_error_code_t::security_regression_detected,
            "severity_clamp");
        require(finding.severity == 123,
                "finding severity was not clamped to the configured limit");
    }
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_findings = 2;
        surface_reconciliation_t reconciliation(limits);
        for (int index = 0; index < 6; ++index) {
            reconciliation.mark_security_regression(
                "finding_" + std::to_string(index), "adverse fixture");
        }
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(first.finding_cap_exceeded && first.findings.size() == 2 &&
                    first.findings_produced > first.findings.size() &&
                    first.findings_discarded != 0,
                "finding capacity did not retain bounded fail-closed evidence");
        require_finding(first, surface_error_code_t::finding_cap_exceeded,
                        "surface_findings");
        require(equal_results(first, second),
                "bounded finding finalization is nondeterministic");
    }
}

void verify_invalid_entries() {
    std::vector<surface_entry_t> entries;
    const auto valid = make_entry(
        "valid", "surface/valid.cpp", surface_entry_kind_t::source_file);
    auto push = [&entries](surface_entry_t entry) {
        entries.push_back(std::move(entry));
    };
    auto entry = valid;
    entry.identifier.clear();
    push(entry);
    entry = valid;
    entry.identifier = "invalid identifier";
    push(entry);
    entry = valid;
    entry.identifier = std::string(513, 'i');
    push(entry);
    entry = valid;
    entry.canonical_path.clear();
    push(entry);
    for (const auto* path : {"/absolute.cpp", "trailing/", "bad\\path.cpp",
                             "C:/absolute.cpp", "a/./b.cpp", "a/../b.cpp",
                             "a//b.cpp"}) {
        entry = valid;
        entry.canonical_path = path;
        push(entry);
    }
    entry = valid;
    entry.kind = static_cast<surface_entry_kind_t>(0xff);
    push(entry);
    entry = valid;
    entry.is_replaced = true;
    entry.replaced_by = "replacement";
    push(entry);
    entry = valid;
    entry.is_active = false;
    entry.is_replaced = true;
    push(entry);
    entry = valid;
    entry.is_active = false;
    entry.is_replaced = true;
    entry.replaced_by = "valid";
    push(entry);
    entry = valid;
    entry.replaced_by = "replacement";
    push(entry);
    entry = make_entry(
        "schema_missing", "surface/schema_missing.cpp",
        surface_entry_kind_t::schema_writer);
    entry.schema_version.clear();
    push(entry);
    entry = make_entry(
        "schema_invalid", "surface/schema_invalid.cpp",
        surface_entry_kind_t::schema_writer, false, "bad version");
    push(entry);
    entry = valid;
    entry.schema_version = "v9";
    push(entry);
    entry = make_entry(
        "guard_missing_note", "surface/guard_missing_note.cpp",
        surface_entry_kind_t::security_guard, false);
    entry.security_note.clear();
    push(entry);
    entry = make_entry(
        "guard_bad_note", "surface/guard_bad_note.cpp",
        surface_entry_kind_t::security_guard);
    entry.security_note = "bad\nnote";
    push(entry);
    entry = valid;
    entry.security_note = "non-guard note";
    push(entry);

    surface_reconciliation_t reconciliation;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        if ((index & 1U) == 0)
            reconciliation.register_baseline_entry(entries[index]);
        else
            reconciliation.register_actual_entry(entries[index]);
    }
    const auto result = reconciliation.reconcile();
    require(result.malformed_entries == entries.size() &&
                result.rejected_baseline_entries == (entries.size() + 1U) / 2U &&
                result.rejected_actual_entries == entries.size() / 2U &&
                reconciliation.baseline_entry_count() == 0 &&
                reconciliation.actual_entry_count() == 0,
            "malformed surface entry accounting is incorrect");
    const auto& finding = require_finding(
        result, surface_error_code_t::invalid_surface_entry, "<invalid>");
    require_contains(finding, "reason=invalid_identifier");
}

void verify_marker_validation_and_capacity() {
    {
        surface_reconciliation_t reconciliation;
        reconciliation.mark_dead_replaced_path("dead", "dead");
        reconciliation.mark_duplicate_store("duplicate", "bad\\path.cpp");
        reconciliation.mark_stale_registration("bad stale");
        reconciliation.mark_old_schema_v8_writer("schema", "bad\\path.cpp");
        reconciliation.mark_legacy_invalid_ast_flow("bad ast");
        reconciliation.mark_unsupported_alias("alias", "alias");
        reconciliation.mark_security_regression("security", "");
        const auto result = reconciliation.reconcile();
        require(result.attempted_auxiliary_markers == 7 &&
                    result.rejected_auxiliary_markers == 7 &&
                    result.malformed_markers == 7,
                "malformed marker accounting is incorrect");
        const auto& finding = require_finding(
            result, surface_error_code_t::invalid_surface_marker, "dead");
        require_contains(finding, "reason=self_replacement");
    }

    {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 7;
        surface_reconciliation_t reconciliation(limits);
        auto old_source = make_entry(
            "dead", "surface/dead.cpp", surface_entry_kind_t::source_file);
        reconciliation.register_actual_entry(retired(old_source, "dead_target"));
        reconciliation.register_actual_entry(make_entry(
            "dead_target", "surface/dead_target.cpp",
            surface_entry_kind_t::source_file));
        reconciliation.register_actual_entry(retired(make_entry(
            "alias", "surface/alias.cpp", surface_entry_kind_t::alias_mapping),
            "alias_target"));
        reconciliation.register_actual_entry(make_entry(
            "alias_target", "surface/alias_target.cpp",
            surface_entry_kind_t::handler_registration));
        reconciliation.register_actual_entry(inactive(make_entry(
            "stale", "surface/stale.cpp",
            surface_entry_kind_t::handler_registration)));
        reconciliation.register_baseline_entry(make_entry(
            "schema", "surface/schema.cpp",
            surface_entry_kind_t::schema_writer, true, "v8"));
        reconciliation.register_actual_entry(make_entry(
            "schema", "surface/schema.cpp",
            surface_entry_kind_t::schema_writer, true, "v9"));
        const auto add_markers = [&reconciliation] {
            reconciliation.mark_dead_replaced_path("dead", "dead_target");
            reconciliation.mark_duplicate_store("duplicate", "surface/duplicate.cpp");
            reconciliation.mark_stale_registration("stale");
            reconciliation.mark_old_schema_v8_writer("schema", "surface/schema.cpp");
            reconciliation.mark_legacy_invalid_ast_flow("legacy");
            reconciliation.mark_unsupported_alias("alias", "alias_target");
            reconciliation.mark_security_regression("security", "adverse fixture");
        };
        add_markers();
        add_markers();
        reconciliation.mark_stale_registration("overflow");
        const auto result = reconciliation.reconcile();
        require(result.attempted_auxiliary_markers == 15 &&
                    result.rejected_auxiliary_markers == 2 &&
                    result.malformed_markers == 1 &&
                    result.auxiliary_cap_exceeded,
                "idempotent markers consumed capacity or overflow accounting regressed");
        require_finding(result,
                        surface_error_code_t::auxiliary_marker_cap_exceeded,
                        "unsupported_aliases");
        require_marker_reason(
            result, "stale_registrations", "overflow",
            "missing_actual_source_identity");
    }

    constexpr std::array<std::string_view, 7> collections = {
        "dead_replaced_paths", "duplicate_stores", "stale_registrations",
        "old_schema_v8_writers", "legacy_ast_flows", "unsupported_aliases",
        "security_regressions"
    };
    for (std::size_t index = 0; index < collections.size(); ++index) {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 1;
        surface_reconciliation_t reconciliation(limits);
        reconciliation.mark_security_regression("seed", "adverse fixture");
        switch (index) {
        case 0: reconciliation.mark_dead_replaced_path("dead", "target"); break;
        case 1: reconciliation.mark_duplicate_store("duplicate", "surface/path.cpp"); break;
        case 2: reconciliation.mark_stale_registration("stale"); break;
        case 3: reconciliation.mark_old_schema_v8_writer("schema", "surface/schema.cpp"); break;
        case 4: reconciliation.mark_legacy_invalid_ast_flow("legacy"); break;
        case 5: reconciliation.mark_unsupported_alias("alias", "canonical"); break;
        case 6: reconciliation.mark_security_regression("overflow", "adverse fixture"); break;
        default: throw std::runtime_error("unreachable marker collection fixture");
        }
        const auto result = reconciliation.reconcile();
        require_finding(result,
                        surface_error_code_t::auxiliary_marker_cap_exceeded,
                        collections[index]);
    }
}

void verify_canonical_invalid_and_overflow_evidence() {
    constexpr std::array<std::array<std::size_t, 3>, 6> permutations = {{
        {{0, 1, 2}}, {{0, 2, 1}}, {{1, 0, 2}},
        {{1, 2, 0}}, {{2, 0, 1}}, {{2, 1, 0}}
    }};

    surface_reconciliation_result_t canonical_entries;
    bool have_entries = false;
    for (const auto& order : permutations) {
        surface_reconciliation_t reconciliation;
        for (const auto index : order) {
            if (index == 0) {
                auto entry = make_entry(
                    "z invalid", "surface/z_invalid.cpp",
                    surface_entry_kind_t::source_file);
                reconciliation.register_baseline_entry(entry);
            } else if (index == 1) {
                auto entry = make_entry(
                    "a invalid", "surface/a_invalid.cpp",
                    surface_entry_kind_t::source_file);
                reconciliation.register_actual_entry(entry);
            } else {
                auto entry = make_entry(
                    "middle_invalid", "bad\\path.cpp",
                    surface_entry_kind_t::source_file);
                reconciliation.register_baseline_entry(entry);
            }
        }
        const auto result = reconciliation.reconcile();
        const auto& finding = require_finding(
            result, surface_error_code_t::invalid_surface_entry, "a invalid");
        require_detail(
            finding,
            "actual surface entry rejected; reason=invalid_identifier, malformed=3");
        require(result.malformed_entries == 3 &&
                    result.rejected_baseline_entries == 2 &&
                    result.rejected_actual_entries == 1,
                "invalid-entry canonical accounting is incorrect");
        if (!have_entries) {
            canonical_entries = result;
            have_entries = true;
        } else {
            require(equal_results(canonical_entries, result),
                    "invalid-entry evidence depends on registration order");
        }
    }

    surface_reconciliation_result_t canonical_markers;
    bool have_markers = false;
    for (const auto& order : permutations) {
        surface_reconciliation_t reconciliation;
        for (const auto index : order) {
            if (index == 0) {
                reconciliation.mark_stale_registration("z invalid");
            } else if (index == 1) {
                reconciliation.mark_security_regression("a", "");
            } else {
                reconciliation.mark_duplicate_store("m", "bad\\path.cpp");
            }
        }
        const auto result = reconciliation.reconcile();
        const auto& finding = require_finding(
            result, surface_error_code_t::invalid_surface_marker, "a");
        require_detail(
            finding,
            "surface marker rejected; collection=security_regressions, reason=invalid_security_marker, malformed=3");
        require(result.attempted_auxiliary_markers == 3 &&
                    result.rejected_auxiliary_markers == 3 &&
                    result.malformed_markers == 3,
                "invalid-marker canonical accounting is incorrect");
        if (!have_markers) {
            canonical_markers = result;
            have_markers = true;
        } else {
            require(equal_results(canonical_markers, result),
                    "invalid-marker evidence depends on registration order");
        }
    }
}

void verify_auxiliary_security_priority() {
    for (std::size_t capacity = 1; capacity <= 5; ++capacity) {
        surface_reconciliation_result_t canonical;
        bool have_canonical = false;
        std::array<std::size_t, 5> order = {{0, 1, 2, 3, 4}};
        do {
            surface_reconciliation_limits_t limits;
            limits.maximum_entries = capacity;
            surface_reconciliation_t reconciliation(limits);
            reconciliation.register_actual_entry(inactive(make_entry(
                "priority_stale", "surface/priority_stale.cpp",
                surface_entry_kind_t::handler_registration)));
            for (const auto index : order) {
                switch (index) {
                case 0:
                    reconciliation.mark_security_regression(
                        "priority_security_a", "security evidence a");
                    break;
                case 1:
                    reconciliation.mark_security_regression(
                        "priority_security_b", "security evidence b");
                    break;
                case 2:
                    reconciliation.mark_duplicate_store(
                        "priority_duplicate", "surface/priority_duplicate.cpp");
                    break;
                case 3:
                    reconciliation.mark_legacy_invalid_ast_flow(
                        "priority_legacy");
                    break;
                case 4:
                    reconciliation.mark_stale_registration("priority_stale");
                    break;
                default:
                    throw std::runtime_error(
                        "unreachable auxiliary-priority fixture");
                }
            }
            const auto result = reconciliation.reconcile();
            require(result.attempted_auxiliary_markers == 5 &&
                        result.rejected_auxiliary_markers == 5 - capacity &&
                        result.auxiliary_cap_exceeded == (capacity < 5),
                    "auxiliary priority capacity accounting is incorrect");
            require_finding(
                result, surface_error_code_t::security_regression_detected,
                "priority_security_a");
            if (capacity == 1) {
                require_no_finding(
                    result, surface_error_code_t::security_regression_detected,
                    "priority_security_b");
            } else {
                require_finding(
                    result, surface_error_code_t::security_regression_detected,
                    "priority_security_b");
            }
            if (capacity < 5) {
                require_finding(
                    result,
                    surface_error_code_t::auxiliary_marker_cap_exceeded,
                    capacity <= 2
                        ? "duplicate_stores"
                        : capacity == 3
                              ? "legacy_ast_flows"
                              : "stale_registrations");
            }
            if (!have_canonical) {
                canonical = result;
                have_canonical = true;
            } else {
                require(equal_results(canonical, result),
                        "auxiliary priority retention depends on input order");
            }
        } while (std::next_permutation(order.begin(), order.end()));
    }

    constexpr std::array<std::array<std::size_t, 3>, 6> proof_orders = {{
        {{0, 1, 2}}, {{0, 2, 1}}, {{1, 0, 2}},
        {{1, 2, 0}}, {{2, 0, 1}}, {{2, 1, 0}}
    }};
    surface_reconciliation_result_t canonical_proof_overflow;
    bool have_proof_overflow = false;
    for (const auto& order : proof_orders) {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 2;
        surface_reconciliation_t reconciliation(limits);
        const auto source = make_entry(
            "priority_proof_source", "surface/priority_proof_source.cpp",
            surface_entry_kind_t::source_file);
        reconciliation.register_actual_entry(retired(
            source, "priority_proof_target"));
        reconciliation.register_actual_entry(make_entry(
            "priority_proof_target", "surface/priority_proof_target.cpp",
            surface_entry_kind_t::source_file));
        for (const auto index : order) {
            if (index == 0) {
                reconciliation.mark_dead_replaced_path(
                    "priority_proof_source", "priority_proof_target");
            } else if (index == 1) {
                reconciliation.mark_security_regression(
                    "priority_proof_security", "security evidence");
            } else {
                reconciliation.mark_stale_registration(
                    "priority_proof_stale");
            }
        }
        const auto result = reconciliation.reconcile();
        require(result.auxiliary_cap_exceeded &&
                    result.attempted_auxiliary_markers == 3 &&
                    result.rejected_auxiliary_markers == 1 &&
                    result.unexplained_removals == 1,
                "incomplete auxiliary inventory did not fail proof closure");
        require_finding(
            result, surface_error_code_t::security_regression_detected,
            "priority_proof_security");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            "priority_proof_source");
        require_no_finding(
            result, surface_error_code_t::invalid_surface_marker,
            "priority_proof_stale");
        require_finding(
            result, surface_error_code_t::auxiliary_marker_cap_exceeded,
            "stale_registrations");
        if (!have_proof_overflow) {
            canonical_proof_overflow = result;
            have_proof_overflow = true;
        } else {
            require(equal_results(canonical_proof_overflow, result),
                    "overflow proof closure depends on marker order");
        }
    }

    surface_reconciliation_result_t canonical_conflict_eviction;
    bool have_conflict_eviction = false;
    for (const bool reverse : {false, true}) {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 2;
        surface_reconciliation_t reconciliation(limits);
        const auto source = make_entry(
            "evicted_conflict_source", "surface/evicted_conflict_source.cpp",
            surface_entry_kind_t::source_file);
        reconciliation.register_actual_entry(retired(
            source, "evicted_conflict_target"));
        reconciliation.register_actual_entry(make_entry(
            "evicted_conflict_target", "surface/evicted_conflict_target.cpp",
            surface_entry_kind_t::source_file));
        const auto add = [&](std::string_view target) {
            reconciliation.mark_dead_replaced_path(source.identifier, target);
        };
        if (reverse) {
            add("evicted_conflict_wrong");
            add("evicted_conflict_target");
        } else {
            add("evicted_conflict_target");
            add("evicted_conflict_wrong");
        }
        reconciliation.mark_security_regression(
            "evicted_conflict_security_b", "security evidence b");
        reconciliation.mark_security_regression(
            "evicted_conflict_security_a", "security evidence a");
        add("evicted_conflict_target");
        const auto result = reconciliation.reconcile();
        require(result.attempted_auxiliary_markers == 5 &&
                    result.rejected_auxiliary_markers == 3 &&
                    result.malformed_markers == 1 &&
                    result.auxiliary_cap_exceeded &&
                    result.unexplained_removals == 1,
                "evicted conflicting proof regained eligibility or changed accounting");
        require_marker_reason(
            result, "dead_replaced_paths", source.identifier,
            "conflicting_duplicate_marker");
        require_finding(
            result, surface_error_code_t::auxiliary_marker_cap_exceeded,
            "dead_replaced_paths");
        require_finding(
            result, surface_error_code_t::unexplained_removal_detected,
            source.identifier);
        require_finding(
            result, surface_error_code_t::security_regression_detected,
            "evicted_conflict_security_a");
        require_finding(
            result, surface_error_code_t::security_regression_detected,
            "evicted_conflict_security_b");
        if (!have_conflict_eviction) {
            canonical_conflict_eviction = result;
            have_conflict_eviction = true;
        } else {
            require(equal_results(canonical_conflict_eviction, result),
                    "evicted conflict disposition depends on marker order");
        }
    }
}

void verify_permanent_auxiliary_history() {
    enum class family_t : std::uint8_t {
        dead = 0,
        duplicate = 1,
        schema = 2,
        alias = 3,
        security = 4
    };

    constexpr std::array<std::array<std::size_t, 9>, 8> orders = {{
        {{0, 1, 2, 3, 4, 5, 6, 7, 8}},
        {{8, 7, 6, 5, 4, 3, 2, 1, 0}},
        {{1, 2, 0, 3, 4, 5, 6, 7, 8}},
        {{6, 1, 2, 3, 4, 5, 0, 7, 8}},
        {{1, 0, 2, 6, 3, 7, 4, 5, 8}},
        {{8, 5, 4, 3, 2, 1, 7, 6, 0}},
        {{0, 1, 6, 2, 3, 7, 4, 5, 8}},
        {{6, 5, 0, 4, 1, 3, 7, 8, 2}}
    }};

    const auto exercise = [](family_t family, std::size_t capacity,
                             const std::array<std::size_t, 9>& order,
                             std::uint64_t metric_limit) {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = capacity;
        if (metric_limit != 0)
            limits.maximum_metric_value = metric_limit;
        surface_reconciliation_t reconciliation(limits);

        if (family == family_t::dead) {
            const auto source = make_entry(
                "z_history_dead", "surface/z_history_dead.cpp",
                surface_entry_kind_t::source_file);
            reconciliation.register_actual_entry(retired(
                source, "z_history_dead_target"));
            if (capacity >= 2) {
                reconciliation.register_actual_entry(make_entry(
                    "z_history_dead_target",
                    "surface/z_history_dead_target.cpp",
                    surface_entry_kind_t::source_file));
            }
        } else if (family == family_t::schema) {
            reconciliation.register_baseline_entry(make_entry(
                "z_history_schema", "surface/z_history_schema.cpp",
                surface_entry_kind_t::schema_writer, true, "v8"));
            reconciliation.register_actual_entry(make_entry(
                "z_history_schema", "surface/z_history_schema.cpp",
                surface_entry_kind_t::schema_writer, true, "v9"));
        } else if (family == family_t::alias) {
            const auto source = make_entry(
                "z_history_alias", "surface/z_history_alias.cpp",
                surface_entry_kind_t::alias_mapping);
            reconciliation.register_actual_entry(retired(
                source, "z_history_alias_target"));
            if (capacity >= 2) {
                reconciliation.register_actual_entry(make_entry(
                    "z_history_alias_target",
                    "surface/z_history_alias_target.cpp",
                    surface_entry_kind_t::handler_registration));
            }
        }

        const auto mark_family = [&](std::uint8_t variant) {
            switch (family) {
            case family_t::dead:
                reconciliation.mark_dead_replaced_path(
                    "z_history_dead",
                    variant == 0
                        ? "z_history_dead_target"
                        : variant == 1
                              ? "z_history_dead_wrong"
                              : "z_history_dead_third");
                break;
            case family_t::duplicate:
                reconciliation.mark_duplicate_store(
                    "z_history_duplicate",
                    variant == 0
                        ? "surface/z_history_duplicate_a.cpp"
                        : variant == 1
                              ? "surface/z_history_duplicate_b.cpp"
                              : "surface/z_history_duplicate_c.cpp");
                break;
            case family_t::schema:
                reconciliation.mark_old_schema_v8_writer(
                    "z_history_schema",
                    variant == 0
                        ? "surface/z_history_schema.cpp"
                        : variant == 1
                              ? "surface/z_history_schema_wrong.cpp"
                              : "surface/z_history_schema_third.cpp");
                break;
            case family_t::alias:
                reconciliation.mark_unsupported_alias(
                    "z_history_alias",
                    variant == 0
                        ? "z_history_alias_target"
                        : variant == 1
                              ? "z_history_alias_wrong"
                              : "z_history_alias_third");
                break;
            case family_t::security:
                reconciliation.mark_security_regression(
                    "z_history_security",
                    variant == 0
                        ? "short security evidence"
                        : variant == 1
                              ? "deterministically stronger retained security evidence"
                              : "intermediate security evidence");
                break;
            }
        };

        for (const auto event : order) {
            if (event == 0 || event == 8) {
                mark_family(0);
            } else if (event == 6) {
                mark_family(1);
            } else if (event == 7) {
                mark_family(2);
            } else {
                const auto suffix = std::to_string(event - 1);
                reconciliation.mark_security_regression(
                    "a_history_interposition_" + suffix,
                    "security interposition evidence " + suffix);
            }
        }
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(equal_results(first, second),
                "permanent auxiliary history changed across repeated reconciliation");
        return first;
    };

    constexpr std::array<family_t, 5> families = {
        family_t::dead, family_t::duplicate, family_t::schema,
        family_t::alias, family_t::security
    };
    for (const auto family : families) {
        for (std::size_t capacity = 1; capacity <= 5; ++capacity) {
            surface_reconciliation_result_t canonical;
            bool have_canonical = false;
            for (const auto& order : orders) {
                const auto result = exercise(family, capacity, order, 0);
                const auto identifier =
                    family == family_t::dead
                        ? "z_history_dead"
                        : family == family_t::duplicate
                              ? "z_history_duplicate"
                              : family == family_t::schema
                                    ? "z_history_schema"
                                    : family == family_t::alias
                                          ? "z_history_alias"
                                          : "z_history_security";
                const auto collection =
                    family == family_t::dead
                        ? "dead_replaced_paths"
                        : family == family_t::duplicate
                              ? "duplicate_stores"
                              : family == family_t::schema
                                    ? "old_schema_v8_writers"
                                    : family == family_t::alias
                                          ? "unsupported_aliases"
                                          : "security_regressions";
                const auto& invalid = require_finding(
                    result, surface_error_code_t::invalid_surface_marker,
                    identifier);
                require_detail(
                    invalid,
                    "surface marker rejected; collection=" +
                        std::string(collection) +
                        ", reason=conflicting_duplicate_marker, malformed=1");
                require(result.attempted_auxiliary_markers == 9 &&
                            result.rejected_auxiliary_markers == 9 - capacity &&
                            result.unexplained_removals ==
                                (family == family_t::dead ||
                                         family == family_t::alias
                                     ? 1U
                                     : 0U) &&
                            result.findings_produced ==
                                capacity +
                                    (family == family_t::duplicate ? 2U : 3U) &&
                            result.findings_discarded == 0 &&
                            result.findings.size() ==
                                capacity +
                                    (family == family_t::duplicate ? 2U : 3U) &&
                            result.malformed_markers == 1 &&
                            result.auxiliary_cap_exceeded &&
                            !result.baseline_cap_exceeded &&
                            !result.actual_cap_exceeded &&
                            !result.metrics_saturated && !result.clean,
                        "permanent auxiliary history metric contract is incorrect");
                const auto overflow_collection =
                    family == family_t::dead
                        ? "dead_replaced_paths"
                        : family == family_t::duplicate
                              ? "duplicate_stores"
                              : family == family_t::schema
                                    ? "old_schema_v8_writers"
                                    : family == family_t::alias && capacity == 5
                                          ? "unsupported_aliases"
                                          : "security_regressions";
                const auto& overflow = require_finding(
                    result,
                    surface_error_code_t::auxiliary_marker_cap_exceeded,
                    overflow_collection);
                require_detail(
                    overflow,
                    "shared auxiliary marker capacity exceeded; attempted=9, rejected=" +
                        std::to_string(9 - capacity));
                require(finding_count(
                            result,
                            surface_error_code_t::security_regression_detected) ==
                            capacity +
                                (family == family_t::security
                                     ? std::size_t{1}
                                     : std::size_t{0}),
                        "security interposition retention is incorrect");

                if (family == family_t::dead) {
                    require_finding(
                        result,
                        surface_error_code_t::unexplained_removal_detected,
                        "z_history_dead");
                    require_no_finding(
                        result,
                        surface_error_code_t::dead_replaced_path_detected,
                        "z_history_dead");
                } else if (family == family_t::duplicate) {
                    require_no_finding(
                        result,
                        surface_error_code_t::duplicate_store_detected,
                        "z_history_duplicate");
                } else if (family == family_t::schema) {
                    require_finding(
                        result, surface_error_code_t::baseline_mismatch,
                        "z_history_schema");
                } else if (family == family_t::alias) {
                    require_finding(
                        result,
                        surface_error_code_t::unexplained_removal_detected,
                        "z_history_alias");
                    require_no_finding(
                        result,
                        surface_error_code_t::unsupported_alias_detected,
                        "z_history_alias");
                } else {
                    const auto& security = require_finding(
                        result,
                        surface_error_code_t::security_regression_detected,
                        "z_history_security");
                    require_detail(
                        security,
                        "security regression: deterministically stronger retained security evidence");
                }
                if (!have_canonical) {
                    canonical = result;
                    have_canonical = true;
                } else {
                    require(equal_results(canonical, result),
                            "permanent auxiliary history depends on eviction order");
                }
            }
        }
    }

    surface_reconciliation_result_t saturated_canonical;
    bool have_saturated_canonical = false;
    for (const auto& order : orders) {
        const auto result = exercise(family_t::security, 1, order, 2);
        require(result.attempted_auxiliary_markers == 2 &&
                    result.rejected_auxiliary_markers == 2 &&
                    result.malformed_markers == 1 &&
                    result.metrics_saturated && !result.clean,
                "permanent auxiliary history saturation contract is incorrect");
        require_finding(
            result, surface_error_code_t::internal_error,
            "metrics_saturated");
        require_finding(
            result, surface_error_code_t::security_regression_detected,
            "z_history_security");
        if (!have_saturated_canonical) {
            saturated_canonical = result;
            have_saturated_canonical = true;
        } else {
            require(equal_results(saturated_canonical, result),
                    "saturated auxiliary history depends on eviction order");
        }
    }

    const auto exercise_history_limit = [](bool reverse,
                                           std::size_t finding_limit) {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 100000;
        limits.maximum_findings = finding_limit;
        surface_reconciliation_t reconciliation(limits);
        const auto add_security = [&] {
            reconciliation.mark_security_regression(
                "history_limit_security", "retained security evidence");
        };
        if (!reverse)
            add_security();
        for (std::size_t index = 0; index < 100000; ++index) {
            const auto value = reverse
                ? std::size_t{99999} - index
                : index;
            reconciliation.mark_stale_registration(
                "history_limit_stale_" + std::to_string(value));
        }
        if (reverse)
            add_security();
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(equal_results(first, second),
                "history-limit fail-closure changed across repeated reconciliation");
        return first;
    };
    const auto require_history_security = [](const auto& result) {
        require(semantic_finding_count(
                    result,
                    surface_finding_semantic_t::auxiliary_security_incomplete) == 1,
                "history fail-closure did not retain one semantic security finding");
        const auto& finding = require_semantic_finding(
            result,
            surface_finding_semantic_t::auxiliary_security_incomplete);
        require(finding.code ==
                    surface_error_code_t::security_regression_detected &&
                    finding.stable_code == "security_regression_detected" &&
                    finding.identifier == "auxiliary_security_evidence" &&
                    finding.canonical_path.empty() &&
                    finding.kind == surface_entry_kind_t::security_guard &&
                    finding.severity == 1000 &&
                    result.findings.front().semantic ==
                        surface_finding_semantic_t::auxiliary_security_incomplete,
                "history fail-closure security classification is incorrect");
        require_detail(
            finding,
            "security regression evidence is present but detailed auxiliary history is incomplete; auxiliary marker capacity and metric accounting failed closed");
    };
    const auto require_metric_semantic = [](const auto& result) {
        require(semantic_finding_count(
                    result,
                    surface_finding_semantic_t::metrics_saturation) == 1,
                "history fail-closure did not retain one metric finding");
        const auto& finding = require_semantic_finding(
            result, surface_finding_semantic_t::metrics_saturation);
        require(finding.code == surface_error_code_t::internal_error &&
                    finding.stable_code == "internal_error" &&
                    finding.identifier == "metrics_saturated" &&
                    finding.canonical_path.empty() &&
                    finding.kind ==
                        surface_entry_kind_t::contract_registration &&
                    finding.severity == 1000,
                "history fail-closure metric classification is incorrect");
    };

    const auto require_history_incomplete_metrics = [](const auto& result) {
        require(result.attempted_auxiliary_markers == 100001 &&
                    result.rejected_auxiliary_markers ==
                    std::numeric_limits<std::uint64_t>::max() &&
                    result.malformed_markers == 0 &&
                    result.auxiliary_cap_exceeded &&
                    result.metrics_saturated && !result.clean,
                "bounded history-incomplete metrics are incorrect");
        require_no_finding(
            result, surface_error_code_t::invalid_surface_marker);
    };

    const auto history_limit_one_forward =
        exercise_history_limit(false, 1);
    const auto history_limit_one_reverse =
        exercise_history_limit(true, 1);
    require(equal_results(
                history_limit_one_forward, history_limit_one_reverse),
            "single-finding history fail-closure depends on input order");
    require_history_incomplete_metrics(history_limit_one_forward);
    require(history_limit_one_forward.finding_cap_exceeded &&
                history_limit_one_forward.findings.size() == 1 &&
                history_limit_one_forward.findings_produced == 5 &&
                history_limit_one_forward.findings_discarded == 4,
            "single-finding history fail-closure retention is incorrect");
    require_history_security(history_limit_one_forward);
    require(semantic_finding_count(
                history_limit_one_forward,
                surface_finding_semantic_t::metrics_saturation) == 0 &&
                semantic_finding_count(
                    history_limit_one_forward,
                    surface_finding_semantic_t::finding_capacity) == 0,
            "single-finding history retention kept a weaker mandatory diagnostic");
    require_no_finding(
        history_limit_one_forward,
        surface_error_code_t::auxiliary_marker_cap_exceeded);
    require_no_finding(
        history_limit_one_forward, surface_error_code_t::internal_error,
        "metrics_saturated");

    const auto history_limit_two_forward =
        exercise_history_limit(false, 2);
    const auto history_limit_two_reverse =
        exercise_history_limit(true, 2);
    require(equal_results(
                history_limit_two_forward, history_limit_two_reverse),
            "two-finding history fail-closure depends on input order");
    require_history_incomplete_metrics(history_limit_two_forward);
    require(history_limit_two_forward.finding_cap_exceeded &&
                history_limit_two_forward.findings.size() == 2 &&
                history_limit_two_forward.findings_produced == 4 &&
                history_limit_two_forward.findings_discarded == 2,
            "two-finding history fail-closure retention is incorrect");
    require_history_security(history_limit_two_forward);
    require_metric_semantic(history_limit_two_forward);
    require(history_limit_two_forward.findings[0].semantic ==
                    surface_finding_semantic_t::auxiliary_security_incomplete &&
                history_limit_two_forward.findings[1].semantic ==
                    surface_finding_semantic_t::metrics_saturation,
            "two-finding history fail-closure order is incorrect");
    require(semantic_finding_count(
                history_limit_two_forward,
                surface_finding_semantic_t::finding_capacity) == 0,
            "two-finding history retention kept the weaker cap marker");
    require_no_finding(
        history_limit_two_forward,
        surface_error_code_t::auxiliary_marker_cap_exceeded);

    const auto exercise_value_history_limit = [](bool reverse) {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 100000;
        limits.maximum_findings = 3;
        surface_reconciliation_t reconciliation(limits);
        for (std::size_t index = 0; index <= 100000; ++index) {
            const auto value = reverse
                ? std::size_t{100000} - index
                : index;
            reconciliation.mark_security_regression(
                "value_history_security",
                "value history security evidence " + std::to_string(value));
        }
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(equal_results(first, second),
                "value-history fail-closure changed across repeated reconciliation");
        return first;
    };
    const auto value_history_forward = exercise_value_history_limit(false);
    const auto value_history_reverse = exercise_value_history_limit(true);
    require(equal_results(value_history_forward, value_history_reverse),
            "value-history fail-closure depends on insertion order");
    require_history_incomplete_metrics(value_history_forward);
    require(value_history_forward.findings_produced == 3 &&
                value_history_forward.findings_discarded == 0 &&
                value_history_forward.findings.size() == 3 &&
                !value_history_forward.finding_cap_exceeded,
            "three-finding value-history retention is incorrect");
    const auto& capacity = require_finding(
        value_history_forward,
        surface_error_code_t::auxiliary_marker_cap_exceeded,
        "auxiliary_marker_history");
    require(capacity.semantic == surface_finding_semantic_t::ordinary,
            "history capacity evidence has the wrong semantic identity");
    require_contains(capacity, "attempted=100001");
    require_history_security(value_history_forward);
    require_metric_semantic(value_history_forward);
    require(value_history_forward.findings[0].semantic ==
                    surface_finding_semantic_t::auxiliary_security_incomplete &&
                value_history_forward.findings[1].semantic ==
                    surface_finding_semantic_t::metrics_saturation &&
                value_history_forward.findings[2].code ==
                    surface_error_code_t::auxiliary_marker_cap_exceeded &&
                value_history_forward.findings[2].semantic ==
                    surface_finding_semantic_t::ordinary,
            "three-finding history fail-closure order is incorrect");
    require(semantic_finding_count(
                value_history_forward,
                surface_finding_semantic_t::finding_capacity) == 0,
            "three-finding history retention fabricated a cap marker");
}

void verify_diagnostic_families() {
    surface_reconciliation_t reconciliation;

    auto dead = make_entry(
        "dead_active", "surface/dead_active.cpp",
        surface_entry_kind_t::source_file);
    reconciliation.register_actual_entry(dead);
    reconciliation.register_actual_entry(make_entry(
        "dead_active_target", "surface/dead_active_target.cpp",
        surface_entry_kind_t::source_file));
    reconciliation.mark_dead_replaced_path("dead_active", "dead_active_target");

    reconciliation.mark_duplicate_store(
        "duplicate_marker", "surface/duplicate_marker.cpp");

    auto stale = make_entry(
        "stale_active", "surface/stale_active.cpp",
        surface_entry_kind_t::handler_registration);
    reconciliation.register_actual_entry(stale);
    reconciliation.mark_stale_registration("stale_active");

    reconciliation.register_actual_entry(make_entry(
        "schema_v8", "surface/schema_v8.cpp",
        surface_entry_kind_t::schema_writer, true, "v8"));

    reconciliation.register_actual_entry(make_entry(
        "legacy_active", "surface/legacy_active.cpp",
        surface_entry_kind_t::ast_path));
    reconciliation.mark_legacy_invalid_ast_flow("legacy_active");

    reconciliation.register_actual_entry(make_entry(
        "alias_active", "surface/alias_active.cpp",
        surface_entry_kind_t::alias_mapping));
    reconciliation.register_actual_entry(make_entry(
        "alias_active_target", "surface/alias_active_target.cpp",
        surface_entry_kind_t::handler_registration));
    reconciliation.mark_unsupported_alias("alias_active", "alias_active_target");

    reconciliation.register_actual_entry(make_entry(
        "inactive_guard", "surface/inactive_guard.cpp",
        surface_entry_kind_t::security_guard, false));

    reconciliation.register_baseline_entry(make_entry(
        "unexplained", "surface/unexplained.cpp",
        surface_entry_kind_t::source_file));

    const auto result = reconciliation.reconcile();
    require_finding(result, surface_error_code_t::dead_replaced_path_detected,
                    "dead_active");
    require_finding(result, surface_error_code_t::duplicate_store_detected,
                    "duplicate_marker");
    require_finding(result, surface_error_code_t::stale_registration_detected,
                    "stale_active");
    require_finding(result, surface_error_code_t::old_schema_v8_writer_detected,
                    "schema_v8");
    require_finding(result,
                    surface_error_code_t::legacy_invalid_ast_flow_detected,
                    "legacy_active");
    require_finding(result, surface_error_code_t::unsupported_alias_detected,
                    "alias_active");
    require_finding(result, surface_error_code_t::security_regression_detected,
                    "inactive_guard");
    require_finding(result, surface_error_code_t::unexplained_removal_detected,
                    "unexplained");
    require(result.unexplained_removals == 1,
            "unexplained removal aggregate is incorrect");
}

void require_metrics_at_most(
    const surface_reconciliation_result_t& result, std::uint64_t maximum) {
    const std::array<std::uint64_t, 14> metrics = {
        result.total_entries_checked,
        result.baseline_entry_count,
        result.actual_entry_count,
        result.unexplained_removals,
        result.attempted_baseline_entries,
        result.attempted_actual_entries,
        result.rejected_baseline_entries,
        result.rejected_actual_entries,
        result.attempted_auxiliary_markers,
        result.rejected_auxiliary_markers,
        result.findings_produced,
        result.findings_discarded,
        result.malformed_entries,
        result.malformed_markers
    };
    require(std::all_of(metrics.begin(), metrics.end(), [maximum](auto value) {
                return value <= maximum;
            }),
            "reconciliation metric exceeded its configured ceiling");
}

void verify_bounded_internal_finding_identity() {
    constexpr std::string_view metric_identifier = "metrics_saturated";
    constexpr std::string_view metric_detail =
        "one or more reconciliation metrics reached the configured ceiling of 1";
    constexpr std::array<std::string_view, 4> security_identifiers = {
        "a", "b", "c", "d"
    };

    for (std::size_t identifier_bound = 1; identifier_bound <= 16;
         ++identifier_bound) {
        for (std::size_t finding_bound = 1; finding_bound <= 3;
             ++finding_bound) {
            const auto exercise = [identifier_bound, finding_bound,
                                   &security_identifiers](bool reverse) {
                surface_reconciliation_limits_t limits;
                limits.maximum_findings = finding_bound;
                limits.maximum_identifier_bytes = identifier_bound;
                limits.maximum_text_bytes = identifier_bound;
                limits.maximum_metric_value = 1;
                surface_reconciliation_t reconciliation(limits);
                if (reverse) {
                    for (auto identifier = security_identifiers.rbegin();
                         identifier != security_identifiers.rend(); ++identifier) {
                        reconciliation.mark_security_regression(*identifier, "x");
                    }
                } else {
                    for (const auto identifier : security_identifiers)
                        reconciliation.mark_security_regression(identifier, "x");
                }
                const auto first = reconciliation.reconcile();
                const auto second = reconciliation.reconcile();
                require(equal_results(first, second),
                        "bounded internal semantic changed across reconciliation");
                return first;
            };

            const auto forward = exercise(false);
            const auto reverse = exercise(true);
            require(equal_results(forward, reverse),
                    "bounded internal semantic depends on input order");
            require(forward.metrics_saturated &&
                        forward.finding_cap_exceeded &&
                        forward.findings.size() == finding_bound &&
                        !forward.clean,
                    "bounded metric and finding-cap disposition is incorrect");
            require(semantic_finding_count(
                        forward,
                        surface_finding_semantic_t::metrics_saturation) == 1 &&
                        finding_count(
                            forward, surface_error_code_t::internal_error) == 1,
                    "bounded metric semantic was duplicated or discarded");
            const auto& metric = require_semantic_finding(
                forward, surface_finding_semantic_t::metrics_saturation);
            require(metric.code == surface_error_code_t::internal_error &&
                        metric.stable_code == "internal_error" &&
                        metric.identifier == std::string(
                            metric_identifier.substr(0, identifier_bound)) &&
                        metric.detail == std::string(
                            metric_detail.substr(0, identifier_bound)) &&
                        metric.canonical_path.empty() &&
                        metric.kind ==
                            surface_entry_kind_t::contract_registration &&
                        metric.severity == 1000,
                    "bounded metric evidence lost semantic or display identity");
            const auto expected_capacity_count =
                finding_bound >= 2 ? std::size_t{1} : std::size_t{0};
            const auto expected_security_count =
                finding_bound == 3 ? std::size_t{1} : std::size_t{0};
            require(semantic_finding_count(
                        forward,
                        surface_finding_semantic_t::finding_capacity) ==
                        expected_capacity_count &&
                        finding_count(
                            forward,
                            surface_error_code_t::finding_cap_exceeded) ==
                        expected_capacity_count &&
                        finding_count(
                            forward,
                            surface_error_code_t::security_regression_detected) ==
                        expected_security_count &&
                        semantic_finding_count(
                            forward,
                            surface_finding_semantic_t::ordinary) ==
                        expected_security_count &&
                        semantic_finding_count(
                            forward,
                            surface_finding_semantic_t::auxiliary_security_incomplete) ==
                        0,
                    "finding-cap retention erased or demoted metric evidence");
            if (finding_bound == 1) {
                require(forward.findings[0].semantic ==
                            surface_finding_semantic_t::metrics_saturation,
                        "single-slot bounded finding order is incorrect");
            } else if (finding_bound == 2) {
                require(forward.findings[0].semantic ==
                                surface_finding_semantic_t::metrics_saturation &&
                            forward.findings[1].semantic ==
                                surface_finding_semantic_t::finding_capacity,
                        "two-slot bounded finding order is incorrect");
            } else {
                require(forward.findings[0].code ==
                                surface_error_code_t::security_regression_detected &&
                            forward.findings[0].semantic ==
                                surface_finding_semantic_t::ordinary &&
                            forward.findings[1].semantic ==
                                surface_finding_semantic_t::metrics_saturation &&
                            forward.findings[2].semantic ==
                                surface_finding_semantic_t::finding_capacity,
                        "three-slot bounded finding order is incorrect");
            }
            if (expected_capacity_count != 0) {
                const auto& capacity = require_semantic_finding(
                    forward, surface_finding_semantic_t::finding_capacity);
                constexpr std::string_view capacity_identifier =
                    "surface_findings";
                constexpr std::string_view capacity_detail =
                    "finding capacity exceeded";
                require(capacity.code ==
                                surface_error_code_t::finding_cap_exceeded &&
                            capacity.stable_code == "finding_cap_exceeded" &&
                            capacity.identifier == std::string(
                                capacity_identifier.substr(0, identifier_bound)) &&
                            capacity.detail == std::string(
                                capacity_detail.substr(0, identifier_bound)) &&
                            capacity.canonical_path.empty() &&
                            capacity.kind ==
                                surface_entry_kind_t::contract_registration &&
                            capacity.severity == 1000,
                        "bounded capacity evidence lost semantic or display identity");
            }
        }
    }
}

void verify_metric_saturation() {
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_entries = 16;
        limits.maximum_findings = 16;
        limits.maximum_metric_value = 1;
        surface_reconciliation_t reconciliation(limits);
        for (int index = 0; index < 3; ++index) {
            auto entry = make_entry(
                "metric_" + std::to_string(index),
                "surface/metric_" + std::to_string(index) + ".cpp",
                surface_entry_kind_t::source_file);
            reconciliation.register_baseline_entry(entry);
            reconciliation.register_actual_entry(entry);
        }
        for (int index = 0; index < 2; ++index) {
            auto invalid = make_entry(
                "invalid metric " + std::to_string(index),
                "surface/invalid_metric.cpp", surface_entry_kind_t::source_file);
            reconciliation.register_baseline_entry(invalid);
            reconciliation.register_actual_entry(invalid);
            reconciliation.register_baseline_entry(make_entry(
                "orphan_metric_" + std::to_string(index),
                "surface/orphan_metric_" + std::to_string(index) + ".cpp",
                surface_entry_kind_t::source_file));
            reconciliation.mark_security_regression(
                "metric_security_" + std::to_string(index), "adverse fixture");
            reconciliation.mark_stale_registration("invalid metric marker");
        }
        const auto first = reconciliation.reconcile();
        const auto second = reconciliation.reconcile();
        require(first.metrics_saturated && second.metrics_saturated &&
                    !first.clean && first.findings.size() > 1,
                "metric saturation did not fail closed without truncating reconciliation");
        require_metrics_at_most(first, 1);
        require_metrics_at_most(second, 1);
        const auto& saturation = require_finding(
            first, surface_error_code_t::internal_error, "metrics_saturated");
        require_detail(
            saturation,
            "one or more reconciliation metrics reached the configured ceiling of 1");
        require(reconciliation.reconciliations_performed() == 1 &&
                    reconciliation.total_findings() == 1,
                "atomic reconciliation metrics did not saturate at the configured ceiling");
    }
    {
        surface_reconciliation_limits_t limits;
        limits.maximum_findings = 2;
        limits.maximum_metric_value = 1;
        surface_reconciliation_t reconciliation(limits);
        for (int index = 0; index < 5; ++index) {
            reconciliation.mark_security_regression(
                "bounded_metric_" + std::to_string(index), "adverse fixture");
        }
        const auto result = reconciliation.reconcile();
        require(result.metrics_saturated && result.finding_cap_exceeded &&
                    result.findings.size() == 2 && !result.clean,
                "combined metric and finding saturation did not fail closed");
        require_metrics_at_most(result, 1);
        require_finding(result, surface_error_code_t::internal_error,
                        "metrics_saturated");
        require_finding(result, surface_error_code_t::finding_cap_exceeded,
                        "surface_findings");
    }
}

}

void run_surface_reconciliation_harness() {
    verify_stable_protocol();
    verify_clean_boundaries_and_determinism();
    verify_semantic_drift_and_security_precedence();
    verify_lawful_migrations();
    verify_inactive_actual_proof_closure();
    verify_schema_migration_predicate();
    verify_stale_registration_proofs();
    verify_replacement_target_graph();
    verify_baseline_only_retirement_rejection();
    verify_schema_identity_and_proof_matrix();
    verify_alias_proof_matrix();
    verify_cross_proof_exclusion_matrix();
    verify_same_key_conflict_invalidation();
    verify_security_evidence_deduplication();
    verify_security_conflict_and_intrinsic_priority();
    verify_security_priority_finding_caps();
    verify_finding_source_fidelity();
    verify_duplicate_identity_contract();
    verify_limits_and_finding_cap();
    verify_invalid_entries();
    verify_marker_validation_and_capacity();
    verify_canonical_invalid_and_overflow_evidence();
    verify_auxiliary_security_priority();
    verify_permanent_auxiliary_history();
    verify_diagnostic_families();
    verify_bounded_internal_finding_identity();
    verify_metric_saturation();
}

}

int main() {
    try {
        aida::analysis::c03_test::run_surface_reconciliation_harness();
        std::cout << "surface_reconciliation_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
