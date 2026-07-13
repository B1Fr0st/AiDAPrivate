#include "surface_reconciliation_harness.hpp"

#include "../../src/core/analysis/surface_reconciliation.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using namespace aida::analysis::c03;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

surface_entry_t make_entry(std::string id, std::string path,
                            surface_entry_kind_t kind,
                            bool active = true,
                            std::string schema_version = "") {
    surface_entry_t entry;
    entry.identifier = std::move(id);
    entry.canonical_path = std::move(path);
    entry.kind = kind;
    entry.is_active = active;
    entry.schema_version = std::move(schema_version);
    return entry;
}

void verify_clean_reconciliation() {
    surface_reconciliation_t recon;

    for (int i = 0; i < 10; ++i) {
        auto entry = make_entry(
            "entry_" + std::to_string(i),
            "src/core/analysis/file_" + std::to_string(i) + ".cpp",
            surface_entry_kind_t::source_file);
        recon.register_baseline_entry(entry);
        recon.register_actual_entry(entry);
    }

    auto result = recon.reconcile();
    require(result.clean, "clean surface reconciliation returned findings");
    require(result.findings.empty(), "clean reconciliation produced non-empty findings");
    require(result.unexplained_removals == 0,
            "clean reconciliation detected unexplained removals");
    require(result.total_entries_checked == 20,
            "clean reconciliation entry count mismatch");
}

void verify_dead_replaced_path_detected() {
    surface_reconciliation_t recon;

    auto old_entry = make_entry("old_decoder", "src/core/analysis/old_decoder.cpp",
                                 surface_entry_kind_t::source_file, true);
    auto new_entry = make_entry("new_decoder", "src/core/analysis/new_decoder.cpp",
                                 surface_entry_kind_t::source_file, true);

    recon.register_baseline_entry(old_entry);
    recon.register_actual_entry(old_entry);
    recon.register_actual_entry(new_entry);

    recon.mark_dead_replaced_path("old_decoder", "new_decoder");

    auto result = recon.reconcile();
    require(!result.clean, "dead replaced path was not detected");

    bool found_dead = false;
    for (const auto& finding : result.findings) {
        if (finding.code == surface_error_code_t::dead_replaced_path_detected &&
            finding.identifier == "old_decoder") {
            found_dead = true;
            require(finding.severity == 500, "dead path finding severity mismatch");
        }
    }
    require(found_dead, "dead_replaced_path_detected finding was not emitted");
}

void verify_duplicate_store_detected() {
    surface_reconciliation_t recon;

    auto store1 = make_entry("packed_store", "src/core/analysis/packed_store.cpp",
                              surface_entry_kind_t::store_definition, true);
    auto store2 = make_entry("packed_store", "src/core/analysis/workspace/packed_store.cpp",
                              surface_entry_kind_t::store_definition, true);

    recon.register_actual_entry(store1);
    recon.register_actual_entry(store2);

    auto result = recon.reconcile();
    require(!result.clean, "duplicate store was not detected");

    bool found_dup = false;
    for (const auto& finding : result.findings) {
        if (finding.code == surface_error_code_t::duplicate_store_detected &&
            finding.identifier == "packed_store") {
            found_dup = true;
        }
    }
    require(found_dup, "duplicate_store_detected finding was not emitted");
}

void verify_stale_registration_detected() {
    surface_reconciliation_t recon;

    auto reg = make_entry("old_handler", "src/core/mcp/compat/handlers/old.cpp",
                           surface_entry_kind_t::handler_registration, true);
    recon.register_baseline_entry(reg);
    recon.register_actual_entry(reg);
    recon.mark_stale_registration("old_handler");

    auto result = recon.reconcile();
    require(!result.clean, "stale registration was not detected");

    bool found_stale = false;
    for (const auto& finding : result.findings) {
        if (finding.code == surface_error_code_t::stale_registration_detected &&
            finding.identifier == "old_handler") {
            found_stale = true;
        }
    }
    require(found_stale, "stale_registration_detected finding was not emitted");

    surface_reconciliation_t recon2;
    auto baseline_reg = make_entry("missing_handler", "src/core/mcp/compat/handlers/missing.cpp",
                                    surface_entry_kind_t::handler_registration, true);
    recon2.register_baseline_entry(baseline_reg);
    auto result2 = recon2.reconcile();
    bool found_missing = false;
    for (const auto& finding : result2.findings) {
        if (finding.code == surface_error_code_t::stale_registration_detected &&
            finding.identifier == "missing_handler") {
            found_missing = true;
        }
    }
    require(found_missing, "missing baseline registration was not detected as stale");
}

void verify_old_schema_v8_writer_detected() {
    surface_reconciliation_t recon;

    auto v8_writer = make_entry("legacy_schema_writer",
                                 "src/core/analysis/workspace/old_schema.cpp",
                                 surface_entry_kind_t::schema_writer, true, "v8");
    auto v9_writer = make_entry("current_schema_writer",
                                 "src/core/analysis/workspace/workspace_schema_v9.cpp",
                                 surface_entry_kind_t::schema_writer, true, "v9");

    recon.register_actual_entry(v8_writer);
    recon.register_actual_entry(v9_writer);

    auto result = recon.reconcile();
    require(!result.clean, "old schema v8 writer was not detected");

    bool found_v8 = false;
    for (const auto& finding : result.findings) {
        if (finding.code == surface_error_code_t::old_schema_v8_writer_detected &&
            finding.identifier == "legacy_schema_writer") {
            found_v8 = true;
            require(finding.severity == 700, "v8 writer severity mismatch");
        }
    }
    require(found_v8, "old_schema_v8_writer_detected finding was not emitted");

    bool found_v9 = false;
    for (const auto& finding : result.findings) {
        if (finding.identifier == "current_schema_writer" &&
            finding.code == surface_error_code_t::old_schema_v8_writer_detected) {
            found_v9 = true;
        }
    }
    require(!found_v9, "v9 writer was incorrectly flagged as v8");
}

void verify_legacy_invalid_ast_flow_detected() {
    surface_reconciliation_t recon;

    auto ast = make_entry("typed_ast_v1", "src/core/analysis/decompiler/typed_ast_v1.cpp",
                           surface_entry_kind_t::ast_path, true);
    recon.register_actual_entry(ast);
    recon.mark_legacy_invalid_ast_flow("typed_ast_v1");

    auto result = recon.reconcile();
    require(!result.clean, "legacy invalid AST flow was not detected");

    bool found_legacy = false;
    for (const auto& finding : result.findings) {
        if (finding.code == surface_error_code_t::legacy_invalid_ast_flow_detected &&
            finding.identifier == "typed_ast_v1") {
            found_legacy = true;
        }
    }
    require(found_legacy, "legacy_invalid_ast_flow_detected finding was not emitted");
}

void verify_unsupported_alias_detected() {
    surface_reconciliation_t recon;

    auto alias = make_entry("set_comment", "src/core/mcp/compat/handlers/modify.cpp",
                             surface_entry_kind_t::alias_mapping, true);
    recon.register_actual_entry(alias);
    recon.mark_unsupported_alias("set_comment", "comment");

    auto result = recon.reconcile();
    require(!result.clean, "unsupported alias was not detected");

    bool found_alias = false;
    for (const auto& finding : result.findings) {
        if (finding.code == surface_error_code_t::unsupported_alias_detected &&
            finding.identifier == "set_comment") {
            found_alias = true;
        }
    }
    require(found_alias, "unsupported_alias_detected finding was not emitted");
}

void verify_security_regression_detected() {
    surface_reconciliation_t recon;

    auto active_guard = make_entry("license_check", "src/core/runtime/standalone_license.cpp",
                                    surface_entry_kind_t::security_guard, true);
    auto inactive_guard = make_entry("arc_check", "src/core/runtime/standalone_anti_tamper.cpp",
                                      surface_entry_kind_t::security_guard, false);
    inactive_guard.security_note = "disabled during development";

    recon.register_baseline_entry(active_guard);
    recon.register_actual_entry(active_guard);
    recon.register_actual_entry(inactive_guard);

    auto result = recon.reconcile();
    require(!result.clean, "security regression was not detected");

    bool found_regression = false;
    for (const auto& finding : result.findings) {
        if (finding.code == surface_error_code_t::security_regression_detected &&
            finding.identifier == "arc_check") {
            found_regression = true;
            require(finding.severity == 900, "security regression severity mismatch");
        }
    }
    require(found_regression, "security_regression_detected finding was not emitted");
}

void verify_unexplained_removal_detected() {
    surface_reconciliation_t recon;

    auto entry1 = make_entry("important_handler",
                              "src/core/mcp/compat/handlers/core.cpp",
                              surface_entry_kind_t::handler_registration, true);
    auto entry2 = make_entry("replaced_handler",
                              "src/core/mcp/compat/handlers/old_route.cpp",
                              surface_entry_kind_t::source_file, true);

    recon.register_baseline_entry(entry1);
    recon.register_baseline_entry(entry2);

    recon.register_actual_entry(entry1);
    recon.mark_dead_replaced_path("replaced_handler", "new_route");

    auto result = recon.reconcile();
    require(result.unexplained_removals == 0,
            "explained removal was counted as unexplained");

    surface_reconciliation_t recon2;
    auto removed = make_entry("mystery_handler",
                               "src/core/mcp/compat/handlers/mystery.cpp",
                               surface_entry_kind_t::handler_registration, true);
    recon2.register_baseline_entry(removed);

    auto result2 = recon2.reconcile();
    require(result2.unexplained_removals == 1,
            "unexplained removal was not counted");

    bool found_unexplained = false;
    for (const auto& finding : result2.findings) {
        if (finding.code == surface_error_code_t::unexplained_removal_detected &&
            finding.identifier == "mystery_handler") {
            found_unexplained = true;
            require(finding.severity == 800, "unexplained removal severity mismatch");
        }
    }
    require(found_unexplained, "unexplained_removal_detected finding was not emitted");
}

void verify_stable_code_mapping() {
    require(surface_reconciliation_t::stable_code_for(
        surface_error_code_t::none) == "none",
        "stable code for 'none' mismatch");
    require(surface_reconciliation_t::stable_code_for(
        surface_error_code_t::dead_replaced_path_detected) == "dead_replaced_path_detected",
        "stable code for dead_replaced_path_detected mismatch");
    require(surface_reconciliation_t::stable_code_for(
        surface_error_code_t::security_regression_detected) == "security_regression_detected",
        "stable code for security_regression_detected mismatch");
    require(surface_reconciliation_t::stable_code_for(
        surface_error_code_t::unexplained_removal_detected) == "unexplained_removal_detected",
        "stable code for unexplained_removal_detected mismatch");
}

void verify_entry_kind_names() {
    require(surface_reconciliation_t::entry_kind_name(
        surface_entry_kind_t::source_file) == "source_file",
        "entry kind name for source_file mismatch");
    require(surface_reconciliation_t::entry_kind_name(
        surface_entry_kind_t::schema_writer) == "schema_writer",
        "entry kind name for schema_writer mismatch");
    require(surface_reconciliation_t::entry_kind_name(
        surface_entry_kind_t::security_guard) == "security_guard",
        "entry kind name for security_guard mismatch");
    require(surface_reconciliation_t::entry_kind_name(
        surface_entry_kind_t::store_definition) == "store_definition",
        "entry kind name for store_definition mismatch");
}

void verify_counters_track() {
    surface_reconciliation_t recon;

    for (int i = 0; i < 5; ++i) {
        auto entry = make_entry("entry_" + std::to_string(i),
                                 "path_" + std::to_string(i) + ".cpp",
                                 surface_entry_kind_t::source_file);
        recon.register_baseline_entry(entry);
        recon.register_actual_entry(entry);
    }

    require(recon.baseline_entry_count() == 5, "baseline entry count mismatch");
    require(recon.actual_entry_count() == 5, "actual entry count mismatch");

    recon.reconcile();
    require(recon.reconciliations_performed() == 1,
            "reconciliation counter did not track");
    require(recon.total_findings() == 0,
            "total findings counter should be zero for clean reconciliation");

    recon.mark_security_regression("test_regression", "weakened check");
    auto result = recon.reconcile();
    require(recon.reconciliations_performed() == 2,
            "reconciliation counter did not track second call");
    require(recon.total_findings() >= 1,
            "total findings counter should be non-zero after finding");
}

}

void run_surface_reconciliation_harness() {
    verify_clean_reconciliation();
    verify_dead_replaced_path_detected();
    verify_duplicate_store_detected();
    verify_stale_registration_detected();
    verify_old_schema_v8_writer_detected();
    verify_legacy_invalid_ast_flow_detected();
    verify_unsupported_alias_detected();
    verify_security_regression_detected();
    verify_unexplained_removal_detected();
    verify_stable_code_mapping();
    verify_entry_kind_names();
    verify_counters_track();
}

}

int main() {
    try {
        aida::analysis::c03_test::run_surface_reconciliation_harness();
        std::cout << "surface_reconciliation_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
