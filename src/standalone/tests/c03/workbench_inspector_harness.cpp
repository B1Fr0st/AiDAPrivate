#include "workbench_inspector_harness.h"

#include "../../src/core/workbench/inspector/workbench_inspector_contracts.hpp"

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace workbench {
namespace inspector {
namespace {

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

inspector_context_t make_context(workspace_id_t workspace,
                                 std::uint64_t workspace_generation,
                                 std::uint64_t selection_generation,
                                 std::uint64_t address)
{
    inspector_context_t context;
    context.workspace = workspace;
    context.workspace_generation = {workspace_generation};
    context.document.workspace = workspace;
    context.document.kind = document_kind_t::disassembly;
    context.document.object_id = workspace.value + 100U;
    context.document.variant_id = 1;
    context.document.provider_key = "c03-inspector-provider-" + std::to_string(workspace.value);
    context.document.has_address = true;
    context.document.address = address;
    context.selection.kind = selection_kind_t::address;
    context.selection.has_address = true;
    context.selection.address = address;
    context.selection_generation = selection_generation;
    return context;
}

inspector_query_limits_t limits_for(inspector_panel_kind_t panel)
{
    inspector_query_limits_t limits;
    limits.max_rows = inspector_panel_max_rows(panel);
    limits.max_bytes = k_inspector_max_query_bytes;
    return limits;
}

inspector_query_result_t make_result(const inspector_lazy_query_t& query)
{
    inspector_query_result_t result;
    result.query = query;
    result.complete = true;
    switch (query.panel) {
    case inspector_panel_kind_t::identity: {
        identity_panel_data_t payload;
        payload.display_name = "entry";
        payload.qualified_name = "fixture.entry";
        payload.module_name = "fixture.exe";
        payload.entity_kind = "function";
        payload.has_address = true;
        payload.address = query.context.selection.address;
        payload.module_relative_address = 0x1000;
        result.payload = std::move(payload);
        break;
    }
    case inspector_panel_kind_t::bytes: {
        bytes_panel_data_t payload;
        payload.base_address = query.context.selection.address;
        payload.bytes = {0x48, 0x89, 0x5C, 0x24, 0x08};
        payload.complete = true;
        result.payload = std::move(payload);
        break;
    }
    case inspector_panel_kind_t::operands:
        result.payload = std::vector<operand_panel_entry_t>{
            {0, "rcx", "destination", false, 0},
            {1, "[rsp+8]", "source", true, query.context.selection.address + 8U}};
        break;
    case inspector_panel_kind_t::xrefs:
        result.payload = std::vector<xref_panel_entry_t>{
            {xref_kind_t::code, true, query.context.selection.address - 5U,
             query.context.selection.address, "call site"}};
        break;
    case inspector_panel_kind_t::calls:
        result.payload = std::vector<call_panel_entry_t>{
            {call_kind_t::direct, query.context.selection.address, true,
             query.context.selection.address + 0x20U, "fixture_target", 100}};
        break;
    case inspector_panel_kind_t::stack_locals:
        result.payload = std::vector<stack_local_panel_entry_t>{
            {stack_storage_kind_t::stack_slot, -16, 8, "local_value", "std::uint64_t", 95}};
        break;
    case inspector_panel_kind_t::types:
        result.payload = std::vector<type_panel_entry_t>{
            {1, "std::uint64_t", "using value_type = unsigned long long;", 100}};
        break;
    case inspector_panel_kind_t::overlays:
        result.payload = std::vector<overlay_panel_entry_t>{
            {overlay_kind_t::analysis_annotation, 7, "analysis", "verified inference", true}};
        break;
    case inspector_panel_kind_t::diagnostics:
        result.payload = std::vector<diagnostic_panel_entry_t>{
            {diagnostic_severity_t::information, "C03-INSPECTOR", "fixture diagnostic", true,
             query.context.selection.address}};
        break;
    case inspector_panel_kind_t::source_provenance:
        result.payload = std::vector<source_provenance_panel_entry_t>{
            {source_provenance_kind_t::disassembler, 4, "zydis", "fixture.exe", "0x401000", 100}};
        break;
    }
    result.returned_rows = inspector_payload_rows(result.payload);
    result.returned_bytes = inspector_payload_bytes(result.payload);
    return result;
}

void verify_panel_contracts()
{
    const auto layout = default_inspector_layout_contract();
    require(validate_inspector_layout_contract(layout).ok(),
            "default inspector layout must preserve the fixed panel contract");

    inspector_query_session_t session;
    const auto context = make_context({11}, 7, 1, 0x401000);
    require(session.activate(context).ok(), "initial inspector context must activate");
    for (std::size_t index = 0; index < k_inspector_panel_count; ++index) {
        const auto panel = static_cast<inspector_panel_kind_t>(index);
        inspector_lazy_query_t query;
        require(session.request(panel, limits_for(panel), "panel-" + std::to_string(index), query).ok(),
                "panel query must be issued inside the active selection");
        const auto result = make_result(query);
        require(validate_inspector_query_result(result).ok(),
                "typed panel payload must satisfy its query contract");
        require(session.accept(result).ok(),
                "typed panel result must bind to its exact selection snapshot");
    }
    require(session.issued_query_count() == k_inspector_panel_count,
            "one bounded request per fixture panel must be retained for replay protection");
}

void verify_selection_change_and_stale_generation()
{
    inspector_query_session_t session;
    const auto first = make_context({21}, 3, 1, 0x401000);
    require(session.activate(first).ok(), "first selection must activate");
    inspector_lazy_query_t first_query;
    require(session.request(inspector_panel_kind_t::xrefs, limits_for(inspector_panel_kind_t::xrefs),
                            "incoming", first_query).ok(),
            "xref request must issue for the first selection");
    const auto first_result = make_result(first_query);

    const auto changed_selection = make_context({21}, 3, 2, 0x401020);
    require(session.activate(changed_selection).ok(), "newer selection must replace the active snapshot");
    require(session.issued_query_count() == 0,
            "selection changes must discard prior selection request state");
    require(session.accept(first_result).code == inspector_error_code_t::selection_changed,
            "late result from the prior selection must be rejected");

    inspector_lazy_query_t second_query;
    require(session.request(inspector_panel_kind_t::calls, limits_for(inspector_panel_kind_t::calls),
                            "outgoing", second_query).ok(),
            "call request must issue for the replacement selection");
    const auto second_result = make_result(second_query);
    const auto next_generation = make_context({21}, 4, 1, 0x401020);
    require(session.activate(next_generation).ok(), "newer workspace generation must activate");
    require(session.accept(second_result).code == inspector_error_code_t::stale_generation,
            "late result from an older workspace generation must be rejected");

    const auto stale_selection = make_context({21}, 4, 0, 0x401030);
    require(session.activate(stale_selection).code == inspector_error_code_t::invalid_context,
            "selection generation zero must fail closed");
}

void verify_workspace_isolation()
{
    inspector_query_session_t session;
    const auto first = make_context({31}, 1, 1, 0x501000);
    const auto second = make_context({32}, 1, 1, 0x601000);
    require(session.activate(first).ok(), "first workspace must activate");
    inspector_lazy_query_t first_query;
    require(session.request(inspector_panel_kind_t::identity, limits_for(inspector_panel_kind_t::identity),
                            "identity", first_query).ok(),
            "identity query must issue in the first workspace");
    const auto first_result = make_result(first_query);
    require(session.activate(second).ok(), "workspace switch must activate the second workspace");
    require(session.issued_query_count() == 0,
            "workspace switch must drop all prior workspace requests");
    require(session.accept(first_result).code == inspector_error_code_t::workspace_mismatch,
            "result from another workspace must never bind into the active workspace");
    require(session.active_context() != nullptr && session.active_context()->workspace == second.workspace,
            "workspace switch must retain only the current workspace context");
}

void verify_query_bounds()
{
    inspector_query_session_t session;
    require(session.activate(make_context({41}, 1, 1, 0x701000)).ok(),
            "bounded-query fixture context must activate");
    const inspector_query_limits_t invalid_rows{k_inspector_max_query_rows + 1U, 256};
    inspector_lazy_query_t output;
    require(session.request(inspector_panel_kind_t::operands, invalid_rows, "invalid-rows", output).code ==
                inspector_error_code_t::invalid_query,
            "query row limits must reject requests above the panel bound");
    const inspector_query_limits_t invalid_bytes{1, k_inspector_max_query_bytes + 1U};
    require(session.request(inspector_panel_kind_t::identity, invalid_bytes, "invalid-bytes", output).code ==
                inspector_error_code_t::invalid_query,
            "query byte limits must reject requests above the global bound");
    require(session.request(inspector_panel_kind_t::identity, limits_for(inspector_panel_kind_t::identity),
                            std::string(k_inspector_max_cursor_bytes + 1U, 'x'), output).code ==
                inspector_error_code_t::invalid_query,
            "oversized lazy-query cursors must be rejected");

    for (std::uint32_t index = 0; index < k_inspector_max_lazy_queries_per_selection; ++index) {
        require(session.request(inspector_panel_kind_t::diagnostics,
                                limits_for(inspector_panel_kind_t::diagnostics),
                                "page-" + std::to_string(index), output).ok(),
                "request budget must allow every explicitly bounded query slot");
    }
    require(session.issued_query_count() == k_inspector_max_lazy_queries_per_selection,
            "request session must cap retained query metadata at its fixed budget");
    require(session.request(inspector_panel_kind_t::diagnostics,
                            limits_for(inspector_panel_kind_t::diagnostics), "overflow", output).code ==
                inspector_error_code_t::query_capacity,
            "request session must reject growth beyond its fixed query budget");
}

void require_result_rejected(inspector_query_session_t& session,
                             const inspector_query_result_t& result,
                             inspector_error_code_t expected_code,
                             const char* validation_message,
                             const char* session_message)
{
    require(validate_inspector_query_result(result).code == expected_code, validation_message);
    require(session.accept(result).code == expected_code, session_message);
}

void verify_mismatched_result_variants()
{
    inspector_query_session_t session;
    require(session.activate(make_context({51}, 1, 1, 0x801000)).ok(),
            "variant-rejection fixture context must activate");
    for (std::size_t index = 0; index < k_inspector_panel_count; ++index) {
        const auto panel = static_cast<inspector_panel_kind_t>(index);
        inspector_lazy_query_t query;
        require(session.request(panel, limits_for(panel), "variant-" + std::to_string(index), query).ok(),
                "variant-rejection query must issue");

        auto result = make_result(query);
        auto alternate_query = query;
        alternate_query.panel = panel == inspector_panel_kind_t::identity ?
            inspector_panel_kind_t::bytes : inspector_panel_kind_t::identity;
        auto alternate_result = make_result(alternate_query);
        result.payload = std::move(alternate_result.payload);
        result.returned_rows = inspector_payload_rows(result.payload);
        result.returned_bytes = inspector_payload_bytes(result.payload);

        require_result_rejected(session, result, inspector_error_code_t::invalid_result,
                                "result payload variant must match its requested panel",
                                "session must reject a result carrying another panel variant");
    }
}

void verify_malformed_provenance_rejection()
{
    inspector_query_session_t session;
    require(session.activate(make_context({52}, 1, 1, 0x802000)).ok(),
            "provenance-rejection fixture context must activate");
    inspector_lazy_query_t query;
    require(session.request(inspector_panel_kind_t::source_provenance,
                            limits_for(inspector_panel_kind_t::source_provenance),
                            "provenance", query).ok(),
            "provenance-rejection query must issue");
    const auto valid_result = make_result(query);

    const auto reject_mutation = [&](const auto& mutate,
                                     const char* validation_message,
                                     const char* session_message) {
        auto result = valid_result;
        auto& entries = std::get<std::vector<source_provenance_panel_entry_t>>(result.payload);
        mutate(entries);
        result.returned_rows = inspector_payload_rows(result.payload);
        result.returned_bytes = inspector_payload_bytes(result.payload);
        require_result_rejected(session, result, inspector_error_code_t::invalid_result,
                                validation_message, session_message);
    };

    reject_mutation([](auto& entries) {
        entries.front().kind = static_cast<source_provenance_kind_t>(0xFFU);
    }, "unknown provenance kinds must be rejected",
       "session must reject provenance with an unknown kind");
    reject_mutation([](auto& entries) {
        entries.front().revision = 0;
    }, "zero provenance revisions must be rejected",
       "session must reject provenance without a revision");
    reject_mutation([](auto& entries) {
        entries.front().provider.clear();
    }, "provenance providers must be present",
       "session must reject provenance without a provider");
    reject_mutation([](auto& entries) {
        entries.front().artifact.clear();
    }, "provenance artifacts must be present",
       "session must reject provenance without an artifact");
    reject_mutation([](auto& entries) {
        entries.front().coordinate.clear();
    }, "provenance coordinates must be present",
       "session must reject provenance without a coordinate");
    reject_mutation([](auto& entries) {
        entries.front().confidence = 101;
    }, "provenance confidence must remain bounded",
       "session must reject provenance with impossible confidence");
    reject_mutation([](auto& entries) {
        entries.front().provider.assign(k_inspector_max_entry_text_bytes + 1U, 'p');
    }, "oversized provenance text must be rejected",
       "session must reject provenance exceeding text bounds");
    reject_mutation([](auto& entries) {
        const auto entry = entries.front();
        entries.assign(k_inspector_max_provenance_entries + 1U, entry);
    }, "oversized provenance collections must be rejected",
       "session must reject provenance exceeding collection bounds");

    require(session.accept(valid_result).ok(),
            "malformed provenance rejections must leave the issued query available");
}

void verify_forged_result_metadata_rejection()
{
    inspector_query_session_t session;
    require(session.activate(make_context({53}, 1, 1, 0x803000)).ok(),
            "metadata-rejection fixture context must activate");
    inspector_lazy_query_t query;
    require(session.request(inspector_panel_kind_t::diagnostics,
                            limits_for(inspector_panel_kind_t::diagnostics),
                            "metadata", query).ok(),
            "metadata-rejection query must issue");
    const auto valid_result = make_result(query);

    auto forged_rows = valid_result;
    ++forged_rows.returned_rows;
    require_result_rejected(session, forged_rows, inspector_error_code_t::payload_mismatch,
                            "forged result row metadata must be rejected",
                            "session must reject forged result row metadata");

    auto forged_bytes = valid_result;
    ++forged_bytes.returned_bytes;
    require_result_rejected(session, forged_bytes, inspector_error_code_t::payload_mismatch,
                            "forged result byte metadata must be rejected",
                            "session must reject forged result byte metadata");

    require(session.accept(valid_result).ok(),
            "forged metadata rejections must leave the issued query available");
}

void verify_result_limit_rejection()
{
    inspector_query_session_t session;
    const auto context = make_context({54}, 1, 1, 0x804000);
    require(session.activate(context).ok(),
            "result-limit fixture context must activate");

    inspector_lazy_query_t row_query;
    const inspector_query_limits_t row_limits{1U, k_inspector_max_query_bytes};
    require(session.request(inspector_panel_kind_t::diagnostics, row_limits,
                            "row-limit", row_query).ok(),
            "row-limit query must issue");
    const auto row_at_limit = make_result(row_query);
    auto rows_exceeded = row_at_limit;
    auto& diagnostics = std::get<std::vector<diagnostic_panel_entry_t>>(rows_exceeded.payload);
    diagnostics.push_back(diagnostics.front());
    rows_exceeded.returned_rows = inspector_payload_rows(rows_exceeded.payload);
    rows_exceeded.returned_bytes = inspector_payload_bytes(rows_exceeded.payload);
    require_result_rejected(session, rows_exceeded, inspector_error_code_t::result_limit_exceeded,
                            "results exceeding the requested row limit must be rejected",
                            "session must reject results exceeding the requested row limit");
    require(session.accept(row_at_limit).ok(),
            "a result at the requested row limit must remain acceptable");

    inspector_lazy_query_t preview_query;
    preview_query.panel = inspector_panel_kind_t::bytes;
    preview_query.context = context;
    const auto preview_result = make_result(preview_query);
    require(preview_result.returned_bytes > 1U &&
                preview_result.returned_bytes <= k_inspector_max_query_bytes,
            "byte-limit fixture must produce a bounded measurable payload");

    inspector_lazy_query_t byte_query;
    const inspector_query_limits_t byte_limits{1U, preview_result.returned_bytes - 1U};
    require(session.request(inspector_panel_kind_t::bytes, byte_limits,
                            "byte-limit", byte_query).ok(),
            "byte-limit query must issue");
    auto bytes_exceeded = make_result(byte_query);
    require_result_rejected(session, bytes_exceeded, inspector_error_code_t::result_limit_exceeded,
                            "results exceeding the requested byte limit must be rejected",
                            "session must reject results exceeding the requested byte limit");

    auto& bytes = std::get<bytes_panel_data_t>(bytes_exceeded.payload).bytes;
    require(!bytes.empty(), "byte-limit fixture must expose at least one payload byte");
    bytes.pop_back();
    bytes_exceeded.returned_rows = inspector_payload_rows(bytes_exceeded.payload);
    bytes_exceeded.returned_bytes = inspector_payload_bytes(bytes_exceeded.payload);
    require(bytes_exceeded.returned_bytes == byte_limits.max_bytes,
            "byte-limit fixture must reduce the payload to the exact requested bound");
    require(session.accept(bytes_exceeded).ok(),
            "a result at the requested byte limit must remain acceptable");
}

void verify_layout_growth_rejection()
{
    auto widened = default_inspector_layout_contract();
    ++widened.inspector_width_pixels;
    require(validate_inspector_layout_contract(widened).code == inspector_error_code_t::layout_growth,
            "inspector width growth must be rejected");

    auto taller = default_inspector_layout_contract();
    ++taller.slots[static_cast<std::size_t>(inspector_panel_kind_t::diagnostics)].visible_rows;
    require(validate_inspector_layout_contract(taller).code == inspector_error_code_t::layout_growth,
            "panel row growth must be rejected");

    auto reordered = default_inspector_layout_contract();
    std::swap(reordered.slots[0], reordered.slots[1]);
    require(validate_inspector_layout_contract(reordered).code == inspector_error_code_t::invalid_layout,
            "panel order must remain deterministic");
}

}

bool run_workbench_inspector_harness(std::string& failure)
{
    try {
        verify_panel_contracts();
        verify_selection_change_and_stale_generation();
        verify_workspace_isolation();
        verify_query_bounds();
        verify_mismatched_result_variants();
        verify_malformed_provenance_rejection();
        verify_forged_result_metadata_rejection();
        verify_result_limit_rejection();
        verify_layout_growth_rejection();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
        failure = exception.what();
        return false;
    }
}

}
}
}

int main()
{
    std::string failure;
    if (!aida::workbench::inspector::run_workbench_inspector_harness(failure)) {
        std::cerr << "workbench_inspector_harness failed: " << failure << '\n';
        return 1;
    }
    std::cout << "workbench_inspector_harness source contract satisfied\n";
    return 0;
}
