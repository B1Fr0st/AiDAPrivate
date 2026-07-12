#include "workbench_inspector_contracts.hpp"

#include <algorithm>
#include <limits>
#include <type_traits>
#include <utility>

namespace aida {
namespace workbench {
namespace inspector {
namespace {

struct payload_measurement_t {
    std::uint64_t rows = 0;
    std::uint64_t bytes = 0;
    bool valid = true;
};

inspector_error_t error(inspector_error_code_t code, std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

bool valid_xref_kind(xref_kind_t kind) noexcept
{
    return kind <= xref_kind_t::indirect;
}

bool valid_call_kind(call_kind_t kind) noexcept
{
    return kind <= call_kind_t::virtual_dispatch;
}

bool valid_stack_storage_kind(stack_storage_kind_t kind) noexcept
{
    return kind <= stack_storage_kind_t::recovered_local;
}

bool valid_overlay_kind(overlay_kind_t kind) noexcept
{
    return kind <= overlay_kind_t::analysis_annotation;
}

bool valid_diagnostic_severity(diagnostic_severity_t severity) noexcept
{
    return severity <= diagnostic_severity_t::error;
}

bool valid_source_provenance_kind(source_provenance_kind_t kind) noexcept
{
    return kind <= source_provenance_kind_t::external_provider;
}

bool valid_text(const std::string& value, std::uint32_t maximum, bool required) noexcept
{
    return value.size() <= maximum && (!required || !value.empty());
}

void add_bytes(payload_measurement_t& measurement, std::uint64_t value) noexcept
{
    if (measurement.bytes > std::numeric_limits<std::uint64_t>::max() - value) {
        measurement.valid = false;
        return;
    }
    measurement.bytes += value;
}

void add_string(payload_measurement_t& measurement, const std::string& value) noexcept
{
    add_bytes(measurement, static_cast<std::uint64_t>(value.size()));
}

bool valid_confidence(std::uint8_t confidence) noexcept
{
    return confidence <= 100;
}

bool valid_identity_payload(const identity_panel_data_t& payload, payload_measurement_t& measurement) noexcept
{
    const bool named = !payload.display_name.empty() || !payload.qualified_name.empty() ||
                       !payload.module_name.empty();
    if ((!named && !payload.has_address) || !valid_text(payload.display_name, k_inspector_max_identity_text_bytes, false) ||
        !valid_text(payload.qualified_name, k_inspector_max_identity_text_bytes, false) ||
        !valid_text(payload.module_name, k_inspector_max_identity_text_bytes, false) ||
        !valid_text(payload.entity_kind, k_inspector_max_identity_text_bytes, true)) {
        return false;
    }
    if (!payload.has_address && (payload.address != 0 || payload.module_relative_address != 0))
        return false;
    measurement.rows = 1;
    add_string(measurement, payload.display_name);
    add_string(measurement, payload.qualified_name);
    add_string(measurement, payload.module_name);
    add_string(measurement, payload.entity_kind);
    add_bytes(measurement, sizeof(payload.has_address) + sizeof(payload.address) +
                              sizeof(payload.module_relative_address));
    return measurement.valid;
}

bool valid_bytes_payload(const bytes_panel_data_t& payload, payload_measurement_t& measurement) noexcept
{
    if (payload.bytes.size() > k_inspector_max_byte_window)
        return false;
    measurement.rows = 1;
    add_bytes(measurement, sizeof(payload.base_address) + sizeof(payload.complete));
    add_bytes(measurement, static_cast<std::uint64_t>(payload.bytes.size()));
    return measurement.valid;
}

bool valid_operand_payload(const std::vector<operand_panel_entry_t>& payload,
                           payload_measurement_t& measurement) noexcept
{
    if (payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::operands))
        return false;
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        if (!valid_text(entry.text, k_inspector_max_entry_text_bytes, true) ||
            !valid_text(entry.role, k_inspector_max_entry_text_bytes, true) ||
            (!entry.has_target_address && entry.target_address != 0)) {
            return false;
        }
        add_bytes(measurement, sizeof(entry.ordinal) + sizeof(entry.has_target_address) +
                                  sizeof(entry.target_address));
        add_string(measurement, entry.text);
        add_string(measurement, entry.role);
    }
    return measurement.valid;
}

bool valid_xref_payload(const std::vector<xref_panel_entry_t>& payload,
                        payload_measurement_t& measurement) noexcept
{
    if (payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::xrefs))
        return false;
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        if (!valid_xref_kind(entry.kind) || !valid_text(entry.label, k_inspector_max_entry_text_bytes, true))
            return false;
        add_bytes(measurement, sizeof(entry.kind) + sizeof(entry.incoming) +
                                  sizeof(entry.source_address) + sizeof(entry.target_address));
        add_string(measurement, entry.label);
    }
    return measurement.valid;
}

bool valid_call_payload(const std::vector<call_panel_entry_t>& payload,
                        payload_measurement_t& measurement) noexcept
{
    if (payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::calls))
        return false;
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        const bool has_target = entry.has_target_address || !entry.target_name.empty();
        if (!valid_call_kind(entry.kind) || !has_target ||
            !valid_text(entry.target_name, k_inspector_max_entry_text_bytes, false) ||
            !valid_confidence(entry.confidence) || (!entry.has_target_address && entry.target_address != 0)) {
            return false;
        }
        add_bytes(measurement, sizeof(entry.kind) + sizeof(entry.site_address) +
                                  sizeof(entry.has_target_address) + sizeof(entry.target_address) +
                                  sizeof(entry.confidence));
        add_string(measurement, entry.target_name);
    }
    return measurement.valid;
}

bool valid_stack_local_payload(const std::vector<stack_local_panel_entry_t>& payload,
                               payload_measurement_t& measurement) noexcept
{
    if (payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::stack_locals))
        return false;
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        if (!valid_stack_storage_kind(entry.storage) || entry.byte_size == 0 ||
            !valid_text(entry.name, k_inspector_max_entry_text_bytes, true) ||
            !valid_text(entry.type_name, k_inspector_max_entry_text_bytes, true) ||
            !valid_confidence(entry.confidence)) {
            return false;
        }
        add_bytes(measurement, sizeof(entry.storage) + sizeof(entry.stack_offset) +
                                  sizeof(entry.byte_size) + sizeof(entry.confidence));
        add_string(measurement, entry.name);
        add_string(measurement, entry.type_name);
    }
    return measurement.valid;
}

bool valid_type_payload(const std::vector<type_panel_entry_t>& payload,
                        payload_measurement_t& measurement) noexcept
{
    if (payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::types))
        return false;
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        if (entry.type_id == 0 || !valid_text(entry.display_name, k_inspector_max_entry_text_bytes, true) ||
            !valid_text(entry.declaration, k_inspector_max_entry_text_bytes, true) ||
            !valid_confidence(entry.confidence)) {
            return false;
        }
        add_bytes(measurement, sizeof(entry.type_id) + sizeof(entry.confidence));
        add_string(measurement, entry.display_name);
        add_string(measurement, entry.declaration);
    }
    return measurement.valid;
}

bool valid_overlay_payload(const std::vector<overlay_panel_entry_t>& payload,
                           payload_measurement_t& measurement) noexcept
{
    if (payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::overlays))
        return false;
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        if (!valid_overlay_kind(entry.kind) || entry.revision == 0 ||
            !valid_text(entry.name, k_inspector_max_entry_text_bytes, true) ||
            !valid_text(entry.summary, k_inspector_max_entry_text_bytes, true)) {
            return false;
        }
        add_bytes(measurement, sizeof(entry.kind) + sizeof(entry.revision) + sizeof(entry.active));
        add_string(measurement, entry.name);
        add_string(measurement, entry.summary);
    }
    return measurement.valid;
}

bool valid_diagnostic_payload(const std::vector<diagnostic_panel_entry_t>& payload,
                              payload_measurement_t& measurement) noexcept
{
    if (payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::diagnostics))
        return false;
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        if (!valid_diagnostic_severity(entry.severity) ||
            !valid_text(entry.code, k_inspector_max_diagnostic_code_bytes, true) ||
            !valid_text(entry.message, k_inspector_max_entry_text_bytes, true) ||
            (!entry.has_address && entry.address != 0)) {
            return false;
        }
        add_bytes(measurement, sizeof(entry.severity) + sizeof(entry.has_address) + sizeof(entry.address));
        add_string(measurement, entry.code);
        add_string(measurement, entry.message);
    }
    return measurement.valid;
}

bool valid_provenance_payload(const std::vector<source_provenance_panel_entry_t>& payload,
                              payload_measurement_t& measurement) noexcept
{
    if (payload.size() > k_inspector_max_provenance_entries ||
        payload.size() > inspector_panel_max_rows(inspector_panel_kind_t::source_provenance)) {
        return false;
    }
    measurement.rows = payload.size();
    for (const auto& entry : payload) {
        if (!valid_source_provenance_kind(entry.kind) || entry.revision == 0 ||
            !valid_text(entry.provider, k_inspector_max_entry_text_bytes, true) ||
            !valid_text(entry.artifact, k_inspector_max_entry_text_bytes, true) ||
            !valid_text(entry.coordinate, k_inspector_max_entry_text_bytes, true) ||
            !valid_confidence(entry.confidence)) {
            return false;
        }
        add_bytes(measurement, sizeof(entry.kind) + sizeof(entry.revision) + sizeof(entry.confidence));
        add_string(measurement, entry.provider);
        add_string(measurement, entry.artifact);
        add_string(measurement, entry.coordinate);
    }
    return measurement.valid;
}

bool measure_payload(inspector_panel_kind_t panel, const inspector_panel_payload_t& payload,
                     payload_measurement_t& measurement) noexcept
{
    switch (panel) {
    case inspector_panel_kind_t::identity:
        return std::holds_alternative<identity_panel_data_t>(payload) &&
               valid_identity_payload(std::get<identity_panel_data_t>(payload), measurement);
    case inspector_panel_kind_t::bytes:
        return std::holds_alternative<bytes_panel_data_t>(payload) &&
               valid_bytes_payload(std::get<bytes_panel_data_t>(payload), measurement);
    case inspector_panel_kind_t::operands:
        return std::holds_alternative<std::vector<operand_panel_entry_t>>(payload) &&
               valid_operand_payload(std::get<std::vector<operand_panel_entry_t>>(payload), measurement);
    case inspector_panel_kind_t::xrefs:
        return std::holds_alternative<std::vector<xref_panel_entry_t>>(payload) &&
               valid_xref_payload(std::get<std::vector<xref_panel_entry_t>>(payload), measurement);
    case inspector_panel_kind_t::calls:
        return std::holds_alternative<std::vector<call_panel_entry_t>>(payload) &&
               valid_call_payload(std::get<std::vector<call_panel_entry_t>>(payload), measurement);
    case inspector_panel_kind_t::stack_locals:
        return std::holds_alternative<std::vector<stack_local_panel_entry_t>>(payload) &&
               valid_stack_local_payload(std::get<std::vector<stack_local_panel_entry_t>>(payload), measurement);
    case inspector_panel_kind_t::types:
        return std::holds_alternative<std::vector<type_panel_entry_t>>(payload) &&
               valid_type_payload(std::get<std::vector<type_panel_entry_t>>(payload), measurement);
    case inspector_panel_kind_t::overlays:
        return std::holds_alternative<std::vector<overlay_panel_entry_t>>(payload) &&
               valid_overlay_payload(std::get<std::vector<overlay_panel_entry_t>>(payload), measurement);
    case inspector_panel_kind_t::diagnostics:
        return std::holds_alternative<std::vector<diagnostic_panel_entry_t>>(payload) &&
               valid_diagnostic_payload(std::get<std::vector<diagnostic_panel_entry_t>>(payload), measurement);
    case inspector_panel_kind_t::source_provenance:
        return std::holds_alternative<std::vector<source_provenance_panel_entry_t>>(payload) &&
               valid_provenance_payload(std::get<std::vector<source_provenance_panel_entry_t>>(payload), measurement);
    }
    return false;
}

bool query_equal(const inspector_lazy_query_t& lhs, const inspector_lazy_query_t& rhs)
{
    return lhs.id == rhs.id && lhs.panel == rhs.panel &&
           inspector_context_equal(lhs.context, rhs.context) &&
           lhs.limits.max_rows == rhs.limits.max_rows &&
           lhs.limits.max_bytes == rhs.limits.max_bytes && lhs.cursor == rhs.cursor;
}

inspector_error_t compare_to_active_context(const inspector_context_t& active,
                                            const inspector_context_t& candidate) noexcept
{
    if (candidate.workspace != active.workspace)
        return error(inspector_error_code_t::workspace_mismatch, candidate.workspace.value);
    if (candidate.workspace_generation != active.workspace_generation)
        return error(inspector_error_code_t::stale_generation, candidate.workspace_generation.value);
    if (candidate.selection_generation != active.selection_generation ||
        !document_identity_equal(candidate.document, active.document) ||
        !selection_context_equal(candidate.selection, active.selection)) {
        return error(inspector_error_code_t::selection_changed, candidate.selection_generation);
    }
    return {};
}

}

bool inspector_context_equal(const inspector_context_t& lhs, const inspector_context_t& rhs)
{
    return lhs.workspace == rhs.workspace && lhs.workspace_generation == rhs.workspace_generation &&
           document_identity_equal(lhs.document, rhs.document) &&
           selection_context_equal(lhs.selection, rhs.selection) &&
           lhs.selection_generation == rhs.selection_generation;
}

bool inspector_panel_kind_valid(inspector_panel_kind_t panel) noexcept
{
    return panel <= inspector_panel_kind_t::source_provenance;
}

std::uint32_t inspector_panel_max_rows(inspector_panel_kind_t panel) noexcept
{
    if (!inspector_panel_kind_valid(panel))
        return 0;
    return panel == inspector_panel_kind_t::identity || panel == inspector_panel_kind_t::bytes ? 1U :
        k_inspector_max_query_rows;
}

inspector_layout_contract_t default_inspector_layout_contract() noexcept
{
    inspector_layout_contract_t layout;
    for (std::size_t index = 0; index < layout.slots.size(); ++index) {
        layout.slots[index].panel = static_cast<inspector_panel_kind_t>(index);
        layout.slots[index].visible_rows = k_inspector_visible_rows_per_panel;
        layout.slots[index].extent_pixels = static_cast<std::uint16_t>(
            k_inspector_header_height_pixels + k_inspector_visible_rows_per_panel * k_inspector_row_height_pixels);
    }
    return layout;
}

inspector_error_t validate_inspector_context(const inspector_context_t& context)
{
    if (!context.workspace.valid() || !context.workspace_generation.valid() ||
        context.selection_generation == 0) {
        return error(inspector_error_code_t::invalid_context, context.workspace.value);
    }
    const auto document_result = validate_document_identity(context.document);
    if (!document_result)
        return error(inspector_error_code_t::invalid_context, context.document.object_id);
    if (context.document.workspace != context.workspace)
        return error(inspector_error_code_t::workspace_mismatch, context.document.workspace.value);
    const auto selection_result = validate_selection_context(context.selection);
    if (!selection_result)
        return error(inspector_error_code_t::invalid_context, context.selection.address);
    return {};
}

inspector_error_t validate_inspector_query_limits(inspector_panel_kind_t panel,
                                                   const inspector_query_limits_t& limits) noexcept
{
    if (!inspector_panel_kind_valid(panel))
        return error(inspector_error_code_t::invalid_panel, static_cast<std::uint64_t>(panel));
    if (limits.max_rows == 0 || limits.max_rows > inspector_panel_max_rows(panel) ||
        limits.max_bytes == 0 || limits.max_bytes > k_inspector_max_query_bytes) {
        return error(inspector_error_code_t::invalid_query, limits.max_rows);
    }
    return {};
}

inspector_error_t validate_inspector_lazy_query(const inspector_lazy_query_t& query)
{
    if (query.id == 0)
        return error(inspector_error_code_t::invalid_query);
    const auto context_result = validate_inspector_context(query.context);
    if (!context_result)
        return context_result;
    const auto limits_result = validate_inspector_query_limits(query.panel, query.limits);
    if (!limits_result)
        return limits_result;
    if (query.cursor.size() > k_inspector_max_cursor_bytes)
        return error(inspector_error_code_t::invalid_query, query.cursor.size());
    return {};
}

inspector_error_t validate_inspector_layout_contract(const inspector_layout_contract_t& layout) noexcept
{
    const auto expected = default_inspector_layout_contract();
    const bool grew = layout.inspector_width_pixels > expected.inspector_width_pixels ||
                      layout.header_height_pixels > expected.header_height_pixels ||
                      layout.row_height_pixels > expected.row_height_pixels;
    if (grew)
        return error(inspector_error_code_t::layout_growth, layout.inspector_width_pixels);
    if (layout.inspector_width_pixels != expected.inspector_width_pixels ||
        layout.header_height_pixels != expected.header_height_pixels ||
        layout.row_height_pixels != expected.row_height_pixels) {
        return error(inspector_error_code_t::invalid_layout, layout.inspector_width_pixels);
    }
    for (std::size_t index = 0; index < layout.slots.size(); ++index) {
        const auto& actual = layout.slots[index];
        const auto& required = expected.slots[index];
        if (actual.visible_rows > required.visible_rows || actual.extent_pixels > required.extent_pixels)
            return error(inspector_error_code_t::layout_growth, index);
        if (actual.panel != required.panel || actual.visible_rows != required.visible_rows ||
            actual.extent_pixels != required.extent_pixels) {
            return error(inspector_error_code_t::invalid_layout, index);
        }
    }
    return {};
}

std::uint32_t inspector_payload_rows(const inspector_panel_payload_t& payload) noexcept
{
    return std::visit([](const auto& value) noexcept -> std::uint32_t {
        using value_t = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<value_t, identity_panel_data_t> ||
                      std::is_same_v<value_t, bytes_panel_data_t>) {
            return 1;
        } else {
            return value.size() > std::numeric_limits<std::uint32_t>::max() ?
                std::numeric_limits<std::uint32_t>::max() : static_cast<std::uint32_t>(value.size());
        }
    }, payload);
}

std::uint32_t inspector_payload_bytes(const inspector_panel_payload_t& payload) noexcept
{
    const auto panel = std::visit([](const auto& value) noexcept -> inspector_panel_kind_t {
        using value_t = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<value_t, identity_panel_data_t>)
            return inspector_panel_kind_t::identity;
        else if constexpr (std::is_same_v<value_t, bytes_panel_data_t>)
            return inspector_panel_kind_t::bytes;
        else if constexpr (std::is_same_v<value_t, std::vector<operand_panel_entry_t>>)
            return inspector_panel_kind_t::operands;
        else if constexpr (std::is_same_v<value_t, std::vector<xref_panel_entry_t>>)
            return inspector_panel_kind_t::xrefs;
        else if constexpr (std::is_same_v<value_t, std::vector<call_panel_entry_t>>)
            return inspector_panel_kind_t::calls;
        else if constexpr (std::is_same_v<value_t, std::vector<stack_local_panel_entry_t>>)
            return inspector_panel_kind_t::stack_locals;
        else if constexpr (std::is_same_v<value_t, std::vector<type_panel_entry_t>>)
            return inspector_panel_kind_t::types;
        else if constexpr (std::is_same_v<value_t, std::vector<overlay_panel_entry_t>>)
            return inspector_panel_kind_t::overlays;
        else if constexpr (std::is_same_v<value_t, std::vector<diagnostic_panel_entry_t>>)
            return inspector_panel_kind_t::diagnostics;
        else
            return inspector_panel_kind_t::source_provenance;
    }, payload);
    payload_measurement_t measurement;
    if (!measure_payload(panel, payload, measurement) ||
        measurement.bytes > std::numeric_limits<std::uint32_t>::max()) {
        return std::numeric_limits<std::uint32_t>::max();
    }
    return static_cast<std::uint32_t>(measurement.bytes);
}

inspector_error_t validate_inspector_query_result(const inspector_query_result_t& result)
{
    const auto query_result = validate_inspector_lazy_query(result.query);
    if (!query_result)
        return query_result;
    payload_measurement_t measurement;
    if (!measure_payload(result.query.panel, result.payload, measurement) || !measurement.valid ||
        measurement.rows > std::numeric_limits<std::uint32_t>::max() ||
        measurement.bytes > std::numeric_limits<std::uint32_t>::max()) {
        return error(inspector_error_code_t::invalid_result, result.query.id);
    }
    const auto rows = static_cast<std::uint32_t>(measurement.rows);
    const auto bytes = static_cast<std::uint32_t>(measurement.bytes);
    if (result.returned_rows != rows || result.returned_bytes != bytes)
        return error(inspector_error_code_t::payload_mismatch, result.query.id);
    if (rows > result.query.limits.max_rows || bytes > result.query.limits.max_bytes)
        return error(inspector_error_code_t::result_limit_exceeded, result.query.id);
    return {};
}

inspector_error_t inspector_query_session_t::activate(const inspector_context_t& context)
{
    const auto context_result = validate_inspector_context(context);
    if (!context_result)
        return context_result;
    if (!active_) {
        active_ = context;
        issued_.clear();
        return {};
    }
    if (context.workspace != active_->workspace) {
        active_ = context;
        issued_.clear();
        return {};
    }
    if (context.workspace_generation < active_->workspace_generation)
        return error(inspector_error_code_t::stale_generation, context.workspace_generation.value);
    if (context.workspace_generation == active_->workspace_generation) {
        if (context.selection_generation < active_->selection_generation)
            return error(inspector_error_code_t::selection_changed, context.selection_generation);
        if (context.selection_generation == active_->selection_generation) {
            if (!inspector_context_equal(context, *active_))
                return error(inspector_error_code_t::selection_changed, context.selection_generation);
            return {};
        }
    }
    active_ = context;
    issued_.clear();
    return {};
}

inspector_error_t inspector_query_session_t::request(inspector_panel_kind_t panel,
                                                      const inspector_query_limits_t& limits,
                                                      std::string cursor,
                                                      inspector_lazy_query_t& output)
{
    if (!active_)
        return error(inspector_error_code_t::invalid_context);
    const auto limits_result = validate_inspector_query_limits(panel, limits);
    if (!limits_result)
        return limits_result;
    if (cursor.size() > k_inspector_max_cursor_bytes)
        return error(inspector_error_code_t::invalid_query, cursor.size());
    if (issued_.size() >= k_inspector_max_lazy_queries_per_selection)
        return error(inspector_error_code_t::query_capacity, issued_.size());
    if (next_query_id_ == 0 || next_query_id_ == std::numeric_limits<std::uint64_t>::max())
        return error(inspector_error_code_t::identifier_overflow);
    for (const auto& issued : issued_) {
        if (issued.query.panel == panel && issued.query.cursor == cursor)
            return error(inspector_error_code_t::duplicate_query, issued.query.id);
    }
    inspector_lazy_query_t query;
    query.id = next_query_id_++;
    query.panel = panel;
    query.context = *active_;
    query.limits = limits;
    query.cursor = std::move(cursor);
    issued_.push_back({query, false});
    output = std::move(query);
    return {};
}

inspector_error_t inspector_query_session_t::accept(const inspector_query_result_t& result)
{
    if (!active_)
        return error(inspector_error_code_t::invalid_context);
    const auto active_result = compare_to_active_context(*active_, result.query.context);
    if (!active_result)
        return active_result;
    const auto issued = std::find_if(issued_.begin(), issued_.end(), [&result](const issued_query_t& value) {
        return value.query.id == result.query.id;
    });
    if (issued == issued_.end() || issued->completed)
        return error(inspector_error_code_t::query_not_found, result.query.id);
    if (!query_equal(issued->query, result.query))
        return error(inspector_error_code_t::invalid_query, result.query.id);
    const auto result_validation = validate_inspector_query_result(result);
    if (!result_validation)
        return result_validation;
    issued->completed = true;
    return {};
}

void inspector_query_session_t::reset() noexcept
{
    active_.reset();
    issued_.clear();
}

const inspector_context_t* inspector_query_session_t::active_context() const noexcept
{
    return active_ ? &*active_ : nullptr;
}

std::uint32_t inspector_query_session_t::issued_query_count() const noexcept
{
    return static_cast<std::uint32_t>(issued_.size());
}

}
}
}
