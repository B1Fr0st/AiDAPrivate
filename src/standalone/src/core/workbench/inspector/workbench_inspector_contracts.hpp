#pragma once

#include "../workbench_contracts.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace aida {
namespace workbench {
namespace inspector {

constexpr std::uint32_t k_workbench_inspector_schema_version = 1;
constexpr std::size_t k_inspector_panel_count = 10;
constexpr std::uint32_t k_inspector_fixed_width_pixels = 360;
constexpr std::uint16_t k_inspector_header_height_pixels = 24;
constexpr std::uint16_t k_inspector_row_height_pixels = 18;
constexpr std::uint16_t k_inspector_visible_rows_per_panel = 8;
constexpr std::uint32_t k_inspector_max_lazy_queries_per_selection = 20;
constexpr std::uint32_t k_inspector_max_query_rows = 128;
constexpr std::uint32_t k_inspector_max_query_bytes = 65536;
constexpr std::uint32_t k_inspector_max_cursor_bytes = 512;
constexpr std::uint32_t k_inspector_max_identity_text_bytes = 512;
constexpr std::uint32_t k_inspector_max_entry_text_bytes = 1024;
constexpr std::uint32_t k_inspector_max_diagnostic_code_bytes = 96;
constexpr std::uint32_t k_inspector_max_byte_window = 4096;
constexpr std::uint32_t k_inspector_max_provenance_entries = 128;

enum class inspector_panel_kind_t : std::uint8_t {
    identity = 0,
    bytes = 1,
    operands = 2,
    xrefs = 3,
    calls = 4,
    stack_locals = 5,
    types = 6,
    overlays = 7,
    diagnostics = 8,
    source_provenance = 9
};

enum class inspector_error_code_t : std::uint16_t {
    none = 0,
    invalid_context,
    invalid_panel,
    invalid_layout,
    layout_growth,
    invalid_query,
    query_capacity,
    duplicate_query,
    query_not_found,
    stale_generation,
    selection_changed,
    workspace_mismatch,
    invalid_result,
    result_limit_exceeded,
    payload_mismatch,
    identifier_overflow
};

struct inspector_error_t {
    inspector_error_code_t code = inspector_error_code_t::none;
    std::uint64_t subject = 0;

    constexpr bool ok() const noexcept { return code == inspector_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

struct inspector_context_t {
    workspace_id_t workspace;
    workspace_revision_t workspace_generation;
    document_identity_t document;
    selection_context_t selection;
    std::uint64_t selection_generation = 0;
};

struct inspector_query_limits_t {
    std::uint32_t max_rows = 0;
    std::uint32_t max_bytes = 0;
};

struct inspector_lazy_query_t {
    std::uint64_t id = 0;
    inspector_panel_kind_t panel = inspector_panel_kind_t::identity;
    inspector_context_t context;
    inspector_query_limits_t limits;
    std::string cursor;
};

struct inspector_panel_slot_t {
    inspector_panel_kind_t panel = inspector_panel_kind_t::identity;
    std::uint16_t visible_rows = k_inspector_visible_rows_per_panel;
    std::uint16_t extent_pixels =
        static_cast<std::uint16_t>(k_inspector_header_height_pixels +
                                   k_inspector_visible_rows_per_panel * k_inspector_row_height_pixels);
};

struct inspector_layout_contract_t {
    std::uint32_t inspector_width_pixels = k_inspector_fixed_width_pixels;
    std::uint16_t header_height_pixels = k_inspector_header_height_pixels;
    std::uint16_t row_height_pixels = k_inspector_row_height_pixels;
    std::array<inspector_panel_slot_t, k_inspector_panel_count> slots{};
};

struct identity_panel_data_t {
    std::string display_name;
    std::string qualified_name;
    std::string module_name;
    std::string entity_kind;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t module_relative_address = 0;
};

struct bytes_panel_data_t {
    std::uint64_t base_address = 0;
    std::vector<std::uint8_t> bytes;
    bool complete = false;
};

struct operand_panel_entry_t {
    std::uint32_t ordinal = 0;
    std::string text;
    std::string role;
    bool has_target_address = false;
    std::uint64_t target_address = 0;
};

enum class xref_kind_t : std::uint8_t {
    code = 0,
    data = 1,
    read = 2,
    write = 3,
    indirect = 4
};

struct xref_panel_entry_t {
    xref_kind_t kind = xref_kind_t::code;
    bool incoming = false;
    std::uint64_t source_address = 0;
    std::uint64_t target_address = 0;
    std::string label;
};

enum class call_kind_t : std::uint8_t {
    direct = 0,
    indirect = 1,
    tail = 2,
    import = 3,
    virtual_dispatch = 4
};

struct call_panel_entry_t {
    call_kind_t kind = call_kind_t::direct;
    std::uint64_t site_address = 0;
    bool has_target_address = false;
    std::uint64_t target_address = 0;
    std::string target_name;
    std::uint8_t confidence = 0;
};

enum class stack_storage_kind_t : std::uint8_t {
    stack_slot = 0,
    register_spill = 1,
    parameter = 2,
    recovered_local = 3
};

struct stack_local_panel_entry_t {
    stack_storage_kind_t storage = stack_storage_kind_t::stack_slot;
    std::int64_t stack_offset = 0;
    std::uint32_t byte_size = 0;
    std::string name;
    std::string type_name;
    std::uint8_t confidence = 0;
};

struct type_panel_entry_t {
    std::uint64_t type_id = 0;
    std::string display_name;
    std::string declaration;
    std::uint8_t confidence = 0;
};

enum class overlay_kind_t : std::uint8_t {
    user_annotation = 0,
    patch = 1,
    type_override = 2,
    debug_annotation = 3,
    analysis_annotation = 4
};

struct overlay_panel_entry_t {
    overlay_kind_t kind = overlay_kind_t::user_annotation;
    std::uint64_t revision = 0;
    std::string name;
    std::string summary;
    bool active = false;
};

enum class diagnostic_severity_t : std::uint8_t {
    information = 0,
    warning = 1,
    error = 2
};

struct diagnostic_panel_entry_t {
    diagnostic_severity_t severity = diagnostic_severity_t::information;
    std::string code;
    std::string message;
    bool has_address = false;
    std::uint64_t address = 0;
};

enum class source_provenance_kind_t : std::uint8_t {
    loader = 0,
    disassembler = 1,
    debug_info = 2,
    decompiler = 3,
    user_overlay = 4,
    external_provider = 5
};

struct source_provenance_panel_entry_t {
    source_provenance_kind_t kind = source_provenance_kind_t::loader;
    std::uint64_t revision = 0;
    std::string provider;
    std::string artifact;
    std::string coordinate;
    std::uint8_t confidence = 0;
};

using inspector_panel_payload_t = std::variant<
    identity_panel_data_t,
    bytes_panel_data_t,
    std::vector<operand_panel_entry_t>,
    std::vector<xref_panel_entry_t>,
    std::vector<call_panel_entry_t>,
    std::vector<stack_local_panel_entry_t>,
    std::vector<type_panel_entry_t>,
    std::vector<overlay_panel_entry_t>,
    std::vector<diagnostic_panel_entry_t>,
    std::vector<source_provenance_panel_entry_t>>;

struct inspector_query_result_t {
    inspector_lazy_query_t query;
    inspector_panel_payload_t payload;
    std::uint32_t returned_rows = 0;
    std::uint32_t returned_bytes = 0;
    bool complete = false;
};

bool inspector_context_equal(const inspector_context_t& lhs, const inspector_context_t& rhs);
bool inspector_panel_kind_valid(inspector_panel_kind_t panel) noexcept;
std::uint32_t inspector_panel_max_rows(inspector_panel_kind_t panel) noexcept;
inspector_layout_contract_t default_inspector_layout_contract() noexcept;

inspector_error_t validate_inspector_context(const inspector_context_t& context);
inspector_error_t validate_inspector_query_limits(inspector_panel_kind_t panel,
                                                   const inspector_query_limits_t& limits) noexcept;
inspector_error_t validate_inspector_lazy_query(const inspector_lazy_query_t& query);
inspector_error_t validate_inspector_layout_contract(const inspector_layout_contract_t& layout) noexcept;
inspector_error_t validate_inspector_query_result(const inspector_query_result_t& result);

std::uint32_t inspector_payload_rows(const inspector_panel_payload_t& payload) noexcept;
std::uint32_t inspector_payload_bytes(const inspector_panel_payload_t& payload) noexcept;

class inspector_query_session_t {
public:
    inspector_error_t activate(const inspector_context_t& context);
    inspector_error_t request(inspector_panel_kind_t panel,
                              const inspector_query_limits_t& limits,
                              std::string cursor,
                              inspector_lazy_query_t& output);
    inspector_error_t accept(const inspector_query_result_t& result);
    void reset() noexcept;

    const inspector_context_t* active_context() const noexcept;
    std::uint32_t issued_query_count() const noexcept;

private:
    struct issued_query_t {
        inspector_lazy_query_t query;
        bool completed = false;
    };

    std::optional<inspector_context_t> active_;
    std::vector<issued_query_t> issued_;
    std::uint64_t next_query_id_ = 1;
};

}
}
}
