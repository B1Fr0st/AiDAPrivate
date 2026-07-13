#pragma once

#include "../workbench_contracts.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace workbench {
namespace disasm_document {

inline constexpr std::uint32_t k_disasm_document_schema_version = 2;
inline constexpr std::uint32_t k_disasm_document_max_page_size = 512;
inline constexpr std::uint32_t k_disasm_document_max_overlays = 4096;
inline constexpr std::uint32_t k_disasm_document_max_row_text_bytes = 256;
inline constexpr std::uint32_t k_disasm_document_max_raw_bytes = 16;
inline constexpr std::uint64_t k_disasm_document_max_total_rows = 16ULL * 1024 * 1024;

enum class disasm_error_code_t : std::uint16_t {
    none = 0,
    invalid_argument,
    invalid_page,
    stale_generation,
    adapter_rejected,
    overlay_capacity,
    overlay_not_found,
    selection_rejected,
    navigation_rejected,
    resource_exhausted,
    cancelled,
    cross_document_rejected
};

struct disasm_error_t {
    disasm_error_code_t code = disasm_error_code_t::none;
    std::uint64_t subject = 0;

    constexpr bool ok() const noexcept { return code == disasm_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

struct disasm_row_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

constexpr bool operator==(disasm_row_id_t lhs, disasm_row_id_t rhs) noexcept
{
    return lhs.value == rhs.value;
}

constexpr bool operator!=(disasm_row_id_t lhs, disasm_row_id_t rhs) noexcept
{
    return !(lhs == rhs);
}

constexpr bool operator<(disasm_row_id_t lhs, disasm_row_id_t rhs) noexcept
{
    return lhs.value < rhs.value;
}

enum class disasm_overlay_kind_t : std::uint8_t {
    user_annotation = 0,
    patch = 1,
    type_override = 2,
    function_name = 3,
    label = 4,
    comment = 5
};

struct disasm_overlay_entry_t {
    disasm_overlay_kind_t kind = disasm_overlay_kind_t::user_annotation;
    std::uint64_t revision = 0;
    std::uint64_t address = 0;
    std::string text;
    bool active = true;
};

struct disasm_instruction_view_t {
    disasm_row_id_t id;
    std::uint64_t address = 0;
    std::uint32_t byte_size = 0;
    std::string mnemonic;
    std::string operands;
    std::string raw_hex;
    bool has_branch_target = false;
    std::uint64_t branch_target = 0;
    bool has_call_target = false;
    std::uint64_t call_target = 0;
    std::optional<disasm_overlay_entry_t> overlay;
};

struct disasm_page_request_t {
    std::uint64_t offset = 0;
    std::uint32_t limit = 0;
};

struct disasm_page_t {
    std::uint64_t snapshot_generation = 0;
    std::uint64_t total_rows = 0;
    std::uint64_t offset = 0;
    std::uint64_t next_offset = 0;
    std::vector<disasm_instruction_view_t> rows;
};

struct disasm_selection_t {
    selection_kind_t kind = selection_kind_t::none;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t extent = 0;
    disasm_row_id_t start_row;
    disasm_row_id_t end_row;
};

struct disasm_navigation_request_t {
    std::uint64_t address = 0;
    bool select_row = true;
    bool request_focus = true;
};

struct disasm_navigation_result_t {
    bool found = false;
    disasm_row_id_t row;
    std::uint64_t page_offset = 0;
};

enum class disasm_cross_document_target_t : std::uint8_t {
    hex = 0,
    pseudocode = 1,
    graph = 2
};

struct disasm_cross_document_request_t {
    disasm_cross_document_target_t target = disasm_cross_document_target_t::hex;
    std::uint64_t address = 0;
    document_identity_t source_document;
};

struct disasm_cross_document_result_t {
    bool resolved = false;
    document_identity_t target_document;
    selection_context_t target_selection;
    document_local_cursor_t target_cursor;
};

struct disasm_navigation_event_bridge_request_t {
    navigation_event_id_t id;
    std::uint64_t sequence = 0;
    navigation_origin_t origin = navigation_origin_t::adapter;
    view_context_t source;
    disasm_cross_document_request_t navigation;
    bool request_focus = true;
};

class disasm_cancellation_t {
public:
    virtual ~disasm_cancellation_t() = default;
    virtual bool cancelled() const noexcept = 0;
};

class disasm_source_adapter_t {
public:
    virtual ~disasm_source_adapter_t() = default;
    virtual std::uint64_t current_generation() const noexcept = 0;
    virtual bool generation_current(std::uint64_t generation) const noexcept = 0;
    virtual std::uint64_t total_rows(std::uint64_t generation) const noexcept = 0;
    virtual bool row_at(std::uint64_t generation, std::uint64_t ordinal,
                        disasm_instruction_view_t& output) const = 0;
    virtual bool row_by_address(std::uint64_t generation, std::uint64_t address,
                                disasm_instruction_view_t& output,
                                std::uint64_t& ordinal) const = 0;
    virtual std::uint64_t overlay_revision(std::uint64_t generation) const noexcept = 0;
};

class disasm_overlay_adapter_t {
public:
    virtual ~disasm_overlay_adapter_t() = default;
    virtual std::uint32_t overlay_count(std::uint64_t generation) const noexcept = 0;
    virtual bool overlay_at(std::uint64_t generation, std::uint32_t ordinal,
                            disasm_overlay_entry_t& output) const = 0;
    virtual bool overlay_by_address(std::uint64_t generation, std::uint64_t address,
                                    disasm_overlay_entry_t& output) const = 0;
    virtual workbench_error_t apply_overlay(std::uint64_t generation,
                                            const disasm_overlay_entry_t& entry) = 0;
    virtual workbench_error_t remove_overlay(std::uint64_t generation,
                                             std::uint64_t address) = 0;
};

class disasm_navigation_adapter_t {
public:
    virtual ~disasm_navigation_adapter_t() = default;
    virtual workbench_error_t resolve_cross_document(
        const disasm_cross_document_request_t& request,
        disasm_cross_document_result_t& output) const = 0;
};

enum class disasm_command_kind_t : std::uint8_t {
    page = 0,
    navigate = 1,
    select = 2,
    apply_overlay = 3,
    remove_overlay = 4,
    clear_selection = 5,
    refresh = 6,
    cross_document = 7,
    emit_navigation_event = 8,
    apply_navigation_event = 9
};

struct disasm_command_t {
    disasm_command_kind_t kind = disasm_command_kind_t::page;
    std::uint64_t expected_generation = 0;
    disasm_page_request_t page_request;
    disasm_navigation_request_t navigation;
    disasm_selection_t selection;
    disasm_overlay_entry_t overlay;
    std::uint64_t overlay_address = 0;
    disasm_cross_document_request_t cross_document;
    disasm_navigation_event_bridge_request_t navigation_event_bridge;
    navigation_event_t navigation_event;
};

struct disasm_command_result_t {
    disasm_error_t error;
    disasm_page_t page;
    disasm_navigation_result_t navigation;
    disasm_selection_t selection;
    disasm_cross_document_result_t cross_document;
    navigation_event_t navigation_event;
    bool has_navigation_event = false;
    bool changed = false;
};

class disasm_document_model_t final {
public:
    disasm_document_model_t(const disasm_source_adapter_t& source,
                            const disasm_overlay_adapter_t* overlays = nullptr,
                            const disasm_navigation_adapter_t* navigation = nullptr) noexcept;

    disasm_error_t page(const disasm_page_request_t& request,
                        const disasm_cancellation_t* cancellation,
                        disasm_page_t& output) const;

    disasm_error_t navigate(const disasm_navigation_request_t& request,
                            std::uint64_t expected_generation,
                            disasm_navigation_result_t& output) const;

    disasm_error_t select(const disasm_selection_t& selection,
                          std::uint64_t expected_generation);

    void clear_selection() noexcept;

    disasm_error_t apply_overlay(std::uint64_t expected_generation,
                                 const disasm_overlay_entry_t& entry);

    disasm_error_t remove_overlay(std::uint64_t expected_generation,
                                  std::uint64_t address);

    disasm_error_t cross_document(const disasm_cross_document_request_t& request,
                                  disasm_cross_document_result_t& output) const;

    disasm_error_t emit_navigation_event(
        const disasm_navigation_event_bridge_request_t& request,
        navigation_event_t& output) const;

    disasm_error_t apply_navigation_event(
        const navigation_event_t& event,
        std::uint64_t expected_generation,
        disasm_navigation_result_t& output);

    disasm_command_result_t execute(const disasm_command_t& command,
                                    const disasm_cancellation_t* cancellation = nullptr);

    std::uint64_t current_generation() const noexcept;
    bool generation_current(std::uint64_t generation) const noexcept;
    std::uint64_t total_rows() const noexcept;
    const disasm_selection_t& selection() const noexcept;
    std::uint32_t overlay_count() const noexcept;
    bool is_stale() const noexcept;
    std::uint64_t bound_generation() const noexcept;

private:
    disasm_error_t fail(disasm_error_code_t code,
                        std::uint64_t subject = 0) const noexcept;
    disasm_error_t stale() const noexcept;
    bool lease_current(std::uint64_t expected_generation) const noexcept;
    disasm_error_t bounded_total_rows(std::uint64_t& output) const noexcept;
    disasm_error_t validate_row(const disasm_instruction_view_t& row,
                                std::uint64_t ordinal,
                                std::uint64_t total_rows) const noexcept;
    disasm_error_t canonicalize_selection(
        const disasm_selection_t& selection,
        disasm_selection_t& output) const;
    disasm_error_t merge_overlay(disasm_instruction_view_t& row,
                                 std::uint64_t generation) const;

    const disasm_source_adapter_t* source_;
    const disasm_overlay_adapter_t* overlays_;
    const disasm_navigation_adapter_t* navigation_;
    std::uint64_t bound_generation_;
    disasm_selection_t selection_;
};

bool disasm_overlay_kind_valid(disasm_overlay_kind_t kind) noexcept;
bool disasm_page_request_valid(const disasm_page_request_t& request) noexcept;
bool disasm_selection_valid(const disasm_selection_t& selection) noexcept;
bool disasm_overlay_entry_valid(const disasm_overlay_entry_t& entry) noexcept;

}
}
}
