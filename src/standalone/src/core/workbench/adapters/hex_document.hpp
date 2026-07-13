#pragma once

#include "../workbench_contracts.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aida {
namespace workbench {
namespace hex_document {

inline constexpr std::uint32_t k_hex_document_schema_version = 1;
inline constexpr std::uint32_t k_hex_document_max_page_size = 1024;
inline constexpr std::uint32_t k_hex_document_bytes_per_row = 16;
inline constexpr std::uint32_t k_hex_document_max_overlays = 8192;
inline constexpr std::uint32_t k_hex_document_max_patch_bytes = 4096;
inline constexpr std::uint64_t k_hex_document_max_total_rows = 64ULL * 1024 * 1024;

enum class hex_error_code_t : std::uint16_t {
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

struct hex_error_t {
    hex_error_code_t code = hex_error_code_t::none;
    std::uint64_t subject = 0;

    constexpr bool ok() const noexcept { return code == hex_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

struct hex_row_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

constexpr bool operator==(hex_row_id_t lhs, hex_row_id_t rhs) noexcept
{
    return lhs.value == rhs.value;
}

constexpr bool operator!=(hex_row_id_t lhs, hex_row_id_t rhs) noexcept
{
    return !(lhs == rhs);
}

constexpr bool operator<(hex_row_id_t lhs, hex_row_id_t rhs) noexcept
{
    return lhs.value < rhs.value;
}

enum class hex_overlay_kind_t : std::uint8_t {
    patch = 0,
    annotation = 1,
    highlight = 2
};

struct hex_overlay_entry_t {
    hex_overlay_kind_t kind = hex_overlay_kind_t::patch;
    std::uint64_t revision = 0;
    std::uint64_t address = 0;
    std::uint64_t extent = 0;
    std::vector<std::uint8_t> patch_bytes;
    std::string text;
    bool active = true;
};

struct hex_row_view_t {
    hex_row_id_t id;
    std::uint64_t address = 0;
    std::string_view hex_text;
    std::string_view ascii_text;
    std::uint32_t byte_count = 0;
    const hex_overlay_entry_t* overlay = nullptr;
};

struct hex_page_request_t {
    std::uint64_t offset = 0;
    std::uint32_t limit = 0;
};

struct hex_page_t {
    std::uint64_t snapshot_generation = 0;
    std::uint64_t total_rows = 0;
    std::uint64_t offset = 0;
    std::uint64_t next_offset = 0;
    std::vector<hex_row_view_t> rows;
    std::vector<hex_overlay_entry_t> overlay_storage;
};

struct hex_selection_t {
    selection_kind_t kind = selection_kind_t::none;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t extent = 0;
    hex_row_id_t start_row;
    hex_row_id_t end_row;
};

struct hex_navigation_request_t {
    std::uint64_t address = 0;
    bool select_row = true;
    bool request_focus = true;
};

struct hex_navigation_result_t {
    bool found = false;
    hex_row_id_t row;
    std::uint64_t page_offset = 0;
};

enum class hex_cross_document_target_t : std::uint8_t {
    disassembly = 0,
    pseudocode = 1,
    graph = 2
};

struct hex_cross_document_request_t {
    hex_cross_document_target_t target = hex_cross_document_target_t::disassembly;
    std::uint64_t address = 0;
    document_identity_t source_document;
};

struct hex_cross_document_result_t {
    bool resolved = false;
    document_identity_t target_document;
    selection_context_t target_selection;
    document_local_cursor_t target_cursor;
};

class hex_cancellation_t {
public:
    virtual ~hex_cancellation_t() = default;
    virtual bool cancelled() const noexcept = 0;
};

class hex_source_adapter_t {
public:
    virtual ~hex_source_adapter_t() = default;
    virtual std::uint64_t current_generation() const noexcept = 0;
    virtual bool generation_current(std::uint64_t generation) const noexcept = 0;
    virtual std::uint64_t total_rows(std::uint64_t generation) const noexcept = 0;
    virtual bool row_at(std::uint64_t generation, std::uint64_t ordinal,
                        hex_row_view_t& output) const noexcept = 0;
    virtual bool row_by_address(std::uint64_t generation, std::uint64_t address,
                                hex_row_view_t& output,
                                std::uint64_t& ordinal) const noexcept = 0;
    virtual std::uint64_t overlay_revision(std::uint64_t generation) const noexcept = 0;
};

class hex_overlay_adapter_t {
public:
    virtual ~hex_overlay_adapter_t() = default;
    virtual std::uint32_t overlay_count(std::uint64_t generation) const noexcept = 0;
    virtual bool overlay_at(std::uint64_t generation, std::uint32_t ordinal,
                            hex_overlay_entry_t& output) const noexcept = 0;
    virtual bool overlay_by_address(std::uint64_t generation, std::uint64_t address,
                                    hex_overlay_entry_t& output) const noexcept = 0;
    virtual workbench_error_t apply_overlay(std::uint64_t generation,
                                            const hex_overlay_entry_t& entry) = 0;
    virtual workbench_error_t remove_overlay(std::uint64_t generation,
                                             std::uint64_t address) = 0;
};

class hex_navigation_adapter_t {
public:
    virtual ~hex_navigation_adapter_t() = default;
    virtual workbench_error_t resolve_cross_document(
        const hex_cross_document_request_t& request,
        hex_cross_document_result_t& output) const = 0;
};

enum class hex_command_kind_t : std::uint8_t {
    page = 0,
    navigate = 1,
    select = 2,
    apply_overlay = 3,
    remove_overlay = 4,
    clear_selection = 5,
    refresh = 6,
    cross_document = 7
};

struct hex_command_t {
    hex_command_kind_t kind = hex_command_kind_t::page;
    std::uint64_t expected_generation = 0;
    hex_page_request_t page_request;
    hex_navigation_request_t navigation;
    hex_selection_t selection;
    hex_overlay_entry_t overlay;
    std::uint64_t overlay_address = 0;
    hex_cross_document_request_t cross_document;
};

struct hex_command_result_t {
    hex_error_t error;
    hex_page_t page;
    hex_navigation_result_t navigation;
    hex_selection_t selection;
    hex_cross_document_result_t cross_document;
    bool changed = false;
};

class hex_document_model_t final {
public:
    hex_document_model_t(const hex_source_adapter_t& source,
                         const hex_overlay_adapter_t* overlays = nullptr,
                         const hex_navigation_adapter_t* navigation = nullptr) noexcept;

    hex_error_t page(const hex_page_request_t& request,
                     const hex_cancellation_t* cancellation,
                     hex_page_t& output) const;

    hex_error_t navigate(const hex_navigation_request_t& request,
                         std::uint64_t expected_generation,
                         hex_navigation_result_t& output) const;

    hex_error_t select(const hex_selection_t& selection,
                       std::uint64_t expected_generation);

    void clear_selection() noexcept;

    hex_error_t apply_overlay(std::uint64_t expected_generation,
                              const hex_overlay_entry_t& entry);

    hex_error_t remove_overlay(std::uint64_t expected_generation,
                               std::uint64_t address);

    hex_error_t cross_document(const hex_cross_document_request_t& request,
                               hex_cross_document_result_t& output) const;

    hex_command_result_t execute(const hex_command_t& command,
                                 const hex_cancellation_t* cancellation = nullptr);

    std::uint64_t current_generation() const noexcept;
    bool generation_current(std::uint64_t generation) const noexcept;
    std::uint64_t total_rows() const noexcept;
    const hex_selection_t& selection() const noexcept;
    std::uint32_t overlay_count() const noexcept;
    bool is_stale() const noexcept;
    std::uint64_t bound_generation() const noexcept;

private:
    hex_error_t fail(hex_error_code_t code, std::uint64_t subject = 0) noexcept;
    hex_error_t stale() noexcept;
    bool merge_overlay(hex_row_view_t& row,
                       std::uint64_t generation,
                       std::vector<hex_overlay_entry_t>& storage) const noexcept;

    const hex_source_adapter_t* source_;
    const hex_overlay_adapter_t* overlays_;
    const hex_navigation_adapter_t* navigation_;
    std::uint64_t bound_generation_;
    hex_selection_t selection_;
};

bool hex_overlay_kind_valid(hex_overlay_kind_t kind) noexcept;
bool hex_page_request_valid(const hex_page_request_t& request) noexcept;
bool hex_selection_valid(const hex_selection_t& selection) noexcept;
bool hex_overlay_entry_valid(const hex_overlay_entry_t& entry) noexcept;

}
}
}
