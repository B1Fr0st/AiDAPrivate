#pragma once

#include "../workbench_contracts.h"

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace workbench {
namespace diff_document {

inline constexpr std::uint32_t k_diff_document_schema_version = 2;
inline constexpr std::uint32_t k_diff_document_max_page_size = 512;
inline constexpr std::uint64_t k_diff_document_max_entries = 1'000'000;
inline constexpr std::uint64_t k_diff_document_max_filtered_scan = 8192;
inline constexpr std::uint32_t k_diff_document_max_entity_key_bytes = 4096;
inline constexpr std::uint32_t k_diff_document_max_value_bytes = 16'384;

enum class diff_error_code_t : std::uint16_t {
    none = 0,
    invalid_argument,
    invalid_page,
    stale_generation,
    adapter_rejected,
    selection_rejected,
    navigation_rejected,
    resource_exhausted,
    cancelled
};

struct diff_error_t {
    diff_error_code_t code = diff_error_code_t::none;
    std::uint64_t subject = 0;

    constexpr bool ok() const noexcept { return code == diff_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

enum class diff_kind_t : std::uint8_t {
    generation = 0,
    overlay = 1,
    workspace = 2
};

enum class diff_entry_kind_t : std::uint8_t {
    added = 0,
    removed = 1,
    modified = 2,
    moved = 3
};

enum class diff_domain_t : std::uint8_t {
    instruction = 0,
    function = 1,
    type = 2,
    string = 3,
    import = 4,
    export_entry = 5,
    symbol = 6,
    overlay = 7,
    section = 8
};

struct diff_endpoint_t {
    std::uint64_t workspace_id = 0;
    std::uint64_t generation = 0;
    std::uint64_t overlay_revision = 0;
};

struct diff_scope_t {
    diff_kind_t kind = diff_kind_t::generation;
    diff_endpoint_t before;
    diff_endpoint_t after;
};

constexpr bool operator==(const diff_endpoint_t& lhs,
                          const diff_endpoint_t& rhs) noexcept
{
    return lhs.workspace_id == rhs.workspace_id &&
           lhs.generation == rhs.generation &&
           lhs.overlay_revision == rhs.overlay_revision;
}

constexpr bool operator!=(const diff_endpoint_t& lhs,
                          const diff_endpoint_t& rhs) noexcept
{
    return !(lhs == rhs);
}

constexpr bool operator==(const diff_scope_t& lhs,
                          const diff_scope_t& rhs) noexcept
{
    return lhs.kind == rhs.kind && lhs.before == rhs.before &&
           lhs.after == rhs.after;
}

constexpr bool operator!=(const diff_scope_t& lhs,
                          const diff_scope_t& rhs) noexcept
{
    return !(lhs == rhs);
}

struct diff_entry_t {
    diff_entry_kind_t kind = diff_entry_kind_t::added;
    diff_domain_t domain = diff_domain_t::instruction;
    std::uint64_t address = 0;
    std::string entity_key;
    std::string old_value;
    std::string new_value;
    std::uint64_t old_address = 0;
    std::uint64_t new_address = 0;
};

struct diff_summary_t {
    std::uint64_t snapshot_generation = 0;
    diff_scope_t scope;
    std::uint64_t total_entries = 0;
    std::uint64_t added_count = 0;
    std::uint64_t removed_count = 0;
    std::uint64_t modified_count = 0;
    std::uint64_t moved_count = 0;
};

struct diff_page_request_t {
    std::uint64_t offset = 0;
    std::uint32_t limit = 0;
    diff_domain_t domain_filter = static_cast<diff_domain_t>(0xFF);
};

struct diff_page_t {
    std::uint64_t snapshot_generation = 0;
    diff_scope_t scope;
    std::uint64_t total_entries = 0;
    std::uint64_t offset = 0;
    std::uint64_t next_offset = 0;
    std::uint64_t scanned_entries = 0;
    std::vector<diff_entry_t> entries;
};

struct diff_selection_t {
    selection_kind_t kind = selection_kind_t::none;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t entry_index = 0;
    diff_domain_t domain = diff_domain_t::instruction;
    std::string entity_key;
};

struct diff_navigation_request_t {
    std::uint64_t entry_index = 0;
    std::uint32_t page_size = k_diff_document_max_page_size;
    bool select_entry = true;
};

struct diff_navigation_result_t {
    bool found = false;
    std::uint64_t entry_index = 0;
    std::uint64_t page_offset = 0;
    diff_selection_t selection;
};

class diff_cancellation_t {
public:
    virtual ~diff_cancellation_t() = default;
    virtual bool cancelled() const noexcept = 0;
};

class diff_source_adapter_t {
public:
    virtual ~diff_source_adapter_t() = default;
    virtual std::uint64_t current_generation() const noexcept = 0;
    virtual bool generation_current(std::uint64_t generation) const noexcept = 0;
    virtual bool supports_kind(diff_kind_t kind) const noexcept = 0;
    virtual bool scope_available(std::uint64_t generation,
                                 const diff_scope_t& scope) const noexcept = 0;
    virtual std::uint64_t entry_count(std::uint64_t generation,
                                      const diff_scope_t& scope) const noexcept = 0;
    virtual bool entry_at(std::uint64_t generation, const diff_scope_t& scope,
                          std::uint64_t ordinal,
                          diff_entry_t& output) const noexcept = 0;
    virtual bool summary(std::uint64_t generation, const diff_scope_t& scope,
                         diff_summary_t& output) const noexcept = 0;
};

enum class diff_command_kind_t : std::uint8_t {
    page = 0,
    navigate = 1,
    select = 2,
    clear_selection = 3,
    refresh = 4,
    summary = 5
};

struct diff_command_t {
    diff_command_kind_t kind = diff_command_kind_t::page;
    std::uint64_t expected_generation = 0;
    diff_scope_t scope;
    diff_page_request_t page_request;
    diff_navigation_request_t navigation;
    diff_selection_t selection;
};

struct diff_command_result_t {
    diff_error_t error;
    diff_page_t page;
    diff_summary_t summary;
    diff_navigation_result_t navigation;
    diff_selection_t selection;
    bool changed = false;
};

class diff_document_model_t final {
public:
    diff_document_model_t(const diff_source_adapter_t& source) noexcept;

    diff_error_t page(const diff_page_request_t& request,
                      std::uint64_t expected_generation,
                      const diff_scope_t& scope,
                      const diff_cancellation_t* cancellation,
                      diff_page_t& output) const;

    diff_error_t navigate(const diff_navigation_request_t& request,
                          std::uint64_t expected_generation,
                          const diff_scope_t& scope,
                          diff_navigation_result_t& output);

    diff_error_t select(const diff_selection_t& selection,
                        std::uint64_t expected_generation,
                        const diff_scope_t& scope);
    diff_error_t clear_selection(std::uint64_t expected_generation) noexcept;

    diff_error_t compute_summary(std::uint64_t expected_generation,
                                 const diff_scope_t& scope,
                                 diff_summary_t& output) const;

    diff_command_result_t execute(const diff_command_t& command,
                                  const diff_cancellation_t* cancellation = nullptr);

    std::uint64_t current_generation() const noexcept;
    bool generation_current(std::uint64_t generation) const noexcept;
    bool is_stale() const noexcept;
    std::uint64_t bound_generation() const noexcept;
    const diff_selection_t& selection() const noexcept;

private:
    diff_error_t fail(diff_error_code_t code,
                      std::uint64_t subject = 0) const noexcept;
    diff_error_t stale() const noexcept;

    const diff_source_adapter_t* source_;
    std::uint64_t bound_generation_;
    diff_selection_t selection_;
};

bool diff_page_request_valid(const diff_page_request_t& request) noexcept;
bool diff_selection_valid(const diff_selection_t& selection) noexcept;
bool diff_scope_valid(const diff_scope_t& scope) noexcept;
bool diff_domain_filter_matches(diff_domain_t entry_domain,
                                diff_domain_t filter) noexcept;

}
}
}
