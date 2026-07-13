#pragma once

#include "../workbench_contracts.h"

#include <cstdint>
#include <string>
#include <vector>

namespace aida::workbench::adapters {

inline constexpr std::uint32_t k_document_adapter_schema_version = 1;
inline constexpr std::uint32_t k_document_adapter_max_page_size = 8192;
inline constexpr std::uint32_t k_document_adapter_max_overlays = 256;
inline constexpr std::uint32_t k_document_adapter_max_selection_extent = 0xFFFFFFFFu;
inline constexpr std::uint64_t k_document_adapter_invalid_generation = 0;

enum class document_adapter_error_code_t : std::uint16_t {
    none = 0,
    invalid_request,
    stale_generation,
    invalid_page,
    page_overflow,
    invalid_selection,
    invalid_overlay,
    overlay_conflict,
    adapter_rejected,
    cancelled,
    resource_exhausted,
    worker_failure,
    missing_entity,
    layout_cancelled,
    layout_overflow,
    diff_mismatch,
    invalid_profile,
    explicit_request_required,
    navigation_mismatch,
    synchronization_rejected,
    out_of_bounds,
    invalid_generation
};

struct document_adapter_error_t {
    document_adapter_error_code_t code = document_adapter_error_code_t::none;
    std::uint64_t subject = 0;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr bool ok() const noexcept { return code == document_adapter_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

class document_cancellation_t {
public:
    virtual ~document_cancellation_t() = default;
    virtual bool cancelled() const noexcept = 0;
};

enum class document_overlay_kind_t : std::uint8_t {
    user_annotation = 0,
    patch = 1,
    type_override = 2,
    analysis_annotation = 3,
    debug_annotation = 4,
    highlight = 5,
    bookmark = 6
};

struct document_overlay_descriptor_t {
    std::uint64_t revision = 0;
    document_overlay_kind_t kind = document_overlay_kind_t::user_annotation;
    std::string name;
    std::string summary;
    bool active = false;
    bool has_address_range = false;
    std::uint64_t address_begin = 0;
    std::uint64_t address_end = 0;
};

struct document_page_request_t {
    std::uint64_t offset = 0;
    std::uint32_t limit = 0;
    std::uint64_t generation = 0;
};

struct document_selection_request_t {
    std::uint64_t generation = 0;
    selection_context_t selection;
};

struct document_navigation_sync_t {
    document_id_t source_document;
    document_kind_t source_kind = document_kind_t::unknown;
    selection_context_t selection;
    document_local_cursor_t cursor;
    std::uint64_t generation = 0;
    view_synchronization_policy_t policy = view_synchronization_policy_t::independent;
    std::uint64_t synchronization_group = 0;
};

struct document_navigation_proposal_t {
    document_identity_t target_document;
    selection_context_t selection;
    document_local_cursor_t cursor;
    bool requires_document_open = false;
};

document_adapter_error_t document_adapter_error(document_adapter_error_code_t code,
                                                std::uint64_t subject = 0,
                                                std::uint64_t expected = 0,
                                                std::uint64_t actual = 0) noexcept;

bool document_overlay_kind_valid(document_overlay_kind_t kind) noexcept;
workbench_error_t validate_document_page_request(const document_page_request_t& request) noexcept;
workbench_error_t validate_document_selection_request(const document_selection_request_t& request);
workbench_error_t validate_document_navigation_sync(const document_navigation_sync_t& sync);

}
