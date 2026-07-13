#include "document_adapter_base.hpp"

#include <algorithm>

namespace aida::workbench::adapters {

document_adapter_error_t document_adapter_error(document_adapter_error_code_t code,
                                                std::uint64_t subject,
                                                std::uint64_t expected,
                                                std::uint64_t actual) noexcept
{
    return {code, subject, expected, actual};
}

bool document_overlay_kind_valid(document_overlay_kind_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <= static_cast<std::uint8_t>(document_overlay_kind_t::bookmark);
}

workbench_error_t validate_document_page_request(const document_page_request_t& request) noexcept
{
    if (request.generation == k_document_adapter_invalid_generation)
        return {workbench_error_code_t::invalid_document_state, request.generation};
    if (request.limit == 0)
        return {workbench_error_code_t::invalid_navigation, 0};
    if (request.limit > k_document_adapter_max_page_size)
        return {workbench_error_code_t::invalid_navigation, request.limit};
    return {};
}

workbench_error_t validate_document_selection_request(const document_selection_request_t& request)
{
    if (request.generation == k_document_adapter_invalid_generation)
        return {workbench_error_code_t::invalid_document_state, request.generation};
    auto sel_err = validate_selection_context(request.selection);
    if (!sel_err.ok())
        return sel_err;
    return {};
}

workbench_error_t validate_document_navigation_sync(const document_navigation_sync_t& sync)
{
    if (sync.generation == k_document_adapter_invalid_generation)
        return {workbench_error_code_t::invalid_document_state, sync.generation};
    if (!sync.source_document.valid())
        return {workbench_error_code_t::invalid_document, sync.source_document.value};
    auto sel_err = validate_selection_context(sync.selection);
    if (!sel_err.ok())
        return sel_err;
    if (sync.policy == view_synchronization_policy_t::independent)
        return {workbench_error_code_t::invalid_synchronization_policy, 0};
    return {};
}

}
