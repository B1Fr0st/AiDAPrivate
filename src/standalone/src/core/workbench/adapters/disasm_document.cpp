#include "disasm_document.hpp"

#include <algorithm>
#include <limits>

namespace aida {
namespace workbench {
namespace disasm_document {
namespace {

bool cancellation_requested(const disasm_cancellation_t* cancellation) noexcept
{
    return cancellation != nullptr && cancellation->cancelled();
}

}

bool disasm_overlay_kind_valid(disasm_overlay_kind_t kind) noexcept
{
    return kind <= disasm_overlay_kind_t::comment;
}

bool disasm_page_request_valid(const disasm_page_request_t& request) noexcept
{
    return request.limit != 0 && request.limit <= k_disasm_document_max_page_size;
}

bool disasm_selection_valid(const disasm_selection_t& selection) noexcept
{
    if (selection.kind == selection_kind_t::none)
        return true;
    if (selection.kind > selection_kind_t::source)
        return false;
    if (selection.kind == selection_kind_t::range) {
        if (!selection.start_row.valid() || !selection.end_row.valid())
            return false;
        if (selection.end_row < selection.start_row)
            return false;
    }
    return true;
}

bool disasm_overlay_entry_valid(const disasm_overlay_entry_t& entry) noexcept
{
    if (!disasm_overlay_kind_valid(entry.kind))
        return false;
    if (entry.text.size() > k_disasm_document_max_row_text_bytes)
        return false;
    return true;
}

disasm_error_t disasm_document_model_t::fail(disasm_error_code_t code,
                                              std::uint64_t subject) noexcept
{
    return {code, subject};
}

disasm_error_t disasm_document_model_t::stale() noexcept
{
    return {disasm_error_code_t::stale_generation, bound_generation_};
}

disasm_document_model_t::disasm_document_model_t(
    const disasm_source_adapter_t& source,
    const disasm_overlay_adapter_t* overlays,
    const disasm_navigation_adapter_t* navigation) noexcept
    : source_(&source)
    , overlays_(overlays)
    , navigation_(navigation)
    , bound_generation_(source.current_generation())
{
}

bool disasm_document_model_t::merge_overlay(
    disasm_instruction_view_t& row,
    std::uint64_t generation,
    std::vector<disasm_overlay_entry_t>& storage) const noexcept
{
    if (!overlays_)
        return false;
    disasm_overlay_entry_t entry;
    if (!overlays_->overlay_by_address(generation, row.address, entry))
        return false;
    if (!entry.active)
        return false;
    storage.push_back(std::move(entry));
    row.overlay = &storage.back();
    return true;
}

disasm_error_t disasm_document_model_t::page(const disasm_page_request_t& request,
                                              const disasm_cancellation_t* cancellation,
                                              disasm_page_t& output) const
{
    if (!disasm_page_request_valid(request))
        return fail(disasm_error_code_t::invalid_page, request.limit);

    const auto gen = bound_generation_;
    if (!source_->generation_current(gen))
        return stale();

    const auto total = source_->total_rows(gen);
    output.snapshot_generation = gen;
    output.total_rows = total;
    output.offset = request.offset;

    if (total == 0 || request.offset >= total) {
        output.next_offset = 0;
        return {};
    }

    const auto remaining = total - request.offset;
    const auto to_read = (std::min)(static_cast<std::uint64_t>(request.limit), remaining);

    output.rows.clear();
    output.rows.reserve(static_cast<std::size_t>(to_read));

    for (std::uint64_t i = 0; i < to_read; ++i) {
        if (cancellation_requested(cancellation))
            return fail(disasm_error_code_t::cancelled, i);
        disasm_instruction_view_t row;
        if (!source_->row_at(gen, request.offset + i, row))
            break;
        row.id = disasm_row_id_t{request.offset + i + 1ULL};
        merge_overlay(row, gen, output.overlay_storage);
        output.rows.push_back(row);
    }

    output.next_offset = request.offset + output.rows.size();
    if (output.next_offset >= total)
        output.next_offset = 0;

    return {};
}

disasm_error_t disasm_document_model_t::navigate(
    const disasm_navigation_request_t& request,
    std::uint64_t expected_generation,
    disasm_navigation_result_t& output) const
{
    if (!source_->generation_current(expected_generation))
        return stale();

    const auto gen = expected_generation;
    disasm_instruction_view_t row;
    std::uint64_t ordinal = 0;
    if (!source_->row_by_address(gen, request.address, row, ordinal)) {
        output.found = false;
        return fail(disasm_error_code_t::navigation_rejected, request.address);
    }

    output.found = true;
    output.row = disasm_row_id_t{ordinal + 1ULL};
    output.page_offset = (ordinal / k_disasm_document_max_page_size) *
                         k_disasm_document_max_page_size;
    return {};
}

disasm_error_t disasm_document_model_t::select(const disasm_selection_t& selection,
                                                std::uint64_t expected_generation)
{
    if (!disasm_selection_valid(selection))
        return fail(disasm_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    if (!source_->generation_current(expected_generation))
        return stale();
    selection_ = selection;
    return {};
}

void disasm_document_model_t::clear_selection() noexcept
{
    selection_ = {};
}

disasm_error_t disasm_document_model_t::apply_overlay(
    std::uint64_t expected_generation,
    const disasm_overlay_entry_t& entry)
{
    if (!disasm_overlay_entry_valid(entry))
        return fail(disasm_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(entry.kind));
    if (!overlays_)
        return fail(disasm_error_code_t::adapter_rejected, 0);
    if (!source_->generation_current(expected_generation))
        return stale();
    if (overlays_->overlay_count(expected_generation) >= k_disasm_document_max_overlays)
        return fail(disasm_error_code_t::overlay_capacity,
                    k_disasm_document_max_overlays);
    auto wb_err = overlays_->apply_overlay(expected_generation, entry);
    if (!wb_err)
        return fail(disasm_error_code_t::adapter_rejected, static_cast<std::uint64_t>(wb_err.code));
    return {};
}

disasm_error_t disasm_document_model_t::remove_overlay(
    std::uint64_t expected_generation,
    std::uint64_t address)
{
    if (!overlays_)
        return fail(disasm_error_code_t::adapter_rejected, 0);
    if (!source_->generation_current(expected_generation))
        return stale();
    disasm_overlay_entry_t existing;
    if (!overlays_->overlay_by_address(expected_generation, address, existing))
        return fail(disasm_error_code_t::overlay_not_found, address);
    auto wb_err = overlays_->remove_overlay(expected_generation, address);
    if (!wb_err)
        return fail(disasm_error_code_t::adapter_rejected, static_cast<std::uint64_t>(wb_err.code));
    return {};
}

disasm_error_t disasm_document_model_t::cross_document(
    const disasm_cross_document_request_t& request,
    disasm_cross_document_result_t& output) const
{
    if (!navigation_)
        return fail(disasm_error_code_t::cross_document_rejected, 0);
    auto wb_err = navigation_->resolve_cross_document(request, output);
    if (!wb_err)
        return fail(disasm_error_code_t::cross_document_rejected,
                    static_cast<std::uint64_t>(wb_err.code));
    return {};
}

disasm_command_result_t disasm_document_model_t::execute(
    const disasm_command_t& command,
    const disasm_cancellation_t* cancellation)
{
    disasm_command_result_t result;

    switch (command.kind) {
    case disasm_command_kind_t::page: {
        result.error = page(command.page_request, cancellation, result.page);
        result.changed = result.error.ok() && !result.page.rows.empty();
        break;
    }
    case disasm_command_kind_t::navigate: {
        result.error = navigate(command.navigation, command.expected_generation,
                                result.navigation);
        result.changed = result.error.ok() && result.navigation.found;
        if (result.changed && command.navigation.select_row) {
            disasm_selection_t sel;
            sel.kind = selection_kind_t::address;
            sel.has_address = true;
            sel.address = command.navigation.address;
            sel.extent = 1;
            sel.start_row = result.navigation.row;
            sel.end_row = result.navigation.row;
            selection_ = sel;
            result.selection = sel;
        }
        break;
    }
    case disasm_command_kind_t::select: {
        result.error = select(command.selection, command.expected_generation);
        result.selection = selection_;
        result.changed = result.error.ok();
        break;
    }
    case disasm_command_kind_t::apply_overlay: {
        result.error = apply_overlay(command.expected_generation, command.overlay);
        result.changed = result.error.ok();
        break;
    }
    case disasm_command_kind_t::remove_overlay: {
        result.error = remove_overlay(command.expected_generation, command.overlay_address);
        result.changed = result.error.ok();
        break;
    }
    case disasm_command_kind_t::clear_selection: {
        clear_selection();
        result.changed = true;
        break;
    }
    case disasm_command_kind_t::refresh: {
        const auto new_gen = source_->current_generation();
        if (new_gen != bound_generation_) {
            bound_generation_ = new_gen;
            selection_ = {};
            result.changed = true;
        }
        break;
    }
    case disasm_command_kind_t::cross_document: {
        result.error = cross_document(command.cross_document, result.cross_document);
        result.changed = result.error.ok() && result.cross_document.resolved;
        break;
    }
    default:
        result.error = fail(disasm_error_code_t::invalid_argument,
                            static_cast<std::uint64_t>(command.kind));
        break;
    }

    return result;
}

std::uint64_t disasm_document_model_t::current_generation() const noexcept
{
    return source_->current_generation();
}

bool disasm_document_model_t::generation_current(
    std::uint64_t generation) const noexcept
{
    return source_->generation_current(generation);
}

std::uint64_t disasm_document_model_t::total_rows() const noexcept
{
    return source_->total_rows(bound_generation_);
}

const disasm_selection_t& disasm_document_model_t::selection() const noexcept
{
    return selection_;
}

std::uint32_t disasm_document_model_t::overlay_count() const noexcept
{
    if (!overlays_)
        return 0;
    return overlays_->overlay_count(bound_generation_);
}

bool disasm_document_model_t::is_stale() const noexcept
{
    return !source_->generation_current(bound_generation_);
}

std::uint64_t disasm_document_model_t::bound_generation() const noexcept
{
    return bound_generation_;
}

}
}
}
