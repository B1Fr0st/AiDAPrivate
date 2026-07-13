#include "diff_document.hpp"

#include <algorithm>

namespace aida {
namespace workbench {
namespace diff_document {
namespace {

bool cancellation_requested(const diff_cancellation_t* cancellation) noexcept
{
    return cancellation != nullptr && cancellation->cancelled();
}

}

bool diff_page_request_valid(const diff_page_request_t& request) noexcept
{
    return request.limit != 0 && request.limit <= k_diff_document_max_page_size;
}

bool diff_selection_valid(const diff_selection_t& selection) noexcept
{
    if (selection.kind == selection_kind_t::none)
        return true;
    if (selection.kind > selection_kind_t::source)
        return false;
    return true;
}

bool diff_domain_filter_matches(diff_domain_t entry_domain,
                                diff_domain_t filter) noexcept
{
    if (static_cast<std::uint8_t>(filter) == 0xFF)
        return true;
    return entry_domain == filter;
}

diff_error_t diff_document_model_t::fail(diff_error_code_t code,
                                          std::uint64_t subject) noexcept
{
    return {code, subject};
}

diff_error_t diff_document_model_t::stale() noexcept
{
    return {diff_error_code_t::stale_generation, bound_generation_};
}

diff_document_model_t::diff_document_model_t(
    const diff_source_adapter_t& source) noexcept
    : source_(&source)
    , bound_generation_(source.current_generation())
{
}

diff_error_t diff_document_model_t::page(
    const diff_page_request_t& request,
    diff_kind_t kind,
    std::uint64_t old_generation,
    std::uint64_t new_generation,
    const diff_cancellation_t* cancellation,
    diff_page_t& output) const
{
    if (!diff_page_request_valid(request))
        return fail(diff_error_code_t::invalid_page, request.limit);

    const auto gen = bound_generation_;
    if (!source_->generation_current(gen))
        return stale();

    const auto total = source_->entry_count(gen, kind, old_generation, new_generation);
    output.snapshot_generation = gen;
    output.diff_kind = kind;
    output.total_entries = total;
    output.offset = request.offset;

    if (total == 0 || request.offset >= total) {
        output.next_offset = 0;
        return {};
    }

    const auto remaining = total - request.offset;
    const auto max_read = (std::min)(static_cast<std::uint64_t>(request.limit), remaining);

    output.entries.clear();
    output.entries.reserve(static_cast<std::size_t>(max_read));

    std::uint64_t read = 0;
    std::uint64_t scan = request.offset;
    while (read < max_read && scan < total) {
        if (cancellation_requested(cancellation))
            return fail(diff_error_code_t::cancelled, scan);
        diff_entry_t entry;
        if (!source_->entry_at(gen, kind, old_generation, new_generation, scan, entry))
            break;
        if (diff_domain_filter_matches(entry.domain, request.domain_filter)) {
            output.entries.push_back(entry);
            ++read;
        }
        ++scan;
    }

    output.next_offset = scan < total ? scan : 0;

    return {};
}

diff_error_t diff_document_model_t::navigate(
    const diff_navigation_request_t& request,
    diff_kind_t kind,
    std::uint64_t old_generation,
    std::uint64_t new_generation,
    diff_navigation_result_t& output) const
{
    const auto gen = bound_generation_;
    if (!source_->generation_current(gen))
        return stale();

    const auto total = source_->entry_count(gen, kind, old_generation, new_generation);
    if (request.entry_index >= total) {
        output.found = false;
        return fail(diff_error_code_t::navigation_rejected, request.entry_index);
    }

    output.found = true;
    output.entry_index = request.entry_index;
    output.page_offset = (request.entry_index / k_diff_document_max_page_size) *
                         k_diff_document_max_page_size;
    return {};
}

diff_error_t diff_document_model_t::select(const diff_selection_t& selection)
{
    if (!diff_selection_valid(selection))
        return fail(diff_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    selection_ = selection;
    return {};
}

void diff_document_model_t::clear_selection() noexcept
{
    selection_ = {};
}

diff_summary_t diff_document_model_t::compute_summary(
    diff_kind_t kind,
    std::uint64_t old_generation,
    std::uint64_t new_generation) const
{
    return source_->summary(bound_generation_, kind, old_generation, new_generation);
}

diff_command_result_t diff_document_model_t::execute(
    const diff_command_t& command,
    const diff_cancellation_t* cancellation)
{
    diff_command_result_t result;

    switch (command.kind) {
    case diff_command_kind_t::page: {
        result.error = page(command.page_request, command.diff_kind,
                            command.old_generation, command.new_generation,
                            cancellation, result.page);
        result.changed = result.error.ok() && !result.page.entries.empty();
        break;
    }
    case diff_command_kind_t::navigate: {
        result.error = navigate(command.navigation, command.diff_kind,
                                command.old_generation, command.new_generation,
                                result.navigation);
        result.changed = result.error.ok() && result.navigation.found;
        if (result.changed && command.navigation.select_entry) {
            diff_selection_t sel;
            sel.kind = selection_kind_t::address;
            sel.has_address = true;
            sel.entry_index = command.navigation.entry_index;
            selection_ = sel;
            result.selection = sel;
        }
        break;
    }
    case diff_command_kind_t::select: {
        result.error = select(command.selection);
        result.selection = selection_;
        result.changed = result.error.ok();
        break;
    }
    case diff_command_kind_t::clear_selection: {
        clear_selection();
        result.changed = true;
        break;
    }
    case diff_command_kind_t::refresh: {
        const auto new_gen = source_->current_generation();
        if (new_gen != bound_generation_) {
            bound_generation_ = new_gen;
            selection_ = {};
            result.changed = true;
        }
        break;
    }
    case diff_command_kind_t::summary: {
        result.summary = compute_summary(command.diff_kind,
                                         command.old_generation,
                                         command.new_generation);
        result.changed = true;
        break;
    }
    default:
        result.error = fail(diff_error_code_t::invalid_argument,
                            static_cast<std::uint64_t>(command.kind));
        break;
    }

    return result;
}

std::uint64_t diff_document_model_t::current_generation() const noexcept
{
    return source_->current_generation();
}

bool diff_document_model_t::generation_current(
    std::uint64_t generation) const noexcept
{
    return source_->generation_current(generation);
}

bool diff_document_model_t::is_stale() const noexcept
{
    return !source_->generation_current(bound_generation_);
}

std::uint64_t diff_document_model_t::bound_generation() const noexcept
{
    return bound_generation_;
}

const diff_selection_t& diff_document_model_t::selection() const noexcept
{
    return selection_;
}

}
}
}
