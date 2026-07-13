#include "diff_document.hpp"

#include <algorithm>
#include <utility>

namespace aida {
namespace workbench {
namespace diff_document {
namespace {

bool cancellation_requested(const diff_cancellation_t* cancellation) noexcept
{
    return cancellation != nullptr && cancellation->cancelled();
}

bool diff_kind_valid(diff_kind_t kind) noexcept
{
    return kind <= diff_kind_t::workspace;
}

bool diff_domain_valid(diff_domain_t domain) noexcept
{
    return domain <= diff_domain_t::section;
}

bool all_domains(diff_domain_t domain) noexcept
{
    return static_cast<std::uint8_t>(domain) == 0xFF;
}

bool diff_entry_valid(const diff_entry_t& entry) noexcept
{
    if (entry.kind > diff_entry_kind_t::moved || !diff_domain_valid(entry.domain))
        return false;
    if (entry.entity_key.empty() ||
        entry.entity_key.size() > k_diff_document_max_entity_key_bytes ||
        entry.old_value.size() > k_diff_document_max_value_bytes ||
        entry.new_value.size() > k_diff_document_max_value_bytes) {
        return false;
    }
    if (entry.kind == diff_entry_kind_t::added && entry.old_address != 0)
        return false;
    if (entry.kind == diff_entry_kind_t::removed && entry.new_address != 0)
        return false;
    if (entry.kind == diff_entry_kind_t::moved) {
        const auto has_old_address = entry.old_address != 0;
        const auto has_new_address = entry.new_address != 0;
        if (has_old_address != has_new_address ||
            (has_old_address && entry.old_address == entry.new_address)) {
            return false;
        }
    }
    return true;
}

std::uint64_t navigation_address(const diff_entry_t& entry) noexcept
{
    switch (entry.kind) {
    case diff_entry_kind_t::added:
        return entry.new_address != 0 ? entry.new_address : entry.address;
    case diff_entry_kind_t::removed:
        return entry.old_address != 0 ? entry.old_address : entry.address;
    case diff_entry_kind_t::modified:
    case diff_entry_kind_t::moved:
        if (entry.new_address != 0)
            return entry.new_address;
        if (entry.address != 0)
            return entry.address;
        return entry.old_address;
    default:
        return 0;
    }
}

diff_selection_t selection_for_entry(const diff_entry_t& entry,
                                     std::uint64_t entry_index)
{
    diff_selection_t selection;
    selection.entry_index = entry_index;
    selection.domain = entry.domain;
    selection.entity_key = entry.entity_key;
    selection.address = navigation_address(entry);
    selection.has_address = selection.address != 0;
    selection.kind = selection.has_address ? selection_kind_t::address
                                           : selection_kind_t::entity;
    return selection;
}

bool selection_matches(const diff_selection_t& requested,
                       const diff_selection_t& canonical) noexcept
{
    if (requested.kind != canonical.kind ||
        requested.entry_index != canonical.entry_index ||
        requested.domain != canonical.domain ||
        requested.has_address != canonical.has_address) {
        return false;
    }
    if (canonical.has_address) {
        return requested.address == canonical.address &&
               requested.entity_key == canonical.entity_key;
    }
    return requested.address == 0 && requested.entity_key == canonical.entity_key;
}

bool summary_counts_valid(const diff_summary_t& summary) noexcept
{
    if (summary.added_count > summary.total_entries ||
        summary.removed_count > summary.total_entries ||
        summary.modified_count > summary.total_entries ||
        summary.moved_count > summary.total_entries) {
        return false;
    }
    return summary.added_count + summary.removed_count +
               summary.modified_count + summary.moved_count ==
           summary.total_entries;
}

}

bool diff_scope_valid(const diff_scope_t& scope) noexcept
{
    if (!diff_kind_valid(scope.kind) || scope.before.workspace_id == 0 ||
        scope.after.workspace_id == 0 || scope.before.generation == 0 ||
        scope.after.generation == 0) {
        return false;
    }

    switch (scope.kind) {
    case diff_kind_t::generation:
        return scope.before.workspace_id == scope.after.workspace_id &&
               scope.before.generation != scope.after.generation &&
               scope.before.overlay_revision == 0 &&
               scope.after.overlay_revision == 0;
    case diff_kind_t::overlay:
        return scope.before.workspace_id == scope.after.workspace_id &&
               scope.before.generation == scope.after.generation &&
               scope.before.overlay_revision != scope.after.overlay_revision;
    case diff_kind_t::workspace:
        return scope.before.workspace_id != scope.after.workspace_id &&
               scope.before.overlay_revision == 0 &&
               scope.after.overlay_revision == 0;
    default:
        return false;
    }
}

bool diff_page_request_valid(const diff_page_request_t& request) noexcept
{
    return request.limit != 0 && request.limit <= k_diff_document_max_page_size &&
           (all_domains(request.domain_filter) ||
            diff_domain_valid(request.domain_filter));
}

bool diff_selection_valid(const diff_selection_t& selection) noexcept
{
    if (selection.entity_key.size() > k_diff_document_max_entity_key_bytes ||
        !diff_domain_valid(selection.domain)) {
        return false;
    }
    if (selection.kind == selection_kind_t::none) {
        return !selection.has_address && selection.address == 0 &&
               selection.entry_index == 0 && selection.entity_key.empty();
    }
    if (selection.kind == selection_kind_t::address) {
        return selection.has_address && selection.address != 0 &&
               !selection.entity_key.empty();
    }
    if (selection.kind == selection_kind_t::entity) {
        return !selection.has_address && selection.address == 0 &&
               !selection.entity_key.empty();
    }
    return false;
}

bool diff_domain_filter_matches(diff_domain_t entry_domain,
                                diff_domain_t filter) noexcept
{
    if (!diff_domain_valid(entry_domain))
        return false;
    return all_domains(filter) || entry_domain == filter;
}

diff_error_t diff_document_model_t::fail(diff_error_code_t code,
                                         std::uint64_t subject) const noexcept
{
    return {code, subject};
}

diff_error_t diff_document_model_t::stale() const noexcept
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
    std::uint64_t expected_generation,
    const diff_scope_t& scope,
    const diff_cancellation_t* cancellation,
    diff_page_t& output) const
{
    output = {};
    if (!diff_page_request_valid(request))
        return fail(diff_error_code_t::invalid_page, request.limit);
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_)) {
        return stale();
    }
    if (!diff_scope_valid(scope))
        return fail(diff_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->supports_kind(scope.kind))
        return fail(diff_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->scope_available(bound_generation_, scope))
        return fail(diff_error_code_t::adapter_rejected,
                    scope.before.generation);
    if (cancellation_requested(cancellation))
        return fail(diff_error_code_t::cancelled, request.offset);

    const auto total = source_->entry_count(bound_generation_, scope);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (total > k_diff_document_max_entries)
        return fail(diff_error_code_t::resource_exhausted, total);

    output.snapshot_generation = bound_generation_;
    output.scope = scope;
    output.total_entries = total;
    output.offset = request.offset;

    if (total == 0 || request.offset >= total)
        return {};

    const auto remaining = total - request.offset;
    const auto max_read = (std::min)(static_cast<std::uint64_t>(request.limit),
                                     remaining);
    const auto scan_budget = all_domains(request.domain_filter)
        ? max_read
        : (std::min)(remaining, k_diff_document_max_filtered_scan);

    output.entries.reserve(static_cast<std::size_t>(max_read));

    std::uint64_t scan = request.offset;
    while (output.entries.size() < max_read &&
           output.scanned_entries < scan_budget && scan < total) {
        if (cancellation_requested(cancellation)) {
            output = {};
            return fail(diff_error_code_t::cancelled, scan);
        }
        diff_entry_t entry;
        if (!source_->entry_at(bound_generation_, scope, scan, entry) ||
            !diff_entry_valid(entry)) {
            output = {};
            return fail(diff_error_code_t::adapter_rejected, scan);
        }
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        if (diff_domain_filter_matches(entry.domain, request.domain_filter))
            output.entries.push_back(std::move(entry));
        ++scan;
        ++output.scanned_entries;
    }

    output.next_offset = scan < total ? scan : 0;
    if (!source_->generation_current(bound_generation_)) {
        output = {};
        return stale();
    }
    return {};
}

diff_error_t diff_document_model_t::navigate(
    const diff_navigation_request_t& request,
    std::uint64_t expected_generation,
    const diff_scope_t& scope,
    diff_navigation_result_t& output)
{
    output = {};
    if (request.page_size == 0 || request.page_size > k_diff_document_max_page_size)
        return fail(diff_error_code_t::invalid_argument, request.page_size);
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_)) {
        return stale();
    }
    if (!diff_scope_valid(scope))
        return fail(diff_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->supports_kind(scope.kind))
        return fail(diff_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->scope_available(bound_generation_, scope))
        return fail(diff_error_code_t::adapter_rejected,
                    scope.before.generation);

    const auto total = source_->entry_count(bound_generation_, scope);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (total > k_diff_document_max_entries)
        return fail(diff_error_code_t::resource_exhausted, total);
    if (request.entry_index >= total)
        return fail(diff_error_code_t::navigation_rejected, request.entry_index);

    diff_entry_t entry;
    if (!source_->entry_at(bound_generation_, scope, request.entry_index, entry) ||
        !diff_entry_valid(entry)) {
        return fail(diff_error_code_t::adapter_rejected, request.entry_index);
    }
    if (!source_->generation_current(bound_generation_))
        return stale();

    output.found = true;
    output.entry_index = request.entry_index;
    output.page_offset = (request.entry_index / request.page_size) *
                         request.page_size;
    output.selection = selection_for_entry(entry, request.entry_index);
    if (!diff_selection_valid(output.selection)) {
        output = {};
        return fail(diff_error_code_t::navigation_rejected, request.entry_index);
    }
    if (request.select_entry)
        selection_ = output.selection;
    return {};
}

diff_error_t diff_document_model_t::select(
    const diff_selection_t& selection,
    std::uint64_t expected_generation,
    const diff_scope_t& scope)
{
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_)) {
        return stale();
    }
    if (!diff_scope_valid(scope))
        return fail(diff_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->supports_kind(scope.kind))
        return fail(diff_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->scope_available(bound_generation_, scope))
        return fail(diff_error_code_t::adapter_rejected,
                    scope.before.generation);
    if (!diff_selection_valid(selection)) {
        return fail(diff_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    }
    if (selection.kind == selection_kind_t::none) {
        selection_ = {};
        return {};
    }

    const auto total = source_->entry_count(bound_generation_, scope);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (total > k_diff_document_max_entries)
        return fail(diff_error_code_t::resource_exhausted, total);
    if (selection.entry_index >= total)
        return fail(diff_error_code_t::selection_rejected,
                    selection.entry_index);

    diff_entry_t entry;
    if (!source_->entry_at(bound_generation_, scope, selection.entry_index, entry) ||
        !diff_entry_valid(entry)) {
        return fail(diff_error_code_t::adapter_rejected,
                    selection.entry_index);
    }
    if (!source_->generation_current(bound_generation_))
        return stale();
    const auto canonical = selection_for_entry(entry, selection.entry_index);
    if (!selection_matches(selection, canonical))
        return fail(diff_error_code_t::selection_rejected,
                    selection.entry_index);

    selection_ = canonical;
    return {};
}

diff_error_t diff_document_model_t::clear_selection(
    std::uint64_t expected_generation) noexcept
{
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_)) {
        return stale();
    }
    selection_ = {};
    return {};
}

diff_error_t diff_document_model_t::compute_summary(
    std::uint64_t expected_generation,
    const diff_scope_t& scope,
    diff_summary_t& output) const
{
    output = {};
    if (expected_generation != bound_generation_ ||
        !source_->generation_current(bound_generation_)) {
        return stale();
    }
    if (!diff_scope_valid(scope))
        return fail(diff_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->supports_kind(scope.kind))
        return fail(diff_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(scope.kind));
    if (!source_->scope_available(bound_generation_, scope))
        return fail(diff_error_code_t::adapter_rejected,
                    scope.before.generation);

    const auto total = source_->entry_count(bound_generation_, scope);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (total > k_diff_document_max_entries)
        return fail(diff_error_code_t::resource_exhausted, total);
    if (!source_->summary(bound_generation_, scope, output) ||
        output.snapshot_generation != bound_generation_ ||
        output.scope != scope || output.total_entries != total ||
        !summary_counts_valid(output)) {
        output = {};
        return fail(diff_error_code_t::adapter_rejected, total);
    }
    if (!source_->generation_current(bound_generation_)) {
        output = {};
        return stale();
    }
    return {};
}

diff_command_result_t diff_document_model_t::execute(
    const diff_command_t& command,
    const diff_cancellation_t* cancellation)
{
    diff_command_result_t result;

    switch (command.kind) {
    case diff_command_kind_t::page:
        result.error = page(command.page_request, command.expected_generation,
                            command.scope, cancellation, result.page);
        result.changed = result.error.ok() && !result.page.entries.empty();
        break;
    case diff_command_kind_t::navigate:
        result.error = navigate(command.navigation, command.expected_generation,
                                command.scope, result.navigation);
        result.changed = result.error.ok() && result.navigation.found;
        if (result.changed && command.navigation.select_entry)
            result.selection = selection_;
        break;
    case diff_command_kind_t::select:
        result.error = select(command.selection, command.expected_generation,
                              command.scope);
        result.selection = selection_;
        result.changed = result.error.ok();
        break;
    case diff_command_kind_t::clear_selection:
        result.error = clear_selection(command.expected_generation);
        result.selection = selection_;
        result.changed = result.error.ok();
        break;
    case diff_command_kind_t::refresh: {
        if (command.expected_generation != bound_generation_ ||
            !source_->generation_current(bound_generation_)) {
            result.error = stale();
            break;
        }
        const auto new_generation = source_->current_generation();
        if (new_generation == 0 ||
            !source_->generation_current(new_generation)) {
            result.error = fail(diff_error_code_t::adapter_rejected, 0);
            break;
        }
        if (new_generation != bound_generation_) {
            bound_generation_ = new_generation;
            selection_ = {};
            result.changed = true;
        }
        break;
    }
    case diff_command_kind_t::summary:
        result.error = compute_summary(command.expected_generation,
                                       command.scope, result.summary);
        result.changed = result.error.ok();
        break;
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
