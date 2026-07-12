#include "workbench_model.h"

#include <algorithm>
#include <limits>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida {
namespace workbench {
namespace {

workbench_error_t error(workbench_error_code_t code, std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

using document_iterator_t = std::vector<document_persistence_dto_t>::iterator;
using view_iterator_t = std::vector<view_persistence_dto_t>::iterator;

document_iterator_t find_document(workbench_persistence_dto_t& dto, document_id_t id)
{
    return std::find_if(dto.documents.begin(), dto.documents.end(), [id](const auto& document) {
        return document.id == id;
    });
}

std::vector<document_persistence_dto_t>::const_iterator find_document(
    const workbench_persistence_dto_t& dto, document_id_t id)
{
    return std::find_if(dto.documents.begin(), dto.documents.end(), [id](const auto& document) {
        return document.id == id;
    });
}

view_iterator_t find_view(workbench_persistence_dto_t& dto, view_id_t id)
{
    return std::find_if(dto.views.begin(), dto.views.end(), [id](const auto& view) {
        return view.id == id;
    });
}

std::vector<view_persistence_dto_t>::const_iterator find_view(
    const workbench_persistence_dto_t& dto, view_id_t id)
{
    return std::find_if(dto.views.begin(), dto.views.end(), [id](const auto& view) {
        return view.id == id;
    });
}

bool contains_document(const workbench_persistence_dto_t& dto, document_id_t id) noexcept
{
    return find_document(dto, id) != dto.documents.end();
}

workbench_error_t focused_view(const workbench_persistence_dto_t& dto, view_id_t& output) noexcept
{
    output = {};
    for (const auto& view : dto.views) {
        if (!view.focused)
            continue;
        if (output.valid())
            return error(workbench_error_code_t::invalid_view, view.id.value);
        output = view.id;
    }
    return output.valid() ? workbench_error_t{} : error(workbench_error_code_t::invalid_view);
}

workbench_error_t validate_model_state(const workbench_persistence_dto_t& dto)
{
    const auto persistence_result = validate_persistence_dto(dto);
    if (!persistence_result)
        return persistence_result;
    if (dto.views.empty())
        return error(workbench_error_code_t::invalid_view);

    view_id_t focused;
    const auto focus_result = focused_view(dto, focused);
    if (!focus_result)
        return focus_result;
    const auto focused_it = find_view(dto, focused);
    if (focused_it == dto.views.end() || focused_it->document != dto.active_document)
        return error(workbench_error_code_t::invalid_persistence, dto.active_document.value);

    std::unordered_set<std::uint64_t> leaves;
    leaves.reserve(dto.split_tree.nodes.size());
    for (const auto& node : dto.split_tree.nodes) {
        if (node.kind == split_node_kind_t::leaf)
            leaves.insert(node.view.value);
    }
    if (leaves.size() != dto.views.size())
        return error(workbench_error_code_t::invalid_split_tree);
    for (const auto& view : dto.views) {
        if (leaves.find(view.id.value) == leaves.end())
            return error(workbench_error_code_t::invalid_split_tree, view.id.value);
    }

    std::unordered_map<std::uint64_t, view_synchronization_policy_t> groups;
    groups.reserve(dto.views.size());
    for (const auto& view : dto.views) {
        if (view.synchronization_group == 0)
            continue;
        const auto found = groups.find(view.synchronization_group);
        if (found == groups.end()) {
            groups.emplace(view.synchronization_group, view.synchronization_policy);
        } else if (found->second != view.synchronization_policy) {
            return error(workbench_error_code_t::invalid_synchronization_policy, view.id.value);
        }
    }
    return {};
}

workbench_error_t set_focus(workbench_persistence_dto_t& dto, view_id_t id)
{
    const auto found = find_view(dto, id);
    if (found == dto.views.end())
        return error(workbench_error_code_t::invalid_view, id.value);
    for (auto& view : dto.views)
        view.focused = view.id == id;
    dto.active_document = found->document;
    return {};
}

workbench_error_t next_identifier(const std::vector<view_persistence_dto_t>& views,
                                  view_id_t& output) noexcept
{
    std::uint64_t maximum = 0;
    for (const auto& view : views)
        maximum = (std::max)(maximum, view.id.value);
    if (maximum == (std::numeric_limits<std::uint64_t>::max)())
        return error(workbench_error_code_t::revision_overflow, maximum);
    output = {maximum + 1U};
    return {};
}

workbench_error_t next_split_identifier(const split_tree_dto_t& tree, split_node_id_t& output) noexcept
{
    std::uint64_t maximum = 0;
    for (const auto& node : tree.nodes)
        maximum = (std::max)(maximum, node.id.value);
    if (maximum == (std::numeric_limits<std::uint64_t>::max)())
        return error(workbench_error_code_t::revision_overflow, maximum);
    output = {maximum + 1U};
    return {};
}

workbench_error_t next_navigation_identifier(const navigation_history_dto_t& history,
                                             navigation_event_id_t& output) noexcept
{
    std::uint64_t maximum = 0;
    for (const auto& event : history.back)
        maximum = (std::max)(maximum, event.id.value);
    for (const auto& event : history.forward)
        maximum = (std::max)(maximum, event.id.value);
    if (maximum == (std::numeric_limits<std::uint64_t>::max)())
        return error(workbench_error_code_t::revision_overflow, maximum);
    output = {maximum + 1U};
    return {};
}

workbench_error_t next_navigation_sequence(const navigation_history_dto_t& history,
                                            std::uint64_t& output) noexcept
{
    std::uint64_t maximum = 0;
    for (const auto& event : history.back)
        maximum = (std::max)(maximum, event.sequence);
    for (const auto& event : history.forward)
        maximum = (std::max)(maximum, event.sequence);
    if (maximum == (std::numeric_limits<std::uint64_t>::max)())
        return error(workbench_error_code_t::revision_overflow, maximum);
    output = maximum + 1U;
    return {};
}

workbench_error_t make_registry(const workbench_persistence_dto_t& dto,
                                document_registry_t& output)
{
    output = document_registry_t(dto.workspace);
    return output.restore(dto.documents);
}

workbench_error_t open_document(document_registry_t& registry, const document_identity_t& identity,
                                const document_catalog_adapter_t* catalog,
                                document_id_t& output, bool& already_open)
{
    const auto identity_result = validate_document_identity(identity);
    if (!identity_result)
        return identity_result;
    document_persistence_dto_t existing;
    if (registry.find(identity, existing).ok()) {
        output = existing.id;
        already_open = true;
        return {};
    }
    if (!catalog)
        return error(workbench_error_code_t::adapter_rejected);

    document_descriptor_t descriptor;
    const auto describe_result = catalog->describe(identity, descriptor);
    if (!describe_result)
        return error(workbench_error_code_t::adapter_rejected);
    if (!document_identity_equal(identity, descriptor.identity) || !descriptor.can_open)
        return error(workbench_error_code_t::adapter_rejected);
    return registry.open(descriptor, output, already_open);
}

void synchronize_navigation_state(workbench_persistence_dto_t& dto,
                                  const view_persistence_dto_t& source,
                                  const selection_context_t& selection,
                                  const document_local_cursor_t& cursor)
{
    if (source.synchronization_policy == view_synchronization_policy_t::independent)
        return;
    for (const auto& view : dto.views) {
        if (view.id == source.id || view.synchronization_group != source.synchronization_group)
            continue;
        const auto document = find_document(dto, view.document);
        if (document == dto.documents.end())
            continue;
        document->local_state.selection = selection;
        if (source.synchronization_policy ==
            view_synchronization_policy_t::cursor_and_selection) {
            document->local_state.cursor = cursor;
        }
    }
}

void scrub_history(navigation_history_dto_t& history, document_id_t id,
                   const document_identity_t& identity)
{
    const auto should_remove = [id, &identity](const navigation_event_t& event) {
        return (event.has_source && event.source.document == id) ||
               document_identity_equal(event.target.document, identity);
    };
    history.back.erase(std::remove_if(history.back.begin(), history.back.end(), should_remove),
                       history.back.end());
    history.forward.erase(std::remove_if(history.forward.begin(), history.forward.end(), should_remove),
                          history.forward.end());
}

workbench_error_t remove_view(workbench_persistence_dto_t& dto, view_id_t id)
{
    if (dto.views.size() <= 1)
        return error(workbench_error_code_t::invalid_view, id.value);
    const auto tree_result = split_tree_remove_view(dto.split_tree, id);
    if (!tree_result)
        return tree_result;
    const auto view = find_view(dto, id);
    if (view == dto.views.end())
        return error(workbench_error_code_t::invalid_view, id.value);
    dto.views.erase(view);
    return {};
}

workbench_error_t select_replacement_document(const workbench_persistence_dto_t& dto,
                                               document_id_t removed,
                                               document_id_t& output) noexcept
{
    output = {};
    for (const auto& document : dto.documents) {
        if (document.id != removed) {
            output = document.id;
            return {};
        }
    }
    return error(workbench_error_code_t::invalid_document, removed.value);
}

workbench_error_t remove_document_references(workbench_persistence_dto_t& dto,
                                             document_id_t removed,
                                             const document_identity_t& identity)
{
    document_id_t replacement;
    const auto replacement_result = select_replacement_document(dto, removed, replacement);
    if (!replacement_result)
        return replacement_result;

    std::vector<view_id_t> affected;
    for (const auto& view : dto.views) {
        if (view.document == removed)
            affected.push_back(view.id);
    }
    std::sort(affected.begin(), affected.end());
    if (affected.size() == dto.views.size()) {
        const auto retained = affected.front();
        const auto retained_view = find_view(dto, retained);
        if (retained_view == dto.views.end())
            return error(workbench_error_code_t::invalid_view, retained.value);
        retained_view->document = replacement;
        for (std::size_t index = 1; index < affected.size(); ++index) {
            const auto remove_result = remove_view(dto, affected[index]);
            if (!remove_result)
                return remove_result;
        }
    } else {
        for (const auto view : affected) {
            const auto remove_result = remove_view(dto, view);
            if (!remove_result)
                return remove_result;
        }
    }

    for (auto& panel : dto.panels) {
        if (panel.selected_document == removed)
            panel.selected_document = replacement;
    }
    scrub_history(dto.history, removed, identity);
    view_id_t current_focus;
    const auto focus_result = focused_view(dto, current_focus);
    if (!focus_result || !contains_document(dto, dto.active_document)) {
        const auto preferred = dto.views.empty() ? view_id_t{} : dto.views.front().id;
        return set_focus(dto, preferred);
    }
    return set_focus(dto, current_focus);
}

workbench_error_t close_document(workbench_persistence_dto_t& dto, document_registry_t& registry,
                                 document_id_t id, bool bypass_closeability)
{
    document_persistence_dto_t removed;
    const auto find_result = registry.find(id, removed);
    if (!find_result)
        return find_result;
    if (registry.documents().size() <= 1)
        return error(workbench_error_code_t::invalid_document, id.value);
    if (!bypass_closeability && (!removed.closeable || removed.pinned))
        return error(workbench_error_code_t::invalid_document, id.value);

    document_persistence_dto_t closed;
    const auto close_result = registry.close(id, closed);
    if (!close_result)
        return close_result;
    dto.documents = registry.documents();
    return remove_document_references(dto, id, closed.identity);
}

workbench_error_t apply_navigation(workbench_persistence_dto_t& dto,
                                   document_registry_t& registry,
                                   const navigation_event_t& event,
                                   const workbench_services_t& services,
                                   bool append_history)
{
    const auto event_result = validate_navigation_event(event);
    if (!event_result)
        return event_result;
    if (!event.has_source)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    const auto source = find_view(dto, event.source.view);
    if (source == dto.views.end() || source->workspace != dto.workspace ||
        source->document != event.source.document ||
        source->synchronization_group != event.source.synchronization_group ||
        source->synchronization_policy != event.source.synchronization_policy) {
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    }
    if (!services.navigation)
        return error(workbench_error_code_t::adapter_rejected, event.id.value);

    navigation_resolution_t resolution;
    const auto resolve_result = services.navigation->resolve(event, resolution);
    if (!resolve_result || !document_identity_equal(resolution.document, event.target.document) ||
        !selection_context_equal(resolution.selection, event.target.selection) ||
        !document_local_cursor_equal(resolution.cursor, event.target.cursor)) {
        return error(workbench_error_code_t::adapter_rejected, event.id.value);
    }
    const auto identity_result = validate_document_identity(resolution.document);
    if (!identity_result || resolution.document.workspace != dto.workspace ||
        !validate_selection_context(resolution.selection) ||
        !validate_document_local_cursor(resolution.cursor)) {
        return error(workbench_error_code_t::adapter_rejected, event.id.value);
    }

    document_id_t target_document;
    bool already_open = false;
    const auto open_result = open_document(registry, resolution.document, services.documents,
                                           target_document, already_open);
    if (!open_result)
        return open_result;
    dto.documents = registry.documents();

    auto target_view = find_view(dto, event.source.view);
    if (target_view == dto.views.end())
        return error(workbench_error_code_t::invalid_view, event.source.view.value);
    target_view->document = target_document;
    auto target = find_document(dto, target_document);
    if (target == dto.documents.end())
        return error(workbench_error_code_t::invalid_document, target_document.value);
    target->local_state.selection = resolution.selection;
    target->local_state.cursor = resolution.cursor;
    const auto source_state = *target_view;
    synchronize_navigation_state(dto, source_state, resolution.selection, resolution.cursor);

    if (append_history) {
        const auto history_result = append_navigation_history(dto.history, event);
        if (!history_result)
            return history_result;
    }
    if (event.request_focus)
        return set_focus(dto, source_state.id);
    return {};
}

workbench_error_t prepare_navigation(const workbench_persistence_dto_t& dto,
                                     const workbench_command_t& command,
                                     navigation_event_t& output)
{
    output = command.navigation;
    if (output.workspace != command.workspace)
        return error(workbench_error_code_t::workspace_mismatch, command.workspace.value);
    if (!output.has_source) {
        view_id_t focus;
        const auto focus_result = focused_view(dto, focus);
        if (!focus_result)
            return focus_result;
        const auto source = find_view(dto, focus);
        if (source == dto.views.end())
            return error(workbench_error_code_t::invalid_view, focus.value);
        output.has_source = true;
        output.source.workspace = dto.workspace;
        output.source.document = source->document;
        output.source.view = source->id;
        const auto source_document = find_document(dto, source->document);
        if (source_document == dto.documents.end())
            return error(workbench_error_code_t::invalid_document, source->document.value);
        output.source.selection = source_document->local_state.selection;
        output.source.cursor = source_document->local_state.cursor;
        output.source.synchronization_group = source->synchronization_group;
        output.source.synchronization_policy = source->synchronization_policy;
    } else {
        const auto source = find_view(dto, output.source.view);
        const auto source_document = find_document(dto, output.source.document);
        if (source == dto.views.end() || source_document == dto.documents.end() ||
            source->workspace != dto.workspace || source->document != output.source.document ||
            source->synchronization_group != output.source.synchronization_group ||
            source->synchronization_policy != output.source.synchronization_policy ||
            !selection_context_equal(source_document->local_state.selection, output.source.selection) ||
            !document_local_cursor_equal(source_document->local_state.cursor, output.source.cursor)) {
            return error(workbench_error_code_t::invalid_navigation, output.id.value);
        }
    }
    if (!output.id.valid()) {
        const auto id_result = next_navigation_identifier(dto.history, output.id);
        if (!id_result)
            return id_result;
    }
    if (output.sequence == 0) {
        const auto sequence_result = next_navigation_sequence(dto.history, output.sequence);
        if (!sequence_result)
            return sequence_result;
    }
    return validate_navigation_event(output);
}

workbench_error_t apply_history_back(workbench_persistence_dto_t& dto)
{
    navigation_event_t event;
    const auto history_result = history_back(dto.history, event);
    if (!history_result)
        return history_result;
    if (!event.has_source || event.source.workspace != dto.workspace)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    const auto view = find_view(dto, event.source.view);
    const auto document = find_document(dto, event.source.document);
    if (view == dto.views.end() || document == dto.documents.end())
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    view->document = document->id;
    document->local_state.selection = event.source.selection;
    document->local_state.cursor = event.source.cursor;
    const auto state = *view;
    synchronize_navigation_state(dto, state, event.source.selection, event.source.cursor);
    return set_focus(dto, state.id);
}

void update_panel_revisions(workbench_persistence_dto_t& dto, workspace_revision_t revision) noexcept
{
    for (auto& panel : dto.panels)
        panel.revision = revision;
}

workbench_error_t normalize_model_state(workbench_persistence_dto_t& dto)
{
    const auto normalize_result = normalize_persistence_dto(dto);
    if (!normalize_result)
        return normalize_result;
    return validate_model_state(dto);
}

workbench_error_t commit(workbench_snapshot_ptr_t& current,
                         workbench_persistence_dto_t& working,
                         workbench_command_result_t& result)
{
    const auto normalized_result = normalize_model_state(working);
    if (!normalized_result)
        return normalized_result;
    if (persistence_dto_equal(current->persistence(), working)) {
        result.snapshot = current;
        return {};
    }
    workspace_revision_t next;
    const auto revision_result = next_workspace_revision(current->revision(), next);
    if (!revision_result)
        return revision_result;
    working.revision = next;
    update_panel_revisions(working, next);
    const auto final_result = normalize_model_state(working);
    if (!final_result)
        return final_result;
    current = std::shared_ptr<const workbench_workspace_snapshot_t>(
        new workbench_workspace_snapshot_t(std::move(working)));
    result.snapshot = current;
    result.changed = true;
    return {};
}

}

struct workbench_model_t::implementation_t {
    struct workspace_entry_t {
        std::mutex mutex;
        workbench_snapshot_ptr_t snapshot;
    };

    mutable std::mutex mutex;
    std::map<workspace_id_t, std::shared_ptr<workspace_entry_t>> workspaces;
};

workbench_workspace_snapshot_t::workbench_workspace_snapshot_t(workbench_persistence_dto_t persistence)
    : persistence_(std::move(persistence)), fingerprint_(persistence_fingerprint(persistence_))
{
    for (const auto& view : persistence_.views) {
        if (view.focused) {
            focused_view_ = view.id;
            break;
        }
    }
}

workspace_id_t workbench_workspace_snapshot_t::workspace() const noexcept
{
    return persistence_.workspace;
}

workspace_revision_t workbench_workspace_snapshot_t::revision() const noexcept
{
    return persistence_.revision;
}

persistence_fingerprint_t workbench_workspace_snapshot_t::fingerprint() const noexcept
{
    return fingerprint_;
}

const workbench_persistence_dto_t& workbench_workspace_snapshot_t::persistence() const noexcept
{
    return persistence_;
}

view_id_t workbench_workspace_snapshot_t::focused_view() const noexcept
{
    return focused_view_;
}

workbench_model_t::workbench_model_t()
    : implementation_(new implementation_t)
{
}

workbench_model_t::~workbench_model_t() = default;

workbench_error_t workbench_model_t::create_workspace(const workbench_persistence_dto_t& initial,
                                                       workbench_snapshot_ptr_t& output)
{
    output.reset();
    workbench_persistence_dto_t normalized = initial;
    const auto normalize_result = normalize_model_state(normalized);
    if (!normalize_result)
        return normalize_result;
    auto entry = std::make_shared<implementation_t::workspace_entry_t>();
    entry->snapshot = std::shared_ptr<const workbench_workspace_snapshot_t>(
        new workbench_workspace_snapshot_t(std::move(normalized)));

    std::lock_guard<std::mutex> lock(implementation_->mutex);
    const auto inserted = implementation_->workspaces.emplace(initial.workspace, entry);
    if (!inserted.second)
        return error(workbench_error_code_t::duplicate_identifier, initial.workspace.value);
    output = entry->snapshot;
    return {};
}

workbench_error_t workbench_model_t::snapshot(workspace_id_t workspace,
                                               workbench_snapshot_ptr_t& output) const
{
    output.reset();
    if (!workspace.valid())
        return error(workbench_error_code_t::invalid_workspace);
    std::shared_ptr<implementation_t::workspace_entry_t> entry;
    {
        std::lock_guard<std::mutex> lock(implementation_->mutex);
        const auto found = implementation_->workspaces.find(workspace);
        if (found == implementation_->workspaces.end())
            return error(workbench_error_code_t::invalid_workspace, workspace.value);
        entry = found->second;
    }
    std::lock_guard<std::mutex> lock(entry->mutex);
    output = entry->snapshot;
    return {};
}

std::vector<workspace_id_t> workbench_model_t::workspace_ids() const
{
    std::vector<workspace_id_t> output;
    std::lock_guard<std::mutex> lock(implementation_->mutex);
    output.reserve(implementation_->workspaces.size());
    for (const auto& item : implementation_->workspaces)
        output.push_back(item.first);
    return output;
}

workbench_command_result_t workbench_model_t::execute(const workbench_command_t& command,
                                                       const workbench_services_t& services)
{
    workbench_command_result_t result;
    if (!command.workspace.valid()) {
        result.error = error(workbench_error_code_t::invalid_workspace);
        return result;
    }
    std::shared_ptr<implementation_t::workspace_entry_t> entry;
    {
        std::lock_guard<std::mutex> lock(implementation_->mutex);
        const auto found = implementation_->workspaces.find(command.workspace);
        if (found == implementation_->workspaces.end()) {
            result.error = error(workbench_error_code_t::invalid_workspace, command.workspace.value);
            return result;
        }
        entry = found->second;
    }

    workbench_snapshot_ptr_t base_snapshot;
    {
        std::lock_guard<std::mutex> lock(entry->mutex);
        base_snapshot = entry->snapshot;
        result.snapshot = base_snapshot;
        if (!revision_matches(command.expected_revision, base_snapshot->revision())) {
            result.error = error(workbench_error_code_t::revision_mismatch,
                                 command.expected_revision.value);
            return result;
        }
    }

    workbench_persistence_dto_t working = base_snapshot->persistence();
    document_registry_t registry;
    const auto registry_result = make_registry(working, registry);
    if (!registry_result) {
        result.error = registry_result;
        return result;
    }

    workbench_error_t operation_result;
    switch (command.kind) {
        case workbench_command_kind_t::open_document: {
            if (command.document_identity.workspace != command.workspace) {
                operation_result = error(workbench_error_code_t::workspace_mismatch,
                                         command.workspace.value);
                break;
            }
            document_id_t opened;
            bool already_open = false;
            operation_result = open_document(registry, command.document_identity, services.documents,
                                             opened, already_open);
            if (!operation_result)
                break;
            working.documents = registry.documents();
            view_id_t target = command.view;
            if (!target.valid()) {
                operation_result = focused_view(working, target);
                if (!operation_result)
                    break;
            }
            const auto target_view = find_view(working, target);
            if (target_view == working.views.end()) {
                operation_result = error(workbench_error_code_t::invalid_view, target.value);
                break;
            }
            target_view->document = opened;
            result.document = opened;
            result.view = target;
            if (command.request_focus)
                operation_result = set_focus(working, target);
            break;
        }
        case workbench_command_kind_t::close_document:
            operation_result = close_document(working, registry, command.document, false);
            result.document = command.document;
            break;
        case workbench_command_kind_t::move_view:
            operation_result = split_tree_swap_views(working.split_tree, command.view,
                                                     command.target_view);
            result.view = command.view;
            break;
        case workbench_command_kind_t::split_view: {
            const auto source = find_view(working, command.view);
            if (source == working.views.end()) {
                operation_result = error(workbench_error_code_t::invalid_view, command.view.value);
                break;
            }
            if (working.views.size() >= k_max_views_per_workspace ||
                working.split_tree.nodes.size() > k_max_split_nodes_per_workspace - 2U) {
                operation_result = error(workbench_error_code_t::invalid_persistence);
                break;
            }
            view_id_t inserted = command.requested_view;
            if (!inserted.valid()) {
                operation_result = next_identifier(working.views, inserted);
                if (!operation_result)
                    break;
            } else if (find_view(working, inserted) != working.views.end()) {
                operation_result = error(workbench_error_code_t::duplicate_identifier, inserted.value);
                break;
            }
            document_id_t target_document = command.document.valid() ? command.document : source->document;
            if (!contains_document(working, target_document)) {
                operation_result = error(workbench_error_code_t::invalid_document, target_document.value);
                break;
            }
            split_node_id_t branch;
            operation_result = next_split_identifier(working.split_tree, branch);
            if (!operation_result)
                break;
            split_node_id_t leaf;
            split_tree_dto_t provisional = working.split_tree;
            provisional.nodes.push_back({branch});
            operation_result = next_split_identifier(provisional, leaf);
            if (!operation_result)
                break;
            view_persistence_dto_t inserted_view = *source;
            inserted_view.id = inserted;
            inserted_view.document = target_document;
            inserted_view.role = view_role_t::secondary;
            inserted_view.focused = false;
            working.views.push_back(inserted_view);
            operation_result = split_tree_split_view(working.split_tree, source->id, inserted,
                                                     command.orientation, command.ratio_basis_points,
                                                     branch, leaf, result.split);
            if (!operation_result)
                break;
            result.view = inserted;
            result.document = target_document;
            break;
        }
        case workbench_command_kind_t::focus_view:
            operation_result = set_focus(working, command.view);
            result.view = command.view;
            break;
        case workbench_command_kind_t::set_synchronization: {
            const auto view = find_view(working, command.view);
            if (view == working.views.end()) {
                operation_result = error(workbench_error_code_t::invalid_view, command.view.value);
                break;
            }
            view->synchronization_group = command.synchronization_group;
            view->synchronization_policy = command.synchronization_policy;
            result.view = command.view;
            break;
        }
        case workbench_command_kind_t::navigate: {
            navigation_event_t event;
            operation_result = prepare_navigation(working, command, event);
            if (!operation_result)
                break;
            operation_result = apply_navigation(working, registry, event, services, true);
            result.navigation = event.id;
            result.view = event.source.view;
            break;
        }
        case workbench_command_kind_t::history_back:
            operation_result = apply_history_back(working);
            break;
        case workbench_command_kind_t::history_forward: {
            navigation_event_t event;
            operation_result = history_forward(working.history, event);
            if (!operation_result)
                break;
            operation_result = apply_navigation(working, registry, event, services, false);
            result.navigation = event.id;
            result.view = event.source.view;
            break;
        }
        default:
            operation_result = error(workbench_error_code_t::invalid_persistence,
                                     static_cast<std::uint8_t>(command.kind));
            break;
    }
    if (!operation_result) {
        result.error = operation_result;
        return result;
    }

    std::lock_guard<std::mutex> lock(entry->mutex);
    if (entry->snapshot != base_snapshot ||
        !revision_matches(command.expected_revision, entry->snapshot->revision())) {
        result.snapshot = entry->snapshot;
        result.error = error(workbench_error_code_t::revision_mismatch,
                             command.expected_revision.value);
        return result;
    }
    result.error = commit(entry->snapshot, working, result);
    return result;
}

workbench_command_result_t workbench_model_t::restore_workspace(
    workspace_id_t workspace, workspace_revision_t expected_revision,
    const workbench_persistence_dto_t& persisted, const document_catalog_adapter_t& catalog,
    missing_document_policy_t policy)
{
    workbench_command_result_t result;
    if (!workspace.valid() || persisted.workspace != workspace) {
        result.error = error(workbench_error_code_t::workspace_mismatch, workspace.value);
        return result;
    }
    std::shared_ptr<implementation_t::workspace_entry_t> entry;
    {
        std::lock_guard<std::mutex> lock(implementation_->mutex);
        const auto found = implementation_->workspaces.find(workspace);
        if (found == implementation_->workspaces.end()) {
            result.error = error(workbench_error_code_t::invalid_workspace, workspace.value);
            return result;
        }
        entry = found->second;
    }

    workbench_snapshot_ptr_t base_snapshot;
    {
        std::lock_guard<std::mutex> lock(entry->mutex);
        base_snapshot = entry->snapshot;
        result.snapshot = base_snapshot;
        if (!revision_matches(expected_revision, base_snapshot->revision())) {
            result.error = error(workbench_error_code_t::revision_mismatch,
                                 expected_revision.value);
            return result;
        }
    }

    workbench_persistence_dto_t working = persisted;
    const auto normalize_result = normalize_model_state(working);
    if (!normalize_result) {
        result.error = normalize_result;
        return result;
    }
    document_registry_t registry;
    const auto registry_result = make_registry(working, registry);
    if (!registry_result) {
        result.error = registry_result;
        return result;
    }
    std::unordered_map<std::uint64_t, document_identity_t> omitted_identities;
    for (const auto& document : working.documents)
        omitted_identities.emplace(document.id.value, document.identity);
    std::vector<document_id_t> omitted;
    const auto reconcile_result = reconcile_document_registry(registry, catalog, policy, omitted);
    if (!reconcile_result) {
        result.error = reconcile_result;
        return result;
    }
    working.documents = registry.documents();
    if (working.documents.empty()) {
        result.error = error(workbench_error_code_t::adapter_rejected);
        return result;
    }
    for (const auto id : omitted) {
        const auto identity = omitted_identities.find(id.value);
        if (identity == omitted_identities.end()) {
            result.error = error(workbench_error_code_t::invalid_document, id.value);
            return result;
        }
        const auto remove_result = remove_document_references(working, id, identity->second);
        if (!remove_result) {
            result.error = remove_result;
            return result;
        }
    }

    std::lock_guard<std::mutex> lock(entry->mutex);
    if (entry->snapshot != base_snapshot ||
        !revision_matches(expected_revision, entry->snapshot->revision())) {
        result.snapshot = entry->snapshot;
        result.error = error(workbench_error_code_t::revision_mismatch,
                             expected_revision.value);
        return result;
    }
    result.error = commit(entry->snapshot, working, result);
    return result;
}

workbench_command_result_t workbench_model_t::restore_workspace(
    workspace_id_t workspace, workspace_revision_t expected_revision,
    const workbench_persistence_adapter_t& persistence, const document_catalog_adapter_t& catalog,
    missing_document_policy_t policy)
{
    workbench_persistence_dto_t persisted;
    const auto load_result = persistence.load(workspace, persisted);
    if (!load_result) {
        workbench_command_result_t result;
        result.error = load_result;
        return result;
    }
    return restore_workspace(workspace, expected_revision, persisted, catalog, policy);
}

}
}
