#include "workbench_model_harness.h"

#include "../../src/core/workbench/workbench_model.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace aida {
namespace workbench {
namespace {

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

document_identity_t make_identity(workspace_id_t workspace, std::uint64_t object_id)
{
    document_identity_t identity;
    identity.workspace = workspace;
    identity.kind = document_kind_t::disassembly;
    identity.object_id = object_id;
    identity.variant_id = object_id + 1000U;
    identity.provider_key = "workbench-model-" + std::to_string(object_id);
    identity.has_address = true;
    identity.address = 0x401000U + object_id;
    return identity;
}

document_persistence_dto_t make_document_record(workspace_id_t workspace,
                                                std::uint64_t document_id,
                                                std::uint64_t object_id)
{
    document_persistence_dto_t document;
    document.id = {document_id};
    document.identity = make_identity(workspace, object_id);
    document.title = "document-" + std::to_string(document_id);
    return document;
}

navigation_event_t make_navigation_event(workspace_id_t workspace,
                                         std::uint64_t event_id,
                                         std::uint64_t sequence)
{
    navigation_event_t event;
    event.id = {event_id};
    event.workspace = workspace;
    event.target.document = make_identity(workspace, 1);
    event.origin = navigation_origin_t::user;
    event.sequence = sequence;
    return event;
}

workbench_persistence_dto_t make_workspace(workspace_id_t workspace)
{
    workbench_persistence_dto_t dto;
    dto.workspace = workspace;
    dto.revision = {1};
    dto.history.workspace = workspace;

    document_persistence_dto_t first;
    first.id = {1};
    first.identity = make_identity(workspace, 1);
    first.title = "entry";
    first.state_token = "entry-state";

    document_persistence_dto_t second;
    second.id = {2};
    second.identity = make_identity(workspace, 2);
    second.title = "worker";
    second.state_token = "worker-state";

    dto.documents = {first, second};
    dto.active_document = first.id;

    view_persistence_dto_t first_view;
    first_view.id = {11};
    first_view.workspace = workspace;
    first_view.document = first.id;
    first_view.focused = true;

    view_persistence_dto_t second_view;
    second_view.id = {12};
    second_view.workspace = workspace;
    second_view.document = second.id;
    second_view.role = view_role_t::secondary;

    dto.views = {first_view, second_view};

    split_node_dto_t first_leaf;
    first_leaf.id = {101};
    first_leaf.kind = split_node_kind_t::leaf;
    first_leaf.view = first_view.id;

    split_node_dto_t second_leaf;
    second_leaf.id = {102};
    second_leaf.kind = split_node_kind_t::leaf;
    second_leaf.view = second_view.id;

    split_node_dto_t root;
    root.id = {103};
    root.kind = split_node_kind_t::branch;
    root.orientation = split_orientation_t::horizontal;
    root.ratio_basis_points = k_split_ratio_default_basis_points;
    root.first = first_leaf.id;
    root.second = second_leaf.id;

    dto.split_tree.root = root.id;
    dto.split_tree.nodes = {root, second_leaf, first_leaf};

    panel_state_dto_t panel;
    panel.id = {401};
    panel.workspace = workspace;
    panel.kind = panel_kind_t::navigator;
    panel.extent_pixels = dto.layout.navigator_pixels;
    panel.revision = dto.revision;
    panel.selected_document = first.id;
    dto.panels = {panel};
    return dto;
}

workbench_persistence_dto_t make_max_layout_workspace(workspace_id_t workspace)
{
    workbench_persistence_dto_t dto = make_workspace(workspace);
    dto.views.clear();
    dto.split_tree = {};
    dto.views.reserve(k_max_views_per_workspace);
    dto.split_tree.nodes.reserve(k_max_split_nodes_per_workspace);

    const auto view_count = static_cast<std::uint64_t>(k_max_views_per_workspace);
    for (std::uint64_t index = 1; index <= view_count; ++index) {
        view_persistence_dto_t view;
        view.id = {index};
        view.workspace = workspace;
        view.document = {1};
        view.role = index == 1 ? view_role_t::primary : view_role_t::secondary;
        view.focused = index == 1;
        dto.views.push_back(view);

        split_node_dto_t leaf;
        leaf.id = {index};
        leaf.kind = split_node_kind_t::leaf;
        leaf.view = view.id;
        dto.split_tree.nodes.push_back(leaf);
    }

    split_node_id_t root{1};
    for (std::uint64_t index = 2; index <= view_count; ++index) {
        split_node_dto_t branch;
        branch.id = {view_count + index - 1U};
        branch.kind = split_node_kind_t::branch;
        branch.orientation = split_orientation_t::horizontal;
        branch.ratio_basis_points = k_split_ratio_default_basis_points;
        branch.first = root;
        branch.second = {index};
        root = branch.id;
        dto.split_tree.nodes.push_back(branch);
    }
    dto.split_tree.root = root;
    return dto;
}

class catalog_t final : public document_catalog_adapter_t {
public:
    explicit catalog_t(std::uint64_t unavailable = 0)
        : unavailable_(unavailable)
    {
    }

    workbench_error_t describe(const document_identity_t& identity,
                               document_descriptor_t& output) const override
    {
        const auto validation = validate_document_identity(identity);
        if (!validation)
            return validation;
        output.identity = identity;
        output.title = "catalog-" + std::to_string(identity.object_id);
        output.can_open = identity.object_id != unavailable_;
        return {};
    }

private:
    std::uint64_t unavailable_;
};

class navigator_t final : public navigation_adapter_t {
public:
    workbench_error_t resolve(const navigation_event_t& event,
                              navigation_resolution_t& output) const override
    {
        const auto validation = validate_navigation_event(event);
        if (!validation)
            return validation;
        output.document = event.target.document;
        output.selection = event.target.selection;
        output.cursor = event.target.cursor;
        output.requires_document_open = true;
        return {};
    }
};

class snapshot_catalog_t final : public document_catalog_adapter_t {
public:
    explicit snapshot_catalog_t(const workbench_model_t& model)
        : model_(model)
    {
    }

    workbench_error_t describe(const document_identity_t& identity,
                               document_descriptor_t& output) const override
    {
        workbench_snapshot_ptr_t snapshot;
        const auto snapshot_result = model_.snapshot(identity.workspace, snapshot);
        if (!snapshot_result)
            return snapshot_result;
        ++calls_;
        output.identity = identity;
        output.title = "snapshot-catalog-" + std::to_string(identity.object_id);
        output.can_open = true;
        return {};
    }

    std::size_t calls() const noexcept
    {
        return calls_;
    }

private:
    const workbench_model_t& model_;
    mutable std::size_t calls_ = 0;
};

class mutating_catalog_t final : public document_catalog_adapter_t {
public:
    explicit mutating_catalog_t(workbench_model_t& model)
        : model_(model)
    {
    }

    workbench_error_t describe(const document_identity_t& identity,
                               document_descriptor_t& output) const override
    {
        workbench_snapshot_ptr_t snapshot;
        const auto snapshot_result = model_.snapshot(identity.workspace, snapshot);
        if (!snapshot_result)
            return snapshot_result;

        workbench_command_t nested;
        nested.kind = workbench_command_kind_t::focus_view;
        nested.workspace = identity.workspace;
        nested.expected_revision = snapshot->revision();
        nested.view = snapshot->focused_view() == view_id_t{11} ? view_id_t{12} : view_id_t{11};
        nested_error_ = model_.execute(nested).error;
        invoked_ = true;
        if (!nested_error_)
            return nested_error_;

        output.identity = identity;
        output.title = "mutating-catalog-" + std::to_string(identity.object_id);
        output.can_open = true;
        return {};
    }

    bool invoked() const noexcept
    {
        return invoked_;
    }

    workbench_error_t nested_error() const noexcept
    {
        return nested_error_;
    }

private:
    workbench_model_t& model_;
    mutable workbench_error_t nested_error_;
    mutable bool invoked_ = false;
};

class snapshot_navigator_t final : public navigation_adapter_t {
public:
    explicit snapshot_navigator_t(const workbench_model_t& model)
        : model_(model)
    {
    }

    workbench_error_t resolve(const navigation_event_t& event,
                              navigation_resolution_t& output) const override
    {
        workbench_snapshot_ptr_t snapshot;
        const auto snapshot_result = model_.snapshot(event.workspace, snapshot);
        if (!snapshot_result)
            return snapshot_result;
        invoked_ = true;
        output.document = event.target.document;
        output.selection = event.target.selection;
        output.cursor = event.target.cursor;
        output.requires_document_open = true;
        return {};
    }

    bool invoked() const noexcept
    {
        return invoked_;
    }

private:
    const workbench_model_t& model_;
    mutable bool invoked_ = false;
};

const document_persistence_dto_t& document(const workbench_workspace_snapshot_t& snapshot,
                                           document_id_t id)
{
    const auto& documents = snapshot.persistence().documents;
    const auto found = std::find_if(documents.begin(), documents.end(), [id](const auto& value) {
        return value.id == id;
    });
    if (found == documents.end())
        throw std::runtime_error("document is missing from snapshot");
    return *found;
}

const view_persistence_dto_t& view(const workbench_workspace_snapshot_t& snapshot, view_id_t id)
{
    const auto& views = snapshot.persistence().views;
    const auto found = std::find_if(views.begin(), views.end(), [id](const auto& value) {
        return value.id == id;
    });
    if (found == views.end())
        throw std::runtime_error("view is missing from snapshot");
    return *found;
}

void verify_revisioned_workspace_isolation()
{
    workbench_model_t model;
    workbench_snapshot_ptr_t first;
    workbench_snapshot_ptr_t second;
    require(model.create_workspace(make_workspace({1}), first).ok(), "first workspace must initialize");
    require(model.create_workspace(make_workspace({2}), second).ok(), "second workspace must initialize");
    require(first->focused_view() == view_id_t{11}, "first workspace must retain local focus");
    require(second->focused_view() == view_id_t{11}, "second workspace must retain local focus");
    require(model.workspace_ids() == std::vector<workspace_id_t>{{1}, {2}},
            "workspace identifiers must remain deterministic");

    workbench_command_t stale;
    stale.kind = workbench_command_kind_t::focus_view;
    stale.workspace = {1};
    stale.expected_revision = {99};
    stale.view = {12};
    const auto stale_result = model.execute(stale);
    require(stale_result.error.code == workbench_error_code_t::revision_mismatch &&
                stale_result.snapshot == first,
            "stale workspace revision must not alter immutable state");

    workbench_command_t split;
    split.kind = workbench_command_kind_t::split_view;
    split.workspace = {1};
    split.expected_revision = first->revision();
    split.view = {11};
    split.document = {1};
    split.orientation = split_orientation_t::vertical;
    split.ratio_basis_points = 4200;
    const auto split_result = model.execute(split);
    require(split_result.error.ok() && split_result.changed && split_result.view.valid() &&
                split_result.split.branch.valid() && split_result.split.leaf.valid(),
            "split must create an independently addressable view");
    const auto split_snapshot = split_result.snapshot;
    require(split_snapshot->persistence().views.size() == 3 &&
                split_snapshot->persistence().split_tree.nodes.size() == 5,
            "split must expand only the addressed workspace layout");
    require(second->persistence().views.size() == 2 && second->revision() == workspace_revision_t{1},
            "unrelated workspace state must remain immutable and unchanged");

    split_node_id_t first_leaf_before;
    split_node_id_t inserted_leaf_before;
    require(split_tree_find_leaf(split_snapshot->persistence().split_tree, {11}, first_leaf_before).ok() &&
                split_tree_find_leaf(split_snapshot->persistence().split_tree, split_result.view,
                                     inserted_leaf_before).ok(),
            "split leaves must remain addressable by explicit view identifiers");
    workbench_command_t move;
    move.kind = workbench_command_kind_t::move_view;
    move.workspace = {1};
    move.expected_revision = split_snapshot->revision();
    move.view = {11};
    move.target_view = split_result.view;
    const auto move_result = model.execute(move);
    require(move_result.error.ok() && move_result.changed, "view move must route by workspace and view");
    split_node_id_t first_leaf_after;
    split_node_id_t inserted_leaf_after;
    require(split_tree_find_leaf(move_result.snapshot->persistence().split_tree, {11}, first_leaf_after).ok() &&
                split_tree_find_leaf(move_result.snapshot->persistence().split_tree, split_result.view,
                                     inserted_leaf_after).ok() &&
                first_leaf_after == inserted_leaf_before && inserted_leaf_after == first_leaf_before,
            "view move must swap only split placement, not document ownership");

    workbench_command_t focus;
    focus.kind = workbench_command_kind_t::focus_view;
    focus.workspace = {1};
    focus.expected_revision = move_result.snapshot->revision();
    focus.view = split_result.view;
    const auto focus_result = model.execute(focus);
    require(focus_result.error.ok() && focus_result.snapshot->focused_view() == split_result.view &&
                focus_result.snapshot->persistence().active_document == document_id_t{1},
            "focus must be stored per workspace and resolve active document locally");
}

void verify_navigation_history_synchronization_and_close()
{
    workbench_model_t model;
    workbench_snapshot_ptr_t initial;
    require(model.create_workspace(make_workspace({7}), initial).ok(), "workspace must initialize");
    catalog_t catalog;
    navigator_t navigator;
    const workbench_services_t services{&catalog, &navigator};

    workbench_command_t first_group;
    first_group.kind = workbench_command_kind_t::set_synchronization;
    first_group.workspace = {7};
    first_group.expected_revision = initial->revision();
    first_group.view = {11};
    first_group.synchronization_group = 77;
    first_group.synchronization_policy = view_synchronization_policy_t::cursor_and_selection;
    const auto first_group_result = model.execute(first_group);
    require(first_group_result.error.ok(), "first synchronized view must configure");

    workbench_command_t second_group = first_group;
    second_group.expected_revision = first_group_result.snapshot->revision();
    second_group.view = {12};
    const auto second_group_result = model.execute(second_group);
    require(second_group_result.error.ok(), "group peers must use a consistent policy");

    workbench_command_t navigation;
    navigation.kind = workbench_command_kind_t::navigate;
    navigation.workspace = {7};
    navigation.expected_revision = second_group_result.snapshot->revision();
    navigation.navigation.workspace = {7};
    navigation.navigation.target.document = make_identity({7}, 1);
    navigation.navigation.target.selection.kind = selection_kind_t::address;
    navigation.navigation.target.selection.has_address = true;
    navigation.navigation.target.selection.address = 0x401133U;
    navigation.navigation.target.cursor.has_position = true;
    navigation.navigation.target.cursor.position = 51;
    navigation.navigation.origin = navigation_origin_t::user;
    navigation.navigation.request_focus = true;
    const auto navigation_result = model.execute(navigation, services);
    require(navigation_result.error.ok() && navigation_result.navigation.valid() &&
                navigation_result.snapshot->focused_view() == view_id_t{11},
            "navigation must create a workspace-local history event and focus explicit source view");
    require(document(*navigation_result.snapshot, {1}).local_state.cursor.position == 51 &&
                document(*navigation_result.snapshot, {2}).local_state.cursor.position == 51 &&
                document(*navigation_result.snapshot, {2}).local_state.selection.address == 0x401133U,
            "synchronized groups must propagate cursor and selection across workspace views");

    workbench_command_t back;
    back.kind = workbench_command_kind_t::history_back;
    back.workspace = {7};
    back.expected_revision = navigation_result.snapshot->revision();
    const auto back_result = model.execute(back, services);
    require(back_result.error.ok() && back_result.snapshot->persistence().history.forward.size() == 1 &&
                document(*back_result.snapshot, {1}).local_state.selection.kind == selection_kind_t::none,
            "history back must restore source-local state without global active view lookup");

    workbench_command_t forward;
    forward.kind = workbench_command_kind_t::history_forward;
    forward.workspace = {7};
    forward.expected_revision = back_result.snapshot->revision();
    const auto forward_result = model.execute(forward, services);
    require(forward_result.error.ok() &&
                document(*forward_result.snapshot, {2}).local_state.cursor.position == 51,
            "history forward must route through the stored workspace source context");

    workbench_command_t close;
    close.kind = workbench_command_kind_t::close_document;
    close.workspace = {7};
    close.expected_revision = forward_result.snapshot->revision();
    close.document = {2};
    const auto close_result = model.execute(close, services);
    require(close_result.error.ok() && close_result.snapshot->persistence().documents.size() == 1 &&
                close_result.snapshot->persistence().views.size() == 1 &&
                close_result.snapshot->persistence().active_document == document_id_t{1},
            "close must remove affected views, normalize the split tree, and retain a valid focus");

    workbench_command_t open;
    open.kind = workbench_command_kind_t::open_document;
    open.workspace = {7};
    open.expected_revision = close_result.snapshot->revision();
    open.document_identity = make_identity({7}, 3);
    const auto open_result = model.execute(open, services);
    require(open_result.error.ok() && open_result.document.valid() &&
                view(*open_result.snapshot, open_result.snapshot->focused_view()).document == open_result.document,
            "open must use the catalog and attach the result to an explicit workspace-local view");
}

void verify_restore_missing_documents_and_workspace_bounds()
{
    workbench_model_t model;
    workbench_snapshot_ptr_t first;
    workbench_snapshot_ptr_t second;
    require(model.create_workspace(make_workspace({31}), first).ok(), "first restore workspace must initialize");
    require(model.create_workspace(make_workspace({32}), second).ok(), "second restore workspace must initialize");
    const auto preserved_first = first;
    catalog_t missing_second_document(2);
    const auto restored = model.restore_workspace({32}, second->revision(), second->persistence(),
                                                  missing_second_document,
                                                  missing_document_policy_t::omit);
    require(restored.error.ok() && restored.changed &&
                restored.snapshot->persistence().documents.size() == 1 &&
                restored.snapshot->persistence().views.size() == 1 &&
                restored.snapshot->persistence().active_document == document_id_t{1},
            "restore must omit unavailable documents and deterministically repair local layout state");
    require(preserved_first->revision() == workspace_revision_t{1} &&
                preserved_first->persistence().documents.size() == 2,
            "restore must not leak missing-document handling across workspaces");

    workbench_snapshot_ptr_t current;
    require(model.snapshot({32}, current).ok() && current == restored.snapshot,
            "published workspace snapshot must remain immutable after restore");
    require(model.snapshot({99}, current).code == workbench_error_code_t::invalid_workspace,
            "unknown workspaces must fail without selecting any global fallback");
}

void verify_concurrent_workspaces_and_unlocked_adapters()
{
    constexpr std::size_t workspace_count = 8;
    workbench_model_t model;
    std::vector<workspace_id_t> workspaces;
    workspaces.reserve(workspace_count);
    for (std::size_t index = 0; index < workspace_count; ++index) {
        const workspace_id_t workspace{100U + static_cast<std::uint64_t>(index)};
        workbench_snapshot_ptr_t snapshot;
        require(model.create_workspace(make_workspace(workspace), snapshot).ok(),
                "concurrent workspace must initialize");
        workspaces.push_back(workspace);
    }

    std::atomic<bool> start{false};
    std::vector<std::future<workbench_command_result_t>> pending;
    pending.reserve(workspace_count);
    try {
        for (const auto workspace : workspaces) {
            pending.push_back(std::async(std::launch::async, [&model, &start, workspace] {
                while (!start.load(std::memory_order_acquire))
                    std::this_thread::yield();
                workbench_command_t focus;
                focus.kind = workbench_command_kind_t::focus_view;
                focus.workspace = workspace;
                focus.expected_revision = {1};
                focus.view = {12};
                return model.execute(focus);
            }));
        }
    } catch (...) {
        start.store(true, std::memory_order_release);
        throw;
    }
    start.store(true, std::memory_order_release);
    for (std::size_t index = 0; index < workspace_count; ++index) {
        const auto result = pending[index].get();
        require(result.error.ok() && result.changed && result.snapshot &&
                    result.snapshot->workspace() == workspaces[index] &&
                    result.snapshot->focused_view() == view_id_t{12} &&
                    result.snapshot->persistence().active_document == document_id_t{2},
                "concurrent workspace command must remain isolated and revisioned");
    }
    require(model.workspace_ids() == workspaces,
            "concurrent workspace registry must remain complete and deterministic");

    workbench_snapshot_ptr_t before_open;
    require(model.snapshot(workspaces.front(), before_open).ok(),
            "adapter workspace snapshot must be available");
    mutating_catalog_t mutating_catalog(model);
    workbench_command_t open;
    open.kind = workbench_command_kind_t::open_document;
    open.workspace = workspaces.front();
    open.expected_revision = before_open->revision();
    open.document_identity = make_identity(workspaces.front(), 3);
    const auto open_result = model.execute(open, {&mutating_catalog, nullptr});
    require(mutating_catalog.invoked() && mutating_catalog.nested_error().ok() &&
                open_result.error.code == workbench_error_code_t::revision_mismatch &&
                open_result.snapshot &&
                open_result.snapshot->revision().value == before_open->revision().value + 1U &&
                open_result.snapshot->persistence().documents.size() == 2,
            "reentrant catalog mutation must not deadlock or commit stale workspace state");

    snapshot_navigator_t navigator(model);
    catalog_t catalog;
    workbench_command_t navigation;
    navigation.kind = workbench_command_kind_t::navigate;
    navigation.workspace = workspaces.front();
    navigation.expected_revision = open_result.snapshot->revision();
    navigation.navigation.workspace = workspaces.front();
    navigation.navigation.target.document = make_identity(workspaces.front(), 1);
    navigation.navigation.target.selection.kind = selection_kind_t::address;
    navigation.navigation.target.selection.has_address = true;
    navigation.navigation.target.selection.address = 0x402000U;
    navigation.navigation.target.cursor.has_position = true;
    navigation.navigation.target.cursor.position = 32;
    navigation.navigation.origin = navigation_origin_t::user;
    const auto navigation_result = model.execute(navigation, {&catalog, &navigator});
    require(navigator.invoked() && navigation_result.error.ok() && navigation_result.changed,
            "reentrant navigation resolution must run without the workspace mutex");

    snapshot_catalog_t restore_catalog(model);
    const auto restore_result = model.restore_workspace(
        workspaces.front(), navigation_result.snapshot->revision(),
        navigation_result.snapshot->persistence(), restore_catalog,
        missing_document_policy_t::reject);
    require(restore_result.error.ok() && restore_result.changed &&
                restore_catalog.calls() == navigation_result.snapshot->persistence().documents.size(),
            "restore catalog callbacks must run without the workspace mutex");
}

void verify_capacity_boundaries()
{
    const workspace_id_t document_workspace{200};
    const auto document_count = static_cast<std::uint64_t>(k_max_documents_per_workspace);
    std::vector<document_persistence_dto_t> documents;
    documents.reserve(k_max_documents_per_workspace);
    for (std::uint64_t index = 1; index <= document_count; ++index)
        documents.push_back(make_document_record(document_workspace, index, index));

    document_registry_t registry(document_workspace);
    require(registry.restore(documents).ok() &&
                registry.documents().size() == k_max_documents_per_workspace,
            "document registry must accept the exact workspace document capacity");
    document_descriptor_t descriptor;
    descriptor.identity = make_identity(document_workspace, document_count + 1U);
    descriptor.title = "capacity-overflow";
    descriptor.can_open = true;
    document_id_t opened;
    bool already_open = true;
    const auto open_result = registry.open(descriptor, opened, already_open);
    require(open_result.code == workbench_error_code_t::invalid_persistence &&
                !opened.valid() && !already_open &&
                registry.documents().size() == k_max_documents_per_workspace,
            "document registry must reject growth beyond the workspace document capacity");

    auto excessive_documents = documents;
    excessive_documents.push_back(make_document_record(document_workspace,
                                                        document_count + 1U,
                                                        document_count + 1U));
    document_registry_t excessive_registry(document_workspace);
    require(!excessive_registry.restore(excessive_documents).ok(),
            "document registry restore must reject one document beyond capacity");

    workbench_model_t model;
    workbench_snapshot_ptr_t maximum_layout;
    require(model.create_workspace(make_max_layout_workspace({201}), maximum_layout).ok() &&
                maximum_layout->persistence().views.size() == k_max_views_per_workspace &&
                maximum_layout->persistence().split_tree.nodes.size() ==
                    k_max_split_nodes_per_workspace,
            "workbench must accept exact view and split-node capacities");

    workbench_command_t split;
    split.kind = workbench_command_kind_t::split_view;
    split.workspace = {201};
    split.expected_revision = maximum_layout->revision();
    split.view = {1};
    const auto split_result = model.execute(split);
    require(split_result.error.code == workbench_error_code_t::invalid_persistence &&
                !split_result.changed && split_result.snapshot == maximum_layout,
            "workbench must reject a view split beyond maximum layout capacity");

    auto full_tree = maximum_layout->persistence().split_tree;
    const auto full_tree_root = full_tree.root;
    split_insert_result_t inserted;
    const auto direct_split_result = split_tree_split_view(
        full_tree, {1}, {static_cast<std::uint64_t>(k_max_views_per_workspace) + 1U},
        split_orientation_t::horizontal, k_split_ratio_default_basis_points,
        {static_cast<std::uint64_t>(k_max_split_nodes_per_workspace) + 1U},
        {static_cast<std::uint64_t>(k_max_split_nodes_per_workspace) + 2U}, inserted);
    require(direct_split_result.code == workbench_error_code_t::invalid_split_tree &&
                full_tree.nodes.size() == k_max_split_nodes_per_workspace &&
                full_tree.root == full_tree_root && !inserted.branch.valid() && !inserted.leaf.valid(),
            "split-tree API must reject growth beyond maximum node capacity without mutation");

    navigation_history_dto_t history;
    history.workspace = {202};
    history.capacity = k_max_history_capacity;
    const auto history_capacity = static_cast<std::uint64_t>(k_max_history_capacity);
    for (std::uint64_t index = 1; index <= history_capacity; ++index) {
        require(append_navigation_history(history,
                                          make_navigation_event(history.workspace, index, index)).ok(),
                "history must fill to its exact configured capacity");
    }
    require(history.back.size() == k_max_history_capacity && history.forward.empty(),
            "history must retain every event through exact maximum capacity");
    require(append_navigation_history(
                history, make_navigation_event(history.workspace, history_capacity + 1U,
                                               history_capacity + 1U)).ok() &&
                history.back.size() == k_max_history_capacity &&
                history.back.front().id == navigation_event_id_t{2} &&
                history.back.back().id == navigation_event_id_t{history_capacity + 1U},
            "history must evict only the oldest event after reaching maximum capacity");
    history.capacity = k_max_history_capacity + 1U;
    require(append_navigation_history(
                history, make_navigation_event(history.workspace, history_capacity + 2U,
                                               history_capacity + 2U)).code ==
                workbench_error_code_t::history_capacity,
            "history must reject configured capacity beyond the contract maximum");
}

void verify_identifier_and_revision_overflow()
{
    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();

    document_registry_t registry({300});
    require(registry.restore({make_document_record({300}, maximum, 1)}).ok(),
            "maximum document identifier fixture must restore");
    document_descriptor_t descriptor;
    descriptor.identity = make_identity({300}, 2);
    descriptor.title = "document-overflow";
    descriptor.can_open = true;
    document_id_t opened;
    bool already_open = false;
    require(registry.open(descriptor, opened, already_open).code ==
                workbench_error_code_t::revision_overflow &&
                !opened.valid() && !already_open,
            "document identifier allocation must reject unsigned overflow");

    auto view_overflow_dto = make_workspace({301});
    for (auto& view : view_overflow_dto.views) {
        if (view.id == view_id_t{12})
            view.id = {maximum};
    }
    for (auto& node : view_overflow_dto.split_tree.nodes) {
        if (node.view == view_id_t{12})
            node.view = {maximum};
    }
    workbench_model_t view_model;
    workbench_snapshot_ptr_t view_snapshot;
    require(view_model.create_workspace(view_overflow_dto, view_snapshot).ok(),
            "maximum view identifier fixture must initialize");
    workbench_command_t view_split;
    view_split.kind = workbench_command_kind_t::split_view;
    view_split.workspace = {301};
    view_split.expected_revision = view_snapshot->revision();
    view_split.view = {11};
    require(view_model.execute(view_split).error.code == workbench_error_code_t::revision_overflow,
            "view identifier allocation must reject unsigned overflow");

    auto split_overflow_dto = make_workspace({302});
    const auto old_root = split_overflow_dto.split_tree.root;
    for (auto& node : split_overflow_dto.split_tree.nodes) {
        if (node.id == old_root)
            node.id = {maximum - 1U};
    }
    split_overflow_dto.split_tree.root = {maximum - 1U};
    workbench_model_t split_model;
    workbench_snapshot_ptr_t split_snapshot;
    require(split_model.create_workspace(split_overflow_dto, split_snapshot).ok(),
            "near-maximum split identifier fixture must initialize");
    workbench_command_t split;
    split.kind = workbench_command_kind_t::split_view;
    split.workspace = {302};
    split.expected_revision = split_snapshot->revision();
    split.view = {11};
    require(split_model.execute(split).error.code == workbench_error_code_t::revision_overflow,
            "second split-node identifier allocation must reject unsigned overflow");

    auto event_id_overflow_dto = make_workspace({303});
    event_id_overflow_dto.history.back.push_back(
        make_navigation_event({303}, maximum, 1));
    workbench_model_t event_id_model;
    workbench_snapshot_ptr_t event_id_snapshot;
    require(event_id_model.create_workspace(event_id_overflow_dto, event_id_snapshot).ok(),
            "maximum navigation identifier fixture must initialize");
    workbench_command_t event_id_navigation;
    event_id_navigation.kind = workbench_command_kind_t::navigate;
    event_id_navigation.workspace = {303};
    event_id_navigation.expected_revision = event_id_snapshot->revision();
    event_id_navigation.navigation.workspace = {303};
    event_id_navigation.navigation.target.document = make_identity({303}, 1);
    event_id_navigation.navigation.origin = navigation_origin_t::user;
    event_id_navigation.navigation.sequence = 2;
    require(event_id_model.execute(event_id_navigation).error.code ==
                workbench_error_code_t::revision_overflow,
            "navigation event identifier allocation must reject unsigned overflow");

    auto sequence_overflow_dto = make_workspace({304});
    sequence_overflow_dto.history.back.push_back(
        make_navigation_event({304}, 1, maximum));
    workbench_model_t sequence_model;
    workbench_snapshot_ptr_t sequence_snapshot;
    require(sequence_model.create_workspace(sequence_overflow_dto, sequence_snapshot).ok(),
            "maximum navigation sequence fixture must initialize");
    workbench_command_t sequence_navigation;
    sequence_navigation.kind = workbench_command_kind_t::navigate;
    sequence_navigation.workspace = {304};
    sequence_navigation.expected_revision = sequence_snapshot->revision();
    sequence_navigation.navigation.id = {2};
    sequence_navigation.navigation.workspace = {304};
    sequence_navigation.navigation.target.document = make_identity({304}, 1);
    sequence_navigation.navigation.origin = navigation_origin_t::user;
    require(sequence_model.execute(sequence_navigation).error.code ==
                workbench_error_code_t::revision_overflow,
            "navigation sequence allocation must reject unsigned overflow");

    auto revision_overflow_dto = make_workspace({305});
    revision_overflow_dto.revision = {maximum};
    for (auto& panel : revision_overflow_dto.panels)
        panel.revision = {maximum};
    workbench_model_t revision_model;
    workbench_snapshot_ptr_t revision_snapshot;
    require(revision_model.create_workspace(revision_overflow_dto, revision_snapshot).ok(),
            "maximum workspace revision fixture must initialize");
    workbench_command_t focus;
    focus.kind = workbench_command_kind_t::focus_view;
    focus.workspace = {305};
    focus.expected_revision = revision_snapshot->revision();
    focus.view = {12};
    const auto revision_result = revision_model.execute(focus);
    require(revision_result.error.code == workbench_error_code_t::revision_overflow &&
                !revision_result.changed && revision_result.snapshot == revision_snapshot,
            "workspace revision commit must reject unsigned overflow without publication");

    workbench_model_t invalid_command_model;
    workbench_snapshot_ptr_t invalid_command_snapshot;
    require(invalid_command_model.create_workspace(make_workspace({306}),
                                                   invalid_command_snapshot).ok(),
            "invalid command fixture must initialize");
    workbench_command_t invalid_command;
    invalid_command.kind = static_cast<workbench_command_kind_t>(255U);
    invalid_command.workspace = {306};
    invalid_command.expected_revision = invalid_command_snapshot->revision();
    const auto invalid_command_result = invalid_command_model.execute(invalid_command);
    require(invalid_command_result.error.code == workbench_error_code_t::invalid_persistence &&
                invalid_command_result.error.subject == 255U &&
                !invalid_command_result.changed &&
                invalid_command_result.snapshot == invalid_command_snapshot,
            "out-of-range workbench command kind must fail without a successful no-op");
}

}

bool run_workbench_model_harness(std::string& failure)
{
    try {
        verify_revisioned_workspace_isolation();
        verify_navigation_history_synchronization_and_close();
        verify_restore_missing_documents_and_workspace_bounds();
        verify_concurrent_workspaces_and_unlocked_adapters();
        verify_capacity_boundaries();
        verify_identifier_and_revision_overflow();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
        failure = exception.what();
        return false;
    }
}

}
}

int main()
{
    std::string failure;
    if (!aida::workbench::run_workbench_model_harness(failure)) {
        std::cerr << "workbench_model_harness failed: " << failure << '\n';
        return 1;
    }
    std::cout << "workbench_model_harness source contract satisfied\n";
    return 0;
}
