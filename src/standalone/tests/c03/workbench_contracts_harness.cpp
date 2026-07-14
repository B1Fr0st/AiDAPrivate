#include "workbench_contracts_harness.h"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/workbench/workbench_contracts.h"

#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida {
namespace workbench {
namespace {

void require(bool condition, const char* message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

document_identity_t make_identity(workspace_id_t workspace, std::uint64_t object_id,
                                  document_kind_t kind = document_kind_t::disassembly)
{
    document_identity_t identity;
    identity.workspace = workspace;
    identity.kind = kind;
    identity.object_id = object_id;
    identity.variant_id = object_id + 1000U;
    identity.provider_key = "fixture-provider-" + std::to_string(object_id);
    return identity;
}

workspace_navigation_event_t make_event(workspace_id_t workspace, document_id_t document,
                                        view_id_t view, std::uint64_t id,
                                        std::uint64_t sequence)
{
    workspace_navigation_event_t event;
    event.id = {id};
    event.workspace = workspace;
    event.has_source = true;
    event.source.workspace = workspace;
    event.source.document = document;
    event.source.view = view;
    event.source.cursor.has_position = true;
    event.source.cursor.position = sequence;
    event.target.document = make_identity(workspace, document.value);
    event.target.selection.kind = selection_kind_t::address;
    event.target.selection.has_address = true;
    event.target.selection.address = 0x401000U + sequence;
    event.target.cursor.has_position = true;
    event.target.cursor.position = sequence + 1U;
    event.origin = navigation_origin_t::user;
    event.sequence = sequence;
    return event;
}

workbench_persistence_dto_t make_persistence(workspace_id_t workspace)
{
    workbench_persistence_dto_t dto;
    dto.workspace = workspace;
    dto.revision = {9};
    dto.history.workspace = workspace;

    document_persistence_dto_t first;
    first.id = {11};
    first.identity = make_identity(workspace, 11);
    first.title = "entry";
    first.state_token = "disassembly:entry";
    first.local_state.cursor.has_position = true;
    first.local_state.cursor.position = 17;
    first.local_state.selection.kind = selection_kind_t::range;
    first.local_state.selection.has_address = true;
    first.local_state.selection.address = 0x401000U;
    first.local_state.selection.extent = 8;

    document_persistence_dto_t second;
    second.id = {12};
    second.identity = make_identity(workspace, 12, document_kind_t::diff);
    second.title = "diff";
    second.state_token = "diff:entry";
    second.local_state.cursor.has_position = true;
    second.local_state.cursor.position = 3;
    second.local_state.selection.kind = selection_kind_t::entity;
    second.local_state.selection.entity_key = "diff-node-12";
    second.pinned = true;

    dto.documents = {second, first};
    dto.active_document = first.id;

    view_persistence_dto_t first_view;
    first_view.id = {101};
    first_view.workspace = workspace;
    first_view.document = first.id;
    first_view.focused = true;

    view_persistence_dto_t second_view;
    second_view.id = {102};
    second_view.workspace = workspace;
    second_view.document = second.id;
    second_view.role = view_role_t::secondary;
    second_view.synchronization_group = 44;
    second_view.synchronization_policy = view_synchronization_policy_t::cursor_and_selection;

    dto.views = {second_view, first_view};

    split_node_dto_t first_leaf;
    first_leaf.id = {1};
    first_leaf.kind = split_node_kind_t::leaf;
    first_leaf.view = first_view.id;

    split_node_dto_t second_leaf;
    second_leaf.id = {2};
    second_leaf.kind = split_node_kind_t::leaf;
    second_leaf.view = second_view.id;

    split_node_dto_t root;
    root.id = {3};
    root.kind = split_node_kind_t::branch;
    root.orientation = split_orientation_t::vertical;
    root.ratio_basis_points = 1;
    root.first = first_leaf.id;
    root.second = second_leaf.id;

    dto.split_tree.root = root.id;
    dto.split_tree.nodes = {root, second_leaf, first_leaf};

    panel_state_dto_t panel;
    panel.id = {501};
    panel.workspace = workspace;
    panel.kind = panel_kind_t::navigator;
    panel.extent_pixels = dto.layout.navigator_pixels;
    panel.selected_document = first.id;
    panel.state_token = "navigator:expanded";
    panel.revision = dto.revision;
    dto.panels = {panel};
    return dto;
}

std::vector<view_persistence_dto_t> make_split_views()
{
    return {{{101}}, {{102}}, {{103}}};
}

split_tree_dto_t make_nested_split_tree(split_orientation_t root_orientation,
                                        split_orientation_t nested_orientation,
                                        std::uint16_t root_ratio,
                                        std::uint16_t nested_ratio)
{
    split_node_dto_t first_leaf;
    first_leaf.id = {1};
    first_leaf.kind = split_node_kind_t::leaf;
    first_leaf.view = {101};

    split_node_dto_t second_leaf;
    second_leaf.id = {2};
    second_leaf.kind = split_node_kind_t::leaf;
    second_leaf.view = {102};

    split_node_dto_t third_leaf;
    third_leaf.id = {3};
    third_leaf.kind = split_node_kind_t::leaf;
    third_leaf.view = {103};

    split_node_dto_t nested;
    nested.id = {4};
    nested.kind = split_node_kind_t::branch;
    nested.orientation = nested_orientation;
    nested.ratio_basis_points = nested_ratio;
    nested.first = first_leaf.id;
    nested.second = second_leaf.id;

    split_node_dto_t root;
    root.id = {5};
    root.kind = split_node_kind_t::branch;
    root.orientation = root_orientation;
    root.ratio_basis_points = root_ratio;
    root.first = nested.id;
    root.second = third_leaf.id;

    return {root.id, {first_leaf, second_leaf, third_leaf, nested, root}};
}

class catalog_adapter_t final : public document_catalog_adapter_t {
public:
    workbench_error_t describe(const document_identity_t& identity,
                               document_descriptor_t& output) const override
    {
        const auto result = validate_document_identity(identity);
        if (!result)
            return result;
        output.identity = identity;
        output.title = "adapter-document";
        output.can_open = true;
        return {};
    }
};

class navigation_adapter_fixture_t final : public navigation_adapter_t {
public:
    workbench_error_t resolve(const navigation_event_t& event,
                              navigation_resolution_t& output) const override
    {
        const auto result = validate_navigation_event(event);
        if (!result)
            return result;
        output.document = event.target.document;
        output.selection = event.target.selection;
        output.cursor = event.target.cursor;
        output.requires_document_open = true;
        return {};
    }
};

class view_context_adapter_fixture_t final : public view_context_adapter_t {
public:
    workbench_error_t bind(const view_context_t& context,
                           legacy_view_binding_t& output) const override
    {
        const auto result = validate_view_context(context);
        if (!result)
            return result;
        output.kind = document_kind_t::disassembly;
        output.role = view_role_t::primary;
        output.legacy_view_tag = context.view.value;
        return {};
    }
};

class persistence_adapter_fixture_t final : public workbench_persistence_adapter_t {
public:
    workbench_error_t load(workspace_id_t workspace,
                           workbench_persistence_dto_t& output) const override
    {
        if (!stored_.workspace.valid() || workspace != stored_.workspace)
            return {workbench_error_code_t::workspace_mismatch, workspace.value};
        output = stored_;
        return {};
    }

    workbench_error_t store(const workbench_persistence_dto_t& input) override
    {
        stored_ = input;
        return normalize_persistence_dto(stored_);
    }

private:
    workbench_persistence_dto_t stored_;
};

void verify_split_normalization_and_document_identity()
{
    const workspace_id_t workspace{1};
    auto dto = make_persistence(workspace);
    require(normalize_persistence_dto(dto).ok(), "split fixture must normalize");
    require(dto.split_tree.nodes.size() == 3, "split fixture node count must be preserved");
    require(dto.split_tree.nodes[0].id.value == 1 && dto.split_tree.nodes[2].id.value == 3,
            "split nodes must use deterministic identifier order");
    require(dto.split_tree.nodes[2].ratio_basis_points == k_split_ratio_min_basis_points,
            "split ratio must clamp to the fixed lower bound");

    const auto original = dto.documents[0].identity;
    auto same = original;
    require(document_identity_equal(original, same), "equal document identities must compare equal");
    same.variant_id += 1;
    require(!document_identity_equal(original, same), "document variants must remain distinct");
    same = original;
    same.workspace = {2};
    require(!document_identity_equal(original, same), "document identities must retain workspace scope");
    const auto diff_identity = make_identity(workspace, 77, document_kind_t::diff);
    require(validate_document_identity(diff_identity).ok(),
            "diff documents must retain a stable typed identity");
    require(dto.documents[0].identity.kind == document_kind_t::diff,
            "diff documents must persist through the typed document contract");
}

void verify_nested_split_layout_extents()
{
    const fixed_layout_constraints_t constraints;
    const auto views = make_split_views();
    const auto valid_tree = make_nested_split_tree(split_orientation_t::horizontal,
                                                   split_orientation_t::vertical,
                                                   k_split_ratio_default_basis_points,
                                                   k_split_ratio_default_basis_points);
    require(validate_split_tree(valid_tree, views).ok(),
            "nested split topology must remain valid without a runtime extent");
    require(validate_split_tree(valid_tree, views, constraints, {1298, 406}).ok(),
            "nested horizontal and vertical splits must preserve minimum leaf extents");

    const auto horizontal_underflow = make_nested_split_tree(split_orientation_t::horizontal,
                                                             split_orientation_t::horizontal,
                                                             k_split_ratio_default_basis_points,
                                                             k_split_ratio_min_basis_points);
    const auto horizontal_result = validate_split_tree(horizontal_underflow, views, constraints,
                                                       {1298, 200});
    require(horizontal_result.code == workbench_error_code_t::invalid_split_tree &&
                horizontal_result.subject == 1,
            "nested horizontal split must reject a leaf below minimum document width");

    const auto vertical_underflow = make_nested_split_tree(split_orientation_t::vertical,
                                                           split_orientation_t::vertical,
                                                           k_split_ratio_default_basis_points,
                                                           k_split_ratio_min_basis_points);
    const auto vertical_result = validate_split_tree(vertical_underflow, views, constraints,
                                                     {320, 818});
    require(vertical_result.code == workbench_error_code_t::invalid_split_tree &&
                vertical_result.subject == 1,
            "nested vertical split must reject a leaf below minimum document height");
}

void verify_history_and_workspace_isolation()
{
    const workspace_id_t first_workspace{1};
    const workspace_id_t second_workspace{2};
    navigation_history_dto_t history;
    history.workspace = first_workspace;
    history.capacity = 4;
    const auto first = make_event(first_workspace, {11}, {101}, 1, 1);
    const auto second = make_event(first_workspace, {11}, {101}, 2, 2);
    require(append_navigation_history(history, first).ok(), "first history entry must append");
    require(append_navigation_history(history, second).ok(), "second history entry must append");

    navigation_event_t restored;
    require(history_back(history, restored).ok() && restored.id == second.id,
            "history back must expose the newest stored event");
    require(history_forward(history, restored).ok() && restored.id == second.id,
            "history forward must restore the moved event");
    auto cross_workspace = make_event(second_workspace, {11}, {101}, 3, 3);
    require(append_navigation_history(history, cross_workspace).code ==
                workbench_error_code_t::workspace_mismatch,
            "history must reject cross-workspace events");

    workspace_navigation_event_t mcp_event = make_event(first_workspace, {11}, {101}, 4, 4);
    mcp_event.origin = navigation_origin_t::mcp;
    mcp_event.request_focus = false;
    require(validate_workspace_navigation_event(mcp_event).ok(),
            "MCP navigation must remain valid without focus activation");
    mcp_event.request_focus = true;
    require(validate_workspace_navigation_event(mcp_event).code ==
                workbench_error_code_t::focus_forbidden,
            "MCP navigation must reject focus activation");

    workspace_view_context_t synchronized_context = make_event(first_workspace, {11}, {101}, 5, 5).source;
    synchronized_context.synchronization_group = 9;
    synchronized_context.synchronization_policy = view_synchronization_policy_t::selection;
    require(validate_workspace_view_context(synchronized_context).ok(),
            "workspace view contexts must validate explicit synchronization policy");
    synchronized_context.synchronization_group = 0;
    require(validate_workspace_view_context(synchronized_context).code ==
                workbench_error_code_t::invalid_synchronization_policy,
            "synchronized workspace views must require a workspace-local group");

    auto first_dto = make_persistence(first_workspace);
    require(normalize_persistence_dto(first_dto).ok(), "first workspace must normalize");
    auto second_dto = make_persistence(second_workspace);
    require(normalize_persistence_dto(second_dto).ok(), "second workspace must normalize");
    second_dto.documents[0].identity.workspace = first_workspace;
    require(validate_persistence_dto(second_dto).code == workbench_error_code_t::workspace_mismatch,
            "workspace persistence must reject cross-workspace documents");
}

void verify_fixed_dimensions_and_revisioning()
{
    fixed_layout_constraints_t constraints;
    const auto minimum = minimum_layout_extent(constraints);
    require(minimum.width_pixels == 1024 && minimum.height_pixels == 514,
            "default fixed layout dimensions must remain stable");
    require(layout_extent_satisfies(constraints, minimum),
            "minimum extent must satisfy fixed layout constraints");
    require(!layout_extent_satisfies(constraints, {minimum.width_pixels - 1U, minimum.height_pixels}),
            "undersized fixed layout width must reject");
    constraints.navigator_pixels = 1;
    constraints.inspector_pixels = 5000;
    constraints.bottom_panel_pixels = 1;
    normalize_fixed_layout_constraints(constraints);
    require(validate_fixed_layout_constraints(constraints).ok(),
            "normalized fixed dimensions must validate");
    require(constraints.navigator_pixels == 160 && constraints.inspector_pixels == 720 &&
                constraints.bottom_panel_pixels == 120,
            "fixed layout normalization must use deterministic bounds");
    auto dto = make_persistence({1});
    require(normalize_persistence_dto(dto).ok(), "fixed panel fixture must normalize");
    dto.panels[0].extent_pixels += 1U;
    require(validate_persistence_dto(dto).code == workbench_error_code_t::invalid_panel,
            "panel state must not diverge from fixed workspace dimensions");

    auto missing_active_document = make_persistence({1});
    missing_active_document.active_document = {};
    require(validate_persistence_dto(missing_active_document).code ==
                workbench_error_code_t::invalid_persistence,
            "persistence must require an active document");
    auto unknown_active_document = make_persistence({1});
    unknown_active_document.active_document = {99};
    require(validate_persistence_dto(unknown_active_document).code ==
                workbench_error_code_t::invalid_document,
            "persistence must require the active document to be open");
    auto invalid_local_state = make_persistence({1});
    invalid_local_state.documents[0].local_state.cursor.has_position = false;
    invalid_local_state.documents[0].local_state.cursor.position = 1;
    require(validate_persistence_dto(invalid_local_state).code ==
                workbench_error_code_t::invalid_document_state,
            "persistence must reject invalid document-local cursor state");
    auto invalid_local_selection = make_persistence({1});
    invalid_local_selection.documents[0].local_state.selection.kind = selection_kind_t::address;
    require(validate_persistence_dto(invalid_local_selection).code ==
                workbench_error_code_t::invalid_document_state,
            "persistence must reject invalid document-local selection state");
    auto invalid_view_synchronization = make_persistence({1});
    invalid_view_synchronization.views[0].synchronization_group = 0;
    require(validate_persistence_dto(invalid_view_synchronization).code ==
                workbench_error_code_t::invalid_synchronization_policy,
            "persistence must retain explicit view synchronization policy");

    workspace_revision_t next;
    require(next_workspace_revision({9}, next).ok() && next.value == 10,
            "revision increment must be monotonic");
    require(revision_matches({10}, next), "matching revisions must compare equal");
    require(next_workspace_revision({(std::numeric_limits<std::uint64_t>::max)()}, next).code ==
                workbench_error_code_t::revision_overflow,
            "revision overflow must fail closed");
}

void verify_deterministic_persistence_and_adapters()
{
    auto first = make_persistence({1});
    auto second = first;
    std::swap(second.documents[0], second.documents[1]);
    std::swap(second.views[0], second.views[1]);
    std::swap(second.split_tree.nodes[0], second.split_tree.nodes[2]);
    require(normalize_persistence_dto(first).ok() && normalize_persistence_dto(second).ok(),
            "equivalent persistence fixtures must normalize");
    const auto first_fingerprint = persistence_fingerprint(first);
    const auto second_fingerprint = persistence_fingerprint(second);
    require(first_fingerprint.value != 0 && first_fingerprint == second_fingerprint,
            "canonical persistence values must be deterministic");
    require(persistence_dto_equal(first, second),
            "canonical persistence DTOs must round-trip equivalently");
    require(first.active_document == document_id_t{11} &&
                first.documents[0].local_state.cursor.has_position &&
                first.documents[0].local_state.selection.kind != selection_kind_t::none,
            "canonical persistence must retain active and document-local navigation state");
    auto local_state_variant = first;
    local_state_variant.documents[0].local_state.cursor.position += 1U;
    require(normalize_persistence_dto(local_state_variant).ok() &&
                !persistence_dto_equal(first, local_state_variant) &&
                persistence_fingerprint(first) != persistence_fingerprint(local_state_variant),
            "document-local cursor state must participate in persistent identity");
    auto active_document_variant = first;
    active_document_variant.active_document = {12};
    require(normalize_persistence_dto(active_document_variant).ok() &&
                !persistence_dto_equal(first, active_document_variant) &&
                persistence_fingerprint(first) != persistence_fingerprint(active_document_variant),
            "active document must participate in persistent identity");

    catalog_adapter_t catalog;
    document_descriptor_t descriptor;
    require(catalog.describe(first.documents[0].identity, descriptor).ok() && descriptor.can_open,
            "document adapter must preserve a valid document identity");

    const workspace_navigation_event_t event = make_event({1}, {11}, {101}, 91, 91);
    navigation_adapter_fixture_t navigator;
    navigation_resolution_t resolution;
    require(navigator.resolve(event, resolution).ok() &&
                document_identity_equal(resolution.document, event.target.document) &&
                document_local_cursor_equal(resolution.cursor, event.target.cursor),
            "navigation adapter must retain target identity");

    view_context_adapter_fixture_t view_adapter;
    legacy_view_binding_t binding;
    require(view_adapter.bind(event.source, binding).ok() && binding.legacy_view_tag == 101,
            "view adapter must retain the explicit source view");

    persistence_adapter_fixture_t persistence;
    require(persistence.store(first).ok(), "persistence adapter must accept canonical state");
    workbench_persistence_dto_t restored;
    require(persistence.load({1}, restored).ok() && persistence_dto_equal(first, restored),
            "persistence adapter must preserve canonical state");
}

}

bool run_workbench_contracts_harness(std::string& failure)
{
    try {
        verify_split_normalization_and_document_identity();
        verify_nested_split_layout_extents();
        verify_history_and_workspace_isolation();
        verify_fixed_dimensions_and_revisioning();
        verify_deterministic_persistence_and_adapters();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(exception.what());
        failure = exception.what();
        return false;
    }
}

}
}

int main()
{
    std::string failure;
    if (!aida::workbench::run_workbench_contracts_harness(failure)) {
        std::cerr << "workbench_contracts_harness failed: " << failure << '\n';
        return 1;
    }
    std::cout << "workbench_contracts_harness source contract satisfied\n";
    return 0;
}
