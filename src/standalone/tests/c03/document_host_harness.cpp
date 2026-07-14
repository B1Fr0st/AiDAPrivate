#include "document_host_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/workbench/document_host/document_host.hpp"

#include <algorithm>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida::workbench::document_host::c03_test {
namespace {

using namespace aida::workbench;

static_assert(k_document_host_contract_schema_version == 1,
              "document host contract schema version changed");
static_assert(static_cast<std::uint8_t>(document_host_dispatch_kind_t::toolbar) == 9,
              "document host toolbar dispatch value changed");
static_assert(static_cast<std::uint8_t>(document_host_dispatch_kind_t::keyboard) == 10,
              "document host dispatch values changed");
static_assert(static_cast<std::uint8_t>(document_host_toolbar_action_t::close_document) == 6,
              "document host toolbar action values changed");
static_assert(static_cast<std::uint8_t>(document_host_presentation_kind_t::empty) == 3,
              "document host presentation values changed");

void require(bool condition, const char* message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

document_persistence_dto_t make_document(workspace_id_t workspace, std::uint64_t id,
                                         std::string title)
{
    document_persistence_dto_t output;
    output.id = {id};
    output.identity.workspace = workspace;
    output.identity.kind = document_kind_t::disassembly;
    output.identity.object_id = 0x1000U + id;
    output.identity.provider_key = "document-host-fixture";
    output.identity.has_address = true;
    output.identity.address = 0x401000U + id * 0x20U;
    output.title = std::move(title);
    return output;
}

workbench_persistence_dto_t make_persistence(workspace_id_t workspace)
{
    workbench_persistence_dto_t output;
    output.workspace = workspace;
    output.revision = {1};
    output.documents = {
        make_document(workspace, 1,
                      "Primary document with a deliberately long title for text fitting checks"),
        make_document(workspace, 2,
                      "Secondary document with a deliberately long title for text fitting checks"),
        make_document(workspace, 3,
                      "Tertiary document with a deliberately long title for text fitting checks")};
    output.active_document = {1};
    output.views = {{{1}, workspace, {1}, view_role_t::primary, 0,
                     view_synchronization_policy_t::independent, true}};
    output.split_tree.root = {1};
    output.split_tree.nodes = {{{1}, split_node_kind_t::leaf, split_orientation_t::horizontal,
                                k_split_ratio_default_basis_points, {1}, {}, {}}};
    output.history.workspace = workspace;
    return output;
}

class navigation_adapter_t final : public aida::workbench::navigation_adapter_t {
public:
    workbench_error_t resolve(const navigation_event_t& event,
                              navigation_resolution_t& output) const override
    {
        output.document = event.target.document;
        output.selection = event.target.selection;
        output.cursor = event.target.cursor;
        return {};
    }
};

class state_adapter_t final : public document_host_state_adapter_t {
public:
    workbench_error_t presentation(const workspace_view_context_t& context,
                                   document_host_presentation_state_t& output) const override
    {
        switch (context.document.value) {
            case 1:
                output.kind = document_host_presentation_kind_t::loading;
                output.message = "Loading analysis";
                return {};
            case 2:
                output.kind = document_host_presentation_kind_t::error;
                output.message = "Analysis worker failed";
                output.retryable = true;
                return {};
            case 3:
                output.kind = document_host_presentation_kind_t::empty;
                output.message = "No derived document content";
                return {};
            default:
                return {workbench_error_code_t::adapter_rejected, context.document.value};
        }
    }
};

class rejected_state_adapter_t final : public document_host_state_adapter_t {
public:
    workbench_error_t presentation(const workspace_view_context_t& context,
                                   document_host_presentation_state_t&) const override
    {
        return {workbench_error_code_t::adapter_rejected, context.document.value};
    }
};

bool contains_presentation(const document_host_chrome_t& chrome,
                           document_host_presentation_kind_t expected)
{
    return std::any_of(chrome.leaves.begin(), chrome.leaves.end(), [expected](const auto& leaf) {
        return leaf.presentation.kind == expected;
    });
}

bool all_assertions_pass(const document_host_chrome_t& chrome)
{
    return !chrome.source_assertions.empty() && std::all_of(
        chrome.source_assertions.begin(), chrome.source_assertions.end(),
        [](const auto& assertion) { return assertion.passed; });
}

workbench_snapshot_ptr_t create(workbench_model_t& model, workspace_id_t workspace)
{
    workbench_snapshot_ptr_t snapshot;
    require(model.create_workspace(make_persistence(workspace), snapshot).ok(),
            "workspace creation failed");
    return snapshot;
}

workbench_command_result_t split(document_host_t& host, workspace_id_t workspace,
                                 workspace_revision_t revision, view_id_t view,
                                 document_id_t document, split_orientation_t orientation)
{
    document_host_dispatch_t input;
    input.kind = orientation == split_orientation_t::horizontal
        ? document_host_dispatch_kind_t::split_horizontal
        : document_host_dispatch_kind_t::split_vertical;
    input.workspace = workspace;
    input.expected_revision = revision;
    input.view = view;
    input.document = document;
    return host.dispatch(input);
}

workbench_command_result_t dispatch_toolbar(document_host_t& host, workspace_id_t workspace,
                                            workspace_revision_t revision,
                                            document_host_toolbar_action_t action,
                                            std::uint16_t ratio_basis_points =
                                                k_split_ratio_default_basis_points,
                                            document_id_t document = {})
{
    document_host_dispatch_t input;
    input.kind = document_host_dispatch_kind_t::toolbar;
    input.workspace = workspace;
    input.expected_revision = revision;
    input.toolbar_action = action;
    input.ratio_basis_points = ratio_basis_points;
    input.document = document;
    return host.dispatch(input);
}

void require_next_revision(const workbench_command_result_t& result,
                           workspace_revision_t previous_revision, const char* message)
{
    require(result.error.ok() && result.changed && result.snapshot &&
                result.snapshot->revision().value == previous_revision.value + 1U,
            message);
}

void verify_desktop_chrome_and_presentation()
{
    workbench_model_t model;
    const workspace_id_t workspace{71};
    auto snapshot = create(model, workspace);
    navigation_adapter_t navigation;
    state_adapter_t state;
    document_host_t host(model, {nullptr, &navigation, &state});

    auto first = split(host, workspace, snapshot->revision(), {1}, {2},
                       split_orientation_t::horizontal);
    require(first.error.ok() && first.changed && first.snapshot, "first split failed");
    auto second = split(host, workspace, first.snapshot->revision(), {1}, {3},
                        split_orientation_t::vertical);
    require(second.error.ok() && second.changed && second.snapshot, "second split failed");

    document_host_chrome_t chrome;
    const document_host_layout_request_t request{{2400, 1600}, 144, 8};
    require(host.compose(workspace, request, chrome).ok(), "desktop chrome composition failed");
    require(chrome.layout_mode == document_host_layout_mode_t::desktop,
            "desktop layout compacted unexpectedly");
    require(chrome.navigator_visible && chrome.inspector_visible && chrome.bottom_panel_visible,
            "desktop chrome lost required panels");
    require(chrome.leaves.size() == 3 && chrome.splitters.size() == 2,
            "split tree chrome did not retain all leaves");
    require(chrome.tabs.size() == 3 && chrome.toolbar.size() == 7,
            "document tabs or toolbar actions are incomplete");
    require(contains_presentation(chrome, document_host_presentation_kind_t::loading) &&
                contains_presentation(chrome, document_host_presentation_kind_t::error) &&
                contains_presentation(chrome, document_host_presentation_kind_t::empty),
            "document presentation states were not rendered per leaf");
    require(all_assertions_pass(chrome) && validate_document_host_chrome(chrome).ok(),
            "desktop chrome source assertions failed");
    for (const auto& tab : chrome.tabs) {
        if (!tab.visible)
            continue;
        require(document_host_text_fits(
                    tab.label, tab.label_bounds.width,
                    document_host_scale_pixels(request.average_character_width_pixels, request.dpi)),
                "tab label exceeded its stable bounds");
    }
}

void verify_compact_and_constrained_layouts()
{
    workbench_model_t model;
    const workspace_id_t workspace{72};
    auto snapshot = create(model, workspace);
    state_adapter_t state;
    document_host_t host(model, {nullptr, nullptr, &state});
    const auto split_result = split(host, workspace, snapshot->revision(), {1}, {2},
                                    split_orientation_t::horizontal);
    require(split_result.error.ok(), "compact fixture split failed");

    document_host_chrome_t compact;
    require(host.compose(workspace, {{780, 600}, 96, 8}, compact).ok(),
            "compact chrome composition failed");
    require(!compact.inspector_visible && compact.layout_mode == document_host_layout_mode_t::constrained,
            "compact width did not preserve constrained split geometry");
    require(all_assertions_pass(compact) && validate_document_host_chrome(compact).ok(),
            "compact chrome overlapped");

    document_host_chrome_t constrained;
    require(host.compose(workspace, {{140, 120}, 96, 8}, constrained).ok(),
            "constrained chrome composition failed");
    require(constrained.layout_mode == document_host_layout_mode_t::constrained &&
                constrained.tab_overflow_visible && constrained.tab_overflow_count == 2,
            "constrained layout did not use bounded tab overflow");
    require(all_assertions_pass(constrained) && validate_document_host_chrome(constrained).ok(),
            "constrained chrome overlapped");
}

void verify_dispatch_and_keyboard_routing()
{
    workbench_model_t model;
    const workspace_id_t workspace{73};
    auto snapshot = create(model, workspace);
    navigation_adapter_t navigation;
    document_host_t host(model, {nullptr, &navigation, nullptr});

    document_host_dispatch_t select;
    select.kind = document_host_dispatch_kind_t::select_document;
    select.workspace = workspace;
    select.expected_revision = snapshot->revision();
    select.document = {2};
    auto result = host.dispatch(select);
    require(result.error.ok() && result.changed && result.snapshot->persistence().active_document == document_id_t{2},
            "tab selection did not route through the B25 open command");

    document_host_dispatch_t next_tab;
    next_tab.kind = document_host_dispatch_kind_t::keyboard;
    next_tab.workspace = workspace;
    next_tab.expected_revision = result.snapshot->revision();
    next_tab.key = {document_host_key_t::tab, true, false, false};
    result = host.dispatch(next_tab);
    require(result.error.ok() && result.snapshot->persistence().active_document == document_id_t{3},
            "Ctrl+Tab did not route to the next document");

    document_host_dispatch_t previous_tab = next_tab;
    previous_tab.expected_revision = result.snapshot->revision();
    previous_tab.key.shift = true;
    result = host.dispatch(previous_tab);
    require(result.error.ok() && result.snapshot->persistence().active_document == document_id_t{2},
            "Ctrl+Shift+Tab did not route to the previous document");

    const auto split_result = split(host, workspace, result.snapshot->revision(), {1}, {1},
                                    split_orientation_t::horizontal);
    require(split_result.error.ok() && split_result.snapshot->persistence().views.size() == 2,
            "split toolbar command fixture failed");

    document_host_dispatch_t next_view;
    next_view.kind = document_host_dispatch_kind_t::keyboard;
    next_view.workspace = workspace;
    next_view.expected_revision = split_result.snapshot->revision();
    next_view.key = {document_host_key_t::f6, false, false, false};
    result = host.dispatch(next_view);
    require(result.error.ok() && result.snapshot->focused_view() == view_id_t{2},
            "F6 did not route focus to the next split");

    document_host_dispatch_t navigate;
    navigate.kind = document_host_dispatch_kind_t::navigate;
    navigate.workspace = workspace;
    navigate.expected_revision = result.snapshot->revision();
    navigate.navigation.workspace = workspace;
    navigate.navigation.target.document = result.snapshot->persistence().documents.front().identity;
    navigate.navigation.target.selection.kind = selection_kind_t::address;
    navigate.navigation.target.selection.has_address = true;
    navigate.navigation.target.selection.address = 0x401020;
    navigate.navigation.target.cursor.has_position = true;
    navigate.navigation.target.cursor.position = 0x401020;
    navigate.navigation.origin = navigation_origin_t::navigator;
    result = host.dispatch(navigate);
    require(result.error.ok() && result.snapshot->persistence().history.back.size() == 1,
            "navigation did not use the B25 history command path");

    document_host_dispatch_t history_back;
    history_back.kind = document_host_dispatch_kind_t::keyboard;
    history_back.workspace = workspace;
    history_back.expected_revision = result.snapshot->revision();
    history_back.key = {document_host_key_t::left, false, true, false};
    result = host.dispatch(history_back);
    require(result.error.ok() && result.snapshot->persistence().history.forward.size() == 1,
            "Alt+Left did not route to B25 history back");

    document_host_dispatch_t close;
    close.kind = document_host_dispatch_kind_t::keyboard;
    close.workspace = workspace;
    close.expected_revision = result.snapshot->revision();
    close.key = {document_host_key_t::w, true, false, false};
    result = host.dispatch(close);
    require(result.error.ok() && result.snapshot->persistence().documents.size() == 2,
            "Ctrl+W did not route to B25 document close");
}

void verify_toolbar_dispatch_mapping_and_revisions()
{
    workbench_model_t model;
    const workspace_id_t workspace{76};
    const auto snapshot = create(model, workspace);
    navigation_adapter_t navigation;
    document_host_t host(model, {nullptr, &navigation, nullptr});

    document_host_dispatch_t navigate;
    navigate.kind = document_host_dispatch_kind_t::navigate;
    navigate.workspace = workspace;
    navigate.expected_revision = snapshot->revision();
    navigate.navigation.workspace = workspace;
    navigate.navigation.target.document = snapshot->persistence().documents.front().identity;
    navigate.navigation.target.selection.kind = selection_kind_t::address;
    navigate.navigation.target.selection.has_address = true;
    navigate.navigation.target.selection.address = 0x401020;
    navigate.navigation.target.cursor.has_position = true;
    navigate.navigation.target.cursor.position = 0x401020;
    navigate.navigation.origin = navigation_origin_t::navigator;
    auto result = host.dispatch(navigate);
    require_next_revision(result, snapshot->revision(),
                          "toolbar history fixture navigation did not advance revision");
    require(result.snapshot->persistence().history.back.size() == 1 &&
                result.snapshot->persistence().history.forward.empty(),
            "toolbar history fixture did not establish B25 history state");

    auto previous_revision = result.snapshot->revision();
    result = dispatch_toolbar(host, workspace, previous_revision,
                              document_host_toolbar_action_t::history_back);
    require_next_revision(result, previous_revision,
                          "toolbar history-back did not commit through B25");
    require(result.snapshot->persistence().history.back.empty() &&
                result.snapshot->persistence().history.forward.size() == 1,
            "toolbar history-back did not transfer the history entry");

    previous_revision = result.snapshot->revision();
    result = dispatch_toolbar(host, workspace, previous_revision,
                              document_host_toolbar_action_t::history_forward);
    require_next_revision(result, previous_revision,
                          "toolbar history-forward did not commit through B25");
    require(result.snapshot->persistence().history.back.size() == 1 &&
                result.snapshot->persistence().history.forward.empty(),
            "toolbar history-forward did not restore the history entry");

    previous_revision = result.snapshot->revision();
    result = dispatch_toolbar(host, workspace, previous_revision,
                              document_host_toolbar_action_t::split_horizontal, 4200);
    require_next_revision(result, previous_revision,
                          "toolbar horizontal split did not commit through B25");
    const auto& horizontal_persistence = result.snapshot->persistence();
    const auto horizontal_branch = std::find_if(
        horizontal_persistence.split_tree.nodes.begin(), horizontal_persistence.split_tree.nodes.end(),
        [branch = result.split.branch](const split_node_dto_t& node) { return node.id == branch; });
    require(result.view.valid() && result.split.branch.valid() && result.split.leaf.valid() &&
                horizontal_persistence.views.size() == 2 &&
                horizontal_branch != horizontal_persistence.split_tree.nodes.end() &&
                horizontal_branch->kind == split_node_kind_t::branch &&
                horizontal_branch->orientation == split_orientation_t::horizontal &&
                horizontal_branch->ratio_basis_points == 4200,
            "toolbar horizontal split did not preserve B25 split state");

    previous_revision = result.snapshot->revision();
    result = dispatch_toolbar(host, workspace, previous_revision,
                              document_host_toolbar_action_t::split_vertical, 5800);
    require_next_revision(result, previous_revision,
                          "toolbar vertical split did not commit through B25");
    const auto& vertical_persistence = result.snapshot->persistence();
    const auto vertical_branch = std::find_if(
        vertical_persistence.split_tree.nodes.begin(), vertical_persistence.split_tree.nodes.end(),
        [branch = result.split.branch](const split_node_dto_t& node) { return node.id == branch; });
    require(result.view.valid() && result.split.branch.valid() && result.split.leaf.valid() &&
                vertical_persistence.views.size() == 3 && vertical_persistence.split_tree.nodes.size() == 5 &&
                vertical_branch != vertical_persistence.split_tree.nodes.end() &&
                vertical_branch->kind == split_node_kind_t::branch &&
                vertical_branch->orientation == split_orientation_t::vertical &&
                vertical_branch->ratio_basis_points == 5800,
            "toolbar vertical split did not preserve B25 split state");

    previous_revision = result.snapshot->revision();
    result = dispatch_toolbar(host, workspace, previous_revision,
                              document_host_toolbar_action_t::next_view);
    require_next_revision(result, previous_revision,
                          "toolbar next-view did not commit through B25");
    require(result.view == view_id_t{2} && result.snapshot->focused_view() == view_id_t{2},
            "toolbar next-view did not focus the next B25 view");

    const auto stale_revision = previous_revision;
    previous_revision = result.snapshot->revision();
    result = dispatch_toolbar(host, workspace, previous_revision,
                              document_host_toolbar_action_t::previous_view);
    require_next_revision(result, previous_revision,
                          "toolbar previous-view did not commit through B25");
    require(result.view == view_id_t{1} && result.snapshot->focused_view() == view_id_t{1},
            "toolbar previous-view did not focus the previous B25 view");

    const auto revision_after_focus = result.snapshot->revision();
    const auto stale = dispatch_toolbar(host, workspace, stale_revision,
                                        document_host_toolbar_action_t::next_view);
    require(stale.error.code == workbench_error_code_t::revision_mismatch && !stale.changed &&
                stale.snapshot && stale.snapshot->revision() == revision_after_focus,
            "stale toolbar dispatch mutated B25 state");

    const auto closing_document = result.snapshot->persistence().active_document;
    result = dispatch_toolbar(host, workspace, revision_after_focus,
                              document_host_toolbar_action_t::close_document,
                              k_split_ratio_default_basis_points, {999});
    require_next_revision(result, revision_after_focus,
                          "toolbar close-document did not commit through B25");
    const auto& closed_persistence = result.snapshot->persistence();
    require(result.document == closing_document && closed_persistence.documents.size() == 2 &&
                closed_persistence.views.size() == 1 &&
                closed_persistence.active_document != closing_document &&
                std::none_of(closed_persistence.documents.begin(), closed_persistence.documents.end(),
                             [closing_document](const document_persistence_dto_t& document) {
                                 return document.id == closing_document;
                             }),
            "toolbar close-document did not remove the active B25 document state");

    document_host_dispatch_t invalid_action;
    invalid_action.kind = document_host_dispatch_kind_t::toolbar;
    invalid_action.workspace = workspace;
    invalid_action.expected_revision = result.snapshot->revision();
    invalid_action.toolbar_action = static_cast<document_host_toolbar_action_t>(0xffU);
    const auto rejected_action = host.dispatch(invalid_action);
    require(rejected_action.error.code == workbench_error_code_t::invalid_persistence &&
                !rejected_action.changed && rejected_action.snapshot &&
                rejected_action.snapshot->revision() == result.snapshot->revision(),
            "invalid toolbar action changed B25 state");

    const auto invalid_workspace = dispatch_toolbar(host, {999}, result.snapshot->revision(),
                                                    document_host_toolbar_action_t::next_view);
    require(invalid_workspace.error.code == workbench_error_code_t::invalid_workspace &&
                !invalid_workspace.changed && !invalid_workspace.snapshot,
            "toolbar dispatch accepted an unknown workspace");
}

void verify_workspace_isolation_and_adapter_failure()
{
    workbench_model_t model;
    const workspace_id_t first_workspace{74};
    const workspace_id_t second_workspace{75};
    auto first = create(model, first_workspace);
    auto second = create(model, second_workspace);
    rejected_state_adapter_t rejected;
    document_host_t host(model, {nullptr, nullptr, &rejected});

    document_host_dispatch_t select;
    select.kind = document_host_dispatch_kind_t::select_document;
    select.workspace = first_workspace;
    select.expected_revision = first->revision();
    select.document = {2};
    const auto selected = host.dispatch(select);
    require(selected.error.ok(), "first workspace selection failed");
    workbench_snapshot_ptr_t second_after;
    require(model.snapshot(second_workspace, second_after).ok() &&
                second_after->persistence().active_document == second->persistence().active_document &&
                second_after->revision() == second->revision(),
            "document host leaked active state across workspaces");

    document_host_chrome_t chrome;
    require(host.compose(first_workspace, {{1600, 1000}, 96, 8}, chrome).ok(),
            "adapter failure chrome composition failed");
    require(!chrome.leaves.empty() &&
                std::all_of(chrome.leaves.begin(), chrome.leaves.end(), [](const auto& leaf) {
                    return leaf.presentation.kind == document_host_presentation_kind_t::error &&
                        leaf.presentation.retryable;
                }),
            "presentation adapter failure was not isolated to a recoverable error state");

    document_host_chrome_t invalid;
    require(host.compose(first_workspace, {{1600, 1000}, 0, 8}, invalid).code ==
                workbench_error_code_t::invalid_layout,
            "invalid DPI was accepted");
}

}

bool run_document_host_harness(std::string& failure)
{
    try {
        verify_desktop_chrome_and_presentation();
        verify_compact_and_constrained_layouts();
        verify_dispatch_and_keyboard_routing();
        verify_toolbar_dispatch_mapping_and_revisions();
        verify_workspace_isolation_and_adapter_failure();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(exception.what());
        failure = exception.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    if (!aida::workbench::document_host::c03_test::run_document_host_harness(failure)) {
        std::cerr << "document_host_harness failed: " << failure << '\n';
        return 1;
    }
    std::cout << "document_host_harness source contract satisfied\n";
    return 0;
}
