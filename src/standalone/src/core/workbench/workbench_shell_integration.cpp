#include "workbench_shell_integration.hpp"

#include "workbench_persistence.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace aida {
namespace workbench {
namespace {

struct workspace_integration_state_t final {
    workspace_id_t workspace;
    workbench_shell_center_view_t center_view;
    std::unique_ptr<navigator::navigator_tree_model_t> navigator_tree;
    std::unique_ptr<navigator::navigator_query_model_t> navigator_query;
    std::unique_ptr<navigator::navigator_navigation_model_t> navigator_nav;
    std::unique_ptr<document_host::document_host_t> document_host;
    std::unique_ptr<inspector::inspector_query_session_t> inspector_session;
    std::unique_ptr<document_registry_t> document_registry;
    const navigator::navigator_packed_store_adapter_t* navigator_adapter = nullptr;
    const document_host::document_host_services_t* host_services = nullptr;
    std::optional<inspector::inspector_context_t> inspector_context;
};

struct integration_state_t final {
    workbench_model_t* model = nullptr;
    workbench_shell_integration_config_t config;
    mutable std::mutex metrics_mutex;
    workbench_shell_metrics_t metrics;
    mutable std::mutex workspaces_mutex;
    std::unordered_map<std::uint64_t, workspace_integration_state_t> workspace_states;
    std::atomic<std::uint64_t> next_workspace_ordinal{1};

    explicit integration_state_t(workbench_model_t& mdl,
                                 workbench_shell_integration_config_t cfg)
        : model(&mdl), config(std::move(cfg)) {}
};

workbench_persistence_dto_t build_default_persistence(
    workspace_id_t workspace,
    const fixed_layout_constraints_t& layout,
    std::uint32_t history_capacity) {
    workbench_persistence_dto_t dto;
    dto.schema_version = k_workbench_contract_schema_version;
    dto.workspace = workspace;
    dto.revision = workspace_revision_t{1};
    dto.layout = layout;
    dto.split_tree.root = split_node_id_t{1};
    split_node_dto_t root_node;
    root_node.id = split_node_id_t{1};
    root_node.kind = split_node_kind_t::leaf;
    root_node.view = view_id_t{1};
    dto.split_tree.nodes.push_back(std::move(root_node));
    dto.active_document = document_id_t{1};
    dto.history.workspace = workspace;
    dto.history.capacity = std::min(history_capacity, k_max_history_capacity);
    document_persistence_dto_t default_doc;
    default_doc.id = document_id_t{1};
    default_doc.identity.workspace = workspace;
    default_doc.identity.kind = document_kind_t::disassembly;
    default_doc.title = "Disassembly";
    default_doc.closeable = true;
    dto.documents.push_back(std::move(default_doc));
    view_persistence_dto_t default_view;
    default_view.id = view_id_t{1};
    default_view.workspace = workspace;
    default_view.document = document_id_t{1};
    default_view.role = view_role_t::primary;
    default_view.focused = true;
    dto.views.push_back(std::move(default_view));
    panel_state_dto_t navigator_panel;
    navigator_panel.id = panel_instance_id_t{1};
    navigator_panel.workspace = workspace;
    navigator_panel.kind = panel_kind_t::navigator;
    navigator_panel.visible = true;
    navigator_panel.extent_pixels = layout.navigator_pixels;
    navigator_panel.revision = workspace_revision_t{1};
    dto.panels.push_back(std::move(navigator_panel));
    panel_state_dto_t inspector_panel;
    inspector_panel.id = panel_instance_id_t{2};
    inspector_panel.workspace = workspace;
    inspector_panel.kind = panel_kind_t::inspector;
    inspector_panel.visible = true;
    inspector_panel.extent_pixels = layout.inspector_pixels;
    inspector_panel.revision = workspace_revision_t{1};
    dto.panels.push_back(std::move(inspector_panel));
    return dto;
}

}

struct workbench_shell_integration_t::impl_t {
    integration_state_t state;

    explicit impl_t(workbench_model_t& mdl,
                    workbench_shell_integration_config_t cfg)
        : state(mdl, std::move(cfg)) {}

    void increment_metric(
        std::uint64_t workbench_shell_metrics_t::*field,
        std::uint64_t delta = 1) noexcept {
        std::lock_guard<std::mutex> lock(state.metrics_mutex);
        state.metrics.*field += delta;
    }

    workspace_integration_state_t* get_state(workspace_id_t workspace) {
        std::lock_guard<std::mutex> lock(state.workspaces_mutex);
        auto it = state.workspace_states.find(workspace.value);
        return it != state.workspace_states.end() ? &it->second : nullptr;
    }

    workspace_integration_state_t& ensure_state(workspace_id_t workspace) {
        std::lock_guard<std::mutex> lock(state.workspaces_mutex);
        auto it = state.workspace_states.find(workspace.value);
        if (it != state.workspace_states.end())
            return it->second;
        auto& inserted = state.workspace_states[workspace.value];
        inserted.workspace = workspace;
        inserted.center_view.workspace = workspace;
        inserted.center_view.default_document_kind = document_kind_t::disassembly;
        inserted.center_view.is_default = false;
        inserted.center_view.navigator_visible = true;
        inserted.center_view.inspector_visible = true;
        inserted.center_view.bottom_panel_visible = false;
        return inserted;
    }
};

workbench_shell_integration_t::workbench_shell_integration_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)),
      config_(impl_ ? impl_->state.config : workbench_shell_integration_config_t{}) {}

workbench_shell_integration_t::~workbench_shell_integration_t() = default;

std::shared_ptr<workbench_shell_integration_t>
workbench_shell_integration_t::create(
    workbench_model_t& model,
    workbench_shell_integration_config_t config) {
    auto impl = std::make_unique<impl_t>(model, config);
    return std::shared_ptr<workbench_shell_integration_t>(
        new workbench_shell_integration_t(std::move(impl)));
}

workbench_error_t
workbench_shell_integration_t::append_center_view(
    workspace_id_t workspace,
    const workbench_shell_center_view_t& center_view,
    workbench_snapshot_ptr_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    auto& ws_state = impl_->ensure_state(workspace);
    ws_state.center_view = center_view;
    ws_state.center_view.workspace = workspace;
    impl_->increment_metric(&workbench_shell_metrics_t::center_views_appended);
    auto snapshot_result = impl_->state.model->snapshot(workspace, output);
    if (!snapshot_result.ok())
        return snapshot_result;
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::make_default_for_analysis(
    workspace_id_t workspace,
    workbench_snapshot_ptr_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.make_default_for_analysis_workspaces)
        return workbench_error_t{};
    auto& ws_state = impl_->ensure_state(workspace);
    ws_state.center_view.is_default = true;
    ws_state.center_view.default_document_kind = document_kind_t::disassembly;
    ws_state.center_view.navigator_visible = true;
    ws_state.center_view.inspector_visible = true;
    if (!ws_state.document_registry) {
        ws_state.document_registry = std::make_unique<document_registry_t>(workspace);
    }
    impl_->increment_metric(&workbench_shell_metrics_t::workspaces_created);
    auto snapshot_result = impl_->state.model->snapshot(workspace, output);
    if (!snapshot_result.ok())
        return snapshot_result;
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::restore_workspace_context(
    workspace_id_t workspace,
    workspace_revision_t expected_revision,
    const workbench_persistence_dto_t& persisted,
    const document_catalog_adapter_t& catalog,
    missing_document_policy_t policy,
    workbench_shell_workspace_context_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.restore_per_workspace_context)
        return workbench_error_t{};
    auto restore_result = impl_->state.model->restore_workspace(
        workspace, expected_revision, persisted, catalog, policy);
    if (!restore_result.error.ok()) {
        impl_->increment_metric(&workbench_shell_metrics_t::context_restore_failures);
        return restore_result.error;
    }
    auto& ws_state = impl_->ensure_state(workspace);
    if (!ws_state.document_registry) {
        ws_state.document_registry = std::make_unique<document_registry_t>(workspace);
    }
    auto doc_restore = ws_state.document_registry->restore(persisted.documents);
    if (!doc_restore.ok()) {
        impl_->increment_metric(&workbench_shell_metrics_t::context_restore_failures);
        return doc_restore;
    }
    output.workspace = workspace;
    output.persistence = persisted;
    output.document_registry = ws_state.document_registry.get();
    output.center_view = ws_state.center_view;
    if (impl_->state.config.integrate_navigator && ws_state.navigator_tree)
        output.navigator_tree = ws_state.navigator_tree.get();
    if (impl_->state.config.integrate_document_host && ws_state.document_host)
        output.document_host = ws_state.document_host.get();
    if (impl_->state.config.integrate_inspector && ws_state.inspector_session)
        output.inspector_session = ws_state.inspector_session.get();
    impl_->increment_metric(&workbench_shell_metrics_t::workspaces_restored);
    impl_->increment_metric(&workbench_shell_metrics_t::context_restores);
    if (impl_->state.config.preserve_commands)
        impl_->increment_metric(&workbench_shell_metrics_t::commands_preserved);
    if (impl_->state.config.preserve_shortcuts)
        impl_->increment_metric(&workbench_shell_metrics_t::shortcuts_preserved);
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::integrate_navigator(
    workspace_id_t workspace,
    const navigator::navigator_packed_store_adapter_t& adapter) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.integrate_navigator)
        return workbench_error_t{};
    auto& ws_state = impl_->ensure_state(workspace);
    ws_state.navigator_adapter = &adapter;
    ws_state.navigator_tree = std::make_unique<navigator::navigator_tree_model_t>(adapter);
    ws_state.navigator_query = std::make_unique<navigator::navigator_query_model_t>(adapter);
    ws_state.navigator_nav = std::make_unique<navigator::navigator_navigation_model_t>(
        adapter, workspace, navigation_event_id_t{1}, 1, true, nullptr);
    impl_->increment_metric(&workbench_shell_metrics_t::navigator_integrations);
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::integrate_document_host(
    workspace_id_t workspace,
    const document_host::document_host_services_t& services) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.integrate_document_host)
        return workbench_error_t{};
    auto& ws_state = impl_->ensure_state(workspace);
    ws_state.host_services = &services;
    ws_state.document_host = std::make_unique<document_host::document_host_t>(
        *impl_->state.model, services);
    impl_->increment_metric(&workbench_shell_metrics_t::document_host_integrations);
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::integrate_inspector(
    workspace_id_t workspace,
    const inspector::inspector_context_t& context) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!workspace.valid())
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (!impl_->state.config.integrate_inspector)
        return workbench_error_t{};
    auto& ws_state = impl_->ensure_state(workspace);
    ws_state.inspector_context = context;
    if (!ws_state.inspector_session)
        ws_state.inspector_session = std::make_unique<inspector::inspector_query_session_t>();
    auto activate = ws_state.inspector_session->activate(context);
    if (!activate.ok())
        return activate;
    impl_->increment_metric(&workbench_shell_metrics_t::inspector_integrations);
    return workbench_error_t{};
}

workbench_error_t
workbench_shell_integration_t::dispatch_command(
    const workbench_command_t& command,
    const workbench_services_t& services,
    workbench_command_result_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    if (impl_->state.config.preserve_all_center_views) {
        output = impl_->state.model->execute(command, services);
        return output.error;
    }
    output = impl_->state.model->execute(command, services);
    return output.error;
}

workbench_error_t
workbench_shell_integration_t::dispatch_host_command(
    const document_host::document_host_dispatch_t& dispatch,
    workbench_command_result_t& output) {
    if (!impl_)
        return workbench_error_t{workbench_error_code_t::invalid_workspace};
    auto* ws_state = impl_->get_state(dispatch.workspace);
    if (!ws_state || !ws_state->document_host) {
        return workbench_error_t{workbench_error_code_t::invalid_workspace,
            dispatch.workspace.value};
    }
    output = ws_state->document_host->dispatch(dispatch);
    return output.error;
}

std::vector<workspace_id_t>
workbench_shell_integration_t::managed_workspaces() const {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->state.workspaces_mutex);
    std::vector<workspace_id_t> result;
    result.reserve(impl_->state.workspace_states.size());
    for (const auto& [id, state] : impl_->state.workspace_states)
        result.push_back(state.workspace);
    return result;
}

bool
workbench_shell_integration_t::has_workspace_context(
    workspace_id_t workspace) const noexcept {
    if (!impl_)
        return false;
    std::lock_guard<std::mutex> lock(impl_->state.workspaces_mutex);
    return impl_->state.workspace_states.find(workspace.value) !=
        impl_->state.workspace_states.end();
}

const workbench_shell_workspace_context_t*
workbench_shell_integration_t::workspace_context(
    workspace_id_t workspace) const {
    if (!impl_)
        return nullptr;
    std::lock_guard<std::mutex> lock(impl_->state.workspaces_mutex);
    auto it = impl_->state.workspace_states.find(workspace.value);
    if (it == impl_->state.workspace_states.end())
        return nullptr;
    static thread_local workbench_shell_workspace_context_t context;
    context.workspace = it->second.workspace;
    context.center_view = it->second.center_view;
    context.navigator_tree = it->second.navigator_tree.get();
    context.navigator_query = it->second.navigator_query.get();
    context.navigator_nav = it->second.navigator_nav.get();
    context.document_host = it->second.document_host.get();
    context.inspector_session = it->second.inspector_session.get();
    context.document_registry = it->second.document_registry.get();
    return &context;
}

workbench_shell_metrics_t
workbench_shell_integration_t::metrics() const noexcept {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->state.metrics_mutex);
    return impl_->state.metrics;
}

workbench_persistence_dto_t
workbench_shell_integration_t::create_default_persistence(
    workspace_id_t workspace,
    const fixed_layout_constraints_t& layout,
    std::uint32_t history_capacity) {
    return build_default_persistence(workspace, layout, history_capacity);
}

}
}
