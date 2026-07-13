#pragma once

#include "workbench_model.h"
#include "workbench_contracts.h"
#include "workbench_persistence.hpp"
#include "document_registry.h"
#include "split_tree.h"
#include "navigator/workbench_navigator.hpp"
#include "inspector/workbench_inspector_contracts.hpp"
#include "document_host/document_host.hpp"
#include "adapters/disasm_document.hpp"
#include "adapters/hex_document.hpp"
#include "adapters/pseudocode_document.hpp"
#include "adapters/graph_document.hpp"
#include "adapters/diff_document.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida {
namespace analysis {
class analysis_workspace_t;
}
}

namespace aida {
namespace workbench {

struct workbench_shell_integration_config_t {
    bool make_default_for_analysis_workspaces = true;
    bool restore_per_workspace_context = true;
    bool integrate_navigator = true;
    bool integrate_document_host = true;
    bool integrate_inspector = true;
    bool preserve_all_center_views = true;
    bool preserve_commands = true;
    bool preserve_shortcuts = true;
    bool integrate_analysis_documents = true;
    bool integrate_persistence = true;
    fixed_layout_constraints_t default_layout = {};
    std::uint32_t default_history_capacity = k_default_history_capacity;
    std::uint32_t retained_generation_limit = 4;
    std::uint32_t retained_overlay_revision_limit = 16;
    std::uint32_t cached_graph_scope_limit = 8;
    std::uint32_t cached_diff_scope_limit = 2;
    std::uint32_t materialized_diff_entry_limit = 1U << 18;
};

struct workbench_shell_metrics_t {
    std::uint64_t workspaces_created = 0;
    std::uint64_t workspaces_restored = 0;
    std::uint64_t center_views_appended = 0;
    std::uint64_t navigator_integrations = 0;
    std::uint64_t document_host_integrations = 0;
    std::uint64_t inspector_integrations = 0;
    std::uint64_t commands_preserved = 0;
    std::uint64_t shortcuts_preserved = 0;
    std::uint64_t context_restores = 0;
    std::uint64_t context_restore_failures = 0;
    std::uint64_t analysis_document_integrations = 0;
    std::uint64_t analysis_document_refreshes = 0;
    std::uint64_t navigation_dispatches = 0;
    std::uint64_t persistence_loads = 0;
    std::uint64_t persistence_stores = 0;
    std::uint64_t persistence_failures = 0;
};

struct workbench_shell_center_view_t {
    workspace_id_t workspace;
    document_kind_t default_document_kind = document_kind_t::disassembly;
    bool is_default = false;
    bool navigator_visible = true;
    bool inspector_visible = true;
    bool bottom_panel_visible = false;
};

struct workbench_shell_workspace_context_t {
    workspace_id_t workspace;
    workbench_persistence_dto_t persistence;
    std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace;
    navigator::navigator_tree_model_t* navigator_tree = nullptr;
    navigator::navigator_query_model_t* navigator_query = nullptr;
    navigator::navigator_navigation_model_t* navigator_nav = nullptr;
    document_host::document_host_t* document_host = nullptr;
    inspector::inspector_query_session_t* inspector_session = nullptr;
    document_registry_t* document_registry = nullptr;
    disasm_document::disasm_document_model_t* disassembly_document = nullptr;
    hex_document::hex_document_model_t* hex_document = nullptr;
    pseudocode_document::pseudocode_document_model_t* pseudocode_document = nullptr;
    graph_document::graph_document_model_t* graph_document = nullptr;
    diff_document::diff_document_model_t* diff_document = nullptr;
    const workbench_document_bridge_t* document_bridge = nullptr;
    std::uint64_t analysis_generation = 0;
    std::uint64_t overlay_revision = 0;
    workbench_shell_center_view_t center_view;
    std::shared_ptr<const void> lifetime;
};

class workbench_shell_integration_t final {
public:
    static std::shared_ptr<workbench_shell_integration_t>
        create(workbench_model_t& model,
               workbench_shell_integration_config_t config = {});

    ~workbench_shell_integration_t();
    workbench_shell_integration_t(const workbench_shell_integration_t&) = delete;
    workbench_shell_integration_t& operator=(const workbench_shell_integration_t&) = delete;

    workbench_error_t append_center_view(
        workspace_id_t workspace,
        const workbench_shell_center_view_t& center_view,
        workbench_snapshot_ptr_t& output);

    workbench_error_t make_default_for_analysis(
        workspace_id_t workspace,
        workbench_snapshot_ptr_t& output);

    workbench_error_t restore_workspace_context(
        workspace_id_t workspace,
        workspace_revision_t expected_revision,
        const workbench_persistence_dto_t& persisted,
        const document_catalog_adapter_t& catalog,
        missing_document_policy_t policy,
        workbench_shell_workspace_context_t& output);

    workbench_error_t integrate_navigator(
        workspace_id_t workspace,
        const navigator::navigator_packed_store_adapter_t& adapter);

    workbench_error_t integrate_document_host(
        workspace_id_t workspace,
        const document_host::document_host_services_t& services);

    workbench_error_t integrate_inspector(
        workspace_id_t workspace,
        const inspector::inspector_context_t& context);

    workbench_error_t integrate_analysis_workspace(
        workspace_id_t workspace,
        std::shared_ptr<analysis::analysis_workspace_t> analysis_workspace);

    workbench_error_t refresh_analysis_documents(workspace_id_t workspace);

    workbench_error_t restore_persisted_workspace_context(
        workspace_id_t workspace,
        workspace_revision_t expected_revision,
        missing_document_policy_t policy,
        workbench_shell_workspace_context_t& output);

    workbench_error_t store_workspace_context(
        workspace_id_t workspace,
        workspace_revision_t expected_revision);

    workbench_error_t dispatch_command(
        const workbench_command_t& command,
        const workbench_services_t& services,
        workbench_command_result_t& output);

    workbench_error_t dispatch_host_command(
        const document_host::document_host_dispatch_t& dispatch,
        workbench_command_result_t& output);

    workbench_error_t dispatch_navigation(
        workspace_id_t workspace,
        workspace_revision_t expected_revision,
        const navigation_event_t& navigation,
        workbench_command_result_t& output);

    std::vector<workspace_id_t> managed_workspaces() const;

    bool has_workspace_context(workspace_id_t workspace) const noexcept;

    const workbench_shell_workspace_context_t*
        workspace_context(workspace_id_t workspace) const;

    workbench_shell_metrics_t metrics() const noexcept;

    const workbench_shell_integration_config_t& config() const noexcept { return config_; }

    static workbench_persistence_dto_t
        create_default_persistence(workspace_id_t workspace,
                                   const fixed_layout_constraints_t& layout,
                                   std::uint32_t history_capacity);

private:
    struct impl_t;
    explicit workbench_shell_integration_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;
    workbench_shell_integration_config_t config_;
};

}
}
