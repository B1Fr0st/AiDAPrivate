#pragma once

#include "document_registry.h"
#include "split_tree.h"

#include <memory>
#include <string>
#include <vector>

namespace aida {
namespace workbench {

class workbench_workspace_snapshot_t final {
public:
    explicit workbench_workspace_snapshot_t(workbench_persistence_dto_t persistence);
    workspace_id_t workspace() const noexcept;
    workspace_revision_t revision() const noexcept;
    persistence_fingerprint_t fingerprint() const noexcept;
    const workbench_persistence_dto_t& persistence() const noexcept;
    view_id_t focused_view() const noexcept;

private:
    workbench_persistence_dto_t persistence_;
    persistence_fingerprint_t fingerprint_;
    view_id_t focused_view_;

};

using workbench_snapshot_ptr_t = std::shared_ptr<const workbench_workspace_snapshot_t>;

enum class workbench_command_kind_t : std::uint8_t {
    open_document = 0,
    close_document = 1,
    move_view = 2,
    split_view = 3,
    focus_view = 4,
    set_synchronization = 5,
    navigate = 6,
    history_back = 7,
    history_forward = 8
};

struct workbench_command_t {
    workbench_command_kind_t kind = workbench_command_kind_t::focus_view;
    workspace_id_t workspace;
    workspace_revision_t expected_revision;
    document_id_t document;
    document_identity_t document_identity;
    view_id_t view;
    view_id_t target_view;
    view_id_t requested_view;
    split_orientation_t orientation = split_orientation_t::horizontal;
    std::uint16_t ratio_basis_points = k_split_ratio_default_basis_points;
    std::uint64_t synchronization_group = 0;
    view_synchronization_policy_t synchronization_policy =
        view_synchronization_policy_t::independent;
    navigation_event_t navigation;
    bool request_focus = true;
};

struct workbench_services_t {
    const document_catalog_adapter_t* documents = nullptr;
    const navigation_adapter_t* navigation = nullptr;
};

struct workbench_command_result_t {
    workbench_error_t error;
    workbench_snapshot_ptr_t snapshot;
    document_id_t document;
    view_id_t view;
    split_insert_result_t split;
    navigation_event_id_t navigation;
    bool changed = false;
};

class workbench_model_t {
public:
    workbench_model_t();
    ~workbench_model_t();
    workbench_model_t(const workbench_model_t&) = delete;
    workbench_model_t& operator=(const workbench_model_t&) = delete;

    workbench_error_t create_workspace(const workbench_persistence_dto_t& initial,
                                       workbench_snapshot_ptr_t& output);
    workbench_error_t snapshot(workspace_id_t workspace, workbench_snapshot_ptr_t& output) const;
    std::vector<workspace_id_t> workspace_ids() const;
    workbench_command_result_t execute(const workbench_command_t& command,
                                       const workbench_services_t& services = {});
    workbench_command_result_t restore_workspace(workspace_id_t workspace,
                                                 workspace_revision_t expected_revision,
                                                 const workbench_persistence_dto_t& persisted,
                                                 const document_catalog_adapter_t& catalog,
                                                 missing_document_policy_t policy);
    workbench_command_result_t restore_workspace(workspace_id_t workspace,
                                                 workspace_revision_t expected_revision,
                                                 const workbench_persistence_adapter_t& persistence,
                                                 const document_catalog_adapter_t& catalog,
                                                 missing_document_policy_t policy);

private:
    struct implementation_t;
    std::unique_ptr<implementation_t> implementation_;
};

}
}
