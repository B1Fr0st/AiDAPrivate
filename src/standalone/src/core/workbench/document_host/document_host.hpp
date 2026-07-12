#pragma once

#include "document_host_contracts.hpp"
#include "../workbench_model.h"

namespace aida::workbench::document_host {

enum class document_host_key_t : std::uint8_t {
    tab = 0,
    w = 1,
    left = 2,
    right = 3,
    f6 = 4
};

enum class document_host_dispatch_kind_t : std::uint8_t {
    open_document = 0,
    select_document = 1,
    close_document = 2,
    focus_view = 3,
    split_horizontal = 4,
    split_vertical = 5,
    history_back = 6,
    history_forward = 7,
    navigate = 8,
    toolbar = 9,
    keyboard = 10
};

struct document_host_key_event_t {
    document_host_key_t key = document_host_key_t::tab;
    bool control = false;
    bool alt = false;
    bool shift = false;
};

struct document_host_dispatch_t {
    document_host_dispatch_kind_t kind = document_host_dispatch_kind_t::focus_view;
    workspace_id_t workspace;
    workspace_revision_t expected_revision;
    document_id_t document;
    document_identity_t document_identity;
    view_id_t view;
    split_orientation_t orientation = split_orientation_t::horizontal;
    std::uint16_t ratio_basis_points = k_split_ratio_default_basis_points;
    navigation_event_t navigation;
    document_host_toolbar_action_t toolbar_action = document_host_toolbar_action_t::next_view;
    document_host_key_event_t key;
    bool request_focus = true;
};

struct document_host_services_t {
    const document_catalog_adapter_t* documents = nullptr;
    const navigation_adapter_t* navigation = nullptr;
    const document_host_state_adapter_t* state = nullptr;
};

class document_host_t {
public:
    document_host_t(workbench_model_t& model, document_host_services_t services = {});

    workbench_error_t compose(workspace_id_t workspace,
                              const document_host_layout_request_t& request,
                              document_host_chrome_t& output) const;
    workbench_command_result_t dispatch(const document_host_dispatch_t& input);

private:
    workbench_model_t& model_;
    document_host_services_t services_;
};

}
