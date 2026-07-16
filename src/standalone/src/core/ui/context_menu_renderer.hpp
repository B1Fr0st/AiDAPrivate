#pragma once

#include "context_menu_contract.hpp"

#include <string>

namespace aida::ui {

struct context_menu_render_result_t {
    bool open = false;
    bool executed = false;
    stable_action_id_t action;
    action_execution_result_t execution;
};

context_menu_render_result_t render_context_menu_popup(
    const char* popup_id,
    const context_menu_presenter_t& presenter,
    const context_menu_open_request_t& request,
    const interaction_context_t& context);

}
