#pragma once

#include "context_menu_contract.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace aida::ui::analysis_context_menu {

enum class menu_kind_t : std::uint8_t {
    instruction,
    pseudocode,
    graph,
    function,
    xref,
    metadata
};

struct action_slot_t {
    capability_state_t capability = capability_state_t::available();
    std::function<action_handler_result_t()> invoke;
    action_check_state_t check_state = action_check_state_t::not_checkable;
};

struct context_t {
    menu_kind_t kind = menu_kind_t::instruction;
    std::string entity_id;
    std::uint64_t generation = 0;
    std::function<std::uint64_t()> live_generation;
    std::function<capability_state_t()> validate_identity;
    std::map<std::string, action_slot_t> actions;
};

void open(context_t context, context_menu_open_origin_t origin);
bool execute_shortcut(context_t context, const char* action_id);
void render();
bool keyboard_request(context_menu_open_origin_t& origin);

}
