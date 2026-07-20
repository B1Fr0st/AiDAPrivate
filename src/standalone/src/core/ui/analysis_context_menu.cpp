#include "analysis_context_menu.hpp"

#include "application_ui_runtime.hpp"

#include "imgui/imgui.h"

#include <utility>

namespace aida::ui::analysis_context_menu {

namespace {

constexpr const char* k_owner = "analysis.context";

const char* menu_id(menu_kind_t kind) {
    switch (kind) {
    case menu_kind_t::instruction: return "menu.analysis.instruction";
    case menu_kind_t::pseudocode: return "menu.analysis.pseudocode";
    case menu_kind_t::graph: return "menu.analysis.graph";
    case menu_kind_t::function: return "menu.analysis.function";
    case menu_kind_t::xref: return "menu.analysis.xref";
    case menu_kind_t::metadata: return "menu.analysis.metadata";
    }
    return "menu.analysis.instruction";
}

stable_view_id_t active_view(menu_kind_t kind) {
    switch (kind) {
    case menu_kind_t::instruction:
    case menu_kind_t::metadata:
        return stable_view_id_t("document.disassembly");
    case menu_kind_t::pseudocode:
        return stable_view_id_t("document.pseudocode");
    case menu_kind_t::graph:
        return stable_view_id_t("document.graph");
    case menu_kind_t::function:
        return stable_view_id_t("view.analysis.functions");
    case menu_kind_t::xref:
        return stable_view_id_t("view.analysis.references");
    }
    return stable_view_id_t("document.disassembly");
}

application_ui::retained_entity_context_t make_retained(context_t context) {
    application_ui::retained_entity_context_t retained;
    retained.owner_id = k_owner;
    retained.entity_id = context.entity_id.empty()
        ? std::string(menu_id(context.kind)) + ":" + std::to_string(context.generation)
        : std::move(context.entity_id);
    retained.entity_generation = context.generation;
    retained.active_view = active_view(context.kind);
    retained.menu = stable_menu_id_t(menu_id(context.kind));
    retained.validate_identity = [generation = context.generation,
                                  live_generation = std::move(context.live_generation),
                                  validate_identity = std::move(context.validate_identity)] {
        if (!live_generation)
            return capability_state_t::unavailable(
                "The analysis provider cannot validate the retained selection");
        if (live_generation() != generation)
            return capability_state_t::unavailable(
                "The analysis selection is stale; select the item again");
        if (validate_identity) {
            const auto identity = validate_identity();
            if (!identity.enabled)
                return identity;
        }
        return capability_state_t::available();
    };
    retained.actions.reserve(context.actions.size());
    for (auto& entry : context.actions) {
        application_ui::retained_entity_action_t action;
        action.action_id = std::move(entry.first);
        action.capability = std::move(entry.second.capability);
        action.invoke = std::move(entry.second.invoke);
        action.check_state = entry.second.check_state;
        retained.actions.push_back(std::move(action));
    }
    return retained;
}

}

void open(context_t context, context_menu_open_origin_t origin) {
    application_ui::open_retained_entity_context_menu(
        make_retained(std::move(context)), origin);
}

bool execute_shortcut(context_t context, const char* action_id) {
    const auto retained = make_retained(std::move(context));
    return application_ui::execute_retained_entity_action(action_id,
        action_invocation_source_t::shortcut, retained).executed();
}

void render() {
    application_ui::render_retained_entity_context_menu(k_owner);
}

bool keyboard_request(context_menu_open_origin_t& origin) {
    if (ImGui::IsKeyPressed(ImGuiKey_Menu, false)) {
        origin = context_menu_open_origin_t::menu_key;
        return true;
    }
    if (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)) {
        origin = context_menu_open_origin_t::shift_f10;
        return true;
    }
    return false;
}

}
