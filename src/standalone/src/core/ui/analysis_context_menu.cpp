#include "analysis_context_menu.hpp"

#include "context_menu_renderer.hpp"

#include "imgui/imgui.h"

#include <optional>
#include <utility>
#include <vector>

namespace aida::ui::analysis_context_menu {

namespace {

constexpr const char* k_context_type = "context.analysis.entity";
constexpr const char* k_popup = "##aida_analysis_context";

struct runtime_t {
    application_action_registry_t registry;
    context_menu_catalog_t menus;
    std::optional<context_t> context;
    interaction_context_t interaction;
    context_menu_open_request_t request;
    bool initialized = false;
};

runtime_t& runtime() {
    static runtime_t value;
    return value;
}

const context_t* payload(const interaction_context_t& context) {
    return context.payload.get<context_t>();
}

capability_state_t capability_for(const interaction_context_t& interaction,
                                  const std::string& action) {
    const auto* context = payload(interaction);
    if (!context)
        return capability_state_t::unavailable("Analysis context is unavailable");
    if (!context->live_generation || context->live_generation() != context->generation)
        return capability_state_t::unavailable("The analysis selection is stale; select the item again");
    const auto found = context->actions.find(action);
    if (found == context->actions.end())
        return capability_state_t::unavailable("This analysis provider does not support this action");
    if (!found->second.invoke)
        return capability_state_t::unavailable("This action has no active provider");
    return found->second.capability;
}

action_handler_result_t execute_for(const action_invocation_t& invocation,
                                    const std::string& action) {
    const auto* context = payload(invocation.context);
    if (!context)
        return action_handler_result_t::failed("Analysis context is unavailable");
    if (!context->live_generation || context->live_generation() != context->generation)
        return action_handler_result_t::failed("The analysis selection changed before the action ran");
    const auto found = context->actions.find(action);
    if (found == context->actions.end() || !found->second.invoke)
        return action_handler_result_t::failed("This analysis provider does not support this action");
    return found->second.invoke();
}

action_check_state_t checked_for(const interaction_context_t& interaction,
                                 const std::string& action) {
    const auto* context = payload(interaction);
    if (!context)
        return action_check_state_t::not_checkable;
    const auto found = context->actions.find(action);
    return found == context->actions.end()
        ? action_check_state_t::not_checkable
        : found->second.check_state;
}

void register_action(runtime_t& rt, const char* id, const char* label,
                     const char* description, bool undoable = false) {
    application_action_descriptor_t descriptor;
    descriptor.id = stable_action_id_t(id);
    descriptor.label = label;
    descriptor.description = description;
    descriptor.category = {"category.analysis", "Analysis"};
    descriptor.icon_semantic = "analysis";
    descriptor.surfaces = action_surface_t::context_menu;
    descriptor.accepted_contexts = {stable_context_type_id_t(k_context_type)};
    descriptor.capability = [action = std::string(id)](const interaction_context_t& context) {
        return capability_for(context, action);
    };
    descriptor.checked = [action = std::string(id)](const interaction_context_t& context) {
        return checked_for(context, action);
    };
    descriptor.invoke = [action = std::string(id)](const action_invocation_t& invocation) {
        return execute_for(invocation, action);
    };
    descriptor.undoable = undoable;
    static_cast<void>(rt.registry.register_action(std::move(descriptor)));
}

context_menu_action_t item(const char* id, int order) {
    context_menu_action_t result;
    result.action = stable_action_id_t(id);
    result.order = order;
    return result;
}

context_menu_section_t section(const char* id, const char* label,
                               context_menu_group_t group, int order,
                               std::vector<context_menu_action_t> actions) {
    context_menu_section_t result;
    result.id = stable_menu_section_id_t(id);
    result.label = label;
    result.group = group;
    result.order = order;
    result.actions = std::move(actions);
    return result;
}

void register_menu(runtime_t& rt, const char* id,
                   std::vector<context_menu_section_t> sections) {
    context_menu_descriptor_t descriptor;
    descriptor.id = stable_menu_id_t(id);
    descriptor.accepted_contexts = {stable_context_type_id_t(k_context_type)};
    descriptor.sections = std::move(sections);
    static_cast<void>(rt.menus.register_menu(std::move(descriptor), rt.registry));
}

void initialize(runtime_t& rt) {
    if (rt.initialized)
        return;
    rt.initialized = true;

    register_action(rt, "analysis.navigate.back", "Back", "Return to the previous analysis location");
    register_action(rt, "analysis.navigate.forward", "Forward", "Advance to the next analysis location");
    register_action(rt, "analysis.navigate.disassembly", "Open in Disassembly", "Navigate the selected entity in the disassembly document");
    register_action(rt, "analysis.navigate.disassembly_side", "Open Disassembly to the Side", "Open the selected entity in a second disassembly document");
    register_action(rt, "analysis.navigate.graph", "Open in Graph", "Open the selected function in graph representation");
    register_action(rt, "analysis.navigate.pseudocode", "Open in Pseudocode", "Open or decompile the selected function as pseudocode");
    register_action(rt, "analysis.navigate.follow", "Follow Target", "Follow the selected direct target");
    register_action(rt, "analysis.navigate.xrefs", "Cross References", "Show references for the selected entity");
    register_action(rt, "analysis.navigate.callers", "Show Callers", "Show functions that call the selected function");
    register_action(rt, "analysis.navigate.callees", "Show Callees", "Show functions called by the selected function");
    register_action(rt, "analysis.copy.line", "Copy Line", "Copy address and rendered text");
    register_action(rt, "analysis.copy.text", "Copy Text", "Copy rendered analysis text");
    register_action(rt, "analysis.copy.address", "Copy Address", "Copy the selected virtual address");
    register_action(rt, "analysis.copy.bytes", "Copy Bytes", "Copy rendered instruction bytes");
    register_action(rt, "analysis.copy.instruction", "Copy Instruction", "Copy instruction text without the address");
    register_action(rt, "analysis.copy.name", "Copy Name", "Copy the selected function or symbol name");
    register_action(rt, "analysis.copy.block", "Copy Block", "Copy all rendered instructions in the selected graph block");
    register_action(rt, "analysis.copy.block_addressed", "Copy Block with Addresses", "Copy graph block instructions with addresses");
    register_action(rt, "analysis.modify.rename", "Rename", "Rename the selected symbol", true);
    register_action(rt, "analysis.modify.retype", "Set Type", "Apply a type to the selected analysis entity", true);
    register_action(rt, "analysis.modify.comment", "Edit Comment", "Add or edit the selected entity comment", true);
    register_action(rt, "analysis.modify.bookmark", "Add Bookmark", "Bookmark the selected address", true);
    register_action(rt, "analysis.modify.remove_bookmark", "Remove Bookmark", "Remove the selected address bookmark", true);
    register_action(rt, "analysis.modify.patch", "Patch Bytes or Instruction...", "Open the reviewed patch workflow at the selected address", true);
    register_action(rt, "analysis.function.decompile", "Decompile Function", "Decompile the enclosing function");
    register_action(rt, "analysis.function.source", "Reconstruct Source", "Reconstruct source for the selected function");
    register_action(rt, "analysis.function.aob", "Generate AOB Signature", "Generate a signature from the selected instruction");
    register_action(rt, "analysis.graph.fit", "Fit Graph", "Fit all graph blocks in the canvas");
    register_action(rt, "analysis.graph.zoom_in", "Zoom In", "Increase graph canvas zoom");
    register_action(rt, "analysis.graph.zoom_out", "Zoom Out", "Decrease graph canvas zoom");
    register_action(rt, "analysis.graph.reset", "Reset View", "Reset graph pan and zoom");
    register_action(rt, "analysis.graph.select_block", "Select Entire Block", "Select all instructions in the graph block");
    register_action(rt, "analysis.graph.clear_selection", "Clear Selection", "Clear the graph text selection");
    register_action(rt, "analysis.view.va", "Virtual Address Format", "Display virtual addresses");
    register_action(rt, "analysis.view.rva", "Relative Address Format", "Display image-relative addresses");
    register_action(rt, "analysis.view.file_offset", "File Offset Format", "Display file offsets where available");
    register_action(rt, "analysis.view.bytes", "Show Bytes", "Show or hide instruction bytes");
    register_action(rt, "analysis.view.full_line", "Full-Line Selection", "Select the complete disassembly row");
    register_action(rt, "analysis.evidence.chat", "Send to AI Chat", "Attach the selected analysis evidence to AI chat");

    const auto navigation = section("section.analysis.navigate", "Navigate",
        context_menu_group_t::open_navigate, 0, {
            item("analysis.navigate.back", 0), item("analysis.navigate.forward", 1),
            item("analysis.navigate.disassembly", 2), item("analysis.navigate.disassembly_side", 3),
            item("analysis.navigate.follow", 4), item("analysis.navigate.graph", 5),
            item("analysis.navigate.pseudocode", 6)});
    const auto inspect = section("section.analysis.inspect", "References",
        context_menu_group_t::inspect_relate, 1, {
            item("analysis.navigate.xrefs", 0), item("analysis.navigate.callers", 1),
            item("analysis.navigate.callees", 2)});
    const auto copy_instruction = section("section.analysis.copy", "Copy",
        context_menu_group_t::copy_export, 2, {
            item("analysis.copy.line", 0), item("analysis.copy.text", 1),
            item("analysis.copy.address", 2), item("analysis.copy.bytes", 3),
            item("analysis.copy.instruction", 4), item("analysis.copy.name", 5)});
    const auto modify = section("section.analysis.modify", "Modify",
        context_menu_group_t::modify_run, 3, {
            item("analysis.modify.rename", 0), item("analysis.modify.retype", 1),
            item("analysis.modify.comment", 2), item("analysis.modify.bookmark", 3),
            item("analysis.modify.remove_bookmark", 4), item("analysis.modify.patch", 5)});
    const auto transform = section("section.analysis.transform", "Represent and Transform",
        context_menu_group_t::modify_run, 4, {
            item("analysis.function.decompile", 0), item("analysis.function.source", 1),
            item("analysis.function.aob", 2)});
    const auto ai = section("section.analysis.ai", "AI and Evidence",
        context_menu_group_t::ai_evidence, 5, {item("analysis.evidence.chat", 0)});

    const auto display = section("section.analysis.display", "Display",
        context_menu_group_t::open_navigate, 4, {
            item("analysis.view.va", 0), item("analysis.view.rva", 1),
            item("analysis.view.file_offset", 2), item("analysis.view.bytes", 3),
            item("analysis.view.full_line", 4)});

    register_menu(rt, "menu.analysis.instruction", {navigation, inspect, copy_instruction, modify, display, transform, ai});
    register_menu(rt, "menu.analysis.pseudocode", {navigation, inspect, copy_instruction, modify, ai});
    register_menu(rt, "menu.analysis.function", {navigation, inspect, copy_instruction, modify, transform, ai});
    register_menu(rt, "menu.analysis.xref", {navigation, copy_instruction, inspect, ai});
    register_menu(rt, "menu.analysis.graph", {
        navigation,
        section("section.graph.canvas", "Graph", context_menu_group_t::open_navigate, 1, {
            item("analysis.graph.fit", 0), item("analysis.graph.zoom_in", 1),
            item("analysis.graph.zoom_out", 2), item("analysis.graph.reset", 3),
            item("analysis.graph.select_block", 4), item("analysis.graph.clear_selection", 5)}),
        section("section.graph.copy", "Copy", context_menu_group_t::copy_export, 2, {
            item("analysis.copy.block", 0), item("analysis.copy.block_addressed", 1),
            item("analysis.copy.address", 2)}),
        modify, inspect, ai
    });
}

const char* menu_id(menu_kind_t kind) {
    switch (kind) {
    case menu_kind_t::instruction: return "menu.analysis.instruction";
    case menu_kind_t::pseudocode: return "menu.analysis.pseudocode";
    case menu_kind_t::graph: return "menu.analysis.graph";
    case menu_kind_t::function: return "menu.analysis.function";
    case menu_kind_t::xref: return "menu.analysis.xref";
    }
    return "menu.analysis.instruction";
}

}

void open(context_t context, context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    rt.context = std::move(context);
    rt.interaction = {};
    rt.interaction.active_view = stable_view_id_t("view.analysis");
    rt.interaction.focus_path.push_back({stable_scope_id_t("scope.analysis.entity"),
                                         focus_scope_kind_t::widget});
    rt.interaction.payload = typed_context_ref_t::from(
        stable_context_type_id_t(k_context_type), *rt.context);
    rt.interaction.generation = rt.context->generation;
    rt.request.menu = stable_menu_id_t(menu_id(rt.context->kind));
    rt.request.origin = origin;
    rt.request.context_generation = rt.context->generation;
    ImGui::OpenPopup(k_popup);
}

void render() {
    auto& rt = runtime();
    if (!rt.context)
        return;
    context_menu_presenter_t presenter(rt.menus, rt.registry);
    const auto result = render_context_menu_popup(
        k_popup, presenter, rt.request, rt.interaction);
    if (!result.open && !ImGui::IsPopupOpen(k_popup))
        rt.context.reset();
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
