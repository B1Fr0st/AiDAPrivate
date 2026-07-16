#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "explorer_views.hpp"
#include "output_views.hpp"
#include "task_center.hpp"
#include "workbench_registry_views.hpp"

#include "../../helpers/globals.h"
#include "../settings/standalone_settings.hpp"
#include "../ai/settings_overlay.hpp"
#include "../ai/agent_manager_view.hpp"
#include "../ai/skill_manager_view.hpp"
#include "../ai/provider_view.hpp"
#include "../ai/standalone_chat.hpp"
#include "../mcp/mcp_marketplace_view.hpp"
#include "../analysis/analysis_hub_view.hpp"
#include "../analysis/binary_map_view.hpp"
#include "../analysis/functions_panel.hpp"
#include "../analysis/types_hub_view.hpp"
#include "../analysis/xref_db_view.hpp"
#include "../debugger/debugger_view.hpp"
#include "../disasm/cfg_view.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../editor/code_editor.hpp"
#include "../editor/hex_view.hpp"
#include "../editor/image_view.hpp"
#include "../network/network_view.hpp"
#include "../scanner/scan_hub_view.hpp"
#include "imgui/imgui.h"
#include "../../preview/studio_semantics.hpp"

#include <algorithm>
#include <cfloat>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <set>
#include <vector>

namespace aida::ui::application_views {
namespace {

enum class legacy_owner_t : std::uint8_t {
    registry,
    unsupported,
    shell
};

enum class legacy_subview_t : std::uint8_t {
    none,
    scan,
    types,
    analysis,
    debugger,
    network
};

struct catalog_entry_t {
    const char* id;
    const char* label;
    view_category_t category;
    view_presentation_role_t role;
    legacy_owner_t owner;
    int legacy_value;
    legacy_subview_t subview;
    int subview_value;
    float minimum_width;
    float minimum_height;
    bool default_open;
    bool closeable;
    bool requires_workspace;
};

#define AIDA_VIEW(ID, LABEL, CATEGORY, ROLE, OWNER, VALUE, SUBVIEW, SUBVALUE, WIDTH, HEIGHT, OPEN, CLOSE, WORKSPACE) \
    {ID, LABEL, view_category_t::CATEGORY, view_presentation_role_t::ROLE, legacy_owner_t::OWNER, VALUE, legacy_subview_t::SUBVIEW, SUBVALUE, WIDTH, HEIGHT, OPEN, CLOSE, WORKSPACE}

constexpr catalog_entry_t k_catalog[] = {
    AIDA_VIEW("view.project_explorer", "Project Explorer", explorer, tool_window, registry, 0, none, 0, 240, 220, true, true, false),
    AIDA_VIEW("view.workspace_search", "Workspace Search", explorer, tool_window, registry, 1, none, 0, 280, 220, false, true, false),
    AIDA_VIEW("view.recent", "Recent", explorer, tool_window, registry, 2, none, 0, 240, 180, false, true, false),
    AIDA_VIEW("view.sessions", "Sessions", shell, shell_surface, shell, 0, none, 0, 320, 90, true, false, false),
    AIDA_VIEW("view.navigator", "Navigator", analysis, tool_window, registry, 0, none, 0, 260, 220, false, true, true),
    AIDA_VIEW("view.inspector", "Inspector", analysis, inspector, registry, 0, none, 0, 300, 220, false, true, true),
    AIDA_VIEW("view.ai_chat", "AI Chat", automation, tool_window, registry, 0, none, 0, 420, 300, true, true, false),
    AIDA_VIEW("view.output", "Output", output, bottom_panel, registry, 0, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.mcp_log", "MCP Log", output, bottom_panel, registry, 1, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.driver_log", "Driver Log", output, bottom_panel, registry, 2, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.sandbox_log", "Sandbox Log", output, bottom_panel, registry, 3, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.terminal", "Terminal", programming, bottom_panel, registry, 4, none, 0, 420, 180, false, true, false),
    AIDA_VIEW("document.code", "Code Editor", programming, document, registry, static_cast<int>(center_view_t::code_editor), none, 0, 420, 260, false, true, false),
    AIDA_VIEW("document.disassembly", "Disassembly", document, document, registry, static_cast<int>(center_view_t::disassembly), none, 0, 480, 280, false, true, true),
    AIDA_VIEW("document.hex", "Hex", document, document, registry, static_cast<int>(center_view_t::hex_view), none, 0, 420, 240, false, true, true),
    AIDA_VIEW("document.pseudocode", "Pseudocode", document, document, registry, static_cast<int>(center_view_t::pseudocode), none, 0, 480, 280, false, true, true),
    AIDA_VIEW("document.graph", "Graph", document, document, registry, static_cast<int>(center_view_t::graph_view), none, 0, 480, 300, false, true, true),
    AIDA_VIEW("document.image", "Image", document, document, registry, static_cast<int>(center_view_t::image_view), none, 0, 360, 260, false, true, false),
    AIDA_VIEW("document.diff", "Diff", document, document, registry, static_cast<int>(center_view_t::snapshot_diff), none, 0, 520, 280, false, true, true),
    AIDA_VIEW("view.analysis_overview", "Analysis Overview", analysis, tool_window, unsupported, 0, none, 0, 420, 260, false, true, true),
    AIDA_VIEW("view.analysis.binary_map", "Binary Map", analysis, document, registry, static_cast<int>(center_view_t::binary_map), none, 0, 520, 300, false, true, true),
    AIDA_VIEW("view.analysis.functions", "Functions", analysis, tool_window, registry, static_cast<int>(center_view_t::functions_panel), none, 0, 300, 260, false, true, true),
    AIDA_VIEW("view.analysis.references", "Cross References", analysis, tool_window, registry, static_cast<int>(center_view_t::xref_database), none, 0, 360, 240, false, true, true),
    AIDA_VIEW("view.analysis.code_patcher_legacy", "Code Patcher", analysis, tool_window, unsupported, 0, none, 0, 440, 280, false, true, false),
    AIDA_VIEW("view.analysis.symbolic", "Symbolic Execution", analysis, tool_window, registry, static_cast<int>(center_view_t::analysis_hub), analysis, 0, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.taint", "Taint Analysis", analysis, tool_window, registry, static_cast<int>(center_view_t::analysis_hub), analysis, 1, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.deobfuscation", "Deobfuscation", analysis, tool_window, registry, static_cast<int>(center_view_t::analysis_hub), analysis, 2, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.fuzzer", "Analysis Fuzzer", analysis, tool_window, registry, static_cast<int>(center_view_t::analysis_hub), analysis, 3, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.protection", "Protection Analysis", analysis, tool_window, registry, static_cast<int>(center_view_t::analysis_hub), analysis, 4, 440, 280, false, true, true),
    AIDA_VIEW("view.memory_overview", "Memory Overview", memory, tool_window, unsupported, 0, none, 0, 420, 260, false, true, false),
    AIDA_VIEW("view.memory.value_scan", "Value Scan", memory, tool_window, registry, static_cast<int>(center_view_t::scan_hub), scan, 0, 480, 280, false, true, false),
    AIDA_VIEW("view.memory.crypto", "Crypto Scanner", memory, tool_window, registry, static_cast<int>(center_view_t::scan_hub), scan, 1, 440, 260, false, true, false),
    AIDA_VIEW("view.memory.aob", "AOB Generator", memory, tool_window, registry, static_cast<int>(center_view_t::scan_hub), scan, 2, 440, 260, false, true, true),
    AIDA_VIEW("view.memory.decrypt", "Decrypt Oracle", memory, tool_window, registry, static_cast<int>(center_view_t::scan_hub), scan, 3, 440, 260, false, true, false),
    AIDA_VIEW("view.memory.pointers", "Pointer Scanner", memory, tool_window, registry, static_cast<int>(center_view_t::scan_hub), scan, 4, 480, 280, false, true, false),
    AIDA_VIEW("view.memory.snapshots", "Snapshot Diff", memory, tool_window, registry, static_cast<int>(center_view_t::scan_hub), scan, 5, 480, 280, false, true, false),
    AIDA_VIEW("view.memory.integrity", "Integrity Hunter", memory, tool_window, registry, static_cast<int>(center_view_t::scan_hub), scan, 6, 480, 280, false, true, false),
    AIDA_VIEW("view.types_overview", "Types Overview", types, tool_window, unsupported, 0, none, 0, 420, 260, false, true, true),
    AIDA_VIEW("view.types.structures", "Structures", types, tool_window, registry, static_cast<int>(center_view_t::types_hub), types, 0, 460, 280, false, true, true),
    AIDA_VIEW("view.types.unions", "Unions", types, tool_window, registry, static_cast<int>(center_view_t::types_hub), types, 1, 420, 260, false, true, true),
    AIDA_VIEW("view.types.enums", "Enums", types, tool_window, registry, static_cast<int>(center_view_t::types_hub), types, 2, 420, 260, false, true, true),
    AIDA_VIEW("view.types.typedefs", "Typedefs", types, tool_window, registry, static_cast<int>(center_view_t::types_hub), types, 3, 420, 260, false, true, true),
    AIDA_VIEW("view.types.functions", "Function Types", types, tool_window, registry, static_cast<int>(center_view_t::types_hub), types, 4, 440, 260, false, true, true),
    AIDA_VIEW("view.types.inferred", "Inferred Types", types, tool_window, registry, static_cast<int>(center_view_t::types_hub), types, 5, 440, 260, false, true, true),
    AIDA_VIEW("view.types.dissector", "Structure Dissector", types, tool_window, registry, static_cast<int>(center_view_t::types_hub), types, 6, 480, 280, false, true, false),
    AIDA_VIEW("view.types.struct_recon", "Structure Reconstruction", types, document, registry, static_cast<int>(center_view_t::struct_recon), none, 0, 520, 300, false, true, false),
#define AIDA_DEBUG_VIEW(ID, LABEL, INDEX) AIDA_VIEW(ID, LABEL, debugger, tool_window, registry, static_cast<int>(center_view_t::debugger_view), debugger, INDEX, 420, 240, false, true, false)
    AIDA_DEBUG_VIEW("view.debug.cpu", "CPU", 0), AIDA_DEBUG_VIEW("view.debug.breakpoints", "Breakpoints", 1),
    AIDA_DEBUG_VIEW("view.debug.memory_map", "Memory Map", 2), AIDA_DEBUG_VIEW("view.debug.call_stack", "Call Stack", 3),
    AIDA_DEBUG_VIEW("view.debug.threads", "Threads", 4), AIDA_DEBUG_VIEW("view.debug.watches", "Watches", 5),
    AIDA_DEBUG_VIEW("view.debug.handles", "Handles", 6), AIDA_DEBUG_VIEW("view.debug.trace", "Trace", 7),
    AIDA_DEBUG_VIEW("view.debug.strings", "Debugger Strings", 8), AIDA_DEBUG_VIEW("view.debug.bookmarks", "Bookmarks", 9),
    AIDA_DEBUG_VIEW("view.debug.modules", "Modules", 10), AIDA_DEBUG_VIEW("view.debug.patches", "Debugger Patches", 11),
    AIDA_DEBUG_VIEW("view.debug.seh", "SEH Chain", 12), AIDA_DEBUG_VIEW("view.debug.cfg", "Debugger CFG", 13),
#define AIDA_NETWORK_VIEW(ID, LABEL, INDEX) AIDA_VIEW(ID, LABEL, network, tool_window, registry, static_cast<int>(center_view_t::network_view), network, INDEX, 460, 260, false, true, false)
    AIDA_NETWORK_VIEW("view.network.connections", "Connections", 0), AIDA_NETWORK_VIEW("view.network.capture", "Capture", 1),
    AIDA_NETWORK_VIEW("view.network.intercept", "Intercept", 2), AIDA_NETWORK_VIEW("view.network.proxy", "Proxy", 3),
    AIDA_NETWORK_VIEW("view.network.dns", "DNS", 4), AIDA_NETWORK_VIEW("view.network.filters", "Filters", 5),
    AIDA_NETWORK_VIEW("view.network.bandwidth", "Bandwidth", 6), AIDA_NETWORK_VIEW("view.network.repeater", "Repeater", 7),
    AIDA_NETWORK_VIEW("view.network.keylog", "KeyLog", 8), AIDA_NETWORK_VIEW("view.network.pcap", "PCAP", 9),
    AIDA_NETWORK_VIEW("view.network.fuzzer", "Network Fuzzer", 10), AIDA_NETWORK_VIEW("view.network.offensive", "Offensive", 11),
    AIDA_NETWORK_VIEW("view.network.websocket", "WebSocket", 12), AIDA_NETWORK_VIEW("view.network.scripting", "Scripting", 13),
    AIDA_NETWORK_VIEW("view.network.decoder", "Decoder", 14), AIDA_NETWORK_VIEW("view.network.site_map", "Site Map", 15),
    AIDA_NETWORK_VIEW("view.network.scope", "Scope", 16), AIDA_NETWORK_VIEW("view.network.cookies", "Cookies", 17),
    AIDA_NETWORK_VIEW("view.network.scanner", "Scanner", 18), AIDA_NETWORK_VIEW("view.network.recon", "Recon", 19),
    AIDA_NETWORK_VIEW("view.network.intruder", "Intruder", 20), AIDA_NETWORK_VIEW("view.network.collaborator", "Collaborator", 21),
    AIDA_NETWORK_VIEW("view.network.sequencer", "Sequencer", 22), AIDA_NETWORK_VIEW("view.network.comparer", "Comparer", 23),
    AIDA_NETWORK_VIEW("view.network.jwt_lab", "JWT Lab", 24), AIDA_NETWORK_VIEW("view.network.match_replace", "Match and Replace", 25),
    AIDA_NETWORK_VIEW("view.network.session", "Session", 26), AIDA_NETWORK_VIEW("view.network.api", "API", 27),
    AIDA_NETWORK_VIEW("view.network.ws_editor", "WebSocket Editor", 28), AIDA_NETWORK_VIEW("view.network.h2_editor", "HTTP/2 Editor", 29),
    AIDA_NETWORK_VIEW("view.network.logger", "Logger", 30), AIDA_NETWORK_VIEW("view.network.csp", "CSP", 31),
    AIDA_NETWORK_VIEW("view.network.upstream", "Upstream Proxy", 32), AIDA_NETWORK_VIEW("view.network.browser", "Browser", 33),
    AIDA_NETWORK_VIEW("view.network.reports", "Reports", 34), AIDA_NETWORK_VIEW("view.network.headless", "Headless Browser", 35),
    AIDA_VIEW("view.ai.agents", "Agents", automation, tool_window, registry, 1, none, 0, 420, 280, false, true, false),
    AIDA_VIEW("view.ai.skills", "Skills", automation, tool_window, registry, 2, none, 0, 480, 300, false, true, false),
    AIDA_VIEW("view.ai.providers", "AI Providers", automation, tool_window, registry, 0, none, 0, 460, 300, false, true, false),
    AIDA_VIEW("view.ai.mcp_marketplace", "MCP Marketplace", automation, tool_window, registry, 0, none, 0, 600, 420, false, true, false),
    AIDA_VIEW("view.ai.mcp_activity", "MCP Activity", automation, tool_window, unsupported, 0, none, 0, 420, 180, false, true, false),
    AIDA_VIEW("view.ai.evidence", "Evidence Review", automation, tool_window, registry, 0, none, 0, 420, 280, false, true, false),
    AIDA_VIEW("view.settings", "Settings", settings, tool_window, registry, 0, none, 0, 520, 360, false, true, false)
};

#undef AIDA_NETWORK_VIEW
#undef AIDA_DEBUG_VIEW
#undef AIDA_VIEW

struct state_t {
    view_registry_t registry;
    interaction_context_t context;
    bool initialized = false;
};

state_t& state() {
    static state_t value;
    return value;
}

const catalog_entry_t* find_catalog(const stable_view_id_t& id) {
    for (const auto& entry : k_catalog) {
        if (id.value() == entry.id)
            return &entry;
    }
    return nullptr;
}

view_instance_id_t instance_for(const catalog_entry_t& entry) {
    const bool document = std::strncmp(entry.id, "document.", 9) == 0;
    if (std::strcmp(entry.id, "document.code") == 0)
        return {stable_view_id_t(entry.id), stable_view_instance_key_t("group.0")};
    return {stable_view_id_t(entry.id), document
        ? stable_view_instance_key_t("primary")
        : stable_view_instance_key_t{}};
}

bool parse_code_group(const stable_view_instance_key_t& key, std::uint32_t& output) {
    constexpr const char* prefix = "group.";
    if (key.value().compare(0, std::strlen(prefix), prefix) != 0)
        return false;
    const char* first = key.value().c_str() + std::strlen(prefix);
    if (*first == '\0')
        return false;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(first, &end, 10);
    if (!end || *end != '\0' ||
        parsed > (std::numeric_limits<std::uint32_t>::max)())
        return false;
    output = static_cast<std::uint32_t>(parsed);
    return true;
}

view_instance_id_t active_code_instance() {
    file_tabs::normalize_document_identities();
    std::uint32_t group = 0;
    if (file_tabs::is_valid_tab_index(file_tabs::active_tab))
        group = file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)].group_id;
    return {stable_view_id_t("document.code"),
        stable_view_instance_key_t(file_tabs::group_instance_key(group))};
}

std::string code_group_label(std::uint32_t group) {
    const int index = file_tabs::active_in_group(group);
    std::string label = index >= 0
        ? file_tabs::tabs[file_tabs::tab_index(index)].filename
        : std::string("Code Editor");
    if (label.empty())
        label = "Untitled";
    if (group != 0)
        label.append(" — Group ").append(std::to_string(group + 1));
    return label;
}

void request_code_tab_close(int index) {
    if (!file_tabs::is_valid_tab_index(index))
        return;
    if (file_tabs::tabs[file_tabs::tab_index(index)].dirty) {
        file_tabs::pending_close_idx = index;
        file_tabs::show_close_confirm = true;
        return;
    }
    file_tabs::close_tab(index);
}

void close_code_group(const view_instance_id_t& instance) {
    std::uint32_t group = 0;
    if (!parse_code_group(instance.instance, group))
        return;
    for (const auto& tab : file_tabs::tabs) {
        if (tab.group_id == group && tab.pinned)
            return;
        if (tab.group_id == group && tab.dirty) {
            const int index = file_tabs::find_document(tab.document_id);
            if (index >= 0) {
                file_tabs::pending_close_idx = index;
                file_tabs::show_close_confirm = true;
            }
            return;
        }
    }
    for (int index = static_cast<int>(file_tabs::tabs.size()) - 1; index >= 0; --index)
        if (file_tabs::tabs[file_tabs::tab_index(index)].group_id == group)
            file_tabs::close_tab(index);
}

void render_code_group(const view_render_context_t& context) {
    std::uint32_t group = 0;
    if (!parse_code_group(context.instance.instance, group)) {
        ImGui::TextUnformatted("This code document group has an invalid identity.");
        return;
    }
    file_tabs::normalize_document_identities();
    int selected = file_tabs::active_in_group(group);
    if (!file_tabs::is_valid_tab_index(selected)) {
        ImGui::TextUnformatted("This code document group is empty.");
        return;
    }

    int close_index = -1;
    if (ImGui::BeginTabBar("##aida_code_group_tabs",
            ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_AutoSelectNewTabs |
            ImGuiTabBarFlags_FittingPolicyScroll)) {
        for (std::size_t raw_index = 0; raw_index < file_tabs::tabs.size(); ++raw_index) {
            auto& tab = file_tabs::tabs[raw_index];
            if (tab.group_id != group)
                continue;
            bool open = true;
            std::string tab_label = tab.filename.empty() ? "Untitled" : tab.filename;
            tab_label.append("###aida.code.document.").append(std::to_string(tab.document_id));
            ImGuiTabItemFlags flags = ImGuiTabItemFlags_None;
            if (tab.dirty)
                flags |= ImGuiTabItemFlags_UnsavedDocument;
            if (static_cast<int>(raw_index) == selected)
                flags |= ImGuiTabItemFlags_SetSelected;
            if (ImGui::BeginTabItem(tab_label.c_str(), tab.pinned ? nullptr : &open, flags)) {
                if ((ImGui::IsItemActivated() ||
                     ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) &&
                    file_tabs::active_tab != static_cast<int>(raw_index)) {
                    file_tabs::switch_to(static_cast<int>(raw_index));
                }
                selected = static_cast<int>(raw_index);
                file_tabs::active_document_by_group[group] = tab.document_id;
                const bool menu_key_context = ImGui::IsItemFocused() &&
                    ImGui::IsKeyPressed(ImGuiKey_Menu, false);
                const bool shift_f10_context = ImGui::IsItemFocused() &&
                    ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right) ||
                    menu_key_context || shift_f10_context)
                    application_ui::open_editor_tab_context_menu(
                        static_cast<int>(raw_index), menu_key_context
                            ? context_menu_open_origin_t::menu_key
                            : shift_f10_context
                                ? context_menu_open_origin_t::shift_f10
                                : context_menu_open_origin_t::pointer);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                const std::string semantic_id = aida::preview::semantics::stable_id(
                    "aida.editor.tab", "document-" + std::to_string(tab.document_id));
                aida::preview::semantics::register_last_item(
                    semantic_id, "editor-document-tab");
#endif
                ImGui::EndTabItem();
            }
            if (!open)
                close_index = static_cast<int>(raw_index);
        }
        ImGui::EndTabBar();
    }

    application_ui::render_editor_tab_context_menu();
    if (close_index >= 0)
        request_code_tab_close(close_index);
    if (!file_tabs::is_valid_tab_index(selected))
        return;

    auto& selected_tab = file_tabs::tabs[file_tabs::tab_index(selected)];
    if (selected_tab.external_conflict) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.24f, 0.12f, 0.04f, 0.92f));
        if (ImGui::BeginChild("##aida_external_change", ImVec2(0.f, 48.f), true)) {
            ImGui::TextUnformatted("The file changed on disk. AiDA will not overwrite it without your decision.");
            ImGui::SameLine();
            ImGui::BeginDisabled(selected_tab.dirty);
            if (ImGui::SmallButton("Reload from Disk"))
                file_tabs::reload_external(selected);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const std::string reload_semantic_id = aida::preview::semantics::stable_id(
                "aida.editor.external", "reload-document-" + std::to_string(selected_tab.document_id));
            aida::preview::semantics::register_last_item(
                reload_semantic_id, "editor-conflict-action");
#endif
            ImGui::EndDisabled();
            if (selected_tab.dirty && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("Save your editor changes elsewhere or explicitly keep the editor version first");
            ImGui::SameLine();
            if (ImGui::SmallButton("Keep Editor Version"))
                file_tabs::keep_editor_version(selected);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const std::string keep_semantic_id = aida::preview::semantics::stable_id(
                "aida.editor.external", "keep-document-" + std::to_string(selected_tab.document_id));
            aida::preview::semantics::register_last_item(
                keep_semantic_id, "editor-conflict-action");
#endif
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("The next Save may overwrite the newer disk version");
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    if (file_tabs::active_tab == selected && code_editor::active) {
        code_editor_widget::document_pane_render_context_t render_context;
        render_context.accent_r = globals::ui::accent.x;
        render_context.accent_g = globals::ui::accent.y;
        render_context.accent_b = globals::ui::accent.z;
        code_editor_widget::render_document_pane(render_context);
        return;
    }

    auto& tab = file_tabs::tabs[file_tabs::tab_index(selected)];
    ImGui::TextDisabled("Read-only while another document group owns editor focus");
    ImGui::SameLine();
    if (ImGui::SmallButton("Activate Editor"))
        file_tabs::switch_to(selected);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::string activate_semantic_id = aida::preview::semantics::stable_id(
        "aida.editor", "activate-document-" + std::to_string(tab.document_id));
    aida::preview::semantics::register_last_item(
        activate_semantic_id, "editor-document-action");
#endif
    const ImVec2 available = ImGui::GetContentRegionAvail();
    const char* text = tab.buffer_loaded ? tab.buffer.c_str() : "Document content is loading.";
    ImGui::InputTextMultiline("##aida_code_inactive_preview", const_cast<char*>(text),
        tab.buffer_loaded ? tab.buffer.size() + 1 : std::strlen(text) + 1,
        available, ImGuiInputTextFlags_ReadOnly);
}

void synchronize_code_groups(state_t& current) {
    file_tabs::normalize_document_identities();
    std::set<std::uint32_t> groups;
    for (const auto& tab : file_tabs::tabs)
        groups.insert(tab.group_id);

    for (const std::uint32_t group : groups) {
        const view_instance_id_t instance{stable_view_id_t("document.code"),
            stable_view_instance_key_t(file_tabs::group_instance_key(group))};
        current.registry.open(instance, current.context, code_group_label(group));
    }

    std::vector<view_instance_id_t> retired;
    current.registry.for_each_instance(
        [&](const view_descriptor_t&, const view_instance_state_t& instance) {
            if (instance.id.view != stable_view_id_t("document.code"))
                return;
            std::uint32_t group = 0;
            if (!parse_code_group(instance.id.instance, group) || groups.find(group) == groups.end())
                retired.push_back(instance.id);
        });
    for (const auto& instance : retired) {
        if (current.registry.is_open(instance))
            current.registry.close(instance);
        current.registry.erase_closed_instance(instance);
    }
}

bool workspace_available() {
    return static_cast<bool>(disasm_view::capture_selected_workspace());
}

void select_subview(const catalog_entry_t& entry) {
    switch (entry.subview) {
    case legacy_subview_t::scan:
        scan_hub_view::set_sub_tab(static_cast<scan_hub_view::sub_tab_t>(entry.subview_value));
        break;
    case legacy_subview_t::types:
        types_hub_view::set_sub_tab(static_cast<types_hub_view::sub_tab_t>(entry.subview_value));
        break;
    case legacy_subview_t::analysis:
        analysis_hub_view::set_sub_tab(static_cast<analysis_hub_view::sub_tab_t>(entry.subview_value));
        break;
    case legacy_subview_t::debugger:
        debugger_view::g_ui.prev_tab = debugger_view::g_ui.active_tab;
        debugger_view::g_ui.active_tab = static_cast<debugger_view::sub_tab_t>(entry.subview_value);
        break;
    case legacy_subview_t::network:
        network_view::g_state.active_tab = static_cast<network_view::sub_tab_t>(entry.subview_value);
        break;
    case legacy_subview_t::none:
        break;
    }
}

bool open_catalog_view(state_t& current, const char* id) {
    const auto* entry = find_catalog(stable_view_id_t(id));
    if (!entry)
        return false;
    return current.registry.open_or_focus(instance_for(*entry), current.context).ok();
}

bool open_catalog_subview(state_t& current, legacy_subview_t subview,
                          int subview_value) {
    for (const auto& entry : k_catalog) {
        if (entry.subview == subview && entry.subview_value == subview_value)
            return current.registry.open_or_focus(instance_for(entry), current.context).ok();
    }
    return false;
}

bool translate_legacy_center(state_t& current, center_view_t view) {
    switch (view) {
    case center_view_t::disassembly:
        return open_catalog_view(current, "document.disassembly");
    case center_view_t::hex_view:
        return open_catalog_view(current, "document.hex");
    case center_view_t::pseudocode:
        return open_catalog_view(current, "document.pseudocode");
    case center_view_t::graph_view:
        return open_catalog_view(current, "document.graph");
    case center_view_t::image_view:
        return open_catalog_view(current, "document.image");
    case center_view_t::binary_map:
        return open_catalog_view(current, "view.analysis.binary_map");
    case center_view_t::functions_panel:
        return open_catalog_view(current, "view.analysis.functions");
    case center_view_t::xref_browser:
    case center_view_t::xref_database:
        return open_catalog_view(current, "view.analysis.references");
    case center_view_t::memory_scanner:
        return open_catalog_view(current, "view.memory.value_scan");
    case center_view_t::crypto_scanner:
        return open_catalog_view(current, "view.memory.crypto");
    case center_view_t::aob_generator:
        return open_catalog_view(current, "view.memory.aob");
    case center_view_t::decrypt_oracle:
        return open_catalog_view(current, "view.memory.decrypt");
    case center_view_t::pointer_scanner:
        return open_catalog_view(current, "view.memory.pointers");
    case center_view_t::snapshot_diff:
        return open_catalog_view(current, "view.memory.snapshots");
    case center_view_t::integrity_hunter:
        return open_catalog_view(current, "view.memory.integrity");
    case center_view_t::symbolic_view:
        return open_catalog_view(current, "view.analysis.symbolic");
    case center_view_t::taint_view:
        return open_catalog_view(current, "view.analysis.taint");
    case center_view_t::deobfuscation_view:
        return open_catalog_view(current, "view.analysis.deobfuscation");
    case center_view_t::fuzzer_view:
        return open_catalog_view(current, "view.analysis.fuzzer");
    case center_view_t::stealth_view:
        return open_catalog_view(current, "view.analysis.protection");
    case center_view_t::scan_hub:
        return open_catalog_subview(current, legacy_subview_t::scan,
            static_cast<int>(scan_hub_view::active_sub_tab()));
    case center_view_t::types_hub:
        return open_catalog_subview(current, legacy_subview_t::types,
            static_cast<int>(types_hub_view::active_sub_tab()));
    case center_view_t::analysis_hub:
        return open_catalog_subview(current, legacy_subview_t::analysis,
            static_cast<int>(analysis_hub_view::active_sub_tab()));
    case center_view_t::debugger_view:
        return open_catalog_subview(current, legacy_subview_t::debugger,
            static_cast<int>(debugger_view::g_ui.active_tab));
    case center_view_t::network_view:
        return open_catalog_subview(current, legacy_subview_t::network,
            static_cast<int>(network_view::g_state.active_tab));
    case center_view_t::struct_recon:
        return open_catalog_view(current, "view.types.struct_recon");
    default:
        return false;
    }
}

void activate(const catalog_entry_t& entry) {
    select_subview(entry);
    switch (entry.owner) {
    case legacy_owner_t::registry:
        if (entry.category == view_category_t::document ||
            entry.category == view_category_t::analysis ||
            entry.category == view_category_t::debugger ||
            entry.category == view_category_t::memory ||
            entry.category == view_category_t::types ||
            entry.category == view_category_t::network)
            globals::ui::active_center_view = center_view_t::welcome;
        break;
    case legacy_owner_t::unsupported:
        break;
    case legacy_owner_t::shell:
        break;
    }
}

void deactivate(const catalog_entry_t& entry) {
    switch (entry.owner) {
    case legacy_owner_t::registry:
        break;
    case legacy_owner_t::unsupported:
        break;
    default:
        break;
    }
}

}

void initialize() {
    auto& current = state();
    if (current.initialized)
        return;
    current.initialized = true;
    current.context.generation = 1;
    for (const auto& entry : k_catalog) {
        view_descriptor_t descriptor;
        descriptor.id = stable_view_id_t(entry.id);
        descriptor.display_name = entry.label;
        descriptor.internal_name = std::string("aida.") + entry.id;
        descriptor.category = entry.category;
        descriptor.role = entry.role;
        descriptor.identity_policy = std::strncmp(entry.id, "document.", 9) == 0
            ? view_identity_policy_t::multi_instance
            : view_identity_policy_t::singleton;
        descriptor.minimum_size = {entry.minimum_width, entry.minimum_height};
        descriptor.default_open = entry.default_open;
        descriptor.closeable = entry.closeable;
        descriptor.render_ownership = entry.owner == legacy_owner_t::registry
            ? view_render_ownership_t::registry_window
            : view_render_ownership_t::legacy_adapter;
        if (std::strcmp(entry.id, "view.project_explorer") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_project_explorer(); };
        else if (std::strcmp(entry.id, "view.workspace_search") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_workspace_search(); };
        else if (std::strcmp(entry.id, "view.recent") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_recent(); };
        else if (std::strcmp(entry.id, "view.output") == 0)
            descriptor.render = [](const view_render_context_t&) { output_views::render(bottom_tab_t::output); };
        else if (std::strcmp(entry.id, "view.mcp_log") == 0)
            descriptor.render = [](const view_render_context_t&) { output_views::render(bottom_tab_t::mcp_log); };
        else if (std::strcmp(entry.id, "view.driver_log") == 0)
            descriptor.render = [](const view_render_context_t&) { output_views::render(bottom_tab_t::driver_log); };
        else if (std::strcmp(entry.id, "view.sandbox_log") == 0)
            descriptor.render = [](const view_render_context_t&) { output_views::render(bottom_tab_t::sandbox_log); };
        else if (std::strcmp(entry.id, "view.terminal") == 0)
            descriptor.render = [](const view_render_context_t&) { output_views::render(bottom_tab_t::terminal); };
        else if (std::strcmp(entry.id, "document.code") == 0)
            descriptor.render = [](const view_render_context_t& context) {
                render_code_group(context);
            };
        else if (std::strcmp(entry.id, "view.navigator") == 0)
            descriptor.render = [](const view_render_context_t&) {
                workbench_registry_views::render_navigator();
            };
        else if (std::strcmp(entry.id, "view.inspector") == 0)
            descriptor.render = [](const view_render_context_t&) {
                workbench_registry_views::render_inspector();
            };
        else if (std::strcmp(entry.id, "document.diff") == 0)
            descriptor.render = [](const view_render_context_t&) {
                workbench_registry_views::render_diff();
            };
        else if (std::strcmp(entry.id, "document.disassembly") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                disasm_view::render(0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z,
                    disasm_view::capture_selected_workspace(), ImGui::GetIO().DeltaTime);
            };
        else if (std::strcmp(entry.id, "document.hex") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                hex_view::render(0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z,
                    disasm_view::capture_selected_workspace());
            };
        else if (std::strcmp(entry.id, "document.pseudocode") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                pseudocode_view::render(0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z,
                    disasm_view::capture_selected_workspace());
            };
        else if (std::strcmp(entry.id, "document.graph") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                cfg_view::render(0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z,
                    disasm_view::capture_selected_workspace());
            };
        else if (std::strcmp(entry.id, "document.image") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                image_view::render(0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (std::strcmp(entry.id, "view.analysis.binary_map") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::binary_map_view::render(0, 0, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z,
                    disasm_view::capture_selected_workspace());
            };
        else if (std::strcmp(entry.id, "view.analysis.functions") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                functions_panel::render(
                    disasm_view::capture_selected_workspace().workspace,
                    0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f));
            };
        else if (std::strcmp(entry.id, "view.analysis.references") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                xref_db_view::render(0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z,
                    disasm_view::capture_selected_workspace());
            };
        else if (entry.category == view_category_t::analysis &&
                 entry.subview == legacy_subview_t::analysis)
            descriptor.render = [tab = static_cast<analysis_hub_view::sub_tab_t>(
                entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                analysis_hub_view::render_subview(tab, 0.f, 0.f,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f),
                    1.f, globals::ui::accent.x, globals::ui::accent.y,
                    globals::ui::accent.z, disasm_view::capture_selected_workspace());
            };
        else if (entry.category == view_category_t::memory && entry.subview == legacy_subview_t::scan)
            descriptor.render = [tab = static_cast<scan_hub_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                scan_hub_view::render_subview(tab, 0.f, 0.f,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (entry.category == view_category_t::types && entry.subview == legacy_subview_t::types)
            descriptor.render = [tab = static_cast<types_hub_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                types_hub_view::render_subview(tab, 0.f, 0.f,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (std::strcmp(entry.id, "view.types.struct_recon") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                struct_recon_view::render(0.f, 0.f,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (entry.category == view_category_t::debugger && entry.subview == legacy_subview_t::debugger)
            descriptor.render = [tab = static_cast<debugger_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                const float width = (std::max)(available.x, 1.f);
                const float height = (std::max)(available.y, 1.f);
                float content_y = 0.f;
                if (tab == debugger_view::sub_tab_t::cpu) {
                    const float controls_height = (std::min)(72.f, height * 0.24f);
                    debugger_view::render_execution_controls(0.f, 0.f, width, controls_height, 1.f,
                        globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
                    content_y = controls_height + 4.f;
                }
                debugger_view::render_pane(tab, 0.f, content_y, width,
                    (std::max)(height - content_y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (entry.category == view_category_t::network && entry.subview == legacy_subview_t::network)
            descriptor.render = [tab = static_cast<network_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                network_view::render_pane(tab, 0.f, 0.f,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (std::strcmp(entry.id, "view.ai.agents") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::agent_manager::render((std::max)(available.x, 1.f), (std::max)(available.y, 1.f));
            };
        else if (std::strcmp(entry.id, "view.ai_chat") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::automation_ui::render_chat_view((std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f));
            };
        else if (std::strcmp(entry.id, "view.ai.skills") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::skill_manager::render((std::max)(available.x, 1.f), (std::max)(available.y, 1.f));
            };
        else if (std::strcmp(entry.id, "view.ai.providers") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::provider_view::render((std::max)(available.x, 1.f), (std::max)(available.y, 1.f));
            };
        else if (std::strcmp(entry.id, "view.ai.evidence") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::automation_ui::render_evidence_view((std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f));
            };
        else if (std::strcmp(entry.id, "view.ai.mcp_marketplace") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::mcp_marketplace_view::render((std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f));
            };
        else if (std::strcmp(entry.id, "view.settings") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                aida::settings_overlay::render_inline((std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f));
            };
        descriptor.capability = [id = descriptor.id, requires_workspace = entry.requires_workspace](const interaction_context_t&) {
            if (id.value() == "view.analysis.code_patcher_legacy")
                return capability_state_t::unavailable("Use Debugging > Debugger Patches; the legacy Code Patcher remains disabled until create/apply/revert/remove/cave/diff/review/readback/virtualization parity is proven");
            if (id.value() == "view.ai.mcp_activity")
                return capability_state_t::unavailable("MCP Activity has no independent renderer yet; use the canonical MCP Log view without claiming duplicate ownership");
            if (id.value() == "document.image" &&
                !image_view::g_state().active.load(std::memory_order_acquire))
                return capability_state_t::unavailable("Open an image file first");
            if (id.value() == "view.analysis_overview" || id.value() == "view.memory_overview" || id.value() == "view.types_overview")
                return capability_state_t::unavailable("The current hub has no separate overview renderer; use its registered domain views without creating a duplicate render owner");
            return !requires_workspace || workspace_available()
                ? capability_state_t::available()
                : capability_state_t::unavailable("Open and analyze a binary first");
        };
        descriptor.activate = [id = descriptor.id](const view_instance_id_t&) {
            if (const auto* catalog = find_catalog(id))
                activate(*catalog);
        };
        descriptor.deactivate = [id = descriptor.id](const view_instance_id_t& instance) {
            if (id.value() == "document.code") {
                close_code_group(instance);
                return;
            }
            if (const auto* catalog = find_catalog(id))
                deactivate(*catalog);
        };
        current.registry.register_view(std::move(descriptor));
    }
    for (const auto& entry : k_catalog) {
        if (entry.owner == legacy_owner_t::registry && entry.default_open)
            current.registry.open(instance_for(entry), current.context);
    }
    if (g_sa_settings.workspace.legacy_bottom_visible) {
        if (const auto* migrated = find_catalog(stable_view_id_t("view.output")))
            current.registry.open(instance_for(*migrated), current.context);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        g_sa_settings.workspace.legacy_bottom_visible = false;
        g_sa_settings.save();
#endif
    }
    task_center::register_views(current.registry);
}

view_registry_t& registry() {
    initialize();
    return state().registry;
}

std::string ensure_window_name(const stable_view_id_t& id) {
    initialize();
    const auto* descriptor = state().registry.find_descriptor(id);
    if (!descriptor)
        return {};
    const auto* entry = find_catalog(id);
    const view_instance_id_t instance = entry
        ? instance_for(*entry)
        : view_instance_id_t{id,
            descriptor->identity_policy == view_identity_policy_t::multi_instance
                ? stable_view_instance_key_t("primary")
                : stable_view_instance_key_t{}};
    const auto result = state().registry.ensure_identity(instance);
    return result.ok() ? state().registry.window_name(instance) : std::string{};
}

void begin_frame() noexcept {
    try {
        initialize();
        synchronize_legacy_state();
        file_tabs::poll_external_changes();
        synchronize_code_groups(state());
        task_center::refresh();
    } catch (...) {
    }
}

view_operation_result_t open_or_focus(const stable_view_id_t& id) {
    initialize();
    if (id.value() == "document.code") {
        const auto instance = active_code_instance();
        std::uint32_t group = 0;
        parse_code_group(instance.instance, group);
        return state().registry.open_or_focus(instance, state().context,
            code_group_label(group));
    }
    const auto* entry = find_catalog(id);
    const view_instance_id_t instance = entry
        ? instance_for(*entry)
        : view_instance_id_t{id, {}};
    return state().registry.open_or_focus(instance, state().context);
}

view_operation_result_t close(const stable_view_id_t& id) {
    initialize();
    if (id.value() == "document.code")
        return state().registry.close(active_code_instance());
    const auto* entry = find_catalog(id);
    const view_instance_id_t instance = entry
        ? instance_for(*entry)
        : view_instance_id_t{id, {}};
    return state().registry.close(instance);
}

view_operation_result_t reopen_last_closed() {
    initialize();
    return state().registry.reopen_last_closed(state().context);
}

view_operation_result_t open_default_missing() {
    initialize();
    return state().registry.open_default_missing(state().context);
}

bool is_open(const stable_view_id_t& id) noexcept {
    try {
        initialize();
        if (id.value() == "document.code")
            return state().registry.is_open(active_code_instance());
        const auto* entry = find_catalog(id);
        const view_instance_id_t instance = entry
            ? instance_for(*entry)
            : view_instance_id_t{id, {}};
        return state().registry.is_open(instance);
    } catch (...) {
        return false;
    }
}

bool can_reopen_last_closed() noexcept {
    try {
        initialize();
        return state().registry.can_reopen_last_closed();
    } catch (...) {
        return false;
    }
}

void synchronize_legacy_state() {
    initialize();
    auto& current = state();
    ++current.context.generation;
    if (globals::ui::active_center_view == center_view_t::code_editor) {
        current.registry.open_or_focus(active_code_instance(), current.context,
            code_group_label(file_tabs::is_valid_tab_index(file_tabs::active_tab)
                ? file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)].group_id
                : 0));
        globals::ui::active_center_view = center_view_t::welcome;
    } else if (translate_legacy_center(current, globals::ui::active_center_view)) {
        globals::ui::active_center_view = center_view_t::welcome;
    }
    for (const auto& entry : k_catalog) {
        if (entry.owner == legacy_owner_t::shell)
            current.registry.open(instance_for(entry), current.context);
    }
}

void render_registry_owned_windows() noexcept {
    try {
    initialize();
    auto& current = state();
    std::vector<view_instance_id_t> instances;
    instances.reserve(current.registry.instance_count());
    current.registry.for_each_instance(
        [&](const view_descriptor_t& descriptor, const view_instance_state_t& instance) {
            if (descriptor.render_ownership == view_render_ownership_t::registry_window)
                instances.push_back(instance.id);
        }, true);
    std::optional<view_instance_id_t> focused;
    for (const auto& id : instances) {
        const auto* descriptor = current.registry.find_descriptor(id.view);
        if (!descriptor)
            continue;
        if (!current.registry.is_open(id))
            continue;
        const std::string& window_name = current.registry.window_name(id);
        ImGui::SetNextWindowSizeConstraints(
            ImVec2(descriptor->minimum_size.width, descriptor->minimum_size.height),
            ImVec2(FLT_MAX, FLT_MAX));
        if (current.registry.consume_focus_request(id))
            ImGui::SetNextWindowFocus();
        bool open = true;
        if (ImGui::Begin(window_name.c_str(), descriptor->closeable ? &open : nullptr)) {
            current.context.active_view = id.view;
            current.context.active_view_instance = id.instance;
            if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows))
                focused = id;
            const auto result = current.registry.render(id, current.context);
            if (!result.ok())
                ImGui::TextWrapped("%s", result.detail.c_str());
        }
        ImGui::End();
        if (!open)
            current.registry.close(id);
    }
    current.registry.update_focus(focused);
    } catch (...) {
    }
}

void for_each_menu_entry(const std::function<void(const menu_entry_t&)>& visitor) {
    if (!visitor)
        return;
    synchronize_legacy_state();
    auto& current = state();
    std::vector<menu_entry_t> entries;
    entries.reserve(current.registry.descriptor_count());
    current.registry.for_each_descriptor([&](const view_descriptor_t& descriptor) {
        if (!descriptor.closeable && descriptor.role == view_presentation_role_t::shell_surface)
            return;
        const auto* catalog = find_catalog(descriptor.id);
        const view_instance_id_t instance = catalog
            ? instance_for(*catalog)
            : view_instance_id_t{descriptor.id, {}};
        const auto capability = current.registry.evaluate(descriptor.id, current.context);
        entries.push_back({descriptor.id, descriptor.display_name, descriptor.category,
            current.registry.is_open(instance), capability.visible && capability.enabled,
            capability.disabled_reason});
    });
    std::sort(entries.begin(), entries.end(), [](const menu_entry_t& lhs, const menu_entry_t& rhs) {
        if (lhs.category != rhs.category)
            return lhs.category < rhs.category;
        return lhs.label < rhs.label;
    });
    for (const auto& entry : entries)
        visitor(entry);
}

const char* category_label(view_category_t category) noexcept {
    switch (category) {
    case view_category_t::shell: return "Shell";
    case view_category_t::explorer: return "Explore";
    case view_category_t::document: return "Documents";
    case view_category_t::analysis: return "Analysis";
    case view_category_t::debugger: return "Debugging";
    case view_category_t::memory: return "Memory";
    case view_category_t::types: return "Types and Structures";
    case view_category_t::network: return "Network";
    case view_category_t::automation: return "Automation and AI";
    case view_category_t::programming: return "Programming";
    case view_category_t::output: return "Output";
    case view_category_t::settings: return "Settings";
    }
    return "Views";
}

}
