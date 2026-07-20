#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "design_system.hpp"
#include "explorer_views.hpp"
#include "output_views.hpp"
#include "programming_tasks.hpp"
#include "programming_language_views.hpp"
#include "task_center.hpp"
#include "theme.hpp"
#include "workbench_registry_views.hpp"
#include "workspace_layout.hpp"

#include "../../helpers/globals.h"
#include "../settings/standalone_settings.hpp"
#include "../settings/settings_persistence_service.hpp"
#include "../ai/settings_overlay.hpp"
#include "../ai/agent_manager_view.hpp"
#include "../ai/skill_manager_view.hpp"
#include "../ai/provider_view.hpp"
#include "../ai/standalone_chat.hpp"
#include "../mcp/mcp_marketplace_view.hpp"
#include "../analysis/analysis_hub_view.hpp"
#include "../analysis/binary_map_view.hpp"
#include "../analysis/functions_panel.hpp"
#include "../analysis/analysis_list_views.hpp"
#include "../analysis/analysis_relationship_views.hpp"
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
#include "../network/burp/project_view.hpp"
#include "../scanner/scan_hub_view.hpp"
#include "../session/analysis_session.hpp"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../preview/studio_semantics.hpp"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <limits>
#include <map>
#include <set>
#include <vector>

namespace aida::ui::application_views {
namespace {

constexpr std::size_t kMaximumWorkspaceVisibilityBytes = 64U * 1024U;

enum class catalog_owner_t : std::uint8_t {
    registry
};

enum class catalog_subview_t : std::uint8_t {
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
    catalog_owner_t owner;
    catalog_subview_t subview;
    int subview_value;
    float minimum_width;
    float minimum_height;
    bool default_open;
    bool closeable;
    bool requires_workspace;
};

#define AIDA_VIEW(ID, LABEL, CATEGORY, ROLE, OWNER, SUBVIEW, SUBVALUE, WIDTH, HEIGHT, OPEN, CLOSE, WORKSPACE) \
    {ID, LABEL, view_category_t::CATEGORY, view_presentation_role_t::ROLE, catalog_owner_t::OWNER, catalog_subview_t::SUBVIEW, SUBVALUE, WIDTH, HEIGHT, OPEN, CLOSE, WORKSPACE}

constexpr catalog_entry_t k_catalog[] = {
    AIDA_VIEW("view.start_center", "Start Center", shell, document, registry, none, 0, 560, 360, true, true, false),
    AIDA_VIEW("view.project_explorer", "Project Explorer", explorer, tool_window, registry, none, 0, 240, 220, true, true, false),
    AIDA_VIEW("view.workspace_search", "Workspace Search", explorer, tool_window, registry, none, 0, 280, 220, false, true, false),
    AIDA_VIEW("view.recent", "Recent", explorer, tool_window, registry, none, 0, 240, 180, false, true, false),
    AIDA_VIEW("view.sessions", "Sessions", shell, shell_surface, registry, none, 0, 320, 160, true, true, false),
    AIDA_VIEW("view.navigator", "Navigator", analysis, tool_window, registry, none, 0, 260, 220, false, true, true),
    AIDA_VIEW("view.inspector", "Inspector", analysis, inspector, registry, none, 0, 300, 220, true, true, false),
    AIDA_VIEW("view.ai_chat", "AI Chat", automation, tool_window, registry, none, 0, 420, 300, true, true, false),
    AIDA_VIEW("view.output", "Output", output, bottom_panel, registry, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.mcp_log", "MCP Activity", output, bottom_panel, registry, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.driver_log", "Driver Log", output, bottom_panel, registry, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.sandbox_log", "Sandbox Log", output, bottom_panel, registry, none, 0, 360, 160, false, true, false),
    AIDA_VIEW("view.terminal", "Terminal", programming, bottom_panel, registry, none, 0, 420, 180, false, true, false),
    AIDA_VIEW("view.programming.outline", "Programming Outline", programming, tool_window, registry, none, 0, 280, 220, false, true, false),
    AIDA_VIEW("view.programming.references", "Programming References", programming, bottom_panel, registry, none, 0, 420, 180, false, true, false),
    AIDA_VIEW("view.programming.source_debug_console", "Source Debug Console", programming, bottom_panel, registry, none, 0, 440, 200, false, true, false),
    AIDA_VIEW("document.code", "Code Editor", programming, document, registry, none, 0, 480, 300, false, true, false),
    AIDA_VIEW("document.disassembly", "Disassembly", document, document, registry, none, 0, 480, 300, false, true, true),
    AIDA_VIEW("document.hex", "Hex", document, document, registry, none, 0, 480, 300, false, true, true),
    AIDA_VIEW("document.pseudocode", "Pseudocode", document, document, registry, none, 0, 480, 300, false, true, true),
    AIDA_VIEW("document.graph", "Graph", document, document, registry, none, 0, 520, 340, false, true, true),
    AIDA_VIEW("document.image", "Image", document, document, registry, none, 0, 480, 300, false, true, false),
    AIDA_VIEW("document.diff", "Diff", document, document, registry, none, 0, 520, 300, false, true, true),
    AIDA_VIEW("view.analysis.binary_map", "Binary Map", analysis, document, registry, none, 0, 520, 340, false, true, true),
    AIDA_VIEW("view.analysis.functions", "Functions", analysis, tool_window, registry, none, 0, 300, 260, false, true, true),
    AIDA_VIEW("view.analysis.imports", "Imports", analysis, tool_window, registry, none, 0, 360, 240, false, true, true),
    AIDA_VIEW("view.analysis.exports", "Exports", analysis, tool_window, registry, none, 0, 360, 240, false, true, true),
    AIDA_VIEW("view.analysis.names", "Names", analysis, tool_window, registry, none, 0, 360, 240, false, true, true),
    AIDA_VIEW("view.analysis.strings", "Strings", analysis, tool_window, registry, none, 0, 400, 240, false, true, true),
    AIDA_VIEW("view.analysis.segments", "Segments", analysis, tool_window, registry, none, 0, 400, 220, false, true, true),
    AIDA_VIEW("view.analysis.local_types", "Local Types", analysis, tool_window, registry, none, 0, 420, 240, false, true, true),
    AIDA_VIEW("view.analysis.segment_registers", "Segment Registers", analysis, tool_window, registry, none, 0, 360, 220, false, true, true),
    AIDA_VIEW("view.analysis.proximity", "Proximity Browser", analysis, tool_window, registry, none, 0, 420, 260, false, true, true),
    AIDA_VIEW("view.analysis.references", "Cross References", analysis, tool_window, registry, none, 0, 360, 240, false, true, true),
    AIDA_VIEW("view.analysis.symbolic", "Symbolic Execution", analysis, tool_window, registry, analysis, 0, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.taint", "Taint Analysis", analysis, tool_window, registry, analysis, 1, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.deobfuscation", "Deobfuscation", analysis, tool_window, registry, analysis, 2, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.fuzzer", "Analysis Fuzzer", analysis, tool_window, registry, analysis, 3, 440, 280, false, true, true),
    AIDA_VIEW("view.analysis.protection", "Protection Analysis", analysis, tool_window, registry, analysis, 4, 440, 280, false, true, true),
    AIDA_VIEW("view.memory.value_scan", "Value Scan", memory, tool_window, registry, scan, 0, 480, 280, false, true, false),
    AIDA_VIEW("view.memory.crypto", "Crypto Scanner", memory, tool_window, registry, scan, 1, 440, 260, false, true, false),
    AIDA_VIEW("view.memory.aob", "AOB Generator", memory, tool_window, registry, scan, 2, 440, 260, false, true, true),
    AIDA_VIEW("view.memory.decrypt", "Decrypt Oracle", memory, tool_window, registry, scan, 3, 440, 260, false, true, false),
    AIDA_VIEW("view.memory.pointers", "Pointer Scanner", memory, tool_window, registry, scan, 4, 480, 280, false, true, false),
    AIDA_VIEW("view.memory.snapshots", "Snapshot Diff", memory, tool_window, registry, scan, 5, 480, 280, false, true, false),
    AIDA_VIEW("view.memory.integrity", "Integrity Hunter", memory, tool_window, registry, scan, 6, 480, 280, false, true, false),
    AIDA_VIEW("view.types.structures", "Structures", types, tool_window, registry, types, 0, 460, 280, false, true, true),
    AIDA_VIEW("view.types.unions", "Unions", types, tool_window, registry, types, 1, 420, 260, false, true, true),
    AIDA_VIEW("view.types.enums", "Enums", types, tool_window, registry, types, 2, 420, 260, false, true, true),
    AIDA_VIEW("view.types.typedefs", "Typedefs", types, tool_window, registry, types, 3, 420, 260, false, true, true),
    AIDA_VIEW("view.types.functions", "Function Types", types, tool_window, registry, types, 4, 440, 260, false, true, true),
    AIDA_VIEW("view.types.inferred", "Inferred Types", types, tool_window, registry, types, 5, 440, 260, false, true, true),
    AIDA_VIEW("view.types.dissector", "Structure Dissector", types, tool_window, registry, types, 6, 560, 360, false, true, false),
    AIDA_VIEW("view.types.struct_recon", "Structure Reconstruction", types, document, registry, none, 0, 560, 360, false, true, false),
#define AIDA_DEBUG_VIEW(ID, LABEL, INDEX) AIDA_VIEW(ID, LABEL, debugger, tool_window, registry, debugger, INDEX, 420, 240, false, true, false)
    AIDA_VIEW("view.debug.cpu", "CPU", debugger, tool_window, registry, debugger, 0, 620, 380, false, true, false),
    AIDA_DEBUG_VIEW("view.debug.breakpoints", "Breakpoints", 1),
    AIDA_DEBUG_VIEW("view.debug.memory_map", "Memory Map", 2), AIDA_DEBUG_VIEW("view.debug.call_stack", "Call Stack", 3),
    AIDA_DEBUG_VIEW("view.debug.threads", "Threads", 4), AIDA_DEBUG_VIEW("view.debug.watches", "Watches", 5),
    AIDA_DEBUG_VIEW("view.debug.handles", "Handles", 6), AIDA_DEBUG_VIEW("view.debug.trace", "Trace", 7),
    AIDA_DEBUG_VIEW("view.debug.strings", "Debugger Strings", 8), AIDA_DEBUG_VIEW("view.debug.bookmarks", "Bookmarks", 9),
    AIDA_DEBUG_VIEW("view.debug.modules", "Modules", 10), AIDA_DEBUG_VIEW("view.debug.patches", "Debugger Patches", 11),
    AIDA_DEBUG_VIEW("view.debug.seh", "SEH Chain", 12), AIDA_DEBUG_VIEW("view.debug.cfg", "Debugger CFG", 13),
    AIDA_DEBUG_VIEW("view.debug.source", "Source / Assembly", 14),
#define AIDA_NETWORK_VIEW(ID, LABEL, INDEX) AIDA_VIEW(ID, LABEL, network, tool_window, registry, network, INDEX, 460, 260, false, true, false)
    AIDA_NETWORK_VIEW("view.network.connections", "Connections", 0), AIDA_NETWORK_VIEW("view.network.capture", "Capture", 1),
    AIDA_NETWORK_VIEW("view.network.intercept", "Intercept", 2), AIDA_NETWORK_VIEW("view.network.proxy", "Proxy", 3),
    AIDA_NETWORK_VIEW("view.network.dns", "DNS", 4), AIDA_NETWORK_VIEW("view.network.filters", "Filters", 5),
    AIDA_NETWORK_VIEW("view.network.bandwidth", "Bandwidth", 6),
    AIDA_VIEW("view.network.repeater", "Repeater", network, tool_window, registry, network, 7, 520, 320, false, true, false),
    AIDA_NETWORK_VIEW("view.network.keylog", "KeyLog", 8), AIDA_NETWORK_VIEW("view.network.pcap", "PCAP", 9),
    AIDA_NETWORK_VIEW("view.network.fuzzer", "Network Fuzzer", 10), AIDA_NETWORK_VIEW("view.network.offensive", "Offensive", 11),
    AIDA_NETWORK_VIEW("view.network.websocket", "WebSocket", 12), AIDA_NETWORK_VIEW("view.network.scripting", "Scripting", 13),
    AIDA_NETWORK_VIEW("view.network.decoder", "Decoder", 14), AIDA_NETWORK_VIEW("view.network.site_map", "Site Map", 15),
    AIDA_NETWORK_VIEW("view.network.scope", "Scope", 16), AIDA_NETWORK_VIEW("view.network.cookies", "Cookies", 17),
    AIDA_NETWORK_VIEW("view.network.scanner", "Scanner", 18), AIDA_NETWORK_VIEW("view.network.recon", "Recon", 19),
    AIDA_NETWORK_VIEW("view.network.intruder", "Intruder", 20), AIDA_NETWORK_VIEW("view.network.collaborator", "Collaborator", 21),
    AIDA_NETWORK_VIEW("view.network.sequencer", "Sequencer", 22), AIDA_NETWORK_VIEW("view.network.comparer", "Comparer", 23),
    AIDA_NETWORK_VIEW("view.network.jwt_lab", "JWT Lab", 24), AIDA_NETWORK_VIEW("view.network.match_replace", "Match and Replace", 25),
    AIDA_NETWORK_VIEW("view.network.session", "Session", 26),
    AIDA_VIEW("view.network.api", "API", network, tool_window, registry, network, 27, 520, 320, false, true, false),
    AIDA_VIEW("view.network.project", "Burp Project", network, tool_window, registry, none, 0, 480, 260, false, true, false),
    AIDA_VIEW("view.network.ws_editor", "WebSocket Editor", network, tool_window, registry, network, 28, 520, 320, false, true, false),
    AIDA_VIEW("view.network.h2_editor", "HTTP/2 Editor", network, tool_window, registry, network, 29, 520, 320, false, true, false),
    AIDA_NETWORK_VIEW("view.network.logger", "Logger", 30), AIDA_NETWORK_VIEW("view.network.csp", "CSP", 31),
    AIDA_NETWORK_VIEW("view.network.upstream", "Upstream Proxy", 32), AIDA_NETWORK_VIEW("view.network.browser", "Browser", 33),
    AIDA_NETWORK_VIEW("view.network.reports", "Reports", 34), AIDA_NETWORK_VIEW("view.network.headless", "Headless Browser", 35),
    AIDA_VIEW("view.ai.agents", "Agents", automation, tool_window, registry, none, 0, 420, 280, false, true, false),
    AIDA_VIEW("view.ai.skills", "Skills", automation, tool_window, registry, none, 0, 480, 300, false, true, false),
    AIDA_VIEW("view.ai.providers", "AI Providers", automation, tool_window, registry, none, 0, 460, 300, false, true, false),
    AIDA_VIEW("view.ai.mcp_marketplace", "MCP Marketplace", automation, tool_window, registry, none, 0, 600, 420, false, true, false),
    AIDA_VIEW("view.ai.evidence", "Evidence Review", automation, tool_window, registry, none, 0, 420, 280, false, true, false),
    AIDA_VIEW("view.ai.scripts", "Automation Scripts", automation, tool_window, registry, none, 0, 520, 300, false, true, false),
    AIDA_VIEW("view.settings", "Settings", settings, tool_window, registry, none, 0, 520, 360, false, true, false)
};

#undef AIDA_NETWORK_VIEW
#undef AIDA_DEBUG_VIEW
#undef AIDA_VIEW

struct state_t {
    struct surface_state_t {
        bool pinned = false;
        bool reset_requested = false;
        bool restore_open = false;
        bool presentation_pending = false;
        disasm_view::presentation_snapshot_t presentation;
    };
    view_registry_t registry;
    interaction_context_t context;
    std::map<view_instance_id_t, surface_state_t> surfaces;
    std::map<view_instance_id_t, std::string> render_failures;
    std::string shell_render_exception;
    std::optional<view_instance_id_t> title_focused;
    bool initialized = false;
    bool start_center_auto_open = true;
    bool workspace_preset_observed = false;
    workspace_layout::workspace_preset_t observed_workspace_preset =
        workspace_layout::workspace_preset_t::analysis;
    std::string observed_workspace_identity;
    std::map<stable_view_id_t, bool> workspace_visibility;
    std::set<stable_view_id_t> deferred_workspace_opens;
    bool visibility_capture_valid = false;
    std::uint64_t visibility_capture_registry_revision = 0;
    workspace_layout::workspace_preset_t visibility_capture_preset =
        workspace_layout::workspace_preset_t::analysis;
    std::string visibility_capture_identity;
};

state_t& state() {
    static state_t value;
    return value;
}

stable_view_id_t canonical_view_id(const stable_view_id_t& id);
const catalog_entry_t* find_catalog(const stable_view_id_t& id);

bool is_disassembly_side_instance(const view_instance_id_t& id) noexcept {
    if (id.view.value() != "document.disassembly")
        return false;
    const std::string& key = id.instance.value();
    return key == "side.1" || key == "side.2" || key == "side.3";
}

void clear_surface_settings(ImGuiContext*, ImGuiSettingsHandler*) {
    state().surfaces.clear();
}

void* open_surface_settings(ImGuiContext*, ImGuiSettingsHandler*, const char* name) {
    if (!name)
        return nullptr;
    const std::string key(name);
    const std::size_t separator = key.find('|');
    if (separator == std::string::npos)
        return nullptr;
    const std::string view = key.substr(0, separator);
    const std::string instance = key.substr(separator + 1);
    if (!is_valid_stable_id(view) || (!instance.empty() && !is_valid_stable_instance_key(instance)))
        return nullptr;
    const view_instance_id_t id{canonical_view_id(stable_view_id_t(view)),
        stable_view_instance_key_t(instance)};
    if (!find_catalog(id.view))
        return nullptr;
    if (!id.instance.empty() && !is_disassembly_side_instance(id) &&
        id.view.value() != "document.code")
        return nullptr;
    return &state().surfaces[id];
}

void read_surface_setting(ImGuiContext*, ImGuiSettingsHandler*, void* entry, const char* line) {
    if (!entry || !line)
        return;
    int pinned = 0;
    if (std::sscanf(line, "Pinned=%d", &pinned) == 1)
        static_cast<state_t::surface_state_t*>(entry)->pinned = pinned != 0;
    int open = 0;
    if (std::sscanf(line, "Open=%d", &open) == 1)
        static_cast<state_t::surface_state_t*>(entry)->restore_open = open != 0;
    int format = 0;
    int show_bytes = 0;
    int section = -1;
    int has_base = 0;
    unsigned long long base = 0;
    int has_selection = 0;
    int space = 0;
    unsigned long long address = 0;
    int architecture = 0;
    int mode = 0;
    unsigned long long scroll_milli = 0;
    if (std::sscanf(line,
            "Presentation=%d,%d,%d,%d,%llu,%d,%d,%llu,%d,%d,%llu",
            &format, &show_bytes, &section, &has_base, &base,
            &has_selection, &space, &address, &architecture, &mode,
            &scroll_milli) == 11 &&
        format >= static_cast<int>(disasm_view::addr_format_t::va) &&
        format <= static_cast<int>(disasm_view::addr_format_t::file_offset)) {
        auto& surface = *static_cast<state_t::surface_state_t*>(entry);
        surface.presentation.addr_format =
            static_cast<disasm_view::addr_format_t>(format);
        surface.presentation.show_bytes = show_bytes != 0;
        surface.presentation.active_section = section;
        surface.presentation.scroll_y = static_cast<float>(
            (std::min)(scroll_milli, 1000000000000000ULL)) / 1000.0f;
        surface.presentation.display_image_base = has_base != 0
            ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(base))
            : std::nullopt;
        if (has_selection != 0) {
            aida::analysis::address_t selection;
            selection.space = static_cast<aida::analysis::address_space_id_t>(space);
            selection.value = static_cast<std::uint64_t>(address);
            selection.architecture =
                static_cast<aida::analysis::architecture_id_t>(architecture);
            selection.mode = static_cast<aida::analysis::architecture_mode_t>(mode);
            surface.presentation.selection = selection;
        } else {
            surface.presentation.selection.reset();
        }
        surface.presentation_pending = true;
    }
}

void write_surface_settings(ImGuiContext*, ImGuiSettingsHandler*, ImGuiTextBuffer* output) {
    if (!output)
        return;
    std::set<view_instance_id_t> entries;
    for (const auto& entry : state().surfaces)
        if (entry.second.pinned)
            entries.insert(entry.first);
    state().registry.for_each_instance(
        [&](const view_descriptor_t&, const view_instance_state_t& instance) {
            if (instance.open && instance.id.view.value() == "document.disassembly" &&
                !instance.id.instance.empty())
                entries.insert(instance.id);
        }, true);
    for (const auto& id : entries) {
        const auto surface = state().surfaces.find(id);
        const bool pinned = surface != state().surfaces.end() && surface->second.pinned;
        const bool open = state().registry.is_open(id);
        if (!pinned && !open)
            continue;
        output->appendf("[AiDAView][%s|%s]\n",
            id.view.c_str(), id.instance.c_str());
        if (pinned)
            output->append("Pinned=1\n");
        if (open)
            output->append("Open=1\n");
        if (open && id.view.value() == "document.disassembly" &&
            !id.instance.empty()) {
            disasm_view::presentation_snapshot_t snapshot;
            if (disasm_view::capture_selected_presentation(
                    id.instance.value(), snapshot)) {
                const auto selection = snapshot.selection.value_or(
                    aida::analysis::address_t{});
                const auto scroll_milli = static_cast<unsigned long long>(
                    std::llround((std::clamp)(snapshot.scroll_y,
                        0.0f, 1000000000000.0f) * 1000.0f));
                output->appendf(
                    "Presentation=%d,%d,%d,%d,%llu,%d,%d,%llu,%d,%d,%llu\n",
                    static_cast<int>(snapshot.addr_format), snapshot.show_bytes ? 1 : 0,
                    snapshot.active_section, snapshot.display_image_base ? 1 : 0,
                    static_cast<unsigned long long>(
                        snapshot.display_image_base.value_or(0)),
                    snapshot.selection ? 1 : 0, static_cast<int>(selection.space),
                    static_cast<unsigned long long>(selection.value),
                    static_cast<int>(selection.architecture),
                    static_cast<int>(selection.mode), scroll_milli);
            }
        }
        output->append("\n");
    }
}

void install_surface_settings_handler() {
    ImGuiContext* context = ImGui::GetCurrentContext();
    if (!context)
        return;
    for (const auto& handler : context->SettingsHandlers)
        if (handler.TypeHash == ImHashStr("AiDAView"))
            return;
    ImGuiSettingsHandler handler;
    handler.TypeName = "AiDAView";
    handler.TypeHash = ImHashStr(handler.TypeName);
    handler.ClearAllFn = clear_surface_settings;
    handler.ReadOpenFn = open_surface_settings;
    handler.ReadLineFn = read_surface_setting;
    handler.WriteAllFn = write_surface_settings;
    ImGui::AddSettingsHandler(&handler);
}

const catalog_entry_t* find_catalog(const stable_view_id_t& id) {
    for (const auto& entry : k_catalog) {
        if (id.value() == entry.id)
            return &entry;
    }
    return nullptr;
}

stable_view_id_t canonical_view_id(const stable_view_id_t& id) {
    stable_view_id_t canonical = id;
    state().registry.for_each_descriptor([&](const view_descriptor_t& descriptor) {
        if (std::find(descriptor.persistence_aliases.begin(),
                      descriptor.persistence_aliases.end(), id) !=
            descriptor.persistence_aliases.end())
            canonical = descriptor.id;
    });
    return canonical;
}

ImGuiID default_dock_node(const view_descriptor_t& descriptor) noexcept {
    switch (descriptor.role) {
    case view_presentation_role_t::document:
        return workspace_layout::node_id(workspace_layout::dock_role_t::documents);
    case view_presentation_role_t::inspector:
        return workspace_layout::node_id(workspace_layout::dock_role_t::inspector);
    case view_presentation_role_t::bottom_panel:
        return workspace_layout::node_id(workspace_layout::dock_role_t::bottom);
    case view_presentation_role_t::shell_surface:
        return workspace_layout::node_id(workspace_layout::dock_role_t::navigator);
    case view_presentation_role_t::tool_window: {
        const std::string& id = descriptor.id.value();
        if (id == "view.ai_chat")
            return workspace_layout::node_id(workspace_layout::dock_role_t::inspector);
        if (descriptor.category == view_category_t::explorer ||
            id == "view.navigator" || id == "view.analysis.functions" ||
            id == "view.programming.outline")
            return workspace_layout::node_id(workspace_layout::dock_role_t::navigator);
        return workspace_layout::node_id(workspace_layout::dock_role_t::documents);
    }
    }
    return 0;
}

std::string workspace_preset_key(workspace_layout::workspace_preset_t preset) {
    std::size_t count = 0;
    const auto* descriptors = workspace_layout::presets(count);
    for (std::size_t index = 0; index < count; ++index)
        if (descriptors[index].id == preset)
            return std::string(descriptors[index].stable_id);
    return "analysis";
}

bool workspace_manages_visibility(const view_descriptor_t& descriptor) noexcept {
    return descriptor.identity_policy == view_identity_policy_t::singleton &&
        descriptor.role != view_presentation_role_t::document && descriptor.closeable;
}

nlohmann::json read_workspace_visibility_root() {
    try {
        if (g_sa_settings.workspace.view_visibility_json.size() >
            kMaximumWorkspaceVisibilityBytes)
            return nlohmann::json::object();
        nlohmann::json root = nlohmann::json::parse(
            g_sa_settings.workspace.view_visibility_json.empty()
                ? "{}" : g_sa_settings.workspace.view_visibility_json);
        if (root.is_object())
            return root;
    } catch (...) {
    }
    return nlohmann::json::object();
}

std::optional<bool> persisted_workspace_visibility(const nlohmann::json* views,
    const stable_view_id_t& id) {
    if (!views)
        return std::nullopt;
    if (views->contains(id.value()) && (*views)[id.value()].is_boolean())
        return (*views)[id.value()].get<bool>();
    for (auto iterator = views->begin(); iterator != views->end(); ++iterator) {
        if (!iterator.value().is_boolean() || !is_valid_stable_id(iterator.key()))
            continue;
        if (canonical_view_id(stable_view_id_t(iterator.key())) == id)
            return iterator.value().get<bool>();
    }
    return std::nullopt;
}

void restore_workspace_visibility(state_t& current,
    workspace_layout::workspace_preset_t preset, std::string_view identity) {
    current.workspace_visibility.clear();
    current.deferred_workspace_opens.clear();
    const nlohmann::json root = read_workspace_visibility_root();
    const std::string preset_key(identity);
    const nlohmann::json* persisted_views = nullptr;
    const nlohmann::json* persisted_entry = nullptr;
    std::uint32_t persisted_revision = 1;
    if (root.contains("presets") && root["presets"].is_object()) {
        const auto& presets = root["presets"];
        if (presets.contains(preset_key) && presets[preset_key].is_object() &&
            presets[preset_key].contains("views") && presets[preset_key]["views"].is_object()) {
            persisted_entry = &presets[preset_key];
            persisted_views = &(*persisted_entry)["views"];
        }
        else if (identity.rfind("builtin:", 0) == 0) {
            const std::string legacy = workspace_preset_key(preset);
            if (presets.contains(legacy) && presets[legacy].is_object() &&
                presets[legacy].contains("views") && presets[legacy]["views"].is_object()) {
                persisted_entry = &presets[legacy];
                persisted_views = &(*persisted_entry)["views"];
            }
        }
    }
    if (persisted_entry && persisted_entry->contains("preset_revision") &&
        (*persisted_entry)["preset_revision"].is_number_unsigned()) {
        const auto value = (*persisted_entry)["preset_revision"].get<std::uint64_t>();
        if (value > 0 && value <= (std::numeric_limits<std::uint32_t>::max)())
            persisted_revision = static_cast<std::uint32_t>(value);
    }
    current.registry.for_each_descriptor([&](const view_descriptor_t& descriptor) {
        if (!workspace_manages_visibility(descriptor))
            return;
        bool desired = persisted_views == nullptr &&
            workspace_layout::preset_default_opens_view(preset, descriptor.id.value());
        if (const auto persisted = persisted_workspace_visibility(persisted_views, descriptor.id)) {
            desired = *persisted;
        } else if (persisted_views &&
            descriptor.preset_introduced_revision > persisted_revision &&
            descriptor.preset_introduced_revision <= workspace_layout::preset_revision(preset)) {
            desired = workspace_layout::preset_default_opens_view(
                preset, descriptor.id.value());
        }
        current.workspace_visibility[descriptor.id] = desired;
        const view_instance_id_t instance{descriptor.id, {}};
        const bool open = current.registry.is_open(instance);
        if (!desired && open) {
            static_cast<void>(current.registry.close(instance));
        } else if (desired && !open) {
            const auto result = current.registry.open(instance, current.context);
            if (!result.ok())
                current.deferred_workspace_opens.insert(descriptor.id);
        }
    });
}

void retry_deferred_workspace_opens(state_t& current) {
    for (auto iterator = current.deferred_workspace_opens.begin();
         iterator != current.deferred_workspace_opens.end();) {
        const stable_view_id_t id = *iterator;
        const auto desired = current.workspace_visibility.find(id);
        if (desired == current.workspace_visibility.end() || !desired->second) {
            iterator = current.deferred_workspace_opens.erase(iterator);
            continue;
        }
        const view_instance_id_t instance{id, {}};
        if (current.registry.is_open(instance) ||
            current.registry.open(instance, current.context).ok()) {
            iterator = current.deferred_workspace_opens.erase(iterator);
            continue;
        }
        ++iterator;
    }
}

void capture_workspace_visibility(state_t& current,
    workspace_layout::workspace_preset_t preset, std::string_view identity) {
    const std::uint64_t registry_revision = current.registry.visibility_revision();
    if (current.visibility_capture_valid &&
        current.visibility_capture_registry_revision == registry_revision &&
        current.visibility_capture_preset == preset &&
        current.visibility_capture_identity == identity)
        return;
    nlohmann::json root = read_workspace_visibility_root();
    root["version"] = 3;
    nlohmann::json views = nlohmann::json::object();
    current.registry.for_each_descriptor([&](const view_descriptor_t& descriptor) {
        if (!workspace_manages_visibility(descriptor))
            return;
        const view_instance_id_t instance{descriptor.id, {}};
        bool open = current.registry.is_open(instance);
        if (current.deferred_workspace_opens.find(descriptor.id) !=
            current.deferred_workspace_opens.end()) {
            const auto desired = current.workspace_visibility.find(descriptor.id);
            open = desired != current.workspace_visibility.end() && desired->second;
        }
        current.workspace_visibility[descriptor.id] = open;
        views[descriptor.id.value()] = open;
    });
    const std::string preset_key(identity);
    if (!root.contains("presets") || !root["presets"].is_object())
        root["presets"] = nlohmann::json::object();
    root["presets"][preset_key] = {
        {"preset_revision", workspace_layout::preset_revision(preset)},
        {"views", std::move(views)}};
    const std::string serialized = root.dump();
    if (serialized.size() > kMaximumWorkspaceVisibilityBytes)
        return;
    if (serialized == g_sa_settings.workspace.view_visibility_json) {
        current.visibility_capture_valid = true;
        current.visibility_capture_registry_revision = registry_revision;
        current.visibility_capture_preset = preset;
        current.visibility_capture_identity.assign(identity);
        return;
    }
    g_sa_settings.workspace.view_visibility_json = serialized;
    current.visibility_capture_valid = true;
    current.visibility_capture_registry_revision = registry_revision;
    current.visibility_capture_preset = preset;
    current.visibility_capture_identity.assign(identity);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#endif
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
    const OpenTab* single = nullptr;
    std::size_t count = 0;
    for (const auto& tab : file_tabs::tabs) {
        if (tab.group_id != group)
            continue;
        single = &tab;
        ++count;
    }
    if (count == 1 && single) {
        std::string label = single->filename.empty() ? "Untitled" : single->filename;
        if (single->dirty)
            label.append(" *");
        if (single->pinned)
            label.append(" [Pinned]");
        if (single->external_conflict)
            label.append(" [Disk conflict]");
        if (single->proposal_pending)
            label.append(" [Review]");
        return label;
    }
    std::string label = "Editor";
    if (group != 0)
        label.append(" - Group ").append(std::to_string(group + 1));
    return label;
}

std::string code_document_tab_label(const OpenTab& tab) {
    std::string label = tab.filename.empty() ? "Untitled" : tab.filename;
    if (tab.pinned)
        label.append(" [Pinned]");
    if (tab.external_conflict)
        label.append(" [Disk conflict]");
    if (tab.proposal_pending)
        label.append(" [Review]");
    label.append("###aida.code.document.").append(std::to_string(tab.document_id));
    return label;
}

void reorder_code_document(std::uint64_t source_document,
                           std::uint64_t target_document,
                           bool insert_after) {
    if (source_document == 0 || target_document == 0 ||
        source_document == target_document)
        return;
    file_tabs::normalize_document_identities();
    int source = file_tabs::find_document(source_document);
    int target = file_tabs::find_document(target_document);
    if (!file_tabs::is_valid_tab_index(source) ||
        !file_tabs::is_valid_tab_index(target) ||
        file_tabs::tabs[file_tabs::tab_index(source)].group_id !=
            file_tabs::tabs[file_tabs::tab_index(target)].group_id)
        return;
    const std::uint64_t active_document = file_tabs::is_valid_tab_index(file_tabs::active_tab)
        ? file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)].document_id
        : 0;
    std::size_t insertion = file_tabs::tab_index(target) + (insert_after ? 1U : 0U);
    if (file_tabs::tab_index(source) < insertion)
        --insertion;
    OpenTab moved = std::move(file_tabs::tabs[file_tabs::tab_index(source)]);
    file_tabs::tabs.erase(file_tabs::tabs.begin() + source);
    file_tabs::tabs.insert(file_tabs::tabs.begin() +
        static_cast<std::vector<OpenTab>::difference_type>(insertion), std::move(moved));
    file_tabs::active_tab = file_tabs::find_document(active_document);
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

view_operation_result_t prepare_code_group_close(const view_instance_id_t& instance) {
    std::uint32_t group = 0;
    if (!parse_code_group(instance.instance, group))
        return {view_operation_status_t::invalid_instance,
            "The editor group identity is invalid"};
    for (const auto& tab : file_tabs::tabs) {
        if (tab.group_id != group)
            continue;
        if (tab.pinned)
            return {view_operation_status_t::unavailable,
                "Unpin every document in this editor group before closing it"};
        if (tab.dirty) {
            const int index = file_tabs::find_document(tab.document_id);
            if (index >= 0) {
                file_tabs::pending_close_idx = index;
                file_tabs::show_close_confirm = true;
            }
            return {view_operation_status_t::unavailable,
                "Review the unsaved document before closing this editor group"};
        }
    }
    return {};
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

    std::size_t group_count = 0;
    for (const auto& tab : file_tabs::tabs)
        if (tab.group_id == group)
            ++group_count;

    int close_index = -1;
    std::uint64_t reorder_source = 0;
    std::uint64_t reorder_target = 0;
    bool reorder_after = false;
    if (group_count > 1 && ImGui::BeginTabBar("##aida_code_group_tabs",
            ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_FittingPolicyScroll)) {
        for (std::size_t raw_index = 0; raw_index < file_tabs::tabs.size(); ++raw_index) {
            auto& tab = file_tabs::tabs[raw_index];
            if (tab.group_id != group)
                continue;
            bool open = true;
            const std::string tab_label = code_document_tab_label(tab);
            ImGuiTabItemFlags flags = ImGuiTabItemFlags_None;
            if (tab.dirty)
                flags |= ImGuiTabItemFlags_UnsavedDocument;
            if (static_cast<int>(raw_index) == selected)
                flags |= ImGuiTabItemFlags_SetSelected;
            const bool visible = ImGui::BeginTabItem(
                tab_label.c_str(), tab.pinned ? nullptr : &open, flags);
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
            const std::uint64_t document_id = tab.document_id;
            if (ImGui::BeginDragDropSource(ImGuiDragDropFlags_SourceAllowNullID)) {
                ImGui::SetDragDropPayload("AIDA_EDITOR_DOCUMENT",
                    &document_id, sizeof(document_id));
                ImGui::TextUnformatted(tab.filename.empty() ? "Untitled" : tab.filename.c_str());
                ImGui::EndDragDropSource();
            }
            if (ImGui::BeginDragDropTarget()) {
                if (const ImGuiPayload* payload =
                        ImGui::AcceptDragDropPayload("AIDA_EDITOR_DOCUMENT")) {
                    if (payload->DataSize == static_cast<int>(sizeof(std::uint64_t))) {
                        reorder_source = *static_cast<const std::uint64_t*>(payload->Data);
                        reorder_target = document_id;
                        reorder_after = ImGui::GetIO().MousePos.x >
                            (ImGui::GetItemRectMin().x + ImGui::GetItemRectMax().x) * 0.5f;
                    }
                }
                ImGui::EndDragDropTarget();
            }
            if (visible) {
                if ((ImGui::IsItemActivated() ||
                     ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) &&
                    file_tabs::active_tab != static_cast<int>(raw_index)) {
                    file_tabs::switch_to(static_cast<int>(raw_index));
                }
                selected = static_cast<int>(raw_index);
                file_tabs::active_document_by_group[group] = tab.document_id;
                ImGui::EndTabItem();
            }
            if (!open)
                close_index = static_cast<int>(raw_index);
        }
        ImGui::EndTabBar();
    }

    application_ui::render_editor_tab_context_menu();
    if (reorder_source != 0)
        reorder_code_document(reorder_source, reorder_target, reorder_after);
    if (close_index >= 0) {
        request_code_tab_close(close_index);
        return;
    }
    selected = file_tabs::active_in_group(group);
    if (!file_tabs::is_valid_tab_index(selected)) {
        return;
    }

    auto& selected_tab = file_tabs::tabs[file_tabs::tab_index(selected)];
    const auto render_tab_action = [selected](const char* action_id,
            const char* label, bool small) {
        const auto presentation = application_ui::present_editor_tab_action(
            selected, action_id);
        if (!presentation.visible)
            return false;
        ImGui::BeginDisabled(!presentation.enabled);
        const bool clicked = small ? ImGui::SmallButton(label) : ImGui::Button(label);
        ImGui::EndDisabled();
        const char* detail = !presentation.enabled && !presentation.disabled_reason.empty()
            ? presentation.disabled_reason.c_str() : presentation.description.c_str();
        design::tooltip_for_last_item(detail,
            presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str());
        if (clicked)
            static_cast<void>(application_ui::execute_editor_tab_action(selected,
                action_id, action_invocation_source_t::toolbar));
        return clicked;
    };
    file_tabs::observe_document_load_dispatch_failure(selected);
    file_tabs::observe_document_save_dispatch_failure(selected);
    if (!selected_tab.buffer_loaded) {
        ImGui::BeginChild("##aida_document_load_state", ImVec2(0.f, 0.f), false,
            ImGuiWindowFlags_NoSavedSettings);
        if (selected_tab.load_in_progress) {
            ImGui::TextDisabled("Loading %s asynchronously...", selected_tab.filename.c_str());
            ImGui::TextWrapped("The editor remains responsive while this bounded file read completes.");
            render_tab_action("tab.load.cancel", "Cancel Load", false);
        } else {
            ImGui::TextUnformatted("Document could not be loaded");
            ImGui::TextWrapped("%s", selected_tab.load_error.empty()
                ? "The file is unavailable or the load did not start."
                : selected_tab.load_error.c_str());
            render_tab_action("tab.load.retry", "Retry", false);
            ImGui::SameLine();
            render_tab_action("tab.close", "Close", false);
        }
        ImGui::EndChild();
        return;
    }
	file_tabs::observe_recovery_dispatch_failure(selected);
	if (selected_tab.save_in_progress || !selected_tab.save_error.empty()) {
		if (ImGui::BeginChild("##aida_document_save_state", ImVec2(0.f, 34.f), true,
				ImGuiWindowFlags_NoSavedSettings)) {
			if (selected_tab.save_in_progress)
				ImGui::TextDisabled("Saving %s in Task Center...", selected_tab.filename.c_str());
			else
				ImGui::TextWrapped("Save: %s", selected_tab.save_error.c_str());
		}
		ImGui::EndChild();
	}
    file_tabs::request_recovery_probe(selected);
    if (selected_tab.recovery_operation_pending) {
        if (ImGui::BeginChild("##aida_document_recovery_busy", ImVec2(0.f, 30.f), true,
                ImGuiWindowFlags_NoSavedSettings))
            ImGui::TextDisabled("%s...", selected_tab.recovery_operation_label.empty()
                ? "Working with recovery storage"
                : selected_tab.recovery_operation_label.c_str());
        ImGui::EndChild();
    }
    if (!selected_tab.recovery.available && selected_tab.recovery_probe_completed &&
        !selected_tab.recovery_error.empty()) {
        if (ImGui::BeginChild("##aida_document_recovery_error", ImVec2(0.f, 52.f), true,
                ImGuiWindowFlags_NoSavedSettings)) {
            ImGui::TextWrapped("Recovery storage: %s", selected_tab.recovery_error.c_str());
            ImGui::SameLine();
            render_tab_action("tab.recovery.retry_probe",
                "Retry Recovery Check", true);
        }
        ImGui::EndChild();
    }
    if (selected_tab.recovery.available) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.06f, 0.15f, 0.24f, 0.96f));
        if (ImGui::BeginChild("##aida_document_recovery", ImVec2(0.f, 70.f), true,
                ImGuiWindowFlags_NoSavedSettings)) {
            ImGui::TextUnformatted("A verified unsaved recovery journal is available.");
            ImGui::SameLine();
            ImGui::TextDisabled("rev %llu | %llu bytes | %s / %s / %s",
                static_cast<unsigned long long>(selected_tab.recovery.metadata.revision),
                static_cast<unsigned long long>(selected_tab.recovery.metadata.byte_length),
                selected_tab.recovery.metadata.text.encoding.c_str(),
                selected_tab.recovery.metadata.text.bom.c_str(),
                selected_tab.recovery.metadata.text.eol.c_str());
            render_tab_action("tab.recovery.recover", "Recover Unsaved Content", true);
            ImGui::SameLine();
            render_tab_action("tab.recovery.compare", "Compare", true);
            ImGui::SameLine();
            render_tab_action("tab.recovery.discard", "Discard Recovery", true);
            if (!selected_tab.recovery_error.empty()) {
                ImGui::SameLine();
                ImGui::TextDisabled("%s", selected_tab.recovery_error.c_str());
            }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            aida::preview::semantics::register_last_item(
                aida::preview::semantics::stable_id("aida.editor.recovery",
                    "document-" + std::to_string(selected_tab.document_id)),
                "editor-recovery-actions");
#endif
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
    if (file_tabs::pending_recovery_discard_document == selected_tab.document_id &&
        !ImGui::IsPopupOpen("Discard Recovery###aida.editor.recovery.discard"))
        design::open_dialog("aida.editor.recovery.discard", "Discard Recovery");
    if (design::begin_dialog("aida.editor.recovery.discard", "Discard Recovery",
            ImVec2(640.0f, 370.0f), ImVec2(460.0f, 300.0f))) {
        const int target_index = file_tabs::find_document(
            file_tabs::pending_recovery_discard_document);
        const bool target_current = file_tabs::is_valid_tab_index(target_index) &&
            file_tabs::tabs[file_tabs::tab_index(target_index)].recovery.available;
        const std::string target = target_current
            ? (file_tabs::tabs[file_tabs::tab_index(target_index)].filename.empty()
                ? "Untitled document" : file_tabs::tabs[file_tabs::tab_index(target_index)].filename)
            : "Unavailable document";
        const float footer_height = design::dialog_footer_reserve_height(
            "Permanently Discard Recovery", "Cancel");
        design::begin_dialog_body("editor_recovery_discard_body", footer_height);
        const std::string discard_title = "Discard recovery for " + target + "?";
        design::text(design::text_role_t::title,
            discard_title.c_str());
        ImGui::TextWrapped("Scope: The current and retained last-good recovery journals for this document.");
        ImGui::TextWrapped("Effect: Permanently removes the verified unsaved recovery content; the open editor buffer and disk file are unchanged.");
        ImGui::TextWrapped("Recovery: The discarded recovery journals cannot be reconstructed after confirmation.");
        if (!target_current)
            ImGui::TextWrapped("Required before continuing: The document or its verified recovery identity changed before confirmation.");
        design::end_dialog_body();
        const auto footer = design::dialog_footer(
            "editor_recovery_discard_footer", "Permanently Discard Recovery",
            target_current, true);
        if (footer.confirmed && target_current) {
            const auto discarded = file_tabs::discard_recovery(target_index);
            if (discarded.succeeded) {
                file_tabs::pending_recovery_discard_document = 0;
                ImGui::CloseCurrentPopup();
            } else if (file_tabs::is_valid_tab_index(target_index)) {
                file_tabs::tabs[file_tabs::tab_index(target_index)].recovery_error =
                    discarded.detail;
            }
        } else if (footer.cancelled) {
            file_tabs::pending_recovery_discard_document = 0;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    if (selected_tab.external_conflict) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.24f, 0.12f, 0.04f, 0.92f));
        if (ImGui::BeginChild("##aida_external_change", ImVec2(0.f, 48.f), true)) {
            ImGui::TextUnformatted("The file changed on disk. AiDA will not overwrite it without your decision.");
            ImGui::SameLine();
            render_tab_action("tab.compare_disk", "Compare", true);
            ImGui::SameLine();
            render_tab_action("tab.external.reload", "Reload from Disk", true);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const std::string reload_semantic_id = aida::preview::semantics::stable_id(
                "aida.editor.external", "reload-document-" + std::to_string(selected_tab.document_id));
            aida::preview::semantics::register_last_item(
                reload_semantic_id, "editor-conflict-action");
#endif
            ImGui::SameLine();
            render_tab_action("tab.external.keep_editor", "Keep Editor Version", true);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const std::string keep_semantic_id = aida::preview::semantics::stable_id(
                "aida.editor.external", "keep-document-" + std::to_string(selected_tab.document_id));
            aida::preview::semantics::register_last_item(
                keep_semantic_id, "editor-conflict-action");
#endif
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    code_editor_widget::document_pane_render_context_t render_context;
    render_context.document_id = selected_tab.document_id;
    render_context.revision = selected_tab.revision;
    render_context.content = selected_tab.buffer;
    render_context.filename = selected_tab.filename;
    render_context.filepath = selected_tab.filepath;
    render_context.dirty = selected_tab.dirty;
    render_context.caret_line = selected_tab.caret_line;
    render_context.caret_column = selected_tab.caret_column;
    render_context.selection_anchor_line = selected_tab.selection_anchor_line;
    render_context.selection_anchor_column = selected_tab.selection_anchor_column;
    render_context.selection_active = selected_tab.selection_active;
    render_context.scroll_x = selected_tab.scroll_x;
    render_context.scroll_y = selected_tab.scroll_y;
    render_context.folded_lines = &selected_tab.folded_lines;
    render_context.language_override = selected_tab.language_override;
    render_context.read_only = selected_tab.streamed_document ||
        selected_tab.buffer.size() >
            aida::editor::programming_documents::maximum_editable_document_bytes;
    render_context.read_only_reason = render_context.read_only
        ? "Files above 1 MiB through 500 MiB are searchable memory-mapped views; editing is disabled to preserve frame pacing and exact crash recovery."
        : std::string_view{};
    render_context.accent_r = globals::ui::accent.x;
    render_context.accent_g = globals::ui::accent.y;
    render_context.accent_b = globals::ui::accent.z;
    code_editor_widget::render_document_pane(render_context);

    const auto editor_state = code_editor_widget::document_state(selected_tab.document_id);
    if (editor_state.focused && file_tabs::active_tab != selected) {
        file_tabs::active_tab = selected;
        file_tabs::active_document_by_group[group] = selected_tab.document_id;
    }
    const auto metadata = code_editor_widget::document_metadata(selected_tab.document_id);
    if (metadata.found) {
        selected_tab.revision = metadata.revision;
        selected_tab.dirty = metadata.dirty;
        selected_tab.caret_line = metadata.caret_line;
        selected_tab.caret_column = metadata.caret_column;
        selected_tab.selection_anchor_line = metadata.selection_anchor_line;
        selected_tab.selection_anchor_column = metadata.selection_anchor_column;
        selected_tab.selection_active = metadata.selection_active;
        selected_tab.scroll_x = metadata.scroll_x;
        selected_tab.scroll_y = metadata.scroll_y;
        selected_tab.folded_lines = metadata.folded_lines;
        selected_tab.language_override = metadata.language_override;
        selected_tab.proposal_pending = metadata.proposal_pending;
        if (metadata.dirty)
            selected_tab.content_hash = 0;
    }
    file_tabs::checkpoint_recovery(selected);
}

void synchronize_code_groups(state_t& current) {
    file_tabs::normalize_document_identities();
    std::set<std::uint32_t> groups;
    for (const auto& tab : file_tabs::tabs)
        groups.insert(tab.group_id);

    for (const std::uint32_t group : groups) {
        const view_instance_id_t instance{stable_view_id_t("document.code"),
            stable_view_instance_key_t(file_tabs::group_instance_key(group))};
        if (current.registry.is_open(instance))
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
    case catalog_subview_t::scan:
        scan_hub_view::set_sub_tab(static_cast<scan_hub_view::sub_tab_t>(entry.subview_value));
        break;
    case catalog_subview_t::types:
        types_hub_view::set_sub_tab(static_cast<types_hub_view::sub_tab_t>(entry.subview_value));
        break;
    case catalog_subview_t::analysis:
        analysis_hub_view::set_sub_tab(static_cast<analysis_hub_view::sub_tab_t>(entry.subview_value));
        break;
    case catalog_subview_t::debugger:
        debugger_view::g_ui.prev_tab = debugger_view::g_ui.active_tab;
        debugger_view::g_ui.active_tab = static_cast<debugger_view::sub_tab_t>(entry.subview_value);
        break;
    case catalog_subview_t::network:
        network_view::g_state.active_tab = static_cast<network_view::sub_tab_t>(entry.subview_value);
        break;
    case catalog_subview_t::none:
        break;
    }
}

void activate(const catalog_entry_t& entry) {
    select_subview(entry);
}

}

void initialize() {
    auto& current = state();
    if (current.initialized)
        return;
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
        if (std::strcmp(entry.id, "view.types.dissector") == 0) {
            descriptor.persistence_version = 2;
            descriptor.persistence_aliases.emplace_back("view.types.live_inspector");
        } else if (std::strcmp(entry.id, "view.mcp_log") == 0) {
            descriptor.persistence_version = 2;
            descriptor.persistence_aliases.emplace_back("view.ai.mcp_activity");
        }
        descriptor.default_open = entry.default_open;
        descriptor.closeable = entry.closeable;
        descriptor.render_ownership = entry.owner == catalog_owner_t::registry
            ? view_render_ownership_t::registry_window
            : view_render_ownership_t::legacy_adapter;
        if (std::strcmp(entry.id, "view.start_center") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_start_center(); };
        else if (std::strcmp(entry.id, "view.project_explorer") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_project_explorer(); };
        else if (std::strcmp(entry.id, "view.workspace_search") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_workspace_search(); };
        else if (std::strcmp(entry.id, "view.recent") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_recent(); };
        else if (std::strcmp(entry.id, "view.sessions") == 0)
            descriptor.render = [](const view_render_context_t&) { explorer_views::render_sessions(); };
        else if (std::strcmp(entry.id, "view.output") == 0)
            descriptor.render = [](const view_render_context_t& context) {
                output_views::render(bottom_tab_t::output,
                    context.instance.view.value(), context.instance.instance.value());
            };
        else if (std::strcmp(entry.id, "view.mcp_log") == 0)
            descriptor.render = [](const view_render_context_t& context) {
                output_views::render(bottom_tab_t::mcp_log,
                    context.instance.view.value(), context.instance.instance.value());
            };
        else if (std::strcmp(entry.id, "view.driver_log") == 0)
            descriptor.render = [](const view_render_context_t& context) {
                output_views::render(bottom_tab_t::driver_log,
                    context.instance.view.value(), context.instance.instance.value());
            };
        else if (std::strcmp(entry.id, "view.sandbox_log") == 0)
            descriptor.render = [](const view_render_context_t& context) {
                output_views::render(bottom_tab_t::sandbox_log,
                    context.instance.view.value(), context.instance.instance.value());
            };
        else if (std::strcmp(entry.id, "view.terminal") == 0)
            descriptor.render = [](const view_render_context_t& context) {
                output_views::render(bottom_tab_t::terminal,
                    context.instance.view.value(), context.instance.instance.value());
            };
        else if (std::strcmp(entry.id, "view.programming.outline") == 0)
            descriptor.render = [](const view_render_context_t&) {
                programming_language_views::render_outline();
            };
        else if (std::strcmp(entry.id, "view.programming.references") == 0)
            descriptor.render = [](const view_render_context_t&) {
                programming_language_views::render_references();
            };
        else if (std::strcmp(entry.id, "view.programming.source_debug_console") == 0)
            descriptor.render = [](const view_render_context_t&) {
                programming_language_views::render_source_debug_console();
            };
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
            descriptor.render = [](const view_render_context_t& context) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                disasm_view::render(0.f, 0.f, (std::max)(available.x, 1.f),
                    (std::max)(available.y, 1.f), 1.f, globals::ui::accent.x,
                    globals::ui::accent.y, globals::ui::accent.z,
                    disasm_view::capture_selected_workspace(
                        context.instance.instance.value()), ImGui::GetIO().DeltaTime);
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
        else if (std::strcmp(entry.id, "view.analysis.imports") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_list_views::render(analysis_list_views::domain_t::imports);
            };
        else if (std::strcmp(entry.id, "view.analysis.exports") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_list_views::render(analysis_list_views::domain_t::exports);
            };
        else if (std::strcmp(entry.id, "view.analysis.names") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_list_views::render(analysis_list_views::domain_t::names);
            };
        else if (std::strcmp(entry.id, "view.analysis.strings") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_list_views::render(analysis_list_views::domain_t::strings);
            };
        else if (std::strcmp(entry.id, "view.analysis.segments") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_list_views::render(analysis_list_views::domain_t::segments);
            };
        else if (std::strcmp(entry.id, "view.analysis.local_types") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_list_views::render(analysis_list_views::domain_t::local_types);
            };
        else if (std::strcmp(entry.id, "view.analysis.segment_registers") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_relationship_views::segment_registers::render();
            };
        else if (std::strcmp(entry.id, "view.analysis.proximity") == 0)
            descriptor.render = [](const view_render_context_t&) {
                analysis_relationship_views::proximity::render();
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
                 entry.subview == catalog_subview_t::analysis)
            descriptor.render = [tab = static_cast<analysis_hub_view::sub_tab_t>(
                entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                const ImVec2 cursor = ImGui::GetCursorPos();
                analysis_hub_view::render_subview(tab, cursor.x, cursor.y,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f),
                    1.f, globals::ui::accent.x, globals::ui::accent.y,
                    globals::ui::accent.z, disasm_view::capture_selected_workspace());
            };
        else if (entry.category == view_category_t::memory && entry.subview == catalog_subview_t::scan)
            descriptor.render = [tab = static_cast<scan_hub_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                const ImVec2 cursor = ImGui::GetCursorPos();
                scan_hub_view::render_subview(tab, cursor.x, cursor.y,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (entry.category == view_category_t::types && entry.subview == catalog_subview_t::types)
            descriptor.render = [tab = static_cast<types_hub_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                types_hub_view::render_subview(tab, 0.f, 0.f,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (std::strcmp(entry.id, "view.types.struct_recon") == 0)
            descriptor.render = [](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                const ImVec2 cursor = ImGui::GetCursorPos();
                struct_recon_view::render(cursor.x, cursor.y,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (entry.category == view_category_t::debugger && entry.subview == catalog_subview_t::debugger)
            descriptor.render = [tab = static_cast<debugger_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                const ImVec2 cursor = ImGui::GetCursorPos();
                const float width = (std::max)(available.x, 1.f);
                const float height = (std::max)(available.y, 1.f);
                float content_y = cursor.y;
                if (tab == debugger_view::sub_tab_t::cpu) {
                    const float controls_height = (std::min)(72.f, height * 0.24f);
                    debugger_view::render_execution_controls(cursor.x, cursor.y, width, controls_height, 1.f,
                        globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
                    content_y = controls_height + 4.f;
                    content_y += cursor.y;
                }
                const float consumed = content_y - cursor.y;
                debugger_view::render_pane(tab, cursor.x, content_y, width,
                    (std::max)(height - consumed, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (entry.category == view_category_t::network && entry.subview == catalog_subview_t::network)
            descriptor.render = [tab = static_cast<network_view::sub_tab_t>(entry.subview_value)](const view_render_context_t&) {
                const ImVec2 available = ImGui::GetContentRegionAvail();
                const ImVec2 cursor = ImGui::GetCursorPos();
                network_view::render_pane(tab, cursor.x, cursor.y,
                    (std::max)(available.x, 1.f), (std::max)(available.y, 1.f), 1.f,
                    globals::ui::accent.x, globals::ui::accent.y, globals::ui::accent.z);
            };
        else if (std::strcmp(entry.id, "view.network.project") == 0)
            descriptor.render = [](const view_render_context_t&) {
                aida::burp::project_view::render();
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
        else if (std::strcmp(entry.id, "view.ai.scripts") == 0)
            descriptor.render = [](const view_render_context_t&) {
                programming_tasks::render_automation_scripts();
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
        if (!descriptor.render) {
            const std::string missing_name = descriptor.display_name;
            descriptor.render = [missing_name](const view_render_context_t&) {
                const std::string message = missing_name +
                    " has no registered renderer in this build and cannot be opened safely.";
                design::state_presentation_t state;
                state.stable_id = "view.renderer.unavailable";
                state.state = design::view_state_t::error;
                state.title = "View renderer unavailable";
                state.message = message.c_str();
                state.hint = "Use the View menu to open another canonical surface.";
                static_cast<void>(design::render_state(state, ImGui::GetContentRegionAvail()));
            };
            descriptor.capability = [missing_name](const interaction_context_t&) {
                return capability_state_t::unavailable(missing_name +
                    " has no registered renderer in this build");
            };
        } else {
            descriptor.capability = [id = descriptor.id,
                requires_workspace = entry.requires_workspace](const interaction_context_t&) {
                if (id.value() == "document.image" &&
                    !image_view::g_state().active.load(std::memory_order_acquire))
                    return capability_state_t::unavailable("Open an image file first");
                return !requires_workspace || workspace_available()
                    ? capability_state_t::available()
                    : capability_state_t::unavailable("Open and analyze a binary first");
            };
        }
        descriptor.activate = [id = descriptor.id](const view_instance_id_t&) {
            if (const auto* catalog = find_catalog(id))
                activate(*catalog);
        };
        if (descriptor.id.value() == "document.code") {
            descriptor.deactivate = [](const view_instance_id_t& instance) {
                close_code_group(instance);
            };
        }
        current.registry.register_view(std::move(descriptor));
    }
    for (const auto& entry : k_catalog) {
        if (entry.owner == catalog_owner_t::registry && entry.default_open)
            current.registry.open(instance_for(entry), current.context);
    }
    if (g_sa_settings.workspace.legacy_bottom_visible) {
        if (const auto* migrated = find_catalog(stable_view_id_t("view.output")))
            current.registry.open(instance_for(*migrated), current.context);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        g_sa_settings.workspace.legacy_bottom_visible = false;
        static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#endif
    }
    task_center::register_views(current.registry);
    install_surface_settings_handler();
    current.initialized = true;
}

view_registry_t& registry() {
    initialize();
    return state().registry;
}

std::string ensure_window_name(const stable_view_id_t& id) {
    initialize();
    const stable_view_id_t target = canonical_view_id(id);
    const auto* descriptor = state().registry.find_descriptor(target);
    if (!descriptor)
        return {};
    const auto* entry = find_catalog(target);
    const view_instance_id_t instance = entry
        ? instance_for(*entry)
        : view_instance_id_t{target,
            descriptor->identity_policy == view_identity_policy_t::multi_instance
                ? stable_view_instance_key_t("primary")
                : stable_view_instance_key_t{}};
    const auto result = state().registry.ensure_identity(instance);
    return result.ok() ? state().registry.window_name(instance) : std::string{};
}

std::optional<stable_view_id_t> stable_subview_id(view_category_t category, int subview) {
    initialize();
    if (subview < 0)
        return std::nullopt;
    for (const auto& entry : k_catalog) {
        if (entry.category == category && entry.subview != catalog_subview_t::none &&
            entry.subview_value == subview)
            return stable_view_id_t(entry.id);
    }
    return std::nullopt;
}

bool synchronize_workspace_visibility(
    workspace_layout::workspace_preset_t preset) noexcept {
    try {
        initialize();
        auto& current = state();
        const std::string identity = workspace_layout::active_identity_key();
        const bool changed = !current.workspace_preset_observed ||
            preset != current.observed_workspace_preset ||
            identity != current.observed_workspace_identity;
        if (!changed)
            return false;
        if (current.workspace_preset_observed)
            capture_workspace_visibility(current, current.observed_workspace_preset,
                current.observed_workspace_identity);
        current.workspace_preset_observed = true;
        current.observed_workspace_preset = preset;
        current.observed_workspace_identity = identity;
        restore_workspace_visibility(current, preset, identity);
        current.visibility_capture_valid = false;
        if (preset == workspace_layout::workspace_preset_t::safe) {
            if (const auto* entry = find_catalog(stable_view_id_t("view.start_center")))
                current.registry.open_or_focus(instance_for(*entry), current.context);
            current.start_center_auto_open = false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

void begin_frame() noexcept {
    try {
        initialize();
        auto& current = state();
        ++current.context.generation;
        for (auto& [id, surface] : current.surfaces) {
            if (!is_disassembly_side_instance(id))
                continue;
            if (surface.restore_open && workspace_available() &&
                !current.registry.is_open(id))
                static_cast<void>(current.registry.open(id, current.context,
                    "Disassembly: Side " + id.instance.value().substr(5)));
            if (surface.restore_open && workspace_available() &&
                surface.presentation_pending &&
                disasm_view::restore_selected_presentation(
                    id.instance.value(), surface.presentation))
                surface.presentation_pending = false;
        }
        file_tabs::poll_external_changes();
        synchronize_code_groups(current);
        task_center::refresh();
        const auto preset = workspace_layout::active_preset();
        const bool preset_changed = synchronize_workspace_visibility(preset);
        if (!preset_changed)
            retry_deferred_workspace_opens(current);
        if (current.start_center_auto_open &&
            (workspace_available() || analysis_session::session_count() != 0 ||
             !file_tabs::tabs.empty())) {
            if (const auto* entry = find_catalog(stable_view_id_t("view.start_center"))) {
                const auto instance = instance_for(*entry);
                if (current.registry.is_open(instance))
                    current.registry.close(instance);
            }
            current.start_center_auto_open = false;
        }
        capture_workspace_visibility(current, preset,
            workspace_layout::active_identity_key());
    } catch (...) {
    }
}

void reset_persisted_workspace_visibility(
    workspace_layout::workspace_preset_t preset, bool all_presets) noexcept {
    try {
        initialize();
        nlohmann::json root = read_workspace_visibility_root();
        if (!root.contains("presets") || !root["presets"].is_object())
            root["presets"] = nlohmann::json::object();
        if (all_presets)
            root["presets"] = nlohmann::json::object();
        else {
            root["presets"].erase("builtin:" + workspace_preset_key(preset));
            root["presets"].erase(workspace_preset_key(preset));
        }
        root["version"] = 3;
        const std::string serialized = root.dump();
        if (serialized.size() > kMaximumWorkspaceVisibilityBytes)
            return;
        g_sa_settings.workspace.view_visibility_json = serialized;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#endif
        if (all_presets || workspace_layout::active_preset() == preset) {
            auto& current = state();
            current.visibility_capture_valid = false;
            current.workspace_preset_observed = false;
            current.observed_workspace_identity.clear();
            current.workspace_visibility.clear();
            current.deferred_workspace_opens.clear();
        }
    } catch (...) {
    }
}

void clone_persisted_workspace_visibility(std::string_view source_identity,
    std::string_view target_identity) noexcept {
    try {
        if (source_identity.empty() || target_identity.empty() || source_identity == target_identity)
            return;
        initialize();
        state().visibility_capture_valid = false;
        nlohmann::json root = read_workspace_visibility_root();
        if (!root.contains("presets") || !root["presets"].is_object())
            root["presets"] = nlohmann::json::object();
        if (!root["presets"].contains(std::string(source_identity))) {
            capture_workspace_visibility(state(), workspace_layout::active_preset(), source_identity);
            root = read_workspace_visibility_root();
        }
        if (!root.contains("presets") || !root["presets"].is_object())
            return;
        auto& refreshed = root["presets"];
        if (!refreshed.contains(std::string(source_identity)))
            return;
        refreshed[std::string(target_identity)] = refreshed[std::string(source_identity)];
        root["version"] = 3;
        const std::string serialized = root.dump();
        if (serialized.size() > kMaximumWorkspaceVisibilityBytes)
            return;
        g_sa_settings.workspace.view_visibility_json = serialized;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#endif
        state().workspace_preset_observed = false;
        state().visibility_capture_valid = false;
    } catch (...) {
    }
}

void rename_persisted_workspace_visibility(std::string_view source_identity,
    std::string_view target_identity) noexcept {
    try {
        if (source_identity.empty() || target_identity.empty() || source_identity == target_identity)
            return;
        initialize();
        nlohmann::json root = read_workspace_visibility_root();
        if (!root.contains("presets") || !root["presets"].is_object())
            return;
        auto& entries = root["presets"];
        const std::string source(source_identity);
        const std::string target(target_identity);
        if (!entries.contains(source))
            return;
        entries[target] = std::move(entries[source]);
        entries.erase(source);
        root["version"] = 3;
        const std::string serialized = root.dump();
        if (serialized.size() > kMaximumWorkspaceVisibilityBytes)
            return;
        g_sa_settings.workspace.view_visibility_json = serialized;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#endif
        state().workspace_preset_observed = false;
        state().visibility_capture_valid = false;
    } catch (...) {
    }
}

void remove_persisted_workspace_visibility(std::string_view identity) noexcept {
    try {
        if (identity.empty())
            return;
        initialize();
        nlohmann::json root = read_workspace_visibility_root();
        if (!root.contains("presets") || !root["presets"].is_object())
            return;
        root["presets"].erase(std::string(identity));
        root["version"] = 3;
        const std::string serialized = root.dump();
        if (serialized.size() > kMaximumWorkspaceVisibilityBytes)
            return;
        g_sa_settings.workspace.view_visibility_json = serialized;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
#endif
        state().workspace_preset_observed = false;
        state().visibility_capture_valid = false;
    } catch (...) {
    }
}

std::string persistence_fingerprint() noexcept {
    try {
        initialize();
        std::uint64_t hash = 14695981039346656037ULL;
        const auto append = [&hash](std::string_view value) {
            for (const char raw_byte : value) {
                const auto byte = static_cast<unsigned char>(raw_byte);
                hash ^= byte;
                hash *= 1099511628211ULL;
            }
            hash ^= 0xFFU;
            hash *= 1099511628211ULL;
        };
        state().registry.for_each_descriptor([&](const view_descriptor_t& descriptor) {
            append(descriptor.id.value());
            append(descriptor.internal_name);
            append(std::to_string(descriptor.persistence_version));
            append(std::to_string(descriptor.preset_introduced_revision));
            append(std::to_string(static_cast<unsigned>(descriptor.category)));
            append(std::to_string(static_cast<unsigned>(descriptor.identity_policy)));
            append(std::to_string(static_cast<unsigned>(descriptor.role)));
            for (const auto& alias : descriptor.persistence_aliases)
                append(alias.value());
        });
        char encoded[17]{};
        const int length = std::snprintf(encoded, sizeof(encoded), "%016llx",
            static_cast<unsigned long long>(hash));
        return length == 16 ? std::string(encoded, 16) : std::string{};
    } catch (...) {
        return {};
    }
}

void migrate_persisted_window_settings() noexcept {
    try {
        initialize();
        ImGuiContext* context = ImGui::GetCurrentContext();
        if (!context)
            return;
        struct migration_t {
            std::string name;
            ImVec2ih pos;
            ImVec2ih size;
            ImVec2ih viewport_pos;
            ImGuiID viewport_id = 0;
            ImGuiID dock_id = 0;
            ImGuiID class_id = 0;
            short dock_order = -1;
            bool collapsed = false;
            bool is_child = false;
        };
        std::vector<migration_t> migrations;
        std::vector<ImGuiID> migrated_old_ids;
        std::vector<ImGuiID> removed_view_ids;
        for (ImGuiWindowSettings* settings = context->SettingsWindows.begin(); settings;
             settings = context->SettingsWindows.next_chunk(settings)) {
            if (settings->WantDelete)
                continue;
            const std::string_view saved_name(settings->GetName());
            const std::size_t hidden_separator = saved_name.find("###");
            const std::string_view saved_identity = hidden_separator == std::string_view::npos
                ? saved_name : saved_name.substr(hidden_separator + 3);
            const std::string_view visible_prefix = hidden_separator == std::string_view::npos
                ? std::string_view{} : saved_name.substr(0, hidden_separator);
            bool migrated = false;
            bool known = false;
            state().registry.for_each_descriptor([&](const view_descriptor_t& descriptor) {
                const std::string& current_prefix = descriptor.internal_name;
                if (saved_identity == current_prefix ||
                    (descriptor.identity_policy == view_identity_policy_t::multi_instance &&
                     saved_identity.size() > current_prefix.size() &&
                     saved_identity.compare(0, current_prefix.size(), current_prefix) == 0 &&
                     saved_identity[current_prefix.size()] == '.'))
                    known = true;
                if (migrated || known)
                    return;
                for (const auto& alias : descriptor.persistence_aliases) {
                    const std::string old_prefix = std::string("aida.") + alias.value();
                    const bool exact = saved_identity == old_prefix;
                    const bool instance = descriptor.identity_policy == view_identity_policy_t::multi_instance &&
                        saved_identity.size() > old_prefix.size() &&
                        saved_identity.compare(0, old_prefix.size(), old_prefix) == 0 &&
                        saved_identity[old_prefix.size()] == '.';
                    if (!exact && !instance)
                        continue;
                    migrated_old_ids.push_back(settings->ID);
                    std::string new_name;
                    if (ImGui::GetIO().ConfigDebugIniSettings && !visible_prefix.empty()) {
                        new_name.assign(visible_prefix);
                        new_name.append("###");
                    } else {
                        new_name.assign("###");
                    }
                    new_name.append(descriptor.internal_name);
                    new_name.append(saved_identity.substr(old_prefix.size()));
                    const ImGuiID new_id = ImHashStr(new_name.c_str());
                    if (!ImGui::FindWindowSettingsByID(new_id)) {
                        migrations.push_back({std::move(new_name), settings->Pos,
                            settings->Size, settings->ViewportPos, settings->ViewportId,
                            settings->DockId, settings->ClassId, settings->DockOrder,
                            settings->Collapsed, settings->IsChild});
                    }
                    migrated = true;
                    break;
                }
            });
            if (!known && !migrated &&
                (saved_identity.rfind("aida.view.", 0) == 0 ||
                 saved_identity.rfind("aida.document.", 0) == 0))
                removed_view_ids.push_back(settings->ID);
        }
        bool completed = true;
        for (const auto& migration : migrations) {
            ImGuiWindowSettings* settings = ImGui::CreateNewWindowSettings(migration.name.c_str());
            if (!settings) {
                completed = false;
                continue;
            }
            settings->Pos = migration.pos;
            settings->Size = migration.size;
            settings->ViewportPos = migration.viewport_pos;
            settings->ViewportId = migration.viewport_id;
            settings->DockId = migration.dock_id;
            settings->ClassId = migration.class_id;
            settings->DockOrder = migration.dock_order;
            settings->Collapsed = migration.collapsed;
            settings->IsChild = migration.is_child;
            settings->WantApply = true;
        }
        if (completed) {
            for (const ImGuiID old_id : migrated_old_ids)
                if (ImGuiWindowSettings* previous = ImGui::FindWindowSettingsByID(old_id))
                    previous->WantDelete = true;
            for (const ImGuiID removed_id : removed_view_ids)
                if (ImGuiWindowSettings* removed = ImGui::FindWindowSettingsByID(removed_id))
                    removed->WantDelete = true;
        }
        if (completed && (!migrated_old_ids.empty() || !removed_view_ids.empty()))
            ImGui::GetIO().WantSaveIniSettings = true;
    } catch (...) {
    }
}

void dismiss_start_center_when_work_available() noexcept {
    try {
        initialize();
        state().start_center_auto_open = true;
    } catch (...) {
    }
}

view_operation_result_t open_or_focus(const stable_view_id_t& id) {
    initialize();
    const stable_view_id_t target = canonical_view_id(id);
    if (target.value() == "view.start_center")
        state().start_center_auto_open = false;
    if (target.value() == "document.code") {
        const auto instance = active_code_instance();
        std::uint32_t group = 0;
        parse_code_group(instance.instance, group);
        return state().registry.open_or_focus(instance, state().context,
            code_group_label(group));
    }
    const auto* entry = find_catalog(target);
    const view_instance_id_t instance = entry
        ? instance_for(*entry)
        : view_instance_id_t{target, {}};
    return state().registry.open_or_focus(instance, state().context);
}

view_operation_result_t open_for_layout(const stable_view_id_t& id) {
    initialize();
    const stable_view_id_t target = canonical_view_id(id);
    if (target.value() == "document.code") {
        const auto instance = active_code_instance();
        std::uint32_t group = 0;
        parse_code_group(instance.instance, group);
        return state().registry.open(instance, state().context, code_group_label(group));
    }
    const auto* entry = find_catalog(target);
    const view_instance_id_t instance = entry
        ? instance_for(*entry)
        : view_instance_id_t{target, {}};
    return state().registry.open(instance, state().context);
}

view_operation_result_t close(const stable_view_id_t& id) {
    initialize();
    const stable_view_id_t target = canonical_view_id(id);
    if (target.value() == "view.start_center")
        state().start_center_auto_open = false;
    if (target.value() == "document.code")
        return close_instance(active_code_instance());
    const auto* entry = find_catalog(target);
    const view_instance_id_t instance = entry
        ? instance_for(*entry)
        : view_instance_id_t{target, {}};
    return close_instance(instance);
}

view_operation_result_t close_instance(const view_instance_id_t& id) {
    initialize();
    const auto* descriptor = state().registry.find_descriptor(id.view);
    if (!descriptor)
        return {view_operation_status_t::not_registered, "The target view is not registered"};
    if (state().surfaces[id].pinned)
        return {view_operation_status_t::unavailable, "Unpin this view before closing it"};
    if (id.view.value() == "document.code") {
        const auto prepared = prepare_code_group_close(id);
        if (!prepared.ok())
            return prepared;
    }
    if (state().title_focused && *state().title_focused == id)
        state().title_focused.reset();
    const auto result = state().registry.close(id);
    if (result.ok() && id.view.value() == "document.disassembly" &&
        !id.instance.empty()) {
        disasm_view::release_presentation(id.instance.value());
        auto& surface = state().surfaces[id];
        surface.restore_open = false;
        surface.presentation_pending = false;
        ImGui::GetIO().WantSaveIniSettings = true;
    }
    return result;
}

view_operation_result_t close_other_instances(const view_instance_id_t& keep) {
    initialize();
    std::vector<view_instance_id_t> targets;
    state().registry.for_each_instance([&](const view_descriptor_t& descriptor,
            const view_instance_state_t& instance) {
        if (!(instance.id == keep) && instance.open && descriptor.closeable &&
            !state().surfaces[instance.id].pinned)
            targets.push_back(instance.id);
    }, true);
    if (targets.empty())
        return {view_operation_status_t::unavailable, "No other closeable unpinned view is open"};
    for (const auto& target : targets) {
        if (target.view.value() != "document.code")
            continue;
        const auto prepared = prepare_code_group_close(target);
        if (!prepared.ok())
            return prepared;
    }
    for (const auto& target : targets) {
        const auto result = close_instance(target);
        if (!result.ok())
            return result;
    }
    return {view_operation_status_t::completed, {}};
}

view_operation_result_t toggle_pin(const view_instance_id_t& id) {
    initialize();
    if (!state().registry.is_open(id))
        return {view_operation_status_t::not_open, "The target view is no longer open"};
    auto& surface = state().surfaces[id];
    surface.pinned = !surface.pinned;
    ImGui::GetIO().WantSaveIniSettings = true;
    return {view_operation_status_t::completed, surface.pinned ? "View pinned" : "View unpinned"};
}

view_operation_result_t request_reset_state(const view_instance_id_t& id) {
    initialize();
    if (!state().registry.is_open(id))
        return {view_operation_status_t::not_open, "The target view is no longer open"};
    state().surfaces[id].reset_requested = true;
    if (id.view.value() == "document.disassembly" && !id.instance.empty())
        disasm_view::reset_presentation(id.instance.value());
    return {view_operation_status_t::completed, {}};
}

view_operation_result_t duplicate_instance(const view_instance_id_t& id) {
    initialize();
    if (id.view.value() != "document.disassembly")
        return {view_operation_status_t::unavailable,
            "This renderer does not declare independent duplicate state"};
    if (!state().registry.is_open(id))
        return {view_operation_status_t::not_open,
            "The source Disassembly view is no longer open"};
    if (!workspace_available())
        return {view_operation_status_t::unavailable,
            "Open and analyze a binary before creating a Disassembly side view"};
    if (workspace_layout::layout_locked())
        return {view_operation_status_t::unavailable,
            "Unlock the workspace layout before opening Disassembly to the side"};
    constexpr unsigned maximum_side_instances = 3;
    for (unsigned index = 1; index <= maximum_side_instances; ++index) {
        const std::string key = "side." + std::to_string(index);
        const view_instance_id_t target{id.view,
            stable_view_instance_key_t(key)};
        if (state().registry.is_open(target))
            continue;
        disasm_view::clone_presentation(id.instance.value(), key);
        const auto result = state().registry.open(target, state().context,
            "Disassembly: Side " + std::to_string(index));
        if (!result.ok()) {
            disasm_view::release_presentation(key);
            return result;
        }
        const auto split = workspace_layout::split_window(
            state().registry.window_name(target), state().registry.window_name(id),
            workspace_layout::dock_split_direction_t::right);
        if (split != workspace_layout::workspace_request_result_t::completed &&
            split != workspace_layout::workspace_request_result_t::unchanged) {
            static_cast<void>(state().registry.close(target));
            disasm_view::release_presentation(key);
            return {view_operation_status_t::unavailable,
                "The source Disassembly dock could not be split; realize the document and unlock the layout before retrying"};
        }
        state().surfaces[target].restore_open = true;
        ImGui::GetIO().WantSaveIniSettings = true;
        return {view_operation_status_t::completed,
            "Opened independent Disassembly side view " + std::to_string(index)};
    }
    return {view_operation_status_t::unavailable,
        "The bounded limit of three Disassembly side views is already open"};
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
        const stable_view_id_t target = canonical_view_id(id);
        if (target.value() == "document.code")
            return state().registry.is_open(active_code_instance());
        const auto* entry = find_catalog(target);
        const view_instance_id_t instance = entry
            ? instance_for(*entry)
            : view_instance_id_t{target, {}};
        return state().registry.is_open(instance);
    } catch (...) {
        return false;
    }
}

bool is_pinned(const view_instance_id_t& id) noexcept {
    try {
        initialize();
        const auto found = state().surfaces.find(id);
        return found != state().surfaces.end() && found->second.pinned;
    } catch (...) {
        return false;
    }
}

bool can_duplicate(const view_instance_id_t& id) noexcept {
    try {
        initialize();
        if (id.view.value() != "document.disassembly" ||
            !state().registry.is_open(id) || !workspace_available() ||
            workspace_layout::layout_locked())
            return false;
        unsigned open_side_instances = 0;
        state().registry.for_each_instance(
            [&](const view_descriptor_t&, const view_instance_state_t& instance) {
                if (instance.open && instance.id.view == id.view &&
                    !instance.id.instance.empty())
                    ++open_side_instances;
            }, true);
        return open_side_instances < 3;
    } catch (...) {
        return false;
    }
}

bool can_reset_state(const view_instance_id_t& id) noexcept {
    try {
        initialize();
        return state().registry.is_open(id);
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

std::string focused_disassembly_presentation_key() noexcept {
    try {
        initialize();
        const auto focused = state().registry.focused_instance();
        if (focused && focused->view.value() == "document.disassembly")
            return focused->instance.value();
    } catch (...) {
    }
    return {};
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
        ImGuiWindow* previous_window = ImGui::FindWindowByName(window_name.c_str());
        const ImGuiWindowSettings* previous_settings = ImGui::FindWindowSettingsByID(
            ImHashStr(window_name.c_str()));
        if (!previous_window && !previous_settings) {
            const ImGuiID target_dock = default_dock_node(*descriptor);
            if (target_dock != 0 && ImGui::DockBuilderGetNode(target_dock) != nullptr)
                ImGui::SetNextWindowDockID(target_dock, ImGuiCond_Appearing);
        }
        if (!previous_window || previous_window->DockId == 0) {
            const ImGuiViewport* placement_viewport = previous_window && previous_window->Viewport
                ? previous_window->Viewport : ImGui::GetMainViewport();
            const float placement_scale = placement_viewport && placement_viewport->DpiScale > 0.0f
                ? placement_viewport->DpiScale : 1.0f;
            ImGui::SetNextWindowSizeConstraints(
                ImVec2(aida::ui::scale_px(descriptor->minimum_size.width, placement_scale),
                    aida::ui::scale_px(descriptor->minimum_size.height, placement_scale)),
                ImVec2(FLT_MAX, FLT_MAX));
        }
        if (current.registry.consume_focus_request(id))
            ImGui::SetNextWindowFocus();
        const bool pinned = is_pinned(id);
        bool open = true;
        const ImGuiWindowFlags placement_flags =
            (workspace_layout::layout_locked() || workspace_layout::operation_pending())
            ? static_cast<ImGuiWindowFlags>(ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize)
            : ImGuiWindowFlags_None;
        const bool content_visible = ImGui::Begin(window_name.c_str(),
            descriptor->closeable && !pinned ? &open : nullptr, placement_flags);
        ImGuiWindow* window = ImGui::GetCurrentWindow();
        const bool owns_visible_content = !window->DockIsActive || window->DockTabIsVisible;
        const bool window_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
        if (window_focused)
            focused = id;
        const ImRect context_rect = window->DockIsActive &&
                window->DC.DockTabItemRect.GetWidth() > 0.0f
            ? window->DC.DockTabItemRect : window->TitleBarRect();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        std::string semantic_identity = id.view.value();
        if (!id.instance.empty())
            semantic_identity.append(".").append(
                aida::preview::semantics::entity_token(id.instance.value()));
        const std::string semantic_window = aida::preview::semantics::stable_id(
            "aida.dock-window", semantic_identity);
        const std::string semantic_tab = aida::preview::semantics::stable_id(
            "aida.dock-tab", semantic_identity);
        if (content_visible && owns_visible_content)
            static_cast<void>(aida::preview::semantics::register_region(semantic_window,
                "dock-window", window->ID, window->Pos,
                ImVec2(window->Pos.x + window->Size.x, window->Pos.y + window->Size.y),
                true));
        const std::string_view semantic_tab_parent = content_visible && owns_visible_content
            ? std::string_view(semantic_window) : std::string_view{};
        static_cast<void>(aida::preview::semantics::register_region(semantic_tab,
            "dock-tab", window->TabId != 0 ? window->TabId : window->ID,
            context_rect.Min, context_rect.Max, true, false, semantic_tab_parent));
#endif
        const bool title_hovered = ImGui::IsMouseHoveringRect(context_rect.Min, context_rect.Max);
        ImGuiContext* gui_context = ImGui::GetCurrentContext();
        const float title_tooltip_delay = (std::max)(ImGui::GetStyle().HoverDelayShort,
            ImGui::GetStyle().HoverStationaryDelay);
        if (title_hovered && gui_context &&
            gui_context->MouseStationaryTimer >= title_tooltip_delay &&
            !ImGui::IsMouseDown(ImGuiMouseButton_Right)) {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(descriptor->display_name.c_str());
            ImGui::Separator();
            ImGui::TextDisabled("%s", id.view.value().c_str());
            if (!id.instance.empty())
                ImGui::TextDisabled("Instance: %s", id.instance.value().c_str());
            ImGui::TextDisabled("Right-click or press Menu / Shift+F10 for view actions");
            ImGui::EndTooltip();
        }
        if (title_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            current.title_focused = id;
        else if (window_focused && ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows) &&
            ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            current.title_focused.reset();
        const bool pointer_context = title_hovered &&
            ImGui::IsMouseClicked(ImGuiMouseButton_Right);
        const bool title_keyboard_focus = window_focused && gui_context &&
            ((current.title_focused && *current.title_focused == id) ||
             gui_context->NavId == window->TabId || gui_context->NavLayer == ImGuiNavLayer_Menu);
        const bool menu_context = title_keyboard_focus && ImGui::IsKeyPressed(ImGuiKey_Menu, false);
        const bool shift_f10_context = title_keyboard_focus && ImGui::GetIO().KeyShift &&
            ImGui::IsKeyPressed(ImGuiKey_F10, false);
        if (pointer_context || menu_context || shift_f10_context)
            application_ui::open_view_surface_context_menu(id,
                pointer_context ? context_menu_open_origin_t::pointer :
                menu_context ? context_menu_open_origin_t::menu_key : context_menu_open_origin_t::shift_f10);
        if (window_focused) {
            const auto& theme = aida::ui::resolved();
            const float scale = window->Viewport && window->Viewport->DpiScale > 0.0f
                ? window->Viewport->DpiScale : 1.0f;
            ImGui::GetForegroundDrawList(window->Viewport)->AddRectFilled(
                ImVec2(context_rect.Min.x + 5.0f * scale, context_rect.Max.y - 2.0f * scale),
                ImVec2(context_rect.Max.x - 5.0f * scale, context_rect.Max.y),
                theme.accent_u32, 1.0f * scale);
        }
        auto surface = current.surfaces.find(id);
        if (surface != current.surfaces.end() && surface->second.reset_requested &&
            content_visible && owns_visible_content) {
            window->StateStorage.Clear();
            ImGui::SetScrollX(0.0f);
            ImGui::SetScrollY(0.0f);
            surface->second.reset_requested = false;
        }
        if (content_visible) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            aida::preview::semantics::scoped_registration_t semantic_registration_scope(
                owns_visible_content);
            aida::preview::semantics::scoped_parent_t semantic_parent_scope(semantic_window);
#endif
            current.context.active_view = id.view;
            current.context.active_view_instance = id.instance;
            const ImVec2 available = ImGui::GetContentRegionAvail();
            const ImVec2 content_min = ImGui::GetCursorScreenPos();
            const ImVec2 content_max(
                content_min.x + (std::max)(available.x, 1.0f),
                content_min.y + (std::max)(available.y, 1.0f));
            ImGui::PushClipRect(content_min, content_max, true);
            const ImVec2 recovery_minimum(
                (std::min)(descriptor->minimum_size.width, 168.0f),
                (std::min)(descriptor->minimum_size.height, 96.0f));
            view_operation_result_t result;
            if (design::tiny_view_required(available, recovery_minimum)) {
                std::string recovery_id = "view.too_small.";
                recovery_id.append(id.view.value());
                if (!id.instance.empty())
                    recovery_id.append(".").append(id.instance.value());
                design::state_presentation_t compact;
                compact.stable_id = recovery_id.c_str();
                compact.state = design::view_state_t::empty;
                compact.title = "View is too small";
                compact.message = "Increase this dock region to restore the complete view.";
                compact.target = descriptor->display_name.c_str();
                compact.hint = "Drag a dock divider, or use the title context menu to float, move, reset, or close this view.";
                static_cast<void>(design::render_state(compact, available));
                result.status = view_operation_status_t::completed;
            } else {
                result = current.registry.render(id, current.context);
            }
            if (!result.ok()) {
                std::string diagnostic_id = "diagnostic.view.render.";
                diagnostic_id.append(id.view.value());
                if (!id.instance.empty())
                    diagnostic_id.append(".").append(id.instance.value());
                design::state_presentation_t failure;
                failure.stable_id = diagnostic_id.c_str();
                failure.state = design::view_state_t::error;
                failure.title = "View could not render";
                failure.message = result.detail.c_str();
                failure.target = window_name.c_str();
                failure.diagnostic_id = diagnostic_id.c_str();
                failure.hint = "Use the panel title menu to reset, move, float, or close this view; persistent failures are retained in Diagnostics.";
                static_cast<void>(design::render_state(failure,
                    ImGui::GetContentRegionAvail()));
                const auto retained = current.render_failures.find(id);
                if (retained == current.render_failures.end() ||
                    retained->second != result.detail) {
                    current.render_failures[id] = result.detail;
                    design::notification_t diagnostic;
                    diagnostic.stable_id = diagnostic_id.c_str();
                    diagnostic.owner = "application.view_registry";
                    diagnostic.target = window_name.c_str();
                    diagnostic.summary = "A dockable view could not render";
                    diagnostic.details = result.detail.c_str();
                    diagnostic.semantic = design::semantic_t::error;
                    diagnostic.attention_required = true;
                    static_cast<void>(design::publish_notification(
                        std::move(diagnostic)));
                }
            } else {
                current.render_failures.erase(id);
            }
            ImGui::PopClipRect();
        }
        application_ui::render_view_surface_context_menu(id);
        ImGui::End();
        if (!open)
            close_instance(id);
    }
    current.registry.update_focus(focused);
    } catch (const std::exception& exception) {
        auto& current = state();
        const std::string detail = exception.what() && *exception.what()
            ? exception.what() : "A dockable view raised an unspecified standard exception";
        if (current.shell_render_exception != detail) {
            current.shell_render_exception = detail;
            design::notification_t diagnostic;
            diagnostic.stable_id = "diagnostic.view_registry.render_exception";
            diagnostic.owner = "application.view_registry";
            diagnostic.target = "Dockable IDE shell";
            diagnostic.summary = "Dockable view rendering terminated unexpectedly";
            diagnostic.details = current.shell_render_exception.c_str();
            diagnostic.semantic = design::semantic_t::error;
            diagnostic.attention_required = true;
            static_cast<void>(design::publish_notification(std::move(diagnostic)));
        }
    } catch (...) {
        auto& current = state();
        const std::string detail = "A dockable view raised a non-standard exception";
        if (current.shell_render_exception != detail) {
            current.shell_render_exception = detail;
            design::notification_t diagnostic;
            diagnostic.stable_id = "diagnostic.view_registry.render_exception";
            diagnostic.owner = "application.view_registry";
            diagnostic.target = "Dockable IDE shell";
            diagnostic.summary = "Dockable view rendering terminated unexpectedly";
            diagnostic.details = current.shell_render_exception.c_str();
            diagnostic.semantic = design::semantic_t::error;
            diagnostic.attention_required = true;
            static_cast<void>(design::publish_notification(std::move(diagnostic)));
        }
    }
}

void for_each_menu_entry(const std::function<void(const menu_entry_t&)>& visitor) {
    if (!visitor)
        return;
    initialize();
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
