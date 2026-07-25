#include "core/ui/workspace_layout.hpp"
#include "core/ui/application_view_registry.hpp"

#include "imgui/imgui_internal.h"
#include "../../preview/studio_semantics.hpp"

#include <algorithm>
#include <cstdint>
#include <array>
#include <cmath>
#include <initializer_list>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace aida::ui::workspace_layout {
namespace {

constexpr std::size_t kMaximumNamedUserLayouts = 4096U;
constexpr std::array<workspace_preset_descriptor_t, 8> kPresetDescriptors{{
    {workspace_preset_t::analysis, "analysis", "Analysis", "Disassembly, pseudocode, graph, symbols, references and inspection", 3},
    {workspace_preset_t::debugging, "debugging", "Debugging", "Execution controls, CPU, registers, breakpoints, threads, stack and trace", 5},
    {workspace_preset_t::memory, "memory", "Memory", "Process sessions, scans, results, memory map, hex, pointers and patches", 5},
    {workspace_preset_t::types_structures, "types-structures", "Types and Structures", "Type catalogs, structure layouts, live values and propagation", 3},
    {workspace_preset_t::network, "network", "Network", "Proxy history, repeater, browser, protocol streams and evidence", 3},
    {workspace_preset_t::automation_ai, "automation-ai", "Automation and AI", "Chat, agents, skills, MCP activity, evidence review and tasks", 4},
    {workspace_preset_t::programming, "programming", "Programming", "Project explorer, source editing, search, terminal, problems and debugging", 4},
    {workspace_preset_t::safe, "safe", "Safe Layout", "Recovery workspace with Start Center, diagnostics and essential navigation", 3}
}};

const workspace_preset_descriptor_t& descriptor_for(workspace_preset_t preset) noexcept
{
    for (const auto& descriptor : kPresetDescriptors) {
        if (descriptor.id == preset)
            return descriptor;
    }
    return kPresetDescriptors.front();
}

bool valid_user_layout_name(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 64 || name.front() == ' ' || name.back() == ' ')
        return false;
    bool previous_space = false;
    for (const char character : name) {
        const auto byte = static_cast<unsigned char>(character);
        if (!(byte >= 'a' && byte <= 'z') &&
            !(byte >= 'A' && byte <= 'Z') &&
            !(byte >= '0' && byte <= '9') &&
            byte != '-' && byte != '_' && byte != ' ')
            return false;
        if (byte == ' ' && previous_space)
            return false;
        previous_space = byte == ' ';
    }
    return true;
}

std::string identity_key(workspace_preset_t preset, std::string_view user_name)
{
    std::string key = user_name.empty() ? "builtin:" : "user:";
    key.append(descriptor_for(preset).stable_id);
    if (!user_name.empty()) {
        key.push_back(':');
        constexpr char digits[] = "0123456789abcdef";
        for (const char character : user_name) {
            const auto byte = static_cast<unsigned char>(character);
            key.push_back(digits[byte >> 4U]);
            key.push_back(digits[byte & 0x0FU]);
        }
    }
    return key;
}

struct layout_ratios_t {
    float left = 0.18f;
    float right = 0.22f;
    float bottom = 0.24f;
};

float declared_minimum_width(std::initializer_list<const char*> stable_ids) noexcept
{
    float width = 0.0f;
    auto& registry = application_views::registry();
    for (const char* stable_id : stable_ids) {
        const auto* descriptor = registry.find_descriptor(stable_view_id_t(stable_id));
        if (descriptor)
            width = (std::max)(width, descriptor->minimum_size.width);
    }
    return width;
}

layout_ratios_t calculate_layout_ratios(workspace_preset_t preset, ImVec2 size,
    float dpi_scale) noexcept
{
    const float desired_left_ratio = preset == workspace_preset_t::memory ? 0.23f :
        preset == workspace_preset_t::automation_ai ? 0.21f :
        preset == workspace_preset_t::debugging || preset == workspace_preset_t::network ? 0.20f : 0.18f;
    const float desired_right_ratio = preset == workspace_preset_t::types_structures ? 0.26f :
        preset == workspace_preset_t::automation_ai ? 0.24f : 0.22f;
    const float desired_bottom_ratio = preset == workspace_preset_t::debugging ? 0.30f :
        preset == workspace_preset_t::network ? 0.28f :
        preset == workspace_preset_t::programming ? 0.25f :
        preset == workspace_preset_t::safe ? 0.18f : 0.24f;
    const float scale = dpi_scale > 0.0f ? dpi_scale : 1.0f;
    const float usable_width = (std::max)(size.x, 1.0f);
    const float usable_height = (std::max)(size.y, 1.0f);
    const bool compact_analysis = preset == workspace_preset_t::analysis &&
        usable_width / scale < 1500.0f;
    const float analysis_left_minimum = declared_minimum_width(
        {"view.project_explorer", "view.navigator", "view.analysis.functions"});
    const float analysis_right_minimum = declared_minimum_width(
        {"view.inspector", "view.analysis.references", "view.ai_chat"});
    const float analysis_center_minimum = declared_minimum_width(
        {"document.disassembly", "document.pseudocode", "document.graph",
         "document.hex", "document.code", "view.analysis.binary_map"});
    const float center_target = preset == workspace_preset_t::analysis
        ? (compact_analysis ? analysis_center_minimum
            : (std::max)(640.0f, analysis_center_minimum)) : 480.0f;
    const float center_minimum = (std::min)(center_target * scale, usable_width * 0.60f);
    const float generic_side_floor = (std::min)(180.0f * scale, usable_width * 0.20f);
    const float left_floor = preset == workspace_preset_t::analysis
        ? (compact_analysis ? (std::min)(260.0f, analysis_left_minimum)
            : analysis_left_minimum) * scale : generic_side_floor;
    const float right_floor = preset == workspace_preset_t::analysis
        ? (compact_analysis ? (std::min)(300.0f, analysis_right_minimum)
            : analysis_right_minimum) * scale : generic_side_floor;
    float left_width = (std::max)(usable_width * desired_left_ratio,
        (std::min)(left_floor, usable_width * 0.28f));
    float right_width = (std::max)(usable_width * desired_right_ratio,
        (std::min)(right_floor, usable_width * 0.34f));
    const float side_budget = (std::max)(0.0f, usable_width - center_minimum);
    const float requested_sides = left_width + right_width;
    if (requested_sides > side_budget && requested_sides > 0.0f) {
        const float contraction = side_budget / requested_sides;
        left_width *= contraction;
        right_width *= contraction;
    }
    layout_ratios_t ratios;
    ratios.left = (std::clamp)(left_width / usable_width, 0.05f, 0.45f);
    const float width_after_left = (std::max)(1.0f, usable_width - left_width);
    ratios.right = (std::clamp)(right_width / width_after_left, 0.05f, 0.55f);
    const float document_height_minimum = (std::min)(300.0f * scale, usable_height * 0.72f);
    const float bottom_floor = (std::min)(140.0f * scale, usable_height * 0.22f);
    const float bottom_height = (std::clamp)(usable_height * desired_bottom_ratio,
        bottom_floor, (std::max)(bottom_floor, usable_height - document_height_minimum));
    ratios.bottom = (std::clamp)(bottom_height / usable_height, 0.08f, 0.45f);
    return ratios;
}

bool compact_single_node_recipe(ImVec2 size, float dpi_scale) noexcept
{
    const float scale = dpi_scale > 0.0f ? dpi_scale : 1.0f;
    return size.x / scale < 900.0f || size.y / scale < 520.0f;
}

const char* compact_primary_view(workspace_preset_t preset) noexcept
{
    switch (preset) {
    case workspace_preset_t::analysis: return "document.disassembly";
    case workspace_preset_t::debugging: return "view.debug.cpu";
    case workspace_preset_t::memory: return "document.hex";
    case workspace_preset_t::types_structures: return "view.types.struct_recon";
    case workspace_preset_t::network: return "view.network.proxy";
    case workspace_preset_t::automation_ai: return "view.ai_chat";
    case workspace_preset_t::programming: return "document.code";
    case workspace_preset_t::safe: return "view.start_center";
    }
    return "view.start_center";
}

void select_docked_window(ImGuiID node_id, const char* stable_id) noexcept
{
    ImGuiDockNode* node = ImGui::DockBuilderGetNode(node_id);
    if (!node || !stable_id)
        return;
    const std::string window_name = application_views::ensure_window_name(
        stable_view_id_t(stable_id));
    if (window_name.empty())
        return;
    ImGuiWindow* window = ImGui::FindWindowByName(window_name.c_str());
    if (window && window->DockNode)
        node = window->DockNode;
    const ImGuiID selected = window ? window->TabId : ImHashStr(window_name.c_str());
    node->SelectedTabId = selected;
    if (node->TabBar) {
        if (ImGuiTabItem* tab = ImGui::TabBarFindTabByID(node->TabBar, selected))
            ImGui::TabBarQueueFocus(node->TabBar, tab);
        else
            node->TabBar->NextSelectedTabId = selected;
        if (window)
            ImGui::FocusWindow(window);
    }
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
void open_builtin_default_views(workspace_preset_t preset) noexcept
{
    auto& registry = application_views::registry();
    registry.for_each_descriptor([preset](const view_descriptor_t& descriptor) {
        if (preset_default_opens_view(preset, descriptor.id.value()))
            static_cast<void>(application_views::open_for_layout(descriptor.id));
    });
}
#endif

#if defined(IMGUI_HAS_DOCK)

struct dock_navigator_target_t {
    const char* label = nullptr;
    const char* window_name = nullptr;
    const char* semantic_id = nullptr;
    ImGuiDockNode* node = nullptr;
    ImRect card;
    ImRect preview;
    ImGuiDir split_direction = ImGuiDir_None;
    float split_ratio = 0.0f;
    bool split_outer = false;
    bool available = false;
};

ImGuiDockNode* dock_tree_root(ImGuiDockNode* node) noexcept
{
    while (node && node->ParentNode)
        node = node->ParentNode;
    return node;
}

bool dock_tree_contains(const ImGuiDockNode* ancestor, const ImGuiDockNode* node) noexcept
{
    while (node) {
        if (node == ancestor)
            return true;
        node = node->ParentNode;
    }
    return false;
}

bool dock_window_class_compatible(const ImGuiWindowClass& host,
    const ImGuiWindowClass& payload) noexcept
{
    if (host.ClassId == payload.ClassId)
        return true;
    if (host.ClassId != 0 && host.DockingAllowUnclassed && payload.ClassId == 0)
        return true;
    return payload.ClassId != 0 && payload.DockingAllowUnclassed && host.ClassId == 0;
}

bool dock_payload_class_compatible(const ImGuiWindowClass& host, ImGuiWindow* payload,
    ImGuiDockNode* payload_node) noexcept
{
    if (!payload_node)
        return payload && dock_window_class_compatible(host, payload->WindowClass);
    bool found_window = false;
    for (ImGuiWindow* window : payload_node->Windows) {
        if (window) {
            found_window = true;
            if (dock_window_class_compatible(host, window->WindowClass))
                return true;
        }
    }
    const bool child_compatible =
        (payload_node->ChildNodes[0] && dock_payload_class_compatible(
            host, payload, payload_node->ChildNodes[0])) ||
        (payload_node->ChildNodes[1] && dock_payload_class_compatible(
            host, payload, payload_node->ChildNodes[1]));
    return child_compatible || (!found_window && payload &&
        dock_window_class_compatible(host, payload->WindowClass));
}

bool dock_split_available(ImGuiDockNode* root, ImGuiWindow* payload,
    ImGuiDockNode* payload_node, const ImGuiIO& io) noexcept
{
    if (!root || !payload || io.ConfigDockingNoSplit || dock_tree_contains(payload_node, root))
        return false;
    const ImGuiDockNodeFlags source_flags = payload_node
        ? payload_node->MergedFlags
        : payload->WindowClass.DockNodeFlagsOverrideSet;
    if ((root->MergedFlags & ImGuiDockNodeFlags_NoDockingSplit) != 0 ||
        (source_flags & ImGuiDockNodeFlags_NoDockingSplitOther) != 0)
        return false;
    ImGuiDockNode* target_root = dock_tree_root(root);
    return target_root && dock_payload_class_compatible(
        target_root->WindowClass, payload, payload_node);
}

ImRect dock_split_card(const ImRect& root, ImGuiDir direction, float scale) noexcept
{
    const float margin = 12.0f * scale;
    const float long_side = 104.0f * scale;
    const float short_side = 40.0f * scale;
    const ImVec2 center = root.GetCenter();
    if (direction == ImGuiDir_Left)
        return ImRect(root.Min.x + margin, center.y - short_side * 0.5f,
            root.Min.x + margin + long_side, center.y + short_side * 0.5f);
    if (direction == ImGuiDir_Right)
        return ImRect(root.Max.x - margin - long_side, center.y - short_side * 0.5f,
            root.Max.x - margin, center.y + short_side * 0.5f);
    if (direction == ImGuiDir_Up)
        return ImRect(center.x - long_side * 0.5f, root.Min.y + margin,
            center.x + long_side * 0.5f, root.Min.y + margin + short_side);
    return ImRect(center.x - long_side * 0.5f, root.Max.y - margin - short_side,
        center.x + long_side * 0.5f, root.Max.y - margin);
}

ImRect dock_split_preview(const ImRect& root, ImGuiDir direction, float ratio) noexcept
{
    const bool horizontal = direction == ImGuiDir_Left || direction == ImGuiDir_Right;
    const ImGuiStyle& style = ImGui::GetStyle();
    const float root_extent = horizontal ? root.GetWidth() : root.GetHeight();
    const float minimum_extent = horizontal
        ? style.WindowMinSize.x * 2.0f
        : style.WindowMinSize.y * 2.0f;
    const float available = (std::max)(
        root_extent - style.DockingSeparatorSize, minimum_extent);
    const bool leading = direction == ImGuiDir_Left || direction == ImGuiDir_Up;
    const float split_ratio = leading ? ratio : 1.0f - ratio;
    const float payload_extent = (std::min)(root_extent,
        leading
            ? IM_TRUNC(available * split_ratio)
            : IM_TRUNC(available - IM_TRUNC(available * split_ratio)));
    if (direction == ImGuiDir_Left)
        return ImRect(root.Min, ImVec2(root.Min.x + payload_extent, root.Max.y));
    if (direction == ImGuiDir_Right)
        return ImRect(ImVec2(root.Max.x - payload_extent, root.Min.y), root.Max);
    if (direction == ImGuiDir_Up)
        return ImRect(root.Min, ImVec2(root.Max.x, root.Min.y + payload_extent));
    return ImRect(ImVec2(root.Min.x, root.Max.y - payload_extent), root.Max);
}

float dock_split_size_ratio(const ImRect& root, ImGuiDir direction,
    const ImGuiWindow* payload) noexcept
{
    const bool horizontal = direction == ImGuiDir_Left || direction == ImGuiDir_Right;
    const float root_extent = horizontal ? root.GetWidth() : root.GetHeight();
    const float payload_extent = payload
        ? (horizontal ? payload->SizeFull.x : payload->SizeFull.y)
        : 0.0f;
    if (root_extent <= 0.0f)
        return 0.22f;
    return (std::clamp)(payload_extent / root_extent, 0.18f, 0.38f);
}

void draw_global_dock_target(ImDrawList* draw_list,
    const dock_navigator_target_t& target, bool active, float scale) noexcept
{
    if (!draw_list || target.card.GetWidth() <= 0.0f || target.card.GetHeight() <= 0.0f)
        return;
    const ImU32 preview = ImGui::GetColorU32(ImGuiCol_DockingPreview,
        active ? 0.82f : (target.available ? 0.50f : 0.16f));
    const ImU32 zone = ImGui::GetColorU32(ImGuiCol_DockingPreview,
        active ? 0.20f : 0.0f);
    const ImU32 surface = ImGui::GetColorU32(ImGuiCol_WindowBg,
        active ? 0.94f : 0.86f);
    const ImU32 text = ImGui::GetColorU32(target.available
        ? ImGuiCol_Text
        : ImGuiCol_TextDisabled);
    if (active && target.preview.GetWidth() > 0.0f && target.preview.GetHeight() > 0.0f) {
        draw_list->AddRectFilled(target.preview.Min, target.preview.Max, zone);
        draw_list->AddRect(target.preview.Min, target.preview.Max, preview,
            3.0f * scale, 0, 2.0f * scale);
    }
    draw_list->AddRectFilled(target.card.Min, target.card.Max, surface, 5.0f * scale);
    draw_list->AddRect(target.card.Min, target.card.Max, preview, 5.0f * scale, 0,
        active ? 2.5f * scale : 1.5f * scale);
    const ImVec2 text_size = ImGui::CalcTextSize(target.label);
    const ImVec2 text_position(
        target.card.GetCenter().x - text_size.x * 0.5f,
        target.card.GetCenter().y - text_size.y * 0.5f);
    draw_list->PushClipRect(target.card.Min, target.card.Max, true);
    draw_list->AddText(text_position, text, target.label);
    draw_list->PopClipRect();
}

bool render_global_dock_target(dock_navigator_target_t& target, ImGuiWindow* payload,
    ImGuiContext& context, const ImGuiViewport& viewport, ImDrawList* draw_list,
    float scale) noexcept
{
    if (!target.window_name || !target.semantic_id ||
        target.card.GetWidth() <= 0.0f || target.card.GetHeight() <= 0.0f)
        return false;
    ImGui::SetNextWindowPos(target.card.Min, ImGuiCond_Always);
    ImGui::SetNextWindowSize(target.card.GetSize(), ImGuiCond_Always);
    ImGui::SetNextWindowViewport(viewport.ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    constexpr ImGuiWindowFlags marker_flags =
        ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse |
        ImGuiWindowFlags_NoNavInputs |
        ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoBackground;
    ImGui::Begin(target.window_name, nullptr, marker_flags);
    ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
    ImGui::PopStyleVar(3);
    ImGui::SetCursorScreenPos(target.card.Min);
    ImGui::InvisibleButton("##dock-target", target.card.GetSize());
    const ImGuiID target_id = ImGui::GetItemID();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::semantics::register_last_item(target.semantic_id,
        "dock-outer-target", false, !target.available);
#endif
    bool active = false;
    if (target.available && target_id != 0 &&
        ImGui::BeginDragDropTargetCustom(target.card, target_id)) {
        const ImGuiPayload* accepted = ImGui::AcceptDragDropPayload(
            IMGUI_PAYLOAD_TYPE_WINDOW,
            ImGuiDragDropFlags_AcceptBeforeDelivery |
                ImGuiDragDropFlags_AcceptNoDrawDefaultRect);
        active = accepted != nullptr;
        if (accepted && accepted->IsDelivery()) {
            ImGui::DockContextQueueDock(&context, nullptr, target.node, payload,
                target.split_direction, target.split_ratio, target.split_outer);
            context.IO.WantSaveIniSettings = true;
        }
        ImGui::EndDragDropTarget();
    }
    ImGui::End();
    draw_global_dock_target(draw_list, target, active, scale);
    return active;
}

#endif

}

void render_global_dock_navigator() noexcept
{
#if defined(IMGUI_HAS_DOCK)
    ImGuiContext* context = ImGui::GetCurrentContext();
    if (!context || !surfaces_ready() || layout_locked() || operation_pending() ||
        (context->IO.ConfigFlags & ImGuiConfigFlags_DockingEnable) == 0 ||
        !context->DragDropActive)
        return;
    const ImGuiPayload& drag_payload = context->DragDropPayload;
    if (!drag_payload.IsDataType(IMGUI_PAYLOAD_TYPE_WINDOW) ||
        drag_payload.Data == nullptr ||
        drag_payload.DataSize != static_cast<int>(sizeof(ImGuiWindow*)))
        return;
    ImGuiWindow* payload = *static_cast<ImGuiWindow**>(drag_payload.Data);
    if (!payload || (payload->Flags & ImGuiWindowFlags_NoDocking) != 0)
        return;
    const ImGuiID root_id = node_id(dock_role_t::root);
    ImGuiDockNode* root = ImGui::DockBuilderGetNode(root_id);
    if (!root || root->LastFrameAlive != context->FrameCount)
        return;
    ImGuiDockNode* payload_node = payload->DockNodeAsHost
        ? payload->DockNodeAsHost
        : payload->DockNode;
    ImGuiViewport* viewport = root->HostWindow && root->HostWindow->Viewport
        ? root->HostWindow->Viewport
        : ImGui::GetMainViewport();
    if (!viewport)
        return;
    const float scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    ImDrawList* draw_list = ImGui::GetForegroundDrawList(viewport);
    const ImRect root_rect = root->Rect();
    if (root_rect.GetWidth() <= 0.0f || root_rect.GetHeight() <= 0.0f)
        return;
    static ImGuiContext* submitted_context = nullptr;
    static int submitted_frame = -1;
    if (submitted_context == context && submitted_frame == context->FrameCount)
        return;
    submitted_context = context;
    submitted_frame = context->FrameCount;

    constexpr std::array<ImGuiDir, 4> directions{
        ImGuiDir_Left, ImGuiDir_Right, ImGuiDir_Up, ImGuiDir_Down
    };
    constexpr std::array<const char*, 4> split_labels{
        "Split left", "Split right", "Split top", "Split bottom"
    };
    constexpr std::array<const char*, 4> split_windows{
        "##aida.dock-navigator.outer-left",
        "##aida.dock-navigator.outer-right",
        "##aida.dock-navigator.outer-top",
        "##aida.dock-navigator.outer-bottom"
    };
    constexpr std::array<const char*, 4> split_semantics{
        "aida.dock.outer-left",
        "aida.dock.outer-right",
        "aida.dock.outer-top",
        "aida.dock.outer-bottom"
    };
    const bool split_available = dock_split_available(root, payload,
        payload_node, context->IO);
    for (std::size_t index = 0; index < directions.size(); ++index) {
        const float size_ratio = dock_split_size_ratio(root_rect,
            directions[index], payload);
        dock_navigator_target_t target;
        target.label = split_labels[index];
        target.window_name = split_windows[index];
        target.semantic_id = split_semantics[index];
        target.node = root;
        target.card = dock_split_card(root_rect, directions[index], scale);
        target.preview = dock_split_preview(root_rect, directions[index], size_ratio);
        target.split_direction = directions[index];
        target.split_ratio = directions[index] == ImGuiDir_Left ||
            directions[index] == ImGuiDir_Up
            ? size_ratio
            : 1.0f - size_ratio;
        target.split_outer = true;
        target.available = split_available;
        static_cast<void>(render_global_dock_target(target, payload, *context,
            *viewport, draw_list, scale));
    }
#endif
}

namespace {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
void open_builtin_default_documents(workspace_preset_t preset) noexcept
{
    auto& registry = application_views::registry();
    registry.for_each_descriptor([preset](const view_descriptor_t& descriptor) {
        if (descriptor.role == view_presentation_role_t::document &&
            preset_default_opens_view(preset, descriptor.id.value()))
            static_cast<void>(application_views::open_for_layout(descriptor.id));
    });
}
#endif

void select_builtin_default_tabs(workspace_preset_t preset, ImGuiID left, ImGuiID center,
    ImGuiID right, ImGuiID bottom) noexcept
{
    if (preset == workspace_preset_t::analysis) {
        select_docked_window(left, "view.analysis.functions");
        select_docked_window(right, "view.inspector");
        select_docked_window(bottom, "view.output");
        select_docked_window(center, "document.disassembly");
    } else if (preset == workspace_preset_t::debugging) {
        select_docked_window(left, "view.debug.threads");
        select_docked_window(right, "view.debug.registers");
        select_docked_window(bottom, "view.debug.stack");
        select_docked_window(center, "view.debug.cpu");
    } else if (preset == workspace_preset_t::memory) {
        select_docked_window(left, "view.memory.value_scan");
        select_docked_window(right, "view.debug.memory_map");
        select_docked_window(bottom, "view.memory.address_list");
        select_docked_window(center, "document.hex");
    } else if (preset == workspace_preset_t::types_structures) {
        select_docked_window(left, "view.types.structures");
        select_docked_window(right, "view.types.dissector");
        select_docked_window(bottom, "view.analysis.references");
        select_docked_window(center, "view.types.struct_recon");
    } else if (preset == workspace_preset_t::network) {
        select_docked_window(left, "view.network.site_map");
        select_docked_window(right, "view.network.scanner");
        select_docked_window(bottom, "view.network.capture");
        select_docked_window(center, "view.network.proxy");
    } else if (preset == workspace_preset_t::automation_ai) {
        select_docked_window(left, "view.ai.agents");
        select_docked_window(right, "view.ai.evidence");
        select_docked_window(bottom, "view.background_tasks");
        select_docked_window(center, "view.ai_chat");
    } else if (preset == workspace_preset_t::programming) {
        select_docked_window(left, "view.project_explorer");
        select_docked_window(right, "view.inspector");
        select_docked_window(bottom, "view.diagnostics");
        select_docked_window(center, "document.code");
    } else {
        select_docked_window(left, "view.project_explorer");
        select_docked_window(right, "view.ai_chat");
        select_docked_window(bottom, "view.diagnostics");
        select_docked_window(center, "document.code");
    }
}

void dock_open_windows_by_role(ImGuiID left, ImGuiID center, ImGuiID right,
    ImGuiID bottom) noexcept
{
    auto& registry = application_views::registry();
    registry.for_each_instance([&](const view_descriptor_t& descriptor,
            const view_instance_state_t& instance) {
        ImGuiID target = 0;
        switch (descriptor.role) {
        case view_presentation_role_t::document:
            target = center;
            break;
        case view_presentation_role_t::inspector:
            target = right;
            break;
        case view_presentation_role_t::bottom_panel:
            target = bottom;
            break;
        case view_presentation_role_t::tool_window:
            target = left;
            break;
        case view_presentation_role_t::shell_surface:
            break;
        }
        if (target == 0)
            return;
        const std::string& window_name = registry.window_name(instance.id);
        if (!window_name.empty())
            ImGui::DockBuilderDockWindow(window_name.c_str(), target);
    }, true);
}

}

const workspace_preset_descriptor_t* presets(std::size_t& count) noexcept
{
    count = kPresetDescriptors.size();
    return kPresetDescriptors.data();
}

std::uint32_t preset_revision(workspace_preset_t preset) noexcept
{
    return descriptor_for(preset).revision;
}

bool preset_default_opens_view(workspace_preset_t preset,
    std::string_view stable_view_id) noexcept
{
    const auto matches = [stable_view_id](std::initializer_list<std::string_view> ids) noexcept {
        return std::find(ids.begin(), ids.end(), stable_view_id) != ids.end();
    };
    switch (preset) {
    case workspace_preset_t::analysis:
        return matches({"view.analysis.functions", "document.disassembly", "document.pseudocode",
            "document.graph", "document.hex", "view.inspector", "view.analysis.references",
            "view.ai_chat", "view.output", "view.background_tasks", "view.diagnostics"});
    case workspace_preset_t::debugging:
        return matches({"view.sessions", "view.debug.threads", "view.debug.modules",
            "view.debug.call_stack", "view.debug.cpu", "view.debug.registers", "view.debug.stack",
            "view.debug.source", "document.hex",
            "view.debug.breakpoints", "view.debug.watches", "view.debug.strings",
            "view.debug.bookmarks", "view.debug.memory_map",
            "view.debug.trace", "view.terminal", "view.background_tasks", "view.diagnostics"});
    case workspace_preset_t::memory:
        return matches({"view.sessions", "view.memory.value_scan", "view.memory.value_scan_results",
            "view.memory.address_list", "view.memory.aob",
            "view.memory.decrypt", "view.memory.integrity", "document.hex",
            "view.memory.pointers", "view.memory.snapshots",
            "view.debug.memory_map", "view.types.dissector", "view.debug.patches",
            "view.debug.watches", "view.background_tasks"});
    case workspace_preset_t::types_structures:
        return matches({"view.sessions", "view.types.structures", "view.types.unions",
            "view.types.enums", "view.types.struct_recon", "document.hex",
            "view.types.dissector", "view.analysis.references", "view.background_tasks"});
    case workspace_preset_t::network:
        return matches({"view.sessions", "view.network.site_map", "view.network.scope",
            "view.network.proxy", "view.network.repeater", "view.network.browser",
            "view.network.decoder", "view.network.comparer", "view.network.scanner",
            "view.network.capture", "view.network.logger", "view.background_tasks"});
    case workspace_preset_t::automation_ai:
        return matches({"view.sessions", "view.ai.agents", "view.ai.skills",
            "view.ai.scripts", "view.project_explorer", "view.ai_chat", "document.code",
            "view.ai.evidence", "view.ai.providers", "view.ai.mcp_marketplace",
            "view.background_tasks", "view.mcp_log", "view.output", "view.terminal",
            "view.diagnostics"});
    case workspace_preset_t::programming:
        return matches({"view.project_explorer", "view.programming.outline", "view.sessions",
            "view.workspace_search", "document.code", "document.disassembly",
            "view.inspector", "view.analysis.references", "view.ai_chat", "view.output",
            "view.terminal", "view.programming.references",
            "view.programming.source_debug_console", "view.background_tasks",
            "view.diagnostics"});
    case workspace_preset_t::safe:
        return matches({"view.project_explorer", "view.sessions", "view.recent",
            "document.code", "view.ai_chat", "view.diagnostics", "view.output"});
    }
    return false;
}

void draw_transition_surface(ImVec2 position, ImVec2 size,
    workspace_preset_t preset) noexcept
{
    if (size.x <= 0.0f || size.y <= 0.0f || ImGui::GetCurrentContext() == nullptr)
        return;
    const ImVec2 maximum(position.x + size.x, position.y + size.y);
    ImGui::SetNextWindowPos(position, ImGuiCond_Always);
    ImGui::SetNextWindowSize(size, ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(1.0f);
#if defined(IMGUI_HAS_DOCK)
    if (const ImGuiViewport* viewport = ImGui::GetMainViewport())
        ImGui::SetNextWindowViewport(viewport->ID);
#endif
    const ImGuiStyle& style = ImGui::GetStyle();
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
#if defined(IMGUI_HAS_DOCK)
    flags |= ImGuiWindowFlags_NoDocking;
#endif
    ImGui::Begin("Workspace Transition###aida.workspace.transition.surface", nullptr, flags);
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddLine(position, ImVec2(maximum.x, position.y),
        ImGui::GetColorU32(ImGuiCol_CheckMark), 2.0f);
    const char* title = "Switching workspace";
    const char* target = descriptor_for(preset).display_name.data();
    const char* detail = "Restoring dock layout and views";
    const ImVec2 title_size = ImGui::CalcTextSize(title);
    const ImVec2 target_size = ImGui::CalcTextSize(target);
    const ImVec2 detail_size = ImGui::CalcTextSize(detail);
    const float line_height = ImGui::GetTextLineHeight();
    const float spacing = style.ItemSpacing.y;
    const float block_height = line_height * 3.0f + spacing * 2.0f;
    float y = position.y + (size.y - block_height) * 0.5f;
    const auto centered_x = [position, size](float width) noexcept {
        return position.x + (size.x - width) * 0.5f;
    };
    draw_list->AddText(ImVec2(centered_x(title_size.x), y),
        ImGui::GetColorU32(ImGuiCol_TextDisabled), title);
    y += line_height + spacing;
    draw_list->AddText(ImVec2(centered_x(target_size.x), y),
        ImGui::GetColorU32(ImGuiCol_Text), target);
    y += line_height + spacing;
    draw_list->AddText(ImVec2(centered_x(detail_size.x), y),
        ImGui::GetColorU32(ImGuiCol_TextDisabled), detail);
    ImGui::End();
    ImGui::PopStyleVar(3);
}

}

#if defined(__EMSCRIPTEN__) || defined(AIDA_IMGUI_STUDIO_PREVIEW)

namespace aida::ui::workspace_layout {
namespace {

constexpr std::size_t kPreviewMaximumPayloadBytes = 4U * 1024U * 1024U;
std::size_t preset_index(workspace_preset_t preset) noexcept
{
    return static_cast<std::size_t>(preset);
}

struct preview_state_t {
    bool initialized = false;
    bool root_prepared = false;
    ImGuiID root = 0;
    dock_nodes_t nodes;
    std::string in_memory_layout;
    std::array<std::string, kPresetDescriptors.size()> layouts;
    std::array<dock_nodes_t, kPresetDescriptors.size()> layout_nodes;
    std::array<bool, kPresetDescriptors.size()> layout_locks{};
    std::map<std::string, std::string> user_layouts;
    std::map<std::string, dock_nodes_t> user_layout_nodes;
    std::map<std::string, workspace_preset_t> user_presets;
    std::map<std::string, std::uint64_t> user_layout_generations;
    std::map<std::string, bool> user_layout_locks;
    std::string active_user;
    std::uint64_t user_generation_sequence = 0;
    workspace_preset_t active = workspace_preset_t::analysis;
    workspace_preset_t pending = workspace_preset_t::analysis;
    bool locked = false;
    bool rebuild = false;
    std::uint8_t select_defaults_after_realize_frames = 0;
    std::uint8_t transition_frames = 0;
    ImVec2 last_position{0.0f, 0.0f};
    ImVec2 last_size{0.0f, 0.0f};
};

void build_preview_recipe(preview_state_t& current, ImGuiID root_dockspace_id,
    ImVec2 position, ImVec2 size) noexcept;

preview_state_t& preview_state() noexcept
{
    static preview_state_t value;
    return value;
}

void collect_preview_leaves(ImGuiDockNode* node,
    std::vector<ImGuiDockNode*>& leaves) noexcept
{
    if (!node)
        return;
    if (node->IsLeafNode()) {
        leaves.push_back(node);
        return;
    }
    collect_preview_leaves(node->ChildNodes[0], leaves);
    collect_preview_leaves(node->ChildNodes[1], leaves);
}

ImGuiID preview_role_leaf(ImGuiDockNode* root, ImGuiID candidate,
    dock_role_t role) noexcept
{
    if (!root)
        return 0;
    ImGuiDockNode* subtree = candidate ? ImGui::DockBuilderGetNode(candidate) : nullptr;
    if (!subtree || !dock_tree_contains(root, subtree))
        subtree = root;
    if (subtree->IsLeafNode())
        return subtree->ID;
    std::vector<ImGuiDockNode*> leaves;
    collect_preview_leaves(subtree, leaves);
    ImGuiDockNode* selected = nullptr;
    double selected_score = -(std::numeric_limits<double>::max)();
    for (ImGuiDockNode* leaf : leaves) {
        const double center_x = leaf->Pos.x + leaf->Size.x * 0.5;
        const double center_y = leaf->Pos.y + leaf->Size.y * 0.5;
        double score = static_cast<double>(leaf->Windows.Size) * 1000000000.0 +
            static_cast<double>((std::max)(leaf->Size.x, 1.0f)) *
            static_cast<double>((std::max)(leaf->Size.y, 1.0f));
        if (role == dock_role_t::documents) {
            if (leaf->IsCentralNode())
                score += 1000000000000.0;
        } else if (role == dock_role_t::navigator) {
            score -= center_x * 1000.0;
        } else if (role == dock_role_t::inspector) {
            score += center_x * 1000.0;
        } else if (role == dock_role_t::bottom) {
            score += center_y * 1000.0;
        }
        if (!selected || score > selected_score) {
            selected = leaf;
            selected_score = score;
        }
    }
    return selected ? selected->ID : root->ID;
}

dock_nodes_t resolved_preview_nodes(preview_state_t& current) noexcept
{
    ImGuiDockNode* root = ImGui::DockBuilderGetNode(current.root);
    if (!root)
        return current.nodes;
    current.nodes.root = current.root;
    current.nodes.navigator = preview_role_leaf(root, current.nodes.navigator,
        dock_role_t::navigator);
    current.nodes.documents = preview_role_leaf(root, current.nodes.documents,
        dock_role_t::documents);
    current.nodes.inspector = preview_role_leaf(root, current.nodes.inspector,
        dock_role_t::inspector);
    current.nodes.bottom = preview_role_leaf(root, current.nodes.bottom,
        dock_role_t::bottom);
    return current.nodes;
}

void apply_preview_lock(ImGuiDockNode* node, bool locked) noexcept
{
    if (!node)
        return;
    constexpr ImGuiDockNodeFlags flags =
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoDocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoUndocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoResize);
    node->SetLocalFlags(locked
        ? static_cast<ImGuiDockNodeFlags>(node->LocalFlags | flags)
        : static_cast<ImGuiDockNodeFlags>(node->LocalFlags & ~flags));
    apply_preview_lock(node->ChildNodes[0], locked);
    apply_preview_lock(node->ChildNodes[1], locked);
}

}

bool initialize(ImGuiID root_dockspace_id) noexcept
{
    preview_state_t& current = preview_state();
    current.initialized = true;
    current.root = root_dockspace_id;
    current.nodes.root = root_dockspace_id;
    return true;
}

void prepare_root(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || current.root != root_dockspace_id)
        return;
    current.last_position = position;
    current.last_size = size;
#if defined(IMGUI_HAS_DOCK)
    if (!current.root_prepared || current.rebuild) {
        current.active = current.pending;
        application_views::synchronize_workspace_visibility(current.pending);
        if (!current.rebuild && !current.layouts[preset_index(current.pending)].empty()) {
            const std::string& saved = current.layouts[preset_index(current.pending)];
            ImGui::DockBuilderRemoveNode(root_dockspace_id);
            ImGui::LoadIniSettingsFromMemory(saved.data(), saved.size());
            application_views::migrate_persisted_window_settings();
            current.nodes = current.layout_nodes[preset_index(current.pending)];
            current.locked = current.layout_locks[preset_index(current.pending)];
            current.select_defaults_after_realize_frames = 0;
        } else {
            current.locked = current.layout_locks[preset_index(current.pending)];
            open_builtin_default_documents(current.pending);
            build_preview_recipe(current, root_dockspace_id, position, size);
        }
        current.rebuild = false;
        current.root_prepared = true;
        ImGui::GetIO().WantSaveIniSettings = true;
    }
#else
    static_cast<void>(position);
    static_cast<void>(size);
#endif
    current.root_prepared = true;
    apply_preview_lock(ImGui::DockBuilderGetNode(root_dockspace_id), current.locked);
}

bool surfaces_ready() noexcept
{
    const preview_state_t& current = preview_state();
    return current.initialized && current.root_prepared;
}

void render_transition_surface() noexcept
{
    preview_state_t& current = preview_state();
    if (current.transition_frames == 0)
        return;
    draw_transition_surface(current.last_position, current.last_size, current.pending);
    --current.transition_frames;
}

void settle_default_selection() noexcept
{
    preview_state_t& current = preview_state();
    if (current.select_defaults_after_realize_frames == 0)
        return;
    --current.select_defaults_after_realize_frames;
    if (current.select_defaults_after_realize_frames != 0)
        return;
    const bool compact = current.nodes.root != 0 &&
        current.nodes.navigator == current.nodes.root &&
        current.nodes.documents == current.nodes.root &&
        current.nodes.inspector == current.nodes.root &&
        current.nodes.bottom == current.nodes.root;
    if (application_views::is_open(stable_view_id_t("view.start_center")))
        select_docked_window(current.nodes.documents, "view.start_center");
    else if (compact)
        select_docked_window(current.nodes.root, compact_primary_view(current.active));
    else
        select_builtin_default_tabs(current.active, current.nodes.navigator,
            current.nodes.documents, current.nodes.inspector, current.nodes.bottom);
}

namespace {

void dock_preview_named_windows(workspace_preset_t preset, ImGuiID left, ImGuiID center,
    ImGuiID right, ImGuiID bottom, bool missing_only) noexcept
{
    const auto dock = [missing_only](ImGuiID node,
                          std::initializer_list<const char*> stable_ids) {
        for (const char* stable_id : stable_ids) {
            const stable_view_id_t view_id(stable_id);
            if (missing_only && !application_views::is_open(view_id)) {
                const auto opened = application_views::open_for_layout(view_id);
                if (!opened.ok())
                    continue;
            }
            const std::string window_name = application_views::ensure_window_name(
                view_id);
            if (window_name.empty())
                continue;
            ImGuiWindow* window = ImGui::FindWindowByName(window_name.c_str());
            if (!missing_only || !window || window->DockId == 0)
                ImGui::DockBuilderDockWindow(window_name.c_str(), node);
        }
    };
    if (preset == workspace_preset_t::analysis) {
        dock(left, {"view.project_explorer", "view.sessions", "view.navigator",
            "view.analysis.functions", "view.analysis.imports", "view.analysis.exports",
            "view.analysis.names", "view.analysis.strings", "view.analysis.segments",
            "view.analysis.local_types", "view.analysis.segment_registers",
            "view.analysis.proximity"});
        dock(center, {"view.start_center", "document.disassembly", "document.pseudocode",
            "document.graph", "document.hex", "document.code", "view.analysis.binary_map"});
        dock(right, {"view.inspector", "view.analysis.references", "view.ai_chat"});
        dock(bottom, {"view.output", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::debugging) {
        dock(left, {"view.sessions", "view.debug.threads", "view.debug.modules",
            "view.debug.call_stack"});
        dock(center, {"view.start_center", "view.debug.cpu", "view.debug.source",
            "document.code", "document.hex", "view.debug.cfg"});
        dock(right, {"view.debug.registers", "view.debug.breakpoints", "view.debug.watches",
            "view.debug.strings", "view.debug.bookmarks"});
        dock(bottom, {"view.debug.stack", "view.debug.memory_map", "view.debug.trace", "view.debug.patches",
            "view.debug.seh", "view.debug.handles", "view.terminal",
            "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::memory) {
        dock(left, {"view.sessions", "view.memory.value_scan", "view.memory.crypto",
            "view.memory.aob", "view.memory.decrypt", "view.memory.integrity"});
        dock(center, {"view.start_center", "document.hex", "view.memory.value_scan_results", "view.memory.pointers",
            "view.memory.snapshots"});
        dock(right, {"view.debug.memory_map", "view.types.dissector"});
        dock(bottom, {"view.memory.address_list", "view.debug.patches", "view.debug.watches",
            "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::types_structures) {
        dock(left, {"view.sessions", "view.types.structures", "view.types.unions",
            "view.types.enums", "view.types.typedefs", "view.types.functions",
            "view.types.inferred"});
        dock(center, {"view.start_center", "view.types.struct_recon", "document.code",
            "document.hex"});
        dock(right, {"view.types.dissector"});
        dock(bottom, {"view.analysis.references", "view.background_tasks",
            "view.diagnostics"});
    } else if (preset == workspace_preset_t::network) {
        dock(left, {"view.sessions", "view.network.site_map", "view.network.scope",
            "view.network.cookies", "view.network.session"});
        dock(center, {"view.start_center", "view.network.proxy", "view.network.intercept",
            "view.network.repeater", "view.network.browser", "view.network.api"});
        dock(right, {"view.network.decoder", "view.network.comparer",
            "view.network.scanner", "view.network.reports"});
        dock(bottom, {"view.network.capture", "view.network.logger",
            "view.network.websocket", "view.network.h2_editor", "view.background_tasks",
            "view.diagnostics"});
    } else if (preset == workspace_preset_t::automation_ai) {
        dock(left, {"view.sessions", "view.ai.agents", "view.ai.skills",
            "view.ai.scripts", "view.project_explorer"});
        dock(center, {"view.start_center", "view.ai_chat", "document.code"});
        dock(right, {"view.ai.evidence", "view.ai.providers",
            "view.ai.mcp_marketplace"});
        dock(bottom, {"view.background_tasks", "view.mcp_log", "view.output",
            "view.terminal", "view.diagnostics"});
    } else if (preset == workspace_preset_t::programming) {
        dock(left, {"view.project_explorer", "view.programming.outline", "view.sessions",
            "view.workspace_search"});
        dock(center, {"view.start_center", "document.code", "document.disassembly",
            "document.pseudocode"});
        dock(right, {"view.inspector", "view.analysis.references", "view.ai_chat"});
        dock(bottom, {"view.programming.source_debug_console", "view.output",
            "view.terminal", "view.programming.references", "view.background_tasks",
            "view.diagnostics"});
    } else {
        dock(left, {"view.project_explorer", "view.sessions", "view.recent"});
        dock(center, {"view.start_center", "document.code"});
        dock(right, {"view.ai_chat"});
        dock(bottom, {"view.diagnostics", "view.output"});
    }
}

void build_preview_recipe(preview_state_t& current, ImGuiID root_dockspace_id,
    ImVec2 position, ImVec2 size) noexcept
{
#if defined(IMGUI_HAS_DOCK)
    const workspace_preset_t preset = current.pending;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const layout_ratios_t ratios = calculate_layout_ratios(preset, size,
        viewport ? viewport->DpiScale : 1.0f);
    ImGui::DockBuilderRemoveNode(root_dockspace_id);
    ImGui::DockBuilderAddNode(root_dockspace_id,
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_DockSpace) |
            static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_PassthruCentralNode));
    ImGui::DockBuilderSetNodePos(root_dockspace_id, position);
    ImGui::DockBuilderSetNodeSize(root_dockspace_id, size);
    if (compact_single_node_recipe(size, viewport ? viewport->DpiScale : 1.0f)) {
        dock_open_windows_by_role(root_dockspace_id, root_dockspace_id,
            root_dockspace_id, root_dockspace_id);
        dock_preview_named_windows(preset, root_dockspace_id, root_dockspace_id,
            root_dockspace_id, root_dockspace_id, false);
        ImGui::DockBuilderFinish(root_dockspace_id);
        const char* primary = application_views::is_open(stable_view_id_t("view.start_center"))
            ? "view.start_center" : compact_primary_view(preset);
        select_docked_window(root_dockspace_id, primary);
        current.nodes = {root_dockspace_id, root_dockspace_id, root_dockspace_id,
            root_dockspace_id, root_dockspace_id};
        current.select_defaults_after_realize_frames = 2;
        return;
    }
    ImGuiID center = root_dockspace_id;
    ImGuiID left = 0;
    ImGuiID right = 0;
    ImGuiID bottom = 0;
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, ratios.left, &left, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, ratios.right, &right, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, ratios.bottom, &bottom, &center);
    dock_open_windows_by_role(left, center, right, bottom);
    dock_preview_named_windows(preset, left, center, right, bottom, false);
    ImGui::DockBuilderFinish(root_dockspace_id);
    if (application_views::is_open(stable_view_id_t("view.start_center"))) {
        select_docked_window(center, "view.start_center");
    } else
        select_builtin_default_tabs(preset, left, center, right, bottom);
    current.nodes = {root_dockspace_id, left, center, right, bottom};
    current.select_defaults_after_realize_frames = 2;
#else
    static_cast<void>(current);
    static_cast<void>(root_dockspace_id);
    static_cast<void>(position);
    static_cast<void>(size);
#endif
}

}

ImGuiID node_id(dock_role_t role) noexcept
{
    preview_state_t& current = preview_state();
    const dock_nodes_t nodes = resolved_preview_nodes(current);
    switch (role) {
    case dock_role_t::root: return nodes.root;
    case dock_role_t::navigator: return nodes.navigator;
    case dock_role_t::documents: return nodes.documents;
    case dock_role_t::inspector: return nodes.inspector;
    case dock_role_t::bottom: return nodes.bottom;
    default: return 0;
    }
}

window_placement_state_t inspect_window_placement(std::string_view window_name) noexcept
{
    window_placement_state_t result;
    if (window_name.empty() || ImGui::GetCurrentContext() == nullptr)
        return result;
    const std::string name(window_name);
    ImGuiWindow* window = ImGui::FindWindowByName(name.c_str());
    if (!window)
        return result;
    result.realized = true;
    result.dock_node = window->DockId;
    result.docked = window->DockId != 0;
    preview_state_t& current = preview_state();
    const dock_nodes_t nodes = resolved_preview_nodes(current);
    if (window->DockId == nodes.navigator) result.role = dock_role_t::navigator;
    else if (window->DockId == nodes.documents) result.role = dock_role_t::documents;
    else if (window->DockId == nodes.inspector) result.role = dock_role_t::inspector;
    else if (window->DockId == nodes.bottom) result.role = dock_role_t::bottom;
    return result;
}

workspace_request_result_t float_window(std::string_view window_name) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared || current.locked || window_name.empty())
        return workspace_request_result_t::unavailable;
    const std::string name(window_name);
    ImGuiWindow* window = ImGui::FindWindowByName(name.c_str());
    if (!window)
        return workspace_request_result_t::unavailable;
    if (window->DockId == 0)
        return workspace_request_result_t::unchanged;
    ImGui::DockContextQueueUndockWindow(ImGui::GetCurrentContext(), window);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

workspace_request_result_t dock_window(std::string_view window_name, dock_role_t role) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared || current.locked || window_name.empty() ||
        role == dock_role_t::root)
        return workspace_request_result_t::unavailable;
    const ImGuiID target = node_id(role);
    if (target == 0 || ImGui::DockBuilderGetNode(target) == nullptr)
        return workspace_request_result_t::unavailable;
    const window_placement_state_t placement = inspect_window_placement(window_name);
    if (placement.realized && placement.dock_node == target)
        return workspace_request_result_t::unchanged;
    const std::string name(window_name);
    ImGuiWindow* window = ImGui::FindWindowByName(name.c_str());
    if (window)
        ImGui::DockContextQueueDock(ImGui::GetCurrentContext(), nullptr,
            ImGui::DockBuilderGetNode(target), window, ImGuiDir_None, 0.0f, false);
    else
        ImGui::DockBuilderDockWindow(name.c_str(), target);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

workspace_request_result_t split_window(std::string_view window_name,
    std::string_view anchor_window_name, dock_split_direction_t direction) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared || current.locked ||
        window_name.empty() || anchor_window_name.empty())
        return workspace_request_result_t::unavailable;
    const std::string anchor_name(anchor_window_name);
    ImGuiWindow* anchor = ImGui::FindWindowByName(anchor_name.c_str());
    if (!anchor || anchor->DockId == 0 || !ImGui::DockBuilderGetNode(anchor->DockId))
        return workspace_request_result_t::unavailable;
    const ImGuiDir imgui_direction = direction == dock_split_direction_t::left
        ? ImGuiDir_Left : direction == dock_split_direction_t::right
        ? ImGuiDir_Right : direction == dock_split_direction_t::up
        ? ImGuiDir_Up : ImGuiDir_Down;
    const ImGuiID anchor_node = anchor->DockId;
    ImGuiID split_node = 0;
    ImGuiID retained_node = 0;
    ImGui::DockBuilderSplitNode(anchor_node, imgui_direction, 0.5f,
        &split_node, &retained_node);
    if (split_node == 0 || retained_node == 0)
        return workspace_request_result_t::failed;
    const std::string name(window_name);
    ImGui::DockBuilderDockWindow(name.c_str(), split_node);
    auto retain_role = [&](ImGuiID& node) {
        if (node == anchor_node) node = retained_node;
    };
    retain_role(current.nodes.navigator);
    retain_role(current.nodes.documents);
    retain_role(current.nodes.inspector);
    retain_role(current.nodes.bottom);
    ImGui::DockBuilderFinish(current.nodes.root);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

void persist_if_requested() noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized)
        return;
    ImGuiIO& io = ImGui::GetIO();
    if (!io.WantSaveIniSettings)
        return;
    current.nodes = resolved_preview_nodes(current);
    std::size_t payload_size = 0;
    const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
    if (!payload || payload_size == 0 || payload_size > kPreviewMaximumPayloadBytes) {
        io.WantSaveIniSettings = true;
        return;
    }
    try {
        if (current.in_memory_layout.size() != payload_size ||
            current.in_memory_layout.compare(0, payload_size, payload, payload_size) != 0)
            current.in_memory_layout.assign(payload, payload_size);
        if (current.active_user.empty()) {
            if (!current.in_memory_layout.empty())
                current.layouts[preset_index(current.active)] = current.in_memory_layout;
            current.layout_nodes[preset_index(current.active)] = current.nodes;
            current.layout_locks[preset_index(current.active)] = current.locked;
        } else {
            const auto layout = current.user_layouts.find(current.active_user);
            const auto nodes = current.user_layout_nodes.find(current.active_user);
            const auto lock = current.user_layout_locks.find(current.active_user);
            if (layout != current.user_layouts.end() &&
                nodes != current.user_layout_nodes.end() &&
                lock != current.user_layout_locks.end()) {
                layout->second = current.in_memory_layout;
                nodes->second = current.nodes;
                lock->second = current.locked;
            } else {
                io.WantSaveIniSettings = true;
                return;
            }
        }
    } catch (...) {
        io.WantSaveIniSettings = true;
        return;
    }
    io.WantSaveIniSettings = false;
}

void settle_pending_operation_for_shutdown() noexcept
{
}


workspace_preset_t active_preset() noexcept { return preview_state().active; }
std::string_view active_preset_name() noexcept { return descriptor_for(active_preset()).display_name; }
workspace_identity_t active_identity() noexcept
{
    const preview_state_t& current = preview_state();
    return {current.active_user.empty() ? workspace_identity_kind_t::built_in :
        workspace_identity_kind_t::user, current.active, current.active_user};
}
std::string active_identity_key() noexcept
{
    try {
        const preview_state_t& current = preview_state();
        return identity_key(current.active, current.active_user);
    } catch (...) {
        return "builtin:analysis";
    }
}
std::shared_ptr<const std::vector<user_workspace_descriptor_t>> user_layout_catalog() noexcept
{
    try {
        const preview_state_t& current = preview_state();
        auto result = std::make_shared<std::vector<user_workspace_descriptor_t>>();
        result->reserve(current.user_layouts.size());
        for (const auto& entry : current.user_layouts) {
            const auto preset = current.user_presets.find(entry.first);
            const auto nodes = current.user_layout_nodes.find(entry.first);
            const auto generation = current.user_layout_generations.find(entry.first);
            const auto lock = current.user_layout_locks.find(entry.first);
            if (preset == current.user_presets.end() ||
                nodes == current.user_layout_nodes.end() ||
                generation == current.user_layout_generations.end() ||
                generation->second == 0 || lock == current.user_layout_locks.end())
                continue;
            result->push_back({entry.first,
                preset->second,
                generation->second,
                current.active_user == entry.first});
        }
        return result;
    } catch (...) {
        return std::make_shared<const std::vector<user_workspace_descriptor_t>>();
    }
}
bool user_layout_catalog_ready() noexcept { return true; }
bool layout_locked() noexcept { return preview_state().locked; }
workspace_request_result_t set_layout_locked(bool locked) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    if (current.locked == locked)
        return workspace_request_result_t::unchanged;
    current.locked = locked;
    apply_preview_lock(ImGui::DockBuilderGetNode(current.root), locked);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

bool operation_pending() noexcept { return false; }
std::string operation_status() noexcept { return {}; }

workspace_request_result_t switch_to(workspace_preset_t preset) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    if (current.active == preset && current.active_user.empty() && !current.rebuild)
        return workspace_request_result_t::unchanged;
    persist_if_requested();
    if (ImGui::GetIO().WantSaveIniSettings)
        return workspace_request_result_t::failed;
    current.active_user.clear();
    current.pending = preset;
    current.rebuild = current.layouts[preset_index(preset)].empty();
    current.root_prepared = false;
    current.transition_frames = 2;
    return workspace_request_result_t::completed;
}

workspace_request_result_t save_user_layout(std::string_view name, bool overwrite) noexcept
{
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    ImGui::GetIO().WantSaveIniSettings = true;
    persist_if_requested();
    if (ImGui::GetIO().WantSaveIniSettings)
        return workspace_request_result_t::failed;
    try {
        const std::string saved_name(name);
        const bool exists = current.user_layouts.find(saved_name) != current.user_layouts.end();
        if (!overwrite && exists)
            return workspace_request_result_t::already_exists;
        if (!exists && current.user_layouts.size() >= kMaximumNamedUserLayouts)
            return workspace_request_result_t::unavailable;
        const std::string previous_identity = identity_key(current.active, current.active_user);
        preview_state_t next = current;
        next.user_layouts[saved_name] = next.in_memory_layout;
        next.user_layout_nodes[saved_name] = next.nodes;
        next.user_presets[saved_name] = next.active;
        const std::uint64_t saved_generation = ++next.user_generation_sequence;
        next.user_layout_generations[saved_name] = saved_generation;
        next.user_layout_locks[saved_name] = next.locked;
        next.active_user = saved_name;
        const std::string target_identity = identity_key(next.active, next.active_user);
        current = std::move(next);
        application_views::clone_persisted_workspace_visibility(previous_identity,
            target_identity);
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return workspace_request_result_t::completed;
}

workspace_request_result_t save_active_user_layout() noexcept
{
    const std::string name = preview_state().active_user;
    return name.empty() ? workspace_request_result_t::unavailable :
        save_user_layout(name, true);
}

workspace_request_result_t load_user_layout(std::string_view name) noexcept
{
    return load_user_layout_exact(name, 0);
}

workspace_request_result_t load_user_layout_exact(std::string_view name,
    std::uint64_t expected_generation) noexcept
{
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    persist_if_requested();
    if (ImGui::GetIO().WantSaveIniSettings)
        return workspace_request_result_t::failed;
    try {
        const auto found = current.user_layouts.find(std::string(name));
        if (found == current.user_layouts.end())
            return workspace_request_result_t::not_found;
        const auto generation = current.user_layout_generations.find(found->first);
        if (generation == current.user_layout_generations.end() ||
            generation->second == 0)
            return workspace_request_result_t::failed;
        if (expected_generation != 0 &&
            expected_generation != generation->second)
            return workspace_request_result_t::unavailable;
        const auto preset = current.user_presets.find(found->first);
        const auto nodes = current.user_layout_nodes.find(found->first);
        const auto lock = current.user_layout_locks.find(found->first);
        if (preset == current.user_presets.end() ||
            nodes == current.user_layout_nodes.end() ||
            lock == current.user_layout_locks.end())
            return workspace_request_result_t::failed;
        std::string payload = found->second;
        std::string selected_name = found->first;
        ImGui::DockBuilderRemoveNode(current.root);
        ImGui::LoadIniSettingsFromMemory(payload.data(), payload.size());
        application_views::migrate_persisted_window_settings();
        current.in_memory_layout = std::move(payload);
        current.nodes = nodes->second;
        current.active = preset->second;
        current.pending = preset->second;
        current.active_user = std::move(selected_name);
        current.locked = lock->second;
        current.root_prepared = true;
        current.transition_frames = 2;
        apply_preview_lock(ImGui::DockBuilderGetNode(current.root), current.locked);
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return workspace_request_result_t::completed;
}

workspace_request_result_t rename_user_layout(std::string_view current_name,
    std::string_view new_name) noexcept
{
    if (!valid_user_layout_name(current_name) || !valid_user_layout_name(new_name))
        return workspace_request_result_t::invalid_name;
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    try {
        const std::string old_value(current_name);
        const std::string new_value(new_name);
        preview_state_t next = current;
        const auto found = next.user_layouts.find(old_value);
        if (found == next.user_layouts.end())
            return workspace_request_result_t::not_found;
        if (old_value == new_value)
            return workspace_request_result_t::unchanged;
        if (next.user_layouts.find(new_value) != next.user_layouts.end())
            return workspace_request_result_t::already_exists;
        const workspace_preset_t preset = next.user_presets.at(old_value);
        const auto nodes = next.user_layout_nodes.find(old_value);
        const auto generation = next.user_layout_generations.find(old_value);
        const auto lock = next.user_layout_locks.find(old_value);
        if (nodes == next.user_layout_nodes.end() ||
            generation == next.user_layout_generations.end() ||
            generation->second == 0 || lock == next.user_layout_locks.end())
            return workspace_request_result_t::failed;
        const std::uint64_t retained_generation = generation->second;
        const bool retained_lock = lock->second;
        next.user_layouts.emplace(new_value, std::move(found->second));
        next.user_layouts.erase(found);
        next.user_layout_nodes.emplace(new_value, nodes->second);
        next.user_layout_nodes.erase(nodes);
        next.user_presets.erase(old_value);
        next.user_presets.emplace(new_value, preset);
        next.user_layout_generations.erase(generation);
        next.user_layout_generations.emplace(new_value, retained_generation);
        next.user_layout_locks.erase(lock);
        next.user_layout_locks.emplace(new_value, retained_lock);
        if (next.active_user == old_value)
            next.active_user = new_value;
        const std::string source_identity = identity_key(preset, old_value);
        const std::string target_identity = identity_key(preset, new_value);
        current = std::move(next);
        application_views::rename_persisted_workspace_visibility(
            source_identity, target_identity);
        return workspace_request_result_t::completed;
    } catch (...) {
        return workspace_request_result_t::failed;
    }
}

workspace_request_result_t delete_user_layout(std::string_view name) noexcept
{
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    try {
        const std::string value(name);
        preview_state_t next = current;
        const auto preset = next.user_presets.find(value);
        const bool has_preset = preset != next.user_presets.end();
        const workspace_preset_t base_preset = preset == next.user_presets.end()
            ? next.active : preset->second;
        const bool deleting_active = next.active_user == value;
        if (next.user_layouts.erase(value) == 0)
            return workspace_request_result_t::not_found;
        next.user_layout_nodes.erase(value);
        next.user_layout_generations.erase(value);
        next.user_layout_locks.erase(value);
        next.user_presets.erase(value);
        if (deleting_active) {
            next.active_user.clear();
            next.active = base_preset;
            next.pending = base_preset;
            next.locked = next.layout_locks[preset_index(base_preset)];
            next.rebuild = next.layouts[preset_index(base_preset)].empty();
            next.root_prepared = false;
            next.transition_frames = 2;
        }
        const std::string removed_identity = has_preset
            ? identity_key(base_preset, value) : std::string{};
        current = std::move(next);
        if (deleting_active) {
            ImGui::GetIO().WantSaveIniSettings = false;
            apply_preview_lock(ImGui::DockBuilderGetNode(current.root), current.locked);
            application_views::synchronize_workspace_visibility(base_preset);
        }
        if (has_preset)
            application_views::remove_persisted_workspace_visibility(
                removed_identity);
        return workspace_request_result_t::completed;
    } catch (...) {
        return workspace_request_result_t::failed;
    }
}

workspace_request_result_t restore_builtin(workspace_preset_t preset) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    current.active_user.clear();
    current.layouts[preset_index(preset)].clear();
    current.layout_nodes[preset_index(preset)] = {};
    current.layout_locks[preset_index(preset)] = false;
    application_views::reset_persisted_workspace_visibility(preset, false);
    current.pending = preset;
    current.rebuild = true;
    current.root_prepared = false;
    current.transition_frames = 2;
    return workspace_request_result_t::completed;
}

workspace_request_result_t reset_current() noexcept { return restore_builtin(active_preset()); }

workspace_request_result_t reset_all() noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    for (auto& layout : current.layouts)
        layout.clear();
    for (auto& nodes : current.layout_nodes)
        nodes = {};
    current.user_layouts.clear();
    current.user_layout_nodes.clear();
    current.user_presets.clear();
    current.user_layout_generations.clear();
    current.user_layout_locks.clear();
    current.active_user.clear();
    application_views::reset_persisted_workspace_visibility(
        workspace_preset_t::analysis, true);
    return restore_builtin(workspace_preset_t::analysis);
}

workspace_request_result_t activate_safe_layout() noexcept
{
    return restore_builtin(workspace_preset_t::safe);
}

workspace_request_result_t open_missing_views() noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || !current.root_prepared || current.locked)
        return workspace_request_result_t::unavailable;
    current.nodes = resolved_preview_nodes(current);
    if (current.nodes.root == 0 || current.nodes.navigator == 0 ||
        current.nodes.documents == 0 || current.nodes.inspector == 0 ||
        current.nodes.bottom == 0 ||
        ImGui::DockBuilderGetNode(current.nodes.root) == nullptr ||
        ImGui::DockBuilderGetNode(current.nodes.navigator) == nullptr ||
        ImGui::DockBuilderGetNode(current.nodes.documents) == nullptr ||
        ImGui::DockBuilderGetNode(current.nodes.inspector) == nullptr ||
        ImGui::DockBuilderGetNode(current.nodes.bottom) == nullptr)
        return workspace_request_result_t::unavailable;
    dock_preview_named_windows(current.active, current.nodes.navigator,
        current.nodes.documents, current.nodes.inspector, current.nodes.bottom, true);
    ImGui::DockBuilderFinish(current.nodes.root);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

void shutdown() noexcept
{
    preview_state() = preview_state_t{};
}

}

#else

#if !defined(AIDA_IMGUI_SOURCE_SHA256)
#error AIDA_IMGUI_SOURCE_SHA256 must identify the audited vendored Dear ImGui source
#endif

#define AIDA_WORKSPACE_STRINGIFY_IMPL(value) #value
#define AIDA_WORKSPACE_STRINGIFY(value) AIDA_WORKSPACE_STRINGIFY_IMPL(value)

#include "core/infra/executor.hpp"
#include "core/ui/task_center.hpp"
#include "helpers/diag_log.hpp"

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string_view>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace aida::ui::workspace_layout {
namespace {

constexpr std::uint32_t kSchemaVersion = 3;
constexpr std::size_t kMaximumPayloadBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaximumContainerBytes = kMaximumPayloadBytes + 2048U;
constexpr std::string_view kMagic = "AIDA_WORKSPACE_LAYOUT\r\n";
constexpr std::string_view kHeaderTerminator = "\r\n\r\n";
constexpr std::string_view kImguiSourceFingerprint = AIDA_WORKSPACE_STRINGIFY(AIDA_IMGUI_SOURCE_SHA256);
#undef AIDA_WORKSPACE_STRINGIFY
#undef AIDA_WORKSPACE_STRINGIFY_IMPL

enum class read_result_t {
    absent,
    io_failure,
    invalid,
    valid
};

struct layout_environment_t {
    std::int64_t work_x = 0;
    std::int64_t work_y = 0;
    std::uint64_t work_width = 0;
    std::uint64_t work_height = 0;
    std::uint32_t dpi_milli = 1000;
};

struct state_t {
    bool initialized = false;
    bool needs_default = false;
    bool root_prepared = false;
    bool recovered_from_backup = false;
    bool preserve_recovery_backup = false;
    bool persistence_available = false;
    ImGuiID expected_root = 0;
    workspace_preset_t active = workspace_preset_t::analysis;
    workspace_preset_t pending = workspace_preset_t::analysis;
    std::string active_user;
    bool rebuild_requested = false;
    bool locked = false;
    std::uint8_t select_defaults_after_realize_frames = 0;
    std::uint8_t transition_frames = 0;
    ImVec2 last_position{0.0f, 0.0f};
    ImVec2 last_size{0.0f, 0.0f};
    ImVec2 rehome_work_position{0.0f, 0.0f};
    ImVec2 rehome_work_size{0.0f, 0.0f};
    float rehome_dpi_scale = 0.0f;
    bool rehome_initialized = false;
    std::uint64_t next_save_attempt_ms = 0;
    std::uint64_t generation = 0;
    layout_environment_t environment;
    dock_nodes_t nodes;
    std::filesystem::path directory;
    std::filesystem::path primary;
    std::filesystem::path backup;
    std::filesystem::path invalid;
    std::filesystem::path active_record;
    std::filesystem::path legacy_primary;
    std::string registry_fingerprint;
    std::string operation_status;
    std::string operation_error;
};

state_t& state() noexcept;

struct layout_paths_t {
    std::filesystem::path directory;
    std::filesystem::path primary;
    std::filesystem::path backup;
    std::filesystem::path invalid;
};

struct record_metadata_t {
    std::uint64_t generation = 0;
    bool clean_shutdown = false;
    dock_nodes_t nodes;
    workspace_preset_t preset = workspace_preset_t::analysis;
    bool locked = false;
    std::uint32_t preset_revision = 1;
    std::uint64_t saved_unix_ms = 0;
    layout_environment_t environment;
    std::array<char, 17> registry_fingerprint{};
};

bool registry_fingerprint_matches(const record_metadata_t& metadata) noexcept
{
    const std::string& current = state().registry_fingerprint;
    return current.size() == 16 && std::equal(current.begin(), current.end(),
        metadata.registry_fingerprint.begin());
}

enum class operation_kind_t : std::uint8_t {
    set_lock,
    switch_preset,
    save_user,
    load_user,
    rename_user,
    delete_user,
    restore_preset,
    reset_all
};

struct operation_request_t {
    operation_kind_t kind = operation_kind_t::switch_preset;
    std::uint64_t serial = 0;
    std::uint64_t source_generation = 0;
    ImGuiID expected_root = 0;
    workspace_preset_t current_preset = workspace_preset_t::analysis;
    workspace_preset_t target_preset = workspace_preset_t::analysis;
    bool target_locked = false;
    std::uint64_t save_generation = 0;
    std::uint64_t expected_user_generation = 0;
    std::uint64_t catalog_epoch = 0;
    bool skip_backup = false;
    dock_nodes_t nodes;
    layout_paths_t current_paths;
    layout_paths_t target_paths;
    layout_paths_t source_user_paths;
    layout_paths_t fallback_paths;
    std::filesystem::path active_record;
    std::filesystem::path workspace_directory;
    std::filesystem::path user_directory;
    std::string current_user_name;
    std::string source_user_name;
    std::string target_user_name;
    std::string registry_fingerprint;
    bool overwrite = false;
    std::vector<layout_paths_t> reset_paths;
    std::shared_ptr<const std::string> current_payload;
    layout_environment_t environment;
    std::string task_id;
};

struct operation_result_t {
    operation_kind_t kind = operation_kind_t::switch_preset;
    std::uint64_t serial = 0;
    std::uint64_t source_generation = 0;
    workspace_preset_t target_preset = workspace_preset_t::analysis;
    bool target_locked = false;
    bool success = false;
    bool use_default = false;
    bool apply_layout = false;
    std::uint64_t saved_generation = 0;
    record_metadata_t metadata;
    std::string payload;
    std::string active_user_name;
    std::string source_user_name;
    std::string target_user_name;
    std::shared_ptr<const std::vector<user_workspace_descriptor_t>> catalog;
    std::uint64_t catalog_epoch = 0;
    std::string error;
    std::string task_id;
};

struct operation_runtime_t {
    std::atomic<bool> pending{false};
    std::atomic<std::uint64_t> serial{0};
    std::mutex result_mutex;
    std::shared_ptr<operation_result_t> result;
    std::shared_ptr<const operation_request_t> active_request;
    std::shared_ptr<const operation_request_t> last_failed_request;
    std::atomic<std::uint64_t> retry_requested{0};
};

operation_runtime_t& operation_runtime() noexcept
{
    static operation_runtime_t value;
    return value;
}

state_t& state() noexcept
{
    static state_t value;
    return value;
}

std::shared_ptr<const std::vector<user_workspace_descriptor_t>>& catalog_publication() noexcept
{
    static std::shared_ptr<const std::vector<user_workspace_descriptor_t>> value =
        std::make_shared<const std::vector<user_workspace_descriptor_t>>();
    return value;
}

std::atomic<std::uint64_t>& catalog_epoch() noexcept
{
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& published_catalog_epoch() noexcept
{
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<bool>& catalog_ready() noexcept
{
    static std::atomic<bool> value{false};
    return value;
}

std::mutex& catalog_publication_mutex() noexcept
{
    static std::mutex value;
    return value;
}

std::shared_ptr<const std::vector<user_workspace_descriptor_t>> catalog_snapshot() noexcept
{
    return std::atomic_load_explicit(&catalog_publication(), std::memory_order_acquire);
}

void publish_catalog(
    std::shared_ptr<const std::vector<user_workspace_descriptor_t>> catalog,
    std::uint64_t epoch) noexcept
{
    if (!catalog)
        return;
    std::lock_guard<std::mutex> lock(catalog_publication_mutex());
    if (epoch < published_catalog_epoch().load(std::memory_order_acquire))
        return;
    std::atomic_store_explicit(&catalog_publication(), std::move(catalog),
        std::memory_order_release);
    published_catalog_epoch().store(epoch, std::memory_order_release);
    catalog_ready().store(true, std::memory_order_release);
}

bool dock_node_within(const ImGuiDockNode* root, const ImGuiDockNode* node) noexcept
{
    while (node) {
        if (node == root)
            return true;
        node = node->ParentNode;
    }
    return false;
}

void collect_dock_leaves(ImGuiDockNode* node, std::vector<ImGuiDockNode*>& leaves) noexcept
{
    if (!node)
        return;
    if (node->IsLeafNode()) {
        leaves.push_back(node);
        return;
    }
    collect_dock_leaves(node->ChildNodes[0], leaves);
    collect_dock_leaves(node->ChildNodes[1], leaves);
}

ImGuiDockNode* preferred_role_leaf(ImGuiDockNode* subtree, ImGuiDockNode* root,
    dock_role_t role) noexcept
{
    std::vector<ImGuiDockNode*> leaves;
    collect_dock_leaves(subtree, leaves);
    if (leaves.empty())
        collect_dock_leaves(root, leaves);
    if (leaves.empty())
        return nullptr;
    const ImVec2 root_center(root->Pos.x + root->Size.x * 0.5f,
        root->Pos.y + root->Size.y * 0.5f);
    ImGuiDockNode* selected = nullptr;
    double selected_score = -(std::numeric_limits<double>::max)();
    for (ImGuiDockNode* leaf : leaves) {
        const double center_x = static_cast<double>(leaf->Pos.x + leaf->Size.x * 0.5f);
        const double center_y = static_cast<double>(leaf->Pos.y + leaf->Size.y * 0.5f);
        const double area = static_cast<double>((std::max)(leaf->Size.x, 1.0f)) *
            static_cast<double>((std::max)(leaf->Size.y, 1.0f));
        double score = static_cast<double>(leaf->Windows.Size) * 1000000000.0 + area;
        if (role == dock_role_t::documents) {
            if (leaf->IsCentralNode())
                score += 1000000000000.0;
            score -= (std::abs(center_x - root_center.x) +
                std::abs(center_y - root_center.y)) * 1000.0;
        } else if (role == dock_role_t::navigator) {
            score -= center_x * 1000.0;
        } else if (role == dock_role_t::inspector) {
            score += center_x * 1000.0;
        } else if (role == dock_role_t::bottom) {
            score += center_y * 1000.0;
        }
        if (!selected || score > selected_score) {
            selected = leaf;
            selected_score = score;
        }
    }
    return selected;
}

dock_nodes_t resolved_nodes(const state_t& current) noexcept
{
    dock_nodes_t nodes = current.nodes;
    nodes.root = current.expected_root;
    ImGuiDockNode* root = ImGui::DockBuilderGetNode(nodes.root);
    if (!root)
        return {nodes.root, nodes.root, nodes.root, nodes.root, nodes.root};
    const auto resolve = [root](ImGuiID candidate, dock_role_t role) noexcept {
        ImGuiDockNode* node = candidate ? ImGui::DockBuilderGetNode(candidate) : nullptr;
        if (!node || !dock_node_within(root, node))
            node = root;
        if (node->IsLeafNode())
            return node->ID;
        if (ImGuiDockNode* leaf = preferred_role_leaf(node, root, role))
            return leaf->ID;
        return root->ID;
    };
    nodes.navigator = resolve(nodes.navigator, dock_role_t::navigator);
    nodes.documents = resolve(nodes.documents, dock_role_t::documents);
    nodes.inspector = resolve(nodes.inspector, dock_role_t::inspector);
    nodes.bottom = resolve(nodes.bottom, dock_role_t::bottom);
    return nodes;
}

std::recursive_mutex& write_mutex() noexcept
{
    static std::recursive_mutex value;
    return value;
}

std::atomic<std::uint64_t>& committed_generation() noexcept
{
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& failed_generation() noexcept
{
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::uint64_t fnv1a64(std::string_view value) noexcept
{
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char raw_byte : value) {
        const auto byte = static_cast<unsigned char>(raw_byte);
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool parse_decimal(std::string_view value, std::uint64_t& output) noexcept
{
    if (value.empty())
        return false;
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
        return false;
    output = parsed;
    return true;
}

bool parse_hex(std::string_view value, std::uint64_t& output) noexcept
{
    if (value.empty())
        return false;
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 16);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
        return false;
    output = parsed;
    return true;
}

bool parse_signed_decimal(std::string_view value, std::int64_t& output) noexcept
{
    if (value.empty())
        return false;
    std::int64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
        return false;
    output = parsed;
    return true;
}

bool valid_registry_fingerprint(std::string_view value) noexcept
{
    if (value.size() != 16)
        return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f');
    });
}

bool parse_docking_token(std::string_view line, std::string_view token,
    std::uint64_t& output, bool& present) noexcept
{
    const std::size_t position = line.find(token);
    if (position == std::string_view::npos) {
        present = false;
        return true;
    }
    const std::size_t first = position + token.size();
    const std::size_t last = line.find(' ', first);
    present = true;
    return parse_hex(line.substr(first, last == std::string_view::npos
        ? line.size() - first : last - first), output);
}

bool validate_docking_structure(std::string_view docking_data, ImGuiID expected_root,
    const dock_nodes_t& roles) noexcept
{
    struct node_record_t {
        std::uint64_t parent = 0;
        std::size_t children = 0;
        bool split = false;
        bool dockspace = false;
    };
    std::map<std::uint64_t, node_record_t> records;
    std::size_t cursor = 0;
    while (cursor < docking_data.size()) {
        const std::size_t line_end = docking_data.find('\n', cursor);
        std::string_view line = docking_data.substr(cursor,
            line_end == std::string_view::npos ? docking_data.size() - cursor : line_end - cursor);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t' || line.front() == '\r'))
            line.remove_prefix(1);
        const bool dockspace = line.rfind("DockSpace", 0) == 0;
        const bool dock_node = line.rfind("DockNode", 0) == 0;
        if (dockspace || dock_node) {
            if (records.size() >= 4096U)
                return false;
            std::uint64_t id = 0;
            std::uint64_t parent = 0;
            bool id_present = false;
            bool parent_present = false;
            if (!parse_docking_token(line, "ID=0x", id, id_present) || !id_present || id == 0 ||
                !parse_docking_token(line, "Parent=0x", parent, parent_present) ||
                (parent_present && parent == 0))
                return false;
            node_record_t record;
            record.parent = parent_present ? parent : 0;
            record.split = line.find(" Split=X") != std::string_view::npos ||
                line.find(" Split=Y") != std::string_view::npos;
            record.dockspace = dockspace;
            if (!records.emplace(id, record).second)
                return false;
        }
        if (line_end == std::string_view::npos)
            break;
        cursor = line_end + 1U;
    }
    const auto root = records.find(expected_root);
    if (root == records.end() || root->second.parent != 0 || !root->second.dockspace)
        return false;
    for (auto& entry : records) {
        if (entry.second.parent != 0) {
            auto parent = records.find(entry.second.parent);
            if (parent == records.end() || ++parent->second.children > 2U)
                return false;
        }
    }
    for (const auto& entry : records) {
        if (entry.second.split != (entry.second.children == 2U))
            return false;
        std::uint64_t current = entry.first;
        for (std::size_t depth = 0; depth <= records.size(); ++depth) {
            const auto node = records.find(current);
            if (node == records.end())
                return false;
            if (node->second.parent == 0)
                break;
            current = node->second.parent;
            if (depth == records.size())
                return false;
        }
    }
    const std::array<ImGuiID, 4> role_ids{
        roles.navigator, roles.documents, roles.inspector, roles.bottom};
    for (const ImGuiID role_id : role_ids) {
        const auto role = records.find(role_id);
        if (role == records.end() || role->second.children != 0 || role->second.split)
            return false;
        std::uint64_t current = role_id;
        bool reached_root = false;
        for (std::size_t depth = 0; depth <= records.size(); ++depth) {
            if (current == expected_root) {
                reached_root = true;
                break;
            }
            const auto node = records.find(current);
            if (node == records.end() || node->second.parent == 0)
                break;
            current = node->second.parent;
        }
        if (!reached_root)
            return false;
    }
    return true;
}

bool select_preset_paths(state_t& current, workspace_preset_t preset) noexcept
{
    try {
        const std::string_view id = descriptor_for(preset).stable_id;
        const std::wstring wide_id(id.begin(), id.end());
        current.primary = current.directory / (wide_id + L".aida-layout");
        current.backup = current.directory / (wide_id + L".aida-layout.bak");
        current.invalid = current.directory / (wide_id + L".aida-layout.invalid");
        return true;
    } catch (...) {
        return false;
    }
}

bool assign_paths(state_t& current) noexcept
{
    PWSTR roaming = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_CREATE, nullptr, &roaming);
    if (FAILED(result) || !roaming)
        return false;
    try {
        current.directory = std::filesystem::path(roaming) / L"AiDA" / L"Standalone" / L"workspaces";
        current.active_record = current.directory / L"active-workspace-v2.txt";
        current.legacy_primary = current.directory / L"standalone-layout-v1.aida-layout";
        if (!select_preset_paths(current, current.active))
            return false;
    } catch (...) {
        CoTaskMemFree(roaming);
        return false;
    }
    CoTaskMemFree(roaming);
    return true;
}

void load_active_workspace_record(state_t& current) noexcept
{
    HANDLE file = CreateFileW(current.active_record.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;
    char value[160]{};
    DWORD read = 0;
    const bool valid = ReadFile(file, value, sizeof(value) - 1U, &read, nullptr) != FALSE;
    CloseHandle(file);
    if (!valid || read == 0 || read >= sizeof(value))
        return;
    const std::string_view record(value, read);
    const std::size_t separator = record.find('\n');
    const std::string_view id = record.substr(0, separator);
    current.locked = separator != std::string_view::npos &&
        separator + 1U < record.size() && record[separator + 1U] == '1';
    const std::size_t user_separator = separator == std::string_view::npos
        ? std::string_view::npos : record.find('\n', separator + 1U);
    if (user_separator != std::string_view::npos && user_separator + 1U < record.size()) {
        const std::string_view user_name = record.substr(user_separator + 1U);
        if (valid_user_layout_name(user_name))
            current.active_user.assign(user_name);
    }
    for (const auto& descriptor : kPresetDescriptors) {
        if (id == descriptor.stable_id) {
            current.active = descriptor.id;
            current.pending = descriptor.id;
            if (!select_preset_paths(current, descriptor.id))
                return;
            return;
        }
    }
}

bool save_active_workspace_record_values(const std::filesystem::path& directory,
    const std::filesystem::path& active_record, workspace_preset_t preset,
    bool locked, std::string_view user_name = {}) noexcept
{
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error)
        return false;
    std::filesystem::path temporary = active_record;
    temporary += L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    std::string record;
    try {
        record = std::string(descriptor_for(preset).stable_id) +
            (locked ? "\n1\n" : "\n0\n");
        if (!user_name.empty()) {
            if (!valid_user_layout_name(user_name))
                throw std::invalid_argument("invalid user workspace name");
            record.append(user_name);
        }
    } catch (...) {
        CloseHandle(file);
        DeleteFileW(temporary.c_str());
        return false;
    }
    DWORD written = 0;
    const bool saved = WriteFile(file, record.data(), static_cast<DWORD>(record.size()), &written, nullptr) != FALSE &&
        written == record.size() && FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!saved || !MoveFileExW(temporary.c_str(), active_record.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

bool read_file_bounded(const std::filesystem::path& path, std::vector<char>& output, read_result_t& result) noexcept
{
    result = read_result_t::io_failure;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        result = GetLastError() == ERROR_FILE_NOT_FOUND ? read_result_t::absent : read_result_t::io_failure;
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        static_cast<unsigned long long>(size.QuadPart) > kMaximumContainerBytes) {
        CloseHandle(file);
        result = read_result_t::invalid;
        return false;
    }

    try {
        output.resize(static_cast<std::size_t>(size.QuadPart));
    } catch (...) {
        CloseHandle(file);
        result = read_result_t::io_failure;
        return false;
    }

    std::size_t offset = 0;
    while (offset < output.size()) {
        const DWORD requested = static_cast<DWORD>((std::min)(output.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD completed = 0;
        if (!ReadFile(file, output.data() + offset, requested, &completed, nullptr) || completed == 0) {
            CloseHandle(file);
            output.clear();
            result = read_result_t::io_failure;
            return false;
        }
        offset += completed;
    }
    CloseHandle(file);
    result = read_result_t::valid;
    return true;
}

bool extract_payload(const std::vector<char>& container, ImGuiID expected_root,
    std::string_view& payload, record_metadata_t* metadata) noexcept
{
    const std::string_view input(container.data(), container.size());
    if (input.size() < kMagic.size() || input.substr(0, kMagic.size()) != kMagic)
        return false;
    const std::size_t terminator = input.find(kHeaderTerminator, kMagic.size());
    if (terminator == std::string_view::npos || terminator > 1536U)
        return false;

    std::uint64_t schema = 0;
    std::uint64_t payload_bytes = 0;
    std::uint64_t checksum = 0;
    std::uint64_t generation = 0;
    std::uint64_t clean_shutdown = 0;
    std::uint64_t preset_revision_value = 0;
    std::uint64_t saved_unix_ms = 0;
    std::int64_t monitor_work_x = 0;
    std::int64_t monitor_work_y = 0;
    std::uint64_t monitor_work_width = 0;
    std::uint64_t monitor_work_height = 0;
    std::uint64_t monitor_dpi_milli = 0;
    std::uint64_t node_root = 0;
    std::uint64_t node_navigator = 0;
    std::uint64_t node_documents = 0;
    std::uint64_t node_inspector = 0;
    std::uint64_t node_bottom = 0;
    bool schema_seen = false;
    bool bytes_seen = false;
    bool checksum_seen = false;
    bool imgui_seen = false;
    bool imgui_source_seen = false;
    bool preset_seen = false;
    workspace_preset_t parsed_preset = workspace_preset_t::analysis;
    bool preset_revision_seen = false;
    bool registry_seen = false;
    bool generation_seen = false;
    bool clean_seen = false;
    bool lock_seen = false;
    std::uint64_t layout_locked = 0;
    bool timestamp_seen = false;
    bool monitor_x_seen = false;
    bool monitor_y_seen = false;
    bool monitor_width_seen = false;
    bool monitor_height_seen = false;
    bool monitor_dpi_seen = false;
    std::string_view registry_fingerprint;
    bool node_root_seen = false;
    bool node_navigator_seen = false;
    bool node_documents_seen = false;
    bool node_inspector_seen = false;
    bool node_bottom_seen = false;
    std::size_t cursor = kMagic.size();
    while (cursor < terminator) {
        const std::size_t line_end = input.find("\r\n", cursor);
        if (line_end == std::string_view::npos || line_end > terminator)
            return false;
        const std::string_view line = input.substr(cursor, line_end - cursor);
        const std::size_t separator = line.find('=');
        if (separator == std::string_view::npos)
            return false;
        const std::string_view key = line.substr(0, separator);
        const std::string_view value = line.substr(separator + 1U);
        if (key == "schema") {
            if (schema_seen || !parse_decimal(value, schema))
                return false;
            schema_seen = true;
        } else if (key == "payload_bytes") {
            if (bytes_seen || !parse_decimal(value, payload_bytes))
                return false;
            bytes_seen = true;
        } else if (key == "payload_fnv1a64") {
            if (checksum_seen || !parse_hex(value, checksum))
                return false;
            checksum_seen = true;
        } else if (key == "imgui_version") {
            if (imgui_seen || value != IMGUI_VERSION)
                return false;
            imgui_seen = true;
        } else if (key == "imgui_source_sha256") {
            if (imgui_source_seen || value != kImguiSourceFingerprint)
                return false;
            imgui_source_seen = true;
        } else if (key == "preset_id") {
            if (preset_seen)
                return false;
            bool recognized = false;
            for (const auto& descriptor : kPresetDescriptors) {
                if (value == descriptor.stable_id) {
                    parsed_preset = descriptor.id;
                    recognized = true;
                    break;
                }
            }
            if (!recognized)
                return false;
            preset_seen = true;
        } else if (key == "preset_revision") {
            if (preset_revision_seen || !parse_decimal(value, preset_revision_value) ||
                preset_revision_value == 0)
                return false;
            preset_revision_seen = true;
        } else if (key == "view_registry") {
            if (registry_seen)
                return false;
            registry_fingerprint = value;
            registry_seen = true;
        } else if (key == "generation") {
            if (generation_seen || !parse_decimal(value, generation) || generation == 0)
                return false;
            generation_seen = true;
        } else if (key == "clean_shutdown") {
            if (clean_seen || !parse_decimal(value, clean_shutdown) || clean_shutdown > 1)
                return false;
            clean_seen = true;
        } else if (key == "layout_locked") {
            if (lock_seen || !parse_decimal(value, layout_locked) || layout_locked > 1)
                return false;
            lock_seen = true;
        } else if (key == "saved_unix_ms") {
            if (timestamp_seen || !parse_decimal(value, saved_unix_ms) || saved_unix_ms == 0)
                return false;
            timestamp_seen = true;
        } else if (key == "monitor_work_x") {
            if (monitor_x_seen || !parse_signed_decimal(value, monitor_work_x))
                return false;
            monitor_x_seen = true;
        } else if (key == "monitor_work_y") {
            if (monitor_y_seen || !parse_signed_decimal(value, monitor_work_y))
                return false;
            monitor_y_seen = true;
        } else if (key == "monitor_work_width") {
            if (monitor_width_seen || !parse_decimal(value, monitor_work_width))
                return false;
            monitor_width_seen = true;
        } else if (key == "monitor_work_height") {
            if (monitor_height_seen || !parse_decimal(value, monitor_work_height))
                return false;
            monitor_height_seen = true;
        } else if (key == "monitor_dpi_milli") {
            if (monitor_dpi_seen || !parse_decimal(value, monitor_dpi_milli))
                return false;
            monitor_dpi_seen = true;
        } else if (key == "node_root") {
            if (node_root_seen || !parse_hex(value, node_root))
                return false;
            node_root_seen = true;
        } else if (key == "node_navigator") {
            if (node_navigator_seen || !parse_hex(value, node_navigator))
                return false;
            node_navigator_seen = true;
        } else if (key == "node_documents") {
            if (node_documents_seen || !parse_hex(value, node_documents))
                return false;
            node_documents_seen = true;
        } else if (key == "node_inspector") {
            if (node_inspector_seen || !parse_hex(value, node_inspector))
                return false;
            node_inspector_seen = true;
        } else if (key == "node_bottom") {
            if (node_bottom_seen || !parse_hex(value, node_bottom))
                return false;
            node_bottom_seen = true;
        } else {
            return false;
        }
        cursor = line_end + 2U;
    }

    const std::size_t payload_offset = terminator + kHeaderTerminator.size();
    if (!schema_seen || !bytes_seen || !checksum_seen || !imgui_seen || !imgui_source_seen || !preset_seen ||
        !preset_revision_seen || !registry_seen || !generation_seen || !clean_seen ||
        !node_root_seen || !node_navigator_seen || !node_documents_seen ||
        !node_inspector_seen || !node_bottom_seen ||
        (schema < 1 || schema > kSchemaVersion) ||
        payload_bytes == 0 || payload_bytes > kMaximumPayloadBytes ||
        payload_offset > input.size() || payload_bytes != input.size() - payload_offset)
        return false;
    if (preset_revision_value > descriptor_for(parsed_preset).revision)
        return false;
    if (schema >= 2 && !lock_seen)
        return false;
    if (schema >= 3) {
        if (!timestamp_seen || !monitor_x_seen || !monitor_y_seen || !monitor_width_seen ||
            !monitor_height_seen || !monitor_dpi_seen ||
            !valid_registry_fingerprint(registry_fingerprint) ||
            monitor_work_x < -10000000 || monitor_work_x > 10000000 ||
            monitor_work_y < -10000000 || monitor_work_y > 10000000 ||
            monitor_work_width == 0 || monitor_work_width > 10000000 ||
            monitor_work_height == 0 || monitor_work_height > 10000000 ||
            monitor_dpi_milli < 250 || monitor_dpi_milli > 8000)
            return false;
    } else if (registry_fingerprint != "compatibility-v1" &&
        registry_fingerprint != "stable-v2") {
        return false;
    }

    payload = input.substr(payload_offset, static_cast<std::size_t>(payload_bytes));
    if (payload.find('\0') != std::string_view::npos || fnv1a64(payload) != checksum ||
        payload.find("[Docking][Data]") == std::string_view::npos)
        return false;

    const std::uint64_t maximum_id = static_cast<std::uint64_t>((std::numeric_limits<ImGuiID>::max)());
    const bool roles_valid = node_root == expected_root && node_root <= maximum_id &&
        node_navigator != 0 && node_navigator <= maximum_id &&
        node_documents != 0 && node_documents <= maximum_id &&
        node_inspector != 0 && node_inspector <= maximum_id &&
        node_bottom != 0 && node_bottom <= maximum_id;
    if (!roles_valid)
        return false;

    const std::size_t docking_start = payload.find("[Docking][Data]");
    const std::size_t next_section = payload.find("\n[", docking_start + 1U);
    const std::string_view docking_data = next_section == std::string_view::npos
        ? payload.substr(docking_start)
        : payload.substr(docking_start, next_section - docking_start);
    const dock_nodes_t parsed_nodes{
        static_cast<ImGuiID>(node_root),
        static_cast<ImGuiID>(node_navigator),
        static_cast<ImGuiID>(node_documents),
        static_cast<ImGuiID>(node_inspector),
        static_cast<ImGuiID>(node_bottom)};
    if (!validate_docking_structure(docking_data, expected_root, parsed_nodes))
        return false;

    if (metadata) {
        metadata->generation = generation;
        metadata->clean_shutdown = clean_shutdown != 0;
        metadata->nodes = parsed_nodes;
        metadata->preset = parsed_preset;
        metadata->locked = layout_locked != 0;
        metadata->preset_revision = static_cast<std::uint32_t>(preset_revision_value);
        metadata->saved_unix_ms = saved_unix_ms;
        metadata->environment = {monitor_work_x, monitor_work_y, monitor_work_width,
            monitor_work_height, static_cast<std::uint32_t>(monitor_dpi_milli == 0
                ? 1000 : monitor_dpi_milli)};
        metadata->registry_fingerprint.fill('\0');
        if (registry_fingerprint.size() == 16)
            std::copy(registry_fingerprint.begin(), registry_fingerprint.end(),
                metadata->registry_fingerprint.begin());
    }
    return true;
}

read_result_t load_layout_file(const std::filesystem::path& path, ImGuiID expected_root,
    record_metadata_t& metadata) noexcept
{
    std::vector<char> container;
    read_result_t result = read_result_t::io_failure;
    if (!read_file_bounded(path, container, result))
        return result;
    std::string_view payload;
    if (!extract_payload(container, expected_root, payload, &metadata))
        return read_result_t::invalid;
    ImGui::LoadIniSettingsFromMemory(payload.data(), payload.size());
    application_views::migrate_persisted_window_settings();
    return read_result_t::valid;
}

bool validate_layout_file(const std::filesystem::path& path, ImGuiID expected_root) noexcept
{
    std::vector<char> container;
    read_result_t result = read_result_t::io_failure;
    if (!read_file_bounded(path, container, result))
        return false;
    std::string_view payload;
    return extract_payload(container, expected_root, payload, nullptr);
}

bool inspect_layout_file(const std::filesystem::path& path, ImGuiID expected_root,
    record_metadata_t& metadata) noexcept
{
    std::vector<char> container;
    read_result_t result = read_result_t::io_failure;
    if (!read_file_bounded(path, container, result))
        return false;
    std::string_view payload;
    return extract_payload(container, expected_root, payload, &metadata);
}

read_result_t read_layout_payload(const std::filesystem::path& path,
    ImGuiID expected_root, record_metadata_t& metadata, std::string& payload_copy) noexcept
{
    std::vector<char> container;
    read_result_t result = read_result_t::io_failure;
    if (!read_file_bounded(path, container, result))
        return result;
    std::string_view payload;
    if (!extract_payload(container, expected_root, payload, &metadata))
        return read_result_t::invalid;
    try {
        payload_copy.assign(payload);
    } catch (...) {
        payload_copy.clear();
        return read_result_t::io_failure;
    }
    return read_result_t::valid;
}

bool write_all(HANDLE file, std::string_view data) noexcept
{
    std::size_t offset = 0;
    while (offset < data.size()) {
        const DWORD requested = static_cast<DWORD>((std::min)(data.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD completed = 0;
        if (!WriteFile(file, data.data() + offset, requested, &completed, nullptr) || completed == 0)
            return false;
        offset += completed;
    }
    return true;
}

bool refresh_backup_atomic(const layout_paths_t& paths) noexcept
{
    std::filesystem::path temporary;
    try {
        temporary = paths.backup;
        temporary += L".tmp";
    } catch (...) {
        return false;
    }
    DeleteFileW(temporary.c_str());
    if (!CopyFileW(paths.primary.c_str(), temporary.c_str(), TRUE))
        return false;
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    const bool flushed = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!flushed || !MoveFileExW(temporary.c_str(), paths.backup.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

bool save_payload(const layout_paths_t& paths, ImGuiID expected_root, std::string_view payload,
    std::uint64_t generation, bool clean_shutdown, bool skip_backup,
    const dock_nodes_t& nodes, workspace_preset_t preset, bool locked,
    const layout_environment_t& environment, std::string_view registry_fingerprint)
{
    if (payload.empty() || payload.size() > kMaximumPayloadBytes || generation == 0 ||
        !valid_registry_fingerprint(registry_fingerprint) ||
        payload.find("[Docking][Data]") == std::string_view::npos)
        return false;

    std::error_code directory_error;
    std::filesystem::create_directories(paths.directory, directory_error);
    if (directory_error)
        return false;

    const std::size_t docking_start = payload.find("[Docking][Data]");
    const std::size_t next_section = payload.find("\n[", docking_start + 1U);
    const std::string_view docking_data = next_section == std::string_view::npos
        ? payload.substr(docking_start)
        : payload.substr(docking_start, next_section - docking_start);
    if (!validate_docking_structure(docking_data, expected_root, nodes) ||
        environment.work_width == 0 || environment.work_height == 0 ||
        environment.dpi_milli < 250 || environment.dpi_milli > 8000)
        return false;
    FILETIME file_time{};
    GetSystemTimeAsFileTime(&file_time);
    ULARGE_INTEGER timestamp{};
    timestamp.LowPart = file_time.dwLowDateTime;
    timestamp.HighPart = file_time.dwHighDateTime;
    constexpr std::uint64_t windows_to_unix_epoch = 116444736000000000ULL;
    if (timestamp.QuadPart <= windows_to_unix_epoch)
        return false;
    const std::uint64_t saved_unix_ms =
        (timestamp.QuadPart - windows_to_unix_epoch) / 10000ULL;

    char header[1536]{};
    const int header_length = std::snprintf(header, sizeof(header),
        "AIDA_WORKSPACE_LAYOUT\r\nschema=%u\r\nimgui_version=%s\r\nimgui_source_sha256=%.*s\r\npreset_id=%.*s\r\npreset_revision=%u\r\nview_registry=%.*s\r\ngeneration=%llu\r\nclean_shutdown=%u\r\nlayout_locked=%u\r\nsaved_unix_ms=%llu\r\nmonitor_work_x=%lld\r\nmonitor_work_y=%lld\r\nmonitor_work_width=%llu\r\nmonitor_work_height=%llu\r\nmonitor_dpi_milli=%u\r\nnode_root=%08X\r\nnode_navigator=%08X\r\nnode_documents=%08X\r\nnode_inspector=%08X\r\nnode_bottom=%08X\r\npayload_bytes=%llu\r\npayload_fnv1a64=%016llx\r\n\r\n",
        kSchemaVersion,
        IMGUI_VERSION,
        static_cast<int>(kImguiSourceFingerprint.size()), kImguiSourceFingerprint.data(),
        static_cast<int>(descriptor_for(preset).stable_id.size()), descriptor_for(preset).stable_id.data(),
        descriptor_for(preset).revision,
        static_cast<int>(registry_fingerprint.size()), registry_fingerprint.data(),
        static_cast<unsigned long long>(generation),
        clean_shutdown ? 1U : 0U,
        locked ? 1U : 0U,
        static_cast<unsigned long long>(saved_unix_ms),
        static_cast<long long>(environment.work_x),
        static_cast<long long>(environment.work_y),
        static_cast<unsigned long long>(environment.work_width),
        static_cast<unsigned long long>(environment.work_height),
        environment.dpi_milli,
        nodes.root, nodes.navigator, nodes.documents, nodes.inspector, nodes.bottom,
        static_cast<unsigned long long>(payload.size()),
        static_cast<unsigned long long>(fnv1a64(payload)));
    if (header_length <= 0 || static_cast<std::size_t>(header_length) >= sizeof(header))
        return false;

    std::filesystem::path temporary = paths.primary;
    temporary += L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    const bool wrote = write_all(file, std::string_view(header, static_cast<std::size_t>(header_length))) &&
        write_all(file, payload) && FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!wrote) {
        DeleteFileW(temporary.c_str());
        return false;
    }

    if (!skip_backup && GetFileAttributesW(paths.primary.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (validate_layout_file(paths.primary, expected_root)) {
            if (!refresh_backup_atomic(paths)) {
                DeleteFileW(temporary.c_str());
                return false;
            }
        } else if (!MoveFileExW(paths.primary.c_str(), paths.invalid.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temporary.c_str());
            return false;
        }
    }
    if (!MoveFileExW(temporary.c_str(), paths.primary.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

layout_paths_t named_user_paths(const state_t& current, std::string_view name);

layout_paths_t capture_paths(const state_t& current) noexcept
{
    try {
        if (!current.active_user.empty())
            return named_user_paths(current, current.active_user);
        return {current.directory, current.primary, current.backup, current.invalid};
    } catch (...) {
        return {};
    }
}

bool write_generation(const layout_paths_t& paths, ImGuiID expected_root,
    std::string_view payload, std::uint64_t generation, bool clean_shutdown,
    bool skip_backup, const dock_nodes_t& nodes, workspace_preset_t preset, bool locked,
    const layout_environment_t& environment, std::string_view registry_fingerprint) noexcept
{
    std::lock_guard<std::recursive_mutex> lock(write_mutex());
    if (generation <= committed_generation().load(std::memory_order_acquire))
        return true;
    const std::uint64_t started_ms = static_cast<std::uint64_t>(GetTickCount64());
    bool saved = false;
    try {
        saved = save_payload(paths, expected_root, payload, generation, clean_shutdown,
            skip_backup, nodes, preset, locked, environment, registry_fingerprint);
    } catch (...) {
        saved = false;
    }
    if (saved)
        committed_generation().store(generation, std::memory_order_release);
    else
        failed_generation().store(generation, std::memory_order_release);
    diag::log_tagged_fmt("workspace_layout",
        "layout_write_complete generation=%llu clean_shutdown=%d payload_bytes=%llu payload_fnv1a64=%016llx elapsed_ms=%llu result=%s",
        static_cast<unsigned long long>(generation), clean_shutdown ? 1 : 0,
        static_cast<unsigned long long>(payload.size()),
        static_cast<unsigned long long>(fnv1a64(payload)),
        static_cast<unsigned long long>(static_cast<std::uint64_t>(GetTickCount64()) - started_ms),
        saved ? "saved" : "failed");
    return saved;
}

bool queue_write(const layout_paths_t& paths, ImGuiID expected_root,
    std::string_view payload, std::uint64_t generation, bool skip_backup,
    const dock_nodes_t& nodes, workspace_preset_t preset, bool locked,
    const layout_environment_t& environment, std::string_view registry_fingerprint)
{
    if (payload.empty() || payload.size() > kMaximumPayloadBytes || generation == 0 ||
        !valid_registry_fingerprint(registry_fingerprint) ||
        payload.find("[Docking][Data]") == std::string_view::npos)
        return false;
    auto immutable_payload = std::make_shared<const std::string>(payload);
    std::string immutable_fingerprint(registry_fingerprint);
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "workspace_layout";
    submission.label = "workspace_layout_atomic_save";
    submission.thread_class = "diagnostics_io";
    submission.domain = aida::infra::executor::domain_t::diagnostics;
    submission.priority = 1;
    submission.generation = generation;
    submission.diagnostic_id = "workspace_layout.save";
    submission.ui_access_policy = "none";
    submission.failure_policy = "retain_last_known_good";
    submission.shutdown_policy = "drain";
    submission.body = [paths, expected_root, immutable_payload, generation, skip_backup,
        nodes, preset, locked, environment,
        registry_fingerprint = std::move(immutable_fingerprint)]() {
        write_generation(paths, expected_root, *immutable_payload, generation, false,
            skip_backup, nodes, preset, locked, environment, registry_fingerprint);
    };
    return aida::infra::executor::submit(std::move(submission)).submitted;
}

void dock_named_windows(workspace_preset_t preset, ImGuiID left, ImGuiID center,
    ImGuiID right, ImGuiID bottom, bool missing_only = false) noexcept
{
    const auto dock = [missing_only](ImGuiID node, std::initializer_list<const char*> stable_ids) {
        for (const char* stable_id : stable_ids) {
            const stable_view_id_t view_id(stable_id);
            if (missing_only && !application_views::is_open(view_id)) {
                const auto opened = application_views::open_for_layout(view_id);
                if (!opened.ok())
                    continue;
            }
            const std::string window_name = application_views::ensure_window_name(
                view_id);
            if (window_name.empty())
                continue;
            ImGuiWindow* window = ImGui::FindWindowByName(window_name.c_str());
            if (!missing_only || !window || window->DockId == 0)
                ImGui::DockBuilderDockWindow(window_name.c_str(), node);
        }
    };
    if (preset == workspace_preset_t::analysis) {
        dock(left, {"view.project_explorer", "view.sessions", "view.navigator", "view.analysis.functions",
            "view.analysis.imports", "view.analysis.exports", "view.analysis.names",
			"view.analysis.strings", "view.analysis.segments", "view.analysis.local_types",
			"view.analysis.segment_registers", "view.analysis.proximity"});
        dock(center, {"view.start_center", "document.disassembly", "document.pseudocode", "document.graph", "document.hex", "document.code", "view.analysis.binary_map"});
        dock(right, {"view.inspector", "view.analysis.references", "view.ai_chat"});
        dock(bottom, {"view.output", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::debugging) {
        dock(left, {"view.sessions", "view.debug.threads", "view.debug.modules", "view.debug.call_stack"});
        dock(center, {"view.start_center", "view.debug.cpu", "view.debug.source", "document.code", "document.hex", "view.debug.cfg"});
        dock(right, {"view.debug.registers", "view.debug.breakpoints", "view.debug.watches", "view.debug.strings", "view.debug.bookmarks"});
        dock(bottom, {"view.debug.stack", "view.debug.memory_map", "view.debug.trace", "view.debug.patches", "view.debug.seh", "view.debug.handles", "view.terminal", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::memory) {
        dock(left, {"view.sessions", "view.memory.value_scan", "view.memory.crypto", "view.memory.aob", "view.memory.decrypt", "view.memory.integrity"});
        dock(center, {"view.start_center", "document.hex", "view.memory.value_scan_results", "view.memory.pointers", "view.memory.snapshots"});
        dock(right, {"view.debug.memory_map", "view.types.dissector"});
        dock(bottom, {"view.memory.address_list", "view.debug.patches", "view.debug.watches", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::types_structures) {
        dock(left, {"view.sessions", "view.types.structures", "view.types.unions", "view.types.enums", "view.types.typedefs", "view.types.functions", "view.types.inferred"});
        dock(center, {"view.start_center", "view.types.struct_recon", "document.code", "document.hex"});
        dock(right, {"view.types.dissector"});
        dock(bottom, {"view.analysis.references", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::network) {
        dock(left, {"view.sessions", "view.network.site_map", "view.network.scope", "view.network.cookies", "view.network.session"});
        dock(center, {"view.start_center", "view.network.proxy", "view.network.intercept", "view.network.repeater", "view.network.browser", "view.network.api"});
        dock(right, {"view.network.decoder", "view.network.comparer", "view.network.scanner", "view.network.reports"});
        dock(bottom, {"view.network.capture", "view.network.logger", "view.network.websocket", "view.network.h2_editor", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::automation_ai) {
        dock(left, {"view.sessions", "view.ai.agents", "view.ai.skills", "view.ai.scripts", "view.project_explorer"});
        dock(center, {"view.start_center", "view.ai_chat", "document.code"});
        dock(right, {"view.ai.evidence", "view.ai.providers", "view.ai.mcp_marketplace"});
        dock(bottom, {"view.background_tasks", "view.mcp_log", "view.output", "view.terminal", "view.diagnostics"});
    } else if (preset == workspace_preset_t::programming) {
        dock(left, {"view.project_explorer", "view.programming.outline", "view.sessions", "view.workspace_search"});
        dock(center, {"view.start_center", "document.code", "document.disassembly", "document.pseudocode"});
        dock(right, {"view.inspector", "view.analysis.references", "view.ai_chat"});
        dock(bottom, {"view.programming.source_debug_console", "view.output", "view.terminal", "view.programming.references", "view.background_tasks", "view.diagnostics"});
    } else {
        dock(left, {"view.project_explorer", "view.sessions", "view.recent"});
        dock(center, {"view.start_center", "document.code"});
        dock(right, {"view.ai_chat"});
        dock(bottom, {"view.diagnostics", "view.output"});
    }
}

void build_default_layout(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size,
    workspace_preset_t preset) noexcept
{
    open_builtin_default_views(preset);
    ImGui::DockBuilderRemoveNode(root_dockspace_id);
    ImGui::DockBuilderAddNode(root_dockspace_id,
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_DockSpace) |
            static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_PassthruCentralNode));
    ImGui::DockBuilderSetNodePos(root_dockspace_id, position);
    ImGui::DockBuilderSetNodeSize(root_dockspace_id, size);

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const float dpi_scale = viewport ? viewport->DpiScale : 1.0f;
    if (compact_single_node_recipe(size, dpi_scale)) {
        dock_open_windows_by_role(root_dockspace_id, root_dockspace_id,
            root_dockspace_id, root_dockspace_id);
        dock_named_windows(preset, root_dockspace_id, root_dockspace_id,
            root_dockspace_id, root_dockspace_id);
        ImGui::DockBuilderFinish(root_dockspace_id);
        const char* primary = application_views::is_open(stable_view_id_t("view.start_center"))
            ? "view.start_center" : compact_primary_view(preset);
        select_docked_window(root_dockspace_id, primary);
        state().nodes = {root_dockspace_id, root_dockspace_id, root_dockspace_id,
            root_dockspace_id, root_dockspace_id};
        state().select_defaults_after_realize_frames = 2;
        ImGui::GetIO().WantSaveIniSettings = true;
        return;
    }

    ImGuiID center = root_dockspace_id;
    ImGuiID left = 0;
    ImGuiID right = 0;
    ImGuiID bottom = 0;
    const layout_ratios_t ratios = calculate_layout_ratios(preset, size,
        dpi_scale);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, ratios.left, &left, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, ratios.right, &right, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, ratios.bottom, &bottom, &center);
    dock_open_windows_by_role(left, center, right, bottom);
    dock_named_windows(preset, left, center, right, bottom);
    ImGui::DockBuilderFinish(root_dockspace_id);
    if (application_views::is_open(stable_view_id_t("view.start_center"))) {
        select_docked_window(center, "view.start_center");
    } else
        select_builtin_default_tabs(preset, left, center, right, bottom);
    state().nodes = {root_dockspace_id, left, center, right, bottom};
    state().select_defaults_after_realize_frames = 2;
    ImGui::GetIO().WantSaveIniSettings = true;
}

void apply_lock_recursive(ImGuiDockNode* node, bool locked) noexcept
{
    if (!node)
        return;
    constexpr ImGuiDockNodeFlags flags =
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoDocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoUndocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoResize);
    node->SetLocalFlags(locked
        ? static_cast<ImGuiDockNodeFlags>(node->LocalFlags | flags)
        : static_cast<ImGuiDockNodeFlags>(node->LocalFlags & ~flags));
    apply_lock_recursive(node->ChildNodes[0], locked);
    apply_lock_recursive(node->ChildNodes[1], locked);
}

void rehome_floating_windows() noexcept
{
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGuiContext* context = ImGui::GetCurrentContext();
    if (!viewport || !context)
        return;
    const float scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const float visible_width = 96.0f * scale;
    const float visible_height = 28.0f * scale;
    const ImVec2 work_min = viewport->WorkPos;
    const ImVec2 work_max(viewport->WorkPos.x + viewport->WorkSize.x,
        viewport->WorkPos.y + viewport->WorkSize.y);
    const ImVec2 maximum_size(
        (std::max)(1.0f, viewport->WorkSize.x),
        (std::max)(1.0f, viewport->WorkSize.y));
    for (ImGuiWindow* window : context->Windows) {
        if (!window || window->DockId != 0 ||
            (window->Flags & (ImGuiWindowFlags_ChildWindow | ImGuiWindowFlags_Popup |
                ImGuiWindowFlags_Tooltip | ImGuiWindowFlags_NoSavedSettings)) != 0)
            continue;
        const ImVec2 clamped_size(
            (std::min)(window->SizeFull.x, maximum_size.x),
            (std::min)(window->SizeFull.y, maximum_size.y));
        if (clamped_size.x != window->SizeFull.x || clamped_size.y != window->SizeFull.y)
            ImGui::SetWindowSize(window, clamped_size, ImGuiCond_Always);
        const float minimum_x = work_min.x - (std::max)(0.0f, clamped_size.x - visible_width);
        const float maximum_x = work_max.x - (std::min)(visible_width, clamped_size.x);
        const float minimum_y = work_min.y;
        const float maximum_y = work_max.y - (std::min)(visible_height, clamped_size.y);
        const ImVec2 clamped(
            std::clamp(window->Pos.x, minimum_x, (std::max)(minimum_x, maximum_x)),
            std::clamp(window->Pos.y, minimum_y, (std::max)(minimum_y, maximum_y)));
        if (clamped.x != window->Pos.x || clamped.y != window->Pos.y)
            ImGui::SetWindowPos(window, clamped, ImGuiCond_Always);
    }
    bool settings_changed = false;
    const auto clamp_short = [](float value) noexcept {
        return static_cast<short>((std::clamp)(std::lround(value), -32768L, 32767L));
    };
    for (ImGuiWindowSettings* settings = context->SettingsWindows.begin(); settings;
         settings = context->SettingsWindows.next_chunk(settings)) {
        const std::string_view saved_name(settings->GetName());
        const std::size_t hidden_separator = saved_name.find("###");
        const std::string_view saved_identity = hidden_separator == std::string_view::npos
            ? saved_name : saved_name.substr(hidden_separator + 3U);
        if (settings->WantDelete || settings->IsChild || settings->DockId != 0 ||
            saved_identity.rfind("aida.", 0) != 0)
            continue;
        const ImVec2 previous_origin = settings->ViewportId != 0
            ? ImVec2(static_cast<float>(settings->ViewportPos.x),
                static_cast<float>(settings->ViewportPos.y))
            : viewport->Pos;
        const ImVec2 saved_size(
            (std::max)(1.0f, static_cast<float>(settings->Size.x)),
            (std::max)(1.0f, static_cast<float>(settings->Size.y)));
        const ImVec2 clamped_size(
            (std::min)(saved_size.x, maximum_size.x),
            (std::min)(saved_size.y, maximum_size.y));
        const ImVec2 absolute_position(
            previous_origin.x + static_cast<float>(settings->Pos.x),
            previous_origin.y + static_cast<float>(settings->Pos.y));
        const float minimum_x = work_min.x - (std::max)(0.0f, clamped_size.x - visible_width);
        const float maximum_x = work_max.x - (std::min)(visible_width, clamped_size.x);
        const float minimum_y = work_min.y;
        const float maximum_y = work_max.y - (std::min)(visible_height, clamped_size.y);
        const ImVec2 clamped_position(
            std::clamp(absolute_position.x, minimum_x, (std::max)(minimum_x, maximum_x)),
            std::clamp(absolute_position.y, minimum_y, (std::max)(minimum_y, maximum_y)));
        const ImVec2ih next_position(
            clamp_short(clamped_position.x - viewport->Pos.x),
            clamp_short(clamped_position.y - viewport->Pos.y));
        const ImVec2ih next_size(clamp_short(clamped_size.x), clamp_short(clamped_size.y));
        if (settings->ViewportId != 0 || settings->ViewportPos.x != 0 ||
            settings->ViewportPos.y != 0 || settings->Pos.x != next_position.x ||
            settings->Pos.y != next_position.y || settings->Size.x != next_size.x ||
            settings->Size.y != next_size.y) {
            settings->ViewportId = 0;
            settings->ViewportPos = ImVec2ih(0, 0);
            settings->Pos = next_position;
            settings->Size = next_size;
            settings->WantApply = true;
            settings_changed = true;
        }
    }
    if (settings_changed)
        ImGui::GetIO().WantSaveIniSettings = true;
}

std::filesystem::path user_layout_path(const state_t& current, std::string_view name)
{
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring encoded = L"u-";
    encoded.reserve(2U + name.size() * 2U + 12U);
    for (const char raw_byte : name) {
        const auto byte = static_cast<unsigned char>(raw_byte);
        encoded.push_back(digits[byte >> 4U]);
        encoded.push_back(digits[byte & 0x0FU]);
    }
    return current.directory / L"user" / (encoded + L".aida-layout");
}

bool decode_user_layout_filename(const std::filesystem::path& path,
    std::string& name) noexcept
{
    try {
        constexpr std::wstring_view suffix = L".aida-layout";
        const std::wstring filename = path.filename().wstring();
        if (filename.size() <= 2U + suffix.size() || filename.compare(
                filename.size() - suffix.size(), suffix.size(), suffix) != 0 ||
            filename[0] != L'u' || filename[1] != L'-')
            return false;
        const std::wstring_view encoded(filename.data() + 2U,
            filename.size() - 2U - suffix.size());
        if (encoded.empty() || encoded.size() % 2U != 0)
            return false;
        auto nibble = [](wchar_t value) noexcept -> int {
            if (value >= L'0' && value <= L'9') return value - L'0';
            if (value >= L'a' && value <= L'f') return value - L'a' + 10;
            return -1;
        };
        std::string decoded;
        decoded.reserve(encoded.size() / 2U);
        for (std::size_t index = 0; index < encoded.size(); index += 2U) {
            const int high = nibble(encoded[index]);
            const int low = nibble(encoded[index + 1U]);
            if (high < 0 || low < 0)
                return false;
            decoded.push_back(static_cast<char>((high << 4) | low));
        }
        if (!valid_user_layout_name(decoded))
            return false;
        name = std::move(decoded);
        return true;
    } catch (...) {
        return false;
    }
}

bool managed_user_layout_artifact(const std::filesystem::path& path) noexcept
{
    try {
        std::filesystem::path primary = path;
        const std::wstring filename = primary.filename().wstring();
        if (filename.size() > 4U && filename.compare(filename.size() - 4U, 4U, L".bak") == 0)
            primary.replace_filename(filename.substr(0, filename.size() - 4U));
        else if (filename.size() > 8U && filename.compare(filename.size() - 8U, 8U, L".invalid") == 0)
            primary.replace_filename(filename.substr(0, filename.size() - 8U));
        std::string name;
        return decode_user_layout_filename(primary, name);
    } catch (...) {
        return false;
    }
}

bool remove_file_exact(const std::filesystem::path& path) noexcept
{
    if (DeleteFileW(path.c_str()))
        return true;
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

layout_paths_t preset_paths(const state_t& current, workspace_preset_t preset)
{
    const std::string_view id = descriptor_for(preset).stable_id;
    const std::wstring wide_id(id.begin(), id.end());
    layout_paths_t paths;
    paths.directory = current.directory;
    paths.primary = current.directory / (wide_id + L".aida-layout");
    paths.backup = current.directory / (wide_id + L".aida-layout.bak");
    paths.invalid = current.directory / (wide_id + L".aida-layout.invalid");
    return paths;
}

layout_paths_t named_user_paths(const state_t& current, std::string_view name)
{
    layout_paths_t paths;
    paths.directory = current.directory / L"user";
    paths.primary = user_layout_path(current, name);
    paths.backup = paths.primary;
    paths.backup += L".bak";
    paths.invalid = paths.primary;
    paths.invalid += L".invalid";
    return paths;
}

std::shared_ptr<const std::vector<user_workspace_descriptor_t>> scan_user_catalog(
    const std::filesystem::path& directory, ImGuiID expected_root,
    std::string_view active_user) noexcept
{
    try {
        auto catalog = std::make_shared<std::vector<user_workspace_descriptor_t>>();
        std::error_code error;
        if (!std::filesystem::exists(directory, error))
            return error ? nullptr : catalog;
        std::filesystem::directory_iterator cursor(directory, error);
        const std::filesystem::directory_iterator end;
        while (!error && cursor != end) {
            if (catalog->size() >= kMaximumNamedUserLayouts)
                return nullptr;
            if (cursor->is_regular_file(error)) {
                std::string name;
                if (decode_user_layout_filename(cursor->path(), name)) {
                    record_metadata_t metadata;
                    if (inspect_layout_file(cursor->path(), expected_root, metadata))
                        catalog->push_back({name, metadata.preset, metadata.generation,
                            name == active_user});
                }
            }
            if (error)
                return nullptr;
            cursor.increment(error);
        }
        if (error)
            return nullptr;
        std::sort(catalog->begin(), catalog->end(), [](const auto& left, const auto& right) {
            return left.name < right.name;
        });
        return catalog;
    } catch (...) {
        return nullptr;
    }
}

std::shared_ptr<const std::string> capture_current_payload(state_t& current) noexcept
{
    std::size_t payload_size = 0;
    const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
    if (!payload || payload_size == 0 || payload_size > kMaximumPayloadBytes)
        return {};
    try {
        current.nodes = resolved_nodes(current);
        return std::make_shared<const std::string>(payload, payload_size);
    } catch (...) {
        return {};
    }
}

read_result_t read_layout_with_backup(const layout_paths_t& paths, ImGuiID expected_root,
    record_metadata_t& metadata, std::string& payload) noexcept
{
    read_result_t result = read_layout_payload(paths.primary, expected_root, metadata, payload);
    if (result == read_result_t::valid)
        return result;
    if (result == read_result_t::invalid &&
        !MoveFileExW(paths.primary.c_str(), paths.invalid.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return read_result_t::io_failure;
    record_metadata_t backup_metadata;
    std::string backup_payload;
    const read_result_t backup = read_layout_payload(paths.backup, expected_root,
        backup_metadata, backup_payload);
    if (backup == read_result_t::valid) {
        metadata = backup_metadata;
        payload = std::move(backup_payload);
        return read_result_t::valid;
    }
    return result == read_result_t::io_failure || backup == read_result_t::io_failure
        ? read_result_t::io_failure
        : result == read_result_t::invalid || backup == read_result_t::invalid
            ? read_result_t::invalid : read_result_t::absent;
}

void execute_operation(const operation_request_t& request, operation_result_t& result) noexcept
{
    result.kind = request.kind;
    result.serial = request.serial;
    result.source_generation = request.source_generation;
    result.catalog_epoch = request.catalog_epoch;
    result.target_preset = request.target_preset;
    result.target_locked = request.target_locked;
    result.source_user_name = request.source_user_name;
    result.target_user_name = request.target_user_name;
    result.task_id = request.task_id;
    const auto fail = [&result](std::string message) {
        result.success = false;
        result.error = std::move(message);
    };
    try {
        std::lock_guard<std::recursive_mutex> transaction_lock(write_mutex());
        if (request.kind == operation_kind_t::set_lock ||
            request.kind == operation_kind_t::switch_preset ||
            request.kind == operation_kind_t::save_user ||
            request.kind == operation_kind_t::load_user) {
            if (!request.current_payload) {
                fail("The immutable current layout snapshot is unavailable.");
                return;
            }
            const workspace_preset_t saved_preset = request.current_preset;
            if (!write_generation(request.current_paths, request.expected_root, *request.current_payload,
                    request.save_generation, false, request.skip_backup, request.nodes,
                    saved_preset, request.target_locked, request.environment,
                    request.registry_fingerprint)) {
                fail("The current layout could not be written atomically.");
                return;
            }
            result.saved_generation = request.save_generation;
            if (request.kind == operation_kind_t::save_user) {
                const DWORD attributes = GetFileAttributesW(request.target_paths.primary.c_str());
                if (!request.overwrite && attributes != INVALID_FILE_ATTRIBUTES) {
                    fail("A named user workspace with this exact name already exists.");
                    return;
                }
                const std::uint64_t named_generation = request.save_generation + 1ULL;
                if (!write_generation(request.target_paths, request.expected_root,
                        *request.current_payload, named_generation, false, false,
                        request.nodes, saved_preset, request.target_locked,
                        request.environment, request.registry_fingerprint)) {
                    fail("The named user layout could not be written atomically.");
                    return;
                }
                result.saved_generation = named_generation;
                result.active_user_name = request.target_user_name;
                if (!save_active_workspace_record_values(request.workspace_directory,
                        request.active_record, saved_preset, request.target_locked,
                        request.target_user_name)) {
                    fail("The active named workspace record could not be replaced atomically.");
                    return;
                }
            }
        }

        if (request.kind == operation_kind_t::switch_preset ||
            request.kind == operation_kind_t::load_user) {
            const read_result_t loaded = read_layout_with_backup(request.target_paths,
                request.expected_root, result.metadata, result.payload);
            if (request.kind == operation_kind_t::load_user &&
                loaded == read_result_t::valid && request.expected_user_generation != 0 &&
                result.metadata.generation != request.expected_user_generation) {
                fail("The named user workspace changed after it was selected.");
                return;
            }
            if (loaded == read_result_t::valid &&
                request.kind == operation_kind_t::switch_preset &&
                result.metadata.preset != request.target_preset) {
                fail("The saved layout belongs to a different workspace preset.");
                return;
            }
            if (loaded != read_result_t::valid) {
                if (request.kind == operation_kind_t::load_user) {
                    fail(loaded == read_result_t::absent
                        ? "The named user layout does not exist."
                        : "The named user layout is invalid or unreadable.");
                    return;
                }
                result.use_default = true;
                result.payload.clear();
                result.metadata = {};
                result.metadata.preset = request.target_preset;
                result.metadata.locked = false;
            } else {
                result.target_preset = result.metadata.preset;
                result.target_locked = result.metadata.locked;
            }
            if (!save_active_workspace_record_values(request.workspace_directory,
                    request.active_record, result.target_preset, result.target_locked,
                    request.kind == operation_kind_t::load_user
                        ? std::string_view(request.target_user_name) : std::string_view{})) {
                fail("The active workspace record could not be replaced atomically.");
                return;
            }
            result.active_user_name = request.kind == operation_kind_t::load_user
                ? request.target_user_name : std::string{};
        } else if (request.kind == operation_kind_t::set_lock) {
            if (!save_active_workspace_record_values(request.workspace_directory,
                    request.active_record, request.current_preset, request.target_locked,
                    request.current_user_name)) {
                fail("The active workspace lock record could not be replaced atomically.");
                return;
            }
            result.active_user_name = request.current_user_name;
        } else if (request.kind == operation_kind_t::rename_user) {
            if (GetFileAttributesW(request.source_user_paths.primary.c_str()) == INVALID_FILE_ATTRIBUTES) {
                fail("The named user workspace no longer exists.");
                return;
            }
            if (GetFileAttributesW(request.target_paths.primary.c_str()) != INVALID_FILE_ATTRIBUTES) {
                fail("A named user workspace with the new exact name already exists.");
                return;
            }
            record_metadata_t source_metadata;
            if (!inspect_layout_file(request.source_user_paths.primary,
                    request.expected_root, source_metadata) ||
                source_metadata.generation != request.expected_user_generation) {
                fail("The named user workspace changed after it was selected.");
                return;
            }
            if (!MoveFileExW(request.source_user_paths.primary.c_str(),
                    request.target_paths.primary.c_str(), MOVEFILE_WRITE_THROUGH)) {
                fail("The named user workspace could not be renamed atomically.");
                return;
            }
            const auto move_optional = [](const std::filesystem::path& source,
                const std::filesystem::path& target, bool& moved) noexcept {
                moved = false;
                if (GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    const DWORD error = GetLastError();
                    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
                }
                moved = MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
                return moved;
            };
            bool backup_moved = false;
            bool invalid_moved = false;
            if (!move_optional(request.source_user_paths.backup, request.target_paths.backup,
                    backup_moved) ||
                !move_optional(request.source_user_paths.invalid, request.target_paths.invalid,
                    invalid_moved)) {
                if (invalid_moved)
                    static_cast<void>(MoveFileExW(request.target_paths.invalid.c_str(),
                        request.source_user_paths.invalid.c_str(), MOVEFILE_WRITE_THROUGH));
                if (backup_moved)
                    static_cast<void>(MoveFileExW(request.target_paths.backup.c_str(),
                        request.source_user_paths.backup.c_str(), MOVEFILE_WRITE_THROUGH));
                static_cast<void>(MoveFileExW(request.target_paths.primary.c_str(),
                    request.source_user_paths.primary.c_str(), MOVEFILE_WRITE_THROUGH));
                fail("The named user workspace companion files could not be renamed exactly.");
                return;
            }
            result.active_user_name = request.current_user_name == request.source_user_name
                ? request.target_user_name : request.current_user_name;
            if (!save_active_workspace_record_values(request.workspace_directory,
                    request.active_record, request.current_preset, request.target_locked,
                    result.active_user_name)) {
                static_cast<void>(MoveFileExW(request.target_paths.primary.c_str(),
                    request.source_user_paths.primary.c_str(), MOVEFILE_WRITE_THROUGH));
                if (invalid_moved)
                    static_cast<void>(MoveFileExW(request.target_paths.invalid.c_str(),
                        request.source_user_paths.invalid.c_str(), MOVEFILE_WRITE_THROUGH));
                if (backup_moved)
                    static_cast<void>(MoveFileExW(request.target_paths.backup.c_str(),
                        request.source_user_paths.backup.c_str(), MOVEFILE_WRITE_THROUGH));
                fail("The active workspace record could not follow the rename.");
                return;
            }
        } else if (request.kind == operation_kind_t::delete_user) {
            record_metadata_t target_metadata;
            if (!inspect_layout_file(request.target_paths.primary,
                    request.expected_root, target_metadata) ||
                target_metadata.generation != request.expected_user_generation) {
                fail("The named user workspace changed after it was selected.");
                return;
            }
            const bool deleting_active = request.current_user_name == request.target_user_name;
            result.active_user_name = deleting_active ? std::string{} : request.current_user_name;
            if (deleting_active) {
                const read_result_t fallback = read_layout_with_backup(request.fallback_paths,
                    request.expected_root, result.metadata, result.payload);
                if (fallback == read_result_t::io_failure) {
                    fail("The built-in fallback workspace could not be read safely.");
                    return;
                }
                if (fallback == read_result_t::valid &&
                    result.metadata.preset != request.target_preset) {
                    fail("The built-in fallback belongs to a different workspace preset.");
                    return;
                }
                result.apply_layout = true;
                result.target_preset = request.target_preset;
                result.use_default = fallback != read_result_t::valid;
                result.target_locked = fallback == read_result_t::valid
                    ? result.metadata.locked : false;
                if (result.use_default) {
                    result.payload.clear();
                    result.metadata = {};
                    result.metadata.preset = request.target_preset;
                    result.metadata.locked = false;
                }
            }
            if (!save_active_workspace_record_values(request.workspace_directory,
                    request.active_record, deleting_active ? request.target_preset : request.current_preset,
                    deleting_active ? result.target_locked : request.target_locked,
                    result.active_user_name)) {
                fail("The active workspace record could not be prepared for deletion.");
                return;
            }
            if (!remove_file_exact(request.target_paths.primary) ||
                !remove_file_exact(request.target_paths.backup) ||
                !remove_file_exact(request.target_paths.invalid)) {
                static_cast<void>(save_active_workspace_record_values(request.workspace_directory,
                    request.active_record, request.current_preset, request.target_locked,
                    request.current_user_name));
                fail("The named user workspace could not be removed exactly.");
                return;
            }
        } else if (request.kind == operation_kind_t::restore_preset ||
                   request.kind == operation_kind_t::reset_all) {
            std::vector<std::filesystem::path> user_files;
            if (request.kind == operation_kind_t::reset_all) {
                std::error_code error;
                if (std::filesystem::exists(request.user_directory, error)) {
                    std::filesystem::directory_iterator cursor(request.user_directory, error);
                    const std::filesystem::directory_iterator end;
                    while (!error && cursor != end) {
                        const bool regular = cursor->is_regular_file(error);
                        if (error || !regular) {
                            fail("The named user workspace set is invalid or exceeds its exact bound.");
                            return;
                        }
                        if (managed_user_layout_artifact(cursor->path())) {
                            if (user_files.size() >= kMaximumNamedUserLayouts * 3U) {
                                fail("The named user workspace set exceeds its exact bound.");
                                return;
                            }
                            user_files.push_back(cursor->path());
                        }
                        cursor.increment(error);
                    }
                }
                if (error) {
                    fail("The user workspace directory could not be enumerated exactly.");
                    return;
                }
            }
            for (const auto& paths : request.reset_paths) {
                if (!remove_file_exact(paths.primary) || !remove_file_exact(paths.backup) ||
                    !remove_file_exact(paths.invalid)) {
                    fail("A saved workspace layout could not be removed exactly.");
                    return;
                }
            }
            if (request.kind == operation_kind_t::reset_all) {
                for (const auto& path : user_files) {
                    if (!remove_file_exact(path)) {
                        fail("A saved user workspace could not be removed exactly.");
                        return;
                    }
                }
            }
            if (!save_active_workspace_record_values(request.workspace_directory,
                    request.active_record, request.target_preset, false)) {
                fail("The reset workspace record could not be replaced atomically.");
                return;
            }
            result.use_default = true;
            result.target_locked = false;
            result.active_user_name.clear();
        }
        result.catalog = scan_user_catalog(request.workspace_directory / L"user",
            request.expected_root, result.active_user_name);
        if (!result.catalog) {
            fail("The named user workspace catalog could not be refreshed exactly.");
            return;
        }
        result.success = true;
    } catch (const std::exception& exception) {
        fail(exception.what());
    } catch (...) {
        fail("The workspace operation failed with an unknown error.");
    }
}

workspace_request_result_t submit_operation(operation_request_t request) noexcept
{
    try {
        request.registry_fingerprint = state().registry_fingerprint;
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    if (!valid_registry_fingerprint(request.registry_fingerprint))
        return workspace_request_result_t::failed;
    operation_runtime_t& runtime = operation_runtime();
    bool expected = false;
    if (!runtime.pending.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel))
        return workspace_request_result_t::busy;
    if (request.catalog_epoch == 0)
        request.catalog_epoch = catalog_epoch().fetch_add(1, std::memory_order_acq_rel) + 1ULL;
    request.serial = runtime.serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    request.task_id = "workspace.layout." + std::to_string(request.serial);
    auto immutable_request = std::make_shared<const operation_request_t>(std::move(request));
    {
        std::lock_guard<std::mutex> lock(runtime.result_mutex);
        runtime.active_request = immutable_request;
    }
    aida::ui::task_center::task_registration_t registration;
    registration.id = immutable_request->task_id;
    registration.source = "workspace_layout";
    registration.owner = "Workspace Layout";
    registration.owner_view = "view.background_tasks";
    registration.owner_action = "Apply workspace transaction";
    registration.target = std::string(descriptor_for(immutable_request->target_preset).display_name);
    registration.label = "Workspace layout transaction";
    registration.stage = "Queued serialized persistence phase";
    registration.affected_entity = std::string(descriptor_for(
        immutable_request->target_preset).stable_id);
    registration.callbacks.retry = [serial = immutable_request->serial] {
        operation_runtime_t& current = operation_runtime();
        std::lock_guard<std::mutex> lock(current.result_mutex);
        if (!current.last_failed_request || current.last_failed_request->serial != serial ||
            current.pending.load(std::memory_order_acquire))
            return false;
        current.retry_requested.store(serial, std::memory_order_release);
        return true;
    };
    if (!aida::ui::task_center::register_task(std::move(registration))) {
        runtime.pending.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(runtime.result_mutex);
            runtime.active_request.reset();
        }
        state().operation_error = "Task Center rejected the workspace transaction.";
        state().operation_status = state().operation_error;
        return workspace_request_result_t::failed;
    }
    state().operation_error.clear();
    state().operation_status = "Workspace transaction queued";
    auto result = std::make_shared<operation_result_t>();
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "workspace_layout";
    submission.label = "workspace_layout.transaction";
    submission.thread_class = "diagnostics_io";
    submission.domain = aida::infra::executor::domain_t::diagnostics;
    submission.priority = 2;
    submission.generation = immutable_request->serial;
    submission.ui_access_policy = "none";
    submission.failure_policy = "retain_last_known_good";
    submission.shutdown_policy = "drain";
    submission.body = [immutable_request, result] {
        static_cast<void>(aida::ui::task_center::update_task(immutable_request->task_id,
            aida::ui::task_center::task_state_t::running, 0.1f,
            "Executing atomic persistence phase"));
        execute_operation(*immutable_request, *result);
        if (result->success) {
            static_cast<void>(aida::ui::task_center::update_task(result->task_id,
                aida::ui::task_center::task_state_t::running, 0.9f,
                "Persistence complete; awaiting UI layout application"));
        } else {
            static_cast<void>(aida::ui::task_center::update_task(result->task_id,
                aida::ui::task_center::task_state_t::failed, 1.0f,
                "Workspace transaction failed", result->error));
        }
        operation_runtime_t& current = operation_runtime();
        {
            std::lock_guard<std::mutex> lock(current.result_mutex);
            current.result = result;
            if (!result->success)
                current.last_failed_request = immutable_request;
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        runtime.pending.store(false, std::memory_order_release);
        state().operation_error = "Workspace executor rejected the transaction: " +
            submitted.reject_reason;
        state().operation_status = state().operation_error;
        {
            std::lock_guard<std::mutex> lock(runtime.result_mutex);
            runtime.last_failed_request = immutable_request;
            runtime.active_request.reset();
        }
        static_cast<void>(aida::ui::task_center::update_task(immutable_request->task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Workspace executor rejected the transaction", submitted.reject_reason));
        return workspace_request_result_t::failed;
    }
    return workspace_request_result_t::queued;
}

void process_operation_completion() noexcept
{
    operation_runtime_t& runtime = operation_runtime();
    std::shared_ptr<operation_result_t> result;
    {
        std::lock_guard<std::mutex> lock(runtime.result_mutex);
        result = std::move(runtime.result);
    }
    if (!result)
        return;
    state_t& current = state();
    if (result->serial != runtime.serial.load(std::memory_order_acquire) ||
        current.expected_root == 0) {
        runtime.pending.store(false, std::memory_order_release);
        static_cast<void>(aida::ui::task_center::update_task(result->task_id,
            aida::ui::task_center::task_state_t::cancelled, 1.0f,
            "Discarded stale workspace transaction", "Root or operation serial changed"));
        {
            std::lock_guard<std::mutex> lock(runtime.result_mutex);
            runtime.active_request.reset();
        }
        return;
    }
    if (!result->success) {
        current.operation_error = result->error;
        current.operation_status = result->error;
        runtime.pending.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(runtime.result_mutex);
            runtime.active_request.reset();
        }
        return;
    }
    if (current.generation != result->source_generation) {
        current.operation_error = "The workspace changed after this transaction was captured; run the action again from the current layout.";
        current.operation_status = current.operation_error;
        runtime.pending.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(runtime.result_mutex);
            runtime.active_request.reset();
        }
        static_cast<void>(aida::ui::task_center::update_task(result->task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Workspace generation changed before UI application", current.operation_error));
        return;
    }
    const std::string previous_identity = identity_key(current.active, current.active_user);
    if (result->catalog)
        publish_catalog(result->catalog, result->catalog_epoch);
    if (result->kind == operation_kind_t::delete_user)
        application_views::remove_persisted_workspace_visibility(
            identity_key(result->target_preset, result->target_user_name));
    if (result->kind == operation_kind_t::set_lock) {
        current.locked = result->target_locked;
        current.generation = (std::max)(current.generation, result->saved_generation);
        apply_lock_recursive(ImGui::DockBuilderGetNode(current.expected_root), current.locked);
    } else if (result->kind == operation_kind_t::save_user) {
        current.generation = (std::max)(current.generation, result->saved_generation);
        current.active_user = result->active_user_name;
        application_views::clone_persisted_workspace_visibility(previous_identity,
            identity_key(current.active, current.active_user));
    } else if (result->kind == operation_kind_t::rename_user) {
        application_views::rename_persisted_workspace_visibility(
            identity_key(result->target_preset, result->source_user_name),
            identity_key(result->target_preset, result->target_user_name));
        current.active_user = result->active_user_name;
    } else if (result->kind == operation_kind_t::delete_user && !result->apply_layout) {
        current.active_user = result->active_user_name;
    } else {
        if (!select_preset_paths(current, result->target_preset)) {
            current.operation_error = "The applied workspace paths could not be represented safely.";
            current.operation_status = current.operation_error;
            runtime.pending.store(false, std::memory_order_release);
            {
                std::lock_guard<std::mutex> lock(runtime.result_mutex);
                runtime.last_failed_request = runtime.active_request;
                runtime.active_request.reset();
            }
            static_cast<void>(aida::ui::task_center::update_task(result->task_id,
                aida::ui::task_center::task_state_t::failed, 1.0f,
                "Workspace UI application failed", current.operation_error));
            return;
        }
        ImGui::DockBuilderRemoveNode(current.expected_root);
        current.active = result->target_preset;
        current.pending = result->target_preset;
        current.active_user = result->active_user_name;
        current.locked = result->target_locked;
        current.generation = (std::max)(current.generation,
            (std::max)(result->saved_generation, result->metadata.generation));
        current.nodes = result->use_default
            ? dock_nodes_t{current.expected_root, 0, 0, 0, 0}
            : result->metadata.nodes;
        if (!result->use_default && !result->payload.empty()) {
            ImGui::LoadIniSettingsFromMemory(result->payload.data(), result->payload.size());
            application_views::migrate_persisted_window_settings();
        }
        current.needs_default = result->use_default;
        current.rebuild_requested = result->use_default;
        current.root_prepared = false;
        current.transition_frames = 1;
        current.recovered_from_backup = false;
        current.preserve_recovery_backup = false;
        if (result->kind == operation_kind_t::restore_preset)
            application_views::reset_persisted_workspace_visibility(
                result->target_preset, false);
        else if (result->kind == operation_kind_t::reset_all)
            application_views::reset_persisted_workspace_visibility(
                result->target_preset, true);
    }
    current.operation_error.clear();
    current.operation_status = "Workspace transaction completed";
    ImGui::GetIO().WantSaveIniSettings = true;
    runtime.pending.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(runtime.result_mutex);
        runtime.active_request.reset();
        runtime.last_failed_request.reset();
    }
    static_cast<void>(aida::ui::task_center::update_task(result->task_id,
        aida::ui::task_center::task_state_t::completed, 1.0f,
        "Workspace transaction applied", std::string(descriptor_for(
            result->target_preset).display_name)));
}

void process_operation_retry() noexcept
{
    operation_runtime_t& runtime = operation_runtime();
    const std::uint64_t retry_serial = runtime.retry_requested.exchange(0,
        std::memory_order_acq_rel);
    if (retry_serial == 0 || runtime.pending.load(std::memory_order_acquire))
        return;
    std::shared_ptr<const operation_request_t> failed;
    {
        std::lock_guard<std::mutex> lock(runtime.result_mutex);
        if (runtime.last_failed_request && runtime.last_failed_request->serial == retry_serial)
            failed = runtime.last_failed_request;
    }
    if (!failed)
        return;
    operation_request_t retry = *failed;
    retry.serial = 0;
    retry.catalog_epoch = 0;
    retry.task_id.clear();
    static_cast<void>(submit_operation(std::move(retry)));
}

}

bool initialize(ImGuiID root_dockspace_id) noexcept
{
    state_t& current = state();
    if (current.initialized)
        return true;
    current.expected_root = root_dockspace_id;
    current.nodes.root = root_dockspace_id;
    current.needs_default = true;
    current.root_prepared = false;
    try {
        current.registry_fingerprint = application_views::persistence_fingerprint();
    } catch (...) {
        current.registry_fingerprint.clear();
    }
    if (!valid_registry_fingerprint(current.registry_fingerprint)) {
        diag::log_tagged_critical("workspace_layout", "view_registry_fingerprint_unavailable");
        current.initialized = true;
        return false;
    }
    if (!assign_paths(current)) {
        diag::log_tagged_critical("workspace_layout", "persistence_path_unavailable");
        current.initialized = true;
        return false;
    }
    load_active_workspace_record(current);
    current.persistence_available = true;

    bool active_named_loaded = false;
    if (!current.active_user.empty()) {
        try {
            record_metadata_t named_metadata;
            std::string named_payload;
            const auto named_paths = named_user_paths(current, current.active_user);
            if (read_layout_with_backup(named_paths, root_dockspace_id,
                    named_metadata, named_payload) == read_result_t::valid &&
                named_metadata.preset == current.active) {
                ImGui::LoadIniSettingsFromMemory(named_payload.data(), named_payload.size());
                application_views::migrate_persisted_window_settings();
                current.active = named_metadata.preset;
                current.pending = named_metadata.preset;
                current.needs_default = false;
                current.generation = named_metadata.generation;
                current.nodes = named_metadata.nodes;
                current.locked = named_metadata.locked;
                current.environment = named_metadata.environment;
                current.recovered_from_backup = false;
                current.preserve_recovery_backup = false;
                committed_generation().store(current.generation, std::memory_order_release);
                ImGui::GetIO().WantSaveIniSettings = true;
                active_named_loaded = true;
                diag::log_tagged_fmt("workspace_layout",
                    "layout_loaded source=named schema=%u preset_revision=%u generation=%llu saved_unix_ms=%llu registry_match=%d monitor=%lld,%lld,%llux%llu dpi_milli=%u",
                    kSchemaVersion, named_metadata.preset_revision,
                    static_cast<unsigned long long>(current.generation),
                    static_cast<unsigned long long>(named_metadata.saved_unix_ms),
                    registry_fingerprint_matches(named_metadata) ? 1 : 0,
                    static_cast<long long>(named_metadata.environment.work_x),
                    static_cast<long long>(named_metadata.environment.work_y),
                    static_cast<unsigned long long>(named_metadata.environment.work_width),
                    static_cast<unsigned long long>(named_metadata.environment.work_height),
                    named_metadata.environment.dpi_milli);
            } else {
                current.active_user.clear();
                if (!save_active_workspace_record_values(current.directory,
                        current.active_record, current.active, current.locked))
                    current.persistence_available = false;
            }
        } catch (...) {
            current.active_user.clear();
            if (!save_active_workspace_record_values(current.directory,
                    current.active_record, current.active, current.locked))
                current.persistence_available = false;
        }
    }
    if (!active_named_loaded) {
    record_metadata_t loaded_metadata;
    read_result_t primary_result = load_layout_file(current.primary, root_dockspace_id, loaded_metadata);
    bool migrated_legacy = false;
    if (primary_result == read_result_t::absent && current.active == workspace_preset_t::analysis) {
        primary_result = load_layout_file(current.legacy_primary, root_dockspace_id, loaded_metadata);
        migrated_legacy = primary_result == read_result_t::valid;
    }
    if (primary_result == read_result_t::valid && loaded_metadata.preset != current.active)
        primary_result = read_result_t::invalid;
    if (primary_result == read_result_t::valid) {
        current.active = loaded_metadata.preset;
        current.pending = loaded_metadata.preset;
        current.needs_default = false;
        current.generation = loaded_metadata.generation;
        current.nodes = loaded_metadata.nodes;
        current.locked = loaded_metadata.locked;
        current.environment = loaded_metadata.environment;
        committed_generation().store(current.generation, std::memory_order_release);
        if (!loaded_metadata.clean_shutdown) {
            record_metadata_t recovery_metadata;
            const bool recovery_available = inspect_layout_file(
                current.backup, root_dockspace_id, recovery_metadata);
            current.preserve_recovery_backup = recovery_available;
            diag::log_tagged_critical_fmt("workspace_layout",
                "layout_unclean_start policy=use_valid_primary_preserve_last_good recovery_available=%d recovery_generation=%llu recovery_clean=%d",
                recovery_available ? 1 : 0,
                static_cast<unsigned long long>(recovery_metadata.generation),
                recovery_available && recovery_metadata.clean_shutdown ? 1 : 0);
        }
        ImGui::GetIO().WantSaveIniSettings = true;
        diag::log_tagged_fmt("workspace_layout",
            "layout_loaded source=%s schema=%u preset_revision=%u generation=%llu clean_shutdown=%d saved_unix_ms=%llu registry_match=%d",
            migrated_legacy ? "legacy" : "primary",
            kSchemaVersion, loaded_metadata.preset_revision,
            static_cast<unsigned long long>(current.generation), loaded_metadata.clean_shutdown ? 1 : 0,
            static_cast<unsigned long long>(loaded_metadata.saved_unix_ms),
            registry_fingerprint_matches(loaded_metadata) ? 1 : 0);
    } else {
        if (primary_result == read_result_t::invalid)
            MoveFileExW(current.primary.c_str(), current.invalid.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        record_metadata_t backup_metadata;
        read_result_t backup_result = load_layout_file(current.backup, root_dockspace_id, backup_metadata);
        if (backup_result == read_result_t::valid && backup_metadata.preset != current.active)
            backup_result = read_result_t::invalid;
        if (backup_result == read_result_t::valid) {
            current.active = backup_metadata.preset;
            current.pending = backup_metadata.preset;
            current.needs_default = false;
            current.recovered_from_backup = true;
            current.generation = backup_metadata.generation;
            current.nodes = backup_metadata.nodes;
            current.locked = backup_metadata.locked;
            current.environment = backup_metadata.environment;
            committed_generation().store(current.generation, std::memory_order_release);
            ImGui::GetIO().WantSaveIniSettings = true;
            diag::log_tagged_critical_fmt("workspace_layout",
                "layout_recovered source=backup schema=%u generation=%llu clean_shutdown=%d",
                kSchemaVersion,
                static_cast<unsigned long long>(current.generation), backup_metadata.clean_shutdown ? 1 : 0);
        } else if (primary_result != read_result_t::absent || backup_result != read_result_t::absent) {
            current.active = workspace_preset_t::safe;
            current.pending = workspace_preset_t::safe;
            if (!select_preset_paths(current, current.active))
                current.persistence_available = false;
            diag::log_tagged_critical_fmt("workspace_layout",
                "layout_recovery_safe primary_result=%u backup_result=%u",
                static_cast<unsigned>(primary_result), static_cast<unsigned>(backup_result));
        } else {
            diag::log_tagged_fmt("workspace_layout", "layout_first_run_default schema=%u", kSchemaVersion);
        }
    }
    }
    aida::infra::executor::submission_t catalog_submission;
    catalog_submission.owner_subsystem = "workspace_layout";
    catalog_submission.label = "workspace_layout.catalog_refresh";
    catalog_submission.thread_class = "diagnostics_io";
    catalog_submission.domain = aida::infra::executor::domain_t::diagnostics;
    catalog_submission.priority = 1;
    catalog_submission.generation = current.generation;
    catalog_submission.ui_access_policy = "none";
    catalog_submission.failure_policy = "retain_last_known_good";
    catalog_submission.shutdown_policy = "drain";
    const std::filesystem::path user_directory = current.directory / L"user";
    const std::string active_user = current.active_user;
    const std::uint64_t refresh_epoch = catalog_epoch().fetch_add(
        1, std::memory_order_acq_rel) + 1ULL;
    catalog_submission.body = [user_directory, root_dockspace_id, active_user,
        refresh_epoch] {
        if (const auto catalog = scan_user_catalog(user_directory,
                root_dockspace_id, active_user))
            publish_catalog(catalog, refresh_epoch);
    };
    static_cast<void>(aida::infra::executor::submit(std::move(catalog_submission)));
    current.initialized = true;
    return true;
}

void prepare_root(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size) noexcept
{
    state_t& current = state();
    if (!current.initialized || current.expected_root != root_dockspace_id)
        return;
    process_operation_completion();
    process_operation_retry();
    current.last_position = position;
    current.last_size = ImVec2((std::max)(size.x, 320.0f), (std::max)(size.y, 240.0f));
    if (!current.root_prepared) {
        if (current.needs_default || ImGui::DockBuilderGetNode(root_dockspace_id) == nullptr) {
            const bool recovery = !current.needs_default;
            build_default_layout(root_dockspace_id, position, size, current.pending);
            current.active = current.pending;
            current.rebuild_requested = false;
            current.needs_default = false;
            diag::log_tagged_fmt("workspace_layout",
                "layout_builder_applied_once root=0x%08X reason=%s work_size=%.0fx%.0f",
                root_dockspace_id, recovery ? "missing_loaded_root" : "first_run_or_recovery",
                size.x, size.y);
        }
        current.root_prepared = true;
    }
    apply_lock_recursive(ImGui::DockBuilderGetNode(root_dockspace_id), current.locked ||
        operation_runtime().pending.load(std::memory_order_acquire));
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (viewport) {
        const float dpi_scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
        current.environment.work_x = static_cast<std::int64_t>(std::llround(viewport->WorkPos.x));
        current.environment.work_y = static_cast<std::int64_t>(std::llround(viewport->WorkPos.y));
        current.environment.work_width = static_cast<std::uint64_t>(
            (std::max)(1.0, std::round(static_cast<double>(viewport->WorkSize.x))));
        current.environment.work_height = static_cast<std::uint64_t>(
            (std::max)(1.0, std::round(static_cast<double>(viewport->WorkSize.y))));
        current.environment.dpi_milli = static_cast<std::uint32_t>((std::clamp)(
            std::llround(static_cast<double>(dpi_scale) * 1000.0), 250LL, 8000LL));
        const bool geometry_changed = !current.rehome_initialized ||
            current.rehome_work_position.x != viewport->WorkPos.x ||
            current.rehome_work_position.y != viewport->WorkPos.y ||
            current.rehome_work_size.x != viewport->WorkSize.x ||
            current.rehome_work_size.y != viewport->WorkSize.y ||
            current.rehome_dpi_scale != dpi_scale;
        if (geometry_changed) {
            current.rehome_work_position = viewport->WorkPos;
            current.rehome_work_size = viewport->WorkSize;
            current.rehome_dpi_scale = dpi_scale;
            current.rehome_initialized = true;
            rehome_floating_windows();
        }
    }
}

bool surfaces_ready() noexcept
{
    const state_t& current = state();
    return current.initialized && current.root_prepared;
}

void render_transition_surface() noexcept
{
    state_t& current = state();
    if (current.transition_frames == 0)
        return;
    draw_transition_surface(current.last_position, current.last_size, current.pending);
    --current.transition_frames;
}

void settle_default_selection() noexcept
{
    state_t& current = state();
    if (current.select_defaults_after_realize_frames == 0)
        return;
    --current.select_defaults_after_realize_frames;
    if (current.select_defaults_after_realize_frames != 0)
        return;
    const bool compact = current.nodes.root != 0 &&
        current.nodes.navigator == current.nodes.root &&
        current.nodes.documents == current.nodes.root &&
        current.nodes.inspector == current.nodes.root &&
        current.nodes.bottom == current.nodes.root;
    if (application_views::is_open(stable_view_id_t("view.start_center")))
        select_docked_window(current.nodes.documents, "view.start_center");
    else if (compact)
        select_docked_window(current.nodes.root, compact_primary_view(current.active));
    else
        select_builtin_default_tabs(current.active, current.nodes.navigator,
            current.nodes.documents, current.nodes.inspector, current.nodes.bottom);
}

ImGuiID node_id(dock_role_t role) noexcept
{
    const dock_nodes_t nodes = resolved_nodes(state());
    switch (role) {
    case dock_role_t::root: return nodes.root;
    case dock_role_t::navigator: return nodes.navigator;
    case dock_role_t::documents: return nodes.documents;
    case dock_role_t::inspector: return nodes.inspector;
    case dock_role_t::bottom: return nodes.bottom;
    default: return 0;
    }
}

window_placement_state_t inspect_window_placement(std::string_view window_name) noexcept
{
    window_placement_state_t result;
    if (window_name.empty() || ImGui::GetCurrentContext() == nullptr)
        return result;
    const std::string name(window_name);
    ImGuiWindow* window = ImGui::FindWindowByName(name.c_str());
    if (!window)
        return result;
    result.realized = true;
    result.dock_node = window->DockId;
    result.docked = window->DockId != 0;
    const dock_nodes_t nodes = resolved_nodes(state());
    if (window->DockId == nodes.navigator) result.role = dock_role_t::navigator;
    else if (window->DockId == nodes.documents) result.role = dock_role_t::documents;
    else if (window->DockId == nodes.inspector) result.role = dock_role_t::inspector;
    else if (window->DockId == nodes.bottom) result.role = dock_role_t::bottom;
    return result;
}

workspace_request_result_t float_window(std::string_view window_name) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || current.locked || window_name.empty())
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    const std::string name(window_name);
    ImGuiWindow* window = ImGui::FindWindowByName(name.c_str());
    if (!window)
        return workspace_request_result_t::unavailable;
    if (window->DockId == 0)
        return workspace_request_result_t::unchanged;
    ImGui::DockContextQueueUndockWindow(ImGui::GetCurrentContext(), window);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

workspace_request_result_t dock_window(std::string_view window_name, dock_role_t role) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || current.locked || window_name.empty() ||
        role == dock_role_t::root)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    const ImGuiID target = node_id(role);
    if (target == 0 || ImGui::DockBuilderGetNode(target) == nullptr)
        return workspace_request_result_t::unavailable;
    const window_placement_state_t placement = inspect_window_placement(window_name);
    if (placement.realized && placement.dock_node == target)
        return workspace_request_result_t::unchanged;
    const std::string name(window_name);
    ImGuiWindow* window = ImGui::FindWindowByName(name.c_str());
    if (window)
        ImGui::DockContextQueueDock(ImGui::GetCurrentContext(), nullptr,
            ImGui::DockBuilderGetNode(target), window, ImGuiDir_None, 0.0f, false);
    else
        ImGui::DockBuilderDockWindow(name.c_str(), target);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

workspace_request_result_t split_window(std::string_view window_name,
    std::string_view anchor_window_name, dock_split_direction_t direction) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || current.locked ||
        window_name.empty() || anchor_window_name.empty())
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    const std::string anchor_name(anchor_window_name);
    ImGuiWindow* anchor = ImGui::FindWindowByName(anchor_name.c_str());
    if (!anchor || anchor->DockId == 0 || !ImGui::DockBuilderGetNode(anchor->DockId))
        return workspace_request_result_t::unavailable;
    const ImGuiDir imgui_direction = direction == dock_split_direction_t::left
        ? ImGuiDir_Left : direction == dock_split_direction_t::right
        ? ImGuiDir_Right : direction == dock_split_direction_t::up
        ? ImGuiDir_Up : ImGuiDir_Down;
    const ImGuiID anchor_node = anchor->DockId;
    ImGuiID split_node = 0;
    ImGuiID retained_node = 0;
    ImGui::DockBuilderSplitNode(anchor_node, imgui_direction, 0.5f,
        &split_node, &retained_node);
    if (split_node == 0 || retained_node == 0)
        return workspace_request_result_t::failed;
    const std::string name(window_name);
    ImGui::DockBuilderDockWindow(name.c_str(), split_node);
    auto retain_role = [&](ImGuiID& node) {
        if (node == anchor_node) node = retained_node;
    };
    retain_role(current.nodes.navigator);
    retain_role(current.nodes.documents);
    retain_role(current.nodes.inspector);
    retain_role(current.nodes.bottom);
    ImGui::DockBuilderFinish(current.nodes.root);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

workspace_preset_t active_preset() noexcept { return state().active; }
std::string_view active_preset_name() noexcept { return descriptor_for(active_preset()).display_name; }
workspace_identity_t active_identity() noexcept
{
    try {
        const state_t& current = state();
        return {current.active_user.empty() ? workspace_identity_kind_t::built_in :
            workspace_identity_kind_t::user, current.active, current.active_user};
    } catch (...) {
        return {};
    }
}
std::string active_identity_key() noexcept
{
    try {
        const state_t& current = state();
        return identity_key(current.active, current.active_user);
    } catch (...) {
        return "builtin:analysis";
    }
}
std::shared_ptr<const std::vector<user_workspace_descriptor_t>> user_layout_catalog() noexcept
{
    const auto catalog = catalog_snapshot();
    return catalog ? catalog :
        std::make_shared<const std::vector<user_workspace_descriptor_t>>();
}
bool user_layout_catalog_ready() noexcept
{
    return catalog_ready().load(std::memory_order_acquire);
}
bool layout_locked() noexcept { return state().locked; }

workspace_request_result_t set_layout_locked(bool locked) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    if (current.locked == locked)
        return workspace_request_result_t::unchanged;
    operation_request_t request;
    request.kind = operation_kind_t::set_lock;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    request.current_user_name = current.active_user;
    request.target_preset = current.active;
    request.target_locked = locked;
    request.save_generation = (std::max)(current.generation,
        committed_generation().load(std::memory_order_acquire)) + 1ULL;
    request.skip_backup = current.recovered_from_backup || current.preserve_recovery_backup;
    request.nodes = resolved_nodes(current);
    request.current_paths = capture_paths(current);
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    request.environment = current.environment;
    request.current_payload = capture_current_payload(current);
    if (!request.current_payload)
        return workspace_request_result_t::failed;
    return submit_operation(std::move(request));
}

bool operation_pending() noexcept
{
    return operation_runtime().pending.load(std::memory_order_acquire);
}

std::string operation_status() noexcept
{
    const state_t& current = state();
    return current.operation_error.empty() ? current.operation_status : current.operation_error;
}

workspace_request_result_t switch_to(workspace_preset_t preset) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (!current.root_prepared)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    if (current.active == preset && current.active_user.empty() && !current.rebuild_requested)
        return workspace_request_result_t::unchanged;
    operation_request_t request;
    request.kind = operation_kind_t::switch_preset;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    request.current_user_name = current.active_user;
    request.target_preset = preset;
    request.target_locked = current.locked;
    request.save_generation = (std::max)(current.generation,
        committed_generation().load(std::memory_order_acquire)) + 1ULL;
    request.skip_backup = current.recovered_from_backup || current.preserve_recovery_backup;
    request.nodes = resolved_nodes(current);
    request.current_paths = capture_paths(current);
    request.target_paths = preset_paths(current, preset);
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    request.environment = current.environment;
    request.current_payload = capture_current_payload(current);
    if (!request.current_payload)
        return workspace_request_result_t::failed;
    return submit_operation(std::move(request));
}

workspace_request_result_t save_user_layout(std::string_view name, bool overwrite) noexcept
{
    state_t& current = state();
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (!current.root_prepared)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    if (!catalog_ready().load(std::memory_order_acquire))
        return workspace_request_result_t::unavailable;
    const auto catalog = catalog_snapshot();
    const bool exists = catalog && std::any_of(catalog->begin(), catalog->end(),
        [name](const auto& entry) { return entry.name == name; });
    if (!overwrite && exists)
        return workspace_request_result_t::already_exists;
    if (!exists && catalog && catalog->size() >= kMaximumNamedUserLayouts)
        return workspace_request_result_t::unavailable;
    operation_request_t request;
    try {
        request.target_paths = named_user_paths(current, name);
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    request.kind = operation_kind_t::save_user;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    request.current_user_name = current.active_user;
    request.target_user_name.assign(name);
    request.overwrite = overwrite;
    request.target_preset = current.active;
    request.target_locked = current.locked;
    request.save_generation = (std::max)(current.generation,
        committed_generation().load(std::memory_order_acquire)) + 1ULL;
    request.skip_backup = current.recovered_from_backup || current.preserve_recovery_backup;
    request.nodes = resolved_nodes(current);
    request.current_paths = capture_paths(current);
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    request.environment = current.environment;
    request.current_payload = capture_current_payload(current);
    if (!request.current_payload)
        return workspace_request_result_t::failed;
    return submit_operation(std::move(request));
}

workspace_request_result_t save_active_user_layout() noexcept
{
    const std::string name = state().active_user;
    return name.empty() ? workspace_request_result_t::unavailable :
        save_user_layout(name, true);
}

workspace_request_result_t load_user_layout(std::string_view name) noexcept
{
    return load_user_layout_exact(name, 0);
}

workspace_request_result_t load_user_layout_exact(std::string_view name,
    std::uint64_t expected_generation) noexcept
{
    state_t& current = state();
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (!current.root_prepared)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    if (!catalog_ready().load(std::memory_order_acquire))
        return workspace_request_result_t::unavailable;
    const auto catalog = catalog_snapshot();
    const auto selected = catalog ? std::find_if(catalog->begin(), catalog->end(),
        [name](const auto& entry) { return entry.name == name; }) :
        std::vector<user_workspace_descriptor_t>::const_iterator{};
    if (!catalog || selected == catalog->end())
        return workspace_request_result_t::not_found;
    if (expected_generation != 0 && selected->generation != expected_generation)
        return workspace_request_result_t::unavailable;
    operation_request_t request;
    try {
        request.target_paths = named_user_paths(current, name);
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    request.kind = operation_kind_t::load_user;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    request.current_user_name = current.active_user;
    request.target_user_name.assign(name);
    request.expected_user_generation = expected_generation != 0
        ? expected_generation : selected->generation;
    request.target_preset = current.active;
    request.target_locked = current.locked;
    request.save_generation = (std::max)(current.generation,
        committed_generation().load(std::memory_order_acquire)) + 1ULL;
    request.skip_backup = current.recovered_from_backup || current.preserve_recovery_backup;
    request.nodes = resolved_nodes(current);
    request.current_paths = capture_paths(current);
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    request.environment = current.environment;
    request.current_payload = capture_current_payload(current);
    if (!request.current_payload)
        return workspace_request_result_t::failed;
    return submit_operation(std::move(request));
}

workspace_request_result_t rename_user_layout(std::string_view current_name,
    std::string_view new_name) noexcept
{
    state_t& current = state();
    if (!valid_user_layout_name(current_name) || !valid_user_layout_name(new_name))
        return workspace_request_result_t::invalid_name;
    if (current_name == new_name)
        return workspace_request_result_t::unchanged;
    if (!current.initialized || !current.root_prepared || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    if (!catalog_ready().load(std::memory_order_acquire))
        return workspace_request_result_t::unavailable;
    const auto catalog = catalog_snapshot();
    if (!catalog || std::none_of(catalog->begin(), catalog->end(),
            [current_name](const auto& entry) { return entry.name == current_name; }))
        return workspace_request_result_t::not_found;
    if (std::any_of(catalog->begin(), catalog->end(),
            [new_name](const auto& entry) { return entry.name == new_name; }))
        return workspace_request_result_t::already_exists;
    operation_request_t request;
    try {
        request.source_user_paths = named_user_paths(current, current_name);
        request.target_paths = named_user_paths(current, new_name);
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    request.kind = operation_kind_t::rename_user;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    const auto source_descriptor = std::find_if(catalog->begin(), catalog->end(),
        [current_name](const auto& entry) { return entry.name == current_name; });
    request.target_preset = source_descriptor->base_preset;
    request.target_locked = current.locked;
    request.current_user_name = current.active_user;
    request.source_user_name.assign(current_name);
    request.target_user_name.assign(new_name);
    request.expected_user_generation = source_descriptor->generation;
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    return submit_operation(std::move(request));
}

workspace_request_result_t delete_user_layout(std::string_view name) noexcept
{
    state_t& current = state();
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    if (!current.initialized || !current.root_prepared || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    if (!catalog_ready().load(std::memory_order_acquire))
        return workspace_request_result_t::unavailable;
    const auto catalog = catalog_snapshot();
    if (!catalog || std::none_of(catalog->begin(), catalog->end(),
            [name](const auto& entry) { return entry.name == name; }))
        return workspace_request_result_t::not_found;
    operation_request_t request;
    try {
        request.target_paths = named_user_paths(current, name);
        if (current.active_user == name)
            request.fallback_paths = preset_paths(current, current.active);
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    request.kind = operation_kind_t::delete_user;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    const auto target_descriptor = std::find_if(catalog->begin(), catalog->end(),
        [name](const auto& entry) { return entry.name == name; });
    request.target_preset = target_descriptor->base_preset;
    request.target_locked = current.locked;
    request.current_user_name = current.active_user;
    request.target_user_name.assign(name);
    request.expected_user_generation = target_descriptor->generation;
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    return submit_operation(std::move(request));
}

workspace_request_result_t restore_builtin(workspace_preset_t preset) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    operation_request_t request;
    request.kind = operation_kind_t::restore_preset;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    request.target_preset = preset;
    request.target_locked = false;
    request.current_user_name = current.active_user;
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    try {
        request.reset_paths.push_back(preset_paths(current, preset));
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return submit_operation(std::move(request));
}

workspace_request_result_t reset_current() noexcept { return restore_builtin(active_preset()); }

workspace_request_result_t reset_all() noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    operation_request_t request;
    request.kind = operation_kind_t::reset_all;
    request.source_generation = current.generation;
    request.expected_root = current.expected_root;
    request.current_preset = current.active;
    request.target_preset = workspace_preset_t::analysis;
    request.target_locked = false;
    request.current_user_name = current.active_user;
    request.workspace_directory = current.directory;
    request.active_record = current.active_record;
    try {
        for (const auto& descriptor : kPresetDescriptors)
            request.reset_paths.push_back(preset_paths(current, descriptor.id));
        request.user_directory = current.directory / L"user";
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return submit_operation(std::move(request));
}

workspace_request_result_t activate_safe_layout() noexcept
{
    return restore_builtin(workspace_preset_t::safe);
}

workspace_request_result_t open_missing_views() noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    if (current.locked)
        return workspace_request_result_t::unavailable;
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return workspace_request_result_t::busy;
    const dock_nodes_t nodes = resolved_nodes(current);
    dock_named_windows(current.active, nodes.navigator, nodes.documents,
        nodes.inspector, nodes.bottom, true);
    ImGui::DockBuilderFinish(current.expected_root);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

void persist_if_requested() noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || !current.persistence_available)
        return;
    process_operation_completion();
    process_operation_retry();
    if (operation_runtime().pending.load(std::memory_order_acquire))
        return;
    ImGuiIO& io = ImGui::GetIO();
    const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t completed = committed_generation().load(std::memory_order_acquire);
    if (current.generation != 0 && completed >= current.generation)
        current.recovered_from_backup = false;
    const std::uint64_t failed = failed_generation().exchange(0, std::memory_order_acq_rel);
    if (failed != 0 && failed == current.generation) {
        io.WantSaveIniSettings = true;
        current.next_save_attempt_ms = now_ms + 5000ULL;
        diag::log_tagged_critical_fmt("workspace_layout",
            "layout_async_save_failed generation=%llu",
            static_cast<unsigned long long>(failed));
    }
    if (!io.WantSaveIniSettings)
        return;
    if (current.next_save_attempt_ms != 0 && now_ms < current.next_save_attempt_ms)
        return;
    std::size_t payload_size = 0;
    const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
    if (!payload || payload_size == 0 || payload_size > kMaximumPayloadBytes) {
        current.next_save_attempt_ms = now_ms + 5000ULL;
        diag::log_tagged_critical_fmt("workspace_layout",
            "layout_save_capture_rejected payload_bytes=%llu maximum_bytes=%llu",
            static_cast<unsigned long long>(payload_size),
            static_cast<unsigned long long>(kMaximumPayloadBytes));
        return;
    }
    current.nodes = resolved_nodes(current);
    bool queued = false;
    const std::uint64_t next_generation = (std::max)(current.generation,
        committed_generation().load(std::memory_order_acquire)) + 1ULL;
    try {
        queued = payload && queue_write(capture_paths(current), current.expected_root,
            std::string_view(payload, payload_size), next_generation,
            current.recovered_from_backup || current.preserve_recovery_backup,
            current.nodes, current.active, current.locked, current.environment,
            current.registry_fingerprint);
    } catch (...) {
        queued = false;
    }
    if (queued) {
        io.WantSaveIniSettings = false;
        current.generation = next_generation;
        current.next_save_attempt_ms = 0;
        diag::log_tagged_fmt("workspace_layout",
            "layout_save_queued generation=%llu payload_bytes=%llu",
            static_cast<unsigned long long>(next_generation),
            static_cast<unsigned long long>(payload_size));
    } else {
        current.next_save_attempt_ms = now_ms + 5000ULL;
        diag::log_tagged_critical_fmt("workspace_layout", "layout_save_queue_failed payload_bytes=%llu",
            static_cast<unsigned long long>(payload_size));
    }
}

void settle_pending_operation_for_shutdown() noexcept
{
    process_operation_completion();
}

void shutdown() noexcept
{
    process_operation_completion();
    state_t& current = state();
    if (!current.initialized)
        return;
    const bool transaction_pending = operation_runtime().pending.load(std::memory_order_acquire);
    if (current.root_prepared && current.persistence_available && !transaction_pending) {
        std::size_t payload_size = 0;
        const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
        current.nodes = resolved_nodes(current);
        bool saved = false;
        const std::uint64_t final_generation = (std::max)(current.generation,
            committed_generation().load(std::memory_order_acquire)) + 1ULL;
        try {
            saved = payload && write_generation(capture_paths(current), current.expected_root,
                std::string_view(payload, payload_size), final_generation, true,
                current.recovered_from_backup || current.preserve_recovery_backup,
                current.nodes, current.active, current.locked, current.environment,
                current.registry_fingerprint);
        } catch (...) {
            saved = false;
        }
        if (!saved)
            diag::log_tagged_critical_fmt("workspace_layout", "layout_shutdown_save_failed payload_bytes=%llu",
                static_cast<unsigned long long>(payload_size));
        else
            diag::log_tagged_fmt("workspace_layout",
                "layout_shutdown_save_complete generation=%llu payload_bytes=%llu clean_shutdown=1",
                static_cast<unsigned long long>(final_generation),
                static_cast<unsigned long long>(payload_size));
    } else if (transaction_pending) {
        diag::log_tagged_critical("workspace_layout",
            "layout_shutdown_save_skipped pending_transaction_not_settled=1");
    }
    const std::uint64_t reset_epoch = catalog_epoch().fetch_add(
        1, std::memory_order_acq_rel) + 1ULL;
    publish_catalog(std::make_shared<const std::vector<user_workspace_descriptor_t>>(),
        reset_epoch);
    catalog_ready().store(false, std::memory_order_release);
    current = {};
}

}

#endif
