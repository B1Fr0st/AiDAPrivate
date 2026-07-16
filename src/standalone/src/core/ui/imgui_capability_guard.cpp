#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#if IMGUI_VERSION_NUM != 19210
#error AiDA requires Dear ImGui 1.92.1 exactly
#endif

#if !defined(IMGUI_HAS_DOCK)
#error AiDA requires the Dear ImGui docking branch
#endif

namespace {

using dock_space_fn = ImGuiID (*)(ImGuiID, const ImVec2&, ImGuiDockNodeFlags, const ImGuiWindowClass*);
using dock_space_over_viewport_fn = ImGuiID (*)(ImGuiID, const ImGuiViewport*, ImGuiDockNodeFlags, const ImGuiWindowClass*);
using dock_builder_add_node_fn = ImGuiID (*)(ImGuiID, ImGuiDockNodeFlags);
using dock_builder_remove_node_fn = void (*)(ImGuiID);
using dock_builder_set_node_pos_fn = void (*)(ImGuiID, ImVec2);
using dock_builder_set_node_size_fn = void (*)(ImGuiID, ImVec2);
using dock_builder_split_node_fn = ImGuiID (*)(ImGuiID, ImGuiDir, float, ImGuiID*, ImGuiID*);
using dock_builder_dock_window_fn = void (*)(const char*, ImGuiID);
using dock_builder_finish_fn = void (*)(ImGuiID);

[[maybe_unused]] constexpr dock_space_fn kDockSpace = &ImGui::DockSpace;
[[maybe_unused]] constexpr dock_space_over_viewport_fn kDockSpaceOverViewport = &ImGui::DockSpaceOverViewport;
[[maybe_unused]] constexpr dock_builder_add_node_fn kDockBuilderAddNode = &ImGui::DockBuilderAddNode;
[[maybe_unused]] constexpr dock_builder_remove_node_fn kDockBuilderRemoveNode = &ImGui::DockBuilderRemoveNode;
[[maybe_unused]] constexpr dock_builder_set_node_pos_fn kDockBuilderSetNodePos = &ImGui::DockBuilderSetNodePos;
[[maybe_unused]] constexpr dock_builder_set_node_size_fn kDockBuilderSetNodeSize = &ImGui::DockBuilderSetNodeSize;
[[maybe_unused]] constexpr dock_builder_split_node_fn kDockBuilderSplitNode = &ImGui::DockBuilderSplitNode;
[[maybe_unused]] constexpr dock_builder_dock_window_fn kDockBuilderDockWindow = &ImGui::DockBuilderDockWindow;
[[maybe_unused]] constexpr dock_builder_finish_fn kDockBuilderFinish = &ImGui::DockBuilderFinish;

}
