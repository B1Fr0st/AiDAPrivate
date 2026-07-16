#pragma once

#include "../disasm/disasm_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace aida::ui::workbench_registry_views {
namespace detail {

class frame_cancellation_t final
    : public aida::workbench::navigator::navigator_cancellation_t,
      public aida::workbench::diff_document::diff_cancellation_t {
public:
    explicit frame_cancellation_t(std::uint32_t budget_ms)
        : deadline_(std::chrono::steady_clock::now() +
            std::chrono::milliseconds(budget_ms)) {}

    bool cancelled() const noexcept override {
        return std::chrono::steady_clock::now() >= deadline_;
    }

private:
    std::chrono::steady_clock::time_point deadline_;
};

struct state_t final {
    aida::workbench::navigator::navigator_domain_t navigator_domain =
        aida::workbench::navigator::navigator_domain_t::functions;
    std::uint64_t navigator_selected_id = 0;
    std::uint64_t last_address = 0;
    std::uint64_t diff_offset = 0;
    std::uint64_t diff_total = 0;
    aida::workbench::diff_document::diff_kind_t diff_kind =
        aida::workbench::diff_document::diff_kind_t::generation;
    std::uint64_t observed_generation = 0;
    std::uint64_t last_touch = 0;
};

inline state_t& state_for(aida::workbench::workspace_id_t workspace) {
    static std::map<std::uint64_t, state_t> states;
    static std::uint64_t touch = 0;
    if (++touch == 0)
        touch = 1;
    auto found = states.find(workspace.value);
    if (found == states.end()) {
        if (states.size() >= 64) {
            const auto oldest = std::min_element(states.begin(), states.end(),
                [](const auto& lhs, const auto& rhs) {
                    return lhs.second.last_touch < rhs.second.last_touch;
                });
            if (oldest != states.end())
                states.erase(oldest);
        }
        found = states.try_emplace(workspace.value).first;
    }
    found->second.last_touch = touch;
    return found->second;
}

inline bool selected_context(
    std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    aida::workbench::workbench_shell_workspace_context_t& context,
    std::string& failure) {
    const auto selected = disasm_view::capture_selected_workspace();
    workspace = selected.workspace;
    if (!workspace) {
        failure = "Open and analyze a binary to use this Workbench surface.";
        return false;
    }
    const auto loaded = aida::workbench::workbench_shell_runtime_t::instance()
        .workspace_context(workspace, context);
    if (!loaded) {
        failure = "Workbench context is unavailable (" +
            std::to_string(static_cast<unsigned>(loaded.code)) + ").";
        return false;
    }
    return true;
}

inline void synchronize_generation(state_t& state,
    const aida::workbench::workbench_shell_workspace_context_t& context) {
    if (state.observed_generation == context.analysis_generation)
        return;
    state.navigator_selected_id = 0;
    state.last_address = 0;
    state.diff_offset = 0;
    state.diff_total = 0;
    state.observed_generation = context.analysis_generation;
}

inline void navigate(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    aida::workbench::workbench_shell_workspace_context_t& context,
    std::uint64_t address, std::string entity_key,
    aida::workbench::document_kind_t kind) {
    aida::workbench::selection_context_t selection;
    selection.kind = aida::workbench::selection_kind_t::address;
    selection.has_address = true;
    selection.address = address;
    selection.entity_key = std::move(entity_key);
    aida::workbench::document_local_cursor_t cursor;
    cursor.has_position = true;
    cursor.position = address;
    static_cast<void>(aida::workbench::workbench_shell_runtime_t::instance()
        .navigate_document(workspace, kind, std::nullopt, selection, cursor, context));
}

inline bool diff_scope(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const aida::workbench::workbench_shell_workspace_context_t& context,
    aida::workbench::diff_document::diff_kind_t kind,
    aida::workbench::diff_document::diff_scope_t& scope) {
    scope = {};
    scope.kind = kind;
    scope.before.workspace_id = context.workspace.value;
    scope.after.workspace_id = context.workspace.value;
    scope.before.generation = context.analysis_generation;
    scope.after.generation = context.analysis_generation;
    if (kind == aida::workbench::diff_document::diff_kind_t::generation) {
        if (context.analysis_generation < 2)
            return false;
        scope.before.generation = context.analysis_generation - 1;
        return true;
    }
    if (kind == aida::workbench::diff_document::diff_kind_t::overlay) {
        if (context.overlay_revision == 0)
            return false;
        scope.before.overlay_revision = context.overlay_revision - 1;
        scope.after.overlay_revision = context.overlay_revision;
        return true;
    }
    for (const auto& other : aida::workbench::workbench_shell_runtime_t::instance()
            .analysis_workspaces()) {
        if (!other || other == workspace)
            continue;
        aida::workbench::workbench_shell_workspace_context_t other_context;
        const auto loaded = aida::workbench::workbench_shell_runtime_t::instance()
            .workspace_context(other, other_context);
        if (!loaded)
            continue;
        scope.after.workspace_id = other_context.workspace.value;
        scope.after.generation = other_context.analysis_generation;
        return true;
    }
    return false;
}

}

inline void render_navigator() {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::workbench::workbench_shell_workspace_context_t context;
    std::string failure;
    if (!detail::selected_context(workspace, context, failure)) {
        ImGui::TextWrapped("%s", failure.c_str());
        return;
    }
    auto& state = detail::state_for(context.workspace);
    detail::synchronize_generation(state, context);
    using domain_t = aida::workbench::navigator::navigator_domain_t;
    constexpr std::array<std::pair<const char*, domain_t>, 6> domains{{
        {"Functions", domain_t::functions}, {"Imports", domain_t::imports},
        {"Exports", domain_t::exports}, {"Strings", domain_t::strings},
        {"Symbols", domain_t::symbols}, {"Types", domain_t::types}}};
    const char* preview = "Functions";
    for (const auto& domain : domains) {
        if (domain.second == state.navigator_domain) {
            preview = domain.first;
            break;
        }
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##workbench_navigator_domain", preview)) {
        for (const auto& domain : domains) {
            const bool selected = domain.second == state.navigator_domain;
            if (ImGui::Selectable(domain.first, selected)) {
                state.navigator_domain = domain.second;
                state.navigator_selected_id = 0;
            }
            if (selected)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    if (!context.navigator_tree) {
        ImGui::TextDisabled("Navigator provider unavailable");
        return;
    }
    aida::workbench::navigator::navigator_tree_request_t request;
    request.domain = state.navigator_domain;
    request.page.limit = 256;
    detail::frame_cancellation_t cancellation(20);
    aida::workbench::navigator::navigator_tree_page_t page;
    const auto loaded = context.navigator_tree->page(request, &cancellation, page);
    if (!loaded) {
        ImGui::TextDisabled("Navigator deferred (%u)",
            static_cast<unsigned>(loaded.code));
        return;
    }
    ImGui::TextDisabled("%llu items", static_cast<unsigned long long>(page.total_rows));
    ImGui::Separator();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(page.rows.size()));
    while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
            const auto& row = page.rows[static_cast<std::size_t>(index)];
            ImGui::PushID(static_cast<int>(row.id.value & 0x7FFFFFFFU));
            const bool selected = state.navigator_selected_id == row.id.value;
            const std::string row_label(row.label);
            if (ImGui::Selectable(row_label.c_str(), selected)) {
                state.navigator_selected_id = row.id.value;
                if (row.has_address) {
                    state.last_address = row.address;
                    detail::navigate(workspace, context, row.address,
                        std::to_string(row.id.value),
                        aida::workbench::document_kind_t::disassembly);
                }
            }
            const bool keyboard_context = selected && ImGui::IsWindowFocused(
                ImGuiFocusedFlags_RootAndChildWindows) &&
                (ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
                 (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)));
            if (keyboard_context)
                ImGui::OpenPopup("navigator_context");
            if (ImGui::BeginPopupContextItem("navigator_context")) {
                if (row.has_address && ImGui::MenuItem("Follow in Disassembly")) {
                    state.last_address = row.address;
                    detail::navigate(workspace, context, row.address,
                        std::to_string(row.id.value),
                        aida::workbench::document_kind_t::disassembly);
                }
                ImGui::BeginDisabled(!row.has_address);
                if (ImGui::MenuItem("Copy Address")) {
                    char address[32];
                    std::snprintf(address, sizeof(address), "0x%llX",
                        static_cast<unsigned long long>(row.address));
                    ImGui::SetClipboardText(address);
                }
                ImGui::EndDisabled();
                if (ImGui::MenuItem("Copy Name"))
                    ImGui::SetClipboardText(row_label.c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }
}

inline void render_inspector() {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::workbench::workbench_shell_workspace_context_t context;
    std::string failure;
    if (!detail::selected_context(workspace, context, failure)) {
        ImGui::TextWrapped("%s", failure.c_str());
        return;
    }
    static_cast<void>(workspace);
    ImGui::Text("Generation: %llu", static_cast<unsigned long long>(
        context.analysis_generation));
    ImGui::Text("Analysis revision: %llu", static_cast<unsigned long long>(
        context.analysis_revision));
    ImGui::Text("Overlay revision: %llu", static_cast<unsigned long long>(
        context.overlay_revision));
    const auto* active = context.inspector_session
        ? context.inspector_session->active_context() : nullptr;
    if (!active) {
        ImGui::Separator();
        ImGui::TextDisabled("No synchronized selection");
        return;
    }
    ImGui::Separator();
    ImGui::Text("Document kind: %u", static_cast<unsigned>(active->document.kind));
    if (active->selection.has_address) {
        ImGui::Text("Address: 0x%llX", static_cast<unsigned long long>(
            active->selection.address));
        if (ImGui::BeginPopupContextItem("inspector_address_context")) {
            if (ImGui::MenuItem("Copy Address")) {
                char address[32];
                std::snprintf(address, sizeof(address), "0x%llX",
                    static_cast<unsigned long long>(active->selection.address));
                ImGui::SetClipboardText(address);
            }
            ImGui::EndPopup();
        }
    }
    if (!active->selection.entity_key.empty()) {
        ImGui::TextWrapped("Entity: %s", active->selection.entity_key.c_str());
        if (ImGui::BeginPopupContextItem("inspector_entity_context")) {
            if (ImGui::MenuItem("Copy Entity"))
                ImGui::SetClipboardText(active->selection.entity_key.c_str());
            ImGui::EndPopup();
        }
    }
    constexpr std::array<const char*, 10> panels{{"Identity", "Bytes", "Operands",
        "Xrefs", "Calls", "Stack/locals", "Types", "Overlays", "Diagnostics",
        "Source provenance"}};
    ImGui::Separator();
    ImGui::TextDisabled("Available selection providers");
    for (const auto* panel : panels)
        ImGui::BulletText("%s", panel);
}

inline void render_diff() {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::workbench::workbench_shell_workspace_context_t context;
    std::string failure;
    if (!detail::selected_context(workspace, context, failure)) {
        ImGui::TextWrapped("%s", failure.c_str());
        return;
    }
    auto& state = detail::state_for(context.workspace);
    detail::synchronize_generation(state, context);
    if (!context.diff_document) {
        ImGui::TextDisabled("Diff provider unavailable");
        return;
    }
    if (ImGui::RadioButton("Generation", state.diff_kind ==
            aida::workbench::diff_document::diff_kind_t::generation))
        state.diff_kind = aida::workbench::diff_document::diff_kind_t::generation;
    ImGui::SameLine();
    if (ImGui::RadioButton("Overlay", state.diff_kind ==
            aida::workbench::diff_document::diff_kind_t::overlay))
        state.diff_kind = aida::workbench::diff_document::diff_kind_t::overlay;
    ImGui::SameLine();
    if (ImGui::RadioButton("Workspace", state.diff_kind ==
            aida::workbench::diff_document::diff_kind_t::workspace))
        state.diff_kind = aida::workbench::diff_document::diff_kind_t::workspace;
    aida::workbench::diff_document::diff_scope_t scope;
    if (!detail::diff_scope(workspace, context, state.diff_kind, scope)) {
        ImGui::TextWrapped("The selected diff requires another retained generation, overlay revision, or workspace.");
        return;
    }
    ImGui::BeginDisabled(state.diff_offset == 0);
    if (ImGui::Button("Previous"))
        state.diff_offset = state.diff_offset > 256 ? state.diff_offset - 256 : 0;
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(state.diff_total <= state.diff_offset + 256);
    if (ImGui::Button("Next"))
        state.diff_offset = (std::min)(state.diff_offset + 256,
            state.diff_total > 256 ? state.diff_total - 256 : 0);
    ImGui::EndDisabled();
    aida::workbench::diff_document::diff_page_t page;
    detail::frame_cancellation_t cancellation(30);
    const auto loaded = context.diff_document->page({state.diff_offset, 256,
        static_cast<aida::workbench::diff_document::diff_domain_t>(0xFF)},
        context.analysis_generation, scope, &cancellation, page);
    if (!loaded) {
        ImGui::TextDisabled("Diff materialization deferred (%u)",
            static_cast<unsigned>(loaded.code));
        return;
    }
    state.diff_total = page.total_entries;
    ImGui::SameLine();
    ImGui::TextDisabled("%llu changes", static_cast<unsigned long long>(state.diff_total));
    ImGui::Separator();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(page.entries.size()));
    while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
            const auto& entry = page.entries[static_cast<std::size_t>(index)];
            char label[2048];
            std::snprintf(label, sizeof(label), "%016llX  %s  %s -> %s##workbench_diff_%llu",
                static_cast<unsigned long long>(entry.address), entry.entity_key.c_str(),
                entry.old_value.c_str(), entry.new_value.c_str(),
                static_cast<unsigned long long>(page.offset + static_cast<std::size_t>(index)));
            const bool selected = state.last_address != 0 && state.last_address == entry.address;
            if (ImGui::Selectable(label, selected) && entry.address != 0) {
                state.last_address = entry.address;
                detail::navigate(workspace, context, entry.address, entry.entity_key,
                    aida::workbench::document_kind_t::diff);
            }
            if (ImGui::BeginPopupContextItem("diff_context")) {
                ImGui::BeginDisabled(entry.address == 0);
                if (ImGui::MenuItem("Follow Change")) {
                    state.last_address = entry.address;
                    detail::navigate(workspace, context, entry.address, entry.entity_key,
                        aida::workbench::document_kind_t::diff);
                }
                if (ImGui::MenuItem("Copy Address")) {
                    char address[32];
                    std::snprintf(address, sizeof(address), "0x%llX",
                        static_cast<unsigned long long>(entry.address));
                    ImGui::SetClipboardText(address);
                }
                ImGui::EndDisabled();
                if (ImGui::MenuItem("Copy Before"))
                    ImGui::SetClipboardText(entry.old_value.c_str());
                if (ImGui::MenuItem("Copy After"))
                    ImGui::SetClipboardText(entry.new_value.c_str());
                ImGui::EndPopup();
            }
        }
    }
}

}
