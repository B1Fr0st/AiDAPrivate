#pragma once

#include "disasm_view.hpp"
#include "../ui/theme.hpp"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace file_metadata_banner {

inline std::string machine_name(std::uint16_t machine) {
    switch (machine) {
    case 0x014c: return "x86";
    case 0x8664: return "x86-64";
    case 0x01c0: return "ARM";
    case 0xaa64: return "ARM64";
    default: {
        char buffer[24]{};
        std::snprintf(buffer, sizeof(buffer), "machine 0x%04X", machine);
        return buffer;
    }
    }
}

inline const char* readiness_name(aida::analysis::workspace_readiness_t readiness) {
    using aida::analysis::workspace_readiness_t;
    switch (readiness) {
    case workspace_readiness_t::created: return "created";
    case workspace_readiness_t::provider_ready: return "provider ready";
    case workspace_readiness_t::parsed: return "parsed";
    case workspace_readiness_t::analyzing: return "analyzing";
    case workspace_readiness_t::baseline_ready: return "baseline ready";
    case workspace_readiness_t::partial: return "partial";
    case workspace_readiness_t::failed: return "failed";
    case workspace_readiness_t::cancelling: return "cancelling";
    case workspace_readiness_t::closing: return "closing";
    case workspace_readiness_t::closed: return "closed";
    }
    return "unknown";
}

inline void render(const disasm_view::workspace_context_t& context, float alpha) {
    if (!context.workspace || !context.image)
        return;
    const auto& identity = context.workspace->identity();
    const auto& image = *context.image;
    const auto& theme = aida::ui::resolved();
    std::uint64_t image_base = image.image_base();
    bool selected_all = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        if (context.view->display_image_base)
            image_base = *context.view->display_image_base;
        selected_all = context.view->banner_selected_all;
    }
    ImGui::PushStyleColor(ImGuiCol_ChildBg, aida::ui::with_alpha(
        selected_all ? theme.selection : theme.panel_bg, alpha));
    ImGui::BeginChild("##workspace_metadata_banner", ImVec2(0.0f, 92.0f), true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    char identity_line[512]{};
    std::snprintf(identity_line, sizeof(identity_line), "%s  %s  image 0x%016llX  entry +0x%08llX",
        identity.bin_name().c_str(), machine_name(image.machine()).c_str(),
        static_cast<unsigned long long>(image_base),
        static_cast<unsigned long long>(image.entry_rva()));
    char counts_line[256]{};
    std::snprintf(counts_line, sizeof(counts_line),
        "%zu sections  %zu imports  %zu exports  %zu unwind records",
        image.sections().size(), image.imports().size(), image.exports().size(),
        image.runtime_functions().size());
    char revision_line[256]{};
    std::snprintf(revision_line, sizeof(revision_line),
        "generation %llu  analysis %llu  overlay %llu  %s",
        static_cast<unsigned long long>(context.publication->generation),
        static_cast<unsigned long long>(context.publication->analysis_revision),
        static_cast<unsigned long long>(context.workspace->overlay_revision()),
        readiness_name(context.progress.readiness));
    const std::string hash_line = "SHA-256 " + identity.content_hash().to_hex();
    const std::string full_text = std::string(identity_line) + "\n" + hash_line + "\n" +
        counts_line + "\n" + revision_line;
    ImGui::TextUnformatted(identity.bin_name().c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("%s  image 0x%016llX  entry +0x%08llX",
        machine_name(image.machine()).c_str(),
        static_cast<unsigned long long>(image_base),
        static_cast<unsigned long long>(image.entry_rva()));
    ImGui::TextDisabled("SHA-256 %s", identity.content_hash().to_hex().c_str());
    ImGui::TextDisabled("%zu sections  %zu imports  %zu exports  %zu unwind records",
        image.sections().size(), image.imports().size(), image.exports().size(),
        image.runtime_functions().size());
    ImGui::TextDisabled("generation %llu  analysis %llu  overlay %llu  %s",
        static_cast<unsigned long long>(context.publication->generation),
        static_cast<unsigned long long>(context.publication->analysis_revision),
        static_cast<unsigned long long>(context.workspace->overlay_revision()),
        readiness_name(context.progress.readiness));
    ImGui::EndChild();
    if (ImGui::BeginPopupContextItem("##metadata_banner_context")) {
        if (ImGui::MenuItem("Copy", "Ctrl+C"))
            ImGui::SetClipboardText(full_text.c_str());
        if (ImGui::MenuItem("Copy Line Text"))
            ImGui::SetClipboardText(identity_line);
        if (ImGui::MenuItem("Copy Address")) {
            char address[32]{};
            std::snprintf(address, sizeof(address), "%016llX",
                static_cast<unsigned long long>(image_base));
            ImGui::SetClipboardText(address);
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Select All Banner")) {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->banner_selected_all = true;
        }
        ImGui::EndPopup();
    }
    if (selected_all && ImGui::IsItemFocused() && ImGui::GetIO().KeyCtrl &&
        ImGui::IsKeyPressed(ImGuiKey_C, false))
        ImGui::SetClipboardText(full_text.c_str());
    ImGui::PopStyleColor();
}

}
