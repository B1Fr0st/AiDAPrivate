#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#include "comment_store.hpp"
#include "imgui/imgui.h"
#include "../ui/components.hpp"
#include "../ui/theme.hpp"

namespace comment_dialog {

namespace detail {

inline bool& open_flag() {
    static bool v = false;
    return v;
}

inline bool& should_open() {
    static bool v = false;
    return v;
}

inline uint64_t& target_addr() {
    static uint64_t v = 0;
    return v;
}

inline char* buffer() {
    static char buf[2048] = {};
    return buf;
}

inline std::string trim_trailing(const char* text) {
    std::string s(text);
    while (!s.empty()) {
        char c = s.back();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            s.pop_back();
        else
            break;
    }
    return s;
}

}

inline bool is_open() {
    return detail::open_flag() || detail::should_open();
}

inline void open(uint64_t addr) {
    detail::target_addr() = addr;
    std::string existing = comment_store::get(addr);
    char* buf = detail::buffer();
    size_t n = existing.size();
    if (n >= 2047) n = 2047;
    if (n > 0) std::memcpy(buf, existing.data(), n);
    buf[n] = '\0';
    detail::should_open() = true;
}

inline void render() {
    if (detail::should_open()) {
        ImGui::OpenPopup("##aida_comment_dialog");
        detail::should_open() = false;
        detail::open_flag() = true;
    }

    if (!detail::open_flag())
        return;

    const auto& tk = aida::ui::resolved();
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.f, 14.f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.f, 8.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tk.bg_overlay));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(tk.panel_bg));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_primary));

    ImVec2 viewport_center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(viewport_center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(460.f, 0.f), ImGuiCond_Appearing);

    char title_buf[64];
    std::snprintf(title_buf, sizeof(title_buf), "Comment at 0x%llX###aida_comment_dialog",
                  static_cast<unsigned long long>(detail::target_addr()));

    bool open_flag_local = true;
    bool save_now = false;
    bool cancel_now = false;

    if (ImGui::BeginPopupModal(title_buf, &open_flag_local,
                               ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
                           "Comment will appear inline next to the disassembly line.");
        ImGui::Spacing();

        ImGuiInputTextFlags itf = ImGuiInputTextFlags_AllowTabInput
                                | ImGuiInputTextFlags_CtrlEnterForNewLine;
        if (ImGui::IsWindowAppearing())
            ImGui::SetKeyboardFocusHere();
        ImGui::InputTextMultiline("##cmt", detail::buffer(), 2048,
                                  ImVec2(420.f, 96.f), itf);

        ImGui::Spacing();

        ImGuiIO& io = ImGui::GetIO();
        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Enter, false))
            save_now = true;
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
            cancel_now = true;

        if (aida::ui::button("Save", aida::ui::button_kind_t::primary,
                             aida::ui::size_t_::md, ImVec2(0.f, 0.f), false, nullptr, false))
            save_now = true;
        ImGui::SameLine();
        if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
                             aida::ui::size_t_::md, ImVec2(0.f, 0.f), false, nullptr, false))
            cancel_now = true;

        if (save_now) {
            std::string trimmed = detail::trim_trailing(detail::buffer());
            comment_store::set(detail::target_addr(), trimmed);
            ImGui::CloseCurrentPopup();
            detail::open_flag() = false;
        } else if (cancel_now || !open_flag_local) {
            ImGui::CloseCurrentPopup();
            detail::open_flag() = false;
        }

        ImGui::EndPopup();
    } else {
        detail::open_flag() = false;
    }

    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar(4);
}

}
