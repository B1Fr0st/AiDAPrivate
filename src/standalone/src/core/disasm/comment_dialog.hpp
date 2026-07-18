#pragma once

#include "disasm_view.hpp"
#include "../ui/design_system.hpp"
#include "imgui/imgui.h"

#include <array>
#include <cfloat>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

namespace comment_dialog {

struct state_t {
    bool open_requested = false;
    disasm_view::workspace_context_t context;
    aida::analysis::address_t address;
    std::array<char, 4096> text{};
    std::string error;
};

inline state_t& state() {
    static state_t value;
    return value;
}

inline std::mutex& state_mutex() {
    static std::mutex value;
    return value;
}

inline void open(const disasm_view::workspace_context_t& context,
                 const aida::analysis::address_t& address) {
    if (!context)
        return;
    std::lock_guard<std::mutex> lock(state_mutex());
    auto& value = state();
    value.context = context;
    value.address = address;
    value.error.clear();
    const std::string current = disasm_view::comment(context, address);
    const std::size_t count = (std::min)(current.size(), value.text.size() - 1);
    std::memcpy(value.text.data(), current.data(), count);
    value.text[count] = '\0';
    value.open_requested = true;
}

inline void render() {
    std::lock_guard<std::mutex> lock(state_mutex());
    auto& value = state();
    if (value.open_requested) {
        ImGui::OpenPopup("Edit comment##workspace_comment");
        value.open_requested = false;
    }
    bool keep_open = true;
    if (!aida::ui::design::begin_dialog_exact("Edit comment##workspace_comment",
            ImVec2(620.0f, 420.0f), ImVec2(400.0f, 300.0f), &keep_open))
        return;
    const float footer_height = aida::ui::design::dialog_footer_reserve_height(
        "Apply", "Cancel");
    aida::ui::design::begin_dialog_body("workspace_comment_body", footer_height);
    const auto runtime = disasm_view::runtime_address(value.context, value.address);
    ImGui::Text("Address: 0x%016llX",
        static_cast<unsigned long long>(runtime.value_or(value.address.value)));
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::InputTextMultiline("##comment_text", value.text.data(), value.text.size(),
        ImVec2(-FLT_MIN, (std::max)(150.0f, ImGui::GetContentRegionAvail().y)));
    if (!value.error.empty())
        ImGui::TextWrapped("%s", value.error.c_str());
    aida::ui::design::end_dialog_body();
    const auto footer = aida::ui::design::dialog_footer("workspace_comment_footer",
        "Apply", true, false, "Cancel");
    const bool submitted = ImGui::GetIO().KeyCtrl &&
        (ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
         ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false));
    if (footer.confirmed || submitted) {
        if (disasm_view::queue_comment(value.context, value.address,
                std::string(value.text.data()))) {
            ImGui::CloseCurrentPopup();
        } else {
            value.error = "The workspace is unavailable or closing.";
        }
    }
    if (footer.cancelled || !keep_open)
        ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

}
