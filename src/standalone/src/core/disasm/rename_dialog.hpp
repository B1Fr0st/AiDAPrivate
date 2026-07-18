#pragma once

#include "disasm_view.hpp"
#include "../ui/design_system.hpp"
#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

namespace rename_dialog {

struct state_t {
    bool open_requested = false;
    disasm_view::workspace_context_t context;
    aida::analysis::address_t address;
    std::array<char, 512> name{};
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

inline bool valid_name(const std::string& name) {
    if (name.empty() || name.size() > 511)
        return false;
    const auto first = static_cast<unsigned char>(name.front());
    if (!(std::isalpha(first) || name.front() == '_' || name.front() == '?' ||
          name.front() == '$' || name.front() == '@'))
        return false;
    return std::all_of(name.begin() + 1, name.end(), [](char character) {
        const auto value = static_cast<unsigned char>(character);
        return std::isalnum(value) || character == '_' || character == '?' ||
               character == '$' || character == '@' || character == ':' ||
               character == '.';
    });
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
    const std::string current = disasm_view::resolve_name(context, address);
    const std::size_t count = (std::min)(current.size(), value.name.size() - 1);
    std::memcpy(value.name.data(), current.data(), count);
    value.name[count] = '\0';
    value.open_requested = true;
}

inline void render() {
    std::lock_guard<std::mutex> lock(state_mutex());
    auto& value = state();
    if (value.open_requested) {
        ImGui::OpenPopup("Rename item##workspace_rename");
        value.open_requested = false;
    }
    bool keep_open = true;
    if (!aida::ui::design::begin_dialog_exact("Rename item##workspace_rename",
            ImVec2(460.0f, 300.0f), ImVec2(360.0f, 240.0f), &keep_open))
        return;
    const float footer_height = aida::ui::design::dialog_footer_reserve_height(
        "Apply", "Cancel");
    aida::ui::design::begin_dialog_body("workspace_rename_body", footer_height);
    const auto runtime = disasm_view::runtime_address(value.context, value.address);
    ImGui::Text("Address: 0x%016llX",
        static_cast<unsigned long long>(runtime.value_or(value.address.value)));
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    const bool submitted = ImGui::InputText("##rename_text", value.name.data(),
        value.name.size(), ImGuiInputTextFlags_EnterReturnsTrue);
    if (!value.error.empty())
        ImGui::TextWrapped("%s", value.error.c_str());
    aida::ui::design::end_dialog_body();
    const auto footer = aida::ui::design::dialog_footer("workspace_rename_footer",
        "Apply", true, false, "Cancel");
    const bool apply = footer.confirmed || submitted;
    if (apply) {
        const std::string proposed(value.name.data());
        if (!valid_name(proposed)) {
            value.error = "Use a non-empty identifier with no whitespace.";
        } else if (disasm_view::queue_rename(value.context, value.address, proposed)) {
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
