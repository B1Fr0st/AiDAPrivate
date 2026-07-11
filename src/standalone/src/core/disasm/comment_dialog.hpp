#pragma once

#include "disasm_view.hpp"
#include "imgui/imgui.h"

#include <array>
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
    if (!ImGui::BeginPopupModal("Edit comment##workspace_comment", &keep_open,
            ImGuiWindowFlags_AlwaysAutoResize))
        return;
    const auto runtime = disasm_view::runtime_address(value.context, value.address);
    ImGui::Text("Address: 0x%016llX",
        static_cast<unsigned long long>(runtime.value_or(value.address.value)));
    ImGui::InputTextMultiline("##comment_text", value.text.data(), value.text.size(),
        ImVec2(520.0f, 150.0f));
    if (!value.error.empty())
        ImGui::TextWrapped("%s", value.error.c_str());
    if (ImGui::Button("Apply", ImVec2(110.0f, 0.0f))) {
        if (disasm_view::queue_comment(value.context, value.address,
                std::string(value.text.data()))) {
            ImGui::CloseCurrentPopup();
        } else {
            value.error = "The workspace is unavailable or closing.";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110.0f, 0.0f)))
        ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

}
