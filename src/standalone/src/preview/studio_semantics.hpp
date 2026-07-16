#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "imgui/imgui.h"

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

#include <studio/widget.hpp>

namespace aida::preview::semantics {

inline constexpr std::size_t k_max_widgets_per_frame = 512;

inline bool valid_stable_id(std::string_view value) noexcept
{
    if (value.size() < 3 || value.size() > 128 || value.front() < 'a' || value.front() > 'z')
        return false;
    bool segment_start = false;
    bool saw_separator = false;
    for (std::size_t index = 1; index < value.size(); ++index) {
        const char character = value[index];
        if (character == '.') {
            if (segment_start || index + 1 >= value.size() ||
                value[index + 1] < 'a' || value[index + 1] > 'z')
                return false;
            segment_start = true;
            saw_separator = true;
            continue;
        }
        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') ||
              (character == '-' && !segment_start)))
            return false;
        segment_start = false;
    }
    return saw_separator && !segment_start;
}

inline std::string stable_id(std::string_view prefix, std::string_view source)
{
    std::string output(prefix);
    if (!output.empty() && output.back() != '.')
        output.push_back('.');
    bool previous_dash = false;
    for (const char value : source) {
        const auto raw = static_cast<unsigned char>(value);
        const char character = static_cast<char>(std::tolower(raw));
        if ((character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '.') {
            output.push_back(character);
            previous_dash = false;
        } else if (!previous_dash && !output.empty() && output.back() != '.') {
            output.push_back('-');
            previous_dash = true;
        }
    }
    while (!output.empty() && (output.back() == '-' || output.back() == '.'))
        output.pop_back();
    return output;
}

inline bool register_last_item(std::string_view stable_id_value,
    std::string_view semantic_type, bool allow_overlap = false,
    bool disabled = false) noexcept
{
    if (!valid_stable_id(stable_id_value) || semantic_type.empty() ||
        semantic_type.size() > 128 || ImGui::GetCurrentContext() == nullptr)
        return false;
    static int frame = -1;
    static std::size_t count = 0;
    const int current_frame = ImGui::GetFrameCount();
    if (frame != current_frame) {
        frame = current_frame;
        count = 0;
    }
    if (count >= k_max_widgets_per_frame)
        return false;
    const ImGuiID item_id = ImGui::GetItemID();
    const ImVec2 minimum = ImGui::GetItemRectMin();
    const ImVec2 maximum = ImGui::GetItemRectMax();
    if (item_id == 0 || maximum.x <= minimum.x || maximum.y <= minimum.y)
        return false;
    studio::ItemFlags flags = studio::ItemFlags::None;
    if (allow_overlap)
        flags = studio::ItemFlags::AllowOverlap;
    if (disabled) {
        const auto bits = static_cast<unsigned>(flags) |
            static_cast<unsigned>(studio::ItemFlags::Disabled);
        flags = static_cast<studio::ItemFlags>(bits);
    }
    static_cast<void>(studio::InspectExistingItem({
        .stableId = stable_id_value,
        .semanticType = semantic_type,
        .imguiId = item_id,
        .bounds = {minimum, maximum},
        .hitbox = studio::Rect{minimum, maximum},
        .layoutSize = {0.0f, 0.0f},
        .flags = flags}));
    ++count;
    return true;
}

}

#endif
