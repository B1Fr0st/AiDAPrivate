#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "imgui/imgui.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>

#include <studio/widget.hpp>

namespace aida::preview::semantics {

inline constexpr std::size_t k_max_widgets_per_frame = 4096;

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
    return saw_separator && !segment_start && value.back() != '-';
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
        const bool segment_start = output.empty() || output.back() == '.';
        if ((character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9')) {
            if (segment_start && character >= '0' && character <= '9')
                output.push_back('x');
            output.push_back(character);
            previous_dash = false;
        } else if (character == '.') {
            while (!output.empty() && output.back() == '-')
                output.pop_back();
            if (!output.empty() && output.back() != '.')
                output.push_back('.');
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

inline std::string entity_token(std::string_view source)
{
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char raw : source) {
        hash ^= static_cast<unsigned char>(raw);
        hash *= 1099511628211ULL;
    }
    char encoded[18]{};
    const int length = std::snprintf(encoded, sizeof(encoded), "e%016llx",
        static_cast<unsigned long long>(hash));
    return length == 17 ? std::string(encoded, 17) : std::string("e0000000000000000");
}

struct budget_state_t {
    int frame = -1;
    std::size_t count = 0;
    bool diagnosed = false;
};

inline budget_state_t& budget_state() noexcept
{
    static budget_state_t value;
    return value;
}

inline bool consume_budget(std::string_view stable_id_value)
{
    auto& budget = budget_state();
    const int current_frame = ImGui::GetFrameCount();
    if (budget.frame != current_frame) {
        budget.frame = current_frame;
        budget.count = 0;
        budget.diagnosed = false;
    }
    if (budget.count >= k_max_widgets_per_frame) {
        if (!budget.diagnosed) {
            studio::ReportDiagnostic("SEMANTIC_BUDGET_EXHAUSTED", stable_id_value,
                "AiDA preview semantic registration exceeded its per-frame safety budget.");
            budget.diagnosed = true;
        }
        return false;
    }
    ++budget.count;
    return true;
}

inline studio::ItemFlags item_flags(bool allow_overlap, bool disabled) noexcept
{
    unsigned bits = static_cast<unsigned>(studio::ItemFlags::None);
    if (allow_overlap)
        bits |= static_cast<unsigned>(studio::ItemFlags::AllowOverlap);
    if (disabled)
        bits |= static_cast<unsigned>(studio::ItemFlags::Disabled);
    return static_cast<studio::ItemFlags>(bits);
}

inline std::string& active_parent_storage() noexcept
{
    static std::string value;
    return value;
}

inline bool& registration_enabled_storage() noexcept
{
    static bool value = true;
    return value;
}

class scoped_registration_t {
public:
    explicit scoped_registration_t(bool enabled) noexcept
        : previous_(registration_enabled_storage())
    {
        registration_enabled_storage() = previous_ && enabled;
    }

    ~scoped_registration_t()
    {
        registration_enabled_storage() = previous_;
    }

    scoped_registration_t(const scoped_registration_t&) = delete;
    scoped_registration_t& operator=(const scoped_registration_t&) = delete;

private:
    bool previous_;
};

class scoped_parent_t {
public:
    explicit scoped_parent_t(std::string_view parent)
        : previous_(active_parent_storage())
    {
        active_parent_storage().assign(parent);
    }

    ~scoped_parent_t()
    {
        active_parent_storage() = std::move(previous_);
    }

    scoped_parent_t(const scoped_parent_t&) = delete;
    scoped_parent_t& operator=(const scoped_parent_t&) = delete;

private:
    std::string previous_;
};

inline bool register_region(std::string_view stable_id_value,
    std::string_view semantic_type, ImGuiID imgui_id, const ImVec2& minimum,
    const ImVec2& maximum, bool allow_overlap = false, bool disabled = false,
    std::string_view parent_stable_id = {})
{
    const std::string_view resolved_parent = parent_stable_id.empty()
        ? std::string_view(active_parent_storage()) : parent_stable_id;
    if (!registration_enabled_storage() || !valid_stable_id(stable_id_value) ||
        semantic_type.empty() ||
        semantic_type.size() > 128 || imgui_id == 0 || maximum.x <= minimum.x ||
        maximum.y <= minimum.y || ImGui::GetCurrentContext() == nullptr ||
        (!resolved_parent.empty() && !valid_stable_id(resolved_parent)))
        return false;
    const ImVec2 viewport = ImGui::GetIO().DisplaySize;
    if (maximum.x <= 0.0f || maximum.y <= 0.0f || minimum.x >= viewport.x ||
        minimum.y >= viewport.y)
        return false;
    if (!consume_budget(stable_id_value))
        return false;
    const auto interaction = studio::InspectRegion({
        .stableId = stable_id_value,
        .semanticType = semantic_type,
        .imguiId = imgui_id,
        .bounds = {minimum, maximum},
        .hitbox = studio::Rect{minimum, maximum},
        .layoutSize = {0.0f, 0.0f},
        .flags = item_flags(allow_overlap, disabled),
        .parentStableId = resolved_parent});
    return interaction.registered;
}

inline bool register_last_item(std::string_view stable_id_value,
    std::string_view semantic_type, bool allow_overlap = false,
    bool disabled = false, std::string_view parent_stable_id = {})
{
    const std::string_view resolved_parent = parent_stable_id.empty()
        ? std::string_view(active_parent_storage()) : parent_stable_id;
    if (!registration_enabled_storage() || !valid_stable_id(stable_id_value) ||
        semantic_type.empty() ||
        semantic_type.size() > 128 || ImGui::GetCurrentContext() == nullptr ||
        (!resolved_parent.empty() && !valid_stable_id(resolved_parent)))
        return false;
    const ImGuiID item_id = ImGui::GetItemID();
    const ImVec2 minimum = ImGui::GetItemRectMin();
    const ImVec2 maximum = ImGui::GetItemRectMax();
    if (item_id == 0 || maximum.x <= minimum.x || maximum.y <= minimum.y ||
        !ImGui::IsItemVisible())
        return false;
    if (!consume_budget(stable_id_value))
        return false;
    const auto interaction = studio::InspectExistingItem({
        .stableId = stable_id_value,
        .semanticType = semantic_type,
        .imguiId = item_id,
        .bounds = {minimum, maximum},
        .hitbox = studio::Rect{minimum, maximum},
        .layoutSize = {0.0f, 0.0f},
        .flags = item_flags(allow_overlap, disabled),
        .parentStableId = resolved_parent});
    return interaction.registered;
}

}

#endif
