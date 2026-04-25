#pragma once
#include "../helpers/globals.h"
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>

namespace toast_notification
{
    enum class toast_type_t : int
    {
        error = 0,
        warning,
        info
    };

    struct toast_t
    {
        std::string message;
        toast_type_t type = toast_type_t::error;
        float duration = 5.0f;
        float elapsed = 0.0f;
        float slide_progress = 0.0f;
        bool dismissed = false;
    };

    inline std::mutex g_toast_mtx;
    inline std::vector<toast_t> g_toasts;
    inline constexpr int MAX_VISIBLE = 5;
    inline constexpr float SLIDE_DURATION = 0.25f;
    inline constexpr float DEDUP_WINDOW = 3.0f;
    inline constexpr float TOAST_WIDTH = 360.0f;
    inline constexpr float TOAST_PADDING = 12.0f;
    inline constexpr float TIMER_BAR_HEIGHT = 3.0f;
    inline constexpr float TOAST_ROUNDING = 8.0f;
    inline constexpr float TOAST_SPACING = 6.0f;
    inline constexpr float TOP_MARGIN = 40.0f;

    inline void push(const std::string& message, toast_type_t type = toast_type_t::error, float duration = 5.0f)
    {
        if (message.empty())
            return;

        std::lock_guard<std::mutex> lk(g_toast_mtx);

        for (const auto& t : g_toasts) {
            if (t.message == message && t.elapsed < DEDUP_WINDOW && !t.dismissed)
                return;
        }

        toast_t t;
        t.message = message;
        t.type = type;
        t.duration = duration;
        t.elapsed = 0.0f;
        t.slide_progress = 0.0f;
        t.dismissed = false;
        g_toasts.push_back(std::move(t));

        while (static_cast<int>(g_toasts.size()) > MAX_VISIBLE * 2) {
            g_toasts.erase(g_toasts.begin());
        }
    }

    inline void render()
    {
        std::lock_guard<std::mutex> lk(g_toast_mtx);

        if (g_toasts.empty())
            return;

        const float dt = ImGui::GetIO().DeltaTime;
        const ImVec2 display = ImGui::GetIO().DisplaySize;
        auto* draw = ImGui::GetForegroundDrawList();

        const ImVec4& accent = globals::ui::accent;
        const auto& theme = themes::resolved;

        ImU32 accent_col = IM_COL32(
            static_cast<int>(accent.x * 255.0f),
            static_cast<int>(accent.y * 255.0f),
            static_cast<int>(accent.z * 255.0f),
            255);

        ImU32 accent_col_dim = IM_COL32(
            static_cast<int>(accent.x * 255.0f),
            static_cast<int>(accent.y * 255.0f),
            static_cast<int>(accent.z * 255.0f),
            60);

        ImU32 bg_col = IM_COL32(
            (theme.panel_bg >> 0) & 0xFF,
            (theme.panel_bg >> 8) & 0xFF,
            (theme.panel_bg >> 16) & 0xFF,
            240);

        ImU32 border_col = IM_COL32(
            (theme.panel_header >> 0) & 0xFF,
            (theme.panel_header >> 8) & 0xFF,
            (theme.panel_header >> 16) & 0xFF,
            200);

        ImU32 text_col = theme.text_primary;
        ImU32 text_dim_col = theme.text_secondary;

        float y_offset = TOP_MARGIN;
        int visible = 0;

        for (auto& t : g_toasts) {
            if (t.dismissed)
                continue;

            t.elapsed += dt;

            if (t.slide_progress < 1.0f)
                t.slide_progress = (std::min)(t.slide_progress + dt / SLIDE_DURATION, 1.0f);

            if (t.elapsed >= t.duration) {
                t.dismissed = true;
                continue;
            }

            if (visible >= MAX_VISIBLE)
                continue;

            float ease = t.slide_progress * t.slide_progress * (3.0f - 2.0f * t.slide_progress);

            float fade_out = 1.0f;
            float remaining = t.duration - t.elapsed;
            if (remaining < 0.3f)
                fade_out = remaining / 0.3f;

            float alpha = ease * fade_out;

            ImFont* font = ImGui::GetFont();
            float wrap_width = TOAST_WIDTH - TOAST_PADDING * 2.0f;
            ImVec2 text_size = font->CalcTextSizeA(font->FontSize, FLT_MAX, wrap_width, t.message.c_str());
            float toast_height = text_size.y + TOAST_PADDING * 2.0f + TIMER_BAR_HEIGHT + 2.0f;

            float target_y = y_offset;
            float start_y = target_y - 30.0f;
            float current_y = start_y + (target_y - start_y) * ease;

            float toast_x = (display.x - TOAST_WIDTH) * 0.5f;

            ImU32 bg_final = IM_COL32(
                (bg_col >> 0) & 0xFF,
                (bg_col >> 8) & 0xFF,
                (bg_col >> 16) & 0xFF,
                static_cast<int>(((bg_col >> 24) & 0xFF) * alpha));

            ImU32 border_final = IM_COL32(
                (border_col >> 0) & 0xFF,
                (border_col >> 8) & 0xFF,
                (border_col >> 16) & 0xFF,
                static_cast<int>(((border_col >> 24) & 0xFF) * alpha));

            ImU32 text_final = IM_COL32(
                (text_col >> 0) & 0xFF,
                (text_col >> 8) & 0xFF,
                (text_col >> 16) & 0xFF,
                static_cast<int>(((text_col >> 24) & 0xFF) * alpha));

            ImU32 accent_bar = IM_COL32(
                static_cast<int>(accent.x * 255.0f),
                static_cast<int>(accent.y * 255.0f),
                static_cast<int>(accent.z * 255.0f),
                static_cast<int>(220.0f * alpha));

            ImU32 accent_bar_bg = IM_COL32(
                static_cast<int>(accent.x * 100.0f),
                static_cast<int>(accent.y * 100.0f),
                static_cast<int>(accent.z * 100.0f),
                static_cast<int>(40.0f * alpha));

            ImVec2 tl(toast_x, current_y);
            ImVec2 br(toast_x + TOAST_WIDTH, current_y + toast_height);

            draw->AddRectFilled(tl, br, bg_final, TOAST_ROUNDING);
            draw->AddRect(tl, br, border_final, TOAST_ROUNDING, 0, 1.0f);

            draw->AddLine(
                ImVec2(tl.x, tl.y + 1.0f),
                ImVec2(br.x, tl.y + 1.0f),
                accent_bar, 2.0f);

            ImVec2 text_pos(toast_x + TOAST_PADDING, current_y + TOAST_PADDING);
            draw->AddText(font, font->FontSize, text_pos, text_final,
                          t.message.c_str(), nullptr, wrap_width);

            float timer_y = br.y - TIMER_BAR_HEIGHT - 1.0f;
            float progress = 1.0f - (t.elapsed / t.duration);
            float bar_width = (TOAST_WIDTH - 2.0f) * progress;

            draw->AddRectFilled(
                ImVec2(tl.x + 1.0f, timer_y),
                ImVec2(br.x - 1.0f, timer_y + TIMER_BAR_HEIGHT),
                accent_bar_bg, TOAST_ROUNDING * 0.5f);

            if (bar_width > 0.0f) {
                draw->AddRectFilled(
                    ImVec2(tl.x + 1.0f, timer_y),
                    ImVec2(tl.x + 1.0f + bar_width, timer_y + TIMER_BAR_HEIGHT),
                    accent_bar, TOAST_ROUNDING * 0.5f);
            }

            ImVec2 mouse = ImGui::GetIO().MousePos;
            if (ImGui::IsMouseClicked(0) &&
                mouse.x >= tl.x && mouse.x <= br.x &&
                mouse.y >= current_y && mouse.y <= current_y + toast_height) {
                t.dismissed = true;
            }

            y_offset += toast_height + TOAST_SPACING;
            ++visible;
        }

        g_toasts.erase(
            std::remove_if(g_toasts.begin(), g_toasts.end(),
                           [](const toast_t& t) { return t.dismissed && t.elapsed > t.duration; }),
            g_toasts.end());
    }
}
