#pragma once

#include "../helpers/globals.h"
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "blur_layer.hpp"
#include "fonts.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <functional>
#include <cstdint>
#include <cmath>

namespace toast_notification
{
    enum class toast_type_t : int
    {
        info = 0,
        success,
        warning,
        error
    };

    struct action_t
    {
        std::string label;
        std::function<void()> on_click;
    };

    struct toast_t
    {
        std::uint64_t id = 0;
        std::string message;
        toast_type_t type = toast_type_t::info;
        float duration = 4.0f;
        float elapsed = 0.0f;
        float intro_progress = 0.0f;
        float fade_out = 1.0f;
        float current_x = 0.0f;
        float current_y = 0.0f;
        float target_x = 0.0f;
        float target_y = 0.0f;
        float velocity_x = 0.0f;
        float velocity_y = 0.0f;
        float swipe_offset = 0.0f;
        float swipe_velocity = 0.0f;
        float dismiss_alpha_decay = 1.0f;
        float hover_amount = 0.0f;
        float hover_velocity = 0.0f;
        bool dismissing = false;
        bool swipe_dismissing = false;
        bool initialized_position = false;
        bool was_dragging = false;
        bool drag_owned = false;
        bool press_started_inside = false;
        action_t action;
        bool has_action = false;
        bool action_clicked_this_frame = false;
    };

    inline constexpr int   MAX_VISIBLE       = 5;
    inline constexpr float DEDUP_WINDOW      = 3.0f;
    inline constexpr float TOAST_WIDTH       = 380.0f;
    inline constexpr float TOAST_HEIGHT      = 56.0f;
    inline constexpr float PADDING           = 14.0f;
    inline constexpr float GAP               = 10.0f;
    inline constexpr float SIDE_MARGIN       = 24.0f;
    inline constexpr float BOTTOM_MARGIN     = 30.0f;
    inline constexpr float SLIDE_DURATION    = 0.32f;
    inline constexpr float FADE_OUT_TAIL     = 0.32f;
    inline constexpr float TOAST_ROUNDING    = 14.0f;
    inline constexpr float ICON_SIZE         = 14.0f;
    inline constexpr float ICON_BOX          = 28.0f;
    inline constexpr float SWIPE_DISMISS_PX  = 100.0f;
    inline constexpr float SWIPE_DISMISS_PCT = 0.30f;
    inline constexpr float HOVER_TIMER_SCALE = 0.18f;

    namespace detail
    {
        inline std::mutex            s_mtx;
        inline std::vector<toast_t>  s_toasts;
        inline std::uint64_t         s_next_id = 1;

        inline ImU32 severity_color(toast_type_t k)
        {
            const auto& th = aida::ui::resolved();
            switch (k) {
                case toast_type_t::success: return th.success;
                case toast_type_t::warning: return th.warning;
                case toast_type_t::error:   return th.error;
                case toast_type_t::info:    return th.info;
            }
            return th.info;
        }

        inline ImU32 severity_soft(toast_type_t k)
        {
            const auto& th = aida::ui::resolved();
            switch (k) {
                case toast_type_t::success: return th.success_soft;
                case toast_type_t::warning: return th.warning_soft;
                case toast_type_t::error:   return th.error_soft;
                case toast_type_t::info:    return th.info_soft;
            }
            return th.info_soft;
        }

        inline ImU32 multiply_alpha(ImU32 c, float a)
        {
            if (a < 0.0f) a = 0.0f;
            if (a > 1.0f) a = 1.0f;
            float aa = static_cast<float>((c >> IM_COL32_A_SHIFT) & 0xFFu) * a;
            ImU32 mask = (0xFFu << IM_COL32_A_SHIFT);
            ImU32 new_a = static_cast<ImU32>(aa);
            return (c & ~mask) | (new_a << IM_COL32_A_SHIFT);
        }

        inline void draw_check(ImDrawList* dl, ImVec2 c, float s, ImU32 col, float thickness)
        {
            float h = s * 0.5f;
            ImVec2 p0(c.x - h * 0.85f,  c.y + h * 0.05f);
            ImVec2 p1(c.x - h * 0.15f,  c.y + h * 0.55f);
            ImVec2 p2(c.x + h * 0.95f,  c.y - h * 0.55f);
            dl->PathLineTo(p0);
            dl->PathLineTo(p1);
            dl->PathLineTo(p2);
            dl->PathStroke(col, 0, thickness);
        }

        inline void draw_warning(ImDrawList* dl, ImVec2 c, float s, ImU32 col, ImU32 fill_col, float thickness)
        {
            float h = s * 0.5f;
            ImVec2 a(c.x,             c.y - h * 0.92f);
            ImVec2 b(c.x + h * 0.95f, c.y + h * 0.70f);
            ImVec2 d(c.x - h * 0.95f, c.y + h * 0.70f);
            dl->PathLineTo(a);
            dl->PathLineTo(b);
            dl->PathLineTo(d);
            dl->PathFillConvex(fill_col);

            dl->PathLineTo(a);
            dl->PathLineTo(b);
            dl->PathLineTo(d);
            dl->PathLineTo(a);
            dl->PathStroke(col, 0, thickness);

            float bar_top = c.y - h * 0.30f;
            float bar_bot = c.y + h * 0.20f;
            dl->AddLine(ImVec2(c.x, bar_top), ImVec2(c.x, bar_bot), col, thickness);
            dl->AddCircleFilled(ImVec2(c.x, c.y + h * 0.45f), thickness * 0.85f, col, 8);
        }

        inline void draw_error(ImDrawList* dl, ImVec2 c, float s, ImU32 col, ImU32 fill_col, float thickness)
        {
            float r = s * 0.55f;
            dl->AddCircleFilled(c, r, fill_col, 28);
            dl->AddCircle(c, r, col, 28, thickness);
            float k = r * 0.42f;
            dl->AddLine(ImVec2(c.x - k, c.y - k), ImVec2(c.x + k, c.y + k), col, thickness);
            dl->AddLine(ImVec2(c.x - k, c.y + k), ImVec2(c.x + k, c.y - k), col, thickness);
        }

        inline void draw_info(ImDrawList* dl, ImVec2 c, float s, ImU32 col, ImU32 fill_col, float thickness)
        {
            float r = s * 0.55f;
            dl->AddCircleFilled(c, r, fill_col, 28);
            dl->AddCircle(c, r, col, 28, thickness);
            float dot_r = thickness * 0.95f;
            dl->AddCircleFilled(ImVec2(c.x, c.y - r * 0.40f), dot_r, col, 10);
            dl->AddLine(ImVec2(c.x, c.y - r * 0.05f), ImVec2(c.x, c.y + r * 0.45f), col, thickness);
        }

        inline void draw_severity_icon(ImDrawList* dl, ImVec2 center, toast_type_t k,
                                        ImU32 color, ImU32 fill, float alpha)
        {
            ImU32 c   = multiply_alpha(color, alpha);
            ImU32 f   = multiply_alpha(fill, alpha);
            float th  = 1.7f;
            switch (k) {
                case toast_type_t::success: draw_check(dl, center, ICON_SIZE, c, th); break;
                case toast_type_t::warning: draw_warning(dl, center, ICON_SIZE + 1.0f, c, f, th); break;
                case toast_type_t::error:   draw_error(dl, center, ICON_SIZE, c, f, th); break;
                case toast_type_t::info:    draw_info(dl, center, ICON_SIZE, c, f, th); break;
            }
        }

        inline void draw_progress_ring(ImDrawList* dl, ImVec2 center, float radius,
                                         float thickness, float progress, ImU32 color, float alpha)
        {
            if (progress < 0.0f) progress = 0.0f;
            if (progress > 1.0f) progress = 1.0f;
            ImU32 track = multiply_alpha(color, alpha * 0.18f);
            dl->AddCircle(center, radius, track, 64, thickness);
            if (progress > 0.0001f) {
                float a0 = -1.5707963f;
                float a1 = a0 + progress * 6.2831853f;
                int seg_count = 64;
                int steps = static_cast<int>(seg_count * progress);
                if (steps < 2) steps = 2;
                dl->PathArcTo(center, radius, a0, a1, steps);
                dl->PathStroke(multiply_alpha(color, alpha), 0, thickness);
            }
        }

        inline float compute_toast_height(const toast_t& t, ImFont* font, float font_size, float text_wrap_w)
        {
            ImVec2 ts = font->CalcTextSizeA(font_size, FLT_MAX, text_wrap_w, t.message.c_str());
            float content_h = ts.y + PADDING * 2.0f;
            float min_h = TOAST_HEIGHT;
            return content_h > min_h ? content_h : min_h;
        }
    }

    inline void push(const std::string& message,
                     toast_type_t type = toast_type_t::info,
                     float duration = 4.0f)
    {
        if (message.empty())
            return;

        std::lock_guard<std::mutex> lk(detail::s_mtx);

        for (const auto& t : detail::s_toasts) {
            if (t.message == message && t.elapsed < DEDUP_WINDOW &&
                !t.dismissing && !t.swipe_dismissing)
                return;
        }

        toast_t nt;
        nt.id = detail::s_next_id++;
        nt.message = message;
        nt.type = type;
        nt.duration = duration;
        detail::s_toasts.push_back(std::move(nt));

        while (static_cast<int>(detail::s_toasts.size()) > MAX_VISIBLE * 2) {
            detail::s_toasts.erase(detail::s_toasts.begin());
        }
    }

    inline void push_with_action(const std::string& message,
                                  toast_type_t type,
                                  action_t action,
                                  float duration = 6.0f)
    {
        if (message.empty())
            return;

        std::lock_guard<std::mutex> lk(detail::s_mtx);

        for (const auto& t : detail::s_toasts) {
            if (t.message == message && t.elapsed < DEDUP_WINDOW &&
                !t.dismissing && !t.swipe_dismissing)
                return;
        }

        toast_t nt;
        nt.id = detail::s_next_id++;
        nt.message = message;
        nt.type = type;
        nt.duration = duration;
        nt.action = std::move(action);
        nt.has_action = !nt.action.label.empty();
        detail::s_toasts.push_back(std::move(nt));

        while (static_cast<int>(detail::s_toasts.size()) > MAX_VISIBLE * 2) {
            detail::s_toasts.erase(detail::s_toasts.begin());
        }
    }

    inline void render()
    {
        std::vector<std::function<void()>> deferred_callbacks;

        {
        std::lock_guard<std::mutex> lk(detail::s_mtx);

        if (detail::s_toasts.empty())
            return;

        ImGuiIO& io = ImGui::GetIO();
        float dt = io.DeltaTime;
        if (dt < 0.0f) dt = 0.0f;
        if (dt > 0.05f) dt = 0.05f;

        const ImVec2 display = io.DisplaySize;
        ImDrawList* dl = ImGui::GetForegroundDrawList();

        ImFont* font_msg    = aida::ui::fonts::body_em();
        ImFont* font_action = aida::ui::fonts::caption();
        if (!font_msg)    font_msg    = ImGui::GetFont();
        if (!font_action) font_action = ImGui::GetFont();
        const float font_size_msg    = font_msg ? font_msg->FontSize : ImGui::GetFontSize();
        const float font_size_action = font_action ? font_action->FontSize : ImGui::GetFontSize();

        const auto& th = aida::ui::resolved();
        const ImU32 text_primary   = th.text_primary;
        const ImU32 text_secondary = th.text_secondary;

        const ImVec2 mouse = io.MousePos;
        const bool mouse_down = ImGui::IsMouseDown(0);
        const bool mouse_clicked = ImGui::IsMouseClicked(0);
        const bool mouse_released = ImGui::IsMouseReleased(0);

        int visible_index = 0;
        std::vector<float> stack_target_y;
        std::vector<float> stack_height;
        stack_target_y.reserve(detail::s_toasts.size());
        stack_height.reserve(detail::s_toasts.size());

        auto compute_action_btn_w = [&](const toast_t& t) -> float {
            if (!t.has_action) return 0.0f;
            ImVec2 lbl_size = font_action->CalcTextSizeA(font_size_action, FLT_MAX, 0.0f, t.action.label.c_str());
            return lbl_size.x + 18.0f + 8.0f;
        };

        for (auto it = detail::s_toasts.rbegin(); it != detail::s_toasts.rend(); ++it) {
            auto& t = *it;
            if (t.dismissing && t.fade_out <= 0.001f) {
                stack_target_y.push_back(0.0f);
                stack_height.push_back(0.0f);
                continue;
            }

            float btn_reserve = compute_action_btn_w(t);
            float content_w = TOAST_WIDTH - PADDING * 2.0f - ICON_BOX - 8.0f - btn_reserve;
            if (content_w < 80.0f) content_w = 80.0f;

            float h = detail::compute_toast_height(t, font_msg, font_size_msg, content_w);
            stack_height.push_back(h);

            if (visible_index >= MAX_VISIBLE) {
                stack_target_y.push_back(display.y);
                continue;
            }

            float ty = display.y - BOTTOM_MARGIN - h;
            for (int p = 0; p < visible_index; ++p) {
                int idx_above = static_cast<int>(stack_height.size()) - 2 - p;
                if (idx_above < 0) break;
                ty -= stack_height[idx_above] + GAP;
            }
            stack_target_y.push_back(ty);
            ++visible_index;
        }

        std::vector<size_t> render_order;
        render_order.reserve(detail::s_toasts.size());
        for (size_t i = 0; i < detail::s_toasts.size(); ++i)
            render_order.push_back(i);

        for (size_t order_i = 0; order_i < render_order.size(); ++order_i) {
            size_t i = render_order[order_i];
            auto& t = detail::s_toasts[i];

            size_t reverse_i = detail::s_toasts.size() - 1 - i;
            float target_y = stack_target_y[reverse_i];
            float h = stack_height[reverse_i];

            float btn_reserve_render = compute_action_btn_w(t);
            float wrap_w = TOAST_WIDTH - PADDING * 2.0f - ICON_BOX - 8.0f - btn_reserve_render;
            if (wrap_w < 80.0f) wrap_w = 80.0f;

            float resting_x = display.x - SIDE_MARGIN - TOAST_WIDTH;

            if (!t.initialized_position) {
                t.current_x = display.x + 12.0f;
                t.current_y = target_y;
                t.target_x = resting_x;
                t.target_y = target_y;
                t.velocity_x = 0.0f;
                t.velocity_y = 0.0f;
                t.initialized_position = true;
            }

            t.target_y = target_y;

            if (!t.dismissing && !t.swipe_dismissing) {
                if (t.intro_progress < 1.0f) {
                    t.intro_progress += dt / SLIDE_DURATION;
                    if (t.intro_progress > 1.0f) t.intro_progress = 1.0f;
                }
                t.target_x = resting_x;
            }

            ImVec2 toast_tl_pre(t.current_x, t.current_y);
            ImVec2 toast_br_pre(t.current_x + TOAST_WIDTH, t.current_y + h);
            bool is_hovered = !t.dismissing && !t.swipe_dismissing &&
                              mouse.x >= toast_tl_pre.x && mouse.x <= toast_br_pre.x &&
                              mouse.y >= toast_tl_pre.y && mouse.y <= toast_br_pre.y;

            float hover_target = is_hovered ? 1.0f : 0.0f;
            t.hover_amount = aida::motion::spring_step(t.hover_amount, hover_target,
                                                        t.hover_velocity,
                                                        aida::motion::spring::balanced, dt);
            if (t.hover_amount < 0.0f) t.hover_amount = 0.0f;
            if (t.hover_amount > 1.0f) t.hover_amount = 1.0f;

            bool click_completed = false;
            if (!t.dismissing && !t.swipe_dismissing) {
                if (mouse_clicked && is_hovered) {
                    t.press_started_inside = true;
                }
                if (mouse_released) {
                    if (t.drag_owned && t.was_dragging) {
                        float threshold_px  = SWIPE_DISMISS_PX;
                        float threshold_pct = TOAST_WIDTH * SWIPE_DISMISS_PCT;
                        float effective = threshold_px < threshold_pct ? threshold_px : threshold_pct;
                        if (t.swipe_offset > effective) {
                            t.swipe_dismissing = true;
                            t.swipe_velocity = 1400.0f;
                            if (t.swipe_offset > 30.0f)
                                t.swipe_velocity = t.swipe_offset * 6.0f + 600.0f;
                        } else {
                            t.swipe_offset = 0.0f;
                        }
                    }
                    else if (t.press_started_inside && is_hovered && !t.drag_owned) {
                        click_completed = true;
                    }
                    t.was_dragging = false;
                    t.drag_owned = false;
                    t.press_started_inside = false;
                }
                else if (!mouse_down) {
                    t.was_dragging = false;
                    t.drag_owned = false;
                    t.press_started_inside = false;
                    t.swipe_offset = 0.0f;
                }
                else if (t.press_started_inside && ImGui::IsMouseDragging(0, 4.0f)) {
                    ImVec2 dd = ImGui::GetMouseDragDelta(0, 4.0f);
                    if (!t.drag_owned) {
                        if (dd.x > 0.0f && dd.x > std::fabs(dd.y)) {
                            t.drag_owned = true;
                        }
                    }
                    if (t.drag_owned) {
                        float drag_dx = dd.x;
                        if (drag_dx < 0.0f) drag_dx = 0.0f;
                        t.was_dragging = true;
                        t.swipe_offset = drag_dx;
                    }
                }
            }

            float timer_scale = 1.0f;
            if (is_hovered || t.was_dragging) timer_scale = HOVER_TIMER_SCALE;
            if (!t.dismissing && !t.swipe_dismissing)
                t.elapsed += dt * timer_scale;

            float remaining = t.duration - t.elapsed;

            if (!t.dismissing && !t.swipe_dismissing && remaining <= 0.0f) {
                t.dismissing = true;
            }

            if (t.swipe_dismissing) {
                t.swipe_offset += t.swipe_velocity * dt;
                t.swipe_velocity += 1200.0f * dt;
                t.dismiss_alpha_decay -= dt / FADE_OUT_TAIL;
                if (t.dismiss_alpha_decay < 0.0f) t.dismiss_alpha_decay = 0.0f;
                if (t.swipe_offset > display.x || t.dismiss_alpha_decay <= 0.001f) {
                    t.fade_out = 0.0f;
                    t.dismissing = true;
                }
            }
            else if (t.dismissing) {
                t.fade_out -= dt / FADE_OUT_TAIL;
                if (t.fade_out < 0.0f) t.fade_out = 0.0f;
            }

            if (!t.swipe_dismissing) {
                t.current_x = aida::motion::spring_step(t.current_x, t.target_x,
                                                         t.velocity_x,
                                                         aida::motion::spring::playful, dt);
            } else {
                t.current_x = t.target_x + t.swipe_offset;
            }
            t.current_y = aida::motion::critically_damped_step(t.current_y, t.target_y,
                                                                t.velocity_y, 0.090f, dt);

            float live_x = t.current_x + (t.swipe_dismissing ? 0.0f : t.swipe_offset);
            ImVec2 tl(live_x, t.current_y);
            ImVec2 br(live_x + TOAST_WIDTH, t.current_y + h);

            float alpha = t.fade_out;
            if (t.swipe_dismissing) alpha *= t.dismiss_alpha_decay;
            float intro_eased = aida::motion::ease::out_quint(t.intro_progress);
            alpha *= intro_eased;
            if (alpha < 0.0f) alpha = 0.0f;
            if (alpha > 1.0f) alpha = 1.0f;

            if (alpha <= 0.001f) {
                continue;
            }

            float lift = t.hover_amount * 2.0f;
            tl.y -= lift;
            br.y -= lift;

            ImU32 sev_color = detail::severity_color(t.type);
            ImU32 sev_soft  = detail::severity_soft(t.type);

            aida::ui::blur::render_drop_shadow(dl, tl, br, TOAST_ROUNDING, 3,
                                                0.40f * alpha,
                                                ImVec2(0.0f, 8.0f + t.hover_amount * 4.0f));

            aida::ui::blur::render_glass_fill(dl, tl, br, TOAST_ROUNDING, alpha);

            ImU32 sev_wash = detail::multiply_alpha(sev_soft, alpha * 0.60f);
            dl->AddRectFilled(tl, br, sev_wash, TOAST_ROUNDING);

            ImU32 hi_top = detail::multiply_alpha(IM_COL32(255, 255, 255, 24), alpha);
            ImU32 hi_bot = detail::multiply_alpha(IM_COL32(255, 255, 255, 0), alpha);
            dl->AddRectFilledMultiColor(tl, ImVec2(br.x, tl.y + h * 0.55f),
                                          hi_top, hi_top, hi_bot, hi_bot);

            aida::ui::blur::render_glass_border(dl, tl, br, TOAST_ROUNDING, alpha, 1.0f);

            ImU32 sev_border = detail::multiply_alpha(sev_color, alpha * 0.45f);
            dl->AddRect(tl, br, sev_border, TOAST_ROUNDING, 0, 1.0f);

            float icon_cx = tl.x + PADDING + ICON_BOX * 0.5f;
            float icon_cy = tl.y + h * 0.5f;
            ImVec2 icon_center(icon_cx, icon_cy);

            float ring_radius = ICON_BOX * 0.5f - 1.0f;
            float progress = 1.0f;
            if (t.duration > 0.0001f) progress = remaining / t.duration;
            if (progress < 0.0f) progress = 0.0f;
            if (progress > 1.0f) progress = 1.0f;

            ImU32 icon_bg = detail::multiply_alpha(sev_color, alpha * 0.16f);
            dl->AddCircleFilled(icon_center, ring_radius - 1.5f, icon_bg, 32);

            detail::draw_progress_ring(dl, icon_center, ring_radius, 1.5f,
                                         progress, sev_color, alpha);

            detail::draw_severity_icon(dl, icon_center, t.type, sev_color, sev_soft, alpha);

            float text_x = icon_cx + ICON_BOX * 0.5f + 10.0f;
            float text_y = tl.y + (h - font_size_msg) * 0.5f;

            ImVec2 msg_size = font_msg->CalcTextSizeA(font_size_msg, FLT_MAX, wrap_w, t.message.c_str());
            if (msg_size.y > font_size_msg + 1.0f) {
                text_y = tl.y + PADDING - 1.0f;
            }

            ImU32 text_col_final = detail::multiply_alpha(text_primary, alpha);
            dl->AddText(font_msg, font_size_msg, ImVec2(text_x, text_y),
                        text_col_final, t.message.c_str(), nullptr, wrap_w);

            if (t.has_action) {
                ImFont* af = font_action;
                float af_size = font_size_action;
                ImVec2 lbl_size = af->CalcTextSizeA(af_size, FLT_MAX, 0.0f, t.action.label.c_str());
                float btn_w = lbl_size.x + 18.0f;
                float btn_h = 24.0f;
                ImVec2 btn_tl(br.x - PADDING - btn_w, tl.y + (h - btn_h) * 0.5f);
                ImVec2 btn_br(btn_tl.x + btn_w, btn_tl.y + btn_h);

                bool btn_hovered = mouse.x >= btn_tl.x && mouse.x <= btn_br.x &&
                                   mouse.y >= btn_tl.y && mouse.y <= btn_br.y &&
                                   !t.dismissing && !t.swipe_dismissing;

                ImU32 btn_fill = detail::multiply_alpha(sev_color, alpha * (btn_hovered ? 0.28f : 0.16f));
                ImU32 btn_border = detail::multiply_alpha(sev_color, alpha * (btn_hovered ? 0.85f : 0.55f));
                ImU32 btn_text = detail::multiply_alpha(sev_color, alpha);

                dl->AddRectFilled(btn_tl, btn_br, btn_fill, btn_h * 0.5f);
                dl->AddRect(btn_tl, btn_br, btn_border, btn_h * 0.5f, 0, 1.0f);
                dl->AddText(af, af_size,
                             ImVec2(btn_tl.x + (btn_w - lbl_size.x) * 0.5f,
                                    btn_tl.y + (btn_h - af_size) * 0.5f),
                             btn_text, t.action.label.c_str());

                if (btn_hovered && click_completed) {
                    t.action_clicked_this_frame = true;
                }
            }

            bool close_hovered = false;
            if (!t.has_action) {
                float close_size = 7.0f;
                float close_pad  = 8.0f;
                ImVec2 close_center(br.x - close_pad - close_size,
                                     tl.y + close_pad + close_size);
                float close_alpha = alpha * (0.30f + 0.65f * t.hover_amount);
                ImU32 close_col = detail::multiply_alpha(text_secondary, close_alpha);
                float ck = close_size * 0.55f;
                dl->AddLine(ImVec2(close_center.x - ck, close_center.y - ck),
                             ImVec2(close_center.x + ck, close_center.y + ck), close_col, 1.5f);
                dl->AddLine(ImVec2(close_center.x - ck, close_center.y + ck),
                             ImVec2(close_center.x + ck, close_center.y - ck), close_col, 1.5f);

                close_hovered = mouse.x >= close_center.x - close_size &&
                                 mouse.x <= close_center.x + close_size &&
                                 mouse.y >= close_center.y - close_size &&
                                 mouse.y <= close_center.y + close_size &&
                                 t.hover_amount > 0.05f &&
                                 !t.dismissing && !t.swipe_dismissing;
            }

            bool body_clicked_for_dismiss = click_completed &&
                                             !t.has_action &&
                                             !close_hovered;

            if (close_hovered && click_completed) {
                t.dismissing = true;
            } else if (body_clicked_for_dismiss) {
                t.dismissing = true;
            }
        }

        for (auto& t : detail::s_toasts) {
            if (t.action_clicked_this_frame && t.action.on_click) {
                deferred_callbacks.push_back(std::move(t.action.on_click));
                t.action.on_click = nullptr;
                t.action_clicked_this_frame = false;
                t.dismissing = true;
            } else {
                t.action_clicked_this_frame = false;
            }
        }

        detail::s_toasts.erase(
            std::remove_if(detail::s_toasts.begin(), detail::s_toasts.end(),
                            [](const toast_t& t) {
                                return (t.dismissing && t.fade_out <= 0.001f) ||
                                       (t.swipe_dismissing && t.dismiss_alpha_decay <= 0.001f);
                            }),
            detail::s_toasts.end());
        }

        for (auto& cb : deferred_callbacks) {
            if (cb) cb();
        }
    }
}
