#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifdef small
#undef small
#endif

#include "comparer_view.hpp"
#include "comparer.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "helpers/diag_log.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/components.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace comparer_view {

namespace {

struct view_state_t
{
    uint64_t selected_a = 0;
    uint64_t selected_b = 0;
    int      mode_idx = 3;
    char     add_label[128] = "Slot";
    char     add_file_path[1024] = {};
    char     paste_buffer[65536] = {};

    std::vector<aida::burp::comparer::diff_block_t> cached_blocks;
    aida::burp::comparer::diff_stats_t              cached_stats;
    aida::burp::comparer::slot_t                    cached_a;
    aida::burp::comparer::slot_t                    cached_b;
    bool                                            cached_valid = false;
    int                                             cached_mode_idx = -1;
    uint64_t                                        cached_ids[2] = {0, 0};

    float                                           sync_scroll_y = 0.f;
};

static view_state_t g_view_state;

static aida::burp::comparer::diff_mode_t mode_from_index(int idx)
{
    switch (idx) {
        case 0: return aida::burp::comparer::diff_mode_t::bytes;
        case 1: return aida::burp::comparer::diff_mode_t::chars;
        case 2: return aida::burp::comparer::diff_mode_t::words;
        case 3: return aida::burp::comparer::diff_mode_t::lines;
    }
    return aida::burp::comparer::diff_mode_t::lines;
}

static void ensure_diff()
{
    if (g_view_state.selected_a == 0 || g_view_state.selected_b == 0) {
        g_view_state.cached_valid = false;
        return;
    }
    if (g_view_state.cached_valid &&
        g_view_state.cached_ids[0] == g_view_state.selected_a &&
        g_view_state.cached_ids[1] == g_view_state.selected_b &&
        g_view_state.cached_mode_idx == g_view_state.mode_idx) {
        return;
    }
    aida::burp::comparer::slot_t a;
    aida::burp::comparer::slot_t b;
    if (!aida::burp::comparer::get_slot(g_view_state.selected_a, a) ||
        !aida::burp::comparer::get_slot(g_view_state.selected_b, b)) {
        g_view_state.cached_valid = false;
        return;
    }
    g_view_state.cached_blocks = aida::burp::comparer::compute_diff_with_stats(
        g_view_state.selected_a, g_view_state.selected_b,
        mode_from_index(g_view_state.mode_idx),
        g_view_state.cached_stats);
    g_view_state.cached_a = std::move(a);
    g_view_state.cached_b = std::move(b);
    g_view_state.cached_valid = true;
    g_view_state.cached_ids[0] = g_view_state.selected_a;
    g_view_state.cached_ids[1] = g_view_state.selected_b;
    g_view_state.cached_mode_idx = g_view_state.mode_idx;
}

static ImU32 block_color(const aida::ui::theme_t& th, aida::burp::comparer::diff_block_t::kind_t k, float alpha)
{
    switch (k) {
        case aida::burp::comparer::diff_block_t::kind_t::equal:   return aida::ui::with_alpha(th.panel_header, alpha * 0.0f);
        case aida::burp::comparer::diff_block_t::kind_t::insert:  return aida::ui::with_alpha(th.success, alpha * 0.30f);
        case aida::burp::comparer::diff_block_t::kind_t::delete_: return aida::ui::with_alpha(th.error,   alpha * 0.30f);
        case aida::burp::comparer::diff_block_t::kind_t::replace: return aida::ui::with_alpha(th.warning, alpha * 0.30f);
    }
    return 0;
}

static void render_pane(const char* id, const std::vector<uint8_t>& data,
                         const std::vector<aida::burp::comparer::diff_block_t>& blocks,
                         bool is_a, ImVec2 sz, float alpha, const aida::ui::theme_t& th)
{
    ImGui::BeginChild(id, sz, true, ImGuiWindowFlags_HorizontalScrollbar);
    if (!data.empty()) {
        std::string text(reinterpret_cast<const char*>(data.data()), data.size());
        ImVec2 cursor_screen = ImGui::GetCursorScreenPos();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        float line_h = ImGui::GetTextLineHeight();
        const float gutter = 50.f;
        float text_x = cursor_screen.x + gutter;

        std::vector<size_t> line_starts;
        line_starts.push_back(0);
        for (size_t i = 0; i < text.size(); ++i) {
            if (text[i] == '\n') line_starts.push_back(i + 1);
        }

        float max_text_x = 0.f;
        for (size_t li = 0; li < line_starts.size(); ++li) {
            size_t ls = line_starts[li];
            size_t le = (li + 1 < line_starts.size()) ? line_starts[li + 1] : text.size();
            size_t inv_end = le;
            if (inv_end > ls && text[inv_end - 1] == '\n') inv_end--;
            std::string line_view = text.substr(ls, inv_end - ls);
            float ly = cursor_screen.y + static_cast<float>(li) * line_h;

            float tw = ImGui::CalcTextSize(line_view.c_str()).x;
            if (tw > max_text_x) max_text_x = tw;

            for (const auto& bk : blocks) {
                if (bk.kind == aida::burp::comparer::diff_block_t::kind_t::equal) continue;
                size_t bs = is_a ? bk.a_start : bk.b_start;
                size_t be = is_a ? bk.a_end   : bk.b_end;
                if (be <= ls || bs >= le) continue;
                size_t ov_start = (bs > ls) ? bs : ls;
                size_t ov_end   = (be < le) ? be : le;
                if (ov_start >= ov_end) continue;
                std::string before = text.substr(ls, ov_start - ls);
                float x_offset = ImGui::CalcTextSize(before.c_str()).x;
                std::string match = text.substr(ov_start, ov_end - ov_start);
                float x_len = ImGui::CalcTextSize(match.c_str()).x;
                ImU32 col = block_color(th, bk.kind, alpha);
                if (col != 0) {
                    dl->AddRectFilled(
                        ImVec2(text_x + x_offset, ly),
                        ImVec2(text_x + x_offset + std::max(2.f, x_len), ly + line_h),
                        col, 2.f);
                }
            }

            char ln_buf[16];
            snprintf(ln_buf, sizeof(ln_buf), "%4zu", li + 1);
            dl->AddText(ImVec2(cursor_screen.x, ly),
                aida::ui::with_alpha(th.text_dim, alpha * 0.7f), ln_buf);

            dl->AddText(ImVec2(text_x, ly),
                aida::ui::with_alpha(th.text_primary, alpha), line_view.c_str());
        }
        ImGui::Dummy(ImVec2(gutter + max_text_x + 16.f, static_cast<float>(line_starts.size()) * line_h));
    }
    if (is_a) {
        if (ImGui::IsWindowHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            g_view_state.sync_scroll_y = ImGui::GetScrollY();
        } else {
            float syn = g_view_state.sync_scroll_y;
            if (std::fabs(ImGui::GetScrollY() - syn) > 0.5f) {
                ImGui::SetScrollY(syn);
            }
        }
    } else {
        float syn = g_view_state.sync_scroll_y;
        if (std::fabs(ImGui::GetScrollY() - syn) > 0.5f) {
            ImGui::SetScrollY(syn);
        }
    }
    ImGui::EndChild();
}

}

void initialize()
{
    ::diag::log_tagged("comparer_v", "initialize");
}

void shutdown()
{
    ::diag::log_tagged("comparer_v", "shutdown");
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##cmp_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    float bar_h = 80.f;
    ImGui::BeginChild("##cmp_bar", ImVec2(width, bar_h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Label");
    ImGui::SameLine();
    ImGui::PushItemWidth(160.f);
    ImGui::InputText("##cmp_lbl", g_view_state.add_label, sizeof(g_view_state.add_label));
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (aida::ui::button("Paste -> slot", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        const char* cb = ImGui::GetClipboardText();
        if (cb && cb[0]) {
            size_t n = strlen(cb);
            std::vector<uint8_t> data(cb, cb + n);
            aida::burp::comparer::add_slot_from_bytes(g_view_state.add_label, data, "clipboard");
            ::diag::log_tagged_fmt("comparer_v", "paste_slot label='%s' bytes=%zu", g_view_state.add_label, n);
        }
    }
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "File");
    ImGui::SameLine();
    ImGui::PushItemWidth(width - 700.f > 200.f ? width - 700.f : 200.f);
    ImGui::InputText("##cmp_file", g_view_state.add_file_path, sizeof(g_view_state.add_file_path));
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (aida::ui::button("Add file", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        if (g_view_state.add_file_path[0]) {
            ::diag::log_tagged_fmt("comparer_v", "add_file_slot label='%s' path='%s'",
                g_view_state.add_label, g_view_state.add_file_path);
            aida::burp::comparer::add_slot_from_file(g_view_state.add_label, g_view_state.add_file_path);
        }
    }
    ImGui::SameLine();
    if (aida::ui::button("Clear slots", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        ::diag::log_tagged("comparer_v", "clear_slots");
        aida::burp::comparer::clear_slots();
        g_view_state.selected_a = 0;
        g_view_state.selected_b = 0;
        g_view_state.cached_valid = false;
    }

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Paste raw text");
    ImGui::SameLine();
    ImGui::PushItemWidth(width - 280.f);
    ImGui::InputText("##cmp_paste", g_view_state.paste_buffer, sizeof(g_view_state.paste_buffer));
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (aida::ui::button("Add text", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        if (g_view_state.paste_buffer[0]) {
            size_t n = strlen(g_view_state.paste_buffer);
            std::vector<uint8_t> data(g_view_state.paste_buffer, g_view_state.paste_buffer + n);
            ::diag::log_tagged_fmt("comparer_v", "add_text_slot label='%s' bytes=%zu", g_view_state.add_label, n);
            aida::burp::comparer::add_slot_from_bytes(g_view_state.add_label, data, "manual");
            g_view_state.paste_buffer[0] = 0;
        }
    }

    ImGui::EndChild();

    float sel_y = bar_h + 4.f;
    float sel_h = 36.f;
    ImGui::SetCursorPos(ImVec2(0.f, sel_y));
    ImGui::BeginChild("##cmp_sel", ImVec2(width, sel_h), false, ImGuiWindowFlags_NoBackground);

    auto slots = aida::burp::comparer::list_slots();

    auto draw_combo = [&](const char* lbl, uint64_t* sel) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "%s", lbl);
        ImGui::SameLine();
        std::string cur = "(none)";
        for (const auto& s : slots) if (s.id == *sel) { cur = s.label + " #" + std::to_string(s.id); break; }
        ImGui::PushItemWidth(220.f);
        if (ImGui::BeginCombo((std::string("##cmp_") + lbl).c_str(), cur.c_str())) {
            for (const auto& s : slots) {
                std::string lab = s.label + " #" + std::to_string(s.id) +
                    " (" + std::to_string(s.data.size()) + " B)";
                bool is_sel = (s.id == *sel);
                if (ImGui::Selectable(lab.c_str(), is_sel)) {
                    *sel = s.id;
                    g_view_state.cached_valid = false;
                }
            }
            ImGui::EndCombo();
        }
        ImGui::PopItemWidth();
    };

    draw_combo("A", &g_view_state.selected_a);
    ImGui::SameLine();
    draw_combo("B", &g_view_state.selected_b);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Mode");
    ImGui::SameLine();
    const char* modes[] = { "bytes", "chars", "words", "lines" };
    ImGui::PushItemWidth(100.f);
    if (ImGui::Combo("##cmp_mode", &g_view_state.mode_idx, modes, 4)) {
        g_view_state.cached_valid = false;
        ::diag::log_tagged_fmt("comparer_v", "mode_changed mode=%s", modes[g_view_state.mode_idx]);
    }
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (aida::ui::button("Swap", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
        ::diag::log_tagged_fmt("comparer_v", "swap_slots a=%llu b=%llu",
            static_cast<unsigned long long>(g_view_state.selected_a),
            static_cast<unsigned long long>(g_view_state.selected_b));
        std::swap(g_view_state.selected_a, g_view_state.selected_b);
        g_view_state.cached_valid = false;
    }

    ImGui::EndChild();

    float stats_y = sel_y + sel_h + 4.f;
    float stats_h = 28.f;
    ImGui::SetCursorPos(ImVec2(0.f, stats_y));
    ImGui::BeginChild("##cmp_stats", ImVec2(width, stats_h), false, ImGuiWindowFlags_NoBackground);

    {
        bool was_valid = g_view_state.cached_valid;
        ensure_diff();
        if (!was_valid && g_view_state.cached_valid) {
            const auto& dst = g_view_state.cached_stats;
            ::diag::log_tagged_fmt("comparer_v", "diff_computed a=%llu b=%llu mode=%d blocks_eq=%zu ins=%zu del=%zu rep=%zu",
                static_cast<unsigned long long>(g_view_state.selected_a),
                static_cast<unsigned long long>(g_view_state.selected_b),
                g_view_state.mode_idx,
                dst.equal_runs, dst.insert_runs, dst.delete_runs, dst.replace_runs);
        }
    }
    if (g_view_state.cached_valid) {
        const auto& st = g_view_state.cached_stats;
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "A=%zuB  B=%zuB  equal_runs=%zu insert_runs=%zu delete_runs=%zu replace_runs=%zu  "
            "bytes equal=%zu inserted=%zu deleted=%zu replaced=%zu%s",
            st.a_size, st.b_size,
            st.equal_runs, st.insert_runs, st.delete_runs, st.replace_runs,
            st.bytes_equal, st.bytes_inserted, st.bytes_deleted, st.bytes_replaced,
            st.truncated ? "  (truncated)" : "");
    } else {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Select two slots above to compute the diff.");
    }
    ImGui::EndChild();

    float panes_y = stats_y + stats_h + 4.f;
    float panes_h = height - panes_y - 8.f;
    float pane_w = (width - 8.f) * 0.5f;

    if (g_view_state.cached_valid) {
        ImGui::SetCursorPos(ImVec2(0.f, panes_y));
        render_pane("##cmp_pane_a", g_view_state.cached_a.data, g_view_state.cached_blocks, true,
                    ImVec2(pane_w, panes_h), alpha, th);
        ImGui::SetCursorPos(ImVec2(pane_w + 8.f, panes_y));
        render_pane("##cmp_pane_b", g_view_state.cached_b.data, g_view_state.cached_blocks, false,
                    ImVec2(pane_w, panes_h), alpha, th);
    } else {
        ImGui::SetCursorPos(ImVec2(0.f, panes_y));
        ImVec2 rp = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::layers;
        cfg.title = "Comparer";
        cfg.body  = "Add two slots from clipboard, file, or text, then select A and B to compute a Myers diff.";
        aida::ui::empty_state::render(rp, ImVec2(width, panes_h), cfg);
        ImGui::Dummy(ImVec2(0.f, 0.f));
    }

    ImGui::EndChild();
}

}
}
}
