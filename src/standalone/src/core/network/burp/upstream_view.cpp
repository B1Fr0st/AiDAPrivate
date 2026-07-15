#include "upstream_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#include "../../../preview/network_preview_burp_core.hpp"
#else
#include "upstream_chain.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace upstream {

namespace {

struct hop_buf_t
{
    int  type_idx = 0;
    char host[256] = {};
    int  port = 0;
    char user[128] = {};
    char pass[128] = {};
};

struct view_state_t
{
    char                    new_label[128] = {};
    std::vector<hop_buf_t>  new_hops;
    int                     selected_chain = -1;
    char                    test_host[256] = "example.com";
    int                     test_port = 443;
    std::string             last_test_result;
    std::mutex              status_mtx;
    float                   anim_time = 0.f;
};

view_state_t& vs()
{
    static view_state_t st;
    return st;
}

const char* hop_types[] = { "http_connect", "socks5" };

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = vs();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_upstream_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();

    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Upstream proxy chain");

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + 36.f));
    ImGui::PushID("burp_upstream_form");

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Label:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(280.f);
    ImGui::InputTextWithHint("##up_label", "my-chain", st.new_label, sizeof(st.new_label));
    ImGui::SameLine();
    if (ImGui::Button("Add hop", ImVec2(80.f, 22.f))) {
        st.new_hops.push_back(hop_buf_t{});
    }
    ImGui::SameLine();
    if (ImGui::Button("Save chain", ImVec2(96.f, 22.f))) {
        if (st.new_label[0] != '\0' && !st.new_hops.empty()) {
            upstream_chain_t c;
            c.label = std::string(st.new_label);
            for (const auto& hb : st.new_hops) {
                if (hb.host[0] == '\0' || hb.port <= 0) continue;
                upstream_hop_t h;
                h.type = hop_types[hb.type_idx];
                h.host = hb.host;
                h.port = static_cast<uint16_t>(std::min(65535, std::max(1, hb.port)));
                h.username = hb.user;
                h.password = hb.pass;
                c.hops.push_back(h);
            }
            if (!c.hops.empty()) {
                add_chain(c);
                st.new_label[0] = '\0';
                st.new_hops.clear();
            }
        }
    }

    for (size_t i = 0; i < st.new_hops.size(); ++i) {
        auto& hb = st.new_hops[i];
        ImGui::PushID(static_cast<int>(i));
        ImGui::Text(" Hop %zu  ", i + 1);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(120.f);
        ImGui::Combo("##type", &hb.type_idx, hop_types, IM_ARRAYSIZE(hop_types));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(220.f);
        ImGui::InputTextWithHint("##host", "host", hb.host, sizeof(hb.host));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80.f);
        ImGui::InputInt("##port", &hb.port);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(120.f);
        ImGui::InputTextWithHint("##user", "user", hb.user, sizeof(hb.user));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(120.f);
        ImGui::InputTextWithHint("##pass", "pass", hb.pass, sizeof(hb.pass), ImGuiInputTextFlags_Password);
        ImGui::SameLine();
        if (ImGui::SmallButton("Up")) {
            if (i > 0) std::swap(st.new_hops[i], st.new_hops[i - 1]);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Down")) {
            if (i + 1 < st.new_hops.size()) std::swap(st.new_hops[i], st.new_hops[i + 1]);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Remove")) {
            const auto hop_offset = static_cast<decltype(st.new_hops)::difference_type>(i);
            st.new_hops.erase(st.new_hops.begin() + hop_offset);
            ImGui::PopID();
            break;
        }
        ImGui::PopID();
    }

    ImGui::PopID();

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + 180.f));
    ImGui::BeginChild("##burp_upstream_table", ImVec2(width - 12.f, height - 280.f), false,
                      ImGuiWindowFlags_NoBackground);

    st.anim_time += ImGui::GetIO().DeltaTime;
    auto chains = list_chains();
    uint64_t active = get_active_chain_id();

    ImVec2 table_org = ImGui::GetWindowPos();
    const float row_h = 26.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    dl->AddRectFilled(ImVec2(table_org.x, table_org.y), ImVec2(table_org.x + width - 12.f, table_org.y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    float cx = table_org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "Label / Hops / Actions");

    ImGui::SetCursorPosY(row_h + 4.f);

    int vi = 0;
    for (size_t i = 0; i < chains.size(); ++i) {
        const auto& c = chains[i];
        float ra = ui_anim::render_row_entrance(vi, st.anim_time, 0.012f);
        float r_alpha = alpha * ra;
        float abs_ry = ImGui::GetCursorScreenPos().y;
        if (c.id == active) {
            dl->AddRectFilled(ImVec2(table_org.x, abs_ry),
                              ImVec2(table_org.x + width - 12.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
        } else if (vi & 1) {
            dl->AddRectFilled(ImVec2(table_org.x, abs_ry),
                              ImVec2(table_org.x + width - 12.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
        }
        ImGui::PushID(static_cast<int>(c.id));
        ImGui::InvisibleButton("##up_row", ImVec2(width - 12.f, row_h));

        std::string label_disp = c.label;
        if (c.id == active) label_disp += "  (active)";

        float ty = abs_ry + text_oy;
        float lx = table_org.x + 8.f;
        ImU32 col = aida::ui::with_alpha(c.id == active ? th.success : th.text_primary, r_alpha);
        dl->AddText(ImVec2(lx, ty), col, label_disp.c_str());

        char hops_buf[512] = {};
        std::string h_concat;
        for (size_t k = 0; k < c.hops.size(); ++k) {
            if (k > 0) h_concat += " -> ";
            h_concat += c.hops[k].type;
            h_concat += "://";
            h_concat += c.hops[k].host;
            h_concat += ":";
            h_concat += std::to_string(static_cast<unsigned>(c.hops[k].port));
        }
        _snprintf_s(hops_buf, sizeof(hops_buf), _TRUNCATE, "%s", h_concat.c_str());
        dl->AddText(ImVec2(lx + 220.f, ty),
                    aida::ui::with_alpha(th.text_secondary, r_alpha),
                    hops_buf);

        ImGui::SetCursorScreenPos(ImVec2(table_org.x + width - 12.f - 240.f, abs_ry + (row_h - ImGui::GetFrameHeight()) * 0.5f));
        if (c.id == active) {
            if (ImGui::SmallButton("Deactivate")) set_active_chain(0);
        } else {
            if (ImGui::SmallButton("Activate")) set_active_chain(c.id);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Test")) {
            std::string err;
            bool ok = test_chain(c.id, std::string(st.test_host),
                                 static_cast<uint16_t>(std::max(1, st.test_port)), err);
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "[chain %llu] %s%s%s",
                        static_cast<unsigned long long>(c.id),
                        ok ? "ok" : "FAIL ",
                        ok ? "" : err.c_str(),
                        "");
            std::lock_guard<std::mutex> lk(st.status_mtx);
            st.last_test_result = buf;
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Remove")) {
            remove_chain(c.id);
            ImGui::PopID();
            break;
        }
        ImGui::PopID();
        ++vi;
    }

    if (chains.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "No upstream chains configured. Click 'Add hop' then 'Save chain'.");
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + height - 80.f));
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Test target host:port:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.f);
    ImGui::InputTextWithHint("##up_test_host", "example.com", st.test_host, sizeof(st.test_host));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputInt("##up_test_port", &st.test_port);

    {
        std::lock_guard<std::mutex> lk(st.status_mtx);
        if (!st.last_test_result.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s", st.last_test_result.c_str());
        }
    }

    ImGui::EndChild();
}

}
}
}
