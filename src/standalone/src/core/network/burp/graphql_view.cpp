#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "graphql_view.hpp"
#include "graphql.hpp"
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/fonts.hpp"
#include "../../infra/executor.hpp"
#include "helpers/diag_log.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <string>
#include <utility>

namespace aida {
namespace burp {
namespace graphql_view {

namespace {

state_t s_state;

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::map<std::string, std::string> parse_kv(const char* buf)
{
    std::map<std::string, std::string> out;
    std::string s(buf);
    size_t p = 0;
    while (p < s.size()) {
        size_t eol = s.find('\n', p);
        if (eol == std::string::npos) eol = s.size();
        std::string line = s.substr(p, eol - p);
        p = eol + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find(':');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        size_t kb = k.find_first_not_of(" \t");
        size_t ke = k.find_last_not_of(" \t");
        size_t vb = v.find_first_not_of(" \t");
        size_t ve = v.find_last_not_of(" \t");
        if (kb == std::string::npos || vb == std::string::npos) continue;
        out[k.substr(kb, ke - kb + 1)] = v.substr(vb, ve - vb + 1);
    }
    return out;
}

}

state_t& get_state() { return s_state; }

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    s_state.active = true;

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##gql_root", ImVec2(width, height), false);

    ImGui::SetCursorPos(ImVec2(8.f, 6.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Endpoint:");
    ImGui::SameLine();
    aida::ui::input_text("##gql_ep", s_state.endpoint_buf, sizeof(s_state.endpoint_buf),
                         "https://example.com/graphql", false, ImVec2(360.f, 28.f));
    ImGui::SameLine();
    bool intro = s_state.introspecting.load();
    if (intro) ImGui::BeginDisabled();
    if (aida::ui::button("Introspect", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm, ImVec2(0.f, 28.f))) {
        std::string ep(s_state.endpoint_buf);
        std::map<std::string, std::string> hdrs = parse_kv(s_state.headers_buf);
        ::diag::log_tagged_fmt("graphql_v", "introspect ep='%s'", ep.c_str());
        s_state.introspecting.store(true);
        {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.graphql_view";
            sub.label = "graphql.introspect";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::external_tool;
            sub.priority = 3;
            sub.body = [ep, hdrs]() {
            graphql::gql_schema_t schema;
            std::string raw;
            bool ok = graphql::introspect(ep, hdrs, schema, raw);
            {
                std::lock_guard<std::mutex> lk(s_state.lock);
                s_state.last_schema_raw = raw;
                s_state.schema_status   = ok ? std::string("Schema loaded, ") + std::to_string(schema.types.size()) + " types"
                                              : (std::string("Introspect failed: ") + graphql::last_error());
            }
            ::diag::log_tagged_fmt("graphql_v", "introspect_result ok=%d types=%zu err='%s'",
                ok ? 1 : 0, schema.types.size(), ok ? "" : graphql::last_error().c_str());
            s_state.introspecting.store(false);
        };
            (void)::aida::infra::executor::submit(std::move(sub));
        }
    }
    if (intro) ImGui::EndDisabled();

    ImGui::SetCursorPos(ImVec2(8.f, 38.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Headers (name: value, one per line)");
    ImGui::SetCursorPos(ImVec2(8.f, 56.f));
    ImGui::InputTextMultiline("##gql_hdrs", s_state.headers_buf, sizeof(s_state.headers_buf),
                              ImVec2(width - 16.f, 56.f));

    ImGui::SetCursorPos(ImVec2(8.f, 122.f));
    if (aida::ui::button("Schema", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        ::diag::log_tagged("graphql_v", "tab_switch tab=schema");
        s_state.active_tab = 0;
    }
    ImGui::SameLine();
    if (aida::ui::button("Query", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        ::diag::log_tagged("graphql_v", "tab_switch tab=query");
        s_state.active_tab = 1;
    }
    ImGui::SameLine();
    if (aida::ui::button("History", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        ::diag::log_tagged("graphql_v", "tab_switch tab=history");
        s_state.active_tab = 2;
    }

    ImGui::SameLine(0.f, 24.f);
    {
        std::lock_guard<std::mutex> lk(s_state.lock);
        if (!s_state.schema_status.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s", s_state.schema_status.c_str());
        }
    }

    float content_y = 158.f;
    float content_h = height - content_y - 8.f;

    if (s_state.active_tab == 0) {
        graphql::gql_schema_t schema;
        bool have = graphql::get_cached_schema(s_state.endpoint_buf, schema);
        ImGui::SetCursorPos(ImVec2(0.f, content_y));
        ImGui::BeginChild("##gql_schema", ImVec2(width, content_h), false);
        if (!have || schema.types.empty()) {
            aida::ui::empty_state::config_t cfg;
            cfg.glyph = aida::ui::empty_state::glyph_t::flow;
            cfg.title = "No schema loaded";
            cfg.body  = "Click Introspect to fetch the schema from the endpoint.";
            aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImVec2(width, content_h), cfg);
        } else {
            float left_w = 340.f;
            float right_w = width - left_w - 24.f;
            ImGui::BeginChild("##gql_types", ImVec2(left_w, content_h - 8.f), false);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                               "Types (%zu)", schema.types.size());
            ImGui::Separator();
            for (size_t i = 0; i < schema.types.size(); ++i) {
                const auto& t = schema.types[i];
                char buf[256];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[%s] %s", t.kind.c_str(), t.name.c_str());
                bool sel = (s_state.selected_type_index == static_cast<int>(i));
                if (ImGui::Selectable(buf, sel)) {
                    s_state.selected_type_index = static_cast<int>(i);
                    s_state.selected_field_index = -1;
                }
            }
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("##gql_type_detail", ImVec2(right_w, content_h - 8.f), false);
            if (s_state.selected_type_index >= 0 && s_state.selected_type_index < static_cast<int>(schema.types.size())) {
                const auto& t = schema.types[s_state.selected_type_index];
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                                   "%s %s", t.kind.c_str(), t.name.c_str());
                ImGui::Separator();
                if (!t.enum_values.empty()) {
                    ImGui::Text("Enum values:");
                    for (const auto& e : t.enum_values) ImGui::BulletText("%s", e.c_str());
                }
                if (!t.fields.empty()) {
                    ImGui::Text("Fields:");
                    for (size_t fi = 0; fi < t.fields.size(); ++fi) {
                        const auto& f = t.fields[fi];
                        char fb[512];
                        _snprintf_s(fb, sizeof(fb), _TRUNCATE, "%s: %s", f.name.c_str(), f.type_str.c_str());
                        bool sel = (s_state.selected_field_index == static_cast<int>(fi));
                        if (ImGui::Selectable(fb, sel)) {
                            s_state.selected_field_index = static_cast<int>(fi);
                        }
                        if (!f.args.empty() && sel) {
                            for (const auto& a : f.args)
                                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                                   "    arg %s: %s", a.first.c_str(), a.second.c_str());
                        }
                    }
                    ImGui::Separator();
                    ImGui::SetNextItemWidth(80.f);
                    ImGui::InputInt("Depth", &s_state.depth, 0, 0);
                    if (s_state.depth < 1) s_state.depth = 1;
                    if (s_state.depth > 5) s_state.depth = 5;
                    ImGui::SameLine();
                    if (aida::ui::button("Generate Query", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
                        if (s_state.selected_field_index >= 0 && s_state.selected_field_index < static_cast<int>(t.fields.size())) {
                            std::string q = graphql::build_example_query(schema, t.fields[s_state.selected_field_index].name, s_state.depth);
                            ::diag::log_tagged_fmt("graphql_v", "generate_query field='%s' depth=%d len=%zu",
                                t.fields[s_state.selected_field_index].name.c_str(), s_state.depth, q.size());
                            std::lock_guard<std::mutex> lk(s_state.lock);
                            s_state.query_text = q;
                            s_state.active_tab = 1;
                        }
                    }
                }
            }
            ImGui::EndChild();
        }
        ImGui::EndChild();
    } else if (s_state.active_tab == 1) {
        ImGui::SetCursorPos(ImVec2(0.f, content_y));
        ImGui::BeginChild("##gql_query", ImVec2(width, content_h), false);
        ImFont* mono = aida::ui::fonts::code();
        if (mono) ImGui::PushFont(mono);
        ImGui::Text("Query:");
        {
            std::lock_guard<std::mutex> lk(s_state.lock);
            static char qbuf[64 * 1024];
            std::strncpy(qbuf, s_state.query_text.c_str(), sizeof(qbuf) - 1);
            qbuf[sizeof(qbuf) - 1] = '\0';
            if (ImGui::InputTextMultiline("##gql_q", qbuf, sizeof(qbuf), ImVec2(width - 16.f, content_h * 0.4f))) {
                s_state.query_text = qbuf;
            }
        }
        ImGui::Text("Variables (JSON):");
        {
            std::lock_guard<std::mutex> lk(s_state.lock);
            static char vbuf[16 * 1024];
            std::strncpy(vbuf, s_state.variables_text.c_str(), sizeof(vbuf) - 1);
            vbuf[sizeof(vbuf) - 1] = '\0';
            if (ImGui::InputTextMultiline("##gql_v", vbuf, sizeof(vbuf), ImVec2(width - 16.f, 90.f))) {
                s_state.variables_text = vbuf;
            }
        }
        if (mono) ImGui::PopFont();

        bool sending = s_state.sending.load();
        if (sending) ImGui::BeginDisabled();
        if (aida::ui::button("Send", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            std::string ep(s_state.endpoint_buf);
            std::map<std::string, std::string> hdrs = parse_kv(s_state.headers_buf);
            std::string q, v;
            {
                std::lock_guard<std::mutex> lk(s_state.lock);
                q = s_state.query_text;
                v = s_state.variables_text;
            }
            ::diag::log_tagged_fmt("graphql_v", "send_query ep='%s' query_len=%zu", ep.c_str(), q.size());
            s_state.sending.store(true);
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.graphql_view";
                sub.label = "graphql.send_query";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [ep, hdrs, q, v]() {
                nlohmann::json variables = nlohmann::json::object();
                if (!v.empty()) {
                    auto parsed = nlohmann::json::parse(v, nullptr, false);
                    if (!parsed.is_discarded()) variables = parsed;
                }
                uint64_t t0 = now_ms();
                nlohmann::json resp;
                std::string raw;
                bool ok = graphql::send_query(ep, hdrs, q, variables, resp, raw);
                uint64_t latency = now_ms() - t0;
                {
                    std::lock_guard<std::mutex> lk(s_state.lock);
                    if (ok) {
                        s_state.last_response_raw = resp.dump(2);
                        s_state.last_status       = 200;
                    } else {
                        s_state.last_response_raw = raw.empty() ? graphql::last_error() : raw;
                        s_state.last_status       = 0;
                    }
                    s_state.last_latency_ms = latency;
                    ::diag::log_tagged_fmt("graphql_v", "query_result ok=%d status=%d latency=%llums",
                        ok ? 1 : 0, s_state.last_status, static_cast<unsigned long long>(latency));
                    history_row_t row;
                    row.ts_ms       = now_ms();
                    row.endpoint    = ep;
                    row.status_code = s_state.last_status;
                    row.latency_ms  = latency;
                    row.query_preview = q.substr(0, std::min<size_t>(q.size(), 120));
                    s_state.history.push_back(std::move(row));
                    while (s_state.history.size() > s_state.history_max) s_state.history.pop_front();
                }
                s_state.sending.store(false);
            };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }
        if (sending) ImGui::EndDisabled();
        ImGui::SameLine();
        if (aida::ui::button("Beautify", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            ::diag::log_tagged("graphql_v", "beautify_query");
            std::lock_guard<std::mutex> lk(s_state.lock);
            s_state.query_text = graphql::beautify_query(s_state.query_text);
        }
        ImGui::SameLine();
        if (aida::ui::button("Minify", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            ::diag::log_tagged("graphql_v", "minify_query");
            std::lock_guard<std::mutex> lk(s_state.lock);
            s_state.query_text = graphql::minify_query(s_state.query_text);
        }
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80.f);
        ImGui::InputInt("##gql_batch", &s_state.batch_count, 0, 0);
        if (s_state.batch_count < 1) s_state.batch_count = 1;
        if (s_state.batch_count > 1000) s_state.batch_count = 1000;
        ImGui::SameLine();
        if (aida::ui::button("Batch", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("graphql_v", "batch_query count=%d", s_state.batch_count);
            std::lock_guard<std::mutex> lk(s_state.lock);
            s_state.query_text = graphql::build_batched_query(s_state.query_text, static_cast<size_t>(s_state.batch_count));
        }

        ImGui::Separator();
        ImGui::Text("Response (HTTP %d, %llu ms):", s_state.last_status, static_cast<unsigned long long>(s_state.last_latency_ms));
        {
            std::lock_guard<std::mutex> lk(s_state.lock);
            if (mono) ImGui::PushFont(mono);
            ImGui::InputTextMultiline("##gql_resp", s_state.last_response_raw.data(),
                                       s_state.last_response_raw.size() + 1,
                                       ImVec2(width - 16.f, content_h - content_h * 0.4f - 220.f),
                                        ImGuiInputTextFlags_ReadOnly);
            if (mono) ImGui::PopFont();
        }
        ImGui::EndChild();
    } else {
        ImGui::SetCursorPos(ImVec2(0.f, content_y));
        ImGui::BeginChild("##gql_hist", ImVec2(width, content_h), false);
        std::lock_guard<std::mutex> lk(s_state.lock);
        for (const auto& row : s_state.history) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%llu ms | HTTP %d | %s | %s",
                               static_cast<unsigned long long>(row.latency_ms), row.status_code,
                               row.endpoint.c_str(), row.query_preview.c_str());
        }
        ImGui::EndChild();
    }

    ImGui::EndChild();
}

}
}
}
