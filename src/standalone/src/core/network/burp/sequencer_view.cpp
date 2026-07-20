#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifdef small
#undef small
#endif

#include "sequencer_view.hpp"
#include "sequencer.hpp"
#include "../human_request_editor.hpp"
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
#include "../../ui/design_system.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_executor.hpp"
#else
#include "../../infra/executor.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace sequencer_view {

namespace {

struct view_state_t
{
    char    url[1024]            = "https://example.com/login";
    bool    use_tls              = true;
    char    host[256]            = "example.com";
    int     port                 = 443;
    char    extract_regex[512]   = "Set-Cookie:\\s*session=([A-Za-z0-9]+)";
    int     capture_group        = 1;
    int     target_count         = 200;
    int     concurrency          = 4;
    int     throttle_ms          = 0;
    char    name[128]            = "Collection";
    char    raw_request[8192]    = {};
    bool    use_raw_request      = false;

    uint64_t selected_id   = 0;
    std::vector<aida::burp::sequencer::collection_status_t> cached;
    std::uint64_t cached_generation = 0;
    aida::burp::sequencer::capacity_snapshot_t capacity;
    std::shared_ptr<const std::string> start_error = std::make_shared<const std::string>();
    bool delete_review_requested = false;
    std::uint64_t reviewed_delete_id = 0;
    std::uint64_t reviewed_delete_started_ms = 0;
    std::uint64_t reviewed_delete_instance_revision = 0;
    std::string reviewed_delete_name;

    aida::burp::sequencer::analysis_result_t last_analysis{};
    bool                                     analysis_valid = false;
    uint64_t                                 analysis_for_id = 0;
    std::atomic<std::uint64_t>               started_id{0};
    std::shared_ptr<const std::pair<std::uint64_t, aida::burp::sequencer::analysis_result_t>> analysis_publication =
        std::make_shared<const std::pair<std::uint64_t, aida::burp::sequencer::analysis_result_t>>();
};

static view_state_t g_view_state;

static void publish_view_error(std::string error)
{
    std::atomic_store_explicit(&g_view_state.start_error,
        std::make_shared<const std::string>(std::move(error)), std::memory_order_release);
}

static bool submit_view_task(aida::infra::executor::submission_t submission, const char* action)
{
    try {
        const auto result = aida::infra::executor::submit(std::move(submission));
        if (result.submitted) return true;
        publish_view_error(std::string(action) + " was rejected by the executor");
    } catch (const std::exception& exception) {
        publish_view_error(std::string(action) + " failed: " + exception.what());
    } catch (...) {
        publish_view_error(std::string(action) + " failed with an unknown exception");
    }
    return false;
}

static void start_pressed()
{
    aida::burp::sequencer::collection_config_t cfg;
    cfg.url      = g_view_state.url;
    cfg.use_tls  = g_view_state.use_tls;
    cfg.host     = g_view_state.host;
    cfg.port     = static_cast<uint16_t>(g_view_state.port);
    cfg.extract_regex = g_view_state.extract_regex;
    cfg.capture_group = g_view_state.capture_group;
    cfg.target_count = static_cast<size_t>(std::max(1, g_view_state.target_count));
    cfg.concurrency  = static_cast<size_t>(std::max(1, g_view_state.concurrency));
    cfg.throttle_ms  = static_cast<size_t>(std::max(0, g_view_state.throttle_ms));
    cfg.name = g_view_state.name;
    if (g_view_state.use_raw_request && g_view_state.raw_request[0] != 0) {
        size_t n = strlen(g_view_state.raw_request);
        cfg.raw_request.assign(g_view_state.raw_request, g_view_state.raw_request + n);
    }
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "burp.sequencer_view";
    submission.label = "sequencer.start_collection";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.priority = 3;
    submission.body = [cfg = std::move(cfg)]() {
        const std::uint64_t id = aida::burp::sequencer::start_collection(cfg);
        if (id != 0) {
            g_view_state.started_id.store(id, std::memory_order_release);
            std::atomic_store_explicit(&g_view_state.start_error,
                std::make_shared<const std::string>(), std::memory_order_release);
        } else {
            std::atomic_store_explicit(&g_view_state.start_error,
                std::make_shared<const std::string>(aida::burp::sequencer::last_error()),
                std::memory_order_release);
        }
    };
    static_cast<void>(submit_view_task(std::move(submission), "Start collection"));
}

}

void initialize()
{
    ::diag::log_tagged("sequencer_v", "initialize");
}

void shutdown()
{
    ::diag::log_tagged("sequencer_v", "shutdown");
}

bool open_new_collection_with(const std::string& url, const std::string& host,
                              std::uint16_t port, bool use_tls,
                              const std::string& raw_request, std::string& reason)
{
    if (url.empty() || host.empty() || port == 0 || raw_request.empty()) {
        reason = "Sequencer requires a URL, host, port, and non-empty request.";
        return false;
    }
    std::snprintf(g_view_state.url, sizeof(g_view_state.url), "%s", url.c_str());
    std::snprintf(g_view_state.host, sizeof(g_view_state.host), "%s", host.c_str());
    g_view_state.port = port;
    g_view_state.use_tls = use_tls;
    const std::size_t count = (std::min)(raw_request.size(), sizeof(g_view_state.raw_request) - 1U);
    std::memcpy(g_view_state.raw_request, raw_request.data(), count);
    g_view_state.raw_request[count] = '\0';
    g_view_state.use_raw_request = true;
    reason.clear();
    return true;
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    const std::uint64_t started_id = g_view_state.started_id.exchange(0, std::memory_order_acq_rel);
    if (started_id != 0) g_view_state.selected_id = started_id;
    const std::uint64_t registry_generation = aida::burp::sequencer::registry_generation();
    if (g_view_state.cached_generation != registry_generation) {
        auto snapshot = aida::burp::sequencer::snapshot_collections();
        g_view_state.cached_generation = snapshot.generation;
        g_view_state.capacity = snapshot.capacity;
        g_view_state.cached = std::move(snapshot.collections);
        if (g_view_state.selected_id != 0) {
            const auto selected = std::find_if(g_view_state.cached.begin(), g_view_state.cached.end(),
                [&](const auto& collection) { return collection.id == g_view_state.selected_id; });
            if (selected == g_view_state.cached.end()) {
                g_view_state.selected_id = 0;
                g_view_state.analysis_valid = false;
                g_view_state.analysis_for_id = 0;
            }
        }
    }
    const auto analysis = std::atomic_load_explicit(&g_view_state.analysis_publication,
        std::memory_order_acquire);
    if (analysis->first != 0 && analysis->first != g_view_state.analysis_for_id) {
        g_view_state.analysis_for_id = analysis->first;
        g_view_state.last_analysis = analysis->second;
        g_view_state.analysis_valid = analysis->second.valid;
    }

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##seq_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    float cfg_w = width * 0.40f;
    float right_x = cfg_w + 8.f;
    float right_w = width - right_x;

    ImGui::SetCursorPos(ImVec2(0.f, 0.f));
    ImGui::BeginChild("##seq_cfg", ImVec2(cfg_w, height), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
        "Collection");
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Name");
    ImGui::SameLine();
    ImGui::PushItemWidth(cfg_w - 100.f);
    ImGui::InputText("##s_name", g_view_state.name, sizeof(g_view_state.name));
    ImGui::PopItemWidth();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "URL");
    ImGui::PushItemWidth(cfg_w - 24.f);
    ImGui::InputText("##s_url", g_view_state.url, sizeof(g_view_state.url));
    ImGui::PopItemWidth();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Host");
    ImGui::SameLine();
    ImGui::PushItemWidth(cfg_w - 240.f);
    ImGui::InputText("##s_host", g_view_state.host, sizeof(g_view_state.host));
    ImGui::PopItemWidth();
    ImGui::SameLine();
    ImGui::PushItemWidth(60.f);
    ImGui::InputInt("##s_port", &g_view_state.port);
    ImGui::PopItemWidth();
    ImGui::SameLine();
    ImGui::Checkbox("TLS", &g_view_state.use_tls);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Extract regex");
    ImGui::PushItemWidth(cfg_w - 24.f);
    ImGui::InputText("##s_regex", g_view_state.extract_regex, sizeof(g_view_state.extract_regex));
    ImGui::PopItemWidth();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Capture group");
    ImGui::SameLine();
    ImGui::PushItemWidth(80.f);
    ImGui::InputInt("##s_grp", &g_view_state.capture_group);
    ImGui::PopItemWidth();
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Target");
    ImGui::SameLine();
    ImGui::PushItemWidth(80.f);
    ImGui::InputInt("##s_tgt", &g_view_state.target_count);
    ImGui::PopItemWidth();
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Threads");
    ImGui::SameLine();
    ImGui::PushItemWidth(60.f);
    ImGui::InputInt("##s_conc", &g_view_state.concurrency);
    ImGui::PopItemWidth();
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Throttle ms");
    ImGui::SameLine();
    ImGui::PushItemWidth(80.f);
    ImGui::InputInt("##s_thr", &g_view_state.throttle_ms);
    ImGui::PopItemWidth();

    ImGui::Checkbox("Use raw request", &g_view_state.use_raw_request);
    static network_view::human_request_editor::fixed_state_t request_editor;
    network_view::human_request_editor::render_result_t request_editor_result;
    if (g_view_state.use_raw_request) {
        network_view::human_request_editor::render_config_t request_config;
        request_config.stable_id = "sequencer-raw-request";
        request_config.size = ImVec2(cfg_w - 24.f, 120.f);
        request_config.max_bytes = sizeof(g_view_state.raw_request) - 1;
        request_editor_result = network_view::human_request_editor::render_fixed(
            request_editor, "sequencer.raw-request", g_view_state.raw_request,
            request_config);
    }

    const bool collection_capacity_full =
        g_view_state.capacity.collection_count >= g_view_state.capacity.collection_limit;
    const bool sample_capacity_full =
        g_view_state.capacity.retained_sample_bytes >= g_view_state.capacity.retained_sample_limit;
    const bool request_unready = g_view_state.use_raw_request &&
        (!request_editor_result.valid || request_editor_result.has_unapplied_pretty);
    ImGui::BeginDisabled(collection_capacity_full || sample_capacity_full || request_unready);
    if (aida::ui::button("Start", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        start_pressed();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (g_view_state.selected_id != 0) {
        if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("sequencer_v", "stop_collection id=%llu", static_cast<unsigned long long>(g_view_state.selected_id));
            const std::uint64_t id = g_view_state.selected_id;
            aida::infra::executor::submission_t submission;
            submission.owner_subsystem = "burp.sequencer_view";
            submission.label = "sequencer.stop_collection";
            submission.thread_class = "bounded_task";
            submission.domain = aida::infra::executor::domain_t::external_tool;
            submission.priority = 3;
            submission.body = [id]() { aida::burp::sequencer::stop_collection(id); };
            static_cast<void>(submit_view_task(std::move(submission), "Stop collection"));
        }
        ImGui::SameLine();
        if (aida::ui::button("Analyze", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("sequencer_v", "analyze_collection id=%llu", static_cast<unsigned long long>(g_view_state.selected_id));
            const std::uint64_t id = g_view_state.selected_id;
            aida::infra::executor::submission_t submission;
            submission.owner_subsystem = "burp.sequencer_view";
            submission.label = "sequencer.analyze_collection";
            submission.thread_class = "bounded_task";
            submission.domain = aida::infra::executor::domain_t::external_tool;
            submission.priority = 3;
            submission.body = [id]() {
                auto publication = std::make_shared<const std::pair<std::uint64_t,
                    aida::burp::sequencer::analysis_result_t>>(id,
                    aida::burp::sequencer::analyze(id));
                std::atomic_store_explicit(&g_view_state.analysis_publication,
                    std::move(publication), std::memory_order_release);
            };
            static_cast<void>(submit_view_task(std::move(submission), "Analyze collection"));
        }
        ImGui::SameLine();
        if (aida::ui::button("Delete", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            const auto selected = std::find_if(g_view_state.cached.begin(), g_view_state.cached.end(),
                [&](const auto& collection) { return collection.id == g_view_state.selected_id; });
            if (selected == g_view_state.cached.end()) {
                publish_view_error("The selected collection changed; select it again before deletion");
            } else {
                g_view_state.reviewed_delete_id = selected->id;
                g_view_state.reviewed_delete_started_ms = selected->started_ms;
                g_view_state.reviewed_delete_instance_revision = selected->instance_revision;
                g_view_state.reviewed_delete_name = selected->name.empty() ? selected->url : selected->name;
                g_view_state.delete_review_requested = true;
            }
        }
    }

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
        "Collections  %zu / %zu    Retained %.1f / %.1f MiB",
        g_view_state.capacity.collection_count, g_view_state.capacity.collection_limit,
        static_cast<double>(g_view_state.capacity.retained_sample_bytes) / (1024.0 * 1024.0),
        static_cast<double>(g_view_state.capacity.retained_sample_limit) / (1024.0 * 1024.0));
    const auto start_error = std::atomic_load_explicit(&g_view_state.start_error,
        std::memory_order_acquire);
    if (collection_capacity_full || sample_capacity_full || (start_error && !start_error->empty())) {
        const std::string message = collection_capacity_full
            ? "Collection capacity reached. Delete a retained collection before starting another."
            : sample_capacity_full
                ? "Retained sample capacity reached. Delete a collection before starting another."
                : *start_error;
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.error, alpha)),
            "%s", message.c_str());
    }

    if (ImGui::BeginTable("##s_clist", 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("ID",       ImGuiTableColumnFlags_WidthFixed, 50.f);
        ImGui::TableSetupColumn("Name",     ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Progress", ImGuiTableColumnFlags_WidthFixed, 100.f);
        ImGui::TableSetupColumn("State",    ImGuiTableColumnFlags_WidthFixed, 70.f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(g_view_state.cached.size()));
        while (clipper.Step())
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& c = g_view_state.cached[static_cast<std::size_t>(row)];
            ImGui::TableNextRow();
            bool sel = (c.id == g_view_state.selected_id);
            ImGui::TableSetColumnIndex(0);
            char idbuf[32];
            snprintf(idbuf, sizeof(idbuf), "%llu", static_cast<unsigned long long>(c.id));
            if (ImGui::Selectable(idbuf, sel, ImGuiSelectableFlags_SpanAllColumns)) {
                g_view_state.selected_id = c.id;
                g_view_state.analysis_valid = false;
                ::diag::log_tagged_fmt("sequencer_v", "collection_selected id=%llu name='%s'",
                    static_cast<unsigned long long>(c.id),
                    c.name.empty() ? c.url.c_str() : c.name.c_str());
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(c.name.empty() ? c.url.c_str() : c.name.c_str());
            ImGui::TableSetColumnIndex(2);
            char pbuf[32];
            snprintf(pbuf, sizeof(pbuf), "%zu/%zu", c.collected, c.target);
            ImGui::TextUnformatted(pbuf);
            ImGui::TableSetColumnIndex(3);
            const char* st = c.running ? "RUN" : (c.error ? "ERR" : "DONE");
            ImU32 col = c.running
                ? aida::ui::with_alpha(th.accent_u32, alpha)
                : (c.error ? aida::ui::with_alpha(th.error, alpha)
                           : aida::ui::with_alpha(th.success, alpha));
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col), "%s", st);
        }
        ImGui::EndTable();
    }

    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(right_x, 0.f));
    ImGui::BeginChild("##seq_right", ImVec2(right_w, height), false, ImGuiWindowFlags_NoBackground);

    if (g_view_state.selected_id == 0) {
        ImVec2 rp = ImGui::GetCursorScreenPos();
        ImVec2 rs = ImVec2(right_w, height - 32.f);
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::flask;
        cfg.title = "No collection selected";
        cfg.body  = "Configure a URL and an extraction regex on the left, click Start, then Analyze.";
        aida::ui::empty_state::render(rp, rs, cfg);
    } else {
        auto st = aida::burp::sequencer::status(g_view_state.selected_id);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "Collection %llu  '%s'  collected=%zu/%zu  running=%d",
            static_cast<unsigned long long>(st.id),
            st.name.empty() ? st.url.c_str() : st.name.c_str(),
            st.collected, st.target,
            st.running ? 1 : 0);
        if (!st.error_message.empty()) {
            ::diag::log_tagged_fmt("sequencer_v", "collection_error id=%llu msg='%s'",
                static_cast<unsigned long long>(st.id), st.error_message.c_str());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.error, alpha)),
                "Error: %s", st.error_message.c_str());
        }

        if (g_view_state.analysis_valid && g_view_state.analysis_for_id == g_view_state.selected_id) {
            const auto& a = g_view_state.last_analysis;
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                "Verdict: %s", a.verdict.c_str());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "FIPS 140-2: %s    samples=%zu length_mode=%zu",
                a.passes_fips_140_2 ? "PASS" : "FAIL",
                a.samples_count, a.token_length_mode);

            if (ImGui::BeginTable("##seq_stats", 2,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableSetupColumn("Metric");
                ImGui::TableSetupColumn("Value");
                ImGui::TableHeadersRow();

                auto row = [&](const char* k, const char* fmt, double v) {
                    char buf[64];
                    if (std::isnan(v)) snprintf(buf, sizeof(buf), "NaN");
                    else                snprintf(buf, sizeof(buf), fmt, v);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(k);
                    ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(buf);
                };

                row("Shannon entropy bits/byte", "%.4f", a.shannon_entropy_bits);
                row("Chi-square",                "%.2f",  a.chi_square);
                row("Chi-square p-value",        "%.4f",  a.chi_square_p_value);
                row("Monobit p-value",           "%.4f",  a.monobit_p_value);
                row("Poker p-value",             "%.4f",  a.poker_p_value);
                row("Runs p-value",              "%.4f",  a.runs_p_value);
                row("Long-run p-value",          "%.4f",  a.long_run_p_value);
                row("Maurer's Universal",        "%.4f",  a.maurer_universal);
                row("Autocorrelation (lag-1)",   "%.4f",  a.autocorrelation);

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted("Bitstream length (bits)");
                ImGui::TableSetColumnIndex(1);
                char bbuf[32]; snprintf(bbuf, sizeof(bbuf), "%zu", a.total_bits);
                ImGui::TextUnformatted(bbuf);

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted("Ones / Zeros");
                ImGui::TableSetColumnIndex(1);
                char obuf[64]; snprintf(obuf, sizeof(obuf), "%zu / %zu", a.monobit_ones, a.monobit_zeros);
                ImGui::TextUnformatted(obuf);

                ImGui::EndTable();
            }

            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                "Byte frequency");
            size_t max_freq = 0;
            for (size_t i = 0; i < 256; ++i) if (a.byte_frequency[i] > max_freq) max_freq = a.byte_frequency[i];
            if (max_freq == 0) max_freq = 1;
            float pw = right_w - 24.f;
            float ph = 120.f;
            ImVec2 hp = ImGui::GetCursorScreenPos();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            dl->AddRectFilled(hp, ImVec2(hp.x + pw, hp.y + ph),
                aida::ui::with_alpha(th.panel_header, alpha * 0.65f), 6.f);
            for (size_t i = 0; i < 256; ++i) {
                float bar_w = pw / 256.f;
                float bx = hp.x + static_cast<float>(i) * bar_w;
                float bh = ph * (static_cast<float>(a.byte_frequency[i]) / static_cast<float>(max_freq));
                ImU32 bc = aida::ui::with_alpha(th.accent_u32, alpha * 0.85f);
                dl->AddRectFilled(ImVec2(bx, hp.y + ph - bh),
                                  ImVec2(bx + bar_w - 0.5f, hp.y + ph), bc);
            }
            ImGui::Dummy(ImVec2(pw, ph + 6.f));
            if (!a.notes.empty()) {
                ImGui::TextWrapped("%s", a.notes.c_str());
            }
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "Click Analyze to compute entropy and FIPS 140-2 metrics over the captured tokens.");

            auto snap = aida::burp::sequencer::samples(g_view_state.selected_id, 32);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                "Recent samples");
            if (ImGui::BeginChild("##seq_samples", ImVec2(right_w - 16.f, height - 220.f), false,
                ImGuiWindowFlags_NoBackground)) {
                for (size_t i = snap.size(); i > 0; --i) {
                    char idx[16];
                    snprintf(idx, sizeof(idx), "%zu:", i);
                    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                        "%s", idx);
                    ImGui::SameLine();
                    ImGui::TextWrapped("%s", snap[i - 1].c_str());
                }
                ImGui::EndChild();
            }
        }
    }

    ImGui::EndChild();

    if (g_view_state.delete_review_requested) {
        aida::ui::design::open_dialog("network.sequencer.delete", "Delete Sequencer Collection");
        g_view_state.delete_review_requested = false;
    }
    if (aida::ui::design::begin_dialog("network.sequencer.delete", "Delete Sequencer Collection",
            ImVec2(560.f, 310.f), ImVec2(430.f, 250.f))) {
        const auto current = aida::burp::sequencer::status(g_view_state.reviewed_delete_id);
        const bool exact = current.id == g_view_state.reviewed_delete_id &&
            current.started_ms == g_view_state.reviewed_delete_started_ms &&
            (current.name.empty() ? current.url : current.name) == g_view_state.reviewed_delete_name &&
            current.instance_revision == g_view_state.reviewed_delete_instance_revision;
        const float footer = aida::ui::design::dialog_footer_reserve_height("Delete Collection");
        if (aida::ui::design::begin_dialog_body("sequencer_delete_body", footer)) {
            ImGui::TextWrapped("Delete Sequencer collection '%s' (ID %llu)?",
                g_view_state.reviewed_delete_name.c_str(),
                static_cast<unsigned long long>(g_view_state.reviewed_delete_id));
            ImGui::TextDisabled("Scope: retained collection configuration and every captured token in this collection.");
            ImGui::TextDisabled("Effect: active collection work is stopped and retained samples are permanently removed.");
            ImGui::TextDisabled("This operation cannot be undone after confirmation.");
            if (!exact)
                ImGui::TextWrapped("The collection or registry changed after review. Cancel and select it again.");
        }
        aida::ui::design::end_dialog_body();
        const auto result = aida::ui::design::dialog_footer(
            "sequencer_delete_footer", "Delete Collection", exact, true, "Cancel", true, false);
        if (result.confirmed) {
            const std::uint64_t id = g_view_state.reviewed_delete_id;
            const std::uint64_t started_ms = g_view_state.reviewed_delete_started_ms;
            const std::uint64_t instance_revision = g_view_state.reviewed_delete_instance_revision;
            aida::infra::executor::submission_t submission;
            submission.owner_subsystem = "burp.sequencer_view";
            submission.label = "sequencer.delete_collection_exact";
            submission.thread_class = "bounded_task";
            submission.domain = aida::infra::executor::domain_t::external_tool;
            submission.priority = 3;
            submission.body = [id, started_ms, instance_revision]() {
                if (!aida::burp::sequencer::delete_collection_exact(id, started_ms, instance_revision))
                    publish_view_error(aida::burp::sequencer::last_error());
            };
            if (submit_view_task(std::move(submission), "Delete collection")) {
                g_view_state.analysis_valid = false;
                ImGui::CloseCurrentPopup();
            }
        }
        if (result.cancelled) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::EndChild();
}

}
}
}
