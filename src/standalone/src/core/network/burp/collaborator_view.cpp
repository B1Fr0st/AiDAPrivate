#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifdef small
#undef small
#endif

#include "collaborator_view.hpp"
#include "collaborator.hpp"
#include "burp_ui_operation.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "helpers/diag_log.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/components.hpp"
#include "../../ui/design_system.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace collaborator_view {

namespace {

struct state_t
{
    char    bind_ip[64]      = "0.0.0.0";
    int     http_port        = 8444;
    int     dns_port         = 5353;
    int     smtp_port        = 2525;
    bool    enable_http      = true;
    bool    enable_dns       = true;
    bool    enable_smtp      = true;
    char    public_host[256] = "aidacollab.local";
    char    public_ip[64]    = "127.0.0.1";
    char    canned_body[1024] = {};
    char    canned_ct[128]   = "text/plain";

    std::string                                          filter_kind = "all";
    char                                                 filter_token[64] = {};
    char                                                 filter_ip[64]    = {};
    int                                                  selected_id     = -1;

    std::shared_ptr<const std::vector<aida::burp::collaborator::interaction_t>> cached =
        std::make_shared<const std::vector<aida::burp::collaborator::interaction_t>>();
    std::atomic<bool>                                    cache_refresh_pending{false};
    std::atomic<std::uint64_t>                           cache_generation{0};
    uint64_t                                             cache_last_ms = 0;
    uint64_t                                             cache_max_id  = 0;

    std::string                                          last_generated_token;
    std::string                                          last_generated_domain;
    std::shared_ptr<const std::pair<std::string, std::string>> generated_token =
        std::make_shared<const std::pair<std::string, std::string>>();
    aida::burp::ui_operation::state_t                    operation;
    std::uint64_t                                        observed_operation_generation = 0;
    std::uint64_t                                        filtered_generation = 0;
    std::string                                          filtered_signature;
    std::vector<std::size_t>                             filtered_indices;
    int                                                  review_operation = 0;
    aida::burp::collaborator::status_t                   reviewed_status;
};

static state_t g_view_state;

static void request_cache_refresh()
{
    bool expected = false;
    if (!g_view_state.cache_refresh_pending.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel))
        return;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "burp.collaborator";
    submission.label = "collaborator.refresh_interactions";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.priority = 4;
    submission.body = []() {
        auto finish_pending = std::unique_ptr<void, void(*)(void*)>(
            reinterpret_cast<void*>(1), [](void*) {
                g_view_state.cache_refresh_pending.store(false, std::memory_order_release);
            });
        auto rows = aida::burp::collaborator::snapshot_all(4096);
        std::shared_ptr<const std::vector<aida::burp::collaborator::interaction_t>> publication =
            std::make_shared<const std::vector<aida::burp::collaborator::interaction_t>>(std::move(rows));
        std::atomic_store_explicit(&g_view_state.cached, std::move(publication),
            std::memory_order_release);
        g_view_state.cache_generation.fetch_add(1, std::memory_order_acq_rel);
    };
    if (!aida::infra::executor::submit(std::move(submission)).submitted)
        g_view_state.cache_refresh_pending.store(false, std::memory_order_release);
}

static bool same_runtime(const aida::burp::collaborator::status_t& left,
    const aida::burp::collaborator::status_t& right)
{
    return left.running == right.running && left.bind_ip == right.bind_ip &&
        left.http_alive == right.http_alive && left.dns_alive == right.dns_alive &&
        left.smtp_alive == right.smtp_alive &&
        left.http_port == right.http_port && left.dns_port == right.dns_port &&
        left.smtp_port == right.smtp_port && left.public_host == right.public_host &&
        left.public_ip == right.public_ip && left.interaction_count == right.interaction_count &&
        left.token_count == right.token_count && left.started_ms == right.started_ms;
}

static void submit_start(aida::burp::collaborator::collaborator_config_t config)
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.collaborator";
    request.owner_view = "view.network.collaborator";
    request.owner_action = "network.collaborator.start";
    request.label = "Start Collaborator";
    request.target = config.bind_ip + ":" + std::to_string(config.http_port);
    request.affected_entity = "Collaborator listeners";
    request.execute = [config = std::move(config)]() {
        aida::burp::ui_operation::result_t result;
        if (aida::burp::collaborator::status().running) {
            result.message = "Collaborator started before this request executed.";
            return result;
        }
        result.success = aida::burp::collaborator::start(config);
        result.message = result.success ? "Collaborator listeners started."
                                        : aida::burp::collaborator::last_error();
        return result;
    };
    static_cast<void>(g_view_state.operation.submit(std::move(request)));
}

static void submit_reviewed_operation(int operation,
    aida::burp::collaborator::status_t reviewed)
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.collaborator";
    request.owner_view = "view.network.collaborator";
    request.owner_action = operation == 1 ? "network.collaborator.stop"
                                          : "network.collaborator.clear";
    request.label = operation == 1 ? "Stop Collaborator" : "Clear Collaborator interactions";
    request.target = reviewed.public_host;
    request.affected_entity = operation == 1 ? "Collaborator listeners"
                                             : std::to_string(reviewed.interaction_count) + " interactions";
    request.execute = [operation, reviewed = std::move(reviewed)]() {
        aida::burp::ui_operation::result_t result;
        const auto current = aida::burp::collaborator::status();
        if (!same_runtime(current, reviewed)) {
            result.message = "Collaborator state changed after review; no operation was applied.";
            return result;
        }
        if (operation == 1) {
            aida::burp::collaborator::stop();
            result.success = !aida::burp::collaborator::status().running;
            result.message = result.success ? "Collaborator listeners stopped."
                                            : "Collaborator did not reach the stopped state.";
        } else {
            aida::burp::collaborator::clear();
            result.success = aida::burp::collaborator::status().interaction_count == 0;
            result.message = result.success ? "Collaborator interactions cleared."
                                            : "Collaborator interactions were not cleared.";
        }
        return result;
    };
    static_cast<void>(g_view_state.operation.submit(std::move(request)));
}

static void submit_generate_token()
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.collaborator";
    request.owner_view = "view.network.collaborator";
    request.owner_action = "network.collaborator.generate_token";
    request.label = "Generate Collaborator token";
    request.target = "Collaborator token store";
    request.affected_entity = "Persisted Collaborator tokens";
    request.execute = []() {
        aida::burp::ui_operation::result_t result;
        const std::string token = aida::burp::collaborator::generate_token();
        const auto config = aida::burp::collaborator::current_config();
        result.success = !token.empty();
        result.message = result.success ? "Collaborator token generated and persisted."
                                        : aida::burp::collaborator::last_error();
        if (result.success) {
            std::shared_ptr<const std::pair<std::string, std::string>> publication =
                std::make_shared<const std::pair<std::string, std::string>>(
                    token, token + "." + config.public_host);
            std::atomic_store_explicit(&g_view_state.generated_token,
                std::move(publication), std::memory_order_release);
        }
        return result;
    };
    static_cast<void>(g_view_state.operation.submit(std::move(request)));
}

static bool interaction_matches(const aida::burp::collaborator::interaction_t& it)
{
    if (g_view_state.filter_kind != "all" && it.kind != g_view_state.filter_kind) return false;
    if (g_view_state.filter_token[0] != 0) {
        std::string filt = g_view_state.filter_token;
        if (it.payload_token.find(filt) == std::string::npos) return false;
    }
    if (g_view_state.filter_ip[0] != 0) {
        std::string filt = g_view_state.filter_ip;
        if (it.client_ip.find(filt) == std::string::npos) return false;
    }
    return true;
}

}

void initialize()
{
    ::diag::log_tagged("collaborator_v", "initialize");
}

void shutdown()
{
    ::diag::log_tagged("collaborator_v", "shutdown");
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##collab_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    auto status = aida::burp::collaborator::status();
    const auto operation_completion = g_view_state.operation.completion();
    if (operation_completion &&
        operation_completion->generation != g_view_state.observed_operation_generation) {
        g_view_state.observed_operation_generation = operation_completion->generation;
        const auto token = std::atomic_load_explicit(&g_view_state.generated_token,
            std::memory_order_acquire);
        if (!token->first.empty() && token->first != g_view_state.last_generated_token) {
            g_view_state.last_generated_token = token->first;
            g_view_state.last_generated_domain = token->second;
        }
        if (operation_completion->result.success &&
            operation_completion->result.message.find("cleared") != std::string::npos)
            g_view_state.selected_id = -1;
    }
    static bool s_last_running = false;
    if (status.running != s_last_running) {
        s_last_running = status.running;
        ::diag::log_tagged_fmt("collaborator_v", "render_state_change running=%d interactions=%zu tokens=%zu",
            status.running ? 1 : 0,
            status.interaction_count,
            status.token_count);
    }

    float bar_h = 64.f;
    ImGui::BeginChild("##collab_bar", ImVec2(width, bar_h), false, ImGuiWindowFlags_NoBackground);
    {
        ImVec2 p = ImGui::GetWindowPos();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(p, ImVec2(p.x + width, p.y + bar_h),
            aida::ui::with_alpha(th.panel_header, alpha * 0.7f), 8.f);
        dl->AddRect(p, ImVec2(p.x + width, p.y + bar_h),
            aida::ui::with_alpha(th.border_subtle, alpha), 8.f);
    }

    ImGui::SetCursorPos(ImVec2(12.f, 8.f));
    ImU32 ind_col = status.running
        ? aida::ui::with_alpha(th.success, alpha)
        : aida::ui::with_alpha(th.text_dim, alpha);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ind_col),
        status.running ? "RUNNING" : "STOPPED");

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "  HTTP %s:%d %s   DNS %s:%d %s   SMTP %s:%d %s",
        status.bind_ip.c_str(), static_cast<int>(status.http_port), status.http_alive ? "OK" : "--",
        status.bind_ip.c_str(), static_cast<int>(status.dns_port),  status.dns_alive  ? "OK" : "--",
        status.bind_ip.c_str(), static_cast<int>(status.smtp_port), status.smtp_alive ? "OK" : "--");

    ImGui::SetCursorPos(ImVec2(12.f, 30.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Public: %s -> %s   Interactions=%zu Tokens=%zu",
        status.public_host.c_str(), status.public_ip.c_str(),
        status.interaction_count, status.token_count);

    float btn_x = width - 480.f;
    if (btn_x < 320.f) btn_x = 320.f;
    ImGui::SetCursorPos(ImVec2(btn_x, 16.f));

    const bool operation_pending = g_view_state.operation.pending();
    ImGui::BeginDisabled(operation_pending);
    if (!status.running) {
        if (aida::ui::button("Start", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            aida::burp::collaborator::collaborator_config_t cfg;
            cfg.bind_ip = g_view_state.bind_ip;
            cfg.http_port = static_cast<uint16_t>(g_view_state.http_port);
            cfg.dns_port  = static_cast<uint16_t>(g_view_state.dns_port);
            cfg.smtp_port = static_cast<uint16_t>(g_view_state.smtp_port);
            cfg.enable_http = g_view_state.enable_http;
            cfg.enable_dns  = g_view_state.enable_dns;
            cfg.enable_smtp = g_view_state.enable_smtp;
            cfg.public_host = g_view_state.public_host;
            cfg.public_ip   = g_view_state.public_ip;
            cfg.canned_body = g_view_state.canned_body;
            cfg.canned_content_type = g_view_state.canned_ct[0] ? g_view_state.canned_ct : "text/plain";
            submit_start(std::move(cfg));
        }
    } else {
        if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            g_view_state.review_operation = 1;
            g_view_state.reviewed_status = status;
            ImGui::OpenPopup("Review Collaborator operation");
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(operation_pending);
    if (aida::ui::button("Generate Token", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
        submit_generate_token();
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (aida::ui::button("Copy Domain", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
        if (!g_view_state.last_generated_domain.empty()) {
            ImGui::SetClipboardText(g_view_state.last_generated_domain.c_str());
            ::diag::log_tagged_fmt("collaborator_v", "copy_domain domain=%s", g_view_state.last_generated_domain.c_str());
        }
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(operation_pending || status.interaction_count == 0);
    if (aida::ui::button("Clear", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
        g_view_state.review_operation = 2;
        g_view_state.reviewed_status = status;
        ImGui::OpenPopup("Review Collaborator operation");
    }
    ImGui::EndDisabled();

    if (aida::ui::design::begin_dialog_exact("Review Collaborator operation",
        ImVec2(540.f, 300.f), ImVec2(420.f, 240.f))) {
        const bool stop = g_view_state.review_operation == 1;
        const char* confirm = stop ? "Stop listeners" : "Clear interactions";
        const float footer = aida::ui::design::dialog_footer_reserve_height(confirm);
        if (aida::ui::design::begin_dialog_body("collaborator_operation_review_body", footer)) {
            ImGui::TextUnformatted(stop ? "Stop all Collaborator listeners?"
                                        : "Permanently clear Collaborator interactions?");
            ImGui::Text("Target: %s", g_view_state.reviewed_status.public_host.c_str());
            ImGui::Text("Interactions: %zu", g_view_state.reviewed_status.interaction_count);
            ImGui::TextWrapped("The exact reviewed listener and interaction state will be revalidated before the operation runs.");
        }
        aida::ui::design::end_dialog_body();
        const auto result = aida::ui::design::dialog_footer(
            "collaborator_operation_review_footer", confirm,
            g_view_state.review_operation != 0 && !g_view_state.operation.pending(), true);
        if (result.confirmed) {
            submit_reviewed_operation(g_view_state.review_operation,
                g_view_state.reviewed_status);
            g_view_state.review_operation = 0;
            ImGui::CloseCurrentPopup();
        }
        if (result.cancelled) {
            g_view_state.review_operation = 0;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::SetCursorPos(ImVec2(12.f, 48.f));
    if (operation_pending) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.info, alpha)), "Operation running in Task Center");
    } else if (operation_completion) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(
            operation_completion->result.success ? th.success : th.error, alpha)),
            "%s", operation_completion->result.message.c_str());
        if (!operation_completion->result.success) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Retry##collaborator_operation"))
                static_cast<void>(g_view_state.operation.retry());
        }
    }

    ImGui::EndChild();

    float cfg_y = bar_h + 6.f;
    float cfg_h = status.running ? 36.f : 110.f;
    ImGui::SetCursorPos(ImVec2(0.f, cfg_y));
    ImGui::BeginChild("##collab_cfg", ImVec2(width, cfg_h), false, ImGuiWindowFlags_NoBackground);

    if (!status.running) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Bind IP");
        ImGui::SameLine();
        ImGui::PushItemWidth(140.f);
        ImGui::InputText("##c_bind", g_view_state.bind_ip, sizeof(g_view_state.bind_ip));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Public host");
        ImGui::SameLine();
        ImGui::PushItemWidth(220.f);
        ImGui::InputText("##c_phost", g_view_state.public_host, sizeof(g_view_state.public_host));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Public IP");
        ImGui::SameLine();
        ImGui::PushItemWidth(140.f);
        ImGui::InputText("##c_pip", g_view_state.public_ip, sizeof(g_view_state.public_ip));
        ImGui::PopItemWidth();

        ImGui::Checkbox("HTTP", &g_view_state.enable_http);
        ImGui::SameLine();
        ImGui::PushItemWidth(80.f);
        ImGui::InputInt("##c_hport", &g_view_state.http_port);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::Checkbox("DNS", &g_view_state.enable_dns);
        ImGui::SameLine();
        ImGui::PushItemWidth(80.f);
        ImGui::InputInt("##c_dport", &g_view_state.dns_port);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::Checkbox("SMTP", &g_view_state.enable_smtp);
        ImGui::SameLine();
        ImGui::PushItemWidth(80.f);
        ImGui::InputInt("##c_sport", &g_view_state.smtp_port);
        ImGui::PopItemWidth();

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Canned body");
        ImGui::SameLine();
        ImGui::PushItemWidth(width - 320.f);
        ImGui::InputText("##c_body", g_view_state.canned_body, sizeof(g_view_state.canned_body));
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "CT");
        ImGui::SameLine();
        ImGui::PushItemWidth(140.f);
        ImGui::InputText("##c_ct", g_view_state.canned_ct, sizeof(g_view_state.canned_ct));
        ImGui::PopItemWidth();
    } else {
        if (!g_view_state.last_generated_domain.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                "Last token domain: %s", g_view_state.last_generated_domain.c_str());
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "Click Generate Token to issue a callback domain.");
        }
    }

    ImGui::EndChild();

    float filt_y = cfg_y + cfg_h + 6.f;
    float filt_h = 36.f;
    ImGui::SetCursorPos(ImVec2(0.f, filt_y));
    ImGui::BeginChild("##collab_filter", ImVec2(width, filt_h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Filter:");
    ImGui::SameLine();
    const char* kinds[] = { "all", "http", "dns", "smtp" };
    int cur = 0;
    for (int i = 0; i < 4; ++i) if (g_view_state.filter_kind == kinds[i]) { cur = i; break; }
    ImGui::PushItemWidth(80.f);
    if (ImGui::Combo("##c_kind", &cur, kinds, 4)) {
        g_view_state.filter_kind = kinds[cur];
        ::diag::log_tagged_fmt("collaborator_v", "filter_kind_changed kind=%s", g_view_state.filter_kind.c_str());
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Token");
    ImGui::SameLine();
    ImGui::PushItemWidth(160.f);
    ImGui::InputText("##c_ftok", g_view_state.filter_token, sizeof(g_view_state.filter_token));
    ImGui::PopItemWidth();

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Client IP");
    ImGui::SameLine();
    ImGui::PushItemWidth(120.f);
    ImGui::InputText("##c_fip", g_view_state.filter_ip, sizeof(g_view_state.filter_ip));
    ImGui::PopItemWidth();

    ImGui::EndChild();

    float list_y = filt_y + filt_h + 6.f;
    float list_h = height - list_y - 8.f;
    float left_w = width * 0.50f;
    float right_w = width - left_w - 8.f;

    const std::uint64_t now = aida::infra::executor::now_ms();
    if (now - g_view_state.cache_last_ms >= 200) {
        g_view_state.cache_last_ms = now;
        request_cache_refresh();
    }
    const auto cached = std::atomic_load_explicit(&g_view_state.cached,
        std::memory_order_acquire);
    const std::uint64_t cache_generation = g_view_state.cache_generation.load(
        std::memory_order_acquire);
    std::string filter_signature = g_view_state.filter_kind;
    filter_signature.push_back('\n');
    filter_signature.append(g_view_state.filter_token).push_back('\n');
    filter_signature.append(g_view_state.filter_ip);
    if (cached && (g_view_state.filtered_generation != cache_generation ||
        g_view_state.filtered_signature != filter_signature)) {
        g_view_state.filtered_indices.clear();
        g_view_state.filtered_indices.reserve(cached->size());
        for (std::size_t index = cached->size(); index > 0; --index)
            if (interaction_matches((*cached)[index - 1]))
                g_view_state.filtered_indices.push_back(index - 1);
        g_view_state.filtered_generation = cache_generation;
        g_view_state.filtered_signature = std::move(filter_signature);
    }

    ImGui::SetCursorPos(ImVec2(0.f, list_y));
    ImGui::BeginChild("##collab_list", ImVec2(left_w, list_h), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
        "Interactions");

    if (ImGui::BeginTable("##c_intable", 5,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("ID",     ImGuiTableColumnFlags_WidthFixed, 60.f);
        ImGui::TableSetupColumn("Time",   ImGuiTableColumnFlags_WidthFixed, 100.f);
        ImGui::TableSetupColumn("Kind",   ImGuiTableColumnFlags_WidthFixed, 60.f);
        ImGui::TableSetupColumn("Client", ImGuiTableColumnFlags_WidthFixed, 120.f);
        ImGui::TableSetupColumn("Token",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(g_view_state.filtered_indices.size()),
            ImGui::GetTextLineHeightWithSpacing());
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& it = (*cached)[g_view_state.filtered_indices[static_cast<std::size_t>(row)]];
            ImGui::TableNextRow();
            const bool sel = (static_cast<int>(it.id) == g_view_state.selected_id);

            ImGui::TableSetColumnIndex(0);
            char idbuf[32];
            snprintf(idbuf, sizeof(idbuf), "%llu", static_cast<unsigned long long>(it.id));
            if (ImGui::Selectable(idbuf, sel, ImGuiSelectableFlags_SpanAllColumns)) {
                g_view_state.selected_id = static_cast<int>(it.id);
                ::diag::log_tagged_fmt("collaborator_v", "interaction_selected id=%llu kind=%s client=%s",
                    static_cast<unsigned long long>(it.id), it.kind.c_str(), it.client_ip.c_str());
            }

            uint64_t age = (status.started_ms == 0) ? 0 : (it.timestamp_ms > status.started_ms ? it.timestamp_ms - status.started_ms : 0);
            uint64_t s = age / 1000;
            uint64_t ms = age % 1000;
            char tbuf[32];
            snprintf(tbuf, sizeof(tbuf), "+%llu.%03llus",
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(ms));
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(tbuf);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(it.kind.c_str());
            ImGui::TableSetColumnIndex(3);
            char ipbuf[80];
            snprintf(ipbuf, sizeof(ipbuf), "%s:%u", it.client_ip.c_str(), static_cast<unsigned>(it.client_port));
            ImGui::TextUnformatted(ipbuf);
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(it.payload_token.empty() ? "-" : it.payload_token.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + 8.f, list_y));
    ImGui::BeginChild("##collab_detail", ImVec2(right_w, list_h), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
        "Detail");

    const aida::burp::collaborator::interaction_t* sel_it = nullptr;
    if (cached && g_view_state.selected_id >= 0) {
        for (const auto& it : *cached) {
            if (static_cast<int>(it.id) == g_view_state.selected_id) { sel_it = &it; break; }
        }
    }

    if (sel_it) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "id=%llu kind=%s client=%s:%u subdomain=%s token=%s",
            static_cast<unsigned long long>(sel_it->id),
            sel_it->kind.c_str(),
            sel_it->client_ip.c_str(),
            static_cast<unsigned>(sel_it->client_port),
            sel_it->subdomain.c_str(),
            sel_it->payload_token.empty() ? "-" : sel_it->payload_token.c_str());

        if (ImGui::BeginTable("##c_det_tbl", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 120.f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
            for (const auto& kv : sel_it->details) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(kv.first.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextWrapped("%s", kv.second.c_str());
            }
            ImGui::EndTable();
        }

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Raw");
        static std::string s_raw_view;
        s_raw_view = sel_it->raw;
        ImGui::InputTextMultiline("##c_raw", s_raw_view.data(), s_raw_view.size() + 1,
            ImVec2(right_w - 8.f, list_h - 200.f),
            ImGuiInputTextFlags_ReadOnly);
    } else {
        ImVec2 rp = ImGui::GetCursorScreenPos();
        ImVec2 rs = ImVec2(right_w, list_h - 32.f);
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No interaction selected";
        cfg.body  = "Click an entry on the left to view the raw payload, headers, and decoded details.";
        aida::ui::empty_state::render(rp, rs, cfg);
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
