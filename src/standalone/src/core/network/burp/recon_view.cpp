#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "recon_view.hpp"
#include "crawler.hpp"
#include "content_discovery.hpp"
#include "subdomain_enum.hpp"
#include "payload_library.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/toast_notification.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace recon_view {

namespace {

enum class tab_t : int
{
    crawler = 0,
    content_discovery = 1,
    subdomains = 2,
    payloads = 3
};

struct ui_state_t
{
    std::atomic<bool>            initialized{false};
    int                          active_tab = 0;

    char                         crawler_seed[2048] = "https://example.com/";
    int                          crawler_max_depth = 3;
    int                          crawler_max_pages = 500;
    int                          crawler_concurrency = 8;
    int                          crawler_rate_per_host = 10;
    bool                         crawler_same_host = true;
    bool                         crawler_scope_only = false;
    bool                         crawler_respect_robots = true;
    bool                         crawler_parse_js = true;
    char                         crawler_user_agent[256] = "AiDA-Crawler/1.0";
    char                         crawler_exclude_ext[512] = ".png,.jpg,.jpeg,.gif,.svg,.ico,.woff,.woff2,.ttf,.eot,.css,.mp4,.webm,.mp3,.pdf";
    uint64_t                     crawler_selected = 0;

    char                         disc_target[1024] = "https://example.com/FUZZ";
    char                         disc_wordlist_id[128] = "dirs/common-100";
    char                         disc_extensions[256] = "";
    char                         disc_match_status[128] = "200,201,204,301,302,401,403,500";
    char                         disc_filter_status[128] = "404";
    int                          disc_concurrency = 25;
    int                          disc_delay_ms = 0;
    int                          disc_recurse_depth = 1;
    bool                         disc_recurse = false;
    bool                         disc_auto_calibrate = true;
    bool                         disc_follow_redir = false;
    char                         disc_cookie[1024] = "";
    char                         disc_user_agent[256] = "AiDA-ContentDiscovery/1.0";
    uint64_t                     disc_selected = 0;

    char                         sub_domain[256] = "example.com";
    char                         sub_wordlist_id[128] = "subdomains/top1000";
    int                          sub_concurrency = 32;
    bool                         sub_run_passive = true;
    bool                         sub_run_brute = true;
    bool                         sub_passive_crtsh = true;
    bool                         sub_passive_bufferover = true;
    bool                         sub_passive_hackertarget = true;
    uint64_t                     sub_selected = 0;

    char                         pl_filter[128] = "";
    char                         pl_selected_id[128] = "";
    char                         pl_new_id[128] = "";
    char                         pl_new_label[128] = "";
    char                         pl_new_desc[256] = "";
    char                         pl_new_entries[4096] = "";

    std::mutex                   mtx;
};

ui_state_t& ui() { static ui_state_t s; return s; }

std::vector<std::string> split_csv(const char* s)
{
    std::vector<std::string> out;
    if (!s) return out;
    std::string cur;
    for (const char* p = s; *p; ++p)
    {
        if (*p == ',')
        {
            while (!cur.empty() && (cur.front() == ' ' || cur.front() == '\t')) cur.erase(cur.begin());
            while (!cur.empty() && (cur.back() == ' ' || cur.back() == '\t')) cur.pop_back();
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        }
        else cur.push_back(*p);
    }
    while (!cur.empty() && (cur.front() == ' ' || cur.front() == '\t')) cur.erase(cur.begin());
    while (!cur.empty() && (cur.back() == ' ' || cur.back() == '\t')) cur.pop_back();
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<int> split_csv_ints(const char* s)
{
    std::vector<int> out;
    if (!s) return out;
    std::string cur;
    for (const char* p = s; ; ++p)
    {
        if (*p == ',' || *p == '\0')
        {
            try { if (!cur.empty()) out.push_back(std::stoi(cur)); } catch (...) {}
            cur.clear();
            if (*p == '\0') break;
        }
        else if (*p != ' ' && *p != '\t') cur.push_back(*p);
    }
    return out;
}

const char* crawl_phase_label(crawler::crawl_status_phase_t p)
{
    switch (p)
    {
        case crawler::crawl_status_phase_t::pending: return "pending";
        case crawler::crawl_status_phase_t::running: return "running";
        case crawler::crawl_status_phase_t::stopping: return "stopping";
        case crawler::crawl_status_phase_t::complete: return "complete";
        case crawler::crawl_status_phase_t::error: return "error";
    }
    return "?";
}

const char* disc_phase_label(content_discovery::disc_phase_t p)
{
    switch (p)
    {
        case content_discovery::disc_phase_t::pending: return "pending";
        case content_discovery::disc_phase_t::calibrating: return "calibrating";
        case content_discovery::disc_phase_t::running: return "running";
        case content_discovery::disc_phase_t::stopping: return "stopping";
        case content_discovery::disc_phase_t::complete: return "complete";
        case content_discovery::disc_phase_t::error: return "error";
    }
    return "?";
}

const char* sub_phase_label(subdomain_enum::enum_phase_t p)
{
    switch (p)
    {
        case subdomain_enum::enum_phase_t::pending: return "pending";
        case subdomain_enum::enum_phase_t::passive: return "passive";
        case subdomain_enum::enum_phase_t::brute: return "brute";
        case subdomain_enum::enum_phase_t::stopping: return "stopping";
        case subdomain_enum::enum_phase_t::complete: return "complete";
        case subdomain_enum::enum_phase_t::error: return "error";
    }
    return "?";
}

void render_crawler(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Crawler / Spider");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Seed URLs (comma-separated):");
    aida::ui::input_text("##crl_seed", st.crawler_seed, sizeof(st.crawler_seed), "https://target/, https://target/api", false, ImVec2(680.f, 28.f));

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Max depth:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_depth", &st.crawler_max_depth, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Max pages:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_maxp", &st.crawler_max_pages, ImVec2(100.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Concurrency:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_conc", &st.crawler_concurrency, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "RPS/host:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_rps", &st.crawler_rate_per_host, ImVec2(80.f, 28.f));

    ImGui::Spacing();
    aida::ui::toggle_switch("##crl_sh", &st.crawler_same_host);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Same host only");
    ImGui::SameLine();
    aida::ui::toggle_switch("##crl_scope", &st.crawler_scope_only);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Scope only");
    ImGui::SameLine();
    aida::ui::toggle_switch("##crl_rob", &st.crawler_respect_robots);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "robots.txt");
    ImGui::SameLine();
    aida::ui::toggle_switch("##crl_js", &st.crawler_parse_js);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Parse JS");

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "User-Agent:");
    aida::ui::input_text("##crl_ua", st.crawler_user_agent, sizeof(st.crawler_user_agent), "AiDA-Crawler/1.0", false, ImVec2(420.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Exclude ext:");
    aida::ui::input_text("##crl_ext", st.crawler_exclude_ext, sizeof(st.crawler_exclude_ext), ".png,.jpg,...", false, ImVec2(360.f, 28.f));

    ImGui::Spacing();
    if (aida::ui::button("Start Crawl", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        crawler::crawl_config_t cfg;
        cfg.start_urls = split_csv(st.crawler_seed);
        cfg.max_depth = std::max(0, st.crawler_max_depth);
        cfg.same_host_only = st.crawler_same_host;
        cfg.scope_only = st.crawler_scope_only;
        cfg.respect_robots_txt = st.crawler_respect_robots;
        cfg.parse_js = st.crawler_parse_js;
        cfg.max_pages = std::max(1, st.crawler_max_pages);
        cfg.concurrency = std::max(1, st.crawler_concurrency);
        cfg.rate_per_host = std::max(1, st.crawler_rate_per_host);
        cfg.user_agent = st.crawler_user_agent;
        cfg.exclude_extensions = split_csv(st.crawler_exclude_ext);
        uint64_t id = crawler::start(cfg);
        if (id == 0) toast_notification::push(std::string("crawler start failed: ") + crawler::last_error(), toast_notification::toast_type_t::error);
        else { st.crawler_selected = id; toast_notification::push("crawl started", toast_notification::toast_type_t::success); }
    }
    ImGui::SameLine();
    if (aida::ui::button("Stop Selected", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
    {
        if (st.crawler_selected != 0) crawler::stop(st.crawler_selected);
    }
    ImGui::SameLine();
    if (aida::ui::button("Remove Selected", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        if (st.crawler_selected != 0) { crawler::remove(st.crawler_selected); st.crawler_selected = 0; }
    }

    ImGui::Spacing();
    auto crawls = crawler::list();
    if (ImGui::BeginTable("##crawls_tbl", 6,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_Resizable,
        ImVec2(0.f, 220.f)))
    {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Phase");
        ImGui::TableSetupColumn("Queue");
        ImGui::TableSetupColumn("Visited");
        ImGui::TableSetupColumn("Failed");
        ImGui::TableSetupColumn("Found");
        ImGui::TableHeadersRow();
        for (auto& c : crawls)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char buf[32];
            snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(c.id));
            bool sel = (c.id == st.crawler_selected);
            if (ImGui::Selectable(buf, sel, ImGuiSelectableFlags_SpanAllColumns)) st.crawler_selected = c.id;
            ImGui::TableNextColumn(); ImGui::TextUnformatted(crawl_phase_label(c.phase));
            ImGui::TableNextColumn(); ImGui::Text("%d", c.queue_depth);
            ImGui::TableNextColumn(); ImGui::Text("%d", c.pages_visited);
            ImGui::TableNextColumn(); ImGui::Text("%d", c.pages_failed);
            ImGui::TableNextColumn(); ImGui::Text("%d", c.urls_found);
        }
        ImGui::EndTable();
    }

    if (st.crawler_selected != 0)
    {
        auto cs = crawler::status(st.crawler_selected);
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Discovered (%zu) | Last: %s", cs.discovered.size(), cs.last_url.c_str());
        if (ImGui::BeginTable("##disc_urls", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.f, 220.f)))
        {
            ImGui::TableSetupColumn("Status");
            ImGui::TableSetupColumn("Bytes");
            ImGui::TableSetupColumn("Depth");
            ImGui::TableSetupColumn("Content-Type");
            ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (auto& d : cs.discovered)
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%d", d.status);
                ImGui::TableNextColumn(); ImGui::Text("%zu", d.body_bytes);
                ImGui::TableNextColumn(); ImGui::Text("%d", d.depth);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(d.content_type.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(d.url.c_str());
            }
            ImGui::EndTable();
        }
    }
}

void render_content_discovery(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Content Discovery (ffuf)");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Target URL (use FUZZ marker):");
    aida::ui::input_text("##cd_url", st.disc_target, sizeof(st.disc_target), "https://target/FUZZ", false, ImVec2(680.f, 28.f));

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Wordlist id:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_wl", st.disc_wordlist_id, sizeof(st.disc_wordlist_id), "dirs/common-100", false, ImVec2(260.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Extensions:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_ext", st.disc_extensions, sizeof(st.disc_extensions), ".php,.bak,.zip", false, ImVec2(260.f, 28.f));

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Match status:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_ms", st.disc_match_status, sizeof(st.disc_match_status), "200,301", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Filter status:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_fs", st.disc_filter_status, sizeof(st.disc_filter_status), "404", false, ImVec2(220.f, 28.f));

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Concurrency:");
    ImGui::SameLine();
    aida::ui::input_int("##cd_conc", &st.disc_concurrency, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Delay ms:");
    ImGui::SameLine();
    aida::ui::input_int("##cd_delay", &st.disc_delay_ms, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    aida::ui::toggle_switch("##cd_rec", &st.disc_recurse);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Recurse");
    ImGui::SameLine();
    aida::ui::input_int("##cd_rdepth", &st.disc_recurse_depth, ImVec2(60.f, 28.f));
    ImGui::SameLine();
    aida::ui::toggle_switch("##cd_calib", &st.disc_auto_calibrate);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Auto-calibrate");
    ImGui::SameLine();
    aida::ui::toggle_switch("##cd_fr", &st.disc_follow_redir);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Follow redir");

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Cookie:");
    aida::ui::input_text("##cd_cook", st.disc_cookie, sizeof(st.disc_cookie), "session=...", false, ImVec2(680.f, 28.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "User-Agent:");
    aida::ui::input_text("##cd_ua", st.disc_user_agent, sizeof(st.disc_user_agent), "AiDA-ContentDiscovery/1.0", false, ImVec2(420.f, 28.f));

    ImGui::Spacing();
    if (aida::ui::button("Start", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        content_discovery::config_t cfg;
        cfg.target_url = st.disc_target;
        cfg.wordlist_id = st.disc_wordlist_id;
        cfg.extensions = split_csv(st.disc_extensions);
        cfg.concurrency = std::max(1, st.disc_concurrency);
        cfg.delay_ms = std::max(0, st.disc_delay_ms);
        cfg.match_status = split_csv_ints(st.disc_match_status);
        cfg.filter_status = split_csv_ints(st.disc_filter_status);
        cfg.recurse = st.disc_recurse;
        cfg.recurse_depth = std::max(1, st.disc_recurse_depth);
        cfg.auto_calibrate = st.disc_auto_calibrate;
        cfg.follow_redirects = st.disc_follow_redir;
        cfg.cookie_header = st.disc_cookie;
        cfg.user_agent = st.disc_user_agent;
        uint64_t id = content_discovery::start(cfg);
        if (id == 0) toast_notification::push(std::string("discovery start failed: ") + content_discovery::last_error(), toast_notification::toast_type_t::error);
        else { st.disc_selected = id; toast_notification::push("discovery started", toast_notification::toast_type_t::success); }
    }
    ImGui::SameLine();
    if (aida::ui::button("Stop Selected", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
    {
        if (st.disc_selected != 0) content_discovery::stop(st.disc_selected);
    }
    ImGui::SameLine();
    if (aida::ui::button("Remove Selected", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        if (st.disc_selected != 0) { content_discovery::remove(st.disc_selected); st.disc_selected = 0; }
    }

    ImGui::Spacing();
    auto runs = content_discovery::list();
    if (ImGui::BeginTable("##cd_tbl", 7,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp,
        ImVec2(0.f, 200.f)))
    {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Phase");
        ImGui::TableSetupColumn("Attempts");
        ImGui::TableSetupColumn("Total");
        ImGui::TableSetupColumn("Hits");
        ImGui::TableSetupColumn("Errors");
        ImGui::TableSetupColumn("Filtered");
        ImGui::TableHeadersRow();
        for (auto& d : runs)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char buf[32]; snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(d.id));
            bool sel = (d.id == st.disc_selected);
            if (ImGui::Selectable(buf, sel, ImGuiSelectableFlags_SpanAllColumns)) st.disc_selected = d.id;
            ImGui::TableNextColumn(); ImGui::TextUnformatted(disc_phase_label(d.phase));
            ImGui::TableNextColumn(); ImGui::Text("%d", d.attempts);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.total);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.hits);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.errors);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.filtered);
        }
        ImGui::EndTable();
    }

    if (st.disc_selected != 0)
    {
        auto ds = content_discovery::status(st.disc_selected);
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Hits (%zu) | Calibrated size range: %zu-%zu", ds.hits_list.size(), ds.calibrated_size_lo, ds.calibrated_size_hi);
        if (ImGui::BeginTable("##cd_hits", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.f, 220.f)))
        {
            ImGui::TableSetupColumn("Status");
            ImGui::TableSetupColumn("Bytes");
            ImGui::TableSetupColumn("Latency");
            ImGui::TableSetupColumn("Payload");
            ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (auto& h : ds.hits_list)
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%d", h.status);
                ImGui::TableNextColumn(); ImGui::Text("%zu", h.body_bytes);
                ImGui::TableNextColumn(); ImGui::Text("%llu", static_cast<unsigned long long>(h.latency_ms));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(h.payload.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(h.url.c_str());
            }
            ImGui::EndTable();
        }
    }
}

void render_subdomains(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Subdomain Enumeration");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Domain:");
    ImGui::SameLine();
    aida::ui::input_text("##sub_dom", st.sub_domain, sizeof(st.sub_domain), "example.com", false, ImVec2(280.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Brute wordlist:");
    ImGui::SameLine();
    aida::ui::input_text("##sub_wl", st.sub_wordlist_id, sizeof(st.sub_wordlist_id), "subdomains/top1000", false, ImVec2(240.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Concurrency:");
    ImGui::SameLine();
    aida::ui::input_int("##sub_conc", &st.sub_concurrency, ImVec2(80.f, 28.f));

    ImGui::Spacing();
    aida::ui::toggle_switch("##sub_passive", &st.sub_run_passive);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Passive");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_brute", &st.sub_run_brute);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Brute");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_crt", &st.sub_passive_crtsh);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "crt.sh");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_buf", &st.sub_passive_bufferover);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "bufferover");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_ht", &st.sub_passive_hackertarget);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "hackertarget");

    ImGui::Spacing();
    if (aida::ui::button("Start Enum", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        subdomain_enum::config_t cfg;
        cfg.domain = st.sub_domain;
        cfg.brute_wordlist_id = st.sub_wordlist_id;
        cfg.run_passive = st.sub_run_passive;
        cfg.run_brute = st.sub_run_brute;
        cfg.resolver_concurrency = std::max(1, st.sub_concurrency);
        if (st.sub_passive_crtsh) cfg.passive_sources.push_back("crt.sh");
        if (st.sub_passive_bufferover) cfg.passive_sources.push_back("bufferover");
        if (st.sub_passive_hackertarget) cfg.passive_sources.push_back("hackertarget");
        uint64_t id = subdomain_enum::start(cfg);
        if (id == 0) toast_notification::push(std::string("enum start failed: ") + subdomain_enum::last_error(), toast_notification::toast_type_t::error);
        else { st.sub_selected = id; toast_notification::push("subdomain enum started", toast_notification::toast_type_t::success); }
    }
    ImGui::SameLine();
    if (aida::ui::button("Stop Selected", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
    {
        if (st.sub_selected != 0) subdomain_enum::stop(st.sub_selected);
    }
    ImGui::SameLine();
    if (aida::ui::button("Remove Selected", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        if (st.sub_selected != 0) { subdomain_enum::remove(st.sub_selected); st.sub_selected = 0; }
    }
    ImGui::SameLine();
    if (aida::ui::button("Export CSV", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        if (st.sub_selected != 0)
        {
            std::string csv = subdomain_enum::export_csv(st.sub_selected);
            PWSTR known = nullptr;
            std::string base;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &known)) && known)
            {
                const int needed = WideCharToMultiByte(CP_UTF8, 0, known, -1, nullptr, 0, nullptr, nullptr);
                if (needed > 1)
                {
                    base.assign(static_cast<size_t>(needed - 1), '\0');
                    WideCharToMultiByte(CP_UTF8, 0, known, -1, base.data(), needed, nullptr, nullptr);
                }
                CoTaskMemFree(known);
            }
            if (base.empty()) base = "C:\\Users\\Public\\Downloads";
            char ts[32]; snprintf(ts, sizeof(ts), "%llu", static_cast<unsigned long long>(st.sub_selected));
            std::string path = base + "\\subdomains_" + ts + ".csv";
            std::ofstream f(path, std::ios::binary);
            if (f) { f.write(csv.data(), static_cast<std::streamsize>(csv.size())); toast_notification::push("CSV exported to " + path, toast_notification::toast_type_t::success); }
            else toast_notification::push("CSV export failed", toast_notification::toast_type_t::error);
        }
    }

    ImGui::Spacing();
    auto runs = subdomain_enum::list();
    if (ImGui::BeginTable("##sub_tbl", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp,
        ImVec2(0.f, 160.f)))
    {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Phase");
        ImGui::TableSetupColumn("Passive");
        ImGui::TableSetupColumn("Brute Tried");
        ImGui::TableSetupColumn("Brute Hit");
        ImGui::TableHeadersRow();
        for (auto& e : runs)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char buf[32]; snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(e.id));
            bool sel = (e.id == st.sub_selected);
            if (ImGui::Selectable(buf, sel, ImGuiSelectableFlags_SpanAllColumns)) st.sub_selected = e.id;
            ImGui::TableNextColumn(); ImGui::TextUnformatted(sub_phase_label(e.phase));
            ImGui::TableNextColumn(); ImGui::Text("%d", e.passive_count);
            ImGui::TableNextColumn(); ImGui::Text("%d", e.brute_attempts);
            ImGui::TableNextColumn(); ImGui::Text("%d", e.brute_resolved);
        }
        ImGui::EndTable();
    }

    if (st.sub_selected != 0)
    {
        auto es = subdomain_enum::status(st.sub_selected);
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Subdomains (%zu)", es.results.size());
        if (ImGui::BeginTable("##sub_res", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.f, 240.f)))
        {
            ImGui::TableSetupColumn("FQDN", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Resolves");
            ImGui::TableSetupColumn("IPs");
            ImGui::TableSetupColumn("Sources");
            ImGui::TableHeadersRow();
            for (auto& s : es.results)
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.fqdn.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.resolves ? "yes" : "no");
                ImGui::TableNextColumn();
                std::string ips;
                for (size_t i = 0; i < s.ips.size(); ++i) { if (i) ips += ", "; ips += s.ips[i]; }
                ImGui::TextUnformatted(ips.c_str());
                ImGui::TableNextColumn();
                std::string srcs;
                for (size_t i = 0; i < s.sources.size(); ++i) { if (i) srcs += ", "; srcs += s.sources[i]; }
                ImGui::TextUnformatted(srcs.c_str());
            }
            ImGui::EndTable();
        }
    }
}

void render_payloads(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Payload Library");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Filter:");
    ImGui::SameLine();
    aida::ui::input_text("##pl_filter", st.pl_filter, sizeof(st.pl_filter), "substring", false, ImVec2(220.f, 28.f));

    auto sets = payloads::list_summaries();
    std::string filter_lo = st.pl_filter;
    std::transform(filter_lo.begin(), filter_lo.end(), filter_lo.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

    ImGui::Spacing();
    ImGui::Columns(2, "##pl_cols", true);
    ImGui::SetColumnWidth(0, 360.f);
    ImGui::BeginChild("##pl_list", ImVec2(0.f, 480.f), true);
    for (auto& s : sets)
    {
        if (!filter_lo.empty())
        {
            std::string idlo = s.id;
            std::transform(idlo.begin(), idlo.end(), idlo.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (idlo.find(filter_lo) == std::string::npos) continue;
        }
        bool sel = (std::strcmp(s.id.c_str(), st.pl_selected_id) == 0);
        ImGui::PushID(s.id.c_str());
        char title[256];
        snprintf(title, sizeof(title), "%s%s", s.id.c_str(), s.builtin ? "  [builtin]" : "  [custom]");
        if (ImGui::Selectable(title, sel))
        {
            std::strncpy(st.pl_selected_id, s.id.c_str(), sizeof(st.pl_selected_id) - 1);
            st.pl_selected_id[sizeof(st.pl_selected_id) - 1] = '\0';
        }
        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::NextColumn();
    ImGui::BeginChild("##pl_detail", ImVec2(0.f, 480.f), true);

    if (st.pl_selected_id[0] != '\0')
    {
        const auto* p = payloads::get(st.pl_selected_id);
        if (p)
        {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "%s", p->label.c_str());
            ImGui::TextWrapped("%s", p->description.c_str());
            ImGui::Text("Entries: %zu", p->entries.size());
            ImGui::Spacing();
            ImGui::BeginChild("##pl_entries", ImVec2(0.f, 320.f), true);
            for (auto& e : p->entries) ImGui::TextUnformatted(e.c_str());
            ImGui::EndChild();
            if (!p->builtin)
            {
                if (aida::ui::button("Delete Set", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
                {
                    std::string id = p->id;
                    if (payloads::remove_custom_set(id))
                    {
                        st.pl_selected_id[0] = '\0';
                        toast_notification::push("Removed custom set " + id, toast_notification::toast_type_t::success);
                    }
                    else
                    {
                        toast_notification::push("Remove failed: " + payloads::last_error(), toast_notification::toast_type_t::error);
                    }
                }
            }
        }
    }
    else
    {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "(select a set on the left)");
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Add custom set:");
    aida::ui::input_text("##pl_new_id", st.pl_new_id, sizeof(st.pl_new_id), "id e.g. custom/xss-fast", false, ImVec2(280.f, 28.f));
    aida::ui::input_text("##pl_new_label", st.pl_new_label, sizeof(st.pl_new_label), "label", false, ImVec2(280.f, 28.f));
    aida::ui::input_text("##pl_new_desc", st.pl_new_desc, sizeof(st.pl_new_desc), "description", false, ImVec2(420.f, 28.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Entries (one per line):");
    ImGui::InputTextMultiline("##pl_new_entries", st.pl_new_entries, sizeof(st.pl_new_entries), ImVec2(0.f, 96.f));
    if (aida::ui::button("Add", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        std::vector<std::string> entries;
        std::string cur;
        for (const char* p2 = st.pl_new_entries; *p2; ++p2)
        {
            if (*p2 == '\n') { if (!cur.empty()) entries.push_back(cur); cur.clear(); }
            else if (*p2 != '\r') cur.push_back(*p2);
        }
        if (!cur.empty()) entries.push_back(cur);
        if (payloads::add_custom_set(st.pl_new_id, st.pl_new_label, st.pl_new_desc, entries))
        {
            toast_notification::push("Custom set added", toast_notification::toast_type_t::success);
            st.pl_new_id[0] = '\0';
            st.pl_new_label[0] = '\0';
            st.pl_new_desc[0] = '\0';
            st.pl_new_entries[0] = '\0';
        }
        else
        {
            toast_notification::push("Add failed: " + payloads::last_error(), toast_notification::toast_type_t::error);
        }
    }

    ImGui::EndChild();
    ImGui::Columns(1);
}

}

bool initialize()
{
    auto& s = ui();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) return true;
    payloads::initialize();
    crawler::initialize();
    content_discovery::initialize();
    subdomain_enum::initialize();
    return true;
}

void shutdown()
{
    auto& s = ui();
    if (!s.initialized.exchange(false)) return;
    crawler::shutdown();
    content_discovery::shutdown();
    subdomain_enum::shutdown();
    payloads::shutdown();
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    auto& s = ui();
    if (!s.initialized.load()) initialize();

    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##recon_view", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    const char* labels[] = { "Crawler", "Content Discovery", "Subdomains", "Payload Library" };
    for (int i = 0; i < 4; ++i)
    {
        bool is_active = (s.active_tab == i);
        if (i > 0) ImGui::SameLine();
        const aida::ui::button_kind_t k = is_active ? aida::ui::button_kind_t::primary : aida::ui::button_kind_t::secondary;
        if (aida::ui::button(labels[i], k, aida::ui::size_t_::sm)) s.active_tab = i;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    switch (static_cast<tab_t>(s.active_tab))
    {
        case tab_t::crawler:           render_crawler(s, alpha); break;
        case tab_t::content_discovery: render_content_discovery(s, alpha); break;
        case tab_t::subdomains:        render_subdomains(s, alpha); break;
        case tab_t::payloads:          render_payloads(s, alpha); break;
    }

    ImGui::EndChild();
}

}
}
}
