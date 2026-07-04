#include "chain_report_view.hpp"

#include <algorithm>
#include <sstream>

namespace aida
{
namespace vuln
{
namespace
{

constexpr const char* k_chain_view_title = "AiDA Chain Verify";
constexpr std::size_t k_max_view_lines = 512;
constexpr std::size_t k_max_line_chars = 260;

std::string trim_line(std::string line)
{
    if (line.size() <= k_max_line_chars)
        return line;
    line.resize(k_max_line_chars - 3);
    line += "...";
    return line;
}

std::string yes_no(bool value)
{
    return value ? "yes" : "no";
}

std::string progress_text(std::size_t current, std::size_t total)
{
    if (total == 0)
        return "indeterminate";
    std::ostringstream oss;
    oss << current << "/" << total;
    return oss.str();
}

}

chain_report_view_t::chain_report_view_t() = default;

chain_report_view_t::~chain_report_view_t()
{
    detach();
}

bool chain_report_view_t::open()
{
    TWidget* existing = find_widget(k_chain_view_title);
    if (existing != nullptr)
    {
        m_widget = existing;
        activate_widget(m_widget, true);
        return true;
    }

    if (m_lines.empty())
        m_lines.push_back(simpleline_t("AiDA Chain Verify"));

    simpleline_place_t min_place(0);
    simpleline_place_t max_place(static_cast<int>(k_max_view_lines));
    simpleline_place_t cur_place(0);
    m_widget = create_custom_viewer(k_chain_view_title, &min_place, &max_place, &cur_place, nullptr, &m_lines, nullptr, this);
    if (m_widget == nullptr)
        return false;

    display_widget(m_widget, WOPN_DP_TAB | WOPN_RESTORE | WOPN_PERSIST | WOPN_NOT_CLOSED_BY_ESC);
    attach_action_to_popup(m_widget, nullptr, "aida:chain_verify_current_function_as_link", "AiDA/Chain Verify/", 0);
    attach_action_to_popup(m_widget, nullptr, "aida:chain_verify_start", "AiDA/Chain Verify/", 0);
    attach_action_to_popup(m_widget, nullptr, "aida:chain_verify_cancel", "AiDA/Chain Verify/", 0);
    attach_action_to_popup(m_widget, nullptr, "aida:chain_verify_copy_result_json", "AiDA/Chain Verify/", 0);
    return true;
}

void chain_report_view_t::detach()
{
    if (m_widget == nullptr)
        return;
    close_widget(m_widget, WCLS_SAVE | WCLS_CLOSE_LATER);
    m_widget = nullptr;
}

bool chain_report_view_t::is_open() const
{
    return m_widget != nullptr;
}

void chain_report_view_t::render(const chain_report_view_snapshot_t& snapshot)
{
    rebuild_lines(snapshot);
    if (m_widget != nullptr)
        refresh_custom_viewer(m_widget);
}

void chain_report_view_t::rebuild_lines(const chain_report_view_snapshot_t& snapshot)
{
    m_lines.clear();
    add_line("AiDA Chain Verify");
    add_line("");
    add_line("Status: " + (snapshot.status.empty() ? std::string("idle") : snapshot.status));
    add_line("Phase: " + (snapshot.phase.empty() ? std::string("idle") : snapshot.phase));
    add_line("Running: " + yes_no(snapshot.running));
    add_line("Stopping: " + yes_no(snapshot.stopping));
    add_line("Draft: " + yes_no(snapshot.has_draft));
    add_line("Result: " + yes_no(snapshot.has_result));
    add_line("Progress: " + progress_text(snapshot.progress_current, snapshot.progress_total));
    if (!snapshot.current_function.empty())
        add_line("Current function: " + snapshot.current_function);
    if (!snapshot.chain_id.empty())
        add_line("Chain: " + snapshot.chain_id);
    if (!snapshot.job_id.empty())
        add_line("Job: " + snapshot.job_id);
    if (!snapshot.verdict.empty())
        add_line("Verdict: " + snapshot.verdict);
    if (!snapshot.error.empty())
        add_line("Error: " + snapshot.error);
    add_line("IDB generation: " + std::to_string(snapshot.idb_generation));
    add_line("Hex-Rays generation: " + std::to_string(snapshot.hexrays_generation));
    if (snapshot.job_idb_generation != 0 || snapshot.job_hexrays_generation != 0)
    {
        add_line("Job generations: idb=" + std::to_string(snapshot.job_idb_generation) +
            " hexrays=" + std::to_string(snapshot.job_hexrays_generation));
    }
    add_line("Queue depth: " + std::to_string(snapshot.queue_depth));
    add_line("Gateway pending: " + std::to_string(snapshot.pending_gateway_requests));
    add_line("Elapsed ms: " + std::to_string(snapshot.elapsed_ms));
    add_line("");
    add_line("Recent events");
    if (snapshot.events.empty())
        add_line("  none");
    else
    {
        for (const std::string& event : snapshot.events)
            add_line("  " + event);
    }
    add_line("");
    add_line("Gateway metrics");
    add_json_preview(snapshot.gateway_metrics, 24);
    if (!snapshot.result.empty())
    {
        add_line("");
        add_line("Result JSON");
        add_json_preview(snapshot.result, 160);
    }
    else if (!snapshot.journal.empty())
    {
        add_line("");
        add_line("Recovery journal");
        add_json_preview(snapshot.journal, 80);
    }
    while (m_lines.size() > k_max_view_lines)
        m_lines.pop_back();
}

void chain_report_view_t::add_line(const std::string& line)
{
    m_lines.push_back(simpleline_t(trim_line(line).c_str()));
}

void chain_report_view_t::add_json_preview(const nlohmann::json& value, std::size_t max_lines)
{
    std::string dump;
    try
    {
        dump = value.dump(2);
    }
    catch (...)
    {
        dump = "{\"error\":\"json_preview_failed\"}";
    }

    std::istringstream stream(dump);
    std::string line;
    std::size_t emitted = 0;
    while (std::getline(stream, line))
    {
        if (emitted >= max_lines)
        {
            add_line("  ...");
            break;
        }
        add_line("  " + line);
        ++emitted;
    }
    if (emitted == 0)
        add_line("  null");
}

}
}
