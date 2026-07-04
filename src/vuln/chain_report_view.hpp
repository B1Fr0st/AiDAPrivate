#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <kernwin.hpp>

namespace aida
{
namespace vuln
{

struct chain_report_view_snapshot_t
{
    bool stopping = false;
    bool running = false;
    bool has_draft = false;
    bool has_result = false;
    bool stale = false;
    std::string status;
    std::string phase;
    std::string job_id;
    std::string chain_id;
    std::string current_function;
    std::string verdict;
    std::string error;
    std::uint64_t idb_generation = 0;
    std::uint64_t hexrays_generation = 0;
    std::uint64_t job_idb_generation = 0;
    std::uint64_t job_hexrays_generation = 0;
    std::uint64_t elapsed_ms = 0;
    std::size_t queue_depth = 0;
    std::size_t pending_gateway_requests = 0;
    std::size_t progress_current = 0;
    std::size_t progress_total = 0;
    std::vector<std::string> events;
    nlohmann::json result = nlohmann::json::object();
    nlohmann::json journal = nlohmann::json::object();
    nlohmann::json gateway_metrics = nlohmann::json::object();
};

class chain_report_view_t
{
public:
    chain_report_view_t();
    ~chain_report_view_t();

    chain_report_view_t(const chain_report_view_t&) = delete;
    chain_report_view_t& operator=(const chain_report_view_t&) = delete;

    bool open();
    void detach();
    bool is_open() const;
    void render(const chain_report_view_snapshot_t& snapshot);

private:
    void rebuild_lines(const chain_report_view_snapshot_t& snapshot);
    void add_line(const std::string& line);
    void add_json_preview(const nlohmann::json& value, std::size_t max_lines);

    TWidget* m_widget = nullptr;
    strvec_t m_lines;
};

}
}
