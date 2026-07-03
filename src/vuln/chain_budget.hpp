#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

enum class budget_exhaustion_t
{
    none,
    cancelled,
    elapsed_time,
    functions,
    links,
    paths,
    branches,
    calls,
    solver_queries,
    facts,
    report_events
};

struct budget_limits_t
{
    uint32_t total_timeout_ms = 120000;
    uint32_t solver_timeout_ms = 5000;
    size_t max_functions = 4096;
    size_t max_links = 512;
    size_t max_paths_per_link = 64;
    size_t max_branch_obligations = 256;
    size_t max_call_obligations = 256;
    size_t max_solver_queries = 4096;
    size_t max_facts = 65536;
    size_t max_report_events = 16384;
};

class cancellation_token_t
{
public:
    cancellation_token_t();
    void cancel() const;
    bool requested() const;
    void reset();

private:
    std::shared_ptr<std::atomic_bool> m_cancelled;
};

struct resume_cursor_t
{
    std::string phase;
    size_t link_index = 0;
    size_t path_index = 0;
    size_t solver_query_index = 0;
    std::string document_hash;
    std::string snapshot_id;
    bool sealed = false;
};

struct job_record_t
{
    std::string job_id;
    std::string chain_id;
    std::string document_hash;
    std::string status;
    std::string phase;
    resume_cursor_t cursor;
    uint64_t started_ms = 0;
    uint64_t updated_ms = 0;
    uint64_t elapsed_ms = 0;
    bool partial = false;
    bool resumable = false;
    std::vector<std::string> failure_codes;
};

class budget_state_t
{
public:
    budget_state_t();
    explicit budget_state_t(const budget_limits_t& limits);

    void reset(const budget_limits_t& limits);
    bool cancelled(const cancellation_token_t& token);
    bool consume_function();
    bool consume_link();
    bool consume_path(size_t paths_in_current_link);
    bool consume_branch();
    bool consume_call();
    bool consume_solver_query();
    bool consume_fact();
    bool consume_report_event();

    budget_exhaustion_t exhaustion() const;
    uint64_t elapsed_ms() const;
    const budget_limits_t& limits() const;

private:
    bool deadline_expired() const;
    bool set_exhaustion(budget_exhaustion_t value);

    budget_limits_t m_limits;
    std::chrono::steady_clock::time_point m_started;
    budget_exhaustion_t m_exhaustion = budget_exhaustion_t::none;
    size_t m_functions = 0;
    size_t m_links = 0;
    size_t m_paths = 0;
    size_t m_branches = 0;
    size_t m_calls = 0;
    size_t m_solver_queries = 0;
    size_t m_facts = 0;
    size_t m_report_events = 0;
};

const char* budget_exhaustion_str(budget_exhaustion_t value);
nlohmann::json to_json(const budget_limits_t& limits);
nlohmann::json to_json(const resume_cursor_t& cursor);
nlohmann::json to_json(const job_record_t& record);

}
}
}
