#include "chain_budget.hpp"

#include <chrono>

namespace aida
{
namespace vuln
{
namespace chain
{

cancellation_token_t::cancellation_token_t()
    : m_cancelled(std::make_shared<std::atomic_bool>(false))
{
}

void cancellation_token_t::cancel() const
{
    m_cancelled->store(true, std::memory_order_release);
}

bool cancellation_token_t::requested() const
{
    return m_cancelled->load(std::memory_order_acquire);
}

void cancellation_token_t::reset()
{
    m_cancelled->store(false, std::memory_order_release);
}

budget_state_t::budget_state_t()
{
    reset({});
}

budget_state_t::budget_state_t(const budget_limits_t& limits)
{
    reset(limits);
}

void budget_state_t::reset(const budget_limits_t& limits)
{
    m_limits = limits;
    m_started = std::chrono::steady_clock::now();
    m_exhaustion = budget_exhaustion_t::none;
    m_functions = 0;
    m_links = 0;
    m_paths = 0;
    m_branches = 0;
    m_calls = 0;
    m_solver_queries = 0;
    m_facts = 0;
    m_report_events = 0;
}

bool budget_state_t::deadline_expired() const
{
    if (m_limits.total_timeout_ms == 0)
        return false;
    return elapsed_ms() >= m_limits.total_timeout_ms;
}

bool budget_state_t::set_exhaustion(budget_exhaustion_t value)
{
    if (m_exhaustion == budget_exhaustion_t::none)
        m_exhaustion = value;
    return false;
}

bool budget_state_t::cancelled(const cancellation_token_t& token)
{
    if (token.requested())
        return set_exhaustion(budget_exhaustion_t::cancelled);
    if (deadline_expired())
        return set_exhaustion(budget_exhaustion_t::elapsed_time);
    return false;
}

bool budget_state_t::consume_function()
{
    if (++m_functions > m_limits.max_functions)
        return set_exhaustion(budget_exhaustion_t::functions);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

bool budget_state_t::consume_link()
{
    if (++m_links > m_limits.max_links)
        return set_exhaustion(budget_exhaustion_t::links);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

bool budget_state_t::consume_path(size_t paths_in_current_link)
{
    ++m_paths;
    if (paths_in_current_link > m_limits.max_paths_per_link)
        return set_exhaustion(budget_exhaustion_t::paths);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

bool budget_state_t::consume_branch()
{
    if (++m_branches > m_limits.max_branch_obligations)
        return set_exhaustion(budget_exhaustion_t::branches);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

bool budget_state_t::consume_call()
{
    if (++m_calls > m_limits.max_call_obligations)
        return set_exhaustion(budget_exhaustion_t::calls);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

bool budget_state_t::consume_solver_query()
{
    if (++m_solver_queries > m_limits.max_solver_queries)
        return set_exhaustion(budget_exhaustion_t::solver_queries);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

bool budget_state_t::consume_fact()
{
    if (++m_facts > m_limits.max_facts)
        return set_exhaustion(budget_exhaustion_t::facts);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

bool budget_state_t::consume_report_event()
{
    if (++m_report_events > m_limits.max_report_events)
        return set_exhaustion(budget_exhaustion_t::report_events);
    return !deadline_expired() || set_exhaustion(budget_exhaustion_t::elapsed_time);
}

budget_exhaustion_t budget_state_t::exhaustion() const
{
    return m_exhaustion;
}

uint64_t budget_state_t::elapsed_ms() const
{
    const auto now = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now - m_started).count());
}

const budget_limits_t& budget_state_t::limits() const
{
    return m_limits;
}

const char* budget_exhaustion_str(budget_exhaustion_t value)
{
    switch (value)
    {
    case budget_exhaustion_t::none: return "none";
    case budget_exhaustion_t::cancelled: return "cancelled";
    case budget_exhaustion_t::elapsed_time: return "elapsed_time";
    case budget_exhaustion_t::functions: return "functions";
    case budget_exhaustion_t::links: return "links";
    case budget_exhaustion_t::paths: return "paths";
    case budget_exhaustion_t::branches: return "branches";
    case budget_exhaustion_t::calls: return "calls";
    case budget_exhaustion_t::solver_queries: return "solver_queries";
    case budget_exhaustion_t::facts: return "facts";
    case budget_exhaustion_t::report_events: return "report_events";
    }
    return "none";
}

nlohmann::json to_json(const budget_limits_t& limits)
{
    return nlohmann::json{
        {"total_timeout_ms", limits.total_timeout_ms},
        {"solver_timeout_ms", limits.solver_timeout_ms},
        {"max_functions", limits.max_functions},
        {"max_links", limits.max_links},
        {"max_paths_per_link", limits.max_paths_per_link},
        {"max_branch_obligations", limits.max_branch_obligations},
        {"max_call_obligations", limits.max_call_obligations},
        {"max_solver_queries", limits.max_solver_queries},
        {"max_facts", limits.max_facts},
        {"max_report_events", limits.max_report_events}
    };
}

nlohmann::json to_json(const resume_cursor_t& cursor)
{
    return nlohmann::json{
        {"phase", cursor.phase},
        {"link_index", cursor.link_index},
        {"path_index", cursor.path_index},
        {"solver_query_index", cursor.solver_query_index},
        {"document_hash", cursor.document_hash},
        {"snapshot_id", cursor.snapshot_id},
        {"sealed", cursor.sealed}
    };
}

nlohmann::json to_json(const job_record_t& record)
{
    return nlohmann::json{
        {"job_id", record.job_id},
        {"chain_id", record.chain_id},
        {"document_hash", record.document_hash},
        {"status", record.status},
        {"phase", record.phase},
        {"cursor", to_json(record.cursor)},
        {"started_ms", record.started_ms},
        {"updated_ms", record.updated_ms},
        {"elapsed_ms", record.elapsed_ms},
        {"partial", record.partial},
        {"resumable", record.resumable},
        {"failure_codes", record.failure_codes}
    };
}

}
}
}
