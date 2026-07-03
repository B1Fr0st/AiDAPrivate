#include "chain_solver.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string read_string(const nlohmann::json& value, const char* key, const std::string& fallback = {})
{
    if (!value.is_object() || !value.contains(key))
        return fallback;
    const auto& item = value.at(key);
    if (item.is_string())
        return item.get<std::string>();
    if (item.is_boolean())
        return item.get<bool>() ? "true" : "false";
    if (item.is_number_integer())
        return std::to_string(item.get<int64_t>());
    if (item.is_number_unsigned())
        return std::to_string(item.get<uint64_t>());
    return fallback;
}

uint32_t read_u32(const nlohmann::json& value, const char* key, uint32_t fallback = 0)
{
    if (!value.is_object() || !value.contains(key))
        return fallback;
    const auto& item = value.at(key);
    if (item.is_number_unsigned())
        return static_cast<uint32_t>(item.get<uint64_t>());
    if (item.is_number_integer())
        return static_cast<uint32_t>(item.get<int64_t>());
    return fallback;
}

std::string query_id_for(const solver_obligation_t& obligation)
{
    return "smt_" + canonical_json_hash(to_json(obligation));
}

failure_code_t default_unsat_failure(solver_obligation_kind_t kind)
{
    switch (kind)
    {
    case solver_obligation_kind_t::branch: return failure_code_t::branch_required_direction_unsat;
    case solver_obligation_kind_t::value: return failure_code_t::postcondition_precondition_mismatch;
    case solver_obligation_kind_t::alias: return failure_code_t::alias_must_not_proven;
    case solver_obligation_kind_t::protocol: return failure_code_t::protocol_state_mismatch;
    case solver_obligation_kind_t::objective: return failure_code_t::objective_not_achieved;
    case solver_obligation_kind_t::generic: return failure_code_t::solver_unknown;
    }
    return failure_code_t::solver_unknown;
}

failure_code_t default_unknown_failure(solver_obligation_kind_t kind)
{
    switch (kind)
    {
    case solver_obligation_kind_t::branch: return failure_code_t::branch_required_direction_unknown;
    case solver_obligation_kind_t::value: return failure_code_t::postcondition_precondition_mismatch;
    case solver_obligation_kind_t::alias: return failure_code_t::alias_must_not_proven;
    case solver_obligation_kind_t::protocol: return failure_code_t::protocol_state_mismatch;
    case solver_obligation_kind_t::objective: return failure_code_t::objective_not_achieved;
    case solver_obligation_kind_t::generic: return failure_code_t::solver_unknown;
    }
    return failure_code_t::solver_unknown;
}

bool result_matches_expected(smt::result_t result, solver_expected_t expected)
{
    return (expected == solver_expected_t::sat && result == smt::result_t::sat) ||
           (expected == solver_expected_t::unsat && result == smt::result_t::unsat);
}

}

chain_solver_t::chain_solver_t(const budget_limits_t& limits)
    : m_limits(limits)
{
}

solver_obligation_result_t chain_solver_t::evaluate(const solver_obligation_t& obligation,
                                                    budget_state_t& budget,
                                                    const cancellation_token_t& token)
{
    solver_obligation_result_t out;
    out.obligation_id = obligation.obligation_id;
    out.kind = obligation.kind;
    out.query_id = query_id_for(obligation);
    out.acceptance_blocker = criticality_blocks_acceptance(obligation.criticality);

    if (token.requested() || budget.cancelled(token))
    {
        out.verdict = chain_verdict_t::inconclusive;
        out.proof_state = contract_proof_state_t::unknown;
        out.failure = failure_code_t::resource_exhausted;
        out.rationale = "solver obligation cancelled before query";
        return out;
    }

    if (obligation.smtlib2.empty() && obligation.declared_state != contract_proof_state_t::unknown)
    {
        if (obligation.declared_state == contract_proof_state_t::proven)
        {
            out.verdict = chain_verdict_t::confirmed;
            out.proof_state = contract_proof_state_t::proven;
            out.failure = failure_code_t::none;
            out.acceptance_blocker = false;
            out.rationale = "declared evidence state is proven";
            return out;
        }
        if (obligation.declared_state == contract_proof_state_t::refuted)
        {
            out.verdict = chain_verdict_t::refuted;
            out.proof_state = contract_proof_state_t::refuted;
            out.failure = obligation.unsat_failure == failure_code_t::none ? default_unsat_failure(obligation.kind) : obligation.unsat_failure;
            out.rationale = "declared evidence state refutes the obligation";
            return out;
        }
        if (obligation.declared_state == contract_proof_state_t::timeout)
            out.verdict = chain_verdict_t::timeout;
        else if (obligation.declared_state == contract_proof_state_t::unsupported)
            out.verdict = chain_verdict_t::unsupported;
        else
            out.verdict = chain_verdict_t::inconclusive;
        out.proof_state = obligation.declared_state;
        out.failure = obligation.declared_state == contract_proof_state_t::timeout ? failure_code_t::solver_timeout :
            (obligation.unknown_failure == failure_code_t::none ? default_unknown_failure(obligation.kind) : obligation.unknown_failure);
        out.rationale = "declared evidence state does not prove the obligation";
        return out;
    }

    if (obligation.smtlib2.empty())
    {
        out.verdict = chain_verdict_t::unsupported;
        out.proof_state = contract_proof_state_t::unsupported;
        out.failure = obligation.unknown_failure == failure_code_t::none ? default_unknown_failure(obligation.kind) : obligation.unknown_failure;
        out.rationale = "solver obligation has no formula";
        return out;
    }

    {
        std::lock_guard<std::mutex> guard(m_mutex);
        const auto it = m_cache.find(out.query_id);
        if (it != m_cache.end())
        {
            out = it->second;
            out.cached = true;
            return out;
        }
    }

    if (!budget.consume_solver_query())
    {
        out.verdict = chain_verdict_t::timeout;
        out.proof_state = contract_proof_state_t::timeout;
        out.failure = failure_code_t::resource_exhausted;
        out.rationale = "solver query budget exhausted";
        return out;
    }

    const uint32_t timeout_ms = obligation.timeout_ms != 0 ? obligation.timeout_ms : m_limits.solver_timeout_ms;
    const auto start = std::chrono::steady_clock::now();
    smt::result_t smt_result = smt::result_t::unknown;
    const bool ok = smt::SmtContext::smtlib2_quick_check(obligation.smtlib2, smt_result, timeout_ms);
    const auto end = std::chrono::steady_clock::now();
    out.solve_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
    out.solver_result.result = smt_result;
    out.solver_result.solve_ms = out.solve_ms;
    out.solver_result.smtlib_dump = obligation.smtlib2;

    if (!ok)
    {
        out.verdict = chain_verdict_t::unsupported;
        out.proof_state = contract_proof_state_t::unsupported;
        out.failure = obligation.unknown_failure == failure_code_t::none ? default_unknown_failure(obligation.kind) : obligation.unknown_failure;
        out.rationale = "solver rejected the formula";
        out.solver_result.reason = out.rationale;
    }
    else if (result_matches_expected(smt_result, obligation.expected))
    {
        out.verdict = chain_verdict_t::confirmed;
        out.proof_state = contract_proof_state_t::proven;
        out.failure = failure_code_t::none;
        out.acceptance_blocker = false;
        out.rationale = "solver result matched required proof state";
    }
    else if (smt_result == smt::result_t::unknown)
    {
        const bool likely_timeout = timeout_ms != 0 && out.solve_ms >= timeout_ms;
        out.verdict = likely_timeout ? chain_verdict_t::timeout : chain_verdict_t::inconclusive;
        out.proof_state = likely_timeout ? contract_proof_state_t::timeout : contract_proof_state_t::unknown;
        out.failure = likely_timeout ? failure_code_t::solver_timeout :
            (obligation.unknown_failure == failure_code_t::none ? default_unknown_failure(obligation.kind) : obligation.unknown_failure);
        out.rationale = likely_timeout ? "solver timed out or reached the query budget" : "solver returned unknown";
        out.solver_result.reason = out.rationale;
    }
    else
    {
        out.verdict = chain_verdict_t::refuted;
        out.proof_state = contract_proof_state_t::refuted;
        out.failure = obligation.unsat_failure == failure_code_t::none ? default_unsat_failure(obligation.kind) : obligation.unsat_failure;
        out.rationale = "solver result contradicted required proof state";
        out.solver_result.reason = out.rationale;
    }

    {
        std::lock_guard<std::mutex> guard(m_mutex);
        m_cache[out.query_id] = out;
    }
    return out;
}

solver_batch_result_t chain_solver_t::evaluate_all(const std::vector<solver_obligation_t>& obligations,
                                                   budget_state_t& budget,
                                                   const cancellation_token_t& token)
{
    solver_batch_result_t out;
    out.verdict = chain_verdict_t::confirmed;
    for (const solver_obligation_t& obligation : obligations)
    {
        solver_obligation_result_t result = evaluate(obligation, budget, token);
        out.verdict = combine_verdict(out.verdict, result.verdict);
        if (result.failure != failure_code_t::none)
        {
            out.failures.push_back(result.failure);
            if (result.acceptance_blocker)
                out.has_acceptance_blocker = true;
        }
        out.results.push_back(std::move(result));
        if (token.requested() || budget.exhaustion() != budget_exhaustion_t::none)
            break;
    }
    if (out.has_acceptance_blocker && out.verdict == chain_verdict_t::confirmed)
        out.verdict = chain_verdict_t::inconclusive;
    return out;
}

void chain_solver_t::clear_cache()
{
    std::lock_guard<std::mutex> guard(m_mutex);
    m_cache.clear();
}

size_t chain_solver_t::cache_size() const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_cache.size();
}

solver_obligation_kind_t parse_solver_obligation_kind(const std::string& value)
{
    const std::string s = lower_copy(value);
    if (s == "branch") return solver_obligation_kind_t::branch;
    if (s == "value") return solver_obligation_kind_t::value;
    if (s == "alias") return solver_obligation_kind_t::alias;
    if (s == "protocol") return solver_obligation_kind_t::protocol;
    if (s == "objective") return solver_obligation_kind_t::objective;
    return solver_obligation_kind_t::generic;
}

solver_expected_t parse_solver_expected(const std::string& value)
{
    const std::string s = lower_copy(value);
    if (s == "unsat" || s == "refuted" || s == "false")
        return solver_expected_t::unsat;
    return solver_expected_t::sat;
}

const char* solver_obligation_kind_str(solver_obligation_kind_t kind)
{
    switch (kind)
    {
    case solver_obligation_kind_t::branch: return "branch";
    case solver_obligation_kind_t::value: return "value";
    case solver_obligation_kind_t::alias: return "alias";
    case solver_obligation_kind_t::protocol: return "protocol";
    case solver_obligation_kind_t::objective: return "objective";
    case solver_obligation_kind_t::generic: return "generic";
    }
    return "generic";
}

const char* solver_expected_str(solver_expected_t expected)
{
    switch (expected)
    {
    case solver_expected_t::sat: return "sat";
    case solver_expected_t::unsat: return "unsat";
    }
    return "sat";
}

solver_obligation_t solver_obligation_from_json(const nlohmann::json& value,
                                                const std::string& default_link_id,
                                                solver_obligation_kind_t default_kind)
{
    solver_obligation_t out;
    if (!value.is_object())
    {
        out.smtlib2 = value.is_string() ? value.get<std::string>() : value.dump();
        out.kind = default_kind;
        out.link_id = default_link_id;
        out.obligation_id = "solver_" + stable_hash_hex(out.smtlib2 + default_link_id);
        out.unsat_failure = default_unsat_failure(out.kind);
        out.unknown_failure = default_unknown_failure(out.kind);
        return out;
    }
    out.obligation_id = read_string(value, "obligation_id", read_string(value, "id"));
    out.kind = parse_solver_obligation_kind(read_string(value, "kind", solver_obligation_kind_str(default_kind)));
    out.link_id = read_string(value, "link_id", default_link_id);
    out.description = read_string(value, "description", read_string(value, "rationale"));
    out.smtlib2 = read_string(value, "smtlib2", read_string(value, "formula"));
    out.expected = parse_solver_expected(read_string(value, "expected", read_string(value, "required_result", "sat")));
    out.criticality = parse_criticality(read_string(value, "criticality", "chain_critical"));
    out.declared_state = parse_proof_state(read_string(value, "proof_state", read_string(value, "state", "unknown")));
    out.unsat_failure = parse_failure_code(read_string(value, "unsat_failure"));
    out.unknown_failure = parse_failure_code(read_string(value, "unknown_failure"));
    if (out.unsat_failure == failure_code_t::none)
        out.unsat_failure = default_unsat_failure(out.kind);
    if (out.unknown_failure == failure_code_t::none)
        out.unknown_failure = default_unknown_failure(out.kind);
    out.timeout_ms = read_u32(value, "timeout_ms", 0);
    if (out.obligation_id.empty())
        out.obligation_id = "solver_" + stable_hash_hex(to_json(out).dump());
    return out;
}

nlohmann::json to_json(const solver_obligation_t& obligation)
{
    return nlohmann::json{
        {"obligation_id", obligation.obligation_id},
        {"kind", solver_obligation_kind_str(obligation.kind)},
        {"link_id", obligation.link_id},
        {"description", obligation.description},
        {"smtlib2", obligation.smtlib2},
        {"expected", solver_expected_str(obligation.expected)},
        {"criticality", criticality_str(obligation.criticality)},
        {"declared_state", proof_state_str(obligation.declared_state)},
        {"unsat_failure", failure_code_str(obligation.unsat_failure)},
        {"unknown_failure", failure_code_str(obligation.unknown_failure)},
        {"timeout_ms", obligation.timeout_ms}
    };
}

nlohmann::json to_json(const solver_obligation_result_t& result)
{
    return nlohmann::json{
        {"obligation_id", result.obligation_id},
        {"query_id", result.query_id},
        {"kind", solver_obligation_kind_str(result.kind)},
        {"verdict", verdict_str(result.verdict)},
        {"proof_state", proof_state_str(result.proof_state)},
        {"failure", failure_code_str(result.failure)},
        {"acceptance_blocker", result.acceptance_blocker},
        {"solve_ms", result.solve_ms},
        {"cached", result.cached},
        {"rationale", result.rationale},
        {"solver_result", smt::to_json(result.solver_result)}
    };
}

nlohmann::json to_json(const solver_batch_result_t& result)
{
    nlohmann::json results = nlohmann::json::array();
    for (const solver_obligation_result_t& item : result.results)
        results.push_back(to_json(item));
    nlohmann::json failures = nlohmann::json::array();
    for (failure_code_t code : result.failures)
        failures.push_back(failure_code_str(code));
    return nlohmann::json{
        {"verdict", verdict_str(result.verdict)},
        {"results", results},
        {"failures", failures},
        {"has_acceptance_blocker", result.has_acceptance_blocker}
    };
}

}
}
}
