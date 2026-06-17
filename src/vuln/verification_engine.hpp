#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>

#include "vuln_common.hpp"
#include "smt_solver.hpp"
#include "symbolic_engine.hpp"

namespace aida
{
namespace vuln
{
namespace verify
{

enum class verdict_t
{
    confirmed,
    refuted,
    inconclusive,
    timeout,
    unsupported
};

inline const char* verdict_str(verdict_t v)
{
    switch (v)
    {
    case verdict_t::confirmed:    return "confirmed";
    case verdict_t::refuted:      return "refuted";
    case verdict_t::inconclusive: return "inconclusive";
    case verdict_t::timeout:      return "timeout";
    case verdict_t::unsupported:  return "unsupported";
    }
    return "inconclusive";
}

struct path_verification_t
{
    verdict_t                                  verdict = verdict_t::inconclusive;
    smt::result_t                              smt_result = smt::result_t::unknown;
    std::vector<symbolic::path_constraint_t>   constraints;
    std::vector<smt::model_entry_t>            witness;
    std::vector<ea_t>                          cited_eas;
    confidence_t                               adjusted_confidence = confidence_t::plausible;
    std::string                                rationale;
    uint64_t                                   solve_ms = 0;
    bool                                       via_seh_handler = false;
    uint64_t                                   cached_at = 0;
};

struct exploit_constraints_t
{
    bool     ascii_only = false;
    bool     no_null_bytes = false;
    int      alignment = 1;
    uint64_t max_byte = 255;
    bool     printable_only = false;
};

struct exploit_input_t
{
    bool                              found = false;
    std::vector<smt::model_entry_t>   inputs;
    std::vector<uint8_t>              concrete_bytes;
    std::vector<ea_t>                 cited_eas;
    std::string                       summary;
    std::string                       rationale;
};

struct loop_bound_proof_t
{
    verdict_t   verdict = verdict_t::inconclusive;
    int64_t     max_index = 0;
    int64_t     min_index = 0;
    int64_t     buffer_size = 0;
    bool        overflow_provable = false;
    std::string rationale;
};

struct triage_result_t
{
    std::string stage_reached;
    verdict_t final_verdict = verdict_t::inconclusive;
    smt::solve_result_t sat_check;
    path_verification_t taint_check;
    exploit_input_t exploit_input;
};

struct cache_key_t
{
    ea_t     func_ea = BADADDR;
    ea_t     sink_ea = BADADDR;
    ea_t     source_ea = BADADDR;
    uint32_t sig_db_rev = 0;

    bool operator==(const cache_key_t& o) const;
};

struct cache_key_hash_t
{
    size_t operator()(const cache_key_t& k) const noexcept;
};

struct wire_constraint_t
{
    uint64_t    buffer_offset = 0;
    int         width_bytes = 0;
    uint64_t    equal_to = 0;
    std::string op;
    ea_t        comparison_ea = BADADDR;
    std::string rationale;
};

struct wire_path_constraints_t
{
    ea_t                              source_ea = BADADDR;
    ea_t                              sink_ea = BADADDR;
    size_t                            implied_min_buffer_size = 0;
    std::vector<wire_constraint_t>    constraints;
    std::string                       smt2_formula;
};

class VerificationEngine
{
public:
    VerificationEngine();
    ~VerificationEngine();

    VerificationEngine(const VerificationEngine&) = delete;
    VerificationEngine& operator=(const VerificationEngine&) = delete;

    bool is_available() const;
    const char* last_error() const;

    path_verification_t verify_taint_path(ea_t source_ea,
                                          ea_t sink_ea,
                                          uint32_t timeout_ms = 5000);

    exploit_input_t solve_for_exploit_input(ea_t source_ea,
                                            ea_t sink_ea,
                                            uint32_t timeout_ms = 10000,
                                            const exploit_constraints_t& constraints = {});

    loop_bound_proof_t prove_loop_bound(ea_t loop_func_ea,
                                        int64_t buffer_size,
                                        uint32_t timeout_ms = 5000);

    symbolic::alias_proof_t prove_pointer_alias(ea_t func_ea,
                                                const std::string& ptr1_spec,
                                                const std::string& ptr2_spec,
                                                uint32_t timeout_ms = 5000);

    symbolic::simplification_t simplify_function_arithmetic(ea_t func_ea,
                                                            int max_insns = 1024);

    smt::solve_result_t check_path_satisfiability(const std::vector<ea_t>& branch_eas,
                                                  uint32_t timeout_ms = 5000);

    smt::solve_result_t solve_smtlib2(const std::string& formula,
                                      uint32_t timeout_ms = 5000);

    triage_result_t triage_sink(ea_t source_ea,
                                ea_t sink_ea,
                                uint32_t cheap_timeout_ms = 250,
                                uint32_t deep_timeout_ms = 10000,
                                const std::string& stop_at = "exploit_input");

    std::vector<path_verification_t> list_verified(verdict_t filter = verdict_t::inconclusive,
                                                   bool use_filter = false,
                                                   ea_t sink_ea = BADADDR,
                                                   size_t max_entries = 100) const;

    nlohmann::json persist_ledger(const std::string& action);
    void cancel();
    int in_flight_count() const;

    wire_path_constraints_t extract_wire_path_constraints(ea_t source_ea,
                                                          ea_t sink_ea,
                                                          int max_branches = 64);

    exploit_input_t synthesize_exploit_payload(ea_t source_ea,
                                               ea_t sink_ea,
                                               uint32_t timeout_ms = 10000,
                                               const exploit_constraints_t& constraints = {});

    nlohmann::json verdict_summary() const;

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

VerificationEngine& engine();

nlohmann::json to_json(const path_verification_t& v);
nlohmann::json to_json(const exploit_input_t& e);
nlohmann::json to_json(const loop_bound_proof_t& p);
nlohmann::json to_json(const triage_result_t& t);
nlohmann::json to_json(const wire_constraint_t& c);
nlohmann::json to_json(const wire_path_constraints_t& w);

}
}
}
