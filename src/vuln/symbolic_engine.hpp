#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <hexrays.hpp>

#include "smt_solver.hpp"

namespace aida
{
namespace vuln
{
namespace symbolic
{

struct path_constraint_t
{
    ea_t         branch_ea = BADADDR;
    std::string  predicate_smt2;
    std::string  predicate_text;
    bool         taken = true;
    bool         via_seh_handler = false;
};

struct symbolic_value_t
{
    std::string  smt2;
    std::string  text;
    int          width_bits = 64;
    bool         is_concrete = false;
    uint64_t     concrete_value = 0;
};

struct simplification_t
{
    bool         simplified = false;
    std::string  before_text;
    std::string  after_text;
    uint64_t     concrete_value = 0;
    bool         is_concrete = false;
};

struct alias_proof_t
{
    enum class verdict_t
    {
        must_alias,
        no_alias,
        may_alias,
        inconclusive
    };

    bool         must_alias = false;
    bool         may_alias = true;
    bool         no_alias = false;
    verdict_t    verdict = verdict_t::inconclusive;
    std::string  verdict_label;
    uint64_t     ptr1_concrete = 0;
    uint64_t     ptr2_concrete = 0;
    bool         have_witness = false;
    std::string  reason;
};

class SymbolicEngine
{
public:
    SymbolicEngine();
    ~SymbolicEngine();

    SymbolicEngine(const SymbolicEngine&) = delete;
    SymbolicEngine& operator=(const SymbolicEngine&) = delete;

    bool             is_available() const;
    const char*      last_error() const;

    bool             load_function(ea_t func_ea, mba_maturity_t mat = MMAT_GLBOPT3);

    std::vector<path_constraint_t> collect_path_to(ea_t target_ea, int max_branches = 64);
    std::vector<path_constraint_t> all_path_constraints(int limit = 256);
    std::string      path_smtlib2(ea_t target_ea, int max_branches = 64);
    smt::solve_result_t solve_path_to(ea_t target_ea,
                                      const std::string& extra_smtlib2_assertions = {},
                                      uint32_t timeout_ms = 5000,
                                      int max_branches = 64);
    bool             constrain_taint_source_at(ea_t source_ea);

    std::optional<symbolic_value_t> symbolize_lvar(int lvar_idx);
    std::optional<symbolic_value_t> symbolize_register(const std::string& reg_name);
    std::optional<symbolic_value_t> symbolize_value_at(ea_t insn_ea, const std::string& var_spec);

    simplification_t simplify_function_arithmetic(int max_insns = 1024);
    simplification_t simplify_subtree_at(ea_t insn_ea, const std::string& var_spec);

    alias_proof_t    prove_alias(const std::string& ptr1_spec,
                                  const std::string& ptr2_spec,
                                  uint32_t timeout_ms = 5000);

    nlohmann::json   dump_state(int max_constraints = 64) const;

    ea_t             current_function_ea() const;
    int              num_path_constraints() const;

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

nlohmann::json to_json(const path_constraint_t& c);
nlohmann::json to_json(const symbolic_value_t& v);
nlohmann::json to_json(const simplification_t& s);
nlohmann::json to_json(const alias_proof_t& a);

}
}
}
