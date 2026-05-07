#include "../aida_pro.hpp"

#include "verification_tools.hpp"
#include "verification_engine.hpp"
#include "smt_solver.hpp"
#include "symbolic_engine.hpp"
#include "vuln_common.hpp"

#include "../agent_tools.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <ios>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{
namespace verify
{
namespace tools
{

namespace
{

using json = nlohmann::json;

int clamp_timeout(const json& params, const char* key, int default_ms, int max_ms)
{
    int requested = default_ms;
    if (params.contains(key))
    {
        const auto& v = params.at(key);
        if (v.is_number_integer())
            requested = v.get<int>();
        else if (v.is_number_unsigned())
            requested = static_cast<int>(v.get<uint64_t>());
        else if (v.is_number_float())
            requested = static_cast<int>(v.get<double>());
        else if (v.is_string())
        {
            const std::string& s = v.get_ref<const std::string&>();
            if (!s.empty())
            {
                char* end_ptr = nullptr;
                long parsed = std::strtol(s.c_str(), &end_ptr, 0);
                if (end_ptr != s.c_str())
                    requested = static_cast<int>(parsed);
            }
        }
    }
    if (requested < 100)
        requested = 100;
    if (requested > max_ms)
        requested = max_ms;
    return requested;
}

int clamp_int_param(const json& params, const char* key, int default_value, int min_value, int max_value)
{
    int requested = default_value;
    if (params.contains(key))
    {
        const auto& v = params.at(key);
        if (v.is_number_integer())
            requested = v.get<int>();
        else if (v.is_number_unsigned())
            requested = static_cast<int>(v.get<uint64_t>());
        else if (v.is_number_float())
            requested = static_cast<int>(v.get<double>());
        else if (v.is_string())
        {
            const std::string& s = v.get_ref<const std::string&>();
            if (!s.empty())
            {
                char* end_ptr = nullptr;
                long parsed = std::strtol(s.c_str(), &end_ptr, 0);
                if (end_ptr != s.c_str())
                    requested = static_cast<int>(parsed);
            }
        }
    }
    if (requested < min_value)
        requested = min_value;
    if (requested > max_value)
        requested = max_value;
    return requested;
}

int64_t extract_int64_param(const json& params, const char* key, int64_t default_value)
{
    if (!params.contains(key))
        return default_value;
    const auto& v = params.at(key);
    if (v.is_number_integer())
        return v.get<int64_t>();
    if (v.is_number_unsigned())
        return static_cast<int64_t>(v.get<uint64_t>());
    if (v.is_number_float())
        return static_cast<int64_t>(v.get<double>());
    if (v.is_string())
    {
        const std::string& s = v.get_ref<const std::string&>();
        if (s.empty())
            return default_value;
        char* end_ptr = nullptr;
        long long parsed = std::strtoll(s.c_str(), &end_ptr, 0);
        if (end_ptr == s.c_str())
            return default_value;
        return static_cast<int64_t>(parsed);
    }
    return default_value;
}

std::string extract_string_param(const json& params, const char* key)
{
    if (!params.contains(key))
        return std::string();
    const auto& v = params.at(key);
    if (v.is_string())
        return v.get<std::string>();
    if (v.is_number_integer())
        return std::to_string(v.get<int64_t>());
    if (v.is_number_unsigned())
        return std::to_string(v.get<uint64_t>());
    return std::string();
}

agent_tools::tool_result_t handle_verify_taint_path(const json& params)
{
    std::string source_str = extract_string_param(params, "source");
    std::string sink_str = extract_string_param(params, "sink");

    if (source_str.empty())
        return agent_tools::tool_result_t::error(OBFSTR("source address is required"));
    if (sink_str.empty())
        return agent_tools::tool_result_t::error(OBFSTR("sink address is required"));

    auto source_ea = agent_tools::helpers::parse_address(source_str);
    if (!source_ea)
        return agent_tools::tool_result_t::error(OBFSTR("invalid source address: ") + source_str);

    auto sink_ea = agent_tools::helpers::parse_address(sink_str);
    if (!sink_ea)
        return agent_tools::tool_result_t::error(OBFSTR("invalid sink address: ") + sink_str);

    int timeout_ms = clamp_timeout(params, "timeout_ms", 5000, 30000);

    auto& eng = verify::engine();
    if (!eng.is_available())
    {
        std::string detail = OBFSTR("verification engine unavailable (libz3.dll or Triton failed to load)");
        const char* err = eng.last_error();
        if (err && *err)
        {
            detail.append(OBFSTR(": "));
            detail.append(err);
        }
        return agent_tools::tool_result_t::error(detail);
    }

    auto result = eng.verify_taint_path(*source_ea, *sink_ea, static_cast<uint32_t>(timeout_ms));
    json data = verify::to_json(result);

    std::ostringstream msg;
    msg << OBFSTR("Path verification: ") << verify::verdict_str(result.verdict)
        << OBFSTR(" (smt=") << smt::result_str(result.smt_result)
        << OBFSTR(", solve_ms=") << result.solve_ms << OBFSTR(")");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_solve_for_exploit_input(const json& params)
{
    std::string source_str = extract_string_param(params, "source");
    std::string sink_str = extract_string_param(params, "sink");

    if (source_str.empty())
        return agent_tools::tool_result_t::error(OBFSTR("source address is required"));
    if (sink_str.empty())
        return agent_tools::tool_result_t::error(OBFSTR("sink address is required"));

    auto source_ea = agent_tools::helpers::parse_address(source_str);
    if (!source_ea)
        return agent_tools::tool_result_t::error(OBFSTR("invalid source address: ") + source_str);

    auto sink_ea = agent_tools::helpers::parse_address(sink_str);
    if (!sink_ea)
        return agent_tools::tool_result_t::error(OBFSTR("invalid sink address: ") + sink_str);

    int timeout_ms = clamp_timeout(params, "timeout_ms", 10000, 60000);

    auto& eng = verify::engine();
    if (!eng.is_available())
    {
        std::string detail = OBFSTR("verification engine unavailable (libz3.dll or Triton failed to load)");
        const char* err = eng.last_error();
        if (err && *err)
        {
            detail.append(OBFSTR(": "));
            detail.append(err);
        }
        return agent_tools::tool_result_t::error(detail);
    }

    auto result = eng.solve_for_exploit_input(*source_ea, *sink_ea, static_cast<uint32_t>(timeout_ms));
    json data = verify::to_json(result);

    std::ostringstream msg;
    if (result.found)
        msg << OBFSTR("Exploit input solved: ") << result.concrete_bytes.size()
            << OBFSTR(" byte(s), ") << result.inputs.size() << OBFSTR(" model entries");
    else
        msg << OBFSTR("Exploit input not solvable: ") << result.summary;
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_prove_loop_bound(const json& params)
{
    std::string func_str = extract_string_param(params, "loop_func_address");
    if (func_str.empty())
        return agent_tools::tool_result_t::error(OBFSTR("loop_func_address is required"));

    auto func_ea = agent_tools::helpers::parse_address(func_str);
    if (!func_ea)
        return agent_tools::tool_result_t::error(OBFSTR("invalid loop_func_address: ") + func_str);

    if (!params.contains("buffer_size"))
        return agent_tools::tool_result_t::error(OBFSTR("buffer_size is required"));

    int64_t buffer_size = extract_int64_param(params, "buffer_size", 0);
    if (buffer_size <= 0)
        return agent_tools::tool_result_t::error(OBFSTR("buffer_size must be a positive integer"));

    int timeout_ms = clamp_timeout(params, "timeout_ms", 5000, 30000);

    auto& eng = verify::engine();
    if (!eng.is_available())
    {
        std::string detail = OBFSTR("verification engine unavailable (libz3.dll or Triton failed to load)");
        const char* err = eng.last_error();
        if (err && *err)
        {
            detail.append(OBFSTR(": "));
            detail.append(err);
        }
        return agent_tools::tool_result_t::error(detail);
    }

    auto result = eng.prove_loop_bound(*func_ea, buffer_size, static_cast<uint32_t>(timeout_ms));
    json data = verify::to_json(result);

    std::ostringstream msg;
    msg << OBFSTR("Loop bound proof: ") << verify::verdict_str(result.verdict)
        << OBFSTR(" (max_index=") << result.max_index
        << OBFSTR(", buffer_size=") << result.buffer_size
        << OBFSTR(", overflow_provable=") << (result.overflow_provable ? "true" : "false") << OBFSTR(")");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_prove_pointer_alias(const json& params)
{
    std::string func_str = extract_string_param(params, "function_address");
    std::string ptr1_spec = extract_string_param(params, "ptr1");
    std::string ptr2_spec = extract_string_param(params, "ptr2");

    if (func_str.empty())
        return agent_tools::tool_result_t::error(OBFSTR("function_address is required"));
    if (ptr1_spec.empty())
        return agent_tools::tool_result_t::error(OBFSTR("ptr1 specifier is required (lvar:NAME, lvar:INDEX, reg:NAME, or stk:OFFSET)"));
    if (ptr2_spec.empty())
        return agent_tools::tool_result_t::error(OBFSTR("ptr2 specifier is required (lvar:NAME, lvar:INDEX, reg:NAME, or stk:OFFSET)"));

    auto func_ea = agent_tools::helpers::parse_address(func_str);
    if (!func_ea)
        return agent_tools::tool_result_t::error(OBFSTR("invalid function_address: ") + func_str);

    int timeout_ms = clamp_timeout(params, "timeout_ms", 5000, 30000);

    auto& eng = verify::engine();
    if (!eng.is_available())
    {
        std::string detail = OBFSTR("verification engine unavailable (libz3.dll or Triton failed to load)");
        const char* err = eng.last_error();
        if (err && *err)
        {
            detail.append(OBFSTR(": "));
            detail.append(err);
        }
        return agent_tools::tool_result_t::error(detail);
    }

    auto result = eng.prove_pointer_alias(*func_ea, ptr1_spec, ptr2_spec, static_cast<uint32_t>(timeout_ms));
    json data = symbolic::to_json(result);

    std::string verdict_text;
    if (result.must_alias)
        verdict_text = OBFSTR("must_alias");
    else if (result.no_alias)
        verdict_text = OBFSTR("no_alias");
    else if (result.may_alias)
        verdict_text = OBFSTR("may_alias");
    else
        verdict_text = OBFSTR("inconclusive");

    std::ostringstream msg;
    msg << OBFSTR("Alias proof: ") << verdict_text;
    if (!result.reason.empty())
        msg << OBFSTR(" (") << result.reason << OBFSTR(")");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_simplify_function_arithmetic(const json& params)
{
    std::string func_str = extract_string_param(params, "address");
    if (func_str.empty())
        return agent_tools::tool_result_t::error(OBFSTR("address is required"));

    auto func_ea = agent_tools::helpers::parse_address(func_str);
    if (!func_ea)
        return agent_tools::tool_result_t::error(OBFSTR("invalid address: ") + func_str);

    int max_insns = clamp_int_param(params, "max_insns", 1024, 1, 8192);

    auto& eng = verify::engine();
    if (!eng.is_available())
    {
        std::string detail = OBFSTR("verification engine unavailable (libz3.dll or Triton failed to load)");
        const char* err = eng.last_error();
        if (err && *err)
        {
            detail.append(OBFSTR(": "));
            detail.append(err);
        }
        return agent_tools::tool_result_t::error(detail);
    }

    auto result = eng.simplify_function_arithmetic(*func_ea, max_insns);
    json data = symbolic::to_json(result);

    std::ostringstream msg;
    if (result.simplified)
    {
        msg << OBFSTR("Arithmetic simplified");
        if (result.is_concrete)
            msg << OBFSTR(" to concrete value 0x") << std::hex << result.concrete_value;
    }
    else
    {
        msg << OBFSTR("Arithmetic could not be simplified");
    }
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_check_path_satisfiability(const json& params)
{
    if (!params.contains("branch_addresses"))
        return agent_tools::tool_result_t::error(OBFSTR("branch_addresses array is required"));

    const auto& raw = params.at("branch_addresses");
    if (!raw.is_array() && !raw.is_string())
        return agent_tools::tool_result_t::error(OBFSTR("branch_addresses must be an array of address strings"));

    std::vector<ea_t> branch_eas = agent_tools::helpers::parse_addresses(raw);
    if (branch_eas.empty())
        return agent_tools::tool_result_t::error(OBFSTR("branch_addresses did not resolve any valid addresses"));

    int timeout_ms = clamp_timeout(params, "timeout_ms", 5000, 30000);

    auto& eng = verify::engine();
    if (!eng.is_available())
    {
        std::string detail = OBFSTR("verification engine unavailable (libz3.dll or Triton failed to load)");
        const char* err = eng.last_error();
        if (err && *err)
        {
            detail.append(OBFSTR(": "));
            detail.append(err);
        }
        return agent_tools::tool_result_t::error(detail);
    }

    auto result = eng.check_path_satisfiability(branch_eas, static_cast<uint32_t>(timeout_ms));
    json data = smt::to_json(result);

    std::ostringstream msg;
    msg << OBFSTR("Path satisfiability: ") << smt::result_str(result.result)
        << OBFSTR(" over ") << branch_eas.size() << OBFSTR(" branch(es)")
        << OBFSTR(" (solve_ms=") << result.solve_ms << OBFSTR(")");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_solve_smt_query(const json& params)
{
    std::string formula = extract_string_param(params, "formula");
    if (formula.empty())
        return agent_tools::tool_result_t::error(OBFSTR("formula is required (SMT-LIB2 with declare-const + assert + check-sat)"));

    int timeout_ms = clamp_timeout(params, "timeout_ms", 5000, 60000);

    auto& eng = verify::engine();
    if (!eng.is_available())
    {
        std::string detail = OBFSTR("verification engine unavailable (libz3.dll failed to load)");
        const char* err = eng.last_error();
        if (err && *err)
        {
            detail.append(OBFSTR(": "));
            detail.append(err);
        }
        return agent_tools::tool_result_t::error(detail);
    }

    auto result = eng.solve_smtlib2(formula, static_cast<uint32_t>(timeout_ms));
    json data = smt::to_json(result);

    std::ostringstream msg;
    msg << OBFSTR("SMT query: ") << smt::result_str(result.result)
        << OBFSTR(" (solve_ms=") << result.solve_ms << OBFSTR(", model_entries=") << result.model.size() << OBFSTR(")");
    if (!result.reason.empty())
        msg << OBFSTR(" - ") << result.reason;
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

}

void register_verification_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("verify_taint_path"),
        OBFSTR("vuln_verify"),
        OBFSTR("SMT-verify whether a Tier-1 taint path is actually satisfiable. Returns 'confirmed' "
               "(path is reachable), 'refuted' (path conditions are UNSAT - false positive), 'timeout', "
               "or 'inconclusive'. The 'witness' field contains a concrete model that triggers the path "
               "when SAT."),
        {
            {OBFSTR("source"), OBFSTR("string"),
             OBFSTR("Source EA (0x...) of the taint origin."), true},
            {OBFSTR("sink"), OBFSTR("string"),
             OBFSTR("Sink EA (0x...) where the value is consumed."), true},
            {OBFSTR("timeout_ms"), OBFSTR("number"),
             OBFSTR("SMT solver timeout in milliseconds (default 5000, max 30000)."), false},
        },
        handle_verify_taint_path,
        true,
    });

    registry.register_tool({
        OBFSTR("solve_for_exploit_input"),
        OBFSTR("vuln_verify"),
        OBFSTR("Use Z3 to solve for concrete input bytes that drive a tainted source value all the "
               "way to a sink, satisfying every branch condition along the way. Returns the exact "
               "byte sequence the attacker would need to send to trigger the bug."),
        {
            {OBFSTR("source"), OBFSTR("string"),
             OBFSTR("Source EA (0x...) of the tainted input."), true},
            {OBFSTR("sink"), OBFSTR("string"),
             OBFSTR("Sink EA (0x...) where the exploit lands."), true},
            {OBFSTR("timeout_ms"), OBFSTR("number"),
             OBFSTR("SMT solver timeout in milliseconds (default 10000, max 60000)."), false},
        },
        handle_solve_for_exploit_input,
        true,
    });

    registry.register_tool({
        OBFSTR("prove_loop_bound"),
        OBFSTR("vuln_verify"),
        OBFSTR("Prove the maximum / minimum reachable value of a loop induction variable using Z3 "
               "optimization. Returns 'confirmed' (overflow is provable: max_index >= buffer_size), "
               "'refuted' (loop is safe), or 'unsupported' (could not identify induction variable)."),
        {
            {OBFSTR("loop_func_address"), OBFSTR("string"),
             OBFSTR("Function EA (0x...) containing the loop to bound."), true},
            {OBFSTR("buffer_size"), OBFSTR("number"),
             OBFSTR("Size in bytes of the buffer being indexed (overflow threshold)."), true},
            {OBFSTR("timeout_ms"), OBFSTR("number"),
             OBFSTR("SMT solver timeout in milliseconds (default 5000, max 30000)."), false},
        },
        handle_prove_loop_bound,
        true,
    });

    registry.register_tool({
        OBFSTR("prove_pointer_alias"),
        OBFSTR("vuln_verify"),
        OBFSTR("Prove whether two pointers in a function can alias the same memory. 'must_alias' = "
               "always overlap. 'may_alias' = can overlap under some path. 'no_alias' = provably "
               "never overlap. Uses Triton's symbolic engine + Z3 to check feasibility."),
        {
            {OBFSTR("function_address"), OBFSTR("string"),
             OBFSTR("Function EA (0x...) where both pointers live."), true},
            {OBFSTR("ptr1"), OBFSTR("string"),
             OBFSTR("First pointer specifier: lvar:NAME, lvar:INDEX, reg:NAME, or stk:OFFSET."), true},
            {OBFSTR("ptr2"), OBFSTR("string"),
             OBFSTR("Second pointer specifier: lvar:NAME, lvar:INDEX, reg:NAME, or stk:OFFSET."), true},
            {OBFSTR("timeout_ms"), OBFSTR("number"),
             OBFSTR("SMT solver timeout in milliseconds (default 5000, max 30000)."), false},
        },
        handle_prove_pointer_alias,
        true,
    });

    registry.register_tool({
        OBFSTR("simplify_function_arithmetic"),
        OBFSTR("vuln_verify"),
        OBFSTR("Symbolically execute the arithmetic in a function and simplify it via Triton. Useful "
               "for cracking opaque predicates and obfuscated math - e.g., a 50-line constant-folding "
               "routine collapses to a single integer constant. Returns the simplified expression and, "
               "when fully concrete, the constant value."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Function EA (0x...) to simplify."), true},
            {OBFSTR("max_insns"), OBFSTR("number"),
             OBFSTR("Instruction budget for the symbolic walk (default 1024, max 8192)."), false},
        },
        handle_simplify_function_arithmetic,
        true,
    });

    registry.register_tool({
        OBFSTR("check_path_satisfiability"),
        OBFSTR("vuln_verify"),
        OBFSTR("Check whether a sequence of branch conditions is mutually satisfiable. Returns SAT "
               "(path is feasible), UNSAT (path is dead code / contradictory), or UNKNOWN (timeout). "
               "Useful for triaging Tier-1 findings without committing to a full source->sink trace."),
        {
            {OBFSTR("branch_addresses"), OBFSTR("array"),
             OBFSTR("Array of branch instruction addresses (0x...) to constrain."), true,
             {},
             nlohmann::json::object({{"type", "string"}, {"description", "Branch instruction address (0x...)"}})},
            {OBFSTR("timeout_ms"), OBFSTR("number"),
             OBFSTR("SMT solver timeout in milliseconds (default 5000, max 30000)."), false},
        },
        handle_check_path_satisfiability,
        true,
    });

    registry.register_tool({
        OBFSTR("solve_smt_query"),
        OBFSTR("vuln_verify"),
        OBFSTR("Run a raw SMT-LIB2 query through Z3. The formula must be self-contained (declare-const "
               "+ assert + check-sat). Use this for ad-hoc constraint checks when the high-level tools "
               "don't fit."),
        {
            {OBFSTR("formula"), OBFSTR("string"),
             OBFSTR("Self-contained SMT-LIB2 formula (declare-const + assert + check-sat)."), true},
            {OBFSTR("timeout_ms"), OBFSTR("number"),
             OBFSTR("SMT solver timeout in milliseconds (default 5000, max 60000)."), false},
        },
        handle_solve_smt_query,
        true,
    });
}

}
}
}
}
