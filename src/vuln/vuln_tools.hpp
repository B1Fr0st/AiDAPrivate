#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <hexrays.hpp>

#include "../agent_tools.hpp"
#include "vuln_common.hpp"

namespace agent_tools
{
namespace vuln_tools
{

void register_tools();
void register_advanced_tools();

}
}

namespace aida
{
namespace vuln
{

namespace callsites
{
    struct call_index_entry_t
    {
        ea_t                     func_ea = BADADDR;
        ea_t                     call_ea = BADADDR;
        ea_t                     callee_ea = BADADDR;
        std::string              callee_name;
        std::vector<bool>        arg_is_literal;
    };

    struct validator_summary_t
    {
        ea_t                     func_ea = BADADDR;
        std::vector<ea_t>        validator_call_eas;
        std::vector<ea_t>        auth_gate_call_eas;
        std::vector<ea_t>        integer_math_call_eas;
        std::vector<std::string> validators_seen;
        std::vector<std::string> auth_gates_seen;
        std::vector<std::string> integer_math_seen;
        int                      length_size_comparisons = 0;
    };

    std::vector<callsite_t> all_calls_to(const std::vector<std::string>& target_names);
    std::vector<callsite_t> all_calls_to_public_wrapper(const std::vector<std::string>& target_names,
                                                        std::size_t limit,
                                                        std::vector<std::string>* unresolved_names,
                                                        bool* capped);
    std::vector<call_index_entry_t> per_function_call_index(ea_t func_ea);
    validator_summary_t summarize_validators_in_function(ea_t func_ea);
    nlohmann::json reverse_slice_sink_to_sources(ea_t sink_call_ea,
                                                 int max_depth,
                                                 const std::string& source_category,
                                                 int max_paths,
                                                 bool require_no_validator,
                                                 bool require_pre_auth);
    nlohmann::json forward_reachability_source_to_sinks(ea_t source_func_ea,
                                                        int max_depth,
                                                        const std::string& sink_category,
                                                        int max_hits,
                                                        bool require_no_validator);
    nlohmann::json protocol_attack_surface_report();
    nlohmann::json find_pre_auth_paths(const std::string& source_category,
                                       const std::string& sink_category,
                                       int max_depth,
                                       int max_paths,
                                       bool require_no_validator);
    nlohmann::json find_dispatch_tables(int min_entries,
                                        int max_entries,
                                        bool include_vtables);
    nlohmann::json find_parser_shaped_functions(int top_k,
                                                bool only_reachable_from_network);
    nlohmann::json find_safearray_misuse(int limit);
    nlohmann::json find_int_overflow_alloc_from_input(int limit);
    std::vector<callsite_t> input_source_callsites();
    bool is_call_arg_literal(const cfunc_t& cf, ea_t call_ea, int arg_idx);

    namespace tools
    {
        void register_tier1_callsite_tools();
    }
}

namespace strings_engine
{
    std::vector<vuln_finding_t> find_hardcoded_credentials(int max_findings = 256);
    std::vector<vuln_finding_t> find_weak_crypto(int max_findings = 256);

    namespace tools
    {
        void register_tier1_string_tools();
    }
}

namespace microcode
{
    void register_tier1_microcode_tools();
}

namespace cfg_engine
{
    struct switch_case_t
    {
        std::uint64_t value = 0;
        ea_t          jump_target_ea = BADADDR;
        ea_t          handler_func_ea = BADADDR;
        std::string   handler_name;
        bool          has_call = false;
    };

    struct switch_dispatch_t
    {
        ea_t                       jmp_ea = BADADDR;
        std::string                switch_kind;
        int                        ncases = 0;
        ea_t                       default_target = BADADDR;
        std::vector<switch_case_t> cases;
    };

    struct reachable_pair_t
    {
        ea_t              source_ea = BADADDR;
        ea_t              sink_ea = BADADDR;
        std::vector<ea_t> path;
    };

    struct indirect_target_t
    {
        ea_t        target_ea = BADADDR;
        std::string source;
        std::string name;
        std::string rationale;
    };

    struct indirect_call_t
    {
        ea_t                              call_ea = BADADDR;
        ea_t                              func_ea = BADADDR;
        std::vector<indirect_target_t>    targets;
        std::string                       reason;
    };

    struct bypass_path_t
    {
        ea_t                         func_ea = BADADDR;
        ea_t                         check_ea = BADADDR;
        ea_t                         sink_ea = BADADDR;
        std::vector<ea_t>            block_path;
        std::vector<ea_t>            ea_trace;
        std::string                  rationale;
    };

    std::vector<indirect_call_t> find_indirect_calls(ea_t func_ea);
    std::vector<bypass_path_t>   find_bypass_paths(ea_t check_ea, ea_t sink_ea);
    bool block_post_dominates(ea_t func_ea, int from_block, int to_block);
    std::vector<switch_dispatch_t> enumerate_switch_dispatch(ea_t func_ea);
    nlohmann::json list_dispatchers(int top_n);
    nlohmann::json resolve_indirect_calls_batched(const std::vector<ea_t>& func_eas,
                                                  bool only_unresolved,
                                                  bool only_vtable,
                                                  const std::string& target_name_filter);
    nlohmann::json enumerate_vtables(int min_entries, int max_entries);
    nlohmann::json reachable_under_constraints(const std::vector<ea_t>& sources,
                                               const std::vector<ea_t>& sinks,
                                               const std::vector<ea_t>& must_not_cross_funcs,
                                               int max_depth);

    void register_tier1_cfg_tools();
}

namespace taint
{
    namespace tools
    {
        void register_tier1_taint_tools();
        void register_tier2_taint_tools();
    }
}

namespace kernel_engine
{
    struct ioctl_handler_t
    {
        ea_t                       handler_ea = BADADDR;
        std::string                handler_name;
        std::vector<uint32_t>      ioctl_codes;
        std::string                source_model;
        std::string                evidence;
        std::vector<std::string>   fallback_metadata;
        uint32_t                   major_function = 0xFFFFFFFFu;
    };

    struct ioctl_decoded_t
    {
        uint32_t     code = 0;
        uint16_t     device_type = 0;
        uint16_t     function_code = 0;
        uint8_t      method = 0;
        uint8_t      access = 0;
        const char*  method_name = "";
        const char*  access_name = "";
    };

    bool is_kernel_driver();
    std::vector<ioctl_handler_t> find_ioctl_handlers();
    std::vector<vuln_finding_t>  find_user_pointer_derefs(int max_findings = 64);
    ioctl_decoded_t              decode_ioctl(uint32_t code);

    namespace tools
    {
        void register_tier1_kernel_tools();
    }
}

namespace surface_engine
{
    struct attack_surface_score_t
    {
        ea_t        func_ea = BADADDR;
        int         total_score = 0;
        int         input_proximity = 0;
        int         sink_count = 0;
        int         missing_validators = 0;
        int         complexity = 0;
        int         taint_paths = 0;
        std::string classification;
    };

    attack_surface_score_t score_function(ea_t func_ea);
    std::vector<ea_t>      attacker_reachable_functions();
    std::string            classify_function_role(ea_t func_ea);
    std::vector<vuln_finding_t> enumerate_callbacks();
    std::vector<vuln_finding_t> find_writable_executable_pages();
    nlohmann::json fingerprint_binary_attack_profile();
    nlohmann::json enumerate_ipc_endpoints(const std::vector<std::string>& kinds);
    nlohmann::json compute_pre_auth_handler_set();
    nlohmann::json enumerate_handler_reachable_sinks(ea_t handler_ea, int max_depth, int max_hits);
    nlohmann::json classify_exploit_primitive(ea_t sink_ea);
    nlohmann::json find_protocol_routers(int min_cases, int max_results);
    nlohmann::json resolve_indirect_call_targets(ea_t call_ea);
    nlohmann::json explain_vulnerability_chain_v2(ea_t source_ea, ea_t sink_ea, bool require_pre_auth);
    nlohmann::json hunt_remote_rce(int top_k, bool extract_constraints);
    nlohmann::json rank_attack_surface(int limit, const std::string& role_filter);
    nlohmann::json add_dynamic_taint_source(ea_t source_ea,
                                            const std::string& kind,
                                            const std::string& name);
    nlohmann::json enumerate_callbacks_extended();

    namespace tools
    {
        void register_tier2_surface_tools();
    }
}

}
}
