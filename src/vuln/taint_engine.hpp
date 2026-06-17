#pragma once

#include <climits>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>

#include "vuln_common.hpp"

namespace aida
{
namespace vuln
{
namespace taint
{

// Slice C1 — explicit underlying type matches the forward declaration in
// vuln_common.hpp so the taint_tag_t struct there is well-formed.
enum class taint_kind_t : int
{
    untainted = 0,
    user_input,
    network_input,
    file_input,
    env_input,
    registry_input,
    kernel_userptr,
    // Slice C1 — new attack-surface kinds keyed off Slice A source arrays.
    rpc_input,
    com_input,
    alpc_input,
    named_pipe_input,
    socket_input,
    http_input,
    websocket_input,
    ndis_wsk_input,
    kernel_irp_input,
};

inline const char* taint_kind_str(taint_kind_t k)
{
    switch (k)
    {
    case taint_kind_t::untainted:        return "untainted";
    case taint_kind_t::user_input:       return "user_input";
    case taint_kind_t::network_input:    return "network_input";
    case taint_kind_t::file_input:       return "file_input";
    case taint_kind_t::env_input:        return "env_input";
    case taint_kind_t::registry_input:   return "registry_input";
    case taint_kind_t::kernel_userptr:   return "kernel_userptr";
    case taint_kind_t::rpc_input:        return "rpc_input";
    case taint_kind_t::com_input:        return "com_input";
    case taint_kind_t::alpc_input:       return "alpc_input";
    case taint_kind_t::named_pipe_input: return "named_pipe_input";
    case taint_kind_t::socket_input:     return "socket_input";
    case taint_kind_t::http_input:       return "http_input";
    case taint_kind_t::websocket_input:  return "websocket_input";
    case taint_kind_t::ndis_wsk_input:   return "ndis_wsk_input";
    case taint_kind_t::kernel_irp_input: return "kernel_irp_input";
    }
    return "untainted";
}

struct taint_origin_t
{
    ea_t          source_ea = BADADDR;
    ea_t          source_func_ea = BADADDR;
    std::string   source_name;
    taint_kind_t  kind = taint_kind_t::untainted;
};

struct taint_path_step_t
{
    ea_t         ea = BADADDR;
    ea_t         func_ea = BADADDR;
    std::string  func_name;
    std::string  description;
    std::string  condition;
};

struct taint_path_t
{
    taint_origin_t                  origin;
    ea_t                            sink_ea = BADADDR;
    ea_t                            sink_func_ea = BADADDR;
    std::string                     sink_name;
    int                             sink_arg_index = -1;
    std::vector<taint_path_step_t>  steps;
    std::vector<std::string>        conditions;
    // Slice C7/C8 — names of validator helpers seen between source and sink.
    std::vector<std::string>        validator_chain;
    std::string                     vulnerability_type;
    severity_t                      severity = severity_t::medium;
    confidence_t                    confidence = confidence_t::plausible;
};

nlohmann::json to_json(const taint_path_t& p);

struct func_summary_t
{
    ea_t                                func_ea = BADADDR;
    std::string                         name;
    std::set<int>                       tainted_param_indices;
    std::set<int>                       tainted_out_param_indices;
    bool                                returns_tainted = false;
    bool                                returns_alloc = false;
    bool                                returns_free = false;
    std::set<std::string>               sinks_reached;
    std::set<std::string>               validators_called;
    std::set<std::string>               allocs_called;
    std::set<std::string>               frees_called;
    std::set<std::string>               input_sources_called;
    std::set<int>                       params_passed_to_sinks;
    std::set<int>                       params_validated;
    std::set<int>                       params_freed;
    int                                 cyclomatic = 0;
    bool                                analyzed = false;

    // Slice C3 — per-parameter sink/validator metadata so downstream callers
    // can reason about which parameter reaches which sink without having to
    // re-walk the microcode. Each tuple in param_sink_uses is
    // (sink_name, sink_category, sink_arg_idx).
    std::map<int, std::set<std::tuple<std::string, std::string, int>>> param_sink_uses;
    std::map<int, std::set<std::string>>                               param_validators_seen;
    std::map<int, std::set<taint_kind_t>>                              param_inferred_kinds;
    std::map<int, std::set<int>>                                        tainted_fields;
};

// Slice C6 — per-function forward/backward reachability record used to rank
// hot functions and prune BFS during inter-procedural path tracing.
struct reach_record_t
{
    std::set<taint_kind_t>                  input_kinds;
    std::vector<std::pair<ea_t, std::string>> input_callsites;
    std::set<std::string>                   sink_categories;
    std::vector<std::pair<ea_t, std::string>> sink_callsites;
    bool                                    capped = false;
    std::set<std::string>                   dominant_validators;
    int                                     min_hops_to_sink   = INT_MAX;
    int                                     min_hops_from_source = INT_MAX;
};

class TaintEngine
{
public:
    TaintEngine();
    ~TaintEngine();

    void clear();
    void analyze_all();

    const func_summary_t* get_summary(ea_t func_ea) const;
    std::vector<func_summary_t> get_all_summaries() const;

    std::vector<taint_path_t> trace_paths(ea_t source_ea,
                                          ea_t sink_ea,
                                          int max_paths = 16,
                                          int max_depth = 10);

    std::vector<taint_path_t> trace_paths_from_source(ea_t source_ea,
                                                      int max_paths = 16,
                                                      int max_depth = 10);

    // Slice C8 — BFS backward from a sink function in the call graph using
    // m_backward_reach for pruning. Returns canonical taint_path_t records.
    std::vector<taint_path_t> trace_paths_reverse(ea_t sink_ea,
                                                  int max_paths = 16,
                                                  int max_depth = 10);

    // Slice C9 — Enumerate input callsites (C4) → forward reach (C6) → filter
    // by require_unsanitized → rank → emit ranked taint_path_t list.
    std::vector<taint_path_t> trace_all_network_to_sinks(
        bool require_unsanitized = false,
        int  max_paths           = 64,
        int  max_depth           = 10,
        std::optional<taint_kind_t> only_kind = std::nullopt);

    std::vector<vuln_finding_t> find_uaf_candidates(int max_findings = 64);
    std::vector<vuln_finding_t> find_double_free_candidates(int max_findings = 64);
    std::vector<vuln_finding_t> find_use_after_realloc(int max_findings = 64);
    std::vector<vuln_finding_t> find_uninit_use(int max_findings = 64);
    std::vector<vuln_finding_t> find_integer_overflow_sites(int max_findings = 64);

    // Slice C4 — Walk xrefs to every imported symbol that appears in the
    // Slice A SOURCE arrays. Returns (callsite_ea, containing_func_ea,
    // callee_name, taint_kind_t). Optional only_kind filters output.
    std::vector<std::tuple<ea_t, ea_t, std::string, taint_kind_t>>
        enumerate_input_callsites(
            std::optional<taint_kind_t> only_kind = std::nullopt) const;

    // Slice C5 — Mirror of C4 over the dangerous-sink arrays. Returns
    // (callsite_ea, containing_func_ea, callee_name, sink_category).
    std::vector<std::tuple<ea_t, ea_t, std::string, std::string>>
        enumerate_sink_callsites() const;

    // Slice C6 — accessors for the forward/backward reach indices.
    const reach_record_t* forward_reach_for(ea_t func_ea) const;
    const reach_record_t* backward_reach_for(ea_t func_ea) const;
    void build_reachability_index(int max_hops = 8);

    // Slice C7 — Path-sensitive sanitizer gate. Walks the linear block list
    // between source and sink and returns the names of LENGTH_VALIDATOR_HELPERS
    // / AUTH_GATE_HELPERS calls observed.
    std::vector<std::string> path_sensitive_sanitizer_gate(ea_t func_ea,
                                                           ea_t source_ea,
                                                           ea_t sink_ea) const;

    // Slice C10 — Per-function complete JSON dump.
    nlohmann::json function_taint_brief(ea_t func_ea) const;

    // Slice C11 — Persistent summary cache (m_summaries + reach indices) keyed
    // on the binary's MD5 + SIGNATURE_DATABASE_REVISION.
    bool save_summaries_to_netnode() const;
    bool load_summaries_from_netnode();

    bool is_analyzed() const { return m_analyzed; }

private:
    std::unordered_map<ea_t, func_summary_t> m_summaries;
    bool m_analyzed = false;

    // Slice C6 — reach indices populated by build_reachability_index().
    std::unordered_map<ea_t, reach_record_t> m_forward_reach;
    std::unordered_map<ea_t, reach_record_t> m_backward_reach;

    void analyze_function(ea_t func_ea);
    void compute_summary(ea_t func_ea, func_summary_t& sum);
    std::vector<ea_t> caller_eas(ea_t callee_ea) const;
};

TaintEngine& engine();

}
}
}
