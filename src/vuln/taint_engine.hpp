#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <optional>

#include <nlohmann/json.hpp>
#include <ida.hpp>

#include "vuln_common.hpp"

namespace aida
{
namespace vuln
{
namespace taint
{

enum class taint_kind_t
{
    untainted = 0,
    user_input,
    network_input,
    file_input,
    env_input,
    registry_input,
    kernel_userptr
};

inline const char* taint_kind_str(taint_kind_t k)
{
    switch (k)
    {
    case taint_kind_t::untainted:       return "untainted";
    case taint_kind_t::user_input:      return "user_input";
    case taint_kind_t::network_input:   return "network_input";
    case taint_kind_t::file_input:      return "file_input";
    case taint_kind_t::env_input:       return "env_input";
    case taint_kind_t::registry_input:  return "registry_input";
    case taint_kind_t::kernel_userptr:  return "kernel_userptr";
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

    std::vector<vuln_finding_t> find_uaf_candidates(int max_findings = 64);
    std::vector<vuln_finding_t> find_double_free_candidates(int max_findings = 64);
    std::vector<vuln_finding_t> find_use_after_realloc(int max_findings = 64);
    std::vector<vuln_finding_t> find_uninit_use(int max_findings = 64);
    std::vector<vuln_finding_t> find_integer_overflow_sites(int max_findings = 64);

    bool is_analyzed() const { return m_analyzed; }

private:
    std::unordered_map<ea_t, func_summary_t> m_summaries;
    bool m_analyzed = false;

    void analyze_function(ea_t func_ea);
    void compute_summary(ea_t func_ea, func_summary_t& sum);
    std::vector<ea_t> caller_eas(ea_t callee_ea) const;
};

TaintEngine& engine();

}
}
}
