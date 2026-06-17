#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <ida.hpp>

namespace aida
{
namespace vuln
{

// Slice C1: forward-declare the taint kind enum from taint_engine.hpp. Because
// the underlying type is fixed (int), this forward declaration is sufficient
// for any code that only needs to hold a taint_kind_t value or store it inside
// a struct/container. Consumers that need to compare against enumerators must
// include taint_engine.hpp explicitly.
namespace taint { enum class taint_kind_t : int; }

// Slice C1: per-lvar taint tag. Replaces a bare unordered_set<int> of tainted
// lvar indices with richer per-lvar metadata: the kind of taint, whether the
// data only ever reaches a conditional branch (control-only, vs flowing into
// memory or a sink argument), and the set of input-source callsite indices
// that contributed to this lvar's taint.
struct taint_tag_t
{
    taint::taint_kind_t kind = static_cast<taint::taint_kind_t>(0);
    bool                control_only = false;
    std::set<int>       source_callsite_idxs;
};

enum class severity_t
{
    info     = 0,
    low      = 1,
    medium   = 2,
    high     = 3,
    critical = 4
};

enum class confidence_t
{
    speculative = 0,
    plausible   = 1,
    likely      = 2,
    confirmed   = 3
};

struct cwe_t
{
    int         id   = 0;
    std::string name;
};

struct callsite_t
{
    ea_t                     call_ea  = BADADDR;
    ea_t                     func_ea  = BADADDR;
    std::string              callee_name;
    std::vector<std::string> arg_summaries;
    std::vector<bool>        arg_is_literal;
};

struct vuln_finding_t
{
    std::string              id;
    std::vector<cwe_t>       cwes;
    severity_t               severity   = severity_t::info;
    confidence_t             confidence = confidence_t::speculative;
    ea_t                     primary_ea = BADADDR;
    std::vector<ea_t>        related_eas;
    std::string              title;
    std::string              rationale;
    nlohmann::json           evidence;
};

inline const char* severity_str(severity_t s)
{
    switch (s)
    {
    case severity_t::info:     return "info";
    case severity_t::low:      return "low";
    case severity_t::medium:   return "medium";
    case severity_t::high:     return "high";
    case severity_t::critical: return "critical";
    }
    return "info";
}

inline const char* confidence_str(confidence_t c)
{
    switch (c)
    {
    case confidence_t::speculative: return "speculative";
    case confidence_t::plausible:   return "plausible";
    case confidence_t::likely:      return "likely";
    case confidence_t::confirmed:   return "confirmed";
    }
    return "speculative";
}

inline nlohmann::json to_json(const cwe_t& c)
{
    return nlohmann::json{{"id", c.id}, {"name", c.name}};
}

inline nlohmann::json to_json(const callsite_t& cs)
{
    nlohmann::json j;
    j["call_ea"]   = static_cast<uint64_t>(cs.call_ea);
    j["func_ea"]   = static_cast<uint64_t>(cs.func_ea);
    j["callee"]    = cs.callee_name;
    j["args"]      = nlohmann::json::array();
    for (size_t i = 0; i < cs.arg_summaries.size(); ++i)
    {
        nlohmann::json a;
        a["summary"]    = cs.arg_summaries[i];
        a["is_literal"] = i < cs.arg_is_literal.size() ? cs.arg_is_literal[i] : false;
        j["args"].push_back(std::move(a));
    }
    return j;
}

inline nlohmann::json to_json(const vuln_finding_t& f)
{
    nlohmann::json j;
    j["id"]         = f.id;
    j["severity"]   = severity_str(f.severity);
    j["confidence"] = confidence_str(f.confidence);
    j["primary_ea"] = static_cast<uint64_t>(f.primary_ea);
    j["title"]      = f.title;
    j["rationale"]  = f.rationale;
    j["cwes"]       = nlohmann::json::array();
    for (const auto& c : f.cwes)
        j["cwes"].push_back(to_json(c));
    j["related_eas"] = nlohmann::json::array();
    for (auto ea : f.related_eas)
        j["related_eas"].push_back(static_cast<uint64_t>(ea));
    if (!f.evidence.is_null())
        j["evidence"] = f.evidence;
    return j;
}

}
}
