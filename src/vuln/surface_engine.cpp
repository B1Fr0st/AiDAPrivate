#include "../aida_pro.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

#include "../agent_tools.hpp"
#include "../ida_utils.hpp"
#include "../obfuscation.hpp"
#include "microcode_engine.hpp"
#include "taint_engine.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace surface_engine
{

namespace
{

using json = nlohmann::json;

constexpr int kMaxBfsDepth        = 4;
constexpr int kMaxQueueElements   = 4096;
constexpr int kMaxCallersPerFunc  = 256;
constexpr int kMaxScannableFuncs  = 8192;

std::string ea_to_hex(ea_t ea)
{
    if (ea == BADADDR)
        return std::string(OBFSTR("0x0"));
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(ea);
    return ss.str();
}

std::string ascii_lower(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        out.push_back(static_cast<char>(uc >= 'A' && uc <= 'Z' ? uc + ('a' - 'A') : uc));
    }
    return out;
}

std::string strip_known_prefixes(const std::string& raw)
{
    static const char* const prefixes[] = {
        "__imp_", "__imp__", "_imp_", "_imp__", "imp_",
        "j_", "j_imp_", "thunk_", "_thunk_",
    };
    std::string out = raw;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const char* p : prefixes)
        {
            const std::size_t plen = std::strlen(p);
            if (out.size() > plen && out.compare(0, plen, p) == 0)
            {
                out.erase(0, plen);
                changed = true;
                break;
            }
        }
    }
    if (out.size() > 1 && out.front() == '_')
    {
        bool only_alnum = true;
        for (char c : out)
        {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '@' || c == '?'))
            {
                only_alnum = false;
                break;
            }
        }
        if (only_alnum)
            out.erase(0, 1);
    }
    auto at_pos = out.find('@');
    if (at_pos != std::string::npos)
        out.erase(at_pos);
    return out;
}

bool name_matches_signature(const std::string& callee, std::string_view sig)
{
    if (callee.empty() || sig.empty())
        return false;
    const std::string sig_l = ascii_lower(std::string(sig));
    const std::string call_l = ascii_lower(callee);
    if (call_l == sig_l)
        return true;
    const std::string stripped = ascii_lower(strip_known_prefixes(callee));
    if (stripped == sig_l)
        return true;
    if (call_l.size() > sig_l.size() &&
        call_l.compare(call_l.size() - sig_l.size(), sig_l.size(), sig_l) == 0)
        return true;
    if (stripped.size() > sig_l.size() &&
        stripped.compare(stripped.size() - sig_l.size(), sig_l.size(), sig_l) == 0)
        return true;
    return false;
}

std::string func_name_for(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return std::string();
    qstring nm;
    if (get_func_name(&nm, func_ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    qstring vn;
    if (get_name(&vn, func_ea) > 0 && !vn.empty())
        return std::string(vn.c_str());
    std::ostringstream ss;
    ss << "sub_" << std::hex << std::uppercase << static_cast<std::uint64_t>(func_ea);
    return ss.str();
}

std::string raw_name_for(ea_t ea)
{
    if (ea == BADADDR)
        return std::string();
    qstring nm;
    if (get_name(&nm, ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    qstring fnm;
    if (get_func_name(&fnm, ea) > 0 && !fnm.empty())
        return std::string(fnm.c_str());
    return std::string();
}

std::mutex& engine_mutex()
{
    static std::mutex m;
    return m;
}

ea_t containing_func_ea(ea_t ea)
{
    if (ea == BADADDR)
        return BADADDR;
    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
        return BADADDR;
    return pfn->start_ea;
}

cfuncptr_t decompile_safe(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return cfuncptr_t(nullptr);
    if (!init_hexrays_plugin())
        return cfuncptr_t(nullptr);
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr || !ida_utils::is_safely_decompilable(pfn))
        return cfuncptr_t(nullptr);
    try
    {
        return decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
    }
    catch (const vd_failure_t&)
    {
        return cfuncptr_t(nullptr);
    }
    catch (...)
    {
        return cfuncptr_t(nullptr);
    }
}

struct call_graph_t
{
    std::unordered_map<ea_t, std::vector<ea_t>> callees;
    std::unordered_map<ea_t, std::vector<ea_t>> callers;
};

call_graph_t build_call_graph()
{
    call_graph_t g;
    const std::size_t fq = get_func_qty();
    g.callees.reserve(fq);
    g.callers.reserve(fq);

    for (std::size_t i = 0; i < fq; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        ea_t fea = pfn->start_ea;
        std::unordered_set<ea_t> outset;
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t cur = fii.current();
            xrefblk_t xb;
            for (bool ix = xb.first_from(cur, XREF_ALL); ix; ix = xb.next_from())
            {
                if (!xb.iscode)
                    continue;
                if (xb.type != fl_CN && xb.type != fl_CF)
                    continue;
                func_t* tgt = get_func(xb.to);
                ea_t tea = tgt != nullptr ? tgt->start_ea : xb.to;
                if (tea == BADADDR || tea == fea)
                    continue;
                if (outset.insert(tea).second)
                    g.callees[fea].push_back(tea);
            }
        }
    }

    for (const auto& kv : g.callees)
    {
        ea_t caller = kv.first;
        for (ea_t callee : kv.second)
            g.callers[callee].push_back(caller);
    }

    for (auto& kv : g.callees)
    {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
    }
    for (auto& kv : g.callers)
    {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
    }

    return g;
}

const call_graph_t& cached_call_graph()
{
    static std::mutex mtx;
    static std::optional<call_graph_t> cache;
    std::lock_guard<std::mutex> lk(mtx);
    if (!cache.has_value())
        cache = build_call_graph();
    return *cache;
}

std::vector<callsite_t> input_source_callsites_safe()
{
    return aida::vuln::callsites::input_source_callsites();
}

std::vector<callsite_t> sink_callsites_safe()
{
    std::vector<std::string> names;
    names.reserve(64);
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
        names.emplace_back(s.name);
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
        names.emplace_back(s.name);
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
        names.emplace_back(s.name);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return aida::vuln::callsites::all_calls_to(names);
}

int caller_distance_to(const call_graph_t& g, ea_t from, ea_t to, int max_depth)
{
    if (from == BADADDR || to == BADADDR)
        return -1;
    if (from == to)
        return 0;
    std::deque<std::pair<ea_t, int>> q;
    std::unordered_set<ea_t> visited;
    q.emplace_back(from, 0);
    visited.insert(from);
    while (!q.empty())
    {
        auto [cur, d] = q.front();
        q.pop_front();
        if (d >= max_depth)
            continue;
        auto it = g.callers.find(cur);
        if (it == g.callers.end())
            continue;
        for (ea_t prev : it->second)
        {
            if (!visited.insert(prev).second)
                continue;
            if (prev == to)
                return d + 1;
            q.emplace_back(prev, d + 1);
            if (q.size() > static_cast<std::size_t>(kMaxQueueElements))
                return -1;
        }
    }
    return -1;
}

int callee_distance_to(const call_graph_t& g, ea_t from, ea_t to, int max_depth)
{
    if (from == BADADDR || to == BADADDR)
        return -1;
    if (from == to)
        return 0;
    std::deque<std::pair<ea_t, int>> q;
    std::unordered_set<ea_t> visited;
    q.emplace_back(from, 0);
    visited.insert(from);
    while (!q.empty())
    {
        auto [cur, d] = q.front();
        q.pop_front();
        if (d >= max_depth)
            continue;
        auto it = g.callees.find(cur);
        if (it == g.callees.end())
            continue;
        for (ea_t nxt : it->second)
        {
            if (!visited.insert(nxt).second)
                continue;
            if (nxt == to)
                return d + 1;
            q.emplace_back(nxt, d + 1);
            if (q.size() > static_cast<std::size_t>(kMaxQueueElements))
                return -1;
        }
    }
    return -1;
}

std::optional<ea_t> parse_addr_param(const json& params, const std::string& key)
{
    if (!params.is_object())
        return std::nullopt;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return std::nullopt;
    if (it->is_string())
    {
        const std::string s = it->get<std::string>();
        if (s.empty())
            return std::nullopt;
        return agent_tools::helpers::parse_address(s);
    }
    if (it->is_number_unsigned())
        return static_cast<ea_t>(it->get<std::uint64_t>());
    if (it->is_number_integer())
        return static_cast<ea_t>(it->get<std::int64_t>());
    return std::nullopt;
}

int extract_int_param(const json& params, const std::string& key, int default_value)
{
    if (!params.is_object())
        return default_value;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return default_value;
    try
    {
        if (it->is_number_integer())
            return it->get<int>();
        if (it->is_number_unsigned())
            return static_cast<int>(it->get<std::uint64_t>());
        if (it->is_number())
            return static_cast<int>(it->get<double>());
        if (it->is_string())
        {
            const std::string s = it->get<std::string>();
            if (s.empty())
                return default_value;
            return std::stoi(s);
        }
    }
    catch (...)
    {
        return default_value;
    }
    return default_value;
}

ea_t resolve_address_or_name(const std::string& spec)
{
    if (spec.empty())
        return BADADDR;
    auto parsed = agent_tools::helpers::parse_address(spec);
    if (parsed.has_value())
        return *parsed;
    ea_t ea = get_name_ea(BADADDR, spec.c_str());
    return ea;
}

cwe_t make_cwe(int id, const char* nm)
{
    cwe_t c;
    c.id = id;
    c.name = nm;
    return c;
}

const char* cwe_name_for(int id)
{
    switch (id)
    {
    case 22:   return "Path Traversal";
    case 78:   return "OS Command Injection";
    case 120:  return "Buffer Copy without Checking Size of Input";
    case 125:  return "Out-of-bounds Read";
    case 129:  return "Improper Validation of Array Index";
    case 130:  return "Improper Handling of Length Parameter Inconsistency";
    case 134:  return "Use of Externally-Controlled Format String";
    case 190:  return "Integer Overflow or Wraparound";
    case 193:  return "Off-by-one Error";
    case 194:  return "Unexpected Sign Extension";
    case 195:  return "Signed to Unsigned Conversion Error";
    case 242:  return "Use of Inherently Dangerous Function";
    case 358:  return "Improperly Implemented Security Check for Standard";
    case 367:  return "Time-of-check Time-of-use (TOCTOU) Race Condition";
    case 415:  return "Double Free";
    case 416:  return "Use After Free";
    case 476:  return "NULL Pointer Dereference";
    case 502:  return "Deserialization of Untrusted Data";
    case 770:  return "Allocation of Resources Without Limits or Throttling";
    case 787:  return "Out-of-bounds Write";
    case 798:  return "Use of Hard-coded Credentials";
    case 822:  return "Untrusted Pointer Dereference";
    case 839:  return "Numeric Range Comparison Without Minimum Check";
    case 1188: return "Insecure Default Initialization of Resource";
    default:   return "Unknown CWE";
    }
}

json findings_to_json_array(const std::vector<vuln_finding_t>& findings)
{
    json arr = json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
}

bool is_alloc_like(const std::string& nm)
{
    for (const auto& a : sig::ALLOC_FUNCS)
    {
        if (name_matches_signature(nm, a))
            return true;
    }
    return false;
}

bool is_free_like(const std::string& nm)
{
    for (const auto& f : sig::FREE_FUNCS)
    {
        if (name_matches_signature(nm, f))
            return true;
    }
    return false;
}

bool is_validator_like(const std::string& nm)
{
    for (const auto& v : sig::KERNEL_VALIDATORS)
    {
        if (name_matches_signature(nm, v))
            return true;
    }
    return false;
}

bool is_input_source_like(const std::string& nm)
{
    for (const auto& s : sig::INPUT_SOURCES)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    return false;
}

bool is_dangerous_sink(const std::string& nm)
{
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    return false;
}

bool is_crypto_function(const std::string& nm)
{
    for (const auto& s : sig::WEAK_HASH_FUNCS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    for (const auto& s : sig::WEAK_CIPHER_FUNCS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    const std::string l = ascii_lower(nm);
    if (l.find("aes_") != std::string::npos)
        return true;
    if (l.find("sha256") != std::string::npos || l.find("sha512") != std::string::npos)
        return true;
    if (l.find("hmac") != std::string::npos)
        return true;
    if (l.find("evp_") != std::string::npos)
        return true;
    if (l.find("crypt") != std::string::npos)
        return true;
    return false;
}

std::vector<std::string> known_callback_apis()
{
    return {
        "SetWindowsHookExA", "SetWindowsHookExW", "SetWindowsHookEx", "SetWindowsHookExEx",
        "CreateRemoteThread", "CreateRemoteThreadEx", "CreateThread", "RtlCreateUserThread",
        "IoRegisterDeviceInterface", "KeInitializeDpc", "KeInitializeTimer",
        "KeInitializeTimerEx", "IoSetCompletionRoutine", "IoSetCompletionRoutineEx",
        "IoRegisterPlugPlayNotification", "IoRegisterShutdownNotification",
        "IoRegisterFsRegistrationChange", "ExRegisterCallback",
        "RegisterServiceCtrlHandlerA", "RegisterServiceCtrlHandlerW",
        "RegisterServiceCtrlHandlerExA", "RegisterServiceCtrlHandlerExW",
        "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
        "AddVectoredContinueHandler", "_set_se_translator", "signal",
        "atexit", "_onexit", "_beginthread", "_beginthreadex",
        "RegisterWaitForSingleObject", "RegisterWaitForSingleObjectEx",
        "CreateTimerQueueTimer", "QueueUserAPC", "QueueUserWorkItem",
    };
}

int callback_arg_index(const std::string& api)
{
    const std::string l = ascii_lower(api);
    if (l.find("setwindowshook") != std::string::npos)
        return 1;
    if (l == "createremotethread" || l == "createremotethreadex" ||
        l == "createthread" || l == "rtlcreateuserthread")
        return 2;
    if (l == "ioregisterdeviceinterface")
        return 1;
    if (l.find("keinitializedpc") != std::string::npos ||
        l.find("keinitializetimer") != std::string::npos)
        return 1;
    if (l.find("iosetcompletionroutine") != std::string::npos)
        return 1;
    if (l.find("ioregisterplugplay") != std::string::npos)
        return 1;
    if (l.find("ioregistershutdown") != std::string::npos)
        return 0;
    if (l.find("ioregisterfsregistration") != std::string::npos)
        return 0;
    if (l.find("exregistercallback") != std::string::npos)
        return 1;
    if (l.find("registerservicectrlhandler") != std::string::npos)
        return 1;
    if (l == "setunhandledexceptionfilter" ||
        l == "addvectoredexceptionhandler" ||
        l == "addvectoredcontinuehandler")
        return 0;
    if (l == "_set_se_translator")
        return 0;
    if (l == "signal")
        return 1;
    if (l == "atexit" || l == "_onexit")
        return 0;
    if (l == "_beginthread" || l == "_beginthreadex")
        return 0;
    if (l.find("registerwaitforsingleobject") != std::string::npos)
        return 1;
    if (l.find("createtimerqueuetimer") != std::string::npos)
        return 1;
    if (l.find("queueuserapc") != std::string::npos)
        return 0;
    if (l.find("queueuserworkitem") != std::string::npos)
        return 0;
    return 0;
}

bool security_sensitive_callback_api(const std::string& api)
{
    const std::string l = ascii_lower(api);
    if (l.find("setwindowshook") != std::string::npos)
        return true;
    if (l == "setunhandledexceptionfilter")
        return true;
    if (l.find("addvectored") != std::string::npos)
        return true;
    if (l.find("ioregister") != std::string::npos)
        return true;
    if (l.find("exregistercallback") != std::string::npos)
        return true;
    return false;
}

cwe_t cwe_for_callback(const std::string& api)
{
    if (security_sensitive_callback_api(api))
        return make_cwe(358, cwe_name_for(358));
    return make_cwe(0, "Informational");
}

struct call_visitor_t : public ctree_visitor_t
{
    cfunc_t*                          cfunc = nullptr;
    std::function<int(cexpr_t*)>      on_call;
    int                               last_result = 0;

    call_visitor_t(cfunc_t* cf, std::function<int(cexpr_t*)> cb)
        : ctree_visitor_t(CV_FAST), cfunc(cf), on_call(std::move(cb)) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr != nullptr && expr->op == cot_call && on_call)
        {
            last_result = on_call(expr);
            return last_result;
        }
        return 0;
    }
};

ea_t resolve_call_target_ea(const cexpr_t* call_expr)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->x == nullptr)
        return BADADDR;
    const cexpr_t* x = call_expr->x;
    while (x != nullptr && (x->op == cot_cast || x->op == cot_ref) && x->x != nullptr)
        x = x->x;
    if (x == nullptr)
        return BADADDR;
    if (x->op == cot_obj)
        return x->obj_ea;
    return BADADDR;
}

std::string resolve_call_target_name(const cexpr_t* call_expr)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->x == nullptr)
        return std::string();
    const cexpr_t* x = call_expr->x;
    while (x != nullptr && (x->op == cot_cast || x->op == cot_ref) && x->x != nullptr)
        x = x->x;
    if (x == nullptr)
        return std::string();
    if (x->op == cot_obj)
    {
        ea_t ea = x->obj_ea;
        if (ea == BADADDR)
            return std::string();
        std::string raw = raw_name_for(ea);
        if (!raw.empty())
            return raw;
        std::string fname = func_name_for(ea);
        return fname;
    }
    if (x->op == cot_helper && x->helper != nullptr)
        return std::string(x->helper);
    return std::string();
}

const cexpr_t* unwrap_cast_ref(const cexpr_t* e)
{
    while (e != nullptr && (e->op == cot_cast || e->op == cot_ref) && e->x != nullptr)
        e = e->x;
    return e;
}

ea_t literal_callback_arg(const cexpr_t* call_expr, int arg_idx)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->a == nullptr)
        return BADADDR;
    if (arg_idx < 0 || static_cast<std::size_t>(arg_idx) >= call_expr->a->size())
        return BADADDR;
    const cexpr_t* arg = static_cast<const cexpr_t*>(&(*call_expr->a)[arg_idx]);
    arg = unwrap_cast_ref(arg);
    if (arg == nullptr)
        return BADADDR;
    if (arg->op == cot_obj)
        return arg->obj_ea;
    return BADADDR;
}

bool ea_is_function(ea_t ea)
{
    if (ea == BADADDR)
        return false;
    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
        return false;
    return pfn->start_ea == ea;
}

}

attack_surface_score_t score_function(ea_t func_ea)
{
    attack_surface_score_t out;
    out.func_ea = func_ea;
    if (func_ea == BADADDR)
        return out;

    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return out;

    const call_graph_t& g = cached_call_graph();

    auto& te = aida::vuln::taint::engine();
    if (!te.is_analyzed())
        te.analyze_all();
    const auto* sum = te.get_summary(func_ea);

    int input_proximity = 0;
    {
        std::vector<callsite_t> sources = input_source_callsites_safe();
        std::unordered_set<ea_t> seen_src_funcs;
        for (const auto& cs : sources)
        {
            if (cs.func_ea == BADADDR)
                continue;
            if (!seen_src_funcs.insert(cs.func_ea).second)
                continue;
            int d = caller_distance_to(g, func_ea, cs.func_ea, kMaxBfsDepth);
            if (d < 0)
                continue;
            int contrib = 5 - d;
            if (contrib < 1)
                contrib = 1;
            input_proximity += contrib;
            if (input_proximity >= 25)
            {
                input_proximity = 25;
                break;
            }
        }
    }

    int sink_count = 0;
    {
        std::vector<callsite_t> sinks = sink_callsites_safe();
        std::unordered_set<ea_t> seen_sink_funcs;
        for (const auto& cs : sinks)
        {
            if (cs.func_ea == BADADDR)
                continue;
            if (!seen_sink_funcs.insert(cs.func_ea).second)
                continue;
            int d = callee_distance_to(g, func_ea, cs.func_ea, kMaxBfsDepth);
            if (d < 0)
                continue;
            int contrib = 5 - d;
            if (contrib < 1)
                contrib = 1;
            sink_count += contrib;
            if (sink_count >= 25)
            {
                sink_count = 25;
                break;
            }
        }
    }

    int missing_validators = 0;
    if (sum != nullptr)
    {
        std::set<int> diff;
        for (int idx : sum->params_passed_to_sinks)
        {
            if (sum->params_validated.count(idx) == 0)
                diff.insert(idx);
        }
        missing_validators = static_cast<int>(diff.size()) * 4;
        if (missing_validators > 20)
            missing_validators = 20;
    }

    int complexity = 0;
    if (sum != nullptr)
    {
        double v = std::log2(static_cast<double>(sum->cyclomatic + 1)) * 3.0;
        if (v < 0.0) v = 0.0;
        if (v > 15.0) v = 15.0;
        complexity = static_cast<int>(v);
    }

    int taint_paths = 0;
    if (sum != nullptr)
    {
        if (!sum->input_sources_called.empty() && !sum->sinks_reached.empty())
        {
            taint_paths = static_cast<int>(sum->input_sources_called.size() * sum->sinks_reached.size());
        }
        else if (sum->returns_tainted && !sum->sinks_reached.empty())
        {
            taint_paths = static_cast<int>(sum->sinks_reached.size());
        }
        if (taint_paths > 15)
            taint_paths = 15;
    }

    out.input_proximity    = input_proximity;
    out.sink_count         = sink_count;
    out.missing_validators = missing_validators;
    out.complexity         = complexity;
    out.taint_paths        = taint_paths;
    out.classification     = classify_function_role(func_ea);
    out.total_score = input_proximity + sink_count + missing_validators + complexity + taint_paths;
    if (out.total_score > 100)
        out.total_score = 100;
    return out;
}

std::vector<ea_t> attacker_reachable_functions()
{
    std::vector<ea_t> out;
    const call_graph_t& g = cached_call_graph();
    std::vector<callsite_t> sources = input_source_callsites_safe();

    std::unordered_set<ea_t> seen;
    std::deque<ea_t> q;
    for (const auto& cs : sources)
    {
        if (cs.func_ea == BADADDR)
            continue;
        if (seen.insert(cs.func_ea).second)
            q.push_back(cs.func_ea);
    }

    while (!q.empty())
    {
        ea_t cur = q.front();
        q.pop_front();
        out.push_back(cur);
        auto it = g.callers.find(cur);
        if (it == g.callers.end())
            continue;
        for (ea_t prev : it->second)
        {
            if (!seen.insert(prev).second)
                continue;
            q.push_back(prev);
            if (q.size() > static_cast<std::size_t>(kMaxQueueElements))
                break;
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

namespace
{

bool function_calls_count(const taint::func_summary_t* sum, bool (*pred)(const std::string&))
{
    if (sum == nullptr)
        return false;
    for (const auto& nm : sum->allocs_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->frees_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->validators_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->input_sources_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->sinks_reached)
        if (pred(nm))
            return true;
    return false;
}

struct callee_counts_t
{
    int allocs = 0;
    int frees = 0;
    int validators = 0;
    int input_sources = 0;
    int sinks = 0;
    int crypto = 0;
    int total_calls = 0;
};

callee_counts_t collect_callee_counts(ea_t func_ea)
{
    callee_counts_t cc;
    if (func_ea == BADADDR)
        return cc;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return cc;
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        if (nm.empty())
            continue;
        cc.total_calls++;
        if (is_alloc_like(nm)) cc.allocs++;
        if (is_free_like(nm)) cc.frees++;
        if (is_validator_like(nm)) cc.validators++;
        if (is_input_source_like(nm)) cc.input_sources++;
        if (is_dangerous_sink(nm)) cc.sinks++;
        if (is_crypto_function(nm)) cc.crypto++;
    }
    return cc;
}

bool function_has_irp_pattern(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    static const std::vector<std::string> irp_apis = {
        "IoCallDriver", "IoCompleteRequest", "IofCompleteRequest",
        "IoBuildSynchronousFsdRequest", "IoAllocateIrp",
        "IoCreateDevice", "IoCreateSymbolicLink",
    };
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        for (const auto& a : irp_apis)
        {
            if (name_matches_signature(nm, a))
                return true;
        }
    }
    return false;
}

bool function_has_ipc_pattern(ea_t func_ea, int& count)
{
    count = 0;
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    static const std::vector<std::string> ipc_apis = {
        "recv", "recvfrom", "send", "sendto", "WSARecv", "WSASend",
        "WSARecvFrom", "WSASendTo", "WriteFile", "ReadFile",
        "TransmitFile", "TransmitPackets",
    };
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        for (const auto& a : ipc_apis)
        {
            if (name_matches_signature(nm, a))
            {
                count++;
                break;
            }
        }
    }
    return count >= 2;
}

bool function_has_validator_pattern(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        if (is_validator_like(nm))
            return true;
    }
    return false;
}

bool function_registers_callbacks(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    auto cbs = known_callback_apis();
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        for (const auto& a : cbs)
        {
            if (name_matches_signature(nm, a))
                return true;
        }
    }
    return false;
}

struct switch_visitor_t : public ctree_visitor_t
{
    int  switch_count = 0;
    int  default_count = 0;
    int  total_cases = 0;
    bool subject_is_field = false;
    bool subject_is_var = false;

    switch_visitor_t() : ctree_visitor_t(CV_FAST) {}

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (ins == nullptr)
            return 0;
        if (ins->op == cit_switch && ins->cswitch != nullptr)
        {
            switch_count++;
            const cexpr_t& subj = ins->cswitch->expr;
            const cexpr_t* x = unwrap_cast_ref(&subj);
            if (x != nullptr)
            {
                if (x->op == cot_memptr || x->op == cot_memref)
                    subject_is_field = true;
                else if (x->op == cot_var)
                    subject_is_var = true;
            }
            for (std::size_t i = 0; i < ins->cswitch->cases.size(); ++i)
            {
                const ccase_t& cc = ins->cswitch->cases[i];
                total_cases += static_cast<int>(cc.values.size());
                if (cc.values.empty())
                    default_count++;
            }
        }
        return 0;
    }
};

bool function_has_dispatcher_shape(ea_t func_ea, int& num_cases, bool& has_default)
{
    num_cases = 0;
    has_default = false;
    cfuncptr_t cf = decompile_safe(func_ea);
    if (!cf)
        return false;
    switch_visitor_t v;
    v.apply_to(&cf->body, nullptr);
    num_cases = v.total_cases;
    has_default = v.default_count > 0;
    return v.switch_count > 0 && v.total_cases > 5 && has_default;
}

bool function_has_parser_shape(ea_t func_ea)
{
    cfuncptr_t cf = decompile_safe(func_ea);
    if (!cf)
        return false;
    switch_visitor_t v;
    v.apply_to(&cf->body, nullptr);
    if (v.switch_count == 0)
        return false;
    return v.subject_is_field;
}

}

std::string classify_function_role(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return std::string("unknown");
    auto& te = aida::vuln::taint::engine();
    if (!te.is_analyzed())
        te.analyze_all();
    const auto* sum = te.get_summary(func_ea);

    std::string nm = func_name_for(func_ea);
    for (const auto& a : sig::ALLOC_FUNCS)
    {
        if (name_matches_signature(nm, a))
            return std::string("allocator");
    }
    for (const auto& f : sig::FREE_FUNCS)
    {
        if (name_matches_signature(nm, f))
            return std::string("deallocator");
    }
    for (const auto& v : sig::KERNEL_VALIDATORS)
    {
        if (name_matches_signature(nm, v))
            return std::string("validator");
    }

    callee_counts_t cc = collect_callee_counts(func_ea);

    if (cc.allocs > 2 && cc.allocs > (cc.total_calls / 2))
        return std::string("allocator");
    if (cc.frees > 2 && cc.frees > (cc.total_calls / 2))
        return std::string("deallocator");

    if (function_has_irp_pattern(func_ea))
        return std::string("ioctl_handler");

    int ipc_calls = 0;
    if (function_has_ipc_pattern(func_ea, ipc_calls))
        return std::string("ipc_endpoint");

    int num_cases = 0;
    bool has_default = false;
    if (function_has_dispatcher_shape(func_ea, num_cases, has_default))
        return std::string("dispatcher");

    if (function_has_parser_shape(func_ea))
        return std::string("parser");

    if (function_has_validator_pattern(func_ea) || (sum != nullptr && !sum->validators_called.empty()))
        return std::string("validator");

    if (function_registers_callbacks(func_ea))
        return std::string("callback");

    if (cc.crypto > 0 || (sum != nullptr && function_calls_count(sum, +[](const std::string& n) { return is_crypto_function(n); })))
        return std::string("crypto");

    return std::string("utility");
}

namespace
{

struct callback_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    std::unordered_set<std::string>* api_index = nullptr;
    std::size_t limit = 0;

    callback_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out,
                       std::unordered_set<std::string>* idx, std::size_t lim)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), api_index(idx), limit(lim) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (findings == nullptr || api_index == nullptr || cfunc == nullptr)
            return 0;
        if (findings->size() >= limit)
            return 1;
        if (expr == nullptr)
            return 0;

        if (expr->op == cot_call)
        {
            std::string nm = resolve_call_target_name(expr);
            if (nm.empty())
                return 0;
            std::string canonical;
            for (const auto& a : *api_index)
            {
                if (name_matches_signature(nm, a))
                {
                    canonical = a;
                    break;
                }
            }
            if (canonical.empty())
                return 0;
            int idx = callback_arg_index(canonical);
            ea_t cb_ea = literal_callback_arg(expr, idx);
            if (cb_ea == BADADDR)
                return 0;
            if (!ea_is_function(cb_ea))
                return 0;

            vuln_finding_t f;
            std::ostringstream id;
            id << "vuln/callback_register/" << std::hex << std::uppercase
               << static_cast<std::uint64_t>(expr->ea);
            f.id = id.str();
            f.primary_ea = expr->ea;
            f.related_eas.push_back(cb_ea);
            cwe_t cwe = cwe_for_callback(canonical);
            if (cwe.id != 0)
                f.cwes.push_back(cwe);
            f.severity   = security_sensitive_callback_api(canonical) ? severity_t::low : severity_t::info;
            f.confidence = confidence_t::likely;
            std::ostringstream tt;
            tt << "Function-pointer registration: " << canonical << "(... &"
               << func_name_for(cb_ea) << ")";
            f.title = tt.str();
            std::ostringstream rat;
            rat << "Call to " << canonical << " at " << ea_to_hex(expr->ea)
                << " registers literal callback " << ea_to_hex(cb_ea)
                << " (" << func_name_for(cb_ea) << ")";
            f.rationale = rat.str();
            json ev;
            ev["api"]              = canonical;
            ev["call_ea"]          = ea_to_hex(expr->ea);
            ev["callback_ea"]      = ea_to_hex(cb_ea);
            ev["callback_name"]    = func_name_for(cb_ea);
            ev["callback_arg_idx"] = idx;
            f.evidence = std::move(ev);
            findings->push_back(std::move(f));
        }
        else if (expr->op == cot_asg && expr->x != nullptr && expr->y != nullptr)
        {
            const cexpr_t* lhs = unwrap_cast_ref(expr->x);
            if (lhs != nullptr && (lhs->op == cot_idx || lhs->op == cot_memptr || lhs->op == cot_memref))
            {
                qstring lhs_text;
                expr->x->print1(&lhs_text, cfunc);
                tag_remove(&lhs_text);
                std::string ls(lhs_text.c_str());
                std::string lower_ls = ascii_lower(ls);
                if (lower_ls.find("majorfunction") != std::string::npos)
                {
                    const cexpr_t* rhs = unwrap_cast_ref(expr->y);
                    ea_t cb_ea = BADADDR;
                    if (rhs != nullptr)
                    {
                        if (rhs->op == cot_obj)
                            cb_ea = rhs->obj_ea;
                    }
                    if (cb_ea != BADADDR && ea_is_function(cb_ea))
                    {
                        vuln_finding_t f;
                        std::ostringstream id;
                        id << "vuln/callback_register/major_function/" << std::hex << std::uppercase
                           << static_cast<std::uint64_t>(expr->ea);
                        f.id = id.str();
                        f.primary_ea = expr->ea;
                        f.related_eas.push_back(cb_ea);
                        f.cwes.push_back(make_cwe(358, cwe_name_for(358)));
                        f.severity   = severity_t::low;
                        f.confidence = confidence_t::likely;
                        std::ostringstream tt;
                        tt << "Function-pointer registration: DriverObject->MajorFunction[*] = &"
                           << func_name_for(cb_ea);
                        f.title = tt.str();
                        std::ostringstream rat;
                        rat << "Assignment at " << ea_to_hex(expr->ea)
                            << " stores literal callback " << ea_to_hex(cb_ea)
                            << " (" << func_name_for(cb_ea) << ") into a DriverObject MajorFunction slot";
                        f.rationale = rat.str();
                        json ev;
                        ev["assignment_ea"] = ea_to_hex(expr->ea);
                        ev["callback_ea"]   = ea_to_hex(cb_ea);
                        ev["callback_name"] = func_name_for(cb_ea);
                        ev["lhs"]           = ls;
                        f.evidence = std::move(ev);
                        findings->push_back(std::move(f));
                    }
                }
            }
        }

        if (findings->size() >= limit)
            return 1;
        return 0;
    }
};

}

std::vector<vuln_finding_t> enumerate_callbacks()
{
    std::vector<vuln_finding_t> out;
    if (!init_hexrays_plugin())
        return out;

    auto apis = known_callback_apis();
    std::unordered_set<std::string> api_index;
    for (auto& a : apis)
        api_index.insert(a);

    std::vector<callsite_t> calls = aida::vuln::callsites::all_calls_to(apis);
    std::unordered_set<ea_t> caller_funcs;
    for (const auto& cs : calls)
    {
        if (cs.func_ea != BADADDR)
            caller_funcs.insert(cs.func_ea);
    }

    const std::size_t limit = 1024;

    if (aida::vuln::kernel_engine::is_kernel_driver())
    {
        const std::size_t fq = get_func_qty();
        for (std::size_t i = 0; i < fq && caller_funcs.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
        {
            func_t* pfn = getn_func(i);
            if (pfn == nullptr)
                continue;
            caller_funcs.insert(pfn->start_ea);
        }
    }

    for (ea_t fea : caller_funcs)
    {
        if (out.size() >= limit)
            break;
        cfuncptr_t cf = decompile_safe(fea);
        if (!cf)
            continue;
        callback_visitor_t v(cf.operator->(), &out, &api_index, limit);
        v.apply_to(&cf->body, nullptr);
    }

    return out;
}

namespace
{

vuln_finding_t make_wxe_segment_finding(const segment_t& s, const std::string& name)
{
    vuln_finding_t f;
    std::ostringstream id;
    id << "vuln/wx_segment/" << std::hex << std::uppercase
       << static_cast<std::uint64_t>(s.start_ea);
    f.id = id.str();
    f.primary_ea = s.start_ea;
    f.related_eas.push_back(s.end_ea);
    f.cwes.push_back(make_cwe(1188, cwe_name_for(1188)));
    f.severity   = severity_t::critical;
    f.confidence = confidence_t::confirmed;
    std::ostringstream tt;
    tt << "Writable+executable segment: " << (name.empty() ? std::string("<unnamed>") : name);
    f.title = tt.str();
    std::ostringstream rat;
    rat << "Segment '" << name << "' [" << ea_to_hex(s.start_ea) << ", "
        << ea_to_hex(s.end_ea) << ") has both SEGPERM_EXEC and SEGPERM_WRITE set, "
        << "violating W^X policy and providing a primitive for code injection or self-modification.";
    f.rationale = rat.str();
    json ev;
    ev["segment_name"]   = name;
    ev["start_ea"]       = ea_to_hex(s.start_ea);
    ev["end_ea"]         = ea_to_hex(s.end_ea);
    ev["perm"]           = static_cast<int>(s.perm);
    ev["perm_exec"]      = (s.perm & SEGPERM_EXEC)  != 0;
    ev["perm_write"]     = (s.perm & SEGPERM_WRITE) != 0;
    ev["perm_read"]      = (s.perm & SEGPERM_READ)  != 0;
    ev["source"]         = "segment";
    f.evidence = std::move(ev);
    return f;
}

vuln_finding_t make_wxe_pe_section_finding(ea_t base, ea_t va, ea_t end_va,
                                           const std::string& name, std::uint32_t chars)
{
    vuln_finding_t f;
    std::ostringstream id;
    id << "vuln/wx_pe_section/" << std::hex << std::uppercase
       << static_cast<std::uint64_t>(va);
    f.id = id.str();
    f.primary_ea = va;
    f.related_eas.push_back(base);
    f.related_eas.push_back(end_va);
    f.cwes.push_back(make_cwe(1188, cwe_name_for(1188)));
    f.severity   = severity_t::critical;
    f.confidence = confidence_t::confirmed;
    std::ostringstream tt;
    tt << "Writable+executable PE section: " << (name.empty() ? std::string("<unnamed>") : name);
    f.title = tt.str();
    std::ostringstream rat;
    rat << "PE section '" << name << "' has both IMAGE_SCN_MEM_EXECUTE (0x20000000) and "
        << "IMAGE_SCN_MEM_WRITE (0x80000000) set in characteristics (0x"
        << std::hex << std::uppercase << chars << ").";
    f.rationale = rat.str();
    json ev;
    ev["section_name"]    = name;
    ev["va"]              = ea_to_hex(va);
    ev["end_va"]          = ea_to_hex(end_va);
    ev["characteristics"] = chars;
    ev["execute_bit"]     = true;
    ev["write_bit"]       = true;
    ev["source"]          = "pe_header";
    f.evidence = std::move(ev);
    return f;
}

}

std::vector<vuln_finding_t> find_writable_executable_pages()
{
    std::vector<vuln_finding_t> out;

    const int qty = get_segm_qty();
    for (int i = 0; i < qty; ++i)
    {
        segment_t* s = getnseg(i);
        if (s == nullptr)
            continue;
        if (s->perm == 0)
            continue;
        if ((s->perm & SEGPERM_EXEC) == 0 || (s->perm & SEGPERM_WRITE) == 0)
            continue;
        qstring nm;
        std::string name;
        if (get_segm_name(&nm, s, 0) > 0 && !nm.empty())
            name = nm.c_str();
        out.push_back(make_wxe_segment_finding(*s, name));
    }

    ea_t base = get_imagebase();
    if (is_loaded(base) && get_word(base) == 0x5A4D)
    {
        std::uint32_t pe_off = get_dword(base + 0x3C);
        ea_t pe_hdr = base + pe_off;
        if (is_loaded(pe_hdr) && get_dword(pe_hdr) == 0x00004550)
        {
            ea_t coff = pe_hdr + 4;
            std::uint16_t num_sections = get_word(coff + 2);
            std::uint16_t opt_size     = get_word(coff + 16);
            ea_t opt = coff + 20;
            ea_t sec_tbl = opt + opt_size;
            for (int si = 0; si < static_cast<int>(num_sections); ++si)
            {
                ea_t sec = sec_tbl + si * 40;
                if (!is_loaded(sec))
                    break;
                char sname[9] = {};
                for (int jj = 0; jj < 8; ++jj)
                    sname[jj] = static_cast<char>(get_byte(sec + jj));
                std::uint32_t vsize = get_dword(sec + 8);
                std::uint32_t vrva  = get_dword(sec + 12);
                std::uint32_t chars = get_dword(sec + 36);
                if (((chars & 0x20000000u) != 0) && ((chars & 0x80000000u) != 0))
                {
                    ea_t va     = base + vrva;
                    ea_t end_va = va + vsize;
                    out.push_back(make_wxe_pe_section_finding(base, va, end_va,
                                                              std::string(sname), chars));
                }
            }
        }
    }

    return out;
}

namespace
{

std::string extract_snippet_at(cfunc_t* cf, ea_t ea)
{
    if (cf == nullptr || ea == BADADDR)
        return std::string();
    citem_t* it = cf->body.find_closest_addr(ea);
    if (it == nullptr)
        return std::string();
    qstring out;
    if (it->is_expr())
        static_cast<cexpr_t*>(it)->print1(&out, cf);
    else
        static_cast<cinsn_t*>(it)->print1(&out, cf);
    tag_remove(&out);
    std::string s(out.c_str());
    if (s.size() > 200)
    {
        s.resize(197);
        s.append("...");
    }
    return s;
}

}

namespace tools
{

namespace
{

agent_tools::tool_result_t handle_analyze_function_attack_surface(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(OBFSTR("address parameter is required"));
    ea_t fea = *addr;
    func_t* pfn = get_func(fea);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(OBFSTR("address does not lie inside a function"));
    fea = pfn->start_ea;

    attack_surface_score_t score;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        score = score_function(fea);
    }

    json data;
    data["func_ea"]            = ea_to_hex(score.func_ea);
    data["func_name"]          = func_name_for(score.func_ea);
    data["total_score"]        = score.total_score;
    data["input_proximity"]    = score.input_proximity;
    data["sink_count"]         = score.sink_count;
    data["missing_validators"] = score.missing_validators;
    data["complexity"]         = score.complexity;
    data["taint_paths"]        = score.taint_paths;
    data["classification"]     = score.classification;

    json breakdown = json::object();
    {
        json b = json::object();
        b["score"] = score.input_proximity;
        b["max"]   = 25;
        b["description"] = "Reachability from input sources via reverse call graph (depth <= 4)";
        breakdown["input_proximity"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.sink_count;
        b["max"]   = 25;
        b["description"] = "Forward reachability to dangerous sinks via call graph (depth <= 4)";
        breakdown["sink_count"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.missing_validators;
        b["max"]   = 20;
        b["description"] = "Tainted parameters that flow to sinks without validation";
        breakdown["missing_validators"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.complexity;
        b["max"]   = 15;
        b["description"] = "log2(cyclomatic + 1) * 3, capped at 15";
        breakdown["complexity"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.taint_paths;
        b["max"]   = 15;
        b["description"] = "Number of input-source x sink combinations on this function";
        breakdown["taint_paths"] = std::move(b);
    }
    data["breakdown"] = std::move(breakdown);

    std::ostringstream msg;
    msg << OBFSTR("Attack-surface score: ") << score.total_score << OBFSTR("/100 (")
        << score.classification << OBFSTR(")");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_list_attacker_reachable_functions(const json& params)
{
    int limit = extract_int_param(params, "limit", 200);
    if (limit <= 0) limit = 200;
    if (limit > 4096) limit = 4096;

    std::vector<ea_t> funcs;
    std::size_t total_sources = 0;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        funcs = attacker_reachable_functions();
        total_sources = input_source_callsites_safe().size();
    }

    json arr = json::array();
    int emitted = 0;
    for (ea_t fea : funcs)
    {
        if (emitted >= limit)
            break;
        json e;
        e["ea"]   = ea_to_hex(fea);
        e["name"] = func_name_for(fea);
        arr.push_back(std::move(e));
        emitted++;
    }

    json data;
    data["count"]               = static_cast<int>(funcs.size());
    data["limit"]               = limit;
    data["functions"]           = std::move(arr);
    data["total_input_sources"] = total_sources;

    std::ostringstream msg;
    msg << OBFSTR("Attacker-reachable functions: ") << funcs.size();
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_classify_function_role(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(OBFSTR("address parameter is required"));
    func_t* pfn = get_func(*addr);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(OBFSTR("address does not lie inside a function"));
    ea_t fea = pfn->start_ea;

    std::string role;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        role = classify_function_role(fea);
    }

    json data;
    data["func_ea"]   = ea_to_hex(fea);
    data["func_name"] = func_name_for(fea);
    data["role"]      = role;

    std::ostringstream msg;
    msg << OBFSTR("Function role: ") << role;
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_enumerate_callbacks(const json&)
{
    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = enumerate_callbacks();
    }
    json data;
    data["count"]    = findings.size();
    data["findings"] = findings_to_json_array(findings);
    std::ostringstream msg;
    msg << OBFSTR("Callback registration scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_writable_executable_pages(const json&)
{
    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = find_writable_executable_pages();
    }
    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 1188;
    std::ostringstream msg;
    msg << OBFSTR("W^X violation scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_explain_vulnerability_chain(const json& params)
{
    const std::string source_spec = params.is_object() && params.contains("source_address") &&
                                    params["source_address"].is_string()
        ? params["source_address"].get<std::string>() : std::string();
    const std::string sink_spec = params.is_object() && params.contains("sink_address") &&
                                  params["sink_address"].is_string()
        ? params["sink_address"].get<std::string>() : std::string();
    if (source_spec.empty() || sink_spec.empty())
        return agent_tools::tool_result_t::error(OBFSTR("source_address and sink_address required"));

    ea_t source_ea = resolve_address_or_name(source_spec);
    ea_t sink_ea   = resolve_address_or_name(sink_spec);
    if (source_ea == BADADDR)
        return agent_tools::tool_result_t::error(OBFSTR("Could not resolve source address: ") + source_spec);
    if (sink_ea == BADADDR)
        return agent_tools::tool_result_t::error(OBFSTR("Could not resolve sink address: ") + sink_spec);

    std::vector<aida::vuln::taint::taint_path_t> paths;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        paths = aida::vuln::taint::engine().trace_paths(source_ea, sink_ea, 8, 8);
    }

    json paths_arr = json::array();
    for (const auto& p : paths)
    {
        json pj;
        std::ostringstream md;
        md << "## Taint path from " << p.origin.source_name << " ("
           << ea_to_hex(p.origin.source_ea) << ") to "
           << p.sink_name << " (" << ea_to_hex(p.sink_ea) << ")\n\n";
        md << "Vulnerability type: **" << p.vulnerability_type << "**  \n";
        md << "Severity: **" << severity_str(p.severity) << "**  \n";
        md << "Confidence: **" << confidence_str(p.confidence) << "**\n\n";

        json steps_arr = json::array();
        int step_idx = 1;
        for (const auto& st : p.steps)
        {
            md << "### Step " << step_idx << ": " << st.func_name << " (" << ea_to_hex(st.func_ea) << ")\n";
            md << "- EA: " << ea_to_hex(st.ea) << "\n";
            if (!st.description.empty())
                md << "- Action: " << st.description << "\n";
            std::string snippet;
            cfuncptr_t cf = decompile_safe(st.func_ea);
            if (cf)
                snippet = extract_snippet_at(cf.operator->(), st.ea);
            if (!snippet.empty())
                md << "```c\n" << snippet << "\n```\n";
            if (!st.condition.empty())
                md << "- Condition: `" << st.condition << "`\n";
            md << "\n";

            json sj;
            sj["ea"]          = ea_to_hex(st.ea);
            sj["func_ea"]     = ea_to_hex(st.func_ea);
            sj["func_name"]   = st.func_name;
            sj["snippet"]     = snippet;
            sj["condition"]   = st.condition;
            sj["summary"]     = st.description;
            steps_arr.push_back(std::move(sj));
            step_idx++;
        }

        if (!p.conditions.empty())
        {
            md << "### Accumulated path conditions\n";
            for (const auto& c : p.conditions)
                md << "- `" << c << "`\n";
            md << "\n";
        }

        pj["narrative_md"] = md.str();
        pj["steps"]        = std::move(steps_arr);
        json conds = json::array();
        for (const auto& c : p.conditions)
            conds.push_back(c);
        pj["conditions"] = std::move(conds);
        json origin_j = json::object();
        origin_j["source_ea"]      = ea_to_hex(p.origin.source_ea);
        origin_j["source_func_ea"] = ea_to_hex(p.origin.source_func_ea);
        origin_j["source_name"]    = p.origin.source_name;
        origin_j["kind"]           = aida::vuln::taint::taint_kind_str(p.origin.kind);
        pj["origin"] = std::move(origin_j);

        json sink_j = json::object();
        sink_j["sink_ea"]        = ea_to_hex(p.sink_ea);
        sink_j["sink_func_ea"]   = ea_to_hex(p.sink_func_ea);
        sink_j["sink_name"]      = p.sink_name;
        sink_j["sink_arg_index"] = p.sink_arg_index;
        pj["sink"] = std::move(sink_j);
        pj["vulnerability_type"] = p.vulnerability_type;
        pj["severity"]           = severity_str(p.severity);
        pj["confidence"]         = confidence_str(p.confidence);
        paths_arr.push_back(std::move(pj));
    }

    json data;
    data["paths"]       = std::move(paths_arr);
    data["total_paths"] = paths.size();
    data["source_ea"]   = ea_to_hex(source_ea);
    data["sink_ea"]     = ea_to_hex(sink_ea);
    data["source_func"] = func_name_for(containing_func_ea(source_ea));
    data["sink_func"]   = func_name_for(containing_func_ea(sink_ea));

    std::ostringstream msg;
    msg << OBFSTR("Vulnerability chain explanation: ") << paths.size() << OBFSTR(" path(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct state_machine_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    bool subject_is_state = false;
    int  total_cases = 0;
    int  num_states = 0;
    bool unguarded = false;
    std::vector<json> transitions;
    std::vector<json> raw_subjects;

    state_machine_visitor_t(cfunc_t* cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}

    static bool is_state_like_name(const std::string& s)
    {
        std::string l = ascii_lower(s);
        return l.find("state") != std::string::npos ||
               l.find("status") != std::string::npos ||
               l.find("phase") != std::string::npos ||
               l.find("mode") != std::string::npos ||
               l.find("step") != std::string::npos ||
               l.find("stage") != std::string::npos ||
               l.find("fsm") != std::string::npos;
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || ins == nullptr)
            return 0;
        if (ins->op != cit_switch || ins->cswitch == nullptr)
            return 0;

        const cexpr_t& subj = ins->cswitch->expr;
        const cexpr_t* x = unwrap_cast_ref(&subj);
        std::string subj_text;
        {
            qstring qs;
            subj.print1(&qs, cfunc);
            tag_remove(&qs);
            subj_text = qs.c_str();
        }
        bool is_state = false;
        if (x != nullptr)
        {
            if (x->op == cot_memptr || x->op == cot_memref || x->op == cot_obj || x->op == cot_var)
            {
                if (is_state_like_name(subj_text))
                    is_state = true;
            }
        }

        for (std::size_t i = 0; i < ins->cswitch->cases.size(); ++i)
        {
            const ccase_t& cc = ins->cswitch->cases[i];
            total_cases += static_cast<int>(cc.values.size());
        }
        if (!is_state)
            return 0;

        subject_is_state = true;
        num_states += static_cast<int>(ins->cswitch->cases.size());

        for (std::size_t i = 0; i < ins->cswitch->cases.size(); ++i)
        {
            const ccase_t& cc = ins->cswitch->cases[i];
            std::uint64_t case_value = cc.values.empty() ? 0ull : cc.values.front();
            std::int64_t to_value = -1;
            ea_t code_ea = cc.ea;
            bool guarded = false;
            const cinsn_t& body = static_cast<const cinsn_t&>(cc);
            if (body.op == cit_block && body.cblock != nullptr)
            {
                for (const cinsn_t& stmt : *body.cblock)
                {
                    if (stmt.op == cit_if && stmt.cif != nullptr)
                        guarded = true;
                    if (stmt.op == cit_expr && stmt.cexpr != nullptr &&
                        stmt.cexpr->op == cot_asg)
                    {
                        const cexpr_t* lhs = unwrap_cast_ref(stmt.cexpr->x);
                        const cexpr_t* rhs = unwrap_cast_ref(stmt.cexpr->y);
                        if (lhs != nullptr && rhs != nullptr && rhs->op == cot_num && rhs->n != nullptr)
                        {
                            qstring lhs_q;
                            stmt.cexpr->x->print1(&lhs_q, cfunc);
                            tag_remove(&lhs_q);
                            std::string lhs_text(lhs_q.c_str());
                            if (lhs_text == subj_text)
                            {
                                to_value = static_cast<std::int64_t>(rhs->n->_value);
                                code_ea  = stmt.ea;
                                break;
                            }
                        }
                    }
                }
            }
            if (!guarded && to_value >= 0)
                unguarded = true;
            json tr;
            tr["case_value"] = case_value;
            tr["from"]       = case_value;
            tr["to"]         = to_value;
            tr["code_ea"]    = ea_to_hex(code_ea);
            tr["guarded"]    = guarded;
            transitions.push_back(std::move(tr));
        }

        return 0;
    }
};

}

agent_tools::tool_result_t handle_map_state_machine(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(OBFSTR("address parameter is required"));
    func_t* pfn = get_func(*addr);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(OBFSTR("address does not lie inside a function"));
    ea_t fea = pfn->start_ea;

    cfuncptr_t cf(nullptr);
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        cf = decompile_safe(fea);
    }
    if (!cf)
        return agent_tools::tool_result_t::error(OBFSTR("Could not decompile function"));

    state_machine_visitor_t v(cf.operator->());
    v.apply_to(&cf->body, nullptr);

    json data;
    data["func_ea"]          = ea_to_hex(fea);
    data["func_name"]        = func_name_for(fea);
    data["is_state_machine"] = v.subject_is_state;
    data["num_states"]       = v.num_states;
    json transitions_j = json::array();
    for (const auto& tr : v.transitions)
        transitions_j.push_back(tr);
    data["transitions"] = std::move(transitions_j);

    std::vector<vuln_finding_t> findings;
    if (v.subject_is_state && v.unguarded)
    {
        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/state_machine_illegal/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(fea);
        f.id = id.str();
        f.primary_ea = fea;
        f.cwes.push_back(make_cwe(0, "Illegal state transition"));
        f.severity   = severity_t::info;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "Possible illegal state transitions in " << func_name_for(fea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Function " << func_name_for(fea) << " contains a state-machine switch with at least "
            << "one case that updates the state field without an explicit guard. Reaching an unexpected "
            << "state from an attacker-influenced input may bypass intended sequencing.";
        f.rationale = rat.str();
        json ev;
        ev["transitions"] = data["transitions"];
        f.evidence = std::move(ev);
        findings.push_back(std::move(f));
    }
    data["findings"] = findings_to_json_array(findings);

    std::ostringstream msg;
    msg << (v.subject_is_state ? OBFSTR("State machine detected: ")
                                : OBFSTR("No state machine: "))
        << func_name_for(fea);
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct length_arith_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    length_arith_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;

        bool is_memcpy_like = name_matches_signature(nm, "memcpy") ||
                              name_matches_signature(nm, "memmove") ||
                              name_matches_signature(nm, "RtlCopyMemory") ||
                              name_matches_signature(nm, "RtlMoveMemory");
        if (!is_memcpy_like)
            return 0;
        if (expr->a == nullptr || expr->a->size() < 3)
            return 0;

        const cexpr_t* sz = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[2]));
        if (sz == nullptr)
            return 0;

        bool size_is_arith = (sz->op == cot_add || sz->op == cot_sub || sz->op == cot_mul ||
                              sz->op == cot_shl);
        bool size_is_var   = (sz->op == cot_var);

        if (!size_is_arith && !size_is_var)
            return 0;

        bool found_off_by_one = false;
        if (sz->op == cot_sub && sz->y != nullptr)
        {
            const cexpr_t* rhs = unwrap_cast_ref(sz->y);
            if (rhs != nullptr && rhs->op == cot_num && rhs->n != nullptr && rhs->n->_value == 1)
                found_off_by_one = true;
        }

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/proto_parser/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(expr->ea);
        f.id = id.str();
        f.primary_ea = expr->ea;
        f.related_eas.push_back(func_ea);

        int cwe_id = found_off_by_one ? 193 : 130;
        f.cwes.push_back(make_cwe(cwe_id, cwe_name_for(cwe_id)));
        f.severity   = found_off_by_one ? severity_t::medium : severity_t::high;
        f.confidence = confidence_t::plausible;

        std::ostringstream tt;
        tt << (found_off_by_one ? "Possible off-by-one in " : "Length-not-checked in ")
           << nm << "(...) call within " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Call to " << nm << " at " << ea_to_hex(expr->ea)
            << " uses a non-literal size expression that may not be bounds-checked against "
            << "the destination size. ";
        if (found_off_by_one)
            rat << "Detected pattern length=n-1 used in " << nm << "(dst, src, n).";
        f.rationale = rat.str();
        json ev;
        ev["call_ea"]   = ea_to_hex(expr->ea);
        ev["callee"]    = nm;
        ev["func_ea"]   = ea_to_hex(func_ea);
        ev["off_by_one"] = found_off_by_one;
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));

        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_protocol_parser_bugs(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        auto& te = aida::vuln::taint::engine();
        if (!te.is_analyzed())
            te.analyze_all();

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            const auto* sum = te.get_summary(fea);
            bool relevant = sum != nullptr && (!sum->input_sources_called.empty() ||
                                                !sum->params_passed_to_sinks.empty());
            if (!relevant && !addr.has_value())
                continue;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            length_arith_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]    = findings.size();
    data["findings"] = findings_to_json_array(findings);
    std::ostringstream msg;
    msg << OBFSTR("Protocol-parser bug scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

bool tinfo_is_unsigned_integer(const tinfo_t& t)
{
    if (t.empty())
        return false;
    if (!t.is_integral())
        return false;
    return t.is_unsigned();
}

bool tinfo_is_signed_integer(const tinfo_t& t)
{
    if (t.empty())
        return false;
    if (!t.is_integral())
        return false;
    return t.is_signed();
}

const lvar_t* lvar_at(cfunc_t* cf, const cexpr_t* e)
{
    if (cf == nullptr || e == nullptr)
        return nullptr;
    const cexpr_t* x = unwrap_cast_ref(e);
    if (x == nullptr || x->op != cot_var)
        return nullptr;
    lvars_t* lv = cf->get_lvars();
    if (lv == nullptr)
        return nullptr;
    if (x->v.idx < 0 || static_cast<std::size_t>(x->v.idx) >= lv->size())
        return nullptr;
    return &(*lv)[x->v.idx];
}

bool is_signed_compare(ctype_t op)
{
    return op == cot_sgt || op == cot_sge || op == cot_slt || op == cot_sle;
}

bool is_compare(ctype_t op)
{
    return is_signed_compare(op) || op == cot_ugt || op == cot_uge ||
           op == cot_ult || op == cot_ule || op == cot_eq || op == cot_ne;
}

struct loose_bounds_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    loose_bounds_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || findings == nullptr || ins == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (ins->op != cit_if || ins->cif == nullptr)
            return 0;
        const cexpr_t& cond = ins->cif->expr;
        if (!is_signed_compare(cond.op))
            return 0;
        const cexpr_t* lhs = unwrap_cast_ref(cond.x);
        const cexpr_t* rhs = unwrap_cast_ref(cond.y);
        if (lhs == nullptr || rhs == nullptr)
            return 0;

        bool rhs_const = (rhs->op == cot_num);
        if (!rhs_const)
            return 0;

        const lvar_t* lv = lvar_at(cfunc, lhs);
        if (lv == nullptr)
            return 0;
        if (!tinfo_is_unsigned_integer(lv->tif))
            return 0;

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/loose_bounds/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(ins->ea);
        f.id = id.str();
        f.primary_ea = ins->ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(839, cwe_name_for(839)));
        f.severity   = severity_t::medium;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "Signed comparison of unsigned value in " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "if-condition at " << ea_to_hex(ins->ea)
            << " uses signed comparison operator on lvar '" << lv->name.c_str()
            << "' whose declared type is unsigned. A negative-valued attacker input may bypass the bound.";
        f.rationale = rat.str();
        json ev;
        ev["if_ea"]    = ea_to_hex(ins->ea);
        ev["lvar"]     = lv->name.c_str();
        ev["compare"]  = static_cast<int>(cond.op);
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_loose_bounds_checks(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            loose_bounds_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 839;
    std::ostringstream msg;
    msg << OBFSTR("Loose bounds-check scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct sign_confusion_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    sign_confusion_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static bool side_is_signed_or_unsigned(cfunc_t* cf, const cexpr_t* e, bool& is_signed, bool& is_unsigned)
    {
        is_signed   = false;
        is_unsigned = false;
        if (cf == nullptr || e == nullptr)
            return false;
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr)
            return false;
        if (x->op == cot_var)
        {
            const lvar_t* lv = lvar_at(cf, x);
            if (lv == nullptr)
                return false;
            is_signed   = tinfo_is_signed_integer(lv->tif);
            is_unsigned = tinfo_is_unsigned_integer(lv->tif);
            return is_signed || is_unsigned;
        }
        if (x->op == cot_num && x->n != nullptr)
        {
            is_signed   = static_cast<std::int64_t>(x->n->_value) < 0;
            is_unsigned = !is_signed;
            return true;
        }
        if (!x->type.empty())
        {
            is_signed   = x->type.is_signed();
            is_unsigned = x->type.is_unsigned();
            return is_signed || is_unsigned;
        }
        return false;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (!is_compare(expr->op))
            return 0;

        bool ls = false, lu = false, rs = false, ru = false;
        if (!side_is_signed_or_unsigned(cfunc, expr->x, ls, lu))
            return 0;
        if (!side_is_signed_or_unsigned(cfunc, expr->y, rs, ru))
            return 0;
        if ((ls && ru) || (lu && rs))
        {
            vuln_finding_t f;
            std::ostringstream id;
            id << "vuln/sign_confusion/" << std::hex << std::uppercase
               << static_cast<std::uint64_t>(expr->ea);
            f.id = id.str();
            f.primary_ea = expr->ea;
            f.related_eas.push_back(func_ea);
            f.cwes.push_back(make_cwe(195, cwe_name_for(195)));
            f.severity   = severity_t::medium;
            f.confidence = confidence_t::plausible;
            std::ostringstream tt;
            tt << "Signed/unsigned comparison in " << func_name_for(func_ea);
            f.title = tt.str();
            std::ostringstream rat;
            rat << "Comparison at " << ea_to_hex(expr->ea)
                << " mixes signed and unsigned operands. Implicit promotion to unsigned can "
                << "skip negative-value paths and bypass length checks.";
            f.rationale = rat.str();
            json ev;
            ev["expr_ea"]    = ea_to_hex(expr->ea);
            ev["lhs_signed"] = ls;
            ev["lhs_unsigned"] = lu;
            ev["rhs_signed"] = rs;
            ev["rhs_unsigned"] = ru;
            f.evidence = std::move(ev);
            findings->push_back(std::move(f));
        }
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_signed_unsigned_confusion(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            sign_confusion_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 195;
    std::ostringstream msg;
    msg << OBFSTR("Signed/unsigned-confusion scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct null_check_collector_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::unordered_set<int> checked_lvars;
    std::unordered_set<int> alloc_assigned_lvars;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    null_check_collector_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static int extract_lvar_idx(const cexpr_t* e)
    {
        if (e == nullptr)
            return -1;
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr)
            return -1;
        if (x->op == cot_var)
            return x->v.idx;
        return -1;
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || ins == nullptr)
            return 0;
        if (ins->op == cit_if && ins->cif != nullptr)
        {
            const cexpr_t& cond = ins->cif->expr;
            if (cond.op == cot_eq || cond.op == cot_ne)
            {
                const cexpr_t* x = unwrap_cast_ref(cond.x);
                const cexpr_t* y = unwrap_cast_ref(cond.y);
                bool x_zero = (x != nullptr && x->op == cot_num && x->n != nullptr && x->n->_value == 0);
                bool y_zero = (y != nullptr && y->op == cot_num && y->n != nullptr && y->n->_value == 0);
                if (y_zero)
                {
                    int idx = extract_lvar_idx(cond.x);
                    if (idx >= 0)
                        checked_lvars.insert(idx);
                }
                else if (x_zero)
                {
                    int idx = extract_lvar_idx(cond.y);
                    if (idx >= 0)
                        checked_lvars.insert(idx);
                }
            }
            else
            {
                int idx = extract_lvar_idx(&cond);
                if (idx >= 0)
                    checked_lvars.insert(idx);
            }
        }
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;

        if (expr->op == cot_asg && expr->x != nullptr && expr->y != nullptr)
        {
            const cexpr_t* lhs = unwrap_cast_ref(expr->x);
            const cexpr_t* rhs = unwrap_cast_ref(expr->y);
            if (lhs != nullptr && rhs != nullptr && lhs->op == cot_var && rhs->op == cot_call)
            {
                std::string nm = resolve_call_target_name(rhs);
                if (!nm.empty() && is_alloc_like(nm))
                    alloc_assigned_lvars.insert(lhs->v.idx);
            }
        }

        if (expr->op == cot_ptr || expr->op == cot_memptr || expr->op == cot_idx)
        {
            const cexpr_t* base = expr->op == cot_idx ? expr->x : expr->x;
            int idx = extract_lvar_idx(base);
            if (idx >= 0 && alloc_assigned_lvars.count(idx) && checked_lvars.count(idx) == 0)
            {
                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/missing_null_check/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(expr->ea);
                f.id = id.str();
                f.primary_ea = expr->ea;
                f.related_eas.push_back(func_ea);
                f.cwes.push_back(make_cwe(476, cwe_name_for(476)));
                f.severity   = severity_t::medium;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "Missing NULL check in " << func_name_for(func_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer lvar v" << idx << " was assigned from a possibly-NULL allocator and "
                    << "is dereferenced at " << ea_to_hex(expr->ea)
                    << " without an intervening explicit zero-check.";
                f.rationale = rat.str();
                json ev;
                ev["deref_ea"] = ea_to_hex(expr->ea);
                ev["lvar_idx"] = idx;
                f.evidence = std::move(ev);
                findings->push_back(std::move(f));
            }
        }
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_missing_null_check(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            null_check_collector_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 476;
    std::ostringstream msg;
    msg << OBFSTR("Missing-NULL-check scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

bool is_toctou_check_api(const std::string& nm)
{
    static const std::vector<std::string> apis = {
        "GetFileAttributesA", "GetFileAttributesW", "GetFileAttributesExA",
        "GetFileAttributesExW", "PathFileExistsA", "PathFileExistsW",
        "_access", "_waccess", "stat", "_stat", "_wstat", "_stat64", "_wstat64",
        "OpenFile", "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
    };
    for (const auto& a : apis)
    {
        if (name_matches_signature(nm, a))
            return true;
    }
    return false;
}

bool is_toctou_use_api(const std::string& nm)
{
    static const std::vector<std::string> apis = {
        "CreateFileA", "CreateFileW", "CreateFile2", "fopen", "_wfopen",
        "_open", "_wopen", "open",
        "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW",
        "MoveFileExA", "MoveFileExW", "CopyFileA", "CopyFileW",
        "CopyFileExA", "CopyFileExW",
    };
    for (const auto& a : apis)
    {
        if (name_matches_signature(nm, a))
            return true;
    }
    return false;
}

struct toctou_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;
    std::vector<std::pair<ea_t, std::string>> checks;

    toctou_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static std::string identify_arg(cfunc_t* cf, const cexpr_t* e)
    {
        if (cf == nullptr || e == nullptr)
            return std::string();
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr)
            return std::string();
        if (x->op == cot_var)
        {
            std::ostringstream ss;
            ss << "v" << x->v.idx;
            return ss.str();
        }
        if (x->op == cot_obj)
        {
            std::ostringstream ss;
            ss << "obj@" << std::hex << std::uppercase << static_cast<std::uint64_t>(x->obj_ea);
            return ss.str();
        }
        if (x->op == cot_str && x->string != nullptr)
            return std::string("str:") + x->string;
        return std::string();
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;

        if (is_toctou_check_api(nm))
        {
            if (expr->a != nullptr && !expr->a->empty())
            {
                std::string argk = identify_arg(cfunc, static_cast<const cexpr_t*>(&(*expr->a)[0]));
                if (!argk.empty())
                    checks.emplace_back(expr->ea, argk);
            }
            return 0;
        }

        if (is_toctou_use_api(nm))
        {
            if (expr->a == nullptr || expr->a->empty())
                return 0;
            std::string argk = identify_arg(cfunc, static_cast<const cexpr_t*>(&(*expr->a)[0]));
            if (argk.empty())
                return 0;
            for (const auto& c : checks)
            {
                if (c.second != argk)
                    continue;
                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/toctou/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(expr->ea);
                f.id = id.str();
                f.primary_ea = expr->ea;
                f.related_eas.push_back(c.first);
                f.related_eas.push_back(func_ea);
                f.cwes.push_back(make_cwe(367, cwe_name_for(367)));
                f.severity   = severity_t::high;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "TOCTOU: check at " << ea_to_hex(c.first)
                   << " precedes use of same identifier at " << ea_to_hex(expr->ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Function " << func_name_for(func_ea) << " checks file/identifier '" << argk
                    << "' at " << ea_to_hex(c.first) << " then uses it at "
                    << ea_to_hex(expr->ea) << ". The window between check and use can be exploited "
                    << "by an attacker with write access to the path namespace (CWE-367).";
                f.rationale = rat.str();
                json ev;
                ev["check_ea"] = ea_to_hex(c.first);
                ev["use_ea"]   = ea_to_hex(expr->ea);
                ev["arg_key"]  = argk;
                ev["check_call"] = "<see related_eas[0]>";
                ev["use_call"]   = nm;
                f.evidence = std::move(ev);
                findings->push_back(std::move(f));
                if (static_cast<int>(findings->size()) >= budget)
                    return 1;
                break;
            }
        }
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_toctou_patterns(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            toctou_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 367;
    std::ostringstream msg;
    msg << OBFSTR("TOCTOU pattern scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

bool mop_traces_to_param(const mop_t& op, const std::unordered_set<int>& tainted_lvars)
{
    switch (op.t)
    {
    case mop_l:
        if (op.l != nullptr && tainted_lvars.count(op.l->idx))
            return true;
        return false;
    case mop_d:
        if (op.d != nullptr)
        {
            if (mop_traces_to_param(op.d->l, tainted_lvars))
                return true;
            if (mop_traces_to_param(op.d->r, tainted_lvars))
                return true;
        }
        return false;
    case mop_a:
        if (op.a != nullptr)
            return mop_traces_to_param(static_cast<const mop_t&>(*op.a), tainted_lvars);
        return false;
    default:
        return false;
    }
}

void seed_argument_taint(const mba_t& mba, std::unordered_set<int>& tainted_lvars)
{
    for (size_t i = 0; i < mba.argidx.size(); ++i)
    {
        if (mba.argidx[i] >= 0)
            tainted_lvars.insert(mba.argidx[i]);
    }
}

}

agent_tools::tool_result_t handle_find_arbitrary_rw_primitives(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());

        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        const bool kernel = aida::vuln::kernel_engine::is_kernel_driver();

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            auto handle = aida::vuln::microcode::generate(fea, MMAT_LVARS);
            if (!handle.has_value() || !handle->mba)
                continue;
            mba_t& mba = *handle->mba;

            std::unordered_set<int> tainted_lvars;
            seed_argument_taint(mba, tainted_lvars);

            for (int b = 0; b < mba.qty; ++b)
            {
                if (static_cast<int>(findings.size()) >= limit)
                    break;
                mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
                if (blk == nullptr)
                    continue;
                for (minsn_t* m = blk->head; m != nullptr; m = m->next)
                {
                    if (static_cast<int>(findings.size()) >= limit)
                        break;
                    if (m->opcode != m_ldx && m->opcode != m_stx)
                        continue;

                    bool addr_tainted = false;
                    bool val_tainted  = false;
                    if (m->opcode == m_ldx)
                    {
                        addr_tainted = mop_traces_to_param(m->r, tainted_lvars);
                    }
                    else
                    {
                        addr_tainted = mop_traces_to_param(m->d, tainted_lvars);
                        val_tainted  = mop_traces_to_param(m->l, tainted_lvars);
                    }

                    if (!addr_tainted && !val_tainted)
                        continue;

                    int cwe_id = m->opcode == m_stx ? 787 : 125;
                    bool is_write = m->opcode == m_stx;

                    vuln_finding_t f;
                    std::ostringstream id;
                    id << "vuln/arbitrary_" << (is_write ? "w" : "r") << "/"
                       << std::hex << std::uppercase << static_cast<std::uint64_t>(m->ea);
                    f.id = id.str();
                    f.primary_ea = m->ea;
                    f.related_eas.push_back(fea);
                    f.cwes.push_back(make_cwe(cwe_id, cwe_name_for(cwe_id)));
                    f.severity   = severity_t::critical;
                    f.confidence = (kernel && is_write && addr_tainted && val_tainted)
                                       ? confidence_t::likely : confidence_t::plausible;
                    std::ostringstream tt;
                    tt << (is_write ? "Arbitrary-write primitive in " : "Arbitrary-read primitive in ")
                       << func_name_for(fea);
                    f.title = tt.str();
                    std::ostringstream rat;
                    rat << "Microcode " << (is_write ? "m_stx" : "m_ldx") << " at "
                        << ea_to_hex(m->ea)
                        << " uses an attacker-influenced address operand"
                        << (is_write && val_tainted ? " AND attacker-controlled value" : "")
                        << ". In a kernel context this is a strong arbitrary-write candidate.";
                    f.rationale = rat.str();
                    json ev;
                    ev["op_ea"]        = ea_to_hex(m->ea);
                    ev["op_kind"]      = is_write ? "m_stx" : "m_ldx";
                    ev["addr_tainted"] = addr_tainted;
                    ev["val_tainted"]  = val_tainted;
                    ev["kernel"]       = kernel;
                    f.evidence = std::move(ev);
                    findings.push_back(std::move(f));
                }
            }
        }
    }

    json data;
    data["count"]    = findings.size();
    data["findings"] = findings_to_json_array(findings);
    data["primary_cwe_write"] = 787;
    data["primary_cwe_read"]  = 125;
    std::ostringstream msg;
    msg << OBFSTR("Arbitrary R/W primitive scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

const std::vector<std::string>& deserializer_names()
{
    static const std::vector<std::string> names = {
        "BinaryFormatter::Deserialize", "BinaryFormatter_Deserialize",
        "marshal::loads", "marshal_loads",
        "pickle::loads", "pickle_loads",
        "unserialize",
        "ObjectInputStream::readObject", "ObjectInputStream_readObject",
        "readObject",
        "deserialize", "Deserialize", "DeSerialize",
        "unmarshal", "Unmarshal",
        "read_blob", "ReadBlob",
        "from_bytes", "FromBytes",
        "load_from_string", "loads",
        "fastbinaryDecode",
        "yaml_load", "yaml_load_unsafe",
        "_unpickle",
        "phpunserialize",
    };
    return names;
}

bool is_deserializer_callee(const std::string& nm)
{
    for (const auto& d : deserializer_names())
    {
        if (name_matches_signature(nm, d))
            return true;
    }
    const std::string l = ascii_lower(nm);
    if (l.find("deserialize") != std::string::npos)
        return true;
    if (l.find("unmarshal") != std::string::npos)
        return true;
    if (l.find("from_bytes") != std::string::npos)
        return true;
    if (l.find("read_blob") != std::string::npos)
        return true;
    return false;
}

bool is_byte_dispatch_helper(const std::string& nm)
{
    return name_matches_signature(nm, "wcsstr") ||
           name_matches_signature(nm, "strstr") ||
           name_matches_signature(nm, "memchr") ||
           name_matches_signature(nm, "wmemchr");
}

struct deserialize_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    const aida::vuln::taint::func_summary_t* summary = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    deserialize_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out,
                          const aida::vuln::taint::func_summary_t* sum, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), summary(sum), func_ea(fea), budget(b) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;

        bool is_des = is_deserializer_callee(nm);
        bool is_dispatch = is_byte_dispatch_helper(nm);
        if (!is_des && !is_dispatch)
            return 0;

        bool first_arg_tainted = false;
        if (expr->a != nullptr && !expr->a->empty() && summary != nullptr)
        {
            const cexpr_t* arg0 = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[0]));
            if (arg0 != nullptr && arg0->op == cot_var)
            {
                int li = arg0->v.idx;
                lvars_t* lv = cfunc->get_lvars();
                if (lv != nullptr && li >= 0 && static_cast<std::size_t>(li) < lv->size())
                {
                    const lvar_t& l = (*lv)[li];
                    if (l.is_arg_var() && summary->tainted_param_indices.count(li))
                        first_arg_tainted = true;
                }
            }
        }
        if (is_des && summary != nullptr && (!summary->input_sources_called.empty() ||
                                              !summary->tainted_param_indices.empty()))
            first_arg_tainted = true;

        if (!is_des && !first_arg_tainted)
            return 0;

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/deserialize/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(expr->ea);
        f.id = id.str();
        f.primary_ea = expr->ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(502, cwe_name_for(502)));
        f.severity   = severity_t::high;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        if (is_des)
            tt << "Unsafe deserialization candidate in " << func_name_for(func_ea) << ": " << nm;
        else
            tt << "Byte-dispatch over attacker buffer in " << func_name_for(func_ea) << ": " << nm;
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Call to " << nm << " at " << ea_to_hex(expr->ea)
            << " consumes a buffer that traces back to attacker-controlled input. ";
        if (is_des)
            rat << "Deserialization frameworks routinely yield arbitrary code execution when invoked on untrusted bytes.";
        else
            rat << "Walking attacker-controlled bytes and dispatching on a tag byte is a classic decoder pattern.";
        f.rationale = rat.str();
        json ev;
        ev["call_ea"] = ea_to_hex(expr->ea);
        ev["callee"]  = nm;
        ev["func_ea"] = ea_to_hex(func_ea);
        ev["mode"]    = is_des ? "deserializer" : "byte_dispatch";
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_unsafe_deserializers(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        auto& te = aida::vuln::taint::engine();
        if (!te.is_analyzed())
            te.analyze_all();

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            const auto* sum = te.get_summary(fea);
            deserialize_visitor_t v(cf.operator->(), &findings, sum, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 502;
    std::ostringstream msg;
    msg << OBFSTR("Unsafe-deserializer scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct off_by_one_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    off_by_one_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static bool cond_is_le_or_ule(const cexpr_t& cond)
    {
        return cond.op == cot_sle || cond.op == cot_ule;
    }

    static int extract_lvar_idx(const cexpr_t* e)
    {
        if (e == nullptr)
            return -1;
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr || x->op != cot_var)
            return -1;
        return x->v.idx;
    }

    void emit_off_by_one(ea_t loop_ea, int loop_var_idx)
    {
        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/off_by_one_loop/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(loop_ea);
        f.id = id.str();
        f.primary_ea = loop_ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(193, cwe_name_for(193)));
        f.severity   = severity_t::medium;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "Possible off-by-one loop bound in " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Loop at " << ea_to_hex(loop_ea)
            << " uses '<= bound' instead of '< bound'. If the body indexes into a fixed-size buffer "
            << "with bound = sizeof(buffer), the final iteration writes one past the end.";
        f.rationale = rat.str();
        json ev;
        ev["loop_ea"] = ea_to_hex(loop_ea);
        ev["loop_var_idx"] = loop_var_idx;
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || findings == nullptr || ins == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (ins->op == cit_for && ins->cfor != nullptr)
        {
            const cexpr_t& cond = ins->cfor->expr;
            if (cond_is_le_or_ule(cond))
            {
                int idx = extract_lvar_idx(cond.x);
                emit_off_by_one(ins->ea, idx);
            }
        }
        else if (ins->op == cit_while && ins->cwhile != nullptr)
        {
            const cexpr_t& cond = ins->cwhile->expr;
            if (cond_is_le_or_ule(cond))
            {
                int idx = extract_lvar_idx(cond.x);
                emit_off_by_one(ins->ea, idx);
            }
        }
        else if (ins->op == cit_do && ins->cdo != nullptr)
        {
            const cexpr_t& cond = ins->cdo->expr;
            if (cond_is_le_or_ule(cond))
            {
                int idx = extract_lvar_idx(cond.x);
                emit_off_by_one(ins->ea, idx);
            }
        }
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;
        bool is_strncpy_like = name_matches_signature(nm, "strncpy") ||
                               name_matches_signature(nm, "wcsncpy") ||
                               name_matches_signature(nm, "_strncpy") ||
                               name_matches_signature(nm, "strncat") ||
                               name_matches_signature(nm, "wcsncat");
        if (!is_strncpy_like)
            return 0;
        if (expr->a == nullptr || expr->a->size() < 3)
            return 0;
        const cexpr_t* sz = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[2]));
        if (sz == nullptr)
            return 0;

        bool size_is_sizeof_dst = false;
        const cexpr_t* dst = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[0]));
        if (sz->op == cot_sizeof && sz->x != nullptr)
        {
            const cexpr_t* sof = unwrap_cast_ref(sz->x);
            if (dst != nullptr && sof != nullptr && dst->op == sof->op)
            {
                if (dst->op == cot_var && dst->v.idx == sof->v.idx)
                    size_is_sizeof_dst = true;
                else if (dst->op == cot_obj && dst->obj_ea == sof->obj_ea)
                    size_is_sizeof_dst = true;
            }
        }
        if (!size_is_sizeof_dst)
            return 0;

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/strncpy_no_terminator/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(expr->ea);
        f.id = id.str();
        f.primary_ea = expr->ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(193, cwe_name_for(193)));
        f.severity   = severity_t::medium;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "strncpy(dst, src, sizeof(dst)) without explicit NUL terminator in " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Call to " << nm << " at " << ea_to_hex(expr->ea)
            << " uses sizeof(dst) for the length argument. strncpy does NOT guarantee a trailing "
            << "NUL when the source is at least as long as the buffer; downstream consumers may "
            << "read past the end. Add 'dst[sizeof(dst) - 1] = 0;' immediately after the call.";
        f.rationale = rat.str();
        json ev;
        ev["call_ea"] = ea_to_hex(expr->ea);
        ev["callee"]  = nm;
        ev["func_ea"] = ea_to_hex(func_ea);
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_off_by_one_patterns(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            off_by_one_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 193;
    std::ostringstream msg;
    msg << OBFSTR("Off-by-one pattern scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

}

void register_tier2_surface_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("analyze_function_attack_surface"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Compute a 0-100 attack-surface score for the given function. Decomposes the score "
               "into input_proximity (reverse-graph distance to input sources, max 25), sink_count "
               "(forward distance to dangerous sinks, max 25), missing_validators (parameters that "
               "flow to sinks without validation, max 20), complexity (log2 of cyclomatic, max 15), "
               "and taint_paths (input x sink combinations on this function, max 15). Also returns "
               "the function's classified role (allocator/deallocator/validator/parser/dispatcher/"
               "ioctl_handler/ipc_endpoint/callback/crypto/utility)."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Address (0x...) of the function to score."), true},
        },
        handle_analyze_function_attack_surface,
        true,
    });

    registry.register_tool({
        OBFSTR("list_attacker_reachable_functions"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Enumerate every function reachable (via reverse call-graph BFS) from any known "
               "input-source callsite. These are the functions that can directly or transitively "
               "process attacker-controlled bytes and therefore form the binary's primary attack "
               "surface."),
        {
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of functions to return (default 200, max 4096)."), false},
        },
        handle_list_attacker_reachable_functions,
        true,
    });

    registry.register_tool({
        OBFSTR("classify_function_role"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Heuristically label a function with a single role: allocator, deallocator, "
               "validator, parser, dispatcher, ioctl_handler, ipc_endpoint, callback, crypto, or "
               "utility. Combines name signatures, callee-set heuristics, switch-shape analysis, "
               "and taint summaries."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Address (0x...) of the function to classify."), true},
        },
        handle_classify_function_role,
        true,
    });

    registry.register_tool({
        OBFSTR("enumerate_callbacks"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Find places where the binary registers a function pointer with the operating system "
               "or another component. Covers SetWindowsHookEx*, CreateRemoteThread*, CreateThread, "
               "RtlCreateUserThread, IoRegisterDeviceInterface, KeInitializeDpc, KeInitializeTimer*, "
               "IoSetCompletionRoutine*, IoRegister*Notification, ExRegisterCallback, "
               "RegisterServiceCtrlHandler*, SetUnhandledExceptionFilter, AddVectored*Handler, "
               "_set_se_translator, signal, atexit, _onexit, _beginthread*, and "
               "DriverObject->MajorFunction[*] assignments in kernel drivers. Each finding records "
               "the registered callback's EA and the registration call EA. Security-sensitive "
               "registrations are flagged with CWE-358."),
        {},
        handle_enumerate_callbacks,
        true,
    });

    registry.register_tool({
        OBFSTR("find_writable_executable_pages"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Identify segments and PE sections that are simultaneously writable and executable "
               "(W^X violation, CWE-1188). Scans IDA segments via SEGPERM_EXEC|SEGPERM_WRITE and "
               "additionally walks the PE section table for IMAGE_SCN_MEM_EXECUTE | "
               "IMAGE_SCN_MEM_WRITE. Each match is emitted as a critical, confirmed finding."),
        {},
        handle_find_writable_executable_pages,
        true,
    });

    registry.register_tool({
        OBFSTR("explain_vulnerability_chain"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Generate a markdown narrative plus structured JSON for taint paths from a source "
               "callsite to a sink callsite. Each step in each path is annotated with the "
               "decompiled snippet at the step EA, accumulated path conditions, and the engine's "
               "summary text."),
        {
            {OBFSTR("source_address"), OBFSTR("string"),
             OBFSTR("Address (0x...) or symbol name of the input-source callsite."), true},
            {OBFSTR("sink_address"),   OBFSTR("string"),
             OBFSTR("Address (0x...) or symbol name of the dangerous-sink callsite."), true},
        },
        handle_explain_vulnerability_chain,
        true,
    });

    registry.register_tool({
        OBFSTR("map_state_machine"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect state-machine-like dispatch in the given function. A state machine is a "
               "switch on a global / member field whose name resembles state/status/phase/mode/"
               "step/stage/fsm, with cases that update the same field. Returns the detected "
               "transitions and emits an info-level finding when at least one transition lacks an "
               "explicit guard, indicating possible illegal-state attacks."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Address (0x...) of the function to analyze."), true},
        },
        handle_map_state_machine,
        true,
    });

    registry.register_tool({
        OBFSTR("find_protocol_parser_bugs"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect bugs in protocol parsers that consume externally-controlled input and "
               "dispatch on length/type/cmd fields. Flags memcpy/memmove/RtlCopyMemory/RtlMoveMemory "
               "calls whose size argument is non-literal arithmetic on attacker-influenced data "
               "(CWE-130 length-not-checked) and detects size = n - 1 patterns flowing into a copy "
               "of n bytes (CWE-193 off-by-one)."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_protocol_parser_bugs,
        true,
    });

    registry.register_tool({
        OBFSTR("find_loose_bounds_checks"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect if-conditions that compare an attacker-influenced value against a constant "
               "bound but use the wrong relational operator. Specifically flags signed comparisons "
               "(cot_sgt/sge/slt/sle) against an unsigned-typed lvar where a negative attacker "
               "value would slip through. CWE-839."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_loose_bounds_checks,
        true,
    });

    registry.register_tool({
        OBFSTR("find_signed_unsigned_confusion"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect signed/unsigned comparisons whose operands have differing signedness "
               "(signed lvar vs unsigned lvar/literal, or vice versa). Implicit promotion to "
               "unsigned can suppress negative-value paths and bypass length checks. CWE-194/195."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_signed_unsigned_confusion,
        true,
    });

    registry.register_tool({
        OBFSTR("find_missing_null_check"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect pointer dereferences that follow an allocator (malloc/calloc/realloc/"
               "HeapAlloc/RtlAllocateHeap/LocalAlloc/GlobalAlloc/VirtualAlloc/ExAllocatePool*/operator new) "
               "without an intervening explicit null-check on the same pointer. CWE-476."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_missing_null_check,
        true,
    });

    registry.register_tool({
        OBFSTR("find_toctou_patterns"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect Time-of-Check-to-Time-of-Use races in the same function: a check call "
               "(GetFileAttributes*/PathFileExists*/_access/stat*/OpenFile/RegOpenKey*) followed by "
               "a use call (CreateFile*/fopen/_open/DeleteFile*/MoveFile*/CopyFile*) on the same "
               "identifier. CWE-367."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_toctou_patterns,
        true,
    });

    registry.register_tool({
        OBFSTR("find_arbitrary_rw_primitives"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect microcode m_ldx/m_stx instructions whose effective address (and, for stores, "
               "value) traces back via def-use to a function parameter or input source. In a kernel "
               "context this yields high-confidence arbitrary-write/arbitrary-read primitives "
               "(CWE-787 / CWE-125)."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_arbitrary_rw_primitives,
        true,
    });

    registry.register_tool({
        OBFSTR("find_unsafe_deserializers"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect calls to deserialization frameworks (BinaryFormatter::Deserialize, "
               "marshal::loads, pickle::loads, unserialize, ObjectInputStream::readObject, generic "
               "*deserialize*/*unmarshal*/*read_blob*/*from_bytes* helpers) whose first argument "
               "traces back to attacker-controlled bytes. Also flags wcsstr/strstr/memchr "
               "byte-dispatch loops over attacker buffers. CWE-502."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_unsafe_deserializers,
        true,
    });

    registry.register_tool({
        OBFSTR("find_off_by_one_patterns"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Detect off-by-one buffer-access patterns: for/while/do loops whose condition uses "
               "'<= bound' (cot_sle / cot_ule) instead of '< bound', and strncpy/wcsncpy/strncat/"
               "wcsncat calls of the form strncpy(dst, src, sizeof(dst)) which do not guarantee "
               "a trailing NUL terminator. CWE-193."),
        {
            {OBFSTR("address"), OBFSTR("string"),
             OBFSTR("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_off_by_one_patterns,
        true,
    });
}

}

}
}
}
