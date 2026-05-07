#include "../aida_pro.hpp"

#include <algorithm>
#include <cctype>
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
namespace taint
{

namespace
{

constexpr int kMaxFunctionsToAnalyze = 8192;
constexpr int kMaxFixpointIterations = 4;
constexpr int kMaxBlocksPerFunction = 4096;
constexpr std::size_t kMaxFreedTrackingPerFunc = 16;

std::string ea_to_hex(ea_t ea)
{
    if (ea == BADADDR)
        return std::string("0x0");
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

bool name_matches_signature(const std::string& callee, const std::string_view sig)
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
    if (call_l.find(sig_l) != std::string::npos)
        return true;
    if (!stripped.empty() && stripped.find(sig_l) != std::string::npos)
        return true;
    return false;
}

bool is_input_source_name(const std::string& name)
{
    for (const auto& s : sig::INPUT_SOURCES)
    {
        if (name_matches_signature(name, s.name))
            return true;
    }
    return false;
}

const sig::source_signature_t* find_input_source(const std::string& name)
{
    for (const auto& s : sig::INPUT_SOURCES)
    {
        if (name_matches_signature(name, s.name))
            return &s;
    }
    return nullptr;
}

struct sink_match_t
{
    const sig::sink_signature_t* sink = nullptr;
    std::string                  category;
};

sink_match_t find_sink_signature(const std::string& name)
{
    sink_match_t out;
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
    {
        if (name_matches_signature(name, s.name))
        {
            out.sink = &s;
            out.category = "buffer_overflow";
            return out;
        }
    }
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
    {
        if (name_matches_signature(name, s.name))
        {
            out.sink = &s;
            out.category = "command_injection";
            return out;
        }
    }
    for (const auto& s : sig::PATH_TRAVERSAL_SINKS)
    {
        if (name_matches_signature(name, s.name))
        {
            out.sink = &s;
            out.category = "path_traversal";
            return out;
        }
    }
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
    {
        if (name_matches_signature(name, s.name))
        {
            out.sink = &s;
            out.category = "format_string";
            return out;
        }
    }
    return out;
}

bool is_sink_name(const std::string& name)
{
    return find_sink_signature(name).sink != nullptr;
}

bool is_validator_name(const std::string& name)
{
    for (const auto& v : sig::KERNEL_VALIDATORS)
    {
        if (name_matches_signature(name, v))
            return true;
    }
    return false;
}

bool is_alloc_name(const std::string& name)
{
    for (const auto& a : sig::ALLOC_FUNCS)
    {
        if (name_matches_signature(name, a))
            return true;
    }
    return false;
}

bool is_free_name(const std::string& name)
{
    for (const auto& f : sig::FREE_FUNCS)
    {
        if (name_matches_signature(name, f))
            return true;
    }
    return false;
}

bool is_realloc_name(const std::string& name)
{
    for (const auto& r : sig::REALLOC_FUNCS)
    {
        if (name_matches_signature(name, r))
            return true;
    }
    return false;
}

taint_kind_t kind_from_source_name(const std::string& name)
{
    const std::string l = ascii_lower(name);
    if (l.find("recv") != std::string::npos ||
        l.find("winhttp") != std::string::npos ||
        l.find("internet") != std::string::npos ||
        l.find("httpquery") != std::string::npos ||
        l.find("wsa") != std::string::npos)
        return taint_kind_t::network_input;
    if (l.find("readfile") != std::string::npos ||
        l.find("ntreadfile") != std::string::npos ||
        l.find("zwreadfile") != std::string::npos ||
        l.find("fread") != std::string::npos ||
        l == "read" || l == "_read")
        return taint_kind_t::file_input;
    if (l.find("getenv") != std::string::npos ||
        l.find("environment") != std::string::npos ||
        l.find("commandline") != std::string::npos)
        return taint_kind_t::env_input;
    if (l.find("regquery") != std::string::npos ||
        l.find("reggetvalue") != std::string::npos)
        return taint_kind_t::registry_input;
    return taint_kind_t::user_input;
}

const char* vulnerability_label_from_cwe(int cwe)
{
    switch (cwe)
    {
    case 22:  return "path_traversal";
    case 78:  return "command_injection";
    case 120: return "buffer_overflow";
    case 134: return "format_string";
    case 190: return "integer_overflow";
    case 242: return "dangerous_function";
    case 415: return "double_free";
    case 416: return "use_after_free";
    case 457: return "uninitialized_use";
    case 770: return "resource_exhaustion";
    default:  return "tainted_sink";
    }
}

const char* cwe_name_for(int id)
{
    switch (id)
    {
    case 22:  return "Path Traversal";
    case 78:  return "OS Command Injection";
    case 120: return "Buffer Copy without Checking Size of Input";
    case 129: return "Improper Validation of Array Index";
    case 134: return "Use of Externally-Controlled Format String";
    case 190: return "Integer Overflow or Wraparound";
    case 242: return "Use of Inherently Dangerous Function";
    case 415: return "Double Free";
    case 416: return "Use After Free";
    case 457: return "Use of Uninitialized Variable";
    case 770: return "Allocation of Resources Without Limits or Throttling";
    default:  return "Unknown CWE";
    }
}

std::string func_name_for(ea_t func_ea)
{
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

bool function_is_skippable(func_t* pfn)
{
    if (pfn == nullptr)
        return true;
    if ((pfn->flags & FUNC_THUNK) != 0)
        return true;
    if ((pfn->flags & FUNC_LIB) != 0)
        return true;
    return false;
}

int compute_cyclomatic_from_mba(const mba_t& mba)
{
    int nodes = 0;
    int edges = 0;
    for (int i = 0; i < mba.qty; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        ++nodes;
        edges += static_cast<int>(blk->succset.size());
    }
    if (nodes <= 0)
        return 1;
    int cc = edges - nodes + 2;
    if (cc < 1)
        cc = 1;
    return cc;
}

int param_index_for_lvar(const mba_t& mba, int lvar_idx)
{
    if (lvar_idx < 0)
        return -1;
    for (size_t i = 0; i < mba.argidx.size(); ++i)
    {
        if (mba.argidx[i] == lvar_idx)
            return static_cast<int>(i);
    }
    return -1;
}

bool is_call_op(mcode_t op)
{
    return op == m_call || op == m_icall;
}

bool is_arith_op(mcode_t op)
{
    switch (op)
    {
    case m_add:
    case m_sub:
    case m_mul:
    case m_or:
    case m_and:
    case m_xor:
    case m_shl:
    case m_shr:
    case m_sar:
        return true;
    default:
        return false;
    }
}

bool is_overflow_arith(mcode_t op)
{
    return op == m_add || op == m_sub || op == m_mul;
}

bool is_move_op(mcode_t op)
{
    switch (op)
    {
    case m_mov:
    case m_xds:
    case m_xdu:
    case m_low:
    case m_high:
    case m_neg:
    case m_lnot:
    case m_bnot:
        return true;
    default:
        return false;
    }
}

bool resolve_callee_simple(const minsn_t& ins, std::string& callee_name, ea_t& callee_ea)
{
    callee_ea = BADADDR;
    callee_name.clear();
    return microcode::resolve_call_target(ins, callee_ea, callee_name);
}

bool collect_first_pointer_arg(const minsn_t& call_ins, mop_t& out_ptr)
{
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return false;
    const mcallargs_t& args = call_ins.d.f->args;
    if (args.empty())
        return false;
    out_ptr = static_cast<const mop_t&>(args[0]);
    return true;
}

int call_arg_count(const minsn_t& call_ins)
{
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return 0;
    return static_cast<int>(call_ins.d.f->args.size());
}

const mop_t* call_arg_at(const minsn_t& call_ins, int idx)
{
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return nullptr;
    const mcallargs_t& args = call_ins.d.f->args;
    if (idx < 0 || static_cast<size_t>(idx) >= args.size())
        return nullptr;
    return static_cast<const mop_t*>(&args[idx]);
}

struct taint_set_t
{
    std::unordered_set<int> tainted_lvars;
    std::unordered_set<int> tainted_param_indices;
};

bool mop_is_tainted(const mop_t& op, const taint_set_t& ts)
{
    switch (op.t)
    {
    case mop_l:
        if (op.l != nullptr && ts.tainted_lvars.count(op.l->idx))
            return true;
        return false;
    case mop_d:
        if (op.d != nullptr)
        {
            if (mop_is_tainted(op.d->l, ts))
                return true;
            if (mop_is_tainted(op.d->r, ts))
                return true;
        }
        return false;
    case mop_a:
        if (op.a != nullptr)
            return mop_is_tainted(static_cast<const mop_t&>(*op.a), ts);
        return false;
    case mop_f:
        if (op.f != nullptr)
        {
            const mcallargs_t& args = op.f->args;
            for (size_t i = 0; i < args.size(); ++i)
            {
                if (mop_is_tainted(static_cast<const mop_t&>(args[i]), ts))
                    return true;
            }
        }
        return false;
    default:
        return false;
    }
}

void collect_tainted_param_origins(const mop_t& op, const taint_set_t& ts, std::set<int>& origins)
{
    if (op.t == mop_l && op.l != nullptr)
    {
        if (ts.tainted_lvars.count(op.l->idx) && ts.tainted_param_indices.count(op.l->idx))
            origins.insert(op.l->idx);
        return;
    }
    if (op.t == mop_d && op.d != nullptr)
    {
        collect_tainted_param_origins(op.d->l, ts, origins);
        collect_tainted_param_origins(op.d->r, ts, origins);
        return;
    }
    if (op.t == mop_a && op.a != nullptr)
    {
        collect_tainted_param_origins(static_cast<const mop_t&>(*op.a), ts, origins);
        return;
    }
    if (op.t == mop_f && op.f != nullptr)
    {
        const mcallargs_t& args = op.f->args;
        for (size_t i = 0; i < args.size(); ++i)
            collect_tainted_param_origins(static_cast<const mop_t&>(args[i]), ts, origins);
    }
}

void taint_destination(const mop_t& d, taint_set_t& ts)
{
    if (d.t == mop_l && d.l != nullptr)
    {
        ts.tainted_lvars.insert(d.l->idx);
    }
}

void clear_destination_taint(const mop_t& d, taint_set_t& ts)
{
    if (d.t == mop_l && d.l != nullptr)
    {
        ts.tainted_lvars.erase(d.l->idx);
    }
}

class TaintCallGraph
{
public:
    void build()
    {
        m_callees.clear();
        m_callers.clear();
        const std::size_t fq = get_func_qty();
        for (std::size_t i = 0; i < fq; ++i)
        {
            func_t* pfn = getn_func(i);
            if (pfn == nullptr)
                continue;
            xrefblk_t xb;
            for (bool ok = xb.first_to(pfn->start_ea, XREF_ALL); ok; ok = xb.next_to())
            {
                if (!xb.iscode)
                    continue;
                if (xb.type != fl_CN && xb.type != fl_CF)
                    continue;
                func_t* caller = get_func(xb.from);
                if (caller == nullptr)
                    continue;
                m_callees[caller->start_ea].push_back(pfn->start_ea);
                m_callers[pfn->start_ea].push_back(caller->start_ea);
            }
        }
        for (auto& kv : m_callees)
        {
            std::sort(kv.second.begin(), kv.second.end());
            kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
        }
        for (auto& kv : m_callers)
        {
            std::sort(kv.second.begin(), kv.second.end());
            kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
        }
    }

    const std::vector<ea_t>& callees_of(ea_t ea) const
    {
        static const std::vector<ea_t> empty;
        auto it = m_callees.find(ea);
        return it == m_callees.end() ? empty : it->second;
    }

    const std::vector<ea_t>& callers_of(ea_t ea) const
    {
        static const std::vector<ea_t> empty;
        auto it = m_callers.find(ea);
        return it == m_callers.end() ? empty : it->second;
    }

    std::vector<ea_t> topological_order(const std::vector<ea_t>& functions) const
    {
        std::unordered_set<ea_t> in_set(functions.begin(), functions.end());
        std::unordered_map<ea_t, int> color;
        std::vector<ea_t> ordered;
        ordered.reserve(functions.size());
        std::function<void(ea_t)> visit = [&](ea_t node) {
            if (in_set.count(node) == 0)
                return;
            int& c = color[node];
            if (c == 1 || c == 2)
                return;
            c = 1;
            const auto& callees = callees_of(node);
            for (ea_t cc : callees)
                visit(cc);
            c = 2;
            ordered.push_back(node);
        };
        for (ea_t f : functions)
            visit(f);
        return ordered;
    }

private:
    std::unordered_map<ea_t, std::vector<ea_t>> m_callees;
    std::unordered_map<ea_t, std::vector<ea_t>> m_callers;
};

struct intra_state_t
{
    taint_set_t                                     ts;
    std::set<int>                                   tainted_param_indices;
    std::set<int>                                   tainted_out_param_indices;
    bool                                            returns_tainted = false;
    bool                                            returns_alloc = false;
    bool                                            returns_free = false;
    std::set<std::string>                           sinks_reached;
    std::set<std::string>                           validators_called;
    std::set<std::string>                           allocs_called;
    std::set<std::string>                           frees_called;
    std::set<std::string>                           input_sources_called;
    std::set<int>                                   params_passed_to_sinks;
    std::set<int>                                   params_validated;
    std::set<int>                                   params_freed;
    std::vector<std::string>                        path_conditions;
};

void initialize_param_taint(const mba_t& mba, intra_state_t& st)
{
    for (size_t i = 0; i < mba.argidx.size(); ++i)
    {
        int lvar_idx = mba.argidx[i];
        if (lvar_idx < 0)
            continue;
        st.ts.tainted_lvars.insert(lvar_idx);
        st.ts.tainted_param_indices.insert(lvar_idx);
    }
}

void process_call_taint(mba_t& mba, minsn_t& ins, intra_state_t& st)
{
    std::string callee_name;
    ea_t callee_ea = BADADDR;
    if (!resolve_callee_simple(ins, callee_name, callee_ea))
        return;
    if (callee_name.empty())
        return;

    if (is_input_source_name(callee_name))
    {
        st.input_sources_called.insert(callee_name);
        const sig::source_signature_t* src = find_input_source(callee_name);
        if (src != nullptr)
        {
            int idx = src->taint_arg_index;
            if (idx >= 0)
            {
                const mop_t* arg = call_arg_at(ins, idx);
                if (arg != nullptr && arg->t == mop_l && arg->l != nullptr)
                    st.ts.tainted_lvars.insert(arg->l->idx);
            }
            else
            {
                if (ins.d.t == mop_l && ins.d.l != nullptr)
                    st.ts.tainted_lvars.insert(ins.d.l->idx);
            }
        }
    }

    sink_match_t sink = find_sink_signature(callee_name);
    if (sink.sink != nullptr)
    {
        st.sinks_reached.insert(callee_name);
        const int n = call_arg_count(ins);
        for (int i = 0; i < n; ++i)
        {
            const mop_t* arg = call_arg_at(ins, i);
            if (arg == nullptr)
                continue;
            if (mop_is_tainted(*arg, st.ts))
            {
                std::set<int> origins;
                collect_tainted_param_origins(*arg, st.ts, origins);
                for (int oi : origins)
                {
                    int p_idx = param_index_for_lvar(mba, oi);
                    if (p_idx >= 0)
                        st.params_passed_to_sinks.insert(p_idx);
                }
            }
        }
    }

    if (is_validator_name(callee_name))
    {
        st.validators_called.insert(callee_name);
        const int n = call_arg_count(ins);
        for (int i = 0; i < n; ++i)
        {
            const mop_t* arg = call_arg_at(ins, i);
            if (arg == nullptr)
                continue;
            if (arg->t == mop_l && arg->l != nullptr)
            {
                int idx = arg->l->idx;
                int p_idx = param_index_for_lvar(mba, idx);
                if (p_idx >= 0)
                    st.params_validated.insert(p_idx);
            }
        }
    }

    if (is_alloc_name(callee_name))
    {
        st.allocs_called.insert(callee_name);
        if (ins.d.t == mop_l && ins.d.l != nullptr)
            st.ts.tainted_lvars.erase(ins.d.l->idx);
    }

    if (is_free_name(callee_name))
    {
        st.frees_called.insert(callee_name);
        const mop_t* arg0 = call_arg_at(ins, 0);
        if (arg0 != nullptr && arg0->t == mop_l && arg0->l != nullptr)
        {
            int idx = arg0->l->idx;
            int p_idx = param_index_for_lvar(mba, idx);
            if (p_idx >= 0)
                st.params_freed.insert(p_idx);
        }
    }
}

void process_arith_taint(minsn_t& ins, intra_state_t& st)
{
    bool l_t = mop_is_tainted(ins.l, st.ts);
    bool r_t = mop_is_tainted(ins.r, st.ts);
    if (l_t || r_t)
        taint_destination(ins.d, st.ts);
}

void process_move_taint(minsn_t& ins, intra_state_t& st)
{
    if (mop_is_tainted(ins.l, st.ts))
        taint_destination(ins.d, st.ts);
    else
        clear_destination_taint(ins.d, st.ts);
}

void process_load_taint(minsn_t& ins, intra_state_t& st)
{
    if (mop_is_tainted(ins.r, st.ts) || mop_is_tainted(ins.l, st.ts))
        taint_destination(ins.d, st.ts);
}

void process_store_taint(minsn_t& ins, intra_state_t& st, mba_t& mba)
{
    if (!mop_is_tainted(ins.l, st.ts))
        return;
    std::set<int> origins;
    collect_tainted_param_origins(ins.l, st.ts, origins);
    for (int oi : origins)
    {
        int p_idx = param_index_for_lvar(mba, oi);
        if (p_idx >= 0)
            st.tainted_out_param_indices.insert(p_idx);
    }
    if (ins.d.t == mop_a && ins.d.a != nullptr)
    {
        const mop_t& base = static_cast<const mop_t&>(*ins.d.a);
        if (base.t == mop_l && base.l != nullptr)
        {
            int p_idx = param_index_for_lvar(mba, base.l->idx);
            if (p_idx >= 0)
                st.tainted_out_param_indices.insert(p_idx);
        }
    }
}

void process_return_taint(minsn_t& ins, intra_state_t& st)
{
    if (mop_is_tainted(ins.l, st.ts))
        st.returns_tainted = true;
}

void process_branch_condition(const minsn_t& ins, intra_state_t& st)
{
    if (!is_mcode_jcond(ins.opcode))
        return;
    qstring qs;
    ins.print(&qs, SHINS_SHORT | SHINS_VALNUM);
    qstring clean;
    tag_remove(&clean, qs);
    if (clean.length() > 0)
        st.path_conditions.emplace_back(clean.c_str());
}

void process_instruction(mba_t& mba, minsn_t& ins, intra_state_t& st)
{
    if (is_call_op(ins.opcode))
    {
        process_call_taint(mba, ins, st);
        return;
    }
    if (is_arith_op(ins.opcode))
    {
        process_arith_taint(ins, st);
        return;
    }
    if (is_move_op(ins.opcode))
    {
        process_move_taint(ins, st);
        return;
    }
    if (ins.opcode == m_ldx)
    {
        process_load_taint(ins, st);
        return;
    }
    if (ins.opcode == m_stx)
    {
        process_store_taint(ins, st, mba);
        return;
    }
    if (ins.opcode == m_ret)
    {
        process_return_taint(ins, st);
        return;
    }
    process_branch_condition(ins, st);
}

void run_intraprocedural_analysis(mba_t& mba, intra_state_t& st)
{
    initialize_param_taint(mba, st);
    for (int idx : st.ts.tainted_param_indices)
    {
        int p_idx = param_index_for_lvar(mba, idx);
        if (p_idx >= 0)
            st.tainted_param_indices.insert(p_idx);
    }
    for (int b = 0; b < mba.qty && b < kMaxBlocksPerFunction; ++b)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
        if (blk == nullptr)
            continue;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            process_instruction(mba, *m, st);
    }
}

ea_t containing_func_ea(ea_t ea)
{
    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
        return BADADDR;
    return pfn->start_ea;
}

std::vector<ea_t> walk_call_to_in_func(ea_t func_ea, ea_t target_func_ea)
{
    std::vector<ea_t> out;
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return out;
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
            ea_t to = xb.to;
            if (to == target_func_ea)
            {
                out.push_back(cur);
                break;
            }
            func_t* tgt = get_func(to);
            if (tgt != nullptr && tgt->start_ea == target_func_ea)
            {
                out.push_back(cur);
                break;
            }
        }
    }
    return out;
}

bool intraprocedural_taint_reaches(mba_t& mba, ea_t source_ea, ea_t sink_ea,
                                   std::vector<std::string>& conditions,
                                   int& sink_arg_index_out,
                                   std::string& sink_name_out,
                                   std::string& source_name_out,
                                   taint_kind_t& kind_out)
{
    sink_arg_index_out = -1;
    bool taint_started = false;
    bool reached = false;
    taint_set_t ts;

    for (int b = 0; b < mba.qty && !reached; ++b)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
        if (blk == nullptr)
            continue;
        for (minsn_t* m = blk->head; m != nullptr && !reached; m = m->next)
        {
            if (m->ea == source_ea && is_call_op(m->opcode))
            {
                std::string nm;
                ea_t ce = BADADDR;
                if (resolve_callee_simple(*m, nm, ce))
                {
                    if (is_input_source_name(nm))
                    {
                        source_name_out = nm;
                        kind_out = kind_from_source_name(nm);
                        const sig::source_signature_t* src = find_input_source(nm);
                        if (src != nullptr)
                        {
                            int idx = src->taint_arg_index;
                            if (idx >= 0)
                            {
                                const mop_t* arg = call_arg_at(*m, idx);
                                if (arg != nullptr && arg->t == mop_l && arg->l != nullptr)
                                    ts.tainted_lvars.insert(arg->l->idx);
                            }
                            else if (m->d.t == mop_l && m->d.l != nullptr)
                            {
                                ts.tainted_lvars.insert(m->d.l->idx);
                            }
                        }
                        taint_started = true;
                        continue;
                    }
                }
            }

            if (!taint_started)
                continue;

            if (m->ea == sink_ea && is_call_op(m->opcode))
            {
                std::string nm;
                ea_t ce = BADADDR;
                if (resolve_callee_simple(*m, nm, ce))
                {
                    sink_match_t sm = find_sink_signature(nm);
                    if (sm.sink != nullptr)
                    {
                        sink_name_out = nm;
                        const int n = call_arg_count(*m);
                        for (int i = 0; i < n; ++i)
                        {
                            const mop_t* arg = call_arg_at(*m, i);
                            if (arg == nullptr)
                                continue;
                            if (mop_is_tainted(*arg, ts))
                            {
                                sink_arg_index_out = i;
                                reached = true;
                                break;
                            }
                        }
                    }
                }
                if (reached)
                    break;
            }

            if (is_call_op(m->opcode))
            {
                std::string nm;
                ea_t ce = BADADDR;
                if (resolve_callee_simple(*m, nm, ce))
                {
                    if (is_input_source_name(nm))
                    {
                        const sig::source_signature_t* src = find_input_source(nm);
                        if (src != nullptr)
                        {
                            int idx = src->taint_arg_index;
                            if (idx >= 0)
                            {
                                const mop_t* arg = call_arg_at(*m, idx);
                                if (arg != nullptr && arg->t == mop_l && arg->l != nullptr)
                                    ts.tainted_lvars.insert(arg->l->idx);
                            }
                            else if (m->d.t == mop_l && m->d.l != nullptr)
                            {
                                ts.tainted_lvars.insert(m->d.l->idx);
                            }
                        }
                    }
                    if (is_alloc_name(nm))
                    {
                        if (m->d.t == mop_l && m->d.l != nullptr)
                            ts.tainted_lvars.erase(m->d.l->idx);
                    }
                    continue;
                }
            }

            if (is_arith_op(m->opcode))
            {
                if (mop_is_tainted(m->l, ts) || mop_is_tainted(m->r, ts))
                    taint_destination(m->d, ts);
                continue;
            }
            if (is_move_op(m->opcode))
            {
                if (mop_is_tainted(m->l, ts))
                    taint_destination(m->d, ts);
                else
                    clear_destination_taint(m->d, ts);
                continue;
            }
            if (m->opcode == m_ldx)
            {
                if (mop_is_tainted(m->r, ts) || mop_is_tainted(m->l, ts))
                    taint_destination(m->d, ts);
                continue;
            }
            if (is_mcode_jcond(m->opcode))
            {
                qstring qs;
                m->print(&qs, SHINS_SHORT | SHINS_VALNUM);
                qstring clean;
                tag_remove(&clean, qs);
                if (clean.length() > 0)
                    conditions.emplace_back(clean.c_str());
            }
        }
    }

    return reached;
}

severity_t severity_from_vulnerability_label(const std::string& label)
{
    if (label == "buffer_overflow") return severity_t::high;
    if (label == "command_injection") return severity_t::high;
    if (label == "format_string") return severity_t::high;
    if (label == "integer_overflow") return severity_t::high;
    if (label == "use_after_free") return severity_t::high;
    if (label == "double_free") return severity_t::high;
    if (label == "path_traversal") return severity_t::medium;
    if (label == "uninitialized_use") return severity_t::medium;
    return severity_t::medium;
}

}

nlohmann::json to_json(const taint_path_t& p)
{
    nlohmann::json j;
    nlohmann::json origin;
    origin["source_ea"]      = ea_to_hex(p.origin.source_ea);
    origin["source_func_ea"] = ea_to_hex(p.origin.source_func_ea);
    origin["source_name"]    = p.origin.source_name;
    origin["kind"]           = taint_kind_str(p.origin.kind);
    j["origin"] = std::move(origin);

    j["sink_ea"]        = ea_to_hex(p.sink_ea);
    j["sink_func_ea"]   = ea_to_hex(p.sink_func_ea);
    j["sink_name"]      = p.sink_name;
    j["sink_arg_index"] = p.sink_arg_index;

    nlohmann::json steps = nlohmann::json::array();
    for (const auto& st : p.steps)
    {
        nlohmann::json sj;
        sj["ea"]          = ea_to_hex(st.ea);
        sj["func_ea"]     = ea_to_hex(st.func_ea);
        sj["func_name"]   = st.func_name;
        sj["description"] = st.description;
        sj["condition"]   = st.condition;
        steps.push_back(std::move(sj));
    }
    j["steps"] = std::move(steps);

    nlohmann::json conds = nlohmann::json::array();
    for (const auto& c : p.conditions)
        conds.push_back(c);
    j["conditions"] = std::move(conds);

    j["vulnerability_type"] = p.vulnerability_type;
    j["severity"]           = severity_str(p.severity);
    j["confidence"]         = confidence_str(p.confidence);
    return j;
}

TaintEngine::TaintEngine() {}
TaintEngine::~TaintEngine() {}

void TaintEngine::clear()
{
    m_summaries.clear();
    m_analyzed = false;
}

void TaintEngine::analyze_function(ea_t func_ea)
{
    func_summary_t sum;
    sum.func_ea = func_ea;
    compute_summary(func_ea, sum);
    m_summaries[func_ea] = std::move(sum);
}

void TaintEngine::compute_summary(ea_t func_ea, func_summary_t& sum)
{
    sum.func_ea = func_ea;
    sum.name    = func_name_for(func_ea);

    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr || function_is_skippable(pfn))
        return;

    if (!ida_utils::is_safely_decompilable(pfn))
        return;

    auto handle = microcode::generate(func_ea, MMAT_LVARS);
    if (!handle.has_value() || !handle->mba)
        return;

    mba_t& mba = *handle->mba;
    sum.cyclomatic = compute_cyclomatic_from_mba(mba);

    intra_state_t st;
    run_intraprocedural_analysis(mba, st);

    sum.tainted_param_indices.insert(st.tainted_param_indices.begin(), st.tainted_param_indices.end());
    sum.tainted_out_param_indices.insert(st.tainted_out_param_indices.begin(), st.tainted_out_param_indices.end());
    sum.returns_tainted = st.returns_tainted;
    sum.sinks_reached = std::move(st.sinks_reached);
    sum.validators_called = std::move(st.validators_called);
    sum.allocs_called = std::move(st.allocs_called);
    sum.frees_called = std::move(st.frees_called);
    sum.input_sources_called = std::move(st.input_sources_called);
    sum.params_passed_to_sinks = std::move(st.params_passed_to_sinks);
    sum.params_validated = std::move(st.params_validated);
    sum.params_freed = std::move(st.params_freed);
    sum.returns_alloc = !sum.allocs_called.empty();
    sum.returns_free = !sum.frees_called.empty();
    sum.analyzed = true;
}

std::vector<ea_t> TaintEngine::caller_eas(ea_t callee_ea) const
{
    std::vector<ea_t> out;
    if (callee_ea == BADADDR)
        return out;
    xrefblk_t xb;
    std::unordered_set<ea_t> seen;
    for (bool ok = xb.first_to(callee_ea, XREF_ALL); ok; ok = xb.next_to())
    {
        if (!xb.iscode)
            continue;
        if (xb.type != fl_CN && xb.type != fl_CF)
            continue;
        func_t* caller = get_func(xb.from);
        if (caller == nullptr)
            continue;
        if (seen.insert(caller->start_ea).second)
            out.push_back(caller->start_ea);
    }
    std::sort(out.begin(), out.end());
    return out;
}

void TaintEngine::analyze_all()
{
    m_summaries.clear();
    m_analyzed = false;

    std::vector<ea_t> functions;
    const std::size_t fq = get_func_qty();
    functions.reserve(fq);
    int analyzed_count = 0;
    for (std::size_t i = 0; i < fq && analyzed_count < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        functions.push_back(pfn->start_ea);
        ++analyzed_count;
    }

    TaintCallGraph cg;
    cg.build();

    std::vector<ea_t> ordered = cg.topological_order(functions);
    if (ordered.empty())
        ordered = functions;

    for (int iter = 0; iter < kMaxFixpointIterations; ++iter)
    {
        bool changed = false;
        for (ea_t fea : ordered)
        {
            func_summary_t prev;
            auto it = m_summaries.find(fea);
            if (it != m_summaries.end())
                prev = it->second;
            func_summary_t sum;
            sum.func_ea = fea;
            compute_summary(fea, sum);
            if (!prev.analyzed ||
                prev.tainted_param_indices != sum.tainted_param_indices ||
                prev.tainted_out_param_indices != sum.tainted_out_param_indices ||
                prev.returns_tainted != sum.returns_tainted ||
                prev.sinks_reached != sum.sinks_reached ||
                prev.input_sources_called != sum.input_sources_called)
            {
                changed = true;
            }
            m_summaries[fea] = std::move(sum);
        }
        if (!changed)
            break;
    }

    m_analyzed = true;
}

const func_summary_t* TaintEngine::get_summary(ea_t func_ea) const
{
    auto it = m_summaries.find(func_ea);
    if (it == m_summaries.end())
        return nullptr;
    return &it->second;
}

std::vector<func_summary_t> TaintEngine::get_all_summaries() const
{
    std::vector<func_summary_t> out;
    out.reserve(m_summaries.size());
    for (const auto& kv : m_summaries)
        out.push_back(kv.second);
    return out;
}

std::vector<taint_path_t> TaintEngine::trace_paths(ea_t source_ea, ea_t sink_ea,
                                                   int max_paths, int max_depth)
{
    std::vector<taint_path_t> out;
    if (max_paths <= 0)
        max_paths = 1;
    if (max_paths > 64)
        max_paths = 64;
    if (max_depth <= 0)
        max_depth = 1;
    if (max_depth > 16)
        max_depth = 16;

    if (!m_analyzed)
        analyze_all();

    ea_t source_func_ea = containing_func_ea(source_ea);
    ea_t sink_func_ea   = containing_func_ea(sink_ea);
    if (source_func_ea == BADADDR || sink_func_ea == BADADDR)
        return out;

    if (source_func_ea == sink_func_ea)
    {
        auto handle = microcode::generate(source_func_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            return out;
        std::vector<std::string> conditions;
        int sink_arg_index = -1;
        std::string sink_name;
        std::string source_name;
        taint_kind_t kind = taint_kind_t::user_input;
        if (intraprocedural_taint_reaches(*handle->mba, source_ea, sink_ea,
                                          conditions, sink_arg_index, sink_name,
                                          source_name, kind))
        {
            taint_path_t p;
            p.origin.source_ea      = source_ea;
            p.origin.source_func_ea = source_func_ea;
            p.origin.source_name    = source_name.empty() ? func_name_for(source_func_ea) : source_name;
            p.origin.kind           = kind;
            p.sink_ea       = sink_ea;
            p.sink_func_ea  = sink_func_ea;
            p.sink_name     = sink_name.empty() ? func_name_for(sink_func_ea) : sink_name;
            p.sink_arg_index = sink_arg_index;
            taint_path_step_t s;
            s.ea          = sink_ea;
            s.func_ea     = source_func_ea;
            s.func_name   = func_name_for(source_func_ea);
            s.description = OBFSTR("intraprocedural taint flow");
            s.condition.clear();
            p.steps.push_back(std::move(s));
            p.conditions = std::move(conditions);
            sink_match_t sm = find_sink_signature(p.sink_name);
            int cwe = sm.sink != nullptr ? sm.sink->primary_cwe : 0;
            p.vulnerability_type = vulnerability_label_from_cwe(cwe);
            p.severity   = severity_from_vulnerability_label(p.vulnerability_type);
            p.confidence = confidence_t::likely;
            out.push_back(std::move(p));
        }
        return out;
    }

    TaintCallGraph cg;
    cg.build();

    struct frame_t
    {
        ea_t                              func_ea;
        std::vector<taint_path_step_t>    steps;
        std::vector<std::string>          conditions;
        std::set<ea_t>                    visited;
    };

    std::deque<frame_t> queue;
    frame_t start;
    start.func_ea = source_func_ea;
    start.visited.insert(source_func_ea);
    taint_path_step_t s0;
    s0.ea          = source_ea;
    s0.func_ea     = source_func_ea;
    s0.func_name   = func_name_for(source_func_ea);
    s0.description = OBFSTR("input source observed");
    start.steps.push_back(std::move(s0));
    queue.push_back(std::move(start));

    std::string sink_name_for_path;
    sink_match_t sm0 = find_sink_signature(func_name_for(sink_func_ea));
    int sink_arg_index_for_path = -1;
    int sink_cwe = 0;
    if (sm0.sink != nullptr)
    {
        sink_name_for_path = std::string(sm0.sink->name);
        sink_cwe = sm0.sink->primary_cwe;
        sink_arg_index_for_path = sm0.sink->len_arg_index >= 0 ? sm0.sink->len_arg_index : 0;
    }

    std::string source_name_for_path = func_name_for(source_func_ea);
    taint_kind_t kind_for_path = kind_from_source_name(source_name_for_path);

    while (!queue.empty() && static_cast<int>(out.size()) < max_paths)
    {
        frame_t cur = std::move(queue.front());
        queue.pop_front();

        if (cur.func_ea == sink_func_ea)
        {
            taint_path_t p;
            p.origin.source_ea      = source_ea;
            p.origin.source_func_ea = source_func_ea;
            p.origin.source_name    = source_name_for_path;
            p.origin.kind           = kind_for_path;
            p.sink_ea       = sink_ea;
            p.sink_func_ea  = sink_func_ea;
            p.sink_name     = sink_name_for_path.empty() ? func_name_for(sink_func_ea) : sink_name_for_path;
            p.sink_arg_index = sink_arg_index_for_path;
            p.steps      = cur.steps;
            p.conditions = cur.conditions;
            p.vulnerability_type = vulnerability_label_from_cwe(sink_cwe);
            p.severity   = severity_from_vulnerability_label(p.vulnerability_type);
            const auto* sum = get_summary(cur.func_ea);
            p.confidence = (sum != nullptr && !sum->validators_called.empty())
                            ? confidence_t::plausible : confidence_t::likely;
            out.push_back(std::move(p));
            continue;
        }

        if (static_cast<int>(cur.steps.size()) >= max_depth)
            continue;

        const auto& callees = cg.callees_of(cur.func_ea);
        for (ea_t next_ea : callees)
        {
            if (cur.visited.count(next_ea))
                continue;
            const auto* nsum = get_summary(next_ea);
            if (next_ea != sink_func_ea)
            {
                if (nsum == nullptr)
                    continue;
                if (nsum->tainted_param_indices.empty() &&
                    nsum->tainted_out_param_indices.empty() &&
                    nsum->sinks_reached.empty() &&
                    !nsum->returns_tainted)
                    continue;
            }
            std::vector<ea_t> call_eas = walk_call_to_in_func(cur.func_ea, next_ea);
            ea_t hop_ea = call_eas.empty() ? BADADDR : call_eas.front();
            frame_t nf = cur;
            nf.func_ea = next_ea;
            nf.visited.insert(next_ea);
            taint_path_step_t st;
            st.ea          = hop_ea;
            st.func_ea     = next_ea;
            st.func_name   = func_name_for(next_ea);
            st.description = OBFSTR("call hop from ") + func_name_for(cur.func_ea) +
                              OBFSTR(" to ") + st.func_name;
            nf.steps.push_back(std::move(st));
            queue.push_back(std::move(nf));
            if (static_cast<int>(queue.size()) > max_paths * 8)
                break;
        }
    }

    return out;
}

std::vector<taint_path_t> TaintEngine::trace_paths_from_source(ea_t source_ea,
                                                                int max_paths,
                                                                int max_depth)
{
    std::vector<taint_path_t> out;
    if (max_paths <= 0)
        max_paths = 1;
    if (max_paths > 64)
        max_paths = 64;
    if (!m_analyzed)
        analyze_all();

    std::vector<std::string> sink_names;
    sink_names.reserve(64);
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
        sink_names.emplace_back(s.name);
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
        sink_names.emplace_back(s.name);
    for (const auto& s : sig::PATH_TRAVERSAL_SINKS)
        sink_names.emplace_back(s.name);
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
        sink_names.emplace_back(s.name);
    std::sort(sink_names.begin(), sink_names.end());
    sink_names.erase(std::unique(sink_names.begin(), sink_names.end()), sink_names.end());

    std::unordered_set<ea_t> sink_eas;
    for (const auto& nm : sink_names)
    {
        ea_t e = get_name_ea(BADADDR, nm.c_str());
        if (e != BADADDR)
            sink_eas.insert(e);
    }

    for (ea_t sink_ea : sink_eas)
    {
        if (static_cast<int>(out.size()) >= max_paths)
            break;
        auto found = trace_paths(source_ea, sink_ea, max_paths - static_cast<int>(out.size()),
                                 max_depth);
        for (auto& p : found)
        {
            if (static_cast<int>(out.size()) >= max_paths)
                break;
            out.push_back(std::move(p));
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_uaf_candidates(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;
        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_call_op(m->opcode))
                    continue;
                std::string nm;
                ea_t ce = BADADDR;
                if (!resolve_callee_simple(*m, nm, ce))
                    continue;
                if (!is_free_name(nm) || is_realloc_name(nm))
                    continue;
                mop_t ptr;
                ptr.zero();
                if (!collect_first_pointer_arg(*m, ptr))
                    continue;
                ea_t free_ea = BADADDR;
                ea_t use_ea  = BADADDR;
                if (!microcode::is_freed_then_used(mba, ptr, free_ea, use_ea))
                    continue;
                if (free_ea == BADADDR || use_ea == BADADDR)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/uaf/" << std::hex << std::uppercase << static_cast<std::uint64_t>(use_ea);
                f.id = id.str();
                f.primary_ea = use_ea;
                f.related_eas.push_back(free_ea);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 416;
                c.name = cwe_name_for(416);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::likely;
                std::ostringstream tt;
                tt << "Use-after-free in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer freed at " << ea_to_hex(free_ea)
                    << " is dereferenced or passed to another sink at "
                    << ea_to_hex(use_ea) << " without an intervening reassignment.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["free_ea"] = ea_to_hex(free_ea);
                ev["use_ea"]  = ea_to_hex(use_ea);
                ev["func_ea"] = ea_to_hex(pfn->start_ea);
                ev["callee"]  = nm;
                ev["ptr"]     = microcode::mop_describe(ptr);
                f.evidence    = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_double_free_candidates(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;
        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_call_op(m->opcode))
                    continue;
                std::string nm;
                ea_t ce = BADADDR;
                if (!resolve_callee_simple(*m, nm, ce))
                    continue;
                if (!is_free_name(nm) || is_realloc_name(nm))
                    continue;
                mop_t ptr;
                ptr.zero();
                if (!collect_first_pointer_arg(*m, ptr))
                    continue;
                ea_t free1 = BADADDR;
                ea_t free2 = BADADDR;
                if (!microcode::is_double_freed(mba, ptr, free1, free2))
                    continue;
                if (free1 == BADADDR || free2 == BADADDR)
                    continue;
                if (free1 != m->ea)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/double_free/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(free2);
                f.id = id.str();
                f.primary_ea = free2;
                f.related_eas.push_back(free1);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 415;
                c.name = cwe_name_for(415);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::likely;
                std::ostringstream tt;
                tt << "Double free in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer freed at " << ea_to_hex(free1)
                    << " is freed again at " << ea_to_hex(free2)
                    << " without an intervening reassignment.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["first_free_ea"]  = ea_to_hex(free1);
                ev["second_free_ea"] = ea_to_hex(free2);
                ev["func_ea"]        = ea_to_hex(pfn->start_ea);
                ev["callee"]         = nm;
                ev["ptr"]            = microcode::mop_describe(ptr);
                f.evidence           = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_use_after_realloc(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;
        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_call_op(m->opcode))
                    continue;
                std::string nm;
                ea_t ce = BADADDR;
                if (!resolve_callee_simple(*m, nm, ce))
                    continue;
                if (!is_realloc_name(nm))
                    continue;
                mop_t input_ptr;
                input_ptr.zero();
                if (!collect_first_pointer_arg(*m, input_ptr))
                    continue;

                ea_t free_ea = BADADDR;
                ea_t use_ea  = BADADDR;
                if (!microcode::is_freed_then_used(mba, input_ptr, free_ea, use_ea))
                    continue;
                if (use_ea == BADADDR || use_ea == m->ea)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/use_after_realloc/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(use_ea);
                f.id = id.str();
                f.primary_ea = use_ea;
                f.related_eas.push_back(m->ea);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 416;
                c.name = cwe_name_for(416);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "Use after realloc in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer reallocated at " << ea_to_hex(m->ea)
                    << " is dereferenced via the original handle at " << ea_to_hex(use_ea)
                    << " without checking whether realloc returned a new pointer.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["realloc_ea"] = ea_to_hex(m->ea);
                ev["use_ea"]     = ea_to_hex(use_ea);
                ev["func_ea"]    = ea_to_hex(pfn->start_ea);
                ev["callee"]     = nm;
                ev["ptr"]        = microcode::mop_describe(input_ptr);
                f.evidence       = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_uninit_use(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;

        std::unordered_set<int> param_lvars;
        for (size_t a = 0; a < mba.argidx.size(); ++a)
            param_lvars.insert(mba.argidx[a]);

        std::size_t per_func = 0;
        for (size_t v = 0; v < mba.vars.size() && per_func < kMaxFreedTrackingPerFunc; ++v)
        {
            int idx = static_cast<int>(v);
            if (param_lvars.count(idx))
                continue;
            const lvar_t& lv = mba.vars[v];
            int width = lv.width > 0 ? lv.width : 1;
            mop_t synth;
            synth._make_lvar(&mba, idx, 0);
            synth.size = width;
            ea_t read_ea = BADADDR;
            if (!microcode::has_uninit_read(mba, synth, read_ea))
                continue;
            if (read_ea == BADADDR)
                continue;

            vuln_finding_t f;
            std::ostringstream id;
            id << "vuln/uninit/" << std::hex << std::uppercase << static_cast<std::uint64_t>(read_ea);
            f.id = id.str();
            f.primary_ea = read_ea;
            f.related_eas.push_back(pfn->start_ea);
            cwe_t c;
            c.id = 457;
            c.name = cwe_name_for(457);
            f.cwes.push_back(c);
            f.severity   = severity_t::medium;
            f.confidence = confidence_t::plausible;
            std::ostringstream tt;
            std::string vname = lv.name.empty() ? std::string("v") + std::to_string(idx) : std::string(lv.name.c_str());
            tt << "Uninitialized read of " << vname << " in " << func_name_for(pfn->start_ea);
            f.title = tt.str();
            std::ostringstream rat;
            rat << "Local variable " << vname
                << " is read at " << ea_to_hex(read_ea)
                << " before any reaching definition.";
            f.rationale = rat.str();
            nlohmann::json ev;
            ev["read_ea"]  = ea_to_hex(read_ea);
            ev["func_ea"]  = ea_to_hex(pfn->start_ea);
            ev["lvar_idx"] = idx;
            ev["lvar_name"] = vname;
            f.evidence     = std::move(ev);
            out.push_back(std::move(f));
            ++per_func;
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
        if (static_cast<int>(out.size()) >= max_findings)
            break;
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_integer_overflow_sites(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;

        intra_state_t st;
        run_intraprocedural_analysis(mba, st);

        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_overflow_arith(m->opcode))
                    continue;
                if (m->d.t == mop_z)
                    continue;
                bool l_t = mop_is_tainted(m->l, st.ts);
                bool r_t = mop_is_tainted(m->r, st.ts);
                if (!l_t && !r_t)
                    continue;
                if (m->d.t != mop_l || m->d.l == nullptr)
                    continue;

                auto chain = microcode::def_use_chain(mba, m->d);
                bool flows_to_alloc_or_copy = false;
                ea_t reaching_sink_ea = BADADDR;
                std::string reaching_sink_name;

                for (ea_t use_ea : chain.uses)
                {
                    for (int bb = 0; bb < mba.qty && !flows_to_alloc_or_copy; ++bb)
                    {
                        const mblock_t* blk2 = mba.get_mblock(static_cast<uint>(bb));
                        if (blk2 == nullptr)
                            continue;
                        for (const minsn_t* mm = blk2->head; mm != nullptr; mm = mm->next)
                        {
                            if (mm->ea != use_ea)
                                continue;
                            if (!is_call_op(mm->opcode))
                                continue;
                            std::string callee_nm;
                            ea_t cce = BADADDR;
                            if (!microcode::resolve_call_target(*mm, cce, callee_nm))
                                continue;
                            if (!(is_alloc_name(callee_nm) || is_sink_name(callee_nm)))
                                continue;
                            flows_to_alloc_or_copy = true;
                            reaching_sink_ea = mm->ea;
                            reaching_sink_name = callee_nm;
                            break;
                        }
                    }
                    if (flows_to_alloc_or_copy)
                        break;
                }

                if (!flows_to_alloc_or_copy)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/integer_overflow/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(m->ea);
                f.id = id.str();
                f.primary_ea = m->ea;
                f.related_eas.push_back(reaching_sink_ea);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 190;
                c.name = cwe_name_for(190);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "Tainted integer arithmetic flowing into " << reaching_sink_name
                   << " in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Arithmetic at " << ea_to_hex(m->ea)
                    << " mixes attacker-tainted operands and the result reaches "
                    << reaching_sink_name << " at " << ea_to_hex(reaching_sink_ea)
                    << " without an intervening overflow guard.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["arith_ea"]   = ea_to_hex(m->ea);
                ev["sink_ea"]    = ea_to_hex(reaching_sink_ea);
                ev["sink_name"]  = reaching_sink_name;
                ev["func_ea"]    = ea_to_hex(pfn->start_ea);
                ev["l_tainted"]  = l_t;
                ev["r_tainted"]  = r_t;
                f.evidence       = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

TaintEngine& engine()
{
    static TaintEngine e;
    return e;
}

namespace tools
{

namespace
{

using nlohmann::json;
using agent_tools::tool_result_t;

std::mutex& engine_mutex()
{
    static std::mutex mtx;
    return mtx;
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

std::string extract_string_param(const json& params, const std::string& key,
                                 const std::string& default_value)
{
    if (!params.is_object())
        return default_value;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return default_value;
    if (it->is_string())
        return it->get<std::string>();
    return default_value;
}

json findings_to_json_array(const std::vector<vuln_finding_t>& findings)
{
    json arr = json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
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

tool_result_t handle_trace_taint_path(const json& params)
{
    const std::string source_spec = extract_string_param(params, "source", std::string());
    const std::string sink_spec   = extract_string_param(params, "sink",   std::string());
    if (source_spec.empty() || sink_spec.empty())
        return tool_result_t::error(OBFSTR("source and sink must be provided"));

    int max_paths = extract_int_param(params, "max_paths", 16);
    if (max_paths <= 0) max_paths = 16;
    if (max_paths > 64) max_paths = 64;

    int max_depth = extract_int_param(params, "max_depth", 10);
    if (max_depth <= 0) max_depth = 10;
    if (max_depth > 16) max_depth = 16;

    ea_t source_ea = resolve_address_or_name(source_spec);
    ea_t sink_ea   = resolve_address_or_name(sink_spec);
    if (source_ea == BADADDR)
        return tool_result_t::error(OBFSTR("Could not resolve source: ") + source_spec);
    if (sink_ea == BADADDR)
        return tool_result_t::error(OBFSTR("Could not resolve sink: ") + sink_spec);

    std::vector<taint_path_t> paths;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        paths = engine().trace_paths(source_ea, sink_ea, max_paths, max_depth);
    }

    json arr = json::array();
    for (const auto& p : paths)
        arr.push_back(to_json(p));

    json data;
    data["paths"] = std::move(arr);
    data["count"] = paths.size();
    data["source_ea"] = ea_to_hex(source_ea);
    data["sink_ea"]   = ea_to_hex(sink_ea);
    func_t* sf = get_func(source_ea);
    func_t* tf = get_func(sink_ea);
    data["source_func"] = sf != nullptr ? func_name_for(sf->start_ea) : std::string();
    data["sink_func"]   = tf != nullptr ? func_name_for(tf->start_ea) : std::string();
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << OBFSTR("Taint path trace: ") << paths.size() << OBFSTR(" path(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_uaf_candidates(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_uaf_candidates(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 416;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << OBFSTR("Use-after-free scan: ") << findings.size() << OBFSTR(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_double_free_candidates(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_double_free_candidates(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 415;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << OBFSTR("Double-free scan: ") << findings.size() << OBFSTR(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_use_after_realloc(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_use_after_realloc(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 416;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << OBFSTR("Use-after-realloc scan: ") << findings.size() << OBFSTR(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_uninit_use(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_uninit_use(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 457;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << OBFSTR("Uninitialized-use scan: ") << findings.size() << OBFSTR(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_integer_overflow_sites(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_integer_overflow_sites(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 190;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << OBFSTR("Integer-overflow scan: ") << findings.size() << OBFSTR(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

}

void register_tier1_taint_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("trace_taint_path"),
        OBFSTR("vuln"),
        OBFSTR("Compute interprocedural taint paths from a known input source callsite (recv/"
               "ReadFile/scanf/getenv/RegQuery/...) to a known dangerous sink callsite "
               "(strcpy/memcpy/system/CreateProcess/sprintf/...). Walks the binary's call graph "
               "and applies per-function taint summaries (parameter taint, returns_tainted, "
               "sinks_reached, validators_called) at each hop. Returns up to max_paths distinct "
               "paths, each with the originating taint kind, the sink argument index, the "
               "caller chain (taint_path_step_t per call hop), accumulated branch conditions, a "
               "vulnerability classification derived from the sink CWE, and a severity / "
               "confidence assessment that downgrades to plausible when validators are present "
               "on the dominant route."),
        {
            {OBFSTR("source"),    OBFSTR("string"),
             OBFSTR("Address (0x...) or symbol name of the input-source callsite."), true},
            {OBFSTR("sink"),      OBFSTR("string"),
             OBFSTR("Address (0x...) or symbol name of the dangerous-sink callsite."), true},
            {OBFSTR("max_paths"), OBFSTR("number"),
             OBFSTR("Maximum number of paths to enumerate (default 16, max 64)."), false},
            {OBFSTR("max_depth"), OBFSTR("number"),
             OBFSTR("Maximum call-graph depth (default 10, max 16)."), false},
        },
        handle_trace_taint_path,
        true,
    });
}

void register_tier2_taint_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("find_uaf_candidates"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Locate use-after-free candidates (CWE-416) by walking each function's microcode, "
               "tracking the freed pointer at every call to free/HeapFree/RtlFreeHeap/ExFreePool/"
               "operator delete and detecting subsequent dereferences (m_ldx/m_stx) or sink-arg "
               "uses without an intervening reassignment of the same pointer. Skips realloc-style "
               "calls because those have a separate engine."),
        {
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_uaf_candidates,
        true,
    });

    registry.register_tool({
        OBFSTR("find_double_free_candidates"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Locate double-free candidates (CWE-415) by walking each function's microcode and "
               "flagging two distinct free-style calls applied to the same pointer without an "
               "intervening reassignment. Free signatures cover free/HeapFree/RtlFreeHeap/"
               "ExFreePool/ExFreePoolWithTag/operator delete and the corresponding mangled "
               "MSVC operator-delete symbols."),
        {
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_double_free_candidates,
        true,
    });

    registry.register_tool({
        OBFSTR("find_use_after_realloc"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Locate use-after-realloc candidates (CWE-416) by walking each function's "
               "microcode for realloc/HeapReAlloc calls, capturing the input pointer, and "
               "checking whether that original handle is dereferenced after the realloc without "
               "an early-return check on the new pointer. Reports the realloc EA, the offending "
               "use EA, and the function context."),
        {
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_use_after_realloc,
        true,
    });

    registry.register_tool({
        OBFSTR("find_uninit_use"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Locate uninitialized-variable reads (CWE-457) by walking each function's "
               "microcode for non-parameter local variables (mba.vars excluding mba.argidx) "
               "where any use precedes any reaching definition. Reports the variable name (or "
               "synthetic v<idx> for unnamed slots), the read EA, and the function context."),
        {
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_uninit_use,
        true,
    });

    registry.register_tool({
        OBFSTR("find_integer_overflow_sites"),
        OBFSTR("vuln_advanced"),
        OBFSTR("Locate integer-overflow sites (CWE-190) by running intraprocedural taint analysis, "
               "scanning each m_add/m_sub/m_mul whose operands are tainted by an input source, "
               "tracing the result through the def-use chain, and emitting a finding when the "
               "result reaches an allocation-size or memcpy-length sink (malloc/calloc/realloc/"
               "HeapAlloc/ExAllocatePool*/memcpy/memmove/snprintf/...) without an intervening "
               "overflow guard."),
        {
            {OBFSTR("limit"), OBFSTR("number"),
             OBFSTR("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_integer_overflow_sites,
        true,
    });
}

}

}
}
}
