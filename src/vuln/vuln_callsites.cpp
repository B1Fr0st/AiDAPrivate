#include "../aida_pro.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <xref.hpp>

#include "../agent_tools.hpp"
#include "../analysis_db.hpp"
#include "../ida_utils.hpp"
#include "../obfuscation.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace callsites
{

namespace
{

using json = nlohmann::json;

constexpr int CACHE_SCHEMA_REVISION = 1;

struct name_index_t
{
    std::unordered_map<std::string, std::vector<ea_t>> by_name;
};

struct callee_match_t
{
    ea_t        callee_ea  = BADADDR;
    std::string canonical_name;
};

inline std::string strip_known_prefixes(const std::string& raw)
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
    if (!out.empty() && out.front() == '_')
    {
        bool only_alnum_underscore = true;
        for (char c : out)
        {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '@' || c == '?'))
            {
                only_alnum_underscore = false;
                break;
            }
        }
        if (only_alnum_underscore && out.size() > 1)
            out.erase(0, 1);
    }
    auto at_pos = out.find('@');
    if (at_pos != std::string::npos)
        out.erase(at_pos);
    return out;
}

inline void add_name_for_ea(name_index_t& idx, const std::string& name, ea_t ea)
{
    if (name.empty() || ea == BADADDR)
        return;
    idx.by_name[name].push_back(ea);
    const std::string stripped = strip_known_prefixes(name);
    if (stripped != name && !stripped.empty())
        idx.by_name[stripped].push_back(ea);
}

struct import_collect_ctx_t
{
    name_index_t* idx = nullptr;
};

int idaapi import_enum_collect_cb(ea_t ea, const char* name, uval_t ord, void* param)
{
    (void)ord;
    if (param == nullptr || name == nullptr || ea == BADADDR)
        return 1;
    auto* ctx = static_cast<import_collect_ctx_t*>(param);
    if (ctx->idx == nullptr)
        return 1;
    std::string str_name(name);
    if (str_name.empty())
        return 1;
    add_name_for_ea(*ctx->idx, str_name, ea);
    qstring real;
    if (get_name(&real, ea) > 0 && !real.empty())
    {
        std::string r = real.c_str();
        if (r != str_name)
            add_name_for_ea(*ctx->idx, r, ea);
    }
    return 1;
}

inline name_index_t build_name_index()
{
    name_index_t idx;

    const uint mod_count = get_import_module_qty();
    for (uint i = 0; i < mod_count; ++i)
    {
        import_collect_ctx_t ctx;
        ctx.idx = &idx;
        enum_import_names(static_cast<int>(i), import_enum_collect_cb, &ctx);
    }

    const std::size_t entry_qty = get_entry_qty();
    for (std::size_t i = 0; i < entry_qty; ++i)
    {
        const uval_t ord = get_entry_ordinal(i);
        const ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;
        qstring nm;
        if (get_entry_name(&nm, ord) > 0 && !nm.empty())
            add_name_for_ea(idx, nm.c_str(), ea);
        qstring real;
        if (get_name(&real, ea) > 0 && !real.empty())
        {
            std::string r = real.c_str();
            add_name_for_ea(idx, r, ea);
        }
    }

    const std::size_t func_qty = get_func_qty();
    for (std::size_t i = 0; i < func_qty; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        qstring nm;
        if (get_func_name(&nm, pfn->start_ea) > 0 && !nm.empty())
            add_name_for_ea(idx, nm.c_str(), pfn->start_ea);
        qstring vname;
        if (get_name(&vname, pfn->start_ea) > 0 && !vname.empty())
        {
            std::string v = vname.c_str();
            add_name_for_ea(idx, v, pfn->start_ea);
        }

        if ((pfn->flags & FUNC_THUNK) != 0)
        {
            ea_t fptr = BADADDR;
            const ea_t target = calc_thunk_func_target(pfn, &fptr);
            if (target != BADADDR && target != pfn->start_ea)
            {
                qstring tnm;
                if (get_func_name(&tnm, target) > 0 && !tnm.empty())
                {
                    std::string t = tnm.c_str();
                    if (!t.empty())
                        idx.by_name[t].push_back(pfn->start_ea);
                }
                qstring tnm2;
                if (get_name(&tnm2, target) > 0 && !tnm2.empty())
                {
                    std::string t2 = tnm2.c_str();
                    if (!t2.empty())
                        idx.by_name[t2].push_back(pfn->start_ea);
                    const std::string stripped_t2 = strip_known_prefixes(t2);
                    if (!stripped_t2.empty() && stripped_t2 != t2)
                        idx.by_name[stripped_t2].push_back(pfn->start_ea);
                }
            }
            if (fptr != BADADDR)
            {
                qstring fnm;
                if (get_name(&fnm, fptr) > 0 && !fnm.empty())
                {
                    std::string f = fnm.c_str();
                    if (!f.empty())
                        idx.by_name[f].push_back(pfn->start_ea);
                    const std::string stripped_f = strip_known_prefixes(f);
                    if (!stripped_f.empty() && stripped_f != f)
                        idx.by_name[stripped_f].push_back(pfn->start_ea);
                }
            }
        }
    }

    for (auto& kv : idx.by_name)
    {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
    }
    return idx;
}

const name_index_t& cached_name_index()
{
    static std::mutex                          mtx;
    static std::optional<name_index_t>         cache;
    static std::string                         cached_hash;
    std::lock_guard<std::mutex> lk(mtx);
    const std::string current_hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (!cache.has_value() || current_hash != cached_hash)
    {
        cache = build_name_index();
        cached_hash = current_hash;
    }
    return *cache;
}

inline std::vector<callee_match_t> resolve_callee_eas(const std::vector<std::string>& names)
{
    const name_index_t& idx = cached_name_index();
    std::vector<callee_match_t> out;
    std::unordered_set<ea_t> seen;
    for (const auto& nm : names)
    {
        if (nm.empty())
            continue;
        auto it = idx.by_name.find(nm);
        if (it != idx.by_name.end())
        {
            for (ea_t ea : it->second)
            {
                if (seen.insert(ea).second)
                {
                    callee_match_t m;
                    m.callee_ea = ea;
                    m.canonical_name = nm;
                    out.push_back(std::move(m));
                }
            }
        }
        const ea_t direct = get_name_ea(BADADDR, nm.c_str());
        if (direct != BADADDR && seen.insert(direct).second)
        {
            callee_match_t m;
            m.callee_ea = direct;
            m.canonical_name = nm;
            out.push_back(std::move(m));
        }
    }
    return out;
}

inline std::string escape_for_summary(const std::string& s, std::size_t max_len = 64)
{
    std::ostringstream out;
    std::size_t emitted = 0;
    for (std::size_t i = 0; i < s.size() && emitted < max_len; ++i)
    {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '\\' || c == '"')
        {
            out << '\\' << static_cast<char>(c);
            emitted += 2;
        }
        else if (c == '\n')
        {
            out << "\\n";
            emitted += 2;
        }
        else if (c == '\r')
        {
            out << "\\r";
            emitted += 2;
        }
        else if (c == '\t')
        {
            out << "\\t";
            emitted += 2;
        }
        else if (c < 0x20 || c == 0x7F)
        {
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            emitted += 4;
        }
        else
        {
            out << static_cast<char>(c);
            emitted += 1;
        }
    }
    if (s.size() > max_len)
        out << "...";
    return out.str();
}

inline bool ea_is_in_readonly_segment(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return false;
    if (seg->perm != 0 && (seg->perm & SEGPERM_WRITE) == 0)
        return true;
    qstring name;
    if (get_segm_name(&name, seg, 0) > 0 && !name.empty())
    {
        std::string n = name.c_str();
        std::transform(n.begin(), n.end(), n.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (n.find("rdata") != std::string::npos ||
            n.find("rodata") != std::string::npos ||
            n.find(".text") != std::string::npos ||
            n.find("const") != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

inline bool obj_is_string_constant(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    flags64_t fl = get_flags(ea);
    if (is_strlit(fl))
        return true;
    return false;
}

inline std::string format_obj_summary(ea_t ea)
{
    std::ostringstream out;
    qstring nm;
    if (get_name(&nm, ea) > 0 && !nm.empty())
    {
        out << "&" << nm.c_str();
        return out.str();
    }
    out << "&0x" << std::hex << std::uppercase << static_cast<uint64_t>(ea);
    return out.str();
}

inline std::string read_string_literal(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return std::string();
    qstring s;
    if (get_strlit_contents(&s, ea, -1, STRTYPE_C) > 0)
        return std::string(s.c_str());
    if (get_strlit_contents(&s, ea, -1, STRTYPE_C_16) > 0)
        return std::string(s.c_str());
    return std::string();
}

inline std::string fallback_expr_summary(const cfunc_t* cf, const cexpr_t* expr)
{
    if (cf == nullptr || expr == nullptr)
        return std::string();
    qstring out;
    expr->print1(&out, cf);
    tag_remove(&out);
    std::string s = out.c_str();
    if (s.size() > 96)
    {
        s.resize(93);
        s.append("...");
    }
    return s;
}

inline std::string lvar_name_for(const cfunc_t* cf, const var_ref_t& v)
{
    if (cf == nullptr)
        return std::string();
    cfunc_t* mut = const_cast<cfunc_t*>(cf);
    lvars_t* lv = mut->get_lvars();
    if (lv == nullptr)
        return std::string();
    if (v.idx < 0 || static_cast<std::size_t>(v.idx) >= lv->size())
        return std::string();
    const lvar_t& l = (*lv)[v.idx];
    if (!l.name.empty())
        return std::string(l.name.c_str());
    return std::string();
}

inline std::string summarize_arg(const cfunc_t* cf, const carg_t& arg, bool& out_is_literal)
{
    out_is_literal = false;
    const cexpr_t* expr = static_cast<const cexpr_t*>(&arg);
    const cexpr_t* inner = expr;
    while (inner != nullptr && (inner->op == cot_cast || inner->op == cot_ref) && inner->x != nullptr)
        inner = inner->x;
    if (inner == nullptr)
        inner = expr;

    if (inner->op == cot_str && inner->string != nullptr)
    {
        out_is_literal = true;
        std::string raw(inner->string);
        std::ostringstream ss;
        ss << "\"" << escape_for_summary(raw, 64) << "\"";
        return ss.str();
    }
    if (inner->op == cot_num)
    {
        out_is_literal = true;
        std::ostringstream ss;
        ss << "#0x" << std::hex << std::uppercase << static_cast<uint64_t>(inner->numval());
        return ss.str();
    }
    if (inner->op == cot_obj)
    {
        if (obj_is_string_constant(inner->obj_ea))
        {
            out_is_literal = true;
            std::string raw = read_string_literal(inner->obj_ea);
            if (!raw.empty())
            {
                std::ostringstream ss;
                ss << "\"" << escape_for_summary(raw, 64) << "\"";
                return ss.str();
            }
        }
        if (ea_is_in_readonly_segment(inner->obj_ea))
            out_is_literal = true;
        return format_obj_summary(inner->obj_ea);
    }
    if (inner->op == cot_var)
    {
        std::ostringstream ss;
        ss << "v" << inner->v.idx;
        const std::string lvname = lvar_name_for(cf, inner->v);
        if (!lvname.empty())
            ss << "(" << lvname << ")";
        return ss.str();
    }
    return fallback_expr_summary(cf, expr);
}

struct call_visitor_t : public ctree_visitor_t
{
    cfunc_t*                        cfunc = nullptr;
    std::function<void(cexpr_t*)>   on_call;

    call_visitor_t(cfunc_t* cf, std::function<void(cexpr_t*)> cb)
        : ctree_visitor_t(CV_FAST), cfunc(cf), on_call(std::move(cb)) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr != nullptr && expr->op == cot_call && on_call)
            on_call(expr);
        return 0;
    }
};

struct decompile_cache_t
{
    std::unordered_map<ea_t, cfuncptr_t> entries;
    std::unordered_set<ea_t>             failed;

    cfunc_t* fetch(ea_t func_ea)
    {
        if (func_ea == BADADDR)
            return nullptr;
        auto it = entries.find(func_ea);
        if (it != entries.end())
            return it->second.operator->();
        if (failed.count(func_ea))
            return nullptr;
        if (!init_hexrays_plugin())
        {
            failed.insert(func_ea);
            return nullptr;
        }
        func_t* pfn = get_func(func_ea);
        if (pfn == nullptr || !ida_utils::is_safely_decompilable(pfn))
        {
            failed.insert(func_ea);
            return nullptr;
        }
        try
        {
            cfuncptr_t cf = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
            if (!cf)
            {
                failed.insert(func_ea);
                return nullptr;
            }
            cfunc_t* raw = cf.operator->();
            entries.emplace(func_ea, std::move(cf));
            return raw;
        }
        catch (const vd_failure_t&)
        {
            failed.insert(func_ea);
            return nullptr;
        }
        catch (...)
        {
            failed.insert(func_ea);
            return nullptr;
        }
    }
};

inline ea_t resolve_call_target_ea(const cexpr_t* call_expr)
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

inline void fill_callsite_args(const cfunc_t* cf, const cexpr_t* call_expr, callsite_t& out)
{
    if (cf == nullptr || call_expr == nullptr || call_expr->a == nullptr)
        return;
    const carglist_t& args = *call_expr->a;
    out.arg_summaries.reserve(args.size());
    out.arg_is_literal.reserve(args.size());
    for (std::size_t i = 0; i < args.size(); ++i)
    {
        bool is_lit = false;
        std::string summary = summarize_arg(cf, args[i], is_lit);
        out.arg_summaries.push_back(std::move(summary));
        out.arg_is_literal.push_back(is_lit);
    }
}

inline std::vector<callsite_t> collect_calls_to_targets(const std::vector<callee_match_t>& callees)
{
    std::vector<callsite_t> result;
    if (callees.empty())
        return result;

    std::unordered_map<ea_t, std::string> ea_to_name;
    ea_to_name.reserve(callees.size());
    for (const auto& m : callees)
        ea_to_name.emplace(m.callee_ea, m.canonical_name);

    std::unordered_map<ea_t, std::vector<ea_t>> caller_to_calls;
    struct pair_hash_t
    {
        std::size_t operator()(const std::pair<ea_t, ea_t>& p) const noexcept
        {
            const std::uint64_t a = static_cast<std::uint64_t>(p.first);
            const std::uint64_t b = static_cast<std::uint64_t>(p.second);
            std::uint64_t h = a ^ (b + 0x9E3779B97F4A7C15ull + (a << 6) + (a >> 2));
            return static_cast<std::size_t>(h);
        }
    };
    std::unordered_map<std::pair<ea_t, ea_t>, std::string, pair_hash_t> call_to_name;
    std::unordered_set<std::pair<ea_t, ea_t>, pair_hash_t>              seen_pairs;

    for (const auto& m : callees)
    {
        xrefblk_t xb;
        for (bool ok = xb.first_to(m.callee_ea, XREF_ALL); ok; ok = xb.next_to())
        {
            if (!xb.iscode)
                continue;
            if (xb.type != fl_CN && xb.type != fl_CF)
                continue;
            func_t* caller = get_func(xb.from);
            if (caller == nullptr)
                continue;
            std::pair<ea_t, ea_t> key(caller->start_ea, xb.from);
            if (!seen_pairs.insert(key).second)
                continue;
            caller_to_calls[caller->start_ea].push_back(xb.from);
            call_to_name[key] = m.canonical_name;
        }
    }

    decompile_cache_t cache;

    for (auto& kv : caller_to_calls)
    {
        ea_t caller_ea = kv.first;
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());

        cfunc_t* cf = cache.fetch(caller_ea);
        std::unordered_map<ea_t, cexpr_t*> call_map;
        if (cf != nullptr)
        {
            call_visitor_t visitor(cf, [&](cexpr_t* e) {
                if (e == nullptr)
                    return;
                if (e->ea != BADADDR)
                    call_map[e->ea] = e;
            });
            visitor.apply_to(&cf->body, nullptr);
        }

        for (ea_t call_ea : kv.second)
        {
            callsite_t cs;
            cs.call_ea = call_ea;
            cs.func_ea = caller_ea;
            auto name_it = call_to_name.find(std::pair<ea_t, ea_t>(caller_ea, call_ea));
            if (name_it != call_to_name.end())
                cs.callee_name = name_it->second;

            if (cf != nullptr)
            {
                auto cm = call_map.find(call_ea);
                if (cm != call_map.end())
                {
                    fill_callsite_args(cf, cm->second, cs);
                }
                else
                {
                    cexpr_t* found = nullptr;
                    call_visitor_t enclosing(cf, [&](cexpr_t* e) {
                        if (found != nullptr)
                            return;
                        if (e == nullptr)
                            return;
                        const ea_t target_ea = resolve_call_target_ea(e);
                        if (target_ea == BADADDR)
                            return;
                        if (ea_to_name.count(target_ea) == 0)
                            return;
                        if (e->ea == call_ea)
                            found = e;
                    });
                    enclosing.apply_to(&cf->body, nullptr);
                    if (found != nullptr)
                        fill_callsite_args(cf, found, cs);
                }
            }

            result.push_back(std::move(cs));
        }
    }

    std::sort(result.begin(), result.end(),
              [](const callsite_t& a, const callsite_t& b) {
                  if (a.func_ea != b.func_ea)
                      return a.func_ea < b.func_ea;
                  return a.call_ea < b.call_ea;
              });

    return result;
}

}

std::vector<callsite_t> all_calls_to(const std::vector<std::string>& target_names)
{
    if (target_names.empty())
        return {};
    auto callees = resolve_callee_eas(target_names);
    if (callees.empty())
        return {};
    return collect_calls_to_targets(callees);
}

std::vector<callsite_t> input_source_callsites()
{
    std::vector<std::string> names;
    names.reserve(sizeof(sig::INPUT_SOURCES) / sizeof(sig::INPUT_SOURCES[0]));
    for (const auto& s : sig::INPUT_SOURCES)
        names.emplace_back(s.name);
    return all_calls_to(names);
}

bool is_call_arg_literal(const cfunc_t& cf, ea_t call_ea, int arg_idx)
{
    if (call_ea == BADADDR || arg_idx < 0)
        return false;

    cfunc_t* mut = const_cast<cfunc_t*>(&cf);
    cexpr_t* found = nullptr;

    call_visitor_t visitor(mut, [&](cexpr_t* e) {
        if (found != nullptr)
            return;
        if (e == nullptr)
            return;
        if (e->ea == call_ea)
        {
            found = e;
        }
    });
    visitor.apply_to(&mut->body, nullptr);

    if (found == nullptr || found->a == nullptr)
        return false;
    if (static_cast<std::size_t>(arg_idx) >= found->a->size())
        return false;

    const carg_t& arg = (*found->a)[arg_idx];
    const cexpr_t* expr = static_cast<const cexpr_t*>(&arg);
    while (expr != nullptr && (expr->op == cot_cast || expr->op == cot_ref) && expr->x != nullptr)
        expr = expr->x;
    if (expr == nullptr)
        return false;

    if (expr->op == cot_str)
        return true;
    if (expr->op == cot_num)
        return true;
    if (expr->op == cot_obj)
    {
        if (obj_is_string_constant(expr->obj_ea))
            return true;
        if (ea_is_in_readonly_segment(expr->obj_ea))
            return true;
        return false;
    }
    return false;
}

namespace tools
{

namespace
{

inline int extract_int_param(const json& params, const std::string& key, int default_value)
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

inline std::string extract_string_param(const json& params, const std::string& key,
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

inline const char* cwe_name(int id)
{
    switch (id)
    {
    case 22:  return "Path Traversal";
    case 78:  return "OS Command Injection";
    case 120: return "Buffer Copy without Checking Size of Input";
    case 134: return "Use of Externally-Controlled Format String";
    case 242: return "Use of Inherently Dangerous Function";
    case 327: return "Use of a Broken or Risky Cryptographic Algorithm";
    case 328: return "Use of Weak Hash";
    case 770: return "Allocation of Resources Without Limits or Throttling";
    case 798: return "Use of Hard-coded Credentials";
    default:  return "Unknown CWE";
    }
}

inline severity_t default_severity_for_category(const std::string& category)
{
    if (category == "buffer_overflow")  return severity_t::high;
    if (category == "format_string")    return severity_t::high;
    if (category == "command_injection") return severity_t::high;
    if (category == "path_traversal")   return severity_t::medium;
    return severity_t::info;
}

inline std::string make_finding_id(const std::string& category, ea_t call_ea)
{
    std::ostringstream ss;
    ss << "vuln/" << category << "/" << std::hex << std::uppercase
       << static_cast<uint64_t>(call_ea);
    return ss.str();
}

inline json findings_to_json(const std::vector<vuln_finding_t>& findings)
{
    json arr = json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
}

inline std::string sink_set_signature(const std::vector<std::string>& names)
{
    std::ostringstream ss;
    ss << "rev=" << CACHE_SCHEMA_REVISION << ";n=";
    for (const auto& n : names)
        ss << n << "|";
    return ss.str();
}

inline ea_t cache_key_address(const std::string& signature)
{
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : signature)
    {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ull;
    }
    return static_cast<ea_t>(h);
}

inline std::optional<json> cache_lookup(const std::string& analysis_type, ea_t key_ea)
{
    const std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (hash.empty())
        return std::nullopt;
    auto entries = aida_db::AnalysisDB::instance().get_analysis(hash, key_ea);
    for (const auto& e : entries)
    {
        if (e.analysis_type == analysis_type && !e.result.empty())
        {
            try
            {
                return json::parse(e.result);
            }
            catch (...)
            {
                return std::nullopt;
            }
        }
    }
    return std::nullopt;
}

inline void cache_store(const std::string& analysis_type, ea_t key_ea, const json& payload)
{
    const std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (hash.empty())
        return;
    aida_db::analysis_entry_t entry;
    entry.address       = key_ea;
    entry.function_name.clear();
    entry.analysis_type = analysis_type;
    entry.result        = payload.dump();
    entry.model_name    = "static";
    entry.timestamp_ms  = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());
    aida_db::AnalysisDB::instance().add_analysis(hash, entry);
}

struct sink_with_category_t
{
    const sig::sink_signature_t* sink     = nullptr;
    std::string                  category;
};

inline std::vector<sink_with_category_t> resolve_buffer_overflow_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
        out.push_back({&s, "buffer_overflow"});
    return out;
}

inline std::vector<sink_with_category_t> resolve_command_injection_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
        out.push_back({&s, "command_injection"});
    return out;
}

inline std::vector<sink_with_category_t> resolve_path_traversal_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::PATH_TRAVERSAL_SINKS)
        out.push_back({&s, "path_traversal"});
    return out;
}

inline std::vector<sink_with_category_t> resolve_format_string_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
        out.push_back({&s, "format_string"});
    return out;
}

inline std::vector<sink_with_category_t> filter_sinks(const std::string& category)
{
    if (category == "buffer_overflow")
        return resolve_buffer_overflow_sinks();
    if (category == "command_injection")
        return resolve_command_injection_sinks();
    if (category == "path_traversal")
        return resolve_path_traversal_sinks();
    if (category == "format_string")
        return resolve_format_string_sinks();
    std::vector<sink_with_category_t> out;
    auto a = resolve_buffer_overflow_sinks();
    auto b = resolve_command_injection_sinks();
    auto c = resolve_path_traversal_sinks();
    auto d = resolve_format_string_sinks();
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    out.insert(out.end(), c.begin(), c.end());
    out.insert(out.end(), d.begin(), d.end());
    return out;
}

inline confidence_t derive_sink_confidence(const sig::sink_signature_t& sink, const callsite_t& cs)
{
    if (sink.len_arg_index >= 0 &&
        static_cast<std::size_t>(sink.len_arg_index) < cs.arg_is_literal.size() &&
        cs.arg_is_literal[sink.len_arg_index])
    {
        return confidence_t::plausible;
    }
    if (!cs.arg_is_literal.empty() && !cs.arg_is_literal[0])
        return confidence_t::likely;
    return confidence_t::plausible;
}

inline severity_t derive_sink_severity(const sig::sink_signature_t& sink,
                                       const callsite_t& cs,
                                       const std::string& category)
{
    severity_t base = default_severity_for_category(category);
    if (sink.len_arg_index >= 0 &&
        static_cast<std::size_t>(sink.len_arg_index) < cs.arg_is_literal.size() &&
        cs.arg_is_literal[sink.len_arg_index])
    {
        if (base == severity_t::high)
            return severity_t::medium;
        if (base == severity_t::medium)
            return severity_t::low;
    }
    return base;
}

inline json callsite_evidence(const callsite_t& cs)
{
    json ev;
    ev["call_ea"]    = static_cast<uint64_t>(cs.call_ea);
    ev["func_ea"]    = static_cast<uint64_t>(cs.func_ea);
    ev["callee"]     = cs.callee_name;
    ev["callsite"]   = to_json(cs);
    return ev;
}

inline std::string func_name_for(ea_t func_ea)
{
    qstring nm;
    if (get_func_name(&nm, func_ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    qstring vn;
    if (get_name(&vn, func_ea) > 0 && !vn.empty())
        return std::string(vn.c_str());
    std::ostringstream ss;
    ss << "sub_" << std::hex << std::uppercase << static_cast<uint64_t>(func_ea);
    return ss.str();
}

}

agent_tools::tool_result_t handle_find_vulnerable_sinks(const json& params)
{
    const std::string category = extract_string_param(params, "category", "all");
    const int limit_raw        = extract_int_param(params, "limit", 256);
    int limit = limit_raw;
    if (limit <= 0)
        return agent_tools::tool_result_t::error(OBFSTR("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    if (category != "all" && category != "buffer_overflow" && category != "command_injection" &&
        category != "path_traversal" && category != "format_string")
    {
        return agent_tools::tool_result_t::error(
            OBFSTR("category must be one of: all, buffer_overflow, command_injection, "
                   "path_traversal, format_string"));
    }

    auto sinks = filter_sinks(category);
    if (sinks.empty())
        return agent_tools::tool_result_t::error(OBFSTR("No sinks resolved for category"));

    std::vector<std::string> names;
    names.reserve(sinks.size());
    for (const auto& s : sinks)
        names.emplace_back(std::string(s.sink->name));

    const std::string analysis_type = "vuln_callsites_v1";
    const std::string sig_str       = sink_set_signature(names);
    const ea_t        cache_key     = cache_key_address(sig_str + "|cat=" + category);

    if (auto cached = cache_lookup(analysis_type, cache_key); cached.has_value() &&
        cached->is_object() && cached->contains("findings"))
    {
        json data = *cached;
        if (data.contains("findings") && data["findings"].is_array() &&
            data["findings"].size() > static_cast<std::size_t>(limit))
        {
            json trimmed = json::array();
            for (std::size_t i = 0; i < static_cast<std::size_t>(limit) &&
                 i < data["findings"].size(); ++i)
                trimmed.push_back(data["findings"][i]);
            data["findings"] = std::move(trimmed);
        }
        data["cached"] = true;
        const std::size_t count = data.value("count", static_cast<std::size_t>(0));
        std::ostringstream msg;
        msg << OBFSTR("Vulnerable-sink scan (cached): ") << count << OBFSTR(" finding(s)");
        return agent_tools::tool_result_t::ok(msg.str(), data);
    }

    std::vector<vuln_finding_t> findings;
    findings.reserve(64);
    std::unordered_map<std::string, std::size_t> by_category;
    by_category["buffer_overflow"]   = 0;
    by_category["command_injection"] = 0;
    by_category["path_traversal"]    = 0;
    by_category["format_string"]     = 0;

    for (const auto& sk : sinks)
    {
        if (findings.size() >= static_cast<std::size_t>(limit))
            break;
        const std::string sink_name(sk.sink->name);
        std::vector<callsite_t> calls = all_calls_to({sink_name});
        if (calls.empty())
            continue;
        for (const auto& cs : calls)
        {
            if (findings.size() >= static_cast<std::size_t>(limit))
                break;
            vuln_finding_t f;
            f.id         = make_finding_id(sk.category, cs.call_ea);
            f.primary_ea = cs.call_ea;
            f.related_eas.push_back(cs.func_ea);
            cwe_t cwe;
            cwe.id   = sk.sink->primary_cwe;
            cwe.name = cwe_name(sk.sink->primary_cwe);
            f.cwes.push_back(cwe);
            f.severity   = derive_sink_severity(*sk.sink, cs, sk.category);
            f.confidence = derive_sink_confidence(*sk.sink, cs);

            std::ostringstream title;
            title << "Dangerous call to " << sink_name << " in " << func_name_for(cs.func_ea);
            f.title = title.str();

            std::ostringstream rat;
            rat << "Call to " << sink_name << " (CWE-" << sk.sink->primary_cwe << ", "
                << cwe.name << ") at "
                << agent_tools::helpers::format_address(cs.call_ea)
                << " inside " << func_name_for(cs.func_ea);
            if (sk.sink->len_arg_index >= 0 &&
                static_cast<std::size_t>(sk.sink->len_arg_index) < cs.arg_summaries.size())
            {
                rat << "; length argument [" << sk.sink->len_arg_index << "] = "
                    << cs.arg_summaries[sk.sink->len_arg_index];
                if (sk.sink->len_arg_index < static_cast<int>(cs.arg_is_literal.size()) &&
                    cs.arg_is_literal[sk.sink->len_arg_index])
                {
                    rat << " (literal)";
                }
                else
                {
                    rat << " (non-literal, may be attacker-controlled)";
                }
            }
            f.rationale = rat.str();
            f.evidence  = callsite_evidence(cs);
            f.evidence["category"] = sk.category;
            findings.push_back(std::move(f));
            by_category[sk.category] += 1;
        }
    }

    json data;
    data["count"]    = findings.size();
    data["limit"]    = limit;
    data["category"] = category;
    data["findings"] = findings_to_json(findings);
    json bc = json::object();
    for (const auto& kv : by_category)
        bc[kv.first] = kv.second;
    data["by_category"] = std::move(bc);
    data["cached"]      = false;

    cache_store(analysis_type, cache_key, data);

    std::ostringstream msg;
    msg << OBFSTR("Vulnerable-sink scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_input_sources(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(OBFSTR("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    std::vector<callsite_t> calls = input_source_callsites();

    std::unordered_map<std::string, std::size_t> by_source;
    json arr = json::array();
    int emitted = 0;
    for (const auto& cs : calls)
    {
        if (emitted >= limit)
            break;
        json entry = to_json(cs);
        entry["caller_name"] = func_name_for(cs.func_ea);
        arr.push_back(std::move(entry));
        by_source[cs.callee_name] += 1;
        ++emitted;
    }

    json data;
    data["count"]      = arr.size();
    data["limit"]      = limit;
    data["callsites"]  = std::move(arr);
    data["total_unique_calls"] = calls.size();
    json bs = json::object();
    for (const auto& kv : by_source)
        bs[kv.first] = kv.second;
    data["by_source"] = std::move(bs);

    std::ostringstream msg;
    msg << OBFSTR("Input-source enumeration: ") << data["count"].get<std::size_t>()
        << OBFSTR(" callsite(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_format_string_bugs(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(OBFSTR("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    if (!init_hexrays_plugin())
        return agent_tools::tool_result_t::error(OBFSTR("Hex-Rays not available"));

    std::vector<vuln_finding_t> findings;
    decompile_cache_t cache;

    for (const auto& fs : sig::FORMAT_STRING_FUNCS)
    {
        if (findings.size() >= static_cast<std::size_t>(limit))
            break;
        const std::string sink_name(fs.name);
        std::vector<callsite_t> calls = all_calls_to({sink_name});
        for (const auto& cs : calls)
        {
            if (findings.size() >= static_cast<std::size_t>(limit))
                break;
            cfunc_t* cf = cache.fetch(cs.func_ea);
            if (cf == nullptr)
                continue;
            const bool literal = is_call_arg_literal(*cf, cs.call_ea, fs.format_arg_index);
            if (literal)
                continue;

            vuln_finding_t f;
            f.id         = make_finding_id("format_string", cs.call_ea);
            f.primary_ea = cs.call_ea;
            f.related_eas.push_back(cs.func_ea);
            cwe_t cwe;
            cwe.id   = fs.primary_cwe;
            cwe.name = cwe_name(fs.primary_cwe);
            f.cwes.push_back(cwe);
            f.severity   = severity_t::high;
            f.confidence = confidence_t::likely;

            std::ostringstream title;
            title << "Non-literal format string passed to " << sink_name
                  << " in " << func_name_for(cs.func_ea);
            f.title = title.str();

            std::ostringstream rat;
            rat << "Call to " << sink_name << " at "
                << agent_tools::helpers::format_address(cs.call_ea)
                << " uses a non-literal value as the format-string argument (index "
                << fs.format_arg_index << "). When that value is attacker-controlled this "
                << "yields an arbitrary read/write primitive (CWE-134).";
            f.rationale = rat.str();
            f.evidence  = callsite_evidence(cs);
            f.evidence["format_arg_index"] = fs.format_arg_index;
            if (static_cast<std::size_t>(fs.format_arg_index) < cs.arg_summaries.size())
                f.evidence["format_arg_summary"] = cs.arg_summaries[fs.format_arg_index];
            f.evidence["category"] = "format_string";

            findings.push_back(std::move(f));
        }
    }

    json data;
    data["count"]    = findings.size();
    data["limit"]    = limit;
    data["findings"] = findings_to_json(findings);
    data["primary_cwe"] = 134;

    std::ostringstream msg;
    msg << OBFSTR("Format-string-bug scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

inline int sensitive_arg_index_for(const std::string& sink_name)
{
    if (sink_name == "CreateProcessA" || sink_name == "CreateProcessW" ||
        sink_name == "CreateProcessAsUserA" || sink_name == "CreateProcessAsUserW")
        return 1;
    if (sink_name == "ShellExecuteA" || sink_name == "ShellExecuteW")
        return 2;
    if (sink_name == "ShellExecuteExA" || sink_name == "ShellExecuteExW")
        return -1;
    return 0;
}

inline std::vector<vuln_finding_t> scan_dangerous_sinks(const std::vector<sink_with_category_t>& sinks,
                                                       const std::string& category_label,
                                                       severity_t default_severity,
                                                       std::size_t limit)
{
    std::vector<vuln_finding_t> findings;
    findings.reserve(64);

    for (const auto& sk : sinks)
    {
        if (findings.size() >= limit)
            break;
        const std::string sink_name(sk.sink->name);
        const int arg_idx = sensitive_arg_index_for(sink_name);
        std::vector<callsite_t> calls = all_calls_to({sink_name});
        for (const auto& cs : calls)
        {
            if (findings.size() >= limit)
                break;
            vuln_finding_t f;
            f.id         = make_finding_id(category_label, cs.call_ea);
            f.primary_ea = cs.call_ea;
            f.related_eas.push_back(cs.func_ea);
            cwe_t cwe;
            cwe.id   = sk.sink->primary_cwe;
            cwe.name = cwe_name(sk.sink->primary_cwe);
            f.cwes.push_back(cwe);
            f.severity   = default_severity;
            f.confidence = confidence_t::plausible;

            bool sensitive_is_literal = false;
            std::string sensitive_summary;
            if (arg_idx >= 0 && static_cast<std::size_t>(arg_idx) < cs.arg_is_literal.size())
            {
                sensitive_is_literal = cs.arg_is_literal[arg_idx];
                if (static_cast<std::size_t>(arg_idx) < cs.arg_summaries.size())
                    sensitive_summary = cs.arg_summaries[arg_idx];
                if (!sensitive_is_literal)
                    f.confidence = confidence_t::likely;
                else
                    f.severity = severity_t::low;
            }

            std::ostringstream title;
            title << "Call to " << sink_name << " in " << func_name_for(cs.func_ea);
            f.title = title.str();

            std::ostringstream rat;
            rat << "Call to " << sink_name << " (CWE-" << sk.sink->primary_cwe << ", "
                << cwe.name << ") at "
                << agent_tools::helpers::format_address(cs.call_ea)
                << " inside " << func_name_for(cs.func_ea);
            if (arg_idx >= 0)
            {
                rat << "; sensitive argument [" << arg_idx << "] = " << sensitive_summary;
                rat << (sensitive_is_literal ? " (literal)" : " (non-literal, may be attacker-controlled)");
            }
            f.rationale = rat.str();
            f.evidence  = callsite_evidence(cs);
            f.evidence["category"] = category_label;
            f.evidence["sensitive_arg_index"] = arg_idx;
            f.evidence["sensitive_arg_is_literal"] = sensitive_is_literal;

            findings.push_back(std::move(f));
        }
    }

    return findings;
}

}

agent_tools::tool_result_t handle_find_command_injection_sites(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(OBFSTR("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    auto sinks = resolve_command_injection_sinks();
    auto findings = scan_dangerous_sinks(sinks, "command_injection",
                                         severity_t::high,
                                         static_cast<std::size_t>(limit));

    json data;
    data["count"]       = findings.size();
    data["limit"]       = limit;
    data["findings"]    = findings_to_json(findings);
    data["primary_cwe"] = 78;

    std::ostringstream msg;
    msg << OBFSTR("Command-injection scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_path_traversal_sites(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(OBFSTR("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    auto sinks = resolve_path_traversal_sinks();
    auto findings = scan_dangerous_sinks(sinks, "path_traversal",
                                         severity_t::medium,
                                         static_cast<std::size_t>(limit));

    json data;
    data["count"]       = findings.size();
    data["limit"]       = limit;
    data["findings"]    = findings_to_json(findings);
    data["primary_cwe"] = 22;

    std::ostringstream msg;
    msg << OBFSTR("Path-traversal scan: ") << findings.size() << OBFSTR(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

void register_tier1_callsite_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    {
        agent_tools::tool_param_t category_param;
        category_param.name        = OBFSTR("category");
        category_param.type        = OBFSTR("string");
        category_param.description = OBFSTR("Sink category to enumerate. One of: all, "
                                            "buffer_overflow, command_injection, path_traversal, "
                                            "format_string. Defaults to all.");
        category_param.required    = false;
        category_param.enum_values = {
            OBFSTR("all"),
            OBFSTR("buffer_overflow"),
            OBFSTR("command_injection"),
            OBFSTR("path_traversal"),
            OBFSTR("format_string"),
        };
        agent_tools::tool_param_t limit_param;
        limit_param.name        = OBFSTR("limit");
        limit_param.type        = OBFSTR("number");
        limit_param.description = OBFSTR("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            OBFSTR("find_vulnerable_sinks"),
            OBFSTR("vuln"),
            OBFSTR("Enumerate calls to known dangerous sink functions across the binary. "
                   "Categories cover buffer overflow (strcpy/memcpy/sprintf/...), command injection "
                   "(system/exec*/CreateProcess/ShellExecute/...), path traversal (fopen/CreateFile/...), "
                   "and format-string sinks (printf/sprintf/...). Each finding records the caller, "
                   "callsite EA, summarized arguments, CWE, severity, and confidence."),
            { category_param, limit_param },
            handle_find_vulnerable_sinks,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = OBFSTR("limit");
        limit_param.type        = OBFSTR("number");
        limit_param.description = OBFSTR("Maximum number of callsites to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            OBFSTR("find_input_sources"),
            OBFSTR("vuln"),
            OBFSTR("Enumerate callsites for known input-source functions (recv/recvfrom, ReadFile, "
                   "fread/fgets, scanf-family, getenv, GetCommandLine, RegQueryValueEx, "
                   "WinHttpReadData, etc.). These are the canonical taint origins for downstream "
                   "taint analysis."),
            { limit_param },
            handle_find_input_sources,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = OBFSTR("limit");
        limit_param.type        = OBFSTR("number");
        limit_param.description = OBFSTR("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            OBFSTR("find_format_string_bugs"),
            OBFSTR("vuln"),
            OBFSTR("Locate format-string vulnerabilities (CWE-134) by decompiling each caller of a "
                   "printf-family sink and confirming that the format-string argument at the "
                   "documented position is NOT a literal. Findings are emitted with severity=high "
                   "and confidence=likely."),
            { limit_param },
            handle_find_format_string_bugs,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = OBFSTR("limit");
        limit_param.type        = OBFSTR("number");
        limit_param.description = OBFSTR("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            OBFSTR("find_command_injection_sites"),
            OBFSTR("vuln"),
            OBFSTR("Locate command-execution callsites (system/_wsystem/popen/exec*/CreateProcess*/"
                   "ShellExecute*/WinExec) and classify whether the command-line / file argument at "
                   "the documented position is a literal or a non-literal (likely attacker-influenced) "
                   "value. CWE-78."),
            { limit_param },
            handle_find_command_injection_sites,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = OBFSTR("limit");
        limit_param.type        = OBFSTR("number");
        limit_param.description = OBFSTR("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            OBFSTR("find_path_traversal_sites"),
            OBFSTR("vuln"),
            OBFSTR("Locate filesystem-API callsites (fopen/_wfopen/open/CreateFile*/Move/Copy/Delete) "
                   "and classify whether the path argument at the documented position is a literal "
                   "or a non-literal (likely attacker-influenced) value. CWE-22."),
            { limit_param },
            handle_find_path_traversal_sites,
            true,
        });
    }
}

}

}
}
}
