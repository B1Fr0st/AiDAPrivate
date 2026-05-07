#include "../aida_pro.hpp"

#include "verification_engine.hpp"

#include "microcode_engine.hpp"
#include "smt_solver.hpp"
#include "symbolic_engine.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <funcs.hpp>
#include <hexrays.hpp>

namespace aida
{
namespace vuln
{
namespace verify
{

namespace
{

constexpr int    k_default_bv_width = 64;
constexpr size_t k_max_inputs_in_summary = 16;

const std::unordered_set<std::string>& smt_keyword_set()
{
    static const std::unordered_set<std::string> keywords = {
        "_", "as", "let", "forall", "exists", "match", "par",
        "and", "or", "xor", "not", "ite", "implies", "iff",
        "true", "false", "BitVec", "Bool", "Int", "Real", "Array",
        "bvadd", "bvsub", "bvmul", "bvudiv", "bvurem", "bvsdiv",
        "bvsrem", "bvsmod", "bvshl", "bvlshr", "bvashr",
        "bvand", "bvor", "bvxor", "bvnand", "bvnor", "bvxnor",
        "bvnot", "bvneg", "bvcomp",
        "bvult", "bvule", "bvugt", "bvuge",
        "bvslt", "bvsle", "bvsgt", "bvsge",
        "concat", "extract", "zero_extend", "sign_extend",
        "rotate_left", "rotate_right", "repeat",
        "select", "store",
        "distinct", "=", "=>",
        "assert", "check-sat", "get-model", "get-value",
        "declare-fun", "declare-const", "define-fun", "set-logic",
        "set-option", "push", "pop", "reset", "exit",
        "to_int", "to_real", "is_int"
    };
    return keywords;
}

bool is_identifier_start(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    return (uc >= 'A' && uc <= 'Z') ||
           (uc >= 'a' && uc <= 'z') ||
           uc == '_';
}

bool is_identifier_continue(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    return is_identifier_start(c) ||
           (uc >= '0' && uc <= '9') ||
           uc == '!' || uc == '.' || uc == '@' || uc == '$';
}

bool is_numeric_token(const std::string& tok)
{
    if (tok.empty())
        return false;
    for (char c : tok)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!(uc >= '0' && uc <= '9'))
            return false;
    }
    return true;
}

int detect_width_from_text(const std::string& text, const std::string& var)
{
    int detected = 0;
    const std::string ext_prefix = "((_ extract ";
    size_t pos = 0;
    while ((pos = text.find(ext_prefix, pos)) != std::string::npos)
    {
        size_t cursor = pos + ext_prefix.size();
        size_t end_high = cursor;
        while (end_high < text.size() && std::isdigit(static_cast<unsigned char>(text[end_high])))
            ++end_high;
        if (end_high == cursor || end_high >= text.size() || text[end_high] != ' ')
        {
            ++pos;
            continue;
        }
        int high = std::atoi(text.substr(cursor, end_high - cursor).c_str());
        size_t low_start = end_high + 1;
        size_t low_end = low_start;
        while (low_end < text.size() && std::isdigit(static_cast<unsigned char>(text[low_end])))
            ++low_end;
        if (low_end == low_start || low_end >= text.size() || text[low_end] != ')')
        {
            ++pos;
            continue;
        }
        size_t inner_start = text.find(' ', low_end + 1);
        if (inner_start == std::string::npos)
        {
            ++pos;
            continue;
        }
        size_t name_start = inner_start + 1;
        while (name_start < text.size() && std::isspace(static_cast<unsigned char>(text[name_start])))
            ++name_start;
        if (name_start + var.size() <= text.size() &&
            text.compare(name_start, var.size(), var) == 0)
        {
            char after = name_start + var.size() < text.size() ? text[name_start + var.size()] : ')';
            if (!is_identifier_continue(after))
            {
                int width = high + 1;
                if (width > detected)
                    detected = width;
            }
        }
        pos = end_high;
    }
    return detected;
}

std::vector<std::string> tokenize_identifiers(const std::string& text)
{
    std::vector<std::string> out;
    out.reserve(16);
    std::set<std::string> seen;
    const auto& keywords = smt_keyword_set();
    const size_t n = text.size();
    for (size_t i = 0; i < n;)
    {
        char c = text[i];
        if (c == ';')
        {
            while (i < n && text[i] != '\n')
                ++i;
            continue;
        }
        if (c == '|')
        {
            size_t end = text.find('|', i + 1);
            if (end == std::string::npos)
                break;
            std::string name = text.substr(i + 1, end - i - 1);
            if (!name.empty() && seen.insert(name).second)
                out.push_back(std::move(name));
            i = end + 1;
            continue;
        }
        if (is_identifier_start(c))
        {
            size_t start = i;
            ++i;
            while (i < n && is_identifier_continue(text[i]))
                ++i;
            std::string tok = text.substr(start, i - start);
            if (keywords.find(tok) != keywords.end())
                continue;
            if (is_numeric_token(tok))
                continue;
            if (tok.size() >= 2 && tok[0] == 'b' && tok[1] == 'v')
            {
                bool all_digits_after = tok.size() > 2;
                for (size_t k = 2; k < tok.size() && all_digits_after; ++k)
                {
                    unsigned char uc = static_cast<unsigned char>(tok[k]);
                    if (!(uc >= '0' && uc <= '9'))
                        all_digits_after = false;
                }
                if (all_digits_after)
                    continue;
            }
            if (seen.insert(tok).second)
                out.push_back(std::move(tok));
            continue;
        }
        ++i;
    }
    return out;
}

bool name_looks_like_input(const std::string& name)
{
    if (name.size() >= 4 && name.compare(0, 4, "lvar") == 0)
        return true;
    if (name.size() >= 5 && name.compare(0, 5, "param") == 0)
        return true;
    if (name.size() >= 5 && name.compare(0, 5, "input") == 0)
        return true;
    if (name.size() >= 3 && name.compare(0, 3, "arg") == 0)
        return true;
    if (name.size() >= 3 && name.compare(0, 3, "reg") == 0)
        return true;
    if (name.size() >= 3 && name.compare(0, 3, "stk") == 0)
        return true;
    return false;
}

std::string format_hex64(uint64_t v)
{
    char buf[24];
    ::qsnprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

void append_concrete_bytes_le(std::vector<uint8_t>& dst, uint64_t value, int width_bits)
{
    int width_bytes = width_bits / 8;
    if (width_bytes <= 0)
        width_bytes = 1;
    if (width_bytes > 8)
        width_bytes = 8;
    for (int b = 0; b < width_bytes; ++b)
    {
        dst.push_back(static_cast<uint8_t>((value >> (b * 8)) & 0xFFu));
    }
}

std::string ensure_assertion(const std::string& predicate, bool negate)
{
    std::string trimmed;
    trimmed.reserve(predicate.size());
    size_t start = 0;
    while (start < predicate.size() && std::isspace(static_cast<unsigned char>(predicate[start])))
        ++start;
    size_t end = predicate.size();
    while (end > start && std::isspace(static_cast<unsigned char>(predicate[end - 1])))
        --end;
    trimmed.assign(predicate, start, end - start);
    if (trimmed.empty())
        trimmed = "true";
    std::ostringstream ss;
    ss << "(assert ";
    if (negate)
        ss << "(not " << trimmed << ")";
    else
        ss << trimmed;
    ss << ")";
    return ss.str();
}

bool emit_declarations(smt::SmtContext& smt,
                       const std::vector<symbolic::path_constraint_t>& constraints,
                       std::unordered_map<std::string, int>& declared_widths)
{
    if (!smt.is_available())
        return false;
    std::unordered_map<std::string, int> wanted;
    for (const auto& c : constraints)
    {
        const std::string& text = c.predicate_smt2;
        auto names = tokenize_identifiers(text);
        for (const auto& n : names)
        {
            int w = detect_width_from_text(text, n);
            if (w <= 0)
                w = k_default_bv_width;
            auto it = wanted.find(n);
            if (it == wanted.end() || w > it->second)
                wanted[n] = w;
        }
    }
    for (const auto& kv : wanted)
    {
        if (kv.second <= 0 || kv.second > 4096)
            continue;
        if (!smt.declare_bv(kv.first, kv.second))
        {
            continue;
        }
        declared_widths[kv.first] = kv.second;
    }
    return true;
}

bool assert_constraints(smt::SmtContext& smt,
                        const std::vector<symbolic::path_constraint_t>& constraints,
                        std::string& failure_reason)
{
    failure_reason.clear();
    for (const auto& c : constraints)
    {
        if (c.predicate_smt2.empty() || c.predicate_smt2.find("<smt-error>") != std::string::npos)
            continue;
        std::string formula = ensure_assertion(c.predicate_smt2, false);
        if (!smt.assert_smtlib2(formula))
        {
            const char* err = smt.last_error();
            if (failure_reason.empty())
            {
                failure_reason = err != nullptr ? std::string(err) : std::string("unknown assert failure");
            }
        }
    }
    return failure_reason.empty();
}

bool block_has_back_edge(const mba_t& mba, const mblock_t& blk)
{
    for (size_t i = 0; i < blk.succset.size(); ++i)
    {
        int succ = blk.succset[i];
        if (succ <= blk.serial)
        {
            const mblock_t* dst = mba.get_mblock(static_cast<uint>(succ));
            if (dst != nullptr)
                return true;
        }
    }
    return false;
}

bool function_has_loop(const mba_t& mba)
{
    for (int i = 0; i < mba.qty; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        if (block_has_back_edge(mba, *blk))
            return true;
    }
    return false;
}

bool find_induction_lvar(mba_t& mba, int& out_idx, int& out_width_bits)
{
    out_idx = -1;
    out_width_bits = 0;
    for (size_t v = 0; v < mba.vars.size(); ++v)
    {
        auto chain = aida::vuln::microcode::def_use_chain_for_lvar(mba, static_cast<int>(v));
        if (chain.defs.empty() || chain.uses.empty())
            continue;
        bool def_in_back_edge_block = false;
        for (ea_t def_ea : chain.defs)
        {
            for (int b = 0; b < mba.qty; ++b)
            {
                const mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
                if (blk == nullptr)
                    continue;
                bool covers = false;
                for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
                {
                    if (m->ea == def_ea)
                    {
                        covers = true;
                        break;
                    }
                }
                if (!covers && def_ea >= blk->start && def_ea < blk->end)
                    covers = true;
                if (covers && block_has_back_edge(mba, *blk))
                {
                    def_in_back_edge_block = true;
                    break;
                }
            }
            if (def_in_back_edge_block)
                break;
        }
        if (!def_in_back_edge_block)
            continue;
        const lvar_t& lv = mba.vars[v];
        int w = lv.width > 0 ? lv.width : 4;
        if (w > 8)
            w = 8;
        out_idx = static_cast<int>(v);
        out_width_bits = w * 8;
        return true;
    }
    return false;
}

}

struct VerificationEngine::impl_t
{
    aida::vuln::symbolic::SymbolicEngine        sym;
    aida::vuln::smt::SmtContext                 smt;
    std::string                                 last_err;
    mutable std::mutex                          mu;
    std::unordered_map<std::string, int>        verdict_counts;

    impl_t() = default;

    void bump_verdict(verdict_t v)
    {
        std::lock_guard<std::mutex> lk(mu);
        verdict_counts[verdict_str(v)] += 1;
    }
};

VerificationEngine::VerificationEngine()
    : m_impl(std::make_unique<impl_t>())
{
    if (!m_impl)
        return;
    if (!m_impl->sym.is_available())
    {
        const char* e = m_impl->sym.last_error();
        m_impl->last_err = e != nullptr && *e ? std::string("symbolic: ") + e
                                              : std::string("symbolic engine unavailable");
    }
    if (!m_impl->smt.is_available())
    {
        const char* e = m_impl->smt.last_error();
        if (!m_impl->last_err.empty())
            m_impl->last_err.append("; ");
        m_impl->last_err.append(e != nullptr && *e ? std::string("smt: ") + e
                                                   : std::string("smt context unavailable"));
    }
}

VerificationEngine::~VerificationEngine() = default;

bool VerificationEngine::is_available() const
{
    if (!m_impl)
        return false;
    return m_impl->sym.is_available() && m_impl->smt.is_available();
}

const char* VerificationEngine::last_error() const
{
    if (!m_impl)
        return "";
    return m_impl->last_err.c_str();
}

path_verification_t VerificationEngine::verify_taint_path(ea_t source_ea,
                                                          ea_t sink_ea,
                                                          uint32_t timeout_ms)
{
    (void)source_ea;
    path_verification_t out;
    if (!m_impl)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "verification engine not initialized";
        return out;
    }
    if (!is_available())
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = m_impl->last_err.empty() ? std::string("z3/triton unavailable") : m_impl->last_err;
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    func_t* pfn = get_func(sink_ea);
    if (pfn == nullptr)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "no enclosing function for sink";
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.verdict = verdict_t::unsupported;
        const char* e = m_impl->sym.last_error();
        out.rationale = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                           : std::string("symbolic load failed");
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    out.constraints = m_impl->sym.collect_path_to(sink_ea, 64);

    if (out.constraints.empty())
    {
        out.verdict = verdict_t::confirmed;
        out.smt_result = smt::result_t::sat;
        out.adjusted_confidence = confidence_t::likely;
        out.rationale = "no path constraints; sink reachable unconditionally";
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    smt::SmtContext local;
    if (!local.is_available())
    {
        out.verdict = verdict_t::unsupported;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                           : std::string("smt unavailable");
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    std::unordered_map<std::string, int> declared;
    emit_declarations(local, out.constraints, declared);

    std::string assert_err;
    assert_constraints(local, out.constraints, assert_err);

    auto t0 = std::chrono::steady_clock::now();
    smt::solve_result_t r = local.check_with_timeout(timeout_ms);
    auto t1 = std::chrono::steady_clock::now();
    out.solve_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    if (out.solve_ms == 0 && r.solve_ms > 0)
        out.solve_ms = r.solve_ms;

    out.smt_result = r.result;
    switch (r.result)
    {
    case smt::result_t::sat:
        out.verdict = verdict_t::confirmed;
        out.adjusted_confidence = confidence_t::confirmed;
        out.witness = r.model;
        {
            std::ostringstream rs;
            rs << "path satisfiable; model has " << r.model.size() << " variable(s)";
            if (!assert_err.empty())
                rs << "; partial constraints: " << assert_err;
            out.rationale = rs.str();
        }
        break;
    case smt::result_t::unsat:
        out.verdict = verdict_t::refuted;
        out.adjusted_confidence = confidence_t::speculative;
        out.rationale = "path unsatisfiable; finding is a ghost / dead-code";
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        break;
    case smt::result_t::unknown:
    default:
        if (r.reason.find("timeout") != std::string::npos ||
            r.reason.find("canceled") != std::string::npos)
        {
            out.verdict = verdict_t::timeout;
            out.rationale = "z3 timeout reached";
        }
        else
        {
            out.verdict = verdict_t::inconclusive;
            out.rationale = r.reason.empty() ? std::string("solver returned unknown") : r.reason;
        }
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        break;
    }

    m_impl->bump_verdict(out.verdict);
    return out;
}

exploit_input_t VerificationEngine::solve_for_exploit_input(ea_t source_ea,
                                                            ea_t sink_ea,
                                                            uint32_t timeout_ms)
{
    (void)source_ea;
    exploit_input_t out;
    if (!m_impl)
    {
        out.found = false;
        out.rationale = "verification engine not initialized";
        return out;
    }
    if (!is_available())
    {
        out.found = false;
        out.rationale = m_impl->last_err.empty() ? std::string("z3/triton unavailable") : m_impl->last_err;
        return out;
    }

    func_t* pfn = get_func(sink_ea);
    if (pfn == nullptr)
    {
        out.found = false;
        out.rationale = "no enclosing function for sink";
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.found = false;
        const char* e = m_impl->sym.last_error();
        out.rationale = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                           : std::string("symbolic load failed");
        return out;
    }

    auto constraints = m_impl->sym.collect_path_to(sink_ea, 64);

    smt::SmtContext local;
    if (!local.is_available())
    {
        out.found = false;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                           : std::string("smt unavailable");
        return out;
    }

    std::unordered_map<std::string, int> declared;
    emit_declarations(local, constraints, declared);

    std::string assert_err;
    assert_constraints(local, constraints, assert_err);

    smt::solve_result_t r = local.check_with_timeout(timeout_ms);

    if (r.result != smt::result_t::sat)
    {
        out.found = false;
        if (r.result == smt::result_t::unsat)
            out.rationale = "path unsatisfiable; no exploit input exists for this path";
        else if (r.reason.find("timeout") != std::string::npos)
            out.rationale = "solver timeout while searching for exploit input";
        else
            out.rationale = r.reason.empty() ? std::string("solver returned unknown") : r.reason;
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        return out;
    }

    out.found = true;
    out.inputs = r.model;

    std::vector<const smt::model_entry_t*> input_entries;
    input_entries.reserve(out.inputs.size());
    for (const auto& m : out.inputs)
    {
        if (!m.is_bitvector)
            continue;
        if (name_looks_like_input(m.name))
            input_entries.push_back(&m);
    }
    if (input_entries.empty())
    {
        for (const auto& m : out.inputs)
        {
            if (m.is_bitvector)
                input_entries.push_back(&m);
        }
    }

    std::sort(input_entries.begin(), input_entries.end(),
              [](const smt::model_entry_t* a, const smt::model_entry_t* b) {
                  return a->name < b->name;
              });

    std::ostringstream trigger;
    trigger << "Trigger: ";
    size_t emitted = 0;
    for (const smt::model_entry_t* m : input_entries)
    {
        if (emitted >= k_max_inputs_in_summary)
        {
            trigger << ", ...";
            break;
        }
        if (emitted > 0)
            trigger << ", ";
        trigger << m->name << " = " << format_hex64(m->bv_value);
        if (m->bv_width > 0)
            trigger << " (" << m->bv_width << "b)";
        ++emitted;
    }
    if (input_entries.empty())
        trigger << "<no concrete inputs in model>";

    for (const smt::model_entry_t* m : input_entries)
    {
        int width = m->bv_width > 0 ? m->bv_width : 64;
        append_concrete_bytes_le(out.concrete_bytes, m->bv_value, width);
    }

    std::ostringstream bytes_str;
    bytes_str << ". Concrete bytes (little-endian):";
    if (out.concrete_bytes.empty())
    {
        bytes_str << " <none>";
    }
    else
    {
        char hex_buf[4];
        for (uint8_t b : out.concrete_bytes)
        {
            ::qsnprintf(hex_buf, sizeof(hex_buf), " %02x", b);
            bytes_str << hex_buf;
        }
    }

    out.summary = trigger.str() + bytes_str.str();
    std::ostringstream rs;
    rs << "z3 produced satisfying assignment in " << r.solve_ms << " ms with "
       << input_entries.size() << " input variable(s)";
    if (!assert_err.empty())
        rs << "; partial constraints: " << assert_err;
    out.rationale = rs.str();
    return out;
}

loop_bound_proof_t VerificationEngine::prove_loop_bound(ea_t loop_func_ea,
                                                        int64_t buffer_size,
                                                        uint32_t timeout_ms)
{
    loop_bound_proof_t out;
    out.buffer_size = buffer_size;

    if (!m_impl || !is_available())
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.rationale.empty())
            out.rationale = "z3/triton unavailable";
        return out;
    }

    func_t* pfn = get_func(loop_func_ea);
    if (pfn == nullptr)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "no enclosing function";
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.verdict = verdict_t::unsupported;
        const char* e = m_impl->sym.last_error();
        out.rationale = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                           : std::string("symbolic load failed");
        return out;
    }

    auto handle_opt = aida::vuln::microcode::generate(pfn->start_ea, MMAT_LVARS);
    if (!handle_opt.has_value() || handle_opt->mba.get() == nullptr)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "could not generate microcode for loop function";
        return out;
    }
    mba_t* mba_ptr = handle_opt->mba.get();

    if (!function_has_loop(*mba_ptr))
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "no back-edge / loop in CFG";
        return out;
    }

    int induction_idx = -1;
    int induction_width_bits = 0;
    if (!find_induction_lvar(*mba_ptr, induction_idx, induction_width_bits))
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "could not identify loop induction variable";
        return out;
    }
    if (induction_width_bits <= 0 || induction_width_bits > 64)
        induction_width_bits = 32;

    std::ostringstream var_name_ss;
    if (induction_idx >= 0 && static_cast<size_t>(induction_idx) < mba_ptr->vars.size())
    {
        const lvar_t& lv = mba_ptr->vars[induction_idx];
        if (!lv.name.empty())
            var_name_ss << "lvar_" << lv.name.c_str() << "_" << induction_idx;
        else
            var_name_ss << "lvar_" << induction_idx;
    }
    else
    {
        var_name_ss << "lvar_" << induction_idx;
    }
    std::string ind_name = var_name_ss.str();

    smt::SmtContext local;
    if (!local.is_available())
    {
        out.verdict = verdict_t::unsupported;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                           : std::string("smt unavailable");
        return out;
    }

    if (!local.declare_bv(ind_name, induction_width_bits))
    {
        out.verdict = verdict_t::unsupported;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("declare failed: ") + e
                                           : std::string("declare failed");
        return out;
    }

    auto last_constraints = m_impl->sym.all_path_constraints(64);
    std::unordered_map<std::string, int> declared;
    emit_declarations(local, last_constraints, declared);
    std::string assert_err;
    assert_constraints(local, last_constraints, assert_err);

    if (buffer_size > 0)
    {
        const uint64_t mask = induction_width_bits >= 64 ? ~static_cast<uint64_t>(0)
                                                         : ((static_cast<uint64_t>(1) << induction_width_bits) - 1u);
        uint64_t bound = static_cast<uint64_t>(buffer_size);
        if (bound > mask)
            bound = mask;
        std::ostringstream upper;
        upper << "(assert (bvule " << ind_name << " (_ bv" << bound << " " << induction_width_bits << ")))";
        local.assert_smtlib2(upper.str());
    }

    (void)timeout_ms;
    auto max_opt = local.max_value_bv(ind_name, induction_width_bits);
    auto min_opt = local.min_value_bv(ind_name, induction_width_bits);

    if (!max_opt.has_value())
    {
        out.verdict = verdict_t::inconclusive;
        out.rationale = "could not derive max index for induction variable";
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        return out;
    }

    out.max_index = static_cast<int64_t>(*max_opt);
    out.min_index = min_opt.has_value() ? static_cast<int64_t>(*min_opt) : 0;

    if (buffer_size > 0 && out.max_index >= buffer_size)
    {
        out.overflow_provable = true;
        out.verdict = verdict_t::confirmed;
        std::ostringstream rs;
        rs << "induction var " << ind_name << " can reach " << out.max_index
           << " (>= buffer_size " << buffer_size << "); overflow provable";
        out.rationale = rs.str();
    }
    else if (buffer_size > 0)
    {
        out.overflow_provable = false;
        out.verdict = verdict_t::refuted;
        std::ostringstream rs;
        rs << "induction var " << ind_name << " bounded to [" << out.min_index << ", "
           << out.max_index << "]; below buffer_size " << buffer_size;
        out.rationale = rs.str();
    }
    else
    {
        out.verdict = verdict_t::inconclusive;
        std::ostringstream rs;
        rs << "induction var " << ind_name << " bounded to [" << out.min_index << ", "
           << out.max_index << "]; no buffer size to compare";
        out.rationale = rs.str();
    }
    if (!assert_err.empty())
        out.rationale.append("; partial constraints: ").append(assert_err);
    return out;
}

symbolic::alias_proof_t VerificationEngine::prove_pointer_alias(ea_t func_ea,
                                                                const std::string& ptr1_spec,
                                                                const std::string& ptr2_spec,
                                                                uint32_t timeout_ms)
{
    (void)timeout_ms;
    symbolic::alias_proof_t out;
    if (!m_impl || !is_available())
    {
        out.reason = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.reason.empty())
            out.reason = "z3/triton unavailable";
        return out;
    }

    if (!m_impl->sym.load_function(func_ea))
    {
        const char* e = m_impl->sym.last_error();
        out.reason = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                        : std::string("symbolic load failed");
        return out;
    }

    return m_impl->sym.prove_alias(ptr1_spec, ptr2_spec);
}

symbolic::simplification_t VerificationEngine::simplify_function_arithmetic(ea_t func_ea,
                                                                            int max_insns)
{
    symbolic::simplification_t out;
    if (!m_impl || !is_available())
    {
        out.before_text = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.before_text.empty())
            out.before_text = "z3/triton unavailable";
        out.after_text = out.before_text;
        return out;
    }

    if (!m_impl->sym.load_function(func_ea))
    {
        const char* e = m_impl->sym.last_error();
        out.before_text = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                             : std::string("symbolic load failed");
        out.after_text = out.before_text;
        return out;
    }

    return m_impl->sym.simplify_function_arithmetic(max_insns);
}

smt::solve_result_t VerificationEngine::check_path_satisfiability(const std::vector<ea_t>& branch_eas,
                                                                  uint32_t timeout_ms)
{
    smt::solve_result_t out;
    if (!m_impl || !is_available())
    {
        out.result = smt::result_t::unknown;
        out.reason = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.reason.empty())
            out.reason = "z3/triton unavailable";
        return out;
    }
    if (branch_eas.empty())
    {
        out.result = smt::result_t::sat;
        out.reason = "no branches; trivially satisfiable";
        return out;
    }

    func_t* pfn = get_func(branch_eas.front());
    if (pfn == nullptr)
    {
        out.result = smt::result_t::unknown;
        out.reason = "no enclosing function for first branch";
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.result = smt::result_t::unknown;
        const char* e = m_impl->sym.last_error();
        out.reason = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                        : std::string("symbolic load failed");
        return out;
    }

    std::vector<symbolic::path_constraint_t> merged;
    std::set<ea_t> seen;
    for (ea_t ea : branch_eas)
    {
        auto pcs = m_impl->sym.collect_path_to(ea, 64);
        for (auto& pc : pcs)
        {
            if (pc.branch_ea != BADADDR && !seen.insert(pc.branch_ea).second)
                continue;
            merged.push_back(std::move(pc));
        }
    }

    smt::SmtContext local;
    if (!local.is_available())
    {
        out.result = smt::result_t::unknown;
        const char* e = local.last_error();
        out.reason = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                        : std::string("smt unavailable");
        return out;
    }

    std::unordered_map<std::string, int> declared;
    emit_declarations(local, merged, declared);
    std::string assert_err;
    assert_constraints(local, merged, assert_err);

    smt::solve_result_t r = local.check_with_timeout(timeout_ms);
    if (!assert_err.empty())
    {
        if (!r.reason.empty())
            r.reason.append("; ");
        r.reason.append("partial constraints: ").append(assert_err);
    }
    return r;
}

smt::solve_result_t VerificationEngine::solve_smtlib2(const std::string& formula,
                                                      uint32_t timeout_ms)
{
    smt::solve_result_t out;
    out.solve_ms = 0;
    if (!m_impl)
    {
        out.result = smt::result_t::unknown;
        out.reason = "verification engine not initialized";
        return out;
    }
    if (!smt::ensure_z3_runtime())
    {
        out.result = smt::result_t::unknown;
        out.reason = "z3 runtime unavailable";
        return out;
    }

    smt::SmtContext local;
    if (!local.is_available())
    {
        out.result = smt::result_t::unknown;
        const char* e = local.last_error();
        out.reason = e != nullptr && *e ? std::string(e) : std::string("smt unavailable");
        return out;
    }

    if (!local.assert_smtlib2(formula))
    {
        smt::result_t quick = smt::result_t::unknown;
        auto t0 = std::chrono::steady_clock::now();
        bool ok = smt::SmtContext::smtlib2_quick_check(formula, quick, timeout_ms);
        auto t1 = std::chrono::steady_clock::now();
        out.solve_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        out.result = quick;
        if (!ok)
        {
            const char* e = local.last_error();
            out.reason = e != nullptr && *e ? std::string("formula invalid: ") + e
                                            : std::string("formula invalid or z3 unavailable");
        }
        return out;
    }

    out = local.check_with_timeout(timeout_ms);
    return out;
}

nlohmann::json VerificationEngine::verdict_summary() const
{
    nlohmann::json j;
    if (!m_impl)
    {
        j["available"] = false;
        j["sym_error"] = "";
        j["smt_error"] = "";
        return j;
    }
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        for (const auto& kv : m_impl->verdict_counts)
            j[kv.first] = kv.second;
    }
    j["available"] = is_available();
    const char* se = m_impl->sym.last_error();
    const char* me = m_impl->smt.last_error();
    j["sym_error"] = se != nullptr ? std::string(se) : std::string("");
    j["smt_error"] = me != nullptr ? std::string(me) : std::string("");
    return j;
}

VerificationEngine& engine()
{
    static VerificationEngine inst;
    return inst;
}

nlohmann::json to_json(const path_verification_t& v)
{
    nlohmann::json j;
    j["verdict"] = verdict_str(v.verdict);
    j["smt_result"] = smt::result_str(v.smt_result);
    j["solve_ms"] = v.solve_ms;
    j["adjusted_confidence"] = confidence_str(v.adjusted_confidence);
    j["rationale"] = v.rationale;
    j["constraints"] = nlohmann::json::array();
    for (const auto& c : v.constraints)
        j["constraints"].push_back(symbolic::to_json(c));
    j["witness"] = nlohmann::json::array();
    for (const auto& w : v.witness)
        j["witness"].push_back(smt::to_json(w));
    return j;
}

nlohmann::json to_json(const exploit_input_t& e)
{
    nlohmann::json j;
    j["found"] = e.found;
    j["summary"] = e.summary;
    j["rationale"] = e.rationale;
    j["inputs"] = nlohmann::json::array();
    for (const auto& i : e.inputs)
        j["inputs"].push_back(smt::to_json(i));
    nlohmann::json bytes = nlohmann::json::array();
    for (uint8_t b : e.concrete_bytes)
        bytes.push_back(static_cast<int>(b));
    j["concrete_bytes"] = bytes;
    std::string hex_dump;
    char hex_buf[3];
    for (uint8_t b : e.concrete_bytes)
    {
        ::qsnprintf(hex_buf, sizeof(hex_buf), "%02x", b);
        if (!hex_dump.empty())
            hex_dump.push_back(' ');
        hex_dump.append(hex_buf);
    }
    j["concrete_bytes_hex"] = hex_dump;
    return j;
}

nlohmann::json to_json(const loop_bound_proof_t& p)
{
    nlohmann::json j;
    j["verdict"] = verdict_str(p.verdict);
    j["max_index"] = p.max_index;
    j["min_index"] = p.min_index;
    j["buffer_size"] = p.buffer_size;
    j["overflow_provable"] = p.overflow_provable;
    j["rationale"] = p.rationale;
    return j;
}

}
}
}
