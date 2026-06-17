#include "../aida_pro.hpp"

#include "symbolic_engine.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hexrays.hpp>
#include <ida.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <pro.h>
#include <tryblks.hpp>

#include "microcode_engine.hpp"
#include "smt_solver.hpp"

#pragma warning(push, 0)
#include <triton/architecture.hpp>
#include <triton/archEnums.hpp>
#include <triton/ast.hpp>
#include <triton/astContext.hpp>
#include <triton/astEnums.hpp>
#include <triton/astRepresentation.hpp>
#include <triton/context.hpp>
#include <triton/exceptions.hpp>
#include <triton/modes.hpp>
#include <triton/modesEnums.hpp>
#include <triton/symbolicVariable.hpp>
#include <triton/tritonTypes.hpp>
#pragma warning(pop)

namespace aida
{
namespace vuln
{
namespace symbolic
{

namespace
{

constexpr int    kMaxAstDepth         = 32;
constexpr size_t kTextClampChars      = 4096;
constexpr int    kDefaultBitWidth     = 64;
constexpr int    kMaxLocalSymExecLog  = 256;

std::string ea_to_hex(ea_t ea)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(ea);
    return ss.str();
}

std::string clamp_text(const std::string& s)
{
    if (s.size() <= kTextClampChars)
        return s;
    std::string out;
    out.reserve(kTextClampChars + 16);
    out.assign(s, 0, kTextClampChars);
    out.append("...[truncated]");
    return out;
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

bool parse_uint64(const std::string& s, uint64_t& out)
{
    if (s.empty())
        return false;
    const std::string& orig = s;
    std::string t = orig;
    if (!t.empty() && (t.front() == '+' || t.front() == '-'))
        return false;
    int base = 10;
    size_t pos = 0;
    if (t.size() > 2 && (t[0] == '0') && (t[1] == 'x' || t[1] == 'X'))
    {
        base = 16;
        pos = 2;
    }
    if (pos >= t.size())
        return false;
    uint64_t value = 0;
    for (size_t i = pos; i < t.size(); ++i)
    {
        char c = t[i];
        int digit = 0;
        if (c >= '0' && c <= '9')
            digit = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f')
            digit = 10 + (c - 'a');
        else if (base == 16 && c >= 'A' && c <= 'F')
            digit = 10 + (c - 'A');
        else
            return false;
        if (digit >= base)
            return false;
        value = value * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
    }
    out = value;
    return true;
}

bool parse_int64(const std::string& s, int64_t& out)
{
    if (s.empty())
        return false;
    bool negative = false;
    size_t start = 0;
    if (s[0] == '-')
    {
        negative = true;
        start = 1;
    }
    else if (s[0] == '+')
    {
        start = 1;
    }
    if (start >= s.size())
        return false;
    uint64_t u = 0;
    if (!parse_uint64(s.substr(start), u))
        return false;
    if (negative)
        out = -static_cast<int64_t>(u);
    else
        out = static_cast<int64_t>(u);
    return true;
}

std::string mreg_to_name(mreg_t reg, int width)
{
    qstring qn;
    int eff_width = width > 0 ? width : 8;
    if (eff_width > 8)
        eff_width = 8;
    if (eff_width <= 0)
        eff_width = 8;
    int got = get_mreg_name(&qn, reg, eff_width, nullptr);
    if (got > 0 && !qn.empty())
        return std::string(qn.c_str());
    std::ostringstream ss;
    ss << "mreg_" << static_cast<uint64_t>(reg);
    return ss.str();
}

std::string lvar_alias(const mba_t& mba, int idx)
{
    if (idx < 0 || static_cast<size_t>(idx) >= mba.vars.size())
    {
        std::ostringstream ss;
        ss << "lvar_unknown_" << idx;
        return ss.str();
    }
    const lvar_t& v = mba.vars[idx];
    if (!v.name.empty())
    {
        std::ostringstream ss;
        ss << "lvar_" << v.name.c_str() << "_" << idx;
        return ss.str();
    }
    std::ostringstream ss;
    ss << "lvar_" << idx;
    return ss.str();
}

int lvar_width_bits(const mba_t& mba, int idx)
{
    if (idx < 0 || static_cast<size_t>(idx) >= mba.vars.size())
        return kDefaultBitWidth;
    const lvar_t& v = mba.vars[idx];
    int w = v.width;
    if (w <= 0)
        w = 8;
    if (w > 64)
        w = 64;
    return w * 8;
}

int op_size_to_bits(int op_size)
{
    int s = op_size;
    if (s <= 0 || s > 64)
        s = 8;
    return s * 8;
}

bool is_branch_opcode(mcode_t op)
{
    return is_mcode_jcond(op);
}

bool block_has_noret_call_tail(const mblock_t& blk)
{
    const minsn_t* tail = blk.tail;
    if (tail == nullptr || !is_mcode_call(tail->opcode))
        return false;
    ea_t callee = BADADDR;
    std::string name;
    if (!aida::vuln::microcode::resolve_call_target(*tail, callee, name) || callee == BADADDR)
        return false;
    return !func_does_return(callee);
}

bool range_contains_ea(const rangevec_t& ranges, ea_t ea)
{
    for (size_t i = 0; i < ranges.size(); ++i)
    {
        if (ranges[i].contains(ea))
            return true;
    }
    return false;
}

bool seh_handler_contains_ea(const tryblk_t& tb, ea_t ea)
{
    if (tb.is_seh())
    {
        const seh_t& seh = tb.seh();
        if (range_contains_ea(seh, ea))
            return true;
        if (range_contains_ea(seh.filter, ea))
            return true;
        return false;
    }
    if (tb.is_cpp())
    {
        const catchvec_t& catches = tb.cpp();
        for (size_t i = 0; i < catches.size(); ++i)
        {
            if (range_contains_ea(catches[i], ea))
                return true;
        }
    }
    return false;
}

bool path_reaches_seh_handler(func_t* pfn, const std::vector<int>& path_blocks, const mba_t& mba, ea_t target_ea)
{
    if (pfn == nullptr)
        return false;
    tryblks_t tbv;
    range_t fr(pfn->start_ea, pfn->end_ea);
    if (get_tryblks(&tbv, fr) == 0)
        return false;
    for (size_t i = 0; i < tbv.size(); ++i)
    {
        const tryblk_t& tb = tbv[i];
        if (!seh_handler_contains_ea(tb, target_ea))
            continue;
        for (int serial : path_blocks)
        {
            const mblock_t* blk = mba.get_mblock(static_cast<uint>(serial));
            if (blk == nullptr)
                continue;
            if (seh_handler_contains_ea(tb, blk->start) || seh_handler_contains_ea(tb, blk->end))
                return true;
        }
        return true;
    }
    return false;
}

}

struct SymbolicEngine::impl_t
{
    triton::Context                                                                 triton_ctx;
    triton::ast::SharedAstContext                                                   ast_ctxt;
    ea_t                                                                            loaded_func = BADADDR;
    std::optional<aida::vuln::microcode::mba_handle_t>                              mba_handle;
    std::vector<path_constraint_t>                                                  all_constraints;
    std::unordered_map<int, triton::ast::SharedAbstractNode>                        lvar_symbols;
    std::unordered_map<std::string, triton::ast::SharedAbstractNode>                reg_symbols;
    std::unordered_map<int64_t, triton::ast::SharedAbstractNode>                    stk_symbols;
    std::unordered_map<uint64_t, triton::ast::SharedAbstractNode>                   gvar_symbols;
    std::unordered_map<std::string, triton::ast::SharedAbstractNode>                helper_symbols;
    std::unordered_map<int, triton::ast::SharedAbstractNode>                        block_predicates;
    std::unordered_map<int, ea_t>                                                   block_branch_eas;
    std::unordered_map<int, std::vector<int>>                                       block_branch_targets;
    std::vector<int>                                                                arg_lvar_indices;
    std::string                                                                     last_err;
    std::atomic<uint64_t>                                                           fresh_counter{0};
    bool                                                                            available = false;

    impl_t()
    {
        try
        {
            triton_ctx.setArchitecture(triton::arch::ARCH_X86_64);
            triton_ctx.setMode(triton::modes::AST_OPTIMIZATIONS, true);
            triton_ctx.setMode(triton::modes::CONSTANT_FOLDING, true);
            ast_ctxt = triton_ctx.getAstContext();
            available = (ast_ctxt != nullptr);
            if (!available)
                last_err = "triton ast context unavailable";
        }
        catch (const triton::exceptions::Exception& e)
        {
            last_err = std::string("triton init: ") + (e.what() ? e.what() : "?");
            available = false;
        }
        catch (const std::exception& e)
        {
            last_err = std::string("triton init: ") + (e.what() ? e.what() : "?");
            available = false;
        }
        catch (...)
        {
            last_err = "triton init: unknown error";
            available = false;
        }
    }

    void reset_state()
    {
        all_constraints.clear();
        lvar_symbols.clear();
        reg_symbols.clear();
        stk_symbols.clear();
        gvar_symbols.clear();
        helper_symbols.clear();
        block_predicates.clear();
        block_branch_eas.clear();
        block_branch_targets.clear();
        arg_lvar_indices.clear();
        loaded_func = BADADDR;
        mba_handle.reset();
        fresh_counter.store(0, std::memory_order_relaxed);
    }

    triton::ast::SharedAbstractNode fresh_variable(const std::string& tag, int width_bits)
    {
        if (!available || !ast_ctxt)
            return nullptr;
        int w = width_bits;
        if (w <= 0)
            w = kDefaultBitWidth;
        if (w > 4096)
            w = 4096;
        try
        {
            const uint64_t id = fresh_counter.fetch_add(1, std::memory_order_relaxed);
            std::ostringstream ss;
            ss << tag << "_" << id;
            auto sym = triton_ctx.newSymbolicVariable(static_cast<triton::uint32>(w), ss.str());
            if (!sym)
                return nullptr;
            return ast_ctxt->variable(sym);
        }
        catch (const triton::exceptions::Exception& e)
        {
            last_err = std::string("fresh var: ") + (e.what() ? e.what() : "?");
            return nullptr;
        }
        catch (...)
        {
            last_err = "fresh var: unknown error";
            return nullptr;
        }
    }

    triton::ast::SharedAbstractNode get_or_create_lvar(const mba_t& mba, int idx)
    {
        auto it = lvar_symbols.find(idx);
        if (it != lvar_symbols.end())
            return it->second;
        const int width_bits = lvar_width_bits(mba, idx);
        try
        {
            auto sym = triton_ctx.newSymbolicVariable(static_cast<triton::uint32>(width_bits),
                                                     lvar_alias(mba, idx));
            if (!sym)
                return nullptr;
            auto node = ast_ctxt->variable(sym);
            lvar_symbols.emplace(idx, node);
            return node;
        }
        catch (const triton::exceptions::Exception& e)
        {
            last_err = std::string("lvar: ") + (e.what() ? e.what() : "?");
            return nullptr;
        }
        catch (...)
        {
            last_err = "lvar: unknown error";
            return nullptr;
        }
    }

    triton::ast::SharedAbstractNode get_or_create_reg(mreg_t reg, int op_size_bytes)
    {
        const std::string base_name = mreg_to_name(reg, op_size_bytes);
        std::ostringstream key_ss;
        key_ss << base_name << "@" << op_size_bytes;
        const std::string key = key_ss.str();
        auto it = reg_symbols.find(key);
        if (it != reg_symbols.end())
            return it->second;
        const int width_bits = op_size_to_bits(op_size_bytes);
        try
        {
            auto sym = triton_ctx.newSymbolicVariable(static_cast<triton::uint32>(width_bits),
                                                     std::string("reg_") + base_name);
            if (!sym)
                return nullptr;
            auto node = ast_ctxt->variable(sym);
            reg_symbols.emplace(key, node);
            return node;
        }
        catch (const triton::exceptions::Exception& e)
        {
            last_err = std::string("reg: ") + (e.what() ? e.what() : "?");
            return nullptr;
        }
        catch (...)
        {
            last_err = "reg: unknown error";
            return nullptr;
        }
    }

    triton::ast::SharedAbstractNode get_or_create_stk(int64_t off, int op_size_bytes)
    {
        auto it = stk_symbols.find(off);
        if (it != stk_symbols.end())
            return it->second;
        const int width_bits = op_size_to_bits(op_size_bytes);
        try
        {
            std::ostringstream ss;
            ss << "stk_" << static_cast<int64_t>(off);
            auto sym = triton_ctx.newSymbolicVariable(static_cast<triton::uint32>(width_bits), ss.str());
            if (!sym)
                return nullptr;
            auto node = ast_ctxt->variable(sym);
            stk_symbols.emplace(off, node);
            return node;
        }
        catch (const triton::exceptions::Exception& e)
        {
            last_err = std::string("stk: ") + (e.what() ? e.what() : "?");
            return nullptr;
        }
        catch (...)
        {
            last_err = "stk: unknown error";
            return nullptr;
        }
    }

    triton::ast::SharedAbstractNode get_or_create_gvar(uint64_t ea, int op_size_bytes)
    {
        auto it = gvar_symbols.find(ea);
        if (it != gvar_symbols.end())
            return it->second;
        const int width_bits = op_size_to_bits(op_size_bytes);
        try
        {
            std::ostringstream ss;
            qstring qn;
            if (get_name(&qn, static_cast<ea_t>(ea)) > 0 && !qn.empty())
                ss << "gvar_" << qn.c_str();
            else
                ss << "gvar_0x" << std::hex << ea;
            auto sym = triton_ctx.newSymbolicVariable(static_cast<triton::uint32>(width_bits), ss.str());
            if (!sym)
                return nullptr;
            auto node = ast_ctxt->variable(sym);
            gvar_symbols.emplace(ea, node);
            return node;
        }
        catch (const triton::exceptions::Exception& e)
        {
            last_err = std::string("gvar: ") + (e.what() ? e.what() : "?");
            return nullptr;
        }
        catch (...)
        {
            last_err = "gvar: unknown error";
            return nullptr;
        }
    }

    triton::ast::SharedAbstractNode get_or_create_helper(const std::string& name, int op_size_bytes)
    {
        std::ostringstream key_ss;
        key_ss << name << "@" << op_size_bytes;
        const std::string key = key_ss.str();
        auto it = helper_symbols.find(key);
        if (it != helper_symbols.end())
            return it->second;
        const int width_bits = op_size_to_bits(op_size_bytes);
        try
        {
            auto sym = triton_ctx.newSymbolicVariable(static_cast<triton::uint32>(width_bits),
                                                     std::string("helper_") + name);
            if (!sym)
                return nullptr;
            auto node = ast_ctxt->variable(sym);
            helper_symbols.emplace(key, node);
            return node;
        }
        catch (const triton::exceptions::Exception& e)
        {
            last_err = std::string("helper: ") + (e.what() ? e.what() : "?");
            return nullptr;
        }
        catch (...)
        {
            last_err = "helper: unknown error";
            return nullptr;
        }
    }

    triton::ast::SharedAbstractNode resize_to_width(triton::ast::SharedAbstractNode node, int target_bits, bool sign_extend)
    {
        if (!node || !ast_ctxt)
            return node;
        try
        {
            const int cur = static_cast<int>(node->getBitvectorSize());
            if (cur == target_bits || target_bits <= 0)
                return node;
            if (cur > target_bits)
                return ast_ctxt->extract(static_cast<triton::uint32>(target_bits - 1), 0, node);
            const int delta = target_bits - cur;
            if (sign_extend)
                return ast_ctxt->sx(static_cast<triton::uint32>(delta), node);
            return ast_ctxt->zx(static_cast<triton::uint32>(delta), node);
        }
        catch (const triton::exceptions::Exception&)
        {
            return node;
        }
        catch (...)
        {
            return node;
        }
    }

    triton::ast::SharedAbstractNode align_pair(triton::ast::SharedAbstractNode l,
                                               triton::ast::SharedAbstractNode r,
                                               triton::ast::SharedAbstractNode& adjusted_other,
                                               bool sign_extend)
    {
        if (!l || !r)
        {
            adjusted_other = r;
            return l;
        }
        try
        {
            const int lw = static_cast<int>(l->getBitvectorSize());
            const int rw = static_cast<int>(r->getBitvectorSize());
            if (lw == rw)
            {
                adjusted_other = r;
                return l;
            }
            const int target = lw > rw ? lw : rw;
            adjusted_other = resize_to_width(r, target, sign_extend);
            return resize_to_width(l, target, sign_extend);
        }
        catch (...)
        {
            adjusted_other = r;
            return l;
        }
    }

    triton::ast::SharedAbstractNode mop_to_ast(const mop_t& op, int depth);
    triton::ast::SharedAbstractNode minsn_to_ast(const minsn_t& ins, int depth);
    triton::ast::SharedAbstractNode build_branch_predicate(const minsn_t& ins);

    void collect_branches(mba_t& mba)
    {
        for (int i = 0; i < mba.qty; ++i)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
            if (blk == nullptr)
                continue;
            std::vector<int> succs;
            succs.reserve(blk->succset.size());
            for (size_t s = 0; s < blk->succset.size(); ++s)
                succs.push_back(blk->succset[s]);
            block_branch_targets.emplace(blk->serial, std::move(succs));

            const minsn_t* tail = blk->tail;
            if (tail == nullptr)
                continue;
            if (!is_branch_opcode(tail->opcode))
                continue;
            block_branch_eas.emplace(blk->serial, tail->ea);
            auto pred = build_branch_predicate(*tail);
            if (!pred)
                continue;
            block_predicates.emplace(blk->serial, pred);

            path_constraint_t pc;
            pc.branch_ea = tail->ea;
            pc.taken = true;
            try
            {
                pc.predicate_smt2 = clamp_text(pred->str());
                pc.predicate_text = pc.predicate_smt2;
            }
            catch (const triton::exceptions::Exception&)
            {
                pc.predicate_smt2 = "<smt-error>";
                pc.predicate_text = pc.predicate_smt2;
            }
            catch (...)
            {
                pc.predicate_smt2 = "<smt-error>";
                pc.predicate_text = pc.predicate_smt2;
            }
            qstring qs;
            tail->print(&qs, SHINS_SHORT | SHINS_VALNUM);
            qstring clean;
            tag_remove(&clean, qs);
            if (!clean.empty())
                pc.predicate_text = std::string(clean.c_str());
            all_constraints.push_back(pc);

            path_constraint_t pcn = pc;
            pcn.taken = false;
            try
            {
                auto neg = ast_ctxt->lnot(pred);
                pcn.predicate_smt2 = clamp_text(neg->str());
            }
            catch (...)
            {
                pcn.predicate_smt2 = std::string("(not ") + pc.predicate_smt2 + ")";
            }
            all_constraints.push_back(pcn);
        }
    }

    bool find_block_for_ea(const mba_t& mba, ea_t ea, int& out_serial) const
    {
        for (int i = 0; i < mba.qty; ++i)
        {
            const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
            if (blk == nullptr)
                continue;
            for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (m->ea == ea)
                {
                    out_serial = blk->serial;
                    return true;
                }
            }
            if (ea >= blk->start && ea < blk->end)
            {
                out_serial = blk->serial;
                return true;
            }
        }
        return false;
    }

    triton::ast::SharedAbstractNode local_evaluate_in_block(const mblock_t& blk,
                                                            const minsn_t* upto,
                                                            const std::function<bool(const mop_t&)>& match_fn,
                                                            int& out_width_bits)
    {
        triton::ast::SharedAbstractNode current;
        out_width_bits = 0;
        int steps = 0;
        for (const minsn_t* m = blk.head; m != nullptr; m = m->next)
        {
            if (m == upto)
                break;
            if (++steps > kMaxLocalSymExecLog)
                break;
            if (m->d.t == mop_z)
                continue;
            if (match_fn(m->d))
            {
                triton::ast::SharedAbstractNode value = minsn_to_ast(*m, 0);
                if (value)
                {
                    current = value;
                    out_width_bits = static_cast<int>(value->getBitvectorSize());
                }
            }
        }
        return current;
    }
};

triton::ast::SharedAbstractNode SymbolicEngine::impl_t::mop_to_ast(const mop_t& op, int depth)
{
    if (!available || !ast_ctxt)
        return nullptr;
    if (depth > kMaxAstDepth)
        return fresh_variable("deep", op_size_to_bits(op.size));

    try
    {
        switch (op.t)
        {
        case mop_z:
        {
            return ast_ctxt->bv(0, static_cast<triton::uint32>(op_size_to_bits(op.size)));
        }
        case mop_n:
        {
            const int bits = op_size_to_bits(op.size);
            uint64_t v = (op.nnn != nullptr) ? static_cast<uint64_t>(op.nnn->value) : 0;
            return ast_ctxt->bv(triton::uint512(v), static_cast<triton::uint32>(bits));
        }
        case mop_l:
        {
            if (op.l == nullptr || op.l->mba == nullptr)
                return fresh_variable("lvar_null", op_size_to_bits(op.size));
            auto base = get_or_create_lvar(*op.l->mba, op.l->idx);
            if (!base)
                return fresh_variable("lvar_fail", op_size_to_bits(op.size));
            const int target_bits = op_size_to_bits(op.size);
            return resize_to_width(base, target_bits, false);
        }
        case mop_r:
        {
            return get_or_create_reg(op.r, op.size);
        }
        case mop_S:
        {
            if (op.s == nullptr)
                return fresh_variable("stk_null", op_size_to_bits(op.size));
            return get_or_create_stk(static_cast<int64_t>(op.s->off), op.size);
        }
        case mop_v:
        {
            return get_or_create_gvar(static_cast<uint64_t>(op.g), op.size);
        }
        case mop_d:
        {
            if (op.d == nullptr)
                return fresh_variable("subinsn_null", op_size_to_bits(op.size));
            auto inner = minsn_to_ast(*op.d, depth + 1);
            if (!inner)
                return fresh_variable("subinsn", op_size_to_bits(op.size));
            return resize_to_width(inner, op_size_to_bits(op.size), false);
        }
        case mop_a:
        {
            if (op.a != nullptr)
            {
                auto inner = mop_to_ast(static_cast<const mop_t&>(*op.a), depth + 1);
                if (inner)
                    return resize_to_width(inner, op_size_to_bits(op.size), false);
            }
            return fresh_variable("addr", op_size_to_bits(op.size));
        }
        case mop_h:
        {
            std::string name = (op.helper != nullptr) ? std::string(op.helper) : std::string("helper");
            return get_or_create_helper(name, op.size);
        }
        case mop_str:
        {
            return fresh_variable("str", op_size_to_bits(op.size));
        }
        case mop_b:
        {
            return ast_ctxt->bv(triton::uint512(static_cast<uint64_t>(op.b)),
                                static_cast<triton::uint32>(op_size_to_bits(op.size)));
        }
        case mop_f:
        {
            return fresh_variable("callinfo", op_size_to_bits(op.size));
        }
        case mop_c:
        {
            return fresh_variable("cases", op_size_to_bits(op.size));
        }
        case mop_fn:
        {
            return fresh_variable("fpnum", op_size_to_bits(op.size));
        }
        case mop_p:
        {
            if (op.pair != nullptr)
            {
                auto lo = mop_to_ast(op.pair->lop, depth + 1);
                auto hi = mop_to_ast(op.pair->hop, depth + 1);
                if (lo && hi)
                    return resize_to_width(ast_ctxt->concat(hi, lo), op_size_to_bits(op.size), false);
                if (lo)
                    return resize_to_width(lo, op_size_to_bits(op.size), false);
                if (hi)
                    return resize_to_width(hi, op_size_to_bits(op.size), false);
            }
            return fresh_variable("pair", op_size_to_bits(op.size));
        }
        case mop_sc:
        {
            return fresh_variable("scattered", op_size_to_bits(op.size));
        }
        default:
            return fresh_variable("unknown_op", op_size_to_bits(op.size));
        }
    }
    catch (const triton::exceptions::Exception& e)
    {
        last_err = std::string("mop_to_ast: ") + (e.what() ? e.what() : "?");
        return fresh_variable("err", op_size_to_bits(op.size));
    }
    catch (...)
    {
        last_err = "mop_to_ast: unknown error";
        return fresh_variable("err", op_size_to_bits(op.size));
    }
}

triton::ast::SharedAbstractNode SymbolicEngine::impl_t::minsn_to_ast(const minsn_t& ins, int depth)
{
    if (!available || !ast_ctxt)
        return nullptr;
    if (depth > kMaxAstDepth)
        return fresh_variable("deep_insn", op_size_to_bits(ins.d.size));

    try
    {
        const int dst_bits = op_size_to_bits(ins.d.size);
        switch (ins.opcode)
        {
        case m_nop:
        case m_und:
            return fresh_variable("undef", dst_bits);
        case m_ldc:
        case m_mov:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("mov", dst_bits);
            return resize_to_width(l, dst_bits, false);
        }
        case m_neg:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("neg", dst_bits);
            l = resize_to_width(l, dst_bits, false);
            return ast_ctxt->bvneg(l);
        }
        case m_lnot:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("lnot", dst_bits);
            const int lb = static_cast<int>(l->getBitvectorSize());
            auto zero = ast_ctxt->bv(0, static_cast<triton::uint32>(lb));
            auto eq = ast_ctxt->equal(l, zero);
            auto one = ast_ctxt->bv(1, static_cast<triton::uint32>(dst_bits));
            auto z = ast_ctxt->bv(0, static_cast<triton::uint32>(dst_bits));
            return ast_ctxt->ite(eq, one, z);
        }
        case m_bnot:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("bnot", dst_bits);
            l = resize_to_width(l, dst_bits, false);
            return ast_ctxt->bvnot(l);
        }
        case m_xds:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("xds", dst_bits);
            return resize_to_width(l, dst_bits, true);
        }
        case m_xdu:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("xdu", dst_bits);
            return resize_to_width(l, dst_bits, false);
        }
        case m_low:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("low", dst_bits);
            const int lb = static_cast<int>(l->getBitvectorSize());
            if (dst_bits >= lb)
                return resize_to_width(l, dst_bits, false);
            return ast_ctxt->extract(static_cast<triton::uint32>(dst_bits - 1), 0, l);
        }
        case m_high:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("high", dst_bits);
            const int lb = static_cast<int>(l->getBitvectorSize());
            if (dst_bits >= lb)
                return resize_to_width(l, dst_bits, false);
            return ast_ctxt->extract(static_cast<triton::uint32>(lb - 1),
                                     static_cast<triton::uint32>(lb - dst_bits),
                                     l);
        }
        case m_add:
        case m_sub:
        case m_mul:
        case m_udiv:
        case m_sdiv:
        case m_umod:
        case m_smod:
        case m_or:
        case m_and:
        case m_xor:
        case m_shl:
        case m_shr:
        case m_sar:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            auto r = mop_to_ast(ins.r, depth + 1);
            if (!l || !r)
                return fresh_variable("binop", dst_bits);
            l = resize_to_width(l, dst_bits, ins.opcode == m_sdiv || ins.opcode == m_smod || ins.opcode == m_sar);
            r = resize_to_width(r, dst_bits, ins.opcode == m_sdiv || ins.opcode == m_smod || ins.opcode == m_sar);
            switch (ins.opcode)
            {
            case m_add:  return ast_ctxt->bvadd(l, r);
            case m_sub:  return ast_ctxt->bvsub(l, r);
            case m_mul:  return ast_ctxt->bvmul(l, r);
            case m_udiv: return ast_ctxt->bvudiv(l, r);
            case m_sdiv: return ast_ctxt->bvsdiv(l, r);
            case m_umod: return ast_ctxt->bvurem(l, r);
            case m_smod: return ast_ctxt->bvsrem(l, r);
            case m_or:   return ast_ctxt->bvor(l, r);
            case m_and:  return ast_ctxt->bvand(l, r);
            case m_xor:  return ast_ctxt->bvxor(l, r);
            case m_shl:  return ast_ctxt->bvshl(l, r);
            case m_shr:  return ast_ctxt->bvlshr(l, r);
            case m_sar:  return ast_ctxt->bvashr(l, r);
            default:     return fresh_variable("binop", dst_bits);
            }
        }
        case m_cfadd:
        case m_ofadd:
        case m_cfshl:
        case m_cfshr:
        case m_setp:
        case m_seto:
        {
            return fresh_variable("flag", dst_bits);
        }
        case m_sets:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            if (!l)
                return fresh_variable("sets", dst_bits);
            const int lb = static_cast<int>(l->getBitvectorSize());
            auto sign_bit = ast_ctxt->extract(static_cast<triton::uint32>(lb - 1),
                                              static_cast<triton::uint32>(lb - 1),
                                              l);
            return resize_to_width(sign_bit, dst_bits, false);
        }
        case m_setnz:
        case m_setz:
        case m_setae:
        case m_setb:
        case m_seta:
        case m_setbe:
        case m_setg:
        case m_setge:
        case m_setl:
        case m_setle:
        {
            auto l = mop_to_ast(ins.l, depth + 1);
            auto r = mop_to_ast(ins.r, depth + 1);
            if (!l || !r)
                return fresh_variable("setcc", dst_bits);
            triton::ast::SharedAbstractNode adj;
            l = align_pair(l, r, adj, false);
            r = adj;
            triton::ast::SharedAbstractNode cond;
            switch (ins.opcode)
            {
            case m_setnz: cond = ast_ctxt->lnot(ast_ctxt->equal(l, r)); break;
            case m_setz:  cond = ast_ctxt->equal(l, r); break;
            case m_setae: cond = ast_ctxt->bvuge(l, r); break;
            case m_setb:  cond = ast_ctxt->bvult(l, r); break;
            case m_seta:  cond = ast_ctxt->bvugt(l, r); break;
            case m_setbe: cond = ast_ctxt->bvule(l, r); break;
            case m_setg:  cond = ast_ctxt->bvsgt(l, r); break;
            case m_setge: cond = ast_ctxt->bvsge(l, r); break;
            case m_setl:  cond = ast_ctxt->bvslt(l, r); break;
            case m_setle: cond = ast_ctxt->bvsle(l, r); break;
            default:      cond = ast_ctxt->equal(l, r); break;
            }
            auto one = ast_ctxt->bv(1, static_cast<triton::uint32>(dst_bits));
            auto zero = ast_ctxt->bv(0, static_cast<triton::uint32>(dst_bits));
            return ast_ctxt->ite(cond, one, zero);
        }
        case m_ldx:
        {
            return fresh_variable("ldx", dst_bits);
        }
        case m_stx:
            return fresh_variable("stx", dst_bits);
        case m_call:
        case m_icall:
        case m_ext:
            return fresh_variable("call_result", dst_bits);
        case m_pop:
            return fresh_variable("pop", dst_bits);
        case m_push:
            return fresh_variable("push", dst_bits);
        case m_ret:
        case m_jcnd:
        case m_jnz:
        case m_jz:
        case m_jae:
        case m_jb:
        case m_ja:
        case m_jbe:
        case m_jg:
        case m_jge:
        case m_jl:
        case m_jle:
        case m_jtbl:
        case m_ijmp:
        case m_goto:
            return fresh_variable("ctrl", dst_bits);
        case m_f2i:
        case m_f2u:
        case m_i2f:
        case m_u2f:
        case m_f2f:
        case m_fneg:
        case m_fadd:
        case m_fsub:
        case m_fmul:
        case m_fdiv:
            return fresh_variable("fp", dst_bits);
        default:
            return fresh_variable("unknown_op", dst_bits);
        }
    }
    catch (const triton::exceptions::Exception& e)
    {
        last_err = std::string("minsn_to_ast: ") + (e.what() ? e.what() : "?");
        return fresh_variable("insn_err", op_size_to_bits(ins.d.size));
    }
    catch (...)
    {
        last_err = "minsn_to_ast: unknown error";
        return fresh_variable("insn_err", op_size_to_bits(ins.d.size));
    }
}

triton::ast::SharedAbstractNode SymbolicEngine::impl_t::build_branch_predicate(const minsn_t& ins)
{
    if (!available || !ast_ctxt)
        return nullptr;

    try
    {
        if (ins.opcode == m_jcnd)
        {
            auto l = mop_to_ast(ins.l, 0);
            if (!l)
                return nullptr;
            const int lb = static_cast<int>(l->getBitvectorSize());
            auto zero = ast_ctxt->bv(0, static_cast<triton::uint32>(lb));
            return ast_ctxt->lnot(ast_ctxt->equal(l, zero));
        }

        if (!is_mcode_jcond(ins.opcode))
            return nullptr;

        auto l = mop_to_ast(ins.l, 0);
        auto r = mop_to_ast(ins.r, 0);
        if (!l || !r)
            return nullptr;
        triton::ast::SharedAbstractNode adj;
        l = align_pair(l, r, adj, false);
        r = adj;
        switch (ins.opcode)
        {
        case m_jnz: return ast_ctxt->lnot(ast_ctxt->equal(l, r));
        case m_jz:  return ast_ctxt->equal(l, r);
        case m_jae: return ast_ctxt->bvuge(l, r);
        case m_jb:  return ast_ctxt->bvult(l, r);
        case m_ja:  return ast_ctxt->bvugt(l, r);
        case m_jbe: return ast_ctxt->bvule(l, r);
        case m_jg:  return ast_ctxt->bvsgt(l, r);
        case m_jge: return ast_ctxt->bvsge(l, r);
        case m_jl:  return ast_ctxt->bvslt(l, r);
        case m_jle: return ast_ctxt->bvsle(l, r);
        default:    return ast_ctxt->equal(l, r);
        }
    }
    catch (const triton::exceptions::Exception&)
    {
        return nullptr;
    }
    catch (...)
    {
        return nullptr;
    }
}

SymbolicEngine::SymbolicEngine()
    : m_impl(std::make_unique<impl_t>())
{
    if (m_impl)
    {
        if (!aida::vuln::smt::ensure_z3_runtime())
        {
            if (m_impl->last_err.empty())
                m_impl->last_err = "z3 runtime unavailable";
        }
    }
}

SymbolicEngine::~SymbolicEngine() = default;

bool SymbolicEngine::is_available() const
{
    return m_impl && m_impl->available;
}

const char* SymbolicEngine::last_error() const
{
    if (!m_impl)
        return "";
    return m_impl->last_err.c_str();
}

bool SymbolicEngine::load_function(ea_t func_ea, mba_maturity_t mat)
{
    if (!m_impl)
        return false;
    if (!m_impl->available)
    {
        if (m_impl->last_err.empty())
            m_impl->last_err = "triton not initialized";
        return false;
    }

    m_impl->reset_state();

    try
    {
        auto handle_opt = aida::vuln::microcode::generate(func_ea, mat);
        if (!handle_opt.has_value())
        {
            m_impl->last_err = "microcode generation failed";
            return false;
        }
        m_impl->mba_handle = std::move(handle_opt);
    }
    catch (const std::exception& e)
    {
        m_impl->last_err = std::string("mba: ") + (e.what() ? e.what() : "?");
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "mba: unknown error";
        return false;
    }

    mba_t* mba_ptr = m_impl->mba_handle->mba.get();
    if (mba_ptr == nullptr)
    {
        m_impl->last_err = "mba pointer null";
        return false;
    }

    m_impl->loaded_func = m_impl->mba_handle->func_ea;

    try
    {
        for (size_t i = 0; i < mba_ptr->argidx.size(); ++i)
        {
            int idx = mba_ptr->argidx[i];
            if (idx < 0 || static_cast<size_t>(idx) >= mba_ptr->vars.size())
                continue;
            m_impl->arg_lvar_indices.push_back(idx);
            (void)m_impl->get_or_create_lvar(*mba_ptr, idx);
        }

        m_impl->collect_branches(*mba_ptr);
    }
    catch (const triton::exceptions::Exception& e)
    {
        m_impl->last_err = std::string("collect: ") + (e.what() ? e.what() : "?");
        return false;
    }
    catch (const std::exception& e)
    {
        m_impl->last_err = std::string("collect: ") + (e.what() ? e.what() : "?");
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "collect: unknown error";
        return false;
    }

    return true;
}

std::vector<path_constraint_t> SymbolicEngine::collect_path_to(ea_t target_ea, int max_branches)
{
    std::vector<path_constraint_t> out;
    if (!m_impl || !m_impl->available || !m_impl->mba_handle.has_value())
        return out;
    if (max_branches <= 0)
        max_branches = 64;

    mba_t* mba_ptr = m_impl->mba_handle->mba.get();
    if (mba_ptr == nullptr)
        return out;

    int target_serial = -1;
    if (!m_impl->find_block_for_ea(*mba_ptr, target_ea, target_serial))
        return out;

    mbl_graph_t* graph = mba_ptr->get_graph();
    if (graph == nullptr)
        return out;

    graph_chains_t* ud_raw = graph->get_ud(GC_REGS_AND_STKVARS);
    graph_chains_t* du_raw = graph->get_du(GC_REGS_AND_STKVARS);
    std::unique_ptr<chain_keeper_t> ud_keeper;
    std::unique_ptr<chain_keeper_t> du_keeper;
    if (ud_raw != nullptr)
        ud_keeper = std::make_unique<chain_keeper_t>(ud_raw);
    if (du_raw != nullptr)
        du_keeper = std::make_unique<chain_keeper_t>(du_raw);

    array_of_node_bitset_t dominators;
    graph->compute_dominators(dominators, false);

    std::vector<int> parent(static_cast<size_t>(mba_ptr->qty), -1);
    std::vector<unsigned char> visited(static_cast<size_t>(mba_ptr->qty), 0);
    std::queue<int> q;
    if (mba_ptr->qty <= 0)
        return out;
    q.push(0);
    visited[0] = 1;

    while (!q.empty())
    {
        if (user_cancelled())
            break;
        int cur = q.front();
        q.pop();
        if (cur == target_serial)
            break;
        const mblock_t* blk = mba_ptr->get_mblock(static_cast<uint>(cur));
        if (blk == nullptr)
            continue;
        if (block_has_noret_call_tail(*blk))
            continue;

        std::vector<int> succs;
        const int nsucc = graph->nsucc(cur);
        succs.reserve(static_cast<size_t>(nsucc));
        for (int si = 0; si < nsucc; ++si)
        {
            int succ = graph->succ(cur, si);
            if (succ >= 0 && succ < mba_ptr->qty)
                succs.push_back(succ);
        }
        auto reaches_target = [&](int start) -> bool {
            if (start == target_serial)
                return true;
            if (start < 0 || start >= mba_ptr->qty)
                return false;
            std::vector<unsigned char> seen(static_cast<size_t>(mba_ptr->qty), 0);
            std::queue<int> rq;
            seen[static_cast<size_t>(start)] = 1;
            rq.push(start);
            while (!rq.empty())
            {
                int node = rq.front();
                rq.pop();
                const int node_succs = graph->nsucc(node);
                for (int rsi = 0; rsi < node_succs; ++rsi)
                {
                    int next = graph->succ(node, rsi);
                    if (next == target_serial)
                        return true;
                    if (next < 0 || next >= mba_ptr->qty || seen[static_cast<size_t>(next)])
                        continue;
                    seen[static_cast<size_t>(next)] = 1;
                    rq.push(next);
                }
            }
            return false;
        };
        std::stable_sort(succs.begin(), succs.end(), [&](int a, int b) {
            const bool a_dom_target = static_cast<size_t>(target_serial) < dominators.size() && dominators[target_serial].has(a);
            const bool b_dom_target = static_cast<size_t>(target_serial) < dominators.size() && dominators[target_serial].has(b);
            if (a_dom_target != b_dom_target)
                return a_dom_target;
            const bool a_reaches = reaches_target(a);
            const bool b_reaches = reaches_target(b);
            if (a_reaches != b_reaches)
                return a_reaches;
            return a < b;
        });
        for (int succ : succs)
        {
            if (visited[succ])
                continue;
            if (!reaches_target(succ) && succ != target_serial)
                continue;
            visited[succ] = 1;
            parent[succ] = cur;
            q.push(succ);
        }
    }

    if (!visited[target_serial])
        return out;

    std::vector<int> path_blocks;
    for (int cur = target_serial; cur >= 0; cur = parent[cur])
    {
        path_blocks.push_back(cur);
        if (cur == 0)
            break;
    }
    std::reverse(path_blocks.begin(), path_blocks.end());
    const bool via_seh = path_reaches_seh_handler(get_func(m_impl->loaded_func), path_blocks, *mba_ptr, target_ea);

    for (size_t i = 0; i + 1 < path_blocks.size(); ++i)
    {
        int from = path_blocks[i];
        int to   = path_blocks[i + 1];
        auto pred_it = m_impl->block_predicates.find(from);
        if (pred_it == m_impl->block_predicates.end())
            continue;

        bool taken = true;
        auto succ_it = m_impl->block_branch_targets.find(from);
        if (succ_it != m_impl->block_branch_targets.end() && succ_it->second.size() == 2)
        {
            int true_target = succ_it->second[0];
            if (to != true_target)
                taken = false;
        }

        path_constraint_t pc;
        auto ea_it = m_impl->block_branch_eas.find(from);
        pc.branch_ea = ea_it != m_impl->block_branch_eas.end() ? ea_it->second : BADADDR;
        pc.taken     = taken;
        pc.via_seh_handler = via_seh;

        try
        {
            triton::ast::SharedAbstractNode node = pred_it->second;
            if (!taken)
                node = m_impl->ast_ctxt->lnot(node);
            pc.predicate_smt2 = clamp_text(node->str());
            pc.predicate_text = pc.predicate_smt2;
        }
        catch (const triton::exceptions::Exception&)
        {
            pc.predicate_smt2 = "<smt-error>";
            pc.predicate_text = pc.predicate_smt2;
        }
        catch (...)
        {
            pc.predicate_smt2 = "<smt-error>";
            pc.predicate_text = pc.predicate_smt2;
        }
        out.push_back(std::move(pc));
        if (static_cast<int>(out.size()) >= max_branches)
            break;
    }

    return out;
}

std::string SymbolicEngine::path_smtlib2(ea_t target_ea, int max_branches)
{
    auto pcs = collect_path_to(target_ea, max_branches);
    std::ostringstream ss;
    ss << "(set-logic QF_BV)\n";
    std::set<std::string> declared;
    for (const auto& pc : pcs)
    {
        const std::string& text = pc.predicate_smt2;
        for (size_t i = 0; i < text.size();)
        {
            unsigned char c = static_cast<unsigned char>(text[i]);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'))
            {
                ++i;
                continue;
            }
            size_t start = i++;
            while (i < text.size())
            {
                unsigned char k = static_cast<unsigned char>(text[i]);
                if (!((k >= 'A' && k <= 'Z') || (k >= 'a' && k <= 'z') ||
                      (k >= '0' && k <= '9') || k == '_' || k == '!' || k == '.' || k == '@' || k == '$'))
                    break;
                ++i;
            }
            std::string token = text.substr(start, i - start);
            if (token == "_" || token == "assert" || token == "not" || token == "and" || token == "or" ||
                token == "true" || token == "false" || token == "bvult" || token == "bvule" ||
                token == "bvugt" || token == "bvuge" || token == "bvslt" || token == "bvsle" ||
                token == "bvsgt" || token == "bvsge" || token == "bvadd" || token == "bvsub" ||
                token == "bvmul" || token == "concat" || token == "extract" || token == "BitVec" ||
                token == "let" || token == "ite" || token == "zero_extend" || token == "sign_extend")
            {
                continue;
            }
            if (token.size() > 2 && token[0] == 'b' && token[1] == 'v')
                continue;
            if (declared.insert(token).second)
                ss << "(declare-const " << token << " (_ BitVec " << kDefaultBitWidth << "))\n";
        }
    }
    for (const auto& pc : pcs)
    {
        if (pc.predicate_smt2.empty() || pc.predicate_smt2.find("<smt-error>") != std::string::npos)
            continue;
        ss << "(assert " << pc.predicate_smt2 << ")\n";
    }
    ss << "(check-sat)\n(get-model)\n";
    return ss.str();
}

smt::solve_result_t SymbolicEngine::solve_path_to(ea_t target_ea,
                                                  const std::string& extra_smtlib2_assertions,
                                                  uint32_t timeout_ms,
                                                  int max_branches)
{
    smt::solve_result_t out;
    auto formula = path_smtlib2(target_ea, max_branches);
    smt::SmtContext local;
    if (!local.is_available())
    {
        out.result = smt::result_t::unknown;
        out.reason = local.last_error() != nullptr ? std::string(local.last_error()) : std::string("smt unavailable");
        return out;
    }
    if (!local.assert_smtlib2(formula))
    {
        smt::result_t quick = smt::result_t::unknown;
        if (smt::SmtContext::smtlib2_quick_check(formula + "\n" + extra_smtlib2_assertions, quick, timeout_ms))
        {
            out.result = quick;
            out.reason = "quick-check fallback";
            return out;
        }
        out.result = smt::result_t::unknown;
        out.reason = local.last_error() != nullptr ? std::string(local.last_error()) : std::string("smtlib assert failed");
        out.smtlib_dump = formula;
        return out;
    }
    if (!extra_smtlib2_assertions.empty() && !local.assert_smtlib2(extra_smtlib2_assertions))
    {
        out.result = smt::result_t::unknown;
        out.reason = local.last_error() != nullptr ? std::string(local.last_error()) : std::string("extra assertions failed");
        out.smtlib_dump = local.to_smtlib2();
        return out;
    }
    return local.check_with_timeout(timeout_ms);
}

bool SymbolicEngine::constrain_taint_source_at(ea_t source_ea)
{
    if (!m_impl || !m_impl->available || !m_impl->mba_handle.has_value())
        return false;
    mba_t* mba_ptr = m_impl->mba_handle->mba.get();
    if (mba_ptr == nullptr)
        return false;
    for (int i = 0; i < mba_ptr->qty; ++i)
    {
        const mblock_t* blk = mba_ptr->get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (m->ea != source_ea)
                continue;
            triton::ast::SharedAbstractNode node = m_impl->mop_to_ast(m->d, 0);
            if (!node)
                node = m_impl->minsn_to_ast(*m, 0);
            if (!node)
                return false;
            path_constraint_t pc;
            pc.branch_ea = source_ea;
            pc.taken = true;
            try
            {
                std::string s = clamp_text(node->str());
                pc.predicate_smt2 = "(= " + s + " " + s + ")";
                pc.predicate_text = "source symbolic at " + ea_to_hex(source_ea);
            }
            catch (...)
            {
                pc.predicate_smt2 = "true";
                pc.predicate_text = "source symbolic at " + ea_to_hex(source_ea);
            }
            m_impl->all_constraints.push_back(std::move(pc));
            return true;
        }
    }
    return false;
}

std::vector<path_constraint_t> SymbolicEngine::all_path_constraints(int limit)
{
    std::vector<path_constraint_t> out;
    if (!m_impl || !m_impl->available)
        return out;
    if (limit <= 0)
        limit = 256;
    const auto& src = m_impl->all_constraints;
    const size_t cap = static_cast<size_t>(limit);
    out.reserve(src.size() < cap ? src.size() : cap);
    for (size_t i = 0; i < src.size() && out.size() < cap; ++i)
        out.push_back(src[i]);
    return out;
}

namespace
{

bool resolve_lvar_idx(const mba_t& mba, const std::string& spec, int& out_idx)
{
    int64_t idx_int = -1;
    if (parse_int64(spec, idx_int) && idx_int >= 0 && static_cast<size_t>(idx_int) < mba.vars.size())
    {
        out_idx = static_cast<int>(idx_int);
        return true;
    }
    const std::string lower = ascii_lower(spec);
    for (size_t i = 0; i < mba.vars.size(); ++i)
    {
        std::string name(mba.vars[i].name.c_str());
        if (ascii_lower(name) == lower)
        {
            out_idx = static_cast<int>(i);
            return true;
        }
    }
    return false;
}

bool parse_var_spec(const std::string& spec, std::string& kind, std::string& value)
{
    size_t colon = spec.find(':');
    if (colon == std::string::npos)
    {
        kind = "lvar";
        value = spec;
        return !spec.empty();
    }
    kind = ascii_lower(spec.substr(0, colon));
    value = spec.substr(colon + 1);
    return !value.empty();
}

}

std::optional<symbolic_value_t> SymbolicEngine::symbolize_lvar(int lvar_idx)
{
    if (!m_impl || !m_impl->available || !m_impl->mba_handle.has_value())
        return std::nullopt;
    mba_t* mba_ptr = m_impl->mba_handle->mba.get();
    if (mba_ptr == nullptr)
        return std::nullopt;
    if (lvar_idx < 0 || static_cast<size_t>(lvar_idx) >= mba_ptr->vars.size())
    {
        m_impl->last_err = "lvar index out of range";
        return std::nullopt;
    }

    auto node = m_impl->get_or_create_lvar(*mba_ptr, lvar_idx);
    if (!node)
        return std::nullopt;

    symbolic_value_t v;
    try
    {
        v.smt2        = clamp_text(node->str());
        v.text        = v.smt2;
        v.width_bits  = static_cast<int>(node->getBitvectorSize());
        v.is_concrete = !node->isSymbolized();
        if (v.is_concrete)
            v.concrete_value = static_cast<uint64_t>(node->evaluate());
    }
    catch (const triton::exceptions::Exception& e)
    {
        m_impl->last_err = std::string("symbolize_lvar: ") + (e.what() ? e.what() : "?");
        return std::nullopt;
    }
    catch (...)
    {
        m_impl->last_err = "symbolize_lvar: unknown error";
        return std::nullopt;
    }
    return v;
}

std::optional<symbolic_value_t> SymbolicEngine::symbolize_register(const std::string& reg_name)
{
    if (!m_impl || !m_impl->available)
        return std::nullopt;
    if (reg_name.empty())
        return std::nullopt;
    auto node = m_impl->fresh_variable(std::string("reg_") + reg_name, kDefaultBitWidth);
    if (!node)
        return std::nullopt;

    std::ostringstream key_ss;
    key_ss << reg_name << "@8";
    m_impl->reg_symbols[key_ss.str()] = node;

    symbolic_value_t v;
    try
    {
        v.smt2        = clamp_text(node->str());
        v.text        = v.smt2;
        v.width_bits  = static_cast<int>(node->getBitvectorSize());
        v.is_concrete = !node->isSymbolized();
        if (v.is_concrete)
            v.concrete_value = static_cast<uint64_t>(node->evaluate());
    }
    catch (const triton::exceptions::Exception& e)
    {
        m_impl->last_err = std::string("symbolize_register: ") + (e.what() ? e.what() : "?");
        return std::nullopt;
    }
    catch (...)
    {
        m_impl->last_err = "symbolize_register: unknown error";
        return std::nullopt;
    }
    return v;
}

std::optional<symbolic_value_t> SymbolicEngine::symbolize_value_at(ea_t insn_ea, const std::string& var_spec)
{
    if (!m_impl || !m_impl->available || !m_impl->mba_handle.has_value())
        return std::nullopt;

    mba_t* mba_ptr = m_impl->mba_handle->mba.get();
    if (mba_ptr == nullptr)
        return std::nullopt;

    std::string kind, value;
    if (!parse_var_spec(var_spec, kind, value))
    {
        m_impl->last_err = "var_spec empty";
        return std::nullopt;
    }

    int blk_serial = -1;
    const minsn_t* upto = nullptr;
    bool found = false;
    if (insn_ea != BADADDR)
    {
        for (int i = 0; i < mba_ptr->qty && !found; ++i)
        {
            const mblock_t* blk = mba_ptr->get_mblock(static_cast<uint>(i));
            if (blk == nullptr)
                continue;
            for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (m->ea == insn_ea)
                {
                    blk_serial = blk->serial;
                    upto = m;
                    found = true;
                    break;
                }
            }
        }
    }

    triton::ast::SharedAbstractNode result;
    int width_bits = 0;

    if (found && blk_serial >= 0 && upto != nullptr)
    {
        const mblock_t* blk = mba_ptr->get_mblock(static_cast<uint>(blk_serial));
        if (blk != nullptr)
        {
            std::function<bool(const mop_t&)> match;
            if (kind == "lvar")
            {
                int idx = -1;
                if (!resolve_lvar_idx(*mba_ptr, value, idx))
                {
                    m_impl->last_err = "lvar not found";
                    return std::nullopt;
                }
                match = [idx](const mop_t& d) -> bool
                {
                    return d.t == mop_l && d.l != nullptr && d.l->idx == idx;
                };
            }
            else if (kind == "reg")
            {
                std::string lower = ascii_lower(value);
                match = [lower](const mop_t& d) -> bool
                {
                    if (d.t != mop_r)
                        return false;
                    qstring qn;
                    int eff = d.size > 0 ? d.size : 8;
                    if (eff > 8)
                        eff = 8;
                    if (get_mreg_name(&qn, d.r, eff, nullptr) > 0 && !qn.empty())
                    {
                        std::string nm(qn.c_str());
                        if (ascii_lower(nm) == lower)
                            return true;
                    }
                    return false;
                };
            }
            else if (kind == "stk")
            {
                int64_t off = 0;
                if (!parse_int64(value, off))
                {
                    m_impl->last_err = "bad stk offset";
                    return std::nullopt;
                }
                match = [off](const mop_t& d) -> bool
                {
                    return d.t == mop_S && d.s != nullptr && static_cast<int64_t>(d.s->off) == off;
                };
            }
            else
            {
                m_impl->last_err = "unsupported var kind";
                return std::nullopt;
            }

            int found_bits = 0;
            result = m_impl->local_evaluate_in_block(*blk, upto, match, found_bits);
            width_bits = found_bits;
        }
    }

    if (!result)
    {
        if (kind == "lvar")
        {
            int idx = -1;
            if (!resolve_lvar_idx(*mba_ptr, value, idx))
            {
                m_impl->last_err = "lvar not found";
                return std::nullopt;
            }
            result = m_impl->get_or_create_lvar(*mba_ptr, idx);
            if (result)
                width_bits = static_cast<int>(result->getBitvectorSize());
        }
        else if (kind == "reg")
        {
            auto it = m_impl->reg_symbols.find(value + "@8");
            if (it != m_impl->reg_symbols.end())
            {
                result = it->second;
                width_bits = static_cast<int>(result->getBitvectorSize());
            }
            else
            {
                result = m_impl->fresh_variable(std::string("reg_") + value, kDefaultBitWidth);
                if (result)
                {
                    m_impl->reg_symbols[value + "@8"] = result;
                    width_bits = static_cast<int>(result->getBitvectorSize());
                }
            }
        }
        else if (kind == "stk")
        {
            int64_t off = 0;
            if (!parse_int64(value, off))
            {
                m_impl->last_err = "bad stk offset";
                return std::nullopt;
            }
            result = m_impl->get_or_create_stk(off, 8);
            if (result)
                width_bits = static_cast<int>(result->getBitvectorSize());
        }
    }

    if (!result)
        return std::nullopt;

    symbolic_value_t v;
    try
    {
        v.smt2        = clamp_text(result->str());
        v.text        = v.smt2;
        v.width_bits  = width_bits > 0 ? width_bits : static_cast<int>(result->getBitvectorSize());
        v.is_concrete = !result->isSymbolized();
        if (v.is_concrete)
            v.concrete_value = static_cast<uint64_t>(result->evaluate());
    }
    catch (const triton::exceptions::Exception& e)
    {
        m_impl->last_err = std::string("symbolize_value_at: ") + (e.what() ? e.what() : "?");
        return std::nullopt;
    }
    catch (...)
    {
        m_impl->last_err = "symbolize_value_at: unknown error";
        return std::nullopt;
    }
    return v;
}

simplification_t SymbolicEngine::simplify_function_arithmetic(int max_insns)
{
    simplification_t out;
    if (!m_impl || !m_impl->available || !m_impl->mba_handle.has_value())
        return out;
    if (max_insns <= 0)
        max_insns = 1024;

    mba_t* mba_ptr = m_impl->mba_handle->mba.get();
    if (mba_ptr == nullptr)
        return out;

    std::vector<triton::ast::SharedAbstractNode> roots;
    int seen = 0;
    for (int i = 0; i < mba_ptr->qty; ++i)
    {
        const mblock_t* blk = mba_ptr->get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (++seen > max_insns)
                break;
            switch (m->opcode)
            {
            case m_add:
            case m_sub:
            case m_mul:
            case m_udiv:
            case m_sdiv:
            case m_umod:
            case m_smod:
            case m_or:
            case m_and:
            case m_xor:
            case m_shl:
            case m_shr:
            case m_sar:
            case m_neg:
            case m_bnot:
            case m_xds:
            case m_xdu:
            case m_low:
            case m_high:
            case m_mov:
            case m_ldc:
            {
                auto node = m_impl->minsn_to_ast(*m, 0);
                if (node)
                    roots.push_back(node);
                break;
            }
            default:
                break;
            }
        }
        if (seen > max_insns)
            break;
    }

    if (roots.empty())
    {
        out.before_text = "<no-arithmetic>";
        out.after_text  = "<no-arithmetic>";
        return out;
    }

    triton::ast::SharedAbstractNode combined = roots.front();
    try
    {
        for (size_t i = 1; i < roots.size(); ++i)
        {
            int target = static_cast<int>(combined->getBitvectorSize());
            if (static_cast<int>(roots[i]->getBitvectorSize()) > target)
                target = static_cast<int>(roots[i]->getBitvectorSize());
            auto a = m_impl->resize_to_width(combined, target, false);
            auto b = m_impl->resize_to_width(roots[i], target, false);
            combined = m_impl->ast_ctxt->bvxor(a, b);
        }

        out.before_text = clamp_text(combined->str());
        auto simp = m_impl->triton_ctx.simplify(combined, false, false);
        if (simp)
        {
            out.after_text = clamp_text(simp->str());
            out.simplified = (out.before_text != out.after_text);
            if (!simp->isSymbolized())
            {
                out.is_concrete = true;
                out.concrete_value = static_cast<uint64_t>(simp->evaluate());
            }
        }
        else
        {
            out.after_text = out.before_text;
        }
    }
    catch (const triton::exceptions::Exception& e)
    {
        m_impl->last_err = std::string("simplify: ") + (e.what() ? e.what() : "?");
        out.after_text = out.before_text;
    }
    catch (...)
    {
        m_impl->last_err = "simplify: unknown error";
        out.after_text = out.before_text;
    }
    return out;
}

simplification_t SymbolicEngine::simplify_subtree_at(ea_t insn_ea, const std::string& var_spec)
{
    simplification_t out;
    if (!m_impl || !m_impl->available || !m_impl->mba_handle.has_value())
        return out;
    auto node_opt = symbolize_value_at(insn_ea, var_spec);
    if (!node_opt.has_value())
        return out;

    triton::ast::SharedAbstractNode source;
    if (insn_ea != BADADDR)
    {
        mba_t* mba_ptr = m_impl->mba_handle->mba.get();
        if (mba_ptr != nullptr)
        {
            for (int i = 0; i < mba_ptr->qty && !source; ++i)
            {
                const mblock_t* blk = mba_ptr->get_mblock(static_cast<uint>(i));
                if (blk == nullptr)
                    continue;
                for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
                {
                    if (m->ea == insn_ea)
                    {
                        source = m_impl->minsn_to_ast(*m, 0);
                        break;
                    }
                }
            }
        }
    }

    if (!source)
    {
        out.before_text   = node_opt->smt2;
        out.after_text    = node_opt->smt2;
        out.is_concrete   = node_opt->is_concrete;
        out.concrete_value = node_opt->concrete_value;
        return out;
    }

    try
    {
        out.before_text = clamp_text(source->str());
        auto simp = m_impl->triton_ctx.simplify(source, false, false);
        if (simp)
        {
            out.after_text = clamp_text(simp->str());
            out.simplified = (out.before_text != out.after_text);
            if (!simp->isSymbolized())
            {
                out.is_concrete = true;
                out.concrete_value = static_cast<uint64_t>(simp->evaluate());
            }
        }
        else
        {
            out.after_text = out.before_text;
        }
    }
    catch (const triton::exceptions::Exception& e)
    {
        m_impl->last_err = std::string("simplify_subtree_at: ") + (e.what() ? e.what() : "?");
        out.after_text = out.before_text;
    }
    catch (...)
    {
        m_impl->last_err = "simplify_subtree_at: unknown error";
        out.after_text = out.before_text;
    }
    return out;
}

alias_proof_t SymbolicEngine::prove_alias(const std::string& ptr1_spec,
                                          const std::string& ptr2_spec,
                                          uint32_t timeout_ms)
{
    alias_proof_t out;
    if (!m_impl || !m_impl->available || !m_impl->mba_handle.has_value())
    {
        out.reason = "engine not loaded";
        return out;
    }

    auto v1 = symbolize_value_at(BADADDR, ptr1_spec);
    auto v2 = symbolize_value_at(BADADDR, ptr2_spec);
    if (!v1.has_value() || !v2.has_value())
    {
        out.reason = "could not resolve pointer specs";
        return out;
    }

    if (v1->is_concrete && v2->is_concrete)
    {
        out.have_witness = true;
        out.ptr1_concrete = v1->concrete_value;
        out.ptr2_concrete = v2->concrete_value;
        if (v1->concrete_value == v2->concrete_value)
        {
            out.must_alias = true;
            out.may_alias  = true;
            out.no_alias   = false;
            out.verdict = alias_proof_t::verdict_t::must_alias;
            out.verdict_label = "must_alias";
            out.reason     = "both concrete and equal";
        }
        else
        {
            out.must_alias = false;
            out.may_alias  = false;
            out.no_alias   = true;
            out.verdict = alias_proof_t::verdict_t::no_alias;
            out.verdict_label = "no_alias";
            out.reason     = "both concrete and distinct";
        }
        return out;
    }

    aida::vuln::smt::SmtContext smt;
    if (!smt.is_available())
    {
        out.reason = std::string("smt unavailable: ") + (smt.last_error() ? smt.last_error() : "?");
        return out;
    }

    int width = v1->width_bits > 0 ? v1->width_bits : kDefaultBitWidth;
    if (v2->width_bits > width)
        width = v2->width_bits;
    if (width <= 0 || width > 256)
        width = kDefaultBitWidth;

    const std::string ptr_a = "ptr1_alias";
    const std::string ptr_b = "ptr2_alias";

    if (!smt.declare_bv(ptr_a, width) || !smt.declare_bv(ptr_b, width))
    {
        out.reason = std::string("declare failed: ") + (smt.last_error() ? smt.last_error() : "?");
        return out;
    }

    smt.push();
    std::ostringstream eq_formula;
    eq_formula << "(assert (= " << ptr_a << " " << ptr_b << "))";
    if (!smt.assert_smtlib2(eq_formula.str()))
    {
        smt.pop();
        out.reason = std::string("assert eq failed: ") + (smt.last_error() ? smt.last_error() : "?");
        return out;
    }
    auto r_eq = smt.check_with_timeout(timeout_ms == 0 ? 5000 : timeout_ms);
    bool eq_sat = r_eq.result == aida::vuln::smt::result_t::sat;
    bool eq_unsat = r_eq.result == aida::vuln::smt::result_t::unsat;

    if (eq_sat)
    {
        out.may_alias = true;
        for (const auto& m : r_eq.model)
        {
            if (m.is_bitvector && m.name == ptr_a)
            {
                out.ptr1_concrete = m.bv_value;
                out.have_witness = true;
            }
            else if (m.is_bitvector && m.name == ptr_b)
            {
                out.ptr2_concrete = m.bv_value;
                out.have_witness = true;
            }
        }
    }
    else
    {
        out.may_alias = false;
    }
    smt.pop();

    smt.push();
    std::ostringstream neq_formula;
    neq_formula << "(assert (not (= " << ptr_a << " " << ptr_b << ")))";
    if (smt.assert_smtlib2(neq_formula.str()))
    {
        auto r_neq = smt.check_with_timeout(timeout_ms == 0 ? 5000 : timeout_ms);
        if (r_neq.result == aida::vuln::smt::result_t::unsat)
        {
            out.must_alias = true;
            out.may_alias  = true;
            out.no_alias   = false;
        }
        else if (r_neq.result == aida::vuln::smt::result_t::sat && !eq_sat && eq_unsat)
        {
            out.no_alias = true;
        }
    }
    smt.pop();

    if (eq_unsat && !out.must_alias)
    {
        out.no_alias = true;
        out.may_alias = false;
    }

    if (out.must_alias)
    {
        out.verdict = alias_proof_t::verdict_t::must_alias;
        out.verdict_label = "must_alias";
    }
    else if (out.no_alias)
    {
        out.verdict = alias_proof_t::verdict_t::no_alias;
        out.verdict_label = "no_alias";
    }
    else if (out.may_alias)
    {
        out.verdict = alias_proof_t::verdict_t::may_alias;
        out.verdict_label = "may_alias";
    }
    else
    {
        out.verdict = alias_proof_t::verdict_t::inconclusive;
        out.verdict_label = "inconclusive";
    }

    std::ostringstream rs;
    rs << "may=" << (out.may_alias ? "1" : "0")
       << " must=" << (out.must_alias ? "1" : "0")
       << " no=" << (out.no_alias ? "1" : "0")
       << " smt=" << aida::vuln::smt::result_str(r_eq.result);
    out.reason = rs.str();
    return out;
}

nlohmann::json SymbolicEngine::dump_state(int max_constraints) const
{
    nlohmann::json j;
    j["available"]       = is_available();
    j["loaded_func"]     = ea_to_hex(m_impl ? m_impl->loaded_func : BADADDR);
    j["num_constraints"] = m_impl ? static_cast<int>(m_impl->all_constraints.size()) : 0;

    nlohmann::json constraints = nlohmann::json::array();
    if (m_impl)
    {
        const int cap = max_constraints > 0 ? max_constraints : 64;
        for (size_t i = 0; i < m_impl->all_constraints.size() && static_cast<int>(constraints.size()) < cap; ++i)
        {
            const path_constraint_t& c = m_impl->all_constraints[i];
            nlohmann::json cj;
            cj["branch_ea"] = ea_to_hex(c.branch_ea);
            cj["taken"]     = c.taken;
            cj["text"]      = clamp_text(c.predicate_text);
            cj["smt2"]      = clamp_text(c.predicate_smt2);
            constraints.push_back(std::move(cj));
        }
    }
    j["constraints"] = std::move(constraints);

    nlohmann::json lvars = nlohmann::json::array();
    if (m_impl && m_impl->mba_handle.has_value())
    {
        const mba_t* mba_ptr = m_impl->mba_handle->mba.get();
        if (mba_ptr != nullptr)
        {
            for (const auto& kv : m_impl->lvar_symbols)
            {
                int idx = kv.first;
                if (idx < 0 || static_cast<size_t>(idx) >= mba_ptr->vars.size())
                    continue;
                nlohmann::json lj;
                lj["idx"]   = idx;
                lj["name"]  = std::string(mba_ptr->vars[idx].name.c_str());
                lj["width"] = lvar_width_bits(*mba_ptr, idx);
                lvars.push_back(std::move(lj));
            }
        }
    }
    j["lvar_symbols"] = std::move(lvars);

    nlohmann::json regs = nlohmann::json::array();
    if (m_impl)
    {
        for (const auto& kv : m_impl->reg_symbols)
        {
            nlohmann::json rj;
            rj["name"] = kv.first;
            try
            {
                if (kv.second)
                    rj["width"] = static_cast<int>(kv.second->getBitvectorSize());
                else
                    rj["width"] = 0;
            }
            catch (...)
            {
                rj["width"] = 0;
            }
            regs.push_back(std::move(rj));
        }
    }
    j["reg_symbols"] = std::move(regs);
    return j;
}

ea_t SymbolicEngine::current_function_ea() const
{
    if (!m_impl)
        return BADADDR;
    return m_impl->loaded_func;
}

int SymbolicEngine::num_path_constraints() const
{
    if (!m_impl)
        return 0;
    return static_cast<int>(m_impl->all_constraints.size());
}

nlohmann::json to_json(const path_constraint_t& c)
{
    nlohmann::json j;
    j["branch_ea"] = ea_to_hex(c.branch_ea);
    j["taken"]     = c.taken;
    j["via_seh_handler"] = c.via_seh_handler;
    j["smt2"]      = clamp_text(c.predicate_smt2);
    j["text"]      = clamp_text(c.predicate_text);
    return j;
}

nlohmann::json to_json(const symbolic_value_t& v)
{
    nlohmann::json j;
    j["smt2"]          = clamp_text(v.smt2);
    j["text"]          = clamp_text(v.text);
    j["width_bits"]    = v.width_bits;
    j["is_concrete"]   = v.is_concrete;
    j["concrete_value"] = v.concrete_value;
    return j;
}

nlohmann::json to_json(const simplification_t& s)
{
    nlohmann::json j;
    j["simplified"]     = s.simplified;
    j["before"]         = clamp_text(s.before_text);
    j["after"]          = clamp_text(s.after_text);
    j["is_concrete"]    = s.is_concrete;
    j["concrete_value"] = s.concrete_value;
    return j;
}

nlohmann::json to_json(const alias_proof_t& a)
{
    nlohmann::json j;
    j["must_alias"]     = a.must_alias;
    j["may_alias"]      = a.may_alias;
    j["no_alias"]       = a.no_alias;
    j["verdict"]        = a.verdict_label.empty() ? std::string("inconclusive") : a.verdict_label;
    j["ptr1_concrete"]  = a.ptr1_concrete;
    j["ptr2_concrete"]  = a.ptr2_concrete;
    j["have_witness"]   = a.have_witness;
    j["reason"]         = a.reason;
    return j;
}

}
}
}
