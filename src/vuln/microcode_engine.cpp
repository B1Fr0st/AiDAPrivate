#include "../aida_pro.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <name.hpp>

#include "../agent_tools.hpp"
#include "../ida_utils.hpp"
#include "../obfuscation.hpp"
#include "microcode_engine.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace microcode
{

namespace
{

constexpr int kMaxMopJsonDepth = 4;

std::string ea_to_hex(ea_t ea)
{
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

const char* opcode_to_mnemonic(mcode_t op)
{
    switch (op)
    {
    case m_nop:    return "nop";
    case m_stx:    return "stx";
    case m_ldx:    return "ldx";
    case m_ldc:    return "ldc";
    case m_mov:    return "mov";
    case m_neg:    return "neg";
    case m_lnot:   return "lnot";
    case m_bnot:   return "bnot";
    case m_xds:    return "xds";
    case m_xdu:    return "xdu";
    case m_low:    return "low";
    case m_high:   return "high";
    case m_add:    return "add";
    case m_sub:    return "sub";
    case m_mul:    return "mul";
    case m_udiv:   return "udiv";
    case m_sdiv:   return "sdiv";
    case m_umod:   return "umod";
    case m_smod:   return "smod";
    case m_or:     return "or";
    case m_and:    return "and";
    case m_xor:    return "xor";
    case m_shl:    return "shl";
    case m_shr:    return "shr";
    case m_sar:    return "sar";
    case m_cfadd:  return "cfadd";
    case m_ofadd:  return "ofadd";
    case m_cfshl:  return "cfshl";
    case m_cfshr:  return "cfshr";
    case m_sets:   return "sets";
    case m_seto:   return "seto";
    case m_setp:   return "setp";
    case m_setnz:  return "setnz";
    case m_setz:   return "setz";
    case m_setae:  return "setae";
    case m_setb:   return "setb";
    case m_seta:   return "seta";
    case m_setbe:  return "setbe";
    case m_setg:   return "setg";
    case m_setge:  return "setge";
    case m_setl:   return "setl";
    case m_setle:  return "setle";
    case m_jcnd:   return "jcnd";
    case m_jnz:    return "jnz";
    case m_jz:     return "jz";
    case m_jae:    return "jae";
    case m_jb:     return "jb";
    case m_ja:     return "ja";
    case m_jbe:    return "jbe";
    case m_jg:     return "jg";
    case m_jge:    return "jge";
    case m_jl:     return "jl";
    case m_jle:    return "jle";
    case m_jtbl:   return "jtbl";
    case m_ijmp:   return "ijmp";
    case m_goto:   return "goto";
    case m_call:   return "call";
    case m_icall:  return "icall";
    case m_ret:    return "ret";
    case m_push:   return "push";
    case m_pop:    return "pop";
    case m_und:    return "und";
    case m_ext:    return "ext";
    case m_f2i:    return "f2i";
    case m_f2u:    return "f2u";
    case m_i2f:    return "i2f";
    case m_u2f:    return "u2f";
    case m_f2f:    return "f2f";
    case m_fneg:   return "fneg";
    case m_fadd:   return "fadd";
    case m_fsub:   return "fsub";
    case m_fmul:   return "fmul";
    case m_fdiv:   return "fdiv";
    default:       return "?";
    }
}

const char* block_type_to_str(mblock_type_t t)
{
    switch (t)
    {
    case BLT_NONE:  return "none";
    case BLT_STOP:  return "stop";
    case BLT_0WAY:  return "0way";
    case BLT_1WAY:  return "1way";
    case BLT_2WAY:  return "2way";
    case BLT_NWAY:  return "nway";
    case BLT_XTRN:  return "xtrn";
    default:        return "unknown";
    }
}

std::string render_minsn_text(const minsn_t& ins)
{
    qstring qs;
    ins.print(&qs, SHINS_SHORT | SHINS_VALNUM);
    qstring clean;
    tag_remove(&clean, qs);
    return std::string(clean.c_str());
}

std::string render_mop_text(const mop_t& op)
{
    qstring qs;
    op.print(&qs, SHINS_SHORT | SHINS_VALNUM);
    qstring clean;
    tag_remove(&clean, qs);
    return std::string(clean.c_str());
}

std::string lvar_name_for(const mop_t& op)
{
    if (op.t != mop_l || op.l == nullptr || op.l->mba == nullptr)
        return std::string();
    int idx = op.l->idx;
    if (idx < 0 || static_cast<size_t>(idx) >= op.l->mba->vars.size())
        return std::string();
    const lvar_t& v = op.l->mba->vars[idx];
    if (v.name.empty())
        return std::string();
    return std::string(v.name.c_str());
}

std::string global_name_for(ea_t ea)
{
    qstring qn;
    if (get_name(&qn, ea) > 0 && !qn.empty())
        return std::string(qn.c_str());
    return std::string();
}

bool reg_groups_overlap(mreg_t a_reg, int a_size, mreg_t b_reg, int b_size)
{
    if (a_size <= 0)
        a_size = 1;
    if (b_size <= 0)
        b_size = 1;
    sval_t a_lo = static_cast<sval_t>(a_reg);
    sval_t a_hi = a_lo + static_cast<sval_t>(a_size);
    sval_t b_lo = static_cast<sval_t>(b_reg);
    sval_t b_hi = b_lo + static_cast<sval_t>(b_size);
    return a_lo < b_hi && b_lo < a_hi;
}

bool stk_ranges_overlap(sval_t a_off, int a_size, sval_t b_off, int b_size)
{
    if (a_size <= 0)
        a_size = 1;
    if (b_size <= 0)
        b_size = 1;
    sval_t a_hi = a_off + static_cast<sval_t>(a_size);
    sval_t b_hi = b_off + static_cast<sval_t>(b_size);
    return a_off < b_hi && b_off < a_hi;
}

nlohmann::json mop_to_json_depth(const mop_t& op, int depth);

nlohmann::json minsn_to_json_depth(const minsn_t& ins, int depth)
{
    nlohmann::json j;
    j["ea"]        = ea_to_hex(ins.ea);
    j["opcode"]    = opcode_to_mnemonic(ins.opcode);
    j["opcode_id"] = static_cast<int>(ins.opcode);
    j["iprops"]    = static_cast<std::int64_t>(ins.iprops);
    j["text"]      = render_minsn_text(ins);

    if (depth < kMaxMopJsonDepth)
    {
        j["l"] = mop_to_json_depth(ins.l, depth + 1);
        j["r"] = mop_to_json_depth(ins.r, depth + 1);
        j["d"] = mop_to_json_depth(ins.d, depth + 1);
    }
    else
    {
        j["l"] = nlohmann::json{{"type", "elided"}};
        j["r"] = nlohmann::json{{"type", "elided"}};
        j["d"] = nlohmann::json{{"type", "elided"}};
    }
    return j;
}

nlohmann::json mop_to_json_depth(const mop_t& op, int depth)
{
    nlohmann::json j;
    j["valnum"] = static_cast<int>(op.valnum);
    j["oprops"] = static_cast<int>(op.oprops);
    j["size"]   = op.size;
    j["text"]   = render_mop_text(op);

    switch (op.t)
    {
    case mop_z:
        j["type"] = "none";
        break;
    case mop_r:
        j["type"] = "reg";
        j["r"]    = static_cast<int>(op.r);
        break;
    case mop_n:
        j["type"]  = "num";
        j["value"] = (op.nnn != nullptr) ? static_cast<std::uint64_t>(op.nnn->value) : 0;
        break;
    case mop_str:
        j["type"]  = "str";
        j["value"] = (op.cstr != nullptr) ? std::string(op.cstr) : std::string();
        break;
    case mop_d:
        j["type"] = "insn";
        if (op.d != nullptr && depth < kMaxMopJsonDepth)
            j["sub"] = minsn_to_json_depth(*op.d, depth + 1);
        else
            j["sub"] = nlohmann::json{{"type", "elided"}};
        break;
    case mop_S:
        j["type"] = "stkvar";
        j["off"]  = (op.s != nullptr) ? static_cast<std::int64_t>(op.s->off) : 0;
        break;
    case mop_v:
        j["type"] = "gvar";
        j["ea"]   = ea_to_hex(op.g);
        j["name"] = global_name_for(op.g);
        break;
    case mop_b:
        j["type"]   = "blkref";
        j["blknum"] = op.b;
        break;
    case mop_f:
    {
        j["type"] = "callinfo";
        if (op.f != nullptr)
        {
            j["callee"] = ea_to_hex(op.f->callee);
            nlohmann::json args = nlohmann::json::array();
            const mcallargs_t& list = op.f->args;
            for (size_t i = 0; i < list.size(); ++i)
            {
                const mcallarg_t& a = list[i];
                nlohmann::json arg_j;
                arg_j["arg_index"] = static_cast<int>(i);
                arg_j["arg_name"]  = std::string(a.name.c_str());
                arg_j["init_ea"]   = ea_to_hex(a.ea);
                if (depth + 1 < kMaxMopJsonDepth)
                    arg_j["value"] = mop_to_json_depth(static_cast<const mop_t&>(a), depth + 1);
                else
                    arg_j["value"] = nlohmann::json{{"type", "elided"}};
                args.push_back(std::move(arg_j));
            }
            j["args"] = std::move(args);
        }
        else
        {
            j["callee"] = ea_to_hex(BADADDR);
            j["args"]   = nlohmann::json::array();
        }
        break;
    }
    case mop_l:
    {
        j["type"] = "lvar";
        if (op.l != nullptr)
        {
            j["idx"]  = op.l->idx;
            j["off"]  = static_cast<std::int64_t>(op.l->off);
            j["name"] = lvar_name_for(op);
        }
        else
        {
            j["idx"]  = -1;
            j["off"]  = 0;
            j["name"] = std::string();
        }
        break;
    }
    case mop_a:
        j["type"] = "addr";
        if (op.a != nullptr && depth + 1 < kMaxMopJsonDepth)
            j["sub"] = mop_to_json_depth(static_cast<const mop_t&>(*op.a), depth + 1);
        else
            j["sub"] = nlohmann::json{{"type", "elided"}};
        break;
    case mop_h:
        j["type"] = "helper";
        j["name"] = (op.helper != nullptr) ? std::string(op.helper) : std::string();
        break;
    case mop_c:
        j["type"] = "cases";
        break;
    case mop_fn:
        j["type"] = "fpnum";
        break;
    case mop_p:
        j["type"] = "pair";
        break;
    case mop_sc:
        j["type"] = "scattered";
        if (op.scif != nullptr)
            j["name"] = std::string(op.scif->name.c_str());
        else
            j["name"] = std::string();
        break;
    default:
        j["type"]    = "unknown";
        j["type_id"] = static_cast<int>(op.t);
        break;
    }
    return j;
}

bool mop_collect_args_aliases(const mop_t& callinfo, const mop_t& tracked)
{
    if (callinfo.t != mop_f || callinfo.f == nullptr)
        return false;
    const mcallargs_t& args = callinfo.f->args;
    for (size_t i = 0; i < args.size(); ++i)
    {
        const mcallarg_t& a = args[i];
        if (mop_aliases(static_cast<const mop_t&>(a), tracked))
            return true;
    }
    return false;
}

void collect_constraint_strings(const minsn_t& ins, std::vector<std::string>& out)
{
    if (!is_mcode_jcond(ins.opcode) && !is_mcode_set(ins.opcode))
        return;
    out.push_back(render_minsn_text(ins));
}

bool insn_uses_tracked(const minsn_t& ins, const mop_t& tracked, bool& uses_in_args)
{
    uses_in_args = false;
    if (mop_aliases(ins.l, tracked))
        return true;
    if (mop_aliases(ins.r, tracked))
        return true;
    if (mop_aliases(ins.d, tracked))
        return true;
    if (mop_collect_args_aliases(ins.l, tracked) ||
        mop_collect_args_aliases(ins.r, tracked) ||
        mop_collect_args_aliases(ins.d, tracked))
    {
        uses_in_args = true;
        return true;
    }
    return false;
}

bool insn_defines_tracked(const minsn_t& ins, const mop_t& tracked)
{
    switch (ins.opcode)
    {
    case m_stx:
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
    case m_ret:
    case m_push:
    case m_nop:
    case m_und:
        return false;
    default:
        break;
    }
    return mop_aliases(ins.d, tracked);
}

bool resolve_callee_name(const minsn_t& ins, std::string& callee_name)
{
    ea_t ea = BADADDR;
    return resolve_call_target(ins, ea, callee_name);
}

bool callee_in_list(const std::string& callee_name, const std::vector<std::string>& names)
{
    if (callee_name.empty())
        return false;
    const std::string lower = ascii_lower(callee_name);
    for (const auto& n : names)
    {
        const std::string nl = ascii_lower(n);
        if (lower == nl)
            return true;
        if (!nl.empty() && lower.size() > nl.size() &&
            lower.compare(lower.size() - nl.size(), nl.size(), nl) == 0)
            return true;
        if (!nl.empty() && lower.find(nl) != std::string::npos)
            return true;
    }
    return false;
}

bool callee_in_signature_list(const std::string& callee_name, const std::string_view* list, size_t count)
{
    if (callee_name.empty())
        return false;
    const std::string lower = ascii_lower(callee_name);
    for (size_t i = 0; i < count; ++i)
    {
        std::string nl = ascii_lower(std::string(list[i]));
        if (nl.empty())
            continue;
        if (lower == nl)
            return true;
        if (lower.size() > nl.size() &&
            lower.compare(lower.size() - nl.size(), nl.size(), nl) == 0)
            return true;
        if (lower.find(nl) != std::string::npos)
            return true;
    }
    return false;
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

void traverse_topinsns(mba_t& mba, std::function<bool(int, minsn_t&)> visitor)
{
    for (int i = 0; i < mba.qty; ++i)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (!visitor(i, *m))
                return;
        }
    }
}

void traverse_topinsns_const(const mba_t& mba, std::function<bool(int, const minsn_t&)> visitor)
{
    for (int i = 0; i < mba.qty; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (!visitor(i, *m))
                return;
        }
    }
}

}

void mba_deleter_t::operator()(mba_t* mba) const noexcept
{
    if (mba != nullptr)
        delete mba;
}

mba_maturity_t parse_maturity(const std::string& s)
{
    const std::string lower = ascii_lower(s);
    if (lower == "generated")        return MMAT_GENERATED;
    if (lower == "preoptimized")     return MMAT_PREOPTIMIZED;
    if (lower == "locopt")           return MMAT_LOCOPT;
    if (lower == "calls")            return MMAT_CALLS;
    if (lower == "glbopt1")          return MMAT_GLBOPT1;
    if (lower == "glbopt2")          return MMAT_GLBOPT2;
    if (lower == "glbopt3")          return MMAT_GLBOPT3;
    if (lower == "lvars")            return MMAT_LVARS;
    return MMAT_LVARS;
}

const char* maturity_str(mba_maturity_t mat)
{
    switch (mat)
    {
    case MMAT_ZERO:         return "zero";
    case MMAT_GENERATED:    return "generated";
    case MMAT_PREOPTIMIZED: return "preoptimized";
    case MMAT_LOCOPT:       return "locopt";
    case MMAT_CALLS:        return "calls";
    case MMAT_GLBOPT1:      return "glbopt1";
    case MMAT_GLBOPT2:      return "glbopt2";
    case MMAT_GLBOPT3:      return "glbopt3";
    case MMAT_LVARS:        return "lvars";
    }
    return "unknown";
}

std::optional<mba_handle_t> generate(ea_t func_ea, mba_maturity_t mat)
{
    if (!init_hexrays_plugin())
        return std::nullopt;

    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return std::nullopt;

    if (!ida_utils::is_safely_decompilable(pfn))
        return std::nullopt;

    mba_handle_t handle;
    handle.maturity = mat;
    handle.func_ea  = pfn->start_ea;

    try
    {
        hexrays_failure_t hf;
        mba_ranges_t mbr(pfn);
        mba_t* mba = gen_microcode(mbr, &hf, nullptr, DECOMP_NO_WAIT | DECOMP_WARNINGS, mat);
        if (mba == nullptr)
            return std::nullopt;
        handle.mba.reset(mba);
        return handle;
    }
    catch (const vd_failure_t&)
    {
        return std::nullopt;
    }
    catch (...)
    {
        return std::nullopt;
    }
}

nlohmann::json minsn_to_json(const minsn_t& ins)
{
    return minsn_to_json_depth(ins, 0);
}

nlohmann::json mop_to_json(const mop_t& op)
{
    return mop_to_json_depth(op, 0);
}

nlohmann::json dump_mba(const mba_t& mba, size_t inst_offset, size_t inst_limit)
{
    nlohmann::json result;
    result["func_ea"]      = ea_to_hex(mba.entry_ea);
    result["maturity"]     = maturity_str(mba.maturity);
    result["block_count"]  = mba.qty;

    size_t total = 0;
    for (int i = 0; i < mba.qty; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
            ++total;
    }
    result["total_instructions"] = total;
    result["offset"]             = inst_offset;
    result["limit"]              = inst_limit;

    nlohmann::json blocks = nlohmann::json::array();
    size_t emitted    = 0;
    size_t seen       = 0;
    bool   truncated  = false;
    bool   limit_hit  = false;

    for (int i = 0; i < mba.qty && !limit_hit; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;

        nlohmann::json blk_j;
        blk_j["serial"] = blk->serial;
        blk_j["type"]   = block_type_to_str(blk->type);
        blk_j["start"]  = ea_to_hex(blk->start);
        blk_j["end"]    = ea_to_hex(blk->end);

        nlohmann::json preds = nlohmann::json::array();
        for (size_t p = 0; p < blk->predset.size(); ++p)
            preds.push_back(blk->predset[p]);
        blk_j["predecessors"] = std::move(preds);

        nlohmann::json succs = nlohmann::json::array();
        for (size_t s = 0; s < blk->succset.size(); ++s)
            succs.push_back(blk->succset[s]);
        blk_j["successors"] = std::move(succs);

        nlohmann::json insns = nlohmann::json::array();
        for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (seen < inst_offset)
            {
                ++seen;
                continue;
            }
            if (inst_limit != 0 && emitted >= inst_limit)
            {
                truncated = true;
                limit_hit = true;
                break;
            }
            insns.push_back(minsn_to_json_depth(*m, 0));
            ++emitted;
            ++seen;
        }
        blk_j["instructions"] = std::move(insns);
        blocks.push_back(std::move(blk_j));
    }

    result["blocks"]                 = std::move(blocks);
    result["returned_instructions"]  = emitted;
    result["truncated"]              = truncated;
    return result;
}

bool mop_equal(const mop_t& a, const mop_t& b)
{
    if (a.t != b.t)
        return false;
    if (a.size != b.size)
        return false;

    switch (a.t)
    {
    case mop_z:
        return true;
    case mop_r:
        return a.r == b.r;
    case mop_n:
        if (a.nnn == nullptr || b.nnn == nullptr)
            return a.nnn == b.nnn;
        return a.nnn->value == b.nnn->value;
    case mop_str:
        if (a.cstr == nullptr || b.cstr == nullptr)
            return a.cstr == b.cstr;
        return std::strcmp(a.cstr, b.cstr) == 0;
    case mop_v:
        return a.g == b.g;
    case mop_l:
        if (a.l == nullptr || b.l == nullptr)
            return a.l == b.l;
        return a.l->idx == b.l->idx && a.l->off == b.l->off;
    case mop_S:
        if (a.s == nullptr || b.s == nullptr)
            return a.s == b.s;
        return a.s->off == b.s->off;
    case mop_b:
        return a.b == b.b;
    case mop_h:
        if (a.helper == nullptr || b.helper == nullptr)
            return a.helper == b.helper;
        return std::strcmp(a.helper, b.helper) == 0;
    case mop_d:
        return a.d == b.d;
    case mop_f:
        return a.f == b.f;
    case mop_a:
        return a.a == b.a;
    case mop_c:
        return a.c == b.c;
    case mop_fn:
        return a.fpc == b.fpc;
    case mop_p:
        return a.pair == b.pair;
    case mop_sc:
        return a.scif == b.scif;
    default:
        break;
    }
    return false;
}

bool mop_aliases(const mop_t& a, const mop_t& b)
{
    if (a.t == mop_z || b.t == mop_z)
        return false;

    if (a.t == mop_l && b.t == mop_l && a.l != nullptr && b.l != nullptr)
    {
        if (a.l->idx != b.l->idx)
            return false;
        sval_t a_off = a.l->off;
        sval_t b_off = b.l->off;
        return stk_ranges_overlap(a_off, a.size, b_off, b.size);
    }

    if (a.t == mop_S && b.t == mop_S && a.s != nullptr && b.s != nullptr)
        return stk_ranges_overlap(a.s->off, a.size, b.s->off, b.size);

    if (a.t == mop_r && b.t == mop_r)
        return reg_groups_overlap(a.r, a.size, b.r, b.size);

    if (a.t == mop_v && b.t == mop_v)
    {
        sval_t a_off = static_cast<sval_t>(a.g);
        sval_t b_off = static_cast<sval_t>(b.g);
        return stk_ranges_overlap(a_off, a.size, b_off, b.size);
    }

    if (a.t == mop_h && b.t == mop_h && a.helper != nullptr && b.helper != nullptr)
        return std::strcmp(a.helper, b.helper) == 0;

    if (a.t == b.t)
        return mop_equal(a, b);

    return false;
}

std::string mop_describe(const mop_t& op)
{
    return render_mop_text(op);
}

bool resolve_call_target(const minsn_t& ins, ea_t& callee_ea, std::string& callee_name)
{
    callee_ea   = BADADDR;
    callee_name.clear();

    if (ins.opcode != m_call && ins.opcode != m_icall)
        return false;

    const mop_t& target = ins.l;
    if (target.t == mop_v)
    {
        callee_ea = target.g;
        callee_name = global_name_for(callee_ea);
    }
    else if (target.t == mop_h && target.helper != nullptr)
    {
        callee_name = std::string(target.helper);
    }
    else if (target.t == mop_b)
    {
        callee_ea = BADADDR;
    }

    if (ins.d.t == mop_f && ins.d.f != nullptr)
    {
        ea_t fc = ins.d.f->callee;
        if (fc != BADADDR)
        {
            callee_ea = fc;
            if (callee_name.empty())
                callee_name = global_name_for(fc);
        }
    }

    if (callee_ea != BADADDR)
    {
        func_t* f = get_func(callee_ea);
        if (f != nullptr && (f->flags & FUNC_THUNK) != 0)
        {
            ea_t fptr = BADADDR;
            ea_t target_ea = calc_thunk_func_target(f, &fptr);
            if (target_ea != BADADDR && target_ea != callee_ea)
            {
                callee_ea = target_ea;
                std::string resolved = global_name_for(target_ea);
                if (!resolved.empty())
                    callee_name = resolved;
            }
        }
    }

    return !callee_name.empty() || callee_ea != BADADDR;
}

std::vector<call_arg_info_t> collect_call_arguments(const minsn_t& call_ins)
{
    std::vector<call_arg_info_t> out;
    if (!is_mcode_call(call_ins.opcode))
        return out;
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return out;

    const mcallargs_t& args = call_ins.d.f->args;
    out.reserve(args.size());
    for (size_t i = 0; i < args.size(); ++i)
    {
        const mcallarg_t& a = args[i];
        call_arg_info_t info;
        info.arg_index  = static_cast<int>(i);
        info.value      = static_cast<const mop_t&>(a);
        info.init_ea    = a.ea;
        info.is_literal = (a.t == mop_n) || (a.t == mop_str);
        if (a.t == mop_n && a.nnn != nullptr)
            info.literal_value = static_cast<std::uint64_t>(a.nnn->value);
        info.summary = render_mop_text(static_cast<const mop_t&>(a));
        out.push_back(std::move(info));
    }
    return out;
}

bool insn_predates(const mba_t& mba, ea_t earlier_ea, ea_t later_ea)
{
    if (earlier_ea == BADADDR || later_ea == BADADDR)
        return false;
    bool seen_earlier = false;
    bool found        = false;
    traverse_topinsns_const(mba, [&](int, const minsn_t& ins) -> bool {
        if (!seen_earlier)
        {
            if (ins.ea == earlier_ea)
                seen_earlier = true;
            return true;
        }
        if (ins.ea == later_ea)
        {
            found = true;
            return false;
        }
        return true;
    });
    return seen_earlier && found;
}

ea_t find_first_call_to(mba_t& mba, const std::vector<std::string>& callee_names)
{
    ea_t result = BADADDR;
    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        if (!is_mcode_call(ins.opcode))
            return true;
        std::string name;
        if (!resolve_callee_name(ins, name))
            return true;
        if (callee_in_list(name, callee_names))
        {
            result = ins.ea;
            return false;
        }
        return true;
    });
    return result;
}

std::vector<ea_t> find_all_calls_to(mba_t& mba, const std::vector<std::string>& callee_names)
{
    std::vector<ea_t> out;
    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        if (!is_mcode_call(ins.opcode))
            return true;
        std::string name;
        if (!resolve_callee_name(ins, name))
            return true;
        if (callee_in_list(name, callee_names))
            out.push_back(ins.ea);
        return true;
    });
    return out;
}

def_use_t def_use_chain(mba_t& mba, const mop_t& tracked)
{
    def_use_t result;
    if (tracked.t == mop_z)
        return result;

    std::unordered_set<std::uint64_t> def_set;
    std::unordered_set<std::uint64_t> use_set;
    ea_t last_def_ea = BADADDR;

    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        bool used_in_args = false;
        const bool is_use = insn_uses_tracked(ins, tracked, used_in_args);
        const bool is_def = insn_defines_tracked(ins, tracked);

        if (is_use)
        {
            if (use_set.insert(static_cast<std::uint64_t>(ins.ea)).second)
                result.uses.push_back(ins.ea);
            if (last_def_ea != BADADDR)
            {
                std::ostringstream rd;
                rd << "def@" << ea_to_hex(last_def_ea) << " -> use@" << ea_to_hex(ins.ea);
                result.reaching_defs.push_back(rd.str());
            }
            (void)used_in_args;
        }

        if (is_def)
        {
            if (def_set.insert(static_cast<std::uint64_t>(ins.ea)).second)
                result.defs.push_back(ins.ea);
            last_def_ea = ins.ea;
        }

        collect_constraint_strings(ins, result.constraints);
        return true;
    });

    return result;
}

def_use_t def_use_chain_for_lvar(mba_t& mba, int lvar_idx)
{
    def_use_t empty;
    if (lvar_idx < 0 || static_cast<size_t>(lvar_idx) >= mba.vars.size())
        return empty;
    const lvar_t& v = mba.vars[lvar_idx];
    int width = v.width > 0 ? v.width : 1;
    mop_t synth;
    synth._make_lvar(&mba, lvar_idx, 0);
    synth.size = width;
    return def_use_chain(mba, synth);
}

def_use_t def_use_chain_for_stkvar(mba_t& mba, sval_t off)
{
    mop_t synth;
    synth._make_stkvar(&mba, off);
    synth.size = 1;
    return def_use_chain(mba, synth);
}

def_use_t def_use_chain_for_reg(mba_t& mba, mreg_t reg)
{
    mop_t synth;
    synth._make_reg(reg, 1);
    return def_use_chain(mba, synth);
}

bool is_freed_then_used(mba_t& mba, const mop_t& ptr, ea_t& free_ea, ea_t& use_ea)
{
    free_ea = BADADDR;
    use_ea  = BADADDR;
    if (ptr.t == mop_z)
        return false;

    bool tracking = false;
    bool result   = false;
    ea_t pending_free_ea = BADADDR;

    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        bool is_matching_free = false;
        if (is_mcode_call(ins.opcode))
        {
            std::string name;
            if (resolve_callee_name(ins, name) &&
                callee_in_signature_list(name, sig::FREE_FUNCS,
                                         sizeof(sig::FREE_FUNCS) / sizeof(sig::FREE_FUNCS[0])))
            {
                mop_t arg_ptr;
                arg_ptr.zero();
                if (collect_first_pointer_arg(ins, arg_ptr) && mop_aliases(arg_ptr, ptr))
                {
                    tracking = true;
                    pending_free_ea = ins.ea;
                    is_matching_free = true;
                }
            }
        }

        if (is_matching_free)
            return true;

        if (!tracking)
            return true;

        if (insn_defines_tracked(ins, ptr))
        {
            tracking = false;
            pending_free_ea = BADADDR;
            return true;
        }

        bool used_in_args = false;
        if (insn_uses_tracked(ins, ptr, used_in_args))
        {
            if (ins.opcode == m_ldx || ins.opcode == m_stx ||
                used_in_args || ins.opcode == m_call || ins.opcode == m_icall)
            {
                free_ea = pending_free_ea;
                use_ea  = ins.ea;
                result  = true;
                return false;
            }
        }
        return true;
    });

    return result;
}

bool is_double_freed(mba_t& mba, const mop_t& ptr, ea_t& free1_ea, ea_t& free2_ea)
{
    free1_ea = BADADDR;
    free2_ea = BADADDR;
    if (ptr.t == mop_z)
        return false;

    ea_t pending_free_ea = BADADDR;
    bool tracking        = false;
    bool result          = false;

    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        bool is_matching_free = false;
        if (is_mcode_call(ins.opcode))
        {
            std::string name;
            if (resolve_callee_name(ins, name) &&
                callee_in_signature_list(name, sig::FREE_FUNCS,
                                         sizeof(sig::FREE_FUNCS) / sizeof(sig::FREE_FUNCS[0])))
            {
                mop_t arg_ptr;
                arg_ptr.zero();
                if (collect_first_pointer_arg(ins, arg_ptr) && mop_aliases(arg_ptr, ptr))
                {
                    if (tracking && pending_free_ea != BADADDR)
                    {
                        free1_ea = pending_free_ea;
                        free2_ea = ins.ea;
                        result   = true;
                        return false;
                    }
                    tracking = true;
                    pending_free_ea = ins.ea;
                    is_matching_free = true;
                }
            }
        }

        if (is_matching_free)
            return true;

        if (tracking && insn_defines_tracked(ins, ptr))
        {
            tracking = false;
            pending_free_ea = BADADDR;
        }
        return true;
    });

    return result;
}

bool has_uninit_read(mba_t& mba, const mop_t& var, ea_t& read_ea)
{
    read_ea = BADADDR;
    if (var.t == mop_z)
        return false;

    bool seen_def = false;
    bool result   = false;

    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        const bool is_def = insn_defines_tracked(ins, var);
        bool used_in_args = false;
        const bool is_use = insn_uses_tracked(ins, var, used_in_args);

        if (is_use && !seen_def)
        {
            read_ea = ins.ea;
            result  = true;
            return false;
        }
        if (is_def)
            seen_def = true;
        return true;
    });

    return result;
}

namespace
{

mreg_t reg_name_to_mreg(const std::string& name)
{
    if (name.empty())
        return mreg_t(-1);
    int r = ::str2reg(name.c_str());
    if (r < 0)
        return mreg_t(-1);
    mreg_t mr = reg2mreg(r);
    return mr;
}

bool parse_int64(const std::string& s, std::int64_t& out)
{
    if (s.empty())
        return false;
    std::string trimmed = s;
    bool neg = false;
    if (trimmed[0] == '-')
    {
        neg = true;
        trimmed.erase(0, 1);
    }
    if (trimmed.empty())
        return false;
    if (trimmed.size() > 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X'))
        trimmed.erase(0, 2);
    if (trimmed.empty())
        return false;
    const char* cstr = trimmed.c_str();
    char* endp = nullptr;
    errno = 0;
    unsigned long long v = ::strtoull(cstr, &endp, 16);
    if (errno != 0 || endp == nullptr || *endp != '\0' || endp == cstr)
        return false;
    std::int64_t signed_v = static_cast<std::int64_t>(v);
    if (neg)
        signed_v = -signed_v;
    out = signed_v;
    return true;
}

int find_lvar_by_name(const mba_t& mba, const std::string& name)
{
    for (size_t i = 0; i < mba.vars.size(); ++i)
    {
        const lvar_t& v = mba.vars[i];
        if (!v.name.empty() && std::strcmp(v.name.c_str(), name.c_str()) == 0)
            return static_cast<int>(i);
    }
    return -1;
}

nlohmann::json def_use_to_json(const def_use_t& du)
{
    nlohmann::json j;
    nlohmann::json defs = nlohmann::json::array();
    for (ea_t ea : du.defs)
        defs.push_back(ea_to_hex(ea));
    j["defs"] = std::move(defs);

    nlohmann::json uses = nlohmann::json::array();
    for (ea_t ea : du.uses)
        uses.push_back(ea_to_hex(ea));
    j["uses"] = std::move(uses);

    nlohmann::json reaching = nlohmann::json::array();
    for (const std::string& s : du.reaching_defs)
        reaching.push_back(s);
    j["reaching_defs"] = std::move(reaching);

    nlohmann::json constraints = nlohmann::json::array();
    for (const std::string& s : du.constraints)
        constraints.push_back(s);
    j["constraints"] = std::move(constraints);

    j["def_count"] = du.defs.size();
    j["use_count"] = du.uses.size();
    return j;
}

agent_tools::tool_result_t handle_decompile_with_microcode(const nlohmann::json& params)
{
    std::optional<ea_t> ea_opt;
    if (params.contains("address") && params["address"].is_string())
        ea_opt = agent_tools::helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt.has_value())
        return agent_tools::tool_result_t::error(OBFSTR("Invalid or missing address"));

    std::string maturity_str_in = "lvars";
    if (params.contains("maturity") && params["maturity"].is_string())
        maturity_str_in = params["maturity"].get<std::string>();
    mba_maturity_t mat = parse_maturity(maturity_str_in);

    size_t offset = 0;
    if (params.contains("offset"))
    {
        const auto& o = params["offset"];
        if (o.is_number_integer())
            offset = static_cast<size_t>(std::max<std::int64_t>(0, o.get<std::int64_t>()));
        else if (o.is_number_unsigned())
            offset = static_cast<size_t>(o.get<std::uint64_t>());
        else if (o.is_number())
            offset = static_cast<size_t>(std::max<double>(0.0, o.get<double>()));
    }

    size_t limit = 2000;
    if (params.contains("limit"))
    {
        const auto& l = params["limit"];
        if (l.is_number_integer())
            limit = static_cast<size_t>(std::max<std::int64_t>(0, l.get<std::int64_t>()));
        else if (l.is_number_unsigned())
            limit = static_cast<size_t>(l.get<std::uint64_t>());
        else if (l.is_number())
            limit = static_cast<size_t>(std::max<double>(0.0, l.get<double>()));
    }
    if (limit == 0)
        limit = 2000;
    if (limit > 50000)
        limit = 50000;

    auto handle = generate(*ea_opt, mat);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(OBFSTR("Failed to generate microcode for the function"));

    nlohmann::json data = dump_mba(*handle->mba, offset, limit);
    std::string msg = OBFSTR("Microcode generated at maturity ") + std::string(maturity_str(mat));
    return agent_tools::tool_result_t::ok(msg, data);
}

agent_tools::tool_result_t handle_get_microcode_dataflow(const nlohmann::json& params)
{
    std::optional<ea_t> ea_opt;
    if (params.contains("address") && params["address"].is_string())
        ea_opt = agent_tools::helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt.has_value())
        return agent_tools::tool_result_t::error(OBFSTR("Invalid or missing address"));

    std::string variable;
    if (params.contains("variable") && params["variable"].is_string())
        variable = params["variable"].get<std::string>();
    if (variable.empty())
        return agent_tools::tool_result_t::error(OBFSTR("Missing 'variable' parameter (lvar:NAME, lvar:INDEX, reg:NAME, stk:OFFSET)"));

    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(OBFSTR("Failed to generate microcode for the function"));

    mba_t& mba = *handle->mba;

    auto colon = variable.find(':');
    if (colon == std::string::npos)
        return agent_tools::tool_result_t::error(OBFSTR("Invalid variable spec; expected lvar:NAME or lvar:INDEX or reg:NAME or stk:OFFSET"));

    std::string kind  = ascii_lower(variable.substr(0, colon));
    std::string value = variable.substr(colon + 1);

    def_use_t du;
    nlohmann::json target_meta;
    target_meta["kind"]  = kind;
    target_meta["value"] = value;

    if (kind == "lvar")
    {
        int idx = -1;
        if (!value.empty())
        {
            const char* cstr = value.c_str();
            char* endp = nullptr;
            long parsed = ::strtol(cstr, &endp, 10);
            if (endp != nullptr && *endp == '\0' && endp != cstr &&
                parsed >= 0 && parsed <= std::numeric_limits<int>::max())
            {
                idx = static_cast<int>(parsed);
            }
        }
        if (idx < 0)
            idx = find_lvar_by_name(mba, value);
        if (idx < 0)
            return agent_tools::tool_result_t::error(OBFSTR("lvar not found: ") + value);
        target_meta["lvar_idx"] = idx;
        if (idx >= 0 && static_cast<size_t>(idx) < mba.vars.size())
            target_meta["lvar_name"] = std::string(mba.vars[idx].name.c_str());
        du = def_use_chain_for_lvar(mba, idx);
    }
    else if (kind == "reg")
    {
        mreg_t reg = reg_name_to_mreg(value);
        if (reg == mr_none)
            return agent_tools::tool_result_t::error(OBFSTR("Unknown register: ") + value);
        target_meta["reg"] = static_cast<int>(reg);
        du = def_use_chain_for_reg(mba, reg);
    }
    else if (kind == "stk")
    {
        std::int64_t off = 0;
        if (!parse_int64(value, off))
            return agent_tools::tool_result_t::error(OBFSTR("Invalid stack offset (hex expected): ") + value);
        target_meta["stk_off"] = off;
        du = def_use_chain_for_stkvar(mba, static_cast<sval_t>(off));
    }
    else
    {
        return agent_tools::tool_result_t::error(OBFSTR("Unknown variable kind: ") + kind);
    }

    nlohmann::json data = def_use_to_json(du);
    data["target"]   = std::move(target_meta);
    data["func_ea"]  = ea_to_hex(handle->func_ea);
    data["maturity"] = maturity_str(handle->maturity);

    std::string msg = OBFSTR("Dataflow: ") +
                      std::to_string(du.defs.size()) +
                      OBFSTR(" def(s), ") +
                      std::to_string(du.uses.size()) +
                      OBFSTR(" use(s)");
    return agent_tools::tool_result_t::ok(msg, data);
}

}

void register_tier1_microcode_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("decompile_with_microcode"),
        OBFSTR("vuln"),
        OBFSTR("Generate Hex-Rays microcode for a function at a specified maturity level "
               "(generated/preoptimized/locopt/calls/glbopt1/glbopt2/glbopt3/lvars) and return "
               "a structured JSON dump of every basic block, control-flow edges, and decoded "
               "instructions with operand-level detail. Useful for low-level vulnerability "
               "analysis where C decompilation hides taint propagation, opaque predicates, or "
               "intermediate value-numbered locations."),
        {
            {OBFSTR("address"),  OBFSTR("string"),
             OBFSTR("Function address (0x...) or function name"), true},
            {OBFSTR("maturity"), OBFSTR("string"),
             OBFSTR("Microcode maturity level (default: lvars)"), false,
             {OBFSTR("generated"), OBFSTR("preoptimized"), OBFSTR("locopt"),
              OBFSTR("calls"), OBFSTR("glbopt1"), OBFSTR("glbopt2"),
              OBFSTR("glbopt3"), OBFSTR("lvars")}},
            {OBFSTR("offset"),   OBFSTR("number"),
             OBFSTR("Skip this many top-level instructions before emitting (default 0)"), false},
            {OBFSTR("limit"),    OBFSTR("number"),
             OBFSTR("Maximum top-level instructions to return (default 2000, max 50000)"), false},
        },
        handle_decompile_with_microcode,
        true,
    });

    registry.register_tool({
        OBFSTR("get_microcode_dataflow"),
        OBFSTR("vuln"),
        OBFSTR("Compute the def/use chain at MMAT_LVARS for a single named local variable, "
               "register, or stack slot inside a function. Returns the addresses of every "
               "definition and use, the linear reaching-definition pairs, and any conditional "
               "constraints encountered along the way. Inputs format: 'lvar:NAME', 'lvar:INDEX', "
               "'reg:NAME' (e.g. reg:rax), or 'stk:OFFSET' (decompiler-stkoff in hex)."),
        {
            {OBFSTR("address"),  OBFSTR("string"),
             OBFSTR("Function address (0x...) or function name"), true},
            {OBFSTR("variable"), OBFSTR("string"),
             OBFSTR("Variable spec: lvar:NAME or lvar:INDEX or reg:NAME or stk:OFFSET"), true},
        },
        handle_get_microcode_dataflow,
        true,
    });
}

}
}
}
