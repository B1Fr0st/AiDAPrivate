#include "../aida_pro.hpp"

#include "vuln_tools.hpp"
#include "microcode_engine.hpp"

#include <ida.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <gdl.hpp>
#include <ua.hpp>
#include <allins.hpp>
#include <hexrays.hpp>
#include <demangle.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace aida
{
namespace vuln
{
namespace cfg_engine
{

namespace
{

using nlohmann::json;
using agent_tools::tool_result_t;

constexpr size_t kMaxIndirectCallsPerFunc = 32u;
constexpr size_t kMaxTargetsPerCall = 16u;
constexpr size_t kMaxAllFuncsScan = 4096u;
constexpr size_t kMaxBypassPathDepth = 16u;
constexpr size_t kMaxBypassPathsCap = 64u;
constexpr int    kMaxConstScanBackBytes = 96;

std::string fmt_addr(ea_t ea)
{
    if (ea == BADADDR)
        return std::string(OBFSTR("0x0"));
    return agent_tools::helpers::format_address(ea);
}

std::string name_of(ea_t ea)
{
    if (ea == BADADDR)
        return std::string();
    qstring nm;
    if (get_name(&nm, ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    return std::string();
}

std::string demangle_or_name(ea_t ea)
{
    qstring nm;
    if (get_name(&nm, ea) <= 0 || nm.empty())
        return std::string();
    qstring dem;
    if (demangle_name(&dem, nm.c_str(), 0) > 0 && !dem.empty())
        return std::string(dem.c_str());
    return std::string(nm.c_str());
}

bool ea_in_code_segment(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    segment_t* s = getseg(ea);
    if (!s)
        return false;
    return s->type == SEG_CODE;
}

bool is_indirect_call_insn(const insn_t& ins)
{
    return ins.itype == NN_callni || ins.itype == NN_callfi;
}

bool is_unconditional_jmp(const insn_t& ins)
{
    return ins.itype == NN_jmp;
}

bool is_conditional_jmp(const insn_t& ins)
{
    switch (ins.itype)
    {
    case NN_ja:    case NN_jae:   case NN_jb:    case NN_jbe:
    case NN_jc:    case NN_jcxz:  case NN_jecxz: case NN_jrcxz:
    case NN_je:    case NN_jg:    case NN_jge:   case NN_jl:
    case NN_jle:   case NN_jna:   case NN_jnae:  case NN_jnb:
    case NN_jnbe:  case NN_jnc:   case NN_jne:   case NN_jng:
    case NN_jnge:  case NN_jnl:   case NN_jnle:  case NN_jno:
    case NN_jnp:   case NN_jns:   case NN_jnz:   case NN_jo:
    case NN_jp:    case NN_jpe:   case NN_jpo:   case NN_js:
    case NN_jz:
        return true;
    default:
        return false;
    }
}

void merge_targets(std::vector<indirect_target_t>& dst, indirect_target_t add)
{
    if (add.target_ea == BADADDR && add.name.empty())
        return;
    for (auto& t : dst)
    {
        if (t.target_ea == add.target_ea && t.source == add.source && t.name == add.name)
            return;
    }
    if (dst.size() >= kMaxTargetsPerCall)
        return;
    dst.push_back(std::move(add));
}

void append_reason(std::string& reason, const std::string& tag)
{
    if (reason.empty())
    {
        reason = tag;
        return;
    }
    if (reason.find(tag) != std::string::npos)
        return;
    reason += ',';
    reason += tag;
}

bool resolve_typeinfo(ea_t call_ea, indirect_target_t& out_t)
{
    tinfo_t tif;
    if (!get_tinfo(&tif, call_ea))
        return false;

    tinfo_t pointed = tif;
    if (pointed.is_ptr())
        pointed.remove_ptr_or_array();

    if (!pointed.is_func() && !tif.is_funcptr())
        return false;

    qstring tstr;
    if (pointed.print(&tstr))
    {
        out_t.name = tstr.c_str();
    }
    out_t.source = OBFSTR("typeinfo");
    out_t.rationale = OBFSTR("Operand has function-pointer type info attached");
    out_t.target_ea = BADADDR;
    return true;
}

bool resolve_direct_mem_operand(const insn_t& ins, indirect_target_t& out_t)
{
    const op_t& op = ins.ops[0];
    if (op.type != o_mem)
        return false;
    ea_t slot = static_cast<ea_t>(op.addr);
    if (!is_loaded(slot))
        return false;
    bool is_64 = inf_is_64bit();
    ea_t target = is_64 ? static_cast<ea_t>(get_qword(slot))
                        : static_cast<ea_t>(get_dword(slot));
    if (target == 0 || !is_loaded(target))
        return false;
    if (!ea_in_code_segment(target))
        return false;

    out_t.target_ea = target;
    out_t.name = demangle_or_name(target);
    if (out_t.name.empty())
        out_t.name = name_of(slot);
    out_t.source = OBFSTR("global_fptr");
    out_t.rationale = OBFSTR("Indirect call reads function pointer from a global slot pointing into a code segment");
    return true;
}

void resolve_xrefs(ea_t call_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    xrefblk_t xb;
    int count = 0;
    for (bool ok = xb.first_from(call_ea, XREF_ALL); ok && count < 64; ok = xb.next_from(), ++count)
    {
        if (!xb.iscode)
            continue;
        if (xb.type != fl_CN && xb.type != fl_CF && xb.type != fl_JN && xb.type != fl_JF)
            continue;
        if (!ea_in_code_segment(xb.to))
            continue;
        func_t* tf = get_func(xb.to);
        if (!tf || tf->start_ea != xb.to)
            continue;
        indirect_target_t t;
        t.target_ea = xb.to;
        t.name = demangle_or_name(xb.to);
        t.source = OBFSTR("xref_switch");
        t.rationale = OBFSTR("IDA cross-reference resolved this indirect target (switch table or analyzer trace)");
        size_t before = out.size();
        merge_targets(out, std::move(t));
        if (out.size() != before)
            append_reason(reason, OBFSTR("xref_switch"));
    }
}

bool init_hexrays_safely()
{
    static bool checked = false;
    static bool ok = false;
    if (!checked)
    {
        try
        {
            ok = init_hexrays_plugin();
        }
        catch (...)
        {
            ok = false;
        }
        checked = true;
    }
    return ok;
}

struct vtable_visitor_t : public ctree_visitor_t
{
    ea_t                     target_call_ea = BADADDR;
    bool                     hit_vtable = false;
    bool                     hit_obj_call = false;
    ea_t                     resolved_obj_ea = BADADDR;
    uint32_t                 member_offset = 0;
    int                      ptr_size = 0;

    vtable_visitor_t() : ctree_visitor_t(CV_PARENTS) {}

    int idaapi visit_expr(cexpr_t* e) override
    {
        if (!e || e->op != cot_call || e->ea != target_call_ea)
            return 0;
        cexpr_t* callee = e->x;
        if (!callee)
            return 0;

        cexpr_t* probe = callee;
        while (probe && (probe->op == cot_cast || probe->op == cot_ref))
            probe = probe->x;
        if (!probe)
            return 0;

        if (probe->op == cot_memptr || probe->op == cot_memref)
        {
            hit_vtable = true;
            member_offset = probe->m;
            ptr_size = probe->ptrsize;
            cexpr_t* base = probe->x;
            while (base && (base->op == cot_cast || base->op == cot_ref))
                base = base->x;
            if (base && base->op == cot_obj)
                resolved_obj_ea = base->obj_ea;
            return 1;
        }

        if (probe->op == cot_obj)
        {
            hit_obj_call = true;
            resolved_obj_ea = probe->obj_ea;
            return 1;
        }

        if (probe->op == cot_idx)
        {
            hit_vtable = true;
            cexpr_t* base = probe->x;
            while (base && (base->op == cot_cast || base->op == cot_ref))
                base = base->x;
            if (base && base->op == cot_obj)
                resolved_obj_ea = base->obj_ea;
            return 1;
        }
        return 0;
    }
};

void resolve_via_vtable(ea_t call_ea, ea_t func_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    if (!init_hexrays_safely())
        return;
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return;

    cfuncptr_t cfunc(nullptr);
    try
    {
        cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
    }
    catch (const vd_failure_t&)
    {
        return;
    }
    catch (...)
    {
        return;
    }
    if (!cfunc)
        return;

    vtable_visitor_t vv;
    vv.target_call_ea = call_ea;
    try
    {
        vv.apply_to(&cfunc->body, nullptr);
    }
    catch (...)
    {
        return;
    }

    if (vv.hit_obj_call && vv.resolved_obj_ea != BADADDR)
    {
        if (ea_in_code_segment(vv.resolved_obj_ea))
        {
            indirect_target_t t;
            t.target_ea = vv.resolved_obj_ea;
            t.name = demangle_or_name(vv.resolved_obj_ea);
            t.source = OBFSTR("hexrays_obj");
            t.rationale = OBFSTR("Hex-Rays resolved indirect call to an object whose ea is a code-segment entry");
            size_t before = out.size();
            merge_targets(out, std::move(t));
            if (out.size() != before)
                append_reason(reason, OBFSTR("hexrays_obj"));
            return;
        }
    }

    if (!vv.hit_vtable || vv.resolved_obj_ea == BADADDR)
        return;
    if (!is_loaded(vv.resolved_obj_ea))
        return;

    bool is_64 = inf_is_64bit();
    size_t ptr_sz = is_64 ? 8u : 4u;
    ea_t vtable_base = vv.resolved_obj_ea;

    if (is_64 && is_loaded(vtable_base) && getseg(vtable_base) && getseg(vtable_base)->type != SEG_CODE)
    {
        ea_t maybe = static_cast<ea_t>(get_qword(vtable_base));
        if (is_loaded(maybe) && getseg(maybe) && getseg(maybe)->type != SEG_CODE)
            vtable_base = maybe;
    }

    ea_t entry_ea = vtable_base + static_cast<ea_t>(vv.member_offset);
    if (!is_loaded(entry_ea))
        return;

    ea_t fn_addr = is_64 ? static_cast<ea_t>(get_qword(entry_ea))
                         : static_cast<ea_t>(get_dword(entry_ea));
    if (fn_addr == 0 || !ea_in_code_segment(fn_addr))
    {
        ea_t scan = vtable_base;
        for (size_t i = 0; i < 8 && is_loaded(scan); ++i)
        {
            ea_t v = is_64 ? static_cast<ea_t>(get_qword(scan))
                           : static_cast<ea_t>(get_dword(scan));
            if (v && ea_in_code_segment(v))
            {
                indirect_target_t t;
                t.target_ea = v;
                t.name = demangle_or_name(v);
                t.source = OBFSTR("vtable");
                t.rationale = OBFSTR("Hex-Rays vtable trace: candidate slot ") + fmt_addr(scan);
                size_t before = out.size();
                merge_targets(out, std::move(t));
                if (out.size() != before)
                    append_reason(reason, OBFSTR("vtable"));
            }
            scan += static_cast<ea_t>(ptr_sz);
        }
        return;
    }

    indirect_target_t t;
    t.target_ea = fn_addr;
    t.name = demangle_or_name(fn_addr);
    t.source = OBFSTR("vtable");
    t.rationale = OBFSTR("Hex-Rays resolved vtable slot at ") + fmt_addr(entry_ea);
    size_t before = out.size();
    merge_targets(out, std::move(t));
    if (out.size() != before)
        append_reason(reason, OBFSTR("vtable"));

    ea_t col_ea = is_64 ? (vtable_base >= 8 ? vtable_base - 8 : BADADDR)
                        : (vtable_base >= 4 ? vtable_base - 4 : BADADDR);
    if (col_ea != BADADDR && is_loaded(col_ea))
    {
        ea_t col_ptr = is_64 ? static_cast<ea_t>(get_qword(col_ea))
                             : static_cast<ea_t>(get_dword(col_ea));
        if (is_loaded(col_ptr))
        {
            uint32_t sig = get_dword(col_ptr);
            if (sig == 0u || sig == 1u)
            {
                int32_t td_off = static_cast<int32_t>(get_dword(col_ptr + 12));
                int32_t self_off = static_cast<int32_t>(get_dword(col_ptr + 20));
                uint64_t img_base = static_cast<uint64_t>(col_ptr) - static_cast<uint64_t>(static_cast<int64_t>(self_off));
                ea_t td = static_cast<ea_t>(img_base + static_cast<uint64_t>(static_cast<int64_t>(td_off)));
                if (is_loaded(td + 16))
                {
                    char tname[256] = {};
                    for (int i = 0; i < 255; ++i)
                    {
                        char ch = static_cast<char>(get_byte(td + 16 + static_cast<ea_t>(i)));
                        if (!ch)
                            break;
                        tname[i] = ch;
                    }
                    if (tname[0] != 0)
                    {
                        indirect_target_t r;
                        r.target_ea = BADADDR;
                        r.name = tname;
                        qstring dem;
                        if (demangle_name(&dem, tname, 0) > 0 && !dem.empty())
                            r.name = dem.c_str();
                        r.source = OBFSTR("rtti");
                        r.rationale = OBFSTR("MSVC RTTI class hierarchy descriptor at ") + fmt_addr(col_ptr);
                        size_t before2 = out.size();
                        merge_targets(out, std::move(r));
                        if (out.size() != before2)
                            append_reason(reason, OBFSTR("rtti"));
                    }
                }
            }
        }
    }
}

void resolve_via_microcode(ea_t call_ea, ea_t func_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    auto handle = aida::vuln::microcode::generate(func_ea, MMAT_LVARS);
    if (!handle.has_value() || !handle->mba)
        return;
    mba_t* mba = handle->mba.get();
    int qty = mba->qty;
    for (int b = 0; b < qty; ++b)
    {
        mblock_t* blk = mba->get_mblock(static_cast<uint>(b));
        if (!blk)
            continue;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (m->ea != call_ea)
                continue;
            if (m->opcode != m_icall && m->opcode != m_call)
                continue;
            if (m->opcode == m_call)
                continue;

            if (m->l.t == mop_v && ea_in_code_segment(m->l.g))
            {
                indirect_target_t t;
                t.target_ea = m->l.g;
                t.name = demangle_or_name(m->l.g);
                t.source = OBFSTR("microcode");
                t.rationale = OBFSTR("Microcode call target is a global value (mop_v) in a code segment");
                size_t before = out.size();
                merge_targets(out, std::move(t));
                if (out.size() != before)
                    append_reason(reason, OBFSTR("microcode"));
                continue;
            }

            auto chain = aida::vuln::microcode::def_use_chain(*mba, m->l);
            if (chain.defs.empty())
                continue;

            bool is_64 = inf_is_64bit();

            int probed = 0;
            for (ea_t def_ea : chain.defs)
            {
                if (++probed > 8)
                    break;
                insn_t di;
                if (decode_insn(&di, def_ea) <= 0)
                    continue;
                for (int oi = 0; oi < UA_MAXOP; ++oi)
                {
                    const op_t& op = di.ops[oi];
                    if (op.type == o_void)
                        break;
                    ea_t cand = BADADDR;
                    if (op.type == o_imm)
                        cand = static_cast<ea_t>(op.value);
                    else if (op.type == o_mem)
                    {
                        ea_t slot = static_cast<ea_t>(op.addr);
                        if (is_loaded(slot))
                        {
                            cand = is_64 ? static_cast<ea_t>(get_qword(slot))
                                         : static_cast<ea_t>(get_dword(slot));
                        }
                    }
                    if (cand == BADADDR || cand == 0)
                        continue;
                    if (!ea_in_code_segment(cand))
                        continue;
                    func_t* tf = get_func(cand);
                    if (!tf || tf->start_ea != cand)
                        continue;
                    indirect_target_t t;
                    t.target_ea = cand;
                    t.name = demangle_or_name(cand);
                    t.source = OBFSTR("microcode_ssa");
                    t.rationale = OBFSTR("Microcode SSA def-use trace from call operand to constant function pointer at ") + fmt_addr(def_ea);
                    size_t before = out.size();
                    merge_targets(out, std::move(t));
                    if (out.size() != before)
                        append_reason(reason, OBFSTR("microcode_ssa"));
                }
                if (out.size() >= kMaxTargetsPerCall)
                    break;
            }
        }
    }
}

void resolve_via_constant_pool(ea_t call_ea, ea_t func_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return;
    ea_t lo = pfn->start_ea;
    ea_t scan = call_ea;
    int budget = kMaxConstScanBackBytes;
    int hits = 0;
    while (scan > lo && budget > 0 && hits < 8)
    {
        ea_t prev = prev_head(scan, lo);
        if (prev == BADADDR || prev < lo)
            break;
        budget -= static_cast<int>(scan - prev);
        scan = prev;
        insn_t di;
        if (decode_insn(&di, prev) <= 0)
            continue;
        if (di.itype != NN_lea && di.itype != NN_mov)
            continue;
        for (int oi = 0; oi < UA_MAXOP; ++oi)
        {
            const op_t& op = di.ops[oi];
            if (op.type == o_void)
                break;
            ea_t cand = BADADDR;
            if (op.type == o_mem || op.type == o_far || op.type == o_near)
                cand = static_cast<ea_t>(op.addr);
            else if (op.type == o_imm)
                cand = static_cast<ea_t>(op.value);
            if (cand == BADADDR || cand == 0)
                continue;
            if (!ea_in_code_segment(cand))
                continue;
            func_t* tf = get_func(cand);
            if (!tf || tf->start_ea != cand)
                continue;
            indirect_target_t t;
            t.target_ea = cand;
            t.name = demangle_or_name(cand);
            t.source = OBFSTR("const_lea");
            t.rationale = OBFSTR("Backwards scan found lea/mov of code address ") + fmt_addr(cand) + OBFSTR(" at ") + fmt_addr(prev);
            size_t before = out.size();
            merge_targets(out, std::move(t));
            if (out.size() != before)
            {
                append_reason(reason, OBFSTR("const_lea"));
                ++hits;
            }
        }
    }
}

indirect_call_t analyze_indirect_call(ea_t call_ea, ea_t func_ea, const insn_t& ins)
{
    indirect_call_t ic;
    ic.call_ea = call_ea;
    ic.func_ea = func_ea;

    if (ins.ops[0].type == o_mem)
    {
        indirect_target_t direct;
        if (resolve_direct_mem_operand(ins, direct))
        {
            merge_targets(ic.targets, std::move(direct));
            append_reason(ic.reason, OBFSTR("global_fptr"));
        }
    }

    indirect_target_t ti;
    if (resolve_typeinfo(call_ea, ti))
    {
        merge_targets(ic.targets, std::move(ti));
        append_reason(ic.reason, OBFSTR("typeinfo"));
    }

    resolve_xrefs(call_ea, ic.targets, ic.reason);
    resolve_via_vtable(call_ea, func_ea, ic.targets, ic.reason);
    resolve_via_constant_pool(call_ea, func_ea, ic.targets, ic.reason);
    resolve_via_microcode(call_ea, func_ea, ic.targets, ic.reason);

    if (ic.reason.empty())
        ic.reason = OBFSTR("unresolved");

    return ic;
}

std::vector<indirect_call_t> scan_function(ea_t func_ea)
{
    std::vector<indirect_call_t> out;
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return out;

    func_item_iterator_t fii(pfn);
    size_t found = 0;
    for (bool ok = fii.first(); ok && found < kMaxIndirectCallsPerFunc; ok = fii.next_head())
    {
        ea_t cur = fii.current();
        insn_t ins;
        if (decode_insn(&ins, cur) <= 0)
            continue;
        if (!is_indirect_call_insn(ins))
            continue;
        indirect_call_t ic = analyze_indirect_call(cur, pfn->start_ea, ins);
        out.push_back(std::move(ic));
        ++found;
    }
    return out;
}

json target_to_json(const indirect_target_t& t)
{
    json j;
    j["target_ea"] = fmt_addr(t.target_ea);
    j["name"]      = t.name;
    j["source"]    = t.source;
    j["rationale"] = t.rationale;
    return j;
}

json call_to_json(const indirect_call_t& ic)
{
    json j;
    j["call_ea"]   = fmt_addr(ic.call_ea);
    j["func_ea"]   = fmt_addr(ic.func_ea);
    qstring fnm;
    if (get_func_name(&fnm, ic.func_ea) > 0 && !fnm.empty())
        j["func_name"] = fnm.c_str();
    else
        j["func_name"] = name_of(ic.func_ea);
    json arr = json::array();
    for (const auto& t : ic.targets)
        arr.push_back(target_to_json(t));
    j["targets"] = std::move(arr);
    j["reason"]  = ic.reason;
    return j;
}

int find_block_containing(const qflow_chart_t& fc, ea_t ea)
{
    int n = fc.size();
    for (int i = 0; i < n; ++i)
    {
        const qbasic_block_t& bb = fc.blocks[i];
        if (ea >= bb.start_ea && ea < bb.end_ea)
            return i;
    }
    return -1;
}

ea_t block_terminator_ea(const qflow_chart_t& fc, int idx)
{
    if (idx < 0 || idx >= fc.size())
        return BADADDR;
    const qbasic_block_t& bb = fc.blocks[idx];
    if (bb.start_ea >= bb.end_ea)
        return BADADDR;
    ea_t scan = bb.end_ea;
    func_t* pfn = fc.pfn;
    ea_t lo = pfn ? pfn->start_ea : bb.start_ea;
    ea_t prev = prev_head(scan, lo);
    if (prev == BADADDR || prev < bb.start_ea)
        return BADADDR;
    return prev;
}

std::string describe_branch_kind(const qflow_chart_t& fc, int from_idx, int to_idx, int avoid_idx)
{
    ea_t term_ea = block_terminator_ea(fc, from_idx);
    if (term_ea == BADADDR)
        return std::string(OBFSTR("fallthrough"));
    insn_t ins;
    if (decode_insn(&ins, term_ea) <= 0)
        return std::string(OBFSTR("fallthrough"));
    if (is_unconditional_jmp(ins))
        return OBFSTR("unconditional_jmp@") + fmt_addr(term_ea);
    if (is_conditional_jmp(ins))
    {
        ea_t taken = static_cast<ea_t>(ins.ops[0].addr);
        const qbasic_block_t& tgt = fc.blocks[to_idx];
        const qbasic_block_t& bypassed = fc.blocks[avoid_idx];
        bool taken_to_tgt = (taken >= tgt.start_ea && taken < tgt.end_ea);
        bool taken_to_avoid = (taken >= bypassed.start_ea && taken < bypassed.end_ea);
        if (taken_to_tgt)
            return OBFSTR("true_branch_at_") + fmt_addr(term_ea);
        if (taken_to_avoid)
            return OBFSTR("false_branch_at_") + fmt_addr(term_ea);
        return OBFSTR("conditional_at_") + fmt_addr(term_ea);
    }
    if (ins.itype == NN_call || ins.itype == NN_callni || ins.itype == NN_callfi)
        return OBFSTR("post_call_at_") + fmt_addr(term_ea);
    return OBFSTR("flow_at_") + fmt_addr(term_ea);
}

std::vector<ea_t> collect_block_eas(const qflow_chart_t& fc, int idx)
{
    std::vector<ea_t> out;
    if (idx < 0 || idx >= fc.size())
        return out;
    const qbasic_block_t& bb = fc.blocks[idx];
    if (bb.start_ea >= bb.end_ea)
        return out;
    func_t* pfn = fc.pfn;
    func_item_iterator_t fii;
    if (pfn)
        fii.set(pfn, bb.start_ea);
    else
        fii.set_range(bb.start_ea, bb.end_ea);
    if (fii.current() < bb.start_ea)
        fii.set_ea(bb.start_ea);
    out.push_back(bb.start_ea);
    while (fii.next_head())
    {
        ea_t cur = fii.current();
        if (cur >= bb.end_ea)
            break;
        out.push_back(cur);
        if (out.size() > 256)
            break;
    }
    return out;
}

void enumerate_paths(const qflow_chart_t& fc,
                     int entry,
                     int sink,
                     int avoid,
                     size_t max_paths,
                     std::vector<std::vector<int>>& paths)
{
    if (entry == avoid)
        return;
    int qty = fc.size();
    if (qty <= 0)
        return;

    std::vector<int> path;
    std::vector<bool> on_path(static_cast<size_t>(qty), false);

    std::function<void(int)> dfs = [&](int node)
    {
        if (paths.size() >= max_paths)
            return;
        if (node == avoid)
            return;
        if (path.size() > kMaxBypassPathDepth)
            return;
        if (on_path[static_cast<size_t>(node)])
            return;
        path.push_back(node);
        on_path[static_cast<size_t>(node)] = true;

        if (node == sink)
        {
            paths.push_back(path);
        }
        else
        {
            int succ_n = fc.nsucc(node);
            for (int s = 0; s < succ_n && paths.size() < max_paths; ++s)
            {
                int next = fc.succ(node, s);
                if (next < 0 || next >= qty)
                    continue;
                if (next == avoid)
                    continue;
                if (on_path[static_cast<size_t>(next)])
                    continue;
                dfs(next);
            }
        }

        on_path[static_cast<size_t>(node)] = false;
        path.pop_back();
    };

    dfs(entry);
}

int dom_intersect(const std::vector<int>& postdom,
                  const std::vector<int>& postorder_index,
                  int b1, int b2)
{
    int finger1 = b1;
    int finger2 = b2;
    while (finger1 != finger2)
    {
        if (finger1 < 0 || finger2 < 0)
            return -1;
        while (finger1 != finger2 && postorder_index[static_cast<size_t>(finger1)] < postorder_index[static_cast<size_t>(finger2)])
        {
            int next = postdom[static_cast<size_t>(finger1)];
            if (next == finger1 || next < 0)
                return -1;
            finger1 = next;
        }
        while (finger1 != finger2 && postorder_index[static_cast<size_t>(finger2)] < postorder_index[static_cast<size_t>(finger1)])
        {
            int next = postdom[static_cast<size_t>(finger2)];
            if (next == finger2 || next < 0)
                return -1;
            finger2 = next;
        }
    }
    return finger1;
}

void compute_postorder_reverse(int virtual_exit_id, int total,
                               const std::vector<std::vector<int>>& reverse_succ,
                               std::vector<int>& reverse_postorder)
{
    std::vector<bool> visited(static_cast<size_t>(total), false);
    std::vector<int> stack;
    std::vector<int> idx_stack;
    stack.push_back(virtual_exit_id);
    idx_stack.push_back(0);
    visited[static_cast<size_t>(virtual_exit_id)] = true;
    while (!stack.empty())
    {
        int u = stack.back();
        int& it = idx_stack.back();
        const auto& succs = reverse_succ[static_cast<size_t>(u)];
        if (it < static_cast<int>(succs.size()))
        {
            int v = succs[static_cast<size_t>(it++)];
            if (!visited[static_cast<size_t>(v)])
            {
                visited[static_cast<size_t>(v)] = true;
                stack.push_back(v);
                idx_stack.push_back(0);
            }
        }
        else
        {
            reverse_postorder.push_back(u);
            stack.pop_back();
            idx_stack.pop_back();
        }
    }
    std::reverse(reverse_postorder.begin(), reverse_postorder.end());
}

std::vector<int> compute_post_dominators(const qflow_chart_t& fc)
{
    int qty = fc.size();
    int virtual_exit_id = qty;
    int total = qty + 1;

    std::vector<std::vector<int>> reverse_succ(static_cast<size_t>(total));
    for (int i = 0; i < qty; ++i)
    {
        int sn = fc.nsucc(i);
        if (sn == 0)
        {
            reverse_succ[static_cast<size_t>(virtual_exit_id)].push_back(i);
        }
        else
        {
            for (int s = 0; s < sn; ++s)
            {
                int next = fc.succ(i, s);
                if (next < 0 || next >= qty)
                    continue;
                reverse_succ[static_cast<size_t>(next)].push_back(i);
            }
        }
    }

    std::vector<int> rpo;
    rpo.reserve(static_cast<size_t>(total));
    compute_postorder_reverse(virtual_exit_id, total, reverse_succ, rpo);

    std::vector<int> postorder_index(static_cast<size_t>(total), -1);
    for (int i = static_cast<int>(rpo.size()) - 1; i >= 0; --i)
    {
        int node = rpo[static_cast<size_t>(i)];
        postorder_index[static_cast<size_t>(node)] = static_cast<int>(rpo.size()) - 1 - i;
    }

    std::vector<int> postdom(static_cast<size_t>(total), -1);
    postdom[static_cast<size_t>(virtual_exit_id)] = virtual_exit_id;

    bool changed = true;
    int safety = 0;
    while (changed && safety < 4096)
    {
        changed = false;
        ++safety;
        for (int node : rpo)
        {
            if (node == virtual_exit_id)
                continue;
            int new_idom = -1;
            int sn = (node < qty) ? fc.nsucc(node) : 0;
            std::vector<int> succs;
            if (node < qty)
            {
                if (sn == 0)
                {
                    succs.push_back(virtual_exit_id);
                }
                else
                {
                    for (int s = 0; s < sn; ++s)
                    {
                        int next = fc.succ(node, s);
                        if (next < 0 || next >= qty)
                            continue;
                        succs.push_back(next);
                    }
                }
            }
            for (int succ : succs)
            {
                if (postdom[static_cast<size_t>(succ)] == -1)
                    continue;
                if (new_idom == -1)
                    new_idom = succ;
                else
                    new_idom = dom_intersect(postdom, postorder_index, succ, new_idom);
                if (new_idom == -1)
                    break;
            }
            if (new_idom != -1 && postdom[static_cast<size_t>(node)] != new_idom)
            {
                postdom[static_cast<size_t>(node)] = new_idom;
                changed = true;
            }
        }
    }
    return postdom;
}

bool postdom_dominates(const std::vector<int>& postdom, int from, int to)
{
    if (from < 0 || to < 0)
        return false;
    int virt = static_cast<int>(postdom.size()) - 1;
    int cur = from;
    int safety = 0;
    while (cur != -1 && cur != virt && safety < 4096)
    {
        if (cur == to)
            return true;
        int next = postdom[static_cast<size_t>(cur)];
        if (next == cur)
            break;
        cur = next;
        ++safety;
    }
    return false;
}

std::string build_path_rationale(const qflow_chart_t& fc,
                                 const std::vector<int>& path_blocks,
                                 int check_block,
                                 ea_t check_ea,
                                 ea_t sink_ea)
{
    std::string r;
    r += OBFSTR("Path enters function at block 0 and reaches sink ");
    r += fmt_addr(sink_ea);
    r += OBFSTR(" without traversing block ");
    r += std::to_string(check_block);
    r += OBFSTR(" (which contains the check at ");
    r += fmt_addr(check_ea);
    r += OBFSTR("). ");

    for (size_t i = 0; i + 1 < path_blocks.size(); ++i)
    {
        int from_b = path_blocks[i];
        int to_b   = path_blocks[i + 1];
        bool from_branches_to_check = false;
        int sn = fc.nsucc(from_b);
        for (int s = 0; s < sn; ++s)
        {
            if (fc.succ(from_b, s) == check_block)
            {
                from_branches_to_check = true;
                break;
            }
        }
        if (!from_branches_to_check)
            continue;
        std::string kind = describe_branch_kind(fc, from_b, to_b, check_block);
        r += OBFSTR("Block ");
        r += std::to_string(from_b);
        r += OBFSTR(" routes to block ");
        r += std::to_string(to_b);
        r += OBFSTR(" via ");
        r += kind;
        r += OBFSTR(" instead of the check block. ");
    }

    if (!path_blocks.empty())
    {
        int last_b = path_blocks.back();
        if (fc.is_ret_block(static_cast<size_t>(last_b)))
            r += OBFSTR("Path terminates in a return block. ");
        else if (fc.is_noret_block(static_cast<size_t>(last_b)))
            r += OBFSTR("Path terminates in a noret block (early-return bypass). ");
    }

    return r;
}

tool_result_t handler_find_indirect_call_targets(const json& params)
{
    std::string addr_param = params.value("address", std::string());
    bool scan_all = false;
    ea_t target_func_ea = BADADDR;
    if (addr_param.empty() || addr_param == OBFSTR("all") || addr_param == OBFSTR("ALL"))
    {
        scan_all = true;
    }
    else
    {
        auto parsed = agent_tools::helpers::parse_address(addr_param);
        if (!parsed)
            return tool_result_t::error(OBFSTR("Invalid address"));
        target_func_ea = *parsed;
    }

    json calls = json::array();
    size_t total_calls = 0;

    if (scan_all)
    {
        size_t fq = get_func_qty();
        size_t scanned = 0;
        for (size_t i = 0; i < fq && scanned < kMaxAllFuncsScan; ++i)
        {
            func_t* pfn = getn_func(i);
            if (!pfn)
                continue;
            ++scanned;
            auto v = scan_function(pfn->start_ea);
            for (auto& ic : v)
            {
                calls.push_back(call_to_json(ic));
                ++total_calls;
            }
        }
    }
    else
    {
        func_t* pfn = get_func(target_func_ea);
        if (!pfn)
            return tool_result_t::error(OBFSTR("No function at ") + agent_tools::helpers::format_address(target_func_ea));
        auto v = scan_function(pfn->start_ea);
        for (auto& ic : v)
        {
            calls.push_back(call_to_json(ic));
            ++total_calls;
        }
    }

    json result;
    result["count"] = total_calls;
    result["calls"] = std::move(calls);
    sanitize_json_utf8_inplace(result);
    return tool_result_t::ok(OBFSTR("Indirect call targets: ") + std::to_string(total_calls), result);
}

tool_result_t handler_find_check_bypass_paths(const json& params)
{
    std::string ca = params.value("check_address", std::string());
    std::string sa = params.value("sink_address", std::string());
    int max_paths = params.value("max_paths", 8);
    if (max_paths <= 0)
        max_paths = 8;
    if (static_cast<size_t>(max_paths) > kMaxBypassPathsCap)
        max_paths = static_cast<int>(kMaxBypassPathsCap);

    auto pca = agent_tools::helpers::parse_address(ca);
    auto psa = agent_tools::helpers::parse_address(sa);
    if (!pca || !psa)
        return tool_result_t::error(OBFSTR("Invalid check_address or sink_address"));

    ea_t check_ea = *pca;
    ea_t sink_ea  = *psa;

    auto paths = aida::vuln::cfg_engine::find_bypass_paths(check_ea, sink_ea);
    if (static_cast<int>(paths.size()) > max_paths)
        paths.resize(static_cast<size_t>(max_paths));

    json arr = json::array();
    for (const auto& p : paths)
    {
        json pj;
        pj["func_ea"]  = fmt_addr(p.func_ea);
        pj["check_ea"] = fmt_addr(p.check_ea);
        pj["sink_ea"]  = fmt_addr(p.sink_ea);
        json bp = json::array();
        for (ea_t e : p.block_path)
            bp.push_back(fmt_addr(e));
        json eat = json::array();
        for (ea_t e : p.ea_trace)
            eat.push_back(fmt_addr(e));
        pj["block_path"] = std::move(bp);
        pj["ea_trace"]   = std::move(eat);
        pj["rationale"]  = p.rationale;
        arr.push_back(std::move(pj));
    }

    json result;
    result["count"] = arr.size();
    result["paths"] = std::move(arr);
    sanitize_json_utf8_inplace(result);
    return tool_result_t::ok(OBFSTR("Bypass paths: ") + std::to_string(result["count"].get<size_t>()), result);
}

}

std::vector<indirect_call_t> find_indirect_calls(ea_t func_ea)
{
    std::vector<indirect_call_t> out;
    if (func_ea == BADADDR)
    {
        size_t fq = get_func_qty();
        size_t scanned = 0;
        for (size_t i = 0; i < fq && scanned < kMaxAllFuncsScan; ++i)
        {
            func_t* pfn = getn_func(i);
            if (!pfn)
                continue;
            ++scanned;
            auto v = scan_function(pfn->start_ea);
            for (auto& ic : v)
                out.push_back(std::move(ic));
        }
        return out;
    }
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return out;
    return scan_function(pfn->start_ea);
}

std::vector<bypass_path_t> find_bypass_paths(ea_t check_ea, ea_t sink_ea)
{
    std::vector<bypass_path_t> out;
    func_t* pcheck = get_func(check_ea);
    func_t* psink  = get_func(sink_ea);
    if (!pcheck || !psink)
        return out;
    if (pcheck->start_ea != psink->start_ea)
        return out;

    qflow_chart_t fc;
    fc.create("", pcheck, BADADDR, BADADDR, FC_RESERVED);
    if (fc.size() <= 0)
        return out;

    int check_block = find_block_containing(fc, check_ea);
    int sink_block  = find_block_containing(fc, sink_ea);
    int entry_block = 0;
    if (check_block < 0 || sink_block < 0)
        return out;
    if (check_block == sink_block)
        return out;
    if (entry_block == check_block)
        return out;

    std::vector<std::vector<int>> paths;
    enumerate_paths(fc, entry_block, sink_block, check_block, kMaxBypassPathsCap, paths);

    for (const auto& bp : paths)
    {
        bypass_path_t bpp;
        bpp.func_ea  = pcheck->start_ea;
        bpp.check_ea = check_ea;
        bpp.sink_ea  = sink_ea;
        bpp.block_path.reserve(bp.size());
        bpp.ea_trace.reserve(bp.size() * 8);
        for (int b : bp)
        {
            if (b < 0 || b >= fc.size())
                continue;
            bpp.block_path.push_back(fc.blocks[b].start_ea);
            auto eas = collect_block_eas(fc, b);
            for (ea_t e : eas)
            {
                if (bpp.ea_trace.size() >= 4096u)
                    break;
                bpp.ea_trace.push_back(e);
            }
        }
        bpp.rationale = build_path_rationale(fc, bp, check_block, check_ea, sink_ea);
        out.push_back(std::move(bpp));
    }

    return out;
}

bool block_post_dominates(ea_t func_ea, int from_block, int to_block)
{
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return false;
    qflow_chart_t fc;
    fc.create("", pfn, BADADDR, BADADDR, FC_RESERVED);
    int qty = fc.size();
    if (qty <= 0)
        return false;
    if (from_block < 0 || from_block >= qty)
        return false;
    if (to_block < 0 || to_block >= qty)
        return false;
    if (from_block == to_block)
        return true;

    std::vector<int> postdom = compute_post_dominators(fc);
    if (postdom.size() != static_cast<size_t>(qty + 1))
        return false;
    return postdom_dominates(postdom, from_block, to_block);
}

void register_tier1_cfg_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        OBFSTR("find_indirect_call_targets"),
        OBFSTR("vuln"),
        OBFSTR("Enumerate every indirect call (callni/callfi/register/memory) in the given function (or 'all' to scan every function) and resolve targets via type-info, IDA xrefs, vtables (Hex-Rays), constant pool scans, microcode SSA def-use, and MSVC RTTI. Returns per-call resolved-target arrays plus the resolution method that succeeded."),
        {
            { OBFSTR("address"), OBFSTR("string"), OBFSTR("Function ea (0x...) or 'all' to scan every function"), true }
        },
        handler_find_indirect_call_targets,
        true
    });

    registry.register_tool({
        OBFSTR("find_check_bypass_paths"),
        OBFSTR("vuln"),
        OBFSTR("Enumerate paths through the function CFG that route AROUND a specific check (its block excluded from BFS/DFS) and still reach a sink. Both check_address and sink_address must be inside the same function. Returns block paths, ea traces, and a rationale describing how each path bypasses the check (true/false branch of a conditional, unconditional jmp, post-call edge, early-return)."),
        {
            { OBFSTR("check_address"), OBFSTR("string"), OBFSTR("Address of the check / validator instruction"), true },
            { OBFSTR("sink_address"),  OBFSTR("string"), OBFSTR("Address of the sink the attacker wants to reach"), true },
            { OBFSTR("max_paths"),     OBFSTR("number"), OBFSTR("Max paths to return (default 8, max 64)"),         false }
        },
        handler_find_check_bypass_paths,
        true
    });
}

}
}
}
