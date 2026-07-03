#include "../aida_pro.hpp"

#include "chain_extraction.hpp"
#include "microcode_engine.hpp"

#include "../ida_utils.hpp"

#include <allins.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <entry.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <hexrays.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

using nlohmann::json;

constexpr std::uint64_t k_fnv_offset = 1469598103934665603ull;
constexpr std::uint64_t k_fnv_prime = 1099511628211ull;

std::uint64_t now_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::string hex_u64(std::uint64_t v)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << v;
    return ss.str();
}

std::string hex_bytes(const std::vector<std::uint8_t>& bytes)
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (std::uint8_t b : bytes)
        ss << std::setw(2) << static_cast<unsigned>(b);
    return ss.str();
}

void fnv_append(std::uint64_t& hash, const void* data, std::size_t size)
{
    const auto* p = static_cast<const std::uint8_t*>(data);
    for (std::size_t i = 0; i < size; ++i)
    {
        hash ^= p[i];
        hash *= k_fnv_prime;
    }
}

void fnv_append(std::uint64_t& hash, const std::string& s)
{
    fnv_append(hash, s.data(), s.size());
}

void fnv_append(std::uint64_t& hash, std::uint64_t v)
{
    fnv_append(hash, &v, sizeof(v));
}

void fnv_append(std::uint64_t& hash, std::uint32_t v)
{
    fnv_append(hash, &v, sizeof(v));
}

std::string fnv_hex(std::uint64_t hash)
{
    std::ostringstream ss;
    ss << "fnv1a64:" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << hash;
    return ss.str();
}

std::string qstring_to_string(const qstring& s)
{
    return s.empty() ? std::string() : std::string(s.c_str());
}

std::string strip_tags(const qstring& in)
{
    qstring clean;
    tag_remove(&clean, in);
    return qstring_to_string(clean);
}

std::string fixed_buffer_to_string(const char* data)
{
    return data != nullptr && data[0] != '\0' ? std::string(data) : std::string();
}

std::string hash_to_hex(const uchar* data, std::size_t size)
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i)
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    return ss.str();
}

std::string lower_ascii(std::string s)
{
    for (char& c : s)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    }
    return s;
}

std::string name_at(ea_t ea, int flags = GN_VISIBLE)
{
    if (ea == BADADDR)
        return {};
    qstring qn;
    if (get_name(&qn, ea, flags) > 0 && !qn.empty())
        return qstring_to_string(qn);
    return {};
}

std::string demangled_at(ea_t ea)
{
    if (ea == BADADDR)
        return {};
    qstring qn;
    if (get_name(&qn, ea, GN_VISIBLE) <= 0 || qn.empty())
        return {};
    qstring dem;
    if (demangle_name(&dem, qn.c_str(), 0) > 0 && !dem.empty())
        return qstring_to_string(dem);
    qstring dem_name;
    if (get_name(&dem_name, ea, GN_VISIBLE | GN_DEMANGLED | GN_SHORT) > 0 && !dem_name.empty())
        return qstring_to_string(dem_name);
    return qstring_to_string(qn);
}

std::string func_name_at(ea_t ea)
{
    if (ea == BADADDR)
        return {};
    qstring qn;
    if (get_func_name(&qn, ea) > 0 && !qn.empty())
        return qstring_to_string(qn);
    return name_at(ea);
}

std::string disasm_line(ea_t ea)
{
    qstring line;
    if (!generate_disasm_line(&line, ea, GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS))
        return {};
    return qstring_to_string(line);
}

std::string operand_text(ea_t ea, int n)
{
    qstring out;
    if (!print_operand(&out, ea, n))
        return {};
    return strip_tags(out);
}

std::string insn_mnemonic(ea_t ea)
{
    qstring out;
    if (print_insn_mnem(&out, ea) && !out.empty())
        return qstring_to_string(out);
    return {};
}

std::uint32_t dtype_bits(op_dtype_t dtype)
{
    switch (dtype)
    {
    case dt_byte:   return 8;
    case dt_word:   return 16;
    case dt_dword:  return 32;
    case dt_qword:  return 64;
    case dt_byte16: return 128;
    case dt_byte32: return 256;
    case dt_byte64: return 512;
    case dt_fword:  return 48;
    case dt_half:   return 16;
    case dt_float:  return 32;
    case dt_double: return 64;
    case dt_ldbl:
    case dt_tbyte:  return 80;
    default:        return 0;
    }
}

std::string op_type_name(optype_t type)
{
    switch (type)
    {
    case o_void:   return "void";
    case o_reg:    return "reg";
    case o_mem:    return "mem";
    case o_phrase: return "phrase";
    case o_displ:  return "displ";
    case o_imm:    return "imm";
    case o_far:    return "far";
    case o_near:   return "near";
    default:       return "unknown";
    }
}

layer_status_t make_status(const std::string& layer,
                           layer_state_t state,
                           const std::string& reason,
                           std::uint64_t start_ms,
                           std::size_t emitted = 0,
                           std::size_t total = 0)
{
    layer_status_t status;
    status.layer = layer;
    status.state = state;
    status.reason = reason;
    status.elapsed_ms = now_ms() - start_ms;
    status.emitted = emitted;
    status.total = total;
    return status;
}

module_identity_t current_module_identity()
{
    module_identity_t out;
    std::array<char, 4096> buf{};
    if (get_root_filename(buf.data(), buf.size()) > 0)
        out.module_name = fixed_buffer_to_string(buf.data());
    buf.fill('\0');
    if (get_input_file_path(buf.data(), buf.size()) > 0)
        out.input_path = fixed_buffer_to_string(buf.data());
    uchar md5[16] = {};
    if (retrieve_input_file_md5(md5))
        out.input_md5 = hash_to_hex(md5, sizeof(md5));
    uchar sha256[32] = {};
    if (retrieve_input_file_sha256(sha256))
        out.input_sha256 = hash_to_hex(sha256, sizeof(sha256));
    out.image_base = static_cast<std::uint64_t>(get_imagebase());
    out.min_ea = static_cast<std::uint64_t>(inf_get_min_ea());
    out.max_ea = static_cast<std::uint64_t>(inf_get_max_ea());
    out.pointer_width_bits = inf_is_64bit() ? 64u : (inf_is_32bit_or_higher() ? 32u : 16u);
    out.big_endian = inf_is_be();
    qstring proc = inf_get_procname();
    out.processor = qstring_to_string(proc);
    if (!out.input_sha256.empty())
        out.module_id = "sha256:" + lower_ascii(out.input_sha256);
    else if (!out.input_md5.empty())
        out.module_id = "md5:" + lower_ascii(out.input_md5);
    else if (!out.input_path.empty())
        out.module_id = "path:" + lower_ascii(out.input_path);
    else
        out.module_id = "name:" + lower_ascii(out.module_name);
    return out;
}

bool rva_for(const module_identity_t& module, ea_t ea, std::uint64_t& rva)
{
    if (ea == BADADDR)
        return false;
    if (module.image_base == 0)
        return false;
    const auto raw = static_cast<std::uint64_t>(ea);
    if (raw < module.image_base)
        return false;
    rva = raw - module.image_base;
    return true;
}

address_identity_t address_for(ea_t ea, const module_identity_t& module)
{
    address_identity_t out;
    out.module = module;
    out.ea = ea == BADADDR ? 0 : static_cast<std::uint64_t>(ea);
    out.has_rva = rva_for(module, ea, out.rva);
    segment_t* seg = ea == BADADDR ? nullptr : getseg(ea);
    if (seg != nullptr)
    {
        qstring sn;
        if (get_segm_name(&sn, seg) > 0)
            out.segment_name = qstring_to_string(sn);
        qstring sc;
        if (get_segm_class(&sc, seg) > 0)
            out.segment_class = qstring_to_string(sc);
        out.segment_permissions = seg->perm;
    }
    out.symbol_name = name_at(ea);
    out.demangled_name = demangled_at(ea);
    func_t* fn = ea == BADADDR ? nullptr : get_func(ea);
    if (fn != nullptr)
    {
        out.function_ea = static_cast<std::uint64_t>(fn->start_ea);
        std::uint64_t frva = 0;
        if (rva_for(module, fn->start_ea, frva))
            out.function_rva = frva;
        out.function_name = func_name_at(fn->start_ea);
    }
    return out;
}

segment_fact_t segment_to_fact(const segment_t& seg, const module_identity_t& module)
{
    segment_fact_t out;
    qstring name;
    if (get_segm_name(&name, &seg) > 0)
        out.name = qstring_to_string(name);
    qstring klass;
    if (get_segm_class(&klass, &seg) > 0)
        out.klass = qstring_to_string(klass);
    out.start_ea = static_cast<std::uint64_t>(seg.start_ea);
    out.end_ea = static_cast<std::uint64_t>(seg.end_ea);
    rva_for(module, seg.start_ea, out.start_rva);
    rva_for(module, seg.end_ea, out.end_rva);
    out.permissions = seg.perm;
    out.type = seg.type;
    return out;
}

std::vector<xref_fact_t> collect_xrefs(ea_t ea,
                                       const std::string& direction,
                                       const module_identity_t& module,
                                       std::size_t limit)
{
    std::vector<xref_fact_t> out;
    xrefblk_t xb;
    bool ok = direction == "from" ? xb.first_from(ea, XREF_ALL) : xb.first_to(ea, XREF_ALL);
    while (ok && out.size() < limit)
    {
        xref_fact_t xf;
        xf.from = address_for(xb.from, module);
        xf.to = address_for(xb.to, module);
        xf.is_code = xb.iscode;
        xf.user = xb.user;
        xf.type = xb.type;
        xf.direction = direction;
        xf.source_disasm = disasm_line(xb.from);
        out.push_back(std::move(xf));
        ok = direction == "from" ? xb.next_from() : xb.next_to();
    }
    return out;
}

void append_unique_xref(std::vector<xref_fact_t>& dst, const xref_fact_t& xref, std::set<std::string>& seen)
{
    std::string key = xref.direction + ":" + std::to_string(xref.from.ea) + ":" + std::to_string(xref.to.ea) + ":" + std::to_string(xref.type);
    if (!seen.insert(key).second)
        return;
    dst.push_back(xref);
}

std::vector<std::uint8_t> read_bytes(ea_t ea, std::size_t size)
{
    std::vector<std::uint8_t> out;
    if (ea == BADADDR || size == 0)
        return out;
    out.resize(size);
    ssize_t got = get_bytes(out.data(), static_cast<ssize_t>(out.size()), ea, GMB_READALL);
    if (got <= 0)
    {
        out.clear();
        return out;
    }
    if (static_cast<std::size_t>(got) < out.size())
        out.resize(static_cast<std::size_t>(got));
    return out;
}

operand_fact_t operand_to_fact(const insn_t& ins, const op_t& op, const module_identity_t& module)
{
    operand_fact_t out;
    out.index = op.n;
    out.type_id = static_cast<std::uint32_t>(op.type);
    out.type = op_type_name(op.type);
    out.dtype = static_cast<std::uint32_t>(op.dtype);
    out.width_bits = dtype_bits(op.dtype);
    out.reg = op.reg;
    out.phrase = op.phrase;
    out.value = static_cast<std::uint64_t>(op.value);
    out.address = static_cast<std::uint64_t>(op.addr);
    out.specval = static_cast<std::uint64_t>(op.specval);
    out.flags = op.flags;
    out.shown = op.shown();
    out.text = operand_text(ins.ea, op.n);
    if (op.type == o_mem || op.type == o_displ || op.type == o_far || op.type == o_near)
        out.address_identity = address_for(op.addr, module);
    return out;
}

bool branch_feature(const insn_t& ins)
{
    if (is_call_insn(ins) || is_ret_insn(ins))
        return false;
    return has_insn_feature(ins.itype, CF_JUMP) || ins.ops[0].type == o_near || ins.ops[0].type == o_far;
}

bool indirect_feature(const insn_t& ins)
{
    if (has_insn_feature(ins.itype, CF_JUMP))
        return true;
    if (is_call_insn(ins))
        return ins.ops[0].type != o_near && ins.ops[0].type != o_far;
    return branch_feature(ins) && ins.ops[0].type != o_near && ins.ops[0].type != o_far;
}

bool target_is_ordinary_flow(const xref_fact_t& xref, ea_t from, const insn_t& ins)
{
    if (!xref.is_code || xref.to.ea == 0)
        return false;
    const ea_t next = from + ins.size;
    return xref.to.ea == static_cast<std::uint64_t>(next);
}

instruction_fact_t instruction_to_fact(func_t& fn,
                                       const insn_t& ins,
                                       const module_identity_t& module,
                                       const extraction_options_t& options,
                                       std::uint64_t& byte_hash)
{
    instruction_fact_t out;
    out.location = address_for(ins.ea, module);
    out.itype = ins.itype;
    out.feature_flags = ins.get_canon_feature(PH);
    out.size = ins.size;
    out.mnemonic = insn_mnemonic(ins.ea);
    out.disassembly = disasm_line(ins.ea);
    out.is_call = is_call_insn(ins);
    out.is_return = is_ret_insn(ins);
    out.is_branch = branch_feature(ins);
    out.is_indirect = indirect_feature(ins);
    out.has_fallthrough = !has_insn_feature(ins.itype, CF_STOP);
    if (out.is_call)
    {
        ea_t target = BADADDR;
        for (const auto& x : collect_xrefs(ins.ea, "from", module, options.max_xrefs_per_address))
        {
            if (x.is_code && x.to.ea != 0 && !target_is_ordinary_flow(x, ins.ea, ins))
            {
                target = static_cast<ea_t>(x.to.ea);
                break;
            }
        }
        if (target != BADADDR)
            out.is_noreturn = !func_does_return(target);
    }
    if (out.is_noreturn)
        out.has_fallthrough = false;
    if (out.has_fallthrough)
    {
        ea_t next = ins.ea + ins.size;
        if (next < fn.end_ea && func_contains(&fn, next))
            out.fallthrough_ea = static_cast<std::uint64_t>(next);
        else
            out.has_fallthrough = false;
    }
    if (options.include_bytes)
    {
        auto bytes = read_bytes(ins.ea, ins.size);
        if (!bytes.empty())
        {
            fnv_append(byte_hash, bytes.data(), bytes.size());
            out.bytes_hex = hex_bytes(bytes);
        }
    }
    for (int i = 0; i < UA_MAXOP; ++i)
    {
        const op_t& op = ins.ops[i];
        if (op.type == o_void)
            continue;
        out.operands.push_back(operand_to_fact(ins, op, module));
    }
    if (options.include_xrefs)
    {
        out.xrefs_from = collect_xrefs(ins.ea, "from", module, options.max_xrefs_per_address);
        out.xrefs_to = collect_xrefs(ins.ea, "to", module, options.max_xrefs_per_address);
        for (const auto& x : out.xrefs_from)
        {
            if (!x.is_code || x.to.ea == 0)
                continue;
            if (target_is_ordinary_flow(x, ins.ea, ins))
                continue;
            out.branch_targets.push_back(x.to.ea);
        }
        std::sort(out.branch_targets.begin(), out.branch_targets.end());
        out.branch_targets.erase(std::unique(out.branch_targets.begin(), out.branch_targets.end()), out.branch_targets.end());
    }
    out.is_conditional = out.is_branch && out.has_fallthrough && !out.branch_targets.empty();
    return out;
}

type_fact_t extract_type_fact(func_t& fn, std::string& type_digest)
{
    type_fact_t out;
    tinfo_t tif;
    if (!get_tinfo(&tif, fn.start_ea))
        return out;
    out.present = true;
    qstring ts;
    if (tif.print(&ts, nullptr, PRTYPE_1LINE))
        out.type_text = qstring_to_string(ts);
    type_digest = out.type_text;
    if (!tif.is_func())
    {
        tinfo_t pointed = tif;
        if (pointed.is_funcptr())
            pointed.remove_ptr_or_array();
        if (pointed.is_func())
            tif = pointed;
    }
    out.is_function = tif.is_func();
    if (!out.is_function)
        return out;
    func_type_data_t ftd;
    if (!tif.get_func_details(&ftd))
        return out;
    out.is_noreturn = ftd.is_noret();
    qstring ret;
    if (ftd.rettype.print(&ret, nullptr, PRTYPE_1LINE))
        out.return_type = qstring_to_string(ret);
    for (const funcarg_t& arg : ftd)
    {
        qstring at;
        const char* arg_name = arg.name.empty() ? nullptr : arg.name.c_str();
        if (arg.type.print(&at, arg_name, PRTYPE_1LINE))
            out.arguments.push_back(qstring_to_string(at));
    }
    for (const reg_info_t& reg : ftd.spoiled)
    {
        out.spoiled_registers.push_back("reg:" + std::to_string(reg.reg) + ":" + std::to_string(reg.size));
    }
    return out;
}

std::string citem_text(const citem_t& item, cfunc_t& cfunc)
{
    qstring q;
    item.print1(&q, &cfunc);
    return strip_tags(q);
}

std::string cexpr_type_text(const cexpr_t& expr)
{
    qstring q;
    if (expr.type.print(&q, nullptr, PRTYPE_1LINE))
        return qstring_to_string(q);
    return {};
}

struct ctree_collector_t : public ctree_visitor_t
{
    cfunc_t& cfunc;
    const module_identity_t& module;
    std::size_t limit;
    std::unordered_map<const citem_t*, std::size_t> ids;
    std::vector<ctree_node_fact_t> nodes;
    bool truncated = false;

    ctree_collector_t(cfunc_t& cf, const module_identity_t& mod, std::size_t lim)
        : ctree_visitor_t(CV_PARENTS), cfunc(cf), module(mod), limit(lim)
    {
    }

    std::size_t id_for(const citem_t* item)
    {
        auto it = ids.find(item);
        if (it != ids.end())
            return it->second;
        const std::size_t id = ids.size();
        ids.emplace(item, id);
        return id;
    }

    void fill_common(ctree_node_fact_t& out, const citem_t& item, const std::string& role)
    {
        out.id = id_for(&item);
        out.location = address_for(item.ea, module);
        out.op = get_ctype_name(item.op) != nullptr ? std::string(get_ctype_name(item.op)) : std::to_string(static_cast<int>(item.op));
        out.role = role;
        out.text = citem_text(item, cfunc);
        for (const citem_t* parent : parents)
        {
            if (parent == nullptr)
                continue;
            out.parent_ids.push_back(id_for(parent));
            if (parent->ea != BADADDR)
                out.parent_eas.push_back(static_cast<std::uint64_t>(parent->ea));
        }
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr == nullptr)
            return 0;
        if (nodes.size() >= limit)
        {
            truncated = true;
            return 1;
        }
        ctree_node_fact_t node;
        fill_common(node, *expr, "expr");
        node.type_text = cexpr_type_text(*expr);
        nodes.push_back(std::move(node));
        return 0;
    }

    int idaapi visit_insn(cinsn_t* insn) override
    {
        if (insn == nullptr)
            return 0;
        if (nodes.size() >= limit)
        {
            truncated = true;
            return 1;
        }
        ctree_node_fact_t node;
        fill_common(node, *insn, "stmt");
        nodes.push_back(std::move(node));
        return 0;
    }
};

ctree_fact_t extract_ctree_fact(func_t& fn, const module_identity_t& module, const extraction_options_t& options)
{
    ctree_fact_t out;
    const std::uint64_t start = now_ms();
    out.status.layer = "ctree";
    if (!init_hexrays_plugin())
    {
        out.status = make_status("ctree", layer_state_t::unavailable, "hexrays_unavailable", start);
        return out;
    }
    if (!ida_utils::is_safely_decompilable(&fn))
    {
        out.status = make_status("ctree", layer_state_t::skipped, "function_not_safely_decompilable", start);
        return out;
    }
    try
    {
        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile_func(&fn, &hf, DECOMP_NO_WAIT | DECOMP_WARNINGS);
        if (!cfunc)
        {
            out.status = make_status("ctree", layer_state_t::failed, qstring_to_string(hf.desc()), start);
            return out;
        }
        qstring code;
        qstring_printer_t printer(cfunc, code, false);
        cfunc->print_func(printer);
        std::istringstream lines(qstring_to_string(code));
        std::string line;
        while (std::getline(lines, line))
        {
            if (out.pseudocode_lines.size() >= options.max_pseudocode_lines)
                break;
            out.pseudocode_lines.push_back(line);
        }
        if (lvars_t* lvars = cfunc->get_lvars())
        {
            for (std::size_t i = 0; i < lvars->size(); ++i)
            {
                const lvar_t& lv = (*lvars)[i];
                json lj;
                lj["index"] = i;
                lj["name"] = qstring_to_string(lv.name);
                qstring tq;
                if (lv.type().print(&tq, nullptr, PRTYPE_1LINE))
                    lj["type"] = qstring_to_string(tq);
                lj["width"] = lv.width;
                lj["is_arg"] = lv.is_arg_var();
                out.locals.push_back(std::move(lj));
            }
        }
        ctree_collector_t visitor(*cfunc, module, options.max_ctree_nodes);
        visitor.apply_to(&cfunc->body, nullptr);
        out.nodes = std::move(visitor.nodes);
        out.status = make_status("ctree",
                                 visitor.truncated ? layer_state_t::truncated : layer_state_t::ok,
                                 visitor.truncated ? "ctree_node_limit_reached" : "",
                                 start,
                                 out.nodes.size(),
                                 visitor.ids.size());
        return out;
    }
    catch (const vd_failure_t& e)
    {
        out.status = make_status("ctree", layer_state_t::failed, qstring_to_string(e.desc()), start);
        return out;
    }
    catch (...)
    {
        out.status = make_status("ctree", layer_state_t::failed, "exception", start);
        return out;
    }
}

std::string mlist_text(const mlist_t& list)
{
    qstring q;
    list.print(&q);
    return qstring_to_string(q);
}

microcode_fact_t extract_microcode_fact(ea_t func_ea,
                                        const std::string& maturity,
                                        const extraction_options_t& options)
{
    microcode_fact_t out;
    const std::uint64_t start = now_ms();
    out.maturity = maturity;
    out.status.layer = "microcode:" + maturity;
    mba_maturity_t mat = microcode::parse_maturity(maturity);
    if (!init_hexrays_plugin())
    {
        out.status = make_status(out.status.layer, layer_state_t::unavailable, "hexrays_unavailable", start);
        return out;
    }
    try
    {
        auto handle = microcode::generate(func_ea, mat);
        if (!handle.has_value() || handle->mba == nullptr)
        {
            out.status = make_status(out.status.layer, layer_state_t::failed, "microcode_generation_failed", start);
            return out;
        }
        mba_t& mba = *handle->mba;
        out.blocks = microcode::dump_mba(mba, 0, options.max_microcode_instructions);
        std::size_t emitted = out.blocks.value("returned_instructions", static_cast<std::size_t>(0));
        bool truncated = out.blocks.value("truncated", false);
        for (int bi = 0; bi < mba.qty && out.use_def.size() < options.max_microcode_instructions; ++bi)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(bi));
            if (blk == nullptr)
                continue;
            for (minsn_t* ins = blk->head; ins != nullptr && out.use_def.size() < options.max_microcode_instructions; ins = ins->next)
            {
                json ud;
                ud["block"] = blk->serial;
                ud["ea"] = hex_u64(static_cast<std::uint64_t>(ins->ea));
                ud["instruction"] = microcode::minsn_to_json(*ins);
                mlist_t uses = blk->build_use_list(*ins, MAY_ACCESS);
                mlist_t defs = blk->build_def_list(*ins, MAY_ACCESS);
                ud["may_use"] = mlist_text(uses);
                ud["may_def"] = mlist_text(defs);
                if (is_mcode_call(ins->opcode))
                {
                    ea_t callee = BADADDR;
                    std::string name;
                    if (microcode::resolve_call_target(*ins, callee, name))
                    {
                        json call;
                        call["ea"] = hex_u64(static_cast<std::uint64_t>(ins->ea));
                        call["callee_ea"] = callee == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(callee));
                        call["callee_name"] = name;
                        call["kind"] = ins->opcode == m_icall ? "indirect" : "direct";
                        json args = json::array();
                        for (const auto& arg : microcode::collect_call_arguments(*ins))
                        {
                            json aj;
                            aj["index"] = arg.arg_index;
                            aj["init_ea"] = arg.init_ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(arg.init_ea));
                            aj["is_literal"] = arg.is_literal;
                            aj["literal_value"] = arg.literal_value;
                            aj["summary"] = arg.summary;
                            args.push_back(std::move(aj));
                        }
                        call["args"] = std::move(args);
                        out.calls.push_back(std::move(call));
                    }
                }
                out.use_def.push_back(std::move(ud));
            }
        }
        out.status = make_status(out.status.layer,
                                 truncated ? layer_state_t::truncated : layer_state_t::ok,
                                 truncated ? "microcode_instruction_limit_reached" : "",
                                 start,
                                 emitted,
                                 out.blocks.value("total_instructions", emitted));
        return out;
    }
    catch (const vd_failure_t& e)
    {
        out.status = make_status(out.status.layer, layer_state_t::failed, qstring_to_string(e.desc()), start);
        return out;
    }
    catch (...)
    {
        out.status = make_status(out.status.layer, layer_state_t::failed, "exception", start);
        return out;
    }
}

std::string branch_kind_from_instruction(const instruction_fact_t& ins)
{
    if (ins.is_return)
        return "return";
    if (ins.is_call)
        return ins.is_indirect ? "indirect_call" : "call";
    if (ins.is_conditional)
        return "conditional_branch";
    if (ins.is_branch)
        return ins.is_indirect ? "indirect_branch" : "unconditional_branch";
    if (ins.is_noreturn)
        return "noreturn";
    return "fallthrough";
}

std::vector<basic_block_fact_t> extract_basic_blocks(func_t& fn,
                                                     const module_identity_t& module,
                                                     const std::unordered_map<std::uint64_t, instruction_fact_t>& insn_by_ea,
                                                     const extraction_options_t& options)
{
    std::vector<basic_block_fact_t> out;
    qflow_chart_t fc("aida_chain_extract", &fn, fn.start_ea, fn.end_ea, FC_RESERVED);
    const int n = fc.size();
    const int cap = static_cast<int>(std::min<std::size_t>(options.max_basic_blocks, static_cast<std::size_t>(std::max(n, 0))));
    out.reserve(static_cast<std::size_t>(cap));
    for (int i = 0; i < cap; ++i)
    {
        const qbasic_block_t& bb = fc.blocks[i];
        basic_block_fact_t block;
        block.id = static_cast<std::size_t>(i);
        block.start = address_for(bb.start_ea, module);
        block.end = address_for(bb.end_ea, module);
        for (int s = 0; s < fc.nsucc(i); ++s)
            block.successors.push_back(static_cast<std::size_t>(fc.succ(i, s)));
        for (int p = 0; p < fc.npred(i); ++p)
            block.predecessors.push_back(static_cast<std::size_t>(fc.pred(i, p)));
        ea_t cur = bb.start_ea;
        while (cur != BADADDR && cur < bb.end_ea)
        {
            auto it = insn_by_ea.find(static_cast<std::uint64_t>(cur));
            if (it != insn_by_ea.end())
            {
                block.instruction_eas.push_back(it->first);
                block.terminal_kind = branch_kind_from_instruction(it->second);
                block.is_return = it->second.is_return;
                block.is_noreturn = it->second.is_noreturn;
                cur += std::max<std::uint32_t>(it->second.size, 1);
            }
            else
            {
                ea_t next = next_head(cur, bb.end_ea);
                if (next == BADADDR || next <= cur)
                    break;
                cur = next;
            }
        }
        out.push_back(std::move(block));
    }
    return out;
}

call_fact_t call_from_instruction(const instruction_fact_t& ins, const module_identity_t& module)
{
    call_fact_t call;
    call.callsite = ins.location;
    call.kind = ins.is_indirect ? "indirect" : "direct";
    call.resolved = false;
    call.does_return = !ins.is_noreturn;
    call.confidence = ins.is_indirect ? "unresolved" : "exact";
    call.arguments = ins.operands;
    for (std::uint64_t target : ins.branch_targets)
    {
        if (target == 0 || target == ins.fallthrough_ea)
            continue;
        call.target = address_for(static_cast<ea_t>(target), module);
        call.callee_name = !call.target.demangled_name.empty() ? call.target.demangled_name : call.target.symbol_name;
        call.resolved = true;
        break;
    }
    if (!call.resolved)
        call.confidence = "unresolved";
    return call;
}

branch_fact_t branch_from_instruction(const instruction_fact_t& ins, const module_identity_t& module)
{
    branch_fact_t branch;
    branch.branch = ins.location;
    branch.kind = branch_kind_from_instruction(ins);
    branch.predicate_text = ins.disassembly;
    branch.conditional = ins.is_conditional;
    for (std::uint64_t target : ins.branch_targets)
        branch.targets.push_back(address_for(static_cast<ea_t>(target), module));
    if (ins.has_fallthrough)
        branch.targets.push_back(address_for(static_cast<ea_t>(ins.fallthrough_ea), module));
    return branch;
}

std::string build_cache_key(function_snapshot_t& snapshot)
{
    std::uint64_t h = k_fnv_offset;
    fnv_append(h, std::string(k_chain_extraction_schema));
    fnv_append(h, snapshot.identity.start.module.module_id);
    fnv_append(h, snapshot.identity.start.module.processor);
    fnv_append(h, snapshot.identity.byte_digest);
    fnv_append(h, snapshot.identity.type_digest);
    fnv_append(h, snapshot.identity.start.rva);
    fnv_append(h, snapshot.identity.end.rva);
    fnv_append(h, snapshot.identity.flags);
    return fnv_hex(h);
}

function_snapshot_t extract_function_snapshot_ida(ea_t ea, const extraction_options_t& options)
{
    function_snapshot_t out;
    module_identity_t module = current_module_identity();
    const std::uint64_t raw_start = now_ms();
    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
    {
        out.statuses.push_back(make_status("function", layer_state_t::failed, "no_enclosing_function", raw_start));
        return out;
    }
    out.identity.start = address_for(pfn->start_ea, module);
    out.identity.end = address_for(pfn->end_ea, module);
    out.identity.size = pfn->end_ea > pfn->start_ea ? static_cast<std::uint64_t>(pfn->end_ea - pfn->start_ea) : 0;
    out.identity.flags = pfn->flags;
    out.identity.does_return = pfn->does_return();
    out.identity.is_thunk = (pfn->flags & FUNC_THUNK) != 0;
    out.identity.is_tail = (pfn->flags & FUNC_TAIL) != 0;
    std::uint64_t byte_hash = k_fnv_offset;
    std::set<std::string> xref_from_seen;
    std::set<std::string> xref_to_seen;
    std::unordered_map<std::uint64_t, instruction_fact_t> insn_by_ea;
    func_item_iterator_t fii(pfn);
    std::size_t total = 0;
    bool truncated = false;
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ++total;
        if (out.instructions.size() >= options.max_instructions)
        {
            truncated = true;
            continue;
        }
        ea_t cur = fii.current();
        flags64_t flags = get_flags(cur);
        if (!is_code(flags))
            continue;
        insn_t ins;
        if (decode_insn(&ins, cur) <= 0)
            continue;
        instruction_fact_t fact = instruction_to_fact(*pfn, ins, module, options, byte_hash);
        for (const auto& x : fact.xrefs_from)
            append_unique_xref(out.xrefs_from, x, xref_from_seen);
        for (const auto& x : fact.xrefs_to)
            append_unique_xref(out.xrefs_to, x, xref_to_seen);
        if (fact.is_call)
            out.calls.push_back(call_from_instruction(fact, module));
        if (fact.is_branch || fact.is_return || fact.is_noreturn)
            out.branches.push_back(branch_from_instruction(fact, module));
        insn_by_ea.emplace(fact.location.ea, fact);
        out.instructions.push_back(std::move(fact));
    }
    out.identity.byte_digest = fnv_hex(byte_hash);
    out.statuses.push_back(make_status("raw_instructions",
                                       truncated ? layer_state_t::truncated : layer_state_t::ok,
                                       truncated ? "instruction_limit_reached" : "",
                                       raw_start,
                                       out.instructions.size(),
                                       total));
    const std::uint64_t cfg_start = now_ms();
    out.basic_blocks = extract_basic_blocks(*pfn, module, insn_by_ea, options);
    layer_state_t cfg_state = out.basic_blocks.size() >= options.max_basic_blocks ? layer_state_t::truncated : layer_state_t::ok;
    out.statuses.push_back(make_status("raw_cfg",
                                       cfg_state,
                                       cfg_state == layer_state_t::truncated ? "basic_block_limit_reached" : "",
                                       cfg_start,
                                       out.basic_blocks.size(),
                                       out.basic_blocks.size()));
    if (options.include_types)
    {
        const std::uint64_t type_start = now_ms();
        out.type = extract_type_fact(*pfn, out.identity.type_digest);
        out.statuses.push_back(make_status("types",
                                           out.type.present ? layer_state_t::ok : layer_state_t::unavailable,
                                           out.type.present ? "" : "no_type_information",
                                           type_start,
                                           out.type.present ? 1 : 0,
                                           1));
    }
    else
    {
        out.statuses.push_back(make_status("types", layer_state_t::skipped, "disabled", now_ms()));
    }
    if (options.include_ctree)
    {
        out.ctree = extract_ctree_fact(*pfn, module, options);
        out.statuses.push_back(out.ctree.status);
    }
    else
    {
        out.ctree.status = make_status("ctree", layer_state_t::skipped, "disabled", now_ms());
        out.statuses.push_back(out.ctree.status);
    }
    if (options.include_microcode)
    {
        std::set<std::string> seen_mats;
        for (const std::string& mat : options.microcode_maturities)
        {
            if (!seen_mats.insert(mat).second)
                continue;
            microcode_fact_t mc = extract_microcode_fact(pfn->start_ea, mat, options);
            out.statuses.push_back(mc.status);
            out.microcode.push_back(std::move(mc));
        }
    }
    else
    {
        out.statuses.push_back(make_status("microcode", layer_state_t::skipped, "disabled", now_ms()));
    }
    out.identity.cache_key = build_cache_key(out);
    out.complete = true;
    for (const layer_status_t& status : out.statuses)
    {
        if (status.state == layer_state_t::failed)
        {
            out.complete = false;
            break;
        }
    }
    return out;
}

struct import_collect_t
{
    const module_identity_t* module = nullptr;
    std::vector<address_identity_t>* imports = nullptr;
    std::string module_name;
};

int idaapi import_cb(ea_t ea, const char* name, uval_t ord, void* param)
{
    auto* ctx = static_cast<import_collect_t*>(param);
    if (ctx == nullptr || ctx->module == nullptr || ctx->imports == nullptr)
        return 1;
    address_identity_t item = address_for(ea, *ctx->module);
    if (name != nullptr && name[0] != '\0')
        item.symbol_name = name;
    else
        item.symbol_name = "ordinal_" + std::to_string(static_cast<std::uint64_t>(ord));
    item.demangled_name = ctx->module_name;
    item.api_confidence = "import";
    ctx->imports->push_back(std::move(item));
    return 1;
}

module_snapshot_t extract_module_snapshot_ida(const extraction_options_t&)
{
    module_snapshot_t out;
    const std::uint64_t start = now_ms();
    out.identity = current_module_identity();
    const int seg_count = get_segm_qty();
    for (int i = 0; i < seg_count; ++i)
    {
        segment_t* seg = getnseg(i);
        if (seg != nullptr)
            out.segments.push_back(segment_to_fact(*seg, out.identity));
    }
    const std::uint64_t entry_start = now_ms();
    const std::size_t entry_count = get_entry_qty();
    for (std::size_t i = 0; i < entry_count; ++i)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        address_identity_t entry = address_for(ea, out.identity);
        qstring name;
        if (get_entry_name(&name, ord) > 0 && !name.empty())
            entry.symbol_name = qstring_to_string(name);
        qstring fwd;
        if (get_entry_forwarder(&fwd, ord) > 0 && !fwd.empty())
            entry.demangled_name = qstring_to_string(fwd);
        entry.api_confidence = "entry";
        out.entries.push_back(std::move(entry));
    }
    out.statuses.push_back(make_status("entries", layer_state_t::ok, "", entry_start, out.entries.size(), entry_count));
    const std::uint64_t import_start = now_ms();
    const uint import_qty = get_import_module_qty();
    for (uint i = 0; i < import_qty; ++i)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, static_cast<int>(i));
        import_collect_t ctx;
        ctx.module = &out.identity;
        ctx.imports = &out.imports;
        ctx.module_name = qstring_to_string(mod_name);
        enum_import_names(static_cast<int>(i), import_cb, &ctx);
    }
    out.statuses.push_back(make_status("imports", layer_state_t::ok, "", import_start, out.imports.size(), import_qty));
    out.statuses.push_back(make_status("segments", layer_state_t::ok, "", start, out.segments.size(), static_cast<std::size_t>(seg_count)));
    return out;
}

template <typename Snapshot>
Snapshot failed_snapshot(const std::string& layer, const std::string& reason)
{
    Snapshot out;
    out.statuses.push_back(make_status(layer, layer_state_t::failed, reason, now_ms()));
    return out;
}

}

module_snapshot_t extract_module_snapshot(const extraction_options_t& options)
{
    struct request_t : public exec_request_t
    {
        extraction_options_t options;
        module_snapshot_t result;
        bool ok = false;
        request_t(const extraction_options_t& o) : options(o) {}
        ssize_t idaapi execute() override
        {
            try
            {
                result = extract_module_snapshot_ida(options);
                ok = true;
            }
            catch (...)
            {
                result = failed_snapshot<module_snapshot_t>("module", "exception");
            }
            return 1;
        }
    };
    request_t req(options);
    if (execute_sync(req, MFF_READ) <= 0)
        return failed_snapshot<module_snapshot_t>("module", "execute_sync_failed");
    if (!req.ok)
        return req.result;
    return req.result;
}

function_snapshot_t extract_function_snapshot(ea_t ea, const extraction_options_t& options)
{
    struct request_t : public exec_request_t
    {
        ea_t ea;
        extraction_options_t options;
        function_snapshot_t result;
        bool ok = false;
        request_t(ea_t e, const extraction_options_t& o) : ea(e), options(o) {}
        ssize_t idaapi execute() override
        {
            try
            {
                result = extract_function_snapshot_ida(ea, options);
                ok = true;
            }
            catch (...)
            {
                result = failed_snapshot<function_snapshot_t>("function", "exception");
            }
            return 1;
        }
    };
    request_t req(ea, options);
    if (execute_sync(req, MFF_READ) <= 0)
        return failed_snapshot<function_snapshot_t>("function", "execute_sync_failed");
    if (!req.ok)
        return req.result;
    return req.result;
}

nlohmann::json to_json(layer_state_t state)
{
    switch (state)
    {
    case layer_state_t::ok:          return "ok";
    case layer_state_t::skipped:     return "skipped";
    case layer_state_t::failed:      return "failed";
    case layer_state_t::timeout:     return "timeout";
    case layer_state_t::unavailable: return "unavailable";
    case layer_state_t::truncated:   return "truncated";
    }
    return "failed";
}

nlohmann::json to_json(const layer_status_t& status)
{
    return json{{"layer", status.layer},
                {"state", to_json(status.state)},
                {"reason", status.reason},
                {"elapsed_ms", status.elapsed_ms},
                {"emitted", status.emitted},
                {"total", status.total}};
}

nlohmann::json to_json(const module_identity_t& identity)
{
    return json{{"module_id", identity.module_id},
                {"module_name", identity.module_name},
                {"input_path", identity.input_path},
                {"input_md5", identity.input_md5},
                {"input_sha256", identity.input_sha256},
                {"processor", identity.processor},
                {"image_base", hex_u64(identity.image_base)},
                {"min_ea", hex_u64(identity.min_ea)},
                {"max_ea", hex_u64(identity.max_ea)},
                {"pointer_width_bits", identity.pointer_width_bits},
                {"big_endian", identity.big_endian}};
}

nlohmann::json to_json(const address_identity_t& identity)
{
    return json{{"module", to_json(identity.module)},
                {"ea", hex_u64(identity.ea)},
                {"rva", identity.has_rva ? hex_u64(identity.rva) : std::string()},
                {"has_rva", identity.has_rva},
                {"segment", identity.segment_name},
                {"segment_class", identity.segment_class},
                {"segment_permissions", identity.segment_permissions},
                {"symbol", identity.symbol_name},
                {"demangled", identity.demangled_name},
                {"function_ea", hex_u64(identity.function_ea)},
                {"function_rva", hex_u64(identity.function_rva)},
                {"function_name", identity.function_name},
                {"api_confidence", identity.api_confidence}};
}

nlohmann::json to_json(const segment_fact_t& segment)
{
    return json{{"name", segment.name},
                {"class", segment.klass},
                {"start_ea", hex_u64(segment.start_ea)},
                {"end_ea", hex_u64(segment.end_ea)},
                {"start_rva", hex_u64(segment.start_rva)},
                {"end_rva", hex_u64(segment.end_rva)},
                {"permissions", segment.permissions},
                {"type", segment.type}};
}

nlohmann::json to_json(const xref_fact_t& xref)
{
    return json{{"from", to_json(xref.from)},
                {"to", to_json(xref.to)},
                {"is_code", xref.is_code},
                {"user", xref.user},
                {"type", xref.type},
                {"direction", xref.direction},
                {"source_disasm", xref.source_disasm}};
}

nlohmann::json to_json(const operand_fact_t& operand)
{
    return json{{"index", operand.index},
                {"type", operand.type},
                {"type_id", operand.type_id},
                {"dtype", operand.dtype},
                {"width_bits", operand.width_bits},
                {"reg", operand.reg},
                {"phrase", operand.phrase},
                {"value", hex_u64(operand.value)},
                {"address", hex_u64(operand.address)},
                {"specval", hex_u64(operand.specval)},
                {"flags", operand.flags},
                {"shown", operand.shown},
                {"text", operand.text},
                {"address_identity", to_json(operand.address_identity)}};
}

nlohmann::json to_json(const instruction_fact_t& instruction)
{
    json operands = json::array();
    for (const auto& op : instruction.operands)
        operands.push_back(to_json(op));
    json xfrom = json::array();
    for (const auto& x : instruction.xrefs_from)
        xfrom.push_back(to_json(x));
    json xto = json::array();
    for (const auto& x : instruction.xrefs_to)
        xto.push_back(to_json(x));
    json targets = json::array();
    for (std::uint64_t target : instruction.branch_targets)
        targets.push_back(hex_u64(target));
    return json{{"location", to_json(instruction.location)},
                {"itype", instruction.itype},
                {"feature_flags", instruction.feature_flags},
                {"size", instruction.size},
                {"mnemonic", instruction.mnemonic},
                {"disassembly", instruction.disassembly},
                {"bytes", instruction.bytes_hex},
                {"operands", std::move(operands)},
                {"xrefs_from", std::move(xfrom)},
                {"xrefs_to", std::move(xto)},
                {"branch_targets", std::move(targets)},
                {"fallthrough_ea", hex_u64(instruction.fallthrough_ea)},
                {"has_fallthrough", instruction.has_fallthrough},
                {"is_call", instruction.is_call},
                {"is_return", instruction.is_return},
                {"is_branch", instruction.is_branch},
                {"is_indirect", instruction.is_indirect},
                {"is_conditional", instruction.is_conditional},
                {"is_noreturn", instruction.is_noreturn}};
}

nlohmann::json to_json(const basic_block_fact_t& block)
{
    json insns = json::array();
    for (std::uint64_t ea : block.instruction_eas)
        insns.push_back(hex_u64(ea));
    return json{{"id", block.id},
                {"start", to_json(block.start)},
                {"end", to_json(block.end)},
                {"instruction_eas", std::move(insns)},
                {"predecessors", block.predecessors},
                {"successors", block.successors},
                {"terminal_kind", block.terminal_kind},
                {"is_return", block.is_return},
                {"is_noreturn", block.is_noreturn}};
}

nlohmann::json to_json(const call_fact_t& call)
{
    json args = json::array();
    for (const auto& arg : call.arguments)
        args.push_back(to_json(arg));
    return json{{"callsite", to_json(call.callsite)},
                {"target", to_json(call.target)},
                {"kind", call.kind},
                {"callee_name", call.callee_name},
                {"resolved", call.resolved},
                {"does_return", call.does_return},
                {"confidence", call.confidence},
                {"arguments", std::move(args)}};
}

nlohmann::json to_json(const branch_fact_t& branch)
{
    json targets = json::array();
    for (const auto& target : branch.targets)
        targets.push_back(to_json(target));
    return json{{"branch", to_json(branch.branch)},
                {"kind", branch.kind},
                {"predicate_text", branch.predicate_text},
                {"targets", std::move(targets)},
                {"conditional", branch.conditional}};
}

nlohmann::json to_json(const type_fact_t& type)
{
    return json{{"present", type.present},
                {"is_function", type.is_function},
                {"is_noreturn", type.is_noreturn},
                {"type_text", type.type_text},
                {"return_type", type.return_type},
                {"arguments", type.arguments},
                {"spoiled_registers", type.spoiled_registers}};
}

nlohmann::json to_json(const ctree_node_fact_t& node)
{
    json parent_eas = json::array();
    for (std::uint64_t ea : node.parent_eas)
        parent_eas.push_back(hex_u64(ea));
    return json{{"id", node.id},
                {"location", to_json(node.location)},
                {"op", node.op},
                {"role", node.role},
                {"text", node.text},
                {"type_text", node.type_text},
                {"parent_ids", node.parent_ids},
                {"parent_eas", std::move(parent_eas)}};
}

nlohmann::json to_json(const ctree_fact_t& ctree)
{
    json nodes = json::array();
    for (const auto& node : ctree.nodes)
        nodes.push_back(to_json(node));
    return json{{"status", to_json(ctree.status)},
                {"pseudocode_lines", ctree.pseudocode_lines},
                {"locals", ctree.locals},
                {"nodes", std::move(nodes)}};
}

nlohmann::json to_json(const microcode_fact_t& microcode)
{
    return json{{"status", to_json(microcode.status)},
                {"maturity", microcode.maturity},
                {"blocks", microcode.blocks},
                {"calls", microcode.calls},
                {"use_def", microcode.use_def}};
}

nlohmann::json to_json(const function_identity_t& identity)
{
    return json{{"start", to_json(identity.start)},
                {"end", to_json(identity.end)},
                {"size", identity.size},
                {"flags", identity.flags},
                {"does_return", identity.does_return},
                {"is_thunk", identity.is_thunk},
                {"is_tail", identity.is_tail},
                {"byte_digest", identity.byte_digest},
                {"type_digest", identity.type_digest},
                {"cache_key", identity.cache_key}};
}

nlohmann::json to_json(const function_snapshot_t& snapshot)
{
    json statuses = json::array();
    for (const auto& status : snapshot.statuses)
        statuses.push_back(to_json(status));
    json insns = json::array();
    for (const auto& insn : snapshot.instructions)
        insns.push_back(to_json(insn));
    json blocks = json::array();
    for (const auto& block : snapshot.basic_blocks)
        blocks.push_back(to_json(block));
    json xfrom = json::array();
    for (const auto& x : snapshot.xrefs_from)
        xfrom.push_back(to_json(x));
    json xto = json::array();
    for (const auto& x : snapshot.xrefs_to)
        xto.push_back(to_json(x));
    json calls = json::array();
    for (const auto& call : snapshot.calls)
        calls.push_back(to_json(call));
    json branches = json::array();
    for (const auto& branch : snapshot.branches)
        branches.push_back(to_json(branch));
    json micro = json::array();
    for (const auto& mc : snapshot.microcode)
        micro.push_back(to_json(mc));
    return json{{"schema", k_chain_extraction_schema},
                {"identity", to_json(snapshot.identity)},
                {"complete", snapshot.complete},
                {"statuses", std::move(statuses)},
                {"instructions", std::move(insns)},
                {"basic_blocks", std::move(blocks)},
                {"xrefs_from", std::move(xfrom)},
                {"xrefs_to", std::move(xto)},
                {"calls", std::move(calls)},
                {"branches", std::move(branches)},
                {"type", to_json(snapshot.type)},
                {"ctree", to_json(snapshot.ctree)},
                {"microcode", std::move(micro)}};
}

nlohmann::json to_json(const module_snapshot_t& snapshot)
{
    json statuses = json::array();
    for (const auto& status : snapshot.statuses)
        statuses.push_back(to_json(status));
    json segments = json::array();
    for (const auto& segment : snapshot.segments)
        segments.push_back(to_json(segment));
    json entries = json::array();
    for (const auto& entry : snapshot.entries)
        entries.push_back(to_json(entry));
    json imports = json::array();
    for (const auto& imp : snapshot.imports)
        imports.push_back(to_json(imp));
    return json{{"schema", k_chain_extraction_schema},
                {"identity", to_json(snapshot.identity)},
                {"statuses", std::move(statuses)},
                {"segments", std::move(segments)},
                {"entries", std::move(entries)},
                {"imports", std::move(imports)}};
}

std::string stable_cache_key(const function_snapshot_t& snapshot)
{
    std::uint64_t h = k_fnv_offset;
    fnv_append(h, std::string(k_chain_extraction_schema));
    fnv_append(h, snapshot.identity.start.module.module_id);
    fnv_append(h, snapshot.identity.byte_digest);
    fnv_append(h, snapshot.identity.type_digest);
    fnv_append(h, snapshot.identity.start.rva);
    fnv_append(h, snapshot.identity.end.rva);
    fnv_append(h, snapshot.identity.flags);
    return fnv_hex(h);
}

}
}
}
