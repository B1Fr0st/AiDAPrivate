#include "../aida_pro.hpp"

#include "chain_extraction.hpp"
#include "chain_binary_corpus.hpp"
#include "chain_side_effects.hpp"
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
#include <netnode.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
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

bool operand_is_memory_fact(const operand_fact_t& op)
{
    return op.type == "mem" || op.type == "displ" || op.type == "phrase" || op.type == "far" || op.type == "near";
}

bool operand_is_stack_text(const std::string& text)
{
    const std::string l = lower_ascii(text);
    return l.find("rsp") != std::string::npos || l.find("esp") != std::string::npos ||
           l.find("rbp") != std::string::npos || l.find("ebp") != std::string::npos ||
           l.find("[sp") != std::string::npos || l.find("[bp") != std::string::npos;
}

std::string value_ref_for_operand(const operand_fact_t& op)
{
    if (op.type == "reg")
        return "reg";
    if (op.type == "imm")
        return "imm";
    if (operand_is_memory_fact(op))
    {
        if (operand_is_stack_text(op.text))
            return "stack";
        if (op.address != 0)
            return "gvar";
        return "mem";
    }
    return "unknown";
}

std::string alias_class_for_operand(const operand_fact_t& op)
{
    if (op.type == "reg")
        return "reg:" + std::to_string(op.reg);
    if (op.type == "imm")
        return "imm:" + std::to_string(op.value);
    if (operand_is_stack_text(op.text))
        return "stack:" + op.text;
    if (op.address != 0)
        return "global:" + hex_u64(op.address);
    if (operand_is_memory_fact(op))
        return "mem:" + op.text;
    return "unknown";
}

json raw_effect_json(const std::string& kind,
                     const instruction_fact_t& ins,
                     const operand_fact_t* operand,
                     const std::string& reason,
                     const std::string& confidence)
{
    json e;
    e["kind"] = kind;
    e["source_layer"] = "raw";
    e["ea"] = hex_u64(ins.location.ea);
    e["mnemonic"] = ins.mnemonic;
    e["reason"] = reason;
    e["confidence"] = confidence;
    if (operand != nullptr)
    {
        e["operand_index"] = operand->index;
        e["expr"] = operand->text;
        e["value_ref"] = operand->value_ref;
        e["alias_class"] = operand->alias_class;
        e["width_bits"] = operand->width_bits;
        e["address_expr"] = operand->address_expr;
    }
    return e;
}

void append_register_use(instruction_fact_t& ins, const operand_fact_t& op, const std::string& reason)
{
    const std::string reg = op.type == "reg" ? "reg:" + std::to_string(op.reg) : op.alias_class;
    if (std::find(ins.register_uses.begin(), ins.register_uses.end(), reg) == ins.register_uses.end())
        ins.register_uses.push_back(reg);
    ins.raw_effects.push_back(raw_effect_json("register_use", ins, &op, reason, "conservative"));
}

void append_register_def(instruction_fact_t& ins, const operand_fact_t& op, const std::string& reason)
{
    const std::string reg = op.type == "reg" ? "reg:" + std::to_string(op.reg) : op.alias_class;
    if (std::find(ins.register_defs.begin(), ins.register_defs.end(), reg) == ins.register_defs.end())
        ins.register_defs.push_back(reg);
    ins.raw_effects.push_back(raw_effect_json("register_def", ins, &op, reason, "conservative"));
}

void append_operand_read(instruction_fact_t& ins, const operand_fact_t& op, const std::string& reason)
{
    if (op.type == "reg")
        append_register_use(ins, op, reason);
    else if (operand_is_memory_fact(op))
        ins.raw_effects.push_back(raw_effect_json("memory_read", ins, &op, reason, "conservative"));
}

void append_operand_write(instruction_fact_t& ins, const operand_fact_t& op, const std::string& reason)
{
    if (op.type == "reg")
        append_register_def(ins, op, reason);
    else if (operand_is_memory_fact(op))
        ins.raw_effects.push_back(raw_effect_json("memory_write", ins, &op, reason, "conservative"));
}

void append_flags_effect(instruction_fact_t& ins, const std::string& kind)
{
    json e;
    e["kind"] = kind;
    e["source_layer"] = "raw";
    e["ea"] = hex_u64(ins.location.ea);
    e["mnemonic"] = ins.mnemonic;
    e["reason"] = "condition_flags";
    e["confidence"] = "conservative";
    ins.raw_effects.push_back(std::move(e));
}

void append_stack_delta(instruction_fact_t& ins, std::int64_t delta, const std::string& reason)
{
    ins.stack_delta += delta;
    json e;
    e["kind"] = "stack_delta";
    e["source_layer"] = "raw";
    e["ea"] = hex_u64(ins.location.ea);
    e["mnemonic"] = ins.mnemonic;
    e["delta"] = delta;
    e["reason"] = reason;
    e["confidence"] = "conservative";
    ins.raw_effects.push_back(std::move(e));
}

void append_unknown_effect(instruction_fact_t& ins, const std::string& reason)
{
    ins.unknown_effect = true;
    ins.raw_effects.push_back(raw_effect_json("unknown", ins, nullptr, reason, "inconclusive"));
}

bool mnemonic_is_one_of(const std::string& mnemonic, const std::vector<std::string>& prefixes)
{
    const std::string m = lower_ascii(mnemonic);
    for (const std::string& prefix : prefixes)
    {
        if (m.rfind(prefix, 0) == 0)
            return true;
    }
    return false;
}

std::string canonical_mnemonic(std::string mnemonic)
{
    mnemonic = lower_ascii(std::move(mnemonic));
    for (;;)
    {
        const std::size_t p = mnemonic.find(' ');
        const std::string head = p == std::string::npos ? mnemonic : mnemonic.substr(0, p);
        if (head != "lock" && head != "rep" && head != "repe" && head != "repz" && head != "repne" && head != "repnz" && head != "bnd")
            break;
        mnemonic = p == std::string::npos ? std::string() : mnemonic.substr(p + 1);
    }
    return mnemonic;
}

void apply_raw_semantics(instruction_fact_t& ins, std::uint32_t pointer_width_bits)
{
    const std::uint32_t pointer_bytes = pointer_width_bits == 0 ? 8u : pointer_width_bits / 8u;
    const std::string m = canonical_mnemonic(ins.mnemonic);
    const bool has_dst = !ins.operands.empty();
    const bool has_src = ins.operands.size() > 1;
    if (m.empty())
    {
        append_unknown_effect(ins, "missing_mnemonic");
        return;
    }
    if (mnemonic_is_one_of(m, {"stos", "movs", "lods", "scas", "cmps", "ins", "outs"}))
    {
        json e;
        e["kind"] = "string_op";
        e["source_layer"] = "raw";
        e["ea"] = hex_u64(ins.location.ea);
        e["mnemonic"] = ins.mnemonic;
        e["reason"] = "implicit_memory_register_effects";
        e["confidence"] = "conservative";
        ins.raw_effects.push_back(std::move(e));
        append_unknown_effect(ins, "string_op_implicit_operands");
        return;
    }
    if (mnemonic_is_one_of(m, {"mov", "movzx", "movsx"}))
    {
        if (has_dst)
            append_operand_write(ins, ins.operands[0], "move_destination");
        if (has_src)
            append_operand_read(ins, ins.operands[1], "move_source");
        return;
    }
    if (mnemonic_is_one_of(m, {"cmov"}))
    {
        if (has_dst)
        {
            append_operand_read(ins, ins.operands[0], "conditional_move_old_destination");
            append_operand_write(ins, ins.operands[0], "conditional_move_destination");
        }
        if (has_src)
            append_operand_read(ins, ins.operands[1], "conditional_move_source");
        append_flags_effect(ins, "flags_read");
        return;
    }
    if (mnemonic_is_one_of(m, {"set"}))
    {
        if (has_dst)
            append_operand_write(ins, ins.operands[0], "setcc_destination");
        append_flags_effect(ins, "flags_read");
        return;
    }
    if (m == "lea")
    {
        if (has_dst)
            append_operand_write(ins, ins.operands[0], "lea_destination");
        if (has_src)
            ins.raw_effects.push_back(raw_effect_json("address_read", ins, &ins.operands[1], "lea_source_address", "conservative"));
        return;
    }
    if (mnemonic_is_one_of(m, {"xlat"}))
    {
        append_unknown_effect(ins, "xlat_implicit_table_lookup");
        return;
    }
    if (mnemonic_is_one_of(m, {"cmp", "test"}))
    {
        for (const auto& op : ins.operands)
            append_operand_read(ins, op, "comparison_operand");
        append_flags_effect(ins, "flags_def");
        return;
    }
    if (mnemonic_is_one_of(m, {"add", "adc", "sub", "sbb", "and", "or", "xor", "imul", "mul", "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr"}))
    {
        if (has_dst)
        {
            append_operand_read(ins, ins.operands[0], "read_modify_write_destination");
            append_operand_write(ins, ins.operands[0], "read_modify_write_destination");
        }
        for (std::size_t i = 1; i < ins.operands.size(); ++i)
            append_operand_read(ins, ins.operands[i], "arithmetic_source");
        append_flags_effect(ins, "flags_def");
        return;
    }
    if (mnemonic_is_one_of(m, {"div", "idiv"}))
    {
        for (const auto& op : ins.operands)
            append_operand_read(ins, op, "division_operand");
        append_unknown_effect(ins, "implicit_dividend_quotient_remainder_registers");
        return;
    }
    if (mnemonic_is_one_of(m, {"bt", "btc", "btr", "bts"}))
    {
        if (has_dst)
            append_operand_read(ins, ins.operands[0], "bit_test_base");
        if (has_src)
            append_operand_read(ins, ins.operands[1], "bit_test_index");
        if (mnemonic_is_one_of(m, {"btc", "btr", "bts"}))
            append_operand_write(ins, ins.operands[0], "bit_test_modify_base");
        append_flags_effect(ins, "flags_def");
        return;
    }
    if (mnemonic_is_one_of(m, {"inc", "dec", "neg", "not"}))
    {
        if (has_dst)
        {
            append_operand_read(ins, ins.operands[0], "unary_read_modify_write");
            append_operand_write(ins, ins.operands[0], "unary_read_modify_write");
        }
        append_flags_effect(ins, "flags_def");
        return;
    }
    if (mnemonic_is_one_of(m, {"cbw", "cwde", "cdqe", "cwd", "cdq", "cqo"}))
    {
        append_unknown_effect(ins, "implicit_sign_extension_registers");
        return;
    }
    if (m == "push")
    {
        if (has_dst)
            append_operand_read(ins, ins.operands[0], "push_source");
        append_stack_delta(ins, -static_cast<std::int64_t>(pointer_bytes), "push_stack_write");
        return;
    }
    if (m == "pop")
    {
        if (has_dst)
            append_operand_write(ins, ins.operands[0], "pop_destination");
        append_stack_delta(ins, static_cast<std::int64_t>(pointer_bytes), "pop_stack_read");
        return;
    }
    if (ins.is_call)
    {
        if (has_dst)
            append_operand_read(ins, ins.operands[0], "call_target");
        append_stack_delta(ins, -static_cast<std::int64_t>(pointer_bytes), "call_return_address_push");
        append_unknown_effect(ins, ins.is_indirect ? "indirect_call_side_effects" : "call_side_effects");
        return;
    }
    if (ins.is_return)
    {
        append_stack_delta(ins, static_cast<std::int64_t>(pointer_bytes), "return_address_pop");
        return;
    }
    if (mnemonic_is_one_of(m, {"xchg", "xadd", "cmpxchg"}))
    {
        for (const auto& op : ins.operands)
        {
            append_operand_read(ins, op, "atomic_read_modify_write");
            append_operand_write(ins, op, "atomic_read_modify_write");
        }
        append_flags_effect(ins, "flags_def");
        return;
    }
    if (ins.is_branch)
    {
        append_flags_effect(ins, ins.is_conditional ? "flags_read" : "control_transfer");
        return;
    }
    append_unknown_effect(ins, "opcode_not_modelled");
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
    status.timeout = state == layer_state_t::timeout;
    status.cancelled = reason == "cancelled";
    if (state == layer_state_t::failed || state == layer_state_t::timeout || state == layer_state_t::truncated || state == layer_state_t::unavailable)
        status.cutoff_reason = reason;
    status.diagnostics = json{{"phase", layer},
                              {"operation", "chain_extraction"},
                              {"elapsed_ms", status.elapsed_ms},
                              {"emitted", emitted},
                              {"total", total},
                              {"failure_reason", reason}};
    return status;
}

enum class extraction_stop_t
{
    none,
    timeout,
    cancelled
};

extraction_stop_t stop_state(std::uint64_t start_ms, const extraction_options_t& options)
{
    if (options.timeout_ms != 0 && now_ms() - start_ms >= options.timeout_ms)
        return extraction_stop_t::timeout;
    if (options.cancellation_requested && options.cancellation_requested())
        return extraction_stop_t::cancelled;
    if (options.allow_interactive_cancel && user_cancelled())
        return extraction_stop_t::cancelled;
    return extraction_stop_t::none;
}

layer_status_t stop_status(const std::string& layer,
                           extraction_stop_t stop,
                           std::uint64_t start_ms,
                           std::size_t emitted,
                           std::size_t total)
{
    const bool timed_out = stop == extraction_stop_t::timeout;
    layer_status_t status = make_status(layer,
                                        timed_out ? layer_state_t::timeout : layer_state_t::truncated,
                                        timed_out ? "timeout" : "cancelled",
                                        start_ms,
                                        emitted,
                                        total);
    status.timeout = timed_out;
    status.cancelled = stop == extraction_stop_t::cancelled;
    status.cutoff_reason = status.reason;
    return status;
}

void annotate_status(layer_status_t& status,
                     const module_identity_t& module,
                     ea_t function_ea,
                     const std::string& phase,
                     const std::string& operation,
                     const extraction_cache_status_t* cache = nullptr)
{
    status.diagnostics["phase"] = phase.empty() ? status.layer : phase;
    status.diagnostics["operation"] = operation;
    status.diagnostics["module"] = to_json(module);
    if (function_ea != BADADDR)
        status.diagnostics["function_ea"] = hex_u64(static_cast<std::uint64_t>(function_ea));
    if (!status.reason.empty())
        status.diagnostics["failure_reason"] = status.reason;
    if (cache != nullptr)
        status.diagnostics["cache"] = to_json(*cache);
}

void annotate_statuses(std::vector<layer_status_t>& statuses,
                       const module_identity_t& module,
                       ea_t function_ea,
                       const std::string& operation,
                       const extraction_cache_status_t* cache = nullptr)
{
    for (layer_status_t& status : statuses)
        annotate_status(status, module, function_ea, status.layer, operation, cache);
}

std::uint64_t parse_u64(const json& v)
{
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>();
    if (v.is_number_integer())
        return static_cast<std::uint64_t>(v.get<std::int64_t>());
    if (!v.is_string())
        return 0;
    const std::string s = v.get<std::string>();
    if (s.empty())
        return 0;
    char* endp = nullptr;
    std::uint64_t out = _strtoui64(s.c_str(), &endp, 0);
    return endp == s.c_str() ? 0 : out;
}

layer_state_t parse_layer_state(const json& v)
{
    const std::string s = v.is_string() ? v.get<std::string>() : std::string();
    if (s == "ok")
        return layer_state_t::ok;
    if (s == "failed")
        return layer_state_t::failed;
    if (s == "timeout")
        return layer_state_t::timeout;
    if (s == "unavailable")
        return layer_state_t::unavailable;
    if (s == "truncated")
        return layer_state_t::truncated;
    return layer_state_t::skipped;
}

std::vector<std::string> string_vector_from_json(const json& v)
{
    std::vector<std::string> out;
    if (!v.is_array())
        return out;
    for (const auto& item : v)
    {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
    return out;
}

module_identity_t module_identity_from_json(const json& j)
{
    module_identity_t out;
    if (!j.is_object())
        return out;
    out.module_id = j.value("module_id", std::string());
    out.module_name = j.value("module_name", std::string());
    out.input_path = j.value("input_path", std::string());
    out.input_md5 = j.value("input_md5", std::string());
    out.input_sha256 = j.value("input_sha256", std::string());
    out.processor = j.value("processor", std::string());
    if (j.contains("image_base"))
        out.image_base = parse_u64(j["image_base"]);
    if (j.contains("min_ea"))
        out.min_ea = parse_u64(j["min_ea"]);
    if (j.contains("max_ea"))
        out.max_ea = parse_u64(j["max_ea"]);
    out.pointer_width_bits = j.value("pointer_width_bits", 0u);
    out.big_endian = j.value("big_endian", false);
    return out;
}

address_identity_t address_identity_from_json(const json& j)
{
    address_identity_t out;
    if (!j.is_object())
        return out;
    if (j.contains("module"))
        out.module = module_identity_from_json(j["module"]);
    if (j.contains("ea"))
        out.ea = parse_u64(j["ea"]);
    if (j.contains("rva"))
        out.rva = parse_u64(j["rva"]);
    out.has_rva = j.value("has_rva", false);
    out.segment_name = j.value("segment", std::string());
    out.segment_class = j.value("segment_class", std::string());
    out.segment_permissions = j.value("segment_permissions", 0u);
    out.symbol_name = j.value("symbol", std::string());
    out.demangled_name = j.value("demangled", std::string());
    if (j.contains("function_ea"))
        out.function_ea = parse_u64(j["function_ea"]);
    if (j.contains("function_rva"))
        out.function_rva = parse_u64(j["function_rva"]);
    out.function_name = j.value("function_name", std::string());
    out.api_confidence = j.value("api_confidence", std::string("exact"));
    return out;
}

layer_status_t layer_status_from_json(const json& j)
{
    layer_status_t out;
    if (!j.is_object())
        return out;
    out.layer = j.value("layer", std::string());
    if (j.contains("state"))
        out.state = parse_layer_state(j["state"]);
    out.reason = j.value("reason", std::string());
    out.exception_class = j.value("exception_class", std::string());
    out.cutoff_reason = j.value("cutoff_reason", std::string());
    if (j.contains("fallback_layers"))
        out.fallback_layers = string_vector_from_json(j["fallback_layers"]);
    out.elapsed_ms = j.value("elapsed_ms", std::uint64_t(0));
    out.emitted = j.value("emitted", std::size_t(0));
    out.total = j.value("total", std::size_t(0));
    out.cache_hit = j.value("cache_hit", false);
    out.timeout = j.value("timeout", false);
    out.cancelled = j.value("cancelled", false);
    out.diagnostics = j.value("diagnostics", json::object());
    return out;
}

operand_fact_t operand_from_json(const json& j)
{
    operand_fact_t out;
    if (!j.is_object())
        return out;
    out.index = j.value("index", -1);
    out.type = j.value("type", std::string());
    out.value_ref = j.value("value_ref", std::string("unknown"));
    out.address_expr = j.value("address_expr", std::string());
    out.alias_class = j.value("alias_class", std::string("unknown"));
    out.type_ref = j.value("type_ref", std::string());
    out.type_id = j.value("type_id", 0u);
    out.dtype = j.value("dtype", 0u);
    out.width_bits = j.value("width_bits", 0u);
    out.offb = j.value("offb", 0);
    out.offo = j.value("offo", 0);
    out.reg = j.value("reg", std::uint64_t(0));
    out.phrase = j.value("phrase", std::uint64_t(0));
    if (j.contains("value"))
        out.value = parse_u64(j["value"]);
    if (j.contains("address"))
        out.address = parse_u64(j["address"]);
    if (j.contains("specval"))
        out.specval = parse_u64(j["specval"]);
    out.flags = j.value("flags", 0u);
    out.shown = j.value("shown", true);
    out.text = j.value("text", std::string());
    if (j.contains("address_identity"))
        out.address_identity = address_identity_from_json(j["address_identity"]);
    return out;
}

xref_fact_t xref_from_json(const json& j)
{
    xref_fact_t out;
    if (!j.is_object())
        return out;
    if (j.contains("from"))
        out.from = address_identity_from_json(j["from"]);
    if (j.contains("to"))
        out.to = address_identity_from_json(j["to"]);
    out.is_code = j.value("is_code", false);
    out.user = j.value("user", false);
    out.type = j.value("type", 0u);
    out.direction = j.value("direction", std::string());
    out.source_disasm = j.value("source_disasm", std::string());
    return out;
}

instruction_fact_t instruction_from_json(const json& j)
{
    instruction_fact_t out;
    if (!j.is_object())
        return out;
    if (j.contains("location"))
        out.location = address_identity_from_json(j["location"]);
    out.itype = j.value("itype", 0u);
    out.feature_flags = j.value("feature_flags", 0u);
    out.item_flags = j.value("item_flags", std::uint64_t(0));
    out.size = j.value("size", 0u);
    out.mnemonic = j.value("mnemonic", std::string());
    out.disassembly = j.value("disassembly", std::string());
    out.bytes_hex = j.value("bytes", std::string());
    out.raw_effects = j.value("raw_effects", json::array());
    if (j.contains("register_uses"))
        out.register_uses = string_vector_from_json(j["register_uses"]);
    if (j.contains("register_defs"))
        out.register_defs = string_vector_from_json(j["register_defs"]);
    if (j.contains("operands") && j["operands"].is_array())
    {
        for (const auto& item : j["operands"])
            out.operands.push_back(operand_from_json(item));
    }
    if (j.contains("xrefs_from") && j["xrefs_from"].is_array())
    {
        for (const auto& item : j["xrefs_from"])
            out.xrefs_from.push_back(xref_from_json(item));
    }
    if (j.contains("xrefs_to") && j["xrefs_to"].is_array())
    {
        for (const auto& item : j["xrefs_to"])
            out.xrefs_to.push_back(xref_from_json(item));
    }
    if (j.contains("branch_targets") && j["branch_targets"].is_array())
    {
        for (const auto& item : j["branch_targets"])
            out.branch_targets.push_back(parse_u64(item));
    }
    out.stack_delta = j.value("stack_delta", std::int64_t(0));
    if (j.contains("fallthrough_ea"))
        out.fallthrough_ea = parse_u64(j["fallthrough_ea"]);
    out.has_fallthrough = j.value("has_fallthrough", false);
    out.is_call = j.value("is_call", false);
    out.is_return = j.value("is_return", false);
    out.is_branch = j.value("is_branch", false);
    out.is_indirect = j.value("is_indirect", false);
    out.is_conditional = j.value("is_conditional", false);
    out.is_noreturn = j.value("is_noreturn", false);
    out.block_end = j.value("block_end", false);
    out.unknown_effect = j.value("unknown_effect", false);
    return out;
}

basic_block_fact_t basic_block_from_json(const json& j)
{
    basic_block_fact_t out;
    if (!j.is_object())
        return out;
    out.id = j.value("id", std::size_t(0));
    if (j.contains("start"))
        out.start = address_identity_from_json(j["start"]);
    if (j.contains("end"))
        out.end = address_identity_from_json(j["end"]);
    if (j.contains("instruction_eas") && j["instruction_eas"].is_array())
    {
        for (const auto& item : j["instruction_eas"])
            out.instruction_eas.push_back(parse_u64(item));
    }
    if (j.contains("predecessors") && j["predecessors"].is_array())
        out.predecessors = j["predecessors"].get<std::vector<std::size_t>>();
    if (j.contains("successors") && j["successors"].is_array())
        out.successors = j["successors"].get<std::vector<std::size_t>>();
    out.edges = j.value("edges", json::array());
    out.terminal_kind = j.value("terminal_kind", std::string());
    out.is_return = j.value("is_return", false);
    out.is_noreturn = j.value("is_noreturn", false);
    return out;
}

call_fact_t call_from_json(const json& j)
{
    call_fact_t out;
    if (!j.is_object())
        return out;
    if (j.contains("callsite"))
        out.callsite = address_identity_from_json(j["callsite"]);
    if (j.contains("target"))
        out.target = address_identity_from_json(j["target"]);
    out.kind = j.value("kind", std::string());
    out.callee_name = j.value("callee_name", std::string());
    out.resolution_quality = j.value("resolution_quality", std::string("unresolved"));
    if (j.contains("target_preconditions"))
        out.target_preconditions = string_vector_from_json(j["target_preconditions"]);
    out.resolved = j.value("resolved", false);
    out.does_return = j.value("does_return", true);
    out.confidence = j.value("confidence", std::string());
    if (j.contains("arguments") && j["arguments"].is_array())
    {
        for (const auto& item : j["arguments"])
            out.arguments.push_back(operand_from_json(item));
    }
    return out;
}

branch_fact_t branch_from_json(const json& j)
{
    branch_fact_t out;
    if (!j.is_object())
        return out;
    if (j.contains("branch"))
        out.branch = address_identity_from_json(j["branch"]);
    out.kind = j.value("kind", std::string());
    out.predicate_text = j.value("predicate_text", std::string());
    if (j.contains("targets") && j["targets"].is_array())
    {
        for (const auto& item : j["targets"])
            out.targets.push_back(address_identity_from_json(item));
    }
    if (j.contains("true_target_ea"))
        out.true_target_ea = parse_u64(j["true_target_ea"]);
    if (j.contains("false_target_ea"))
        out.false_target_ea = parse_u64(j["false_target_ea"]);
    if (j.contains("ctree_parent_ids") && j["ctree_parent_ids"].is_array())
        out.ctree_parent_ids = j["ctree_parent_ids"].get<std::vector<std::size_t>>();
    out.conditional = j.value("conditional", false);
    return out;
}

type_fact_t type_fact_from_json(const json& j)
{
    type_fact_t out;
    if (!j.is_object())
        return out;
    out.present = j.value("present", false);
    out.is_function = j.value("is_function", false);
    out.is_noreturn = j.value("is_noreturn", false);
    out.type_text = j.value("type_text", std::string());
    out.return_type = j.value("return_type", std::string());
    if (j.contains("arguments"))
        out.arguments = string_vector_from_json(j["arguments"]);
    if (j.contains("spoiled_registers"))
        out.spoiled_registers = string_vector_from_json(j["spoiled_registers"]);
    out.argument_details = j.value("argument_details", json::array());
    out.local_variables = j.value("local_variables", json::array());
    out.stack_variables = j.value("stack_variables", json::array());
    out.referenced_udts = j.value("referenced_udts", json::array());
    out.referenced_enums = j.value("referenced_enums", json::array());
    out.udt_layouts = j.value("udt_layouts", json::array());
    out.member_offsets = j.value("member_offsets", json::array());
    out.dependencies = j.value("dependencies", json::array());
    return out;
}

ctree_node_fact_t ctree_node_from_json(const json& j)
{
    ctree_node_fact_t out;
    if (!j.is_object())
        return out;
    out.id = j.value("id", std::size_t(0));
    if (j.contains("location"))
        out.location = address_identity_from_json(j["location"]);
    out.op = j.value("op", std::string());
    out.role = j.value("role", std::string());
    out.text = j.value("text", std::string());
    out.type_text = j.value("type_text", std::string());
    out.value_kind = j.value("value_kind", std::string("unknown"));
    out.callee_text = j.value("callee_text", std::string());
    if (j.contains("argument_texts"))
        out.argument_texts = string_vector_from_json(j["argument_texts"]);
    if (j.contains("lvar_refs"))
        out.lvar_refs = string_vector_from_json(j["lvar_refs"]);
    out.member_refs = j.value("member_refs", json::array());
    out.object_refs = j.value("object_refs", json::array());
    out.constants = j.value("constants", json::array());
    if (j.contains("true_child_id") && !j["true_child_id"].is_null())
        out.true_child_id = j["true_child_id"].get<std::size_t>();
    if (j.contains("false_child_id") && !j["false_child_id"].is_null())
        out.false_child_id = j["false_child_id"].get<std::size_t>();
    if (j.contains("parent_ids") && j["parent_ids"].is_array())
        out.parent_ids = j["parent_ids"].get<std::vector<std::size_t>>();
    if (j.contains("parent_eas") && j["parent_eas"].is_array())
    {
        for (const auto& item : j["parent_eas"])
            out.parent_eas.push_back(parse_u64(item));
    }
    out.is_call = j.value("is_call", false);
    out.is_assignment = j.value("is_assignment", false);
    out.is_branch = j.value("is_branch", false);
    out.is_return = j.value("is_return", false);
    out.is_switch = j.value("is_switch", false);
    out.is_loop = j.value("is_loop", false);
    out.is_memory_ref = j.value("is_memory_ref", false);
    return out;
}

ctree_fact_t ctree_fact_from_json(const json& j)
{
    ctree_fact_t out;
    if (!j.is_object())
        return out;
    if (j.contains("status"))
        out.status = layer_status_from_json(j["status"]);
    if (j.contains("pseudocode_lines"))
        out.pseudocode_lines = string_vector_from_json(j["pseudocode_lines"]);
    out.locals = j.value("locals", json::array());
    if (j.contains("nodes") && j["nodes"].is_array())
    {
        for (const auto& item : j["nodes"])
            out.nodes.push_back(ctree_node_from_json(item));
    }
    out.branch_facts = j.value("branch_facts", json::array());
    out.call_facts = j.value("call_facts", json::array());
    out.assignment_facts = j.value("assignment_facts", json::array());
    out.memory_facts = j.value("memory_facts", json::array());
    return out;
}

microcode_fact_t microcode_fact_from_json(const json& j)
{
    microcode_fact_t out;
    if (!j.is_object())
        return out;
    if (j.contains("status"))
        out.status = layer_status_from_json(j["status"]);
    out.maturity = j.value("maturity", std::string());
    out.blocks = j.value("blocks", json::array());
    out.calls = j.value("calls", json::array());
    out.use_def = j.value("use_def", json::array());
    out.effects = j.value("effects", json::array());
    return out;
}

extraction_cache_status_t cache_status_from_json(const json& j)
{
    extraction_cache_status_t out;
    if (!j.is_object())
        return out;
    out.schema = j.value("schema", std::string(k_chain_extraction_schema));
    out.key = j.value("key", std::string());
    out.lookup_state = j.value("lookup_state", std::string("miss"));
    out.invalidation_reason = j.value("invalidation_reason", std::string());
    out.hit = j.value("hit", false);
    out.persistent = j.value("persistent", false);
    out.force_refresh = j.value("force_refresh", false);
    out.memory_entries = j.value("memory_entries", std::size_t(0));
    out.memory_bytes = j.value("memory_bytes", std::size_t(0));
    out.persistent_bytes = j.value("persistent_bytes", std::size_t(0));
    out.hits = j.value("hits", std::uint64_t(0));
    out.misses = j.value("misses", std::uint64_t(0));
    out.persistent_hits = j.value("persistent_hits", std::uint64_t(0));
    out.stores = j.value("stores", std::uint64_t(0));
    return out;
}

function_identity_t function_identity_from_json(const json& j)
{
    function_identity_t out;
    if (!j.is_object())
        return out;
    if (j.contains("start"))
        out.start = address_identity_from_json(j["start"]);
    if (j.contains("end"))
        out.end = address_identity_from_json(j["end"]);
    out.size = j.value("size", std::uint64_t(0));
    out.flags = j.value("flags", 0u);
    out.does_return = j.value("does_return", true);
    out.is_thunk = j.value("is_thunk", false);
    out.is_tail = j.value("is_tail", false);
    out.byte_digest = j.value("byte_digest", std::string());
    out.type_digest = j.value("type_digest", std::string());
    out.cache_key = j.value("cache_key", std::string());
    return out;
}

function_snapshot_t function_snapshot_from_json(const json& j)
{
    function_snapshot_t out;
    if (!j.is_object())
        return out;
    if (j.contains("identity"))
        out.identity = function_identity_from_json(j["identity"]);
    if (j.contains("cache"))
        out.cache = cache_status_from_json(j["cache"]);
    if (j.contains("statuses") && j["statuses"].is_array())
    {
        for (const auto& item : j["statuses"])
            out.statuses.push_back(layer_status_from_json(item));
    }
    if (j.contains("instructions") && j["instructions"].is_array())
    {
        for (const auto& item : j["instructions"])
            out.instructions.push_back(instruction_from_json(item));
    }
    if (j.contains("basic_blocks") && j["basic_blocks"].is_array())
    {
        for (const auto& item : j["basic_blocks"])
            out.basic_blocks.push_back(basic_block_from_json(item));
    }
    if (j.contains("xrefs_from") && j["xrefs_from"].is_array())
    {
        for (const auto& item : j["xrefs_from"])
            out.xrefs_from.push_back(xref_from_json(item));
    }
    if (j.contains("xrefs_to") && j["xrefs_to"].is_array())
    {
        for (const auto& item : j["xrefs_to"])
            out.xrefs_to.push_back(xref_from_json(item));
    }
    out.xref_from_index = j.value("xref_from_index", json::object());
    out.xref_to_index = j.value("xref_to_index", json::object());
    if (j.contains("calls") && j["calls"].is_array())
    {
        for (const auto& item : j["calls"])
            out.calls.push_back(call_from_json(item));
    }
    if (j.contains("branches") && j["branches"].is_array())
    {
        for (const auto& item : j["branches"])
            out.branches.push_back(branch_from_json(item));
    }
    out.effects = j.value("effects", json::array());
    if (j.contains("type"))
        out.type = type_fact_from_json(j["type"]);
    if (j.contains("ctree"))
        out.ctree = ctree_fact_from_json(j["ctree"]);
    if (j.contains("microcode") && j["microcode"].is_array())
    {
        for (const auto& item : j["microcode"])
            out.microcode.push_back(microcode_fact_from_json(item));
    }
    out.diagnostics = j.value("diagnostics", json::object());
    out.complete = j.value("complete", false);
    return out;
}

nodeidx_t slot_for_key(const std::string& key)
{
    std::uint64_t h = k_fnv_offset;
    fnv_append(h, key);
    if (sizeof(nodeidx_t) < sizeof(std::uint64_t))
        h = (h ^ (h >> 32)) & 0x7FFFFFFFull;
    else
        h &= 0x7FFFFFFFFFFFFFFFull;
    nodeidx_t slot = static_cast<nodeidx_t>(h);
    if (slot == BADNODE || slot == 0)
        slot = 1;
    return slot;
}

std::string options_digest(const extraction_options_t& options)
{
    std::uint64_t h = k_fnv_offset;
    fnv_append(h, static_cast<std::uint64_t>(options.include_bytes));
    fnv_append(h, static_cast<std::uint64_t>(options.include_xrefs));
    fnv_append(h, static_cast<std::uint64_t>(options.include_types));
    fnv_append(h, static_cast<std::uint64_t>(options.include_ctree));
    fnv_append(h, static_cast<std::uint64_t>(options.include_microcode));
    fnv_append(h, static_cast<std::uint64_t>(options.include_effects));
    fnv_append(h, static_cast<std::uint64_t>(options.include_xref_indexes));
    fnv_append(h, static_cast<std::uint64_t>(options.max_instructions));
    fnv_append(h, static_cast<std::uint64_t>(options.max_basic_blocks));
    fnv_append(h, static_cast<std::uint64_t>(options.max_xrefs_per_address));
    fnv_append(h, static_cast<std::uint64_t>(options.max_ctree_nodes));
    fnv_append(h, static_cast<std::uint64_t>(options.max_microcode_instructions));
    fnv_append(h, static_cast<std::uint64_t>(options.max_pseudocode_lines));
    fnv_append(h, static_cast<std::uint64_t>(options.max_module_items));
    for (const std::string& maturity : options.microcode_maturities)
        fnv_append(h, maturity);
    return fnv_hex(h);
}

struct cache_entry_t
{
    function_snapshot_t snapshot;
    std::size_t bytes = 0;
    std::uint64_t last_access = 0;
};

class extraction_cache_t
{
    std::mutex m_mutex;
    std::unordered_map<std::string, cache_entry_t> m_entries;
    std::deque<std::string> m_lru;
    std::uint64_t m_hits = 0;
    std::uint64_t m_misses = 0;
    std::uint64_t m_persistent_hits = 0;
    std::uint64_t m_stores = 0;
    std::size_t m_memory_bytes = 0;

    static constexpr std::size_t k_max_entries = 256;
    static constexpr std::size_t k_max_memory_bytes = 64ull * 1024ull * 1024ull;
    static constexpr std::size_t k_max_persistent_bytes = 8ull * 1024ull * 1024ull;
    static constexpr uchar k_blob_tag = 'X';

    static netnode node(bool create)
    {
        return netnode("$ AiDA.chain.extraction.cache", 0, create);
    }

    void touch_locked(const std::string& key)
    {
        m_lru.erase(std::remove(m_lru.begin(), m_lru.end(), key), m_lru.end());
        m_lru.push_back(key);
    }

    void trim_locked()
    {
        while ((!m_lru.empty() && m_entries.size() > k_max_entries) || m_memory_bytes > k_max_memory_bytes)
        {
            const std::string victim = m_lru.front();
            m_lru.pop_front();
            auto it = m_entries.find(victim);
            if (it == m_entries.end())
                continue;
            m_memory_bytes -= std::min(m_memory_bytes, it->second.bytes);
            m_entries.erase(it);
        }
    }

    bool persistent_load_locked(const std::string& key, function_snapshot_t& out, std::size_t& bytes)
    {
        netnode nn = node(false);
        if (nn == BADNODE)
            return false;
        qvector<uchar> qblob;
        if (nn.getblob(&qblob, slot_for_key(key), k_blob_tag) <= 0)
            return false;
        bytes = qblob.size();
        try
        {
            std::vector<std::uint8_t> blob(qblob.begin(), qblob.end());
            json root = json::from_msgpack(blob, true, false);
            if (!root.is_object() || root.value("key", std::string()) != key)
                return false;
            out = function_snapshot_from_json(root.value("snapshot", json::object()));
            return !out.identity.cache_key.empty();
        }
        catch (...)
        {
            return false;
        }
    }

    void persistent_store_locked(const std::string& key, const function_snapshot_t& snapshot, std::size_t& bytes)
    {
        netnode nn = node(true);
        if (nn == BADNODE)
            return;
        json root;
        root["schema"] = k_chain_extraction_schema;
        root["key"] = key;
        root["stored_ms"] = now_ms();
        root["snapshot"] = to_json(snapshot);
        std::vector<std::uint8_t> blob = json::to_msgpack(root);
        bytes = blob.size();
        if (blob.empty() || blob.size() > k_max_persistent_bytes)
            return;
        nn.setblob(blob.data(), blob.size(), slot_for_key(key), k_blob_tag);
    }

public:
    static extraction_cache_t& instance()
    {
        static extraction_cache_t cache;
        return cache;
    }

    bool lookup(const std::string& key, function_snapshot_t& out, extraction_cache_status_t& status)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        status.key = key;
        auto it = m_entries.find(key);
        if (it != m_entries.end())
        {
            ++m_hits;
            it->second.last_access = now_ms();
            touch_locked(key);
            out = it->second.snapshot;
            status.hit = true;
            status.lookup_state = "memory_hit";
            status.memory_entries = m_entries.size();
            status.memory_bytes = m_memory_bytes;
            status.hits = m_hits;
            status.misses = m_misses;
            status.persistent_hits = m_persistent_hits;
            status.stores = m_stores;
            return true;
        }
        std::size_t persistent_bytes = 0;
        function_snapshot_t loaded;
        if (persistent_load_locked(key, loaded, persistent_bytes))
        {
            ++m_hits;
            ++m_persistent_hits;
            cache_entry_t entry;
            entry.snapshot = loaded;
            entry.bytes = persistent_bytes;
            entry.last_access = now_ms();
            m_memory_bytes += entry.bytes;
            m_entries[key] = entry;
            touch_locked(key);
            trim_locked();
            out = loaded;
            status.hit = true;
            status.persistent = true;
            status.persistent_bytes = persistent_bytes;
            status.lookup_state = "persistent_hit";
            status.memory_entries = m_entries.size();
            status.memory_bytes = m_memory_bytes;
            status.hits = m_hits;
            status.misses = m_misses;
            status.persistent_hits = m_persistent_hits;
            status.stores = m_stores;
            return true;
        }
        ++m_misses;
        status.hit = false;
        status.lookup_state = "miss";
        status.memory_entries = m_entries.size();
        status.memory_bytes = m_memory_bytes;
        status.hits = m_hits;
        status.misses = m_misses;
        status.persistent_hits = m_persistent_hits;
        status.stores = m_stores;
        return false;
    }

    extraction_cache_status_t store(const std::string& key, const function_snapshot_t& snapshot)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        extraction_cache_status_t status;
        status.key = key;
        status.lookup_state = "stored_after_miss";
        cache_entry_t entry;
        entry.snapshot = snapshot;
        entry.bytes = to_json(snapshot).dump().size();
        entry.last_access = now_ms();
        auto it = m_entries.find(key);
        if (it != m_entries.end())
            m_memory_bytes -= std::min(m_memory_bytes, it->second.bytes);
        m_entries[key] = entry;
        m_memory_bytes += entry.bytes;
        touch_locked(key);
        std::size_t persistent_bytes = 0;
        persistent_store_locked(key, snapshot, persistent_bytes);
        ++m_stores;
        trim_locked();
        status.memory_entries = m_entries.size();
        status.memory_bytes = m_memory_bytes;
        status.persistent_bytes = persistent_bytes;
        status.hits = m_hits;
        status.misses = m_misses;
        status.persistent_hits = m_persistent_hits;
        status.stores = m_stores;
        return status;
    }

    json status()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        extraction_cache_status_t status;
        status.lookup_state = "status";
        status.memory_entries = m_entries.size();
        status.memory_bytes = m_memory_bytes;
        status.hits = m_hits;
        status.misses = m_misses;
        status.persistent_hits = m_persistent_hits;
        status.stores = m_stores;
        return to_json(status);
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.clear();
        m_lru.clear();
        m_memory_bytes = 0;
        netnode nn = node(false);
        if (nn != BADNODE)
            nn.kill();
    }
};

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
    corpus_identity_t corpus;
    corpus.canonical_name = canonical_name_from_path(out.input_path.empty() ? out.module_name : out.input_path);
    corpus.input_path = out.input_path;
    corpus.hashes.md5 = out.input_md5;
    corpus.hashes.sha256 = out.input_sha256;
    corpus.image_base = out.image_base;
    corpus.min_ea = out.min_ea;
    corpus.max_ea = out.max_ea;
    corpus.processor = out.processor;
    corpus.bitness = out.pointer_width_bits;
    out.module_id = derive_module_id(corpus);
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

bool append_unique_xref(std::vector<xref_fact_t>& dst, const xref_fact_t& xref, std::set<std::string>& seen)
{
    std::string key = xref.direction + ":" + std::to_string(xref.from.ea) + ":" + std::to_string(xref.to.ea) + ":" + std::to_string(xref.type);
    if (!seen.insert(key).second)
        return false;
    dst.push_back(xref);
    return true;
}

void append_xref_index(json& index, const xref_fact_t& xref, bool by_from)
{
    const std::string key = hex_u64(by_from ? xref.from.ea : xref.to.ea);
    if (!index.contains(key) || !index[key].is_array())
        index[key] = json::array();
    index[key].push_back(to_json(xref));
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
    out.offb = op.offb;
    out.offo = op.offo;
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
    out.value_ref = value_ref_for_operand(out);
    out.address_expr = operand_is_memory_fact(out) ? out.text : std::string();
    out.alias_class = alias_class_for_operand(out);
    out.type_ref = out.width_bits == 0 ? std::string() : ("bits:" + std::to_string(out.width_bits));
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
    out.item_flags = static_cast<std::uint64_t>(get_flags(ins.ea));
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
    auto bytes = read_bytes(ins.ea, ins.size);
    if (!bytes.empty())
    {
        fnv_append(byte_hash, bytes.data(), bytes.size());
        if (options.include_bytes)
            out.bytes_hex = hex_bytes(bytes);
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
    out.block_end = out.is_return || out.is_branch || out.is_call || out.is_noreturn || !out.has_fallthrough;
    apply_raw_semantics(out, module.pointer_width_bits);
    return out;
}

std::string type_to_string(const tinfo_t& tif, const char* name = nullptr)
{
    qstring out;
    if (tif.print(&out, name, PRTYPE_1LINE))
        return qstring_to_string(out);
    const char* debug = tif.dstr();
    return debug != nullptr ? std::string(debug) : std::string();
}

json type_ref_json(const tinfo_t& tif, const std::string& role)
{
    json out;
    out["role"] = role;
    out["text"] = type_to_string(tif);
    out["tid"] = tif.get_tid() == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(tif.get_tid()));
    out["ordinal"] = tif.get_ordinal();
    out["is_udt"] = tif.is_udt();
    out["is_enum"] = tif.is_enum();
    out["is_ptr"] = tif.is_ptr();
    return out;
}

json udm_to_json(const udm_t& member, std::size_t index, const std::string& owner)
{
    json out;
    out["index"] = index;
    out["owner"] = owner;
    out["name"] = qstring_to_string(member.name);
    out["type"] = type_to_string(member.type);
    out["offset_bits"] = member.offset;
    out["offset_bytes"] = member.offset / 8;
    out["size_bits"] = member.size;
    out["size_bytes"] = member.size / 8;
    out["tid"] = member.type.get_tid() == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(member.type.get_tid()));
    out["ordinal"] = member.type.get_ordinal();
    out["is_bitfield"] = member.is_bitfield();
    out["is_baseclass"] = member.is_baseclass();
    out["is_vftable"] = member.is_vftable();
    out["is_gap"] = member.is_gap();
    out["is_retaddr"] = member.is_retaddr();
    out["is_savregs"] = member.is_savregs();
    return out;
}

void append_dependency(json& dependencies, const json& dep)
{
    const std::string key = dep.dump();
    for (const auto& existing : dependencies)
    {
        if (existing.dump() == key)
            return;
    }
    dependencies.push_back(dep);
}

void collect_udt_layout(const tinfo_t& tif,
                        const std::string& role,
                        type_fact_t& out,
                        std::set<std::string>& seen)
{
    if (tif.empty())
        return;
    tinfo_t cur = tif;
    if (cur.is_ptr())
        cur = cur.get_pointed_object();
    if (!cur.is_udt() && !cur.is_enum())
        return;
    json ref = type_ref_json(cur, role);
    append_dependency(out.dependencies, ref);
    const std::string ref_key = ref.dump();
    if (!seen.insert(ref_key).second)
        return;
    if (cur.is_enum())
    {
        out.referenced_enums.push_back(ref);
        return;
    }
    out.referenced_udts.push_back(ref);
    udt_type_data_t udt;
    if (!cur.get_udt_details(&udt))
        return;
    json layout;
    layout["role"] = role;
    layout["type"] = type_to_string(cur);
    layout["tid"] = cur.get_tid() == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(cur.get_tid()));
    layout["ordinal"] = cur.get_ordinal();
    layout["total_size"] = udt.total_size;
    layout["unpadded_size"] = udt.unpadded_size;
    layout["effalign"] = udt.effalign;
    layout["is_union"] = udt.is_union;
    layout["members"] = json::array();
    for (std::size_t i = 0; i < udt.size(); ++i)
    {
        json member = udm_to_json(udt[i], i, role);
        layout["members"].push_back(member);
        out.member_offsets.push_back(member);
        collect_udt_layout(udt[i].type, role + "." + qstring_to_string(udt[i].name), out, seen);
    }
    out.udt_layouts.push_back(std::move(layout));
}

json argloc_to_json(const argloc_t& loc)
{
    char rendered[256] = {};
    if (print_argloc(rendered, sizeof(rendered), loc, 0, PRALOC_STKOFF) != 0 && rendered[0] != '\0')
        return std::string(rendered);
    std::ostringstream ss;
    ss << "atype:" << static_cast<int>(loc.atype());
    if (loc.is_reg1())
        ss << ":reg" << loc.reg1() << ":off" << loc.regoff();
    else if (loc.is_reg2())
        ss << ":reg" << loc.reg1() << ":reg" << loc.reg2();
    else if (loc.is_stkoff())
        ss << ":stk" << loc.stkoff();
    else if (loc.is_ea())
        ss << ":ea" << hex_u64(static_cast<std::uint64_t>(loc.get_ea()));
    return ss.str();
}

type_fact_t extract_type_fact(func_t& fn, std::string& type_digest)
{
    type_fact_t out;
    std::set<std::string> seen_types;
    tinfo_t tif;
    if (!get_tinfo(&tif, fn.start_ea))
    {
        tinfo_t frame;
        if (get_func_frame(&frame, &fn))
        {
            out.present = true;
            collect_udt_layout(frame, "frame", out, seen_types);
        }
        type_digest = out.dependencies.dump();
        return out;
    }
    out.present = true;
    out.type_text = type_to_string(tif);
    type_digest = out.type_text;
    collect_udt_layout(tif, "function_type", out, seen_types);
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
    out.return_type = type_to_string(ftd.rettype);
    collect_udt_layout(ftd.rettype, "return", out, seen_types);
    for (std::size_t i = 0; i < ftd.size(); ++i)
    {
        const funcarg_t& arg = ftd[i];
        const char* arg_name = arg.name.empty() ? nullptr : arg.name.c_str();
        out.arguments.push_back(type_to_string(arg.type, arg_name));
        json aj;
        aj["index"] = i;
        aj["name"] = arg.name.c_str();
        aj["type"] = type_to_string(arg.type);
        aj["location"] = argloc_to_json(arg.argloc);
        aj["flags"] = arg.flags;
        aj["is_struct"] = (arg.flags & FAI_STRUCT) != 0;
        out.argument_details.push_back(aj);
        collect_udt_layout(arg.type, "arg:" + std::to_string(i), out, seen_types);
    }
    for (const reg_info_t& reg : ftd.spoiled)
    {
        out.spoiled_registers.push_back("reg:" + std::to_string(reg.reg) + ":" + std::to_string(reg.size));
    }
    tinfo_t frame;
    if (get_func_frame(&frame, &fn))
    {
        collect_udt_layout(frame, "frame", out, seen_types);
        udt_type_data_t udt;
        if (frame.get_udt_details(&udt))
        {
            for (std::size_t i = 0; i < udt.size(); ++i)
            {
                const udm_t& m = udt[i];
                json sj = udm_to_json(m, i, "frame");
                const sval_t fpoff = soff_to_fpoff(&fn, static_cast<uval_t>(m.offset / 8));
                sj["fp_offset"] = fpoff;
                sj["kind"] = m.is_special_member() ? "special" : (fpoff < 0 ? "local" : "argument");
                out.stack_variables.push_back(sj);
                if (fpoff < 0)
                    out.local_variables.push_back(sj);
            }
        }
    }
    type_digest = out.type_text + "|" + out.argument_details.dump() + "|" + out.dependencies.dump() + "|" + out.stack_variables.dump();
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

bool is_loop_opcode(ctype_t op)
{
    return op == cit_for || op == cit_while || op == cit_do;
}

std::string ctree_value_kind(ctype_t op)
{
    switch (op)
    {
    case cot_num:    return "constant";
    case cot_str:    return "string";
    case cot_obj:    return "object";
    case cot_var:    return "local";
    case cot_call:   return "call";
    case cot_ptr:
    case cot_idx:
    case cot_memref:
    case cot_memptr: return "memory";
    default:         return is_assignment(op) ? "assignment" : "expression";
    }
}

struct ctree_collector_t : public ctree_visitor_t
{
    cfunc_t& cfunc;
    const module_identity_t& module;
    std::size_t limit;
    std::unordered_map<const citem_t*, std::size_t> ids;
    std::vector<ctree_node_fact_t> nodes;
    json branch_facts = json::array();
    json call_facts = json::array();
    json assignment_facts = json::array();
    json memory_facts = json::array();
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

    void append_expr_metadata(ctree_node_fact_t& node, const cexpr_t& expr)
    {
        node.type_text = cexpr_type_text(expr);
        node.value_kind = ctree_value_kind(expr.op);
        node.is_call = expr.op == cot_call;
        node.is_assignment = is_assignment(expr.op);
        node.is_memory_ref = expr.op == cot_ptr || expr.op == cot_idx || expr.op == cot_memref || expr.op == cot_memptr;
        switch (expr.op)
        {
        case cot_call:
            if (expr.x != nullptr)
                node.callee_text = citem_text(*expr.x, cfunc);
            if (expr.a != nullptr)
            {
                for (const carg_t& arg : *expr.a)
                    node.argument_texts.push_back(citem_text(arg, cfunc));
            }
            call_facts.push_back({{"id", node.id},
                                  {"ea", expr.ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(expr.ea))},
                                  {"callee", node.callee_text},
                                  {"arguments", node.argument_texts},
                                  {"parent_ids", node.parent_ids},
                                  {"type", node.type_text}});
            break;
        case cot_var:
        {
            json ref;
            ref["index"] = expr.v.idx;
            if (lvars_t* lvars = cfunc.get_lvars())
            {
                if (expr.v.idx >= 0 && static_cast<std::size_t>(expr.v.idx) < lvars->size())
                {
                    const lvar_t& lv = (*lvars)[static_cast<std::size_t>(expr.v.idx)];
                    ref["name"] = qstring_to_string(lv.name);
                    ref["is_arg"] = lv.is_arg_var();
                    ref["is_stack"] = lv.is_stk_var();
                    ref["is_reg"] = lv.is_reg_var();
                    ref["width"] = lv.width;
                }
            }
            node.lvar_refs.push_back(ref.dump());
            break;
        }
        case cot_obj:
            node.object_refs.push_back({{"ea", hex_u64(static_cast<std::uint64_t>(expr.obj_ea))},
                                        {"identity", to_json(address_for(expr.obj_ea, module))},
                                        {"refwidth", expr.refwidth}});
            break;
        case cot_num:
        {
            const std::uint64_t value = expr.numval();
            node.constants.push_back({{"value", hex_u64(value)}, {"width", expr.type.get_size()}});
            break;
        }
        case cot_str:
            node.constants.push_back({{"string", expr.string != nullptr ? std::string(expr.string) : std::string()}});
            break;
        case cot_memref:
        case cot_memptr:
        {
            json ref;
            ref["member_offset"] = expr.m;
            ref["ptrsize"] = expr.op == cot_memptr ? expr.ptrsize : 0;
            ref["base"] = expr.x != nullptr ? citem_text(*expr.x, cfunc) : std::string();
            ref["type"] = node.type_text;
            node.member_refs.push_back(ref);
            memory_facts.push_back({{"id", node.id},
                                    {"ea", expr.ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(expr.ea))},
                                    {"kind", node.op},
                                    {"base", ref["base"]},
                                    {"member_offset", expr.m},
                                    {"width", expr.op == cot_memptr ? expr.ptrsize : expr.type.get_size()},
                                    {"type", node.type_text}});
            break;
        }
        case cot_ptr:
        case cot_idx:
            memory_facts.push_back({{"id", node.id},
                                    {"ea", expr.ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(expr.ea))},
                                    {"kind", node.op},
                                    {"base", expr.x != nullptr ? citem_text(*expr.x, cfunc) : std::string()},
                                    {"index", expr.op == cot_idx && expr.y != nullptr ? citem_text(*expr.y, cfunc) : std::string()},
                                    {"width", expr.op == cot_ptr ? expr.ptrsize : expr.type.get_size()},
                                    {"type", node.type_text}});
            break;
        default:
            break;
        }
        if (node.is_assignment)
        {
            assignment_facts.push_back({{"id", node.id},
                                        {"ea", expr.ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(expr.ea))},
                                        {"op", node.op},
                                        {"destination", expr.x != nullptr ? citem_text(*expr.x, cfunc) : std::string()},
                                        {"source", expr.y != nullptr ? citem_text(*expr.y, cfunc) : std::string()},
                                        {"type", node.type_text},
                                        {"parent_ids", node.parent_ids}});
        }
    }

    void append_insn_metadata(ctree_node_fact_t& node, const cinsn_t& insn)
    {
        node.is_branch = insn.op == cit_if || insn.op == cit_switch || insn.op == cit_goto || insn.op == cit_break || insn.op == cit_continue;
        node.is_return = insn.op == cit_return;
        node.is_switch = insn.op == cit_switch;
        node.is_loop = is_loop_opcode(insn.op);
        if (insn.op == cit_if && insn.cif != nullptr)
        {
            node.true_child_id = insn.cif->ithen != nullptr ? id_for(insn.cif->ithen) : static_cast<std::size_t>(-1);
            node.false_child_id = insn.cif->ielse != nullptr ? id_for(insn.cif->ielse) : static_cast<std::size_t>(-1);
            branch_facts.push_back({{"id", node.id},
                                    {"ea", insn.ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(insn.ea))},
                                    {"kind", "if"},
                                    {"condition", citem_text(insn.cif->expr, cfunc)},
                                    {"true_child_id", node.true_child_id == static_cast<std::size_t>(-1) ? json(nullptr) : json(node.true_child_id)},
                                    {"false_child_id", node.false_child_id == static_cast<std::size_t>(-1) ? json(nullptr) : json(node.false_child_id)},
                                    {"parent_ids", node.parent_ids}});
        }
        else if (insn.op == cit_switch && insn.cswitch != nullptr)
        {
            json cases = json::array();
            for (const ccase_t& c : insn.cswitch->cases)
            {
                json cj;
                cj["child_id"] = id_for(&c);
                cj["values"] = json::array();
                for (int i = 0; i < static_cast<int>(c.size()); ++i)
                    cj["values"].push_back(hex_u64(static_cast<std::uint64_t>(c.value(i))));
                cases.push_back(std::move(cj));
            }
            branch_facts.push_back({{"id", node.id},
                                    {"ea", insn.ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(insn.ea))},
                                    {"kind", "switch"},
                                    {"condition", citem_text(insn.cswitch->expr, cfunc)},
                                    {"cases", std::move(cases)},
                                    {"parent_ids", node.parent_ids}});
        }
        else if (node.is_loop)
        {
            const cexpr_t* cond = nullptr;
            const cinsn_t* body = nullptr;
            if (insn.op == cit_for && insn.cfor != nullptr)
            {
                cond = &insn.cfor->expr;
                body = insn.cfor->body;
            }
            else if (insn.op == cit_while && insn.cwhile != nullptr)
            {
                cond = &insn.cwhile->expr;
                body = insn.cwhile->body;
            }
            else if (insn.op == cit_do && insn.cdo != nullptr)
            {
                cond = &insn.cdo->expr;
                body = insn.cdo->body;
            }
            if (body != nullptr)
                node.true_child_id = id_for(body);
            branch_facts.push_back({{"id", node.id},
                                    {"ea", insn.ea == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(insn.ea))},
                                    {"kind", node.op},
                                    {"condition", cond != nullptr ? citem_text(*cond, cfunc) : std::string()},
                                    {"body_child_id", body != nullptr ? json(id_for(body)) : json(nullptr)},
                                    {"parent_ids", node.parent_ids}});
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
        append_expr_metadata(node, *expr);
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
        append_insn_metadata(node, *insn);
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
        out.branch_facts = std::move(visitor.branch_facts);
        out.call_facts = std::move(visitor.call_facts);
        out.assignment_facts = std::move(visitor.assignment_facts);
        out.memory_facts = std::move(visitor.memory_facts);
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
                if (!ud["may_use"].get<std::string>().empty())
                    out.effects.push_back({{"source_layer", "microcode"},
                                           {"kind", "may_use"},
                                           {"maturity", maturity},
                                           {"block", blk->serial},
                                           {"ea", ud["ea"]},
                                           {"mlist", ud["may_use"]},
                                           {"confidence", "conservative"}});
                if (!ud["may_def"].get<std::string>().empty())
                    out.effects.push_back({{"source_layer", "microcode"},
                                           {"kind", "may_def"},
                                           {"maturity", maturity},
                                           {"block", blk->serial},
                                           {"ea", ud["ea"]},
                                           {"mlist", ud["may_def"]},
                                           {"confidence", "conservative"}});
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
                        out.effects.push_back({{"source_layer", "microcode"},
                                               {"kind", call["kind"] == "indirect" ? "indirect_call" : "call"},
                                               {"maturity", maturity},
                                               {"block", blk->serial},
                                               {"ea", call["ea"]},
                                               {"callee_ea", call["callee_ea"]},
                                               {"callee_name", name},
                                               {"arguments", call["args"]},
                                               {"confidence", callee == BADADDR ? "unresolved" : "resolved"}});
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
        {
            const std::size_t succ = static_cast<std::size_t>(fc.succ(i, s));
            block.edges.push_back({{"from_block", block.id}, {"to_block", succ}, {"kind", "cfg_successor"}});
            block.successors.push_back(static_cast<std::size_t>(fc.succ(i, s)));
        }
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
    call.resolution_quality = ins.is_indirect ? "unresolved_indirect_operand" : "xref_target";
    call.arguments = ins.operands;
    for (std::uint64_t target : ins.branch_targets)
    {
        if (target == 0 || target == ins.fallthrough_ea)
            continue;
        call.target = address_for(static_cast<ea_t>(target), module);
        call.callee_name = !call.target.demangled_name.empty() ? call.target.demangled_name : call.target.symbol_name;
        call.resolved = true;
        call.resolution_quality = "code_xref";
        break;
    }
    if (!call.resolved)
    {
        call.confidence = "unresolved";
        call.target_preconditions.push_back(ins.is_indirect ? "state_resolves_indirect_call_target" : "missing_code_xref_to_callee");
    }
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
    if (branch.conditional)
    {
        branch.true_target_ea = !ins.branch_targets.empty() ? ins.branch_targets.front() : 0;
        branch.false_target_ea = ins.has_fallthrough ? ins.fallthrough_ea : 0;
    }
    return branch;
}

std::string build_cache_key(function_snapshot_t& snapshot, const extraction_options_t& options)
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
    fnv_append(h, static_cast<std::uint64_t>(snapshot.identity.start.module.pointer_width_bits));
    fnv_append(h, options_digest(options));
    fnv_append(h, static_cast<std::uint64_t>(inf_get_database_change_count()));
    const bool hexrays_layer_requested = options.include_ctree || options.include_microcode;
    fnv_append(h, static_cast<std::uint64_t>(hexrays_layer_requested && init_hexrays_plugin()));
    return fnv_hex(h);
}

layer_status_t cache_layer_status(const extraction_cache_status_t& cache, std::uint64_t start)
{
    layer_status_t status;
    status.layer = "cache";
    status.state = cache.hit ? layer_state_t::ok : layer_state_t::skipped;
    status.reason = cache.lookup_state;
    status.elapsed_ms = now_ms() - start;
    status.emitted = cache.hit ? 1 : 0;
    status.total = 1;
    status.cache_hit = cache.hit;
    status.diagnostics = to_json(cache);
    return status;
}

void finalize_function_snapshot(function_snapshot_t& snapshot,
                                const module_identity_t& module,
                                ea_t function_ea,
                                const std::string& operation)
{
    annotate_statuses(snapshot.statuses, module, function_ea, operation, &snapshot.cache);
    snapshot.diagnostics["operation"] = operation;
    snapshot.diagnostics["module"] = to_json(module);
    if (function_ea != BADADDR)
        snapshot.diagnostics["function_ea"] = hex_u64(static_cast<std::uint64_t>(function_ea));
    snapshot.diagnostics["cache"] = to_json(snapshot.cache);
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
        finalize_function_snapshot(out, module, BADADDR, "extract_function_snapshot");
        return out;
    }
    out.identity.start = address_for(pfn->start_ea, module);
    out.identity.end = address_for(pfn->end_ea, module);
    out.identity.size = pfn->end_ea > pfn->start_ea ? static_cast<std::uint64_t>(pfn->end_ea - pfn->start_ea) : 0;
    out.identity.flags = static_cast<std::uint32_t>(pfn->flags);
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
    extraction_stop_t raw_stop = extraction_stop_t::none;
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        if ((total & 0x3Fu) == 0)
        {
            raw_stop = stop_state(raw_start, options);
            if (raw_stop != extraction_stop_t::none)
                break;
        }
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
        {
            const bool added = append_unique_xref(out.xrefs_from, x, xref_from_seen);
            if (added && options.include_xref_indexes)
                append_xref_index(out.xref_from_index, x, true);
        }
        for (const auto& x : fact.xrefs_to)
        {
            const bool added = append_unique_xref(out.xrefs_to, x, xref_to_seen);
            if (added && options.include_xref_indexes)
                append_xref_index(out.xref_to_index, x, false);
        }
        if (fact.is_call)
            out.calls.push_back(call_from_instruction(fact, module));
        if (fact.is_branch || fact.is_return || fact.is_noreturn)
            out.branches.push_back(branch_from_instruction(fact, module));
        insn_by_ea.emplace(fact.location.ea, fact);
        out.instructions.push_back(std::move(fact));
    }
    out.identity.byte_digest = fnv_hex(byte_hash);
    if (raw_stop != extraction_stop_t::none)
    {
        out.statuses.push_back(stop_status("raw_instructions", raw_stop, raw_start, out.instructions.size(), total));
        out.complete = false;
        finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
        return out;
    }
    out.statuses.push_back(make_status("raw_instructions",
                                       truncated ? layer_state_t::truncated : layer_state_t::ok,
                                       truncated ? "instruction_limit_reached" : "",
                                       raw_start,
                                       out.instructions.size(),
                                       total));
    extraction_stop_t stop = stop_state(raw_start, options);
    if (stop != extraction_stop_t::none)
    {
        out.statuses.push_back(stop_status("raw_cfg", stop, now_ms(), 0, 0));
        out.complete = false;
        finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
        return out;
    }
    const std::uint64_t cfg_start = now_ms();
    out.basic_blocks = extract_basic_blocks(*pfn, module, insn_by_ea, options);
    layer_state_t cfg_state = out.basic_blocks.size() >= options.max_basic_blocks ? layer_state_t::truncated : layer_state_t::ok;
    out.statuses.push_back(make_status("raw_cfg",
                                       cfg_state,
                                       cfg_state == layer_state_t::truncated ? "basic_block_limit_reached" : "",
                                       cfg_start,
                                       out.basic_blocks.size(),
                                       out.basic_blocks.size()));
    stop = stop_state(raw_start, options);
    if (stop != extraction_stop_t::none)
    {
        out.statuses.push_back(stop_status("types", stop, now_ms(), 0, 0));
        out.complete = false;
        finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
        return out;
    }
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
    out.identity.cache_key = build_cache_key(out, options);
    const std::uint64_t cache_start = now_ms();
    if (options.force_refresh)
    {
        out.cache.key = out.identity.cache_key;
        out.cache.lookup_state = "force_refresh";
        out.cache.force_refresh = true;
        out.cache.invalidation_reason = "caller_requested_refresh";
        out.statuses.push_back(cache_layer_status(out.cache, cache_start));
    }
    else
    {
        function_snapshot_t cached;
        extraction_cache_status_t cache_status;
        if (extraction_cache_t::instance().lookup(out.identity.cache_key, cached, cache_status))
        {
            cached.cache = cache_status;
            cached.statuses.push_back(cache_layer_status(cache_status, cache_start));
            cached.diagnostics["cache_returned_after_identity_probe"] = true;
            finalize_function_snapshot(cached, module, pfn->start_ea, "extract_function_snapshot");
            return cached;
        }
        out.cache = cache_status;
        out.statuses.push_back(cache_layer_status(out.cache, cache_start));
    }
    stop = stop_state(raw_start, options);
    if (stop != extraction_stop_t::none)
    {
        out.statuses.push_back(stop_status("ctree", stop, now_ms(), 0, 0));
        out.complete = false;
        finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
        return out;
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
    stop = stop_state(raw_start, options);
    if (stop != extraction_stop_t::none)
    {
        out.statuses.push_back(stop_status("microcode", stop, now_ms(), 0, 0));
        out.complete = false;
        finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
        return out;
    }
    if (options.include_microcode)
    {
        std::set<std::string> seen_mats;
        for (const std::string& mat : options.microcode_maturities)
        {
            if (!seen_mats.insert(mat).second)
                continue;
            stop = stop_state(raw_start, options);
            if (stop != extraction_stop_t::none)
            {
                out.statuses.push_back(stop_status("microcode:" + mat, stop, now_ms(), 0, 0));
                out.complete = false;
                finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
                return out;
            }
            microcode_fact_t mc = extract_microcode_fact(pfn->start_ea, mat, options);
            out.statuses.push_back(mc.status);
            out.microcode.push_back(std::move(mc));
        }
    }
    else
    {
        out.statuses.push_back(make_status("microcode", layer_state_t::skipped, "disabled", now_ms()));
    }
    stop = stop_state(raw_start, options);
    if (stop != extraction_stop_t::none)
    {
        out.statuses.push_back(stop_status("effects", stop, now_ms(), 0, 0));
        out.complete = false;
        finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
        return out;
    }
    if (options.include_effects)
    {
        out.effects = json::array();
        for (const extracted_side_effect_t& effect : classify_side_effects(out))
            out.effects.push_back(to_json(effect));
        out.statuses.push_back(make_status("effects", layer_state_t::ok, "", now_ms(), out.effects.size(), out.effects.size()));
    }
    else
    {
        out.statuses.push_back(make_status("effects", layer_state_t::skipped, "disabled", now_ms()));
    }
    out.complete = true;
    for (const layer_status_t& status : out.statuses)
    {
        if (status.state == layer_state_t::failed)
        {
            out.complete = false;
            break;
        }
    }
    finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
    if (!out.identity.cache_key.empty())
    {
        out.cache = extraction_cache_t::instance().store(out.identity.cache_key, out);
        finalize_function_snapshot(out, module, pfn->start_ea, "extract_function_snapshot");
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

json mapped_item_fact(ea_t ea, const module_identity_t& module)
{
    const flags64_t flags = get_flags(ea);
    const ea_t item_end = get_item_end(ea);
    json item;
    item["address"] = to_json(address_for(ea, module));
    item["end_ea"] = item_end == BADADDR ? std::string() : hex_u64(static_cast<std::uint64_t>(item_end));
    item["size"] = item_end != BADADDR && item_end > ea ? static_cast<std::uint64_t>(item_end - ea) : 1ull;
    item["flags"] = static_cast<std::uint64_t>(flags);
    item["is_head"] = is_head(flags);
    item["is_code"] = is_code(flags);
    item["is_mapped"] = is_mapped(ea);
    item["kind"] = is_code(flags) ? "code" : "data";
    item["name"] = name_at(ea, GN_VISIBLE);
    item["demangled"] = demangled_at(ea);
    func_t* fn = get_func(ea);
    item["function"] = fn != nullptr ? to_json(address_for(fn->start_ea, module)) : json(nullptr);
    item["is_function_start"] = fn != nullptr && fn->start_ea == ea;
    if (is_code(flags))
    {
        insn_t ins;
        if (decode_insn(&ins, ea) > 0)
        {
            item["itype"] = ins.itype;
            item["mnemonic"] = insn_mnemonic(ea);
            item["disassembly"] = disasm_line(ea);
        }
    }
    return item;
}

void append_symbol_index(json& index, ea_t ea, const module_identity_t& module, const json& item)
{
    const std::string name = item.value("name", std::string());
    const std::string demangled = item.value("demangled", std::string());
    if (name.empty() && demangled.empty() && !item.value("is_function_start", false))
        return;
    json sym;
    sym["address"] = to_json(address_for(ea, module));
    sym["name"] = name;
    sym["demangled"] = demangled;
    sym["kind"] = item.value("is_function_start", false) ? "function" : "symbol";
    sym["is_code"] = item.value("is_code", false);
    index.push_back(std::move(sym));
}

layer_status_t scan_module_items(module_snapshot_t& out,
                                 const extraction_options_t& options,
                                 std::uint64_t operation_start)
{
    const std::uint64_t scan_start = now_ms();
    std::size_t total_heads = 0;
    std::set<std::string> from_seen;
    std::set<std::string> to_seen;
    extraction_stop_t stopped = extraction_stop_t::none;
    for (const segment_fact_t& sf : out.segments)
    {
        ea_t cur = static_cast<ea_t>(sf.start_ea);
        const ea_t end = static_cast<ea_t>(sf.end_ea);
        while (cur != BADADDR && cur < end)
        {
            if ((total_heads & 0x3Fu) == 0)
            {
                stopped = stop_state(operation_start, options);
                if (stopped != extraction_stop_t::none)
                    return stop_status("mapped_items", stopped, scan_start, out.mapped_items.size(), total_heads);
            }
            ea_t next = next_head(cur, end);
            if (!is_mapped(cur))
            {
                if (next == BADADDR || next <= cur)
                    break;
                cur = next;
                continue;
            }
            const flags64_t flags = get_flags(cur);
            if (!is_head(flags))
            {
                if (next == BADADDR || next <= cur)
                    break;
                cur = next;
                continue;
            }
            ++total_heads;
            if (out.mapped_items.size() >= options.max_module_items)
            {
                layer_status_t status = make_status("mapped_items", layer_state_t::truncated, "module_item_limit_reached", scan_start, out.mapped_items.size(), total_heads);
                status.cutoff_reason = "module_item_limit_reached";
                return status;
            }
            json item = mapped_item_fact(cur, out.identity);
            std::size_t from_count = 0;
            for (const xref_fact_t& x : collect_xrefs(cur, "from", out.identity, options.max_xrefs_per_address))
            {
                const std::string key = "from:" + std::to_string(x.from.ea) + ":" + std::to_string(x.to.ea) + ":" + std::to_string(x.type);
                if (from_seen.insert(key).second)
                    append_xref_index(out.xref_from_index, x, true);
                ++from_count;
            }
            std::size_t to_count = 0;
            for (const xref_fact_t& x : collect_xrefs(cur, "to", out.identity, options.max_xrefs_per_address))
            {
                const std::string key = "to:" + std::to_string(x.from.ea) + ":" + std::to_string(x.to.ea) + ":" + std::to_string(x.type);
                if (to_seen.insert(key).second)
                    append_xref_index(out.xref_to_index, x, false);
                ++to_count;
            }
            item["xref_from_count"] = from_count;
            item["xref_to_count"] = to_count;
            append_symbol_index(out.symbol_index, cur, out.identity, item);
            out.mapped_items.push_back(std::move(item));
            if (next == BADADDR || next <= cur)
                break;
            cur = next;
        }
    }
    return make_status("mapped_items", layer_state_t::ok, "", scan_start, out.mapped_items.size(), total_heads);
}

module_snapshot_t extract_module_snapshot_ida(const extraction_options_t& options)
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
    const std::uint64_t function_start = now_ms();
    const std::size_t function_qty = get_func_qty();
    const std::size_t function_cap = std::min(function_qty, options.max_batch_functions);
    for (std::size_t i = 0; i < function_cap; ++i)
    {
        func_t* fn = getn_func(i);
        if (fn == nullptr)
            continue;
        json item;
        item["index"] = i;
        item["start"] = to_json(address_for(fn->start_ea, out.identity));
        item["end"] = to_json(address_for(fn->end_ea, out.identity));
        item["size"] = fn->end_ea > fn->start_ea ? static_cast<std::uint64_t>(fn->end_ea - fn->start_ea) : 0;
        item["flags"] = fn->flags;
        item["does_return"] = fn->does_return();
        item["is_thunk"] = (fn->flags & FUNC_THUNK) != 0;
        item["name"] = func_name_at(fn->start_ea);
        out.function_index.push_back(std::move(item));
    }
    const bool functions_truncated = function_cap < function_qty;
    out.statuses.push_back(make_status("function_index",
                                       functions_truncated ? layer_state_t::truncated : layer_state_t::ok,
                                       functions_truncated ? "function_batch_limit_reached" : "",
                                       function_start,
                                       out.function_index.size(),
                                       function_qty));
    if (options.include_xref_indexes)
        out.statuses.push_back(scan_module_items(out, options, start));
    else
        out.statuses.push_back(make_status("mapped_items", layer_state_t::skipped, "xref_indexes_disabled", now_ms()));
    out.statuses.push_back(make_status("segments", layer_state_t::ok, "", start, out.segments.size(), static_cast<std::size_t>(seg_count)));
    out.cache = cache_status_from_json(extraction_cache_t::instance().status());
    annotate_statuses(out.statuses, out.identity, BADADDR, "extract_module_snapshot", &out.cache);
    out.resolver_index = build_cross_binary_resolver_index(json::array({to_json(out)}));
    return out;
}

template <typename Snapshot>
Snapshot failed_snapshot(const std::string& layer, const std::string& reason)
{
    Snapshot out;
    out.statuses.push_back(make_status(layer, layer_state_t::failed, reason, now_ms()));
    return out;
}

function_batch_result_t extract_function_batch_ida(const std::vector<ea_t>& functions, const extraction_options_t& options)
{
    function_batch_result_t out;
    const std::uint64_t start = now_ms();
    out.module = current_module_identity();
    std::vector<ea_t> work = functions;
    if (work.empty())
    {
        const std::size_t qty = get_func_qty();
        const std::size_t cap = std::min(qty, options.max_batch_functions);
        work.reserve(cap);
        for (std::size_t i = 0; i < cap; ++i)
        {
            func_t* fn = getn_func(i);
            if (fn != nullptr)
                work.push_back(fn->start_ea);
        }
        if (cap < qty)
        {
            layer_status_t status = make_status("batch_enumeration", layer_state_t::truncated, "function_batch_limit_reached", start, work.size(), qty);
            status.cutoff_reason = "function_batch_limit_reached";
            out.statuses.push_back(status);
        }
    }
    std::set<ea_t> seen;
    for (ea_t ea : work)
    {
        if (out.functions.size() >= options.max_batch_functions)
        {
            out.reason = "function_batch_limit_reached";
            break;
        }
        if (options.timeout_ms != 0 && now_ms() - start >= options.timeout_ms)
        {
            out.timeout = true;
            out.reason = "timeout";
            break;
        }
        if (options.cancellation_requested && options.cancellation_requested())
        {
            out.cancelled = true;
            out.reason = "cancelled";
            break;
        }
        if (options.allow_interactive_cancel && user_cancelled())
        {
            out.cancelled = true;
            out.reason = "cancelled";
            break;
        }
        func_t* fn = get_func(ea);
        const ea_t start_ea = fn != nullptr ? fn->start_ea : ea;
        if (!seen.insert(start_ea).second)
            continue;
        out.functions.push_back(extract_function_snapshot_ida(start_ea, options));
    }
    out.complete = !out.cancelled && !out.timeout && out.reason.empty();
    layer_status_t status = make_status("function_batch",
                                        out.complete ? layer_state_t::ok : (out.timeout ? layer_state_t::timeout : layer_state_t::truncated),
                                        out.reason,
                                        start,
                                        out.functions.size(),
                                        work.size());
    status.timeout = out.timeout;
    status.cancelled = out.cancelled;
    status.cutoff_reason = out.complete ? std::string() : out.reason;
    out.statuses.push_back(status);
    return out;
}

}

nlohmann::json build_cross_binary_resolver_index(const nlohmann::json& module_facts)
{
    json modules = module_facts;
    if (modules.is_object() && modules.contains("modules") && modules["modules"].is_array())
        modules = modules["modules"];
    if (modules.is_object())
        modules = json::array({modules});
    json out;
    out["schema"] = "aida_chain_cross_binary_resolver_v1";
    out["module_count"] = modules.is_array() ? modules.size() : 0;
    out["modules"] = json::array();
    out["exports"] = json::array();
    out["imports"] = json::array();
    out["symbols"] = json::array();
    auto normalized = [](std::string s) {
        s = lower_ascii(s);
        while (!s.empty() && (s.front() == '_' || s.front() == '@'))
            s.erase(s.begin());
        if (s.rfind("__imp_", 0) == 0)
            s.erase(0, 6);
        if (s.rfind("imp_", 0) == 0)
            s.erase(0, 4);
        if (s.rfind("j_", 0) == 0)
            s.erase(0, 2);
        const std::size_t at = s.find('@');
        if (at != std::string::npos)
            s.erase(at);
        return s;
    };
    if (!modules.is_array())
        return out;
    for (const json& module : modules)
    {
        const json identity = module.value("identity", module.value("module", json::object()));
        const std::string module_id = identity.value("module_id", identity.value("corpus_id", std::string()));
        const std::string module_name = identity.value("module_name", identity.value("canonical_name", std::string()));
        json mod;
        mod["module_id"] = module_id;
        mod["module_name"] = module_name;
        mod["normalized_module_name"] = normalized(module_name);
        mod["input_sha256"] = identity.value("input_sha256", std::string());
        mod["image_base"] = identity.value("image_base", std::string());
        out["modules"].push_back(std::move(mod));
        const auto append_addr = [&](const json& addr, const std::string& kind, json& target) {
            json item;
            item["module_id"] = module_id;
            item["module_name"] = module_name;
            item["kind"] = kind;
            item["address"] = addr;
            std::string name;
            if (addr.is_object())
            {
                name = addr.value("symbol", addr.value("name", std::string()));
                if (name.empty())
                    name = addr.value("demangled", std::string());
            }
            item["name"] = name;
            item["normalized_name"] = normalized(name);
            if (!name.empty() || kind == "function")
                target.push_back(std::move(item));
        };
        if (module.contains("entries") && module["entries"].is_array())
        {
            for (const json& entry : module["entries"])
                append_addr(entry, "export", out["exports"]);
        }
        if (module.contains("imports") && module["imports"].is_array())
        {
            for (const json& imp : module["imports"])
                append_addr(imp, "import", out["imports"]);
        }
        if (module.contains("function_index") && module["function_index"].is_array())
        {
            for (const json& fn : module["function_index"])
            {
                json item;
                item["module_id"] = module_id;
                item["module_name"] = module_name;
                item["kind"] = "function";
                item["name"] = fn.value("name", std::string());
                item["normalized_name"] = normalized(item["name"].get<std::string>());
                item["address"] = fn.value("start", json::object());
                out["symbols"].push_back(std::move(item));
            }
        }
        if (module.contains("symbol_index") && module["symbol_index"].is_array())
        {
            for (const json& sym : module["symbol_index"])
            {
                json item;
                item["module_id"] = module_id;
                item["module_name"] = module_name;
                item["kind"] = sym.value("kind", std::string("symbol"));
                item["name"] = sym.value("name", std::string());
                if (item["name"].get<std::string>().empty())
                    item["name"] = sym.value("demangled", std::string());
                item["normalized_name"] = normalized(item["name"].get<std::string>());
                item["address"] = sym.value("address", json::object());
                if (!item["normalized_name"].get<std::string>().empty())
                    out["symbols"].push_back(std::move(item));
            }
        }
    }
    return out;
}

nlohmann::json resolve_cross_binary_reference(const nlohmann::json& module_facts, const nlohmann::json& reference)
{
    json index = build_cross_binary_resolver_index(module_facts);
    json out;
    out["schema"] = "aida_chain_cross_binary_resolution_v1";
    out["reference"] = reference;
    out["resolved"] = false;
    out["quality"] = "unresolved";
    out["target"] = nullptr;
    out["candidates"] = json::array();
    out["diagnostics"] = {{"module_count", index.value("module_count", 0)}, {"reason", "no_supported_match"}};
    auto normalized = [](std::string s) {
        s = lower_ascii(s);
        while (!s.empty() && (s.front() == '_' || s.front() == '@'))
            s.erase(s.begin());
        if (s.rfind("__imp_", 0) == 0)
            s.erase(0, 6);
        if (s.rfind("imp_", 0) == 0)
            s.erase(0, 4);
        if (s.rfind("j_", 0) == 0)
            s.erase(0, 2);
        const std::size_t at = s.find('@');
        if (at != std::string::npos)
            s.erase(at);
        return s;
    };
    if (reference.is_object() && reference.value("controlled", false))
    {
        out["resolved"] = true;
        out["quality"] = "controlled";
        out["target"] = reference;
        out["diagnostics"]["reason"] = "chain_state_supplies_target";
        return out;
    }
    const json ref_addr = reference.is_object() ? reference.value("address", reference) : json::object();
    std::string ref_module = ref_addr.is_object() ? ref_addr.value("module_id", ref_addr.value("corpus_id", std::string())) : std::string();
    if (ref_module.empty() && ref_addr.is_object() && ref_addr.contains("module") && ref_addr["module"].is_object())
        ref_module = ref_addr["module"].value("module_id", ref_addr["module"].value("corpus_id", std::string()));
    const bool has_ref_rva = ref_addr.is_object() && ref_addr.contains("rva") && !ref_addr["rva"].is_null()
        && (!ref_addr["rva"].is_string() || !ref_addr["rva"].get<std::string>().empty());
    const std::uint64_t ref_rva = has_ref_rva ? parse_u64(ref_addr["rva"]) : 0;
    if (!ref_module.empty() && has_ref_rva && index["modules"].is_array())
    {
        for (const json& module : index["modules"])
        {
            if (module.value("module_id", std::string()) != ref_module)
                continue;
            json target;
            target["module"] = module;
            target["module_id"] = ref_module;
            target["rva"] = hex_u64(ref_rva);
            std::uint64_t image_base = 0;
            if (module.contains("image_base"))
                image_base = parse_u64(module["image_base"]);
            if (image_base != 0)
                target["ea"] = hex_u64(image_base + ref_rva);
            out["resolved"] = true;
            out["quality"] = "exact";
            out["target"] = target;
            out["diagnostics"]["reason"] = "module_id_and_rva_match";
            return out;
        }
    }
    std::string symbol;
    if (reference.is_object())
        symbol = reference.value("symbol", reference.value("name", reference.value("callee_name", std::string())));
    if (symbol.empty() && ref_addr.is_object())
        symbol = ref_addr.value("symbol", ref_addr.value("demangled", std::string()));
    const std::string wanted = normalized(symbol);
    std::string import_module;
    if (reference.is_object())
        import_module = normalized(reference.value("import_module", reference.value("target_module", std::string())));
    if (!wanted.empty())
    {
        auto collect = [&](const json& list, const std::string& required_kind) {
            if (!list.is_array())
                return;
            for (const json& item : list)
            {
                if (item.value("normalized_name", std::string()) != wanted)
                    continue;
                if (!required_kind.empty() && item.value("kind", std::string()) != required_kind)
                    continue;
                if (!import_module.empty() && item.value("module_name", std::string()).empty())
                    continue;
                out["candidates"].push_back(item);
            }
        };
        collect(index["exports"], "export");
        collect(index["symbols"], "");
        if (!out["candidates"].empty())
        {
            json best = out["candidates"].front();
            bool symbolic_exact = false;
            if (!import_module.empty())
            {
                for (const json& candidate : out["candidates"])
                {
                    if (normalized(candidate.value("module_name", std::string())) == import_module)
                    {
                        best = candidate;
                        symbolic_exact = true;
                        break;
                    }
                }
            }
            out["resolved"] = true;
            out["quality"] = symbolic_exact || out["candidates"].size() == 1 ? "symbolic_exact" : "name_weak";
            out["target"] = best.value("address", best);
            out["diagnostics"]["reason"] = out["quality"] == "symbolic_exact" ? "symbol_match" : "ambiguous_name_match";
            return out;
        }
    }
    out["diagnostics"]["wanted_symbol"] = symbol;
    out["diagnostics"]["wanted_module"] = import_module;
    return out;
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

function_batch_result_t extract_function_batch(const std::vector<ea_t>& functions, const extraction_options_t& options)
{
    struct request_t : public exec_request_t
    {
        std::vector<ea_t> functions;
        extraction_options_t options;
        function_batch_result_t result;
        bool ok = false;
        request_t(const std::vector<ea_t>& f, const extraction_options_t& o) : functions(f), options(o) {}
        ssize_t idaapi execute() override
        {
            try
            {
                result = extract_function_batch_ida(functions, options);
                ok = true;
            }
            catch (...)
            {
                result = failed_snapshot<function_batch_result_t>("function_batch", "exception");
            }
            return 1;
        }
    };
    request_t req(functions, options);
    if (execute_sync(req, MFF_READ) <= 0)
        return failed_snapshot<function_batch_result_t>("function_batch", "execute_sync_failed");
    if (!req.ok)
        return req.result;
    return req.result;
}

nlohmann::json extraction_cache_status()
{
    return extraction_cache_t::instance().status();
}

void clear_extraction_cache()
{
    struct request_t : public exec_request_t
    {
        ssize_t idaapi execute() override
        {
            extraction_cache_t::instance().clear();
            return 1;
        }
    };
    request_t req;
    execute_sync(req, MFF_WRITE);
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
                {"exception_class", status.exception_class},
                {"fallback_layers", status.fallback_layers},
                {"cutoff_reason", status.cutoff_reason},
                {"elapsed_ms", status.elapsed_ms},
                {"emitted", status.emitted},
                {"total", status.total},
                {"cache_hit", status.cache_hit},
                {"timeout", status.timeout},
                {"cancelled", status.cancelled},
                {"diagnostics", status.diagnostics}};
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
                {"value_ref", operand.value_ref},
                {"address_expr", operand.address_expr},
                {"alias_class", operand.alias_class},
                {"type_ref", operand.type_ref},
                {"offb", operand.offb},
                {"offo", operand.offo},
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
                {"item_flags", instruction.item_flags},
                {"size", instruction.size},
                {"mnemonic", instruction.mnemonic},
                {"disassembly", instruction.disassembly},
                {"bytes", instruction.bytes_hex},
                {"operands", std::move(operands)},
                {"raw_effects", instruction.raw_effects},
                {"register_uses", instruction.register_uses},
                {"register_defs", instruction.register_defs},
                {"xrefs_from", std::move(xfrom)},
                {"xrefs_to", std::move(xto)},
                {"branch_targets", std::move(targets)},
                {"stack_delta", instruction.stack_delta},
                {"fallthrough_ea", hex_u64(instruction.fallthrough_ea)},
                {"has_fallthrough", instruction.has_fallthrough},
                {"is_call", instruction.is_call},
                {"is_return", instruction.is_return},
                {"is_branch", instruction.is_branch},
                {"is_indirect", instruction.is_indirect},
                {"is_conditional", instruction.is_conditional},
                {"is_noreturn", instruction.is_noreturn},
                {"block_end", instruction.block_end},
                {"unknown_effect", instruction.unknown_effect}};
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
                {"edges", block.edges},
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
                {"resolution_quality", call.resolution_quality},
                {"target_preconditions", call.target_preconditions},
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
                {"true_target_ea", branch.true_target_ea == 0 ? std::string() : hex_u64(branch.true_target_ea)},
                {"false_target_ea", branch.false_target_ea == 0 ? std::string() : hex_u64(branch.false_target_ea)},
                {"ctree_parent_ids", branch.ctree_parent_ids},
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
                {"spoiled_registers", type.spoiled_registers},
                {"argument_details", type.argument_details},
                {"local_variables", type.local_variables},
                {"stack_variables", type.stack_variables},
                {"referenced_udts", type.referenced_udts},
                {"referenced_enums", type.referenced_enums},
                {"udt_layouts", type.udt_layouts},
                {"member_offsets", type.member_offsets},
                {"dependencies", type.dependencies}};
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
                {"value_kind", node.value_kind},
                {"callee_text", node.callee_text},
                {"argument_texts", node.argument_texts},
                {"lvar_refs", node.lvar_refs},
                {"member_refs", node.member_refs},
                {"object_refs", node.object_refs},
                {"constants", node.constants},
                {"true_child_id", node.true_child_id == static_cast<std::size_t>(-1) ? json(nullptr) : json(node.true_child_id)},
                {"false_child_id", node.false_child_id == static_cast<std::size_t>(-1) ? json(nullptr) : json(node.false_child_id)},
                {"parent_ids", node.parent_ids},
                {"parent_eas", std::move(parent_eas)},
                {"is_call", node.is_call},
                {"is_assignment", node.is_assignment},
                {"is_branch", node.is_branch},
                {"is_return", node.is_return},
                {"is_switch", node.is_switch},
                {"is_loop", node.is_loop},
                {"is_memory_ref", node.is_memory_ref}};
}

nlohmann::json to_json(const ctree_fact_t& ctree)
{
    json nodes = json::array();
    for (const auto& node : ctree.nodes)
        nodes.push_back(to_json(node));
    return json{{"status", to_json(ctree.status)},
                {"pseudocode_lines", ctree.pseudocode_lines},
                {"locals", ctree.locals},
                {"nodes", std::move(nodes)},
                {"branch_facts", ctree.branch_facts},
                {"call_facts", ctree.call_facts},
                {"assignment_facts", ctree.assignment_facts},
                {"memory_facts", ctree.memory_facts}};
}

nlohmann::json to_json(const microcode_fact_t& microcode)
{
    return json{{"status", to_json(microcode.status)},
                {"maturity", microcode.maturity},
                {"blocks", microcode.blocks},
                {"calls", microcode.calls},
                {"use_def", microcode.use_def},
                {"effects", microcode.effects}};
}

nlohmann::json to_json(const extraction_cache_status_t& cache)
{
    return json{{"schema", cache.schema},
                {"key", cache.key},
                {"lookup_state", cache.lookup_state},
                {"invalidation_reason", cache.invalidation_reason},
                {"hit", cache.hit},
                {"persistent", cache.persistent},
                {"force_refresh", cache.force_refresh},
                {"memory_entries", cache.memory_entries},
                {"memory_bytes", cache.memory_bytes},
                {"persistent_bytes", cache.persistent_bytes},
                {"hits", cache.hits},
                {"misses", cache.misses},
                {"persistent_hits", cache.persistent_hits},
                {"stores", cache.stores}};
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
                {"cache", to_json(snapshot.cache)},
                {"complete", snapshot.complete},
                {"statuses", std::move(statuses)},
                {"instructions", std::move(insns)},
                {"basic_blocks", std::move(blocks)},
                {"xrefs_from", std::move(xfrom)},
                {"xrefs_to", std::move(xto)},
                {"xref_from_index", snapshot.xref_from_index},
                {"xref_to_index", snapshot.xref_to_index},
                {"calls", std::move(calls)},
                {"branches", std::move(branches)},
                {"effects", snapshot.effects},
                {"type", to_json(snapshot.type)},
                {"ctree", to_json(snapshot.ctree)},
                {"microcode", std::move(micro)},
                {"diagnostics", snapshot.diagnostics}};
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
                {"imports", std::move(imports)},
                {"function_index", snapshot.function_index},
                {"mapped_items", snapshot.mapped_items},
                {"symbol_index", snapshot.symbol_index},
                {"xref_from_index", snapshot.xref_from_index},
                {"xref_to_index", snapshot.xref_to_index},
                {"resolver_index", snapshot.resolver_index},
                {"cache", to_json(snapshot.cache)}};
}

nlohmann::json to_json(const function_batch_result_t& batch)
{
    json statuses = json::array();
    for (const layer_status_t& status : batch.statuses)
        statuses.push_back(to_json(status));
    json functions = json::array();
    for (const function_snapshot_t& fn : batch.functions)
        functions.push_back(to_json(fn));
    return json{{"schema", k_chain_extraction_schema},
                {"module", to_json(batch.module)},
                {"functions", std::move(functions)},
                {"statuses", std::move(statuses)},
                {"complete", batch.complete},
                {"cancelled", batch.cancelled},
                {"timeout", batch.timeout},
                {"reason", batch.reason}};
}

}
}
}
