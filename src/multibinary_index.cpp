#include "multibinary_index.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <allins.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "vuln/microcode_engine.hpp"
#include "vuln/verification_engine.hpp"

namespace aida
{
namespace multibinary
{
namespace
{

using json = nlohmann::json;

std::string path_join(const std::string& left, const std::string& right)
{
    if (left.empty())
        return right;
    if (right.empty())
        return left;
    const char last = left.back();
    if (last == '/' || last == '\\')
        return left + right;
#ifdef _WIN32
    return left + "\\" + right;
#else
    return left + "/" + right;
#endif
}

std::string lowercase_ascii(std::string value)
{
    for (char& c : value)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    }
    return value;
}

std::uint64_t parse_u64_loose(const json& value)
{
    if (value.is_number_unsigned())
        return value.get<std::uint64_t>();
    if (value.is_number_integer())
        return static_cast<std::uint64_t>(value.get<std::int64_t>());
    if (!value.is_string())
        return 0;
    char* endp = nullptr;
#ifdef _WIN32
    unsigned long long parsed = _strtoui64(value.get_ref<const std::string&>().c_str(), &endp, 0);
#else
    unsigned long long parsed = std::strtoull(value.get_ref<const std::string&>().c_str(), &endp, 0);
#endif
    if (endp == value.get_ref<const std::string&>().c_str())
        return 0;
    return static_cast<std::uint64_t>(parsed);
}

std::string hex_u64(std::uint64_t value)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::nouppercase << value;
    return ss.str();
}

std::string bytes_hex(const std::vector<uchar>& bytes)
{
    static const char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uchar b : bytes)
    {
        out.push_back(h[(b >> 4) & 0xf]);
        out.push_back(h[b & 0xf]);
    }
    return out;
}

json module_identity(const json& module)
{
    if (module.contains("identity") && module["identity"].is_object())
        return module["identity"];
    return module;
}

std::string canonical_name_of(const json& module)
{
    json identity = module_identity(module);
    std::string name = identity.value("canonical_name", module.value("canonical_name", std::string()));
    if (name.empty())
        name = module.value("input_basename", identity.value("input_basename", std::string()));
    return lowercase_ascii(name);
}

std::string function_catalog_path(const std::string& project_id, const std::string& module_id)
{
    return path_join(path_join(project_root(project_id), "functions"), sanitize_id_component(module_id) + ".msgpack");
}

std::string cross_edges_path(const std::string& project_id)
{
    return path_join(path_join(project_root(project_id), "edges"), "cross_edges.msgpack");
}

std::string family_dir_name(const std::string& family)
{
    const std::string f = sanitize_id_component(lowercase_ascii(family));
    if (f.empty())
        return "summaries";
    return f;
}

std::string page_family_dir(const std::string& project_id, const std::string& family)
{
    return path_join(project_root(project_id), family_dir_name(family));
}

std::string page_manifest_path(const std::string& project_id, const std::string& module_id, const std::string& family)
{
    return path_join(page_family_dir(project_id, family), sanitize_id_component(module_id) + ".manifest.msgpack");
}

std::string page_file_path(const std::string& project_id, const std::string& module_id, const std::string& family, std::size_t page_index)
{
    return path_join(page_family_dir(project_id, family),
                     sanitize_id_component(module_id) + "." + std::to_string(page_index) + ".msgpack");
}

std::string page_cursor(const std::string& family, const std::string& module_id, std::size_t page_index)
{
    return "aida_idx|" + family_dir_name(family) + "|" + sanitize_id_component(module_id) + "|" + std::to_string(page_index);
}

bool parse_page_cursor(const std::string& cursor, std::string& family, std::string& module_id, std::size_t& page_index)
{
    if (cursor.empty())
        return false;
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= cursor.size())
    {
        const std::size_t pos = cursor.find('|', start);
        if (pos == std::string::npos)
        {
            parts.push_back(cursor.substr(start));
            break;
        }
        parts.push_back(cursor.substr(start, pos - start));
        start = pos + 1;
    }
    if (parts.size() != 4 || parts[0] != "aida_idx")
        return false;
    char* endp = nullptr;
    unsigned long parsed = std::strtoul(parts[3].c_str(), &endp, 10);
    if (endp == parts[3].c_str() || *endp != '\0')
        return false;
    family = parts[1];
    module_id = parts[2];
    page_index = static_cast<std::size_t>(parsed);
    return true;
}

bool write_binary_file(const std::string& path, const std::vector<std::uint8_t>& bytes, std::string* error)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        if (error != nullptr)
            *error = "open_failed";
        return false;
    }
    if (!bytes.empty())
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out.good())
    {
        if (error != nullptr)
            *error = "write_failed";
        return false;
    }
    return true;
}

bool read_binary_file(const std::string& path, std::vector<std::uint8_t>& bytes, std::string* error)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
    {
        if (error != nullptr)
            *error = "open_failed";
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0)
    {
        if (error != nullptr)
            *error = "size_failed";
        return false;
    }
    in.seekg(0, std::ios::beg);
    bytes.resize(static_cast<std::size_t>(size));
    if (!bytes.empty())
        in.read(reinterpret_cast<char*>(bytes.data()), size);
    if (!in.good() && !in.eof())
    {
        if (error != nullptr)
            *error = "read_failed";
        return false;
    }
    return true;
}

project_io_result_t make_error(const std::string& code, const std::string& message, const json& data = json::object())
{
    project_io_result_t r;
    r.ok = false;
    r.error_code = code;
    r.error_message = message;
    r.data = data;
    return r;
}

project_io_result_t make_ok(const json& data)
{
    project_io_result_t r;
    r.ok = true;
    r.data = data;
    return r;
}

void save_netnode_blob(const char* name, uchar tag, const json& value)
{
    netnode node(name, 0, true);
    if (node == BADNODE)
        return;
    std::vector<std::uint8_t> blob = json::to_msgpack(value);
    if (!blob.empty())
        node.setblob(blob.data(), blob.size(), 1, tag);
}

json normalize_imports(const json& module)
{
    if (module.contains("imports") && module["imports"].is_array())
        return module["imports"];
    if (module.contains("imports_preview") && module["imports_preview"].is_array())
        return module["imports_preview"];
    return json::array();
}

json normalize_exports(const json& module)
{
    if (module.contains("exports") && module["exports"].is_array())
        return module["exports"];
    if (module.contains("entry_points") && module["entry_points"].is_array())
        return module["entry_points"];
    return json::array();
}

std::string import_symbol_name(const json& imp)
{
    return lowercase_ascii(imp.value("name", imp.value("symbol", std::string())));
}

std::string import_module_name(const json& imp)
{
    return lowercase_ascii(imp.value("module", imp.value("module_name", std::string())));
}

bool is_api_set_contract_name(const std::string& name)
{
    return name.rfind("api-ms-", 0) == 0 || name.rfind("ext-ms-", 0) == 0;
}

bool is_syscall_symbol(const std::string& name)
{
    return name.size() > 2
        && ((name[0] == 'n' && name[1] == 't') || (name[0] == 'z' && name[1] == 'w'));
}

bool is_guard_dispatch_symbol(const std::string& name)
{
    return name.find("guard_dispatch") != std::string::npos
        || name.find("guard_xfg_dispatch") != std::string::npos
        || name.find("__guard_dispatch_icall") != std::string::npos
        || name.find("__guard_xfg_dispatch_icall") != std::string::npos;
}

std::string normalized_export_symbol(std::string value)
{
    value = lowercase_ascii(std::move(value));
    while (!value.empty() && (value.front() == '_' || value.front() == '@'))
        value.erase(value.begin());
    if (value.rfind("__imp_", 0) == 0)
        value.erase(0, 6);
    if (value.rfind("imp_", 0) == 0)
        value.erase(0, 4);
    if (value.rfind("j_", 0) == 0)
        value.erase(0, 2);
    const std::size_t at = value.find('@');
    if (at != std::string::npos)
        value.erase(at);
    return value;
}

std::string export_name(const json& item)
{
    return lowercase_ascii(item.value("name", item.value("symbol", std::string())));
}

std::uint64_t export_ordinal(const json& item)
{
    if (item.contains("ordinal"))
        return parse_u64_loose(item["ordinal"]);
    return 0;
}

std::uint64_t export_rva(const json& item, const json& target_module)
{
    if (item.contains("address") && item["address"].is_object() && item["address"].contains("rva"))
        return parse_u64_loose(item["address"]["rva"]);
    if (item.contains("rva"))
        return parse_u64_loose(item["rva"]);
    if (item.contains("ea") && !item["ea"].is_null())
    {
        const std::uint64_t ea = parse_u64_loose(item["ea"]);
        const std::uint64_t base = parse_u64_loose(module_identity(target_module).value("image_base", json(0)));
        if (base != 0 && ea >= base)
            return ea - base;
    }
    return 0;
}

json make_target_address(const json& target_module, const json& export_item)
{
    const std::string module_id = canonical_module_id_from_json(target_module);
    const std::uint64_t rva = export_rva(export_item, target_module);
    std::uint64_t ea_hint = 0;
    if (export_item.contains("ea") && !export_item["ea"].is_null())
        ea_hint = parse_u64_loose(export_item["ea"]);
    return canonical_address_json(module_id, rva, ea_hint, std::string(), 0, 0, rva == 0 ? "weak_name" : "exact");
}

std::string ida_name(ea_t ea)
{
    if (ea == BADADDR)
        return std::string();
    qstring q;
    if (get_name(&q, ea, GN_VISIBLE | GN_DEMANGLED | GN_SHORT) > 0 && !q.empty())
        return std::string(q.c_str());
    if (get_ea_name(&q, ea) > 0 && !q.empty())
        return std::string(q.c_str());
    return std::string();
}

std::string function_name(ea_t ea)
{
    if (ea == BADADDR)
        return std::string();
    qstring q;
    if (get_func_name(&q, ea) > 0 && !q.empty())
        return std::string(q.c_str());
    return ida_name(ea);
}

std::string operand_text(ea_t ea, int n)
{
    qstring q;
    if (!print_operand(&q, ea, n))
        return std::string();
    tag_remove(&q);
    return std::string(q.c_str());
}

std::string instruction_text(ea_t ea)
{
    qstring q;
    if (!generate_disasm_line(&q, ea, GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS))
        return std::string();
    tag_remove(&q);
    return std::string(q.c_str());
}

std::string register_name(int reg)
{
    if (reg < 0)
        return std::string();
    qstring q;
    if (get_reg_name(&q, reg, 0) > 0 && !q.empty())
        return std::string(q.c_str());
    if (get_reg_name(&q, reg, inf_is_64bit() ? 8 : 4) > 0 && !q.empty())
        return std::string(q.c_str());
    if (PH.reg_names != nullptr && reg < PH.regs_num && PH.reg_names[reg] != nullptr)
        return std::string(PH.reg_names[reg]);
    return std::to_string(reg);
}

int find_register_by_name(const std::initializer_list<const char*>& names)
{
    std::set<std::string> wanted;
    for (const char* name : names)
        wanted.insert(lowercase_ascii(name != nullptr ? std::string(name) : std::string()));
    for (int i = 0; i < PH.regs_num; ++i)
    {
        const std::string reg = lowercase_ascii(register_name(i));
        if (wanted.find(reg) != wanted.end())
            return i;
    }
    return -1;
}

bool ea_in_segment_type(ea_t ea, uchar type)
{
    segment_t* seg = getseg(ea);
    return seg != nullptr && seg->type == type;
}

bool ea_in_code(ea_t ea)
{
    return ea != BADADDR && ea_in_segment_type(ea, SEG_CODE);
}

bool ea_in_data(ea_t ea)
{
    if (ea == BADADDR)
        return false;
    segment_t* seg = getseg(ea);
    return seg != nullptr && seg->type != SEG_CODE;
}

ea_t function_entry(ea_t ea)
{
    if (!ea_in_code(ea))
        return BADADDR;
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return BADADDR;
    return fn->start_ea;
}

bool read_pointer_value(ea_t ea, ea_t& out)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    out = inf_is_64bit() ? static_cast<ea_t>(get_qword(ea)) : static_cast<ea_t>(get_dword(ea));
    return out != BADADDR && out != 0;
}

json address_for_ea(const vuln::chain::corpus_record_t& corpus, ea_t ea, const std::string& confidence = "exact")
{
    auto norm = vuln::chain::normalize_ea(corpus, static_cast<std::uint64_t>(ea));
    if (norm.ok)
        return canonical_address_from_chain(norm.address);
    return json::object({{"ea_hint", hex_u64(static_cast<std::uint64_t>(ea))}, {"confidence", confidence}});
}

json function_target_json(const vuln::chain::corpus_record_t& corpus, ea_t target, const std::string& source)
{
    const ea_t entry = function_entry(target);
    if (entry == BADADDR)
        return json::object();
    json out;
    out["module_id"] = corpus.identity.corpus_id;
    out["address"] = address_for_ea(corpus, entry);
    out["ea_hint"] = hex_u64(static_cast<std::uint64_t>(entry));
    out["name"] = function_name(entry);
    out["source"] = source;
    return out;
}

struct resolved_target_t
{
    bool ok = false;
    ea_t target = BADADDR;
    std::string source;
    json trace = json::array();
};

resolved_target_t resolve_operand_function_target(const vuln::chain::corpus_record_t& corpus, const insn_t& ins, const op_t& op)
{
    resolved_target_t out;
    auto accept = [&](ea_t ea, const std::string& source) {
        const ea_t entry = function_entry(ea);
        if (entry == BADADDR)
            return false;
        out.ok = true;
        out.target = entry;
        out.source = source;
        out.trace.push_back({{"ea", hex_u64(static_cast<std::uint64_t>(ins.ea))}, {"instruction", instruction_text(ins.ea)}, {"operand", operand_text(ins.ea, op.n)}, {"source", source}, {"target", function_target_json(corpus, entry, source)}});
        return true;
    };
    if (op.type == o_near || op.type == o_far)
        accept(static_cast<ea_t>(op.addr), "direct_code_operand");
    else if (op.type == o_imm)
        accept(static_cast<ea_t>(op.value), "immediate_code_address");
    else if (op.type == o_mem)
    {
        if (!accept(static_cast<ea_t>(op.addr), "memory_operand_code_address"))
        {
            ea_t ptr = BADADDR;
            if (read_pointer_value(static_cast<ea_t>(op.addr), ptr))
                accept(ptr, "global_pointer_value");
        }
    }
    else if (op.type == o_displ)
    {
        if (is_loaded(static_cast<ea_t>(op.addr)))
        {
            if (!accept(static_cast<ea_t>(op.addr), "displacement_code_address"))
            {
                ea_t ptr = BADADDR;
                if (read_pointer_value(static_cast<ea_t>(op.addr), ptr))
                    accept(ptr, "displacement_pointer_value");
            }
        }
    }
    return out;
}

bool operand_writes_register(const op_t& op, int reg)
{
    return reg >= 0 && op.type == o_reg && op.reg == reg;
}

resolved_target_t trace_register_function_value(const vuln::chain::corpus_record_t& corpus, func_t* fn, ea_t before, int reg, std::size_t max_steps)
{
    resolved_target_t out;
    if (fn == nullptr || reg < 0 || before == BADADDR)
        return out;
    ea_t scan = prev_head(before, fn->start_ea);
    std::size_t steps = 0;
    while (scan != BADADDR && scan >= fn->start_ea && steps < max_steps)
    {
        insn_t prev;
        if (decode_insn(&prev, scan) <= 0)
            break;
        if (operand_writes_register(prev.ops[0], reg))
        {
            if (prev.itype == NN_mov || prev.itype == NN_lea)
            {
                out = resolve_operand_function_target(corpus, prev, prev.ops[1]);
                if (out.ok)
                {
                    out.source = std::string("register_trace:") + register_name(reg);
                    out.trace.push_back({{"ea", hex_u64(static_cast<std::uint64_t>(before))}, {"instruction", instruction_text(before)}, {"register", register_name(reg)}, {"distance", steps + 1}});
                }
                return out;
            }
            if (prev.itype == NN_xor || prev.itype == NN_sub)
                return out;
        }
        scan = prev_head(scan, fn->start_ea);
        ++steps;
    }
    return out;
}

resolved_target_t resolve_call_or_store_operand(const vuln::chain::corpus_record_t& corpus, func_t* fn, const insn_t& ins, const op_t& op)
{
    resolved_target_t direct = resolve_operand_function_target(corpus, ins, op);
    if (direct.ok)
        return direct;
    if (op.type == o_reg)
        return trace_register_function_value(corpus, fn, ins.ea, op.reg, 96);
    return direct;
}

ea_t first_xref_target(ea_t ea)
{
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_FAR); ok; ok = xb.next_from())
        if (xb.to != BADADDR)
            return xb.to;
    return BADADDR;
}

bool is_call_like(const insn_t& ins)
{
    return ins.itype == NN_call || ins.itype == NN_callfi || ins.itype == NN_callni;
}

bool is_indirect_call_like(const insn_t& ins)
{
    return ins.itype == NN_callfi || ins.itype == NN_callni || ins.itype == NN_jmpfi || ins.itype == NN_jmpni;
}

bool is_callback_registration_api(const std::string& name)
{
    const std::string n = normalized_export_symbol(name);
    static const std::set<std::string> apis = {
        "pssetcreateprocessnotifyroutine", "pssetcreateprocessnotifyroutineex", "pssetcreateprocessnotifyroutineex2",
        "pssetloadimagenotifyroutine", "pssetloadimagenotifyroutineex", "pssetcreatethreadnotifyroutine",
        "cmregistercallback", "cmregistercallbackex", "obregistercallbacks", "exregistercallback",
        "ioregistershutdownnotification", "ioregisterlastchanceshutdownnotification",
        "ioregisterplugplaynotification", "ioregisterfsregistrationchange", "ioregisterfsregistrationchangeex",
        "kesetimer", "kesetimerex", "keinitializedpc", "keinsertqueuedpc",
        "fltregisterfilter", "wdfdrivercreate", "wdfdevicecreate",
        "wdfioqueuecreate", "wskregister", "wskcaptureprovidernpi", "etwregister", "eventregister"
    };
    if (apis.find(n) != apis.end())
        return true;
    return n.find("register") != std::string::npos && (n.find("callback") != std::string::npos || n.find("notify") != std::string::npos);
}

resolved_target_t resolve_first_callback_argument(const vuln::chain::corpus_record_t& corpus, func_t* fn, const insn_t& call_ins)
{
    if (inf_is_64bit())
    {
        const int rcx = find_register_by_name({"rcx", "ecx", "cx"});
        return trace_register_function_value(corpus, fn, call_ins.ea, rcx, 96);
    }
    ea_t scan = prev_head(call_ins.ea, fn != nullptr ? fn->start_ea : BADADDR);
    for (std::size_t steps = 0; scan != BADADDR && fn != nullptr && scan >= fn->start_ea && steps < 32; ++steps)
    {
        insn_t prev;
        if (decode_insn(&prev, scan) <= 0)
            break;
        if (prev.itype == NN_push)
            return resolve_operand_function_target(corpus, prev, prev.ops[0]);
        scan = prev_head(scan, fn->start_ea);
    }
    return resolved_target_t();
}

std::set<std::string> syscall_symbol_aliases(const std::string& symbol)
{
    std::set<std::string> aliases;
    std::string s = normalized_export_symbol(symbol);
    aliases.insert(s);
    if (s.size() > 2 && s.rfind("nt", 0) == 0)
        aliases.insert(std::string("zw") + s.substr(2));
    if (s.size() > 2 && s.rfind("zw", 0) == 0)
        aliases.insert(std::string("nt") + s.substr(2));
    return aliases;
}

bool is_syscall_service_table_name(const std::string& name)
{
    const std::string n = lowercase_ascii(name);
    if (n.find("descriptor") != std::string::npos || n.find("limit") != std::string::npos)
        return false;
    return n == "kiservicetable"
        || n == "w32pservicetable"
        || n == "win32kservicetable"
        || n.find("kiservicetable") != std::string::npos
        || n.find("w32pservicetable") != std::string::npos
        || n.find("win32kservicetable") != std::string::npos;
}

ea_t find_limit_symbol(const std::string& table_name)
{
    std::vector<std::string> names;
    names.push_back(table_name);
    const std::string lower = lowercase_ascii(table_name);
    if (lower.find("kiservicetable") != std::string::npos)
        names.push_back("KiServiceLimit");
    if (lower.find("w32pservicetable") != std::string::npos || lower.find("win32kservicetable") != std::string::npos)
        names.push_back("W32pServiceLimit");
    for (std::string candidate : names)
    {
        const std::string lc = lowercase_ascii(candidate);
        std::size_t pos = lc.find("servicetable");
        if (pos != std::string::npos)
            candidate.replace(pos, std::string("ServiceTable").size(), "ServiceLimit");
        ea_t ea = get_name_ea(BADADDR, candidate.c_str());
        if (ea != BADADDR && is_loaded(ea))
            return ea;
    }
    for (size_t i = 0; i < get_nlist_size(); ++i)
    {
        const char* raw = get_nlist_name(i);
        if (raw == nullptr)
            continue;
        const std::string n = lowercase_ascii(raw);
        if ((lower.find("ki") != std::string::npos && n.find("kiservicelimit") != std::string::npos)
            || (lower.find("w32") != std::string::npos && n.find("w32pservicelimit") != std::string::npos)
            || (lower.find("win32k") != std::string::npos && n.find("win32kservicelimit") != std::string::npos))
            return get_nlist_ea(i);
    }
    return BADADDR;
}

bool decode_service_entry(ea_t table_ea, ea_t entry_ea, ea_t& handler, std::uint64_t& raw_value, std::string& model)
{
    if (!is_loaded(entry_ea))
        return false;
    if (inf_is_64bit())
    {
        const std::uint32_t raw = get_dword(entry_ea);
        const std::int32_t signed_raw = static_cast<std::int32_t>(raw);
        const std::int64_t rel = static_cast<std::int64_t>(signed_raw >> 4);
        const ea_t target = static_cast<ea_t>(static_cast<std::int64_t>(table_ea) + rel);
        raw_value = raw;
        model = "x64_ssdt_relative_shift4";
        if (function_entry(target) != BADADDR)
        {
            handler = function_entry(target);
            return true;
        }
    }
    ea_t ptr = BADADDR;
    if (read_pointer_value(entry_ea, ptr) && function_entry(ptr) != BADADDR)
    {
        raw_value = static_cast<std::uint64_t>(ptr);
        handler = function_entry(ptr);
        model = inf_is_64bit() ? "direct_qword_pointer" : "direct_dword_pointer";
        return true;
    }
    return false;
}

json extract_syscall_services_for_current_idb(const vuln::chain::corpus_record_t& corpus, std::size_t max_items)
{
    json out;
    out["services"] = json::array();
    out["tables"] = json::array();
    out["diagnostics"] = json::array();
    out["state"] = "unavailable";
    out["proof_state"] = "inconclusive";
    out["source"] = "ida_named_service_tables";
    out["module_id"] = corpus.identity.corpus_id;
    std::vector<std::pair<ea_t, std::string>> tables;
    for (size_t i = 0; i < get_nlist_size(); ++i)
    {
        const char* raw = get_nlist_name(i);
        if (raw == nullptr)
            continue;
        std::string name = raw;
        if (!is_syscall_service_table_name(name))
            continue;
        const ea_t ea = get_nlist_ea(i);
        if (ea != BADADDR && is_loaded(ea))
            tables.emplace_back(ea, name);
    }
    std::sort(tables.begin(), tables.end(), [](const auto& a, const auto& b) {
        if (a.first != b.first)
            return a.first < b.first;
        return a.second < b.second;
    });
    tables.erase(std::unique(tables.begin(), tables.end(), [](const auto& a, const auto& b) {
        return a.first == b.first;
    }), tables.end());
    if (tables.empty())
    {
        out["reason"] = "service_table_symbol_missing";
        out["diagnostics"].push_back({{"reason", "no KiServiceTable/W32pServiceTable symbol present in IDA name list"}});
        return out;
    }
    const std::size_t cap = std::max<std::size_t>(1, max_items);
    for (const auto& table : tables)
    {
        json table_doc;
        table_doc["name"] = table.second;
        table_doc["ea"] = hex_u64(static_cast<std::uint64_t>(table.first));
        table_doc["address"] = address_for_ea(corpus, table.first, "table_symbol");
        table_doc["entry_stride"] = inf_is_64bit() ? 4 : static_cast<int>(sizeof(ea_t));
        table_doc["services"] = json::array();
        ea_t limit_ea = find_limit_symbol(table.second);
        std::uint64_t limit = 0;
        std::string limit_source;
        if (limit_ea != BADADDR && is_loaded(limit_ea))
        {
            limit = get_dword(limit_ea);
            limit_source = "named_service_limit";
            table_doc["limit_ea"] = hex_u64(static_cast<std::uint64_t>(limit_ea));
        }
        else
        {
            const std::size_t infer_cap = std::min<std::size_t>(cap, 4096);
            for (std::size_t i = 0; i < infer_cap; ++i)
            {
                ea_t handler = BADADDR;
                std::uint64_t raw_value = 0;
                std::string model;
                const ea_t entry_ea = table.first + static_cast<ea_t>(i * (inf_is_64bit() ? 4 : sizeof(ea_t)));
                if (!decode_service_entry(table.first, entry_ea, handler, raw_value, model))
                    break;
                limit = i + 1;
            }
            if (limit != 0)
                limit_source = "contiguous_table_inference";
        }
        table_doc["limit"] = limit;
        table_doc["limit_source"] = limit_source.empty() ? "unavailable" : limit_source;
        if (limit == 0)
        {
            table_doc["state"] = "unavailable";
            table_doc["reason"] = "service_limit_unavailable";
            out["tables"].push_back(std::move(table_doc));
            continue;
        }
        const std::size_t stride = inf_is_64bit() ? 4 : sizeof(ea_t);
        const std::size_t end = static_cast<std::size_t>(std::min<std::uint64_t>(limit, static_cast<std::uint64_t>(cap)));
        for (std::size_t i = 0; i < end; ++i)
        {
            const ea_t entry_ea = table.first + static_cast<ea_t>(i * stride);
            ea_t handler = BADADDR;
            std::uint64_t raw_value = 0;
            std::string model;
            if (!decode_service_entry(table.first, entry_ea, handler, raw_value, model))
                continue;
            const std::string handler_name = function_name(handler);
            json svc;
            svc["kind"] = "windows_syscall_service";
            svc["table_name"] = table.second;
            svc["table_ea"] = hex_u64(static_cast<std::uint64_t>(table.first));
            svc["entry_ea"] = hex_u64(static_cast<std::uint64_t>(entry_ea));
            svc["index"] = i;
            svc["service_index"] = i;
            svc["entry_value"] = hex_u64(raw_value);
            svc["entry_model"] = model;
            svc["name"] = lowercase_ascii(handler_name);
            svc["display_name"] = handler_name;
            svc["service_name"] = lowercase_ascii(handler_name);
            svc["handler"] = function_target_json(corpus, handler, "syscall_service_table");
            svc["target"] = svc["handler"];
            svc["proof_state"] = "proven";
            svc["confidence"] = "exact";
            svc["source"] = limit_source;
            svc["build_identity"] = json::object({
                {"module_id", corpus.identity.corpus_id},
                {"input_sha256", corpus.identity.input_sha256},
                {"image_base", hex_u64(static_cast<std::uint64_t>(get_imagebase()))},
                {"processor", inf_get_procname().c_str()},
                {"bitness", static_cast<int>(inf_get_app_bitness())}
            });
            table_doc["services"].push_back(svc);
            if (out["services"].size() < cap)
                out["services"].push_back(std::move(svc));
        }
        table_doc["state"] = table_doc["services"].empty() ? "unavailable" : "proven";
        table_doc["proof_state"] = table_doc["services"].empty() ? "inconclusive" : "proven";
        if (table_doc["services"].empty())
            table_doc["reason"] = "no_valid_service_entries";
        out["tables"].push_back(std::move(table_doc));
    }
    if (!out["services"].empty())
    {
        out["state"] = "proven";
        out["proof_state"] = "proven";
        out["reason"] = "source_backed_service_table";
    }
    else
    {
        out["reason"] = "service_entries_unavailable";
    }
    out["service_count"] = out["services"].size();
    return out;
}

struct module_maps_t
{
    json modules = json::array();
    std::unordered_map<std::string, std::vector<json>> by_name;
    std::unordered_map<std::string, json> by_id;
    std::unordered_map<std::string, std::vector<std::string>> api_set_hosts;
};

void append_name_alias(std::unordered_map<std::string, std::vector<json>>& by_name,
                       const std::string& alias,
                       const json& module)
{
    const std::string key = lowercase_ascii(alias);
    if (key.empty())
        return;
    auto& bucket = by_name[key];
    const std::string id = canonical_module_id_from_json(module);
    for (const json& existing : bucket)
    {
        if (canonical_module_id_from_json(existing) == id)
            return;
    }
    bucket.push_back(module);
}

void append_api_host(module_maps_t& maps, const std::string& contract, const std::string& host)
{
    const std::string c = lowercase_ascii(contract);
    const std::string h = lowercase_ascii(host);
    if (c.empty() || h.empty())
        return;
    auto& hosts = maps.api_set_hosts[c];
    if (std::find(hosts.begin(), hosts.end(), h) == hosts.end())
        hosts.push_back(h);
}

void collect_module_aliases(module_maps_t& maps, const json& module)
{
    append_name_alias(maps.by_name, canonical_name_of(module), module);
    const json identity = module_identity(module);
    append_name_alias(maps.by_name, identity.value("module_name", std::string()), module);
    append_name_alias(maps.by_name, identity.value("input_basename", std::string()), module);
    if (module.contains("aliases") && module["aliases"].is_array())
    {
        for (const json& alias : module["aliases"])
            if (alias.is_string())
                append_name_alias(maps.by_name, alias.get<std::string>(), module);
    }
    if (module.contains("api_set_contracts") && module["api_set_contracts"].is_array())
    {
        for (const json& contract : module["api_set_contracts"])
        {
            if (contract.is_string())
                append_api_host(maps, contract.get<std::string>(), canonical_name_of(module));
        }
    }
    if (module.contains("api_set_hosts") && module["api_set_hosts"].is_object())
    {
        for (auto it = module["api_set_hosts"].begin(); it != module["api_set_hosts"].end(); ++it)
        {
            if (it.value().is_string())
            {
                append_api_host(maps, it.key(), it.value().get<std::string>());
            }
            else if (it.value().is_array())
            {
                for (const json& host : it.value())
                    if (host.is_string())
                        append_api_host(maps, it.key(), host.get<std::string>());
            }
        }
    }
    if (module.contains("api_set_map") && module["api_set_map"].is_object())
    {
        for (auto it = module["api_set_map"].begin(); it != module["api_set_map"].end(); ++it)
        {
            if (it.value().is_string())
            {
                append_api_host(maps, it.key(), it.value().get<std::string>());
            }
            else if (it.value().is_array())
            {
                for (const json& host : it.value())
                    if (host.is_string())
                        append_api_host(maps, it.key(), host.get<std::string>());
            }
        }
    }
}

module_maps_t build_module_maps(const json& modules)
{
    module_maps_t maps;
    if (!modules.is_array())
        return maps;
    for (const json& raw : modules)
    {
        json module = normalize_module_record(raw);
        const std::string id = canonical_module_id_from_json(module);
        maps.modules.push_back(module);
        maps.by_id[id] = module;
        collect_module_aliases(maps, module);
    }
    return maps;
}

json find_export_matches(const json& module, const json& imp)
{
    json matches = json::array();
    const std::string wanted_name = import_symbol_name(imp);
    const std::string normalized_wanted_name = normalized_export_symbol(wanted_name);
    const std::uint64_t wanted_ordinal = imp.contains("ordinal") ? parse_u64_loose(imp["ordinal"]) : 0;
    for (const json& exp : normalize_exports(module))
    {
        if (!exp.is_object())
            continue;
        const bool name_match = !wanted_name.empty()
            && (export_name(exp) == wanted_name || normalized_export_symbol(export_name(exp)) == normalized_wanted_name);
        const bool ordinal_match = wanted_ordinal != 0 && export_ordinal(exp) == wanted_ordinal;
        if (name_match || ordinal_match)
            matches.push_back(exp);
    }
    return matches;
}

std::pair<std::string, std::string> parse_forwarder(const std::string& forwarder)
{
    const size_t pos = forwarder.find_last_of('.');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= forwarder.size())
        return {std::string(), std::string()};
    std::string mod = lowercase_ascii(forwarder.substr(0, pos));
    std::string sym = forwarder.substr(pos + 1);
    if (mod.find('.') == std::string::npos)
        mod += ".dll";
    return {mod, sym};
}

json resolve_import_against_maps(const module_maps_t& maps,
                                 const json& source_module,
                                 const json& imp,
                                 int depth);

json target_modules_for_import(const module_maps_t& maps, const std::string& requested_module, json& result)
{
    json targets = json::array();
    auto mit = maps.by_name.find(requested_module);
    if (mit != maps.by_name.end())
    {
        for (const json& module : mit->second)
            targets.push_back(module);
        result["resolution_basis"] = "module_alias";
        return targets;
    }
    if (!is_api_set_contract_name(requested_module))
        return targets;
    result["kind"] = "api_set_import";
    result["api_set_contract"] = requested_module;
    auto hit = maps.api_set_hosts.find(requested_module);
    if (hit == maps.api_set_hosts.end() || hit->second.empty())
    {
        result["reason"] = "api_set_map_missing";
        result["confidence"] = "unresolved";
        result["missing_module"] = requested_module;
        return targets;
    }
    std::set<std::string> seen;
    for (const std::string& host : hit->second)
    {
        auto host_it = maps.by_name.find(host);
        if (host_it == maps.by_name.end())
            continue;
        for (const json& module : host_it->second)
        {
            const std::string id = canonical_module_id_from_json(module);
            if (seen.insert(id).second)
                targets.push_back(module);
        }
    }
    if (targets.empty())
    {
        result["reason"] = "api_set_hosts_not_loaded";
        result["confidence"] = "unresolved";
        result["host_candidates"] = hit->second;
        return targets;
    }
    result["resolution_basis"] = "api_set_host_map";
    result["host_candidates"] = hit->second;
    return targets;
}

json resolve_forwarder_against_maps(const module_maps_t& maps,
                                    const json& source_module,
                                    const json& export_item,
                                    int depth)
{
    const std::string fwd = export_item.value("forwarder", std::string());
    if (fwd.empty())
        return json::object();
    auto parsed = parse_forwarder(fwd);
    if (parsed.first.empty())
    {
        return json::object({
            {"state", "unresolved"},
            {"reason", "forwarder_parse_failed"},
            {"forwarder", fwd}
        });
    }
    json imp;
    imp["module"] = parsed.first;
    if (!parsed.second.empty() && parsed.second[0] == '#')
        imp["ordinal"] = parsed.second.substr(1);
    else
        imp["name"] = parsed.second;
    json resolved = resolve_import_against_maps(maps, source_module, imp, depth + 1);
    resolved["forwarder"] = fwd;
    resolved["kind"] = "forwarded_export";
    return resolved;
}

json resolve_import_against_maps(const module_maps_t& maps,
                                 const json& source_module,
                                 const json& imp,
                                 int depth)
{
    if (depth > 8)
        return json::object({{"state", "unresolved"}, {"reason", "forwarder_depth_exceeded"}, {"import", imp}});
    const std::string requested_module = import_module_name(imp);
    json result;
    result["state"] = "unresolved";
    result["kind"] = "import_export";
    result["source_module_id"] = canonical_module_id_from_json(source_module);
    result["import"] = imp;
    result["target_candidates"] = json::array();
    json target_modules = target_modules_for_import(maps, requested_module, result);
    if (target_modules.empty())
    {
        if (!result.contains("reason"))
        {
            result["reason"] = "module_missing";
            result["missing_module"] = requested_module;
            result["confidence"] = "unresolved";
        }
        return result;
    }
    json matches = json::array();
    for (const json& target_module : target_modules)
    {
        const json exports = find_export_matches(target_module, imp);
        for (const json& exp : exports)
        {
            json candidate;
            candidate["module_id"] = canonical_module_id_from_json(target_module);
            candidate["module_name"] = canonical_name_of(target_module);
            candidate["export"] = exp;
            candidate["address"] = make_target_address(target_module, exp);
            matches.push_back(candidate);
        }
    }
    result["target_candidates"] = matches;
    if (matches.empty())
    {
        result["reason"] = "symbol_missing";
        result["confidence"] = "unresolved";
        return result;
    }
    if (matches.size() > 1)
    {
        result["state"] = "ambiguous";
        result["reason"] = "multiple_export_matches";
        result["confidence"] = "ambiguous";
        return result;
    }
    const json selected = matches.front();
    result["state"] = "resolved";
    result["reason"] = "exact_export_match";
    result["confidence"] = "exact";
    result["target"] = selected;
    const std::string forwarder = selected.value("export", json::object()).value("forwarder", std::string());
    if (!forwarder.empty())
    {
        json forwarded = resolve_forwarder_against_maps(maps, source_module, selected["export"], depth + 1);
        result["forwarded_resolution"] = forwarded;
        if (forwarded.value("state", std::string()) == "resolved")
        {
            result["target"] = forwarded.value("target", selected);
            result["reason"] = "forwarder_resolved";
        }
        else
        {
            result["state"] = forwarded.value("state", std::string("unresolved"));
            result["reason"] = forwarded.value("reason", std::string("forwarder_unresolved"));
            result["confidence"] = forwarded.value("confidence", std::string("unresolved"));
        }
    }
    return result;
}

json target_from_declared_edge(const json& item)
{
    if (item.contains("target") && item["target"].is_object())
        return item["target"];
    if (item.contains("handler") && item["handler"].is_object())
        return item["handler"];
    if (item.contains("callback") && item["callback"].is_object())
        return item["callback"];
    if (item.contains("address") && item["address"].is_object())
        return item["address"];
    if (item.contains("module_id") && item.contains("rva"))
        return json::object({{"module_id", item["module_id"]}, {"address", canonical_address_json(item.value("module_id", std::string()), parse_u64_loose(item["rva"]))}});
    return json::object();
}

bool declared_edge_is_proven(const json& item)
{
    const std::string state = lowercase_ascii(item.value("proof_state", item.value("state", item.value("confidence", std::string()))));
    if (state != "proven" && state != "confirmed" && state != "exact")
        return false;
    if (item.contains("evidence") && (item["evidence"].is_object() || item["evidence"].is_array()) && !item["evidence"].empty())
        return true;
    for (const char* key : {"source", "source_layer", "layer", "lineage", "evidence_id", "snapshot_id", "trace_id", "assignment_ea", "instruction"})
    {
        if (!item.contains(key) || !item[key].is_string())
            continue;
        const std::string value = lowercase_ascii(item[key].get<std::string>());
        if (!value.empty() && value != "user_declared" && value != "declared" && value != "assumption")
            return true;
    }
    return false;
}

json make_declared_edge(const json& module, const json& item, const std::string& family, std::size_t ordinal)
{
    const std::string module_id = canonical_module_id_from_json(module);
    json edge;
    edge["edge_id"] = family + "_" + stable_hash_hex(module_id + item.dump() + std::to_string(ordinal));
    edge["kind"] = family;
    edge["source_module_id"] = module_id;
    edge["source_module_name"] = canonical_name_of(module);
    edge["evidence"] = item;
    edge["target_candidates"] = json::array();
    json target = target_from_declared_edge(item);
    if (declared_edge_is_proven(item) && !target.empty())
    {
        edge["state"] = "resolved";
        edge["reason"] = "source_backed_assignment";
        edge["confidence"] = "exact";
        edge["target"] = target;
    }
    else
    {
        edge["state"] = "unresolved";
        edge["reason"] = target.empty() ? "target_missing" : "assignment_not_proven";
        edge["confidence"] = "unresolved";
    }
    return edge;
}

void append_declared_edges(json& graph, const json& module, const char* field, const std::string& family)
{
    if (!module.contains(field) || !module[field].is_array())
        return;
    std::size_t index = 0;
    for (const json& item : module[field])
    {
        if (!item.is_object())
            continue;
        json edge = make_declared_edge(module, item, family, index++);
        if (edge.value("state", std::string()) == "resolved")
            graph["edges"].push_back(edge);
        else
            graph["unresolved"].push_back(edge);
    }
}

json resolve_syscall_against_maps(const module_maps_t& maps, const json& source_module, const json& imp)
{
    json result;
    const std::string symbol = import_symbol_name(imp);
    result["state"] = "unresolved";
    result["kind"] = "syscall_service";
    result["source_module_id"] = canonical_module_id_from_json(source_module);
    result["import"] = imp;
    result["service_name"] = symbol;
    result["target_candidates"] = json::array();
    if (!is_syscall_symbol(symbol))
    {
        result["reason"] = "not_syscall_symbol";
        result["confidence"] = "unresolved";
        return result;
    }
    for (const json& module : maps.modules)
    {
        if (!module.contains("syscall_services") || !module["syscall_services"].is_array())
            continue;
        for (const json& svc : module["syscall_services"])
        {
            if (!svc.is_object())
                continue;
            const std::string svc_name = lowercase_ascii(svc.value("name", svc.value("service_name", std::string())));
            const std::set<std::string> wanted = syscall_symbol_aliases(symbol);
            const std::set<std::string> service_aliases = syscall_symbol_aliases(svc_name);
            bool matched = false;
            for (const std::string& alias : wanted)
            {
                if (service_aliases.find(alias) != service_aliases.end())
                {
                    matched = true;
                    break;
                }
            }
            if (!matched)
                continue;
            json candidate;
            candidate["module_id"] = canonical_module_id_from_json(module);
            candidate["module_name"] = canonical_name_of(module);
            candidate["service"] = svc;
            candidate["target"] = target_from_declared_edge(svc);
            result["target_candidates"].push_back(candidate);
        }
    }
    if (result["target_candidates"].empty())
    {
        result["reason"] = "syscall_mapping_missing";
        result["confidence"] = "unresolved";
        return result;
    }
    if (result["target_candidates"].size() > 1)
    {
        result["state"] = "ambiguous";
        result["reason"] = "multiple_syscall_service_matches";
        result["confidence"] = "ambiguous";
        return result;
    }
    const json candidate = result["target_candidates"].front();
    if (candidate.value("target", json::object()).empty())
    {
        result["reason"] = "syscall_handler_missing";
        result["confidence"] = "unresolved";
        return result;
    }
    result["state"] = "resolved";
    result["reason"] = "source_backed_syscall_mapping";
    result["confidence"] = "exact";
    result["target"] = candidate;
    return result;
}

json make_guard_dispatch_gap(const json& module, const json& imp)
{
    const std::string module_id = canonical_module_id_from_json(module);
    return json::object({
        {"edge_id", "guard_" + stable_hash_hex(module_id + imp.dump())},
        {"kind", "cfg_xfg_guard_dispatch"},
        {"state", "unresolved"},
        {"reason", "guard_target_requires_trace_state"},
        {"confidence", "unresolved"},
        {"source_module_id", module_id},
        {"import", imp},
        {"proof_obligation", "target register or memory slot must be proven at guard dispatch entry"}
    });
}

void append_edge_by_state(json& graph, const json& edge)
{
    const std::string state = edge.value("state", std::string());
    if (state == "resolved")
        graph["edges"].push_back(edge);
    else if (state == "ambiguous")
        graph["ambiguous"].push_back(edge);
    else
        graph["unresolved"].push_back(edge);
}

json derive_resolver_evidence(const json& module, const json& catalog, std::size_t max_items)
{
    json out;
    out["dispatch_tables"] = json::array();
    out["ioctl_dispatchers"] = json::array();
    out["callback_registrations"] = json::array();
    out["global_pointers"] = json::array();
    out["guarded_indirects"] = json::array();
    out["indirect_calls"] = json::array();
    const std::string module_id = canonical_module_id_from_json(module);
    auto append_candidate = [&](const std::string& family, json item) {
        if (!item.is_object())
            return;
        item["source"] = item.value("source", std::string("ida_index"));
        item["proof_state"] = item.value("proof_state", std::string("candidate"));
        item["module_id"] = module_id;
        if (out[family].size() < max_items)
            out[family].push_back(std::move(item));
    };
    for (const json& imp : normalize_imports(module))
    {
        if (!imp.is_object())
            continue;
        const std::string sym = import_symbol_name(imp);
        if (is_guard_dispatch_symbol(sym))
            append_candidate("guarded_indirects", json::object({{"kind", "guard_import"}, {"import", imp}, {"reason", "guard import requires trace-state target"}}));
    }
    for (const json& fn : catalog.value("functions", json::array()))
    {
        if (!fn.is_object())
            continue;
        const std::string name = lowercase_ascii(fn.value("name", std::string()));
        if (name.find("devicecontrol") != std::string::npos || name.find("ioctl") != std::string::npos)
            append_candidate("ioctl_dispatchers", json::object({{"kind", "ioctl_handler_candidate"}, {"function", fn}, {"reason", "function name evidence only"}}));
        if (name.find("dispatch") != std::string::npos || name.find("majorfunction") != std::string::npos)
            append_candidate("dispatch_tables", json::object({{"kind", "driver_dispatch_candidate"}, {"function", fn}, {"reason", "function name evidence only"}}));
        if (name.find("callback") != std::string::npos || name.find("notify") != std::string::npos || name.find("completion") != std::string::npos || name.find("routine") != std::string::npos)
            append_candidate("callback_registrations", json::object({{"kind", "callback_candidate"}, {"function", fn}, {"reason", "function name evidence only"}}));
    }
    for (const json& xref : catalog.value("local_xrefs", json::array()))
    {
        if (!xref.is_object())
            continue;
        const std::string kind = xref.value("kind", std::string());
        if (kind == "data_read" || kind == "data_write" || kind == "data_offset")
            append_candidate("global_pointers", json::object({{"kind", "global_pointer_reference"}, {"xref", xref}, {"reason", "data xref requires value trace before it can be a function-pointer edge"}}));
    }
    return out;
}

void append_trace_item(json& out, const std::string& family, json item, std::size_t max_items)
{
    if (!item.is_object())
        return;
    if (!out.contains(family) || !out[family].is_array())
        out[family] = json::array();
    json key_item = item;
    key_item.erase("evidence_hash");
    item["evidence_hash"] = stable_hash_hex(key_item.dump());
    for (const json& existing : out[family])
    {
        if (existing.is_object() && existing.value("evidence_hash", std::string()) == item.value("evidence_hash", std::string()))
            return;
    }
    if (out[family].size() < max_items)
        out[family].push_back(std::move(item));
}

json function_context_json(const vuln::chain::corpus_record_t& corpus, func_t* fn)
{
    if (fn == nullptr)
        return json::object();
    return json::object({
        {"name", function_name(fn->start_ea)},
        {"start", address_for_ea(corpus, fn->start_ea)},
        {"ea_hint", hex_u64(static_cast<std::uint64_t>(fn->start_ea))}
    });
}

json base_instruction_evidence(const vuln::chain::corpus_record_t& corpus, func_t* fn, const insn_t& ins)
{
    json item;
    item["module_id"] = corpus.identity.corpus_id;
    item["function"] = function_context_json(corpus, fn);
    item["assignment_ea"] = hex_u64(static_cast<std::uint64_t>(ins.ea));
    item["address"] = address_for_ea(corpus, ins.ea);
    item["instruction"] = instruction_text(ins.ea);
    item["source"] = "ida_instruction_trace";
    return item;
}

json proven_target_payload(const vuln::chain::corpus_record_t& corpus, const resolved_target_t& target)
{
    json payload = function_target_json(corpus, target.target, target.source);
    payload["trace"] = target.trace;
    return payload;
}

bool destination_mentions_major_function(const std::string& text)
{
    const std::string lower = lowercase_ascii(text);
    return lower.find("majorfunction") != std::string::npos || lower.find("major_function") != std::string::npos;
}

bool function_name_mentions_ioctl(const std::string& name)
{
    const std::string lower = lowercase_ascii(name);
    return lower.find("devicecontrol") != std::string::npos
        || lower.find("device_control") != std::string::npos
        || lower.find("ioctl") != std::string::npos;
}

bool function_name_mentions_dispatch(const std::string& name)
{
    const std::string lower = lowercase_ascii(name);
    return lower.find("driverentry") != std::string::npos
        || lower.find("dispatch") != std::string::npos
        || lower.find("majorfunction") != std::string::npos;
}

struct ioctl_switch_visitor_t : public ctree_visitor_t
{
    json* out = nullptr;
    const vuln::chain::corpus_record_t* corpus = nullptr;
    func_t* fn = nullptr;
    std::size_t max_items = 0;

    ioctl_switch_visitor_t(json* output, const vuln::chain::corpus_record_t* c, func_t* f, std::size_t max)
        : ctree_visitor_t(CV_FAST), out(output), corpus(c), fn(f), max_items(max)
    {
    }

    int idaapi visit_insn(cinsn_t* insn) override
    {
        if (insn == nullptr || insn->op != cit_switch || insn->cswitch == nullptr || out == nullptr || corpus == nullptr || fn == nullptr)
            return 0;
        std::size_t ordinal = 0;
        for (const auto& cc : insn->cswitch->cases)
        {
            if (out->value("ioctl_dispatchers", json::array()).size() >= max_items)
                return 1;
            json item;
            item["kind"] = "ioctl_switch_case";
            item["module_id"] = corpus->identity.corpus_id;
            item["function"] = function_context_json(*corpus, fn);
            item["switch_ea"] = insn->ea == BADADDR ? json(nullptr) : json(hex_u64(static_cast<std::uint64_t>(insn->ea)));
            item["case_ea"] = cc.ea == BADADDR ? json(nullptr) : json(hex_u64(static_cast<std::uint64_t>(cc.ea)));
            item["case_values"] = json::array();
            for (uint64_t value : cc.values)
                item["case_values"].push_back(value);
            item["ordinal"] = ordinal++;
            item["target"] = cc.ea == BADADDR ? function_target_json(*corpus, fn->start_ea, "ctree_ioctl_switch")
                                               : json::object({{"module_id", corpus->identity.corpus_id}, {"address", address_for_ea(*corpus, cc.ea)}, {"ea_hint", hex_u64(static_cast<std::uint64_t>(cc.ea))}, {"name", function_name(fn->start_ea)}, {"source", "ctree_ioctl_switch"}});
            item["proof_state"] = "proven";
            item["confidence"] = "exact";
            item["source"] = "hexrays_ctree_switch";
            append_trace_item(*out, "ioctl_dispatchers", std::move(item), max_items);
        }
        return 0;
    }
};

void trace_ioctl_switches(json& out, const vuln::chain::corpus_record_t& corpus, func_t* fn, std::size_t max_items)
{
    if (fn == nullptr || out.value("ioctl_dispatchers", json::array()).size() >= max_items)
        return;
    if (!function_name_mentions_ioctl(function_name(fn->start_ea)))
        return;
    if (!init_hexrays_plugin())
    {
        json item;
        item["kind"] = "ioctl_switch_analysis";
        item["module_id"] = corpus.identity.corpus_id;
        item["function"] = function_context_json(corpus, fn);
        item["proof_state"] = "inconclusive";
        item["reason"] = "hexrays_unavailable";
        item["source"] = "hexrays_ctree_switch";
        append_trace_item(out, "ioctl_dispatchers", std::move(item), max_items);
        return;
    }
    try
    {
        hexrays_failure_t hf;
        cfuncptr_t cf = decompile_func(fn, &hf, DECOMP_NO_WAIT | DECOMP_WARNINGS);
        if (cf == nullptr)
        {
            json item;
            item["kind"] = "ioctl_switch_analysis";
            item["module_id"] = corpus.identity.corpus_id;
            item["function"] = function_context_json(corpus, fn);
            item["proof_state"] = "inconclusive";
            item["reason"] = std::string("decompile_failed:") + hf.desc().c_str();
            item["source"] = "hexrays_ctree_switch";
            append_trace_item(out, "ioctl_dispatchers", std::move(item), max_items);
            return;
        }
        ioctl_switch_visitor_t visitor(&out, &corpus, fn, max_items);
        visitor.apply_to(&cf->body, nullptr);
    }
    catch (const vd_failure_t&)
    {
        json item;
        item["kind"] = "ioctl_switch_analysis";
        item["module_id"] = corpus.identity.corpus_id;
        item["function"] = function_context_json(corpus, fn);
        item["proof_state"] = "inconclusive";
        item["reason"] = "decompile_exception";
        item["source"] = "hexrays_ctree_switch";
        append_trace_item(out, "ioctl_dispatchers", std::move(item), max_items);
    }
    catch (...)
    {
        json item;
        item["kind"] = "ioctl_switch_analysis";
        item["module_id"] = corpus.identity.corpus_id;
        item["function"] = function_context_json(corpus, fn);
        item["proof_state"] = "inconclusive";
        item["reason"] = "decompile_unknown_exception";
        item["source"] = "hexrays_ctree_switch";
        append_trace_item(out, "ioctl_dispatchers", std::move(item), max_items);
    }
}

json capture_source_trace_evidence(const json&, const json&, std::size_t max_items)
{
    struct request_t : public exec_request_t
    {
        std::size_t max_items = 0;
        json result = json::object();
        ssize_t idaapi execute() override
        {
            vuln::chain::corpus_record_t corpus = vuln::chain::snapshot_current_idb_corpus();
            result["schema"] = "aida.multibinary.source_trace_evidence";
            result["module_id"] = corpus.identity.corpus_id;
            result["dispatch_tables"] = json::array();
            result["ioctl_dispatchers"] = json::array();
            result["callback_registrations"] = json::array();
            result["global_pointers"] = json::array();
            result["guarded_indirects"] = json::array();
            result["indirect_calls"] = json::array();
            result["syscall_services"] = json::array();
            result["syscall_service_extraction"] = extract_syscall_services_for_current_idb(corpus, max_items);
            result["syscall_services"] = result["syscall_service_extraction"].value("services", json::array());
            const int guard_rcx = find_register_by_name({"rcx", "ecx", "cx"});
            const std::size_t qty = get_func_qty();
            for (std::size_t i = 0; i < qty; ++i)
            {
                if (user_cancelled())
                {
                    result["cancelled"] = true;
                    break;
                }
                func_t* fn = getn_func(i);
                if (fn == nullptr)
                    continue;
                const std::string fn_name = function_name(fn->start_ea);
                trace_ioctl_switches(result, corpus, fn, max_items);
                func_item_iterator_t fii(fn);
                for (bool ok = fii.first(); ok; ok = fii.next_head())
                {
                    const ea_t ea = fii.current();
                    insn_t ins;
                    if (decode_insn(&ins, ea) <= 0)
                        continue;
                    if (ins.itype == NN_mov && ins.ops[0].type != o_void && ins.ops[1].type != o_void)
                    {
                        const std::string dst_text = operand_text(ea, 0);
                        const bool memory_destination = ins.ops[0].type == o_mem || ins.ops[0].type == o_displ || ins.ops[0].type == o_phrase;
                        if (memory_destination)
                        {
                            resolved_target_t rhs = resolve_call_or_store_operand(corpus, fn, ins, ins.ops[1]);
                            if (rhs.ok && destination_mentions_major_function(dst_text))
                            {
                                json item = base_instruction_evidence(corpus, fn, ins);
                                item["kind"] = "driver_major_function_assignment";
                                item["destination_operand"] = dst_text;
                                item["handler"] = proven_target_payload(corpus, rhs);
                                item["target"] = item["handler"];
                                item["proof_state"] = "proven";
                                item["confidence"] = "exact";
                                append_trace_item(result, "dispatch_tables", std::move(item), max_items);
                            }
                            else if (rhs.ok && ins.ops[0].type == o_mem && ea_in_data(static_cast<ea_t>(ins.ops[0].addr)))
                            {
                                json item = base_instruction_evidence(corpus, fn, ins);
                                item["kind"] = "global_function_pointer_store";
                                item["slot_ea"] = hex_u64(static_cast<std::uint64_t>(ins.ops[0].addr));
                                item["slot"] = address_for_ea(corpus, static_cast<ea_t>(ins.ops[0].addr), "global_slot");
                                item["destination_operand"] = dst_text;
                                item["target"] = proven_target_payload(corpus, rhs);
                                item["proof_state"] = "proven";
                                item["confidence"] = "exact";
                                append_trace_item(result, "global_pointers", std::move(item), max_items);
                            }
                            else if (!rhs.ok && destination_mentions_major_function(dst_text) && function_name_mentions_dispatch(fn_name))
                            {
                                json item = base_instruction_evidence(corpus, fn, ins);
                                item["kind"] = "driver_major_function_assignment";
                                item["destination_operand"] = dst_text;
                                item["proof_state"] = "candidate";
                                item["reason"] = "major_function_store_target_unresolved";
                                append_trace_item(result, "dispatch_tables", std::move(item), max_items);
                            }
                        }
                    }
                    if (is_call_like(ins))
                    {
                        const ea_t callee = first_xref_target(ea);
                        const std::string api_name = ida_name(callee);
                        if (is_callback_registration_api(api_name))
                        {
                            resolved_target_t cb = resolve_first_callback_argument(corpus, fn, ins);
                            json item = base_instruction_evidence(corpus, fn, ins);
                            item["kind"] = "callback_registration_call";
                            item["api"] = api_name;
                            item["api_ea"] = callee == BADADDR ? json(nullptr) : json(hex_u64(static_cast<std::uint64_t>(callee)));
                            if (cb.ok)
                            {
                                item["callback"] = proven_target_payload(corpus, cb);
                                item["target"] = item["callback"];
                                item["proof_state"] = "proven";
                                item["confidence"] = "exact";
                            }
                            else
                            {
                                item["proof_state"] = "candidate";
                                item["reason"] = "callback_argument_unresolved";
                            }
                            append_trace_item(result, "callback_registrations", std::move(item), max_items);
                        }
                    }
                    int guard_reg = -1;
                    ssize_t guard_kind = processor_t::is_control_flow_guard(&guard_reg, &ins);
                    if (guard_kind == 1 || guard_kind == 2 || is_guard_dispatch_symbol(ida_name(first_xref_target(ea))))
                    {
                        if (guard_reg < 0)
                            guard_reg = guard_rcx;
                        resolved_target_t target = trace_register_function_value(corpus, fn, ea, guard_reg, 96);
                        json item = base_instruction_evidence(corpus, fn, ins);
                        item["kind"] = guard_kind == 2 ? "xfg_security_check_target" : "cfg_xfg_guard_target";
                        item["guard_kind"] = guard_kind;
                        item["target_register"] = guard_reg;
                        item["target_register_name"] = register_name(guard_reg);
                        if (target.ok)
                        {
                            item["target"] = proven_target_payload(corpus, target);
                            item["proof_state"] = "proven";
                            item["confidence"] = "exact";
                        }
                        else
                        {
                            item["proof_state"] = "candidate";
                            item["reason"] = "guard_target_register_unresolved";
                        }
                        append_trace_item(result, "guarded_indirects", std::move(item), max_items);
                    }
                    if (is_indirect_call_like(ins))
                    {
                        resolved_target_t target = resolve_call_or_store_operand(corpus, fn, ins, ins.ops[0]);
                        json item = base_instruction_evidence(corpus, fn, ins);
                        item["kind"] = "indirect_call_target_state";
                        item["operand"] = operand_text(ea, 0);
                        if (target.ok)
                        {
                            item["target"] = proven_target_payload(corpus, target);
                            item["proof_state"] = "proven";
                            item["confidence"] = "exact";
                        }
                        else
                        {
                            item["proof_state"] = "candidate";
                            item["reason"] = "indirect_target_state_unresolved";
                        }
                        append_trace_item(result, "indirect_calls", std::move(item), max_items);
                    }
                }
            }
            return 1;
        }
    } req;
    req.max_items = std::max<std::size_t>(1, max_items);
    if (execute_sync(req, MFF_READ) <= 0)
        return json::object({{"schema", "aida.multibinary.source_trace_evidence"}, {"error", "execute_sync_failed"}});
    return req.result;
}

void merge_resolver_evidence(json& dst, const json& src, const std::vector<std::string>& families, std::size_t max_items)
{
    for (const std::string& family : families)
    {
        if (!dst.contains(family) || !dst[family].is_array())
            dst[family] = json::array();
        for (const json& item : src.value(family, json::array()))
            append_trace_item(dst, family, item, max_items);
    }
    if (src.contains("syscall_service_extraction"))
        dst["syscall_service_extraction"] = src["syscall_service_extraction"];
    if (src.contains("syscall_services"))
        dst["syscall_services"] = src["syscall_services"];
}

json capture_function_catalog(std::size_t max_functions, std::size_t max_edges)
{
    struct request_t : public exec_request_t
    {
        std::size_t max_functions = 0;
        std::size_t max_edges = 0;
        json result = json::object();
        ssize_t idaapi execute() override
        {
            vuln::chain::corpus_record_t corpus = vuln::chain::snapshot_current_idb_corpus();
            const std::string module_id = corpus.identity.corpus_id;
            result["schema"] = k_index_schema;
            result["version"] = k_project_schema_version;
            result["module_id"] = module_id;
            result["generated_at_ms"] = now_ms();
            result["auto_analysis_ok"] = auto_is_ok();
            result["functions"] = json::array();
            result["local_call_edges"] = json::array();
            result["local_xrefs"] = json::array();
            result["signatures"] = json::array();
            result["truncated"] = false;
            const std::size_t qty = get_func_qty();
            const std::size_t end = std::min(qty, max_functions);
            for (std::size_t i = 0; i < end; ++i)
            {
                if (user_cancelled())
                {
                    result["cancelled"] = true;
                    result["truncated"] = true;
                    break;
                }
                func_t* fn = getn_func(i);
                if (fn == nullptr)
                    continue;
                auto start_norm = vuln::chain::normalize_ea(corpus, static_cast<std::uint64_t>(fn->start_ea));
                auto end_norm = vuln::chain::normalize_ea(corpus, static_cast<std::uint64_t>(fn->end_ea > fn->start_ea ? fn->end_ea - 1 : fn->start_ea));
                if (!start_norm.ok)
                    continue;
                qstring name;
                get_func_name(&name, fn->start_ea);
                json f;
                f["function_id"] = module_id + ":" + hex_u64(start_norm.address.rva);
                f["module_id"] = module_id;
                f["start"] = canonical_address_from_chain(start_norm.address);
                f["end"] = end_norm.ok ? canonical_address_from_chain(end_norm.address) : json(nullptr);
                f["ea_hint"] = hex_u64(static_cast<std::uint64_t>(fn->start_ea));
                f["name"] = name.c_str();
                f["flags"] = static_cast<std::uint64_t>(fn->flags);
                f["size"] = static_cast<std::uint64_t>(fn->end_ea - fn->start_ea);
                f["does_return"] = (fn->flags & FUNC_NORET) == 0;
                f["is_thunk"] = (fn->flags & FUNC_THUNK) != 0;
                const std::size_t function_size = fn->end_ea > fn->start_ea ? static_cast<std::size_t>(fn->end_ea - fn->start_ea) : 0;
                const std::size_t signature_len = std::min<std::size_t>(function_size, 64);
                if (signature_len > 0 && is_loaded(fn->start_ea))
                {
                    std::vector<uchar> bytes(signature_len);
                    const ssize_t got = get_bytes(bytes.data(), static_cast<ssize_t>(bytes.size()), fn->start_ea);
                    if (got > 0)
                    {
                        bytes.resize(static_cast<std::size_t>(got));
                        json sig;
                        sig["function_id"] = f["function_id"];
                        sig["module_id"] = module_id;
                        sig["start"] = f["start"];
                        sig["byte_count"] = bytes.size();
                        sig["bytes_hex"] = bytes_hex(bytes);
                        sig["flags"] = f["flags"];
                        sig["size"] = f["size"];
                        sig["content_hash"] = stable_hash_hex(sig["bytes_hex"].get<std::string>());
                        f["signature"] = sig;
                        result["signatures"].push_back(sig);
                    }
                }
                if ((fn->flags & FUNC_THUNK) != 0)
                {
                    ea_t fptr = BADADDR;
                    ea_t target = calc_thunk_func_target(fn, &fptr);
                    if (target != BADADDR)
                    {
                        auto tnorm = vuln::chain::normalize_ea(corpus, static_cast<std::uint64_t>(target));
                        f["thunk_target"] = tnorm.ok ? canonical_address_from_chain(tnorm.address) : json::object({{"ea_hint", hex_u64(static_cast<std::uint64_t>(target))}, {"confidence", "unresolved"}});
                    }
                    if (fptr != BADADDR)
                        f["thunk_function_pointer_ea"] = hex_u64(static_cast<std::uint64_t>(fptr));
                }
                result["functions"].push_back(std::move(f));
                func_item_iterator_t fii(fn);
                for (bool ok = fii.first(); ok && result["local_call_edges"].size() < max_edges; ok = fii.next_head())
                {
                    const ea_t item = fii.current();
                    xrefblk_t xb;
                    for (bool xok = xb.first_from(item, XREF_FAR); xok && result["local_xrefs"].size() < max_edges; xok = xb.next_from())
                    {
                        auto from_norm = vuln::chain::normalize_ea(corpus, static_cast<std::uint64_t>(item));
                        auto to_norm = vuln::chain::normalize_ea(corpus, static_cast<std::uint64_t>(xb.to));
                        json xref;
                        xref["xref_id"] = "xref_" + stable_hash_hex(module_id + std::to_string(item) + std::to_string(xb.to) + std::to_string(xb.type) + std::to_string(xb.iscode));
                        xref["module_id"] = module_id;
                        xref["from"] = from_norm.ok ? canonical_address_from_chain(from_norm.address) : json::object({{"ea_hint", hex_u64(static_cast<std::uint64_t>(item))}, {"confidence", "unresolved"}});
                        xref["to"] = to_norm.ok ? canonical_address_from_chain(to_norm.address) : json::object({{"ea_hint", hex_u64(static_cast<std::uint64_t>(xb.to))}, {"confidence", "unresolved"}});
                        xref["xref_type"] = static_cast<int>(xb.type);
                        xref["is_code"] = xb.iscode;
                        xref["user"] = xb.user;
                        if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
                            xref["kind"] = "local_direct_call";
                        else if (!xb.iscode && xb.type == dr_R)
                            xref["kind"] = "data_read";
                        else if (!xb.iscode && xb.type == dr_W)
                            xref["kind"] = "data_write";
                        else if (!xb.iscode && xb.type == dr_O)
                            xref["kind"] = "data_offset";
                        else
                            xref["kind"] = xb.iscode ? "code_xref" : "data_xref";
                        xref["confidence"] = to_norm.ok ? "exact" : "unresolved";
                        if (xref.value("kind", std::string()) == "local_direct_call" && result["local_call_edges"].size() < max_edges)
                        {
                            json edge = xref;
                            edge["edge_id"] = "local_" + stable_hash_hex(module_id + std::to_string(item) + std::to_string(xb.to) + std::to_string(xb.type));
                            result["local_call_edges"].push_back(edge);
                        }
                        result["local_xrefs"].push_back(std::move(xref));
                    }
                }
            }
            if (qty > end || result["local_call_edges"].size() >= max_edges || result["local_xrefs"].size() >= max_edges)
                result["truncated"] = true;
            result["function_count_total"] = static_cast<std::uint64_t>(qty);
            result["function_count_indexed"] = result["functions"].size();
            result["local_edge_count"] = result["local_call_edges"].size();
            result["local_xref_count"] = result["local_xrefs"].size();
            result["signature_count"] = result["signatures"].size();
            result["content_hash"] = stable_hash_hex(result["functions"].dump() + result["local_call_edges"].dump() + result["local_xrefs"].dump() + result["signatures"].dump());
            return 1;
        }
    } req;
    req.max_functions = max_functions;
    req.max_edges = max_edges;
    if (execute_sync(req, MFF_READ) <= 0)
        return json::object({{"schema", k_index_schema}, {"error", "execute_sync_failed"}});
    return req.result;
}

project_io_result_t persist_page_series(const std::string& project_id,
                                        const std::string& module_id,
                                        const std::string& family,
                                        const json& items,
                                        std::size_t page_size,
                                        const json& metadata = json::object())
{
    if (!items.is_array())
        return make_error("index_page_input_invalid", "index page input must be an array", {{"family", family}});
    std::string dir_error;
    if (!ensure_project_dirs(project_id, &dir_error))
        return make_error("project_dir_error", "project directories could not be created", {{"path", dir_error}});
    std::filesystem::create_directories(page_family_dir(project_id, family));
    const std::size_t safe_page_size = std::max<std::size_t>(1, page_size);
    const std::size_t total = items.size();
    const std::size_t page_count = total == 0 ? 1 : ((total + safe_page_size - 1) / safe_page_size);
    json manifest;
    manifest["schema"] = "aida.multibinary.index.pages";
    manifest["version"] = k_project_schema_version;
    manifest["project_id"] = project_id;
    manifest["module_id"] = module_id;
    manifest["family"] = family_dir_name(family);
    manifest["item_count"] = total;
    manifest["page_size"] = safe_page_size;
    manifest["page_count"] = page_count;
    manifest["generated_at_ms"] = now_ms();
    manifest["pages"] = json::array();
    manifest["metadata"] = metadata.is_object() ? metadata : json::object();
    for (std::size_t page = 0; page < page_count; ++page)
    {
        const std::size_t begin = page * safe_page_size;
        const std::size_t end = std::min<std::size_t>(begin + safe_page_size, total);
        json page_doc;
        page_doc["schema"] = "aida.multibinary.index.page";
        page_doc["version"] = k_project_schema_version;
        page_doc["project_id"] = project_id;
        page_doc["module_id"] = module_id;
        page_doc["family"] = family_dir_name(family);
        page_doc["page_index"] = page;
        page_doc["page_count"] = page_count;
        page_doc["cursor"] = page_cursor(family, module_id, page);
        page_doc["next_cursor"] = page + 1 < page_count ? json(page_cursor(family, module_id, page + 1)) : json(nullptr);
        page_doc["items"] = json::array();
        for (std::size_t i = begin; i < end; ++i)
            page_doc["items"].push_back(items[i]);
        page_doc["item_count"] = page_doc["items"].size();
        page_doc["content_hash"] = stable_hash_hex(page_doc["items"].dump());
        std::vector<std::uint8_t> bytes = json::to_msgpack(page_doc);
        std::string error;
        const std::string path = page_file_path(project_id, module_id, family, page);
        if (!write_binary_file(path, bytes, &error))
            return make_error("index_page_write_failed", "index page could not be written", {{"path", path}, {"error", error}, {"family", family}});
        manifest["pages"].push_back({
            {"page_index", page},
            {"path", path},
            {"cursor", page_doc["cursor"]},
            {"next_cursor", page_doc["next_cursor"]},
            {"item_count", page_doc["item_count"]},
            {"content_hash", page_doc["content_hash"]}
        });
    }
    manifest["content_hash"] = stable_hash_hex(manifest["pages"].dump());
    std::vector<std::uint8_t> manifest_bytes = json::to_msgpack(manifest);
    std::string error;
    const std::string manifest_path = page_manifest_path(project_id, module_id, family);
    if (!write_binary_file(manifest_path, manifest_bytes, &error))
        return make_error("index_page_manifest_write_failed", "index page manifest could not be written", {{"path", manifest_path}, {"error", error}, {"family", family}});
    return make_ok({{"project_id", project_id}, {"module_id", module_id}, {"family", family_dir_name(family)}, {"manifest_path", manifest_path}, {"manifest", manifest}});
}

project_io_result_t load_page_manifest(const std::string& project_id, const std::string& module_id, const std::string& family)
{
    const std::string path = page_manifest_path(project_id, module_id, family);
    std::vector<std::uint8_t> bytes;
    std::string error;
    if (!read_binary_file(path, bytes, &error))
        return make_error("index_page_manifest_not_found", "index page manifest could not be read", {{"project_id", project_id}, {"module_id", module_id}, {"family", family_dir_name(family)}, {"path", path}, {"error", error}});
    try
    {
        return make_ok({{"project_id", project_id}, {"module_id", module_id}, {"family", family_dir_name(family)}, {"manifest_path", path}, {"manifest", json::from_msgpack(bytes)}});
    }
    catch (const std::exception& ex)
    {
        return make_error("index_page_manifest_corrupt", "index page manifest msgpack could not be decoded", {{"path", path}, {"error", ex.what()}});
    }
}

ea_t ea_from_summary_start(const json& item)
{
    const json start = item.value("start", json::object());
    if (start.is_object())
    {
        if (start.contains("ea_hint") && !start["ea_hint"].is_null())
        {
            const std::uint64_t ea = parse_u64_loose(start["ea_hint"]);
            if (ea != 0)
                return static_cast<ea_t>(ea);
        }
        if (start.contains("rva"))
        {
            const std::uint64_t rva = parse_u64_loose(start["rva"]);
            const ea_t base = get_imagebase();
            if (base != BADADDR && base != 0)
                return static_cast<ea_t>(base + rva);
        }
    }
    if (item.contains("ea_hint") && !item["ea_hint"].is_null())
        return static_cast<ea_t>(parse_u64_loose(item["ea_hint"]));
    return BADADDR;
}

bool is_conditional_branch(const insn_t& ins)
{
    switch (ins.itype)
    {
    case NN_ja: case NN_jae: case NN_jb: case NN_jbe:
    case NN_jc: case NN_jcxz: case NN_jecxz: case NN_jrcxz:
    case NN_je: case NN_jg: case NN_jge: case NN_jl:
    case NN_jle: case NN_jna: case NN_jnae: case NN_jnb:
    case NN_jnbe: case NN_jnc: case NN_jne: case NN_jng:
    case NN_jnge: case NN_jnl: case NN_jnle: case NN_jno:
    case NN_jnp: case NN_jns: case NN_jnz: case NN_jo:
    case NN_jp: case NN_jpe: case NN_jpo: case NN_js:
    case NN_jz:
        return true;
    default:
        return false;
    }
}

std::vector<ea_t> collect_branch_eas(func_t* fn, std::size_t max_items)
{
    std::vector<ea_t> out;
    if (fn == nullptr)
        return out;
    func_item_iterator_t fii(fn);
    for (bool ok = fii.first(); ok && out.size() < max_items; ok = fii.next_head())
    {
        insn_t ins;
        if (decode_insn(&ins, fii.current()) > 0 && is_conditional_branch(ins))
            out.push_back(fii.current());
    }
    return out;
}

json decompiler_summary(func_t* fn)
{
    json out;
    out["status"] = "inconclusive";
    out["line_count"] = 0;
    out["pseudocode_hash"] = "";
    if (fn == nullptr)
    {
        out["reason"] = "function_missing";
        return out;
    }
    if (!init_hexrays_plugin())
    {
        out["reason"] = "hexrays_unavailable";
        return out;
    }
    try
    {
        hexrays_failure_t hf;
        cfuncptr_t cf = decompile_func(fn, &hf, DECOMP_NO_WAIT | DECOMP_WARNINGS);
        if (cf == nullptr)
        {
            out["reason"] = std::string("decompile_failed:") + hf.desc().c_str();
            return out;
        }
        const strvec_t& lines = cf->get_pseudocode();
        std::string normalized;
        normalized.reserve(lines.size() * 80);
        for (size_t i = 0; i < lines.size(); ++i)
        {
            qstring stripped;
            tag_remove(&stripped, lines[i].line);
            normalized.append(stripped.c_str());
            normalized.push_back('\n');
        }
        out["status"] = "proven";
        out["line_count"] = lines.size();
        out["pseudocode_hash"] = stable_hash_hex(normalized);
        hexwarns_t& warnings = cf->get_warnings();
        out["warning_count"] = warnings.size();
        out["warnings"] = json::array();
        for (const auto& warning : warnings)
            out["warnings"].push_back(std::string(warning.text.c_str()));
        return out;
    }
    catch (const vd_failure_t&)
    {
        out["reason"] = "decompile_exception";
        return out;
    }
    catch (...)
    {
        out["reason"] = "decompile_unknown_exception";
        return out;
    }
}

json microcode_summary(func_t* fn)
{
    json out;
    out["status"] = "inconclusive";
    out["maturity"] = "lvars";
    out["block_count"] = 0;
    out["instruction_count"] = 0;
    out["call_count"] = 0;
    out["memory_op_count"] = 0;
    if (fn == nullptr)
    {
        out["reason"] = "function_missing";
        return out;
    }
    auto handle = vuln::microcode::generate(fn->start_ea, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
    {
        out["reason"] = "microcode_generation_failed";
        return out;
    }
    int blocks = 0;
    int insns = 0;
    int calls = 0;
    int memops = 0;
    mba_t& mba = *handle->mba;
    for (int bi = 0; bi < mba.qty; ++bi)
    {
        mblock_t* blk = mba.get_mblock(bi);
        if (blk == nullptr)
            continue;
        ++blocks;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            ++insns;
            if (m->opcode == m_call || m->opcode == m_icall)
                ++calls;
            if (m->l.t == mop_S || m->l.t == mop_v || m->l.t == mop_d || m->r.t == mop_S || m->r.t == mop_v || m->r.t == mop_d || m->d.t == mop_S || m->d.t == mop_v || m->d.t == mop_d)
                ++memops;
        }
    }
    out["status"] = "proven";
    out["block_count"] = blocks;
    out["instruction_count"] = insns;
    out["call_count"] = calls;
    out["memory_op_count"] = memops;
    out["mba_hash"] = stable_hash_hex(out.dump());
    return out;
}

json smt_summary(func_t* fn)
{
    json out;
    out["status"] = "inconclusive";
    out["branch_count"] = 0;
    out["smt_result"] = "unknown";
    if (fn == nullptr)
    {
        out["reason"] = "function_missing";
        return out;
    }
    std::vector<ea_t> branches = collect_branch_eas(fn, 16);
    out["branch_count"] = branches.size();
    out["branch_eas"] = json::array();
    for (ea_t ea : branches)
        out["branch_eas"].push_back(hex_u64(static_cast<std::uint64_t>(ea)));
    if (branches.empty())
    {
        out["status"] = "proven";
        out["reason"] = "no_branch_constraints";
        out["smt_result"] = "sat";
        return out;
    }
    auto solved = vuln::verify::engine().check_path_satisfiability(branches, 250);
    out["smt_result"] = vuln::smt::result_str(solved.result);
    out["reason"] = solved.reason;
    out["solve_ms"] = solved.solve_ms;
    if (solved.result == vuln::smt::result_t::sat)
        out["status"] = "proven";
    else if (solved.result == vuln::smt::result_t::unsat)
        out["status"] = "refuted";
    else
        out["status"] = "inconclusive";
    return out;
}

json build_deep_summary_record(const vuln::chain::corpus_record_t& corpus, const json& item, const std::string& page_cursor_value)
{
    json out = item;
    out["summary_schema"] = "aida.multibinary.deep_summary";
    out["summary_level"] = "decompiler_microcode_smt";
    out["materialized_at_ms"] = now_ms();
    out["cache"] = json::object({
        {"page_cursor", page_cursor_value},
        {"function_id", item.value("function_id", std::string())},
        {"signature_hash", item.value("signature", json::object()).value("content_hash", std::string())},
        {"module_id", corpus.identity.corpus_id},
        {"hexrays_version", init_hexrays_plugin() ? std::string(get_hexrays_version()) : std::string()}
    });
    out["dependencies"] = json::object({
        {"module_id", corpus.identity.corpus_id},
        {"input_sha256", corpus.identity.input_sha256},
        {"auto_analysis_ok", auto_is_ok()},
        {"function_signature", item.value("signature", json(nullptr))}
    });
    const ea_t ea = ea_from_summary_start(item);
    func_t* fn = ea == BADADDR ? nullptr : get_func(ea);
    if (fn != nullptr && fn->start_ea != ea)
        fn = get_func(fn->start_ea);
    out["decompiler"] = decompiler_summary(fn);
    out["microcode"] = microcode_summary(fn);
    out["smt"] = smt_summary(fn);
    const std::string decomp_status = out["decompiler"].value("status", std::string("inconclusive"));
    const std::string micro_status = out["microcode"].value("status", std::string("inconclusive"));
    const std::string smt_status = out["smt"].value("status", std::string("inconclusive"));
    if (smt_status == "refuted")
        out["proof_state"] = "refuted";
    else if (decomp_status == "proven" && micro_status == "proven" && smt_status == "proven")
        out["proof_state"] = "proven";
    else
        out["proof_state"] = "inconclusive";
    out["evidence_status"] = out["proof_state"];
    out["content_hash"] = stable_hash_hex(out.dump());
    return out;
}

json materialize_summary_page_for_current_idb(const std::string& module_id, const json& page, std::size_t max_deep_summaries)
{
    struct request_t : public exec_request_t
    {
        std::string module_id;
        std::size_t max_deep_summaries = 0;
        json page = json::object();
        json result = json::object();
        ssize_t idaapi execute() override
        {
            vuln::chain::corpus_record_t corpus = vuln::chain::snapshot_current_idb_corpus();
            result = page;
            result["lazy_summary_materialized"] = false;
            result["lazy_summary_state"] = "inconclusive";
            if (module_id != corpus.identity.corpus_id)
            {
                result["lazy_summary_reason"] = "requested_module_not_current_idb";
                result["current_module_id"] = corpus.identity.corpus_id;
                return 1;
            }
            if (!result.contains("items") || !result["items"].is_array())
                return 1;
            bool changed = false;
            const std::string cursor_value = result.value("cursor", std::string());
            std::size_t materialized_count = 0;
            for (json& item : result["items"])
            {
                if (!item.is_object())
                    continue;
                const std::string state = lowercase_ascii(item.value("proof_state", std::string()));
                if (state == "proven" || state == "refuted")
                    continue;
                if (materialized_count >= max_deep_summaries)
                {
                    item["lazy_summary_state"] = "deferred";
                    item["lazy_summary_reason"] = "page_materialization_budget_exhausted";
                    continue;
                }
                item = build_deep_summary_record(corpus, item, cursor_value);
                changed = true;
                ++materialized_count;
            }
            result["lazy_summary_materialized"] = changed;
            result["lazy_summary_state"] = changed ? "ready" : "unchanged";
            result["lazy_summary_materialized_count"] = materialized_count;
            result["lazy_summary_budget"] = max_deep_summaries;
            result["content_hash"] = stable_hash_hex(result["items"].dump());
            return 1;
        }
    } req;
    req.module_id = module_id;
    req.max_deep_summaries = std::max<std::size_t>(1, max_deep_summaries);
    req.page = page;
    if (execute_sync(req, MFF_READ) <= 0)
    {
        json out = page;
        out["lazy_summary_materialized"] = false;
        out["lazy_summary_state"] = "inconclusive";
        out["lazy_summary_reason"] = "execute_sync_failed";
        return out;
    }
    return req.result;
}

bool write_msgpack_json(const std::string& path, const json& value, std::string* error)
{
    std::vector<std::uint8_t> bytes = json::to_msgpack(value);
    return write_binary_file(path, bytes, error);
}

json persist_catalog_pages(const std::string& project_id,
                           const json& module,
                           const json& catalog,
                           const json& resolver_evidence,
                           std::size_t page_size,
                           std::size_t max_deep_summaries)
{
    const std::string module_id = canonical_module_id_from_json(module);
    json manifests = json::object();
    auto persist = [&](const std::string& family, const json& items, const json& metadata = json::object()) {
        project_io_result_t r = persist_page_series(project_id, module_id, family, items.is_array() ? items : json::array(), page_size, metadata);
        manifests[family_dir_name(family)] = r.ok ? r.data.value("manifest", json::object()) : json::object({{"error_code", r.error_code}, {"error_message", r.error_message}});
    };
    persist("functions", catalog.value("functions", json::array()), {{"source", "function_catalog"}});
    persist("xrefs", catalog.value("local_xrefs", json::array()), {{"source", "xrefblk_first_from"}});
    persist("signatures", catalog.value("signatures", json::array()), {{"source", "get_bytes"}});
    persist("imports", normalize_imports(module), {{"source", "enum_import_names"}});
    persist("exports", normalize_exports(module), {{"source", "entry_table"}});
    persist("syscall_services", module.value("syscall_services", json::array()), {{"source", "ida_named_service_tables"}});
    persist("dispatch_tables", resolver_evidence.value("dispatch_tables", json::array()), {{"source", "resolver_evidence"}});
    persist("callbacks", resolver_evidence.value("callback_registrations", json::array()), {{"source", "resolver_evidence"}});
    persist("globals", resolver_evidence.value("global_pointers", json::array()), {{"source", "resolver_evidence"}});
    json summaries = json::array();
    for (const json& fn : catalog.value("functions", json::array()))
    {
        json summary;
        summary["function_id"] = fn.value("function_id", std::string());
        summary["module_id"] = module_id;
        summary["start"] = fn.value("start", json::object());
        summary["name"] = fn.value("name", std::string());
        summary["does_return"] = fn.value("does_return", true);
        summary["is_thunk"] = fn.value("is_thunk", false);
        summary["thunk_target"] = fn.value("thunk_target", json(nullptr));
        summary["signature"] = fn.value("signature", json(nullptr));
        summary["summary_level"] = "catalog_seed";
        summary["proof_state"] = "lazy_pending";
        summary["evidence_status"] = "inconclusive";
        summary["cache"] = json::object({
            {"module_id", module_id},
            {"function_id", summary["function_id"]},
            {"signature_hash", summary["signature"].is_object() ? summary["signature"].value("content_hash", std::string()) : std::string()},
            {"materialization", "load_index_page:summaries"}
        });
        summaries.push_back(std::move(summary));
    }
    persist("summaries", summaries, {{"source", "bounded_function_catalog"}, {"lazy_materializer", "decompiler_microcode_smt"}, {"max_deep_summaries_per_page", max_deep_summaries}});
    return manifests;
}

}

index_build_options_t index_options_from_json(const json& value)
{
    index_build_options_t out;
    if (!value.is_object())
        return out;
    out.force = value.value("force", false);
    out.max_functions = static_cast<std::size_t>(std::min<std::uint64_t>(value.value("max_functions", static_cast<std::uint64_t>(out.max_functions)), 1000000ull));
    out.max_edges = static_cast<std::size_t>(std::min<std::uint64_t>(value.value("max_edges", static_cast<std::uint64_t>(out.max_edges)), 5000000ull));
    out.max_imports = static_cast<std::size_t>(std::min<std::uint64_t>(value.value("max_imports", static_cast<std::uint64_t>(out.max_imports)), 1000000ull));
    out.max_exports = static_cast<std::size_t>(std::min<std::uint64_t>(value.value("max_exports", static_cast<std::uint64_t>(out.max_exports)), 1000000ull));
    out.page_size = static_cast<std::size_t>(std::min<std::uint64_t>(value.value("page_size", static_cast<std::uint64_t>(out.page_size)), 100000ull));
    out.max_deep_summaries = static_cast<std::size_t>(std::min<std::uint64_t>(value.value("max_deep_summaries", static_cast<std::uint64_t>(out.max_deep_summaries)), 100000ull));
    return out;
}

project_io_result_t build_current_module_index(const std::string& requested_project_id,
                                               const json& indices,
                                               const index_build_options_t& options)
{
    const json inventory = current_idb_inventory(true, true, true, std::max(options.max_imports, options.max_exports));
    if (inventory.contains("error"))
        return make_error("inventory_failed", "current IDB inventory capture failed", inventory);
    const std::string project_id = requested_project_id.empty() ? default_project_id_for_current_idb() : sanitize_id_component(requested_project_id);
    json module = normalize_module_record(inventory["module"]);
    const std::string module_id = canonical_module_id_from_json(module);
    project_io_result_t saved_project = bind_current_inventory_to_project(project_id, inventory, json::object(), {{"force_lock", options.force}});
    if (!saved_project.ok)
        return saved_project;
    json catalog = capture_function_catalog(options.max_functions, options.max_edges);
    if (catalog.contains("error"))
        return make_error("function_catalog_failed", "function catalog capture failed", catalog);
    catalog["requested_indices"] = indices.is_array() ? indices : json::array({"identity", "segments", "imports", "exports", "functions", "local_edges", "cross_edges"});
    catalog["project_id"] = project_id;
    json resolver_evidence = derive_resolver_evidence(module, catalog, std::max<std::size_t>(1, options.page_size));
    json source_trace_evidence = capture_source_trace_evidence(module, catalog, std::max<std::size_t>(1, options.page_size));
    if (source_trace_evidence.contains("error"))
        resolver_evidence["source_trace_error"] = source_trace_evidence;
    else
        merge_resolver_evidence(resolver_evidence, source_trace_evidence, {"dispatch_tables", "ioctl_dispatchers", "callback_registrations", "global_pointers", "guarded_indirects", "indirect_calls"}, std::max<std::size_t>(1, options.page_size));
    module["dispatch_tables"] = resolver_evidence.value("dispatch_tables", json::array());
    module["ioctl_dispatchers"] = resolver_evidence.value("ioctl_dispatchers", json::array());
    module["callback_registrations"] = resolver_evidence.value("callback_registrations", json::array());
    module["global_pointers"] = resolver_evidence.value("global_pointers", json::array());
    module["guarded_indirects"] = resolver_evidence.value("guarded_indirects", json::array());
    module["indirect_calls"] = resolver_evidence.value("indirect_calls", json::array());
    module["syscall_services"] = resolver_evidence.value("syscall_services", json::array());
    module["syscall_service_extraction"] = resolver_evidence.value("syscall_service_extraction", json::object({{"state", "unavailable"}, {"proof_state", "inconclusive"}, {"reason", "source_trace_unavailable"}}));
    catalog["resolver_evidence"] = resolver_evidence;
    catalog["syscall_services"] = module["syscall_services"];
    catalog["syscall_service_extraction"] = module["syscall_service_extraction"];
    catalog["page_manifests"] = persist_catalog_pages(project_id, module, catalog, resolver_evidence, options.page_size, options.max_deep_summaries);
    project_io_result_t catalog_saved = save_function_catalog(project_id, module_id, catalog);
    if (!catalog_saved.ok)
        return catalog_saved;
    module["index_generation"] = catalog.value("content_hash", std::string());
    module["index_status"] = catalog.value("truncated", false) ? "partial" : "ready";
    module["function_catalog"] = json::object({
        {"path", function_catalog_path(project_id, module_id)},
        {"content_hash", catalog.value("content_hash", std::string())},
        {"function_count_indexed", catalog.value("function_count_indexed", static_cast<std::size_t>(0))},
        {"local_edge_count", catalog.value("local_edge_count", static_cast<std::size_t>(0))},
        {"local_xref_count", catalog.value("local_xref_count", static_cast<std::size_t>(0))},
        {"signature_count", catalog.value("signature_count", static_cast<std::size_t>(0))},
        {"page_manifests", catalog["page_manifests"]}
    });
    project_io_result_t wrote_module = write_module_record(project_id, module);
    if (!wrote_module.ok)
        return wrote_module;
    project_io_result_t cross = resolve_project_cross_edges(project_id);
    if (!cross.ok)
        return cross;
    json result;
    result["project_id"] = project_id;
    result["module_id"] = module_id;
    result["module"] = module;
    result["function_catalog"] = catalog_saved.data;
    result["cross_edges"] = cross.data;
    result["status"] = module["index_status"];
    result["auto_analysis_ok"] = inventory.value("auto_analysis_ok", false);
    save_netnode_blob("$ AiDA.multibinary.module", 'M', module);
    save_netnode_blob("$ AiDA.multibinary.functions", 'F', catalog);
    save_netnode_blob("$ AiDA.multibinary.edges", 'E', cross.data);
    return make_ok(result);
}

project_io_result_t load_function_catalog(const std::string& project_id, const std::string& module_id)
{
    const std::string path = function_catalog_path(project_id, module_id);
    std::vector<std::uint8_t> bytes;
    std::string error;
    if (!read_binary_file(path, bytes, &error))
        return make_error("function_catalog_not_found", "function catalog could not be read", {{"project_id", project_id}, {"module_id", module_id}, {"path", path}, {"error", error}});
    try
    {
        json catalog = json::from_msgpack(bytes);
        return make_ok({{"project_id", project_id}, {"module_id", module_id}, {"path", path}, {"catalog", catalog}});
    }
    catch (const std::exception& ex)
    {
        return make_error("function_catalog_corrupt", "function catalog msgpack could not be decoded", {{"project_id", project_id}, {"module_id", module_id}, {"path", path}, {"error", ex.what()}});
    }
}

project_io_result_t save_function_catalog(const std::string& project_id,
                                          const std::string& module_id,
                                          const json& catalog)
{
    std::string dir_error;
    if (!ensure_project_dirs(project_id, &dir_error))
        return make_error("project_dir_error", "project directories could not be created", {{"path", dir_error}});
    const std::string path = function_catalog_path(project_id, module_id);
    std::vector<std::uint8_t> bytes = json::to_msgpack(catalog);
    std::string error;
    if (!write_binary_file(path, bytes, &error))
        return make_error("function_catalog_write_failed", "function catalog could not be written", {{"project_id", project_id}, {"module_id", module_id}, {"path", path}, {"error", error}});
    return make_ok({{"project_id", project_id}, {"module_id", module_id}, {"path", path}, {"bytes", bytes.size()}, {"content_hash", catalog.value("content_hash", stable_hash_hex(catalog.dump()))}});
}

project_io_result_t resolve_project_cross_edges(const std::string& project_id)
{
    project_io_result_t modules_loaded = load_project_modules(project_id);
    if (!modules_loaded.ok)
        return modules_loaded;
    json modules = modules_loaded.data["modules"];
    module_maps_t maps = build_module_maps(modules);
    json edges;
    edges["schema"] = k_cross_edges_schema;
    edges["version"] = k_project_schema_version;
    edges["project_id"] = project_id;
    edges["generated_at_ms"] = now_ms();
    edges["edges"] = json::array();
    edges["unresolved"] = json::array();
    edges["ambiguous"] = json::array();
    for (const json& module : maps.modules)
    {
        const std::string source_id = canonical_module_id_from_json(module);
        if (module.value("availability", std::string()) == "missing")
            continue;
        for (const json& imp : normalize_imports(module))
        {
            if (!imp.is_object())
                continue;
            json edge = resolve_import_against_maps(maps, module, imp, 0);
            edge["edge_id"] = "cross_" + stable_hash_hex(source_id + imp.dump());
            edge["source_module_id"] = source_id;
            append_edge_by_state(edges, edge);
            const std::string sym = import_symbol_name(imp);
            if (is_syscall_symbol(sym))
            {
                json syscall_edge = resolve_syscall_against_maps(maps, module, imp);
                syscall_edge["edge_id"] = "syscall_" + stable_hash_hex(source_id + imp.dump());
                append_edge_by_state(edges, syscall_edge);
            }
            if (is_guard_dispatch_symbol(sym))
                append_edge_by_state(edges, make_guard_dispatch_gap(module, imp));
        }
        append_declared_edges(edges, module, "dispatch_tables", "driver_dispatch_table");
        append_declared_edges(edges, module, "ioctl_dispatchers", "ioctl_dispatch");
        append_declared_edges(edges, module, "callback_registrations", "callback_registration");
        append_declared_edges(edges, module, "global_pointers", "global_function_pointer");
        append_declared_edges(edges, module, "guarded_indirects", "guarded_indirect_call");
        append_declared_edges(edges, module, "indirect_calls", "indirect_call");
    }
    edges["resolved_count"] = edges["edges"].size();
    edges["ambiguous_count"] = edges["ambiguous"].size();
    edges["unresolved_count"] = edges["unresolved"].size();
    edges["content_hash"] = stable_hash_hex(edges["edges"].dump() + edges["ambiguous"].dump() + edges["unresolved"].dump());
    std::vector<std::uint8_t> bytes = json::to_msgpack(edges);
    std::string error;
    if (!write_binary_file(cross_edges_path(project_id), bytes, &error))
        return make_error("cross_edges_write_failed", "cross-edge graph could not be written", {{"project_id", project_id}, {"path", cross_edges_path(project_id)}, {"error", error}});
    json all_cross = json::array();
    for (const json& edge : edges["edges"])
        all_cross.push_back(edge);
    for (const json& edge : edges["ambiguous"])
        all_cross.push_back(edge);
    for (const json& edge : edges["unresolved"])
        all_cross.push_back(edge);
    project_io_result_t cross_pages = persist_page_series(project_id, "project", "cross_edges", all_cross, 4096, {{"source", "resolve_project_cross_edges"}});
    if (cross_pages.ok)
        edges["page_manifest"] = cross_pages.data.value("manifest", json::object());
    return make_ok({{"project_id", project_id}, {"path", cross_edges_path(project_id)}, {"graph", edges}, {"bytes", bytes.size()}});
}

project_io_result_t load_project_cross_edges(const std::string& project_id)
{
    std::vector<std::uint8_t> bytes;
    std::string error;
    const std::string path = cross_edges_path(project_id);
    if (!read_binary_file(path, bytes, &error))
        return make_error("cross_edges_not_found", "cross-edge graph could not be read", {{"project_id", project_id}, {"path", path}, {"error", error}});
    try
    {
        return make_ok({{"project_id", project_id}, {"path", path}, {"graph", json::from_msgpack(bytes)}});
    }
    catch (const std::exception& ex)
    {
        return make_error("cross_edges_corrupt", "cross-edge graph msgpack could not be decoded", {{"project_id", project_id}, {"path", path}, {"error", ex.what()}});
    }
}

project_io_result_t resolve_project_reference(const std::string& project_id, const json& reference)
{
    project_io_result_t modules_loaded = load_project_modules(project_id);
    if (!modules_loaded.ok)
        return modules_loaded;
    module_maps_t maps = build_module_maps(modules_loaded.data["modules"]);
    if (reference.contains("import") && reference["import"].is_object())
    {
        std::string source_id = reference.value("source_module_id", std::string());
        json source = source_id.empty() || maps.by_id.find(source_id) == maps.by_id.end() ? json::object() : maps.by_id[source_id];
        json resolution = resolve_import_against_maps(maps, source, reference["import"], 0);
        return make_ok({{"project_id", project_id}, {"reference", reference}, {"resolution", resolution}});
    }
    json imp;
    if (reference.contains("module"))
        imp["module"] = reference["module"];
    if (reference.contains("module_name"))
        imp["module"] = reference["module_name"];
    if (reference.contains("name"))
        imp["name"] = reference["name"];
    if (reference.contains("symbol"))
        imp["name"] = reference["symbol"];
    if (reference.contains("ordinal"))
        imp["ordinal"] = reference["ordinal"];
    if (imp.contains("module") && (imp.contains("name") || imp.contains("ordinal")))
    {
        json resolution = resolve_import_against_maps(maps, json::object(), imp, 0);
        return make_ok({{"project_id", project_id}, {"reference", reference}, {"resolution", resolution}});
    }
    if ((reference.contains("module_id") || reference.contains("rva"))
        && !reference.contains("kind") && !reference.contains("edge_kind") && !reference.contains("family"))
    {
        const std::string module_id = reference.value("module_id", reference.value("corpus_id", std::string()));
        const std::uint64_t rva = reference.contains("rva") ? parse_u64_loose(reference["rva"]) : 0;
        auto it = maps.by_id.find(module_id);
        if (it == maps.by_id.end())
            return make_ok({{"project_id", project_id}, {"reference", reference}, {"resolution", {{"state", "unresolved"}, {"reason", "module_missing"}, {"module_id", module_id}}}});
        return make_ok({{"project_id", project_id}, {"reference", reference}, {"resolution", {{"state", "resolved"}, {"reason", "module_rva"}, {"target", {{"module_id", module_id}, {"address", canonical_address_json(module_id, rva)}}}, {"confidence", rva == 0 ? "weak_name" : "exact"}}}});
    }
    if (reference.contains("kind") || reference.contains("edge_kind") || reference.contains("family"))
    {
        const std::string kind = lowercase_ascii(reference.value("kind", reference.value("edge_kind", reference.value("family", std::string()))));
        const std::string source = reference.value("source_module_id", reference.value("module_id", std::string()));
        project_io_result_t cross = load_project_cross_edges(project_id);
        if (!cross.ok)
            cross = resolve_project_cross_edges(project_id);
        if (!cross.ok)
            return cross;
        json candidates = json::array();
        const json graph = cross.data.value("graph", json::object());
        for (const char* bucket : {"edges", "ambiguous", "unresolved"})
        {
            for (const json& edge : graph.value(bucket, json::array()))
            {
                if (!kind.empty() && lowercase_ascii(edge.value("kind", std::string())) != kind)
                    continue;
                if (!source.empty() && edge.value("source_module_id", std::string()) != source)
                    continue;
                candidates.push_back(edge);
            }
        }
        json resolution;
        resolution["state"] = candidates.empty() ? "unresolved" : (candidates.size() == 1 && candidates.front().value("state", std::string()) == "resolved" ? "resolved" : "ambiguous");
        resolution["reason"] = candidates.empty() ? "edge_kind_missing" : "edge_kind_match";
        resolution["candidates"] = candidates;
        if (candidates.size() == 1 && candidates.front().contains("target"))
            resolution["target"] = candidates.front()["target"];
        return make_ok({{"project_id", project_id}, {"reference", reference}, {"resolution", resolution}});
    }
    return make_error("reference_unsupported", "reference must contain import, module/name, module/ordinal, or module_id+rva", {{"reference", reference}});
}

project_io_result_t load_index_page(const std::string& project_id,
                                    const std::string& requested_module_id,
                                    const std::string& requested_family,
                                    const std::string& cursor,
                                    std::size_t requested_page_index)
{
    std::string family = requested_family;
    std::string module_id = requested_module_id;
    std::size_t page_index = requested_page_index;
    if (!cursor.empty())
    {
        if (!parse_page_cursor(cursor, family, module_id, page_index))
            return make_error("index_cursor_invalid", "index page cursor is invalid", {{"cursor", cursor}});
    }
    if (family.empty())
        return make_error("index_family_required", "index page family is required");
    if (module_id.empty())
        module_id = "project";
    project_io_result_t manifest = load_page_manifest(project_id, module_id, family);
    if (!manifest.ok)
        return manifest;
    json manifest_doc = manifest.data.value("manifest", json::object());
    if (page_index >= manifest_doc.value("page_count", static_cast<std::size_t>(0)))
        return make_error("index_page_out_of_range", "index page is outside the manifest range", {{"page_index", page_index}, {"manifest", manifest_doc}});
    const std::string path = page_file_path(project_id, module_id, family, page_index);
    std::vector<std::uint8_t> bytes;
    std::string error;
    if (!read_binary_file(path, bytes, &error))
        return make_error("index_page_not_found", "index page could not be read", {{"path", path}, {"error", error}});
    try
    {
        json page = json::from_msgpack(bytes);
        if (family_dir_name(family) == "summaries")
        {
            const std::size_t deep_budget = static_cast<std::size_t>(std::min<std::uint64_t>(
                manifest_doc.value("metadata", json::object()).value("max_deep_summaries_per_page", static_cast<std::uint64_t>(64)),
                100000ull));
            json materialized = materialize_summary_page_for_current_idb(module_id, page, deep_budget);
            const bool changed = materialized.value("lazy_summary_materialized", false)
                && materialized.value("lazy_summary_state", std::string()) == "ready";
            page = std::move(materialized);
            if (changed)
            {
                std::string write_error;
                if (write_msgpack_json(path, page, &write_error))
                {
                    for (json& row : manifest_doc["pages"])
                    {
                        if (row.value("page_index", static_cast<std::size_t>(0)) == page_index)
                        {
                            row["content_hash"] = page.value("content_hash", stable_hash_hex(page.value("items", json::array()).dump()));
                            break;
                        }
                    }
                    manifest_doc["content_hash"] = stable_hash_hex(manifest_doc["pages"].dump());
                    manifest_doc["updated_at_ms"] = now_ms();
                    std::string manifest_error;
                    write_msgpack_json(page_manifest_path(project_id, module_id, family), manifest_doc, &manifest_error);
                }
                else
                {
                    page["lazy_summary_cache_write_error"] = write_error;
                }
            }
        }
        return make_ok({{"project_id", project_id}, {"module_id", module_id}, {"family", family_dir_name(family)}, {"manifest", manifest_doc}, {"page", page}, {"path", path}});
    }
    catch (const std::exception& ex)
    {
        return make_error("index_page_corrupt", "index page msgpack could not be decoded", {{"path", path}, {"error", ex.what()}});
    }
}

project_io_result_t index_page_status(const std::string& project_id, const std::string& module_id)
{
    project_io_result_t modules_loaded = load_project_modules(project_id);
    if (!modules_loaded.ok)
        return modules_loaded;
    const std::vector<std::string> families = {
        "functions", "xrefs", "signatures", "syscall_services", "dispatch_tables", "callbacks", "globals", "imports", "exports", "summaries"
    };
    json out;
    out["project_id"] = project_id;
    out["schema"] = "aida.multibinary.index.page_status";
    out["modules"] = json::array();
    for (const json& module : modules_loaded.data.value("modules", json::array()))
    {
        const std::string id = canonical_module_id_from_json(module);
        if (!module_id.empty() && id != module_id && sanitize_id_component(id) != sanitize_id_component(module_id))
            continue;
        json row;
        row["module_id"] = id;
        row["canonical_name"] = canonical_name_of(module);
        row["families"] = json::object();
        for (const std::string& family : families)
        {
            project_io_result_t manifest = load_page_manifest(project_id, id, family);
            if (manifest.ok)
                row["families"][family] = manifest.data.value("manifest", json::object());
            else
                row["families"][family] = json::object({{"state", "missing"}, {"error_code", manifest.error_code}});
        }
        out["modules"].push_back(std::move(row));
    }
    project_io_result_t cross = load_page_manifest(project_id, "project", "cross_edges");
    out["cross_edges"] = cross.ok ? cross.data.value("manifest", json::object()) : json::object({{"state", "missing"}, {"error_code", cross.error_code}});
    return make_ok(out);
}

project_io_result_t index_status(const std::string& project_id)
{
    project_io_result_t status = project_status(project_id);
    if (!status.ok)
        return status;
    project_io_result_t cross = load_project_cross_edges(project_id);
    status.data["cross_edges"] = cross.ok ? cross.data["graph"] : json::object({{"state", "missing"}, {"error_code", cross.error_code}});
    project_io_result_t pages = index_page_status(project_id);
    status.data["paged_indexes"] = pages.ok ? pages.data : json::object({{"state", "missing"}, {"error_code", pages.error_code}});
    return status;
}

}
}
