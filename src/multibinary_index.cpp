#include "multibinary_index.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <nalt.hpp>
#include <xref.hpp>

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
    return state == "proven" || state == "confirmed" || state == "exact";
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
            if (svc_name != symbol)
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

json persist_catalog_pages(const std::string& project_id,
                           const json& module,
                           const json& catalog,
                           const json& resolver_evidence,
                           std::size_t page_size)
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
        summary["proof_state"] = "summary_only";
        summaries.push_back(std::move(summary));
    }
    persist("summaries", summaries, {{"source", "bounded_function_catalog"}});
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
    module["dispatch_tables"] = resolver_evidence.value("dispatch_tables", json::array());
    module["ioctl_dispatchers"] = resolver_evidence.value("ioctl_dispatchers", json::array());
    module["callback_registrations"] = resolver_evidence.value("callback_registrations", json::array());
    module["global_pointers"] = resolver_evidence.value("global_pointers", json::array());
    module["guarded_indirects"] = resolver_evidence.value("guarded_indirects", json::array());
    module["indirect_calls"] = resolver_evidence.value("indirect_calls", json::array());
    catalog["resolver_evidence"] = resolver_evidence;
    catalog["page_manifests"] = persist_catalog_pages(project_id, module, catalog, resolver_evidence, options.page_size);
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
    const json manifest_doc = manifest.data.value("manifest", json::object());
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
        "functions", "xrefs", "signatures", "dispatch_tables", "callbacks", "globals", "imports", "exports", "summaries"
    };
    json out;
    out["project_id"] = project_id;
    out["schema"] = "aida.multibinary.index.page_status";
    out["modules"] = json::array();
    for (const json& module : modules_loaded.data.value("modules", json::array()))
    {
        const std::string id = canonical_module_id_from_json(module);
        if (!module_id.empty() && id != sanitize_id_component(module_id))
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
