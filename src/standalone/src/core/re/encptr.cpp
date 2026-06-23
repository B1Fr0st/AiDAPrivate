#include "encptr.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <sstream>
#include <thread>

namespace re::encptr
{
namespace
{
std::uint64_t rotl64(std::uint64_t value, unsigned bits)
{
    bits &= 63u;
    return bits == 0 ? value : ((value << bits) | (value >> (64u - bits)));
}

std::uint64_t rotr64(std::uint64_t value, unsigned bits)
{
    bits &= 63u;
    return bits == 0 ? value : ((value >> bits) | (value << (64u - bits)));
}

bool valid_pointer(std::uint32_t pid, std::uint64_t value)
{
    if ((value & 0x7ull) != 0 || value < 0x10000 || value >= 0x0000800000000000ULL)
        return false;
    driver_bridge::memory_region_t region{};
    if (query_region(pid, value, region) && is_readable(region))
        return true;
    std::vector<std::uint8_t> probe;
    return read_bytes(pid, value, 1, probe) && !probe.empty();
}

bool canonical_address(std::uint64_t value)
{
    return value >= 0x10000 && value < 0x0000800000000000ULL;
}

bool canonical_pointer(std::uint64_t value)
{
    return (value & 0x7ull) == 0 && canonical_address(value);
}

int transform_specificity(const std::string& type, std::uint64_t key, bool derived_key)
{
    if (type == "identity" || type == "deref")
        return 1000;
    if (type == "xor_address")
        return derived_key ? 840 : 930;
    if (type == "rol" || type == "ror")
        return 880 - static_cast<int>(std::min<std::uint64_t>(key & 63ull, 32ull));
    if (type == "add" || type == "sub")
    {
        if (key <= 0x1000ull)
            return 780;
        if (key <= 0x100000ull)
            return 720;
        return derived_key ? 560 : 640;
    }
    if (type == "xor")
        return derived_key ? 500 : 620;
    return 400;
}

bool valid_address(std::uint32_t pid, std::uint64_t value)
{
    if (!canonical_address(value))
        return false;
    driver_bridge::memory_region_t region{};
    if (query_region(pid, value, region) && is_readable(region))
        return true;
    std::vector<std::uint8_t> probe;
    return read_bytes(pid, value, 1, probe) && !probe.empty();
}

bool add_signed(std::uint64_t value, std::int64_t delta, std::uint64_t& out)
{
    if (delta < 0)
    {
        const auto magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1ull;
        if (value < magnitude)
            return false;
        out = value - magnitude;
        return true;
    }
    const auto magnitude = static_cast<std::uint64_t>(delta);
    if (value > UINT64_MAX - magnitude)
        return false;
    out = value + magnitude;
    return true;
}

json transform_json(const std::string& type,
                    std::uint64_t key,
                    std::uint64_t raw,
                    std::uint64_t expected,
                    std::uint64_t address,
                    bool has_address,
                    bool derived_key = false)
{
    json out;
    out["transform_type"] = type;
    out["key"] = sa_format_address(key);
    out["raw_value"] = sa_format_address(raw);
    out["expected_next"] = sa_format_address(expected);
    out["specificity"] = transform_specificity(type, key, derived_key);
    out["derived_key"] = derived_key;
    if (has_address)
        out["address_va"] = sa_format_address(address);
    return out;
}

void rank_transform_json(std::vector<json>& items)
{
    for (auto& item : items)
    {
        const std::string type = item.value("transform_type", std::string());
        std::uint64_t key = 0;
        if (item.contains("key"))
            parse_u64_value(item["key"], key);
        const bool derived = item.value("derived_key", false);
        item["specificity"] = transform_specificity(type, key, derived);
    }
    std::stable_sort(items.begin(), items.end(), [](const json& a, const json& b) {
        const int sa = a.value("specificity", 0);
        const int sb = b.value("specificity", 0);
        if (sa != sb)
            return sa > sb;
        return a.value("transform_type", std::string()) < b.value("transform_type", std::string());
    });
    const bool ambiguous = items.size() > 1;
    const int top_specificity = items.empty() ? 0 : items.front().value("specificity", 0);
    std::size_t top_tie_count = 0;
    for (const auto& item : items)
    {
        if (item.value("specificity", 0) == top_specificity)
            ++top_tie_count;
    }
    for (std::size_t i = 0; i < items.size(); ++i)
    {
        items[i]["rank"] = i + 1;
        items[i]["ambiguous"] = ambiguous;
        items[i]["top_specificity"] = top_specificity;
        items[i]["top_tie"] = items[i].value("specificity", 0) == top_specificity;
        items[i]["top_tie_count"] = top_tie_count;
        items[i]["specificity_margin_from_top"] = top_specificity - items[i].value("specificity", 0);
    }
}

std::vector<std::uint64_t> numeric_array_param(const json& params, const char* key)
{
    std::vector<std::uint64_t> out;
    if (!params.contains(key))
        return out;
    if (params[key].is_array())
    {
        for (const auto& item : params[key])
        {
            std::uint64_t value = 0;
            if (parse_u64_value(item, value))
                out.push_back(value);
        }
    }
    else
    {
        std::uint64_t value = 0;
        if (parse_u64_value(params[key], value))
            out.push_back(value);
    }
    return out;
}

std::vector<json> detect_transforms(std::uint64_t raw,
                                    std::uint64_t expected,
                                    std::uint64_t address,
                                    bool has_address,
                                    bool test_xor,
                                    bool test_rol,
                                    bool test_add,
                                    bool allow_derived_keys)
{
    std::vector<json> out;
    if (raw == expected)
        out.push_back(transform_json("identity", 0, raw, expected, address, has_address));
    if (test_xor)
    {
        if (has_address && (raw ^ address) == expected)
            out.push_back(transform_json("xor_address", 0, raw, expected, address, true));
        if (allow_derived_keys && raw != expected)
            out.push_back(transform_json("xor", raw ^ expected, raw, expected, address, has_address, true));
        if (allow_derived_keys && has_address && (raw ^ address) != expected)
            out.push_back(transform_json("xor_address", raw ^ address ^ expected, raw, expected, address, true, true));
    }
    if (test_add)
    {
        if (expected >= raw)
        {
            const std::uint64_t key = expected - raw;
            if (allow_derived_keys || key <= 0x100000ull)
                out.push_back(transform_json("add", key, raw, expected, address, has_address, allow_derived_keys));
        }
        if (raw >= expected)
        {
            const std::uint64_t key = raw - expected;
            if (allow_derived_keys || key <= 0x100000ull)
                out.push_back(transform_json("sub", key, raw, expected, address, has_address, allow_derived_keys));
        }
    }
    if (test_rol)
    {
        for (unsigned bits = 1; bits < 64; ++bits)
        {
            if (rotl64(raw, bits) == expected)
                out.push_back(transform_json("rol", bits, raw, expected, address, has_address));
            if (rotr64(raw, bits) == expected)
                out.push_back(transform_json("ror", bits, raw, expected, address, has_address));
        }
    }
    rank_transform_json(out);
    return out;
}

std::uint64_t apply_transform(const json& hop, std::uint64_t value, std::uint64_t address)
{
    const std::string type = hop.value("type", std::string("deref"));
    std::uint64_t key = 0;
    if (hop.contains("value"))
        parse_u64_value(hop["value"], key);
    else if (hop.contains("key"))
        parse_u64_value(hop["key"], key);
    if (type == "xor")
        return value ^ key;
    if (type == "xor_address")
        return value ^ address ^ key;
    if (type == "add")
        return value + key;
    if (type == "sub")
        return value - key;
    if (type == "rol")
        return rotl64(value, static_cast<unsigned>(key));
    if (type == "ror")
        return rotr64(value, static_cast<unsigned>(key));
    return value;
}

struct transform_candidate_t
{
    std::string type;
    std::uint64_t key = 0;
    std::uint64_t result = 0;
    int specificity = 0;
    bool derived_key = false;
    bool exact_target = false;
};

void add_candidate(std::vector<transform_candidate_t>& out,
                   std::set<std::pair<std::string, std::uint64_t>>& seen,
                   const std::string& type,
                   std::uint64_t key,
                   std::uint64_t result,
                   bool derived_key = false)
{
    if (!canonical_address(result))
        return;
    if (seen.insert({type + ":" + sa_format_address(key), result}).second)
        out.push_back({type, key, result, transform_specificity(type, key, derived_key), derived_key, false});
}

std::vector<std::uint64_t> common_add_sub_keys()
{
    std::vector<std::uint64_t> keys;
    for (std::uint64_t value = 8; value <= 0x100; value += 8)
        keys.push_back(value);
    for (std::uint64_t value = 0x200; value <= 0x1000; value <<= 1)
        keys.push_back(value);
    keys.push_back(0x10000);
    keys.push_back(0x100000);
    return keys;
}

void append_unique_keys(std::vector<std::uint64_t>& dst, const std::vector<std::uint64_t>& src)
{
    for (auto key : src)
    {
        if (std::find(dst.begin(), dst.end(), key) == dst.end())
            dst.push_back(key);
    }
}

void append_unique_key(std::vector<std::uint64_t>& dst, std::uint64_t key)
{
    if (std::find(dst.begin(), dst.end(), key) == dst.end())
        dst.push_back(key);
}

std::vector<transform_candidate_t> build_candidates(std::uint64_t raw,
                                                    std::uint64_t slot_va,
                                                    std::uint64_t final_target,
                                                    const std::vector<std::uint64_t>& xor_keys,
                                                    const std::vector<std::uint64_t>& add_keys,
                                                    const std::vector<std::uint64_t>& sub_keys,
                                                    bool test_xor,
                                                    bool test_rol,
                                                    bool test_add,
                                                    bool auto_derive,
                                                    std::size_t max_candidates)
{
    std::vector<transform_candidate_t> out;
    std::set<std::pair<std::string, std::uint64_t>> seen;
    add_candidate(out, seen, "deref", 0, raw);
    if (test_xor)
    {
        add_candidate(out, seen, "xor_address", 0, raw ^ slot_va);
        for (auto key : xor_keys)
            add_candidate(out, seen, "xor", key, raw ^ key);
        if (auto_derive && final_target != 0)
        {
            add_candidate(out, seen, "xor", raw ^ final_target, final_target, true);
            add_candidate(out, seen, "xor_address", raw ^ slot_va ^ final_target, final_target, true);
        }
    }
    if (test_add)
    {
        std::vector<std::uint64_t> effective_add_keys = add_keys;
        std::vector<std::uint64_t> effective_sub_keys = sub_keys;
        if (auto_derive)
        {
            const auto common = common_add_sub_keys();
            append_unique_keys(effective_add_keys, common);
            append_unique_keys(effective_sub_keys, common);
            if (final_target != 0 && final_target >= raw)
                append_unique_key(effective_add_keys, final_target - raw);
            if (final_target != 0 && raw >= final_target)
                append_unique_key(effective_sub_keys, raw - final_target);
        }
        for (auto key : effective_add_keys)
        {
            if (raw <= UINT64_MAX - key)
                add_candidate(out, seen, "add", key, raw + key, auto_derive && std::find(add_keys.begin(), add_keys.end(), key) == add_keys.end());
        }
        for (auto key : effective_sub_keys)
        {
            if (raw >= key)
                add_candidate(out, seen, "sub", key, raw - key, auto_derive && std::find(sub_keys.begin(), sub_keys.end(), key) == sub_keys.end());
        }
    }
    if (test_rol)
    {
        for (unsigned bits = 1; bits < 64; ++bits)
        {
            add_candidate(out, seen, "rol", bits, rotl64(raw, bits));
            add_candidate(out, seen, "ror", bits, rotr64(raw, bits));
        }
    }
    for (auto& candidate : out)
        candidate.exact_target = final_target != 0 && candidate.result == final_target;
    std::stable_sort(out.begin(), out.end(), [](const transform_candidate_t& a, const transform_candidate_t& b) {
        if (a.exact_target != b.exact_target)
            return a.exact_target;
        if (a.specificity != b.specificity)
            return a.specificity > b.specificity;
        if (a.result != b.result)
            return a.result < b.result;
        return a.type < b.type;
    });
    if (out.size() > max_candidates)
        out.resize(max_candidates);
    return out;
}

json hop_json(const transform_candidate_t& candidate, std::int64_t offset, std::uint64_t raw, std::uint64_t slot_va)
{
    json hop;
    hop["type"] = candidate.type;
    hop["offset"] = offset;
    hop["value"] = sa_format_address(candidate.key);
    hop["key"] = sa_format_address(candidate.key);
    hop["raw_value"] = sa_format_address(raw);
    hop["result"] = sa_format_address(candidate.result);
    hop["slot_va"] = sa_format_address(slot_va);
    hop["specificity"] = candidate.specificity;
    hop["derived_key"] = candidate.derived_key;
    hop["exact_target"] = candidate.exact_target;
    return hop;
}

bool resolve_chain_once(std::uint32_t pid, const json& chain, std::uint64_t& out)
{
    const json* root = &chain;
    if (chain.contains("chain") && chain["chain"].is_object())
        root = &chain["chain"];
    std::uint64_t current = 0;
    if (root->contains("source_va"))
        parse_u64_value((*root)["source_va"], current);
    else if (root->contains("source"))
        parse_u64_value((*root)["source"], current);
    if (current == 0 || !root->contains("hops") || !(*root)["hops"].is_array())
        return false;
    const auto& hops_array = (*root)["hops"];
    for (std::size_t i = 0; i < hops_array.size(); ++i)
    {
        const auto& hop = hops_array[i];
        std::int64_t offset = hop.value("offset", 0ll);
        std::uint64_t slot_va = 0;
        if (!add_signed(current, offset, slot_va))
            return false;
        std::uint64_t raw = 0;
        if (!read_u64(pid, slot_va, raw))
            return false;
        current = apply_transform(hop, raw, slot_va);
        const bool last = i + 1 == hops_array.size();
        if (last ? !valid_address(pid, current) : !valid_pointer(pid, current))
            return false;
    }
    out = current;
    return true;
}

std::string resolver_function_name(const json& params)
{
    return sanitize_identifier(string_param(params, "function_name", "resolve_ptr"), "resolve_ptr");
}

bool select_chain_input(const json& params, json& out, std::string& error)
{
    const json* input = &params;
    if (params.contains("chain") && params["chain"].is_object())
        input = &params["chain"];
    if (input->contains("chain") && (*input)["chain"].is_object())
        input = &(*input)["chain"];
    const std::size_t path_index = static_cast<std::size_t>(numeric_param(params, "path_index", 0, 0, 1024));
    if (input->contains("paths") && (*input)["paths"].is_array())
    {
        const auto& paths = (*input)["paths"];
        if (paths.empty())
        {
            error = "chain.paths is empty.";
            return false;
        }
        if (path_index >= paths.size())
        {
            error = "'path_index' is outside chain.paths.";
            return false;
        }
        if (!paths[path_index].is_object() || !paths[path_index].contains("hops"))
        {
            error = "Selected path is not a chain object.";
            return false;
        }
        out = paths[path_index];
        return true;
    }
    if (input->contains("hops") && (*input)["hops"].is_array())
    {
        out = *input;
        return true;
    }
    error = "A chain object or scan result with paths is required.";
    return false;
}
}

tool_result_t detect_transform(const json& params)
{
    std::uint64_t raw = 0;
    std::uint64_t expected = 0;
    std::uint64_t address = 0;
    if (!parse_address_param(params, "raw_value", raw))
        return tool_result_t::error("'raw_value' is required.");
    if (!parse_address_param(params, "expected_next", expected))
        return tool_result_t::error("'expected_next' is required.");
    const bool has_address = parse_address_param(params, "address_va", address) || parse_address_param(params, "slot_va", address);
    const auto transforms = detect_transforms(raw, expected, address, has_address, true, true, true, true);
    json result;
    if (transforms.empty())
    {
        result["transform_type"] = nullptr;
        return tool_result_t::ok("No transform detected.", result);
    }
    result = transforms.front();
    result["candidates"] = transforms;
    result["candidate_count"] = transforms.size();
    result["ambiguity"] = {
        {"candidate_count", transforms.size()},
        {"top_specificity", result.value("top_specificity", result.value("specificity", 0))},
        {"top_tie_count", result.value("top_tie_count", 1)},
        {"selected_margin_from_top", result.value("specificity_margin_from_top", 0)}
    };
    return tool_result_t::ok(result);
}

tool_result_t scan_chain(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());

    std::uint64_t source = 0;
    std::uint64_t target = 0;
    if (!parse_address_param(params, "source_va", source) || source == 0)
        return tool_result_t::error("'source_va' is required.");
    if (!parse_address_param(params, "target_va", target) || target == 0)
        return tool_result_t::error("'target_va' is required.");

    const std::size_t max_hops = static_cast<std::size_t>(numeric_param(params, "max_hops", 6, 1, 8));
    const bool test_xor = bool_param(params, "test_xor", true);
    const bool test_rol = bool_param(params, "test_rol", true);
    const bool test_add = bool_param(params, "test_add", true);
    const bool auto_derive = bool_param(params, "auto_derive", true);
    const std::int64_t max_offset = static_cast<std::int64_t>(numeric_param(params, "max_offset", 0x400, 0, 0x4000));
    const std::size_t max_paths = static_cast<std::size_t>(numeric_param(params, "max_results", 64, 1, 512));
    const std::size_t max_candidates_per_slot = static_cast<std::size_t>(numeric_param(params, "max_candidates_per_slot", 96, 8, 512));
    std::vector<std::uint64_t> xor_keys = numeric_array_param(params, "xor_keys");
    std::vector<std::uint64_t> add_keys = numeric_array_param(params, "add_keys");
    std::vector<std::uint64_t> sub_keys = numeric_array_param(params, "sub_keys");
    if (params.contains("xor_key"))
    {
        std::uint64_t key = 0;
        if (parse_u64_value(params["xor_key"], key))
            xor_keys.push_back(key);
    }
    if (params.contains("add_key"))
    {
        std::uint64_t key = 0;
        if (parse_u64_value(params["add_key"], key))
            add_keys.push_back(key);
    }
    if (params.contains("sub_key"))
    {
        std::uint64_t key = 0;
        if (parse_u64_value(params["sub_key"], key))
            sub_keys.push_back(key);
    }
    if (!valid_address(scope.pid(), target))
        return tool_result_t::error("'target_va' does not currently resolve to readable memory.");

    struct node_t
    {
        std::uint64_t address = 0;
        json hops = json::array();
    };

    std::vector<node_t> frontier;
    frontier.push_back({source, json::array()});
    std::set<std::pair<std::uint64_t, std::size_t>> visited;
    json paths = json::array();

    for (std::size_t depth = 0; depth < max_hops && !frontier.empty() && paths.size() < max_paths; ++depth)
    {
        std::vector<node_t> next;
        for (const auto& node : frontier)
        {
            for (std::int64_t offset = -max_offset; offset <= max_offset; offset += 8)
            {
                std::uint64_t slot_va = 0;
                if (!add_signed(node.address, offset, slot_va))
                    continue;
                std::uint64_t raw = 0;
                if (!read_u64(scope.pid(), slot_va, raw))
                    continue;
                auto candidates = build_candidates(raw,
                                                   slot_va,
                                                   target,
                                                   xor_keys,
                                                   add_keys,
                                                   sub_keys,
                                                   test_xor,
                                                   test_rol,
                                                   test_add,
                                                   auto_derive,
                                                   max_candidates_per_slot);
                for (const auto& candidate : candidates)
                {
                    if (candidate.result != target)
                        continue;
                    json hops = node.hops;
                    hops.push_back(hop_json(candidate, offset, raw, slot_va));
                    json chain;
                    chain["source_va"] = sa_format_address(source);
                    chain["target_va"] = sa_format_address(target);
                    if (auto module = find_module_for_address(scope.pid(), source))
                    {
                        chain["source_module_name"] = module->name;
                        chain["source_module_base"] = sa_format_address(module->base);
                        chain["source_rva"] = sa_format_address(source - module->base);
                    }
                    chain["hops"] = std::move(hops);
                    chain["hop_count"] = chain["hops"].size();
                    paths.push_back(std::move(chain));
                    if (paths.size() >= max_paths)
                        break;
                }
                if (paths.size() >= max_paths)
                    break;

                for (const auto& candidate : candidates)
                {
                    if (!valid_pointer(scope.pid(), candidate.result))
                        continue;
                    auto key = std::make_pair(candidate.result, depth + 1);
                    if (visited.insert(key).second)
                    {
                        json hops = node.hops;
                        hops.push_back(hop_json(candidate, offset, raw, slot_va));
                        next.push_back({candidate.result, std::move(hops)});
                    }
                }
            }
            if (paths.size() >= max_paths)
                break;
        }
        frontier = std::move(next);
        if (frontier.size() > 4096)
            frontier.resize(4096);
    }

    json result;
    result["process_id"] = scope.pid();
    result["source_va"] = sa_format_address(source);
    result["target_va"] = sa_format_address(target);
    result["auto_derive"] = auto_derive;
    result["max_candidates_per_slot"] = max_candidates_per_slot;
    if (auto module = find_module_for_address(scope.pid(), source))
    {
        result["source_module_name"] = module->name;
        result["source_module_base"] = sa_format_address(module->base);
        result["source_rva"] = sa_format_address(source - module->base);
    }
    result["paths"] = std::move(paths);
    result["count"] = result["paths"].size();
    result["exhausted"] = result["count"].get<std::size_t>() >= max_paths;
    return tool_result_t::ok(result);
}

tool_result_t emit_resolver(const json& params)
{
    json selected_chain;
    std::string chain_error;
    if (!select_chain_input(params, selected_chain, chain_error))
        return tool_result_t::error(chain_error);
    const json& chain = selected_chain;
    const std::string fn = resolver_function_name(params);
    const std::string base_symbol = sanitize_identifier(string_param(params, "base_symbol", "base"), "base");
    std::uint64_t source = 0;
    std::uint64_t source_rva = 0;
    if (chain.contains("source_va"))
        parse_u64_value(chain["source_va"], source);
    const bool has_source_rva = chain.contains("source_rva") && parse_u64_value(chain["source_rva"], source_rva);

    std::ostringstream os;
    os << "template <typename Read64>\n";
    os << "bool " << fn << "(uintptr_t " << base_symbol << ", Read64&& read64, uintptr_t& out)\n";
    os << "{\n";
    if (has_source_rva)
        os << "    uintptr_t current = " << base_symbol << " + static_cast<uintptr_t>(0x" << std::hex << std::uppercase << source_rva << std::dec << "ull);\n";
    else if (source != 0)
    {
        os << "    (void)" << base_symbol << ";\n";
        os << "    uintptr_t current = static_cast<uintptr_t>(0x" << std::hex << std::uppercase << source << std::dec << "ull);\n";
    }
    else
        os << "    uintptr_t current = " << base_symbol << ";\n";
    os << "    uintptr_t raw = 0;\n";
    if (!chain.contains("hops") || !chain["hops"].is_array())
        return tool_result_t::error("chain.hops array is required.");
    const auto& hops_array = chain["hops"];
    for (std::size_t i = 0; i < hops_array.size(); ++i)
    {
        const auto& hop = hops_array[i];
        const std::string type = hop.value("type", std::string("deref"));
        const std::int64_t offset = hop.value("offset", 0ll);
        std::uint64_t key = 0;
        if (hop.contains("value"))
            parse_u64_value(hop["value"], key);
        os << "    uintptr_t slot = current";
        if (offset >= 0)
            os << " + 0x" << std::hex << std::uppercase << offset << std::dec;
        else
            os << " - 0x" << std::hex << std::uppercase << -offset << std::dec;
        os << ";\n";
        os << "    if (!read64(slot, raw)) return false;\n";
        if (type == "xor")
            os << "    current = raw ^ static_cast<uintptr_t>(0x" << std::hex << std::uppercase << key << std::dec << "ull);\n";
        else if (type == "xor_address")
            os << "    current = raw ^ slot ^ static_cast<uintptr_t>(0x" << std::hex << std::uppercase << key << std::dec << "ull);\n";
        else if (type == "add")
            os << "    current = raw + static_cast<uintptr_t>(0x" << std::hex << std::uppercase << key << std::dec << "ull);\n";
        else if (type == "sub")
            os << "    current = raw - static_cast<uintptr_t>(0x" << std::hex << std::uppercase << key << std::dec << "ull);\n";
        else if (type == "rol")
            os << "    current = (raw << " << (key & 63ull) << ") | (raw >> " << ((64ull - key) & 63ull) << ");\n";
        else if (type == "ror")
            os << "    current = (raw >> " << (key & 63ull) << ") | (raw << " << ((64ull - key) & 63ull) << ");\n";
        else
            os << "    current = raw;\n";
        if (i + 1 == hops_array.size())
            os << "    if (current < 0x10000ull || current >= 0x0000800000000000ull) return false;\n";
        else
            os << "    if ((current & 0x7ull) != 0 || current < 0x10000ull || current >= 0x0000800000000000ull) return false;\n";
    }
    os << "    out = current;\n";
    os << "    return true;\n";
    os << "}\n";

    json result;
    result["cpp_source"] = os.str();
    return tool_result_t::ok(result);
}

tool_result_t verify_stable(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    if (!params.contains("chain") || !params["chain"].is_object())
        return tool_result_t::error("'chain' object is required.");

    const std::size_t samples = static_cast<std::size_t>(numeric_param(params, "samples", 10, 1, 100));
    const std::uint64_t interval_ms = numeric_param(params, "interval_ms", 500, 0, 10000);
    json values = json::array();
    std::set<std::uint64_t> unique;
    std::size_t ok_count = 0;
    for (std::size_t i = 0; i < samples; ++i)
    {
        std::uint64_t value = 0;
        const bool ok = resolve_chain_once(scope.pid(), params["chain"], value);
        json row;
        row["sample"] = i;
        row["ok"] = ok;
        if (ok)
        {
            row["value"] = sa_format_address(value);
            unique.insert(value);
            ++ok_count;
        }
        values.push_back(std::move(row));
        if (i + 1 < samples && interval_ms != 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
    std::string stability = "never_same";
    if (ok_count == samples && unique.size() == 1)
        stability = "always_same";
    else if (ok_count > 1 && unique.size() < ok_count)
        stability = "sometimes_same";

    json result;
    result["process_id"] = scope.pid();
    result["samples_requested"] = samples;
    result["samples_ok"] = ok_count;
    result["unique_values"] = unique.size();
    result["stability"] = stability;
    result["samples"] = std::move(values);
    return tool_result_t::ok(result);
}
}
