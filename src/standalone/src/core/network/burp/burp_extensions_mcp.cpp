#include "burp_extensions_mcp.hpp"

#include "extensions.hpp"

#include <string>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

bool json_bool(const json& params, const char* key, bool fallback)
{
    if (!params.is_object() || !params.contains(key))
        return fallback;
    const auto& value = params[key];
    if (value.is_boolean())
        return value.get<bool>();
    if (value.is_string()) {
        const std::string s = value.get<std::string>();
        return s == "1" || s == "true" || s == "yes";
    }
    return fallback;
}

std::string json_string(const json& params, const char* key)
{
    if (!params.is_object() || !params.contains(key) || !params[key].is_string())
        return {};
    return params[key].get<std::string>();
}

tool_result_t handle_list(const json& params)
{
    const bool include_disabled = json_bool(params, "include_disabled", true);
    const bool include_descriptors = json_bool(params, "include_descriptors", true);
    return tool_result_t::ok(extensions::snapshot_json(include_disabled, include_descriptors));
}

tool_result_t handle_refresh(const json&)
{
    std::string error;
    if (!extensions::refresh(&error))
        return tool_result_t::error(error.empty() ? "Burp extension refresh failed" : error);
    return tool_result_t::ok(extensions::snapshot_json(true, true));
}

tool_result_t handle_get(const json& params)
{
    const std::string id = json_string(params, "id");
    if (id.empty())
        return tool_result_t::error("Missing extension id");
    auto ext = extensions::find_extension(id);
    if (!ext)
        return tool_result_t::error("Extension not found: " + id);
    json out = extensions::snapshot_json(true, true);
    json matched = json::array();
    for (const auto& item : out["extensions"]) {
        if (item.contains("id") && item["id"].is_string() && item["id"].get<std::string>() == id)
            matched.push_back(item);
    }
    json result;
    result["root"] = out["root"];
    result["generation"] = out["generation"];
    result["extension"] = matched.empty() ? json::object() : matched.front();
    return tool_result_t::ok(result);
}

tool_result_t handle_set_enabled(const json& params)
{
    const std::string id = json_string(params, "id");
    if (id.empty())
        return tool_result_t::error("Missing extension id");
    if (!params.is_object() || !params.contains("enabled") || !params["enabled"].is_boolean())
        return tool_result_t::error("Missing explicit enabled boolean");
    std::string error;
    if (!extensions::set_enabled(id, params["enabled"].get<bool>(), &error))
        return tool_result_t::error(error.empty() ? "Failed to update extension enabled state" : error);
    json result;
    result["id"] = id;
    result["enabled"] = params["enabled"].get<bool>();
    result["registry"] = extensions::snapshot_json(true, true);
    return tool_result_t::ok(result);
}

}

void register_extension_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "burp_extensions_list",
        "List validated local Burp extension manifests and tool descriptors from the approved AiDA extension directory. This is descriptor inventory only and never executes extension code.",
        {
            {"include_disabled", "boolean", "Include disabled extensions. Default true.", false},
            {"include_descriptors", "boolean", "Include input schemas and descriptor metadata. Default true.", false}
        },
        true,
        handle_list
    });

    srv.register_tool({
        "burp_extensions_refresh",
        "Reload local Burp extension manifests from disk without fetching remote code or enabling new extensions.",
        {},
        false,
        handle_refresh
    });

    srv.register_tool({
        "burp_extensions_get",
        "Return one validated local Burp extension record by id without executing extension code.",
        {
            {"id", "string", "Extension id", true}
        },
        true,
        handle_get
    });

    srv.register_tool({
        "burp_extensions_set_enabled",
        "Toggle descriptor inventory visibility for a validated local Burp extension. This does not register or execute extension tools.",
        {
            {"id", "string", "Extension id", true},
            {"enabled", "boolean", "Explicit enabled state", true}
        },
        false,
        handle_set_enabled
    });
}

}
}
