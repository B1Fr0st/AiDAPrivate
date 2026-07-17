#include "../core/ai/standalone_chat.hpp"
#include "../core/ai/settings_overlay.hpp"
#include "../core/mcp/mcp_client.hpp"
#include "../core/mcp/mcp_marketplace.hpp"
#include "../core/settings/standalone_settings.hpp"
#include "../helpers/globals.h"
#include "command_registry_preview.inl"

#include <limits>

namespace {

std::atomic<bool> s_preview_cancel{false};
std::atomic<bool> s_preview_busy{false};
std::string s_preview_session = "preview-nightfall-session";
std::string s_preview_assistant_message;
file_context::tracker_t s_preview_file_tracker;
std::vector<mcp_client::server_config_t> s_preview_mcp_configs;

struct tool_approval_t {
    std::mutex mtx;
    std::condition_variable cv;
    bool pending = false;
    bool approved = false;
    bool answered = false;
    std::string tool_name;
    std::string tool_args_preview;
};

tool_approval_t s_tool_approval;

void seed_preview_chat()
{
    if (!g_chat_messages.empty())
        return;

    ChatMessage user;
    user.text = "Trace how the license response reaches the feature gate and identify every cross-reference that can mutate the decision.";
    user.is_user = true;
    user.timestamp = 1784048400;
    g_chat_messages.push_back(std::move(user));

    ChatMessage assistant;
    assistant.text = "## Analysis complete\n\nThe decision flows through three independently validated stages:\n\n1. `validate_response_envelope` authenticates the signed server payload.\n2. `bind_session_claims` checks nonce, device, and subscription claims.\n3. `commit_runtime_gate` publishes the verified capability set.\n\n```cpp\nif (!claims.signature_ok || !claims.session_bound)\n    return gate_result_t::rejected;\n```\n\nThe strongest patch-resistance comes from downstream consumers reading the capability set instead of a single shared boolean.";
    assistant.has_thinking = true;
    assistant.thinking_text = "Mapped the call graph, followed data references, and compared the three gate writers against their readers.";
    assistant.timestamp = 1784048408;
    assistant.input_tokens = 4281;
    assistant.output_tokens = 1168;
    assistant.cache_read_tokens = 2048;
    assistant.cost = 0.0417;
    assistant.model_id = "gpt-5.4";
    g_chat_messages.push_back(std::move(assistant));

    ChatMessage tool;
    tool.text = "Found 14 references across 6 functions. Highest-confidence path: `sub_14018A920 -> validate_response_envelope -> bind_session_claims -> commit_runtime_gate`.";
    tool.tool_name = "xref_search";
    tool.is_tool_result = true;
    tool.timestamp = 1784048410;
    g_chat_messages.push_back(std::move(tool));
    g_chat_scroll_to_bottom = true;
}

}

namespace aida::agent {

namespace {
std::vector<agent_info_t> s_preview_agents = [] {
    agent_info_t build;
    build.name = "build";
    build.description = "Execute reverse engineering workflows and apply verified changes";
    build.mode = agent_info_t::mode_t::primary;
    build.color = "#44B881";
    build.temperature = 0.7;
    build.max_steps = 24;

    agent_info_t plan;
    plan.name = "plan";
    plan.description = "Map binaries, reason about evidence, and produce analysis plans";
    plan.mode = agent_info_t::mode_t::primary;
    plan.color = "#458BE8";
    plan.temperature = 0.4;
    plan.max_steps = 18;

    agent_info_t triage;
    triage.name = "malware-triage";
    triage.description = "Triage suspicious binaries and prioritize indicators";
    triage.mode = agent_info_t::mode_t::subagent;
    triage.color = "#D9A441";
    triage.temperature = 0.3;
    triage.max_steps = 12;
    return std::vector<agent_info_t>{build, plan, triage};
}();
std::string s_preview_active_agent = "build";
std::string s_preview_default_agent = "build";
std::string s_preview_agent_error;
}

bool initialize() { return true; }
const std::vector<agent_info_t>& list() { return s_preview_agents; }

std::vector<const agent_info_t*> primary_agents()
{
    std::vector<const agent_info_t*> out;
    for (const auto& agent : s_preview_agents)
        if (agent.mode == agent_info_t::mode_t::primary && !agent.hidden)
            out.push_back(&agent);
    return out;
}

std::vector<const agent_info_t*> subagents()
{
    std::vector<const agent_info_t*> out;
    for (const auto& agent : s_preview_agents)
        if (agent.mode == agent_info_t::mode_t::subagent && !agent.hidden)
            out.push_back(&agent);
    return out;
}

const agent_info_t* get(const std::string& name)
{
    auto it = std::find_if(s_preview_agents.begin(), s_preview_agents.end(), [&](const agent_info_t& agent) { return agent.name == name; });
    return it == s_preview_agents.end() ? nullptr : &*it;
}

const std::string& default_agent_name() { return s_preview_default_agent; }
const agent_info_t* small_compaction_agent_for(const std::string&) { return get("plan"); }

bool register_custom(const agent_info_t& info)
{
    if (info.name.empty() || get(info.name) != nullptr)
        return false;
    s_preview_agents.push_back(info);
    return true;
}

bool unregister_custom(const std::string& name)
{
    auto it = std::find_if(s_preview_agents.begin(), s_preview_agents.end(), [&](const agent_info_t& agent) { return agent.name == name && !agent.native; });
    if (it == s_preview_agents.end())
        return false;
    s_preview_agents.erase(it);
    return true;
}

bool save_custom_to_disk() { return true; }
bool load_custom_from_disk() { return true; }
const std::string& last_error() { return s_preview_agent_error; }
const std::string& active_agent_name() { return s_preview_active_agent; }

bool set_active_agent(const std::string& name)
{
    if (get(name) == nullptr)
        return false;
    s_preview_active_agent = name;
    return true;
}

const agent_info_t* active_agent() { return get(s_preview_active_agent); }
void set_default_agent_name(const std::string& name) { if (get(name)) s_preview_default_agent = name; }

permission_rule_t::action_t evaluate_ruleset(const ruleset_t& rules, const std::string& key, const std::string& pattern)
{
    for (const auto& rule : rules)
        if (rule.permission_key == key && wildcard_match(rule.pattern, pattern))
            return rule.action;
    return permission_rule_t::action_t::ask;
}

bool tool_allowed(const agent_info_t& agent, const std::string& tool)
{
    return std::find(agent.tools_denied.begin(), agent.tools_denied.end(), tool) == agent.tools_denied.end();
}

std::string permission_key_for_tool(const std::string& tool) { return "tool." + tool; }

bool wildcard_match(const std::string& pattern, const std::string& target)
{
    if (pattern.empty() || pattern == "*")
        return true;
    const auto star = pattern.find('*');
    if (star == std::string::npos)
        return pattern == target;
    return target.size() >= star && target.compare(0, star, pattern, 0, star) == 0;
}

nlohmann::json to_json(const agent_info_t& info)
{
    return {{"name", info.name}, {"description", info.description}, {"color", info.color}};
}

bool from_json(const nlohmann::json& object, agent_info_t& out)
{
    if (!object.is_object() || !object.contains("name") || !object["name"].is_string())
        return false;
    out.name = object["name"].get<std::string>();
    out.description = object.value("description", std::string());
    out.color = object.value("color", std::string("#458BE8"));
    out.native = false;
    return true;
}

}

namespace aida::provider::catalog {

namespace {
std::vector<model_info_t> s_preview_models = [] {
    model_info_t gpt;
    gpt.id = "gpt-5.4";
    gpt.provider_id = "openai_native";
    gpt.name = "GPT-5.4";
    gpt.family = "gpt-5";
    gpt.capabilities.reasoning = true;
    gpt.limit.context = 400000;
    gpt.cost.input_per_million = 2.50;
    gpt.cost.output_per_million = 10.00;

    model_info_t mini = gpt;
    mini.id = "gpt-5.4-mini";
    mini.name = "GPT-5.4 mini";
    mini.cost.input_per_million = 0.40;
    mini.cost.output_per_million = 1.60;

    model_info_t claude;
    claude.id = "claude-sonnet-4-6";
    claude.provider_id = "anthropic";
    claude.name = "Claude Sonnet 4.6";
    claude.family = "claude-sonnet";
    claude.capabilities.reasoning = true;
    claude.limit.context = 200000;
    claude.cost.input_per_million = 3.00;
    claude.cost.output_per_million = 15.00;
    return std::vector<model_info_t>{gpt, mini, claude};
}();
std::vector<provider_info_t> s_preview_providers = {
    {"openai_native", "OpenAI", "@ai-sdk/openai", "OPENAI_API_KEY", "https://api.openai.com", {"gpt-5.4", "gpt-5.4-mini"}},
    {"anthropic", "Anthropic", "@ai-sdk/anthropic", "ANTHROPIC_API_KEY", "https://api.anthropic.com", {"claude-sonnet-4-6"}}
};
}

bool fetch_and_cache(int) { return true; }
bool load_cached_or_fetch(int) { return true; }
std::int64_t cached_age_seconds() noexcept { return 18; }
model_list_validation_t validate_provider_model_list_response(
    const std::string& provider_id, const std::string& body)
{
    model_list_validation_t result;
    if (body.empty()) {
        result.error = "Provider returned an empty response";
        return result;
    }
    try {
        const auto json = nlohmann::json::parse(body);
        if (!json.is_object()) {
            result.error = "Provider response root is not an object";
            return result;
        }
        if (json.contains("error") && !json["error"].is_null()) {
            result.error = "Provider returned an error payload";
            return result;
        }
        const char* collection = provider_id == "google" ? "models" : "data";
        const char* identifier = provider_id == "google" ? "name" : "id";
        if (!json.contains(collection) || !json[collection].is_array()) {
            result.error = std::string("Provider response is missing the ") + collection + " array";
            return result;
        }
        const auto& models = json[collection];
        if (models.empty()) {
            result.error = "Provider returned no models";
            return result;
        }
        for (const auto& model : models) {
            if (!model.is_object() || !model.contains(identifier)
                || !model[identifier].is_string()
                || model[identifier].get_ref<const std::string&>().empty()) {
                result.model_count = 0;
                result.error = "Provider returned a malformed model entry";
                return result;
            }
            if (result.model_count == (std::numeric_limits<int>::max)()) {
                result.model_count = 0;
                result.error = "Provider model count exceeds the supported limit";
                return result;
            }
            ++result.model_count;
        }
        result.valid = true;
    } catch (...) {
        result.error = "Provider response JSON is malformed";
    }
    return result;
}
bool initialize_async(int) { return true; }
void cancel_initialize() noexcept {}
const std::vector<provider_info_t>& list_providers() { return s_preview_providers; }

const provider_info_t* get_provider(const std::string& id)
{
    auto it = std::find_if(s_preview_providers.begin(), s_preview_providers.end(), [&](const provider_info_t& provider) { return provider.id == id; });
    return it == s_preview_providers.end() ? nullptr : &*it;
}

const model_info_t* get_model(const std::string& provider, const std::string& model)
{
    auto it = std::find_if(s_preview_models.begin(), s_preview_models.end(), [&](const model_info_t& current) { return current.provider_id == provider && current.id == model; });
    return it == s_preview_models.end() ? nullptr : &*it;
}

std::vector<const model_info_t*> closest(const std::string& provider, const std::vector<std::string>&)
{
    std::vector<const model_info_t*> out;
    for (const auto& model : s_preview_models)
        if (model.provider_id == provider)
            out.push_back(&model);
    return out;
}

const model_info_t* get_small_model(const std::string& provider)
{
    return provider == "openai_native" ? get_model(provider, "gpt-5.4-mini") : default_model(provider);
}

const model_info_t* default_model(const std::string& provider)
{
    for (const auto& model : s_preview_models)
        if (model.provider_id == provider)
            return &model;
    return nullptr;
}

std::string last_error() { return {}; }

}

namespace aida::skills {

namespace {
std::vector<skill_metadata_t> s_preview_skills = {
    {"binary-analysis", "Map sections, functions, imports, and cross-references", "global", {"build", "plan"}, "C:\\AiDA\\skills\\binary-analysis.md"},
    {"deobfuscate", "Recover control flow and simplify obfuscated expressions", "project", {"build"}, "C:\\analysis\\nightfall\\.aida\\skills\\deobfuscate.md"},
    {"malware-triage", "Prioritize indicators, capabilities, and suspicious behavior", "remote", {"build", "malware-triage"}, "C:\\AiDA\\skills\\malware-triage.md"},
    {"patch-review", "Review binary patches against the analyzed control flow", "project", {"build", "plan"}, "C:\\analysis\\nightfall\\.aida\\skills\\patch-review.md"}
};
std::set<std::string> s_preview_disabled;
std::string s_preview_skill_error;
std::vector<std::string> s_preview_remote_urls = {"https://skills.aidapro.net/index.json"};
manager_t s_preview_skill_manager;
}

const std::string& last_error() { return s_preview_skill_error; }

bool parse_yaml_frontmatter(const std::string& content, skill_metadata_t& meta, std::string& body)
{
    meta.name = "preview-skill";
    meta.description = "Preview skill";
    body = content;
    return !content.empty();
}

void manager_t::add_search_path(const std::string&) {}
void manager_t::discover() {}
std::vector<skill_metadata_t> manager_t::get_all() const { return s_preview_skills; }
std::vector<skill_metadata_t> manager_t::get_for_agent(const std::string& agent) const
{
    std::vector<skill_metadata_t> out;
    for (const auto& skill : s_preview_skills)
        if (skill.agent_slugs.empty() || std::find(skill.agent_slugs.begin(), skill.agent_slugs.end(), agent) != skill.agent_slugs.end())
            out.push_back(skill);
    return out;
}
std::vector<skill_metadata_t> manager_t::get_for_mode(const std::string& mode) const { return get_for_agent(mode); }
skill_content_t manager_t::resolve(const std::string& name) const { return aida::skills::resolve(name); }
void manager_t::reload() {}
bool manager_t::has_skill(const std::string& name) const { return find(name) != nullptr; }
const skill_metadata_t* manager_t::find(const std::string& name) const { return aida::skills::find(name); }
std::vector<std::string> manager_t::search_paths() const { return {"C:\\AiDA\\skills", "C:\\analysis\\nightfall\\.aida\\skills"}; }
manager_t& global() { return s_preview_skill_manager; }
void configure_default_paths(const std::string&) {}
bool reindex() { return true; }
std::vector<skill_metadata_t> all() { return s_preview_skills; }

const skill_metadata_t* find(const std::string& name)
{
    auto it = std::find_if(s_preview_skills.begin(), s_preview_skills.end(), [&](const skill_metadata_t& skill) { return skill.name == name; });
    return it == s_preview_skills.end() ? nullptr : &*it;
}

skill_content_t resolve(const std::string& name)
{
    skill_content_t out;
    if (const auto* metadata = find(name)) {
        static_cast<skill_metadata_t&>(out) = *metadata;
        out.instructions = "Inspect the current evidence, preserve symbol provenance, and report confidence for every conclusion.";
    }
    return out;
}

std::vector<std::string> placeholder_hints_for(const std::string&) { return {"target", "address", "scope"}; }

std::vector<skill_as_command_t> all_as_commands()
{
    std::vector<skill_as_command_t> out;
    for (const auto& skill : s_preview_skills)
        out.push_back({skill.name, skill.description, "/" + skill.name + " ${target}", {"target"}, skill.file_path, skill.agent_slugs});
    return out;
}

bool fetch_remote_index(const std::string& url, remote_index_t& out, int)
{
    out.url = url;
    out.entries = {
        {"malware-triage", "Prioritize suspicious behavior and indicators", {"SKILL.md"}},
        {"firmware-analysis", "Inspect firmware images and embedded filesystems", {"SKILL.md"}}
    };
    return true;
}

bool install_remote_skill(const std::string&, const std::string& name)
{
    if (find(name) != nullptr)
        return true;
    s_preview_skills.push_back({name, "Installed preview skill", "remote", {"build", "plan"}, "C:\\AiDA\\skills\\" + name + ".md"});
    return true;
}

bool uninstall_remote_skill(const std::string& name)
{
    const auto old_size = s_preview_skills.size();
    s_preview_skills.erase(
        std::remove_if(s_preview_skills.begin(), s_preview_skills.end(),
            [&](const skill_metadata_t& skill) { return skill.name == name && skill.source == "remote"; }),
        s_preview_skills.end());
    return old_size != s_preview_skills.size();
}

std::vector<std::string> list_remote_urls() { return s_preview_remote_urls; }
bool add_remote_url(const std::string& url) { if (std::find(s_preview_remote_urls.begin(), s_preview_remote_urls.end(), url) == s_preview_remote_urls.end()) s_preview_remote_urls.push_back(url); return true; }
bool remove_remote_url(const std::string& url) { s_preview_remote_urls.erase(std::remove(s_preview_remote_urls.begin(), s_preview_remote_urls.end(), url), s_preview_remote_urls.end()); return true; }

std::vector<const skill_metadata_t*> available_for_agent(const std::string& agent)
{
    std::vector<const skill_metadata_t*> out;
    for (const auto& skill : s_preview_skills)
        if (skill.agent_slugs.empty() || std::find(skill.agent_slugs.begin(), skill.agent_slugs.end(), agent) != skill.agent_slugs.end())
            out.push_back(&skill);
    return out;
}

bool set_enabled(const std::string& name, bool enabled)
{
    if (enabled)
        s_preview_disabled.erase(name);
    else
        s_preview_disabled.insert(name);
    return true;
}

bool is_enabled(const std::string& name) { return s_preview_disabled.find(name) == s_preview_disabled.end(); }
std::vector<std::string> list_disabled() { return {s_preview_disabled.begin(), s_preview_disabled.end()}; }

}

namespace mcp_client {

manager_t::manager_t() = default;
manager_t::~manager_t() = default;

void manager_t::add_server(const server_config_t& cfg)
{
    auto it = std::find_if(s_preview_mcp_configs.begin(), s_preview_mcp_configs.end(),
        [&](const server_config_t& current) { return current.name == cfg.name; });
    if (it == s_preview_mcp_configs.end())
        s_preview_mcp_configs.push_back(cfg);
    else
        *it = cfg;
}

void manager_t::remove_server(const std::string& name)
{
    s_preview_mcp_configs.erase(
        std::remove_if(s_preview_mcp_configs.begin(), s_preview_mcp_configs.end(),
            [&](const server_config_t& cfg) { return cfg.name == name; }),
        s_preview_mcp_configs.end());
}

void manager_t::connect_all() {}
void manager_t::disconnect_all() {}
bool manager_t::connect_server(const std::string&) { return true; }
void manager_t::disconnect_server(const std::string&) {}
std::vector<remote_tool_t> manager_t::get_all_tools() { return {}; }
call_result_t manager_t::call_tool(const std::string& name, const json&) { return call_result_t::ok("Preview receipt: " + name); }
size_t manager_t::tool_count() const { return 18; }
std::vector<remote_resource_t> manager_t::get_all_resources() { return {}; }
std::string manager_t::read_resource(const std::string&, const std::string&) { return "Preview resource receipt"; }
std::vector<remote_prompt_t> manager_t::get_all_prompts() { return {}; }
std::string manager_t::get_prompt(const std::string&, const std::string&, const std::map<std::string, std::string>&) { return "Preview prompt receipt"; }

std::vector<manager_t::server_status_t> manager_t::get_status() const
{
    std::vector<server_status_t> out;
    out.push_back({"AiDA Local Tools", connection_state_t::connected, {}, 14, oauth_status_t::not_required});
    out.push_back({"Reverse Engineering Docs", connection_state_t::connected, {}, 4, oauth_status_t::authenticated});
    for (const auto& cfg : s_preview_mcp_configs) {
        auto exists = std::find_if(out.begin(), out.end(), [&](const server_status_t& status) { return status.name == cfg.name; });
        if (exists == out.end())
            out.push_back({cfg.name, cfg.enabled ? connection_state_t::connected : connection_state_t::disconnected, {}, cfg.enabled ? 3u : 0u, oauth_status_t::not_required});
    }
    return out;
}

void manager_t::poll() {}
bool manager_t::refresh_tools(const std::string&) { return true; }

bool manager_t::find_config(const std::string& name, server_config_t& out) const
{
    auto it = std::find_if(s_preview_mcp_configs.begin(), s_preview_mcp_configs.end(),
        [&](const server_config_t& cfg) { return cfg.name == name; });
    if (it == s_preview_mcp_configs.end())
        return false;
    out = *it;
    return true;
}

json manager_t::mcp_tool_list_json() { return json::array(); }
bool supports_oauth(const std::string&) { return true; }
bool has_stored_tokens(const std::string& server_name) { return server_name == "Reverse Engineering Docs"; }
bool start_auth(const std::string&, oauth_state_t&) { return true; }
oauth_status_t poll_auth(oauth_state_t&) { return oauth_status_t::authenticated; }
bool finish_auth(const std::string&, const std::string&) { return true; }
bool remove_auth(const std::string&) { return true; }
oauth_status_t auth_status(const std::string& server_name) { return server_name == "Reverse Engineering Docs" ? oauth_status_t::authenticated : oauth_status_t::not_required; }
bool cancel_auth(oauth_state_t&) { return true; }

bool trigger_auth_flow(const std::string& server_name, auth_completion_callback_t callback)
{
    if (callback)
        callback(server_name, oauth_status_t::authenticated, {});
    return true;
}

std::string last_error()
{
    return {};
}

}

namespace mcp_standalone {

server_t::server_t() = default;
server_t::~server_t() = default;

bool server_t::start(int port)
{
    _port = port;
    _running.store(true, std::memory_order_release);
    _server_done.store(true, std::memory_order_release);
    return true;
}

void server_t::stop()
{
    _stop_requested.store(true, std::memory_order_release);
    _running.store(false, std::memory_order_release);
    _server_done.store(true, std::memory_order_release);
}

}

namespace mcp_marketplace {

namespace {
std::vector<installed_server_t> s_preview_installed = {
    {"@aida/local-tools", "1.4.0", registry_t::npm, {}, "stdio", "aida-local-tools", {}, {}, true, true},
    {"reverse-engineering-docs", "2.1.3", registry_t::pypi, {}, "stdio", "reverse-engineering-docs", {}, {}, true, false}
};
std::vector<package_info_t> s_preview_results = {
    {"@aida/local-tools", "AiDA Local Tools", "Workspace-aware reverse engineering tools", "1.4.0", "AiDA", "MIT", {}, {}, registry_t::npm, 18340, "reverse engineering analysis", true},
    {"reverse-engineering-docs", "Reverse Engineering Docs", "Searchable platform and ABI references", "2.1.3", "AiDA Community", "Apache-2.0", {}, {}, registry_t::pypi, 9210, "documentation symbols abi", true},
    {"malware-analysis-mcp", "Malware Analysis", "Static triage and indicator enrichment", "0.9.8", "Security Labs", "MIT", {}, {}, registry_t::npm, 4720, "malware triage pe", false}
};
}

void search_async(const std::string&, registry_t) {}
std::string registry_label(registry_t registry) { return registry == registry_t::npm ? "npm" : "PyPI"; }
std::string install_root() { return "Studio preview memory"; }

installed_server_t preview_install(const package_info_t& package)
{
    installed_server_t server;
    server.package_name = package.name;
    server.version = package.version;
    server.registry = package.registry;
    server.command = package.name;
    return server;
}

std::string launch_command_preview(const installed_server_t& server)
{
    std::string out = server.command;
    for (const auto& arg : server.args) {
        out += " ";
        out += arg;
    }
    return out;
}

search_state_t get_search_state() { return search_state_t::done; }
std::string get_search_error() { return {}; }
std::vector<package_info_t> get_search_results() { return s_preview_results; }

void install_async(const package_info_t& package)
{
    auto server = preview_install(package);
    server.enabled = true;
    s_preview_installed.push_back(std::move(server));
}

bool uninstall(const std::string& name)
{
    const auto old_size = s_preview_installed.size();
    s_preview_installed.erase(
        std::remove_if(s_preview_installed.begin(), s_preview_installed.end(),
            [&](const installed_server_t& server) { return server.package_name == name; }),
        s_preview_installed.end());
    return old_size != s_preview_installed.size();
}

install_state_t get_install_state() { return install_state_t::done; }
std::string get_install_error() { return {}; }
std::vector<installed_server_t> get_installed() { return s_preview_installed; }
void activate_server(const installed_server_t& server) { set_server_policy(server.package_name, true, server.auto_connect); }
void deactivate_server(const std::string& name) { set_server_policy(name, false, false); }

bool set_server_policy(const std::string& name, bool enabled, bool auto_connect)
{
    auto it = std::find_if(s_preview_installed.begin(), s_preview_installed.end(),
        [&](const installed_server_t& server) { return server.package_name == name; });
    if (it == s_preview_installed.end())
        return false;
    it->enabled = enabled;
    it->auto_connect = auto_connect;
    return true;
}

void load_installed(const std::string&) {}
std::string save_installed() { return nlohmann::json::array().dump(); }
void tick() {}
void shutdown() {}

}


void init_standalone_chat()
{
    g_sa_settings.load();
    seed_preview_chat();
    s_preview_cancel.store(false, std::memory_order_release);
}

void shutdown_standalone_chat() { s_preview_busy.store(false, std::memory_order_release); }
void mark_ide_ready_for_mcp_services() {}
void start_authorized_mcp_services() {}
void tick_ai_chat() {}
void poll_ai_chat() {}
bool is_ai_busy() { return s_preview_busy.load(std::memory_order_acquire); }
void chat_request_cancel() { s_preview_cancel.store(true, std::memory_order_release); s_preview_busy.store(false, std::memory_order_release); }
std::atomic<bool>* chat_cancel_flag() { return &s_preview_cancel; }
void chat_bind_session(const std::string& session_id) { s_preview_session = session_id.empty() ? "preview-nightfall-session" : session_id; }
std::string chat_active_session() { return s_preview_session; }
void chat_record_assistant_message_id(const std::string& message_id) { s_preview_assistant_message = message_id; }

std::string start_new_conversation()
{
    static unsigned sequence = 1;
    s_preview_session = "preview-conversation-" + std::to_string(sequence++);
    g_chat_messages.clear();
    seed_preview_chat();
    return s_preview_session;
}

mcp_client::manager_t& get_mcp_client_manager()
{
    static mcp_client::manager_t manager;
    return manager;
}

mcp_standalone::server_t& get_local_mcp_server()
{
    static mcp_standalone::server_t server;
    return server;
}

std::vector<mcp_standalone::tool_def_t> snapshot_local_tools() { return {}; }
std::string execute_local_tool(const std::string& name, const nlohmann::json& arguments)
{
    std::lock_guard<std::mutex> lock(s_tool_approval.mtx);
    s_tool_approval.pending = true;
    s_tool_approval.approved = false;
    s_tool_approval.answered = false;
    s_tool_approval.tool_name = name;
    s_tool_approval.tool_args_preview = arguments.dump(2);
    return "Preview receipt: " + name;
}
file_context::tracker_t& get_file_tracker() { return s_preview_file_tracker; }
void do_process_attach(unsigned long) {}
void do_process_detach() {}
bool is_process_attached() { return true; }
std::string get_attached_process_name() { return "nightfall.exe"; }
unsigned long get_attached_pid() { return 7428; }
