#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <memory>
#include <optional>
#include <variant>
#include <map>
#include <cstdint>

#include <nlohmann/json.hpp>

#include "provider_catalog.hpp"


namespace mcp_standalone { struct tool_def_t; }
struct settings_sa_t;
namespace httplib { class Client; }


namespace provider {


enum class stream_chunk_type_t
{
    text,
    reasoning,
    thinking_complete,
    usage,
    grounding,
    tool_call,
    tool_call_start,
    tool_call_delta,
    tool_call_end,
    error
};


struct grounding_source_t
{
    std::string title;
    std::string url;
    std::string snippet;
};


struct stream_chunk_t
{
    stream_chunk_type_t type = stream_chunk_type_t::text;

    std::string text;
    std::string id;
    std::string name;
    std::string signature;

    int64_t input_tokens      = 0;
    int64_t output_tokens     = 0;
    int64_t cache_read_tokens = 0;
    int64_t cache_write_tokens= 0;
    int64_t reasoning_tokens  = 0;
    double  total_cost        = 0.0;

    std::vector<grounding_source_t> sources;
    int index = 0;

    static stream_chunk_t make_text(const std::string& t)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::text; c.text = t; return c;
    }
    static stream_chunk_t make_reasoning(const std::string& t, const std::string& sig = "")
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::reasoning; c.text = t; c.signature = sig; return c;
    }
    static stream_chunk_t make_thinking_complete(const std::string& sig)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::thinking_complete; c.signature = sig; return c;
    }
    static stream_chunk_t make_usage(int64_t in, int64_t out, int64_t cr = 0, int64_t cw = 0, int64_t rt = 0)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::usage;
        c.input_tokens = in; c.output_tokens = out;
        c.cache_read_tokens = cr; c.cache_write_tokens = cw;
        c.reasoning_tokens = rt; return c;
    }
    static stream_chunk_t make_tool_call(const std::string& id, const std::string& name, const std::string& args)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::tool_call;
        c.id = id; c.name = name; c.text = args; return c;
    }
    static stream_chunk_t make_tool_call_start(const std::string& id, const std::string& name, int idx = 0)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::tool_call_start;
        c.id = id; c.name = name; c.index = idx; return c;
    }
    static stream_chunk_t make_tool_call_delta(const std::string& id, const std::string& delta, int idx = 0)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::tool_call_delta;
        c.id = id; c.text = delta; c.index = idx; return c;
    }
    static stream_chunk_t make_tool_call_end(const std::string& id, int idx = 0)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::tool_call_end;
        c.id = id; c.index = idx; return c;
    }
    static stream_chunk_t make_error(const std::string& err)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::error; c.text = err; return c;
    }
    static stream_chunk_t make_grounding(std::vector<grounding_source_t> s)
    {
        stream_chunk_t c; c.type = stream_chunk_type_t::grounding; c.sources = std::move(s); return c;
    }
};


using stream_callback_t = std::function<void(const stream_chunk_t&)>;


struct provider_context_t
{
    const settings_sa_t& settings;
    std::function<std::shared_ptr<httplib::Client>(const std::string&)> get_client;
    std::atomic<bool>& cancelled;
};


struct ai_generation_result_t
{
    std::string text;
    std::string thinking;

    struct tool_call_t {
        std::string id;
        std::string name;
        nlohmann::json arguments;
    };

    std::vector<tool_call_t> tool_calls;
    std::string stop_reason;

    int64_t input_tokens  = 0;
    int64_t output_tokens = 0;
    int64_t cache_read    = 0;
    int64_t cache_write   = 0;
    int64_t reasoning_tokens = 0;
    bool    is_error      = false;
};


class provider_t
{
public:
    virtual ~provider_t() = default;

    explicit provider_t(provider_context_t ctx) : _ctx(std::move(ctx)) {}

    virtual ai_generation_result_t create_message(
        const std::string& system_prompt,
        const nlohmann::json& messages,
        const std::vector<mcp_standalone::tool_def_t>& tools,
        stream_callback_t on_chunk) = 0;

    virtual std::string generate_text(
        const std::string& prompt,
        double temperature,
        std::function<void(const std::string&)> on_chunk,
        std::function<bool(const std::string&)> stop_check) = 0;

    virtual nlohmann::json build_tools(
        const std::vector<mcp_standalone::tool_def_t>& tools) const = 0;

    virtual std::string provider_name() const = 0;

    virtual void cancel() { _ctx.cancelled.store(true); }

    bool is_cancelled() const { return _ctx.cancelled.load(); }

protected:
    provider_context_t _ctx;
};


enum class api_format_t
{
    anthropic,
    openai,
    gemini,
    openrouter
};


inline api_format_t get_api_format(const std::string& provider_kind)
{
    if (const auto* prov = aida::provider::catalog::get_provider(provider_kind)) {
        const std::string& npm = prov->npm;
        if (npm == "@ai-sdk/anthropic" ||
            npm == "@ai-sdk/google-vertex/anthropic" ||
            npm == "@ai-sdk/amazon-bedrock")
            return api_format_t::anthropic;
        if (npm == "@ai-sdk/google" || npm == "@ai-sdk/google-vertex")
            return api_format_t::gemini;
        if (npm == "@openrouter/ai-sdk-provider")
            return api_format_t::openrouter;
        if (!npm.empty())
            return api_format_t::openai;
    }
    if (provider_kind == "anthropic" || provider_kind == "bedrock" || provider_kind == "vertex" ||
        provider_kind == "amazon-bedrock" || provider_kind == "google-vertex-anthropic")
        return api_format_t::anthropic;
    if (provider_kind == "gemini" || provider_kind == "google" || provider_kind == "google-vertex")
        return api_format_t::gemini;
    if (provider_kind == "openrouter")
        return api_format_t::openrouter;
    return api_format_t::openai;
}


inline std::string resolve_npm_for_provider(const std::string& provider_id)
{
    if (const auto* prov = aida::provider::catalog::get_provider(provider_id))
        return prov->npm;
    if (provider_id == "anthropic")        return "@ai-sdk/anthropic";
    if (provider_id == "openai")           return "@ai-sdk/openai";
    if (provider_id == "openai_native")    return "@ai-sdk/openai";
    if (provider_id == "openai_codex")     return "@ai-sdk/openai";
    if (provider_id == "openai_compatible")return "@ai-sdk/openai-compatible";
    if (provider_id == "gemini")           return "@ai-sdk/google";
    if (provider_id == "google")           return "@ai-sdk/google";
    if (provider_id == "google-vertex")    return "@ai-sdk/google-vertex";
    if (provider_id == "vertex")           return "@ai-sdk/google-vertex";
    if (provider_id == "azure")            return "@ai-sdk/azure";
    if (provider_id == "amazon-bedrock")   return "@ai-sdk/amazon-bedrock";
    if (provider_id == "bedrock")          return "@ai-sdk/amazon-bedrock";
    if (provider_id == "openrouter")       return "@openrouter/ai-sdk-provider";
    if (provider_id == "mistral")          return "@ai-sdk/mistral";
    if (provider_id == "github-copilot")   return "@ai-sdk/github-copilot";
    if (provider_id == "xai")              return "@ai-sdk/xai";
    if (provider_id == "groq")             return "@ai-sdk/groq";
    if (provider_id == "deepinfra")        return "@ai-sdk/deepinfra";
    if (provider_id == "cerebras")         return "@ai-sdk/cerebras";
    if (provider_id == "cohere")           return "@ai-sdk/cohere";
    if (provider_id == "togetherai")       return "@ai-sdk/togetherai";
    if (provider_id == "perplexity")       return "@ai-sdk/perplexity";
    if (provider_id == "alibaba" || provider_id == "alibaba-cn") return "@ai-sdk/alibaba";
    if (provider_id == "gateway")          return "@ai-sdk/gateway";
    return "@ai-sdk/openai-compatible";
}


inline std::string sdk_key_for_npm(const std::string& npm)
{
    if (npm == "@ai-sdk/github-copilot")   return "copilot";
    if (npm == "@ai-sdk/azure")            return "azure";
    if (npm == "@ai-sdk/openai")           return "openai";
    if (npm == "@ai-sdk/amazon-bedrock")   return "bedrock";
    if (npm == "@ai-sdk/anthropic" ||
        npm == "@ai-sdk/google-vertex/anthropic")
        return "anthropic";
    if (npm == "@ai-sdk/google-vertex")    return "vertex";
    if (npm == "@ai-sdk/google")           return "google";
    if (npm == "@ai-sdk/gateway")          return "gateway";
    if (npm == "@openrouter/ai-sdk-provider") return "openrouter";
    return std::string();
}


inline std::vector<std::string> catalog_provider_ids()
{
    std::vector<std::string> out;
    const auto& list = aida::provider::catalog::list_providers();
    out.reserve(list.size());
    for (const auto& p : list)
        out.push_back(p.id);
    return out;
}


inline std::vector<std::string> catalog_model_ids(const std::string& provider_id)
{
    if (const auto* prov = aida::provider::catalog::get_provider(provider_id))
        return prov->model_ids;
    return {};
}


inline std::string catalog_provider_display_name(const std::string& provider_id)
{
    if (const auto* prov = aida::provider::catalog::get_provider(provider_id))
        return prov->name;
    return provider_id;
}


inline std::string catalog_provider_base_url(const std::string& provider_id)
{
    if (const auto* prov = aida::provider::catalog::get_provider(provider_id))
        return prov->base_url;
    return std::string();
}


inline std::string catalog_provider_env_var(const std::string& provider_id)
{
    if (const auto* prov = aida::provider::catalog::get_provider(provider_id))
        return prov->env_var;
    return std::string();
}


class tool_call_parser_t
{
public:
    void process_partial(int index, const std::string& id, const std::string& name, const std::string& args_delta,
                         stream_callback_t& on_chunk)
    {
        auto it = _active.find(index);
        if (it == _active.end()) {
            tool_state_t st;
            st.id = id.empty() ? "call_" + std::to_string(index) : id;
            st.name = name;
            st.args_buffer = args_delta;
            _active[index] = std::move(st);
            if (on_chunk)
                on_chunk(stream_chunk_t::make_tool_call_start(_active[index].id, _active[index].name, index));
        } else {
            if (!id.empty() && it->second.id.empty()) it->second.id = id;
            if (!name.empty() && it->second.name.empty()) it->second.name = name;
            if (!args_delta.empty()) {
                it->second.args_buffer += args_delta;
                if (on_chunk)
                    on_chunk(stream_chunk_t::make_tool_call_delta(it->second.id, args_delta, index));
            }
        }
    }

    void finalize_all(stream_callback_t& on_chunk, std::vector<ai_generation_result_t::tool_call_t>& out)
    {
        for (auto& [idx, st] : _active) {
            if (on_chunk)
                on_chunk(stream_chunk_t::make_tool_call_end(st.id, idx));

            ai_generation_result_t::tool_call_t tc;
            tc.id = st.id;
            tc.name = st.name;
            tc.arguments = nlohmann::json::parse(st.args_buffer, nullptr, false);
            if (tc.arguments.is_discarded())
                tc.arguments = nlohmann::json::object();
            out.push_back(std::move(tc));
        }
        _active.clear();
    }

    void finalize_single(int index, stream_callback_t& on_chunk, std::vector<ai_generation_result_t::tool_call_t>& out)
    {
        auto it = _active.find(index);
        if (it == _active.end()) return;

        if (on_chunk)
            on_chunk(stream_chunk_t::make_tool_call_end(it->second.id, index));

        ai_generation_result_t::tool_call_t tc;
        tc.id = it->second.id;
        tc.name = it->second.name;
        tc.arguments = nlohmann::json::parse(it->second.args_buffer, nullptr, false);
        if (tc.arguments.is_discarded())
            tc.arguments = nlohmann::json::object();
        out.push_back(std::move(tc));

        _active.erase(it);
    }

    bool has_active() const { return !_active.empty(); }

private:
    struct tool_state_t {
        std::string id;
        std::string name;
        std::string args_buffer;
    };
    std::map<int, tool_state_t> _active;
};


}
