#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <memory>
#include <optional>
#include <variant>
#include <cstdint>

#include <nlohmann/json.hpp>


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


std::unique_ptr<provider_t> build_provider(
    const settings_sa_t& settings,
    std::function<std::shared_ptr<httplib::Client>(const std::string&)> get_client,
    std::atomic<bool>& cancelled);


enum class api_format_t
{
    anthropic,
    openai,
    gemini,
    openrouter
};


inline api_format_t get_api_format(const std::string& provider_kind)
{
    if (provider_kind == "anthropic" || provider_kind == "bedrock" || provider_kind == "vertex")
        return api_format_t::anthropic;
    if (provider_kind == "gemini")
        return api_format_t::gemini;
    if (provider_kind == "openrouter")
        return api_format_t::openrouter;
    return api_format_t::openai;
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


nlohmann::json build_openai_format_tools(const std::vector<mcp_standalone::tool_def_t>& tools);
nlohmann::json build_anthropic_format_tools(const std::vector<mcp_standalone::tool_def_t>& tools);
nlohmann::json build_gemini_format_tools(const std::vector<mcp_standalone::tool_def_t>& tools);

nlohmann::json convert_messages_openai(const nlohmann::json& messages, const std::string& system_prompt);
nlohmann::json convert_messages_gemini(const nlohmann::json& messages);
nlohmann::json merge_consecutive_roles(const nlohmann::json& messages);

nlohmann::json make_tool_result_anthropic(const std::string& tool_use_id, const std::string& content, bool is_error = false);
nlohmann::json make_tool_result_openai(const std::string& tool_call_id, const std::string& content);
nlohmann::json make_tool_result_gemini(const std::string& function_name, const nlohmann::json& result_data);


}
