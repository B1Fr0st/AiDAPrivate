#pragma once


#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>
#include <functional>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <deque>
#include <chrono>

#include <nlohmann/json.hpp>


struct settings_sa_t;
namespace mcp_standalone { struct tool_def_t; }


using ai_callback_t        = std::function<void(const std::string& result)>;
using ai_stream_chunk_t    = std::function<void(const std::string& chunk)>;
using ai_stop_predicate_t  = std::function<bool(const std::string& accumulated)>;


struct ai_tool_call_t
{
    std::string id;
    std::string name;
    nlohmann::json arguments;
};


struct ai_generation_result_t
{
    std::string text;
    std::string thinking;
    std::vector<ai_tool_call_t> tool_calls;
    std::string stop_reason;
    int64_t input_tokens  = 0;
    int64_t output_tokens = 0;
    int64_t cache_read    = 0;
    int64_t cache_write   = 0;
    bool    is_error      = false;
    bool    thinking_streamed = false;
};


class standalone_ai_client_t
{
public:
    struct runtime_control_t;
    struct runtime_operation_t;
    struct async_state_t;
    struct usage_record_t;

    class cancellation_handle_t
    {
    public:
        cancellation_handle_t() = default;
        void cancel() const noexcept;
        bool valid() const noexcept;

    private:
        friend class standalone_ai_client_t;
        explicit cancellation_handle_t(std::weak_ptr<runtime_control_t> control) noexcept;
        std::weak_ptr<runtime_control_t> _control;
    };

    explicit standalone_ai_client_t(const settings_sa_t& settings);
    ~standalone_ai_client_t() noexcept;

    standalone_ai_client_t(const standalone_ai_client_t&) = delete;
    standalone_ai_client_t& operator=(const standalone_ai_client_t&) = delete;

    bool is_available() const;

    void chat_async(
        const std::string& user_message,
        const std::vector<std::pair<std::string, std::string>>& history,
        ai_callback_t on_complete,
        ai_stream_chunk_t on_chunk = nullptr);

    std::string chat_blocking(
        const std::string& user_message,
        const std::vector<std::pair<std::string, std::string>>& history,
        ai_stream_chunk_t on_chunk = nullptr,
        ai_stop_predicate_t stop_check = nullptr);

    ai_generation_result_t generate_with_tools(
        const nlohmann::json& messages,
        const std::string& system_prompt,
        const std::vector<mcp_standalone::tool_def_t>& tools,
        ai_stream_chunk_t on_chunk = nullptr);

    static nlohmann::json build_anthropic_tools(
        const std::vector<mcp_standalone::tool_def_t>& tools);
    static nlohmann::json build_openai_tools(
        const std::vector<mcp_standalone::tool_def_t>& tools);
    static nlohmann::json build_gemini_tools(
        const std::vector<mcp_standalone::tool_def_t>& tools);
    static nlohmann::json build_full_tools(
        const std::vector<mcp_standalone::tool_def_t>& tools);
    static nlohmann::json make_tool_result_block(
        const std::string& tool_use_id,
        const std::string& content,
        bool is_error = false);
    static nlohmann::json make_openai_tool_result(
        const std::string& tool_call_id,
        const std::string& content);
    static nlohmann::json make_gemini_tool_result(
        const std::string& function_name,
        const nlohmann::json& result_data);
    static nlohmann::json convert_messages_for_openai(
        const nlohmann::json& anthropic_messages,
        const std::string& system_prompt);
    static nlohmann::json convert_messages_for_gemini(
        const nlohmann::json& anthropic_messages);
    static nlohmann::json merge_consecutive_roles(
        const nlohmann::json& messages);
    static std::string clean_model_name(const std::string& model);

    bool poll();
    void cancel() noexcept;
    cancellation_handle_t cancellation_handle() const noexcept;
    bool is_busy() const noexcept;

private:
    const settings_sa_t* _settings_source = nullptr;
    std::shared_ptr<runtime_control_t> _control;
    std::shared_ptr<async_state_t> _async;
    mutable std::mutex _async_submit_mutex;

    static bool is_available(const settings_sa_t& settings);
    static std::string resolve_api_key_logged(
        const settings_sa_t& settings,
        const char* context);
    static std::string do_generate(
        const std::shared_ptr<runtime_operation_t>& operation,
        const settings_sa_t& settings,
        const std::string& prompt,
        double temperature,
        ai_stream_chunk_t on_chunk,
        ai_stop_predicate_t stop_check,
        usage_record_t& usage);
    static std::string generate_gemini(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check, usage_record_t& usage);
    static std::string generate_openai(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check, usage_record_t& usage);
    static std::string generate_anthropic(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check, usage_record_t& usage);
    static std::string generate_openrouter(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const std::string& prompt, double temperature, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check, usage_record_t& usage);
    static ai_generation_result_t generate_with_tools_anthropic(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const nlohmann::json& messages, const std::string& system_prompt, const std::vector<mcp_standalone::tool_def_t>& tools, ai_stream_chunk_t on_chunk, usage_record_t& usage);
    static ai_generation_result_t generate_with_tools_openai(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const nlohmann::json& messages, const std::string& system_prompt, const std::vector<mcp_standalone::tool_def_t>& tools, ai_stream_chunk_t on_chunk, usage_record_t& usage);
    static ai_generation_result_t generate_with_tools_gemini(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const nlohmann::json& messages, const std::string& system_prompt, const std::vector<mcp_standalone::tool_def_t>& tools, ai_stream_chunk_t on_chunk, usage_record_t& usage);
    static ai_generation_result_t generate_with_tools_generic_openai(const std::shared_ptr<runtime_operation_t>& operation, const settings_sa_t& settings, const nlohmann::json& messages, const std::string& system_prompt, const std::vector<mcp_standalone::tool_def_t>& tools, ai_stream_chunk_t on_chunk, usage_record_t& usage);
    static std::string streaming_post(const std::shared_ptr<runtime_operation_t>& operation, const std::string& host, const std::string& path, const std::map<std::string, std::string>& headers, const std::string& body, std::function<std::string(const std::string& sse_data)> chunk_parser, ai_stream_chunk_t on_chunk, ai_stop_predicate_t stop_check);
    static std::string simple_post(const std::shared_ptr<runtime_operation_t>& operation, const std::string& host, const std::string& path, const std::map<std::string, std::string>& headers, const std::string& body, std::function<std::string(const nlohmann::json&)> response_parser);
    static std::string build_chat_prompt(const std::string& user_message, const std::vector<std::pair<std::string, std::string>>& history);
};


inline std::unique_ptr<standalone_ai_client_t> g_sa_ai_client;
