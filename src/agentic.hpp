#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>

#include <ida.hpp>
#include <kernwin.hpp>
#include <nlohmann/json.hpp>

class AIClient;

namespace agentic
{

struct config_t
{
    double temperature = 0.15;
    bool auto_approve = true;
    bool verbose_logging = true;
    int max_context_tokens = 1000000;
    int output_token_reserve = 65536;
    int max_tool_result_chars = 24576;
    int agentic_output_tokens = 16384;
    int synthesis_output_tokens = 16384;
    int max_rounds = 25;
    std::string user_message;
    std::string context_block;
    std::string chat_history;
};

struct tool_execution_t
{
    std::string tool_name;
    nlohmann::json params;
    bool success;
    std::string message;
    nlohmann::json data;
};

struct result_t
{
    std::string final_response;
    std::vector<tool_execution_t> tool_results;
    bool was_cancelled = false;
};

enum class status_type_t
{
    thinking,
    calling_ai,
    executing_tool,
    tool_complete,
    final_response,
    new_round
};

struct status_update_t
{
    status_type_t type;
    int round = 0;
    std::string message;
    std::string tool_name;
    std::string reasoning;
    bool tool_success = false;
    std::vector<std::string> pending_tools;
};

using progress_fn = std::function<void(int round, const std::string& status)>;
using status_fn = std::function<void(const status_update_t& status)>;
using stream_fn = std::function<void(const std::string& chunk)>;

std::string build_agentic_prompt(
    const std::string& user_message,
    const std::string& context_block,
    const std::string& chat_history = "");

result_t run(
    AIClient* client,
    const std::string& initial_prompt,
    const config_t& config = {},
    std::atomic<bool>* cancelled = nullptr,
    progress_fn on_progress = nullptr,
    status_fn on_status = nullptr,
    stream_fn on_stream = nullptr);

bool has_tool_calls(const std::string& response);

nlohmann::json extract_tool_calls(const std::string& response);

std::string format_tool_results(const std::vector<tool_execution_t>& results, size_t max_chars_per_result = 4096);

size_t estimate_tokens(const std::string& text);

}
