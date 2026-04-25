#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <map>


namespace context_mgmt {


struct model_info_t
{
    int         context_window     = 128000;
    bool        supports_tools     = true;
    bool        supports_reasoning = false;
    bool        supports_caching   = false;
    bool        supports_images    = false;
    double      input_price        = 3.0;
    double      output_price       = 15.0;
    double      cache_read_price   = 0.30;
    double      cache_write_price  = 3.75;
    bool        use_developer_role = false;
    bool        use_max_completion_tokens = false;
    std::string reasoning_effort_param;
    bool        openai_compatible  = false;
};


inline const model_info_t& get_model_info(const std::string& model)
{
    static const std::map<std::string, model_info_t> db = {
        {"claude-sonnet-4-6",          {200000, true, true,  true, true,    3.0,   15.0,   0.30,  3.75,  false, false, "", false}},
        {"claude-sonnet-4-5",          {200000, true, true,  true, true,    3.0,   15.0,   0.30,  3.75,  false, false, "", false}},
        {"claude-sonnet-4-20250514",   {200000, true, true,  true, true,    3.0,   15.0,   0.30,  3.75,  false, false, "", false}},
        {"claude-opus-4-6",            {200000, true, true,  true, true,   15.0,   75.0,   1.50, 18.75,  false, false, "", false}},
        {"claude-opus-4-5-20251101",   {200000, true, true,  true, true,   15.0,   75.0,   1.50, 18.75,  false, false, "", false}},
        {"claude-opus-4-1-20250805",   {200000, true, true,  true, true,   15.0,   75.0,   1.50, 18.75,  false, false, "", false}},
        {"claude-opus-4-20250514",     {200000, true, true,  true, true,   15.0,   75.0,   1.50, 18.75,  false, false, "", false}},
        {"claude-3-5-sonnet-20241022", {200000, true, false, true, true,    3.0,   15.0,   0.30,  3.75,  false, false, "", false}},
        {"claude-3-5-haiku-20241022",  {200000, true, false, true, true,    0.80,   4.0,   0.08,  1.0,   false, false, "", false}},
        {"claude-haiku-4-5-20251001",  {200000, true, false, true, true,    0.80,   4.0,   0.08,  1.0,   false, false, "", false}},
        {"claude-3-opus-20240229",     {200000, true, false, true, true,   15.0,   75.0,   1.50, 18.75,  false, false, "", false}},

        {"gpt-5.4",                   {1000000, true, false, true, true,    2.0,    8.0,   0.50,  2.0,   false, false, "", true}},
        {"gpt-5.4-mini",             { 1000000, true, false, true, true,    0.40,   1.60,  0.10,  0.40,  false, false, "", true}},
        {"gpt-5.2",                   { 200000, true, false, true, true,    2.0,    8.0,   0.50,  2.0,   false, false, "", true}},
        {"gpt-5.1",                   { 200000, true, false, true, true,    2.0,    8.0,   0.50,  2.0,   false, false, "", true}},
        {"gpt-5.1-codex",            { 200000, true, false, true, true,    2.0,    8.0,   0.50,  2.0,   false, false, "", true}},
        {"gpt-5.1-codex-max",        { 200000, true, false, true, true,    2.0,    8.0,   0.50,  2.0,   false, false, "", true}},
        {"gpt-5",                     { 200000, true, false, true, true,    2.0,    8.0,   0.50,  2.0,   false, false, "", true}},
        {"gpt-5-mini",               { 200000, true, false, true, true,    0.40,   1.60,  0.10,  0.40,  false, false, "", true}},
        {"gpt-4.1",                   { 200000, true, false, true, true,    2.0,    8.0,   0.50,  2.0,   false, false, "", true}},
        {"gpt-4.1-mini",             { 200000, true, false, true, true,    0.40,   1.60,  0.10,  0.40,  false, false, "", true}},
        {"gpt-4.1-nano",             { 200000, true, false, true, true,    0.10,   0.40,  0.025, 0.10,  false, false, "", true}},
        {"gpt-4o",                    { 128000, true, false, true, true,    2.50,  10.0,   1.25,  2.50,  false, false, "", true}},
        {"gpt-4o-mini",              { 128000, true, false, true, true,    0.15,   0.60,  0.075, 0.15,  false, false, "", true}},
        {"o3",                        { 200000, true, true,  true, true,   10.0,   40.0,   2.50, 10.0,   true,  true, "high", true}},
        {"o3-high",                   { 200000, true, true,  true, true,   10.0,   40.0,   2.50, 10.0,   true,  true, "high", true}},
        {"o3-low",                    { 200000, true, true,  true, true,   10.0,   40.0,   2.50, 10.0,   true,  true, "low",  true}},
        {"o4-mini",                   { 200000, true, true,  true, true,    1.10,   4.40,  0.275, 1.10,  true,  true, "medium", true}},
        {"o4-mini-high",              { 200000, true, true,  true, true,    1.10,   4.40,  0.275, 1.10,  true,  true, "high", true}},
        {"o4-mini-low",               { 200000, true, true,  true, true,    1.10,   4.40,  0.275, 1.10,  true,  true, "low",  true}},
        {"o1",                        { 200000, true, true,  false, true,  15.0,   60.0,   7.50, 15.0,   true,  true, "high", true}},
        {"o1-mini",                   { 128000, true, true,  false, true,   3.0,   12.0,   1.50,  3.0,   true,  true, "medium", true}},

        {"gemini-3.1-pro-preview",    {2000000, true, true,  true, true,    1.25,  10.0,   0.315, 4.50,  false, false, "", false}},
        {"gemini-3-pro-preview",      {2000000, true, true,  true, true,    1.25,  10.0,   0.315, 4.50,  false, false, "", false}},
        {"gemini-2.5-pro",            {1000000, true, true,  true, true,    1.25,  10.0,   0.315, 4.50,  false, false, "", false}},
        {"gemini-2.5-flash",          {1000000, true, true,  true, true,    0.15,   0.60,  0.0375,0.15,  false, false, "", false}},
        {"gemini-flash-latest",       {1000000, true, true,  true, true,    0.15,   0.60,  0.0375,0.15,  false, false, "", false}},
        {"gemini-flash-lite-latest",  {1000000, true, false, true, true,    0.075,  0.30,  0.01,  0.075, false, false, "", false}},

        {"deepseek-chat",             { 128000, true, false, false,false,   0.14,   0.28,  0.014, 0.14,  false, false, "", true}},
        {"deepseek-reasoner",         { 128000, true, true,  false,false,   0.55,   2.19,  0.14,  0.55,  false, false, "", true}},

        {"grok-4.20-beta-0309-reasoning", {131072, true, true, false, true, 3.0, 15.0, 0.0, 0.0, false, false, "", true}},
        {"grok-4-0709",               { 131072, true, false, false, true,   2.0,    10.0,  0.0,   0.0,  false, false, "", true}},
        {"grok-3",                    { 131072, true, false, false, false,  3.0,   15.0,   0.0,   0.0,  false, false, "", true}},

        {"codestral-latest",          { 256000, true, false, false, false,  0.30,   0.90,  0.0,   0.0,  false, false, "", false}},
        {"mistral-large-latest",      { 128000, true, false, false, true,   2.0,    6.0,   0.0,   0.0,  false, false, "", false}},
    };

    auto it = db.find(model);
    if (it != db.end()) return it->second;

    static const model_info_t fallback = {128000, true, false, false, false, 3.0, 15.0, 0.30, 3.75, false, false, "", true};

    for (auto& [k, v] : db) {
        if (model.find(k) != std::string::npos)
            return v;
    }
    return fallback;
}


inline int64_t estimate_token_count(const std::string& text)
{
    if (text.empty()) return 0;
    int64_t words = 1;
    int64_t punctuation = 0;
    for (char c : text) {
        if (c == ' ' || c == '\n' || c == '\t' || c == '\r') ++words;
        else if (c == '.' || c == ',' || c == ';' || c == ':' ||
                 c == '(' || c == ')' || c == '{' || c == '}' ||
                 c == '[' || c == ']' || c == '"' || c == '\'') ++punctuation;
    }
    return static_cast<int64_t>(words * 1.3 + punctuation * 0.3 + 10);
}


inline constexpr double TOKEN_BUFFER_PERCENTAGE = 0.10;

inline constexpr double DEFAULT_CONDENSE_THRESHOLD = 0.80;


struct conversation_token_state_t
{
    int64_t total_input_tokens  = 0;
    int64_t total_output_tokens = 0;
    int     context_window      = 128000;
    double  condense_threshold  = DEFAULT_CONDENSE_THRESHOLD;

    bool should_condense() const
    {
        double usable = context_window * (1.0 - TOKEN_BUFFER_PERCENTAGE);
        return total_input_tokens >= static_cast<int64_t>(usable * condense_threshold);
    }

    int64_t tokens_remaining() const
    {
        double usable = context_window * (1.0 - TOKEN_BUFFER_PERCENTAGE);
        return static_cast<int64_t>(usable) - total_input_tokens;
    }

    double usage_percentage() const
    {
        if (context_window <= 0) return 0.0;
        double usable = context_window * (1.0 - TOKEN_BUFFER_PERCENTAGE);
        if (usable <= 0.0) return 100.0;
        return (static_cast<double>(total_input_tokens) / usable) * 100.0;
    }
};


inline std::string build_condensation_prompt(
    const std::vector<std::pair<std::string, std::string>>& old_messages,
    const std::string& task_context = "")
{
    std::string prompt;
    prompt.reserve(8192);

    prompt += "Summarize the following conversation into a concise but complete summary. "
              "Preserve:\n"
              "- Key findings and analysis results\n"
              "- Important addresses, function names, and offsets\n"
              "- Decisions made and their reasoning\n"
              "- Any pending tasks or unanswered questions\n"
              "- Tool results that produced important data\n\n";

    if (!task_context.empty())
        prompt += "Task context: " + task_context + "\n\n";

    prompt += "Conversation to summarize:\n\n";
    for (auto& [role, content] : old_messages) {
        prompt += role + ": " + content.substr(0, 2000) + "\n\n";
    }

    prompt += "\nProvide a structured summary. Be concise but preserve all critical technical details.";
    return prompt;
}


struct truncation_state_t
{
    int first_visible_idx = 0;
    int total_messages    = 0;
    bool is_truncated     = false;

    void apply_truncation(int keep_recent, int total)
    {
        total_messages = total;
        if (total <= keep_recent + 1) {
            first_visible_idx = 0;
            is_truncated = false;
            return;
        }
        first_visible_idx = total - keep_recent;
        if (first_visible_idx < 1) first_visible_idx = 1;
        is_truncated = true;
    }

    void restore()
    {
        first_visible_idx = 0;
        is_truncated = false;
    }
};

}
