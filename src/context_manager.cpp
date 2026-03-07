

#include "context_manager.hpp"
#include "aida_pro.hpp"
#include "ai_client.hpp"

#include <sstream>
#include <algorithm>
#include <chrono>

namespace context_manager
{

static const char* SUMMARY_PROMPT_TEMPLATE = R"(Summarize the following conversation history concisely.
Focus on preserving:
1. Key findings (specific addresses, function names, struct layouts, offsets)
2. Actions taken (renames, type changes, comments added)
3. Important decompilation results and their conclusions
4. Any verified vulnerabilities or security findings
5. User's original objectives and progress toward them

Omit raw tool output data, verbose code listings, and intermediate reasoning.
Keep the summary under 500 words. Use bullet points for findings.

CONVERSATION HISTORY:
%s

CONCISE SUMMARY:)";

ContextWindowManager::ContextWindowManager(const config_t& cfg)
    : m_config(cfg)
{}

size_t ContextWindowManager::estimate_tokens(const std::string& text) const
{
    if (text.empty()) return 0;
    return static_cast<size_t>(text.size() / m_config.chars_per_token) + 1;
}

size_t ContextWindowManager::estimate_tokens(const std::vector<message_t>& messages) const
{
    size_t total = 0;
    for (auto& m : messages)
    {
        total += estimate_tokens(m.content);
        total += estimate_tokens(m.role);
        total += 4;
    }
    return total;
}

size_t ContextWindowManager::available_tokens(const std::string& system_prompt,
                                               const std::vector<message_t>& history) const
{
    size_t used = estimate_tokens(system_prompt) + estimate_tokens(history);
    size_t budget = static_cast<size_t>(m_config.max_context_tokens - m_config.output_reserve);
    return used < budget ? budget - used : 0;
}

bool ContextWindowManager::needs_compression(const std::string& system_prompt,
                                              const std::vector<message_t>& history) const
{
    size_t used = estimate_tokens(system_prompt) + estimate_tokens(history);
    size_t budget = static_cast<size_t>(m_config.max_context_tokens - m_config.output_reserve);
    double usage = static_cast<double>(used) / budget;
    return usage >= m_config.compression_trigger;
}

std::string ContextWindowManager::build_summary_prompt(
    const std::vector<message_t>& old_messages) const
{
    std::ostringstream transcript;
    for (auto& m : old_messages)
    {
        transcript << "[" << m.role << "]: ";

        if (m.content.size() > 500)
            transcript << m.content.substr(0, 500) << "... (truncated)\n";
        else
            transcript << m.content << "\n";
    }

    char buf[65536];
    qsnprintf(buf, sizeof(buf), SUMMARY_PROMPT_TEMPLATE, transcript.str().c_str());
    return buf;
}

std::string ContextWindowManager::extractive_summary(
    const std::vector<message_t>& messages) const
{
    std::ostringstream ss;
    ss << "[Previous conversation summary]\n";

    for (auto& m : messages)
    {
        if (m.role == "user")
        {
            ss << "- User asked: ";
            if (m.content.size() > 200)
                ss << m.content.substr(0, 200) << "...";
            else
                ss << m.content;
            ss << "\n";
        }
        else if (m.role == "assistant")
        {

            std::istringstream iss(m.content);
            std::string line;
            int extracted = 0;
            while (std::getline(iss, line) && extracted < 10)
            {
                if (line.find("0x") != std::string::npos ||
                    line.find("renamed") != std::string::npos ||
                    line.find("found") != std::string::npos ||
                    line.find("identified") != std::string::npos ||
                    line.find("struct") != std::string::npos ||
                    line.find("vulnerability") != std::string::npos)
                {
                    std::string trimmed = line;
                    if (trimmed.size() > 150) trimmed = trimmed.substr(0, 150) + "...";
                    ss << "  " << trimmed << "\n";
                    ++extracted;
                }
            }
        }
    }

    return ss.str();
}

std::vector<message_t> ContextWindowManager::compress(
    const std::string& system_prompt,
    const std::vector<message_t>& history,
    AIClient* client)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    if (!needs_compression(system_prompt, history))
        return history;

    size_t total = history.size();
    size_t keep_count = static_cast<size_t>(m_config.min_recent_messages);
    if (keep_count >= total)
        return history;


    std::vector<message_t> old_msgs(history.begin(), history.begin() + (total - keep_count));
    std::vector<message_t> recent_msgs(history.begin() + (total - keep_count), history.end());

    m_stats.original_messages += static_cast<int>(old_msgs.size());
    m_stats.original_tokens += estimate_tokens(old_msgs);

    std::string summary;

    if (client)
    {

        std::string prompt = build_summary_prompt(old_msgs);
        summary = client->blocking_generate(prompt, 0.3);

        if (summary.empty() || summary.substr(0, 6) == "Error:")
        {

            summary = extractive_summary(old_msgs);
        }
    }
    else
    {
        summary = extractive_summary(old_msgs);
    }


    std::vector<message_t> compressed;

    message_t summary_msg;
    summary_msg.role = "system";
    summary_msg.content = summary;
    summary_msg.round = -1;
    summary_msg.timestamp_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());
    compressed.push_back(summary_msg);

    for (auto& m : recent_msgs)
        compressed.push_back(m);

    m_stats.compressed_messages += 1;
    m_stats.compressed_tokens += estimate_tokens(summary);
    ++m_stats.compressions_performed;

    return compressed;
}

std::vector<message_t> ContextWindowManager::emergency_truncate(
    const std::vector<message_t>& history) const
{
    if (history.size() <= static_cast<size_t>(m_config.min_recent_messages))
        return history;


    size_t keep = static_cast<size_t>(m_config.min_recent_messages);
    std::vector<message_t> result;

    message_t truncation_notice;
    truncation_notice.role = "system";
    truncation_notice.content = "[Earlier conversation was truncated due to context limits. "
                                 "Only the most recent messages are preserved.]";
    truncation_notice.round = -1;
    result.push_back(truncation_notice);

    for (size_t i = history.size() - keep; i < history.size(); ++i)
        result.push_back(history[i]);

    return result;
}

std::vector<message_t> ContextWindowManager::validate_tool_pairs(
    const std::vector<message_t>& history) const
{
    std::vector<message_t> result;


    bool pending_tool_call = false;

    for (size_t i = 0; i < history.size(); ++i)
    {
        auto& m = history[i];

        if (m.role == "tool_call")
        {

            bool has_result = false;
            for (size_t j = i + 1; j < history.size(); ++j)
            {
                if (history[j].role == "tool_result") { has_result = true; break; }
                if (history[j].role == "assistant" || history[j].role == "user") break;
            }
            if (has_result)
            {
                result.push_back(m);
                pending_tool_call = true;
            }

        }
        else if (m.role == "tool_result")
        {
            if (pending_tool_call)
            {
                result.push_back(m);
                pending_tool_call = false;
            }

        }
        else
        {
            pending_tool_call = false;
            result.push_back(m);
        }
    }

    return result;
}

std::string ContextWindowManager::fit_to_budget(const std::string& text,
                                                 size_t max_tokens) const
{
    size_t est = estimate_tokens(text);
    if (est <= max_tokens) return text;


    size_t max_chars = static_cast<size_t>(max_tokens * m_config.chars_per_token);
    if (max_chars >= text.size()) return text;
    return text.substr(0, max_chars) + "\n... (truncated to fit context window)";
}

compression_stats_t ContextWindowManager::get_stats() const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_stats;
}

void ContextWindowManager::reset_stats()
{
    std::lock_guard<std::mutex> lk(m_mtx);
    m_stats = {};
}

}
