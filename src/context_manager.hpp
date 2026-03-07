

#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>

#include <nlohmann/json.hpp>

class AIClient;

namespace context_manager
{


struct config_t
{
    int    max_context_tokens   = 1000000;
    int    output_reserve       = 65536;
    double compression_trigger  = 0.75;
    int    min_recent_messages  = 4;
    int    summary_max_tokens   = 2048;
    double chars_per_token      = 4.0;
};


struct message_t
{
    std::string role;
    std::string content;
    int         round = -1;
    uint64_t    timestamp_ms = 0;
};


struct compression_stats_t
{
    int    original_messages = 0;
    int    compressed_messages = 0;
    size_t original_tokens = 0;
    size_t compressed_tokens = 0;
    int    compressions_performed = 0;
    int    emergency_truncations = 0;
};


class ContextWindowManager
{
public:
    explicit ContextWindowManager(const config_t& cfg = {});


    size_t estimate_tokens(const std::string& text) const;
    size_t estimate_tokens(const std::vector<message_t>& messages) const;


    size_t available_tokens(const std::string& system_prompt,
                            const std::vector<message_t>& history) const;


    bool needs_compression(const std::string& system_prompt,
                           const std::vector<message_t>& history) const;


    std::vector<message_t> compress(const std::string& system_prompt,
                                     const std::vector<message_t>& history,
                                     AIClient* client = nullptr);


    std::vector<message_t> emergency_truncate(const std::vector<message_t>& history) const;


    std::vector<message_t> validate_tool_pairs(const std::vector<message_t>& history) const;


    std::string fit_to_budget(const std::string& text, size_t max_tokens) const;


    compression_stats_t get_stats() const;


    void reset_stats();


    const config_t& get_config() const { return m_config; }
    void set_config(const config_t& cfg) { m_config = cfg; }

private:
    config_t            m_config;
    compression_stats_t m_stats;
    mutable std::mutex  m_mtx;


    std::string build_summary_prompt(const std::vector<message_t>& old_messages) const;


    std::string extractive_summary(const std::vector<message_t>& messages) const;
};

}
