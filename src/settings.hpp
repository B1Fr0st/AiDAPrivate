#pragma once

#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

class aida_plugin_t;

class settings_t
{
public:
    std::string api_provider;

    std::string gemini_api_key;
    std::string gemini_model_name;
    std::string gemini_base_url;

    std::string openai_api_key;
    std::string openai_model_name;
    std::string openai_base_url;

    std::string openrouter_api_key;
    std::string openrouter_model_name;

    std::string anthropic_api_key;
    std::string anthropic_model_name;
    std::string anthropic_base_url;

    std::string copilot_proxy_address;
    std::string copilot_model_name;

    std::string local_llm_base_url;
    std::string local_llm_model_name;
    std::string local_llm_api_key;
    int local_llm_context_window;

    int xref_context_count;
    int xref_analysis_depth;
    int xref_code_snippet_lines;
    double bulk_processing_delay;

    int max_root_func_scan_count;
    int max_root_func_candidates;
    double temperature;
    bool check_for_updates;

    bool mcp_enabled;
    int mcp_port;

    std::string license_key;
    int64_t     license_validated_at;
    std::string license_hwid;
    std::string firebase_api_key;

public:
    std::map<std::string, std::string> custom_prompts;
    std::string active_prompt_name;

    static const std::vector<std::string> gemini_models;
    static const std::vector<std::string> openai_models;
    static const std::vector<std::string> openrouter_models;
    static const std::vector<std::string> anthropic_models;
    static const std::vector<std::string> copilot_models;
    static const std::vector<std::string> local_llm_models;

    settings_t();
    void save();
    void load(aida_plugin_t* plugin_instance);
    bool load_from_file();
    std::string get_active_api_key() const;
    int get_active_context_window() const;
    static int get_model_context_window(const std::string& model_name);

private:
    void prompt_for_api_key();
};

extern settings_t g_settings;