#include "aida_pro.hpp"

static std::string get_trimmed_json_string(const nlohmann::json& j, const char* key, const std::string& default_val)
{
    std::string val = j.value(key, default_val);
    qstring q_val = val.c_str();
    q_val.trim2();
    return q_val.c_str();
}

settings_t g_settings;

const std::vector<std::string> settings_t::gemini_models = {
    "gemini-3-pro-preview",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-pro-latest",
    "gemini-1.5-pro",
    "gemini-1.5-pro-002",
    "gemini-1.5-flash-latest",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
    "gemini-1.5-flash-8b-latest",
    "gemini-2.0-flash-exp",
    "gemini-2.0-flash-lite-preview",
    "gemini-2.0-pro-exp",
    "gemini-2.0-flash-thinking-exp",
    "gemma-3-1b-it",
    "gemma-3-4b-it",
    "gemma-3-12b-it",
    "gemma-3-27b-it",
    "gemma-3n-e4b-it",
    "gemma-3n-e2b-it"
};

const std::vector<std::string> settings_t::openai_models = {
  "gpt-5.1 Instant",
  "gpt-5.1 Thinking",
  "gpt-5",
  "gpt-5-mini",
  "gpt-5-nano",
  "o3-pro",
  "o3",
  "o3-mini",
  "o1-pro",
  "o1",
  "o4-mini",
  "gpt-4.5-preview",
  "gpt-4.1",
  "gpt-4.1-mini",
  "gpt-4.1-nano",
  "gpt-4o",
  "gpt-4-turbo",
  "gpt-4",
  "gpt-4o-mini",
  "gpt-3.5-turbo",
  "gpt-3.5-turbo-16k",
};

const std::vector<std::string> settings_t::openrouter_models = {
  "moonshotai/kimi-k2:free",
  "openai/gpt-oss-20b:free",
  "z-ai/glm-4.5-air:free",
  "tngtech/deepseek-r1t2-chimera:free",
  
};

const std::vector<std::string> settings_t::anthropic_models = {
  "claude-opus-4-5 (High Effort)",
  "claude-opus-4-5 (Medium Effort)",
  "claude-opus-4-5 (Low Effort)",
  "claude-sonnet-4-5",
  "claude-haiku-4-5",
  "claude-opus-4-1",
  "claude-opus-4",
  "claude-sonnet-4",
  "claude-3-7-sonnet-thought",
  "claude-3-7-sonnet",
  "claude-3.5-sonnet-latest",
  "claude-3.5-haiku-latest",
  "claude-3-opus-latest",
  "claude-3-sonnet-latest",
  "claude-3-haiku-latest",
  "claude-2.1",
  "claude-2",
  "claude-instant-v1.2",
};

const std::vector<std::string> settings_t::copilot_models = {
    "claude-sonnet-4",
    "claude-3.7-sonnet-thought",
    "gemini-2.5-pro",
    "claude-3.7-sonnet",
    "gpt-4.1-2025-04-14",
    "gpt-4.1",
    "o4-mini-2025-04-16",
    "o4-mini",
    "o3-mini-2025-01-31",
    "o3-mini",
    "o3-mini-paygo",
    "claude-3.5-sonnet",
    "gemini-2.0-flash-001",
    "gpt-4o-2024-11-20",
    "gpt-4o-2024-08-06",
    "gpt-4o-2024-05-13",
    "gpt-4o",
    "gpt-4o-copilot",
    "gpt-4-o-preview",
    "gpt-4-0125-preview",
    "gpt-4",
    "gpt-4-0613",
    "gpt-4o-mini-2024-07-18",
    "gpt-4o-mini",
    "gpt-3.5-turbo",
    "gpt-3.5-turbo-0613",
};

const std::vector<std::string> settings_t::local_llm_models = {
    "llama3.3:latest",
    "llama3.1:latest",
    "llama3:latest",
    "qwen3:latest",
    "qwen2.5-coder:latest",
    "deepseek-r1:latest",
    "deepseek-coder-v2:latest",
    "codellama:latest",
    "mistral:latest",
    "mixtral:latest",
    "phi4:latest",
    "gemma3:latest",
    "command-r:latest",
};

static void to_json(nlohmann::json& j, const settings_t& s)
{
    j = nlohmann::json{
        {"api_provider", s.api_provider},
        {"gemini_api_key", s.gemini_api_key},
        {"gemini_model_name", s.gemini_model_name},
        {"gemini_base_url", s.gemini_base_url},
        {"openai_api_key", s.openai_api_key},
        {"openai_model_name", s.openai_model_name},
        {"openai_base_url", s.openai_base_url},
        {"openrouter_api_key", s.openrouter_api_key},
        {"openrouter_model_name", s.openrouter_model_name},
        {"anthropic_api_key", s.anthropic_api_key},
        {"anthropic_model_name", s.anthropic_model_name},
        {"anthropic_base_url", s.anthropic_base_url},
        {"copilot_proxy_address", s.copilot_proxy_address},
        {"copilot_model_name", s.copilot_model_name},
        {"local_llm_base_url", s.local_llm_base_url},
        {"local_llm_model_name", s.local_llm_model_name},
        {"local_llm_api_key", s.local_llm_api_key},
        {"local_llm_context_window", s.local_llm_context_window},
        {"xref_context_count", s.xref_context_count},
        {"xref_analysis_depth", s.xref_analysis_depth},
        {"xref_code_snippet_lines", s.xref_code_snippet_lines},
        {"bulk_processing_delay", s.bulk_processing_delay},
        {"max_root_func_scan_count", s.max_root_func_scan_count},
        {"max_root_func_candidates", s.max_root_func_candidates},
        {"custom_prompts", s.custom_prompts},
        {"active_prompt_name", s.active_prompt_name},
        {"temperature", s.temperature},
        {"check_for_updates", s.check_for_updates},
        {"mcp_enabled", s.mcp_enabled},
        {"mcp_port", s.mcp_port},
        {"license_key", s.license_key},
        {"license_validated_at", s.license_validated_at},
        {"license_hwid", s.license_hwid}
    };
}

static void from_json(const nlohmann::json& j, settings_t& s)
{
    settings_t d;
    s.api_provider = j.value("api_provider", d.api_provider);

    s.gemini_api_key = get_trimmed_json_string(j, "gemini_api_key", d.gemini_api_key);
    s.gemini_model_name = j.value("gemini_model_name", d.gemini_model_name);
    s.gemini_base_url = get_trimmed_json_string(j, "gemini_base_url", d.gemini_base_url);

    s.openai_api_key = get_trimmed_json_string(j, "openai_api_key", d.openai_api_key);
    s.openai_model_name = j.value("openai_model_name", d.openai_model_name);
    s.openai_base_url = get_trimmed_json_string(j, "openai_base_url", d.openai_base_url);

    s.openrouter_api_key = get_trimmed_json_string(j, "openrouter_api_key", d.openrouter_api_key);
    s.openrouter_model_name = j.value("openrouter_model_name", d.openrouter_model_name);

    s.anthropic_api_key = get_trimmed_json_string(j, "anthropic_api_key", d.anthropic_api_key);
    s.anthropic_model_name = j.value("anthropic_model_name", d.anthropic_model_name);
    s.anthropic_base_url = get_trimmed_json_string(j, "anthropic_base_url", d.anthropic_base_url);

    s.copilot_proxy_address = j.value("copilot_proxy_address", d.copilot_proxy_address);
    s.copilot_model_name = j.value("copilot_model_name", d.copilot_model_name);

    s.local_llm_base_url = get_trimmed_json_string(j, "local_llm_base_url", d.local_llm_base_url);
    s.local_llm_model_name = j.value("local_llm_model_name", d.local_llm_model_name);
    s.local_llm_api_key = get_trimmed_json_string(j, "local_llm_api_key", d.local_llm_api_key);
    s.local_llm_context_window = j.value("local_llm_context_window", d.local_llm_context_window);

    s.xref_context_count = j.value("xref_context_count", d.xref_context_count);
    s.xref_analysis_depth = j.value("xref_analysis_depth", d.xref_analysis_depth);
    s.xref_code_snippet_lines = j.value("xref_code_snippet_lines", d.xref_code_snippet_lines);

    s.bulk_processing_delay = j.value("bulk_processing_delay", d.bulk_processing_delay);

    s.max_root_func_scan_count = j.value("max_root_func_scan_count", d.max_root_func_scan_count);
    s.max_root_func_candidates = j.value("max_root_func_candidates", d.max_root_func_candidates);

    s.temperature = j.value("temperature", d.temperature);
    s.check_for_updates = j.value("check_for_updates", d.check_for_updates);

    s.mcp_enabled = j.value("mcp_enabled", d.mcp_enabled);
    s.mcp_port = j.value("mcp_port", d.mcp_port);

    s.license_key = j.value("license_key", d.license_key);
    s.license_validated_at = j.value("license_validated_at", d.license_validated_at);
    s.license_hwid = j.value("license_hwid", d.license_hwid);

    if (j.contains("custom_prompts"))
        j.at("custom_prompts").get_to(s.custom_prompts);
    s.active_prompt_name = j.value("active_prompt_name", d.active_prompt_name);
}

static qstring get_config_file()
{
    qstring path = get_user_idadir();
    path.append("/ai_assistant.cfg");
    return path;
}

static bool save_settings_to_file(const settings_t& settings, const qstring& path)
{
    try
    {
        nlohmann::json j = settings;
        std::string json_str = j.dump(4);

        FILE* fp = qfopen(path.c_str(), "wb");
        if (fp == nullptr)
        {
            warning(OBFSTR_C("Failed to open settings file for writing: %s"), path.c_str());
            return false;
        }

        file_janitor_t fj(fp);

        size_t written = qfwrite(fp, json_str.c_str(), json_str.length());
        if (written != json_str.length())
        {
            warning(OBFSTR_C("Failed to write all settings to %s"), path.c_str());
            return false;
        }

        msg(OBFSTR_C("Settings saved to %s\n"), path.c_str());
        return true;
    }
    catch (const std::exception& e)
    {
        warning(OBFSTR_C("Failed to serialize settings: %s"), e.what());
        return false;
    }
}

static bool load_settings_from_file(settings_t& settings, const qstring& path)
{
    if (!qfileexist(path.c_str()))
        return false;

    FILE* fp = qfopen(path.c_str(), "rb");
    if (fp == nullptr)
        return false;

    file_janitor_t fj(fp);

    uint64 file_size = qfsize(fp);
    if (file_size == 0)
        return false;

    qstring json_data;
    json_data.resize(file_size);
    if (qfread(fp, json_data.begin(), file_size) != file_size)
    {
        warning(OBFSTR_C("Failed to read settings file: %s"), path.c_str());
        return false;
    }

    try
    {
        nlohmann::json j = nlohmann::json::parse(json_data.c_str());

        bool missing = false;
        auto req = [&](const char* key){ if (!j.contains(key)) missing = true; };
        req("api_provider");
        req("gemini_api_key"); req("gemini_model_name"); req("gemini_base_url");
        req("openai_api_key"); req("openai_model_name"); req("openai_base_url");
        req("openrouter_api_key"); req("openrouter_model_name");
        req("anthropic_api_key"); req("anthropic_model_name"); req("anthropic_base_url");
        req("copilot_proxy_address"); req("copilot_model_name");
        req("local_llm_base_url"); req("local_llm_model_name"); req("local_llm_api_key");
        req("local_llm_context_window");
        req("xref_context_count"); req("xref_analysis_depth"); req("xref_code_snippet_lines");
        req("bulk_processing_delay");
        req("max_root_func_scan_count"); req("max_root_func_candidates");
        req("custom_prompts"); req("active_prompt_name");
        req("temperature");
        req("check_for_updates");
        req("mcp_enabled");
        req("mcp_port");

        settings = j.get<settings_t>();

        if (missing)
        {
            save_settings_to_file(settings, path);
        }
        return true;
    }
    catch (const std::exception& e)
    {
        warning(OBFSTR_C("Could not parse config file %s: %s"), path.c_str(), e.what());
        return false;
    }
}


settings_t::settings_t() :
    api_provider(""),
    gemini_api_key(""),
    gemini_model_name("gemini-2.5-flash"),
    gemini_base_url(""),
    openai_api_key(""),
    openai_model_name("gpt-5"),
    openai_base_url(""),
    openrouter_api_key(""),
    openrouter_model_name("moonshotai/kimi-k2:free"),
    anthropic_api_key(""),
    anthropic_model_name("claude-sonnet-4-5"),
    anthropic_base_url(""),
    copilot_proxy_address("http://127.0.0.1:4141"),
    copilot_model_name("gpt-4.1"),
    local_llm_base_url("http://localhost:1234"),
    local_llm_model_name(""),
    local_llm_api_key(""),
    local_llm_context_window(8192),
    xref_context_count(5),
    xref_analysis_depth(3),
    xref_code_snippet_lines(30),
    bulk_processing_delay(1.5),
    max_root_func_scan_count(40),
    max_root_func_candidates(40),
    temperature(0.1),
    check_for_updates(true),
    mcp_enabled(true),
    mcp_port(13120),
    license_key(""),
    license_validated_at(0),
    license_hwid("")
{
}

void settings_t::save()
{
    save_settings_to_file(*this, get_config_file());
}

void settings_t::load(aida_plugin_t* plugin_instance)
{
    bool has_env_keys = false;
    qstring val;

    if (gemini_api_key.empty() && qgetenv("GEMINI_API_KEY", &val))
    {
        val.trim2();
        gemini_api_key = val.c_str();
        has_env_keys = true;
    }
    if (openai_api_key.empty() && qgetenv("OPENAI_API_KEY", &val))
    {
        val.trim2();
        openai_api_key = val.c_str();
        has_env_keys = true;
    }
    if (openrouter_api_key.empty() && qgetenv("OPENROUTER_API_KEY", &val))
    {
        val.trim2();
        openrouter_api_key = val.c_str();
        has_env_keys = true;
    }
    if (anthropic_api_key.empty() && qgetenv("ANTHROPIC_API_KEY", &val))
    {
        val.trim2();
        anthropic_api_key = val.c_str();
        has_env_keys = true;
    }

    if (has_env_keys)
    {
        msg(OBFSTR_C("Loaded one or more API keys from environment variables.\n"));
    }

    bool config_exists_and_valid = load_from_file();

    if (custom_prompts.empty())
    {
        msg(OBFSTR_C("No custom prompts found, loading defaults.\n"));
        custom_prompts["Anti-Cheat / Anti-Tamper"] = ANTICHEAT_RE_PROMPT;
        custom_prompts["Windows Kernel / Drivers"] = KERNEL_DRIVER_PROMPT;
        custom_prompts["Crackme / CTF Challenges"] = CRACKME_PROMPT;
        custom_prompts["Malware Analysis"] = MALWARE_ANALYSIS_PROMPT;
        custom_prompts["Application RE (General)"] = APPLICATION_RE_PROMPT;
        custom_prompts["Firmware / Embedded"] = FIRMWARE_ANALYSIS_PROMPT;
        custom_prompts["Cryptography"] = CRYPTO_ANALYSIS_PROMPT;
        custom_prompts["Network Protocol"] = NETWORK_PROTOCOL_PROMPT;
        custom_prompts["iOS / macOS"] = IOS_MACOS_RE_PROMPT;
        custom_prompts["Android"] = ANDROID_RE_PROMPT;
        custom_prompts["Linux Userspace / Kernel"] = LINUX_RE_PROMPT;
        custom_prompts["Unity Game (IL2CPP)"] = UNITY_GAME_PROMPT;
        custom_prompts["Cheat Loader / Malware"] = CHEAT_LOADER_PROMPT;
        save();
    }

    if (!config_exists_and_valid || api_provider.empty())
    {
        info(OBFSTR_C("Welcome! Please configure the plugin to begin."));
        SettingsForm::show_and_apply(plugin_instance);
        return;
    }

    if (config_exists_and_valid)
    {
        msg(OBFSTR_C("Loaded settings from %s\n"), get_config_file().c_str());
    }

    if (!api_provider.empty() && get_active_api_key().empty())
    {
        prompt_for_api_key();
    }
}

bool settings_t::load_from_file()
{
    return load_settings_from_file(*this, get_config_file());
}

std::string settings_t::get_active_api_key() const
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    if (provider == "gemini") return gemini_api_key;
    if (provider == "openai") return openai_api_key;
    if (provider == "openrouter") return openrouter_api_key;
    if (provider == "anthropic") return anthropic_api_key;
    if (provider == "copilot") return copilot_proxy_address;
    if (provider == "local llm") return local_llm_base_url;
    return "";
}

int settings_t::get_model_context_window(const std::string& model_name)
{
    static const std::unordered_map<std::string, int> context_windows = {
        {"gemini-3-pro-preview",             1000000},
        {"gemini-2.5-pro",                   1048576},
        {"gemini-2.5-flash",                 1048576},
        {"gemini-2.5-flash-lite",            1048576},
        {"gemini-2.0-flash",                 1048576},
        {"gemini-2.0-flash-lite",            1048576},
        {"gemini-1.5-pro-latest",            2097152},
        {"gemini-1.5-pro",                   2097152},
        {"gemini-1.5-pro-002",               2097152},
        {"gemini-1.5-flash-latest",          1048576},
        {"gemini-1.5-flash",                 1048576},
        {"gemini-1.5-flash-8b",              1048576},
        {"gemini-1.5-flash-8b-latest",       1048576},
        {"gemini-2.0-flash-exp",             1048576},
        {"gemini-2.0-flash-lite-preview",    1048576},
        {"gemini-2.0-pro-exp",               1048576},
        {"gemini-2.0-flash-thinking-exp",    1048576},
        {"gemma-3-1b-it",                      32768},
        {"gemma-3-4b-it",                      32768},
        {"gemma-3-12b-it",                     32768},
        {"gemma-3-27b-it",                     32768},
        {"gemma-3n-e4b-it",                    32768},
        {"gemma-3n-e2b-it",                    32768},

        {"gpt-5.1 Instant",                  1047576},
        {"gpt-5.1 Thinking",                 1047576},
        {"gpt-5",                             1047576},
        {"gpt-5-mini",                        1047576},
        {"gpt-5-nano",                         524288},
        {"o3-pro",                             200000},
        {"o3",                                 200000},
        {"o3-mini",                            200000},
        {"o1-pro",                             200000},
        {"o1",                                 200000},
        {"o4-mini",                            200000},
        {"gpt-4.5-preview",                   128000},
        {"gpt-4.1",                           1047576},
        {"gpt-4.1-mini",                      1047576},
        {"gpt-4.1-nano",                      1047576},
        {"gpt-4o",                             128000},
        {"gpt-4-turbo",                        128000},
        {"gpt-4",                                8192},
        {"gpt-4o-mini",                        128000},
        {"gpt-3.5-turbo",                      16385},
        {"gpt-3.5-turbo-16k",                  16385},

        {"moonshotai/kimi-k2:free",            131072},
        {"openai/gpt-oss-20b:free",            128000},
        {"z-ai/glm-4.5-air:free",             128000},
        {"tngtech/deepseek-r1t2-chimera:free", 164000},

        {"claude-opus-4-5 (High Effort)",      200000},
        {"claude-opus-4-5 (Medium Effort)",    200000},
        {"claude-opus-4-5 (Low Effort)",       200000},
        {"claude-sonnet-4-5",                  200000},
        {"claude-haiku-4-5",                   200000},
        {"claude-opus-4-1",                    200000},
        {"claude-opus-4",                      200000},
        {"claude-sonnet-4",                    200000},
        {"claude-3-7-sonnet-thought",          200000},
        {"claude-3-7-sonnet",                  200000},
        {"claude-3.7-sonnet-thought",          200000},
        {"claude-3.7-sonnet",                  200000},
        {"claude-3.5-sonnet-latest",           200000},
        {"claude-3.5-haiku-latest",            200000},
        {"claude-3.5-sonnet",                  200000},
        {"claude-3-opus-latest",               200000},
        {"claude-3-sonnet-latest",             200000},
        {"claude-3-haiku-latest",              200000},
        {"claude-2.1",                         200000},
        {"claude-2",                           100000},
        {"claude-instant-v1.2",                100000},

        {"gpt-4.1-2025-04-14",               1047576},
        {"o4-mini-2025-04-16",                 200000},
        {"o3-mini-2025-01-31",                 200000},
        {"o3-mini-paygo",                      200000},
        {"gemini-2.0-flash-001",              1048576},
        {"gpt-4o-2024-11-20",                  128000},
        {"gpt-4o-2024-08-06",                  128000},
        {"gpt-4o-2024-05-13",                  128000},
        {"gpt-4o-copilot",                     128000},
        {"gpt-4-o-preview",                    128000},
        {"gpt-4-0125-preview",                 128000},
        {"gpt-4-0613",                           8192},
        {"gpt-4o-mini-2024-07-18",             128000},
        {"gpt-3.5-turbo-0613",                  16385},
    };

    auto it = context_windows.find(model_name);
    if (it != context_windows.end())
        return it->second;

    return 128000;
}

int settings_t::get_active_context_window() const
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    std::string model;
    if (provider == "gemini")          model = gemini_model_name;
    else if (provider == "openai")     model = openai_model_name;
    else if (provider == "openrouter") model = openrouter_model_name;
    else if (provider == "anthropic")  model = anthropic_model_name;
    else if (provider == "copilot")    model = copilot_model_name;
    else if (provider == "local llm") return local_llm_context_window > 0 ? local_llm_context_window : 8192;
    else                               return 128000;
    return get_model_context_window(model);
}

void settings_t::prompt_for_api_key()
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());

    if (provider == "copilot")
    {
        warning(OBFSTR_C("Copilot provider is selected, but the proxy address is not configured. Please set it in the settings dialog."));
        return;
    }

    if (provider == "local llm")
    {
        warning(OBFSTR_C("Local LLM provider is selected, but the server URL is not configured. Please set it in the settings dialog."));
        return;
    }

    qstring provider_name = api_provider.c_str();
    if (!provider_name.empty())
        provider_name[0] = qtoupper(provider_name[0]);

    warning(OBFSTR_C("%s API key not found."), provider_name.c_str());

    qstring key;
    qstring question;
    question.sprnt("Please enter your %s API key to continue:", provider_name.c_str());
    if (ask_str(&key, HIST_SRCH, question.c_str()))
    {
        if (provider == "gemini") gemini_api_key = key.c_str();
        else if (provider == "openai") openai_api_key = key.c_str();
        else if (provider == "openrouter") openrouter_api_key = key.c_str();
        else if (provider == "anthropic") anthropic_api_key = key.c_str();
        save();
    }
    else
    {
        warning(OBFSTR_C("Plugin will be disabled until an API key is provided for %s."), provider_name.c_str());
    }
}