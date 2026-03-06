#include "aida_pro.hpp"
#include "vmp.hpp"

#ifdef __NT__
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#endif

static constexpr uint8_t CFG_OBF_KEY[] = {
    0xA3, 0x7B, 0x1E, 0xD4, 0x5F, 0x92, 0xC8, 0x06,
    0xE1, 0x3A, 0x8D, 0x47, 0xB0, 0x6C, 0xF5, 0x29
};
static constexpr const char CFG_OBF_PREFIX[] = "enc1:";
static constexpr const char CFG_DPAPI_PREFIX[] = "dpapi1:";

static std::string hex_encode_bytes(const unsigned char* data, size_t size)
{
    std::string out;
    out.reserve(size * 2);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i)
    {
        const unsigned char b = data[i];
        out.push_back(digits[(b >> 4) & 0x0F]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

static bool hex_decode_bytes(const std::string& text, std::vector<unsigned char>& out)
{
    if ((text.size() % 2) != 0)
        return false;

    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2)
    {
        unsigned int byte_value = 0;
        std::istringstream iss(text.substr(i, 2));
        iss >> std::hex >> byte_value;
        if (iss.fail())
            return false;
        out.push_back(static_cast<unsigned char>(byte_value));
    }
    return true;
}

#ifdef __NT__
static std::string protect_with_dpapi(const std::string& plaintext, const char* scope)
{
    if (plaintext.empty())
        return plaintext;

    DATA_BLOB input_blob{};
    input_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()));
    input_blob.cbData = static_cast<DWORD>(plaintext.size());

    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(scope));
    entropy_blob.cbData = static_cast<DWORD>(std::strlen(scope));

    DATA_BLOB output_blob{};
    if (!CryptProtectData(&input_blob,
                          L"AiDA Secret",
                          &entropy_blob,
                          nullptr,
                          nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN,
                          &output_blob))
    {
        return "";
    }

    std::string protected_hex = hex_encode_bytes(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return std::string(CFG_DPAPI_PREFIX) + protected_hex;
}

static std::string unprotect_with_dpapi(const std::string& encoded, const char* scope)
{
    if (encoded.compare(0, sizeof(CFG_DPAPI_PREFIX) - 1, CFG_DPAPI_PREFIX) != 0)
        return "";

    std::vector<unsigned char> protected_bytes;
    if (!hex_decode_bytes(encoded.substr(sizeof(CFG_DPAPI_PREFIX) - 1), protected_bytes))
        return "";

    DATA_BLOB input_blob{};
    input_blob.pbData = protected_bytes.data();
    input_blob.cbData = static_cast<DWORD>(protected_bytes.size());

    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(scope));
    entropy_blob.cbData = static_cast<DWORD>(std::strlen(scope));

    DATA_BLOB output_blob{};
    if (!CryptUnprotectData(&input_blob,
                            nullptr,
                            &entropy_blob,
                            nullptr,
                            nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN,
                            &output_blob))
    {
        return "";
    }

    std::string plaintext(reinterpret_cast<const char*>(output_blob.pbData), output_blob.cbData);
    SecureZeroMemory(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return plaintext;
}
#endif

static std::string obfuscate_key(const std::string& plain)
{
    VMP_VIRT("obf_key");
    if (plain.empty())
    {
        VMP_END;
        return plain;
    }

#ifdef __NT__
    if (std::string protected_value = protect_with_dpapi(plain, "AiDA:settings:v1");
        !protected_value.empty())
    {
        VMP_END;
        return protected_value;
    }
#endif

    std::string out;
    out.reserve(plain.size() * 2 + sizeof(CFG_OBF_PREFIX));
    out = CFG_OBF_PREFIX;

    for (size_t i = 0; i < plain.size(); ++i)
    {
        uint8_t b = static_cast<uint8_t>(plain[i]) ^ CFG_OBF_KEY[i % sizeof(CFG_OBF_KEY)];
        char hex[3];
        qsnprintf(hex, sizeof(hex), "%02x", b);
        out += hex;
    }
    VMP_END;
    return out;
}

static std::string deobfuscate_key(const std::string& encoded)
{
    VMP_VIRT("deobf_key");
    if (encoded.empty())
    {
        VMP_END;
        return encoded;
    }

#ifdef __NT__
    if (encoded.compare(0, sizeof(CFG_DPAPI_PREFIX) - 1, CFG_DPAPI_PREFIX) == 0)
    {
        std::string plaintext = unprotect_with_dpapi(encoded, "AiDA:settings:v1");
        VMP_END;
        return plaintext;
    }
#endif

    if (encoded.compare(0, sizeof(CFG_OBF_PREFIX) - 1, CFG_OBF_PREFIX) != 0)
    {
        VMP_END;
        return encoded;
    }

    std::string hex_part = encoded.substr(sizeof(CFG_OBF_PREFIX) - 1);
    std::string out;
    out.reserve(hex_part.size() / 2);

    for (size_t i = 0; i + 1 < hex_part.size(); i += 2)
    {
        uint8_t b = static_cast<uint8_t>(std::stoi(hex_part.substr(i, 2), nullptr, 16));
        b ^= CFG_OBF_KEY[(i / 2) % sizeof(CFG_OBF_KEY)];
        out.push_back(static_cast<char>(b));
    }
    VMP_END;
    return out;
}

static std::string get_trimmed_json_string(const nlohmann::json& j, const char* key, const std::string& default_val)
{
    std::string val = j.value(key, default_val);
    qstring q_val = val.c_str();
    q_val.trim2();
    return q_val.c_str();
}

static std::string get_trimmed_key_string(const nlohmann::json& j, const char* key, const std::string& default_val)
{
    std::string raw = get_trimmed_json_string(j, key, default_val);
    return deobfuscate_key(raw);
}

settings_t g_settings;

const std::vector<std::string> settings_t::gemini_models = {
    OBFSTR("gemini-3-pro-preview"),
    OBFSTR("gemini-2.5-pro"),
    OBFSTR("gemini-2.5-flash"),
    OBFSTR("gemini-2.5-flash-lite"),
    OBFSTR("gemini-2.0-flash"),
    OBFSTR("gemini-2.0-flash-lite"),
    OBFSTR("gemini-1.5-pro-latest"),
    OBFSTR("gemini-1.5-pro"),
    OBFSTR("gemini-1.5-pro-002"),
    OBFSTR("gemini-1.5-flash-latest"),
    OBFSTR("gemini-1.5-flash"),
    OBFSTR("gemini-1.5-flash-8b"),
    OBFSTR("gemini-1.5-flash-8b-latest"),
    OBFSTR("gemini-2.0-flash-exp"),
    OBFSTR("gemini-2.0-flash-lite-preview"),
    OBFSTR("gemini-2.0-pro-exp"),
    OBFSTR("gemini-2.0-flash-thinking-exp"),
    OBFSTR("gemma-3-1b-it"),
    OBFSTR("gemma-3-4b-it"),
    OBFSTR("gemma-3-12b-it"),
    OBFSTR("gemma-3-27b-it"),
    OBFSTR("gemma-3n-e4b-it"),
    OBFSTR("gemma-3n-e2b-it")
};

const std::vector<std::string> settings_t::openai_models = {
  OBFSTR("gpt-5.1 Instant"),
  OBFSTR("gpt-5.1 Thinking"),
  OBFSTR("gpt-5"),
  OBFSTR("gpt-5-mini"),
  OBFSTR("gpt-5-nano"),
  OBFSTR("o3-pro"),
  OBFSTR("o3"),
  OBFSTR("o3-mini"),
  OBFSTR("o1-pro"),
  OBFSTR("o1"),
  OBFSTR("o4-mini"),
  OBFSTR("gpt-4.5-preview"),
  OBFSTR("gpt-4.1"),
  OBFSTR("gpt-4.1-mini"),
  OBFSTR("gpt-4.1-nano"),
  OBFSTR("gpt-4o"),
  OBFSTR("gpt-4-turbo"),
  OBFSTR("gpt-4"),
  OBFSTR("gpt-4o-mini"),
  OBFSTR("gpt-3.5-turbo"),
  OBFSTR("gpt-3.5-turbo-16k"),
};

const std::vector<std::string> settings_t::openrouter_models = {
  OBFSTR("moonshotai/kimi-k2:free"),
  OBFSTR("openai/gpt-oss-20b:free"),
  OBFSTR("z-ai/glm-4.5-air:free"),
  OBFSTR("tngtech/deepseek-r1t2-chimera:free"),

};

const std::vector<std::string> settings_t::anthropic_models = {
  OBFSTR("claude-opus-4-6"),
  OBFSTR("claude-opus-4-6 (Max Effort)"),
  OBFSTR("claude-opus-4-6 (Standard)"),
  OBFSTR("claude-sonnet-4-6"),
  OBFSTR("claude-opus-4-5 (High Effort)"),
  OBFSTR("claude-opus-4-5 (Medium Effort)"),
  OBFSTR("claude-opus-4-5 (Low Effort)"),
  OBFSTR("claude-sonnet-4-5"),
  OBFSTR("claude-haiku-4-5"),
  OBFSTR("claude-opus-4-1"),
  OBFSTR("claude-opus-4"),
  OBFSTR("claude-sonnet-4"),
  OBFSTR("claude-3-7-sonnet-thought"),
  OBFSTR("claude-3-7-sonnet"),
  OBFSTR("claude-3.5-sonnet-latest"),
  OBFSTR("claude-3.5-haiku-latest"),
  OBFSTR("claude-3-opus-latest"),
  OBFSTR("claude-3-sonnet-latest"),
  OBFSTR("claude-3-haiku-latest"),
  OBFSTR("claude-2.1"),
  OBFSTR("claude-2"),
  OBFSTR("claude-instant-v1.2"),
};

const std::vector<std::string> settings_t::copilot_models = {
    OBFSTR("claude-sonnet-4"),
    OBFSTR("claude-3.7-sonnet-thought"),
    OBFSTR("gemini-2.5-pro"),
    OBFSTR("claude-3.7-sonnet"),
    OBFSTR("gpt-4.1-2025-04-14"),
    OBFSTR("gpt-4.1"),
    OBFSTR("o4-mini-2025-04-16"),
    OBFSTR("o4-mini"),
    OBFSTR("o3-mini-2025-01-31"),
    OBFSTR("o3-mini"),
    OBFSTR("o3-mini-paygo"),
    OBFSTR("claude-3.5-sonnet"),
    OBFSTR("gemini-2.0-flash-001"),
    OBFSTR("gpt-4o-2024-11-20"),
    OBFSTR("gpt-4o-2024-08-06"),
    OBFSTR("gpt-4o-2024-05-13"),
    OBFSTR("gpt-4o"),
    OBFSTR("gpt-4o-copilot"),
    OBFSTR("gpt-4-o-preview"),
    OBFSTR("gpt-4-0125-preview"),
    OBFSTR("gpt-4"),
    OBFSTR("gpt-4-0613"),
    OBFSTR("gpt-4o-mini-2024-07-18"),
    OBFSTR("gpt-4o-mini"),
    OBFSTR("gpt-3.5-turbo"),
    OBFSTR("gpt-3.5-turbo-0613"),
};

const std::vector<std::string> settings_t::local_llm_models = {
    OBFSTR("llama3.3:latest"),
    OBFSTR("llama3.1:latest"),
    OBFSTR("llama3:latest"),
    OBFSTR("qwen3:latest"),
    OBFSTR("qwen2.5-coder:latest"),
    OBFSTR("deepseek-r1:latest"),
    OBFSTR("deepseek-coder-v2:latest"),
    OBFSTR("codellama:latest"),
    OBFSTR("mistral:latest"),
    OBFSTR("mixtral:latest"),
    OBFSTR("phi4:latest"),
    OBFSTR("gemma3:latest"),
    OBFSTR("command-r:latest"),
};

static void to_json(nlohmann::json& j, const settings_t& s)
{
    j = nlohmann::json{
        {OBFSTR_C("api_provider"), s.api_provider},
        {OBFSTR_C("gemini_api_key"), obfuscate_key(s.gemini_api_key)},
        {OBFSTR_C("gemini_model_name"), s.gemini_model_name},
        {OBFSTR_C("gemini_base_url"), s.gemini_base_url},
        {OBFSTR_C("openai_api_key"), obfuscate_key(s.openai_api_key)},
        {OBFSTR_C("openai_model_name"), s.openai_model_name},
        {OBFSTR_C("openai_base_url"), s.openai_base_url},
        {OBFSTR_C("openrouter_api_key"), obfuscate_key(s.openrouter_api_key)},
        {OBFSTR_C("openrouter_model_name"), s.openrouter_model_name},
        {OBFSTR_C("anthropic_api_key"), obfuscate_key(s.anthropic_api_key)},
        {OBFSTR_C("anthropic_model_name"), s.anthropic_model_name},
        {OBFSTR_C("anthropic_base_url"), s.anthropic_base_url},
        {OBFSTR_C("copilot_proxy_address"), s.copilot_proxy_address},
        {OBFSTR_C("copilot_model_name"), s.copilot_model_name},
        {OBFSTR_C("local_llm_base_url"), s.local_llm_base_url},
        {OBFSTR_C("local_llm_model_name"), s.local_llm_model_name},
        {OBFSTR_C("local_llm_api_key"), obfuscate_key(s.local_llm_api_key)},
        {OBFSTR_C("local_llm_context_window"), s.local_llm_context_window},
        {OBFSTR_C("xref_context_count"), s.xref_context_count},
        {OBFSTR_C("xref_analysis_depth"), s.xref_analysis_depth},
        {OBFSTR_C("xref_code_snippet_lines"), s.xref_code_snippet_lines},
        {OBFSTR_C("bulk_processing_delay"), s.bulk_processing_delay},
        {OBFSTR_C("max_root_func_scan_count"), s.max_root_func_scan_count},
        {OBFSTR_C("max_root_func_candidates"), s.max_root_func_candidates},
        {OBFSTR_C("custom_prompts"), s.custom_prompts},
        {OBFSTR_C("active_prompt_name"), s.active_prompt_name},
        {OBFSTR_C("temperature"), s.temperature},
        {OBFSTR_C("check_for_updates"), s.check_for_updates},
        {OBFSTR_C("mcp_enabled"), s.mcp_enabled},
        {OBFSTR_C("mcp_port"), s.mcp_port},
        {OBFSTR_C("license_key"), obfuscate_key(s.license_key)},
        {OBFSTR_C("license_validated_at"), s.license_validated_at},
        {OBFSTR_C("license_hwid"), s.license_hwid},
        {OBFSTR_C("firebase_api_key"), obfuscate_key(s.firebase_api_key)}
    };
}

static void from_json(const nlohmann::json& j, settings_t& s)
{
    settings_t d;
    s.api_provider = j.value(OBFSTR_C("api_provider"), d.api_provider);

    s.gemini_api_key = get_trimmed_key_string(j, OBFSTR_C("gemini_api_key"), d.gemini_api_key);
    s.gemini_model_name = j.value(OBFSTR_C("gemini_model_name"), d.gemini_model_name);
    s.gemini_base_url = get_trimmed_json_string(j, OBFSTR_C("gemini_base_url"), d.gemini_base_url);

    s.openai_api_key = get_trimmed_key_string(j, OBFSTR_C("openai_api_key"), d.openai_api_key);
    s.openai_model_name = j.value(OBFSTR_C("openai_model_name"), d.openai_model_name);
    s.openai_base_url = get_trimmed_json_string(j, OBFSTR_C("openai_base_url"), d.openai_base_url);

    s.openrouter_api_key = get_trimmed_key_string(j, OBFSTR_C("openrouter_api_key"), d.openrouter_api_key);
    s.openrouter_model_name = j.value(OBFSTR_C("openrouter_model_name"), d.openrouter_model_name);

    s.anthropic_api_key = get_trimmed_key_string(j, OBFSTR_C("anthropic_api_key"), d.anthropic_api_key);
    s.anthropic_model_name = j.value(OBFSTR_C("anthropic_model_name"), d.anthropic_model_name);
    s.anthropic_base_url = get_trimmed_json_string(j, OBFSTR_C("anthropic_base_url"), d.anthropic_base_url);

    s.copilot_proxy_address = j.value(OBFSTR_C("copilot_proxy_address"), d.copilot_proxy_address);
    s.copilot_model_name = j.value(OBFSTR_C("copilot_model_name"), d.copilot_model_name);

    s.local_llm_base_url = get_trimmed_json_string(j, OBFSTR_C("local_llm_base_url"), d.local_llm_base_url);
    s.local_llm_model_name = j.value(OBFSTR_C("local_llm_model_name"), d.local_llm_model_name);
    s.local_llm_api_key = get_trimmed_key_string(j, OBFSTR_C("local_llm_api_key"), d.local_llm_api_key);
    s.local_llm_context_window = j.value(OBFSTR_C("local_llm_context_window"), d.local_llm_context_window);

    s.xref_context_count = j.value(OBFSTR_C("xref_context_count"), d.xref_context_count);
    s.xref_analysis_depth = j.value(OBFSTR_C("xref_analysis_depth"), d.xref_analysis_depth);
    s.xref_code_snippet_lines = j.value(OBFSTR_C("xref_code_snippet_lines"), d.xref_code_snippet_lines);

    s.bulk_processing_delay = j.value(OBFSTR_C("bulk_processing_delay"), d.bulk_processing_delay);

    s.max_root_func_scan_count = j.value(OBFSTR_C("max_root_func_scan_count"), d.max_root_func_scan_count);
    s.max_root_func_candidates = j.value(OBFSTR_C("max_root_func_candidates"), d.max_root_func_candidates);

    s.temperature = j.value(OBFSTR_C("temperature"), d.temperature);
    s.check_for_updates = j.value(OBFSTR_C("check_for_updates"), d.check_for_updates);

    s.mcp_enabled = j.value(OBFSTR_C("mcp_enabled"), d.mcp_enabled);
    s.mcp_port = j.value(OBFSTR_C("mcp_port"), d.mcp_port);

    s.license_key = deobfuscate_key(j.value(OBFSTR_C("license_key"), d.license_key));
    s.license_validated_at = j.value(OBFSTR_C("license_validated_at"), d.license_validated_at);
    s.license_hwid = j.value(OBFSTR_C("license_hwid"), d.license_hwid);
    s.firebase_api_key = get_trimmed_key_string(j, OBFSTR_C("firebase_api_key"), d.firebase_api_key);

    if (j.contains(OBFSTR_C("custom_prompts")))
        j.at(OBFSTR_C("custom_prompts")).get_to(s.custom_prompts);
    s.active_prompt_name = j.value(OBFSTR_C("active_prompt_name"), d.active_prompt_name);
}

static qstring get_config_file()
{
    qstring path = get_user_idadir();
    path.append(OBFSTR_C("/ai_assistant.cfg"));
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
        req(OBFSTR_C("api_provider"));
        req(OBFSTR_C("gemini_api_key")); req(OBFSTR_C("gemini_model_name")); req(OBFSTR_C("gemini_base_url"));
        req(OBFSTR_C("openai_api_key")); req(OBFSTR_C("openai_model_name")); req(OBFSTR_C("openai_base_url"));
        req(OBFSTR_C("openrouter_api_key")); req(OBFSTR_C("openrouter_model_name"));
        req(OBFSTR_C("anthropic_api_key")); req(OBFSTR_C("anthropic_model_name")); req(OBFSTR_C("anthropic_base_url"));
        req(OBFSTR_C("copilot_proxy_address")); req(OBFSTR_C("copilot_model_name"));
        req(OBFSTR_C("local_llm_base_url")); req(OBFSTR_C("local_llm_model_name")); req(OBFSTR_C("local_llm_api_key"));
        req(OBFSTR_C("local_llm_context_window"));
        req(OBFSTR_C("xref_context_count")); req(OBFSTR_C("xref_analysis_depth")); req(OBFSTR_C("xref_code_snippet_lines"));
        req(OBFSTR_C("bulk_processing_delay"));
        req(OBFSTR_C("max_root_func_scan_count")); req(OBFSTR_C("max_root_func_candidates"));
        req(OBFSTR_C("custom_prompts")); req(OBFSTR_C("active_prompt_name"));
        req(OBFSTR_C("temperature"));
        req(OBFSTR_C("check_for_updates"));
        req(OBFSTR_C("mcp_enabled"));
        req(OBFSTR_C("mcp_port"));
        req(OBFSTR_C("firebase_api_key"));

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
    gemini_model_name(OBFSTR("gemini-2.5-flash")),
    gemini_base_url(""),
    openai_api_key(""),
    openai_model_name(OBFSTR("gpt-5")),
    openai_base_url(""),
    openrouter_api_key(""),
    openrouter_model_name(OBFSTR("moonshotai/kimi-k2:free")),
    anthropic_api_key(""),
    anthropic_model_name(OBFSTR("claude-sonnet-4-5")),
    anthropic_base_url(""),
    copilot_proxy_address(OBFSTR("http://127.0.0.1:4141")),
    copilot_model_name(OBFSTR("gpt-4.1")),
    local_llm_base_url(OBFSTR("http://localhost:1234")),
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
    license_hwid(""),
    firebase_api_key("")
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

    if (gemini_api_key.empty() && qgetenv(OBFSTR_C("GEMINI_API_KEY"), &val))
    {
        val.trim2();
        gemini_api_key = val.c_str();
        has_env_keys = true;
    }
    if (openai_api_key.empty() && qgetenv(OBFSTR_C("OPENAI_API_KEY"), &val))
    {
        val.trim2();
        openai_api_key = val.c_str();
        has_env_keys = true;
    }
    if (openrouter_api_key.empty() && qgetenv(OBFSTR_C("OPENROUTER_API_KEY"), &val))
    {
        val.trim2();
        openrouter_api_key = val.c_str();
        has_env_keys = true;
    }
    if (anthropic_api_key.empty() && qgetenv(OBFSTR_C("ANTHROPIC_API_KEY"), &val))
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
        custom_prompts[OBFSTR("Anti-Cheat / Anti-Tamper")] = ANTICHEAT_RE_PROMPT;
        custom_prompts[OBFSTR("Windows Kernel / Drivers")] = KERNEL_DRIVER_PROMPT;
        custom_prompts[OBFSTR("Crackme / CTF Challenges")] = CRACKME_PROMPT;
        custom_prompts[OBFSTR("Malware Analysis")] = MALWARE_ANALYSIS_PROMPT;
        custom_prompts[OBFSTR("Application RE (General)")] = APPLICATION_RE_PROMPT;
        custom_prompts[OBFSTR("Firmware / Embedded")] = FIRMWARE_ANALYSIS_PROMPT;
        custom_prompts[OBFSTR("Cryptography")] = CRYPTO_ANALYSIS_PROMPT;
        custom_prompts[OBFSTR("Network Protocol")] = NETWORK_PROTOCOL_PROMPT;
        custom_prompts[OBFSTR("iOS / macOS")] = IOS_MACOS_RE_PROMPT;
        custom_prompts[OBFSTR("Android")] = ANDROID_RE_PROMPT;
        custom_prompts[OBFSTR("Linux Userspace / Kernel")] = LINUX_RE_PROMPT;
        custom_prompts[OBFSTR("Unity Game (IL2CPP)")] = UNITY_GAME_PROMPT;
        custom_prompts[OBFSTR("Cheat Loader / Malware")] = CHEAT_LOADER_PROMPT;
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

    if (!api_provider.empty() && get_active_api_key().empty() && !has_custom_base_url())
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
    VMP_MUT("get_active_key");
    std::string result;
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    if (provider == OBFSTR_C("gemini"))
        result = gemini_api_key.empty() ? gemini_base_url : gemini_api_key;
    else if (provider == OBFSTR_C("openai"))
        result = openai_api_key.empty() ? openai_base_url : openai_api_key;
    else if (provider == OBFSTR_C("openrouter"))
        result = openrouter_api_key;
    else if (provider == OBFSTR_C("anthropic"))
        result = anthropic_api_key.empty() ? anthropic_base_url : anthropic_api_key;
    else if (provider == OBFSTR_C("copilot"))
        result = copilot_proxy_address;
    else if (provider == OBFSTR_C("local llm"))
        result = local_llm_base_url;
    VMP_END;
    return result;
}

int settings_t::get_model_context_window(const std::string& model_name)
{
    static const std::unordered_map<std::string, int> context_windows = {
        {OBFSTR("gemini-3-pro-preview"),             1000000},
        {OBFSTR("gemini-2.5-pro"),                   1048576},
        {OBFSTR("gemini-2.5-flash"),                 1048576},
        {OBFSTR("gemini-2.5-flash-lite"),            1048576},
        {OBFSTR("gemini-2.0-flash"),                 1048576},
        {OBFSTR("gemini-2.0-flash-lite"),            1048576},
        {OBFSTR("gemini-1.5-pro-latest"),            2097152},
        {OBFSTR("gemini-1.5-pro"),                   2097152},
        {OBFSTR("gemini-1.5-pro-002"),               2097152},
        {OBFSTR("gemini-1.5-flash-latest"),          1048576},
        {OBFSTR("gemini-1.5-flash"),                 1048576},
        {OBFSTR("gemini-1.5-flash-8b"),              1048576},
        {OBFSTR("gemini-1.5-flash-8b-latest"),       1048576},
        {OBFSTR("gemini-2.0-flash-exp"),             1048576},
        {OBFSTR("gemini-2.0-flash-lite-preview"),    1048576},
        {OBFSTR("gemini-2.0-pro-exp"),               1048576},
        {OBFSTR("gemini-2.0-flash-thinking-exp"),    1048576},
        {OBFSTR("gemma-3-1b-it"),                      32768},
        {OBFSTR("gemma-3-4b-it"),                      32768},
        {OBFSTR("gemma-3-12b-it"),                     32768},
        {OBFSTR("gemma-3-27b-it"),                     32768},
        {OBFSTR("gemma-3n-e4b-it"),                    32768},
        {OBFSTR("gemma-3n-e2b-it"),                    32768},

        {OBFSTR("gpt-5.1 Instant"),                  1047576},
        {OBFSTR("gpt-5.1 Thinking"),                 1047576},
        {OBFSTR("gpt-5"),                             1047576},
        {OBFSTR("gpt-5-mini"),                        1047576},
        {OBFSTR("gpt-5-nano"),                         524288},
        {OBFSTR("o3-pro"),                             200000},
        {OBFSTR("o3"),                                 200000},
        {OBFSTR("o3-mini"),                            200000},
        {OBFSTR("o1-pro"),                             200000},
        {OBFSTR("o1"),                                 200000},
        {OBFSTR("o4-mini"),                            200000},
        {OBFSTR("gpt-4.5-preview"),                   128000},
        {OBFSTR("gpt-4.1"),                           1047576},
        {OBFSTR("gpt-4.1-mini"),                      1047576},
        {OBFSTR("gpt-4.1-nano"),                      1047576},
        {OBFSTR("gpt-4o"),                             128000},
        {OBFSTR("gpt-4-turbo"),                        128000},
        {OBFSTR("gpt-4"),                                8192},
        {OBFSTR("gpt-4o-mini"),                        128000},
        {OBFSTR("gpt-3.5-turbo"),                      16385},
        {OBFSTR("gpt-3.5-turbo-16k"),                  16385},

        {OBFSTR("moonshotai/kimi-k2:free"),            131072},
        {OBFSTR("openai/gpt-oss-20b:free"),            128000},
        {OBFSTR("z-ai/glm-4.5-air:free"),             128000},
        {OBFSTR("tngtech/deepseek-r1t2-chimera:free"), 164000},

        {OBFSTR("claude-opus-4-5 (High Effort)"),      200000},
        {OBFSTR("claude-opus-4-5 (Medium Effort)"),    200000},
        {OBFSTR("claude-opus-4-5 (Low Effort)"),       200000},
        {OBFSTR("claude-sonnet-4-5"),                  200000},
        {OBFSTR("claude-haiku-4-5"),                   200000},
        {OBFSTR("claude-opus-4-1"),                    200000},
        {OBFSTR("claude-opus-4"),                      200000},
        {OBFSTR("claude-sonnet-4"),                    200000},
        {OBFSTR("claude-3-7-sonnet-thought"),          200000},
        {OBFSTR("claude-3-7-sonnet"),                  200000},
        {OBFSTR("claude-3.7-sonnet-thought"),          200000},
        {OBFSTR("claude-3.7-sonnet"),                  200000},
        {OBFSTR("claude-3.5-sonnet-latest"),           200000},
        {OBFSTR("claude-3.5-haiku-latest"),            200000},
        {OBFSTR("claude-3.5-sonnet"),                  200000},
        {OBFSTR("claude-3-opus-latest"),               200000},
        {OBFSTR("claude-3-sonnet-latest"),             200000},
        {OBFSTR("claude-3-haiku-latest"),              200000},
        {OBFSTR("claude-2.1"),                         200000},
        {OBFSTR("claude-2"),                           100000},
        {OBFSTR("claude-instant-v1.2"),                100000},

        {OBFSTR("gpt-4.1-2025-04-14"),               1047576},
        {OBFSTR("o4-mini-2025-04-16"),                 200000},
        {OBFSTR("o3-mini-2025-01-31"),                 200000},
        {OBFSTR("o3-mini-paygo"),                      200000},
        {OBFSTR("gemini-2.0-flash-001"),              1048576},
        {OBFSTR("gpt-4o-2024-11-20"),                  128000},
        {OBFSTR("gpt-4o-2024-08-06"),                  128000},
        {OBFSTR("gpt-4o-2024-05-13"),                  128000},
        {OBFSTR("gpt-4o-copilot"),                     128000},
        {OBFSTR("gpt-4-o-preview"),                    128000},
        {OBFSTR("gpt-4-0125-preview"),                 128000},
        {OBFSTR("gpt-4-0613"),                           8192},
        {OBFSTR("gpt-4o-mini-2024-07-18"),             128000},
        {OBFSTR("gpt-3.5-turbo-0613"),                  16385},
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
    if (provider == OBFSTR_C("gemini"))          model = gemini_model_name;
    else if (provider == OBFSTR_C("openai"))     model = openai_model_name;
    else if (provider == OBFSTR_C("openrouter")) model = openrouter_model_name;
    else if (provider == OBFSTR_C("anthropic"))  model = anthropic_model_name;
    else if (provider == OBFSTR_C("copilot"))    model = copilot_model_name;
    else if (provider == OBFSTR_C("local llm")) return local_llm_context_window > 0 ? local_llm_context_window : 8192;
    else                               return 128000;
    return get_model_context_window(model);
}

bool settings_t::has_custom_base_url() const
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    if (provider == OBFSTR_C("gemini")) return !gemini_base_url.empty();
    if (provider == OBFSTR_C("openai")) return !openai_base_url.empty();
    if (provider == OBFSTR_C("anthropic")) return !anthropic_base_url.empty();
    if (provider == OBFSTR_C("copilot")) return !copilot_proxy_address.empty();
    if (provider == OBFSTR_C("local llm")) return !local_llm_base_url.empty();
    return false;
}

void settings_t::prompt_for_api_key()
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());

    if (has_custom_base_url())
        return;

    if (provider == OBFSTR_C("copilot"))
    {
        warning(OBFSTR_C("Copilot provider is selected, but the proxy address is not configured. Please set it in the settings dialog."));
        return;
    }

    if (provider == OBFSTR_C("local llm"))
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
    question.sprnt(OBFSTR_C("Please enter your %s API key to continue:"), provider_name.c_str());
    if (ask_str(&key, HIST_SRCH, question.c_str()))
    {
        if (provider == OBFSTR_C("gemini")) gemini_api_key = key.c_str();
        else if (provider == OBFSTR_C("openai")) openai_api_key = key.c_str();
        else if (provider == OBFSTR_C("openrouter")) openrouter_api_key = key.c_str();
        else if (provider == OBFSTR_C("anthropic")) anthropic_api_key = key.c_str();
        save();
    }
    else
    {
        warning(OBFSTR_C("Plugin will be disabled until an API key is provided for %s."), provider_name.c_str());
    }
}
