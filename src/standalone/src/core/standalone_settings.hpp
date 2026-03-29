#pragma once


#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <nlohmann/json.hpp>


namespace sa_settings_detail {

static constexpr uint8_t CFG_OBF_KEY[] = {
    0xA3, 0x7B, 0x1E, 0xD4, 0x5F, 0x92, 0xC8, 0x06,
    0xE1, 0x3A, 0x8D, 0x47, 0xB0, 0x6C, 0xF5, 0x29
};
static constexpr const char CFG_OBF_PREFIX[]   = "enc1:";
static constexpr const char CFG_DPAPI_PREFIX[] = "dpapi1:";

inline std::string hex_encode(const unsigned char* data, size_t size)
{
    std::string out;
    out.reserve(size * 2);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        out.push_back(digits[(data[i] >> 4) & 0x0F]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

inline bool hex_decode(const std::string& text, std::vector<unsigned char>& out)
{
    if (text.size() % 2 != 0) return false;
    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2) {
        unsigned int v = 0;
        std::istringstream iss(text.substr(i, 2));
        iss >> std::hex >> v;
        if (iss.fail()) return false;
        out.push_back(static_cast<unsigned char>(v));
    }
    return true;
}

inline std::string protect_dpapi(const std::string& plaintext, const char* scope)
{
    if (plaintext.empty()) return plaintext;
    DATA_BLOB in_blob{static_cast<DWORD>(plaintext.size()),
                      reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()))};
    DATA_BLOB ent{static_cast<DWORD>(std::strlen(scope)),
                  reinterpret_cast<BYTE*>(const_cast<char*>(scope))};
    DATA_BLOB out_blob{};
    if (!CryptProtectData(&in_blob, L"AiDA Secret", &ent, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &out_blob))
        return "";
    auto hex = hex_encode(out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
    return std::string(CFG_DPAPI_PREFIX) + hex;
}

inline std::string unprotect_dpapi(const std::string& encoded, const char* scope)
{
    if (encoded.compare(0, strlen(CFG_DPAPI_PREFIX), CFG_DPAPI_PREFIX) != 0)
        return "";
    std::vector<unsigned char> bytes;
    if (!hex_decode(encoded.substr(strlen(CFG_DPAPI_PREFIX)), bytes))
        return "";
    DATA_BLOB in_blob{static_cast<DWORD>(bytes.size()), bytes.data()};
    DATA_BLOB ent{static_cast<DWORD>(std::strlen(scope)),
                  reinterpret_cast<BYTE*>(const_cast<char*>(scope))};
    DATA_BLOB out_blob{};
    if (!CryptUnprotectData(&in_blob, nullptr, &ent, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out_blob))
        return "";
    std::string result(reinterpret_cast<const char*>(out_blob.pbData), out_blob.cbData);
    SecureZeroMemory(out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
    return result;
}

inline std::string obfuscate_key(const std::string& plain)
{
    if (plain.empty()) return plain;
    auto dpapi = protect_dpapi(plain, "AiDA:settings:v1");
    if (!dpapi.empty()) return dpapi;

    std::string out(CFG_OBF_PREFIX);
    for (size_t i = 0; i < plain.size(); ++i) {
        uint8_t b = static_cast<uint8_t>(plain[i]) ^ CFG_OBF_KEY[i % sizeof(CFG_OBF_KEY)];
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", b);
        out += hex;
    }
    return out;
}

inline std::string deobfuscate_key(const std::string& encoded)
{
    if (encoded.empty()) return encoded;
    if (encoded.compare(0, strlen(CFG_DPAPI_PREFIX), CFG_DPAPI_PREFIX) == 0)
        return unprotect_dpapi(encoded, "AiDA:settings:v1");
    if (encoded.compare(0, strlen(CFG_OBF_PREFIX), CFG_OBF_PREFIX) != 0)
        return encoded;

    std::string hex_part = encoded.substr(strlen(CFG_OBF_PREFIX));
    std::string out;
    out.reserve(hex_part.size() / 2);
    for (size_t i = 0; i + 1 < hex_part.size(); i += 2) {
        uint8_t b = static_cast<uint8_t>(std::stoi(hex_part.substr(i, 2), nullptr, 16));
        b ^= CFG_OBF_KEY[(i / 2) % sizeof(CFG_OBF_KEY)];
        out.push_back(static_cast<char>(b));
    }
    return out;
}

inline std::string trim(const std::string& s)
{
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
}

}


struct settings_sa_t
{
    std::string api_provider = "gemini";

    std::string gemini_api_key;
    std::string gemini_model_name    = "gemini-2.5-flash";
    std::string gemini_base_url;

    std::string openai_api_key;
    std::string openai_model_name    = "gpt-4o";
    std::string openai_base_url;

    std::string openrouter_api_key;
    std::string openrouter_model_name;

    std::string anthropic_api_key;
    std::string anthropic_model_name = "claude-sonnet-4";
    std::string anthropic_base_url;

    std::string copilot_proxy_address;
    std::string copilot_model_name;

    std::string local_llm_base_url;
    std::string local_llm_model_name;
    std::string local_llm_api_key;
    int         local_llm_context_window = 8192;

    double      temperature          = 0.7;
    int         mcp_port             = 29117;
    bool        mcp_enabled          = true;

    std::string license_key;
    std::string firebase_api_key;


    static const std::vector<std::string>& gemini_models();
    static const std::vector<std::string>& openai_models();
    static const std::vector<std::string>& anthropic_models();
    static const std::vector<std::string>& openrouter_models();
    static const std::vector<std::string>& copilot_models();
    static const std::vector<std::string>& local_llm_models();


    std::string get_active_api_key() const
    {
        if (api_provider == "gemini")      return gemini_api_key;
        if (api_provider == "openai")      return openai_api_key;
        if (api_provider == "anthropic")   return anthropic_api_key;
        if (api_provider == "openrouter")  return openrouter_api_key;
        if (api_provider == "copilot")     return {};
        if (api_provider == "local_llm")   return local_llm_api_key;
        return {};
    }

    std::string get_active_model() const
    {
        if (api_provider == "gemini")      return gemini_model_name;
        if (api_provider == "openai")      return openai_model_name;
        if (api_provider == "anthropic")   return anthropic_model_name;
        if (api_provider == "openrouter")  return openrouter_model_name;
        if (api_provider == "copilot")     return copilot_model_name;
        if (api_provider == "local_llm")   return local_llm_model_name;
        return {};
    }

    std::string get_active_base_url() const
    {
        if (api_provider == "gemini"    && !gemini_base_url.empty())    return gemini_base_url;
        if (api_provider == "openai"    && !openai_base_url.empty())    return openai_base_url;
        if (api_provider == "anthropic" && !anthropic_base_url.empty()) return anthropic_base_url;
        if (api_provider == "local_llm" && !local_llm_base_url.empty()) return local_llm_base_url;
        return {};
    }


    static std::filesystem::path config_path()
    {
        wchar_t* appdata = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
            auto p = std::filesystem::path(appdata) / L"Hex-Rays" / L"IDA Pro" / L"ai_assistant.cfg";
            CoTaskMemFree(appdata);
            return p;
        }

        return std::filesystem::current_path() / "ai_assistant.cfg";
    }


    bool load()
    {
        auto path = config_path();
        std::ifstream ifs(path);
        if (!ifs.is_open()) return false;

        nlohmann::json j;
        try {
            ifs >> j;
        } catch (...) { return false; }

        auto str = [&](const char* key, std::string& dst) {
            if (j.contains(key) && j[key].is_string()) dst = j[key].get<std::string>();
        };
        auto key = [&](const char* k, std::string& dst) {
            if (j.contains(k) && j[k].is_string())
                dst = sa_settings_detail::deobfuscate_key(
                    sa_settings_detail::trim(j[k].get<std::string>()));
        };
        auto num_int = [&](const char* k, int& dst) {
            if (j.contains(k) && j[k].is_number_integer()) dst = j[k].get<int>();
        };
        auto num_dbl = [&](const char* k, double& dst) {
            if (j.contains(k) && j[k].is_number()) dst = j[k].get<double>();
        };
        auto boolean = [&](const char* k, bool& dst) {
            if (j.contains(k) && j[k].is_boolean()) dst = j[k].get<bool>();
        };

        str("api_provider",          api_provider);
        key("gemini_api_key",        gemini_api_key);
        str("gemini_model_name",     gemini_model_name);
        str("gemini_base_url",       gemini_base_url);
        key("openai_api_key",        openai_api_key);
        str("openai_model_name",     openai_model_name);
        str("openai_base_url",       openai_base_url);
        key("openrouter_api_key",    openrouter_api_key);
        str("openrouter_model_name", openrouter_model_name);
        key("anthropic_api_key",     anthropic_api_key);
        str("anthropic_model_name",  anthropic_model_name);
        str("anthropic_base_url",    anthropic_base_url);
        str("copilot_proxy_address", copilot_proxy_address);
        str("copilot_model_name",    copilot_model_name);
        str("local_llm_base_url",    local_llm_base_url);
        str("local_llm_model_name",  local_llm_model_name);
        key("local_llm_api_key",     local_llm_api_key);
        num_int("local_llm_context_window", local_llm_context_window);
        num_dbl("temperature",       temperature);
        num_int("mcp_port",          mcp_port);
        boolean("mcp_enabled",       mcp_enabled);
        key("firebase_api_key",      firebase_api_key);

        return true;
    }


    bool save() const
    {
        auto path = config_path();
        std::filesystem::create_directories(path.parent_path());

        nlohmann::json merged = nlohmann::json::object();
        {
            std::ifstream ifs(path);
            if (ifs.is_open()) {
                try { ifs >> merged; } catch (...) { merged = nlohmann::json::object(); }
                if (!merged.is_object()) merged = nlohmann::json::object();
            }
        }

        merged["api_provider"]          = api_provider;
        merged["gemini_api_key"]        = sa_settings_detail::obfuscate_key(gemini_api_key);
        merged["gemini_model_name"]     = gemini_model_name;
        merged["gemini_base_url"]       = gemini_base_url;
        merged["openai_api_key"]        = sa_settings_detail::obfuscate_key(openai_api_key);
        merged["openai_model_name"]     = openai_model_name;
        merged["openai_base_url"]       = openai_base_url;
        merged["openrouter_api_key"]    = sa_settings_detail::obfuscate_key(openrouter_api_key);
        merged["openrouter_model_name"] = openrouter_model_name;
        merged["anthropic_api_key"]     = sa_settings_detail::obfuscate_key(anthropic_api_key);
        merged["anthropic_model_name"]  = anthropic_model_name;
        merged["anthropic_base_url"]    = anthropic_base_url;
        merged["copilot_proxy_address"] = copilot_proxy_address;
        merged["copilot_model_name"]    = copilot_model_name;
        merged["local_llm_base_url"]    = local_llm_base_url;
        merged["local_llm_model_name"]  = local_llm_model_name;
        merged["local_llm_api_key"]     = sa_settings_detail::obfuscate_key(local_llm_api_key);
        merged["local_llm_context_window"] = local_llm_context_window;
        merged["temperature"]           = temperature;
        merged["mcp_port"]              = mcp_port;
        merged["mcp_enabled"]           = mcp_enabled;

        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs.is_open()) return false;
        ofs << merged.dump(4);
        return true;
    }
};


inline const std::vector<std::string>& settings_sa_t::gemini_models()
{
    static const std::vector<std::string> v = {
        "gemini-3-pro-preview", "gemini-2.5-pro", "gemini-2.5-flash",
        "gemini-2.5-flash-lite", "gemini-2.0-flash", "gemini-2.0-flash-lite",
        "gemini-1.5-pro-latest", "gemini-1.5-pro", "gemini-1.5-flash"
    };
    return v;
}

inline const std::vector<std::string>& settings_sa_t::openai_models()
{
    static const std::vector<std::string> v = {
        "gpt-5.1 Instant", "gpt-5.1 Thinking", "gpt-5", "gpt-5-mini", "gpt-5-nano",
        "o3-pro", "o3", "o3-mini", "o4-mini",
        "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
        "gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-4o-mini"
    };
    return v;
}

inline const std::vector<std::string>& settings_sa_t::anthropic_models()
{
    static const std::vector<std::string> v = {
        "claude-opus-4-6", "claude-sonnet-4-6",
        "claude-opus-4-5 (High Effort)", "claude-sonnet-4-5", "claude-haiku-4-5",
        "claude-sonnet-4", "claude-3-7-sonnet-thought", "claude-3-7-sonnet",
        "claude-3.5-sonnet-latest", "claude-3.5-haiku-latest",
        "claude-3-opus-latest"
    };
    return v;
}

inline const std::vector<std::string>& settings_sa_t::openrouter_models()
{
    static const std::vector<std::string> v = {
        "moonshotai/kimi-k2:free", "openai/gpt-oss-20b:free",
        "tngtech/deepseek-r1t2-chimera:free"
    };
    return v;
}

inline const std::vector<std::string>& settings_sa_t::copilot_models()
{
    static const std::vector<std::string> v = {
        "gpt-5.3-codex", "claude-sonnet-4", "claude-3.7-sonnet-thought",
        "gemini-2.5-pro", "gpt-4.1", "o4-mini", "gpt-4o"
    };
    return v;
}

inline const std::vector<std::string>& settings_sa_t::local_llm_models()
{
    static const std::vector<std::string> v = {
        "llama3.3:latest", "qwen3:latest", "qwen2.5-coder:latest",
        "deepseek-r1:latest", "deepseek-coder-v2:latest",
        "codellama:latest", "mistral:latest", "phi4:latest"
    };
    return v;
}


inline settings_sa_t g_sa_settings;
