#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")

namespace sa_settings_detail
{
    static constexpr uint8_t CFG_OBF_KEY[] = {
        0xA3, 0x7B, 0x1E, 0xD4, 0x5F, 0x92, 0xC8, 0x06,
        0xE1, 0x3A, 0x8D, 0x47, 0xB0, 0x6C, 0xF5, 0x29
    };
    static constexpr const char CFG_OBF_PREFIX[]   = "enc1:";
    static constexpr const char CFG_DPAPI_PREFIX[] = "dpapi1:";

    inline std::string trim(const std::string& s)
    {
        const auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos)
            return {};
        return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
    }

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
        if ((text.size() % 2) != 0)
            return false;

        out.clear();
        out.reserve(text.size() / 2);
        for (size_t i = 0; i < text.size(); i += 2) {
            unsigned int v = 0;
            std::istringstream iss(text.substr(i, 2));
            iss >> std::hex >> v;
            if (iss.fail())
                return false;
            out.push_back(static_cast<unsigned char>(v));
        }
        return true;
    }

    inline std::string protect_dpapi(const std::string& plaintext, const char* scope)
    {
        if (plaintext.empty())
            return plaintext;

        DATA_BLOB input_blob{
            static_cast<DWORD>(plaintext.size()),
            reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()))
        };
        DATA_BLOB entropy_blob{
            static_cast<DWORD>(std::strlen(scope)),
            reinterpret_cast<BYTE*>(const_cast<char*>(scope))
        };
        DATA_BLOB output_blob{};

        if (!CryptProtectData(&input_blob, L"AiDA Standalone Secret", &entropy_blob,
                              nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output_blob))
            return {};

        const std::string encoded = hex_encode(output_blob.pbData, output_blob.cbData);
        LocalFree(output_blob.pbData);
        return std::string(CFG_DPAPI_PREFIX) + encoded;
    }

    inline std::string unprotect_dpapi(const std::string& encoded, const char* scope)
    {
        if (encoded.compare(0, std::strlen(CFG_DPAPI_PREFIX), CFG_DPAPI_PREFIX) != 0)
            return {};

        std::vector<unsigned char> bytes;
        if (!hex_decode(encoded.substr(std::strlen(CFG_DPAPI_PREFIX)), bytes))
            return {};

        DATA_BLOB input_blob{static_cast<DWORD>(bytes.size()), bytes.data()};
        DATA_BLOB entropy_blob{
            static_cast<DWORD>(std::strlen(scope)),
            reinterpret_cast<BYTE*>(const_cast<char*>(scope))
        };
        DATA_BLOB output_blob{};

        if (!CryptUnprotectData(&input_blob, nullptr, &entropy_blob, nullptr, nullptr,
                                CRYPTPROTECT_UI_FORBIDDEN, &output_blob))
            return {};

        std::string result(reinterpret_cast<const char*>(output_blob.pbData), output_blob.cbData);
        SecureZeroMemory(output_blob.pbData, output_blob.cbData);
        LocalFree(output_blob.pbData);
        return result;
    }

    inline std::string obfuscate_key(const std::string& plain)
    {
        if (plain.empty())
            return plain;

        const auto dpapi = protect_dpapi(plain, "AiDA:standalone:settings:v2");
        if (!dpapi.empty())
            return dpapi;

        std::string out(CFG_OBF_PREFIX);
        for (size_t i = 0; i < plain.size(); ++i) {
            const uint8_t b = static_cast<uint8_t>(plain[i]) ^ CFG_OBF_KEY[i % sizeof(CFG_OBF_KEY)];
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", b);
            out += hex;
        }
        return out;
    }

    inline std::string deobfuscate_key(const std::string& encoded)
    {
        if (encoded.empty())
            return encoded;
        if (encoded.compare(0, std::strlen(CFG_DPAPI_PREFIX), CFG_DPAPI_PREFIX) == 0)
            return unprotect_dpapi(encoded, "AiDA:standalone:settings:v2");
        if (encoded.compare(0, std::strlen(CFG_OBF_PREFIX), CFG_OBF_PREFIX) != 0)
            return encoded;

        const std::string hex_part = encoded.substr(std::strlen(CFG_OBF_PREFIX));
        std::string out;
        out.reserve(hex_part.size() / 2);
        for (size_t i = 0; i + 1 < hex_part.size(); i += 2) {
            const uint8_t b = static_cast<uint8_t>(std::stoi(hex_part.substr(i, 2), nullptr, 16));
            out.push_back(static_cast<char>(b ^ CFG_OBF_KEY[(i / 2) % sizeof(CFG_OBF_KEY)]));
        }
        return out;
    }

    inline std::string make_profile_id(const std::string& display_name, size_t index)
    {
        std::string id;
        id.reserve(display_name.size() + 8);
        for (unsigned char c : display_name) {
            if (std::isalnum(c))
                id.push_back(static_cast<char>(std::tolower(c)));
            else if (c == ' ' || c == '-' || c == '_')
                id.push_back('-');
        }
        if (id.empty())
            id = "profile";
        id += "-" + std::to_string(index);
        return id;
    }

    inline std::string normalize_provider_kind(std::string kind)
    {
        kind = trim(kind);
        if (kind == "openai")
            return "openai_compatible";
        if (kind == "local_llm")
            return "local";
        if (kind.empty())
            return "openai_compatible";
        return kind;
    }

    inline bool read_json_file(const std::filesystem::path& path, nlohmann::json& out)
    {
        std::ifstream ifs(path);
        if (!ifs.is_open())
            return false;
        try {
            ifs >> out;
            return out.is_object();
        } catch (...) {
            out = nlohmann::json::object();
            return false;
        }
    }
}

struct provider_profile_t
{
    std::string id;
    std::string display_name;
    std::string kind = "openai_compatible";
    std::string base_url;
    std::string api_key;
    std::string model;
    std::string headers_json;
    bool        enabled = true;
};

struct theme_pack_t
{
    int         version = 1;
    std::string name;
    std::string palette_json;
    uint32_t    acrylic_color = 0;
    std::string icon_mode = "builtin";
    int         builtin_icon = 3;
    std::string custom_icon_path;
};

struct workspace_state_t
{
    std::string root_path;
    std::string open_tabs_json;
    int         active_tab = -1;
    std::string last_active_path;
    std::string active_view = "editor";
    float       left_width = 220.0f;
    float       right_width = 350.0f;
    float       bottom_height = 180.0f;
    bool        left_visible = true;
    bool        right_visible = true;
    bool        bottom_visible = false;
};

struct sandbox_settings_t
{
    bool        enabled = true;
    int         timeout_ms = 30000;
    int         memory_limit_mb = 256;
    std::string network_mode = "off";
    std::string shared_folder_root;
};


struct mcp_client_server_t
{
    std::string name;
    std::string url;
    std::string transport = "http_sse";
    std::string command;
    std::string args;
    std::string api_key;
    bool        enabled = true;
    bool        auto_connect = true;
};

struct settings_sa_t
{
    std::vector<provider_profile_t> provider_profiles;
    std::string active_provider_profile_id;

    double      temperature = 0.7;
    int         mcp_port = 29117;
    bool        mcp_enabled = true;

    std::string license_key;
    std::string license_plan;
    std::string license_sig_payload;
    std::string license_server_sig;
    std::string license_session_token;
    std::string license_server_nonce;
    std::string license_client_nonce;
    std::string license_hwid;
    int64_t     license_issued_at = 0;
    int64_t     license_ttl = 3600;
    std::string firebase_api_key;

    int         active_theme_idx = 0;
    int         active_custom_theme_idx = -1;
    int         editor_tab_size = 4;
    float       editor_font_size = 14.0f;
    bool        editor_auto_complete = true;
    bool        editor_line_numbers = true;
    bool        editor_highlight_line = true;
    int         theme_icon_index = 3;
    std::string custom_icon_path;
    std::string custom_themes_json;


    bool        thinking_enabled  = false;
    int         thinking_budget   = 10000;
    int         effort_level      = 2;
    bool        prompt_caching    = true;
    int         task_budget_tokens = 0;
    bool        web_search_enabled = false;
    int         max_agentic_rounds = 15;
    bool        fast_mode          = false;
    bool        redact_thinking    = false;
    bool        first_run_completed = false;


    bool        editor_word_wrap    = false;
    bool        editor_minimap      = false;
    bool        editor_bracket_match = true;
    float       chat_font_size      = 13.0f;
    int         chat_density        = 1;
    bool        chat_show_timestamps = true;
    bool        chat_show_tokens     = true;
    bool        ghost_text_enabled   = false;
    std::string ghost_text_model;
    std::string ghost_text_provider_id;
    int         ghost_text_debounce_ms = 500;


    bool        auto_save_enabled  = false;
    int         auto_save_interval_s = 30;


    std::string terminal_shell = "powershell.exe";
    int         terminal_scrollback = 10000;


    bool        tool_auto_approve    = false;
    std::string tool_always_allow;
    std::string tool_always_deny;


    std::string recent_workspaces_json;


    bool        activity_bar_visible = true;


    int         window_x = -1;
    int         window_y = -1;
    int         window_w = 1400;
    int         window_h = 850;
    bool        window_maximized = false;

    workspace_state_t workspace;
    sandbox_settings_t sandbox;
    std::vector<mcp_client_server_t> mcp_client_servers;

    std::string marketplace_installed_json;


    std::string api_provider = "openai_compatible";
    std::string gemini_api_key;
    std::string gemini_model_name = "gemini-2.5-flash";
    std::string gemini_base_url;
    std::string openai_api_key;
    std::string openai_model_name = "gpt-4.1-mini";
    std::string openai_base_url;
    std::string openrouter_api_key;
    std::string openrouter_model_name = "openai/gpt-oss-20b:free";
    std::string anthropic_api_key;
    std::string anthropic_model_name = "claude-sonnet-4";
    std::string anthropic_base_url;
    std::string local_llm_base_url = "http://127.0.0.1:11434";
    std::string local_llm_model_name = "llama3.3:latest";
    std::string local_llm_api_key;

    static std::filesystem::path config_path()
    {
        wchar_t* appdata = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
            auto path = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"settings.json";
            CoTaskMemFree(appdata);
            return path;
        }
        return std::filesystem::current_path() / "aida_standalone_settings.json";
    }

    static std::filesystem::path legacy_config_path()
    {
        wchar_t* appdata = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
            auto path = std::filesystem::path(appdata) / L"Hex-Rays" / L"IDA Pro" / L"ai_assistant.cfg";
            CoTaskMemFree(appdata);
            return path;
        }
        return {};
    }

    static const std::vector<std::string>& provider_kinds()
    {
        static const std::vector<std::string> v = {
            "openai_compatible", "gemini", "anthropic", "openrouter", "local"
        };
        return v;
    }

    static const std::vector<std::string>& gemini_models()
    {
        static const std::vector<std::string> v = {
            "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite",
            "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"
        };
        return v;
    }

    static const std::vector<std::string>& openai_models()
    {
        static const std::vector<std::string> v = {
            "gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-4.1", "gpt-4.1-mini",
            "gpt-4o", "gpt-4o-mini", "o4-mini", "o3-mini"
        };
        return v;
    }

    static const std::vector<std::string>& anthropic_models()
    {
        static const std::vector<std::string> v = {
            "claude-opus-4-1", "claude-sonnet-4", "claude-3-7-sonnet", "claude-3.5-sonnet"
        };
        return v;
    }

    static const std::vector<std::string>& openrouter_models()
    {
        static const std::vector<std::string> v = {
            "openai/gpt-oss-20b:free", "moonshotai/kimi-k2:free", "google/gemini-2.5-flash"
        };
        return v;
    }

    static const std::vector<std::string>& local_llm_models()
    {
        static const std::vector<std::string> v = {
            "llama3.3:latest", "qwen2.5-coder:latest", "deepseek-r1:latest", "mistral:latest"
        };
        return v;
    }

    static const std::vector<std::string>& models_for_kind(const std::string& kind)
    {
        const std::string normalized = sa_settings_detail::normalize_provider_kind(kind);
        if (normalized == "gemini")
            return gemini_models();
        if (normalized == "anthropic")
            return anthropic_models();
        if (normalized == "openrouter")
            return openrouter_models();
        if (normalized == "local")
            return local_llm_models();
        return openai_models();
    }

    provider_profile_t* get_active_profile()
    {
        ensure_default_profiles();
        auto it = std::find_if(provider_profiles.begin(), provider_profiles.end(),
            [&](const provider_profile_t& profile) {
                return profile.id == active_provider_profile_id;
            });
        if (it != provider_profiles.end())
            return &(*it);

        active_provider_profile_id = provider_profiles.front().id;
        return &provider_profiles.front();
    }

    const provider_profile_t* get_active_profile() const
    {
        return const_cast<settings_sa_t*>(this)->get_active_profile();
    }

    std::string get_active_profile_kind() const
    {
        const auto* profile = get_active_profile();
        return profile ? sa_settings_detail::normalize_provider_kind(profile->kind) : std::string("openai_compatible");
    }

    std::string get_active_profile_name() const
    {
        const auto* profile = get_active_profile();
        return profile ? profile->display_name : std::string("Default");
    }

    std::string get_active_api_key() const
    {
        const auto* profile = get_active_profile();
        return profile ? profile->api_key : std::string();
    }

    std::string get_active_model() const
    {
        const auto* profile = get_active_profile();
        return profile ? profile->model : std::string();
    }

    std::string get_active_base_url() const
    {
        const auto* profile = get_active_profile();
        if (!profile)
            return {};
        if (!profile->base_url.empty())
            return profile->base_url;

        const std::string kind = sa_settings_detail::normalize_provider_kind(profile->kind);
        if (kind == "gemini")
            return "https://generativelanguage.googleapis.com";
        if (kind == "anthropic")
            return "https://api.anthropic.com";
        if (kind == "openrouter")
            return "https://openrouter.ai";
        if (kind == "local")
            return "http://127.0.0.1:11434";
        return "https://api.openai.com";
    }

    std::map<std::string, std::string> get_active_headers() const
    {
        std::map<std::string, std::string> headers;
        const auto* profile = get_active_profile();
        if (!profile || profile->headers_json.empty())
            return headers;

        try {
            const auto parsed = nlohmann::json::parse(profile->headers_json);
            if (!parsed.is_object())
                return headers;
            for (auto it = parsed.begin(); it != parsed.end(); ++it) {
                if (it.value().is_string())
                    headers[it.key()] = it.value().get<std::string>();
            }
        } catch (...) {
        }
        return headers;
    }

    void ensure_default_profiles()
    {
        if (!provider_profiles.empty()) {
            if (active_provider_profile_id.empty())
                active_provider_profile_id = provider_profiles.front().id;
            return;
        }

        provider_profiles = {
            {"openai-default", "OpenAI Compatible", "openai_compatible", "https://api.openai.com", {}, "gpt-4.1-mini", "{}", true},
            {"gemini-default", "Gemini", "gemini", "https://generativelanguage.googleapis.com", {}, "gemini-2.5-flash", "{}", true},
            {"anthropic-default", "Anthropic", "anthropic", "https://api.anthropic.com", {}, "claude-sonnet-4", "{}", true},
            {"openrouter-default", "OpenRouter", "openrouter", "https://openrouter.ai", {}, "openai/gpt-oss-20b:free", "{}", true},
            {"local-default", "Local LLM", "local", "http://127.0.0.1:11434", {}, "llama3.3:latest", "{}", true},
        };
        active_provider_profile_id = provider_profiles.front().id;
        sync_legacy_fields_from_active_profile();
    }

    void sync_legacy_fields_from_active_profile()
    {
        const auto* profile = get_active_profile();
        if (!profile)
            return;

        api_provider = sa_settings_detail::normalize_provider_kind(profile->kind);
        theme_icon_index = std::clamp(theme_icon_index, 0, 3);

        if (api_provider == "gemini") {
            gemini_api_key = profile->api_key;
            gemini_model_name = profile->model;
            gemini_base_url = profile->base_url;
        } else if (api_provider == "anthropic") {
            anthropic_api_key = profile->api_key;
            anthropic_model_name = profile->model;
            anthropic_base_url = profile->base_url;
        } else if (api_provider == "openrouter") {
            openrouter_api_key = profile->api_key;
            openrouter_model_name = profile->model;
        } else if (api_provider == "local") {
            local_llm_api_key = profile->api_key;
            local_llm_model_name = profile->model;
            local_llm_base_url = profile->base_url;
        } else {
            openai_api_key = profile->api_key;
            openai_model_name = profile->model;
            openai_base_url = profile->base_url;
            api_provider = "openai_compatible";
        }
    }

    void apply_legacy_fields_to_active_profile()
    {
        auto* profile = get_active_profile();
        if (!profile)
            return;

        const std::string kind = sa_settings_detail::normalize_provider_kind(api_provider);
        profile->kind = kind;
        if (kind == "gemini") {
            profile->base_url = gemini_base_url;
            profile->api_key = gemini_api_key;
            profile->model = gemini_model_name;
        } else if (kind == "anthropic") {
            profile->base_url = anthropic_base_url;
            profile->api_key = anthropic_api_key;
            profile->model = anthropic_model_name;
        } else if (kind == "openrouter") {
            profile->base_url = "https://openrouter.ai";
            profile->api_key = openrouter_api_key;
            profile->model = openrouter_model_name;
        } else if (kind == "local") {
            profile->base_url = local_llm_base_url;
            profile->api_key = local_llm_api_key;
            profile->model = local_llm_model_name;
        } else {
            profile->kind = "openai_compatible";
            profile->base_url = openai_base_url;
            profile->api_key = openai_api_key;
            profile->model = openai_model_name;
        }
    }

    void migrate_legacy_fields_into_profiles()
    {
        if (!provider_profiles.empty())
            return;

        if (!openai_model_name.empty() || !openai_api_key.empty() || !openai_base_url.empty()) {
            provider_profiles.push_back({
                "openai-default", "OpenAI Compatible", "openai_compatible",
                openai_base_url.empty() ? "https://api.openai.com" : openai_base_url,
                openai_api_key, openai_model_name.empty() ? "gpt-4.1-mini" : openai_model_name, "{}", true
            });
        }
        if (!gemini_model_name.empty() || !gemini_api_key.empty()) {
            provider_profiles.push_back({
                "gemini-default", "Gemini", "gemini",
                gemini_base_url.empty() ? "https://generativelanguage.googleapis.com" : gemini_base_url,
                gemini_api_key, gemini_model_name.empty() ? "gemini-2.5-flash" : gemini_model_name, "{}", true
            });
        }
        if (!anthropic_model_name.empty() || !anthropic_api_key.empty()) {
            provider_profiles.push_back({
                "anthropic-default", "Anthropic", "anthropic",
                anthropic_base_url.empty() ? "https://api.anthropic.com" : anthropic_base_url,
                anthropic_api_key, anthropic_model_name.empty() ? "claude-sonnet-4" : anthropic_model_name, "{}", true
            });
        }
        if (!openrouter_model_name.empty() || !openrouter_api_key.empty()) {
            provider_profiles.push_back({
                "openrouter-default", "OpenRouter", "openrouter",
                "https://openrouter.ai", openrouter_api_key,
                openrouter_model_name.empty() ? "openai/gpt-oss-20b:free" : openrouter_model_name,
                "{}", true
            });
        }
        if (!local_llm_model_name.empty() || !local_llm_base_url.empty()) {
            provider_profiles.push_back({
                "local-default", "Local LLM", "local",
                local_llm_base_url.empty() ? "http://127.0.0.1:11434" : local_llm_base_url,
                local_llm_api_key,
                local_llm_model_name.empty() ? "llama3.3:latest" : local_llm_model_name,
                "{}", true
            });
        }

        ensure_default_profiles();
        if (active_provider_profile_id.empty()) {
            const std::string desired = sa_settings_detail::normalize_provider_kind(api_provider);
            auto it = std::find_if(provider_profiles.begin(), provider_profiles.end(),
                [&](const provider_profile_t& profile) {
                    return sa_settings_detail::normalize_provider_kind(profile.kind) == desired;
                });
            active_provider_profile_id = (it != provider_profiles.end()) ? it->id : provider_profiles.front().id;
        }
    }

    bool load()
    {
        nlohmann::json root;
        auto source = config_path();
        bool imported_legacy = false;

        if (!sa_settings_detail::read_json_file(source, root)) {
            const auto legacy = legacy_config_path();
            if (!legacy.empty() && sa_settings_detail::read_json_file(legacy, root)) {
                imported_legacy = true;
            } else {
                ensure_default_profiles();
                return false;
            }
        }

        auto str = [&](const char* key, std::string& dst) {
            if (root.contains(key) && root[key].is_string())
                dst = root[key].get<std::string>();
        };
        auto secret = [&](const char* key, std::string& dst) {
            if (root.contains(key) && root[key].is_string())
                dst = sa_settings_detail::deobfuscate_key(sa_settings_detail::trim(root[key].get<std::string>()));
        };
        auto integer = [&](const char* key, int& dst) {
            if (root.contains(key) && root[key].is_number_integer())
                dst = root[key].get<int>();
        };
        auto i64 = [&](const char* key, int64_t& dst) {
            if (root.contains(key) && root[key].is_number_integer())
                dst = root[key].get<int64_t>();
        };
        auto boolean = [&](const char* key, bool& dst) {
            if (root.contains(key) && root[key].is_boolean())
                dst = root[key].get<bool>();
        };

        str("api_provider", api_provider);
        secret("gemini_api_key", gemini_api_key);
        str("gemini_model_name", gemini_model_name);
        str("gemini_base_url", gemini_base_url);
        secret("openai_api_key", openai_api_key);
        str("openai_model_name", openai_model_name);
        str("openai_base_url", openai_base_url);
        secret("openrouter_api_key", openrouter_api_key);
        str("openrouter_model_name", openrouter_model_name);
        secret("anthropic_api_key", anthropic_api_key);
        str("anthropic_model_name", anthropic_model_name);
        str("anthropic_base_url", anthropic_base_url);
        secret("local_llm_api_key", local_llm_api_key);
        str("local_llm_model_name", local_llm_model_name);
        str("local_llm_base_url", local_llm_base_url);

        if (root.contains("temperature") && root["temperature"].is_number())
            temperature = root["temperature"].get<double>();
        integer("mcp_port", mcp_port);
        boolean("mcp_enabled", mcp_enabled);

        secret("license_key", license_key);
        str("license_plan", license_plan);
        str("license_sig_payload", license_sig_payload);
        str("license_server_sig", license_server_sig);
        str("license_session_token", license_session_token);
        str("license_server_nonce", license_server_nonce);
        str("license_client_nonce", license_client_nonce);
        str("license_hwid", license_hwid);
        i64("license_issued_at", license_issued_at);
        i64("license_ttl", license_ttl);
        secret("firebase_api_key", firebase_api_key);

        integer("active_theme_idx", active_theme_idx);
        integer("active_custom_theme_idx", active_custom_theme_idx);
        integer("editor_tab_size", editor_tab_size);
        boolean("editor_auto_complete", editor_auto_complete);
        boolean("editor_line_numbers", editor_line_numbers);
        boolean("editor_highlight_line", editor_highlight_line);
        integer("theme_icon_index", theme_icon_index);
        str("custom_icon_path", custom_icon_path);
        str("custom_themes_json", custom_themes_json);
        if (root.contains("editor_font_size") && root["editor_font_size"].is_number())
            editor_font_size = root["editor_font_size"].get<float>();
        if (root.contains("chat_font_size") && root["chat_font_size"].is_number())
            chat_font_size = root["chat_font_size"].get<float>();

        boolean("thinking_enabled", thinking_enabled);
        integer("thinking_budget", thinking_budget);
        integer("effort_level", effort_level);
        boolean("prompt_caching", prompt_caching);
        integer("task_budget_tokens", task_budget_tokens);
        boolean("web_search_enabled", web_search_enabled);
        integer("max_agentic_rounds", max_agentic_rounds);
        boolean("fast_mode", fast_mode);
        boolean("redact_thinking", redact_thinking);
        boolean("first_run_completed", first_run_completed);

        boolean("editor_word_wrap", editor_word_wrap);
        boolean("editor_minimap", editor_minimap);
        boolean("editor_bracket_match", editor_bracket_match);
        integer("chat_density", chat_density);
        boolean("chat_show_timestamps", chat_show_timestamps);
        boolean("chat_show_tokens", chat_show_tokens);
        boolean("ghost_text_enabled", ghost_text_enabled);
        str("ghost_text_model", ghost_text_model);
        str("ghost_text_provider_id", ghost_text_provider_id);
        integer("ghost_text_debounce_ms", ghost_text_debounce_ms);

        boolean("auto_save_enabled", auto_save_enabled);
        integer("auto_save_interval_s", auto_save_interval_s);
        str("terminal_shell", terminal_shell);
        integer("terminal_scrollback", terminal_scrollback);
        boolean("tool_auto_approve", tool_auto_approve);
        str("tool_always_allow", tool_always_allow);
        str("tool_always_deny", tool_always_deny);
        str("recent_workspaces_json", recent_workspaces_json);
        boolean("activity_bar_visible", activity_bar_visible);

        integer("window_x", window_x);
        integer("window_y", window_y);
        integer("window_w", window_w);
        integer("window_h", window_h);
        boolean("window_maximized", window_maximized);

        if (root.contains("provider_profiles") && root["provider_profiles"].is_array()) {
            provider_profiles.clear();
            size_t index = 0;
            for (const auto& item : root["provider_profiles"]) {
                if (!item.is_object())
                    continue;
                provider_profile_t profile;
                profile.display_name = item.value("display_name", item.value("name", "Profile"));
                profile.id = item.value("id", sa_settings_detail::make_profile_id(profile.display_name, index++));
                profile.kind = sa_settings_detail::normalize_provider_kind(item.value("kind", "openai_compatible"));
                profile.base_url = item.value("base_url", "");
                if (item.contains("api_key") && item["api_key"].is_string())
                    profile.api_key = sa_settings_detail::deobfuscate_key(sa_settings_detail::trim(item["api_key"].get<std::string>()));
                profile.model = item.value("model", "");
                profile.headers_json = item.value("headers_json", "{}");
                profile.enabled = item.value("enabled", true);
                provider_profiles.push_back(std::move(profile));
            }
        }
        str("active_provider_profile_id", active_provider_profile_id);

        if (root.contains("workspace") && root["workspace"].is_object()) {
            const auto& ws = root["workspace"];
            workspace.root_path = ws.value("root_path", "");
            workspace.open_tabs_json = ws.value("open_tabs_json", "[]");
            workspace.active_tab = ws.value("active_tab", -1);
            workspace.last_active_path = ws.value("last_active_path", "");
            workspace.active_view = ws.value("active_view", "editor");
            if (ws.contains("left_width") && ws["left_width"].is_number())
                workspace.left_width = ws["left_width"].get<float>();
            if (ws.contains("right_width") && ws["right_width"].is_number())
                workspace.right_width = ws["right_width"].get<float>();
            if (ws.contains("bottom_height") && ws["bottom_height"].is_number())
                workspace.bottom_height = ws["bottom_height"].get<float>();
            workspace.left_visible   = ws.value("left_visible", true);
            workspace.right_visible  = ws.value("right_visible", true);
            workspace.bottom_visible = ws.value("bottom_visible", false);
        }

        if (root.contains("sandbox") && root["sandbox"].is_object()) {
            const auto& sb = root["sandbox"];
            sandbox.enabled = sb.value("enabled", true);
            sandbox.timeout_ms = sb.value("timeout_ms", 30000);
            sandbox.memory_limit_mb = sb.value("memory_limit_mb", 256);
            sandbox.network_mode = sb.value("network_mode", "off");
            sandbox.shared_folder_root = sb.value("shared_folder_root", "");
        }


        if (root.contains("mcp_client_servers") && root["mcp_client_servers"].is_array()) {
            mcp_client_servers.clear();
            for (const auto& item : root["mcp_client_servers"]) {
                if (!item.is_object()) continue;
                mcp_client_server_t srv;
                srv.name         = item.value("name", "");
                srv.url          = item.value("url", "");
                srv.transport    = item.value("transport", "http_sse");
                srv.command      = item.value("command", "");
                srv.args         = item.value("args", "");
                if (item.contains("api_key") && item["api_key"].is_string())
                    srv.api_key = sa_settings_detail::deobfuscate_key(
                        sa_settings_detail::trim(item["api_key"].get<std::string>()));
                srv.enabled      = item.value("enabled", true);
                srv.auto_connect = item.value("auto_connect", true);
                if (!srv.name.empty())
                    mcp_client_servers.push_back(std::move(srv));
            }
        }

        marketplace_installed_json = root.value("marketplace_installed_json", "");

        migrate_legacy_fields_into_profiles();
        sync_legacy_fields_from_active_profile();

        if (imported_legacy)
            save();
        return true;
    }

    bool save()
    {
        ensure_default_profiles();
        apply_legacy_fields_to_active_profile();
        sync_legacy_fields_from_active_profile();

        auto path = config_path();
        std::filesystem::create_directories(path.parent_path());

        nlohmann::json root = nlohmann::json::object();
        root["api_provider"] = api_provider;
        root["gemini_api_key"] = sa_settings_detail::obfuscate_key(gemini_api_key);
        root["gemini_model_name"] = gemini_model_name;
        root["gemini_base_url"] = gemini_base_url;
        root["openai_api_key"] = sa_settings_detail::obfuscate_key(openai_api_key);
        root["openai_model_name"] = openai_model_name;
        root["openai_base_url"] = openai_base_url;
        root["openrouter_api_key"] = sa_settings_detail::obfuscate_key(openrouter_api_key);
        root["openrouter_model_name"] = openrouter_model_name;
        root["anthropic_api_key"] = sa_settings_detail::obfuscate_key(anthropic_api_key);
        root["anthropic_model_name"] = anthropic_model_name;
        root["anthropic_base_url"] = anthropic_base_url;
        root["local_llm_api_key"] = sa_settings_detail::obfuscate_key(local_llm_api_key);
        root["local_llm_model_name"] = local_llm_model_name;
        root["local_llm_base_url"] = local_llm_base_url;

        root["temperature"] = temperature;
        root["mcp_port"] = mcp_port;
        root["mcp_enabled"] = mcp_enabled;
        root["license_key"] = sa_settings_detail::obfuscate_key(license_key);
        root["license_plan"] = license_plan;
        root["license_sig_payload"] = license_sig_payload;
        root["license_server_sig"] = license_server_sig;
        root["license_session_token"] = license_session_token;
        root["license_server_nonce"] = license_server_nonce;
        root["license_client_nonce"] = license_client_nonce;
        root["license_hwid"] = license_hwid;
        root["license_issued_at"] = license_issued_at;
        root["license_ttl"] = license_ttl;
        root["firebase_api_key"] = sa_settings_detail::obfuscate_key(firebase_api_key);

        root["active_theme_idx"] = active_theme_idx;
        root["active_custom_theme_idx"] = active_custom_theme_idx;
        root["editor_tab_size"] = editor_tab_size;
        root["editor_font_size"] = editor_font_size;
        root["editor_auto_complete"] = editor_auto_complete;
        root["editor_line_numbers"] = editor_line_numbers;
        root["editor_highlight_line"] = editor_highlight_line;
        root["theme_icon_index"] = theme_icon_index;
        root["custom_icon_path"] = custom_icon_path;
        root["custom_themes_json"] = custom_themes_json;

        root["thinking_enabled"] = thinking_enabled;
        root["thinking_budget"] = thinking_budget;
        root["effort_level"] = effort_level;
        root["prompt_caching"] = prompt_caching;
        root["task_budget_tokens"] = task_budget_tokens;
        root["web_search_enabled"] = web_search_enabled;
        root["max_agentic_rounds"] = max_agentic_rounds;
        root["fast_mode"] = fast_mode;
        root["redact_thinking"] = redact_thinking;
        root["first_run_completed"] = first_run_completed;
        root["chat_font_size"] = chat_font_size;
        root["editor_word_wrap"] = editor_word_wrap;
        root["editor_minimap"] = editor_minimap;
        root["editor_bracket_match"] = editor_bracket_match;
        root["chat_density"] = chat_density;
        root["chat_show_timestamps"] = chat_show_timestamps;
        root["chat_show_tokens"] = chat_show_tokens;
        root["ghost_text_enabled"] = ghost_text_enabled;
        root["ghost_text_model"] = ghost_text_model;
        root["ghost_text_provider_id"] = ghost_text_provider_id;
        root["ghost_text_debounce_ms"] = ghost_text_debounce_ms;

        root["auto_save_enabled"] = auto_save_enabled;
        root["auto_save_interval_s"] = auto_save_interval_s;
        root["terminal_shell"] = terminal_shell;
        root["terminal_scrollback"] = terminal_scrollback;
        root["tool_auto_approve"] = tool_auto_approve;
        root["tool_always_allow"] = tool_always_allow;
        root["tool_always_deny"] = tool_always_deny;
        root["recent_workspaces_json"] = recent_workspaces_json;
        root["activity_bar_visible"] = activity_bar_visible;

        root["window_x"] = window_x;
        root["window_y"] = window_y;
        root["window_w"] = window_w;
        root["window_h"] = window_h;
        root["window_maximized"] = window_maximized;

        nlohmann::json profiles = nlohmann::json::array();
        for (const auto& profile : provider_profiles) {
            profiles.push_back({
                {"id", profile.id},
                {"display_name", profile.display_name},
                {"kind", sa_settings_detail::normalize_provider_kind(profile.kind)},
                {"base_url", profile.base_url},
                {"api_key", sa_settings_detail::obfuscate_key(profile.api_key)},
                {"model", profile.model},
                {"headers_json", profile.headers_json.empty() ? std::string("{}") : profile.headers_json},
                {"enabled", profile.enabled}
            });
        }
        root["provider_profiles"] = profiles;
        root["active_provider_profile_id"] = active_provider_profile_id;

        root["workspace"] = {
            {"root_path", workspace.root_path},
            {"open_tabs_json", workspace.open_tabs_json},
            {"active_tab", workspace.active_tab},
            {"last_active_path", workspace.last_active_path},
            {"active_view", workspace.active_view},
            {"left_width", workspace.left_width},
            {"right_width", workspace.right_width},
            {"bottom_height", workspace.bottom_height},
            {"left_visible", workspace.left_visible},
            {"right_visible", workspace.right_visible},
            {"bottom_visible", workspace.bottom_visible}
        };

        root["sandbox"] = {
            {"enabled", sandbox.enabled},
            {"timeout_ms", sandbox.timeout_ms},
            {"memory_limit_mb", sandbox.memory_limit_mb},
            {"network_mode", sandbox.network_mode},
            {"shared_folder_root", sandbox.shared_folder_root}
        };


        nlohmann::json mcp_clients = nlohmann::json::array();
        for (const auto& srv : mcp_client_servers) {
            mcp_clients.push_back({
                {"name",         srv.name},
                {"url",          srv.url},
                {"transport",    srv.transport},
                {"command",      srv.command},
                {"args",         srv.args},
                {"api_key",      sa_settings_detail::obfuscate_key(srv.api_key)},
                {"enabled",      srv.enabled},
                {"auto_connect", srv.auto_connect}
            });
        }
        root["mcp_client_servers"] = mcp_clients;
        root["marketplace_installed_json"] = marketplace_installed_json;

        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs.is_open())
            return false;
        ofs << root.dump(4);
        return true;
    }
};

inline settings_sa_t g_sa_settings;
