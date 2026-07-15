#pragma once

#include "network_preview_adapter.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace script_engine {

enum class log_level { info, warn, error, debug, output, command };

struct log_entry {
    uint64_t timestamp = 0;
    uint64_t wall_seconds = 0;
    std::string script_name;
    log_level level = log_level::info;
    std::string message;
    uint32_t repeat_count = 1;
};

inline bool& initialized_storage() {
    static bool value = true;
    return value;
}

inline std::vector<log_entry>& log_storage() {
    static std::vector<log_entry> value = {
        { aida::preview::network::monotonic_ms(), 0, "redact-auth.js", log_level::info, "Hook onRequest registered", 1 },
        { aida::preview::network::monotonic_ms(), 0, "tag-findings.js", log_level::info, "Hook onResponse registered", 1 },
        { aida::preview::network::monotonic_ms(), 0, "redact-auth.js", log_level::output, "Request 2041 sanitized in 0.4 ms", 1 }
    };
    return value;
}

inline bool is_initialized() { return initialized_storage(); }

inline bool load_script(const std::string& path) {
    const bool ok = !path.empty();
    log_storage().push_back({ aida::preview::network::monotonic_ms(), 0, path, ok ? log_level::info : log_level::error,
        ok ? "Script loaded" : "Script path is empty", 1 });
    aida::preview::network::record_receipt("Script load", path);
    return ok;
}

inline bool load_script_source(const std::string& name, const std::string& source) {
    const bool ok = !name.empty() && !source.empty();
    log_storage().push_back({ aida::preview::network::monotonic_ms(), 0, name, ok ? log_level::output : log_level::error,
        ok ? "Source evaluated successfully" : "Source is empty", 1 });
    aida::preview::network::record_receipt("Script evaluate", name);
    return ok;
}

inline bool unload_script(const std::string& name) {
    aida::preview::network::record_receipt("Script unload", name);
    return !name.empty();
}

inline void set_script_enabled(const std::string& name, bool enabled) {
    aida::preview::network::record_receipt(enabled ? "Script enabled" : "Script disabled", name);
}

inline size_t registered_hook_count() { return 5; }

inline std::string execute(const std::string& code) {
    const std::string output = code.empty() ? "No expression" : "preview> " + code + "\nundefined";
    log_storage().push_back({ aida::preview::network::monotonic_ms(), 0, "console", log_level::command, code, 1 });
    log_storage().push_back({ aida::preview::network::monotonic_ms(), 0, "console", log_level::output, output, 1 });
    aida::preview::network::record_receipt("Script console", code);
    return output;
}

inline std::vector<log_entry> get_log(size_t max_count = 0) {
    auto& entries = log_storage();
    const size_t count = max_count == 0 ? entries.size() : std::min(max_count, entries.size());
    return std::vector<log_entry>(entries.end() - static_cast<ptrdiff_t>(count), entries.end());
}

inline void clear_log() {
    log_storage().clear();
    aida::preview::network::record_receipt("Script log", "cleared");
}

}

namespace decoder_pipeline {

struct transform_param {
    std::string name;
    std::string label;
    std::string default_value;
    enum class type_t { text, hex_bytes, integer, choice } type = type_t::text;
    std::vector<std::string> choices;
};

struct transform_result {
    bool success = false;
    std::vector<uint8_t> data;
    std::string error;
};

struct transform_def {
    std::string id;
    std::string name;
    std::string category;
    std::vector<transform_param> params;
};

class registry {
public:
    static registry& instance() {
        static registry value;
        return value;
    }

    std::vector<const transform_def*> all() const {
        std::vector<const transform_def*> result;
        for (const auto& transform : transforms_) result.push_back(&transform);
        return result;
    }

private:
    registry() : transforms_({
        { "URL decode", "URL decode", "Encoding", {} },
        { "Base64 decode", "Base64 decode", "Encoding", {} },
        { "Hex decode", "Hex decode", "Encoding", {} },
        { "Gunzip", "Gunzip", "Compression", {} },
        { "JSON pretty", "JSON pretty", "Formatting", {} },
        { "XOR", "XOR", "Crypto", { { "key", "Key", "41", transform_param::type_t::hex_bytes, {} } } },
        { "SHA-256", "SHA-256", "Hashing", {} }
    }) {}

    std::vector<transform_def> transforms_;
};

inline transform_result apply_single(const std::string& transform_id,
                                     const std::vector<uint8_t>& input,
                                     const std::map<std::string, std::string>&) {
    transform_result result;
    result.success = true;
    result.data = input;
    if (transform_id == "URL decode") {
        std::vector<uint8_t> decoded;
        for (size_t i = 0; i < result.data.size(); ++i) {
            if (result.data[i] == '%' && i + 2 < result.data.size()) {
                auto nibble = [](uint8_t value) -> int {
                    if (value >= '0' && value <= '9') return value - '0';
                    value = static_cast<uint8_t>(std::tolower(value));
                    return value >= 'a' && value <= 'f' ? 10 + value - 'a' : -1;
                };
                const int high = nibble(result.data[i + 1]);
                const int low = nibble(result.data[i + 2]);
                if (high >= 0 && low >= 0) {
                    decoded.push_back(static_cast<uint8_t>((high << 4) | low));
                    i += 2;
                    continue;
                }
            }
            decoded.push_back(result.data[i]);
        }
        result.data = std::move(decoded);
    } else if (transform_id == "JSON pretty") {
        const std::string text(result.data.begin(), result.data.end());
        std::string formatted;
        int depth = 0;
        bool quoted = false;
        for (char character : text) {
            if (character == '"') quoted = !quoted;
            if (!quoted && (character == '}' || character == ']')) {
                formatted += '\n';
                --depth;
                formatted.append(static_cast<size_t>(std::max(0, depth)) * 2, ' ');
            }
            formatted += character;
            if (!quoted && (character == '{' || character == '[' || character == ',')) {
                if (character != ',') ++depth;
                formatted += '\n';
                formatted.append(static_cast<size_t>(std::max(0, depth)) * 2, ' ');
            }
        }
        result.data.assign(formatted.begin(), formatted.end());
    }
    aida::preview::network::record_receipt("Decoder transform", transform_id);
    return result;
}

}
