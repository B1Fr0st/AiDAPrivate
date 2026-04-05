#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ssl_keylog {

// NSS Key Log Format entry
// Format: <label> <client_random_hex> <secret_hex>
// Labels: CLIENT_RANDOM, CLIENT_EARLY_TRAFFIC_SECRET, CLIENT_HANDSHAKE_TRAFFIC_SECRET,
//         SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, etc.
struct keylog_entry {
    std::string label;
    std::string client_random_hex; // 64 hex chars (32 bytes)
    std::string secret_hex;
    uint64_t    timestamp = 0;    // when this entry was read
};

// State for the SSLKEYLOGFILE watcher
struct state_t {
    std::string                keylog_path;
    std::atomic<bool>          watching{false};
    std::thread                watcher_thread;

    std::mutex                 entries_mutex;
    std::deque<keylog_entry>   entries;
    size_t                     max_entries = 8192;

    // Map: client_random_hex -> vector of secrets (for TLS 1.2: single CLIENT_RANDOM entry;
    // for TLS 1.3: multiple per-stage secrets)
    std::unordered_map<std::string, std::vector<keylog_entry>> by_client_random;

    size_t                     file_pos = 0;  // current read position in log file
};

inline state_t g_state;

// ─── Launch Process with SSLKEYLOGFILE ────────────────────────────

struct launch_result {
    bool     success = false;
    uint32_t pid = 0;
    std::string error;
    std::string keylog_path;
};

inline launch_result launch_with_keylog(const std::string& exe_path,
                                         const std::string& args = {},
                                         const std::string& keylog_path = {}) {
    launch_result result;

    // Determine keylog file path
    std::string kpath = keylog_path;
    if (kpath.empty()) {
        char temp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp);
        kpath = std::string(temp) + "aida_sslkeylog_" + std::to_string(GetCurrentProcessId()) + ".log";
    }
    result.keylog_path = kpath;

    // Build command line
    std::string cmdline = "\"" + exe_path + "\"";
    if (!args.empty()) cmdline += " " + args;

    // Build environment block with SSLKEYLOGFILE added
    // Get current environment
    LPCH env_block = GetEnvironmentStringsA();
    if (!env_block) {
        result.error = "Failed to get environment strings";
        return result;
    }

    // Calculate current env block size and build new block
    std::vector<char> new_env;
    const char* p = env_block;
    bool found_keylog = false;

    while (*p) {
        std::string var(p);
        size_t len = var.size();

        // Check if this is SSLKEYLOGFILE - replace it
        if (var.size() > 14 && _strnicmp(var.c_str(), "SSLKEYLOGFILE=", 14) == 0) {
            std::string new_var = "SSLKEYLOGFILE=" + kpath;
            new_env.insert(new_env.end(), new_var.begin(), new_var.end());
            new_env.push_back('\0');
            found_keylog = true;
        } else {
            new_env.insert(new_env.end(), var.begin(), var.end());
            new_env.push_back('\0');
        }
        p += len + 1;
    }

    // Add SSLKEYLOGFILE if not already present
    if (!found_keylog) {
        std::string new_var = "SSLKEYLOGFILE=" + kpath;
        new_env.insert(new_env.end(), new_var.begin(), new_var.end());
        new_env.push_back('\0');
    }
    new_env.push_back('\0'); // double null terminator

    FreeEnvironmentStringsA(env_block);

    // Create process
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    std::vector<char> cmd_buf(cmdline.begin(), cmdline.end());
    cmd_buf.push_back('\0');

    BOOL ok = CreateProcessA(
        nullptr,
        cmd_buf.data(),
        nullptr, nullptr, FALSE,
        CREATE_NEW_PROCESS_GROUP,
        new_env.data(),
        nullptr,
        &si, &pi);

    if (!ok) {
        result.error = "CreateProcess failed: " + std::to_string(GetLastError());
        return result;
    }

    result.success = true;
    result.pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;
}

// ─── Keylog File Parser ───────────────────────────────────────────

inline bool parse_keylog_line(const std::string& line, keylog_entry& entry) {
    // Skip empty lines and comments
    if (line.empty() || line[0] == '#') return false;

    // Format: <label> <client_random_hex> <secret_hex>
    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;

    entry.label = line.substr(0, sp1);
    entry.client_random_hex = line.substr(sp1 + 1, sp2 - sp1 - 1);
    entry.secret_hex = line.substr(sp2 + 1);

    // Basic validation
    if (entry.client_random_hex.size() != 64) return false;
    if (entry.secret_hex.size() < 32) return false;

    return true;
}

inline void process_new_lines(state_t& state, const std::string& content) {
    std::istringstream iss(content);
    std::string line;
    uint64_t now = GetTickCount64();

    std::lock_guard<std::mutex> lock(state.entries_mutex);
    while (std::getline(iss, line)) {
        // Strip \r if present
        if (!line.empty() && line.back() == '\r') line.pop_back();

        keylog_entry entry;
        if (parse_keylog_line(line, entry)) {
            entry.timestamp = now;

            state.by_client_random[entry.client_random_hex].push_back(entry);
            state.entries.push_back(std::move(entry));

            while (state.entries.size() > state.max_entries)
                state.entries.pop_front();
        }
    }
}

// ─── File Watcher ─────────────────────────────────────────────────

inline void start_watching(const std::string& keylog_path) {
    stop_watching();

    g_state.keylog_path = keylog_path;
    g_state.file_pos = 0;
    g_state.watching.store(true);

    g_state.watcher_thread = std::thread([&state = g_state]() {
        while (state.watching.load()) {
            std::ifstream file(state.keylog_path, std::ios::binary);
            if (file.is_open()) {
                file.seekg(0, std::ios::end);
                auto file_size = file.tellg();

                if (static_cast<size_t>(file_size) > state.file_pos) {
                    file.seekg(static_cast<std::streamoff>(state.file_pos));
                    size_t to_read = static_cast<size_t>(file_size) - state.file_pos;
                    std::string content(to_read, '\0');
                    file.read(content.data(), static_cast<std::streamsize>(to_read));
                    auto actually_read = file.gcount();
                    content.resize(static_cast<size_t>(actually_read));
                    state.file_pos += static_cast<size_t>(actually_read);

                    if (!content.empty()) {
                        process_new_lines(state, content);
                    }
                }
                file.close();
            }
            // Poll every 200ms
            for (int i = 0; i < 20 && state.watching.load(); i++)
                Sleep(10);
        }
    });
}

inline void stop_watching() {
    g_state.watching.store(false);
    if (g_state.watcher_thread.joinable())
        g_state.watcher_thread.join();
}

// ─── Query API ────────────────────────────────────────────────────

inline std::vector<keylog_entry> get_entries(size_t max_count = 0) {
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    std::vector<keylog_entry> result;
    if (max_count == 0 || max_count >= g_state.entries.size()) {
        result.assign(g_state.entries.begin(), g_state.entries.end());
    } else {
        auto start = g_state.entries.end() - static_cast<ptrdiff_t>(max_count);
        result.assign(start, g_state.entries.end());
    }
    return result;
}

inline std::vector<keylog_entry> find_by_client_random(const std::string& client_random_hex) {
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    auto it = g_state.by_client_random.find(client_random_hex);
    if (it != g_state.by_client_random.end()) return it->second;
    return {};
}

inline size_t entry_count() {
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    return g_state.entries.size();
}

inline void clear_entries() {
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    g_state.entries.clear();
    g_state.by_client_random.clear();
}

inline bool is_watching() {
    return g_state.watching.load();
}

} // namespace ssl_keylog
