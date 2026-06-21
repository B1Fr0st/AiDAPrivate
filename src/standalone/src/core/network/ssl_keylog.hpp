#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "work_queue.hpp"
#include "helpers/diag_log.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ssl_keylog {


struct keylog_entry {
    std::string label;
    std::string client_random_hex;
    std::string secret_hex;
    uint64_t    timestamp = 0;
};


struct state_t {
    std::string                keylog_path;
    std::atomic<bool>          watching{false};

    std::mutex                 entries_mutex;
    std::deque<keylog_entry>   entries;
    size_t                     max_entries = 8192;


    std::unordered_map<std::string, std::vector<keylog_entry>> by_client_random;

    size_t                     file_pos = 0;
};

inline state_t g_state;


struct launch_result {
    bool     success = false;
    uint32_t pid = 0;
    std::string error;
    std::string keylog_path;
};

inline launch_result launch_with_keylog(const std::string& exe_path,
                                         const std::string& args = {},
                                         const std::string& keylog_path = {}) {
    static std::mutex s_launch_mutex;
    std::lock_guard<std::mutex> launch_lock(s_launch_mutex);

    launch_result result;


    std::string kpath = keylog_path;
    if (kpath.empty()) {
        const std::string name = "aida_sslkeylog_" + std::to_string(GetCurrentProcessId()) + ".log";
        char path[MAX_PATH] = {};
        if (diag::build_log_path(name.c_str(), path, sizeof(path)))
            kpath = path;
    }
    result.keylog_path = kpath;


    std::string cmdline = "\"" + exe_path + "\"";
    if (!args.empty()) cmdline += " " + args;


    char old_keylog[4096] = {};
    DWORD had_old = GetEnvironmentVariableA("SSLKEYLOGFILE", old_keylog, sizeof(old_keylog));


    SetEnvironmentVariableA("SSLKEYLOGFILE", kpath.c_str());


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
        nullptr,
        nullptr,
        &si, &pi);


    if (had_old > 0 && had_old < sizeof(old_keylog))
        SetEnvironmentVariableA("SSLKEYLOGFILE", old_keylog);
    else
        SetEnvironmentVariableA("SSLKEYLOGFILE", nullptr);

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


inline bool parse_keylog_line(const std::string& line, keylog_entry& entry) {

    if (line.empty() || line[0] == '#') return false;


    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;

    entry.label = line.substr(0, sp1);
    entry.client_random_hex = line.substr(sp1 + 1, sp2 - sp1 - 1);
    entry.secret_hex = line.substr(sp2 + 1);


    if (entry.client_random_hex.size() != 64) return false;
    if (entry.secret_hex.size() < 32) return false;

    return true;
}

inline void process_new_lines(state_t& state, const std::string& content) {
    std::istringstream iss(content);
    std::string line;
    uint64_t now = GetTickCount64();
    size_t added = 0;

    std::lock_guard<std::mutex> lock(state.entries_mutex);
    while (std::getline(iss, line)) {

        if (!line.empty() && line.back() == '\r') line.pop_back();

        keylog_entry entry;
        if (parse_keylog_line(line, entry)) {
            entry.timestamp = now;

            state.by_client_random[entry.client_random_hex].push_back(entry);
            state.entries.push_back(std::move(entry));
            ++added;

            while (state.entries.size() > state.max_entries)
                state.entries.pop_front();
        }
    }
    if (added > 0) {
        diag::log_tagged_fmt("network", "ssl_keylog_entries_parsed added=%zu total=%zu",
            added, state.entries.size());
    }
}


inline void stop_watching();

inline void start_watching(const std::string& keylog_path) {
    stop_watching();

    g_state.keylog_path = keylog_path;
    g_state.file_pos = 0;
    g_state.watching.store(true);
    diag::log_tagged_fmt("network", "ssl_keylog_watch_started path='%s'", keylog_path.c_str());

    work_queue::post([&state = g_state]() {
        bool warned_missing = false;
        while (state.watching.load()) {
            std::ifstream file(state.keylog_path, std::ios::binary);
            if (file.is_open()) {
                warned_missing = false;
                file.seekg(0, std::ios::end);
                std::streampos sp = file.tellg();
                if (sp >= 0) {
                    size_t file_size = static_cast<size_t>(sp);

                    if (file_size < state.file_pos) {
                        diag::log_tagged_fmt("network", "ssl_keylog_file_truncated prev=%zu now=%zu",
                            state.file_pos, file_size);
                        state.file_pos = 0;
                    }
                    if (file_size > state.file_pos) {
                        file.seekg(static_cast<std::streamoff>(state.file_pos));
                        size_t to_read = file_size - state.file_pos;
                        constexpr size_t kMaxChunk = 4 * 1024 * 1024;
                        if (to_read > kMaxChunk) to_read = kMaxChunk;
                        std::string content(to_read, '\0');
                        file.read(content.data(), static_cast<std::streamsize>(to_read));
                        auto actually_read = file.gcount();
                        if (actually_read > 0) {
                            content.resize(static_cast<size_t>(actually_read));
                            state.file_pos += static_cast<size_t>(actually_read);
                            process_new_lines(state, content);
                        }
                    }
                }
                file.close();
            } else if (!warned_missing) {
                diag::log_tagged_fmt("network", "ssl_keylog_file_missing path='%s'",
                    state.keylog_path.c_str());
                warned_missing = true;
            }

            for (int i = 0; i < 20 && state.watching.load(); i++)
                Sleep(10);
        }
        diag::log_tagged("network", "ssl_keylog_watch_loop_exited");
    });
}

inline void stop_watching() {
    if (g_state.watching.exchange(false)) {
        diag::log_tagged_fmt("network", "ssl_keylog_watch_stopping path='%s' entries=%zu",
            g_state.keylog_path.c_str(), g_state.entries.size());
    }
}


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


struct decrypt_result {
    bool success = false;
    std::vector<uint8_t> plaintext;
    std::string error;
    uint8_t content_type = 0;
};


inline std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte = 0;
        if (sscanf(hex.c_str() + i, "%02x", &byte) == 1)
            result.push_back(static_cast<uint8_t>(byte));
    }
    return result;
}


inline std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                                const std::string& label,
                                                const std::vector<uint8_t>& context,
                                                size_t length,
                                                const EVP_MD* md = EVP_sha256()) {

    std::string full_label = "tls13 " + label;
    std::vector<uint8_t> hkdf_label;
    hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xff));
    hkdf_label.push_back(static_cast<uint8_t>(length & 0xff));
    hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
    hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());
    hkdf_label.push_back(static_cast<uint8_t>(context.size()));
    hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

    std::vector<uint8_t> out(length, 0);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return {};

    size_t outlen = length;
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), static_cast<int>(secret.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label.data(), static_cast<int>(hkdf_label.size())) <= 0 ||
        EVP_PKEY_derive(pctx, out.data(), &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    EVP_PKEY_CTX_free(pctx);
    out.resize(outlen);
    return out;
}


inline decrypt_result decrypt_tls13_record(const uint8_t* record_data, size_t record_len,
                                            const std::string& client_random_hex,
                                            bool is_from_server,
                                            uint64_t seq_num,
                                            size_t key_size = 16) {
    decrypt_result result;


    std::string target_label = is_from_server ? "SERVER_TRAFFIC_SECRET_0" : "CLIENT_TRAFFIC_SECRET_0";
    std::vector<keylog_entry> entries;
    {
        std::lock_guard<std::mutex> lock(g_state.entries_mutex);
        auto it = g_state.by_client_random.find(client_random_hex);
        if (it == g_state.by_client_random.end()) {
            result.error = "no keylog entries for client_random";
            return result;
        }
        entries = it->second;
    }


    std::string secret_hex;
    for (auto& e : entries) {
        if (e.label == target_label) {
            secret_hex = e.secret_hex;
            break;
        }
    }
    if (secret_hex.empty()) {
        result.error = "no " + target_label + " found in keylog";
        return result;
    }

    auto secret = hex_decode(secret_hex);
    if (secret.empty()) {
        result.error = "failed to decode secret hex";
        return result;
    }

    const EVP_MD* md = (secret.size() == 48 || key_size == 32) ? EVP_sha384() : EVP_sha256();

    auto key = hkdf_expand_label(secret, "key", {}, key_size, md);
    auto iv = hkdf_expand_label(secret, "iv", {}, 12, md);

    if (key.size() != key_size || iv.size() != 12) {
        result.error = "HKDF key/IV derivation failed";
        return result;
    }


    for (int i = 0; i < 8; i++) {
        iv[static_cast<size_t>(11 - i)] ^= static_cast<uint8_t>((seq_num >> (i * 8)) & 0xff);
    }


    if (record_len < 16) {
        result.error = "record too short for GCM tag";
        return result;
    }

    size_t ciphertext_len = record_len - 16;
    const uint8_t* ciphertext = record_data;
    const uint8_t* tag = record_data + ciphertext_len;


    uint8_t aad[5] = { 0x17, 0x03, 0x03,
                        static_cast<uint8_t>((record_len >> 8) & 0xff),
                        static_cast<uint8_t>(record_len & 0xff) };

    const EVP_CIPHER* cipher = (key_size == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.error = "EVP_CIPHER_CTX_new failed";
        return result;
    }

    result.plaintext.resize(ciphertext_len);
    int out_len = 0;

    bool ok = true;
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) ok = false;
    if (ok && EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, sizeof(aad)) != 1) ok = false;
    if (ok && EVP_DecryptUpdate(ctx, result.plaintext.data(), &out_len,
                                 ciphertext, static_cast<int>(ciphertext_len)) != 1) ok = false;

    int pt_len = out_len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                   const_cast<uint8_t*>(tag)) != 1) ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, result.plaintext.data() + pt_len, &out_len) != 1) ok = false;
    pt_len += out_len;

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        result.error = "AES-GCM decryption failed (bad key or corrupted data)";
        result.plaintext.clear();
        return result;
    }

    result.plaintext.resize(static_cast<size_t>(pt_len));


    if (!result.plaintext.empty()) {

        size_t end = result.plaintext.size();
        while (end > 0 && result.plaintext[end - 1] == 0) end--;
        if (end > 0) {
            result.content_type = result.plaintext[end - 1];
            result.plaintext.resize(end - 1);
        }
    }

    result.success = true;
    return result;
}

}
