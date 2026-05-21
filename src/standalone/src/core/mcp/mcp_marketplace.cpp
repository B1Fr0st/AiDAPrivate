#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "mcp_marketplace.hpp"
#include "work_queue.hpp"
#include "mcp_client.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "../helpers/globals.h"
#include "../../helpers/diag_log.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>

extern mcp_client::manager_t s_mcp_client_mgr;

namespace mcp_marketplace
{

using json = nlohmann::json;


static std::mutex               s_mtx;
static std::vector<package_info_t>  s_results;
static search_state_t           s_search_state = search_state_t::idle;
static std::string              s_search_error;

static install_state_t          s_install_state = install_state_t::idle;
static std::string              s_install_error;

static std::mutex               s_installed_mtx;
static std::vector<installed_server_t> s_installed;

static std::atomic<bool>        s_shutdown{false};

struct deferred_log_entry_t
{
    bottom_tab_t tab;
    std::string  line;
};

static std::mutex                          s_deferred_mtx;
static std::vector<deferred_log_entry_t>   s_deferred_logs;
static std::atomic<bool>                   s_persisted_load_initialized{false};
static install_state_t                     s_last_observed_install_state = install_state_t::idle;
static std::atomic<bool>                   s_install_persist_pending{false};

static void enqueue_deferred_log(bottom_tab_t tab, std::string line)
{
    std::lock_guard<std::mutex> lk(s_deferred_mtx);
    if (s_deferred_logs.size() >= 1024)
        s_deferred_logs.erase(s_deferred_logs.begin());
    s_deferred_logs.push_back({tab, std::move(line)});
}


static std::filesystem::path marketplace_dir()
{
    wchar_t* appdata = nullptr;
    std::filesystem::path base;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
        base = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"marketplace";
        CoTaskMemFree(appdata);
    } else {
        base = std::filesystem::current_path() / "aida_marketplace";
    }
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    return base;
}


static std::string run_process_capture(const std::string& cmd,
                                       const std::string& working_dir,
                                       int timeout_ms = 60000)
{
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr, write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0))
        return "";

    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = write_pipe;
    si.hStdError  = write_pipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    std::string cmd_copy = cmd;

    BOOL ok = CreateProcessA(
        nullptr, cmd_copy.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr,
        working_dir.empty() ? nullptr : working_dir.c_str(),
        &si, &pi);

    CloseHandle(write_pipe);

    if (!ok) {
        CloseHandle(read_pipe);
        return "";
    }

    std::string output;
    char buf[4096];
    DWORD bytes_read = 0;
    auto start = std::chrono::steady_clock::now();
    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout_ms) {
            TerminateProcess(pi.hProcess, 1);
            break;
        }
        DWORD avail = 0;
        if (!PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) {
            DWORD exit_code = 0;
            if (GetExitCodeProcess(pi.hProcess, &exit_code) && exit_code != STILL_ACTIVE)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        if (ReadFile(read_pipe, buf, sizeof(buf) - 1, &bytes_read, nullptr) && bytes_read > 0) {
            output.append(buf, bytes_read);
        }
    }

    while (ReadFile(read_pipe, buf, sizeof(buf) - 1, &bytes_read, nullptr) && bytes_read > 0)
        output.append(buf, bytes_read);

    CloseHandle(read_pipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return output;
}


static std::vector<package_info_t> search_npm(const std::string& query, std::string& err_out)
{
    std::vector<package_info_t> results;
    err_out.clear();

    httplib::Client cli("https://registry.npmjs.org");
    cli.set_connection_timeout(10);
    cli.set_read_timeout(15);


    std::string search_term = query;
    if (search_term.find("mcp") == std::string::npos)
        search_term = "mcp " + search_term;

    std::string path = "/-/v1/search?text=" + httplib::detail::encode_url(search_term)
                     + "+keywords:mcp&size=30";

    auto res = cli.Get(path);
    if (!res) {
        err_out = "registry.npmjs.org unreachable: " + httplib::to_string(res.error());
        return results;
    }
    if (res->status != 200) {
        err_out = "registry.npmjs.org returned HTTP " + std::to_string(res->status);
        return results;
    }

    auto j = json::parse(res->body, nullptr, false);
    if (j.is_discarded() || !j.contains("objects")) {
        err_out = "registry.npmjs.org returned malformed JSON";
        return results;
    }

    for (auto& obj : j["objects"]) {
        if (!obj.contains("package")) continue;
        auto& pkg = obj["package"];

        package_info_t info;
        info.name = pkg.value("name", "");
        info.description = pkg.value("description", "");
        info.version = pkg.value("version", "");
        info.registry = registry_t::npm;

        if (pkg.contains("author") && pkg["author"].is_object())
            info.author = pkg["author"].value("name", "");

        if (pkg.contains("links")) {
            info.homepage = pkg["links"].value("homepage", "");
            info.repository = pkg["links"].value("repository", "");
        }


        if (obj.contains("score") && obj["score"].contains("detail")) {
            auto pop = obj["score"]["detail"].value("popularity", 0.0);
            info.weekly_downloads = static_cast<int64_t>(pop * 100000);
        }

        if (pkg.contains("keywords") && pkg["keywords"].is_array()) {
            std::string kw;
            for (auto& k : pkg["keywords"]) {
                if (!k.is_string()) continue;
                if (!kw.empty()) kw += ", ";
                kw += k.get<std::string>();
            }
            info.keywords_str = kw;
        }


        info.display_name = info.name;
        auto slash = info.display_name.rfind('/');
        if (slash != std::string::npos)
            info.display_name = info.display_name.substr(slash + 1);

        for (const char* prefix : {"server-", "mcp-server-", "mcp-"}) {
            if (info.display_name.find(prefix) == 0) {
                info.display_name = info.display_name.substr(strlen(prefix));
                break;
            }
        }

        if (!info.display_name.empty())
            info.display_name[0] = static_cast<char>(toupper(info.display_name[0]));

        if (!info.name.empty())
            results.push_back(std::move(info));
    }

    return results;
}


static std::vector<package_info_t> search_pypi(const std::string& query, std::string& err_out)
{
    std::vector<package_info_t> results;
    err_out.clear();
    bool any_transport_ok = false;

    httplib::Client cli("https://pypi.org");
    cli.set_connection_timeout(10);
    cli.set_read_timeout(15);


    std::string search_term = query;
    if (search_term.find("mcp") == std::string::npos)
        search_term = "mcp " + search_term;

    std::string path = "/pypi/" + httplib::detail::encode_url(search_term) + "/json";


    auto res = cli.Get(path);
    if (res) any_transport_ok = true;
    if (res && res->status == 200) {
        auto j = json::parse(res->body, nullptr, false);
        if (!j.is_discarded() && j.contains("info")) {
            auto& info_obj = j["info"];
            package_info_t info;
            info.name = info_obj.value("name", "");
            info.description = info_obj.value("summary", "");
            info.version = info_obj.value("version", "");
            info.author = info_obj.value("author", "");
            info.license = info_obj.value("license", "");
            info.homepage = info_obj.value("home_page", "");
            info.registry = registry_t::pypi;
            info.display_name = info.name;
            if (!info.name.empty())
                results.push_back(std::move(info));
        }
    }


    static const char* mcp_pypi_prefixes[] = {
        "mcp-server-", "mcp-", "modelcontextprotocol-"
    };

    for (const char* prefix : mcp_pypi_prefixes) {
        std::string pkg_name = std::string(prefix) + query;
        std::string pkg_path = "/pypi/" + httplib::detail::encode_url(pkg_name) + "/json";
        auto pkg_res = cli.Get(pkg_path);
        if (pkg_res) any_transport_ok = true;
        if (!pkg_res || pkg_res->status != 200) continue;

        auto j = json::parse(pkg_res->body, nullptr, false);
        if (j.is_discarded() || !j.contains("info")) continue;

        auto& info_obj = j["info"];
        package_info_t info;
        info.name = info_obj.value("name", "");
        info.description = info_obj.value("summary", "");
        info.version = info_obj.value("version", "");
        info.author = info_obj.value("author", "");
        info.license = info_obj.value("license", "");
        info.homepage = info_obj.value("home_page", "");
        info.registry = registry_t::pypi;
        info.display_name = info.name;


        bool dup = false;
        for (auto& r : results)
            if (r.name == info.name) { dup = true; break; }
        if (!dup && !info.name.empty())
            results.push_back(std::move(info));
    }

    if (!any_transport_ok)
        err_out = "pypi.org unreachable";
    return results;
}


void search_async(const std::string& query, registry_t reg)
{
    diag::log_tagged_fmt("mcp_market", "search_async query='%.80s' reg=%d",
        query.c_str(), (int)reg);
    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_marketplace_search);
        if (gt == 0) {
            diag::log_tagged_fmt("mcp_market", "search_async gate blocked");
            std::lock_guard<std::mutex> lk(s_mtx);
            s_search_state = search_state_t::error_state;
            s_search_error = "License gate blocked marketplace search.";
            return;
        }
    }


    {
        std::lock_guard<std::mutex> lk(s_mtx);
        s_search_state = search_state_t::searching;
        s_search_error.clear();
        s_results.clear();
    }

    std::string q = query;
    work_queue::post([q, reg]() {
        std::vector<package_info_t> results;
        std::string err;
        try {
            if (reg == registry_t::npm)
                results = search_npm(q, err);
            else
                results = search_pypi(q, err);
        } catch (...) {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_search_state = search_state_t::error_state;
            s_search_error = "Search failed with an exception.";
            return;
        }


        {
            std::lock_guard<std::mutex> lk2(s_installed_mtx);
            for (auto& r : results) {
                for (auto& inst : s_installed) {
                    if (inst.package_name == r.name) {
                        r.is_installed = true;
                        break;
                    }
                }
            }
        }

        std::lock_guard<std::mutex> lk(s_mtx);
        s_results = std::move(results);
        if (s_results.empty() && !err.empty()) {
            diag::log_tagged_fmt("mcp_market", "search_async error err='%s'", err.c_str());
            s_search_state = search_state_t::error_state;
            s_search_error = err;
        } else {
            diag::log_tagged_fmt("mcp_market", "search_async done results=%zu", s_results.size());
            s_search_state = search_state_t::done;
            s_search_error.clear();
        }
    });
}


search_state_t get_search_state()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_search_state;
}

std::string get_search_error()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_search_error;
}

std::vector<package_info_t> get_search_results()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_results;
}


void install_async(const package_info_t& pkg)
{
    diag::log_tagged_fmt("mcp_market", "install_async pkg='%s' version='%s'",
        pkg.name.c_str(), pkg.version.c_str());
    {
        uint64_t gt = standalone_license::inline_gate_check(
            standalone_license::gate_marketplace_install);
        if (gt == 0) {
            diag::log_tagged_fmt("mcp_market", "install_async gate blocked");
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::error_state;
            s_install_error = "License gate blocked marketplace install.";
            return;
        }
    }

    {
        std::lock_guard<std::mutex> lk(s_mtx);
        s_install_state = install_state_t::installing;
        s_install_error.clear();
    }

    package_info_t p = pkg;
    work_queue::post([p]() {
        auto dir = marketplace_dir();

        std::string safe_name;
        safe_name.reserve(p.name.size());
        for (char c : p.name) {
            const unsigned char uc = static_cast<unsigned char>(c);
            const bool keep = (uc >= '0' && uc <= '9')
                           || (uc >= 'A' && uc <= 'Z')
                           || (uc >= 'a' && uc <= 'z')
                           || uc == '-'
                           || uc == '_'
                           || uc == '.';
            safe_name.push_back(keep ? static_cast<char>(uc) : '_');
        }
        while (!safe_name.empty() && safe_name.front() == '.') safe_name.erase(safe_name.begin());
        if (safe_name.empty() || safe_name == "." || safe_name == "..") {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::error_state;
            s_install_error = "Refusing to install package with unsafe name: " + p.name;
            return;
        }
        std::error_code can_ec;
        auto root = std::filesystem::weakly_canonical(dir, can_ec);
        if (can_ec) root = dir;
        auto pkg_path = std::filesystem::weakly_canonical(dir / safe_name, can_ec);
        if (can_ec) pkg_path = dir / safe_name;
        {
            const std::string root_str = root.string();
            const std::string pkg_str = pkg_path.string();
            if (pkg_str.size() < root_str.size() || pkg_str.compare(0, root_str.size(), root_str) != 0) {
                std::lock_guard<std::mutex> lk(s_mtx);
                s_install_state = install_state_t::error_state;
                s_install_error = "Refusing to install outside marketplace directory: " + p.name;
                return;
            }
        }
        std::string pkg_dir = pkg_path.string();

        std::error_code ec;
        std::filesystem::create_directories(pkg_dir, ec);

        std::string output;
        installed_server_t srv;

        auto safe_for_shell = [](const std::string& s) -> bool {
            for (unsigned char c : s) {
                const bool ok = (c >= '0' && c <= '9')
                             || (c >= 'A' && c <= 'Z')
                             || (c >= 'a' && c <= 'z')
                             || c == '-' || c == '_' || c == '.'
                             || c == '/' || c == '@';
                if (!ok) return false;
            }
            return !s.empty();
        };

        if (!safe_for_shell(p.name) || (!p.version.empty() && !safe_for_shell(p.version))) {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::error_state;
            s_install_error = "Refusing to install package with shell-unsafe identifier: " + p.name;
            return;
        }

        if (p.registry == registry_t::npm) {
            diag::log_tagged_fmt("mcp_market", "install_async npm pkg='%s' dir='%.120s'",
                p.name.c_str(), pkg_dir.c_str());
            std::string spec = p.name + (p.version.empty() ? std::string{} : "@" + p.version);
            std::string cmd = "cmd.exe /c npm install --prefix \"" + pkg_dir + "\" \"" + spec + "\"";
            output = run_process_capture(cmd, pkg_dir, 120000);

            srv.package_name = p.name;
            srv.version = p.version;
            srv.registry = registry_t::npm;
            srv.install_path = pkg_dir;
            srv.transport = "stdio";
            srv.command = "cmd.exe";
            srv.args = {"/c", "npx", "-y", p.name};
        } else {
            diag::log_tagged_fmt("mcp_market", "install_async pypi pkg='%s' dir='%.120s'",
                p.name.c_str(), pkg_dir.c_str());
            std::string venv_dir = pkg_dir + "\\venv";
            std::string cmd_venv = "python -m venv \"" + venv_dir + "\"";
            run_process_capture(cmd_venv, pkg_dir, 60000);

            std::string pip = venv_dir + "\\Scripts\\pip.exe";
            std::string spec = p.version.empty() ? p.name : (p.name + "==" + p.version);
            std::string cmd_install = "\"" + pip + "\" install \"" + spec + "\"";
            output = run_process_capture(cmd_install, pkg_dir, 120000);

            srv.package_name = p.name;
            srv.version = p.version;
            srv.registry = registry_t::pypi;
            srv.install_path = pkg_dir;
            srv.transport = "stdio";
            srv.command = venv_dir + "\\Scripts\\python.exe";
            srv.args = {"-m", p.name};
        }


        bool success = false;
        if (p.registry == registry_t::npm) {
            success = std::filesystem::exists(pkg_dir + "\\node_modules", ec);
        } else {
            success = std::filesystem::exists(pkg_dir + "\\venv\\Scripts", ec);
        }

        if (!success) {
            diag::log_tagged_fmt("mcp_market", "install_async fail pkg='%s'", p.name.c_str());
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::error_state;
            s_install_error = "Install failed. Output:\n" + output.substr(0, 500);
            return;
        }
        diag::log_tagged_fmt("mcp_market", "install_async ok pkg='%s'", p.name.c_str());


        {
            std::lock_guard<std::mutex> lk(s_installed_mtx);

            s_installed.erase(
                std::remove_if(s_installed.begin(), s_installed.end(),
                    [&](const installed_server_t& s) { return s.package_name == p.name; }),
                s_installed.end());
            s_installed.push_back(srv);
        }

        {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::done;
        }

        s_install_persist_pending.store(true, std::memory_order_release);

        enqueue_deferred_log(bottom_tab_t::output,
            "[marketplace] Installed " + p.name + "@" + p.version);
    });
}


bool uninstall(const std::string& package_name)
{
    diag::log_tagged_fmt("mcp_market", "uninstall pkg='%s'", package_name.c_str());
    ::s_mcp_client_mgr.disconnect_server(package_name);
    ::s_mcp_client_mgr.remove_server(package_name);

    std::string remove_path;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(s_installed_mtx);
        auto it = std::find_if(s_installed.begin(), s_installed.end(),
            [&](const installed_server_t& s) { return s.package_name == package_name; });
        if (it == s_installed.end()) return false;
        remove_path = it->install_path;
        s_installed.erase(it);
        found = true;
    }

    if (!remove_path.empty()) {
        std::error_code can_ec;
        auto root = std::filesystem::weakly_canonical(marketplace_dir(), can_ec);
        if (can_ec) root = marketplace_dir();
        auto target = std::filesystem::weakly_canonical(remove_path, can_ec);
        if (can_ec) target = remove_path;
        const std::string root_str = root.string();
        const std::string target_str = target.string();
        if (!root_str.empty()
            && target_str.size() >= root_str.size()
            && target_str.compare(0, root_str.size(), root_str) == 0
            && target_str.size() > root_str.size())
        {
            std::error_code ec;
            std::filesystem::remove_all(target_str, ec);
        }
    }

    s_install_persist_pending.store(true, std::memory_order_release);
    diag::log_tagged_fmt("mcp_market", "uninstall %s pkg='%s'",
        found ? "ok" : "not_found", package_name.c_str());
    enqueue_deferred_log(bottom_tab_t::output,
        "[marketplace] Uninstalled " + package_name);
    return found;
}


install_state_t get_install_state()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_install_state;
}

std::string get_install_error()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_install_error;
}

std::vector<installed_server_t> get_installed()
{
    std::lock_guard<std::mutex> lk(s_installed_mtx);
    return s_installed;
}


void activate_server(const installed_server_t& srv)
{
    diag::log_tagged_fmt("mcp_market", "activate_server pkg='%s'", srv.package_name.c_str());
    mcp_client::server_config_t cfg;
    cfg.name = srv.package_name;
    cfg.transport = (srv.transport == "stdio")
        ? mcp_client::transport_type_t::stdio
        : mcp_client::transport_type_t::http_sse;
    cfg.command = srv.command;
    cfg.args = srv.args;
    cfg.env = srv.env;
    cfg.enabled = srv.enabled;
    cfg.auto_connect = srv.auto_connect;

    ::s_mcp_client_mgr.add_server(cfg);
    ::s_mcp_client_mgr.connect_server(cfg.name);

    diag::log_tagged_fmt("mcp_market", "activate_server ok pkg='%s'", srv.package_name.c_str());
    enqueue_deferred_log(bottom_tab_t::mcp_log,
        "[marketplace] Activated server: " + srv.package_name);
}

void deactivate_server(const std::string& package_name)
{
    diag::log_tagged_fmt("mcp_market", "deactivate_server pkg='%s'", package_name.c_str());
    ::s_mcp_client_mgr.disconnect_server(package_name);
    ::s_mcp_client_mgr.remove_server(package_name);

    diag::log_tagged_fmt("mcp_market", "deactivate_server ok pkg='%s'", package_name.c_str());
    enqueue_deferred_log(bottom_tab_t::mcp_log,
        "[marketplace] Deactivated server: " + package_name);
}


void load_installed(const std::string& json_str)
{
    if (json_str.empty()) return;
    auto j = json::parse(json_str, nullptr, false);
    if (j.is_discarded() || !j.is_array()) return;

    std::lock_guard<std::mutex> lk(s_installed_mtx);
    s_installed.clear();
    for (auto& item : j) {
        installed_server_t srv;
        srv.package_name = item.value("package_name", "");
        srv.version      = item.value("version", "");
        srv.registry     = item.value("registry", "npm") == "pypi" ? registry_t::pypi : registry_t::npm;
        srv.install_path = item.value("install_path", "");
        srv.transport    = item.value("transport", "stdio");
        srv.command      = item.value("command", "");
        if (item.contains("args") && item["args"].is_array()) {
            for (auto& a : item["args"]) {
                if (a.is_string())
                    srv.args.push_back(a.get<std::string>());
            }
        }
        if (item.contains("env") && item["env"].is_object()) {
            for (auto it2 = item["env"].begin(); it2 != item["env"].end(); ++it2) {
                if (it2.value().is_string())
                    srv.env[it2.key()] = it2.value().get<std::string>();
            }
        }
        srv.enabled      = item.value("enabled", true);
        srv.auto_connect  = item.value("auto_connect", true);

        if (!srv.package_name.empty())
            s_installed.push_back(std::move(srv));
    }
}


std::string save_installed()
{
    std::lock_guard<std::mutex> lk(s_installed_mtx);
    json arr = json::array();
    for (auto& srv : s_installed) {
        json item = {
            {"package_name", srv.package_name},
            {"version",      srv.version},
            {"registry",     srv.registry == registry_t::pypi ? "pypi" : "npm"},
            {"install_path", srv.install_path},
            {"transport",    srv.transport},
            {"command",      srv.command},
            {"enabled",      srv.enabled},
            {"auto_connect", srv.auto_connect}
        };
        json args_arr = json::array();
        for (auto& a : srv.args) args_arr.push_back(a);
        item["args"] = args_arr;

        json env_obj = json::object();
        for (auto& [k, v] : srv.env) env_obj[k] = v;
        item["env"] = env_obj;

        arr.push_back(std::move(item));
    }
    return arr.dump();
}


void tick()
{
    if (s_shutdown.load(std::memory_order_acquire))
        return;

    bool expected_uninit = false;
    if (s_persisted_load_initialized.compare_exchange_strong(
            expected_uninit, true,
            std::memory_order_acq_rel, std::memory_order_acquire))
    {
        bool need_load = false;
        {
            std::lock_guard<std::mutex> lk(s_installed_mtx);
            need_load = s_installed.empty();
        }
        if (need_load)
        {
            const std::string& cached = g_sa_settings.marketplace_installed_json;
            if (!cached.empty())
                load_installed(cached);
        }
    }

    std::vector<deferred_log_entry_t> drained;
    {
        std::lock_guard<std::mutex> lk(s_deferred_mtx);
        if (!s_deferred_logs.empty())
            drained.swap(s_deferred_logs);
    }
    for (auto& entry : drained)
        output_log::push(entry.tab, entry.line);

    install_state_t cur_install;
    {
        std::lock_guard<std::mutex> lk(s_mtx);
        cur_install = s_install_state;
    }

    bool install_just_finished =
        (s_last_observed_install_state == install_state_t::installing) &&
        (cur_install == install_state_t::done || cur_install == install_state_t::error_state);

    s_last_observed_install_state = cur_install;

    bool persist_now = s_install_persist_pending.exchange(false, std::memory_order_acq_rel);
    if (persist_now || install_just_finished)
    {
        std::string serialized = save_installed();
        if (g_sa_settings.marketplace_installed_json != serialized)
        {
            g_sa_settings.marketplace_installed_json = std::move(serialized);
            g_sa_settings.save();
        }
    }
}


void shutdown()
{
    s_shutdown.store(true);
}

}
