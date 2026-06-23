#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>

#include <nlohmann/json.hpp>

namespace mcp_marketplace
{

using json = nlohmann::json;


enum class registry_t
{
    npm,
    pypi
};


struct package_info_t
{
    std::string name;
    std::string display_name;
    std::string description;
    std::string version;
    std::string author;
    std::string license;
    std::string homepage;
    std::string repository;
    registry_t  registry = registry_t::npm;
    int64_t     weekly_downloads = 0;
    std::string keywords_str;
    bool        is_installed = false;
};


struct installed_server_t
{
    std::string package_name;
    std::string version;
    registry_t  registry = registry_t::npm;
    std::string install_path;
    std::string transport = "stdio";
    std::string command;
    std::vector<std::string> args;
    std::map<std::string, std::string> env;
    bool        enabled = false;
    bool        auto_connect = false;
};


enum class search_state_t
{
    idle,
    searching,
    done,
    error_state
};


enum class install_state_t
{
    idle,
    installing,
    done,
    error_state
};


void search_async(const std::string& query, registry_t reg = registry_t::npm);


std::string registry_label(registry_t reg);


std::string install_root();


installed_server_t preview_install(const package_info_t& pkg);


std::string launch_command_preview(const installed_server_t& srv);


search_state_t get_search_state();


std::string get_search_error();


std::vector<package_info_t> get_search_results();


void install_async(const package_info_t& pkg);


bool uninstall(const std::string& package_name);


install_state_t get_install_state();


std::string get_install_error();


std::vector<installed_server_t> get_installed();


void activate_server(const installed_server_t& srv);


void deactivate_server(const std::string& package_name);


bool set_server_policy(const std::string& package_name, bool enabled, bool auto_connect);


void load_installed(const std::string& json_str);


std::string save_installed();


void tick();


void shutdown();

}
