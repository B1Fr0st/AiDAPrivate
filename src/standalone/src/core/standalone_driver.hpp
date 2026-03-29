

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace driver_bridge
{


    using log_fn_t = std::function<void(const char* msg)>;
    void set_log_callback(log_fn_t fn);


    using confirm_fn_t = std::function<bool(const char* question)>;
    void set_confirm_callback(confirm_fn_t fn);


    bool initialize();


    bool is_loaded();


    bool attach(uint32_t pid);


    void detach();


    std::string status();


    uint32_t attached_pid();


    struct process_info_t {
        uint32_t    pid;
        std::string name;
    };
    std::vector<process_info_t> enumerate_processes();
}
