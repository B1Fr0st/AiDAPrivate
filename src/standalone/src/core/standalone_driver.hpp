
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace driver_bridge
{
    using log_fn_t = std::function<void(const char* msg)>;
    using confirm_fn_t = std::function<bool(const char* question)>;

    struct process_info_t {
        uint32_t    pid = 0;
        std::string name;
        std::string path;
        std::string window_title;
    };

    struct module_info_t {
        uint64_t    base = 0;
        uint32_t    size = 0;
        std::string name;
        std::string path;
    };

    struct memory_region_t {
        uint64_t    base = 0;
        uint64_t    size = 0;
        uint32_t    state = 0;
        uint32_t    protect = 0;
        uint32_t    type = 0;
    };

    struct thread_info_t {
        uint32_t tid = 0;
        uint32_t owner_pid = 0;
        int      priority = 0;
    };

    void set_log_callback(log_fn_t fn);
    void set_confirm_callback(confirm_fn_t fn);

    bool initialize();
    bool load_kernel_driver();
    bool is_loaded();
    bool using_kernel_driver();
    bool attach(uint32_t pid);
    bool attach_by_name(const std::string& process_name);
    void detach();

    std::string status();
    std::string last_error();
    uint32_t attached_pid();
    std::string attached_process_name();

    std::vector<process_info_t> enumerate_processes();
    std::vector<module_info_t> enumerate_modules();
    std::vector<thread_info_t> enumerate_threads();
    std::vector<memory_region_t> enumerate_memory_regions(size_t max_regions = 512);

    bool query_memory(uint64_t address, memory_region_t& region);
    bool read_memory(uint64_t address, size_t size, std::vector<uint8_t>& out);
    bool write_memory(uint64_t address, const std::vector<uint8_t>& data);
    bool read_string(uint64_t address, size_t max_length, std::string& out);
}
