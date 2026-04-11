
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
        uint32_t state = 0;
        uint64_t rip = 0;
    };

    struct thread_context_t {
        uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
        uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
        uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
        uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
        uint64_t rip = 0, rflags = 0;
        uint64_t cs = 0, ss = 0;
        uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr6 = 0, dr7 = 0;
    };

    struct peb_info_t {
        uint64_t peb_address = 0;
        uint64_t image_base = 0;
        uint8_t  being_debugged = 0;
        uint32_t nt_global_flag = 0;
        uint64_t ldr_address = 0;
        uint64_t process_heap = 0;
        uint32_t number_of_heaps = 0;
        uint32_t max_heaps = 0;
        uint64_t process_heaps = 0;
    };

    struct net_connection_info_t {
        uint32_t pid = 0;
        uint32_t protocol = 0;
        uint32_t state = 0;
        uint32_t local_port = 0;
        uint32_t remote_port = 0;
        uint32_t address_family = 0;
        uint8_t  local_addr[16] = {};
        uint8_t  remote_addr[16] = {};
        char     process_path[260] = {};
    };

    struct captured_packet_t {
        uint64_t timestamp = 0;
        uint32_t pid = 0;
        uint32_t protocol = 0;
        uint32_t direction = 0;
        uint32_t payload_size = 0;
        uint32_t local_port = 0;
        uint32_t remote_port = 0;
        uint32_t address_family = 0;
        uint8_t  local_addr[16] = {};
        uint8_t  remote_addr[16] = {};
        std::vector<uint8_t> payload;
    };

    struct dns_entry_t {
        uint64_t    timestamp = 0;
        uint32_t    pid = 0;
        uint32_t    query_type = 0;
        std::string domain;
        uint8_t     resolved_addr[16] = {};
        uint32_t    response_code = 0;
        uint32_t    ttl = 0;
    };

    struct network_stats_t {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        uint32_t active_connections = 0;
        uint32_t capture_active = 0;
        uint32_t total_captured = 0;
        uint32_t total_dropped = 0;
        uint32_t total_dns_logged = 0;
        uint32_t active_filter_rules = 0;
    };

    struct bw_process_info_t {
        uint32_t pid = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_recv = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_recv = 0;
        uint64_t last_activity = 0;
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

    bool read_kernel_memory(uint64_t address, size_t size, std::vector<uint8_t>& out);
    bool write_kernel_memory(uint64_t address, const std::vector<uint8_t>& data);

    uint64_t allocate_memory(size_t size);
    bool free_memory(uint64_t address);
    bool protect_memory(uint64_t address, uint64_t size, uint32_t new_protect, uint32_t* old_protect = nullptr);

    bool get_thread_context(uint32_t tid, thread_context_t& ctx);
    bool set_thread_context(uint32_t tid, const thread_context_t& ctx, uint64_t register_mask);
    bool suspend_thread(uint32_t tid, uint32_t* prev_count = nullptr);
    bool resume_thread(uint32_t tid, uint32_t* prev_count = nullptr);

    bool read_peb(peb_info_t& out);
    uint64_t resolve_export(uint64_t module_base, const char* export_name);
    uint64_t virtual_to_physical(uint64_t virtual_address);

    std::vector<net_connection_info_t> enumerate_connections(uint32_t filter_pid = 0, uint32_t filter_protocol = 0);
    bool start_capture(uint32_t filter_pid = 0, uint32_t filter_port = 0, uint32_t filter_protocol = 0, const uint8_t* filter_ip = nullptr, uint32_t max_payload = 1500);
    bool stop_capture();
    bool get_capture_status(bool& active, uint32_t& captured, uint32_t& dropped);
    std::vector<captured_packet_t> get_captured_packets(uint32_t max_packets = 32);
    std::vector<dns_entry_t> get_dns_queries(uint32_t filter_pid = 0);
    bool add_filter_rule(uint32_t action, uint32_t direction, uint32_t protocol = 0, uint32_t pid = 0, uint32_t port = 0, const uint8_t* ip_addr = nullptr, const uint8_t* ip_mask = nullptr, uint32_t* out_rule_id = nullptr);
    bool remove_filter_rule(uint32_t rule_id);
    bool clear_filter_rules();
    bool get_network_stats(network_stats_t& stats);
    bool bw_monitor_op(uint32_t operation, uint32_t filter_pid = 0);
    std::vector<bw_process_info_t> get_bw_per_process(uint32_t filter_pid = 0);
}
