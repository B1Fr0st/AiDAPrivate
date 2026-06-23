
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace driver_bridge
{
    using log_fn_t = std::function<void(const char* msg)>;
    using confirm_fn_t = std::function<bool(const char* question)>;
    using pre_detach_fn_t = std::function<void()>;

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

    struct bw_stats_t {
        uint64_t total_bytes_sent = 0;
        uint64_t total_bytes_recv = 0;
        uint64_t total_packets_sent = 0;
        uint64_t total_packets_recv = 0;
        uint64_t bps_in = 0;
        uint64_t bps_out = 0;
        bool     active = false;
    };

    struct wfp_callout_info_t {
        uint64_t    classify_fn = 0;
        uint64_t    notify_fn = 0;
        uint64_t    flow_delete_fn = 0;
        uint64_t    owning_module_base = 0;
        uint64_t    filter_id = 0;
        uint32_t    callout_id = 0;
        uint32_t    layer_id = 0;
        uint32_t    flags = 0;
        uint32_t    entry_type = 0;
        uint32_t    action_type = 0;
        uint32_t    provider_present = 0;
        uint32_t    aida_match_reason = 0;
        std::string callout_key_str;
        std::string applicable_layer_str;
        std::string sublayer_key_str;
        std::string owning_module;
    };

    struct socket_info_t {
        uint64_t handle_value = 0;
        uint64_t afd_endpoint_addr = 0;
        uint32_t pid = 0;
        uint32_t protocol = 0;
        uint32_t state = 0;
        uint32_t local_port = 0;
        uint32_t remote_port = 0;
        uint32_t address_family = 0;
        uint8_t  local_addr[16] = {};
        uint8_t  remote_addr[16] = {};
    };

    struct tcpip_connection_t {
        uint64_t tcb_address = 0;
        uint64_t owning_module_base = 0;
        uint32_t pid = 0;
        uint32_t protocol = 0;
        uint32_t state = 0;
        uint32_t local_port = 0;
        uint32_t remote_port = 0;
        uint32_t address_family = 0;
        uint8_t  local_addr[16] = {};
        uint8_t  remote_addr[16] = {};
        uint64_t create_time = 0;
        uint64_t bytes_in = 0;
        uint64_t bytes_out = 0;
    };

    struct dpi_result_t {
        uint64_t timestamp = 0;
        uint32_t direction = 0;
        uint32_t protocol = 0;
        uint32_t src_port = 0;
        uint32_t dst_port = 0;
        uint32_t pid = 0;
        uint32_t payload_size = 0;
        uint32_t af = 0;
        uint8_t  src_addr[16] = {};
        uint8_t  dst_addr[16] = {};
        uint32_t tcp_flags = 0;
        uint32_t tcp_window = 0;
        bool     is_http = false;
        bool     is_tls = false;
        bool     is_dns = false;
        uint32_t http_method = 0;
        uint32_t tls_version = 0;
        uint32_t tls_content_type = 0;
        std::string http_host;
        std::string http_path;
        std::string tls_sni;
    };

    struct held_packet_info_t {
        uint64_t hold_id = 0;
        uint64_t timestamp = 0;
        uint32_t direction = 0;
        uint32_t protocol = 0;
        uint32_t src_port = 0;
        uint32_t dst_port = 0;
        uint32_t pid = 0;
        uint32_t payload_size = 0;
        uint32_t af = 0;
        uint8_t  src_addr[16] = {};
        uint8_t  dst_addr[16] = {};
        std::vector<uint8_t> payload;
    };

    struct mod_rule_info_t {
        uint32_t rule_id = 0;
        uint32_t direction = 0;
        uint32_t protocol = 0;
        uint32_t port = 0;
        uint32_t pid = 0;
        uint32_t match_count = 0;
        uint32_t active = 0;
    };

    struct redirect_rule_info_t {
        uint32_t rule_id = 0;
        uint32_t protocol = 0;
        uint32_t match_port = 0;
        uint32_t redirect_port = 0;
        uint32_t af = 0;
        uint32_t match_count = 0;
        uint32_t active = 0;
    };

    struct dns_spoof_info_t {
        uint32_t    rule_id = 0;
        std::string domain;
        uint32_t    af = 0;
        uint32_t    match_count = 0;
        uint32_t    active = 0;
        uint32_t    ttl = 0;
    };

    struct net_iface_info_t {
        uint32_t    if_index = 0;
        uint32_t    if_type = 0;
        uint32_t    mtu = 0;
        uint32_t    oper_status = 0;
        uint64_t    speed = 0;
        uint8_t     mac_addr[6] = {};
        uint8_t     ipv4_addr[4] = {};
        uint8_t     ipv4_mask[4] = {};
        uint8_t     ipv6_addr[16] = {};
        std::string name;
        std::string description;
        uint64_t    in_octets = 0;
        uint64_t    out_octets = 0;
    };

    struct pcap_packet_t {
        uint32_t ts_sec = 0;
        uint32_t ts_usec = 0;
        std::vector<uint8_t> data;
    };

    struct pcap_global_header_t {
        uint32_t magic_number = 0;
        uint16_t version_major = 0;
        uint16_t version_minor = 0;
        int32_t  thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 0;
        uint32_t network = 0;
    };

    struct pcap_export_result_t {
        pcap_global_header_t header;
        std::vector<pcap_packet_t> packets;
    };

    struct fingerprint_info_t {
        uint8_t     remote_addr[16] = {};
        uint32_t    af = 0;
        uint32_t    ttl = 0;
        uint32_t    window_size = 0;
        uint32_t    mss = 0;
        uint32_t    window_scale = 0;
        uint32_t    df_flag = 0;
        uint32_t    sack_permitted = 0;
        uint32_t    nop_count = 0;
        std::string os_guess;
    };

    void set_log_callback(log_fn_t fn);
    void set_confirm_callback(confirm_fn_t fn);
    void add_pre_detach_callback(pre_detach_fn_t fn);
    void debug_log(const char* fmt, ...);

    bool initialize();
    bool load_kernel_driver();
    void invalidate_kernel_session(const char* reason);
    void shutdown(const char* reason = nullptr);
    bool is_loaded();
    bool using_kernel_driver();
    bool kernel_session_available(std::string* reason = nullptr);
    bool can_read_memory();
    bool attach(uint32_t pid);
    bool attach_by_name(const std::string& process_name);
    void detach();

    bool attach_additional(uint32_t pid);
    bool set_active_pid(uint32_t pid);
    bool detach_one(uint32_t pid);
    bool clear_active_pid();
    std::vector<uint32_t> attached_pids();

    std::string status();
    std::string last_error();
    uint32_t attached_pid();
    bool attached_process_alive(uint32_t* exit_code_out = nullptr);
    std::string attached_process_name();

    std::vector<process_info_t> enumerate_processes();
    std::vector<module_info_t> enumerate_modules();
    std::vector<thread_info_t> enumerate_threads();
    std::vector<memory_region_t> enumerate_memory_regions(size_t max_regions = 512);

    bool query_memory(uint64_t address, memory_region_t& region);
    bool read_memory(uint64_t address, size_t size, std::vector<uint8_t>& out);
    bool write_memory(uint64_t address, const std::vector<uint8_t>& data);
    bool read_string(uint64_t address, size_t max_length, std::string& out);

    bool read_memory_for(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out);
    bool write_memory_for(uint32_t pid, uint64_t address, const std::vector<uint8_t>& data);
    bool query_memory_for(uint32_t pid, uint64_t address, memory_region_t& region);
    bool protect_memory_for(uint32_t pid, uint64_t address, uint64_t size, uint32_t new_protect, uint32_t* old_protect = nullptr);
    std::vector<module_info_t>   enumerate_modules_for(uint32_t pid);
    std::vector<thread_info_t>   enumerate_threads_for(uint32_t pid);
    std::vector<memory_region_t> enumerate_memory_regions_for(uint32_t pid, size_t max_regions = 512);
    bool read_peb_for(uint32_t pid, peb_info_t& out);
    uint64_t resolve_export_for(uint32_t pid, uint64_t module_base, const char* export_name);
    uint64_t allocate_memory_for(uint32_t pid, size_t size);
    bool free_memory_for(uint32_t pid, uint64_t address);

    bool read_kernel_memory(uint64_t address, size_t size, std::vector<uint8_t>& out);
    bool write_kernel_memory(uint64_t address, const std::vector<uint8_t>& data);

    uint64_t allocate_memory(size_t size);
    bool free_memory(uint64_t address);
    bool protect_memory(uint64_t address, uint64_t size, uint32_t new_protect, uint32_t* old_protect = nullptr);

    bool get_thread_context(uint32_t tid, thread_context_t& ctx);
    bool set_thread_context(uint32_t tid, const thread_context_t& ctx, uint64_t register_mask);
    bool suspend_thread(uint32_t tid, uint32_t* prev_count = nullptr);
    bool resume_thread(uint32_t tid, uint32_t* prev_count = nullptr);
    bool query_thread_information(uint32_t tid, uint32_t info_class, void* buffer, uint32_t buffer_size, uint32_t* return_length = nullptr);
    bool terminate_thread(uint32_t tid, uint32_t exit_status = 0xDEADu);
    bool close_process_handle(uint32_t pid, uint64_t handle_value);

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
    bool bw_monitor_op(uint32_t operation, uint32_t filter_pid = 0, bw_stats_t* out_stats = nullptr);
    std::vector<bw_process_info_t> get_bw_per_process(uint32_t filter_pid = 0);
    std::vector<dpi_result_t> get_dpi_results(uint32_t filter_pid = 0, uint32_t filter_protocol = 0, uint32_t filter_port = 0, uint32_t flags = 0);
    std::vector<wfp_callout_info_t> enumerate_wfp_callouts(const std::string& filter_module = {});
    std::vector<socket_info_t> get_socket_handles(uint32_t target_pid = 0);
    std::vector<tcpip_connection_t> dump_tcpip_connections(uint32_t target_pid = 0, uint32_t filter_protocol = 0);
    std::vector<net_iface_info_t> enumerate_interfaces();
    std::vector<held_packet_info_t> get_held_packets();
    std::vector<mod_rule_info_t> list_packet_mod_rules();
    std::vector<redirect_rule_info_t> list_redirect_rules();
    std::vector<dns_spoof_info_t> list_dns_spoof_rules();
    bool fingerprint_op(uint32_t operation);
    std::vector<fingerprint_info_t> get_fingerprints();
    bool export_pcap(uint32_t filter_pid = 0, uint32_t filter_protocol = 0, uint32_t max_packets = 64, pcap_export_result_t* out = nullptr);

    struct dll_protect_status_t {
        uint32_t status = 0;
        uint64_t current_hash = 0;
        uint64_t expected_hash = 0;
        uint64_t last_check_tsc = 0;
    };

    uint64_t call_function(uint64_t function_address, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0, uint64_t arg4 = 0);
    uint64_t find_gadget(const char* pattern, size_t pattern_size);

    bool set_hardware_breakpoint(uint32_t tid, int index, uint64_t address, int type = 0, int size = 0);
    bool clear_hardware_breakpoint(uint32_t tid, int index);

    bool spoof_debug_flags(uint32_t* result_flags = nullptr);
    bool refresh_heartbeat();
    bool sentinel_bridge_ready();
    uint64_t sentinel_ready_since_tsc();

    struct dynamic_ioctl_state_t {
        bool loaded = false;
        bool kernel = false;
        bool connected = false;
        bool ready = false;
        uint32_t instance_server_seed = 0;
        uint32_t instance_ioctl_seed = 0;
        uint32_t global_server_seed = 0;
        uint32_t global_ioctl_seed = 0;
        uint32_t ioctl_seed_hash = 0;
        uint32_t heartbeat_ioctl_seed_hash = 0;
    };

    dynamic_ioctl_state_t dynamic_ioctl_state();
    bool dynamic_ioctls_ready();

    bool register_dll_protection(uint64_t module_base, uint64_t text_va, uint32_t text_size, uint64_t expected_hash, uint32_t check_interval_ms = 2000);
    bool register_self_dll_protection(uint64_t module_base, uint64_t text_va, uint32_t text_size, uint64_t expected_hash, uint32_t check_interval_ms = 2000);
    bool query_dll_protection(dll_protect_status_t& out);
    bool unregister_dll_protection();
    bool unregister_self_dll_protection(uint64_t module_base = 0);


    bool trigger_kernel_bsod(uint32_t reason_code, uint64_t evidence_hash);
    bool latch_targeting_from_usermode(uint32_t reason);

    struct re_evidence_blob_t {
        uint64_t magic;
        uint32_t version;
        uint32_t signal_family;
        uint32_t signal_id;
        uint32_t score;
        uint32_t pid;
        uint32_t reserved0;
        uint64_t caller_image_hash;
        uint64_t signals_bitmap_hash;
        uint64_t timestamp;
    };

    bool tier_a_driver_present_query(bool* out_present = nullptr,
                                     uint32_t* out_mask = nullptr,
                                     uint64_t* out_first_base = nullptr);
    bool tier_a_driver_present();
    bool canary_register(void* va, size_t size);
    bool re_confirmed_usermode_bsod(const re_evidence_blob_t& evidence);

    struct anti_debug_result_t {
        uint32_t result_flags;
        uint64_t detected_debugger_pid;
        uint64_t dr_clear_count;
    };
    bool kernel_anti_debug_query(anti_debug_result_t& out);
    bool kernel_anti_debug_clear_dr(uint64_t* out_clear_count = nullptr);
    bool kernel_anti_debug_clear_process_dr(uint32_t pid, uint64_t* out_clear_count = nullptr);
    bool kernel_anti_debug_scan_debuggers(uint64_t* out_debugger_pid = nullptr);
    bool kernel_anti_debug_hide_thread(uint32_t pid, uint32_t tid);
    bool kernel_anti_debug_hide_all_threads(uint32_t pid);
    bool kernel_anti_debug_install_instrumentation(uint32_t pid, void* callback);
    bool kernel_anti_debug_remove_instrumentation(uint32_t pid);

    bool kernel_anti_dump_full(uint32_t pid);
    bool kernel_anti_dump_register_filter(uint32_t pid);
    bool kernel_anti_dump_hide_threads(uint32_t pid);
    bool kernel_anti_dump_erase_headers(uint32_t pid);
    struct anti_dump_result_t {
        uint64_t blocks_count;
    };
    bool kernel_anti_dump_query(anti_dump_result_t& out);
    bool kernel_anti_dump_permit_pid(uint32_t pid);
    bool kernel_anti_dump_unpermit_pid(uint32_t pid);
    bool kernel_anti_dump_stop_continuous();
    bool kernel_anti_dump_start_continuous(uint32_t pid);

    bool malware_safe_protect_pid(uint32_t pid, uint32_t flags = 0, uint64_t* out_denials = nullptr);
    bool malware_safe_unprotect_pid(uint32_t pid, uint64_t* out_denials = nullptr);
    bool malware_safe_net_log(uint32_t pid, bool enable);

    struct packet_record_t {
        uint64_t timestamp;
        uint64_t tcp_seq;
        uint32_t pid;
        uint32_t payload_len;
        uint32_t flags;
        uint16_t local_port;
        uint16_t remote_port;
        uint16_t address_family;
        uint8_t  protocol;
        uint8_t  direction;
        uint8_t  local_addr[16];
        uint8_t  remote_addr[16];
        uint8_t  payload[256];
    };

    bool malware_safe_pull_packets(uint32_t pid, uint32_t max_records,
                                   std::vector<packet_record_t>& out,
                                   uint64_t* out_dropped = nullptr);

    bool relay_server_token(uint32_t token_hash, uint64_t server_nonce);
    bool relay_server_token_v2(uint32_t token_hash, uint64_t server_nonce, uint64_t* out_driver_proof = nullptr);

    bool traffic_redirect_op(uint32_t operation, uint32_t rule_id = 0, uint32_t protocol = 0,
                             uint32_t match_port = 0, const uint8_t* match_addr = nullptr,
                             uint32_t redirect_port = 0, const uint8_t* redirect_addr = nullptr,
                             uint32_t af = 2, uint32_t* out_rule_id = nullptr, uint32_t exclude_pid = 0);

    bool inject_packet(uint32_t direction, uint32_t protocol, uint32_t af,
                       uint32_t src_port, uint32_t dst_port,
                       const uint8_t* src_addr, const uint8_t* dst_addr,
                       const uint8_t* payload, uint32_t payload_size,
                       uint32_t tcp_flags = 0, uint32_t tcp_seq = 0, uint32_t tcp_ack = 0);

    bool kill_connection(uint32_t protocol, uint32_t af,
                         uint32_t src_port, uint32_t dst_port,
                         const uint8_t* src_addr, const uint8_t* dst_addr,
                         uint32_t pid = 0);

    bool intercept_op(uint32_t operation, uint32_t filter_pid = 0, uint32_t filter_port = 0,
                      uint32_t filter_protocol = 0, uint64_t hold_id = 0,
                      const uint8_t* modify_payload = nullptr, uint32_t modify_size = 0,
                      uint32_t* out_held_count = nullptr, bool* out_active = nullptr);

    bool dns_spoof_op(uint32_t operation, uint32_t rule_id = 0, const char* domain = nullptr,
                      const uint8_t* spoof_addr = nullptr, uint32_t af = 2,
                      uint32_t ttl = 300, uint32_t* out_rule_id = nullptr);

    bool packet_mod_rule_op(uint32_t operation, uint32_t rule_id = 0,
                            uint32_t direction = 2, uint32_t protocol = 0,
                            uint32_t port = 0, uint32_t pid = 0,
                            const uint8_t* pattern = nullptr, uint32_t pattern_size = 0,
                            const uint8_t* replacement = nullptr, uint32_t replace_size = 0,
                            uint32_t* out_rule_id = nullptr);

    bool stream_reassemble_op(uint32_t operation, uint32_t src_port = 0, uint32_t dst_port = 0,
                              uint32_t pid = 0, const uint8_t* src_addr = nullptr,
                              const uint8_t* dst_addr = nullptr,
                              std::vector<uint8_t>* out_data = nullptr,
                              uint32_t* out_packets = nullptr, uint32_t* out_truncated = nullptr);

    bool sniff_net_buffers_start(uint64_t address, uint32_t buf_reg, uint32_t size_reg,
                                 uint32_t max_captures = 1, uint32_t tid = 0, uint32_t bp_index = 0);
    bool sniff_net_buffers_stop();

    struct sniff_result_t {
        uint64_t timestamp;
        uint64_t thread_id;
        std::vector<uint8_t> buffer;
    };
    std::vector<sniff_result_t> sniff_net_buffers_get(bool& active);

    struct hv_kernel_detect_result_t {
        uint8_t sidt_lock_prefix;
        uint8_t sidt_invalid_pf;
        uint8_t sidt_tlb_only;
        uint8_t sidt_timing;
        uint8_t sidt_compat_mode;
        uint8_t sidt_noncanonical_gp;
        uint8_t sidt_noncanonical_ss;
        uint8_t sidt_cpl3_umip_off;
        uint8_t sidt_cpl3_umip_on;

        uint8_t lidt_lock_prefix;
        uint8_t lidt_invalid_pf;
        uint8_t lidt_tlb_only;
        uint8_t lidt_timing;
        uint8_t lidt_noncanonical_gp;
        uint8_t lidt_noncanonical_ss;
        uint8_t lidt_cpl3_gp;

        uint8_t ve_trigger;
        uint8_t ve_lbr_stack;
        uint8_t ve_xsetbv_gp;
        uint8_t ve_cr4_vmxe;

        uint8_t vmf_cpuid_vendor;
        uint8_t vmf_hyperv_guest;
        uint8_t vmf_smbios_vm;
        uint8_t vmf_acpi_vm;
        uint8_t vmf_pci_vm;
        uint8_t vmf_disk_vm;
        uint8_t vmf_mac_vm;
        uint8_t vmf_registry_vm;

        uint8_t total_run;
        uint8_t total_failed;
        uint8_t ms_hv_root;
        uint8_t is_virtual_machine;

        char    vm_vendor_name[16];
        uint8_t measurements_hmac[16];

        bool any_hv_detected() const {
            return (sidt_lock_prefix | sidt_invalid_pf | sidt_tlb_only | sidt_timing |
                    sidt_compat_mode | sidt_noncanonical_gp | sidt_noncanonical_ss |
                    sidt_cpl3_umip_off | sidt_cpl3_umip_on |
                    lidt_lock_prefix | lidt_invalid_pf | lidt_tlb_only | lidt_timing |
                    lidt_noncanonical_gp | lidt_noncanonical_ss | lidt_cpl3_gp |
                    ve_trigger | ve_lbr_stack | ve_xsetbv_gp | ve_cr4_vmxe) != 0;
        }

        bool any_vm_detected() const {
            return is_virtual_machine != 0;
        }

        bool any_detected() const {
            return any_hv_detected() || any_vm_detected();
        }
    };
    bool run_kernel_hv_detection(hv_kernel_detect_result_t& result);

    enum class debug_event_type_e : uint32_t {
        invalid         = 0,
        image_loaded    = 1,
        process_created = 2,
        process_exited  = 3,
    };

    struct debug_event_t {
        debug_event_type_e type = debug_event_type_e::invalid;
        uint32_t           process_id = 0;
        uint32_t           thread_id = 0;
        uint32_t           flags = 0;
        uint64_t           timestamp = 0;
        uint64_t           image_base = 0;
        uint64_t           image_size = 0;
        std::wstring       image_path_wide;
        std::string        image_path;
        std::string        image_name;
    };

    struct debug_event_stats_t {
        uint32_t returned_count = 0;
        uint32_t dropped_since_last_drain = 0;
        uint64_t total_dropped = 0;
        uint64_t total_published = 0;
    };

    bool drain_debug_events(std::vector<debug_event_t>& out,
                            size_t max_events = 64,
                            debug_event_stats_t* out_stats = nullptr);
}
