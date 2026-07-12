#pragma once
#include <ntifs.h>
#include <stddef.h>

extern "C" {
    extern POBJECT_TYPE* IoDriverObjectType;
}

#pragma pack(push, 8)

typedef struct _DB {
    UINT32 pid;
    UINT32 padding;
    UINT64 dtb;
} dtb_solve, * p_dtb_solve;
static_assert(sizeof(dtb_solve) == 16, "dtb_solve size must be 16 bytes");

typedef struct _PRW {
    UINT32 pid;
    UINT32 padding_1;
    UINT64 dtb;
    PVOID address;
    PVOID buffer;
    SIZE_T size;
    SIZE_T retSize;
    UINT8 shouldWrite;
    UINT8 padding_2[7];
} physical_rw, * p_physical_rw;
static_assert(sizeof(physical_rw) == 56, "physical_rw size must be 56 bytes");

typedef struct _BA {
    UINT32 pid;
    UINT32 padding;
    ULONGLONG* outAddress;
} base_address, * p_base_address;
static_assert(sizeof(base_address) == 16, "base_address size must be 16 bytes");

typedef struct _RC {
    UINT64 dtb;
    UINT64 target_function;
    UINT64 shellcode_address;
    UINT64 spoof_return;
    UINT64 arg1;
    UINT64 arg2;
    UINT64 arg3;
    UINT64 arg4;
    UINT64 result;
    UINT64 completed;
    UINT64 original_rip;
    UINT64 trampoline_addr;
} remote_call, * p_remote_call;
static_assert(sizeof(remote_call) == 96, "remote_call size must be 96 bytes");

typedef struct _CR {
    UINT64 dtb;
    UINT64 result_address;
    UINT64 result;
    UINT64 completed;
} call_result, * p_call_result;
static_assert(sizeof(call_result) == 32, "call_result size must be 32 bytes");

#pragma pack(push, 1)
typedef struct _SHELLCODE_CONTEXT {
    UINT64 target_function;
    UINT64 spoof_return;
    UINT64 arg1;
    UINT64 arg2;
    UINT64 arg3;
    UINT64 arg4;
    UINT64 result;
    UINT64 saved_rsp;
    UINT64 original_rip;
    UINT64 rbx_backup;
    volatile UINT64 completed;
    UINT64 trampoline_addr;
    UINT64 stack_backup[8];
    UINT64 xmm_backup[12];
    UINT64 reserved[8];
} SHELLCODE_CONTEXT, *PSHELLCODE_CONTEXT;
static_assert(sizeof(SHELLCODE_CONTEXT) == 320, "SHELLCODE_CONTEXT must be 320 bytes");
static_assert(offsetof(SHELLCODE_CONTEXT, result) == 0x30, "result must be at 0x30 in SHELLCODE_CONTEXT");
static_assert(offsetof(SHELLCODE_CONTEXT, original_rip) == 0x40, "original_rip must be at 0x40 in SHELLCODE_CONTEXT");
static_assert(offsetof(SHELLCODE_CONTEXT, completed) == 0x50, "completed must be at 0x50 in SHELLCODE_CONTEXT");
static_assert(offsetof(SHELLCODE_CONTEXT, trampoline_addr) == 0x58, "trampoline_addr must be at 0x58 in SHELLCODE_CONTEXT");
#pragma pack(pop)

#define SHELLCODE_MAGIC_COMPLETE 0xDEADC0DE12345678ULL

typedef struct _AM {
    UINT32 pid;
    UINT32 padding;
    UINT64 size;
    UINT64 allocated_address;
    UINT64 actual_size;
} alloc_mem, * p_alloc_mem;
static_assert(sizeof(alloc_mem) == 32, "alloc_mem size must be 32 bytes");

typedef struct _FM {
    UINT32 pid;
    UINT32 padding;
    UINT64 address;
} free_mem, * p_free_mem;
static_assert(sizeof(free_mem) == 16, "free_mem size must be 16 bytes");

typedef struct _HB {
    UINT32 magic;
    UINT32 session_key;
    UINT64 timestamp;
    UINT64 response;
    UINT64 whoswho_tsc;
    UINT64 sentinel_tsc;
} heartbeat, * p_heartbeat;
static_assert(sizeof(heartbeat) == 40, "heartbeat size must be 40 bytes");


typedef struct _TCTX {
    UINT32 pid;
    UINT32 tid;
    UINT32 should_set;
    UINT32 padding;
    UINT64 register_mask;

    UINT64 rax;
    UINT64 rbx;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 rbp;
    UINT64 rsp;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;
    UINT64 rip;
    UINT64 rflags;

    UINT64 cs;
    UINT64 ss;

    UINT64 dr0;
    UINT64 dr1;
    UINT64 dr2;
    UINT64 dr3;
    UINT64 dr6;
    UINT64 dr7;
} thread_ctx, * p_thread_ctx;
static_assert(sizeof(thread_ctx) == 232, "thread_ctx size must be 232 bytes");


#define MAX_ENUM_THREADS 256

typedef struct _THREAD_ENTRY {
    UINT32 tid;
    UINT32 state;
    UINT64 rip;
} THREAD_ENTRY;
static_assert(sizeof(THREAD_ENTRY) == 16, "THREAD_ENTRY size must be 16 bytes");

typedef struct _TENUM {
    UINT32 pid;
    UINT32 thread_count;
    THREAD_ENTRY entries[MAX_ENUM_THREADS];
} thread_enum, * p_thread_enum;
static_assert(sizeof(thread_enum) == 8 + sizeof(THREAD_ENTRY) * MAX_ENUM_THREADS, "thread_enum size check");


typedef struct _TSR {
    UINT32 tid;
    UINT32 should_resume;
    ULONG  previous_count;
    UINT32 pid;
} suspend_resume_thread, * p_suspend_resume_thread;
static_assert(sizeof(suspend_resume_thread) == 16, "suspend_resume_thread size must be 16 bytes");


typedef struct _TQIF {
    UINT32 pid;
    UINT32 tid;
    UINT32 info_class;
    UINT32 return_length;
    UINT32 status;
    UINT32 padding;
    INT64  exit_status;
    UINT64 teb_base;
    UINT64 client_process;
    UINT64 client_thread;
    UINT64 affinity_mask;
    INT32  priority;
    INT32  base_priority;
} thread_query_information, * p_thread_query_information;
static_assert(sizeof(thread_query_information) == 72, "thread_query_information size must be 72 bytes");

typedef struct _TTERM {
    UINT32 pid;
    UINT32 tid;
    UINT32 exit_status;
    UINT32 status;
} terminate_thread_request, * p_terminate_thread_request;
static_assert(sizeof(terminate_thread_request) == 16, "terminate_thread_request size must be 16 bytes");

typedef struct _HCLS {
    UINT32 pid;
    UINT32 status;
    UINT64 handle_value;
} close_handle_request, * p_close_handle_request;
static_assert(sizeof(close_handle_request) == 16, "close_handle_request size must be 16 bytes");


typedef struct _QM {
    UINT32 pid;
    UINT32 padding;
    UINT64 address;

    UINT64 region_base;
    UINT64 region_size;
    UINT32 state;
    UINT32 protect;
    UINT32 type;
    UINT32 allocation_protect;
    UINT64 allocation_base;
} query_memory, * p_query_memory;
static_assert(sizeof(query_memory) == 56, "query_memory size must be 56 bytes");


typedef struct _PM {
    UINT32 pid;
    UINT32 new_protect;
    UINT64 address;
    UINT64 size;
    UINT32 old_protect;
    UINT32 padding;
} protect_memory, * p_protect_memory;
static_assert(sizeof(protect_memory) == 32, "protect_memory size must be 32 bytes");


#define MAX_ENUM_REGIONS 4096

typedef struct _REGION_ENTRY {
    UINT64 base;
    UINT64 size;
    UINT32 state;
    UINT32 protect;
    UINT32 type;
    UINT32 padding;
} REGION_ENTRY;
static_assert(sizeof(REGION_ENTRY) == 32, "REGION_ENTRY size must be 32 bytes");

typedef struct _EREGS {
    UINT32 pid;
    UINT32 include_all;
    UINT64 start_address;
    UINT64 max_address;
    UINT32 region_count;
    UINT32 padding;
    REGION_ENTRY entries[MAX_ENUM_REGIONS];
} enum_regions, * p_enum_regions;
static_assert(sizeof(enum_regions) == 32 + sizeof(REGION_ENTRY) * MAX_ENUM_REGIONS, "enum_regions size check");


typedef struct _RPEB {
    UINT32 pid;
    UINT32 padding;

    UINT64 peb_address;
    UINT64 image_base;
    UINT8  being_debugged;
    UINT8  pad1[3];
    UINT32 nt_global_flag;
    UINT64 ldr_address;
    UINT64 process_heap;
    UINT32 number_of_heaps;
    UINT32 max_heaps;
    UINT64 process_heaps;
} read_peb, * p_read_peb;
static_assert(sizeof(read_peb) == 64, "read_peb size must be 64 bytes");


typedef struct _SDF {
    UINT32 pid;
    UINT32 result_flags;
} spoof_debug, * p_spoof_debug;
static_assert(sizeof(spoof_debug) == 8, "spoof_debug size must be 8 bytes");


typedef struct _MEX {
    UINT64 dtb;
    UINT64 module_base;
    char   export_name[128];
    UINT64 resolved_address;
    UINT32 ordinal;
    UINT32 padding;
} module_export, * p_module_export;
static_assert(sizeof(module_export) == 160, "module_export size must be 160 bytes");


typedef struct _V2P {
    UINT64 dtb;
    UINT64 virtual_address;
    UINT64 physical_address;
} virt_to_phys, * p_virt_to_phys;
static_assert(sizeof(virt_to_phys) == 24, "virt_to_phys size must be 24 bytes");

typedef struct _SSDTQ {
    UINT64 lstar;
    UINT64 descriptor_address;
    UINT64 service_table;
    UINT64 counter_table;
    UINT64 argument_table;
    UINT32 service_limit;
    UINT32 flags;
} ssdt_query, * p_ssdt_query;
static_assert(sizeof(ssdt_query) == 48, "ssdt_query size must be 48 bytes");


typedef struct _NET_CONN_ENTRY {
    UINT32 pid;
    UINT32 protocol;
    UINT32 state;
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;
    UINT8  local_addr[16];
    UINT8  remote_addr[16];
    char   process_path[260];
    UINT32 padding_pp;
} NET_CONN_ENTRY, *PNET_CONN_ENTRY;
static_assert(sizeof(NET_CONN_ENTRY) == 320, "NET_CONN_ENTRY size must be 320 bytes");


#define MAX_NET_CONNECTIONS 1024

typedef struct _NET_ENUM_CONN {
    UINT32 filter_pid;
    UINT32 filter_protocol;
    UINT32 connection_count;
    UINT32 padding;
    NET_CONN_ENTRY entries[MAX_NET_CONNECTIONS];
} net_enum_conn, *p_net_enum_conn;
static_assert(sizeof(net_enum_conn) == 16 + sizeof(NET_CONN_ENTRY) * MAX_NET_CONNECTIONS,
    "net_enum_conn size check");


typedef struct _NET_CAP_CTRL {
    UINT32 operation;
    UINT32 filter_pid;
    UINT32 filter_port;
    UINT32 filter_protocol;
    UINT8  filter_ip[16];
    UINT32 max_packet_bytes;
    UINT32 capture_active;
    UINT32 packets_captured;
    UINT32 packets_dropped;
} net_cap_ctrl, *p_net_cap_ctrl;
static_assert(sizeof(net_cap_ctrl) == 48, "net_cap_ctrl size must be 48 bytes");


#define NET_PKT_MAX_PAYLOAD 1500

typedef struct _NET_PACKET_ENTRY {
    UINT64 timestamp;
    UINT32 pid;
    UINT32 protocol;
    UINT32 direction;
    UINT32 payload_size;
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;
    UINT32 padding;
    UINT8  local_addr[16];
    UINT8  remote_addr[16];
    UINT8  payload[NET_PKT_MAX_PAYLOAD];
    UINT8  pad_payload[4];
} NET_PACKET_ENTRY, *PNET_PACKET_ENTRY;
static_assert(sizeof(NET_PACKET_ENTRY) == 1576, "NET_PACKET_ENTRY size must be 1576 bytes");


#define NET_CAP_GET_MAX 32

typedef struct _NET_CAP_GET {
    UINT32 max_packets;
    UINT32 packet_count;
    NET_PACKET_ENTRY packets[NET_CAP_GET_MAX];
} net_cap_get, *p_net_cap_get;
static_assert(sizeof(net_cap_get) == 8 + sizeof(NET_PACKET_ENTRY) * NET_CAP_GET_MAX,
    "net_cap_get size check");


typedef struct _NET_DNS_ENTRY {
    UINT64 timestamp;
    UINT32 pid;
    UINT32 query_type;
    char   domain[260];
    UINT8  resolved_addr[16];
    UINT32 ttl;
    UINT32 response_code;
} NET_DNS_ENTRY, *PNET_DNS_ENTRY;
static_assert(sizeof(NET_DNS_ENTRY) == 304, "NET_DNS_ENTRY size must be 304 bytes");

#define NET_DNS_GET_MAX 64

typedef struct _NET_DNS_GET {
    UINT32 filter_pid;
    UINT32 entry_count;
    NET_DNS_ENTRY entries[NET_DNS_GET_MAX];
} net_dns_get, *p_net_dns_get;
static_assert(sizeof(net_dns_get) == 8 + sizeof(NET_DNS_ENTRY) * NET_DNS_GET_MAX,
    "net_dns_get size check");


typedef struct _NET_FILTER_RULE {
    UINT32 rule_id;
    UINT32 action;
    UINT32 direction;
    UINT32 protocol;
    UINT32 pid;
    UINT32 port;
    UINT8  ip_addr[16];
    UINT8  ip_mask[16];
    UINT32 operation;
    UINT32 rule_count;
} net_filter_rule, *p_net_filter_rule;
static_assert(sizeof(net_filter_rule) == 64, "net_filter_rule size must be 64 bytes");


typedef struct _NET_STATS {
    UINT32 filter_pid;
    UINT32 padding;
    UINT64 bytes_sent;
    UINT64 bytes_received;
    UINT64 packets_sent;
    UINT64 packets_received;
    UINT32 active_connections;
    UINT32 capture_active;
    UINT32 total_captured;
    UINT32 total_dropped;
    UINT32 total_dns_logged;
    UINT32 active_filter_rules;
} net_stats, *p_net_stats;
static_assert(sizeof(net_stats) == 64, "net_stats size must be 64 bytes");


#define MAX_WFP_CALLOUTS 256
#define WFP_ENTRY_TYPE_CALLOUT 0
#define WFP_ENTRY_TYPE_FILTER  1
#define WFP_AIDA_MATCH_SUBLAYER       0x00000001u
#define WFP_AIDA_MATCH_ACTION_CALLOUT 0x00000002u
#define WFP_AIDA_MATCH_DISPLAY_DATA   0x00000004u
#define WFP_AIDA_MATCH_RUNTIME_FALLBACK 0x80000000u

typedef struct _WFP_CALLOUT_ENTRY {
    UINT64 classify_fn;
    UINT64 notify_fn;
    UINT64 flow_delete_fn;
    UINT64 owning_module_base;
    UINT64 filter_id;
    UINT32 callout_id;
    UINT32 layer_id;
    UINT32 flags;
    UINT32 entry_type;
    GUID   callout_key;
    GUID   applicable_layer;
    GUID   sublayer_key;
    UINT32 action_type;
    UINT32 provider_present;
    UINT32 aida_match_reason;
    UINT32 padding0;
    char   owning_module[64];
} WFP_CALLOUT_ENTRY, *PWFP_CALLOUT_ENTRY;
static_assert(sizeof(WFP_CALLOUT_ENTRY) == 184, "WFP_CALLOUT_ENTRY size check");

typedef struct _WFP_CALLOUT_ENUM {
    char   filter_module[64];
    UINT32 callout_count;
    UINT32 padding;
    WFP_CALLOUT_ENTRY entries[MAX_WFP_CALLOUTS];
} wfp_callout_enum, *p_wfp_callout_enum;


#define MAX_SOCKET_HANDLES 512

typedef struct _SOCKET_HANDLE_ENTRY {
    UINT64 handle_value;
    UINT64 afd_endpoint_addr;
    UINT32 pid;
    UINT32 protocol;
    UINT32 state;
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;
    UINT8  local_addr[16];
    UINT8  remote_addr[16];
} SOCKET_HANDLE_ENTRY, *PSOCKET_HANDLE_ENTRY;
static_assert(sizeof(SOCKET_HANDLE_ENTRY) == 72, "SOCKET_HANDLE_ENTRY size check");

typedef struct _SOCKET_HANDLE_ENUM {
    UINT32 target_pid;
    UINT32 socket_count;
    SOCKET_HANDLE_ENTRY entries[MAX_SOCKET_HANDLES];
} socket_handle_enum, *p_socket_handle_enum;


#define SNIFF_MAX_CAPTURES 16
#define SNIFF_MAX_BUF_SIZE 2048

typedef struct _SNIFF_CAPTURE {
    UINT64 timestamp;
    UINT64 thread_id;
    UINT32 buffer_size;
    UINT32 padding;
    UINT8  buffer[SNIFF_MAX_BUF_SIZE];
} SNIFF_CAPTURE, *PSNIFF_CAPTURE;
static_assert(sizeof(SNIFF_CAPTURE) == 2072, "SNIFF_CAPTURE size check");

typedef struct _SNIFF_NET_BUFFERS {
    UINT64 target_address;
    UINT32 buffer_reg_index;
    UINT32 size_reg_index;
    UINT32 max_captures;
    UINT32 operation;
    UINT32 capture_count;
    UINT32 active;
    UINT32 target_tid;
    UINT32 bp_index;
    SNIFF_CAPTURE captures[SNIFF_MAX_CAPTURES];
} sniff_net_buffers, *p_sniff_net_buffers;


#define MAX_TCPIP_CONNECTIONS 1024

typedef struct _TCPIP_CONN_ENTRY {
    UINT64 tcb_address;
    UINT64 owning_module_base;
    UINT32 pid;
    UINT32 protocol;
    UINT32 state;
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;
    UINT8  local_addr[16];
    UINT8  remote_addr[16];
    UINT64 create_time;
    UINT64 bytes_in;
    UINT64 bytes_out;
} TCPIP_CONN_ENTRY, *PTCPIP_CONN_ENTRY;
static_assert(sizeof(TCPIP_CONN_ENTRY) == 96, "TCPIP_CONN_ENTRY size check");

typedef struct _TCPIP_CONN_DUMP {
    UINT32 target_pid;
    UINT32 filter_protocol;
    UINT32 connection_count;
    UINT32 padding;
    TCPIP_CONN_ENTRY entries[MAX_TCPIP_CONNECTIONS];
} tcpip_conn_dump, *p_tcpip_conn_dump;


#define INJECT_MAX_PAYLOAD 1500

typedef struct _PACKET_INJECT_REQUEST {
    UINT32 direction;
    UINT32 protocol;
    UINT32 address_family;
    UINT32 src_port;
    UINT32 dst_port;
    UINT32 payload_size;
    UINT8  src_addr[16];
    UINT8  dst_addr[16];
    UINT32 tcp_flags;
    UINT32 tcp_seq;
    UINT32 tcp_ack;
    UINT32 status;
    UINT8  payload[INJECT_MAX_PAYLOAD];
} PACKET_INJECT_REQUEST, *P_PACKET_INJECT_REQUEST,
  packet_inject_request, *p_packet_inject_request;


#define MOD_MAX_PATTERN 256
#define MOD_MAX_REPLACE 256
#define MOD_MAX_RULES   32

typedef struct _PACKET_MOD_RULE {
    UINT32 rule_id;
    UINT32 operation;
    UINT32 direction;
    UINT32 protocol;
    UINT32 port;
    UINT32 pid;
    UINT32 pattern_size;
    UINT32 replace_size;
    UINT8  pattern[MOD_MAX_PATTERN];
    UINT8  replacement[MOD_MAX_REPLACE];
    UINT32 match_count;
    UINT32 active;
} PACKET_MOD_RULE, *P_PACKET_MOD_RULE,
  packet_mod_rule, *p_packet_mod_rule;

typedef struct _PACKET_MOD_RULE_LIST {
    UINT32 operation;
    UINT32 rule_count;
    PACKET_MOD_RULE rules[MOD_MAX_RULES];
} PACKET_MOD_RULE_LIST, *P_PACKET_MOD_RULE_LIST,
  packet_mod_rule_list, *p_packet_mod_rule_list;


#define REDIR_MAX_RULES 16

typedef struct _TRAFFIC_REDIRECT_RULE {
    UINT32 rule_id;
    UINT32 operation;
    UINT32 protocol;
    UINT32 match_port;
    UINT8  match_addr[16];
    UINT32 redirect_port;
    UINT8  redirect_addr[16];
    UINT32 address_family;
    UINT32 match_count;
    UINT32 active;
    UINT32 exclude_pid;
} TRAFFIC_REDIRECT_RULE, *P_TRAFFIC_REDIRECT_RULE,
  traffic_redirect_rule, *p_traffic_redirect_rule;

typedef struct _TRAFFIC_REDIRECT_LIST {
    UINT32 operation;
    UINT32 rule_count;
    TRAFFIC_REDIRECT_RULE rules[REDIR_MAX_RULES];
} TRAFFIC_REDIRECT_LIST, *P_TRAFFIC_REDIRECT_LIST,
  traffic_redirect_list, *p_traffic_redirect_list;


#define STREAM_MAX_SIZE (64 * 1024)

typedef struct _STREAM_REASSEMBLE_REQUEST {
    UINT32 operation;
    UINT32 src_port;
    UINT32 dst_port;
    UINT32 pid;
    UINT8  src_addr[16];
    UINT8  dst_addr[16];
    UINT32 stream_size;
    UINT32 total_packets;
    UINT32 stream_count;
    UINT32 truncated;
    UINT8  stream_data[STREAM_MAX_SIZE];
} stream_reassemble_request, *p_stream_reassemble_request;


#define DPI_MAX_RESULTS 64

typedef struct _DPI_HEADER_INFO {
    UINT64 timestamp;
    UINT32 direction;
    UINT32 protocol;
    UINT32 src_port;
    UINT32 dst_port;
    UINT8  src_addr[16];
    UINT8  dst_addr[16];
    UINT32 address_family;
    UINT32 pid;

    UINT32 tcp_flags;
    UINT32 tcp_seq;
    UINT32 tcp_ack;
    UINT32 tcp_window;

    UINT32 payload_size;
    UINT32 is_http;
    UINT32 is_tls;
    UINT32 is_dns;
    UINT32 http_method;
    UINT32 tls_version;
    UINT32 tls_content_type;
    char   http_host[128];
    char   http_path[256];
    char   tls_sni[128];
} DPI_HEADER_INFO, *PDPI_HEADER_INFO;
static_assert(sizeof(DPI_HEADER_INFO) == 624, "DPI_HEADER_INFO size check");

typedef struct _DPI_REQUEST {
    UINT32 filter_pid;
    UINT32 filter_protocol;
    UINT32 filter_port;
    UINT32 flags;
    UINT32 result_count;
    UINT32 padding;
    DPI_HEADER_INFO results[DPI_MAX_RESULTS];
} dpi_request, *p_dpi_request;


#define INTERCEPT_MAX_HELD    32
#define INTERCEPT_MAX_PAYLOAD 1500

typedef struct _HELD_PACKET {
    UINT64 hold_id;
    UINT64 timestamp;
    UINT32 direction;
    UINT32 protocol;
    UINT32 src_port;
    UINT32 dst_port;
    UINT8  src_addr[16];
    UINT8  dst_addr[16];
    UINT32 pid;
    UINT32 payload_size;
    UINT8  payload[INTERCEPT_MAX_PAYLOAD];
    UINT32 address_family;
    UINT32 padding;
} HELD_PACKET, *PHELD_PACKET;

typedef struct _INTERCEPT_REQUEST {
    UINT32 operation;
    UINT32 filter_pid;
    UINT32 filter_port;
    UINT32 filter_protocol;
    UINT64 hold_id;
    UINT32 held_count;
    UINT32 intercepting;
    UINT32 modify_payload_size;
    UINT32 padding;
    UINT8  modify_payload[INTERCEPT_MAX_PAYLOAD];
    UINT32 padding2;
    HELD_PACKET held_packets[INTERCEPT_MAX_HELD];
} intercept_request, *p_intercept_request;


typedef struct _CONN_KILL_REQUEST {
    UINT32 protocol;
    UINT32 address_family;
    UINT32 src_port;
    UINT32 dst_port;
    UINT8  src_addr[16];
    UINT8  dst_addr[16];
    UINT32 pid;
    UINT32 status;
} conn_kill_request, *p_conn_kill_request;


#define DNS_SPOOF_MAX_RULES 32
#define DNS_SPOOF_MAX_DOMAIN 128

typedef struct _DNS_SPOOF_RULE {
    UINT32 rule_id;
    UINT32 operation;
    char   domain[DNS_SPOOF_MAX_DOMAIN];
    UINT8  spoof_addr[16];
    UINT32 address_family;
    UINT32 match_count;
    UINT32 active;
    UINT32 ttl;
} DNS_SPOOF_RULE, *P_DNS_SPOOF_RULE,
  dns_spoof_rule, *p_dns_spoof_rule;

typedef struct _DNS_SPOOF_LIST {
    UINT32 operation;
    UINT32 rule_count;
    DNS_SPOOF_RULE rules[DNS_SPOOF_MAX_RULES];
} DNS_SPOOF_LIST, *P_DNS_SPOOF_LIST,
  dns_spoof_list, *p_dns_spoof_list;


#define BW_MAX_PROCESSES 128

typedef struct _BW_PROCESS_ENTRY {
    UINT32 pid;
    UINT32 padding;
    UINT64 bytes_sent;
    UINT64 bytes_recv;
    UINT64 packets_sent;
    UINT64 packets_recv;
    UINT64 last_activity_time;
} BW_PROCESS_ENTRY, *PBW_PROCESS_ENTRY;
static_assert(sizeof(BW_PROCESS_ENTRY) == 48, "BW_PROCESS_ENTRY size check");

typedef struct _BW_MONITOR_REQUEST {
    UINT32 operation;
    UINT32 filter_pid;
    UINT64 total_bytes_sent;
    UINT64 total_bytes_recv;
    UINT64 total_packets_sent;
    UINT64 total_packets_recv;
    UINT64 bytes_per_second_in;
    UINT64 bytes_per_second_out;
    UINT32 monitoring_active;
    UINT32 process_count;
    BW_PROCESS_ENTRY processes[BW_MAX_PROCESSES];
} bw_monitor_request, *p_bw_monitor_request;


#define NET_IF_MAX 32
#define NET_IF_NAME_LEN 64

typedef struct _NET_INTERFACE_ENTRY {
    UINT32 if_index;
    UINT32 if_type;
    UINT32 mtu;
    UINT32 oper_status;
    UINT64 speed;
    UINT8  mac_addr[6];
    UINT8  pad[2];
    UINT8  ipv4_addr[4];
    UINT8  ipv4_mask[4];
    UINT8  ipv6_addr[16];
    char   name[NET_IF_NAME_LEN];
    char   description[NET_IF_NAME_LEN];
    UINT64 in_octets;
    UINT64 out_octets;
} NET_INTERFACE_ENTRY, *PNET_INTERFACE_ENTRY;

typedef struct _NET_INTERFACE_ENUM {
    UINT32 interface_count;
    UINT32 padding;
    NET_INTERFACE_ENTRY interfaces[NET_IF_MAX];
} net_interface_enum, *p_net_interface_enum;


typedef struct _PCAP_GLOBAL_HEADER {
    UINT32 magic_number;
    UINT16 version_major;
    UINT16 version_minor;
    INT32  thiszone;
    UINT32 sigfigs;
    UINT32 snaplen;
    UINT32 network;
} PCAP_GLOBAL_HEADER;

#define PCAP_MAX_EXPORT_PACKETS 256
#define PCAP_RECORD_MAX_SIZE    1548

typedef struct _PCAP_RECORD {
    UINT32 ts_sec;
    UINT32 ts_usec;
    UINT32 incl_len;
    UINT32 orig_len;
    UINT8  data[PCAP_RECORD_MAX_SIZE];
} PCAP_RECORD;

typedef struct _PCAP_EXPORT_REQUEST {
    UINT32 operation;
    UINT32 filter_pid;
    UINT32 filter_protocol;
    UINT32 max_packets;
    UINT32 packet_count;
    UINT32 data_size;
    PCAP_GLOBAL_HEADER header;
    PCAP_RECORD records[PCAP_MAX_EXPORT_PACKETS];
} pcap_export_request, *p_pcap_export_request;


typedef struct _NET_FINGERPRINT_ENTRY {
    UINT8  remote_addr[16];
    UINT32 address_family;
    UINT32 ttl;
    UINT32 window_size;
    UINT32 mss;
    UINT32 window_scale;
    UINT32 df_flag;
    UINT32 sack_permitted;
    UINT32 nop_count;
    UINT32 tcp_options_order;
    char   os_guess[64];
} NET_FINGERPRINT_ENTRY, *PNET_FINGERPRINT_ENTRY;

#define FINGERPRINT_MAX 64

typedef struct _NET_FINGERPRINT_REQUEST {
    UINT32 operation;
    UINT32 result_count;
    NET_FINGERPRINT_ENTRY entries[FINGERPRINT_MAX];
} net_fingerprint_request, *p_net_fingerprint_request;


#define MAX_SEQ_DELTA_ENTRIES 256
typedef struct _SEQ_DELTA_ENTRY {
    volatile LONG active;
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    LONG32 outbound_delta;
    LONG32 inbound_delta;
    UINT64 last_activity;
} SEQ_DELTA_ENTRY, *PSEQ_DELTA_ENTRY;


#define MAX_FRAGMENT_ENTRIES 32
#define FRAGMENT_MAX_SIZE (64 * 1024)
typedef struct _FRAGMENT_ENTRY {
    volatile LONG active;
    UINT16 ip_id;
    UINT8  protocol;
    UINT8  padding1;
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT32 total_received;
    UINT32 highest_offset;
    BOOLEAN last_fragment_seen;
    UINT8  padding2[3];
    UINT64 first_seen;
    UINT8  data[FRAGMENT_MAX_SIZE];
    UINT8  received_map[8192];
} FRAGMENT_ENTRY, *PFRAGMENT_ENTRY;


#define MAX_UDP_FLOW_ENTRIES 128
typedef struct _UDP_FLOW_ENTRY {
    volatile LONG active;
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    UINT32 pid;
    UINT64 last_activity;
} UDP_FLOW_ENTRY, *PUDP_FLOW_ENTRY;


#pragma pack(pop)

#define DTB_CACHE_SIZE 32

typedef struct _DTB_CACHE_ENTRY {
    UINT64 dtb;
    UINT64 last_access;
    UINT32 pid;
    UINT32 valid;
} DTB_CACHE_ENTRY, *PDTB_CACHE_ENTRY;
static_assert(sizeof(DTB_CACHE_ENTRY) == 24, "DTB_CACHE_ENTRY must be 24 bytes");

inline DTB_CACHE_ENTRY g_dtb_cache[DTB_CACHE_SIZE] = { 0 };


#define DPRT_OP_REGISTER   0
#define DPRT_OP_QUERY      1
#define DPRT_OP_UNREGISTER 2

#define DPRT_STATUS_INACTIVE   0
#define DPRT_STATUS_ACTIVE     1
#define DPRT_STATUS_TAMPERED   2
#define DPRT_STATUS_DEBUGGER   3

typedef struct _DPRT {
    UINT32 operation;
    UINT32 pid;
    UINT64 module_base;
    UINT64 text_section_va;
    UINT32 text_section_size;
    UINT32 padding;
    UINT64 expected_hash;
    UINT64 current_hash;
    UINT32 status;
    UINT32 check_interval;
    UINT64 last_check_tsc;
} dll_protect, *p_dll_protect;
static_assert(sizeof(dll_protect) == 64, "dll_protect size must be 64 bytes");


typedef struct _ABRT {
    UINT32 magic;
    UINT32 reason_code;
    UINT64 evidence_hash;
    UINT64 timestamp;
} abort_request, *p_abort_request;
static_assert(sizeof(abort_request) == 24, "abort_request size must be 24 bytes");


#define ADBG_OP_QUERY          0
#define ADBG_OP_CLEAR_DR       1
#define ADBG_OP_SCAN_DEBUGGERS 2
#define ADBG_OP_HIDE_THREAD    3

typedef struct _ADBG {
    UINT32 operation;
    UINT32 pid;
    UINT32 tid;
    UINT32 result_flags;
    UINT64 detected_debugger_pid;
    UINT64 dr_clear_count;
} anti_debug_request, *p_anti_debug_request;
static_assert(sizeof(anti_debug_request) == 32, "anti_debug_request size must be 32 bytes");


typedef struct _SRVT {
    UINT32 token_hash;
    UINT32 session_key;
    UINT64 timestamp;
    UINT64 server_nonce;
    UINT32 result;
    UINT32 padding;
} server_token_relay, *p_server_token_relay;
static_assert(sizeof(server_token_relay) == 32, "server_token_relay size must be 32 bytes");


#define ADMP_OP_FULL_PROTECT     0
#define ADMP_OP_REGISTER_FILTER  1
#define ADMP_OP_HIDE_THREADS     2
#define ADMP_OP_ERASE_HEADERS    3
#define ADMP_OP_QUERY            4
#define ADMP_OP_START_CONTINUOUS  5
#define ADMP_OP_STOP_CONTINUOUS   6
#define ADMP_OP_SCAN_KILL         7
#define ADMP_OP_CORRUPT_SECTIONS  8
#define ADMP_OP_SCRAMBLE_PEB      9
#define ADMP_OP_PERMIT_PID       10
#define ADMP_OP_UNPERMIT_PID     11
#define ADMP_OP_VERIFY_HEADERS    12
#define ADMP_OP_LOCK_PAGES        13
#define ADMP_OP_REGISTER_MODULE_RANGE 14

typedef struct _ADMP {
    UINT32 operation;
    UINT32 pid;
    UINT64 blocks_count;
    UINT32 result;
    UINT32 padding;
} anti_dump_request, *p_anti_dump_request;
static_assert(sizeof(anti_dump_request) == 24, "anti_dump_request size must be 24 bytes");

typedef struct _ADMP_HEADER_STATE {
    UINT16 dos_magic;
    UINT32 nt_signature;
    UINT32 first_section_va;
    UINT32 checksum;
    UINT32 headers_restored;
} admp_header_state, *p_admp_header_state;

typedef struct _ADMP_LOCK_PAGES_REQ {
    UINT32 operation;
    UINT32 pid;
    UINT32 page_count;
    UINT32 padding;
    UINT64 page_bases[32];
    UINT64 page_sizes[32];
} admp_lock_pages_req, *p_admp_lock_pages_req;

typedef struct _ADMP_MODULE_RANGE {
    UINT32 operation;
    UINT32 pid;
    UINT32 range_count;
    UINT32 padding;
    UINT64 bases[16];
    UINT64 sizes[16];
} admp_module_range_req, *p_admp_module_range_req;


#define ADBG_OP_CLEAR_PROC_DR      4
#define ADBG_OP_HIDE_ALL_THREADS   5
#define ADBG_OP_INSTALL_INSTR_CB   6
#define ADBG_OP_REMOVE_INSTR_CB    7
#define ADBG_OP_START_CONTINUOUS   8
#define ADBG_OP_STOP_CONTINUOUS    9
#define ADBG_OP_CLEAR_DEBUG_OBJ    10


typedef struct _SRVT2 {
    UINT32 token_hash;
    UINT32 session_key;
    UINT64 timestamp;
    UINT64 server_nonce;
    UINT64 driver_proof;
    UINT32 result;
    UINT32 action;
} server_token_relay_v2, *p_server_token_relay_v2;
static_assert(sizeof(server_token_relay_v2) == 40, "server_token_relay_v2 size must be 40 bytes");

inline volatile LONG g_cache_lock = 0;

__forceinline void AcquireCacheLock() {
    while (_InterlockedCompareExchange(&g_cache_lock, 1, 0) != 0) {
        YieldProcessor();
    }
    KeMemoryBarrier();
}

__forceinline void ReleaseCacheLock() {
    KeMemoryBarrier();
    _InterlockedExchange(&g_cache_lock, 0);
}

__forceinline BOOLEAN LookupDTBCache(UINT32 pid, PUINT64 out_dtb) {
    if (!out_dtb || pid == 0) {
        return FALSE;
    }

    AcquireCacheLock();

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (g_dtb_cache[i].valid && g_dtb_cache[i].pid == pid) {
            *out_dtb = g_dtb_cache[i].dtb;
            g_dtb_cache[i].last_access = __rdtsc();
            ReleaseCacheLock();
            return TRUE;
        }
    }

    ReleaseCacheLock();
    return FALSE;
}

__forceinline void InsertDTBCache(UINT32 pid, UINT64 dtb) {
    if (pid == 0 || dtb == 0) {
        return;
    }

    AcquireCacheLock();

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (g_dtb_cache[i].valid && g_dtb_cache[i].pid == pid) {
            g_dtb_cache[i].dtb = dtb;
            g_dtb_cache[i].last_access = __rdtsc();
            ReleaseCacheLock();
            return;
        }
    }

    int target_idx = 0;
    UINT64 oldest_time = ~0ULL;

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (!g_dtb_cache[i].valid) {
            target_idx = i;
            break;
        }
        if (g_dtb_cache[i].last_access < oldest_time) {
            oldest_time = g_dtb_cache[i].last_access;
            target_idx = i;
        }
    }

    g_dtb_cache[target_idx].pid = pid;
    g_dtb_cache[target_idx].dtb = dtb;
    g_dtb_cache[target_idx].last_access = __rdtsc();
    KeMemoryBarrier();
    g_dtb_cache[target_idx].valid = TRUE;

    ReleaseCacheLock();
}

__forceinline void InvalidateDTBCache(UINT32 pid) {
    AcquireCacheLock();

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (g_dtb_cache[i].pid == pid) {
            g_dtb_cache[i].valid = FALSE;
            KeMemoryBarrier();
        }
    }

    ReleaseCacheLock();
}


typedef struct _IOMMU_STATUS {
    UINT8  dmar_present;
    UINT8  ivrs_present;
    UINT8  vtd_enabled;
    UINT8  amd_vi_enabled;
    UINT8  iommu_present;
    UINT8  remapping_bypassed;
    UINT8  pad[2];
    UINT64 dmar_table_pa;
    UINT64 ivrs_table_pa;
    UINT32 remapping_units;
    UINT32 risk_level;
    UINT64 detection_timestamp;
} iommu_status_k, *p_iommu_status_k;
static_assert(sizeof(iommu_status_k) == 40, "iommu_status_k must be 40 bytes");


typedef struct _PCIE_DEVICE_ENTRY {
    UINT16 vendor_id;
    UINT16 device_id;
    UINT32 class_code;
    UINT8  bus;
    UINT8  device;
    UINT8  function;
    UINT8  header_type;
    UINT64 bar_pa[6];
    UINT64 bar_size;
    UINT32 flags;
    UINT32 whitelist_status;
} pcie_device_entry_k, *p_pcie_device_entry_k;
static_assert(sizeof(pcie_device_entry_k) == 80, "pcie_device_entry_k must be 80 bytes");


#define MAX_PCIE_DEVICES 256

typedef struct _PCIE_ENUM_RESULT {
    UINT32 device_count;
    UINT32 unknown_count;
    pcie_device_entry_k entries[MAX_PCIE_DEVICES];
} pcie_enum_result_k, *p_pcie_enum_result_k;
static_assert(sizeof(pcie_enum_result_k) == 8 + sizeof(pcie_device_entry_k) * MAX_PCIE_DEVICES,
    "pcie_enum_result_k size check");


typedef struct _PCIE_WHITELIST_REQUEST {
    UINT32 operation;
    UINT32 entry_count;
    UINT16 vendor_id;
    UINT16 device_id;
    UINT32 result;
    UINT64 timestamp;
} pcie_whitelist_request_k, *p_pcie_whitelist_request_k;
static_assert(sizeof(pcie_whitelist_request_k) == 24, "pcie_whitelist_request_k must be 24 bytes");


typedef struct _CANARY_POISON_REQUEST {
    UINT64 va;
    UINT64 pa;
    UINT64 poison_signature;
    UINT64 original_value;
    UINT32 active;
    UINT32 result;
} canary_poison_request_k, *p_canary_poison_request_k;
static_assert(sizeof(canary_poison_request_k) == 40, "canary_poison_request_k must be 40 bytes");


typedef struct _PTE_PROTECTION_ENTRY {
    UINT64 va;
    UINT64 pa;
    UINT64 original_pte;
    UINT64 current_pte;
    UINT32 page_size;
    UINT32 active;
    UINT64 last_restore_timestamp;
} pte_protection_entry_k, *p_pte_protection_entry_k;
static_assert(sizeof(pte_protection_entry_k) == 48, "pte_protection_entry_k must be 48 bytes");


#define MAX_PTE_PROTECTION_ENTRIES 64

typedef struct _PTE_PROTECTION_TABLE {
    UINT32 entry_count;
    UINT32 active_count;
    pte_protection_entry_k entries[MAX_PTE_PROTECTION_ENTRIES];
} pte_protection_table_k, *p_pte_protection_table_k;
static_assert(sizeof(pte_protection_table_k) == 8 + sizeof(pte_protection_entry_k) * MAX_PTE_PROTECTION_ENTRIES,
    "pte_protection_table_k size check");


typedef struct _EPT_CHECK_RESULT {
    UINT8  ept_present;
    UINT8  npte_present;
    UINT8  ept_hook_detected;
    UINT8  vmm_present;
    UINT8  pad[4];
    UINT64 ept_pointer_msr;
    UINT32 npte_anomaly_count;
    UINT32 risk_level;
    UINT64 detection_timestamp;
} ept_check_result_k, *p_ept_check_result_k;
static_assert(sizeof(ept_check_result_k) == 32, "ept_check_result_k must be 32 bytes");


typedef struct _DMA_PROTECTION_STATE {
    iommu_status_k iommu;
    UINT32 canary_count;
    UINT32 canary_hits;
    UINT32 pcie_unknown_count;
    UINT32 ept_anomaly_count;
    UINT32 tier1_refused;
    UINT32 tier2_bsod_armed;
    UINT64 timestamp;
} dma_protection_state_k, *p_dma_protection_state_k;
static_assert(sizeof(dma_protection_state_k) == 72, "dma_protection_state_k must be 72 bytes");


typedef struct _DMA_COUNTERMEASURE_REQUEST {
    UINT32 action;
    UINT32 reason;
    UINT32 target_pid;
    UINT32 result;
    UINT64 evidence_hash;
    UINT64 timestamp;
} dma_countermeasure_request_k, *p_dma_countermeasure_request_k;
static_assert(sizeof(dma_countermeasure_request_k) == 32, "dma_countermeasure_request_k must be 32 bytes");

#pragma pack(push, 8)
typedef struct _RE_TOOL_HASH_UPDATE_REQUEST_K {
    UINT32 magic;
    UINT32 hash_count;
    UINT32 session_key;
    UINT32 padding;
    UINT8  hashes[16 * 32];
    UINT32 werfault_hash_count;
    UINT32 werfault_padding;
    UINT8  werfault_hashes[16 * 32];
    UINT64 timestamp;
} re_tool_hash_update_request_k, *p_re_tool_hash_update_request_k;
#pragma pack(pop)
static_assert(sizeof(re_tool_hash_update_request_k) == (16 + 512 + 8 + 512 + 8), "re_tool_hash_update_request_k size mismatch");

#pragma pack(push, 8)
typedef struct _CE_DRIVER_HASH_UPDATE_REQUEST_K {
    UINT32 magic;
    UINT32 hash_count;
    UINT32 session_key;
    UINT32 padding;
    UINT8  hashes[32 * 32];
    UINT64 timestamp;
} ce_driver_hash_update_request_k, *p_ce_driver_hash_update_request_k;
#pragma pack(pop)
static_assert(sizeof(ce_driver_hash_update_request_k) == (16 + 1024 + 8), "ce_driver_hash_update_request_k size mismatch");


#pragma pack(push, 8)
typedef struct _TEXT_SCAN_REQUEST_K {
    UINT64 module_base;
    UINT64 exception_dir_va;
    UINT32 exception_dir_size;
    UINT32 padding;
    UINT64 hit_rva;
} text_scan_request_k, *p_text_scan_request_k;
#pragma pack(pop)
static_assert(sizeof(text_scan_request_k) == 32, "text_scan_request_k must be 32 bytes");

#define OP_HIDE_PROCESS     0
#define OP_UNHIDE_PROCESS   1

#pragma pack(push, 8)
typedef struct _HIDE_PROCESS_REQUEST_K {
    UINT32 operation;
    UINT32 pid;
    UINT32 result;
    UINT32 padding;
} hide_process_request_k, *p_hide_process_request_k;
#pragma pack(pop)
static_assert(sizeof(hide_process_request_k) == 16, "hide_process_request_k must be 16 bytes");

typedef struct _PROLOGUE_HASH_REQUEST {
    UINT64 va;
    UINT32 size;
    UINT32 pad;
    UINT64 hash_result;
} prologue_hash_request_k;
static_assert(sizeof(prologue_hash_request_k) == 24, "prologue_hash_request_k size check");

typedef struct _DISPATCH_GUARD_QUERY_K {
    UINT8  hook_detected;
    UINT8  pad[7];
    UINT64 hook_target;
} dispatch_guard_query_k;
static_assert(sizeof(dispatch_guard_query_k) == 16, "dispatch_guard_query_k size check");

typedef struct _CALLBACK_SCAN_QUERY_K {
    UINT8  hostile_drivers;
    UINT8  modified_callbacks;
    UINT8  pad[6];
} callback_scan_query_k;
static_assert(sizeof(callback_scan_query_k) == 8, "callback_scan_query_k size check");

#pragma pack(push, 1)
typedef struct _WATERMARK_VERIFY_REQUEST {
    UINT8  expected_watermark[16];
    UINT32 watermark_rva;
    UINT32 pad;
    UINT8  actual_watermark[16];
    UINT8  verified;
} watermark_verify_request_k, *p_watermark_verify_request_k;
#pragma pack(pop)
static_assert(sizeof(watermark_verify_request_k) == 41, "watermark_verify_request_k must be 41 bytes");

#define HANDSHAKE_MAGIC 0x4853484Bu

typedef struct _HSHK {
    UINT32 magic;
    UINT32 session_key;
    UINT8  challenge[32];
    UINT8  response[32];
    UINT8  driver_challenge[32];
    UINT32 verified;
    UINT32 padding;
} handshake_request, *p_handshake_request;
static_assert(sizeof(handshake_request) == 112, "handshake_request must be 112 bytes");
