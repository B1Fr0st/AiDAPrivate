#pragma once
#include <ntifs.h>
#include <ntddmou.h>
#include <stddef.h>

typedef VOID
(*MouseClassServiceCallback)(
    PDEVICE_OBJECT DeviceObject,
    PMOUSE_INPUT_DATA InputDataStart,
    PMOUSE_INPUT_DATA InputDataEnd,
    PULONG InputDataConsumed
);

typedef struct _MOUSE_OBJECT
{
    PDEVICE_OBJECT mouse_device;
    MouseClassServiceCallback service_callback;
} MOUSE_OBJECT, * PMOUSE_OBJECT;

inline PDEVICE_OBJECT g_mouse_device = nullptr;
inline MouseClassServiceCallback g_mouse_callback = nullptr;
inline volatile LONG g_mouse_init_lock = 0;

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

typedef struct _MM {
    INT32 inputX;
    INT32 inputY;
    UINT32 buttonFlags;
} mouse_move, * p_mouse_move;
static_assert(sizeof(mouse_move) == 12, "mouse_move size must be 12 bytes");

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
} heartbeat, * p_heartbeat;
static_assert(sizeof(heartbeat) == 24, "heartbeat size must be 24 bytes");


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
    UINT32 padding;
} suspend_resume_thread, * p_suspend_resume_thread;
static_assert(sizeof(suspend_resume_thread) == 16, "suspend_resume_thread size must be 16 bytes");


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


// ===================== NETWORK INTERCEPTION STRUCTURES =====================

// Network connection entry (IPv4/IPv6 unified)
typedef struct _NET_CONN_ENTRY {
    UINT32 pid;
    UINT32 protocol;          // IPPROTO_TCP=6, IPPROTO_UDP=17
    UINT32 state;             // TCP state: 0=CLOSED..12=TIME_WAIT
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;    // AF_INET=2, AF_INET6=23
    UINT8  local_addr[16];    // IPv4 in first 4 bytes, or full IPv6
    UINT8  remote_addr[16];
} NET_CONN_ENTRY, *PNET_CONN_ENTRY;
static_assert(sizeof(NET_CONN_ENTRY) == 56, "NET_CONN_ENTRY size must be 56 bytes");

// Connection enumeration request
#define MAX_NET_CONNECTIONS 1024

typedef struct _NET_ENUM_CONN {
    UINT32 filter_pid;        // 0 = all processes
    UINT32 filter_protocol;   // 0 = all, 6=TCP, 17=UDP
    UINT32 connection_count;
    UINT32 padding;
    NET_CONN_ENTRY entries[MAX_NET_CONNECTIONS];
} net_enum_conn, *p_net_enum_conn;
static_assert(sizeof(net_enum_conn) == 16 + sizeof(NET_CONN_ENTRY) * MAX_NET_CONNECTIONS,
    "net_enum_conn size check");

// Packet capture control
typedef struct _NET_CAP_CTRL {
    UINT32 operation;         // 0=start, 1=stop, 2=query_status
    UINT32 filter_pid;        // 0 = capture all
    UINT32 filter_port;       // 0 = all ports
    UINT32 filter_protocol;   // 0 = all, 6=TCP, 17=UDP
    UINT8  filter_ip[16];     // 0 = all IPs, otherwise match remote IP
    UINT32 max_packet_bytes;  // max payload per packet to capture (default 1500)
    UINT32 capture_active;    // output: 1 if capture is running
    UINT32 packets_captured;  // output: total packets captured since start
    UINT32 packets_dropped;   // output: packets dropped (ring buffer full)
} net_cap_ctrl, *p_net_cap_ctrl;
static_assert(sizeof(net_cap_ctrl) == 48, "net_cap_ctrl size must be 48 bytes");

// Single captured packet
#define NET_PKT_MAX_PAYLOAD 1500

typedef struct _NET_PACKET_ENTRY {
    UINT64 timestamp;         // KeQuerySystemTime value
    UINT32 pid;
    UINT32 protocol;          // 6=TCP, 17=UDP
    UINT32 direction;         // 0=inbound, 1=outbound
    UINT32 payload_size;      // actual captured payload bytes
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;    // AF_INET=2, AF_INET6=23
    UINT32 padding;
    UINT8  local_addr[16];
    UINT8  remote_addr[16];
    UINT8  payload[NET_PKT_MAX_PAYLOAD];
    UINT8  pad_payload[4];    // alignment padding
} NET_PACKET_ENTRY, *PNET_PACKET_ENTRY;
static_assert(sizeof(NET_PACKET_ENTRY) == 1576, "NET_PACKET_ENTRY size must be 1576 bytes");

// Packet retrieval request
#define NET_CAP_GET_MAX 32

typedef struct _NET_CAP_GET {
    UINT32 max_packets;       // input: how many to retrieve (max NET_CAP_GET_MAX)
    UINT32 packet_count;      // output: how many returned
    NET_PACKET_ENTRY packets[NET_CAP_GET_MAX];
} net_cap_get, *p_net_cap_get;
static_assert(sizeof(net_cap_get) == 8 + sizeof(NET_PACKET_ENTRY) * NET_CAP_GET_MAX,
    "net_cap_get size check");

// DNS query log entry
typedef struct _NET_DNS_ENTRY {
    UINT64 timestamp;
    UINT32 pid;
    UINT32 query_type;        // A=1, AAAA=28, CNAME=5, MX=15, etc.
    char   domain[260];       // null-terminated domain name
    UINT8  resolved_addr[16]; // resolved address (if available)
    UINT32 ttl;
    UINT32 response_code;     // 0=NOERROR, 3=NXDOMAIN, etc.
} NET_DNS_ENTRY, *PNET_DNS_ENTRY;
static_assert(sizeof(NET_DNS_ENTRY) == 304, "NET_DNS_ENTRY size must be 304 bytes");

#define NET_DNS_GET_MAX 64

typedef struct _NET_DNS_GET {
    UINT32 filter_pid;        // 0 = all
    UINT32 entry_count;       // output
    NET_DNS_ENTRY entries[NET_DNS_GET_MAX];
} net_dns_get, *p_net_dns_get;
static_assert(sizeof(net_dns_get) == 8 + sizeof(NET_DNS_ENTRY) * NET_DNS_GET_MAX,
    "net_dns_get size check");

// Packet filter/firewall rule
typedef struct _NET_FILTER_RULE {
    UINT32 rule_id;           // output on add, input on remove
    UINT32 action;            // 0=allow, 1=block, 2=log_only
    UINT32 direction;         // 0=inbound, 1=outbound, 2=both
    UINT32 protocol;          // 0=all, 6=TCP, 17=UDP
    UINT32 pid;               // 0=all processes
    UINT32 port;              // 0=all ports
    UINT8  ip_addr[16];       // 0=all IPs
    UINT8  ip_mask[16];       // subnet mask (0xFF..FF = exact match)
    UINT32 operation;         // 0=add, 1=remove, 2=clear_all, 3=list
    UINT32 rule_count;        // output: number of active rules
} net_filter_rule, *p_net_filter_rule;
static_assert(sizeof(net_filter_rule) == 64, "net_filter_rule size must be 64 bytes");

// Network statistics
typedef struct _NET_STATS {
    UINT32 filter_pid;        // input: 0 = global stats
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

// ============================================================
// Advanced network recon structures (Ring 0 tools)
// ============================================================

// WFP callout entry — one registered callout in the system
#define MAX_WFP_CALLOUTS 256

typedef struct _WFP_CALLOUT_ENTRY {
    UINT64 classify_fn;         // kernel VA of classifyFn callback
    UINT64 notify_fn;           // kernel VA of notifyFn callback
    UINT64 flow_delete_fn;      // kernel VA of flowDeleteFn callback
    UINT64 owning_module_base;  // base of the module that owns this callout
    UINT32 callout_id;          // FWPS callout ID
    UINT32 layer_id;            // WFP layer this callout is registered on
    UINT32 flags;               // callout flags
    UINT32 padding0;
    GUID   callout_key;         // GUID of the callout
    GUID   applicable_layer;    // GUID of the applicable layer
    char   owning_module[64];   // driver name string (e.g. "EasyAntiCheat_EOS.sys")
} WFP_CALLOUT_ENTRY, *PWFP_CALLOUT_ENTRY;
static_assert(sizeof(WFP_CALLOUT_ENTRY) == 144, "WFP_CALLOUT_ENTRY size check");

typedef struct _WFP_CALLOUT_ENUM {
    char   filter_module[64];   // input: empty = all, or substring match
    UINT32 callout_count;       // output: entries filled
    UINT32 padding;
    WFP_CALLOUT_ENTRY entries[MAX_WFP_CALLOUTS];
} wfp_callout_enum, *p_wfp_callout_enum;

// Socket handle entry — AFD object from handle table walk
#define MAX_SOCKET_HANDLES 512

typedef struct _SOCKET_HANDLE_ENTRY {
    UINT64 handle_value;        // actual handle value
    UINT64 afd_endpoint_addr;   // kernel VA of AFD_ENDPOINT object
    UINT32 pid;
    UINT32 protocol;            // 6=TCP, 17=UDP
    UINT32 state;               // TCP state
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;      // AF_INET=2, AF_INET6=23
    UINT8  local_addr[16];
    UINT8  remote_addr[16];
} SOCKET_HANDLE_ENTRY, *PSOCKET_HANDLE_ENTRY;
static_assert(sizeof(SOCKET_HANDLE_ENTRY) == 72, "SOCKET_HANDLE_ENTRY size check");

typedef struct _SOCKET_HANDLE_ENUM {
    UINT32 target_pid;          // input: PID to walk (0 = attached process)
    UINT32 socket_count;        // output: entries filled
    SOCKET_HANDLE_ENTRY entries[MAX_SOCKET_HANDLES];
} socket_handle_enum, *p_socket_handle_enum;

// Network buffer sniff request — uses HW breakpoints to capture plaintext
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
    UINT64 target_address;      // input: address to breakpoint (send/recv/encrypt)
    UINT32 buffer_reg_index;    // input: register index containing buffer ptr (0=rax..15=r15)
    UINT32 size_reg_index;      // input: register index containing size (0=rax..15=r15)
    UINT32 max_captures;        // input: how many to capture before removing BP
    UINT32 operation;           // 0=start, 1=stop, 2=get_results
    UINT32 capture_count;       // output: captures filled
    UINT32 active;              // output: 1 if sniff is active
    UINT32 target_tid;          // input: thread ID (0 = first thread of attached process)
    UINT32 bp_index;            // input: DR index to use (0-3)
    SNIFF_CAPTURE captures[SNIFF_MAX_CAPTURES];
} sniff_net_buffers, *p_sniff_net_buffers;

// tcpip.sys direct connection dump
#define MAX_TCPIP_CONNECTIONS 1024

typedef struct _TCPIP_CONN_ENTRY {
    UINT64 tcb_address;         // kernel VA of TCP Control Block / UDP endpoint
    UINT64 owning_module_base;  // base of the owning module (for AF_UNIX etc.)
    UINT32 pid;
    UINT32 protocol;            // 6=TCP, 17=UDP, 1=ICMP
    UINT32 state;               // TCP state
    UINT32 local_port;
    UINT32 remote_port;
    UINT32 address_family;
    UINT8  local_addr[16];
    UINT8  remote_addr[16];
    UINT64 create_time;         // connection creation timestamp
    UINT64 bytes_in;            // bytes received on this connection
    UINT64 bytes_out;           // bytes sent on this connection
} TCPIP_CONN_ENTRY, *PTCPIP_CONN_ENTRY;
static_assert(sizeof(TCPIP_CONN_ENTRY) == 96, "TCPIP_CONN_ENTRY size check");

typedef struct _TCPIP_CONN_DUMP {
    UINT32 target_pid;          // input: 0 = all
    UINT32 filter_protocol;     // input: 0 = all, 6=TCP, 17=UDP
    UINT32 connection_count;    // output: entries filled
    UINT32 padding;
    TCPIP_CONN_ENTRY entries[MAX_TCPIP_CONNECTIONS];
} tcpip_conn_dump, *p_tcpip_conn_dump;

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
