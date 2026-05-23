#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"
#include "../Stealth.h"
#include "../MalwareSafe.h"
#include <ndis.h>
#include <ndis/nbl.h>
#include <ndis/nblaccessors.h>
#include <ndis/nblapi.h>
#include <fwpmk.h>


#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 23
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define FWPS_INJECTION_TYPE_STREAM    0x00000001
#define FWPS_INJECTION_TYPE_TRANSPORT 0x00000002
#define FWPS_INJECTION_TYPE_NETWORK   0x00000004
#define FWPS_INJECTION_TYPE_FORWARD   0x00000008

typedef struct _AIDA_WSACMSGHDR {
    SIZE_T cmsg_len;
    INT cmsg_level;
    INT cmsg_type;
} AIDA_WSACMSGHDR;

typedef struct _FWPS_TRANSPORT_SEND_PARAMS0_COMPAT {
    UCHAR* remoteAddress;
    ULONG remoteScopeId;
    AIDA_WSACMSGHDR* controlData;
    ULONG controlDataLength;
} FWPS_TRANSPORT_SEND_PARAMS0_COMPAT;

#define AIDA_ENDPOINT_PID_CACHE_SIZE 128


#ifdef AIDA_NET_DEBUG


#define NET_DBG(fmt, ...) \
    do { if (_DbgPrintEx) _DbgPrintEx(77, 0, "[AIDA-NET] " fmt "\n", ##__VA_ARGS__); } while(0)

#define NET_ERR(fmt, ...) \
    do { if (_DbgPrintEx) _DbgPrintEx(77, 0, "[AIDA-NET][ERR] " fmt "\n", ##__VA_ARGS__); } while(0)

#else
#define NET_DBG(fmt, ...) ((void)0)
#define NET_ERR(fmt, ...) ((void)0)
#endif


typedef struct _FWPS_CALLOUT2_COMPAT {
    GUID   calloutKey;
    UINT32 flags;
    PVOID  classifyFn;
    PVOID  notifyFn;
    PVOID  flowDeleteFn;
} FWPS_CALLOUT2_COMPAT;

typedef FWP_ACTION_TYPE FWP_ACTION_TYPE_;
typedef FWP_VALUE0 FWP_VALUE0_COMPAT;
typedef FWP_BYTE_BLOB FWP_BYTE_BLOB_COMPAT;
typedef FWP_CONDITION_VALUE0 FWP_CONDITION_VALUE0_COMPAT;
typedef FWPM_FILTER_CONDITION0 FWPM_FILTER_CONDITION0_COMPAT;
typedef FWPM_ACTION0 FWPM_ACTION0_COMPAT;
typedef FWPM_FILTER0 FWPM_FILTER0_COMPAT;
typedef FWPM_CALLOUT0 FWPM_CALLOUT0_COMPAT;
typedef FWPM_SUBLAYER0 FWPM_SUBLAYER0_COMPAT;

typedef struct _FWPS_INCOMING_VALUE0_COMPAT {
    FWP_VALUE0_COMPAT value;
} FWPS_INCOMING_VALUE0_COMPAT;

typedef struct _FWPS_INCOMING_VALUES0_COMPAT {
    UINT16 layerId;
    UINT16 reserved;
    UINT32 valueCount;
    FWPS_INCOMING_VALUE0_COMPAT* incomingValue;
} FWPS_INCOMING_VALUES0_COMPAT;

typedef struct _FWPS_DISCARD_METADATA0_COMPAT {
    UINT64 handle;
    UINT32 flags;
    UINT32 reserved;
} FWPS_DISCARD_METADATA0_COMPAT;

typedef struct _FWPS_INBOUND_FRAGMENT_METADATA0_COMPAT {
    UINT32 fragmentOffset;
    UINT32 fragmentLength;
    UINT32 flags;
    UINT32 reserved;
} FWPS_INBOUND_FRAGMENT_METADATA0_COMPAT;

typedef struct _SCOPE_ID_COMPAT {
    ULONG Value;
} SCOPE_ID_COMPAT;

typedef struct _FWPS_INCOMING_METADATA_VALUES0_COMPAT {
    UINT32 currentMetadataValues;
    UINT32 flags;
    UINT64 reserved;
    FWPS_DISCARD_METADATA0_COMPAT discardMetadata;
    UINT64 flowHandle;
    UINT32 ipHeaderSize;
    UINT32 transportHeaderSize;
    FWP_BYTE_BLOB_COMPAT* processPath;
    UINT64 token;
    UINT64 processId;
    UINT32 sourceInterfaceIndex;
    UINT32 destinationInterfaceIndex;
    ULONG compartmentId;
    FWPS_INBOUND_FRAGMENT_METADATA0_COMPAT fragmentMetadata;
    ULONG pathMtu;
    HANDLE completionHandle;
    UINT64 transportEndpointHandle;
    SCOPE_ID_COMPAT remoteScopeId;
    AIDA_WSACMSGHDR* controlData;
    ULONG controlDataLength;
} FWPS_INCOMING_METADATA_VALUES0_COMPAT;

typedef struct _FWPS_CLASSIFY_OUT0_COMPAT {
    FWP_ACTION_TYPE_ actionType;
    UINT64 outContext;
    UINT64 filterId;
    UINT32 rights;
    UINT32 flags;
    UINT32 reserved;
} FWPS_CLASSIFY_OUT0_COMPAT;

#define FWP_ACTION_BLOCK_ FWP_ACTION_BLOCK
#define FWP_ACTION_PERMIT_ FWP_ACTION_PERMIT
#define FWP_ACTION_CONTINUE_ FWP_ACTION_CONTINUE
#define FWP_ACTION_CALLOUT_TERMINATING_ FWP_ACTION_CALLOUT_TERMINATING
#define FWP_EMPTY_ FWP_EMPTY
#define FWP_CONDITION_FLAG_IS_LOOPBACK_ FWP_CONDITION_FLAG_IS_LOOPBACK
#define FWPS_METADATA_FIELD_PROCESS_ID_ 0x00000020
#define FWPS_RIGHT_ACTION_WRITE_ 0x00000001
#define FWPS_CLASSIFY_OUT_FLAG_ABSORB_ 0x00000001


typedef NTSTATUS(NTAPI* fn_FwpsCalloutRegister2)(
    PVOID deviceObject, const FWPS_CALLOUT2_COMPAT* callout,
    UINT32* calloutId);
typedef NTSTATUS(NTAPI* fn_FwpsCalloutUnregisterById0)(UINT32 calloutId);
typedef NTSTATUS(NTAPI* fn_FwpmEngineOpen0)(
    const wchar_t* serverName, UINT32 authnService,
    PVOID authIdentity, PVOID session, HANDLE* engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmEngineClose0)(HANDLE engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmTransactionBegin0)(HANDLE engineHandle, UINT32 flags);
typedef NTSTATUS(NTAPI* fn_FwpmTransactionCommit0)(HANDLE engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmTransactionAbort0)(HANDLE engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutAdd0)(
    HANDLE engineHandle, const FWPM_CALLOUT0_COMPAT* callout,
    PVOID sd, UINT32* id);
typedef NTSTATUS(NTAPI* fn_FwpmSubLayerAdd0)(
    HANDLE engineHandle, const FWPM_SUBLAYER0_COMPAT* subLayer, PVOID sd);
typedef NTSTATUS(NTAPI* fn_FwpmFilterAdd0)(
    HANDLE engineHandle, const FWPM_FILTER0_COMPAT* filter,
    PVOID sd, UINT64* id);
typedef NTSTATUS(NTAPI* fn_FwpmFilterDeleteById0)(HANDLE engineHandle, UINT64 filterId);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutDeleteById0)(HANDLE engineHandle, UINT32 calloutId);
typedef NTSTATUS(NTAPI* fn_FwpmSubLayerDeleteByKey0)(HANDLE engineHandle, const GUID* key);


static const GUID GUID_LAYER_INBOUND_V4 =
    { 0x5926dfc8, 0xe3cf, 0x4426, { 0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d } };

static const GUID GUID_LAYER_OUTBOUND_V4 =
    { 0x09e61aea, 0xd214, 0x46e2, { 0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8 } };

static const GUID GUID_LAYER_ALE_CONNECT_V4 =
    { 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };

static const GUID GUID_LAYER_ALE_RECV_V4 =
    { 0xe1cd9fe7, 0xf4b5, 0x4273, { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 } };


#define FWPS_FIELD_IN_TRANS_V4_PROTOCOL      0
#define FWPS_FIELD_IN_TRANS_V4_LOCAL_ADDR    1
#define FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR   2
#define FWPS_FIELD_IN_TRANS_V4_LOCAL_PORT    4
#define FWPS_FIELD_IN_TRANS_V4_REMOTE_PORT   5


#define FWPS_FIELD_OUT_TRANS_V4_PROTOCOL     0
#define FWPS_FIELD_OUT_TRANS_V4_LOCAL_ADDR   1
#define FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR  3
#define FWPS_FIELD_OUT_TRANS_V4_LOCAL_PORT   4
#define FWPS_FIELD_OUT_TRANS_V4_REMOTE_PORT  5


#define FWPS_FIELD_ALE_V4_IP_LOCAL_ADDR     1
#define FWPS_FIELD_ALE_V4_IP_LOCAL_PORT     3
#define FWPS_FIELD_ALE_V4_IP_PROTOCOL       4
#define FWPS_FIELD_ALE_V4_IP_REMOTE_ADDR    5
#define FWPS_FIELD_ALE_V4_IP_REMOTE_PORT    6


namespace net_bw {
    void record_traffic(UINT32 pid, UINT32 direction, UINT32 bytes);
}
namespace net_mod {
    BOOLEAN apply_modifications(UINT8* data, UINT32* data_len, UINT32 max_len,
                                UINT32 direction, UINT32 protocol,
                                UINT32 port, UINT32 pid);
    BOOLEAN has_active_rules();
}
namespace net_stream {
    void feed_packet(UINT32 src_port, UINT32 dst_port, UINT32 pid,
                     const UINT8* src_addr, const UINT8* dst_addr,
                     const UINT8* data, UINT32 data_len);
    BOOLEAN has_active_streams();
    BOOLEAN get_first_active_stream(UINT32* src_port, UINT32* dst_port,
                                    UINT32* pid, UINT8* src_addr, UINT8* dst_addr);
    void cleanup();
}

static UINT32 aida_resolve_packet_pid(UINT64 endpoint_handle,
                                      UINT32 protocol,
                                      UINT32 local_port,
                                      UINT32 remote_port);
static UINT32 aida_lookup_cached_port_pid(UINT32 protocol,
                                          UINT32 local_port,
                                          UINT32 remote_port);
static VOID aida_store_cached_port_pid(UINT32 protocol,
                                       UINT32 port,
                                       UINT32 pid);
static NTSTATUS aida_refresh_pid_cache_for_process(UINT32 target_pid,
                                                   UINT32 protocol_filter);
static VOID aida_store_cached_endpoint_pid(UINT64 endpoint_handle,
                                           UINT32 protocol,
                                           UINT32 local_port,
                                           UINT32 pid);
static __forceinline BOOLEAN aida_can_query_system_handles();
static void afd_init_offsets();

namespace net_capture {
    void NTAPI classify_inbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    void NTAPI classify_outbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    void NTAPI classify_ale_connect(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    void NTAPI classify_ale_recv(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    NTSTATUS NTAPI callout_notify(UINT32 notifyType, const GUID* filterKey, const void* filter);
}
namespace net_fingerprint {
    inline KSPIN_LOCK g_fp_lock;
    void analyze_tcp_syn(const UINT8* src_addr, UINT32 af,
                         const UINT8* tcp_data, UINT32 tcp_len,
                         UINT32 ip_ttl);
    BOOLEAN is_active();
    void cleanup();
}
namespace net_dpi {
    NTSTATUS init();
    void analyze_packet(UINT64 timestamp, UINT32 direction, UINT32 protocol,
                        UINT32 src_port, UINT32 dst_port,
                        const UINT8* src_addr, const UINT8* dst_addr,
                        UINT32 af, UINT32 pid,
                        const UINT8* payload, UINT32 payload_len);
    BOOLEAN is_active();
    void cleanup();
}
namespace net_intercept {
    void init_lock();
    BOOLEAN try_hold_packet(UINT32 direction, UINT32 protocol,
                            UINT32 src_port, UINT32 dst_port,
                            const UINT8* src_addr, const UINT8* dst_addr,
                            UINT32 af, UINT32 pid,
                            const UINT8* payload, UINT32 payload_len);
    BOOLEAN is_active();
    void cleanup();
}
namespace net_redirect {
    BOOLEAN check_redirect(UINT32 protocol, UINT32 dst_port, const UINT8* dst_addr,
                           UINT32 af, UINT32 pid, UINT32* new_port, UINT8* new_addr);
    BOOLEAN has_active_rules();
}
namespace net_dns_spoof {
    BOOLEAN check_spoof(const char* domain, UINT8* out_addr, UINT32* out_af, UINT32* out_ttl);
    BOOLEAN has_active_rules();
    void cleanup();
}
namespace net_bw {
    BOOLEAN is_active();
    void cleanup();
}
namespace net_inject {
    inline constexpr UINT32 INJECT_FLAG_RAW_TRANSPORT = 0x80000000u;
    BOOLEAN resolve_inject_functions();
    BOOLEAN prepare_injection_runtime();
    NTSTATUS inject_packet(p_packet_inject_request request);
    void cleanup();
    extern HANDLE g_inject_handle_v4;
    extern HANDLE g_inject_handle_net_v4;
    typedef UINT32(NTAPI* fn_FwpsQueryPacketInjectionState0)(
        HANDLE injectionHandle, PVOID netBufferList, HANDLE* injectionContext);
    extern fn_FwpsQueryPacketInjectionState0 _FwpsQueryPacketInjectionState0;
}
namespace net_checksum {
    UINT16 ip_checksum(const UINT8* ip_header, UINT32 header_len);
    UINT16 tcp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* tcp_data, UINT32 tcp_len);
    UINT16 udp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* udp_data, UINT32 udp_len);
    void recalculate_transport_checksums(UINT8* ip_header, UINT32 total_len);
}
namespace net_seq_delta {
    SEQ_DELTA_ENTRY* find_or_create(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port);
    BOOLEAN apply_delta(UINT8* tcp_header, UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound);
    void record_size_change(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound, LONG32 delta);
    void cleanup_expired();
    void handle_fin_rst(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port);
}
namespace net_fragment {
    UINT8* process_fragment(const UINT8* ip_header, UINT32 total_packet_len, UINT32* out_reassembled_len);
    void init();
    void cleanup();
    void cleanup_expired();
}
namespace net_udp_cache {
    UINT32 lookup(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port);
    void store(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, UINT32 pid);
    void cleanup_expired();
}

namespace net_capture {


    inline fn_FwpsCalloutRegister2       _FwpsCalloutRegister2       = nullptr;
    inline fn_FwpsCalloutUnregisterById0 _FwpsCalloutUnregisterById0 = nullptr;
    inline fn_FwpmEngineOpen0            _FwpmEngineOpen0            = nullptr;
    inline fn_FwpmEngineClose0           _FwpmEngineClose0           = nullptr;
    inline fn_FwpmTransactionBegin0      _FwpmTransactionBegin0      = nullptr;
    inline fn_FwpmTransactionCommit0     _FwpmTransactionCommit0     = nullptr;
    inline fn_FwpmTransactionAbort0      _FwpmTransactionAbort0      = nullptr;
    inline fn_FwpmCalloutAdd0            _FwpmCalloutAdd0            = nullptr;
    inline fn_FwpmSubLayerAdd0           _FwpmSubLayerAdd0           = nullptr;
    inline fn_FwpmFilterAdd0             _FwpmFilterAdd0             = nullptr;
    inline fn_FwpmFilterDeleteById0      _FwpmFilterDeleteById0      = nullptr;
    inline fn_FwpmCalloutDeleteById0     _FwpmCalloutDeleteById0     = nullptr;
    inline fn_FwpmSubLayerDeleteByKey0   _FwpmSubLayerDeleteByKey0   = nullptr;


    inline volatile LONG g_wfp_initialized = 0;
    inline volatile LONG g_capture_active = 0;
    inline HANDLE g_engine_handle = nullptr;
    inline PDEVICE_OBJECT g_device_object = nullptr;


    inline UINT32 g_callout_id_inbound = 0;
    inline UINT32 g_callout_id_outbound = 0;
    inline UINT32 g_callout_id_ale_connect = 0;
    inline UINT32 g_callout_id_ale_recv = 0;
    inline UINT64 g_filter_id_inbound = 0;
    inline UINT64 g_filter_id_outbound = 0;
    inline UINT64 g_filter_id_ale_connect = 0;
    inline UINT64 g_filter_id_ale_recv = 0;


    static const GUID GUID_AIDA_CALLOUT_INBOUND =
        { 0x7a8b3c1d, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } };
    static const GUID GUID_AIDA_CALLOUT_OUTBOUND =
        { 0x7a8b3c1e, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf7 } };
    static const GUID GUID_AIDA_CALLOUT_ALE_CONNECT =
        { 0x7a8b3c20, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf9 } };
    static const GUID GUID_AIDA_CALLOUT_ALE_RECV =
        { 0x7a8b3c21, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xfa } };
    static const GUID GUID_AIDA_SUBLAYER =
        { 0x7a8b3c1f, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf8 } };


    inline UINT32 g_filter_pid = 0;
    inline UINT32 g_filter_port = 0;
    inline UINT32 g_filter_protocol = 0;
    inline UINT8  g_filter_ip[16] = {};
    inline UINT32 g_max_payload = NET_PKT_MAX_PAYLOAD;


    #define RING_BUFFER_SIZE 2048
    inline NET_PACKET_ENTRY* g_ring_buffer = nullptr;
    inline volatile LONG g_ring_head = 0;
    inline volatile LONG g_ring_tail = 0;
    inline volatile LONG g_ring_count = 0;
    inline KSPIN_LOCK g_ring_lock;
    inline volatile LONG g_total_captured = 0;
    inline volatile LONG g_total_dropped = 0;


    inline volatile LONG64 g_global_bytes_sent = 0;
    inline volatile LONG64 g_global_bytes_recv = 0;
    inline volatile LONG64 g_global_pkts_sent = 0;
    inline volatile LONG64 g_global_pkts_recv = 0;


    #define DNS_RING_SIZE 256
    inline NET_DNS_ENTRY* g_dns_ring = nullptr;
    inline volatile LONG g_dns_head = 0;
    inline volatile LONG g_dns_tail = 0;
    inline volatile LONG g_dns_count = 0;
    inline KSPIN_LOCK g_dns_lock;
    inline volatile LONG g_total_dns = 0;


    #define MAX_FILTER_RULES 64
    typedef struct _ACTIVE_FILTER_RULE {
        UINT32 rule_id;
        UINT32 action;
        UINT32 direction;
        UINT32 protocol;
        UINT32 pid;
        UINT32 port;
        UINT8  ip_addr[16];
        UINT8  ip_mask[16];
        volatile LONG active;
    } ACTIVE_FILTER_RULE;

    inline ACTIVE_FILTER_RULE g_filter_rules[MAX_FILTER_RULES] = {};
    inline volatile LONG g_next_rule_id = 1;
    inline volatile LONG g_active_rule_count = 0;


    inline SEQ_DELTA_ENTRY g_seq_delta[MAX_SEQ_DELTA_ENTRIES] = {};
    inline KSPIN_LOCK g_seq_delta_lock;


    inline FRAGMENT_ENTRY* g_fragment_entries = nullptr;
    inline KSPIN_LOCK g_fragment_lock;


    inline UDP_FLOW_ENTRY g_udp_flow[MAX_UDP_FLOW_ENTRIES] = {};
    inline KSPIN_LOCK g_udp_flow_lock;


    #define PID_PATH_CACHE_SIZE 64
    typedef struct _PID_PATH_CACHE_ENTRY {
        UINT32 pid;
        UINT32 padding;
        UINT64 timestamp;
        char path[260];
        UINT32 padding2;
    } PID_PATH_CACHE_ENTRY;
    inline PID_PATH_CACHE_ENTRY g_pid_path_cache[PID_PATH_CACHE_SIZE] = {};
    inline KSPIN_LOCK g_pid_path_lock;


    __forceinline BOOLEAN is_zero_ip(const UINT8* ip) {
        for (int i = 0; i < 16; i++) {
            if (ip[i] != 0) return FALSE;
        }
        return TRUE;
    }

    __forceinline BOOLEAN ip_matches(const UINT8* pkt_ip, const UINT8* rule_ip,
                                      const UINT8* rule_mask, UINT32 af) {
        UINT32 len = (af == 23) ? 16 : 4;
        for (UINT32 i = 0; i < len; i++) {
            if ((pkt_ip[i] & rule_mask[i]) != (rule_ip[i] & rule_mask[i]))
                return FALSE;
        }
        return TRUE;
    }

    __forceinline void copy_ipv4_fixed_value(UINT32 address, UINT8* out_ip) {
        strong::kmemset(out_ip, 0, 16);
        out_ip[0] = (UINT8)((address >> 24) & 0xFF);
        out_ip[1] = (UINT8)((address >> 16) & 0xFF);
        out_ip[2] = (UINT8)((address >> 8) & 0xFF);
        out_ip[3] = (UINT8)(address & 0xFF);
    }

    __forceinline UINT32 copy_transport_bytes(void* layerData, UINT8* out_data, UINT32 max_len) {
        if (!layerData || !out_data || max_len == 0)
            return 0;

        __try {
            PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
            PNET_BUFFER first_nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (!first_nb) {
                return 0;
            }

            ULONG data_length = NET_BUFFER_DATA_LENGTH(first_nb);
            if (data_length == 0) {
                return 0;
            }

            ULONG copy_len = (data_length < max_len) ? data_length : max_len;
            ULONG copied = 0;
            PMDL mdl = NET_BUFFER_CURRENT_MDL(first_nb);
            ULONG mdl_offset = NET_BUFFER_CURRENT_MDL_OFFSET(first_nb);

            while (mdl && copied < copy_len) {
                PUCHAR mapped = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
                if (!mapped) {
                    break;
                }

                ULONG mdl_len = MmGetMdlByteCount(mdl);
                if (mdl_offset >= mdl_len) {
                    mdl_offset -= mdl_len;
                    mdl = mdl->Next;
                    continue;
                }

                ULONG avail = mdl_len - mdl_offset;
                ULONG chunk = ((copy_len - copied) < avail) ? (copy_len - copied) : avail;
                strong::kmemcpy(out_data + copied, mapped + mdl_offset, chunk);
                copied += chunk;
                mdl = mdl->Next;
                mdl_offset = 0;
            }

            if (copied == 0 && NET_BUFFER_CURRENT_MDL(first_nb)) {
            }

            return copied;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }


    __forceinline UINT32 get_transport_data_length(void* layerData) {
        if (!layerData)
            return 0;
        __try {
            PNET_BUFFER_LIST nbl = reinterpret_cast<PNET_BUFFER_LIST>(layerData);
            PNET_BUFFER first_nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (!first_nb)
                return 0;
            return NET_BUFFER_DATA_LENGTH(first_nb);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }

    __forceinline UINT32 parse_dns_name(const UINT8* dns_data, UINT32 offset,
                                         UINT32 data_len, char* out, UINT32 out_size) {
        UINT32 pos = offset;
        UINT32 out_pos = 0;
        UINT32 jumps = 0;
        BOOLEAN jumped = FALSE;
        UINT32 return_pos = 0;

        while (pos < data_len && out_pos < out_size - 1) {
            UINT8 label_len = dns_data[pos];
            if (label_len == 0) {
                pos++;
                break;
            }

            if ((label_len & 0xC0) == 0xC0) {
                if (pos + 1 >= data_len) break;
                if (!jumped) return_pos = pos + 2;
                UINT16 ptr_off = ((UINT16)(label_len & 0x3F) << 8) | dns_data[pos + 1];
                pos = ptr_off;
                jumped = TRUE;
                jumps++;
                if (jumps > 64) break;
                continue;
            }
            if (label_len > 63) break;
            pos++;
            if (pos + label_len > data_len) break;
            if (out_pos > 0 && out_pos < out_size - 1) {
                out[out_pos++] = '.';
            }
            for (UINT8 i = 0; i < label_len && out_pos < out_size - 1; i++) {
                out[out_pos++] = (char)dns_data[pos + i];
            }
            pos += label_len;
        }
        out[out_pos] = '\0';
        return jumped ? return_pos : pos;
    }


    __forceinline UINT32 check_filter_rules(UINT32 direction, UINT32 protocol,
                                             UINT32 pid, UINT32 local_port, UINT32 remote_port,
                                             const UINT8* remote_ip, UINT32 af) {

        for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
            if (g_filter_rules[i].active != 1) continue;
            const ACTIVE_FILTER_RULE* r = &g_filter_rules[i];

            if (r->direction != 2 && r->direction != direction) continue;
            if (r->protocol != 0 && r->protocol != protocol) continue;
            if (r->pid != 0 && r->pid != pid) continue;
            if (r->port != 0 && r->port != local_port && r->port != remote_port) continue;
            if (!is_zero_ip(r->ip_addr)) {
                if (!ip_matches(remote_ip, r->ip_addr, r->ip_mask, af))
                    continue;
            }
            return r->action;
        }
        return 0;
    }


    __forceinline void store_packet(UINT32 direction, UINT32 protocol,
                                     UINT32 pid, UINT32 local_port, UINT32 remote_port,
                                     UINT32 af, const UINT8* local_ip, const UINT8* remote_ip,
                                     const UINT8* payload_data, UINT32 payload_len) {
        if (!g_ring_buffer) return;

        UINT32 effective_pid = pid;
        if (effective_pid == 0 && g_filter_pid != 0) {
            return;
        }


        if (g_filter_pid != 0 && effective_pid != g_filter_pid) {
            return;
        }
        if (g_filter_port != 0 && local_port != g_filter_port && remote_port != g_filter_port) return;
        if (g_filter_protocol != 0 && protocol != g_filter_protocol) return;
        if (!is_zero_ip(g_filter_ip)) {
            UINT8 mask[16];
            strong::kmemset(mask, 0xFF, sizeof(mask));
            if (!ip_matches(remote_ip, g_filter_ip, mask, af)) return;
        }

        UINT32 cap_len = payload_len;
        if (cap_len > g_max_payload) cap_len = g_max_payload;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_ring_lock, &old_irql);

        if (g_ring_count >= RING_BUFFER_SIZE) {
            g_ring_tail = (g_ring_tail + 1) % RING_BUFFER_SIZE;
            g_ring_count--;
            _InterlockedIncrement(&g_total_dropped);
        }

        NET_PACKET_ENTRY* entry = &g_ring_buffer[g_ring_head];
        strong::kmemset(entry, 0, sizeof(NET_PACKET_ENTRY));

        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);
        entry->timestamp = ts.QuadPart;
        entry->pid = effective_pid;
        entry->protocol = protocol;
        entry->direction = direction;
        entry->payload_size = cap_len;
        entry->local_port = local_port;
        entry->remote_port = remote_port;
        entry->address_family = af;

        if (local_ip) {
            UINT32 copy_len = (af == 23) ? 16 : 4;
            strong::kmemcpy(entry->local_addr, local_ip, copy_len);
        }
        if (remote_ip) {
            UINT32 copy_len = (af == 23) ? 16 : 4;
            strong::kmemcpy(entry->remote_addr, remote_ip, copy_len);
        }
        if (payload_data && cap_len > 0) {
            strong::kmemcpy(entry->payload, payload_data, cap_len);
        }

        g_ring_head = (g_ring_head + 1) % RING_BUFFER_SIZE;
        g_ring_count++;
        _InterlockedIncrement(&g_total_captured);

        KeReleaseSpinLock(&g_ring_lock, old_irql);
    }


    __forceinline void store_dns_entry(UINT32 pid, const char* domain,
                                        UINT32 query_type, UINT32 response_code,
                                        const UINT8* resolved, UINT32 ttl) {
        if (!g_dns_ring) return;

        UINT32 effective_pid = pid;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_dns_lock, &old_irql);

        if (g_dns_count >= DNS_RING_SIZE) {
            g_dns_tail = (g_dns_tail + 1) % DNS_RING_SIZE;
            g_dns_count--;
        }

        NET_DNS_ENTRY* entry = &g_dns_ring[g_dns_head];
        strong::kmemset(entry, 0, sizeof(NET_DNS_ENTRY));

        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);
        entry->timestamp = ts.QuadPart;
        entry->pid = effective_pid;
        entry->query_type = query_type;
        entry->response_code = response_code;
        entry->ttl = ttl;

        if (domain) {
            UINT32 i = 0;
            while (domain[i] && i < 259) {
                entry->domain[i] = domain[i];
                i++;
            }
            entry->domain[i] = '\0';
        }
        if (resolved) {
            strong::kmemcpy(entry->resolved_addr, resolved, 16);
        }

        g_dns_head = (g_dns_head + 1) % DNS_RING_SIZE;
        g_dns_count++;
        _InterlockedIncrement(&g_total_dns);

        KeReleaseSpinLock(&g_dns_lock, old_irql);
    }


    __forceinline void try_parse_dns(UINT32 pid, const UINT8* data, UINT32 data_len,
                                      UINT32 local_port, UINT32 remote_port) {
        if (local_port != 53 && remote_port != 53) return;
        if (data_len < 12) return;

        const UINT8* dns_data = data;
        UINT32 dns_len = data_len;

        if (data_len >= 20) {
            UINT16 udp_src = ((UINT16)data[0] << 8) | data[1];
            UINT16 udp_dst = ((UINT16)data[2] << 8) | data[3];
            UINT16 udp_len = ((UINT16)data[4] << 8) | data[5];
            BOOLEAN ports_match =
                ((udp_src == (UINT16)local_port || udp_src == (UINT16)remote_port ||
                  udp_dst == (UINT16)local_port || udp_dst == (UINT16)remote_port) &&
                 (udp_src == 53 || udp_dst == 53));
            if (ports_match && udp_len >= 20 && udp_len <= data_len) {
                dns_data = data + 8;
                dns_len = udp_len - 8;
            }
        }

        if (dns_len < 12) return;

        UINT16 flags = ((UINT16)dns_data[2] << 8) | dns_data[3];
        UINT16 qdcount = ((UINT16)dns_data[4] << 8) | dns_data[5];
        UINT16 ancount = ((UINT16)dns_data[6] << 8) | dns_data[7];
        UINT8  rcode = dns_data[3] & 0x0F;
        BOOLEAN is_response = (flags & 0x8000) != 0;

        if (qdcount == 0 || qdcount > 16) return;

        char domain[260] = {};
        UINT32 pos = 12;


        pos = parse_dns_name(dns_data, pos, dns_len, domain, sizeof(domain));
        if (pos == 0 || pos + 4 > dns_len) return;

        UINT16 qtype = ((UINT16)dns_data[pos] << 8) | dns_data[pos + 1];
        pos += 4;

        UINT8 resolved[16] = {};
        UINT32 ttl = 0;


        if (is_response && ancount > 0 && pos < dns_len) {
            for (UINT16 i = 0; i < ancount && pos < dns_len; i++) {

                if ((dns_data[pos] & 0xC0) == 0xC0) {
                    pos += 2;
                } else {
                    while (pos < dns_len && dns_data[pos] != 0) {
                        if ((dns_data[pos] & 0xC0) == 0xC0) { pos += 2; goto after_name; }
                        if (dns_data[pos] > 63) break;
                        pos += dns_data[pos] + 1;
                    }
                    pos++;
                }
                after_name:
                if (pos + 10 > dns_len) break;

                UINT16 atype = ((UINT16)dns_data[pos] << 8) | dns_data[pos + 1];
                pos += 4;
                ttl = ((UINT32)dns_data[pos] << 24) | ((UINT32)dns_data[pos+1] << 16) |
                      ((UINT32)dns_data[pos+2] << 8) | dns_data[pos+3];
                pos += 4;
                UINT16 rdlength = ((UINT16)dns_data[pos] << 8) | dns_data[pos + 1];
                pos += 2;

                if (atype == 1 && rdlength == 4 && pos + 4 <= dns_len) {
                    strong::kmemcpy(resolved, &dns_data[pos], 4);
                    break;
                } else if (atype == 28 && rdlength == 16 && pos + 16 <= dns_len) {
                    strong::kmemcpy(resolved, &dns_data[pos], 16);
                    break;
                }
                pos += rdlength;
            }
        }

        store_dns_entry(pid, domain, qtype, rcode, resolved, ttl);
    }

    __forceinline BOOLEAN should_process_packet_pipeline() {
        if (g_capture_active) return TRUE;
        if (g_active_rule_count != 0) return TRUE;
        if (net_bw::is_active()) return TRUE;
        if (net_intercept::is_active()) return TRUE;
        if (net_dpi::is_active()) return TRUE;
        if (net_fingerprint::is_active()) return TRUE;
        if (net_mod::has_active_rules()) return TRUE;
        if (net_redirect::has_active_rules()) return TRUE;
        if (net_dns_spoof::has_active_rules()) return TRUE;
        if (net_stream::has_active_streams()) return TRUE;
        if (malware_safe::any_sandboxed()) return TRUE;
        return FALSE;
    }


    void NTAPI classify_inbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;

        classifyOut->actionType = FWP_ACTION_PERMIT_;


        if (layerData && net_inject::_FwpsQueryPacketInjectionState0) {
            if (net_inject::g_inject_handle_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
            if (net_inject::g_inject_handle_net_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_net_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
        }

        if (!inFixedValues || !inMetaValues) return;
        if (!should_process_packet_pipeline()) return;

        __try {
        UINT8* pkt_data = nullptr;
        packet_inject_request* inj_buf = nullptr;
        __try {
            UINT32 protocol = 0;
            UINT32 local_port = 0;
            UINT32 remote_port = 0;
            UINT8 local_ip[16] = {};
            UINT8 remote_ip[16] = {};
            UINT32 pid = 0;

            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_PROTOCOL) {
                protocol = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_PROTOCOL].value.uint8;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_LOCAL_PORT) {
                local_port = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_LOCAL_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_REMOTE_PORT) {
                remote_port = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_REMOTE_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_LOCAL_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_LOCAL_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, local_ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, remote_ip);
            }

            if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) != 0) {
                pid = (UINT32)inMetaValues->processId;
            }
            if (pid != 0 && inMetaValues->transportEndpointHandle != 0) {
                aida_store_cached_endpoint_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, pid);
            }
            if (pid == 0) {
                pid = aida_resolve_packet_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, remote_port);
            }
            if (pid == 0) {
                pid = aida_lookup_cached_port_pid(protocol, local_port, remote_port);
            }
            if (pid == 0 && protocol == 17) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                pid = net_udp_cache::lookup(rip, lip, (UINT16)remote_port, (UINT16)local_port);
            }
            if (pid != 0) {
                aida_store_cached_port_pid(protocol, local_port, pid);
                aida_store_cached_port_pid(protocol, remote_port, pid);
                if (protocol == 17) {
                    UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                 ((UINT32)local_ip[2] << 8) | local_ip[3];
                    UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                 ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                    net_udp_cache::store(rip, lip, (UINT16)remote_port, (UINT16)local_port, pid);
                }
            }

            _InterlockedIncrement64(&g_global_pkts_recv);

            UINT32 rule_action = check_filter_rules(0, protocol, pid, local_port, remote_port, remote_ip, 2);
            if (rule_action == 1) {
                NET_DBG("classify_inbound: BLOCKED by filter rule proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }


            BOOLEAN malsafe_log_inbound = FALSE;
            if (pid != 0 && malware_safe::any_sandboxed()) {
                HANDLE pid_handle_check = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                if (malware_safe::sandbox_has_net_logging(pid_handle_check)) {
                    malsafe_log_inbound = TRUE;
                }
            }

            {
                UINT32 data_length = get_transport_data_length(layerData);
                _InterlockedExchangeAdd64(&g_global_bytes_recv, static_cast<LONG64>(data_length));
                net_bw::record_traffic(pid, 0, data_length);

                BOOLEAN need_full_pipeline = FALSE;
                if (g_active_rule_count != 0) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_mod::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_intercept::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dpi::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_fingerprint::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dns_spoof::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_redirect::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_stream::has_active_streams()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && malsafe_log_inbound) need_full_pipeline = TRUE;
                if (!need_full_pipeline) {
                    if (!g_capture_active || (g_filter_pid != 0 && pid != g_filter_pid))
                        __leave;
                }
            }

            pkt_data = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, NET_PKT_MAX_PAYLOAD, 'pdNW');
            if (!pkt_data) __leave;
            inj_buf = (packet_inject_request*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(packet_inject_request), 'piNW');
            if (!inj_buf) __leave;

            UINT32 pkt_len = 0;
            pkt_len = copy_transport_bytes(layerData, pkt_data, NET_PKT_MAX_PAYLOAD);
            if (pkt_len == 0 && layerData) {
            }


            if (pkt_len >= 12 && protocol == 17 && remote_port == 53 &&
                net_dns_spoof::has_active_rules()) {
                UINT16 dns_flags = ((UINT16)pkt_data[2] << 8) | pkt_data[3];
                BOOLEAN is_dns_response = (dns_flags & 0x8000) != 0;
                UINT16 qdcount = ((UINT16)pkt_data[4] << 8) | pkt_data[5];
                if (is_dns_response && qdcount > 0 && qdcount <= 16) {
                    char spoof_domain[260] = {};
                    UINT32 qpos = parse_dns_name(pkt_data, 12, pkt_len, spoof_domain, sizeof(spoof_domain));
                    if (qpos != 0 && qpos + 4 <= pkt_len && spoof_domain[0] != '\0') {
                        UINT8 spoof_addr[16] = {};
                        UINT32 spoof_af = 0;
                        UINT32 spoof_ttl = 0;
                        if (net_dns_spoof::check_spoof(spoof_domain, spoof_addr, &spoof_af, &spoof_ttl)) {
                            UINT32 ans_pos = qpos + 4;
                            UINT16 ancount = ((UINT16)pkt_data[6] << 8) | pkt_data[7];
                            BOOLEAN spoofed = FALSE;
                            for (UINT16 ai = 0; ai < ancount && ans_pos < pkt_len; ai++) {
                                if ((pkt_data[ans_pos] & 0xC0) == 0xC0) {
                                    ans_pos += 2;
                                } else {
                                    while (ans_pos < pkt_len && pkt_data[ans_pos] != 0) {
                                        if ((pkt_data[ans_pos] & 0xC0) == 0xC0) { ans_pos += 2; goto spoof_after_name; }
                                        if (pkt_data[ans_pos] > 63) break;
                                        ans_pos += pkt_data[ans_pos] + 1;
                                    }
                                    ans_pos++;
                                }
                                spoof_after_name:
                                if (ans_pos + 10 > pkt_len) break;
                                UINT16 atype = ((UINT16)pkt_data[ans_pos] << 8) | pkt_data[ans_pos + 1];
                                ans_pos += 4;
                                UINT32 ttl_pos = ans_pos;
                                ans_pos += 4;
                                UINT16 rdlength = ((UINT16)pkt_data[ans_pos] << 8) | pkt_data[ans_pos + 1];
                                ans_pos += 2;
                                if (atype == 1 && rdlength == 4 && ans_pos + 4 <= pkt_len && spoof_af == 2) {
                                    pkt_data[ttl_pos] = (UINT8)(spoof_ttl >> 24);
                                    pkt_data[ttl_pos + 1] = (UINT8)(spoof_ttl >> 16);
                                    pkt_data[ttl_pos + 2] = (UINT8)(spoof_ttl >> 8);
                                    pkt_data[ttl_pos + 3] = (UINT8)(spoof_ttl);
                                    strong::kmemcpy(&pkt_data[ans_pos], spoof_addr, 4);
                                    spoofed = TRUE;
                                } else if (atype == 28 && rdlength == 16 && ans_pos + 16 <= pkt_len && spoof_af == 23) {
                                    pkt_data[ttl_pos] = (UINT8)(spoof_ttl >> 24);
                                    pkt_data[ttl_pos + 1] = (UINT8)(spoof_ttl >> 16);
                                    pkt_data[ttl_pos + 2] = (UINT8)(spoof_ttl >> 8);
                                    pkt_data[ttl_pos + 3] = (UINT8)(spoof_ttl);
                                    strong::kmemcpy(&pkt_data[ans_pos], spoof_addr, 16);
                                    spoofed = TRUE;
                                }
                                ans_pos += rdlength;
                            }
                            if (spoofed) {
                                NET_DBG("classify_inbound: DNS SPOOFED domain=%s", spoof_domain);
                                RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                                inj_buf->direction = 0;
                                inj_buf->protocol = 17;
                                inj_buf->address_family = 2;
                                inj_buf->src_port = remote_port;
                                inj_buf->dst_port = local_port;
                                strong::kmemcpy(inj_buf->src_addr, remote_ip, 4);
                                strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                                inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                                inj_buf->payload_size = pkt_len;
                                if (pkt_len <= INJECT_MAX_PAYLOAD)
                                    strong::kmemcpy(inj_buf->payload, pkt_data, pkt_len);
                                classifyOut->actionType = FWP_ACTION_BLOCK_;
                                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                                net_inject::inject_packet(inj_buf);
                                __leave;
                            }
                        }
                    }
                }
            }


            BOOLEAN needs_reinject = FALSE;

            if (protocol == 6 && pkt_len >= 20) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                needs_reinject = net_seq_delta::apply_delta(pkt_data, rip, lip, (UINT16)remote_port, (UINT16)local_port, FALSE);

                UINT8 tcp_flags = pkt_data[13];
                if (tcp_flags & 0x05) {
                    net_seq_delta::handle_fin_rst(rip, lip, (UINT16)remote_port, (UINT16)local_port);
                }
            }


            if (pkt_len > 0) {
                UINT32 orig_len = pkt_len;
                BOOLEAN was_modified = net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            0, protocol, remote_port, pid);
                if (was_modified) {
                    NET_DBG("classify_inbound: MODIFIED proto=%u pid=%u port=%u (len %u->%u)",
                            protocol, pid, remote_port, orig_len, pkt_len);
                    if (protocol == 6 && pkt_len != orig_len) {
                        UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                     ((UINT32)local_ip[2] << 8) | local_ip[3];
                        UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                     ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                        LONG32 delta = (LONG32)pkt_len - (LONG32)orig_len;
                        net_seq_delta::record_size_change(rip, lip, (UINT16)remote_port, (UINT16)local_port, FALSE, delta);
                    }
                    needs_reinject = TRUE;
                }
            }


            if (needs_reinject && pkt_len > 0) {
                if (net_inject::g_inject_handle_v4) {
                    RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                    inj_buf->direction = 0;
                    inj_buf->protocol = protocol;
                    inj_buf->address_family = 2;
                    inj_buf->src_port = remote_port;
                    inj_buf->dst_port = local_port;
                    strong::kmemcpy(inj_buf->src_addr, remote_ip, 4);
                    strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                    inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                    inj_buf->payload_size = pkt_len;
                    if (pkt_len <= INJECT_MAX_PAYLOAD)
                        strong::kmemcpy(inj_buf->payload, pkt_data, pkt_len);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    net_inject::inject_packet(inj_buf);
                } else {
                    NET_ERR("classify_inbound: packet modified/delta-adjusted but inject handle unavailable, blocking proto=%u pid=%u", protocol, pid);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    __leave;
                }
            }


            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }


            if (protocol == 6 && pkt_len >= 20) {
                UINT8 ip_ttl = 0;
                if (layerData && inMetaValues->ipHeaderSize >= 20) {
                    __try {
                        PNET_BUFFER_LIST ttl_nbl = reinterpret_cast<PNET_BUFFER_LIST>(layerData);
                        PNET_BUFFER ttl_nb = NET_BUFFER_LIST_FIRST_NB(ttl_nbl);
                        if (ttl_nb) {
                            PMDL curMdl = NET_BUFFER_CURRENT_MDL(ttl_nb);
                            ULONG curOff = NET_BUFFER_CURRENT_MDL_OFFSET(ttl_nb);
                            ULONG ipSz = inMetaValues->ipHeaderSize;
                            if (curMdl && curOff >= ipSz) {
                                PUCHAR mapped = reinterpret_cast<PUCHAR>(
                                    MmGetSystemAddressForMdlSafe(curMdl, NormalPagePriority | MdlMappingNoExecute));
                                if (mapped) {
                                    ULONG ttlOff = curOff - ipSz + 8;
                                    if (ttlOff < MmGetMdlByteCount(curMdl)) {
                                        ip_ttl = mapped[ttlOff];
                                    }
                                }
                            }
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
                if (ip_ttl == 0) ip_ttl = 128;
                net_fingerprint::analyze_tcp_syn(remote_ip, 2, pkt_data, pkt_len, ip_ttl);
            }


            {
                LARGE_INTEGER dpi_ts;
                KeQuerySystemTime(&dpi_ts);
                net_dpi::analyze_packet(dpi_ts.QuadPart, 0, protocol,
                    local_port, remote_port, local_ip, remote_ip, 2, pid,
                    pkt_data, pkt_len);
            }


            if (net_intercept::try_hold_packet(0, protocol, local_port, remote_port,
                    local_ip, remote_ip, 2, pid, pkt_data, pkt_len)) {
                NET_DBG("classify_inbound: HELD by intercept proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                __leave;
            }


            if (g_capture_active) {
                store_packet(0, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);


                if (protocol == 17) {
                    try_parse_dns(pid, pkt_data, pkt_len, local_port, remote_port);
                }
            }

            if (malsafe_log_inbound) {
                HANDLE pid_handle = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                UINT64 tcp_seq = 0;
                if (protocol == 6 && pkt_len >= 8) {
                    tcp_seq = ((UINT64)pkt_data[4] << 24) | ((UINT64)pkt_data[5] << 16) |
                              ((UINT64)pkt_data[6] << 8)  | (UINT64)pkt_data[7];
                }
                malware_safe::record_packet_for_pid(pid_handle,
                    (UINT8)0,
                    (UINT8)(protocol & 0xFFu),
                    (UINT16)(local_port & 0xFFFFu),
                    (UINT16)(remote_port & 0xFFFFu),
                    (UINT16)2,
                    local_ip, remote_ip,
                    pkt_len, tcp_seq, pkt_data);
            }
        } __finally {
            if (inj_buf) ExFreePoolWithTag(inj_buf, 'piNW');
            if (pkt_data) ExFreePoolWithTag(pkt_data, 'pdNW');
        }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    void NTAPI classify_outbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;

        classifyOut->actionType = FWP_ACTION_PERMIT_;


        if (layerData && net_inject::_FwpsQueryPacketInjectionState0) {
            if (net_inject::g_inject_handle_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
            if (net_inject::g_inject_handle_net_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_net_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
        }

        if (!inFixedValues || !inMetaValues) return;
        if (!should_process_packet_pipeline()) return;

        __try {
        UINT8* pkt_data = nullptr;
        packet_inject_request* inj_buf = nullptr;
        __try {
            UINT32 protocol = 0;
            UINT32 local_port = 0;
            UINT32 remote_port = 0;
            UINT8 local_ip[16] = {};
            UINT8 remote_ip[16] = {};
            UINT32 pid = 0;

            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_PROTOCOL) {
                protocol = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_PROTOCOL].value.uint8;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_LOCAL_PORT) {
                local_port = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_LOCAL_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_REMOTE_PORT) {
                remote_port = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_REMOTE_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_LOCAL_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_LOCAL_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, local_ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, remote_ip);
            }

            if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) != 0) {
                pid = (UINT32)inMetaValues->processId;
            }
            if (pid != 0 && inMetaValues->transportEndpointHandle != 0) {
                aida_store_cached_endpoint_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, pid);
            }
            if (pid == 0) {
                pid = aida_resolve_packet_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, remote_port);
            }
            if (pid == 0) {
                pid = aida_lookup_cached_port_pid(protocol, local_port, remote_port);
            }
            if (pid == 0 && protocol == 17) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                pid = net_udp_cache::lookup(lip, rip, (UINT16)local_port, (UINT16)remote_port);
            }
            if (pid != 0) {
                aida_store_cached_port_pid(protocol, local_port, pid);
                aida_store_cached_port_pid(protocol, remote_port, pid);
                if (protocol == 17) {
                    UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                 ((UINT32)local_ip[2] << 8) | local_ip[3];
                    UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                 ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                    net_udp_cache::store(lip, rip, (UINT16)local_port, (UINT16)remote_port, pid);
                }
            }

            _InterlockedIncrement64(&g_global_pkts_sent);

            UINT32 rule_action = check_filter_rules(1, protocol, pid, local_port, remote_port, remote_ip, 2);
            if (rule_action == 1) {
                NET_DBG("classify_outbound: BLOCKED by filter rule proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }


            BOOLEAN malsafe_log_outbound = FALSE;
            if (pid != 0 && malware_safe::any_sandboxed()) {
                HANDLE pid_handle_check = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                if (malware_safe::sandbox_has_net_logging(pid_handle_check)) {
                    malsafe_log_outbound = TRUE;
                }
            }

            {
                UINT32 data_length = get_transport_data_length(layerData);
                _InterlockedExchangeAdd64(&g_global_bytes_sent, static_cast<LONG64>(data_length));
                net_bw::record_traffic(pid, 1, data_length);

                BOOLEAN need_full_pipeline = FALSE;
                if (g_active_rule_count != 0) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_mod::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_intercept::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dpi::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_fingerprint::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dns_spoof::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_redirect::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_stream::has_active_streams()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && malsafe_log_outbound) need_full_pipeline = TRUE;
                if (!need_full_pipeline) {
                    if (!g_capture_active || (g_filter_pid != 0 && pid != g_filter_pid))
                        __leave;
                }
            }

            pkt_data = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, NET_PKT_MAX_PAYLOAD, 'pdNW');
            if (!pkt_data) __leave;
            inj_buf = (packet_inject_request*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(packet_inject_request), 'piNW');
            if (!inj_buf) __leave;

            UINT32 pkt_len = 0;
            pkt_len = copy_transport_bytes(layerData, pkt_data, NET_PKT_MAX_PAYLOAD);
            if (pkt_len == 0 && layerData) {
            }


            if (pkt_len > 0 && net_redirect::has_active_rules()) {
                UINT32 redir_port = 0;
                UINT8 redir_addr[16] = {};
                if (net_redirect::check_redirect(protocol, remote_port, remote_ip, 2, pid, &redir_port, redir_addr)) {
                    NET_DBG("classify_outbound: REDIRECTING proto=%u pid=%u port=%u -> %u.%u.%u.%u:%u",
                            protocol, pid, remote_port,
                            redir_addr[0], redir_addr[1], redir_addr[2], redir_addr[3], redir_port);
                    RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                    inj_buf->direction = 1;
                    inj_buf->protocol = protocol;
                    inj_buf->address_family = 2;
                    inj_buf->src_port = local_port;
                    inj_buf->dst_port = redir_port;
                    strong::kmemcpy(inj_buf->src_addr, local_ip, 4);
                    strong::kmemcpy(inj_buf->dst_addr, redir_addr, 4);
                    UINT32 hdr_skip = 0;
                    if (protocol == 6 && pkt_len >= 20) {
                        hdr_skip = ((UINT32)(pkt_data[12] >> 4)) * 4;
                        if (hdr_skip < 20) hdr_skip = 20;
                        if (hdr_skip > pkt_len) hdr_skip = pkt_len;
                        inj_buf->tcp_seq = ((UINT32)pkt_data[4] << 24) | ((UINT32)pkt_data[5] << 16) |
                                      ((UINT32)pkt_data[6] << 8) | pkt_data[7];
                        inj_buf->tcp_ack = ((UINT32)pkt_data[8] << 24) | ((UINT32)pkt_data[9] << 16) |
                                      ((UINT32)pkt_data[10] << 8) | pkt_data[11];
                        inj_buf->tcp_flags = pkt_data[13];
                    } else if (protocol == 17 && pkt_len >= 8) {
                        hdr_skip = 8;
                    }
                    inj_buf->payload_size = pkt_len - hdr_skip;
                    if (inj_buf->payload_size > 0)
                        strong::kmemcpy(inj_buf->payload, pkt_data + hdr_skip, inj_buf->payload_size);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    net_inject::inject_packet(inj_buf);
                    __leave;
                }
            }


            BOOLEAN needs_reinject_out = FALSE;

            if (protocol == 6 && pkt_len >= 20) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                needs_reinject_out = net_seq_delta::apply_delta(pkt_data, lip, rip, (UINT16)local_port, (UINT16)remote_port, TRUE);

                UINT8 tcp_flags = pkt_data[13];
                if (tcp_flags & 0x05) {
                    net_seq_delta::handle_fin_rst(lip, rip, (UINT16)local_port, (UINT16)remote_port);
                }
            }


            if (pkt_len > 0) {
                UINT32 orig_len = pkt_len;
                BOOLEAN was_modified = net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            1, protocol, remote_port, pid);
                if (was_modified) {
                    NET_DBG("classify_outbound: MODIFIED proto=%u pid=%u port=%u (len %u->%u)",
                            protocol, pid, remote_port, orig_len, pkt_len);
                    if (protocol == 6 && pkt_len != orig_len) {
                        UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                     ((UINT32)local_ip[2] << 8) | local_ip[3];
                        UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                     ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                        LONG32 delta = (LONG32)pkt_len - (LONG32)orig_len;
                        net_seq_delta::record_size_change(lip, rip, (UINT16)local_port, (UINT16)remote_port, TRUE, delta);
                    }
                    needs_reinject_out = TRUE;
                }
            }


            if (needs_reinject_out && pkt_len > 0) {
                if (net_inject::g_inject_handle_v4) {
                    RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                    inj_buf->direction = 1;
                    inj_buf->protocol = protocol;
                    inj_buf->address_family = 2;
                    inj_buf->src_port = local_port;
                    inj_buf->dst_port = remote_port;
                    strong::kmemcpy(inj_buf->src_addr, local_ip, 4);
                    strong::kmemcpy(inj_buf->dst_addr, remote_ip, 4);
                    inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                    inj_buf->payload_size = pkt_len;
                    if (pkt_len <= INJECT_MAX_PAYLOAD)
                        strong::kmemcpy(inj_buf->payload, pkt_data, pkt_len);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    net_inject::inject_packet(inj_buf);
                } else {
                    NET_ERR("classify_outbound: packet modified/delta-adjusted but inject handle unavailable, blocking proto=%u pid=%u", protocol, pid);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    __leave;
                }
            }


            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }

            if (protocol == 6 && pkt_len >= 20) {
                net_fingerprint::analyze_tcp_syn(local_ip, 2, pkt_data, pkt_len, 128);
            }


            {
                LARGE_INTEGER dpi_ts;
                KeQuerySystemTime(&dpi_ts);
                net_dpi::analyze_packet(dpi_ts.QuadPart, 1, protocol,
                    local_port, remote_port, local_ip, remote_ip, 2, pid,
                    pkt_data, pkt_len);
            }


            if (net_intercept::try_hold_packet(1, protocol, local_port, remote_port,
                    local_ip, remote_ip, 2, pid, pkt_data, pkt_len)) {
                NET_DBG("classify_outbound: HELD by intercept proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                __leave;
            }

            if (g_capture_active) {
                store_packet(1, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);

                if (protocol == 17) {
                    try_parse_dns(pid, pkt_data, pkt_len, local_port, remote_port);
                }
            }

            if (malsafe_log_outbound) {
                HANDLE pid_handle = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                UINT64 tcp_seq = 0;
                if (protocol == 6 && pkt_len >= 8) {
                    tcp_seq = ((UINT64)pkt_data[4] << 24) | ((UINT64)pkt_data[5] << 16) |
                              ((UINT64)pkt_data[6] << 8)  | (UINT64)pkt_data[7];
                }
                malware_safe::record_packet_for_pid(pid_handle,
                    (UINT8)1,
                    (UINT8)(protocol & 0xFFu),
                    (UINT16)(local_port & 0xFFFFu),
                    (UINT16)(remote_port & 0xFFFFu),
                    (UINT16)2,
                    local_ip, remote_ip,
                    pkt_len, tcp_seq, pkt_data);
            }
        } __finally {
            if (inj_buf) ExFreePoolWithTag(inj_buf, 'piNW');
            if (pkt_data) ExFreePoolWithTag(pkt_data, 'pdNW');
        }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }


    void NTAPI classify_ale_connect(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(layerData);
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;
        classifyOut->actionType = FWP_ACTION_PERMIT_;

        if (!inFixedValues || !inMetaValues) return;

        __try {
            UINT32 pid = 0;
            if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) {
                pid = (UINT32)inMetaValues->processId;
            }
            if (pid == 0) return;


            UINT64 endpoint_handle = 0;
            if (inMetaValues->transportEndpointHandle != 0)
                endpoint_handle = inMetaValues->transportEndpointHandle;

            if (endpoint_handle != 0) {
                aida_store_cached_endpoint_pid(endpoint_handle, 0, 0, pid);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    void NTAPI classify_ale_recv(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(layerData);
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;
        classifyOut->actionType = FWP_ACTION_PERMIT_;

        if (!inFixedValues || !inMetaValues) return;

        __try {
            UINT32 pid = 0;
            if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) {
                pid = (UINT32)inMetaValues->processId;
            }
            if (pid == 0) return;


            UINT64 endpoint_handle = 0;
            if (inMetaValues->transportEndpointHandle != 0)
                endpoint_handle = inMetaValues->transportEndpointHandle;

            if (endpoint_handle != 0) {
                aida_store_cached_endpoint_pid(endpoint_handle, 0, 0, pid);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    NTSTATUS NTAPI callout_notify(
        UINT32 notifyType, const GUID* filterKey, const void* filter)
    {
        UNREFERENCED_PARAMETER(notifyType);
        UNREFERENCED_PARAMETER(filterKey);
        UNREFERENCED_PARAMETER(filter);
        return STATUS_SUCCESS;
    }


    PVOID find_module_base(const char* module_name) {
        NET_DBG("find_module_base: looking for '%s' IRQL=%u", module_name, (UINT32)KeGetCurrentIrql());
        ULONG required = 0;
        NET_DBG("find_module_base: calling ZwQuerySystemInformation(size query)...");
        NTSTATUS status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, nullptr, 0, &required);
        NET_DBG("find_module_base: size query returned 0x%08x required=%lu", status, required);
        if (required == 0) return nullptr;

        required += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, required, 'teNW');
        if (!mods) { NET_ERR("find_module_base: alloc failed size=%lu", required); return nullptr; }

        NET_DBG("find_module_base: calling ZwQuerySystemInformation(full query size=%lu)...", required);
        status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, mods, required, nullptr);
        NET_DBG("find_module_base: full query returned 0x%08x modules=%lu", status, NT_SUCCESS(status) ? mods->NumberOfModules : 0);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(mods, 'teNW');
            return nullptr;
        }

        PVOID base = nullptr;
        for (ULONG i = 0; i < mods->NumberOfModules; i++) {
            const char* full_path = (const char*)mods->Modules[i].FullPathName;
            const char* name = full_path + mods->Modules[i].OffsetToFileName;
            if (_strcmpi_a((char*)name, (char*)module_name) == 0) {
                base = mods->Modules[i].ImageBase;
                break;
            }
        }

        ExFreePoolWithTag(mods, 'teNW');
        NET_DBG("find_module_base: '%s' => %p", module_name, base);
        return base;
    }

    BOOLEAN resolve_wfp_functions() {
        NET_DBG("resolve_wfp_functions: locating FWPKCLNT.SYS");
        PVOID fwp_base = find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) {
            NET_DBG("resolve_wfp_functions: trying lowercase fwpkclnt.sys");
            fwp_base = find_module_base("fwpkclnt.sys");
        }
        if (!fwp_base) {
            NET_ERR("resolve_wfp_functions: FWPKCLNT.SYS not found");
            return FALSE;
        }
        NET_DBG("resolve_wfp_functions: FWPKCLNT.SYS base=%p", fwp_base);

        CHAR n1[] = {'F','w','p','s','C','a','l','l','o','u','t','R','e','g','i','s','t','e','r','2',0};
        CHAR n2[] = {'F','w','p','s','C','a','l','l','o','u','t','U','n','r','e','g','i','s','t','e','r','B','y','I','d','0',0};
        CHAR n3[] = {'F','w','p','m','E','n','g','i','n','e','O','p','e','n','0',0};
        CHAR n4[] = {'F','w','p','m','E','n','g','i','n','e','C','l','o','s','e','0',0};
        CHAR n5[] = {'F','w','p','m','T','r','a','n','s','a','c','t','i','o','n','B','e','g','i','n','0',0};
        CHAR n6[] = {'F','w','p','m','T','r','a','n','s','a','c','t','i','o','n','C','o','m','m','i','t','0',0};
        CHAR n7[] = {'F','w','p','m','T','r','a','n','s','a','c','t','i','o','n','A','b','o','r','t','0',0};
        CHAR n8[] = {'F','w','p','m','C','a','l','l','o','u','t','A','d','d','0',0};
        CHAR n9[] = {'F','w','p','m','S','u','b','L','a','y','e','r','A','d','d','0',0};
        CHAR n10[] = {'F','w','p','m','F','i','l','t','e','r','A','d','d','0',0};
        CHAR n11[] = {'F','w','p','m','F','i','l','t','e','r','D','e','l','e','t','e','B','y','I','d','0',0};
        CHAR n12[] = {'F','w','p','m','C','a','l','l','o','u','t','D','e','l','e','t','e','B','y','I','d','0',0};
        CHAR n13[] = {'F','w','p','m','S','u','b','L','a','y','e','r','D','e','l','e','t','e','B','y','K','e','y','0',0};

        *(PVOID*)&_FwpsCalloutRegister2       = GetProcAddress(fwp_base, n1);
        *(PVOID*)&_FwpsCalloutUnregisterById0 = GetProcAddress(fwp_base, n2);
        *(PVOID*)&_FwpmEngineOpen0            = GetProcAddress(fwp_base, n3);
        *(PVOID*)&_FwpmEngineClose0           = GetProcAddress(fwp_base, n4);
        *(PVOID*)&_FwpmTransactionBegin0      = GetProcAddress(fwp_base, n5);
        *(PVOID*)&_FwpmTransactionCommit0     = GetProcAddress(fwp_base, n6);
        *(PVOID*)&_FwpmTransactionAbort0      = GetProcAddress(fwp_base, n7);
        *(PVOID*)&_FwpmCalloutAdd0            = GetProcAddress(fwp_base, n8);
        *(PVOID*)&_FwpmSubLayerAdd0           = GetProcAddress(fwp_base, n9);
        *(PVOID*)&_FwpmFilterAdd0             = GetProcAddress(fwp_base, n10);
        *(PVOID*)&_FwpmFilterDeleteById0      = GetProcAddress(fwp_base, n11);
        *(PVOID*)&_FwpmCalloutDeleteById0     = GetProcAddress(fwp_base, n12);
        *(PVOID*)&_FwpmSubLayerDeleteByKey0   = GetProcAddress(fwp_base, n13);

        BOOLEAN ok = (_FwpsCalloutRegister2 && _FwpsCalloutUnregisterById0 &&
                _FwpmEngineOpen0 && _FwpmEngineClose0 &&
                _FwpmTransactionBegin0 && _FwpmTransactionCommit0 &&
                _FwpmCalloutAdd0 && _FwpmSubLayerAdd0 && _FwpmFilterAdd0);
        NET_DBG("resolve_wfp_functions: Register2=%p UnregById=%p EngOpen=%p EngClose=%p",
                _FwpsCalloutRegister2, _FwpsCalloutUnregisterById0,
                _FwpmEngineOpen0, _FwpmEngineClose0);
        NET_DBG("resolve_wfp_functions: TxnBegin=%p TxnCommit=%p CalloutAdd=%p SubLayerAdd=%p FilterAdd=%p",
                _FwpmTransactionBegin0, _FwpmTransactionCommit0,
                _FwpmCalloutAdd0, _FwpmSubLayerAdd0, _FwpmFilterAdd0);
        if (!ok) {
            NET_ERR("resolve_wfp_functions: one or more critical functions not resolved");
        } else {
            NET_DBG("resolve_wfp_functions: all critical functions resolved OK");
        }
        return ok;
    }


    NTSTATUS register_wfp(PDEVICE_OBJECT devObj) {
        NET_DBG("register_wfp: devObj=%p", devObj);
        if (!devObj) {
            NET_ERR("register_wfp: devObj is NULL");
            return STATUS_INVALID_PARAMETER;
        }
        g_device_object = devObj;

        NTSTATUS status;


        status = _FwpmEngineOpen0(nullptr, 0x0000000A ,
            nullptr, nullptr, &g_engine_handle);
        NET_DBG("register_wfp: FwpmEngineOpen0 status=0x%08x handle=%p", status, g_engine_handle);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmEngineOpen0 FAILED 0x%08x", status);
            return status;
        }


        status = _FwpmTransactionBegin0(g_engine_handle, 0);
        NET_DBG("register_wfp: FwpmTransactionBegin0 status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmTransactionBegin0 FAILED 0x%08x", status);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        FWPM_DISPLAY_DATA0 sublayer_display = {};
        wchar_t sl_name[] = L"AiDANetSublayer";
        wchar_t sl_desc[] = L"AiDA Network Monitor Sublayer";
        sublayer_display.name = sl_name;
        sublayer_display.description = sl_desc;

        FWPM_SUBLAYER0_COMPAT sublayer = {};
        sublayer.subLayerKey = GUID_AIDA_SUBLAYER;
        sublayer.displayData = sublayer_display;
        sublayer.flags = 0;
        sublayer.weight = 0xFFFF;

        status = _FwpmSubLayerAdd0(g_engine_handle, &sublayer, nullptr);
        NET_DBG("register_wfp: FwpmSubLayerAdd0 status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmSubLayerAdd0 FAILED 0x%08x", status);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        FWPS_CALLOUT2_COMPAT callout_in = {};
        callout_in.calloutKey = GUID_AIDA_CALLOUT_INBOUND;
        callout_in.flags = 0;
        callout_in.classifyFn = (PVOID)classify_inbound;
        callout_in.notifyFn = (PVOID)callout_notify;
        callout_in.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_in, &g_callout_id_inbound);
        NET_DBG("register_wfp: inbound callout register status=0x%08x id=%u", status, g_callout_id_inbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: inbound callout register FAILED 0x%08x", status);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        FWPS_CALLOUT2_COMPAT callout_out = {};
        callout_out.calloutKey = GUID_AIDA_CALLOUT_OUTBOUND;
        callout_out.flags = 0;
        callout_out.classifyFn = (PVOID)classify_outbound;
        callout_out.notifyFn = (PVOID)callout_notify;
        callout_out.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_out, &g_callout_id_outbound);
        NET_DBG("register_wfp: outbound callout register status=0x%08x id=%u", status, g_callout_id_outbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: outbound callout register FAILED 0x%08x", status);
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        FWPM_DISPLAY_DATA0 callout_display = {};
        wchar_t co_name[] = L"AiDANetCallout";
        wchar_t co_desc[] = L"AiDA Network Monitor Callout";
        callout_display.name = co_name;
        callout_display.description = co_desc;

        FWPM_CALLOUT0_COMPAT fwpm_callout_in = {};
        fwpm_callout_in.calloutKey = GUID_AIDA_CALLOUT_INBOUND;
        fwpm_callout_in.displayData = callout_display;
        fwpm_callout_in.applicableLayer = GUID_LAYER_INBOUND_V4;
        UINT32 unused_id;

        status = _FwpmCalloutAdd0(g_engine_handle, &fwpm_callout_in, nullptr, &unused_id);
        if (!NT_SUCCESS(status)) {
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        FWPM_CALLOUT0_COMPAT fwpm_callout_out = {};
        fwpm_callout_out.calloutKey = GUID_AIDA_CALLOUT_OUTBOUND;
        fwpm_callout_out.displayData = callout_display;
        fwpm_callout_out.applicableLayer = GUID_LAYER_OUTBOUND_V4;

        status = _FwpmCalloutAdd0(g_engine_handle, &fwpm_callout_out, nullptr, &unused_id);
        if (!NT_SUCCESS(status)) {
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        FWPM_DISPLAY_DATA0 filter_display = {};
        wchar_t fi_name[] = L"AiDANetFilter";
        wchar_t fi_desc[] = L"AiDA Network Monitor Filter";
        filter_display.name = fi_name;
        filter_display.description = fi_desc;

        FWPM_FILTER0_COMPAT filter_in = {};
        strong::kmemset(&filter_in, 0, sizeof(filter_in));
        filter_in.displayData = filter_display;
        filter_in.layerKey = GUID_LAYER_INBOUND_V4;
        filter_in.subLayerKey = GUID_AIDA_SUBLAYER;

        filter_in.weight.type = FWP_EMPTY_;
        filter_in.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
        filter_in.action.calloutKey = GUID_AIDA_CALLOUT_INBOUND;
        filter_in.numFilterConditions = 0;
        status = _FwpmFilterAdd0(g_engine_handle, &filter_in, nullptr, &g_filter_id_inbound);
        if (!NT_SUCCESS(status)) {
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        FWPM_FILTER0_COMPAT filter_out = {};
        strong::kmemset(&filter_out, 0, sizeof(filter_out));
        filter_out.displayData = filter_display;
        filter_out.layerKey = GUID_LAYER_OUTBOUND_V4;
        filter_out.subLayerKey = GUID_AIDA_SUBLAYER;
        filter_out.weight.type = FWP_EMPTY_;
        filter_out.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
        filter_out.action.calloutKey = GUID_AIDA_CALLOUT_OUTBOUND;
        filter_out.numFilterConditions = 0;
        status = _FwpmFilterAdd0(g_engine_handle, &filter_out, nullptr, &g_filter_id_outbound);
        if (!NT_SUCCESS(status)) {
            _FwpmFilterDeleteById0(g_engine_handle, g_filter_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        FWPS_CALLOUT2_COMPAT callout_ale_conn = {};
        callout_ale_conn.calloutKey = GUID_AIDA_CALLOUT_ALE_CONNECT;
        callout_ale_conn.flags = 0;
        callout_ale_conn.classifyFn = (PVOID)classify_ale_connect;
        callout_ale_conn.notifyFn = (PVOID)callout_notify;
        callout_ale_conn.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_ale_conn, &g_callout_id_ale_connect);
        if (!NT_SUCCESS(status)) {
            g_callout_id_ale_connect = 0;
            NET_ERR("register_wfp: ALE connect callout register FAILED 0x%08x", status);
        } else {
            FWPS_CALLOUT2_COMPAT callout_ale_recv_co = {};
            callout_ale_recv_co.calloutKey = GUID_AIDA_CALLOUT_ALE_RECV;
            callout_ale_recv_co.flags = 0;
            callout_ale_recv_co.classifyFn = (PVOID)classify_ale_recv;
            callout_ale_recv_co.notifyFn = (PVOID)callout_notify;
            callout_ale_recv_co.flowDeleteFn = nullptr;

            status = _FwpsCalloutRegister2(devObj, &callout_ale_recv_co, &g_callout_id_ale_recv);
            NET_DBG("register_wfp: ALE recv callout register status=0x%08x id=%u", status, g_callout_id_ale_recv);
            if (!NT_SUCCESS(status)) {
                NET_ERR("register_wfp: ALE recv callout register FAILED 0x%08x", status);
                g_callout_id_ale_recv = 0;
            }


            if (g_callout_id_ale_connect) {
                FWPM_CALLOUT0_COMPAT fwpm_ale_conn = {};
                fwpm_ale_conn.calloutKey = GUID_AIDA_CALLOUT_ALE_CONNECT;
                fwpm_ale_conn.displayData = callout_display;
                fwpm_ale_conn.applicableLayer = GUID_LAYER_ALE_CONNECT_V4;
                _FwpmCalloutAdd0(g_engine_handle, &fwpm_ale_conn, nullptr, &unused_id);

                FWPM_FILTER0_COMPAT filter_ale_conn = {};
                strong::kmemset(&filter_ale_conn, 0, sizeof(filter_ale_conn));
                filter_ale_conn.displayData = filter_display;
                filter_ale_conn.layerKey = GUID_LAYER_ALE_CONNECT_V4;
                filter_ale_conn.subLayerKey = GUID_AIDA_SUBLAYER;
                filter_ale_conn.weight.type = FWP_EMPTY_;
                filter_ale_conn.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
                filter_ale_conn.action.calloutKey = GUID_AIDA_CALLOUT_ALE_CONNECT;
                filter_ale_conn.numFilterConditions = 0;

                status = _FwpmFilterAdd0(g_engine_handle, &filter_ale_conn, nullptr, &g_filter_id_ale_connect);
                NET_DBG("register_wfp: ALE connect filter add status=0x%08x filter_id=%llu", status, g_filter_id_ale_connect);
                if (!NT_SUCCESS(status)) {
                    NET_ERR("register_wfp: ALE connect filter add FAILED 0x%08x", status);
                    g_filter_id_ale_connect = 0;
                }
            }


            if (g_callout_id_ale_recv) {
                FWPM_CALLOUT0_COMPAT fwpm_ale_recv = {};
                fwpm_ale_recv.calloutKey = GUID_AIDA_CALLOUT_ALE_RECV;
                fwpm_ale_recv.displayData = callout_display;
                fwpm_ale_recv.applicableLayer = GUID_LAYER_ALE_RECV_V4;
                _FwpmCalloutAdd0(g_engine_handle, &fwpm_ale_recv, nullptr, &unused_id);

                FWPM_FILTER0_COMPAT filter_ale_recv = {};
                strong::kmemset(&filter_ale_recv, 0, sizeof(filter_ale_recv));
                filter_ale_recv.displayData = filter_display;
                filter_ale_recv.layerKey = GUID_LAYER_ALE_RECV_V4;
                filter_ale_recv.subLayerKey = GUID_AIDA_SUBLAYER;
                filter_ale_recv.weight.type = FWP_EMPTY_;
                filter_ale_recv.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
                filter_ale_recv.action.calloutKey = GUID_AIDA_CALLOUT_ALE_RECV;
                filter_ale_recv.numFilterConditions = 0;

                status = _FwpmFilterAdd0(g_engine_handle, &filter_ale_recv, nullptr, &g_filter_id_ale_recv);
                NET_DBG("register_wfp: ALE recv filter add status=0x%08x filter_id=%llu", status, g_filter_id_ale_recv);
                if (!NT_SUCCESS(status)) {
                    NET_ERR("register_wfp: ALE recv filter add FAILED 0x%08x", status);
                    g_filter_id_ale_recv = 0;
                }
            }

        }


        status = STATUS_SUCCESS;


        status = _FwpmTransactionCommit0(g_engine_handle);
        NET_DBG("register_wfp: FwpmTransactionCommit0 status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmTransactionCommit0 FAILED 0x%08x", status);
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        NET_DBG("register_wfp: SUCCESS — inbound_id=%u outbound_id=%u ale_conn_id=%u ale_recv_id=%u",
                g_callout_id_inbound, g_callout_id_outbound,
                g_callout_id_ale_connect, g_callout_id_ale_recv);
        return STATUS_SUCCESS;
    }

    void unregister_wfp() {
        if (g_engine_handle) {
            if (g_filter_id_ale_recv) {
                _FwpmFilterDeleteById0(g_engine_handle, g_filter_id_ale_recv);
                g_filter_id_ale_recv = 0;
            }
            if (g_filter_id_ale_connect) {
                _FwpmFilterDeleteById0(g_engine_handle, g_filter_id_ale_connect);
                g_filter_id_ale_connect = 0;
            }
            if (g_filter_id_inbound) {
                _FwpmFilterDeleteById0(g_engine_handle, g_filter_id_inbound);
                g_filter_id_inbound = 0;
            }
            if (g_filter_id_outbound) {
                _FwpmFilterDeleteById0(g_engine_handle, g_filter_id_outbound);
                g_filter_id_outbound = 0;
            }
            if (_FwpmSubLayerDeleteByKey0) {
                _FwpmSubLayerDeleteByKey0(g_engine_handle, &GUID_AIDA_SUBLAYER);
            }
            if (_FwpmCalloutDeleteById0) {
                if (g_callout_id_inbound)
                    _FwpmCalloutDeleteById0(g_engine_handle, g_callout_id_inbound);
                if (g_callout_id_outbound)
                    _FwpmCalloutDeleteById0(g_engine_handle, g_callout_id_outbound);
                if (g_callout_id_ale_connect)
                    _FwpmCalloutDeleteById0(g_engine_handle, g_callout_id_ale_connect);
                if (g_callout_id_ale_recv)
                    _FwpmCalloutDeleteById0(g_engine_handle, g_callout_id_ale_recv);
            }
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
        }
        if (g_callout_id_ale_recv) {
            _FwpsCalloutUnregisterById0(g_callout_id_ale_recv);
            g_callout_id_ale_recv = 0;
        }
        if (g_callout_id_ale_connect) {
            _FwpsCalloutUnregisterById0(g_callout_id_ale_connect);
            g_callout_id_ale_connect = 0;
        }
        if (g_callout_id_inbound) {
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            g_callout_id_inbound = 0;
        }
        if (g_callout_id_outbound) {
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            g_callout_id_outbound = 0;
        }
    }


    NTSTATUS initialize(PDEVICE_OBJECT devObj) {
        NET_DBG("initialize: starting WFP init, devObj=%p", devObj);
        LONG prev = _InterlockedCompareExchange(&g_wfp_initialized, 1, 0);
        if (prev == 2) {
            NET_DBG("initialize: already initialized (state=2)");
            return STATUS_SUCCESS;
        }
        if (prev == 1) {
            NET_DBG("initialize: concurrent init detected, waiting...");
            for (UINT32 spin = 0; spin < 10000000u; spin++) {
                if (_InterlockedCompareExchange(&g_wfp_initialized, 0, 0) != 1)
                    break;
                YieldProcessor();
            }
            return (g_wfp_initialized == 2) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = STATUS_SUCCESS;


        KeInitializeSpinLock(&g_ring_lock);
        KeInitializeSpinLock(&g_dns_lock);
        KeInitializeSpinLock(&g_seq_delta_lock);
        KeInitializeSpinLock(&g_udp_flow_lock);
        KeInitializeSpinLock(&g_pid_path_lock);
        KeInitializeSpinLock(&net_fingerprint::g_fp_lock);


        SIZE_T ring_size = (SIZE_T)RING_BUFFER_SIZE * sizeof(NET_PACKET_ENTRY);
        g_ring_buffer = (NET_PACKET_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, ring_size, 'pkNW');
        if (!g_ring_buffer) {
            NET_ERR("initialize: packet ring alloc FAILED (size=%llu)", (ULONGLONG)ring_size);
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NET_DBG("initialize: packet ring allocated at %p (size=%llu, entries=%u)",
                g_ring_buffer, (ULONGLONG)ring_size, RING_BUFFER_SIZE);
        strong::kmemset(g_ring_buffer, 0, ring_size);

        SIZE_T dns_size = (SIZE_T)DNS_RING_SIZE * sizeof(NET_DNS_ENTRY);
        g_dns_ring = (NET_DNS_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, dns_size, 'dnNW');
        if (!g_dns_ring) {
            NET_ERR("initialize: DNS ring alloc FAILED (size=%llu)", (ULONGLONG)dns_size);
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NET_DBG("initialize: DNS ring allocated at %p (size=%llu, entries=%u)",
                g_dns_ring, (ULONGLONG)dns_size, DNS_RING_SIZE);
        strong::kmemset(g_dns_ring, 0, dns_size);

        net_intercept::init_lock();

        status = net_dpi::init();
        NET_DBG("initialize: net_dpi::init status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("initialize: DPI init FAILED 0x%08x", status);
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
            _InterlockedExchange(&g_wfp_initialized, 0);
            return status;
        }


        if (!resolve_wfp_functions()) {
            NET_ERR("initialize: resolve_wfp_functions FAILED");
            net_dpi::cleanup();
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_NOT_SUPPORTED;
        }

        if (!net_inject::prepare_injection_runtime()) {
            NET_ERR("initialize: injection runtime prewarm FAILED; reinjection-only features will report not-supported instead of resolving inside WFP callouts");
        }


        status = register_wfp(devObj);
        NET_DBG("initialize: register_wfp status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("initialize: register_wfp FAILED 0x%08x", status);
            net_dpi::cleanup();
            if (g_ring_buffer) {
                ExFreePoolWithTag(g_ring_buffer, 'pkNW');
                g_ring_buffer = nullptr;
            }
            if (g_dns_ring) {
                ExFreePoolWithTag(g_dns_ring, 'dnNW');
                g_dns_ring = nullptr;
            }
            _InterlockedExchange(&g_wfp_initialized, 0);
            return status;
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_wfp_initialized, 2);
        NET_DBG("initialize: WFP fully initialized (state=2)");


        NET_DBG("initialize: pre-resolving AFD offsets");
        afd_init_offsets();
        NET_DBG("initialize: AFD offsets resolved");

        return STATUS_SUCCESS;
    }

    void cleanup() {
        _InterlockedExchange(&g_capture_active, 0);
        g_filter_pid = 0;
        g_filter_port = 0;
        g_filter_protocol = 0;
        strong::kmemset(g_filter_ip, 0, sizeof(g_filter_ip));
        for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
            _InterlockedExchange(&g_filter_rules[i].active, 0);
        }
        _InterlockedExchange(&g_active_rule_count, 0);
        unregister_wfp();
        net_inject::cleanup();
        net_stream::cleanup();
        net_dpi::cleanup();
        net_intercept::cleanup();
        net_dns_spoof::cleanup();
        net_fingerprint::cleanup();
        net_bw::cleanup();

        if (g_ring_buffer) {
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
        }
        if (g_dns_ring) {
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
        }

        _InterlockedExchange(&g_wfp_initialized, 0);
    }

}


typedef struct _AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _AIDA_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} AIDA_SYSTEM_HANDLE_INFORMATION, *PAIDA_SYSTEM_HANDLE_INFORMATION;

static NTSTATUS aida_query_system_handles(PAIDA_SYSTEM_HANDLE_INFORMATION* out_info) {
    if (!out_info) return STATUS_INVALID_PARAMETER;
    *out_info = nullptr;

    if (!aida_can_query_system_handles()) {
        NET_ERR("query_handles: blocked - not at PASSIVE_LEVEL");
        return STATUS_INVALID_DEVICE_STATE;
    }

    constexpr SYSTEM_INFORMATION_CLASS_INTERNAL system_handle_information_class =
        (SYSTEM_INFORMATION_CLASS_INTERNAL)16;

    NET_DBG("query_handles: ENTER initial_size=4MB");
    ULONG size = 0x400000;
    for (UINT32 attempt = 0; attempt < 4; attempt++) {
        NET_DBG("query_handles: attempt %u alloc_size=%lu", attempt, size);
        PAIDA_SYSTEM_HANDLE_INFORMATION info = (PAIDA_SYSTEM_HANDLE_INFORMATION)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'hANW');
        if (!info) {
            NET_ERR("query_handles: alloc FAILED size=%lu", size);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG required = 0;
        NET_DBG("query_handles: calling ZwQuerySystemInformation...");
        NTSTATUS status = ZwQuerySystemInformation(system_handle_information_class, info, size, &required);
        NET_DBG("query_handles: ZwQuery returned 0x%08x required=%lu", status, required);
        if (NT_SUCCESS(status)) {
            NET_DBG("query_handles: SUCCESS handle_count=%lu", info->NumberOfHandles);
            *out_info = info;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(info, 'hANW');
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
            NET_ERR("query_handles: unexpected status 0x%08x", status);
            return status;
        }

        size = (required > size) ? (required + 0x4000) : (size << 1);
    }

    NET_ERR("query_handles: exhausted 4 attempts");
    return STATUS_INSUFFICIENT_RESOURCES;
}


static BOOLEAN aida_is_afd_file_object(PFILE_OBJECT fileObj) {
    if (!fileObj)
        return FALSE;

    BOOLEAN is_afd = FALSE;

    __try {

        PDEVICE_OBJECT devObj = fileObj->DeviceObject;
        if (!devObj)
            __leave;

        PDRIVER_OBJECT drvObj = devObj->DriverObject;
        if (!drvObj)
            __leave;

        PUNICODE_STRING drvName = &drvObj->DriverName;


        if (!drvName->Buffer || drvName->Length < 8)
            __leave;

        USHORT max_chars = (USHORT)(drvName->Length / sizeof(wchar_t));
        if (max_chars > 128) {
            max_chars = 128;
        }


        wchar_t* buf = drvName->Buffer;
        for (USHORT i = 0; i + 2 < max_chars; i++) {
            wchar_t c0 = buf[i];
            wchar_t c1 = buf[i + 1];
            wchar_t c2 = buf[i + 2];
            if (c0 >= 'a' && c0 <= 'z') c0 -= 32;
            if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
            if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
            if (c0 == 'A' && c1 == 'F' && c2 == 'D') {
                is_afd = TRUE;
                break;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        is_afd = FALSE;
    }

    return is_afd;
}

static BOOLEAN aida_ip_bytes_equal(const UINT8* left, const UINT8* right, UINT32 len) {
    if (!left || !right) return FALSE;
    for (UINT32 i = 0; i < len; i++) {
        if (left[i] != right[i]) {
            return FALSE;
        }
    }
    return TRUE;
}


struct afd_endpoint_offsets_t {
    ULONG transport_info;
    ULONG local_addr_size;
    ULONG local_addr_ptr;
};


static const afd_endpoint_offsets_t g_afd_fallback_win10 = { 0xF8,  0xDC,  0xE0  };
static const afd_endpoint_offsets_t g_afd_fallback_win11 = { 0x108, 0xEC,  0xF0  };

static afd_endpoint_offsets_t g_afd_offsets = {};
static volatile LONG g_afd_offsets_state = 0;


static BOOLEAN afd_resolve_offsets_by_scan() {
    NET_DBG("afd_resolve: ENTER");
    PVOID afd_base = net_capture::find_module_base("afd.sys");
    NET_DBG("afd_resolve: find_module_base('afd.sys') => %p", afd_base);
    if (!afd_base) afd_base = net_capture::find_module_base("afd.SYS");
    if (!afd_base) {
        NET_ERR("afd_resolve: afd.sys not found in module list");
        return FALSE;
    }

    NET_DBG("afd_resolve: afd_base=%p, starting pattern scan", afd_base);


    static const UCHAR pat_w11_a[] = {
        0x48, 0x89, 0x97, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00
    };
    static const UCHAR pat_w11_b[] = {
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x97, 0x00, 0x00, 0x00, 0x00
    };

    static const UCHAR pat_w10_a[] = {
        0x4C, 0x89, 0xBF, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00
    };
    static const UCHAR pat_w10_b[] = {
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00,
        0x4C, 0x89, 0xBF, 0x00, 0x00, 0x00, 0x00
    };
    static const char mask_a[] = "xxx??xxxxx??xx";
    static const char mask_b[] = "xxx??xxxxx??xx";

    ULONG local_addr_size = 0;
    ULONG local_addr_ptr  = 0;
    PVOID match = nullptr;
    BOOLEAN reversed = FALSE;


    BOOLEAN is_win11 = stealth::IsWindows11();

    if (is_win11) {
        NET_DBG("afd_resolve: Win11 detected, scanning Win11 patterns first...");
        match = stealth::FindPatternInAllSections(afd_base, pat_w11_a, mask_a);
        NET_DBG("afd_resolve: Win11 pattern A result=%p", match);
        if (!match) {
            match = stealth::FindPatternInAllSections(afd_base, pat_w11_b, mask_b);
            NET_DBG("afd_resolve: Win11 pattern B result=%p", match);
            reversed = (match != nullptr);
        }
    }

    if (!match) {
        NET_DBG("afd_resolve: scanning Win10 patterns...");
        match = stealth::FindPatternInAllSections(afd_base, pat_w10_a, mask_a);
        NET_DBG("afd_resolve: Win10 pattern A result=%p", match);
        if (!match) {
            match = stealth::FindPatternInAllSections(afd_base, pat_w10_b, mask_b);
            NET_DBG("afd_resolve: Win10 pattern B result=%p", match);
            reversed = (match != nullptr);
        }
    }

    if (!match && !is_win11) {
        NET_DBG("afd_resolve: scanning Win11 patterns as fallback...");
        match = stealth::FindPatternInAllSections(afd_base, pat_w11_a, mask_a);
        NET_DBG("afd_resolve: Win11 pattern A fallback result=%p", match);
        if (!match) {
            match = stealth::FindPatternInAllSections(afd_base, pat_w11_b, mask_b);
            NET_DBG("afd_resolve: Win11 pattern B fallback result=%p", match);
            reversed = (match != nullptr);
        }
    }

    if (match) {
        UCHAR* p = static_cast<UCHAR*>(match);
        if (reversed) {
            local_addr_size = *reinterpret_cast<ULONG*>(p + 3);
            local_addr_ptr  = *reinterpret_cast<ULONG*>(p + 10);
        } else {
            local_addr_ptr  = *reinterpret_cast<ULONG*>(p + 3);
            local_addr_size = *reinterpret_cast<ULONG*>(p + 10);
        }
    }

    if (!match) {
        NET_ERR("afd_resolve: no pattern match in afd.sys");
        return FALSE;
    }

    if (local_addr_ptr != local_addr_size + 4) {
        NET_ERR("afd_resolve: validation failed size=0x%X ptr=0x%X (expected delta=4)",
                local_addr_size, local_addr_ptr);
        return FALSE;
    }

    if (local_addr_size < 0x80 || local_addr_size > 0x400) {
        NET_ERR("afd_resolve: local_addr_size 0x%X out of expected range", local_addr_size);
        return FALSE;
    }

    ULONG transport_info = local_addr_size + 0x1C;

    g_afd_offsets.transport_info  = transport_info;
    g_afd_offsets.local_addr_size = local_addr_size;
    g_afd_offsets.local_addr_ptr  = local_addr_ptr;

    NET_DBG("afd_resolve: SCAN OK transport=+0x%X size=+0x%X ptr=+0x%X (match=%p)",
            transport_info, local_addr_size, local_addr_ptr, match);
    return TRUE;
}

static void afd_init_offsets() {
    NET_DBG("afd_init_offsets: ENTER state=%ld", g_afd_offsets_state);
    LONG prev = _InterlockedCompareExchange(&g_afd_offsets_state, 1, 0);
    if (prev == 2) { NET_DBG("afd_init_offsets: already done"); return; }
    if (prev == 1) {
        NET_DBG("afd_init_offsets: another thread initializing, waiting...");
        volatile UINT32 spin = 0;
        while (g_afd_offsets_state != 2 && spin < 100000) { YieldProcessor(); spin++; }
        if (g_afd_offsets_state != 2) {
            NET_ERR("afd_init_offsets: SPIN TIMEOUT after 100K iterations, state=%ld", g_afd_offsets_state);
        } else {
            NET_DBG("afd_init_offsets: wait done after %u spins", spin);
        }
        return;
    }

    if (!afd_resolve_offsets_by_scan()) {
        if (stealth::IsWindows11_24H2OrNewer()) {
            g_afd_offsets = g_afd_fallback_win11;
            NET_DBG("afd_init: fallback to Win11 offsets (build >= 26100)");
        } else {
            g_afd_offsets = g_afd_fallback_win10;
            NET_DBG("afd_init: fallback to Win10 offsets (build < 26100)");
        }
    }

    _InterlockedExchange(&g_afd_offsets_state, 2);
}

static __forceinline const afd_endpoint_offsets_t& afd_get_offsets() {
    if (g_afd_offsets_state != 2) afd_init_offsets();
    return g_afd_offsets;
}

static BOOLEAN aida_parse_transport_address(const UINT8* ta_buf, UINT32 ta_size,
                                            UINT32* out_af, UINT32* out_port, UINT8* out_addr) {
    if (!ta_buf || !out_af || !out_port || !out_addr) return FALSE;
    if (ta_size < 4) return FALSE;

    if (!_MmIsAddressValid((PVOID)ta_buf) || !_MmIsAddressValid((PVOID)(ta_buf + 3)))
        return FALSE;

    strong::kmemset(out_addr, 0, 16);


    USHORT sa_family = *(const USHORT*)(ta_buf + 0);

    if (sa_family == AF_INET && ta_size >= 8 && ta_size <= 16) {
        if (!_MmIsAddressValid((PVOID)(ta_buf + 7)))
            return FALSE;
        USHORT port_be = *(const USHORT*)(ta_buf + 2);
        UINT32 port_he = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);
        if (ta_size >= 8 && _MmIsAddressValid((PVOID)(ta_buf + 7)))
            strong::kmemcpy(out_addr, ta_buf + 4, 4);
        *out_af = AF_INET;
        *out_port = port_he;
        return TRUE;
    }

    if (sa_family == AF_INET6 && ta_size >= 8 && ta_size <= 28) {
        if (!_MmIsAddressValid((PVOID)(ta_buf + 7)))
            return FALSE;
        USHORT port_be = *(const USHORT*)(ta_buf + 2);
        UINT32 port_he = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);
        if (ta_size >= 24 && _MmIsAddressValid((PVOID)(ta_buf + 23)))
            strong::kmemcpy(out_addr, ta_buf + 8, 16);
        *out_af = AF_INET6;
        *out_port = port_he;
        return TRUE;
    }


    if (ta_size < 10 || !_MmIsAddressValid((PVOID)(ta_buf + 9)))
        return FALSE;

    LONG addr_count = *(const LONG*)(ta_buf + 0);
    if (addr_count < 1) return FALSE;

    USHORT addr_type = *(const USHORT*)(ta_buf + 6);
    USHORT port_be   = *(const USHORT*)(ta_buf + 8);
    UINT32 port_he   = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);

    if (addr_type == AF_INET) {
        if (ta_size < 14 || !_MmIsAddressValid((PVOID)(ta_buf + 13)))
            return FALSE;
        strong::kmemcpy(out_addr, ta_buf + 10, 4);
        *out_af = AF_INET;
        *out_port = port_he;
        return TRUE;
    }

    if (addr_type == AF_INET6) {
        if (ta_size < 30 || !_MmIsAddressValid((PVOID)(ta_buf + 29)))
            return FALSE;
        strong::kmemcpy(out_addr, ta_buf + 14, 16);
        *out_af = AF_INET6;
        *out_port = port_he;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN aida_extract_socket_info_from_fo(PFILE_OBJECT fo, SOCKET_HANDLE_ENTRY* out) {
    if (!fo || !out) return FALSE;

    BOOLEAN result = FALSE;

    __try {

        PVOID afd_endpoint = fo->FsContext;
        if (!afd_endpoint || !_MmIsAddressValid(afd_endpoint)) {
            result = FALSE;
            __leave;
        }

        out->afd_endpoint_addr = (UINT64)afd_endpoint;
        UINT8* ep = (UINT8*)afd_endpoint;

        out->address_family = 0;
        out->protocol = 0;
        out->state = 0;
        out->local_port = 0;
        out->remote_port = 0;
        strong::kmemset(out->local_addr, 0, 16);
        strong::kmemset(out->remote_addr, 0, 16);

        const auto& offsets = afd_get_offsets();


        if (_MmIsAddressValid(ep + offsets.transport_info + sizeof(PVOID) - 1)) {
            UINT8* transport_info = *(UINT8**)(ep + offsets.transport_info);
            NET_DBG("socket_extract: ep=0x%llx ti_offset=0x%x ti_ptr=0x%llx",
                    (UINT64)ep, offsets.transport_info, (UINT64)transport_info);
            if (transport_info && _MmIsAddressValid(transport_info) &&
                _MmIsAddressValid(transport_info + 0x1D)) {
                UINT16 raw_af = *(UINT16*)(transport_info + 0x16);
                if (raw_af == 0 && _MmIsAddressValid(transport_info + 0x17)) {
                    DWORD dw_af = *(DWORD*)(transport_info + 0x14);
                    if (dw_af == AF_INET || dw_af == AF_INET6)
                        raw_af = static_cast<UINT16>(dw_af);
                }
                DWORD raw_proto = *(DWORD*)(transport_info + 0x18);
                NET_DBG("socket_extract: ti raw af=%u proto=%u (at ti+0x16, ti+0x18)",
                        raw_af, raw_proto);
                out->address_family = raw_af;
                out->protocol = (raw_proto <= 256) ? raw_proto : 0;
            }
        }


        if (_MmIsAddressValid(ep + 0x02)) {
            UINT8 afd_state = *(ep + 0x02);
            switch (afd_state) {
                case 2: out->state = 5; break;
                case 3: out->state = 2; break;
                case 4: out->state = 2; break;
                default: out->state = 0; break;
            }
        }


        if (_MmIsAddressValid(ep + offsets.local_addr_size + 3) && _MmIsAddressValid(ep + offsets.local_addr_ptr + sizeof(PVOID) - 1)) {
            UINT32 ta_size = *(UINT32*)(ep + offsets.local_addr_size);
            UINT8* ta_ptr  = *(UINT8**)(ep + offsets.local_addr_ptr);
            NET_DBG("socket_extract: la_size_off=0x%x la_ptr_off=0x%x ta_size=%u ta_ptr=0x%llx",
                    offsets.local_addr_size, offsets.local_addr_ptr, ta_size, (UINT64)ta_ptr);
            if (ta_ptr && ta_size >= 10 && ta_size <= 256 && _MmIsAddressValid(ta_ptr)) {
                UINT32 local_af = 0, local_port = 0;
                UINT8 local_addr[16] = {};
                if (aida_parse_transport_address(ta_ptr, ta_size, &local_af, &local_port, local_addr)) {
                    out->local_port = local_port;
                    strong::kmemcpy(out->local_addr, local_addr, (local_af == AF_INET6) ? 16u : 4u);
                    if (out->address_family == 0) {
                        out->address_family = local_af;
                    }
                }
            }
        }

        result = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }

    if (result) {
        static volatile LONG s_dbg_count = 0;
        LONG cnt = _InterlockedIncrement(&s_dbg_count);
        if (cnt <= 5) {
            NET_DBG("socket_info[%ld]: af=%u proto=%u state=%u lport=%u rport=%u ep=0x%llx",
                    cnt, out->address_family, out->protocol, out->state,
                    out->local_port, out->remote_port, out->afd_endpoint_addr);
            NET_DBG("socket_info[%ld]: local=%u.%u.%u.%u remote=%u.%u.%u.%u",
                    cnt,
                    out->local_addr[0], out->local_addr[1], out->local_addr[2], out->local_addr[3],
                    out->remote_addr[0], out->remote_addr[1], out->remote_addr[2], out->remote_addr[3]);
        }
    }

    return result;
}


typedef struct _AIDA_ENDPOINT_PID_CACHE_ENTRY {
    volatile LONG active;
    UINT64 endpoint_handle;
    UINT32 pid;
    UINT32 protocol;
    UINT32 local_port;
} AIDA_ENDPOINT_PID_CACHE_ENTRY;

typedef struct _AIDA_PORT_PID_CACHE_ENTRY {
    volatile LONG active;
    UINT32 protocol;
    UINT32 port;
    UINT32 pid;
} AIDA_PORT_PID_CACHE_ENTRY;

inline AIDA_ENDPOINT_PID_CACHE_ENTRY g_endpoint_pid_cache[AIDA_ENDPOINT_PID_CACHE_SIZE] = {};
inline AIDA_PORT_PID_CACHE_ENTRY g_port_pid_cache[AIDA_ENDPOINT_PID_CACHE_SIZE] = {};
inline KSPIN_LOCK g_endpoint_pid_cache_lock;
inline volatile LONG g_endpoint_pid_cache_lock_state = 0;
inline volatile LONG g_handle_query_irql_warned = 0;

static VOID aida_ensure_endpoint_pid_cache_init() {
    LONG state = _InterlockedCompareExchange(&g_endpoint_pid_cache_lock_state, 1, 0);
    if (state == 0) {
        KeInitializeSpinLock(&g_endpoint_pid_cache_lock);
        KeMemoryBarrier();
        _InterlockedExchange(&g_endpoint_pid_cache_lock_state, 2);
        return;
    }

    for (UINT32 spin = 0; spin < 100000; spin++) {
        if (_InterlockedCompareExchange(&g_endpoint_pid_cache_lock_state, 2, 2) == 2)
            return;
        YieldProcessor();
    }
}

static UINT32 aida_lookup_cached_endpoint_pid(UINT64 endpoint_handle,
                                              UINT32 protocol,
                                              UINT32 local_port) {
    UNREFERENCED_PARAMETER(protocol);
    UNREFERENCED_PARAMETER(local_port);
    if (endpoint_handle == 0) return 0;

    aida_ensure_endpoint_pid_cache_init();


    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    for (UINT32 i = 0; i < AIDA_ENDPOINT_PID_CACHE_SIZE; i++) {
        const AIDA_ENDPOINT_PID_CACHE_ENTRY* entry = &g_endpoint_pid_cache[i];
        if (!entry->active) continue;
        if (entry->endpoint_handle != endpoint_handle) continue;

        UINT32 pid = entry->pid;
        KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
        return pid;
    }
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
    return 0;
}

static VOID aida_store_cached_endpoint_pid(UINT64 endpoint_handle,
                                           UINT32 protocol,
                                           UINT32 local_port,
                                           UINT32 pid) {
    if (endpoint_handle == 0 || pid == 0) return;

    aida_ensure_endpoint_pid_cache_init();

    UINT32 slot = (UINT32)(endpoint_handle % AIDA_ENDPOINT_PID_CACHE_SIZE);

    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    UINT32 target = slot;
    UINT32 empty_slot = AIDA_ENDPOINT_PID_CACHE_SIZE;
    for (UINT32 probe = 0; probe < 4; probe++) {
        UINT32 idx = (slot + probe) % AIDA_ENDPOINT_PID_CACHE_SIZE;
        if (!g_endpoint_pid_cache[idx].active) {
            if (empty_slot == AIDA_ENDPOINT_PID_CACHE_SIZE) empty_slot = idx;
            continue;
        }
        if (g_endpoint_pid_cache[idx].endpoint_handle == endpoint_handle) {
            target = idx;
            goto store_endpoint;
        }
    }
    target = (empty_slot != AIDA_ENDPOINT_PID_CACHE_SIZE) ? empty_slot : slot;
store_endpoint:
    g_endpoint_pid_cache[target].endpoint_handle = endpoint_handle;
    g_endpoint_pid_cache[target].protocol = protocol;
    g_endpoint_pid_cache[target].local_port = local_port;
    g_endpoint_pid_cache[target].pid = pid;
    KeMemoryBarrier();
    _InterlockedExchange(&g_endpoint_pid_cache[target].active, 1);
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
}

static VOID aida_store_cached_port_pid(UINT32 protocol,
                                       UINT32 port,
                                       UINT32 pid) {
    if (port == 0 || pid == 0) return;

    aida_ensure_endpoint_pid_cache_init();

    UINT32 slot = ((protocol * 131u) ^ port) % AIDA_ENDPOINT_PID_CACHE_SIZE;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    UINT32 target = slot;
    UINT32 empty_slot = AIDA_ENDPOINT_PID_CACHE_SIZE;
    for (UINT32 probe = 0; probe < 4; probe++) {
        UINT32 idx = (slot + probe) % AIDA_ENDPOINT_PID_CACHE_SIZE;
        if (!g_port_pid_cache[idx].active) {
            if (empty_slot == AIDA_ENDPOINT_PID_CACHE_SIZE) empty_slot = idx;
            continue;
        }
        if (g_port_pid_cache[idx].protocol == protocol && g_port_pid_cache[idx].port == port) {
            target = idx;
            goto store_port;
        }
    }
    target = (empty_slot != AIDA_ENDPOINT_PID_CACHE_SIZE) ? empty_slot : slot;
store_port:
    g_port_pid_cache[target].protocol = protocol;
    g_port_pid_cache[target].port = port;
    g_port_pid_cache[target].pid = pid;
    KeMemoryBarrier();
    _InterlockedExchange(&g_port_pid_cache[target].active, 1);
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
}

static UINT32 aida_lookup_cached_port_pid(UINT32 protocol,
                                          UINT32 local_port,
                                          UINT32 remote_port) {
    if (local_port == 0 && remote_port == 0)
        return 0;

    aida_ensure_endpoint_pid_cache_init();

    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    for (UINT32 i = 0; i < AIDA_ENDPOINT_PID_CACHE_SIZE; i++) {
        const AIDA_PORT_PID_CACHE_ENTRY* entry = &g_port_pid_cache[i];
        if (!entry->active) continue;
        if (entry->pid == 0) continue;
        if (entry->protocol != 0 && protocol != 0 && entry->protocol != protocol)
            continue;
        if (entry->port != local_port && entry->port != remote_port)
            continue;

        UINT32 pid = entry->pid;
        KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
        return pid;
    }
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
    return 0;
}

static VOID aida_cache_pid_from_socket_info(const SOCKET_HANDLE_ENTRY* socket_info,
                                            UINT32 pid) {
    if (!socket_info || pid == 0)
        return;

    if (socket_info->afd_endpoint_addr != 0) {
        aida_store_cached_endpoint_pid(socket_info->afd_endpoint_addr,
            socket_info->protocol,
            socket_info->local_port,
            pid);
    }

    aida_store_cached_port_pid(socket_info->protocol, socket_info->local_port, pid);
    aida_store_cached_port_pid(socket_info->protocol, socket_info->remote_port, pid);
}


static NTSTATUS aida_refresh_pid_cache_for_process(UINT32 target_pid,
                                                   UINT32 protocol_filter) {
    if (target_pid == 0)
        return STATUS_INVALID_PARAMETER;

    if (!aida_can_query_system_handles())
        return STATUS_INVALID_DEVICE_STATE;

    PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
    NTSTATUS status = aida_query_system_handles(&handles);
    if (!NT_SUCCESS(status) || !handles)
        return status;


    constexpr UINT32 MAX_PID_HANDLES = 1024;
    USHORT* pid_handles = static_cast<USHORT*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_PID_HANDLES * sizeof(USHORT), 'pcNW'));
    if (!pid_handles) {
        ExFreePoolWithTag(handles, 'hANW');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT32 pid_handle_count = 0;
    for (ULONG i = 0; i < handles->NumberOfHandles && pid_handle_count < MAX_PID_HANDLES; i++) {
        if (static_cast<UINT32>(handles->Handles[i].UniqueProcessId) == target_pid) {
            pid_handles[pid_handle_count++] = handles->Handles[i].HandleValue;
        }
    }
    ExFreePoolWithTag(handles, 'hANW');
    handles = nullptr;

    if (pid_handle_count == 0) {
        ExFreePoolWithTag(pid_handles, 'pcNW');
        return STATUS_NOT_FOUND;
    }


    PEPROCESS process = nullptr;
    status = PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &process);
    if (!NT_SUCCESS(status) || !process) {
        ExFreePoolWithTag(pid_handles, 'pcNW');
        return status;
    }


    (void)afd_get_offsets();

    UINT32 cached = 0;
    KAPC_STATE apc_state = {};
    KeStackAttachProcess(process, &apc_state);

    __try {
        for (UINT32 i = 0; i < pid_handle_count; i++) {
            HANDLE h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid_handles[i]));

            PVOID file_obj = nullptr;
            NTSTATUS ref_st = ObReferenceObjectByHandle(
                h, 0,
                (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr,
                KernelMode, &file_obj, nullptr);
            if (!NT_SUCCESS(ref_st) || !file_obj)
                continue;

            PFILE_OBJECT fo = static_cast<PFILE_OBJECT>(file_obj);
            if (!aida_is_afd_file_object(fo)) {
                ObDereferenceObject(fo);
                continue;
            }

            SOCKET_HANDLE_ENTRY socket_info = {};
            BOOLEAN ok = aida_extract_socket_info_from_fo(fo, &socket_info);
            ObDereferenceObject(fo);
            if (!ok)
                continue;

            if (protocol_filter != 0 && socket_info.protocol != 0 &&
                socket_info.protocol != protocol_filter)
                continue;

            aida_cache_pid_from_socket_info(&socket_info, target_pid);
            cached++;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(process);
    ExFreePoolWithTag(pid_handles, 'pcNW');

    if (!NT_SUCCESS(status))
        return status;
    return (cached != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


static volatile LONG64 g_last_handle_enum_tsc = 0;


static constexpr ULONG HANDLE_ENUM_MAX_ITER = 50000;


static constexpr LONG64 HANDLE_ENUM_COOLDOWN_TSC = 500000000LL;

static __forceinline BOOLEAN aida_can_query_system_handles() {
    KIRQL irql = KeGetCurrentIrql();
    if (irql == PASSIVE_LEVEL)
        return TRUE;

    if (_InterlockedCompareExchange(&g_handle_query_irql_warned, 1, 0) == 0) {
        NET_ERR("aida_can_query_system_handles: blocked at IRQL=%u (need PASSIVE_LEVEL), future warnings suppressed", (UINT32)irql);
    }
    return FALSE;
}


namespace net_enum {


    #define TCP_STATE_CLOSED       0
    #define TCP_STATE_LISTEN       1
    #define TCP_STATE_SYN_SENT     2
    #define TCP_STATE_SYN_RCVD     3
    #define TCP_STATE_ESTABLISHED  4
    #define TCP_STATE_FIN_WAIT1    5
    #define TCP_STATE_FIN_WAIT2    6
    #define TCP_STATE_CLOSE_WAIT   7
    #define TCP_STATE_CLOSING      8
    #define TCP_STATE_LAST_ACK     9
    #define TCP_STATE_TIME_WAIT    10
    #define TCP_STATE_DELETE_TCB   11


    typedef struct _MIB_TCPROW2 {
        UINT32 dwState;
        UINT32 dwLocalAddr;
        UINT32 dwLocalPort;
        UINT32 dwRemoteAddr;
        UINT32 dwRemotePort;
        UINT32 dwOwningPid;
        UINT32 dwOffloadState;
    } MIB_TCPROW2;

    typedef struct _MIB_UDPROW_OWNER_PID {
        UINT32 dwLocalAddr;
        UINT32 dwLocalPort;
        UINT32 dwOwningPid;
    } MIB_UDPROW_OWNER_PID;


    typedef NTSTATUS(NTAPI* fn_NsiEnumerateObjectsAllParameters)(
        UINT32 NsiQueryMode, UINT32 NsiStore, const PVOID NsiModule,
        UINT32 NsiType, PVOID KeyData, UINT32 KeySize,
        PVOID RwParamData, UINT32 RwParamSize,
        PVOID DynParamData, UINT32 DynParamSize,
        PVOID StaticParamData, UINT32 StaticParamSize,
        PUINT32 Count);


    inline constexpr UINT32 NSI_STORE_ACTIVE = 1;


    inline constexpr UINT32 NSI_QUERY_RUNTIME = 1;

    inline fn_NsiEnumerateObjectsAllParameters _NsiEnumerate = nullptr;
    inline volatile LONG g_nsi_resolved = 0;


    static const UINT8 NPI_MS_TCP_MODULEID[24] = {
        0x18, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x03, 0x4a, 0x00, 0xeb, 0x1a, 0x9b, 0xd4, 0x11,
        0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc
    };


    static const UINT8 NPI_MS_UDP_MODULEID[24] = {
        0x18, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x4a, 0x00, 0xeb, 0x1a, 0x9b, 0xd4, 0x11,
        0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc
    };


    #pragma pack(push, 1)
    typedef struct _NSI_SOCKADDR_IN6 {
        UINT16 family;
        UINT16 port_be;
        UINT32 flowinfo;
        UINT8  addr[16];
        UINT32 scope_id;
    } NSI_SOCKADDR_IN6;

    typedef struct _NSI_TCP_KEY {
        NSI_SOCKADDR_IN6 local;
        NSI_SOCKADDR_IN6 remote;
    } NSI_TCP_KEY;

    typedef struct _NSI_TCP_DYNAMIC {
        UINT32 state;
        UINT8  _pad[44];
    } NSI_TCP_DYNAMIC;

    typedef struct _NSI_TCP_STATIC {
        UINT8  _pad0[12];
        UINT32 mod_pid;
        UINT64 create_time;
        UINT8  _pad1[8];
    } NSI_TCP_STATIC;

    typedef struct _NSI_UDP_KEY {
        NSI_SOCKADDR_IN6 local;
    } NSI_UDP_KEY;

    typedef struct _NSI_UDP_STATIC {
        UINT32 mod_pid;
        UINT32 _pad0;
        UINT64 create_time;
        UINT8  _pad1[16];
    } NSI_UDP_STATIC;
    #pragma pack(pop)

    BOOLEAN resolve_nsi() {
        NET_DBG("resolve_nsi: enter");
        LONG prev = _InterlockedCompareExchange(&g_nsi_resolved, 1, 0);
        if (prev == 2) {
            return _NsiEnumerate != nullptr;
        }
        if (prev == 1) {
            for (UINT32 spin = 0; spin < 100000; spin++) {
                if (_InterlockedCompareExchange(&g_nsi_resolved, 0, 0) != 1)
                    break;
                YieldProcessor();
            }
            return _NsiEnumerate != nullptr;
        }


        PVOID netio = net_capture::find_module_base("netio.sys");
        if (!netio) netio = net_capture::find_module_base("NETIO.SYS");

        if (netio) {
            CHAR nsi_name[] = {'N','s','i','E','n','u','m','e','r','a','t','e',
                'O','b','j','e','c','t','s','A','l','l',
                'P','a','r','a','m','e','t','e','r','s',0};
            *(PVOID*)&_NsiEnumerate = GetProcAddress(netio, nsi_name);
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_nsi_resolved, 2);
        NET_DBG("resolve_nsi: NsiEnumerate=%p", _NsiEnumerate);
        return _NsiEnumerate != nullptr;
    }

    static void fill_process_path(NET_CONN_ENTRY* out, UINT32 pid) {
        out->process_path[0] = '\0';
        if (pid == 0 || pid == 4) return;


        BOOLEAN found_in_cache = FALSE;
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_pid_path_lock, &old_irql);
        for (UINT32 c = 0; c < PID_PATH_CACHE_SIZE; c++) {
            if (net_capture::g_pid_path_cache[c].pid == pid && net_capture::g_pid_path_cache[c].path[0] != '\0') {
                UINT32 plen = 0;
                while (plen < 259 && net_capture::g_pid_path_cache[c].path[plen] != '\0') {
                    out->process_path[plen] = net_capture::g_pid_path_cache[c].path[plen];
                    plen++;
                }
                out->process_path[plen] = '\0';
                found_in_cache = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&net_capture::g_pid_path_lock, old_irql);

        if (found_in_cache) return;

        PEPROCESS process = nullptr;
        NTSTATUS lookup_st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(lookup_st) || !process) return;

        PUNICODE_STRING image_name = nullptr;
        lookup_st = SeLocateProcessImageName(process, &image_name);
        if (NT_SUCCESS(lookup_st) && image_name && image_name->Buffer && image_name->Length > 0) {
            UINT32 char_count = image_name->Length / sizeof(WCHAR);
            if (char_count > 259) char_count = 259;
            for (UINT32 ci = 0; ci < char_count; ci++) {
                WCHAR wc = image_name->Buffer[ci];
                out->process_path[ci] = (wc < 128) ? (char)wc : '?';
            }
            out->process_path[char_count] = '\0';
            ExFreePool(image_name);


            KeAcquireSpinLock(&net_capture::g_pid_path_lock, &old_irql);
            UINT32 cache_idx = PID_PATH_CACHE_SIZE;
            UINT64 oldest_ts = ~0ULL;
            for (UINT32 c = 0; c < PID_PATH_CACHE_SIZE; c++) {
                if (net_capture::g_pid_path_cache[c].pid == 0) {
                    cache_idx = c;
                    break;
                }
                if (net_capture::g_pid_path_cache[c].timestamp < oldest_ts) {
                    oldest_ts = net_capture::g_pid_path_cache[c].timestamp;
                    cache_idx = c;
                }
            }
            if (cache_idx < PID_PATH_CACHE_SIZE) {
                net_capture::g_pid_path_cache[cache_idx].pid = pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                net_capture::g_pid_path_cache[cache_idx].timestamp = now.QuadPart;
                UINT32 plen = 0;
                while (plen < 259 && out->process_path[plen] != '\0') {
                    net_capture::g_pid_path_cache[cache_idx].path[plen] = out->process_path[plen];
                    plen++;
                }
                net_capture::g_pid_path_cache[cache_idx].path[plen] = '\0';
            }
            KeReleaseSpinLock(&net_capture::g_pid_path_lock, old_irql);
        } else if (image_name) {
            ExFreePool(image_name);
        }
        ObDereferenceObject(process);
    }


    static __forceinline UINT32 nsi_tcp_state_to_mib(UINT32 nsi_state) {

        return (nsi_state <= TCP_STATE_DELETE_TCB) ? nsi_state : 0;
    }

    NTSTATUS enumerate_connections(p_net_enum_conn request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->connection_count = 0;

        if (!resolve_nsi()) {
            NET_ERR("enumerate_connections: NsiEnumerate not resolved");
            return STATUS_NOT_SUPPORTED;
        }

        NET_DBG("enumerate_connections: NSI struct sizes KEY=%u DYN=%u STA=%u",
            (UINT32)sizeof(NSI_TCP_KEY), (UINT32)sizeof(NSI_TCP_DYNAMIC), (UINT32)sizeof(NSI_TCP_STATIC));


        {
            UINT32 tcp_capacity = 4096;
            UINT32 tcp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;
            NSI_TCP_KEY*     keys = nullptr;
            NSI_TCP_DYNAMIC* dyns = nullptr;
            NSI_TCP_STATIC*  stats = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                tcp_count = tcp_capacity;
                ULONG key_sz = tcp_capacity * sizeof(NSI_TCP_KEY);
                ULONG dyn_sz = tcp_capacity * sizeof(NSI_TCP_DYNAMIC);
                ULONG sta_sz = tcp_capacity * sizeof(NSI_TCP_STATIC);
                ULONG total  = key_sz + dyn_sz + sta_sz;

                buf = static_cast<UINT8*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'nsNW'));
                if (!buf) break;

                keys  = reinterpret_cast<NSI_TCP_KEY*>(buf);
                dyns  = reinterpret_cast<NSI_TCP_DYNAMIC*>(buf + key_sz);
                stats = reinterpret_cast<NSI_TCP_STATIC*>(buf + key_sz + dyn_sz);

                st = _NsiEnumerate(
                    NSI_QUERY_RUNTIME, NSI_STORE_ACTIVE, (PVOID)NPI_MS_TCP_MODULEID,
                    3, keys, sizeof(NSI_TCP_KEY),
                    nullptr, 0,
                    dyns, sizeof(NSI_TCP_DYNAMIC),
                    stats, sizeof(NSI_TCP_STATIC),
                    &tcp_count);

                NET_DBG("enumerate_connections: TCP direct [cap=%u] st=0x%08x count=%u",
                        tcp_capacity, st, tcp_count);

                if (NT_SUCCESS(st)) break;

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == tcp_capacity) {
                        NET_ERR("enumerate_connections: TCP exhausted retries at cap=%u", tcp_capacity);
                        ExFreePoolWithTag(buf, 'nsNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'nsNW');
                    buf = nullptr;
                    tcp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'nsNW');
                buf = nullptr;
                break;
            }

            if (buf && NT_SUCCESS(st) && tcp_count > 0) {
                for (UINT32 i = 0; i < tcp_count && request->connection_count < MAX_NET_CONNECTIONS; i++) {
                    UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                    if (request->filter_pid != 0 && pid != request->filter_pid)
                        continue;
                    if (request->filter_protocol != 0 && request->filter_protocol != 6)
                        continue;

                    NET_CONN_ENTRY* out = &request->entries[request->connection_count];
                    strong::kmemset(out, 0, sizeof(NET_CONN_ENTRY));
                    out->pid = pid;
                    out->protocol = 6;
                    out->state = nsi_tcp_state_to_mib(dyns[i].state);
                    out->address_family = AF_INET;

                    out->local_port  = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                    out->remote_port = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);

                    strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);
                    strong::kmemcpy(out->remote_addr, keys[i].remote.addr, 4);

                    fill_process_path(out, pid);
                    request->connection_count++;
                }
            } else if (buf) {
                NET_ERR("enumerate_connections: NSI TCP4 enum failed 0x%08x", st);
            }
            if (buf) ExFreePoolWithTag(buf, 'nsNW');
        }


        {
            UINT32 udp_capacity = 4096;
            UINT32 udp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;
            NSI_UDP_KEY*    keys  = nullptr;
            NSI_UDP_STATIC* stats = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                udp_count = udp_capacity;
                ULONG key_sz = udp_capacity * sizeof(NSI_UDP_KEY);
                ULONG sta_sz = udp_capacity * sizeof(NSI_UDP_STATIC);
                ULONG total  = key_sz + sta_sz;

                buf = static_cast<UINT8*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'nsNW'));
                if (!buf) break;

                keys  = reinterpret_cast<NSI_UDP_KEY*>(buf);
                stats = reinterpret_cast<NSI_UDP_STATIC*>(buf + key_sz);

                st = _NsiEnumerate(
                    NSI_QUERY_RUNTIME, NSI_STORE_ACTIVE, (PVOID)NPI_MS_UDP_MODULEID,
                    1, keys, sizeof(NSI_UDP_KEY),
                    nullptr, 0,
                    nullptr, 0,
                    stats, sizeof(NSI_UDP_STATIC),
                    &udp_count);

                NET_DBG("enumerate_connections: UDP direct [cap=%u] st=0x%08x count=%u",
                        udp_capacity, st, udp_count);

                if (NT_SUCCESS(st)) break;

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (udp_count > udp_capacity) ? udp_count + 64 : udp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == udp_capacity) {
                        NET_ERR("enumerate_connections: UDP exhausted retries at cap=%u", udp_capacity);
                        ExFreePoolWithTag(buf, 'nsNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'nsNW');
                    buf = nullptr;
                    udp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'nsNW');
                buf = nullptr;
                break;
            }

            if (buf && NT_SUCCESS(st) && udp_count > 0) {
                for (UINT32 i = 0; i < udp_count && request->connection_count < MAX_NET_CONNECTIONS; i++) {
                    UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                    if (request->filter_pid != 0 && pid != request->filter_pid)
                        continue;
                    if (request->filter_protocol != 0 && request->filter_protocol != 17)
                        continue;

                    NET_CONN_ENTRY* out = &request->entries[request->connection_count];
                    strong::kmemset(out, 0, sizeof(NET_CONN_ENTRY));
                    out->pid = pid;
                    out->protocol = 17;
                    out->state = 0;
                    out->address_family = AF_INET;

                    out->local_port = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                    out->remote_port = 0;

                    strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);

                    fill_process_path(out, pid);
                    request->connection_count++;
                }
            } else if (buf) {
                NET_ERR("enumerate_connections: NSI UDP enum failed 0x%08x", st);
            }
            if (buf) ExFreePoolWithTag(buf, 'nsNW');
        }

        NET_DBG("enumerate_connections: found=%u connections (filter_pid=%u filter_proto=%u)",
                request->connection_count, request->filter_pid, request->filter_protocol);
        for (UINT32 dbg_i = 0; dbg_i < request->connection_count && dbg_i < 5; dbg_i++) {
            const NET_CONN_ENTRY* e = &request->entries[dbg_i];
            NET_DBG("  conn[%u]: pid=%u proto=%u state=%u af=%u lport=%u rport=%u",
                    dbg_i, e->pid, e->protocol, e->state, e->address_family,
                    e->local_port, e->remote_port);
            NET_DBG("  conn[%u]: local=%u.%u.%u.%u remote=%u.%u.%u.%u",
                    dbg_i,
                    e->local_addr[0], e->local_addr[1], e->local_addr[2], e->local_addr[3],
                    e->remote_addr[0], e->remote_addr[1], e->remote_addr[2], e->remote_addr[3]);
        }
        return STATUS_SUCCESS;
    }

}


NTSTATUS functions::handle_net_enum_conn(p_net_enum_conn request) {
    if (!request) { NET_ERR("handle_net_enum_conn: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_net_enum_conn: filter_pid=%u filter_proto=%u", request->filter_pid, request->filter_protocol);
    NTSTATUS st = net_enum::enumerate_connections(request);
    NET_DBG("handle_net_enum_conn: returned 0x%08x count=%u", st, request->connection_count);
    return st;
}

NTSTATUS functions::handle_net_cap_ctrl(p_net_cap_ctrl request) {
    if (!request) { NET_ERR("handle_net_cap_ctrl: NULL request"); return STATUS_INVALID_PARAMETER; }

    if (net_capture::g_wfp_initialized != 2) {


        if (net_capture::g_device_object != nullptr) {
            NET_DBG("handle_net_cap_ctrl: WFP not ready (state=%d), attempting lazy re-init", (int)net_capture::g_wfp_initialized);
            NTSTATUS reinit_status = net_capture::initialize(net_capture::g_device_object);
            if (!NT_SUCCESS(reinit_status)) {
                NET_ERR("handle_net_cap_ctrl: lazy WFP re-init FAILED status=0x%08lx", reinit_status);
                return STATUS_DEVICE_NOT_READY;
            }
            NET_DBG("handle_net_cap_ctrl: lazy WFP re-init OK");
        } else {
            NET_ERR("handle_net_cap_ctrl: WFP not initialized (state=%d) and no device object", (int)net_capture::g_wfp_initialized);
            return STATUS_DEVICE_NOT_READY;
        }
    }

    switch (request->operation) {
        case 0: {
            net_capture::g_filter_pid = request->filter_pid;
            net_capture::g_filter_port = request->filter_port;
            net_capture::g_filter_protocol = request->filter_protocol;
            strong::kmemcpy(net_capture::g_filter_ip, request->filter_ip, 16);


            if (request->max_packet_bytes > 0 && request->max_packet_bytes <= NET_PKT_MAX_PAYLOAD)
                net_capture::g_max_payload = request->max_packet_bytes;
            else
                net_capture::g_max_payload = NET_PKT_MAX_PAYLOAD;


            KIRQL old_irql;
            KeAcquireSpinLock(&net_capture::g_ring_lock, &old_irql);
            net_capture::g_ring_head = 0;
            net_capture::g_ring_tail = 0;
            net_capture::g_ring_count = 0;
            KeReleaseSpinLock(&net_capture::g_ring_lock, old_irql);

            _InterlockedExchange(&net_capture::g_total_captured, 0);
            _InterlockedExchange(&net_capture::g_total_dropped, 0);
            _InterlockedExchange(&net_capture::g_capture_active, 1);

            NET_DBG("handle_net_cap_ctrl: capture STARTED pid=%u port=%u proto=%u max_bytes=%u",
                    request->filter_pid, request->filter_port, request->filter_protocol, net_capture::g_max_payload);
            request->capture_active = 1;
            break;
        }
        case 1: {
            _InterlockedExchange(&net_capture::g_capture_active, 0);
            net_capture::g_filter_pid = 0;
            net_capture::g_filter_port = 0;
            net_capture::g_filter_protocol = 0;
            strong::kmemset(net_capture::g_filter_ip, 0, sizeof(net_capture::g_filter_ip));
            NET_DBG("handle_net_cap_ctrl: capture STOPPED");
            request->capture_active = 0;
            break;
        }
        case 2: {
            break;
        }
        default:
            return STATUS_INVALID_PARAMETER;
    }

    request->capture_active = (UINT32)net_capture::g_capture_active;
    request->packets_captured = (UINT32)net_capture::g_total_captured;
    request->packets_dropped = (UINT32)net_capture::g_total_dropped;

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_net_cap_get(p_net_cap_get request) {
    if (!request) { NET_ERR("handle_net_cap_get: NULL request"); return STATUS_INVALID_PARAMETER; }
    if (!net_capture::g_ring_buffer) {
        NET_ERR("handle_net_cap_get: ring buffer not allocated");
        return STATUS_DEVICE_NOT_READY;
    }

    UINT32 max_packets = request->max_packets;
    if (max_packets > NET_CAP_GET_MAX) max_packets = NET_CAP_GET_MAX;
    if (max_packets == 0) max_packets = NET_CAP_GET_MAX;

    request->packet_count = 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&net_capture::g_ring_lock, &old_irql);

    UINT32 available = (UINT32)net_capture::g_ring_count;
    UINT32 to_read = (available < max_packets) ? available : max_packets;

    for (UINT32 i = 0; i < to_read; i++) {
        strong::kmemcpy(&request->packets[i],
            &net_capture::g_ring_buffer[net_capture::g_ring_tail],
            sizeof(NET_PACKET_ENTRY));
        net_capture::g_ring_tail = (net_capture::g_ring_tail + 1) % RING_BUFFER_SIZE;
        net_capture::g_ring_count--;
    }

    request->packet_count = to_read;

    KeReleaseSpinLock(&net_capture::g_ring_lock, old_irql);

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_net_dns_get(p_net_dns_get request) {
    if (!request) { NET_ERR("handle_net_dns_get: NULL request"); return STATUS_INVALID_PARAMETER; }
    if (!net_capture::g_dns_ring) {
        NET_ERR("handle_net_dns_get: DNS ring not allocated");
        return STATUS_DEVICE_NOT_READY;
    }

    request->entry_count = 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&net_capture::g_dns_lock, &old_irql);

    UINT32 available = (UINT32)net_capture::g_dns_count;

    UINT32 out_idx = 0;
    LONG local_tail = net_capture::g_dns_tail;
    LONG local_count = available;
    for (UINT32 i = 0; i < (UINT32)local_count && out_idx < NET_DNS_GET_MAX; i++) {
        NET_DNS_ENTRY* src = &net_capture::g_dns_ring[local_tail];

        if (request->filter_pid == 0 || src->pid == request->filter_pid) {
            strong::kmemcpy(&request->entries[out_idx], src, sizeof(NET_DNS_ENTRY));
            out_idx++;
        }

        local_tail = (local_tail + 1) % DNS_RING_SIZE;
    }

    request->entry_count = out_idx;

    KeReleaseSpinLock(&net_capture::g_dns_lock, old_irql);

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_net_filter_rule(p_net_filter_rule request) {
    if (!request) { NET_ERR("handle_net_filter_rule: NULL request"); return STATUS_INVALID_PARAMETER; }

    switch (request->operation) {
        case 0: {
            if (request->pid == 0 && request->port == 0 &&
                request->protocol == 0 && net_capture::is_zero_ip(request->ip_addr)) {
                NET_ERR("filter_rule: rejecting wildcard rule with no pid/port/protocol/ip");
                return STATUS_INVALID_PARAMETER;
            }
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                if (_InterlockedCompareExchange(&net_capture::g_filter_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&net_capture::g_next_rule_id);
                    net_capture::g_filter_rules[i].rule_id = id;
                    net_capture::g_filter_rules[i].action = request->action;
                    net_capture::g_filter_rules[i].direction = request->direction;
                    net_capture::g_filter_rules[i].protocol = request->protocol;
                    net_capture::g_filter_rules[i].pid = request->pid;
                    net_capture::g_filter_rules[i].port = request->port;
                    strong::kmemcpy(net_capture::g_filter_rules[i].ip_addr, request->ip_addr, 16);
                    strong::kmemcpy(net_capture::g_filter_rules[i].ip_mask, request->ip_mask, 16);
                    KeMemoryBarrier();
                    _InterlockedExchange(&net_capture::g_filter_rules[i].active, 1);
                    _InterlockedIncrement(&net_capture::g_active_rule_count);

                    request->rule_id = id;
                    request->rule_count = (UINT32)net_capture::g_active_rule_count;
                    NET_DBG("filter_rule: ADDED id=%u action=%u dir=%u proto=%u pid=%u port=%u (total=%u)",
                            id, request->action, request->direction, request->protocol, request->pid, request->port,
                            request->rule_count);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                if (net_capture::g_filter_rules[i].active == 1 &&
                    net_capture::g_filter_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&net_capture::g_filter_rules[i].active, 0);
                    _InterlockedDecrement(&net_capture::g_active_rule_count);
                    request->rule_count = (UINT32)net_capture::g_active_rule_count;
                    NET_DBG("filter_rule: REMOVED id=%u (remaining=%u)", request->rule_id, request->rule_count);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 2: {
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                _InterlockedExchange(&net_capture::g_filter_rules[i].active, 0);
            }
            _InterlockedExchange(&net_capture::g_active_rule_count, 0);
            request->rule_count = 0;
            NET_DBG("filter_rule: CLEARED all rules");
            return STATUS_SUCCESS;
        }
        case 3: {
            request->rule_count = (UINT32)net_capture::g_active_rule_count;
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS functions::handle_net_stats(p_net_stats request) {
    if (!request) { NET_ERR("handle_net_stats: NULL request"); return STATUS_INVALID_PARAMETER; }

    request->bytes_sent = (UINT64)net_capture::g_global_bytes_sent;
    request->bytes_received = (UINT64)net_capture::g_global_bytes_recv;
    request->packets_sent = (UINT64)net_capture::g_global_pkts_sent;
    request->packets_received = (UINT64)net_capture::g_global_pkts_recv;
    request->active_connections = 0;
    request->capture_active = (UINT32)net_capture::g_capture_active;
    request->total_captured = (UINT32)net_capture::g_total_captured;
    request->total_dropped = (UINT32)net_capture::g_total_dropped;
    request->total_dns_logged = (UINT32)net_capture::g_total_dns;
    request->active_filter_rules = (UINT32)net_capture::g_active_rule_count;

    NET_DBG("handle_net_stats: sent=%llu recv=%llu pkts_s=%llu pkts_r=%llu cap=%u captured=%u dropped=%u wfp_init=%d",
            request->bytes_sent, request->bytes_received,
            request->packets_sent, request->packets_received,
            request->capture_active, request->total_captured, request->total_dropped,
            (int)net_capture::g_wfp_initialized);
    return STATUS_SUCCESS;
}


typedef NTSTATUS(NTAPI* fn_FwpmCalloutCreateEnumHandle0)(
    HANDLE engineHandle, const VOID* enumTemplate, HANDLE* enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutDestroyEnumHandle0)(
    HANDLE engineHandle, HANDLE enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutEnum0)(
    HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested,
    FWPM_CALLOUT0_COMPAT*** entries, UINT32* numEntriesReturned);
typedef VOID(NTAPI* fn_FwpmFreeMemory0)(VOID** p);


typedef struct _FWPS_CALLOUT_ENUM_ENTRY {
    GUID   calloutKey;
    UINT32 calloutId;
    UINT32 flags;
    PVOID  classifyFn;
    PVOID  notifyFn;
    PVOID  flowDeleteFn;
} FWPS_CALLOUT_ENUM_ENTRY;

typedef NTSTATUS(NTAPI* fn_FwpsCalloutEnum0)(
    HANDLE engineHandle, HANDLE enumHandle, UINT32 numRequested,
    FWPS_CALLOUT_ENUM_ENTRY** entries, UINT32* numReturned);

namespace net_wfp_enum {

    static void get_module_name_for_address(UINT64 address, char* out_name, SIZE_T max_len);

    static void append_registered_callout(p_wfp_callout_enum request,
                                          UINT32* total_filled,
                                          UINT32 callout_id,
                                          const GUID* callout_key,
                                          const GUID* applicable_layer,
                                          UINT64 classify_fn,
                                          UINT64 notify_fn,
                                          UINT64 flow_delete_fn) {
        if (!request || !total_filled || *total_filled >= MAX_WFP_CALLOUTS || callout_id == 0)
            return;

        WFP_CALLOUT_ENTRY* out = &request->entries[*total_filled];
        strong::kmemset(out, 0, sizeof(WFP_CALLOUT_ENTRY));
        out->callout_id = callout_id;
        out->callout_key = *callout_key;
        out->applicable_layer = *applicable_layer;
        out->classify_fn = classify_fn;
        out->notify_fn = notify_fn;
        out->flow_delete_fn = flow_delete_fn;
        out->owning_module_base = (UINT64)net_capture::find_module_base("WhosWho.sys");
        get_module_name_for_address(classify_fn, out->owning_module, sizeof(out->owning_module));
        (*total_filled)++;
    }

    static NTSTATUS enumerate_registered_callouts(p_wfp_callout_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        UINT32 total_filled = 0;
        append_registered_callout(request, &total_filled,
            net_capture::g_callout_id_inbound,
            &net_capture::GUID_AIDA_CALLOUT_INBOUND,
            &GUID_LAYER_INBOUND_V4,
            (UINT64)net_capture::classify_inbound,
            (UINT64)net_capture::callout_notify,
            0);
        append_registered_callout(request, &total_filled,
            net_capture::g_callout_id_outbound,
            &net_capture::GUID_AIDA_CALLOUT_OUTBOUND,
            &GUID_LAYER_OUTBOUND_V4,
            (UINT64)net_capture::classify_outbound,
            (UINT64)net_capture::callout_notify,
            0);
        request->callout_count = total_filled;
        return (total_filled != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }


    static void get_module_name_for_address(UINT64 address, char* out_name, SIZE_T max_len) {
        out_name[0] = 0;
        if (address == 0) return;

        ULONG required = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, nullptr, 0, &required);
        if (required == 0) return;

        required += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, required, 'wmNW');
        if (!mods) return;

        status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, mods, required, nullptr);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(mods, 'wmNW');
            return;
        }

        for (ULONG i = 0; i < mods->NumberOfModules; i++) {
            UINT64 base = (UINT64)mods->Modules[i].ImageBase;
            UINT64 end = base + mods->Modules[i].ImageSize;
            if (address >= base && address < end) {
                const char* full_path = (const char*)mods->Modules[i].FullPathName;
                const char* name = full_path + mods->Modules[i].OffsetToFileName;
                SIZE_T j = 0;
                while (name[j] && j < max_len - 1) {
                    out_name[j] = name[j];
                    j++;
                }
                out_name[j] = 0;
                break;
            }
        }

        ExFreePoolWithTag(mods, 'wmNW');
    }

    static NTSTATUS enumerate_wfp_callouts(p_wfp_callout_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->callout_count = 0;


        if (!net_capture::_FwpmEngineOpen0 || !net_capture::_FwpmEngineClose0) {
            if (!net_capture::resolve_wfp_functions())
                return STATUS_NOT_SUPPORTED;
        }


        PVOID fwp_base = net_capture::find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) fwp_base = net_capture::find_module_base("fwpkclnt.sys");
        if (!fwp_base) return STATUS_NOT_FOUND;

        CHAR en1[] = {'F','w','p','m','C','a','l','l','o','u','t','C','r','e','a','t','e','E','n','u','m','H','a','n','d','l','e','0',0};
        CHAR en2[] = {'F','w','p','m','C','a','l','l','o','u','t','D','e','s','t','r','o','y','E','n','u','m','H','a','n','d','l','e','0',0};
        CHAR en3[] = {'F','w','p','m','C','a','l','l','o','u','t','E','n','u','m','0',0};
        CHAR en4[] = {'F','w','p','m','F','r','e','e','M','e','m','o','r','y','0',0};

        auto _CreateEnum = (fn_FwpmCalloutCreateEnumHandle0)GetProcAddress(fwp_base, en1);
        auto _DestroyEnum = (fn_FwpmCalloutDestroyEnumHandle0)GetProcAddress(fwp_base, en2);
        auto _Enum = (fn_FwpmCalloutEnum0)GetProcAddress(fwp_base, en3);
        auto _FreeMem = (fn_FwpmFreeMemory0)GetProcAddress(fwp_base, en4);

        if (!_CreateEnum || !_DestroyEnum || !_Enum || !_FreeMem)
            return enumerate_registered_callouts(request);


        HANDLE engine = nullptr;
        NTSTATUS status = net_capture::_FwpmEngineOpen0(nullptr, 0, nullptr, nullptr, &engine);
        if (!NT_SUCCESS(status) || !engine)
            return enumerate_registered_callouts(request);

        HANDLE enumHandle = nullptr;
        status = _CreateEnum(engine, nullptr, &enumHandle);
        if (!NT_SUCCESS(status) || !enumHandle) {
            net_capture::_FwpmEngineClose0(engine);
            return status ? status : STATUS_UNSUCCESSFUL;
        }

        UINT32 total_filled = 0;
        BOOLEAN has_filter = (request->filter_module[0] != 0);


        while (total_filled < MAX_WFP_CALLOUTS) {
            FWPM_CALLOUT0_COMPAT** entries = nullptr;
            UINT32 returned = 0;

            status = _Enum(engine, enumHandle, 64, &entries, &returned);
            if (!NT_SUCCESS(status) || returned == 0) break;

            for (UINT32 i = 0; i < returned && total_filled < MAX_WFP_CALLOUTS; i++) {
                FWPM_CALLOUT0_COMPAT* c = (FWPM_CALLOUT0_COMPAT*)entries[i];
                if (!c) continue;

                WFP_CALLOUT_ENTRY* out = &request->entries[total_filled];
                strong::kmemset(out, 0, sizeof(WFP_CALLOUT_ENTRY));

                out->callout_id = c->calloutId;
                out->callout_key = c->calloutKey;
                out->applicable_layer = c->applicableLayer;
                out->flags = c->flags;


                out->classify_fn = 0;
                out->notify_fn = 0;
                out->flow_delete_fn = 0;


                if (c->providerKey && _MmIsAddressValid(c->providerKey)) {

                }


                __try {
                    wchar_t* wname = c->displayData.name;
                    if (wname && _MmIsAddressValid(wname)) {

                        for (int j = 0; j < 63 && wname[j]; j++) {
                            out->owning_module[j] = (char)(wname[j] & 0x7F);
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}


                if (has_filter) {
                    if (out->owning_module[0] == 0) continue;

                    BOOLEAN match = FALSE;
                    SIZE_T flen = 0;
                    while (request->filter_module[flen] && flen < 63) flen++;
                    SIZE_T mlen = 0;
                    while (out->owning_module[mlen] && mlen < 63) mlen++;
                    if (mlen >= flen) {
                        for (SIZE_T s = 0; s <= mlen - flen; s++) {
                            BOOLEAN ok = TRUE;
                            for (SIZE_T k = 0; k < flen; k++) {
                                char a = out->owning_module[s + k];
                                char b = request->filter_module[k];
                                if (a >= 'A' && a <= 'Z') a += 32;
                                if (b >= 'A' && b <= 'Z') b += 32;
                                if (a != b) { ok = FALSE; break; }
                            }
                            if (ok) { match = TRUE; break; }
                        }
                    }
                    if (!match) continue;
                }

                total_filled++;
            }

            _FreeMem((VOID**)&entries);
        }

        _DestroyEnum(engine, enumHandle);
        net_capture::_FwpmEngineClose0(engine);

        request->callout_count = total_filled;
        if (total_filled == 0) {
            return enumerate_registered_callouts(request);
        }
        return STATUS_SUCCESS;
    }
}


static UINT32 aida_resolve_packet_pid(UINT64 endpoint_handle,
                                      UINT32 protocol,
                                      UINT32 local_port,
                                      UINT32 remote_port) {
    UINT32 cached_pid = aida_lookup_cached_endpoint_pid(endpoint_handle, protocol, local_port);
    if (cached_pid != 0) {
        return cached_pid;
    }

    cached_pid = aida_lookup_cached_port_pid(protocol, local_port, remote_port);
    if (cached_pid != 0) {
        return cached_pid;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return 0;

    {
        LONG64 now_tsc = static_cast<LONG64>(__rdtsc());
        LONG64 last    = _InterlockedCompareExchange64(&g_last_handle_enum_tsc, 0, 0);
        if (last != 0 && (now_tsc - last) < HANDLE_ENUM_COOLDOWN_TSC)
            return 0;
        _InterlockedExchange64(&g_last_handle_enum_tsc, now_tsc);
    }

    if (!net_enum::resolve_nsi())
        return 0;


    if (protocol == 0 || protocol == IPPROTO_TCP) {
        UINT32 tcp_capacity = 4096;
        UINT32 tcp_count = 0;
        NTSTATUS st = STATUS_UNSUCCESSFUL;
        UINT8* buf = nullptr;

        for (UINT32 attempt = 0; attempt < 8; attempt++) {
            tcp_count = tcp_capacity;
            ULONG key_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_KEY);
            ULONG sta_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_STATIC);

            buf = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'rpNW'));
            if (!buf) break;

            auto* keys = reinterpret_cast<net_enum::NSI_TCP_KEY*>(buf);
            auto* stats = reinterpret_cast<net_enum::NSI_TCP_STATIC*>(buf + key_sz);


            st = net_enum::_NsiEnumerate(
                net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_TCP_MODULEID,
                3, keys, sizeof(net_enum::NSI_TCP_KEY),
                nullptr, 0,
                nullptr, 0,
                stats, sizeof(net_enum::NSI_TCP_STATIC),
                &tcp_count);


            if (NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW ||
                st == STATUS_BUFFER_TOO_SMALL || st == static_cast<NTSTATUS>(0xC0000023)) {
                for (UINT32 i = 0; i < tcp_count; i++) {
                    UINT32 lp = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                    UINT32 rp = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);

                    BOOLEAN match = FALSE;
                    if (local_port != 0 && lp == local_port) match = TRUE;
                    if (!match && remote_port != 0 && rp == remote_port) match = TRUE;
                    if (!match && local_port != 0 && rp == local_port) match = TRUE;

                    if (match && static_cast<UINT32>(stats[i].mod_pid) != 0) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        aida_store_cached_port_pid(IPPROTO_TCP, local_port, pid);
                        aida_store_cached_port_pid(IPPROTO_TCP, remote_port, pid);
                        if (endpoint_handle != 0)
                            aida_store_cached_endpoint_pid(endpoint_handle, protocol, local_port, pid);
                        ExFreePoolWithTag(buf, 'rpNW');
                        return pid;
                    }
                }
            }

            if (NT_SUCCESS(st)) {
                ExFreePoolWithTag(buf, 'rpNW');
                break;
            }

            ExFreePoolWithTag(buf, 'rpNW');
            buf = nullptr;
            if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                st == static_cast<NTSTATUS>(0xC0000023)) {
                UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                if (next > 65536) next = 65536;
                if (next == tcp_capacity) break;
                tcp_capacity = next;
                continue;
            }
            break;
        }
    }


    if (protocol == 0 || protocol == IPPROTO_UDP) {
        UINT32 udp_capacity = 4096;
        UINT32 udp_count = 0;
        NTSTATUS st = STATUS_UNSUCCESSFUL;
        UINT8* buf = nullptr;

        for (UINT32 attempt = 0; attempt < 8; attempt++) {
            udp_count = udp_capacity;
            ULONG key_sz = udp_capacity * sizeof(net_enum::NSI_UDP_KEY);
            ULONG sta_sz = udp_capacity * sizeof(net_enum::NSI_UDP_STATIC);

            buf = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'rpNW'));
            if (!buf) break;

            auto* keys = reinterpret_cast<net_enum::NSI_UDP_KEY*>(buf);
            auto* stats = reinterpret_cast<net_enum::NSI_UDP_STATIC*>(buf + key_sz);

            st = net_enum::_NsiEnumerate(
                net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_UDP_MODULEID,
                1, keys, sizeof(net_enum::NSI_UDP_KEY),
                nullptr, 0,
                nullptr, 0,
                stats, sizeof(net_enum::NSI_UDP_STATIC),
                &udp_count);


            if (NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW ||
                st == STATUS_BUFFER_TOO_SMALL || st == static_cast<NTSTATUS>(0xC0000023)) {
                for (UINT32 i = 0; i < udp_count; i++) {
                    UINT32 lp = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);

                    if ((local_port != 0 && lp == local_port) && static_cast<UINT32>(stats[i].mod_pid) != 0) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        aida_store_cached_port_pid(IPPROTO_UDP, local_port, pid);
                        if (endpoint_handle != 0)
                            aida_store_cached_endpoint_pid(endpoint_handle, protocol, local_port, pid);
                        ExFreePoolWithTag(buf, 'rpNW');
                        return pid;
                    }
                }
            }

            if (NT_SUCCESS(st)) {
                ExFreePoolWithTag(buf, 'rpNW');
                break;
            }

            ExFreePoolWithTag(buf, 'rpNW');
            buf = nullptr;
            if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                st == static_cast<NTSTATUS>(0xC0000023)) {
                UINT32 next = (udp_count > udp_capacity) ? udp_count + 64 : udp_capacity * 2;
                if (next > 65536) next = 65536;
                if (next == udp_capacity) break;
                udp_capacity = next;
                continue;
            }
            break;
        }
    }

    return 0;
}


namespace net_socket_enum {
    typedef AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL;
    typedef AIDA_SYSTEM_HANDLE_INFORMATION SYSTEM_HANDLE_INFORMATION_LOCAL;
    typedef PAIDA_SYSTEM_HANDLE_INFORMATION PSYSTEM_HANDLE_INFORMATION_LOCAL;

    static NTSTATUS query_system_handles(PSYSTEM_HANDLE_INFORMATION_LOCAL* out_info) {
        return aida_query_system_handles(out_info);
    }


    static NTSTATUS enumerate_socket_handles(p_socket_handle_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->socket_count = 0;

        UINT32 target_pid = request->target_pid;
        NET_DBG("enum_sock: ENTER target_pid=%u IRQL=%u", target_pid, (UINT32)KeGetCurrentIrql());
        if (target_pid == 0) {
            NET_ERR("enum_sock: target_pid is 0, returning INVALID_PARAMETER");
            return STATUS_INVALID_PARAMETER;
        }

        if (!aida_can_query_system_handles()) {
            NET_ERR("enum_sock: cannot query handles (IRQL too high)");
            return STATUS_INVALID_DEVICE_STATE;
        }

        NET_DBG("enum_sock: calling query_system_handles...");
        PSYSTEM_HANDLE_INFORMATION_LOCAL handles = nullptr;
        NTSTATUS status = query_system_handles(&handles);
        NET_DBG("enum_sock: query_system_handles returned 0x%08x handles=%p", status, handles);
        if (!NT_SUCCESS(status) || !handles) {
            NET_ERR("enum_sock: query_system_handles FAILED 0x%08x", status);
            return status;
        }


        constexpr UINT32 MAX_PID_HANDLES = 1024;
        USHORT* pid_handles = static_cast<USHORT*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_PID_HANDLES * sizeof(USHORT), 'shNW'));
        if (!pid_handles) {
            ExFreePoolWithTag(handles, 'hANW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NET_DBG("enum_sock: total system handles=%lu, scanning for pid=%u", handles->NumberOfHandles, target_pid);
        UINT32 pid_handle_count = 0;
        for (ULONG i = 0; i < handles->NumberOfHandles && pid_handle_count < MAX_PID_HANDLES; i++) {
            const SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL* entry = &handles->Handles[i];
            if (static_cast<UINT32>(entry->UniqueProcessId) == target_pid) {
                pid_handles[pid_handle_count++] = entry->HandleValue;
            }
        }
        ExFreePoolWithTag(handles, 'hANW');
        handles = nullptr;

        NET_DBG("enum_sock: found %u handles for pid %u", pid_handle_count, target_pid);

        if (pid_handle_count == 0) {
            ExFreePoolWithTag(pid_handles, 'shNW');
            NET_DBG("enum_sock: no handles, returning SUCCESS with count=0");
            return STATUS_SUCCESS;
        }


        PEPROCESS process = nullptr;
        status = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &process);
        if (!NT_SUCCESS(status) || !process) {
            NET_ERR("enum_sock: PsLookupProcessByProcessId failed 0x%08x", status);
            ExFreePoolWithTag(pid_handles, 'shNW');
            return status;
        }


        NET_DBG("enum_sock: pre-initializing AFD offsets before attach");
        (void)afd_get_offsets();
        NET_DBG("enum_sock: AFD offsets ready, attaching to process %u, iterating %u handles", target_pid, pid_handle_count);
        UINT32 filled = 0;
        UINT32 ref_fail = 0, not_afd = 0, extract_fail = 0;
        KAPC_STATE apc_state = {};
        KeStackAttachProcess(process, &apc_state);

        __try {
            for (UINT32 i = 0; i < pid_handle_count && filled < MAX_SOCKET_HANDLES; i++) {
                HANDLE h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid_handles[i]));
                if (i < 3 || (i % 100 == 0))
                    NET_DBG("enum_sock: handle[%u/%u] val=0x%X", i, pid_handle_count, pid_handles[i]);


                PVOID file_obj = nullptr;
                NTSTATUS ref_st = ObReferenceObjectByHandle(
                    h, 0,
                    (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr,
                    KernelMode, &file_obj, nullptr);
                if (!NT_SUCCESS(ref_st) || !file_obj) {
                    ref_fail++;
                    continue;
                }

                PFILE_OBJECT fo = static_cast<PFILE_OBJECT>(file_obj);


                if (!aida_is_afd_file_object(fo)) {
                    ObDereferenceObject(fo);
                    not_afd++;
                    continue;
                }

                if (i < 3 || (i % 100 == 0))
                    NET_DBG("enum_sock: handle[%u] is AFD, extracting info", i);

                SOCKET_HANDLE_ENTRY* out = &request->entries[filled];
                strong::kmemset(out, 0, sizeof(SOCKET_HANDLE_ENTRY));
                out->handle_value = static_cast<UINT64>(pid_handles[i]);
                out->pid = target_pid;

                BOOLEAN ok = aida_extract_socket_info_from_fo(fo, out);
                ObDereferenceObject(fo);

                if (!ok) {
                    extract_fail++;
                    continue;
                }

                aida_cache_pid_from_socket_info(out, target_pid);
                filled++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            NET_ERR("enum_sock: EXCEPTION in handle loop at iteration, filled=%u", filled);
        }

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(process);
        ExFreePoolWithTag(pid_handles, 'shNW');

        NET_DBG("enum_sock: DONE filled=%u ref_fail=%u not_afd=%u extract_fail=%u", filled, ref_fail, not_afd, extract_fail);
        request->socket_count = filled;
        return STATUS_SUCCESS;
    }
}


namespace net_sniff {


    inline volatile LONG g_sniff_active = 0;
    inline KSPIN_LOCK g_sniff_lock;
    inline BOOLEAN g_sniff_lock_initialized = FALSE;

    inline UINT32 g_sniff_bp_index = 0;
    inline UINT32 g_sniff_tid = 0;
    inline UINT32 g_sniff_buf_reg = 0;
    inline UINT32 g_sniff_size_reg = 0;
    inline UINT32 g_sniff_max_captures = 1;
    inline volatile LONG g_sniff_capture_count = 0;
    inline SNIFF_CAPTURE* g_sniff_captures = nullptr;


    static NTSTATUS handle_sniff(p_sniff_net_buffers request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_sniff: op=%u target_addr=0x%llx buf_reg=%u size_reg=%u max_cap=%u tid=%u bp=%u",
                request->operation, request->target_address,
                request->buffer_reg_index, request->size_reg_index,
                request->max_captures, request->target_tid, request->bp_index);

        if (!g_sniff_lock_initialized) {
            KeInitializeSpinLock(&g_sniff_lock);
            g_sniff_lock_initialized = TRUE;
        }

        switch (request->operation) {
        case 0:
        {
            if (_InterlockedCompareExchange(&g_sniff_active, 1, 0) != 0) {

                request->active = 1;
                request->capture_count = (UINT32)g_sniff_capture_count;
                return STATUS_DEVICE_BUSY;
            }


            UINT32 max_cap = request->max_captures;
            if (max_cap == 0) max_cap = 1;
            if (max_cap > SNIFF_MAX_CAPTURES) max_cap = SNIFF_MAX_CAPTURES;

            SIZE_T alloc_size = (SIZE_T)max_cap * sizeof(SNIFF_CAPTURE);
            PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, 'fsNW');
            if (!buf) {
                _InterlockedExchange(&g_sniff_active, 0);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            strong::kmemset(buf, 0, alloc_size);

            KIRQL irql;
            KeAcquireSpinLock(&g_sniff_lock, &irql);
            g_sniff_captures = (SNIFF_CAPTURE*)buf;
            g_sniff_max_captures = max_cap;
            g_sniff_capture_count = 0;
            g_sniff_bp_index = request->bp_index;
            g_sniff_tid = request->target_tid;
            g_sniff_buf_reg = request->buffer_reg_index;
            g_sniff_size_reg = request->size_reg_index;
            KeReleaseSpinLock(&g_sniff_lock, irql);


            request->active = 1;
            request->capture_count = 0;
            NET_DBG("handle_sniff[start]: SUCCESS max_cap=%u bp=%u tid=%u buf_reg=%u size_reg=%u",
                    max_cap, g_sniff_bp_index, g_sniff_tid, g_sniff_buf_reg, g_sniff_size_reg);
            return STATUS_SUCCESS;
        }
        case 1:
        {
            _InterlockedExchange(&g_sniff_active, 0);

            KIRQL irql;
            KeAcquireSpinLock(&g_sniff_lock, &irql);
            if (g_sniff_captures) {
                ExFreePoolWithTag(g_sniff_captures, 'fsNW');
                g_sniff_captures = nullptr;
            }
            g_sniff_capture_count = 0;
            KeReleaseSpinLock(&g_sniff_lock, irql);

            request->active = 0;
            request->capture_count = 0;
            return STATUS_SUCCESS;
        }
        case 2:
        {
            request->active = (UINT32)g_sniff_active;
            UINT32 count = (UINT32)g_sniff_capture_count;
            if (count > SNIFF_MAX_CAPTURES) count = SNIFF_MAX_CAPTURES;
            request->capture_count = count;

            if (count > 0 && g_sniff_captures) {
                KIRQL irql;
                KeAcquireSpinLock(&g_sniff_lock, &irql);
                SIZE_T copy_size = (SIZE_T)count * sizeof(SNIFF_CAPTURE);
                strong::kmemcpy(request->captures, g_sniff_captures, copy_size);
                KeReleaseSpinLock(&g_sniff_lock, irql);
            }

            return STATUS_SUCCESS;
        }
        case 3:
        {
            if (!g_sniff_active) return STATUS_DEVICE_NOT_READY;

            UINT32 idx = (UINT32)_InterlockedIncrement(&g_sniff_capture_count) - 1;
            if (idx >= g_sniff_max_captures) {

                _InterlockedExchange(&g_sniff_active, 0);
                request->active = 0;
                request->capture_count = g_sniff_max_captures;
                return STATUS_SUCCESS;
            }

            KIRQL irql;
            KeAcquireSpinLock(&g_sniff_lock, &irql);
            if (g_sniff_captures && idx < g_sniff_max_captures) {

                strong::kmemcpy(&g_sniff_captures[idx], &request->captures[0], sizeof(SNIFF_CAPTURE));
            }
            KeReleaseSpinLock(&g_sniff_lock, irql);

            request->active = (UINT32)g_sniff_active;
            request->capture_count = idx + 1;


            if (idx + 1 >= g_sniff_max_captures) {
                _InterlockedExchange(&g_sniff_active, 0);
                request->active = 0;
            }

            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

}


namespace net_tcpip {


    #pragma pack(push, 1)
    typedef struct _NPI_MODULEID_TCPIP {
        USHORT Length;
        UCHAR  Type;
        UCHAR  padding;
        GUID   Id;
    } NPI_MODULEID_TCPIP;
    #pragma pack(pop)

    static const NPI_MODULEID_TCPIP NPI_TCP_MOD = {
        sizeof(NPI_MODULEID_TCPIP), 1, 0,
        { 0xEB004A03, 0x9B1A, 0x11D4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC } }
    };

    static const NPI_MODULEID_TCPIP NPI_UDP_MOD = {
        sizeof(NPI_MODULEID_TCPIP), 1, 0,
        { 0xEB004A02, 0x9B1A, 0x11D4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC } }
    };


    typedef NTSTATUS(NTAPI* fn_NsiEnumObjectsAllParams)(
        ULONG Unknown0, ULONG Unknown1, PVOID ModuleId,
        ULONG InfoClass, PVOID KeyData, ULONG KeySize,
        PVOID RwData, ULONG RwSize,
        PVOID DynamicData, ULONG DynSize,
        PVOID StaticData, ULONG StaticSize,
        PULONG Count);


    #pragma pack(push, 1)
    typedef struct _TCP4_KEY {
        UINT8  local_addr[4];
        UINT32 pad1;
        UINT16 local_port_be;
        UINT16 pad2;
        UINT8  remote_addr[4];
        UINT32 pad3;
        UINT16 remote_port_be;
        UINT16 pad4;
    } TCP4_KEY;

    typedef struct _TCP4_DYNAMIC {
        UINT32 state;
        UINT8  _reserved[44];
    } TCP4_DYNAMIC;

    typedef struct _TCP4_STATIC {
        UINT8  _pad0[12];
        UINT32 mod_pid;
        UINT64 create_time;
        UINT8  _pad1[8];
    } TCP4_STATIC;

    typedef struct _UDP4_KEY {
        UINT8  local_addr[4];
        UINT32 pad1;
        UINT16 local_port_be;
        UINT16 pad2;
    } UDP4_KEY;

    typedef struct _UDP4_STATIC {
        UINT32 mod_pid;
        UINT32 _pad0;
        UINT64 create_time;
        UINT8  _pad1[16];
    } UDP4_STATIC;
    #pragma pack(pop)


    static NTSTATUS dump_connections(p_tcpip_conn_dump request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->connection_count = 0;

        if (!net_enum::resolve_nsi()) {
            NET_ERR("net_tcpip::dump_connections: NsiEnumerate not resolved");
            return STATUS_NOT_SUPPORTED;
        }

        UINT32 filled = 0;


        if (request->filter_protocol == 0 || request->filter_protocol == 6) {
            UINT32 tcp_capacity = 4096;
            UINT32 tcp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                tcp_count = tcp_capacity;
                ULONG key_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_KEY);
                ULONG dyn_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_DYNAMIC);
                ULONG sta_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_STATIC);

                buf = static_cast<UINT8*>(
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + dyn_sz + sta_sz, 'tdNW'));
                if (!buf) break;

                auto* keys  = reinterpret_cast<net_enum::NSI_TCP_KEY*>(buf);
                auto* dyns  = reinterpret_cast<net_enum::NSI_TCP_DYNAMIC*>(buf + key_sz);
                auto* stats = reinterpret_cast<net_enum::NSI_TCP_STATIC*>(buf + key_sz + dyn_sz);

                st = net_enum::_NsiEnumerate(
                    net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_TCP_MODULEID,
                    3, keys, sizeof(net_enum::NSI_TCP_KEY),
                    nullptr, 0,
                    dyns, sizeof(net_enum::NSI_TCP_DYNAMIC),
                    stats, sizeof(net_enum::NSI_TCP_STATIC),
                    &tcp_count);

                if (NT_SUCCESS(st)) {
                    for (UINT32 i = 0; i < tcp_count && filled < MAX_TCPIP_CONNECTIONS; i++) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        if (request->target_pid != 0 && pid != request->target_pid)
                            continue;

                        TCPIP_CONN_ENTRY* out = &request->entries[filled];
                        strong::kmemset(out, 0, sizeof(TCPIP_CONN_ENTRY));
                        out->pid = pid;
                        out->protocol = 6;
                        out->state = net_enum::nsi_tcp_state_to_mib(dyns[i].state);
                        out->address_family = AF_INET;
                        out->local_port  = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                        out->remote_port = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);
                        strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);
                        strong::kmemcpy(out->remote_addr, keys[i].remote.addr, 4);
                        out->create_time = stats[i].create_time;
                        filled++;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    break;
                }

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == tcp_capacity) {
                        NET_ERR("dump_connections: TCP exhausted retries at cap=%u", tcp_capacity);
                        ExFreePoolWithTag(buf, 'tdNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    buf = nullptr;
                    tcp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'tdNW');
                buf = nullptr;
                break;
            }
        }


        if (request->filter_protocol == 0 || request->filter_protocol == 17) {
            UINT32 udp_capacity = 4096;
            UINT32 udp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                udp_count = udp_capacity;
                ULONG key_sz = udp_capacity * sizeof(net_enum::NSI_UDP_KEY);
                ULONG sta_sz = udp_capacity * sizeof(net_enum::NSI_UDP_STATIC);

                buf = static_cast<UINT8*>(
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'tdNW'));
                if (!buf) break;

                auto* keys  = reinterpret_cast<net_enum::NSI_UDP_KEY*>(buf);
                auto* stats = reinterpret_cast<net_enum::NSI_UDP_STATIC*>(buf + key_sz);

                st = net_enum::_NsiEnumerate(
                    net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_UDP_MODULEID,
                    1, keys, sizeof(net_enum::NSI_UDP_KEY),
                    nullptr, 0,
                    nullptr, 0,
                    stats, sizeof(net_enum::NSI_UDP_STATIC),
                    &udp_count);

                if (NT_SUCCESS(st)) {
                    for (UINT32 i = 0; i < udp_count && filled < MAX_TCPIP_CONNECTIONS; i++) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        if (request->target_pid != 0 && pid != request->target_pid)
                            continue;

                        TCPIP_CONN_ENTRY* out = &request->entries[filled];
                        strong::kmemset(out, 0, sizeof(TCPIP_CONN_ENTRY));
                        out->pid = pid;
                        out->protocol = 17;
                        out->state = 0;
                        out->address_family = AF_INET;
                        out->local_port = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                        out->remote_port = 0;
                        strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);
                        out->create_time = stats[i].create_time;
                        filled++;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    break;
                }

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (udp_count > udp_capacity) ? udp_count + 64 : udp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == udp_capacity) {
                        NET_ERR("dump_connections: UDP exhausted retries at cap=%u", udp_capacity);
                        ExFreePoolWithTag(buf, 'tdNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    buf = nullptr;
                    udp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'tdNW');
                buf = nullptr;
                break;
            }
        }

        request->connection_count = filled;
        return STATUS_SUCCESS;
    }
}


namespace net_inject {


    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleCreate0)(
        UINT16 addressFamily, UINT32 flags, HANDLE* injectionHandle);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleDestroy0)(HANDLE injectionHandle);
    typedef UINT32(NTAPI* fn_FwpsQueryPacketInjectionState0)(
        HANDLE injectionHandle, PVOID netBufferList, HANDLE* injectionContext);
    typedef PVOID(NTAPI* fn_NdisAllocateNetBufferListPool)(
        NDIS_HANDLE ndisHandle, PNET_BUFFER_LIST_POOL_PARAMETERS parameters);
    typedef VOID(NTAPI* fn_NdisFreeNetBufferListPool)(PVOID poolHandle);
    typedef NTSTATUS(NTAPI* fn_FwpsAllocateNetBufferAndNetBufferList0)(
        HANDLE poolHandle, UINT16 contextSize, UINT16 contextBackfill,
        PMDL mdlChain, ULONG dataOffset, SIZE_T dataLength, PVOID* netBufferList);
    typedef void(NTAPI* fn_FwpsFreeNetBufferList0)(PVOID netBufferList);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectTransportSendAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        UINT64 endpointHandle, UINT32 flags,
        PVOID sendArgs, UINT16 addressFamily,
        UINT32 compartmentId, PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectTransportReceiveAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        PVOID reserved, UINT32 flags,
        UINT16 addressFamily, UINT32 compartmentId,
        UINT32 interfaceIndex, UINT32 subInterfaceIndex,
        PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectNetworkSendAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        UINT32 flags, UINT32 compartmentId,
        PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectNetworkReceiveAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        UINT32 flags, UINT32 compartmentId,
        UINT32 interfaceIndex, UINT32 subInterfaceIndex,
        PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);

    inline fn_FwpsInjectionHandleCreate0         _FwpsInjectionHandleCreate0   = nullptr;
    inline fn_FwpsInjectionHandleDestroy0        _FwpsInjectionHandleDestroy0  = nullptr;
    inline fn_FwpsQueryPacketInjectionState0     _FwpsQueryPacketInjectionState0 = nullptr;
    inline fn_NdisAllocateNetBufferListPool      _NdisAllocateNetBufferListPool = nullptr;
    inline fn_NdisFreeNetBufferListPool          _NdisFreeNetBufferListPool     = nullptr;
    inline fn_FwpsAllocateNetBufferAndNetBufferList0 _FwpsAllocateNBL0         = nullptr;
    inline fn_FwpsFreeNetBufferList0             _FwpsFreeNBL0                 = nullptr;
    inline fn_FwpsInjectTransportSendAsync0      _FwpsInjectSend0              = nullptr;
    inline fn_FwpsInjectTransportReceiveAsync0   _FwpsInjectRecv0              = nullptr;
    inline fn_FwpsInjectNetworkSendAsync0        _FwpsInjectNetSend0           = nullptr;
    inline fn_FwpsInjectNetworkReceiveAsync0     _FwpsInjectNetRecv0           = nullptr;

    inline HANDLE g_inject_handle_v4 = nullptr;
    inline HANDLE g_inject_handle_net_v4 = nullptr;
    inline NDIS_HANDLE g_inject_nbl_pool = nullptr;
    inline volatile LONG g_inject_resolved = 0;

    typedef struct _INJECT_COMPLETION_CONTEXT {
        PVOID buffer;
        PMDL mdl;
    } INJECT_COMPLETION_CONTEXT;

    static __forceinline void write_be16(UINT8* dst, UINT16 value) {
        dst[0] = (UINT8)(value >> 8);
        dst[1] = (UINT8)(value & 0xFF);
    }

    static __forceinline void write_be32(UINT8* dst, UINT32 value) {
        dst[0] = (UINT8)(value >> 24);
        dst[1] = (UINT8)((value >> 16) & 0xFF);
        dst[2] = (UINT8)((value >> 8) & 0xFF);
        dst[3] = (UINT8)(value & 0xFF);
    }

    static UINT32 checksum_accumulate(UINT32 sum, const UINT8* data, UINT32 len) {
        if (!data) {
            return sum;
        }

        UINT32 i = 0;
        while (i + 1 < len) {
            sum += ((UINT32)data[i] << 8) | data[i + 1];
            i += 2;
        }

        if (i < len) {
            sum += ((UINT32)data[i] << 8);
        }

        return sum;
    }

    static UINT16 finalize_checksum(UINT32 sum) {
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFFu) + (sum >> 16);
        }
        return (UINT16)(~sum & 0xFFFFu);
    }

    static UINT16 transport_checksum_ipv4(const UINT8* src_addr,
                                          const UINT8* dst_addr,
                                          UINT8 protocol,
                                          const UINT8* segment,
                                          UINT32 segment_len) {
        UINT32 sum = 0;
        sum = checksum_accumulate(sum, src_addr, 4);
        sum = checksum_accumulate(sum, dst_addr, 4);
        sum += protocol;
        sum += (segment_len >> 16) & 0xFFFFu;
        sum += segment_len & 0xFFFFu;
        sum = checksum_accumulate(sum, segment, segment_len);
        return finalize_checksum(sum);
    }

    static __forceinline BOOLEAN is_loopback_ipv4_addr(const UINT8* addr) {
        return addr != nullptr && addr[0] == 127;
    }

    static UINT32 build_transport_packet(const packet_inject_request* request, UINT8* out_buf, UINT32 out_cap) {
        if (!request || !out_buf || out_cap == 0)
            return 0;

        if (request->tcp_flags & INJECT_FLAG_RAW_TRANSPORT) {
            if (request->payload_size > out_cap) return 0;
            strong::kmemcpy(out_buf, request->payload, request->payload_size);
            if (request->address_family == AF_INET) {
                if (request->protocol == IPPROTO_TCP && request->payload_size >= 20) {
                    write_be16(out_buf + 16, 0);
                    UINT16 checksum = transport_checksum_ipv4(
                        request->src_addr, request->dst_addr,
                        IPPROTO_TCP, out_buf, request->payload_size);
                    write_be16(out_buf + 16, checksum);
                } else if (request->protocol == IPPROTO_UDP && request->payload_size >= 8) {
                    write_be16(out_buf + 6, 0);
                    UINT16 checksum = transport_checksum_ipv4(
                        request->src_addr, request->dst_addr,
                        IPPROTO_UDP, out_buf, request->payload_size);
                    if (checksum == 0) checksum = 0xFFFFu;
                    write_be16(out_buf + 6, checksum);
                }
            }
            return request->payload_size;
        }

        if (request->protocol == IPPROTO_UDP) {
            UINT32 total = request->payload_size + 8;
            if (total > out_cap) return 0;
            strong::kmemset(out_buf, 0, total);
            write_be16(out_buf, (UINT16)request->src_port);
            write_be16(out_buf + 2, (UINT16)request->dst_port);
            write_be16(out_buf + 4, (UINT16)total);
            strong::kmemcpy(out_buf + 8, request->payload, request->payload_size);
            if (request->address_family == AF_INET) {
                UINT16 checksum = transport_checksum_ipv4(
                    request->src_addr,
                    request->dst_addr,
                    IPPROTO_UDP,
                    out_buf,
                    total);
                if (checksum == 0) {
                    checksum = 0xFFFFu;
                }
                write_be16(out_buf + 6, checksum);
            }
            return total;
        }

        if (request->protocol == IPPROTO_TCP) {
            UINT32 total = request->payload_size + 20;
            if (total > out_cap) return 0;
            strong::kmemset(out_buf, 0, total);
            write_be16(out_buf, (UINT16)request->src_port);
            write_be16(out_buf + 2, (UINT16)request->dst_port);
            write_be32(out_buf + 4, request->tcp_seq);
            write_be32(out_buf + 8, request->tcp_ack);
            out_buf[12] = 0x50;
            out_buf[13] = (UINT8)(request->tcp_flags & 0xFF);
            out_buf[14] = 0xFF;
            out_buf[15] = 0xFF;
            strong::kmemcpy(out_buf + 20, request->payload, request->payload_size);
            if (request->address_family == AF_INET) {
                UINT16 checksum = transport_checksum_ipv4(
                    request->src_addr,
                    request->dst_addr,
                    IPPROTO_TCP,
                    out_buf,
                    total);
                write_be16(out_buf + 16, checksum);
            }
            return total;
        }

        if (request->payload_size > out_cap) {
            return 0;
        }

        strong::kmemcpy(out_buf, request->payload, request->payload_size);
        return request->payload_size;
    }

    BOOLEAN resolve_inject_functions() {
        NET_DBG("resolve_inject_functions: enter");
        LONG state = _InterlockedCompareExchange(&g_inject_resolved, 0, 0);
        if (state == 2) {
            NET_DBG("resolve_inject_functions: already resolved, handle_v4=%p handle_net_v4=%p",
                    g_inject_handle_v4, g_inject_handle_net_v4);
            return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
        }
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            NET_ERR("resolve_inject_functions: blocked at IRQL=%u before first-time export resolution",
                    (UINT32)KeGetCurrentIrql());
            return FALSE;
        }
        if (state == 1) {
            for (UINT32 spin = 0; spin < 100000; spin++) {
                if (_InterlockedCompareExchange(&g_inject_resolved, 0, 0) != 1)
                    break;
                YieldProcessor();
            }
            return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
        }

        LONG prev = _InterlockedCompareExchange(&g_inject_resolved, 1, 0);
        if (prev == 2) {
            return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
        }
        if (prev != 0) {
            return FALSE;
        }

        PVOID fwp_base = net_capture::find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) fwp_base = net_capture::find_module_base("fwpkclnt.sys");
        if (!fwp_base) {
            NET_ERR("resolve_inject_functions: FWPKCLNT.SYS not found");
            _InterlockedExchange(&g_inject_resolved, 2);
            return FALSE;
        }
        NET_DBG("resolve_inject_functions: FWPKCLNT.SYS base=%p", fwp_base);

        CHAR f1[] = {'F','w','p','s','I','n','j','e','c','t','i','o','n','H','a','n','d','l','e','C','r','e','a','t','e','0',0};
        CHAR f2[] = {'F','w','p','s','I','n','j','e','c','t','i','o','n','H','a','n','d','l','e','D','e','s','t','r','o','y','0',0};
        CHAR f3[] = {'F','w','p','s','A','l','l','o','c','a','t','e','N','e','t','B','u','f','f','e','r','A','n','d','N','e','t','B','u','f','f','e','r','L','i','s','t','0',0};
        CHAR f4[] = {'F','w','p','s','F','r','e','e','N','e','t','B','u','f','f','e','r','L','i','s','t','0',0};
        CHAR f5[] = {'F','w','p','s','I','n','j','e','c','t','T','r','a','n','s','p','o','r','t','S','e','n','d','A','s','y','n','c','0',0};
        CHAR f6[] = {'F','w','p','s','I','n','j','e','c','t','T','r','a','n','s','p','o','r','t','R','e','c','e','i','v','e','A','s','y','n','c','0',0};
        CHAR f7[] = {'F','w','p','s','I','n','j','e','c','t','N','e','t','w','o','r','k','S','e','n','d','A','s','y','n','c','0',0};
        CHAR f8[] = {'F','w','p','s','I','n','j','e','c','t','N','e','t','w','o','r','k','R','e','c','e','i','v','e','A','s','y','n','c','0',0};
        CHAR f9[] = {'F','w','p','s','Q','u','e','r','y','P','a','c','k','e','t','I','n','j','e','c','t','i','o','n','S','t','a','t','e','0',0};
        CHAR n1[] = {'N','d','i','s','A','l','l','o','c','a','t','e','N','e','t','B','u','f','f','e','r','L','i','s','t','P','o','o','l',0};
        CHAR n2[] = {'N','d','i','s','F','r','e','e','N','e','t','B','u','f','f','e','r','L','i','s','t','P','o','o','l',0};

        PVOID ndis_base = net_capture::find_module_base("NDIS.SYS");
        if (!ndis_base) ndis_base = net_capture::find_module_base("ndis.sys");

        *(PVOID*)&_FwpsInjectionHandleCreate0 = GetProcAddress(fwp_base, f1);
        *(PVOID*)&_FwpsInjectionHandleDestroy0 = GetProcAddress(fwp_base, f2);
        *(PVOID*)&_FwpsAllocateNBL0 = GetProcAddress(fwp_base, f3);
        *(PVOID*)&_FwpsFreeNBL0 = GetProcAddress(fwp_base, f4);
        *(PVOID*)&_FwpsInjectSend0 = GetProcAddress(fwp_base, f5);
        *(PVOID*)&_FwpsInjectRecv0 = GetProcAddress(fwp_base, f6);
        *(PVOID*)&_FwpsInjectNetSend0 = GetProcAddress(fwp_base, f7);
        *(PVOID*)&_FwpsInjectNetRecv0 = GetProcAddress(fwp_base, f8);
        *(PVOID*)&_FwpsQueryPacketInjectionState0 = GetProcAddress(fwp_base, f9);
        if (ndis_base) {
            *(PVOID*)&_NdisAllocateNetBufferListPool = GetProcAddress(ndis_base, n1);
            *(PVOID*)&_NdisFreeNetBufferListPool = GetProcAddress(ndis_base, n2);
        }

        if (_FwpsInjectionHandleCreate0) {
            NTSTATUS st = _FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &g_inject_handle_v4);
            NET_DBG("resolve_inject_functions: transport inject handle create st=0x%08x handle=%p", st, g_inject_handle_v4);
            if (!NT_SUCCESS(st)) g_inject_handle_v4 = nullptr;

            st = _FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &g_inject_handle_net_v4);
            NET_DBG("resolve_inject_functions: network inject handle create st=0x%08x handle=%p", st, g_inject_handle_net_v4);
            if (!NT_SUCCESS(st)) g_inject_handle_net_v4 = nullptr;
        } else {
            NET_ERR("resolve_inject_functions: FwpsInjectionHandleCreate0 not found");
        }

        NET_DBG("resolve_inject_functions: InjectSend=%p InjectRecv=%p NetSend=%p NetRecv=%p NBLPool=%p",
                _FwpsInjectSend0, _FwpsInjectRecv0, _FwpsInjectNetSend0, _FwpsInjectNetRecv0,
                _NdisAllocateNetBufferListPool);
        KeMemoryBarrier();
        _InterlockedExchange(&g_inject_resolved, 2);
        return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
    }

    void NTAPI inject_completion(PVOID context, PVOID nbl, BOOLEAN dispatch_level) {
        UNREFERENCED_PARAMETER(dispatch_level);
        INJECT_COMPLETION_CONTEXT* completion = (INJECT_COMPLETION_CONTEXT*)context;
        if (nbl && _FwpsFreeNBL0) _FwpsFreeNBL0(nbl);
        if (completion) {
            if (completion->mdl) IoFreeMdl(completion->mdl);
            if (completion->buffer) ExFreePoolWithTag(completion->buffer, 'jiNW');
            ExFreePoolWithTag(completion, 'jcNW');
        }
    }

    static BOOLEAN ensure_inject_nbl_pool() {
        if (g_inject_nbl_pool) {
            return TRUE;
        }

        NET_BUFFER_LIST_POOL_PARAMETERS params = {};
        params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        params.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        params.ProtocolId = 0;
        params.fAllocateNetBuffer = TRUE;
        params.ContextSize = 0;
        params.PoolTag = 'jnNW';
        params.DataSize = 0;

        if (!_NdisAllocateNetBufferListPool || !_NdisFreeNetBufferListPool) {
            return FALSE;
        }

        g_inject_nbl_pool = _NdisAllocateNetBufferListPool(nullptr, &params);
        if (!g_inject_nbl_pool) {
            return FALSE;
        }

        return TRUE;
    }

    BOOLEAN prepare_injection_runtime() {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            NET_ERR("prepare_injection_runtime: blocked at IRQL=%u", (UINT32)KeGetCurrentIrql());
            return FALSE;
        }
        if (!resolve_inject_functions()) {
            return FALSE;
        }
        return ensure_inject_nbl_pool();
    }

    static UINT64 lookup_endpoint_handle_by_port(UINT32 protocol, UINT32 src_port) {
        aida_ensure_endpoint_pid_cache_init();
        KIRQL old_irql;
        KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
        for (UINT32 i = 0; i < AIDA_ENDPOINT_PID_CACHE_SIZE; i++) {
            const AIDA_ENDPOINT_PID_CACHE_ENTRY* entry = &g_endpoint_pid_cache[i];
            if (!entry->active) continue;
            if (protocol != 0 && entry->protocol != 0 && entry->protocol != protocol) continue;
            if (src_port != 0 && entry->local_port != 0 && entry->local_port != src_port) continue;
            UINT64 handle = entry->endpoint_handle;
            KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
            return handle;
        }
        KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
        return 0;
    }

#pragma pack(push, 1)
    typedef struct _IPV4_HEADER {
        UINT8  ver_ihl;
        UINT8  tos;
        UINT16 total_length;
        UINT16 identification;
        UINT16 flags_fragoffset;
        UINT8  ttl;
        UINT8  protocol;
        UINT16 checksum;
        UINT8  src_addr[4];
        UINT8  dst_addr[4];
    } IPV4_HEADER;
#pragma pack(pop)

    static UINT16 ip_checksum(const UINT8* data, UINT32 len) {
        UINT32 sum = 0;
        for (UINT32 i = 0; i + 1 < len; i += 2)
            sum += (UINT16)((data[i] << 8) | data[i + 1]);
        if (len & 1)
            sum += (UINT16)(data[len - 1] << 8);
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (UINT16)(~sum & 0xFFFF);
    }

    static UINT32 build_ip_wrapped_packet(const p_packet_inject_request request,
                                          const UINT8* transport_data, UINT32 transport_len,
                                          UINT8* out_buf, UINT32 out_cap) {
        UINT32 total_len = sizeof(IPV4_HEADER) + transport_len;
        if (total_len > out_cap) return 0;

        IPV4_HEADER* ip = (IPV4_HEADER*)out_buf;
        strong::kmemset(ip, 0, sizeof(IPV4_HEADER));
        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->total_length = _byteswap_ushort((UINT16)total_len);
        ip->identification = _byteswap_ushort((UINT16)(KeQueryTimeIncrement() & 0xFFFF));
        ip->flags_fragoffset = 0;
        ip->ttl = 128;
        ip->protocol = (UINT8)request->protocol;
        ip->checksum = 0;
        strong::kmemcpy(ip->src_addr, request->src_addr, 4);
        strong::kmemcpy(ip->dst_addr, request->dst_addr, 4);

        ip->checksum = _byteswap_ushort(ip_checksum((const UINT8*)ip, sizeof(IPV4_HEADER)));

        strong::kmemcpy(out_buf + sizeof(IPV4_HEADER), transport_data, transport_len);
        return total_len;
    }

    NTSTATUS inject_packet(p_packet_inject_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->status = 1;

        NET_DBG("inject_packet: dir=%u proto=%u af=%u src_port=%u dst_port=%u payload=%u",
                request->direction, request->protocol, request->address_family,
                request->src_port, request->dst_port, request->payload_size);
        NET_DBG("inject_packet: src=%u.%u.%u.%u dst=%u.%u.%u.%u",
                request->src_addr[0], request->src_addr[1], request->src_addr[2], request->src_addr[3],
                request->dst_addr[0], request->dst_addr[1], request->dst_addr[2], request->dst_addr[3]);

        if (!resolve_inject_functions()) {
            NET_ERR("inject_packet: resolve_inject_functions FAILED");
            return STATUS_NOT_SUPPORTED;
        }

        if (!g_inject_nbl_pool && KeGetCurrentIrql() != PASSIVE_LEVEL) {
            NET_ERR("inject_packet: NBL pool unavailable at IRQL=%u; injection runtime was not prewarmed",
                    (UINT32)KeGetCurrentIrql());
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (!ensure_inject_nbl_pool()) {
            NET_ERR("inject_packet: ensure_inject_nbl_pool FAILED");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BOOLEAN have_transport = (g_inject_handle_v4 != nullptr && _FwpsInjectSend0 && _FwpsInjectRecv0);
        BOOLEAN have_network = (g_inject_handle_net_v4 != nullptr && (_FwpsInjectNetSend0 || _FwpsInjectNetRecv0));
        NET_DBG("inject_packet: have_transport=%d have_network=%d handle_v4=%p handle_net_v4=%p",
                (int)have_transport, (int)have_network, g_inject_handle_v4, g_inject_handle_net_v4);
        if (!have_transport && !have_network)
            return STATUS_NOT_SUPPORTED;

        if (request->payload_size > INJECT_MAX_PAYLOAD)
            return STATUS_INVALID_PARAMETER;
        if (request->payload_size == 0 &&
            request->protocol != IPPROTO_TCP && request->protocol != IPPROTO_UDP)
            return STATUS_INVALID_PARAMETER;

        UINT8 packet_buf[INJECT_MAX_PAYLOAD + 32] = {};
        UINT32 packet_size = build_transport_packet(request, packet_buf, sizeof(packet_buf));
        if (packet_size == 0) {
            NET_ERR("inject_packet: build_transport_packet returned 0");
            return STATUS_INVALID_PARAMETER;
        }

        BOOLEAN loopback_v4 =
            request->address_family == AF_INET &&
            is_loopback_ipv4_addr(request->src_addr) &&
            is_loopback_ipv4_addr(request->dst_addr);
        UINT32 recv_interface_index = loopback_v4 ? 1u : 0u;

        UINT64 endpoint_handle = lookup_endpoint_handle_by_port(request->protocol, request->src_port);
        NET_DBG("inject_packet: packet_size=%u loopback=%d endpoint_handle=0x%llx",
                packet_size, (int)loopback_v4, endpoint_handle);

        NTSTATUS st = STATUS_UNSUCCESSFUL;
        BOOLEAN transport_attempted = FALSE;

        if (have_transport && (endpoint_handle != 0 || !have_network)) {
            PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, 'jiNW');
            if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
            strong::kmemcpy(buf, packet_buf, packet_size);

            INJECT_COMPLETION_CONTEXT* completion = (INJECT_COMPLETION_CONTEXT*)
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECT_COMPLETION_CONTEXT), 'jcNW');
            if (!completion) {
                ExFreePoolWithTag(buf, 'jiNW');
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            strong::kmemset(completion, 0, sizeof(*completion));
            completion->buffer = buf;

            PMDL mdl = IoAllocateMdl(buf, packet_size, FALSE, FALSE, nullptr);
            if (!mdl) {
                ExFreePoolWithTag(completion, 'jcNW');
                ExFreePoolWithTag(buf, 'jiNW');
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            completion->mdl = mdl;
            MmBuildMdlForNonPagedPool(mdl);

            PVOID nbl = nullptr;
            st = _FwpsAllocateNBL0(g_inject_nbl_pool, 0, 0, mdl, 0, packet_size, &nbl);
            if (!NT_SUCCESS(st) || !nbl) {
                IoFreeMdl(mdl);
                ExFreePoolWithTag(completion, 'jcNW');
                ExFreePoolWithTag(buf, 'jiNW');
                return st;
            }

            transport_attempted = TRUE;
            NET_DBG("inject_packet: trying transport path, dir=%u", request->direction);

            if (request->direction == 1) {
                FWPS_TRANSPORT_SEND_PARAMS0_COMPAT sendArgs = {};
                sendArgs.remoteAddress = request->dst_addr;

                st = _FwpsInjectSend0(g_inject_handle_v4, nullptr, endpoint_handle, 0,
                    &sendArgs, (UINT16)request->address_family, 0, nbl,
                    (PVOID)inject_completion, completion);

                if (!NT_SUCCESS(st) && _FwpsInjectRecv0 && loopback_v4) {
                    st = _FwpsInjectRecv0(g_inject_handle_v4, nullptr, nullptr, 0,
                        (UINT16)request->address_family, 0, recv_interface_index, 0, nbl,
                        (PVOID)inject_completion, completion);
                }
            } else {
                st = _FwpsInjectRecv0(g_inject_handle_v4, nullptr, nullptr, 0,
                    (UINT16)request->address_family, 0, recv_interface_index, 0, nbl,
                    (PVOID)inject_completion, completion);

                if (!NT_SUCCESS(st) && _FwpsInjectSend0 && loopback_v4) {
                    FWPS_TRANSPORT_SEND_PARAMS0_COMPAT sendArgs = {};
                    sendArgs.remoteAddress = request->dst_addr;
                    st = _FwpsInjectSend0(g_inject_handle_v4, nullptr, endpoint_handle, 0,
                        &sendArgs, (UINT16)request->address_family, 0, nbl,
                        (PVOID)inject_completion, completion);
                }
            }

            if (NT_SUCCESS(st)) {
                NET_DBG("inject_packet: transport inject SUCCESS st=0x%08x", st);
                request->status = 0;
                return STATUS_SUCCESS;
            }

            NET_ERR("inject_packet: transport inject FAILED 0x%08x", st);
            _FwpsFreeNBL0(nbl);
            IoFreeMdl(mdl);
            ExFreePoolWithTag(completion, 'jcNW');
            ExFreePoolWithTag(buf, 'jiNW');
        }

        if (!have_network) {
            NET_ERR("inject_packet: no network inject path available, returning 0x%08x", st);
            return st;
        }

        UINT8 ip_packet_buf[INJECT_MAX_PAYLOAD + 64] = {};
        UINT32 ip_packet_size = build_ip_wrapped_packet(request, packet_buf, packet_size,
            ip_packet_buf, sizeof(ip_packet_buf));
        if (ip_packet_size == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        PVOID net_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, ip_packet_size, 'jiNW');
        if (!net_buf) return STATUS_INSUFFICIENT_RESOURCES;
        strong::kmemcpy(net_buf, ip_packet_buf, ip_packet_size);

        INJECT_COMPLETION_CONTEXT* net_completion = (INJECT_COMPLETION_CONTEXT*)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECT_COMPLETION_CONTEXT), 'jcNW');
        if (!net_completion) {
            ExFreePoolWithTag(net_buf, 'jiNW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        strong::kmemset(net_completion, 0, sizeof(*net_completion));
        net_completion->buffer = net_buf;

        PMDL net_mdl = IoAllocateMdl(net_buf, ip_packet_size, FALSE, FALSE, nullptr);
        if (!net_mdl) {
            ExFreePoolWithTag(net_completion, 'jcNW');
            ExFreePoolWithTag(net_buf, 'jiNW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        net_completion->mdl = net_mdl;
        MmBuildMdlForNonPagedPool(net_mdl);

        PVOID net_nbl = nullptr;
        st = _FwpsAllocateNBL0(g_inject_nbl_pool, 0, 0, net_mdl, 0, ip_packet_size, &net_nbl);
        if (!NT_SUCCESS(st) || !net_nbl) {
            IoFreeMdl(net_mdl);
            ExFreePoolWithTag(net_completion, 'jcNW');
            ExFreePoolWithTag(net_buf, 'jiNW');
            return st;
        }

        if (request->direction == 1 && _FwpsInjectNetSend0) {
            NET_DBG("inject_packet: trying network send path ip_size=%u", ip_packet_size);
            st = _FwpsInjectNetSend0(g_inject_handle_net_v4, nullptr, 0, 0,
                net_nbl, (PVOID)inject_completion, net_completion);
        } else if (_FwpsInjectNetRecv0) {
            NET_DBG("inject_packet: trying network recv path ip_size=%u if_idx=%u", ip_packet_size, recv_interface_index);
            st = _FwpsInjectNetRecv0(g_inject_handle_net_v4, nullptr, 0, 0,
                recv_interface_index, 0, net_nbl,
                (PVOID)inject_completion, net_completion);
        } else if (_FwpsInjectNetSend0) {
            NET_DBG("inject_packet: fallback network send path");
            st = _FwpsInjectNetSend0(g_inject_handle_net_v4, nullptr, 0, 0,
                net_nbl, (PVOID)inject_completion, net_completion);
        } else {
            st = STATUS_NOT_SUPPORTED;
        }

        if (!NT_SUCCESS(st)) {
            NET_ERR("inject_packet: network inject FAILED 0x%08x", st);
            _FwpsFreeNBL0(net_nbl);
            IoFreeMdl(net_mdl);
            ExFreePoolWithTag(net_completion, 'jcNW');
            ExFreePoolWithTag(net_buf, 'jiNW');
            return st;
        }

        NET_DBG("inject_packet: network inject SUCCESS");
        request->status = 0;
        return STATUS_SUCCESS;
    }

    void cleanup() {
        if (g_inject_handle_v4 && _FwpsInjectionHandleDestroy0) {
            _FwpsInjectionHandleDestroy0(g_inject_handle_v4);
            g_inject_handle_v4 = nullptr;
        }
        if (g_inject_handle_net_v4 && _FwpsInjectionHandleDestroy0) {
            _FwpsInjectionHandleDestroy0(g_inject_handle_net_v4);
            g_inject_handle_net_v4 = nullptr;
        }
        if (g_inject_nbl_pool && _NdisFreeNetBufferListPool) {
            _NdisFreeNetBufferListPool(g_inject_nbl_pool);
            g_inject_nbl_pool = nullptr;
        }
    }
}


namespace net_checksum {

    static UINT32 accumulate(UINT32 sum, const UINT8* data, UINT32 len) {
        if (!data) return sum;
        UINT32 i = 0;
        while (i + 1 < len) {
            sum += ((UINT32)data[i] << 8) | data[i + 1];
            i += 2;
        }
        if (i < len) {
            sum += ((UINT32)data[i] << 8);
        }
        return sum;
    }

    static UINT16 finalize(UINT32 sum) {
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFFu) + (sum >> 16);
        return (UINT16)(~sum & 0xFFFFu);
    }

    UINT16 ip_checksum(const UINT8* ip_header, UINT32 header_len) {
        if (!ip_header || header_len < 20) return 0;
        return finalize(accumulate(0, ip_header, header_len));
    }

    UINT16 tcp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* tcp_data, UINT32 tcp_len) {
        if (!tcp_data || tcp_len < 20) return 0;
        UINT32 sum = 0;

        UINT8 pseudo[12];
        pseudo[0] = (UINT8)(src_ip >> 24); pseudo[1] = (UINT8)(src_ip >> 16);
        pseudo[2] = (UINT8)(src_ip >> 8);  pseudo[3] = (UINT8)(src_ip);
        pseudo[4] = (UINT8)(dst_ip >> 24); pseudo[5] = (UINT8)(dst_ip >> 16);
        pseudo[6] = (UINT8)(dst_ip >> 8);  pseudo[7] = (UINT8)(dst_ip);
        pseudo[8] = 0; pseudo[9] = IPPROTO_TCP;
        pseudo[10] = (UINT8)(tcp_len >> 8); pseudo[11] = (UINT8)(tcp_len);
        sum = accumulate(sum, pseudo, 12);
        sum = accumulate(sum, tcp_data, tcp_len);
        return finalize(sum);
    }

    UINT16 udp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* udp_data, UINT32 udp_len) {
        if (!udp_data || udp_len < 8) return 0;
        UINT32 sum = 0;
        UINT8 pseudo[12];
        pseudo[0] = (UINT8)(src_ip >> 24); pseudo[1] = (UINT8)(src_ip >> 16);
        pseudo[2] = (UINT8)(src_ip >> 8);  pseudo[3] = (UINT8)(src_ip);
        pseudo[4] = (UINT8)(dst_ip >> 24); pseudo[5] = (UINT8)(dst_ip >> 16);
        pseudo[6] = (UINT8)(dst_ip >> 8);  pseudo[7] = (UINT8)(dst_ip);
        pseudo[8] = 0; pseudo[9] = IPPROTO_UDP;
        pseudo[10] = (UINT8)(udp_len >> 8); pseudo[11] = (UINT8)(udp_len);
        sum = accumulate(sum, pseudo, 12);
        sum = accumulate(sum, udp_data, udp_len);
        UINT16 result = finalize(sum);
        if (result == 0) result = 0xFFFFu;
        return result;
    }

    void recalculate_transport_checksums(UINT8* ip_header, UINT32 total_len) {
        if (!ip_header || total_len < 20) return;

        UINT8 ver_ihl = ip_header[0];
        if ((ver_ihl >> 4) != 4) return;

        UINT32 ihl = (ver_ihl & 0x0F) * 4;
        if (ihl < 20 || ihl > total_len) return;

        UINT8 protocol = ip_header[9];
        UINT32 src_ip = ((UINT32)ip_header[12] << 24) | ((UINT32)ip_header[13] << 16) |
                        ((UINT32)ip_header[14] << 8) | ip_header[15];
        UINT32 dst_ip = ((UINT32)ip_header[16] << 24) | ((UINT32)ip_header[17] << 16) |
                        ((UINT32)ip_header[18] << 8) | ip_header[19];


        ip_header[10] = 0;
        ip_header[11] = 0;
        UINT16 ip_cksum = ip_checksum(ip_header, ihl);
        ip_header[10] = (UINT8)(ip_cksum >> 8);
        ip_header[11] = (UINT8)(ip_cksum);

        UINT8* transport = ip_header + ihl;
        UINT32 transport_len = total_len - ihl;

        if (protocol == IPPROTO_TCP && transport_len >= 20) {

            transport[16] = 0;
            transport[17] = 0;
            UINT16 cksum = tcp_checksum_ipv4(src_ip, dst_ip, transport, transport_len);
            transport[16] = (UINT8)(cksum >> 8);
            transport[17] = (UINT8)(cksum);
        } else if (protocol == IPPROTO_UDP && transport_len >= 8) {

            transport[6] = 0;
            transport[7] = 0;
            UINT16 cksum = udp_checksum_ipv4(src_ip, dst_ip, transport, transport_len);
            transport[6] = (UINT8)(cksum >> 8);
            transport[7] = (UINT8)(cksum);
        }
    }
}


namespace net_seq_delta {

    static __forceinline UINT32 hash_5tuple(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        UINT32 h = src_ip ^ dst_ip ^ ((UINT32)src_port << 16) ^ dst_port;
        h = (h ^ (h >> 16)) * 0x45d9f3b;
        h = (h ^ (h >> 16));
        return h % MAX_SEQ_DELTA_ENTRIES;
    }

    SEQ_DELTA_ENTRY* find_or_create(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);


        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if (e->src_ip == src_ip && e->dst_ip == dst_ip &&
                e->src_port == src_port && e->dst_port == dst_port) {
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
                return e;
            }

            if (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                e->src_port == dst_port && e->dst_port == src_port) {
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
                return e;
            }
        }


        UINT32 start = hash_5tuple(src_ip, dst_ip, src_port, dst_port);
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            UINT32 idx = (start + i) % MAX_SEQ_DELTA_ENTRIES;
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[idx];
            if (!e->active) {
                e->src_ip = src_ip;
                e->dst_ip = dst_ip;
                e->src_port = src_port;
                e->dst_port = dst_port;
                e->outbound_delta = 0;
                e->inbound_delta = 0;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeMemoryBarrier();
                _InterlockedExchange(&e->active, 1);
                KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
                return e;
            }
        }

        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
        return nullptr;
    }

    BOOLEAN apply_delta(UINT8* tcp_header, UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound) {
        if (!tcp_header) return FALSE;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);

        SEQ_DELTA_ENTRY* entry = nullptr;
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if ((e->src_ip == src_ip && e->dst_ip == dst_ip &&
                 e->src_port == src_port && e->dst_port == dst_port) ||
                (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                 e->src_port == dst_port && e->dst_port == src_port)) {
                entry = e;
                break;
            }
        }

        if (!entry || (entry->outbound_delta == 0 && entry->inbound_delta == 0)) {
            KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
            return FALSE;
        }


        LONG32 seq_adjust = is_outbound ? entry->outbound_delta : entry->inbound_delta;
        if (seq_adjust != 0) {
            UINT32 seq = ((UINT32)tcp_header[4] << 24) | ((UINT32)tcp_header[5] << 16) |
                         ((UINT32)tcp_header[6] << 8) | tcp_header[7];
            seq = (UINT32)((INT64)seq + seq_adjust);
            tcp_header[4] = (UINT8)(seq >> 24);
            tcp_header[5] = (UINT8)(seq >> 16);
            tcp_header[6] = (UINT8)(seq >> 8);
            tcp_header[7] = (UINT8)(seq);
        }


        LONG32 ack_adjust = is_outbound ? entry->inbound_delta : entry->outbound_delta;
        if (ack_adjust != 0) {
            UINT32 ack = ((UINT32)tcp_header[8] << 24) | ((UINT32)tcp_header[9] << 16) |
                         ((UINT32)tcp_header[10] << 8) | tcp_header[11];
            ack = (UINT32)((INT64)ack + ack_adjust);
            tcp_header[8] = (UINT8)(ack >> 24);
            tcp_header[9] = (UINT8)(ack >> 16);
            tcp_header[10] = (UINT8)(ack >> 8);
            tcp_header[11] = (UINT8)(ack);
        }

        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
        return TRUE;
    }

    void record_size_change(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound, LONG32 delta) {
        if (delta == 0) return;
        SEQ_DELTA_ENTRY* entry = find_or_create(src_ip, dst_ip, src_port, dst_port);
        if (!entry) return;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);
        if (is_outbound) {
            entry->outbound_delta += delta;
        } else {
            entry->inbound_delta += delta;
        }
        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
    }

    void cleanup_expired() {
        LARGE_INTEGER now;
        LARGE_INTEGER freq;
        now = KeQueryPerformanceCounter(&freq);
        UINT64 threshold = (UINT64)freq.QuadPart * 120;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if ((now.QuadPart - e->last_activity) > threshold) {
                _InterlockedExchange(&e->active, 0);
            }
        }
        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
    }

    void handle_fin_rst(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if ((e->src_ip == src_ip && e->dst_ip == dst_ip &&
                 e->src_port == src_port && e->dst_port == dst_port) ||
                (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                 e->src_port == dst_port && e->dst_port == src_port)) {
                _InterlockedExchange(&e->active, 0);
                break;
            }
        }
        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
    }
}


namespace net_fragment {

    void init() {
        KeInitializeSpinLock(&net_capture::g_fragment_lock);
        SIZE_T alloc_size = (SIZE_T)MAX_FRAGMENT_ENTRIES * sizeof(FRAGMENT_ENTRY);
        net_capture::g_fragment_entries = (FRAGMENT_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, alloc_size, 'frNW');
        if (net_capture::g_fragment_entries) {
            strong::kmemset(net_capture::g_fragment_entries, 0, alloc_size);
        }
        NET_DBG("net_fragment::init: allocated %p (%llu bytes)", net_capture::g_fragment_entries, (ULONGLONG)alloc_size);
    }

    void cleanup() {
        if (net_capture::g_fragment_entries) {
            ExFreePoolWithTag(net_capture::g_fragment_entries, 'frNW');
            net_capture::g_fragment_entries = nullptr;
        }
    }

    void cleanup_expired() {
        if (!net_capture::g_fragment_entries) return;
        LARGE_INTEGER now;
        LARGE_INTEGER freq;
        now = KeQueryPerformanceCounter(&freq);
        UINT64 threshold = (UINT64)freq.QuadPart * 30;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_fragment_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_FRAGMENT_ENTRIES; i++) {
            FRAGMENT_ENTRY* e = &net_capture::g_fragment_entries[i];
            if (!e->active) continue;
            if ((now.QuadPart - e->first_seen) > threshold) {
                _InterlockedExchange(&e->active, 0);
            }
        }
        KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
    }

    UINT8* process_fragment(const UINT8* ip_header, UINT32 total_packet_len, UINT32* out_reassembled_len) {
        if (!ip_header || total_packet_len < 20 || !out_reassembled_len) return nullptr;
        if (!net_capture::g_fragment_entries) return nullptr;

        *out_reassembled_len = 0;

        UINT8 ver_ihl = ip_header[0];
        if ((ver_ihl >> 4) != 4) return nullptr;
        UINT32 ihl = (ver_ihl & 0x0F) * 4;
        if (ihl < 20 || ihl > total_packet_len) return nullptr;

        UINT16 total_length = ((UINT16)ip_header[2] << 8) | ip_header[3];
        UINT16 ip_id = ((UINT16)ip_header[4] << 8) | ip_header[5];
        UINT16 flags_frag = ((UINT16)ip_header[6] << 8) | ip_header[7];
        UINT16 frag_offset = (flags_frag & 0x1FFF) * 8;
        BOOLEAN more_fragments = (flags_frag & 0x2000) != 0;
        UINT8 protocol = ip_header[9];
        UINT32 src_ip = ((UINT32)ip_header[12] << 24) | ((UINT32)ip_header[13] << 16) |
                        ((UINT32)ip_header[14] << 8) | ip_header[15];
        UINT32 dst_ip = ((UINT32)ip_header[16] << 24) | ((UINT32)ip_header[17] << 16) |
                        ((UINT32)ip_header[18] << 8) | ip_header[19];

        UINT32 payload_len = total_length - ihl;
        if (payload_len == 0) return nullptr;
        if (frag_offset + payload_len > FRAGMENT_MAX_SIZE) return nullptr;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_fragment_lock, &old_irql);


        FRAGMENT_ENTRY* entry = nullptr;
        UINT32 free_idx = MAX_FRAGMENT_ENTRIES;
        for (UINT32 i = 0; i < MAX_FRAGMENT_ENTRIES; i++) {
            FRAGMENT_ENTRY* e = &net_capture::g_fragment_entries[i];
            if (e->active && e->ip_id == ip_id && e->src_ip == src_ip &&
                e->dst_ip == dst_ip && e->protocol == protocol) {
                entry = e;
                break;
            }
            if (!e->active && free_idx == MAX_FRAGMENT_ENTRIES) {
                free_idx = i;
            }
        }

        if (!entry) {
            if (free_idx >= MAX_FRAGMENT_ENTRIES) {
                KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
                return nullptr;
            }
            entry = &net_capture::g_fragment_entries[free_idx];
            strong::kmemset(entry, 0, sizeof(FRAGMENT_ENTRY));
            entry->ip_id = ip_id;
            entry->protocol = protocol;
            entry->src_ip = src_ip;
            entry->dst_ip = dst_ip;
            LARGE_INTEGER now;
            now = KeQueryPerformanceCounter(nullptr);
            entry->first_seen = now.QuadPart;
            _InterlockedExchange(&entry->active, 1);
        }


        strong::kmemcpy(entry->data + frag_offset, ip_header + ihl, payload_len);


        for (UINT32 b = frag_offset; b < frag_offset + payload_len; b++) {
            entry->received_map[b / 8] |= (1 << (b % 8));
        }

        UINT32 end_offset = frag_offset + payload_len;
        if (end_offset > entry->highest_offset)
            entry->highest_offset = end_offset;
        entry->total_received += payload_len;

        if (!more_fragments) {
            entry->last_fragment_seen = TRUE;
        }


        BOOLEAN complete = FALSE;
        if (entry->last_fragment_seen && entry->highest_offset > 0) {
            complete = TRUE;
            for (UINT32 b = 0; b < entry->highest_offset; b++) {
                if (!(entry->received_map[b / 8] & (1 << (b % 8)))) {
                    complete = FALSE;
                    break;
                }
            }
        }

        if (complete) {
            UINT32 reassembled_len = entry->highest_offset;
            UINT8* result = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, reassembled_len, 'rfNW');
            if (result) {
                strong::kmemcpy(result, entry->data, reassembled_len);
                *out_reassembled_len = reassembled_len;
            }
            _InterlockedExchange(&entry->active, 0);
            KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
            return result;
        }

        KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
        return nullptr;
    }
}


namespace net_udp_cache {

    static __forceinline UINT32 hash_flow(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        UINT32 h = src_ip ^ dst_ip ^ ((UINT32)src_port << 16) ^ dst_port;
        h = (h ^ (h >> 16)) * 0x45d9f3b;
        return (h ^ (h >> 16)) % MAX_UDP_FLOW_ENTRIES;
    }

    UINT32 lookup(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_udp_flow_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[i];
            if (!e->active) continue;
            if (e->src_ip == src_ip && e->dst_ip == dst_ip &&
                e->src_port == src_port && e->dst_port == dst_port) {
                UINT32 pid = e->pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return pid;
            }

            if (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                e->src_port == dst_port && e->dst_port == src_port) {
                UINT32 pid = e->pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return pid;
            }
        }
        KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
        return 0;
    }

    void store(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, UINT32 pid) {
        if (pid == 0) return;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_udp_flow_lock, &old_irql);


        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[i];
            if (!e->active) continue;
            if ((e->src_ip == src_ip && e->dst_ip == dst_ip &&
                 e->src_port == src_port && e->dst_port == dst_port) ||
                (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                 e->src_port == dst_port && e->dst_port == src_port)) {
                e->pid = pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return;
            }
        }


        UINT32 start = hash_flow(src_ip, dst_ip, src_port, dst_port);
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UINT32 idx = (start + i) % MAX_UDP_FLOW_ENTRIES;
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[idx];
            if (!e->active) {
                e->src_ip = src_ip;
                e->dst_ip = dst_ip;
                e->src_port = src_port;
                e->dst_port = dst_port;
                e->pid = pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeMemoryBarrier();
                _InterlockedExchange(&e->active, 1);
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return;
            }
        }


        UINT64 oldest_time = ~0ULL;
        UINT32 oldest_idx = 0;
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            if (net_capture::g_udp_flow[i].last_activity < oldest_time) {
                oldest_time = net_capture::g_udp_flow[i].last_activity;
                oldest_idx = i;
            }
        }
        UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[oldest_idx];
        e->src_ip = src_ip;
        e->dst_ip = dst_ip;
        e->src_port = src_port;
        e->dst_port = dst_port;
        e->pid = pid;
        LARGE_INTEGER now;
        now = KeQueryPerformanceCounter(nullptr);
        e->last_activity = now.QuadPart;
        KeMemoryBarrier();
        _InterlockedExchange(&e->active, 1);
        KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
    }

    void cleanup_expired() {
        LARGE_INTEGER now;
        LARGE_INTEGER freq;
        now = KeQueryPerformanceCounter(&freq);
        UINT64 threshold = (UINT64)freq.QuadPart * 60;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_udp_flow_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[i];
            if (!e->active) continue;
            if ((now.QuadPart - e->last_activity) > threshold) {
                _InterlockedExchange(&e->active, 0);
            }
        }
        KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
    }
}


namespace net_mod {

    typedef struct _ACTIVE_MOD_RULE {
        volatile LONG active;
        UINT32 rule_id;
        UINT32 direction;
        UINT32 protocol;
        UINT32 port;
        UINT32 pid;
        UINT32 pattern_size;
        UINT32 replace_size;
        UINT8  pattern[MOD_MAX_PATTERN];
        UINT8  replacement[MOD_MAX_REPLACE];
        volatile LONG match_count;
    } ACTIVE_MOD_RULE;

    inline ACTIVE_MOD_RULE g_mod_rules[MOD_MAX_RULES] = {};
    inline volatile LONG g_next_mod_id = 1;
    inline volatile LONG g_active_mod_count = 0;

    BOOLEAN has_active_rules() {
        return (g_active_mod_count != 0);
    }


    BOOLEAN apply_modifications(UINT8* data, UINT32* data_len, UINT32 max_len,
                                UINT32 direction, UINT32 protocol,
                                UINT32 port, UINT32 pid) {
        if (g_active_mod_count == 0) return FALSE;
        BOOLEAN modified = FALSE;

        for (UINT32 r = 0; r < MOD_MAX_RULES; r++) {
            if (g_mod_rules[r].active != 1) continue;
            ACTIVE_MOD_RULE* rule = &g_mod_rules[r];
            if (rule->direction != 2 && rule->direction != direction) continue;
            if (rule->protocol != 0 && rule->protocol != protocol) continue;
            if (rule->port != 0 && rule->port != port) continue;
            if (rule->pid != 0 && rule->pid != pid) continue;
            if (rule->pattern_size == 0 || rule->pattern_size > *data_len) continue;


            for (UINT32 i = 0; i + rule->pattern_size <= *data_len; i++) {
                BOOLEAN match = TRUE;
                for (UINT32 j = 0; j < rule->pattern_size; j++) {
                    if (data[i + j] != rule->pattern[j]) { match = FALSE; break; }
                }
                if (match) {

                    INT32 diff = (INT32)rule->replace_size - (INT32)rule->pattern_size;
                    UINT32 new_len = *data_len + diff;
                    if (new_len > max_len) continue;

                    if (diff != 0) {

                        UINT32 tail_start = i + rule->pattern_size;
                        UINT32 tail_len = *data_len - tail_start;
                        if (tail_len > 0) {

                            for (INT32 k = (diff > 0 ? (INT32)tail_len - 1 : 0);
                                 diff > 0 ? k >= 0 : (UINT32)k < tail_len;
                                 diff > 0 ? k-- : k++) {
                                data[tail_start + diff + k] = data[tail_start + k];
                            }
                        }
                    }
                    strong::kmemcpy(&data[i], rule->replacement, rule->replace_size);
                    *data_len = new_len;
                    _InterlockedIncrement(&rule->match_count);
                    modified = TRUE;
                    if (rule->replace_size > 0) i += rule->replace_size - 1;
                }
            }
        }
        return modified;
    }

    NTSTATUS handle_mod_rule(p_packet_mod_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_mod_rule: op=%u rule_id=%u dir=%u proto=%u port=%u pid=%u pat_sz=%u rep_sz=%u",
                request->operation, request->rule_id, request->direction,
                request->protocol, request->port, request->pid,
                request->pattern_size, request->replace_size);

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (_InterlockedCompareExchange(&g_mod_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&g_next_mod_id);
                    g_mod_rules[i].rule_id = id;
                    g_mod_rules[i].direction = request->direction;
                    g_mod_rules[i].protocol = request->protocol;
                    g_mod_rules[i].port = request->port;
                    g_mod_rules[i].pid = request->pid;
                    g_mod_rules[i].pattern_size = request->pattern_size;
                    g_mod_rules[i].replace_size = request->replace_size;
                    if (request->pattern_size > 0 && request->pattern_size <= MOD_MAX_PATTERN)
                        strong::kmemcpy(g_mod_rules[i].pattern, request->pattern, request->pattern_size);
                    if (request->replace_size > 0 && request->replace_size <= MOD_MAX_REPLACE)
                        strong::kmemcpy(g_mod_rules[i].replacement, request->replacement, request->replace_size);
                    g_mod_rules[i].match_count = 0;
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_mod_rules[i].active, 1);
                    _InterlockedIncrement(&g_active_mod_count);
                    request->rule_id = id;
                    request->active = 1;
                    NET_DBG("handle_mod_rule: ADDED rule slot=%u id=%u dir=%u proto=%u port=%u",
                            i, id, request->direction, request->protocol, request->port);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (g_mod_rules[i].active == 1 && g_mod_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&g_mod_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_mod_count);
                    request->active = 0;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 3: {
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (g_mod_rules[i].active == 1) {
                    _InterlockedExchange(&g_mod_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_mod_count);
                }
            }
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS handle_mod_rule_list(p_packet_mod_rule_list request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->rule_count = 0;
        for (UINT32 i = 0; i < MOD_MAX_RULES && request->rule_count < MOD_MAX_RULES; i++) {
            if (g_mod_rules[i].active == 1) {
                PACKET_MOD_RULE* out = &request->rules[request->rule_count];
                out->rule_id = g_mod_rules[i].rule_id;
                out->direction = g_mod_rules[i].direction;
                out->protocol = g_mod_rules[i].protocol;
                out->port = g_mod_rules[i].port;
                out->pid = g_mod_rules[i].pid;
                out->pattern_size = g_mod_rules[i].pattern_size;
                out->replace_size = g_mod_rules[i].replace_size;
                strong::kmemcpy(out->pattern, g_mod_rules[i].pattern, g_mod_rules[i].pattern_size);
                strong::kmemcpy(out->replacement, g_mod_rules[i].replacement, g_mod_rules[i].replace_size);
                out->match_count = g_mod_rules[i].match_count;
                out->active = 1;
                request->rule_count++;
            }
        }
        return STATUS_SUCCESS;
    }
}


namespace net_redirect {

    typedef struct _ACTIVE_REDIR_RULE {
        volatile LONG active;
        UINT32 rule_id;
        UINT32 protocol;
        UINT32 match_port;
        UINT8  match_addr[16];
        UINT32 redirect_port;
        UINT8  redirect_addr[16];
        UINT32 address_family;
        volatile LONG match_count;
        UINT32 exclude_pid;
    } ACTIVE_REDIR_RULE;

    inline ACTIVE_REDIR_RULE g_redir_rules[REDIR_MAX_RULES] = {};
    inline volatile LONG g_next_redir_id = 1;
    inline volatile LONG g_active_redir_count = 0;

    static BOOLEAN is_valid_redirect_add_request(p_traffic_redirect_rule request) {
        if (!request) return FALSE;
        if (request->address_family != AF_INET && request->address_family != AF_INET6) return FALSE;
        if (request->redirect_port == 0) return FALSE;
        if (net_capture::is_zero_ip(request->redirect_addr)) return FALSE;

        const BOOLEAN wildcard_match =
            request->protocol == 0 &&
            request->match_port == 0 &&
            net_capture::is_zero_ip(request->match_addr);
        if (wildcard_match) return FALSE;

        return TRUE;
    }

    BOOLEAN has_active_rules() {
        return (g_active_redir_count != 0);
    }


    BOOLEAN check_redirect(UINT32 protocol, UINT32 dst_port, const UINT8* dst_addr,
                           UINT32 af, UINT32 pid, UINT32* new_port, UINT8* new_addr) {
        if (g_active_redir_count == 0) return FALSE;
        for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
            if (g_redir_rules[i].active != 1) continue;
            ACTIVE_REDIR_RULE* r = &g_redir_rules[i];
            if (r->exclude_pid != 0 && r->exclude_pid == pid) continue;
            if (r->protocol != 0 && r->protocol != protocol) continue;
            if (r->match_port != 0 && r->match_port != dst_port) continue;
            if (!net_capture::is_zero_ip(r->match_addr)) {
                UINT8 mask[16];
                strong::kmemset(mask, 0xFF, sizeof(mask));
                if (!net_capture::ip_matches(dst_addr, r->match_addr, mask, af)) continue;
            }
            *new_port = r->redirect_port;
            strong::kmemcpy(new_addr, r->redirect_addr, 16);
            _InterlockedIncrement(&r->match_count);
            return TRUE;
        }
        return FALSE;
    }

    NTSTATUS handle_redirect_rule(p_traffic_redirect_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_redirect_rule: op=%u rule_id=%u proto=%u match_port=%u redir_port=%u af=%u excl_pid=%u",
                request->operation, request->rule_id, request->protocol,
                request->match_port, request->redirect_port,
                request->address_family, request->exclude_pid);

        switch (request->operation) {
        case 0: {
            if (!is_valid_redirect_add_request(request)) {
                NET_ERR("handle_redirect_rule: reject invalid add proto=%u match_port=%u redir_port=%u af=%u",
                        request->protocol, request->match_port,
                        request->redirect_port, request->address_family);
                return STATUS_INVALID_PARAMETER;
            }
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (_InterlockedCompareExchange(&g_redir_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&g_next_redir_id);
                    g_redir_rules[i].rule_id = id;
                    g_redir_rules[i].protocol = request->protocol;
                    g_redir_rules[i].match_port = request->match_port;
                    strong::kmemcpy(g_redir_rules[i].match_addr, request->match_addr, 16);
                    g_redir_rules[i].redirect_port = request->redirect_port;
                    strong::kmemcpy(g_redir_rules[i].redirect_addr, request->redirect_addr, 16);
                    g_redir_rules[i].address_family = request->address_family;
                    g_redir_rules[i].exclude_pid = request->exclude_pid;
                    g_redir_rules[i].match_count = 0;
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_redir_rules[i].active, 1);
                    _InterlockedIncrement(&g_active_redir_count);
                    request->rule_id = id;
                    request->active = 1;
                    NET_DBG("handle_redirect_rule: ADDED rule slot=%u id=%u proto=%u match_port=%u redir_port=%u",
                            i, id, request->protocol, request->match_port, request->redirect_port);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (g_redir_rules[i].active == 1 && g_redir_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&g_redir_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_redir_count);
                    request->active = 0;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 3: {
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (g_redir_rules[i].active == 1) {
                    _InterlockedExchange(&g_redir_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_redir_count);
                }
            }
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS handle_redirect_list(p_traffic_redirect_list request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->rule_count = 0;
        for (UINT32 i = 0; i < REDIR_MAX_RULES && request->rule_count < REDIR_MAX_RULES; i++) {
            if (g_redir_rules[i].active == 1) {
                TRAFFIC_REDIRECT_RULE* out = &request->rules[request->rule_count];
                out->rule_id = g_redir_rules[i].rule_id;
                out->protocol = g_redir_rules[i].protocol;
                out->match_port = g_redir_rules[i].match_port;
                strong::kmemcpy(out->match_addr, g_redir_rules[i].match_addr, 16);
                out->redirect_port = g_redir_rules[i].redirect_port;
                strong::kmemcpy(out->redirect_addr, g_redir_rules[i].redirect_addr, 16);
                out->address_family = g_redir_rules[i].address_family;
                out->match_count = g_redir_rules[i].match_count;
                out->active = 1;
                request->rule_count++;
            }
        }
        return STATUS_SUCCESS;
    }
}


namespace net_stream {


    #define MAX_TRACKED_STREAMS 1024

    typedef struct _TRACKED_STREAM {
        volatile LONG active;
        UINT32 src_port;
        UINT32 dst_port;
        UINT32 pid;
        UINT8  src_addr[16];
        UINT8  dst_addr[16];
        UINT32 stream_size;
        UINT32 total_packets;
        UINT32 truncated;
        UINT8* stream_data;
        KSPIN_LOCK lock;
    } TRACKED_STREAM;

    inline TRACKED_STREAM g_streams[MAX_TRACKED_STREAMS] = {};
    inline volatile LONG g_active_stream_count = 0;

    BOOLEAN has_active_streams() {
        return (g_active_stream_count != 0);
    }


    void feed_packet(UINT32 src_port, UINT32 dst_port, UINT32 pid,
                     const UINT8* src_addr, const UINT8* dst_addr,
                     const UINT8* data, UINT32 data_len) {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            if (g_streams[i].active != 1) continue;

            BOOLEAN match = FALSE;
            BOOLEAN src_addr_wildcard = net_capture::is_zero_ip(g_streams[i].src_addr);
            BOOLEAN dst_addr_wildcard = net_capture::is_zero_ip(g_streams[i].dst_addr);

            BOOLEAN forward_port_match =
                (g_streams[i].src_port == 0 || g_streams[i].src_port == src_port) &&
                (g_streams[i].dst_port == 0 || g_streams[i].dst_port == dst_port);
            if (forward_port_match) {
                BOOLEAN addr_match = TRUE;
                if (!src_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].src_addr[j] != src_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match && !dst_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].dst_addr[j] != dst_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match) match = TRUE;
            }

            BOOLEAN reverse_port_match =
                (g_streams[i].src_port == 0 || g_streams[i].src_port == dst_port) &&
                (g_streams[i].dst_port == 0 || g_streams[i].dst_port == src_port);
            if (!match && reverse_port_match) {
                BOOLEAN addr_match = TRUE;
                if (!src_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].src_addr[j] != dst_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match && !dst_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].dst_addr[j] != src_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match) match = TRUE;
            }
            if (g_streams[i].pid != 0 && g_streams[i].pid != pid) match = FALSE;

            if (match && g_streams[i].stream_data && data_len > 0) {
                KIRQL irql;
                KeAcquireSpinLock(&g_streams[i].lock, &irql);
                if (g_streams[i].stream_data) {
                    UINT32 avail = STREAM_MAX_SIZE - g_streams[i].stream_size;
                    if (avail > 0) {
                        UINT32 copy = data_len < avail ? data_len : avail;
                        strong::kmemcpy(g_streams[i].stream_data + g_streams[i].stream_size, data, copy);
                        g_streams[i].stream_size += copy;
                        if (copy < data_len) g_streams[i].truncated = 1;
                    } else {
                        g_streams[i].truncated = 1;
                    }
                    g_streams[i].total_packets++;
                }
                KeReleaseSpinLock(&g_streams[i].lock, irql);
            }
        }
    }

    NTSTATUS handle_stream(p_stream_reassemble_request request) {
        if (!request) {
            WW_LOG("netaction::net_stream::handle_stream NULL_REQUEST");
            return STATUS_INVALID_PARAMETER;
        }

        WW_LOG("netaction::net_stream::handle_stream op=%u src_port=%u dst_port=%u pid=%u active_count=%ld",
            request->operation, request->src_port, request->dst_port, request->pid,
            _InterlockedCompareExchange(&g_active_stream_count, 0, 0));
        NET_DBG("handle_stream: op=%u src_port=%u dst_port=%u pid=%u",
                request->operation, request->src_port, request->dst_port, request->pid);

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (_InterlockedCompareExchange(&g_streams[i].active, 2, 0) == 0) {
                    g_streams[i].src_port = request->src_port;
                    g_streams[i].dst_port = request->dst_port;
                    g_streams[i].pid = request->pid;
                    strong::kmemcpy(g_streams[i].src_addr, request->src_addr, 16);
                    strong::kmemcpy(g_streams[i].dst_addr, request->dst_addr, 16);
                    g_streams[i].stream_size = 0;
                    g_streams[i].total_packets = 0;
                    g_streams[i].truncated = 0;
                    if (!g_streams[i].stream_data) {
                        g_streams[i].stream_data = (UINT8*)ExAllocatePool2(
                            POOL_FLAG_NON_PAGED, STREAM_MAX_SIZE, 'stNW');
                        if (!g_streams[i].stream_data) {
                            WW_LOG("netaction::net_stream::handle_stream[start] alloc_failed slot=%u status=STATUS_INSUFFICIENT_RESOURCES", i);
                            _InterlockedExchange(&g_streams[i].active, 0);
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }
                    }
                    strong::kmemset(g_streams[i].stream_data, 0, STREAM_MAX_SIZE);
                    KeInitializeSpinLock(&g_streams[i].lock);
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_streams[i].active, 1);
                    _InterlockedIncrement(&g_active_stream_count);
                    WW_LOG("netaction::net_stream::handle_stream[start] OK slot=%u src_port=%u dst_port=%u pid=%u",
                        i, request->src_port, request->dst_port, request->pid);
                    NET_DBG("handle_stream[start]: slot=%u src_port=%u dst_port=%u pid=%u",
                            i, request->src_port, request->dst_port, request->pid);
                    return STATUS_SUCCESS;
                }
            }
            WW_LOG("netaction::net_stream::handle_stream[start] no_free_slot active=%ld status=STATUS_INSUFFICIENT_RESOURCES",
                _InterlockedCompareExchange(&g_active_stream_count, 0, 0));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active == 1 &&
                    g_streams[i].src_port == request->src_port &&
                    g_streams[i].dst_port == request->dst_port) {
                    _InterlockedExchange(&g_streams[i].active, 0);
                    _InterlockedDecrement(&g_active_stream_count);
                    WW_LOG("netaction::net_stream::handle_stream[stop] OK slot=%u src_port=%u dst_port=%u",
                        i, request->src_port, request->dst_port);
                    return STATUS_SUCCESS;
                }
            }
            WW_LOG("netaction::net_stream::handle_stream[stop] not_found src_port=%u dst_port=%u status=STATUS_NOT_FOUND",
                request->src_port, request->dst_port);
            return STATUS_NOT_FOUND;
        }
        case 2: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active == 1 &&
                    g_streams[i].src_port == request->src_port &&
                    g_streams[i].dst_port == request->dst_port) {
                    KIRQL irql;
                    KeAcquireSpinLock(&g_streams[i].lock, &irql);
                    UINT32 copy = g_streams[i].stream_size;
                    if (copy > STREAM_MAX_SIZE) copy = STREAM_MAX_SIZE;
                    strong::kmemcpy(request->stream_data, g_streams[i].stream_data, copy);
                    request->stream_size = g_streams[i].stream_size;
                    request->total_packets = g_streams[i].total_packets;
                    request->truncated = g_streams[i].truncated;
                    KeReleaseSpinLock(&g_streams[i].lock, irql);
                    WW_LOG("netaction::net_stream::handle_stream[get] OK slot=%u stream_size=%u total_packets=%u truncated=%u",
                        i, request->stream_size, request->total_packets, request->truncated);
                    return STATUS_SUCCESS;
                }
            }
            WW_LOG("netaction::net_stream::handle_stream[get] not_found src_port=%u dst_port=%u active_count=%ld status=STATUS_NOT_FOUND",
                request->src_port, request->dst_port,
                _InterlockedCompareExchange(&g_active_stream_count, 0, 0));
            return STATUS_NOT_FOUND;
        }
        case 3: {
            request->stream_count = 0;
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active == 1) request->stream_count++;
            }
            WW_LOG("netaction::net_stream::handle_stream[count] OK count=%u", request->stream_count);
            return STATUS_SUCCESS;
        }
        case 4: {
            UINT32 cleared = 0;
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (_InterlockedExchange(&g_streams[i].active, 0) == 1)
                    cleared++;
                g_streams[i].src_port = 0;
                g_streams[i].dst_port = 0;
                g_streams[i].pid = 0;
                g_streams[i].stream_size = 0;
                g_streams[i].total_packets = 0;
                g_streams[i].truncated = 0;
                strong::kmemset(g_streams[i].src_addr, 0, sizeof(g_streams[i].src_addr));
                strong::kmemset(g_streams[i].dst_addr, 0, sizeof(g_streams[i].dst_addr));
            }
            _InterlockedExchange(&g_active_stream_count, 0);
            request->stream_count = 0;
            WW_LOG("netaction::net_stream::handle_stream[clear] OK cleared=%u", cleared);
            return STATUS_SUCCESS;
        }
        default:
            WW_LOG("netaction::net_stream::handle_stream invalid_operation op=%u status=STATUS_INVALID_PARAMETER",
                request->operation);
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            _InterlockedExchange(&g_streams[i].active, 0);
            if (g_streams[i].stream_data) {
                KIRQL irql;
                KeAcquireSpinLock(&g_streams[i].lock, &irql);
                UINT8* data = g_streams[i].stream_data;
                g_streams[i].stream_data = nullptr;
                KeReleaseSpinLock(&g_streams[i].lock, irql);
                if (data) {
                    ExFreePoolWithTag(data, 'stNW');
                }
            }
        }
        _InterlockedExchange(&g_active_stream_count, 0);
    }
}


namespace net_dpi {


    inline DPI_HEADER_INFO* g_dpi_ring = nullptr;
    inline volatile LONG g_dpi_head = 0;
    inline volatile LONG g_dpi_tail = 0;
    inline volatile LONG g_dpi_count = 0;
    inline KSPIN_LOCK g_dpi_lock;
    inline volatile LONG g_dpi_active = 0;

    BOOLEAN is_active() {
        return (g_dpi_active != 0);
    }

    #define DPI_RING_SIZE 256

    NTSTATUS init() {
        if (g_dpi_ring) return STATUS_SUCCESS;
        SIZE_T sz = (SIZE_T)DPI_RING_SIZE * sizeof(DPI_HEADER_INFO);
        g_dpi_ring = (DPI_HEADER_INFO*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, 'dpNW');
        if (!g_dpi_ring) return STATUS_INSUFFICIENT_RESOURCES;
        strong::kmemset(g_dpi_ring, 0, sz);
        KeInitializeSpinLock(&g_dpi_lock);
        return STATUS_SUCCESS;
    }


    static UINT32 detect_http_method(const UINT8* data, UINT32 len) {
        if (len < 4) return 0;
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
        if (len >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ') return 2;
        if (len >= 4 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return 3;
        if (len >= 7 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L') return 4;
        if (len >= 5 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ') return 5;
        if (len >= 5 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && data[4] == '/') return 6;
        return 0;
    }


    static void extract_http_host(const UINT8* data, UINT32 len, char* out, UINT32 out_size) {
        out[0] = 0;

        for (UINT32 i = 0; i + 6 < len; i++) {
            if ((data[i] == 'H' || data[i] == 'h') &&
                (data[i+1] == 'o' || data[i+1] == 'O') &&
                (data[i+2] == 's' || data[i+2] == 'S') &&
                (data[i+3] == 't' || data[i+3] == 'T') &&
                data[i+4] == ':' && data[i+5] == ' ') {
                UINT32 j = i + 6;
                UINT32 k = 0;
                while (j < len && data[j] != '\r' && data[j] != '\n' && k < out_size - 1) {
                    out[k++] = (char)data[j++];
                }
                out[k] = 0;
                return;
            }
        }
    }


    static void extract_http_path(const UINT8* data, UINT32 len, char* out, UINT32 out_size) {
        out[0] = 0;

        UINT32 i = 0;
        while (i < len && data[i] != ' ') i++;
        if (i >= len) return;
        i++;
        UINT32 k = 0;
        while (i < len && data[i] != ' ' && data[i] != '\r' && data[i] != '\n' && k < out_size - 1) {
            out[k++] = (char)data[i++];
        }
        out[k] = 0;
    }


    static void detect_tls(const UINT8* data, UINT32 len, DPI_HEADER_INFO* info) {
        if (len < 5) return;

        UINT8 content_type = data[0];
        if (content_type < 20 || content_type > 23) return;

        UINT16 version = ((UINT16)data[1] << 8) | data[2];

        if (version < 0x0300 || version > 0x0304) return;

        info->is_tls = 1;
        info->tls_version = version;
        info->tls_content_type = content_type;


        if (content_type == 22 && len > 43) {
            UINT8 handshake_type = data[5];
            if (handshake_type == 1) {

                UINT32 pos = 43;
                if (pos >= len) return;
                UINT8 session_id_len = data[pos];
                pos += 1 + session_id_len;
                if (pos + 2 >= len) return;

                UINT16 cs_len = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 2 + cs_len;
                if (pos + 1 >= len) return;

                UINT8 comp_len = data[pos];
                pos += 1 + comp_len;
                if (pos + 2 >= len) return;

                UINT16 ext_len = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 2;
                UINT32 ext_end = pos + ext_len;
                while (pos + 4 <= ext_end && pos + 4 <= len) {
                    UINT16 ext_type = ((UINT16)data[pos] << 8) | data[pos + 1];
                    UINT16 elen = ((UINT16)data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                    if (ext_type == 0 && elen > 5 && pos + elen <= len) {

                        UINT32 sni_pos = pos + 2 + 1;
                        if (sni_pos + 2 >= len) break;
                        UINT16 name_len = ((UINT16)data[sni_pos] << 8) | data[sni_pos + 1];
                        sni_pos += 2;
                        if (sni_pos + name_len <= len && name_len < 128) {
                            for (UINT16 s = 0; s < name_len; s++)
                                info->tls_sni[s] = (char)data[sni_pos + s];
                            info->tls_sni[name_len] = 0;
                        }
                        break;
                    }
                    pos += elen;
                }
            }
        }
    }


    void analyze_packet(UINT64 timestamp, UINT32 direction, UINT32 protocol,
                        UINT32 src_port, UINT32 dst_port,
                        const UINT8* src_addr, const UINT8* dst_addr,
                        UINT32 af, UINT32 pid,
                        const UINT8* payload, UINT32 payload_len) {
        if (!g_dpi_active || !g_dpi_ring) return;

        DPI_HEADER_INFO info;
        strong::kmemset(&info, 0, sizeof(info));
        info.timestamp = timestamp;
        info.direction = direction;
        info.protocol = protocol;
        info.src_port = src_port;
        info.dst_port = dst_port;
        info.address_family = af;
        info.pid = pid;
        info.payload_size = payload_len;
        strong::kmemcpy(info.src_addr, src_addr, (af == 23) ? 16 : 4);
        strong::kmemcpy(info.dst_addr, dst_addr, (af == 23) ? 16 : 4);


        if (protocol == 6 && payload_len >= 20) {
            info.tcp_seq = ((UINT32)payload[4] << 24) | ((UINT32)payload[5] << 16) |
                           ((UINT32)payload[6] << 8) | payload[7];
            info.tcp_ack = ((UINT32)payload[8] << 24) | ((UINT32)payload[9] << 16) |
                           ((UINT32)payload[10] << 8) | payload[11];
            info.tcp_flags = payload[13];
            info.tcp_window = ((UINT32)payload[14] << 8) | payload[15];

            UINT32 tcp_hdr_len = ((payload[12] >> 4) & 0xF) * 4;
            if (tcp_hdr_len >= 20 && tcp_hdr_len <= payload_len) {
                const UINT8* app_data = payload + tcp_hdr_len;
                UINT32 app_len = payload_len - tcp_hdr_len;


                info.http_method = detect_http_method(app_data, app_len);
                if (info.http_method) {
                    info.is_http = 1;
                    extract_http_host(app_data, app_len, info.http_host, sizeof(info.http_host));
                    extract_http_path(app_data, app_len, info.http_path, sizeof(info.http_path));
                }


                detect_tls(app_data, app_len, &info);


                if ((src_port == 53 || dst_port == 53) && app_len > 0) {
                    info.is_dns = 1;
                }
            }
        }


        if (protocol == 17 && (src_port == 53 || dst_port == 53) && payload_len > 0) {
            info.is_dns = 1;
        }


        if (protocol == 17 && payload_len >= 13) {
            UINT8 ct = payload[0];
            if (ct >= 20 && ct <= 25) {
                UINT16 ver = ((UINT16)payload[1] << 8) | payload[2];
                if (ver == 0xFEFF || ver == 0xFEFD) {
                    info.is_tls = 1;
                    info.tls_content_type = ct;
                    info.tls_version = ver;
                }
            }
        }

        KIRQL irql;
        KeAcquireSpinLock(&g_dpi_lock, &irql);
        if (g_dpi_count >= DPI_RING_SIZE) {
            g_dpi_tail = (g_dpi_tail + 1) % DPI_RING_SIZE;
            g_dpi_count--;
        }
        strong::kmemcpy(&g_dpi_ring[g_dpi_head], &info, sizeof(info));
        g_dpi_head = (g_dpi_head + 1) % DPI_RING_SIZE;
        g_dpi_count++;
        KeReleaseSpinLock(&g_dpi_lock, irql);
    }

    NTSTATUS get_results(p_dpi_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        if (!g_dpi_ring) {
            NTSTATUS st = init();
            if (!NT_SUCCESS(st)) return st;
        }
        request->result_count = 0;
        KIRQL irql;
        KeAcquireSpinLock(&g_dpi_lock, &irql);

        LONG entries_to_scan = g_dpi_count;
        UINT32 idx = g_dpi_tail;
        LONG scanned = 0;
        while (scanned < entries_to_scan && request->result_count < DPI_MAX_RESULTS) {
            DPI_HEADER_INFO* src = &g_dpi_ring[idx];


            if (request->filter_pid != 0 && src->pid != request->filter_pid) goto next;
            if (request->filter_protocol != 0 && src->protocol != request->filter_protocol) goto next;
            if (request->filter_port != 0 && src->src_port != request->filter_port &&
                src->dst_port != request->filter_port) goto next;
            if (request->flags & 1) { if (!src->is_http) goto next; }
            if (request->flags & 2) { if (!src->is_tls) goto next; }
            if (request->flags & 4) { if (!src->is_dns) goto next; }

            strong::kmemcpy(&request->results[request->result_count], src, sizeof(DPI_HEADER_INFO));
            request->result_count++;

        next:
            idx = (idx + 1) % DPI_RING_SIZE;
            scanned++;
        }
        KeReleaseSpinLock(&g_dpi_lock, irql);
        return STATUS_SUCCESS;
    }

    void cleanup() {
        _InterlockedExchange(&g_dpi_active, 0);
        if (g_dpi_ring) {
            ExFreePoolWithTag(g_dpi_ring, 'dpNW');
            g_dpi_ring = nullptr;
        }
    }
}


namespace net_intercept {

    inline HELD_PACKET g_held[INTERCEPT_MAX_HELD] = {};
    inline volatile LONG g_held_count = 0;
    inline volatile LONG g_intercepting = 0;
    inline volatile LONG g_next_hold_id = 1;
    inline UINT32 g_filter_pid = 0;
    inline UINT32 g_filter_port = 0;
    inline UINT32 g_filter_protocol = 0;
    inline KSPIN_LOCK g_intercept_lock;

    BOOLEAN is_active() {
        return (g_intercepting != 0);
    }

    void init_lock() {
        KeInitializeSpinLock(&g_intercept_lock);
    }


    BOOLEAN try_hold_packet(UINT32 direction, UINT32 protocol,
                            UINT32 src_port, UINT32 dst_port,
                            const UINT8* src_addr, const UINT8* dst_addr,
                            UINT32 af, UINT32 pid,
                            const UINT8* payload, UINT32 payload_len) {
        if (!g_intercepting) return FALSE;
        if (g_filter_pid != 0 && pid != g_filter_pid) return FALSE;
        if (g_filter_port != 0 && src_port != g_filter_port && dst_port != g_filter_port) return FALSE;
        if (g_filter_protocol != 0 && protocol != g_filter_protocol) return FALSE;

        KIRQL irql;
        KeAcquireSpinLock(&g_intercept_lock, &irql);

        if (g_held_count >= INTERCEPT_MAX_HELD) {
            KeReleaseSpinLock(&g_intercept_lock, irql);
            return FALSE;
        }


        for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
            if (g_held[i].hold_id == 0) {
                g_held[i].hold_id = (UINT64)_InterlockedIncrement(&g_next_hold_id);
                LARGE_INTEGER ts;
                KeQuerySystemTime(&ts);
                g_held[i].timestamp = ts.QuadPart;
                g_held[i].direction = direction;
                g_held[i].protocol = protocol;
                g_held[i].src_port = src_port;
                g_held[i].dst_port = dst_port;
                strong::kmemcpy(g_held[i].src_addr, src_addr, 16);
                strong::kmemcpy(g_held[i].dst_addr, dst_addr, 16);
                g_held[i].pid = pid;
                g_held[i].address_family = af;
                UINT32 cap = payload_len < INTERCEPT_MAX_PAYLOAD ? payload_len : INTERCEPT_MAX_PAYLOAD;
                g_held[i].payload_size = cap;
                if (payload && cap > 0)
                    strong::kmemcpy(g_held[i].payload, payload, cap);
                g_held_count++;
                KeReleaseSpinLock(&g_intercept_lock, irql);
                return TRUE;
            }
        }

        KeReleaseSpinLock(&g_intercept_lock, irql);
        return FALSE;
    }

    NTSTATUS handle_intercept(p_intercept_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: {
            if (request->filter_pid == 0 && request->filter_port == 0 &&
                request->filter_protocol == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            g_filter_pid = request->filter_pid;
            g_filter_port = request->filter_port;
            g_filter_protocol = request->filter_protocol;
            _InterlockedExchange(&g_intercepting, 1);
            request->intercepting = 1;
            request->held_count = g_held_count;
            return STATUS_SUCCESS;
        }
        case 1: {
            _InterlockedExchange(&g_intercepting, 0);
            g_filter_pid = 0;
            g_filter_port = 0;
            g_filter_protocol = 0;

            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                g_held[i].hold_id = 0;
            }
            g_held_count = 0;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            request->intercepting = 0;
            request->held_count = 0;
            return STATUS_SUCCESS;
        }
        case 2: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            request->held_count = 0;
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id != 0 && request->held_count < INTERCEPT_MAX_HELD) {
                    strong::kmemcpy(&request->held_packets[request->held_count],
                                    &g_held[i], sizeof(HELD_PACKET));
                    request->held_count++;
                }
            }
            request->intercepting = g_intercepting;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            return STATUS_SUCCESS;
        }
        case 3: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            packet_inject_request inj = {};
            BOOLEAN do_inject = FALSE;
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {

                    if (net_inject::g_inject_handle_v4 && g_held[i].payload_size > 0) {
                        inj.direction = g_held[i].direction;
                        inj.protocol = g_held[i].protocol;
                        inj.address_family = g_held[i].address_family;
                        inj.src_port = g_held[i].src_port;
                        inj.dst_port = g_held[i].dst_port;
                        strong::kmemcpy(inj.src_addr, g_held[i].src_addr, 16);
                        strong::kmemcpy(inj.dst_addr, g_held[i].dst_addr, 16);
                        inj.payload_size = g_held[i].payload_size;
                        strong::kmemcpy(inj.payload, g_held[i].payload, g_held[i].payload_size);
                        do_inject = TRUE;
                    }
                    g_held[i].hold_id = 0;
                    strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
                    if (g_held_count > 0) g_held_count--;
                    break;
                }
            }
            request->held_count = g_held_count;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            if (do_inject) {
                net_inject::inject_packet(&inj);
            }
            return STATUS_SUCCESS;
        }
        case 4: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {
                    g_held[i].hold_id = 0;
                    strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
                    if (g_held_count > 0) g_held_count--;
                    break;
                }
            }
            request->held_count = g_held_count;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            return STATUS_SUCCESS;
        }
        case 5: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            packet_inject_request inj = {};
            BOOLEAN do_inject = FALSE;
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {

                    if (net_inject::g_inject_handle_v4 && request->modify_payload_size > 0 &&
                        request->modify_payload_size <= INTERCEPT_MAX_PAYLOAD) {
                        inj.direction = g_held[i].direction;
                        inj.protocol = g_held[i].protocol;
                        inj.address_family = g_held[i].address_family;
                        inj.src_port = g_held[i].src_port;
                        inj.dst_port = g_held[i].dst_port;
                        strong::kmemcpy(inj.src_addr, g_held[i].src_addr, 16);
                        strong::kmemcpy(inj.dst_addr, g_held[i].dst_addr, 16);
                        inj.payload_size = request->modify_payload_size;
                        strong::kmemcpy(inj.payload, request->modify_payload, request->modify_payload_size);
                        do_inject = TRUE;
                    }
                    g_held[i].hold_id = 0;
                    strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
                    if (g_held_count > 0) g_held_count--;
                    break;
                }
            }
            request->held_count = g_held_count;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            if (do_inject) {
                net_inject::inject_packet(&inj);
            }
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        _InterlockedExchange(&g_intercepting, 0);
        g_filter_pid = 0;
        g_filter_port = 0;
        g_filter_protocol = 0;

        KIRQL irql;
        KeAcquireSpinLock(&g_intercept_lock, &irql);
        for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
            strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
        }
        g_held_count = 0;
        KeReleaseSpinLock(&g_intercept_lock, irql);
    }
}


namespace net_kill {

    typedef struct _TCP_RESET_CANDIDATES {
        BOOLEAN have_forward;
        BOOLEAN have_reverse;
        DPI_HEADER_INFO forward;
        DPI_HEADER_INFO reverse;
    } TCP_RESET_CANDIDATES;

    static __forceinline UINT32 tuple_addr_len(UINT32 address_family) {
        return (address_family == AF_INET6) ? 16u : 4u;
    }

    static BOOLEAN request_ip_is_zero(const UINT8* ip, UINT32 address_family) {
        UINT32 len = tuple_addr_len(address_family);
        for (UINT32 i = 0; i < len; i++) {
            if (ip[i] != 0) {
                return FALSE;
            }
        }
        return TRUE;
    }

    static BOOLEAN tuple_ip_matches(const UINT8* actual,
                                    const UINT8* expected,
                                    UINT32 address_family) {
        if (!actual || !expected) {
            return FALSE;
        }

        if (request_ip_is_zero(expected, address_family)) {
            return TRUE;
        }

        UINT32 len = tuple_addr_len(address_family);
        if (aida_ip_bytes_equal(actual, expected, len)) {
            return TRUE;
        }

        if (address_family == AF_INET && len == 4) {
            UINT8 swapped[4] = { actual[3], actual[2], actual[1], actual[0] };
            return aida_ip_bytes_equal(swapped, expected, 4);
        }

        return FALSE;
    }

    static BOOLEAN dpi_tuple_matches_request(const DPI_HEADER_INFO* info,
                                             const conn_kill_request* request,
                                             BOOLEAN reverse) {
        if (!info || !request || info->protocol != IPPROTO_TCP) {
            return FALSE;
        }

        UINT32 address_family = request->address_family != 0 ? request->address_family : info->address_family;
        if (!reverse) {
            if (request->src_port != 0 && info->src_port != request->src_port) return FALSE;
            if (request->dst_port != 0 && info->dst_port != request->dst_port) return FALSE;
            if (!tuple_ip_matches(info->src_addr, request->src_addr, address_family)) return FALSE;
            if (!tuple_ip_matches(info->dst_addr, request->dst_addr, address_family)) return FALSE;
        } else {
            if (request->src_port != 0 && info->dst_port != request->src_port) return FALSE;
            if (request->dst_port != 0 && info->src_port != request->dst_port) return FALSE;
            if (!tuple_ip_matches(info->dst_addr, request->src_addr, address_family)) return FALSE;
            if (!tuple_ip_matches(info->src_addr, request->dst_addr, address_family)) return FALSE;
        }

        return TRUE;
    }

    static BOOLEAN find_recent_reset_candidates(p_conn_kill_request request,
                                                TCP_RESET_CANDIDATES* out) {
        if (!request || !out || !net_dpi::g_dpi_ring || net_dpi::g_dpi_count <= 0) {
            return FALSE;
        }

        strong::kmemset(out, 0, sizeof(*out));

        KIRQL irql;
        KeAcquireSpinLock(&net_dpi::g_dpi_lock, &irql);

        LONG entries = net_dpi::g_dpi_count;
        LONG idx = net_dpi::g_dpi_head;
        for (LONG scanned = 0; scanned < entries && (!out->have_forward || !out->have_reverse); scanned++) {
            if (idx == 0) {
                idx = DPI_RING_SIZE;
            }
            idx--;

            const DPI_HEADER_INFO* info = &net_dpi::g_dpi_ring[idx];
            if (!out->have_forward && dpi_tuple_matches_request(info, request, FALSE)) {
                strong::kmemcpy(&out->forward, info, sizeof(*info));
                out->have_forward = TRUE;
            }
            if (!out->have_reverse && dpi_tuple_matches_request(info, request, TRUE)) {
                strong::kmemcpy(&out->reverse, info, sizeof(*info));
                out->have_reverse = TRUE;
            }
        }

        KeReleaseSpinLock(&net_dpi::g_dpi_lock, irql);

        if (!out->have_forward && !out->have_reverse) {
            KIRQL dbg_irql;
            KeAcquireSpinLock(&net_dpi::g_dpi_lock, &dbg_irql);
            LONG dbg_entries = net_dpi::g_dpi_count;
            LONG dbg_idx = net_dpi::g_dpi_head;
            UINT32 dumped = 0;
            for (LONG scanned = 0; scanned < dbg_entries && dumped < 6; scanned++) {
                if (dbg_idx == 0) {
                    dbg_idx = DPI_RING_SIZE;
                }
                dbg_idx--;

                const DPI_HEADER_INFO* info = &net_dpi::g_dpi_ring[dbg_idx];
                if (info->protocol != IPPROTO_TCP) {
                    continue;
                }

                if (info->address_family == AF_INET) {
                } else {
                }

                dumped++;
            }
            KeReleaseSpinLock(&net_dpi::g_dpi_lock, dbg_irql);
        }

        return out->have_forward || out->have_reverse;
    }

    static NTSTATUS inject_reset_from_dpi_entry(const DPI_HEADER_INFO* info,
                                                UINT32 direction) {
        if (!info || (info->tcp_flags & 0x10u) == 0 || info->tcp_ack == 0) {
            return STATUS_NOT_FOUND;
        }

        packet_inject_request inj = {};
        inj.direction = direction;
        inj.protocol = IPPROTO_TCP;
        inj.address_family = info->address_family;
        inj.src_port = info->dst_port;
        inj.dst_port = info->src_port;
        inj.payload_size = 0;
        inj.tcp_flags = 0x04;
        inj.tcp_seq = info->tcp_ack;
        inj.tcp_ack = 0;
        strong::kmemcpy(inj.src_addr, info->dst_addr, 16);
        strong::kmemcpy(inj.dst_addr, info->src_addr, 16);
        return net_inject::inject_packet(&inj);
    }

    static NTSTATUS inject_tcp_reset_fallback(p_conn_kill_request request) {
        TCP_RESET_CANDIDATES candidates = {};
        if (!find_recent_reset_candidates(request, &candidates)) {
            return STATUS_NOT_FOUND;
        }

        NTSTATUS last_status = STATUS_NOT_FOUND;
        BOOLEAN injected = FALSE;

        if (candidates.have_forward) {
            last_status = inject_reset_from_dpi_entry(&candidates.forward, 0);
            if (NT_SUCCESS(last_status)) {
                injected = TRUE;
            } else {
            }
        }

        if (candidates.have_reverse) {
            NTSTATUS reverse_status = inject_reset_from_dpi_entry(&candidates.reverse, 1);
            if (NT_SUCCESS(reverse_status)) {
                injected = TRUE;
            } else {
                if (!NT_SUCCESS(last_status)) {
                    last_status = reverse_status;
                }
            }
        }

        return injected ? STATUS_SUCCESS : last_status;
    }

    static BOOLEAN socket_matches_kill_request(const SOCKET_HANDLE_ENTRY* socket_info,
                                               const conn_kill_request* request) {
        if (!socket_info || !request)
            return FALSE;

        if (request->protocol != 0 && socket_info->protocol != 0 && socket_info->protocol != request->protocol)
            return FALSE;

        BOOLEAN src_match = FALSE;
        BOOLEAN dst_match = FALSE;
        if (request->src_port != 0) {
            src_match = (socket_info->local_port == request->src_port) ||
                        (socket_info->remote_port == request->src_port);
        }
        if (request->dst_port != 0) {
            dst_match = (socket_info->local_port == request->dst_port) ||
                        (socket_info->remote_port == request->dst_port);
        }

        if (request->src_port != 0 && request->dst_port != 0) {
            if (src_match && dst_match)
                return TRUE;

            if ((src_match || dst_match) &&
                (socket_info->local_port == 0 || socket_info->remote_port == 0)) {
                return TRUE;
            }

            return FALSE;
        }

        if (request->src_port != 0)
            return src_match;
        if (request->dst_port != 0)
            return dst_match;

        return TRUE;
    }


    static UINT32 resolve_owner_pid_by_tuple(p_conn_kill_request request) {
        if (!request)
            return 0;


        if (request->protocol == 6 && net_enum::resolve_nsi()) {
            UINT32 tcp_capacity = 4096;
            UINT32 tcp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                tcp_count = tcp_capacity;
                ULONG key_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_KEY);
                ULONG sta_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_STATIC);

                buf = static_cast<UINT8*>(
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'klNW'));
                if (!buf) break;

                auto* keys = reinterpret_cast<net_enum::NSI_TCP_KEY*>(buf);
                auto* stats = reinterpret_cast<net_enum::NSI_TCP_STATIC*>(buf + key_sz);


                st = net_enum::_NsiEnumerate(
                    net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_TCP_MODULEID,
                    3, keys, sizeof(net_enum::NSI_TCP_KEY),
                    nullptr, 0,
                    nullptr, 0,
                    stats, sizeof(net_enum::NSI_TCP_STATIC),
                    &tcp_count);


                if (NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW ||
                    st == STATUS_BUFFER_TOO_SMALL || st == static_cast<NTSTATUS>(0xC0000023)) {
                    for (UINT32 i = 0; i < tcp_count; i++) {
                        UINT32 lport = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                        UINT32 rport = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);

                        BOOLEAN match = TRUE;
                        if (request->src_port != 0 && lport != request->src_port) match = FALSE;
                        if (match && request->dst_port != 0 && rport != request->dst_port) match = FALSE;

                        if (match && static_cast<UINT32>(stats[i].mod_pid) != 0) {
                            UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                            ExFreePoolWithTag(buf, 'klNW');
                            return pid;
                        }
                    }
                }

                if (NT_SUCCESS(st)) {
                    ExFreePoolWithTag(buf, 'klNW');
                    break;
                }

                ExFreePoolWithTag(buf, 'klNW');
                buf = nullptr;
                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (next == tcp_capacity) break;
                    tcp_capacity = next;
                    continue;
                }
                break;
            }
        }

        return 0;
    }


    static NTSTATUS close_matching_socket(UINT32 owner_pid, p_conn_kill_request request) {
        if (!aida_can_query_system_handles())
            return STATUS_INVALID_DEVICE_STATE;

        PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
        NTSTATUS status = aida_query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles) {
            return status;
        }


        constexpr UINT32 MAX_HANDLES_TO_CHECK = 4096;
        USHORT* pid_handles = static_cast<USHORT*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_HANDLES_TO_CHECK * sizeof(USHORT), 'khNW'));
        if (!pid_handles) {
            ExFreePoolWithTag(handles, 'hANW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        UINT32 count = 0;
        for (ULONG i = 0; i < handles->NumberOfHandles && count < MAX_HANDLES_TO_CHECK; i++) {
            if (static_cast<UINT32>(handles->Handles[i].UniqueProcessId) == owner_pid) {
                pid_handles[count++] = handles->Handles[i].HandleValue;
            }
        }
        ExFreePoolWithTag(handles, 'hANW');

        if (count == 0) {
            ExFreePoolWithTag(pid_handles, 'khNW');
            return STATUS_NOT_FOUND;
        }

        PEPROCESS process = nullptr;
        status = stack_spoof::spoofed_PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(owner_pid)), &process);
        if (!NT_SUCCESS(status) || !process) {
            ExFreePoolWithTag(pid_handles, 'khNW');
            return status;
        }


        (void)afd_get_offsets();

        NTSTATUS close_status = STATUS_NOT_FOUND;
        KAPC_STATE apc = {};
        KeStackAttachProcess(process, &apc);

        __try {
            for (UINT32 i = 0; i < count; i++) {
                HANDLE h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid_handles[i]));

                PVOID file_obj = nullptr;
                NTSTATUS ref_st = ObReferenceObjectByHandle(
                    h, 0,
                    (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr,
                    KernelMode, &file_obj, nullptr);
                if (!NT_SUCCESS(ref_st) || !file_obj)
                    continue;

                PFILE_OBJECT fo = static_cast<PFILE_OBJECT>(file_obj);
                if (!aida_is_afd_file_object(fo)) {
                    ObDereferenceObject(fo);
                    continue;
                }

                SOCKET_HANDLE_ENTRY socket_info = {};
                BOOLEAN ok = aida_extract_socket_info_from_fo(fo, &socket_info);
                ObDereferenceObject(fo);
                if (!ok)
                    continue;

                if (!socket_matches_kill_request(&socket_info, request))
                    continue;

                close_status = ZwClose(h);
                if (NT_SUCCESS(close_status))
                    break;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            close_status = STATUS_ACCESS_VIOLATION;
        }

        KeUnstackDetachProcess(&apc);
        stack_spoof::spoofed_ObfDereferenceObject(process);
        ExFreePoolWithTag(pid_handles, 'khNW');
        return close_status;
    }


    static NTSTATUS resolve_and_close_socket(p_conn_kill_request request) {
        UINT32 owner_pid = resolve_owner_pid_by_tuple(request);
        if (owner_pid == 0)
            return STATUS_NOT_FOUND;

        return close_matching_socket(owner_pid, request);
    }

    NTSTATUS kill_connection(p_conn_kill_request request) {
        if (!request) {
            WW_LOG("netaction::net_kill::kill_connection NULL_REQUEST status=STATUS_INVALID_PARAMETER");
            return STATUS_INVALID_PARAMETER;
        }
        request->status = 1;

        WW_LOG("netaction::net_kill::kill_connection ENTER protocol=%u af=%u src_port=%u dst_port=%u pid=%u",
            request->protocol, request->address_family,
            request->src_port, request->dst_port, request->pid);

        if (request->protocol != 6) {
            WW_LOG("netaction::net_kill::kill_connection unsupported_protocol protocol=%u status=STATUS_INVALID_PARAMETER",
                request->protocol);
            return STATUS_INVALID_PARAMETER;
        }

        UINT32 owner_pid = request->pid;
        if (owner_pid != 0) {
            WW_LOG("netaction::net_kill::kill_connection path=pid_provided owner_pid=%u", owner_pid);
            NTSTATUS st = close_matching_socket(owner_pid, request);
            WW_LOG("netaction::net_kill::kill_connection close_matching_socket(pid=%u) returned=0x%08X",
                owner_pid, st);
            if (NT_SUCCESS(st)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
            NTSTATUS rst_status = inject_tcp_reset_fallback(request);
            WW_LOG("netaction::net_kill::kill_connection inject_tcp_reset_fallback returned=0x%08X",
                rst_status);
            if (NT_SUCCESS(rst_status)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
            NTSTATUS final_st = NT_SUCCESS(st) ? rst_status : st;
            WW_LOG("netaction::net_kill::kill_connection EXIT final_status=0x%08X", final_st);
            return final_st;
        }

        WW_LOG("netaction::net_kill::kill_connection path=tuple_resolve");
        owner_pid = resolve_owner_pid_by_tuple(request);
        WW_LOG("netaction::net_kill::kill_connection resolve_owner_pid_by_tuple returned=%u", owner_pid);
        if (owner_pid != 0) {
            NTSTATUS st_close = close_matching_socket(owner_pid, request);
            WW_LOG("netaction::net_kill::kill_connection close_matching_socket(resolved_pid=%u) returned=0x%08X",
                owner_pid, st_close);
            if (NT_SUCCESS(st_close)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
        }

        NTSTATUS st = resolve_and_close_socket(request);
        WW_LOG("netaction::net_kill::kill_connection resolve_and_close_socket returned=0x%08X", st);
        if (NT_SUCCESS(st)) {
            request->status = 0;
            return STATUS_SUCCESS;
        }

        NTSTATUS rst_status = inject_tcp_reset_fallback(request);
        WW_LOG("netaction::net_kill::kill_connection inject_tcp_reset_fallback returned=0x%08X",
            rst_status);
        if (NT_SUCCESS(rst_status)) {
            request->status = 0;
            return STATUS_SUCCESS;
        }
        NTSTATUS final_st = NT_SUCCESS(st) ? rst_status : st;
        WW_LOG("netaction::net_kill::kill_connection EXIT final_status=0x%08X", final_st);
        return final_st;
    }
}


namespace net_dns_spoof {

    typedef struct _DNS_SPOOF_ACTIVE {
        volatile LONG active;
        UINT32 rule_id;
        char domain[DNS_SPOOF_MAX_DOMAIN];
        UINT8 spoof_addr[16];
        UINT32 address_family;
        UINT32 ttl;
        volatile LONG match_count;
    } DNS_SPOOF_ACTIVE;

    inline DNS_SPOOF_ACTIVE g_spoof_rules[DNS_SPOOF_MAX_RULES] = {};
    inline volatile LONG g_next_spoof_id = 1;
    inline volatile LONG g_active_spoof_count = 0;

    BOOLEAN has_active_rules() {
        return (g_active_spoof_count != 0);
    }


    static BOOLEAN domain_matches(const char* pattern, const char* domain) {
        if (!pattern || !domain) return FALSE;
        if (pattern[0] == '*' && pattern[1] == '.') {

            const char* suffix = pattern + 1;
            UINT32 slen = 0, dlen = 0;
            while (suffix[slen]) slen++;
            while (domain[dlen]) dlen++;
            if (dlen < slen) return FALSE;

            for (UINT32 i = 0; i < slen; i++) {
                char a = suffix[slen - 1 - i];
                char b = domain[dlen - 1 - i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) return FALSE;
            }
            return TRUE;
        }

        UINT32 i = 0;
        while (pattern[i] && domain[i]) {
            char a = pattern[i], b = domain[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) return FALSE;
            i++;
        }
        return (pattern[i] == 0 && domain[i] == 0);
    }


    BOOLEAN check_spoof(const char* domain, UINT8* out_addr, UINT32* out_af, UINT32* out_ttl) {
        if (g_active_spoof_count == 0) return FALSE;
        for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
            if (g_spoof_rules[i].active != 1) continue;
            if (domain_matches(g_spoof_rules[i].domain, domain)) {
                strong::kmemcpy(out_addr, g_spoof_rules[i].spoof_addr, 16);
                *out_af = g_spoof_rules[i].address_family;
                *out_ttl = g_spoof_rules[i].ttl;
                _InterlockedIncrement(&g_spoof_rules[i].match_count);
                return TRUE;
            }
        }
        return FALSE;
    }

    NTSTATUS handle_spoof_rule(p_dns_spoof_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
                if (_InterlockedCompareExchange(&g_spoof_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&g_next_spoof_id);
                    g_spoof_rules[i].rule_id = id;
                    strong::kmemcpy(g_spoof_rules[i].domain, request->domain, DNS_SPOOF_MAX_DOMAIN);
                    strong::kmemcpy(g_spoof_rules[i].spoof_addr, request->spoof_addr, 16);
                    g_spoof_rules[i].address_family = request->address_family;
                    g_spoof_rules[i].ttl = request->ttl ? request->ttl : 300;
                    g_spoof_rules[i].match_count = 0;
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_spoof_rules[i].active, 1);
                    _InterlockedIncrement(&g_active_spoof_count);
                    request->rule_id = id;
                    request->active = 1;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
                if (g_spoof_rules[i].active == 1 && g_spoof_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&g_spoof_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_spoof_count);
                    request->active = 0;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 3: {
            for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
                if (g_spoof_rules[i].active == 1) {
                    _InterlockedExchange(&g_spoof_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_spoof_count);
                }
            }
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS handle_spoof_list(p_dns_spoof_list request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->rule_count = 0;
        for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES && request->rule_count < DNS_SPOOF_MAX_RULES; i++) {
            if (g_spoof_rules[i].active == 1) {
                DNS_SPOOF_RULE* out = &request->rules[request->rule_count];
                out->rule_id = g_spoof_rules[i].rule_id;
                strong::kmemcpy(out->domain, g_spoof_rules[i].domain, DNS_SPOOF_MAX_DOMAIN);
                strong::kmemcpy(out->spoof_addr, g_spoof_rules[i].spoof_addr, 16);
                out->address_family = g_spoof_rules[i].address_family;
                out->ttl = g_spoof_rules[i].ttl;
                out->match_count = g_spoof_rules[i].match_count;
                out->active = 1;
                request->rule_count++;
            }
        }
        return STATUS_SUCCESS;
    }

    void cleanup() {
        for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
            _InterlockedExchange(&g_spoof_rules[i].active, 0);
            g_spoof_rules[i].rule_id = 0;
            strong::kmemset(g_spoof_rules[i].domain, 0, sizeof(g_spoof_rules[i].domain));
            strong::kmemset(g_spoof_rules[i].spoof_addr, 0, sizeof(g_spoof_rules[i].spoof_addr));
            g_spoof_rules[i].address_family = 0;
            g_spoof_rules[i].ttl = 0;
            _InterlockedExchange(&g_spoof_rules[i].match_count, 0);
        }
        _InterlockedExchange(&g_active_spoof_count, 0);
    }
}


namespace net_bw {

    typedef struct _BW_PID_ENTRY {
        volatile LONG active;
        UINT32 pid;
        volatile LONG64 bytes_sent;
        volatile LONG64 bytes_recv;
        volatile LONG64 packets_sent;
        volatile LONG64 packets_recv;
        UINT64 last_activity;
    } BW_PID_ENTRY;

    inline BW_PID_ENTRY g_bw_entries[BW_MAX_PROCESSES] = {};
    inline volatile LONG g_bw_active = 0;
    inline volatile LONG64 g_bw_total_sent = 0;
    inline volatile LONG64 g_bw_total_recv = 0;
    inline volatile LONG64 g_bw_total_pkts_sent = 0;
    inline volatile LONG64 g_bw_total_pkts_recv = 0;
    inline volatile LONG64 g_bw_last_sample_sent = 0;
    inline volatile LONG64 g_bw_last_sample_recv = 0;
    inline UINT64 g_bw_last_sample_time = 0;

    BOOLEAN is_active() {
        return (g_bw_active != 0);
    }


    void record_traffic(UINT32 pid, UINT32 direction, UINT32 bytes) {
        if (!g_bw_active) return;

        if (direction == 0) {
            _InterlockedExchangeAdd64(&g_bw_total_recv, bytes);
            _InterlockedIncrement64(&g_bw_total_pkts_recv);
        } else {
            _InterlockedExchangeAdd64(&g_bw_total_sent, bytes);
            _InterlockedIncrement64(&g_bw_total_pkts_sent);
        }

        if (pid == 0) return;


        INT32 free_slot = -1;
        for (UINT32 i = 0; i < BW_MAX_PROCESSES; i++) {
            if (g_bw_entries[i].active == 1 && g_bw_entries[i].pid == pid) {
                if (direction == 0) {
                    _InterlockedExchangeAdd64(&g_bw_entries[i].bytes_recv, bytes);
                    _InterlockedIncrement64(&g_bw_entries[i].packets_recv);
                } else {
                    _InterlockedExchangeAdd64(&g_bw_entries[i].bytes_sent, bytes);
                    _InterlockedIncrement64(&g_bw_entries[i].packets_sent);
                }
                LARGE_INTEGER ts;
                KeQuerySystemTime(&ts);
                g_bw_entries[i].last_activity = ts.QuadPart;
                return;
            }
            if (!g_bw_entries[i].active && free_slot == -1) free_slot = i;
        }
        if (free_slot >= 0) {
            if (_InterlockedCompareExchange(&g_bw_entries[free_slot].active, 2, 0) == 0) {
                for (UINT32 j = 0; j < BW_MAX_PROCESSES; j++) {
                    if (g_bw_entries[j].active == 1 && g_bw_entries[j].pid == pid) {
                        _InterlockedExchange(&g_bw_entries[free_slot].active, 0);
                        if (direction == 0) {
                            _InterlockedExchangeAdd64(&g_bw_entries[j].bytes_recv, bytes);
                            _InterlockedIncrement64(&g_bw_entries[j].packets_recv);
                        } else {
                            _InterlockedExchangeAdd64(&g_bw_entries[j].bytes_sent, bytes);
                            _InterlockedIncrement64(&g_bw_entries[j].packets_sent);
                        }
                        return;
                    }
                }
                g_bw_entries[free_slot].pid = pid;
                g_bw_entries[free_slot].bytes_sent = 0;
                g_bw_entries[free_slot].bytes_recv = 0;
                g_bw_entries[free_slot].packets_sent = 0;
                g_bw_entries[free_slot].packets_recv = 0;
                if (direction == 0)
                    g_bw_entries[free_slot].bytes_recv = bytes;
                else
                    g_bw_entries[free_slot].bytes_sent = bytes;
                LARGE_INTEGER ts;
                KeQuerySystemTime(&ts);
                g_bw_entries[free_slot].last_activity = ts.QuadPart;
                KeMemoryBarrier();
                _InterlockedExchange(&g_bw_entries[free_slot].active, 1);
            }
        }
    }

    NTSTATUS handle_bw(p_bw_monitor_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_bw: op=%u filter_pid=%u bw_active=%d",
                request->operation, request->filter_pid, (int)g_bw_active);

        switch (request->operation) {
        case 0:
            _InterlockedExchange(&g_bw_active, 1);
            request->monitoring_active = 1;
            request->total_bytes_sent = g_bw_total_sent;
            request->total_bytes_recv = g_bw_total_recv;
            request->total_packets_sent = g_bw_total_pkts_sent;
            request->total_packets_recv = g_bw_total_pkts_recv;
            {
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                UINT64 elapsed = now.QuadPart - g_bw_last_sample_time;
                if (elapsed > 0 && g_bw_last_sample_time != 0) {
                    LONG64 delta_sent = g_bw_total_sent - g_bw_last_sample_sent;
                    LONG64 delta_recv = g_bw_total_recv - g_bw_last_sample_recv;
                    UINT64 seconds = elapsed / 10000000ULL;
                    if (seconds > 0) {
                        request->bytes_per_second_out = delta_sent / seconds;
                        request->bytes_per_second_in = delta_recv / seconds;
                    }
                }
                g_bw_last_sample_sent = g_bw_total_sent;
                g_bw_last_sample_recv = g_bw_total_recv;
                g_bw_last_sample_time = now.QuadPart;
            }
            return STATUS_SUCCESS;
        case 1:
            _InterlockedExchange(&g_bw_active, 0);
            request->monitoring_active = 0;
            return STATUS_SUCCESS;
        case 2: {
            request->total_bytes_sent = g_bw_total_sent;
            request->total_bytes_recv = g_bw_total_recv;
            request->total_packets_sent = g_bw_total_pkts_sent;
            request->total_packets_recv = g_bw_total_pkts_recv;
            request->monitoring_active = g_bw_active;

            NET_DBG("handle_bw[get]: total_sent=%lld total_recv=%lld pkts_s=%lld pkts_r=%lld active=%d",
                    (LONG64)g_bw_total_sent, (LONG64)g_bw_total_recv,
                    (LONG64)g_bw_total_pkts_sent, (LONG64)g_bw_total_pkts_recv, (int)g_bw_active);


            LARGE_INTEGER now;
            KeQuerySystemTime(&now);
            UINT64 elapsed = now.QuadPart - g_bw_last_sample_time;
            if (elapsed > 0 && g_bw_last_sample_time != 0) {
                LONG64 delta_sent = g_bw_total_sent - g_bw_last_sample_sent;
                LONG64 delta_recv = g_bw_total_recv - g_bw_last_sample_recv;

                UINT64 seconds = elapsed / 10000000ULL;
                if (seconds > 0) {
                    request->bytes_per_second_out = delta_sent / seconds;
                    request->bytes_per_second_in = delta_recv / seconds;
                }
            }
            g_bw_last_sample_sent = g_bw_total_sent;
            g_bw_last_sample_recv = g_bw_total_recv;
            g_bw_last_sample_time = now.QuadPart;
            return STATUS_SUCCESS;
        }
        case 3: {
            g_bw_total_sent = 0;
            g_bw_total_recv = 0;
            g_bw_total_pkts_sent = 0;
            g_bw_total_pkts_recv = 0;
            for (UINT32 i = 0; i < BW_MAX_PROCESSES; i++) {
                _InterlockedExchange(&g_bw_entries[i].active, 0);
            }
            return STATUS_SUCCESS;
        }
        case 4: {
            request->process_count = 0;
            for (UINT32 i = 0; i < BW_MAX_PROCESSES && request->process_count < BW_MAX_PROCESSES; i++) {
                if (g_bw_entries[i].active == 1) {
                    if (request->filter_pid != 0 && g_bw_entries[i].pid != request->filter_pid) continue;
                    BW_PROCESS_ENTRY* out = &request->processes[request->process_count];
                    out->pid = g_bw_entries[i].pid;
                    out->bytes_sent = g_bw_entries[i].bytes_sent;
                    out->bytes_recv = g_bw_entries[i].bytes_recv;
                    out->packets_sent = g_bw_entries[i].packets_sent;
                    out->packets_recv = g_bw_entries[i].packets_recv;
                    out->last_activity_time = g_bw_entries[i].last_activity;
                    request->process_count++;
                }
            }
            request->monitoring_active = g_bw_active;
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        _InterlockedExchange(&g_bw_active, 0);
        _InterlockedExchange64(&g_bw_total_sent, 0);
        _InterlockedExchange64(&g_bw_total_recv, 0);
        _InterlockedExchange64(&g_bw_total_pkts_sent, 0);
        _InterlockedExchange64(&g_bw_total_pkts_recv, 0);
        _InterlockedExchange64(&g_bw_last_sample_sent, 0);
        _InterlockedExchange64(&g_bw_last_sample_recv, 0);
        g_bw_last_sample_time = 0;
        for (UINT32 i = 0; i < BW_MAX_PROCESSES; i++) {
            _InterlockedExchange(&g_bw_entries[i].active, 0);
            g_bw_entries[i].pid = 0;
            _InterlockedExchange64(&g_bw_entries[i].bytes_sent, 0);
            _InterlockedExchange64(&g_bw_entries[i].bytes_recv, 0);
            _InterlockedExchange64(&g_bw_entries[i].packets_sent, 0);
            _InterlockedExchange64(&g_bw_entries[i].packets_recv, 0);
            g_bw_entries[i].last_activity = 0;
        }
    }
}


namespace net_if_enum {


    typedef NTSTATUS(NTAPI* fn_GetIfTable2)(PVOID* Table);
    typedef void(NTAPI* fn_FreeMibTable)(PVOID Table);


    typedef struct _AIDA_MIB_IF_ROW2 {
        UINT64 InterfaceLuid;
        UINT32 InterfaceIndex;
        GUID   InterfaceGuid;
        WCHAR  Alias[257];
        WCHAR  Description[257];
        UINT32 PhysicalAddressLength;
        UINT8  PhysicalAddress[32];
        UINT8  PermanentPhysicalAddress[32];
        UINT32 Mtu;
        UINT32 Type;
        UINT32 TunnelType;
        UINT32 MediaType;
        UINT32 PhysicalMediumType;
        UINT32 AccessType;
        UINT32 DirectionType;
        struct {
            BOOLEAN HardwareInterface  : 1;
            BOOLEAN FilterInterface    : 1;
            BOOLEAN ConnectorPresent   : 1;
            BOOLEAN NotAuthenticated   : 1;
            BOOLEAN NotMediaConnected  : 1;
            BOOLEAN Paused             : 1;
            BOOLEAN LowPower           : 1;
            BOOLEAN EndPointInterface  : 1;
        } InterfaceAndOperStatusFlags;
        UINT32 OperStatus;
        UINT32 AdminStatus;
        UINT32 MediaConnectState;
        GUID   NetworkGuid;
        UINT32 ConnectionType;
        UINT64 TransmitLinkSpeed;
        UINT64 ReceiveLinkSpeed;
        UINT64 InOctets;
        UINT64 InUcastPkts;
        UINT64 InNUcastPkts;
        UINT64 InDiscards;
        UINT64 InErrors;
        UINT64 InUnknownProtos;
        UINT64 InUcastOctets;
        UINT64 InMulticastOctets;
        UINT64 InBroadcastOctets;
        UINT64 OutOctets;
        UINT64 OutUcastPkts;
        UINT64 OutNUcastPkts;
        UINT64 OutDiscards;
        UINT64 OutErrors;
        UINT64 OutUcastOctets;
        UINT64 OutMulticastOctets;
        UINT64 OutBroadcastOctets;
        UINT64 OutQLen;
    } AIDA_MIB_IF_ROW2;

    typedef struct _AIDA_MIB_IF_TABLE2 {
        UINT32 NumEntries;
        AIDA_MIB_IF_ROW2 Table[1];
    } AIDA_MIB_IF_TABLE2;

    static_assert(sizeof(AIDA_MIB_IF_ROW2) == 1352,
        "AIDA_MIB_IF_ROW2 layout mismatch — must be 1352 bytes to match MIB_IF_ROW2");

    NTSTATUS enumerate_interfaces(p_net_interface_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->interface_count = 0;

        NET_DBG("enumerate_interfaces: enter");

        PVOID netio = net_capture::find_module_base("netio.sys");
        if (!netio) netio = net_capture::find_module_base("NETIO.SYS");
        if (!netio) return STATUS_NOT_SUPPORTED;

        CHAR gt2[] = {'G','e','t','I','f','T','a','b','l','e','2',0};
        CHAR fmt[] = {'F','r','e','e','M','i','b','T','a','b','l','e',0};

        fn_GetIfTable2 _GetIfTable2 = (fn_GetIfTable2)GetProcAddress(netio, gt2);
        fn_FreeMibTable _FreeMibTable = (fn_FreeMibTable)GetProcAddress(netio, fmt);

        if (!_GetIfTable2 || !_FreeMibTable) return STATUS_NOT_SUPPORTED;

        PVOID table = nullptr;
        NTSTATUS st = _GetIfTable2(&table);
        if (!NT_SUCCESS(st) || !table) {
            NET_ERR("enumerate_interfaces: GetIfTable2 failed 0x%08x table=%p", st, table);
            return st;
        }

        __try {
            const AIDA_MIB_IF_TABLE2* if_table = static_cast<const AIDA_MIB_IF_TABLE2*>(table);
            NET_DBG("enumerate_interfaces: NumEntries=%u", if_table->NumEntries);

            for (ULONG i = 0; i < if_table->NumEntries && request->interface_count < NET_IF_MAX; i++) {
                const AIDA_MIB_IF_ROW2* row = &if_table->Table[i];
                if (!_MmIsAddressValid(const_cast<AIDA_MIB_IF_ROW2*>(row))) break;

                NET_INTERFACE_ENTRY* e = &request->interfaces[request->interface_count];
                strong::kmemset(e, 0, sizeof(NET_INTERFACE_ENTRY));

                e->if_index = row->InterfaceIndex;
                e->mtu = row->Mtu;
                e->if_type = row->Type;
                e->speed = row->TransmitLinkSpeed;
                e->oper_status = row->OperStatus;

                if (row->PhysicalAddressLength >= 6) {
                    strong::kmemcpy(e->mac_addr, row->PhysicalAddress, 6);
                }

                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && row->Alias[j]; j++) {
                    e->name[j] = static_cast<char>(row->Alias[j] & 0x7F);
                }

                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && row->Description[j]; j++) {
                    e->description[j] = static_cast<char>(row->Description[j] & 0x7F);
                }

                e->in_octets = row->InOctets;
                e->out_octets = row->OutOctets;

                request->interface_count++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            NET_ERR("enumerate_interfaces: exception during enumeration");
        }

        NET_DBG("enumerate_interfaces: returned %u interfaces", request->interface_count);
        for (UINT32 dbg_i = 0; dbg_i < request->interface_count && dbg_i < 3; dbg_i++) {
            const NET_INTERFACE_ENTRY* e = &request->interfaces[dbg_i];
            NET_DBG("  iface[%u]: idx=%u type=%u mtu=%u oper=%u speed=%llu mac=%02x:%02x:%02x:%02x:%02x:%02x",
                    dbg_i, e->if_index, e->if_type, e->mtu, e->oper_status, e->speed,
                    e->mac_addr[0], e->mac_addr[1], e->mac_addr[2],
                    e->mac_addr[3], e->mac_addr[4], e->mac_addr[5]);
            NET_DBG("  iface[%u]: name='%.32s' desc='%.32s'",
                    dbg_i, e->name, e->description);
        }

        _FreeMibTable(table);
        return STATUS_SUCCESS;
    }
}


namespace net_pcap {

    NTSTATUS export_pcap(p_pcap_export_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;


        request->header.magic_number = 0xa1b2c3d4;
        request->header.version_major = 2;
        request->header.version_minor = 4;
        request->header.thiszone = 0;
        request->header.sigfigs = 0;
        request->header.snaplen = PCAP_RECORD_MAX_SIZE;
        request->header.network = 101;

        UINT32 max_pkts = request->max_packets;
        if (max_pkts == 0 || max_pkts > PCAP_MAX_EXPORT_PACKETS)
            max_pkts = PCAP_MAX_EXPORT_PACKETS;

        request->packet_count = 0;
        request->data_size = sizeof(PCAP_GLOBAL_HEADER);


        if (!net_capture::g_ring_buffer) return STATUS_NOT_SUPPORTED;

        KIRQL irql;
        KeAcquireSpinLock(&net_capture::g_ring_lock, &irql);

        LONG idx = 0;
        LONG total_scan = RING_BUFFER_SIZE;

        while (total_scan > 0 && request->packet_count < max_pkts) {
            NET_PACKET_ENTRY* pkt = &net_capture::g_ring_buffer[idx];

            if (pkt->timestamp == 0) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                total_scan--;
                continue;
            }

            if (request->filter_pid != 0 && pkt->pid != 0 && pkt->pid != request->filter_pid) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                total_scan--;
                continue;
            }
            if (request->filter_protocol != 0 && pkt->protocol != request->filter_protocol) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                total_scan--;
                continue;
            }

            PCAP_RECORD* rec = &request->records[request->packet_count];
            strong::kmemset(rec, 0, sizeof(PCAP_RECORD));


            UINT64 unix_100ns = pkt->timestamp - 116444736000000000ULL;
            rec->ts_sec = (UINT32)(unix_100ns / 10000000ULL);
            rec->ts_usec = (UINT32)((unix_100ns % 10000000ULL) / 10);


            UINT32 ip_header_len = 20;
            UINT32 total_len = ip_header_len + pkt->payload_size;
            if (total_len > PCAP_RECORD_MAX_SIZE) total_len = PCAP_RECORD_MAX_SIZE;


            rec->data[0] = 0x45;
            rec->data[1] = 0x00;
            rec->data[2] = (UINT8)(total_len >> 8);
            rec->data[3] = (UINT8)(total_len & 0xFF);
            rec->data[4] = 0; rec->data[5] = 0;
            rec->data[6] = 0x40; rec->data[7] = 0;
            rec->data[8] = 64;
            rec->data[9] = (UINT8)pkt->protocol;


            strong::kmemcpy(&rec->data[12], pkt->local_addr, 4);

            strong::kmemcpy(&rec->data[16], pkt->remote_addr, 4);


            if (pkt->direction == 0) {
                strong::kmemcpy(&rec->data[12], pkt->remote_addr, 4);
                strong::kmemcpy(&rec->data[16], pkt->local_addr, 4);
            }

            {
                UINT16 cksum = net_checksum::ip_checksum(rec->data, ip_header_len);
                rec->data[10] = (UINT8)(cksum >> 8);
                rec->data[11] = (UINT8)(cksum & 0xFF);
            }


            UINT32 payload_copy = pkt->payload_size;
            if (ip_header_len + payload_copy > PCAP_RECORD_MAX_SIZE)
                payload_copy = PCAP_RECORD_MAX_SIZE - ip_header_len;
            strong::kmemcpy(&rec->data[ip_header_len], pkt->payload, payload_copy);

            rec->incl_len = ip_header_len + payload_copy;
            rec->orig_len = total_len;
            request->data_size += sizeof(UINT32) * 4 + rec->incl_len;

            request->packet_count++;
            idx = (idx + 1) % RING_BUFFER_SIZE;
            total_scan--;
        }

        KeReleaseSpinLock(&net_capture::g_ring_lock, irql);

        return STATUS_SUCCESS;
    }
}


namespace net_fingerprint {

    inline NET_FINGERPRINT_ENTRY g_fp_entries[FINGERPRINT_MAX] = {};
    inline volatile LONG g_fp_count = 0;
    inline volatile LONG g_fp_active = 0;

    BOOLEAN is_active() {
        return (g_fp_active != 0);
    }


    void analyze_tcp_syn(const UINT8* src_addr, UINT32 af,
                         const UINT8* tcp_data, UINT32 tcp_len,
                         UINT32 ip_ttl) {
        if (!g_fp_active || tcp_len < 20) return;

        UINT8 flags = tcp_data[13];
        if (!(flags & 0x02)) return;

        UINT32 window = ((UINT32)tcp_data[14] << 8) | tcp_data[15];
        UINT32 data_offset = ((tcp_data[12] >> 4) & 0xF) * 4;


        UINT32 mss = 0;
        UINT32 ws = 0;
        UINT32 sack = 0;
        UINT32 nops = 0;
        UINT32 opt_order = 0;

        if (data_offset > 20 && data_offset <= tcp_len) {
            UINT32 pos = 20;
            UINT32 opt_idx = 0;
            while (pos < data_offset && pos < tcp_len) {
                UINT8 kind = tcp_data[pos];
                if (kind == 0) break;
                if (kind == 1) { nops++; pos++; continue; }
                if (pos + 1 >= tcp_len) break;
                UINT8 olen = tcp_data[pos + 1];
                if (olen < 2 || pos + olen > tcp_len) break;

                if (kind == 2 && olen == 4) {
                    mss = ((UINT32)tcp_data[pos + 2] << 8) | tcp_data[pos + 3];
                    opt_order |= (2 << (opt_idx * 4));
                }
                else if (kind == 3 && olen == 3) {
                    ws = tcp_data[pos + 2];
                    opt_order |= (3 << (opt_idx * 4));
                }
                else if (kind == 4 && olen == 2) {
                    sack = 1;
                    opt_order |= (4 << (opt_idx * 4));
                }
                else if (kind == 8 && olen == 10) {
                    opt_order |= (8 << (opt_idx * 4));
                }
                opt_idx++;
                pos += olen;
            }
        }


        char os[64] = {};


        UINT32 ttl_bucket = (ip_ttl > 96) ? 128 : (ip_ttl > 48 ? 64 : 32);

        if (ttl_bucket == 128) {
            if (window == 65535 || window == 64240) {

                const char* s = "Windows 10/11";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            } else if (window == 8192) {
                const char* s = "Windows 7/8";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            } else {
                const char* s = "Windows (unknown)";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            }
        } else if (ttl_bucket == 64) {
            if (ws > 0 && sack) {
                if (mss == 1460 && window >= 29200) {
                    const char* s = "Linux 4.x/5.x";
                    for (int i = 0; s[i]; i++) os[i] = s[i];
                } else if (mss == 1460 && window == 65535) {
                    const char* s = "macOS / FreeBSD";
                    for (int i = 0; s[i]; i++) os[i] = s[i];
                } else {
                    const char* s = "Linux/Unix";
                    for (int i = 0; s[i]; i++) os[i] = s[i];
                }
            } else {
                const char* s = "Unix-like";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            }
        } else {
            const char* s = "Unknown";
            for (int i = 0; s[i]; i++) os[i] = s[i];
        }


        KIRQL irql;
        KeAcquireSpinLock(&g_fp_lock, &irql);


        for (UINT32 i = 0; i < FINGERPRINT_MAX; i++) {
            if (g_fp_entries[i].address_family == af) {
                UINT32 len = (af == 23) ? 16 : 4;
                BOOLEAN same = TRUE;
                for (UINT32 j = 0; j < len; j++) {
                    if (g_fp_entries[i].remote_addr[j] != src_addr[j]) {
                        same = FALSE; break;
                    }
                }
                if (same) {

                    g_fp_entries[i].ttl = ip_ttl;
                    g_fp_entries[i].window_size = window;
                    g_fp_entries[i].mss = mss;
                    g_fp_entries[i].window_scale = ws;
                    g_fp_entries[i].sack_permitted = sack;
                    g_fp_entries[i].nop_count = nops;
                    g_fp_entries[i].tcp_options_order = opt_order;
                    strong::kmemcpy(g_fp_entries[i].os_guess, os, 64);
                    KeReleaseSpinLock(&g_fp_lock, irql);
                    return;
                }
            }
        }


        if (g_fp_count < FINGERPRINT_MAX) {
            UINT32 idx = g_fp_count;
            strong::kmemset(&g_fp_entries[idx], 0, sizeof(NET_FINGERPRINT_ENTRY));
            strong::kmemcpy(g_fp_entries[idx].remote_addr, src_addr, (af == 23) ? 16 : 4);
            g_fp_entries[idx].address_family = af;
            g_fp_entries[idx].ttl = ip_ttl;
            g_fp_entries[idx].window_size = window;
            g_fp_entries[idx].mss = mss;
            g_fp_entries[idx].window_scale = ws;
            g_fp_entries[idx].sack_permitted = sack;
            g_fp_entries[idx].nop_count = nops;
            g_fp_entries[idx].tcp_options_order = opt_order;
            g_fp_entries[idx].df_flag = 0;
            strong::kmemcpy(g_fp_entries[idx].os_guess, os, 64);
            _InterlockedIncrement(&g_fp_count);
        }
        KeReleaseSpinLock(&g_fp_lock, irql);
    }

    NTSTATUS handle_fingerprint(p_net_fingerprint_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0:
            _InterlockedExchange(&g_fp_active, 1);
            return STATUS_SUCCESS;
        case 1:
            _InterlockedExchange(&g_fp_active, 0);
            return STATUS_SUCCESS;
        case 2: {
            KIRQL irql;
            KeAcquireSpinLock(&g_fp_lock, &irql);
            request->result_count = (UINT32)g_fp_count;
            UINT32 copy = g_fp_count;
            if (copy > FINGERPRINT_MAX) copy = FINGERPRINT_MAX;
            strong::kmemcpy(request->entries, g_fp_entries, copy * sizeof(NET_FINGERPRINT_ENTRY));
            KeReleaseSpinLock(&g_fp_lock, irql);
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        _InterlockedExchange(&g_fp_active, 0);
        KIRQL irql;
        KeAcquireSpinLock(&g_fp_lock, &irql);
        strong::kmemset(g_fp_entries, 0, sizeof(g_fp_entries));
        _InterlockedExchange(&g_fp_count, 0);
        KeReleaseSpinLock(&g_fp_lock, irql);
    }
}


NTSTATUS functions::handle_wfp_callout_enum(p_wfp_callout_enum request) {
    if (!request) { NET_ERR("handle_wfp_callout_enum: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_wfp_enum::enumerate_wfp_callouts(request);
}

NTSTATUS functions::handle_socket_handle_enum(p_socket_handle_enum request) {
    if (!request) { NET_ERR("handle_socket_handle_enum: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_socket_handle_enum: ENTER target_pid=%u", request->target_pid);
    NTSTATUS st = net_socket_enum::enumerate_socket_handles(request);
    NET_DBG("handle_socket_handle_enum: EXIT status=0x%08x socket_count=%u", st, request->socket_count);
    return st;
}

NTSTATUS functions::handle_sniff_net_buffers(p_sniff_net_buffers request) {
    if (!request) { NET_ERR("handle_sniff_net_buffers: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_sniff_net_buffers: op=%u", request->operation);
    NTSTATUS st = net_sniff::handle_sniff(request);
    NET_DBG("handle_sniff_net_buffers: returned 0x%08x active=%u capture_count=%u",
            st, request->active, request->capture_count);
    return st;
}

NTSTATUS functions::handle_tcpip_conn_dump(p_tcpip_conn_dump request) {
    if (!request) { NET_ERR("handle_tcpip_conn_dump: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_tcpip::dump_connections(request);
}


NTSTATUS functions::handle_packet_inject(p_packet_inject_request request) {
    if (!request) { NET_ERR("handle_packet_inject: NULL request"); return STATUS_INVALID_PARAMETER; }
    NTSTATUS st = net_inject::inject_packet(request);
    if (!NT_SUCCESS(st)) {
        NET_ERR("handle_packet_inject: FAILED dir=%u proto=%u af=%u payload=%u status=0x%08x",
                request->direction, request->protocol, request->address_family, request->payload_size, st);
    }
    return st;
}

NTSTATUS functions::handle_packet_mod_rule(p_packet_mod_rule request) {
    if (!request) { NET_ERR("handle_packet_mod_rule: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_packet_mod_rule: op=%u rule_id=%u", request->operation, request->rule_id);
    NTSTATUS st = net_mod::handle_mod_rule(request);
    NET_DBG("handle_packet_mod_rule: returned 0x%08x rule_id=%u active=%u",
            st, request->rule_id, request->active);
    return st;
}

NTSTATUS functions::handle_packet_mod_rule_list(p_packet_mod_rule_list request) {
    if (!request) { NET_ERR("handle_packet_mod_rule_list: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_mod::handle_mod_rule_list(request);
}

NTSTATUS functions::handle_traffic_redirect(p_traffic_redirect_rule request) {
    if (!request) { NET_ERR("handle_traffic_redirect: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_traffic_redirect: op=%u rule_id=%u", request->operation, request->rule_id);
    NTSTATUS st = net_redirect::handle_redirect_rule(request);
    NET_DBG("handle_traffic_redirect: returned 0x%08x rule_id=%u active=%u",
            st, request->rule_id, request->active);
    return st;
}

NTSTATUS functions::handle_traffic_redirect_list(p_traffic_redirect_list request) {
    if (!request) { NET_ERR("handle_traffic_redirect_list: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_redirect::handle_redirect_list(request);
}

NTSTATUS functions::handle_stream_reassemble(p_stream_reassemble_request request) {
    if (!request) {
        WW_LOG("netaction::handle_stream_reassemble NULL_REQUEST status=STATUS_INVALID_PARAMETER");
        NET_ERR("handle_stream_reassemble: NULL request");
        return STATUS_INVALID_PARAMETER;
    }
    WW_LOG("netaction::handle_stream_reassemble ENTER op=%u src_port=%u dst_port=%u pid=%u",
        request->operation, request->src_port, request->dst_port, request->pid);
    NET_DBG("handle_stream_reassemble: op=%u src_port=%u dst_port=%u pid=%u",
            request->operation, request->src_port, request->dst_port, request->pid);
    if (request->operation == 0 && request->pid != 0) {
        aida_refresh_pid_cache_for_process(request->pid, IPPROTO_TCP);
    }
    NTSTATUS st = net_stream::handle_stream(request);
    WW_LOG("netaction::handle_stream_reassemble EXIT status=0x%08X stream_size=%u total_packets=%u stream_count=%u truncated=%u",
        st, request->stream_size, request->total_packets, request->stream_count, request->truncated);
    NET_DBG("handle_stream_reassemble: returned 0x%08x stream_size=%u total_pkts=%u",
            st, request->stream_size, request->total_packets);
    return st;
}

NTSTATUS functions::handle_deep_inspect(p_dpi_request request) {
    if (!request) { NET_ERR("handle_deep_inspect: NULL request"); return STATUS_INVALID_PARAMETER; }
    if (request->filter_pid != 0) {
        aida_refresh_pid_cache_for_process(request->filter_pid, request->filter_protocol);
    }
    return net_dpi::get_results(request);
}

NTSTATUS functions::handle_intercept_hold(p_intercept_request request) {
    if (!request) { NET_ERR("handle_intercept_hold: NULL request"); return STATUS_INVALID_PARAMETER; }
    if (request->operation == 0 && request->filter_pid != 0) {
        aida_refresh_pid_cache_for_process(request->filter_pid, request->filter_protocol);
    }
    return net_intercept::handle_intercept(request);
}

NTSTATUS functions::handle_conn_kill(p_conn_kill_request request) {
    if (!request) {
        WW_LOG("netaction::handle_conn_kill NULL_REQUEST status=STATUS_INVALID_PARAMETER");
        NET_ERR("handle_conn_kill: NULL request");
        return STATUS_INVALID_PARAMETER;
    }
    WW_LOG("netaction::handle_conn_kill ENTER protocol=%u af=%u src_port=%u dst_port=%u pid=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u",
        request->protocol, request->address_family,
        request->src_port, request->dst_port, request->pid,
        request->src_addr[0], request->src_addr[1], request->src_addr[2], request->src_addr[3],
        request->dst_addr[0], request->dst_addr[1], request->dst_addr[2], request->dst_addr[3]);
    NTSTATUS st = net_kill::kill_connection(request);
    WW_LOG("netaction::handle_conn_kill EXIT status=0x%08X request_status=%u",
        st, request->status);
    if (!NT_SUCCESS(st)) {
        NET_ERR("handle_conn_kill: FAILED status=0x%08x", st);
    }
    return st;
}

NTSTATUS functions::handle_dns_spoof(p_dns_spoof_rule request) {
    if (!request) { NET_ERR("handle_dns_spoof: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_dns_spoof::handle_spoof_rule(request);
}

NTSTATUS functions::handle_dns_spoof_list(p_dns_spoof_list request) {
    if (!request) { NET_ERR("handle_dns_spoof_list: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_dns_spoof::handle_spoof_list(request);
}

NTSTATUS functions::handle_bw_monitor(p_bw_monitor_request request) {
    if (!request) { NET_ERR("handle_bw_monitor: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_bw_monitor: op=%u filter_pid=%u", request->operation, request->filter_pid);
    NTSTATUS st = net_bw::handle_bw(request);
    NET_DBG("handle_bw_monitor: returned 0x%08x active=%u total_sent=%llu total_recv=%llu",
            st, request->monitoring_active, request->total_bytes_sent, request->total_bytes_recv);
    return st;
}

NTSTATUS functions::handle_net_iface_enum(p_net_interface_enum request) {
    if (!request) { NET_ERR("handle_net_iface_enum: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_net_iface_enum: enter");
    NTSTATUS st = net_if_enum::enumerate_interfaces(request);
    NET_DBG("handle_net_iface_enum: returned 0x%08x count=%u", st, request->interface_count);
    return st;
}

NTSTATUS functions::handle_pcap_export(p_pcap_export_request request) {
    if (!request) { NET_ERR("handle_pcap_export: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_pcap::export_pcap(request);
}

NTSTATUS functions::handle_net_fingerprint(p_net_fingerprint_request request) {
    if (!request) { NET_ERR("handle_net_fingerprint: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_fingerprint::handle_fingerprint(request);
}
