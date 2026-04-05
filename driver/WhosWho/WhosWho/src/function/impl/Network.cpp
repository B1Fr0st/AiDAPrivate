#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"
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
    void analyze_tcp_syn(const UINT8* src_addr, UINT32 af,
                         const UINT8* tcp_data, UINT32 tcp_len,
                         UINT32 ip_ttl);
    BOOLEAN is_active();
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
}
namespace net_redirect {
    BOOLEAN check_redirect(UINT32 protocol, UINT32 dst_port, const UINT8* dst_addr,
                           UINT32 af, UINT32* new_port, UINT8* new_addr);
    BOOLEAN has_active_rules();
}
namespace net_dns_spoof {
    BOOLEAN check_spoof(const char* domain, UINT8* out_addr, UINT32* out_af, UINT32* out_ttl);
    BOOLEAN has_active_rules();
}
namespace net_bw {
    BOOLEAN is_active();
}
namespace net_inject {
    BOOLEAN resolve_inject_functions();
    NTSTATUS inject_packet(p_packet_inject_request request);
    void cleanup();
    extern HANDLE g_inject_handle_v4;
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
            if (!g_filter_rules[i].active) continue;
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
            return; // Cannot determine packet owner; drop rather than misattribute
        }


        if (g_filter_pid != 0 && effective_pid != g_filter_pid) return;
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
        if (effective_pid == 0 && g_filter_pid != 0) {
            return; // Cannot determine DNS entry owner; drop rather than misattribute
        }

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

        UINT16 flags = ((UINT16)data[2] << 8) | data[3];
        UINT16 qdcount = ((UINT16)data[4] << 8) | data[5];
        UINT16 ancount = ((UINT16)data[6] << 8) | data[7];
        UINT8  rcode = data[3] & 0x0F;
        BOOLEAN is_response = (flags & 0x8000) != 0;

        if (qdcount == 0 || qdcount > 16) return;

        char domain[260] = {};
        UINT32 pos = 12;


        pos = parse_dns_name(data, pos, data_len, domain, sizeof(domain));
        if (pos == 0 || pos + 4 > data_len) return;

        UINT16 qtype = ((UINT16)data[pos] << 8) | data[pos + 1];
        pos += 4;

        UINT8 resolved[16] = {};
        UINT32 ttl = 0;


        if (is_response && ancount > 0 && pos < data_len) {
            for (UINT16 i = 0; i < ancount && pos < data_len; i++) {

                if ((data[pos] & 0xC0) == 0xC0) {
                    pos += 2;
                } else {
                    while (pos < data_len && data[pos] != 0) {
                        if ((data[pos] & 0xC0) == 0xC0) { pos += 2; goto after_name; }
                        pos += data[pos] + 1;
                    }
                    pos++;
                }
                after_name:
                if (pos + 10 > data_len) break;

                UINT16 atype = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 4;
                ttl = ((UINT32)data[pos] << 24) | ((UINT32)data[pos+1] << 16) |
                      ((UINT32)data[pos+2] << 8) | data[pos+3];
                pos += 4;
                UINT16 rdlength = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 2;

                if (atype == 1 && rdlength == 4 && pos + 4 <= data_len) {
                    strong::kmemcpy(resolved, &data[pos], 4);
                    break;
                } else if (atype == 28 && rdlength == 16 && pos + 16 <= data_len) {
                    strong::kmemcpy(resolved, &data[pos], 16);
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

        if (!inFixedValues || !inMetaValues) return;
        if (!should_process_packet_pipeline()) return;

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
            if (pid != 0) {
                aida_store_cached_port_pid(protocol, local_port, pid);
                aida_store_cached_port_pid(protocol, remote_port, pid);
            }

            _InterlockedIncrement64(&g_global_pkts_recv);


            UINT32 rule_action = check_filter_rules(0, protocol, pid, local_port, remote_port, remote_ip, 2);
            if (rule_action == 1) {
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }


            UINT8 pkt_data[NET_PKT_MAX_PAYLOAD] = {};
            UINT32 pkt_len = 0;

            pkt_len = copy_transport_bytes(layerData, pkt_data, NET_PKT_MAX_PAYLOAD);
            if (pkt_len == 0 && layerData) {
            }
            _InterlockedExchangeAdd64(&g_global_bytes_recv, (LONG64)pkt_len);


            net_bw::record_traffic(pid, 0, pkt_len);


            if (pkt_len > 0) {
                net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            0, protocol, remote_port, pid);
            }


            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }


            if (protocol == 6 && pkt_len >= 20) {
                net_fingerprint::analyze_tcp_syn(remote_ip, 2, pkt_data, pkt_len, 0);
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
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }


            if (g_capture_active) {
                store_packet(0, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);


                if (protocol == 17) {
                    try_parse_dns(pid, pkt_data, pkt_len, local_port, remote_port);
                }
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

        if (!inFixedValues || !inMetaValues) return;
        if (!should_process_packet_pipeline()) return;

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
            if (pid != 0) {
                aida_store_cached_port_pid(protocol, local_port, pid);
                aida_store_cached_port_pid(protocol, remote_port, pid);
            }

            _InterlockedIncrement64(&g_global_pkts_sent);

            UINT32 rule_action = check_filter_rules(1, protocol, pid, local_port, remote_port, remote_ip, 2);
            if (rule_action == 1) {
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }

            UINT8 pkt_data[NET_PKT_MAX_PAYLOAD] = {};
            UINT32 pkt_len = 0;

            pkt_len = copy_transport_bytes(layerData, pkt_data, NET_PKT_MAX_PAYLOAD);
            if (pkt_len == 0 && layerData) {
            }
            _InterlockedExchangeAdd64(&g_global_bytes_sent, (LONG64)pkt_len);


            net_bw::record_traffic(pid, 1, pkt_len);


            if (pkt_len > 0) {
                net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            1, protocol, remote_port, pid);
            }


            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }

            if (protocol == 6 && pkt_len >= 20) {
                net_fingerprint::analyze_tcp_syn(local_ip, 2, pkt_data, pkt_len, 0);
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
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }

            if (g_capture_active) {
                store_packet(1, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);

                if (protocol == 17) {
                    try_parse_dns(pid, pkt_data, pkt_len, local_port, remote_port);
                }
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

            UINT32 protocol = 0;
            UINT32 local_port = 0;
            UINT32 remote_port = 0;

            if (inFixedValues->valueCount > FWPS_FIELD_ALE_V4_IP_PROTOCOL)
                protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_V4_IP_PROTOCOL].value.uint8;
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_V4_IP_LOCAL_PORT)
                local_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_V4_IP_LOCAL_PORT].value.uint16;
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_V4_IP_REMOTE_PORT)
                remote_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_V4_IP_REMOTE_PORT].value.uint16;

            UINT64 endpoint_handle = 0;
            if (inMetaValues->transportEndpointHandle != 0)
                endpoint_handle = inMetaValues->transportEndpointHandle;

            if (endpoint_handle != 0) {
                aida_store_cached_endpoint_pid(endpoint_handle, protocol, local_port, pid);
            }
            aida_store_cached_port_pid(protocol, local_port, pid);
            if (remote_port != 0)
                aida_store_cached_port_pid(protocol, remote_port, pid);
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

            UINT32 protocol = 0;
            UINT32 local_port = 0;
            UINT32 remote_port = 0;

            if (inFixedValues->valueCount > FWPS_FIELD_ALE_V4_IP_PROTOCOL)
                protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_V4_IP_PROTOCOL].value.uint8;
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_V4_IP_LOCAL_PORT)
                local_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_V4_IP_LOCAL_PORT].value.uint16;
            if (inFixedValues->valueCount > FWPS_FIELD_ALE_V4_IP_REMOTE_PORT)
                remote_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_V4_IP_REMOTE_PORT].value.uint16;

            UINT64 endpoint_handle = 0;
            if (inMetaValues->transportEndpointHandle != 0)
                endpoint_handle = inMetaValues->transportEndpointHandle;

            if (endpoint_handle != 0) {
                aida_store_cached_endpoint_pid(endpoint_handle, protocol, local_port, pid);
            }
            aida_store_cached_port_pid(protocol, local_port, pid);
            if (remote_port != 0)
                aida_store_cached_port_pid(protocol, remote_port, pid);
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
        ULONG required = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, nullptr, 0, &required);
        if (required == 0) return nullptr;

        required += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, required, 'teNW');
        if (!mods) return nullptr;

        status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, mods, required, nullptr);
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
        return base;
    }

    BOOLEAN resolve_wfp_functions() {
        PVOID fwp_base = find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) {

            fwp_base = find_module_base("fwpkclnt.sys");
        }
        if (!fwp_base) {
            return FALSE;
        }

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
        return ok;
    }


    NTSTATUS register_wfp(PDEVICE_OBJECT devObj) {
        if (!devObj) {
            return STATUS_INVALID_PARAMETER;
        }
        g_device_object = devObj;

        NTSTATUS status;


        status = _FwpmEngineOpen0(nullptr, 0x0000000A ,
            nullptr, nullptr, &g_engine_handle);
        if (!NT_SUCCESS(status)) {
            return status;
        }


        status = _FwpmTransactionBegin0(g_engine_handle, 0);
        if (!NT_SUCCESS(status)) {
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
        if (!NT_SUCCESS(status)) {
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
        if (!NT_SUCCESS(status)) {
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
        if (!NT_SUCCESS(status)) {
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
        } else {
            FWPS_CALLOUT2_COMPAT callout_ale_recv_co = {};
            callout_ale_recv_co.calloutKey = GUID_AIDA_CALLOUT_ALE_RECV;
            callout_ale_recv_co.flags = 0;
            callout_ale_recv_co.classifyFn = (PVOID)classify_ale_recv;
            callout_ale_recv_co.notifyFn = (PVOID)callout_notify;
            callout_ale_recv_co.flowDeleteFn = nullptr;

            status = _FwpsCalloutRegister2(devObj, &callout_ale_recv_co, &g_callout_id_ale_recv);
            if (!NT_SUCCESS(status)) {
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
                if (!NT_SUCCESS(status)) {
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
                if (!NT_SUCCESS(status)) {
                    g_filter_id_ale_recv = 0;
                }
            }

        }


        status = STATUS_SUCCESS;


        status = _FwpmTransactionCommit0(g_engine_handle);
        if (!NT_SUCCESS(status)) {
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


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
        LONG prev = _InterlockedCompareExchange(&g_wfp_initialized, 1, 0);
        if (prev == 2) return STATUS_SUCCESS;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_wfp_initialized, 0, 0) == 1)
                YieldProcessor();
            return (g_wfp_initialized == 2) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = STATUS_SUCCESS;


        KeInitializeSpinLock(&g_ring_lock);
        KeInitializeSpinLock(&g_dns_lock);


        SIZE_T ring_size = (SIZE_T)RING_BUFFER_SIZE * sizeof(NET_PACKET_ENTRY);
        g_ring_buffer = (NET_PACKET_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, ring_size, 'pkNW');
        if (!g_ring_buffer) {
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        strong::kmemset(g_ring_buffer, 0, ring_size);

        SIZE_T dns_size = (SIZE_T)DNS_RING_SIZE * sizeof(NET_DNS_ENTRY);
        g_dns_ring = (NET_DNS_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, dns_size, 'dnNW');
        if (!g_dns_ring) {
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        strong::kmemset(g_dns_ring, 0, dns_size);

        net_intercept::init_lock();

        status = net_dpi::init();
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
            _InterlockedExchange(&g_wfp_initialized, 0);
            return status;
        }


        if (!resolve_wfp_functions()) {
            net_dpi::cleanup();
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_NOT_SUPPORTED;
        }


        status = register_wfp(devObj);
        if (!NT_SUCCESS(status)) {
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
        return STATUS_SUCCESS;
    }

    void cleanup() {
        _InterlockedExchange(&g_capture_active, 0);
        unregister_wfp();
        net_inject::cleanup();
        net_stream::cleanup();
        net_dpi::cleanup();

        if (g_ring_buffer) {
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
        }
        if (g_dns_ring) {
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
        }
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
        return STATUS_INVALID_DEVICE_STATE;
    }

    constexpr SYSTEM_INFORMATION_CLASS_INTERNAL system_handle_information_class =
        (SYSTEM_INFORMATION_CLASS_INTERNAL)16;

    ULONG size = 0x10000;
    for (UINT32 attempt = 0; attempt < 8; attempt++) {
        PAIDA_SYSTEM_HANDLE_INFORMATION info = (PAIDA_SYSTEM_HANDLE_INFORMATION)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'hANW');
        if (!info) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG required = 0;
        NTSTATUS status = ZwQuerySystemInformation(system_handle_information_class, info, size, &required);
        if (NT_SUCCESS(status)) {
            *out_info = info;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(info, 'hANW');
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
            return status;
        }

        size = (required > size) ? (required + 0x4000) : (size << 1);
    }

    return STATUS_INSUFFICIENT_RESOURCES;
}

static BOOLEAN aida_is_afd_device_object(PVOID object) {
    if (!object || !_MmIsAddressValid(object)) return FALSE;

    __try {
        PFILE_OBJECT fileObj = (PFILE_OBJECT)object;


        POBJECT_TYPE fileType = (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr;
        NTSTATUS ref_status = ObReferenceObjectByPointer(fileObj, 0, fileType, KernelMode);
        if (!NT_SUCCESS(ref_status)) {
            return FALSE;
        }

        BOOLEAN is_afd = FALSE;


        PDEVICE_OBJECT devObj = fileObj->DeviceObject;
        if (!devObj) {
            ObDereferenceObject(fileObj);
            return FALSE;
        }

        PDRIVER_OBJECT drvObj = devObj->DriverObject;
        if (!drvObj) {
            ObDereferenceObject(fileObj);
            return FALSE;
        }

        PUNICODE_STRING drvName = &drvObj->DriverName;


        if (!drvName->Buffer || drvName->Length < 8) {
            ObDereferenceObject(fileObj);
            return FALSE;
        }

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

        ObDereferenceObject(fileObj);
        return is_afd;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static __forceinline UINT32 aida_sockaddr_addr_len(UINT16 family) {
    return (family == AF_INET6) ? 16u : 4u;
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

static BOOLEAN aida_parse_sockaddr_candidate(PVOID candidate,
                                             UINT32* out_af,
                                             UINT32* out_port,
                                             UINT8* out_addr) {
    if (!candidate || !out_af || !out_port || !out_addr || !_MmIsAddressValid(candidate)) {
        return FALSE;
    }

    __try {
        const UINT8* sa = (const UINT8*)candidate;
        if (!_MmIsAddressValid((PVOID)(sa + sizeof(UINT16) - 1))) {
            return FALSE;
        }

        UINT16 family = *(const UINT16*)(sa + 0);
        if (family == AF_INET) {
            if (!_MmIsAddressValid((PVOID)(sa + 7))) {
                return FALSE;
            }

            UINT16 port_be = *(const UINT16*)(sa + 2);
            strong::kmemset(out_addr, 0, 16);
            strong::kmemcpy(out_addr, sa + 4, 4);
            *out_af = AF_INET;
            *out_port = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);
            return TRUE;
        }

        if (family == AF_INET6) {
            if (!_MmIsAddressValid((PVOID)(sa + 23))) {
                return FALSE;
            }

            UINT16 port_be = *(const UINT16*)(sa + 2);
            strong::kmemset(out_addr, 0, 16);
            strong::kmemcpy(out_addr, sa + 8, 16);
            *out_af = AF_INET6;
            *out_port = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);
            return TRUE;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

static VOID aida_capture_socket_endpoint(SOCKET_HANDLE_ENTRY* out,
                                         UINT32 af,
                                         UINT32 port,
                                         const UINT8* addr) {
    if (!out || !addr) {
        return;
    }

    UINT32 copy_len = aida_sockaddr_addr_len((UINT16)af);
    if (port == 0 && net_capture::is_zero_ip(addr)) {
        return;
    }

    if (out->address_family == 0) {
        out->address_family = af;
    }

    if (out->local_port == 0 && net_capture::is_zero_ip(out->local_addr)) {
        out->local_port = port;
        strong::kmemcpy(out->local_addr, addr, copy_len);
        return;
    }

    if (out->local_port == port && aida_ip_bytes_equal(out->local_addr, addr, copy_len)) {
        return;
    }

    if (out->remote_port == 0 && net_capture::is_zero_ip(out->remote_addr)) {
        out->remote_port = port;
        strong::kmemcpy(out->remote_addr, addr, copy_len);
    }
}

static BOOLEAN aida_extract_socket_info(PVOID file_object, SOCKET_HANDLE_ENTRY* out) {
    if (!file_object || !out || !_MmIsAddressValid(file_object)) return FALSE;

    PFILE_OBJECT fo = (PFILE_OBJECT)file_object;
    BOOLEAN referenced = FALSE;
    BOOLEAN result = FALSE;

    __try {
        POBJECT_TYPE fileType = (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr;
        NTSTATUS ref_status = ObReferenceObjectByPointer(fo, 0, fileType, KernelMode);
        if (!NT_SUCCESS(ref_status)) {
            result = FALSE;
            __leave;
        }
        referenced = TRUE;

        PVOID afd_endpoint = fo->FsContext;
        if (!afd_endpoint || !_MmIsAddressValid(afd_endpoint)) {
            result = FALSE;
            __leave;
        }

        out->afd_endpoint_addr = (UINT64)afd_endpoint;
        UINT8* ep = (UINT8*)afd_endpoint;

        if (_MmIsAddressValid(ep + 0x14)) {
            out->address_family = *(UINT16*)(ep + 0x14);
        }
        if (_MmIsAddressValid(ep + 0x18)) {
            LONG proto = *(LONG*)(ep + 0x18);
            out->protocol = (UINT32)(proto > 0 ? proto : 0);
        }

        out->state = 0;
        out->local_port = 0;
        out->remote_port = 0;
        strong::kmemset(out->local_addr, 0, 16);
        strong::kmemset(out->remote_addr, 0, 16);

        for (UINT32 offset = 0x20; offset <= 0x90; offset += (UINT32)sizeof(PVOID)) {
            if (!_MmIsAddressValid(ep + offset + sizeof(PVOID) - 1)) {
                continue;
            }

            PVOID candidate = *(PVOID*)(ep + offset);
            UINT32 cand_af = 0;
            UINT32 cand_port = 0;
            UINT8 cand_addr[16] = {};
            if (!aida_parse_sockaddr_candidate(candidate, &cand_af, &cand_port, cand_addr)) {
                continue;
            }

            aida_capture_socket_endpoint(out, cand_af, cand_port, cand_addr);
            if (out->local_port != 0 && out->remote_port != 0) {
                break;
            }
        }

        if (out->local_port == 0 && _MmIsAddressValid(ep + 0x20)) {
            PVOID local_info = *(PVOID*)(ep + 0x20);
            UINT32 cand_af = 0;
            UINT32 cand_port = 0;
            UINT8 cand_addr[16] = {};
            if (aida_parse_sockaddr_candidate(local_info, &cand_af, &cand_port, cand_addr)) {
                aida_capture_socket_endpoint(out, cand_af, cand_port, cand_addr);
            }
        }

        result = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }

    if (referenced) {
        ObDereferenceObject(fo);
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

    while (_InterlockedCompareExchange(&g_endpoint_pid_cache_lock_state, 2, 2) != 2) {
        YieldProcessor();
    }
}

static BOOLEAN aida_socket_matches_ports(const SOCKET_HANDLE_ENTRY* socket_info,
                                         UINT32 protocol,
                                         UINT32 local_port,
                                         UINT32 remote_port) {
    if (!socket_info) return FALSE;
    if (protocol != 0 && socket_info->protocol != 0 && socket_info->protocol != protocol)
        return FALSE;
    if (local_port != 0 && socket_info->local_port != local_port && socket_info->remote_port != local_port)
        return FALSE;
    if (remote_port != 0 && socket_info->remote_port != 0 &&
        socket_info->local_port != remote_port && socket_info->remote_port != remote_port) {
        return FALSE;
    }
    return TRUE;
}

static UINT32 aida_lookup_cached_endpoint_pid(UINT64 endpoint_handle,
                                              UINT32 protocol,
                                              UINT32 local_port) {
    if (endpoint_handle == 0) return 0;

    aida_ensure_endpoint_pid_cache_init();

    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    for (UINT32 i = 0; i < AIDA_ENDPOINT_PID_CACHE_SIZE; i++) {
        const AIDA_ENDPOINT_PID_CACHE_ENTRY* entry = &g_endpoint_pid_cache[i];
        if (!entry->active) continue;
        if (entry->endpoint_handle != endpoint_handle) continue;
        if (entry->protocol != 0 && protocol != 0 && entry->protocol != protocol) continue;
        if (entry->local_port != 0 && local_port != 0 && entry->local_port != local_port) continue;

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
    g_endpoint_pid_cache[slot].endpoint_handle = endpoint_handle;
    g_endpoint_pid_cache[slot].protocol = protocol;
    g_endpoint_pid_cache[slot].local_port = local_port;
    g_endpoint_pid_cache[slot].pid = pid;
    KeMemoryBarrier();
    _InterlockedExchange(&g_endpoint_pid_cache[slot].active, 1);
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
    g_port_pid_cache[slot].protocol = protocol;
    g_port_pid_cache[slot].port = port;
    g_port_pid_cache[slot].pid = pid;
    KeMemoryBarrier();
    _InterlockedExchange(&g_port_pid_cache[slot].active, 1);
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

    UINT32 cached = 0;
    __try {
        for (ULONG i = 0; i < handles->NumberOfHandles; i++) {
            const AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry = &handles->Handles[i];
            UINT32 pid = (UINT32)entry->UniqueProcessId;
            if (pid != target_pid || !entry->Object)
                continue;
            if (!aida_is_afd_device_object(entry->Object))
                continue;

            SOCKET_HANDLE_ENTRY socket_info = {};
            if (!aida_extract_socket_info(entry->Object, &socket_info))
                continue;
            if (protocol_filter != 0 && socket_info.protocol != 0 && socket_info.protocol != protocol_filter)
                continue;

            aida_cache_pid_from_socket_info(&socket_info, pid);
            cached++;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    ExFreePoolWithTag(handles, 'hANW');

    if (!NT_SUCCESS(status))
        return status;
    return (cached != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static __forceinline BOOLEAN aida_can_query_system_handles() {
    KIRQL irql = KeGetCurrentIrql();
    if (irql == PASSIVE_LEVEL)
        return TRUE;

    if (_InterlockedCompareExchange(&g_handle_query_irql_warned, 1, 0) == 0) {
    }
    return FALSE;
}

static UINT32 aida_resolve_packet_pid(UINT64 endpoint_handle,
                                      UINT32 protocol,
                                      UINT32 local_port,
                                      UINT32 remote_port) {
    UINT32 cached_pid = aida_lookup_cached_endpoint_pid(endpoint_handle, protocol, local_port);
    if (cached_pid != 0)
        return cached_pid;

    cached_pid = aida_lookup_cached_port_pid(protocol, local_port, remote_port);
    if (cached_pid != 0)
        return cached_pid;

    if (!aida_can_query_system_handles())
        return 0;

    PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
    NTSTATUS status = aida_query_system_handles(&handles);
    if (!NT_SUCCESS(status) || !handles)
        return 0;

    UINT32 resolved_pid = 0;
    __try {
        for (ULONG i = 0; i < handles->NumberOfHandles; i++) {
            const AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry = &handles->Handles[i];
            if (!entry->Object || !aida_is_afd_device_object(entry->Object))
                continue;

            SOCKET_HANDLE_ENTRY socket_info = {};
            if (!aida_extract_socket_info(entry->Object, &socket_info))
                continue;

            BOOLEAN endpoint_match = (endpoint_handle != 0 && socket_info.afd_endpoint_addr == endpoint_handle);
            BOOLEAN tuple_match = FALSE;
            if (!endpoint_match && local_port != 0) {
                tuple_match = aida_socket_matches_ports(&socket_info, protocol, local_port, remote_port);
            }

            if (!endpoint_match && !tuple_match)
                continue;

            resolved_pid = (UINT32)entry->UniqueProcessId;
            if (endpoint_match) {
                aida_store_cached_endpoint_pid(endpoint_handle, protocol, local_port, resolved_pid);
            }
            aida_store_cached_port_pid(protocol, local_port, resolved_pid);
            aida_store_cached_port_pid(protocol, remote_port, resolved_pid);
            break;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        resolved_pid = 0;
    }

    ExFreePoolWithTag(handles, 'hANW');
    return resolved_pid;
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
        UINT64 NsiHandle, UINT32 Nsi0, const PVOID NsiModule,
        UINT32 NsiType, PVOID KeyData, UINT32 KeySize,
        PVOID RwParamData, UINT32 RwParamSize,
        PVOID DynParamData, UINT32 DynParamSize,
        PVOID StaticParamData, UINT32 StaticParamSize,
        PUINT32 Count);

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
    typedef struct _NSI_TCP_KEY {
        UINT8  local_addr[16];
        UINT32 local_port;
        UINT8  remote_addr[16];
        UINT32 remote_port;
    } NSI_TCP_KEY;

    typedef struct _NSI_TCP_DYNAMIC {
        UINT32 state;
    } NSI_TCP_DYNAMIC;

    typedef struct _NSI_TCP_STATIC {
        UINT32 pid;
        UINT64 create_time;
    } NSI_TCP_STATIC;

    typedef struct _NSI_UDP_KEY {
        UINT8  local_addr[16];
        UINT32 local_port;
    } NSI_UDP_KEY;

    typedef struct _NSI_UDP_STATIC {
        UINT32 pid;
        UINT64 create_time;
    } NSI_UDP_STATIC;
    #pragma pack(pop)

    BOOLEAN resolve_nsi() {
        LONG prev = _InterlockedCompareExchange(&g_nsi_resolved, 1, 0);
        if (prev == 2) return _NsiEnumerate != nullptr;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_nsi_resolved, 0, 0) == 1)
                YieldProcessor();
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
        return _NsiEnumerate != nullptr;
    }

    NTSTATUS enumerate_connections(p_net_enum_conn request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->connection_count = 0;

        PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
        NTSTATUS status = aida_query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles) {
            return status;
        }

        __try {
            for (ULONG i = 0; i < handles->NumberOfHandles && request->connection_count < MAX_NET_CONNECTIONS; i++) {
                const AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry = &handles->Handles[i];
                UINT32 pid = (UINT32)entry->UniqueProcessId;
                if (request->filter_pid != 0 && pid != request->filter_pid)
                    continue;
                if (!entry->Object || !aida_is_afd_device_object(entry->Object))
                    continue;

                SOCKET_HANDLE_ENTRY socket_info = {};
                aida_extract_socket_info(entry->Object, &socket_info);
                if (request->filter_protocol != 0 && socket_info.protocol != 0 &&
                    socket_info.protocol != request->filter_protocol) {
                    continue;
                }

                NET_CONN_ENTRY* out = &request->entries[request->connection_count];
                strong::kmemset(out, 0, sizeof(NET_CONN_ENTRY));
                out->pid = pid;
                out->protocol = socket_info.protocol;
                out->state = socket_info.state;
                out->local_port = socket_info.local_port;
                out->remote_port = socket_info.remote_port;
                out->address_family = socket_info.address_family;
                strong::kmemcpy(out->local_addr, socket_info.local_addr, 16);
                strong::kmemcpy(out->remote_addr, socket_info.remote_addr, 16);
                request->connection_count++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            ExFreePoolWithTag(handles, 'hANW');
            return STATUS_ACCESS_VIOLATION;
        }

        ExFreePoolWithTag(handles, 'hANW');

        return STATUS_SUCCESS;
    }

}


NTSTATUS functions::handle_net_enum_conn(p_net_enum_conn request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_enum::enumerate_connections(request);
}

NTSTATUS functions::handle_net_cap_ctrl(p_net_cap_ctrl request) {
    if (!request) return STATUS_INVALID_PARAMETER;

    if (net_capture::g_wfp_initialized != 2) {
        return STATUS_DEVICE_NOT_READY;
    }

    switch (request->operation) {
        case 0: {
            net_capture::g_filter_pid = request->filter_pid;
            net_capture::g_filter_port = request->filter_port;
            net_capture::g_filter_protocol = request->filter_protocol;
            strong::kmemcpy(net_capture::g_filter_ip, request->filter_ip, 16);
            if (request->filter_pid != 0) {
                NTSTATUS cache_status = aida_refresh_pid_cache_for_process(
                    request->filter_pid,
                    request->filter_protocol);
            }
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

            request->capture_active = 1;
            break;
        }
        case 1: {
            _InterlockedExchange(&net_capture::g_capture_active, 0);
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
    if (!request) return STATUS_INVALID_PARAMETER;
    if (!net_capture::g_ring_buffer) return STATUS_DEVICE_NOT_READY;

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
    if (!request) return STATUS_INVALID_PARAMETER;
    if (!net_capture::g_dns_ring) return STATUS_DEVICE_NOT_READY;

    request->entry_count = 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&net_capture::g_dns_lock, &old_irql);

    UINT32 available = (UINT32)net_capture::g_dns_count;
    UINT32 to_read = (available < NET_DNS_GET_MAX) ? available : NET_DNS_GET_MAX;

    UINT32 out_idx = 0;
    for (UINT32 i = 0; i < to_read; i++) {
        NET_DNS_ENTRY* src = &net_capture::g_dns_ring[net_capture::g_dns_tail];


        if (request->filter_pid == 0 || src->pid == request->filter_pid) {
            strong::kmemcpy(&request->entries[out_idx], src, sizeof(NET_DNS_ENTRY));
            out_idx++;
        }

        net_capture::g_dns_tail = (net_capture::g_dns_tail + 1) % DNS_RING_SIZE;
        net_capture::g_dns_count--;
    }

    request->entry_count = out_idx;

    KeReleaseSpinLock(&net_capture::g_dns_lock, old_irql);

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_net_filter_rule(p_net_filter_rule request) {
    if (!request) return STATUS_INVALID_PARAMETER;

    switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                if (_InterlockedCompareExchange(&net_capture::g_filter_rules[i].active, 1, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&net_capture::g_next_rule_id);
                    net_capture::g_filter_rules[i].rule_id = id;
                    net_capture::g_filter_rules[i].action = request->action;
                    net_capture::g_filter_rules[i].direction = request->direction;
                    net_capture::g_filter_rules[i].protocol = request->protocol;
                    net_capture::g_filter_rules[i].pid = request->pid;
                    net_capture::g_filter_rules[i].port = request->port;
                    strong::kmemcpy(net_capture::g_filter_rules[i].ip_addr, request->ip_addr, 16);
                    strong::kmemcpy(net_capture::g_filter_rules[i].ip_mask, request->ip_mask, 16);
                    _InterlockedIncrement(&net_capture::g_active_rule_count);

                    request->rule_id = id;
                    request->rule_count = (UINT32)net_capture::g_active_rule_count;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                if (net_capture::g_filter_rules[i].active &&
                    net_capture::g_filter_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&net_capture::g_filter_rules[i].active, 0);
                    _InterlockedDecrement(&net_capture::g_active_rule_count);
                    request->rule_count = (UINT32)net_capture::g_active_rule_count;
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
    if (!request) return STATUS_INVALID_PARAMETER;

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


namespace net_socket_enum {
    typedef AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL;
    typedef AIDA_SYSTEM_HANDLE_INFORMATION SYSTEM_HANDLE_INFORMATION_LOCAL;
    typedef PAIDA_SYSTEM_HANDLE_INFORMATION PSYSTEM_HANDLE_INFORMATION_LOCAL;

    static BOOLEAN is_afd_device_object(PVOID object) {
        return aida_is_afd_device_object(object);
    }

    static NTSTATUS query_system_handles(PSYSTEM_HANDLE_INFORMATION_LOCAL* out_info) {
        return aida_query_system_handles(out_info);
    }

    static BOOLEAN extract_socket_info(PVOID file_object, SOCKET_HANDLE_ENTRY* out) {
        return aida_extract_socket_info(file_object, out);
    }

    static NTSTATUS enumerate_socket_handles(p_socket_handle_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->socket_count = 0;

        UINT32 target_pid = request->target_pid;
        if (target_pid == 0) return STATUS_INVALID_PARAMETER;

        PSYSTEM_HANDLE_INFORMATION_LOCAL handles = nullptr;
        NTSTATUS status = query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles) {
            return status;
        }

        UINT32 filled = 0;
        __try {
            for (ULONG i = 0; i < handles->NumberOfHandles && filled < MAX_SOCKET_HANDLES; i++) {
                const SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL* entry = &handles->Handles[i];
                if ((UINT32)entry->UniqueProcessId != target_pid || !entry->Object)
                    continue;
                if (!is_afd_device_object(entry->Object))
                    continue;

                SOCKET_HANDLE_ENTRY* out = &request->entries[filled];
                strong::kmemset(out, 0, sizeof(SOCKET_HANDLE_ENTRY));
                out->handle_value = (UINT64)entry->HandleValue;
                out->pid = target_pid;

                if (!extract_socket_info(entry->Object, out)) {
                    out->afd_endpoint_addr = (UINT64)((PFILE_OBJECT)entry->Object)->FsContext;
                }

                aida_cache_pid_from_socket_info(out, target_pid);

                filled++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            ExFreePoolWithTag(handles, 'hANW');
            return STATUS_ACCESS_VIOLATION;
        }

        ExFreePoolWithTag(handles, 'hANW');
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
        UINT64 create_time;
        UINT64 mod_pid;
    } TCP4_STATIC;

    typedef struct _UDP4_KEY {
        UINT8  local_addr[4];
        UINT32 pad1;
        UINT16 local_port_be;
        UINT16 pad2;
    } UDP4_KEY;

    typedef struct _UDP4_STATIC {
        UINT64 create_time;
        UINT64 mod_pid;
    } UDP4_STATIC;
    #pragma pack(pop)

    static NTSTATUS dump_connections(p_tcpip_conn_dump request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->connection_count = 0;

        PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
        NTSTATUS status = aida_query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles) {
            return status;
        }

        UINT32 filled = 0;
        __try {
            for (ULONG i = 0; i < handles->NumberOfHandles && filled < MAX_TCPIP_CONNECTIONS; i++) {
                const AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry = &handles->Handles[i];
                UINT32 pid = (UINT32)entry->UniqueProcessId;
                if (request->target_pid != 0 && pid != request->target_pid)
                    continue;
                if (!entry->Object || !aida_is_afd_device_object(entry->Object))
                    continue;

                SOCKET_HANDLE_ENTRY socket_info = {};
                aida_extract_socket_info(entry->Object, &socket_info);
                if (request->filter_protocol != 0 && socket_info.protocol != 0 &&
                    socket_info.protocol != request->filter_protocol) {
                    continue;
                }

                TCPIP_CONN_ENTRY* out = &request->entries[filled];
                strong::kmemset(out, 0, sizeof(TCPIP_CONN_ENTRY));
                out->pid = pid;
                out->protocol = socket_info.protocol;
                out->state = socket_info.state;
                out->local_port = socket_info.local_port;
                out->remote_port = socket_info.remote_port;
                out->address_family = socket_info.address_family;
                out->tcb_address = socket_info.afd_endpoint_addr;
                strong::kmemcpy(out->local_addr, socket_info.local_addr, 16);
                strong::kmemcpy(out->remote_addr, socket_info.remote_addr, 16);
                filled++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            ExFreePoolWithTag(handles, 'hANW');
            return STATUS_ACCESS_VIOLATION;
        }

        ExFreePoolWithTag(handles, 'hANW');
        request->connection_count = filled;
        return STATUS_SUCCESS;
    }
}


namespace net_inject {


    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleCreate0)(
        UINT16 addressFamily, UINT32 flags, HANDLE* injectionHandle);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleDestroy0)(HANDLE injectionHandle);
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
        LONG prev = _InterlockedCompareExchange(&g_inject_resolved, 1, 0);
        if (prev == 2) return g_inject_handle_v4 != nullptr;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_inject_resolved, 0, 0) == 1)
                YieldProcessor();
            return g_inject_handle_v4 != nullptr;
        }

        PVOID fwp_base = net_capture::find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) fwp_base = net_capture::find_module_base("fwpkclnt.sys");
        if (!fwp_base) { _InterlockedExchange(&g_inject_resolved, 2); return FALSE; }

        CHAR f1[] = {'F','w','p','s','I','n','j','e','c','t','i','o','n','H','a','n','d','l','e','C','r','e','a','t','e','0',0};
        CHAR f2[] = {'F','w','p','s','I','n','j','e','c','t','i','o','n','H','a','n','d','l','e','D','e','s','t','r','o','y','0',0};
        CHAR f3[] = {'F','w','p','s','A','l','l','o','c','a','t','e','N','e','t','B','u','f','f','e','r','A','n','d','N','e','t','B','u','f','f','e','r','L','i','s','t','0',0};
        CHAR f4[] = {'F','w','p','s','F','r','e','e','N','e','t','B','u','f','f','e','r','L','i','s','t','0',0};
        CHAR f5[] = {'F','w','p','s','I','n','j','e','c','t','T','r','a','n','s','p','o','r','t','S','e','n','d','A','s','y','n','c','0',0};
        CHAR f6[] = {'F','w','p','s','I','n','j','e','c','t','T','r','a','n','s','p','o','r','t','R','e','c','e','i','v','e','A','s','y','n','c','0',0};
        CHAR f7[] = {'F','w','p','s','I','n','j','e','c','t','N','e','t','w','o','r','k','S','e','n','d','A','s','y','n','c','0',0};
        CHAR f8[] = {'F','w','p','s','I','n','j','e','c','t','N','e','t','w','o','r','k','R','e','c','e','i','v','e','A','s','y','n','c','0',0};
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
        if (ndis_base) {
            *(PVOID*)&_NdisAllocateNetBufferListPool = GetProcAddress(ndis_base, n1);
            *(PVOID*)&_NdisFreeNetBufferListPool = GetProcAddress(ndis_base, n2);
        }

        if (_FwpsInjectionHandleCreate0) {
            NTSTATUS st = _FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &g_inject_handle_v4);
            if (!NT_SUCCESS(st)) g_inject_handle_v4 = nullptr;

            st = _FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &g_inject_handle_net_v4);
            if (!NT_SUCCESS(st)) g_inject_handle_net_v4 = nullptr;
        } else {
        }

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

        if (!resolve_inject_functions())
            return STATUS_NOT_SUPPORTED;

        if (!ensure_inject_nbl_pool())
            return STATUS_INSUFFICIENT_RESOURCES;

        BOOLEAN have_transport = (g_inject_handle_v4 != nullptr && _FwpsInjectSend0 && _FwpsInjectRecv0);
        BOOLEAN have_network = (g_inject_handle_net_v4 != nullptr && (_FwpsInjectNetSend0 || _FwpsInjectNetRecv0));
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
            return STATUS_INVALID_PARAMETER;
        }

        BOOLEAN loopback_v4 =
            request->address_family == AF_INET &&
            is_loopback_ipv4_addr(request->src_addr) &&
            is_loopback_ipv4_addr(request->dst_addr);
        UINT32 recv_interface_index = loopback_v4 ? 1u : 0u;

        UINT64 endpoint_handle = lookup_endpoint_handle_by_port(request->protocol, request->src_port);

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
                request->status = 0;
                return STATUS_SUCCESS;
            }

            _FwpsFreeNBL0(nbl);
            IoFreeMdl(mdl);
            ExFreePoolWithTag(completion, 'jcNW');
            ExFreePoolWithTag(buf, 'jiNW');
        }

        if (!have_network) {
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
            st = _FwpsInjectNetSend0(g_inject_handle_net_v4, nullptr, 0, 0,
                net_nbl, (PVOID)inject_completion, net_completion);
        } else if (_FwpsInjectNetRecv0) {
            st = _FwpsInjectNetRecv0(g_inject_handle_net_v4, nullptr, 0, 0,
                recv_interface_index, 0, net_nbl,
                (PVOID)inject_completion, net_completion);
        } else if (_FwpsInjectNetSend0) {
            st = _FwpsInjectNetSend0(g_inject_handle_net_v4, nullptr, 0, 0,
                net_nbl, (PVOID)inject_completion, net_completion);
        } else {
            st = STATUS_NOT_SUPPORTED;
        }

        if (!NT_SUCCESS(st)) {
            _FwpsFreeNBL0(net_nbl);
            IoFreeMdl(net_mdl);
            ExFreePoolWithTag(net_completion, 'jcNW');
            ExFreePoolWithTag(net_buf, 'jiNW');
            return st;
        }

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
            if (!g_mod_rules[r].active) continue;
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
                    i += rule->replace_size - 1;
                }
            }
        }
        return modified;
    }

    NTSTATUS handle_mod_rule(p_packet_mod_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (!g_mod_rules[i].active) {
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
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (g_mod_rules[i].active && g_mod_rules[i].rule_id == request->rule_id) {
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
                if (g_mod_rules[i].active) {
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
            if (g_mod_rules[i].active) {
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
    } ACTIVE_REDIR_RULE;

    inline ACTIVE_REDIR_RULE g_redir_rules[REDIR_MAX_RULES] = {};
    inline volatile LONG g_next_redir_id = 1;
    inline volatile LONG g_active_redir_count = 0;

    BOOLEAN has_active_rules() {
        return (g_active_redir_count != 0);
    }


    BOOLEAN check_redirect(UINT32 protocol, UINT32 dst_port, const UINT8* dst_addr,
                           UINT32 af, UINT32* new_port, UINT8* new_addr) {
        if (g_active_redir_count == 0) return FALSE;
        for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
            if (!g_redir_rules[i].active) continue;
            ACTIVE_REDIR_RULE* r = &g_redir_rules[i];
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

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (!g_redir_rules[i].active) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&g_next_redir_id);
                    g_redir_rules[i].rule_id = id;
                    g_redir_rules[i].protocol = request->protocol;
                    g_redir_rules[i].match_port = request->match_port;
                    strong::kmemcpy(g_redir_rules[i].match_addr, request->match_addr, 16);
                    g_redir_rules[i].redirect_port = request->redirect_port;
                    strong::kmemcpy(g_redir_rules[i].redirect_addr, request->redirect_addr, 16);
                    g_redir_rules[i].address_family = request->address_family;
                    g_redir_rules[i].match_count = 0;
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_redir_rules[i].active, 1);
                    _InterlockedIncrement(&g_active_redir_count);
                    request->rule_id = id;
                    request->active = 1;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (g_redir_rules[i].active && g_redir_rules[i].rule_id == request->rule_id) {
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
                if (g_redir_rules[i].active) {
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
            if (g_redir_rules[i].active) {
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

    #define MAX_TRACKED_STREAMS 8

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

    BOOLEAN has_active_streams() {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            if (g_streams[i].active)
                return TRUE;
        }
        return FALSE;
    }


    void feed_packet(UINT32 src_port, UINT32 dst_port, UINT32 pid,
                     const UINT8* src_addr, const UINT8* dst_addr,
                     const UINT8* data, UINT32 data_len) {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            if (!g_streams[i].active) continue;

            BOOLEAN match = FALSE;
            BOOLEAN src_addr_wildcard = net_capture::is_zero_ip(g_streams[i].src_addr);
            BOOLEAN dst_addr_wildcard = net_capture::is_zero_ip(g_streams[i].dst_addr);

            BOOLEAN forward_port_match =
                (g_streams[i].src_port == 0 || g_streams[i].src_port == src_port) &&
                (g_streams[i].dst_port == 0 || g_streams[i].dst_port == dst_port);
            if (forward_port_match) {
                BOOLEAN addr_match = TRUE;
                if (!src_addr_wildcard) {
                    for (int j = 0; j < 4; j++) {
                        if (g_streams[i].src_addr[j] != src_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match && !dst_addr_wildcard) {
                    for (int j = 0; j < 4; j++) {
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
                    for (int j = 0; j < 4; j++) {
                        if (g_streams[i].src_addr[j] != dst_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match && !dst_addr_wildcard) {
                    for (int j = 0; j < 4; j++) {
                        if (g_streams[i].dst_addr[j] != src_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match) match = TRUE;
            }
            if (g_streams[i].pid != 0 && pid != 0 && g_streams[i].pid != pid) match = FALSE;

            if (match && g_streams[i].stream_data && data_len > 0) {
                KIRQL irql;
                KeAcquireSpinLock(&g_streams[i].lock, &irql);
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
                KeReleaseSpinLock(&g_streams[i].lock, irql);
            }
        }
    }

    NTSTATUS handle_stream(p_stream_reassemble_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (!g_streams[i].active) {
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
                        if (!g_streams[i].stream_data) return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    strong::kmemset(g_streams[i].stream_data, 0, STREAM_MAX_SIZE);
                    KeInitializeSpinLock(&g_streams[i].lock);
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_streams[i].active, 1);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active &&
                    g_streams[i].src_port == request->src_port &&
                    g_streams[i].dst_port == request->dst_port) {
                    _InterlockedExchange(&g_streams[i].active, 0);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 2: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active &&
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
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 3: {
            request->stream_count = 0;
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active) request->stream_count++;
            }
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            _InterlockedExchange(&g_streams[i].active, 0);
            if (g_streams[i].stream_data) {
                ExFreePoolWithTag(g_streams[i].stream_data, 'stNW');
                g_streams[i].stream_data = nullptr;
            }
        }
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
        _InterlockedExchange(&g_dpi_active, 1);
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


            if (request->filter_pid != 0 && src->pid != 0 && src->pid != request->filter_pid) goto next;
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
        if (g_filter_pid != 0 && pid != 0 && pid != g_filter_pid) return FALSE;
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
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {

                    if (net_inject::g_inject_handle_v4 && g_held[i].payload_size > 0) {
                        packet_inject_request inj = {};
                        inj.direction = g_held[i].direction;
                        inj.protocol = g_held[i].protocol;
                        inj.address_family = g_held[i].address_family;
                        inj.src_port = g_held[i].src_port;
                        inj.dst_port = g_held[i].dst_port;
                        strong::kmemcpy(inj.src_addr, g_held[i].src_addr, 16);
                        strong::kmemcpy(inj.dst_addr, g_held[i].dst_addr, 16);
                        inj.payload_size = g_held[i].payload_size;
                        strong::kmemcpy(inj.payload, g_held[i].payload, g_held[i].payload_size);
                        KeReleaseSpinLock(&g_intercept_lock, irql);
                        net_inject::inject_packet(&inj);
                        KeAcquireSpinLock(&g_intercept_lock, &irql);
                    }
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
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {

                    if (net_inject::g_inject_handle_v4 && request->modify_payload_size > 0 &&
                        request->modify_payload_size <= INTERCEPT_MAX_PAYLOAD) {
                        packet_inject_request inj = {};
                        inj.direction = g_held[i].direction;
                        inj.protocol = g_held[i].protocol;
                        inj.address_family = g_held[i].address_family;
                        inj.src_port = g_held[i].src_port;
                        inj.dst_port = g_held[i].dst_port;
                        strong::kmemcpy(inj.src_addr, g_held[i].src_addr, 16);
                        strong::kmemcpy(inj.dst_addr, g_held[i].dst_addr, 16);
                        inj.payload_size = request->modify_payload_size;
                        strong::kmemcpy(inj.payload, request->modify_payload, request->modify_payload_size);
                        KeReleaseSpinLock(&g_intercept_lock, irql);
                        net_inject::inject_packet(&inj);
                        KeAcquireSpinLock(&g_intercept_lock, &irql);
                    }
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
        default:
            return STATUS_INVALID_PARAMETER;
        }
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

        PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
        NTSTATUS status = aida_query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles)
            return 0;

        UINT32 owner_pid = 0;
        __try {
            for (ULONG i = 0; i < handles->NumberOfHandles; i++) {
                const AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry = &handles->Handles[i];
                if (!entry->Object)
                    continue;
                if (!aida_is_afd_device_object(entry->Object))
                    continue;

                SOCKET_HANDLE_ENTRY socket_info = {};
                if (!aida_extract_socket_info(entry->Object, &socket_info))
                    continue;
                if (!socket_matches_kill_request(&socket_info, request)) {
                    continue;
                }

                owner_pid = (UINT32)entry->UniqueProcessId;
                if (owner_pid != 0) {
                    aida_cache_pid_from_socket_info(&socket_info, owner_pid);
                    break;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            owner_pid = 0;
        }

        ExFreePoolWithTag(handles, 'hANW');
        return owner_pid;
    }

    static NTSTATUS close_matching_socket(UINT32 owner_pid, p_conn_kill_request request) {
        PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
        NTSTATUS status = aida_query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles) {
            return status;
        }

        PEPROCESS process = nullptr;
        status = stack_spoof::spoofed_PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)owner_pid, &process);
        if (!NT_SUCCESS(status) || !process) {
            ExFreePoolWithTag(handles, 'hANW');
            return status;
        }

        NTSTATUS close_status = STATUS_NOT_FOUND;
        __try {
            for (ULONG i = 0; i < handles->NumberOfHandles; i++) {
                const AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry = &handles->Handles[i];
                if ((UINT32)entry->UniqueProcessId != owner_pid || !entry->Object)
                    continue;
                if (!aida_is_afd_device_object(entry->Object))
                    continue;

                SOCKET_HANDLE_ENTRY socket_info = {};
                if (!aida_extract_socket_info(entry->Object, &socket_info))
                    continue;
                if (!socket_matches_kill_request(&socket_info, request)) {
                    continue;
                }

                KAPC_STATE apc = {};
                KeStackAttachProcess(process, &apc);
                close_status = ZwClose((HANDLE)(ULONG_PTR)entry->HandleValue);
                KeUnstackDetachProcess(&apc);
                if (NT_SUCCESS(close_status)) {
                    break;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            close_status = STATUS_ACCESS_VIOLATION;
        }

        ExFreePoolWithTag(handles, 'hANW');
        stack_spoof::spoofed_ObfDereferenceObject(process);
        return close_status;
    }

    static NTSTATUS resolve_and_close_socket(p_conn_kill_request request) {
        PAIDA_SYSTEM_HANDLE_INFORMATION handles = nullptr;
        NTSTATUS status = aida_query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles) {
            return status;
        }

        NTSTATUS close_status = STATUS_NOT_FOUND;
        __try {
            for (ULONG i = 0; i < handles->NumberOfHandles; i++) {
                const AIDA_SYSTEM_HANDLE_TABLE_ENTRY_INFO* entry = &handles->Handles[i];
                if (!entry->Object)
                    continue;
                if (!aida_is_afd_device_object(entry->Object))
                    continue;

                SOCKET_HANDLE_ENTRY socket_info = {};
                if (!aida_extract_socket_info(entry->Object, &socket_info))
                    continue;
                if (!socket_matches_kill_request(&socket_info, request))
                    continue;

                UINT32 owner_pid = (UINT32)entry->UniqueProcessId;
                if (owner_pid == 0)
                    continue;

                aida_cache_pid_from_socket_info(&socket_info, owner_pid);

                PEPROCESS process = nullptr;
                status = stack_spoof::spoofed_PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)owner_pid, &process);
                if (!NT_SUCCESS(status) || !process)
                    continue;

                KAPC_STATE apc = {};
                KeStackAttachProcess(process, &apc);
                close_status = ZwClose((HANDLE)(ULONG_PTR)entry->HandleValue);
                KeUnstackDetachProcess(&apc);
                stack_spoof::spoofed_ObfDereferenceObject(process);

                if (NT_SUCCESS(close_status)) {
                    break;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            close_status = STATUS_ACCESS_VIOLATION;
        }

        ExFreePoolWithTag(handles, 'hANW');
        return close_status;
    }

    NTSTATUS kill_connection(p_conn_kill_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->status = 1;

        if (request->protocol != 6) return STATUS_INVALID_PARAMETER;

        UINT32 owner_pid = request->pid;
        if (owner_pid != 0) {
            NTSTATUS st = close_matching_socket(owner_pid, request);
            if (NT_SUCCESS(st)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
            NTSTATUS rst_status = inject_tcp_reset_fallback(request);
            if (NT_SUCCESS(rst_status)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
            return NT_SUCCESS(st) ? rst_status : st;
        }

        owner_pid = resolve_owner_pid_by_tuple(request);
        if (owner_pid != 0) {
            NTSTATUS st = close_matching_socket(owner_pid, request);
            if (NT_SUCCESS(st)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
        }

        NTSTATUS st = resolve_and_close_socket(request);
        if (NT_SUCCESS(st)) {
            request->status = 0;
            return STATUS_SUCCESS;
        }

        NTSTATUS rst_status = inject_tcp_reset_fallback(request);
        if (NT_SUCCESS(rst_status)) {
            request->status = 0;
            return STATUS_SUCCESS;
        }
        return NT_SUCCESS(st) ? rst_status : st;
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
            if (!g_spoof_rules[i].active) continue;
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
                if (!g_spoof_rules[i].active) {
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
                if (g_spoof_rules[i].active && g_spoof_rules[i].rule_id == request->rule_id) {
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
                if (g_spoof_rules[i].active) {
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
            if (g_spoof_rules[i].active) {
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
            if (g_bw_entries[i].active && g_bw_entries[i].pid == pid) {
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

    NTSTATUS handle_bw(p_bw_monitor_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0:
            _InterlockedExchange(&g_bw_active, 1);
            request->monitoring_active = 1;
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
                if (g_bw_entries[i].active) {
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
}


namespace net_if_enum {


    typedef NTSTATUS(NTAPI* fn_GetIfTable2)(PVOID* Table);
    typedef void(NTAPI* fn_FreeMibTable)(PVOID Table);
    typedef NTSTATUS(NTAPI* fn_GetAdaptersAddresses)(
        ULONG Family, ULONG Flags, PVOID Reserved,
        PVOID AdapterAddresses, PULONG SizePointer);

    NTSTATUS enumerate_interfaces(p_net_interface_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->interface_count = 0;


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
        if (!NT_SUCCESS(st) || !table) return st;

        __try {


            ULONG num = *(ULONG*)table;
            UINT8* rows = (UINT8*)table + 8;


            #define MIB_IF_ROW2_SIZE 1352

            for (ULONG i = 0; i < num && request->interface_count < NET_IF_MAX; i++) {
                UINT8* row = rows + (SIZE_T)i * MIB_IF_ROW2_SIZE;
                if (!_MmIsAddressValid(row)) break;

                NET_INTERFACE_ENTRY* e = &request->interfaces[request->interface_count];
                strong::kmemset(e, 0, sizeof(NET_INTERFACE_ENTRY));

                e->if_index = *(UINT32*)(row + 0x08);
                e->mtu = *(UINT32*)(row + 0x46C);
                e->if_type = *(UINT32*)(row + 0x470);
                e->speed = *(UINT64*)(row + 0x488);
                e->oper_status = *(UINT32*)(row + 0x498);


                UINT32 phys_len = *(UINT32*)(row + 0x428);
                if (phys_len >= 6) {
                    strong::kmemcpy(e->mac_addr, row + 0x42C, 6);
                }


                wchar_t* alias = (wchar_t*)(row + 0x01C);
                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && alias[j]; j++) {
                    e->name[j] = (char)(alias[j] & 0x7F);
                }


                wchar_t* desc = (wchar_t*)(row + 0x222);
                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && desc[j]; j++) {
                    e->description[j] = (char)(desc[j] & 0x7F);
                }


                e->in_octets = *(UINT64*)(row + 0x508);
                e->out_octets = *(UINT64*)(row + 0x510);

                request->interface_count++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {

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

        LONG count = net_capture::g_ring_count;
        LONG idx = net_capture::g_ring_tail;

        while (count > 0 && request->packet_count < max_pkts) {
            NET_PACKET_ENTRY* pkt = &net_capture::g_ring_buffer[idx];

            if (request->filter_pid != 0 && pkt->pid != 0 && pkt->pid != request->filter_pid) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                count--;
                continue;
            }
            if (request->filter_protocol != 0 && pkt->protocol != request->filter_protocol) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                count--;
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


            UINT32 payload_copy = pkt->payload_size;
            if (ip_header_len + payload_copy > PCAP_RECORD_MAX_SIZE)
                payload_copy = PCAP_RECORD_MAX_SIZE - ip_header_len;
            strong::kmemcpy(&rec->data[ip_header_len], pkt->payload, payload_copy);

            rec->incl_len = ip_header_len + payload_copy;
            rec->orig_len = total_len;
            request->data_size += sizeof(UINT32) * 4 + rec->incl_len;

            request->packet_count++;
            idx = (idx + 1) % RING_BUFFER_SIZE;
            count--;
        }

        KeReleaseSpinLock(&net_capture::g_ring_lock, irql);

        return STATUS_SUCCESS;
    }
}


namespace net_fingerprint {

    inline NET_FINGERPRINT_ENTRY g_fp_entries[FINGERPRINT_MAX] = {};
    inline volatile LONG g_fp_count = 0;
    inline volatile LONG g_fp_active = 0;
    inline KSPIN_LOCK g_fp_lock;

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
            KeInitializeSpinLock(&g_fp_lock);
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
}


NTSTATUS functions::handle_wfp_callout_enum(p_wfp_callout_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_wfp_enum::enumerate_wfp_callouts(request);
    return st;
}

NTSTATUS functions::handle_socket_handle_enum(p_socket_handle_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_socket_enum::enumerate_socket_handles(request);
    return st;
}

NTSTATUS functions::handle_sniff_net_buffers(p_sniff_net_buffers request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_sniff::handle_sniff(request);
}

NTSTATUS functions::handle_tcpip_conn_dump(p_tcpip_conn_dump request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_tcpip::dump_connections(request);
    return st;
}


NTSTATUS functions::handle_packet_inject(p_packet_inject_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_inject::inject_packet(request);
    return st;
}

NTSTATUS functions::handle_packet_mod_rule(p_packet_mod_rule request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_mod::handle_mod_rule(request);
    return st;
}

NTSTATUS functions::handle_packet_mod_rule_list(p_packet_mod_rule_list request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_mod::handle_mod_rule_list(request);
    return st;
}

NTSTATUS functions::handle_traffic_redirect(p_traffic_redirect_rule request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_redirect::handle_redirect_rule(request);
    return st;
}

NTSTATUS functions::handle_traffic_redirect_list(p_traffic_redirect_list request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_redirect::handle_redirect_list(request);
    return st;
}

NTSTATUS functions::handle_stream_reassemble(p_stream_reassemble_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    if (request->operation == 0 && request->pid != 0) {
        NTSTATUS cache_status = aida_refresh_pid_cache_for_process(request->pid, IPPROTO_TCP);
    }
    NTSTATUS st = net_stream::handle_stream(request);
    return st;
}

NTSTATUS functions::handle_deep_inspect(p_dpi_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    if (request->filter_pid != 0) {
        NTSTATUS cache_status = aida_refresh_pid_cache_for_process(request->filter_pid, request->filter_protocol);
    }
    NTSTATUS st = net_dpi::get_results(request);
    return st;
}

NTSTATUS functions::handle_intercept_hold(p_intercept_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    if (request->operation == 0 && request->filter_pid != 0) {
        NTSTATUS cache_status = aida_refresh_pid_cache_for_process(request->filter_pid, request->filter_protocol);
    }
    NTSTATUS st = net_intercept::handle_intercept(request);
    return st;
}

NTSTATUS functions::handle_conn_kill(p_conn_kill_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_kill::kill_connection(request);
    return st;
}

NTSTATUS functions::handle_dns_spoof(p_dns_spoof_rule request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_dns_spoof::handle_spoof_rule(request);
    return st;
}

NTSTATUS functions::handle_dns_spoof_list(p_dns_spoof_list request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_dns_spoof::handle_spoof_list(request);
    return st;
}

NTSTATUS functions::handle_bw_monitor(p_bw_monitor_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_bw::handle_bw(request);
    return st;
}

NTSTATUS functions::handle_net_iface_enum(p_net_interface_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_if_enum::enumerate_interfaces(request);
    return st;
}

NTSTATUS functions::handle_pcap_export(p_pcap_export_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_pcap::export_pcap(request);
    return st;
}

NTSTATUS functions::handle_net_fingerprint(p_net_fingerprint_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_fingerprint::handle_fingerprint(request);
    return st;
}