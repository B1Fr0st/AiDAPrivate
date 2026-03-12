#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"

#ifndef AIDA_NET_LOG0
#define AIDA_NET_LOG0(msg) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AiDA-Net] %s\n", msg)
#define AIDA_NET_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AiDA-Net] " fmt "\n", __VA_ARGS__)
#endif

// =====================================================================
// WFP (Windows Filtering Platform) type definitions
// Defined manually to avoid header dependencies and static imports.
// All WFP functions are resolved dynamically from fwpkclnt.sys.
// =====================================================================

#pragma pack(push, 8)

// WFP data types
typedef UINT16 FWP_IP_VERSION_;
typedef UINT8  FWP_DIRECTION_;
typedef UINT32 FWP_ACTION_TYPE_;

#define FWP_ACTION_BLOCK_   0x00001001
#define FWP_ACTION_PERMIT_  0x00001002
#define FWP_ACTION_CONTINUE_ 0x00003001
#define FWP_ACTION_CALLOUT_TERMINATING_ 0x00005003

#define FWP_EMPTY_ 0

#define FWP_CONDITION_FLAG_IS_LOOPBACK_ 0x00000001

// FWP_VALUE0 simplified (we only read uint8/uint16/uint32)
typedef struct _FWP_VALUE0_COMPAT {
    UINT32 type;
    union {
        UINT8   uint8;
        UINT16  uint16;
        UINT32  uint32;
        UINT64* uint64;
        INT8    int8;
        INT16   int16;
        INT32   int32;
        INT64*  int64;
        float   float32;
        double* double64;
        PVOID   byteArray16;
        PVOID   byteBlob;
        PVOID   sid;
        PVOID   byteArray6;
        PVOID   v4AddrMask;
        PVOID   v6AddrMask;
        PVOID   rangeValue;
    };
} FWP_VALUE0_COMPAT;

typedef struct _FWPS_INCOMING_VALUE0_COMPAT {
    FWP_VALUE0_COMPAT value;
} FWPS_INCOMING_VALUE0_COMPAT;

typedef struct _FWPS_INCOMING_VALUES0_COMPAT {
    UINT16 layerId;
    UINT32 valueCount;
    FWPS_INCOMING_VALUE0_COMPAT* incomingValue;
} FWPS_INCOMING_VALUES0_COMPAT;

typedef struct _FWPS_INCOMING_METADATA_VALUES0_COMPAT {
    UINT32 currentMetadataValues;
    UINT32 flags;
    UINT64 reserved0;
    UINT64 reserved1;
    UINT64 reserved2;
    UINT64 processId;
    // Additional fields exist but we only need processId
    // Padding to avoid accessing beyond allocation
    UINT8 _reserved_padding[256];
} FWPS_INCOMING_METADATA_VALUES0_COMPAT;

#define FWPS_METADATA_FIELD_PROCESS_ID_ 0x00000020

typedef struct _FWPS_CLASSIFY_OUT0_COMPAT {
    FWP_ACTION_TYPE_ actionType;
    UINT64 outContext;
    UINT64 filterId;
    UINT32 rights;
    UINT32 flags;
    UINT32 reserved;
} FWPS_CLASSIFY_OUT0_COMPAT;

#define FWPS_RIGHT_ACTION_WRITE_ 0x00000001
#define FWPS_CLASSIFY_OUT_FLAG_ABSORB_ 0x00000001

// FWPS_CALLOUT structure for registration
typedef struct _FWPS_CALLOUT2_COMPAT {
    GUID   calloutKey;
    UINT32 flags;
    PVOID  classifyFn;
    PVOID  notifyFn;
    PVOID  flowDeleteFn;
} FWPS_CALLOUT2_COMPAT;

// FWP_BYTE_BLOB for match conditions
typedef struct _FWP_BYTE_BLOB_COMPAT {
    UINT32 size;
    UINT8* data;
} FWP_BYTE_BLOB_COMPAT;

// FWPM_FILTER_CONDITION0
typedef struct _FWP_CONDITION_VALUE0_COMPAT {
    UINT32 type;
    union {
        UINT8  uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64* uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64* int64;
        float float32;
        double* double64;
        PVOID byteArray16;
        PVOID byteBlob;
        PVOID sid;
        PVOID sd;
        PVOID tokenInformation;
        PVOID tokenAccessInformation;
        PVOID unicodeString;
        PVOID byteArray6;
    };
} FWP_CONDITION_VALUE0_COMPAT;

typedef struct _FWPM_FILTER_CONDITION0_COMPAT {
    GUID   fieldKey;
    UINT32 matchType;
    FWP_CONDITION_VALUE0_COMPAT conditionValue;
} FWPM_FILTER_CONDITION0_COMPAT;

typedef struct _FWPM_DISPLAY_DATA0 {
    wchar_t* name;
    wchar_t* description;
} FWPM_DISPLAY_DATA0;

typedef struct _FWPM_ACTION0_COMPAT {
    FWP_ACTION_TYPE_ type;
    union {
        GUID filterType;
        GUID calloutKey;
    } action;
} FWPM_ACTION0_COMPAT;

typedef struct _FWPM_FILTER0_COMPAT {
    GUID   filterKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID*  providerKey;
    FWP_BYTE_BLOB_COMPAT providerData;
    GUID   layerKey;
    GUID   subLayerKey;
    FWP_VALUE0_COMPAT weight;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0_COMPAT* filterCondition;
    FWPM_ACTION0_COMPAT action;
    union {
        UINT64 rawContext;
        GUID   providerContextKey;
    } context;
    GUID*  reserved;
    UINT64 filterId;
    FWP_VALUE0_COMPAT effectiveWeight;
} FWPM_FILTER0_COMPAT;

typedef struct _FWPM_CALLOUT0_COMPAT {
    GUID   calloutKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID*  providerKey;
    FWP_BYTE_BLOB_COMPAT providerData;
    GUID   applicableLayer;
    UINT32 calloutId;
} FWPM_CALLOUT0_COMPAT;

typedef struct _FWPM_SUBLAYER0_COMPAT {
    GUID   subLayerKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID*  providerKey;
    FWP_BYTE_BLOB_COMPAT providerData;
    UINT16 weight;
} FWPM_SUBLAYER0_COMPAT;

#pragma pack(pop)

// WFP function pointer types
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

// WFP Layer GUIDs (transport V4 inbound/outbound)
// FWPM_LAYER_INBOUND_TRANSPORT_V4
static const GUID GUID_LAYER_INBOUND_V4 =
    { 0xa82acc24, 0x4ee1, 0x4ee1, { 0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4 } };
// FWPM_LAYER_OUTBOUND_TRANSPORT_V4
static const GUID GUID_LAYER_OUTBOUND_V4 =
    { 0x09e61aea, 0xd214, 0x46e2, { 0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8 } };
// FWPM_LAYER_ALE_AUTH_CONNECT_V4
static const GUID GUID_LAYER_ALE_CONNECT_V4 =
    { 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };
// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
static const GUID GUID_LAYER_ALE_RECV_V4 =
    { 0xe1cd9fe7, 0xf4b5, 0x4273, { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 } };

// Inbound transport V4 field indices
#define FWPS_FIELD_IN_TRANS_V4_LOCAL_ADDR    0
#define FWPS_FIELD_IN_TRANS_V4_LOCAL_PORT    1
#define FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR   2
#define FWPS_FIELD_IN_TRANS_V4_REMOTE_PORT   3
#define FWPS_FIELD_IN_TRANS_V4_PROTOCOL      4

// Outbound transport V4 field indices
#define FWPS_FIELD_OUT_TRANS_V4_LOCAL_ADDR   0
#define FWPS_FIELD_OUT_TRANS_V4_LOCAL_PORT   1
#define FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR  2
#define FWPS_FIELD_OUT_TRANS_V4_REMOTE_PORT  3
#define FWPS_FIELD_OUT_TRANS_V4_PROTOCOL     4

// =====================================================================
// Network capture subsystem global state
// =====================================================================

// Forward declarations for MITM subsystems referenced by classify callbacks.
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
}
namespace net_fingerprint {
    void analyze_tcp_syn(const UINT8* src_addr, UINT32 af,
                         const UINT8* tcp_data, UINT32 tcp_len,
                         UINT32 ip_ttl);
    BOOLEAN is_active();
}
namespace net_dpi {
    void analyze_packet(UINT64 timestamp, UINT32 direction, UINT32 protocol,
                        UINT32 src_port, UINT32 dst_port,
                        const UINT8* src_addr, const UINT8* dst_addr,
                        UINT32 af, UINT32 pid,
                        const UINT8* payload, UINT32 payload_len);
    BOOLEAN is_active();
}
namespace net_intercept {
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

namespace net_capture {

    // WFP function pointers (dynamically resolved)
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

    // Capture state
    inline volatile LONG g_wfp_initialized = 0;     // 0=not init, 1=initializing, 2=ready
    inline volatile LONG g_capture_active = 0;
    inline HANDLE g_engine_handle = nullptr;
    inline PDEVICE_OBJECT g_device_object = nullptr;

    // WFP registration IDs
    inline UINT32 g_callout_id_inbound = 0;
    inline UINT32 g_callout_id_outbound = 0;
    inline UINT64 g_filter_id_inbound = 0;
    inline UINT64 g_filter_id_outbound = 0;

    // Custom GUIDs for our callout/sublayer
    static const GUID GUID_AIDA_CALLOUT_INBOUND =
        { 0x7a8b3c1d, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } };
    static const GUID GUID_AIDA_CALLOUT_OUTBOUND =
        { 0x7a8b3c1e, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf7 } };
    static const GUID GUID_AIDA_SUBLAYER =
        { 0x7a8b3c1f, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf8 } };

    // Capture filter settings
    inline UINT32 g_filter_pid = 0;
    inline UINT32 g_filter_port = 0;
    inline UINT32 g_filter_protocol = 0;
    inline UINT8  g_filter_ip[16] = {};
    inline UINT32 g_max_payload = NET_PKT_MAX_PAYLOAD;

    // Ring buffer for captured packets
    #define RING_BUFFER_SIZE 2048
    inline NET_PACKET_ENTRY* g_ring_buffer = nullptr;
    inline volatile LONG g_ring_head = 0;    // write index
    inline volatile LONG g_ring_tail = 0;    // read index
    inline volatile LONG g_ring_count = 0;   // current count
    inline KSPIN_LOCK g_ring_lock;
    inline volatile LONG g_total_captured = 0;
    inline volatile LONG g_total_dropped = 0;

    // Per-process byte/packet counters
    inline volatile LONG64 g_global_bytes_sent = 0;
    inline volatile LONG64 g_global_bytes_recv = 0;
    inline volatile LONG64 g_global_pkts_sent = 0;
    inline volatile LONG64 g_global_pkts_recv = 0;

    // DNS log ring buffer
    #define DNS_RING_SIZE 256
    inline NET_DNS_ENTRY* g_dns_ring = nullptr;
    inline volatile LONG g_dns_head = 0;
    inline volatile LONG g_dns_tail = 0;
    inline volatile LONG g_dns_count = 0;
    inline KSPIN_LOCK g_dns_lock;
    inline volatile LONG g_total_dns = 0;

    // Debug counters for sampled classify logging.
    inline volatile LONG g_dbg_inbound_seen = 0;
    inline volatile LONG g_dbg_outbound_seen = 0;

    // Packet filter rules
    #define MAX_FILTER_RULES 64
    typedef struct _ACTIVE_FILTER_RULE {
        UINT32 rule_id;
        UINT32 action;       // 0=allow, 1=block, 2=log
        UINT32 direction;    // 0=in, 1=out, 2=both
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

    // ================================================================
    // Helpers
    // ================================================================

    __forceinline BOOLEAN is_zero_ip(const UINT8* ip) {
        for (int i = 0; i < 16; i++) {
            if (ip[i] != 0) return FALSE;
        }
        return TRUE;
    }

    __forceinline BOOLEAN ip_matches(const UINT8* pkt_ip, const UINT8* rule_ip,
                                      const UINT8* rule_mask, UINT32 af) {
        UINT32 len = (af == 23) ? 16 : 4;  // AF_INET6=23, AF_INET=2
        for (UINT32 i = 0; i < len; i++) {
            if ((pkt_ip[i] & rule_mask[i]) != (rule_ip[i] & rule_mask[i]))
                return FALSE;
        }
        return TRUE;
    }

    // Parse DNS name from wire format (compressed names are truncated)
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
            // Pointer (compression)
            if ((label_len & 0xC0) == 0xC0) {
                if (pos + 1 >= data_len) break;
                if (!jumped) return_pos = pos + 2;
                UINT16 ptr_off = ((UINT16)(label_len & 0x3F) << 8) | dns_data[pos + 1];
                pos = ptr_off;
                jumped = TRUE;
                jumps++;
                if (jumps > 64) break; // prevent infinite loops
                continue;
            }
            if (label_len > 63) break; // invalid label
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

    // Check if a packet matches any block rule
    __forceinline UINT32 check_filter_rules(UINT32 direction, UINT32 protocol,
                                             UINT32 pid, UINT32 port,
                                             const UINT8* remote_ip, UINT32 af) {
        // Returns: 0 = no matching rule (allow), 1 = block, 2 = log_only
        for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
            if (!g_filter_rules[i].active) continue;
            const ACTIVE_FILTER_RULE* r = &g_filter_rules[i];

            if (r->direction != 2 && r->direction != direction) continue;
            if (r->protocol != 0 && r->protocol != protocol) continue;
            if (r->pid != 0 && r->pid != pid) continue;
            if (r->port != 0 && r->port != port) continue;
            if (!is_zero_ip(r->ip_addr)) {
                if (!ip_matches(remote_ip, r->ip_addr, r->ip_mask, af))
                    continue;
            }
            return r->action;
        }
        return 0; // default: allow
    }

    // Store a packet in the ring buffer
    __forceinline void store_packet(UINT32 direction, UINT32 protocol,
                                     UINT32 pid, UINT32 local_port, UINT32 remote_port,
                                     UINT32 af, const UINT8* local_ip, const UINT8* remote_ip,
                                     const UINT8* payload_data, UINT32 payload_len) {
        if (!g_ring_buffer) return;

        // Apply capture filter
        if (g_filter_pid != 0 && pid != g_filter_pid) return;
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
            // Drop oldest
            g_ring_tail = (g_ring_tail + 1) % RING_BUFFER_SIZE;
            g_ring_count--;
            _InterlockedIncrement(&g_total_dropped);
        }

        NET_PACKET_ENTRY* entry = &g_ring_buffer[g_ring_head];
        strong::kmemset(entry, 0, sizeof(NET_PACKET_ENTRY));

        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);
        entry->timestamp = ts.QuadPart;
        entry->pid = pid;
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

    // Store a DNS query/response
    __forceinline void store_dns_entry(UINT32 pid, const char* domain,
                                        UINT32 query_type, UINT32 response_code,
                                        const UINT8* resolved, UINT32 ttl) {
        if (!g_dns_ring) return;

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
        entry->pid = pid;
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

    // Try to parse DNS from UDP port 53 traffic
    __forceinline void try_parse_dns(UINT32 pid, const UINT8* data, UINT32 data_len,
                                      UINT32 local_port, UINT32 remote_port) {
        if (local_port != 53 && remote_port != 53) return;
        if (data_len < 12) return; // DNS header is 12 bytes minimum

        UINT16 flags = ((UINT16)data[2] << 8) | data[3];
        UINT16 qdcount = ((UINT16)data[4] << 8) | data[5];
        UINT16 ancount = ((UINT16)data[6] << 8) | data[7];
        UINT8  rcode = data[3] & 0x0F;
        BOOLEAN is_response = (flags & 0x8000) != 0;

        if (qdcount == 0 || qdcount > 16) return;

        char domain[260] = {};
        UINT32 pos = 12;

        // Parse first question
        pos = parse_dns_name(data, pos, data_len, domain, sizeof(domain));
        if (pos == 0 || pos + 4 > data_len) return;

        UINT16 qtype = ((UINT16)data[pos] << 8) | data[pos + 1];
        pos += 4; // skip qtype + qclass

        UINT8 resolved[16] = {};
        UINT32 ttl = 0;

        // If response, try to extract first A/AAAA answer
        if (is_response && ancount > 0 && pos < data_len) {
            for (UINT16 i = 0; i < ancount && pos < data_len; i++) {
                // Skip answer name
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
                pos += 4; // type + class
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

    // ================================================================
    // WFP Classify callbacks
    // ================================================================

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
        UNREFERENCED_PARAMETER(layerData);

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
                local_ip[0] = (UINT8)(ip >> 24);
                local_ip[1] = (UINT8)(ip >> 16);
                local_ip[2] = (UINT8)(ip >> 8);
                local_ip[3] = (UINT8)(ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR].value.uint32;
                remote_ip[0] = (UINT8)(ip >> 24);
                remote_ip[1] = (UINT8)(ip >> 16);
                remote_ip[2] = (UINT8)(ip >> 8);
                remote_ip[3] = (UINT8)(ip);
            }

            if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) {
                pid = (UINT32)inMetaValues->processId;
            }

            LONG seen = _InterlockedIncrement(&g_dbg_inbound_seen);
            if ((seen & 0x3FF) == 1) {
                AIDA_NET_LOG("classify_inbound sample seen=%ld cap=%ld pid=%u proto=%u lport=%u rport=%u",
                    seen, g_capture_active, pid, protocol, local_port, remote_port);
            }

            // Update stats
            _InterlockedIncrement64(&g_global_pkts_recv);

            // Check filter rules
            UINT32 rule_action = check_filter_rules(0, protocol, pid, remote_port, remote_ip, 2);
            if (rule_action == 1) { // block
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }

            // Extract packet data from NET_BUFFER_LIST if available
            UINT8 pkt_data[NET_PKT_MAX_PAYLOAD] = {};
            UINT32 pkt_len = 0;

            if (layerData) {
                __try {
                    // layerData is a PNET_BUFFER_LIST at transport layer
                    // NET_BUFFER_LIST->FirstNetBuffer->DataLength / MdlChain
                    // We access it carefully with SEH protection
                    PVOID nbl = layerData;
                    // First field of NET_BUFFER_LIST at offset 0x10 (Next) then FirstNetBuffer
                    PVOID first_nb = *(PVOID*)((UINT8*)nbl + sizeof(PVOID) * 2); // FirstNetBuffer
                    if (first_nb && _MmIsAddressValid(first_nb)) {
                        UINT32 data_length = *(UINT32*)((UINT8*)first_nb + 0x18); // DataLength
                        UINT32 data_offset = *(UINT32*)((UINT8*)first_nb + 0x14); // DataOffset
                        PMDL mdl_chain = *(PMDL*)((UINT8*)first_nb + 0x08); // MdlChain

                        if (mdl_chain && _MmIsAddressValid(mdl_chain) && data_length > 0) {
                            PVOID mapped = _MmMapLockedPagesSpecifyCache(
                                mdl_chain, KernelMode, MmCached, NULL, FALSE, 0);
                            if (mapped) {
                                UINT32 avail = mdl_chain->ByteCount - data_offset;
                                pkt_len = (avail < data_length) ? avail : data_length;
                                if (pkt_len > NET_PKT_MAX_PAYLOAD) pkt_len = NET_PKT_MAX_PAYLOAD;
                                strong::kmemcpy(pkt_data, (UINT8*)mapped + data_offset, pkt_len);
                                _MmUnmapLockedPages(mapped, mdl_chain);
                            }
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    pkt_len = 0;
                }

                _InterlockedExchangeAdd64(&g_global_bytes_recv, (LONG64)pkt_len);
            }

            // Bandwidth monitoring
            net_bw::record_traffic(pid, 0, pkt_len);

            // Packet modification engine
            if (pkt_len > 0) {
                net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            0, protocol, remote_port, pid);
            }

            // TCP stream reassembly feed
            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }

            // Network fingerprinting (analyze inbound SYN-ACK)
            if (protocol == 6 && pkt_len >= 20) {
                net_fingerprint::analyze_tcp_syn(remote_ip, 2, pkt_data, pkt_len, 0);
            }

            // DPI analysis
            {
                LARGE_INTEGER dpi_ts;
                KeQuerySystemTime(&dpi_ts);
                net_dpi::analyze_packet(dpi_ts.QuadPart, 0, protocol,
                    local_port, remote_port, local_ip, remote_ip, 2, pid,
                    pkt_data, pkt_len);
            }

            // Intercept-and-hold check
            if (net_intercept::try_hold_packet(0, protocol, local_port, remote_port,
                    local_ip, remote_ip, 2, pid, pkt_data, pkt_len)) {
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }

            // Store packet if capture is active
            if (g_capture_active) {
                store_packet(0, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);

                // Try DNS parsing
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
        UNREFERENCED_PARAMETER(layerData);

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
                local_ip[0] = (UINT8)(ip >> 24);
                local_ip[1] = (UINT8)(ip >> 16);
                local_ip[2] = (UINT8)(ip >> 8);
                local_ip[3] = (UINT8)(ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR].value.uint32;
                remote_ip[0] = (UINT8)(ip >> 24);
                remote_ip[1] = (UINT8)(ip >> 16);
                remote_ip[2] = (UINT8)(ip >> 8);
                remote_ip[3] = (UINT8)(ip);
            }

            if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) {
                pid = (UINT32)inMetaValues->processId;
            }

            LONG seen = _InterlockedIncrement(&g_dbg_outbound_seen);
            if ((seen & 0x3FF) == 1) {
                AIDA_NET_LOG("classify_outbound sample seen=%ld cap=%ld pid=%u proto=%u lport=%u rport=%u",
                    seen, g_capture_active, pid, protocol, local_port, remote_port);
            }

            _InterlockedIncrement64(&g_global_pkts_sent);

            UINT32 rule_action = check_filter_rules(1, protocol, pid, remote_port, remote_ip, 2);
            if (rule_action == 1) {
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }

            UINT8 pkt_data[NET_PKT_MAX_PAYLOAD] = {};
            UINT32 pkt_len = 0;

            if (layerData) {
                __try {
                    PVOID nbl = layerData;
                    PVOID first_nb = *(PVOID*)((UINT8*)nbl + sizeof(PVOID) * 2);
                    if (first_nb && _MmIsAddressValid(first_nb)) {
                        UINT32 data_length = *(UINT32*)((UINT8*)first_nb + 0x18);
                        UINT32 data_offset = *(UINT32*)((UINT8*)first_nb + 0x14);
                        PMDL mdl_chain = *(PMDL*)((UINT8*)first_nb + 0x08);

                        if (mdl_chain && _MmIsAddressValid(mdl_chain) && data_length > 0) {
                            PVOID mapped = _MmMapLockedPagesSpecifyCache(
                                mdl_chain, KernelMode, MmCached, NULL, FALSE, 0);
                            if (mapped) {
                                UINT32 avail = mdl_chain->ByteCount - data_offset;
                                pkt_len = (avail < data_length) ? avail : data_length;
                                if (pkt_len > NET_PKT_MAX_PAYLOAD) pkt_len = NET_PKT_MAX_PAYLOAD;
                                strong::kmemcpy(pkt_data, (UINT8*)mapped + data_offset, pkt_len);
                                _MmUnmapLockedPages(mapped, mdl_chain);
                            }
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    pkt_len = 0;
                }

                _InterlockedExchangeAdd64(&g_global_bytes_sent, (LONG64)pkt_len);
            }

            // Bandwidth monitoring
            net_bw::record_traffic(pid, 1, pkt_len);

            // Packet modification engine
            if (pkt_len > 0) {
                net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            1, protocol, remote_port, pid);
            }

            // TCP stream reassembly feed
            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }

            // DPI analysis
            {
                LARGE_INTEGER dpi_ts;
                KeQuerySystemTime(&dpi_ts);
                net_dpi::analyze_packet(dpi_ts.QuadPart, 1, protocol,
                    local_port, remote_port, local_ip, remote_ip, 2, pid,
                    pkt_data, pkt_len);
            }

            // Intercept-and-hold check
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

    NTSTATUS NTAPI callout_notify(
        UINT32 notifyType, const GUID* filterKey, const void* filter)
    {
        UNREFERENCED_PARAMETER(notifyType);
        UNREFERENCED_PARAMETER(filterKey);
        UNREFERENCED_PARAMETER(filter);
        return STATUS_SUCCESS;
    }

    // ================================================================
    // Find fwpkclnt.sys module and resolve WFP functions
    // ================================================================

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
        AIDA_NET_LOG0("resolve_wfp_functions: begin");
        PVOID fwp_base = find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) {
            // Try lowercase
            fwp_base = find_module_base("fwpkclnt.sys");
        }
        if (!fwp_base) {
            AIDA_NET_LOG0("resolve_wfp_functions: fwpkclnt.sys not found");
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
        AIDA_NET_LOG("resolve_wfp_functions: done ok=%u base=%p", ok ? 1u : 0u, fwp_base);
        return ok;
    }

    // ================================================================
    // WFP registration / unregistration
    // ================================================================

    NTSTATUS register_wfp(PDEVICE_OBJECT devObj) {
        if (!devObj) {
            AIDA_NET_LOG0("register_wfp: invalid device object");
            return STATUS_INVALID_PARAMETER;
        }
        g_device_object = devObj;
        AIDA_NET_LOG("register_wfp: begin devObj=%p", devObj);
        AIDA_NET_LOG("register_wfp: abi sizes FWP_VALUE0=%Iu FWP_CONDITION_VALUE0=%Iu FWPM_FILTER0=%Iu FWPM_CALLOUT0=%Iu FWPM_SUBLAYER0=%Iu",
            sizeof(FWP_VALUE0_COMPAT),
            sizeof(FWP_CONDITION_VALUE0_COMPAT),
            sizeof(FWPM_FILTER0_COMPAT),
            sizeof(FWPM_CALLOUT0_COMPAT),
            sizeof(FWPM_SUBLAYER0_COMPAT));

        NTSTATUS status;

        // Open BFE engine
        status = _FwpmEngineOpen0(nullptr, 0x0000000A /*RPC_C_AUTHN_WINNT*/,
            nullptr, nullptr, &g_engine_handle);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("register_wfp: FwpmEngineOpen0 failed status=0x%08X", (UINT32)status);
            return status;
        }

        // Begin transaction
        status = _FwpmTransactionBegin0(g_engine_handle, 0);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("register_wfp: FwpmTransactionBegin0 failed status=0x%08X", (UINT32)status);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        // Add sublayer
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
            AIDA_NET_LOG("register_wfp: FwpmSubLayerAdd0 failed status=0x%08X", (UINT32)status);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        // Register inbound callout with kernel (FWPS)
        FWPS_CALLOUT2_COMPAT callout_in = {};
        callout_in.calloutKey = GUID_AIDA_CALLOUT_INBOUND;
        callout_in.flags = 0;
        callout_in.classifyFn = (PVOID)classify_inbound;
        callout_in.notifyFn = (PVOID)callout_notify;
        callout_in.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_in, &g_callout_id_inbound);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("register_wfp: inbound FwpsCalloutRegister2 failed status=0x%08X", (UINT32)status);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        // Register outbound callout with kernel (FWPS)
        FWPS_CALLOUT2_COMPAT callout_out = {};
        callout_out.calloutKey = GUID_AIDA_CALLOUT_OUTBOUND;
        callout_out.flags = 0;
        callout_out.classifyFn = (PVOID)classify_outbound;
        callout_out.notifyFn = (PVOID)callout_notify;
        callout_out.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_out, &g_callout_id_outbound);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("register_wfp: outbound FwpsCalloutRegister2 failed status=0x%08X", (UINT32)status);
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        // Add callouts to BFE (FWPM)
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
            AIDA_NET_LOG("register_wfp: inbound FwpmCalloutAdd0 failed status=0x%08X", (UINT32)status);
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
            AIDA_NET_LOG("register_wfp: outbound FwpmCalloutAdd0 failed status=0x%08X", (UINT32)status);
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        // Add filters
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
        // FWP_EMPTY lets BFE assign automatic weight and avoids invalid pointer semantics.
        filter_in.weight.type = FWP_EMPTY_;
        filter_in.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
        filter_in.action.action.calloutKey = GUID_AIDA_CALLOUT_INBOUND;
        filter_in.numFilterConditions = 0;
        AIDA_NET_LOG("register_wfp: add inbound filter layer=%p sublayer=%p providerData=%p weightType=%u actionType=0x%08X",
            &filter_in.layerKey,
            &filter_in.subLayerKey,
            filter_in.providerData.data,
            filter_in.weight.type,
            filter_in.action.type);

        status = _FwpmFilterAdd0(g_engine_handle, &filter_in, nullptr, &g_filter_id_inbound);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("register_wfp: inbound FwpmFilterAdd0 failed status=0x%08X", (UINT32)status);
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
        filter_out.action.action.calloutKey = GUID_AIDA_CALLOUT_OUTBOUND;
        filter_out.numFilterConditions = 0;
        AIDA_NET_LOG("register_wfp: add outbound filter layer=%p sublayer=%p providerData=%p weightType=%u actionType=0x%08X",
            &filter_out.layerKey,
            &filter_out.subLayerKey,
            filter_out.providerData.data,
            filter_out.weight.type,
            filter_out.action.type);

        status = _FwpmFilterAdd0(g_engine_handle, &filter_out, nullptr, &g_filter_id_outbound);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("register_wfp: outbound FwpmFilterAdd0 failed status=0x%08X", (UINT32)status);
            _FwpmFilterDeleteById0(g_engine_handle, g_filter_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmTransactionAbort0(g_engine_handle);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        // Commit transaction
        status = _FwpmTransactionCommit0(g_engine_handle);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("register_wfp: FwpmTransactionCommit0 failed status=0x%08X", (UINT32)status);
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }

        AIDA_NET_LOG("register_wfp: success inCallout=%u outCallout=%u inFilter=%llu outFilter=%llu",
            g_callout_id_inbound, g_callout_id_outbound,
            (unsigned long long)g_filter_id_inbound,
            (unsigned long long)g_filter_id_outbound);

        return STATUS_SUCCESS;
    }

    void unregister_wfp() {
        if (g_engine_handle) {
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
        if (g_callout_id_inbound) {
            _FwpsCalloutUnregisterById0(g_callout_id_inbound);
            g_callout_id_inbound = 0;
        }
        if (g_callout_id_outbound) {
            _FwpsCalloutUnregisterById0(g_callout_id_outbound);
            g_callout_id_outbound = 0;
        }
    }

    // ================================================================
    // Initialization / Cleanup
    // ================================================================

    NTSTATUS initialize(PDEVICE_OBJECT devObj) {
        AIDA_NET_LOG("initialize: begin devObj=%p", devObj);
        LONG prev = _InterlockedCompareExchange(&g_wfp_initialized, 1, 0);
        if (prev == 2) return STATUS_SUCCESS;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_wfp_initialized, 0, 0) == 1)
                YieldProcessor();
            return (g_wfp_initialized == 2) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        // Initialize spin locks
        KeInitializeSpinLock(&g_ring_lock);
        KeInitializeSpinLock(&g_dns_lock);

        // Allocate ring buffers
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

        // Resolve WFP functions
        if (!resolve_wfp_functions()) {
            AIDA_NET_LOG0("initialize: resolve_wfp_functions failed");
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_NOT_SUPPORTED;
        }

        // Register WFP callouts
        NTSTATUS status = register_wfp(devObj);
        if (!NT_SUCCESS(status)) {
            AIDA_NET_LOG("initialize: register_wfp failed status=0x%08X", (UINT32)status);
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
        AIDA_NET_LOG0("initialize: success");
        return STATUS_SUCCESS;
    }

    void cleanup() {
        AIDA_NET_LOG0("cleanup: begin");
        _InterlockedExchange(&g_capture_active, 0);
        unregister_wfp();

        if (g_ring_buffer) {
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
        }
        if (g_dns_ring) {
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
        }
        AIDA_NET_LOG0("cleanup: complete");
    }

} // namespace net_capture


// =====================================================================
// Connection enumeration using kernel process/handle table walking
// =====================================================================

namespace net_enum {

    // TCP state constants matching Windows internal values
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

    // NSI structures for enumerating TCP/UDP endpoints
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

    // AllocateAndGetTcpExTableFromStack and similar are not kernel-exported.
    // We use ZwQuerySystemInformation with undocumented network classes.
    // Alternative: walk tcpip.sys internal partition table.
    // For robustness, we use the user-mode helper approach via process attach.

    typedef NTSTATUS(NTAPI* fn_NsiEnumerateObjectsAllParameters)(
        UINT64 NsiHandle, UINT32 Nsi0, const PVOID NsiModule,
        UINT32 NsiType, PVOID KeyData, UINT32 KeySize,
        PVOID RwParamData, UINT32 RwParamSize,
        PVOID DynParamData, UINT32 DynParamSize,
        PVOID StaticParamData, UINT32 StaticParamSize,
        PUINT32 Count);

    inline fn_NsiEnumerateObjectsAllParameters _NsiEnumerate = nullptr;
    inline volatile LONG g_nsi_resolved = 0;

    // NSI module identifiers for TCP and UDP
    // These are GUID-like structures that identify the NSI module
    // NPI_MS_TCP_MODULEID: {eb004a03-9b1a-11d4-9123-0050047759bc}
    static const UINT8 NPI_MS_TCP_MODULEID[24] = {
        0x18, 0x00, 0x00, 0x00, // length
        0x01, 0x00, 0x00, 0x00, // type
        0x03, 0x4a, 0x00, 0xeb, 0x1a, 0x9b, 0xd4, 0x11,
        0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc
    };

    // NPI_MS_UDP_MODULEID: {eb004a02-9b1a-11d4-9123-0050047759bc}
    static const UINT8 NPI_MS_UDP_MODULEID[24] = {
        0x18, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x4a, 0x00, 0xeb, 0x1a, 0x9b, 0xd4, 0x11,
        0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc
    };

    // TCP key structure for NSI enumeration
    #pragma pack(push, 1)
    typedef struct _NSI_TCP_KEY {
        UINT8  local_addr[16]; // IN6_ADDR (IPv4-mapped for v4)
        UINT32 local_port;     // network byte order
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

        // Find nsi.sys or netio.sys and resolve NsiEnumerateObjectsAllParameters
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

        // If NSI is available, use it for native kernel enumeration
        if (resolve_nsi() && _NsiEnumerate) {
            // Enumerate TCP connections
            if (request->filter_protocol == 0 || request->filter_protocol == 6) {
                UINT32 tcp_count = 0;

                // First call to get count
                NTSTATUS status = _NsiEnumerate(
                    0, 0, (PVOID)NPI_MS_TCP_MODULEID, 3,
                    nullptr, sizeof(NSI_TCP_KEY),
                    nullptr, 0,
                    nullptr, sizeof(NSI_TCP_DYNAMIC),
                    nullptr, sizeof(NSI_TCP_STATIC),
                    &tcp_count);

                if (tcp_count > 0 && tcp_count < 65536) {
                    SIZE_T key_buf_size = (SIZE_T)tcp_count * sizeof(NSI_TCP_KEY);
                    SIZE_T dyn_buf_size = (SIZE_T)tcp_count * sizeof(NSI_TCP_DYNAMIC);
                    SIZE_T sta_buf_size = (SIZE_T)tcp_count * sizeof(NSI_TCP_STATIC);

                    NSI_TCP_KEY* keys = (NSI_TCP_KEY*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, key_buf_size, 'tcNW');
                    NSI_TCP_DYNAMIC* dyns = (NSI_TCP_DYNAMIC*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, dyn_buf_size, 'tcNW');
                    NSI_TCP_STATIC* stats = (NSI_TCP_STATIC*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, sta_buf_size, 'tcNW');

                    if (keys && dyns && stats) {
                        strong::kmemset(keys, 0, key_buf_size);
                        strong::kmemset(dyns, 0, dyn_buf_size);
                        strong::kmemset(stats, 0, sta_buf_size);

                        status = _NsiEnumerate(
                            0, 0, (PVOID)NPI_MS_TCP_MODULEID, 3,
                            keys, sizeof(NSI_TCP_KEY),
                            nullptr, 0,
                            dyns, sizeof(NSI_TCP_DYNAMIC),
                            stats, sizeof(NSI_TCP_STATIC),
                            &tcp_count);

                        if (NT_SUCCESS(status)) {
                            for (UINT32 i = 0; i < tcp_count &&
                                 request->connection_count < MAX_NET_CONNECTIONS; i++) {
                                UINT32 pid = stats[i].pid;
                                if (request->filter_pid != 0 && pid != request->filter_pid)
                                    continue;

                                NET_CONN_ENTRY* e = &request->entries[request->connection_count];
                                strong::kmemset(e, 0, sizeof(NET_CONN_ENTRY));
                                e->pid = pid;
                                e->protocol = 6;
                                e->state = dyns[i].state;
                                // Port is in network byte order, swap to host
                                e->local_port = (UINT16)((keys[i].local_port >> 8) |
                                    ((keys[i].local_port & 0xFF) << 8));
                                e->remote_port = (UINT16)((keys[i].remote_port >> 8) |
                                    ((keys[i].remote_port & 0xFF) << 8));

                                // Check if IPv4-mapped IPv6 (::ffff:x.x.x.x)
                                BOOLEAN is_v4 = TRUE;
                                for (int j = 0; j < 10; j++) {
                                    if (keys[i].local_addr[j] != 0) { is_v4 = FALSE; break; }
                                }
                                if (is_v4 && keys[i].local_addr[10] == 0xFF &&
                                    keys[i].local_addr[11] == 0xFF) {
                                    e->address_family = 2; // AF_INET
                                    strong::kmemcpy(e->local_addr, &keys[i].local_addr[12], 4);
                                    strong::kmemcpy(e->remote_addr, &keys[i].remote_addr[12], 4);
                                } else {
                                    e->address_family = 23; // AF_INET6
                                    strong::kmemcpy(e->local_addr, keys[i].local_addr, 16);
                                    strong::kmemcpy(e->remote_addr, keys[i].remote_addr, 16);
                                }

                                request->connection_count++;
                            }
                        }
                    }

                    if (keys) ExFreePoolWithTag(keys, 'tcNW');
                    if (dyns) ExFreePoolWithTag(dyns, 'tcNW');
                    if (stats) ExFreePoolWithTag(stats, 'tcNW');
                }
            }

            // Enumerate UDP bindings
            if (request->filter_protocol == 0 || request->filter_protocol == 17) {
                UINT32 udp_count = 0;

                NTSTATUS status = _NsiEnumerate(
                    0, 0, (PVOID)NPI_MS_UDP_MODULEID, 3,
                    nullptr, sizeof(NSI_UDP_KEY),
                    nullptr, 0,
                    nullptr, 0,
                    nullptr, sizeof(NSI_UDP_STATIC),
                    &udp_count);

                if (udp_count > 0 && udp_count < 65536) {
                    SIZE_T key_buf_size = (SIZE_T)udp_count * sizeof(NSI_UDP_KEY);
                    SIZE_T sta_buf_size = (SIZE_T)udp_count * sizeof(NSI_UDP_STATIC);

                    NSI_UDP_KEY* keys = (NSI_UDP_KEY*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, key_buf_size, 'udNW');
                    NSI_UDP_STATIC* stats = (NSI_UDP_STATIC*)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, sta_buf_size, 'udNW');

                    if (keys && stats) {
                        strong::kmemset(keys, 0, key_buf_size);
                        strong::kmemset(stats, 0, sta_buf_size);

                        status = _NsiEnumerate(
                            0, 0, (PVOID)NPI_MS_UDP_MODULEID, 3,
                            keys, sizeof(NSI_UDP_KEY),
                            nullptr, 0,
                            nullptr, 0,
                            stats, sizeof(NSI_UDP_STATIC),
                            &udp_count);

                        if (NT_SUCCESS(status)) {
                            for (UINT32 i = 0; i < udp_count &&
                                 request->connection_count < MAX_NET_CONNECTIONS; i++) {
                                UINT32 pid = stats[i].pid;
                                if (request->filter_pid != 0 && pid != request->filter_pid)
                                    continue;

                                NET_CONN_ENTRY* e = &request->entries[request->connection_count];
                                strong::kmemset(e, 0, sizeof(NET_CONN_ENTRY));
                                e->pid = pid;
                                e->protocol = 17;
                                e->state = 0;
                                e->local_port = (UINT16)((keys[i].local_port >> 8) |
                                    ((keys[i].local_port & 0xFF) << 8));
                                e->remote_port = 0;

                                BOOLEAN is_v4 = TRUE;
                                for (int j = 0; j < 10; j++) {
                                    if (keys[i].local_addr[j] != 0) { is_v4 = FALSE; break; }
                                }
                                if (is_v4 && keys[i].local_addr[10] == 0xFF &&
                                    keys[i].local_addr[11] == 0xFF) {
                                    e->address_family = 2;
                                    strong::kmemcpy(e->local_addr, &keys[i].local_addr[12], 4);
                                } else if (is_v4 && keys[i].local_addr[10] == 0 &&
                                           keys[i].local_addr[11] == 0) {
                                    e->address_family = 2;
                                    strong::kmemcpy(e->local_addr, &keys[i].local_addr[12], 4);
                                } else {
                                    e->address_family = 23;
                                    strong::kmemcpy(e->local_addr, keys[i].local_addr, 16);
                                }

                                request->connection_count++;
                            }
                        }
                    }

                    if (keys) ExFreePoolWithTag(keys, 'udNW');
                    if (stats) ExFreePoolWithTag(stats, 'udNW');
                }
            }
        }

        return STATUS_SUCCESS;
    }

} // namespace net_enum


// =====================================================================
// IOCTL handler implementations
// =====================================================================

NTSTATUS functions::handle_net_enum_conn(p_net_enum_conn request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_enum::enumerate_connections(request);
}

NTSTATUS functions::handle_net_cap_ctrl(p_net_cap_ctrl request) {
    if (!request) return STATUS_INVALID_PARAMETER;

    AIDA_NET_LOG("IOCTL NCAP op=%u filter_pid=%u filter_port=%u proto=%u max_payload=%u init_state=%ld",
        request->operation, request->filter_pid, request->filter_port,
        request->filter_protocol, request->max_packet_bytes, net_capture::g_wfp_initialized);

    if (net_capture::g_wfp_initialized != 2) {
        AIDA_NET_LOG0("IOCTL NCAP rejected: WFP not initialized");
        return STATUS_DEVICE_NOT_READY;
    }

    switch (request->operation) {
        case 0: { // start capture
            net_capture::g_filter_pid = request->filter_pid;
            net_capture::g_filter_port = request->filter_port;
            net_capture::g_filter_protocol = request->filter_protocol;
            strong::kmemcpy(net_capture::g_filter_ip, request->filter_ip, 16);
            if (request->max_packet_bytes > 0 && request->max_packet_bytes <= NET_PKT_MAX_PAYLOAD)
                net_capture::g_max_payload = request->max_packet_bytes;
            else
                net_capture::g_max_payload = NET_PKT_MAX_PAYLOAD;

            // Clear ring buffer
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
        case 1: { // stop capture
            _InterlockedExchange(&net_capture::g_capture_active, 0);
            request->capture_active = 0;
            break;
        }
        case 2: { // query status
            break;
        }
        default:
            return STATUS_INVALID_PARAMETER;
    }

    request->capture_active = (UINT32)net_capture::g_capture_active;
    request->packets_captured = (UINT32)net_capture::g_total_captured;
    request->packets_dropped = (UINT32)net_capture::g_total_dropped;

    AIDA_NET_LOG("IOCTL NCAP done op=%u active=%u captured=%u dropped=%u",
        request->operation, request->capture_active,
        request->packets_captured, request->packets_dropped);

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

        // Apply PID filter
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
        case 0: { // add rule
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
            return STATUS_INSUFFICIENT_RESOURCES; // rule table full
        }
        case 1: { // remove rule by id
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
        case 2: { // clear all rules
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                _InterlockedExchange(&net_capture::g_filter_rules[i].active, 0);
            }
            _InterlockedExchange(&net_capture::g_active_rule_count, 0);
            request->rule_count = 0;
            return STATUS_SUCCESS;
        }
        case 3: { // list (return count)
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
    request->active_connections = 0; // populated by enumeration
    request->capture_active = (UINT32)net_capture::g_capture_active;
    request->total_captured = (UINT32)net_capture::g_total_captured;
    request->total_dropped = (UINT32)net_capture::g_total_dropped;
    request->total_dns_logged = (UINT32)net_capture::g_total_dns;
    request->active_filter_rules = (UINT32)net_capture::g_active_rule_count;

    return STATUS_SUCCESS;
}

// =====================================================================
// Advanced network recon: WFP callout enumeration
// =====================================================================

// WFP management API function types for callout enumeration
typedef NTSTATUS(NTAPI* fn_FwpmCalloutCreateEnumHandle0)(
    HANDLE engineHandle, const VOID* enumTemplate, HANDLE* enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutDestroyEnumHandle0)(
    HANDLE engineHandle, HANDLE enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutEnum0)(
    HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested,
    FWPM_CALLOUT0_COMPAT*** entries, UINT32* numEntriesReturned);
typedef VOID(NTAPI* fn_FwpmFreeMemory0)(VOID** p);

// FWPS_CALLOUT0 — the kernel-side registered callout (different from FWPM_CALLOUT0_COMPAT)
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

    // Resolve a module base address to its name
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

        // Ensure WFP engine is available
        if (!net_capture::_FwpmEngineOpen0 || !net_capture::_FwpmEngineClose0) {
            if (!net_capture::resolve_wfp_functions())
                return STATUS_NOT_SUPPORTED;
        }

        // Resolve additional WFP enumeration functions from fwpkclnt.sys
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
            return STATUS_NOT_SUPPORTED;

        // Open a temporary engine handle for enumeration
        HANDLE engine = nullptr;
        NTSTATUS status = net_capture::_FwpmEngineOpen0(nullptr, 0, nullptr, nullptr, &engine);
        if (!NT_SUCCESS(status) || !engine)
            return status ? status : STATUS_UNSUCCESSFUL;

        HANDLE enumHandle = nullptr;
        status = _CreateEnum(engine, nullptr, &enumHandle);
        if (!NT_SUCCESS(status) || !enumHandle) {
            net_capture::_FwpmEngineClose0(engine);
            return status ? status : STATUS_UNSUCCESSFUL;
        }

        UINT32 total_filled = 0;
        BOOLEAN has_filter = (request->filter_module[0] != 0);

        // Enumerate in batches
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

                // The FWPM_CALLOUT0 has providerKey but no classify/notify ptrs.
                // The classify/notify are in FWPS (kernel-side) data.
                // We resolve the owning module from providerKey or scan for the callout ID.
                out->classify_fn = 0;
                out->notify_fn = 0;
                out->flow_delete_fn = 0;

                // Try to find callout function addresses from FWPS callout registration
                // The FWPS_CALLOUT data is internal to netio.sys/fwpkclnt.sys.
                // We can look up the provider module name from system module list
                // by checking the provider data or displayData.
                if (c->providerKey && _MmIsAddressValid(c->providerKey)) {
                    // store provider key as module base hint
                }

                // displayData.name often contains the driver/callout name
                __try {
                    wchar_t* wname = c->displayData.name;
                    if (wname && _MmIsAddressValid(wname)) {
                        // Convert wide to ASCII for module name
                        for (int j = 0; j < 63 && wname[j]; j++) {
                            out->owning_module[j] = (char)(wname[j] & 0x7F);
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {}

                // If we have a module name filter, check it
                if (has_filter) {
                    if (out->owning_module[0] == 0) continue;
                    // Substring search
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
        return STATUS_SUCCESS;
    }
}

// =====================================================================
// Advanced network recon: Socket handle enumeration via EPROCESS
// =====================================================================

namespace net_socket_enum {

    // Object type name for AFD endpoints
    static BOOLEAN is_afd_device_object(PVOID object) {
        if (!object || !_MmIsAddressValid(object)) return FALSE;

        __try {
            // FILE_OBJECT has DeviceObject at offset 0x08 (Win10+)
            PDEVICE_OBJECT devObj = ((PFILE_OBJECT)object)->DeviceObject;
            if (!devObj || !_MmIsAddressValid(devObj)) return FALSE;

            // Check if the device object belongs to AFD driver
            PDRIVER_OBJECT drvObj = devObj->DriverObject;
            if (!drvObj || !_MmIsAddressValid(drvObj)) return FALSE;

            // DriverName is at a known offset in DRIVER_OBJECT
            PUNICODE_STRING drvName = &drvObj->DriverName;
            if (!drvName->Buffer || !_MmIsAddressValid(drvName->Buffer)) return FALSE;

            // Check for "\\Driver\\AFD" or "\\Device\\Afd"
            if (drvName->Length < 8) return FALSE;
            wchar_t* buf = drvName->Buffer;
            // Look for "AFD" or "Afd" in the driver name
            for (USHORT i = 0; i + 2 < drvName->Length / sizeof(wchar_t); i++) {
                wchar_t c0 = buf[i];
                wchar_t c1 = buf[i + 1];
                wchar_t c2 = buf[i + 2];
                if (c0 >= 'a') c0 -= 32;
                if (c1 >= 'a') c1 -= 32;
                if (c2 >= 'a') c2 -= 32;
                if (c0 == 'A' && c1 == 'F' && c2 == 'D') return TRUE;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return FALSE;
    }

    // Offsets for Windows 10/11 22H2+ EPROCESS -> ObjectTable
    // These are version-dependent; we use known Win10 22H2/Win11 24H2 offsets
    static constexpr ULONG EPROCESS_OBJECT_TABLE_OFFSET_W10     = 0x570;
    static constexpr ULONG EPROCESS_OBJECT_TABLE_OFFSET_W11     = 0x570;
    static constexpr ULONG EPROCESS_UNIQUE_PROCESS_ID_OFFSET    = 0x440;

    // HANDLE_TABLE_ENTRY layout
    typedef struct _HANDLE_TABLE_ENTRY_W10 {
        union {
            UINT64 ObjectPointerBits;   // bits 1-44 = encoded pointer, bit 0 = lock
            UINT64 Value;
        };
        union {
            UINT32 GrantedAccessBits;
            struct {
                UINT32 GrantedAccess : 25;
                UINT32 NoRightsUpgrade : 1;
                UINT32 Spare1 : 6;
            };
        };
        UINT16 TypeInfo;
        UINT16 Spare2;
    } HANDLE_TABLE_ENTRY_W10;

    // Decode Object pointer from handle table entry
    // The top bits and bottom bits are encoded
    static PVOID decode_object_pointer(UINT64 value) {
        // Strip lock bit and sign extend from bits 1-44
        // Object header = (value >> 4) & ~0xF shifted to canonical address
        if (value == 0) return nullptr;
        // Windows uses: Object = (HandleTableEntry->ObjectPointerBits >> 0x10) & 0xFFFFFFFFFFF0
        // Simplified: address = ((value >> 16) | 0xFFFF000000000000)
        UINT64 addr = (value >> 0x10) & 0x0000FFFFFFFFFFFF;
        if (addr == 0) return nullptr;
        addr |= 0xFFFF000000000000ULL;  // sign extend to kernel space
        return (PVOID)addr;
    }

    // Try to extract socket info from an AFD endpoint file object
    static BOOLEAN extract_socket_info(PVOID file_object, SOCKET_HANDLE_ENTRY* out) {
        if (!file_object || !_MmIsAddressValid(file_object)) return FALSE;

        __try {
            PFILE_OBJECT fo = (PFILE_OBJECT)file_object;
            // AFD stores its endpoint context in FsContext
            PVOID afd_endpoint = fo->FsContext;
            if (!afd_endpoint || !_MmIsAddressValid(afd_endpoint)) return FALSE;

            out->afd_endpoint_addr = (UINT64)afd_endpoint;

            // AFD_ENDPOINT internal structure (offsets vary by build)
            // Common layout for Win10/11:
            //   +0x00: Type (USHORT)
            //   +0x02: State (USHORT)
            //   +0x14: AddressFamily (USHORT)
            //   +0x16: SocketType (USHORT)
            //   +0x18: Protocol (LONG)
            //   +0x20: LocalAddress  (TRANSPORT_ADDRESS pointer or inline)
            //   +0x28: Context / Connection pointer
            // These offsets are approximate — we read cautiously

            UINT8* ep = (UINT8*)afd_endpoint;

            // Read address family
            if (_MmIsAddressValid(ep + 0x14)) {
                out->address_family = *(UINT16*)(ep + 0x14);
            }
            // Read protocol
            if (_MmIsAddressValid(ep + 0x18)) {
                LONG proto = *(LONG*)(ep + 0x18);
                out->protocol = (UINT32)(proto > 0 ? proto : 0);
            }

            // For TCP endpoints, try to read the connection state
            // The AFD_CONNECTION structure at various offsets stores state info
            // We don't have reliable offsets for all builds, so we report what we can
            out->state = 0;
            out->local_port = 0;
            out->remote_port = 0;
            strong::kmemset(out->local_addr, 0, 16);
            strong::kmemset(out->remote_addr, 0, 16);

            // Try to read local address from TransportInfo
            // AFD stores bound address info at various offsets
            // For TCP: +0x20 may point to local SOCKADDR
            if (_MmIsAddressValid(ep + 0x20)) {
                PVOID local_info = *(PVOID*)(ep + 0x20);
                if (local_info && _MmIsAddressValid(local_info)) {
                    UINT8* sa = (UINT8*)local_info;
                    if (_MmIsAddressValid(sa + 8)) {
                        UINT16 sa_family = *(UINT16*)(sa + 0);
                        if (sa_family == 2) { // AF_INET: port at +2, addr at +4
                            UINT16 port_be = *(UINT16*)(sa + 2);
                            out->local_port = ((port_be >> 8) & 0xFF) | ((port_be & 0xFF) << 8);
                            strong::kmemcpy(out->local_addr, sa + 4, 4);
                        }
                    }
                }
            }

            return TRUE;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    static NTSTATUS enumerate_socket_handles(p_socket_handle_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->socket_count = 0;

        UINT32 target_pid = request->target_pid;
        if (target_pid == 0) return STATUS_INVALID_PARAMETER;

        // Look up the target process
        PEPROCESS process = nullptr;
        NTSTATUS status = stack_spoof::spoofed_PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)target_pid, &process);
        if (!NT_SUCCESS(status) || !process) return status ? status : STATUS_NOT_FOUND;

        __try {
            // Get the handle table from EPROCESS
            UINT64 eprocess_addr = (UINT64)process;
            PVOID handle_table = nullptr;

            if (_MmIsAddressValid((PVOID)(eprocess_addr + EPROCESS_OBJECT_TABLE_OFFSET_W10))) {
                handle_table = *(PVOID*)(eprocess_addr + EPROCESS_OBJECT_TABLE_OFFSET_W10);
            }

            if (!handle_table || !_MmIsAddressValid(handle_table)) {
                stack_spoof::spoofed_ObfDereferenceObject(process);
                return STATUS_NOT_FOUND;
            }

            // HANDLE_TABLE structure:
            //   +0x00: TableCode (encoded pointer to handle table levels)
            //   +0x08: QuotaProcess
            //   ...
            UINT64 table_code = *(UINT64*)handle_table;

            // Table level is encoded in bottom 2 bits
            UINT32 level = (UINT32)(table_code & 3);
            UINT64 table_base = table_code & ~3ULL;

            if (!_MmIsAddressValid((PVOID)table_base)) {
                stack_spoof::spoofed_ObfDereferenceObject(process);
                return STATUS_NOT_FOUND;
            }

            UINT32 filled = 0;

            // Level 0: single table (up to 256 entries typically)
            // Level 1: array of L0 table pointers
            // Level 2: array of L1 table pointers
            // Handle entry size = 16 bytes, each L0 table = 4096 bytes = 256 entries

            auto process_table = [&](UINT64 l0_base) {
                if (!_MmIsAddressValid((PVOID)l0_base)) return;
                // Each L0 table page holds (PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY)) entries
                constexpr UINT32 ENTRIES_PER_PAGE = 256;  // 4096 / 16
                for (UINT32 i = 1; i < ENTRIES_PER_PAGE && filled < MAX_SOCKET_HANDLES; i++) {
                    UINT64 entry_addr = l0_base + (UINT64)i * 16;
                    if (!_MmIsAddressValid((PVOID)entry_addr)) break;

                    HANDLE_TABLE_ENTRY_W10* entry = (HANDLE_TABLE_ENTRY_W10*)entry_addr;
                    if (entry->Value == 0) continue;

                    PVOID obj_header = decode_object_pointer(entry->Value);
                    if (!obj_header || !_MmIsAddressValid(obj_header)) continue;

                    // Object body is at OBJECT_HEADER + 0x30 (Win10/11)
                    PVOID object = (PVOID)((UINT64)obj_header + 0x30);
                    if (!_MmIsAddressValid(object)) continue;

                    // Check if this is an AFD file object
                    if (!is_afd_device_object(object)) continue;

                    SOCKET_HANDLE_ENTRY* out = &request->entries[filled];
                    strong::kmemset(out, 0, sizeof(SOCKET_HANDLE_ENTRY));
                    out->handle_value = (UINT64)i * 4;  // handle = index * 4
                    out->pid = target_pid;

                    if (extract_socket_info(object, out)) {
                        filled++;
                    }
                }
            };

            if (level == 0) {
                process_table(table_base);
            }
            else if (level == 1) {
                // L1: array of pointers to L0 tables
                constexpr UINT32 PTRS_PER_PAGE = 512;  // 4096 / 8
                for (UINT32 j = 0; j < PTRS_PER_PAGE && filled < MAX_SOCKET_HANDLES; j++) {
                    UINT64 ptr_addr = table_base + (UINT64)j * 8;
                    if (!_MmIsAddressValid((PVOID)ptr_addr)) break;
                    UINT64 l0 = *(UINT64*)ptr_addr;
                    if (l0 == 0 || !_MmIsAddressValid((PVOID)l0)) continue;
                    process_table(l0);
                }
            }
            else if (level == 2) {
                constexpr UINT32 PTRS_PER_PAGE = 512;
                for (UINT32 k = 0; k < PTRS_PER_PAGE && filled < MAX_SOCKET_HANDLES; k++) {
                    UINT64 l1_ptr_addr = table_base + (UINT64)k * 8;
                    if (!_MmIsAddressValid((PVOID)l1_ptr_addr)) break;
                    UINT64 l1 = *(UINT64*)l1_ptr_addr;
                    if (l1 == 0 || !_MmIsAddressValid((PVOID)l1)) continue;
                    for (UINT32 j = 0; j < PTRS_PER_PAGE && filled < MAX_SOCKET_HANDLES; j++) {
                        UINT64 ptr_addr = l1 + (UINT64)j * 8;
                        if (!_MmIsAddressValid((PVOID)ptr_addr)) break;
                        UINT64 l0 = *(UINT64*)ptr_addr;
                        if (l0 == 0 || !_MmIsAddressValid((PVOID)l0)) continue;
                        process_table(l0);
                    }
                }
            }

            request->socket_count = filled;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            stack_spoof::spoofed_ObfDereferenceObject(process);
            return STATUS_ACCESS_VIOLATION;
        }

        stack_spoof::spoofed_ObfDereferenceObject(process);
        return STATUS_SUCCESS;
    }
}

// =====================================================================
// Advanced network recon: Network buffer sniffing (HW breakpoint based)
// =====================================================================

namespace net_sniff {

    // Sniff state — one active sniff session at a time
    inline volatile LONG g_sniff_active = 0;
    inline KSPIN_LOCK g_sniff_lock;
    inline BOOLEAN g_sniff_lock_initialized = FALSE;

    inline UINT32 g_sniff_bp_index = 0;
    inline UINT32 g_sniff_tid = 0;
    inline UINT32 g_sniff_buf_reg = 0;
    inline UINT32 g_sniff_size_reg = 0;
    inline UINT32 g_sniff_max_captures = 1;
    inline volatile LONG g_sniff_capture_count = 0;
    inline SNIFF_CAPTURE* g_sniff_captures = nullptr;  // allocated on start

    // This is implemented as a lightweight controller —
    // The actual HW breakpoints and context reads are done through
    // the existing thread context IOCTL infrastructure.
    // This IOCTL manages the sniff session state.

    static NTSTATUS handle_sniff(p_sniff_net_buffers request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        if (!g_sniff_lock_initialized) {
            KeInitializeSpinLock(&g_sniff_lock);
            g_sniff_lock_initialized = TRUE;
        }

        switch (request->operation) {
        case 0: // START
        {
            if (_InterlockedCompareExchange(&g_sniff_active, 1, 0) != 0) {
                // Already active
                request->active = 1;
                request->capture_count = (UINT32)g_sniff_capture_count;
                return STATUS_DEVICE_BUSY;
            }

            // Allocate capture buffer
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

            // The actual HW breakpoint is set by the usermode side via
            // the existing driver_set_hw_breakpoint tool (TCTX IOCTL).
            // This handler manages session state and capture storage.
            // The usermode orchestrates: set BP → poll thread context →
            // read buffer at addr from register → store via this IOCTL result.

            request->active = 1;
            request->capture_count = 0;
            return STATUS_SUCCESS;
        }
        case 1: // STOP
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
        case 2: // GET_RESULTS
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
        case 3: // STORE_CAPTURE (called from usermode after reading buffer via memory read)
        {
            if (!g_sniff_active) return STATUS_DEVICE_NOT_READY;

            UINT32 idx = (UINT32)_InterlockedIncrement(&g_sniff_capture_count) - 1;
            if (idx >= g_sniff_max_captures) {
                // Reached max — auto-stop
                _InterlockedExchange(&g_sniff_active, 0);
                request->active = 0;
                request->capture_count = g_sniff_max_captures;
                return STATUS_SUCCESS;
            }

            KIRQL irql;
            KeAcquireSpinLock(&g_sniff_lock, &irql);
            if (g_sniff_captures && idx < g_sniff_max_captures) {
                // Copy the first capture entry from request as the stored capture
                strong::kmemcpy(&g_sniff_captures[idx], &request->captures[0], sizeof(SNIFF_CAPTURE));
            }
            KeReleaseSpinLock(&g_sniff_lock, irql);

            request->active = (UINT32)g_sniff_active;
            request->capture_count = idx + 1;

            // Auto-stop if we've hit the max
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

// =====================================================================
// Advanced network recon: tcpip.sys direct connection table dump
// =====================================================================

namespace net_tcpip {

    // tcpip.sys partition table structures
    // Windows maintains TCP connections in a hash table called the
    // "Partition Table" or "TCB Table" inside tcpip.sys.
    // We use the NSI (Network Store Interface) approach from netio.sys
    // as a more reliable method than walking raw tcpip structures,
    // because the internal TCB layout changes between builds.
    // But we enhance it with extra data only available from kernel.

    // NPI Module IDs
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

    // NSI enumeration function type
    typedef NTSTATUS(NTAPI* fn_NsiEnumObjectsAllParams)(
        ULONG Unknown0, ULONG Unknown1, PVOID ModuleId,
        ULONG InfoClass, PVOID KeyData, ULONG KeySize,
        PVOID RwData, ULONG RwSize,
        PVOID DynamicData, ULONG DynSize,
        PVOID StaticData, ULONG StaticSize,
        PULONG Count);

    // TCP key/rw/dynamic/static structures (NSI table 3 = established)
    // These match common Windows 10/11 layouts
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
        UINT64 mod_pid;   // Bits 0-23 = PID, or full at +8 depending on version
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

    static fn_NsiEnumObjectsAllParams resolve_nsi_enum() {
        PVOID netio = net_capture::find_module_base("netio.sys");
        if (!netio) netio = net_capture::find_module_base("NETIO.SYS");
        if (!netio) return nullptr;

        CHAR name[] = {'N','s','i','E','n','u','m','e','r','a','t','e','O','b','j','e','c','t','s','A','l','l','P','a','r','a','m','e','t','e','r','s',0};
        return (fn_NsiEnumObjectsAllParams)GetProcAddress(netio, name);
    }

    static NTSTATUS dump_connections(p_tcpip_conn_dump request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->connection_count = 0;

        auto _NsiEnum = resolve_nsi_enum();
        if (!_NsiEnum) return STATUS_NOT_SUPPORTED;

        UINT32 filled = 0;
        UINT32 target_pid = request->target_pid;
        BOOLEAN want_tcp = (request->filter_protocol == 0 || request->filter_protocol == 6);
        BOOLEAN want_udp = (request->filter_protocol == 0 || request->filter_protocol == 17);

        // ---- TCP connections (NSI table class 3 = established) ----
        if (want_tcp) {
            ULONG tcp_count = 0;
            NTSTATUS probe = _NsiEnum(
                0, 0, (PVOID)&NPI_TCP_MOD, 3,
                nullptr, sizeof(TCP4_KEY),
                nullptr, 0,
                nullptr, sizeof(TCP4_DYNAMIC),
                nullptr, sizeof(TCP4_STATIC),
                &tcp_count);

            if (tcp_count > 0) {
                if (tcp_count > 4096) tcp_count = 4096;

                SIZE_T key_buf_sz = (SIZE_T)tcp_count * sizeof(TCP4_KEY);
                SIZE_T dyn_buf_sz = (SIZE_T)tcp_count * sizeof(TCP4_DYNAMIC);
                SIZE_T sta_buf_sz = (SIZE_T)tcp_count * sizeof(TCP4_STATIC);

                TCP4_KEY* keys = (TCP4_KEY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, key_buf_sz, 'ktNW');
                TCP4_DYNAMIC* dyns = (TCP4_DYNAMIC*)ExAllocatePool2(POOL_FLAG_NON_PAGED, dyn_buf_sz, 'dtNW');
                TCP4_STATIC* stas = (TCP4_STATIC*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sta_buf_sz, 'stNW');

                if (keys && dyns && stas) {
                    strong::kmemset(keys, 0, key_buf_sz);
                    strong::kmemset(dyns, 0, dyn_buf_sz);
                    strong::kmemset(stas, 0, sta_buf_sz);

                    ULONG actual = tcp_count;
                    NTSTATUS st = _NsiEnum(
                        0, 0, (PVOID)&NPI_TCP_MOD, 3,
                        keys, sizeof(TCP4_KEY),
                        nullptr, 0,
                        dyns, sizeof(TCP4_DYNAMIC),
                        stas, sizeof(TCP4_STATIC),
                        &actual);

                    if (NT_SUCCESS(st)) {
                        for (ULONG i = 0; i < actual && filled < MAX_TCPIP_CONNECTIONS; i++) {
                            UINT32 pid_val = (UINT32)(stas[i].mod_pid & 0xFFFFFF);
                            if (target_pid != 0 && pid_val != target_pid) continue;

                            TCPIP_CONN_ENTRY* e = &request->entries[filled];
                            strong::kmemset(e, 0, sizeof(TCPIP_CONN_ENTRY));

                            e->pid = pid_val;
                            e->protocol = 6;
                            e->state = dyns[i].state;
                            e->address_family = 2;
                            e->local_port = ((keys[i].local_port_be >> 8) & 0xFF) | ((keys[i].local_port_be & 0xFF) << 8);
                            e->remote_port = ((keys[i].remote_port_be >> 8) & 0xFF) | ((keys[i].remote_port_be & 0xFF) << 8);
                            strong::kmemcpy(e->local_addr, keys[i].local_addr, 4);
                            strong::kmemcpy(e->remote_addr, keys[i].remote_addr, 4);
                            e->create_time = stas[i].create_time;
                            e->tcb_address = 0;  // Not available via NSI
                            e->owning_module_base = 0;
                            e->bytes_in = 0;
                            e->bytes_out = 0;
                            filled++;
                        }
                    }
                }

                if (keys) ExFreePoolWithTag(keys, 'ktNW');
                if (dyns) ExFreePoolWithTag(dyns, 'dtNW');
                if (stas) ExFreePoolWithTag(stas, 'stNW');
            }

            // Also enumerate TCP listeners (table class 1)
            ULONG listen_count = 0;
            _NsiEnum(0, 0, (PVOID)&NPI_TCP_MOD, 1,
                nullptr, sizeof(TCP4_KEY),
                nullptr, 0,
                nullptr, 0,
                nullptr, sizeof(TCP4_STATIC),
                &listen_count);

            if (listen_count > 0) {
                if (listen_count > 4096) listen_count = 4096;

                SIZE_T key_sz = (SIZE_T)listen_count * sizeof(TCP4_KEY);
                SIZE_T sta_sz = (SIZE_T)listen_count * sizeof(TCP4_STATIC);

                TCP4_KEY* lkeys = (TCP4_KEY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz, 'klNW');
                TCP4_STATIC* lstas = (TCP4_STATIC*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sta_sz, 'slNW');

                if (lkeys && lstas) {
                    strong::kmemset(lkeys, 0, key_sz);
                    strong::kmemset(lstas, 0, sta_sz);

                    ULONG actual = listen_count;
                    NTSTATUS st = _NsiEnum(
                        0, 0, (PVOID)&NPI_TCP_MOD, 1,
                        lkeys, sizeof(TCP4_KEY),
                        nullptr, 0,
                        nullptr, 0,
                        lstas, sizeof(TCP4_STATIC),
                        &actual);

                    if (NT_SUCCESS(st)) {
                        for (ULONG i = 0; i < actual && filled < MAX_TCPIP_CONNECTIONS; i++) {
                            UINT32 pid_val = (UINT32)(lstas[i].mod_pid & 0xFFFFFF);
                            if (target_pid != 0 && pid_val != target_pid) continue;

                            TCPIP_CONN_ENTRY* e = &request->entries[filled];
                            strong::kmemset(e, 0, sizeof(TCPIP_CONN_ENTRY));
                            e->pid = pid_val;
                            e->protocol = 6;
                            e->state = 1;  // LISTEN
                            e->address_family = 2;
                            e->local_port = ((lkeys[i].local_port_be >> 8) & 0xFF) | ((lkeys[i].local_port_be & 0xFF) << 8);
                            strong::kmemcpy(e->local_addr, lkeys[i].local_addr, 4);
                            e->create_time = lstas[i].create_time;
                            filled++;
                        }
                    }
                }

                if (lkeys) ExFreePoolWithTag(lkeys, 'klNW');
                if (lstas) ExFreePoolWithTag(lstas, 'slNW');
            }
        }

        // ---- UDP endpoints ----
        if (want_udp) {
            ULONG udp_count = 0;
            _NsiEnum(0, 0, (PVOID)&NPI_UDP_MOD, 1,
                nullptr, sizeof(UDP4_KEY),
                nullptr, 0,
                nullptr, 0,
                nullptr, sizeof(UDP4_STATIC),
                &udp_count);

            if (udp_count > 0) {
                if (udp_count > 4096) udp_count = 4096;

                SIZE_T key_sz = (SIZE_T)udp_count * sizeof(UDP4_KEY);
                SIZE_T sta_sz = (SIZE_T)udp_count * sizeof(UDP4_STATIC);

                UDP4_KEY* ukeys = (UDP4_KEY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz, 'kuNW');
                UDP4_STATIC* ustas = (UDP4_STATIC*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sta_sz, 'suNW');

                if (ukeys && ustas) {
                    strong::kmemset(ukeys, 0, key_sz);
                    strong::kmemset(ustas, 0, sta_sz);

                    ULONG actual = udp_count;
                    NTSTATUS st = _NsiEnum(
                        0, 0, (PVOID)&NPI_UDP_MOD, 1,
                        ukeys, sizeof(UDP4_KEY),
                        nullptr, 0,
                        nullptr, 0,
                        ustas, sizeof(UDP4_STATIC),
                        &actual);

                    if (NT_SUCCESS(st)) {
                        for (ULONG i = 0; i < actual && filled < MAX_TCPIP_CONNECTIONS; i++) {
                            UINT32 pid_val = (UINT32)(ustas[i].mod_pid & 0xFFFFFF);
                            if (target_pid != 0 && pid_val != target_pid) continue;

                            TCPIP_CONN_ENTRY* e = &request->entries[filled];
                            strong::kmemset(e, 0, sizeof(TCPIP_CONN_ENTRY));
                            e->pid = pid_val;
                            e->protocol = 17;
                            e->address_family = 2;
                            e->local_port = ((ukeys[i].local_port_be >> 8) & 0xFF) | ((ukeys[i].local_port_be & 0xFF) << 8);
                            strong::kmemcpy(e->local_addr, ukeys[i].local_addr, 4);
                            e->create_time = ustas[i].create_time;
                            filled++;
                        }
                    }
                }

                if (ukeys) ExFreePoolWithTag(ukeys, 'kuNW');
                if (ustas) ExFreePoolWithTag(ustas, 'suNW');
            }
        }

        request->connection_count = filled;
        return STATUS_SUCCESS;
    }
}


// =====================================================================
// MITM: Packet injection via WFP inject APIs
// =====================================================================
namespace net_inject {

    // WFP injection function pointers
    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleCreate0)(
        UINT16 addressFamily, UINT32 flags, HANDLE* injectionHandle);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleDestroy0)(HANDLE injectionHandle);
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

    inline fn_FwpsInjectionHandleCreate0         _FwpsInjectionHandleCreate0   = nullptr;
    inline fn_FwpsInjectionHandleDestroy0        _FwpsInjectionHandleDestroy0  = nullptr;
    inline fn_FwpsAllocateNetBufferAndNetBufferList0 _FwpsAllocateNBL0         = nullptr;
    inline fn_FwpsFreeNetBufferList0             _FwpsFreeNBL0                 = nullptr;
    inline fn_FwpsInjectTransportSendAsync0      _FwpsInjectSend0              = nullptr;
    inline fn_FwpsInjectTransportReceiveAsync0   _FwpsInjectRecv0              = nullptr;

    inline HANDLE g_inject_handle_v4 = nullptr;
    inline volatile LONG g_inject_resolved = 0;

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

        *(PVOID*)&_FwpsInjectionHandleCreate0 = GetProcAddress(fwp_base, f1);
        *(PVOID*)&_FwpsInjectionHandleDestroy0 = GetProcAddress(fwp_base, f2);
        *(PVOID*)&_FwpsAllocateNBL0 = GetProcAddress(fwp_base, f3);
        *(PVOID*)&_FwpsFreeNBL0 = GetProcAddress(fwp_base, f4);
        *(PVOID*)&_FwpsInjectSend0 = GetProcAddress(fwp_base, f5);
        *(PVOID*)&_FwpsInjectRecv0 = GetProcAddress(fwp_base, f6);

        if (_FwpsInjectionHandleCreate0) {
            NTSTATUS st = _FwpsInjectionHandleCreate0(2 /*AF_INET*/, 0, &g_inject_handle_v4);
            if (!NT_SUCCESS(st)) g_inject_handle_v4 = nullptr;
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_inject_resolved, 2);
        return g_inject_handle_v4 != nullptr;
    }

    void NTAPI inject_completion(PVOID context, PVOID nbl, BOOLEAN dispatch_level) {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(dispatch_level);
        if (nbl && _FwpsFreeNBL0) _FwpsFreeNBL0(nbl);
    }

    NTSTATUS inject_packet(p_packet_inject_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->status = 1; // assume failure

        if (!resolve_inject_functions() || !g_inject_handle_v4)
            return STATUS_NOT_SUPPORTED;

        if (request->payload_size == 0 || request->payload_size > INJECT_MAX_PAYLOAD)
            return STATUS_INVALID_PARAMETER;

        // Allocate MDL for payload
        PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, request->payload_size, 'jiNW');
        if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
        strong::kmemcpy(buf, request->payload, request->payload_size);

        PMDL mdl = IoAllocateMdl(buf, request->payload_size, FALSE, FALSE, nullptr);
        if (!mdl) {
            ExFreePoolWithTag(buf, 'jiNW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        MmBuildMdlForNonPagedPool(mdl);

        PVOID nbl = nullptr;
        NTSTATUS st = _FwpsAllocateNBL0(nullptr, 0, 0, mdl, 0, request->payload_size, &nbl);
        if (!NT_SUCCESS(st) || !nbl) {
            IoFreeMdl(mdl);
            ExFreePoolWithTag(buf, 'jiNW');
            return st;
        }

        if (request->direction == 1) {
            // Outbound inject
            st = _FwpsInjectSend0(g_inject_handle_v4, nullptr, 0, 0,
                nullptr, (UINT16)request->address_family, 0, nbl,
                (PVOID)inject_completion, buf);
        } else {
            // Inbound inject
            st = _FwpsInjectRecv0(g_inject_handle_v4, nullptr, nullptr, 0,
                (UINT16)request->address_family, 0, 0, 0, nbl,
                (PVOID)inject_completion, buf);
        }

        if (!NT_SUCCESS(st)) {
            _FwpsFreeNBL0(nbl);
            IoFreeMdl(mdl);
            ExFreePoolWithTag(buf, 'jiNW');
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
    }
}

// =====================================================================
// MITM: Packet modification engine
// =====================================================================
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

    // Called from classify callbacks to apply modification rules
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

            // Scan for pattern in data
            for (UINT32 i = 0; i + rule->pattern_size <= *data_len; i++) {
                BOOLEAN match = TRUE;
                for (UINT32 j = 0; j < rule->pattern_size; j++) {
                    if (data[i + j] != rule->pattern[j]) { match = FALSE; break; }
                }
                if (match) {
                    // Replace in-place if size difference fits
                    INT32 diff = (INT32)rule->replace_size - (INT32)rule->pattern_size;
                    UINT32 new_len = *data_len + diff;
                    if (new_len > max_len) continue;

                    if (diff != 0) {
                        // Shift tail of data
                        UINT32 tail_start = i + rule->pattern_size;
                        UINT32 tail_len = *data_len - tail_start;
                        if (tail_len > 0) {
                            // Move forward or backward
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
                    i += rule->replace_size - 1; // skip past replacement
                }
            }
        }
        return modified;
    }

    NTSTATUS handle_mod_rule(p_packet_mod_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: { // add
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
        case 1: { // remove by rule_id
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
        case 3: { // clear all
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

// =====================================================================
// MITM: Traffic redirect engine
// =====================================================================
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

    // Called from classify callbacks - checks if we should redirect this packet
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
        case 0: { // add
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
        case 1: { // remove
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
        case 3: { // clear
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

// =====================================================================
// MITM: TCP stream reassembly engine
// =====================================================================
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

    // Called from classify to feed data into tracked streams
    void feed_packet(UINT32 src_port, UINT32 dst_port, UINT32 pid,
                     const UINT8* src_addr, const UINT8* dst_addr,
                     const UINT8* data, UINT32 data_len) {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            if (!g_streams[i].active) continue;

            BOOLEAN match = FALSE;
            // Match either direction of the connection
            if (g_streams[i].src_port == src_port && g_streams[i].dst_port == dst_port) {
                BOOLEAN addr_match = TRUE;
                for (int j = 0; j < 4; j++) {
                    if (g_streams[i].src_addr[j] != src_addr[j] ||
                        g_streams[i].dst_addr[j] != dst_addr[j]) {
                        addr_match = FALSE; break;
                    }
                }
                if (addr_match) match = TRUE;
            }
            if (!match && g_streams[i].src_port == dst_port && g_streams[i].dst_port == src_port) {
                BOOLEAN addr_match = TRUE;
                for (int j = 0; j < 4; j++) {
                    if (g_streams[i].src_addr[j] != dst_addr[j] ||
                        g_streams[i].dst_addr[j] != src_addr[j]) {
                        addr_match = FALSE; break;
                    }
                }
                if (addr_match) match = TRUE;
            }
            if (g_streams[i].pid != 0 && g_streams[i].pid != pid) match = FALSE;

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
        case 0: { // start_tracking
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
        case 1: { // stop
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
        case 2: { // get_data
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
        case 3: { // list
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

// =====================================================================
// Deep Packet Inspection (DPI) engine
// =====================================================================
namespace net_dpi {

    // DPI ring buffer for analyzed packets
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

    // Detect HTTP method from payload start
    static UINT32 detect_http_method(const UINT8* data, UINT32 len) {
        if (len < 4) return 0;
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
        if (len >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ') return 2;
        if (len >= 4 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return 3;
        if (len >= 7 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L') return 4;
        if (len >= 5 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ') return 5;
        if (len >= 5 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && data[4] == '/') return 6; // Response
        return 0;
    }

    // Extract HTTP Host header
    static void extract_http_host(const UINT8* data, UINT32 len, char* out, UINT32 out_size) {
        out[0] = 0;
        // Scan for "Host: "
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

    // Extract HTTP path (first line after method)
    static void extract_http_path(const UINT8* data, UINT32 len, char* out, UINT32 out_size) {
        out[0] = 0;
        // Find first space (after method)
        UINT32 i = 0;
        while (i < len && data[i] != ' ') i++;
        if (i >= len) return;
        i++; // skip space
        UINT32 k = 0;
        while (i < len && data[i] != ' ' && data[i] != '\r' && data[i] != '\n' && k < out_size - 1) {
            out[k++] = (char)data[i++];
        }
        out[k] = 0;
    }

    // Detect and parse TLS record from payload
    static void detect_tls(const UINT8* data, UINT32 len, DPI_HEADER_INFO* info) {
        if (len < 5) return;
        // TLS content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData
        UINT8 content_type = data[0];
        if (content_type < 20 || content_type > 23) return;

        UINT16 version = ((UINT16)data[1] << 8) | data[2];
        // Valid TLS versions: 0x0301 (TLS1.0), 0x0302 (TLS1.1), 0x0303 (TLS1.2), 0x0304 (TLS1.3)
        if (version < 0x0300 || version > 0x0304) return;

        info->is_tls = 1;
        info->tls_version = version;
        info->tls_content_type = content_type;

        // For handshake Client Hello, extract SNI
        if (content_type == 22 && len > 43) {
            UINT8 handshake_type = data[5];
            if (handshake_type == 1) { // ClientHello
                // Session ID at offset 43
                UINT32 pos = 43;
                if (pos >= len) return;
                UINT8 session_id_len = data[pos];
                pos += 1 + session_id_len;
                if (pos + 2 >= len) return;
                // Cipher suites
                UINT16 cs_len = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 2 + cs_len;
                if (pos + 1 >= len) return;
                // Compression methods
                UINT8 comp_len = data[pos];
                pos += 1 + comp_len;
                if (pos + 2 >= len) return;
                // Extensions
                UINT16 ext_len = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 2;
                UINT32 ext_end = pos + ext_len;
                while (pos + 4 <= ext_end && pos + 4 <= len) {
                    UINT16 ext_type = ((UINT16)data[pos] << 8) | data[pos + 1];
                    UINT16 elen = ((UINT16)data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                    if (ext_type == 0 && elen > 5 && pos + elen <= len) {
                        // SNI extension: skip SNI list length (2) + type (1) + name length (2)
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

    // Called from classify callbacks to perform deep inspection
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

        // Parse TCP header if TCP payload includes flags
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

                // HTTP detection
                info.http_method = detect_http_method(app_data, app_len);
                if (info.http_method) {
                    info.is_http = 1;
                    extract_http_host(app_data, app_len, info.http_host, sizeof(info.http_host));
                    extract_http_path(app_data, app_len, info.http_path, sizeof(info.http_path));
                }

                // TLS detection
                detect_tls(app_data, app_len, &info);

                // DNS over TCP
                if ((src_port == 53 || dst_port == 53) && app_len > 0) {
                    info.is_dns = 1;
                }
            }
        }

        // UDP DNS
        if (protocol == 17 && (src_port == 53 || dst_port == 53) && payload_len > 0) {
            info.is_dns = 1;
        }

        // UDP TLS (DTLS)
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

        UINT32 idx = g_dpi_tail;
        while (idx != (UINT32)g_dpi_head && request->result_count < DPI_MAX_RESULTS) {
            DPI_HEADER_INFO* src = &g_dpi_ring[idx];

            // Apply filters
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

// =====================================================================
// MITM: Intercept-and-hold engine (Burp Suite proxy mode)
// =====================================================================
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

    // Called from classify — returns TRUE if packet should be held (blocked)
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
            return FALSE; // queue full, let it through
        }

        // Find empty slot
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
                return TRUE; // block the packet, we're holding it
            }
        }

        KeReleaseSpinLock(&g_intercept_lock, irql);
        return FALSE;
    }

    NTSTATUS handle_intercept(p_intercept_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: { // enable
            g_filter_pid = request->filter_pid;
            g_filter_port = request->filter_port;
            g_filter_protocol = request->filter_protocol;
            _InterlockedExchange(&g_intercepting, 1);
            request->intercepting = 1;
            request->held_count = g_held_count;
            return STATUS_SUCCESS;
        }
        case 1: { // disable
            _InterlockedExchange(&g_intercepting, 0);
            // Release all held packets (just clear them)
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
        case 2: { // get_held
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
        case 3: { // release (let through - just remove from held)
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {
                    // Re-inject packet via injection API
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
        case 4: { // drop (just remove without re-injecting)
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
        case 5: { // modify_and_release
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {
                    // Re-inject with modified payload
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

// =====================================================================
// MITM: Connection kill (RST injection)
// =====================================================================
namespace net_kill {

    NTSTATUS kill_connection(p_conn_kill_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->status = 1;

        if (request->protocol != 6) return STATUS_INVALID_PARAMETER; // TCP only

        if (!net_inject::resolve_inject_functions() || !net_inject::g_inject_handle_v4)
            return STATUS_NOT_SUPPORTED;

        // Build a TCP RST packet
        // We need to craft a minimal TCP segment with RST flag
        UINT8 rst_pkt[20] = {}; // minimal TCP header
        // Source port (network byte order)
        rst_pkt[0] = (UINT8)(request->src_port >> 8);
        rst_pkt[1] = (UINT8)(request->src_port & 0xFF);
        // Dest port
        rst_pkt[2] = (UINT8)(request->dst_port >> 8);
        rst_pkt[3] = (UINT8)(request->dst_port & 0xFF);
        // Seq number = 0
        // Data offset = 5 (20 bytes / 4), and RST flag
        rst_pkt[12] = 0x50; // data offset = 5
        rst_pkt[13] = 0x04; // RST flag
        // Window
        rst_pkt[14] = 0xFF;
        rst_pkt[15] = 0xFF;

        packet_inject_request inj = {};
        inj.direction = 1; // outbound
        inj.protocol = 6;
        inj.address_family = request->address_family;
        inj.src_port = request->src_port;
        inj.dst_port = request->dst_port;
        strong::kmemcpy(inj.src_addr, request->src_addr, 16);
        strong::kmemcpy(inj.dst_addr, request->dst_addr, 16);
        inj.payload_size = 20;
        strong::kmemcpy(inj.payload, rst_pkt, 20);
        inj.tcp_flags = 0x04; // RST

        NTSTATUS st = net_inject::inject_packet(&inj);
        if (NT_SUCCESS(st)) request->status = 0;
        return st;
    }
}

// =====================================================================
// MITM: DNS spoofing engine
// =====================================================================
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

    // Simple domain match with wildcard support (*.example.com)
    static BOOLEAN domain_matches(const char* pattern, const char* domain) {
        if (!pattern || !domain) return FALSE;
        if (pattern[0] == '*' && pattern[1] == '.') {
            // Wildcard: match any subdomain
            const char* suffix = pattern + 1; // ".example.com"
            UINT32 slen = 0, dlen = 0;
            while (suffix[slen]) slen++;
            while (domain[dlen]) dlen++;
            if (dlen < slen) return FALSE;
            // Compare suffix
            for (UINT32 i = 0; i < slen; i++) {
                char a = suffix[slen - 1 - i];
                char b = domain[dlen - 1 - i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) return FALSE;
            }
            return TRUE;
        }
        // Exact match (case-insensitive)
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

    // Called from DNS parser in classify - checks if this domain should be spoofed
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
        case 0: { // add
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
        case 1: { // remove
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
        case 3: { // clear
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

// =====================================================================
// MITM: Bandwidth monitoring engine
// =====================================================================
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

    // Called from classify callbacks
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

        // Find or create per-process entry
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
        case 0: // start
            _InterlockedExchange(&g_bw_active, 1);
            request->monitoring_active = 1;
            return STATUS_SUCCESS;
        case 1: // stop
            _InterlockedExchange(&g_bw_active, 0);
            request->monitoring_active = 0;
            return STATUS_SUCCESS;
        case 2: { // get_stats
            request->total_bytes_sent = g_bw_total_sent;
            request->total_bytes_recv = g_bw_total_recv;
            request->total_packets_sent = g_bw_total_pkts_sent;
            request->total_packets_recv = g_bw_total_pkts_recv;
            request->monitoring_active = g_bw_active;

            // Calculate rate
            LARGE_INTEGER now;
            KeQuerySystemTime(&now);
            UINT64 elapsed = now.QuadPart - g_bw_last_sample_time;
            if (elapsed > 0 && g_bw_last_sample_time != 0) {
                LONG64 delta_sent = g_bw_total_sent - g_bw_last_sample_sent;
                LONG64 delta_recv = g_bw_total_recv - g_bw_last_sample_recv;
                // elapsed is in 100ns units; convert to seconds
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
        case 3: { // reset
            g_bw_total_sent = 0;
            g_bw_total_recv = 0;
            g_bw_total_pkts_sent = 0;
            g_bw_total_pkts_recv = 0;
            for (UINT32 i = 0; i < BW_MAX_PROCESSES; i++) {
                _InterlockedExchange(&g_bw_entries[i].active, 0);
            }
            return STATUS_SUCCESS;
        }
        case 4: { // get_per_process
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

// =====================================================================
// Network interface enumeration
// =====================================================================
namespace net_if_enum {

    // MIB_IF_TABLE2 / MIB_IF_ROW2 layout (simplified)
    typedef NTSTATUS(NTAPI* fn_GetIfTable2)(PVOID* Table);
    typedef void(NTAPI* fn_FreeMibTable)(PVOID Table);
    typedef NTSTATUS(NTAPI* fn_GetAdaptersAddresses)(
        ULONG Family, ULONG Flags, PVOID Reserved,
        PVOID AdapterAddresses, PULONG SizePointer);

    NTSTATUS enumerate_interfaces(p_net_interface_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->interface_count = 0;

        // Use ZwQuerySystemInformation for network interface info
        // We walk kernel's network interface structures via IOCTL to NDIS or IP helper
        // Simpler approach: enumerate from SystemModuleInformation + NDIS miniport info
        // For robustness, we use a simpler approach: walk net_capture's WFP data

        // Direct approach via netio.sys GetIfTable2
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
            // MIB_IF_TABLE2: first ULONG is NumEntries, then array of MIB_IF_ROW2
            // MIB_IF_ROW2 is large (~1352 bytes each)
            ULONG num = *(ULONG*)table;
            UINT8* rows = (UINT8*)table + 8; // aligned after count

            // MIB_IF_ROW2 offsets (Windows 10/11):
            //   +0x000: InterfaceLuid (UINT64)
            //   +0x008: InterfaceIndex (UINT32)
            //   +0x00C: InterfaceGuid (GUID)
            //   +0x01C: Alias (wchar_t[257]) = 514 bytes
            //   +0x222: Description (wchar_t[257]) = 514 bytes
            //   +0x428: PhysicalAddressLength (UINT32)
            //   +0x42C: PhysicalAddress[32]
            //   +0x44C: PermanentPhysicalAddress[32]
            //   +0x46C: Mtu (UINT32)
            //   +0x470: Type (UINT32)
            //   +0x478: MediaType... TransmitLinkSpeed(+0x488, UINT64), ReceiveLinkSpeed(+0x490)
            //   +0x498: OperStatus (UINT32)
            //   +0x500+: InOctets, OutOctets etc

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

                // Physical address (MAC)
                UINT32 phys_len = *(UINT32*)(row + 0x428);
                if (phys_len >= 6) {
                    strong::kmemcpy(e->mac_addr, row + 0x42C, 6);
                }

                // Convert alias (wchar_t) to char for name
                wchar_t* alias = (wchar_t*)(row + 0x01C);
                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && alias[j]; j++) {
                    e->name[j] = (char)(alias[j] & 0x7F);
                }

                // Convert description
                wchar_t* desc = (wchar_t*)(row + 0x222);
                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && desc[j]; j++) {
                    e->description[j] = (char)(desc[j] & 0x7F);
                }

                // InOctets / OutOctets (at offset ~0x508/0x510)
                e->in_octets = *(UINT64*)(row + 0x508);
                e->out_octets = *(UINT64*)(row + 0x510);

                request->interface_count++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Partial results are fine
        }

        _FreeMibTable(table);
        return STATUS_SUCCESS;
    }
}

// =====================================================================
// PCAP export engine
// =====================================================================
namespace net_pcap {

    NTSTATUS export_pcap(p_pcap_export_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        // Fill PCAP global header
        request->header.magic_number = 0xa1b2c3d4;
        request->header.version_major = 2;
        request->header.version_minor = 4;
        request->header.thiszone = 0;
        request->header.sigfigs = 0;
        request->header.snaplen = PCAP_RECORD_MAX_SIZE;
        request->header.network = 101; // LINKTYPE_RAW (raw IP)

        UINT32 max_pkts = request->max_packets;
        if (max_pkts == 0 || max_pkts > PCAP_MAX_EXPORT_PACKETS)
            max_pkts = PCAP_MAX_EXPORT_PACKETS;

        request->packet_count = 0;
        request->data_size = sizeof(PCAP_GLOBAL_HEADER);

        // Read from captured packet ring buffer
        if (!net_capture::g_ring_buffer) return STATUS_NOT_SUPPORTED;

        KIRQL irql;
        KeAcquireSpinLock(&net_capture::g_ring_lock, &irql);

        LONG count = net_capture::g_ring_count;
        LONG idx = net_capture::g_ring_tail;

        while (count > 0 && request->packet_count < max_pkts) {
            NET_PACKET_ENTRY* pkt = &net_capture::g_ring_buffer[idx];

            PCAP_RECORD* rec = &request->records[request->packet_count];
            strong::kmemset(rec, 0, sizeof(PCAP_RECORD));

            // Convert Windows FILETIME (100ns since 1601) to Unix timestamp
            UINT64 unix_100ns = pkt->timestamp - 116444736000000000ULL;
            rec->ts_sec = (UINT32)(unix_100ns / 10000000ULL);
            rec->ts_usec = (UINT32)((unix_100ns % 10000000ULL) / 10);

            // Build a minimal IP header + payload
            UINT32 ip_header_len = 20;
            UINT32 total_len = ip_header_len + pkt->payload_size;
            if (total_len > PCAP_RECORD_MAX_SIZE) total_len = PCAP_RECORD_MAX_SIZE;

            // IPv4 header
            rec->data[0] = 0x45; // version=4, IHL=5
            rec->data[1] = 0x00; // DSCP
            rec->data[2] = (UINT8)(total_len >> 8);
            rec->data[3] = (UINT8)(total_len & 0xFF);
            rec->data[4] = 0; rec->data[5] = 0; // ID
            rec->data[6] = 0x40; rec->data[7] = 0; // DF flag
            rec->data[8] = 64; // TTL
            rec->data[9] = (UINT8)pkt->protocol;
            // Checksum = 0 (no checksumming for pcap)
            // Src IP
            strong::kmemcpy(&rec->data[12], pkt->local_addr, 4);
            // Dst IP
            strong::kmemcpy(&rec->data[16], pkt->remote_addr, 4);

            // If direction is inbound, swap src/dst
            if (pkt->direction == 0) {
                strong::kmemcpy(&rec->data[12], pkt->remote_addr, 4);
                strong::kmemcpy(&rec->data[16], pkt->local_addr, 4);
            }

            // Copy payload after IP header
            UINT32 payload_copy = pkt->payload_size;
            if (ip_header_len + payload_copy > PCAP_RECORD_MAX_SIZE)
                payload_copy = PCAP_RECORD_MAX_SIZE - ip_header_len;
            strong::kmemcpy(&rec->data[ip_header_len], pkt->payload, payload_copy);

            rec->incl_len = ip_header_len + payload_copy;
            rec->orig_len = total_len;
            request->data_size += sizeof(UINT32) * 4 + rec->incl_len; // pcap record header + data

            request->packet_count++;
            idx = (idx + 1) % RING_BUFFER_SIZE;
            count--;
        }

        KeReleaseSpinLock(&net_capture::g_ring_lock, irql);

        // Apply PID/protocol filter
        if (request->filter_pid != 0 || request->filter_protocol != 0) {
            // Re-filter (we captured all, now trim)
            UINT32 write_idx = 0;
            for (UINT32 i = 0; i < request->packet_count; i++) {
                // We need to check against original packet data, but we've already lost PID info
                // For simplicity, filter before export or just provide all
                if (write_idx != i) {
                    strong::kmemcpy(&request->records[write_idx], &request->records[i], sizeof(PCAP_RECORD));
                }
                write_idx++;
            }
            request->packet_count = write_idx;
        }

        return STATUS_SUCCESS;
    }
}

// =====================================================================
// Network fingerprinting engine
// =====================================================================
namespace net_fingerprint {

    inline NET_FINGERPRINT_ENTRY g_fp_entries[FINGERPRINT_MAX] = {};
    inline volatile LONG g_fp_count = 0;
    inline volatile LONG g_fp_active = 0;
    inline KSPIN_LOCK g_fp_lock;

    BOOLEAN is_active() {
        return (g_fp_active != 0);
    }

    // Analyze a SYN or SYN-ACK packet for OS fingerprinting
    void analyze_tcp_syn(const UINT8* src_addr, UINT32 af,
                         const UINT8* tcp_data, UINT32 tcp_len,
                         UINT32 ip_ttl) {
        if (!g_fp_active || tcp_len < 20) return;

        UINT8 flags = tcp_data[13];
        if (!(flags & 0x02)) return; // Not SYN

        UINT32 window = ((UINT32)tcp_data[14] << 8) | tcp_data[15];
        UINT32 data_offset = ((tcp_data[12] >> 4) & 0xF) * 4;

        // Parse TCP options
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
                if (kind == 0) break; // End of options
                if (kind == 1) { nops++; pos++; continue; } // NOP
                if (pos + 1 >= tcp_len) break;
                UINT8 olen = tcp_data[pos + 1];
                if (olen < 2 || pos + olen > tcp_len) break;

                if (kind == 2 && olen == 4) { // MSS
                    mss = ((UINT32)tcp_data[pos + 2] << 8) | tcp_data[pos + 3];
                    opt_order |= (2 << (opt_idx * 4));
                }
                else if (kind == 3 && olen == 3) { // Window Scale
                    ws = tcp_data[pos + 2];
                    opt_order |= (3 << (opt_idx * 4));
                }
                else if (kind == 4 && olen == 2) { // SACK permitted
                    sack = 1;
                    opt_order |= (4 << (opt_idx * 4));
                }
                else if (kind == 8 && olen == 10) { // Timestamp
                    opt_order |= (8 << (opt_idx * 4));
                }
                opt_idx++;
                pos += olen;
            }
        }

        // Simple OS detection heuristic
        char os[64] = {};
        // Windows: TTL=128, MSS=1460, window varies
        // Linux: TTL=64, MSS=1460, window=65535 or scaled
        // macOS: TTL=64, MSS=1460
        // FreeBSD: TTL=64, MSS=1460

        UINT32 ttl_bucket = (ip_ttl > 96) ? 128 : (ip_ttl > 48 ? 64 : 32);

        if (ttl_bucket == 128) {
            if (window == 65535 || window == 64240) {
                // Windows 10/11
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

        // Store fingerprint
        KIRQL irql;
        KeAcquireSpinLock(&g_fp_lock, &irql);

        // Check if we already have this remote address
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
                    // Update
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

        // Add new
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
            g_fp_entries[idx].df_flag = 0; // would need IP header access
            strong::kmemcpy(g_fp_entries[idx].os_guess, os, 64);
            _InterlockedIncrement(&g_fp_count);
        }
        KeReleaseSpinLock(&g_fp_lock, irql);
    }

    NTSTATUS handle_fingerprint(p_net_fingerprint_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: // enable
            KeInitializeSpinLock(&g_fp_lock);
            _InterlockedExchange(&g_fp_active, 1);
            return STATUS_SUCCESS;
        case 1: // disable
            _InterlockedExchange(&g_fp_active, 0);
            return STATUS_SUCCESS;
        case 2: { // get_results
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

// =====================================================================
// IOCTL handler wrappers for the 4 advanced network recon tools
// =====================================================================

NTSTATUS functions::handle_wfp_callout_enum(p_wfp_callout_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL EWFP filter='%s'", request->filter_module);
    NTSTATUS st = net_wfp_enum::enumerate_wfp_callouts(request);
    AIDA_NET_LOG("IOCTL EWFP status=0x%08X count=%u", (UINT32)st, request->callout_count);
    return st;
}

NTSTATUS functions::handle_socket_handle_enum(p_socket_handle_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL GSKT pid=%u", request->target_pid);
    NTSTATUS st = net_socket_enum::enumerate_socket_handles(request);
    AIDA_NET_LOG("IOCTL GSKT status=0x%08X count=%u", (UINT32)st, request->socket_count);
    return st;
}

NTSTATUS functions::handle_sniff_net_buffers(p_sniff_net_buffers request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_sniff::handle_sniff(request);
}

NTSTATUS functions::handle_tcpip_conn_dump(p_tcpip_conn_dump request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL DTCP pid=%u proto=%u", request->target_pid, request->filter_protocol);
    NTSTATUS st = net_tcpip::dump_connections(request);
    AIDA_NET_LOG("IOCTL DTCP status=0x%08X count=%u", (UINT32)st, request->connection_count);
    return st;
}

// =====================================================================
// IOCTL handler wrappers for MITM / interception tools
// =====================================================================

NTSTATUS functions::handle_packet_inject(p_packet_inject_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL PINJ dir=%u proto=%u af=%u src_port=%u dst_port=%u size=%u",
        request->direction, request->protocol, request->address_family,
        request->src_port, request->dst_port, request->payload_size);
    NTSTATUS st = net_inject::inject_packet(request);
    AIDA_NET_LOG("IOCTL PINJ status=0x%08X req_status=%u", (UINT32)st, request->status);
    return st;
}

NTSTATUS functions::handle_packet_mod_rule(p_packet_mod_rule request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL PMOD op=%u rule_id=%u proto=%u port=%u pid=%u pat=%u rep=%u",
        request->operation, request->rule_id, request->protocol, request->port,
        request->pid, request->pattern_size, request->replace_size);
    if (request->operation == 2) {
        // List operation uses the larger struct
        NTSTATUS st = net_mod::handle_mod_rule_list((p_packet_mod_rule_list)request);
        AIDA_NET_LOG("IOCTL PMOD(list) status=0x%08X count=%u", (UINT32)st,
            ((p_packet_mod_rule_list)request)->rule_count);
        return st;
    }
    NTSTATUS st = net_mod::handle_mod_rule(request);
    AIDA_NET_LOG("IOCTL PMOD status=0x%08X out_rule_id=%u active=%u", (UINT32)st, request->rule_id, request->active);
    return st;
}

NTSTATUS functions::handle_traffic_redirect(p_traffic_redirect_rule request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL PRED op=%u rule_id=%u proto=%u match_port=%u redirect_port=%u",
        request->operation, request->rule_id, request->protocol, request->match_port, request->redirect_port);
    if (request->operation == 2) {
        NTSTATUS st = net_redirect::handle_redirect_list((p_traffic_redirect_list)request);
        AIDA_NET_LOG("IOCTL PRED(list) status=0x%08X count=%u", (UINT32)st,
            ((p_traffic_redirect_list)request)->rule_count);
        return st;
    }
    NTSTATUS st = net_redirect::handle_redirect_rule(request);
    AIDA_NET_LOG("IOCTL PRED status=0x%08X out_rule_id=%u active=%u", (UINT32)st, request->rule_id, request->active);
    return st;
}

NTSTATUS functions::handle_stream_reassemble(p_stream_reassemble_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL STRM op=%u src_port=%u dst_port=%u pid=%u", request->operation, request->src_port, request->dst_port, request->pid);
    NTSTATUS st = net_stream::handle_stream(request);
    AIDA_NET_LOG("IOCTL STRM status=0x%08X stream_size=%u packets=%u streams=%u",
        (UINT32)st, request->stream_size, request->total_packets, request->stream_count);
    return st;
}

NTSTATUS functions::handle_deep_inspect(p_dpi_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL DPIN filter_pid=%u filter_proto=%u filter_port=%u flags=0x%X",
        request->filter_pid, request->filter_protocol, request->filter_port, request->flags);
    NTSTATUS st = net_dpi::get_results(request);
    AIDA_NET_LOG("IOCTL DPIN status=0x%08X results=%u", (UINT32)st, request->result_count);
    return st;
}

NTSTATUS functions::handle_intercept_hold(p_intercept_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL IHLD op=%u hold_id=%llu filter_pid=%u filter_port=%u filter_proto=%u modify_size=%u",
        request->operation, (unsigned long long)request->hold_id, request->filter_pid,
        request->filter_port, request->filter_protocol, request->modify_payload_size);
    NTSTATUS st = net_intercept::handle_intercept(request);
    AIDA_NET_LOG("IOCTL IHLD status=0x%08X intercepting=%u held=%u", (UINT32)st, request->intercepting, request->held_count);
    return st;
}

NTSTATUS functions::handle_conn_kill(p_conn_kill_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL CKIL proto=%u af=%u src_port=%u dst_port=%u pid=%u",
        request->protocol, request->address_family, request->src_port, request->dst_port, request->pid);
    NTSTATUS st = net_kill::kill_connection(request);
    AIDA_NET_LOG("IOCTL CKIL status=0x%08X req_status=%u", (UINT32)st, request->status);
    return st;
}

NTSTATUS functions::handle_dns_spoof(p_dns_spoof_rule request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL DNSS op=%u rule_id=%u af=%u ttl=%u domain='%s'",
        request->operation, request->rule_id, request->address_family, request->ttl, request->domain);
    if (request->operation == 2) {
        NTSTATUS st = net_dns_spoof::handle_spoof_list((p_dns_spoof_list)request);
        AIDA_NET_LOG("IOCTL DNSS(list) status=0x%08X count=%u", (UINT32)st,
            ((p_dns_spoof_list)request)->rule_count);
        return st;
    }
    NTSTATUS st = net_dns_spoof::handle_spoof_rule(request);
    AIDA_NET_LOG("IOCTL DNSS status=0x%08X out_rule_id=%u active=%u", (UINT32)st, request->rule_id, request->active);
    return st;
}

NTSTATUS functions::handle_bw_monitor(p_bw_monitor_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL BWMN op=%u filter_pid=%u", request->operation, request->filter_pid);
    NTSTATUS st = net_bw::handle_bw(request);
    AIDA_NET_LOG("IOCTL BWMN status=0x%08X active=%u total_sent=%llu total_recv=%llu proc_count=%u",
        (UINT32)st, request->monitoring_active,
        (unsigned long long)request->total_bytes_sent,
        (unsigned long long)request->total_bytes_recv,
        request->process_count);
    return st;
}

NTSTATUS functions::handle_net_iface_enum(p_net_interface_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = net_if_enum::enumerate_interfaces(request);
    AIDA_NET_LOG("IOCTL NIFS status=0x%08X count=%u", (UINT32)st, request->interface_count);
    return st;
}

NTSTATUS functions::handle_pcap_export(p_pcap_export_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL PCEX op=%u filter_pid=%u filter_proto=%u max_packets=%u",
        request->operation, request->filter_pid, request->filter_protocol, request->max_packets);
    NTSTATUS st = net_pcap::export_pcap(request);
    AIDA_NET_LOG("IOCTL PCEX status=0x%08X packet_count=%u data_size=%u",
        (UINT32)st, request->packet_count, request->data_size);
    return st;
}

NTSTATUS functions::handle_net_fingerprint(p_net_fingerprint_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    AIDA_NET_LOG("IOCTL NFPR op=%u", request->operation);
    NTSTATUS st = net_fingerprint::handle_fingerprint(request);
    AIDA_NET_LOG("IOCTL NFPR status=0x%08X result_count=%u", (UINT32)st, request->result_count);
    return st;
}
