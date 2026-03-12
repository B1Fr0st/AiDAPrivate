#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"

// =====================================================================
// WFP (Windows Filtering Platform) type definitions
// Defined manually to avoid header dependencies and static imports.
// All WFP functions are resolved dynamically from fwpkclnt.sys.
// =====================================================================

// WFP data types
typedef UINT16 FWP_IP_VERSION_;
typedef UINT8  FWP_DIRECTION_;
typedef UINT32 FWP_ACTION_TYPE_;

#define FWP_ACTION_PERMIT_  0x00001001
#define FWP_ACTION_BLOCK_   0x00002001
#define FWP_ACTION_CONTINUE_ 0x00003001

#define FWP_CONDITION_FLAG_IS_LOOPBACK_ 0x00000001

// FWP_VALUE0 simplified (we only read uint8/uint16/uint32)
typedef struct _FWP_VALUE0_COMPAT {
    UINT32 type;
    union {
        UINT8   uint8;
        UINT16  uint16;
        UINT32  uint32;
        UINT64  uint64;
        INT8    int8;
        INT16   int16;
        INT32   int32;
        INT64   int64;
        float   float32;
        double  double64;
        PVOID   byteArray16;
        PVOID   byteBlob;
        PVOID   sid;
        PVOID   byteArray6;
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
        UINT64 uint64;
    };
} FWP_CONDITION_VALUE0_COMPAT;

typedef struct _FWPM_FILTER_CONDITION0_COMPAT {
    GUID   fieldKey;
    UINT32 matchType;
    FWP_CONDITION_VALUE0_COMPAT conditionValue;
} FWPM_FILTER_CONDITION0_COMPAT;

typedef struct _FWPM_FILTER0_COMPAT {
    GUID   filterKey;
    FWPM_DISPLAY_DATA0* displayData;
    UINT32 flags;
    GUID*  providerKey;
    FWP_BYTE_BLOB_COMPAT providerData;
    GUID   layerKey;
    GUID   subLayerKey;
    FWP_VALUE0_COMPAT weight;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0_COMPAT* filterCondition;
    FWP_ACTION_TYPE_ action_type;
    union {
        GUID   filterType;
        GUID   calloutKey;
    } action;
    union {
        UINT64 rawContext;
        GUID   providerContextKey;
    } context;
    GUID*  reserved;
    UINT64 filterId;
    FWP_VALUE0_COMPAT effectiveWeight;
} FWPM_FILTER0_COMPAT;

typedef struct _FWPM_DISPLAY_DATA0 {
    wchar_t* name;
    wchar_t* description;
} FWPM_DISPLAY_DATA0;

typedef struct _FWPM_CALLOUT0_COMPAT {
    GUID   calloutKey;
    FWPM_DISPLAY_DATA0* displayData;
    UINT32 flags;
    GUID*  providerKey;
    FWP_BYTE_BLOB_COMPAT providerData;
    GUID   applicableLayer;
    UINT32 calloutId;
} FWPM_CALLOUT0_COMPAT;

typedef struct _FWPM_SUBLAYER0_COMPAT {
    GUID   subLayerKey;
    FWPM_DISPLAY_DATA0* displayData;
    UINT32 flags;
    GUID*  providerKey;
    FWP_BYTE_BLOB_COMPAT providerData;
    UINT16 weight;
} FWPM_SUBLAYER0_COMPAT;

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
        if (!g_capture_active && g_active_rule_count == 0) return;

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
        if (!g_capture_active && g_active_rule_count == 0) return;

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
        PVOID fwp_base = find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) {
            // Try lowercase
            fwp_base = find_module_base("fwpkclnt.sys");
        }
        if (!fwp_base) return FALSE;

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

        return (_FwpsCalloutRegister2 && _FwpsCalloutUnregisterById0 &&
                _FwpmEngineOpen0 && _FwpmEngineClose0 &&
                _FwpmTransactionBegin0 && _FwpmTransactionCommit0 &&
                _FwpmCalloutAdd0 && _FwpmSubLayerAdd0 && _FwpmFilterAdd0);
    }

    // ================================================================
    // WFP registration / unregistration
    // ================================================================

    NTSTATUS register_wfp(PDEVICE_OBJECT devObj) {
        if (!devObj) return STATUS_INVALID_PARAMETER;
        g_device_object = devObj;

        NTSTATUS status;

        // Open BFE engine
        status = _FwpmEngineOpen0(nullptr, 0x0000000A /*RPC_C_AUTHN_WINNT*/,
            nullptr, nullptr, &g_engine_handle);
        if (!NT_SUCCESS(status)) return status;

        // Begin transaction
        status = _FwpmTransactionBegin0(g_engine_handle, 0);
        if (!NT_SUCCESS(status)) {
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
        sublayer.displayData = &sublayer_display;
        sublayer.flags = 0;
        sublayer.weight = 0xFFFF;

        status = _FwpmSubLayerAdd0(g_engine_handle, &sublayer, nullptr);
        if (!NT_SUCCESS(status)) {
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
        fwpm_callout_in.displayData = &callout_display;
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
        fwpm_callout_out.displayData = &callout_display;
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

        // Add filters
        FWPM_DISPLAY_DATA0 filter_display = {};
        wchar_t fi_name[] = L"AiDANetFilter";
        wchar_t fi_desc[] = L"AiDA Network Monitor Filter";
        filter_display.name = fi_name;
        filter_display.description = fi_desc;

        FWPM_FILTER0_COMPAT filter_in = {};
        strong::kmemset(&filter_in, 0, sizeof(filter_in));
        filter_in.displayData = &filter_display;
        filter_in.layerKey = GUID_LAYER_INBOUND_V4;
        filter_in.subLayerKey = GUID_AIDA_SUBLAYER;
        filter_in.weight.type = 8; // FWP_UINT64
        UINT64 weight_val = 0xFFFFFFFFFFFFFFFF;
        filter_in.weight.uint64 = weight_val;
        filter_in.action_type = 0x00005003; // FWP_ACTION_CALLOUT_INSPECTION
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
        filter_out.displayData = &filter_display;
        filter_out.layerKey = GUID_LAYER_OUTBOUND_V4;
        filter_out.subLayerKey = GUID_AIDA_SUBLAYER;
        filter_out.weight.type = 8;
        filter_out.weight.uint64 = weight_val;
        filter_out.action_type = 0x00005003;
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

        // Commit transaction
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
            // WFP not available - buffers still allocated for manual population
            KeMemoryBarrier();
            _InterlockedExchange(&g_wfp_initialized, 2);
            return STATUS_SUCCESS;
        }

        // Register WFP callouts
        NTSTATUS status = register_wfp(devObj);
        if (!NT_SUCCESS(status)) {
            // WFP registration failed but ring buffers available
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_wfp_initialized, 2);
        return STATUS_SUCCESS;
    }

    void cleanup() {
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

    if (net_capture::g_wfp_initialized != 2) {
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

                if (c->displayData && _MmIsAddressValid(c->displayData)) {
                    // displayData->name often contains the driver/callout name
                    __try {
                        wchar_t* wname = c->displayData->name;
                        if (wname && _MmIsAddressValid(wname)) {
                            // Convert wide to ASCII for module name
                            for (int j = 0; j < 63 && wname[j]; j++) {
                                out->owning_module[j] = (char)(wname[j] & 0x7F);
                            }
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }

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
// IOCTL handler wrappers for the 4 advanced network recon tools
// =====================================================================

NTSTATUS functions::handle_wfp_callout_enum(p_wfp_callout_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_wfp_enum::enumerate_wfp_callouts(request);
}

NTSTATUS functions::handle_socket_handle_enum(p_socket_handle_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_socket_enum::enumerate_socket_handles(request);
}

NTSTATUS functions::handle_sniff_net_buffers(p_sniff_net_buffers request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_sniff::handle_sniff(request);
}

NTSTATUS functions::handle_tcpip_conn_dump(p_tcpip_conn_dump request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    return net_tcpip::dump_connections(request);
}
