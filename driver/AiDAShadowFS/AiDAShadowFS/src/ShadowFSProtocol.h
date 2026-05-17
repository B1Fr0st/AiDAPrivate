#pragma once

#define SHADOWFS_PORT_NAME              L"\\AiDAShadowFSPort"
#define SHADOWFS_PORT_NAME_NARROW       "\\AiDAShadowFSPort"

#define SHADOWFS_PROTOCOL_VERSION       0x00010002ul
#define SHADOWFS_PROTOCOL_VERSION_LEGACY 0x00010001ul
#define SHADOWFS_MSG_MAGIC              0x5346534Aul

#define SHADOWFS_MAX_PATH_CHARS         520
#define SHADOWFS_MAX_PATH_BYTES         (SHADOWFS_MAX_PATH_CHARS * sizeof(WCHAR))

#define SHADOWFS_MSG_REGISTER_PID       1ul
#define SHADOWFS_MSG_UNREGISTER_PID     2ul
#define SHADOWFS_MSG_PING               3ul
#define SHADOWFS_MSG_QUERY_STATS        4ul

#define SHADOWFS_FLAG_DEFAULT           0x00000000ul
#define SHADOWFS_FLAG_BLOCK_REMOTE      0x00000001ul
#define SHADOWFS_FLAG_BLOCK_RAW_DEVICE  0x00000002ul
#define SHADOWFS_FLAG_BLOCK_DESTRUCTIVE 0x00000004ul
#define SHADOWFS_FLAG_LOG_VERBOSE       0x00000008ul
#define SHADOWFS_FLAG_BLOCK_FSCTL       0x00000010ul
#define SHADOWFS_FLAG_BLOCK_ALT_STREAMS 0x00000020ul

#define SHADOWFS_DEFAULT_FLAGS \
    (SHADOWFS_FLAG_BLOCK_REMOTE \
     | SHADOWFS_FLAG_BLOCK_RAW_DEVICE \
     | SHADOWFS_FLAG_BLOCK_DESTRUCTIVE \
     | SHADOWFS_FLAG_BLOCK_FSCTL \
     | SHADOWFS_FLAG_BLOCK_ALT_STREAMS)

#pragma pack(push, 1)

typedef struct _SHADOWFS_MSG_HEADER {
    unsigned long magic;
    unsigned long version;
    unsigned long command;
    unsigned long payload_bytes;
} SHADOWFS_MSG_HEADER;

typedef struct _SHADOWFS_MSG_REGISTER {
    SHADOWFS_MSG_HEADER header;
    unsigned long pid;
    unsigned long flags;
    unsigned long sandbox_root_chars;
    WCHAR sandbox_root[SHADOWFS_MAX_PATH_CHARS];
} SHADOWFS_MSG_REGISTER;

typedef struct _SHADOWFS_MSG_UNREGISTER {
    SHADOWFS_MSG_HEADER header;
    unsigned long pid;
    unsigned long reserved;
} SHADOWFS_MSG_UNREGISTER;

typedef struct _SHADOWFS_MSG_PING_REQ {
    SHADOWFS_MSG_HEADER header;
    unsigned long client_token;
    unsigned long reserved;
} SHADOWFS_MSG_PING_REQ;

typedef struct _SHADOWFS_REPLY_GENERIC_V1 {
    unsigned long magic;
    unsigned long version;
    unsigned long status;
    unsigned long pid_count;
    long long denials;
    long long redirects;
    long long copies;
} SHADOWFS_REPLY_GENERIC_V1;

typedef struct _SHADOWFS_REPLY_GENERIC {
    unsigned long magic;
    unsigned long version;
    unsigned long status;
    unsigned long pid_count;
    long long denials;
    long long redirects;
    long long copies;
    long long bytes_copied;
    long long fsctl_denials;
    long long ads_denials;
    long long mapping_denials;
    long long unc_denials;
    long long raw_device_denials;
    long long set_info_denials;
    long long dir_merge_emits;
    long long reserved0;
} SHADOWFS_REPLY_GENERIC;

typedef struct _SHADOWFS_MSG_QUERY_STATS_T {
    SHADOWFS_MSG_HEADER header;
    unsigned long reserved0;
    unsigned long reserved1;
} SHADOWFS_MSG_QUERY_STATS_T;

#pragma pack(pop)
