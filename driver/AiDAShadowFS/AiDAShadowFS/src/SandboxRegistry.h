#pragma once

#include <fltKernel.h>

#define SHADOWFS_MAX_SANDBOX_PIDS 32
#define SHADOWFS_MAX_ROOT_CHARS   520
#define SHADOWFS_MAX_ROOT_BYTES   (SHADOWFS_MAX_ROOT_CHARS * sizeof(WCHAR))

typedef struct _SHADOW_SANDBOX_ENTRY {
    HANDLE pid;
    ULONG  flags;
    USHORT root_length_bytes;
    USHORT pad0;
    UCHAR  active;
    UCHAR  pad1[3];
    WCHAR  root_buffer[SHADOWFS_MAX_ROOT_CHARS];
} SHADOW_SANDBOX_ENTRY, *PSHADOW_SANDBOX_ENTRY;

typedef struct _SHADOW_DIR_ENUM_STATE {
    UNICODE_STRING shadow_dir_path;
    UNICODE_STRING saved_pattern;
    ULONG          shadow_emit_index;
    UCHAR          shadow_done;
    UCHAR          attempted_open;
    UCHAR          shadow_dir_exists;
    UCHAR          pattern_seen;
    LONG64         total_shadow_emitted;
} SHADOW_DIR_ENUM_STATE, *PSHADOW_DIR_ENUM_STATE;

typedef struct _SHADOW_STREAM_CONTEXT {
    UNICODE_STRING shadow_path;
    UNICODE_STRING original_path;
    HANDLE         owner_pid;
    ULONG          flags;
    UCHAR          is_shadow_redirected;
    UCHAR          is_passthrough;
    UCHAR          is_directory;
    UCHAR          pad0[5];
    SHADOW_DIR_ENUM_STATE enum_state;
} SHADOW_STREAM_CONTEXT, *PSHADOW_STREAM_CONTEXT;

void shadow_registry_init();
void shadow_registry_cleanup();

bool shadow_registry_add(HANDLE pid, ULONG flags, PCUNICODE_STRING sandbox_root);
bool shadow_registry_remove(HANDLE pid);
bool shadow_registry_any_active();
bool shadow_registry_lookup(HANDLE pid, ULONG* out_flags, UNICODE_STRING* out_root);
ULONG shadow_registry_active_count();

void shadow_stats_inc_denials();
void shadow_stats_inc_redirects();
void shadow_stats_inc_copies();
void shadow_stats_add_bytes_copied(LONG64 amount);
void shadow_stats_inc_fsctl_denials();
void shadow_stats_inc_ads_denials();
void shadow_stats_inc_mapping_denials();
void shadow_stats_inc_unc_denials();
void shadow_stats_inc_raw_device_denials();
void shadow_stats_inc_set_info_denials();
void shadow_stats_inc_dir_merge_emits();

LONG64 shadow_stats_denials();
LONG64 shadow_stats_redirects();
LONG64 shadow_stats_copies();
LONG64 shadow_stats_bytes_copied();
LONG64 shadow_stats_fsctl_denials();
LONG64 shadow_stats_ads_denials();
LONG64 shadow_stats_mapping_denials();
LONG64 shadow_stats_unc_denials();
LONG64 shadow_stats_raw_device_denials();
LONG64 shadow_stats_set_info_denials();
LONG64 shadow_stats_dir_merge_emits();
