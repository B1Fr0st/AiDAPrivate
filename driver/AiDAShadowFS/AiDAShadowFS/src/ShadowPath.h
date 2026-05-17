#pragma once

#include <fltKernel.h>

typedef struct _SHADOW_COPY_RESULT {
    NTSTATUS status;
    LONG64   bytes_copied;
    UCHAR    original_existed;
    UCHAR    shadow_created;
    UCHAR    is_reparse_point;
    UCHAR    pad0;
} SHADOW_COPY_RESULT;

NTSTATUS shadow_path_init();
void shadow_path_cleanup();

NTSTATUS shadow_path_build(
    _In_ PCUNICODE_STRING sandbox_root,
    _In_ PCUNICODE_STRING original_path,
    _Out_ PUNICODE_STRING shadow_path);

NTSTATUS shadow_path_free(_Inout_ PUNICODE_STRING path);

NTSTATUS shadow_ensure_parent_directories(_In_ PCUNICODE_STRING path);

NTSTATUS shadow_copy_original_to_shadow(
    _In_ PFLT_FILTER filter,
    _In_ PFLT_INSTANCE instance,
    _In_ PCUNICODE_STRING original,
    _In_ PCUNICODE_STRING shadow);

NTSTATUS shadow_copy_original_to_shadow_ex(
    _In_ PFLT_FILTER filter,
    _In_ PFLT_INSTANCE instance,
    _In_ PCUNICODE_STRING original,
    _In_ PCUNICODE_STRING shadow,
    _In_ bool only_if_exists,
    _Out_opt_ SHADOW_COPY_RESULT* out_result);

NTSTATUS shadow_create_empty_shadow(
    _In_ PFLT_FILTER filter,
    _In_ PFLT_INSTANCE instance,
    _In_ PCUNICODE_STRING shadow);

bool shadow_is_path_under_root(
    _In_ PCUNICODE_STRING candidate,
    _In_ PCUNICODE_STRING root);

bool shadow_is_named_pipe(_In_ PCUNICODE_STRING path);
bool shadow_is_unc_remote(_In_ PCUNICODE_STRING path);
bool shadow_is_raw_volume_or_disk(_In_ PCUNICODE_STRING path);

bool shadow_path_has_ads_colon(_In_ PCUNICODE_STRING path);
bool shadow_path_is_volume_root(_In_ PCUNICODE_STRING path);

bool shadow_directory_exists(
    _In_ PFLT_FILTER filter,
    _In_ PFLT_INSTANCE instance,
    _In_ PCUNICODE_STRING path);

bool shadow_path_compute_shadow_dir(
    _In_ PCUNICODE_STRING sandbox_root,
    _In_ PCUNICODE_STRING directory_path,
    _Out_ PUNICODE_STRING out_shadow_dir);
