#pragma once

#include <fltKernel.h>

#include "../SandboxRegistry.h"
#include "../ShadowPath.h"

bool dir_info_class_is_supported(FILE_INFORMATION_CLASS fic);

bool dir_info_extract_name(
    _In_ FILE_INFORMATION_CLASS fic,
    _In_reads_bytes_(remaining) const UCHAR* entry,
    _In_ ULONG remaining,
    _Out_ ULONG* next_entry_offset,
    _Out_ const WCHAR** name_buf,
    _Out_ ULONG* name_length_bytes,
    _Out_ ULONG* entry_record_bytes);

NTSTATUS dir_merge_synthesize(
    _In_ PFLT_FILTER filter,
    _In_ PFLT_INSTANCE instance,
    _In_ PSHADOW_STREAM_CONTEXT ctx,
    _In_ FILE_INFORMATION_CLASS fic,
    _In_ ULONG sl_flags,
    _In_opt_ PCUNICODE_STRING file_pattern,
    _Inout_ UCHAR* user_buffer,
    _In_ ULONG user_buffer_capacity,
    _Inout_ PULONG bytes_already_in_user_buffer);

void dir_merge_state_reset(_Inout_ PSHADOW_DIR_ENUM_STATE state);
