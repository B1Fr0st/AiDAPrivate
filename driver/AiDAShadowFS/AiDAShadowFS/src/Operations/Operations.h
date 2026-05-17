#pragma once

#include <fltKernel.h>

#include "../SandboxRegistry.h"
#include "../ShadowPath.h"
#include "../MinifilterContext.h"
#include "../Logging.h"
#include "../ShadowFSProtocol.h"

#define SHADOWFS_WRITE_ACCESS_MASK \
    (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA \
     | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER \
     | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)

__forceinline ULONG shadow_extract_create_disposition(ULONG options_raw) {
    return (options_raw >> 24) & 0xFFul;
}

__forceinline bool shadow_disposition_is_write(ULONG disp) {
    switch (disp) {
        case FILE_CREATE:
        case FILE_SUPERSEDE:
        case FILE_OVERWRITE:
        case FILE_OVERWRITE_IF:
        case FILE_OPEN_IF:
            return true;
        default:
            return false;
    }
}

__forceinline bool shadow_disposition_must_exist(ULONG disp) {
    switch (disp) {
        case FILE_OPEN:
        case FILE_OVERWRITE:
            return true;
        default:
            return false;
    }
}

__forceinline bool shadow_disposition_creates_empty(ULONG disp) {
    switch (disp) {
        case FILE_CREATE:
        case FILE_SUPERSEDE:
            return true;
        default:
            return false;
    }
}

__forceinline bool shadow_access_is_write(ACCESS_MASK access) {
    return (access & SHADOWFS_WRITE_ACCESS_MASK) != 0;
}

__forceinline bool shadow_access_is_executable_mapping(ACCESS_MASK access, ULONG options) {
    UNREFERENCED_PARAMETER(options);
    if ((access & FILE_EXECUTE) != 0 && (access & SHADOWFS_WRITE_ACCESS_MASK) != 0) {
        return true;
    }
    return false;
}

NTSTATUS shadow_create_stream_context_for(
    _In_ PFLT_FILTER filter,
    _In_ PCUNICODE_STRING original,
    _In_opt_ PCUNICODE_STRING shadow,
    _In_ HANDLE pid,
    _In_ ULONG flags,
    _Out_ PSHADOW_STREAM_CONTEXT* out_context);

NTSTATUS shadow_get_normalized_name(
    _In_ PFLT_CALLBACK_DATA data,
    _Outptr_ PFLT_FILE_NAME_INFORMATION* out_info);

namespace shadow_ops {
    FLT_POSTOP_CALLBACK_STATUS FLTAPI post_directory_control(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_opt_ PVOID CompletionContext,
        _In_ FLT_POST_OPERATION_FLAGS Flags);

    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_file_system_control(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);
}
