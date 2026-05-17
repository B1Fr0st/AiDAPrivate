#pragma once

#include <fltKernel.h>

#define SHADOWFS_INSTANCE_FLAGS 0x0

extern PFLT_FILTER g_shadow_filter;
extern PDRIVER_OBJECT g_shadow_driver_object;

extern volatile LONG g_shadow_filter_started;

NTSTATUS FLTAPI shadow_unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS FLTAPI shadow_instance_setup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

NTSTATUS FLTAPI shadow_instance_query_teardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID FLTAPI shadow_instance_teardown_start(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID FLTAPI shadow_instance_teardown_complete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID FLTAPI shadow_stream_context_cleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType);

namespace shadow_ops {
    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_create(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);

    FLT_POSTOP_CALLBACK_STATUS FLTAPI post_create(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_opt_ PVOID CompletionContext,
        _In_ FLT_POST_OPERATION_FLAGS Flags);

    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_write(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);

    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_set_information(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);

    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_cleanup(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);

    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_directory_control(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);

    FLT_POSTOP_CALLBACK_STATUS FLTAPI post_directory_control(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_opt_ PVOID CompletionContext,
        _In_ FLT_POST_OPERATION_FLAGS Flags);

    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_file_system_control(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);

    FLT_PREOP_CALLBACK_STATUS FLTAPI pre_set_volume_information(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext);
}
