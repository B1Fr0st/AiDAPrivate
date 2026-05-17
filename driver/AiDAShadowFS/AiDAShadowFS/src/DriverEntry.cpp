#include <fltKernel.h>
#include <ntstrsafe.h>

#include "MinifilterContext.h"
#include "SandboxRegistry.h"
#include "ShadowPath.h"
#include "Comms.h"
#include "Logging.h"

PFLT_FILTER g_shadow_filter = nullptr;
PDRIVER_OBJECT g_shadow_driver_object = nullptr;
volatile LONG g_shadow_filter_started = 0;

NTSTATUS FLTAPI shadow_unload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS FLTAPI shadow_instance_setup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS FLTAPI shadow_instance_query_teardown(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
VOID FLTAPI shadow_instance_teardown_start(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS Flags);
VOID FLTAPI shadow_instance_teardown_complete(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS Flags);
VOID FLTAPI shadow_stream_context_cleanup(
    PFLT_CONTEXT Context,
    FLT_CONTEXT_TYPE ContextType);

namespace {
    const FLT_OPERATION_REGISTRATION k_callbacks[] = {
        { IRP_MJ_CREATE,                   0, shadow_ops::pre_create,                 shadow_ops::post_create },
        { IRP_MJ_WRITE,                    0, shadow_ops::pre_write,                  nullptr },
        { IRP_MJ_SET_INFORMATION,          0, shadow_ops::pre_set_information,        nullptr },
        { IRP_MJ_SET_VOLUME_INFORMATION,   0, shadow_ops::pre_set_volume_information, nullptr },
        { IRP_MJ_CLEANUP,                  0, shadow_ops::pre_cleanup,                nullptr },
        { IRP_MJ_DIRECTORY_CONTROL,        0, shadow_ops::pre_directory_control,      shadow_ops::post_directory_control },
        { IRP_MJ_FILE_SYSTEM_CONTROL,      0, shadow_ops::pre_file_system_control,    nullptr },
        { IRP_MJ_OPERATION_END }
    };

    const FLT_CONTEXT_REGISTRATION k_contexts[] = {
        { FLT_STREAMHANDLE_CONTEXT,
          0,
          shadow_stream_context_cleanup,
          sizeof(SHADOW_STREAM_CONTEXT),
          SHADOW_TAG_CTX,
          nullptr, nullptr, nullptr },
        { FLT_CONTEXT_END }
    };

    const FLT_REGISTRATION k_registration = {
        sizeof(FLT_REGISTRATION),
        FLT_REGISTRATION_VERSION,
        0,
        k_contexts,
        k_callbacks,
        shadow_unload,
        shadow_instance_setup,
        shadow_instance_query_teardown,
        shadow_instance_teardown_start,
        shadow_instance_teardown_complete,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    };
}

VOID FLTAPI shadow_stream_context_cleanup(
    PFLT_CONTEXT Context,
    FLT_CONTEXT_TYPE ContextType)
{
    UNREFERENCED_PARAMETER(ContextType);
    if (Context == nullptr) return;
    PSHADOW_STREAM_CONTEXT ctx = reinterpret_cast<PSHADOW_STREAM_CONTEXT>(Context);
    SHADOW_LOG_VERBOSE_PID(ctx->flags, ctx->owner_pid,
        "stream_context_cleanup shadow=%d passthrough=%d directory=%d total_shadow=%lld",
        (int)ctx->is_shadow_redirected,
        (int)ctx->is_passthrough,
        (int)ctx->is_directory,
        (long long)ctx->enum_state.total_shadow_emitted);
    if (ctx->shadow_path.Buffer != nullptr) {
        ExFreePoolWithTag(ctx->shadow_path.Buffer, SHADOW_TAG_PATH);
        ctx->shadow_path.Buffer = nullptr;
        ctx->shadow_path.Length = 0;
        ctx->shadow_path.MaximumLength = 0;
    }
    if (ctx->original_path.Buffer != nullptr) {
        ExFreePoolWithTag(ctx->original_path.Buffer, SHADOW_TAG_PATH);
        ctx->original_path.Buffer = nullptr;
        ctx->original_path.Length = 0;
        ctx->original_path.MaximumLength = 0;
    }
    if (ctx->enum_state.shadow_dir_path.Buffer != nullptr) {
        ExFreePoolWithTag(ctx->enum_state.shadow_dir_path.Buffer, SHADOW_TAG_PATH);
        ctx->enum_state.shadow_dir_path.Buffer = nullptr;
        ctx->enum_state.shadow_dir_path.Length = 0;
        ctx->enum_state.shadow_dir_path.MaximumLength = 0;
    }
    if (ctx->enum_state.saved_pattern.Buffer != nullptr) {
        ExFreePoolWithTag(ctx->enum_state.saved_pattern.Buffer, SHADOW_TAG_PATH);
        ctx->enum_state.saved_pattern.Buffer = nullptr;
        ctx->enum_state.saved_pattern.Length = 0;
        ctx->enum_state.saved_pattern.MaximumLength = 0;
    }
}

NTSTATUS FLTAPI shadow_instance_setup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    switch (VolumeFilesystemType) {
        case FLT_FSTYPE_NTFS:
        case FLT_FSTYPE_REFS:
        case FLT_FSTYPE_FAT:
        case FLT_FSTYPE_EXFAT:
        case FLT_FSTYPE_RAW:
            SHADOW_LOG_INFO("instance_setup attach fs_type=%d", (int)VolumeFilesystemType);
            return STATUS_SUCCESS;
        default:
            SHADOW_LOG_INFO("instance_setup DO_NOT_ATTACH fs_type=%d", (int)VolumeFilesystemType);
            return STATUS_FLT_DO_NOT_ATTACH;
    }
}

NTSTATUS FLTAPI shadow_instance_query_teardown(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    SHADOW_LOG_INFO("instance_query_teardown");
    return STATUS_SUCCESS;
}

VOID FLTAPI shadow_instance_teardown_start(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    SHADOW_LOG_INFO("instance_teardown_start");
}

VOID FLTAPI shadow_instance_teardown_complete(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    SHADOW_LOG_INFO("instance_teardown_complete");
}

NTSTATUS FLTAPI shadow_unload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    SHADOW_LOG_INFO("shadow_unload begin");

    shadow_comms_cleanup();

    if (g_shadow_filter != nullptr) {
        FltUnregisterFilter(g_shadow_filter);
        g_shadow_filter = nullptr;
        SHADOW_LOG_INFO("shadow_unload FltUnregisterFilter done");
    }

    shadow_path_cleanup();
    shadow_registry_cleanup();

    InterlockedExchange(&g_shadow_filter_started, 0);
    SHADOW_LOG_INFO("shadow_unload complete");
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    g_shadow_driver_object = DriverObject;

    SHADOW_LOG_INFO("DriverEntry begin DriverObject=%p RegistryPath='%wZ'",
        DriverObject, RegistryPath);

    shadow_registry_init();

    NTSTATUS s = shadow_path_init();
    if (!NT_SUCCESS(s)) {
        SHADOW_LOG_ERROR("DriverEntry shadow_path_init FAILED status=0x%08lX", s);
        shadow_registry_cleanup();
        return s;
    }
    SHADOW_LOG_INFO("DriverEntry shadow_path_init ok");

    s = FltRegisterFilter(DriverObject, &k_registration, &g_shadow_filter);
    if (!NT_SUCCESS(s) || g_shadow_filter == nullptr) {
        SHADOW_LOG_ERROR("DriverEntry FltRegisterFilter FAILED status=0x%08lX filter=%p",
            s, g_shadow_filter);
        shadow_path_cleanup();
        shadow_registry_cleanup();
        return s;
    }
    SHADOW_LOG_INFO("DriverEntry FltRegisterFilter ok filter=%p", g_shadow_filter);

    s = shadow_comms_init(g_shadow_filter);
    if (!NT_SUCCESS(s)) {
        SHADOW_LOG_ERROR("DriverEntry shadow_comms_init FAILED status=0x%08lX", s);
        FltUnregisterFilter(g_shadow_filter);
        g_shadow_filter = nullptr;
        shadow_path_cleanup();
        shadow_registry_cleanup();
        return s;
    }
    SHADOW_LOG_INFO("DriverEntry shadow_comms_init ok");

    s = FltStartFiltering(g_shadow_filter);
    if (!NT_SUCCESS(s)) {
        SHADOW_LOG_ERROR("DriverEntry FltStartFiltering FAILED status=0x%08lX", s);
        shadow_comms_cleanup();
        FltUnregisterFilter(g_shadow_filter);
        g_shadow_filter = nullptr;
        shadow_path_cleanup();
        shadow_registry_cleanup();
        return s;
    }

    InterlockedExchange(&g_shadow_filter_started, 1);
    SHADOW_LOG_INFO("DriverEntry ok filter=%p port='%ws' protocol=0x%08lX",
        g_shadow_filter, L"\\AiDAShadowFSPort", 0x00010002ul);
    return STATUS_SUCCESS;
}
