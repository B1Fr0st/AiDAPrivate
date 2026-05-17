#include "Operations.h"

namespace shadow_ops {

FLT_PREOP_CALLBACK_STATUS FLTAPI pre_write(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    if (CompletionContext) *CompletionContext = nullptr;

    if (Data == nullptr || FltObjects == nullptr) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!shadow_registry_any_active()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE caller = PsGetCurrentProcessId();
    ULONG sandbox_flags = 0;
    WCHAR root_buf[SHADOWFS_MAX_ROOT_CHARS];
    UNICODE_STRING root_us;
    root_us.Buffer = root_buf;
    root_us.Length = 0;
    root_us.MaximumLength = sizeof(root_buf);
    if (!shadow_registry_lookup(caller, &sandbox_flags, &root_us)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PSHADOW_STREAM_CONTEXT ctx = nullptr;
    NTSTATUS cs = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        reinterpret_cast<PFLT_CONTEXT*>(&ctx));
    if (NT_SUCCESS(cs) && ctx != nullptr) {
        bool allowed = (ctx->is_shadow_redirected != 0) || (ctx->is_passthrough != 0);
        ULONG length = Data->Iopb->Parameters.Write.Length;
        SHADOW_LOG_VERBOSE_PID(ctx->flags, caller,
            "PreWrite ctx_hit allowed=%d shadow=%d passthrough=%d length=%lu",
            (int)allowed,
            (int)ctx->is_shadow_redirected,
            (int)ctx->is_passthrough,
            length);
        FltReleaseContext(ctx);
        if (allowed) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    PFLT_FILE_NAME_INFORMATION name_info = nullptr;
    NTSTATUS ns = shadow_get_normalized_name(Data, &name_info);
    if (!NT_SUCCESS(ns) || name_info == nullptr) {
        Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
        Data->IoStatus.Information = 0;
        shadow_stats_inc_denials();
        SHADOW_LOG_ERROR_PID(caller, "PreWrite DENY no_name_info length=%lu",
            (unsigned long)Data->Iopb->Parameters.Write.Length);
        return FLT_PREOP_COMPLETE;
    }

    UNICODE_STRING target = name_info->Name;

    if (shadow_is_named_pipe(&target)
        || shadow_is_path_under_root(&target, &root_us)) {
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "PreWrite pass_through path='%wZ' length=%lu",
            &target,
            (unsigned long)Data->Iopb->Parameters.Write.Length);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOW_LOG_ERROR_PID(caller,
        "PreWrite DENY raw_write_unmediated path='%wZ' length=%lu",
        &target, (unsigned long)Data->Iopb->Parameters.Write.Length);
    shadow_stats_inc_denials();

    Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
    Data->IoStatus.Information = 0;
    FltReleaseFileNameInformation(name_info);
    return FLT_PREOP_COMPLETE;
}

}
