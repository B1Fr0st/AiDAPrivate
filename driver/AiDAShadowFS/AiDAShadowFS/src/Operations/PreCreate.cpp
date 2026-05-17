#include "Operations.h"

#include <ntstrsafe.h>

namespace {
    NTSTATUS allocate_stream_context_internal(
        PFLT_FILTER filter,
        PCUNICODE_STRING original,
        PCUNICODE_STRING shadow,
        HANDLE pid,
        ULONG flags,
        PSHADOW_STREAM_CONTEXT* out_ctx)
    {
        if (out_ctx == nullptr) return STATUS_INVALID_PARAMETER;
        *out_ctx = nullptr;

        PSHADOW_STREAM_CONTEXT ctx = nullptr;
        NTSTATUS s = FltAllocateContext(
            filter,
            FLT_STREAMHANDLE_CONTEXT,
            sizeof(SHADOW_STREAM_CONTEXT),
            PagedPool,
            reinterpret_cast<PFLT_CONTEXT*>(&ctx));
        if (!NT_SUCCESS(s) || ctx == nullptr) {
            return s;
        }

        RtlZeroMemory(ctx, sizeof(SHADOW_STREAM_CONTEXT));
        ctx->owner_pid = pid;
        ctx->flags = flags;

        if (original != nullptr && original->Buffer != nullptr && original->Length > 0) {
            PWCHAR buf = static_cast<PWCHAR>(
                ExAllocatePool2(POOL_FLAG_PAGED, original->Length + sizeof(WCHAR), SHADOW_TAG_PATH));
            if (buf != nullptr) {
                RtlCopyMemory(buf, original->Buffer, original->Length);
                buf[original->Length / sizeof(WCHAR)] = L'\0';
                ctx->original_path.Buffer = buf;
                ctx->original_path.Length = original->Length;
                ctx->original_path.MaximumLength = original->Length + sizeof(WCHAR);
            }
        }

        if (shadow != nullptr && shadow->Buffer != nullptr && shadow->Length > 0) {
            PWCHAR buf = static_cast<PWCHAR>(
                ExAllocatePool2(POOL_FLAG_PAGED, shadow->Length + sizeof(WCHAR), SHADOW_TAG_PATH));
            if (buf != nullptr) {
                RtlCopyMemory(buf, shadow->Buffer, shadow->Length);
                buf[shadow->Length / sizeof(WCHAR)] = L'\0';
                ctx->shadow_path.Buffer = buf;
                ctx->shadow_path.Length = shadow->Length;
                ctx->shadow_path.MaximumLength = shadow->Length + sizeof(WCHAR);
                ctx->is_shadow_redirected = 1;
            }
        } else {
            ctx->is_passthrough = 1;
        }

        *out_ctx = ctx;
        return STATUS_SUCCESS;
    }

    void complete_deny(
        PFLT_CALLBACK_DATA data,
        NTSTATUS deny_status,
        HANDLE caller,
        const char* reason,
        PCUNICODE_STRING target)
    {
        data->IoStatus.Status = deny_status;
        data->IoStatus.Information = 0;
        SHADOW_LOG_ERROR_PID(caller, "DENY reason=%s status=0x%08lX path='%wZ'",
            reason ? reason : "?",
            deny_status,
            target);
    }
}

NTSTATUS shadow_create_stream_context_for(
    PFLT_FILTER filter,
    PCUNICODE_STRING original,
    PCUNICODE_STRING shadow,
    HANDLE pid,
    ULONG flags,
    PSHADOW_STREAM_CONTEXT* out_context)
{
    return allocate_stream_context_internal(filter, original, shadow, pid, flags, out_context);
}

NTSTATUS shadow_get_normalized_name(
    PFLT_CALLBACK_DATA data,
    PFLT_FILE_NAME_INFORMATION* out_info)
{
    if (out_info) *out_info = nullptr;
    if (data == nullptr) return STATUS_INVALID_PARAMETER;

    PFLT_FILE_NAME_INFORMATION info = nullptr;
    NTSTATUS s = FltGetFileNameInformation(
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &info);
    if (!NT_SUCCESS(s) || info == nullptr) {
        return s;
    }
    s = FltParseFileNameInformation(info);
    if (!NT_SUCCESS(s)) {
        FltReleaseFileNameInformation(info);
        return s;
    }
    if (out_info) *out_info = info;
    return STATUS_SUCCESS;
}

namespace shadow_ops {

FLT_PREOP_CALLBACK_STATUS FLTAPI pre_create(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    if (CompletionContext) *CompletionContext = nullptr;

    if (Data == nullptr || FltObjects == nullptr) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb == nullptr) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
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

    PFLT_FILE_NAME_INFORMATION name_info = nullptr;
    NTSTATUS ns = shadow_get_normalized_name(Data, &name_info);
    if (!NT_SUCCESS(ns) || name_info == nullptr) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNICODE_STRING target = name_info->Name;

    ACCESS_MASK desired_access = 0;
    if (Data->Iopb->Parameters.Create.SecurityContext != nullptr) {
        desired_access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    ULONG options_raw = Data->Iopb->Parameters.Create.Options;
    ULONG share_access = Data->Iopb->Parameters.Create.ShareAccess;
    ULONG disposition = shadow_extract_create_disposition(options_raw);

    SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
        "PreCreate enter name='%wZ' opts=0x%08lX access=0x%08lX disp=%lu share=0x%08lX",
        &target, options_raw, (unsigned long)desired_access, disposition, share_access);

    if (shadow_is_named_pipe(&target)) {
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "PreCreate pipe pass_through path='%wZ'", &target);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (shadow_is_raw_volume_or_disk(&target)) {
        complete_deny(Data, STATUS_ACCESS_DENIED, caller, "raw_disk", &target);
        shadow_stats_inc_raw_device_denials();
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }

    if (shadow_path_is_volume_root(&target)) {
        if ((options_raw & FILE_OPEN_FOR_BACKUP_INTENT) != 0) {
            complete_deny(Data, STATUS_ACCESS_DENIED, caller, "volume_root_backup_intent", &target);
            shadow_stats_inc_raw_device_denials();
            FltReleaseFileNameInformation(name_info);
            return FLT_PREOP_COMPLETE;
        }
    }

    if (shadow_is_unc_remote(&target) && (sandbox_flags & SHADOWFS_FLAG_BLOCK_REMOTE)) {
        if (shadow_access_is_write(desired_access)
            || shadow_disposition_is_write(disposition)) {
            complete_deny(Data, STATUS_NETWORK_ACCESS_DENIED, caller, "unc_remote_write", &target);
            shadow_stats_inc_unc_denials();
            FltReleaseFileNameInformation(name_info);
            return FLT_PREOP_COMPLETE;
        }
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "PreCreate unc_remote_read pass_through path='%wZ'", &target);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (shadow_is_path_under_root(&target, &root_us)) {
        PSHADOW_STREAM_CONTEXT ctx = nullptr;
        NTSTATUS cs = allocate_stream_context_internal(
            FltObjects->Filter,
            &target,
            nullptr,
            caller,
            sandbox_flags,
            &ctx);
        if (NT_SUCCESS(cs) && ctx != nullptr) {
            ctx->is_passthrough = 1;
            *CompletionContext = ctx;
            SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
                "PreCreate under_sandbox_root pass_through path='%wZ'", &target);
            FltReleaseFileNameInformation(name_info);
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        if (ctx != nullptr) FltReleaseContext(ctx);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    bool is_write = shadow_access_is_write(desired_access)
                 || shadow_disposition_is_write(disposition);

    if ((sandbox_flags & SHADOWFS_FLAG_BLOCK_ALT_STREAMS) != 0
        && shadow_path_has_ads_colon(&target)) {
        complete_deny(Data, STATUS_ACCESS_DENIED, caller, "ads_stream", &target);
        shadow_stats_inc_ads_denials();
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }

    if (is_write && shadow_access_is_executable_mapping(desired_access, options_raw)) {
        complete_deny(Data, STATUS_ACCESS_DENIED, caller, "writable_executable_mapping", &target);
        shadow_stats_inc_mapping_denials();
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }

    if (!is_write) {
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "PreCreate read_only pass_through path='%wZ'", &target);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNICODE_STRING shadow_target = {};
    NTSTATUS bs = shadow_path_build(&root_us, &target, &shadow_target);
    if (!NT_SUCCESS(bs)) {
        complete_deny(Data, STATUS_ACCESS_DENIED, caller, "shadow_path_build_FAILED", &target);
        SHADOW_LOG_ERROR_PID(caller, "shadow_path_build status=0x%08lX path='%wZ'", bs, &target);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }

    NTSTATUS ces = shadow_ensure_parent_directories(&shadow_target);
    if (!NT_SUCCESS(ces)) {
        SHADOW_LOG_WARN_PID(caller, "ensure_parent_directories status=0x%08lX shadow='%wZ'",
            ces, &shadow_target);
    }

    if (shadow_disposition_creates_empty(disposition)) {
        if (disposition == FILE_CREATE) {
            HANDLE chk_h = nullptr;
            PFILE_OBJECT chk_fo = nullptr;
            OBJECT_ATTRIBUTES chk_oa;
            IO_STATUS_BLOCK chk_iosb = {};
            UNICODE_STRING target_us = target;
            InitializeObjectAttributes(&chk_oa,
                &target_us,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                NULL, NULL);
            NTSTATUS chk_s = FltCreateFileEx(
                FltObjects->Filter,
                FltObjects->Instance,
                &chk_h, &chk_fo,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &chk_oa, &chk_iosb,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);
            if (NT_SUCCESS(chk_s)) {
                if (chk_h) FltClose(chk_h);
                if (chk_fo) ObDereferenceObject(chk_fo);
                shadow_path_free(&shadow_target);
                complete_deny(Data, STATUS_OBJECT_NAME_COLLISION, caller,
                    "file_create_original_exists", &target);
                FltReleaseFileNameInformation(name_info);
                return FLT_PREOP_COMPLETE;
            }
        }
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "PreCreate empty_path disp=%lu shadow='%wZ' (FS will create)",
            disposition, &shadow_target);
    } else {
        SHADOW_COPY_RESULT cres = {};
        NTSTATUS cstatus = shadow_copy_original_to_shadow_ex(
            FltObjects->Filter,
            FltObjects->Instance,
            &target,
            &shadow_target,
            true,
            &cres);

        if (shadow_disposition_must_exist(disposition) && cres.original_existed == 0) {
            shadow_path_free(&shadow_target);
            complete_deny(Data, STATUS_OBJECT_NAME_NOT_FOUND, caller, "must_exist_missing", &target);
            FltReleaseFileNameInformation(name_info);
            return FLT_PREOP_COMPLETE;
        }

        if (!NT_SUCCESS(cstatus)
            && cstatus != STATUS_OBJECT_NAME_NOT_FOUND
            && cstatus != STATUS_OBJECT_PATH_NOT_FOUND
            && cstatus != STATUS_NO_SUCH_FILE) {
            if (cstatus == STATUS_SHARING_VIOLATION) {
                shadow_path_free(&shadow_target);
                complete_deny(Data, STATUS_SHARING_VIOLATION, caller, "original_sharing_violation", &target);
                FltReleaseFileNameInformation(name_info);
                return FLT_PREOP_COMPLETE;
            }
            SHADOW_LOG_WARN_PID(caller, "shadow_copy status=0x%08lX original='%wZ' shadow='%wZ'",
                cstatus, &target, &shadow_target);
        }

        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "shadow_copy bytes=%lld orig_existed=%d shadow_created=%d reparse=%d",
            (long long)cres.bytes_copied,
            (int)cres.original_existed,
            (int)cres.shadow_created,
            (int)cres.is_reparse_point);
    }

    PFILE_OBJECT file_object = FltObjects->FileObject;
    if (file_object == nullptr) {
        shadow_path_free(&shadow_target);
        complete_deny(Data, STATUS_ACCESS_DENIED, caller, "no_file_object", &target);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }
    NTSTATUS rs = IoReplaceFileObjectName(
        file_object,
        shadow_target.Buffer,
        shadow_target.Length);
    if (!NT_SUCCESS(rs)) {
        SHADOW_LOG_ERROR_PID(caller,
            "IoReplaceFileObjectName FAILED status=0x%08lX original='%wZ' shadow='%wZ'",
            rs, &target, &shadow_target);
        shadow_path_free(&shadow_target);
        complete_deny(Data, STATUS_ACCESS_DENIED, caller, "replace_filename_FAILED", &target);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }
    FltSetCallbackDataDirty(Data);

    SHADOW_LOG_INFO("[pid=%lu] REDIRECT acc=0x%08lX disp=%lu original='%wZ' -> shadow='%wZ'",
        (unsigned long)(ULONG_PTR)caller,
        (unsigned long)desired_access, disposition, &target, &shadow_target);
    shadow_stats_inc_redirects();

    PSHADOW_STREAM_CONTEXT ctx = nullptr;
    NTSTATUS cs = allocate_stream_context_internal(
        FltObjects->Filter,
        &target,
        &shadow_target,
        caller,
        sandbox_flags,
        &ctx);

    shadow_path_free(&shadow_target);

    if (NT_SUCCESS(cs) && ctx != nullptr) {
        *CompletionContext = ctx;
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    if (ctx != nullptr) FltReleaseContext(ctx);
    FltReleaseFileNameInformation(name_info);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI post_create(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        if (CompletionContext != nullptr) {
            FltReleaseContext(reinterpret_cast<PFLT_CONTEXT>(CompletionContext));
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (CompletionContext == nullptr) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PSHADOW_STREAM_CONTEXT ctx =
        reinterpret_cast<PSHADOW_STREAM_CONTEXT>(CompletionContext);

    if (FltObjects != nullptr && FltObjects->FileObject != nullptr
        && Data != nullptr
        && NT_SUCCESS(Data->IoStatus.Status)) {
        NTSTATUS s = FltSetStreamHandleContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            ctx,
            nullptr);
        if (!NT_SUCCESS(s) && s != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            SHADOW_LOG_WARN("post_create FltSetStreamHandleContext FAILED status=0x%08lX pid=%lu",
                s, (unsigned long)(ULONG_PTR)ctx->owner_pid);
        }
    } else if (Data != nullptr && !NT_SUCCESS(Data->IoStatus.Status)) {
        SHADOW_LOG_VERBOSE_PID(ctx->flags, ctx->owner_pid,
            "post_create irp_failed status=0x%08lX skipping_ctx_attach",
            Data->IoStatus.Status);
    }

    FltReleaseContext(ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

}
