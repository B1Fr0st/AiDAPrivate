#include "Operations.h"

namespace {
    bool info_class_is_destructive(FILE_INFORMATION_CLASS fic) {
        switch (fic) {
            case FileDispositionInformation:
            case FileDispositionInformationEx:
            case FileRenameInformation:
            case FileRenameInformationEx:
            case FileRenameInformationBypassAccessCheck:
            case FileLinkInformation:
            case FileLinkInformationEx:
            case FileLinkInformationBypassAccessCheck:
            case FileShortNameInformation:
            case FileBasicInformation:
            case FileEndOfFileInformation:
            case FileAllocationInformation:
            case FileValidDataLengthInformation:
                return true;
            default:
                return false;
        }
    }

    bool extract_rename_target(
        FILE_INFORMATION_CLASS fic,
        const UCHAR* buffer,
        ULONG length,
        UNICODE_STRING* out_target)
    {
        if (out_target == nullptr) return false;
        out_target->Buffer = nullptr;
        out_target->Length = 0;
        out_target->MaximumLength = 0;
        if (buffer == nullptr || length == 0) return false;
        ULONG name_offset = 0;
        ULONG name_length_offset = 0;
        switch (fic) {
            case FileRenameInformation:
            case FileRenameInformationEx:
            case FileRenameInformationBypassAccessCheck:
                name_length_offset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileNameLength);
                name_offset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
                break;
            case FileLinkInformation:
            case FileLinkInformationEx:
            case FileLinkInformationBypassAccessCheck:
                name_length_offset = FIELD_OFFSET(FILE_LINK_INFORMATION, FileNameLength);
                name_offset = FIELD_OFFSET(FILE_LINK_INFORMATION, FileName);
                break;
            default:
                return false;
        }
        if (length < name_length_offset + sizeof(ULONG)) return false;
        ULONG nlen = *reinterpret_cast<const ULONG*>(buffer + name_length_offset);
        if (nlen == 0) return false;
        if (length < name_offset + nlen) return false;
        out_target->Buffer = const_cast<PWCHAR>(reinterpret_cast<const WCHAR*>(buffer + name_offset));
        out_target->Length = static_cast<USHORT>(nlen);
        out_target->MaximumLength = static_cast<USHORT>(nlen);
        return true;
    }

    bool path_starts_with_literal_i(PCUNICODE_STRING path, const WCHAR* literal) {
        if (path == nullptr || path->Buffer == nullptr || literal == nullptr) return false;
        ULONG chars = path->Length / sizeof(WCHAR);
        ULONG i = 0;
        while (literal[i] != L'\0') {
            if (i >= chars) return false;
            WCHAR a = path->Buffer[i];
            WCHAR b = literal[i];
            if (a >= L'A' && a <= L'Z') a = static_cast<WCHAR>(a - L'A' + L'a');
            if (b >= L'A' && b <= L'Z') b = static_cast<WCHAR>(b - L'A' + L'a');
            if (a != b) return false;
            ++i;
        }
        return true;
    }
}

namespace shadow_ops {

FLT_PREOP_CALLBACK_STATUS FLTAPI pre_set_information(
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

    FILE_INFORMATION_CLASS fic = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
        "PreSetInformation enter class=%d length=%lu",
        (int)fic,
        (unsigned long)Data->Iopb->Parameters.SetFileInformation.Length);

    if (!info_class_is_destructive(fic)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PSHADOW_STREAM_CONTEXT ctx = nullptr;
    NTSTATUS cs = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        reinterpret_cast<PFLT_CONTEXT*>(&ctx));
    if (NT_SUCCESS(cs) && ctx != nullptr) {
        bool allowed = (ctx->is_shadow_redirected != 0) || (ctx->is_passthrough != 0);
        SHADOW_LOG_VERBOSE_PID(ctx->flags, caller,
            "PreSetInformation ctx_hit allowed=%d shadow=%d passthrough=%d",
            (int)allowed,
            (int)ctx->is_shadow_redirected,
            (int)ctx->is_passthrough);
        FltReleaseContext(ctx);
        if (allowed) {
            if ((fic == FileRenameInformation || fic == FileRenameInformationEx
                 || fic == FileRenameInformationBypassAccessCheck
                 || fic == FileLinkInformation || fic == FileLinkInformationEx
                 || fic == FileLinkInformationBypassAccessCheck)) {
                UNICODE_STRING rt = {};
                if (extract_rename_target(
                        fic,
                        reinterpret_cast<const UCHAR*>(Data->Iopb->Parameters.SetFileInformation.InfoBuffer),
                        Data->Iopb->Parameters.SetFileInformation.Length,
                        &rt)) {
                    if (path_starts_with_literal_i(&rt, L"\\Device\\Mup\\")
                        || path_starts_with_literal_i(&rt, L"\\??\\UNC\\")
                        || path_starts_with_literal_i(&rt, L"\\Device\\LanmanRedirector\\")) {
                        SHADOW_LOG_ERROR_PID(caller,
                            "PreSetInformation DENY rename_target_unc target='%wZ'", &rt);
                        Data->IoStatus.Status = STATUS_NETWORK_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        shadow_stats_inc_unc_denials();
                        shadow_stats_inc_set_info_denials();
                        return FLT_PREOP_COMPLETE;
                    }
                }
            }
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    PFLT_FILE_NAME_INFORMATION name_info = nullptr;
    NTSTATUS ns = shadow_get_normalized_name(Data, &name_info);
    if (!NT_SUCCESS(ns) || name_info == nullptr) {
        SHADOW_LOG_ERROR_PID(caller, "PreSetInformation DENY no_name_info class=%d", (int)fic);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        shadow_stats_inc_set_info_denials();
        return FLT_PREOP_COMPLETE;
    }

    UNICODE_STRING target = name_info->Name;

    if (shadow_is_path_under_root(&target, &root_us)
        || shadow_is_named_pipe(&target)) {
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "PreSetInformation pass_through path='%wZ' class=%d", &target, (int)fic);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!(sandbox_flags & SHADOWFS_FLAG_BLOCK_DESTRUCTIVE)) {
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "PreSetInformation non_destructive_pass class=%d path='%wZ'", (int)fic, &target);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SHADOW_LOG_ERROR_PID(caller, "PreSetInformation DENY class=%d path='%wZ'", (int)fic, &target);
    shadow_stats_inc_set_info_denials();

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    FltReleaseFileNameInformation(name_info);
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI pre_set_volume_information(
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

    if ((sandbox_flags & SHADOWFS_FLAG_BLOCK_DESTRUCTIVE) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FS_INFORMATION_CLASS fsic = Data->Iopb->Parameters.SetVolumeInformation.FsInformationClass;
    SHADOW_LOG_ERROR_PID(caller, "PreSetVolumeInformation DENY fsic=%d", (int)fsic);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    shadow_stats_inc_set_info_denials();
    return FLT_PREOP_COMPLETE;
}

}
