#include "Operations.h"

namespace {

bool fsctl_is_destructive(ULONG code) {
    switch (code) {
        case FSCTL_SET_REPARSE_POINT:
        case FSCTL_SET_REPARSE_POINT_EX:
        case FSCTL_DELETE_REPARSE_POINT:
        case FSCTL_SET_OBJECT_ID:
        case FSCTL_DELETE_OBJECT_ID:
        case FSCTL_SET_OBJECT_ID_EXTENDED:
        case FSCTL_CREATE_OR_GET_OBJECT_ID:
        case FSCTL_SET_SPARSE:
        case FSCTL_SET_ZERO_DATA:
        case FSCTL_SET_ENCRYPTION:
        case FSCTL_ENCRYPTION_FSCTL_IO:
        case FSCTL_WRITE_RAW_ENCRYPTED:
        case FSCTL_SET_COMPRESSION:
        case FSCTL_SET_DEFECT_MANAGEMENT:
        case FSCTL_SET_SHORT_NAME_BEHAVIOR:
        case FSCTL_DELETE_USN_JOURNAL:
        case FSCTL_CREATE_USN_JOURNAL:
        case FSCTL_DISMOUNT_VOLUME:
        case FSCTL_LOCK_VOLUME:
        case FSCTL_UNLOCK_VOLUME:
        case FSCTL_INVALIDATE_VOLUMES:
        case FSCTL_MARK_VOLUME_DIRTY:
        case FSCTL_EXTEND_VOLUME:
        case FSCTL_SHRINK_VOLUME:
        case FSCTL_SET_VOLUME_COMPRESSION_STATE:
        case FSCTL_MARK_HANDLE:
        case FSCTL_FILE_LEVEL_TRIM:
        case FSCTL_OFFLOAD_WRITE:
            return true;
        default:
            return false;
    }
}

}

namespace shadow_ops {

FLT_PREOP_CALLBACK_STATUS FLTAPI pre_file_system_control(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    if (CompletionContext) *CompletionContext = nullptr;

    if (Data == nullptr || FltObjects == nullptr || Data->Iopb == nullptr) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!shadow_registry_any_active()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UCHAR minor = Data->Iopb->MinorFunction;
    if (minor != IRP_MN_USER_FS_REQUEST && minor != IRP_MN_KERNEL_CALL) {
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

    if ((sandbox_flags & SHADOWFS_FLAG_BLOCK_FSCTL) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

    SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
        "PreFsCtrl enter code=0x%08lX minor=%u", code, (unsigned)minor);

    if (!fsctl_is_destructive(code)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION name_info = nullptr;
    NTSTATUS ns = shadow_get_normalized_name(Data, &name_info);
    if (NT_SUCCESS(ns) && name_info != nullptr) {
        if (shadow_is_path_under_root(&name_info->Name, &root_us)
            || shadow_is_named_pipe(&name_info->Name)) {
            SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
                "PreFsCtrl pass_through_under_sandbox path='%wZ' code=0x%08lX",
                &name_info->Name, code);
            FltReleaseFileNameInformation(name_info);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        SHADOW_LOG_ERROR_PID(caller,
            "PreFsCtrl DENY code=0x%08lX path='%wZ'", code, &name_info->Name);
        FltReleaseFileNameInformation(name_info);
    } else {
        SHADOW_LOG_ERROR_PID(caller, "PreFsCtrl DENY code=0x%08lX (no_name_info)", code);
    }

    shadow_stats_inc_fsctl_denials();
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

}
