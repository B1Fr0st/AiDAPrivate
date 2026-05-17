#include "Operations.h"
#include "DirMerge.h"

namespace {

struct dir_completion_t {
    ULONG sandbox_flags;
    HANDLE owner_pid;
    FILE_INFORMATION_CLASS fic;
    ULONG sl_flags;
    ULONG length;
    ULONG file_name_index;
    PUNICODE_STRING file_name;
    ULONG flags;
    ULONG _reserved0;
};

bool minor_is_query_directory(UCHAR minor) {
    return minor == IRP_MN_QUERY_DIRECTORY;
}

PSHADOW_STREAM_CONTEXT load_stream_context(
    PFLT_INSTANCE instance,
    PFILE_OBJECT fo)
{
    if (instance == nullptr || fo == nullptr) return nullptr;
    PSHADOW_STREAM_CONTEXT ctx = nullptr;
    NTSTATUS cs = FltGetStreamHandleContext(
        instance, fo, reinterpret_cast<PFLT_CONTEXT*>(&ctx));
    if (!NT_SUCCESS(cs)) return nullptr;
    return ctx;
}

bool ensure_shadow_dir_state(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PSHADOW_STREAM_CONTEXT ctx,
    PCUNICODE_STRING sandbox_root,
    PFLT_FILE_NAME_INFORMATION name_info,
    HANDLE caller_pid)
{
    if (ctx->enum_state.attempted_open != 0) {
        return ctx->enum_state.shadow_dir_exists != 0;
    }

    UNICODE_STRING shadow_dir = {};
    if (!shadow_path_compute_shadow_dir(sandbox_root, &name_info->Name, &shadow_dir)) {
        ctx->enum_state.attempted_open = 1;
        ctx->enum_state.shadow_dir_exists = 0;
        SHADOW_LOG_VERBOSE_PID(ctx->flags, caller_pid,
            "dir_enum no_shadow_path real='%wZ'", &name_info->Name);
        return false;
    }

    bool exists = shadow_directory_exists(filter, instance, &shadow_dir);

    if (exists) {
        if (ctx->shadow_path.Buffer != nullptr) {
            ExFreePoolWithTag(ctx->shadow_path.Buffer, SHADOW_TAG_PATH);
            ctx->shadow_path.Buffer = nullptr;
            ctx->shadow_path.Length = 0;
            ctx->shadow_path.MaximumLength = 0;
        }
        ctx->shadow_path.Buffer = shadow_dir.Buffer;
        ctx->shadow_path.Length = shadow_dir.Length;
        ctx->shadow_path.MaximumLength = shadow_dir.MaximumLength;
        ctx->is_directory = 1;
        ctx->enum_state.attempted_open = 1;
        ctx->enum_state.shadow_dir_exists = 1;
        SHADOW_LOG_VERBOSE_PID(ctx->flags, caller_pid,
            "dir_enum shadow_dir_exists real='%wZ' shadow='%wZ'",
            &name_info->Name, &ctx->shadow_path);
        return true;
    }

    shadow_path_free(&shadow_dir);
    ctx->enum_state.attempted_open = 1;
    ctx->enum_state.shadow_dir_exists = 0;
    SHADOW_LOG_VERBOSE_PID(ctx->flags, caller_pid,
        "dir_enum no_shadow_dir real='%wZ'", &name_info->Name);
    return false;
}

}

namespace shadow_ops {

FLT_POSTOP_CALLBACK_STATUS FLTAPI post_directory_control_safe(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS FLTAPI post_directory_control(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        if (CompletionContext != nullptr) {
            ExFreePoolWithTag(CompletionContext, SHADOW_TAG_ENUM);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (CompletionContext == nullptr) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FLT_POSTOP_CALLBACK_STATUS ret_status = FLT_POSTOP_FINISHED_PROCESSING;
    BOOLEAN safe = FltDoCompletionProcessingWhenSafe(
        Data,
        FltObjects,
        CompletionContext,
        Flags,
        post_directory_control_safe,
        &ret_status);
    UNREFERENCED_PARAMETER(safe);
    return ret_status;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI post_directory_control_safe(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (CompletionContext == nullptr) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    dir_completion_t* comp = reinterpret_cast<dir_completion_t*>(CompletionContext);

    NTSTATUS irp_status = Data->IoStatus.Status;
    bool consider_status =
        NT_SUCCESS(irp_status)
        || irp_status == STATUS_BUFFER_OVERFLOW
        || irp_status == STATUS_NO_MORE_FILES
        || irp_status == STATUS_NO_SUCH_FILE;
    if (!consider_status) {
        ExFreePoolWithTag(comp, SHADOW_TAG_ENUM);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (FltObjects == nullptr || FltObjects->Filter == nullptr
        || FltObjects->Instance == nullptr || FltObjects->FileObject == nullptr) {
        ExFreePoolWithTag(comp, SHADOW_TAG_ENUM);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PSHADOW_STREAM_CONTEXT ctx = load_stream_context(FltObjects->Instance, FltObjects->FileObject);
    if (ctx == nullptr) {
        ExFreePoolWithTag(comp, SHADOW_TAG_ENUM);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (ctx->shadow_path.Buffer == nullptr || ctx->enum_state.shadow_dir_exists == 0) {
        FltReleaseContext(ctx);
        ExFreePoolWithTag(comp, SHADOW_TAG_ENUM);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PVOID buffer = nullptr;
    PMDL mdl = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress;
    if (mdl == nullptr) {
        NTSTATUS ls = FltLockUserBuffer(Data);
        if (NT_SUCCESS(ls)) {
            mdl = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress;
        }
    }
    if (mdl != nullptr) {
        buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
    } else {
        buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    }
    if (buffer == nullptr) {
        SHADOW_LOG_WARN_PID(comp->owner_pid,
            "post_directory_control no_buffer mdl=%p dir_buf=%p",
            mdl,
            Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer);
        FltReleaseContext(ctx);
        ExFreePoolWithTag(comp, SHADOW_TAG_ENUM);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    ULONG capacity = comp->length;
    ULONG bytes_in_buf = (ULONG)Data->IoStatus.Information;
    if (bytes_in_buf > capacity) bytes_in_buf = capacity;

    ULONG combined = bytes_in_buf;
    NTSTATUS s = STATUS_SUCCESS;
    __try {
        s = dir_merge_synthesize(
            FltObjects->Filter,
            FltObjects->Instance,
            ctx,
            comp->fic,
            comp->sl_flags,
            comp->file_name,
            static_cast<UCHAR*>(buffer),
            capacity,
            &combined);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
        SHADOW_LOG_ERROR_PID(comp->owner_pid,
            "post_directory_control dir_merge_synthesize SEH 0x%08lX", s);
    }

    if (NT_SUCCESS(s)) {
        Data->IoStatus.Information = combined;
        if (combined == 0) {
            Data->IoStatus.Status = STATUS_NO_MORE_FILES;
        } else if (irp_status == STATUS_BUFFER_OVERFLOW) {
            Data->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
        } else {
            Data->IoStatus.Status = STATUS_SUCCESS;
        }
        FltSetCallbackDataDirty(Data);
        SHADOW_LOG_VERBOSE_PID(comp->flags,
            comp->owner_pid,
            "dir_merge_complete real_bytes=%lu combined_bytes=%lu shadow_done=%d total_shadow=%lld irp_status=0x%08lX",
            bytes_in_buf, combined,
            (int)ctx->enum_state.shadow_done,
            (long long)ctx->enum_state.total_shadow_emitted,
            irp_status);
    } else {
        SHADOW_LOG_WARN_PID(comp->owner_pid,
            "dir_merge_synthesize FAILED status=0x%08lX (preserving real result)", s);
    }

    FltReleaseContext(ctx);
    ExFreePoolWithTag(comp, SHADOW_TAG_ENUM);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI pre_directory_control(
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
    if (!minor_is_query_directory(minor)) {
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

    FILE_INFORMATION_CLASS fic = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
    if (!dir_info_class_is_supported(fic)) {
        SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
            "pre_directory_control unsupported_class=%d pass_through", (int)fic);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION name_info = nullptr;
    NTSTATUS ns = shadow_get_normalized_name(Data, &name_info);
    if (!NT_SUCCESS(ns) || name_info == nullptr) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (shadow_is_named_pipe(&name_info->Name)
        || shadow_is_unc_remote(&name_info->Name)
        || shadow_is_raw_volume_or_disk(&name_info->Name)) {
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (shadow_is_path_under_root(&name_info->Name, &root_us)) {
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PSHADOW_STREAM_CONTEXT ctx = load_stream_context(FltObjects->Instance, FltObjects->FileObject);
    if (ctx == nullptr) {
        PSHADOW_STREAM_CONTEXT new_ctx = nullptr;
        NTSTATUS cs = shadow_create_stream_context_for(
            FltObjects->Filter,
            &name_info->Name,
            nullptr,
            caller,
            sandbox_flags,
            &new_ctx);
        if (!NT_SUCCESS(cs) || new_ctx == nullptr) {
            FltReleaseFileNameInformation(name_info);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        new_ctx->is_passthrough = 1;
        new_ctx->is_directory = 1;
        NTSTATUS ss = FltSetStreamHandleContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            new_ctx,
            nullptr);
        if (ss == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            FltReleaseContext(new_ctx);
            ctx = load_stream_context(FltObjects->Instance, FltObjects->FileObject);
            if (ctx == nullptr) {
                FltReleaseFileNameInformation(name_info);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
        } else if (!NT_SUCCESS(ss)) {
            FltReleaseContext(new_ctx);
            FltReleaseFileNameInformation(name_info);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        } else {
            ctx = new_ctx;
        }
    }

    if (!ensure_shadow_dir_state(
            FltObjects->Filter,
            FltObjects->Instance,
            ctx,
            &root_us,
            name_info,
            caller)) {
        FltReleaseContext(ctx);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG sl_flags = Data->Iopb->OperationFlags;
    if (sl_flags & SL_RESTART_SCAN) {
        dir_merge_state_reset(&ctx->enum_state);
        if (ctx->enum_state.saved_pattern.Buffer != nullptr) {
            ExFreePoolWithTag(ctx->enum_state.saved_pattern.Buffer, SHADOW_TAG_PATH);
            ctx->enum_state.saved_pattern.Buffer = nullptr;
            ctx->enum_state.saved_pattern.Length = 0;
            ctx->enum_state.saved_pattern.MaximumLength = 0;
        }
        ctx->enum_state.pattern_seen = 0;
    }

    PUNICODE_STRING current_pattern = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName;
    if (current_pattern != nullptr && current_pattern->Length > 0
        && ctx->enum_state.saved_pattern.Buffer == nullptr) {
        PWCHAR pbuf = static_cast<PWCHAR>(
            ExAllocatePool2(POOL_FLAG_PAGED,
                current_pattern->Length + sizeof(WCHAR), SHADOW_TAG_PATH));
        if (pbuf != nullptr) {
            RtlCopyMemory(pbuf, current_pattern->Buffer, current_pattern->Length);
            pbuf[current_pattern->Length / sizeof(WCHAR)] = L'\0';
            ctx->enum_state.saved_pattern.Buffer = pbuf;
            ctx->enum_state.saved_pattern.Length = current_pattern->Length;
            ctx->enum_state.saved_pattern.MaximumLength = current_pattern->Length + sizeof(WCHAR);
            ctx->enum_state.pattern_seen = 1;
            SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
                "pre_directory_control cached_pattern='%wZ'",
                &ctx->enum_state.saved_pattern);
        }
    }

    PUNICODE_STRING effective_pattern = nullptr;
    if (current_pattern != nullptr && current_pattern->Length > 0) {
        effective_pattern = current_pattern;
    } else if (ctx->enum_state.saved_pattern.Buffer != nullptr) {
        effective_pattern = &ctx->enum_state.saved_pattern;
    }

    static UNICODE_STRING k_null_pattern = RTL_CONSTANT_STRING(L"(none)");
    SHADOW_LOG_VERBOSE_PID(sandbox_flags, caller,
        "pre_directory_control real='%wZ' shadow='%wZ' fic=%d sl=0x%08lX shadow_done=%d pattern='%wZ'",
        &name_info->Name, &ctx->shadow_path,
        (int)fic, sl_flags, (int)ctx->enum_state.shadow_done,
        effective_pattern ? effective_pattern : &k_null_pattern);

    dir_completion_t* comp = static_cast<dir_completion_t*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(dir_completion_t), SHADOW_TAG_ENUM));
    if (comp == nullptr) {
        FltReleaseContext(ctx);
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    comp->sandbox_flags = sandbox_flags;
    comp->owner_pid = caller;
    comp->fic = fic;
    comp->sl_flags = sl_flags;
    comp->length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    comp->file_name_index = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileIndex;
    comp->file_name = effective_pattern;
    comp->flags = sandbox_flags;

    *CompletionContext = comp;

    FltReleaseContext(ctx);
    FltReleaseFileNameInformation(name_info);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

}
