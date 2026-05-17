#include "Operations.h"

namespace shadow_ops {

FLT_PREOP_CALLBACK_STATUS FLTAPI pre_cleanup(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);

    if (CompletionContext) *CompletionContext = nullptr;

    if (FltObjects == nullptr
        || FltObjects->FileObject == nullptr
        || FltObjects->Instance == nullptr) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PSHADOW_STREAM_CONTEXT ctx = nullptr;
    NTSTATUS s = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        reinterpret_cast<PFLT_CONTEXT*>(&ctx));
    if (NT_SUCCESS(s) && ctx != nullptr) {
        SHADOW_LOG_VERBOSE_PID(ctx->flags, ctx->owner_pid,
            "PreCleanup ctx_release shadow=%d passthrough=%d directory=%d shadow_emitted=%lld",
            (int)ctx->is_shadow_redirected,
            (int)ctx->is_passthrough,
            (int)ctx->is_directory,
            (long long)ctx->enum_state.total_shadow_emitted);
        FltDeleteStreamHandleContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            nullptr);
        FltReleaseContext(ctx);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

}
