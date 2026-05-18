#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>
#include "KernelDebugCapture.h"

#ifndef DPFLTR_IHVDRIVER_ID
#define DPFLTR_IHVDRIVER_ID 77
#endif

#ifndef DPFLTR_ERROR_LEVEL
#define DPFLTR_ERROR_LEVEL 0
#endif
#ifndef DPFLTR_WARNING_LEVEL
#define DPFLTR_WARNING_LEVEL 1
#endif
#ifndef DPFLTR_TRACE_LEVEL
#define DPFLTR_TRACE_LEVEL 2
#endif
#ifndef DPFLTR_INFO_LEVEL
#define DPFLTR_INFO_LEVEL 3
#endif

#define SHADOW_TAG_LOG  'LSWS'
#define SHADOW_TAG_PATH 'PSWS'
#define SHADOW_TAG_CTX  'XSWS'
#define SHADOW_TAG_BUF  'BSWS'
#define SHADOW_TAG_REG  'RSWS'
#define SHADOW_TAG_ENUM 'ESWS'

__forceinline VOID shadow_log_va_at(_In_ ULONG level, _In_z_ PCSTR fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[768];
    NTSTATUS s = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (NT_SUCCESS(s) || s == STATUS_BUFFER_OVERFLOW) {
        size_t out_len = 0;
        if (NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &out_len))) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, level, "%s", buf);
            dbg_capture::write_raw(buf, static_cast<ULONG>(out_len));
        }
    }
}

#define SHADOW_LOG_INFO(fmt, ...) \
    shadow_log_va_at(DPFLTR_INFO_LEVEL, "[shadowfs] " fmt "\n", ##__VA_ARGS__)

#define SHADOW_LOG_WARN(fmt, ...) \
    shadow_log_va_at(DPFLTR_WARNING_LEVEL, "[shadowfs] " fmt "\n", ##__VA_ARGS__)

#define SHADOW_LOG_ERROR(fmt, ...) \
    shadow_log_va_at(DPFLTR_ERROR_LEVEL, "[shadowfs] " fmt "\n", ##__VA_ARGS__)

#define SHADOW_LOG_TRACE(fmt, ...) \
    shadow_log_va_at(DPFLTR_TRACE_LEVEL, "[shadowfs] " fmt "\n", ##__VA_ARGS__)

#define SHADOW_LOG(fmt, ...) \
    shadow_log_va_at(DPFLTR_INFO_LEVEL, "[shadowfs] " fmt "\n", ##__VA_ARGS__)

#define SHADOW_LOG_PID(pid, fmt, ...) \
    shadow_log_va_at(DPFLTR_INFO_LEVEL, "[shadowfs][pid=%lu] " fmt "\n", \
        (unsigned long)(ULONG_PTR)(pid), ##__VA_ARGS__)

#define SHADOW_LOG_VERBOSE_PID(flags, pid, fmt, ...) \
    do { \
        if (((flags) & 0x00000008ul) != 0) { \
            shadow_log_va_at(DPFLTR_INFO_LEVEL, "[shadowfs][pid=%lu][v] " fmt "\n", \
                (unsigned long)(ULONG_PTR)(pid), ##__VA_ARGS__); \
        } \
    } while (0)

#define SHADOW_LOG_WARN_PID(pid, fmt, ...) \
    shadow_log_va_at(DPFLTR_WARNING_LEVEL, "[shadowfs][pid=%lu] " fmt "\n", \
        (unsigned long)(ULONG_PTR)(pid), ##__VA_ARGS__)

#define SHADOW_LOG_ERROR_PID(pid, fmt, ...) \
    shadow_log_va_at(DPFLTR_ERROR_LEVEL, "[shadowfs][pid=%lu] " fmt "\n", \
        (unsigned long)(ULONG_PTR)(pid), ##__VA_ARGS__)
