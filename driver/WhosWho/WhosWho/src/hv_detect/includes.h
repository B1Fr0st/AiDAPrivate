#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "ia32_defs.h"

namespace dbg_capture {
    void write_formatted(const char* fmt, ...);
    void write_immediate_formatted(const char* fmt, ...);
}

#define HVD_CAN_CAPTURE_FILE() (KeGetCurrentIrql() == PASSIVE_LEVEL && ((__readeflags() & 0x200ULL) != 0))

#define HVD_LOG(fmt, ...) do { \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[HVDT] " fmt "\n", ##__VA_ARGS__); \
        if (HVD_CAN_CAPTURE_FILE()) dbg_capture::write_formatted("[WW] HVDT " fmt "\n", ##__VA_ARGS__); \
    } while(0)

#define HVD_LOG_IMMEDIATE(fmt, ...) do { \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[HVDT] " fmt "\n", ##__VA_ARGS__); \
        if (HVD_CAN_CAPTURE_FILE()) dbg_capture::write_immediate_formatted("[WW] HVDT " fmt "\n", ##__VA_ARGS__); \
    } while(0)

#define HVD_LOG_FAST(fmt, ...) do { \
    } while(0)

#define log_info(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " fmt "\n", ##__VA_ARGS__)
#define log_success(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-!-] " fmt "\n", ##__VA_ARGS__)
#define log_info_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " fmt "\n", ##__VA_ARGS__)
#define log_success_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " fmt "\n", ##__VA_ARGS__)
#define log_error_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-!-] " fmt "\n", ##__VA_ARGS__)
#define log_new_line() DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"\n")
