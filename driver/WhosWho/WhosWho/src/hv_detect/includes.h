#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "ia32_defs.h"

#define log_info(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " fmt "\n", ##__VA_ARGS__)
#define log_success(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-!-] " fmt "\n", ##__VA_ARGS__)
#define log_info_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " fmt "\n", ##__VA_ARGS__)
#define log_success_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " fmt "\n", ##__VA_ARGS__)
#define log_error_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-!-] " fmt "\n", ##__VA_ARGS__)
#define log_new_line() DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"\n")
