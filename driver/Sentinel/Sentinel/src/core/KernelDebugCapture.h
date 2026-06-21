#pragma once

#include <ntifs.h>

namespace dbg_capture {

    void configure_log_path(PUNICODE_STRING registry_path);

    NTSTATUS initialize();

    void write_formatted(const char* fmt, ...);

    void write_immediate_formatted(const char* fmt, ...);
}
