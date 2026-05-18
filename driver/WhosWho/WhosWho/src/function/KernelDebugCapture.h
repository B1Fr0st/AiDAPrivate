#pragma once

#include <ntifs.h>

namespace dbg_capture {

    NTSTATUS initialize();

    void write_formatted(const char* fmt, ...);
}
