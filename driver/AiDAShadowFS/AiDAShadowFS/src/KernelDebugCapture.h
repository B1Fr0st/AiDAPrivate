#pragma once

#include <fltKernel.h>

namespace dbg_capture {

    NTSTATUS initialize();

    void write_raw(const char* data, ULONG len);
}
