#pragma once

#include <string>

namespace aida_ipc
{
    bool verify_standalone_runtime(std::string* failure = nullptr);

    bool start_standalone_watchdog();

    void shutdown();

    bool is_standalone_alive();

    void install_crash_breadcrumbs();

    void uninstall_crash_breadcrumbs();

    void trace_breadcrumb(const char* fmt, ...);
}
