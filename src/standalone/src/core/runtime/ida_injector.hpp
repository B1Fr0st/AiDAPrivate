#pragma once

#include <cstdint>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace ida_injector
{
    bool launch_ida_with_aida(const std::string& target_file_or_empty,
                              std::string& err_out);

    std::string discover_ida_path();

    bool validate_ida_path(const std::string& path);

    bool prompt_and_persist_ida_path(HWND owner, std::string& path_out);

    void shutdown_pipe_server();
}
