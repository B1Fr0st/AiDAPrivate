#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include "win32_dialog.hpp"


namespace disasm
{
    inline std::string open_file_dialog(HWND owner)
    {
        std::string buf(32768, '\0');
        static const char k_filter[] =
            "PE Files (*.exe;*.dll;*.sys;*.bin)\0*.exe;*.dll;*.sys;*.bin\0"
            "All files (*.*)\0*.*\0\0";
        if (win32_dialog::show_open_file_dialog(owner,
                "Open PE File",
                k_filter,
                buf.data(), buf.size(),
                "disasm.h::open_file_dialog"))
            return std::string(buf.c_str());
        return {};
    }
}
