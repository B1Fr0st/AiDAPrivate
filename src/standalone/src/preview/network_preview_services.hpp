#pragma once

#include "network_preview_adapter.hpp"
#include "shell_preview_platform.hpp"

#include <cstddef>
#include <cstdio>
#include <string>

namespace aida::preview::network_dialog {

inline bool show_open_file_dialog(void*, const char* title, const char*, char* out_path,
                                  std::size_t capacity, const char*) {
    if (!out_path || capacity == 0) return false;
    std::string path;
    const std::string label = title ? title : "";
    if (label.find("executable") != std::string::npos || label.find("Executable") != std::string::npos)
        path = "/aida-preview/targets/suspect.exe";
    else if (label.find("keylog") != std::string::npos || label.find("Keylog") != std::string::npos)
        path = "/aida-preview/captures/sslkeys.log";
    else if (label.find("script") != std::string::npos || label.find("Script") != std::string::npos)
        path = "/aida-preview/scripts/redact-auth.js";
    else
        path = "/aida-preview/fixtures/request.bin";
    std::snprintf(out_path, capacity, "%s", path.c_str());
    aida::preview::network::record_receipt("Open dialog", path);
    return true;
}

}
