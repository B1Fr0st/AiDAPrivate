#pragma once

#include <string>

namespace driver_loader
{
    bool initialize_and_load();
    bool is_driver_loaded();
    void mark_already_loaded();
    const std::string& last_error();

    bool load_shadow_fs();
    bool is_shadow_fs_loaded();
    void mark_shadow_fs_loaded();
}
