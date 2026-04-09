#pragma once


#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace arc_loader
{

    struct loaded_module_t
    {
        void*    base;
        size_t   image_size;
        bool     initialized;
    };


    loaded_module_t load(uint8_t* pe_buffer, size_t pe_size);


    void* get_export(const loaded_module_t& mod, const char* export_name);


    void unload(loaded_module_t& mod);


    const std::string& last_error();
}
