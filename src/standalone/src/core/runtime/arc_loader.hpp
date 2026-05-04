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
        size_t   header_size;
        void*    entry_point;
        bool     initialized;
        bool     sealed;
        unsigned long owning_pid;
        uint64_t image_path_hash;
        uint64_t loader_code_hash;
        uint64_t binding_salt;
        void*    auto_seal_timer;
        void*    function_table;
        uint32_t function_table_count;
        bool     ldr_unlinked;
        uint32_t ldr_unlink_count;
        bool     unwind_isolated;
    };


    loaded_module_t load(uint8_t* pe_buffer, size_t pe_size);


    void* get_export(const loaded_module_t& mod, const char* export_name);


    bool seal(loaded_module_t& mod);


    bool verify_process_binding(const loaded_module_t& mod);


    void unload(loaded_module_t& mod);


    const std::string& last_error();

    bool last_error_is_fatal();

    void mark_error_fatal(const std::string& msg);


    void prime_import_cache();
}
