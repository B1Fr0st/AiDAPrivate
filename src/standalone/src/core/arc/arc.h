#pragma once


#include <cstdint>
#include <cstddef>

#ifdef ARC_EXPORTS
#define ARC_API __declspec(dllexport)
#else
#define ARC_API
#endif


static constexpr uint32_t ARC_INTERFACE_VERSION = 0x00010001u;


struct arc_comm_vtable_t
{


    bool (*connect)(uint64_t device_path_seed);


    void (*disconnect)();


    bool (*is_connected)();


    void (*set_process_id)(uint32_t pid);


    uint64_t (*solve_dtb)();


    uint64_t (*get_dtb)();


    uint64_t (*find_image)();


    void (*set_base_address)(uint64_t base);


    uint32_t (*find_process)(const char* name);


    void (*clear_process_context)();


    size_t (*read_raw)(uint64_t address, void* buffer, size_t size);


    size_t (*write_raw)(uint64_t address, const void* buffer, size_t size);


    struct memory_region_info_t {
        uint64_t base;
        uint64_t size;
        uint32_t state;
        uint32_t protect;
        uint32_t type;
    };
    uint32_t (*enumerate_memory_regions)(
        void (*callback)(const memory_region_info_t* region, void* ctx),
        void* ctx);


    bool (*query_memory)(uint64_t address, memory_region_info_t* out);


    struct thread_info_t {
        uint32_t tid;
        uint32_t state;
        uint64_t rip;
    };
    uint32_t (*enumerate_threads)(
        void (*callback)(const thread_info_t* thread, void* ctx),
        void* ctx);


    uint64_t (*remote_call)(
        uint64_t function_address,
        uint64_t arg1, uint64_t arg2,
        uint64_t arg3, uint64_t arg4);


    void* _reserved[12];
};


struct arc_heartbeat_result_t
{
    bool     valid;
    uint64_t proof_token;
    uint64_t timestamp;
};


struct arc_page_result_t
{
    bool     valid;
    uint32_t page_index;
    uint32_t total_pages;
    uint32_t page_size;
    uint64_t blob_size;
};


extern "C"
{


    ARC_API bool arc_init(
        const char*  session_token,
        const char*  hwid,
        int64_t      timestamp,
        uint32_t     interface_version
    );


    ARC_API const arc_comm_vtable_t* arc_get_comm_bridge();


    ARC_API uint64_t arc_validate_tool_exec(
        uint64_t tool_name_hash,
        uint64_t gate_token
    );


    ARC_API arc_heartbeat_result_t arc_heartbeat();


    ARC_API void arc_cleanup();


    ARC_API arc_page_result_t arc_request_page_count(
        const char* server_url
    );

    ARC_API bool arc_download_page(
        const char*  server_url,
        uint32_t     page_index,
        uint8_t*     out_decrypted,
        uint32_t*    out_size
    );

    ARC_API bool arc_download_all_pages(
        const char*  server_url,
        uint8_t*     out_blob,
        uint64_t     blob_buf_size,
        uint64_t*    out_total_size
    );
}
