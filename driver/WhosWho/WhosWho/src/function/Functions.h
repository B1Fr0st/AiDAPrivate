#pragma once
#include <ntifs.h>
#include "Struct.h"
#include "impl/driver/Strong.h"

namespace functions {
    NTSTATUS handle777d(p_dtb_solve request);
    NTSTATUS handle777e(p_physical_rw request);
    NTSTATUS handle777f(p_base_address request);
    NTSTATUS setup_mouclasscallback(PMOUSE_OBJECT mouse);
    NTSTATUS handle7780(p_mouse_move request);
    NTSTATUS handle7781(p_remote_call request);
    NTSTATUS handle7782(p_call_result request);
    NTSTATUS handle7783(p_alloc_mem request);
    NTSTATUS handle7784(p_free_mem request);


    NTSTATUS handle_thread_ctx(p_thread_ctx request);
    NTSTATUS handle_thread_enum(p_thread_enum request);
    NTSTATUS handle_suspend_resume_thread(p_suspend_resume_thread request);
    NTSTATUS handle_query_memory(p_query_memory request);
    NTSTATUS handle_protect_memory(p_protect_memory request);
    NTSTATUS handle_enum_regions(p_enum_regions request);
    NTSTATUS handle_read_peb(p_read_peb request);
    NTSTATUS handle_spoof_debug_flags(p_spoof_debug request);
    NTSTATUS handle_get_module_export(p_module_export request);
    NTSTATUS handle_virt_to_phys(p_virt_to_phys request);
}
