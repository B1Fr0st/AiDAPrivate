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
}