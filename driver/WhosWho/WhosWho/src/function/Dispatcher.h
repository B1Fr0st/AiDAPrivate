#pragma once
#include <ntifs.h>
#include <intrin.h>

#include <function/Struct.h>
#include <function/Functions.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>


#ifndef WW_LOG
#define WW_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] " fmt "\n", __VA_ARGS__)
#define WW_LOG0(msg) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] %s\n", msg)
#endif

__forceinline ULONG hash_build_key(ULONG key) {
    key ^= key >> 16;
    key *= 0x85ebca6bu;
    key ^= key >> 13;
    key *= 0xc2b2ae35u;
    key ^= key >> 16;
    return key;
}

__forceinline ULONG secondary_hash(ULONG key) {
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = (key >> 16) ^ key;
    return key;
}

namespace ioctl_codes {
    __forceinline ULONG get_base() {
        ULONG key = dynamic_key::get();
        return ((hash_build_key(key) ^ secondary_hash(key >> 3)) & 0x7FF) | 0x800;
    }

    __forceinline ULONG make(ULONG offset) {
        return 0x00220000u | ((get_base() + offset) << 2);
    }

    __forceinline ULONG DB()  { return make(0); }
    __forceinline ULONG PRW() { return make(1); }
    __forceinline ULONG BA()  { return make(2); }
    __forceinline ULONG MM()  { return make(3); }
    __forceinline ULONG RC()  { return make(4); }
    __forceinline ULONG CR()  { return make(5); }
    __forceinline ULONG AM()  { return make(6); }
    __forceinline ULONG FM()  { return make(7); }
    __forceinline ULONG HB()  { return make(8); }


    __forceinline ULONG TCTX()  { return make(9); }
    __forceinline ULONG TENUM() { return make(10); }
    __forceinline ULONG TSR()   { return make(11); }
    __forceinline ULONG QM()    { return make(12); }
    __forceinline ULONG PM()    { return make(13); }
    __forceinline ULONG ER()    { return make(14); }
    __forceinline ULONG RPEB()  { return make(15); }
    __forceinline ULONG SDF()   { return make(16); }
    __forceinline ULONG MEX()   { return make(17); }
    __forceinline ULONG V2P()   { return make(18); }


    __forceinline ULONG NCON() { return make(19); }
    __forceinline ULONG NCAP() { return make(20); }
    __forceinline ULONG NCPG() { return make(21); }
    __forceinline ULONG NDNS() { return make(22); }
    __forceinline ULONG NFLT() { return make(23); }
    __forceinline ULONG NSTS() { return make(24); }


    __forceinline ULONG EWFP() { return make(25); }
    __forceinline ULONG GSKT() { return make(26); }
    __forceinline ULONG SNBF() { return make(27); }
    __forceinline ULONG DTCP() { return make(28); }


    __forceinline ULONG PINJ() { return make(29); }
    __forceinline ULONG PMOD() { return make(30); }
    __forceinline ULONG PRED() { return make(31); }
    __forceinline ULONG STRM() { return make(32); }
    __forceinline ULONG DPIN() { return make(33); }
    __forceinline ULONG IHLD() { return make(34); }
    __forceinline ULONG CKIL() { return make(35); }
    __forceinline ULONG DNSS() { return make(36); }
    __forceinline ULONG BWMN() { return make(37); }
    __forceinline ULONG NIFS() { return make(38); }
    __forceinline ULONG PCEX() { return make(39); }
    __forceinline ULONG NFPR() { return make(40); }
    __forceinline ULONG DPRT() { return make(41); }
}

namespace dispatcher {

    inline volatile LONG64 g_request_counter = 0;
    inline volatile LONG64 g_last_request_time = 0;
    inline volatile ULONG g_entropy_seed = 0x5A5A5A5Au;

    inline volatile LONG64 g_last_heartbeat_time = 0;
    inline volatile ULONG g_heartbeat_counter = 0;
    inline volatile ULONG g_session_key = 0;
    inline volatile LONG g_driver_activated = 0;

    inline volatile UINT64 g_integrity_check_tsc = 0;
    inline volatile LONG g_integrity_verified = 0;
    constexpr UINT64 INTEGRITY_CHECK_INTERVAL = 500000000ULL;

    constexpr LONG64 HEARTBEAT_TIMEOUT = 300000000LL;

    __forceinline ULONG get_heartbeat_magic() {
        return 0xDEADBEEFu ^ dynamic_key::get();
    }

    __forceinline BOOLEAN verify_dispatch_integrity(PDRIVER_OBJECT driver_obj) {
        if (!driver_obj) return FALSE;

        __try {
            volatile PDRIVER_DISPATCH create_handler = driver_obj->MajorFunction[IRP_MJ_CREATE];
            volatile PDRIVER_DISPATCH ioctl_handler = driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL];

            if (!create_handler || !ioctl_handler) return FALSE;

            UINT64 create_addr = reinterpret_cast<UINT64>(create_handler);
            UINT64 ioctl_addr = reinterpret_cast<UINT64>(ioctl_handler);

            if (create_addr < 0xFFFF800000000000ULL) return FALSE;
            if (ioctl_addr < 0xFFFF800000000000ULL) return FALSE;

            PUINT8 create_bytes = reinterpret_cast<PUINT8>(create_handler);
            PUINT8 ioctl_bytes = reinterpret_cast<PUINT8>(ioctl_handler);

            if (*create_bytes == 0xE9 || *create_bytes == 0xFF) return FALSE;
            if (*ioctl_bytes == 0xE9 || *ioctl_bytes == 0xFF) return FALSE;

            if (create_bytes[0] == 0x48 && create_bytes[1] == 0xB8) return FALSE;
            if (ioctl_bytes[0] == 0x48 && ioctl_bytes[1] == 0xB8) return FALSE;

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return TRUE;
    }

    __forceinline BOOLEAN is_session_valid() {
        if (g_driver_activated == 0)
            return FALSE;

        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);

        LONG64 last_hb = _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0);
        if (last_hb == 0)
            return FALSE;

        LONG64 elapsed = current_time.QuadPart - last_hb;
        if (elapsed > HEARTBEAT_TIMEOUT) {
            _InterlockedExchange(&g_driver_activated, 0);
            caller_validation::unregister_client();
            return FALSE;
        }

        if (!caller_validation::is_valid_request()) {
            return FALSE;
        }

        return TRUE;
    }

    __forceinline ULONG next_random() {
        ULONG x = g_entropy_seed;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        g_entropy_seed = x;
        return x;
    }

    __forceinline void add_timing_noise() {
        volatile LONG64 tsc = (LONG64)__rdtsc();
        volatile ULONG spin = ((ULONG)tsc & 0x7) + 1;
        while (spin--) {
            YieldProcessor();
        }
        g_entropy_seed ^= (ULONG)(tsc & 0xFFFFFFFFu);
    }

    __forceinline void scatter_kernel() {
        ULONG pattern = next_random() & 0xF;
        switch (pattern) {
            case 0: YieldProcessor(); break;
            case 1: add_timing_noise(); break;
            case 2: YieldProcessor(); YieldProcessor(); break;
            case 3: KeMemoryBarrier(); break;
            case 4: { volatile int v = 0; for(int i = 0; i < 2; i++) { v += i; YieldProcessor(); } } break;
            case 5: { volatile ULONG x = g_entropy_seed; x ^= x << 7; g_entropy_seed = x; } break;
            case 6: add_timing_noise(); YieldProcessor(); break;
            case 7: { for(int i = 0; i < 3; i++) YieldProcessor(); } break;
            case 8: KeMemoryBarrier(); YieldProcessor(); break;
            case 9: { volatile LONG64 t = (LONG64)__rdtsc(); g_last_request_time = t; } break;
            case 10: { volatile int v = 0; v = (int)(next_random() & 0x3); } break;
            default: YieldProcessor(); break;
        }
    }

    __forceinline BOOLEAN check_rate_limit() {
        LONG64 current_count = _InterlockedIncrement64(&g_request_counter);

        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);

        LONG64 last_time = _InterlockedCompareExchange64(&g_last_request_time, current_time.QuadPart, 0);

        if (last_time != 0) {
            LONG64 elapsed = current_time.QuadPart - last_time;
            if (elapsed > 10000000) {
                _InterlockedExchange64(&g_last_request_time, current_time.QuadPart);
                _InterlockedExchange64(&g_request_counter, 0);
            }
        }

        if (current_count > 50000) {
            return FALSE;
        }

        return TRUE;
    }

    __forceinline NTSTATUS Pilot(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        add_timing_noise();
        scatter_kernel();

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    __forceinline NTSTATUS Controller(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        add_timing_noise();
        scatter_kernel();

        if (!check_rate_limit()) {
            WW_LOG("Controller: RATE LIMITED, rejecting request");
            irp->IoStatus.Status = STATUS_DEVICE_BUSY;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_DEVICE_BUSY;
        }

        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        ULONG bytes = 0;

        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

        const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        const ULONG input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
        const ULONG output_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PVOID buffer = irp->AssociatedIrp.SystemBuffer;

        WW_LOG("Controller: IOCTL=0x%08X input_size=%u output_size=%u buffer=%p",
            code, input_size, output_size, buffer);

        if (!buffer) {
            WW_LOG("Controller: NULL buffer, returning STATUS_INVALID_PARAMETER");
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        if (code != ioctl_codes::HB() && !is_session_valid()) {
            WW_LOG("Controller: session invalid for non-HB IOCTL=0x%08X (activated=%d session_key=0x%08X)",
                code, (int)g_driver_activated, (ULONG)g_session_key);
            irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        add_timing_noise();

        if (code == ioctl_codes::PRW()) {
            WW_LOG("Controller: -> PRW (Physical R/W) pid=%u dtb=0x%llX addr=%p size=%llu write=%u",
                ((p_physical_rw)buffer)->pid, ((p_physical_rw)buffer)->dtb,
                ((p_physical_rw)buffer)->address, (UINT64)((p_physical_rw)buffer)->size,
                (UINT32)((p_physical_rw)buffer)->shouldWrite);
            if (input_size >= sizeof(_PRW) && output_size >= sizeof(_PRW)) {
                status = functions::handle777e((p_physical_rw)buffer);
                WW_LOG("Controller: <- PRW status=0x%08X retSize=%llu", status, (UINT64)((p_physical_rw)buffer)->retSize);
                bytes = sizeof(_PRW);
            }
            else {
                WW_LOG("Controller: <- PRW SIZE MISMATCH input=%u need=%u output=%u need=%u",
                    input_size, (ULONG)sizeof(_PRW), output_size, (ULONG)sizeof(_PRW));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::BA()) {
            WW_LOG("Controller: -> BA (Base Address) pid=%u", ((p_base_address)buffer)->pid);
            if (input_size >= sizeof(_BA) && output_size >= sizeof(_BA)) {
                status = functions::handle777f((p_base_address)buffer);
                WW_LOG("Controller: <- BA status=0x%08X", status);
                bytes = sizeof(_BA);
            }
            else {
                WW_LOG("Controller: <- BA SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(_BA));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::MM()) {
            WW_LOG("Controller: -> MM (Mouse) x=%d y=%d flags=0x%X",
                ((p_mouse_move)buffer)->inputX, ((p_mouse_move)buffer)->inputY,
                ((p_mouse_move)buffer)->buttonFlags);
            if (input_size >= sizeof(_MM)) {
                status = functions::handle7780((p_mouse_move)buffer);
                WW_LOG("Controller: <- MM status=0x%08X", status);
                bytes = sizeof(_MM);
            }
            else {
                WW_LOG("Controller: <- MM SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(_MM));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DB()) {
            WW_LOG("Controller: -> DB (DTB Solve) pid=%u", ((p_dtb_solve)buffer)->pid);
            if (input_size >= sizeof(_DB) && output_size >= sizeof(_DB)) {
                status = functions::handle777d((p_dtb_solve)buffer);
                WW_LOG("Controller: <- DB status=0x%08X dtb=0x%llX", status, ((p_dtb_solve)buffer)->dtb);
                bytes = sizeof(_DB);
            }
            else {
                WW_LOG("Controller: <- DB SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(_DB));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RC()) {
            WW_LOG("Controller: -> RC (Remote Call) dtb=0x%llX target_func=0x%llX shellcode=0x%llX",
                ((p_remote_call)buffer)->dtb, ((p_remote_call)buffer)->target_function,
                ((p_remote_call)buffer)->shellcode_address);
            if (input_size >= sizeof(_RC) && output_size >= sizeof(_RC)) {
                status = functions::handle7781((p_remote_call)buffer);
                WW_LOG("Controller: <- RC status=0x%08X result=0x%llX completed=%llu",
                    status, ((p_remote_call)buffer)->result, ((p_remote_call)buffer)->completed);
                bytes = sizeof(_RC);
            }
            else {
                WW_LOG("Controller: <- RC SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(_RC));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::CR()) {
            WW_LOG("Controller: -> CR (Call Result) dtb=0x%llX result_addr=0x%llX",
                ((p_call_result)buffer)->dtb, ((p_call_result)buffer)->result_address);
            if (input_size >= sizeof(_CR) && output_size >= sizeof(_CR)) {
                status = functions::handle7782((p_call_result)buffer);
                WW_LOG("Controller: <- CR status=0x%08X result=0x%llX completed=%llu",
                    status, ((p_call_result)buffer)->result, ((p_call_result)buffer)->completed);
                bytes = sizeof(_CR);
            }
            else if (input_size >= (sizeof(_CR) - sizeof(UINT64)) && output_size >= (sizeof(_CR) - sizeof(UINT64))) {
                status = functions::handle7782_legacy((p_call_result)buffer);
                WW_LOG("Controller: <- CR(legacy) status=0x%08X", status);
                bytes = sizeof(_CR) - sizeof(UINT64);
            }
            else {
                WW_LOG("Controller: <- CR SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(_CR));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::AM()) {
            WW_LOG("Controller: -> AM (Alloc Mem) pid=%u size=0x%llX",
                ((p_alloc_mem)buffer)->pid, ((p_alloc_mem)buffer)->size);
            if (input_size >= sizeof(_AM) && output_size >= sizeof(_AM)) {
                status = functions::handle7783((p_alloc_mem)buffer);
                WW_LOG("Controller: <- AM status=0x%08X addr=0x%llX actual=0x%llX",
                    status, ((p_alloc_mem)buffer)->allocated_address, ((p_alloc_mem)buffer)->actual_size);
                bytes = sizeof(_AM);
            }
            else {
                WW_LOG("Controller: <- AM SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(_AM));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::FM()) {
            WW_LOG("Controller: -> FM (Free Mem) pid=%u addr=0x%llX",
                ((p_free_mem)buffer)->pid, ((p_free_mem)buffer)->address);
            if (input_size >= sizeof(_FM) && output_size >= sizeof(_FM)) {
                status = functions::handle7784((p_free_mem)buffer);
                WW_LOG("Controller: <- FM status=0x%08X", status);
                bytes = sizeof(_FM);
            }
            else {
                WW_LOG("Controller: <- FM SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::TCTX()) {
            WW_LOG("Controller: -> TCTX (Thread Ctx) tid=%u set=%u",
                ((p_thread_ctx)buffer)->tid, ((p_thread_ctx)buffer)->should_set);
            if (input_size >= sizeof(thread_ctx) && output_size >= sizeof(thread_ctx)) {
                status = functions::handle_thread_ctx((p_thread_ctx)buffer);
                WW_LOG("Controller: <- TCTX status=0x%08X", status);
                bytes = sizeof(thread_ctx);
            }
            else {
                WW_LOG("Controller: <- TCTX SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(thread_ctx));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TENUM()) {
            WW_LOG("Controller: -> TENUM (Thread Enum) pid=%u", ((p_thread_enum)buffer)->pid);
            if (input_size >= sizeof(thread_enum) && output_size >= sizeof(thread_enum)) {
                status = functions::handle_thread_enum((p_thread_enum)buffer);
                WW_LOG("Controller: <- TENUM status=0x%08X count=%u", status, ((p_thread_enum)buffer)->thread_count);
                bytes = sizeof(thread_enum);
            }
            else {
                WW_LOG("Controller: <- TENUM SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(thread_enum));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TSR()) {
            WW_LOG("Controller: -> TSR (Suspend/Resume) tid=%u resume=%u",
                ((p_suspend_resume_thread)buffer)->tid, ((p_suspend_resume_thread)buffer)->should_resume);
            if (input_size >= sizeof(suspend_resume_thread) && output_size >= sizeof(suspend_resume_thread)) {
                status = functions::handle_suspend_resume_thread((p_suspend_resume_thread)buffer);
                WW_LOG("Controller: <- TSR status=0x%08X", status);
                bytes = sizeof(suspend_resume_thread);
            }
            else {
                WW_LOG("Controller: <- TSR SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::QM()) {
            WW_LOG("Controller: -> QM (Query Memory) pid=%u addr=0x%llX",
                ((p_query_memory)buffer)->pid, ((p_query_memory)buffer)->address);
            if (input_size >= sizeof(query_memory) && output_size >= sizeof(query_memory)) {
                status = functions::handle_query_memory((p_query_memory)buffer);
                WW_LOG("Controller: <- QM status=0x%08X state=0x%X protect=0x%X size=0x%llX",
                    status, ((p_query_memory)buffer)->state, ((p_query_memory)buffer)->protect,
                    ((p_query_memory)buffer)->region_size);
                bytes = sizeof(query_memory);
            }
            else {
                WW_LOG("Controller: <- QM SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::PM()) {
            WW_LOG("Controller: -> PM (Protect Memory) pid=%u addr=0x%llX size=0x%llX newprot=0x%X",
                ((p_protect_memory)buffer)->pid, ((p_protect_memory)buffer)->address,
                ((p_protect_memory)buffer)->size, ((p_protect_memory)buffer)->new_protect);
            if (input_size >= sizeof(protect_memory) && output_size >= sizeof(protect_memory)) {
                status = functions::handle_protect_memory((p_protect_memory)buffer);
                WW_LOG("Controller: <- PM status=0x%08X old_protect=0x%X", status, ((p_protect_memory)buffer)->old_protect);
                bytes = sizeof(protect_memory);
            }
            else {
                WW_LOG("Controller: <- PM SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::ER()) {
            WW_LOG("Controller: -> ER (Enum Regions) pid=%u", ((p_enum_regions)buffer)->pid);
            if (input_size >= sizeof(enum_regions) && output_size >= sizeof(enum_regions)) {
                status = functions::handle_enum_regions((p_enum_regions)buffer);
                WW_LOG("Controller: <- ER status=0x%08X count=%u", status, ((p_enum_regions)buffer)->region_count);
                bytes = sizeof(enum_regions);
            }
            else {
                WW_LOG("Controller: <- ER SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RPEB()) {
            WW_LOG("Controller: -> RPEB (Read PEB) pid=%u", ((p_read_peb)buffer)->pid);
            if (input_size >= sizeof(read_peb) && output_size >= sizeof(read_peb)) {
                status = functions::handle_read_peb((p_read_peb)buffer);
                WW_LOG("Controller: <- RPEB status=0x%08X image_base=0x%llX", status, ((p_read_peb)buffer)->image_base);
                bytes = sizeof(read_peb);
            }
            else {
                WW_LOG("Controller: <- RPEB SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SDF()) {
            WW_LOG("Controller: -> SDF (Spoof Debug Flags) pid=%u", ((p_spoof_debug)buffer)->pid);
            if (input_size >= sizeof(spoof_debug) && output_size >= sizeof(spoof_debug)) {
                status = functions::handle_spoof_debug_flags((p_spoof_debug)buffer);
                WW_LOG("Controller: <- SDF status=0x%08X", status);
                bytes = sizeof(spoof_debug);
            }
            else {
                WW_LOG("Controller: <- SDF SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::MEX()) {
            WW_LOG("Controller: -> MEX (Module Export) dtb=0x%llX", ((p_module_export)buffer)->dtb);
            if (input_size >= sizeof(module_export) && output_size >= sizeof(module_export)) {
                status = functions::handle_get_module_export((p_module_export)buffer);
                WW_LOG("Controller: <- MEX status=0x%08X addr=0x%llX", status, ((p_module_export)buffer)->resolved_address);
                bytes = sizeof(module_export);
            }
            else {
                WW_LOG("Controller: <- MEX SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::V2P()) {
            WW_LOG("Controller: -> V2P (Virtual->Physical) dtb=0x%llX vaddr=0x%llX",
                ((p_virt_to_phys)buffer)->dtb, ((p_virt_to_phys)buffer)->virtual_address);
            if (input_size >= sizeof(virt_to_phys) && output_size >= sizeof(virt_to_phys)) {
                status = functions::handle_virt_to_phys((p_virt_to_phys)buffer);
                WW_LOG("Controller: <- V2P status=0x%08X phys=0x%llX", status, ((p_virt_to_phys)buffer)->physical_address);
                bytes = sizeof(virt_to_phys);
            }
            else {
                WW_LOG("Controller: <- V2P SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCON()) {
            WW_LOG("Controller: -> NCON (Net Enum Conn) pid=%u", ((p_net_enum_conn)buffer)->filter_pid);
            if (input_size >= sizeof(net_enum_conn) && output_size >= sizeof(net_enum_conn)) {
                status = functions::handle_net_enum_conn((p_net_enum_conn)buffer);
                WW_LOG("Controller: <- NCON status=0x%08X count=%u", status, ((p_net_enum_conn)buffer)->connection_count);
                bytes = sizeof(net_enum_conn);
            }
            else {
                WW_LOG("Controller: <- NCON SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCAP()) {
            WW_LOG("Controller: -> NCAP (Net Capture Ctrl) op=%u", ((p_net_cap_ctrl)buffer)->operation);
            if (input_size >= sizeof(net_cap_ctrl) && output_size >= sizeof(net_cap_ctrl)) {
                status = functions::handle_net_cap_ctrl((p_net_cap_ctrl)buffer);
                WW_LOG("Controller: <- NCAP status=0x%08X", status);
                bytes = sizeof(net_cap_ctrl);
            }
            else {
                WW_LOG("Controller: <- NCAP SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCPG()) {
            WW_LOG0("Controller: -> NCPG (Net Capture Get)");
            if (input_size >= sizeof(net_cap_get) && output_size >= sizeof(net_cap_get)) {
                status = functions::handle_net_cap_get((p_net_cap_get)buffer);
                WW_LOG("Controller: <- NCPG status=0x%08X count=%u", status, ((p_net_cap_get)buffer)->packet_count);
                bytes = sizeof(net_cap_get);
            }
            else {
                WW_LOG("Controller: <- NCPG SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NDNS()) {
            WW_LOG0("Controller: -> NDNS (Net DNS Get)");
            if (input_size >= sizeof(net_dns_get) && output_size >= sizeof(net_dns_get)) {
                status = functions::handle_net_dns_get((p_net_dns_get)buffer);
                WW_LOG("Controller: <- NDNS status=0x%08X count=%u", status, ((p_net_dns_get)buffer)->entry_count);
                bytes = sizeof(net_dns_get);
            }
            else {
                WW_LOG("Controller: <- NDNS SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NFLT()) {
            WW_LOG("Controller: -> NFLT (Net Filter Rule) op=%u", ((p_net_filter_rule)buffer)->operation);
            if (input_size >= sizeof(net_filter_rule) && output_size >= sizeof(net_filter_rule)) {
                status = functions::handle_net_filter_rule((p_net_filter_rule)buffer);
                WW_LOG("Controller: <- NFLT status=0x%08X", status);
                bytes = sizeof(net_filter_rule);
            }
            else {
                WW_LOG("Controller: <- NFLT SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NSTS()) {
            WW_LOG0("Controller: -> NSTS (Net Stats)");
            if (input_size >= sizeof(net_stats) && output_size >= sizeof(net_stats)) {
                status = functions::handle_net_stats((p_net_stats)buffer);
                WW_LOG("Controller: <- NSTS status=0x%08X", status);
                bytes = sizeof(net_stats);
            }
            else {
                WW_LOG("Controller: <- NSTS SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::EWFP()) {
            WW_LOG0("Controller: -> EWFP (WFP Callout Enum)");
            if (input_size >= sizeof(wfp_callout_enum) && output_size >= sizeof(wfp_callout_enum)) {
                status = functions::handle_wfp_callout_enum((p_wfp_callout_enum)buffer);
                WW_LOG("Controller: <- EWFP status=0x%08X count=%u", status, ((p_wfp_callout_enum)buffer)->callout_count);
                bytes = sizeof(wfp_callout_enum);
            }
            else {
                WW_LOG("Controller: <- EWFP SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::GSKT()) {
            WW_LOG("Controller: -> GSKT (Socket Handle Enum) pid=%u", ((p_socket_handle_enum)buffer)->target_pid);
            if (input_size >= sizeof(socket_handle_enum) && output_size >= sizeof(socket_handle_enum)) {
                status = functions::handle_socket_handle_enum((p_socket_handle_enum)buffer);
                WW_LOG("Controller: <- GSKT status=0x%08X count=%u", status, ((p_socket_handle_enum)buffer)->socket_count);
                bytes = sizeof(socket_handle_enum);
            }
            else {
                WW_LOG("Controller: <- GSKT SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SNBF()) {
            WW_LOG0("Controller: -> SNBF (Sniff Net Buffers)");
            if (input_size >= sizeof(sniff_net_buffers) && output_size >= sizeof(sniff_net_buffers)) {
                status = functions::handle_sniff_net_buffers((p_sniff_net_buffers)buffer);
                WW_LOG("Controller: <- SNBF status=0x%08X count=%u", status, ((p_sniff_net_buffers)buffer)->capture_count);
                bytes = sizeof(sniff_net_buffers);
            }
            else {
                WW_LOG("Controller: <- SNBF SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DTCP()) {
            WW_LOG0("Controller: -> DTCP (TCPIP Conn Dump)");
            if (input_size >= sizeof(tcpip_conn_dump) && output_size >= sizeof(tcpip_conn_dump)) {
                status = functions::handle_tcpip_conn_dump((p_tcpip_conn_dump)buffer);
                WW_LOG("Controller: <- DTCP status=0x%08X count=%u", status, ((p_tcpip_conn_dump)buffer)->connection_count);
                bytes = sizeof(tcpip_conn_dump);
            }
            else {
                WW_LOG("Controller: <- DTCP SIZE MISMATCH", 0);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::PINJ()) {
            WW_LOG("Controller: -> PINJ (Packet Inject) dir=%u proto=%u",
                ((p_packet_inject_request)buffer)->direction, ((p_packet_inject_request)buffer)->protocol);
            if (input_size >= sizeof(packet_inject_request) && output_size >= sizeof(packet_inject_request)) {
                status = functions::handle_packet_inject((p_packet_inject_request)buffer);
                WW_LOG("Controller: <- PINJ status=0x%08X", status);
                bytes = sizeof(packet_inject_request);
            }
            else { WW_LOG("Controller: <- PINJ SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PMOD()) {
            WW_LOG("Controller: -> PMOD (Packet Mod Rule)");
            if (input_size >= sizeof(packet_mod_rule_list) && output_size >= sizeof(packet_mod_rule_list) &&
                ((p_packet_mod_rule_list)buffer)->operation == 2) {
                status = functions::handle_packet_mod_rule_list((p_packet_mod_rule_list)buffer);
                WW_LOG("Controller: <- PMOD(list) status=0x%08X", status);
                bytes = sizeof(packet_mod_rule_list);
            }
            else if (input_size >= sizeof(packet_mod_rule) && output_size >= sizeof(packet_mod_rule)) {
                status = functions::handle_packet_mod_rule((p_packet_mod_rule)buffer);
                WW_LOG("Controller: <- PMOD status=0x%08X", status);
                bytes = sizeof(packet_mod_rule);
            }
            else { WW_LOG("Controller: <- PMOD SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PRED()) {
            WW_LOG("Controller: -> PRED (Traffic Redirect)");
            if (input_size >= sizeof(traffic_redirect_list) && output_size >= sizeof(traffic_redirect_list) &&
                ((p_traffic_redirect_list)buffer)->operation == 2) {
                status = functions::handle_traffic_redirect_list((p_traffic_redirect_list)buffer);
                WW_LOG("Controller: <- PRED(list) status=0x%08X", status);
                bytes = sizeof(traffic_redirect_list);
            }
            else if (input_size >= sizeof(traffic_redirect_rule) && output_size >= sizeof(traffic_redirect_rule)) {
                status = functions::handle_traffic_redirect((p_traffic_redirect_rule)buffer);
                WW_LOG("Controller: <- PRED status=0x%08X", status);
                bytes = sizeof(traffic_redirect_rule);
            }
            else { WW_LOG("Controller: <- PRED SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::STRM()) {
            WW_LOG("Controller: -> STRM (Stream Reassemble)");
            if (input_size >= sizeof(stream_reassemble_request) && output_size >= sizeof(stream_reassemble_request)) {
                status = functions::handle_stream_reassemble((p_stream_reassemble_request)buffer);
                WW_LOG("Controller: <- STRM status=0x%08X", status);
                bytes = sizeof(stream_reassemble_request);
            }
            else { WW_LOG("Controller: <- STRM SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DPIN()) {
            WW_LOG("Controller: -> DPIN (Deep Inspect)");
            if (input_size >= sizeof(dpi_request) && output_size >= sizeof(dpi_request)) {
                status = functions::handle_deep_inspect((p_dpi_request)buffer);
                WW_LOG("Controller: <- DPIN status=0x%08X", status);
                bytes = sizeof(dpi_request);
            }
            else { WW_LOG("Controller: <- DPIN SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::IHLD()) {
            WW_LOG("Controller: -> IHLD (Intercept Hold)");
            if (input_size >= sizeof(intercept_request) && output_size >= sizeof(intercept_request)) {
                status = functions::handle_intercept_hold((p_intercept_request)buffer);
                WW_LOG("Controller: <- IHLD status=0x%08X", status);
                bytes = sizeof(intercept_request);
            }
            else { WW_LOG("Controller: <- IHLD SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CKIL()) {
            WW_LOG("Controller: -> CKIL (Conn Kill)");
            if (input_size >= sizeof(conn_kill_request) && output_size >= sizeof(conn_kill_request)) {
                status = functions::handle_conn_kill((p_conn_kill_request)buffer);
                WW_LOG("Controller: <- CKIL status=0x%08X", status);
                bytes = sizeof(conn_kill_request);
            }
            else { WW_LOG("Controller: <- CKIL SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DNSS()) {
            WW_LOG("Controller: -> DNSS (DNS Spoof)");
            if (input_size >= sizeof(dns_spoof_list) && output_size >= sizeof(dns_spoof_list) &&
                ((p_dns_spoof_list)buffer)->operation == 2) {
                status = functions::handle_dns_spoof_list((p_dns_spoof_list)buffer);
                WW_LOG("Controller: <- DNSS(list) status=0x%08X", status);
                bytes = sizeof(dns_spoof_list);
            }
            else if (input_size >= sizeof(dns_spoof_rule) && output_size >= sizeof(dns_spoof_rule)) {
                status = functions::handle_dns_spoof((p_dns_spoof_rule)buffer);
                WW_LOG("Controller: <- DNSS status=0x%08X", status);
                bytes = sizeof(dns_spoof_rule);
            }
            else { WW_LOG("Controller: <- DNSS SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::BWMN()) {
            WW_LOG("Controller: -> BWMN (BW Monitor)");
            if (input_size >= sizeof(bw_monitor_request) && output_size >= sizeof(bw_monitor_request)) {
                status = functions::handle_bw_monitor((p_bw_monitor_request)buffer);
                WW_LOG("Controller: <- BWMN status=0x%08X", status);
                bytes = sizeof(bw_monitor_request);
            }
            else { WW_LOG("Controller: <- BWMN SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NIFS()) {
            WW_LOG0("Controller: -> NIFS (Net Interface Enum)");
            if (input_size >= sizeof(net_interface_enum) && output_size >= sizeof(net_interface_enum)) {
                status = functions::handle_net_iface_enum((p_net_interface_enum)buffer);
                WW_LOG("Controller: <- NIFS status=0x%08X count=%u", status, ((p_net_interface_enum)buffer)->interface_count);
                bytes = sizeof(net_interface_enum);
            }
            else { WW_LOG("Controller: <- NIFS SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PCEX()) {
            WW_LOG0("Controller: -> PCEX (PCAP Export)");
            if (input_size >= sizeof(pcap_export_request) && output_size >= sizeof(pcap_export_request)) {
                status = functions::handle_pcap_export((p_pcap_export_request)buffer);
                WW_LOG("Controller: <- PCEX status=0x%08X", status);
                bytes = sizeof(pcap_export_request);
            }
            else { WW_LOG("Controller: <- PCEX SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NFPR()) {
            WW_LOG0("Controller: -> NFPR (Net Fingerprint)");
            if (input_size >= sizeof(net_fingerprint_request) && output_size >= sizeof(net_fingerprint_request)) {
                status = functions::handle_net_fingerprint((p_net_fingerprint_request)buffer);
                WW_LOG("Controller: <- NFPR status=0x%08X", status);
                bytes = sizeof(net_fingerprint_request);
            }
            else { WW_LOG("Controller: <- NFPR SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DPRT()) {
            WW_LOG("Controller: -> DPRT (DLL Protect) pid=%u op=%u",
                ((p_dll_protect)buffer)->pid, ((p_dll_protect)buffer)->operation);
            if (input_size >= sizeof(dll_protect) && output_size >= sizeof(dll_protect)) {
                status = functions::handle_dll_protect((p_dll_protect)buffer);
                WW_LOG("Controller: <- DPRT status=0x%08X", status);
                bytes = sizeof(dll_protect);
            }
            else { WW_LOG("Controller: <- DPRT SIZE MISMATCH", 0); status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::HB()) {
            WW_LOG("Controller: -> HB (Heartbeat) magic=0x%08X session_key=0x%08X",
                ((p_heartbeat)buffer)->magic, ((p_heartbeat)buffer)->session_key);
            if (input_size >= sizeof(_HB) && output_size >= sizeof(_HB)) {
                p_heartbeat hb = (p_heartbeat)buffer;

                ULONG expectedMagic = get_heartbeat_magic();

                if (hb->magic == expectedMagic) {
                    {
                        LARGE_INTEGER current_time;
                        KeQuerySystemTime(&current_time);

                        LONG existing_key = _InterlockedCompareExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key, 0);
                        WW_LOG("Controller: HB existing_key=0x%08X incoming_key=0x%08X",
                            (ULONG)existing_key, hb->session_key);

                        if (existing_key != 0 && (ULONG)existing_key != hb->session_key) {
                            WW_LOG("Controller: HB session key MISMATCH, resetting. old=0x%08X new=0x%08X",
                                (ULONG)existing_key, hb->session_key);
                            caller_validation::unregister_client();
                            _InterlockedExchange((volatile LONG*)&g_session_key, 0);
                            _InterlockedExchange((volatile LONG*)&g_heartbeat_counter, 0);
                            _InterlockedExchange(&g_driver_activated, 0);
                            existing_key = _InterlockedCompareExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key, 0);
                        }

                        if (existing_key == 0 || (ULONG)existing_key == hb->session_key) {
                            _InterlockedExchange64(&g_last_heartbeat_time, current_time.QuadPart);
                            _InterlockedIncrement((volatile LONG*)&g_heartbeat_counter);
                            _InterlockedExchange(&g_driver_activated, 1);

                            if (existing_key == 0) {
                                WW_LOG0("Controller: HB first heartbeat, registering client");
                                caller_validation::register_client();
                            }

                            hb->response = (UINT64)g_heartbeat_counter ^ dynamic_key::get();
                            WW_LOG("Controller: <- HB SUCCESS counter=%u response=0x%llX",
                                (ULONG)g_heartbeat_counter, hb->response);
                            status = STATUS_SUCCESS;
                        } else {
                            WW_LOG("Controller: <- HB ACCESS_DENIED existing=0x%08X", (ULONG)existing_key);
                            hb->response = 0;
                            status = STATUS_ACCESS_DENIED;
                        }
                    }
                } else {
                    WW_LOG("Controller: <- HB BAD MAGIC got=0x%08X expected=0x%08X",
                        hb->magic, expectedMagic);
                    hb->response = 0;
                    status = STATUS_INVALID_PARAMETER;
                }
                bytes = sizeof(_HB);
            }
            else {
                WW_LOG("Controller: <- HB SIZE MISMATCH input=%u need=%u", input_size, (ULONG)sizeof(_HB));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else {
            WW_LOG("Controller: UNKNOWN IOCTL=0x%08X", code);
            status = STATUS_INVALID_DEVICE_REQUEST;
            bytes = 0;
        }

        add_timing_noise();

        WW_LOG("Controller: COMPLETE IOCTL=0x%08X status=0x%08X bytes=%u", code, status, bytes);

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = bytes;
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }
}
