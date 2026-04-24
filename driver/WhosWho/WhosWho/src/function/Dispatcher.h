#pragma once
#include <ntifs.h>
#include <intrin.h>

#include <function/Struct.h>
#include <function/Functions.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>
#include <function/SentinelBridge.h>
#include <function/impl/AntiDumpKernel.h>
#include <function/DmaCanary.h>
#include <function/TargetingLatch.h>
#include <hv_detect/hv_detect.h>

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
    inline volatile ULONG g_server_ioctl_seed = 0;

    __forceinline ULONG get_base() {
        ULONG key = dynamic_key::get();
        ULONG base = ((hash_build_key(key) ^ secondary_hash(key >> 3)) & 0x7FF) | 0x800;
        ULONG seed = g_server_ioctl_seed;
        if (seed != 0) {
            base ^= hash_build_key(seed) & 0x7FF;
            base |= 0x800;
        }
        return base;
    }

    __forceinline ULONG make(ULONG offset) {
        return 0x00220000u | ((get_base() + offset) << 2);
    }

    __forceinline ULONG DB()  { return make(0); }
    __forceinline ULONG PRW() { return make(1); }
    __forceinline ULONG BA()  { return make(2); }
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
    __forceinline ULONG ABRT() { return make(42); }
    __forceinline ULONG ADBG() { return make(43); }
    __forceinline ULONG SRVT() { return make(44); }

    __forceinline ULONG ADMP() { return make(45); }
    __forceinline ULONG SRV2() { return make(46); }
    __forceinline ULONG RECU() { return make(47); }
    __forceinline ULONG TIRA() { return make(48); }
    __forceinline ULONG CANR() { return make(49); }
    __forceinline ULONG CANQ() { return make(50); }
    __forceinline ULONG DBGA() { return make(51); }
    __forceinline ULONG HVDT() { return make(52); }
    __forceinline ULONG RELA() { return make(53); }
}

namespace phase3_msg {

    struct latch_targeting_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT32 reason;
        UINT32 reserved;
    };
    static_assert(sizeof(latch_targeting_request_k) == 16, "latch_targeting_request_k must be 16 bytes");

    struct re_evidence_blob_k {
        UINT64 magic;
        UINT32 version;
        UINT32 signal_family;
        UINT32 signal_id;
        UINT32 score;
        UINT32 pid;
        UINT32 reserved0;
        UINT64 caller_image_hash;
        UINT64 signals_bitmap_hash;
        UINT64 timestamp;
    };
    static_assert(sizeof(re_evidence_blob_k) == 56, "re_evidence_blob_k must be 56 bytes");

    struct re_confirmed_usermode_request_k {
        UINT32 magic;
        UINT32 session_key;
        re_evidence_blob_k evidence;
    };
    static_assert(sizeof(re_confirmed_usermode_request_k) == 64, "re_confirmed_usermode_request_k must be 64 bytes");

    struct tier_a_query_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT32 present_flag;
        UINT32 tier_mask;
        UINT64 first_driver_base;
    };
    static_assert(sizeof(tier_a_query_request_k) == 24, "tier_a_query_request_k must be 24 bytes");

    struct canary_register_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT64 va;
        UINT64 size;
        UINT32 pid;
        UINT32 result;
    };
    static_assert(sizeof(canary_register_request_k) == 32, "canary_register_request_k must be 32 bytes");

    struct debug_attach_request_k {
        UINT32 magic;
        UINT32 session_key;
        UINT32 pid;
        UINT32 result_flags;
        UINT64 reserved;
    };
    static_assert(sizeof(debug_attach_request_k) == 24, "debug_attach_request_k must be 24 bytes");
}

namespace dispatcher {

    inline volatile LONG64 g_request_counter = 0;
    inline volatile LONG64 g_last_request_time = 0;
    inline volatile ULONG g_entropy_seed = 0x5A5A5A5Au;

    inline volatile LONG64 g_last_heartbeat_time = 0;
    inline volatile ULONG g_heartbeat_counter = 0;
    inline volatile ULONG g_session_key = 0;
    inline volatile LONG g_driver_activated = 0;

    inline volatile LONG64 g_server_token_time = 0;
    inline volatile ULONG g_server_token_hash = 0;
    constexpr LONG64 SERVER_TOKEN_TIMEOUT = 300000000LL;

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

        LONG64 srv_time = _InterlockedCompareExchange64(&g_server_token_time, 0, 0);
        if (srv_time != 0) {
            LONG64 srv_elapsed = current_time.QuadPart - srv_time;
            if (srv_elapsed > SERVER_TOKEN_TIMEOUT) {
                _InterlockedExchange64(&g_server_token_time, 0);
                _InterlockedExchange(&g_driver_activated, 0);
                caller_validation::unregister_client();
                return FALSE;
            }
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

        if (device_object && !verify_dispatch_integrity(device_object->DriverObject)) {
            _InterlockedExchange(&g_driver_activated, 0);
            caller_validation::unregister_client();
            irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }

        if (!check_rate_limit()) {
            irp->IoStatus.Status = STATUS_DEVICE_BUSY;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_DEVICE_BUSY;
        }


        {
            LONG64 last_hb = _InterlockedCompareExchange64(&g_last_heartbeat_time, 0, 0);
            if (last_hb != 0) {
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                LONG64 elapsed = now.QuadPart - last_hb;
                if (elapsed > HEARTBEAT_TIMEOUT) {
                    WW_LOG("Controller: session timed out (elapsed=%lld > %lld), resetting dynamic state for reconnection",
                        elapsed, (LONG64)HEARTBEAT_TIMEOUT);
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed), 0);
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&ioctl_codes::g_server_ioctl_seed), 0);
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_session_key), 0);
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_heartbeat_counter), 0);
                    _InterlockedExchange(&g_driver_activated, 0);
                    _InterlockedExchange64(&g_last_heartbeat_time, 0);
                    caller_validation::unregister_client();
                    secure_comm::reset();
                }
            }
        }

        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        ULONG bytes = 0;

        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

        const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        const ULONG input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
        const ULONG output_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PVOID buffer = irp->AssociatedIrp.SystemBuffer;
        PVOID original_buffer = buffer;
        PVOID secure_work_buffer = nullptr;
        BOOLEAN secure_wrapped = FALSE;
        UINT64 secure_request_entropy = 0;
        UINT64 secure_request_id = 0;

        if (!buffer) {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        if (code != ioctl_codes::HB() && secure_comm::g_comm_initialized != 0) {
            if (input_size < sizeof(secure_comm::SECURE_HEADER)) {
                irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                irp->IoStatus.Information = 0;
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }

            secure_comm::SECURE_HEADER sec_hdr{};
            RtlCopyMemory(&sec_hdr, buffer, sizeof(sec_hdr));
            secure_request_entropy = sec_hdr.entropy;
            secure_request_id = sec_hdr.request_id;

            SIZE_T work_size = output_size > input_size ? output_size : input_size;
            if (work_size < sizeof(secure_comm::SECURE_HEADER))
                work_size = sizeof(secure_comm::SECURE_HEADER);

            secure_work_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, work_size, 'mocS');
            if (!secure_work_buffer) {
                irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                irp->IoStatus.Information = 0;
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T plain_size = 0;
            if (!secure_comm::decrypt_request(buffer, input_size,
                secure_work_buffer, work_size, &plain_size)) {
                ExFreePoolWithTag(secure_work_buffer, 'mocS');
                irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                irp->IoStatus.Information = 0;
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }

            buffer = secure_work_buffer;
            secure_wrapped = TRUE;
        }

        if (code != ioctl_codes::HB() && code != ioctl_codes::SRVT() && code != ioctl_codes::SRV2() && !is_session_valid()) {
            if (secure_work_buffer)
                ExFreePoolWithTag(secure_work_buffer, 'mocS');
            irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        add_timing_noise();

        if (code == ioctl_codes::PRW()) {
            if (input_size >= sizeof(_PRW) && output_size >= sizeof(_PRW)) {
                status = functions::handle777e((p_physical_rw)buffer);
                bytes = sizeof(_PRW);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::BA()) {
            if (input_size >= sizeof(_BA) && output_size >= sizeof(_BA)) {
                status = functions::handle777f((p_base_address)buffer);
                bytes = sizeof(_BA);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DB()) {
            if (input_size >= sizeof(_DB) && output_size >= sizeof(_DB)) {
                status = functions::handle777d((p_dtb_solve)buffer);
                bytes = sizeof(_DB);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RC()) {
            if (input_size >= sizeof(_RC) && output_size >= sizeof(_RC)) {
                status = functions::handle7781((p_remote_call)buffer);
                bytes = sizeof(_RC);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::CR()) {
            if (input_size >= sizeof(_CR) && output_size >= sizeof(_CR)) {
                status = functions::handle7782((p_call_result)buffer);
                bytes = sizeof(_CR);
            }
            else if (input_size >= (sizeof(_CR) - sizeof(UINT64)) && output_size >= (sizeof(_CR) - sizeof(UINT64))) {
                status = functions::handle7782_legacy((p_call_result)buffer);
                bytes = sizeof(_CR) - sizeof(UINT64);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::AM()) {
            if (input_size >= sizeof(_AM) && output_size >= sizeof(_AM)) {
                status = functions::handle7783((p_alloc_mem)buffer);
                bytes = sizeof(_AM);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::FM()) {
            if (input_size >= sizeof(_FM) && output_size >= sizeof(_FM)) {
                status = functions::handle7784((p_free_mem)buffer);
                bytes = sizeof(_FM);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::TCTX()) {
            if (input_size >= sizeof(thread_ctx) && output_size >= sizeof(thread_ctx)) {
                status = functions::handle_thread_ctx((p_thread_ctx)buffer);
                bytes = sizeof(thread_ctx);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TENUM()) {
            if (input_size >= sizeof(thread_enum) && output_size >= sizeof(thread_enum)) {
                status = functions::handle_thread_enum((p_thread_enum)buffer);
                bytes = sizeof(thread_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TSR()) {
            if (input_size >= sizeof(suspend_resume_thread) && output_size >= sizeof(suspend_resume_thread)) {
                status = functions::handle_suspend_resume_thread((p_suspend_resume_thread)buffer);
                bytes = sizeof(suspend_resume_thread);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::QM()) {
            if (input_size >= sizeof(query_memory) && output_size >= sizeof(query_memory)) {
                status = functions::handle_query_memory((p_query_memory)buffer);
                bytes = sizeof(query_memory);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::PM()) {
            if (input_size >= sizeof(protect_memory) && output_size >= sizeof(protect_memory)) {
                status = functions::handle_protect_memory((p_protect_memory)buffer);
                bytes = sizeof(protect_memory);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::ER()) {
            if (input_size >= sizeof(enum_regions) && output_size >= sizeof(enum_regions)) {
                status = functions::handle_enum_regions((p_enum_regions)buffer);
                bytes = sizeof(enum_regions);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RPEB()) {
            if (input_size >= sizeof(read_peb) && output_size >= sizeof(read_peb)) {
                status = functions::handle_read_peb((p_read_peb)buffer);
                bytes = sizeof(read_peb);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SDF()) {
            if (input_size >= sizeof(spoof_debug) && output_size >= sizeof(spoof_debug)) {
                status = functions::handle_spoof_debug_flags((p_spoof_debug)buffer);
                bytes = sizeof(spoof_debug);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::MEX()) {
            if (input_size >= sizeof(module_export) && output_size >= sizeof(module_export)) {
                status = functions::handle_get_module_export((p_module_export)buffer);
                bytes = sizeof(module_export);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::V2P()) {
            if (input_size >= sizeof(virt_to_phys) && output_size >= sizeof(virt_to_phys)) {
                status = functions::handle_virt_to_phys((p_virt_to_phys)buffer);
                bytes = sizeof(virt_to_phys);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCON()) {
            if (input_size >= sizeof(net_enum_conn) && output_size >= sizeof(net_enum_conn)) {
                status = functions::handle_net_enum_conn((p_net_enum_conn)buffer);
                bytes = sizeof(net_enum_conn);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCAP()) {
            if (input_size >= sizeof(net_cap_ctrl) && output_size >= sizeof(net_cap_ctrl)) {
                status = functions::handle_net_cap_ctrl((p_net_cap_ctrl)buffer);
                bytes = sizeof(net_cap_ctrl);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCPG()) {
            if (input_size >= sizeof(net_cap_get) && output_size >= sizeof(net_cap_get)) {
                status = functions::handle_net_cap_get((p_net_cap_get)buffer);
                bytes = sizeof(net_cap_get);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NDNS()) {
            if (input_size >= sizeof(net_dns_get) && output_size >= sizeof(net_dns_get)) {
                status = functions::handle_net_dns_get((p_net_dns_get)buffer);
                bytes = sizeof(net_dns_get);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NFLT()) {
            if (input_size >= sizeof(net_filter_rule) && output_size >= sizeof(net_filter_rule)) {
                status = functions::handle_net_filter_rule((p_net_filter_rule)buffer);
                bytes = sizeof(net_filter_rule);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NSTS()) {
            if (input_size >= sizeof(net_stats) && output_size >= sizeof(net_stats)) {
                status = functions::handle_net_stats((p_net_stats)buffer);
                bytes = sizeof(net_stats);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::EWFP()) {
            if (input_size >= sizeof(wfp_callout_enum) && output_size >= sizeof(wfp_callout_enum)) {
                status = functions::handle_wfp_callout_enum((p_wfp_callout_enum)buffer);
                bytes = sizeof(wfp_callout_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::GSKT()) {
            if (input_size >= sizeof(socket_handle_enum) && output_size >= sizeof(socket_handle_enum)) {
                status = functions::handle_socket_handle_enum((p_socket_handle_enum)buffer);
                bytes = sizeof(socket_handle_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SNBF()) {
            if (input_size >= sizeof(sniff_net_buffers) && output_size >= sizeof(sniff_net_buffers)) {
                status = functions::handle_sniff_net_buffers((p_sniff_net_buffers)buffer);
                bytes = sizeof(sniff_net_buffers);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DTCP()) {
            if (input_size >= sizeof(tcpip_conn_dump) && output_size >= sizeof(tcpip_conn_dump)) {
                status = functions::handle_tcpip_conn_dump((p_tcpip_conn_dump)buffer);
                bytes = sizeof(tcpip_conn_dump);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::PINJ()) {
            if (input_size >= sizeof(packet_inject_request) && output_size >= sizeof(packet_inject_request)) {
                status = functions::handle_packet_inject((p_packet_inject_request)buffer);
                bytes = sizeof(packet_inject_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PMOD()) {
            if (input_size >= sizeof(packet_mod_rule_list) && output_size >= sizeof(packet_mod_rule_list) &&
                ((p_packet_mod_rule_list)buffer)->operation == 2) {
                status = functions::handle_packet_mod_rule_list((p_packet_mod_rule_list)buffer);
                bytes = sizeof(packet_mod_rule_list);
            }
            else if (input_size >= sizeof(packet_mod_rule) && output_size >= sizeof(packet_mod_rule)) {
                status = functions::handle_packet_mod_rule((p_packet_mod_rule)buffer);
                bytes = sizeof(packet_mod_rule);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PRED()) {
            if (input_size >= sizeof(traffic_redirect_list) && output_size >= sizeof(traffic_redirect_list) &&
                ((p_traffic_redirect_list)buffer)->operation == 2) {
                status = functions::handle_traffic_redirect_list((p_traffic_redirect_list)buffer);
                bytes = sizeof(traffic_redirect_list);
            }
            else if (input_size >= sizeof(traffic_redirect_rule) && output_size >= sizeof(traffic_redirect_rule)) {
                status = functions::handle_traffic_redirect((p_traffic_redirect_rule)buffer);
                bytes = sizeof(traffic_redirect_rule);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::STRM()) {
            if (input_size >= sizeof(stream_reassemble_request) && output_size >= sizeof(stream_reassemble_request)) {
                status = functions::handle_stream_reassemble((p_stream_reassemble_request)buffer);
                bytes = sizeof(stream_reassemble_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DPIN()) {
            if (input_size >= sizeof(dpi_request) && output_size >= sizeof(dpi_request)) {
                status = functions::handle_deep_inspect((p_dpi_request)buffer);
                bytes = sizeof(dpi_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::IHLD()) {
            if (input_size >= sizeof(intercept_request) && output_size >= sizeof(intercept_request)) {
                status = functions::handle_intercept_hold((p_intercept_request)buffer);
                bytes = sizeof(intercept_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CKIL()) {
            if (input_size >= sizeof(conn_kill_request) && output_size >= sizeof(conn_kill_request)) {
                status = functions::handle_conn_kill((p_conn_kill_request)buffer);
                bytes = sizeof(conn_kill_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DNSS()) {
            if (input_size >= sizeof(dns_spoof_list) && output_size >= sizeof(dns_spoof_list) &&
                ((p_dns_spoof_list)buffer)->operation == 2) {
                status = functions::handle_dns_spoof_list((p_dns_spoof_list)buffer);
                bytes = sizeof(dns_spoof_list);
            }
            else if (input_size >= sizeof(dns_spoof_rule) && output_size >= sizeof(dns_spoof_rule)) {
                status = functions::handle_dns_spoof((p_dns_spoof_rule)buffer);
                bytes = sizeof(dns_spoof_rule);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::BWMN()) {
            if (input_size >= sizeof(bw_monitor_request) && output_size >= sizeof(bw_monitor_request)) {
                status = functions::handle_bw_monitor((p_bw_monitor_request)buffer);
                bytes = sizeof(bw_monitor_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NIFS()) {
            if (input_size >= sizeof(net_interface_enum) && output_size >= sizeof(net_interface_enum)) {
                status = functions::handle_net_iface_enum((p_net_interface_enum)buffer);
                bytes = sizeof(net_interface_enum);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PCEX()) {
            if (input_size >= sizeof(pcap_export_request) && output_size >= sizeof(pcap_export_request)) {
                status = functions::handle_pcap_export((p_pcap_export_request)buffer);
                bytes = sizeof(pcap_export_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NFPR()) {
            if (input_size >= sizeof(net_fingerprint_request) && output_size >= sizeof(net_fingerprint_request)) {
                status = functions::handle_net_fingerprint((p_net_fingerprint_request)buffer);
                bytes = sizeof(net_fingerprint_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DPRT()) {
            if (input_size >= sizeof(dll_protect) && output_size >= sizeof(dll_protect)) {
                status = functions::handle_dll_protect((p_dll_protect)buffer);
                bytes = sizeof(dll_protect);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::ABRT()) {


            if (input_size >= sizeof(abort_request)) {
                p_abort_request abrt = (p_abort_request)buffer;
                ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0xABCD1234u;
                if (abrt->magic == expected_magic && g_driver_activated != 0) {
                    WW_LOG("ABRT: Tamper enforcement triggered reason=0x%lx evidence=0x%llx",
                        abrt->reason_code, abrt->evidence_hash);

                    BOOLEAN should_bsod = TRUE;
                    ULONG reason = abrt->reason_code;
                    bool is_re_reason =
                        (reason == sentinel_bridge::RE_REASON_GENERIC) ||
                        (reason == sentinel_bridge::RE_REASON_DEBUG_ATTACH) ||
                        (reason == sentinel_bridge::RE_REASON_DR_SET) ||
                        (reason == sentinel_bridge::RE_REASON_FOREIGN_HND) ||
                        (reason == sentinel_bridge::RE_REASON_INJECTED_DLL) ||
                        (reason == sentinel_bridge::RE_REASON_WATCHDOG_STALL) ||
                        (reason == 0x0002u);

                    if (is_re_reason) {
                        UINT32 det_flags = anti_debug::run_all_checks();
                        UINT64 dbg_pid = 0;
                        NTSTATUS scan_st = anti_debug::scan_for_debugger_processes(&dbg_pid);
                        BOOLEAN scan_hit = NT_SUCCESS(scan_st) && dbg_pid != 0;

                        if (det_flags == 0 && !scan_hit) {
                            static volatile LONG g_spurious_count = 0;
                            static volatile LONG64 g_spurious_window_tsc = 0;
                            LONG64 now_tsc = static_cast<LONG64>(__rdtsc());
                            LONG64 window = _InterlockedCompareExchange64(
                                &g_spurious_window_tsc, 0, 0);
                            constexpr LONG64 WINDOW_TSC = 30LL * 3000000000LL;
                            if (window == 0 || (now_tsc - window) > WINDOW_TSC) {
                                _InterlockedExchange64(&g_spurious_window_tsc, now_tsc);
                                _InterlockedExchange(&g_spurious_count, 1);
                                should_bsod = FALSE;
                            } else {
                                LONG c = _InterlockedIncrement(&g_spurious_count);
                                if (c < 3) {
                                    should_bsod = FALSE;
                                }
                            }
                            WW_LOG("ABRT: RE reason but no kernel confirmation, spurious=%ld should_bsod=%d",
                                g_spurious_count, (int)should_bsod);
                        } else {
                            WW_LOG("ABRT: RE reason confirmed by kernel det=0x%lx dbg_pid=%llu",
                                det_flags, dbg_pid);
                        }
                    }

                    if (should_bsod && _KeBugCheckEx) {
                        sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_PRE_BSOD_INTENT;
                        sentinel_bridge::g_bridge.sentinel_cmd_param = reason;

                        _KeBugCheckEx(
                            0xDEAD0001u,
                            (ULONG_PTR)abrt->reason_code,
                            (ULONG_PTR)abrt->evidence_hash,
                            (ULONG_PTR)abrt->timestamp,
                            (ULONG_PTR)g_session_key
                        );
                    }

                    status = STATUS_SUCCESS;
                } else {
                    WW_LOG("ABRT: REJECTED magic=0x%lx expected=0x%lx activated=%ld",
                        abrt->magic, expected_magic, g_driver_activated);
                    status = STATUS_ACCESS_DENIED;
                }
                bytes = sizeof(abort_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::ADBG()) {
            if (input_size >= sizeof(anti_debug_request) && output_size >= sizeof(anti_debug_request)) {
                status = functions::handle_anti_debug((p_anti_debug_request)buffer);
                bytes = sizeof(anti_debug_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::SRVT()) {
            if (input_size >= sizeof(server_token_relay) && output_size >= sizeof(server_token_relay)) {
                p_server_token_relay srvt = (p_server_token_relay)buffer;

                if (srvt->session_key == g_session_key) {
                    LARGE_INTEGER current_time;
                    KeQuerySystemTime(&current_time);

                    ULONG expected_hash = srvt->token_hash ^ dynamic_key::get() ^ (ULONG)(srvt->server_nonce & 0xFFFFFFFFu);
                    _InterlockedExchange((volatile LONG*)&g_server_token_hash, (LONG)expected_hash);
                    _InterlockedExchange64(&g_server_token_time, current_time.QuadPart);
                    _InterlockedExchange(&g_driver_activated, 1);
                    _InterlockedExchange64(&g_last_heartbeat_time, current_time.QuadPart);

                    srvt->result = 1;
                    status = STATUS_SUCCESS;
                } else {
                    srvt->result = 0;
                    status = STATUS_ACCESS_DENIED;
                }
                bytes = sizeof(server_token_relay);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::HB()) {
            if (input_size >= sizeof(_HB) && output_size >= sizeof(_HB)) {
                p_heartbeat hb = (p_heartbeat)buffer;

                ULONG expectedMagic = get_heartbeat_magic();

                WW_LOG("HB: received magic=0x%lx expected=0x%lx session_key=0x%lx",
                    hb->magic, expectedMagic, hb->session_key);

                if (hb->magic == expectedMagic) {
                    {
                        LARGE_INTEGER current_time;
                        KeQuerySystemTime(&current_time);

                        LONG existing_key = _InterlockedCompareExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key, 0);
                        if (existing_key != 0 && (ULONG)existing_key != hb->session_key) {
                            WW_LOG("HB: session key mismatch existing=0x%lx new=0x%lx, resetting",
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
                            sentinel_bridge::tick();
                            _InterlockedExchange(&g_driver_activated, 1);
                            hb->whoswho_tsc = (UINT64)sentinel_bridge::g_bridge.whoswho_tsc;
                            hb->sentinel_tsc = (UINT64)sentinel_bridge::g_bridge.sentinel_tsc;

                            if (existing_key == 0) {
                                WW_LOG("HB: first heartbeat, registering client, counter=%ld",
                                    g_heartbeat_counter);
                                caller_validation::register_client();

                                HANDLE caller_pid = PsGetCurrentProcessId();
                                UINT32 client_pid = (UINT32)(ULONG_PTR)caller_pid;
                                continuous_anti_debug::start(client_pid);
                                continuous_anti_dump::start(client_pid);
                                WW_LOG("HB: continuous anti-debug + anti-dump started for pid=%u", client_pid);
                            }

                            hb->response = (UINT64)g_heartbeat_counter ^ dynamic_key::get();


                            WW_LOG("HB: OK counter=%ld activated=%ld bridge_whoswho_tsc=%lld bridge_sentinel_tsc=%lld",
                                g_heartbeat_counter, g_driver_activated,
                                sentinel_bridge::g_bridge.whoswho_tsc,
                                sentinel_bridge::g_bridge.sentinel_tsc);
                            status = STATUS_SUCCESS;
                        } else {
                            WW_LOG("HB: ACCESS_DENIED existing_key=0x%lx hb_key=0x%lx",
                                (ULONG)existing_key, hb->session_key);
                            hb->response = 0;
                            hb->whoswho_tsc = 0;
                            hb->sentinel_tsc = 0;
                            status = STATUS_ACCESS_DENIED;
                        }
                    }
                } else {
                    WW_LOG("HB: INVALID_PARAMETER magic mismatch");
                    hb->response = 0;
                    hb->whoswho_tsc = 0;
                    hb->sentinel_tsc = 0;
                    status = STATUS_INVALID_PARAMETER;
                }
                bytes = sizeof(_HB);
            }
            else {
                WW_LOG("HB: INFO_LENGTH_MISMATCH input=%lu output=%lu", input_size, output_size);
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::ADMP()) {
            if (input_size >= sizeof(anti_dump_request) && output_size >= sizeof(anti_dump_request)) {
                status = functions::handle_anti_dump((p_anti_dump_request)buffer);
                bytes = sizeof(anti_dump_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::SRV2()) {
            if (input_size >= sizeof(server_token_relay_v2) && output_size >= sizeof(server_token_relay_v2)) {
                status = functions::handle_server_token_v2((p_server_token_relay_v2)buffer);


                bytes = sizeof(server_token_relay_v2);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::DBGA()) {
            if (input_size >= sizeof(phase3_msg::debug_attach_request_k) &&
                output_size >= sizeof(phase3_msg::debug_attach_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::debug_attach_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    ULONG pid = req->pid;
                    if (pid == 0)
                        pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                            caller_validation::g_registered_client_pid));

                    UINT32 flags = 0;
                    BOOLEAN kd_now = anti_debug::kd_transitioned_to_enabled();
                    if (kd_now) flags |= 0x1;

                    PEPROCESS proc = nullptr;
                    if (pid != 0 &&
                        NT_SUCCESS(PsLookupProcessByProcessId(
                            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &proc)) &&
                        proc) {
                        PVOID debug_port = nullptr;
                        __try {
                            debug_port = *reinterpret_cast<PVOID*>(
                                reinterpret_cast<UCHAR*>(proc) + 0x578);
                        } __except (EXCEPTION_EXECUTE_HANDLER) { debug_port = nullptr; }
                        if (debug_port) flags |= 0x2;
                        ObDereferenceObject(proc);
                    }

                    if (flags != 0) {
                        sentinel_bridge::populate_evidence_blob(
                            0x20u, sentinel_bridge::RE_REASON_DEBUG_ATTACH,
                            100, pid, 0, 0, flags);
                        ULONG cmd = sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND;
                        ULONG par = pid;
                        sentinel_bridge::bridge_encrypt_cmd(cmd, par);
                        _InterlockedExchange(
                            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                            static_cast<LONG>(cmd));
                        _InterlockedExchange(
                            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                            static_cast<LONG>(par));
                        if (_KeBugCheckEx) {
                            _KeBugCheckEx(
                                sentinel_bridge::BUGCHECK_RE_USERMODE_CONFIRMED,
                                sentinel_bridge::RE_REASON_DEBUG_ATTACH,
                                sentinel_bridge::g_evidence_blob_offset,
                                static_cast<ULONG_PTR>(pid),
                                static_cast<ULONG_PTR>(flags));
                        }
                    }
                    req->result_flags = flags;
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::debug_attach_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CANR()) {
            if (input_size >= sizeof(phase3_msg::canary_register_request_k) &&
                output_size >= sizeof(phase3_msg::canary_register_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::canary_register_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    ULONG pid = req->pid;
                    if (pid == 0)
                        pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
                            caller_validation::g_registered_client_pid));
                    req->result = anti_dma_canary::register_canary(req->va, req->size, pid) ? 1u : 0u;
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::canary_register_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CANQ()) {
            if (input_size >= sizeof(phase3_msg::canary_register_request_k) &&
                output_size >= sizeof(phase3_msg::canary_register_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::canary_register_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    req->result = anti_dma_canary::g_canary_count;
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::canary_register_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::TIRA()) {
            if (input_size >= sizeof(phase3_msg::tier_a_query_request_k) &&
                output_size >= sizeof(phase3_msg::tier_a_query_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::tier_a_query_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    req->present_flag      = anti_dma_canary::query_tier_a_preloaded() ? 1u : 0u;
                    req->tier_mask         = req->present_flag;
                    req->first_driver_base = 0;
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::tier_a_query_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::RECU()) {
            if (input_size >= sizeof(phase3_msg::re_confirmed_usermode_request_k) &&
                output_size >= sizeof(phase3_msg::re_confirmed_usermode_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::re_confirmed_usermode_request_k*>(buffer);
                if (req->session_key != g_session_key) {
                    status = STATUS_ACCESS_DENIED;
                } else {
                    sentinel_bridge::populate_evidence_blob(
                        req->evidence.signal_family,
                        req->evidence.signal_id,
                        req->evidence.score,
                        req->evidence.pid,
                        req->evidence.caller_image_hash,
                        req->evidence.signals_bitmap_hash,
                        req->evidence.timestamp);
                    ULONG cmd = sentinel_bridge::BRIDGE_CMD_RE_CONFIRMED_USERMODE;
                    ULONG par = req->evidence.pid;
                    sentinel_bridge::bridge_encrypt_cmd(cmd, par);
                    _InterlockedExchange(
                        reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                        static_cast<LONG>(cmd));
                    _InterlockedExchange(
                        reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                        static_cast<LONG>(par));
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(
                            sentinel_bridge::BUGCHECK_RE_USERMODE_CONFIRMED,
                            static_cast<ULONG_PTR>(req->evidence.signal_id),
                            (static_cast<ULONG_PTR>(req->evidence.score) << 32) |
                                req->evidence.signal_family,
                            static_cast<ULONG_PTR>(req->evidence.pid),
                            static_cast<ULONG_PTR>(req->evidence.signals_bitmap_hash));
                    }
                    status = STATUS_SUCCESS;
                }
                bytes = sizeof(phase3_msg::re_confirmed_usermode_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::HVDT()) {
            if (input_size >= sizeof(hv_detect_request_k) &&
                output_size >= sizeof(hv_detect_result_k)) {
                auto* req = reinterpret_cast<hv_detect_request_k*>(buffer);
                UNREFERENCED_PARAMETER(req);
                hv_detect_result_k result_buf{};
                status = hv_detect::handle_request(req, &result_buf);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(buffer, &result_buf, sizeof(hv_detect_result_k));
                }
                bytes = sizeof(hv_detect_result_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::RELA()) {
            if (input_size >= sizeof(phase3_msg::latch_targeting_request_k)) {
                auto* req = reinterpret_cast<phase3_msg::latch_targeting_request_k*>(buffer);
                ULONG expected_magic = g_session_key ^ dynamic_key::get() ^ 0x1A7C4B2Eu;
                if (req->magic == expected_magic && req->session_key == g_session_key) {
                    targeting_latch::latch_targeting(
                        req->reason,
                        (UINT64)(ULONG_PTR)caller_validation::g_registered_client_pid,
                        0, 0, 0
                    );
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_ACCESS_DENIED;
                }
                bytes = sizeof(phase3_msg::latch_targeting_request_k);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else {


            UINT32 base_key = dynamic_key::compute();

            UINT32 orig_server_seed = dynamic_key::g_server_seed;
            BOOLEAN was_seeded = (orig_server_seed != 0 || ioctl_codes::g_server_ioctl_seed != 0);
            if (was_seeded) {

                _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed), 0);
                _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
                UINT32 base_key_clean = dynamic_key::compute();
                ULONG base_ioctl_base = ((hash_build_key(base_key_clean) ^ secondary_hash(base_key_clean >> 3)) & 0x7FF) | 0x800;
                ULONG base_hb_code = 0x00220000u | ((base_ioctl_base + 8) << 2);

                if (code == base_hb_code && input_size >= sizeof(_HB) && output_size >= sizeof(_HB)) {
                    WW_LOG("HB-RECONNECT: detected fresh client using base IOCTL code 0x%lx (seeded was 0x%lx)",
                        base_hb_code, ioctl_codes::HB());

                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&ioctl_codes::g_server_ioctl_seed), 0);
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_session_key), 0);
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_heartbeat_counter), 0);
                    _InterlockedExchange(&g_driver_activated, 0);
                    _InterlockedExchange64(&g_last_heartbeat_time, 0);
                    caller_validation::unregister_client();
                    secure_comm::reset();


                    p_heartbeat hb = (p_heartbeat)buffer;
                    ULONG expectedMagic = 0xDEADBEEFu ^ base_key_clean;
                    WW_LOG("HB-RECONNECT: magic check received=0x%lx expected=0x%lx",
                        hb->magic, expectedMagic);

                    if (hb->magic == expectedMagic) {
                        LARGE_INTEGER current_time;
                        KeQuerySystemTime(&current_time);

                        _InterlockedExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key);
                        _InterlockedExchange64(&g_last_heartbeat_time, current_time.QuadPart);
                        _InterlockedIncrement((volatile LONG*)&g_heartbeat_counter);
                        sentinel_bridge::tick();
                        _InterlockedExchange(&g_driver_activated, 1);

                        WW_LOG("HB-RECONNECT: registering new client");
                        caller_validation::register_client();

                        HANDLE caller_pid = PsGetCurrentProcessId();
                        UINT32 client_pid = (UINT32)(ULONG_PTR)caller_pid;
                        continuous_anti_debug::start(client_pid);
                        continuous_anti_dump::start(client_pid);

                        hb->response = (UINT64)g_heartbeat_counter ^ dynamic_key::get();


                        WW_LOG("HB-RECONNECT: SUCCESS, session re-established");
                        status = STATUS_SUCCESS;
                    } else {
                        WW_LOG("HB-RECONNECT: magic mismatch, rejecting");
                        hb->response = 0;
                        status = STATUS_INVALID_PARAMETER;
                    }
                    bytes = sizeof(_HB);
                } else {

                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_server_seed),
                        static_cast<LONG>(orig_server_seed));
                    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&dynamic_key::g_cached_key), 0);
                    status = STATUS_INVALID_DEVICE_REQUEST;
                    bytes = 0;
                }
            } else {
                status = STATUS_INVALID_DEVICE_REQUEST;
                bytes = 0;
            }
        }

        add_timing_noise();

        if (secure_wrapped && NT_SUCCESS(status) && bytes > 0) {
            if (!secure_comm::encrypt_response(
                buffer,
                bytes,
                original_buffer,
                output_size,
                secure_request_entropy,
                secure_request_id)) {
                status = STATUS_ACCESS_DENIED;
                bytes = 0;
            } else {
                bytes += sizeof(secure_comm::SECURE_HEADER);
            }
        }

        if (secure_work_buffer)
            ExFreePoolWithTag(secure_work_buffer, 'mocS');

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = bytes;
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }
}
