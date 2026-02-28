#pragma once
#include <ntifs.h>
#include <intrin.h>

#include <function/Struct.h>
#include <function/Functions.h>
#include <function/CoreSecurity.h>
#include <function/AntiDebug.h>

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

        if (!buffer) {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        if (code != ioctl_codes::HB() && !is_session_valid()) {
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
        else if (code == ioctl_codes::MM()) {
            if (input_size >= sizeof(_MM)) {
                status = functions::handle7780((p_mouse_move)buffer);
                bytes = sizeof(_MM);
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
        else if (code == ioctl_codes::HB()) {
            if (input_size >= sizeof(_HB) && output_size >= sizeof(_HB)) {
                p_heartbeat hb = (p_heartbeat)buffer;
                
                ULONG expectedMagic = get_heartbeat_magic();
                
                if (hb->magic == expectedMagic) {
                    {
                        LARGE_INTEGER current_time;
                        KeQuerySystemTime(&current_time);
                    
                        LONG existing_key = _InterlockedCompareExchange((volatile LONG*)&g_session_key, (LONG)hb->session_key, 0);
                    
                        if (existing_key != 0 && (ULONG)existing_key != hb->session_key) {
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
                                caller_validation::register_client();
                            }
                        
                            hb->response = (UINT64)g_heartbeat_counter ^ dynamic_key::get();
                            status = STATUS_SUCCESS;
                        } else {
                            hb->response = 0;
                            status = STATUS_ACCESS_DENIED;
                        }
                    }
                } else {
                    hb->response = 0;
                    status = STATUS_INVALID_PARAMETER;
                }
                bytes = sizeof(_HB);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else {
            status = STATUS_INVALID_DEVICE_REQUEST;
            bytes = 0;
        }

        add_timing_noise();

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = bytes;
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }
}