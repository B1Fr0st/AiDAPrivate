#include "../Functions.h"
#include "../../imports/Defs.h"
#include <ntddmou.h>

#ifndef MOUSE_MOVE_NOCOALESCE
#define MOUSE_MOVE_NOCOALESCE    0x08  
#endif

NTSTATUS functions::setup_mouclasscallback(PMOUSE_OBJECT mouse_obj) {
    if (!mouse_obj) {
        return STATUS_INVALID_PARAMETER;
    }

    if (mouse_obj->service_callback && mouse_obj->mouse_device) {
        return STATUS_SUCCESS;
    }

    UNICODE_STRING mouclass;
    _RtlInitUnicodeString(&mouclass, L"\\Driver\\MouClass");

    PDRIVER_OBJECT mouclass_obj = nullptr;
    NTSTATUS status = _ObReferenceObjectByName(
        &mouclass, 
        OBJ_CASE_INSENSITIVE, 
        nullptr, 
        0, 
        *IoDriverObjectType, 
        KernelMode, 
        nullptr, 
        (PVOID*)&mouclass_obj
    );
    
    if (!NT_SUCCESS(status) || !mouclass_obj) {
        return status;
    }

    UNICODE_STRING mouhid;
    _RtlInitUnicodeString(&mouhid, L"\\Driver\\MouHID");

    PDRIVER_OBJECT mouhid_obj = nullptr;
    status = _ObReferenceObjectByName(
        &mouhid, 
        OBJ_CASE_INSENSITIVE, 
        nullptr, 
        0, 
        *IoDriverObjectType, 
        KernelMode, 
        nullptr, 
        (PVOID*)&mouhid_obj
    );
    
    if (!NT_SUCCESS(status) || !mouhid_obj) {
        _ObfDereferenceObject(mouclass_obj);
        return status;
    }

    PDEVICE_OBJECT mouhid_device = mouhid_obj->DeviceObject;

    while (mouhid_device && !mouse_obj->service_callback)
    {
        PDEVICE_OBJECT mouclass_device = mouclass_obj->DeviceObject;

        while (mouclass_device && !mouse_obj->service_callback)
        {
            if (!mouclass_device->NextDevice && !mouse_obj->mouse_device)
            {
                mouse_obj->mouse_device = mouclass_device;
            }

            if (!mouhid_device->DeviceExtension || !mouhid_device->DeviceObjectExtension) {
                mouclass_device = mouclass_device->NextDevice;
                continue;
            }

            PULONG_PTR deviceobj_extension = (PULONG_PTR)mouhid_device->DeviceExtension;
            ULONG_PTR ext_start = (ULONG_PTR)mouhid_device->DeviceExtension;
            ULONG_PTR ext_end = (ULONG_PTR)mouhid_device->DeviceObjectExtension;

            if (ext_end <= ext_start) {
                mouclass_device = mouclass_device->NextDevice;
                continue;
            }

            ULONG_PTR deviceobj_ext_size = (ext_end - ext_start) / sizeof(ULONG_PTR);

            if (deviceobj_ext_size > 0x1000) {
                mouclass_device = mouclass_device->NextDevice;
                continue;
            }

            for (ULONG_PTR i = 0; i < deviceobj_ext_size - 1; i++)
            {
                __try {
                    ULONG_PTR first_value = deviceobj_extension[i];
                    ULONG_PTR second_value = deviceobj_extension[i + 1];

                    if (first_value == (ULONG_PTR)mouclass_device && 
                        second_value > (ULONG_PTR)mouclass_obj &&
                        _MmIsAddressValid((PVOID)second_value))
                    {
                        mouse_obj->service_callback = (MouseClassServiceCallback)second_value;
                        break;
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    break;
                }
            }

            mouclass_device = mouclass_device->NextDevice;
        }

        mouhid_device = mouhid_device->AttachedDevice;
    }

    if (!mouse_obj->mouse_device)
    {
        PDEVICE_OBJECT target_device = mouclass_obj->DeviceObject;
        while (target_device)
        {
            if (!target_device->NextDevice)
            {
                mouse_obj->mouse_device = target_device;
                break;
            }
            target_device = target_device->NextDevice;
        }
    }

    _ObfDereferenceObject(mouclass_obj);
    _ObfDereferenceObject(mouhid_obj);

    if (!mouse_obj->service_callback) {
        return STATUS_NOT_FOUND;
    }
    if (!mouse_obj->mouse_device) {
        return STATUS_DEVICE_NOT_READY;
    }

    return STATUS_SUCCESS;
}

#define _KeRaiseIrql(a,b) *(b) = _KfRaiseIrql(a)

static NTSTATUS EnsureMouseInitialized(PVOID* out_callback, PVOID* out_device) {
    PVOID callback = (PVOID)_InterlockedCompareExchangePointer((PVOID*)&g_mouse_callback, nullptr, nullptr);
    PVOID device = (PVOID)_InterlockedCompareExchangePointer((PVOID*)&g_mouse_device, nullptr, nullptr);
    
    if (callback && device) {
        *out_callback = callback;
        *out_device = device;
        return STATUS_SUCCESS;
    }
    
    if (_InterlockedCompareExchange(&g_mouse_init_lock, 1, 0) == 0) {
        MOUSE_OBJECT temp_mouse = { 0 };
        NTSTATUS status = functions::setup_mouclasscallback(&temp_mouse);
        
        if (NT_SUCCESS(status) && temp_mouse.service_callback && temp_mouse.mouse_device) {
            _InterlockedExchangePointer((PVOID*)&g_mouse_device, temp_mouse.mouse_device);
            KeMemoryBarrier();
            _InterlockedExchangePointer((PVOID*)&g_mouse_callback, (PVOID)temp_mouse.service_callback);
            
            *out_callback = (PVOID)temp_mouse.service_callback;
            *out_device = temp_mouse.mouse_device;
            
            _InterlockedExchange(&g_mouse_init_lock, 0);
            return STATUS_SUCCESS;
        }
        
        _InterlockedExchange(&g_mouse_init_lock, 0);
        return status;
    }
    
    for (int spin_count = 0; spin_count < 10000; spin_count++) {
        YieldProcessor();
        
        callback = (PVOID)_InterlockedCompareExchangePointer((PVOID*)&g_mouse_callback, nullptr, nullptr);
        device = (PVOID)_InterlockedCompareExchangePointer((PVOID*)&g_mouse_device, nullptr, nullptr);
        
        if (callback && device) {
            *out_callback = callback;
            *out_device = device;
            return STATUS_SUCCESS;
        }
        
        if (_InterlockedCompareExchange(&g_mouse_init_lock, 0, 0) == 0) {
            return EnsureMouseInitialized(out_callback, out_device);
        }
    }
    
    return STATUS_DEVICE_NOT_READY;
}

namespace mouse_guard {
    inline volatile ULONG g_mouse_entropy = 0xBADC0DEu;
    inline volatile ULONG64 g_last_move_time = 0;
    inline volatile ULONG g_move_count = 0;
    inline volatile ULONG64 g_last_input_tsc = 0;
    
    constexpr ULONG64 MIN_INPUT_INTERVAL = 2000000ULL;
    
    constexpr ULONG MAX_INPUTS_PER_SECOND = 200;
    
    __forceinline ULONG next_rand() {
        ULONG x = g_mouse_entropy ^ (ULONG)(__rdtsc() & 0xFFFFFFFFu);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        g_mouse_entropy = x;
        return x;
    }
    
    __forceinline void scatter() {
        ULONG x = next_rand();
        volatile ULONG spin = (x & 0x7) + 1;
        while (spin--) YieldProcessor();
    }
    
    __forceinline void add_micro_jitter(INT32* x, INT32* y) {
        ULONG r = next_rand();
        
        if ((r & 0xFF) < 77) {
            if (*x != 0) {
                *x += ((r >> 8) & 1) ? 1 : -1;
            }
        }
        
        r = next_rand();
        if ((r & 0xFF) < 77) {
            if (*y != 0) {
                *y += ((r >> 8) & 1) ? 1 : -1;
            }
        }
    }
    
    __forceinline BOOLEAN rate_check() {
        ULONG64 current = __rdtsc();
        ULONG64 last = g_last_input_tsc;
        
        if (last == 0) {
            g_last_input_tsc = current;
            g_move_count = 1;
            return TRUE;
        }
        
        if (current - last < MIN_INPUT_INTERVAL) {
            volatile ULONG spin = 16;
            while (spin--) YieldProcessor();
            return FALSE;
        }
        
        g_last_input_tsc = current;
        g_move_count++;
        
        if (g_move_count > MAX_INPUTS_PER_SECOND) {
            scatter();
            g_move_count = 0;
        }
        
        return TRUE;
    }
    
    __forceinline void add_timing_jitter() {
        ULONG r = next_rand();
        
        if ((r & 0xFF) < 51) {
            volatile ULONG extra = ((r >> 8) & 0x3);
            while (extra--) YieldProcessor();
        }
    }
}

NTSTATUS functions::handle7780(p_mouse_move req) {
    if (!req) {
        return STATUS_INVALID_PARAMETER;
    }
    
    mouse_guard::scatter();
    
    if (!mouse_guard::rate_check()) {
        return STATUS_SUCCESS;
    }

    PVOID callback = nullptr;
    PVOID device = nullptr;
    
    NTSTATUS status = EnsureMouseInitialized(&callback, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!_MmIsAddressValid(callback)) {
        return STATUS_INVALID_ADDRESS;
    }

    if (!_MmIsAddressValid(device)) {
        return STATUS_INVALID_ADDRESS;
    }
    
    KIRQL old_irql = KeGetCurrentIrql();
    BOOLEAN raised_irql = FALSE;
    if (old_irql < DISPATCH_LEVEL && _KfRaiseIrql && _KeLowerIrql) {
        old_irql = _KfRaiseIrql(DISPATCH_LEVEL);
        raised_irql = TRUE;
    }

    INT32 clamped_x = req->inputX;
    INT32 clamped_y = req->inputY;
    
    if (clamped_x != 0 || clamped_y != 0) {
        mouse_guard::add_micro_jitter(&clamped_x, &clamped_y);
    }
    
    const INT32 MAX_MOVE = 127;
    if (clamped_x > MAX_MOVE) clamped_x = MAX_MOVE;
    if (clamped_x < -MAX_MOVE) clamped_x = -MAX_MOVE;
    if (clamped_y > MAX_MOVE) clamped_y = MAX_MOVE;
    if (clamped_y < -MAX_MOVE) clamped_y = -MAX_MOVE;
    
    MOUSE_INPUT_DATA input = {};
    input.UnitId = 0;

    if (clamped_x != 0 || clamped_y != 0) {
        input.Flags = MOUSE_MOVE_RELATIVE | MOUSE_MOVE_NOCOALESCE;
    }
    
    input.ButtonFlags = (USHORT)req->buttonFlags;
    
    input.RawButtons = 0;
    if (req->buttonFlags & (MOUSE_LEFT_BUTTON_DOWN | MOUSE_LEFT_BUTTON_UP)) {
        input.RawButtons |= 0x01;
    }
    if (req->buttonFlags & (MOUSE_RIGHT_BUTTON_DOWN | MOUSE_RIGHT_BUTTON_UP)) {
        input.RawButtons |= 0x02;
    }
    if (req->buttonFlags & (MOUSE_MIDDLE_BUTTON_DOWN | MOUSE_MIDDLE_BUTTON_UP)) {
        input.RawButtons |= 0x04;
    }
    
    input.LastX = clamped_x;
    input.LastY = clamped_y;
    input.ExtraInformation = 0;

    mouse_guard::add_timing_jitter();

    ULONG consumed = 0;

    NTSTATUS result = STATUS_UNSUCCESSFUL;
    
    __try {
        ((MouseClassServiceCallback)callback)((PDEVICE_OBJECT)device, &input, (&input) + 1, &consumed);
        result = (consumed > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        result = STATUS_UNSUCCESSFUL;
    }
    
    mouse_guard::scatter();
    
    if (raised_irql && _KeLowerIrql) {
        _KeLowerIrql(old_irql);
    }

    return result;
}