#pragma once
#include <imports/Defs.h>


namespace dispatch_guard {


    constexpr ULONG MAX_DISPATCH_SLOTS = 28;


    constexpr ULONG PROLOGUE_SIZE = 16;

    struct dispatch_entry_t {
        PDRIVER_DISPATCH handler;
        UCHAR prologue[PROLOGUE_SIZE];
    };

    inline dispatch_entry_t g_snapshot[MAX_DISPATCH_SLOTS] = {};
    inline volatile PDRIVER_OBJECT g_target_driver_object = nullptr;
    inline volatile LONG g_initialized = 0;

    __forceinline bool snapshot(PDRIVER_OBJECT driver_object) {
        if (!driver_object || !_MmIsAddressValid(driver_object))
            return false;

        g_target_driver_object = driver_object;

        __try {
            for (ULONG i = 0; i < MAX_DISPATCH_SLOTS; i++) {
                PDRIVER_DISPATCH handler = driver_object->MajorFunction[i];
                g_snapshot[i].handler = handler;


                if (handler && _MmIsAddressValid(reinterpret_cast<PVOID>(handler))) {
                    RtlCopyMemory(g_snapshot[i].prologue,
                                  reinterpret_cast<PVOID>(handler),
                                  PROLOGUE_SIZE);
                } else {
                    RtlZeroMemory(g_snapshot[i].prologue, PROLOGUE_SIZE);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        _InterlockedExchange(&g_initialized, 1);
        return true;
    }


    __forceinline bool is_hook_instruction(UCHAR first_byte) {
        switch (first_byte) {
            case 0xE9:
            case 0xEB:
            case 0xFF:
            case 0x68:
            case 0xE8:
                return true;
            default:
                return false;
        }
    }

    __forceinline bool verify() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;

        PDRIVER_OBJECT drv_obj = (PDRIVER_OBJECT)g_target_driver_object;
        if (!drv_obj || !_MmIsAddressValid(drv_obj))
            return true;

        __try {
            for (ULONG i = 0; i < MAX_DISPATCH_SLOTS; i++) {
                PDRIVER_DISPATCH current_handler = drv_obj->MajorFunction[i];


                if (current_handler != g_snapshot[i].handler) {


                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(
                            0xDEAD5E02,
                            (ULONG_PTR)i,
                            (ULONG_PTR)g_snapshot[i].handler,
                            (ULONG_PTR)current_handler,
                            (ULONG_PTR)0
                        );
                    }
                    return false;
                }


                if (current_handler && _MmIsAddressValid(reinterpret_cast<PVOID>(current_handler))) {
                    UCHAR current_prologue[PROLOGUE_SIZE];
                    RtlCopyMemory(current_prologue,
                                  reinterpret_cast<PVOID>(current_handler),
                                  PROLOGUE_SIZE);

                    bool mismatch = false;
                    for (ULONG b = 0; b < PROLOGUE_SIZE; b++) {
                        if (current_prologue[b] != g_snapshot[i].prologue[b]) {
                            mismatch = true;
                            break;
                        }
                    }

                    if (mismatch) {
                        if (_KeBugCheckEx) {
                            _KeBugCheckEx(
                                0xDEAD5E02,
                                (ULONG_PTR)i,
                                (ULONG_PTR)current_handler,
                                (ULONG_PTR)current_prologue[0],
                                (ULONG_PTR)1
                            );
                        }
                        return false;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        return true;
    }
}
