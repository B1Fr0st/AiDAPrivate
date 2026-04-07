#pragma once
#include <imports/Defs.h>


namespace object_guard {

    inline volatile LONG g_initialized = 0;


    __forceinline bool hide_device_and_symlink(PDRIVER_OBJECT target_driver_object) {
        if (!target_driver_object || !_MmIsAddressValid(target_driver_object))
            return false;

        __try {
            PDEVICE_OBJECT device = target_driver_object->DeviceObject;
            if (!device || !_MmIsAddressValid(device))
                return false;


            UCHAR* obj_header_addr = reinterpret_cast<UCHAR*>(device) - 0x30;

            if (_MmIsAddressValid(obj_header_addr)) {


                UCHAR info_mask = obj_header_addr[0x1A];
                if (info_mask & 0x02) {


                    device->Flags |= DO_DEVICE_INITIALIZING;
                }
            }

            _InterlockedExchange(&g_initialized, 1);
            return true;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    __forceinline bool init(PDRIVER_OBJECT target_driver_object) {
        return hide_device_and_symlink(target_driver_object);
    }
}
