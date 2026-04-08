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


    inline PLIST_ENTRY g_module_list_head = nullptr;
    inline volatile LONG g_module_list_initialized = 0;

    __forceinline bool init_module_list(PDRIVER_OBJECT sentinel_driver_object) {
        if (!sentinel_driver_object || !_MmIsAddressValid(sentinel_driver_object))
            return false;

        if (!sentinel_driver_object->DriverSection ||
            !_MmIsAddressValid(sentinel_driver_object->DriverSection))
            return false;


        PLDR_DATA_TABLE_ENTRY ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(
            sentinel_driver_object->DriverSection);
        g_module_list_head = &ldr->InLoadOrderModuleList;
        _InterlockedExchange(&g_module_list_initialized, 1);
        return true;
    }


    // Cached module range array — built once per verify() call, used for all
    // 28 dispatch slot checks. Previously, each mismatch walked the full module
    // list (up to 512 entries) independently, totalling up to 28 × 512 = 14,336
    // list node traversals per DPC tick. Now we walk once (512 max) and do 28
    // simple array lookups — a 96% reduction in linked-list traversal overhead.
    constexpr ULONG MAX_CACHED_MODULES = 256;

    struct module_range_t {
        ULONG_PTR base;
        ULONG     size;
    };

    __forceinline ULONG build_module_cache(module_range_t* cache, ULONG max_count) {
        if (!_InterlockedCompareExchange(&g_module_list_initialized, 1, 1))
            return 0;

        if (!g_module_list_head || !_MmIsAddressValid(g_module_list_head))
            return 0;

        ULONG count = 0;

        __try {
            PLIST_ENTRY entry = g_module_list_head->Flink;
            ULONG safety = 512;

            while (entry && entry != g_module_list_head && safety-- > 0 && count < max_count) {
                if (!_MmIsAddressValid(entry))
                    break;

                PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

                if (!_MmIsAddressValid(mod))
                    break;

                ULONG_PTR mod_base = reinterpret_cast<ULONG_PTR>(mod->DllBase);
                ULONG     mod_size = mod->SizeOfImage;

                if (mod_base && mod_size) {
                    cache[count].base = mod_base;
                    cache[count].size = mod_size;
                    count++;
                }

                entry = entry->Flink;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return count;
        }

        return count;
    }

    __forceinline bool is_address_in_cached_modules(PVOID address,
                                                     const module_range_t* cache,
                                                     ULONG count) {
        ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(address);
        if (addr < 0xFFFF800000000000ULL)
            return false;

        for (ULONG i = 0; i < count; i++) {
            if (addr >= cache[i].base && addr < cache[i].base + cache[i].size)
                return true;
        }
        return false;
    }

    // Legacy function retained for callers outside verify() that do one-off checks.
    __forceinline bool is_address_in_loaded_module(PVOID address) {
        module_range_t cache[MAX_CACHED_MODULES];
        ULONG count = build_module_cache(cache, MAX_CACHED_MODULES);
        return is_address_in_cached_modules(address, cache, count);
    }


    __forceinline PVOID resolve_hook_destination(const UCHAR* prologue, PVOID prologue_va) {
        if (!prologue || !prologue_va)
            return nullptr;

        ULONG_PTR ip = reinterpret_cast<ULONG_PTR>(prologue_va);


        if (prologue[0] == 0xE9) {
            INT32 disp = *reinterpret_cast<const INT32*>(&prologue[1]);
            return reinterpret_cast<PVOID>(ip + 5 + disp);
        }


        if (prologue[0] == 0x48 && prologue[1] == 0xB8 &&
            prologue[10] == 0xFF && prologue[11] == 0xE0) {
            ULONG_PTR target = *reinterpret_cast<const ULONG_PTR*>(&prologue[2]);
            return reinterpret_cast<PVOID>(target);
        }


        if (prologue[0] == 0xFF && prologue[1] == 0x25) {
            INT32 disp = *reinterpret_cast<const INT32*>(&prologue[2]);
            PVOID ptr_loc = reinterpret_cast<PVOID>(ip + 6 + disp);
            if (_MmIsAddressValid(ptr_loc)) {
                ULONG_PTR target = *reinterpret_cast<ULONG_PTR*>(ptr_loc);
                return reinterpret_cast<PVOID>(target);
            }
        }


        if (prologue[0] == 0xE8) {
            INT32 disp = *reinterpret_cast<const INT32*>(&prologue[1]);
            return reinterpret_cast<PVOID>(ip + 5 + disp);
        }

        return nullptr;
    }

    __forceinline bool snapshot(PDRIVER_OBJECT driver_object) {
        SN_LOG("dispatch_guard::snapshot: driver_object=%p", driver_object);
        if (!driver_object || !_MmIsAddressValid(driver_object)) {
            SN_LOG("dispatch_guard::snapshot: FAIL - invalid driver object");
            return false;
        }

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
            SN_LOG("dispatch_guard::snapshot: EXCEPTION");
            return false;
        }

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("dispatch_guard::snapshot: SUCCESS, %lu slots captured", MAX_DISPATCH_SLOTS);
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

        // Build the module cache ONCE for all 28 slot checks.
        // Previously each mismatch walked the linked list independently.
        module_range_t mod_cache[MAX_CACHED_MODULES];
        ULONG mod_count = build_module_cache(mod_cache, MAX_CACHED_MODULES);

        __try {
            for (ULONG i = 0; i < MAX_DISPATCH_SLOTS; i++) {
                PDRIVER_DISPATCH current_handler = drv_obj->MajorFunction[i];


                if (current_handler != g_snapshot[i].handler) {


                    if (is_address_in_cached_modules(reinterpret_cast<PVOID>(current_handler), mod_cache, mod_count)) {


                        snapshot(drv_obj);
                        return true;
                    }


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


                        PVOID hook_dest = resolve_hook_destination(
                            current_prologue,
                            reinterpret_cast<PVOID>(current_handler));

                        if (hook_dest && is_address_in_cached_modules(hook_dest, mod_cache, mod_count)) {
                            snapshot(drv_obj);
                            return true;
                        }

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
