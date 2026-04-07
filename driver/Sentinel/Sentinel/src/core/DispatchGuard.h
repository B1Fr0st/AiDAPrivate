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

    // PsLoadedModuleList head — used to distinguish anticheat hooks
    // (redirect into a legitimately-loaded kernel module) from attacker
    // hooks (redirect into pool memory or a manually-mapped driver).
    inline PLIST_ENTRY g_module_list_head = nullptr;
    inline volatile LONG g_module_list_initialized = 0;

    __forceinline bool init_module_list(PDRIVER_OBJECT sentinel_driver_object) {
        if (!sentinel_driver_object || !_MmIsAddressValid(sentinel_driver_object))
            return false;

        if (!sentinel_driver_object->DriverSection ||
            !_MmIsAddressValid(sentinel_driver_object->DriverSection))
            return false;

        // DriverSection points to a LDR_DATA_TABLE_ENTRY whose first
        // field (InLoadOrderModuleList) is a LIST_ENTRY linked into
        // PsLoadedModuleList.  We can use any entry as a traversal anchor.
        PLDR_DATA_TABLE_ENTRY ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(
            sentinel_driver_object->DriverSection);
        g_module_list_head = &ldr->InLoadOrderModuleList;
        _InterlockedExchange(&g_module_list_initialized, 1);
        return true;
    }

    // Walk PsLoadedModuleList to check whether `address` falls inside any
    // legitimately-loaded kernel module.  This runs at DISPATCH_LEVEL (DPC
    // context) so it must NOT call any Zw* or pageable APIs.  The walk is
    // bounded to 512 iterations and every pointer is validated before access.
    __forceinline bool is_address_in_loaded_module(PVOID address) {
        if (!_InterlockedCompareExchange(&g_module_list_initialized, 1, 1))
            return false;

        if (!g_module_list_head || !_MmIsAddressValid(g_module_list_head))
            return false;

        ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(address);
        if (addr < 0xFFFF800000000000ULL)
            return false;

        __try {
            PLIST_ENTRY entry = g_module_list_head->Flink;
            ULONG safety = 512;

            while (entry && entry != g_module_list_head && safety-- > 0) {
                if (!_MmIsAddressValid(entry))
                    break;

                PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

                if (!_MmIsAddressValid(mod))
                    break;

                ULONG_PTR mod_base = reinterpret_cast<ULONG_PTR>(mod->DllBase);
                ULONG     mod_size = mod->SizeOfImage;

                if (mod_base && mod_size &&
                    addr >= mod_base && addr < mod_base + mod_size) {
                    return true;
                }

                entry = entry->Flink;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return false;
    }

    // Attempt to resolve the target of a JMP/CALL hook at `prologue`.
    // Returns the destination address, or nullptr if the first bytes are not
    // a recognisable hook pattern.  Only handles the common inline-hook forms
    // seen in anticheat and attacker code.
    __forceinline PVOID resolve_hook_destination(const UCHAR* prologue, PVOID prologue_va) {
        if (!prologue || !prologue_va)
            return nullptr;

        ULONG_PTR ip = reinterpret_cast<ULONG_PTR>(prologue_va);

        // E9 xx xx xx xx — relative near JMP (most common hook form)
        if (prologue[0] == 0xE9) {
            INT32 disp = *reinterpret_cast<const INT32*>(&prologue[1]);
            return reinterpret_cast<PVOID>(ip + 5 + disp);
        }

        // 48 B8 xx xx xx xx xx xx xx xx; FF E0 — mov rax, imm64; jmp rax
        if (prologue[0] == 0x48 && prologue[1] == 0xB8 &&
            prologue[10] == 0xFF && prologue[11] == 0xE0) {
            ULONG_PTR target = *reinterpret_cast<const ULONG_PTR*>(&prologue[2]);
            return reinterpret_cast<PVOID>(target);
        }

        // FF 25 xx xx xx xx — jmp qword ptr [rip+disp32]
        if (prologue[0] == 0xFF && prologue[1] == 0x25) {
            INT32 disp = *reinterpret_cast<const INT32*>(&prologue[2]);
            PVOID ptr_loc = reinterpret_cast<PVOID>(ip + 6 + disp);
            if (_MmIsAddressValid(ptr_loc)) {
                ULONG_PTR target = *reinterpret_cast<ULONG_PTR*>(ptr_loc);
                return reinterpret_cast<PVOID>(target);
            }
        }

        // E8 xx xx xx xx — relative near CALL (less common for dispatch hooks)
        if (prologue[0] == 0xE8) {
            INT32 disp = *reinterpret_cast<const INT32*>(&prologue[1]);
            return reinterpret_cast<PVOID>(ip + 5 + disp);
        }

        return nullptr;
    }

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

                // ---- Pointer-swap detection ----
                if (current_handler != g_snapshot[i].handler) {
                    // The dispatch pointer was changed.  Anticheats do this by
                    // redirecting through their own loaded driver module.
                    // Attackers redirect into pool allocations or manually-mapped
                    // code that never appears in PsLoadedModuleList.
                    if (is_address_in_loaded_module(reinterpret_cast<PVOID>(current_handler))) {
                        // Legitimate loaded module (anticheat) — re-snapshot and
                        // continue monitoring.
                        snapshot(drv_obj);
                        return true;
                    }

                    // Rogue destination — attacker hook.
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

                // ---- Inline-hook (prologue patch) detection ----
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
                        // Prologue was patched — try to resolve where the hook
                        // redirects to.  If it goes into a loaded module
                        // (anticheat inline hook), re-snapshot.  Otherwise BSOD.
                        PVOID hook_dest = resolve_hook_destination(
                            current_prologue,
                            reinterpret_cast<PVOID>(current_handler));

                        if (hook_dest && is_address_in_loaded_module(hook_dest)) {
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
