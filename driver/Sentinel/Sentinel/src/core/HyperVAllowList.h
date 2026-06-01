#pragma once
#include <imports/Defs.h>
#include <intrin.h>

namespace hv_allow_list {

    inline volatile LONG g_checked = 0;
    inline volatile LONG g_is_ms_hv_root = 0;
    inline volatile LONG g_has_vbs = 0;

    __forceinline void detect_once() {
        if (_InterlockedCompareExchange(&g_checked, 0, 0) != 0)
            return;

        __try {
            struct {
                BOOLEAN SecureKernelRunning;
                BOOLEAN HvciEnabled;
                BOOLEAN HvciStrictMode;
                BOOLEAN DebugEnabled;
                BOOLEAN FirmwarePageProtection;
                BOOLEAN EncryptionKeyAvailable;
                BOOLEAN SpareFlags;
                BOOLEAN TrustletRunning;
                BOOLEAN HvciDisableAllowed;
                BOOLEAN Reserved[7];
            } ium = {};

            ULONG ret = 0;
            NTSTATUS st = ZwQuerySystemInformation(
                static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(0xA5),
                &ium, sizeof(ium), &ret);

            if (NT_SUCCESS(st) && (ium.SecureKernelRunning || ium.HvciEnabled)) {
                _InterlockedExchange(&g_has_vbs, 1);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        int regs[4] = {};
        __cpuid(regs, 1);
        if ((regs[2] & (1 << 31)) == 0) {
            _InterlockedExchange(&g_checked, 1);
            return;
        }

        __cpuid(regs, 0x40000000);
        char vendor[12];
        *reinterpret_cast<int*>(vendor + 0) = regs[1];
        *reinterpret_cast<int*>(vendor + 4) = regs[2];
        *reinterpret_cast<int*>(vendor + 8) = regs[3];

        const char expected[12] = {
            'M','i','c','r','o','s','o','f','t',' ','H','v'
        };
        bool ms_match = true;
        for (int i = 0; i < 12; i++) {
            if (vendor[i] != expected[i]) {
                ms_match = false;
                break;
            }
        }

        if (!ms_match) {
            _InterlockedExchange(&g_checked, 1);
            return;
        }

        __cpuid(regs, 0x40000001);
        if (static_cast<UINT32>(regs[0]) != 0x31237648u) {
            _InterlockedExchange(&g_checked, 1);
            return;
        }

        __cpuid(regs, 0x40000003);
        UINT32 part_priv = static_cast<UINT32>(regs[0]);
        constexpr UINT32 kAccessVpRuntime    = 1u << 0;
        constexpr UINT32 kAccessPartRefCount = 1u << 1;
        constexpr UINT32 kAccessHypercall    = 1u << 5;
        UINT32 required = kAccessVpRuntime | kAccessPartRefCount | kAccessHypercall;

        if ((part_priv & required) != required) {
            _InterlockedExchange(&g_checked, 1);
            return;
        }

        _InterlockedExchange(&g_is_ms_hv_root, 1);

        _InterlockedExchange(&g_checked, 1);
    }

    __forceinline BOOLEAN is_microsoft_hyperv_root() {
        detect_once();
        return _InterlockedCompareExchange(&g_is_ms_hv_root, 0, 0) != 0;
    }

    __forceinline BOOLEAN has_vbs_or_hvci() {
        detect_once();
        return _InterlockedCompareExchange(&g_has_vbs, 0, 0) != 0;
    }
}
