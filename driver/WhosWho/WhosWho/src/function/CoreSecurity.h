#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"

#ifndef YieldProcessor
#define YieldProcessor() _mm_pause()
#endif

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _ReadWriteBarrier()
#endif

namespace device_names {

    inline wchar_t g_device_name[80] = L"\\Device\\WhosWho";
    inline wchar_t g_symlink_name[80] = L"\\DosDevices\\Global\\WhosWho";

    __forceinline BOOLEAN initialize_names() {
        return TRUE;
    }

    __forceinline const wchar_t* get_device_name() {
        return g_device_name;
    }

    __forceinline const wchar_t* get_symlink_name() {
        return g_symlink_name;
    }

}

namespace caller_validation {

    inline volatile HANDLE g_registered_client_pid = nullptr;

    __forceinline BOOLEAN register_client() {
        HANDLE pid = PsGetCurrentProcessId();
        _InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), pid);
        WW_LOG("CLIENT_REGISTER pid=%llu",
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(pid)));
        return TRUE;
    }

    __forceinline void unregister_client() {
        HANDLE prev = reinterpret_cast<HANDLE>(_InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), nullptr));
        if (prev != nullptr) {
            WW_LOG("CLIENT_UNREGISTER pid=%llu",
                static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(prev)));
        }
    }

    __forceinline BOOLEAN is_registered_client(HANDLE pid) {
        return pid != nullptr && pid == g_registered_client_pid;
    }
}
