#pragma once
#include <imports/Defs.h>
#include <core/TargetingLatch.h>

namespace debug_port_trap {

    __forceinline bool resolve_offsets(ULONG_PTR* debug_port_offset, ULONG_PTR* debug_object_offset)
    {
        *debug_port_offset = 0;
        *debug_object_offset = 0;

        RTL_OSVERSIONINFOW ver = {};
        ver.dwOSVersionInfoSize = sizeof(ver);
        if (!_RtlGetVersion || !NT_SUCCESS(_RtlGetVersion(&ver)))
            return false;

        if (ver.dwBuildNumber >= 26100) {
            *debug_port_offset = 0x308;
            return true;
        }
        if (ver.dwBuildNumber >= 19041) {
            *debug_port_offset = 0x578;
            return true;
        }
        if (ver.dwBuildNumber >= 17763) {
            *debug_port_offset = 0x550;
            return true;
        }
        return false;
    }

    __forceinline bool is_werfault_debugger(HANDLE client_pid)
    {
        if (!client_pid)
            return false;

        ULONG required_size = 0;
        ZwQuerySystemInformation(
            SystemProcessInformationInternal,
            nullptr, 0, &required_size);
        if (required_size == 0)
            return false;

        required_size += 0x10000;
        PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, required_size, 'wftD');
        if (!buffer)
            return false;

        NTSTATUS st = ZwQuerySystemInformation(
            SystemProcessInformationInternal,
            buffer, required_size, nullptr);
        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(buffer, 'wftD');
            return false;
        }

        bool found_werfault = false;
        ULONG offset = 0;
        ULONG safety = 2048;
        while (offset < required_size && safety-- > 0) {
            PSYSTEM_PROCESS_INFORMATION_ENTRY entry =
                reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_ENTRY>(
                    static_cast<UCHAR*>(buffer) + offset);
            if (entry->NextEntryOffset == 0 && entry->UniqueProcessId != client_pid)
                break;

            if (entry->UniqueProcessId == client_pid && entry->ImageName.Buffer) {
                __try {
                    UCHAR* img_name = PsGetProcessImageFileName(
                        reinterpret_cast<PEPROCESS>(
                            const_cast<void*>(static_cast<const void*>(entry))));
                    (void)img_name;

                    UNICODE_STRING werfault_name = RTL_CONSTANT_STRING(L"WerFault.exe");
                    if (entry->ImageName.Length == werfault_name.Length) {
                        PCWSTR buf = entry->ImageName.Buffer;
                        PCWSTR target = werfault_name.Buffer;
                        USHORT chars = entry->ImageName.Length / sizeof(WCHAR);
                        bool match = true;
                        for (USHORT i = 0; i < chars; ++i) {
                            WCHAR a = buf[i] | 0x20;
                            WCHAR b = target[i] | 0x20;
                            if (a != b) { match = false; break; }
                        }
                        if (match) {
                            found_werfault = true;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
                if (found_werfault)
                    break;
            }

            if (entry->NextEntryOffset == 0)
                break;
            offset += entry->NextEntryOffset;
        }

        ExFreePoolWithTag(buffer, 'wftD');

        if (found_werfault) {
            SN_LOG("debug_port_trap: WerFault.exe is debugger pid=%llu -- SKIP BSOD",
                (UINT64)(ULONG_PTR)client_pid);
            return true;
        }

        PEPROCESS proc = nullptr;
        st = PsLookupProcessByProcessId(client_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return false;

        __try {
            UCHAR* name = PsGetProcessImageFileName(proc);
            if (name) {
                const char* werfault_a = "WerFault.exe";
                ULONG i = 0;
                bool match = true;
                while (werfault_a[i]) {
                    char a = (char)(name[i] | 0x20);
                    char b = (char)(werfault_a[i] | 0x20);
                    if (a != b) { match = false; break; }
                    ++i;
                }
                if (match && name[i] == 0) {
                    found_werfault = true;
                    SN_LOG("debug_port_trap: WerFault.exe confirmed by PsGetProcessImageFileName pid=%llu",
                        (UINT64)(ULONG_PTR)client_pid);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        _ObfDereferenceObject(proc);
        return found_werfault;
    }

    __forceinline bool is_kernel_pointer(ULONG_PTR value)
    {
        return value >= 0xFFFF800000000000ull;
    }

    __forceinline ULONG_PTR read_eprocess_ptr(PEPROCESS proc, ULONG_PTR offset)
    {
        ULONG_PTR val = 0;
        __try {
            ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(proc) + offset;
            if (_MmIsAddressValid(reinterpret_cast<PVOID>(addr)))
                val = *reinterpret_cast<volatile ULONG_PTR*>(addr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            val = 0;
        }
        return val;
    }

    __forceinline void check(HANDLE client_pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;
        if (!client_pid)
            return;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(client_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return;

        __try {
            ULONG_PTR debug_port_offset = 0;
            ULONG_PTR debug_object_offset = 0;
            if (!resolve_offsets(&debug_port_offset, &debug_object_offset)) {
                _ObfDereferenceObject(proc);
                return;
            }

            ULONG_PTR debug_port = debug_port_offset ? read_eprocess_ptr(proc, debug_port_offset) : 0;
            ULONG_PTR debug_object = debug_object_offset ? read_eprocess_ptr(proc, debug_object_offset) : 0;

            if ((debug_port != 0 && is_kernel_pointer(debug_port)) ||
                (debug_object != 0 && is_kernel_pointer(debug_object))) {
                UINT64 pid_val = (UINT64)(ULONG_PTR)client_pid;
                UINT64 port_hash = debug_port ^ (debug_port >> 17);

                if (is_werfault_debugger(client_pid)) {
                    SN_LOG("debug_port_trap: DebugPort set by WerFault (crash dump) pid=%llu -- SKIP BSOD",
                        (UINT64)(ULONG_PTR)client_pid);
                    _ObfDereferenceObject(proc);
                    return;
                }

                targeting_latch::latch_targeting(
                    targeting_latch::RE_REASON_DEBUG_PORT_TRAP,
                    pid_val,
                    port_hash,
                    debug_object,
                    0
                );
#ifndef AIDA_DEV_MODE
                KeBugCheckEx(0xA1DA0005, (ULONG_PTR)client_pid, (ULONG_PTR)debug_port, 0, 0);
#endif
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        _ObfDereferenceObject(proc);
    }
}
