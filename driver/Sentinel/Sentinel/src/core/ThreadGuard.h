#pragma once
#include <imports/Defs.h>
#include <core/TargetingLatch.h>
#include <core/Heartbeat.h>


namespace thread_guard {

    inline volatile UINT64 g_target_base = 0;
    inline volatile UINT64 g_target_size = 0;
    inline volatile HANDLE g_target_pid = nullptr;
    inline volatile LONG   g_initialized = 0;
    inline volatile LONG   g_not_initialized_logged = 0;


    inline volatile LONG   g_targeted_debug_strikes = 0;
    constexpr LONG         STRIKE_THRESHOLD = 10;

    inline NTSTATUS (NTAPI* _PsLookupThreadByThreadId)(HANDLE, PETHREAD*);
    inline volatile LONG g_thread_funcs_resolved = 0;

    __forceinline bool resolve_thread_funcs() {
        if (_InterlockedCompareExchange(&g_thread_funcs_resolved, 1, 0) == 1)
            return true;

        PVOID kernelBase = (PVOID)get_nt_base();
        if (!kernelBase) return false;

        *(PVOID*)&_PsLookupThreadByThreadId =
            GetProcAddress(kernelBase, (PCHAR)skCrypt("PsLookupThreadByThreadId"));

        SN_LOG("thread_guard: _PsLookupThreadByThreadId=%p", _PsLookupThreadByThreadId);
        return _PsLookupThreadByThreadId != nullptr;
    }

    __forceinline ULONG_PTR resolve_win32_start_address_offset() {
        RTL_OSVERSIONINFOW ver = {};
        ver.dwOSVersionInfoSize = sizeof(ver);
        if (!_RtlGetVersion || !NT_SUCCESS(_RtlGetVersion(&ver)))
            return 0;

        if (ver.dwBuildNumber >= 26100) return 0x560;
        if (ver.dwBuildNumber >= 22631) return 0x520;
        if (ver.dwBuildNumber >= 22000) return 0x4D0;
        if (ver.dwBuildNumber >= 19041) return 0x4D0;
        if (ver.dwBuildNumber >= 17763) return 0x4D0;
        return 0;
    }

    __forceinline UINT64 get_thread_start_address(PETHREAD thread) {
        ULONG_PTR offset = resolve_win32_start_address_offset();
        if (offset == 0)
            return 0;

        __try {
            UINT8* ethread = reinterpret_cast<UINT8*>(thread);
            ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(ethread + offset);
            if (_MmIsAddressValid(reinterpret_cast<PVOID>(addr))) {
                return *reinterpret_cast<volatile UINT64*>(addr);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        return 0;
    }

    __forceinline bool is_address_in_module_range(UINT64 addr) {
        if (!addr)
            return false;

        HANDLE prot_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&process_notify::g_protected_pid), 0, 0));
        if (!prot_pid)
            return false;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(prot_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return false;

        bool in_module = false;

        __try {
            KAPC_STATE apc_state;
            _KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(proc), &apc_state);

            PPEB peb = nullptr;
            if (_PsGetProcessPeb)
                peb = _PsGetProcessPeb(proc);
            else
                peb = *(PPEB*)((UINT8*)proc + 0x550);

            if (peb && _MmIsAddressValid(peb)) {
                PUM_PEB_LDR_DATA_X ldr = *(PUM_PEB_LDR_DATA_X*)((UINT8*)peb + 0x18);
                if (ldr && _MmIsAddressValid(ldr)) {
                    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
                    if (_MmIsAddressValid(head)) {
                        PLIST_ENTRY entry = head->Flink;
                        ULONG safety = 1024;
                        while (entry && entry != head && safety-- > 0) {
                            if (!_MmIsAddressValid(entry))
                                break;

                            PUM_LDR_DATA_TABLE_ENTRY_X mod =
                                CONTAINING_RECORD(entry, UM_LDR_DATA_TABLE_ENTRY_X, InLoadOrderModuleList);

                            if (_MmIsAddressValid(mod)) {
                                UINT64 base = reinterpret_cast<UINT64>(mod->DllBase);
                                ULONG size = mod->SizeOfImage;
                                if (base && size && addr >= base && addr < (base + size)) {
                                    in_module = true;
                                    break;
                                }
                            }
                            entry = entry->Flink;
                        }
                    }
                }
            }

            _KeUnstackDetachProcess(&apc_state);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("thread_guard: is_address_in_module_range EXCEPTION addr=0x%llx", addr);
        }

        _ObfDereferenceObject(proc);
        return in_module;
    }

    __forceinline void detect_remote_thread_injection(HANDLE ProcessId, HANDLE ThreadId) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;

        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return;

        if (!resolve_thread_funcs())
            return;

        HANDLE prot_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&process_notify::g_protected_pid), 0, 0));
        if (!prot_pid || ProcessId != prot_pid)
            return;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == prot_pid)
            return;
        if ((ULONG_PTR)caller_pid == 4)
            return;
        if ((ULONG_PTR)caller_pid == 0)
            return;

        PETHREAD thread = nullptr;
        NTSTATUS st = _PsLookupThreadByThreadId(ThreadId, &thread);
        if (!NT_SUCCESS(st) || !thread)
            return;

        UINT64 start_addr = get_thread_start_address(thread);
        _ObfDereferenceObject(thread);

        SN_LOG("thread_guard: REMOTE_THREAD pid=%llu tid=%llu start_addr=0x%llx caller=%llu",
            (UINT64)(ULONG_PTR)ProcessId,
            (UINT64)(ULONG_PTR)ThreadId,
            start_addr,
            (UINT64)(ULONG_PTR)caller_pid);

        if (start_addr == 0) {
            targeting_latch::latch_targeting(
                targeting_latch::RE_REASON_OB_CREATE_THREAD,
                (UINT64)(ULONG_PTR)caller_pid,
                (UINT64)(ULONG_PTR)ThreadId,
                0, 0
            );
            heartbeat::send_command(heartbeat::BRIDGE_CMD_SENTINEL_THREAD_INJECT,
                static_cast<ULONG>((ULONG_PTR)caller_pid & 0xFFFFFFFF));
            return;
        }

        bool in_module = is_address_in_module_range(start_addr);

        if (!in_module) {
            SN_LOG("thread_guard: INJECTION DETECTED start_addr=0x%llx NOT in module range -- BSOD",
                start_addr);

            targeting_latch::latch_targeting(
                targeting_latch::RE_REASON_OB_CREATE_THREAD,
                (UINT64)(ULONG_PTR)caller_pid,
                (UINT64)(ULONG_PTR)ThreadId,
                start_addr,
                0
            );

            heartbeat::send_command(heartbeat::BRIDGE_CMD_SENTINEL_THREAD_INJECT,
                static_cast<ULONG>((ULONG_PTR)caller_pid & 0xFFFFFFFF));

#ifndef AIDA_DEV_MODE
            if (_KeBugCheckEx) {
                _KeBugCheckEx(0xA1DA0006,
                    (ULONG_PTR)ProcessId,
                    (ULONG_PTR)ThreadId,
                    (ULONG_PTR)start_addr,
                    0);
            }
#endif
        }
    }

    __forceinline bool init(UINT64 target_base, UINT64 target_size) {
        SN_LOG("thread_guard::init: target_base=%p target_size=0x%llx", (PVOID)target_base, target_size);
        if (!target_base || !target_size) {
            SN_LOG("thread_guard::init: FAIL - null base or zero size");
            return false;
        }

        g_target_base = target_base;
        g_target_size = target_size;
        g_target_pid = PsGetCurrentProcessId();
        _InterlockedExchange(&g_not_initialized_logged, 0);
        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("thread_guard::init: SUCCESS");
        return true;
    }


    __forceinline ULONG_PTR NTAPI ipi_clear_callback(ULONG_PTR Context) {
        UNREFERENCED_PARAMETER(Context);

        __try {
            UINT64 dr0 = __readdr(0);
            UINT64 dr1 = __readdr(1);
            UINT64 dr2 = __readdr(2);
            UINT64 dr3 = __readdr(3);
            UINT64 dr7 = __readdr(7);

            UINT64 base = g_target_base;
            UINT64 end  = base + g_target_size;

            volatile LONG* flag = (volatile LONG*)Context;

            if (base && end > base) {
                const UINT64 drs[4] = { dr0, dr1, dr2, dr3 };
                for (UINT64 i = 0; i < 4; ++i) {
                    if (drs[i] >= base && drs[i] < end) {
                        if ((dr7 & 0x3000) != 0x3000) {
                            if (flag)
                                _InterlockedExchange(flag, 1);
                        }
                    }
                }
            }

            __writedr(0, 0);
            __writedr(1, 0);
            __writedr(2, 0);
            __writedr(3, 0);
            __writedr(7, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        return 0;
    }


    __forceinline void clear_debug_registers_current_cpu() {
        __try {
            __writedr(0, 0);
            __writedr(1, 0);
            __writedr(2, 0);
            __writedr(3, 0);
            __writedr(7, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("thread_guard::clear_current_cpu: EXCEPTION");
        }
    }

    __forceinline void record_targeted_debug_detection() {
        LONG strikes = _InterlockedIncrement(&g_targeted_debug_strikes);

        if (strikes >= STRIKE_THRESHOLD) {
            targeting_latch::latch_targeting(
                targeting_latch::RE_REASON_DR_ON_TEXT,
                g_target_base,
                g_target_size,
                static_cast<UINT64>(strikes),
                0
            );
        }
    }

    __forceinline bool check_and_clear_current_cpu() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1)) {
            if (_InterlockedCompareExchange(&g_not_initialized_logged, 1, 0) == 0)
                SN_LOG("thread_guard::current_cpu: not initialized, skip");
            return true;
        }

        bool targeted = false;
        UINT64 targeted_dr_value = 0;
        UINT64 targeted_dr_index = 0;
        UINT64 dr7_val = 0;
        __try {
            UINT64 dr0 = __readdr(0);
            UINT64 dr1 = __readdr(1);
            UINT64 dr2 = __readdr(2);
            UINT64 dr3 = __readdr(3);
            dr7_val = __readdr(7);

            UINT64 base = g_target_base;
            UINT64 end  = base + g_target_size;
            if (base && end > base) {
                const UINT64 drs[4] = { dr0, dr1, dr2, dr3 };
                for (UINT64 i = 0; i < 4; ++i) {
                    if (drs[i] >= base && drs[i] < end) {
                        if ((dr7_val & 0x3000) != 0x3000) {
                            targeted = true;
                            targeted_dr_value = drs[i];
                            targeted_dr_index = i;
                        }
                    }
                }
            }

            __writedr(0, 0);
            __writedr(1, 0);
            __writedr(2, 0);
            __writedr(3, 0);
            __writedr(7, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("thread_guard::current_cpu: EXCEPTION");
            return true;
        }

        if (targeted) {
            HANDLE pid = PsGetCurrentProcessId();
            KeBugCheckEx(0xA1DA0006, (ULONG_PTR)pid, (ULONG_PTR)targeted_dr_index,
                         (ULONG_PTR)targeted_dr_value, (ULONG_PTR)dr7_val);
        }

        _InterlockedExchange(&g_targeted_debug_strikes, 0);
        return true;
    }


    __forceinline bool ipi_clear_all_cpus() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1)) {
            if (_InterlockedCompareExchange(&g_not_initialized_logged, 1, 0) == 0)
                SN_LOG("thread_guard::ipi_clear: not initialized, skip");
            return true;
        }

        if (!_KeIpiGenericCall) {
            SN_LOG("thread_guard::ipi_clear: no _KeIpiGenericCall");
            return true;
        }

        volatile LONG targeted_debug_detected = 0;

        __try {
            _KeIpiGenericCall(
                (PKIPI_BROADCAST_WORKER)ipi_clear_callback,
                (ULONG_PTR)&targeted_debug_detected
            );
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("thread_guard::ipi_clear: EXCEPTION in IPI call");

            clear_debug_registers_current_cpu();
            return true;
        }

        if (_InterlockedCompareExchange(&targeted_debug_detected, 0, 0) != 0) {
            HANDLE pid = g_target_pid;
            KeBugCheckEx(0xA1DA0006, (ULONG_PTR)pid, 0, 0, 0);
        }


        _InterlockedExchange(&g_targeted_debug_strikes, 0);

        return true;
    }
}
