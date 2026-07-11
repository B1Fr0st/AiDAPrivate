#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include "CoreSecurity.h"
#include "SentinelBridge.h"
#include "TargetingLatch.h"
#include "Struct.h"
#include "DmaCanary.h"
#include "AntiDebug.h"
#include "impl/AntiDumpKernel.h"

namespace dll_protection {
    ULONG cleanup_for_pid(UINT32 pid);
    BOOLEAN has_tracked_pid(UINT32 pid);
}

namespace process_guard {

    inline PVOID g_ob_handle = nullptr;
    inline PVOID g_bridge_ob_handle = nullptr;
    inline volatile LONG g_initialized = 0;
    inline volatile UINT64 g_bridge_region_start = 0;
    inline volatile UINT64 g_bridge_region_end = 0;
    inline volatile LONG g_create_notify_registered = 0;
    inline volatile LONG g_thread_notify_registered = 0;

    inline volatile HANDLE g_known_re_tool_pids[16] = {};
    inline volatile LONG g_known_re_tool_pid_count = 0;
    inline KSPIN_LOCK g_re_tool_pid_lock = {};
    inline volatile LONG g_re_tool_pid_lock_init = 0;

    __forceinline void ensure_re_tool_pid_lock() {
        if (_InterlockedCompareExchange(&g_re_tool_pid_lock_init, 1, 0) == 0) {
            KeInitializeSpinLock(&g_re_tool_pid_lock);
        }
    }

    __forceinline bool is_known_re_tool_pid(HANDLE pid) {
        if (!pid)
            return false;
        ensure_re_tool_pid_lock();
        KIRQL old_irql;
        KeAcquireSpinLock(&g_re_tool_pid_lock, &old_irql);
        bool found = false;
        LONG count = g_known_re_tool_pid_count;
        if (count > 16) count = 16;
        for (LONG i = 0; i < count; ++i) {
            if (g_known_re_tool_pids[i] == pid) {
                found = true;
                break;
            }
        }
        KeReleaseSpinLock(&g_re_tool_pid_lock, old_irql);
        return found;
    }

    __forceinline void register_re_tool_pid(HANDLE pid) {
        if (!pid)
            return;
        ensure_re_tool_pid_lock();
        KIRQL old_irql;
        KeAcquireSpinLock(&g_re_tool_pid_lock, &old_irql);
        LONG count = g_known_re_tool_pid_count;
        if (count > 16) count = 16;
        for (LONG i = 0; i < count; ++i) {
            if (g_known_re_tool_pids[i] == pid) {
                KeReleaseSpinLock(&g_re_tool_pid_lock, old_irql);
                return;
            }
        }
        if (count < 16) {
            g_known_re_tool_pids[count] = pid;
            _InterlockedIncrement(&g_known_re_tool_pid_count);
        }
        KeReleaseSpinLock(&g_re_tool_pid_lock, old_irql);
    }

    __forceinline void unregister_re_tool_pid(HANDLE pid) {
        if (!pid)
            return;
        ensure_re_tool_pid_lock();
        KIRQL old_irql;
        KeAcquireSpinLock(&g_re_tool_pid_lock, &old_irql);
        LONG count = g_known_re_tool_pid_count;
        if (count > 16) count = 16;
        for (LONG i = 0; i < count; ++i) {
            if (g_known_re_tool_pids[i] == pid) {
                g_known_re_tool_pids[i] = g_known_re_tool_pids[count - 1];
                g_known_re_tool_pids[count - 1] = nullptr;
                _InterlockedDecrement(&g_known_re_tool_pid_count);
                break;
            }
        }
        KeReleaseSpinLock(&g_re_tool_pid_lock, old_irql);
    }

    __forceinline bool tracked_process_exit_needs_cleanup(
        UINT32 dying_pid,
        HANDLE registered,
        bool* out_registered_client,
        bool* out_canary_possible,
        bool* out_dprt_tracked,
        bool* out_adbg_target,
        bool* out_admp_target,
        bool* out_antidump_protected,
        bool* out_permitted_pid)
    {
        bool registered_client = registered &&
            reinterpret_cast<UINT64>(registered) == static_cast<UINT64>(dying_pid);
        bool canary_possible = anti_dma_canary::g_canary_count != 0;
        bool dprt_tracked = dll_protection::has_tracked_pid(dying_pid) ? true : false;
        bool adbg_target = continuous_anti_debug::g_target_pid == dying_pid;
        bool admp_target = continuous_anti_dump::g_target_pid == dying_pid;
        bool antidump_protected = anti_dump_kernel::g_protected_pid == dying_pid;
        bool permitted_pid = anti_dump_kernel::is_permitted_pid(dying_pid);

        if (out_registered_client) *out_registered_client = registered_client;
        if (out_canary_possible) *out_canary_possible = canary_possible;
        if (out_dprt_tracked) *out_dprt_tracked = dprt_tracked;
        if (out_adbg_target) *out_adbg_target = adbg_target;
        if (out_admp_target) *out_admp_target = admp_target;
        if (out_antidump_protected) *out_antidump_protected = antidump_protected;
        if (out_permitted_pid) *out_permitted_pid = permitted_pid;

        return registered_client ||
            canary_possible ||
            dprt_tracked ||
            adbg_target ||
            admp_target ||
            antidump_protected ||
            permitted_pid;
    }

    constexpr ACCESS_MASK DEBUG_GRADE_ACCESS =
        PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
        PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION;

    constexpr ULONG CALLER_CACHE_SIZE = 16;
    constexpr LONG64 CALLER_CACHE_TTL_100NS = 50000000LL;

    struct caller_cache_entry_t {
        HANDLE pid;
        LARGE_INTEGER last_time;
        UCHAR valid;
        UCHAR is_werfault;
        UCHAR is_allowlisted;
    };

    inline caller_cache_entry_t g_caller_cache[CALLER_CACHE_SIZE] = {};
    inline KSPIN_LOCK g_caller_cache_lock = {};
    inline volatile LONG g_caller_cache_lock_init = 0;

    __forceinline void ensure_caller_cache_lock() {
        if (_InterlockedCompareExchange(&g_caller_cache_lock_init, 1, 0) == 0) {
            KeInitializeSpinLock(&g_caller_cache_lock);
        }
    }

    __forceinline bool compute_caller_attrs_uncached(HANDLE caller_pid, bool* out_is_werfault, bool* out_is_allowlisted) {
        *out_is_werfault = false;
        *out_is_allowlisted = false;

        static const char* const ALLOWLIST[] = {
            "csrss", "services", "wininit", "lsass",
            "msmpeng", "securityheal", "werfault"
        };
        static const int ALLOWLIST_LENS[] = { 5, 8, 7, 5, 7, 12, 8 };
        constexpr int ALLOWLIST_COUNT = 7;

        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(caller_pid, &proc)) || !proc)
            return false;

        bool got_image = false;
        __try {
            UCHAR* img = PsGetProcessImageFileName(proc);
            if (img && _MmIsAddressValid(img)) {
                got_image = true;

                {
                    const char prefix[] = "werfault";
                    bool match = true;
                    for (int c = 0; c < 8; ++c) {
                        if ((char)(img[c] | 0x20) != prefix[c]) { match = false; break; }
                    }
                    if (match) *out_is_werfault = true;
                }

                for (int i = 0; i < ALLOWLIST_COUNT; ++i) {
                    const char* prefix = ALLOWLIST[i];
                    int plen = ALLOWLIST_LENS[i];
                    bool match = true;
                    for (int c = 0; c < plen; ++c) {
                        char a = (char)(img[c] | 0x20);
                        char b = (char)(prefix[c] | 0x20);
                        if (a != b) { match = false; break; }
                    }
                    if (match) { *out_is_allowlisted = true; break; }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            got_image = false;
            *out_is_werfault = false;
            *out_is_allowlisted = false;
        }

        _ObfDereferenceObject(proc);
        return got_image;
    }

    __forceinline void copy_unicode_for_log(PCUNICODE_STRING text, char* out, SIZE_T out_size) {
        if (!out || out_size == 0)
            return;
        out[0] = 0;
        if (!text || !text->Buffer || text->Length == 0) {
            const char none[] = "<none>";
            SIZE_T n = sizeof(none) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = none[i];
            out[n] = 0;
            return;
        }
        __try {
            USHORT chars = text->Length / sizeof(WCHAR);
            SIZE_T limit = out_size - 1;
            SIZE_T count = chars < limit ? chars : limit;
            for (SIZE_T i = 0; i < count; ++i) {
                WCHAR wc = text->Buffer[i];
                out[i] = (wc >= 32 && wc < 127) ? static_cast<char>(wc) : '?';
            }
            out[count] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const char bad[] = "<except>";
            SIZE_T n = sizeof(bad) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = bad[i];
            out[n] = 0;
        }
    }

    __forceinline void copy_process_image_for_log(HANDLE pid, char* out, SIZE_T out_size) {
        if (!out || out_size == 0)
            return;
        out[0] = 0;
        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(pid, &proc);
        if (!NT_SUCCESS(st) || !proc) {
            const char unknown[] = "<lookup_failed>";
            SIZE_T n = sizeof(unknown) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = unknown[i];
            out[n] = 0;
            return;
        }
        __try {
            UCHAR* img = PsGetProcessImageFileName(proc);
            if (img && _MmIsAddressValid(img)) {
                SIZE_T i = 0;
                for (; i + 1 < out_size && i < 15 && img[i] != 0; ++i)
                    out[i] = static_cast<char>(img[i]);
                out[i] = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const char bad[] = "<except>";
            SIZE_T n = sizeof(bad) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = bad[i];
            out[n] = 0;
        }
        if (out[0] == 0) {
            const char none[] = "<none>";
            SIZE_T n = sizeof(none) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = none[i];
            out[n] = 0;
        }
        _ObfDereferenceObject(proc);
    }

    __forceinline void copy_process_object_image_for_log(PEPROCESS proc, char* out, SIZE_T out_size) {
        if (!out || out_size == 0)
            return;
        out[0] = 0;
        if (!proc) {
            const char none[] = "<none>";
            SIZE_T n = sizeof(none) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = none[i];
            out[n] = 0;
            return;
        }
        __try {
            UCHAR* img = PsGetProcessImageFileName(proc);
            if (img && _MmIsAddressValid(img)) {
                SIZE_T i = 0;
                for (; i + 1 < out_size && i < 15 && img[i] != 0; ++i)
                    out[i] = static_cast<char>(img[i]);
                out[i] = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const char bad[] = "<except>";
            SIZE_T n = sizeof(bad) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = bad[i];
            out[n] = 0;
        }
        if (out[0] == 0) {
            const char unknown[] = "<unknown>";
            SIZE_T n = sizeof(unknown) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = unknown[i];
            out[n] = 0;
        }
    }

    __forceinline void query_caller_attrs(HANDLE caller_pid, bool* out_is_werfault, bool* out_is_allowlisted) {
        *out_is_werfault = false;
        *out_is_allowlisted = false;

        ensure_caller_cache_lock();

        LARGE_INTEGER now;
        KeQuerySystemTime(&now);

        KIRQL old_irql;
        KeAcquireSpinLock(&g_caller_cache_lock, &old_irql);

        ULONG hit_index = CALLER_CACHE_SIZE;
        for (ULONG i = 0; i < CALLER_CACHE_SIZE; ++i) {
            if (g_caller_cache[i].valid && g_caller_cache[i].pid == caller_pid) {
                hit_index = i;
                break;
            }
        }

        if (hit_index < CALLER_CACHE_SIZE) {
            LONG64 delta = now.QuadPart - g_caller_cache[hit_index].last_time.QuadPart;
            if (delta >= 0 && delta < CALLER_CACHE_TTL_100NS) {
                *out_is_werfault = g_caller_cache[hit_index].is_werfault != 0;
                *out_is_allowlisted = g_caller_cache[hit_index].is_allowlisted != 0;
                KeReleaseSpinLock(&g_caller_cache_lock, old_irql);
                return;
            }
        }

        KeReleaseSpinLock(&g_caller_cache_lock, old_irql);

        bool computed_wer = false;
        bool computed_allow = false;
        bool ok = compute_caller_attrs_uncached(caller_pid, &computed_wer, &computed_allow);

        *out_is_werfault = computed_wer;
        *out_is_allowlisted = computed_allow;

        if (!ok)
            return;

        KeAcquireSpinLock(&g_caller_cache_lock, &old_irql);

        ULONG slot = CALLER_CACHE_SIZE;
        for (ULONG i = 0; i < CALLER_CACHE_SIZE; ++i) {
            if (g_caller_cache[i].valid && g_caller_cache[i].pid == caller_pid) {
                slot = i;
                break;
            }
        }
        if (slot == CALLER_CACHE_SIZE) {
            for (ULONG i = 0; i < CALLER_CACHE_SIZE; ++i) {
                if (!g_caller_cache[i].valid) {
                    slot = i;
                    break;
                }
            }
        }
        if (slot == CALLER_CACHE_SIZE) {
            ULONG oldest = 0;
            LONG64 oldest_time = g_caller_cache[0].last_time.QuadPart;
            for (ULONG i = 1; i < CALLER_CACHE_SIZE; ++i) {
                if (g_caller_cache[i].last_time.QuadPart < oldest_time) {
                    oldest_time = g_caller_cache[i].last_time.QuadPart;
                    oldest = i;
                }
            }
            slot = oldest;
        }

        g_caller_cache[slot].pid = caller_pid;
        g_caller_cache[slot].last_time = now;
        g_caller_cache[slot].valid = 1;
        g_caller_cache[slot].is_werfault = computed_wer ? 1 : 0;
        g_caller_cache[slot].is_allowlisted = computed_allow ? 1 : 0;

        KeReleaseSpinLock(&g_caller_cache_lock, old_irql);
    }

    __forceinline bool is_allowlisted_system_caller(HANDLE caller_pid) {
        bool is_wer = false;
        bool is_allow = false;
        query_caller_attrs(caller_pid, &is_wer, &is_allow);
        return is_allow;
    }

    __forceinline bool is_werfault_caller(HANDLE caller_pid) {
        bool is_wer = false;
        bool is_allow = false;
        query_caller_attrs(caller_pid, &is_wer, &is_allow);
        return is_wer;
    }

    inline OB_PREOP_CALLBACK_STATUS NTAPI process_pre_callback(
        PVOID,
        POB_PRE_OPERATION_INFORMATION Info)
    {
        if (!Info || !Info->Object)
            return OB_PREOP_SUCCESS;

        if (Info->KernelHandle) {
            HANDLE kh_client_pid = caller_validation::g_registered_client_pid;

            if (!kh_client_pid) {
                HANDLE kh_caller_fc = PsGetCurrentProcessId();
                if (is_werfault_caller(kh_caller_fc))
                    return OB_PREOP_SUCCESS;
                if (is_allowlisted_system_caller(kh_caller_fc))
                    return OB_PREOP_SUCCESS;

                ACCESS_MASK kh_req_fc = 0;
                if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                    kh_req_fc = Info->Parameters->CreateHandleInformation.DesiredAccess;
                else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
                    kh_req_fc = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

                constexpr ACCESS_MASK KH_FAIL_CLOSED_STRIP =
                    PROCESS_TERMINATE | PROCESS_CREATE_THREAD |
                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                    PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME;

                if (kh_req_fc & KH_FAIL_CLOSED_STRIP) {
                    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~KH_FAIL_CLOSED_STRIP;
                    else
                        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~KH_FAIL_CLOSED_STRIP;

                    targeting_latch::latch_targeting(
                        sentinel_bridge::RE_REASON_FOREIGN_HND,
                        (UINT64)(ULONG_PTR)kh_caller_fc,
                        (UINT64)kh_req_fc, 0, 0);
                    WW_LOG("[THREAT] kernel_handle_fail_closed caller=%llu requested=0x%08X stripped=0x%08X",
                        (UINT64)(ULONG_PTR)kh_caller_fc, (UINT32)kh_req_fc, (UINT32)KH_FAIL_CLOSED_STRIP);
                }
                return OB_PREOP_SUCCESS;
            }

            HANDLE kh_target = PsGetProcessId(static_cast<PEPROCESS>(Info->Object));
            if (kh_target != kh_client_pid)
                return OB_PREOP_SUCCESS;

            HANDLE kh_caller = PsGetCurrentProcessId();
            if (kh_caller == kh_client_pid)
                return OB_PREOP_SUCCESS;

            if (is_werfault_caller(kh_caller))
                return OB_PREOP_SUCCESS;

            if (is_known_re_tool_pid(kh_caller)) {
                if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                    Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
                else
                    Info->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_FOREIGN_HND,
                    (UINT64)(ULONG_PTR)kh_caller, 0, 0, 0);
                WW_LOG("[THREAT] kernel_handle_re_tool caller=%llu stripped_all=1",
                    (UINT64)(ULONG_PTR)kh_caller);
                return OB_PREOP_SUCCESS;
            }

            ACCESS_MASK kh_requested = 0;
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                kh_requested = Info->Parameters->CreateHandleInformation.DesiredAccess;
            else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
                kh_requested = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

            bool kh_allowlisted = is_allowlisted_system_caller(kh_caller);

            if (kh_allowlisted) {
                constexpr ACCESS_MASK KH_ALLOWLIST_STRIP =
                    PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION;

                if (kh_requested & KH_ALLOWLIST_STRIP) {
                    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~KH_ALLOWLIST_STRIP;
                    else
                        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~KH_ALLOWLIST_STRIP;
                }
            } else {
                constexpr ACCESS_MASK KH_FULL_STRIP =
                    PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
                    PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION |
                    PROCESS_SET_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_VM_READ;

                if (kh_requested & KH_FULL_STRIP) {
                    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~KH_FULL_STRIP;
                    else
                        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~KH_FULL_STRIP;

                    targeting_latch::latch_targeting(
                        sentinel_bridge::RE_REASON_FOREIGN_HND,
                        (UINT64)(ULONG_PTR)kh_caller,
                        (UINT64)kh_requested, 0, 0);
                    WW_LOG("[THREAT] kernel_handle_strip caller=%llu requested=0x%08X stripped=0x%08X allowlisted=0",
                        (UINT64)(ULONG_PTR)kh_caller, (UINT32)kh_requested, (UINT32)KH_FULL_STRIP);
                }
            }
            return OB_PREOP_SUCCESS;
        }

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
        {
            HANDLE caller_pid_fc = PsGetCurrentProcessId();
            if (reinterpret_cast<UINT64>(caller_pid_fc) == 4)
                return OB_PREOP_SUCCESS;
            if (is_werfault_caller(caller_pid_fc))
                return OB_PREOP_SUCCESS;
            if (is_allowlisted_system_caller(caller_pid_fc))
                return OB_PREOP_SUCCESS;

            constexpr ACCESS_MASK HOSTILE_FAIL_CLOSED =
                PROCESS_TERMINATE | PROCESS_CREATE_THREAD |
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME;

            ACCESS_MASK requested_fc = 0;
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                requested_fc = Info->Parameters->CreateHandleInformation.DesiredAccess;
            else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
                requested_fc = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

            if (requested_fc & HOSTILE_FAIL_CLOSED) {
                if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                    Info->Parameters->CreateHandleInformation.DesiredAccess &= ~HOSTILE_FAIL_CLOSED;
                else
                    Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~HOSTILE_FAIL_CLOSED;

                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_OB_WRITE,
                    (UINT64)(ULONG_PTR)caller_pid_fc,
                    (UINT64)requested_fc,
                    0, 0
                );
            }
            return OB_PREOP_SUCCESS;
        }

        HANDLE target_pid = PsGetProcessId(static_cast<PEPROCESS>(Info->Object));
        if (target_pid != client_pid)
            return OB_PREOP_SUCCESS;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return OB_PREOP_SUCCESS;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return OB_PREOP_SUCCESS;

        if (is_known_re_tool_pid(caller_pid)) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
            return OB_PREOP_SUCCESS;
        }

        ACCESS_MASK requested = 0;
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            requested = Info->Parameters->CreateHandleInformation.DesiredAccess;
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            requested = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

        if (is_werfault_caller(caller_pid))
            return OB_PREOP_SUCCESS;

        constexpr ACCESS_MASK BASE_HOSTILE =
            PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
            PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION;
        constexpr ACCESS_MASK STRIP_READ = PROCESS_VM_READ;

        bool is_system = is_allowlisted_system_caller(caller_pid);

        ACCESS_MASK hostile_proc = BASE_HOSTILE;
        if (!is_system)
            hostile_proc |= PROCESS_DUP_HANDLE;

        if (requested & hostile_proc) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~(hostile_proc | STRIP_READ);
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(hostile_proc | STRIP_READ);

            if (!is_system) {
                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_OB_WRITE,
                    (UINT64)(ULONG_PTR)caller_pid,
                    (UINT64)requested,
                    0, 0
                );
            }
        } else if (requested & STRIP_READ) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIP_READ;
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIP_READ;
        }

        return OB_PREOP_SUCCESS;
    }

    inline OB_PREOP_CALLBACK_STATUS NTAPI thread_pre_callback(
        PVOID,
        POB_PRE_OPERATION_INFORMATION Info)
    {
        if (!Info || !Info->Object)
            return OB_PREOP_SUCCESS;

        if (Info->KernelHandle) {
            HANDLE kh_thr_client_pid = caller_validation::g_registered_client_pid;
            if (!kh_thr_client_pid)
                return OB_PREOP_SUCCESS;

            PEPROCESS kh_thr_owner = IoThreadToProcess(static_cast<PETHREAD>(Info->Object));
            if (!kh_thr_owner)
                return OB_PREOP_SUCCESS;

            HANDLE kh_thr_owner_pid = PsGetProcessId(kh_thr_owner);
            if (kh_thr_owner_pid != kh_thr_client_pid)
                return OB_PREOP_SUCCESS;

            HANDLE kh_thr_caller = PsGetCurrentProcessId();
            if (kh_thr_caller == kh_thr_client_pid)
                return OB_PREOP_SUCCESS;

            if (is_werfault_caller(kh_thr_caller))
                return OB_PREOP_SUCCESS;

            if (is_known_re_tool_pid(kh_thr_caller)) {
                if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                    Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
                else
                    Info->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_OB_SUSPEND,
                    (UINT64)(ULONG_PTR)kh_thr_caller, 0, 0, 0);
                WW_LOG("[THREAT] kernel_thread_handle_re_tool caller=%llu stripped_all=1",
                    (UINT64)(ULONG_PTR)kh_thr_caller);
                return OB_PREOP_SUCCESS;
            }

            ACCESS_MASK kh_thr_req = 0;
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                kh_thr_req = Info->Parameters->CreateHandleInformation.DesiredAccess;
            else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
                kh_thr_req = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

            constexpr ACCESS_MASK KH_THR_STRIP =
                THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
                THREAD_TERMINATE | THREAD_GET_CONTEXT;

            if (kh_thr_req & KH_THR_STRIP) {
                if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                    Info->Parameters->CreateHandleInformation.DesiredAccess &= ~KH_THR_STRIP;
                else
                    Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~KH_THR_STRIP;

                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_OB_SUSPEND,
                    (UINT64)(ULONG_PTR)kh_thr_caller,
                    (UINT64)kh_thr_req, 0, 0);
                WW_LOG("[THREAT] kernel_thread_handle_strip caller=%llu requested=0x%08X stripped=0x%08X",
                    (UINT64)(ULONG_PTR)kh_thr_caller, (UINT32)kh_thr_req, (UINT32)KH_THR_STRIP);
            }
            return OB_PREOP_SUCCESS;
        }

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return OB_PREOP_SUCCESS;

        PEPROCESS owner = IoThreadToProcess(static_cast<PETHREAD>(Info->Object));
        if (!owner)
            return OB_PREOP_SUCCESS;

        HANDLE thread_owner_pid = PsGetProcessId(owner);
        if (thread_owner_pid != client_pid)
            return OB_PREOP_SUCCESS;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return OB_PREOP_SUCCESS;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return OB_PREOP_SUCCESS;

        if (is_werfault_caller(caller_pid))
            return OB_PREOP_SUCCESS;

        ACCESS_MASK requested = 0;
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            requested = Info->Parameters->CreateHandleInformation.DesiredAccess;
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            requested = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

        constexpr ACCESS_MASK HOSTILE_THR =
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_TERMINATE;
        constexpr ACCESS_MASK STRIP_THR = HOSTILE_THR | THREAD_GET_CONTEXT;

        bool is_system = is_allowlisted_system_caller(caller_pid);

        if (requested & HOSTILE_THR) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIP_THR;
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIP_THR;

            if (!is_system) {
                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_OB_SUSPEND,
                    (UINT64)(ULONG_PTR)caller_pid,
                    (UINT64)requested,
                    0, 0
                );
            }
        } else if (requested & THREAD_GET_CONTEXT) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_GET_CONTEXT;
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_GET_CONTEXT;
        }

        return OB_PREOP_SUCCESS;
    }

    __forceinline void set_bridge_region(PVOID base, ULONG size)
    {
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge_region_start),
            reinterpret_cast<LONG64>(base));
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge_region_end),
            reinterpret_cast<LONG64>(static_cast<UINT8*>(base) + size));
    }

    inline OB_PREOP_CALLBACK_STATUS NTAPI bridge_pre_callback(
        PVOID,
        POB_PRE_OPERATION_INFORMATION Info)
    {
        if (!Info || !Info->Object)
            return OB_PREOP_SUCCESS;

        if (Info->KernelHandle) {
            HANDLE kh_br_client_pid = caller_validation::g_registered_client_pid;
            if (!kh_br_client_pid)
                return OB_PREOP_SUCCESS;

            HANDLE kh_br_caller = PsGetCurrentProcessId();
            if (kh_br_caller == kh_br_client_pid)
                return OB_PREOP_SUCCESS;

            if (is_werfault_caller(kh_br_caller))
                return OB_PREOP_SUCCESS;

            if (is_known_re_tool_pid(kh_br_caller)) {
                if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                    Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
                else
                    Info->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                return OB_PREOP_SUCCESS;
            }

            UINT64 br_start = g_bridge_region_start;
            UINT64 br_end = g_bridge_region_end;
            if (br_start == 0 || br_end == 0)
                return OB_PREOP_SUCCESS;

            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &=
                    ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE);
            else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &=
                    ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE);

            return OB_PREOP_SUCCESS;
        }

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return OB_PREOP_SUCCESS;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return OB_PREOP_SUCCESS;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return OB_PREOP_SUCCESS;

        UINT64 bridge_start = g_bridge_region_start;
        UINT64 bridge_end = g_bridge_region_end;
        if (bridge_start == 0 || bridge_end == 0)
            return OB_PREOP_SUCCESS;

        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            Info->Parameters->CreateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE);

        return OB_PREOP_SUCCESS;
    }

    inline VOID NTAPI thread_create_notify(
        HANDLE ProcessId,
        HANDLE ThreadId,
        BOOLEAN Create)
    {
        if (!Create)
            return;

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return;

        if (ProcessId != client_pid)
            return;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return;

        if (_KeBugCheckEx) {
            WW_LOG("[THREAT] thread_injection detected client_pid=%llu caller_pid=%llu thread_id=%llu",
                reinterpret_cast<UINT64>(client_pid),
                reinterpret_cast<UINT64>(caller_pid),
                reinterpret_cast<UINT64>(ThreadId));
            _KeBugCheckEx(0xA1DA0005,
                reinterpret_cast<ULONG_PTR>(caller_pid),
                reinterpret_cast<ULONG_PTR>(ProcessId),
                reinterpret_cast<ULONG_PTR>(ThreadId),
                0);
        }

        UNREFERENCED_PARAMETER(ThreadId);
    }


    inline VOID NTAPI create_process_notify(
        PEPROCESS Process,
        HANDLE ProcessId,
        PPS_CREATE_NOTIFY_INFO CreateInfo)
    {
        if (!CreateInfo) {
            UINT32 dying_pid = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(ProcessId));
            if (dying_pid != 0 && dying_pid != 4) {
                unregister_re_tool_pid((HANDLE)(ULONG_PTR)dying_pid);
                HANDLE registered = caller_validation::g_registered_client_pid;
                bool registered_client = false;
                bool canary_possible = false;
                bool dprt_tracked = false;
                bool adbg_target = false;
                bool admp_target = false;
                bool antidump_protected = false;
                bool permitted_pid = false;
                if (!tracked_process_exit_needs_cleanup(
                        dying_pid,
                        registered,
                        &registered_client,
                        &canary_possible,
                        &dprt_tracked,
                        &adbg_target,
                        &admp_target,
                        &antidump_protected,
                        &permitted_pid)) {
                    return;
                }

                char dying_image[32] = {};
                copy_process_object_image_for_log(Process, dying_image, sizeof(dying_image));
                ULONG cleared = canary_possible ? anti_dma_canary::cleanup_for_pid(dying_pid) : 0;
                ULONG dprt_cleared = dprt_tracked ? dll_protection::cleanup_for_pid(dying_pid) : 0;
                if (registered || cleared || dprt_cleared || adbg_target || admp_target || antidump_protected)
                    InvalidateDTBCache(dying_pid);
                if (adbg_target)
                    continuous_anti_debug::stop_if_target(dying_pid);
                if (registered_client)
                    context_guard::uninstall();
                if (admp_target)
                    continuous_anti_dump::stop_if_target(dying_pid);
                if (antidump_protected)
                    anti_dump_kernel::cleanup();
                BOOLEAN permitted_evicted = permitted_pid && anti_dump_kernel::remove_permitted_pid(dying_pid) ? TRUE : FALSE;
                WW_LOG("create_process_notify: pid=%u exited image='%s' current_pid=%llu irql=%lu canaries_cleared=%lu dprt_slots_cleared=%lu permitted_evict=%lu registered_client=%lu canary_possible=%lu dprt_tracked=%lu adbg_target=%lu admp_target=%lu antidump_protected=%lu",
                    dying_pid,
                    dying_image,
                    reinterpret_cast<UINT64>(PsGetCurrentProcessId()),
                    static_cast<ULONG>(KeGetCurrentIrql()),
                    cleared,
                    dprt_cleared,
                    static_cast<ULONG>(permitted_evicted ? 1 : 0),
                    static_cast<ULONG>(registered_client ? 1 : 0),
                    static_cast<ULONG>(canary_possible ? 1 : 0),
                    static_cast<ULONG>(dprt_tracked ? 1 : 0),
                    static_cast<ULONG>(adbg_target ? 1 : 0),
                    static_cast<ULONG>(admp_target ? 1 : 0),
                    static_cast<ULONG>(antidump_protected ? 1 : 0));
                if (registered_client) {
                    dispatcher::reset_dynamic_session_state("registered_client_exit", registered, cleared, FALSE);
                    WW_LOG("create_process_notify: registered client pid=%u exited, session reset (canaries_cleared=%lu)",
                        dying_pid, cleared);
                } else if (cleared) {
                    WW_LOG("create_process_notify: pid=%u exited, canaries_cleared=%lu",
                        dying_pid, cleared);
                }
                if (dprt_cleared) {
                    WW_LOG("create_process_notify: pid=%u exited, dprt_slots_cleared=%lu",
                        dying_pid, dprt_cleared);
                }
            }
            return;
        }

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return;


        HANDLE parent_pid = CreateInfo->ParentProcessId;
        HANDLE creator_pid = CreateInfo->CreatingThreadId.UniqueProcess;
        HANDLE creator_tid = CreateInfo->CreatingThreadId.UniqueThread;
        HANDLE current_pid = PsGetCurrentProcessId();
        char image_path[192] = {};
        char command_line[192] = {};
        char parent_image[32] = {};
        char creator_image[32] = {};
        copy_unicode_for_log(CreateInfo->ImageFileName, image_path, sizeof(image_path));
        copy_unicode_for_log(CreateInfo->CommandLine, command_line, sizeof(command_line));
        copy_process_image_for_log(parent_pid, parent_image, sizeof(parent_image));
        copy_process_image_for_log(creator_pid, creator_image, sizeof(creator_image));

        WW_LOG("create_process_notify: pid=%llu parent=%llu creator_pid=%llu creator_tid=%llu current_pid=%llu irql=%lu status=0x%08X parent_is_client=%lu parent_is_system=%lu image='%s' parent_image='%s' creator_image='%s' cmd='%s'",
            reinterpret_cast<UINT64>(ProcessId),
            reinterpret_cast<UINT64>(parent_pid),
            reinterpret_cast<UINT64>(creator_pid),
            reinterpret_cast<UINT64>(creator_tid),
            reinterpret_cast<UINT64>(current_pid),
            static_cast<ULONG>(KeGetCurrentIrql()),
            static_cast<ULONG>(CreateInfo->CreationStatus),
            static_cast<ULONG>(parent_pid == client_pid ? 1 : 0),
            static_cast<ULONG>(reinterpret_cast<UINT64>(parent_pid) == 4 ? 1 : 0),
            image_path,
            parent_image,
            creator_image,
            command_line);

        if (parent_pid == client_pid)
            return;

        if (reinterpret_cast<UINT64>(parent_pid) == 4)
            return;

        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            LONG hash_count = anti_debug::g_re_tool_hash_count;
            if (hash_count > 0 && KeGetCurrentIrql() == PASSIVE_LEVEL) {
                UINT8 file_hash[32] = {};
                NTSTATUS hash_status = anti_debug::compute_file_sha256(
                    CreateInfo->ImageFileName, file_hash);
                if (NT_SUCCESS(hash_status)) {
                    bool matched = anti_debug::match_re_tool_hash(file_hash);
                    if (matched) {
                        register_re_tool_pid(ProcessId);
                        WW_LOG("create_process_notify: re_tool_hash_match pid=%llu",
                            reinterpret_cast<UINT64>(ProcessId));
                        RtlSecureZeroMemory(file_hash, sizeof(file_hash));
                        return;
                    }
                }
                RtlSecureZeroMemory(file_hash, sizeof(file_hash));
            }
        }
    }

    inline NTSTATUS init()
    {
        if (_InterlockedCompareExchange(&g_initialized, 1, 0) != 0)
            return STATUS_ALREADY_REGISTERED;

        if (!_ObRegisterCallbacks) {
            WW_LOG("process_guard::init: ObRegisterCallbacks not resolved");
            _InterlockedExchange(&g_initialized, 0);
            return STATUS_NOT_SUPPORTED;
        }

        OB_OPERATION_REGISTRATION op_reg[2] = {};

        op_reg[0].ObjectType = PsProcessType;
        op_reg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        op_reg[0].PreOperation = process_pre_callback;
        op_reg[0].PostOperation = nullptr;

        op_reg[1].ObjectType = PsThreadType;
        op_reg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        op_reg[1].PreOperation = thread_pre_callback;
        op_reg[1].PostOperation = nullptr;

        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"321124");

        OB_CALLBACK_REGISTRATION cb_reg = {};
        cb_reg.Version = OB_FLT_REGISTRATION_VERSION;
        cb_reg.OperationRegistrationCount = 2;
        cb_reg.Altitude = altitude;
        cb_reg.RegistrationContext = nullptr;
        cb_reg.OperationRegistration = op_reg;

        NTSTATUS status = _ObRegisterCallbacks(&cb_reg, &g_ob_handle);

        if (!NT_SUCCESS(status)) {
            WW_LOG("process_guard::init: ObRegisterCallbacks FAILED status=0x%08lx", status);
            g_ob_handle = nullptr;
            _InterlockedExchange(&g_initialized, 0);
        } else {
            WW_LOG("process_guard::init: ObRegisterCallbacks OK handle=%p", g_ob_handle);
        }

        if (NT_SUCCESS(status) && g_bridge_region_start != 0)
        {
            OB_OPERATION_REGISTRATION bridge_op[1] = {};

            bridge_op[0].ObjectType = PsProcessType;
            bridge_op[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
            bridge_op[0].PreOperation = bridge_pre_callback;
            bridge_op[0].PostOperation = nullptr;

            UNICODE_STRING bridge_altitude;
            RtlInitUnicodeString(&bridge_altitude, L"321125");

            OB_CALLBACK_REGISTRATION bridge_cb = {};
            bridge_cb.Version = OB_FLT_REGISTRATION_VERSION;
            bridge_cb.OperationRegistrationCount = 1;
            bridge_cb.Altitude = bridge_altitude;
            bridge_cb.RegistrationContext = nullptr;
            bridge_cb.OperationRegistration = bridge_op;

            NTSTATUS bridge_st = _ObRegisterCallbacks(&bridge_cb, &g_bridge_ob_handle);
            if (!NT_SUCCESS(bridge_st)) {
                WW_LOG("process_guard::init: bridge ObRegisterCallbacks FAILED 0x%08lx", bridge_st);
                g_bridge_ob_handle = nullptr;
            }
        }


        if (NT_SUCCESS(status) && _PsSetCreateProcessNotifyRoutineEx)
        {
            NTSTATUS notify_st = _PsSetCreateProcessNotifyRoutineEx(
                create_process_notify, FALSE);
            if (NT_SUCCESS(notify_st)) {
                _InterlockedExchange(&g_create_notify_registered, 1);
                WW_LOG("process_guard::init: PsSetCreateProcessNotifyRoutineEx OK");
            } else {
                WW_LOG("process_guard::init: PsSetCreateProcessNotifyRoutineEx FAILED 0x%08lx", notify_st);
                status = notify_st;
            }
        }
        else if (NT_SUCCESS(status)) {
            WW_LOG("process_guard::init: PsSetCreateProcessNotifyRoutineEx missing");
            status = STATUS_PROCEDURE_NOT_FOUND;
        }

        if (NT_SUCCESS(status)) {
            NTSTATUS thr_st = PsSetCreateThreadNotifyRoutine(thread_create_notify);
            if (NT_SUCCESS(thr_st)) {
                _InterlockedExchange(&g_thread_notify_registered, 1);
                WW_LOG("process_guard::init: PsSetCreateThreadNotifyRoutine OK");
            } else {
                WW_LOG("process_guard::init: PsSetCreateThreadNotifyRoutine FAILED 0x%08lx", thr_st);
            }
        }

        return status;
    }

    inline void cleanup()
    {
        if (_InterlockedCompareExchange(&g_thread_notify_registered, 0, 1) == 1) {
            PsRemoveCreateThreadNotifyRoutine(thread_create_notify);
        }
        if (_InterlockedCompareExchange(&g_create_notify_registered, 0, 1) == 1) {
            if (_PsSetCreateProcessNotifyRoutineEx)
                _PsSetCreateProcessNotifyRoutineEx(create_process_notify, TRUE);
        }
        if (g_ob_handle && _ObUnRegisterCallbacks) {
            _ObUnRegisterCallbacks(g_ob_handle);
            g_ob_handle = nullptr;
        }
        if (g_bridge_ob_handle && _ObUnRegisterCallbacks) {
            _ObUnRegisterCallbacks(g_bridge_ob_handle);
            g_bridge_ob_handle = nullptr;
        }
        _InterlockedExchange(&g_initialized, 0);
    }

}

namespace anti_debug { namespace process_guard_fwd {
    __forceinline void register_re_tool_pid(HANDLE pid) {
        process_guard::register_re_tool_pid(pid);
    }
}}
