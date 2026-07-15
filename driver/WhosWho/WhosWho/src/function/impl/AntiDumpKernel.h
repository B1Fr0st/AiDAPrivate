#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <imports/Defs.h>
#include "../KernelLayout.h"
#include "../SentinelBridge.h"
#include "../TargetingLatch.h"
#include "../DmaDefense.h"

#ifndef POOL_FLAG_NON_PAGED_EXECUTE
#define POOL_FLAG_NON_PAGED_EXECUTE 0x00000040
#endif

namespace anti_dump_kernel { PVOID pattern_scan_ntoskrnl(const UINT8*, const bool*, SIZE_T); }

#include "PhysMemGuard.h"

namespace anti_dump_kernel {

    inline PVOID g_ob_handle = nullptr;
    inline volatile UINT32 g_protected_pid = 0;
    inline volatile LONG g_initialized = 0;
    inline volatile UINT64 g_blocks_count = 0;

    inline PVOID g_canary_page_addr = nullptr;
    inline UINT64 g_canary_pattern = 0;
    inline PMDL g_locked_mdls[32] = {};
    inline volatile LONG g_canary_initialized = 0;

    inline volatile LONG g_permitted_pids[8] = {};

    inline PVOID g_pMmCopyVirtualMemory = nullptr;
    inline volatile LONG g_mmcopy_resolved = 0;
    inline volatile UINT32 g_canary_crc32 = 0;
    inline volatile LONG g_kernel_dump_detected = 0;

    inline PVOID g_resolved_kestackattach = nullptr;
    inline PVOID g_resolved_keunstackdetach = nullptr;
    inline volatile LONG g_kestack_resolved = 0;
    inline volatile LONG g_keunstack_resolved = 0;

    inline volatile LONG g_foreign_attach_strike_pid = 0;
    inline volatile LONG g_foreign_attach_strike_count = 0;
    inline volatile LONG g_foreign_attach_detected = 0;
    inline volatile UINT64 g_foreign_attach_scan_count = 0;

    using fn_MmCopyVirtualMemory_t = NTSTATUS(*)(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, PSIZE_T);

    inline PVOID g_original_MmCopyVirtualMemory = nullptr;
    inline UINT8 g_saved_bytes_MmCopyVirtual[16] = {};
    inline PVOID g_trampoline_MmCopyVirtual = nullptr;
    inline volatile LONG g_mmcopy_hook_installed = 0;
    inline volatile LONG g_mmcopy_reentrancy_guard[MAXIMUM_PROCESSORS] = {};

    inline volatile LONG g_mmcopy_strike_pid = 0;
    inline volatile LONG g_mmcopy_strike_count = 0;

    constexpr ULONG MMCOPY_HOOK_COPY_SIZE  = 16;
    constexpr ULONG MMCOPY_HOOK_PATCH_SIZE = 14;
    constexpr ULONG MMCOPY_JUMP_BACK_SIZE  = 14;
    constexpr ULONG MMCOPY_TRAMPOLINE_SIZE = MMCOPY_HOOK_COPY_SIZE + MMCOPY_JUMP_BACK_SIZE;
    constexpr ULONG MMCOPY_TRAMPOLINE_TAG  = 'TCmM';

    PVOID pattern_scan_ntoskrnl(const UINT8* pattern, const bool* wildcard, SIZE_T pattern_len);

    typedef VOID (NTAPI* fn_ke_stack_attach)(PEPROCESS, PKAPC_STATE);
    typedef VOID (NTAPI* fn_ke_unstack_detach)(PKAPC_STATE);

    __forceinline PVOID resolve_kestackattachprocess_fallback()
    {
        if (_KeStackAttachProcess)
            return (PVOID)_KeStackAttachProcess;

        if (_InterlockedCompareExchange(&g_kestack_resolved, 0, 0) == 2)
            return g_resolved_kestackattach;

        LONG prev = _InterlockedCompareExchange(&g_kestack_resolved, 1, 0);
        if (prev == 2)
            return g_resolved_kestackattach;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_kestack_resolved, 0, 0) == 1)
                YieldProcessor();
            return g_resolved_kestackattach;
        }

        static const UINT8 pat1[] = {
            0x40, 0x53, 0x56, 0x57, 0x48, 0x83, 0xEC, 0x30,
            0x65, 0x48, 0x8B, 0x3C, 0x25
        };
        static const bool wc1[] = {
            false, false, false, false, false, false, false, false,
            false, false, false, false, false
        };
        PVOID found = pattern_scan_ntoskrnl(pat1, wc1, sizeof(pat1));
        if (found) {
            g_resolved_kestackattach = found;
            WW_LOG("anti_dump: KeStackAttachProcess resolved via pattern variant 1 (Win10) at %p", found);
        }

        if (!found) {
            static const UINT8 pat2[] = {
                0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0xC2, 0x33,
                0xD2, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83,
                0xC4, 0x28, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0x48, 0x89, 0x5C, 0x24, 0x00, 0x57
            };
            static const bool wc2[] = {
                false, false, false, false, false, false, false, false,
                false, false, true,  true,  true,  true,  false, false,
                false, false, false, false, false, false, false, false,
                false, false, false, false, true,  false
            };
            found = pattern_scan_ntoskrnl(pat2, wc2, sizeof(pat2));
            if (found) {
                g_resolved_kestackattach = found;
                WW_LOG("anti_dump: KeStackAttachProcess resolved via pattern variant 2 (Win11 24H2+) at %p", found);
            }
        }

        if (!found) {
            static const UINT8 pat3[] = {
                0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0xC2, 0x33,
                0xD2, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83,
                0xC4, 0x28, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0x40, 0x53, 0x48, 0x83, 0xEC, 0x20
            };
            static const bool wc3[] = {
                false, false, false, false, false, false, false, false,
                false, false, true,  true,  true,  true,  false, false,
                false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false,
                false, false, false, false, false, false
            };
            found = pattern_scan_ntoskrnl(pat3, wc3, sizeof(pat3));
            if (found) {
                g_resolved_kestackattach = found;
                WW_LOG("anti_dump: KeStackAttachProcess resolved via pattern variant 3 (Win11 23H2) at %p", found);
            }
        }

        if (!found) {
            WW_LOG("anti_dump: KeStackAttachProcess fallback resolution failed");
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_kestack_resolved, 2);
        return g_resolved_kestackattach;
    }

    __forceinline PVOID resolve_keunstackdetachprocess_fallback()
    {
        if (_KeUnstackDetachProcess)
            return (PVOID)_KeUnstackDetachProcess;

        if (_InterlockedCompareExchange(&g_keunstack_resolved, 0, 0) == 2)
            return g_resolved_keunstackdetach;

        LONG prev = _InterlockedCompareExchange(&g_keunstack_resolved, 1, 0);
        if (prev == 2)
            return g_resolved_keunstackdetach;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_keunstack_resolved, 0, 0) == 1)
                YieldProcessor();
            return g_resolved_keunstackdetach;
        }

        static const UINT8 pat1[] = {
            0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x41, 0x00,
            0x48, 0x83, 0xF8, 0x01
        };
        static const bool wc1[] = {
            false, false, false, false, false, false, false, true,
            false, false, false, false
        };
        PVOID found = pattern_scan_ntoskrnl(pat1, wc1, sizeof(pat1));
        if (found) {
            g_resolved_keunstackdetach = found;
            WW_LOG("anti_dump: KeUnstackDetachProcess resolved via pattern variant 1 (Win10) at %p", found);
        }

        if (!found) {
            static const UINT8 pat2[] = {
                0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x68, 0x48,
                0x8B, 0x41
            };
            static const bool wc2[] = {
                false, false, false, false, false, false, false, false,
                false, false
            };
            found = pattern_scan_ntoskrnl(pat2, wc2, sizeof(pat2));
            if (found) {
                g_resolved_keunstackdetach = found;
                WW_LOG("anti_dump: KeUnstackDetachProcess resolved via pattern variant 2 (Win11 24H2+) at %p", found);
            }
        }

        if (!found) {
            static const UINT8 pat3[] = {
                0x48, 0x83, 0xEC, 0x28, 0x33, 0xD2, 0xE8, 0x00,
                0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3,
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0x44, 0x89, 0x01
            };
            static const bool wc3[] = {
                false, false, false, false, false, false, false, true,
                true,  true,  true,  false, false, false, false, false,
                false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false,
                false, false, false
            };
            found = pattern_scan_ntoskrnl(pat3, wc3, sizeof(pat3));
            if (found) {
                g_resolved_keunstackdetach = found;
                WW_LOG("anti_dump: KeUnstackDetachProcess resolved via pattern variant 3 (Win11 23H2) at %p", found);
            }
        }

        if (!found) {
            WW_LOG("anti_dump: KeUnstackDetachProcess fallback resolution failed");
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_keunstack_resolved, 2);
        return g_resolved_keunstackdetach;
    }

    __forceinline fn_ke_stack_attach get_kestackattachprocess()
    {
        if (_KeStackAttachProcess)
            return (fn_ke_stack_attach)_KeStackAttachProcess;
        return (fn_ke_stack_attach)resolve_kestackattachprocess_fallback();
    }

    __forceinline fn_ke_unstack_detach get_keunstackdetachprocess()
    {
        if (_KeUnstackDetachProcess)
            return (fn_ke_unstack_detach)_KeUnstackDetachProcess;
        return (fn_ke_unstack_detach)resolve_keunstackdetachprocess_fallback();
    }

    __forceinline void ke_stack_attach(PEPROCESS proc, PKAPC_STATE apc)
    {
        auto fn = get_kestackattachprocess();
        if (fn) fn(proc, apc);
    }

    __forceinline void ke_unstack_detach(PKAPC_STATE apc)
    {
        auto fn = get_keunstackdetachprocess();
        if (fn) fn(apc);
    }

    __forceinline char lowercase_ascii_char(char ch)
    {
        if (ch >= 'A' && ch <= 'Z')
            return static_cast<char>(ch + ('a' - 'A'));
        return ch;
    }

    __forceinline bool image_file_name_equals_ascii(const UCHAR* image_name, const char* target)
    {
        if (!image_name || !target)
            return false;

        ULONG index = 0;
        __try {
            for (; index < 15; ++index) {
                char lhs = lowercase_ascii_char(static_cast<char>(image_name[index]));
                char rhs = lowercase_ascii_char(target[index]);
                if (rhs == '\0')
                    return lhs == '\0';
                if (lhs == '\0' || lhs != rhs)
                    return false;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return target[index] == '\0';
    }

    __forceinline bool image_file_name_is_supported_ida_host(const UCHAR* image_name)
    {
        static const char* supported_ida_hosts[] = {
            "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
            "idat.exe", "idat64.exe", "idaw.exe", "idaw64.exe"
        };
        for (int i = 0; i < static_cast<int>(sizeof(supported_ida_hosts) / sizeof(supported_ida_hosts[0])); ++i) {
            if (image_file_name_equals_ascii(image_name, supported_ida_hosts[i]))
                return true;
        }
        return false;
    }

    inline NTSTATUS hide_thread_object_from_debugger(PETHREAD thread)
    {
        if (!thread || !_ObOpenObjectByPointer || !_ZwSetInformationThread ||
            !PsThreadType || !*PsThreadType)
            return STATUS_NOT_SUPPORTED;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        HANDLE thread_handle = nullptr;
        NTSTATUS status = _ObOpenObjectByPointer(
            thread,
            OBJ_KERNEL_HANDLE,
            nullptr,
            THREAD_SET_INFORMATION,
            *PsThreadType,
            KernelMode,
            &thread_handle);
        if (!NT_SUCCESS(status))
            return status;

        status = _ZwSetInformationThread(
            thread_handle,
            0x11u,
            nullptr,
            0);
        _ZwClose(thread_handle);
        return status;
    }

    inline bool is_permitted_pid(UINT32 pid)
    {
        if (pid == 0) return false;
        for (int i = 0; i < 8; ++i) {
            if ((UINT32)_InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&g_permitted_pids[i]), 0, 0) == pid)
                return true;
        }
        return false;
    }

    inline bool add_permitted_pid(UINT32 pid)
    {
        if (pid == 0) return false;
        for (int i = 0; i < 8; ++i) {
            if ((UINT32)_InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&g_permitted_pids[i]), 0, 0) == pid)
                return true;
        }
        for (int i = 0; i < 8; ++i) {
            if (_InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&g_permitted_pids[i]),
                    (LONG)pid, 0) == 0) {
                return true;
            }
        }
        return false;
    }

    inline bool remove_permitted_pid(UINT32 pid)
    {
        if (pid == 0) return false;
        bool removed = false;
        for (int i = 0; i < 8; ++i) {
            if (_InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&g_permitted_pids[i]),
                    0, (LONG)pid) == (LONG)pid) {
                removed = true;
            }
        }
        return removed;
    }

    static OB_PREOP_CALLBACK_STATUS handle_pre_open(
        PVOID RegistrationContext,
        POB_PRE_OPERATION_INFORMATION OperationInfo)
    {
        UNREFERENCED_PARAMETER(RegistrationContext);

        if (!OperationInfo || !OperationInfo->Object)
            return OB_PREOP_SUCCESS;

        UINT32 prot_pid = g_protected_pid;
        if (prot_pid == 0)
            return OB_PREOP_SUCCESS;

        __try {
            PEPROCESS target = (PEPROCESS)OperationInfo->Object;
            HANDLE target_pid = PsGetProcessId(target);

            if ((UINT32)(ULONG_PTR)target_pid != prot_pid)
                return OB_PREOP_SUCCESS;

            PEPROCESS caller = PsGetCurrentProcess();
            HANDLE caller_pid = PsGetProcessId(caller);

            if ((UINT32)(ULONG_PTR)caller_pid == prot_pid)
                return OB_PREOP_SUCCESS;

            constexpr ACCESS_MASK DENY_MASK =
                PROCESS_VM_READ |
                PROCESS_VM_WRITE |
                PROCESS_VM_OPERATION |
                PROCESS_DUP_HANDLE |
                PROCESS_CREATE_THREAD |
                PROCESS_QUERY_INFORMATION;

            if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~DENY_MASK;
            }
            else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~DENY_MASK;
            }

            InterlockedIncrement64((volatile LONG64*)&g_blocks_count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return OB_PREOP_SUCCESS;
    }

    inline NTSTATUS register_handle_filter(UINT32 pid)
    {
        if (_InterlockedCompareExchange(&g_initialized, 1, 0) != 0)
            return STATUS_ALREADY_REGISTERED;

        g_protected_pid = pid;

        if (!_ObRegisterCallbacks)
            return STATUS_NOT_SUPPORTED;

        OB_OPERATION_REGISTRATION op_reg = {};
        op_reg.ObjectType = PsProcessType;
        op_reg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        op_reg.PreOperation = handle_pre_open;
        op_reg.PostOperation = nullptr;

        UNICODE_STRING altitude;
        WCHAR alt_buf[] = L"321124.5";
        altitude.Buffer = alt_buf;
        altitude.Length = sizeof(alt_buf) - sizeof(WCHAR);
        altitude.MaximumLength = sizeof(alt_buf);

        OB_CALLBACK_REGISTRATION cb_reg = {};
        cb_reg.Version = OB_FLT_REGISTRATION_VERSION;
        cb_reg.OperationRegistrationCount = 1;
        cb_reg.Altitude = altitude;
        cb_reg.RegistrationContext = nullptr;
        cb_reg.OperationRegistration = &op_reg;

        NTSTATUS status = _ObRegisterCallbacks(&cb_reg, &g_ob_handle);
        if (!NT_SUCCESS(status)) {
            g_protected_pid = 0;
            _InterlockedExchange(&g_initialized, 0);
            return status;
        }

        WW_LOG("anti_dump: handle filter active for pid=%u", pid);
        return STATUS_SUCCESS;
    }


    inline NTSTATUS hide_all_threads(UINT32 pid)
    {
        if (!_PsGetNextProcessThread) return STATUS_NOT_SUPPORTED;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status))
            return status;

        UINT32 hidden = 0;

        __try {
            PETHREAD thread = nullptr;
            while ((thread = _PsGetNextProcessThread(process, thread)) != nullptr) {
                NTSTATUS hs = hide_thread_object_from_debugger(thread);
                if (NT_SUCCESS(hs))
                    hidden++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(process);
        WW_LOG("anti_dump: hid %u threads for pid=%u", hidden, pid);
        return status;
    }


    inline NTSTATUS erase_pe_headers(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status))
            return status;

        PVOID base = _PsGetProcessSectionBaseAddress(process);
        if (!base) {
            ObDereferenceObject(process);
            return STATUS_NOT_FOUND;
        }

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT8*)base + dos->e_lfanew);

                ULONG old_prot = 0;
                PVOID prot_base = base;
                SIZE_T prot_size = 0x1000;

                status = _ZwProtectVirtualMemory(
                    ZwCurrentProcess(), &prot_base, &prot_size,
                    PAGE_READWRITE, &old_prot);

                if (NT_SUCCESS(status)) {
                    UINT64 tsc = __rdtsc();
                    UINT8* header_bytes = (UINT8*)base;
                    for (SIZE_T i = 2; i < 0x1000 && i < prot_size; ++i) {
                        tsc = tsc * 6364136223846793005ULL + 1442695040888963407ULL;
                        header_bytes[i] = (UINT8)(tsc >> 33);
                    }

                    dos->e_magic = 0;

                    _ZwProtectVirtualMemory(
                        ZwCurrentProcess(), &prot_base, &prot_size,
                        old_prot, &old_prot);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);

        WW_LOG("anti_dump: erased PE headers for pid=%u", pid);
        return status;
    }


    inline NTSTATUS setup_thread_notify(UINT32 pid)
    {
        g_protected_pid = pid;
        return STATUS_SUCCESS;
    }


    inline NTSTATUS corrupt_section_headers(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        PVOID base = _PsGetProcessSectionBaseAddress(process);
        if (!base) {
            ObDereferenceObject(process);
            return STATUS_NOT_FOUND;
        }

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            if (dos->e_magic != 0 && dos->e_magic != IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT8*)base + dos->e_lfanew);
                if (_MmIsAddressValid(nt) && nt->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG old_prot = 0;
                    SIZE_T sec_offset = (ULONG_PTR)IMAGE_FIRST_SECTION(nt) - (ULONG_PTR)base;
                    SIZE_T sec_size = nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
                    PVOID sec_base = (PVOID)IMAGE_FIRST_SECTION(nt);

                    status = _ZwProtectVirtualMemory(
                        ZwCurrentProcess(), &sec_base, &sec_size,
                        PAGE_READWRITE, &old_prot);

                    if (NT_SUCCESS(status)) {
                        UINT64 tsc = __rdtsc();
                        UINT8* sec_bytes = (UINT8*)IMAGE_FIRST_SECTION(nt);
                        for (SIZE_T i = 0; i < sec_size; ++i) {
                            tsc = tsc * 6364136223846793005ULL + 1442695040888963407ULL;
                            sec_bytes[i] = (UINT8)(tsc >> 33);
                        }
                        _ZwProtectVirtualMemory(
                            ZwCurrentProcess(), &sec_base, &sec_size,
                            old_prot, &old_prot);
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);
        return status;
    }

    inline NTSTATUS verify_headers_zeroed(UINT32 pid, p_admp_header_state out_state)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!out_state) return STATUS_INVALID_PARAMETER;

        out_state->dos_magic = 0;
        out_state->nt_signature = 0;
        out_state->first_section_va = 0;
        out_state->checksum = 0;
        out_state->headers_restored = 0;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        PVOID base = _PsGetProcessSectionBaseAddress(process);
        if (!base) {
            ObDereferenceObject(process);
            return STATUS_NOT_FOUND;
        }

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            out_state->dos_magic = dos->e_magic;

            UINT32 simple_checksum = dos->e_magic;
            LONG e_lfanew = dos->e_lfanew;

            if (e_lfanew > 0 && static_cast<UINT32>(e_lfanew) < 0x10000) {
                PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT8*)base + e_lfanew);
                if (_MmIsAddressValid(nt)) {
                    out_state->nt_signature = nt->Signature;
                    simple_checksum += nt->Signature;

                    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
                    if (_MmIsAddressValid(sec) && nt->FileHeader.NumberOfSections > 0) {
                        out_state->first_section_va = sec[0].VirtualAddress;
                        simple_checksum += sec[0].VirtualAddress;
                    }
                }
            }

            out_state->checksum = simple_checksum;

            if (out_state->dos_magic == IMAGE_DOS_SIGNATURE ||
                out_state->nt_signature == IMAGE_NT_SIGNATURE) {
                out_state->headers_restored = 1;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);
        return status;
    }

    inline NTSTATUS scramble_peb_loader_data(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PVOID peb_raw = _PsGetProcessPeb(process);
            if (peb_raw && _MmIsAddressValid(peb_raw)) {
                PVOID ldr = *(PVOID*)((UINT8*)peb_raw + 0x18);
                if (ldr && _MmIsAddressValid(ldr)) {
                    PLIST_ENTRY head = (PLIST_ENTRY)((UINT8*)ldr + 0x10);
                    PLIST_ENTRY entry = head->Flink;
                    int skip = 0;
                    for (int iter = 0; iter < 256 && entry && entry != head; ++iter, entry = entry->Flink) {
                        if (!_MmIsAddressValid(entry)) break;
                        if (skip++ < 2) continue;
                        UINT8* ldr_entry = (UINT8*)entry;

                        PUNICODE_STRING full_name = (PUNICODE_STRING)(ldr_entry + 0x48);
                        if (_MmIsAddressValid(full_name) &&
                            full_name->Buffer &&
                            _MmIsAddressValid(full_name->Buffer) &&
                            full_name->Length > 0) {
                            for (USHORT i = 0; i < full_name->Length / sizeof(WCHAR); ++i) {
                                full_name->Buffer[i] = L'\0';
                            }
                        }

                        PVOID* dll_base_ptr = (PVOID*)(ldr_entry + 0x30);
                        if (_MmIsAddressValid(dll_base_ptr)) {
                            *dll_base_ptr = nullptr;
                        }

                        ULONG* size_of_image_ptr = (ULONG*)(ldr_entry + 0x40);
                        if (_MmIsAddressValid(size_of_image_ptr)) {
                            *size_of_image_ptr = 0;
                        }

                        PUNICODE_STRING base_name = (PUNICODE_STRING)(ldr_entry + 0x58);
                        if (_MmIsAddressValid(base_name) &&
                            base_name->Buffer &&
                            _MmIsAddressValid(base_name->Buffer) &&
                            base_name->Length > 0) {
                            for (USHORT i = 0; i < base_name->Length / sizeof(WCHAR); ++i) {
                                base_name->Buffer[i] = L'\0';
                            }
                        }
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);
        return status;
    }


    __forceinline bool mmcopy_create_trampoline(PVOID target, PVOID* out_trampoline, UINT8* saved_bytes, ULONG saved_size)
    {
        if (!target || !out_trampoline || !saved_bytes || saved_size < MMCOPY_HOOK_COPY_SIZE)
            return false;
        if (!_MmIsAddressValid || !_MmIsAddressValid(target))
            return false;

        __try {
            RtlCopyMemory(saved_bytes, target, saved_size);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("anti_dump: mmcopy trampoline failed to save bytes at %p", target);
            return false;
        }

        PVOID trampoline = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, MMCOPY_TRAMPOLINE_SIZE, MMCOPY_TRAMPOLINE_TAG);
        if (!trampoline) {
            WW_LOG("anti_dump: mmcopy trampoline alloc failed size=%lu", MMCOPY_TRAMPOLINE_SIZE);
            return false;
        }

        RtlCopyMemory(trampoline, saved_bytes, saved_size);

        UINT8* jump_back = (UINT8*)trampoline + saved_size;
        UINT64 return_addr = (UINT64)target + saved_size;
        jump_back[0]  = 0x48;
        jump_back[1]  = 0xB8;
        *(UINT64*)(jump_back + 2) = return_addr;
        jump_back[10] = 0xFF;
        jump_back[11] = 0xE0;
        jump_back[12] = 0x90;
        jump_back[13] = 0x90;

        *out_trampoline = trampoline;

        WW_LOG("anti_dump: mmcopy trampoline created target=%p trampoline=%p return_addr=0x%llx",
            target, trampoline, return_addr);
        return true;
    }

    __forceinline bool mmcopy_write_inline_hook(PVOID target, PVOID hook_func)
    {
        if (!target || !hook_func)
            return false;
        if (!_MmIsAddressValid || !_MmIsAddressValid(target))
            return false;

        UINT8 hook_bytes[MMCOPY_HOOK_PATCH_SIZE];
        hook_bytes[0]  = 0x48;
        hook_bytes[1]  = 0xB8;
        *(UINT64*)(hook_bytes + 2) = (UINT64)hook_func;
        hook_bytes[10] = 0xFF;
        hook_bytes[11] = 0xE0;
        hook_bytes[12] = 0x90;
        hook_bytes[13] = 0x90;

        KIRQL old_irql = KeRaiseIrqlToDpcLevel();

        UINT64 cr0 = 0;
        __try {
            cr0 = __readcr0();
            __writecr0(cr0 & ~0x10000ULL);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KeLowerIrql(old_irql);
            WW_LOG("anti_dump: mmcopy hook failed to disable CR0.WP for target %p", target);
            return false;
        }

        __try {
            RtlCopyMemory(target, hook_bytes, MMCOPY_HOOK_PATCH_SIZE);
            KeMemoryBarrier();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            __try { __writecr0(cr0); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            KeLowerIrql(old_irql);
            WW_LOG("anti_dump: mmcopy hook failed to write bytes at %p", target);
            return false;
        }

        __try {
            __writecr0(cr0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        KeLowerIrql(old_irql);

        __try {
            __wbinvd();
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        WW_LOG("anti_dump: mmcopy inline hook written at %p -> %p", target, hook_func);
        return true;
    }

    __forceinline bool mmcopy_remove_inline_hook(PVOID target, const UINT8* saved_bytes, ULONG saved_size)
    {
        if (!target || !saved_bytes || saved_size == 0)
            return false;
        if (!_MmIsAddressValid || !_MmIsAddressValid(target))
            return false;

        KIRQL old_irql = KeRaiseIrqlToDpcLevel();

        UINT64 cr0 = 0;
        __try {
            cr0 = __readcr0();
            __writecr0(cr0 & ~0x10000ULL);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KeLowerIrql(old_irql);
            WW_LOG("anti_dump: mmcopy unhook failed to disable CR0.WP for target %p", target);
            return false;
        }

        __try {
            RtlCopyMemory(target, saved_bytes, MMCOPY_HOOK_PATCH_SIZE);
            KeMemoryBarrier();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            __try { __writecr0(cr0); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            KeLowerIrql(old_irql);
            WW_LOG("anti_dump: mmcopy unhook failed to restore bytes at %p", target);
            return false;
        }

        __try {
            __writecr0(cr0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        KeLowerIrql(old_irql);

        __try {
            __wbinvd();
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        WW_LOG("anti_dump: mmcopy inline hook removed at %p", target);
        return true;
    }

    inline NTSTATUS NTAPI Hook_MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T Size,
        PSIZE_T Result)
    {
        ULONG cpu = KeGetCurrentProcessorNumber();
        if (cpu < MAXIMUM_PROCESSORS) {
            if (_InterlockedCompareExchange(&g_mmcopy_reentrancy_guard[cpu], 1, 0) != 0) {
                if (g_trampoline_MmCopyVirtual)
                    return ((fn_MmCopyVirtualMemory_t)g_trampoline_MmCopyVirtual)(
                        SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, Result);
                return STATUS_UNSUCCESSFUL;
            }
        }

        bool violation_detected = false;
        UINT64 violation_source_addr = 0;
        UINT32 violation_size = 0;
        UINT32 caller_pid_u32 = 0;
        const UCHAR* caller_img_ptr = nullptr;
        bool caller_is_re_tool = false;

        UINT32 prot_pid = g_protected_pid;
        if (prot_pid != 0 && SourceProcess) {
            PEPROCESS protected_proc = nullptr;
            NTSTATUS lookup_st = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)prot_pid, &protected_proc);
            if (NT_SUCCESS(lookup_st) && protected_proc) {
                __try {
                    if (SourceProcess == protected_proc) {
                        PEPROCESS caller_proc = PsGetCurrentProcess();
                        HANDLE caller_pid = PsGetProcessId(caller_proc);
                        caller_pid_u32 = (UINT32)(ULONG_PTR)caller_pid;

                        if (caller_pid_u32 == prot_pid) {
                        } else if (caller_pid_u32 <= 4) {
                        } else {
                            UCHAR* caller_img = nullptr;
                            __try {
                                caller_img = PsGetProcessImageFileName(caller_proc);
                            } __except (EXCEPTION_EXECUTE_HANDLER) {
                                caller_img = nullptr;
                            }

                            bool caller_allowlisted = false;
                            if (caller_img && _MmIsAddressValid(caller_img)) {
                                caller_img_ptr = caller_img;
                                static const char* const mmc_allowlist[] = {
                                    "csrss", "services", "wininit", "lsass",
                                    "msmpeng", "securityheal", "werfault"
                                };
                                for (int a = 0; a < 7; ++a) {
                                    if (image_file_name_equals_ascii(caller_img, mmc_allowlist[a])) {
                                        caller_allowlisted = true;
                                        break;
                                    }
                                }
                            }

                            if (!caller_allowlisted && is_permitted_pid(caller_pid_u32)) {
                                caller_allowlisted = true;
                            }

                            if (!caller_allowlisted) {
                                if (process_guard::is_known_re_tool_pid(caller_pid)) {
                                    caller_is_re_tool = true;
                                }
                                violation_detected = true;
                                violation_source_addr = (UINT64)(UINT_PTR)SourceAddress;
                                violation_size = (UINT32)Size;
                            }
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    violation_detected = false;
                }
                ObDereferenceObject(protected_proc);
            }
        }

        if (cpu < MAXIMUM_PROCESSORS) {
            _InterlockedExchange(&g_mmcopy_reentrancy_guard[cpu], 0);
        }

        if (violation_detected) {
            LONG prev_pid = _InterlockedCompareExchange(&g_mmcopy_strike_pid, 0, 0);
            if (prev_pid != (LONG)caller_pid_u32) {
                _InterlockedExchange(&g_mmcopy_strike_pid, (LONG)caller_pid_u32);
                _InterlockedExchange(&g_mmcopy_strike_count, 0);
            }

            LONG strike = _InterlockedIncrement(&g_mmcopy_strike_count);

            const char* img_log = "<null>";
            __try {
                if (caller_img_ptr && _MmIsAddressValid(const_cast<UCHAR*>(caller_img_ptr))) {
                    img_log = (const char*)caller_img_ptr;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                img_log = "<fault>";
            }

            if (strike == 1) {
                WW_LOG("anti_dump: MMCOPY_STRIKE_1 caller_pid=%u src_addr=%p size=%llu image=%.15s re_tool=%d prot_pid=%u",
                    caller_pid_u32, (PVOID)violation_source_addr, (UINT64)violation_size,
                    img_log, caller_is_re_tool ? 1 : 0, prot_pid);
            } else if (strike == 2) {
                WW_LOG("anti_dump: MMCOPY_STRIKE_2 latch_targeting caller_pid=%u src_addr=%p size=%llu image=%.15s re_tool=%d prot_pid=%u",
                    caller_pid_u32, (PVOID)violation_source_addr, (UINT64)violation_size,
                    img_log, caller_is_re_tool ? 1 : 0, prot_pid);

                ULONG latch_cmd = sentinel_bridge::BRIDGE_CMD_LATCH_TARGETING;
                ULONG latch_param = caller_pid_u32;
                sentinel_bridge::bridge_encrypt_cmd(latch_cmd, latch_param);
                _InterlockedExchange(
                    reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                    static_cast<LONG>(latch_cmd));
                _InterlockedExchange(
                    reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                    static_cast<LONG>(latch_param));

                targeting_latch::latch_targeting(
                    0x02,
                    static_cast<UINT64>(caller_pid_u32),
                    violation_source_addr,
                    static_cast<UINT64>(violation_size),
                    0);
            } else {
                WW_LOG("anti_dump: MMCOPY_STRIKE_3 scrub_keys_bsod caller_pid=%u strike=%ld src_addr=%p size=%llu re_tool=%d prot_pid=%u",
                    caller_pid_u32, strike, (PVOID)violation_source_addr, (UINT64)violation_size,
                    caller_is_re_tool ? 1 : 0, prot_pid);

                anti_dma::countermeasure::scrub_keys_then_bsod(
                    0xA1DA0005u, violation_source_addr, violation_size, (UINT64)caller_pid_u32);
            }
        }

        if (g_trampoline_MmCopyVirtual)
            return ((fn_MmCopyVirtualMemory_t)g_trampoline_MmCopyVirtual)(
                SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, Result);
        return STATUS_UNSUCCESSFUL;
    }

    inline NTSTATUS install_mmcopy_hook()
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        if (_InterlockedCompareExchange(&g_mmcopy_hook_installed, 1, 0) != 0) {
            WW_LOG("anti_dump: mmcopy hook already installed");
            return STATUS_ALREADY_REGISTERED;
        }

        PVOID target = g_pMmCopyVirtualMemory;
        if (!target) {
            _InterlockedExchange(&g_mmcopy_hook_installed, 0);
            WW_LOG("anti_dump: mmcopy hook aborted - g_pMmCopyVirtualMemory is null");
            return STATUS_NOT_FOUND;
        }

        if (!_MmIsAddressValid || !_MmIsAddressValid(target)) {
            _InterlockedExchange(&g_mmcopy_hook_installed, 0);
            WW_LOG("anti_dump: mmcopy hook aborted - target address invalid %p", target);
            return STATUS_INVALID_ADDRESS;
        }

        g_original_MmCopyVirtualMemory = target;

        if (!mmcopy_create_trampoline(target, &g_trampoline_MmCopyVirtual,
                                       g_saved_bytes_MmCopyVirtual, MMCOPY_HOOK_COPY_SIZE)) {
            _InterlockedExchange(&g_mmcopy_hook_installed, 0);
            g_original_MmCopyVirtualMemory = nullptr;
            WW_LOG("anti_dump: mmcopy hook failed to create trampoline");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (!mmcopy_write_inline_hook(target, (PVOID)Hook_MmCopyVirtualMemory)) {
            if (g_trampoline_MmCopyVirtual) {
                ExFreePoolWithTag(g_trampoline_MmCopyVirtual, MMCOPY_TRAMPOLINE_TAG);
                g_trampoline_MmCopyVirtual = nullptr;
            }
            _InterlockedExchange(&g_mmcopy_hook_installed, 0);
            g_original_MmCopyVirtualMemory = nullptr;
            WW_LOG("anti_dump: mmcopy hook failed to write inline hook");
            return STATUS_UNSUCCESSFUL;
        }

        WW_LOG("anti_dump: mmcopy hook installed target=%p trampoline=%p hook=%p",
            target, g_trampoline_MmCopyVirtual, (PVOID)Hook_MmCopyVirtualMemory);
        return STATUS_SUCCESS;
    }

    inline NTSTATUS uninstall_mmcopy_hook()
    {
        if (_InterlockedCompareExchange(&g_mmcopy_hook_installed, 0, 1) != 1) {
            WW_LOG("anti_dump: mmcopy hook not installed, nothing to uninstall");
            return STATUS_NOT_FOUND;
        }

        if (g_original_MmCopyVirtualMemory) {
            mmcopy_remove_inline_hook(g_original_MmCopyVirtualMemory,
                                       g_saved_bytes_MmCopyVirtual, MMCOPY_HOOK_COPY_SIZE);
        }

        if (g_trampoline_MmCopyVirtual) {
            ExFreePoolWithTag(g_trampoline_MmCopyVirtual, MMCOPY_TRAMPOLINE_TAG);
            g_trampoline_MmCopyVirtual = nullptr;
        }

        g_original_MmCopyVirtualMemory = nullptr;

        WW_LOG("anti_dump: mmcopy hook uninstalled");
        return STATUS_SUCCESS;
    }

    inline NTSTATUS pre_protection_handle_sweep(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (pid == 0) return STATUS_INVALID_PARAMETER;

        PEPROCESS protected_proc = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &protected_proc);
        if (!NT_SUCCESS(status)) return status;

        ULONG buf_size = 4 * 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hSPW');
        if (!buf) {
            ObDereferenceObject(protected_proc);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG ret_len = 0;
        status = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
            buf, buf_size, &ret_len);

        if (status == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'hSPW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hSPW');
            if (!buf) {
                ObDereferenceObject(protected_proc);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            status = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
                buf, buf_size, &ret_len);
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buf, 'hSPW');
            ObDereferenceObject(protected_proc);
            return status;
        }

        auto* info = (SYSTEM_HANDLE_INFORMATION_EX_AD*)buf;

        static const char* const sweep_allowlist[] = {
            "csrss", "services", "wininit", "lsass",
            "msmpeng", "securityheal", "werfault"
        };
        constexpr int sweep_allowlist_count = sizeof(sweep_allowlist) / sizeof(sweep_allowlist[0]);

        __try {
            for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
                auto& h = info->Handles[i];
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId == pid) continue;
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId <= 4) continue;

                if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;
                if (h.Object != protected_proc) continue;

                if (h.GrantedAccess & PROCESS_VM_READ) {
                    UINT32 owner_pid = (UINT32)h.UniqueProcessId;

                    if (is_permitted_pid(owner_pid)) continue;

                    bool is_allowlisted = false;
                    PEPROCESS owner_proc = nullptr;
                    NTSTATUS lookup_st = PsLookupProcessByProcessId(
                        (HANDLE)(ULONG_PTR)owner_pid, &owner_proc);
                    if (NT_SUCCESS(lookup_st) && owner_proc) {
                        UCHAR* img_name = nullptr;
                        __try {
                            img_name = PsGetProcessImageFileName(owner_proc);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            img_name = nullptr;
                        }

                        if (img_name && _MmIsAddressValid(img_name)) {
                            for (int a = 0; a < sweep_allowlist_count; ++a) {
                                if (image_file_name_equals_ascii(img_name, sweep_allowlist[a])) {
                                    is_allowlisted = true;
                                    break;
                                }
                            }
                        }

                        ObDereferenceObject(owner_proc);
                    }

                    if (is_allowlisted) continue;

                    if (_ZwOpenProcess && _ZwTerminateProcess && _ZwClose) {
                        OBJECT_ATTRIBUTES oa;
                        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                        CLIENT_ID cid = {};
                        cid.UniqueProcess = (HANDLE)h.UniqueProcessId;
                        HANDLE hProc = nullptr;
                        if (NT_SUCCESS(_ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid)) && hProc) {
                            _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
                            _ZwClose(hProc);
                            WW_LOG("anti_dump: pre_protection_handle_sweep killed pid=%u vm_read_handle_to_protected=%u",
                                owner_pid, pid);
                        }
                    }
                    InterlockedIncrement64((volatile LONG64*)&g_blocks_count);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ExFreePoolWithTag(buf, 'hSPW');
        ObDereferenceObject(protected_proc);
        WW_LOG("anti_dump: pre_protection_handle_sweep complete pid=%u", pid);
        return status;
    }

    inline NTSTATUS place_canary_page(UINT32 pid);
    inline NTSTATUS check_canary_page(UINT32 pid, bool& canary_intact, bool& canary_accessed);
    inline NTSTATUS lock_pages(UINT32 pid, UINT64* bases, UINT64* sizes, UINT32 count);
    inline void unlock_all_pages();

    inline NTSTATUS full_protect(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        NTSTATUS status;

        status = pre_protection_handle_sweep(pid);
        if (!NT_SUCCESS(status)) {
            WW_LOG("anti_dump: pre-protection handle sweep failed 0x%08x pid=%u", status, pid);
        }

        status = register_handle_filter(pid);
        if (!NT_SUCCESS(status) && status != STATUS_ALREADY_REGISTERED) {
            WW_LOG("anti_dump: handle filter failed 0x%08x", status);
        }

        status = hide_all_threads(pid);
        if (status == STATUS_NOT_SUPPORTED) {
            WW_LOG("anti_dump: thread hide unsupported pid=%u", pid);
        } else if (!NT_SUCCESS(status)) {
            WW_LOG("anti_dump: thread hide failed 0x%08x", status);
        }

        status = erase_pe_headers(pid);
        if (!NT_SUCCESS(status)) {
            WW_LOG("anti_dump: header erase failed 0x%08x", status);
        }

        corrupt_section_headers(pid);
        scramble_peb_loader_data(pid);

        place_canary_page(pid);

        detect_mmcopyvirtualmemory(pid);

        NTSTATUS mmcopy_hook_st = install_mmcopy_hook();
        if (!NT_SUCCESS(mmcopy_hook_st) && mmcopy_hook_st != STATUS_ALREADY_REGISTERED) {
            WW_LOG("anti_dump: mmcopy hook install failed 0x%08x pid=%u", mmcopy_hook_st, pid);
        } else if (NT_SUCCESS(mmcopy_hook_st)) {
            WW_LOG("anti_dump: mmcopy hook installed pid=%u", pid);
        }

        return STATUS_SUCCESS;
    }

    inline NTSTATUS place_canary_page(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PVOID canary = nullptr;
            SIZE_T page_size = 4096;
            status = _ZwAllocateVirtualMemory(
                ZwCurrentProcess(), &canary, 0, &page_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (NT_SUCCESS(status) && canary) {
                UINT64 pattern = 0xA1DA0000ULL | (static_cast<UINT64>(pid) << 32);
                UINT64* words = reinterpret_cast<UINT64*>(canary);
                for (SIZE_T i = 0; i < page_size / sizeof(UINT64); ++i)
                    words[i] = pattern ^ (i * 0x9E3779B97F4A7C15ULL);

                ULONG old_prot = 0;
                PVOID prot_base = canary;
                SIZE_T prot_size = page_size;
                _ZwProtectVirtualMemory(
                    ZwCurrentProcess(), &prot_base, &prot_size,
                    PAGE_READONLY, &old_prot);

                g_canary_page_addr = canary;
                g_canary_pattern = pattern;
                _InterlockedExchange(&g_canary_initialized, 1);

                WW_LOG("anti_dump: canary placed pid=%u addr=%p pattern=0x%llX",
                    pid, canary, pattern);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);
        return status;
    }

    inline NTSTATUS check_canary_page(UINT32 pid, bool& canary_intact, bool& canary_accessed)
    {
        canary_intact = false;
        canary_accessed = false;

        if (_InterlockedCompareExchange(&g_canary_initialized, 0, 0) == 0)
            return STATUS_NOT_FOUND;
        if (!g_canary_page_addr)
            return STATUS_NOT_FOUND;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PVOID canary = g_canary_page_addr;
            if (_MmIsAddressValid(canary)) {
                UINT64* words = reinterpret_cast<UINT64*>(canary);
                UINT64 expected = g_canary_pattern;
                bool intact = true;
                for (SIZE_T i = 0; i < 4; ++i) {
                    if (words[i] != (expected ^ (i * 0x9E3779B97F4A7C15ULL))) {
                        intact = false;
                        break;
                    }
                }
                canary_intact = intact;

                MEMORY_BASIC_INFORMATION mbi{};
                SIZE_T ret_len = 0;
                NTSTATUS qst = _ZwQueryVirtualMemory(
                    ZwCurrentProcess(), canary,
                    MemoryWorkingSetExInformation,
                    &mbi, sizeof(mbi), &ret_len);
                if (NT_SUCCESS(qst) && (mbi.Protect & PAGE_GUARD) == 0) {
                    DWORD prot = mbi.Protect & 0xFF;
                    if (prot != PAGE_READONLY && prot != PAGE_NOACCESS)
                        canary_accessed = true;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);
        return status;
    }

    inline NTSTATUS lock_pages(UINT32 pid, UINT64* bases, UINT64* sizes, UINT32 count)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!bases || !sizes || count == 0 || count > 32) return STATUS_INVALID_PARAMETER;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            for (UINT32 i = 0; i < count; ++i) {
                if (!bases[i] || !sizes[i]) continue;

                PMDL mdl = _IoAllocateMdl(
                    reinterpret_cast<PVOID>(bases[i]),
                    static_cast<ULONG>(sizes[i]),
                    FALSE, FALSE, nullptr);
                if (!mdl) continue;

                __try {
                    _MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
                    g_locked_mdls[i] = mdl;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    _IoFreeMdl(mdl);
                }
            }
            WW_LOG("anti_dump: locked %u pages for pid=%u", count, pid);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);
        return status;
    }

    inline void unlock_all_pages()
    {
        for (int i = 0; i < 32; ++i) {
            if (g_locked_mdls[i]) {
                _MmUnlockPages(g_locked_mdls[i]);
                _IoFreeMdl(g_locked_mdls[i]);
                g_locked_mdls[i] = nullptr;
            }
        }
    }

    inline void cleanup()
    {
        uninstall_mmcopy_hook();
        unlock_all_pages();
        if (g_ob_handle && _ObUnRegisterCallbacks) {
            _ObUnRegisterCallbacks(g_ob_handle);
            g_ob_handle = nullptr;
        }
        g_protected_pid = 0;
        _InterlockedExchange(&g_initialized, 0);
        g_pMmCopyVirtualMemory = nullptr;
        _InterlockedExchange(&g_mmcopy_resolved, 0);
        _InterlockedExchange((volatile LONG*)&g_canary_crc32, 0);
        _InterlockedExchange(&g_kernel_dump_detected, 0);
        g_resolved_kestackattach = nullptr;
        _InterlockedExchange(&g_kestack_resolved, 0);
        g_resolved_keunstackdetach = nullptr;
        _InterlockedExchange(&g_keunstack_resolved, 0);
    }

    inline NTSTATUS scan_and_kill_readers(UINT32 pid)
    {
        if (pid == 0) return STATUS_INVALID_PARAMETER;

        __try {
            PEPROCESS initial = PsInitialSystemProcess;
            if (!initial || !_MmIsAddressValid(initial)) return STATUS_UNSUCCESSFUL;

            SIZE_T active_links_offset = whoswho_kernel_layout::eprocess_active_process_links_offset();
            if (active_links_offset == 0) {
                WW_LOG("anti_dump: scan_and_kill_readers fail_closed pid=%u build=%lu reason=unsupported_eprocess_layout",
                    pid,
                    whoswho_kernel_layout::build_number());
                return STATUS_NOT_SUPPORTED;
            }

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + active_links_offset);
            PLIST_ENTRY entry = list_head->Flink;

            const char* dump_tools[] = {
                "procdump",    "processdump", "hollowshunt",
                "pe-sieve",    "scylla",      "taskdmp",
                "minidump",    "dumper",       "processhacker",
                "x64dbg",      "x32dbg",      "windbg",
                "ida",         "ida64",       "idaq",
                "ghidra",      "binaryninja", "dotpeek",
                "dnspy",       "ilspy",       "cheatengine",
                "ce.exe",      "apimonitor",  "ollydbg",
                "reshack",     "exeinfope",   "pestudio",
                "radare2",     "cutter",      "hyperdbg",
                "reclass",     "classinfo",   "hmm.exe",
                "sigmaker",    "peid",        "die.exe",
                "titanhide",   "scyllahide",  "sharphound",
                "volatility",  "rekall",      "vmmap.exe",
                "apispy",      "wireshark",   "procmon"
            };
            constexpr int num_tools = sizeof(dump_tools) / sizeof(dump_tools[0]);

            for (int iter = 0; iter < 2048 && entry != list_head; ++iter, entry = entry->Flink) {
                PEPROCESS proc = (PEPROCESS)((UINT8*)entry - active_links_offset);
                if (!_MmIsAddressValid(proc)) continue;

                HANDLE proc_pid = PsGetProcessId(proc);
                if ((UINT32)(ULONG_PTR)proc_pid == pid) continue;
                if ((UINT32)(ULONG_PTR)proc_pid <= 4) continue;

                UCHAR* name = PsGetProcessImageFileName(proc);
                if (!name || !_MmIsAddressValid(name)) continue;

                if (image_file_name_is_supported_ida_host(name)) {
                    WW_LOG("anti_dump: supported IDA host ignored pid=%u name=%.15s",
                        (UINT32)(ULONG_PTR)proc_pid, name);
                    continue;
                }

                for (int t = 0; t < num_tools; ++t) {
                    const char* target = dump_tools[t];
                    bool match = true;
                    for (int c = 0; target[c] != '\0'; ++c) {
                        char a = (char)(name[c] | 0x20);
                        char b = (char)(target[c] | 0x20);
                        if (a != b) { match = false; break; }
                    }
                    if (match) {
                        UINT32 pid_u32 = (UINT32)(ULONG_PTR)proc_pid;
                        if (is_permitted_pid(pid_u32)) {
                            WW_LOG("anti_dump: skipped kill for permitted pid=%u name=%.15s",
                                pid_u32, name);
                            break;
                        }
                        if (_ZwOpenProcess && _ZwTerminateProcess && _ZwClose) {
                            OBJECT_ATTRIBUTES oa;
                            InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                            CLIENT_ID cid = {};
                            cid.UniqueProcess = proc_pid;
                            HANDLE hProc = nullptr;
                            if (NT_SUCCESS(_ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid)) && hProc) {
                                _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
                                _ZwClose(hProc);
                                WW_LOG("anti_dump: killed dump tool pid=%u name=%.15s",
                                    pid_u32, name);
                            }
                        }
                        InterlockedIncrement64((volatile LONG64*)&g_blocks_count);
                        break;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_SUCCESS;
    }

    __forceinline UINT32 crc32_compute(const UINT8* data, SIZE_T len)
    {
        static UINT32 table[256] = {};
        static volatile LONG table_init = 0;
        if (_InterlockedCompareExchange(&table_init, 1, 0) == 0) {
            for (UINT32 i = 0; i < 256; ++i) {
                UINT32 c = i;
                for (int j = 0; j < 8; ++j) {
                    c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                }
                table[i] = c;
            }
            KeMemoryBarrier();
            _InterlockedExchange(&table_init, 2);
        } else {
            while (_InterlockedCompareExchange(&table_init, 0, 0) == 1)
                YieldProcessor();
        }

        UINT32 crc = 0xFFFFFFFFu;
        __try {
            for (SIZE_T i = 0; i < len; ++i) {
                crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        return crc ^ 0xFFFFFFFFu;
    }

#pragma pack(push, 1)
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_AD {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ACCESS_MASK GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };
    struct SYSTEM_HANDLE_INFORMATION_EX_AD {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_AD Handles[1];
    };
#pragma pack(pop)

    __forceinline NTSTATUS monitor_kernel_reads(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (pid == 0) return STATUS_INVALID_PARAMETER;

        PEPROCESS protected_proc = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &protected_proc);
        if (!NT_SUCCESS(status)) return status;

        ULONG buf_size = 4 * 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hKAW');
        if (!buf) {
            ObDereferenceObject(protected_proc);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG ret_len = 0;
        status = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
            buf, buf_size, &ret_len);

        if (status == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'hKAW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hKAW');
            if (!buf) {
                ObDereferenceObject(protected_proc);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            status = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
                buf, buf_size, &ret_len);
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buf, 'hKAW');
            ObDereferenceObject(protected_proc);
            return status;
        }

        auto* info = (SYSTEM_HANDLE_INFORMATION_EX_AD*)buf;

        __try {
            for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
                auto& h = info->Handles[i];
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId == pid) continue;
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId <= 4) continue;

                if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;
                if (h.Object != protected_proc) continue;

                if (h.GrantedAccess & PROCESS_VM_READ) {
                    UINT32 owner_pid = (UINT32)h.UniqueProcessId;
                    if (is_permitted_pid(owner_pid)) continue;

                    if (_ZwOpenProcess && _ZwTerminateProcess && _ZwClose) {
                        OBJECT_ATTRIBUTES oa;
                        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                        CLIENT_ID cid = {};
                        cid.UniqueProcess = (HANDLE)h.UniqueProcessId;
                        HANDLE hProc = nullptr;
                        if (NT_SUCCESS(_ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid)) && hProc) {
                            _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
                            _ZwClose(hProc);
                            WW_LOG("anti_dump: monitor_kernel_reads killed pid=%u vm_read_handle_to_protected=%u",
                                owner_pid, pid);
                        }
                    }
                    InterlockedIncrement64((volatile LONG64*)&g_blocks_count);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ExFreePoolWithTag(buf, 'hKAW');
        ObDereferenceObject(protected_proc);
        return status;
    }

    __forceinline PVOID pattern_scan_ntoskrnl(const UINT8* pattern, const bool* wildcard, SIZE_T pattern_len)
    {
        std::uintptr_t nt_base_val = get_nt_base();
        if (nt_base_val == 0) return nullptr;

        PVOID nt_base_ptr = (PVOID)nt_base_val;
        ULONG nt_size = 0;
        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)nt_base_ptr;
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT8*)nt_base_ptr + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
            nt_size = nt->OptionalHeader.SizeOfImage;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }

        if (nt_size < pattern_len) return nullptr;

        PUCHAR base = (PUCHAR)nt_base_ptr;
        for (ULONG offset = 0; offset + pattern_len <= nt_size; ++offset) {
            bool match = true;
            for (SIZE_T j = 0; j < pattern_len; ++j) {
                if (wildcard[j]) continue;
                if (base[offset + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return (PVOID)(base + offset);
        }
        return nullptr;
    }

    __forceinline NTSTATUS scrub_keys_on_kernel_dump_detection(UINT32 pid);

    __forceinline NTSTATUS detect_mmcopyvirtualmemory(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        if (_InterlockedCompareExchange(&g_mmcopy_resolved, 0, 0) == 0) {
            LONG prev = _InterlockedCompareExchange(&g_mmcopy_resolved, 1, 0);
            if (prev == 0) {
                static const UINT8 pat_v1[] = {
                    0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55,
                    0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x10,
                    0x04, 0x00, 0x00
                };
                static const bool wc_v1[] = {
                    false, false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false, false,
                    false, false, false
                };

                static const UINT8 pat_v2[] = {
                    0x48, 0x83, 0xEC, 0x48, 0x83, 0x64, 0x24, 0x00,
                    0x00, 0x48, 0x8B, 0x84, 0x24
                };
                static const bool wc_v2[] = {
                    false, false, false, false, false, false, false, true,
                    true,  false, false, false, false
                };

                static const UINT8 pat_v3[] = {
                    0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x84, 0x24,
                    0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24
                };
                static const bool wc_v3[] = {
                    false, false, false, false, false, false, false, false,
                    true,  true,  true,  true,  false, false, false
                };

                PVOID found = nullptr;

                found = pattern_scan_ntoskrnl(pat_v1, wc_v1, sizeof(pat_v1));
                if (found) {
                    g_pMmCopyVirtualMemory = found;
                    WW_LOG("anti_dump: MmCopyVirtualMemory resolved via variant 1 (Win10 22H2) at %p", found);
                }

                if (!found) {
                    found = pattern_scan_ntoskrnl(pat_v2, wc_v2, sizeof(pat_v2));
                    if (found) {
                        g_pMmCopyVirtualMemory = found;
                        WW_LOG("anti_dump: MmCopyVirtualMemory resolved via variant 2 (Win11 24H2/25H2) at %p", found);
                    }
                }

                if (!found) {
                    found = pattern_scan_ntoskrnl(pat_v3, wc_v3, sizeof(pat_v3));
                    if (found) {
                        g_pMmCopyVirtualMemory = found;
                        WW_LOG("anti_dump: MmCopyVirtualMemory resolved via variant 3 (Win11 23H2) at %p", found);
                    }
                }

                if (!found) {
                    WW_LOG("anti_dump: MmCopyVirtualMemory pattern not found across all 3 variants");
                }
                KeMemoryBarrier();
                _InterlockedExchange(&g_mmcopy_resolved, 2);
            } else {
                while (_InterlockedCompareExchange(&g_mmcopy_resolved, 0, 0) == 1)
                    YieldProcessor();
            }
        }

        if (_InterlockedCompareExchange(&g_canary_initialized, 0, 0) == 0 || !g_canary_page_addr)
            return STATUS_NOT_FOUND;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PVOID canary = g_canary_page_addr;
            if (_MmIsAddressValid(canary)) {
                UINT8* bytes = (UINT8*)canary;
                UINT32 current_crc = crc32_compute(bytes, 64);

                UINT32 prev_crc = (UINT32)_InterlockedCompareExchange(
                    (volatile LONG*)&g_canary_crc32, 0, 0);

                if (prev_crc == 0) {
                    _InterlockedExchange((volatile LONG*)&g_canary_crc32, (LONG)current_crc);
                } else if (current_crc != prev_crc) {
                    WW_LOG("anti_dump: canary CRC32 mismatch prev=0x%08X curr=0x%08X pid=%u mmcopy=%p",
                        prev_crc, current_crc, pid, g_pMmCopyVirtualMemory);
                    scrub_keys_on_kernel_dump_detection(pid);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);
        return status;
    }

    __forceinline NTSTATUS scrub_keys_on_kernel_dump_detection(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (pid == 0) return STATUS_INVALID_PARAMETER;

        _InterlockedExchange(&g_kernel_dump_detected, 1);
        WW_LOG("anti_dump: KERNEL_DUMP_DETECTED pid=%u scrubbing_keys", pid);

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        KAPC_STATE apc;
        ke_stack_attach(process, &apc);

        __try {
            PVOID peb_raw = _PsGetProcessPeb(process);
            if (peb_raw && _MmIsAddressValid(peb_raw)) {
                ULONG old_prot = 0;
                PVOID prot_base = peb_raw;
                SIZE_T prot_size = 0x1000;
                NTSTATUS pst = _ZwProtectVirtualMemory(
                    ZwCurrentProcess(), &prot_base, &prot_size,
                    PAGE_READWRITE, &old_prot);
                if (NT_SUCCESS(pst)) {
                    RtlZeroMemory(peb_raw, 0x1000);
                    _ZwProtectVirtualMemory(
                        ZwCurrentProcess(), &prot_base, &prot_size,
                        old_prot, &old_prot);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ke_unstack_detach(&apc);
        ObDereferenceObject(process);

        WW_LOG("anti_dump: TIER2_BSOD kernel_dump pid=%u", pid);
        if (_KeBugCheckEx) {
            _KeBugCheckEx(0xA1DA0002u, (ULONG_PTR)pid, 0, 0, 0);
        }
        return status;
    }

    __forceinline NTSTATUS scan_for_dump_files(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (pid == 0) return STATUS_INVALID_PARAMETER;

        ULONG buf_size = 4 * 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hDSW');
        if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

        ULONG ret_len = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
            buf, buf_size, &ret_len);

        if (status == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'hDSW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hDSW');
            if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
            status = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
                buf, buf_size, &ret_len);
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buf, 'hDSW');
            return status;
        }

        auto* info = (SYSTEM_HANDLE_INFORMATION_EX_AD*)buf;

        USHORT file_type_idx = 0;
        if (_IoFileObjectType && *_IoFileObjectType && _ObGetObjectType) {
            __try {
                for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000 && file_type_idx == 0; ++i) {
                    auto& h = info->Handles[i];
                    if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;
                    POBJECT_TYPE otype = _ObGetObjectType(h.Object);
                    if (otype == *_IoFileObjectType) {
                        file_type_idx = h.ObjectTypeIndex;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    file_type_idx = 0;
                }
            }
        }

        __try {
            for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
                auto& h = info->Handles[i];
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId == pid) continue;
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId <= 4) continue;

                if (file_type_idx != 0 && h.ObjectTypeIndex != file_type_idx) continue;

                if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;

                PFILE_OBJECT file_obj = (PFILE_OBJECT)h.Object;
                if (!file_obj || !_MmIsAddressValid(file_obj)) continue;
                if (file_obj->FileName.Length == 0) continue;
                if (!file_obj->FileName.Buffer || !_MmIsAddressValid(file_obj->FileName.Buffer)) continue;

                WCHAR lower_name[256] = {};
                USHORT chars = file_obj->FileName.Length / sizeof(WCHAR);
                if (chars > 255) chars = 255;
                for (USHORT c = 0; c < chars; ++c) {
                    WCHAR ch = file_obj->FileName.Buffer[c];
                    lower_name[c] = (ch >= L'A' && ch <= L'Z') ? (ch + 32) : ch;
                }

                bool is_dump = false;
                if (chars >= 4) {
                    if (lower_name[chars-4] == L'.' && lower_name[chars-3] == L'd' &&
                        lower_name[chars-2] == L'm' && lower_name[chars-1] == L'p')
                        is_dump = true;
                    else if (chars >= 5 && lower_name[chars-5] == L'.' &&
                             lower_name[chars-4] == L'd' && lower_name[chars-3] == L'u' &&
                             lower_name[chars-2] == L'm' && lower_name[chars-1] == L'p')
                        is_dump = true;
                    else if (chars >= 5 && lower_name[chars-5] == L'.' &&
                             lower_name[chars-4] == L'm' && lower_name[chars-3] == L'd' &&
                             lower_name[chars-2] == L'm' && lower_name[chars-1] == L'p')
                        is_dump = true;
                }

                if (is_dump) {
                    UINT32 owner_pid = (UINT32)h.UniqueProcessId;
                    if (is_permitted_pid(owner_pid)) continue;

                    if (_ZwOpenProcess && _ZwTerminateProcess && _ZwClose) {
                        OBJECT_ATTRIBUTES oa;
                        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                        CLIENT_ID cid = {};
                        cid.UniqueProcess = (HANDLE)h.UniqueProcessId;
                        HANDLE hProc = nullptr;
                        if (NT_SUCCESS(_ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid)) && hProc) {
                            _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
                            _ZwClose(hProc);
                            WW_LOG("anti_dump: scan_for_dump_files killed pid=%u dump_file_handle", owner_pid);
                        }
                    }
                    InterlockedIncrement64((volatile LONG64*)&g_blocks_count);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ExFreePoolWithTag(buf, 'hDSW');
        return status;
    }

    __forceinline int canary_access_allowlist_check(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return -1;
        if (pid == 0) return -1;

        PEPROCESS protected_proc = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &protected_proc);
        if (!NT_SUCCESS(status)) return -1;

        ULONG buf_size = 4 * 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'aCAW');
        if (!buf) {
            ObDereferenceObject(protected_proc);
            return -1;
        }

        ULONG ret_len = 0;
        status = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
            buf, buf_size, &ret_len);

        if (status == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'aCAW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'aCAW');
            if (!buf) {
                ObDereferenceObject(protected_proc);
                return -1;
            }
            status = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
                buf, buf_size, &ret_len);
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buf, 'aCAW');
            ObDereferenceObject(protected_proc);
            return -1;
        }

        auto* info = (SYSTEM_HANDLE_INFORMATION_EX_AD*)buf;

        static const char* const canary_allowlist[] = {
            "csrss", "services", "wininit", "lsass",
            "msmpeng", "securityheal", "werfault"
        };
        constexpr int canary_allowlist_count = sizeof(canary_allowlist) / sizeof(canary_allowlist[0]);

        bool any_vm_read = false;
        bool any_non_allowlisted = false;

        __try {
            for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
                auto& h = info->Handles[i];
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId == pid) continue;
                if ((ULONG_PTR)(HANDLE)h.UniqueProcessId <= 4) continue;

                if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;
                if (h.Object != protected_proc) continue;

                if (h.GrantedAccess & PROCESS_VM_READ) {
                    any_vm_read = true;
                    UINT32 owner_pid = (UINT32)h.UniqueProcessId;

                    if (is_permitted_pid(owner_pid))
                        continue;

                    PEPROCESS owner_proc = nullptr;
                    NTSTATUS lookup_st = PsLookupProcessByProcessId(
                        (HANDLE)(ULONG_PTR)owner_pid, &owner_proc);
                    if (!NT_SUCCESS(lookup_st) || !owner_proc) {
                        any_non_allowlisted = true;
                        WW_LOG("anti_dump: canary_access_non_allowlisted owner_pid=%u pid=%u access=0x%08X reason=lookup_failed",
                            owner_pid, pid, (UINT32)h.GrantedAccess);
                        continue;
                    }

                    UCHAR* img_name = nullptr;
                    __try {
                        img_name = PsGetProcessImageFileName(owner_proc);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        img_name = nullptr;
                    }

                    bool is_allowlisted = false;
                    if (img_name && _MmIsAddressValid(img_name)) {
                        for (int a = 0; a < canary_allowlist_count; ++a) {
                            if (image_file_name_equals_ascii(img_name, canary_allowlist[a])) {
                                is_allowlisted = true;
                                break;
                            }
                        }
                    }

                    if (!is_allowlisted) {
                        any_non_allowlisted = true;
                        WW_LOG("anti_dump: canary_access_non_allowlisted owner_pid=%u pid=%u access=0x%08X image=%.15s",
                            owner_pid, pid, (UINT32)h.GrantedAccess,
                            img_name ? (const char*)img_name : "<null>");
                    } else {
                        WW_LOG("anti_dump: canary_access_allowlisted owner_pid=%u pid=%u access=0x%08X image=%.15s",
                            owner_pid, pid, (UINT32)h.GrantedAccess,
                            img_name ? (const char*)img_name : "<null>");
                    }

                    ObDereferenceObject(owner_proc);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ExFreePoolWithTag(buf, 'aCAW');
            ObDereferenceObject(protected_proc);
            return -1;
        }

        ExFreePoolWithTag(buf, 'aCAW');
        ObDereferenceObject(protected_proc);

        if (!any_vm_read) return 0;
        if (any_non_allowlisted) return 2;
        return 1;
    }

    inline NTSTATUS scan_for_foreign_attaches(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (pid == 0) return STATUS_INVALID_PARAMETER;
        if (!_PsGetNextProcessThread) return STATUS_NOT_SUPPORTED;

        SIZE_T active_links_offset = whoswho_kernel_layout::eprocess_active_process_links_offset();
        if (active_links_offset == 0) return STATUS_NOT_SUPPORTED;

        SIZE_T apc_state_abs_offset = whoswho_kernel_layout::kthread_apc_state_process_absolute_offset();
        if (apc_state_abs_offset == 0) return STATUS_NOT_SUPPORTED;

        PEPROCESS protected_proc = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &protected_proc);
        if (!NT_SUCCESS(status)) return status;

        _InterlockedIncrement64((volatile LONG64*)&g_foreign_attach_scan_count);

        static const char* const allowlist[] = {
            "csrss", "services", "wininit", "lsass",
            "msmpeng", "securityheal", "werfault", "svchost"
        };
        constexpr int allowlist_count = sizeof(allowlist) / sizeof(allowlist[0]);

        bool detection_this_scan = false;

        __try {
            PEPROCESS initial = PsInitialSystemProcess;
            if (!initial || !_MmIsAddressValid(initial)) {
                ObDereferenceObject(protected_proc);
                return STATUS_UNSUCCESSFUL;
            }

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + active_links_offset);
            if (!_MmIsAddressValid(list_head)) {
                ObDereferenceObject(protected_proc);
                return STATUS_UNSUCCESSFUL;
            }
            PLIST_ENTRY entry = list_head->Flink;

            for (int iter = 0; iter < 2048 && entry != list_head && !detection_this_scan; ++iter, entry = entry->Flink) {
                if (!_MmIsAddressValid(entry)) break;

                PEPROCESS proc = (PEPROCESS)((UINT8*)entry - active_links_offset);
                if (!_MmIsAddressValid(proc)) continue;

                HANDLE proc_pid_h = PsGetProcessId(proc);
                UINT32 pid_u32 = (UINT32)(ULONG_PTR)proc_pid_h;
                if (pid_u32 == 0 || pid_u32 <= 4 || pid_u32 == pid) continue;

                PETHREAD thread = nullptr;
                while ((thread = _PsGetNextProcessThread(proc, thread)) != nullptr) {
                    if (!_MmIsAddressValid(thread)) continue;

                    UINT64 apc_state_process = 0;
                    __try {
                        apc_state_process = *(volatile UINT64*)((UINT8*)thread + apc_state_abs_offset);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        continue;
                    }

                    if ((PVOID)apc_state_process != (PVOID)protected_proc) continue;

                    UCHAR* img_name = nullptr;
                    __try {
                        img_name = PsGetProcessImageFileName(proc);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        img_name = nullptr;
                    }

                    bool is_allowlisted = false;
                    if (img_name && _MmIsAddressValid(img_name)) {
                        for (int a = 0; a < allowlist_count; ++a) {
                            if (image_file_name_equals_ascii(img_name, allowlist[a])) {
                                is_allowlisted = true;
                                break;
                            }
                        }
                    }

                    if (!is_allowlisted) {
                        if (is_permitted_pid(pid_u32)) {
                            is_allowlisted = true;
                            WW_LOG("anti_dump: foreign_attach_permitted_pid_exempted owner_pid=%u protected_pid=%u image=%.15s",
                                pid_u32, pid, img_name ? (const char*)img_name : "<null>");
                        }
                    }

                    if (is_allowlisted) continue;

                    detection_this_scan = true;
                    _InterlockedExchange(&g_foreign_attach_detected, 1);

                    HANDLE tid = nullptr;
                    if (_PsGetThreadId) {
                        __try {
                            tid = _PsGetThreadId(thread);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            tid = nullptr;
                        }
                    }

                    UINT64 tid_u64 = (UINT64)(ULONG_PTR)tid;

                    WW_LOG("anti_dump: FOREIGN_ATTACH_DETECTED protected_pid=%u owner_pid=%u tid=%llu owner_image=%.15s apc_state_process=0x%llX protected_eprocess=%p",
                        pid, pid_u32, tid_u64,
                        img_name ? (const char*)img_name : "<null>",
                        (unsigned long long)apc_state_process,
                        (PVOID)protected_proc);

                    LONG prev_pid = _InterlockedCompareExchange(&g_foreign_attach_strike_pid, 0, 0);
                    if (prev_pid != (LONG)pid_u32) {
                        _InterlockedExchange(&g_foreign_attach_strike_pid, (LONG)pid_u32);
                        _InterlockedExchange(&g_foreign_attach_strike_count, 0);
                    }

                    LONG strike = _InterlockedIncrement(&g_foreign_attach_strike_count);

                    if (strike == 1) {
                        WW_LOG("anti_dump: FOREIGN_ATTACH_STRIKE_1 protected_pid=%u owner_pid=%u tid=%llu owner_image=%.15s apc_state_proc=0x%llX",
                            pid, pid_u32, tid_u64,
                            img_name ? (const char*)img_name : "<null>",
                            (unsigned long long)apc_state_process);
                    } else if (strike == 2) {
                        WW_LOG("anti_dump: FOREIGN_ATTACH_STRIKE_2 latch_targeting protected_pid=%u owner_pid=%u tid=%llu owner_image=%.15s",
                            pid, pid_u32, tid_u64,
                            img_name ? (const char*)img_name : "<null>");

                        ULONG latch_cmd = sentinel_bridge::BRIDGE_CMD_LATCH_TARGETING;
                        ULONG latch_param = pid_u32;
                        sentinel_bridge::bridge_encrypt_cmd(latch_cmd, latch_param);
                        _InterlockedExchange(
                            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                            static_cast<LONG>(latch_cmd));
                        _InterlockedExchange(
                            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                            static_cast<LONG>(latch_param));

                        targeting_latch::latch_targeting(
                            0x01,
                            static_cast<UINT64>(pid_u32),
                            tid_u64,
                            apc_state_process,
                            static_cast<UINT64>(reinterpret_cast<UINT_PTR>(protected_proc)));
                    } else {
                        WW_LOG("anti_dump: FOREIGN_ATTACH_STRIKE_3 scrub_keys_bsod protected_pid=%u owner_pid=%u tid=%llu strike=%ld",
                            pid, pid_u32, tid_u64, strike);

                        anti_dma::countermeasure::scrub_keys();

                        if (_KeBugCheckEx) {
                            _KeBugCheckEx(0xA1DA0003u,
                                static_cast<ULONG_PTR>(pid),
                                static_cast<ULONG_PTR>(pid_u32),
                                static_cast<ULONG_PTR>(tid_u64),
                                static_cast<ULONG_PTR>(apc_state_process));
                        }
                    }

                    break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(protected_proc);
        return status;
    }
}

namespace continuous_anti_dump {

    inline KTIMER   g_timer = {};
    inline KDPC     g_dpc   = {};
    inline volatile LONG   g_active = 0;
    inline volatile UINT32 g_target_pid = 0;
    inline volatile UINT64 g_cycle_count = 0;
    inline WORK_QUEUE_ITEM g_work_item = {};
    inline volatile LONG   g_work_item_queued = 0;

    constexpr LONG TIMER_PERIOD_MS = 7000;

    inline VOID NTAPI work_item_callback(PVOID)
    {
        if (!_InterlockedCompareExchange(&g_active, 0, 0)) {
            _InterlockedExchange(&g_work_item_queued, 0);
            return;
        }

        UINT64 jitter_ms = __rdtsc() % 2000;
        if (jitter_ms > 0 && KeGetCurrentIrql() == PASSIVE_LEVEL && _KeDelayExecutionThread) {
            LARGE_INTEGER jitter_wait;
            jitter_wait.QuadPart = -static_cast<LONGLONG>(jitter_ms) * 10000LL;
            _KeDelayExecutionThread(KernelMode, FALSE, &jitter_wait);
        }
        WW_LOG("continuous_admp: jitter_applied ms=%llu", jitter_ms);

        __try {
            UINT32 pid = g_target_pid;
            if (pid == 0) {
                _InterlockedExchange(&g_work_item_queued, 0);
                return;
            }

            InterlockedIncrement64((volatile LONG64*)&g_cycle_count);
            UINT64 cycle = g_cycle_count;

            anti_dump_kernel::scan_and_kill_readers(pid);

            if ((cycle % 3) == 0) {
                anti_dump_kernel::hide_all_threads(pid);
                anti_dump_kernel::monitor_kernel_reads(pid);
                anti_dump_kernel::scan_for_foreign_attaches(pid);
            }

            if ((cycle % 10) == 0) {
                anti_dump_kernel::erase_pe_headers(pid);
            }

            if ((cycle % 7) == 0) {
                anti_dump_kernel::corrupt_section_headers(pid);
            }

            if ((cycle % 15) == 0) {
                anti_dump_kernel::scramble_peb_loader_data(pid);
            }

            if ((cycle % 5) == 0) {
                admp_header_state state{};
                NTSTATUS vs = anti_dump_kernel::verify_headers_zeroed(pid, &state);
                if (NT_SUCCESS(vs) && state.headers_restored) {
                    WW_LOG("continuous_admp: HEADER_RESTORE detected pid=%u dos=0x%X nt=0x%X",
                        pid, state.dos_magic, state.nt_signature);
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(0xA1DA0002u, pid, state.dos_magic, state.nt_signature, 0);
                    }
                }
            }

            if ((cycle % 3) == 0) {
                bool canary_intact = false;
                bool canary_accessed = false;
                NTSTATUS cs = anti_dump_kernel::check_canary_page(pid, canary_intact, canary_accessed);
                if (NT_SUCCESS(cs) && canary_accessed && !canary_intact) {
                    WW_LOG("continuous_admp: CANARY_CORRUPTION detected pid=%u", pid);
                    int allowlist_result = anti_dump_kernel::canary_access_allowlist_check(pid);
                    if (allowlist_result == 1) {
                        WW_LOG("continuous_admp: canary_access_allowlisted pid=%u -- AV scan, clearing canary without BSOD", pid);
                        _InterlockedExchange(&anti_dump_kernel::g_canary_initialized, 0);
                        anti_dump_kernel::place_canary_page(pid);
                    } else {
                        if (allowlist_result == 0) {
                            WW_LOG("continuous_admp: canary_kernel_read pid=%u no_vm_read_handles -- BSOD", pid);
                        } else if (allowlist_result == 2) {
                            WW_LOG("continuous_admp: canary_stripping_bypass pid=%u non_allowlisted_vm_read -- BSOD", pid);
                        } else {
                            WW_LOG("continuous_admp: canary_check_error pid=%u result=%d -- BSOD fail_closed", pid, allowlist_result);
                        }
                        if (_KeBugCheckEx) {
                            _KeBugCheckEx(0xA1DA0002u, pid, 0, 0, 0);
                        }
                    }
                }
                anti_dump_kernel::detect_mmcopyvirtualmemory(pid);
            }

            if ((cycle % 20) == 0) {
                anti_dump_kernel::scan_for_dump_files(pid);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("continuous_admp: work_exception");
        }

        _InterlockedExchange(&g_work_item_queued, 0);
    }

    inline VOID NTAPI timer_callback(
        PKDPC,
        PVOID,
        PVOID,
        PVOID)
    {
        if (!_InterlockedCompareExchange(&g_active, 0, 0))
            return;

        if (_InterlockedCompareExchange(&g_work_item_queued, 1, 0) == 0) {
            ExInitializeWorkItem(&g_work_item, work_item_callback, nullptr);
            if (_ExQueueWorkItem)
                _ExQueueWorkItem(&g_work_item, DelayedWorkQueue);
            else
                ExQueueWorkItem(&g_work_item, DelayedWorkQueue);
        }
    }

    inline void start(UINT32 pid)
    {
        if (_InterlockedCompareExchange(&g_active, 1, 0) != 0) {
            _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_target_pid),
                static_cast<LONG>(pid));
            _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_cycle_count), 0);
            WW_LOG("continuous_admp: retarget pid=%u cycle_reset (was already active)", pid);
            return;
        }

        g_target_pid = pid;
        g_cycle_count = 0;

        _KeInitializeTimerEx(&g_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_dpc, timer_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(TIMER_PERIOD_MS) * 10000LL;

        _KeSetTimerEx(&g_timer, due_time, TIMER_PERIOD_MS, &g_dpc);

        WW_LOG("continuous_admp: started for pid=%u period=%dms", pid, TIMER_PERIOD_MS);
    }

    inline void stop()
    {
        if (_InterlockedCompareExchange(&g_active, 0, 1) != 1)
            return;

        KeCancelTimer(&g_timer);
        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();
        g_target_pid = 0;
        WW_LOG("continuous_admp: stopped");
    }

    inline void stop_if_target(UINT32 pid)
    {
        if (pid == 0) return;
        LONG queued = _InterlockedCompareExchange(&g_work_item_queued, 0, 0);
        LONG active_before = _InterlockedCompareExchange(&g_active, 0, 0);
        LONG prev = _InterlockedCompareExchange(
            reinterpret_cast<volatile LONG*>(&g_target_pid),
            0,
            static_cast<LONG>(pid));
        if (prev == static_cast<LONG>(pid)) {
            LONG stopped = _InterlockedExchange(&g_active, 0);
            KeCancelTimer(&g_timer);
            if (_KeFlushQueuedDpcs && KeGetCurrentIrql() < DISPATCH_LEVEL)
                _KeFlushQueuedDpcs();
            WW_LOG("continuous_admp: stopped target pid=%u process_exiting active_before=%ld stopped=%ld queued_before=%ld queued_after=%ld irql=%lu",
                pid,
                active_before,
                stopped,
                queued,
                _InterlockedCompareExchange(&g_work_item_queued, 0, 0),
                static_cast<ULONG>(KeGetCurrentIrql()));
        }
    }
}
