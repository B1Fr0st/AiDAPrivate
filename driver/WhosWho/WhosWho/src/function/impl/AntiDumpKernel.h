#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <imports/Defs.h>
#include "../KernelLayout.h"

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
        _KeStackAttachProcess(process, &apc);

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

        _KeUnstackDetachProcess(&apc);
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
        _KeStackAttachProcess(process, &apc);

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

        _KeUnstackDetachProcess(&apc);
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
        _KeStackAttachProcess(process, &apc);

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

        _KeUnstackDetachProcess(&apc);
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
        _KeStackAttachProcess(process, &apc);

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

        _KeUnstackDetachProcess(&apc);
        ObDereferenceObject(process);
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

        return STATUS_SUCCESS;
    }

    inline NTSTATUS place_canary_page(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        KAPC_STATE apc;
        _KeStackAttachProcess(process, &apc);

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

        _KeUnstackDetachProcess(&apc);
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
        _KeStackAttachProcess(process, &apc);

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

        _KeUnstackDetachProcess(&apc);
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
        _KeStackAttachProcess(process, &apc);

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

        _KeUnstackDetachProcess(&apc);
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
        unlock_all_pages();
        if (g_ob_handle && _ObUnRegisterCallbacks) {
            _ObUnRegisterCallbacks(g_ob_handle);
            g_ob_handle = nullptr;
        }
        g_protected_pid = 0;
        _InterlockedExchange(&g_initialized, 0);
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
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(0xA1DA0002u, pid, 0, 0, 0);
                    }
                }
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
