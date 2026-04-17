#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <imports/Defs.h>

namespace anti_dump_kernel {

    inline PVOID g_ob_handle = nullptr;
    inline volatile UINT32 g_protected_pid = 0;
    inline volatile LONG g_initialized = 0;
    inline volatile UINT64 g_blocks_count = 0;

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
                PROCESS_CREATE_THREAD;

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
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status))
            return status;

        UINT32 hidden = 0;

        __try {
            PETHREAD thread = nullptr;
            while ((thread = _PsGetNextProcessThread(process, thread)) != nullptr) {
                UINT8* thread_ptr = (UINT8*)thread;
                volatile ULONG* cross_flags = (volatile ULONG*)(thread_ptr + 0x74);
                InterlockedOr((volatile LONG*)cross_flags, 0x4);
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

    inline NTSTATUS scramble_peb_loader_data(UINT32 pid)
    {
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


    inline NTSTATUS full_protect(UINT32 pid)
    {
        NTSTATUS status;

        status = register_handle_filter(pid);
        if (!NT_SUCCESS(status) && status != STATUS_ALREADY_REGISTERED) {
            WW_LOG("anti_dump: handle filter failed 0x%08x", status);
        }

        status = hide_all_threads(pid);
        if (!NT_SUCCESS(status)) {
            WW_LOG("anti_dump: thread hide failed 0x%08x", status);
        }

        status = erase_pe_headers(pid);
        if (!NT_SUCCESS(status)) {
            WW_LOG("anti_dump: header erase failed 0x%08x", status);
        }

        corrupt_section_headers(pid);
        scramble_peb_loader_data(pid);

        return STATUS_SUCCESS;
    }


    inline void cleanup()
    {
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

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + 0x448);
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
                PEPROCESS proc = (PEPROCESS)((UINT8*)entry - 0x448);
                if (!_MmIsAddressValid(proc)) continue;

                HANDLE proc_pid = PsGetProcessId(proc);
                if ((UINT32)(ULONG_PTR)proc_pid == pid) continue;
                if ((UINT32)(ULONG_PTR)proc_pid <= 4) continue;

                UCHAR* name = PsGetProcessImageFileName(proc);
                if (!name || !_MmIsAddressValid(name)) continue;

                for (int t = 0; t < num_tools; ++t) {
                    const char* target = dump_tools[t];
                    bool match = true;
                    for (int c = 0; target[c] != '\0'; ++c) {
                        char a = (char)(name[c] | 0x20);
                        char b = (char)(target[c] | 0x20);
                        if (a != b) { match = false; break; }
                    }
                    if (match) {
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
                                    (UINT32)(ULONG_PTR)proc_pid, name);
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

    constexpr LONG TIMER_PERIOD_MS = 7000;

    inline VOID NTAPI timer_callback(
        PKDPC,
        PVOID,
        PVOID,
        PVOID)
    {
        if (!_InterlockedCompareExchange(&g_active, 0, 0))
            return;

        UINT32 pid = g_target_pid;
        if (pid == 0)
            return;

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
    }

    inline void start(UINT32 pid)
    {
        if (_InterlockedCompareExchange(&g_active, 1, 0) != 0)
            return;

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
        g_target_pid = 0;
        WW_LOG("continuous_admp: stopped");
    }
}
