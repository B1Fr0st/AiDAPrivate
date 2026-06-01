#pragma once
#pragma warning(push)
#pragma warning(disable: 4714)

#include <ntifs.h>
#include <intrin.h>
#include <imports/Defs.h>
#include <function/SentinelBridge.h>
#include <function/CoreSecurity.h>

namespace file_handle_scanner {

    inline const char* g_re_tools[] = {
        "procdump", "processdump", "hollowshunt",
        "pe-sieve", "scylla", "taskdmp", "minidump",
        "processhacker", "x64dbg", "x32dbg",
        "windbg", "idaq", "idaq64",
        "ghidra", "binaryninja", "dnspy", "ilspy",
        "cheatengine", "apimonitor",
        "ollydbg", "reshark", "pestudio", "radare2",
        "cutter", "hyperdbg", "reclass", "classinfo",
        "sigmaker", "peid", "titanhide",
        "scyllahide", "volatility", "rekall",
        "apispy", "procmon", "rweverything",
        "pcihunter", "pchunter", "winobj", "kerneldetect"
    };
    constexpr int g_re_tool_count = sizeof(g_re_tools) / sizeof(g_re_tools[0]);

    inline volatile LONG g_scanner_active = 0;
    inline KTIMER g_scan_timer = {};
    inline KDPC g_scan_dpc = {};
    inline WORK_QUEUE_ITEM g_scan_work_item = {};
    inline KEVENT g_scan_work_done = {};
    inline volatile LONG g_scan_work_sync_initialized = 0;
    inline volatile LONG g_scan_work_queued = 0;
    inline volatile LONG g_scan_work_running = 0;

    inline UNICODE_STRING g_our_device_name = {};
    inline WCHAR g_our_device_buf[128] = {};

    __forceinline int _lower(int c) {
        return (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c;
    }

    __forceinline void _strip_ext(const char* src, char* dst, int dst_len) {
        int len = 0;
        while (src[len] && len < dst_len - 1) {
            dst[len] = (char)_lower(src[len]);
            len++;
        }
        dst[len] = '\0';
        for (int i = len - 1; i >= 1; --i) {
            if (dst[i] == '.') {
                dst[i] = '\0';
                break;
            }
        }
    }

    __forceinline void ensure_work_sync_initialized() {
        if (_InterlockedCompareExchange(&g_scan_work_sync_initialized, 1, 0) == 0)
            KeInitializeEvent(&g_scan_work_done, NotificationEvent, TRUE);
    }

    __forceinline bool _match_tool(const char* image_name) {
        if (!image_name) return false;
        char img[64] = {};
        _strip_ext(image_name, img, sizeof(img));

        for (int t = 0; t < g_re_tool_count; ++t) {
            char tool[64] = {};
            _strip_ext(g_re_tools[t], tool, sizeof(tool));
            const char* a = img;
            const char* b = tool;
            while (*a && *b && *a == *b) { ++a; ++b; }
            if (!*a && !*b) return true;
        }
        return false;
    }

    __forceinline bool _is_registered_client(HANDLE pid) {
        return (pid != nullptr &&
                pid == caller_validation::g_registered_client_pid);
    }

    __forceinline ULONG get_build_number() {
        RTL_OSVERSIONINFOW ver = { sizeof(ver) };
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&ver)))
            return ver.dwBuildNumber;
        return 19045;
    }

    __forceinline ULONG vad_root_offset() {
        ULONG build = get_build_number();
        if (build >= 26200) return 0x7D8;
        if (build >= 26100) return 0x7D8;
        if (build >= 22631) return 0x7D8;
        if (build >= 22621) return 0x7D8;
        if (build >= 22000) return 0x7D8;
        if (build >= 19041) return 0x7D8;
        return 0x658;
    }

    __forceinline void scan_file_handles() {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;
        if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject)
            return;

        ULONG buf_size = 4 * 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hFsW');
        if (!buf) return;

        ULONG ret_len = 0;
        NTSTATUS st = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
            buf, buf_size, &ret_len);

        if (st == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'hFsW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hFsW');
            if (!buf) return;
            st = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
                buf, buf_size, &ret_len);
        }

        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(buf, 'hFsW');
            return;
        }

#pragma pack(push, 1)
        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
            PVOID Object;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR HandleValue;
            ACCESS_MASK GrantedAccess;
            USHORT CreatorBackTraceIndex;
            USHORT ObjectTypeIndex;
            ULONG HandleAttributes;
            ULONG Reserved;
        };
        struct SYSTEM_HANDLE_INFORMATION_EX {
            ULONG_PTR NumberOfHandles;
            ULONG_PTR Reserved;
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
        };
#pragma pack(pop)

        auto* info = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
        HANDLE my_pid = PsGetCurrentProcessId();

        USHORT file_type_idx = 0;
        if (_IoFileObjectType && *_IoFileObjectType && _ObGetObjectType) {
            __try {
                PEPROCESS my_proc = nullptr;
                if (NT_SUCCESS(_PsLookupProcessByProcessId(my_pid, &my_proc))) {
                    for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
                        auto& h = info->Handles[i];
                        if ((HANDLE)h.UniqueProcessId != my_pid) continue;
                        if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;
                        __try {
                            POBJECT_TYPE otype = _ObGetObjectType(h.Object);
                            if (otype == *_IoFileObjectType) {
                                file_type_idx = h.ObjectTypeIndex;
                                break;
                            }
                        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
                    }
                    _ObfDereferenceObject(my_proc);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        PVOID our_section_base = nullptr;
        __try {
            PEPROCESS cur = nullptr;
            if (NT_SUCCESS(_PsLookupProcessByProcessId(my_pid, &cur))) {
                if (_PsGetProcessSectionBaseAddress)
                    our_section_base = _PsGetProcessSectionBaseAddress(cur);
                _ObfDereferenceObject(cur);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
            auto& h = info->Handles[i];
            if ((HANDLE)h.UniqueProcessId == my_pid) continue;
            if (_is_registered_client((HANDLE)h.UniqueProcessId)) continue;
            if (file_type_idx != 0 && h.ObjectTypeIndex != file_type_idx) continue;

            PEPROCESS owner_proc = nullptr;
            NTSTATUS look_st = _PsLookupProcessByProcessId((HANDLE)h.UniqueProcessId, &owner_proc);
            if (!NT_SUCCESS(look_st)) continue;

            UCHAR* image_name = PsGetProcessImageFileName(owner_proc);
            bool is_re = _match_tool((const char*)image_name);
            _ObfDereferenceObject(owner_proc);

            if (!is_re) continue;

            __try {
                if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;
                PFILE_OBJECT file_obj = (PFILE_OBJECT)h.Object;
                if (!_MmIsAddressValid(file_obj->FileName.Buffer)) continue;
                if (file_obj->FileName.Length == 0) continue;

                WCHAR lower_name[128] = {};
                USHORT chars = file_obj->FileName.Length / sizeof(WCHAR);
                if (chars > 127) chars = 127;
                for (USHORT c = 0; c < chars; ++c) {
                    WCHAR ch = file_obj->FileName.Buffer[c];
                    lower_name[c] = (ch >= L'A' && ch <= L'Z') ? (ch + 32) : ch;
                }

                bool name_match = false;
                if (wcsstr(lower_name, L"whoswho"))
                    name_match = true;

                if (name_match) {
                    WW_LOG("FileHandleScanner: RE-tool PID %llu has file handle to our driver",
                        (ULONG64)h.UniqueProcessId);
                    sentinel_bridge::evidence_accumulator::add_evidence(
                        sentinel_bridge::RE_REASON_TARGET_FILE_OPENED);
                    if (sentinel_bridge::evidence_accumulator::should_bugcheck()) {
                        if (_KeBugCheckEx)
                            _KeBugCheckEx(0xDEAD0002u,
                                sentinel_bridge::BRIDGE_CMD_RE_EVIDENCE,
                                sentinel_bridge::RE_REASON_TARGET_FILE_OPENED, 0, 0);
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        }

        ExFreePoolWithTag(buf, 'hFsW');
    }

    __forceinline void scan_vad_sections() {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;
        if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject || !_MmIsAddressValid)
            return;

        PVOID our_section_base = nullptr;
        HANDLE my_pid = PsGetCurrentProcessId();
        __try {
            PEPROCESS cur = nullptr;
            if (NT_SUCCESS(_PsLookupProcessByProcessId(my_pid, &cur))) {
                if (_PsGetProcessSectionBaseAddress)
                    our_section_base = _PsGetProcessSectionBaseAddress(cur);
                _ObfDereferenceObject(cur);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

        if (!our_section_base) return;

        ULONG buf_size = 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'vAsW');
        if (!buf) return;

        ULONG ret_len = 0;
        NTSTATUS st = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)5,
            buf, buf_size, &ret_len);

        if (st == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'vAsW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'vAsW');
            if (!buf) return;
            st = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)5,
                buf, buf_size, &ret_len);
        }

        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(buf, 'vAsW');
            return;
        }

        struct SYSTEM_PROCESS_INFORMATION {
            ULONG NextEntryOffset;
            ULONG NumberOfThreads;
            LARGE_INTEGER WorkingSetPrivateSize;
            ULONG HardFaultCount;
            ULONG NumberOfThreadsHighWatermark;
            ULONGLONG CycleTime;
            LARGE_INTEGER CreateTime;
            LARGE_INTEGER UserTime;
            LARGE_INTEGER KernelTime;
            UNICODE_STRING ImageName;
            LONG BasePriority;
            HANDLE UniqueProcessId;
            HANDLE InheritedFromUniqueProcessId;
            ULONG HandleCount;
            ULONG SessionId;
            ULONG_PTR UniqueProcessKey;
            SIZE_T PeakVirtualSize;
            SIZE_T VirtualSize;
            ULONG PageFaultCount;
            SIZE_T PeakWorkingSetSize;
            SIZE_T WorkingSetSize;
            SIZE_T QuotaPeakPagedPoolUsage;
            SIZE_T QuotaPagedPoolUsage;
            SIZE_T QuotaPeakNonPagedPoolUsage;
            SIZE_T QuotaNonPagedPoolUsage;
            SIZE_T PagefileUsage;
            SIZE_T PeakPagefileUsage;
            SIZE_T PrivatePageCount;
            LARGE_INTEGER ReadOperationCount;
            LARGE_INTEGER WriteOperationCount;
            LARGE_INTEGER OtherOperationCount;
            LARGE_INTEGER ReadTransferCount;
            LARGE_INTEGER WriteTransferCount;
            LARGE_INTEGER OtherTransferCount;
        };

        auto* entry = (SYSTEM_PROCESS_INFORMATION*)buf;
        while (true) {
            if (entry->UniqueProcessId == my_pid ||
                entry->UniqueProcessId == nullptr ||
                _is_registered_client(entry->UniqueProcessId)) {
                if (entry->NextEntryOffset == 0) break;
                entry = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)entry + entry->NextEntryOffset);
                continue;
            }

            PEPROCESS proc = nullptr;
            if (NT_SUCCESS(_PsLookupProcessByProcessId(entry->UniqueProcessId, &proc))) {
                UCHAR* image_name = PsGetProcessImageFileName(proc);
                bool is_re = _match_tool((const char*)image_name);

                if (is_re && _KeStackAttachProcess && _KeUnstackDetachProcess && _ZwQueryVirtualMemory) {
                    KAPC_STATE apc_state = {};
                    __try {
                        _KeStackAttachProcess(proc, &apc_state);

                        MEMORY_BASIC_INFORMATION mbi = {};
                        PVOID addr = nullptr;
                        SIZE_T ret_size = 0;

                        while ((ULONG_PTR)addr < 0x7FFFFFFFFFFFF000ULL) {
                            st = _ZwQueryVirtualMemory(
                                NtCurrentProcess(), addr, MemoryBasicInformation,
                                &mbi, sizeof(mbi), &ret_size);

                            if (!NT_SUCCESS(st)) break;

                            if (mbi.State == MEM_COMMIT &&
                                mbi.Type == MEM_MAPPED &&
                                mbi.RegionSize >= 0x1000) {
                                __try {
                                    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mbi.BaseAddress;
                                    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                                        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
                                            (ULONG_PTR)mbi.BaseAddress + dos->e_lfanew);
                                        if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                            WW_LOG("FileHandleScanner: RE-tool PID %llu has mapped section at %p",
                                                (ULONG64)(ULONG_PTR)entry->UniqueProcessId, mbi.BaseAddress);
                                            sentinel_bridge::evidence_accumulator::add_evidence(
                                                sentinel_bridge::RE_REASON_TARGET_SECTION_MAPPED);
                                        }
                                    }
                                } __except (EXCEPTION_EXECUTE_HANDLER) {}
                            }

                            addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
                            if ((ULONG_PTR)addr <= (ULONG_PTR)mbi.BaseAddress) break;
                        }

                        _KeUnstackDetachProcess(&apc_state);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        _KeUnstackDetachProcess(&apc_state);
                    }
                }

                _ObfDereferenceObject(proc);
            }

            if (entry->NextEntryOffset == 0) break;
            entry = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)entry + entry->NextEntryOffset);
        }

        ExFreePoolWithTag(buf, 'vAsW');
    }

    __forceinline void NTAPI scan_work_routine(PVOID) {
        _InterlockedExchange(&g_scan_work_running, 1);
        __try {
            if (_InterlockedCompareExchange(&g_scanner_active, 1, 1) == 1) {
                scan_file_handles();
                scan_vad_sections();
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        _InterlockedExchange(&g_scan_work_running, 0);
        _InterlockedExchange(&g_scan_work_queued, 0);
        KeSetEvent(&g_scan_work_done, IO_NO_INCREMENT, FALSE);
    }

    static void NTAPI scan_dpc_callback(
        PKDPC,
        PVOID,
        PVOID,
        PVOID)
    {
        if (!_InterlockedCompareExchange(&g_scanner_active, 0, 0))
            return;
        ensure_work_sync_initialized();
        if (_InterlockedCompareExchange(&g_scan_work_queued, 1, 0) != 0)
            return;

        KeClearEvent(&g_scan_work_done);
        ExInitializeWorkItem(&g_scan_work_item,
            (PWORKER_THREAD_ROUTINE)scan_work_routine, nullptr);
        ExQueueWorkItem(&g_scan_work_item, DelayedWorkQueue);
    }

    __forceinline void start(ULONG interval_seconds = 30) {
        if (_InterlockedCompareExchange(&g_scanner_active, 1, 0) != 0)
            return;
        ensure_work_sync_initialized();
        _InterlockedExchange(&g_scan_work_queued, 0);
        _InterlockedExchange(&g_scan_work_running, 0);
        KeSetEvent(&g_scan_work_done, IO_NO_INCREMENT, FALSE);

        KeInitializeTimer(&g_scan_timer);
        KeInitializeDpc(&g_scan_dpc, scan_dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -((LONG64)interval_seconds * 10000000LL);
        KeSetTimerEx(&g_scan_timer, due_time,
            interval_seconds * 1000, &g_scan_dpc);

        WW_LOG("FileHandleScanner: started (interval=%lu sec)", interval_seconds);
    }

    __forceinline void stop() {
        _InterlockedExchange(&g_scanner_active, 0);
        KeCancelTimer(&g_scan_timer);
        KeFlushQueuedDpcs();
        ensure_work_sync_initialized();
        if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
            (_InterlockedCompareExchange(&g_scan_work_queued, 0, 0) != 0 ||
             _InterlockedCompareExchange(&g_scan_work_running, 0, 0) != 0)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50'000'000LL;
            KeWaitForSingleObject(&g_scan_work_done, Executive, KernelMode, FALSE, &timeout);
        }
        WW_LOG("FileHandleScanner: stopped");
    }
}

#pragma warning(pop)
