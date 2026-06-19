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
    inline volatile LONG g_scan_timer_initialized = 0;
    inline volatile LONG g_scan_interval_seconds = 30;
    inline volatile LONG64 g_scan_cycle_id = 0;
    inline volatile ULONG g_start_session_counter = 0;
    inline volatile ULONG g_start_client_pid = 0;

    inline UNICODE_STRING g_our_device_name = {};
    inline WCHAR g_our_device_buf[128] = {};

    struct file_handle_scan_stats_t {
        NTSTATUS status;
        ULONG buffer_size;
        ULONG return_length;
        ULONG query_attempts;
        ULONG total_handles;
        ULONG handles_examined;
        ULONG file_type_index;
        ULONG lookup_attempts;
        ULONG lookup_success;
        ULONG re_tool_matches;
        ULONG file_object_checks;
        ULONG evidence_hits;
        ULONG skipped_registered;
        ULONG exceptions;
    };

    struct vad_scan_stats_t {
        NTSTATUS status;
        ULONG buffer_size;
        ULONG return_length;
        ULONG query_attempts;
        ULONG process_entries;
        ULONG skipped_registered;
        ULONG lookup_attempts;
        ULONG lookup_success;
        ULONG re_tool_matches;
        ULONG attach_attempts;
        ULONG attach_success;
        ULONG detach_count;
        ULONG vad_query_attempts;
        ULONG vad_query_success;
        ULONG mapped_regions;
        ULONG pe_headers;
        ULONG evidence_hits;
        ULONG exceptions;
    };

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

    __forceinline ULONG current_registered_client_pid() {
        return static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
            caller_validation::g_registered_client_pid));
    }

    __forceinline ULONG elapsed_us_from_100ns(ULONGLONG start_100ns, ULONGLONG end_100ns) {
        return end_100ns >= start_100ns
            ? static_cast<ULONG>((end_100ns - start_100ns) / 10ULL)
            : 0;
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

    __forceinline void scan_file_handles(file_handle_scan_stats_t* stats) {
        if (stats) RtlZeroMemory(stats, sizeof(*stats));
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            if (stats) stats->status = STATUS_INVALID_DEVICE_STATE;
            return;
        }
        if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject) {
            if (stats) stats->status = STATUS_PROCEDURE_NOT_FOUND;
            return;
        }

        ULONG buf_size = 4 * 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hFsW');
        if (!buf) {
            if (stats) {
                stats->status = STATUS_INSUFFICIENT_RESOURCES;
                stats->buffer_size = buf_size;
            }
            return;
        }

        ULONG ret_len = 0;
        if (stats) {
            stats->query_attempts++;
            stats->buffer_size = buf_size;
        }
        NTSTATUS st = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
            buf, buf_size, &ret_len);
        if (stats) {
            stats->status = st;
            stats->return_length = ret_len;
        }

        if (st == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'hFsW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'hFsW');
            if (!buf) {
                if (stats) {
                    stats->status = STATUS_INSUFFICIENT_RESOURCES;
                    stats->buffer_size = buf_size;
                    stats->return_length = ret_len;
                }
                return;
            }
            if (stats) {
                stats->query_attempts++;
                stats->buffer_size = buf_size;
            }
            st = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
                buf, buf_size, &ret_len);
            if (stats) {
                stats->status = st;
                stats->return_length = ret_len;
            }
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
        if (stats) {
            stats->total_handles = static_cast<ULONG>(
                info->NumberOfHandles > 0xFFFFFFFFULL ? 0xFFFFFFFFUL : info->NumberOfHandles);
        }

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
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            if (stats) stats->exceptions++;
                            continue;
                        }
                    }
                    _ObfDereferenceObject(my_proc);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                if (stats) stats->exceptions++;
            }
        }
        if (stats) stats->file_type_index = file_type_idx;

        PVOID our_section_base = nullptr;
        __try {
            PEPROCESS cur = nullptr;
            if (NT_SUCCESS(_PsLookupProcessByProcessId(my_pid, &cur))) {
                if (_PsGetProcessSectionBaseAddress)
                    our_section_base = _PsGetProcessSectionBaseAddress(cur);
                _ObfDereferenceObject(cur);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (stats) stats->exceptions++;
        }

        for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
            auto& h = info->Handles[i];
            if (stats) stats->handles_examined++;
            if ((HANDLE)h.UniqueProcessId == my_pid) continue;
            if (_is_registered_client((HANDLE)h.UniqueProcessId)) {
                if (stats) stats->skipped_registered++;
                continue;
            }
            if (file_type_idx != 0 && h.ObjectTypeIndex != file_type_idx) continue;

            PEPROCESS owner_proc = nullptr;
            if (stats) stats->lookup_attempts++;
            NTSTATUS look_st = _PsLookupProcessByProcessId((HANDLE)h.UniqueProcessId, &owner_proc);
            if (!NT_SUCCESS(look_st)) continue;
            if (stats) stats->lookup_success++;

            UCHAR* image_name = PsGetProcessImageFileName(owner_proc);
            bool is_re = _match_tool((const char*)image_name);
            _ObfDereferenceObject(owner_proc);

            if (!is_re) continue;
            if (stats) stats->re_tool_matches++;

            __try {
                if (!_MmIsAddressValid || !_MmIsAddressValid(h.Object)) continue;
                PFILE_OBJECT file_obj = (PFILE_OBJECT)h.Object;
                if (!_MmIsAddressValid(file_obj->FileName.Buffer)) continue;
                if (file_obj->FileName.Length == 0) continue;
                if (stats) stats->file_object_checks++;

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
                    if (stats) stats->evidence_hits++;
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
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                if (stats) stats->exceptions++;
                continue;
            }
        }

        ExFreePoolWithTag(buf, 'hFsW');
    }

    __forceinline void scan_vad_sections(vad_scan_stats_t* stats) {
        if (stats) RtlZeroMemory(stats, sizeof(*stats));
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            if (stats) stats->status = STATUS_INVALID_DEVICE_STATE;
            return;
        }
        if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject || !_MmIsAddressValid) {
            if (stats) stats->status = STATUS_PROCEDURE_NOT_FOUND;
            return;
        }

        PVOID our_section_base = nullptr;
        HANDLE my_pid = PsGetCurrentProcessId();
        __try {
            PEPROCESS cur = nullptr;
            if (NT_SUCCESS(_PsLookupProcessByProcessId(my_pid, &cur))) {
                if (_PsGetProcessSectionBaseAddress)
                    our_section_base = _PsGetProcessSectionBaseAddress(cur);
                _ObfDereferenceObject(cur);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (stats) {
                stats->exceptions++;
                stats->status = STATUS_UNSUCCESSFUL;
            }
            return;
        }

        if (!our_section_base) {
            if (stats) stats->status = STATUS_NOT_FOUND;
            return;
        }

        ULONG buf_size = 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'vAsW');
        if (!buf) {
            if (stats) {
                stats->status = STATUS_INSUFFICIENT_RESOURCES;
                stats->buffer_size = buf_size;
            }
            return;
        }

        ULONG ret_len = 0;
        if (stats) {
            stats->query_attempts++;
            stats->buffer_size = buf_size;
        }
        NTSTATUS st = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)5,
            buf, buf_size, &ret_len);
        if (stats) {
            stats->status = st;
            stats->return_length = ret_len;
        }

        if (st == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'vAsW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'vAsW');
            if (!buf) {
                if (stats) {
                    stats->status = STATUS_INSUFFICIENT_RESOURCES;
                    stats->buffer_size = buf_size;
                    stats->return_length = ret_len;
                }
                return;
            }
            if (stats) {
                stats->query_attempts++;
                stats->buffer_size = buf_size;
            }
            st = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)5,
                buf, buf_size, &ret_len);
            if (stats) {
                stats->status = st;
                stats->return_length = ret_len;
            }
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
            if (stats) stats->process_entries++;
            if (entry->UniqueProcessId == my_pid ||
                entry->UniqueProcessId == nullptr ||
                _is_registered_client(entry->UniqueProcessId)) {
                if (stats && _is_registered_client(entry->UniqueProcessId))
                    stats->skipped_registered++;
                if (entry->NextEntryOffset == 0) break;
                entry = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)entry + entry->NextEntryOffset);
                continue;
            }

            PEPROCESS proc = nullptr;
            if (stats) stats->lookup_attempts++;
            if (NT_SUCCESS(_PsLookupProcessByProcessId(entry->UniqueProcessId, &proc))) {
                if (stats) stats->lookup_success++;
                UCHAR* image_name = PsGetProcessImageFileName(proc);
                bool is_re = _match_tool((const char*)image_name);

                if (is_re && _KeStackAttachProcess && _KeUnstackDetachProcess && _ZwQueryVirtualMemory) {
                    if (stats) stats->re_tool_matches++;
                    KAPC_STATE apc_state = {};
                    BOOLEAN attached = FALSE;
                    __try {
                        if (stats) stats->attach_attempts++;
                        _KeStackAttachProcess(proc, &apc_state);
                        attached = TRUE;
                        if (stats) stats->attach_success++;

                        MEMORY_BASIC_INFORMATION mbi = {};
                        PVOID addr = nullptr;
                        SIZE_T ret_size = 0;

                        while ((ULONG_PTR)addr < 0x7FFFFFFFFFFFF000ULL) {
                            if (stats) stats->vad_query_attempts++;
                            st = _ZwQueryVirtualMemory(
                                NtCurrentProcess(), addr, MemoryBasicInformation,
                                &mbi, sizeof(mbi), &ret_size);

                            if (!NT_SUCCESS(st)) break;
                            if (stats) {
                                stats->vad_query_success++;
                                stats->status = st;
                            }

                            if (mbi.State == MEM_COMMIT &&
                                mbi.Type == MEM_MAPPED &&
                                mbi.RegionSize >= 0x1000) {
                                if (stats) stats->mapped_regions++;
                                __try {
                                    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mbi.BaseAddress;
                                    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                                        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
                                            (ULONG_PTR)mbi.BaseAddress + dos->e_lfanew);
                                        if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                            if (stats) {
                                                stats->pe_headers++;
                                                stats->evidence_hits++;
                                            }
                                            WW_LOG("FileHandleScanner: RE-tool PID %llu has mapped section at %p",
                                                (ULONG64)(ULONG_PTR)entry->UniqueProcessId, mbi.BaseAddress);
                                            sentinel_bridge::evidence_accumulator::add_evidence(
                                                sentinel_bridge::RE_REASON_TARGET_SECTION_MAPPED);
                                        }
                                    }
                                } __except (EXCEPTION_EXECUTE_HANDLER) {
                                    if (stats) stats->exceptions++;
                                }
                            }

                            addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
                            if ((ULONG_PTR)addr <= (ULONG_PTR)mbi.BaseAddress) break;
                        }

                        if (attached) {
                            _KeUnstackDetachProcess(&apc_state);
                            attached = FALSE;
                            if (stats) stats->detach_count++;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        if (stats) stats->exceptions++;
                        if (attached) {
                            _KeUnstackDetachProcess(&apc_state);
                            if (stats) stats->detach_count++;
                        }
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
        ULONGLONG start_time = KeQueryInterruptTime();
        LONG64 cycle = _InterlockedIncrement64(&g_scan_cycle_id);
        ULONG client_pid = current_registered_client_pid();
        ULONG session_counter = static_cast<ULONG>(
            _InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_start_session_counter), 0, 0));
        _InterlockedExchange(&g_scan_work_running, 1);
        WW_LOG("FileHandleScanner: work_entry id=%lld active=%ld queued=%ld running=%ld client_pid=%lu start_client=%lu session_counter=%lu irql=%lu",
            cycle,
            _InterlockedCompareExchange(&g_scanner_active, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0),
            client_pid,
            static_cast<ULONG>(_InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_start_client_pid), 0, 0)),
            session_counter,
            static_cast<ULONG>(KeGetCurrentIrql()));
        file_handle_scan_stats_t file_stats = {};
        vad_scan_stats_t vad_stats = {};
        __try {
            if (_InterlockedCompareExchange(&g_scanner_active, 1, 1) == 1 && client_pid != 0) {
                scan_file_handles(&file_stats);
                scan_vad_sections(&vad_stats);
            } else if (client_pid == 0) {
                _InterlockedExchange(&g_scanner_active, 0);
                if (_InterlockedCompareExchange(&g_scan_timer_initialized, 0, 0) != 0) {
                    KeCancelTimer(&g_scan_timer);
                    _InterlockedExchange(&g_scan_timer_initialized, 0);
                }
                WW_LOG("FileHandleScanner: work_quiesce_no_client id=%lld active=%ld queued=%ld running=%ld",
                    cycle,
                    _InterlockedCompareExchange(&g_scanner_active, 0, 0),
                    _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
                    _InterlockedCompareExchange(&g_scan_work_running, 0, 0));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            file_stats.exceptions++;
            vad_stats.exceptions++;
            WW_LOG("FileHandleScanner: work_exception id=%lld client_pid=%lu", cycle, client_pid);
        }
        _InterlockedExchange(&g_scan_work_running, 0);
        _InterlockedExchange(&g_scan_work_queued, 0);
        KeSetEvent(&g_scan_work_done, IO_NO_INCREMENT, FALSE);
        ULONGLONG end_time = KeQueryInterruptTime();
        WW_LOG("FileHandleScanner: work_exit id=%lld elapsed_us=%lu active=%ld queued=%ld running=%ld client_pid=%lu file_status=0x%08lx file_q=%lu file_buf=%lu file_ret=%lu handles=%lu examined=%lu file_type=%lu lookups=%lu/%lu re=%lu file_checks=%lu file_hits=%lu file_skip_client=%lu file_ex=%lu vad_status=0x%08lx vad_q=%lu vad_buf=%lu vad_ret=%lu proc_entries=%lu vad_skip_client=%lu lookups=%lu/%lu re=%lu attach=%lu/%lu detach=%lu vad_queries=%lu/%lu mapped=%lu pe=%lu vad_hits=%lu vad_ex=%lu",
            cycle,
            elapsed_us_from_100ns(start_time, end_time),
            _InterlockedCompareExchange(&g_scanner_active, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0),
            current_registered_client_pid(),
            file_stats.status,
            file_stats.query_attempts,
            file_stats.buffer_size,
            file_stats.return_length,
            file_stats.total_handles,
            file_stats.handles_examined,
            file_stats.file_type_index,
            file_stats.lookup_success,
            file_stats.lookup_attempts,
            file_stats.re_tool_matches,
            file_stats.file_object_checks,
            file_stats.evidence_hits,
            file_stats.skipped_registered,
            file_stats.exceptions,
            vad_stats.status,
            vad_stats.query_attempts,
            vad_stats.buffer_size,
            vad_stats.return_length,
            vad_stats.process_entries,
            vad_stats.skipped_registered,
            vad_stats.lookup_success,
            vad_stats.lookup_attempts,
            vad_stats.re_tool_matches,
            vad_stats.attach_success,
            vad_stats.attach_attempts,
            vad_stats.detach_count,
            vad_stats.vad_query_success,
            vad_stats.vad_query_attempts,
            vad_stats.mapped_regions,
            vad_stats.pe_headers,
            vad_stats.evidence_hits,
            vad_stats.exceptions);
    }

    static void NTAPI scan_dpc_callback(
        PKDPC,
        PVOID,
        PVOID,
        PVOID)
    {
        ULONG client_pid = current_registered_client_pid();
        LONG active = _InterlockedCompareExchange(&g_scanner_active, 0, 0);
        WW_LOG("FileHandleScanner: dpc_entry active=%ld queued=%ld running=%ld client_pid=%lu interval=%ld irql=%lu",
            active,
            _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0),
            client_pid,
            _InterlockedCompareExchange(&g_scan_interval_seconds, 0, 0),
            static_cast<ULONG>(KeGetCurrentIrql()));
        if (!active)
            return;
        if (client_pid == 0) {
            _InterlockedExchange(&g_scanner_active, 0);
            if (_InterlockedCompareExchange(&g_scan_timer_initialized, 0, 0) != 0) {
                KeCancelTimer(&g_scan_timer);
                _InterlockedExchange(&g_scan_timer_initialized, 0);
            }
            WW_LOG("FileHandleScanner: dpc_quiesce_no_client queued=%ld running=%ld",
                _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_scan_work_running, 0, 0));
            return;
        }
        ensure_work_sync_initialized();
        if (_InterlockedCompareExchange(&g_scan_work_running, 0, 0) != 0) {
            WW_LOG("FileHandleScanner: dpc_skip_work_running client_pid=%lu queued=%ld",
                client_pid,
                _InterlockedCompareExchange(&g_scan_work_queued, 0, 0));
            return;
        }
        if (_InterlockedCompareExchange(&g_scan_work_queued, 1, 0) != 0) {
            WW_LOG("FileHandleScanner: dpc_skip_work_already_queued client_pid=%lu running=%ld",
                client_pid,
                _InterlockedCompareExchange(&g_scan_work_running, 0, 0));
            return;
        }

        KeClearEvent(&g_scan_work_done);
        ExInitializeWorkItem(&g_scan_work_item,
            (PWORKER_THREAD_ROUTINE)scan_work_routine, nullptr);
        ExQueueWorkItem(&g_scan_work_item, DelayedWorkQueue);
        WW_LOG("FileHandleScanner: dpc_queued_work client_pid=%lu queued=%ld running=%ld",
            client_pid,
            _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0));
    }

    __forceinline void start(ULONG interval_seconds = 30, const char* reason = "session_live", HANDLE client_pid_handle = nullptr, ULONG session_counter = 0) {
        ULONGLONG start_time = KeQueryInterruptTime();
        ULONG registered_pid = current_registered_client_pid();
        ULONG client_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(client_pid_handle));
        if (client_pid == 0)
            client_pid = registered_pid;
        WW_LOG("FileHandleScanner: start_entry reason=%s interval=%lu active=%ld queued=%ld running=%ld registered_pid=%lu client_pid=%lu session_counter=%lu irql=%lu",
            reason ? reason : "unknown",
            interval_seconds,
            _InterlockedCompareExchange(&g_scanner_active, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0),
            registered_pid,
            client_pid,
            session_counter,
            static_cast<ULONG>(KeGetCurrentIrql()));
        if (client_pid == 0 || registered_pid == 0 || client_pid != registered_pid) {
            WW_LOG("FileHandleScanner: start_reject reason=%s registered_pid=%lu client_pid=%lu session_counter=%lu",
                reason ? reason : "unknown",
                registered_pid,
                client_pid,
                session_counter);
            return;
        }
        if (_InterlockedCompareExchange(&g_scanner_active, 1, 0) != 0) {
            _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_start_client_pid), static_cast<LONG>(client_pid));
            _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_start_session_counter), static_cast<LONG>(session_counter));
            WW_LOG("FileHandleScanner: start_noop_already_active reason=%s registered_pid=%lu client_pid=%lu session_counter=%lu queued=%ld running=%ld",
                reason ? reason : "unknown",
                registered_pid,
                client_pid,
                session_counter,
                _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_scan_work_running, 0, 0));
            return;
        }
        ensure_work_sync_initialized();
        if (_InterlockedCompareExchange(&g_scan_work_queued, 0, 0) != 0 ||
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0) != 0) {
            NTSTATUS wait_status = STATUS_NOT_SUPPORTED;
            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -50'000'000LL;
                wait_status = KeWaitForSingleObject(&g_scan_work_done, Executive, KernelMode, FALSE, &timeout);
            }
            if (_InterlockedCompareExchange(&g_scan_work_queued, 0, 0) != 0 ||
                _InterlockedCompareExchange(&g_scan_work_running, 0, 0) != 0) {
                WW_LOG("FileHandleScanner: start_pending_work reason=%s registered_pid=%lu client_pid=%lu session_counter=%lu wait_status=0x%08lx queued=%ld running=%ld",
                    reason ? reason : "unknown",
                    registered_pid,
                    client_pid,
                    session_counter,
                    wait_status,
                    _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
                    _InterlockedCompareExchange(&g_scan_work_running, 0, 0));
                _InterlockedExchange(&g_scanner_active, 0);
                return;
            }
        }
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_start_client_pid), static_cast<LONG>(client_pid));
        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_start_session_counter), static_cast<LONG>(session_counter));
        _InterlockedExchange(&g_scan_interval_seconds, static_cast<LONG>(interval_seconds));
        KeSetEvent(&g_scan_work_done, IO_NO_INCREMENT, FALSE);

        KeInitializeTimer(&g_scan_timer);
        KeInitializeDpc(&g_scan_dpc, scan_dpc_callback, nullptr);
        _InterlockedExchange(&g_scan_timer_initialized, 1);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -((LONG64)interval_seconds * 10000000LL);
        KeSetTimerEx(&g_scan_timer, due_time,
            interval_seconds * 1000, &g_scan_dpc);

        ULONGLONG end_time = KeQueryInterruptTime();
        WW_LOG("FileHandleScanner: start_exit reason=%s interval=%lu elapsed_us=%lu active=%ld queued=%ld running=%ld registered_pid=%lu client_pid=%lu session_counter=%lu",
            reason ? reason : "unknown",
            interval_seconds,
            elapsed_us_from_100ns(start_time, end_time),
            _InterlockedCompareExchange(&g_scanner_active, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0),
            current_registered_client_pid(),
            client_pid,
            session_counter);
    }

    __forceinline void stop(const char* reason = "manual", HANDLE client_pid_handle = nullptr, BOOLEAN wait_for_work = TRUE) {
        ULONGLONG start_time = KeQueryInterruptTime();
        ULONG client_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(client_pid_handle));
        ULONG registered_pid = current_registered_client_pid();
        LONG active_before = _InterlockedExchange(&g_scanner_active, 0);
        LONG queued_before = _InterlockedCompareExchange(&g_scan_work_queued, 0, 0);
        LONG running_before = _InterlockedCompareExchange(&g_scan_work_running, 0, 0);
        LONG timer_initialized = _InterlockedCompareExchange(&g_scan_timer_initialized, 0, 0);
        WW_LOG("FileHandleScanner: stop_entry reason=%s active_before=%ld queued_before=%ld running_before=%ld timer_initialized=%ld registered_pid=%lu client_pid=%lu wait=%u irql=%lu",
            reason ? reason : "unknown",
            active_before,
            queued_before,
            running_before,
            timer_initialized,
            registered_pid,
            client_pid,
            wait_for_work ? 1u : 0u,
            static_cast<ULONG>(KeGetCurrentIrql()));
        if (timer_initialized != 0) {
            KeCancelTimer(&g_scan_timer);
            _InterlockedExchange(&g_scan_timer_initialized, 0);
        }
        if (_KeFlushQueuedDpcs && KeGetCurrentIrql() < DISPATCH_LEVEL)
            _KeFlushQueuedDpcs();
        ensure_work_sync_initialized();
        NTSTATUS wait_status = STATUS_NOT_SUPPORTED;
        if (wait_for_work && KeGetCurrentIrql() == PASSIVE_LEVEL &&
            (_InterlockedCompareExchange(&g_scan_work_queued, 0, 0) != 0 ||
             _InterlockedCompareExchange(&g_scan_work_running, 0, 0) != 0)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50'000'000LL;
            wait_status = KeWaitForSingleObject(&g_scan_work_done, Executive, KernelMode, FALSE, &timeout);
        }
        ULONGLONG end_time = KeQueryInterruptTime();
        WW_LOG("FileHandleScanner: stop_exit reason=%s elapsed_us=%lu active=%ld queued=%ld running=%ld registered_pid=%lu client_pid=%lu wait_status=0x%08lx",
            reason ? reason : "unknown",
            elapsed_us_from_100ns(start_time, end_time),
            _InterlockedCompareExchange(&g_scanner_active, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_scan_work_running, 0, 0),
            current_registered_client_pid(),
            client_pid,
            wait_status);
    }
}

#pragma warning(pop)
