#pragma once
#include <imports/Defs.h>
#include <core/Heartbeat.h>


namespace object_guard {

    inline volatile LONG g_initialized = 0;


    __forceinline bool hide_device_and_symlink(PDRIVER_OBJECT target_driver_object) {
        if (!target_driver_object || !_MmIsAddressValid(target_driver_object))
            return false;

        __try {
            PDEVICE_OBJECT device = target_driver_object->DeviceObject;
            if (!device || !_MmIsAddressValid(device))
                return false;


            UCHAR* obj_header_addr = reinterpret_cast<UCHAR*>(device) - 0x30;

            if (_MmIsAddressValid(obj_header_addr)) {


                UCHAR info_mask = obj_header_addr[0x1A];
                if (info_mask & 0x02) {


                    device->Flags |= DO_DEVICE_INITIALIZING;
                }
            }

            _InterlockedExchange(&g_initialized, 1);
            return true;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    __forceinline bool init(PDRIVER_OBJECT target_driver_object) {
        SN_LOG("object_guard::init: target_driver_object=%p", target_driver_object);
        bool result = hide_device_and_symlink(target_driver_object);
        SN_LOG("object_guard::init: result=%d", (int)result);
        return result;
    }

    inline volatile UINT64 g_last_suspicious_pid = 0;
    inline volatile UINT32 g_suspicious_handle_count = 0;

    __forceinline void scan_suspicious_handles() {
        __try {
            PEPROCESS initial = PsInitialSystemProcess;
            if (!initial || !_MmIsAddressValid(initial)) return;

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + 0x448);
            PLIST_ENTRY entry = list_head->Flink;

            const char* dump_tools[] = {
                "procdump", "processdump", "hollowshunt",
                "pe-sieve", "scylla", "taskdmp", "minidump",
                "dumper", "processhacker", "x64dbg", "x32dbg",
                "windbg", "ida", "ida64", "idaq", "idaq64",
                "ghidra", "binaryninja", "dnspy", "ilspy",
                "cheatengine", "ce.exe", "apimonitor",
                "ollydbg", "reshack", "pestudio", "radare2",
                "cutter", "hyperdbg", "reclass", "classinfo",
                "sigmaker", "peid", "die.exe", "titanhide",
                "scyllahide", "volatility", "rekall",
                "vmmap.exe", "apispy", "procmon", "rweverything",
                "pcihunter", "pchunter", "winobj", "kerneldetect"
            };
            constexpr int num_tools = sizeof(dump_tools) / sizeof(dump_tools[0]);

            for (int iter = 0; iter < 1024 && entry != list_head; ++iter, entry = entry->Flink) {
                PEPROCESS proc = (PEPROCESS)((UINT8*)entry - 0x448);
                if (!_MmIsAddressValid(proc)) continue;

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
                        HANDLE pid = PsGetProcessId(proc);
                        g_last_suspicious_pid = (UINT64)(ULONG_PTR)pid;
                        InterlockedIncrement((volatile LONG*)&g_suspicious_handle_count);
                        SN_LOG("object_guard::scan: DUMP TOOL DETECTED pid=%llu name=%.15s — TERMINATING",
                            (UINT64)(ULONG_PTR)pid, name);


                        if (_ZwOpenProcess && _ZwTerminateProcess && _ZwClose) {
                            OBJECT_ATTRIBUTES oa;
                            InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                            CLIENT_ID cid = {};
                            cid.UniqueProcess = pid;
                            HANDLE hProc = nullptr;
                            NTSTATUS term_st = _ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid);
                            if (NT_SUCCESS(term_st) && hProc) {
                                _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
                                _ZwClose(hProc);
                                SN_LOG("object_guard::scan: terminated dump tool pid=%llu",
                                    (UINT64)(ULONG_PTR)pid);
                            }
                        }


                        heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
                            static_cast<ULONG>((ULONG_PTR)pid & 0xFFFFFFFF));

                        return;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
}
