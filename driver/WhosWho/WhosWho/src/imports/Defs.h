#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include <cstdint>

#include <Crypter.h>
#include <imports/Strings.h>

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderModuleList;
    UCHAR          _Reserved0[0x20];
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    ULONG          _Reserved1;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS_INTERNAL {
    SystemModuleInformationInternal = 11
} SYSTEM_INFORMATION_CLASS_INTERNAL;

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS_INTERNAL SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

namespace func_obfuscate {
    constexpr std::uintptr_t compute_key() {
        std::uintptr_t h = 0xDEADBEEFCAFEBABEULL;
        const char* t = __TIME__ __DATE__;
        while (*t) { h = h * 31 + *t++; }
        return h ^ 0x5A5A5A5A5A5A5A5AULL;
    }

    constexpr std::uintptr_t KEY = compute_key();

    template<typename T>
    __forceinline T decode(T encoded) {
        return (T)((std::uintptr_t)encoded ^ KEY);
    }

    template<typename T>
    __forceinline T encode(T raw) {
        return (T)((std::uintptr_t)raw ^ KEY);
    }
}

inline PVOID GetProcAddress(PVOID ModBase, CHAR Name[]) {
    if (!ModBase || !Name)
        return nullptr;

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    PIMAGE_NT_HEADERS64 NT_Head = (PIMAGE_NT_HEADERS64)((ULONG64)ModBase + DosHeader->e_lfanew);
    if (NT_Head->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    ULONG export_dir_rva = NT_Head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_dir_rva)
        return nullptr;

    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + export_dir_rva);

    PULONG AddressOfFunctions = (PULONG)((ULONG64)ModBase + ExportDir->AddressOfFunctions);
    PULONG AddressOfNames = (PULONG)((ULONG64)ModBase + ExportDir->AddressOfNames);
    PUSHORT AddressOfNameOrdinals = (PUSHORT)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals);

    for (ULONG i = 0; i < ExportDir->NumberOfNames; i++) {
        const char* ExpName = (const char*)((ULONG64)ModBase + AddressOfNames[i]);

        if (!_strcmpi_a(Name, ExpName)) {
            USHORT Ordinal = AddressOfNameOrdinals[i];
            ULONG FuncRva = AddressOfFunctions[Ordinal];
            return (PVOID)((ULONG64)ModBase + FuncRva);
        }
    }

    return nullptr;
}


inline std::uintptr_t get_nt_base() {
    ULONG requiredSize = 0;


    NTSTATUS status = ZwQuerySystemInformation(
        SystemModuleInformationInternal,
        nullptr,
        0,
        &requiredSize
    );

    if (requiredSize == 0) {
        return 0;
    }


    requiredSize += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;

    PRTL_PROCESS_MODULES moduleInfo = static_cast<PRTL_PROCESS_MODULES>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, requiredSize, 'tNgW')
    );

    if (!moduleInfo) {
        return 0;
    }

    status = ZwQuerySystemInformation(
        SystemModuleInformationInternal,
        moduleInfo,
        requiredSize,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, 'tNgW');
        return 0;
    }

    std::uintptr_t kernelBase = 0;


    if (moduleInfo->NumberOfModules > 0) {
        kernelBase = reinterpret_cast<std::uintptr_t>(moduleInfo->Modules[0].ImageBase);
    }

    ExFreePoolWithTag(moduleInfo, 'tNgW');
    return kernelBase;
}

inline VOID               (NTAPI* _RtlInitUnicodeString)           (PUNICODE_STRING, PCWSTR);
inline NTSTATUS           (NTAPI* _IoCreateDevice)                 (PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*);
inline NTSTATUS           (NTAPI* _IoCreateSymbolicLink)           (PUNICODE_STRING, PUNICODE_STRING);
inline VOID               (NTAPI* _IofCompleteRequest)             (PIRP, CCHAR);
inline SIZE_T             (NTAPI* _MmCopyMemory)                   (PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T);
inline PVOID              (NTAPI* _MmMapIoSpaceEx)                 (PHYSICAL_ADDRESS, SIZE_T, ULONG);
inline VOID               (NTAPI* _MmUnmapIoSpace)                 (PVOID, SIZE_T);
inline NTSTATUS           (NTAPI* _PsLookupProcessByProcessId)     (HANDLE, PEPROCESS*);
inline PVOID              (NTAPI* _PsGetProcessSectionBaseAddress) (PEPROCESS);
inline VOID               (NTAPI* _ObfDereferenceObject)           (PVOID);
inline NTSTATUS           (NTAPI* _ObReferenceObjectByName)        (PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*);
inline NTSTATUS           (NTAPI* _RtlGetVersion)                  (PRTL_OSVERSIONINFOW);
inline PPHYSICAL_MEMORY_RANGE(NTAPI* _MmGetPhysicalMemoryRanges)   (VOID);
inline PVOID              (NTAPI* _MmGetVirtualForPhysical)        (PHYSICAL_ADDRESS);
inline KIRQL              (NTAPI* _IRQL_requires_max_(HIGH_LEVEL) _IRQL_raises_(NewIrql) _IRQL_saves_ _KfRaiseIrql) (KIRQL);
inline VOID               (NTAPI* _IRQL_requires_max_(HIGH_LEVEL) _KeLowerIrql) (KIRQL);
inline BOOLEAN            (NTAPI* _MmIsAddressValid)               (PVOID);
inline NTSTATUS           (NTAPI* _ZwOpenProcess)                  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
inline NTSTATUS           (NTAPI* _ZwClose)                        (HANDLE);

inline PMDL               (NTAPI* _IoAllocateMdl)                  (PVOID, ULONG, BOOLEAN, BOOLEAN, PIRP);
inline VOID               (NTAPI* _IoFreeMdl)                      (PMDL);
inline VOID               (NTAPI* _MmBuildMdlForNonPagedPool)      (PMDL);
inline PVOID              (NTAPI* _MmMapLockedPagesSpecifyCache)   (PMDL, KPROCESSOR_MODE, MEMORY_CACHING_TYPE, PVOID, ULONG, ULONG);
inline VOID               (NTAPI* _MmUnmapLockedPages)             (PVOID, PMDL);
inline VOID               (NTAPI* _MmProbeAndLockPages)            (PMDL, KPROCESSOR_MODE, LOCK_OPERATION);
inline VOID               (NTAPI* _MmUnlockPages)                  (PMDL);

inline NTSTATUS           (NTAPI* _PsCreateSystemThread)           (PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID);
inline NTSTATUS           (NTAPI* _KeDelayExecutionThread)         (KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER);
inline NTSTATUS           (NTAPI* _PsTerminateSystemThread)        (NTSTATUS);

inline VOID               (NTAPI* _KeStackAttachProcess)           (PEPROCESS, PKAPC_STATE);
inline VOID               (NTAPI* _KeUnstackDetachProcess)         (PKAPC_STATE);
inline NTSTATUS           (NTAPI* _ZwAllocateVirtualMemory)        (HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
inline NTSTATUS           (NTAPI* _ZwFreeVirtualMemory)            (HANDLE, PVOID*, PSIZE_T, ULONG);
inline VOID               (NTAPI* _IoDeleteDevice)                 (PDEVICE_OBJECT);
inline NTSTATUS           (NTAPI* _IoDeleteSymbolicLink)            (PUNICODE_STRING);


inline NTSTATUS           (NTAPI* _PsLookupThreadByThreadId)       (HANDLE, PETHREAD*);
inline PETHREAD           (NTAPI* _PsGetNextProcessThread)         (PEPROCESS, PETHREAD);
inline HANDLE             (NTAPI* _PsGetThreadId)                  (PETHREAD);
inline NTSTATUS           (NTAPI* _PsGetContextThread)             (PETHREAD, PCONTEXT, KPROCESSOR_MODE);
inline NTSTATUS           (NTAPI* _PsSetContextThread)             (PETHREAD, PCONTEXT, KPROCESSOR_MODE);
inline NTSTATUS           (NTAPI* _PsSuspendThread)                (PETHREAD, PULONG);
inline NTSTATUS           (NTAPI* _PsResumeThread)                 (PETHREAD, PULONG);
inline PVOID              (NTAPI* _PsGetProcessPeb)                (PEPROCESS);
inline NTSTATUS           (NTAPI* _ZwQueryVirtualMemory)           (HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
inline NTSTATUS           (NTAPI* _ZwProtectVirtualMemory)         (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
inline NTSTATUS           (NTAPI* _ObOpenObjectByPointer)          (PVOID, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PHANDLE);
inline NTSTATUS           (NTAPI* _ZwSuspendThread)                (HANDLE, PULONG);
inline NTSTATUS           (NTAPI* _ZwResumeThread)                 (HANDLE, PULONG);

inline POBJECT_TYPE*       _IoFileObjectType = nullptr;
inline POBJECT_TYPE        (NTAPI* _ObGetObjectType)(PVOID) = nullptr;

inline NTSTATUS           (NTAPI* _ZwOpenKey)                      (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwQueryValueKey)                (HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
inline NTSTATUS           (NTAPI* _ZwDeleteFile)                    (POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwSetInformationFile)           (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
inline NTSTATUS           (NTAPI* _IoCreateFileEx)                 (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG, CREATE_FILE_TYPE, PVOID, ULONG, PIO_DRIVER_CREATE_CONTEXT);


namespace ssdt_resolver {
    typedef struct _KSERVICE_TABLE_DESCRIPTOR {
        PLONG   ServiceTable;
        PVOID   CounterTable;
        ULONG64 ServiceLimit;
        PUCHAR  ArgumentTable;
    } KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

    typedef NTSTATUS (NTAPI* fn_NtSuspendThread)(HANDLE, PULONG);
    typedef NTSTATUS (NTAPI* fn_NtResumeThread)(HANDLE, PULONG);
    typedef NTSTATUS (NTAPI* fn_NtGetContextThread)(HANDLE, PCONTEXT);
    typedef NTSTATUS (NTAPI* fn_NtSetContextThread)(HANDLE, PCONTEXT);

    inline PKSERVICE_TABLE_DESCRIPTOR g_ssdt = nullptr;
    inline fn_NtSuspendThread g_NtSuspendThread = nullptr;
    inline fn_NtResumeThread  g_NtResumeThread  = nullptr;
    inline fn_NtGetContextThread g_NtGetContextThread = nullptr;
    inline fn_NtSetContextThread g_NtSetContextThread = nullptr;
    inline volatile LONG g_ssdt_found = 0;
    inline volatile LONG g_funcs_resolved = 0;
    inline volatile LONG g_ctx_funcs_resolved = 0;


    constexpr ULONG KTHREAD_PREVIOUSMODE_OFFSET = 0x232;

    __forceinline BOOLEAN find_ssdt() {
        LONG prev = _InterlockedCompareExchange(&g_ssdt_found, 1, 0);
        if (prev == 2) return g_ssdt != nullptr;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_ssdt_found, 0, 0) == 1)
                YieldProcessor();
            return g_ssdt != nullptr;
        }

        __try {

            UINT64 lstar = __readmsr(0xC0000082);
            if (lstar < 0xFFFF800000000000ULL) {
                _InterlockedExchange(&g_ssdt_found, 2);
                return FALSE;
            }

            PUCHAR scan = (PUCHAR)lstar;


            for (ULONG i = 0; i < 0x500; i++) {
                if (!_MmIsAddressValid || !_MmIsAddressValid(&scan[i + 6]))
                    break;

                if (scan[i] == 0x4C && scan[i + 1] == 0x8D && scan[i + 2] == 0x15) {
                    LONG disp = *(PLONG)&scan[i + 3];
                    UINT64 target = (UINT64)&scan[i + 7] + (LONG64)disp;

                    if (target > 0xFFFF800000000000ULL &&
                        _MmIsAddressValid((PVOID)target)) {
                        PKSERVICE_TABLE_DESCRIPTOR candidate = (PKSERVICE_TABLE_DESCRIPTOR)target;

                        if (_MmIsAddressValid(candidate->ServiceTable) &&
                            candidate->ServiceLimit > 0 && candidate->ServiceLimit < 0x2000) {
                            g_ssdt = candidate;
                            break;
                        }
                    }
                }
            }


        if (!g_ssdt) {
            for (ULONG i = 0; i < 0x300; i++) {
                if (!_MmIsAddressValid(&scan[i + 4]))
                    break;

                if (scan[i] == 0xE9) {
                    LONG jmp_disp = *(PLONG)&scan[i + 1];
                    PUCHAR jmp_target = &scan[i + 5] + jmp_disp;


                    if ((UINT64)jmp_target < 0xFFFF800000000000ULL)
                        continue;
                    LONG64 distance = (LONG64)jmp_target - (LONG64)scan;
                    if (distance > -0x10000 && distance < 0x10000)
                        continue;
                    if (!_MmIsAddressValid(jmp_target))
                        continue;


                    for (ULONG j = 0; j < 0x500; j++) {
                        if (!_MmIsAddressValid(&jmp_target[j + 6]))
                            break;

                        if (jmp_target[j] == 0x4C && jmp_target[j+1] == 0x8D && jmp_target[j+2] == 0x15) {
                            LONG ssdt_disp = *(PLONG)&jmp_target[j + 3];
                            UINT64 ssdt_addr = (UINT64)&jmp_target[j + 7] + (LONG64)ssdt_disp;

                            if (ssdt_addr > 0xFFFF800000000000ULL &&
                                _MmIsAddressValid((PVOID)ssdt_addr)) {
                                PKSERVICE_TABLE_DESCRIPTOR candidate = (PKSERVICE_TABLE_DESCRIPTOR)ssdt_addr;
                                if (_MmIsAddressValid(candidate->ServiceTable) &&
                                    candidate->ServiceLimit > 0 && candidate->ServiceLimit < 0x2000) {
                                    g_ssdt = candidate;
                                    break;
                                }
                            }
                        }
                    }
                    if (g_ssdt) break;
                }
            }
        }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_ssdt_found, 2);
        return g_ssdt != nullptr;
    }

    __forceinline PVOID get_ssdt_entry(ULONG index) {
        if (!g_ssdt || !g_ssdt->ServiceTable) return nullptr;
        if (index >= (ULONG)g_ssdt->ServiceLimit) return nullptr;

        LONG entry = g_ssdt->ServiceTable[index];
        return (PVOID)((PUCHAR)g_ssdt->ServiceTable + (entry >> 4));
    }


    __forceinline BOOLEAN resolve_suspend_resume() {
        LONG state = _InterlockedCompareExchange(&g_funcs_resolved, 0, 0);
        if (state == 2) return g_NtSuspendThread != nullptr && g_NtResumeThread != nullptr;

        LONG prev = _InterlockedCompareExchange(&g_funcs_resolved, 1, 0);
        if (prev == 2) return g_NtSuspendThread != nullptr && g_NtResumeThread != nullptr;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_funcs_resolved, 0, 0) == 1)
                YieldProcessor();
            return g_NtSuspendThread != nullptr && g_NtResumeThread != nullptr;
        }

        if (!g_ssdt || !_PsGetProcessPeb) {
            _InterlockedExchange(&g_funcs_resolved, 2);
            return FALSE;
        }

        __try {

            PVOID peb = _PsGetProcessPeb(PsGetCurrentProcess());
            if (!peb) {
                _InterlockedExchange(&g_funcs_resolved, 2);
                return FALSE;
            }


            PVOID ldr = *(PVOID*)((UCHAR*)peb + 0x18);
            if (!ldr) {
                _InterlockedExchange(&g_funcs_resolved, 2);
                return FALSE;
            }


            PLIST_ENTRY head = (PLIST_ENTRY)((UCHAR*)ldr + 0x10);
            PLIST_ENTRY entry = head->Flink;


            if (entry == head) { _InterlockedExchange(&g_funcs_resolved, 2); return FALSE; }
            entry = entry->Flink;
            if (entry == head) { _InterlockedExchange(&g_funcs_resolved, 2); return FALSE; }


            PVOID ntdll_base = *(PVOID*)((UCHAR*)entry + 0x30);
            if (!ntdll_base) {
                _InterlockedExchange(&g_funcs_resolved, 2);
                return FALSE;
            }


            CHAR suspend_name[] = { 'N','t','S','u','s','p','e','n','d','T','h','r','e','a','d',0 };
            CHAR resume_name[]  = { 'N','t','R','e','s','u','m','e','T','h','r','e','a','d',0 };

            PVOID suspend_stub = GetProcAddress(ntdll_base, suspend_name);
            PVOID resume_stub  = GetProcAddress(ntdll_base, resume_name);

            if (!suspend_stub || !resume_stub) {
                _InterlockedExchange(&g_funcs_resolved, 2);
                return FALSE;
            }


            PUCHAR s_bytes = (PUCHAR)suspend_stub;
            PUCHAR r_bytes = (PUCHAR)resume_stub;

            if (s_bytes[0] != 0x4C || s_bytes[1] != 0x8B || s_bytes[2] != 0xD1 || s_bytes[3] != 0xB8) {
                _InterlockedExchange(&g_funcs_resolved, 2);
                return FALSE;
            }
            if (r_bytes[0] != 0x4C || r_bytes[1] != 0x8B || r_bytes[2] != 0xD1 || r_bytes[3] != 0xB8) {
                _InterlockedExchange(&g_funcs_resolved, 2);
                return FALSE;
            }

            ULONG suspend_idx = *(PULONG)&s_bytes[4];
            ULONG resume_idx  = *(PULONG)&r_bytes[4];

            if (suspend_idx >= (ULONG)g_ssdt->ServiceLimit ||
                resume_idx  >= (ULONG)g_ssdt->ServiceLimit) {
                _InterlockedExchange(&g_funcs_resolved, 2);
                return FALSE;
            }

            g_NtSuspendThread = (fn_NtSuspendThread)get_ssdt_entry(suspend_idx);
            g_NtResumeThread  = (fn_NtResumeThread)get_ssdt_entry(resume_idx);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_funcs_resolved, 2);
        return g_NtSuspendThread != nullptr && g_NtResumeThread != nullptr;
    }


    __forceinline NTSTATUS call_NtSuspendThread(HANDLE thread_handle, PULONG prev_count) {
        if (!g_NtSuspendThread) return STATUS_PROCEDURE_NOT_FOUND;

        PUCHAR kthread = (PUCHAR)PsGetCurrentThread();
        CHAR saved_mode = kthread[KTHREAD_PREVIOUSMODE_OFFSET];
        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = KernelMode;

        NTSTATUS status = g_NtSuspendThread(thread_handle, prev_count);

        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = saved_mode;
        return status;
    }

    __forceinline NTSTATUS call_NtResumeThread(HANDLE thread_handle, PULONG prev_count) {
        if (!g_NtResumeThread) return STATUS_PROCEDURE_NOT_FOUND;

        PUCHAR kthread = (PUCHAR)PsGetCurrentThread();
        CHAR saved_mode = kthread[KTHREAD_PREVIOUSMODE_OFFSET];
        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = KernelMode;

        NTSTATUS status = g_NtResumeThread(thread_handle, prev_count);

        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = saved_mode;
        return status;
    }

    __forceinline BOOLEAN resolve_thread_context() {
        LONG state = _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0);
        if (state == 2) return g_NtGetContextThread != nullptr && g_NtSetContextThread != nullptr;

        LONG prev = _InterlockedCompareExchange(&g_ctx_funcs_resolved, 1, 0);
        if (prev == 2) return g_NtGetContextThread != nullptr && g_NtSetContextThread != nullptr;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0) == 1)
                YieldProcessor();
            return g_NtGetContextThread != nullptr && g_NtSetContextThread != nullptr;
        }

        if (!g_ssdt || !_PsGetProcessPeb) {
            _InterlockedExchange(&g_ctx_funcs_resolved, 2);
            return FALSE;
        }

        __try {
            PVOID peb = _PsGetProcessPeb(PsGetCurrentProcess());
            if (!peb) {
                _InterlockedExchange(&g_ctx_funcs_resolved, 2);
                return FALSE;
            }

            PVOID ldr = *(PVOID*)((UCHAR*)peb + 0x18);
            if (!ldr) {
                _InterlockedExchange(&g_ctx_funcs_resolved, 2);
                return FALSE;
            }

            PLIST_ENTRY head = (PLIST_ENTRY)((UCHAR*)ldr + 0x10);
            PLIST_ENTRY entry = head->Flink;
            if (entry == head) { _InterlockedExchange(&g_ctx_funcs_resolved, 2); return FALSE; }
            entry = entry->Flink;
            if (entry == head) { _InterlockedExchange(&g_ctx_funcs_resolved, 2); return FALSE; }

            PVOID ntdll_base = *(PVOID*)((UCHAR*)entry + 0x30);
            if (!ntdll_base) {
                _InterlockedExchange(&g_ctx_funcs_resolved, 2);
                return FALSE;
            }

            CHAR get_name[] = { 'N','t','G','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };
            CHAR set_name[] = { 'N','t','S','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };

            PUCHAR get_bytes = (PUCHAR)GetProcAddress(ntdll_base, get_name);
            PUCHAR set_bytes = (PUCHAR)GetProcAddress(ntdll_base, set_name);

            if (!get_bytes || !set_bytes) {
                _InterlockedExchange(&g_ctx_funcs_resolved, 2);
                return FALSE;
            }

            if (get_bytes[0] != 0x4C || get_bytes[1] != 0x8B || get_bytes[2] != 0xD1 || get_bytes[3] != 0xB8) {
                _InterlockedExchange(&g_ctx_funcs_resolved, 2);
                return FALSE;
            }

            if (set_bytes[0] != 0x4C || set_bytes[1] != 0x8B || set_bytes[2] != 0xD1 || set_bytes[3] != 0xB8) {
                _InterlockedExchange(&g_ctx_funcs_resolved, 2);
                return FALSE;
            }

            ULONG get_idx = *(PULONG)&get_bytes[4];
            ULONG set_idx = *(PULONG)&set_bytes[4];

            if (get_idx >= (ULONG)g_ssdt->ServiceLimit || set_idx >= (ULONG)g_ssdt->ServiceLimit) {
                _InterlockedExchange(&g_ctx_funcs_resolved, 2);
                return FALSE;
            }

            g_NtGetContextThread = (fn_NtGetContextThread)get_ssdt_entry(get_idx);
            g_NtSetContextThread = (fn_NtSetContextThread)get_ssdt_entry(set_idx);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_ctx_funcs_resolved, 2);
        return g_NtGetContextThread != nullptr && g_NtSetContextThread != nullptr;
    }

    __forceinline NTSTATUS call_NtGetContextThread(HANDLE thread_handle, PCONTEXT context) {
        if (!g_NtGetContextThread) return STATUS_PROCEDURE_NOT_FOUND;

        PUCHAR kthread = (PUCHAR)PsGetCurrentThread();
        CHAR saved_mode = kthread[KTHREAD_PREVIOUSMODE_OFFSET];
        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = KernelMode;

        NTSTATUS status = g_NtGetContextThread(thread_handle, context);

        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = saved_mode;
        return status;
    }

    __forceinline NTSTATUS call_NtSetContextThread(HANDLE thread_handle, PCONTEXT context) {
        if (!g_NtSetContextThread) return STATUS_PROCEDURE_NOT_FOUND;

        PUCHAR kthread = (PUCHAR)PsGetCurrentThread();
        CHAR saved_mode = kthread[KTHREAD_PREVIOUSMODE_OFFSET];
        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = KernelMode;

        NTSTATUS status = g_NtSetContextThread(thread_handle, context);

        kthread[KTHREAD_PREVIOUSMODE_OFFSET] = saved_mode;
        return status;
    }
}

inline bool SetupFunctions() {
    PVOID kernelBase = (PVOID)get_nt_base();

    if (!kernelBase) {
        return false;
    }

    *(PVOID*)&_RtlInitUnicodeString = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlInitUnicodeString"));
    *(PVOID*)&_IoCreateDevice = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoCreateDevice"));
    *(PVOID*)&_IoCreateSymbolicLink = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoCreateSymbolicLink"));
    *(PVOID*)&_IofCompleteRequest = GetProcAddress(kernelBase, (PCHAR)skCrypt("IofCompleteRequest"));
    *(PVOID*)&_MmCopyMemory = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmCopyMemory"));
    *(PVOID*)&_MmMapIoSpaceEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmMapIoSpaceEx"));
    *(PVOID*)&_MmUnmapIoSpace = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmUnmapIoSpace"));
    *(PVOID*)&_PsLookupProcessByProcessId = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsLookupProcessByProcessId"));
    *(PVOID*)&_PsGetProcessSectionBaseAddress = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsGetProcessSectionBaseAddress"));
    *(PVOID*)&_ObfDereferenceObject = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObfDereferenceObject"));
    *(PVOID*)&_ObReferenceObjectByName = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObReferenceObjectByName"));
    *(PVOID*)&_MmGetPhysicalMemoryRanges = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmGetPhysicalMemoryRanges"));
    *(PVOID*)&_MmGetVirtualForPhysical = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmGetVirtualForPhysical"));
    *(PVOID*)&_RtlGetVersion = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlGetVersion"));
    *(PVOID*)&_KfRaiseIrql = GetProcAddress(kernelBase, (PCHAR)skCrypt("KfRaiseIrql"));
    *(PVOID*)&_KeLowerIrql = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeLowerIrql"));
    *(PVOID*)&_MmIsAddressValid = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmIsAddressValid"));
    *(PVOID*)&_ZwOpenProcess = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwOpenProcess"));
    *(PVOID*)&_ZwClose = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwClose"));

    *(PVOID*)&_IoAllocateMdl = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoAllocateMdl"));
    *(PVOID*)&_IoFreeMdl = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoFreeMdl"));
    *(PVOID*)&_MmBuildMdlForNonPagedPool = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmBuildMdlForNonPagedPool"));
    *(PVOID*)&_MmMapLockedPagesSpecifyCache = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmMapLockedPagesSpecifyCache"));
    *(PVOID*)&_MmUnmapLockedPages = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmUnmapLockedPages"));
    *(PVOID*)&_MmProbeAndLockPages = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmProbeAndLockPages"));
    *(PVOID*)&_MmUnlockPages = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmUnlockPages"));

    *(PVOID*)&_PsCreateSystemThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsCreateSystemThread"));
    *(PVOID*)&_KeDelayExecutionThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeDelayExecutionThread"));
    *(PVOID*)&_PsTerminateSystemThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsTerminateSystemThread"));

    *(PVOID*)&_KeStackAttachProcess = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeStackAttachProcess"));
    *(PVOID*)&_KeUnstackDetachProcess = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeUnstackDetachProcess"));
    *(PVOID*)&_ZwAllocateVirtualMemory = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwAllocateVirtualMemory"));
    *(PVOID*)&_ZwFreeVirtualMemory = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwFreeVirtualMemory"));
    *(PVOID*)&_IoDeleteDevice = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoDeleteDevice"));
    *(PVOID*)&_IoDeleteSymbolicLink = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoDeleteSymbolicLink"));


    *(PVOID*)&_PsLookupThreadByThreadId = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsLookupThreadByThreadId"));
    *(PVOID*)&_PsGetNextProcessThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsGetNextProcessThread"));
    *(PVOID*)&_PsGetThreadId = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsGetThreadId"));
    *(PVOID*)&_PsGetContextThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsGetContextThread"));
    *(PVOID*)&_PsSetContextThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSetContextThread"));
    *(PVOID*)&_PsSuspendThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSuspendThread"));
    *(PVOID*)&_PsResumeThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsResumeThread"));
    *(PVOID*)&_PsGetProcessPeb = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsGetProcessPeb"));
    *(PVOID*)&_ZwQueryVirtualMemory = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwQueryVirtualMemory"));
    *(PVOID*)&_ZwProtectVirtualMemory = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwProtectVirtualMemory"));
    *(PVOID*)&_ObOpenObjectByPointer = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObOpenObjectByPointer"));
    *(PVOID*)&_ZwSuspendThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSuspendThread"));
    *(PVOID*)&_ZwResumeThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwResumeThread"));

    _IoFileObjectType = (POBJECT_TYPE*)GetProcAddress(kernelBase, (PCHAR)skCrypt("IoFileObjectType"));
    *(PVOID*)&_ObGetObjectType = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObGetObjectType"));

    *(PVOID*)&_ZwOpenKey = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwOpenKey"));
    *(PVOID*)&_ZwQueryValueKey = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwQueryValueKey"));
    *(PVOID*)&_ZwDeleteFile = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwDeleteFile"));
    *(PVOID*)&_ZwSetInformationFile = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSetInformationFile"));
    *(PVOID*)&_IoCreateFileEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoCreateFileEx"));


    if (!_PsSuspendThread && !_ZwSuspendThread) {
        ssdt_resolver::find_ssdt();
    }

    if (!_RtlInitUnicodeString || !_IoCreateDevice ||
        !_IoCreateSymbolicLink || !_IofCompleteRequest || !_MmCopyMemory ||
        !_PsLookupProcessByProcessId || !_PsGetProcessSectionBaseAddress ||
        !_ObfDereferenceObject || !_MmGetPhysicalMemoryRanges ||
        !_MmGetVirtualForPhysical || !_MmIsAddressValid ||
        !_ZwOpenProcess || !_ZwClose ||
        !_IoAllocateMdl || !_IoFreeMdl || !_MmBuildMdlForNonPagedPool ||
        !_MmMapLockedPagesSpecifyCache || !_MmUnmapLockedPages ||
        !_MmProbeAndLockPages || !_MmUnlockPages ||
        !_PsCreateSystemThread || !_KeDelayExecutionThread || !_PsTerminateSystemThread ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess ||
        !_ZwAllocateVirtualMemory || !_ZwFreeVirtualMemory ||
        !_IoDeleteDevice || !_IoDeleteSymbolicLink) {
        return false;
    }


    return true;
}
