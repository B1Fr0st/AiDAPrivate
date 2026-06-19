#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include <cstdint>

#include <Crypter.h>
#include <imports/Strings.h>


#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD       0x0002
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION     0x0200
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION        0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ             0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE            0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE          0x0040
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME      0x0800
#endif


extern "C" UCHAR* NTAPI PsGetProcessImageFileName(PEPROCESS Process);

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
inline NTSTATUS           (NTAPI* _ZwTerminateProcess)             (HANDLE, NTSTATUS);

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
inline NTSTATUS           (NTAPI* _ZwGetContextThread)             (HANDLE, PCONTEXT);
inline NTSTATUS           (NTAPI* _ZwSetContextThread)             (HANDLE, PCONTEXT);
inline NTSTATUS           (NTAPI* _PsSuspendThread)                (PETHREAD, PULONG);
inline NTSTATUS           (NTAPI* _PsResumeThread)                 (PETHREAD, PULONG);
inline PVOID              (NTAPI* _PsGetProcessPeb)                (PEPROCESS);
inline NTSTATUS           (NTAPI* _ZwQueryVirtualMemory)           (HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
inline NTSTATUS           (NTAPI* _ZwProtectVirtualMemory)         (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
inline NTSTATUS           (NTAPI* _ObOpenObjectByPointer)          (PVOID, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PHANDLE);
inline NTSTATUS           (NTAPI* _ZwSuspendThread)                (HANDLE, PULONG);
inline NTSTATUS           (NTAPI* _ZwResumeThread)                 (HANDLE, PULONG);
inline NTSTATUS           (NTAPI* _ZwSetInformationThread)         (HANDLE, ULONG, PVOID, ULONG);

inline POBJECT_TYPE*       _IoFileObjectType = nullptr;
inline POBJECT_TYPE        (NTAPI* _ObGetObjectType)(PVOID) = nullptr;
inline BOOLEAN             (NTAPI* _ObReferenceObjectSafe)(PVOID) = nullptr;

inline NTSTATUS           (NTAPI* _ZwOpenKey)                      (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwQueryValueKey)                (HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
inline NTSTATUS           (NTAPI* _ZwDeleteFile)                    (POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwSetInformationFile)           (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
inline NTSTATUS           (NTAPI* _IoCreateFileEx)                 (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG, CREATE_FILE_TYPE, PVOID, ULONG, PIO_DRIVER_CREATE_CONTEXT);

inline VOID               (NTAPI* _KeBugCheckEx)                   (ULONG, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
inline BOOLEAN            (NTAPI* _KdRefreshDebuggerNotPresent)    (VOID) = nullptr;
inline VOID               (NTAPI* _KeInitializeDpc)                (PRKDPC, PKDEFERRED_ROUTINE, PVOID);
inline VOID               (NTAPI* _KeInitializeTimerEx)            (PKTIMER, TIMER_TYPE);
inline BOOLEAN            (NTAPI* _KeSetTimerEx)                   (PKTIMER, LARGE_INTEGER, LONG, PKDPC);
inline BOOLEAN            (NTAPI* _KeCancelTimer)                  (PKTIMER);
inline VOID               (NTAPI* _KeFlushQueuedDpcs)              (VOID);
inline VOID               (NTAPI* _ExQueueWorkItem)                (PWORK_QUEUE_ITEM, WORK_QUEUE_TYPE);

inline NTSTATUS           (NTAPI* _ObRegisterCallbacks)             (POB_CALLBACK_REGISTRATION, PVOID*);
inline VOID               (NTAPI* _ObUnRegisterCallbacks)           (PVOID);

typedef VOID (NTAPI* PCREATE_PROCESS_NOTIFY_ROUTINE_EX)(
    PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
inline NTSTATUS           (NTAPI* _PsSetCreateProcessNotifyRoutineEx)(PCREATE_PROCESS_NOTIFY_ROUTINE_EX, BOOLEAN);

typedef VOID (NTAPI* PLOAD_IMAGE_NOTIFY_ROUTINE_LOCAL)(
    PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
inline NTSTATUS           (NTAPI* _PsSetLoadImageNotifyRoutine)    (PLOAD_IMAGE_NOTIFY_ROUTINE_LOCAL);
inline NTSTATUS           (NTAPI* _PsRemoveLoadImageNotifyRoutine) (PLOAD_IMAGE_NOTIFY_ROUTINE_LOCAL);

typedef NTSTATUS (NTAPI* PEX_CALLBACK_FUNCTION_LOCAL)(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);
inline NTSTATUS           (NTAPI* _CmRegisterCallbackEx)           (PEX_CALLBACK_FUNCTION_LOCAL, PCUNICODE_STRING, PVOID, PVOID, PLARGE_INTEGER, PVOID);
inline NTSTATUS           (NTAPI* _CmUnRegisterCallback)           (LARGE_INTEGER);

inline ULONG              (__cdecl* _DbgPrintEx)                   (ULONG, ULONG, PCSTR, ...);

namespace dbg_capture { void write_formatted(const char* fmt, ...); }

#define WW_LOG(fmt, ...) do { \
        if (_DbgPrintEx) _DbgPrintEx(77, 0, "[WW] " fmt "\n", ##__VA_ARGS__); \
        dbg_capture::write_formatted("[WW] " fmt "\n", ##__VA_ARGS__); \
    } while(0)


namespace ssdt_resolver {
    typedef struct _KSERVICE_TABLE_DESCRIPTOR {
        PLONG   ServiceTable;
        PVOID   CounterTable;
        ULONG   ServiceLimit;
        ULONG   Reserved;
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
    inline volatile UINT64 g_lstar = 0;

    struct ntdll_lookup_result_t {
        PVOID peb;
        PVOID ldr;
        PVOID list_head;
        PVOID list_entry;
        PVOID ntdll_base;
        ULONG module_count;
        ULONG named_count;
        ULONG match_index;
        char selected_name[32];
        char first_name[32];
        char second_name[32];
        const char* reason;
    };

    __forceinline WCHAR lower_wchar(WCHAR c)
    {
        if (c >= L'A' && c <= L'Z')
            return static_cast<WCHAR>(c + (L'a' - L'A'));
        return c;
    }

    __forceinline void copy_unicode_ascii(PCUNICODE_STRING text, char* out, SIZE_T out_size)
    {
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
                WCHAR c = text->Buffer[i];
                out[i] = c < 0x80 ? static_cast<char>(c) : '?';
            }
            out[count] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const char ex[] = "<except>";
            SIZE_T n = sizeof(ex) - 1;
            if (n >= out_size) n = out_size - 1;
            for (SIZE_T i = 0; i < n; ++i) out[i] = ex[i];
            out[n] = 0;
        }
    }

    __forceinline BOOLEAN unicode_equals_ascii_ci(PCUNICODE_STRING text, const char* ascii)
    {
        if (!text || !text->Buffer || !ascii)
            return FALSE;
        USHORT chars = text->Length / sizeof(WCHAR);
        ULONG ascii_len = 0;
        while (ascii[ascii_len])
            ++ascii_len;
        if (chars != ascii_len)
            return FALSE;
        __try {
            for (USHORT i = 0; i < chars; ++i) {
                WCHAR lhs = lower_wchar(text->Buffer[i]);
                char rhs_c = ascii[i];
                if (rhs_c >= 'A' && rhs_c <= 'Z')
                    rhs_c = static_cast<char>(rhs_c + ('a' - 'A'));
                if (lhs != static_cast<WCHAR>(rhs_c))
                    return FALSE;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
        return TRUE;
    }

    __forceinline BOOLEAN locate_current_ntdll(ntdll_lookup_result_t* out)
    {
        if (!out)
            return FALSE;
        RtlZeroMemory(out, sizeof(*out));
        out->match_index = 0xFFFFFFFFu;
        out->reason = "unresolved";

        if (!_PsGetProcessPeb) {
            out->reason = "missing_ps_get_process_peb";
            return FALSE;
        }

        __try {
            out->peb = _PsGetProcessPeb(PsGetCurrentProcess());
            if (!out->peb) {
                out->reason = "missing_current_peb";
                return FALSE;
            }

            out->ldr = *(PVOID*)((UCHAR*)out->peb + 0x18);
            if (!out->ldr) {
                out->reason = "missing_peb_ldr";
                return FALSE;
            }

            out->list_head = (PLIST_ENTRY)((UCHAR*)out->ldr + 0x10);
            if (_MmIsAddressValid && !_MmIsAddressValid(out->list_head)) {
                out->reason = "invalid_ldr_head";
                return FALSE;
            }

            PLIST_ENTRY head = static_cast<PLIST_ENTRY>(out->list_head);
            PLIST_ENTRY entry = head->Flink;
            if (!entry || entry == head) {
                out->reason = "empty_ldr_list";
                return FALSE;
            }

            for (ULONG index = 0; index < 128 && entry && entry != head; ++index) {
                if (_MmIsAddressValid && !_MmIsAddressValid(entry)) {
                    out->reason = "invalid_ldr_entry";
                    return FALSE;
                }

                out->module_count = index + 1;
                PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
                UNICODE_STRING base_name = module->BaseDllName;
                PVOID dll_base = module->DllBase;
                char name_buf[32] = {};
                copy_unicode_ascii(&base_name, name_buf, sizeof(name_buf));
                if (index == 0)
                    RtlCopyMemory(out->first_name, name_buf, sizeof(out->first_name));
                else if (index == 1)
                    RtlCopyMemory(out->second_name, name_buf, sizeof(out->second_name));
                if (base_name.Buffer && base_name.Length != 0)
                    ++out->named_count;
                if (unicode_equals_ascii_ci(&base_name, "ntdll.dll")) {
                    out->list_entry = entry;
                    out->ntdll_base = dll_base;
                    out->match_index = index;
                    RtlCopyMemory(out->selected_name, name_buf, sizeof(out->selected_name));
                    if (!dll_base) {
                        out->reason = "missing_ntdll_base";
                        return FALSE;
                    }
                    out->reason = "found";
                    return TRUE;
                }

                entry = entry->Flink;
            }
            out->reason = "ntdll_not_found";
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            out->reason = "exception";
        }

        return FALSE;
    }

    __forceinline UINT64 read_stub_qword(PUCHAR stub)
    {
        UINT64 value = 0;
        if (!stub)
            return 0;
        __try {
            RtlCopyMemory(&value, stub, sizeof(value));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            value = 0;
        }
        return value;
    }

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
            g_lstar = lstar;
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

        if (!g_ssdt) {
            find_ssdt();
        }

        const char* reason = "unresolved";
        PVOID ntdll_base = nullptr;
        PVOID suspend_stub = nullptr;
        PVOID resume_stub = nullptr;
        ULONG suspend_idx = 0xFFFFFFFFu;
        ULONG resume_idx = 0xFFFFFFFFu;
        BOOLEAN resolved = FALSE;
        ntdll_lookup_result_t ntdll = {};
        UINT64 suspend_stub8 = 0;
        UINT64 resume_stub8 = 0;

        do {
            if (!g_ssdt || !g_ssdt->ServiceTable) {
                reason = "missing_ssdt";
                break;
            }

            if (!locate_current_ntdll(&ntdll)) {
                reason = ntdll.reason;
                break;
            }

            ntdll_base = ntdll.ntdll_base;
            __try {
                CHAR suspend_name[] = { 'N','t','S','u','s','p','e','n','d','T','h','r','e','a','d',0 };
                CHAR resume_name[]  = { 'N','t','R','e','s','u','m','e','T','h','r','e','a','d',0 };
                suspend_stub = GetProcAddress(ntdll_base, suspend_name);
                resume_stub  = GetProcAddress(ntdll_base, resume_name);
                suspend_stub8 = read_stub_qword((PUCHAR)suspend_stub);
                resume_stub8 = read_stub_qword((PUCHAR)resume_stub);
                if (!suspend_stub || !resume_stub) {
                    reason = "missing_ntdll_export";
                } else {
                    PUCHAR s_bytes = (PUCHAR)suspend_stub;
                    PUCHAR r_bytes = (PUCHAR)resume_stub;
                    if (s_bytes[0] != 0x4C || s_bytes[1] != 0x8B || s_bytes[2] != 0xD1 || s_bytes[3] != 0xB8) {
                        reason = "unexpected_suspend_stub";
                    } else if (r_bytes[0] != 0x4C || r_bytes[1] != 0x8B || r_bytes[2] != 0xD1 || r_bytes[3] != 0xB8) {
                        reason = "unexpected_resume_stub";
                    } else {
                        suspend_idx = *(PULONG)&s_bytes[4];
                        resume_idx  = *(PULONG)&r_bytes[4];
                        if (suspend_idx >= (ULONG)g_ssdt->ServiceLimit ||
                            resume_idx  >= (ULONG)g_ssdt->ServiceLimit) {
                            reason = "syscall_index_out_of_range";
                        } else {
                            g_NtSuspendThread = (fn_NtSuspendThread)get_ssdt_entry(suspend_idx);
                            g_NtResumeThread  = (fn_NtResumeThread)get_ssdt_entry(resume_idx);
                            resolved = (g_NtSuspendThread != nullptr && g_NtResumeThread != nullptr);
                            reason = resolved ? "resolved" : "null_ssdt_entry";
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                reason = "export_exception";
            }
        } while (FALSE);

        KeMemoryBarrier();
        _InterlockedExchange(&g_funcs_resolved, resolved ? 2 : 0);
        WW_LOG("SSDT resolve_suspend_resume result=%u reason=%s state=%ld ssdt=%p service_table=%p limit=%lu ntdll=%p suspend_stub=%p resume_stub=%p suspend_idx=%lu resume_idx=%lu nt_suspend=%p nt_resume=%p zw_suspend=%p zw_resume=%p ps_suspend=%p ps_resume=%p ps_get_peb=%p current_pid=%p current_tid=%p",
            resolved ? 1u : 0u,
            reason,
            _InterlockedCompareExchange(&g_funcs_resolved, 0, 0),
            g_ssdt,
            g_ssdt ? g_ssdt->ServiceTable : nullptr,
            g_ssdt ? g_ssdt->ServiceLimit : 0,
            ntdll_base,
            suspend_stub,
            resume_stub,
            suspend_idx,
            resume_idx,
            g_NtSuspendThread,
            g_NtResumeThread,
            _ZwSuspendThread,
            _ZwResumeThread,
            _PsSuspendThread,
            _PsResumeThread,
            _PsGetProcessPeb,
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId());
        WW_LOG("SSDT resolve_suspend_resume ldr_diag reason=%s ntdll_reason=%s peb=%p ldr=%p head=%p entry=%p modules=%lu names=%lu match=%lu selected='%s' first='%s' second='%s' suspend_stub8=0x%llx resume_stub8=0x%llx",
            reason,
            ntdll.reason ? ntdll.reason : "<none>",
            ntdll.peb,
            ntdll.ldr,
            ntdll.list_head,
            ntdll.list_entry,
            ntdll.module_count,
            ntdll.named_count,
            ntdll.match_index,
            ntdll.selected_name,
            ntdll.first_name,
            ntdll.second_name,
            static_cast<unsigned long long>(suspend_stub8),
            static_cast<unsigned long long>(resume_stub8));
        return resolved;
    }


    __forceinline NTSTATUS call_NtSuspendThread(HANDLE thread_handle, PULONG prev_count) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!thread_handle) return STATUS_INVALID_PARAMETER;
        if (_ZwSuspendThread) {
            NTSTATUS status = _ZwSuspendThread(thread_handle, prev_count);
            WW_LOG("SSDT call_NtSuspendThread path=zw_export status=0x%08X handle=%p prev=%lu zw_suspend=%p nt_suspend=%p ssdt=%p state=%ld",
                (ULONG)status,
                thread_handle,
                prev_count ? *prev_count : 0,
                _ZwSuspendThread,
                g_NtSuspendThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
            return status;
        }
        if (!g_NtSuspendThread) {
            find_ssdt();
            BOOLEAN resolved = resolve_suspend_resume();
            WW_LOG("SSDT call_NtSuspendThread resolve resolved=%u handle=%p ssdt=%p nt_suspend=%p nt_resume=%p state=%ld",
                resolved ? 1u : 0u,
                thread_handle,
                g_ssdt,
                g_NtSuspendThread,
                g_NtResumeThread,
                _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
        }
        if (!g_NtSuspendThread) {
            WW_LOG("SSDT call_NtSuspendThread path=missing status=0x%08X handle=%p zw_suspend=%p nt_suspend=%p ssdt=%p state=%ld",
                (ULONG)STATUS_PROCEDURE_NOT_FOUND,
                thread_handle,
                _ZwSuspendThread,
                g_NtSuspendThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        NTSTATUS status = g_NtSuspendThread(thread_handle, prev_count);
        WW_LOG("SSDT call_NtSuspendThread path=ssdt status=0x%08X handle=%p prev=%lu zw_suspend=%p nt_suspend=%p ssdt=%p state=%ld",
            (ULONG)status,
            thread_handle,
            prev_count ? *prev_count : 0,
            _ZwSuspendThread,
            g_NtSuspendThread,
            g_ssdt,
            _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
        return status;
    }

    __forceinline NTSTATUS call_NtResumeThread(HANDLE thread_handle, PULONG prev_count) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!thread_handle) return STATUS_INVALID_PARAMETER;
        if (_ZwResumeThread) {
            NTSTATUS status = _ZwResumeThread(thread_handle, prev_count);
            WW_LOG("SSDT call_NtResumeThread path=zw_export status=0x%08X handle=%p prev=%lu zw_resume=%p nt_resume=%p ssdt=%p state=%ld",
                (ULONG)status,
                thread_handle,
                prev_count ? *prev_count : 0,
                _ZwResumeThread,
                g_NtResumeThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
            return status;
        }
        if (!g_NtResumeThread) {
            find_ssdt();
            BOOLEAN resolved = resolve_suspend_resume();
            WW_LOG("SSDT call_NtResumeThread resolve resolved=%u handle=%p ssdt=%p nt_suspend=%p nt_resume=%p state=%ld",
                resolved ? 1u : 0u,
                thread_handle,
                g_ssdt,
                g_NtSuspendThread,
                g_NtResumeThread,
                _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
        }
        if (!g_NtResumeThread) {
            WW_LOG("SSDT call_NtResumeThread path=missing status=0x%08X handle=%p zw_resume=%p nt_resume=%p ssdt=%p state=%ld",
                (ULONG)STATUS_PROCEDURE_NOT_FOUND,
                thread_handle,
                _ZwResumeThread,
                g_NtResumeThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        NTSTATUS status = g_NtResumeThread(thread_handle, prev_count);
        WW_LOG("SSDT call_NtResumeThread path=ssdt status=0x%08X handle=%p prev=%lu zw_resume=%p nt_resume=%p ssdt=%p state=%ld",
            (ULONG)status,
            thread_handle,
            prev_count ? *prev_count : 0,
            _ZwResumeThread,
            g_NtResumeThread,
            g_ssdt,
            _InterlockedCompareExchange(&g_funcs_resolved, 0, 0));
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

        if (!g_ssdt) {
            find_ssdt();
        }

        const char* reason = "unresolved";
        PVOID ntdll_base = nullptr;
        PUCHAR get_bytes = nullptr;
        PUCHAR set_bytes = nullptr;
        ULONG get_idx = 0xFFFFFFFFu;
        ULONG set_idx = 0xFFFFFFFFu;
        BOOLEAN resolved = FALSE;
        ntdll_lookup_result_t ntdll = {};
        UINT64 get_stub8 = 0;
        UINT64 set_stub8 = 0;

        do {
            if (!g_ssdt || !g_ssdt->ServiceTable) {
                reason = "missing_ssdt";
                break;
            }

            if (!locate_current_ntdll(&ntdll)) {
                reason = ntdll.reason;
                break;
            }

            ntdll_base = ntdll.ntdll_base;
            __try {
                CHAR get_name[] = { 'N','t','G','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };
                CHAR set_name[] = { 'N','t','S','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };
                get_bytes = (PUCHAR)GetProcAddress(ntdll_base, get_name);
                set_bytes = (PUCHAR)GetProcAddress(ntdll_base, set_name);
                get_stub8 = read_stub_qword(get_bytes);
                set_stub8 = read_stub_qword(set_bytes);
                if (!get_bytes || !set_bytes) {
                    reason = "missing_ntdll_export";
                } else if (get_bytes[0] != 0x4C || get_bytes[1] != 0x8B || get_bytes[2] != 0xD1 || get_bytes[3] != 0xB8) {
                    reason = "unexpected_get_stub";
                } else if (set_bytes[0] != 0x4C || set_bytes[1] != 0x8B || set_bytes[2] != 0xD1 || set_bytes[3] != 0xB8) {
                    reason = "unexpected_set_stub";
                } else {
                    get_idx = *(PULONG)&get_bytes[4];
                    set_idx = *(PULONG)&set_bytes[4];
                    if (get_idx >= (ULONG)g_ssdt->ServiceLimit || set_idx >= (ULONG)g_ssdt->ServiceLimit) {
                        reason = "syscall_index_out_of_range";
                    } else {
                        g_NtGetContextThread = (fn_NtGetContextThread)get_ssdt_entry(get_idx);
                        g_NtSetContextThread = (fn_NtSetContextThread)get_ssdt_entry(set_idx);
                        resolved = (g_NtGetContextThread != nullptr && g_NtSetContextThread != nullptr);
                        reason = resolved ? "resolved" : "null_ssdt_entry";
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                reason = "export_exception";
            }
        } while (FALSE);

        KeMemoryBarrier();
        _InterlockedExchange(&g_ctx_funcs_resolved, resolved ? 2 : 0);
        WW_LOG("SSDT resolve_thread_context result=%u reason=%s state=%ld ssdt=%p service_table=%p limit=%lu ntdll=%p get_stub=%p set_stub=%p get_idx=%lu set_idx=%lu nt_get=%p nt_set=%p zw_get=%p zw_set=%p ps_get=%p ps_set=%p ps_get_peb=%p current_pid=%p current_tid=%p",
            resolved ? 1u : 0u,
            reason,
            _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0),
            g_ssdt,
            g_ssdt ? g_ssdt->ServiceTable : nullptr,
            g_ssdt ? g_ssdt->ServiceLimit : 0,
            ntdll_base,
            get_bytes,
            set_bytes,
            get_idx,
            set_idx,
            g_NtGetContextThread,
            g_NtSetContextThread,
            _ZwGetContextThread,
            _ZwSetContextThread,
            _PsGetContextThread,
            _PsSetContextThread,
            _PsGetProcessPeb,
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId());
        WW_LOG("SSDT resolve_thread_context ldr_diag reason=%s ntdll_reason=%s peb=%p ldr=%p head=%p entry=%p modules=%lu names=%lu match=%lu selected='%s' first='%s' second='%s' get_stub8=0x%llx set_stub8=0x%llx",
            reason,
            ntdll.reason ? ntdll.reason : "<none>",
            ntdll.peb,
            ntdll.ldr,
            ntdll.list_head,
            ntdll.list_entry,
            ntdll.module_count,
            ntdll.named_count,
            ntdll.match_index,
            ntdll.selected_name,
            ntdll.first_name,
            ntdll.second_name,
            static_cast<unsigned long long>(get_stub8),
            static_cast<unsigned long long>(set_stub8));
        return resolved;
    }

    __forceinline NTSTATUS call_NtGetContextThread(HANDLE thread_handle, PCONTEXT context) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!thread_handle || !context) return STATUS_INVALID_PARAMETER;
        if (_ZwGetContextThread) {
            NTSTATUS status = _ZwGetContextThread(thread_handle, context);
            WW_LOG("SSDT call_NtGetContextThread path=zw_export status=0x%08X handle=%p flags=0x%08X rip=0x%llX rsp=0x%llX zw_get=%p nt_get=%p ssdt=%p state=%ld",
                (ULONG)status,
                thread_handle,
                context->ContextFlags,
                (unsigned long long)context->Rip,
                (unsigned long long)context->Rsp,
                _ZwGetContextThread,
                g_NtGetContextThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
            return status;
        }
        if (!g_NtGetContextThread) {
            find_ssdt();
            BOOLEAN resolved = resolve_thread_context();
            WW_LOG("SSDT call_NtGetContextThread resolve resolved=%u handle=%p flags=0x%08X ssdt=%p nt_get=%p nt_set=%p state=%ld",
                resolved ? 1u : 0u,
                thread_handle,
                context->ContextFlags,
                g_ssdt,
                g_NtGetContextThread,
                g_NtSetContextThread,
                _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
        }
        if (!g_NtGetContextThread) {
            WW_LOG("SSDT call_NtGetContextThread path=missing status=0x%08X handle=%p flags=0x%08X zw_get=%p nt_get=%p ssdt=%p state=%ld",
                (ULONG)STATUS_PROCEDURE_NOT_FOUND,
                thread_handle,
                context->ContextFlags,
                _ZwGetContextThread,
                g_NtGetContextThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        NTSTATUS status = g_NtGetContextThread(thread_handle, context);
        WW_LOG("SSDT call_NtGetContextThread path=ssdt status=0x%08X handle=%p flags=0x%08X rip=0x%llX rsp=0x%llX zw_get=%p nt_get=%p ssdt=%p state=%ld",
            (ULONG)status,
            thread_handle,
            context->ContextFlags,
            (unsigned long long)context->Rip,
            (unsigned long long)context->Rsp,
            _ZwGetContextThread,
            g_NtGetContextThread,
            g_ssdt,
            _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
        return status;
    }

    __forceinline NTSTATUS call_NtSetContextThread(HANDLE thread_handle, PCONTEXT context) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!thread_handle || !context) return STATUS_INVALID_PARAMETER;
        if (_ZwSetContextThread) {
            NTSTATUS status = _ZwSetContextThread(thread_handle, context);
            WW_LOG("SSDT call_NtSetContextThread path=zw_export status=0x%08X handle=%p flags=0x%08X rip=0x%llX rsp=0x%llX zw_set=%p nt_set=%p ssdt=%p state=%ld",
                (ULONG)status,
                thread_handle,
                context->ContextFlags,
                (unsigned long long)context->Rip,
                (unsigned long long)context->Rsp,
                _ZwSetContextThread,
                g_NtSetContextThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
            return status;
        }
        if (!g_NtSetContextThread) {
            find_ssdt();
            BOOLEAN resolved = resolve_thread_context();
            WW_LOG("SSDT call_NtSetContextThread resolve resolved=%u handle=%p flags=0x%08X ssdt=%p nt_get=%p nt_set=%p state=%ld",
                resolved ? 1u : 0u,
                thread_handle,
                context->ContextFlags,
                g_ssdt,
                g_NtGetContextThread,
                g_NtSetContextThread,
                _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
        }
        if (!g_NtSetContextThread) {
            WW_LOG("SSDT call_NtSetContextThread path=missing status=0x%08X handle=%p flags=0x%08X zw_set=%p nt_set=%p ssdt=%p state=%ld",
                (ULONG)STATUS_PROCEDURE_NOT_FOUND,
                thread_handle,
                context->ContextFlags,
                _ZwSetContextThread,
                g_NtSetContextThread,
                g_ssdt,
                _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        NTSTATUS status = g_NtSetContextThread(thread_handle, context);
        WW_LOG("SSDT call_NtSetContextThread path=ssdt status=0x%08X handle=%p flags=0x%08X rip=0x%llX rsp=0x%llX zw_set=%p nt_set=%p ssdt=%p state=%ld",
            (ULONG)status,
            thread_handle,
            context->ContextFlags,
            (unsigned long long)context->Rip,
            (unsigned long long)context->Rsp,
            _ZwSetContextThread,
            g_NtSetContextThread,
            g_ssdt,
            _InterlockedCompareExchange(&g_ctx_funcs_resolved, 0, 0));
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
    *(PVOID*)&_ZwTerminateProcess = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwTerminateProcess"));

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
    *(PVOID*)&_ZwGetContextThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwGetContextThread"));
    *(PVOID*)&_ZwSetContextThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSetContextThread"));
    *(PVOID*)&_PsSuspendThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSuspendThread"));
    *(PVOID*)&_PsResumeThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsResumeThread"));
    *(PVOID*)&_PsGetProcessPeb = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsGetProcessPeb"));
    *(PVOID*)&_ZwQueryVirtualMemory = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwQueryVirtualMemory"));
    *(PVOID*)&_ZwProtectVirtualMemory = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwProtectVirtualMemory"));
    *(PVOID*)&_ObOpenObjectByPointer = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObOpenObjectByPointer"));
    *(PVOID*)&_ZwSuspendThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSuspendThread"));
    *(PVOID*)&_ZwResumeThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwResumeThread"));
    *(PVOID*)&_ZwSetInformationThread = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSetInformationThread"));

    _IoFileObjectType = (POBJECT_TYPE*)GetProcAddress(kernelBase, (PCHAR)skCrypt("IoFileObjectType"));
    *(PVOID*)&_ObGetObjectType = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObGetObjectType"));
    *(PVOID*)&_ObReferenceObjectSafe = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObReferenceObjectSafe"));

    *(PVOID*)&_ZwOpenKey = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwOpenKey"));
    *(PVOID*)&_ZwQueryValueKey = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwQueryValueKey"));
    *(PVOID*)&_ZwDeleteFile = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwDeleteFile"));
    *(PVOID*)&_ZwSetInformationFile = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSetInformationFile"));
    *(PVOID*)&_IoCreateFileEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoCreateFileEx"));

    *(PVOID*)&_KeBugCheckEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeBugCheckEx"));
    *(PVOID*)&_KdRefreshDebuggerNotPresent = GetProcAddress(kernelBase, (PCHAR)skCrypt("KdRefreshDebuggerNotPresent"));
    *(PVOID*)&_KeInitializeDpc = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeInitializeDpc"));
    *(PVOID*)&_KeInitializeTimerEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeInitializeTimerEx"));
    *(PVOID*)&_KeSetTimerEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeSetTimerEx"));
    *(PVOID*)&_KeCancelTimer = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeCancelTimer"));
    *(PVOID*)&_KeFlushQueuedDpcs = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeFlushQueuedDpcs"));
    *(PVOID*)&_ExQueueWorkItem = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExQueueWorkItem"));

    *(PVOID*)&_ObRegisterCallbacks = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObRegisterCallbacks"));
    *(PVOID*)&_ObUnRegisterCallbacks = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObUnRegisterCallbacks"));

    *(PVOID*)&_PsSetCreateProcessNotifyRoutineEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSetCreateProcessNotifyRoutineEx"));

    *(PVOID*)&_PsSetLoadImageNotifyRoutine = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSetLoadImageNotifyRoutine"));
    *(PVOID*)&_PsRemoveLoadImageNotifyRoutine = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsRemoveLoadImageNotifyRoutine"));

    *(PVOID*)&_CmRegisterCallbackEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("CmRegisterCallbackEx"));
    *(PVOID*)&_CmUnRegisterCallback = GetProcAddress(kernelBase, (PCHAR)skCrypt("CmUnRegisterCallback"));

    *(PVOID*)&_DbgPrintEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("DbgPrintEx"));

    WW_LOG("SetupFunctions: kernelBase=%p", kernelBase);
    WW_LOG("SetupFunctions: _RtlInitUnicodeString=%p _IoCreateDevice=%p _IoCreateSymbolicLink=%p", _RtlInitUnicodeString, _IoCreateDevice, _IoCreateSymbolicLink);
    WW_LOG("SetupFunctions: _IofCompleteRequest=%p _MmCopyMemory=%p _MmMapIoSpaceEx=%p", _IofCompleteRequest, _MmCopyMemory, _MmMapIoSpaceEx);
    WW_LOG("SetupFunctions: _MmUnmapIoSpace=%p _PsLookupProcessByProcessId=%p _PsGetProcessSectionBaseAddress=%p", _MmUnmapIoSpace, _PsLookupProcessByProcessId, _PsGetProcessSectionBaseAddress);
    WW_LOG("SetupFunctions: _ObfDereferenceObject=%p _ObReferenceObjectByName=%p _MmGetPhysicalMemoryRanges=%p", _ObfDereferenceObject, _ObReferenceObjectByName, _MmGetPhysicalMemoryRanges);
    WW_LOG("SetupFunctions: _MmGetVirtualForPhysical=%p _RtlGetVersion=%p _KfRaiseIrql=%p _KeLowerIrql=%p", _MmGetVirtualForPhysical, _RtlGetVersion, _KfRaiseIrql, _KeLowerIrql);
    WW_LOG("SetupFunctions: _MmIsAddressValid=%p _ZwOpenProcess=%p _ZwClose=%p _ZwTerminateProcess=%p", _MmIsAddressValid, _ZwOpenProcess, _ZwClose, _ZwTerminateProcess);
    WW_LOG("SetupFunctions: _IoAllocateMdl=%p _IoFreeMdl=%p _MmBuildMdlForNonPagedPool=%p", _IoAllocateMdl, _IoFreeMdl, _MmBuildMdlForNonPagedPool);
    WW_LOG("SetupFunctions: _MmMapLockedPagesSpecifyCache=%p _MmUnmapLockedPages=%p _MmProbeAndLockPages=%p _MmUnlockPages=%p", _MmMapLockedPagesSpecifyCache, _MmUnmapLockedPages, _MmProbeAndLockPages, _MmUnlockPages);
    WW_LOG("SetupFunctions: _PsCreateSystemThread=%p _KeDelayExecutionThread=%p _PsTerminateSystemThread=%p", _PsCreateSystemThread, _KeDelayExecutionThread, _PsTerminateSystemThread);
    WW_LOG("SetupFunctions: _KeStackAttachProcess=%p _KeUnstackDetachProcess=%p _ZwAllocateVirtualMemory=%p _ZwFreeVirtualMemory=%p", _KeStackAttachProcess, _KeUnstackDetachProcess, _ZwAllocateVirtualMemory, _ZwFreeVirtualMemory);
    WW_LOG("SetupFunctions: _IoDeleteDevice=%p _IoDeleteSymbolicLink=%p", _IoDeleteDevice, _IoDeleteSymbolicLink);
    WW_LOG("SetupFunctions: _PsLookupThreadByThreadId=%p _PsGetNextProcessThread=%p _PsGetThreadId=%p", _PsLookupThreadByThreadId, _PsGetNextProcessThread, _PsGetThreadId);
    WW_LOG("SetupFunctions: _PsGetContextThread=%p _PsSetContextThread=%p _PsSuspendThread=%p _PsResumeThread=%p", _PsGetContextThread, _PsSetContextThread, _PsSuspendThread, _PsResumeThread);
    WW_LOG("SetupFunctions: _ZwGetContextThread=%p _ZwSetContextThread=%p", _ZwGetContextThread, _ZwSetContextThread);
    WW_LOG("SetupFunctions: _PsGetProcessPeb=%p _ZwQueryVirtualMemory=%p _ZwProtectVirtualMemory=%p", _PsGetProcessPeb, _ZwQueryVirtualMemory, _ZwProtectVirtualMemory);
    WW_LOG("SetupFunctions: _ObOpenObjectByPointer=%p _ZwSuspendThread=%p _ZwResumeThread=%p _ZwSetInformationThread=%p", _ObOpenObjectByPointer, _ZwSuspendThread, _ZwResumeThread, _ZwSetInformationThread);
    WW_LOG("SetupFunctions: _IoFileObjectType=%p _ObGetObjectType=%p _ObReferenceObjectSafe=%p", _IoFileObjectType, _ObGetObjectType, _ObReferenceObjectSafe);
    WW_LOG("SetupFunctions: _ZwOpenKey=%p _ZwQueryValueKey=%p _ZwDeleteFile=%p _ZwSetInformationFile=%p", _ZwOpenKey, _ZwQueryValueKey, _ZwDeleteFile, _ZwSetInformationFile);
    WW_LOG("SetupFunctions: _IoCreateFileEx=%p _KeBugCheckEx=%p _KdRefreshDebuggerNotPresent=%p", _IoCreateFileEx, _KeBugCheckEx, _KdRefreshDebuggerNotPresent);
    WW_LOG("SetupFunctions: _KeInitializeDpc=%p _KeInitializeTimerEx=%p _KeSetTimerEx=%p _KeCancelTimer=%p _KeFlushQueuedDpcs=%p", _KeInitializeDpc, _KeInitializeTimerEx, _KeSetTimerEx, _KeCancelTimer, _KeFlushQueuedDpcs);
    WW_LOG("SetupFunctions: _ExQueueWorkItem=%p", _ExQueueWorkItem);
    WW_LOG("SetupFunctions: _ObRegisterCallbacks=%p _ObUnRegisterCallbacks=%p _PsSetCreateProcessNotifyRoutineEx=%p", _ObRegisterCallbacks, _ObUnRegisterCallbacks, _PsSetCreateProcessNotifyRoutineEx);
    WW_LOG("SetupFunctions: _PsSetLoadImageNotifyRoutine=%p _PsRemoveLoadImageNotifyRoutine=%p", _PsSetLoadImageNotifyRoutine, _PsRemoveLoadImageNotifyRoutine);
    WW_LOG("SetupFunctions: _CmRegisterCallbackEx=%p _CmUnRegisterCallback=%p", _CmRegisterCallbackEx, _CmUnRegisterCallback);
    WW_LOG("SetupFunctions: _DbgPrintEx=%p", _DbgPrintEx);

    if (!_PsSuspendThread && !_ZwSuspendThread) {
        WW_LOG("SetupFunctions: no PsSuspendThread or ZwSuspendThread, priming SSDT suspend resolver");
        BOOLEAN ssdt_found = ssdt_resolver::find_ssdt();
        BOOLEAN sr_resolved = ssdt_resolver::resolve_suspend_resume();
        WW_LOG("SetupFunctions: SSDT suspend resolver primed ssdt_found=%u suspend_resume_resolved=%u state=%ld ssdt=%p NtSuspend=%p NtResume=%p",
            ssdt_found ? 1u : 0u,
            sr_resolved ? 1u : 0u,
            _InterlockedCompareExchange(&ssdt_resolver::g_funcs_resolved, 0, 0),
            ssdt_resolver::g_ssdt,
            ssdt_resolver::g_NtSuspendThread,
            ssdt_resolver::g_NtResumeThread);
    }

    if (!_ZwGetContextThread || !_ZwSetContextThread) {
        WW_LOG("SetupFunctions: missing Zw context export, priming SSDT context resolver");
        BOOLEAN ssdt_found = ssdt_resolver::find_ssdt();
        BOOLEAN ctx_resolved = ssdt_resolver::resolve_thread_context();
        WW_LOG("SetupFunctions: SSDT context resolver primed ssdt_found=%u context_resolved=%u state=%ld ssdt=%p NtGetContext=%p NtSetContext=%p",
            ssdt_found ? 1u : 0u,
            ctx_resolved ? 1u : 0u,
            _InterlockedCompareExchange(&ssdt_resolver::g_ctx_funcs_resolved, 0, 0),
            ssdt_resolver::g_ssdt,
            ssdt_resolver::g_NtGetContextThread,
            ssdt_resolver::g_NtSetContextThread);
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
        !_IoDeleteDevice || !_IoDeleteSymbolicLink ||
        !_KeBugCheckEx || !_KeInitializeDpc || !_KeInitializeTimerEx ||
        !_KeSetTimerEx || !_KeCancelTimer || !_KeFlushQueuedDpcs ||
        !_ExQueueWorkItem) {
        WW_LOG("SetupFunctions: CRITICAL FUNCTION MISSING - returning false");
        return false;
    }

    WW_LOG("SetupFunctions: ALL functions resolved successfully");
    return true;
}
