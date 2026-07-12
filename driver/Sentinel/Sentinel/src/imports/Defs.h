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


#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE            0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME       0x0002
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT          0x0008
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT          0x0010
#endif


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
    SystemModuleInformationInternal = 11,
    SystemProcessInformationInternal = 5,
    SystemHandleInformationInternal = 16,
    SystemExtendedHandleInformationInternal = 64
} SYSTEM_INFORMATION_CLASS_INTERNAL;

typedef struct _SYSTEM_PROCESS_INFORMATION_ENTRY {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} SYSTEM_PROCESS_INFORMATION_ENTRY, *PSYSTEM_PROCESS_INFORMATION_ENTRY;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_X {
    ULONG UniqueProcessId;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_X, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_X;

typedef struct _SYSTEM_HANDLE_INFORMATION_X {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_X Handles[1];
} SYSTEM_HANDLE_INFORMATION_X, *PSYSTEM_HANDLE_INFORMATION_X;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT HandleAttributes;
    USHORT Reserved;
    PVOID ObjectCreatorInfo;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _UM_PEB_LDR_DATA_X {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} UM_PEB_LDR_DATA_X, *PUM_PEB_LDR_DATA_X;

typedef struct _UM_LDR_DATA_TABLE_ENTRY_X {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    ULONG Padding;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} UM_LDR_DATA_TABLE_ENTRY_X, *PUM_LDR_DATA_TABLE_ENTRY_X;

constexpr ULONG_PTR AIDA_WATERMARK_MAGIC = 0xA1DA71A5u;
constexpr ULONGLONG AIDA_WATERMARK_MAGIC_64 = 0xA1DA71A5A1DA71A5ULL;
constexpr ULONG_PTR AIDA_WATERMARK_OPT_HDR_OFFSET = 0x70;
constexpr ULONG BUGCHECK_MODULE_CROSSCHECK = 0xA1DA0001u;
constexpr ULONG BUGCHECK_SSDT_HOOK         = 0xA1DA000Au;

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

    if (requiredSize == 0)
        return 0;

    requiredSize += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;

    PRTL_PROCESS_MODULES moduleInfo = static_cast<PRTL_PROCESS_MODULES>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, requiredSize, 'tSmM')
    );

    if (!moduleInfo)
        return 0;

    status = ZwQuerySystemInformation(
        SystemModuleInformationInternal,
        moduleInfo,
        requiredSize,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, 'tSmM');
        return 0;
    }

    std::uintptr_t kernelBase = 0;

    if (moduleInfo->NumberOfModules > 0)
        kernelBase = reinterpret_cast<std::uintptr_t>(moduleInfo->Modules[0].ImageBase);

    ExFreePoolWithTag(moduleInfo, 'tSmM');
    return kernelBase;
}


inline BOOLEAN            (NTAPI* _MmIsAddressValid)                (PVOID);
inline SIZE_T             (NTAPI* _MmCopyMemory)                    (PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T);
inline PVOID              (NTAPI* _MmMapIoSpaceEx)                  (PHYSICAL_ADDRESS, SIZE_T, ULONG);
inline VOID               (NTAPI* _MmUnmapIoSpace)                 (PVOID, SIZE_T);


inline PMDL               (NTAPI* _IoAllocateMdl)                   (PVOID, ULONG, BOOLEAN, BOOLEAN, PIRP);
inline VOID               (NTAPI* _IoFreeMdl)                       (PMDL);
inline VOID               (NTAPI* _MmBuildMdlForNonPagedPool)       (PMDL);
inline PVOID              (NTAPI* _MmMapLockedPagesSpecifyCache)    (PMDL, KPROCESSOR_MODE, MEMORY_CACHING_TYPE, PVOID, ULONG, ULONG);
inline VOID               (NTAPI* _MmUnmapLockedPages)              (PVOID, PMDL);
inline VOID               (NTAPI* _MmProbeAndLockPages)             (PMDL, KPROCESSOR_MODE, LOCK_OPERATION);
inline VOID               (NTAPI* _MmUnlockPages)                   (PMDL);


inline VOID               (NTAPI* _KeInitializeDpc)                 (PRKDPC, PKDEFERRED_ROUTINE, PVOID);
inline VOID               (NTAPI* _KeInitializeTimerEx)             (PKTIMER, TIMER_TYPE);
inline BOOLEAN            (NTAPI* _KeSetTimerEx)                    (PKTIMER, LARGE_INTEGER, LONG, PRKDPC);
inline BOOLEAN            (NTAPI* _KeCancelTimer)                   (PKTIMER);
inline VOID               (NTAPI* _KeFlushQueuedDpcs)               (VOID);

inline ULONG              (__cdecl* _DbgPrintEx)                   (ULONG, ULONG, PCSTR, ...);

namespace dbg_capture { void write_formatted(const char* fmt, ...); }

#define SN_LOG(fmt, ...) do { \
        if (_DbgPrintEx) _DbgPrintEx(77, 0, "[SN] " fmt "\n", ##__VA_ARGS__); \
        dbg_capture::write_formatted("[SN] " fmt "\n", ##__VA_ARGS__); \
    } while(0)


inline VOID               (NTAPI* _KeBugCheckEx)                    (ULONG, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);


inline ULONG_PTR          (NTAPI* _KeIpiGenericCall)                (PKIPI_BROADCAST_WORKER, ULONG_PTR);


inline NTSTATUS           (NTAPI* _PsCreateSystemThread)            (PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID);
inline NTSTATUS           (NTAPI* _KeDelayExecutionThread)          (KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER);
inline NTSTATUS           (NTAPI* _PsTerminateSystemThread)         (NTSTATUS);


inline VOID               (NTAPI* _ObfDereferenceObject)            (PVOID);
inline NTSTATUS           (NTAPI* _ObReferenceObjectByName)         (PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*);
inline NTSTATUS           (NTAPI* _ObRegisterCallbacks)             (POB_CALLBACK_REGISTRATION, PVOID*);
inline VOID               (NTAPI* _ObUnRegisterCallbacks)           (PVOID);
inline NTSTATUS           (NTAPI* _ZwClose)                         (HANDLE);


inline VOID               (NTAPI* _RtlInitUnicodeString)            (PUNICODE_STRING, PCWSTR);
inline NTSTATUS           (NTAPI* _RtlGetVersion)                   (PRTL_OSVERSIONINFOW);


inline KIRQL              (NTAPI* _IRQL_requires_max_(HIGH_LEVEL) _IRQL_raises_(NewIrql) _IRQL_saves_ _KfRaiseIrql) (KIRQL);
inline VOID               (NTAPI* _IRQL_requires_max_(HIGH_LEVEL) _KeLowerIrql) (KIRQL);


inline BOOLEAN            (NTAPI* _ExAcquireResourceExclusiveLite)  (PERESOURCE, BOOLEAN);
inline VOID               (NTAPI* _ExReleaseResourceLite)           (PERESOURCE);
inline PVOID              (NTAPI* _RtlLookupElementGenericTableAvl) (PRTL_AVL_TABLE, PVOID);
inline BOOLEAN            (NTAPI* _RtlDeleteElementGenericTableAvl) (PRTL_AVL_TABLE, PVOID);


inline VOID               (NTAPI* _KeEnterCriticalRegion)           (VOID);
inline VOID               (NTAPI* _KeLeaveCriticalRegion)           (VOID);

inline VOID               (NTAPI* _ExQueueWorkItem)                (PWORK_QUEUE_ITEM, WORK_QUEUE_TYPE);


inline NTSTATUS           (NTAPI* _ZwOpenKey)                       (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwQueryValueKey)                 (HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
inline NTSTATUS           (NTAPI* _ZwDeleteFile)                    (POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwSetInformationFile)            (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
inline NTSTATUS           (NTAPI* _IoCreateFileEx)                  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG, CREATE_FILE_TYPE, PVOID, ULONG, PIO_DRIVER_CREATE_CONTEXT);


inline NTSTATUS           (NTAPI* _PsSetCreateProcessNotifyRoutine) (PCREATE_PROCESS_NOTIFY_ROUTINE, BOOLEAN);
typedef VOID (NTAPI* PCREATE_PROCESS_NOTIFY_ROUTINE_EX)(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);
inline NTSTATUS           (NTAPI* _PsSetCreateProcessNotifyRoutineEx) (PCREATE_PROCESS_NOTIFY_ROUTINE_EX, BOOLEAN);
inline NTSTATUS           (NTAPI* _PsSetLoadImageNotifyRoutine)     (PLOAD_IMAGE_NOTIFY_ROUTINE);
inline NTSTATUS           (NTAPI* _PsRemoveLoadImageNotifyRoutine)  (PLOAD_IMAGE_NOTIFY_ROUTINE);

inline NTSTATUS           (NTAPI* _ZwTerminateProcess)              (HANDLE, NTSTATUS);
inline NTSTATUS           (NTAPI* _ZwOpenProcess)                   (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

inline VOID               (NTAPI* _KeStackAttachProcess)            (PRKPROCESS, PKAPC_STATE);
inline VOID               (NTAPI* _KeUnstackDetachProcess)          (PKAPC_STATE);
inline NTSTATUS           (NTAPI* _ObQueryNameString)               (PVOID, POBJECT_NAME_INFORMATION, ULONG, PULONG);
inline PPEB               (NTAPI* _PsGetProcessPeb)                 (PEPROCESS);

inline POBJECT_TYPE*       _IoDriverObjectType_ptr = nullptr;
inline POBJECT_TYPE*       _IoFileObjectType_ptr = nullptr;
inline POBJECT_TYPE        (NTAPI* _ObGetObjectType)(PVOID) = nullptr;

inline PVOID              (NTAPI* _MmGetSystemRoutineAddress)     (PUNICODE_STRING);

inline NTSTATUS           (NTAPI* _ZwOpenFile)                    (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
inline NTSTATUS           (NTAPI* _ObReferenceObjectByHandle)     (HANDLE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID*, POBJECT_HANDLE_INFORMATION);


inline bool SetupFunctions() {
    PVOID kernelBase = (PVOID)get_nt_base();

    if (!kernelBase)
        return false;


    *(PVOID*)&_MmIsAddressValid             = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmIsAddressValid"));
    *(PVOID*)&_MmCopyMemory                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmCopyMemory"));
    *(PVOID*)&_MmMapIoSpaceEx               = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmMapIoSpaceEx"));
    *(PVOID*)&_MmUnmapIoSpace               = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmUnmapIoSpace"));


    *(PVOID*)&_IoAllocateMdl                = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoAllocateMdl"));
    *(PVOID*)&_IoFreeMdl                    = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoFreeMdl"));
    *(PVOID*)&_MmBuildMdlForNonPagedPool    = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmBuildMdlForNonPagedPool"));
    *(PVOID*)&_MmMapLockedPagesSpecifyCache = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmMapLockedPagesSpecifyCache"));
    *(PVOID*)&_MmUnmapLockedPages           = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmUnmapLockedPages"));
    *(PVOID*)&_MmProbeAndLockPages          = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmProbeAndLockPages"));
    *(PVOID*)&_MmUnlockPages               = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmUnlockPages"));


    *(PVOID*)&_KeInitializeDpc              = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeInitializeDpc"));
    *(PVOID*)&_KeInitializeTimerEx          = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeInitializeTimerEx"));
    *(PVOID*)&_KeSetTimerEx                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeSetTimerEx"));
    *(PVOID*)&_KeCancelTimer                = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeCancelTimer"));
    *(PVOID*)&_KeFlushQueuedDpcs            = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeFlushQueuedDpcs"));

    *(PVOID*)&_DbgPrintEx                  = GetProcAddress(kernelBase, (PCHAR)skCrypt("DbgPrintEx"));


    *(PVOID*)&_KeBugCheckEx                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeBugCheckEx"));


    *(PVOID*)&_KeIpiGenericCall             = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeIpiGenericCall"));


    *(PVOID*)&_PsCreateSystemThread         = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsCreateSystemThread"));
    *(PVOID*)&_KeDelayExecutionThread       = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeDelayExecutionThread"));
    *(PVOID*)&_PsTerminateSystemThread      = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsTerminateSystemThread"));


    *(PVOID*)&_ObfDereferenceObject         = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObfDereferenceObject"));
    *(PVOID*)&_ObReferenceObjectByName      = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObReferenceObjectByName"));
    *(PVOID*)&_ObRegisterCallbacks          = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObRegisterCallbacks"));
    *(PVOID*)&_ObUnRegisterCallbacks        = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObUnRegisterCallbacks"));
    *(PVOID*)&_ZwClose                      = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwClose"));


    *(PVOID*)&_RtlInitUnicodeString         = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlInitUnicodeString"));
    *(PVOID*)&_RtlGetVersion                = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlGetVersion"));


    *(PVOID*)&_KfRaiseIrql                  = GetProcAddress(kernelBase, (PCHAR)skCrypt("KfRaiseIrql"));
    *(PVOID*)&_KeLowerIrql                  = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeLowerIrql"));


    *(PVOID*)&_ExAcquireResourceExclusiveLite  = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExAcquireResourceExclusiveLite"));
    *(PVOID*)&_ExReleaseResourceLite           = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExReleaseResourceLite"));
    *(PVOID*)&_RtlLookupElementGenericTableAvl = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlLookupElementGenericTableAvl"));
    *(PVOID*)&_RtlDeleteElementGenericTableAvl = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlDeleteElementGenericTableAvl"));


    *(PVOID*)&_KeEnterCriticalRegion           = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeEnterCriticalRegion"));
    *(PVOID*)&_KeLeaveCriticalRegion           = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeLeaveCriticalRegion"));

    *(PVOID*)&_ExQueueWorkItem                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExQueueWorkItem"));


    *(PVOID*)&_ZwOpenKey                       = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwOpenKey"));
    *(PVOID*)&_ZwQueryValueKey                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwQueryValueKey"));
    *(PVOID*)&_ZwDeleteFile                    = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwDeleteFile"));
    *(PVOID*)&_ZwSetInformationFile            = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSetInformationFile"));
    *(PVOID*)&_IoCreateFileEx                  = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoCreateFileEx"));


    *(PVOID*)&_PsSetCreateProcessNotifyRoutine = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSetCreateProcessNotifyRoutine"));
    *(PVOID*)&_PsSetCreateProcessNotifyRoutineEx = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSetCreateProcessNotifyRoutineEx"));
    *(PVOID*)&_PsSetLoadImageNotifyRoutine     = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSetLoadImageNotifyRoutine"));
    *(PVOID*)&_PsRemoveLoadImageNotifyRoutine  = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsRemoveLoadImageNotifyRoutine"));

    *(PVOID*)&_ZwTerminateProcess              = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwTerminateProcess"));
    *(PVOID*)&_ZwOpenProcess                   = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwOpenProcess"));

    *(PVOID*)&_KeStackAttachProcess            = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeStackAttachProcess"));
    *(PVOID*)&_KeUnstackDetachProcess          = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeUnstackDetachProcess"));
    *(PVOID*)&_ObQueryNameString               = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObQueryNameString"));
    *(PVOID*)&_PsGetProcessPeb                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsGetProcessPeb"));

    _IoDriverObjectType_ptr = (POBJECT_TYPE*)GetProcAddress(kernelBase, (PCHAR)skCrypt("IoDriverObjectType"));
    _IoFileObjectType_ptr = (POBJECT_TYPE*)GetProcAddress(kernelBase, (PCHAR)skCrypt("IoFileObjectType"));
    *(PVOID*)&_ObGetObjectType = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObGetObjectType"));

    *(PVOID*)&_MmGetSystemRoutineAddress     = GetProcAddress(kernelBase, (PCHAR)skCrypt("MmGetSystemRoutineAddress"));
    *(PVOID*)&_ZwOpenFile                    = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwOpenFile"));
    *(PVOID*)&_ObReferenceObjectByHandle     = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObReferenceObjectByHandle"));

    SN_LOG("SetupFunctions: kernelBase=%p", kernelBase);
    SN_LOG("SetupFunctions: _MmIsAddressValid=%p _MmCopyMemory=%p _MmMapIoSpaceEx=%p _MmUnmapIoSpace=%p", _MmIsAddressValid, _MmCopyMemory, _MmMapIoSpaceEx, _MmUnmapIoSpace);
    SN_LOG("SetupFunctions: _IoAllocateMdl=%p _IoFreeMdl=%p _MmBuildMdlForNonPagedPool=%p", _IoAllocateMdl, _IoFreeMdl, _MmBuildMdlForNonPagedPool);
    SN_LOG("SetupFunctions: _MmMapLockedPagesSpecifyCache=%p _MmUnmapLockedPages=%p _MmProbeAndLockPages=%p _MmUnlockPages=%p", _MmMapLockedPagesSpecifyCache, _MmUnmapLockedPages, _MmProbeAndLockPages, _MmUnlockPages);
    SN_LOG("SetupFunctions: _KeInitializeDpc=%p _KeInitializeTimerEx=%p _KeSetTimerEx=%p _KeCancelTimer=%p _KeFlushQueuedDpcs=%p", _KeInitializeDpc, _KeInitializeTimerEx, _KeSetTimerEx, _KeCancelTimer, _KeFlushQueuedDpcs);
    SN_LOG("SetupFunctions: _DbgPrintEx=%p _KeBugCheckEx=%p _KeIpiGenericCall=%p", _DbgPrintEx, _KeBugCheckEx, _KeIpiGenericCall);
    SN_LOG("SetupFunctions: _PsCreateSystemThread=%p _KeDelayExecutionThread=%p _PsTerminateSystemThread=%p", _PsCreateSystemThread, _KeDelayExecutionThread, _PsTerminateSystemThread);
    SN_LOG("SetupFunctions: _ObfDereferenceObject=%p _ObReferenceObjectByName=%p _ObRegisterCallbacks=%p _ObUnRegisterCallbacks=%p", _ObfDereferenceObject, _ObReferenceObjectByName, _ObRegisterCallbacks, _ObUnRegisterCallbacks);
    SN_LOG("SetupFunctions: _ZwClose=%p _RtlInitUnicodeString=%p _RtlGetVersion=%p", _ZwClose, _RtlInitUnicodeString, _RtlGetVersion);
    SN_LOG("SetupFunctions: _KfRaiseIrql=%p _KeLowerIrql=%p", _KfRaiseIrql, _KeLowerIrql);
    SN_LOG("SetupFunctions: _ExAcquireResourceExclusiveLite=%p _ExReleaseResourceLite=%p", _ExAcquireResourceExclusiveLite, _ExReleaseResourceLite);
    SN_LOG("SetupFunctions: _RtlLookupElementGenericTableAvl=%p _RtlDeleteElementGenericTableAvl=%p", _RtlLookupElementGenericTableAvl, _RtlDeleteElementGenericTableAvl);
    SN_LOG("SetupFunctions: _KeEnterCriticalRegion=%p _KeLeaveCriticalRegion=%p _ExQueueWorkItem=%p", _KeEnterCriticalRegion, _KeLeaveCriticalRegion, _ExQueueWorkItem);
    SN_LOG("SetupFunctions: _ZwOpenKey=%p _ZwQueryValueKey=%p _ZwDeleteFile=%p _ZwSetInformationFile=%p _IoCreateFileEx=%p", _ZwOpenKey, _ZwQueryValueKey, _ZwDeleteFile, _ZwSetInformationFile, _IoCreateFileEx);
    SN_LOG("SetupFunctions: _PsSetCreateProcessNotifyRoutine=%p _PsSetCreateProcessNotifyRoutineEx=%p", _PsSetCreateProcessNotifyRoutine, _PsSetCreateProcessNotifyRoutineEx);
    SN_LOG("SetupFunctions: _PsSetLoadImageNotifyRoutine=%p _PsRemoveLoadImageNotifyRoutine=%p", _PsSetLoadImageNotifyRoutine, _PsRemoveLoadImageNotifyRoutine);
    SN_LOG("SetupFunctions: _ZwTerminateProcess=%p _ZwOpenProcess=%p _IoDriverObjectType_ptr=%p", _ZwTerminateProcess, _ZwOpenProcess, _IoDriverObjectType_ptr);
    SN_LOG("SetupFunctions: _IoFileObjectType_ptr=%p _ObGetObjectType=%p", _IoFileObjectType_ptr, _ObGetObjectType);
    SN_LOG("SetupFunctions: _KeStackAttachProcess=%p _KeUnstackDetachProcess=%p _ObQueryNameString=%p _PsGetProcessPeb=%p",
        _KeStackAttachProcess, _KeUnstackDetachProcess, _ObQueryNameString, _PsGetProcessPeb);
    SN_LOG("SetupFunctions: _MmGetSystemRoutineAddress=%p", _MmGetSystemRoutineAddress);
    SN_LOG("SetupFunctions: _ZwOpenFile=%p _ObReferenceObjectByHandle=%p", _ZwOpenFile, _ObReferenceObjectByHandle);

    if (!_MmIsAddressValid || !_MmCopyMemory ||
        !_IoAllocateMdl || !_IoFreeMdl || !_MmBuildMdlForNonPagedPool ||
        !_MmMapLockedPagesSpecifyCache || !_MmUnmapLockedPages ||
        !_KeInitializeDpc || !_KeInitializeTimerEx || !_KeSetTimerEx ||
        !_KeCancelTimer || !_KeBugCheckEx || !_KeIpiGenericCall ||
        !_PsCreateSystemThread || !_KeDelayExecutionThread || !_PsTerminateSystemThread ||
        !_ObfDereferenceObject || !_ZwClose ||
        !_RtlInitUnicodeString || !_RtlGetVersion ||
        !_ExAcquireResourceExclusiveLite || !_ExReleaseResourceLite ||
        !_ExQueueWorkItem) {
        SN_LOG("SetupFunctions: CRITICAL FUNCTION MISSING - returning false");
        return false;
    }

    SN_LOG("SetupFunctions: ALL functions resolved successfully");
    return true;
}


namespace hvci_detect {

    constexpr ULONG CI_OPTION_HVCI_KMCI_ENABLED = 0x400u;
    constexpr ULONG CI_OPTION_HVCI_STRICT       = 0x800u;
    constexpr ULONG64 KUSER_SHARED_DATA_VA      = 0xFFFFF78000000000ULL;

    inline volatile LONG g_hvci_state = -1;

    __forceinline BOOLEAN detect_hvci() {
        __try {
            volatile ULONG* ci_options = reinterpret_cast<volatile ULONG*>(
                KUSER_SHARED_DATA_VA + 0x03A8);

            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<ULONG*>(ci_options))))
                return FALSE;

            ULONG options = *ci_options;

            if (options & CI_OPTION_HVCI_KMCI_ENABLED)
                return TRUE;
            if (options & CI_OPTION_HVCI_STRICT)
                return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {


            return TRUE;
        }
        return FALSE;
    }

    __forceinline BOOLEAN is_hvci_enabled() {
        LONG state = _InterlockedCompareExchange(&g_hvci_state, -1, -1);
        if (state >= 0)
            return (state != 0);

        BOOLEAN enabled = detect_hvci();
        _InterlockedExchange(&g_hvci_state, enabled ? 1 : 0);
        return enabled;
    }
}
