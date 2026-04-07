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


inline VOID               (NTAPI* _KeBugCheckEx)                    (ULONG, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);


inline ULONG_PTR          (NTAPI* _KeIpiGenericCall)                (PKIPI_BROADCAST_WORKER, ULONG_PTR);


inline NTSTATUS           (NTAPI* _PsCreateSystemThread)            (PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID);
inline NTSTATUS           (NTAPI* _KeDelayExecutionThread)          (KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER);
inline NTSTATUS           (NTAPI* _PsTerminateSystemThread)         (NTSTATUS);


inline VOID               (NTAPI* _ObfDereferenceObject)            (PVOID);
inline NTSTATUS           (NTAPI* _ObReferenceObjectByName)         (PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*);
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


inline NTSTATUS           (NTAPI* _ZwOpenKey)                       (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwQueryValueKey)                 (HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
inline NTSTATUS           (NTAPI* _ZwDeleteFile)                    (POBJECT_ATTRIBUTES);
inline NTSTATUS           (NTAPI* _ZwSetInformationFile)            (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
inline NTSTATUS           (NTAPI* _IoCreateFileEx)                  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG, CREATE_FILE_TYPE, PVOID, ULONG, PIO_DRIVER_CREATE_CONTEXT);


inline NTSTATUS           (NTAPI* _PsSetCreateProcessNotifyRoutine) (PCREATE_PROCESS_NOTIFY_ROUTINE, BOOLEAN);


inline POBJECT_TYPE*       _IoDriverObjectType_ptr = nullptr;


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


    *(PVOID*)&_KeBugCheckEx                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeBugCheckEx"));


    *(PVOID*)&_KeIpiGenericCall             = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeIpiGenericCall"));


    *(PVOID*)&_PsCreateSystemThread         = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsCreateSystemThread"));
    *(PVOID*)&_KeDelayExecutionThread       = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeDelayExecutionThread"));
    *(PVOID*)&_PsTerminateSystemThread      = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsTerminateSystemThread"));


    *(PVOID*)&_ObfDereferenceObject         = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObfDereferenceObject"));
    *(PVOID*)&_ObReferenceObjectByName      = GetProcAddress(kernelBase, (PCHAR)skCrypt("ObReferenceObjectByName"));
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


    *(PVOID*)&_ZwOpenKey                       = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwOpenKey"));
    *(PVOID*)&_ZwQueryValueKey                 = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwQueryValueKey"));
    *(PVOID*)&_ZwDeleteFile                    = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwDeleteFile"));
    *(PVOID*)&_ZwSetInformationFile            = GetProcAddress(kernelBase, (PCHAR)skCrypt("ZwSetInformationFile"));
    *(PVOID*)&_IoCreateFileEx                  = GetProcAddress(kernelBase, (PCHAR)skCrypt("IoCreateFileEx"));


    *(PVOID*)&_PsSetCreateProcessNotifyRoutine = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsSetCreateProcessNotifyRoutine"));


    _IoDriverObjectType_ptr = (POBJECT_TYPE*)GetProcAddress(kernelBase, (PCHAR)skCrypt("IoDriverObjectType"));


    if (!_MmIsAddressValid || !_MmCopyMemory ||
        !_IoAllocateMdl || !_IoFreeMdl || !_MmBuildMdlForNonPagedPool ||
        !_MmMapLockedPagesSpecifyCache || !_MmUnmapLockedPages ||
        !_KeInitializeDpc || !_KeInitializeTimerEx || !_KeSetTimerEx ||
        !_KeCancelTimer || !_KeBugCheckEx || !_KeIpiGenericCall ||
        !_PsCreateSystemThread || !_KeDelayExecutionThread || !_PsTerminateSystemThread ||
        !_ObfDereferenceObject || !_ZwClose ||
        !_RtlInitUnicodeString || !_RtlGetVersion ||
        !_ExAcquireResourceExclusiveLite || !_ExReleaseResourceLite) {
        return false;
    }

    return true;
}
