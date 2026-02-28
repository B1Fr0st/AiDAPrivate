#pragma once
#include <ntifs.h>
#include <ntimage.h>
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

// Safe implementation of get_nt_base using ZwQuerySystemInformation
// This replaces the unsafe assembly version that caused PAGE_FAULT_IN_NONPAGED_AREA (0x50)
// when memory pages become invalid due to driver loading order or memory pressure.
//
// The assembly version (ntoskernel_base.asm) performs raw memory reads without MmIsAddressValid
// checks, causing crashes when another driver (like the spoofer) modifies kernel memory layout.
inline std::uintptr_t get_nt_base() {
    ULONG requiredSize = 0;
    
    // First call to get required buffer size
    NTSTATUS status = ZwQuerySystemInformation(
        SystemModuleInformationInternal,
        nullptr,
        0,
        &requiredSize
    );
    
    if (requiredSize == 0) {
        return 0;
    }
    
    // Add extra space for safety
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
    
    // ntoskrnl.exe is always the first module in the list
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
        !_IoDeleteDevice) {
        return false;
    }

    return true;
}