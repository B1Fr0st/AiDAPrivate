#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <cstdint>

#include <imports/Strings.h>

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


extern "C" std::uintptr_t get_nt_base();

#include <Windows.h>
#include <cstdint>
extern "C" std::uintptr_t get_nt_base() {
    return (std::uintptr_t)GetModuleHandleA("ntoskrnl.exe");
}

inline VOID               (NTAPI* _RtlInitUnicodeString)           (PUNICODE_STRING, PCWSTR);
inline NTSTATUS           (NTAPI* _IoCreateDriver)                 (PUNICODE_STRING, PDRIVER_INITIALIZE);
inline NTSTATUS           (NTAPI* _IoCreateDevice)                 (PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*);
inline NTSTATUS           (NTAPI* _IoCreateSymbolicLink)           (PUNICODE_STRING, PUNICODE_STRING);
inline PIO_STACK_LOCATION (__drv_aliasesMem NTAPI* _IoGetCurrentIrpStackLocation)   (PIRP);
inline VOID               (NTAPI* _IofCompleteRequest)             (PIRP, CCHAR);
inline NTSTATUS           (NTAPI* _MmCopyVirtualMemory)            (PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);
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

inline bool SetupFunctions() {
    PVOID kernelBase = (PVOID)get_nt_base();

    if (!kernelBase) {
        return false;
    }

    *(PVOID*)&_RtlInitUnicodeString = GetProcAddress(kernelBase, (PCHAR)"RtlInitUnicodeString");
    *(PVOID*)&_IoCreateDriver = GetProcAddress(kernelBase, (PCHAR)"IoCreateDriver");
    *(PVOID*)&_IoCreateDevice = GetProcAddress(kernelBase, (PCHAR)"IoCreateDevice");
    *(PVOID*)&_IoCreateSymbolicLink = GetProcAddress(kernelBase, (PCHAR)"IoCreateSymbolicLink");
    *(PVOID*)&_IoGetCurrentIrpStackLocation = GetProcAddress(kernelBase, (PCHAR)"IoGetCurrentIrpStackLocation");
    *(PVOID*)&_IofCompleteRequest = GetProcAddress(kernelBase, (PCHAR)"IofCompleteRequest");
    *(PVOID*)&_MmCopyVirtualMemory = GetProcAddress(kernelBase, (PCHAR)"MmCopyVirtualMemory");
    *(PVOID*)&_MmCopyMemory = GetProcAddress(kernelBase, (PCHAR)"MmCopyMemory");
    *(PVOID*)&_MmMapIoSpaceEx = GetProcAddress(kernelBase, (PCHAR)"MmMapIoSpaceEx");
    *(PVOID*)&_MmUnmapIoSpace = GetProcAddress(kernelBase, (PCHAR)"MmUnmapIoSpace");
    *(PVOID*)&_PsLookupProcessByProcessId = GetProcAddress(kernelBase, (PCHAR)"PsLookupProcessByProcessId");
    *(PVOID*)&_PsGetProcessSectionBaseAddress = GetProcAddress(kernelBase, (PCHAR)"PsGetProcessSectionBaseAddress");
    *(PVOID*)&_ObfDereferenceObject = GetProcAddress(kernelBase, (PCHAR)"ObfDereferenceObject");
    *(PVOID*)&_ObReferenceObjectByName = GetProcAddress(kernelBase, (PCHAR)"ObReferenceObjectByName");
    *(PVOID*)&_MmGetPhysicalMemoryRanges = GetProcAddress(kernelBase, (PCHAR)"MmGetPhysicalMemoryRanges");
    *(PVOID*)&_MmGetVirtualForPhysical = GetProcAddress(kernelBase, (PCHAR)"MmGetVirtualForPhysical");
    *(PVOID*)&_RtlGetVersion = GetProcAddress(kernelBase, (PCHAR)"RtlGetVersion");
    *(PVOID*)&_KfRaiseIrql = GetProcAddress(kernelBase, (PCHAR)"KfRaiseIrql");
    *(PVOID*)&_KeLowerIrql = GetProcAddress(kernelBase, (PCHAR)"KeLowerIrql");
    *(PVOID*)&_MmIsAddressValid = GetProcAddress(kernelBase, (PCHAR)"MmIsAddressValid");
    *(PVOID*)&_ZwOpenProcess = GetProcAddress(kernelBase, (PCHAR)"ZwOpenProcess");
    *(PVOID*)&_ZwClose = GetProcAddress(kernelBase, (PCHAR)"ZwClose");

    if (!_RtlInitUnicodeString || !_IoCreateDriver || !_IoCreateDevice ||
        !_IoCreateSymbolicLink || !_IofCompleteRequest || !_MmCopyMemory ||
        !_PsLookupProcessByProcessId || !_PsGetProcessSectionBaseAddress ||
        !_ObfDereferenceObject || !_MmGetPhysicalMemoryRanges ||
        !_MmGetVirtualForPhysical || !_MmIsAddressValid ||
        !_ZwOpenProcess || !_ZwClose) {
        return false;
    }

    return true;
}
