#include "Mapper.h"

namespace DriverLoader {

    NTSTATUS CreateDriverService(PWSTR servicePath, PCWSTR filePath) {
        const WCHAR prefix[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        SIZE_T prefixLen = wcslen(prefix);
        
        wmemcpy(servicePath, prefix, prefixLen);
        
        PCWSTR filePtr = filePath;
        PCWSTR lastSlash = filePath;
        
        while (*filePtr) {
            if (*filePtr == L'\\') {
                lastSlash = filePtr + 1;
            }
            filePtr++;
        }
        
        SIZE_T pathLen = prefixLen;
        PCWSTR namePtr = lastSlash;
        while (*namePtr && *namePtr != L'.' && pathLen < 126) {
            servicePath[pathLen] = *namePtr;
            pathLen++;
            namePtr++;
        }
        servicePath[pathLen] = L'\0';
        
        NTSTATUS status = RtlCreateRegistryKeyPtr(0, servicePath);

        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        WCHAR ntPath[512] = {0};
        wcscpy_s(ntPath, L"\\??\\");
        wcscat_s(ntPath, _countof(ntPath), filePath);
        
        SIZE_T ntPathLen = wcslen(ntPath);
        
        status = RtlWriteRegistryValuePtr(0, servicePath, L"ImagePath", REG_SZ, ntPath, 
            static_cast<ULONG>((ntPathLen + 1) * sizeof(WCHAR)));

        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        DWORD typeValue = 1;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Type", REG_DWORD, &typeValue, sizeof(DWORD));

        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        return STATUS_SUCCESS;
    }

    NTSTATUS LoadDriver(PCWSTR servicePath) {
        UNICODE_STRING usServicePath;
        RtlInitUnicodeString(&usServicePath, servicePath);
        
        NTSTATUS status = NtLoadDriverPtr(&usServicePath);
        
        return status;
    }

    NTSTATUS UnloadDriver(PCWSTR servicePath) {
        UNICODE_STRING usServicePath;
        RtlInitUnicodeString(&usServicePath, servicePath);
        
        NTSTATUS status = NtUnloadDriverPtr(&usServicePath);
        
        return status;
    }

}
        