#include "Mapper.h"
#include <cstdarg>

// Forward declare from MapperCore.cpp
extern FILE* g_LogFile;
static void DLDbgLog(const char* func, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int prefixLen = snprintf(buf, sizeof(buf), "[DriverLoader][%s] ", func);
    if (prefixLen < 0) prefixLen = 0;
    vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);
    printf("%s\n", buf);
    fflush(stdout);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", buf); FlushMapperLogFile(); }
}
#define DLLOG(fmt, ...) DLDbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)
#define DLLOG_STATUS(msg, st) DLDbgLog(__FUNCTION__, "%s: 0x%08X (%s)", msg, (DWORD)(st), NT_SUCCESS(st) ? "SUCCESS" : "FAILED")

static NTSTATUS WriteKernelLogPathValue(PCWSTR servicePath) {
    WCHAR kernelLogPath[512] = {};
    DWORD len = GetEnvironmentVariableW(L"AIDA_KERNEL_LOG_PATH", kernelLogPath, _countof(kernelLogPath));
    if (len == 0) {
        wcscpy_s(kernelLogPath, L"\\??\\C:\\Users\\Public\\Desktop\\aida_kernel.log");
        len = static_cast<DWORD>(wcslen(kernelLogPath));
        DLLOG("AIDA_KERNEL_LOG_PATH not set, using default");
    }
    if (len >= _countof(kernelLogPath)) {
        DLLOG("AIDA_KERNEL_LOG_PATH too long len=%lu", static_cast<unsigned long>(len));
        return static_cast<NTSTATUS>(0xC0000023L);
    }
    NTSTATUS status = RtlWriteRegistryValuePtr(0, servicePath, L"AidaKernelLogPath", REG_SZ, kernelLogPath,
        static_cast<ULONG>((wcslen(kernelLogPath) + 1) * sizeof(WCHAR)));
    DLLOG("AidaKernelLogPath: %ls", kernelLogPath);
    DLLOG_STATUS("RtlWriteRegistryValue (AidaKernelLogPath)", status);
    return status;
}

namespace DriverLoader {

    NTSTATUS CreateDriverService(PWSTR servicePath, PCWSTR filePath) {
        DLLOG("Creating service for: %ls", filePath);
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
        DLLOG("Service path: %ls", servicePath);
        DLLOG_STATUS("RtlCreateRegistryKey", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        WCHAR ntPath[512] = {0};
        wcscpy_s(ntPath, L"\\??\\");
        wcscat_s(ntPath, _countof(ntPath), filePath);

        SIZE_T ntPathLen = wcslen(ntPath);

        status = RtlWriteRegistryValuePtr(0, servicePath, L"ImagePath", REG_SZ, ntPath,
            static_cast<ULONG>((ntPathLen + 1) * sizeof(WCHAR)));
        DLLOG("ImagePath: %ls", ntPath);
        DLLOG_STATUS("RtlWriteRegistryValue (ImagePath)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteKernelLogPathValue(servicePath);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        DWORD typeValue = 1;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Type", REG_DWORD, &typeValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (Type)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        DWORD startValue = 3;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Start", REG_DWORD, &startValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (Start)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        DWORD errorControlValue = 1;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"ErrorControl", REG_DWORD, &errorControlValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (ErrorControl)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        DLLOG("Service created successfully");
        return STATUS_SUCCESS;
    }

    NTSTATUS CreateMinifilterService(PWSTR servicePath, PCWSTR filePath,
                                     PCWSTR instanceName, PCWSTR altitude) {
        DLLOG("Creating minifilter service for: %ls (altitude=%ls)", filePath, altitude);
        const WCHAR prefix[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        SIZE_T prefixLen = wcslen(prefix);

        wmemcpy(servicePath, prefix, prefixLen);

        PCWSTR filePtr = filePath;
        PCWSTR lastSlash = filePath;
        while (*filePtr) {
            if (*filePtr == L'\\') lastSlash = filePtr + 1;
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
        DLLOG("Service path: %ls", servicePath);
        DLLOG_STATUS("RtlCreateRegistryKey (service)", status);
        if (!NT_SUCCESS(status)) return status;

        WCHAR ntPath[512] = {0};
        wcscpy_s(ntPath, L"\\??\\");
        wcscat_s(ntPath, _countof(ntPath), filePath);
        SIZE_T ntPathLen = wcslen(ntPath);

        status = RtlWriteRegistryValuePtr(0, servicePath, L"ImagePath", REG_SZ, ntPath,
            static_cast<ULONG>((ntPathLen + 1) * sizeof(WCHAR)));
        DLLOG_STATUS("RtlWriteRegistryValue (ImagePath)", status);
        if (!NT_SUCCESS(status)) return status;

        status = WriteKernelLogPathValue(servicePath);
        if (!NT_SUCCESS(status)) return status;

        DWORD typeValue = 2;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Type", REG_DWORD,
            &typeValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (Type=2 FILE_SYSTEM_DRIVER)", status);
        if (!NT_SUCCESS(status)) return status;

        DWORD startValue = 3;
        RtlWriteRegistryValuePtr(0, servicePath, L"Start", REG_DWORD,
            &startValue, sizeof(DWORD));

        DWORD errorControlValue = 1;
        RtlWriteRegistryValuePtr(0, servicePath, L"ErrorControl", REG_DWORD,
            &errorControlValue, sizeof(DWORD));

        static const WCHAR groupName[] = L"FSFilter Activity Monitor";
        RtlWriteRegistryValuePtr(0, servicePath, L"Group", REG_SZ,
            const_cast<PWSTR>(groupName),
            static_cast<ULONG>((wcslen(groupName) + 1) * sizeof(WCHAR)));

        static const WCHAR dependOn[] = L"FltMgr\0";
        RtlWriteRegistryValuePtr(0, servicePath, L"DependOnService", REG_MULTI_SZ,
            const_cast<PWSTR>(dependOn),
            static_cast<ULONG>((_countof(dependOn) + 1) * sizeof(WCHAR)));

        WCHAR instancesPath[256] = {0};
        wcscpy_s(instancesPath, servicePath);
        wcscat_s(instancesPath, L"\\Instances");

        status = RtlCreateRegistryKeyPtr(0, instancesPath);
        DLLOG_STATUS("RtlCreateRegistryKey (Instances)", status);
        if (!NT_SUCCESS(status)) return status;

        RtlWriteRegistryValuePtr(0, instancesPath, L"DefaultInstance", REG_SZ,
            const_cast<PWSTR>(instanceName),
            static_cast<ULONG>((wcslen(instanceName) + 1) * sizeof(WCHAR)));

        WCHAR instanceKey[320] = {0};
        wcscpy_s(instanceKey, instancesPath);
        wcscat_s(instanceKey, L"\\");
        wcscat_s(instanceKey, _countof(instanceKey), instanceName);

        status = RtlCreateRegistryKeyPtr(0, instanceKey);
        DLLOG_STATUS("RtlCreateRegistryKey (Instance)", status);
        if (!NT_SUCCESS(status)) return status;

        RtlWriteRegistryValuePtr(0, instanceKey, L"Altitude", REG_SZ,
            const_cast<PWSTR>(altitude),
            static_cast<ULONG>((wcslen(altitude) + 1) * sizeof(WCHAR)));

        DWORD instanceFlags = 0;
        RtlWriteRegistryValuePtr(0, instanceKey, L"Flags", REG_DWORD,
            &instanceFlags, sizeof(DWORD));

        DLLOG("Minifilter service created successfully");
        return STATUS_SUCCESS;
    }

    NTSTATUS LoadDriver(PCWSTR servicePath) {
        DLLOG("Loading driver: %ls", servicePath);
        UNICODE_STRING usServicePath;
        RtlInitUnicodeString(&usServicePath, servicePath);

        NTSTATUS status = NtLoadDriverPtr(&usServicePath);
        DLLOG_STATUS("NtLoadDriver", status);
        if (!NT_SUCCESS(status)) {
            DLLOG("NtLoadDriver FAILED for '%ls', NTSTATUS=0x%08X", servicePath, (DWORD)status);
        }

        return status;
    }

    NTSTATUS UnloadDriver(PCWSTR servicePath) {
        DLLOG("Unloading driver: %ls", servicePath);
        UNICODE_STRING usServicePath;
        RtlInitUnicodeString(&usServicePath, servicePath);

        NTSTATUS status = NtUnloadDriverPtr(&usServicePath);
        DLLOG_STATUS("NtUnloadDriver", status);

        return status;
    }

}
