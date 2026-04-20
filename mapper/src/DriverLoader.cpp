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
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", buf); fflush(g_LogFile); }
}
#define DLLOG(fmt, ...) DLDbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)
#define DLLOG_STATUS(msg, st) DLDbgLog(__FUNCTION__, "%s: 0x%08X (%s)", msg, (DWORD)(st), NT_SUCCESS(st) ? "SUCCESS" : "FAILED")

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

        DWORD typeValue = 1;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Type", REG_DWORD, &typeValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (Type)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        DLLOG("Service created successfully");
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
