#pragma once

#include "shell_preview_platform.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>

inline int fopen_s(FILE** stream, const char* path, const char* mode) {
    if (!stream) return 22;
    *stream = std::fopen(path, mode);
    return *stream ? 0 : 1;
}

inline int localtime_s(std::tm* destination, const std::time_t* source) {
    if (!destination || !source) return 22;
    const std::tm* value = std::localtime(source);
    if (!value) return 1;
    *destination = *value;
    return 0;
}

inline int gmtime_s(std::tm* destination, const std::time_t* source) {
    if (!destination || !source) return 22;
    const std::tm* value = std::gmtime(source);
    if (!value) return 1;
    *destination = *value;
    return 0;
}

inline std::time_t _mkgmtime(std::tm* value) {
#if defined(__EMSCRIPTEN__) || defined(__GNUC__)
    return timegm(value);
#else
    return std::mktime(value);
#endif
}

inline ULONGLONG GetTickCount64() {
    return static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline DWORD GetCurrentThreadId() {
    return 1;
}

inline void Sleep(DWORD milliseconds) {
    if (milliseconds > 0) std::this_thread::yield();
}

inline DWORD GetTempPathA(DWORD capacity, char* destination) {
    const char* value = "/aida-preview/exports/";
    const std::size_t required = std::strlen(value);
    if (!destination || capacity <= required) return static_cast<DWORD>(required + 1);
    std::memcpy(destination, value, required + 1);
    return static_cast<DWORD>(required);
}

inline int inet_pton(int, const char* source, void* destination) {
    if (!source || !destination) return 0;
    unsigned int a = 0;
    unsigned int b = 0;
    unsigned int c = 0;
    unsigned int d = 0;
    if (std::sscanf(source, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    auto* bytes = static_cast<std::uint8_t*>(destination);
    bytes[0] = static_cast<std::uint8_t>(a);
    bytes[1] = static_cast<std::uint8_t>(b);
    bytes[2] = static_cast<std::uint8_t>(c);
    bytes[3] = static_cast<std::uint8_t>(d);
    return 1;
}

inline const char* inet_ntop(int, const void* source, char* destination, std::size_t capacity) {
    if (!source || !destination || capacity == 0) return nullptr;
    const auto* bytes = static_cast<const std::uint8_t*>(source);
    std::snprintf(destination, capacity,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return destination;
}

inline constexpr int AF_INET = 2;
inline constexpr int AF_INET6 = 23;
inline constexpr std::size_t INET6_ADDRSTRLEN = 46;
