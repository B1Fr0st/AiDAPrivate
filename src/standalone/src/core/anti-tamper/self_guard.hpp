#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>
#include <intrin.h>
#include <nmmintrin.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "webhook.hpp"
#include "state.hpp"
#include "enforcement.hpp"
#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "syscall.hpp"
#include "../../helpers/diag_log.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

namespace self_guard {

constexpr uint32_t SELF_GUARD_BUGCHECK_CODE   = 0xA1DA0001u;
constexpr uint32_t REASON_SELF_ANALYSIS_ATTEMPT = 0xAE40u;
constexpr uint32_t kSevenDaysSeconds          = 604800u;
constexpr uint32_t kMaxParentPidHops          = 8u;

constexpr const char* kAidaBinaryNames[] = {
    "aidastandalone",
    "aida_core",
    "aida.dll",
    "aidaguestagent",
    "aida_camoufoxreversemcp",
    "camoufox-reverse-mcp",
};

constexpr const char* kAidaSectionNames[] = {
    ".packed",
    ".dseal",
    ".dthunk",
    ".rdiag",
};

constexpr const char* kAllowlistedChildProcesses[] = {
    "camoufox.exe",
    "aidatesttarget.exe",
    "aida_camoufoxreversemcp.exe",
    "conda.exe",
    "python.exe",
    "node.exe",
};

constexpr uint32_t kPackedMagic = 0x41504B44u;
constexpr uint32_t kAuxMagic    = 0x4D585541u;
constexpr uint32_t kAuxVersion  = 0x00030000u;

constexpr uint64_t kCacheTtlPidNs   = 5ULL  * 1000ULL * 1000ULL * 1000ULL;
constexpr uint64_t kCacheTtlFileNs  = 60ULL * 1000ULL * 1000ULL * 1000ULL;
constexpr size_t   kCacheMaxEntries = 256;

constexpr uint32_t BL_MATCH_HASH      = 0x1u;
constexpr uint32_t BL_MATCH_WATERMARK = 0x2u;
constexpr uint32_t BL_MATCH_NAME      = 0x4u;
constexpr uint32_t BL_MATCH_ALL       = BL_MATCH_HASH | BL_MATCH_WATERMARK | BL_MATCH_NAME;

#pragma pack(push, 1)
struct sg_packed_header_t {
    uint32_t magic;
    uint32_t version;
    uint32_t section_count;
    uint32_t import_count;
    uint32_t string_fixup_count;
    uint32_t resource_fixup_count;
    uint32_t section_table_offset;
    uint32_t import_table_offset;
    uint32_t string_table_offset;
    uint32_t resource_table_offset;
    uint32_t master_key_offset;
    uint32_t stub_code_offset;
    uint32_t master_key_pe_timestamp;
    uint32_t master_key_pe_size_of_code;
    uint32_t bind_flags;
    uint32_t aux_offset;
    uint32_t aux_size;
    uint8_t  bind_salt[16];
    uint32_t reserved[3];
};
static_assert(sizeof(sg_packed_header_t) == 96, "sg_packed_header_t must be 96 bytes");

struct sg_aux_block_t {
    uint32_t magic;
    uint32_t version;
    uint32_t spread_seed;
    uint32_t tamper_response_level;
    uint32_t bind_flags;
    uint32_t reserved0;
    uint8_t  watermark[16];
    uint8_t  watermark_hash[32];
    uint8_t  fingerprint_hash[32];
    uint8_t  bind_salt[16];
    uint32_t phase_flags;
    uint32_t stolen_block_count;
};
static_assert(offsetof(sg_aux_block_t, watermark) == 24, "watermark must be at offset 24");
static_assert(offsetof(sg_aux_block_t, watermark_hash) == 40, "watermark_hash must be at offset 40");
#pragma pack(pop)

enum class self_guard_result_t : uint32_t {
    allow               = 0,
    bsod_self_pid       = 1,
    bsod_self_address   = 2,
    bsod_self_binary    = 3,
    bsod_self_watermark = 4,
    bsod_blocklist      = 5,
    bsod_ida_plugin     = 6,
};

struct self_guard_context_t {
    std::string     tool_name;
    uint32_t        target_pid = 0;
    uint64_t        target_address = 0;
    std::string     target_binary_path;
    std::string     target_binary_id;
    bool            has_pid = false;
    bool            has_address = false;
    bool            has_binary_path = false;
};

struct self_identity_t {
    uint32_t    self_pid = 0;
    uint64_t    self_module_base = 0;
    uint64_t    self_module_size = 0;
    uint64_t    self_text_base = 0;
    uint32_t    self_text_size = 0;
    uint64_t    self_text_hash = 0;
    uint8_t     self_watermark[16] = {};
    uint8_t     self_image_hash[32] = {};
    std::vector<std::pair<uint64_t, uint64_t>> self_module_ranges;
    bool        initialized = false;
};

struct aida_blocklist_entry_t {
    uint8_t  image_hash[32] = {};
    uint8_t  watermark[16] = {};
    char     name_pattern[64] = {};
    uint32_t rotation_epoch = 0;
    uint32_t expires_at = 0;
    uint32_t flags = 0;
};

struct check_cache_entry_t {
    std::string         cache_key;
    self_guard_result_t result = self_guard_result_t::allow;
    uint64_t            timestamp_ns = 0;
    uint32_t            hit_count = 0;
};

using self_guard_fn_t = self_guard_result_t(*)(const self_guard_context_t&);
using vm_protect_fn_t = bool(*)(void*, size_t);

inline self_identity_t& identity() {
    static self_identity_t s_identity;
    return s_identity;
}

inline std::shared_mutex& blocklist_mutex() {
    static std::shared_mutex s_mtx;
    return s_mtx;
}

inline std::vector<aida_blocklist_entry_t>& blocklist() {
    static std::vector<aida_blocklist_entry_t> s_blocklist;
    return s_blocklist;
}

inline std::shared_mutex& cache_mutex() {
    static std::shared_mutex s_mtx;
    return s_mtx;
}

inline std::unordered_map<std::string, check_cache_entry_t>& check_cache() {
    static std::unordered_map<std::string, check_cache_entry_t> s_cache;
    return s_cache;
}

inline std::atomic<uintptr_t> g_self_guard_fn_scrambled{0};
inline std::atomic<uintptr_t> g_check_pid_fn_scrambled{0};
inline std::atomic<uintptr_t> g_check_addr_fn_scrambled{0};
inline std::atomic<uintptr_t> g_check_binary_fn_scrambled{0};
inline std::atomic<uintptr_t> g_check_blocklist_fn_scrambled{0};

inline std::atomic<vm_protect_fn_t> g_vm_protect_fn{nullptr};

inline std::atomic<uint64_t> g_self_guard_crc32c_expected{0};
inline std::atomic<uint64_t> g_self_guard_code_base{0};
inline std::atomic<uint64_t> g_self_guard_code_size{0};

inline uint64_t now_ns() {
    LARGE_INTEGER freq{}, ctr{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&ctr);
    if (freq.QuadPart == 0) return 0;
    return static_cast<uint64_t>(
        (static_cast<double>(ctr.QuadPart) / static_cast<double>(freq.QuadPart)) * 1e9);
}

inline uint32_t unix_time_now() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return static_cast<uint32_t>((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

inline std::string to_lower_str(const std::string& input) {
    std::string out = input;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

inline std::string basename_of(const std::string& path) {
    size_t sep = path.find_last_of("\\/");
    if (sep == std::string::npos) return path;
    return path.substr(sep + 1);
}

inline std::string normalize_path(const std::string& path) {
    std::string lower = to_lower_str(path);
    std::replace(lower.begin(), lower.end(), '/', '\\');
    return lower;
}

inline bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

inline bool is_aida_binary_name(const std::string& process_or_module_name) {
    std::string lower = to_lower_str(basename_of(process_or_module_name));
    for (const char* pattern : kAidaBinaryNames) {
        std::string pat(pattern);
        if (lower.find(pat) != std::string::npos)
            return true;
    }
    return false;
}

inline bool is_allowlisted_child(const std::string& process_name) {
    std::string lower = to_lower_str(basename_of(process_name));
    for (const char* allowed : kAllowlistedChildProcesses) {
        if (lower == allowed)
            return true;
    }
    return false;
}

inline uint64_t get_process_create_time(uint32_t pid) {
    if (pid == 0) return 0;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;
    FILETIME creation{}, exit_time{}, kernel{}, user{};
    BOOL ok = GetProcessTimes(hProc, &creation, &exit_time, &kernel, &user);
    CloseHandle(hProc);
    if (!ok) return 0;
    return (static_cast<uint64_t>(creation.dwHighDateTime) << 32) |
           static_cast<uint64_t>(creation.dwLowDateTime);
}

inline std::string process_name_from_pid(uint32_t pid) {
    if (pid == 0) return {};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return {};
    wchar_t buf[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    std::string result;
    if (QueryFullProcessImageNameW(hProc, 0, buf, &sz) && sz > 0) {
        std::wstring wpath(buf, sz);
        size_t sep = wpath.find_last_of(L"\\/");
        std::wstring wname = (sep == std::wstring::npos) ? wpath : wpath.substr(sep + 1);
        int len = WideCharToMultiByte(CP_UTF8, 0, wname.c_str(),
            static_cast<int>(wname.size()), nullptr, 0, nullptr, nullptr);
        if (len > 0) {
            result.resize(static_cast<size_t>(len));
            WideCharToMultiByte(CP_UTF8, 0, wname.c_str(),
                static_cast<int>(wname.size()), result.data(), len, nullptr, nullptr);
        }
    }
    CloseHandle(hProc);
    return result;
}

inline std::string process_image_path_from_pid(uint32_t pid) {
    if (pid == 0) return {};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return {};
    wchar_t buf[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    std::string result;
    if (QueryFullProcessImageNameW(hProc, 0, buf, &sz) && sz > 0) {
        std::wstring wpath(buf, sz);
        int len = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(),
            static_cast<int>(wpath.size()), nullptr, 0, nullptr, nullptr);
        if (len > 0) {
            result.resize(static_cast<size_t>(len));
            WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(),
                static_cast<int>(wpath.size()), result.data(), len, nullptr, nullptr);
        }
    }
    CloseHandle(hProc);
    return result;
}

inline bool compute_sha256_file(const std::string& file_path, uint8_t out_hash[32]) {
    memset(out_hash, 0, 32);
    HANDLE hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != 0) { CloseHandle(hFile); return false; }
    DWORD obj_len = 0, cb = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    if (status != 0 || obj_len == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return false;
    }
    std::vector<UCHAR> hash_obj(obj_len);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, hash_obj.data(), obj_len, nullptr, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return false;
    }
    constexpr DWORD kBufSize = 65536;
    std::vector<uint8_t> buf(kBufSize);
    DWORD bytesRead = 0;
    bool ok = true;
    while (ReadFile(hFile, buf.data(), kBufSize, &bytesRead, nullptr) && bytesRead > 0) {
        status = BCryptHashData(hHash, buf.data(), bytesRead, 0);
        if (status != 0) { ok = false; break; }
    }
    if (ok) {
        status = BCryptFinishHash(hHash, out_hash, 32, 0);
        if (status != 0) ok = false;
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return ok;
}

inline bool compute_sha256_bytes(const uint8_t* data, size_t len, uint8_t out_hash[32]) {
    memset(out_hash, 0, 32);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != 0) return false;
    DWORD obj_len = 0, cb = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    if (status != 0 || obj_len == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    std::vector<UCHAR> hash_obj(obj_len);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, hash_obj.data(), obj_len, nullptr, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    status = BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
    if (status == 0)
        status = BCryptFinishHash(hHash, out_hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == 0;
}

inline bool read_pe_section_table_from_file(HANDLE hFile,
    std::vector<IMAGE_SECTION_HEADER>& sections) {
    sections.clear();
    DWORD read = 0;
    IMAGE_DOS_HEADER dos{};
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    if (!ReadFile(hFile, &dos, sizeof(dos), &read, nullptr) || read != sizeof(dos))
        return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN);
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadFile(hFile, &nt, sizeof(nt), &read, nullptr) || read != sizeof(nt))
        return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    DWORD num = nt.FileHeader.NumberOfSections;
    if (num == 0 || num > 96) return false;
    DWORD table_off = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt.FileHeader.SizeOfOptionalHeader;
    sections.resize(num);
    SetFilePointer(hFile, table_off, nullptr, FILE_BEGIN);
    if (!ReadFile(hFile, sections.data(),
        static_cast<DWORD>(num * sizeof(IMAGE_SECTION_HEADER)), &read, nullptr))
        return false;
    return read == num * sizeof(IMAGE_SECTION_HEADER);
}

inline bool pe_has_aida_watermark(const std::string& file_path) {
    if (file_path.empty()) return false;
    HANDLE hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    std::vector<IMAGE_SECTION_HEADER> sections;
    if (!read_pe_section_table_from_file(hFile, sections)) {
        CloseHandle(hFile);
        return false;
    }
    auto& sid = identity();
    DWORD read = 0;
    for (const auto& sec : sections) {
        if (sec.SizeOfRawData < sizeof(sg_packed_header_t) + sizeof(sg_aux_block_t))
            continue;
        constexpr DWORD kMaxScan = 0x20000u;
        DWORD scan_size = sec.SizeOfRawData;
        if (scan_size > kMaxScan) scan_size = kMaxScan;
        DWORD read_size = scan_size;
        std::vector<uint8_t> sec_data(read_size);
        SetFilePointer(hFile, sec.PointerToRawData, nullptr, FILE_BEGIN);
        if (!ReadFile(hFile, sec_data.data(), read_size, &read, nullptr) || read != read_size)
            continue;
        for (DWORD off = 0; off + sizeof(sg_packed_header_t) + sizeof(sg_aux_block_t) <= read_size; off += 8) {
            uint32_t magic = 0;
            memcpy(&magic, sec_data.data() + off, sizeof(magic));
            if (magic != kPackedMagic) continue;
            sg_packed_header_t hdr{};
            if (off + sizeof(hdr) > read_size) break;
            memcpy(&hdr, sec_data.data() + off, sizeof(hdr));
            if (hdr.aux_offset == 0 || hdr.aux_size < sizeof(sg_aux_block_t))
                continue;
            uint64_t aux_pos = static_cast<uint64_t>(off) + hdr.aux_offset;
            if (aux_pos + sizeof(sg_aux_block_t) > read_size)
                continue;
            sg_aux_block_t aux{};
            memcpy(&aux, sec_data.data() + aux_pos, sizeof(aux));
            if (aux.magic != kAuxMagic) continue;
            if (sid.initialized) {
                if (constant_time_compare(aux.watermark, sid.self_watermark, 16)) {
                    CloseHandle(hFile);
                    return true;
                }
                bool all_zero_self = true;
                bool all_zero_aux = true;
                for (int i = 0; i < 16; ++i) {
                    if (sid.self_watermark[i] != 0) all_zero_self = false;
                    if (aux.watermark[i] != 0) all_zero_aux = false;
                }
                if (all_zero_self && all_zero_aux) {
                    CloseHandle(hFile);
                    return true;
                }
                CloseHandle(hFile);
                return false;
            }
            CloseHandle(hFile);
            return true;
        }
    }
    CloseHandle(hFile);
    return false;
}

inline bool pe_has_aida_sections(const std::string& file_path) {
    if (file_path.empty()) return false;
    HANDLE hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    std::vector<IMAGE_SECTION_HEADER> sections;
    if (!read_pe_section_table_from_file(hFile, sections)) {
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);
    uint32_t match_count = 0;
    for (const auto& sec : sections) {
        char name[9] = {};
        memcpy(name, sec.Name, 8);
        std::string sec_name(name);
        for (const char* aida_sec : kAidaSectionNames) {
            if (sec_name == aida_sec) {
                ++match_count;
                break;
            }
        }
    }
    return match_count >= 2;
}

inline bool pe_extract_watermark_from_memory(const uint8_t* module_base,
    uint64_t module_size, uint8_t out_watermark[16]) {
    if (!module_base || module_size < sizeof(IMAGE_DOS_HEADER)) return false;
    __try {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        if (static_cast<uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > module_size)
            return false;
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            uint64_t sec_va = sec[i].VirtualAddress;
            uint32_t sec_size = sec[i].Misc.VirtualSize;
            if (sec_va >= module_size) continue;
            uint32_t max_mapped = static_cast<uint32_t>(module_size - sec_va);
            if (sec_size == 0 || sec_size > max_mapped) sec_size = max_mapped;
            uint32_t scan_size = sec_size < 0x20000u ? sec_size : 0x20000u;
            if (scan_size < sizeof(sg_packed_header_t) + sizeof(sg_aux_block_t)) continue;
            const uint8_t* sbase = module_base + sec_va;
            for (uint32_t off = 0; off + sizeof(sg_packed_header_t) + sizeof(sg_aux_block_t) <= scan_size; off += 8) {
                uint32_t magic = 0;
                memcpy(&magic, sbase + off, sizeof(magic));
                if (magic != kPackedMagic) continue;
                sg_packed_header_t hdr{};
                if (off + sizeof(hdr) > scan_size) break;
                memcpy(&hdr, sbase + off, sizeof(hdr));
                if (hdr.aux_offset == 0 || hdr.aux_size < sizeof(sg_aux_block_t)) continue;
                uint64_t aux_pos = static_cast<uint64_t>(off) + hdr.aux_offset;
                if (aux_pos + sizeof(sg_aux_block_t) > scan_size) continue;
                sg_aux_block_t aux{};
                memcpy(&aux, sbase + aux_pos, sizeof(aux));
                if (aux.magic != kAuxMagic) continue;
                memcpy(out_watermark, aux.watermark, 16);
                return true;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
}

inline bool is_self_or_child_pid(uint32_t pid) {
    auto& sid = identity();
    if (pid == sid.self_pid) return true;
    uint32_t current = pid;
    for (uint32_t depth = 0; depth < kMaxParentPidHops && current != 0; ++depth) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, current);
        if (!hProc) break;
        struct pbi_t {
            LONG      ExitStatus;
            PVOID     PebBaseAddress;
            ULONG_PTR AffinityMask;
            LONG      BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;
        };
        pbi_t info{};
        ULONG ret_len = 0;
        NTSTATUS status = anti_tamper::syscall::call_NtQueryInformationProcess(
            hProc, 0, &info, sizeof(info), &ret_len);
        CloseHandle(hProc);
        if (status < 0) break;
        uint32_t parent_pid = static_cast<uint32_t>(info.InheritedFromUniqueProcessId);
        if (parent_pid == 0) break;
        if (parent_pid == sid.self_pid) return true;
        current = parent_pid;
    }
    return false;
}

inline bool is_address_in_self_module(uint64_t address, uint32_t target_pid) {
    auto& sid = identity();
    if (target_pid != sid.self_pid) return false;
    if (address >= sid.self_module_base &&
        address < sid.self_module_base + sid.self_module_size)
        return true;
    for (const auto& range : sid.self_module_ranges) {
        if (address >= range.first && address < range.first + range.second)
            return true;
    }
    return false;
}

inline bool is_module_aida(const driver_bridge::module_info_t& mod) {
    if (!mod.path.empty()) {
        if (pe_has_aida_watermark(mod.path))
            return true;
    }
    if (is_aida_binary_name(mod.name))
        return true;
    if (mod.base != 0 && mod.size > 0) {
        std::vector<uint8_t> header_buf(4096);
        if (driver_bridge::read_memory(mod.base, 4096, header_buf)) {
            uint8_t wm[16] = {};
            if (pe_extract_watermark_from_memory(header_buf.data(), 4096, wm)) {
                auto& sid = identity();
                if (sid.initialized && constant_time_compare(wm, sid.self_watermark, 16))
                    return true;
                bool self_zero = true, target_zero = true;
                for (int i = 0; i < 16; ++i) {
                    if (sid.self_watermark[i] != 0) self_zero = false;
                    if (wm[i] != 0) target_zero = false;
                }
                if (sid.initialized && self_zero && target_zero)
                    return true;
                if (!sid.initialized)
                    return true;
            }
        }
    }
    return false;
}

inline bool resolve_address_to_module(uint64_t address,
    driver_bridge::module_info_t& out) {
    auto modules = driver_bridge::enumerate_modules();
    for (const auto& mod : modules) {
        if (address >= mod.base && address < mod.base + mod.size) {
            out = mod;
            return true;
        }
    }
    return false;
}

inline bool blocklist_entry_matches(const aida_blocklist_entry_t& entry,
    const std::string& name, const uint8_t* image_hash,
    const uint8_t* watermark, uint32_t now) {
    if ((entry.flags & BL_MATCH_ALL) == 0 || (entry.flags & ~BL_MATCH_ALL) != 0)
        return false;

    if (entry.expires_at != 0) {
        const uint64_t valid_until = static_cast<uint64_t>(entry.expires_at)
            + static_cast<uint64_t>(kSevenDaysSeconds);
        if (static_cast<uint64_t>(now) > valid_until)
            return false;
    }

    bool hash_matched = false;
    bool watermark_matched = false;
    bool name_matched = false;

    if ((entry.flags & BL_MATCH_HASH) != 0 && image_hash != nullptr)
        hash_matched = constant_time_compare(image_hash, entry.image_hash, 32);

    if ((entry.flags & BL_MATCH_WATERMARK) != 0 && watermark != nullptr)
        watermark_matched = constant_time_compare(watermark, entry.watermark, 16);

    if ((entry.flags & BL_MATCH_NAME) != 0 && !name.empty()) {
        const size_t pattern_length = strnlen_s(entry.name_pattern,
            sizeof(entry.name_pattern));
        if (pattern_length != 0 && pattern_length < sizeof(entry.name_pattern)) {
            const std::string lower_name = to_lower_str(name);
            const std::string lower_pattern = to_lower_str(
                std::string(entry.name_pattern, pattern_length));
            name_matched = lower_name.find(lower_pattern) != std::string::npos;
        }
    }

    return hash_matched || watermark_matched || name_matched;
}

inline bool blocklist_matches(const std::string& name,
    const uint8_t* image_hash, const uint8_t* watermark) {
    std::shared_lock<std::shared_mutex> lk(blocklist_mutex());
    const uint32_t now = unix_time_now();
    for (const auto& entry : blocklist()) {
        if (blocklist_entry_matches(entry, name, image_hash, watermark, now))
            return true;
    }
    return false;
}

inline bool validate_blocklist_entry(const aida_blocklist_entry_t& entry) {
    bool has_nonzero_hash = false;
    for (int i = 0; i < 32; ++i) {
        if (entry.image_hash[i] != 0) { has_nonzero_hash = true; break; }
    }
    bool has_nonzero_wm = false;
    for (int i = 0; i < 16; ++i) {
        if (entry.watermark[i] != 0) { has_nonzero_wm = true; break; }
    }
    bool has_name = false;
    for (int i = 0; i < 64; ++i) {
        if (entry.name_pattern[i] != 0) { has_name = true; break; }
    }
    if (!has_nonzero_hash && !has_nonzero_wm && !has_name) return false;
    if (entry.flags == 0 || (entry.flags & ~BL_MATCH_ALL) != 0) return false;
    if (entry.flags & BL_MATCH_HASH) {
        if (!has_nonzero_hash) return false;
    }
    if (entry.flags & BL_MATCH_WATERMARK) {
        if (!has_nonzero_wm) return false;
    }
    if (entry.flags & BL_MATCH_NAME) {
        if (!has_name || strnlen_s(entry.name_pattern,
                sizeof(entry.name_pattern)) == sizeof(entry.name_pattern))
            return false;
    }
    return true;
}

inline void update_blocklist(const std::vector<aida_blocklist_entry_t>& entries) {
    std::vector<aida_blocklist_entry_t> validated;
    validated.reserve(entries.size());
    for (const auto& entry : entries) {
        if (validate_blocklist_entry(entry))
            validated.push_back(entry);
    }
    if (validated.empty() && !entries.empty()) {
        webhook::write_log("self_guard", "blocklist_update_all_invalid_retaining_previous");
        return;
    }
    std::unique_lock<std::shared_mutex> lk(blocklist_mutex());
    blocklist() = std::move(validated);
    webhook::write_log_critical_fmt("self_guard",
        "blocklist_updated entries=%zu epoch=%u",
        blocklist().size(),
        entries.empty() ? 0u : entries.front().rotation_epoch);
}

inline bool binary_image_hash_matches_self(const std::string& file_path) {
    if (file_path.empty()) return false;
    auto& sid = identity();
    if (!sid.initialized) return false;
    uint8_t hash[32] = {};
    if (!compute_sha256_file(file_path, hash)) return false;
    return constant_time_compare(hash, sid.self_image_hash, 32);
}

inline bool cache_get(const std::string& key, self_guard_result_t& out_result) {
    std::shared_lock<std::shared_mutex> lk(cache_mutex());
    auto it = check_cache().find(key);
    if (it == check_cache().end()) return false;
    uint64_t now = now_ns();
    uint64_t age = now - it->second.timestamp_ns;
    bool is_file = (key.rfind("path:", 0) == 0);
    uint64_t ttl = is_file ? kCacheTtlFileNs : kCacheTtlPidNs;
    if (age > ttl) {
        lk.unlock();
        std::unique_lock<std::shared_mutex> wlk(cache_mutex());
        check_cache().erase(key);
        return false;
    }
    if (key.rfind("pid:", 0) == 0) {
        size_t first_colon = key.find(':', 4);
        if (first_colon != std::string::npos) {
            uint32_t cached_pid = static_cast<uint32_t>(
                std::strtoul(key.c_str() + 4, nullptr, 10));
            if (cached_pid != 0) {
                uint64_t current_ct = get_process_create_time(cached_pid);
                size_t second_colon = key.find(':', first_colon + 1);
                if (second_colon != std::string::npos) {
                    uint64_t cached_ct = std::strtoull(
                        key.c_str() + second_colon + 1, nullptr, 10);
                    if (current_ct != 0 && cached_ct != 0 && current_ct != cached_ct) {
                        wlk.unlock();
                        lk.unlock();
                        std::unique_lock<std::shared_mutex> wlk2(cache_mutex());
                        check_cache().erase(key);
                        return false;
                    }
                }
            }
        }
    }
    out_result = it->second.result;
    it->second.hit_count++;
    return true;
}

inline void cache_evict_oldest() {
    if (check_cache().size() <= kCacheMaxEntries) return;
    auto& cache = check_cache();
    uint64_t oldest_ts = UINT64_MAX;
    std::string oldest_key;
    for (const auto& p : cache) {
        if (p.second.timestamp_ns < oldest_ts) {
            oldest_ts = p.second.timestamp_ns;
            oldest_key = p.first;
        }
    }
    if (!oldest_key.empty())
        cache.erase(oldest_key);
}

inline void cache_put(const std::string& key, self_guard_result_t result) {
    if (result != self_guard_result_t::allow) return;
    std::unique_lock<std::shared_mutex> lk(cache_mutex());
    if (check_cache().size() >= kCacheMaxEntries)
        cache_evict_oldest();
    check_cache_entry_t entry;
    entry.cache_key = key;
    entry.result = result;
    entry.timestamp_ns = now_ns();
    entry.hit_count = 0;
    check_cache()[key] = std::move(entry);
}

inline uint64_t resolve_rolling_key_self_guard(uint32_t rva) {
    uint64_t k0 = 0, k1 = 0;
    anti_tamper::integrity::get_session_keys(k0, k1);
    uint8_t ikm[24];
    memcpy(ikm, &k0, 8);
    memcpy(ikm + 8, &k1, 8);
    uint64_t rva_u64 = static_cast<uint64_t>(rva);
    memcpy(ikm + 16, &rva_u64, 8);
    uint8_t prk[32];
    anti_tamper::virtualizer::detail::hmac_sha256(
        anti_tamper::state::g_vm_master_key, 32, ikm, 24, prk);
    static const uint8_t info[16] = {
        'a','i','d','a','_','s','e','l','f','g','u','a','r','d','_','k'
    };
    uint8_t okm[16];
    anti_tamper::virtualizer::detail::hkdf_expand_sha256(prk, info, 16, okm, 16);
    uint64_t out_lo = 0, out_hi = 0;
    memcpy(&out_lo, okm, 8);
    memcpy(&out_hi, okm + 8, 8);
    SecureZeroMemory(prk, 32);
    SecureZeroMemory(okm, 16);
    SecureZeroMemory(ikm, 24);
    return out_lo ^ _rotl64(out_hi, 23);
}

inline uintptr_t scramble_pointer(uintptr_t raw, uint32_t rva) {
    if (raw == 0) return 0;
    uint64_t key = resolve_rolling_key_self_guard(rva);
    return raw ^ key;
}

inline uintptr_t descramble_pointer(uintptr_t scrambled, uint32_t rva) {
    if (scrambled == 0) return 0;
    uint64_t key = resolve_rolling_key_self_guard(rva);
    return scrambled ^ key;
}

__declspec(noinline) self_guard_result_t check_pid_self_impl(const self_guard_context_t& ctx) {
    auto& sid = identity();
    if (ctx.target_pid == sid.self_pid)
        return self_guard_result_t::bsod_self_pid;

    uint64_t ct = get_process_create_time(ctx.target_pid);
    std::string cache_key = "pid:" + std::to_string(ctx.target_pid) + ":" + std::to_string(ct);
    self_guard_result_t cached = self_guard_result_t::allow;
    if (cache_get(cache_key, cached))
        return cached;

    bool in_chain = is_self_or_child_pid(ctx.target_pid);
    std::string proc_name = process_name_from_pid(ctx.target_pid);
    std::string image_path = process_image_path_from_pid(ctx.target_pid);

    if (in_chain) {
        if (!image_path.empty()) {
            if (pe_has_aida_watermark(image_path)) {
                return self_guard_result_t::bsod_self_watermark;
            }
            uint8_t hash[32] = {};
            if (compute_sha256_file(image_path, hash)) {
                if (constant_time_compare(hash, sid.self_image_hash, 32))
                    return self_guard_result_t::bsod_self_binary;
                if (blocklist_matches(proc_name, hash, nullptr))
                    return self_guard_result_t::bsod_blocklist;
            }
        }
        if (is_allowlisted_child(proc_name)) {
            cache_put(cache_key, self_guard_result_t::allow);
            return self_guard_result_t::allow;
        }
        if (is_aida_binary_name(proc_name)) {
            if (!image_path.empty() && pe_has_aida_watermark(image_path))
                return self_guard_result_t::bsod_self_watermark;
            uint8_t hash[32] = {};
            if (!image_path.empty() && compute_sha256_file(image_path, hash)) {
                if (constant_time_compare(hash, sid.self_image_hash, 32))
                    return self_guard_result_t::bsod_self_binary;
                if (blocklist_matches(proc_name, hash, nullptr))
                    return self_guard_result_t::bsod_blocklist;
            }
            cache_put(cache_key, self_guard_result_t::allow);
            return self_guard_result_t::allow;
        }
        cache_put(cache_key, self_guard_result_t::allow);
        return self_guard_result_t::allow;
    }

    if (is_aida_binary_name(proc_name)) {
        if (!image_path.empty() && pe_has_aida_watermark(image_path))
            return self_guard_result_t::bsod_self_watermark;
        uint8_t hash[32] = {};
        if (!image_path.empty() && compute_sha256_file(image_path, hash)) {
            if (constant_time_compare(hash, sid.self_image_hash, 32))
                return self_guard_result_t::bsod_self_binary;
            if (blocklist_matches(proc_name, hash, nullptr))
                return self_guard_result_t::bsod_blocklist;
        }
        cache_put(cache_key, self_guard_result_t::allow);
        return self_guard_result_t::allow;
    }

    cache_put(cache_key, self_guard_result_t::allow);
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t check_address_self_impl(const self_guard_context_t& ctx) {
    auto& sid = identity();
    if (!ctx.has_pid || !ctx.has_address)
        return self_guard_result_t::allow;
    if (ctx.target_pid != sid.self_pid)
        return self_guard_result_t::allow;

    uint64_t page = ctx.target_address & ~0xFFFULL;
    std::string cache_key = "addr:" + std::to_string(ctx.target_pid) + ":" + std::to_string(page);
    self_guard_result_t cached = self_guard_result_t::allow;
    if (cache_get(cache_key, cached))
        return cached;

    if (is_address_in_self_module(ctx.target_address, ctx.target_pid))
        return self_guard_result_t::bsod_self_address;

    driver_bridge::module_info_t mod{};
    if (resolve_address_to_module(ctx.target_address, mod)) {
        if (is_module_aida(mod)) {
            uint8_t hash[32] = {};
            if (!mod.path.empty() && compute_sha256_file(mod.path, hash)) {
                if (constant_time_compare(hash, sid.self_image_hash, 32))
                    return self_guard_result_t::bsod_self_binary;
            }
            if (!mod.path.empty() && pe_has_aida_watermark(mod.path))
                return self_guard_result_t::bsod_self_watermark;
        }
    }

    cache_put(cache_key, self_guard_result_t::allow);
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t check_binary_self_impl(const self_guard_context_t& ctx) {
    if (ctx.target_binary_path.empty())
        return self_guard_result_t::allow;
    auto& sid = identity();

    std::string cache_key = "path:" + normalize_path(ctx.target_binary_path);
    self_guard_result_t cached = self_guard_result_t::allow;
    if (cache_get(cache_key, cached))
        return cached;

    bool has_watermark = pe_has_aida_watermark(ctx.target_binary_path);
    bool has_sections = pe_has_aida_sections(ctx.target_binary_path);
    uint8_t hash[32] = {};
    bool hash_computed = compute_sha256_file(ctx.target_binary_path, hash);

    if (has_watermark) {
        if (hash_computed && constant_time_compare(hash, sid.self_image_hash, 32))
            return self_guard_result_t::bsod_self_binary;
        return self_guard_result_t::bsod_self_watermark;
    }

    if (hash_computed) {
        if (constant_time_compare(hash, sid.self_image_hash, 32))
            return self_guard_result_t::bsod_self_binary;
        if (blocklist_matches(basename_of(ctx.target_binary_path), hash, nullptr))
            return self_guard_result_t::bsod_blocklist;
    }

    if (has_sections && hash_computed) {
        if (blocklist_matches(basename_of(ctx.target_binary_path), hash, nullptr))
            return self_guard_result_t::bsod_blocklist;
    }

    cache_put(cache_key, self_guard_result_t::allow);
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t check_blocklist_impl(const self_guard_context_t& ctx) {
    std::string name;
    uint8_t hash[32] = {};
    bool hash_computed = false;
    uint8_t wm[16] = {};
    bool wm_extracted = false;

    if (ctx.has_binary_path && !ctx.target_binary_path.empty()) {
        name = basename_of(ctx.target_binary_path);
        hash_computed = compute_sha256_file(ctx.target_binary_path, hash);
        if (pe_has_aida_watermark(ctx.target_binary_path)) {
            auto& sid = identity();
            memcpy(wm, sid.self_watermark, 16);
            wm_extracted = true;
        }
    } else if (ctx.has_pid) {
        name = process_name_from_pid(ctx.target_pid);
        std::string img_path = process_image_path_from_pid(ctx.target_pid);
        if (!img_path.empty()) {
            hash_computed = compute_sha256_file(img_path, hash);
            if (pe_has_aida_watermark(img_path)) {
                auto& sid = identity();
                memcpy(wm, sid.self_watermark, 16);
                wm_extracted = true;
            }
        }
    } else if (!ctx.target_binary_id.empty()) {
        name = ctx.target_binary_id;
    }

    const uint8_t* hash_ptr = hash_computed ? hash : nullptr;
    const uint8_t* wm_ptr = wm_extracted ? wm : nullptr;

    if (blocklist_matches(name, hash_ptr, wm_ptr))
        return self_guard_result_t::bsod_blocklist;

    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t decoy_guard_1(const self_guard_context_t& ctx) {
    volatile uint32_t noise = 0;
    noise ^= static_cast<uint32_t>(__rdtsc());
    noise ^= ctx.target_pid;
    noise ^= static_cast<uint32_t>(ctx.target_address);
    (void)noise;
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t decoy_guard_2(const self_guard_context_t& ctx) {
    volatile uint64_t noise = 0;
    noise ^= __rdtsc();
    noise ^= ctx.target_address;
    noise ^= static_cast<uint64_t>(ctx.target_pid) << 32;
    (void)noise;
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t decoy_guard_3(const self_guard_context_t& ctx) {
    volatile uint32_t noise = 0x55AA55AAu;
    noise ^= ctx.target_pid ^ static_cast<uint32_t>(ctx.target_address);
    noise ^= static_cast<uint32_t>(__rdtsc());
    (void)noise;
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t decoy_guard_4(const self_guard_context_t& ctx) {
    volatile uint64_t noise = 0xA1DA0001ULL;
    noise ^= static_cast<uint64_t>(ctx.target_pid) | (ctx.target_address << 16);
    noise ^= __rdtsc();
    (void)noise;
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t decoy_guard_5(const self_guard_context_t& ctx) {
    volatile uint32_t noise = 0xDEADBEEFu;
    for (int i = 0; i < 4; ++i) {
        noise ^= static_cast<uint32_t>(ctx.target_address >> (i * 8));
        noise ^= ctx.target_pid;
    }
    (void)noise;
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t decoy_guard_6(const self_guard_context_t& ctx) {
    volatile uint64_t a = __rdtsc();
    volatile uint64_t b = a ^ ctx.target_address ^ ctx.target_pid;
    volatile uint64_t c = b ^ _rotl64(a, 13);
    (void)c;
    return self_guard_result_t::allow;
}

__declspec(noinline) self_guard_result_t self_guard_check_impl(const self_guard_context_t& ctx) {
    using check_fn_t = self_guard_result_t(*)(const self_guard_context_t&);

    if (ctx.has_pid) {
        uintptr_t scrambled = g_check_pid_fn_scrambled.load(std::memory_order_acquire);
        uintptr_t raw = descramble_pointer(scrambled, 0x7A1DA001u);
        auto fn = reinterpret_cast<check_fn_t>(raw);
        if (fn) {
            auto r = fn(ctx);
            if (r != self_guard_result_t::allow) return r;
        } else {
            auto r = check_pid_self_impl(ctx);
            if (r != self_guard_result_t::allow) return r;
        }
    }

    if (ctx.has_address && ctx.has_pid) {
        uintptr_t scrambled = g_check_addr_fn_scrambled.load(std::memory_order_acquire);
        uintptr_t raw = descramble_pointer(scrambled, 0x7A1DA002u);
        auto fn = reinterpret_cast<check_fn_t>(raw);
        if (fn) {
            auto r = fn(ctx);
            if (r != self_guard_result_t::allow) return r;
        } else {
            auto r = check_address_self_impl(ctx);
            if (r != self_guard_result_t::allow) return r;
        }
    }

    if (ctx.has_binary_path) {
        uintptr_t scrambled = g_check_binary_fn_scrambled.load(std::memory_order_acquire);
        uintptr_t raw = descramble_pointer(scrambled, 0x7A1DA003u);
        auto fn = reinterpret_cast<check_fn_t>(raw);
        if (fn) {
            auto r = fn(ctx);
            if (r != self_guard_result_t::allow) return r;
        } else {
            auto r = check_binary_self_impl(ctx);
            if (r != self_guard_result_t::allow) return r;
        }
    }

    {
        uintptr_t scrambled = g_check_blocklist_fn_scrambled.load(std::memory_order_acquire);
        uintptr_t raw = descramble_pointer(scrambled, 0x7A1DA004u);
        auto fn = reinterpret_cast<check_fn_t>(raw);
        if (fn) {
            auto r = fn(ctx);
            if (r != self_guard_result_t::allow) return r;
        } else {
            auto r = check_blocklist_impl(ctx);
            if (r != self_guard_result_t::allow) return r;
        }
    }

    return self_guard_result_t::allow;
}

inline self_guard_fn_t resolve_self_guard_fn() {
    uintptr_t scrambled = g_self_guard_fn_scrambled.load(std::memory_order_acquire);
    if (scrambled == 0) return nullptr;
    uintptr_t raw = descramble_pointer(scrambled, 0x7A1DA000u);
    return reinterpret_cast<self_guard_fn_t>(raw);
}

inline void report_self_analysis_attempt(const self_guard_context_t& ctx,
    self_guard_result_t result) {
    (void)ctx;
    (void)result;
    driver_bridge::latch_targeting_from_usermode(REASON_SELF_ANALYSIS_ATTEMPT);
}

inline void report_self_guard_tamper(const self_guard_context_t& ctx) {
    (void)ctx;
    driver_bridge::latch_targeting_from_usermode(REASON_SELF_ANALYSIS_ATTEMPT);
}

inline void execute_self_guard_bsod(self_guard_result_t result,
    const self_guard_context_t& ctx) {
    report_self_analysis_attempt(ctx, result);
    uint64_t evidence = static_cast<uint64_t>(ctx.target_pid) |
        (ctx.target_address << 32) |
        (static_cast<uint64_t>(result) << 60);
    bool bsod_ok = driver_bridge::trigger_kernel_bsod(SELF_GUARD_BUGCHECK_CODE, evidence);
    if (!bsod_ok) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            auto pRtlReportFatalFailure = reinterpret_cast<void(*)()>(
                GetProcAddress(ntdll, "RtlReportFatalFailure"));
            if (pRtlReportFatalFailure) {
                pRtlReportFatalFailure();
            }
        }
    }
    __fastfail(static_cast<unsigned int>(SELF_GUARD_BUGCHECK_CODE));
    for (;;) { }
}

inline self_guard_result_t invoke_self_guard(const self_guard_context_t& ctx) {
    auto fn = resolve_self_guard_fn();
    if (!fn) {
        if (ctx.has_pid && ctx.target_pid == GetCurrentProcessId()) {
            report_self_guard_tamper(ctx);
            return self_guard_result_t::bsod_self_pid;
        }
        return self_guard_check_impl(ctx);
    }
    return fn(ctx);
}

inline void verify_self_guard_integrity() {
    auto& sid = identity();
    if (!sid.initialized) return;
    auto& rt = anti_tamper::state::get();
    if (rt.code_snap.text_base == 0 || rt.code_snap.text_size == 0) return;

    bool hash_ok = false;
    uint64_t current_hash = anti_tamper::driver_crc_text_hash_seh(
        reinterpret_cast<const void*>(rt.code_snap.text_base),
        rt.code_snap.text_size,
        hash_ok);
    if (!hash_ok || current_hash != rt.code_snap.text_hash) {
        anti_tamper::enforce_violation_id(
            aida::reason_ids::reason_id_from_string("self_guard_integrity_tamper"),
            "self_guard_integrity_tamper");
        return;
    }

    auto verify_fn_ptr = [](std::atomic<uintptr_t>& scrambled, uint32_t rva) -> bool {
        uintptr_t s = scrambled.load(std::memory_order_acquire);
        if (s == 0) return false;
        uintptr_t raw = descramble_pointer(s, rva);
        if (raw == 0) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<void*>(raw), &mbi, sizeof(mbi)) == 0)
            return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            return false;
        return true;
    };

    bool ptr1 = verify_fn_ptr(g_self_guard_fn_scrambled, 0x7A1DA000u);
    bool ptr2 = verify_fn_ptr(g_check_pid_fn_scrambled, 0x7A1DA001u);
    bool ptr3 = verify_fn_ptr(g_check_addr_fn_scrambled, 0x7A1DA002u);
    bool ptr4 = verify_fn_ptr(g_check_binary_fn_scrambled, 0x7A1DA003u);
    bool ptr5 = verify_fn_ptr(g_check_blocklist_fn_scrambled, 0x7A1DA004u);

    if (!ptr1 || !ptr2 || !ptr3 || !ptr4 || !ptr5) {
        anti_tamper::enforce_violation_id(
            aida::reason_ids::reason_id_from_string("self_guard_pointer_tamper"),
            "self_guard_pointer_tamper");
    }
}

inline void populate_self_module_ranges() {
    auto& sid = identity();
    sid.self_module_ranges.clear();
    HMODULE hMods[1024] = {};
    DWORD needed = 0;
    HANDLE hProc = GetCurrentProcess();
    if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &needed, LIST_MODULES_ALL)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count && i < 1024; ++i) {
            wchar_t mod_path[MAX_PATH] = {};
            if (GetModuleFileNameW(hMods[i], mod_path, MAX_PATH) > 0) {
                std::string utf8_path;
                int len = WideCharToMultiByte(CP_UTF8, 0, mod_path, -1,
                    nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    utf8_path.resize(static_cast<size_t>(len));
                    WideCharToMultiByte(CP_UTF8, 0, mod_path, -1,
                        utf8_path.data(), len, nullptr, nullptr);
                    if (!utf8_path.empty() && utf8_path.back() == '\0')
                        utf8_path.pop_back();
                }
                std::string base = basename_of(utf8_path);
                if (is_aida_binary_name(base)) {
                    MODULEINFO mod_info{};
                    if (GetModuleInformation(hProc, hMods[i], &mod_info, sizeof(mod_info))) {
                        sid.self_module_ranges.emplace_back(
                            reinterpret_cast<uint64_t>(mod_info.lpBaseOfDll),
                            static_cast<uint64_t>(mod_info.SizeOfImage));
                    }
                }
            }
        }
    }
}

inline void read_own_watermark() {
    auto& sid = identity();
    HMODULE hSelf = GetModuleHandleW(nullptr);
    if (!hSelf) return;
    auto* base = reinterpret_cast<const uint8_t*>(hSelf);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    uint64_t image_size = nt->OptionalHeader.SizeOfImage;
    uint8_t wm[16] = {};
    if (pe_extract_watermark_from_memory(base, image_size, wm)) {
        memcpy(sid.self_watermark, wm, 16);
    } else {
        wchar_t self_path[MAX_PATH] = {};
        DWORD path_len = GetModuleFileNameW(nullptr, self_path, MAX_PATH);
        if (path_len > 0 && path_len < MAX_PATH) {
            std::string utf8_path;
            int u8len = WideCharToMultiByte(CP_UTF8, 0, self_path, path_len,
                nullptr, 0, nullptr, nullptr);
            if (u8len > 0) {
                utf8_path.resize(static_cast<size_t>(u8len));
                WideCharToMultiByte(CP_UTF8, 0, self_path, path_len,
                    utf8_path.data(), u8len, nullptr, nullptr);
            }
            if (!utf8_path.empty()) {
                HANDLE hFile = CreateFileA(utf8_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hFile != INVALID_HANDLE_VALUE) {
                    std::vector<IMAGE_SECTION_HEADER> sections;
                    if (read_pe_section_table_from_file(hFile, sections)) {
                        DWORD read = 0;
                        for (const auto& sec : sections) {
                            if (sec.SizeOfRawData < sizeof(sg_packed_header_t) + sizeof(sg_aux_block_t))
                                continue;
                            constexpr DWORD kMaxScan = 0x20000u;
                            DWORD scan_size = sec.SizeOfRawData;
                            if (scan_size > kMaxScan) scan_size = kMaxScan;
                            std::vector<uint8_t> sec_data(scan_size);
                            SetFilePointer(hFile, sec.PointerToRawData, nullptr, FILE_BEGIN);
                            if (!ReadFile(hFile, sec_data.data(), scan_size, &read, nullptr) || read != scan_size)
                                continue;
                            for (DWORD off = 0; off + sizeof(sg_packed_header_t) + sizeof(sg_aux_block_t) <= scan_size; off += 8) {
                                uint32_t magic = 0;
                                memcpy(&magic, sec_data.data() + off, sizeof(magic));
                                if (magic != kPackedMagic) continue;
                                sg_packed_header_t hdr{};
                                if (off + sizeof(hdr) > scan_size) break;
                                memcpy(&hdr, sec_data.data() + off, sizeof(hdr));
                                if (hdr.aux_offset == 0 || hdr.aux_size < sizeof(sg_aux_block_t)) continue;
                                uint64_t aux_pos = static_cast<uint64_t>(off) + hdr.aux_offset;
                                if (aux_pos + sizeof(sg_aux_block_t) > scan_size) continue;
                                sg_aux_block_t aux{};
                                memcpy(&aux, sec_data.data() + aux_pos, sizeof(aux));
                                if (aux.magic == kAuxMagic) {
                                    memcpy(sid.self_watermark, aux.watermark, 16);
                                    CloseHandle(hFile);
                                    return;
                                }
                            }
                        }
                    }
                    CloseHandle(hFile);
                }
            }
        }
    }
}

inline void seed_builtin_blocklist() {
    auto& sid = identity();
    std::vector<aida_blocklist_entry_t> builtin;

    aida_blocklist_entry_t self_entry{};
    memcpy(self_entry.image_hash, sid.self_image_hash, 32);
    memcpy(self_entry.watermark, sid.self_watermark, 16);
    strncpy(self_entry.name_pattern, "aidastandalone", sizeof(self_entry.name_pattern) - 1);
    self_entry.rotation_epoch = 1;
    self_entry.expires_at = 0;
    self_entry.flags = BL_MATCH_HASH | BL_MATCH_WATERMARK | BL_MATCH_NAME;
    builtin.push_back(self_entry);

    for (const char* name : kAidaBinaryNames) {
        aida_blocklist_entry_t entry{};
        strncpy(entry.name_pattern, name, sizeof(entry.name_pattern) - 1);
        memcpy(entry.watermark, sid.self_watermark, 16);
        entry.rotation_epoch = 1;
        entry.expires_at = 0;
        entry.flags = BL_MATCH_NAME | BL_MATCH_WATERMARK;
        builtin.push_back(entry);
    }

    std::unique_lock<std::shared_mutex> lk(blocklist_mutex());
    blocklist() = std::move(builtin);
}

inline void vm_protect_self_guard_functions() {
    auto fn = g_vm_protect_fn.load(std::memory_order_acquire);
    if (!fn) return;
    fn(reinterpret_cast<void*>(&check_pid_self_impl), 4096);
    fn(reinterpret_cast<void*>(&check_address_self_impl), 4096);
    fn(reinterpret_cast<void*>(&check_binary_self_impl), 4096);
    fn(reinterpret_cast<void*>(&check_blocklist_impl), 4096);
    fn(reinterpret_cast<void*>(&self_guard_check_impl), 4096);
}

inline bool initialize() {
    webhook::write_log("init", "self_guard_initialize_ENTRY");
    auto& sid = identity();
    if (sid.initialized) {
        webhook::write_log("init", "self_guard_already_initialized");
        return true;
    }

    sid.self_pid = GetCurrentProcessId();
    HMODULE hSelf = GetModuleHandleW(nullptr);
    sid.self_module_base = reinterpret_cast<uint64_t>(hSelf);
    if (hSelf) {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hSelf);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                reinterpret_cast<uint8_t*>(hSelf) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE &&
                nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                sid.self_module_size = nt->OptionalHeader.SizeOfImage;
            }
        }
    }

    auto& rt = anti_tamper::state::get();
    sid.self_text_base = rt.code_snap.text_base;
    sid.self_text_size = rt.code_snap.text_size;
    sid.self_text_hash = rt.code_snap.text_hash;

    wchar_t self_path[MAX_PATH] = {};
    DWORD path_len = GetModuleFileNameW(nullptr, self_path, MAX_PATH);
    if (path_len > 0 && path_len < MAX_PATH) {
        std::string utf8_path;
        int u8len = WideCharToMultiByte(CP_UTF8, 0, self_path, path_len,
            nullptr, 0, nullptr, nullptr);
        if (u8len > 0) {
            utf8_path.resize(static_cast<size_t>(u8len));
            WideCharToMultiByte(CP_UTF8, 0, self_path, path_len,
                utf8_path.data(), u8len, nullptr, nullptr);
        }
        if (!utf8_path.empty()) {
            compute_sha256_file(utf8_path, sid.self_image_hash);
        }
    }

    read_own_watermark();
    populate_self_module_ranges();

    g_self_guard_fn_scrambled.store(
        scramble_pointer(reinterpret_cast<uintptr_t>(&self_guard_check_impl), 0x7A1DA000u),
        std::memory_order_release);
    g_check_pid_fn_scrambled.store(
        scramble_pointer(reinterpret_cast<uintptr_t>(&check_pid_self_impl), 0x7A1DA001u),
        std::memory_order_release);
    g_check_addr_fn_scrambled.store(
        scramble_pointer(reinterpret_cast<uintptr_t>(&check_address_self_impl), 0x7A1DA002u),
        std::memory_order_release);
    g_check_binary_fn_scrambled.store(
        scramble_pointer(reinterpret_cast<uintptr_t>(&check_binary_self_impl), 0x7A1DA003u),
        std::memory_order_release);
    g_check_blocklist_fn_scrambled.store(
        scramble_pointer(reinterpret_cast<uintptr_t>(&check_blocklist_impl), 0x7A1DA004u),
        std::memory_order_release);

    seed_builtin_blocklist();
    vm_protect_self_guard_functions();

    g_self_guard_code_base.store(reinterpret_cast<uint64_t>(&self_guard_check_impl),
        std::memory_order_release);
    g_self_guard_code_size.store(4096, std::memory_order_release);

    sid.initialized = true;
    webhook::write_log_critical_fmt("init",
        "self_guard_initialize_OK pid=%lu module_base=0x%llX module_size=0x%llX "
        "text_base=0x%llX text_size=0x%X text_hash=0x%016llX module_ranges=%zu "
        "watermark_set=%d image_hash_set=%d",
        static_cast<unsigned long>(sid.self_pid),
        static_cast<unsigned long long>(sid.self_module_base),
        static_cast<unsigned long long>(sid.self_module_size),
        static_cast<unsigned long long>(sid.self_text_base),
        sid.self_text_size,
        static_cast<unsigned long long>(sid.self_text_hash),
        sid.self_module_ranges.size(),
        [&sid]() -> int {
            for (int i = 0; i < 16; ++i)
                if (sid.self_watermark[i] != 0) return 1;
            return 0;
        }(),
        [&sid]() -> int {
            for (int i = 0; i < 32; ++i)
                if (sid.self_image_hash[i] != 0) return 1;
            return 0;
        }());
    return true;
}

} // namespace self_guard
