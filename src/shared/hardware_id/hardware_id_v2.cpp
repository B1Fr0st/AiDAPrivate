#include "hardware_id_v2.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <wincrypt.h>
#include <winioctl.h>
#include <intrin.h>
#include <tbs.h>

#include <chrono>
#include <cstring>
#include <cstdio>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace aida::hardware_id::v2
{
    namespace
    {
        constexpr std::uint32_t kTpmStNoSessions = 0x8001u;
        constexpr std::uint32_t kTpmCcNvRead     = 0x0000014Eu;
        constexpr std::uint32_t kTpmCcNvReadPublic = 0x00000169u;
        constexpr std::uint32_t kTpmRhNull       = 0x40000007u;
        constexpr std::uint32_t kTpmRhPlatform   = 0x4000000Cu;
        constexpr std::uint32_t kTpmRhOwner      = 0x40000001u;
        constexpr std::uint32_t kTpmRsPw         = 0x40000009u;
        constexpr std::uint32_t kEkNvIndexRsa    = 0x01C00002u;
        constexpr std::uint32_t kEkNvIndexEcc    = 0x01C0000Au;

        bool sha256_compute(const std::uint8_t* data, std::size_t len,
                            std::array<std::uint8_t, 32>& out) noexcept
        {
            HCRYPTPROV prov = 0;
            HCRYPTHASH hash = 0;
            out.fill(0);
            if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES,
                                      CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
                return false;
            }
            bool ok = false;
            if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
                if (CryptHashData(hash,
                                  reinterpret_cast<const BYTE*>(data),
                                  static_cast<DWORD>(len), 0)) {
                    DWORD dlen = 32;
                    BYTE digest[32]{};
                    if (CryptGetHashParam(hash, HP_HASHVAL, digest, &dlen, 0) &&
                        dlen == 32) {
                        std::memcpy(out.data(), digest, 32);
                        ok = true;
                    }
                }
                CryptDestroyHash(hash);
            }
            CryptReleaseContext(prov, 0);
            return ok;
        }

        std::string to_upper_ascii(const std::string& in) noexcept
        {
            std::string out;
            out.reserve(in.size());
            for (char c : in) {
                if (c >= 'a' && c <= 'z') out.push_back(static_cast<char>(c - 32));
                else out.push_back(c);
            }
            return out;
        }

        bool is_whitespace(char c) noexcept
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                   c == '\v' || c == '\f';
        }

        std::string trim_and_collapse(const std::string& in) noexcept
        {
            std::size_t a = 0;
            std::size_t b = in.size();
            while (a < b && is_whitespace(in[a])) ++a;
            while (b > a && is_whitespace(in[b - 1])) --b;
            std::string out;
            out.reserve(b - a);
            bool prev_space = false;
            for (std::size_t i = a; i < b; ++i) {
                if (is_whitespace(in[i])) {
                    if (!prev_space) {
                        out.push_back(' ');
                        prev_space = true;
                    }
                } else {
                    out.push_back(in[i]);
                    prev_space = false;
                }
            }
            return out;
        }

        std::string normalize_string_factor(const std::string& in) noexcept
        {
            return to_upper_ascii(trim_and_collapse(in));
        }

        std::string trim_only(const std::string& in) noexcept
        {
            std::size_t a = 0;
            std::size_t b = in.size();
            while (a < b && is_whitespace(in[a])) ++a;
            while (b > a && is_whitespace(in[b - 1])) --b;
            return in.substr(a, b - a);
        }

        std::string normalize_serial_factor(const std::string& in) noexcept
        {
            return to_upper_ascii(trim_only(in));
        }

        std::string normalize_uuid_lowercase_canonical(const std::uint8_t bytes[16]) noexcept
        {
            std::uint8_t b[16];
            std::memcpy(b, bytes, 16);
            std::uint8_t reordered[16];
            reordered[0] = b[3];
            reordered[1] = b[2];
            reordered[2] = b[1];
            reordered[3] = b[0];
            reordered[4] = b[5];
            reordered[5] = b[4];
            reordered[6] = b[7];
            reordered[7] = b[6];
            for (int i = 8; i < 16; ++i) reordered[i] = b[i];
            char buf[64];
            std::snprintf(buf, sizeof(buf),
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                reordered[0], reordered[1], reordered[2], reordered[3],
                reordered[4], reordered[5], reordered[6], reordered[7],
                reordered[8], reordered[9], reordered[10], reordered[11],
                reordered[12], reordered[13], reordered[14], reordered[15]);
            return std::string(buf);
        }

        std::vector<std::uint8_t> read_smbios_table() noexcept
        {
            std::vector<std::uint8_t> out;
            UINT sz = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
            if (sz == 0) return out;
            out.resize(sz);
            UINT got = GetSystemFirmwareTable('RSMB', 0, out.data(), sz);
            if (got == 0 || got > sz) {
                out.clear();
                return out;
            }
            out.resize(got);
            return out;
        }

        bool parse_smbios(const std::vector<std::uint8_t>& raw,
                          const std::uint8_t** out_table,
                          std::size_t* out_table_len) noexcept
        {
            if (raw.size() < 8) return false;
            *out_table = raw.data() + 8;
            *out_table_len = raw.size() - 8;
            return true;
        }

        const char* smbios_string_at(const std::uint8_t* str_area,
                                     std::size_t str_area_len,
                                     std::uint8_t index) noexcept
        {
            if (index == 0) return nullptr;
            const char* p = reinterpret_cast<const char*>(str_area);
            const char* end = p + str_area_len;
            for (std::uint8_t i = 1; i < index; ++i) {
                while (p < end && *p) ++p;
                if (p < end) ++p;
                if (p >= end) return nullptr;
            }
            if (p < end && *p) return p;
            return nullptr;
        }

        bool find_smbios_structure(const std::uint8_t* tbl, std::size_t tbl_len,
                                   std::uint8_t target_type,
                                   const std::uint8_t** out_fixed,
                                   std::uint8_t* out_fixed_len,
                                   const std::uint8_t** out_strings,
                                   std::size_t* out_strings_len) noexcept
        {
            std::size_t off = 0;
            while (off + 4 < tbl_len) {
                std::uint8_t type = tbl[off];
                std::uint8_t len  = tbl[off + 1];
                if (len < 4) break;
                if (off + len > tbl_len) break;
                std::size_t str_start = off + len;
                std::size_t after = str_start;
                while (after + 1 < tbl_len &&
                       !(tbl[after] == 0 && tbl[after + 1] == 0)) {
                    ++after;
                }
                if (type == target_type) {
                    *out_fixed = tbl + off;
                    *out_fixed_len = len;
                    *out_strings = tbl + str_start;
                    *out_strings_len = (after > str_start) ? (after - str_start) : 0;
                    return true;
                }
                off = after + 2;
                if (off > tbl_len) break;
                if (type == 127) break;
            }
            return false;
        }

        bool collect_smbios_uuid(std::vector<std::uint8_t>& out) noexcept
        {
            auto raw = read_smbios_table();
            const std::uint8_t* tbl = nullptr;
            std::size_t tbl_len = 0;
            if (!parse_smbios(raw, &tbl, &tbl_len)) return false;
            const std::uint8_t* fixed = nullptr;
            std::uint8_t fixed_len = 0;
            const std::uint8_t* strings = nullptr;
            std::size_t strings_len = 0;
            if (!find_smbios_structure(tbl, tbl_len, 1, &fixed, &fixed_len,
                                       &strings, &strings_len)) {
                return false;
            }
            if (fixed_len < 24) return false;
            std::uint8_t uuid[16];
            std::memcpy(uuid, fixed + 8, 16);
            bool all_zero = true;
            bool all_ff = true;
            for (int i = 0; i < 16; ++i) {
                if (uuid[i] != 0x00) all_zero = false;
                if (uuid[i] != 0xFF) all_ff = false;
            }
            if (all_zero || all_ff) return false;
            std::string s = normalize_uuid_lowercase_canonical(uuid);
            out.assign(s.begin(), s.end());
            return !out.empty();
        }

        bool collect_smbios_string_factor(std::uint8_t target_type,
                                          std::uint8_t string_offset_in_fixed,
                                          std::vector<std::uint8_t>& out) noexcept
        {
            auto raw = read_smbios_table();
            const std::uint8_t* tbl = nullptr;
            std::size_t tbl_len = 0;
            if (!parse_smbios(raw, &tbl, &tbl_len)) return false;
            const std::uint8_t* fixed = nullptr;
            std::uint8_t fixed_len = 0;
            const std::uint8_t* strings = nullptr;
            std::size_t strings_len = 0;
            if (!find_smbios_structure(tbl, tbl_len, target_type, &fixed, &fixed_len,
                                       &strings, &strings_len)) {
                return false;
            }
            if (fixed_len <= string_offset_in_fixed) return false;
            std::uint8_t index = fixed[string_offset_in_fixed];
            const char* s = smbios_string_at(strings, strings_len, index);
            if (!s) return false;
            std::string normalized = normalize_serial_factor(std::string(s));
            if (normalized.empty()) return false;
            out.assign(normalized.begin(), normalized.end());
            return true;
        }

        bool collect_disk_serial(std::vector<std::uint8_t>& out) noexcept
        {
            HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            STORAGE_PROPERTY_QUERY q{};
            q.PropertyId = StorageDeviceProperty;
            q.QueryType  = PropertyStandardQuery;
            std::vector<std::uint8_t> buf(2048);
            DWORD returned = 0;
            BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                                      &q, sizeof(q),
                                      buf.data(), static_cast<DWORD>(buf.size()),
                                      &returned, nullptr);
            CloseHandle(h);
            if (!ok || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return false;
            auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf.data());
            if (desc->SerialNumberOffset == 0 ||
                desc->SerialNumberOffset >= returned) return false;
            const char* raw_serial =
                reinterpret_cast<const char*>(buf.data() + desc->SerialNumberOffset);
            std::size_t max_serial =
                (returned > desc->SerialNumberOffset)
                    ? (returned - desc->SerialNumberOffset) : 0;
            std::size_t actual = 0;
            while (actual < max_serial && raw_serial[actual] != 0) ++actual;
            if (actual == 0) return false;
            std::string serial(raw_serial, actual);
            std::string normalized = normalize_serial_factor(serial);
            if (normalized.empty()) return false;
            out.assign(normalized.begin(), normalized.end());
            return true;
        }

        bool collect_cpuid_brand(std::vector<std::uint8_t>& out) noexcept
        {
            int info[4]{};
            __cpuid(info, 0x80000000);
            if (static_cast<unsigned>(info[0]) < 0x80000004u) return false;
            char brand[49]{};
            __cpuid(reinterpret_cast<int*>(brand + 0),  0x80000002);
            __cpuid(reinterpret_cast<int*>(brand + 16), 0x80000003);
            __cpuid(reinterpret_cast<int*>(brand + 32), 0x80000004);
            brand[48] = 0;
            std::string s = normalize_string_factor(std::string(brand));
            if (s.empty()) return false;
            out.assign(s.begin(), s.end());
            return true;
        }

        bool read_reg_string(HKEY root, const wchar_t* subkey, const wchar_t* value,
                             std::string& out_ascii) noexcept
        {
            HKEY h = nullptr;
            LSTATUS rc = RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h);
            if (rc != ERROR_SUCCESS) return false;
            wchar_t buf[256]{};
            DWORD sz = sizeof(buf);
            DWORD type = 0;
            rc = RegQueryValueExW(h, value, nullptr, &type,
                                  reinterpret_cast<LPBYTE>(buf), &sz);
            RegCloseKey(h);
            if (rc != ERROR_SUCCESS) return false;
            if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
            char ascii[512]{};
            int got = WideCharToMultiByte(CP_UTF8, 0, buf, -1, ascii, sizeof(ascii),
                                          nullptr, nullptr);
            if (got <= 0) return false;
            out_ascii.assign(ascii);
            return !out_ascii.empty();
        }

        bool collect_machine_guid(std::vector<std::uint8_t>& out) noexcept
        {
            std::string s;
            if (!read_reg_string(HKEY_LOCAL_MACHINE,
                                 L"SOFTWARE\\Microsoft\\Cryptography",
                                 L"MachineGuid", s)) return false;
            std::string normalized = trim_and_collapse(s);
            if (normalized.empty()) return false;
            std::string lower;
            lower.reserve(normalized.size());
            for (char c : normalized) {
                if (c >= 'A' && c <= 'Z') lower.push_back(static_cast<char>(c + 32));
                else lower.push_back(c);
            }
            out.assign(lower.begin(), lower.end());
            return true;
        }

        bool collect_installation_guid(std::vector<std::uint8_t>& out) noexcept
        {
            std::string s;
            if (!read_reg_string(HKEY_LOCAL_MACHINE,
                                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                 L"InstallationGUID", s) &&
                !read_reg_string(HKEY_LOCAL_MACHINE,
                                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                 L"InstallationID", s)) {
                if (!read_reg_string(HKEY_LOCAL_MACHINE,
                                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                                     L"InstallationID", s)) {
                    return false;
                }
            }
            std::string normalized = trim_and_collapse(s);
            if (normalized.empty()) return false;
            std::string lower;
            lower.reserve(normalized.size());
            for (char c : normalized) {
                if (c >= 'A' && c <= 'Z') lower.push_back(static_cast<char>(c + 32));
                else lower.push_back(c);
            }
            out.assign(lower.begin(), lower.end());
            return true;
        }

        void be_put_u16(std::vector<std::uint8_t>& v, std::uint16_t x) noexcept
        {
            v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
            v.push_back(static_cast<std::uint8_t>(x & 0xFF));
        }
        void be_put_u32(std::vector<std::uint8_t>& v, std::uint32_t x) noexcept
        {
            v.push_back(static_cast<std::uint8_t>((x >> 24) & 0xFF));
            v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xFF));
            v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
            v.push_back(static_cast<std::uint8_t>(x & 0xFF));
        }
        std::uint32_t be_get_u32(const std::uint8_t* p) noexcept
        {
            return (static_cast<std::uint32_t>(p[0]) << 24) |
                   (static_cast<std::uint32_t>(p[1]) << 16) |
                   (static_cast<std::uint32_t>(p[2]) << 8)  |
                   static_cast<std::uint32_t>(p[3]);
        }
        std::uint16_t be_get_u16(const std::uint8_t* p) noexcept
        {
            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                              static_cast<std::uint16_t>(p[1]));
        }

        void tpm_patch_header_size(std::vector<std::uint8_t>& cmd) noexcept
        {
            std::uint32_t total = static_cast<std::uint32_t>(cmd.size());
            cmd[2] = static_cast<std::uint8_t>((total >> 24) & 0xFF);
            cmd[3] = static_cast<std::uint8_t>((total >> 16) & 0xFF);
            cmd[4] = static_cast<std::uint8_t>((total >> 8)  & 0xFF);
            cmd[5] = static_cast<std::uint8_t>(total & 0xFF);
        }

        using tbsi_context_create_fn = TBS_RESULT (WINAPI*)(const TBS_CONTEXT_PARAMS*, PTBS_HCONTEXT);
        using tbsip_submit_command_fn = TBS_RESULT (WINAPI*)(TBS_HCONTEXT, TBS_COMMAND_LOCALITY, TBS_COMMAND_PRIORITY, const BYTE*, UINT32, BYTE*, PUINT32);
        using tbsip_context_close_fn = TBS_RESULT (WINAPI*)(TBS_HCONTEXT);

        struct tbs_api_t
        {
            tbsi_context_create_fn   create  = nullptr;
            tbsip_submit_command_fn  submit  = nullptr;
            tbsip_context_close_fn   close   = nullptr;
            bool                     ready   = false;
        };

        const tbs_api_t& tbs_api() noexcept
        {
            static tbs_api_t api = []() noexcept {
                tbs_api_t a{};
                HMODULE mod = LoadLibraryExW(L"tbs.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (!mod) return a;
                a.create = reinterpret_cast<tbsi_context_create_fn>(
                    reinterpret_cast<void*>(GetProcAddress(mod, "Tbsi_Context_Create")));
                a.submit = reinterpret_cast<tbsip_submit_command_fn>(
                    reinterpret_cast<void*>(GetProcAddress(mod, "Tbsip_Submit_Command")));
                a.close  = reinterpret_cast<tbsip_context_close_fn>(
                    reinterpret_cast<void*>(GetProcAddress(mod, "Tbsip_Context_Close")));
                a.ready = (a.create && a.submit && a.close);
                return a;
            }();
            return api;
        }

        bool tbs_submit(const std::vector<std::uint8_t>& cmd,
                        std::vector<std::uint8_t>& reply) noexcept
        {
            const tbs_api_t& api = tbs_api();
            if (!api.ready) return false;
            TBS_CONTEXT_PARAMS2 params{};
            params.version = TBS_CONTEXT_VERSION_TWO;
            params.includeTpm20 = 1;
            TBS_HCONTEXT ctx = nullptr;
            TBS_RESULT rc = api.create(
                reinterpret_cast<const TBS_CONTEXT_PARAMS*>(&params), &ctx);
            if (rc != TBS_SUCCESS || ctx == nullptr) return false;
            reply.assign(4096, 0);
            UINT32 reply_len = static_cast<UINT32>(reply.size());
            rc = api.submit(ctx,
                            TBS_COMMAND_LOCALITY_ZERO,
                            TBS_COMMAND_PRIORITY_NORMAL,
                            cmd.data(),
                            static_cast<UINT32>(cmd.size()),
                            reply.data(), &reply_len);
            api.close(ctx);
            if (rc != TBS_SUCCESS) return false;
            if (reply_len < 10) return false;
            reply.resize(reply_len);
            return true;
        }

        bool tpm_nv_readpublic_size(std::uint32_t nv_index,
                                    std::uint16_t& out_data_size,
                                    std::uint16_t& out_alg_hash) noexcept
        {
            std::vector<std::uint8_t> cmd;
            be_put_u16(cmd, static_cast<std::uint16_t>(kTpmStNoSessions));
            be_put_u32(cmd, 0);
            be_put_u32(cmd, kTpmCcNvReadPublic);
            be_put_u32(cmd, nv_index);
            tpm_patch_header_size(cmd);
            std::vector<std::uint8_t> reply;
            if (!tbs_submit(cmd, reply)) return false;
            if (reply.size() < 10) return false;
            std::uint32_t rc = be_get_u32(reply.data() + 6);
            if (rc != 0) return false;
            std::size_t off = 10;
            if (off + 2 > reply.size()) return false;
            off += 2;
            if (off + 2 > reply.size()) return false;
            off += 2;
            if (off + 4 > reply.size()) return false;
            off += 4;
            if (off + 2 > reply.size()) return false;
            std::uint16_t alg = be_get_u16(reply.data() + off);
            off += 2;
            if (off + 2 > reply.size()) return false;
            off += 2;
            if (off + 2 > reply.size()) return false;
            std::uint16_t auth_pol_size = be_get_u16(reply.data() + off);
            off += 2 + auth_pol_size;
            if (off + 2 > reply.size()) return false;
            std::uint16_t data_size = be_get_u16(reply.data() + off);
            out_alg_hash = alg;
            out_data_size = data_size;
            return true;
        }

        bool tpm_nv_read_chunk(std::uint32_t nv_index, std::uint16_t size,
                               std::uint16_t offset, std::vector<std::uint8_t>& out) noexcept
        {
            std::vector<std::uint8_t> cmd;
            be_put_u16(cmd, static_cast<std::uint16_t>(0x8002));
            be_put_u32(cmd, 0);
            be_put_u32(cmd, kTpmCcNvRead);
            be_put_u32(cmd, nv_index);
            be_put_u32(cmd, nv_index);
            std::vector<std::uint8_t> session;
            be_put_u32(session, kTpmRsPw);
            be_put_u16(session, 0);
            session.push_back(0);
            be_put_u16(session, 0);
            be_put_u32(cmd, static_cast<std::uint32_t>(session.size()));
            cmd.insert(cmd.end(), session.begin(), session.end());
            be_put_u16(cmd, size);
            be_put_u16(cmd, offset);
            tpm_patch_header_size(cmd);
            std::vector<std::uint8_t> reply;
            if (!tbs_submit(cmd, reply)) return false;
            if (reply.size() < 10) return false;
            std::uint32_t rc = be_get_u32(reply.data() + 6);
            if (rc != 0) return false;
            std::size_t off = 10;
            if (off + 4 > reply.size()) return false;
            off += 4;
            if (off + 2 > reply.size()) return false;
            std::uint16_t data_size = be_get_u16(reply.data() + off);
            off += 2;
            if (off + data_size > reply.size()) return false;
            out.assign(reply.begin() + off, reply.begin() + off + data_size);
            return true;
        }

        bool tpm_nv_read_full(std::uint32_t nv_index,
                              std::vector<std::uint8_t>& out) noexcept
        {
            std::uint16_t total = 0;
            std::uint16_t alg = 0;
            if (!tpm_nv_readpublic_size(nv_index, total, alg)) return false;
            if (total == 0) return false;
            out.clear();
            out.reserve(total);
            const std::uint16_t kChunk = 768;
            std::uint16_t offset = 0;
            while (offset < total) {
                std::uint16_t want = static_cast<std::uint16_t>(total - offset);
                if (want > kChunk) want = kChunk;
                std::vector<std::uint8_t> chunk;
                if (!tpm_nv_read_chunk(nv_index, want, offset, chunk)) return false;
                if (chunk.empty()) return false;
                out.insert(out.end(), chunk.begin(), chunk.end());
                offset = static_cast<std::uint16_t>(offset + chunk.size());
                if (chunk.size() < want) break;
            }
            return !out.empty();
        }

        bool collect_tpm_ek_sha256(std::vector<std::uint8_t>& out,
                                   bool& out_present) noexcept
        {
            out_present = false;
            const char* literal = "no_tpm";
            out.assign(reinterpret_cast<const std::uint8_t*>(literal),
                       reinterpret_cast<const std::uint8_t*>(literal) + 6);
            return true;
        }

        std::uint64_t monotonic_ms() noexcept
        {
            using namespace std::chrono;
            return static_cast<std::uint64_t>(
                duration_cast<milliseconds>(
                    steady_clock::now().time_since_epoch()).count());
        }

        bool finalize_factor(factor_record_t& f) noexcept
        {
            if (f.bytes.empty()) {
                f.factor_hash.fill(0);
                f.collected = false;
                return false;
            }
            if (!sha256_compute(f.bytes.data(), f.bytes.size(), f.factor_hash)) {
                f.factor_hash.fill(0);
                f.collected = false;
                return false;
            }
            f.collected = true;
            return true;
        }

        bool compute_hwid_hash(const collection_t& c,
                               std::array<std::uint8_t, 32>& out) noexcept
        {
            std::vector<std::uint8_t> buf;
            buf.reserve(2048);
            std::uint8_t hdr[4];
            hdr[0] = static_cast<std::uint8_t>(kHwidVersion & 0xFF);
            hdr[1] = static_cast<std::uint8_t>((kHwidVersion >> 8) & 0xFF);
            hdr[2] = static_cast<std::uint8_t>((kHwidVersion >> 16) & 0xFF);
            hdr[3] = static_cast<std::uint8_t>((kHwidVersion >> 24) & 0xFF);
            buf.insert(buf.end(), hdr, hdr + 4);
            for (std::size_t i = 0; i < kFactorCount; ++i) {
                const auto& f = c.factors[i];
                std::uint16_t len = static_cast<std::uint16_t>(
                    (f.bytes.size() > 0xFFFFu) ? 0xFFFFu : f.bytes.size());
                buf.push_back(static_cast<std::uint8_t>(len & 0xFF));
                buf.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
                if (len) buf.insert(buf.end(), f.bytes.begin(),
                                    f.bytes.begin() + len);
            }
            return sha256_compute(buf.data(), buf.size(), out);
        }
    }

    bool collect(collection_t& out, std::string& last_error) noexcept
    {
        out = collection_t{};
        for (std::size_t i = 0; i < kFactorCount; ++i) {
            out.factors[i].id = static_cast<std::uint8_t>(i + 1);
        }
        last_error.clear();

        bool ok1 = collect_smbios_uuid(out.factors[0].bytes);
        bool ok2 = collect_smbios_string_factor(2, 0x07, out.factors[1].bytes);
        bool ok3 = collect_smbios_string_factor(3, 0x07, out.factors[2].bytes);
        bool ok4 = collect_disk_serial(out.factors[3].bytes);
        bool ok6 = collect_cpuid_brand(out.factors[5].bytes);
        bool ok7 = collect_machine_guid(out.factors[6].bytes);
        bool ok8 = collect_installation_guid(out.factors[7].bytes);
        bool tpm_present_flag = false;
        bool ok9 = collect_tpm_ek_sha256(out.factors[8].bytes, tpm_present_flag);

        for (std::size_t i = 0; i < kFactorCount; ++i) {
            finalize_factor(out.factors[i]);
        }
        out.tpm_present = tpm_present_flag;
        out.factor_present_mask = 0;
        for (std::size_t i = 0; i < kFactorCount; ++i) {
            if (out.factors[i].collected) {
                out.factor_present_mask |= (1u << i);
            }
        }
        out.collected_at_ms = monotonic_ms();

        int collected_count = 0;
        if (ok1) ++collected_count;
        if (ok2) ++collected_count;
        if (ok3) ++collected_count;
        if (ok4) ++collected_count;
        if (ok6) ++collected_count;
        if (ok7) ++collected_count;
        if (ok8) ++collected_count;
        if (ok9) ++collected_count;

        if (collected_count < 5) {
            char tmp[128];
            std::snprintf(tmp, sizeof(tmp),
                "insufficient_factors collected=%d mask=0x%08X",
                collected_count, out.factor_present_mask);
            last_error.assign(tmp);
            return false;
        }

        if (!compute_hwid_hash(out, out.hwid_hash)) {
            last_error.assign("hwid_hash_compute_failed");
            return false;
        }
        return true;
    }

    bool hash_only(std::array<std::uint8_t, 32>& out_hash,
                   std::string& last_error) noexcept
    {
        collection_t c;
        if (!collect(c, last_error)) return false;
        out_hash = c.hwid_hash;
        return true;
    }

    bool factor_hashes(std::array<std::array<std::uint8_t, 32>, kFactorCount>& out,
                       std::string& last_error) noexcept
    {
        collection_t c;
        if (!collect(c, last_error)) return false;
        for (std::size_t i = 0; i < kFactorCount; ++i) {
            out[i] = c.factors[i].factor_hash;
        }
        return true;
    }

    bool hwid_factor_count_changed(
        const std::array<std::array<std::uint8_t, 32>, kFactorCount>& a,
        const std::array<std::array<std::uint8_t, 32>, kFactorCount>& b,
        std::uint32_t& out_changed_count) noexcept
    {
        std::uint32_t changed = 0;
        for (std::size_t i = 0; i < kFactorCount; ++i) {
            if (std::memcmp(a[i].data(), b[i].data(), 32) != 0) {
                ++changed;
            }
        }
        out_changed_count = changed;
        return changed > 0;
    }

    std::string hash_to_hex(const std::array<std::uint8_t, 32>& hash) noexcept
    {
        static const char* hex = "0123456789abcdef";
        std::string s;
        s.resize(64);
        for (int i = 0; i < 32; ++i) {
            s[i * 2]     = hex[(hash[i] >> 4) & 0xF];
            s[i * 2 + 1] = hex[hash[i] & 0xF];
        }
        return s;
    }
}
