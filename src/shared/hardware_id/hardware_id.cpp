#include "hardware_id.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <intrin.h>
#include <tbs.h>

#include <cstdio>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <array>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "tbs.lib")

namespace aida::hardware_id
{
    namespace
    {
        std::string to_hex(const unsigned char* data, size_t len)
        {
            static const char* digits = "0123456789abcdef";
            std::string out;
            out.resize(len * 2);
            for (size_t i = 0; i < len; ++i) {
                out[i * 2]     = digits[(data[i] >> 4) & 0xF];
                out[i * 2 + 1] = digits[data[i] & 0xF];
            }
            return out;
        }

        std::string sha256_hex(const std::string& s)
        {
            HCRYPTPROV prov = 0;
            HCRYPTHASH hash = 0;
            unsigned char digest[32] = {};
            DWORD dlen = sizeof(digest);
            if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
            std::string out;
            if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
                if (CryptHashData(hash, reinterpret_cast<const BYTE*>(s.data()), static_cast<DWORD>(s.size()), 0)) {
                    if (CryptGetHashParam(hash, HP_HASHVAL, digest, &dlen, 0)) {
                        out = to_hex(digest, dlen);
                    }
                }
                CryptDestroyHash(hash);
            }
            CryptReleaseContext(prov, 0);
            return out;
        }

        std::string read_machine_guid()
        {
            HKEY h = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return {};
            wchar_t buf[128] = {};
            DWORD sz = sizeof(buf);
            DWORD type = 0;
            std::string out;
            if (RegQueryValueExW(h, L"MachineGuid", nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
                char ascii[128] = {};
                WideCharToMultiByte(CP_UTF8, 0, buf, -1, ascii, sizeof(ascii), nullptr, nullptr);
                out = ascii;
            }
            RegCloseKey(h);
            return out;
        }

        std::string read_volume_serial()
        {
            wchar_t system_dir[MAX_PATH] = {};
            GetSystemDirectoryW(system_dir, MAX_PATH);
            wchar_t root[4] = { system_dir[0], L':', L'\\', 0 };
            DWORD serial = 0;
            if (!GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) return {};
            char buf[32] = {};
            std::snprintf(buf, sizeof(buf), "%08lx", static_cast<unsigned long>(serial));
            return buf;
        }

        std::string read_primary_mac()
        {
            ULONG sz = 0;
            GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &sz);
            if (sz == 0) return {};
            std::vector<unsigned char> buf(sz);
            auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
            if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapters, &sz) != NO_ERROR) return {};
            for (auto* a = adapters; a; a = a->Next) {
                if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
                if (a->PhysicalAddressLength >= 6) {
                    return to_hex(a->PhysicalAddress, 6);
                }
            }
            return {};
        }

        std::string read_cpu_topology()
        {
            int info[4] = {};
            std::ostringstream os;
            __cpuid(info, 0);
            os << std::hex << std::setw(8) << std::setfill('0') << info[0] << info[1] << info[2] << info[3];
            __cpuid(info, 1);
            os << std::hex << std::setw(8) << std::setfill('0') << info[0] << info[3];
            __cpuid(info, 7);
            os << std::hex << std::setw(8) << std::setfill('0') << info[1];
            return os.str();
        }

        std::string read_smbios_uuid()
        {
            UINT table_size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
            if (table_size == 0) return {};
            std::vector<unsigned char> buf(table_size);
            if (GetSystemFirmwareTable('RSMB', 0, buf.data(), table_size) == 0) return {};
            if (buf.size() < 8) return {};
            const unsigned char* tbl = buf.data() + 8;
            size_t tbl_len = buf.size() - 8;
            size_t off = 0;
            while (off + 4 < tbl_len) {
                unsigned char type = tbl[off];
                unsigned char len  = tbl[off + 1];
                if (len < 4 || off + len > tbl_len) break;
                if (type == 1 && len >= 24) {
                    return to_hex(tbl + off + 8, 16);
                }
                size_t after = off + len;
                while (after + 1 < tbl_len && !(tbl[after] == 0 && tbl[after + 1] == 0)) ++after;
                off = after + 2;
            }
            return {};
        }

        std::string read_baseboard_serial()
        {
            UINT table_size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
            if (table_size == 0) return {};
            std::vector<unsigned char> buf(table_size);
            if (GetSystemFirmwareTable('RSMB', 0, buf.data(), table_size) == 0) return {};
            if (buf.size() < 8) return {};
            const unsigned char* tbl = buf.data() + 8;
            size_t tbl_len = buf.size() - 8;
            size_t off = 0;
            while (off + 4 < tbl_len) {
                unsigned char type = tbl[off];
                unsigned char len  = tbl[off + 1];
                if (len < 4 || off + len > tbl_len) break;
                size_t after = off + len;
                const unsigned char* strings_start = tbl + after;
                while (after + 1 < tbl_len && !(tbl[after] == 0 && tbl[after + 1] == 0)) ++after;
                if (type == 2 && len >= 8) {
                    unsigned char serial_index = tbl[off + 4];
                    if (serial_index > 0) {
                        const char* p = reinterpret_cast<const char*>(strings_start);
                        const char* end = reinterpret_cast<const char*>(tbl + after);
                        for (unsigned char i = 1; i < serial_index && p < end; ++i) {
                            while (p < end && *p) ++p;
                            if (p < end) ++p;
                        }
                        if (p < end) {
                            std::string s(p);
                            return s;
                        }
                    }
                }
                off = after + 2;
            }
            return {};
        }

        std::string read_disk_vpd()
        {
            HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h == INVALID_HANDLE_VALUE) return {};
            STORAGE_PROPERTY_QUERY q = {};
            q.PropertyId = StorageDeviceProperty;
            q.QueryType = PropertyStandardQuery;
            std::vector<unsigned char> out(1024);
            DWORD returned = 0;
            BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), out.data(), static_cast<DWORD>(out.size()), &returned, nullptr);
            CloseHandle(h);
            if (!ok || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return {};
            auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(out.data());
            if (desc->SerialNumberOffset == 0) return {};
            const char* serial = reinterpret_cast<const char*>(out.data() + desc->SerialNumberOffset);
            return std::string(serial);
        }
    }

    anchor_set_t collect_user_mode() noexcept
    {
        anchor_set_t a;
        a.smbios_uuid        = read_smbios_uuid();
        a.baseboard_serial   = read_baseboard_serial();
        a.disk_vpd_serial    = read_disk_vpd();
        a.machine_guid       = read_machine_guid();
        a.efi_boot_guid      = "";
        a.primary_mac        = read_primary_mac();
        a.cpu_topology       = read_cpu_topology();
        a.volume_serial      = read_volume_serial();
        a.boot_nonce         = 0;

        int n = 0;
        if (!a.smbios_uuid.empty())      ++n;
        if (!a.baseboard_serial.empty()) ++n;
        if (!a.disk_vpd_serial.empty())  ++n;
        if (!a.machine_guid.empty())     ++n;
        if (!a.primary_mac.empty())      ++n;
        if (!a.cpu_topology.empty())     ++n;
        if (!a.volume_serial.empty())    ++n;
        a.collected_anchor_count = n;
        a.valid_count = (n >= 6);
        return a;
    }

    bool collect_from_driver(anchor_set_t& ) noexcept
    {
        return false;
    }

    std::string canonical_string(const anchor_set_t& a) noexcept
    {
        std::ostringstream os;
        os  << "v1|"
            << a.smbios_uuid       << '|'
            << a.baseboard_serial  << '|'
            << a.disk_vpd_serial   << '|'
            << a.machine_guid      << '|'
            << a.efi_boot_guid     << '|'
            << a.primary_mac       << '|'
            << a.cpu_topology      << '|'
            << a.volume_serial;
        return os.str();
    }

    composite_t hash_anchors(const anchor_set_t& a) noexcept
    {
        composite_t c;
        c.hardware_id_sha256    = sha256_hex(canonical_string(a));
        c.smbios_uuid_hash      = sha256_hex(a.smbios_uuid);
        c.baseboard_serial_hash = sha256_hex(a.baseboard_serial);
        c.disk_vpd_hash         = sha256_hex(a.disk_vpd_serial);
        c.machine_guid_hash     = sha256_hex(a.machine_guid);
        c.anchor_count          = a.collected_anchor_count;
        return c;
    }

    namespace
    {
        constexpr std::uint32_t TPM_ST_NO_SESSIONS                 = 0x8001;
        constexpr std::uint32_t TPM_CC_PCR_Read                    = 0x0000017E;
        constexpr std::uint32_t TPM_CC_NV_ReadPublic               = 0x00000169;
        constexpr std::uint32_t TPM_CC_ReadPublic                  = 0x00000173;
        constexpr std::uint32_t TPM_RH_ENDORSEMENT                 = 0x4000000B;
        constexpr std::uint32_t TPM_ALG_SHA256                     = 0x000B;
        constexpr std::uint32_t EK_NV_INDEX_RSA_2048               = 0x01C00002;

        static void be_put_u16(std::vector<unsigned char>& out, std::uint16_t v)
        {
            out.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
            out.push_back(static_cast<unsigned char>(v & 0xFF));
        }
        static void be_put_u32(std::vector<unsigned char>& out, std::uint32_t v)
        {
            out.push_back(static_cast<unsigned char>((v >> 24) & 0xFF));
            out.push_back(static_cast<unsigned char>((v >> 16) & 0xFF));
            out.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
            out.push_back(static_cast<unsigned char>(v & 0xFF));
        }

        static std::uint16_t be_get_u16(const unsigned char* p)
        {
            return (static_cast<std::uint16_t>(p[0]) << 8) | static_cast<std::uint16_t>(p[1]);
        }
        static std::uint32_t be_get_u32(const unsigned char* p)
        {
            return (static_cast<std::uint32_t>(p[0]) << 24)
                 | (static_cast<std::uint32_t>(p[1]) << 16)
                 | (static_cast<std::uint32_t>(p[2]) << 8)
                 |  static_cast<std::uint32_t>(p[3]);
        }

        static std::vector<unsigned char> build_pcr_read_command(const std::vector<int>& indices)
        {
            std::vector<unsigned char> cmd;
            be_put_u16(cmd, static_cast<std::uint16_t>(TPM_ST_NO_SESSIONS));
            be_put_u32(cmd, 0);
            be_put_u32(cmd, TPM_CC_PCR_Read);
            be_put_u32(cmd, 1);
            be_put_u16(cmd, static_cast<std::uint16_t>(TPM_ALG_SHA256));
            cmd.push_back(3);
            unsigned char bitmap[3] = { 0, 0, 0 };
            for (int idx : indices) {
                if (idx < 0 || idx >= 24) continue;
                bitmap[idx >> 3] |= static_cast<unsigned char>(1 << (idx & 7));
            }
            cmd.push_back(bitmap[0]);
            cmd.push_back(bitmap[1]);
            cmd.push_back(bitmap[2]);
            std::uint32_t total = static_cast<std::uint32_t>(cmd.size());
            cmd[2] = static_cast<unsigned char>((total >> 24) & 0xFF);
            cmd[3] = static_cast<unsigned char>((total >> 16) & 0xFF);
            cmd[4] = static_cast<unsigned char>((total >> 8) & 0xFF);
            cmd[5] = static_cast<unsigned char>(total & 0xFF);
            return cmd;
        }

        static bool parse_pcr_read_response(const unsigned char* resp, std::uint32_t resp_len, std::vector<std::array<unsigned char, 32>>& out)
        {
            if (resp_len < 10) return false;
            std::uint32_t rc = be_get_u32(resp + 6);
            if (rc != 0) return false;
            std::uint32_t cursor = 10;
            if (cursor + 4 > resp_len) return false;
            cursor += 4;
            if (cursor + 4 > resp_len) return false;
            std::uint32_t pcr_select_count = be_get_u32(resp + cursor);
            cursor += 4;
            for (std::uint32_t i = 0; i < pcr_select_count; ++i) {
                if (cursor + 3 > resp_len) return false;
                cursor += 2;
                std::uint8_t size_of_select = resp[cursor];
                cursor += 1;
                if (cursor + size_of_select > resp_len) return false;
                cursor += size_of_select;
            }
            if (cursor + 4 > resp_len) return false;
            std::uint32_t pcr_count = be_get_u32(resp + cursor);
            cursor += 4;
            out.clear();
            out.reserve(pcr_count);
            for (std::uint32_t i = 0; i < pcr_count; ++i) {
                if (cursor + 2 > resp_len) return false;
                std::uint16_t pcr_size = be_get_u16(resp + cursor);
                cursor += 2;
                if (pcr_size != 32) return false;
                if (cursor + pcr_size > resp_len) return false;
                std::array<unsigned char, 32> pcr;
                std::memcpy(pcr.data(), resp + cursor, 32);
                out.push_back(pcr);
                cursor += pcr_size;
            }
            return true;
        }

        static std::vector<unsigned char> build_nv_readpublic_command(std::uint32_t nv_index)
        {
            std::vector<unsigned char> cmd;
            be_put_u16(cmd, static_cast<std::uint16_t>(TPM_ST_NO_SESSIONS));
            be_put_u32(cmd, 0);
            be_put_u32(cmd, TPM_CC_NV_ReadPublic);
            be_put_u32(cmd, nv_index);
            std::uint32_t total = static_cast<std::uint32_t>(cmd.size());
            cmd[2] = static_cast<unsigned char>((total >> 24) & 0xFF);
            cmd[3] = static_cast<unsigned char>((total >> 16) & 0xFF);
            cmd[4] = static_cast<unsigned char>((total >> 8) & 0xFF);
            cmd[5] = static_cast<unsigned char>(total & 0xFF);
            return cmd;
        }

        static bool tbs_submit(const std::vector<unsigned char>& cmd, std::vector<unsigned char>& reply)
        {
            TBS_CONTEXT_PARAMS2 params{};
            params.version = TBS_CONTEXT_VERSION_TWO;
            params.includeTpm20 = 1;
            TBS_HCONTEXT ctx = nullptr;
            TBS_RESULT rc = Tbsi_Context_Create(reinterpret_cast<TBS_CONTEXT_PARAMS*>(&params), &ctx);
            if (rc != TBS_SUCCESS || ctx == nullptr) return false;
            reply.assign(4096, 0);
            UINT32 reply_len = static_cast<UINT32>(reply.size());
            rc = Tbsip_Submit_Command(
                ctx,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd.data(),
                static_cast<UINT32>(cmd.size()),
                reply.data(),
                &reply_len);
            Tbsip_Context_Close(ctx);
            if (rc != TBS_SUCCESS) return false;
            reply.resize(reply_len);
            return true;
        }

        static bool read_pcr_values_sha256(std::vector<std::array<unsigned char, 32>>& pcr_out)
        {
            std::vector<int> indices = { 0, 1, 2, 3, 4, 5, 6, 7 };
            auto cmd = build_pcr_read_command(indices);
            std::vector<unsigned char> reply;
            if (!tbs_submit(cmd, reply)) return false;
            return parse_pcr_read_response(reply.data(), static_cast<std::uint32_t>(reply.size()), pcr_out);
        }

        static bool read_ek_public_blob(std::vector<unsigned char>& der_out)
        {
            auto cmd = build_nv_readpublic_command(EK_NV_INDEX_RSA_2048);
            std::vector<unsigned char> reply;
            if (!tbs_submit(cmd, reply)) return false;
            if (reply.size() < 14) return false;
            std::uint32_t rc = be_get_u32(reply.data() + 6);
            if (rc != 0) return false;
            der_out.assign(reply.begin() + 10, reply.end());
            return !der_out.empty();
        }

        static std::string sha256_bytes_hex(const unsigned char* data, size_t len)
        {
            HCRYPTPROV prov = 0;
            HCRYPTHASH hash = 0;
            unsigned char digest[32] = {};
            DWORD dlen = sizeof(digest);
            if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
            std::string out;
            if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
                if (CryptHashData(hash, data, static_cast<DWORD>(len), 0)) {
                    if (CryptGetHashParam(hash, HP_HASHVAL, digest, &dlen, 0)) {
                        out = to_hex(digest, dlen);
                    }
                }
                CryptDestroyHash(hash);
            }
            CryptReleaseContext(prov, 0);
            return out;
        }
    }

    bool collect_tpm_attestation(tpm_attest_t& out) noexcept
    {
        out = tpm_attest_t{};
        std::vector<std::array<unsigned char, 32>> pcrs;
        if (!read_pcr_values_sha256(pcrs)) return false;
        if (pcrs.size() < 8) return false;
        std::vector<unsigned char> ek_blob;
        if (!read_ek_public_blob(ek_blob)) return false;
        if (ek_blob.size() < 32) return false;
        out.present = true;
        out.pcr_values = pcrs;
        out.ek_pub_der = ek_blob;
        out.ek_pub_sha256 = sha256_bytes_hex(ek_blob.data(), ek_blob.size());
        std::vector<unsigned char> pcr_concat;
        pcr_concat.reserve(8 * 32);
        for (size_t i = 0; i < 8; ++i) {
            pcr_concat.insert(pcr_concat.end(), pcrs[i].begin(), pcrs[i].end());
        }
        out.pcr_composite_sha256 = sha256_bytes_hex(pcr_concat.data(), pcr_concat.size());
        std::vector<unsigned char> hwid_input;
        hwid_input.reserve(ek_blob.size() + pcr_concat.size());
        hwid_input.insert(hwid_input.end(), ek_blob.begin(), ek_blob.end());
        hwid_input.insert(hwid_input.end(), pcr_concat.begin(), pcr_concat.end());
        out.hwid_component_sha256 = sha256_bytes_hex(hwid_input.data(), hwid_input.size());
        return true;
    }

    composite_t hash_anchors_with_tpm(const anchor_set_t& a, const tpm_attest_t& tpm) noexcept
    {
        composite_t c = hash_anchors(a);
        if (!tpm.present) return c;
        std::ostringstream os;
        os << c.hardware_id_sha256
           << "|tpm-ek|" << tpm.ek_pub_sha256
           << "|tpm-pcr|" << tpm.pcr_composite_sha256;
        c.hardware_id_sha256 = sha256_hex(os.str());
        return c;
    }
}
