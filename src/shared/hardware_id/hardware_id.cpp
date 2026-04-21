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

#include <cstdio>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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
}
