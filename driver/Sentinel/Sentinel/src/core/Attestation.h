#pragma once

#include <ntddk.h>
#include <intrin.h>
#include <bcrypt.h>
#include "KernelCrypto.h"
#include "HardwareId.h"
#include "WitnessKey.h"

namespace attestation
{
    constexpr ULONG ATTEST_POOL_TAG = 'tA7k';
    constexpr ULONG HWID_SIZE = 32;

    struct attest_state_t
    {
        UINT8   hardware_id[HWID_SIZE];
        UINT8   boot_nonce[HWID_SIZE];
        UINT8   attest_hmac[HWID_SIZE];
        BOOLEAN valid;
        UINT64  boot_timestamp;
    };

    inline attest_state_t g_attest = {};

    __forceinline NTSTATUS collect_hardware_anchors()
    {
        NTSTATUS st = hardware_id::collect_smbios(
            hardware_id::g_anchors.smbios_uuid,
            hardware_id::g_anchors.baseboard_serial,
            sizeof(hardware_id::g_anchors.baseboard_serial));

        hardware_id::collect_disk_serial(
            hardware_id::g_anchors.disk_serial,
            sizeof(hardware_id::g_anchors.disk_serial));

        hardware_id::collect_machine_guid(
            hardware_id::g_anchors.machine_guid,
            sizeof(hardware_id::g_anchors.machine_guid));

        hardware_id::collect_volume_serial(
            &hardware_id::g_anchors.volume_serial);

        hardware_id::g_anchors.cpu_topology = hardware_id::collect_cpu_topology();

        UNICODE_STRING adapter_path;
        RtlInitUnicodeString(&adapter_path,
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards");
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &adapter_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE net_key = nullptr;
        st = ZwOpenKey(&net_key, KEY_READ, &oa);
        if (NT_SUCCESS(st))
        {
            UCHAR enum_buf[256] = {};
            ULONG idx = 0;
            ULONG result_len = 0;

            while (NT_SUCCESS(ZwEnumerateKey(net_key, idx, KeyBasicInformation,
                enum_buf, sizeof(enum_buf), &result_len)))
            {
                auto* kbi = reinterpret_cast<KEY_BASIC_INFORMATION*>(enum_buf);

                UNICODE_STRING sub_name;
                sub_name.Buffer = kbi->Name;
                sub_name.Length = static_cast<USHORT>(kbi->NameLength);
                sub_name.MaximumLength = sub_name.Length;

                OBJECT_ATTRIBUTES sub_oa;
                InitializeObjectAttributes(&sub_oa, &sub_name,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, net_key, nullptr);

                HANDLE sub_key = nullptr;
                if (NT_SUCCESS(ZwOpenKey(&sub_key, KEY_READ, &sub_oa)))
                {
                    UNICODE_STRING svc_name;
                    RtlInitUnicodeString(&svc_name, L"ServiceName");

                    UCHAR val_buf[256] = {};
                    if (NT_SUCCESS(ZwQueryValueKey(sub_key, &svc_name,
                        KeyValuePartialInformation, val_buf, sizeof(val_buf), &result_len)))
                    {
                        auto* vpi = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION*>(val_buf);
                        if (vpi->Type == REG_SZ && vpi->DataLength > sizeof(WCHAR))
                        {
                            WCHAR ndis_path[256] = {};
                            int pos = 0;
                            const WCHAR* prefix = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
                            while (prefix[pos]) { ndis_path[pos] = prefix[pos]; pos++; }
                            PWCHAR sub_buf = kbi->Name;
                            USHORT sub_chars = static_cast<USHORT>(kbi->NameLength / sizeof(WCHAR));
                            for (USHORT ci = 0; ci < sub_chars && pos < 254; ci++)
                                ndis_path[pos++] = sub_buf[ci];
                            ndis_path[pos] = L'\0';

                            UNICODE_STRING ndis_key_path;
                            RtlInitUnicodeString(&ndis_key_path, ndis_path);
                            OBJECT_ATTRIBUTES ndis_oa;
                            InitializeObjectAttributes(&ndis_oa, &ndis_key_path,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

                            HANDLE ndis_key = nullptr;
                            if (NT_SUCCESS(ZwOpenKey(&ndis_key, KEY_READ, &ndis_oa)))
                            {
                                UNICODE_STRING mac_name;
                                RtlInitUnicodeString(&mac_name, L"NetworkAddress");
                                UCHAR mac_buf[128] = {};
                                if (NT_SUCCESS(ZwQueryValueKey(ndis_key, &mac_name,
                                    KeyValuePartialInformation, mac_buf, sizeof(mac_buf), &result_len)))
                                {
                                    auto* mac_vpi = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION*>(mac_buf);
                                    if (mac_vpi->Type == REG_SZ && mac_vpi->DataLength >= 12 * sizeof(WCHAR))
                                    {
                                        PWCHAR mac_str = reinterpret_cast<PWCHAR>(mac_vpi->Data);
                                        for (int b = 0; b < 6; b++)
                                        {
                                            auto hex_val = [](WCHAR c) -> UINT8 {
                                                if (c >= L'0' && c <= L'9') return static_cast<UINT8>(c - L'0');
                                                if (c >= L'A' && c <= L'F') return static_cast<UINT8>(c - L'A' + 10);
                                                if (c >= L'a' && c <= L'f') return static_cast<UINT8>(c - L'a' + 10);
                                                return 0;
                                            };
                                            hardware_id::g_anchors.mac_addr[b] =
                                                (hex_val(mac_str[b * 2]) << 4) | hex_val(mac_str[b * 2 + 1]);
                                        }
                                        ZwClose(ndis_key);
                                        ZwClose(sub_key);
                                        goto mac_done;
                                    }
                                }
                                ZwClose(ndis_key);
                            }
                        }
                    }
                    ZwClose(sub_key);
                }
                idx++;
            }
        mac_done:
            ZwClose(net_key);
        }

        LARGE_INTEGER pc = KeQueryPerformanceCounter(nullptr);
        PKUSER_SHARED_DATA ksd = reinterpret_cast<PKUSER_SHARED_DATA>(0xFFFFF78000000000ULL);
        UINT8 boot_nonce_data[24] = {};
        RtlCopyMemory(boot_nonce_data, &pc.QuadPart, 8);
        __try {
            UINT64 sys_time = *reinterpret_cast<volatile UINT64*>(
                reinterpret_cast<ULONG_PTR>(ksd) + 0x14);
            RtlCopyMemory(boot_nonce_data + 8, &sys_time, 8);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        UINT8 install_key[32];
        if (witness_key::read_kw(install_key))
        {
            kernel_crypto::hmac_sha256(
                install_key, 32,
                boot_nonce_data, sizeof(boot_nonce_data),
                g_attest.boot_nonce);
            RtlSecureZeroMemory(install_key, sizeof(install_key));
        }
        else
        {
            kernel_crypto::sha256(boot_nonce_data, sizeof(boot_nonce_data), g_attest.boot_nonce);
        }

        return STATUS_SUCCESS;
    }

    __forceinline NTSTATUS compute_hardware_id()
    {
        UINT8 concat[16 + 64 + 64 + 64 + 6 + 8 + 4 + 32];
        ULONG offset = 0;

        RtlCopyMemory(concat + offset, hardware_id::g_anchors.smbios_uuid, 16); offset += 16;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.baseboard_serial, 64); offset += 64;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.disk_serial, 64); offset += 64;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.machine_guid, 64); offset += 64;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.mac_addr, 6); offset += 6;
        RtlCopyMemory(concat + offset, &hardware_id::g_anchors.cpu_topology, 8); offset += 8;
        RtlCopyMemory(concat + offset, &hardware_id::g_anchors.volume_serial, 4); offset += 4;
        RtlCopyMemory(concat + offset, g_attest.boot_nonce, 32); offset += 32;

        return kernel_crypto::sha256(concat, offset, g_attest.hardware_id);
    }

    __forceinline NTSTATUS compute_attest_hmac(
        const UINT8* license_key, ULONG license_key_len)
    {
        UINT8 install_secret[32];
        if (!witness_key::read_kw(install_secret))
            return STATUS_UNSUCCESSFUL;

        LARGE_INTEGER boot_ts;
        KeQuerySystemTime(&boot_ts);
        g_attest.boot_timestamp = static_cast<UINT64>(boot_ts.QuadPart);

        UINT8 hmac_input[HWID_SIZE + 256 + sizeof(UINT64)];
        ULONG hmac_len = 0;

        RtlCopyMemory(hmac_input + hmac_len, g_attest.hardware_id, HWID_SIZE);
        hmac_len += HWID_SIZE;

        ULONG copy_len = license_key_len;
        if (copy_len > 256) copy_len = 256;
        if (license_key && copy_len > 0)
        {
            RtlCopyMemory(hmac_input + hmac_len, license_key, copy_len);
            hmac_len += copy_len;
        }

        RtlCopyMemory(hmac_input + hmac_len, &g_attest.boot_timestamp, sizeof(UINT64));
        hmac_len += sizeof(UINT64);

        NTSTATUS st = kernel_crypto::hmac_sha256(
            install_secret, 32,
            hmac_input, hmac_len,
            g_attest.attest_hmac);

        RtlSecureZeroMemory(install_secret, sizeof(install_secret));
        return st;
    }

    __forceinline BOOLEAN init()
    {
        collect_hardware_anchors();
        NTSTATUS st = compute_hardware_id();
        if (!NT_SUCCESS(st))
            return FALSE;

        g_attest.valid = TRUE;
        return TRUE;
    }
}
