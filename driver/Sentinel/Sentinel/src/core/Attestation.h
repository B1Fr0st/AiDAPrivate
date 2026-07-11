#pragma once

#include <ntddk.h>
#include <intrin.h>
#include <bcrypt.h>
#include "KernelCrypto.h"
#include "HardwareId.h"
#include "WitnessKey.h"
#include "Integrity.h"

namespace attestation
{
    constexpr ULONG ATTEST_POOL_TAG = 'tA7k';
    constexpr ULONG HWID_SIZE = 32;
    constexpr ULONG BUILD_ID_SIZE = 16;

    struct attest_state_t
    {
        UINT8   hardware_id[HWID_SIZE];
        UINT8   boot_nonce[HWID_SIZE];
        UINT8   attest_hmac[HWID_SIZE];
        BOOLEAN valid;
        UINT64  boot_timestamp;
        UINT8   build_id[BUILD_ID_SIZE];
    };

#pragma pack(push, 1)
    struct attest_with_integrity_t
    {
        UINT8   nonce[16];
        UINT8   usermode_code_hash[32];
        UINT64  timestamp;
        UINT8   hardware_id[32];
        UINT8   build_id[16];
        UINT8   hmac[32];
    };
#pragma pack(pop)
    static_assert(sizeof(attest_with_integrity_t) == 136,
        "attest_with_integrity_t must be 136 bytes");

    inline attest_state_t g_attest = {};

    __forceinline NTSTATUS collect_hardware_anchors()
    {
        NTSTATUS smbios_status = hardware_id::collect_smbios(
            hardware_id::g_anchors.smbios_uuid,
            hardware_id::g_anchors.baseboard_serial,
            sizeof(hardware_id::g_anchors.baseboard_serial));

        NTSTATUS disk_status = hardware_id::collect_disk_serial(
            hardware_id::g_anchors.disk_serial,
            sizeof(hardware_id::g_anchors.disk_serial));

        NTSTATUS machine_guid_status = hardware_id::collect_machine_guid(
            hardware_id::g_anchors.machine_guid,
            sizeof(hardware_id::g_anchors.machine_guid));

        NTSTATUS volume_status = hardware_id::collect_volume_serial(
            &hardware_id::g_anchors.volume_serial);

        hardware_id::g_anchors.cpu_topology = hardware_id::collect_cpu_topology();
        hardware_id::g_anchors.anchor_build = hardware_id::kernel_build_number();
        hardware_id::g_anchors.anchor_status = hardware_id::build_anchor_status(smbios_status, disk_status, machine_guid_status, volume_status);
        SN_LOG("attestation::collect_hardware_anchors statuses build=%lu smbios=0x%08lx disk=0x%08lx machine_guid=0x%08lx volume=0x%08lx anchor_status=0x%08lx storage_gate=%u",
            hardware_id::g_anchors.anchor_build,
            smbios_status,
            disk_status,
            machine_guid_status,
            volume_status,
            hardware_id::g_anchors.anchor_status,
            hardware_id::skip_storage_device_open() ? 1u : 0u);

        UNICODE_STRING adapter_path;
        RtlInitUnicodeString(&adapter_path,
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards");
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &adapter_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE net_key = nullptr;
        NTSTATUS st = ZwOpenKey(&net_key, KEY_READ, &oa);
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
        UINT8 concat[16 + 64 + 64 + 64 + 6 + 8 + 4 + 4 + 4 + 32];
        ULONG offset = 0;

        RtlCopyMemory(concat + offset, hardware_id::g_anchors.smbios_uuid, 16); offset += 16;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.baseboard_serial, 64); offset += 64;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.disk_serial, 64); offset += 64;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.machine_guid, 64); offset += 64;
        RtlCopyMemory(concat + offset, hardware_id::g_anchors.mac_addr, 6); offset += 6;
        RtlCopyMemory(concat + offset, &hardware_id::g_anchors.cpu_topology, 8); offset += 8;
        RtlCopyMemory(concat + offset, &hardware_id::g_anchors.volume_serial, 4); offset += 4;
        RtlCopyMemory(concat + offset, &hardware_id::g_anchors.anchor_status, 4); offset += 4;
        RtlCopyMemory(concat + offset, &hardware_id::g_anchors.anchor_build, 4); offset += 4;
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

    __forceinline NTSTATUS compute_attest_with_integrity(
        attest_with_integrity_t& out)
    {
        RtlZeroMemory(&out, sizeof(out));

        if (!_InterlockedCompareExchange(&integrity::g_usermode_hash_initialized, 1, 1)) {
            SN_LOG("attestation::compute_attest_with_integrity: usermode hash not initialized, skipping");
            return STATUS_NOT_FOUND;
        }

        NTSTATUS st = kernel_crypto::gen_random(out.nonce, 16);
        if (!NT_SUCCESS(st)) {
            SN_LOG("attestation::compute_attest_with_integrity: gen_random nonce failed status=0x%08lx", st);
            return st;
        }

        RtlCopyMemory(out.usermode_code_hash,
            integrity::g_usermode_last_computed_sha256, 32);

        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);
        out.timestamp = static_cast<UINT64>(ts.QuadPart);

        RtlCopyMemory(out.hardware_id, g_attest.hardware_id, 32);

        RtlCopyMemory(out.build_id, g_attest.build_id, 16);

        UINT8 install_secret[32];
        if (!witness_key::read_kw(install_secret)) {
            SN_LOG("attestation::compute_attest_with_integrity: witness_key read_kw failed");
            return STATUS_UNSUCCESSFUL;
        }

        UINT8 hmac_input[104];
        RtlCopyMemory(hmac_input + 0,  out.nonce, 16);
        RtlCopyMemory(hmac_input + 16, out.usermode_code_hash, 32);
        RtlCopyMemory(hmac_input + 48, &out.timestamp, 8);
        RtlCopyMemory(hmac_input + 56, out.hardware_id, 32);
        RtlCopyMemory(hmac_input + 88, out.build_id, 16);

        st = kernel_crypto::hmac_sha256(
            install_secret, 32,
            hmac_input, sizeof(hmac_input),
            out.hmac);

        RtlSecureZeroMemory(install_secret, sizeof(install_secret));
        RtlSecureZeroMemory(hmac_input, sizeof(hmac_input));

        if (!NT_SUCCESS(st)) {
            SN_LOG("attestation::compute_attest_with_integrity: hmac_sha256 failed status=0x%08lx", st);
        }
        return st;
    }

    __forceinline BOOLEAN init()
    {
        SN_LOG("attestation::init: collecting hardware anchors");
        collect_hardware_anchors();
        SN_LOG("attestation::init: computing hardware ID");
        NTSTATUS st = compute_hardware_id();
        if (!NT_SUCCESS(st)) {
            SN_LOG("attestation::init: FAIL - compute_hardware_id status=0x%08lx", st);
            return FALSE;
        }

        g_attest.valid = TRUE;
        SN_LOG("attestation::init: SUCCESS");
        return TRUE;
    }

    constexpr ULONG WATERMARK_SIZE = 16;

    struct watermark_state_t {
        UINT8   expected_watermark[WATERMARK_SIZE];
        UINT8   actual_watermark[WATERMARK_SIZE];
        BOOLEAN watermark_verified;
        UINT32  watermark_rva;
        UINT64  verification_timestamp;
    };

    inline watermark_state_t g_watermark_state = {};

    __forceinline NTSTATUS extract_usermode_watermark(
        PEPROCESS process, UINT32* watermark_offset, UINT8 out_watermark[16])
    {
        if (!process || !out_watermark || !watermark_offset)
            return STATUS_INVALID_PARAMETER;

        if (!_PsGetProcessPeb || !_KeStackAttachProcess || !_KeUnstackDetachProcess || !_MmIsAddressValid)
            return STATUS_NOT_IMPLEMENTED;

        *watermark_offset = 0;
        RtlZeroMemory(out_watermark, 16);

        KAPC_STATE apc_state;
        BOOLEAN attached = FALSE;
        NTSTATUS result = STATUS_UNSUCCESSFUL;

        __try {
            PPEB peb = _PsGetProcessPeb(process);
            if (!peb) {
                SN_LOG("attestation::extract_usermode_watermark: PEB is null");
                goto detach_and_return;
            }

            _KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(process), &apc_state);
            attached = TRUE;

            if (!_MmIsAddressValid(peb)) {
                SN_LOG("attestation::extract_usermode_watermark: PEB not valid after attach");
                goto detach_and_return;
            }

            PVOID image_base = *reinterpret_cast<PVOID*>(
                reinterpret_cast<PUCHAR>(peb) + 0x10);
            if (!image_base || !_MmIsAddressValid(image_base)) {
                SN_LOG("attestation::extract_usermode_watermark: image_base invalid base=%p", image_base);
                goto detach_and_return;
            }

            PUCHAR base = static_cast<PUCHAR>(image_base);

            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(base + 0x3C))) {
                SN_LOG("attestation::extract_usermode_watermark: DOS header e_lfanew ptr invalid");
                goto detach_and_return;
            }

            DWORD e_lfanew = *reinterpret_cast<DWORD*>(base + 0x3C);
            if (e_lfanew == 0 || e_lfanew > 0x100000) {
                SN_LOG("attestation::extract_usermode_watermark: e_lfanew invalid=%lu", e_lfanew);
                goto detach_and_return;
            }

            ULONG wm_offset = e_lfanew + 24 + static_cast<ULONG>(AIDA_WATERMARK_OPT_HDR_OFFSET);
            PVOID watermark_addr = reinterpret_cast<PVOID>(base + wm_offset);

            if (!_MmIsAddressValid(watermark_addr)) {
                SN_LOG("attestation::extract_usermode_watermark: watermark addr invalid offset=%lu", wm_offset);
                goto detach_and_return;
            }

            RtlCopyMemory(out_watermark, watermark_addr, 16);
            *watermark_offset = wm_offset;
            result = STATUS_SUCCESS;

            SN_LOG("attestation::extract_usermode_watermark: success base=%p e_lfanew=%lu wm_offset=%lu wm[0..3]=0x%02x%02x%02x%02x",
                image_base, e_lfanew, wm_offset,
                out_watermark[0], out_watermark[1], out_watermark[2], out_watermark[3]);

        detach_and_return:
            if (attached) {
                __try {
                    _KeUnstackDetachProcess(&apc_state);
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("attestation::extract_usermode_watermark: EXCEPTION");
            if (attached) {
                __try {
                    _KeUnstackDetachProcess(&apc_state);
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
            result = STATUS_ACCESS_VIOLATION;
        }

        return result;
    }

    __forceinline BOOLEAN verify_watermark(PEPROCESS process, const UINT8 expected[16])
    {
        if (!process || !expected)
            return FALSE;

        UINT32 wm_offset = 0;
        UINT8 actual[16] = {};

        NTSTATUS st = extract_usermode_watermark(process, &wm_offset, actual);
        if (!NT_SUCCESS(st)) {
            SN_LOG("attestation::verify_watermark: extract failed status=0x%08lx", st);
            RtlCopyMemory(g_watermark_state.expected_watermark, expected, 16);
            RtlZeroMemory(g_watermark_state.actual_watermark, 16);
            g_watermark_state.watermark_verified = FALSE;
            g_watermark_state.watermark_rva = 0;
            g_watermark_state.verification_timestamp = static_cast<UINT64>(__rdtsc());
            return FALSE;
        }

        BOOLEAN match = static_cast<BOOLEAN>(RtlEqualMemory(actual, expected, 16));

        RtlCopyMemory(g_watermark_state.expected_watermark, expected, 16);
        RtlCopyMemory(g_watermark_state.actual_watermark, actual, 16);
        g_watermark_state.watermark_verified = match;
        g_watermark_state.watermark_rva = wm_offset;

        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);
        g_watermark_state.verification_timestamp = static_cast<UINT64>(ts.QuadPart);

        SN_LOG("attestation::verify_watermark: match=%u wm_offset=%lu expected[0..3]=0x%02x%02x%02x%02x actual[0..3]=0x%02x%02x%02x%02x",
            match ? 1u : 0u, wm_offset,
            expected[0], expected[1], expected[2], expected[3],
            actual[0], actual[1], actual[2], actual[3]);

        return match;
    }
}
