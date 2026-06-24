#include "HardwareId.h"

#include <ntifs.h>
#include <ntddk.h>
#include <ntddstor.h>
#include <intrin.h>

#include "../imports/Defs.h"
#include "../function/KernelCrypto.h"

namespace hardware_id_kernel
{
    constexpr ULONG kSystemFirmwareTableInformation = 76u;
    constexpr ULONG kRsmbProvider = 'RSMB';
    constexpr ULONG kPoolTag = 'wHWI';
    constexpr ULONG kFactorCount = AIDA_HWID_FACTOR_COUNT;
    constexpr ULONG kHwidVersion = 2;

    typedef SYSTEM_FIRMWARE_TABLE_INFORMATION   SYSTEM_FIRMWARE_TABLE_INFORMATION_T;
    typedef PSYSTEM_FIRMWARE_TABLE_INFORMATION  PSYSTEM_FIRMWARE_TABLE_INFORMATION_T;

    static volatile LONG g_initialized = 0;
    static UCHAR g_session_secret[32] = { 0 };

    static UCHAR uppercase_ascii(UCHAR c)
    {
        if (c >= 'a' && c <= 'z') return static_cast<UCHAR>(c - 32);
        return c;
    }

    static UCHAR lowercase_ascii(UCHAR c)
    {
        if (c >= 'A' && c <= 'Z') return static_cast<UCHAR>(c + 32);
        return c;
    }

    static BOOLEAN is_whitespace_ascii(UCHAR c)
    {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
    }

    static SIZE_T trim_and_collapse(const UCHAR* in, SIZE_T in_len, UCHAR* out, SIZE_T out_cap)
    {
        SIZE_T a = 0;
        SIZE_T b = in_len;
        while (a < b && is_whitespace_ascii(in[a])) ++a;
        while (b > a && is_whitespace_ascii(in[b - 1])) --b;
        SIZE_T w = 0;
        BOOLEAN prev_space = FALSE;
        for (SIZE_T i = a; i < b && w < out_cap; ++i) {
            if (is_whitespace_ascii(in[i])) {
                if (!prev_space) {
                    out[w++] = ' ';
                    prev_space = TRUE;
                }
            } else {
                out[w++] = in[i];
                prev_space = FALSE;
            }
        }
        return w;
    }

    static SIZE_T to_upper_buffer(UCHAR* buf, SIZE_T len)
    {
        for (SIZE_T i = 0; i < len; ++i) buf[i] = uppercase_ascii(buf[i]);
        return len;
    }

    static SIZE_T to_lower_buffer(UCHAR* buf, SIZE_T len)
    {
        for (SIZE_T i = 0; i < len; ++i) buf[i] = lowercase_ascii(buf[i]);
        return len;
    }

    static SIZE_T normalize_string_factor(const UCHAR* in, SIZE_T in_len, UCHAR* out, SIZE_T out_cap)
    {
        SIZE_T n = trim_and_collapse(in, in_len, out, out_cap);
        return to_upper_buffer(out, n);
    }

    static SIZE_T trim_only(const UCHAR* in, SIZE_T in_len, UCHAR* out, SIZE_T out_cap)
    {
        SIZE_T a = 0;
        SIZE_T b = in_len;
        while (a < b && is_whitespace_ascii(in[a])) ++a;
        while (b > a && is_whitespace_ascii(in[b - 1])) --b;
        SIZE_T w = 0;
        for (SIZE_T i = a; i < b && w < out_cap; ++i) {
            out[w++] = in[i];
        }
        return w;
    }

    static SIZE_T normalize_serial_factor(const UCHAR* in, SIZE_T in_len, UCHAR* out, SIZE_T out_cap)
    {
        SIZE_T n = trim_only(in, in_len, out, out_cap);
        return to_upper_buffer(out, n);
    }

    static SIZE_T format_uuid_lowercase(const UCHAR raw[16], UCHAR* out, SIZE_T out_cap)
    {
        if (out_cap < 36) return 0;
        static const char hex[] = "0123456789abcdef";
        UCHAR b[16];
        b[0] = raw[3];
        b[1] = raw[2];
        b[2] = raw[1];
        b[3] = raw[0];
        b[4] = raw[5];
        b[5] = raw[4];
        b[6] = raw[7];
        b[7] = raw[6];
        for (int i = 8; i < 16; ++i) b[i] = raw[i];
        SIZE_T w = 0;
        for (int i = 0; i < 16; ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) out[w++] = '-';
            out[w++] = hex[(b[i] >> 4) & 0xF];
            out[w++] = hex[b[i] & 0xF];
        }
        return w;
    }

    static NTSTATUS read_smbios_table(PUCHAR* out_buf, ULONG* out_len)
    {
        *out_buf = nullptr;
        *out_len = 0;
        ULONG required = 0;
        NTSTATUS probe_status = ZwQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(kSystemFirmwareTableInformation),
            nullptr, 0, &required);
        if ((probe_status != STATUS_INFO_LENGTH_MISMATCH &&
             probe_status != STATUS_BUFFER_TOO_SMALL) || required == 0) {
            return STATUS_UNSUCCESSFUL;
        }
        const ULONG header_size = static_cast<ULONG>(
            FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION_T, TableBuffer));
        const ULONG alloc_size =
            (required > header_size) ? required : (required + header_size);
        PSYSTEM_FIRMWARE_TABLE_INFORMATION_T info =
            reinterpret_cast<PSYSTEM_FIRMWARE_TABLE_INFORMATION_T>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, kPoolTag));
        if (!info) return STATUS_INSUFFICIENT_RESOURCES;
        info->ProviderSignature = kRsmbProvider;
        info->Action = SystemFirmwareTable_Get;
        info->TableID = 0;
        info->TableBufferLength = required;
        ULONG returned = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(kSystemFirmwareTableInformation),
            info, alloc_size, &returned);
        if (!NT_SUCCESS(status) || info->TableBufferLength == 0) {
            ExFreePoolWithTag(info, kPoolTag);
            return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
        }
        PUCHAR copy = reinterpret_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, info->TableBufferLength, kPoolTag));
        if (!copy) {
            ExFreePoolWithTag(info, kPoolTag);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(copy, info->TableBuffer, info->TableBufferLength);
        *out_buf = copy;
        *out_len = info->TableBufferLength;
        ExFreePoolWithTag(info, kPoolTag);
        return STATUS_SUCCESS;
    }

    static BOOLEAN find_smbios_structure(const UCHAR* tbl, SIZE_T tbl_len,
                                         UCHAR target_type,
                                         const UCHAR** out_fixed, UCHAR* out_fixed_len,
                                         const UCHAR** out_strings, SIZE_T* out_strings_len)
    {
        SIZE_T off = 0;
        while (off + 4 < tbl_len) {
            UCHAR type = tbl[off];
            UCHAR len = tbl[off + 1];
            if (len < 4) break;
            if (off + len > tbl_len) break;
            SIZE_T str_start = off + len;
            SIZE_T after = str_start;
            while (after + 1 < tbl_len && !(tbl[after] == 0 && tbl[after + 1] == 0)) ++after;
            if (type == target_type) {
                *out_fixed = tbl + off;
                *out_fixed_len = len;
                *out_strings = tbl + str_start;
                *out_strings_len = (after > str_start) ? (after - str_start) : 0;
                return TRUE;
            }
            off = after + 2;
            if (off > tbl_len) break;
            if (type == 127) break;
        }
        return FALSE;
    }

    static const char* smbios_string_at(const UCHAR* str_area, SIZE_T str_area_len, UCHAR index)
    {
        if (index == 0) return nullptr;
        const char* p = reinterpret_cast<const char*>(str_area);
        const char* end = p + str_area_len;
        for (UCHAR i = 1; i < index; ++i) {
            while (p < end && *p) ++p;
            if (p < end) ++p;
            if (p >= end) return nullptr;
        }
        if (p < end && *p) return p;
        return nullptr;
    }

    static NTSTATUS collect_smbios_uuid(PUCHAR out_buf, ULONG out_cap, PULONG out_len)
    {
        *out_len = 0;
        PUCHAR raw = nullptr;
        ULONG raw_len = 0;
        NTSTATUS status = read_smbios_table(&raw, &raw_len);
        if (!NT_SUCCESS(status)) return status;
        if (raw_len < 8) {
            ExFreePoolWithTag(raw, kPoolTag);
            return STATUS_UNSUCCESSFUL;
        }
        const UCHAR* tbl = raw + 8;
        SIZE_T tbl_len = raw_len - 8;
        const UCHAR* fixed = nullptr;
        UCHAR fixed_len = 0;
        const UCHAR* strings = nullptr;
        SIZE_T strings_len = 0;
        BOOLEAN found = find_smbios_structure(tbl, tbl_len, 1, &fixed, &fixed_len,
                                              &strings, &strings_len);
        if (!found || fixed_len < 24) {
            ExFreePoolWithTag(raw, kPoolTag);
            return STATUS_NOT_FOUND;
        }
        UCHAR uuid[16];
        RtlCopyMemory(uuid, fixed + 8, 16);
        BOOLEAN all_zero = TRUE;
        BOOLEAN all_ff = TRUE;
        for (int i = 0; i < 16; ++i) {
            if (uuid[i] != 0x00) all_zero = FALSE;
            if (uuid[i] != 0xFF) all_ff = FALSE;
        }
        if (all_zero || all_ff) {
            ExFreePoolWithTag(raw, kPoolTag);
            return STATUS_NOT_FOUND;
        }
        SIZE_T w = format_uuid_lowercase(uuid, out_buf, out_cap);
        ExFreePoolWithTag(raw, kPoolTag);
        if (w == 0) return STATUS_BUFFER_TOO_SMALL;
        *out_len = static_cast<ULONG>(w);
        return STATUS_SUCCESS;
    }

    static NTSTATUS collect_smbios_string_factor(UCHAR target_type, UCHAR string_offset_in_fixed,
                                                 PUCHAR out_buf, ULONG out_cap, PULONG out_len)
    {
        *out_len = 0;
        PUCHAR raw = nullptr;
        ULONG raw_len = 0;
        NTSTATUS status = read_smbios_table(&raw, &raw_len);
        if (!NT_SUCCESS(status)) return status;
        if (raw_len < 8) {
            ExFreePoolWithTag(raw, kPoolTag);
            return STATUS_UNSUCCESSFUL;
        }
        const UCHAR* tbl = raw + 8;
        SIZE_T tbl_len = raw_len - 8;
        const UCHAR* fixed = nullptr;
        UCHAR fixed_len = 0;
        const UCHAR* strings = nullptr;
        SIZE_T strings_len = 0;
        BOOLEAN found = find_smbios_structure(tbl, tbl_len, target_type, &fixed, &fixed_len,
                                              &strings, &strings_len);
        if (!found || fixed_len <= string_offset_in_fixed) {
            ExFreePoolWithTag(raw, kPoolTag);
            return STATUS_NOT_FOUND;
        }
        UCHAR idx = fixed[string_offset_in_fixed];
        const char* s = smbios_string_at(strings, strings_len, idx);
        if (!s) {
            ExFreePoolWithTag(raw, kPoolTag);
            return STATUS_NOT_FOUND;
        }
        SIZE_T sl = 0;
        while (s[sl] != 0 && sl < 256) ++sl;
        UCHAR tmp[256];
        SIZE_T n = normalize_serial_factor(reinterpret_cast<const UCHAR*>(s), sl, tmp, sizeof(tmp));
        ExFreePoolWithTag(raw, kPoolTag);
        if (n == 0 || n > out_cap) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(out_buf, tmp, n);
        *out_len = static_cast<ULONG>(n);
        return STATUS_SUCCESS;
    }

    static NTSTATUS open_device_by_name(const wchar_t* name, PFILE_OBJECT* out_file,
                                        PDEVICE_OBJECT* out_dev)
    {
        UNICODE_STRING dev_name;
        RtlInitUnicodeString(&dev_name, name);
        return IoGetDeviceObjectPointer(&dev_name, FILE_READ_DATA, out_file, out_dev);
    }

    static NTSTATUS forward_ioctl_buffered(PDEVICE_OBJECT dev, ULONG ioctl,
                                           PVOID in_buf, ULONG in_len,
                                           PVOID out_buf, ULONG out_len,
                                           PULONG out_returned)
    {
        if (out_returned) *out_returned = 0;
        KEVENT event;
        KeInitializeEvent(&event, NotificationEvent, FALSE);
        IO_STATUS_BLOCK iosb = { 0 };
        PIRP irp = IoBuildDeviceIoControlRequest(
            ioctl, dev, in_buf, in_len, out_buf, out_len,
            FALSE, &event, &iosb);
        if (!irp) return STATUS_INSUFFICIENT_RESOURCES;
        NTSTATUS status = IoCallDriver(dev, irp);
        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, nullptr);
            status = iosb.Status;
        }
        if (NT_SUCCESS(status) && out_returned) {
            *out_returned = static_cast<ULONG>(iosb.Information);
        }
        return status;
    }

    static NTSTATUS collect_disk_serial(PUCHAR out_buf, ULONG out_cap, PULONG out_len)
    {
        *out_len = 0;
        PFILE_OBJECT fileobj = nullptr;
        PDEVICE_OBJECT devobj = nullptr;
        NTSTATUS status = open_device_by_name(L"\\Device\\Harddisk0\\DR0", &fileobj, &devobj);
        if (!NT_SUCCESS(status)) {
            status = open_device_by_name(L"\\Device\\Harddisk0\\Partition0", &fileobj, &devobj);
        }
        if (!NT_SUCCESS(status)) return status;

        STORAGE_PROPERTY_QUERY q = { 0 };
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;
        ULONG out_size = 2048;
        PUCHAR buf = reinterpret_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, out_size, kPoolTag));
        if (!buf) {
            ObDereferenceObject(fileobj);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ULONG returned = 0;
        status = forward_ioctl_buffered(devobj, IOCTL_STORAGE_QUERY_PROPERTY,
                                        &q, sizeof(q),
                                        buf, out_size, &returned);
        ObDereferenceObject(fileobj);
        if (!NT_SUCCESS(status) || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            ExFreePoolWithTag(buf, kPoolTag);
            return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
        }
        STORAGE_DEVICE_DESCRIPTOR* desc =
            reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf);
        if (desc->SerialNumberOffset == 0 ||
            desc->SerialNumberOffset >= returned) {
            ExFreePoolWithTag(buf, kPoolTag);
            return STATUS_NOT_FOUND;
        }
        const char* raw_serial =
            reinterpret_cast<const char*>(buf + desc->SerialNumberOffset);
        SIZE_T max_serial = returned - desc->SerialNumberOffset;
        SIZE_T actual = 0;
        while (actual < max_serial && raw_serial[actual] != 0) ++actual;
        if (actual == 0) {
            ExFreePoolWithTag(buf, kPoolTag);
            return STATUS_NOT_FOUND;
        }
        UCHAR tmp[256];
        SIZE_T n = normalize_serial_factor(reinterpret_cast<const UCHAR*>(raw_serial),
                                           actual, tmp, sizeof(tmp));
        ExFreePoolWithTag(buf, kPoolTag);
        if (n == 0 || n > out_cap) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(out_buf, tmp, n);
        *out_len = static_cast<ULONG>(n);
        return STATUS_SUCCESS;
    }

    static NTSTATUS collect_cpuid_brand(PUCHAR out_buf, ULONG out_cap, PULONG out_len)
    {
        *out_len = 0;
        int info[4] = { 0 };
        __cpuid(info, 0x80000000);
        if (static_cast<ULONG>(info[0]) < 0x80000004u) return STATUS_NOT_FOUND;
        char brand[49];
        RtlZeroMemory(brand, sizeof(brand));
        __cpuid(reinterpret_cast<int*>(brand + 0),  0x80000002);
        __cpuid(reinterpret_cast<int*>(brand + 16), 0x80000003);
        __cpuid(reinterpret_cast<int*>(brand + 32), 0x80000004);
        brand[48] = 0;
        SIZE_T sl = 0;
        while (brand[sl] != 0 && sl < 48) ++sl;
        UCHAR tmp[64];
        SIZE_T n = normalize_string_factor(reinterpret_cast<const UCHAR*>(brand), sl, tmp, sizeof(tmp));
        if (n == 0 || n > out_cap) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(out_buf, tmp, n);
        *out_len = static_cast<ULONG>(n);
        return STATUS_SUCCESS;
    }

    static NTSTATUS read_registry_string(const wchar_t* full_path, const wchar_t* value_name,
                                         wchar_t* out_buf, ULONG out_cap_chars,
                                         PULONG out_chars_used)
    {
        *out_chars_used = 0;
        UNICODE_STRING key_path;
        RtlInitUnicodeString(&key_path, full_path);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &key_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   nullptr, nullptr);
        HANDLE key = nullptr;
        NTSTATUS status = ZwOpenKey(&key, KEY_READ, &oa);
        if (!NT_SUCCESS(status)) return status;
        UNICODE_STRING value_us;
        RtlInitUnicodeString(&value_us, value_name);
        ULONG req = 0;
        status = ZwQueryValueKey(key, &value_us, KeyValuePartialInformation,
                                 nullptr, 0, &req);
        if (req == 0) {
            ZwClose(key);
            return STATUS_NOT_FOUND;
        }
        PKEY_VALUE_PARTIAL_INFORMATION info =
            reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, req, kPoolTag));
        if (!info) {
            ZwClose(key);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ULONG got = 0;
        status = ZwQueryValueKey(key, &value_us, KeyValuePartialInformation,
                                 info, req, &got);
        ZwClose(key);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(info, kPoolTag);
            return status;
        }
        if (info->Type != REG_SZ && info->Type != REG_EXPAND_SZ) {
            ExFreePoolWithTag(info, kPoolTag);
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        const wchar_t* src = reinterpret_cast<const wchar_t*>(info->Data);
        ULONG chars = info->DataLength / sizeof(wchar_t);
        while (chars > 0 && src[chars - 1] == L'\0') --chars;
        if (chars == 0 || chars >= out_cap_chars) {
            ExFreePoolWithTag(info, kPoolTag);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(out_buf, src, chars * sizeof(wchar_t));
        out_buf[chars] = 0;
        *out_chars_used = chars;
        ExFreePoolWithTag(info, kPoolTag);
        return STATUS_SUCCESS;
    }

    static SIZE_T wide_to_ascii(const wchar_t* in, SIZE_T in_chars, UCHAR* out, SIZE_T out_cap)
    {
        SIZE_T w = 0;
        for (SIZE_T i = 0; i < in_chars && w < out_cap; ++i) {
            wchar_t c = in[i];
            if (c > 0x7E || c < 0x20) continue;
            out[w++] = static_cast<UCHAR>(c & 0xFF);
        }
        return w;
    }

    static NTSTATUS collect_machine_guid(PUCHAR out_buf, ULONG out_cap, PULONG out_len)
    {
        *out_len = 0;
        wchar_t buf[256];
        ULONG chars = 0;
        NTSTATUS status = read_registry_string(
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid", buf, 256, &chars);
        if (!NT_SUCCESS(status)) return status;
        UCHAR ascii[256];
        SIZE_T ac = wide_to_ascii(buf, chars, ascii, sizeof(ascii));
        if (ac == 0) return STATUS_NOT_FOUND;
        UCHAR tmp[256];
        SIZE_T n = trim_and_collapse(ascii, ac, tmp, sizeof(tmp));
        to_lower_buffer(tmp, n);
        if (n == 0 || n > out_cap) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(out_buf, tmp, n);
        *out_len = static_cast<ULONG>(n);
        return STATUS_SUCCESS;
    }

    static NTSTATUS collect_installation_guid(PUCHAR out_buf, ULONG out_cap, PULONG out_len)
    {
        *out_len = 0;
        wchar_t buf[256];
        ULONG chars = 0;
        NTSTATUS status = read_registry_string(
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"InstallationGUID", buf, 256, &chars);
        if (!NT_SUCCESS(status)) {
            status = read_registry_string(
                L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                L"InstallationID", buf, 256, &chars);
        }
        if (!NT_SUCCESS(status)) {
            status = read_registry_string(
                L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                L"InstallationID", buf, 256, &chars);
        }
        if (!NT_SUCCESS(status)) return status;
        UCHAR ascii[256];
        SIZE_T ac = wide_to_ascii(buf, chars, ascii, sizeof(ascii));
        if (ac == 0) return STATUS_NOT_FOUND;
        UCHAR tmp[256];
        SIZE_T n = trim_and_collapse(ascii, ac, tmp, sizeof(tmp));
        to_lower_buffer(tmp, n);
        if (n == 0 || n > out_cap) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(out_buf, tmp, n);
        *out_len = static_cast<ULONG>(n);
        return STATUS_SUCCESS;
    }

    static BOOLEAN tpm_kernel_device_present()
    {
        const wchar_t* candidates[] = {
            L"\\Device\\TPM",
            L"\\Device\\Tpm",
            L"\\Device\\TcgTpm",
        };
        for (int i = 0; i < 3; ++i) {
            UNICODE_STRING us;
            RtlInitUnicodeString(&us, candidates[i]);
            PFILE_OBJECT fileobj = nullptr;
            PDEVICE_OBJECT devobj = nullptr;
            NTSTATUS status = IoGetDeviceObjectPointer(&us, FILE_READ_DATA, &fileobj, &devobj);
            if (NT_SUCCESS(status)) {
                ObDereferenceObject(fileobj);
                return TRUE;
            }
        }
        return FALSE;
    }

    static NTSTATUS collect_tpm_ek_sha256_factor(PUCHAR out_buf, ULONG out_cap,
                                                 PULONG out_len, PBOOLEAN out_present)
    {
        *out_present = FALSE;
        const char* literal = "no_tpm";
        if (out_cap < 6) return STATUS_BUFFER_TOO_SMALL;
        if (tpm_kernel_device_present()) {
            RtlCopyMemory(out_buf, literal, 6);
            *out_len = 6;
            *out_present = FALSE;
            return STATUS_SUCCESS;
        }
        RtlCopyMemory(out_buf, literal, 6);
        *out_len = 6;
        return STATUS_SUCCESS;
    }

    static void compute_factor_hash(const UCHAR* data, ULONG len, UCHAR out[32])
    {
        kernel_crypto::sw_sha256(data, len, out);
    }

    static void compute_hwid_hash(PUCHAR factor_bufs[], const ULONG factor_lens[],
                                  UCHAR out[32])
    {
        kernel_crypto::sha256_ctx_t ctx;
        kernel_crypto::sha256_init(&ctx);
        UCHAR hdr[4];
        hdr[0] = static_cast<UCHAR>(kHwidVersion & 0xFF);
        hdr[1] = static_cast<UCHAR>((kHwidVersion >> 8) & 0xFF);
        hdr[2] = static_cast<UCHAR>((kHwidVersion >> 16) & 0xFF);
        hdr[3] = static_cast<UCHAR>((kHwidVersion >> 24) & 0xFF);
        kernel_crypto::sha256_update(&ctx, hdr, 4);
        for (ULONG i = 0; i < kFactorCount; ++i) {
            ULONG flen = factor_lens[i];
            UCHAR len_le[2];
            UCHAR len_lo = static_cast<UCHAR>(flen & 0xFF);
            UCHAR len_hi = static_cast<UCHAR>((flen >> 8) & 0xFF);
            len_le[0] = len_lo;
            len_le[1] = len_hi;
            kernel_crypto::sha256_update(&ctx, len_le, 2);
            if (flen > 0) {
                kernel_crypto::sha256_update(&ctx, factor_bufs[i], flen);
            }
        }
        kernel_crypto::sha256_final(&ctx, out);
    }

    static NTSTATUS generate_session_secret()
    {
        LARGE_INTEGER tsc1;
        LARGE_INTEGER tsc2;
        LARGE_INTEGER perf;
        LARGE_INTEGER perf_freq;
        LARGE_INTEGER systime;
        UCHAR mix[256];
        RtlZeroMemory(mix, sizeof(mix));
        ULONG off = 0;
        tsc1.QuadPart = static_cast<LONGLONG>(__rdtsc());
        RtlCopyMemory(mix + off, &tsc1, sizeof(tsc1));
        off += sizeof(tsc1);
        perf = KeQueryPerformanceCounter(&perf_freq);
        RtlCopyMemory(mix + off, &perf, sizeof(perf));
        off += sizeof(perf);
        RtlCopyMemory(mix + off, &perf_freq, sizeof(perf_freq));
        off += sizeof(perf_freq);
        KeQuerySystemTime(&systime);
        RtlCopyMemory(mix + off, &systime, sizeof(systime));
        off += sizeof(systime);
        for (int i = 0; i < 8; ++i) {
            ULONG seed = static_cast<ULONG>(__rdtsc()) ^ static_cast<ULONG>(systime.LowPart) ^ (i * 0x9E3779B9u);
            ULONG r = RtlRandomEx(&seed);
            RtlCopyMemory(mix + off, &r, sizeof(r));
            off += sizeof(r);
            YieldProcessor();
        }
        tsc2.QuadPart = static_cast<LONGLONG>(__rdtsc());
        RtlCopyMemory(mix + off, &tsc2, sizeof(tsc2));
        off += sizeof(tsc2);
        PVOID stack_addr = &mix;
        RtlCopyMemory(mix + off, &stack_addr, sizeof(stack_addr));
        off += sizeof(stack_addr);
        kernel_crypto::sw_sha256(mix, off, g_session_secret);
        RtlSecureZeroMemory(mix, sizeof(mix));
        return STATUS_SUCCESS;
    }
}

NTSTATUS HardwareIdInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (InterlockedCompareExchange(&hardware_id_kernel::g_initialized, 1, 0) != 0) {
        return STATUS_SUCCESS;
    }
    return hardware_id_kernel::generate_session_secret();
}

VOID HardwareIdShutdown(VOID)
{
    RtlSecureZeroMemory(hardware_id_kernel::g_session_secret,
                        sizeof(hardware_id_kernel::g_session_secret));
    InterlockedExchange(&hardware_id_kernel::g_initialized, 0);
}

NTSTATUS HardwareIdGetSessionSecret(_Out_writes_bytes_(32) PUCHAR OutSecret)
{
    if (!OutSecret) return STATUS_INVALID_PARAMETER;
    if (hardware_id_kernel::g_initialized == 0) return STATUS_DEVICE_NOT_READY;
    RtlCopyMemory(OutSecret, hardware_id_kernel::g_session_secret, 32);
    return STATUS_SUCCESS;
}

NTSTATUS HardwareIdHandleIoctl(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IoStack)
{
    if (!Irp || !IoStack) return STATUS_INVALID_PARAMETER;
    Irp->IoStatus.Information = 0;
    if (hardware_id_kernel::g_initialized == 0) {
        NTSTATUS init_st = HardwareIdInitialize(nullptr);
        if (!NT_SUCCESS(init_st)) return init_st;
    }
    ULONG output_size = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (output_size < sizeof(AIDA_HWID_REPLY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    PVOID system_buf = Irp->AssociatedIrp.SystemBuffer;
    if (!system_buf) return STATUS_INVALID_PARAMETER;

    PAIDA_HWID_REPLY reply = static_cast<PAIDA_HWID_REPLY>(system_buf);
    RtlZeroMemory(reply, sizeof(AIDA_HWID_REPLY));

    constexpr ULONG kPerFactorCap = 96;
    PUCHAR factor_bufs[hardware_id_kernel::kFactorCount];
    ULONG  factor_lens[hardware_id_kernel::kFactorCount] = { 0 };
    for (ULONG i = 0; i < hardware_id_kernel::kFactorCount; ++i) {
        factor_bufs[i] = reinterpret_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, kPerFactorCap, hardware_id_kernel::kPoolTag));
        if (!factor_bufs[i]) {
            for (ULONG j = 0; j < i; ++j) {
                if (factor_bufs[j]) {
                    RtlSecureZeroMemory(factor_bufs[j], kPerFactorCap);
                    ExFreePoolWithTag(factor_bufs[j], hardware_id_kernel::kPoolTag);
                    factor_bufs[j] = nullptr;
                }
            }
            RtlZeroMemory(reply, sizeof(AIDA_HWID_REPLY));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    BOOLEAN tpm_present = FALSE;
    ULONG mask = 0;

    if (NT_SUCCESS(hardware_id_kernel::collect_smbios_uuid(factor_bufs[0], kPerFactorCap, &factor_lens[0])))
        mask |= (1u << 0);
    if (NT_SUCCESS(hardware_id_kernel::collect_smbios_string_factor(2, 0x07, factor_bufs[1], kPerFactorCap, &factor_lens[1])))
        mask |= (1u << 1);
    if (NT_SUCCESS(hardware_id_kernel::collect_smbios_string_factor(3, 0x07, factor_bufs[2], kPerFactorCap, &factor_lens[2])))
        mask |= (1u << 2);
    if (NT_SUCCESS(hardware_id_kernel::collect_disk_serial(factor_bufs[3], kPerFactorCap, &factor_lens[3])))
        mask |= (1u << 3);
    if (NT_SUCCESS(hardware_id_kernel::collect_cpuid_brand(factor_bufs[5], kPerFactorCap, &factor_lens[5])))
        mask |= (1u << 5);
    if (NT_SUCCESS(hardware_id_kernel::collect_machine_guid(factor_bufs[6], kPerFactorCap, &factor_lens[6])))
        mask |= (1u << 6);
    if (NT_SUCCESS(hardware_id_kernel::collect_installation_guid(factor_bufs[7], kPerFactorCap, &factor_lens[7])))
        mask |= (1u << 7);
    if (NT_SUCCESS(hardware_id_kernel::collect_tpm_ek_sha256_factor(factor_bufs[8], kPerFactorCap, &factor_lens[8], &tpm_present))) {
        mask |= (1u << 8);
    }

    UCHAR factor_hashes[hardware_id_kernel::kFactorCount][32];
    RtlZeroMemory(factor_hashes, sizeof(factor_hashes));
    for (ULONG i = 0; i < hardware_id_kernel::kFactorCount; ++i) {
        if (factor_lens[i] > 0) {
            hardware_id_kernel::compute_factor_hash(factor_bufs[i], factor_lens[i],
                                                    factor_hashes[i]);
        }
    }

    UCHAR hwid_hash[32];
    hardware_id_kernel::compute_hwid_hash(factor_bufs, factor_lens, hwid_hash);

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LARGE_INTEGER nonce;
    nonce.QuadPart = static_cast<LONGLONG>(__rdtsc());

    reply->magic = AIDA_HWID_REPLY_MAGIC;
    reply->version = hardware_id_kernel::kHwidVersion;
    RtlCopyMemory(reply->hwid_hash, hwid_hash, 32);
    RtlCopyMemory(reply->factor_hashes, factor_hashes, sizeof(factor_hashes));
    reply->factor_present_mask = mask;
    reply->reserved0 = 0;
    reply->timestamp = now;
    reply->nonce = nonce;

    UCHAR hmac_input[64 + 32 * hardware_id_kernel::kFactorCount + sizeof(LARGE_INTEGER) * 2 + 8];
    ULONG hi = 0;
    RtlCopyMemory(hmac_input + hi, hwid_hash, 32);
    hi += 32;
    RtlCopyMemory(hmac_input + hi, factor_hashes, sizeof(factor_hashes));
    hi += sizeof(factor_hashes);
    RtlCopyMemory(hmac_input + hi, &now, sizeof(now));
    hi += sizeof(now);
    RtlCopyMemory(hmac_input + hi, &nonce, sizeof(nonce));
    hi += sizeof(nonce);
    UCHAR mask_le[4];
    mask_le[0] = static_cast<UCHAR>(mask & 0xFF);
    mask_le[1] = static_cast<UCHAR>((mask >> 8) & 0xFF);
    mask_le[2] = static_cast<UCHAR>((mask >> 16) & 0xFF);
    mask_le[3] = static_cast<UCHAR>((mask >> 24) & 0xFF);
    RtlCopyMemory(hmac_input + hi, mask_le, 4);
    hi += 4;

    kernel_crypto::sw_hmac_sha256(
        hardware_id_kernel::g_session_secret, 32,
        hmac_input, hi,
        reply->hmac_signature);

    for (ULONG i = 0; i < hardware_id_kernel::kFactorCount; ++i) {
        if (factor_bufs[i]) {
            RtlSecureZeroMemory(factor_bufs[i], kPerFactorCap);
            ExFreePoolWithTag(factor_bufs[i], hardware_id_kernel::kPoolTag);
            factor_bufs[i] = nullptr;
        }
    }
    RtlSecureZeroMemory(hmac_input, sizeof(hmac_input));

    Irp->IoStatus.Information = sizeof(AIDA_HWID_REPLY);
    return STATUS_SUCCESS;
}
