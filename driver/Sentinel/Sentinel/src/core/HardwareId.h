#pragma once

#include <ntddk.h>
#include <ntddstor.h>
#include <intrin.h>
#include <bcrypt.h>
#include <imports/Defs.h>

namespace hardware_id
{
    struct hw_anchors_t
    {
        UINT8  smbios_uuid[16];
        CHAR   baseboard_serial[64];
        CHAR   disk_serial[64];
        CHAR   machine_guid[64];
        UINT8  mac_addr[6];
        UINT64 cpu_topology;
        ULONG  volume_serial;
        ULONG  anchor_status;
        ULONG  anchor_build;
        UINT8  composite_sha256[32];
    };

    inline hw_anchors_t g_anchors = {};
    inline BOOLEAN g_anchors_valid = FALSE;

    enum : ULONG
    {
        ANCHOR_SMBIOS_OK = 0x00000001u,
        ANCHOR_DISK_OK = 0x00000002u,
        ANCHOR_DISK_SKIPPED = 0x00000004u,
        ANCHOR_MACHINE_GUID_OK = 0x00000008u,
        ANCHOR_VOLUME_OK = 0x00000010u,
        ANCHOR_VOLUME_SKIPPED = 0x00000020u,
        ANCHOR_STORAGE_OPEN_GATED = 0x00000040u
    };

    __forceinline ULONG kernel_build_number()
    {
        ULONG value = 0;
        __try {
            volatile ULONG* ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000000ULL + 0x260);
            value = *ptr;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            value = 0;
        }
        return value & 0xFFFFu;
    }

    __forceinline BOOLEAN skip_storage_device_open()
    {
        return kernel_build_number() >= 26100;
    }

    __forceinline ULONG build_anchor_status(NTSTATUS smbios_status, NTSTATUS disk_status, NTSTATUS machine_guid_status, NTSTATUS volume_status)
    {
        ULONG status = 0;
        BOOLEAN storage_gate = skip_storage_device_open();
        if (NT_SUCCESS(smbios_status))
            status |= ANCHOR_SMBIOS_OK;
        if (NT_SUCCESS(disk_status))
            status |= ANCHOR_DISK_OK;
        else if (storage_gate && disk_status == STATUS_NOT_SUPPORTED)
            status |= ANCHOR_DISK_SKIPPED;
        if (NT_SUCCESS(machine_guid_status))
            status |= ANCHOR_MACHINE_GUID_OK;
        if (NT_SUCCESS(volume_status))
            status |= ANCHOR_VOLUME_OK;
        else if (storage_gate && volume_status == STATUS_NOT_SUPPORTED)
            status |= ANCHOR_VOLUME_SKIPPED;
        if (storage_gate)
            status |= ANCHOR_STORAGE_OPEN_GATED;
        return status;
    }

    __forceinline UINT64 collect_cpu_topology()
    {
        int info[4] = {};
        UINT64 result = 0;

        __cpuid(info, 0);
        result ^= static_cast<UINT64>(info[1]) | (static_cast<UINT64>(info[2]) << 32);

        __cpuid(info, 1);
        result ^= static_cast<UINT64>(info[0]) | (static_cast<UINT64>(info[3]) << 32);

        __cpuid(info, 7);
        result ^= static_cast<UINT64>(info[1]) ^ (static_cast<UINT64>(info[2]) << 16);

        __cpuidex(info, 0x80000008, 0);
        result ^= static_cast<UINT64>(info[0]);

        return result;
    }

    __forceinline NTSTATUS collect_smbios(UINT8* uuid_out, CHAR* baseboard_out, SIZE_T bb_max)
    {
        ULONG required = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(76),
            nullptr, 0, &required);
        if (status != STATUS_INFO_LENGTH_MISMATCH || required == 0)
            return STATUS_UNSUCCESSFUL;

        struct SYSTEM_FIRMWARE_TABLE_INFORMATION {
            ULONG  ProviderSignature;
            ULONG  Action;
            ULONG  TableID;
            ULONG  TableBufferLength;
            UCHAR  TableBuffer[1];
        };

        const ULONG alloc_size = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) + required;
        auto* info = static_cast<SYSTEM_FIRMWARE_TABLE_INFORMATION*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, 'smbi'));
        if (!info) return STATUS_INSUFFICIENT_RESOURCES;

        info->ProviderSignature = 'RSMB';
        info->Action = 1;
        info->TableID = 0;
        info->TableBufferLength = required;

        status = ZwQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(76),
            info, alloc_size, &required);

        if (NT_SUCCESS(status))
        {
            UCHAR* raw = info->TableBuffer;
            ULONG  raw_len = info->TableBufferLength;

            if (raw_len > 8) raw += 8;
            ULONG pos = 0;
            BOOLEAN found_uuid = FALSE, found_bb = FALSE;

            while (pos + 4 < raw_len && (!found_uuid || !found_bb))
            {
                UINT8 type = raw[pos];
                UINT8 length = raw[pos + 1];
                if (length < 4 || pos + length > raw_len) break;

                if (type == 1 && length >= 25 && !found_uuid)
                {
                    RtlCopyMemory(uuid_out, &raw[pos + 8], 16);
                    found_uuid = TRUE;
                }

                if (type == 2 && !found_bb)
                {
                    UINT8 serial_idx = (length > 7) ? raw[pos + 7] : 0;
                    if (serial_idx > 0)
                    {
                        ULONG str_pos = pos + length;
                        UINT8 cur_str = 1;
                        while (str_pos < raw_len)
                        {
                            if (cur_str == serial_idx)
                            {
                                SIZE_T slen = 0;
                                while (str_pos + slen < raw_len && raw[str_pos + slen] != 0 && slen < bb_max - 1)
                                    ++slen;
                                RtlCopyMemory(baseboard_out, &raw[str_pos], slen);
                                baseboard_out[slen] = 0;
                                found_bb = TRUE;
                                break;
                            }
                            while (str_pos < raw_len && raw[str_pos] != 0) ++str_pos;
                            ++str_pos;
                            ++cur_str;
                        }
                    }
                }

                ULONG next = pos + length;
                while (next + 1 < raw_len && (raw[next] != 0 || raw[next + 1] != 0)) ++next;
                pos = next + 2;
            }
        }

        ExFreePoolWithTag(info, 'smbi');
        return status;
    }

    __forceinline NTSTATUS collect_disk_serial(CHAR* serial_out, SIZE_T max_len)
    {
        ULONG build = kernel_build_number();
        if (skip_storage_device_open()) {
            SN_LOG("hardware_id: disk_serial_skipped_build_gate build=%lu device=\\\\Device\\\\Harddisk0\\\\DR0", build);
            return STATUS_NOT_SUPPORTED;
        }

        UNICODE_STRING dev_name;
        RtlInitUnicodeString(&dev_name, L"\\Device\\Harddisk0\\DR0");

        PFILE_OBJECT file_obj = nullptr;
        PDEVICE_OBJECT dev_obj = nullptr;
        NTSTATUS status = IoGetDeviceObjectPointer(&dev_name, FILE_READ_DATA, &file_obj, &dev_obj);
        if (!NT_SUCCESS(status)) return status;

        const ULONG buf_size = sizeof(STORAGE_DEVICE_DESCRIPTOR) + 256;
        auto* buf = static_cast<UINT8*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, buf_size, 'dskS'));
        if (!buf) { ObDereferenceObject(file_obj); return STATUS_INSUFFICIENT_RESOURCES; }

        auto* query = static_cast<STORAGE_PROPERTY_QUERY*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(STORAGE_PROPERTY_QUERY), 'dskQ'));
        if (!query) { ExFreePoolWithTag(buf, 'dskS'); ObDereferenceObject(file_obj); return STATUS_INSUFFICIENT_RESOURCES; }

        query->PropertyId = StorageDeviceProperty;
        query->QueryType = PropertyStandardQuery;

        KEVENT event;
        KeInitializeEvent(&event, NotificationEvent, FALSE);
        IO_STATUS_BLOCK iosb = {};
        PIRP irp = IoBuildDeviceIoControlRequest(
            IOCTL_STORAGE_QUERY_PROPERTY,
            dev_obj, query, sizeof(STORAGE_PROPERTY_QUERY),
            buf, buf_size, FALSE, &event, &iosb);

        if (irp)
        {
            status = IoCallDriver(dev_obj, irp);
            if (status == STATUS_PENDING)
            {
                KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, nullptr);
                status = iosb.Status;
            }
            if (NT_SUCCESS(status))
            {
                auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf);
                if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < buf_size)
                {
                    const char* src = reinterpret_cast<const char*>(buf + desc->SerialNumberOffset);
                    SIZE_T slen = 0;
                    while (slen < max_len - 1 && src[slen] != 0) ++slen;
                    RtlCopyMemory(serial_out, src, slen);
                    serial_out[slen] = 0;
                }
            }
        }
        else
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        ExFreePoolWithTag(query, 'dskQ');
        ExFreePoolWithTag(buf, 'dskS');
        ObDereferenceObject(file_obj);
        return status;
    }

    __forceinline NTSTATUS collect_machine_guid(CHAR* guid_out, SIZE_T max_len)
    {
        UNICODE_STRING key_path;
        RtlInitUnicodeString(&key_path, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &key_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE hkey = nullptr;
        NTSTATUS status = ZwOpenKey(&hkey, KEY_READ, &oa);
        if (!NT_SUCCESS(status)) return status;

        UNICODE_STRING val_name;
        RtlInitUnicodeString(&val_name, L"MachineGuid");

        const ULONG info_size = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 128;
        auto* vinfo = static_cast<KEY_VALUE_PARTIAL_INFORMATION*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, info_size, 'mgid'));
        if (!vinfo) { ZwClose(hkey); return STATUS_INSUFFICIENT_RESOURCES; }

        ULONG result_len = 0;
        status = ZwQueryValueKey(hkey, &val_name, KeyValuePartialInformation, vinfo, info_size, &result_len);
        if (NT_SUCCESS(status) && vinfo->Type == REG_SZ && vinfo->DataLength > 0)
        {
            UNICODE_STRING wide_guid;
            wide_guid.Buffer = reinterpret_cast<PWCH>(vinfo->Data);
            wide_guid.Length = static_cast<USHORT>(vinfo->DataLength) - sizeof(WCHAR);
            wide_guid.MaximumLength = wide_guid.Length;

            ANSI_STRING ansi;
            ansi.Buffer = guid_out;
            ansi.Length = 0;
            ansi.MaximumLength = static_cast<USHORT>(max_len);
            RtlUnicodeStringToAnsiString(&ansi, &wide_guid, FALSE);
        }

        ExFreePoolWithTag(vinfo, 'mgid');
        ZwClose(hkey);
        return status;
    }

    __forceinline NTSTATUS collect_volume_serial(ULONG* serial_out)
    {
        ULONG build = kernel_build_number();
        if (skip_storage_device_open()) {
            SN_LOG("hardware_id: volume_serial_skipped_build_gate build=%lu device=\\\\DosDevices\\\\C:", build);
            return STATUS_NOT_SUPPORTED;
        }

        UNICODE_STRING vol_name;
        RtlInitUnicodeString(&vol_name, L"\\DosDevices\\C:");

        PFILE_OBJECT file_obj = nullptr;
        PDEVICE_OBJECT dev_obj = nullptr;
        NTSTATUS status = IoGetDeviceObjectPointer(&vol_name, FILE_READ_ATTRIBUTES, &file_obj, &dev_obj);
        if (!NT_SUCCESS(status)) return status;

        const ULONG buf_size = sizeof(FILE_FS_VOLUME_INFORMATION) + 128;
        auto* vol_info = static_cast<FILE_FS_VOLUME_INFORMATION*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, buf_size, 'volS'));
        if (!vol_info) { ObDereferenceObject(file_obj); return STATUS_INSUFFICIENT_RESOURCES; }

        KEVENT event;
        KeInitializeEvent(&event, NotificationEvent, FALSE);
        IO_STATUS_BLOCK iosb = {};
        PIRP irp = IoBuildDeviceIoControlRequest(
            0, dev_obj, nullptr, 0, vol_info, buf_size, FALSE, &event, &iosb);

        if (!irp) {
            ExFreePoolWithTag(vol_info, 'volS');
            ObDereferenceObject(file_obj);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        auto* sp = IoGetNextIrpStackLocation(irp);
        sp->MajorFunction = IRP_MJ_QUERY_VOLUME_INFORMATION;
        sp->Parameters.QueryVolume.FsInformationClass = FileFsVolumeInformation;
        sp->Parameters.QueryVolume.Length = buf_size;

        status = IoCallDriver(dev_obj, irp);
        if (status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, nullptr);
            status = iosb.Status;
        }
        if (NT_SUCCESS(status))
            *serial_out = vol_info->VolumeSerialNumber;

        ExFreePoolWithTag(vol_info, 'volS');
        ObDereferenceObject(file_obj);
        return status;
    }

    __forceinline void sha256_simple(const UINT8* data, ULONG len, UINT8* hash_out)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            return;

        BCRYPT_HASH_HANDLE hh = nullptr;
        if (NT_SUCCESS(BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0)))
        {
            BCryptHashData(hh, const_cast<UINT8*>(data), len, 0);
            BCryptFinishHash(hh, hash_out, 32, 0);
            BCryptDestroyHash(hh);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    __forceinline BOOLEAN collect_all()
    {
        RtlZeroMemory(&g_anchors, sizeof(g_anchors));

        NTSTATUS smbios_status = collect_smbios(g_anchors.smbios_uuid, g_anchors.baseboard_serial, sizeof(g_anchors.baseboard_serial));
        NTSTATUS disk_status = collect_disk_serial(g_anchors.disk_serial, sizeof(g_anchors.disk_serial));
        NTSTATUS machine_guid_status = collect_machine_guid(g_anchors.machine_guid, sizeof(g_anchors.machine_guid));
        NTSTATUS volume_status = collect_volume_serial(&g_anchors.volume_serial);
        g_anchors.cpu_topology = collect_cpu_topology();
        g_anchors.anchor_build = kernel_build_number();
        g_anchors.anchor_status = build_anchor_status(smbios_status, disk_status, machine_guid_status, volume_status);
        SN_LOG("hardware_id::collect_all statuses build=%lu smbios=0x%08lx disk=0x%08lx machine_guid=0x%08lx volume=0x%08lx cpu_topology=0x%llx storage_gate=%u",
            g_anchors.anchor_build,
            smbios_status,
            disk_status,
            machine_guid_status,
            volume_status,
            static_cast<unsigned long long>(g_anchors.cpu_topology),
            skip_storage_device_open() ? 1u : 0u);
        SN_LOG("hardware_id::collect_all anchor_status=0x%08lx anchor_build=%lu", g_anchors.anchor_status, g_anchors.anchor_build);

        UINT8 concat[16 + 64 + 64 + 64 + 6 + 8 + 4 + 4 + 4];
        ULONG offset = 0;

        RtlCopyMemory(concat + offset, g_anchors.smbios_uuid, 16); offset += 16;
        RtlCopyMemory(concat + offset, g_anchors.baseboard_serial, 64); offset += 64;
        RtlCopyMemory(concat + offset, g_anchors.disk_serial, 64); offset += 64;
        RtlCopyMemory(concat + offset, g_anchors.machine_guid, 64); offset += 64;
        RtlCopyMemory(concat + offset, g_anchors.mac_addr, 6); offset += 6;
        RtlCopyMemory(concat + offset, &g_anchors.cpu_topology, 8); offset += 8;
        RtlCopyMemory(concat + offset, &g_anchors.volume_serial, 4); offset += 4;
        RtlCopyMemory(concat + offset, &g_anchors.anchor_status, 4); offset += 4;
        RtlCopyMemory(concat + offset, &g_anchors.anchor_build, 4); offset += 4;

        sha256_simple(concat, offset, g_anchors.composite_sha256);
        g_anchors_valid = TRUE;
        return TRUE;
    }
}
