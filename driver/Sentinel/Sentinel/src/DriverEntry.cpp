#include <ntifs.h>
#include <Crypter.h>
#include <imports/Defs.h>
#include <core/Guardian.h>
#include <core/ProcessNotify.h>
#include <core/HardwareId.h>
#include <core/WitnessKey.h>
#include <core/BridgeV2.h>
#include <core/WskTransport.h>
#include <core/Attestation.h>
#include <core/Resurrect.h>
#include <core/DeviceScan.h>
#include <core/EvidenceRing.h>
#include <core/DriverLoadAudit.h>
#include <core/KernelDebugCapture.h>


#pragma data_seg(".sntl")
volatile PVOID  g_target_driver_base   = nullptr;
volatile PVOID  g_target_driver_object = nullptr;
volatile ULONG  g_target_driver_size   = 0;
#pragma data_seg()


#pragma comment(linker, "/SECTION:.sntl,RW")


#ifndef FILE_DISPOSITION_FLAG_DELETE
#define FILE_DISPOSITION_FLAG_DELETE                 0x00000001
#endif
#ifndef FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
#define FILE_DISPOSITION_FLAG_POSIX_SEMANTICS       0x00000002
#endif
#ifndef FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif

static constexpr FILE_INFORMATION_CLASS FileDispositionInformationExClass =
    static_cast<FILE_INFORMATION_CLASS>(64);

constexpr ULONG TAG_DEL = 'leDW';


PDRIVER_OBJECT g_sentinel_driver_object = nullptr;
static volatile LONG  g_shutdown_flag = 0;
static HANDLE         g_init_thread_handle = nullptr;
static WCHAR          g_registry_path_buffer[512] = {};
static UNICODE_STRING g_registry_path = {};

static UINT64 init_handle_to_u64(HANDLE value)
{
    return static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(value));
}

static ULONG init_elapsed_us(const LARGE_INTEGER& start, const LARGE_INTEGER& freq)
{
    LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
    if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
        return 0;
    return static_cast<ULONG>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<ULONGLONG>(freq.QuadPart));
}

static ULONG init_read_kuser_u32(ULONG offset)
{
    ULONG value = 0;
    __try {
        volatile ULONG* ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000000ULL + offset);
        value = *ptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
    }
    return value;
}

static void init_log_driverentry_phase(const char* phase, const LARGE_INTEGER& start, const LARGE_INTEGER& freq)
{
    ULONG build = init_read_kuser_u32(0x260) & 0xFFFFu;
    ULONG ci_options = init_read_kuser_u32(0x3A8);
    SN_LOG("DriverEntryPhase phase=%s elapsed_us=%lu pid=%llu tid=%llu irql=%lu cpu=%lu build=%lu ci_options=0x%08lx hvci=%u ci_enabled=%u target_base=%p target_size=0x%lx target_object=%p bridge=%p",
        phase ? phase : "unknown",
        init_elapsed_us(start, freq),
        init_handle_to_u64(PsGetCurrentProcessId()),
        init_handle_to_u64(PsGetCurrentThreadId()),
        static_cast<ULONG>(KeGetCurrentIrql()),
        KeGetCurrentProcessorNumber(),
        build,
        ci_options,
        (ci_options & hvci_detect::CI_OPTION_HVCI_KMCI_ENABLED) || (ci_options & hvci_detect::CI_OPTION_HVCI_STRICT) ? 1u : 0u,
        (ci_options & 0x1u) ? 1u : 0u,
        (PVOID)g_target_driver_base,
        g_target_driver_size,
        (PVOID)g_target_driver_object,
        heartbeat::g_bridge);
}

static HANDLE init_object_protected_pid()
{
    return reinterpret_cast<HANDLE>(
        _InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&object_guard::g_protected_pid),
            0,
            0));
}

static HANDLE init_notify_protected_pid()
{
    return reinterpret_cast<HANDLE>(
        _InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&process_notify::g_protected_pid),
            0,
            0));
}

static void init_log_session_state(const char* phase)
{
    HANDLE object_pid = init_object_protected_pid();
    HANDLE notify_pid = init_notify_protected_pid();
    LONG heartbeat_initialized = _InterlockedCompareExchange(&heartbeat::g_initialized, 0, 0);
    LONG first_seen = _InterlockedCompareExchange(&heartbeat::g_first_heartbeat_seen, 0, 0);

    SN_LOG("init_thread::session phase=%s active=%u object_protected_pid=%llu notify_protected_pid=%llu heartbeat_initialized=%ld first_seen=%ld target_base=%p target_size=0x%lx bridge=%p shutdown=%ld",
        phase ? phase : "unknown",
        (object_pid || notify_pid) ? 1u : 0u,
        init_handle_to_u64(object_pid),
        init_handle_to_u64(notify_pid),
        heartbeat_initialized,
        first_seen,
        (PVOID)g_target_driver_base,
        g_target_driver_size,
        heartbeat::g_bridge,
        _InterlockedCompareExchange(&g_shutdown_flag, 0, 0));
}

static BOOLEAN init_scan_backoff(const char* phase, UINT64 probes, ULONG module_count, USHORT section_index, ULONG offset)
{
    if (_InterlockedCompareExchange(&g_shutdown_flag, 0, 0)) {
        SN_LOG("init_thread::backoff_cancel phase=%s probes=%llu modules=%lu section=%u offset=0x%lx shutdown=1",
            phase ? phase : "unknown",
            static_cast<unsigned long long>(probes),
            module_count,
            section_index,
            offset);
        return FALSE;
    }

    if (probes <= 16384 || (probes % 65536) == 0) {
        SN_LOG("init_thread::backoff phase=%s probes=%llu modules=%lu section=%u offset=0x%lx object_protected_pid=%llu notify_protected_pid=%llu",
            phase ? phase : "unknown",
            static_cast<unsigned long long>(probes),
            module_count,
            section_index,
            offset,
            init_handle_to_u64(init_object_protected_pid()),
            init_handle_to_u64(init_notify_protected_pid()));
    }

    if (_KeDelayExecutionThread && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        LARGE_INTEGER wait;
        wait.QuadPart = -10000LL;
        _KeDelayExecutionThread(KernelMode, FALSE, &wait);
    } else {
        YieldProcessor();
    }

    return TRUE;
}

static bool find_text_section(PVOID image_base, PVOID* out_base, ULONG* out_size) {
    if (!image_base || !_MmIsAddressValid(image_base))
        return false;

    __try {
        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(image_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(image_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {


            if (sections[i].Name[0] == '.' &&
                sections[i].Name[1] == 't' &&
                sections[i].Name[2] == 'e' &&
                sections[i].Name[3] == 'x' &&
                sections[i].Name[4] == 't') {
                *out_base = static_cast<UCHAR*>(image_base) + sections[i].VirtualAddress;
                *out_size = sections[i].Misc.VirtualSize;
                return true;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return false;
}


static bool find_target_text(PVOID target_base, PVOID* out_text, ULONG* out_text_size) {
    return find_text_section(target_base, out_text, out_text_size);
}


static UINT32 compute_target_device_key() {
    int cpu[4] = {};
    __cpuid(cpu, 0);
    UINT32 h = 0x811C9DC5u;
    h = (h ^ static_cast<UINT32>(cpu[1])) * 0x01000193u;
    h = (h ^ static_cast<UINT32>(cpu[2])) * 0x01000193u;
    h = (h ^ static_cast<UINT32>(cpu[3])) * 0x01000193u;
    __cpuid(cpu, 1);
    h = (h ^ static_cast<UINT32>(cpu[0])) * 0x01000193u;
    h = (h ^ static_cast<UINT32>(cpu[3])) * 0x01000193u;
    volatile UINT32 build = *reinterpret_cast<volatile UINT32*>(0xFFFFF78000000260ULL) & 0xFFFFu;
    h = (h ^ build) * 0x01000193u;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    if (h == 0) h = 1;
    return h;
}

static SIZE_T copy_wstr(WCHAR* dest, SIZE_T dest_count, const WCHAR* src) {
    SIZE_T i = 0;
    while (src[i] && (i + 1) < dest_count) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
    return i;
}

static void append_decimal_suffix(WCHAR* buffer, SIZE_T buffer_count, SIZE_T current_len, UINT32 seed) {
    UINT32 suffix_val = (seed >> 8) % 100;
    if (current_len + 3 >= buffer_count)
        return;

    if (suffix_val >= 10) {
        buffer[current_len] = L'0' + static_cast<WCHAR>((suffix_val / 10) % 10);
        buffer[current_len + 1] = L'0' + static_cast<WCHAR>(suffix_val % 10);
        buffer[current_len + 2] = L'\0';
    } else {
        buffer[current_len] = L'0' + static_cast<WCHAR>(suffix_val);
        buffer[current_len + 1] = L'\0';
    }
}

static BOOLEAN build_target_device_name(WCHAR* buffer, SIZE_T buffer_count) {
    if (!buffer || buffer_count < 32)
        return FALSE;

    static const WCHAR* const bases[] = {
        L"RdpRefMp",
        L"KsecDD",
        L"MountPointManager",
        L"VolumesSafeForWriteAccess",
        L"VolMgrControl",
        L"DeviceApi",
        L"Ucx01000",
        L"USBPDO",
        L"ACPI_HAL",
        L"PnpManager",
        L"WdfLdr",
        L"KernelCng",
        L"WUDFLpcDevice",
        L"DxgKrnl",
        L"NdisCap",
        L"WfpLwfs",
    };

    UINT32 seed = compute_target_device_key();
    seed = (seed * 0x45D9F3Bu) ^ (seed >> 16);
    seed = (seed * 0x1B873593u) ^ (seed >> 13);

    SIZE_T pos = copy_wstr(buffer, buffer_count, L"\\Device\\");
    const WCHAR* base_name = bases[seed % (sizeof(bases) / sizeof(bases[0]))];
    pos += copy_wstr(buffer + pos, buffer_count - pos, base_name);
    append_decimal_suffix(buffer, buffer_count, pos, seed >> 4);
    SN_LOG("init_thread: target_device_name_built name=%ws base=%ws seed=0x%08lx build=%lu ci_options=0x%08lx",
        buffer,
        base_name,
        seed,
        init_read_kuser_u32(0x260) & 0xFFFFu,
        init_read_kuser_u32(0x3A8));
    return TRUE;
}

static BOOLEAN extract_target_driver_image_candidate(PDRIVER_OBJECT driver_object, PDEVICE_OBJECT device_object, PVOID* out_base, ULONG* out_size) {
    LARGE_INTEGER freq = {};
    LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
    SN_LOG("extract_target_driver_image_candidate: entry driver=%p device=%p out_base=%p out_size=%p irql=%lu pid=%llu tid=%llu",
        driver_object,
        device_object,
        out_base,
        out_size,
        static_cast<ULONG>(KeGetCurrentIrql()),
        init_handle_to_u64(PsGetCurrentProcessId()),
        init_handle_to_u64(PsGetCurrentThreadId()));
    if (!driver_object || !device_object || !out_base || !out_size) {
        SN_LOG("extract_target_driver_image_candidate: reject reason=null_arg driver=%p device=%p elapsed_us=%lu",
            driver_object,
            device_object,
            init_elapsed_us(start, freq));
        return FALSE;
    }

    __try {
        BOOLEAN driver_valid = _MmIsAddressValid(driver_object) ? TRUE : FALSE;
        BOOLEAN device_valid = _MmIsAddressValid(device_object) ? TRUE : FALSE;
        if (!driver_valid || !device_valid) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=invalid_object driver_valid=%u device_valid=%u elapsed_us=%lu",
                driver_valid ? 1u : 0u,
                device_valid ? 1u : 0u,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        if (device_object->DriverObject != driver_object) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=device_driver_mismatch device_driver=%p expected=%p elapsed_us=%lu",
                device_object->DriverObject,
                driver_object,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        if (!driver_object->DriverSection || !_MmIsAddressValid(driver_object->DriverSection)) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=invalid_driver_section section=%p elapsed_us=%lu",
                driver_object->DriverSection,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PLDR_DATA_TABLE_ENTRY ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);
        if (!_MmIsAddressValid(ldr) || !ldr->DllBase || ldr->SizeOfImage == 0) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=invalid_ldr ldr=%p base=%p size=0x%lx elapsed_us=%lu",
                ldr,
                ldr && _MmIsAddressValid(ldr) ? ldr->DllBase : nullptr,
                ldr && _MmIsAddressValid(ldr) ? ldr->SizeOfImage : 0,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PVOID base = ldr->DllBase;
        ULONG size = ldr->SizeOfImage;
        if (reinterpret_cast<ULONG_PTR>(base) < 0xFFFF800000000000ULL ||
            size > 50 * 1024 * 1024) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=range base=%p size=0x%lx elapsed_us=%lu",
                base,
                size,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        if (!_MmIsAddressValid(base)) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=base_invalid base=%p size=0x%lx elapsed_us=%lu",
                base,
                size,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=bad_dos base=%p magic=0x%04x elapsed_us=%lu",
                base,
                dos->e_magic,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=bad_nt nt=%p valid=%u elapsed_us=%lu",
                nt,
                _MmIsAddressValid(nt) ? 1u : 0u,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PDRIVER_DISPATCH create_handler = driver_object->MajorFunction[IRP_MJ_CREATE];
        PDRIVER_DISPATCH ioctl_handler = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        if (!create_handler || !ioctl_handler) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=missing_dispatch create=%p ioctl=%p elapsed_us=%lu",
                create_handler,
                ioctl_handler,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        if (reinterpret_cast<ULONG_PTR>(create_handler) < 0xFFFF800000000000ULL ||
            reinterpret_cast<ULONG_PTR>(ioctl_handler) < 0xFFFF800000000000ULL) {
            SN_LOG("extract_target_driver_image_candidate: reject reason=dispatch_user_range create=%p ioctl=%p elapsed_us=%lu",
                create_handler,
                ioctl_handler,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        *out_base = base;
        *out_size = size;
        SN_LOG("extract_target_driver_image_candidate: accept driver=%p device=%p base=%p end=%p size=0x%lx create=%p ioctl=%p sections=%u elapsed_us=%lu",
            driver_object,
            device_object,
            base,
            static_cast<UCHAR*>(base) + size,
            size,
            create_handler,
            ioctl_handler,
            nt->FileHeader.NumberOfSections,
            init_elapsed_us(start, freq));
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SN_LOG("extract_target_driver_image_candidate: exception code=0x%08lx driver=%p device=%p elapsed_us=%lu",
            GetExceptionCode(),
            driver_object,
            device_object,
            init_elapsed_us(start, freq));
        return FALSE;
    }
}

static BOOLEAN validate_target_driver_object(PDRIVER_OBJECT driver_object, PVOID target_base) {
    LARGE_INTEGER freq = {};
    LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
    if (!driver_object || !target_base || !_MmIsAddressValid(driver_object)) {
        SN_LOG("validate_target_driver_object: reject reason=invalid_arg driver=%p target_base=%p elapsed_us=%lu",
            driver_object,
            target_base,
            init_elapsed_us(start, freq));
        return FALSE;
    }

    __try {
        if (!driver_object->DriverSection || !_MmIsAddressValid(driver_object->DriverSection)) {
            SN_LOG("validate_target_driver_object: reject reason=invalid_section driver=%p section=%p elapsed_us=%lu",
                driver_object,
                driver_object->DriverSection,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PLDR_DATA_TABLE_ENTRY ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);
        if (!_MmIsAddressValid(ldr) || ldr->DllBase != target_base) {
            SN_LOG("validate_target_driver_object: reject reason=base_mismatch ldr=%p ldr_base=%p target_base=%p elapsed_us=%lu",
                ldr,
                _MmIsAddressValid(ldr) ? ldr->DllBase : nullptr,
                target_base,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PDEVICE_OBJECT device = driver_object->DeviceObject;
        if (!device || !_MmIsAddressValid(device) || device->DriverObject != driver_object) {
            SN_LOG("validate_target_driver_object: reject reason=device_invalid device=%p device_valid=%u device_driver=%p expected=%p elapsed_us=%lu",
                device,
                device && _MmIsAddressValid(device) ? 1u : 0u,
                device && _MmIsAddressValid(device) ? device->DriverObject : nullptr,
                driver_object,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        PDRIVER_DISPATCH create_handler = driver_object->MajorFunction[IRP_MJ_CREATE];
        PDRIVER_DISPATCH ioctl_handler = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        if (!create_handler || !ioctl_handler) {
            SN_LOG("validate_target_driver_object: reject reason=missing_dispatch create=%p ioctl=%p elapsed_us=%lu",
                create_handler,
                ioctl_handler,
                init_elapsed_us(start, freq));
            return FALSE;
        }

        if (reinterpret_cast<ULONG_PTR>(create_handler) < 0xFFFF800000000000ULL ||
            reinterpret_cast<ULONG_PTR>(ioctl_handler) < 0xFFFF800000000000ULL) {
            SN_LOG("validate_target_driver_object: reject reason=dispatch_user_range create=%p ioctl=%p elapsed_us=%lu",
                create_handler,
                ioctl_handler,
                init_elapsed_us(start, freq));
            return FALSE;
        }
        SN_LOG("validate_target_driver_object: accept driver=%p device=%p base=%p size=0x%lx create=%p ioctl=%p elapsed_us=%lu",
            driver_object,
            device,
            target_base,
            ldr->SizeOfImage,
            create_handler,
            ioctl_handler,
            init_elapsed_us(start, freq));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SN_LOG("validate_target_driver_object: exception code=0x%08lx driver=%p target_base=%p elapsed_us=%lu",
            GetExceptionCode(),
            driver_object,
            target_base,
            init_elapsed_us(start, freq));
        return FALSE;
    }

    return TRUE;
}

static PDRIVER_OBJECT resolve_target_driver_object_from_device(PVOID target_base) {
    LARGE_INTEGER freq = {};
    LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
    if (!target_base || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        SN_LOG("find_target_driver_object: device_resolve_skipped target_base=%p irql=%lu elapsed_us=%lu",
            target_base,
            static_cast<ULONG>(KeGetCurrentIrql()),
            init_elapsed_us(start, freq));
        return nullptr;
    }

    WCHAR device_name_buffer[80] = {};
    if (!build_target_device_name(device_name_buffer, sizeof(device_name_buffer) / sizeof(device_name_buffer[0]))) {
        SN_LOG("find_target_driver_object: device_name_build_failed target_base=%p elapsed_us=%lu",
            target_base,
            init_elapsed_us(start, freq));
        return nullptr;
    }

    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, device_name_buffer);
    SN_LOG("find_target_driver_object: device_resolve_begin target_base=%p device=%wZ elapsed_us=%lu",
        target_base,
        &device_name,
        init_elapsed_us(start, freq));

    PFILE_OBJECT file_object = nullptr;
    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = IoGetDeviceObjectPointer(&device_name, FILE_READ_DATA, &file_object, &device_object);
    if (!NT_SUCCESS(status) || !file_object || !device_object) {
        SN_LOG("find_target_driver_object: device_resolve_failed status=0x%08lx device=%wZ file=%p device_object=%p elapsed_us=%lu",
            status,
            &device_name,
            file_object,
            device_object,
            init_elapsed_us(start, freq));
        if (file_object)
            ObDereferenceObject(file_object);
        return nullptr;
    }

    PDRIVER_OBJECT driver_object = nullptr;
    __try {
        if (_MmIsAddressValid(device_object))
            driver_object = device_object->DriverObject;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        driver_object = nullptr;
    }

    BOOLEAN valid = validate_target_driver_object(driver_object, target_base);
    SN_LOG("find_target_driver_object: device_resolve status=0x%08lx valid=%u device=%wZ file=%p device_object=%p driver=%p elapsed_us=%lu",
        status,
        valid ? 1u : 0u,
        &device_name,
        file_object,
        device_object,
        driver_object,
        init_elapsed_us(start, freq));
    ObDereferenceObject(file_object);

    return valid ? driver_object : nullptr;
}

static BOOLEAN discover_target_driver_from_device() {
    LARGE_INTEGER freq = {};
    LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        SN_LOG("init_thread: device_discovery_skipped irql=%lu elapsed_us=%lu",
            static_cast<unsigned long>(KeGetCurrentIrql()),
            init_elapsed_us(start, freq));
        return FALSE;
    }

    WCHAR device_name_buffer[80] = {};
    if (!build_target_device_name(device_name_buffer, sizeof(device_name_buffer) / sizeof(device_name_buffer[0]))) {
        SN_LOG("init_thread: device_discovery_name_build_failed elapsed_us=%lu", init_elapsed_us(start, freq));
        return FALSE;
    }

    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, device_name_buffer);
    SN_LOG("init_thread: device_discovery_begin device=%wZ pid=%llu tid=%llu irql=%lu elapsed_us=%lu",
        &device_name,
        init_handle_to_u64(PsGetCurrentProcessId()),
        init_handle_to_u64(PsGetCurrentThreadId()),
        static_cast<ULONG>(KeGetCurrentIrql()),
        init_elapsed_us(start, freq));

    PFILE_OBJECT file_object = nullptr;
    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = IoGetDeviceObjectPointer(&device_name, FILE_READ_DATA, &file_object, &device_object);
    if (!NT_SUCCESS(status) || !file_object || !device_object) {
        SN_LOG("init_thread: device_discovery_resolve_failed status=0x%08lx device=%wZ file=%p device=%p elapsed_us=%lu",
            status,
            &device_name,
            file_object,
            device_object,
            init_elapsed_us(start, freq));
        if (file_object)
            ObDereferenceObject(file_object);
        return FALSE;
    }

    PDRIVER_OBJECT driver_object = nullptr;
    PVOID candidate_base = nullptr;
    ULONG candidate_size = 0;
    BOOLEAN shape_ok = FALSE;

    __try {
        if (_MmIsAddressValid(device_object))
            driver_object = device_object->DriverObject;
        shape_ok = extract_target_driver_image_candidate(driver_object, device_object, &candidate_base, &candidate_size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SN_LOG("init_thread: device_discovery_candidate_exception code=0x%08lx device=%wZ file=%p device=%p elapsed_us=%lu",
            GetExceptionCode(),
            &device_name,
            file_object,
            device_object,
            init_elapsed_us(start, freq));
        shape_ok = FALSE;
    }

    BOOLEAN bridge_ok = FALSE;
    BOOLEAN object_ok = FALSE;
    if (shape_ok) {
        bridge_ok = heartbeat::locate_bridge(candidate_base, candidate_size) ? TRUE : FALSE;
        object_ok = validate_target_driver_object(driver_object, candidate_base);
    }

    SN_LOG("init_thread: device_discovery_candidate status=0x%08lx device_name=%wZ shape=%u bridge=%u object=%u base=%p end=%p size=0x%lx driver=%p device=%p file=%p elapsed_us=%lu",
        status,
        &device_name,
        shape_ok ? 1u : 0u,
        bridge_ok ? 1u : 0u,
        object_ok ? 1u : 0u,
        candidate_base,
        candidate_base ? static_cast<UCHAR*>(candidate_base) + candidate_size : nullptr,
        candidate_size,
        driver_object,
        device_object,
        file_object,
        init_elapsed_us(start, freq));

    if (shape_ok && bridge_ok && object_ok) {
        g_target_driver_base = candidate_base;
        g_target_driver_size = candidate_size;
        g_target_driver_object = driver_object;
        SN_LOG("init_thread: device_discovery_success device=%wZ base=%p size=0x%lx driver=%p bridge=%p whoswho_tsc=%llu sentinel_tsc=%llu elapsed_us=%lu",
            &device_name,
            candidate_base,
            candidate_size,
            driver_object,
            heartbeat::g_bridge,
            heartbeat::g_bridge ? static_cast<unsigned long long>(heartbeat::g_bridge->whoswho_tsc) : 0ULL,
            heartbeat::g_bridge ? static_cast<unsigned long long>(heartbeat::g_bridge->sentinel_tsc) : 0ULL,
            init_elapsed_us(start, freq));
        ObDereferenceObject(file_object);
        return TRUE;
    }

    heartbeat::g_bridge = nullptr;
    heartbeat::g_last_whoswho_tsc = 0;
    heartbeat::g_last_check_tsc = 0;
    ObDereferenceObject(file_object);
    SN_LOG("init_thread: device_discovery_reject device=%wZ reset_bridge=1 shape=%u bridge=%u object=%u elapsed_us=%lu",
        &device_name,
        shape_ok ? 1u : 0u,
        bridge_ok ? 1u : 0u,
        object_ok ? 1u : 0u,
        init_elapsed_us(start, freq));
    return FALSE;
}

static PDRIVER_OBJECT find_target_driver_object(PVOID target_base) {
    if (g_target_driver_object && validate_target_driver_object(static_cast<PDRIVER_OBJECT>((PVOID)g_target_driver_object), target_base)) {
        SN_LOG("find_target_driver_object: using preseeded object valid=1");
        return static_cast<PDRIVER_OBJECT>((PVOID)g_target_driver_object);
    }

    PDRIVER_OBJECT resolved = resolve_target_driver_object_from_device(target_base);
    if (resolved) {
        g_target_driver_object = resolved;
        SN_LOG("find_target_driver_object: resolved from device valid=1");
        return resolved;
    }

    SN_LOG("find_target_driver_object: unavailable preseeded_object=%u target_base_set=%u dispatch_snapshot_coverage=0",
        g_target_driver_object != nullptr ? 1u : 0u,
        target_base != nullptr ? 1u : 0u);

    return nullptr;
}


static BOOLEAN ForceDeleteFileByPath(PUNICODE_STRING FilePath) {
    if (!FilePath || !FilePath->Buffer || !_ZwSetInformationFile)
        return FALSE;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


    {
        HANDLE clearHandle = NULL;
        IO_STATUS_BLOCK clearIosb = {};
        NTSTATUS clearStatus = ZwCreateFile(
            &clearHandle,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &objAttr,
            &clearIosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        if (NT_SUCCESS(clearStatus) && clearHandle) {
            PFILE_OBJECT fileObj = NULL;
            clearStatus = ObReferenceObjectByHandle(
                clearHandle, 0, *IoFileObjectType, KernelMode,
                reinterpret_cast<PVOID*>(&fileObj), NULL);

            if (NT_SUCCESS(clearStatus) && fileObj) {
                PSECTION_OBJECT_POINTERS sop = fileObj->SectionObjectPointer;
                if (sop)
                    sop->ImageSectionObject = NULL;
                ObDereferenceObject(fileObj);
            }
            _ZwClose(clearHandle);
        }
    }


    if (_IoCreateFileEx) {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

        NTSTATUS status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0, CreateFileTypeNone, NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK, &createCtx);

        if (NT_SUCCESS(status)) {
            struct { ULONG Flags; } dispEx = {};
            dispEx.Flags = FILE_DISPOSITION_FLAG_DELETE
                         | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                         | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;

            status = _ZwSetInformationFile(
                fileHandle, &ioStatus,
                &dispEx, sizeof(dispEx),
                FileDispositionInformationExClass);
            _ZwClose(fileHandle);

            if (NT_SUCCESS(status))
                return TRUE;
        }
    }


    if (_ZwDeleteFile) {
        if (NT_SUCCESS(_ZwDeleteFile(&objAttr)))
            return TRUE;
    }


    if (_IoCreateFileEx) {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        IO_DRIVER_CREATE_CONTEXT createCtx = {};
        createCtx.Size = sizeof(createCtx);

        NTSTATUS status = _IoCreateFileEx(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
            NULL, 0, CreateFileTypeNone, NULL,
            IO_IGNORE_SHARE_ACCESS_CHECK, &createCtx);

        if (NT_SUCCESS(status)) {
            _ZwClose(fileHandle);
            return TRUE;
        }
    }


    {
        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};
        NTSTATUS status = ZwCreateFile(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        if (!NT_SUCCESS(status))
            return FALSE;

        struct { BOOLEAN DeleteFile; } dispInfo = { TRUE };
        status = _ZwSetInformationFile(
            fileHandle, &ioStatus,
            &dispInfo, sizeof(dispInfo),
            static_cast<FILE_INFORMATION_CLASS>(13));
        _ZwClose(fileHandle);
        return NT_SUCCESS(status);
    }
}


static VOID DeleteDriverOnDisk(PUNICODE_STRING RegistryPath) {
    if (!RegistryPath || !RegistryPath->Buffer)
        return;
    if (!_ZwOpenKey || !_ZwQueryValueKey || !_ZwClose)
        return;

    OBJECT_ATTRIBUTES keyAttr;
    InitializeObjectAttributes(&keyAttr, RegistryPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    NTSTATUS status = _ZwOpenKey(&keyHandle, KEY_READ, &keyAttr);
    if (!NT_SUCCESS(status))
        return;

    UNICODE_STRING valueName;
    _RtlInitUnicodeString(&valueName, L"ImagePath");

    ULONG kvSize = 0;
    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, NULL, 0, &kvSize);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        _ZwClose(keyHandle);
        return;
    }

    auto kvInfo = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, kvSize, TAG_DEL));

    if (!kvInfo) {
        _ZwClose(keyHandle);
        return;
    }

    status = _ZwQueryValueKey(keyHandle, &valueName,
        KeyValuePartialInformation, kvInfo, kvSize, &kvSize);
    _ZwClose(keyHandle);

    if (!NT_SUCCESS(status) ||
        (kvInfo->Type != REG_SZ && kvInfo->Type != REG_EXPAND_SZ)) {
        ExFreePoolWithTag(kvInfo, TAG_DEL);
        return;
    }

    ULONG dataLen = kvInfo->DataLength;
    if (dataLen >= sizeof(WCHAR)) {
        PWCHAR imgBuf = reinterpret_cast<PWCHAR>(kvInfo->Data);
        ULONG chars = dataLen / sizeof(WCHAR);
        if (imgBuf[chars - 1] == L'\0')
            chars--;

        UNICODE_STRING imagePath;
        imagePath.Buffer = imgBuf;
        imagePath.Length = static_cast<USHORT>(chars * sizeof(WCHAR));
        imagePath.MaximumLength = static_cast<USHORT>(dataLen);

        ForceDeleteFileByPath(&imagePath);
    }

    ExFreePoolWithTag(kvInfo, TAG_DEL);
}

namespace sentinel_build_identity {
    constexpr unsigned long long fnv1a64(const char* text) {
        unsigned long long h = 14695981039346656037ull;
        while (*text) {
            h ^= static_cast<unsigned char>(*text);
            h *= 1099511628211ull;
            ++text;
        }
        return h;
    }

    constexpr unsigned long long kHash = fnv1a64("Sentinel|" __DATE__ "|" __TIME__ "|" __FILE__);
}


static void NTAPI init_thread_routine(PVOID ) {

    LARGE_INTEGER init_freq;
    LARGE_INTEGER init_start = KeQueryPerformanceCounter(&init_freq);
    SN_LOG("init_thread: started routine=%p pid=%llu tid=%llu",
        reinterpret_cast<PVOID>(&init_thread_routine),
        init_handle_to_u64(PsGetCurrentProcessId()),
        init_handle_to_u64(PsGetCurrentThreadId()));
    SN_LOG("init_thread: system_state build=%lu ci_options=0x%08lx hvci=%u ci_enabled=%u secure_kernel_hint=%u irql=%lu cpu=%lu",
        init_read_kuser_u32(0x260) & 0xFFFFu,
        init_read_kuser_u32(0x3A8),
        hvci_detect::is_hvci_enabled() ? 1u : 0u,
        (init_read_kuser_u32(0x3A8) & 0x1u) ? 1u : 0u,
        (init_read_kuser_u32(0x3A8) & (hvci_detect::CI_OPTION_HVCI_KMCI_ENABLED | hvci_detect::CI_OPTION_HVCI_STRICT)) ? 1u : 0u,
        static_cast<ULONG>(KeGetCurrentIrql()),
        KeGetCurrentProcessorNumber());
    init_log_session_state("entry");

    constexpr ULONG SETTLE_POLLS = 5;
    constexpr LONG64 POLL_INTERVAL = -1'000'000LL;

    LARGE_INTEGER interval;
    interval.QuadPart = POLL_INTERVAL;

    for (ULONG i = 0; i < SETTLE_POLLS; i++) {
        if (_InterlockedCompareExchange(&g_shutdown_flag, 0, 0)) {
            SN_LOG("init_thread: shutdown flag set at settle %lu", i);
            goto exit_thread;
        }

        if (g_target_driver_base != nullptr) {
            SN_LOG("init_thread: g_target_driver_base pre-set at %p after %lu settles", (PVOID)g_target_driver_base, i);
            break;
        }

        _KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }


    if (g_target_driver_base == nullptr) {
        SN_LOG("init_thread: settle done, attempting device discovery before bridge magic scan...");
        init_log_session_state("before_bridge_scan");

        if (discover_target_driver_from_device()) {
            SN_LOG("init_thread: device discovery completed before module list scan");
            goto discovery_done;
        }

        SN_LOG("init_thread: device discovery unavailable, scanning module list for bridge magic...");

        if (g_sentinel_driver_object &&
            _MmIsAddressValid(g_sentinel_driver_object) &&
            g_sentinel_driver_object->DriverSection &&
            _MmIsAddressValid(g_sentinel_driver_object->DriverSection))
        {
            PLDR_DATA_TABLE_ENTRY sentinel_ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(
                g_sentinel_driver_object->DriverSection);
            PLIST_ENTRY list_head = &sentinel_ldr->InLoadOrderModuleList;
            PLIST_ENTRY entry = list_head->Flink;
            ULONG safety = 512;
            ULONG modules_checked = 0;
            UINT64 magic_probes = 0;
            BOOLEAN scan_cancelled = FALSE;

            SN_LOG("init_thread: sentinel_ldr=%p base=%p size=0x%lx",
                sentinel_ldr, sentinel_ldr->DllBase, sentinel_ldr->SizeOfImage);

            while (entry && entry != list_head && safety-- > 0) {
                if (!_MmIsAddressValid(entry)) {
                    SN_LOG("init_thread: entry %p not valid, stopping walk", entry);
                    break;
                }

                PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

                if (!_MmIsAddressValid(mod) || !mod->DllBase || !mod->SizeOfImage) {
                    entry = entry->Flink;
                    continue;
                }


                if (mod->DllBase == sentinel_ldr->DllBase) {
                    entry = entry->Flink;
                    continue;
                }

                PVOID mod_base = mod->DllBase;
                ULONG mod_size = mod->SizeOfImage;

                modules_checked++;


                if (reinterpret_cast<ULONG_PTR>(mod_base) < 0xFFFF800000000000ULL ||
                    mod_size > 50 * 1024 * 1024) {
                    SN_LOG("init_thread: mod %p size=0x%lx skipped (bad range)", mod_base, mod_size);
                    entry = entry->Flink;
                    continue;
                }

                SN_LOG("init_thread: checking module %p size=0x%lx for bridge magic", mod_base, mod_size);

                __try {
                    if (!_MmIsAddressValid(mod_base))
                        goto next_module;

                    PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(mod_base);
                    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                        SN_LOG("init_thread: mod %p bad DOS sig", mod_base);
                        goto next_module;
                    }

                    PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                        static_cast<UCHAR*>(mod_base) + dos->e_lfanew);
                    if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
                        SN_LOG("init_thread: mod %p bad NT sig", mod_base);
                        goto next_module;
                    }

                    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
                    SN_LOG("init_thread: mod %p has %u sections", mod_base, nt->FileHeader.NumberOfSections);

                    for (USHORT si = 0; si < nt->FileHeader.NumberOfSections; si++) {
                        UCHAR* sec_base = static_cast<UCHAR*>(mod_base) + sections[si].VirtualAddress;
                        ULONG sec_size = sections[si].Misc.VirtualSize;

                        if (sec_size < sizeof(heartbeat::sentinel_bridge_t))
                            continue;

                        ULONG magic_checks = 0;
                        for (ULONG off = 0; off <= sec_size - sizeof(heartbeat::sentinel_bridge_t); off += 4) {
                            magic_probes++;
                            if ((magic_probes & 0x0FFFULL) == 0) {
                                if (!init_scan_backoff("bridge_magic_scan", magic_probes, modules_checked, si, off)) {
                                    scan_cancelled = TRUE;
                                    break;
                                }
                            }

                            if (!_MmIsAddressValid(sec_base + off))
                                continue;

                            volatile UINT32* magic_ptr = reinterpret_cast<volatile UINT32*>(sec_base + off);
                            if (*magic_ptr != heartbeat::BRIDGE_MAGIC)
                                continue;

                            magic_checks++;
                            SN_LOG("init_thread: BRIDGE_MAGIC found at %p (mod %p sec[%u] off=0x%lx)",
                                magic_ptr, mod_base, si, off);

                            volatile UINT32* ver_ptr = magic_ptr + 1;
                            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<UINT32*>(ver_ptr)))) {
                                SN_LOG("init_thread: version ptr %p not valid", ver_ptr);
                                continue;
                            }

                            if (*ver_ptr != heartbeat::BRIDGE_VERSION) {
                                SN_LOG("init_thread: version mismatch: got %u expected %u",
                                    *ver_ptr, heartbeat::BRIDGE_VERSION);
                                continue;
                            }

                            SN_LOG("init_thread: BRIDGE FOUND at %p (magic=0x%lx ver=%u) in module %p",
                                magic_ptr, *magic_ptr, *ver_ptr, mod_base);
                            g_target_driver_base = mod_base;
                            g_target_driver_size = mod_size;
                            goto discovery_done;
                        }
                        if (scan_cancelled)
                            break;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    SN_LOG("init_thread: EXCEPTION scanning module %p", mod_base);
                }

                if (scan_cancelled)
                    break;

            next_module:
                entry = entry->Flink;
            }

            SN_LOG("init_thread: module list scan complete, checked %lu modules probes=%llu cancelled=%u elapsed_us=%lu",
                modules_checked,
                static_cast<unsigned long long>(magic_probes),
                scan_cancelled ? 1u : 0u,
                init_elapsed_us(init_start, init_freq));
            if (scan_cancelled)
                goto exit_thread;
        } else {
            SN_LOG("init_thread: cannot scan module list: driver_obj=%p valid=%d section=%p",
                g_sentinel_driver_object,
                g_sentinel_driver_object ? (int)_MmIsAddressValid(g_sentinel_driver_object) : -1,
                g_sentinel_driver_object ? g_sentinel_driver_object->DriverSection : nullptr);
        }
    }
discovery_done:
    init_log_session_state("after_discovery");

    if (g_target_driver_base == nullptr) {
        SN_LOG("init_thread: FATAL - target driver NOT FOUND, exiting");
        goto exit_thread;
    }

    SN_LOG("init_thread: target found at %p size=0x%lx, beginning subsystem init",
        (PVOID)g_target_driver_base, g_target_driver_size);
    init_log_session_state("before_subsystem_init");

    {
        PVOID target_base = (PVOID)g_target_driver_base;

        if (!_MmIsAddressValid(target_base)) {
            SN_LOG("init_thread: target_base %p not valid after discovery", target_base);
            goto exit_thread;
        }

        if (reinterpret_cast<ULONG_PTR>(target_base) < 0xFFFF800000000000ULL) {
            SN_LOG("init_thread: target_base %p below kernel range", target_base);
            goto exit_thread;
        }

        PVOID target_text = nullptr;
        ULONG target_text_size = 0;
        if (!find_target_text(target_base, &target_text, &target_text_size)) {
            SN_LOG("init_thread: find_target_text FAILED for %p", target_base);
            goto exit_thread;
        }

        if (!target_text || target_text_size == 0 || target_text_size > 10 * 1024 * 1024) {
            SN_LOG("init_thread: bad text section: base=%p size=0x%lx", target_text, target_text_size);
            goto exit_thread;
        }

        SN_LOG("init_thread: target .text at %p size=0x%lx", target_text, target_text_size);

        PDRIVER_OBJECT target_driver_obj = find_target_driver_object(target_base);
        SN_LOG("init_thread: target_driver_obj_present=%u", target_driver_obj != nullptr ? 1u : 0u);


        bool integrity_ok = integrity::init(target_text, target_text_size);
        SN_LOG("init_thread: integrity::init = %d", (int)integrity_ok);


        if (target_driver_obj) {
            bool dg_ok = dispatch_guard::snapshot(target_driver_obj);
            SN_LOG("init_thread: dispatch_guard::snapshot = %d", (int)dg_ok);
        } else {
            SN_LOG("init_thread: skip dispatch_guard::snapshot reason=target_driver_object_unavailable coverage=0 base_known=%u size_known=%u",
                g_target_driver_base != nullptr ? 1u : 0u,
                g_target_driver_size != 0 ? 1u : 0u);
        }


        bool ml_ok = dispatch_guard::init_module_list(g_sentinel_driver_object);
        SN_LOG("init_thread: dispatch_guard::init_module_list = %d", (int)ml_ok);


        {
            ULONG hb_size = g_target_driver_size ? g_target_driver_size : target_text_size * 4;
            SN_LOG("init_thread: heartbeat::init target_base=%p hb_size=0x%lx (driver_size=0x%lx text_size=0x%lx)",
                target_base, hb_size, g_target_driver_size, target_text_size);
            bool hb_ok = heartbeat::init(target_base, hb_size);
            SN_LOG("init_thread: heartbeat::init = %d", (int)hb_ok);

            if (hb_ok) {


                heartbeat::update_and_check();
                SN_LOG("init_thread: heartbeat initial tick done bridge=%p whoswho_seen=%u sentinel_seen=%u whoswho_tsc=%llu sentinel_tsc=%llu initialized=%ld first_seen=%ld",
                    heartbeat::g_bridge,
                    heartbeat::g_bridge && heartbeat::g_bridge->whoswho_tsc != 0 ? 1u : 0u,
                    heartbeat::g_bridge && heartbeat::g_bridge->sentinel_tsc != 0 ? 1u : 0u,
                    heartbeat::g_bridge ? static_cast<unsigned long long>(heartbeat::g_bridge->whoswho_tsc) : 0ULL,
                    heartbeat::g_bridge ? static_cast<unsigned long long>(heartbeat::g_bridge->sentinel_tsc) : 0ULL,
                    _InterlockedCompareExchange(&heartbeat::g_initialized, 0, 0),
                    _InterlockedCompareExchange(&heartbeat::g_first_heartbeat_seen, 0, 0));
            }
        }

        {
            bool hw_ok = hardware_id::collect_all();
            SN_LOG("init_thread: hardware_id::collect_all = %d", (int)hw_ok);

            bool kw_ok = witness_key::init();
            SN_LOG("init_thread: witness_key::init = %d", (int)kw_ok);

            if (kw_ok) {
                UINT8 kw_seed[32] = {};
                if (hw_ok) {
                    RtlCopyMemory(kw_seed, hardware_id::g_anchors.composite_sha256, sizeof(kw_seed));
                } else {
                    kernel_crypto::gen_random(kw_seed, sizeof(kw_seed));
                }

                kw_ok = witness_key::store_kw(kw_seed);
                SN_LOG("init_thread: witness_key::store_kw = %d", (int)kw_ok);
                RtlSecureZeroMemory(kw_seed, sizeof(kw_seed));

                UINT8 bridge_key[32] = {};
                bool derive_ok = witness_key::derive_subkey("bridge-v2", bridge_key);
                SN_LOG("init_thread: witness_key::derive_subkey = %d", (int)derive_ok);

                bool bridge_ok = FALSE;
                if (derive_ok) {
                    bridge_ok = bridge_v2::init_bridge(bridge_key);
                }
                SN_LOG("init_thread: bridge_v2::init_bridge = %d", (int)bridge_ok);
                RtlSecureZeroMemory(bridge_key, sizeof(bridge_key));
            }

            SN_LOG("init_thread: wsk cloud heartbeat not started; client license heartbeat carries live driver proof");

            bool attest_ok = attestation::init();
            SN_LOG("init_thread: attestation::init = %d", (int)attest_ok);

            bool ev_ok = evidence::init();
            SN_LOG("init_thread: evidence::init = %d", (int)ev_ok);

            bool dla_ok = driver_load_audit::init();
            SN_LOG("init_thread: driver_load_audit::init = %d", (int)dla_ok);

            integrity::collect_sensor_baseline();
            SN_LOG("init_thread: integrity::collect_sensor_baseline done");
        }


        SN_LOG("init_thread: calling thread_guard::check_and_clear_current_cpu");
        if (g_target_driver_base && g_target_driver_size) {
            UINT64 tg_base = reinterpret_cast<UINT64>(const_cast<PVOID>(g_target_driver_base));
            UINT64 tg_size = static_cast<UINT64>(g_target_driver_size);
            bool tg_ok = thread_guard::init(tg_base, tg_size);
            SN_LOG("init_thread: thread_guard::init base=0x%llx size=0x%llx = %d",
                tg_base, tg_size, (int)tg_ok);
        } else {
            SN_LOG("init_thread: thread_guard::init SKIPPED (no target base/size)");
        }
        thread_guard::check_and_clear_current_cpu();
        SN_LOG("init_thread: thread_guard done");


        SN_LOG("init_thread: starting guardian...");
        bool guard_ok = guardian::start();
        SN_LOG("init_thread: guardian::start = %d", (int)guard_ok);
        init_log_session_state("after_guardian_start");


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            SN_LOG("init_thread: nt_base=%p for etw_disable", nt_base);
            if (nt_base) {
                bool etw_ok = etw_disable::init();
                SN_LOG("init_thread: etw_disable::init = %d", (int)etw_ok);
            }
        }


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                bool cb_ok = callback_scanner::init();
                SN_LOG("init_thread: callback_scanner::init = %d", (int)cb_ok);
                callback_scanner::init_ob_monitoring();
                callback_scanner::start_image_load_monitoring();
            }
        }

        device_scan::start();


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                bool ps_ok = pool_scrub::init();
                SN_LOG("init_thread: pool_scrub::init = %d", (int)ps_ok);
                pool_scrub::scrub_tags();
                SN_LOG("init_thread: pool_scrub::scrub_tags done");
            }
        }


        if (target_driver_obj) {
            bool og_ok = object_guard::init(target_driver_obj);
            SN_LOG("init_thread: object_guard::init = %d", (int)og_ok);
        }

        {
            bool pn_ok = process_notify::init();
            SN_LOG("init_thread: process_notify::init = %d", (int)pn_ok);
        }

        __try {
            SN_LOG("init_thread: calling self_protect::apply_stealth");
            self_protect::apply_stealth(g_sentinel_driver_object);
            SN_LOG("init_thread: self_protect::apply_stealth done");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("init_thread: EXCEPTION in self_protect::apply_stealth");
        }


        if (g_registry_path.Buffer && g_registry_path.Length > 0) {
            SN_LOG("init_thread: deleting driver on disk");
            DeleteDriverOnDisk(&g_registry_path);
        }

        SN_LOG("init_thread: ALL SUBSYSTEMS INITIALIZED");
        init_log_session_state("subsystems_initialized");
    }

exit_thread:
    SN_LOG("init_thread: exiting elapsed_us=%lu target_base=%p target_size=0x%lx shutdown=%ld",
        init_elapsed_us(init_start, init_freq),
        (PVOID)g_target_driver_base,
        g_target_driver_size,
        _InterlockedCompareExchange(&g_shutdown_flag, 0, 0));
    init_log_session_state("exit");
    _PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

    LARGE_INTEGER entry_freq = {};
    LARGE_INTEGER entry_start = KeQueryPerformanceCounter(&entry_freq);
    dbg_capture::configure_log_path(RegistryPath);
    ULONG early_build = init_read_kuser_u32(0x260) & 0xFFFFu;
    ULONG early_ci_options = init_read_kuser_u32(0x3A8);
    dbg_capture::write_immediate_formatted("[SN-EARLY] DriverEntry entered driver_object_present=%u registry_path_present=%u pid=%llu tid=%llu irql=%lu cpu=%lu build=%lu ci_options=0x%08lx hvci=%u ci_enabled=%u\n",
        DriverObject != nullptr ? 1u : 0u,
        RegistryPath != nullptr ? 1u : 0u,
        init_handle_to_u64(PsGetCurrentProcessId()),
        init_handle_to_u64(PsGetCurrentThreadId()),
        static_cast<ULONG>(KeGetCurrentIrql()),
        KeGetCurrentProcessorNumber(),
        early_build,
        early_ci_options,
        (early_ci_options & hvci_detect::CI_OPTION_HVCI_KMCI_ENABLED) || (early_ci_options & hvci_detect::CI_OPTION_HVCI_STRICT) ? 1u : 0u,
        (early_ci_options & 0x1u) ? 1u : 0u);
    dbg_capture::write_immediate_formatted("[SN-EARLY] build_identity hash=0x%llX date=%s time=%s msc=%u cpp=%lu entry=%p\n",
        sentinel_build_identity::kHash,
        __DATE__,
        __TIME__,
        (unsigned)_MSC_VER,
        (unsigned long)__cplusplus,
        reinterpret_cast<PVOID>(&DriverEntry));
    dbg_capture::write_immediate_formatted("[SN-EARLY] SetupFunctions begin\n");

    if (!SetupFunctions()) {
        dbg_capture::write_immediate_formatted("[SN-EARLY] SetupFunctions FAILED elapsed_us=%lu\n",
            init_elapsed_us(entry_start, entry_freq));
        return STATUS_UNSUCCESSFUL;
    }

    dbg_capture::write_immediate_formatted("[SN-EARLY] SetupFunctions OK elapsed_us=%lu\n",
        init_elapsed_us(entry_start, entry_freq));

    NTSTATUS dbg_status = dbg_capture::initialize();
    dbg_capture::write_immediate_formatted("[SN-EARLY] dbg_capture::initialize status=0x%08lx elapsed_us=%lu\n",
        static_cast<ULONG>(dbg_status),
        init_elapsed_us(entry_start, entry_freq));

    SN_LOG("DriverEntry: SetupFunctions OK");
    SN_LOG("DriverEntry: build_identity hash=0x%llX date=%s time=%s msc=%u cpp=%lu entry=%p driver_object=%p registry_path_present=%u",
        sentinel_build_identity::kHash,
        __DATE__,
        __TIME__,
        (unsigned)_MSC_VER,
        (unsigned long)__cplusplus,
        reinterpret_cast<PVOID>(&DriverEntry),
        DriverObject,
        RegistryPath != nullptr ? 1u : 0u);
    init_log_driverentry_phase("post_setup", entry_start, entry_freq);

    g_sentinel_driver_object = DriverObject;
    SN_LOG("DriverEntry: sentinel driver object registered object=%p device_object=%p public_device_create=0 symlink_create=0 reason=sentinel_internal_bridge_only elapsed_us=%lu",
        DriverObject,
        DriverObject ? DriverObject->DeviceObject : nullptr,
        init_elapsed_us(entry_start, entry_freq));


    if (RegistryPath && RegistryPath->Buffer && RegistryPath->Length > 0) {
        USHORT copy_len = RegistryPath->Length;
        if (copy_len > sizeof(g_registry_path_buffer) - sizeof(WCHAR))
            copy_len = sizeof(g_registry_path_buffer) - sizeof(WCHAR);

        RtlCopyMemory(g_registry_path_buffer, RegistryPath->Buffer, copy_len);
        g_registry_path_buffer[copy_len / sizeof(WCHAR)] = L'\0';

        g_registry_path.Buffer = g_registry_path_buffer;
        g_registry_path.Length = copy_len;
        g_registry_path.MaximumLength = sizeof(g_registry_path_buffer);
        SN_LOG("DriverEntry: registry path captured bytes=%u chars=%u path=%wZ elapsed_us=%lu",
            copy_len,
            copy_len / sizeof(WCHAR),
            &g_registry_path,
            init_elapsed_us(entry_start, entry_freq));
    } else {
        SN_LOG("DriverEntry: registry path absent elapsed_us=%lu", init_elapsed_us(entry_start, entry_freq));
    }


    DriverObject->DriverUnload = nullptr;
    SN_LOG("DriverEntry: unload disabled unload=%p major_create=%p major_ioctl=%p elapsed_us=%lu",
        DriverObject->DriverUnload,
        DriverObject->MajorFunction[IRP_MJ_CREATE],
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        init_elapsed_us(entry_start, entry_freq));


    if (DriverObject->DriverSection) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        ldr->Flags |= 0x20u;
        SN_LOG("DriverEntry: DriverSection flag set ldr=%p flags=0x%lx base=%p size=0x%lx elapsed_us=%lu",
            ldr,
            ldr->Flags,
            ldr->DllBase,
            ldr->SizeOfImage,
            init_elapsed_us(entry_start, entry_freq));
    }


    PVOID own_text = nullptr;
    ULONG own_text_size = 0;
    PVOID own_base = nullptr;

    if (DriverObject->DriverSection && _MmIsAddressValid(DriverObject->DriverSection)) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        own_base = ldr->DllBase;
    }

    SN_LOG("DriverEntry: own_base=%p build_hash=0x%llX", own_base, sentinel_build_identity::kHash);

    if (own_base) {
        find_text_section(own_base, &own_text, &own_text_size);
    }

    SN_LOG("DriverEntry: own_text=%p own_text_size=0x%lx", own_text, own_text_size);

    if (own_text && own_text_size > 0) {
        bool bl_ok = self_protect::init_baseline(own_text, own_text_size);
        SN_LOG("DriverEntry: self_protect::init_baseline = %d elapsed_us=%lu", (int)bl_ok, init_elapsed_us(entry_start, entry_freq));
    } else {
        SN_LOG("DriverEntry: self_protect::init_baseline skipped reason=no_text elapsed_us=%lu", init_elapsed_us(entry_start, entry_freq));
    }


    HANDLE thread_handle = nullptr;
    NTSTATUS status = _PsCreateSystemThread(
        &thread_handle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        init_thread_routine,
        nullptr);

    SN_LOG("DriverEntry: PsCreateSystemThread status=0x%08lx handle=%p routine=%p elapsed_us=%lu",
        status,
        thread_handle,
        reinterpret_cast<PVOID>(&init_thread_routine),
        init_elapsed_us(entry_start, entry_freq));

    if (NT_SUCCESS(status) && thread_handle) {
        g_init_thread_handle = thread_handle;


        _ZwClose(thread_handle);
        g_init_thread_handle = nullptr;
        SN_LOG("DriverEntry: init thread handle closed status=0x%08lx elapsed_us=%lu",
            status,
            init_elapsed_us(entry_start, entry_freq));
    } else if (!NT_SUCCESS(status)) {
        SN_LOG("DriverEntry: init thread creation failed status=0x%08lx elapsed_us=%lu",
            status,
            init_elapsed_us(entry_start, entry_freq));
    }

    init_log_driverentry_phase("return_success", entry_start, entry_freq);
    SN_LOG("DriverEntry: returning STATUS_SUCCESS, g_target_driver_base=%p elapsed_us=%lu",
        (PVOID)g_target_driver_base,
        init_elapsed_us(entry_start, entry_freq));
    return STATUS_SUCCESS;
}
