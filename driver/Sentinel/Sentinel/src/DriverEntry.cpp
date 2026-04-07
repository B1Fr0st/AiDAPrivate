#include <ntifs.h>
#include <Crypter.h>
#include <imports/Defs.h>
#include <core/Guardian.h>


#pragma data_seg(".sntl")
volatile PVOID  g_target_driver_base   = nullptr;
volatile PVOID  g_target_driver_object = nullptr;
volatile ULONG  g_target_driver_size   = 0;
#pragma data_seg()


#pragma comment(linker, "/SECTION:.sntl,RW")


static PDRIVER_OBJECT g_sentinel_driver_object = nullptr;
static volatile LONG  g_shutdown_flag = 0;
static HANDLE         g_init_thread_handle = nullptr;


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


static PDRIVER_OBJECT find_target_driver_object(PVOID target_base) {

    if (g_target_driver_object && _MmIsAddressValid((PVOID)g_target_driver_object))
        return static_cast<PDRIVER_OBJECT>((PVOID)g_target_driver_object);


    return nullptr;
}


static void NTAPI init_thread_routine(PVOID ) {


    constexpr ULONG MAX_POLLS = 300;
    constexpr LONG64 POLL_INTERVAL = -1'000'000LL;

    LARGE_INTEGER interval;
    interval.QuadPart = POLL_INTERVAL;

    for (ULONG i = 0; i < MAX_POLLS; i++) {
        if (_InterlockedCompareExchange(&g_shutdown_flag, 0, 0))
            goto exit_thread;

        if (g_target_driver_base != nullptr)
            break;

        _KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }


    if (g_target_driver_base == nullptr)
        goto exit_thread;


    {
        PVOID target_base = (PVOID)g_target_driver_base;

        if (!_MmIsAddressValid(target_base))
            goto exit_thread;


        if (reinterpret_cast<ULONG_PTR>(target_base) < 0xFFFF800000000000ULL)
            goto exit_thread;


        PVOID target_text = nullptr;
        ULONG target_text_size = 0;
        if (!find_target_text(target_base, &target_text, &target_text_size))
            goto exit_thread;

        if (!target_text || target_text_size == 0 || target_text_size > 10 * 1024 * 1024)
            goto exit_thread;


        PDRIVER_OBJECT target_driver_obj = find_target_driver_object(target_base);


        integrity::init(target_text, target_text_size);


        if (target_driver_obj)
            dispatch_guard::snapshot(target_driver_obj);


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                etw_disable::init();
            }
        }


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                callback_scanner::init();
            }
        }


        {
            PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
            if (nt_base) {
                pool_scrub::init();
                pool_scrub::scrub_tags();
            }
        }


        {
            heartbeat::init(target_base,
                            g_target_driver_size ? g_target_driver_size : target_text_size * 4);
        }


        if (target_driver_obj)
            object_guard::init(target_driver_obj);


        thread_guard::ipi_clear_all_cpus();


        guardian::start();
    }

exit_thread:
    _PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING ) {


    if (!SetupFunctions())
        return STATUS_UNSUCCESSFUL;

    g_sentinel_driver_object = DriverObject;


    DriverObject->DriverUnload = nullptr;


    if (DriverObject->DriverSection) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        ldr->Flags |= 0x20u;
    }


    PVOID own_text = nullptr;
    ULONG own_text_size = 0;
    PVOID own_base = nullptr;

    if (DriverObject->DriverSection && _MmIsAddressValid(DriverObject->DriverSection)) {
        auto ldr = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        own_base = ldr->DllBase;
    }

    if (own_base) {
        find_text_section(own_base, &own_text, &own_text_size);
    }


    if (own_text && own_text_size > 0)
        self_protect::init(DriverObject, own_text, own_text_size);


    HANDLE thread_handle = nullptr;
    NTSTATUS status = _PsCreateSystemThread(
        &thread_handle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        init_thread_routine,
        nullptr);

    if (NT_SUCCESS(status) && thread_handle) {
        g_init_thread_handle = thread_handle;


        _ZwClose(thread_handle);
        g_init_thread_handle = nullptr;
    }


    return STATUS_SUCCESS;
}
