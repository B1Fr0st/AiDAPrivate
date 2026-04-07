#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"

#ifndef YieldProcessor
#define YieldProcessor() _mm_pause()
#endif

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _ReadWriteBarrier()
#endif

namespace dynamic_key {
    inline volatile ULONG g_cached_key = 0;

    __forceinline UINT32 compute() {
        int cpu[4] = {0};
        __cpuid(cpu, 0);
        UINT32 h = 0x811C9DC5u;
        h = (h ^ (UINT32)cpu[1]) * 0x01000193u;
        h = (h ^ (UINT32)cpu[2]) * 0x01000193u;
        h = (h ^ (UINT32)cpu[3]) * 0x01000193u;
        __cpuid(cpu, 1);
        h = (h ^ (UINT32)cpu[0]) * 0x01000193u;
        h = (h ^ (UINT32)cpu[3]) * 0x01000193u;
        volatile UINT32 build = *(volatile UINT32*)(0xFFFFF78000000260ULL) & 0xFFFFu;
        h = (h ^ build) * 0x01000193u;
        h ^= h >> 16;
        h *= 0x85ebca6bu;
        h ^= h >> 13;
        if (h == 0) h = 1;
        return h;
    }

    __forceinline UINT32 get() {
        ULONG cached = g_cached_key;
        if (cached != 0) return cached;
        UINT32 key = compute();
        _InterlockedCompareExchange((volatile LONG*)&g_cached_key, (LONG)key, 0);
        return g_cached_key;
    }
}

namespace device_names {

    static const wchar_t* const g_device_bases[] = {
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

    constexpr SIZE_T NUM_DEVICE_BASES = sizeof(g_device_bases) / sizeof(g_device_bases[0]);

    inline wchar_t g_device_name[80] = { 0 };
    inline wchar_t g_symlink_name[80] = { 0 };
    inline volatile LONG g_names_initialized = 0;

    __forceinline UINT32 hash_bytes(const UCHAR* data, SIZE_T len) {
        UINT32 hash = 0x811C9DC5u;
        for (SIZE_T i = 0; i < len; i++) {
            hash ^= data[i];
            hash *= 0x01000193u;
        }
        return hash;
    }

    __forceinline UINT32 get_machine_seed() {
        UINT32 seed = dynamic_key::get();
        seed = (seed * 0x45D9F3Bu) ^ (seed >> 16);
        seed = (seed * 0x1B873593u) ^ (seed >> 13);
        return seed;
    }

    __forceinline void append_suffix(wchar_t* buffer, SIZE_T buffer_size, SIZE_T current_len, UINT32 seed) {
        UINT32 suffix_val = (seed >> 8) % 100;

        if (current_len + 3 >= buffer_size) {
            return;
        }

        if (suffix_val >= 10) {
            buffer[current_len] = L'0' + static_cast<wchar_t>((suffix_val / 10) % 10);
            buffer[current_len + 1] = L'0' + static_cast<wchar_t>(suffix_val % 10);
            buffer[current_len + 2] = L'\0';
        } else {
            buffer[current_len] = L'0' + static_cast<wchar_t>(suffix_val);
            buffer[current_len + 1] = L'\0';
        }
    }

    __forceinline SIZE_T copy_wstring(wchar_t* dest, SIZE_T dest_size, const wchar_t* src) {
        SIZE_T i = 0;
        while (src[i] && (i + 1) < dest_size) {
            dest[i] = src[i];
            i++;
        }
        dest[i] = L'\0';
        return i;
    }

    __forceinline BOOLEAN initialize_names() {
        if (_InterlockedCompareExchange(&g_names_initialized, 1, 0) != 0) {
            while (_InterlockedCompareExchange(&g_names_initialized, 2, 2) != 2) {
                YieldProcessor();
            }
            return TRUE;
        }

        UINT32 seed = get_machine_seed();

        SIZE_T base_index = seed % NUM_DEVICE_BASES;
        const wchar_t* base_name = g_device_bases[base_index];

        SIZE_T pos = copy_wstring(g_device_name, 80, L"\\Device\\");
        pos += copy_wstring(&g_device_name[pos], 80 - pos, base_name);
        append_suffix(g_device_name, 80, pos, seed >> 4);

        pos = copy_wstring(g_symlink_name, 80, L"\\DosDevices\\Global\\");
        pos += copy_wstring(&g_symlink_name[pos], 80 - pos, base_name);
        append_suffix(g_symlink_name, 80, pos, seed >> 4);

        KeMemoryBarrier();
        _InterlockedExchange(&g_names_initialized, 2);

        return TRUE;
    }

    __forceinline const wchar_t* get_device_name() {
        if (g_names_initialized != 2) {
            initialize_names();
        }
        return g_device_name;
    }

    __forceinline const wchar_t* get_symlink_name() {
        if (g_names_initialized != 2) {
            initialize_names();
        }
        return g_symlink_name;
    }

}

namespace caller_validation {

    inline volatile HANDLE g_registered_client_pid = nullptr;
    inline volatile UINT64 g_registered_client_eprocess = 0;
    inline volatile UINT64 g_client_base_address = 0;
    inline volatile UINT64 g_client_cr3 = 0;
    inline volatile LONG g_validation_enabled = 0;
    inline volatile LONG g_validation_lock = 0;

    constexpr UINT32 MAX_VALIDATION_FAILURES = 5;
    inline volatile UINT32 g_validation_failures = 0;

    inline volatile UINT64 g_last_validation_tsc = 0;

    inline volatile ULONG g_DirectoryTableBase_offset = 0;
    inline volatile LONG g_offsets_initialized = 0;

    __forceinline BOOLEAN initialize_eprocess_offsets() {
        LONG prev = _InterlockedCompareExchange(&g_offsets_initialized, 1, 0);
        if (prev == 2) return TRUE;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_offsets_initialized, 2, 2) != 2) {
                YieldProcessor();
            }
            return (g_DirectoryTableBase_offset != 0);
        }

        RTL_OSVERSIONINFOW version_info = { sizeof(RTL_OSVERSIONINFOW) };
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&version_info))) {
            g_DirectoryTableBase_offset = 0x28;
        } else {
            g_DirectoryTableBase_offset = 0x28;
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_offsets_initialized, 2);
        return TRUE;
    }

    __forceinline ULONG get_dtb_offset() {
        if (g_offsets_initialized != 2) {
            initialize_eprocess_offsets();
        }
        return g_DirectoryTableBase_offset;
    }

    __forceinline void acquire_lock() {
        while (_InterlockedCompareExchange(&g_validation_lock, 1, 0) != 0) {
            YieldProcessor();
        }
        KeMemoryBarrier();
    }

    __forceinline void release_lock() {
        KeMemoryBarrier();
        _InterlockedExchange(&g_validation_lock, 0);
    }

    __forceinline BOOLEAN register_client() {
        acquire_lock();

        PEPROCESS current_process = PsGetCurrentProcess();
        if (!current_process) {
            release_lock();
            return FALSE;
        }

        HANDLE pid = PsGetCurrentProcessId();

        g_registered_client_pid = pid;
        g_registered_client_eprocess = reinterpret_cast<UINT64>(current_process);

        if (_PsGetProcessSectionBaseAddress) {
            g_client_base_address = reinterpret_cast<UINT64>(
                _PsGetProcessSectionBaseAddress(current_process));
        }

        ULONG dtb_offset = get_dtb_offset();

        __try {
            g_client_cr3 = *reinterpret_cast<UINT64*>(
                reinterpret_cast<UCHAR*>(current_process) + dtb_offset);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            g_client_cr3 = 0;
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_validation_enabled, 1);

        release_lock();
        return TRUE;
    }

    __forceinline void unregister_client() {
        acquire_lock();

        g_registered_client_pid = nullptr;
        g_registered_client_eprocess = 0;
        g_client_base_address = 0;
        g_client_cr3 = 0;
        g_validation_failures = 0;

        KeMemoryBarrier();
        _InterlockedExchange(&g_validation_enabled, 0);

        release_lock();
    }

    __forceinline BOOLEAN validate_caller() {
        if (_InterlockedCompareExchange(&g_validation_enabled, 0, 0) == 0) {
            return TRUE;
        }

        UINT64 current_tsc = __rdtsc();
        UINT64 last_tsc = g_last_validation_tsc;

        BOOLEAN fast_path = (current_tsc - last_tsc < 10000);

        if (!fast_path) {
            g_last_validation_tsc = current_tsc;
        }

        PEPROCESS current_process = PsGetCurrentProcess();
        if (!current_process) {
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_validation_failures));
            return FALSE;
        }

        HANDLE current_pid = PsGetCurrentProcessId();

        if (current_pid != g_registered_client_pid) {
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_validation_failures));
            return FALSE;
        }

        if (reinterpret_cast<UINT64>(current_process) != g_registered_client_eprocess) {
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_validation_failures));
            return FALSE;
        }

        if (fast_path) {
            return TRUE;
        }

        if (_PsGetProcessSectionBaseAddress && g_client_base_address != 0) {
            UINT64 current_base = reinterpret_cast<UINT64>(
                _PsGetProcessSectionBaseAddress(current_process));

            if (current_base != g_client_base_address) {
                _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_validation_failures));
                return FALSE;
            }
        }

        if (g_client_cr3 != 0) {
            ULONG dtb_offset = get_dtb_offset();

            __try {
                UINT64 current_cr3 = *reinterpret_cast<UINT64*>(
                    reinterpret_cast<UCHAR*>(current_process) + dtb_offset);

                if ((current_cr3 & ~0xFFFULL) != (g_client_cr3 & ~0xFFFULL)) {
                    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_validation_failures));
                    return FALSE;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                return FALSE;
            }
        }

        if (g_validation_failures > 0) {
            _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_validation_failures), 0);
        }

        return TRUE;
    }

    __forceinline BOOLEAN is_under_attack() {
        return (g_validation_failures >= MAX_VALIDATION_FAILURES);
    }

    __forceinline BOOLEAN validate_irql() {
        KIRQL current_irql = (KIRQL)__readcr8();

        if (current_irql > 0) {
            return FALSE;
        }

        return TRUE;
    }

    __forceinline BOOLEAN is_valid_request() {
        if (is_under_attack()) {
            return FALSE;
        }

        if (!validate_irql()) {
            return FALSE;
        }

        if (!validate_caller()) {
            return FALSE;
        }

        return TRUE;
    }
}


namespace hvci_detect {


    constexpr ULONG CI_OPTION_HVCI_KMCI_ENABLED = 0x400u;

    constexpr ULONG CI_OPTION_HVCI_STRICT       = 0x800u;

    constexpr ULONG CI_OPTION_ENABLED            = 0x01u;


    constexpr ULONG64 KUSER_SHARED_DATA_VA = 0xFFFFF78000000000ULL;


    inline volatile LONG g_hvci_state = -1;

    __forceinline BOOLEAN detect_hvci() {
        __try {

            volatile ULONG* ci_options = reinterpret_cast<volatile ULONG*>(
                KUSER_SHARED_DATA_VA + 0x03A8);


            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<ULONG*>(ci_options))))
                return FALSE;

            ULONG options = *ci_options;

            if (options & CI_OPTION_HVCI_KMCI_ENABLED)
                return TRUE;
            if (options & CI_OPTION_HVCI_STRICT)
                return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {


            return TRUE;
        }
        return FALSE;
    }

    __forceinline BOOLEAN is_hvci_enabled() {
        LONG state = _InterlockedCompareExchange(&g_hvci_state, -1, -1);
        if (state >= 0)
            return (state != 0);


        BOOLEAN enabled = detect_hvci();
        _InterlockedExchange(&g_hvci_state, enabled ? 1 : 0);
        return enabled;
    }

    __forceinline BOOLEAN is_secure_boot_ci_enabled() {
        __try {
            volatile ULONG* ci_options = reinterpret_cast<volatile ULONG*>(
                KUSER_SHARED_DATA_VA + 0x03A8);
            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(const_cast<ULONG*>(ci_options))))
                return FALSE;
            return ((*ci_options) & CI_OPTION_ENABLED) != 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return TRUE;
        }
    }
}

namespace stack_spoof {

    inline volatile ULONG64 g_spoof_entropy = 0xCAFEBABEDEADC0DEULL;

    __forceinline ULONG64 next_spoof_rand() {
        ULONG64 x = g_spoof_entropy;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x ^= (__rdtsc() & 0xFFFFULL);
        g_spoof_entropy = x;
        return x;
    }

    __forceinline void add_spoof_delay() {
        ULONG64 entropy = next_spoof_rand();
        volatile ULONG spin = static_cast<ULONG>((entropy & 0x3) + 1);
        while (spin--) {
            YieldProcessor();
        }
    }

    struct StackFrame {
        ULONG64 saved_rbp;
        ULONG64 return_address;
    };

    __forceinline BOOLEAN is_kernel_address(ULONG64 addr) {
        return (addr >= 0xFFFF800000000000ULL);
    }

    __forceinline void obfuscate_rbp_chain() {
        volatile ULONG64 dummy_frames[4];
        ULONG64 entropy = next_spoof_rand();

        dummy_frames[0] = entropy;
        dummy_frames[1] = entropy ^ 0xDEADBEEFCAFEBABEULL;
        dummy_frames[2] = __rdtsc();
        dummy_frames[3] = dummy_frames[0] + dummy_frames[1];

        KeMemoryBarrier();

        volatile ULONG64 result = dummy_frames[0] ^ dummy_frames[3];
        (void)result;
    }

    __forceinline void pre_call_setup() {
        add_spoof_delay();
        obfuscate_rbp_chain();
        KeMemoryBarrier();
    }

    __forceinline void post_call_cleanup() {
        KeMemoryBarrier();
        add_spoof_delay();

        volatile ULONG64 clear_block[4] = { 0, 0, 0, 0 };
        (void)clear_block;
    }

    template<typename RetT, typename FuncT, typename... Args>
    __forceinline RetT spoofed_call(FuncT func, Args... args) {
        pre_call_setup();

        volatile FuncT volatile_func = func;
        KeMemoryBarrier();

        RetT result = volatile_func(args...);

        post_call_cleanup();

        return result;
    }

    template<typename FuncT, typename... Args>
    __forceinline void spoofed_call_void(FuncT func, Args... args) {
        pre_call_setup();

        volatile FuncT volatile_func = func;
        KeMemoryBarrier();

        volatile_func(args...);

        post_call_cleanup();
    }

    __forceinline NTSTATUS spoofed_MmCopyMemory(
        PVOID TargetAddress,
        MM_COPY_ADDRESS SourceAddress,
        SIZE_T NumberOfBytes,
        ULONG Flags,
        PSIZE_T NumberOfBytesTransferred
    ) {
        if (!_MmCopyMemory) {
            return STATUS_NOT_SUPPORTED;
        }

        pre_call_setup();

        volatile auto func = _MmCopyMemory;
        KeMemoryBarrier();

        NTSTATUS status = func(TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred);

        post_call_cleanup();

        return status;
    }

    __forceinline PVOID spoofed_MmMapIoSpaceEx(
        PHYSICAL_ADDRESS PhysicalAddress,
        SIZE_T NumberOfBytes,
        ULONG Protect
    ) {
        if (!_MmMapIoSpaceEx) {
            return nullptr;
        }

        pre_call_setup();

        volatile auto func = _MmMapIoSpaceEx;
        KeMemoryBarrier();

        PVOID result = func(PhysicalAddress, NumberOfBytes, Protect);

        post_call_cleanup();

        return result;
    }

    __forceinline void spoofed_MmUnmapIoSpace(
        PVOID BaseAddress,
        SIZE_T NumberOfBytes
    ) {
        if (!_MmUnmapIoSpace) {
            return;
        }

        pre_call_setup();

        volatile auto func = _MmUnmapIoSpace;
        KeMemoryBarrier();

        func(BaseAddress, NumberOfBytes);

        post_call_cleanup();
    }

    __forceinline NTSTATUS spoofed_PsLookupProcessByProcessId(
        HANDLE ProcessId,
        PEPROCESS* Process
    ) {
        if (!_PsLookupProcessByProcessId) {
            return STATUS_NOT_SUPPORTED;
        }

        pre_call_setup();

        volatile auto func = _PsLookupProcessByProcessId;
        KeMemoryBarrier();

        NTSTATUS status = func(ProcessId, Process);

        post_call_cleanup();

        return status;
    }

    __forceinline void spoofed_ObfDereferenceObject(PVOID Object) {
        if (!_ObfDereferenceObject || !Object) {
            return;
        }

        pre_call_setup();

        volatile auto func = _ObfDereferenceObject;
        KeMemoryBarrier();

        func(Object);

        post_call_cleanup();
    }
}

#define SPOOF_CALL(ret_type, func, ...) stack_spoof::spoofed_call<ret_type>(func, __VA_ARGS__)
#define SPOOF_CALL_VOID(func, ...) stack_spoof::spoofed_call_void(func, __VA_ARGS__)

namespace call_obfuscation {

    inline volatile ULONG64 g_call_entropy = 0xDEADC0DEBEEFCAFEULL;
    inline volatile ULONG64 g_call_counter = 0;

    __forceinline ULONG64 next_entropy() {
        ULONG64 x = g_call_entropy;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x ^= __rdtsc();
        g_call_entropy = x;
        _InterlockedIncrement64((volatile LONG64*)&g_call_counter);
        return x;
    }

    __forceinline void add_call_jitter() {
        ULONG64 entropy = next_entropy();
        volatile ULONG spin = static_cast<ULONG>((entropy & 0x7) + 1);
        while (spin--) {
            YieldProcessor();
        }
    }

    __forceinline void obfuscate_timing() {
        ULONG64 entropy = next_entropy();
        ULONG pattern = static_cast<ULONG>(entropy & 0xF);

        switch (pattern) {
            case 0: case 1:
                YieldProcessor();
                break;
            case 2: case 3:
                { volatile ULONG64 tsc = __rdtsc(); g_call_entropy ^= tsc; }
                break;
            case 4: case 5:
                KeMemoryBarrier();
                YieldProcessor();
                break;
            case 6: case 7:
                { volatile ULONG spin = 2; while (spin--) YieldProcessor(); }
                break;
            case 8: case 9:
                { volatile ULONG64 dummy = g_call_counter * 3; (void)dummy; }
                break;
            default:
                KeMemoryBarrier();
                break;
        }
    }

    template<typename FuncT, typename... Args>
    __forceinline auto indirect_call(FuncT func, Args... args) -> decltype(func(args...)) {
        add_call_jitter();

        volatile FuncT func_ptr = func;
        KeMemoryBarrier();

        auto result = func_ptr(args...);

        obfuscate_timing();

        return result;
    }

    template<typename FuncT, typename... Args>
    __forceinline void indirect_call_void(FuncT func, Args... args) {
        add_call_jitter();

        volatile FuncT func_ptr = func;
        KeMemoryBarrier();

        func_ptr(args...);

        obfuscate_timing();
    }

    __forceinline PVOID encode_pointer(PVOID ptr) {
        ULONG64 key = g_call_entropy ^ 0x5A5A5A5A5A5A5A5AULL;
        return reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(ptr) ^ key);
    }

    __forceinline PVOID decode_pointer(PVOID encoded_ptr) {
        ULONG64 key = g_call_entropy ^ 0x5A5A5A5A5A5A5A5AULL;
        return reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(encoded_ptr) ^ key);
    }

    struct EncodedFunction {
        volatile ULONG64 encoded_addr;
        volatile ULONG64 encoding_key;

        __forceinline void store(PVOID func) {
            ULONG64 key = __rdtsc() ^ g_call_entropy;
            encoded_addr = reinterpret_cast<ULONG64>(func) ^ key;
            encoding_key = key;
            KeMemoryBarrier();
        }

        __forceinline PVOID get() const {
            KeMemoryBarrier();
            return reinterpret_cast<PVOID>(encoded_addr ^ encoding_key);
        }

        __forceinline bool is_valid() const {
            return encoded_addr != 0 && encoding_key != 0;
        }
    };

    __forceinline void scramble_stack_locals() {
        volatile ULONG64 dummy[4];
        ULONG64 entropy = next_entropy();

        dummy[0] = entropy;
        dummy[1] = entropy ^ 0xDEADBEEFu;
        dummy[2] = __rdtsc();
        dummy[3] = dummy[0] ^ dummy[1] ^ dummy[2];

        KeMemoryBarrier();

        volatile ULONG64 result = dummy[0] + dummy[1] + dummy[2] + dummy[3];
        (void)result;
    }

    __forceinline void clear_local_traces() {
        volatile ULONG64 zero_block[8] = { 0 };
        KeMemoryBarrier();
        (void)zero_block;
    }
}

#define OBFUSCATED_CALL(func, ...) call_obfuscation::indirect_call(func, __VA_ARGS__)
#define OBFUSCATED_CALL_VOID(func, ...) call_obfuscation::indirect_call_void(func, __VA_ARGS__)

namespace secure_comm {

    inline volatile UINT64 g_session_entropy = 0x5A5A5A5A5A5A5A5AULL;
    inline volatile UINT64 g_request_id = 0;
    inline volatile UINT64 g_client_token = 0;
    inline volatile LONG g_comm_initialized = 0;

    constexpr UINT64 KEY_PRIME_1 = 0x100000001B3ULL;
    constexpr UINT64 KEY_PRIME_2 = 0xCBF29CE484222325ULL;
    constexpr UINT64 KEY_MIX_CONST = 0xFF51AFD7ED558CCDULL;

    __forceinline UINT64 derive_key(UINT64 seed, UINT64 request_id) {
        UINT64 hash = KEY_PRIME_2;
        hash ^= seed;
        hash *= KEY_PRIME_1;
        hash ^= request_id;
        hash *= KEY_PRIME_1;
        hash ^= (__rdtsc() & 0xFFFFULL);
        hash *= KEY_PRIME_1;
        return hash ^ (hash >> 32);
    }

    __forceinline void xor_buffer(PVOID buffer, SIZE_T size, UINT64 key) {
        if (!buffer || size == 0) return;

        PUINT8 bytes = static_cast<PUINT8>(buffer);
        UINT64 rolling_key = key;

        SIZE_T chunks = size / sizeof(UINT64);
        PUINT64 chunks_ptr = reinterpret_cast<PUINT64>(bytes);

        for (SIZE_T i = 0; i < chunks; i++) {
            chunks_ptr[i] ^= rolling_key;
            rolling_key = (rolling_key * KEY_PRIME_1) ^ KEY_MIX_CONST;
        }

        SIZE_T remaining_offset = chunks * sizeof(UINT64);
        for (SIZE_T i = remaining_offset; i < size; i++) {
            bytes[i] ^= static_cast<UINT8>(rolling_key >> ((i - remaining_offset) * 8));
        }
    }

    #pragma pack(push, 1)
    typedef struct _SECURE_HEADER {
        UINT64 request_id;
        UINT64 client_token;
        UINT64 entropy;
        UINT32 payload_size;
        UINT32 checksum;
    } SECURE_HEADER, *PSECURE_HEADER;
    #pragma pack(pop)

    static_assert(sizeof(SECURE_HEADER) == 32, "SECURE_HEADER must be 32 bytes");

    __forceinline UINT32 compute_checksum(PVOID data, SIZE_T size) {
        if (!data || size == 0) return 0;

        PUINT8 bytes = static_cast<PUINT8>(data);
        UINT32 sum = 0x12345678u;

        for (SIZE_T i = 0; i < size; i++) {
            sum = ((sum << 5) | (sum >> 27)) ^ bytes[i];
        }

        return sum;
    }

    __forceinline BOOLEAN init_session(UINT64 client_token, UINT64 initial_entropy) {
        if (_InterlockedCompareExchange(&g_comm_initialized, 1, 0) != 0) {
            return (g_client_token == client_token);
        }

        g_client_token = client_token;
        g_session_entropy = initial_entropy ^ __rdtsc();
        g_request_id = 0;

        KeMemoryBarrier();
        return TRUE;
    }

    __forceinline BOOLEAN decrypt_request(
        PVOID encrypted_buffer,
        SIZE_T buffer_size,
        PVOID output_buffer,
        SIZE_T output_size,
        PSIZE_T actual_size
    ) {
        if (!encrypted_buffer || buffer_size < sizeof(SECURE_HEADER) || !output_buffer) {
            return FALSE;
        }

        if (g_comm_initialized == 0) {
            return FALSE;
        }

        SECURE_HEADER header;
        RtlCopyMemory(&header, encrypted_buffer, sizeof(SECURE_HEADER));

        if (header.client_token != g_client_token) {
            return FALSE;
        }

        UINT64 expected_id = _InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&g_request_id), 0, 0);

        if (header.request_id <= expected_id) {
            if (expected_id - header.request_id > 16) {
                return FALSE;
            }
        }

        SIZE_T payload_offset = sizeof(SECURE_HEADER);
        if (payload_offset + header.payload_size > buffer_size) {
            return FALSE;
        }

        if (header.payload_size > output_size) {
            return FALSE;
        }

        UINT64 decrypt_key = derive_key(
            g_session_entropy ^ header.entropy,
            header.request_id
        );

        PUINT8 payload = static_cast<PUINT8>(encrypted_buffer) + payload_offset;
        RtlCopyMemory(output_buffer, payload, header.payload_size);

        xor_buffer(output_buffer, header.payload_size, decrypt_key);

        UINT32 computed_checksum = compute_checksum(output_buffer, header.payload_size);
        if (computed_checksum != header.checksum) {
            RtlSecureZeroMemory(output_buffer, header.payload_size);
            return FALSE;
        }

        _InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&g_request_id),
            header.request_id,
            expected_id);

        g_session_entropy ^= header.entropy ^ __rdtsc();

        if (actual_size) {
            *actual_size = header.payload_size;
        }

        return TRUE;
    }

    __forceinline BOOLEAN encrypt_response(
        PVOID plaintext_buffer,
        SIZE_T plaintext_size,
        PVOID output_buffer,
        SIZE_T output_buffer_size,
        UINT64 request_entropy,
        UINT64 request_id
    ) {
        if (!plaintext_buffer || plaintext_size == 0 || !output_buffer) {
            return FALSE;
        }

        SIZE_T required_size = sizeof(SECURE_HEADER) + plaintext_size;
        if (required_size > output_buffer_size) {
            return FALSE;
        }

        SECURE_HEADER header;
        header.request_id = request_id;
        header.client_token = g_client_token;
        header.entropy = request_entropy ^ (__rdtsc() & 0xFFFFFFFF);
        header.payload_size = static_cast<UINT32>(plaintext_size);
        header.checksum = compute_checksum(plaintext_buffer, plaintext_size);

        RtlCopyMemory(output_buffer, &header, sizeof(SECURE_HEADER));

        UINT64 encrypt_key = derive_key(
            g_session_entropy ^ header.entropy,
            header.request_id
        );

        PUINT8 payload_dest = static_cast<PUINT8>(output_buffer) + sizeof(SECURE_HEADER);
        RtlCopyMemory(payload_dest, plaintext_buffer, plaintext_size);

        xor_buffer(payload_dest, plaintext_size, encrypt_key);

        return TRUE;
    }

    __forceinline BOOLEAN validate_request_timing() {
        static volatile UINT64 s_last_request_tsc = 0;

        UINT64 current_tsc = __rdtsc();
        UINT64 last_tsc = _InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&s_last_request_tsc),
            current_tsc,
            0);

        if (last_tsc != 0) {
            _InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&s_last_request_tsc),
                current_tsc);

            if (current_tsc - last_tsc < 1000) {
                return FALSE;
            }
        }

        return TRUE;
    }

    __forceinline void reset_session() {
        g_client_token = 0;
        g_session_entropy = 0;
        g_request_id = 0;
        KeMemoryBarrier();
        _InterlockedExchange(&g_comm_initialized, 0);
    }
}
