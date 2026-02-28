#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <memory>
#include <type_traits>
#include <string>
#include <intrin.h>

namespace dynamic_key {
    inline std::uint32_t g_cached_key = 0;

    __forceinline std::uint32_t compute() {
        int cpu[4] = {0};
        __cpuid(cpu, 0);
        std::uint32_t h = 0x811C9DC5u;
        h = (h ^ static_cast<std::uint32_t>(cpu[1])) * 0x01000193u;
        h = (h ^ static_cast<std::uint32_t>(cpu[2])) * 0x01000193u;
        h = (h ^ static_cast<std::uint32_t>(cpu[3])) * 0x01000193u;
        __cpuid(cpu, 1);
        h = (h ^ static_cast<std::uint32_t>(cpu[0])) * 0x01000193u;
        h = (h ^ static_cast<std::uint32_t>(cpu[3])) * 0x01000193u;
        volatile std::uint32_t build = *reinterpret_cast<volatile std::uint32_t*>(static_cast<std::uintptr_t>(0x7FFE0260)) & 0xFFFFu;
        h = (h ^ build) * 0x01000193u;
        h ^= h >> 16;
        h *= 0x85ebca6bu;
        h ^= h >> 13;
        if (h == 0) h = 1;
        return h;
    }

    __forceinline std::uint32_t get() {
        if (g_cached_key != 0) return g_cached_key;
        g_cached_key = compute();
        return g_cached_key;
    }
}

__forceinline std::uint32_t hash_build_key(std::uint32_t key) {
    key ^= key >> 16;
    key *= 0x85ebca6bu;
    key ^= key >> 13;
    key *= 0xc2b2ae35u;
    key ^= key >> 16;
    return key;
}

__forceinline std::uint32_t secondary_hash(std::uint32_t key) {
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = (key >> 16) ^ key;
    return key;
}

namespace ioctl_codes {
    __forceinline std::uint32_t get_base() {
        std::uint32_t key = dynamic_key::get();
        return ((hash_build_key(key) ^ secondary_hash(key >> 3)) & 0x7FF) | 0x800;
    }

    __forceinline DWORD make(std::uint32_t offset) {
        return static_cast<DWORD>(0x00220000u | ((get_base() + offset) << 2));
    }

    __forceinline DWORD DTB()  { return make(0); }
    __forceinline DWORD PHYS() { return make(1); }
    __forceinline DWORD BASE() { return make(2); }
    __forceinline DWORD MM()   { return make(3); }
    __forceinline DWORD RC()   { return make(4); }
    __forceinline DWORD CR()   { return make(5); }
    __forceinline DWORD AM()   { return make(6); }
    __forceinline DWORD FM()   { return make(7); }
    __forceinline DWORD HB()   { return make(8); }
}

namespace voyager {
    namespace detail {

        __forceinline std::uint32_t get_heartbeat_magic() {
            return 0xDEADBEEFu ^ dynamic_key::get();
        }
        constexpr std::uint64_t HEARTBEAT_REFRESH_INTERVAL = 200000000ULL;

        struct heartbeat_request {
            std::uint32_t magic;
            std::uint32_t session_key;
            std::uint64_t timestamp;
            std::uint64_t response;
        };
        static_assert(sizeof(heartbeat_request) == 24, "heartbeat_request size mismatch with kernel driver");

        struct dtb_solve {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t dtb;
        };
        static_assert(sizeof(dtb_solve) == 16, "dtb_solve size mismatch with kernel driver");
        
        struct physical_request {
            std::uint32_t pid;
            std::uint32_t padding_1;
            std::uint64_t dtb;     
            void* address;    
            void* buffer;  
            std::size_t size;   
            std::size_t ret_size;
            std::uint8_t should_write; 
            std::uint8_t padding_2[7]; 
        };
        static_assert(sizeof(physical_request) == 56, "physical_request size mismatch with kernel driver");

        struct base_address_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t* out_address;
        };
        static_assert(sizeof(base_address_request) == 16, "base_address_request size mismatch with kernel driver");

        struct mouse_request {
            std::int32_t inputX;
            std::int32_t inputY;
            std::uint32_t buttonFlags;
        };
        static_assert(sizeof(mouse_request) == 12, "mouse_request size mismatch with kernel driver");

        struct remote_call_request {
            std::uint64_t dtb;
            std::uint64_t target_function;
            std::uint64_t shellcode_address;
            std::uint64_t spoof_return;
            std::uint64_t arg1;
            std::uint64_t arg2;
            std::uint64_t arg3;
            std::uint64_t arg4;
            std::uint64_t result;
            std::uint64_t completed;
            std::uint64_t original_rip;
            std::uint64_t trampoline_addr;
        };
        static_assert(sizeof(remote_call_request) == 96, "remote_call_request size mismatch with kernel driver");

        struct call_result_request {
            std::uint64_t dtb;
            std::uint64_t result_address;
            std::uint64_t result;
        };
        static_assert(sizeof(call_result_request) == 24, "call_result_request size mismatch with kernel driver");

        struct alloc_mem_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t size;
            std::uint64_t allocated_address;
            std::uint64_t actual_size;
        };
        static_assert(sizeof(alloc_mem_request) == 32, "alloc_mem_request size mismatch with kernel driver");

        struct free_mem_request {
            std::uint32_t pid;
            std::uint32_t padding;
            std::uint64_t address;
        };
        static_assert(sizeof(free_mem_request) == 16, "free_mem_request size mismatch with kernel driver");

        constexpr std::size_t SHELLCODE_ALLOC_SIZE = 0x2000;
        constexpr std::size_t CONTEXT_OFFSET = 0x0;
        constexpr std::size_t CODE_OFFSET = 0x200;
        constexpr std::size_t EPILOGUE_OFFSET = 0x600;
        
        constexpr std::size_t CTX_TARGET_FUNC = 0x00;
        constexpr std::size_t CTX_SPOOF_GADGET = 0x08;
        constexpr std::size_t CTX_PARAM1 = 0x10;
        constexpr std::size_t CTX_PARAM2 = 0x18;
        constexpr std::size_t CTX_PARAM3 = 0x20;
        constexpr std::size_t CTX_PARAM4 = 0x28;
        constexpr std::size_t CTX_RET_VALUE = 0x30;
        constexpr std::size_t CTX_SAVED_RSP = 0x38;
        constexpr std::size_t CTX_ORIGINAL_RIP = 0x40;
        constexpr std::size_t CTX_RBX_BACKUP = 0x48;
        constexpr std::size_t CTX_EXEC_DONE = 0x50;
        constexpr std::size_t CTX_TRAMPOLINE = 0x58;
    }

    namespace device_names_um {
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
        constexpr std::size_t NUM_DEVICE_BASES = 16;

        inline std::uint32_t get_device_seed() {
            std::uint32_t hash = dynamic_key::get();
            hash = (hash * 0x45D9F3Bu) ^ (hash >> 16);
            hash = (hash * 0x1B873593u) ^ (hash >> 13);
            return hash;
        }

        inline std::wstring get_device_path() {
            std::uint32_t seed = get_device_seed();
            std::size_t idx = seed % NUM_DEVICE_BASES;
            std::wstring path = L"\\\\.\\";
            path += g_device_bases[idx];

            std::uint32_t suffix_seed = seed >> 4;
            std::uint32_t suffix_val = (suffix_seed >> 8) % 100;
            if (suffix_val >= 10) {
                path += static_cast<wchar_t>(L'0' + (suffix_val / 10) % 10);
                path += static_cast<wchar_t>(L'0' + suffix_val % 10);
            } else {
                path += static_cast<wchar_t>(L'0' + suffix_val);
            }

            return path;
        }
    }

    class device_t final {
    public:
        device_t() noexcept = default;
        ~device_t() noexcept { disconnect(); }

        device_t(const device_t&) = delete;
        device_t& operator=(const device_t&) = delete;
        device_t(device_t&&) = delete;
        device_t& operator=(device_t&&) = delete;

        bool connect() noexcept;
        void disconnect() noexcept;
        [[nodiscard]] bool is_connected() const noexcept { return driver_handle_ != INVALID_HANDLE_VALUE; }

        bool send_heartbeat() noexcept;
        bool refresh_heartbeat() noexcept;

        std::uint32_t find_process(const char* process_name) noexcept;
        std::uint64_t find_image() noexcept;

        void solve_dtb() noexcept;
        void solve_kernel_dtb() noexcept;

        template<typename T>
        [[nodiscard]] T read(std::uint64_t address) const noexcept;

        template<typename T>
        void write(std::uint64_t address, const T& value) const noexcept;

        std::size_t read_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept;
        std::size_t write_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept;

        std::size_t read_kernel_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept;
        std::size_t write_kernel_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept;

        void move_mouse(std::int32_t input_x, std::int32_t input_y, std::uint32_t mouse_flags);
        void send_key(unsigned short button);

        std::uint64_t allocate_memory(std::size_t size) noexcept;
        bool free_memory(std::uint64_t address) noexcept;
        
        std::uint64_t call_function(std::uint64_t function_address, std::uint64_t arg1 = 0, std::uint64_t arg2 = 0, std::uint64_t arg3 = 0, std::uint64_t arg4 = 0) noexcept;
        
        template<typename RetType = std::uint64_t>
        RetType call(std::uint64_t function_address) noexcept {
            return static_cast<RetType>(call_function(function_address, 0, 0, 0, 0));
        }
        
        template<typename RetType = std::uint64_t, typename A1>
        RetType call(std::uint64_t function_address, A1 a1) noexcept {
            return static_cast<RetType>(call_function(function_address, 
                static_cast<std::uint64_t>(a1), 0, 0, 0));
        }
        
        template<typename RetType = std::uint64_t, typename A1, typename A2>
        RetType call(std::uint64_t function_address, A1 a1, A2 a2) noexcept {
            return static_cast<RetType>(call_function(function_address,
                static_cast<std::uint64_t>(a1),
                static_cast<std::uint64_t>(a2), 0, 0));
        }
        
        template<typename RetType = std::uint64_t, typename A1, typename A2, typename A3>
        RetType call(std::uint64_t function_address, A1 a1, A2 a2, A3 a3) noexcept {
            return static_cast<RetType>(call_function(function_address,
                static_cast<std::uint64_t>(a1),
                static_cast<std::uint64_t>(a2),
                static_cast<std::uint64_t>(a3), 0));
        }
        
        template<typename RetType = std::uint64_t, typename A1, typename A2, typename A3, typename A4>
        RetType call(std::uint64_t function_address, A1 a1, A2 a2, A3 a3, A4 a4) noexcept {
            return static_cast<RetType>(call_function(function_address,
                static_cast<std::uint64_t>(a1),
                static_cast<std::uint64_t>(a2),
                static_cast<std::uint64_t>(a3),
                static_cast<std::uint64_t>(a4)));
        }
        
        std::uint64_t find_gadget(const char* pattern, std::size_t pattern_size) noexcept;

        [[nodiscard]] std::uint32_t get_process_id() const noexcept { return process_id_; }
        [[nodiscard]] std::uint64_t get_base_address() const noexcept { return base_address_; }
        [[nodiscard]] std::uint64_t get_dtb() const noexcept { return dtb_; }
        [[nodiscard]] std::uint64_t get_kernel_dtb() const noexcept { return kernel_dtb_; }

        void set_process_id(std::uint32_t pid) noexcept { process_id_ = pid; }
        void set_base_address(std::uint64_t base) noexcept { base_address_ = base; }
        void set_kernel_dtb(std::uint64_t dtb) noexcept { kernel_dtb_ = dtb; }

    private:
        HANDLE driver_handle_ = INVALID_HANDLE_VALUE;
        std::uint32_t process_id_ = 0;
        std::uint64_t base_address_ = 0;
        std::uint64_t dtb_ = 0;
        std::uint64_t kernel_dtb_ = 0;
        std::uint64_t shellcode_address_ = 0;
        std::uint64_t spoof_gadget_ = 0;
        std::uint32_t session_key_ = 0;
        mutable std::uint64_t last_heartbeat_tsc_ = 0;

        bool send_request(DWORD control_code, void* input, DWORD input_size) const noexcept;
        bool ensure_shellcode_allocated() noexcept;
        bool find_spoof_gadget() noexcept;
    };

    template<typename T>
    [[nodiscard]] T device_t::read(std::uint64_t address) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable for memory operations");

        alignas(T) T result{};
        if (read_raw(address, &result, sizeof(T)) == sizeof(T)) {
            return result;
        }
        return T{};
    }

    template<typename T>
    void device_t::write(std::uint64_t address, const T& value) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable for memory operations");
        write_raw(address, &value, sizeof(T));
    }
}

inline std::unique_ptr<voyager::device_t> device = std::make_unique<voyager::device_t>();