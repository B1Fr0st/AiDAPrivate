#include "comm.h"
#include <algorithm>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include "encrypt/crypter.h"
#include "spoofer/spoof.hpp"
#include <string>
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <intrin.h>
#include <cstdio>

#pragma comment(lib, "ntdll.lib")

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif

#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

namespace syscall_indices {
    inline std::uint32_t NtOpenThread_idx = 0;
    inline std::uint32_t NtSuspendThread_idx = 0;
    inline std::uint32_t NtResumeThread_idx = 0;
    inline std::uint32_t NtGetContextThread_idx = 0;
    inline std::uint32_t NtSetContextThread_idx = 0;
    inline std::uint32_t NtClose_idx = 0;
    inline std::uint32_t NtDelayExecution_idx = 0;
    inline std::uint8_t* syscall_instruction_addr = nullptr;
    inline volatile bool indices_resolved = false;
    
    __forceinline std::uint8_t* find_syscall_ret() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return nullptr;
        
        std::uint8_t* base = reinterpret_cast<std::uint8_t*>(ntdll);
        PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        
        PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        
        std::uint32_t text_size = nt->OptionalHeader.SizeOfCode;
        std::uint32_t text_rva = nt->OptionalHeader.BaseOfCode;
        std::uint8_t* text = base + text_rva;
        
        for (std::uint32_t i = 0; i < text_size - 3; i++) {
            if (text[i] == 0x0F && text[i + 1] == 0x05 && text[i + 2] == 0xC3) {
                return &text[i];
            }
        }
        return nullptr;
    }
    
    __forceinline bool resolve_syscall_indices() {
        if (indices_resolved) return true;
        
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        
        syscall_instruction_addr = find_syscall_ret();
        if (!syscall_instruction_addr) return false;
        
        auto get_syscall_number = [&](const char* name) -> std::uint32_t {
            PVOID func = reinterpret_cast<PVOID>(GetProcAddress(ntdll, name));
            if (!func) return 0;
            std::uint8_t* bytes = reinterpret_cast<std::uint8_t*>(func);
            if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
                return *reinterpret_cast<std::uint32_t*>(&bytes[4]);
            }
            if (bytes[0] == 0xB8) {
                return *reinterpret_cast<std::uint32_t*>(&bytes[1]);
            }
            for (int j = 0; j < 32; j++) {
                if (bytes[j] == 0xB8 && bytes[j + 5] == 0x0F && bytes[j + 6] == 0x05) {
                    return *reinterpret_cast<std::uint32_t*>(&bytes[j + 1]);
                }
            }
            return 0;
        };
        
        NtOpenThread_idx = get_syscall_number("NtOpenThread");
        NtSuspendThread_idx = get_syscall_number("NtSuspendThread");
        NtResumeThread_idx = get_syscall_number("NtResumeThread");
        NtGetContextThread_idx = get_syscall_number("NtGetContextThread");
        NtSetContextThread_idx = get_syscall_number("NtSetContextThread");
        NtClose_idx = get_syscall_number("NtClose");
        NtDelayExecution_idx = get_syscall_number("NtDelayExecution");
        
        indices_resolved = (NtOpenThread_idx && NtSuspendThread_idx && NtResumeThread_idx &&
                           NtGetContextThread_idx && NtSetContextThread_idx && NtClose_idx &&
                           syscall_instruction_addr);
        return indices_resolved;
    }
}

namespace anti_debug {
    __forceinline bool quick_check() {
        volatile std::uint64_t start = __rdtsc();
        _mm_lfence();
        volatile int x = 1;
        x += 1;
        (void)x;
        _mm_lfence();
        volatile std::uint64_t elapsed = __rdtsc() - start;
        return elapsed < 0x100000;
    }
    
    __forceinline bool check_hardware_bp() {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                return false;
            }
        }
        return true;
    }
}

bool voyager::device_t::connect() noexcept {
    SPOOF_FUNC;
    
    if (is_connected()) {
        return true;
    }

    std::wstring device_path = device_names_um::get_device_path();

    driver_handle_ = CreateFileW(
        device_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (!is_connected()) {
        return false;
    }

    session_key_ = static_cast<std::uint32_t>(__rdtsc() ^ 0xDEADC0DEu);
    if (session_key_ == 0) session_key_ = 0x12345678u;

    if (!send_heartbeat()) {
        CloseHandle(driver_handle_);
        driver_handle_ = INVALID_HANDLE_VALUE;
        session_key_ = 0;
        return false;
    }

    return true;
}

void voyager::device_t::disconnect() noexcept {
    SPOOF_FUNC;
    
    if (shellcode_address_ != 0 && process_id_ != 0) {
        free_memory(shellcode_address_);
        shellcode_address_ = 0;
    }
    
    if (is_connected()) {
        CloseHandle(driver_handle_);
        driver_handle_ = INVALID_HANDLE_VALUE;
    }
    
    process_id_ = 0;
    base_address_ = 0;
    dtb_ = 0;
    spoof_gadget_ = 0;
    session_key_ = 0;
    last_heartbeat_tsc_ = 0;
}

std::uint32_t voyager::device_t::find_process(const char* process_name) noexcept {
    SPOOF_FUNC;
    
    if (!process_name || std::strlen(process_name) == 0 || std::strlen(process_name) >= MAX_PATH) {
        return 0;
    }

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    std::uint32_t found_pid = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            const size_t exe_len = std::wcslen(entry.szExeFile);
            const size_t target_len = std::strlen(process_name);

            if (exe_len == target_len) {
                bool match = true;
                for (std::size_t i = 0; i < exe_len; ++i) {
                    if (std::towlower(static_cast<wint_t>(entry.szExeFile[i])) !=
                        std::towlower(static_cast<wint_t>(static_cast<unsigned char>(process_name[i])))) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    found_pid = entry.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (found_pid != 0) {
        if (shellcode_address_ != 0 && process_id_ != 0 && process_id_ != found_pid) {
            free_memory(shellcode_address_);
            shellcode_address_ = 0;
        }
        process_id_ = found_pid;
        dtb_ = 0;
        base_address_ = 0;
        spoof_gadget_ = 0;
    }

    return found_pid;
}

bool voyager::device_t::send_heartbeat() noexcept {
    SPOOF_FUNC;
    
    if (!is_connected()) {
        return false;
    }

    detail::heartbeat_request hb{};
    hb.magic = detail::get_heartbeat_magic();
    hb.session_key = session_key_;
    hb.timestamp = __rdtsc();
    hb.response = 0;

    DWORD ioctlCode = ioctl_codes::HB();

    DWORD bytes_returned = 0;
    BOOL result = DeviceIoControl(
        driver_handle_,
        ioctlCode,
        &hb,
        sizeof(hb),
        &hb,
        sizeof(hb),
        &bytes_returned,
        nullptr
    );

    if (result && bytes_returned >= sizeof(hb) && hb.response != 0) {
        last_heartbeat_tsc_ = __rdtsc();
        return true;
    }

    return false;
}

bool voyager::device_t::refresh_heartbeat() noexcept {
    std::uint64_t current_tsc = __rdtsc();
    if (last_heartbeat_tsc_ == 0 || (current_tsc - last_heartbeat_tsc_) > detail::HEARTBEAT_REFRESH_INTERVAL) {
        return send_heartbeat();
    }
    return true;
}

void voyager::device_t::solve_dtb() noexcept {
    SPOOF_FUNC;
    
    if (process_id_ == 0) {
        dtb_ = 0;
        return;
    }

    detail::dtb_solve req{};
    req.pid = process_id_;
    req.padding = 0;
    req.dtb = 0;
    
    if (send_request(ioctl_codes::DTB(), &req, sizeof(req)) && req.dtb != 0) {
        dtb_ = req.dtb;
    } else {
        dtb_ = 0;
    }
}

std::uint64_t voyager::device_t::find_image() noexcept {
    SPOOF_FUNC;
    
    std::uint64_t image_address = 0;

    detail::base_address_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.out_address = &image_address;

    if (send_request(ioctl_codes::BASE(), &req, sizeof(req))) {
        base_address_ = image_address;
    }

    return image_address;
}

std::size_t voyager::device_t::read_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;
    
    if (!buffer || size == 0 || !is_connected() || dtb_ == 0) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }

    detail::physical_request req{};
    req.pid = process_id_;
    req.dtb = dtb_;
    req.address = reinterpret_cast<void*>(address);
    req.buffer = buffer;
    req.size = size;
    req.ret_size = 0;
    req.should_write = 0;
    std::memset(req.padding_2, 0, sizeof(req.padding_2));

    if (send_request(ioctl_codes::PHYS(), &req, sizeof(req))) {
        return req.ret_size;
    }
    
    return 0;
}

std::size_t voyager::device_t::write_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;
    
    if (!buffer || size == 0 || !is_connected() || dtb_ == 0) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }

    detail::physical_request req{};
    req.pid = process_id_;
    req.dtb = dtb_;
    req.address = reinterpret_cast<void*>(address);
    req.buffer = const_cast<void*>(buffer);
    req.size = size;
    req.ret_size = 0;
    req.should_write = 1;
    std::memset(req.padding_2, 0, sizeof(req.padding_2));

    if (send_request(ioctl_codes::PHYS(), &req, sizeof(req))) {
        return req.ret_size;
    }
    return 0;
}

void voyager::device_t::move_mouse(std::int32_t input_x, std::int32_t input_y, std::uint32_t mouse_flags) {
    SPOOF_FUNC;
    
    if (!is_connected()) {
        return;
    }

    detail::mouse_request req{};
    req.inputX = input_x;
    req.inputY = input_y;
    req.buttonFlags = mouse_flags;

    send_request(ioctl_codes::MM(), &req, sizeof(req));
}

void voyager::device_t::send_key(unsigned short button) {
    SPOOF_FUNC;
    
    if (!is_connected()) {
        return;
    }

    detail::mouse_request req{};
    req.inputX = 0;
    req.inputY = 0;
    req.buttonFlags = static_cast<std::uint32_t>(button);

    send_request(ioctl_codes::MM(), &req, sizeof(req));
}

std::uint64_t voyager::device_t::allocate_memory(std::size_t size) noexcept {
    SPOOF_FUNC;
    
    if (!is_connected() || process_id_ == 0 || size == 0) {
        return 0;
    }

    detail::alloc_mem_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.size = size;
    req.allocated_address = 0;
    req.actual_size = 0;

    if (send_request(ioctl_codes::AM(), &req, sizeof(req)) && req.allocated_address != 0) {
        return req.allocated_address;
    }

    return 0;
}

bool voyager::device_t::free_memory(std::uint64_t address) noexcept {
    SPOOF_FUNC;
    
    if (!is_connected() || process_id_ == 0 || address == 0) {
        return false;
    }

    detail::free_mem_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.address = address;

    return send_request(ioctl_codes::FM(), &req, sizeof(req));
}

bool voyager::device_t::ensure_shellcode_allocated() noexcept {
    SPOOF_FUNC;
    
    if (shellcode_address_ != 0) {
        return true;
    }

    shellcode_address_ = allocate_memory(detail::SHELLCODE_ALLOC_SIZE);
    return shellcode_address_ != 0;
}

bool voyager::device_t::find_spoof_gadget() noexcept {
    SPOOF_FUNC;
    
    if (spoof_gadget_ != 0) {
        return true;
    }

    if (base_address_ == 0 || dtb_ == 0) {
        return false;
    }

    std::uint8_t dos_header[64] = {};
    if (read_raw(base_address_, dos_header, sizeof(dos_header)) != sizeof(dos_header)) {
        return false;
    }

    if (dos_header[0] != 'M' || dos_header[1] != 'Z') {
        return false;
    }

    std::uint32_t e_lfanew = *reinterpret_cast<std::uint32_t*>(&dos_header[60]);
    if (e_lfanew > 0x1000) {
        return false;
    }

    std::uint8_t nt_headers[264] = {};
    if (read_raw(base_address_ + e_lfanew, nt_headers, sizeof(nt_headers)) != sizeof(nt_headers)) {
        return false;
    }

    if (nt_headers[0] != 'P' || nt_headers[1] != 'E') {
        return false;
    }

    std::uint32_t size_of_image = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 56]);
    std::uint32_t size_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 28]);
    std::uint32_t base_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 20]);

    if (size_of_code == 0 || size_of_code > size_of_image) {
        size_of_code = 0x100000;
        base_of_code = 0x1000;
    }

    std::uint64_t code_start = base_address_ + base_of_code;
    std::uint64_t search_size = (size_of_code > 0x200000) ? 0x200000 : size_of_code;

    constexpr std::size_t chunk_size = 0x10000;
    std::uint8_t buffer[chunk_size];

    for (std::uint64_t offset = 0; offset < search_size; offset += chunk_size - 16) {
        std::size_t to_read = chunk_size;
        if (offset + to_read > search_size) {
            to_read = static_cast<std::size_t>(search_size - offset);
        }

        if (read_raw(code_start + offset, buffer, to_read) != to_read) {
            continue;
        }

        for (std::size_t i = 0; i < to_read - 2; ++i) {
            if (buffer[i] == 0xFF && buffer[i + 1] == 0x23) {
                spoof_gadget_ = code_start + offset + i;
                return true;
            }
        }

        for (std::size_t i = 0; i < to_read - 2; ++i) {
            if (buffer[i] == 0xFF && buffer[i + 1] == 0xE3) {
                spoof_gadget_ = code_start + offset + i;
                return true;
            }
        }

        for (std::size_t i = 0; i < to_read - 2; ++i) {
            if (buffer[i] == 0xFF && buffer[i + 1] == 0x25) {
                spoof_gadget_ = code_start + offset + i;
                return true;
            }
        }
    }

    spoof_gadget_ = base_address_ + base_of_code + 0x100;
    return true;
}

std::uint64_t voyager::device_t::find_gadget(const char* pattern, std::size_t pattern_size) noexcept {
    SPOOF_FUNC;
    
    if (!pattern || pattern_size == 0 || base_address_ == 0 || dtb_ == 0) {
        return 0;
    }

    std::uint8_t dos_header[64] = {};
    if (read_raw(base_address_, dos_header, sizeof(dos_header)) != sizeof(dos_header)) {
        return 0;
    }

    std::uint32_t e_lfanew = *reinterpret_cast<std::uint32_t*>(&dos_header[60]);
    
    std::uint8_t nt_headers[264] = {};
    if (read_raw(base_address_ + e_lfanew, nt_headers, sizeof(nt_headers)) != sizeof(nt_headers)) {
        return 0;
    }

    std::uint32_t size_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 28]);
    std::uint32_t base_of_code = *reinterpret_cast<std::uint32_t*>(&nt_headers[24 + 20]);

    std::uint64_t code_start = base_address_ + base_of_code;

    constexpr std::size_t chunk_size = 0x10000;
    std::uint8_t buffer[chunk_size];

    for (std::uint64_t offset = 0; offset < size_of_code; offset += chunk_size - pattern_size) {
        std::size_t to_read = chunk_size;
        if (offset + to_read > size_of_code) {
            to_read = static_cast<std::size_t>(size_of_code - offset);
        }

        if (read_raw(code_start + offset, buffer, to_read) != to_read) {
            continue;
        }

        for (std::size_t i = 0; i <= to_read - pattern_size; ++i) {
            bool found = true;
            for (std::size_t j = 0; j < pattern_size; ++j) {
                if (pattern[j] != '?' && buffer[i + j] != static_cast<std::uint8_t>(pattern[j])) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return code_start + offset + i;
            }
        }
    }

    return 0;
}

namespace thread_hijack {
    typedef NTSTATUS(NTAPI* NtSuspendThread_t)(HANDLE, PULONG);
    typedef NTSTATUS(NTAPI* NtResumeThread_t)(HANDLE, PULONG);
    typedef NTSTATUS(NTAPI* NtGetContextThread_t)(HANDLE, PCONTEXT);
    typedef NTSTATUS(NTAPI* NtSetContextThread_t)(HANDLE, PCONTEXT);
    typedef NTSTATUS(NTAPI* NtOpenThread_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);
    typedef NTSTATUS(NTAPI* NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
    typedef NTSTATUS(NTAPI* NtYieldExecution_t)();
    typedef NTSTATUS(NTAPI* NtQuerySystemTime_t)(PLARGE_INTEGER);
    
    inline NtSuspendThread_t pNtSuspendThread = nullptr;
    inline NtResumeThread_t pNtResumeThread = nullptr;
    inline NtGetContextThread_t pNtGetContextThread = nullptr;
    inline NtSetContextThread_t pNtSetContextThread = nullptr;
    inline NtOpenThread_t pNtOpenThread = nullptr;
    inline NtClose_t pNtClose = nullptr;
    inline NtDelayExecution_t pNtDelayExecution = nullptr;
    inline NtYieldExecution_t pNtYieldExecution = nullptr;
    inline NtQuerySystemTime_t pNtQuerySystemTime = nullptr;
    inline volatile bool g_initialized = false;
    inline volatile std::uint64_t g_entropy_pool = 0;
    
    extern "C" NTSTATUS do_syscall_4(std::uint32_t syscall_idx, std::uint8_t* syscall_addr, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4);
    
    __forceinline NTSTATUS syscall_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtOpenThread_idx) {
            return do_syscall_4(
                syscall_indices::NtOpenThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                static_cast<std::uint64_t>(DesiredAccess),
                reinterpret_cast<std::uint64_t>(ObjectAttributes),
                reinterpret_cast<std::uint64_t>(ClientId)
            );
        }
        return pNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    
    __forceinline NTSTATUS syscall_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtSuspendThread_idx) {
            return do_syscall_4(
                syscall_indices::NtSuspendThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(PreviousSuspendCount),
                0, 0
            );
        }
        return pNtSuspendThread(ThreadHandle, PreviousSuspendCount);
    }
    
    __forceinline NTSTATUS syscall_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtResumeThread_idx) {
            return do_syscall_4(
                syscall_indices::NtResumeThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(PreviousSuspendCount),
                0, 0
            );
        }
        return pNtResumeThread(ThreadHandle, PreviousSuspendCount);
    }
    
    __forceinline NTSTATUS syscall_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtGetContextThread_idx) {
            return do_syscall_4(
                syscall_indices::NtGetContextThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(ThreadContext),
                0, 0
            );
        }
        return pNtGetContextThread(ThreadHandle, ThreadContext);
    }
    
    __forceinline NTSTATUS syscall_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtSetContextThread_idx) {
            return do_syscall_4(
                syscall_indices::NtSetContextThread_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(ThreadHandle),
                reinterpret_cast<std::uint64_t>(ThreadContext),
                0, 0
            );
        }
        return pNtSetContextThread(ThreadHandle, ThreadContext);
    }
    
    __forceinline NTSTATUS syscall_NtClose(HANDLE Handle) {
        if (syscall_indices::syscall_instruction_addr && syscall_indices::NtClose_idx) {
            return do_syscall_4(
                syscall_indices::NtClose_idx,
                syscall_indices::syscall_instruction_addr,
                reinterpret_cast<std::uint64_t>(Handle),
                0, 0, 0
            );
        }
        return pNtClose(Handle);
    }
    
#pragma warning(push)
#pragma warning(disable: 4100)
    __forceinline NTSTATUS indirect_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
        return syscall_NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    
    __forceinline NTSTATUS indirect_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        return syscall_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
    }
    
    __forceinline NTSTATUS indirect_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
        return syscall_NtResumeThread(ThreadHandle, PreviousSuspendCount);
    }
    
    __forceinline NTSTATUS indirect_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        return syscall_NtGetContextThread(ThreadHandle, ThreadContext);
    }
    
    __forceinline NTSTATUS indirect_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
        return syscall_NtSetContextThread(ThreadHandle, ThreadContext);
    }
    
    __forceinline NTSTATUS indirect_NtClose(HANDLE Handle) {
        return syscall_NtClose(Handle);
    }
#pragma warning(pop)
    
    __forceinline void collect_entropy() {
        std::uint64_t tsc = __rdtsc();
        std::uint64_t mix = tsc ^ (tsc >> 17);
        mix *= 0xff51afd7ed558ccdULL;
        mix ^= mix >> 33;
        mix *= 0xc4ceb9fe1a85ec53ULL;
        g_entropy_pool ^= mix;
    }
    
    __forceinline bool initialize() {
        if (g_initialized) return true;
        
        collect_entropy();
        
        if (!syscall_indices::resolve_syscall_indices()) {
            return false;
        }
        
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        
        auto get_func = [&](const char* name) -> void* {
            void* addr = reinterpret_cast<void*>(GetProcAddress(ntdll, name));
            return addr;
        };
        
        pNtSuspendThread = (NtSuspendThread_t)get_func("NtSuspendThread");
        pNtResumeThread = (NtResumeThread_t)get_func("NtResumeThread");
        pNtGetContextThread = (NtGetContextThread_t)get_func("NtGetContextThread");
        pNtSetContextThread = (NtSetContextThread_t)get_func("NtSetContextThread");
        pNtOpenThread = (NtOpenThread_t)get_func("NtOpenThread");
        pNtClose = (NtClose_t)get_func("NtClose");
        pNtDelayExecution = (NtDelayExecution_t)get_func("NtDelayExecution");
        pNtYieldExecution = (NtYieldExecution_t)get_func("NtYieldExecution");
        pNtQuerySystemTime = (NtQuerySystemTime_t)get_func("NtQuerySystemTime");
        
        g_initialized = (pNtSuspendThread && pNtResumeThread && pNtGetContextThread && 
                        pNtSetContextThread && pNtOpenThread && pNtClose && pNtDelayExecution);
        
        collect_entropy();
        return g_initialized;
    }
    
    __forceinline void delay_random() {
        collect_entropy();
        if (pNtYieldExecution) {
            std::uint32_t spin = static_cast<std::uint32_t>((g_entropy_pool ^ __rdtsc()) & 0xF) + 1;
            while (spin--) {
                pNtYieldExecution();
            }
        }
    }
    
    __forceinline void delay_us(LONGLONG microseconds) {
        collect_entropy();
        LONGLONG jitter = static_cast<LONGLONG>((g_entropy_pool ^ __rdtsc()) & 0x3F);
        if (pNtDelayExecution) {
            LARGE_INTEGER interval;
            interval.QuadPart = -((microseconds + jitter) * 10);
            pNtDelayExecution(FALSE, &interval);
        }
    }
    
    __forceinline void scatter_timing() {
        collect_entropy();
        std::uint32_t pattern = static_cast<std::uint32_t>(g_entropy_pool & 0x7);
        switch (pattern) {
            case 0: _mm_pause(); break;
            case 1: delay_random(); break;
            case 2: _mm_pause(); _mm_pause(); break;
            case 3: if (pNtYieldExecution) pNtYieldExecution(); break;
            default: break;
        }
    }
}

std::uint64_t voyager::device_t::call_function(std::uint64_t function_address, std::uint64_t arg1, std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4) noexcept {
    SPOOF_FUNC;
    
    if (!is_connected() || dtb_ == 0 || function_address == 0) {
        return 0;
    }

    if (!ensure_shellcode_allocated()) {
        return 0;
    }

    if (!find_spoof_gadget()) {
        return 0;
    }
    
    if (!thread_hijack::initialize()) {
        return 0;
    }
    
    thread_hijack::scatter_timing();

    std::uint64_t context_base = shellcode_address_;

    detail::remote_call_request req{};
    req.dtb = dtb_;
    req.target_function = function_address;
    req.shellcode_address = context_base;
    req.spoof_return = spoof_gadget_;
    req.arg1 = arg1;
    req.arg2 = arg2;
    req.arg3 = arg3;
    req.arg4 = arg4;
    req.result = 0;
    req.completed = 0;
    req.original_rip = 0;
    req.trampoline_addr = 0;

    thread_hijack::scatter_timing();

    if (!send_request(ioctl_codes::RC(), &req, sizeof(req))) {
        return 0;
    }
    
    std::uint64_t code_entry = req.shellcode_address;
    
    thread_hijack::scatter_timing();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(THREADENTRY32);
    
    DWORD target_tid = 0;
    HANDLE target_thread = nullptr;
    
    DWORD current_tid = GetCurrentThreadId();
    DWORD current_pid = GetCurrentProcessId();
    std::uint32_t thread_scan_count = 0;
    constexpr std::uint32_t MAX_THREAD_SCANS = 128;
    
    std::int32_t best_priority = -999;
    HANDLE best_thread = nullptr;
    DWORD best_tid = 0;
    CONTEXT best_ctx{};
    
    DWORD main_tid = 0;
    THREADENTRY32 first_te{};
    first_te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(snapshot, &first_te)) {
        do {
            if (first_te.th32OwnerProcessID == process_id_) {
                main_tid = first_te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &first_te));
    }
    SetFilePointer(snapshot, 0, nullptr, FILE_BEGIN);
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot, &te)) {
        do {
            if (thread_scan_count++ > MAX_THREAD_SCANS) break;
            
            if (te.th32OwnerProcessID == process_id_ && te.th32ThreadID != current_tid && te.th32ThreadID != main_tid) {
                thread_hijack::scatter_timing();
                
                OBJECT_ATTRIBUTES objAttr = {};
                objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
                
                CLIENT_ID clientId = {};
                clientId.UniqueProcess = nullptr;
                clientId.UniqueThread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(te.th32ThreadID));
                
                HANDLE th = nullptr;
                NTSTATUS status = thread_hijack::indirect_NtOpenThread(
                    &th,
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    &objAttr,
                    &clientId
                );
                
                if (status >= 0 && th) {
                    thread_hijack::scatter_timing();
                    
                    ULONG prev_count = 0;
                    status = thread_hijack::indirect_NtSuspendThread(th, &prev_count);
                    
                    if (status >= 0) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_FULL;
                        
                        thread_hijack::scatter_timing();
                        
                        if (thread_hijack::indirect_NtGetContextThread(th, &ctx) >= 0) {
                            if (ctx.Rip > 0x10000 && ctx.Rip < 0x00007FFFFFFFFFFFULL &&
                                ctx.Rsp > 0x10000 && ctx.Rsp < 0x00007FFFFFFFFFFFULL &&
                                (ctx.Rsp & 0xF) == 0) {
                                std::int32_t priority = static_cast<std::int32_t>(te.tpBasePri);
                                
                                bool is_waiting = (ctx.Rip >= 0x00007FF000000000ULL);
                                if (is_waiting) {
                                    priority += 10;
                                }
                                
                                if (priority > best_priority) {
                                    if (best_thread) {
                                        thread_hijack::indirect_NtResumeThread(best_thread, nullptr);
                                        thread_hijack::indirect_NtClose(best_thread);
                                    }
                                    best_priority = priority;
                                    best_thread = th;
                                    best_tid = te.th32ThreadID;
                                    best_ctx = ctx;
                                    continue;
                                }
                            }
                        }
                        thread_hijack::indirect_NtResumeThread(th, nullptr);
                    }
                    thread_hijack::indirect_NtClose(th);
                }
            }
            
            if ((thread_scan_count & 0xF) == 0) {
                thread_hijack::scatter_timing();
            }
        } while (Thread32Next(snapshot, &te));
    }
    
    CloseHandle(snapshot);
    
    if (!best_thread || best_tid == 0) {
        return 0;
    }
    
    target_thread = best_thread;
    target_tid = best_tid;
    
    thread_hijack::scatter_timing();

    CONTEXT original_ctx = best_ctx;

    write_raw(context_base + detail::CTX_ORIGINAL_RIP, &original_ctx.Rip, sizeof(std::uint64_t));

    CONTEXT hijack_ctx = original_ctx;
    hijack_ctx.Rip = code_entry;
    
    std::uint64_t aligned_rsp = (hijack_ctx.Rsp - 0x100) & ~0xFULL;
    hijack_ctx.Rsp = aligned_rsp;
    
    thread_hijack::scatter_timing();
    
    if (thread_hijack::indirect_NtSetContextThread(target_thread, &hijack_ctx) < 0) {
        thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
        thread_hijack::indirect_NtClose(target_thread);
        return 0;
    }

    thread_hijack::collect_entropy();
    
    thread_hijack::indirect_NtResumeThread(target_thread, nullptr);

    constexpr int MAX_WAIT_ITERATIONS = 12000;
    constexpr int FAST_POLL_THRESHOLD = 500;
    constexpr int MEDIUM_POLL_THRESHOLD = 3000;
    
    std::uint64_t result = 0;
    bool completed = false;
    
    thread_hijack::collect_entropy();

    for (int i = 0; i < MAX_WAIT_ITERATIONS && !completed; ++i) {
        std::uint64_t base_delay;
        if (i < FAST_POLL_THRESHOLD) {
            base_delay = 25;
        } else if (i < MEDIUM_POLL_THRESHOLD) {
            base_delay = 75;
        } else {
            base_delay = 200;
        }
        
        std::uint64_t jitter = static_cast<std::uint64_t>((thread_hijack::g_entropy_pool ^ __rdtsc()) & 0x7F);
        thread_hijack::delay_us(static_cast<LONGLONG>(base_delay + jitter));
        
        detail::call_result_request result_req{};
        result_req.dtb = dtb_;
        result_req.result_address = context_base;
        result_req.result = 0;

        DWORD bytes_ret = 0;
        BOOL ioctl_result = DeviceIoControl(
            driver_handle_,
            ioctl_codes::CR(),
            &result_req,
            sizeof(result_req),
            &result_req,
            sizeof(result_req),
            &bytes_ret,
            nullptr
        );
        
        if (ioctl_result && bytes_ret >= sizeof(result_req)) {
            volatile std::uint64_t exec_done = 0;
            read_raw(context_base + detail::CTX_EXEC_DONE, const_cast<std::uint64_t*>(&exec_done), sizeof(exec_done));
            
            if (exec_done != 0) {
                read_raw(context_base + detail::CTX_RET_VALUE, &result, sizeof(result));
                completed = true;
                break;
            }
        }
        
        if ((i & 0x3F) == 0) {
            thread_hijack::scatter_timing();
            thread_hijack::collect_entropy();
            spoofer::scatter_execution();
        }
    }

    thread_hijack::scatter_timing();
    
    ULONG suspend_count = 0;
    thread_hijack::indirect_NtSuspendThread(target_thread, &suspend_count);
    
    thread_hijack::scatter_timing();
    
    if (!completed) {
        thread_hijack::indirect_NtSetContextThread(target_thread, &original_ctx);
    }
    
    thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
    thread_hijack::indirect_NtClose(target_thread);

    return result;
}

bool voyager::device_t::send_request(DWORD control_code, void* input, DWORD input_size) const noexcept {
    if (!is_connected() || !input || input_size == 0) {
        return false;
    }

    if (control_code != ioctl_codes::HB()) {
        std::uint64_t current_tsc = __rdtsc();
        if (last_heartbeat_tsc_ == 0 || (current_tsc - last_heartbeat_tsc_) > detail::HEARTBEAT_REFRESH_INTERVAL) {
            detail::heartbeat_request hb{};
            hb.magic = detail::get_heartbeat_magic();
            hb.session_key = session_key_;
            hb.timestamp = current_tsc;
            hb.response = 0;

            DWORD hb_bytes = 0;
            BOOL hb_result = DeviceIoControl(
                driver_handle_,
                ioctl_codes::HB(),
                &hb,
                sizeof(hb),
                &hb,
                sizeof(hb),
                &hb_bytes,
                nullptr
            );

            if (hb_result && hb_bytes >= sizeof(hb) && hb.response != 0) {
                last_heartbeat_tsc_ = __rdtsc();
            }
        }
    }

    spoofer::scatter_execution();
    thread_hijack::collect_entropy();
    
    volatile std::uint32_t pre_delay = static_cast<std::uint32_t>((__rdtsc() ^ thread_hijack::g_entropy_pool) & 0x7);
    while (pre_delay--) {
        _mm_pause();
        spoofer::compiler_barrier();
    }

    DWORD bytes_returned = 0;
    
    BOOL result = DeviceIoControl(
        driver_handle_,
        control_code,
        input,
        input_size,
        input,
        input_size,
        &bytes_returned,
        nullptr
    );

    spoofer::scatter_execution();
    thread_hijack::collect_entropy();

    return result != FALSE;
}