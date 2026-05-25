#include "comm.h"
#include <algorithm>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include "encrypt/crypter.h"
#include "spoofer/spoof.hpp"
#include "../src/standalone/src/helpers/diag_log.hpp"
#include <string>
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <intrin.h>
#include <cstdio>

#ifdef _DEBUG
#define RC_UM_DBG(fmt, ...) do { char _rc_buf[512]; _snprintf_s(_rc_buf, sizeof(_rc_buf), _TRUNCATE, "[AIDA-RC-UM] " fmt "\n", ##__VA_ARGS__); OutputDebugStringA(_rc_buf); } while(0)
#else
#define RC_UM_DBG(fmt, ...) do { char _rc_buf[512]; _snprintf_s(_rc_buf, sizeof(_rc_buf), _TRUNCATE, "[AIDA-RC-UM] " fmt "\n", ##__VA_ARGS__); OutputDebugStringA(_rc_buf); } while(0)
#endif

#pragma comment(lib, "ntdll.lib")

#ifndef _PCLIENT_ID_DEFINED
#define _PCLIENT_ID_DEFINED
typedef CLIENT_ID* PCLIENT_ID;
#endif

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif

#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace syscall_indices {
    inline std::uint32_t NtOpenThread_idx = 0;
    inline std::uint32_t NtSuspendThread_idx = 0;
    inline std::uint32_t NtResumeThread_idx = 0;
    inline std::uint32_t NtGetContextThread_idx = 0;
    inline std::uint32_t NtSetContextThread_idx = 0;
    inline std::uint32_t NtClose_idx = 0;
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

        indices_resolved = (NtOpenThread_idx && NtSuspendThread_idx && NtResumeThread_idx &&
                           NtGetContextThread_idx && NtSetContextThread_idx && NtClose_idx &&
                           syscall_instruction_addr);
        return indices_resolved;
    }
}

namespace {
    constexpr std::size_t k_staged_physical_chunk_size = 0x1000;

    class virtual_alloc_buffer_t final {
    public:
        explicit virtual_alloc_buffer_t(std::size_t size) noexcept : size_(size) {
            data_ = static_cast<std::uint8_t*>(::VirtualAlloc(
                nullptr,
                size_,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE));

            if (data_ != nullptr) {
                std::memset(data_, 0, size_);
            }
        }

        ~virtual_alloc_buffer_t() {
            if (data_ != nullptr) {
                ::VirtualFree(data_, 0, MEM_RELEASE);
            }
        }

        virtual_alloc_buffer_t(const virtual_alloc_buffer_t&) = delete;
        virtual_alloc_buffer_t& operator=(const virtual_alloc_buffer_t&) = delete;

        std::uint8_t* data() const noexcept { return data_; }
        explicit operator bool() const noexcept { return data_ != nullptr; }

    private:
        std::uint8_t* data_ = nullptr;
        std::size_t size_ = 0;
    };
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
        last_connect_error_ = GetLastError();
        return false;
    }
    last_connect_error_ = 0;
    session_key_ = static_cast<std::uint32_t>(__rdtsc() ^ 0xDEADC0DEu);
    if (session_key_ == 0) session_key_ = 0x12345678u;
    if (!send_heartbeat()) {
        DWORD hb_err = last_heartbeat_error_;
        if (hb_err == 0 && last_heartbeat_dioctl_result_) {
            if (last_heartbeat_bytes_ < sizeof(detail::heartbeat_request)) {
                hb_err = ERROR_MORE_DATA;
            } else if (last_heartbeat_response_ == 0) {
                hb_err = ERROR_DATATYPE_MISMATCH;
            }
        }
        if (hb_err == 0) {
            hb_err = ERROR_GEN_FAILURE;
        }
        last_connect_error_ = 0xBEA70000u | (hb_err & 0xFFFFu);
        CloseHandle(driver_handle_);
        driver_handle_ = INVALID_HANDLE_VALUE;
        session_key_ = 0;
        return false;
    }

    return true;
}

void voyager::device_t::disconnect() noexcept {
    SPOOF_FUNC;

    clear_process_context();

    if (is_connected()) {
        CloseHandle(driver_handle_);
        driver_handle_ = INVALID_HANDLE_VALUE;
    }

    kernel_dtb_ = 0;
    session_key_ = 0;
    last_heartbeat_tsc_ = 0;
    last_bridge_whoswho_tsc_ = 0;
    last_bridge_sentinel_tsc_ = 0;
    first_sentinel_ready_tsc_ = 0;
}

void voyager::device_t::clear_process_context() noexcept {
    SPOOF_FUNC;

    if (is_connected() && shellcode_address_ != 0 && process_id_ != 0) {
        free_memory(shellcode_address_);
    }

    shellcode_address_ = 0;
    process_id_ = 0;
    base_address_ = 0;
    dtb_ = 0;
    spoof_gadget_ = 0;
    last_failed_tid_ = 0;
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
        last_heartbeat_error_ = ERROR_INVALID_HANDLE;
        last_heartbeat_dioctl_result_ = FALSE;
        last_heartbeat_bytes_ = 0;
        last_heartbeat_response_ = 0;
        last_heartbeat_ioctl_code_ = 0;
        last_heartbeat_magic_ = 0;
        return false;
    }

    detail::heartbeat_request hb{};
    hb.magic = detail::get_heartbeat_magic();
    hb.session_key = session_key_;
    hb.timestamp = __rdtsc();
    hb.response = 0;

    DWORD ioctlCode = ioctl_codes::HB();
    last_heartbeat_ioctl_code_ = static_cast<std::uint32_t>(ioctlCode);
    last_heartbeat_magic_ = hb.magic;

    DWORD bytes_returned = 0;
    SetLastError(0);
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
    DWORD captured_error = GetLastError();

    last_heartbeat_dioctl_result_ = result;
    last_heartbeat_bytes_ = bytes_returned;
    last_heartbeat_response_ = hb.response;
    last_heartbeat_error_ = result ? 0 : captured_error;

    if (result && bytes_returned >= sizeof(hb) && hb.response != 0) {
        last_heartbeat_tsc_ = __rdtsc();
        last_bridge_whoswho_tsc_ = hb.whoswho_tsc;
        last_bridge_sentinel_tsc_ = hb.sentinel_tsc;
        if (hb.sentinel_tsc != 0 && first_sentinel_ready_tsc_ == 0)
            first_sentinel_ready_tsc_ = hb.sentinel_tsc;
        return true;
    }

    return false;
}

bool voyager::device_t::refresh_heartbeat() noexcept {
    std::uint64_t current_tsc = __rdtsc();
    std::uint64_t elapsed = (last_heartbeat_tsc_ == 0) ? 0 : (current_tsc - last_heartbeat_tsc_);
    if (last_heartbeat_tsc_ == 0 || elapsed > detail::HEARTBEAT_REFRESH_INTERVAL) {
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

void voyager::device_t::solve_kernel_dtb() noexcept {
    SPOOF_FUNC;

    detail::dtb_solve req{};
    req.pid = 4;
    req.padding = 0;
    req.dtb = 0;

    if (send_request(ioctl_codes::DTB(), &req, sizeof(req)) && req.dtb != 0) {
        kernel_dtb_ = req.dtb;
    } else {
        if (dtb_ != 0) {
            kernel_dtb_ = dtb_;
        } else {
            kernel_dtb_ = 0;
        }
    }
}

std::size_t voyager::device_t::transfer_physical_read(
    std::uint32_t pid,
    std::uint64_t dtb,
    std::uint64_t address,
    void* buffer,
    std::size_t size) const noexcept {
    SPOOF_FUNC;

    if (!buffer || size == 0 || !is_connected() || dtb == 0) {
        return 0;
    }

    const std::size_t staging_size = (size < k_staged_physical_chunk_size)
        ? size
        : k_staged_physical_chunk_size;
    virtual_alloc_buffer_t staging(staging_size);
    if (!staging) {
        return 0;
    }

    auto* destination = static_cast<std::uint8_t*>(buffer);
    std::size_t total_read = 0;

    while (total_read < size) {
        const std::size_t chunk_size = (size - total_read < k_staged_physical_chunk_size)
            ? (size - total_read)
            : k_staged_physical_chunk_size;

        std::memset(staging.data(), 0, chunk_size);

        detail::physical_request req{};
        req.pid = pid;
        req.dtb = dtb;
        req.address = reinterpret_cast<void*>(address + total_read);
        req.buffer = staging.data();
        req.size = chunk_size;
        req.ret_size = 0;
        req.should_write = 0;
        std::memset(req.padding_2, 0, sizeof(req.padding_2));

        if (!send_request(ioctl_codes::PHYS(), &req, sizeof(req))) {
            break;
        }

        const std::size_t bytes_read = (req.ret_size <= chunk_size) ? req.ret_size : chunk_size;
        if (bytes_read == 0) {
            break;
        }

        std::memcpy(destination + total_read, staging.data(), bytes_read);
        total_read += bytes_read;

        if (bytes_read < chunk_size) {
            break;
        }
    }

    return total_read;
}

std::size_t voyager::device_t::transfer_physical_write(
    std::uint32_t pid,
    std::uint64_t dtb,
    std::uint64_t address,
    const void* buffer,
    std::size_t size) const noexcept {
    SPOOF_FUNC;

    if (!buffer || size == 0 || !is_connected() || dtb == 0) {
        return 0;
    }

    const std::size_t staging_size = (size < k_staged_physical_chunk_size)
        ? size
        : k_staged_physical_chunk_size;
    virtual_alloc_buffer_t staging(staging_size);
    if (!staging) {
        return 0;
    }

    const auto* source = static_cast<const std::uint8_t*>(buffer);
    std::size_t total_written = 0;

    while (total_written < size) {
        const std::size_t chunk_size = (size - total_written < k_staged_physical_chunk_size)
            ? (size - total_written)
            : k_staged_physical_chunk_size;

        std::memcpy(staging.data(), source + total_written, chunk_size);

        detail::physical_request req{};
        req.pid = pid;
        req.dtb = dtb;
        req.address = reinterpret_cast<void*>(address + total_written);
        req.buffer = staging.data();
        req.size = chunk_size;
        req.ret_size = 0;
        req.should_write = 1;
        std::memset(req.padding_2, 0, sizeof(req.padding_2));

        if (!send_request(ioctl_codes::PHYS(), &req, sizeof(req))) {
            break;
        }

        const std::size_t bytes_written = (req.ret_size <= chunk_size) ? req.ret_size : chunk_size;
        if (bytes_written == 0) {
            break;
        }

        total_written += bytes_written;
        if (bytes_written < chunk_size) {
            break;
        }
    }

    return total_written;
}

std::size_t voyager::device_t::read_kernel_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;

    if (!buffer || size == 0 || !is_connected()) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }


    std::uint64_t use_dtb = kernel_dtb_;
    if (use_dtb == 0) use_dtb = dtb_;
    if (use_dtb == 0) {
        return 0;
    }
    std::size_t result = transfer_physical_read(4, use_dtb, address, buffer, size);
    return result;
}

std::size_t voyager::device_t::write_kernel_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;

    if (!buffer || size == 0 || !is_connected()) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }

    std::uint64_t use_dtb = kernel_dtb_;
    if (use_dtb == 0) use_dtb = dtb_;
    if (use_dtb == 0) {
        return 0;
    }

    std::size_t result = transfer_physical_write(4, use_dtb, address, buffer, size);
    return result;
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

    return transfer_physical_read(process_id_, dtb_, address, buffer, size);
}

std::size_t voyager::device_t::write_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;

    if (!buffer || size == 0 || !is_connected() || dtb_ == 0) {
        return 0;
    }

    if (size > 0x10000000) {
        return 0;
    }

    return transfer_physical_write(process_id_, dtb_, address, buffer, size);
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

    bool ok = send_request(ioctl_codes::FM(), &req, sizeof(req));
    return ok;
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
            if (buffer[i] == 0xFF && buffer[i + 1] == 0xE3) {
                spoof_gadget_ = code_start + offset + i;
                return true;
            }
        }
    }

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
                std::uint64_t gadget_addr = code_start + offset + i;
                return gadget_addr;
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
    typedef NTSTATUS(NTAPI* NtAlertThread_t)(HANDLE);
    typedef BOOL(WINAPI* CancelSynchronousIo_t)(HANDLE);

    inline NtSuspendThread_t pNtSuspendThread = nullptr;
    inline NtResumeThread_t pNtResumeThread = nullptr;
    inline NtGetContextThread_t pNtGetContextThread = nullptr;
    inline NtSetContextThread_t pNtSetContextThread = nullptr;
    inline NtOpenThread_t pNtOpenThread = nullptr;
    inline NtClose_t pNtClose = nullptr;
    inline NtDelayExecution_t pNtDelayExecution = nullptr;
    inline NtYieldExecution_t pNtYieldExecution = nullptr;
    inline NtAlertThread_t pNtAlertThread = nullptr;
    inline CancelSynchronousIo_t pCancelSynchronousIo = nullptr;
    inline volatile bool g_initialized = false;
    inline volatile std::uint64_t g_entropy_pool = 0;


    inline std::uint64_t g_ntdll_base = 0;
    inline std::uint64_t g_ntdll_size = 0;

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
        pNtAlertThread = (NtAlertThread_t)get_func("NtAlertThread");


        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32) {
            pCancelSynchronousIo = reinterpret_cast<CancelSynchronousIo_t>(
                GetProcAddress(kernel32, "CancelSynchronousIo"));
        }


        {
            std::uint8_t* base = reinterpret_cast<std::uint8_t*>(ntdll);
            g_ntdll_base = reinterpret_cast<std::uint64_t>(base);
            g_ntdll_size = 0;

            __try {
                PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE) {
                        g_ntdll_size = static_cast<std::uint64_t>(nt->OptionalHeader.SizeOfImage);
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {

            }

            if (g_ntdll_size == 0) {
                g_ntdll_size = 0x200000;
            }
        }

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


    inline std::uint64_t g_tsc_ticks_per_us = 0;

    __forceinline void calibrate_tsc() {
        if (g_tsc_ticks_per_us != 0) return;

        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);


        LARGE_INTEGER qpc_start, qpc_end;
        QueryPerformanceCounter(&qpc_start);
        std::uint64_t tsc_start = __rdtsc();


        for (;;) {
            QueryPerformanceCounter(&qpc_end);
            if ((qpc_end.QuadPart - qpc_start.QuadPart) * 1000 >= freq.QuadPart)
                break;
            _mm_pause();
        }

        std::uint64_t tsc_end = __rdtsc();
        std::uint64_t tsc_elapsed = tsc_end - tsc_start;
        std::uint64_t us_elapsed = static_cast<std::uint64_t>(
            (qpc_end.QuadPart - qpc_start.QuadPart) * 1000000 / freq.QuadPart);

        if (us_elapsed > 0) {
            g_tsc_ticks_per_us = tsc_elapsed / us_elapsed;
        }
        if (g_tsc_ticks_per_us == 0) {
            g_tsc_ticks_per_us = 3000;
        }
    }

    __forceinline void delay_us_rdtsc(std::uint64_t microseconds) {
        if (g_tsc_ticks_per_us == 0) calibrate_tsc();
        std::uint64_t target = __rdtsc() + (microseconds * g_tsc_ticks_per_us);
        while (__rdtsc() < target) {
            _mm_pause();
        }
    }


    __forceinline void force_wake_thread(HANDLE thread_handle) {


        if (pCancelSynchronousIo) {
            pCancelSynchronousIo(thread_handle);
        }


        if (pNtAlertThread) {
            pNtAlertThread(thread_handle);
        }
    }


    __forceinline bool is_rip_in_ntdll(std::uint64_t rip) {
        if (g_ntdll_base == 0) return false;
        return (rip >= g_ntdll_base && rip < g_ntdll_base + g_ntdll_size);
    }
}

std::uint64_t voyager::device_t::call_function(std::uint64_t function_address, std::uint64_t arg1, std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4) noexcept {
    SPOOF_FUNC;

    RC_UM_DBG("call_function: ENTER target=0x%llX args=(0x%llX, 0x%llX, 0x%llX, 0x%llX)",
        function_address, arg1, arg2, arg3, arg4);

    if (!is_connected() || dtb_ == 0 || function_address == 0) {
        RC_UM_DBG("call_function: ABORT connected=%d dtb=0x%llX func=0x%llX",
            is_connected() ? 1 : 0, dtb_, function_address);
        return 0;
    }

    if (!ensure_shellcode_allocated()) {
        RC_UM_DBG("call_function: ensure_shellcode_allocated FAILED");
        return 0;
    }
    if (!find_spoof_gadget()) {
        RC_UM_DBG("call_function: find_spoof_gadget FAILED");
        return 0;
    }
    if (!thread_hijack::initialize()) {
        RC_UM_DBG("call_function: thread_hijack::initialize FAILED");
        return 0;
    }


    ntdll_base_ = thread_hijack::g_ntdll_base;
    ntdll_size_ = thread_hijack::g_ntdll_size;


    thread_hijack::calibrate_tsc();


    constexpr int MAX_ATTEMPTS = 5;
    DWORD blacklist[MAX_ATTEMPTS] = {};
    int blacklist_count = 0;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        if (attempt > 0) {
            RC_UM_DBG("call_function: RETRY attempt=%d/%d blacklisted=%d tids",
                attempt + 1, MAX_ATTEMPTS, blacklist_count);

            thread_hijack::delay_us(5000);
        }

        bool attempt_completed = false;
        std::uint64_t result = call_function_attempt(
            function_address, arg1, arg2, arg3, arg4,
            blacklist, blacklist_count, attempt_completed);

        if (attempt_completed) {
            return result;
        }


        if (last_failed_tid_ != 0 && blacklist_count < MAX_ATTEMPTS) {
            blacklist[blacklist_count++] = last_failed_tid_;
        }


        if (shellcode_address_ == 0) {
            if (!ensure_shellcode_allocated()) {
                RC_UM_DBG("call_function: re-alloc FAILED on attempt %d", attempt + 1);
                return 0;
            }
        }
    }

    RC_UM_DBG("call_function: ALL %d attempts FAILED for target=0x%llX", MAX_ATTEMPTS, function_address);
    return 0;
}


bool voyager::device_t::send_poll_request(void* input, DWORD input_size) const noexcept {
    DWORD bytes_ret = 0;
    BOOL ok = DeviceIoControl(
        driver_handle_,
        ioctl_codes::CR(),
        input, input_size,
        input, input_size,
        &bytes_ret, nullptr);

    if (ok && bytes_ret >= input_size) {
        return true;
    }


    DWORD err = GetLastError();
    if (!ok && err != ERROR_IO_PENDING && err != ERROR_IO_INCOMPLETE) {
        force_heartbeat();


        bytes_ret = 0;
        ok = DeviceIoControl(
            driver_handle_,
            ioctl_codes::CR(),
            input, input_size,
            input, input_size,
            &bytes_ret, nullptr);

        if (ok && bytes_ret >= input_size) {
            return true;
        }
    }

    return false;
}


bool voyager::device_t::force_heartbeat() const noexcept {
    detail::heartbeat_request hb{};
    hb.magic = detail::get_heartbeat_magic();
    hb.session_key = session_key_;
    hb.timestamp = __rdtsc();
    hb.response = 0;

    DWORD hb_bytes = 0;
    BOOL hb_result = DeviceIoControl(
        driver_handle_,
        ioctl_codes::HB(),
        &hb, sizeof(hb),
        &hb, sizeof(hb),
        &hb_bytes, nullptr);

    if (hb_result && hb_bytes >= sizeof(hb) && hb.response != 0) {
        last_heartbeat_tsc_ = __rdtsc();
        return true;
    }
    return false;
}


std::uint64_t voyager::device_t::call_function_attempt(
    std::uint64_t function_address,
    std::uint64_t arg1, std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4,
    const DWORD* blacklist, int blacklist_count,
    bool& out_completed) noexcept
{
    SPOOF_FUNC;

    out_completed = false;

    RC_UM_DBG("call_function: shellcode_addr=0x%llX spoof_gadget=0x%llX dtb=0x%llX",
        shellcode_address_, spoof_gadget_, dtb_);

    thread_hijack::scatter_timing();

    std::uint64_t context_base = shellcode_address_;

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
    std::uint32_t thread_scan_count = 0;
    constexpr std::uint32_t MAX_TARGET_THREAD_SCANS = 64;

    std::int32_t best_priority = -999;
    HANDLE best_thread = nullptr;
    DWORD best_tid = 0;
    CONTEXT best_ctx{};

    if (Thread32First(snapshot, &te)) {
        do {
            if (thread_scan_count >= MAX_TARGET_THREAD_SCANS) break;

            if (te.th32OwnerProcessID == process_id_ && te.th32ThreadID != current_tid) {

                if (last_failed_tid_ != 0 && te.th32ThreadID == last_failed_tid_) {
                    continue;
                }

                if (last_hijacked_tid_ != 0 && te.th32ThreadID == last_hijacked_tid_) {
                    continue;
                }


                bool is_blacklisted = false;
                for (int b = 0; b < blacklist_count; ++b) {
                    if (blacklist[b] == te.th32ThreadID) {
                        is_blacklisted = true;
                        break;
                    }
                }
                if (is_blacklisted) continue;

                thread_scan_count++;
                thread_hijack::scatter_timing();

                OBJECT_ATTRIBUTES objAttr = {};
                objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

                CLIENT_ID clientId = {};
                clientId.UniqueProcess = nullptr;
                clientId.UniqueThread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(te.th32ThreadID));

                HANDLE th = nullptr;
                NTSTATUS status = thread_hijack::indirect_NtOpenThread(
                    &th,
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | THREAD_TERMINATE,
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
                                (ctx.Rsp & 0x7) == 0) {
                                std::int32_t priority = static_cast<std::int32_t>(te.tpBasePri);


                                bool in_ntdll = thread_hijack::is_rip_in_ntdll(ctx.Rip);


                                bool in_target = (base_address_ != 0 &&
                                                  ctx.Rip >= base_address_ &&
                                                  ctx.Rip < base_address_ + 0x100000);

                                if (in_target) {
                                    priority += 20;
                                } else if (in_ntdll) {
                                    priority -= 20;
                                }


                                if (prev_count == 0) {
                                    priority += 5;
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
        RC_UM_DBG("call_function: NO suitable thread found (scanned %u)", thread_scan_count);
        return 0;
    }

    target_thread = best_thread;
    target_tid = best_tid;

    bool is_in_ntdll = thread_hijack::is_rip_in_ntdll(best_ctx.Rip);
    bool is_in_target = (base_address_ != 0 && best_ctx.Rip >= base_address_ && best_ctx.Rip < base_address_ + 0x100000);
    RC_UM_DBG("call_function: SELECTED tid=%u rip=0x%llX rsp=0x%llX priority=%d in_ntdll=%d in_target=%d scanned=%u",
        target_tid, best_ctx.Rip, best_ctx.Rsp, best_priority, is_in_ntdll ? 1 : 0, is_in_target ? 1 : 0, thread_scan_count);

    thread_hijack::scatter_timing();

    CONTEXT original_ctx = best_ctx;


    constexpr std::uint64_t EXEC_DONE_OFFSET = 0x50;
    write<std::uint64_t>(context_base + EXEC_DONE_OFFSET, 0);

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
    req.original_rip = original_ctx.Rip;
    req.trampoline_addr = 0;

    thread_hijack::scatter_timing();

    if (!send_request(ioctl_codes::RC(), &req, sizeof(req))) {
        thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
        thread_hijack::indirect_NtClose(target_thread);
        return 0;
    }

    std::uint64_t code_entry = req.shellcode_address;


    CONTEXT hijack_ctx = original_ctx;
    hijack_ctx.Rip = code_entry;

    std::uint64_t shellcode_rsp = ((hijack_ctx.Rsp - 0x108) & ~0xFULL) + 0x8;
    hijack_ctx.Rsp = shellcode_rsp;

    RC_UM_DBG("call_function: HIJACK rip=0x%llX->0x%llX rsp=0x%llX->0x%llX",
        original_ctx.Rip, hijack_ctx.Rip, original_ctx.Rsp, hijack_ctx.Rsp);

    thread_hijack::scatter_timing();

    NTSTATUS set_status = thread_hijack::indirect_NtSetContextThread(target_thread, &hijack_ctx);
    if (set_status < 0) {
        RC_UM_DBG("call_function: NtSetContextThread FAILED status=0x%08X", (unsigned)set_status);
        thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
        thread_hijack::indirect_NtClose(target_thread);
        return 0;
    }
    RC_UM_DBG("call_function: NtSetContextThread OK, resuming tid=%u", target_tid);
    last_hijacked_tid_ = target_tid;

    thread_hijack::collect_entropy();

    thread_hijack::indirect_NtResumeThread(target_thread, nullptr);


    if (is_in_ntdll) {
        thread_hijack::force_wake_thread(target_thread);
        RC_UM_DBG("call_function: force_wake sent to tid=%u (was in ntdll)", target_tid);
    }


    constexpr int MAX_WAIT_ITERATIONS = 6000;
    constexpr int FAST_POLL_THRESHOLD = 500;
    constexpr int MEDIUM_POLL_THRESHOLD = 2000;

    std::uint64_t result = 0;
    bool completed = false;
    int consecutive_poll_failures = 0;

    RC_UM_DBG("call_function: POLLING start (max=%d iterations) ctx_base=0x%llX",
        MAX_WAIT_ITERATIONS, context_base);

    thread_hijack::collect_entropy();


    force_heartbeat();

    int last_log_iteration = 0;
    for (int i = 0; i < MAX_WAIT_ITERATIONS && !completed; ++i) {


        if (i < FAST_POLL_THRESHOLD) {

            thread_hijack::delay_us_rdtsc(25);
        } else if (i < MEDIUM_POLL_THRESHOLD) {

            thread_hijack::delay_us_rdtsc(100);
        } else {

            std::uint64_t jitter = static_cast<std::uint64_t>((thread_hijack::g_entropy_pool ^ __rdtsc()) & 0x7F);
            thread_hijack::delay_us(static_cast<LONGLONG>(500 + jitter));
        }


        detail::call_result_request result_req{};
        result_req.dtb = dtb_;
        result_req.result_address = context_base;
        result_req.result = 0;
        result_req.completed = 0;

        if (send_poll_request(&result_req, sizeof(result_req))) {
            if (result_req.completed != 0) {
                result = result_req.result;
                completed = true;
                RC_UM_DBG("call_function: COMPLETED at iteration %d result=0x%llX", i, result);
                break;
            }

            consecutive_poll_failures = 0;
            if (i - last_log_iteration >= 2000) {
                RC_UM_DBG("call_function: POLLING iter=%d still waiting (exec_done=0)", i);
                last_log_iteration = i;
            }
        } else {


            ++consecutive_poll_failures;
            if (consecutive_poll_failures >= 16) {
                RC_UM_DBG("call_function: POLL FAILED 16x consecutively, iter=%d", i);
                break;
            }
        }


        if ((i & 0xF) == 0) {
            thread_hijack::collect_entropy();
            spoofer::scatter_execution();
            refresh_heartbeat();


            if ((i & 0xFF) == 0 && i > 0 && is_in_ntdll) {
                thread_hijack::force_wake_thread(target_thread);
            }
        }
    }


    thread_hijack::scatter_timing();

    ULONG suspend_count = 0;
    thread_hijack::indirect_NtSuspendThread(target_thread, &suspend_count);
    thread_hijack::scatter_timing();

    if (!completed) {
        RC_UM_DBG("call_function: TIMEOUT after %d iterations, tid=%u rip_was=0x%llX target=0x%llX",
            MAX_WAIT_ITERATIONS, target_tid, original_ctx.Rip, function_address);


        CONTEXT check_ctx{};
        check_ctx.ContextFlags = CONTEXT_FULL;
        if (thread_hijack::indirect_NtGetContextThread(target_thread, &check_ctx) >= 0) {
            RC_UM_DBG("call_function: TIMEOUT current_rip=0x%llX current_rsp=0x%llX (expected_rip=0x%llX)",
                check_ctx.Rip, check_ctx.Rsp, code_entry);
        }


        {
            std::uint64_t diag_done = read<std::uint64_t>(context_base + 0x50);
            std::uint64_t diag_ret = read<std::uint64_t>(context_base + 0x30);
            std::uint64_t diag_rsp = read<std::uint64_t>(context_base + 0x38);
            RC_UM_DBG("call_function: TIMEOUT diag exec_done=0x%llX ret_value=0x%llX saved_rsp=0x%llX",
                diag_done, diag_ret, diag_rsp);
        }

        thread_hijack::indirect_NtSetContextThread(target_thread, &original_ctx);
        last_failed_tid_ = target_tid;


    } else {
        RC_UM_DBG("call_function: SUCCESS result=0x%llX tid=%u target=0x%llX",
            result, target_tid, function_address);
        thread_hijack::indirect_NtSetContextThread(target_thread, &original_ctx);
        last_failed_tid_ = 0;
        last_hijacked_tid_ = 0;
    }

    thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
    thread_hijack::indirect_NtClose(target_thread);

    out_completed = completed;
    return result;
}

bool voyager::device_t::send_request(DWORD control_code, void* input, DWORD input_size) const noexcept {
    if (!is_connected() || !input || input_size == 0) {
        diag::log_tagged_fmt("comm",
            "send_request REJECT ioctl=0x%08X input_size=%u connected=%d input=%p handle=0x%llX pid=%u",
            control_code, input_size, is_connected() ? 1 : 0, input,
            reinterpret_cast<unsigned long long>(driver_handle_), process_id_);
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
                last_bridge_whoswho_tsc_ = hb.whoswho_tsc;
                last_bridge_sentinel_tsc_ = hb.sentinel_tsc;
                if (hb.sentinel_tsc != 0 && first_sentinel_ready_tsc_ == 0)
                    first_sentinel_ready_tsc_ = hb.sentinel_tsc;
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
    const ULONGLONG ioctl_start = GetTickCount64();

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

    if (!result) {
        DWORD err = GetLastError();
        RC_UM_DBG("send_request FAILED ioctl=0x%08X input_size=%u err=%lu handle=0x%llX",
            control_code, input_size, err, reinterpret_cast<unsigned long long>(driver_handle_));
        diag::log_tagged_fmt("comm",
            "send_request FAILED ioctl=0x%08X input_size=%u bytes=%lu err=%lu handle=0x%llX pid=%u session=%d elapsed_ms=%llu",
            control_code, input_size, static_cast<unsigned long>(bytes_returned), err,
            reinterpret_cast<unsigned long long>(driver_handle_), process_id_,
            session_key_ != 0 ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - ioctl_start));
    } else if (bytes_returned == 0 || (GetTickCount64() - ioctl_start) > 250) {
        diag::log_tagged_fmt("comm",
            "send_request OK_SUSPICIOUS ioctl=0x%08X input_size=%u bytes=%lu handle=0x%llX pid=%u session=%d elapsed_ms=%llu",
            control_code, input_size, static_cast<unsigned long>(bytes_returned),
            reinterpret_cast<unsigned long long>(driver_handle_), process_id_,
            session_key_ != 0 ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - ioctl_start));
    }

    spoofer::scatter_execution();
    thread_hijack::collect_entropy();

    return result != FALSE;
}


bool voyager::device_t::get_thread_context(std::uint32_t tid, thread_context& ctx) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0) {
        RC_UM_DBG("TCTX get skip connected=%d pid=%u tid=%u", is_connected() ? 1 : 0, process_id_, tid);
        return false;
    }

    voyager::detail::thread_ctx_request req{};
    req.pid = process_id_;
    req.tid = tid;
    req.should_set = 0;
    req.register_mask = 0;

    bool ok = send_request(ioctl_codes::TCTX(), &req, sizeof(req));
    DWORD first_gle = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) {
        std::uint32_t prev_count = 0;
        bool suspended = suspend_thread(tid, &prev_count);
        DWORD suspend_gle = suspended ? ERROR_SUCCESS : GetLastError();
        if (suspended) {
            ok = send_request(ioctl_codes::TCTX(), &req, sizeof(req));
            first_gle = ok ? ERROR_SUCCESS : GetLastError();
            std::uint32_t ignored = 0;
            (void)resume_thread(tid, &ignored);
        } else {
            RC_UM_DBG("TCTX get suspend_failed pid=%u tid=%u gle=%lu", process_id_, tid, suspend_gle);
        }
    }
    if (!ok) {
        RC_UM_DBG("TCTX get send_failed pid=%u tid=%u gle=%lu ioctl=0x%08X", process_id_, tid, first_gle, ioctl_codes::TCTX());
        return false;
    }

    ctx.rax = req.rax; ctx.rbx = req.rbx; ctx.rcx = req.rcx; ctx.rdx = req.rdx;
    ctx.rsi = req.rsi; ctx.rdi = req.rdi; ctx.rbp = req.rbp; ctx.rsp = req.rsp;
    ctx.r8 = req.r8;   ctx.r9 = req.r9;   ctx.r10 = req.r10; ctx.r11 = req.r11;
    ctx.r12 = req.r12; ctx.r13 = req.r13; ctx.r14 = req.r14; ctx.r15 = req.r15;
    ctx.rip = req.rip; ctx.rflags = req.rflags;
    ctx.cs = req.cs;   ctx.ss = req.ss;
    ctx.dr0 = req.dr0; ctx.dr1 = req.dr1; ctx.dr2 = req.dr2; ctx.dr3 = req.dr3;
    ctx.dr6 = req.dr6; ctx.dr7 = req.dr7;
    ctx.kernel_gs_base = 0;

    return true;
}

bool voyager::device_t::set_thread_context(std::uint32_t tid, const thread_context& ctx, std::uint64_t register_mask) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0) {
        RC_UM_DBG("TCTX set skip connected=%d pid=%u tid=%u mask=0x%llX", is_connected() ? 1 : 0, process_id_, tid, register_mask);
        return false;
    }

    voyager::detail::thread_ctx_request req{};
    req.pid = process_id_;
    req.tid = tid;
    req.should_set = 1;
    req.register_mask = register_mask;

    req.rax = ctx.rax; req.rbx = ctx.rbx; req.rcx = ctx.rcx; req.rdx = ctx.rdx;
    req.rsi = ctx.rsi; req.rdi = ctx.rdi; req.rbp = ctx.rbp; req.rsp = ctx.rsp;
    req.r8 = ctx.r8;   req.r9 = ctx.r9;   req.r10 = ctx.r10; req.r11 = ctx.r11;
    req.r12 = ctx.r12; req.r13 = ctx.r13; req.r14 = ctx.r14; req.r15 = ctx.r15;
    req.rip = ctx.rip; req.rflags = ctx.rflags;
    req.cs = ctx.cs;   req.ss = ctx.ss;
    req.dr0 = ctx.dr0; req.dr1 = ctx.dr1; req.dr2 = ctx.dr2; req.dr3 = ctx.dr3;
    req.dr6 = ctx.dr6; req.dr7 = ctx.dr7;

    bool ok = send_request(ioctl_codes::TCTX(), &req, sizeof(req));
    DWORD first_gle = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) {
        std::uint32_t prev_count = 0;
        bool suspended = suspend_thread(tid, &prev_count);
        DWORD suspend_gle = suspended ? ERROR_SUCCESS : GetLastError();
        if (suspended) {
            ok = send_request(ioctl_codes::TCTX(), &req, sizeof(req));
            first_gle = ok ? ERROR_SUCCESS : GetLastError();
            std::uint32_t ignored = 0;
            (void)resume_thread(tid, &ignored);
        } else {
            RC_UM_DBG("TCTX set suspend_failed pid=%u tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX gle=%lu",
                process_id_,
                tid,
                register_mask,
                ctx.rip,
                ctx.rsp,
                suspend_gle);
        }
    }
    if (!ok) {
        RC_UM_DBG("TCTX set send_failed pid=%u tid=%u mask=0x%llX rip=0x%llX rsp=0x%llX gle=%lu ioctl=0x%08X",
            process_id_,
            tid,
            register_mask,
            ctx.rip,
            ctx.rsp,
            first_gle,
            ioctl_codes::TCTX());
    }
    return ok;
}

std::vector<voyager::device_t::thread_info> voyager::device_t::enumerate_threads() noexcept {
    std::vector<thread_info> result;
    if (!is_connected() || process_id_ == 0) {
        return result;
    }

    auto* req = static_cast<voyager::detail::thread_enum_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::thread_enum_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->pid = process_id_;
    req->thread_count = 0;

    if (send_request(ioctl_codes::TENUM(), req, sizeof(*req))) {
        result.reserve(req->thread_count);
        for (std::uint32_t i = 0; i < req->thread_count && i < voyager::detail::MAX_ENUM_THREADS; i++) {
            thread_info ti;
            ti.tid = req->entries[i].tid;
            ti.state = req->entries[i].state;
            ti.rip = req->entries[i].rip;
            result.push_back(ti);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::suspend_thread(std::uint32_t tid, std::uint32_t* prev_count) noexcept {
    if (!is_connected() || tid == 0) {
        return false;
    }

    voyager::detail::suspend_resume_request req{};
    req.tid = tid;
    req.should_resume = 0;

    bool ok = send_request(ioctl_codes::TSR(), &req, sizeof(req));
    if (ok && prev_count) *prev_count = req.previous_count;
    return ok;
}

bool voyager::device_t::resume_thread(std::uint32_t tid, std::uint32_t* prev_count) noexcept {
    if (!is_connected() || tid == 0) {
        return false;
    }

    voyager::detail::suspend_resume_request req{};
    req.tid = tid;
    req.should_resume = 1;

    bool ok = send_request(ioctl_codes::TSR(), &req, sizeof(req));
    if (ok && prev_count) *prev_count = req.previous_count;
    return ok;
}

bool voyager::device_t::query_memory(std::uint64_t address, memory_region_info& info) noexcept {
    if (!is_connected() || process_id_ == 0) {
        return false;
    }

    voyager::detail::query_memory_request req{};
    req.pid = process_id_;
    req.address = address;

    if (!send_request(ioctl_codes::QM(), &req, sizeof(req))) {
        return false;
    }

    info.base = req.region_base;
    info.size = req.region_size;
    info.state = req.state;
    info.protect = req.protect;
    info.type = req.type;
    info.allocation_protect = req.allocation_protect;
    info.allocation_base = req.allocation_base;

    return true;
}

bool voyager::device_t::protect_memory(std::uint64_t address, std::uint64_t size, std::uint32_t new_protect, std::uint32_t* old_protect) noexcept {
    const DWORD pm_code = ioctl_codes::PM();
    RC_UM_DBG("protect_memory: ENTER pid=%lu addr=0x%016llX size=0x%llX new=0x%08X ioctl=0x%08X connected=%d",
        static_cast<unsigned long>(process_id_),
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        static_cast<unsigned int>(new_protect),
        static_cast<unsigned int>(pm_code),
        is_connected() ? 1 : 0);

    if (!is_connected() || process_id_ == 0 || size == 0) {
        RC_UM_DBG("protect_memory: ABORT connected=%d pid=%lu size=0x%llX",
            is_connected() ? 1 : 0,
            static_cast<unsigned long>(process_id_),
            static_cast<unsigned long long>(size));
        return false;
    }

    if (address == 0) {
        RC_UM_DBG("protect_memory: ABORT address_zero");
        return false;
    }

    constexpr std::uint64_t kUserAddressMax = 0x00007FFFFFFFFFFFULL;
    if (address >= kUserAddressMax) {
        RC_UM_DBG("protect_memory: ABORT address_in_kernel_range addr=0x%016llX",
            static_cast<unsigned long long>(address));
        return false;
    }

    if (size > 0xFFFFFFFFULL) {
        RC_UM_DBG("protect_memory: ABORT size_too_large size=0x%llX",
            static_cast<unsigned long long>(size));
        return false;
    }

    const std::uint64_t end_addr = address + size;
    if (end_addr < address || end_addr >= kUserAddressMax) {
        RC_UM_DBG("protect_memory: ABORT range_overflow addr=0x%016llX size=0x%llX end=0x%016llX",
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(end_addr));
        return false;
    }

    constexpr std::uint32_t kAllowedProtect =
        0x01u | 0x02u | 0x04u | 0x08u |
        0x10u | 0x20u | 0x40u | 0x80u |
        0x100u | 0x200u | 0x400u;
    if ((new_protect & ~kAllowedProtect) != 0 || new_protect == 0) {
        RC_UM_DBG("protect_memory: ABORT bad_protect_flags new=0x%08X mask=0x%08X",
            static_cast<unsigned int>(new_protect),
            static_cast<unsigned int>(kAllowedProtect));
        return false;
    }

    voyager::detail::protect_memory_request req{};
    req.pid = process_id_;
    req.address = address;
    req.size = size;
    req.new_protect = new_protect;

    bool ok = send_request(pm_code, &req, sizeof(req));
    DWORD post_err = GetLastError();

    if (!ok) {
        RC_UM_DBG("protect_memory: send_request FAILED ioctl=0x%08X pid=%lu addr=0x%016llX size=0x%llX new=0x%08X gle=%lu",
            static_cast<unsigned int>(pm_code),
            static_cast<unsigned long>(process_id_),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(size),
            static_cast<unsigned int>(new_protect),
            static_cast<unsigned long>(post_err));
        return false;
    }

    if (old_protect) *old_protect = req.old_protect;

    RC_UM_DBG("protect_memory: OK pid=%lu addr=0x%016llX size=0x%llX new=0x%08X old=0x%08X",
        static_cast<unsigned long>(process_id_),
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        static_cast<unsigned int>(new_protect),
        static_cast<unsigned int>(req.old_protect));
    return true;
}

std::vector<voyager::detail::region_entry> voyager::device_t::enumerate_memory_regions(std::uint64_t start, std::uint64_t end_addr, bool include_all) noexcept {
    std::vector<voyager::detail::region_entry> result;
    if (!is_connected() || process_id_ == 0) {
        return result;
    }

    auto* req = static_cast<voyager::detail::enum_regions_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::enum_regions_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->pid = process_id_;
    req->include_all = include_all ? 1 : 0;
    req->start_address = start;
    req->max_address = end_addr;
    req->region_count = 0;

    if (send_request(ioctl_codes::ER(), req, sizeof(*req))) {
        result.reserve(req->region_count);
        for (std::uint32_t i = 0; i < req->region_count && i < voyager::detail::MAX_ENUM_REGIONS; i++) {
            result.push_back(req->entries[i]);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::read_peb(peb_info& info) noexcept {
    if (!is_connected() || process_id_ == 0) {
        return false;
    }

    voyager::detail::read_peb_request req{};
    req.pid = process_id_;

    if (!send_request(ioctl_codes::RPEB(), &req, sizeof(req))) {
        return false;
    }

    info.peb_address = req.peb_address;
    info.image_base = req.image_base;
    info.being_debugged = req.being_debugged;
    info.nt_global_flag = req.nt_global_flag;
    info.ldr_address = req.ldr_address;
    info.process_heap = req.process_heap;
    info.number_of_heaps = req.number_of_heaps;
    info.max_heaps = req.max_heaps;
    info.process_heaps = req.process_heaps;

    return true;
}

bool voyager::device_t::spoof_debug_flags(std::uint32_t* result_flags) noexcept {
    if (!is_connected() || process_id_ == 0) {
        return false;
    }

    voyager::detail::spoof_debug_request req{};
    req.pid = process_id_;

    bool ok = send_request(ioctl_codes::SDF(), &req, sizeof(req));
    if (ok && result_flags) *result_flags = req.result_flags;
    return ok;
}

std::uint64_t voyager::device_t::resolve_export(std::uint64_t module_base, const char* export_name) noexcept {
    if (!is_connected() || dtb_ == 0 || module_base == 0 || !export_name) {
        return 0;
    }

    voyager::detail::module_export_request req{};
    req.dtb = dtb_;
    req.module_base = module_base;
    std::memset(req.export_name, 0, sizeof(req.export_name));
    for (int i = 0; i < 127 && export_name[i]; i++) {
        req.export_name[i] = export_name[i];
    }

    if (!send_request(ioctl_codes::MEX(), &req, sizeof(req))) {
        return 0;
    }
    return req.resolved_address;
}

std::uint64_t voyager::device_t::virtual_to_physical(std::uint64_t virtual_address) noexcept {
    if (!is_connected() || dtb_ == 0 || virtual_address == 0) {
        return 0;
    }

    voyager::detail::virt_to_phys_request req{};
    req.dtb = dtb_;
    req.virtual_address = virtual_address;

    if (!send_request(ioctl_codes::V2P(), &req, sizeof(req))) {
        return 0;
    }
    return req.physical_address;
}

bool voyager::device_t::query_ssdt(ssdt_info& info) noexcept {
    std::memset(&info, 0, sizeof(info));
    if (!is_connected()) {
        return false;
    }

    voyager::detail::ssdt_query_request req{};
    if (!send_request(ioctl_codes::SSDT(), &req, sizeof(req))) {
        return false;
    }

    info.lstar = req.lstar;
    info.descriptor_address = req.descriptor_address;
    info.service_table = req.service_table;
    info.counter_table = req.counter_table;
    info.argument_table = req.argument_table;
    info.service_limit = req.service_limit;
    info.flags = req.flags;
    return info.descriptor_address != 0 && info.service_table != 0 && info.service_limit != 0;
}

bool voyager::device_t::set_hardware_breakpoint(std::uint32_t tid, int index, std::uint64_t address, int type, int size) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0 || index < 0 || index > 3) {
        return false;
    }

    thread_context ctx{};
    if (!get_thread_context(tid, ctx)) {
        return false;
    }

    switch (index) {
        case 0: ctx.dr0 = address; break;
        case 1: ctx.dr1 = address; break;
        case 2: ctx.dr2 = address; break;
        case 3: ctx.dr3 = address; break;
    }


    ctx.dr6 = 0;


    std::uint64_t dr7 = ctx.dr7;
    constexpr std::uint64_t kDr7UserMask = 0xFFFF0355ULL;
    constexpr std::uint64_t kDr7GlobalEnableMask = 0xAAULL;
    dr7 &= kDr7UserMask;
    dr7 &= ~kDr7GlobalEnableMask;


    int rw_shift = 16 + index * 4;
    int len_shift = 18 + index * 4;
    dr7 &= ~(3ULL << (index * 2));
    dr7 &= ~(3ULL << rw_shift);
    dr7 &= ~(3ULL << len_shift);


    dr7 |= (1ULL << (index * 2));


    std::uint64_t rw_val = static_cast<std::uint64_t>(type) & 3;
    dr7 |= (rw_val << rw_shift);


    std::uint64_t len_val = static_cast<std::uint64_t>(size) & 3;
    dr7 |= (len_val << len_shift);

    ctx.dr7 = dr7;

    std::uint64_t mask = (1ULL << 22) | (1ULL << 23);
    mask |= (1ULL << (18 + index));

    return set_thread_context(tid, ctx, mask);
}

bool voyager::device_t::clear_hardware_breakpoint(std::uint32_t tid, int index) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0 || index < 0 || index > 3) {
        return false;
    }

    thread_context ctx{};
    if (!get_thread_context(tid, ctx)) {
        return false;
    }

    switch (index) {
        case 0: ctx.dr0 = 0; break;
        case 1: ctx.dr1 = 0; break;
        case 2: ctx.dr2 = 0; break;
        case 3: ctx.dr3 = 0; break;
    }


    std::uint64_t dr7 = ctx.dr7;
    constexpr std::uint64_t kDr7UserMask = 0xFFFF0355ULL;
    constexpr std::uint64_t kDr7GlobalEnableMask = 0xAAULL;
    dr7 &= kDr7UserMask;
    dr7 &= ~kDr7GlobalEnableMask;
    dr7 &= ~(3ULL << (index * 2));
    dr7 &= ~(3ULL << (16 + index * 4));
    dr7 &= ~(3ULL << (18 + index * 4));
    ctx.dr6 = 0;
    ctx.dr7 = dr7;

    std::uint64_t mask = (1ULL << (18 + index)) | (1ULL << 22) | (1ULL << 23);

    return set_thread_context(tid, ctx, mask);
}


std::vector<voyager::device_t::net_connection_info> voyager::device_t::enumerate_connections(std::uint32_t filter_pid, std::uint32_t filter_protocol) noexcept {
    std::vector<net_connection_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::net_enum_conn_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_enum_conn_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->filter_pid = filter_pid;
    req->filter_protocol = filter_protocol;

    if (send_request(ioctl_codes::NCON(), req, static_cast<DWORD>(sizeof(*req)))) {
        RC_UM_DBG("enumerate_connections: ioctl OK, connection_count=%u", req->connection_count);
        result.reserve(req->connection_count);
        for (std::uint32_t i = 0; i < req->connection_count; i++) {
            net_connection_info info{};
            info.pid = req->entries[i].pid;
            info.protocol = req->entries[i].protocol;
            info.state = req->entries[i].state;
            info.local_port = req->entries[i].local_port;
            info.remote_port = req->entries[i].remote_port;
            info.address_family = req->entries[i].address_family;
            std::memcpy(info.local_addr, req->entries[i].local_addr, 16);
            std::memcpy(info.remote_addr, req->entries[i].remote_addr, 16);
            std::memcpy(info.process_path, req->entries[i].process_path, 260);
            info.process_path[259] = '\0';
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::start_capture(std::uint32_t filter_pid, std::uint32_t filter_port,
    std::uint32_t filter_protocol, const std::uint8_t* filter_ip, std::uint32_t max_payload) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 0;
    req.filter_pid = filter_pid;
    req.filter_port = filter_port;
    req.filter_protocol = filter_protocol;
    req.max_packet_bytes = max_payload;
    if (filter_ip) std::memcpy(req.filter_ip, filter_ip, 16);

    if (!send_request(ioctl_codes::NCAP(), &req, sizeof(req))) {
        RC_UM_DBG("start_capture: ioctl FAILED");
        return false;
    }
    RC_UM_DBG("start_capture: ioctl OK, capture_active=%u", req.capture_active);
    return req.capture_active != 0;
}

bool voyager::device_t::stop_capture() noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 1;

    bool ok = send_request(ioctl_codes::NCAP(), &req, sizeof(req));
    return ok;
}

bool voyager::device_t::get_capture_status(bool& active, std::uint32_t& captured, std::uint32_t& dropped) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 2;

    if (!send_request(ioctl_codes::NCAP(), &req, sizeof(req))) {
        return false;
    }

    active = req.capture_active != 0;
    captured = req.packets_captured;
    dropped = req.packets_dropped;
    return true;
}

std::vector<voyager::device_t::captured_packet> voyager::device_t::get_captured_packets(std::uint32_t max_packets) noexcept {
    std::vector<captured_packet> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::net_cap_get_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_cap_get_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->max_packets = max_packets;

    if (send_request(ioctl_codes::NCPG(), req, static_cast<DWORD>(sizeof(*req)))) {
        RC_UM_DBG("get_captured_packets: ioctl OK, packet_count=%u", req->packet_count);
        result.reserve(req->packet_count);
        for (std::uint32_t i = 0; i < req->packet_count; i++) {
            captured_packet pkt{};
            const auto& src = req->packets[i];
            pkt.timestamp = src.timestamp;
            pkt.pid = src.pid;
            pkt.protocol = src.protocol;
            pkt.direction = src.direction;
            pkt.payload_size = src.payload_size;
            pkt.local_port = src.local_port;
            pkt.remote_port = src.remote_port;
            pkt.address_family = src.address_family;
            std::memcpy(pkt.local_addr, src.local_addr, 16);
            std::memcpy(pkt.remote_addr, src.remote_addr, 16);
            if (src.payload_size > 0) {
                std::uint32_t sz = src.payload_size;
                if (sz > voyager::detail::NET_PKT_MAX_PAYLOAD) sz = static_cast<std::uint32_t>(voyager::detail::NET_PKT_MAX_PAYLOAD);
                pkt.payload.assign(src.payload, src.payload + sz);
            }
            result.push_back(std::move(pkt));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

std::vector<voyager::device_t::dns_entry> voyager::device_t::get_dns_queries(std::uint32_t filter_pid) noexcept {
    std::vector<dns_entry> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::net_dns_get_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_dns_get_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->filter_pid = filter_pid;

    if (send_request(ioctl_codes::NDNS(), req, static_cast<DWORD>(sizeof(*req)))) {
        RC_UM_DBG("get_dns_queries: ioctl OK, entry_count=%u", req->entry_count);
        result.reserve(req->entry_count);
        for (std::uint32_t i = 0; i < req->entry_count; i++) {
            dns_entry entry{};
            const auto& src = req->entries[i];
            entry.timestamp = src.timestamp;
            entry.pid = src.pid;
            entry.query_type = src.query_type;
            entry.domain = std::string(src.domain);
            std::memcpy(entry.resolved_addr, src.resolved_addr, 16);
            entry.response_code = src.response_code;
            entry.ttl = src.ttl;
            result.push_back(std::move(entry));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::add_filter_rule(std::uint32_t action, std::uint32_t direction,
    std::uint32_t protocol, std::uint32_t pid, std::uint32_t port,
    const std::uint8_t* ip_addr, const std::uint8_t* ip_mask,
    std::uint32_t* out_rule_id) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 0;
    req.action = action;
    req.direction = direction;
    req.protocol = protocol;
    req.pid = pid;
    req.port = port;
    if (ip_addr) std::memcpy(req.ip_addr, ip_addr, 16);
    if (ip_mask) std::memcpy(req.ip_mask, ip_mask, 16);

    if (!send_request(ioctl_codes::NFLT(), &req, sizeof(req))) {
        return false;
    }
    if (out_rule_id) *out_rule_id = req.rule_id;
    return true;
}

bool voyager::device_t::remove_filter_rule(std::uint32_t rule_id) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 1;
    req.rule_id = rule_id;

    bool ok = send_request(ioctl_codes::NFLT(), &req, sizeof(req));
    return ok;
}

bool voyager::device_t::clear_filter_rules() noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 2;

    bool ok = send_request(ioctl_codes::NFLT(), &req, sizeof(req));
    return ok;
}

bool voyager::device_t::get_network_stats(network_stats& stats) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::net_stats_request req{};

    if (!send_request(ioctl_codes::NSTS(), &req, sizeof(req))) {
        return false;
    }

    stats.bytes_sent = req.bytes_sent;
    stats.bytes_received = req.bytes_received;
    stats.packets_sent = req.packets_sent;
    stats.packets_received = req.packets_received;
    stats.active_connections = req.active_connections;
    stats.capture_active = req.capture_active;
    stats.total_captured = req.total_captured;
    stats.total_dropped = req.total_dropped;
    stats.total_dns_logged = req.total_dns_logged;
    stats.active_filter_rules = req.active_filter_rules;
    return true;
}


static std::string guid_to_string(const voyager::detail::GUID_COMPAT& g) {
    char buf[40];
    snprintf(buf, sizeof(buf), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

std::vector<voyager::device_t::wfp_callout_info>
voyager::device_t::enumerate_wfp_callouts(const std::string& filter_module) noexcept {
    std::vector<wfp_callout_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::wfp_callout_enum_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::wfp_callout_enum_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    if (!filter_module.empty()) {
        std::size_t len = filter_module.size();
        if (len > 63) len = 63;
        std::memcpy(req->filter_module, filter_module.c_str(), len);
    }

    if (send_request(ioctl_codes::EWFP(), req, static_cast<DWORD>(sizeof(*req)))) {
        result.reserve(req->callout_count);
        for (std::uint32_t i = 0; i < req->callout_count; i++) {
            const auto& e = req->entries[i];
            wfp_callout_info info{};
            info.classify_fn = e.classify_fn;
            info.notify_fn = e.notify_fn;
            info.flow_delete_fn = e.flow_delete_fn;
            info.owning_module_base = e.owning_module_base;
            info.callout_id = e.callout_id;
            info.layer_id = e.layer_id;
            info.flags = e.flags;
            info.callout_key_str = guid_to_string(e.callout_key);
            info.applicable_layer_str = guid_to_string(e.applicable_layer);
            info.owning_module = std::string(e.owning_module,
                strnlen(e.owning_module, sizeof(e.owning_module)));
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

std::vector<voyager::device_t::socket_info>
voyager::device_t::get_socket_handles(std::uint32_t target_pid) noexcept {
    std::vector<socket_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::socket_handle_enum_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::socket_handle_enum_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->target_pid = (target_pid != 0) ? target_pid : process_id_;

    if (send_request(ioctl_codes::GSKT(), req, static_cast<DWORD>(sizeof(*req)))) {
        result.reserve(req->socket_count);
        for (std::uint32_t i = 0; i < req->socket_count; i++) {
            const auto& e = req->entries[i];
            socket_info info{};
            info.handle_value = e.handle_value;
            info.afd_endpoint_addr = e.afd_endpoint_addr;
            info.pid = e.pid;
            info.protocol = e.protocol;
            info.state = e.state;
            info.local_port = e.local_port;
            info.remote_port = e.remote_port;
            info.address_family = e.address_family;
            std::memcpy(info.local_addr, e.local_addr, 16);
            std::memcpy(info.remote_addr, e.remote_addr, 16);
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::sniff_net_buffers_start(std::uint64_t address, std::uint32_t buf_reg,
    std::uint32_t size_reg, std::uint32_t max_captures, std::uint32_t tid, std::uint32_t bp_index) noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::sniff_net_buffers_request req{};
    req.target_address = address;
    req.buffer_reg_index = buf_reg;
    req.size_reg_index = size_reg;
    req.max_captures = max_captures;
    req.operation = 0;
    req.target_tid = tid;
    req.bp_index = bp_index;

    bool ok_sniff = send_request(ioctl_codes::SNBF(), &req, sizeof(req));
    return ok_sniff;
}

bool voyager::device_t::sniff_net_buffers_stop() noexcept {
    if (!is_connected()) {
        return false;
    }

    voyager::detail::sniff_net_buffers_request req{};
    req.operation = 1;

    bool ok = send_request(ioctl_codes::SNBF(), &req, sizeof(req));
    return ok;
}

std::vector<voyager::device_t::sniff_result>
voyager::device_t::sniff_net_buffers_get(bool& active) noexcept {
    std::vector<sniff_result> result;
    active = false;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::sniff_net_buffers_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::sniff_net_buffers_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::SNBF(), req, static_cast<DWORD>(sizeof(*req)))) {
        active = (req->active != 0);
        result.reserve(req->capture_count);
        for (std::uint32_t i = 0; i < req->capture_count; i++) {
            const auto& c = req->captures[i];
            sniff_result sr;
            sr.timestamp = c.timestamp;
            sr.thread_id = c.thread_id;
            std::uint32_t sz = c.buffer_size;
            if (sz > voyager::detail::SNIFF_MAX_BUF_SIZE)
                sz = static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_BUF_SIZE);
            sr.buffer.assign(c.buffer, c.buffer + sz);
            result.push_back(std::move(sr));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::sniff_net_buffers_store(std::uint64_t timestamp, std::uint64_t thread_id,
    const std::uint8_t* data, std::uint32_t size) noexcept {
    if (!is_connected() || !data || size == 0) {
        return false;
    }

    auto* req = static_cast<voyager::detail::sniff_net_buffers_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::sniff_net_buffers_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = 3;

    std::uint32_t copy_sz = size;
    if (copy_sz > static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_BUF_SIZE))
        copy_sz = static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_BUF_SIZE);

    req->captures[0].timestamp = timestamp;
    req->captures[0].thread_id = thread_id;
    req->captures[0].buffer_size = copy_sz;
    std::memcpy(req->captures[0].buffer, data, copy_sz);

    bool ok = send_request(ioctl_codes::SNBF(), req, static_cast<DWORD>(sizeof(*req)));
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::tcpip_connection>
voyager::device_t::dump_tcpip_connections(std::uint32_t target_pid, std::uint32_t filter_protocol) noexcept {
    std::vector<tcpip_connection> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<voyager::detail::tcpip_conn_dump_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::tcpip_conn_dump_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->target_pid = target_pid;
    req->filter_protocol = filter_protocol;

    if (send_request(ioctl_codes::DTCP(), req, static_cast<DWORD>(sizeof(*req)))) {
        result.reserve(req->connection_count);
        for (std::uint32_t i = 0; i < req->connection_count; i++) {
            const auto& e = req->entries[i];
            tcpip_connection conn{};
            conn.tcb_address = e.tcb_address;
            conn.owning_module_base = e.owning_module_base;
            conn.pid = e.pid;
            conn.protocol = e.protocol;
            conn.state = e.state;
            conn.local_port = e.local_port;
            conn.remote_port = e.remote_port;
            conn.address_family = e.address_family;
            std::memcpy(conn.local_addr, e.local_addr, 16);
            std::memcpy(conn.remote_addr, e.remote_addr, 16);
            conn.create_time = e.create_time;
            conn.bytes_in = e.bytes_in;
            conn.bytes_out = e.bytes_out;
            result.push_back(conn);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}


bool voyager::device_t::inject_packet(std::uint32_t direction, std::uint32_t protocol, std::uint32_t af,
                                       std::uint32_t src_port, std::uint32_t dst_port,
                                       const std::uint8_t* src_addr, const std::uint8_t* dst_addr,
                                       const std::uint8_t* payload, std::uint32_t payload_size,
                                       std::uint32_t tcp_flags, std::uint32_t tcp_seq, std::uint32_t tcp_ack) noexcept {
    if (!is_connected() || !payload || payload_size == 0) {
        return false;
    }
    if (payload_size > detail::INJECT_MAX_PAYLOAD) payload_size = detail::INJECT_MAX_PAYLOAD;

    auto* req = static_cast<detail::packet_inject_request*>(
        VirtualAlloc(nullptr, sizeof(detail::packet_inject_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->direction = direction;
    req->protocol = protocol;
    req->address_family = af;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->payload_size = payload_size;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);
    req->tcp_flags = tcp_flags;
    req->tcp_seq = tcp_seq;
    req->tcp_ack = tcp_ack;
    std::memcpy(req->payload, payload, payload_size);

    bool ok = send_request(ioctl_codes::PINJ(), req, static_cast<DWORD>(sizeof(*req)));
    bool success = ok && (req->status == 0);
    VirtualFree(req, 0, MEM_RELEASE);
    return success;
}

bool voyager::device_t::packet_mod_rule_op(std::uint32_t operation, std::uint32_t rule_id,
                                            std::uint32_t direction, std::uint32_t protocol,
                                            std::uint32_t port, std::uint32_t pid,
                                            const std::uint8_t* pattern, std::uint32_t pattern_size,
                                            const std::uint8_t* replacement, std::uint32_t replace_size,
                                            std::uint32_t* out_rule_id) noexcept {
    if (!is_connected()) {
        return false;
    }

    auto* req = static_cast<detail::packet_mod_rule*>(
        VirtualAlloc(nullptr, sizeof(detail::packet_mod_rule), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->rule_id = rule_id;
    req->direction = direction;
    req->protocol = protocol;
    req->port = port;
    req->pid = pid;
    if (pattern && pattern_size > 0) {
        req->pattern_size = (pattern_size > detail::MOD_MAX_PATTERN) ? detail::MOD_MAX_PATTERN : pattern_size;
        std::memcpy(req->pattern, pattern, req->pattern_size);
    }
    if (replacement && replace_size > 0) {
        req->replace_size = (replace_size > detail::MOD_MAX_REPLACE) ? detail::MOD_MAX_REPLACE : replace_size;
        std::memcpy(req->replacement, replacement, req->replace_size);
    }

    bool ok = send_request(ioctl_codes::PMOD(), req, static_cast<DWORD>(sizeof(*req)));
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::mod_rule_info> voyager::device_t::list_packet_mod_rules() noexcept {
    std::vector<mod_rule_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::packet_mod_rule_list*>(
        VirtualAlloc(nullptr, sizeof(detail::packet_mod_rule_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::PMOD(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->rule_count && i < detail::MOD_MAX_RULES; i++) {
            const auto& r = req->rules[i];
            mod_rule_info info{};
            info.rule_id = r.rule_id;
            info.direction = r.direction;
            info.protocol = r.protocol;
            info.port = r.port;
            info.pid = r.pid;
            info.match_count = r.match_count;
            info.active = r.active;
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::traffic_redirect_op(std::uint32_t operation, std::uint32_t rule_id,
                                             std::uint32_t protocol,
                                             std::uint32_t match_port, const std::uint8_t* match_addr,
                                             std::uint32_t redirect_port, const std::uint8_t* redirect_addr,
                                             std::uint32_t af, std::uint32_t* out_rule_id,
                                             std::uint32_t exclude_pid) noexcept {
    if (!is_connected()) {
        return false;
    }

    auto* req = static_cast<detail::traffic_redirect_rule*>(
        VirtualAlloc(nullptr, sizeof(detail::traffic_redirect_rule), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->rule_id = rule_id;
    req->protocol = protocol;
    req->match_port = match_port;
    req->redirect_port = redirect_port;
    req->address_family = af;
    if (match_addr) std::memcpy(req->match_addr, match_addr, 16);
    if (redirect_addr) std::memcpy(req->redirect_addr, redirect_addr, 16);
    req->exclude_pid = exclude_pid;

    bool ok = send_request(ioctl_codes::PRED(), req, static_cast<DWORD>(sizeof(*req)));
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::redirect_rule_info> voyager::device_t::list_redirect_rules() noexcept {
    std::vector<redirect_rule_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::traffic_redirect_list*>(
        VirtualAlloc(nullptr, sizeof(detail::traffic_redirect_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::PRED(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->rule_count && i < detail::REDIR_MAX_RULES; i++) {
            const auto& r = req->rules[i];
            redirect_rule_info info{};
            info.rule_id = r.rule_id;
            info.protocol = r.protocol;
            info.match_port = r.match_port;
            info.redirect_port = r.redirect_port;
            info.af = r.address_family;
            info.match_count = r.match_count;
            info.active = r.active;
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::stream_reassemble_op(std::uint32_t operation, std::uint32_t src_port, std::uint32_t dst_port,
                                              std::uint32_t pid, const std::uint8_t* src_addr,
                                              const std::uint8_t* dst_addr,
                                              std::vector<std::uint8_t>* out_data,
                                              std::uint32_t* out_packets, std::uint32_t* out_truncated) noexcept {
    DWORD strm_code = ioctl_codes::STRM();
    diag::log_tagged_fmt("netaction-strm",
        "stream_reassemble_op ENTER op=%u src_port=%u dst_port=%u pid=%u ioctl=0x%08X struct_size=%zu connected=%d",
        operation, src_port, dst_port, pid, strm_code,
        sizeof(detail::stream_reassemble_request), is_connected() ? 1 : 0);

    if (!is_connected()) {
        diag::log_tagged_fmt("netaction-strm",
            "stream_reassemble_op ABORT not_connected handle=0x%llX",
            reinterpret_cast<unsigned long long>(driver_handle_));
        return false;
    }

    auto* req = static_cast<detail::stream_reassemble_request*>(
        VirtualAlloc(nullptr, sizeof(detail::stream_reassemble_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("netaction-strm",
            "stream_reassemble_op ABORT VirtualAlloc_failed bytes=%zu err=%lu",
            sizeof(detail::stream_reassemble_request), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->pid = pid;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);

    SetLastError(0);
    bool ok = send_request(strm_code, req, static_cast<DWORD>(sizeof(*req)));
    DWORD post_err = GetLastError();
    diag::log_tagged_fmt("netaction-strm",
        "stream_reassemble_op send_request ok=%d last_error=%lu stream_size=%u total_packets=%u stream_count=%u truncated=%u",
        ok ? 1 : 0, post_err,
        req->stream_size, req->total_packets, req->stream_count, req->truncated);

    if (ok) {
        if (out_data && req->stream_size > 0) {
            out_data->assign(req->stream_data, req->stream_data + req->stream_size);
        }
        if (out_packets) *out_packets = req->total_packets;
        if (out_truncated) *out_truncated = req->truncated;
    }

    VirtualFree(req, 0, MEM_RELEASE);
    diag::log_tagged_fmt("netaction-strm",
        "stream_reassemble_op EXIT ok=%d", ok ? 1 : 0);
    return ok;
}

std::vector<voyager::device_t::dpi_result> voyager::device_t::get_dpi_results(
    std::uint32_t filter_pid, std::uint32_t filter_protocol,
    std::uint32_t filter_port, std::uint32_t flags) noexcept {
    std::vector<dpi_result> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::dpi_request*>(
        VirtualAlloc(nullptr, sizeof(detail::dpi_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->filter_pid = filter_pid;
    req->filter_protocol = filter_protocol;
    req->filter_port = filter_port;
    req->flags = flags;

    if (send_request(ioctl_codes::DPIN(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->result_count && i < detail::DPI_MAX_RESULTS; i++) {
            const auto& h = req->results[i];
            dpi_result d{};
            d.timestamp = h.timestamp;
            d.direction = h.direction;
            d.protocol = h.protocol;
            d.src_port = h.src_port;
            d.dst_port = h.dst_port;
            d.pid = h.pid;
            d.payload_size = h.payload_size;
            d.af = h.address_family;
            std::memcpy(d.src_addr, h.src_addr, 16);
            std::memcpy(d.dst_addr, h.dst_addr, 16);
            d.tcp_flags = h.tcp_flags;
            d.tcp_window = h.tcp_window;
            d.is_http = (h.is_http != 0);
            d.is_tls = (h.is_tls != 0);
            d.is_dns = (h.is_dns != 0);
            d.http_method = h.http_method;
            d.tls_version = h.tls_version;
            d.tls_content_type = h.tls_content_type;
            if (h.http_host[0]) d.http_host = h.http_host;
            if (h.http_path[0]) d.http_path = h.http_path;
            if (h.tls_sni[0]) d.tls_sni = h.tls_sni;
            result.push_back(std::move(d));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::intercept_op(std::uint32_t operation, std::uint32_t filter_pid, std::uint32_t filter_port,
                                      std::uint32_t filter_protocol, std::uint64_t hold_id,
                                      const std::uint8_t* modify_payload, std::uint32_t modify_size,
                                      std::uint32_t* out_held_count, bool* out_active) noexcept {
    if (!is_connected()) {
        return false;
    }

    auto* req = static_cast<detail::intercept_request*>(
        VirtualAlloc(nullptr, sizeof(detail::intercept_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->filter_pid = filter_pid;
    req->filter_port = filter_port;
    req->filter_protocol = filter_protocol;
    req->hold_id = hold_id;
    if (modify_payload && modify_size > 0) {
        req->modify_payload_size = (modify_size > detail::INTERCEPT_MAX_PAYLOAD) ? detail::INTERCEPT_MAX_PAYLOAD : modify_size;
        std::memcpy(req->modify_payload, modify_payload, req->modify_payload_size);
    }

    bool ok = send_request(ioctl_codes::IHLD(), req, static_cast<DWORD>(sizeof(*req)));
    if (ok) {
        if (out_held_count) *out_held_count = req->held_count;
        if (out_active) *out_active = (req->intercepting != 0);
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::held_packet_info> voyager::device_t::get_held_packets() noexcept {
    std::vector<held_packet_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::intercept_request*>(
        VirtualAlloc(nullptr, sizeof(detail::intercept_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::IHLD(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->held_count && i < detail::INTERCEPT_MAX_HELD; i++) {
            const auto& h = req->held_packets[i];
            held_packet_info info{};
            info.hold_id = h.hold_id;
            info.timestamp = h.timestamp;
            info.direction = h.direction;
            info.protocol = h.protocol;
            info.src_port = h.src_port;
            info.dst_port = h.dst_port;
            info.pid = h.pid;
            info.payload_size = h.payload_size;
            info.af = h.address_family;
            std::memcpy(info.src_addr, h.src_addr, 16);
            std::memcpy(info.dst_addr, h.dst_addr, 16);
            if (h.payload_size > 0) {
                std::uint32_t sz = (h.payload_size > detail::INTERCEPT_MAX_PAYLOAD) ? detail::INTERCEPT_MAX_PAYLOAD : h.payload_size;
                info.payload.assign(h.payload, h.payload + sz);
            }
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::kill_connection(std::uint32_t protocol, std::uint32_t af,
                                         std::uint32_t src_port, std::uint32_t dst_port,
                                         const std::uint8_t* src_addr, const std::uint8_t* dst_addr,
                                         std::uint32_t pid) noexcept {
    DWORD ckil_code = ioctl_codes::CKIL();
    diag::log_tagged_fmt("netaction-ckil",
        "kill_connection ENTER protocol=%u af=%u src_port=%u dst_port=%u pid=%u ioctl=0x%08X struct_size=%zu connected=%d",
        protocol, af, src_port, dst_port, pid, ckil_code,
        sizeof(detail::conn_kill_request), is_connected() ? 1 : 0);

    if (!is_connected()) {
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection ABORT not_connected handle=0x%llX",
            reinterpret_cast<unsigned long long>(driver_handle_));
        return false;
    }

    auto* req = static_cast<detail::conn_kill_request*>(
        VirtualAlloc(nullptr, sizeof(detail::conn_kill_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection ABORT VirtualAlloc_failed bytes=%zu err=%lu",
            sizeof(detail::conn_kill_request), err);
        return false;
    }

    std::memset(req, 0, sizeof(*req));
    req->protocol = protocol;
    req->address_family = af;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->pid = pid;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);

    if (src_addr) {
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection src_addr=%u.%u.%u.%u",
            (unsigned)src_addr[0], (unsigned)src_addr[1],
            (unsigned)src_addr[2], (unsigned)src_addr[3]);
    }
    if (dst_addr) {
        diag::log_tagged_fmt("netaction-ckil",
            "kill_connection dst_addr=%u.%u.%u.%u",
            (unsigned)dst_addr[0], (unsigned)dst_addr[1],
            (unsigned)dst_addr[2], (unsigned)dst_addr[3]);
    }

    SetLastError(0);
    bool ok = send_request(ckil_code, req, static_cast<DWORD>(sizeof(*req)));
    DWORD post_err = GetLastError();
    bool success = ok && (req->status == 0);
    diag::log_tagged_fmt("netaction-ckil",
        "kill_connection send_request ok=%d last_error=%lu request_status=%u success=%d",
        ok ? 1 : 0, post_err, req->status, success ? 1 : 0);

    VirtualFree(req, 0, MEM_RELEASE);
    diag::log_tagged_fmt("netaction-ckil",
        "kill_connection EXIT success=%d", success ? 1 : 0);
    return success;
}

bool voyager::device_t::dns_spoof_op(std::uint32_t operation, std::uint32_t rule_id,
                                      const char* domain,
                                      const std::uint8_t* spoof_addr, std::uint32_t af,
                                      std::uint32_t ttl, std::uint32_t* out_rule_id) noexcept {
    if (!is_connected()) {
        return false;
    }

    auto* req = static_cast<detail::dns_spoof_rule*>(
        VirtualAlloc(nullptr, sizeof(detail::dns_spoof_rule), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->rule_id = rule_id;
    req->address_family = af;
    req->ttl = ttl;
    if (domain) {
        size_t len = strlen(domain);
        if (len >= detail::DNS_SPOOF_MAX_DOMAIN) len = detail::DNS_SPOOF_MAX_DOMAIN - 1;
        std::memcpy(req->domain, domain, len);
    }
    if (spoof_addr) std::memcpy(req->spoof_addr, spoof_addr, 16);

    bool ok = send_request(ioctl_codes::DNSS(), req, static_cast<DWORD>(sizeof(*req)));
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::dns_spoof_info> voyager::device_t::list_dns_spoof_rules() noexcept {
    std::vector<dns_spoof_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::dns_spoof_list*>(
        VirtualAlloc(nullptr, sizeof(detail::dns_spoof_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::DNSS(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->rule_count && i < detail::DNS_SPOOF_MAX_RULES; i++) {
            const auto& r = req->rules[i];
            dns_spoof_info info{};
            info.rule_id = r.rule_id;
            if (r.domain[0]) info.domain = r.domain;
            info.af = r.address_family;
            info.match_count = r.match_count;
            info.active = r.active;
            info.ttl = r.ttl;
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::bw_monitor_op(std::uint32_t operation, std::uint32_t filter_pid,
                                       bw_stats* out_stats) noexcept {
    if (!is_connected()) {
        return false;
    }

    auto* req = static_cast<detail::bw_monitor_request*>(
        VirtualAlloc(nullptr, sizeof(detail::bw_monitor_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->filter_pid = filter_pid;

    bool ok = send_request(ioctl_codes::BWMN(), req, static_cast<DWORD>(sizeof(*req)));
    if (ok && out_stats) {
        out_stats->total_bytes_sent = req->total_bytes_sent;
        out_stats->total_bytes_recv = req->total_bytes_recv;
        out_stats->total_packets_sent = req->total_packets_sent;
        out_stats->total_packets_recv = req->total_packets_recv;
        out_stats->bps_in = req->bytes_per_second_in;
        out_stats->bps_out = req->bytes_per_second_out;
        out_stats->active = (req->monitoring_active != 0);
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::bw_process_info> voyager::device_t::get_bw_per_process(std::uint32_t filter_pid) noexcept {
    std::vector<bw_process_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::bw_monitor_request*>(
        VirtualAlloc(nullptr, sizeof(detail::bw_monitor_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 4;
    req->filter_pid = filter_pid;

    if (send_request(ioctl_codes::BWMN(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->process_count && i < detail::BW_MAX_PROCESSES; i++) {
            const auto& p = req->processes[i];
            bw_process_info info{};
            info.pid = p.pid;
            info.bytes_sent = p.bytes_sent;
            info.bytes_recv = p.bytes_recv;
            info.packets_sent = p.packets_sent;
            info.packets_recv = p.packets_recv;
            info.last_activity = p.last_activity_time;
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

std::vector<voyager::device_t::net_iface_info> voyager::device_t::enumerate_interfaces() noexcept {
    std::vector<net_iface_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::net_interface_enum*>(
        VirtualAlloc(nullptr, sizeof(detail::net_interface_enum), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));

    if (send_request(ioctl_codes::NIFS(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->interface_count && i < detail::NET_IF_MAX; i++) {
            const auto& e = req->interfaces[i];
            net_iface_info info{};
            info.if_index = e.if_index;
            info.if_type = e.if_type;
            info.mtu = e.mtu;
            info.oper_status = e.oper_status;
            info.speed = e.speed;
            std::memcpy(info.mac_addr, e.mac_addr, 6);
            std::memcpy(info.ipv4_addr, e.ipv4_addr, 4);
            std::memcpy(info.ipv4_mask, e.ipv4_mask, 4);
            std::memcpy(info.ipv6_addr, e.ipv6_addr, 16);
            if (e.name[0]) info.name = e.name;
            if (e.description[0]) info.description = e.description;
            info.in_octets = e.in_octets;
            info.out_octets = e.out_octets;
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::export_pcap(std::uint32_t filter_pid, std::uint32_t filter_protocol,
                                     std::uint32_t max_packets, pcap_export_result* out) noexcept {
    if (!is_connected()) {
        return false;
    }
    if (max_packets > detail::PCAP_MAX_EXPORT_PACKETS) max_packets = detail::PCAP_MAX_EXPORT_PACKETS;

    auto* req = static_cast<detail::pcap_export_request*>(
        VirtualAlloc(nullptr, sizeof(detail::pcap_export_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = 0;
    req->filter_pid = filter_pid;
    req->filter_protocol = filter_protocol;
    req->max_packets = max_packets;

    bool ok = send_request(ioctl_codes::PCEX(), req, static_cast<DWORD>(sizeof(*req)));
    if (ok && out) {
        out->header = req->header;
        out->packets.clear();
        for (std::uint32_t i = 0; i < req->packet_count && i < detail::PCAP_MAX_EXPORT_PACKETS; i++) {
            const auto& r = req->records[i];
            pcap_packet pkt{};
            pkt.ts_sec = r.ts_sec;
            pkt.ts_usec = r.ts_usec;
            std::uint32_t len = (r.incl_len > detail::PCAP_RECORD_MAX_SIZE) ? detail::PCAP_RECORD_MAX_SIZE : r.incl_len;
            pkt.data.assign(r.data, r.data + len);
            out->packets.push_back(std::move(pkt));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

bool voyager::device_t::fingerprint_op(std::uint32_t operation) noexcept {
    if (!is_connected()) {
        return false;
    }

    auto* req = static_cast<detail::net_fingerprint_request*>(
        VirtualAlloc(nullptr, sizeof(detail::net_fingerprint_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;

    bool ok = send_request(ioctl_codes::NFPR(), req, static_cast<DWORD>(sizeof(*req)));
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::fingerprint_info> voyager::device_t::get_fingerprints() noexcept {
    std::vector<fingerprint_info> result;
    if (!is_connected()) {
        return result;
    }

    auto* req = static_cast<detail::net_fingerprint_request*>(
        VirtualAlloc(nullptr, sizeof(detail::net_fingerprint_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::NFPR(), req, static_cast<DWORD>(sizeof(*req)))) {
        for (std::uint32_t i = 0; i < req->result_count && i < detail::FINGERPRINT_MAX; i++) {
            const auto& e = req->entries[i];
            fingerprint_info info{};
            std::memcpy(info.remote_addr, e.remote_addr, 16);
            info.af = e.address_family;
            info.ttl = e.ttl;
            info.window_size = e.window_size;
            info.mss = e.mss;
            info.window_scale = e.window_scale;
            info.df_flag = e.df_flag;
            info.sack_permitted = e.sack_permitted;
            info.nop_count = e.nop_count;
            if (e.os_guess[0]) info.os_guess = e.os_guess;
            result.push_back(std::move(info));
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}


bool voyager::device_t::register_dll_protection(
    std::uint64_t module_base, std::uint64_t text_va,
    std::uint32_t text_size, std::uint64_t expected_hash,
    std::uint32_t check_interval_ms) noexcept
{
    if (!is_connected() || process_id_ == 0) {
        return false;
    }

    detail::dll_protect_request req{};
    req.operation = detail::DPRT_OP_REGISTER;
    req.pid = process_id_;
    req.module_base = module_base;
    req.text_section_va = text_va;
    req.text_section_size = text_size;
    req.expected_hash = expected_hash;
    req.check_interval = check_interval_ms;

    if (!send_request(ioctl_codes::DPRT(), &req, static_cast<DWORD>(sizeof(req)))) {
        return false;
    }

    return req.status == detail::DPRT_STATUS_ACTIVE;
}

bool voyager::device_t::query_dll_protection(dll_protect_status& out) noexcept
{
    if (!is_connected()) {
        return false;
    }

    detail::dll_protect_request req{};
    req.operation = detail::DPRT_OP_QUERY;
    req.pid = process_id_;

    if (!send_request(ioctl_codes::DPRT(), &req, static_cast<DWORD>(sizeof(req)))) {
        return false;
    }

    out.status = req.status;
    out.current_hash = req.current_hash;
    out.expected_hash = req.expected_hash;
    out.last_check_tsc = req.last_check_tsc;
    return true;
}

bool voyager::device_t::unregister_dll_protection() noexcept
{
    if (!is_connected()) {
        return false;
    }

    detail::dll_protect_request req{};
    req.operation = detail::DPRT_OP_UNREGISTER;
    req.pid = process_id_;

    bool ok = send_request(ioctl_codes::DPRT(), &req, static_cast<DWORD>(sizeof(req)));
    return ok;
}

bool voyager::device_t::trigger_kernel_bsod(std::uint32_t reason_code, std::uint64_t evidence_hash) noexcept
{


    if (!is_connected()) {
        return false;
    }

    detail::abort_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0xABCD1234u;
    req.reason_code = reason_code;
    req.evidence_hash = evidence_hash;
    req.timestamp = __rdtsc();


    send_request(ioctl_codes::ABRT(), &req, static_cast<DWORD>(sizeof(req)));


    return false;
}

bool voyager::device_t::latch_targeting_from_usermode(std::uint32_t reason) noexcept
{
    if (!is_connected())
        return false;

    detail::latch_targeting_request req{};
    req.magic        = session_key_ ^ dynamic_key::get() ^ 0x1A7C4B2Eu;
    req.session_key  = session_key_;
    req.reason       = reason;
    req.reserved     = 0;

    return send_request(ioctl_codes::RELA(), &req, static_cast<DWORD>(sizeof(req)));
}

bool voyager::device_t::tier_a_driver_present_query(bool& out_present, std::uint32_t* out_mask,
                                                    std::uint64_t* out_first_base) noexcept
{
    out_present = false;
    if (out_mask) *out_mask = 0;
    if (out_first_base) *out_first_base = 0;

    if (!is_connected()) return false;

    detail::tier_a_query_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0x7A1E0011u;
    req.session_key = session_key_;

    if (!send_request(ioctl_codes::TIRA(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    out_present = req.present_flag != 0;
    if (out_mask) *out_mask = req.tier_mask;
    if (out_first_base) *out_first_base = req.first_driver_base;
    return true;
}

bool voyager::device_t::canary_register(std::uint64_t va, std::uint64_t size) noexcept
{
    return canary_register_for_pid(va, size, process_id_ != 0 ? process_id_ : GetCurrentProcessId());
}

bool voyager::device_t::canary_register_for_pid(std::uint64_t va, std::uint64_t size, std::uint32_t pid) noexcept
{
    if (!is_connected()) {
        RC_UM_DBG("CANR skip not_connected va=0x%llX size=0x%llX", va, size);
        return false;
    }

    detail::canary_register_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0xCA110013u;
    req.session_key = session_key_;
    req.va = va;
    req.size = size;
    req.pid = pid != 0 ? pid : GetCurrentProcessId();

    RC_UM_DBG("CANR request va=0x%llX size=0x%llX pid=%u ioctl=0x%08X",
        req.va,
        req.size,
        req.pid,
        ioctl_codes::CANR());

    if (!send_request(ioctl_codes::CANR(), &req, static_cast<DWORD>(sizeof(req)))) {
        RC_UM_DBG("CANR send_failed va=0x%llX size=0x%llX pid=%u last_error=%lu",
            va,
            size,
            req.pid,
            GetLastError());
        return false;
    }

    RC_UM_DBG("CANR response va=0x%llX size=0x%llX pid=%u result=%u",
        req.va,
        req.size,
        req.pid,
        req.result);

    return req.result != 0;
}

bool voyager::device_t::canary_query_count(std::uint32_t& out_count) noexcept
{
    out_count = 0;
    if (!is_connected()) {
        RC_UM_DBG("CANQ skip not_connected");
        return false;
    }

    detail::canary_register_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0xCA110013u;
    req.session_key = session_key_;
    req.pid = process_id_ != 0 ? process_id_ : GetCurrentProcessId();

    RC_UM_DBG("CANQ request pid=%u ioctl=0x%08X", req.pid, ioctl_codes::CANQ());

    if (!send_request(ioctl_codes::CANQ(), &req, static_cast<DWORD>(sizeof(req)))) {
        RC_UM_DBG("CANQ send_failed pid=%u last_error=%lu", req.pid, GetLastError());
        return false;
    }

    out_count = req.result;
    RC_UM_DBG("CANQ response pid=%u count=%u", req.pid, out_count);
    return true;
}

bool voyager::device_t::re_confirmed_usermode_bsod(const detail::re_evidence_blob_t& evidence) noexcept
{
    if (!is_connected()) return false;

    detail::re_confirmed_usermode_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0xDEAD0010u;
    req.session_key = session_key_;
    req.evidence = evidence;

    send_request(ioctl_codes::RECU(), &req, static_cast<DWORD>(sizeof(req)));
    return false;
}

bool voyager::device_t::protect_sandbox_pid(std::uint32_t pid, std::uint32_t flags, std::uint64_t* out_denials) noexcept
{
    diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid ENTER pid=%u flags_in=0x%08X connected=%d session=0x%08X self_pid=%lu",
        pid, flags, is_connected() ? 1 : 0, session_key_, GetCurrentProcessId());

    if (!is_connected()) {
        diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid REJECT not_connected pid=%u", pid);
        return false;
    }
    if (pid == 0) {
        diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid REJECT pid=0");
        return false;
    }

    detail::protect_sandbox_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0x5A4E0B01u;
    req.session_key = session_key_;
    req.pid = pid;
    req.flags = (flags == 0) ? detail::SANDBOX_FLAG_DEFAULT : flags;

    diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid SEND ioctl=0x%08X pid=%u flags_effective=0x%08X magic=0x%08X session_key=0x%08X size=%u",
        ioctl_codes::PSBX(), req.pid, req.flags, req.magic, req.session_key, static_cast<unsigned>(sizeof(req)));

    if (!send_request(ioctl_codes::PSBX(), &req, static_cast<DWORD>(sizeof(req)))) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid send_request FAILED pid=%u err=%lu", pid, err);
        return false;
    }
    if (out_denials) *out_denials = req.denials_so_far;
    bool ok = req.result != 0;
    diag::log_tagged_fmt("ww:malsafe-um", "protect_sandbox_pid RESULT pid=%u result=%u denials=%llu ok=%d",
        pid, req.result, static_cast<unsigned long long>(req.denials_so_far), ok ? 1 : 0);
    return ok;
}

bool voyager::device_t::unprotect_sandbox_pid(std::uint32_t pid, std::uint64_t* out_denials) noexcept
{
    diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid ENTER pid=%u connected=%d session=0x%08X self_pid=%lu",
        pid, is_connected() ? 1 : 0, session_key_, GetCurrentProcessId());

    if (!is_connected()) {
        diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid REJECT not_connected pid=%u", pid);
        return false;
    }
    if (pid == 0) {
        diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid REJECT pid=0");
        return false;
    }

    detail::protect_sandbox_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0x5A4E0B02u;
    req.session_key = session_key_;
    req.pid = pid;
    req.flags = 0;

    diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid SEND ioctl=0x%08X pid=%u magic=0x%08X session_key=0x%08X size=%u",
        ioctl_codes::USBX(), req.pid, req.magic, req.session_key, static_cast<unsigned>(sizeof(req)));

    if (!send_request(ioctl_codes::USBX(), &req, static_cast<DWORD>(sizeof(req)))) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid send_request FAILED pid=%u err=%lu", pid, err);
        return false;
    }
    if (out_denials) *out_denials = req.denials_so_far;
    bool ok = req.result != 0;
    diag::log_tagged_fmt("ww:malsafe-um", "unprotect_sandbox_pid RESULT pid=%u result=%u denials=%llu ok=%d",
        pid, req.result, static_cast<unsigned long long>(req.denials_so_far), ok ? 1 : 0);
    return ok;
}

bool voyager::device_t::net_log_register_pid(std::uint32_t pid, bool enable) noexcept
{
    diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid ENTER pid=%u enable=%d connected=%d session=0x%08X self_pid=%lu",
        pid, enable ? 1 : 0, is_connected() ? 1 : 0, session_key_, GetCurrentProcessId());

    if (!is_connected()) {
        diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid REJECT not_connected pid=%u", pid);
        return false;
    }
    if (pid == 0) {
        diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid REJECT pid=0");
        return false;
    }

    detail::net_log_register_request req{};
    req.magic = session_key_ ^ dynamic_key::get() ^ 0x5A4E0B03u;
    req.session_key = session_key_;
    req.pid = pid;
    req.operation = enable ? 1u : 0u;

    diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid SEND ioctl=0x%08X pid=%u op=%u magic=0x%08X session_key=0x%08X size=%u",
        ioctl_codes::NLOG(), req.pid, req.operation, req.magic, req.session_key, static_cast<unsigned>(sizeof(req)));

    if (!send_request(ioctl_codes::NLOG(), &req, static_cast<DWORD>(sizeof(req)))) {
        DWORD err = GetLastError();
        diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid send_request FAILED pid=%u err=%lu", pid, err);
        return false;
    }
    bool ok = req.result != 0;
    diag::log_tagged_fmt("ww:malsafe-um", "net_log_register_pid RESULT pid=%u op=%u result=%u ok=%d",
        pid, req.operation, req.result, ok ? 1 : 0);
    return ok;
}

bool voyager::device_t::malware_safe_pull_packets(std::uint32_t pid,
                                                  std::uint32_t max_records,
                                                  std::vector<detail::net_packet_record>& out,
                                                  std::uint64_t* out_dropped_since_last_pull) noexcept
{
    out.clear();
    if (out_dropped_since_last_pull) *out_dropped_since_last_pull = 0;
    if (!is_connected()) return false;
    if (pid == 0) return false;
    if (max_records == 0) max_records = detail::NET_PKT_PULL_RING_CAPACITY;
    if (max_records > detail::NET_PKT_PULL_RING_CAPACITY) max_records = detail::NET_PKT_PULL_RING_CAPACITY;

    const std::size_t request_size = sizeof(detail::net_packet_pull_request);
    const std::size_t response_size = sizeof(detail::net_packet_pull_response_header) +
        static_cast<std::size_t>(max_records) * sizeof(detail::net_packet_record);
    const std::size_t total_size = (request_size > response_size) ? request_size : response_size;
    if (total_size > 0xFFFFFFFFu) return false;

    std::unique_ptr<std::uint8_t[]> buf(new (std::nothrow) std::uint8_t[total_size]);
    if (!buf) return false;
    std::memset(buf.get(), 0, total_size);

    auto* req = reinterpret_cast<detail::net_packet_pull_request*>(buf.get());
    req->magic = session_key_ ^ dynamic_key::get() ^ 0x5A4E0B04u;
    req->session_key = session_key_;
    req->pid = pid;
    req->max_records = max_records;
    req->reserved = 0;
    req->padding = 0;

    DWORD dw_size = static_cast<DWORD>(total_size);
    if (!send_request(ioctl_codes::NPKT(), buf.get(), dw_size)) {
        return false;
    }

    auto* resp = reinterpret_cast<detail::net_packet_pull_response_header*>(buf.get());
    if (resp->magic != detail::NET_PKT_PULL_RESP_MAGIC) {
        return false;
    }
    std::uint32_t count = resp->record_count;
    if (count > max_records) count = max_records;
    if (out_dropped_since_last_pull) *out_dropped_since_last_pull = resp->dropped_since_last_pull;

    if (count > 0) {
        const auto* recs = reinterpret_cast<const detail::net_packet_record*>(
            buf.get() + sizeof(detail::net_packet_pull_response_header));
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            out.push_back(recs[i]);
        }
    }
    return true;
}

bool voyager::device_t::kernel_anti_debug_query(anti_debug_result& out) noexcept
{
    if (!is_connected()) return false;

    detail::anti_debug_request req{};
    req.operation = 0;
    req.pid = process_id_;

    if (!send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    out.result_flags = req.result_flags;
    out.detected_debugger_pid = req.detected_debugger_pid;
    out.dr_clear_count = req.dr_clear_count;
    return true;
}

bool voyager::device_t::kernel_anti_debug_clear_dr(std::uint64_t* out_clear_count) noexcept
{
    if (!is_connected()) return false;

    detail::anti_debug_request req{};
    req.operation = 1;

    if (!send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    if (out_clear_count) *out_clear_count = req.dr_clear_count;
    return req.result_flags == 0;
}

bool voyager::device_t::kernel_anti_debug_clear_process_dr(std::uint32_t pid, std::uint64_t* out_clear_count) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_debug_request req{};
    req.operation = 4;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    if (out_clear_count) *out_clear_count = req.dr_clear_count;
    return req.result_flags == 0;
}

bool voyager::device_t::kernel_anti_debug_scan_debuggers(std::uint64_t* out_debugger_pid) noexcept
{
    if (!is_connected()) return false;

    detail::anti_debug_request req{};
    req.operation = 2;

    if (!send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    if (out_debugger_pid) *out_debugger_pid = req.detected_debugger_pid;
    return true;
}

bool voyager::device_t::kernel_anti_debug_hide_thread(std::uint32_t pid, std::uint32_t tid) noexcept
{
    if (!is_connected() || pid == 0 || tid == 0) return false;

    detail::anti_debug_request req{};
    req.operation = 3;
    req.pid = pid;
    req.tid = tid;

    return send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req)));
}

bool voyager::device_t::kernel_anti_debug_hide_all_threads(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_debug_request req{};
    req.operation = 5;
    req.pid = pid;

    return send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req)));
}

bool voyager::device_t::kernel_anti_debug_install_instrumentation(std::uint32_t pid, void* callback) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_debug_request req{};
    req.operation = 6;
    req.pid = pid;
    req.detected_debugger_pid = reinterpret_cast<std::uint64_t>(callback);

    return send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req)));
}

bool voyager::device_t::kernel_anti_debug_remove_instrumentation(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_debug_request req{};
    req.operation = 7;
    req.pid = pid;

    return send_request(ioctl_codes::ADBG(), &req, static_cast<DWORD>(sizeof(req)));
}

bool voyager::device_t::kernel_anti_dump_full(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_dump_request req{};
    req.operation = 0;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::kernel_anti_dump_register_filter(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_dump_request req{};
    req.operation = 1;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::kernel_anti_dump_hide_threads(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_dump_request req{};
    req.operation = 2;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::kernel_anti_dump_erase_headers(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_dump_request req{};
    req.operation = 3;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::kernel_anti_dump_query(anti_dump_result& out) noexcept
{
    if (!is_connected()) return false;

    detail::anti_dump_request req{};
    req.operation = 4;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    out.blocks_count = req.blocks_count;
    return true;
}

bool voyager::device_t::kernel_anti_dump_permit_pid(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_dump_request req{};
    req.operation = 10;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::kernel_anti_dump_unpermit_pid(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_dump_request req{};
    req.operation = 11;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::kernel_anti_dump_stop_continuous() noexcept
{
    if (!is_connected()) return false;

    detail::anti_dump_request req{};
    req.operation = 6;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::kernel_anti_dump_start_continuous(std::uint32_t pid) noexcept
{
    if (!is_connected() || pid == 0) return false;

    detail::anti_dump_request req{};
    req.operation = 5;
    req.pid = pid;

    if (!send_request(ioctl_codes::ADMP(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::relay_server_token(std::uint32_t token_hash, std::uint64_t server_nonce) noexcept
{
    if (!is_connected()) return false;

    detail::server_token_relay req{};
    req.token_hash = token_hash;
    req.session_key = session_key_;
    req.timestamp = __rdtsc();
    req.server_nonce = server_nonce;

    if (!send_request(ioctl_codes::SRVT(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    return req.result == 1;
}

bool voyager::device_t::relay_server_token_v2(std::uint32_t token_hash, std::uint64_t server_nonce, std::uint64_t* out_driver_proof) noexcept
{
    if (!is_connected()) return false;

    detail::server_token_relay_v2 req{};
    req.token_hash = token_hash;
    req.session_key = session_key_;
    req.timestamp = __rdtsc();
    req.server_nonce = server_nonce;

    if (!send_request(ioctl_codes::SRV2(), &req, static_cast<DWORD>(sizeof(req))))
        return false;

    if (out_driver_proof) *out_driver_proof = req.driver_proof;
    return req.result == 1;
}

bool voyager::device_t::run_hv_detect(detail::hv_detect_result& out) noexcept {
    if (!is_connected()) {
        return false;
    }

    union {
        detail::hv_detect_request req;
        detail::hv_detect_result  result;
    } buf{};
    buf.req.flags = 0;

    DWORD buf_size = sizeof(buf);
    if (!send_request(ioctl_codes::HVDT(), &buf, buf_size)) {
        return false;
    }

    std::memcpy(&out, &buf.result, sizeof(out));
    return true;
}

bool voyager::device_t::drain_debug_events(std::vector<debug_event_record>& out,
                                           std::size_t max_events,
                                           debug_event_drain_stats* out_stats) noexcept {
    out.clear();
    if (out_stats) {
        *out_stats = debug_event_drain_stats{};
    }

    if (!is_connected()) {
        return false;
    }

    if (max_events == 0) {
        return true;
    }

    if (max_events > detail::DRAIN_DEBUG_EVENTS_CAP) {
        max_events = detail::DRAIN_DEBUG_EVENTS_CAP;
    }

    auto buffer = std::make_unique<detail::drain_debug_events_request>();
    std::memset(buffer.get(), 0, sizeof(*buffer));
    buffer->session_key = session_key_;
    buffer->max_events = static_cast<std::uint32_t>(max_events);

    if (!send_request(ioctl_codes::EVTS(), buffer.get(),
                      static_cast<DWORD>(sizeof(*buffer)))) {
        return false;
    }

    std::uint32_t count = buffer->returned_count;
    if (count > detail::DRAIN_DEBUG_EVENTS_CAP) {
        count = detail::DRAIN_DEBUG_EVENTS_CAP;
    }

    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const detail::debug_event_t& src = buffer->events[i];
        debug_event_record rec;
        rec.type = static_cast<debug_event_type_e>(src.event_type);
        rec.process_id = src.process_id;
        rec.thread_id = src.thread_id;
        rec.flags = src.flags;
        rec.timestamp = src.timestamp;
        rec.image_base = src.image_base;
        rec.image_size = src.image_size;

        std::size_t path_chars = 0;
        while (path_chars < detail::DEBUG_EVENT_PATH_CHARS &&
               src.image_path[path_chars] != L'\0') {
            ++path_chars;
        }
        if (path_chars > 0) {
            rec.image_path.assign(src.image_path, src.image_path + path_chars);
        }

        out.push_back(std::move(rec));
    }

    if (out_stats) {
        out_stats->returned_count = buffer->returned_count;
        out_stats->dropped_since_last_drain = buffer->dropped_since_last_drain;
        out_stats->total_dropped = buffer->total_dropped;
        out_stats->total_published = buffer->total_published;
    }

    return true;
}
