#include "comm.h"
#include <algorithm>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include "encrypt/crypter.h"
#include "spoofer/spoof.hpp"
#include <string>
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <intrin.h>
#include <cstdio>

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

    fprintf(stderr, "[WhosWho-UM] connect: attempting connection...\n");

    if (is_connected()) {
        fprintf(stderr, "[WhosWho-UM] connect: already connected, handle=%p\n", driver_handle_);
        return true;
    }

    std::wstring device_path = device_names_um::get_device_path();
    fprintf(stderr, "[WhosWho-UM] connect: device_path=\"%ls\"\n", device_path.c_str());

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
        fprintf(stderr, "[WhosWho-UM] connect: CreateFileW FAILED err=%lu\n", GetLastError());
        return false;
    }
    fprintf(stderr, "[WhosWho-UM] connect: handle=%p opened OK\n", driver_handle_);

    session_key_ = static_cast<std::uint32_t>(__rdtsc() ^ 0xDEADC0DEu);
    if (session_key_ == 0) session_key_ = 0x12345678u;
    fprintf(stderr, "[WhosWho-UM] connect: session_key=0x%08X\n", session_key_);

    if (!send_heartbeat()) {
        fprintf(stderr, "[WhosWho-UM] connect: initial heartbeat FAILED, closing handle\n");
        CloseHandle(driver_handle_);
        driver_handle_ = INVALID_HANDLE_VALUE;
        session_key_ = 0;
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] connect: SUCCESS, driver connected\n");
    return true;
}

void voyager::device_t::disconnect() noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] disconnect: disconnecting (handle=%p pid=%u)\n", driver_handle_, process_id_);

    clear_process_context();

    if (is_connected()) {
        CloseHandle(driver_handle_);
        driver_handle_ = INVALID_HANDLE_VALUE;
        fprintf(stderr, "[WhosWho-UM] disconnect: handle closed\n");
    }

    kernel_dtb_ = 0;
    session_key_ = 0;
    last_heartbeat_tsc_ = 0;
    fprintf(stderr, "[WhosWho-UM] disconnect: done\n");
}

void voyager::device_t::clear_process_context() noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] clear_process_context: pid=%u shellcode=0x%llX base=0x%llX dtb=0x%llX\n",
        process_id_, shellcode_address_, base_address_, dtb_);

    if (is_connected() && shellcode_address_ != 0 && process_id_ != 0) {
        fprintf(stderr, "[WhosWho-UM] clear_process_context: freeing shellcode at 0x%llX\n", shellcode_address_);
        free_memory(shellcode_address_);
    }

    shellcode_address_ = 0;
    process_id_ = 0;
    base_address_ = 0;
    dtb_ = 0;
    spoof_gadget_ = 0;
    fprintf(stderr, "[WhosWho-UM] clear_process_context: context cleared\n");
}

std::uint32_t voyager::device_t::find_process(const char* process_name) noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] find_process: searching for \"%s\"\n", process_name ? process_name : "(null)");

    if (!process_name || std::strlen(process_name) == 0 || std::strlen(process_name) >= MAX_PATH) {
        fprintf(stderr, "[WhosWho-UM] find_process: invalid process_name\n");
        return 0;
    }

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[WhosWho-UM] find_process: CreateToolhelp32Snapshot FAILED err=%lu\n", GetLastError());
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
        fprintf(stderr, "[WhosWho-UM] find_process: FOUND pid=%u\n", found_pid);
        if (shellcode_address_ != 0 && process_id_ != 0 && process_id_ != found_pid) {
            fprintf(stderr, "[WhosWho-UM] find_process: switching from old pid=%u, freeing shellcode 0x%llX\n",
                process_id_, shellcode_address_);
            free_memory(shellcode_address_);
            shellcode_address_ = 0;
        }
        process_id_ = found_pid;
        dtb_ = 0;
        base_address_ = 0;
        spoof_gadget_ = 0;
    } else {
        fprintf(stderr, "[WhosWho-UM] find_process: NOT FOUND\n");
    }

    return found_pid;
}

bool voyager::device_t::send_heartbeat() noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] send_heartbeat: connected=%d session_key=0x%08X\n", is_connected(), session_key_);

    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] send_heartbeat: not connected\n");
        return false;
    }

    detail::heartbeat_request hb{};
    hb.magic = detail::get_heartbeat_magic();
    hb.session_key = session_key_;
    hb.timestamp = __rdtsc();
    hb.response = 0;

    DWORD ioctlCode = ioctl_codes::HB();
    fprintf(stderr, "[WhosWho-UM] send_heartbeat: magic=0x%08X ioctl=0x%08X\n", hb.magic, ioctlCode);

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
        fprintf(stderr, "[WhosWho-UM] send_heartbeat: OK response=0x%016llX bytes=%u\n", hb.response, bytes_returned);
        return true;
    }

    fprintf(stderr, "[WhosWho-UM] send_heartbeat: FAILED result=%d bytes=%u response=0x%016llX err=%lu\n",
        result, bytes_returned, hb.response, GetLastError());
    return false;
}

bool voyager::device_t::refresh_heartbeat() noexcept {
    std::uint64_t current_tsc = __rdtsc();
    std::uint64_t elapsed = (last_heartbeat_tsc_ == 0) ? 0 : (current_tsc - last_heartbeat_tsc_);
    if (last_heartbeat_tsc_ == 0 || elapsed > detail::HEARTBEAT_REFRESH_INTERVAL) {
        fprintf(stderr, "[WhosWho-UM] refresh_heartbeat: refreshing (elapsed=0x%llX threshold=0x%llX)\n",
            elapsed, detail::HEARTBEAT_REFRESH_INTERVAL);
        return send_heartbeat();
    }
    return true;
}

void voyager::device_t::solve_dtb() noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] solve_dtb: pid=%u\n", process_id_);

    if (process_id_ == 0) {
        fprintf(stderr, "[WhosWho-UM] solve_dtb: no pid set\n");
        dtb_ = 0;
        return;
    }

    detail::dtb_solve req{};
    req.pid = process_id_;
    req.padding = 0;
    req.dtb = 0;

    if (send_request(ioctl_codes::DTB(), &req, sizeof(req)) && req.dtb != 0) {
        dtb_ = req.dtb;
        fprintf(stderr, "[WhosWho-UM] solve_dtb: OK dtb=0x%llX\n", dtb_);
    } else {
        dtb_ = 0;
        fprintf(stderr, "[WhosWho-UM] solve_dtb: FAILED (req.dtb=0x%llX)\n", req.dtb);
    }
}

void voyager::device_t::solve_kernel_dtb() noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] solve_kernel_dtb: resolving System (pid=4) DTB\n");

    detail::dtb_solve req{};
    req.pid = 4;
    req.padding = 0;
    req.dtb = 0;

    if (send_request(ioctl_codes::DTB(), &req, sizeof(req)) && req.dtb != 0) {
        kernel_dtb_ = req.dtb;
        fprintf(stderr, "[WhosWho-UM] solve_kernel_dtb: OK kernel_dtb=0x%llX\n", kernel_dtb_);
    } else {
        fprintf(stderr, "[WhosWho-UM] solve_kernel_dtb: IOCTL failed, fallback to dtb_=0x%llX\n", dtb_);
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

    fprintf(stderr, "[WhosWho-UM] transfer_physical_read: pid=%u dtb=0x%llX addr=0x%llX size=0x%zX\n",
        pid, dtb, address, size);

    if (!buffer || size == 0 || !is_connected() || dtb == 0) {
        fprintf(stderr, "[WhosWho-UM] transfer_physical_read: precondition fail buf=%p size=0x%zX connected=%d dtb=0x%llX\n",
            buffer, size, is_connected(), dtb);
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
            fprintf(stderr, "[WhosWho-UM] transfer_physical_read: PHYS IOCTL failed at offset=0x%zX\n", total_read);
            break;
        }

        const std::size_t bytes_read = (req.ret_size <= chunk_size) ? req.ret_size : chunk_size;
        if (bytes_read == 0) {
            fprintf(stderr, "[WhosWho-UM] transfer_physical_read: 0 bytes returned at offset=0x%zX\n", total_read);
            break;
        }

        std::memcpy(destination + total_read, staging.data(), bytes_read);
        total_read += bytes_read;

        if (bytes_read < chunk_size) {
            break;
        }
    }

    fprintf(stderr, "[WhosWho-UM] transfer_physical_read: total_read=0x%zX / 0x%zX\n", total_read, size);
    return total_read;
}

std::size_t voyager::device_t::transfer_physical_write(
    std::uint32_t pid,
    std::uint64_t dtb,
    std::uint64_t address,
    const void* buffer,
    std::size_t size) const noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] transfer_physical_write: pid=%u dtb=0x%llX addr=0x%llX size=0x%zX\n",
        pid, dtb, address, size);

    if (!buffer || size == 0 || !is_connected() || dtb == 0) {
        fprintf(stderr, "[WhosWho-UM] transfer_physical_write: precondition fail buf=%p size=0x%zX connected=%d dtb=0x%llX\n",
            buffer, size, is_connected(), dtb);
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
            fprintf(stderr, "[WhosWho-UM] transfer_physical_write: PHYS IOCTL failed at offset=0x%zX\n", total_written);
            break;
        }

        const std::size_t bytes_written = (req.ret_size <= chunk_size) ? req.ret_size : chunk_size;
        if (bytes_written == 0) {
            fprintf(stderr, "[WhosWho-UM] transfer_physical_write: 0 bytes written at offset=0x%zX\n", total_written);
            break;
        }

        total_written += bytes_written;
        if (bytes_written < chunk_size) {
            break;
        }
    }

    fprintf(stderr, "[WhosWho-UM] transfer_physical_write: total_written=0x%zX / 0x%zX\n", total_written, size);
    return total_written;
}

std::size_t voyager::device_t::read_kernel_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] read_kernel_raw: addr=0x%llX size=0x%zX\n", address, size);

    if (!buffer || size == 0 || !is_connected()) {
        fprintf(stderr, "[WhosWho-UM] read_kernel_raw: precondition fail\n");
        return 0;
    }

    if (size > 0x10000000) {
        fprintf(stderr, "[WhosWho-UM] read_kernel_raw: size too large (0x%zX)\n", size);
        return 0;
    }


    std::uint64_t use_dtb = kernel_dtb_;
    if (use_dtb == 0) use_dtb = dtb_;
    if (use_dtb == 0) {
        fprintf(stderr, "[WhosWho-UM] read_kernel_raw: no DTB available (kernel_dtb_=0, dtb_=0)\n");
        return 0;
    }
    fprintf(stderr, "[WhosWho-UM] read_kernel_raw: using dtb=0x%llX\n", use_dtb);

    std::size_t result = transfer_physical_read(4, use_dtb, address, buffer, size);
    fprintf(stderr, "[WhosWho-UM] read_kernel_raw: read 0x%zX / 0x%zX bytes\n", result, size);
    return result;
}

std::size_t voyager::device_t::write_kernel_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] write_kernel_raw: addr=0x%llX size=0x%zX\n", address, size);

    if (!buffer || size == 0 || !is_connected()) {
        fprintf(stderr, "[WhosWho-UM] write_kernel_raw: precondition fail\n");
        return 0;
    }

    if (size > 0x10000000) {
        fprintf(stderr, "[WhosWho-UM] write_kernel_raw: size too large (0x%zX)\n", size);
        return 0;
    }

    std::uint64_t use_dtb = kernel_dtb_;
    if (use_dtb == 0) use_dtb = dtb_;
    if (use_dtb == 0) {
        fprintf(stderr, "[WhosWho-UM] write_kernel_raw: no DTB available\n");
        return 0;
    }

    std::size_t result = transfer_physical_write(4, use_dtb, address, buffer, size);
    fprintf(stderr, "[WhosWho-UM] write_kernel_raw: wrote 0x%zX / 0x%zX bytes\n", result, size);
    return result;
}

std::uint64_t voyager::device_t::find_image() noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] find_image: pid=%u\n", process_id_);

    std::uint64_t image_address = 0;

    detail::base_address_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.out_address = &image_address;

    if (send_request(ioctl_codes::BASE(), &req, sizeof(req))) {
        base_address_ = image_address;
        fprintf(stderr, "[WhosWho-UM] find_image: OK base=0x%llX\n", base_address_);
    } else {
        fprintf(stderr, "[WhosWho-UM] find_image: BASE IOCTL failed\n");
    }

    return image_address;
}

std::size_t voyager::device_t::read_raw(std::uint64_t address, void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;

    if (!buffer || size == 0 || !is_connected() || dtb_ == 0) {
        fprintf(stderr, "[WhosWho-UM] read_raw: precondition fail buf=%p size=0x%zX connected=%d dtb=0x%llX\n",
            buffer, size, is_connected(), dtb_);
        return 0;
    }

    if (size > 0x10000000) {
        fprintf(stderr, "[WhosWho-UM] read_raw: size too large (0x%zX)\n", size);
        return 0;
    }

    return transfer_physical_read(process_id_, dtb_, address, buffer, size);
}

std::size_t voyager::device_t::write_raw(std::uint64_t address, const void* buffer, std::size_t size) const noexcept {
    SPOOF_FUNC;

    if (!buffer || size == 0 || !is_connected() || dtb_ == 0) {
        fprintf(stderr, "[WhosWho-UM] write_raw: precondition fail buf=%p size=0x%zX connected=%d dtb=0x%llX\n",
            buffer, size, is_connected(), dtb_);
        return 0;
    }

    if (size > 0x10000000) {
        fprintf(stderr, "[WhosWho-UM] write_raw: size too large (0x%zX)\n", size);
        return 0;
    }

    return transfer_physical_write(process_id_, dtb_, address, buffer, size);
}

void voyager::device_t::move_mouse(std::int32_t input_x, std::int32_t input_y, std::uint32_t mouse_flags) {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] move_mouse: x=%d y=%d flags=0x%X\n", input_x, input_y, mouse_flags);

    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] move_mouse: not connected\n");
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

    fprintf(stderr, "[WhosWho-UM] send_key: button=0x%X\n", button);

    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] send_key: not connected\n");
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

    fprintf(stderr, "[WhosWho-UM] allocate_memory: pid=%u size=0x%zX\n", process_id_, size);

    if (!is_connected() || process_id_ == 0 || size == 0) {
        fprintf(stderr, "[WhosWho-UM] allocate_memory: precondition fail\n");
        return 0;
    }

    detail::alloc_mem_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.size = size;
    req.allocated_address = 0;
    req.actual_size = 0;

    if (send_request(ioctl_codes::AM(), &req, sizeof(req)) && req.allocated_address != 0) {
        fprintf(stderr, "[WhosWho-UM] allocate_memory: OK addr=0x%llX actual_size=0x%llX\n",
            req.allocated_address, req.actual_size);
        return req.allocated_address;
    }

    fprintf(stderr, "[WhosWho-UM] allocate_memory: FAILED\n");
    return 0;
}

bool voyager::device_t::free_memory(std::uint64_t address) noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] free_memory: pid=%u addr=0x%llX\n", process_id_, address);

    if (!is_connected() || process_id_ == 0 || address == 0) {
        fprintf(stderr, "[WhosWho-UM] free_memory: precondition fail\n");
        return false;
    }

    detail::free_mem_request req{};
    req.pid = process_id_;
    req.padding = 0;
    req.address = address;

    bool ok = send_request(ioctl_codes::FM(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] free_memory: %s\n", ok ? "OK" : "FAILED");
    return ok;
}

bool voyager::device_t::ensure_shellcode_allocated() noexcept {
    SPOOF_FUNC;

    if (shellcode_address_ != 0) {
        fprintf(stderr, "[WhosWho-UM] ensure_shellcode_allocated: already at 0x%llX\n", shellcode_address_);
        return true;
    }

    shellcode_address_ = allocate_memory(detail::SHELLCODE_ALLOC_SIZE);
    fprintf(stderr, "[WhosWho-UM] ensure_shellcode_allocated: result=0x%llX %s\n",
        shellcode_address_, shellcode_address_ ? "OK" : "FAILED");
    return shellcode_address_ != 0;
}

bool voyager::device_t::find_spoof_gadget() noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] find_spoof_gadget: base=0x%llX dtb=0x%llX\n", base_address_, dtb_);

    if (spoof_gadget_ != 0) {
        fprintf(stderr, "[WhosWho-UM] find_spoof_gadget: already cached at 0x%llX\n", spoof_gadget_);
        return true;
    }

    if (base_address_ == 0 || dtb_ == 0) {
        fprintf(stderr, "[WhosWho-UM] find_spoof_gadget: no base/dtb\n");
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
                fprintf(stderr, "[WhosWho-UM] find_spoof_gadget: FOUND at 0x%llX\n", spoof_gadget_);
                return true;
            }
        }
    }

    fprintf(stderr, "[WhosWho-UM] find_spoof_gadget: not found, using fallback\n");
    return true;
}

std::uint64_t voyager::device_t::find_gadget(const char* pattern, std::size_t pattern_size) noexcept {
    SPOOF_FUNC;

    fprintf(stderr, "[WhosWho-UM] find_gadget: pattern_size=%zu base=0x%llX\n", pattern_size, base_address_);

    if (!pattern || pattern_size == 0 || base_address_ == 0 || dtb_ == 0) {
        fprintf(stderr, "[WhosWho-UM] find_gadget: precondition fail\n");
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
                fprintf(stderr, "[WhosWho-UM] find_gadget: FOUND at 0x%llX\n", gadget_addr);
                return gadget_addr;
            }
        }
    }

    fprintf(stderr, "[WhosWho-UM] find_gadget: pattern not found\n");
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

    fprintf(stderr, "[WhosWho-UM] call_function: target=0x%llX args=[0x%llX, 0x%llX, 0x%llX, 0x%llX]\n",
        function_address, arg1, arg2, arg3, arg4);
    fprintf(stderr, "[WhosWho-UM] call_function: pid=%u dtb=0x%llX base=0x%llX spoof_gadget=0x%llX shellcode=0x%llX\n",
        process_id_, dtb_, base_address_, spoof_gadget_, shellcode_address_);

    if (!is_connected() || dtb_ == 0 || function_address == 0) {
        fprintf(stderr, "[WhosWho-UM] call_function: precondition fail connected=%d dtb=0x%llX func=0x%llX\n",
            is_connected(), dtb_, function_address);
        return 0;
    }

    if (!ensure_shellcode_allocated()) {
        fprintf(stderr, "[WhosWho-UM] call_function: ensure_shellcode_allocated FAILED\n");
        return 0;
    }
    fprintf(stderr, "[WhosWho-UM] call_function: shellcode_address=0x%llX\n", shellcode_address_);

    if (!find_spoof_gadget()) {
        fprintf(stderr, "[WhosWho-UM] call_function: find_spoof_gadget FAILED\n");
        return 0;
    }
    fprintf(stderr, "[WhosWho-UM] call_function: spoof_gadget=0x%llX\n", spoof_gadget_);

    if (!thread_hijack::initialize()) {
        fprintf(stderr, "[WhosWho-UM] call_function: thread_hijack::initialize FAILED\n");
        fprintf(stderr, "[WhosWho-UM] call_function: syscall_addr=%p NtOpenThread=%u NtSuspend=%u NtResume=%u NtGetCtx=%u NtSetCtx=%u NtClose=%u\n",
            syscall_indices::syscall_instruction_addr,
            syscall_indices::NtOpenThread_idx, syscall_indices::NtSuspendThread_idx,
            syscall_indices::NtResumeThread_idx, syscall_indices::NtGetContextThread_idx,
            syscall_indices::NtSetContextThread_idx, syscall_indices::NtClose_idx);
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
        fprintf(stderr, "[WhosWho-UM] call_function: RC ioctl FAILED\n");
        return 0;
    }

    std::uint64_t code_entry = req.shellcode_address;
    fprintf(stderr, "[WhosWho-UM] call_function: RC ioctl OK, code_entry=0x%llX\n", code_entry);

    thread_hijack::scatter_timing();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[WhosWho-UM] call_function: CreateToolhelp32Snapshot FAILED err=%lu\n", GetLastError());
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
                                (ctx.Rsp & 0x7) == 0) {
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

    fprintf(stderr, "[WhosWho-UM] call_function: thread scan done, scanned=%u best_tid=%lu best_priority=%d\n",
        thread_scan_count, best_tid, best_priority);

    if (!best_thread || best_tid == 0) {
        fprintf(stderr, "[WhosWho-UM] call_function: no suitable thread found for hijack\n");
        return 0;
    }

    target_thread = best_thread;
    target_tid = best_tid;

    thread_hijack::scatter_timing();

    CONTEXT original_ctx = best_ctx;

    write_raw(context_base + detail::CTX_ORIGINAL_RIP, &original_ctx.Rip, sizeof(std::uint64_t));

    CONTEXT hijack_ctx = original_ctx;
    hijack_ctx.Rip = code_entry;

    std::uint64_t shellcode_rsp = ((hijack_ctx.Rsp - 0x108) & ~0xFULL) + 0x8;
    hijack_ctx.Rsp = shellcode_rsp;

    fprintf(stderr, "[WhosWho-UM] call_function: hijacking tid=%lu original_rip=0x%llX original_rsp=0x%llX -> new_rip=0x%llX new_rsp=0x%llX\n",
        target_tid, original_ctx.Rip, original_ctx.Rsp, hijack_ctx.Rip, hijack_ctx.Rsp);

    thread_hijack::scatter_timing();

    NTSTATUS set_status = thread_hijack::indirect_NtSetContextThread(target_thread, &hijack_ctx);
    if (set_status < 0) {
        fprintf(stderr, "[WhosWho-UM] call_function: NtSetContextThread FAILED status=0x%lX\n", set_status);
        thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
        thread_hijack::indirect_NtClose(target_thread);
        return 0;
    }
    fprintf(stderr, "[WhosWho-UM] call_function: NtSetContextThread OK, resuming thread\n");

    thread_hijack::collect_entropy();

    thread_hijack::indirect_NtResumeThread(target_thread, nullptr);

    constexpr int MAX_WAIT_ITERATIONS = 12000;
    constexpr int FAST_POLL_THRESHOLD = 500;
    constexpr int MEDIUM_POLL_THRESHOLD = 3000;

    std::uint64_t result = 0;
    bool completed = false;
    int consecutive_poll_failures = 0;

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
        result_req.completed = 0;

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
            if (result_req.completed != 0) {
                result = result_req.result;
                completed = true;
                break;
            }

            consecutive_poll_failures = 0;
            continue;
        }

        if (!ioctl_result) {
            DWORD poll_error = GetLastError();

            if (poll_error == ERROR_IO_PENDING || poll_error == ERROR_IO_INCOMPLETE) {
                consecutive_poll_failures = 0;
            } else {
                ++consecutive_poll_failures;
                if (consecutive_poll_failures >= 8) {
                    fprintf(stderr, "[WhosWho-UM] call_function: aborting result poll after repeated CR failures err=%lu\n",
                        poll_error);
                    break;
                }
            }
        } else {
            consecutive_poll_failures = 0;
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
        fprintf(stderr, "[WhosWho-UM] call_function: TIMED OUT after polling, restoring original context\n");
        thread_hijack::indirect_NtSetContextThread(target_thread, &original_ctx);
    } else {
        fprintf(stderr, "[WhosWho-UM] call_function: completed, result=0x%llX\n", result);
    }

    thread_hijack::indirect_NtResumeThread(target_thread, nullptr);
    thread_hijack::indirect_NtClose(target_thread);

    return result;
}

bool voyager::device_t::send_request(DWORD control_code, void* input, DWORD input_size) const noexcept {
    if (!is_connected() || !input || input_size == 0) {
        fprintf(stderr, "[WhosWho-UM] send_request: precondition fail connected=%d input=%p size=%u\n",
            is_connected(), input, input_size);
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

    if (!result) {
        DWORD err = GetLastError();
        fprintf(stderr, "[WhosWho-UM] send_request: DeviceIoControl FAILED ioctl=0x%08X err=%u(0x%X) bytes_returned=%u\n",
            control_code, err, err, bytes_returned);
    }

    return result != FALSE;
}


bool voyager::device_t::get_thread_context(std::uint32_t tid, thread_context& ctx) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0) {
        fprintf(stderr, "[WhosWho-UM] get_thread_context: precondition fail connected=%d pid=%u tid=%u\n",
            is_connected(), process_id_, tid);
        return false;
    }

    voyager::detail::thread_ctx_request req{};
    req.pid = process_id_;
    req.tid = tid;
    req.should_set = 0;
    req.register_mask = 0;

    fprintf(stderr, "[WhosWho-UM] get_thread_context: sending TCTX ioctl=0x%08X for PID=%u TID=%u\n",
        ioctl_codes::TCTX(), process_id_, tid);

    bool ok = send_request(ioctl_codes::TCTX(), &req, sizeof(req));
    if (!ok) {
        std::uint32_t prev_count = 0;
        bool suspended = suspend_thread(tid, &prev_count);
        if (suspended) {
            fprintf(stderr, "[WhosWho-UM] get_thread_context: retrying after suspend TID=%u\n", tid);
            ok = send_request(ioctl_codes::TCTX(), &req, sizeof(req));
            std::uint32_t ignored = 0;
            (void)resume_thread(tid, &ignored);
        }
    }
    if (!ok) {
        fprintf(stderr, "[WhosWho-UM] get_thread_context: send_request FAILED for TID=%u\n", tid);
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] get_thread_context: response RIP=0x%llX RSP=0x%llX RAX=0x%llX DR0=0x%llX DR7=0x%llX\n",
        req.rip, req.rsp, req.rax, req.dr0, req.dr7);

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
        fprintf(stderr, "[WhosWho-UM] set_thread_context: precondition fail connected=%d pid=%u tid=%u\n",
            is_connected(), process_id_, tid);
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] set_thread_context: PID=%u TID=%u mask=0x%llX\n",
        process_id_, tid, register_mask);
    fprintf(stderr, "[WhosWho-UM] set_thread_context: RIP=0x%llX RSP=0x%llX DR0=0x%llX DR7=0x%llX\n",
        ctx.rip, ctx.rsp, ctx.dr0, ctx.dr7);

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
    if (!ok) {
        std::uint32_t prev_count = 0;
        bool suspended = suspend_thread(tid, &prev_count);
        if (suspended) {
            fprintf(stderr, "[WhosWho-UM] set_thread_context: retrying after suspend TID=%u\n", tid);
            ok = send_request(ioctl_codes::TCTX(), &req, sizeof(req));
            std::uint32_t ignored = 0;
            (void)resume_thread(tid, &ignored);
        }
    }
    return ok;
}

std::vector<voyager::device_t::thread_info> voyager::device_t::enumerate_threads() noexcept {
    std::vector<thread_info> result;
    if (!is_connected() || process_id_ == 0) {
        fprintf(stderr, "[WhosWho-UM] enumerate_threads: precondition fail\n");
        return result;
    }

    auto* req = new (std::nothrow) voyager::detail::thread_enum_request{};
    if (!req) return result;

    req->pid = process_id_;
    req->thread_count = 0;

    if (send_request(ioctl_codes::TENUM(), req, sizeof(*req))) {
        fprintf(stderr, "[WhosWho-UM] enumerate_threads: found %u threads\n", req->thread_count);
        result.reserve(req->thread_count);
        for (std::uint32_t i = 0; i < req->thread_count && i < voyager::detail::MAX_ENUM_THREADS; i++) {
            thread_info ti;
            ti.tid = req->entries[i].tid;
            ti.state = req->entries[i].state;
            ti.rip = req->entries[i].rip;
            result.push_back(ti);
        }
    } else {
        fprintf(stderr, "[WhosWho-UM] enumerate_threads: IOCTL failed\n");
    }

    delete req;
    return result;
}

bool voyager::device_t::suspend_thread(std::uint32_t tid, std::uint32_t* prev_count) noexcept {
    fprintf(stderr, "[WhosWho-UM] suspend_thread: tid=%u\n", tid);
    if (!is_connected() || tid == 0) {
        fprintf(stderr, "[WhosWho-UM] suspend_thread: precondition fail\n");
        return false;
    }

    voyager::detail::suspend_resume_request req{};
    req.tid = tid;
    req.should_resume = 0;

    bool ok = send_request(ioctl_codes::TSR(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] suspend_thread: %s prev_count=%u\n", ok ? "OK" : "FAILED", req.previous_count);
    if (ok && prev_count) *prev_count = req.previous_count;
    return ok;
}

bool voyager::device_t::resume_thread(std::uint32_t tid, std::uint32_t* prev_count) noexcept {
    fprintf(stderr, "[WhosWho-UM] resume_thread: tid=%u\n", tid);
    if (!is_connected() || tid == 0) {
        fprintf(stderr, "[WhosWho-UM] resume_thread: precondition fail\n");
        return false;
    }

    voyager::detail::suspend_resume_request req{};
    req.tid = tid;
    req.should_resume = 1;

    bool ok = send_request(ioctl_codes::TSR(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] resume_thread: %s prev_count=%u\n", ok ? "OK" : "FAILED", req.previous_count);
    if (ok && prev_count) *prev_count = req.previous_count;
    return ok;
}

bool voyager::device_t::query_memory(std::uint64_t address, memory_region_info& info) noexcept {
    fprintf(stderr, "[WhosWho-UM] query_memory: pid=%u addr=0x%llX\n", process_id_, address);
    if (!is_connected() || process_id_ == 0) {
        fprintf(stderr, "[WhosWho-UM] query_memory: precondition fail\n");
        return false;
    }

    voyager::detail::query_memory_request req{};
    req.pid = process_id_;
    req.address = address;

    if (!send_request(ioctl_codes::QM(), &req, sizeof(req))) {
        fprintf(stderr, "[WhosWho-UM] query_memory: IOCTL failed\n");
        return false;
    }

    info.base = req.region_base;
    info.size = req.region_size;
    info.state = req.state;
    info.protect = req.protect;
    info.type = req.type;
    info.allocation_protect = req.allocation_protect;
    info.allocation_base = req.allocation_base;

    fprintf(stderr, "[WhosWho-UM] query_memory: OK base=0x%llX size=0x%llX state=0x%X protect=0x%X\n",
        info.base, info.size, info.state, info.protect);
    return true;
}

bool voyager::device_t::protect_memory(std::uint64_t address, std::uint64_t size, std::uint32_t new_protect, std::uint32_t* old_protect) noexcept {
    fprintf(stderr, "[WhosWho-UM] protect_memory: pid=%u addr=0x%llX size=0x%llX new_protect=0x%X\n",
        process_id_, address, size, new_protect);
    if (!is_connected() || process_id_ == 0 || size == 0) {
        fprintf(stderr, "[WhosWho-UM] protect_memory: precondition fail\n");
        return false;
    }

    voyager::detail::protect_memory_request req{};
    req.pid = process_id_;
    req.address = address;
    req.size = size;
    req.new_protect = new_protect;

    bool ok = send_request(ioctl_codes::PM(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] protect_memory: %s old_protect=0x%X\n", ok ? "OK" : "FAILED", req.old_protect);
    if (ok && old_protect) *old_protect = req.old_protect;
    return ok;
}

std::vector<voyager::detail::region_entry> voyager::device_t::enumerate_memory_regions(std::uint64_t start, std::uint64_t end_addr, bool include_all) noexcept {
    std::vector<voyager::detail::region_entry> result;
    fprintf(stderr, "[WhosWho-UM] enumerate_memory_regions: pid=%u start=0x%llX end=0x%llX include_all=%d\n",
        process_id_, start, end_addr, include_all);
    if (!is_connected() || process_id_ == 0) {
        fprintf(stderr, "[WhosWho-UM] enumerate_memory_regions: precondition fail\n");
        return result;
    }

    auto* req = new (std::nothrow) voyager::detail::enum_regions_request{};
    if (!req) return result;

    req->pid = process_id_;
    req->include_all = include_all ? 1 : 0;
    req->start_address = start;
    req->max_address = end_addr;
    req->region_count = 0;

    if (send_request(ioctl_codes::ER(), req, sizeof(*req))) {
        fprintf(stderr, "[WhosWho-UM] enumerate_memory_regions: found %u regions\n", req->region_count);
        result.reserve(req->region_count);
        for (std::uint32_t i = 0; i < req->region_count && i < voyager::detail::MAX_ENUM_REGIONS; i++) {
            result.push_back(req->entries[i]);
        }
    } else {
        fprintf(stderr, "[WhosWho-UM] enumerate_memory_regions: IOCTL failed\n");
    }

    delete req;
    return result;
}

bool voyager::device_t::read_peb(peb_info& info) noexcept {
    fprintf(stderr, "[WhosWho-UM] read_peb: pid=%u\n", process_id_);
    if (!is_connected() || process_id_ == 0) {
        fprintf(stderr, "[WhosWho-UM] read_peb: precondition fail\n");
        return false;
    }

    voyager::detail::read_peb_request req{};
    req.pid = process_id_;

    if (!send_request(ioctl_codes::RPEB(), &req, sizeof(req))) {
        fprintf(stderr, "[WhosWho-UM] read_peb: IOCTL failed\n");
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

    fprintf(stderr, "[WhosWho-UM] read_peb: OK peb=0x%llX image_base=0x%llX debugged=%u\n",
        info.peb_address, info.image_base, info.being_debugged);
    return true;
}

bool voyager::device_t::spoof_debug_flags(std::uint32_t* result_flags) noexcept {
    fprintf(stderr, "[WhosWho-UM] spoof_debug_flags: pid=%u\n", process_id_);
    if (!is_connected() || process_id_ == 0) {
        fprintf(stderr, "[WhosWho-UM] spoof_debug_flags: precondition fail\n");
        return false;
    }

    voyager::detail::spoof_debug_request req{};
    req.pid = process_id_;

    bool ok = send_request(ioctl_codes::SDF(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] spoof_debug_flags: %s flags=0x%X\n", ok ? "OK" : "FAILED", req.result_flags);
    if (ok && result_flags) *result_flags = req.result_flags;
    return ok;
}

std::uint64_t voyager::device_t::resolve_export(std::uint64_t module_base, const char* export_name) noexcept {
    fprintf(stderr, "[WhosWho-UM] resolve_export: module=0x%llX name=%s\n", module_base, export_name ? export_name : "(null)");
    if (!is_connected() || dtb_ == 0 || module_base == 0 || !export_name) {
        fprintf(stderr, "[WhosWho-UM] resolve_export: precondition fail\n");
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
        fprintf(stderr, "[WhosWho-UM] resolve_export: IOCTL failed\n");
        return 0;
    }
    fprintf(stderr, "[WhosWho-UM] resolve_export: resolved=0x%llX\n", req.resolved_address);
    return req.resolved_address;
}

std::uint64_t voyager::device_t::virtual_to_physical(std::uint64_t virtual_address) noexcept {
    fprintf(stderr, "[WhosWho-UM] virtual_to_physical: virt=0x%llX dtb=0x%llX\n", virtual_address, dtb_);
    if (!is_connected() || dtb_ == 0 || virtual_address == 0) {
        fprintf(stderr, "[WhosWho-UM] virtual_to_physical: precondition fail\n");
        return 0;
    }

    voyager::detail::virt_to_phys_request req{};
    req.dtb = dtb_;
    req.virtual_address = virtual_address;

    if (!send_request(ioctl_codes::V2P(), &req, sizeof(req))) {
        fprintf(stderr, "[WhosWho-UM] virtual_to_physical: IOCTL failed\n");
        return 0;
    }
    fprintf(stderr, "[WhosWho-UM] virtual_to_physical: phys=0x%llX\n", req.physical_address);
    return req.physical_address;
}

bool voyager::device_t::set_hardware_breakpoint(std::uint32_t tid, int index, std::uint64_t address, int type, int size) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0 || index < 0 || index > 3) {
        fprintf(stderr, "[WhosWho-UM] set_hw_bp: precondition fail connected=%d pid=%u tid=%u index=%d\n",
            is_connected(), process_id_, tid, index);
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] set_hw_bp: TID=%u index=%d addr=0x%llX type=%d size=%d\n",
        tid, index, address, type, size);

    thread_context ctx{};
    if (!get_thread_context(tid, ctx)) {
        fprintf(stderr, "[WhosWho-UM] set_hw_bp: get_thread_context FAILED for TID=%u\n", tid);
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] set_hw_bp: current DR0=0x%llX DR1=0x%llX DR2=0x%llX DR3=0x%llX DR6=0x%llX DR7=0x%llX\n",
        ctx.dr0, ctx.dr1, ctx.dr2, ctx.dr3, ctx.dr6, ctx.dr7);


    switch (index) {
        case 0: ctx.dr0 = address; break;
        case 1: ctx.dr1 = address; break;
        case 2: ctx.dr2 = address; break;
        case 3: ctx.dr3 = address; break;
    }


    ctx.dr6 = 0;


    std::uint64_t dr7 = ctx.dr7;


    int rw_shift = 16 + index * 4;
    int len_shift = 18 + index * 4;
    dr7 &= ~(1ULL << (index * 2));
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

    fprintf(stderr, "[WhosWho-UM] set_hw_bp: new DR%d=0x%llX DR7=0x%llX mask=0x%llX\n",
        index, address, dr7, mask);

    return set_thread_context(tid, ctx, mask);
}

bool voyager::device_t::clear_hardware_breakpoint(std::uint32_t tid, int index) noexcept {
    if (!is_connected() || process_id_ == 0 || tid == 0 || index < 0 || index > 3) {
        fprintf(stderr, "[WhosWho-UM] clear_hw_bp: precondition fail\n");
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] clear_hw_bp: TID=%u index=%d\n", tid, index);

    thread_context ctx{};
    if (!get_thread_context(tid, ctx)) {
        fprintf(stderr, "[WhosWho-UM] clear_hw_bp: get_thread_context FAILED for TID=%u\n", tid);
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] clear_hw_bp: current DR0=0x%llX DR7=0x%llX\n", ctx.dr0, ctx.dr7);


    switch (index) {
        case 0: ctx.dr0 = 0; break;
        case 1: ctx.dr1 = 0; break;
        case 2: ctx.dr2 = 0; break;
        case 3: ctx.dr3 = 0; break;
    }


    std::uint64_t dr7 = ctx.dr7;
    dr7 &= ~(1ULL << (index * 2));
    dr7 &= ~(3ULL << (16 + index * 4));
    dr7 &= ~(3ULL << (18 + index * 4));
    ctx.dr7 = dr7;

    std::uint64_t mask = (1ULL << (18 + index)) | (1ULL << 23);

    return set_thread_context(tid, ctx, mask);
}


std::vector<voyager::device_t::net_connection_info> voyager::device_t::enumerate_connections(std::uint32_t filter_pid, std::uint32_t filter_protocol) noexcept {
    std::vector<net_connection_info> result;
    fprintf(stderr, "[WhosWho-UM] enumerate_connections: filter_pid=%u filter_proto=%u\n", filter_pid, filter_protocol);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] enumerate_connections: not connected\n");
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
        fprintf(stderr, "[WhosWho-UM] enumerate_connections: found %u connections\n", req->connection_count);
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
            result.push_back(info);
        }
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return result;
}

bool voyager::device_t::start_capture(std::uint32_t filter_pid, std::uint32_t filter_port,
    std::uint32_t filter_protocol, const std::uint8_t* filter_ip, std::uint32_t max_payload) noexcept {
    fprintf(stderr, "[WhosWho-UM] start_capture: pid=%u port=%u proto=%u max_payload=%u\n",
        filter_pid, filter_port, filter_protocol, max_payload);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] start_capture: not connected\n");
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
        fprintf(stderr, "[WhosWho-UM] start_capture: IOCTL failed\n");
        return false;
    }
    fprintf(stderr, "[WhosWho-UM] start_capture: active=%u\n", req.capture_active);
    return req.capture_active != 0;
}

bool voyager::device_t::stop_capture() noexcept {
    fprintf(stderr, "[WhosWho-UM] stop_capture\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] stop_capture: not connected\n");
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 1;

    bool ok = send_request(ioctl_codes::NCAP(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] stop_capture: %s\n", ok ? "OK" : "FAILED");
    return ok;
}

bool voyager::device_t::get_capture_status(bool& active, std::uint32_t& captured, std::uint32_t& dropped) noexcept {
    fprintf(stderr, "[WhosWho-UM] get_capture_status\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_capture_status: not connected\n");
        return false;
    }

    voyager::detail::net_cap_ctrl_request req{};
    req.operation = 2;

    if (!send_request(ioctl_codes::NCAP(), &req, sizeof(req))) {
        fprintf(stderr, "[WhosWho-UM] get_capture_status: IOCTL failed\n");
        return false;
    }

    active = req.capture_active != 0;
    captured = req.packets_captured;
    dropped = req.packets_dropped;
    fprintf(stderr, "[WhosWho-UM] get_capture_status: active=%d captured=%u dropped=%u\n", active, captured, dropped);
    return true;
}

std::vector<voyager::device_t::captured_packet> voyager::device_t::get_captured_packets(std::uint32_t max_packets) noexcept {
    std::vector<captured_packet> result;
    fprintf(stderr, "[WhosWho-UM] get_captured_packets: max=%u\n", max_packets);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_captured_packets: not connected\n");
        return result;
    }

    auto* req = static_cast<voyager::detail::net_cap_get_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_cap_get_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->max_packets = max_packets;

    if (send_request(ioctl_codes::NCPG(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] get_captured_packets: got %u packets\n", req->packet_count);
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
    fprintf(stderr, "[WhosWho-UM] get_dns_queries: filter_pid=%u\n", filter_pid);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_dns_queries: not connected\n");
        return result;
    }

    auto* req = static_cast<voyager::detail::net_dns_get_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::net_dns_get_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->filter_pid = filter_pid;

    if (send_request(ioctl_codes::NDNS(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] get_dns_queries: got %u entries\n", req->entry_count);
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
    fprintf(stderr, "[WhosWho-UM] add_filter_rule: action=%u dir=%u proto=%u pid=%u port=%u\n",
        action, direction, protocol, pid, port);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] add_filter_rule: not connected\n");
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
        fprintf(stderr, "[WhosWho-UM] add_filter_rule: IOCTL failed\n");
        return false;
    }
    fprintf(stderr, "[WhosWho-UM] add_filter_rule: OK rule_id=%u\n", req.rule_id);
    if (out_rule_id) *out_rule_id = req.rule_id;
    return true;
}

bool voyager::device_t::remove_filter_rule(std::uint32_t rule_id) noexcept {
    fprintf(stderr, "[WhosWho-UM] remove_filter_rule: rule_id=%u\n", rule_id);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] remove_filter_rule: not connected\n");
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 1;
    req.rule_id = rule_id;

    bool ok = send_request(ioctl_codes::NFLT(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] remove_filter_rule: %s\n", ok ? "OK" : "FAILED");
    return ok;
}

bool voyager::device_t::clear_filter_rules() noexcept {
    fprintf(stderr, "[WhosWho-UM] clear_filter_rules\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] clear_filter_rules: not connected\n");
        return false;
    }

    voyager::detail::net_filter_rule_request req{};
    req.operation = 2;

    bool ok = send_request(ioctl_codes::NFLT(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] clear_filter_rules: %s\n", ok ? "OK" : "FAILED");
    return ok;
}

bool voyager::device_t::get_network_stats(network_stats& stats) noexcept {
    fprintf(stderr, "[WhosWho-UM] get_network_stats\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_network_stats: not connected\n");
        return false;
    }

    voyager::detail::net_stats_request req{};

    if (!send_request(ioctl_codes::NSTS(), &req, sizeof(req))) {
        fprintf(stderr, "[WhosWho-UM] get_network_stats: IOCTL failed\n");
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
    fprintf(stderr, "[WhosWho-UM] get_network_stats: sent=%llu recv=%llu active_conn=%u\n",
        stats.bytes_sent, stats.bytes_received, stats.active_connections);
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
    fprintf(stderr, "[WhosWho-UM] enumerate_wfp_callouts: filter='%s'\n", filter_module.c_str());
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] enumerate_wfp_callouts: not connected\n");
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
        fprintf(stderr, "[WhosWho-UM] enumerate_wfp_callouts: found %u callouts\n", req->callout_count);
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
    fprintf(stderr, "[WhosWho-UM] get_socket_handles: target_pid=%u\n", target_pid);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_socket_handles: not connected\n");
        return result;
    }

    auto* req = static_cast<voyager::detail::socket_handle_enum_request*>(
        VirtualAlloc(nullptr, sizeof(voyager::detail::socket_handle_enum_request),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->target_pid = (target_pid != 0) ? target_pid : process_id_;

    if (send_request(ioctl_codes::GSKT(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] get_socket_handles: found %u sockets\n", req->socket_count);
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
    fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_start: addr=0x%llX buf_reg=%u size_reg=%u max=%u tid=%u bp=%u\n",
        address, buf_reg, size_reg, max_captures, tid, bp_index);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_start: not connected\n");
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
    fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_start: %s\n", ok_sniff ? "OK" : "FAILED");
    return ok_sniff;
}

bool voyager::device_t::sniff_net_buffers_stop() noexcept {
    fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_stop\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_stop: not connected\n");
        return false;
    }

    voyager::detail::sniff_net_buffers_request req{};
    req.operation = 1;

    bool ok = send_request(ioctl_codes::SNBF(), &req, sizeof(req));
    fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_stop: %s\n", ok ? "OK" : "FAILED");
    return ok;
}

std::vector<voyager::device_t::sniff_result>
voyager::device_t::sniff_net_buffers_get(bool& active) noexcept {
    std::vector<sniff_result> result;
    active = false;
    fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_get\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_get: not connected\n");
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
        fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_get: active=%d captures=%u\n", active, req->capture_count);
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
    fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_store: ts=%llu tid=%llu size=%u\n", timestamp, thread_id, size);
    if (!is_connected() || !data || size == 0) {
        fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_store: precondition fail\n");
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
    fprintf(stderr, "[WhosWho-UM] sniff_net_buffers_store: %s\n", ok ? "OK" : "FAILED");
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::tcpip_connection>
voyager::device_t::dump_tcpip_connections(std::uint32_t target_pid, std::uint32_t filter_protocol) noexcept {
    std::vector<tcpip_connection> result;
    fprintf(stderr, "[WhosWho-UM] dump_tcpip_connections: pid=%u proto=%u\n", target_pid, filter_protocol);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] dump_tcpip_connections: not connected\n");
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
        fprintf(stderr, "[WhosWho-UM] dump_tcpip_connections: found %u connections\n", req->connection_count);
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
    fprintf(stderr, "[WhosWho-UM] inject_packet: dir=%u proto=%u af=%u sport=%u dport=%u size=%u\n",
        direction, protocol, af, src_port, dst_port, payload_size);
    if (!is_connected() || !payload || payload_size == 0) {
        fprintf(stderr, "[WhosWho-UM] inject_packet: precondition fail\n");
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
    fprintf(stderr, "[WhosWho-UM] inject_packet: ioctl=%s status=%u\n", ok ? "OK" : "FAILED", ok ? req->status : 0);
    VirtualFree(req, 0, MEM_RELEASE);
    return success;
}

bool voyager::device_t::packet_mod_rule_op(std::uint32_t operation, std::uint32_t rule_id,
                                            std::uint32_t direction, std::uint32_t protocol,
                                            std::uint32_t port, std::uint32_t pid,
                                            const std::uint8_t* pattern, std::uint32_t pattern_size,
                                            const std::uint8_t* replacement, std::uint32_t replace_size,
                                            std::uint32_t* out_rule_id) noexcept {
    fprintf(stderr, "[WhosWho-UM] packet_mod_rule_op: op=%u rule=%u dir=%u proto=%u port=%u pid=%u pat_sz=%u rep_sz=%u\n",
        operation, rule_id, direction, protocol, port, pid, pattern_size, replace_size);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] packet_mod_rule_op: not connected\n");
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
    fprintf(stderr, "[WhosWho-UM] packet_mod_rule_op: %s out_rule=%u\n", ok ? "OK" : "FAILED", ok ? req->rule_id : 0);
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::mod_rule_info> voyager::device_t::list_packet_mod_rules() noexcept {
    std::vector<mod_rule_info> result;
    fprintf(stderr, "[WhosWho-UM] list_packet_mod_rules\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] list_packet_mod_rules: not connected\n");
        return result;
    }

    auto* req = static_cast<detail::packet_mod_rule_list*>(
        VirtualAlloc(nullptr, sizeof(detail::packet_mod_rule_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::PMOD(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] list_packet_mod_rules: found %u rules\n", req->rule_count);
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
                                             std::uint32_t af, std::uint32_t* out_rule_id) noexcept {
    fprintf(stderr, "[WhosWho-UM] traffic_redirect_op: op=%u rule=%u proto=%u match_port=%u redir_port=%u af=%u\n",
        operation, rule_id, protocol, match_port, redirect_port, af);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] traffic_redirect_op: not connected\n");
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

    bool ok = send_request(ioctl_codes::PRED(), req, static_cast<DWORD>(sizeof(*req)));
    fprintf(stderr, "[WhosWho-UM] traffic_redirect_op: %s out_rule=%u\n", ok ? "OK" : "FAILED", ok ? req->rule_id : 0);
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::redirect_rule_info> voyager::device_t::list_redirect_rules() noexcept {
    std::vector<redirect_rule_info> result;
    fprintf(stderr, "[WhosWho-UM] list_redirect_rules\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] list_redirect_rules: not connected\n");
        return result;
    }

    auto* req = static_cast<detail::traffic_redirect_list*>(
        VirtualAlloc(nullptr, sizeof(detail::traffic_redirect_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::PRED(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] list_redirect_rules: found %u rules\n", req->rule_count);
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
    fprintf(stderr, "[WhosWho-UM] stream_reassemble_op: op=%u sport=%u dport=%u pid=%u\n",
        operation, src_port, dst_port, pid);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] stream_reassemble_op: not connected\n");
        return false;
    }

    auto* req = static_cast<detail::stream_reassemble_request*>(
        VirtualAlloc(nullptr, sizeof(detail::stream_reassemble_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->pid = pid;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);

    bool ok = send_request(ioctl_codes::STRM(), req, static_cast<DWORD>(sizeof(*req)));
    fprintf(stderr, "[WhosWho-UM] stream_reassemble_op: %s total_pkts=%u truncated=%u\n",
        ok ? "OK" : "FAILED", ok ? req->total_packets : 0, ok ? req->truncated : 0);
    if (ok) {
        if (out_data && req->stream_size > 0) {
            out_data->assign(req->stream_data, req->stream_data + req->stream_size);
        }
        if (out_packets) *out_packets = req->total_packets;
        if (out_truncated) *out_truncated = req->truncated;
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::dpi_result> voyager::device_t::get_dpi_results(
    std::uint32_t filter_pid, std::uint32_t filter_protocol,
    std::uint32_t filter_port, std::uint32_t flags) noexcept {
    std::vector<dpi_result> result;
    fprintf(stderr, "[WhosWho-UM] get_dpi_results: pid=%u proto=%u port=%u flags=0x%X\n",
        filter_pid, filter_protocol, filter_port, flags);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_dpi_results: not connected\n");
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
        fprintf(stderr, "[WhosWho-UM] get_dpi_results: found %u results\n", req->result_count);
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
    fprintf(stderr, "[WhosWho-UM] intercept_op: op=%u pid=%u port=%u proto=%u hold_id=%llu mod_sz=%u\n",
        operation, filter_pid, filter_port, filter_protocol, hold_id, modify_size);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] intercept_op: not connected\n");
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
    fprintf(stderr, "[WhosWho-UM] intercept_op: %s held=%u active=%d\n",
        ok ? "OK" : "FAILED", ok ? req->held_count : 0, ok ? req->intercepting : 0);
    if (ok) {
        if (out_held_count) *out_held_count = req->held_count;
        if (out_active) *out_active = (req->intercepting != 0);
    }

    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::held_packet_info> voyager::device_t::get_held_packets() noexcept {
    std::vector<held_packet_info> result;
    fprintf(stderr, "[WhosWho-UM] get_held_packets\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_held_packets: not connected\n");
        return result;
    }

    auto* req = static_cast<detail::intercept_request*>(
        VirtualAlloc(nullptr, sizeof(detail::intercept_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::IHLD(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] get_held_packets: found %u held packets\n", req->held_count);
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
    fprintf(stderr, "[WhosWho-UM] kill_connection: proto=%u af=%u sport=%u dport=%u pid=%u\n",
        protocol, af, src_port, dst_port, pid);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] kill_connection: not connected\n");
        return false;
    }

    auto* req = static_cast<detail::conn_kill_request*>(
        VirtualAlloc(nullptr, sizeof(detail::conn_kill_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->protocol = protocol;
    req->address_family = af;
    req->src_port = src_port;
    req->dst_port = dst_port;
    req->pid = pid;
    if (src_addr) std::memcpy(req->src_addr, src_addr, 16);
    if (dst_addr) std::memcpy(req->dst_addr, dst_addr, 16);

    bool ok = send_request(ioctl_codes::CKIL(), req, static_cast<DWORD>(sizeof(*req)));
    bool success = ok && (req->status == 0);
    fprintf(stderr, "[WhosWho-UM] kill_connection: ioctl=%s status=%u\n", ok ? "OK" : "FAILED", ok ? req->status : 0);
    VirtualFree(req, 0, MEM_RELEASE);
    return success;
}

bool voyager::device_t::dns_spoof_op(std::uint32_t operation, std::uint32_t rule_id,
                                      const char* domain,
                                      const std::uint8_t* spoof_addr, std::uint32_t af,
                                      std::uint32_t ttl, std::uint32_t* out_rule_id) noexcept {
    fprintf(stderr, "[WhosWho-UM] dns_spoof_op: op=%u rule=%u domain='%s' af=%u ttl=%u\n",
        operation, rule_id, domain ? domain : "(null)", af, ttl);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] dns_spoof_op: not connected\n");
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
    fprintf(stderr, "[WhosWho-UM] dns_spoof_op: %s out_rule=%u\n", ok ? "OK" : "FAILED", ok ? req->rule_id : 0);
    if (ok && out_rule_id) *out_rule_id = req->rule_id;
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::dns_spoof_info> voyager::device_t::list_dns_spoof_rules() noexcept {
    std::vector<dns_spoof_info> result;
    fprintf(stderr, "[WhosWho-UM] list_dns_spoof_rules\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] list_dns_spoof_rules: not connected\n");
        return result;
    }

    auto* req = static_cast<detail::dns_spoof_list*>(
        VirtualAlloc(nullptr, sizeof(detail::dns_spoof_list), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::DNSS(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] list_dns_spoof_rules: found %u rules\n", req->rule_count);
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
    fprintf(stderr, "[WhosWho-UM] bw_monitor_op: op=%u pid=%u\n", operation, filter_pid);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] bw_monitor_op: not connected\n");
        return false;
    }

    auto* req = static_cast<detail::bw_monitor_request*>(
        VirtualAlloc(nullptr, sizeof(detail::bw_monitor_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;
    req->filter_pid = filter_pid;

    bool ok = send_request(ioctl_codes::BWMN(), req, static_cast<DWORD>(sizeof(*req)));
    fprintf(stderr, "[WhosWho-UM] bw_monitor_op: %s active=%d\n", ok ? "OK" : "FAILED",
        ok ? req->monitoring_active : 0);
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
    fprintf(stderr, "[WhosWho-UM] get_bw_per_process: pid=%u\n", filter_pid);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_bw_per_process: not connected\n");
        return result;
    }

    auto* req = static_cast<detail::bw_monitor_request*>(
        VirtualAlloc(nullptr, sizeof(detail::bw_monitor_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 4;
    req->filter_pid = filter_pid;

    if (send_request(ioctl_codes::BWMN(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] get_bw_per_process: found %u processes\n", req->process_count);
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
    fprintf(stderr, "[WhosWho-UM] enumerate_interfaces\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] enumerate_interfaces: not connected\n");
        return result;
    }

    auto* req = static_cast<detail::net_interface_enum*>(
        VirtualAlloc(nullptr, sizeof(detail::net_interface_enum), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));

    if (send_request(ioctl_codes::NIFS(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] enumerate_interfaces: found %u interfaces\n", req->interface_count);
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
    fprintf(stderr, "[WhosWho-UM] export_pcap: pid=%u proto=%u max=%u\n", filter_pid, filter_protocol, max_packets);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] export_pcap: not connected\n");
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
    fprintf(stderr, "[WhosWho-UM] export_pcap: %s packets=%u\n", ok ? "OK" : "FAILED",
        ok ? req->packet_count : 0);
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
    fprintf(stderr, "[WhosWho-UM] fingerprint_op: op=%u\n", operation);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] fingerprint_op: not connected\n");
        return false;
    }

    auto* req = static_cast<detail::net_fingerprint_request*>(
        VirtualAlloc(nullptr, sizeof(detail::net_fingerprint_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return false;

    std::memset(req, 0, sizeof(*req));
    req->operation = operation;

    bool ok = send_request(ioctl_codes::NFPR(), req, static_cast<DWORD>(sizeof(*req)));
    fprintf(stderr, "[WhosWho-UM] fingerprint_op: %s\n", ok ? "OK" : "FAILED");
    VirtualFree(req, 0, MEM_RELEASE);
    return ok;
}

std::vector<voyager::device_t::fingerprint_info> voyager::device_t::get_fingerprints() noexcept {
    std::vector<fingerprint_info> result;
    fprintf(stderr, "[WhosWho-UM] get_fingerprints\n");
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] get_fingerprints: not connected\n");
        return result;
    }

    auto* req = static_cast<detail::net_fingerprint_request*>(
        VirtualAlloc(nullptr, sizeof(detail::net_fingerprint_request), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!req) return result;

    std::memset(req, 0, sizeof(*req));
    req->operation = 2;

    if (send_request(ioctl_codes::NFPR(), req, static_cast<DWORD>(sizeof(*req)))) {
        fprintf(stderr, "[WhosWho-UM] get_fingerprints: found %u entries\n", req->result_count);
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

// ── DLL Protection API ──────────────────────────────────────────────────
// WHY: The driver's kernel-resident DPC timer computes a CRC hash of the
// DLL's .text section via physical memory reads every N milliseconds.
// If the hash ever mismatches the registered value, the driver issues
// KeBugCheckEx from ring-0 — there is no user-mode code path that can
// intercept or NOP this. An attacker would need to patch the driver
// *in kernel memory* (PatchGuard territory) to circumvent it.

bool voyager::device_t::register_dll_protection(
    std::uint64_t module_base, std::uint64_t text_va,
    std::uint32_t text_size, std::uint64_t expected_hash,
    std::uint32_t check_interval_ms) noexcept
{
    fprintf(stderr, "[WhosWho-UM] register_dll_protection: base=0x%llX text_va=0x%llX size=%u hash=0x%llX interval=%u\n",
        module_base, text_va, text_size, expected_hash, check_interval_ms);
    if (!is_connected() || process_id_ == 0) {
        fprintf(stderr, "[WhosWho-UM] register_dll_protection: precondition fail (connected=%d pid=%u)\n",
            is_connected(), process_id_);
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
        fprintf(stderr, "[WhosWho-UM] register_dll_protection: IOCTL failed\n");
        return false;
    }

    fprintf(stderr, "[WhosWho-UM] register_dll_protection: status=%u\n", req.status);
    return req.status == detail::DPRT_STATUS_ACTIVE;
}

bool voyager::device_t::query_dll_protection(dll_protect_status& out) noexcept
{
    fprintf(stderr, "[WhosWho-UM] query_dll_protection: pid=%u\n", process_id_);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] query_dll_protection: not connected\n");
        return false;
    }

    detail::dll_protect_request req{};
    req.operation = detail::DPRT_OP_QUERY;
    req.pid = process_id_;

    if (!send_request(ioctl_codes::DPRT(), &req, static_cast<DWORD>(sizeof(req)))) {
        fprintf(stderr, "[WhosWho-UM] query_dll_protection: IOCTL failed\n");
        return false;
    }

    out.status = req.status;
    out.current_hash = req.current_hash;
    out.expected_hash = req.expected_hash;
    out.last_check_tsc = req.last_check_tsc;
    fprintf(stderr, "[WhosWho-UM] query_dll_protection: status=%u cur_hash=0x%llX exp_hash=0x%llX\n",
        out.status, out.current_hash, out.expected_hash);
    return true;
}

bool voyager::device_t::unregister_dll_protection() noexcept
{
    fprintf(stderr, "[WhosWho-UM] unregister_dll_protection: pid=%u\n", process_id_);
    if (!is_connected()) {
        fprintf(stderr, "[WhosWho-UM] unregister_dll_protection: not connected\n");
        return false;
    }

    detail::dll_protect_request req{};
    req.operation = detail::DPRT_OP_UNREGISTER;
    req.pid = process_id_;

    bool ok = send_request(ioctl_codes::DPRT(), &req, static_cast<DWORD>(sizeof(req)));
    fprintf(stderr, "[WhosWho-UM] unregister_dll_protection: %s\n", ok ? "OK" : "FAILED");
    return ok;
}
