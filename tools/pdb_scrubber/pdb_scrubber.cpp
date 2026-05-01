#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

bool read_file(const char* path, std::vector<uint8_t>& out_buffer) {
    HANDLE handle = ::CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size = {};
    if (!::GetFileSizeEx(handle, &size)) {
        ::CloseHandle(handle);
        return false;
    }
    if (size.QuadPart <= 0 || size.QuadPart > (1024LL * 1024LL * 1024LL)) {
        ::CloseHandle(handle);
        return false;
    }
    out_buffer.resize(static_cast<size_t>(size.QuadPart));
    DWORD read_total = 0;
    BOOL ok = ::ReadFile(
        handle,
        out_buffer.data(),
        static_cast<DWORD>(out_buffer.size()),
        &read_total,
        nullptr);
    ::CloseHandle(handle);
    return ok != FALSE && read_total == out_buffer.size();
}

bool write_file(const char* path, const std::vector<uint8_t>& buffer) {
    HANDLE handle = ::CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    BOOL ok = ::WriteFile(
        handle,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &written,
        nullptr);
    ::CloseHandle(handle);
    return ok != FALSE && written == buffer.size();
}

bool locate_nt_headers(const std::vector<uint8_t>& image,
                       size_t& out_dos_size,
                       PIMAGE_DOS_HEADER& out_dos,
                       PIMAGE_NT_HEADERS64& out_nt) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    out_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<uint8_t*>(image.data()));
    if (out_dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (out_dos->e_lfanew <= 0 ||
        static_cast<size_t>(out_dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > image.size()) {
        return false;
    }
    out_nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        const_cast<uint8_t*>(image.data()) + out_dos->e_lfanew);
    if (out_nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    out_dos_size = static_cast<size_t>(out_dos->e_lfanew);
    return true;
}

void wipe_rich_header(uint8_t* dos_stub, size_t stub_size) {
    if (!dos_stub || stub_size < sizeof(IMAGE_DOS_HEADER) + 4u) {
        return;
    }
    static const uint8_t k_rich_marker[4] = { 'R', 'i', 'c', 'h' };
    size_t scan_end = stub_size - 4u;
    size_t rich_pos = static_cast<size_t>(-1);
    for (size_t idx = sizeof(IMAGE_DOS_HEADER); idx <= scan_end; idx += 4u) {
        if (std::memcmp(dos_stub + idx, k_rich_marker, 4) == 0) {
            rich_pos = idx;
            break;
        }
    }
    if (rich_pos == static_cast<size_t>(-1)) {
        return;
    }
    static const uint8_t k_dans_marker[4] = { 'D', 'a', 'n', 'S' };
    uint32_t xor_key = 0;
    if (rich_pos + 8u <= stub_size) {
        std::memcpy(&xor_key, dos_stub + rich_pos + 4u, sizeof(uint32_t));
    }
    size_t dans_pos = static_cast<size_t>(-1);
    for (size_t idx = sizeof(IMAGE_DOS_HEADER); idx + 4u <= rich_pos; idx += 4u) {
        uint32_t word = 0;
        std::memcpy(&word, dos_stub + idx, sizeof(uint32_t));
        uint32_t decoded = word ^ xor_key;
        if (std::memcmp(&decoded, k_dans_marker, 4) == 0) {
            dans_pos = idx;
            break;
        }
    }
    size_t wipe_start = (dans_pos != static_cast<size_t>(-1)) ? dans_pos : sizeof(IMAGE_DOS_HEADER);
    size_t wipe_end = rich_pos + 8u;
    if (wipe_end > stub_size) {
        wipe_end = stub_size;
    }
    if (wipe_start >= wipe_end) {
        return;
    }
    std::memset(dos_stub + wipe_start, 0, wipe_end - wipe_start);
}

uint8_t* rva_to_ptr(std::vector<uint8_t>& image,
                    PIMAGE_NT_HEADERS64 nt,
                    uint32_t rva) {
    if (!nt || rva == 0) {
        return nullptr;
    }
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (uint16_t idx = 0; idx < nt->FileHeader.NumberOfSections; ++idx, ++section) {
        uint32_t va_start = section->VirtualAddress;
        uint32_t va_end = va_start + section->Misc.VirtualSize;
        if (rva >= va_start && rva < va_end) {
            uint32_t delta = rva - va_start;
            uint32_t raw = section->PointerToRawData + delta;
            if (static_cast<size_t>(raw) >= image.size()) {
                return nullptr;
            }
            return image.data() + raw;
        }
    }
    return nullptr;
}

void wipe_pdb_paths(std::vector<uint8_t>& image, PIMAGE_NT_HEADERS64 nt) {
    if (!nt) {
        return;
    }
    IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return;
    }
    uint32_t entry_count = dir.Size / static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
    for (uint32_t idx = 0; idx < entry_count; ++idx) {
        uint32_t entry_rva = dir.VirtualAddress + idx * static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY));
        uint8_t* entry_ptr = rva_to_ptr(image, nt, entry_rva);
        if (!entry_ptr) {
            continue;
        }
        IMAGE_DEBUG_DIRECTORY entry = {};
        std::memcpy(&entry, entry_ptr, sizeof(entry));
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData < 24u) {
            continue;
        }
        uint32_t cv_offset = entry.PointerToRawData;
        if (cv_offset == 0 || cv_offset + entry.SizeOfData > image.size()) {
            continue;
        }
        uint8_t* cv_ptr = image.data() + cv_offset;
        uint32_t signature = 0;
        std::memcpy(&signature, cv_ptr, sizeof(signature));
        if (signature != 0x53445352u) {
            continue;
        }
        uint32_t name_offset = 24u;
        if (name_offset >= entry.SizeOfData) {
            continue;
        }
        uint8_t* name_ptr = cv_ptr + name_offset;
        uint32_t name_max = entry.SizeOfData - name_offset;
        uint32_t terminator = name_max;
        for (uint32_t pos = 0; pos < name_max; ++pos) {
            if (name_ptr[pos] == 0) {
                terminator = pos;
                break;
            }
        }
        if (terminator == 0u) {
            continue;
        }
        uint32_t base_start = 0;
        for (uint32_t pos = 0; pos < terminator; ++pos) {
            uint8_t ch = name_ptr[pos];
            if (ch == '\\' || ch == '/') {
                base_start = pos + 1u;
            }
        }
        if (base_start == 0u) {
            continue;
        }
        uint32_t base_len = terminator - base_start;
        std::memmove(name_ptr, name_ptr + base_start, base_len);
        std::memset(name_ptr + base_len, 0, name_max - base_len);
    }
}

bool process_image(const std::string& path) {
    std::vector<uint8_t> image;
    if (!read_file(path.c_str(), image)) {
        std::fprintf(stderr, "aida_pdb_scrubber: cannot read %s\n", path.c_str());
        return false;
    }
    size_t dos_stub_size = 0;
    PIMAGE_DOS_HEADER dos = nullptr;
    PIMAGE_NT_HEADERS64 nt = nullptr;
    if (!locate_nt_headers(image, dos_stub_size, dos, nt)) {
        std::fprintf(stderr, "aida_pdb_scrubber: invalid PE %s\n", path.c_str());
        return false;
    }
    wipe_rich_header(image.data(), dos_stub_size);
    wipe_pdb_paths(image, nt);
    if (!write_file(path.c_str(), image)) {
        std::fprintf(stderr, "aida_pdb_scrubber: cannot write %s\n", path.c_str());
        return false;
    }
    return true;
}

}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: aida_pdb_scrubber <pe_path> [<pe_path> ...]\n");
        return 1;
    }
    int rc = 0;
    for (int idx = 1; idx < argc; ++idx) {
        if (!process_image(argv[idx])) {
            rc = 2;
        }
    }
    return rc;
}
