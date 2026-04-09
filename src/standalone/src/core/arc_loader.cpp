#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "arc_loader.hpp"

#include <windows.h>
#include <cstring>
#include <algorithm>

namespace
{
    std::string g_last_error;

    void set_error(const char* msg)
    {
        g_last_error = msg;
        OutputDebugStringA("ARC Loader: ");
        OutputDebugStringA(msg);
        OutputDebugStringA("\n");
    }

    // ─── PE Header Validation ───────────────────────────────────────────

    bool validate_pe(const uint8_t* buf, size_t size)
    {
        if (size < sizeof(IMAGE_DOS_HEADER)) {
            set_error("Buffer too small for DOS header.");
            return false;
        }

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            set_error("Invalid DOS signature.");
            return false;
        }

        if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > size) {
            set_error("PE header offset out of bounds.");
            return false;
        }

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buf + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            set_error("Invalid PE signature.");
            return false;
        }

        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            set_error("Not an x64 PE image.");
            return false;
        }

        if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
            set_error("PE is not a DLL.");
            return false;
        }

        return true;
    }

    // ─── Map Sections ───────────────────────────────────────────────────

    bool map_sections(uint8_t* image_base, const uint8_t* pe_buf, size_t pe_size,
                      const IMAGE_NT_HEADERS* nt)
    {
        // Copy headers first
        size_t header_size = nt->OptionalHeader.SizeOfHeaders;
        if (header_size > pe_size) {
            set_error("SizeOfHeaders exceeds PE buffer.");
            return false;
        }
        memcpy(image_base, pe_buf, header_size);

        // Copy each section
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].SizeOfRawData == 0)
                continue;

            // Bounds check source
            if (static_cast<size_t>(sec[i].PointerToRawData) + sec[i].SizeOfRawData > pe_size) {
                set_error("Section raw data exceeds PE buffer.");
                return false;
            }

            // Bounds check destination
            if (static_cast<size_t>(sec[i].VirtualAddress) + sec[i].SizeOfRawData >
                nt->OptionalHeader.SizeOfImage) {
                set_error("Section virtual address exceeds image size.");
                return false;
            }

            memcpy(image_base + sec[i].VirtualAddress,
                   pe_buf + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }

        return true;
    }

    // ─── Process Relocations ────────────────────────────────────────────

    bool process_relocations(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        auto delta = reinterpret_cast<uintptr_t>(image_base) -
                     nt->OptionalHeader.ImageBase;
        if (delta == 0)
            return true; // No relocations needed

        const auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) {
            if (delta != 0) {
                set_error("Image needs relocation but has no relocation directory.");
                return false;
            }
            return true;
        }

        auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            image_base + reloc_dir.VirtualAddress);
        auto* reloc_end = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            image_base + reloc_dir.VirtualAddress + reloc_dir.Size);

        while (reloc < reloc_end && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            auto* entries = reinterpret_cast<uint16_t*>(
                reinterpret_cast<uint8_t*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));

            for (uint32_t i = 0; i < count; ++i) {
                uint16_t type   = entries[i] >> 12;
                uint16_t offset = entries[i] & 0xFFF;

                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    break; // Padding, skip
                case IMAGE_REL_BASED_DIR64: {
                    auto* patch = reinterpret_cast<uint64_t*>(
                        image_base + reloc->VirtualAddress + offset);
                    *patch += delta;
                    break;
                }
                case IMAGE_REL_BASED_HIGHLOW: {
                    auto* patch = reinterpret_cast<uint32_t*>(
                        image_base + reloc->VirtualAddress + offset);
                    *patch += static_cast<uint32_t>(delta);
                    break;
                }
                default:
                    set_error("Unsupported relocation type.");
                    return false;
                }
            }

            reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
        }

        return true;
    }

    // ─── Resolve Imports ────────────────────────────────────────────────
    // Only allow imports from trusted system DLLs.

    bool is_allowed_import_dll(const char* name)
    {
        // Case-insensitive comparison for allowed DLLs
        static const char* allowed[] = {
            "kernel32.dll",
            "ntdll.dll",
            "bcrypt.dll",
            "advapi32.dll",
            "ws2_32.dll",
            "iphlpapi.dll",
            "msvcrt.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
            "ucrtbase.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "api-ms-win-crt-heap-l1-1-0.dll",
            "api-ms-win-crt-stdio-l1-1-0.dll",
            "api-ms-win-crt-string-l1-1-0.dll",
            "api-ms-win-crt-math-l1-1-0.dll",
            "api-ms-win-crt-locale-l1-1-0.dll",
            "api-ms-win-crt-time-l1-1-0.dll",
            "api-ms-win-crt-environment-l1-1-0.dll",
            "api-ms-win-crt-convert-l1-1-0.dll",
            "api-ms-win-crt-utility-l1-1-0.dll",
            "api-ms-win-crt-filesystem-l1-1-0.dll",
        };

        for (const auto* a : allowed) {
            if (_stricmp(name, a) == 0)
                return true;
        }
        return false;
    }

    bool resolve_imports(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        const auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
            return true; // No imports

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            image_base + import_dir.VirtualAddress);

        for (; desc->Name != 0; ++desc) {
            const char* dll_name = reinterpret_cast<const char*>(image_base + desc->Name);

            if (!is_allowed_import_dll(dll_name)) {
                set_error("ARC imports from disallowed DLL.");
                return false;
            }

            HMODULE hMod = GetModuleHandleA(dll_name);
            if (!hMod) {
                hMod = LoadLibraryA(dll_name);
                if (!hMod) {
                    set_error("Failed to load import DLL.");
                    return false;
                }
            }

            auto* thunk_ref = reinterpret_cast<IMAGE_THUNK_DATA*>(
                image_base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            auto* func_ref = reinterpret_cast<IMAGE_THUNK_DATA*>(
                image_base + desc->FirstThunk);

            for (; thunk_ref->u1.AddressOfData; ++thunk_ref, ++func_ref) {
                FARPROC proc = nullptr;

                if (IMAGE_SNAP_BY_ORDINAL64(thunk_ref->u1.Ordinal)) {
                    proc = GetProcAddress(hMod,
                        MAKEINTRESOURCEA(IMAGE_ORDINAL64(thunk_ref->u1.Ordinal)));
                } else {
                    auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        image_base + thunk_ref->u1.AddressOfData);
                    proc = GetProcAddress(hMod, import_by_name->Name);
                }

                if (!proc) {
                    set_error("Failed to resolve import function.");
                    return false;
                }

                func_ref->u1.Function = reinterpret_cast<uint64_t>(proc);
            }
        }

        return true;
    }

    // ─── Set Section Permissions ────────────────────────────────────────

    void finalize_sections(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            DWORD protect = PAGE_NOACCESS;
            bool exec  = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)  != 0;
            bool read  = (sec[i].Characteristics & IMAGE_SCN_MEM_READ)     != 0;
            bool write = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)    != 0;

            if (exec && read && write)       protect = PAGE_EXECUTE_READWRITE;
            else if (exec && read)           protect = PAGE_EXECUTE_READ;
            else if (exec && write)          protect = PAGE_EXECUTE_WRITECOPY;
            else if (exec)                   protect = PAGE_EXECUTE;
            else if (read && write)          protect = PAGE_READWRITE;
            else if (read)                   protect = PAGE_READONLY;
            else if (write)                  protect = PAGE_WRITECOPY;

            size_t sec_size = sec[i].Misc.VirtualSize;
            if (sec_size == 0)
                sec_size = sec[i].SizeOfRawData;
            if (sec_size == 0)
                continue;

            DWORD old_protect = 0;
            VirtualProtect(image_base + sec[i].VirtualAddress,
                           sec_size, protect, &old_protect);
        }
    }

    // ─── Process TLS Callbacks ──────────────────────────────────────────

    void process_tls(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        const auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls_dir.VirtualAddress == 0 || tls_dir.Size == 0)
            return;

        auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(
            image_base + tls_dir.VirtualAddress);
        auto** callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        if (!callback)
            return;

        for (; *callback; ++callback) {
            (*callback)(image_base, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    // ─── Export Resolution ──────────────────────────────────────────────

    void* find_export(uint8_t* image_base, const IMAGE_NT_HEADERS* nt, const char* name)
    {
        const auto& export_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_dir.VirtualAddress == 0 || export_dir.Size == 0)
            return nullptr;

        auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            image_base + export_dir.VirtualAddress);

        auto* names     = reinterpret_cast<const uint32_t*>(image_base + exports->AddressOfNames);
        auto* ordinals  = reinterpret_cast<const uint16_t*>(image_base + exports->AddressOfNameOrdinals);
        auto* functions = reinterpret_cast<const uint32_t*>(image_base + exports->AddressOfFunctions);

        for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
            const char* export_name = reinterpret_cast<const char*>(image_base + names[i]);
            if (strcmp(export_name, name) == 0) {
                uint16_t ordinal = ordinals[i];
                uint32_t rva = functions[ordinal];

                // Check for forwarded export (RVA within export directory)
                if (rva >= export_dir.VirtualAddress &&
                    rva < export_dir.VirtualAddress + export_dir.Size) {
                    // Forwarded exports not supported for ARC
                    return nullptr;
                }

                return image_base + rva;
            }
        }

        return nullptr;
    }
}

// ─── Public API ─────────────────────────────────────────────────────────────

namespace arc_loader
{
    loaded_module_t load(uint8_t* pe_buffer, size_t pe_size)
    {
        loaded_module_t result{};
        g_last_error.clear();

        if (!pe_buffer || pe_size == 0) {
            set_error("Null PE buffer.");
            return result;
        }

        if (!validate_pe(pe_buffer, pe_size))
            return result;

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe_buffer);
        auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(pe_buffer + dos->e_lfanew);

        size_t image_size = nt->OptionalHeader.SizeOfImage;
        if (image_size == 0 || image_size > 16 * 1024 * 1024) {
            set_error("Image size is invalid (0 or > 16MB).");
            return result;
        }

        // Allocate memory for the image
        auto* image_base = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, image_size,
                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!image_base) {
            set_error("VirtualAlloc failed for image.");
            return result;
        }

        // Map sections from PE buffer to allocated memory
        if (!map_sections(image_base, pe_buffer, pe_size, nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        // Get the NT headers from the mapped image (not from the original buffer)
        auto* mapped_nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            image_base + dos->e_lfanew);

        // Process relocations
        if (!process_relocations(image_base, mapped_nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        // Resolve imports
        if (!resolve_imports(image_base, mapped_nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        // Set section permissions
        finalize_sections(image_base, mapped_nt);

        // Process TLS callbacks
        process_tls(image_base, mapped_nt);

        // Securely zero the original PE buffer
        SecureZeroMemory(pe_buffer, pe_size);

        // Call DllMain(DLL_PROCESS_ATTACH)
        using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto entry_point = reinterpret_cast<DllMain_t>(
            image_base + mapped_nt->OptionalHeader.AddressOfEntryPoint);

        BOOL dll_result = FALSE;
        __try {
            dll_result = entry_point(
                reinterpret_cast<HINSTANCE>(image_base),
                DLL_PROCESS_ATTACH,
                nullptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            set_error("DllMain threw an exception during DLL_PROCESS_ATTACH.");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        if (!dll_result) {
            set_error("DllMain returned FALSE.");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        result.base        = image_base;
        result.image_size  = image_size;
        result.initialized = true;
        return result;
    }

    void* get_export(const loaded_module_t& mod, const char* export_name)
    {
        g_last_error.clear();

        if (!mod.base || !mod.initialized || !export_name) {
            set_error("Invalid module or export name.");
            return nullptr;
        }

        auto* image_base = static_cast<uint8_t*>(mod.base);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
        auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos->e_lfanew);

        void* addr = find_export(image_base, nt, export_name);
        if (!addr) {
            set_error("Export not found.");
        }
        return addr;
    }

    void unload(loaded_module_t& mod)
    {
        g_last_error.clear();

        if (!mod.base)
            return;

        auto* image_base = static_cast<uint8_t*>(mod.base);

        // Call DllMain(DLL_PROCESS_DETACH) if it was initialized
        if (mod.initialized) {
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
            auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos->e_lfanew);

            using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
            auto entry_point = reinterpret_cast<DllMain_t>(
                image_base + nt->OptionalHeader.AddressOfEntryPoint);

            __try {
                entry_point(
                    reinterpret_cast<HINSTANCE>(image_base),
                    DLL_PROCESS_DETACH,
                    nullptr);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore exceptions during detach
            }
        }

        // Securely zero the image before freeing
        SecureZeroMemory(mod.base, mod.image_size);
        VirtualFree(mod.base, 0, MEM_RELEASE);

        mod.base        = nullptr;
        mod.image_size  = 0;
        mod.initialized = false;
    }

    const std::string& last_error()
    {
        return g_last_error;
    }
}
