#pragma once

// ============================================================================
// Reflective DLL Loader for ARC (AiDA Runtime Core)
// ============================================================================
// Loads a raw PE DLL entirely in memory without touching disk.
// Steps:
//   1. Parse PE headers from buffer
//   2. Allocate memory via VirtualAlloc
//   3. Map sections
//   4. Process relocations
//   5. Resolve imports (kernel32, ntdll, bcrypt, advapi32, ws2_32, iphlpapi only)
//   6. Call DllMain(DLL_PROCESS_ATTACH)
//   7. Resolve exports by name
//
// After loading, the original buffer is securely zeroed.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace arc_loader
{
    // Opaque handle representing a reflectively-loaded module.
    struct loaded_module_t
    {
        void*    base;           // Base address of mapped image
        size_t   image_size;     // Total image size
        bool     initialized;    // DllMain was called successfully
    };

    // Load a raw PE DLL from a memory buffer.
    // On success, the buffer is securely zeroed and the module handle is returned.
    // On failure, returns a module with base == nullptr.
    loaded_module_t load(uint8_t* pe_buffer, size_t pe_size);

    // Resolve an exported function from a loaded module.
    // Returns nullptr if the export is not found.
    void* get_export(const loaded_module_t& mod, const char* export_name);

    // Unload a previously loaded module.
    // Calls DllMain(DLL_PROCESS_DETACH), then VirtualFree.
    void unload(loaded_module_t& mod);

    // Get the last error message from load/get_export/unload.
    const std::string& last_error();
}
