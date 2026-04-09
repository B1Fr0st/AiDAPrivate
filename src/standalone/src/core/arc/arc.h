#pragma once

// ============================================================================
// AiDA Runtime Core (ARC) — Public Header
// ============================================================================
// This header defines the types and vtable structures that AiDA uses to
// communicate with the ARC module. ARC is loaded reflectively into memory
// after license validation and provides:
//
//   1. Session initialization + HWID verification
//   2. Driver communication bridge vtable
//   3. Per-tool execution validation
//   4. Heartbeat integrity proofs
//
// Without ARC loaded, all driver_bridge functions return failure and all
// tool execution gates deny access.
// ============================================================================

#include <cstdint>
#include <cstddef>

#ifdef ARC_EXPORTS
#define ARC_API __declspec(dllexport)
#else
#define ARC_API
#endif

// ─── ARC Interface Version ──────────────────────────────────────────────────
// Checked at arc_init() — if the version embedded in the DLL doesn't match
// what AiDA expects, initialization fails. This prevents stale ARC binaries
// from being loaded after client updates.

static constexpr uint32_t ARC_INTERFACE_VERSION = 0x00010001u; // 1.1

// ─── Communication Bridge VTable ────────────────────────────────────────────
// AiDA calls the kernel driver ONLY through these function pointers.
// ARC wraps each call with session validation + anti-debug checks.

struct arc_comm_vtable_t
{
    // Connect to the kernel driver device.
    // Returns true if driver handle acquired and heartbeat succeeded.
    bool (*connect)(uint64_t device_path_seed);

    // Disconnect and release driver handle.
    void (*disconnect)();

    // Check if driver is currently connected.
    bool (*is_connected)();

    // Set target process ID for subsequent operations.
    void (*set_process_id)(uint32_t pid);

    // Resolve the target process DTB (Directory Table Base).
    // Returns the DTB value, or 0 on failure.
    uint64_t (*solve_dtb)();

    // Get the currently resolved DTB.
    uint64_t (*get_dtb)();

    // Find the image base of the target process.
    uint64_t (*find_image)();

    // Set the base address for the target process image.
    void (*set_base_address)(uint64_t base);

    // Find a process by name (kernel-level enumeration).
    // Returns PID, or 0 if not found.
    uint32_t (*find_process)(const char* name);

    // Clear process context (pid, dtb, base).
    void (*clear_process_context)();

    // Read raw memory from the target process.
    // Returns number of bytes actually read.
    size_t (*read_raw)(uint64_t address, void* buffer, size_t size);

    // Write raw memory to the target process.
    // Returns number of bytes actually written.
    size_t (*write_raw)(uint64_t address, const void* buffer, size_t size);

    // Enumerate memory regions of the target process.
    // Calls the callback for each region. Returns total count.
    struct memory_region_info_t {
        uint64_t base;
        uint64_t size;
        uint32_t state;
        uint32_t protect;
        uint32_t type;
    };
    uint32_t (*enumerate_memory_regions)(
        void (*callback)(const memory_region_info_t* region, void* ctx),
        void* ctx);

    // Query a single memory region at the given address.
    bool (*query_memory)(uint64_t address, memory_region_info_t* out);

    // Enumerate threads of the attached process (kernel-level).
    struct thread_info_t {
        uint32_t tid;
        uint32_t state;
        uint64_t rip;
    };
    uint32_t (*enumerate_threads)(
        void (*callback)(const thread_info_t* thread, void* ctx),
        void* ctx);

    // Execute a remote function call via thread hijacking.
    // Returns the return value of the remote function, or 0 on failure.
    uint64_t (*remote_call)(
        uint64_t function_address,
        uint64_t arg1, uint64_t arg2,
        uint64_t arg3, uint64_t arg4);

    // Reserved for future expansion (12 slots).
    void* _reserved[12];
};

// ─── Heartbeat Result ───────────────────────────────────────────────────────

struct arc_heartbeat_result_t
{
    bool     valid;               // true if all integrity checks passed
    uint64_t proof_token;         // Cryptographic proof for server heartbeat
    uint64_t timestamp;           // When the heartbeat was computed
};

// ─── ARC Exported Functions ─────────────────────────────────────────────────
// These are resolved by name after reflective loading.

extern "C"
{
    // Initialize ARC with session credentials.
    // Must be called once after reflective loading, before any other function.
    // Returns true if session is valid and ARC is ready.
    ARC_API bool arc_init(
        const char*  session_token,     // 64-char hex session token from server
        const char*  hwid,              // Client HWID string
        int64_t      timestamp,         // Current unix timestamp
        uint32_t     interface_version  // Must match ARC_INTERFACE_VERSION
    );

    // Get the communication bridge vtable.
    // Returns nullptr if arc_init() hasn't been called or failed.
    ARC_API const arc_comm_vtable_t* arc_get_comm_bridge();

    // Validate a tool execution request.
    // Called before each tool handler runs.
    // Returns a non-zero verification token on success, 0 on denial.
    ARC_API uint64_t arc_validate_tool_exec(
        uint64_t tool_name_hash,    // FNV-1a hash of tool name
        uint64_t gate_token         // Token from standalone_license::inline_gate_check()
    );

    // Compute a heartbeat integrity proof.
    // Called periodically; the proof_token is included in server heartbeats.
    ARC_API arc_heartbeat_result_t arc_heartbeat();

    // Shutdown and securely wipe all internal state.
    ARC_API void arc_cleanup();
}
