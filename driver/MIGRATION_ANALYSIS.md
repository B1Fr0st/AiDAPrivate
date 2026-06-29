# Migration Analysis: Driver-Based comm.cpp to Driverless UAF Exploit

## What comm.cpp Currently Does

The current comm.cpp is a **driver IOCTL client** that communicates with the
WhosWho kernel driver via `DeviceIoControl`. Here is what it does:

### Communication Layer
- Opens a handle to the WhosWho driver device (`\\.\DeviceName`)
- Sends IOCTLs for each operation (heartbeat, DTB solve, memory R/W, etc.)
- Uses dynamic IOCTL computation (CPUID + OS build + server nonce)
- Encrypted communication with AES-256-GCM and HMAC-SHA256
- Heartbeat-based session management with server token relay

### Memory Operations (all via IOCTL to driver)
- `solve_dtb()` - Resolve CR3/DirectoryTableBase for a target PID
- `read_memory()` / `write_memory()` - Cross-process R/W via DTB-based physical memory
- `alloc_memory()` / `free_memory()` - Allocate/free memory in target process
- `remote_call()` - Execute shellcode in target process (hijack thread, set context)
- `get_base_address()` - Get process image base

### Debugging Operations (all via IOCTL to driver)
- `get_thread_context()` / `set_thread_context()` - Thread context R/W
- `suspend_thread()` / `resume_thread()` - Thread control
- `enumerate_threads()` - List threads in target process
- Hardware breakpoint support via DR0-DR7 in thread context

### Protection Operations (all via IOCTL to driver)
- `dll_protect()` - DLL text section integrity monitoring
- `anti_debug()` - Anti-debugging operations (DR clearing, debugger scanning)
- `anti_dump()` - PE header corruption, handle stripping

### Network Operations (all via IOCTL to driver)
- Packet capture, DNS spoofing, traffic redirect, packet injection
- All via WFP callouts in the kernel driver

## What the Driverless UAF Exploit Replaces

The UAF exploit gives us **arbitrary kernel R/W** without loading a driver.
Once we have kernel R/W, we can do everything the driver does, but from
usermode via a shared memory ring buffer (no IOCTLs needed).

### What Changes

| Component | Driver-Based | Driverless UAF |
|---|---|---|
| Kernel access | Driver IOCTLs | UAF -> kernel RIP -> shared memory |
| Memory R/W | IOCTL to driver (DTB walk) | Shared memory ring buffer (kernel thread) |
| DTB resolution | Driver reads EPROCESS+0x28 | Kernel thread reads EPROCESS+0x28 |
| Thread context | Driver uses PsGetContextThread | Kernel thread uses KeStackAttach + context |
| HW breakpoints | Driver sets DR0-7 via DPC | Kernel thread sets DR0-7 via DPC |
| Remote call | Driver writes shellcode + hijacks | Kernel thread writes shellcode + hijacks |
| Process protection | Driver uses ObRegisterCallbacks | NOT possible driverless (no callbacks) |
| Anti-debug | Driver clears DRs, scans processes | Kernel thread clears DRs, scans processes |
| Anti-dump | Driver corrupts PE headers | Kernel thread corrupts PE headers |
| Network capture | Driver uses WFP callouts | NOT possible driverless (no WFP) |
| Session/heartbeat | Driver validates heartbeat | Server-side validation (unchanged) |

### What Stays the Same
- The entire `voyager::device_t` API surface (callers don't need to change)
- The dynamic key computation (CPUID + OS build + server nonce)
- The encrypted communication protocol (AES-256-GCM + HMAC-SHA256)
- The server token relay and session management
- The process enumeration and finding logic
- The diagnostic logging infrastructure

### What Needs to Change
1. `connect()` - Replace `CreateFile(driver_device)` with UAF trigger + shared memory setup
2. `send_heartbeat()` - Replace `DeviceIoControl` with shared memory write
3. `send_request()` - Replace `DeviceIoControl` with shared memory ring buffer write
4. `solve_dtb()` - Replace IOCTL with shared memory command to kernel thread
5. `read_memory()` / `write_memory()` - Replace IOCTL with shared memory command
6. ALL other IOCTL-based operations - Replace with shared memory commands

### What We LOSE (cannot do driverless)
- `ObRegisterCallbacks` - Cannot register kernel callbacks without a driver
- WFP callouts - Cannot register WFP filters without a driver
- `CmRegisterCallbackEx` - Cannot register registry callbacks without a driver
- `PsSetCreateProcessNotifyRoutineEx` - Cannot without a driver
- Process handle protection - Cannot strip handles without Ob callbacks

### What We KEEP (can do with kernel R/W)
- Cross-process memory R/W (via DTB-based physical access)
- Hardware breakpoints (set DR0-7 in target thread context)
- Thread context R/W (via KeStackAttachProcess + context manipulation)
- Remote function calls (write shellcode, hijack thread)
- Memory allocation in target process
- Anti-debug (clear DRs, scan for debugger processes)
- Anti-dump (corrupt PE headers, strip handles via kernel R/W)
- DTB resolution (read EPROCESS+0x28)

## Migration Effort Estimate

The migration is **moderate** — about 60% of comm.cpp needs to be rewritten:

1. **Transport layer** (connect, send_request, heartbeat): Full rewrite
   - Replace CreateFile + DeviceIoControl with shared memory ring buffer
   - Keep the session/key/encryption logic
   - Keep the heartbeat concept but implement via shared memory

2. **Memory operations** (read, write, solve_dtb, alloc, free): Rewrite dispatch
   - Replace IOCTL dispatch with shared memory command dispatch
   - The kernel-side logic stays the same (DTB walk, physical R/W)
   - But now runs in a kernel polling thread instead of IOCTL handler

3. **Thread/debugging operations**: Rewrite dispatch
   - Same as memory operations — replace IOCTL with shared memory
   - HW breakpoints work: kernel thread can set DR0-7 via DPC

4. **Protection operations**: Remove or stub
   - ObRegisterCallbacks: NOT possible driverless
   - Anti-debug/anti-dump: CAN be done via kernel R/W (poll from kernel thread)

5. **Network operations**: Remove entirely
   - WFP callouts: NOT possible driverless
   - This is a P2C — network capture is not needed

6. **Remote call operations**: Rewrite dispatch
   - Replace IOCTL with shared memory command
   - Kernel thread handles the shellcode injection

## Hardware Breakpoint Support

YES, hardware breakpoints work with the driverless approach:
1. Kernel thread receives "set HW breakpoint" command via shared memory
2. Kernel thread resolves target process EPROCESS
3. Kernel thread enumerates threads via PsGetNextProcessThread
4. Kernel thread sets DR0-7 in each thread's CONTEXT via NtSetContextThread
5. Or: kernel thread directly writes DR registers via KeSetSystemAffinityThread + __writedr

This gives us full debugging capability: conditional breakpoints, memory access
breakpoints (read/write/execute), up to 4 hardware breakpoints per thread.

## DLL Injection

YES, DLL injection is possible but NOT recommended for a P2C:
1. Kernel thread allocates RWX memory in target process
2. Kernel thread writes DLL bytes to allocated memory
3. Kernel thread creates a remote thread to execute the DLL
4. BUT: this is noisy — the DLL appears in the module list
5. Anti-cheats scan for injected DLLs

RECOMMENDED: Stay external. Use kernel R/W to read game memory and
render an overlay. No DLL in the game = no detection.
