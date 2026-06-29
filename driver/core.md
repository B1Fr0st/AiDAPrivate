# Technical Analysis of WindMapper: A Kernel Driver Mapping System

## 1. Executive Summary

**WindMapper** is a sophisticated user‑mode tool designed to load arbitrary, unsigned kernel drivers into the Windows kernel without triggering driver signature enforcement. It operates by:

1. Embedding a **vulnerable driver** (likely a variant of WinIO) inside its executable, stored XOR‑encrypted.
2. Deploying this driver via the native `NtLoadDriver` API (by creating a service entry under the registry).
3. Opening the driver’s device and using its physical memory read/write primitives to **patch the Code Integrity (CI) callback** in the kernel, temporarily disabling signature verification.
4. Loading the **target driver** (and optional helper drivers) through the same service mechanism while the CI bypass is active.
5. Restoring the CI callback and patching the target driver’s flags in the kernel’s loaded module list to mark it as *trusted*.
6. Performing post‑load stealth operations (file hiding, registry cleanup, etc.).

The mapper is designed for Windows 10 and 11 (including recent builds) with adaptations for newer kernel mitigations. It uses a combination of pattern scanning, physical memory translation, and kernel structure manipulation to achieve its goals.

---

## 2. Overall Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WindMapper (EXE)                         │
├─────────────────────────────────────────────────────────────┤
│ ┌───────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│ │ EmbeddedDriver │  │ KernelUtils  │  │  VulnDriver      │ │
│ │ (XOR decrypted)│  │ (pattern     │  │  (device I/O)    │ │
│ └───────┬───────┘  │  scanning,   │  └────────┬─────────┘ │
│         │          │  module list)│           │           │
│         ▼          └──────┬───────┘           │           │
│ ┌───────────────┐        │                   │           │
│ │ DriverLoader  │◄───────┴───────────────────┘           │
│ │ (NtLoadDriver)│                                       │
│ └───────┬───────┘                                       │
└─────────┼─────────────────────────────────────────────────┘
          │ writes temp .sys
          ▼
┌─────────────────────────┐
│ Vulnerable driver (WinIO)│ ── physical memory R/W ──► Kernel
└─────────────────────────┘
          │
          │ uses physical R/W to:
          │  • Patch CI callback (SeCiCallbacks → ZwFlushInstructionCache)
          │  • Load target driver (via service)
          │  • Patch driver flags (0x20) in KLDR_DATA_TABLE_ENTRY
          │  • Restore CI callback
          ▼
┌─────────────────────────┐
│ Target driver (unsigned) │ now considered trusted by kernel
└─────────────────────────┘
```

**Components:**

- **EmbeddedDriver**: Contains the vulnerable driver bytes (XOR‑encrypted) and decryption logic.
- **VulnDriver**: Interacts with the vulnerable driver’s device to map physical memory and perform arbitrary reads/writes.
- **KernelUtils**: Implements pattern scanning to locate kernel structures (SeCiCallbacks, PsLoadedModuleList) and functions to manipulate them.
- **DriverLoader**: Creates registry service keys and invokes `NtLoadDriver`/`NtUnloadDriver`.
- **MapperCore**: Orchestrates the entire workflow, including file staging, self‑signing, CI patch, driver loading, and cleanup.
- **SignedMemory**: Provides functions to self‑sign drivers or transplant certificates to avoid detection.

---

## 3. Detailed File‑by‑File Analysis

### 3.1 `DriverLoader.cpp`

**Purpose:** Manage Windows driver services via the native NT API.

**Key Functions:**

- `CreateDriverService(PWSTR servicePath, PCWSTR filePath)`
  - Constructs a registry path under `\Registry\Machine\System\CurrentControlSet\Services\` using the filename (without extension).
  - Calls `RtlCreateRegistryKey` to create the service key.
  - Writes values:
    - `ImagePath` → `\??\<full file path>`
    - `AidaKernelLogPath` → custom logging path.
    - `Type` = 1 (kernel driver).
    - `Start` = 3 (demand start).
    - `ErrorControl` = 1.
  - Flushes the key with `NtFlushKey`.

- `CreateMinifilterService` – similar but for a file system minifilter (ShadowFS), setting `Type` = 2 (`FILE_SYSTEM_DRIVER`), adding `Group` = `FSFilter Activity Monitor`, and creating an `Instances` subkey with altitude `385701`.

- `LoadDriver(PCWSTR servicePath, PCWSTR imagePath)`
  - Converts the service path to a `UNICODE_STRING` and calls `NtLoadDriver`.
  - If `STATUS_OBJECT_NAME_NOT_FOUND` (0xC0000034), it retries after a short sleep.
  - Logs extensively.

- `UnloadDriver` – calls `NtUnloadDriver`.

**Observations:**

- No use of the SCM (Service Control Manager) – entirely native API (`NtLoadDriver`) for stealth and direct control.
- Uses `RtlWriteRegistryValue` and `RtlCreateRegistryKey` from ntdll.
- Includes detailed logging for debugging and telemetry.

### 3.2 `EmbeddedDriver.cpp` / `EmbeddedDriver.h`

**Purpose:** Decrypt and manage the embedded vulnerable driver.

**Global variables:**

```cpp
unsigned char* g_P2CDriverData = nullptr;
size_t g_P2CDriverSize = 0;
```

**Encryption/Decryption:**

- The driver bytes are stored in `P2CDriverBytes.h` as an array `rawData[]`.
- The XOR key is a fixed 16‑byte array:
  ```cpp
  static constexpr unsigned char XOR_KEY[] = {
      0x7A, 0xC3, 0x91, 0xE5, 0x3D, 0xF8, 0x46, 0xAB,
      0x1F, 0x82, 0xD7, 0x54, 0x69, 0xBE, 0x03, 0xC6
  };
  ```
- `InitializeDriverData()`:
  - Allocates RW memory of size `rawDataSize`.
  - XOR‑decrypts each byte: `decrypted[i] = rawData[i] ^ XOR_KEY[i % 16]`.
  - Verifies the MZ header (`'M'`, `'Z'`).
  - Stores the pointer and size in globals.
- `ReleaseDriverData()` – zeroes and frees the memory.

**Note:** The encryption script (`encrypt_driver.py`) is used to generate the header from a plaintext driver, ensuring that the raw data does not start with `MZ` (to avoid double encryption).

### 3.3 `KernelUtils.cpp`

**Purpose:** Provide kernel interaction functions without direct device I/O (i.e., using the vulnerable driver for physical memory access).

**Key Functions:**

- **`PVOID GetKernelModuleBase(const char* moduleName)`**
  - Uses `NtQuerySystemInformation` (class 11 – `SystemModuleInformation`) to enumerate loaded kernel modules.
  - Searches for the given module name (e.g., `"ntoskrnl.exe"`).
  - Falls back to `EnumDeviceDrivers` (Psapi) if the system query fails.

- **`PVOID GetKernelProcAddress(PVOID moduleBase, const char* procName)`**
  - Loads `ntoskrnl.exe` locally, resolves the offset of the procedure, then adds that offset to the kernel base.
  - Used to locate functions like `PsInitialSystemProcess` for CR3 discovery.

- **`BOOL GetCiValidateImageHeaderEntry(PVOID* outCiEntry, PVOID* outZwFlush)`**
  - Performs **pattern scanning** on the local copy of `ntoskrnl.exe` to locate the `SeCiCallbacks` pointer.
  - Patterns vary for Windows 10 and Windows 11 builds. Examples:
    - Win10: `FF 48 8B D3 4C 8D 05` (call; mov rdx,rbx; lea r8)
    - Win11: `41 B8 05 00 00 00 4C 8D 0D` (mov r8d,5; lea r9)
  - Once the `SeCiCallbacks` address is found in the local image, it computes the kernel address using the offset from the kernel base.
  - The CI callback entry is at `SeCiCallbacks + 0x20`.
  - Also returns `ZwFlushInstructionCache` address (used as the harmless replacement).

- **`BOOL PatchDriverSigningFlagsByBase(HANDLE device, PVOID driverBase, ULONG driverImageSize, PCSTR label, BOOL updateDriverLoadAddress)`**
  - Finds the `KLDR_DATA_TABLE_ENTRY` for the specified driver base by walking `PsLoadedModuleList`.
  - For Windows 11 builds (≥ 22000), it simply sets a global flag (`g_KernelSigningVerified = true`) without actual patching – possibly due to kernel changes (the flag may be moved or not required).
  - For earlier versions, it walks the doubly‑linked list, reads each entry, compares `DllBase` (offset 0x30) to `driverBase`, and upon match, sets bit 0x20 in the `Flags` field (offset 0x68) via `WriteKernelMemory`.
  - Verifies the patch by reading back.
  - Caches the list head and resume entry for performance.

- **`PVOID GetDriverBaseByName(PCWSTR driverFileName, PULONG outImageSize)`**
  - Uses `NtQuerySystemInformation` to find a loaded driver by its file name.
  - Returns its base address and image size.
  - Falls back to `ResolveDriverBaseWithPsapi` (using `EnumDeviceDrivers`).

### 3.4 `Mapper.h`

**Purpose:** Central header containing type definitions, constants, and external declarations.

**Key Definitions:**

- IOCTL codes for the vulnerable driver (WinIO):
  ```cpp
  #define IOCTL_WINIO_MAPPHYSTOLIN   CTL_CODE(WINIO_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
  #define IOCTL_WINIO_UNMAPPHYSADDR  CTL_CODE(WINIO_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
  #define IOCTL_WINIO_READPORT       CTL_CODE(WINIO_DEVICE_TYPE, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
  #define IOCTL_WINIO_WRITEPORT      CTL_CODE(WINIO_DEVICE_TYPE, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
  ```

- Structures for physical memory mapping:
  ```cpp
  typedef struct _WINIO_PHYS_MEM {
      LARGE_INTEGER Size;
      LARGE_INTEGER PhysicalAddress;
      HANDLE SectionHandle;
      PVOID MappedAddress;
      PVOID SectionObject;
  } WINIO_PHYS_MEM;
  ```

- Function pointer types for native APIs (`pNtLoadDriver`, `pNtQuerySystemInformation`, etc.).
- Global variables: `g_P2CDriverData`, `g_OriginalCiCallback`, `g_DriverLoadAddress`, etc.
- `AntiDetect` namespace with `TimingJitter()`, `IsBeingDebugged()`, and `MemoryBarrier()`.

### 3.5 `MapperCore.cpp`

**Purpose:** Orchestrates the entire mapping process; contains `main()` and the core logic.

**Main Flow:**

1. **Logging Initialization:** Opens a log file if environment variable `AIDA_MAPPER_LOG` is set.
2. **Debugger Check:** In non‑debug builds, calls `AntiDetect::IsBeingDebugged()` and exits if detected.
3. **Privilege Adjustment:** Uses `AdjustTokenPrivileges` to enable `SeLoadDriverPrivilege`.
4. **Initialize Nt Functions:** `Utils::InitializeNtFunctions()` resolves all needed ntdll functions.
5. **Embedded Driver Extraction:** `InitializeDriverData()` decrypts the embedded vulnerable driver.
6. **Temp File Creation:**
   - Writes the decrypted vulnerable driver to a temporary `.sys` file (`loaderFilePath`).
   - Copies the target driver (provided as command‑line argument) to another temp file.
   - If Sentinel or ShadowFS drivers are specified (additional arguments), they are copied as well.
7. **Self‑Signing:**
   - `SignedMemory::SelfSignDriver` attempts to sign each driver using a self‑signed certificate (via `mssign32.dll`).
   - If that fails, `SignedMemory::TransplantCertificateToDriver` extracts a certificate from a valid signed system driver and transplants it.
8. **Driver Deployment & Exploit:**
   - Calls `MapperCore::WindLoadDriver(loaderPath, driverPath, sentinelPath, shadowFsPath)`.
   - This function:
     - Creates service registry keys for all drivers.
     - Calls `TriggerExploit` which:
       1. Opens the vulnerable driver device.
       2. Resolves and patches the CI callback to `ZwFlushInstructionCache`.
       3. Loads the target (and optional) drivers via `NtLoadDriver`.
       4. For Windows 11 build ≥ 26100, performs a **Sentinel file preseed** – writes a handoff block into the Sentinel driver’s `.sntl` section before loading (because post‑load module queries crash).
       5. Restores the original CI callback.
       6. Patches the driver signing flags for all loaded drivers.
       7. Unloads the vulnerable driver and deletes its temp file.
9. **Cleanup:** Deletes temp files, registry keys, etc.

**Key Helper Functions:**

- `WriteSentinelGlobals`: Writes a handoff structure to the `.sntl` section of the Sentinel driver, containing the base address and size of the target driver. This is used by the Sentinel driver to locate the WhosWho driver.
- `LogKernelModuleSnapshot`: Dumps loaded modules for debugging.

### 3.6 `VulnDriver.cpp`

**Purpose:** Implements the low‑level communication with the vulnerable driver’s device.

**Device Opening:**

- `OpenDevice(PHANDLE deviceHandle)` tries multiple methods:
  1. `SetupDiGetClassDevs` with the device interface GUIDs (`GUID_DEVINTERFACE_GIO`, `GUID_DEVINTERFACE_GIO_ALT`).
  2. `CM_Get_Device_Interface_List` (CfgMgr).
  3. Direct `NtCreateFile` on `\??\GLCKIo`, `\Device\GLCKIo`, `\DosDevices\GLCKIo`.

**Physical Memory Operations:**

- `MapPhysicalMemory(HANDLE device, ULONGLONG physAddr, ULONG size, PVOID* mappedAddr)`
  - Sends `IOCTL_WINIO_MAPPHYSTOLIN` with a `WINIO_PHYS_MEM` structure.
  - The driver returns a user‑mode mapped address for the physical page.
  - Caches the result for later unmapping.

- `UnmapPhysicalMemory(HANDLE device, PVOID mappedAddr)` – sends `IOCTL_WINIO_UNMAPPHYSADDR`.

- `ReadPhysicalMemory` / `WritePhysicalMemory` – map the required page, perform `memcpy`, then unmap.

**Virtual‑to‑Physical Translation:**

- `ULONGLONG VirtualToPhysical(HANDLE device, PVOID virtualAddress)`
  - Uses the current kernel CR3 (cached).
  - Walks the page tables (PML4, PDPT, PD, PT) by reading physical memory through the vulnerable driver.
  - The CR3 is obtained by:
    1. Locating `PsInitialSystemProcess` in the kernel.
    2. Scanning physical memory (by reading physical RAM ranges) to find a page directory that maps the ntoskrnl base.
  - This is a **self‑contained page table walker** that does not rely on `MmGetVirtualForPhysical`.

**Atomic Pointer Exchange:**

- `ExchangePhysicalPointer(HANDLE device, ULONGLONG physAddr, PVOID newValue, PVOID* oldValue)`
  - Maps the physical page containing `physAddr`.
  - Uses `InterlockedExchange64` to atomically replace the pointer with `newValue`, returning the old value.
  - Used to patch the CI callback atomically (and restore it later).

### 3.7 `P2CDriverBytes.h`

**Purpose:** Contains the XOR‑encrypted vulnerable driver.

- Generated by `encrypt_driver.py`.
- Defines:
  ```cpp
  unsigned char rawData[<size>] = { 0x... };
  static const unsigned long rawDataSize = sizeof(rawData);
  ```
- The data is the vulnerable driver (likely WinIO.sys or a derivative) XOR‑encrypted with the 16‑byte key.
- Size is not explicitly shown in the provided snippet, but it’s the full driver image.

### 3.8 `P2CVulnDriver/CI.asm` & `nroskrnl.asm`

These files are **not provided** in the given text. Based on naming:

- `CI.asm` likely contains assembly code to locate or patch the Code Integrity callback, possibly using a different method (e.g., direct kernel memory search).
- `nroskrnl.asm` might contain routines to obtain the ntoskrnl base address or read MSRs.

Since we lack the content, we cannot analyze them further.

### 3.9 `imports/Defs.h`

**Purpose:** Defines kernel structures, function pointers, and string obfuscation helpers.

- **`GetProcAddress` implementation** – manually parses the PE exports of a kernel module (works in user‑mode for loaded kernel images).
- **`func_obfuscate` namespace** – provides compile‑time XOR encoding/decoding of function pointers using a key derived from `__TIME__` and `__DATE__`. This is used to obfuscate the address of imported kernel functions (e.g., `IoCreateDriver`).
- **`SetupFunctions()`** – resolves all needed kernel function pointers by calling `GetProcAddress` on `ntoskrnl.exe` (loaded in user‑space). Uses `skCrypt` macro for string obfuscation (likely defined elsewhere as a compile‑time string encryptor).
- Defines function pointers for:
  - `_RtlInitUnicodeString`, `_IoCreateDriver`, `_IoCreateDevice`, `_IoCreateSymbolicLink`, `_IoGetCurrentIrpStackLocation`, `_IofCompleteRequest`, `_MmCopyVirtualMemory`, `_MmCopyMemory`, `_MmMapIoSpaceEx`, `_MmUnmapIoSpace`, `_PsLookupProcessByProcessId`, `_PsGetProcessSectionBaseAddress`, `_ObfDereferenceObject`, `_ObReferenceObjectByName`, `_MmGetPhysicalMemoryRanges`, `_MmGetVirtualForPhysical`, `_RtlGetVersion`, `_KfRaiseIrql`, `_KeLowerIrql`, `_MmIsAddressValid`, `_ZwOpenProcess`, `_ZwClose`.

### 3.10 `imports/Strings.h`

**Purpose:** Case‑insensitive string comparison functions.

- `locase_a` / `locase_w` – convert to lowercase.
- `_strcmpi_a` / `_strcmpi_w` – compare strings case‑insensitively.
- Used in the manual `GetProcAddress` to match export names.

### 3.11 `imports/ntoskernel_base.asm`

Not provided. It likely contains assembly code to retrieve the kernel base address, possibly via reading the `IA32_LSTAR` MSR or using the `KiSystemCall64` pattern. However, the provided `get_nt_base()` in Defs.h uses `GetModuleHandleA("ntoskrnl.exe")` in user mode, which loads the kernel image into the user process and returns its base – this is a common trick for offset calculation.

### 3.12 `encrypt_driver.py`

**Purpose:** Encrypt the plaintext driver and generate `P2CDriverBytes.h`.

**Algorithm:**
- Reads the header file (which contains hex bytes of the plaintext driver).
- Parses all `0xXX` tokens to extract raw bytes.
- Verifies that the first two bytes are `MZ` (to ensure it’s not already encrypted).
- XOR‑encrypts each byte with a repeating 16‑byte key (same key as in `EmbeddedDriver.cpp`).
- Writes a new header with the encrypted data, formatted as a C array.

**Flow:**
1. Open `P2CDriverBytes.h`.
2. Extract hex values.
3. If not already encrypted (starts with MZ), XOR‑encrypt.
4. Write back with `#pragma once`, the array definition, and `rawDataSize`.

### 3.13 `WindMapper.rc` / `WindMapper.manifest`

These files are not shown but are part of the project. The manifest likely requests administrator execution level (as seen in the vcxproj: `<UACExecutionLevel>RequireAdministrator</UACExecutionLevel>`). The resource file probably contains the application icon and version info.

### 3.14 `WindMapper.vcxproj`

**Purpose:** Visual Studio project configuration.

**Notable settings:**

- **Platform Toolset:** v143 (Visual Studio 2022).
- **Runtime Library:** `MultiThreaded` (Release) and `MultiThreadedDebug` (Debug) – static linking.
- **C++ Language Standard:** C++17.
- **Additional Dependencies:** `ntdll.lib`, `setupapi.lib`, `Shlwapi.lib`, `crypt32.lib`.
- **Manifest:** Included (`WindMapper.manifest`).
- **UAC Execution Level:** `RequireAdministrator`.
- **WholeProgramOptimization** enabled for Release.

No special warning disables are explicitly shown.

---

## 4. Functionality Walkthrough

### 4.1 Initial Setup

1. **`main(int argc, char* argv[])`**:
   - Opens log file.
   - Performs anti‑debugging checks.
   - Enables `SeLoadDriverPrivilege`.
   - Initializes required Nt functions.
   - Decrypts the embedded vulnerable driver via `InitializeDriverData()`.

2. **Prepare the vulnerable driver**:
   - Writes decrypted bytes to a temp file (`loaderFilePath`).
   - Copies target driver (from command‑line arg) to another temp file.
   - Copies Sentinel and ShadowFS drivers if provided.

3. **Self‑sign all drivers**:
   - Attempts `SelfSignDriver` (creates a self‑signed certificate and signs the PE).
   - Falls back to `TransplantCertificateToDriver` (extracts a valid certificate from a signed system file and injects it).

### 4.2 WindLoadDriver

- **Creates services** for all drivers using `DriverLoader::CreateDriverService` (and `CreateMinifilterService` for ShadowFS).

- **Calls `TriggerExploit`**.

### 4.3 TriggerExploit

1. **Open Vulnerable Device**:
   - `VulnDriver::OpenDevice()` – tries several methods.

2. **Locate and Patch CI Callback**:
   - `KernelUtils::GetCiValidateImageHeaderEntry()` finds `SeCiCallbacks` in the kernel.
   - Reads the original CI callback pointer.
   - Uses `VulnDriver::ExchangePhysicalPointer` to atomically replace it with `ZwFlushInstructionCache` (a harmless function).
   - Verifies the patch.

3. **Load Target Driver**:
   - `DriverLoader::LoadDriver(g_DriverServicePath, targetDriverFullPath)`.
   - Because CI is now bypassed, the unsigned driver loads successfully.

4. **Load Sentinel Driver (if specified)**:
   - On Windows 11 build 26100+, the mapper **pre‑seeds** a handoff block into Sentinel’s `.sntl` section (via `PreseedSentinelFileHandoff`) before loading to avoid a crash when querying loaded modules post‑load.
   - Then loads the Sentinel driver.

5. **Load ShadowFS Minifilter (if specified)**.

6. **Restore CI Callback**:
   - Atomically writes back the original CI callback pointer.

7. **Patch Driver Signing Flags**:
   - For each loaded driver (target, sentinel, shadowfs), calls `KernelUtils::PatchDriverSigningFlagsByBase` to set bit 0x20 in the `Flags` field of the `KLDR_DATA_TABLE_ENTRY`, marking the driver as trusted.
   - On Win11, this step is skipped (the flag may not exist or is handled differently).

8. **Write Sentinel Globals**:
   - If Sentinel is loaded, write the WhosWho driver base/size into Sentinel’s `.sntl` section so Sentinel can locate it (if not already done via file preseed).

9. **Cleanup**:
   - Unloads the vulnerable driver (`DriverLoader::UnloadDriver`).
   - Deletes temp files.
   - Optionally hides the driver image paths via `Utils::HideLoadedImagePath`.

### 4.4 Finalization

- Registry service keys are cleaned up (deleted).
- The program exits with `STATUS_SUCCESS` if the target driver was loaded.

---

## 5. Security Implications

### 5.1 Vulnerabilities Exploited

- **Vulnerable Driver**: The embedded driver (WinIO or similar) exposes physical memory mapping via IOCTLs. This allows arbitrary kernel read/write from user mode.
- **CI Bypass**: By patching `SeCiCallbacks`, the mapper disables driver signature enforcement, allowing unsigned drivers to load.
- **Lack of Kernel Mitigations**: The code relies on the kernel not enforcing `Kernel‑Mode Code Signing` (KMCS) or having strict pointer integrity.

### 5.2 Stealth Techniques

- **XOR encryption** of the vulnerable driver to evade static detection.
- **Service registry manipulation** – uses native APIs to avoid SCM logging.
- **File hiding** – uses `FILE_ATTRIBUTE_HIDDEN`, `FILE_ATTRIBUTE_SYSTEM`, and moves files to system directories.
- **Self‑signing** – makes the drivers appear signed, though not by a trusted CA.
- **Deferred cleanup** – moves files to be deleted on reboot.

### 5.3 Detectability

- **Logging**: The mapper logs heavily (if log file is enabled). This can be detected by monitoring `C:\Users\Public\Desktop\aida_kernel.log` or via DebugView.
- **Registry keys**: Leftover service keys under `HKLM\System\CurrentControlSet\Services\<random>`.
- **IOCTL patterns**: The vulnerable driver’s IOCTL codes are well‑known; security software can hook device I/O.
- **Memory signatures**: The patch to CI callback leaves a fingerprint (pointer to `ZwFlushInstructionCache`).
- **Kernel module list**: The loaded driver will appear in `PsLoadedModuleList` with a modified flag (0x20 set). However, many legitimate drivers have this flag.

### 5.4 Limitations

- **Windows 11 Build ≥ 26100**: The mapper adapts by skipping module queries after loading, but the reliance on the vulnerable driver still works.
- **PatchGuard**: The code does not disable PatchGuard; however, it modifies memory that is not typically protected (data sections). The CI callback patch might be detected by PatchGuard if the kernel checks integrity.
- **Digital Signature Enforcement**: The self‑signing may not work if the system enforces strict certificate chain validation (e.g., WHQL only). The transplant method uses a valid certificate, which may be revoked eventually.

---

## 6. Code Snippets and Key Offsets

### 6.1 CI Callback Patch (Exchange)

```cpp
NTSTATUS ExchangePhysicalPointer(HANDLE device, ULONGLONG physAddr, PVOID newValue, PVOID* oldValue) {
    PVOID mapped = nullptr;
    NTSTATUS status = MapPhysicalMemory(device, physAddr & ~0xFFFULL, 0x1000, &mapped);
    if (!NT_SUCCESS(status)) return status;
    ULONG offset = static_cast<ULONG>(physAddr & 0xFFF);
    volatile LONG64* slot = (volatile LONG64*)((PUCHAR)mapped + offset);
    LONG64 newBits = (LONG64)newValue;
    LONG64 oldBits = InterlockedExchange64(slot, newBits);
    *oldValue = (PVOID)(ULONG_PTR)oldBits;
    UnmapPhysicalMemory(device, mapped);
    return STATUS_SUCCESS;
}
```

### 6.2 Page Table Walk (Virtual‑to‑Physical)

```cpp
ULONGLONG VirtualToPhysicalWithCR3(HANDLE device, ULONGLONG cr3, ULONGLONG va) {
    ULONGLONG pml4Index = (va >> 39) & 0x1FF;
    ULONGLONG pdptIndex = (va >> 30) & 0x1FF;
    ULONGLONG pdIndex = (va >> 21) & 0x1FF;
    ULONGLONG ptIndex = (va >> 12) & 0x1FF;
    ULONGLONG pageOffset = va & 0xFFF;
    // Read PML4E, PDPTE, PDE, PTE via physical memory ...
}
```

### 6.3 Pattern Scanning for SeCiCallbacks (Win10)

```cpp
BYTE win10Pattern[] = { 0xFF, 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }; // length 7, lea offset 4
// Search in local ntoskrnl image, compute offset to SeCiCallbacks.
```

### 6.4 Registry Service Creation

```cpp
NTSTATUS CreateDriverService(PWSTR servicePath, PCWSTR filePath) {
    wcscpy(servicePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    // append filename (without extension)
    RtlCreateRegistryKey(0, servicePath);
    RtlWriteRegistryValue(0, servicePath, L"ImagePath", REG_SZ, ntPath, ...);
    RtlWriteRegistryValue(0, servicePath, L"Type", REG_DWORD, &type, 4);
    RtlWriteRegistryValue(0, servicePath, L"Start", REG_DWORD, &start, 4);
    // ...
}
```

### 6.5 Sentinel Handoff Block Structure

Defined in `driver/sentinel_handoff.h` (not shown). It contains magic, version, target base, target size, checksum. This is written into the Sentinel driver’s `.sntl` section to pass information.

---

## 7. Conclusion

WindMapper is a comprehensive tool for loading unsigned kernel drivers by leveraging a known vulnerable driver (WinIO) and patching the Code Integrity callback. It demonstrates advanced kernel exploitation techniques, including physical memory access, page table walking, pattern scanning, and atomic pointer exchange. The code is well‑structured with extensive logging and supports Windows 10 and 11. While it is used in cheat development (P2C), it also serves as a case study for kernel bypass techniques. Mitigations such as PatchGuard, HVCI, and strict signing policies can detect or prevent many of its actions, but the mapper employs several evasive measures to remain effective.

---

*This report was generated by analyzing the provided source files of WindMapper. All findings are based on the code present.*