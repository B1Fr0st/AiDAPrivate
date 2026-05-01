# QEMU / KVM Hypervisor Detection Report

Source reference: <https://www.unknowncheats.me/wiki/Spoofing_QEMU/KVM_-_Anti-Detection_Checklist>

This document is the **inverse** of the UnknownCheats spoofing checklist: it enumerates every detection vector a QEMU/KVM spoofer is required to defeat. Each vector below is a probe AiDA's `hv_detect` layer should implement (or already implements) to flag a QEMU/KVM guest. Vectors are grouped by surface and tagged with the original `VM::FLAG` identifiers and the spoofer's stated certainty (which doubles as our detection confidence when the artifact is observed unmodified).

---

## 1. CPU Architecture & Timing ("Red Pill")

Defeats: instruction-level analysis, RDTSC/timing discrepancies, CPUID enumeration.

| Flag | Conf. | Detection Probe | Positive Signal |
|---|---|---|---|
| `VM::HYPERVISOR_BIT` | 100% | `CPUID.1:ECX[31]` | Bit set → hypervisor present (`-cpu host,kvm=off` clears it; absence alone is not a clear signal). |
| `VM::CPUID_SIGNATURE`, `VM::KGT_SIGNATURE` | 95% | `CPUID.0x40000000` vendor string | `KVMKVMKVM\0\0\0`, `TCGTCGTCGTCG`, `Microsoft Hv`, `KVM\0KGT\0`. Spoofers blank or replace with `GenuineIntel`/`AuthenticAMD`. |
| `VM::CPUID_LEAVES` | 90% | Probe `CPUID.0x40000000..0x40000010` | KVM exposes paravirt leaves (`KVM_CPUID_FEATURES = 0x40000001`); real silicon does not. |
| `VM::RDTSC`, `VM::TIMER` | 150% | Tight RDTSC loop deltas, `CPUID;RDTSC` vs `RDTSCP` skew, GetTickCount/QPC drift | VM-exits cause >5000-cycle CPUID round-trips; bare-metal is ~100–300. Lack of `+invtsc` causes drift. |
| `VM::TRAP`, `VM::BLOCKSTEP` | 100% | Single-step / `INT 1` / `MSR_KVM_WALL_CLOCK` `RDMSR` while expecting `#GP` | Real HW raises `#GP`; KVM frequently swallows or proxies. Patched KVM that silently ignores faults is itself a fingerprint when paired with timing probes. |
| `VM::THREAD_COUNT`, `VM::THREAD_MISMATCH` | 50% | Compare `CPUID.0xB` topology vs SMBIOS Type 4 vs `GetLogicalProcessorInformationEx` | High-end SKU (i9/Ryzen 9) advertised with `threads=1` per core, or sockets/dies/cores not matching the claimed CPU model. |
| `VM::CACHE` | n/a | `CPUID.0x4` deterministic cache parameters | Missing L3 (`l3-cache=off`), or cache line/size maps that disagree with the CPU brand string. |
| `VM::IBRS`, `VM::SPEC_CTRL` | medium | `CPUID.0x7:EDX[26..29]`, `IA32_SPEC_CTRL` | Modern Intel/AMD silicon advertises IBRS/STIBP/SSBD; minimal QEMU configs omit these. |
| `VM::CPU_HEURISTIC (CLZERO)` | 90% (AMD) | `CLZERO` opcode test | CPU reports Intel/pre-Zen AMD but `CLZERO` executes (or executes as NOP without zeroing). |
| `VM::CPU_HEURISTIC (RDRAND)` | 100% | Statistical test of `RDRAND` output | Constant values, all-zero, all-ones, low entropy, or carry-flag never set → emulated RNG. |
| `VM::HYPERV_LEAF` | high | `CPUID.0x40000003..0x40000006` | KVM masquerading as Hyper-V leaves the wrong feature bits / partition counts. |

---

## 2. Firmware, ACPI & SMBIOS (Static Identity)

Defeats: static table parsing, licensing checks, string analysis.

| Flag | Conf. | Detection Probe | Positive Signal |
|---|---|---|---|
| `VM::ACPI_SIGNATURE`, `VM::FIRMWARE` | 100% | `EnumSystemFirmwareTables('ACPI')` → DSDT/SSDT/FACP/RSDT OEM IDs and OEM Table IDs | `BOCHS`, `BXPC`, `QEMU`, `KVMKVM`, `VBOX`, `VRTUAL`, `INTEL ` followed by `BOCHS`. Real OEMs emit `ALASKA`, `DELL `, `HPQOEM`, `LENOVO`, `_ASUS_`. |
| `VM::ACPI_TABLE_HASH` | high | Hash of DSDT/SSDT body | Compare against known QEMU/SeaBIOS/OVMF DSDT fingerprints. |
| `VM::SMBIOS_VM_BIT` | 50% | SMBIOS Type 0/1/2/3 strings via `GetSystemFirmwareTable('RSMB')` | Manufacturer = `QEMU`, Product = `Standard PC (Q35 + ICH9, 2009)`, BIOS Vendor = `SeaBIOS` / `EFI Development Kit II / OVMF`, Chassis Type = `Other (0x1)` / `Unknown (0x2)`. |
| `VM::SMBIOS_UUID` | high | SMBIOS Type 1 UUID | All-zero UUID, or UUID known to be QEMU's default `00000000-0000-0000-0000-000000000000`, or UUID with `QEMU` ASCII sub-pattern. |
| `VM::QEMU_FW_CFG` | 70% | Probe IO ports `0x510`/`0x511` and the `etc/...` selector list, or DT node `fw-cfg` | Successful read of `fw_cfg` signature `QEMU` (0x51454d55). Driver presence (`qemufwcfg.sys`) on Windows. |
| `VM::NVRAM` (UEFI) | 100% | `GetFirmwareEnvironmentVariableEx` for `BootOrder`, `PK`, `KEK`, `db`, `dbx`, `*Default` | Strings `Tianocore`, `EDK II`, `OVMF`, `Red Hat`, `QEMU` in NVRAM contents; missing `PKDefault`/`KEKDefault`/`dbxDefault`/`MemoryOverwriteRequestControlLock`; `PK` not matching `PKDefault`. |
| `VM::BOOT_LOGO` | 100% | BGRT (`EnumSystemFirmwareTables('ACPI','BGRT')`) image hash | Default `Tianocore` or `SeaBIOS` splash bitmap. |
| `VM::ACPI_OEM_TABLES` | high | Presence/absence of vendor SSDTs (`AMI ` `Cpu0Ist`, `HpetTbl`), MSDM, SLIC | Real OEM systems carry MSDM/SLIC; QEMU defaults do not unless explicitly injected. |
| `VM::HPET`, `VM::WAET` | medium | `WAET` table presence | `WAET` (Windows ACPI Emulated devices Table) is emitted by QEMU/Hyper-V to hint emulation; presence is itself a tell. |

---

## 3. Peripheral, Bus & Device Topology

Defeats: driver interrogation, PCI ID analysis, device-capability checks.

| Flag | Conf. | Detection Probe | Positive Signal |
|---|---|---|---|
| `VM::PCI_DEVICES`, `VM::GPU_CAPABILITIES` | 95% | `SetupDiGetClassDevs(GUID_DEVCLASS_*)`, `CM_Get_Device_ID` | Vendor IDs `0x1234` (Bochs/QEMU VGA), `0x1B36` (Red Hat QXL), `0x1AF4` (virtio), `0x1B21`/`0x1AF4` device IDs from the virtio range. |
| `VM::VIRTIO` | 100% | Service/driver enumeration | `viostor`, `vioscsi`, `vioser`, `viorng`, `NetKVM`, `vioinput`, `viogpudo`, `Balloon`, `pvpanic`. |
| `VM::MAC` | 20% | `GetAdaptersAddresses` OUI | `52:54:00` (QEMU), `08:00:27` (VBox), `00:0C:29`/`00:50:56`/`00:05:69`/`00:1C:14` (VMware), `00:16:E3` (Xen), `00:1C:42` (Parallels). |
| `VM::DISK_SERIAL`, `VM::SCSI` | 100% | `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty`) | Serial prefix `QM000...`, model `QEMU HARDDISK`, `QEMU DVD-ROM`, `QEMU QEMU HARDDISK`, vendor `ATA QEMU`. VirtualBox: 19-char hex serial starting `VB`. |
| `VM::AUDIO` | 25% | `IMMDeviceEnumerator::EnumAudioEndpoints` | No render/capture endpoints, or sole device `QEMU 0.0.0` / `Intel HDA` with no codec. |
| `VM::TEMPERATURE`, `VM::HWMON` | 80% | WMI `MSAcpi_ThermalZoneTemperature`, SuperI/O probe | No thermal zones at all, or constant 27°C, or zone names not matching real ASUS/MSI/Gigabyte conventions. |
| `VM::QEMU_USB` | 20% | `SetupDiEnumDeviceInterfaces(GUID_DEVINTERFACE_USB_HOST_CONTROLLER)` | xHCI VID/PID matching QEMU defaults; empty USB tree (no HID keyboard/mouse). |
| `VM::PCI_TOPOLOGY` | medium | PCI bridge enumeration | Single `pcie.0` root with virtio devices clustered on bus 0; absence of vendor PCH (Intel `Q470`/`Z690`, AMD `X570`/`B550`). |
| `VM::INPUT_DEVICES` | medium | RawInput / `GetRawInputDeviceList` | `QEMU USB Tablet`, `vmmouse`, `vmusbmouse` device names; absent physical HID. |

---

## 4. OS Artifacts & Heuristics

Defeats: file-system analysis, process scanning, registry/service introspection, side-channels.

| Flag | Conf. | Detection Probe | Positive Signal |
|---|---|---|---|
| `VM::DRIVERS`, `VM::DEVICE_HANDLES` | 100% | `EnumDeviceDrivers`, `CreateFileA("\\\\.\\<name>")` | Loaded drivers / device names: `VBoxGuest`, `VBoxMouse`, `VBoxSF`, `VBoxVideo`, `vmusbmouse`, `vmmouse`, `vmmemctl`, `qemu-ga`, `vioser`, `viostor`, `vioscsi`, `NetKVM`, `Balloon`, `pvpanic`. |
| `VM::VIRTUAL_REGISTRY` | 90% | Registry walk | `HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\...\Identifier` containing `QEMU`/`Virtio`; `HKLM\SYSTEM\CurrentControlSet\Services\{viostor,vioscsi,NetKVM,...}`; `HKLM\HARDWARE\DESCRIPTION\System\BIOS` with `SystemManufacturer=QEMU`. |
| `VM::PROCESSES` | 40% | `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` | `qemu-ga.exe`, `spice-vdagent.exe`, `spice-webdavd.exe`, `vioserial-*.exe`. |
| `VM::FILES` | 90% | Path probes | `C:\Program Files\qemu-ga\`, `C:\Program Files\Virtio-Win\`, `C:\Windows\System32\drivers\{viostor,vioscsi,NetKVM,vioser,Balloon,pvpanic}.sys`. |
| `VM::EDID` | 100% | `EnumDisplayDevices` + registry `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\Device Parameters\EDID` | Missing EDID, invalid 8-byte header (`00 FF FF FF FF FF FF 00`), bad checksum (sum of 128 bytes ≠ 0 mod 256), Manufacturer ID `QEM`/`RHT`/`BOC`, or default 1024×768 EDID. |
| `VM::MOUSE_MOVEMENT` | 30% | Long-window mouse delta sampling | No movement over the sampling window strongly correlates with sandbox/headless QEMU. |
| `VM::WINDOW_NAMES`, `VM::CLASS_NAMES` | 30% | `EnumWindows` | `QEMU`, `SeaBIOS`, `vmtoolsd`, `VirtualBox` substrings in titles or class names. |
| `VM::WMI_QUERIES` | high | `Win32_ComputerSystem.Manufacturer/Model`, `Win32_BIOS`, `Win32_VideoController` | `Manufacturer = QEMU`, `Model = Standard PC (Q35 + ICH9, 2009)`, video controller `Microsoft Basic Display Adapter` over `Bochs/QEMU VGA`. |
| `VM::POWER_PROFILE` | low | `CallNtPowerInformation(SystemBatteryState/ProcessorInformation)` | No battery on a "laptop" SKU; flat ProcessorPerformance (no SpeedStep/CPB activity). |
| `VM::PIPES` | medium | `\\.\pipe\` enumeration | `\\.\pipe\qmp-*`, `\\.\pipe\qemu-monitor`, `\\.\pipe\qga.*`. |

---

## Aggregation Rules

- **Hard signals** (`VM::HYPERVISOR_BIT`, `VM::CPUID_SIGNATURE`, `VM::ACPI_SIGNATURE`, `VM::DISK_SERIAL`, `VM::DRIVERS`, `VM::EDID`, `VM::NVRAM`, `VM::VIRTIO`) → 100% certainty when matched, single hit is sufficient to flag QEMU/KVM.
- **Soft signals** (`VM::MAC`, `VM::AUDIO`, `VM::QEMU_USB`, `VM::PROCESSES`, `VM::MOUSE_MOVEMENT`, `VM::POWER_PROFILE`) → require correlation; aggregate ≥3 distinct soft hits before raising.
- **Timing signals** (`VM::RDTSC`, `VM::TIMER`, `VM::TRAP`) must be measured in a tight loop on a pinned thread, with at least 1024 samples and median (not mean) used to defeat outlier scrubbing.
- **Spoof-aware**: a positive `VM::HYPERVISOR_BIT=0` paired with one of the harder static signals (ACPI OEM, SMBIOS UUID, virtio driver) is itself a strong "hidden hypervisor" indicator. Cleared hypervisor bit + virtio storage = high-confidence KVM.

## Probe Priority for `hv_preflight`

1. CPUID hypervisor-bit and `0x40000000` vendor (cheap, runs first).
2. SMBIOS Type 0/1 strings (`GetSystemFirmwareTable('RSMB')`).
3. ACPI OEM IDs across DSDT/SSDT/FACP (`EnumSystemFirmwareTables('ACPI')`).
4. Storage `IOCTL_STORAGE_QUERY_PROPERTY` on the boot disk.
5. PCI vendor sweep via SetupDi for virtio/Bochs/Red Hat IDs.
6. Driver/service registry probe for the virtio-win family.
7. EDID structural + checksum validation.
8. RDTSC tight-loop calibration (last; expensive, susceptible to OS noise).

Each probe records to the same `hv_detect_t` accumulator; `__fastfail(0xBEA7DEADu)` is **never** raised from these probes — they feed the license/anti-tamper layer's risk score, never the driver-heartbeat fast-fail path.
