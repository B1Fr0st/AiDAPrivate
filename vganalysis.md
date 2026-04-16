Vanguard Kernel Mode Analysis
---

1. Overall Architecture

Code:
+----------------------------------------------------------+
|                    USERMODE (Vanguard Tray)               |
|  Shared Memory (Section Object 0x133) <-> Ring3 Client   |
+-------------------------+--------------------------------+
                          | IOCTL / Shared Memory
+-------------------------v--------------------------------+
|                    vgk.sys KERNEL DRIVER                  |
|                                                          |
|  +--------------+  +---------------+  +----------------+ |
|  | 7 Callbacks  |  | 4 System      |  | XOR'd IAT      | |
|  | (Process,    |  | Threads       |  | 234 Entries     | |
|  |  Thread,     |  | (Monitor,     |  | ~180 APIs       | |
|  |  Image,      |  |  Scan x2,     |  | ntoskrnl +      | |
|  |  Registry,   |  |  LBR)         |  | ci.dll +        | |
|  |  OB x2)      |  |               |  | cng.sys         | |
|  +--------------+  +---------------+  +----------------+ |
|                                                          |
|  +--------------+  +---------------+  +----------------+ |
|  | SSDT Hooks   |  | Detection     |  | LBR Monitor    | |
|  | NtMapView    |  | Flags         |  | AMD MSR 0x1DB  | |
|  | NtProtectVM  |  | (0xA83C8)     |  | 6MB Buffer     | |
|  +--------------+  +---------------+  +----------------+ |
|                                                          |
|  +--------------+  +---------------+  +----------------+ |
|  | 7x NAL       |  | BCrypt Hash   |  | Device:        | |
|  | PhysMem      |  | & Signature   |  | gobbledygook   | |
|  | Driver Copy  |  | Verify        |  |                | |
|  +--------------+  +---------------+  +----------------+ |
+----------------------------------------------------------+
---

2. XOR'd IAT — Obfuscation Mechanism

vgk.sys doesn't call APIs through a normal IAT. Instead it uses a custom XOR-encoded import table that gets resolved at driver init time.

2.1 Structure

The master resolver sits at vgk+0x6F31C (vgk_ResolveAllAPIs). It runs during driver initialization and resolves all API addresses into an XOR-encoded table.

Each entry is 0x20 bytes:
Code:
+0x00: idx    (QWORD) — 0 or 1, selects which enc slot to use
+0x08: key    (QWORD) — XOR key
+0x10: enc[0] (QWORD) — encoded address slot 0
+0x18: enc[1] (QWORD) — encoded address slot 1
 
Resolution: resolved_address = key ^ enc[idx]
Table location: .data section, RVA 0xB14D8 to 0xB3ED0 (234 entries total).

2.2 Runtime Call Pattern

Here's what a typical XOR'd API call looks like at runtime:
Code:
; Typical XOR'd API call:
movzx eax, byte ptr [vgk+0x322B0]     ; load idx
mov   rax, [rsi+rax*8+0B25E8h]        ; load enc[idx]
xor   rax, [vgk+0x322B8]              ; XOR with key -> real address
call  rax                              ; call the API
2.3 Resolved API Table (Live Verified)

I resolved these by reading the XOR table entries live from memory and computing key ^ enc[idx]. All addresses verified against loaded module symbols.

Kernel Debug Monitoring APIs:
- 0xB1AE8 -> KdDebuggerNotPresent
- 0xB1B08 -> KdDebuggerEnabled
- 0xB1B38 -> KdEnteredDebugger
- 0xB1D68 -> KdChangeOption

Process/Thread Management:
- 0xB1B58 -> PsInitialSystemProcess
- 0xB1B78 -> PsProcessType
- 0xB1B98 -> PsThreadType
- 0xB1BB8 -> IoDriverObjectType
- 0xB1BD8 -> MmSectionObjectType
- 0xB1BF8 -> MmUserProbeAddress
- 0xB1C78 -> HalPrivateDispatchTable
- 0xB1E08 -> PsGetProcessDebugPort
- 0xB1E30 -> PsCreateSystemThread
- 0xB1E58 -> PsTerminateSystemThread
- 0xB1EA8 -> PsGetThreadId
- 0xB1EC8 -> IoThreadToProcess
- 0xB1EF8 -> PsGetThreadProcessId

Callback Registration APIs:
- 0xB1F18 -> PsSetCreateProcessNotifyRoutine
- 0xB1F38 -> PsSetCreateProcessNotifyRoutineEx
- 0xB1F58 -> PsSetCreateThreadNotifyRoutine
- 0xB1F78 -> PsSetLoadImageNotifyRoutine
- 0xB1F98 -> PsRemoveCreateThreadNotifyRoutine
- 0xB1FB8 -> PsRemoveLoadImageNotifyRoutine

Work Item / Callback:
- 0xB1CA0 -> ExCreateCallback
- 0xB1CC8 -> ExQueueWorkItem
- 0xB1CF0 -> IoAllocateWorkItem
- 0xB1D18 -> IoFreeWorkItem
- 0xB1D40 -> IoQueueWorkItem

Process Inspection APIs:
- 0xB1D88 -> PsGetProcessWow64Process
- 0xB1DA8 -> PsGetCurrentProcessWow64Process
- 0xB1DC8 -> PsGetProcessExitStatus
- 0xB1DE8 -> PsGetProcessId
- 0xB2038 -> PsGetCurrentThreadPreviousMode
- 0xB2058 -> PsGetProcessPeb
- 0xB2078 -> PsIsProtectedProcessLight
- 0xB2098 -> PsGetProcessImageFileName
- 0xB20B8 -> PsGetProcessWin32Process
- 0xB20D8 -> PsGetProcessCreateTimeQuadPart
- 0xB20F8 -> PsIsProtectedProcess

Crypto APIs (cng.sys):
- 0xB36E8 -> BCryptOpenAlgorithmProvider
- 0xB3708 -> BCryptGetProperty
- 0xB3728 -> BCryptCreateHash
- 0xB3748 -> BCryptFinishHash
- 0xB3768 -> BCryptHashData

SSDT Hook Targets:
- 0xB1680 -> NtMapViewOfSection
- 0xB1678 -> NtProtectVirtualMemory

---

3. Callback System — 7 Kernel Callbacks

I verified these by directly reading the kernel callback arrays (PspCreateProcessNotifyRoutine, PspCreateThreadNotifyRoutine, PspLoadImageNotifyRoutine) from live memory.

3.1 CreateProcess Notify (2 callbacks)
Code:
PspCreateProcessNotifyRoutine[10] -> vgk+0xCC98
PspCreateProcessNotifyRoutine[11] -> vgk+0xCD40
Called on every process creation/termination. Sub-functions:
- vgk+0xB940C -> Debug detection -> g_DetectionFlags |= 0x2
- vgk+0xBA22C -> Tamper detection -> g_DetectionFlags |= 0x1
- Uses SeLocateProcessImageName for process image analysis

Why two? One registered via PsSetCreateProcessNotifyRoutine, the other via PsSetCreateProcessNotifyRoutineEx. The Ex version can BLOCK process creation.

3.2 LoadImage Notify (1 callback)
Code:
PspLoadImageNotifyRoutine[1] -> vgk+0xBEE4
Called whenever a DLL/driver is loaded. If image size < 0x1000000, runs signature/hash check via vgk+0xB38A8. Suspicious image sets g_DetectionFlags |= 0x400. Logs image info to a circular buffer.

3.3 CreateThread Notify (1 callback)
Code:
PspCreateThreadNotifyRoutine[2] -> vgk+0xD5CC
Called on every thread creation. Validates return address — if outside any known module, sets g_DetectionFlags |= 0x800. Also inspects section objects (SEC_IMAGE, SEC_FILE). Anomaly sets g_DetectionFlags |= 0x4000000.

3.4 Registry Callback (1 callback)
Code:
CmRegisterCallbackEx -> vgk+0xBD2DC
Monitors registry write operations. Only handles RegNtPostSetValueKey (a2 == 8). If the key matches a blacklist, returns STATUS_ACCESS_DENIED.

3.5 OB Callback — Process/Thread Handle Guard (2 callbacks)
Code:
ObRegisterCallbacks -> vgk+0xBC42C (entry), vgk+0xBC4C8 (handler)
Filters process/thread handle open operations. Strips PROCESS_VM_READ/WRITE and similar access rights from DesiredAccess. Protected process is stored in g_ProtectedProcessEPROCESS (Valorant.exe when running). Also does return address validation -> g_DetectionFlags |= 0x800.

3.6 Other Registered Callbacks on the Same System

For reference, here's the full process notify callback array I dumped:
Code:
Process[0]  -> ntoskrnl
Process[1]  -> cng.sys
Process[2]  -> CI.dll
Process[3]  -> unknown
Process[4]  -> unknown
Process[5]  -> CI.dll
Process[6]  -> unknown
Process[7]  -> unknown
Process[8]  -> unknown
Process[9]  -> unknown
Process[10] -> vgk.sys (vgk+0xCC98)
Process[11] -> vgk.sys (vgk+0xCD40)
---

4. SSDT Hook Mechanism

4.1 Hooked Syscalls

vgk.sys hooks exactly 2 SSDT entries:

| Hook | Original API | Stored Address | Hook Handler |
|------|-------------|----------------|--------------|
| #1 | NtMapViewOfSection | vgk+0xB1680 | vgk+0x4F6CC |
| #2 | NtProtectVirtualMemory | vgk+0xB1678 | vgk+0x4FA38 |

4.2 Why These Two?

NtMapViewOfSection: Cheats commonly use section mapping for code injection. This hook monitors which process maps which section.

NtProtectVirtualMemory: Changing memory protection (making pages RWX) is a fundamental step in cheat injection. This hook monitors protection changes in the protected process.

4.3 Hook Handler Structure
Code:
vgk+0x4F6CC (NtMapViewOfSection hook):
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  ; ... parameter validation, logging, redirect to original
 
vgk+0x4FA38 (NtProtectVirtualMemory hook):
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  ; ... same structure

---

5. System Threads

5.1 Thread Layout

vgk.sys creates 4 system threads:

| Thread | RVA | Purpose | Interval |
|--------|-----|---------|----------|
| MonitorThread | 0x470C4 | Heartbeat/monitoring | Continuous |
| ScanThread #1 | 0x635C | Periodic scanning | 1.5 seconds |
| ScanThread #2 | 0x635C | Periodic scanning | 30 seconds |
| LBR Monitor | 0x88FC8 | Last Branch Record monitoring | Continuous |

5.2 ScanThread Details

The ScanThread is the main scanning loop. Each iteration runs:
Code:
1.  Enumerate 32 system modules
2.  vgk+0xB2AE8 -> Module integrity (hash) check
3.  vgk+0xB5DA0 -> Additional module check
4.  vgk+0xB50E8 -> VAD (Virtual Address Descriptor) scan
5.  vgk+0xB2964 -> Hook detection
6.  vgk+0xB247C -> Patch detection
7.  vgk+0xB4088 -> Additional check A
8.  vgk+0xB3C1C -> Additional check B
9.  vgk+0xB6300 -> Control check (fail = flag set)
10. vgk+0x310D4 -> Periodic check (every 10 iterations)
11. rdtsc timestamp evidence collection
Live status:
Code:
g_ScanIterationCount = 0x8DB (2267 iterations)
g_LogCounter         = 0x29 (41 log entries)
g_DetectionFlags     = 0x0 (CLEAN)
5.3 LBR (Last Branch Record) Monitor

This thread uses the CPU's Last Branch Record feature to monitor code flow:

- AMD CPU: MSR 0x1DB (MSR_LASTBRANCHFROMIP)
- Intel CPU: MSR 0x680 (LBR_FROM_IP)
- Ring Buffer 1: 5.7MB (0x5B8D80 bytes), entry size 0x28 (40 bytes)
- Ring Buffer 2: 360KB (0x57E40 bytes), entry size 0x18 (24 bytes)

Purpose: ROP/JOP gadget detection. If a cheat uses ROP chains, abnormal branch patterns will show up in the LBR records.

Live status:
Code:
g_LBR_RingBuffer1 = ffff8189'ac410000 (allocated)
g_LBR_RingBuffer2 = ffff8189'a8702000 (allocated)
g_LBR_EntryCount  = 0 (Valorant not running)
g_CpuVendor       = 1 (AMD)
g_LBR_MsrNumber   = 0x1DB
---

6. Detection Flags System

6.1 Central Bitmask: g_DetectionFlags (RVA 0xA83C8)

All detections are accumulated into a single 64-bit bitmask:

| Bit | Value | Source | Description |
|-----|-------|--------|-------------|
| 0 | 0x00000001 | CreateProcess CB | Tamper detection |
| 1 | 0x00000002 | CreateProcess CB | Debug detection |
| 2 | 0x00000004 | Scan Thread | Hook detection |
| 3 | 0x00000008 | Scan Thread | Patch detection |
| 5 | 0x00000020 | Scan Thread | Module integrity violation |
| 10 | 0x00000400 | LoadImage CB | Suspicious image loaded |
| 11 | 0x00000800 | OB/Thread CB | Return address outside module |
| 12 | 0x00001000 | Scan Thread | Scan check A |
| 13 | 0x00002000 | Scan Thread | Scan check B (inverted) |
| 14 | 0x00004000 | Scan Thread | Scan check C |
| 15 | 0x00008000 | Scan Thread | Byte flag A |
| 16 | 0x00010000 | Scan Thread | Byte flag B |
| 19 | 0x00080000 | Scan Thread | Module anomaly |
| 20 | 0x00100000 | Scan Thread | VAD anomaly |
| 24 | 0x01000000 | Scan Thread | Scan check D |
| 26 | 0x04000000 | Thread CB | Code injection |

6.2 Reporting Mechanism
Code:
When a flag is set:
  1. rdtsc -> get timestamp
  2. g_TimestampXor ^= timestamp  (accumulate evidence)
  3. Transfer to usermode via shared memory
  4. Usermode client -> send to Riot servers
Live status:
Code:
g_DetectionFlags = 0x0000000000000000  <- CLEAN
g_TimestampXor   = 0x22066fdb9581bb49  <- set during init
---

7. CPU / HVCI / VBS / SecureBoot Checks

7.1 CPU Vendor Detection (vgk+0x89CB0)
Code:
xor eax, eax
xor ecx, ecx
cpuid                           ; CPUID(0) - vendor string
; edx:ecx:ebx = vendor string
 
; Intel check: "GenuineIntel"
xor r8d, 49656E69h             ; "ineI"
xor eax, 6C65746Eh             ; "ntel"
xor eax, 756E6547h             ; "Genu"
or  r8d, eax
jne not_intel
mov byte ptr [g_CpuVendor], 2  ; Intel = 2
mov ecx, 680h                  ; Intel LBR MSR
rdmsr
 
; AMD check: "AuthenticAMD"
xor ebx, 68747541h             ; "Auth"
xor edx, 69746E65h             ; "enti"
xor ecx, 444D4163h             ; "cAMD"
or  ebx, edx
jne not_amd
mov byte ptr [g_CpuVendor], 1  ; AMD = 1
mov ecx, 1DBh                  ; AMD LBR MSR (MSR_LASTBRANCHFROMIP)
rdmsr
7.2 HVCI (Hypervisor Code Integrity) Check
Code:
; ZwQuerySystemInformation(0x67) = SystemCodeIntegrityInformation
mov ecx, 67h
call ZwQuerySystemInformation_XOR
test eax, eax
js   hvci_fail
test dword ptr [rsp+44h], 1C00h  ; HVCI bits check
setne al                          ; al = 1 if HVCI enabled
test al, al
jne  hvci_enabled
; HVCI disabled:
mov eax, 1
xchg eax, [g_HvciNotEnabled]     ; g_HvciNotEnabled = 1
Live status: g_HvciNotEnabled = 1 -> HVCI is OFF

7.3 VSM/VBS Protection Check (vgk+0x80590)
Code:
; ZwQuerySystemInformation(0xDD) = SystemVsmProtectionInformation
mov ecx, 0DDh
call ZwQuerySystemInformation_XOR
test eax, eax
js   fail
mov eax, [rsp+30h]
shr eax, 8                     ; check bit 8
and al, 1                      ; VBS active?
7.4 SecureBoot Policy Check (vgk+0x76204)
Code:
; ZwQuerySystemInformation(0xB7) = SystemSecureBootPolicyInformation
; Called from the certificate verification chain
7.5 Additional HVCI Check (vgk+0x815D4)

This function is heavily obfuscated — jumps to another location:
Code:
jmp vgk!Egg+0x189D74  ; obfuscated check
---

8. Shared Memory — Kernel <-> Usermode Communication

8.1 Structure
Code:
g_SectionObject  = 0x133        <- Kernel handle (ZwCreateSection)
g_SharedMemState = 0x01         <- ACTIVE
8.2 Creation Process (vgk+0x1E7405)

1. IoCreateDevice("\\Device\\gobbledygook") — create device
2. MmAllocatePagesForMdl -> allocate physical pages
3. MmMapLockedPagesSpecifyCache -> kernel mapping
4. ZwCreateSection -> create section object
5. Usermode client connects via ZwOpenSection + ZwMapViewOfSection

8.3 Data Flow
Code:
Kernel -> Shared Memory:
  - Detection flags
  - Timestamp evidence (rdtsc XOR)
  - Scan results
  - Module integrity reports
 
Shared Memory -> Usermode:
  - Vanguard tray client reads it
  - Sends to Riot servers via HTTPS
---

9. NAL Driver — Physical Memory Access

9.1 Embedded NAL Copies

vgk.sys contains 7 embedded copies of code from the Intel NAL (Network Abstraction Layer) driver:
Code:
Found strings:
  "NalDeviceControl: InputBuffer was NULL"  (7 copies)
  "MAPMEM.SYS: memory successfully mapped"  (7 copies)
  "Leaving MsIoDispatch"
  "Leaving WinIoDispatch"
  "Nal Windows Driver Loaded"
9.2 Purpose

The NAL driver provides physical memory read/write capability. vgk.sys uses this for:
- Kernel memory integrity checks
- Reading memory via physical addresses to detect rootkits
- Works through the MmGetPhysicalAddress + MmMapIoSpace pattern

9.3 Why 7 Copies?

Obfuscation. Each copy may be encoded with a different XOR key or called from different entry points. This makes static analysis harder.

---

10. Crypto — Hash & Signature Verification

10.1 APIs Used

From cng.sys (Cryptographic Next Generation):
- BCryptOpenAlgorithmProvider — open hash algorithm
- BCryptCreateHash — create hash context
- BCryptHashData — hash data
- BCryptFinishHash — finalize hash
- BCryptGetProperty — query algorithm property

Plaintext strings found in .stub0 section:
Code:
BCryptOpenAlgorithmProvider
BCryptGetProperty
BCryptCloseAlgorithmProvider
BCryptImportKeyPair
BCryptVerifySignature
BCryptCreateHash
BCryptHashData
BCryptFinishHash
BCryptDestroyHash
10.2 Use Cases

1. Module Integrity: Compute hash of loaded drivers, compare against known hashes
2. Image Verification: Verify signature of DLLs/drivers in the LoadImage callback
3. Code Signing: Riot's own signature verification (BCryptImportKeyPair + BCryptVerifySignature)
4. HWID Hashing: Hash hardware identifiers to create a unique ID

---

11. HWID Collection Mechanism

11.1 General Approach

vgk.sys doesn't store HWID info as plaintext strings — everything is XOR-obfuscated. But we can infer the collection mechanism from the APIs it resolves and the structures it uses.

11.2 Collected Information (API Analysis Based)

| Source | Method | API |
|--------|--------|-----|
| CPU | CPUID(0) vendor, CPUID(1) family/model/stepping | Direct CPUID instruction |
| Disk | IOCTL_STORAGE_QUERY_PROPERTY via ZwDeviceIoControlFile | XOR'd ZwDeviceIoControlFile (0xA3CA8) |
| NIC MAC | IoGetDeviceObjectPointer + IOCTL | XOR'd IoGetDeviceObjectPointer (0xA33C0) |
| SMBIOS | ZwQuerySystemInformation(0x4C) = SystemFirmwareTableInformation | XOR'd ZwQuerySystemInformation (0xA25D8) |
| Registry | ZwOpenKey + ZwQueryValueKey | XOR'd ZwOpenKey (0xA3898), ZwQueryValueKey (0xA26A0) |
| TPM | IoCreateFileEx -> TPM device | XOR'd IoCreateFileEx (0xA2B78) |
| Process List | ZwQuerySystemInformation(5) | Cheat process detection |

11.3 HWID Hash Generation
Code:
1. Collect hardware info (disk serial, MAC, SMBIOS, CPU ID)
2. BCryptCreateHash to create hash context
3. BCryptHashData to feed each piece of info into the hash
4. BCryptFinishHash to get the final hash
5. This hash = HWID fingerprint
6. Send to usermode via shared memory
7. Forward to Riot servers
11.4 Anti-Spoof Mechanisms

- Physical memory reads: Uses the NAL driver to read from physical addresses, bypassing hypervisor-level spoofs
- Multiple sources: Combines multiple hardware identifiers instead of relying on a single HWID
- Timestamp evidence: Collects timing info via rdtsc — VM detection
- LBR monitoring: Code flow integrity check via branch history

---

12. IOCTL Dispatch — Usermode Communication (Fully Reversed)

This was the hardest part. The IOCTL dispatch is buried under layers of anti-disassembly and obfuscation. I initially thought it was VM-protected, but after iterating on different approaches I found the real handler at vgk+0x53694 which uses standard (though obfuscated) x86-64 code with the XOR'd IAT pattern.

12.1 Dispatch Chain (Fully Resolved)
Code:
vgk+0x112D1F (DriverDispatch_Entry)
  -> Stack frame setup, parameter rearrangement
  -> call vgk+0x22E52F (IOCTL_Dispatch_Wrapper)
    -> call vgk+0x2238BC (IOCTL_Dispatch_Outer)
      +-- r13d = IOCTL code, rbx = first param
      +-- nop; jmp -> call vgk+0x244E1D; jmp rax (anti-disassembly thunk)
      +-- Real dispatch: vgk+0x53694 (IOCTL_Handler_Inner)
 
vgk+0x53694 (IOCTL_Handler_Inner) - MAIN HANDLER:
  +-- Stack frame: 0x1F0 bytes, security cookie
  +-- PsGetCurrentProcess() -> caller EPROCESS
  +-- PsGetProcessImageFileName() -> caller process name
  +-- vgk+0x7A68C -> Process whitelist validation
  |   +-- Fail -> STATUS_ACCESS_DENIED (0xC0000022)
  |   +-- Pass -> continue
  +-- IRP_MJ_DEVICE_CONTROL parameter parsing:
  |   +-- [rsi+18h] = SystemBuffer (IRP->AssociatedIrp.SystemBuffer)
  |   +-- [r12+8]  = InputBufferLength  (min 8 bytes)
  |   +-- [r12+10h] = OutputBufferLength (min 8 bytes)
  |   +-- [r12+18h] = IoControlCode
  +-- vgk+0x572A4 -> IOCTL code validation (whitelist check)
  |   +-- Invalid code -> STATUS_INVALID_PARAMETER (0xC000000D)
  +-- RC4 Decryption:
  |   +-- Key: 130 bytes (0x82) @ vgk+0x28A78 (RVA 0x98260)
  |   +-- S-box init: 0x100 bytes @ [rsp+0xB0]
  |   +-- XMM copy for key -> S-box KSA
  |   +-- Input buffer XOR decrypt (byte-by-byte RC4 stream)
  +-- IOCTL Code Dispatch (binary search tree):
  |   +-- Pivot: 0x22C0D8
  |   +-- Sub-pivots: 0x22C04C, 0x22C028, 0x22C128, 0x22C150
  |   +-- Sequential sub chains for all codes
  +-- Handler function call
  +-- RC4 Encryption (response):
  |   +-- Same key encrypts output buffer
  |   +-- rdtsc timestamp -> [SystemBuffer] (first 8 bytes)
  |   +-- [rsi+38h] = IoStatus.Information (output size)
  +-- IofCompleteRequest
12.2 RC4 Encryption

All IOCTL communication is RC4-encrypted. I dumped the key from live memory:
Code:
Key (130 bytes, RVA 0x98260):
  66 b3 23 6e 7a ff cd 5d 91 c4 3d 29 c6 65 4f 15
  d2 5b a9 8d 8b 3a 4c d9 de 6d 9e 85 a8 96 e2 97
  61 36 cf 6c bd 05 2b 78 b6 a6 2d f6 0b 51 da c5
  aa 59 a2 63 06 7d 76 48 fc 4b 90 d3 46 f5 cb 4e
  ae 47 bf 56 39 72 a0 be 5e ea 80 3f ec 31 e9 17
  52 28 b5 68 04 0a 6b e0 a7 ab 57 d0 44 27 cc 26
  c8 9d 6f 42 69 30 62 ed 2f b9 88 1e b1 b0 1f 67
  93 a3 94 09 d7 8c 74 45 0c 95 98 58 f8 df 34 89
  1b 5f
 
Flow:
  1. Usermode -> RC4 encrypt(request) -> DeviceIoControl
  2. Kernel: RC4 decrypt(input) -> process -> RC4 encrypt(output)
  3. Kernel -> rdtsc timestamp written to first 8 bytes
  4. Usermode -> RC4 decrypt(response)
12.3 Process Whitelist Validation

Every IOCTL call validates the caller process:
Code:
PsGetCurrentProcess()           -> EPROCESS
PsGetProcessImageFileName()     -> "RiotClientServices.exe" etc.
call vgk+0x7A68C                -> whitelist check
  Fail -> STATUS_ACCESS_DENIED (0xC0000022)
  Pass -> IOCTL dispatch continues
Only Riot's own processes can send IOCTLs to the driver.

12.4 Complete IOCTL Code Table (55 IOCTLs)

All are DeviceType=0x22, METHOD_BUFFERED, FILE_ANY_ACCESS. I extracted these from the clean (non-obfuscated) validator function at vgk+0x572A4.

Low Range (0x22C000 - 0x22C04C):
Code:
0x22C000  Func 0x00
0x22C004  Func 0x01
0x22C00C  Func 0x03
0x22C028  Func 0x0A
0x22C02C  Func 0x0B
0x22C04C  Func 0x13
Mid-Low Range (0x22C050 - 0x22C080):
Code:
0x22C050  Func 0x14
0x22C054  Func 0x15
0x22C058  Func 0x16
0x22C05C  Func 0x17
0x22C060  Func 0x18
0x22C064  Func 0x19
0x22C06C  Func 0x1B
0x22C074  Func 0x1D
0x22C080  Func 0x20
Mid Range (0x22C084 - 0x22C0D8):
Code:
0x22C084  Func 0x21
0x22C090  Func 0x24
0x22C094  Func 0x25
0x22C098  Func 0x26
0x22C09C  Func 0x27
0x22C0A0  Func 0x28
0x22C0CC  Func 0x33
0x22C0D8  Func 0x36  (dispatch pivot)
Mid-High Range (0x22C0DC - 0x22C128):
Code:
0x22C0DC  Func 0x37
0x22C0E4  Func 0x39
0x22C0E8  Func 0x3A
0x22C0EC  Func 0x3B
0x22C0F0  Func 0x3C  ** recursive dispatch **
0x22C0F4  Func 0x3D
0x22C0F8  Func 0x3E
0x22C0FC  Func 0x3F
0x22C100  Func 0x40
0x22C104  Func 0x41
0x22C108  Func 0x42
0x22C128  Func 0x4A
High Range (0x22C12C - 0x22C150):
Code:
0x22C12C  Func 0x4B
0x22C130  Func 0x4C
0x22C134  Func 0x4D
0x22C138  Func 0x4E
0x22C140  Func 0x50
0x22C144  Func 0x51
0x22C148  Func 0x52
0x22C14C  Func 0x53
0x22C150  Func 0x54
Highest Range (0x22C154 - 0x22C17C):
Code:
0x22C154  Func 0x55
0x22C158  Func 0x56
0x22C15C  Func 0x57
0x22C160  Func 0x58
0x22C164  Func 0x59
0x22C168  Func 0x5A
0x22C16C  Func 0x5B
0x22C170  Func 0x5C
0x22C174  Func 0x5D
0x22C178  Func 0x5E
0x22C17C  Func 0x5F
12.5 Notable Handler Functions

Some interesting handlers I identified from the dispatch code:

| IOCTL Group | Handler RVA | Type |
|-------------|-------------|------|
| 0x22C000 group | vgk+0x571E0 | Obfuscated handler |
| 0x22C004 | vgk+0x55820 | Obfuscated handler |
| 0x22C00C | vgk+0x56AA4 | Obfuscated handler |
| 0x22C0F0 (Func 0x3C) | vgk+0x320C -> vgk+0x2238BC | Recursive dispatch |
| 0x22C0F8 (Func 0x3E) | vgk+0x564B0 | Clean prologue - data query |
| 0x22C0FC (Func 0x3F) | vgk+0x567A4 | Clean prologue - data query |
| 0x22C148-0x22C14C | vgk+0x731C4 | Registered handler table lookup |

12.6 Special Handlers

Recursive Dispatch (0x22C0F0):
Code:
vgk+0x320C -> jmp vgk+0x2238BC (IOCTL_Dispatch_Outer)
This IOCTL code re-dispatches itself — probably a "batch" or "compound" IOCTL mechanism. A single IOCTL call can execute multiple sub-commands.

Registered Handler Table (0x22C148-0x22C14C):
Code:
vgk+0x731C4:
  mov r10d, [vgk+0x3EF8]     ; handler count
  lea rdi, [vgk+0x3F00]      ; handler table base
  ; Search table, call matching handler
This is a dispatch mechanism for dynamically registered handlers. The usermode client can register handlers at runtime.

Buffer Size Validation (0x22C0F8, Func 0x3E):
Code:
cmp r14d, 18h               ; InputBufferLength == 0x18?
jne error
call vgk+0x53AA0             ; handler
mov [rsi+38h], 18h           ; IoStatus.Information = 0x18
This handler expects exactly 0x18 (24) bytes of input and returns 0x18 bytes of output.

Version/Init Check (0x22C0FC, Func 0x3F):
Code:
call vgk+0xD261C:
  call vgk+0xD6170            ; check A -> return 1?
  call vgk+0xD6788            ; check B -> return 3?
  ; Two-stage init/version verification
12.7 IOCTL Dispatch Flow Diagram
Code:
Usermode (Vanguard Client)
  |
  +-- RC4 encrypt(request_data, key_130byte)
  +-- DeviceIoControl(hDevice, IOCTL_CODE, encrypted_buf, ...)
  |
  v
vgk+0x112D1F (DriverDispatch_Entry)
  |
  +-- IRP parse, get stack location
  v
vgk+0x2238BC (IOCTL_Dispatch_Outer)
  |
  +-- r13d = IOCTL code
  +-- Anti-disassembly thunk -> vgk+0x244E1D
  v
vgk+0x53694 (IOCTL_Handler_Inner)
  |
  +-- PsGetCurrentProcess() + PsGetProcessImageFileName()
  +-- Process whitelist check (vgk+0x7A68C)
  |   +-- Fail -> STATUS_ACCESS_DENIED
  |
  +-- IOCTL code validation (vgk+0x572A4)
  |   +-- Invalid -> STATUS_INVALID_PARAMETER
  |
  +-- Buffer size validation (min 8 bytes in/out)
  |
  +-- RC4 decrypt(input_buffer)
  |   +-- Key: 130 bytes @ RVA 0x98260
  |
  +-- Binary search dispatch:
  |   +-- cmp 0x22C0D8 (pivot)
  |   +-- cmp 0x22C04C / 0x22C028 (sub-pivots)
  |   +-- cmp 0x22C128 / 0x22C150 (upper pivots)
  |   +-- sub chain for all 55 IOCTL codes
  |
  +-- Handler function call
  |   +-- rcx=decrypted_buffer, edx=input_size, r8d=output_size, r9=[rsi+30h]
  |
  +-- RC4 encrypt(output_buffer)
  +-- rdtsc -> output[0:8] (timestamp)
  +-- IoStatus.Information = output_size
  +-- IofCompleteRequest(IRP, IO_NO_INCREMENT)
12.8 Anti-Disassembly Techniques

Obfuscation techniques used in the IOCTL dispatch:

1. Junk Instructions: clc, stc, cmc, test reg,reg (flag-only ops) sprinkled between real instructions
2. Dead Code: movzx cx,r9b; movsx ecx,ax; mov ecx,6 — only the last assignment matters, the rest is junk
3. Opaque Predicates: cmp r12,45846954h — comparisons that are never true
4. Anti-Disassembly Thunks: call X; jmp rax pattern — X computes an address and returns it
5. Indirect Dispatch: call vgk+0x244E1D -> computed address via jmp rax

---

13. Module Whitelist

Code:
Whitelist[0] = vgk.sys base
Whitelist[1] = vgk.sys end
Whitelist[2..20] = 0 (empty)
Only vgk.sys itself is in the whitelist. Other modules (ntoskrnl, ci.dll, etc.) are checked through a different mechanism.

---

14. Debug Spoof Status

I wrote a separate KDMapper-compatible driver (vgkpatch.c) that spoofs all kernel debug globals before vgk.sys can read them. Here's what it patches:

| Global | Original | Spoofed | Status |
|--------|----------|---------|--------|
| KdDebuggerEnabled | TRUE | FALSE (0x00) | Working |
| KdDebuggerNotPresent | FALSE | TRUE (0x01) | Working |
| KdEnteredDebugger | TRUE | FALSE (0x00) | Working |
| KSHD+0x2D4 | 1 | 0 | Working |
| SharedDataFlags | debug bits | cleared | Working |

Result: g_DetectionFlags = 0x0 — debug detection never triggers. The CreateProcess callback's debug check at vgk+0xB940C reads these globals, and since they're spoofed, bit 1 (FLAG_DEBUG_DETECTION) is never set.

---

15. Manipulation Analysis — What Can and Can't Be Done

15.1 Safe Manipulations

| Target | Method | Risk |
|--------|--------|------|
| Debug globals | Direct write (R+W .data) | Low — PatchGuard doesn't protect these |
| g_DetectionFlags | Direct zeroing | Low — but gets continuously re-set |
| g_ProtectedProcessEPROCESS | Zero it out | Medium — OB callback becomes inactive |
| g_HvciNotEnabled | Set to 1 | Low — already 1 |

15.2 Dangerous Manipulations (PatchGuard / BSOD)

| Target | Why It's Dangerous |
|--------|--------------------|
| SSDT unhook | PatchGuard monitors SSDT -> BSOD 0x109 |
| OB callback code patching | PatchGuard monitors callback list |
| Callback removal | PsRemove* call is safe but vgk.sys re-registers |
| .text section patching | Code integrity violation -> detection |

15.3 Medium Risk Manipulations

| Target | Method | Risk |
|--------|--------|------|
| Callback function pointer | Modify pointer in .data | Medium — integrity check may detect |
| Scan thread termination | Thread terminate | Medium — heartbeat timeout triggers |
| Shared memory | Close section handle | Medium — usermode client gets errors |
| LBR buffer | Zero/fill | Low-Medium |

---

16. Summary Status Table

| Component | Status | Detail |
|-----------|--------|--------|
| Detection Flags | 0x0 CLEAN | Debug spoof working |
| Scan Thread | ACTIVE (2267 iter) | Normal operation |
| SSDT Hooks | ACTIVE | NtMapViewOfSection + NtProtectVirtualMemory |
| Process Callbacks | 2 REGISTERED | Slots 10 and 11 |
| LoadImage Callback | 1 REGISTERED | Slot 1 |
| Thread Callback | 1 REGISTERED | Slot 2 |
| Registry Callback | 1 REGISTERED | CmRegisterCallbackEx |
| OB Callbacks | 2 REGISTERED | Process + Thread handle guard |
| LBR Monitoring | ACTIVE | AMD MSR 0x1DB, 6MB buffer |
| HVCI | OFF | g_HvciNotEnabled = 1 |
| Shared Memory | ACTIVE | Handle 0x133 |
| Module Whitelist | vgk.sys only | |
| NAL PhysMem | 7 COPIES | Physical memory access |
| Crypto | ACTIVE | BCrypt hash + signature |
| Debug Spoof | WORKING | All Kd* globals clean |
| Protected Process | EMPTY | Valorant not running |
| IOCTL Dispatch | FULLY REVERSED | 55 IOCTLs, RC4 encrypted, process whitelist |

---

Offsets.h
Code:
#pragma once
 
#define VGK_IMAGE_NAME          "vgk.sys"
#define VGK_IMAGE_NAME_LEN      7
 
#define SCAN_INTERVAL_MS        500
#define SCAN_MAX_ATTEMPTS       120
 
#define VGK_OBF_CONSTANT        0xFFFFF80649DB0000ULL
#define VGK_OBF_ENTRY_SIZE      0x20
#define VGK_OBF_TABLE_START     0xB14D8
#define VGK_OBF_TABLE_END       0xB3ED0
#define VGK_OBF_TOTAL_ENTRIES   234
#define VGK_OBF_NAMED_ENTRIES   211
 
#define OFF_CreateProcessNotify_Entry1      0xBCD40
#define OFF_CreateProcessNotify_Entry2      0xBCC98
#define OFF_CreateProcessNotify_Handler     0xBCDE8
#define OFF_DebugDetection                  0xB940C
#define OFF_TamperDetection                 0xBA22C
 
#define OFF_LoadImageNotify_Entry           0xBBEE4
#define OFF_LoadImageNotify_Handler         0xBBFB8
#define OFF_ImageSignatureCheck             0xB38A8
#define OFF_ImageAnalysis                   0xBDAA0
 
#define OFF_RegistryCallback                0xBD2DC
#define OFF_RegistryBlacklist1              0xBA354
#define OFF_RegistryBlacklist2              0xBA7C4
 
#define OFF_ObCallback_Entry                0xBC42C
#define OFF_ObCallback_Handler              0xBC4C8
 
#define OFF_CreateThreadNotify_Entry        0xBD5CC
#define OFF_CreateThreadNotify_Handler      0xBD67C
 
#define OFF_MonitorThread                   0x470C4
 
#define OFF_ScanThread_Main                 0x635C
#define OFF_ScanThread_Trampoline           0x72D4C4
#define OFF_ModuleIntegrityCheck            0xB2AE8
#define OFF_ModuleExtraCheck                0xB5DA0
#define OFF_VADScan                         0xB50E8
#define OFF_HookDetection                   0xB2964
#define OFF_PatchDetection                  0xB247C
#define OFF_ScanCheckA                      0xB4088
#define OFF_ScanCheckB                      0xB3C1C
#define OFF_ScanControl                     0xB6300
#define OFF_PeriodicCheck                   0x310D4
 
#define OFF_DriverDispatch_Entry             0x112D1F
#define OFF_IOCTL_Dispatch_Wrapper           0x22E52F
#define OFF_IOCTL_Dispatch_Outer             0x2238BC
#define OFF_IOCTL_AntiDisasm_Thunk           0x1F4E1D
#define OFF_IOCTL_Handler_Inner              0x53694
#define OFF_IOCTL_ProcessWhitelist           0x7A68C
#define OFF_IOCTL_CodeValidator              0x572A4
#define OFF_IOCTL_RC4_Key                    0x98260
#define OFF_IOCTL_RC4_KeyLen                 0x82
#define OFF_IOCTL_LogFunction                0x57CC8
#define OFF_IOCTL_RecursiveDispatch          0x320C
#define OFF_IOCTL_RegisteredHandlerTable     0x3EF8
#define OFF_IOCTL_RegisteredHandlerData      0x3F00
#define OFF_IRP_Dispatch                     0x24E2D5
 
#define OFF_DeviceSetup_SharedMemory         0x1E7405
#define OFF_DeviceSetup_Thunk                0x9534
#define OFF_DeviceInit                       0x259C69
 
#define OFF_SharedMem_CreateSection          0x5DF90
#define OFF_SharedMem_OpenSection            0x6DF58
#define OFF_SharedMem_MapView                0x235810
#define OFF_SharedMem_MapView2               0x21B458
 
#define OFF_FileIO_Utility                   0x281D32
#define OFF_Section_FileProtect              0x28DD0B
 
#define FLAG_TAMPER_DETECTION               0x00000001
#define FLAG_DEBUG_DETECTION                0x00000002
#define FLAG_HOOK_DETECTION                 0x00000004
#define FLAG_PATCH_DETECTION                0x00000008
#define FLAG_MODULE_INTEGRITY               0x00000020
#define FLAG_SUSPICIOUS_IMAGE               0x00000400
#define FLAG_RETADDR_OUTSIDE_MODULE         0x00000800
#define FLAG_SCAN_CHECK_A                   0x00001000
#define FLAG_SCAN_CHECK_B                   0x00002000
#define FLAG_SCAN_CHECK_C                   0x00004000
#define FLAG_BYTE_FLAG_A                    0x00008000
#define FLAG_BYTE_FLAG_B                    0x00010000
#define FLAG_MODULE_ANOMALY                 0x00080000
#define FLAG_VAD_ANOMALY                    0x00100000
#define FLAG_SCAN_CHECK_D                   0x01000000
#define FLAG_CODE_INJECTION                 0x04000000
 
#define OFF_g_DetectionFlags                0xA83C8
#define OFF_g_TimestampXor                  0xA8A08
#define OFF_g_ProtectedProcessEPROCESS      0xA81B8
#define OFF_g_LogCounter                    0xA8250
#define OFF_g_ScanIterationCount            0xA4218
#define OFF_g_KernelObjects_Table           0xA4040
#define OFF_g_DeviceObject                  0xA4070
#define OFF_g_SectionObject                 0xA4108
#define OFF_g_SharedMemState                0xA28A0
#define OFF_g_DispatchState                 0xA81A8
#define OFF_g_IntegrityLogOnce1             0xA8150
#define OFF_g_IntegrityLogOnce2             0xA8154
#define OFF_g_IntegrityLogOnce3             0xA8158
 
#define OFF_DeviceName_String               0x922D0
 
#define OFF_OBF_ZwCreateSection             0xA28A8
#define OFF_OBF_ZwMapViewOfSection          0xA2768
#define OFF_OBF_ZwOpenSection               0xA25B0
#define OFF_OBF_ZwUnmapViewOfSection        0xA29E8
#define OFF_OBF_ZwAllocateVirtualMemory     0xA3258
#define OFF_OBF_ZwFreeVirtualMemory         0xA32D0
#define OFF_OBF_ZwProtectVirtualMemory      0xA2AB0
#define OFF_OBF_ZwReadVirtualMemory         0xA24E8
#define OFF_OBF_ZwWriteVirtualMemory        0xA2830
#define OFF_OBF_ZwCreateFile                0xA2A60
#define OFF_OBF_ZwOpenFile                  0xA3500
#define OFF_OBF_ZwReadFile                  0xA2560
#define OFF_OBF_ZwWriteFile                 0xA3208
#define OFF_OBF_ZwClose                     0xA2538
#define OFF_OBF_ZwQuerySystemInformation    0xA25D8
#define OFF_OBF_ZwQueryInformationProcess   0xA3280
#define OFF_OBF_ZwQueryInformationThread    0xA32A8
#define OFF_OBF_ZwQueryObject               0xA32F8
#define OFF_OBF_ZwOpenProcess               0xA34B0
#define OFF_OBF_ZwOpenThread                0xA3E88
#define OFF_OBF_ZwQueryKey                  0xA34D8
#define OFF_OBF_ZwOpenKey                   0xA3898
#define OFF_OBF_ZwCreateKey                 0xA2308
#define OFF_OBF_ZwQueryValueKey             0xA26A0
#define OFF_OBF_ZwSetValueKey               0xA2A10
#define OFF_OBF_ZwDeviceIoControlFile       0xA3CA8
#define OFF_OBF_ZwQueryDirectoryFile        0xA3CF8
#define OFF_OBF_ZwQueryInformationToken     0xA28D0
#define OFF_OBF_ZwTerminateProcess          0xA3DE8
 
#define OFF_OBF_IoCreateDevice              0xA1CC8
#define OFF_OBF_IoDeleteDevice              0xA1CF0
#define OFF_OBF_IoCreateSymbolicLink        0xA1D18
#define OFF_OBF_IoDeleteSymbolicLink        0xA1D40
#define OFF_OBF_IoGetCurrentIrpStackLoc     0xA35A0
#define OFF_OBF_IofCompleteRequest          0xA35C8
#define OFF_OBF_IoAllocateMdl               0xA3050
#define OFF_OBF_IoFreeMdl                   0xA3078
#define OFF_OBF_IoGetDeviceObjectPointer    0xA33C0
#define OFF_OBF_IoCreateFileEx              0xA2B78
#define OFF_OBF_IoAllocateIrp               0xA14D8
#define OFF_OBF_IoGetRequestorProcess       0xA3D48
 
#define OFF_OBF_MmMapLockedPages            0xA3140
#define OFF_OBF_MmUnmapLockedPages          0xA3190
#define OFF_OBF_MmAllocatePagesForMdl       0xA31B8
#define OFF_OBF_MmFreePagesFromMdl          0xA31E0
#define OFF_OBF_MmProbeAndLockPages         0xA30A0
#define OFF_OBF_MmUnlockPages               0xA30C8
#define OFF_OBF_MmBuildMdlForNonPagedPool   0xA30F0
#define OFF_OBF_MmIsAddressValid            0xA2240
#define OFF_OBF_MmGetSystemRoutineAddress   0xA2290
#define OFF_OBF_MmGetPhysicalAddress        0xA22B8
#define OFF_OBF_MmMapIoSpace                0xA22E0
#define OFF_OBF_MmUnmapIoSpace              0xA2330
#define OFF_OBF_MmCopyVirtualMemory         0xA3D20
#define OFF_OBF_MmSecureVirtualMemory       0xA3D70
#define OFF_OBF_MmAllocateContiguousMem     0xA2970
#define OFF_OBF_MmFreeContiguousMem         0xA2998
 
#define OFF_OBF_KeInitializeApc             0xA3A00
#define OFF_OBF_KeInsertQueueApc            0xA3A28
#define OFF_OBF_KeTestAlertThread           0xA3A50
 
#define OFF_OBF_PsSetCreateProcessNotifyEx  0xA1F98
#define OFF_OBF_PsSetCreateThreadNotify     0xA1FE8
#define OFF_OBF_PsSetLoadImageNotify        0xA2010
#define OFF_OBF_ObRegisterCallbacks         0xA2038
#define OFF_OBF_CmRegisterCallbackEx        0xA1F20
#define OFF_OBF_PsCreateSystemThread        0xA3438
 
#define OFF_OBF_PsLookupProcessByProcessId  0xA1E80
#define OFF_OBF_ExEnumHandleTable           0xA24C0
#define OFF_OBF_KeStackAttachProcess        0xA1DB8
#define OFF_OBF_KeUnstackDetachProcess      0xA1DE0
#define OFF_OBF_PsReleaseProcessExitSync    0xA2448
#define OFF_OBF_ObfDereferenceObject        0xA2E70
#define OFF_OBF_IoGetCurrentProcess         0xA2510
#define OFF_OBF_PsGetProcessImageFileName   0xA20B0
 
#define OFF_STR_MmMapLockedPages            0xC1858
#define OFF_STR_MmAllocatePagesForMdl       0xC188E
#define OFF_STR_MmHighestUserAddress        0xC16F4
#define OFF_STR_BCryptOpenAlgProvider       0xC12FA
#define OFF_STR_BCryptImportKeyPair         0xC134C
#define OFF_STR_KeInitializeMutex           0xC17AA
#define OFF_STR_KeReleaseMutex              0xC17BE
#define OFF_STR_MAPH4_Tag                   0xC3015
 
#define OFF_STR_NalDeviceControl            0x991F0
#define OFF_STR_MAPMEM_Mapped               0x99218
#define OFF_STR_LeavingMsIoDispatch         0x99308
#define OFF_STR_LeavingWinIoDispatch        0x99320
#define OFF_STR_NalDriverLoaded             0x99548
 
#define OFF_CpuInit_HvciCheck               0x89CB0
#define OFF_QueryVsmProtection              0x80590
#define OFF_QuerySecureBootPolicy           0x76204
#define OFF_EnumerateProcesses              0x68BC
#define OFF_LBR_MonitorThread               0x88FC8
#define OFF_HvciAdditionalCheck             0x815D4
 
#define OFF_g_LBR_DataBuffer                0xB7A50
#define OFF_g_LBR_RingBuffer1               0xB7FA0
#define OFF_g_LBR_RingBuffer2               0xB7FA8
#define OFF_g_LBR_EntryCount                0xB7FB0
#define OFF_g_HvciNotEnabled                0xB7FB8
#define OFF_g_HvciCheckFailed               0xB7FBC
#define OFF_g_CpuVendor                     0xB7FC8
#define OFF_g_LBR_MsrNumber                 0xA7FE0
#define OFF_g_ProcessorCount1               0xB8020
#define OFF_g_ProcessorCount2               0xB8024
 
#define OFF_QueryVsmProtection_Code         0x80590
#define OFF_QuerySecureBootPolicy_Code      0x76204
#define OFF_HvciAdditionalCheck_Code        0x815D4
 
#define IOCTL_VGK_FUNC_00                   0x22C000
#define IOCTL_VGK_FUNC_01                   0x22C004
#define IOCTL_VGK_FUNC_03                   0x22C00C
#define IOCTL_VGK_FUNC_0A                   0x22C028
#define IOCTL_VGK_FUNC_0B                   0x22C02C
#define IOCTL_VGK_FUNC_13                   0x22C04C
#define IOCTL_VGK_FUNC_14                   0x22C050
#define IOCTL_VGK_FUNC_15                   0x22C054
#define IOCTL_VGK_FUNC_16                   0x22C058
#define IOCTL_VGK_FUNC_17                   0x22C05C
#define IOCTL_VGK_FUNC_18                   0x22C060
#define IOCTL_VGK_FUNC_19                   0x22C064
#define IOCTL_VGK_FUNC_1B                   0x22C06C
#define IOCTL_VGK_FUNC_1D                   0x22C074
#define IOCTL_VGK_FUNC_20                   0x22C080
#define IOCTL_VGK_FUNC_21                   0x22C084
#define IOCTL_VGK_FUNC_24                   0x22C090
#define IOCTL_VGK_FUNC_25                   0x22C094
#define IOCTL_VGK_FUNC_26                   0x22C098
#define IOCTL_VGK_FUNC_27                   0x22C09C
#define IOCTL_VGK_FUNC_28                   0x22C0A0
#define IOCTL_VGK_FUNC_33                   0x22C0CC
#define IOCTL_VGK_FUNC_36                   0x22C0D8
#define IOCTL_VGK_FUNC_37                   0x22C0DC
#define IOCTL_VGK_FUNC_39                   0x22C0E4
#define IOCTL_VGK_FUNC_3A                   0x22C0E8
#define IOCTL_VGK_FUNC_3B                   0x22C0EC
#define IOCTL_VGK_FUNC_3C                   0x22C0F0
#define IOCTL_VGK_FUNC_3D                   0x22C0F4
#define IOCTL_VGK_FUNC_3E                   0x22C0F8
#define IOCTL_VGK_FUNC_3F                   0x22C0FC
#define IOCTL_VGK_FUNC_40                   0x22C100
#define IOCTL_VGK_FUNC_41                   0x22C104
#define IOCTL_VGK_FUNC_42                   0x22C108
#define IOCTL_VGK_FUNC_4A                   0x22C128
#define IOCTL_VGK_FUNC_4B                   0x22C12C
#define IOCTL_VGK_FUNC_4C                   0x22C130
#define IOCTL_VGK_FUNC_4D                   0x22C134
#define IOCTL_VGK_FUNC_4E                   0x22C138
#define IOCTL_VGK_FUNC_50                   0x22C140
#define IOCTL_VGK_FUNC_51                   0x22C144
#define IOCTL_VGK_FUNC_52                   0x22C148
#define IOCTL_VGK_FUNC_53                   0x22C14C
#define IOCTL_VGK_FUNC_54                   0x22C150
#define IOCTL_VGK_FUNC_55                   0x22C154
#define IOCTL_VGK_FUNC_56                   0x22C158
#define IOCTL_VGK_FUNC_57                   0x22C15C
#define IOCTL_VGK_FUNC_58                   0x22C160
#define IOCTL_VGK_FUNC_59                   0x22C164
#define IOCTL_VGK_FUNC_5A                   0x22C168
#define IOCTL_VGK_FUNC_5B                   0x22C16C
#define IOCTL_VGK_FUNC_5C                   0x22C170
#define IOCTL_VGK_FUNC_5D                   0x22C174
#define IOCTL_VGK_FUNC_5E                   0x22C178
#define IOCTL_VGK_FUNC_5F                   0x22C17C
#define IOCTL_VGK_TOTAL_COUNT               55
 
#define OFF_ResolveAllAPIs              0x6F31C
#define OFF_GetProcAddress_Thunk        0x80D88
#define OFF_GetProcAddress_Resolver     0x1EF651
#define OFF_GetProcAddress_ByName       0x7E810
#define OFF_PE_ExportResolver           0x7E5F8
#define OFF_Resolve_ci_dll              0x6E900
#define OFF_Resolve_cng_sys             0x5B5C4
#define OFF_LengthDisassembler          0x615D0
#define OFF_PE_ParseSections            0x7E958
#define OFF_PE_FindSection              0x5E500
#define OFF_PatternScan                 0x81D54
#define OFF_PatternScan2                0x81C64
#define OFF_GetModuleHandle             0x69748
#define OFF_LDE_LookupTable             0xA4000
#define OFF_PatternScan2_Pattern        0x9BA68
#define OFF_PatternScan2_Magic          0x78678E2E
 
#define XOR_KEY1_LOW                    0xD9C46AAA226D66CFULL
#define XOR_KEY1_HIGH                   0x046F7BEB5948D514ULL
#define XOR_KEY2_LOW                    0x679677E08E1B45F1ULL
#define XOR_KEY2_HIGH                   0xF4868CB93E71311EULL
 
#define OFF_OBF_KdDebuggerNotPresent        0xB1AE8
#define OFF_OBF_KdDebuggerEnabled           0xB1B10
#define OFF_OBF_KdEnteredDebugger           0xB1B38
#define OFF_OBF_PsInitialSystemProcess      0xB1B60
#define OFF_OBF_PsProcessType               0xB1B88
#define OFF_OBF_PsThreadType                0xB1BB0
#define OFF_OBF_IoDriverObjectType          0xB1BD8
#define OFF_OBF_MmSectionObjectType         0xB1C00
#define OFF_OBF_MmUserProbeAddress          0xB1C28
#define OFF_OBF_HalPrivateDispatchTable     0xB1C78
#define OFF_OBF_ExCreateCallback            0xB1CA0
#define OFF_OBF_ExQueueWorkItem             0xB1CC8
#define OFF_OBF_IoAllocateWorkItem2         0xB1CF0
#define OFF_OBF_IoFreeWorkItem              0xB1D18
#define OFF_OBF_IoQueueWorkItem             0xB1D40
#define OFF_OBF_KdChangeOption              0xB1D68
#define OFF_OBF_MmIsAddressValid2           0xB1D90
#define OFF_OBF_PsGetProcessDebugPort       0xB1E08
#define OFF_OBF_PsCreateSystemThread2       0xB1E30
#define OFF_OBF_PsTerminateSystemThread     0xB1E58
#define OFF_OBF_PsGetThreadId               0xB1EA8
#define OFF_OBF_PsGetThreadProcess          0xB1ED0
#define OFF_OBF_PsGetThreadProcessId        0xB1EF8
#define OFF_OBF_PsSetCreateProcessNotify    0xB1F20
#define OFF_OBF_CmRegisterCallbackEx2       0xB1F48
#define OFF_OBF_PsSetCreateThreadNotify2    0xB1F70
#define OFF_OBF_PsSetCreateProcessNotifyEx2 0xB1F98
#define OFF_OBF_PsSetLoadImageNotify2       0xB1FC0
#define OFF_OBF_PsRemoveLoadImageNotify2    0xB1FE8
 
#define OPCODE_RET              0xC3
#define OPCODE_NOP              0x90
#define OPCODE_XOR_EAX_EAX_0    0x31
#define OPCODE_XOR_EAX_EAX_1    0xC0
#define OPCODE_INT3             0xCC