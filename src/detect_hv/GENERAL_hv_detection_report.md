How anti-cheats detect system emulation
main authors imagedaax, iPower, ajkhoury, drew
Apr 13, 2020
As our first article addressing the various methods of detecting the presence of VMMs, whether commercial or custom, we wanted to be thorough and associate it with our research on popular anti-cheat vendors. To kick off the article it’s important for those outside of the game hacking arena to understand the usage of hypervisors for cheating, and the importance of anti-cheats staying on top of cheat providers using them. This post will cover a few standard detection methods that can be used for both Intel/AMD; offering an explanation, a mitigation, and a general rating of efficacy. We’ll then get into a side-channel attack that can be employed - platform agnostic - that is highly efficient. We’ll then get into some OS specific methods that abuse some mishandling of descriptor table information in WoW64, and ways to block custom methods of syscall hooking like technique documented online.

The more interesting part covers the actual methods used by BattlEye and EasyAntiCheat. We will cover improvements that could be made, and general efficacy of their methods. This is by no means a jab at the anti-cheats as keeping up with the technology and latest ways to abuse the technology is difficult. They perform their job pretty well, and like any software have holes. This is intended to help those interested in understanding how both sides operate, and the various ways attackers/defenders can defeat/employ virtualization detections. We’ll conclude the article with some dumps of miscellaneous data from NtDeviceIoControlFile/IofCallDriver calls in the two anti-cheats. This isn’t related to hypervisors, but we figured while we investigated - why not?

Let’s dig in.

Hypervisor Prevalence
The advent of hypervisors (VMM) brought with it a lot of hype in the security research community. This hype also spurred interest in some not-so-research based circles like cheating/malware communities where the end goal was to use a hypervisor to emulate system behavior/hide presence. Various new technologies like EPT allowed attackers to abuse certain features like EPTP switching or page hooks to hide information from probes of security software. As this technology gained popularity, many open-source projects were released to help the security community understand how to go about developing tools leveraging it. This also meant that questionable communities looking to conceal themselves began using these open-source projects, and one of those was the game hacking community.

The main benefit for anti-cheats was that many pay-to-cheat providers began using slightly modified open-source versions of the tools. These open-source tools were meant for educational purposes and weren’t hardened against the many attacks that could reveal their presence. Anti-cheats use this lack of induration to detect hackers using custom/open-source projects and attempt to cull the herd. However, in recent times, as research on the technologies improves and becomes more widespread the original detection vectors are becoming less effective.

Knowing this, we will look at methods of detecting if a hypervisor is currently running on a machine. There are many detection vectors, and we wanted to detail a handful of techniques ranging from ineffective to super effective. The cat-and-mouse game will continue, but it should require more innovation on the opposing side. It’s our opinion that anti-cheats have stagnated in this arena, and we want to provide more information on why we feel that way.

Standard Detection Methods
This section is going to cover some platform specific methods of detecting hypervisors. The majority of open-source hypervisors are built for use on Intel processors, so there will be more vectors covered. Many of the methods can be applied to AMD as well, despite it being supported less by anti-cheats and cheat providers.

Garbage Write to unimplemented MSR
Both Intel and AMD support the use of a bitmap referred to as the MSR bitmap/MSR permissions bitmap, respectively. This bitmap allows the VMM to control whether rdmsr of the specific MSR causes a VM-exit. This bitmap only covers a specific range of MSR values from 0000-1FFF and C0000000-C0001FFF. This means that any reads/writes to MSRs outside of that range could have undefined behavior when VMX/SVM is enabled.

One way that security software, be it anti-cheat or anti-malware, could leverage this information is to check whether an MSR access to an MSR outside of the range causes an exception to be generated. If a write is performed on real hardware to an unimplemented/reserved MSR address the processor will generate a general-protection exception. However, some open-source hypervisors do not discard writes to invalid/unimplemented MSRs and will write through, causing the system instability. In order to mitigate this, rdmsr performed on an unimplemented/reserved MSR address should inject #GP to the guest.

This is not a very effective method of detection, in any case.

Debug Exception (#DB) w/ TF
A common method of determining if a specific open-source hypervisor is used is to check if the #DB exception is delivered on the proper instruction boundary when executing an exiting instruction with the EFLAGS.TF set. This occurs when single-step debug exceptions are not properly handled. A simple method of detection is to create a detection routine similar to this:

pushfq
or dword ptr [rsp], 0100h
mov eax, 0FFFFFFFFh
popfq
<exiting_inst>
nop
ret
Detecting this particular platform requires the use of VEH to check RIP and determine if the single-step trap flag is set. Prior to executing the detection procedure that will trigger the exception we’ll need to modify the debug registers, and then set the thread context. It’s important to remember that you need to preserve modification of the debug registers in the ContextFlags and enable the proper bit so that the breakpoint condition is set for all tasks.

Once the breakpoint is detected and is associated with the proper DR7 flag, a debug exception is generated. The processor doesn’t clear these flags on task switch which allows for the breakpoint to apply to all tasks.

When the exception is delivered, our exception handler we registered will check RIP and determine if #DB was delivered on the correct instruction. On real hardware, the exception will be delivered on the <exiting_inst> whereas when in a virtualized environment with this oversight it will be delivered on nop.

This method is effective at detecting the specific open-source platform, and mitigation is already documented on a members blog located here. However, despite the publication it’s still present in many cheat providers.

XSETBV
The interesting part of the XSETBV instruction is that it is one of the few instructions that cause VM exits unconditionally. We can leverage this attribute of the XSETBV instruction to detect hypervisor presence.

This method of detecting hypervisor presence relies on causing an exception in the host XSETBV VM-exit handler. Since most known private and public mini hypervisor implementations blindly execute the XSETBV instruction in the host XSETBV handler, if we execute XSETBV in a way that the guest state should cause a fault, we can cause the host to fault under these naïve hypervisor implementations.

First, we must determine under which conditions XSETBV will cause a fault.



With this we see there are several ways to force a general-protection fault (#GP). This documentation tells us that bit 0 must always be set, and that executing the instruction with ECX = 0 and EAX[0] = 0 will cause a #GP. Here’s an example of how we can cause a fault in the host:

UINT64 XCR0 = _xgetbv(0);

__try {

    //
    // Clear the bit 0 of XCR0 to cause a #GP(0)!
    //
    _xsetbv(0, XCR0 & ~1);

} __except(EXCEPTION_EXECUTE_HANDLER) {

    //
    // If we get here, the host has properly handled XSETBV and injected a
    // #GP(0) into the guest.
    //
    LOG_DEBUG("1337!");
}
Running under a naïve hypervisor implementation which handle XSETBV as such, caused the host to fault, resulting in a bugcheck. This is what we wanted! The naïve hypervisor implementation for handling this instruction would look like this:

VMM_EVENT_STATUS HVAPI VmmHandleXsetbv(PVIRTUAL_CPU VirtualCpu)
{
    UINT32 Xcr;
    ULARGE_INTEGER XcrValue;

    Xcr = (UINT32)VirtualCpu->Context->Rcx;
    XcrValue.u.LowPart = (UINT32)VirtualCpu->Context->Rax;
    XcrValue.u.HighPart = (UINT32)VirtualCpu->Context->Rdx;

    //
    // Blindly execute XSETBV with whatever the guest gives us, because we
    // trust our guest :)
    //
    _xsetbv(Xcr, XcrValue.QuadPart);

    return VMM_HANDLED_ADVANCE_RIP;
}
You might be wondering - is it safe to cause a bugcheck like this? Well, no. A properly written hypervisor implementation will not cause a bugcheck when making use of SEH - but most hypervisors used for cheating purposes are unable to use SEH when their driver is mapped into the kernel by exploiting some third-party driver. There are ways to achieve SEH in an unsigned driver, but this is out of the scope of the article. Running on bare metal or under a hypervisor with proper XSETBV emulation will simply output 1337!.

Other than annoying your users, how can this be used as a reliable detection vector? Registering a bugcheck callback! This is a handy way to execute code after a bugcheck has occurred, and manipulate data written to the crash dump. The logic is as follows:

Register bugcheck callback.
Save a magic number and GUID as part of the dump.
Parse dump on next boot.
This is a lot of work, so here is a small piece of the work needing to be done:

KBUGCHECK_REASON_CALLBACK_RECORD BugCheckCallbackRecord = {0};
BOOLEAN BugCheckCallbackRegistered = FALSE;
static const UINT64 MagicNumber = 0x1337133713371337;
// b4911b81-7b73-4f2b-afcc-3b7ce3e1480c
static const GUID MagicDriverGuid = {0xb4911b81, 0x7b73, 0x4f2b, {0xaf, 0xcc, 0x3b, 0x7c, 0xe3, 0xe1, 0x48, 0x0c} };

VOID BugCheckCallbackRoutine(KBUGCHECK_CALLBACK_REASON Reason, struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record, PVOID ReasonSpecificData, UINT32 ReasonSpecificDataLength)
{
    PKBUGCHECK_SECONDARY_DUMP_DATA SecondaryDumpData;
    SecondaryDumpData = (PKBUGCHECK_SECONDARY_DUMP_DATA)ReasonSpecificData;
    SecondaryDumpData->Guid = MagicDriverGuid;
    SecondaryDumpData->OutBuffer = (PVOID)&MagicNumber;
    SecondaryDumpData->OutBufferLength = sizeof(MagicNumber);
}

//
// ...
//

KeInitializeCallbackRecord(&BugCheckCallbackRecord);
BugCheckCallbackRegistered = KeRegisterBugCheckReasonCallback(&BugCheckCallbackRecord, BugCheckCallbackRoutine, KbCallbackSecondaryDumpData, (PUINT8)"secret.club");

if (!BugCheckCallbackRegistered) {
    return STATUS_UNSUCCESSFUL;
}
Mitigating this type of detection is time consuming, but important. The best rule to follow: Read the SDM/APM for the architecture. Here is an example of a properly implemented XSETBV VM-exit handler:

static BOOLEAN VmmpIsValidXcr0(UINT64 Xcr0)
{
    // FP must be unconditionally set.
    if (!(Xcr0 & X86_XCR0_FP)) {
        return FALSE;
    }

    // YMM depends on SSE.
    if ((Xcr0 & X86_XCR0_YMM) && !(Xcr0 & X86_XCR0_SSE)) {
        return FALSE;
    }

    // BNDREGS and BNDCSR must be the same.
    if ((!(Xcr0 & X86_XCR0_BNDREGS)) != (!(Xcr0 & X86_XCR0_BNDCSR))) {
        return FALSE;
    }

    // Validate AVX512 xsave feature bits.
    if (Xcr0 & X86_XSTATE_MASK_AVX512) {

        // OPMASK, ZMM, and HI_ZMM require YMM.
        if (!(Xcr0 & X86_XCR0_YMM)) {
            return FALSE;
        }

        // OPMASK, ZMM, and HI_ZMM must be the same.
        if (~Xcr0 & (X86_XCR0_OPMASK | X86_XCR0_ZMM | X86_XCR0_HI_ZMM)) {
            return FALSE;
        }
    }

    // XCR0 feature bits are valid!
    return TRUE;
}

VMM_EVENT_STATUS HVAPI VmmHandleXsetbv(PVIRTUAL_CPU VirtualCpu)
{
    UINT32 Xcr;
    ULARGE_INTEGER XcrValue;

    Xcr = (UINT32)VirtualCpu->Context->Rcx;

    // Make sure the guest is not trying to write to a bogus XCR.
    //
    switch(Xcr) {
    case X86_XCR_XFEATURE_ENABLED_MASK:
        break;

    default:
        HV_DBG_BREAK();
    GPFault:
        VmxInjectGP(VirtualCpu, 0);
        return VMM_NOT_HANDLED;
    }

    XcrValue.u.LowPart = (UINT32)VirtualCpu->Context->Rax;
    XcrValue.u.HighPart = (UINT32)VirtualCpu->Context->Rdx;

    // Make sure the guest is not trying to set any unsupported bits.
    //
    if (XcrValue.QuadPart & ~GetSupportedXcr0Bits()) {
        HV_DBG_BREAK();
        goto GPFault;
    }

    // Make sure bits being set are architecturally valid.
    //
    if (!VmmpIsValidXcr0(XcrValue.QuadPart)) {
        HV_DBG_BREAK();
        goto GPFault;
    }

    // By this point, the XCR value should be accepted by hardware.
    //
    _xsetbv(Xcr, XcrValue.QuadPart);

    return VMM_HANDLED_ADVANCE_RIP;
}
LBR Virtualization
Tracing interrupts, messages, branches, and such is a very useful feature implemented on Intel hardware through the IA32_DEBUGCTL MSR. In particular, some hypervisors take advantage of last branch recording (LBR) and branch tracing to track down branches in obfuscated products such as anti-cheats. Since some anti-cheat products spoof return addresses one can utilize LBR/BTS to trace the exact location where a branch occurred.

This was noticed in quite a few anti-cheats for private CS:GO leagues. Below is a brief sample of what this detection may look like:

    mov rcx, 01D9h
    xor rdx, rdx
    wrmsr
    rdmsr
    shl rdx, 20h	; EDX:EAX for wrmsr
    or rax, rdx
    jmp check_msr

check_msr:
    test al, 1
    jnz no_detect
    mov al, 1
    ret
    
no_detect:
    xor rax, rax
    xor rdx, rdx
    mov rdx, 01D9h
    wrmsr
    ret
This would roughly translate to:

__writemsr(IA32_DEBUGCTL, DEBUGCTL_LBR | DEBUGCTL_BTS);
res = __readmsr(IA32_DEBUGCTL);

if(!(res & DEBUGCTL_LBR))
    return 1;

return 0;
More importantly there would be checks for potential exceptions that could be thrown. This has been seen in various league anti-cheats for CS:GO, and is quite effective at determining if LBR/BTS virtualization is used.

So, how would someone mitigate this check? The answer is just by injecting a #GP into the guest, which is what real hardware will do when LBR/BTS isn’t supported.

LBR Stack Checks
In addition to the above check, an anti-cheat could implement a detection based on the usage of saved/loaded LBR information between VMX transitions. Since many open-source projects don’t handle store/load of LBR information appropriately an anti-cheat could force a VM-exit through use of an unconditionally exiting instruction like CPUID. After the execution, they would need to check the last branch taken from the LBR stack after resuming guest operation. If the target address doesn’t match the expected value it would mean that some introspective engine is present.

// Save current LBR top of stack
auto last_branch_taken_pre = __read_lbr_tos();

// Force VM-exit with CPUID
__cpuid(0, &regs);

// Save post VM-exit LBR top of stack
auto last_branch_taken_post = __read_lbr_tos();

// Compare last branch taken
if(last_branch_taken_pre != last_branch_taken_post)
    return TRUE;
This would be quite effective at catching hypervisors leveraging LBR but not properly handling the storage of LBR information. The LBR stack consists of pairs of MSRs that store the last branch source and target addresses. There are 8 MSRs associated with these listed below.

// Last Branch Source Addresses
MSR_LASTBRANCH_0_FROM_IP
MSR_LASTBRANCH_N-1_FROM_IP
    
// Last Branch Target Addresses
MSR_LASTBRANCH_0_TO_IP
MSR_LASTBRANCH_N-1_TO_IP
And the MSR_LASTBRANCH_TOS which is the MSR containing the LBR top of stack pointer. With this and knowledge of the VM-exit/VM-entry MSR-store areas documented in the Intel SDM we can save the LBR stack and top of stack when a VM-exit is encountered, then restore them on VM-entry to the guest. The LBR stack size can be determined from this table:

intel_sdm_lbr

The hypervisor would need to have an area allocated where you would then store the values of the LBR stack information, and then write the load/store count and address to the respective VMCS fields:VMCS_VM_EXIT_MSR_(LOAD/STORE)_COUNT and VMCS_VM_EXIT_MSR_(LOAD/STORE)_ADDRESS. This will successfully prevent LBR stack checks from catching the VMM.

Synthetic MSRs
Synthetic MSRs are commonly used by hypervisor platforms to report information to the guest about the host. Hyper-V, VMware, and VirtualBox are examples of commercial hypervisors that implement Synthetic MSRs. You will commonly see them implemented in the range 40000000h - 400000FFh, as this range is marked as a reserved range. It’s documented that future processors will never use this range for any features.

There are also some MSRs that are not implemented in current processors on the market, however, they have a valid MSR address. When queried using rdmsr the platform will typically generate a general protection exception (#GP). However, when in a virtualized environment a read to an unimplemented address could yield undefined results. As an example would be reading from MSR addresses 2 to 5, on VMware, will provide random data and not generate an exception.

Probes to the reserved range mentioned above and any unimplemented MSR addresses could be used to determine if the current system is virtualized. To combat this the hypervisor should force any accesses to the reserved or unimplemented MSRs to inject a #GP into the guest. A simple detection would look something like this:

BOOLEAN KiSyntheticMsrCheck(VOID)
{

#define HV_SYNTHETIC_MSR_RANGE_START 0x40000000
    
    __try
    {
        __readmsr( HV_SYNTHETIC_MSR_RANGE_START );
    } 
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    
    return TRUE;
}
The check is useful for determining if a commercial hypervisor is being used since most investigated implement an MSR in this range.

CRn Access Exiting
Hypervisors that improperly handle control register access exits are at risk of being detected much like the bug discovered in VMware by a member of ours, drew. It was determined that the VMware hypervisor was not properly emulating processor behavior. He’s already done the honors of writing about it, and the use cases for detecting and methods of mitigation are proposed on his blog.

CRn Access Exiting | VMware Bug

CRn Mask & VMX Availability
For each position corresponding to a bit clear in the CRx guest/host mask, the destination operand is loaded with the value of the corresponding bit in CRx. For each position corresponding to a bit set in the CRx guest/host mask, the destination operand is loaded with the value of the corresponding bit in the CRx read shadow. Thus, if every bit is cleared in the CRx guest/host mask, MOV from CRx reads normally from CRx; if every bit is set in the CRx guest/host mask, MOV from CRx returns the value of the CRx read shadow.

TL;DR: Where a bit is set in the guest/host mask, the shadow bit appears. Where a bit is not in the guest/host mask, the actual bit appears. A VM-exit occurs when a guest attempts to modify any of the bits set in the guest/host mask.

Based on this, hypervisors may set the CR4.VMXE bit to 0 in the CR4 read shadow while having the guest/host mask for CR4 set that bit to 1. This would mean that if a guest were to read the value of that bit they would get 0. However, the bug that can be exploited on some platforms is that they signal VMXE being disabled, but VMX instructions still execute. That’s not possible, and is a blatant indication that virtualization is being used.

The fix for this would be to inject an undefined opcode exception (#UD) into the guest on execution of a VMX instruction if you intend to mask off the VMXE bit. Some public platforms inject #GP(0) to the guest for execution of VMX instructions as opposed to #UD which is the proper exception. This is also indicative of presence.

CPUID Leaf Comparisons
A quick method similar to the reserved MSR address ranges is the check reserved CPUID responses against what their values would normally be. As an example, the leaf 40000000h is a CPUID leaf marked reserved by the architecture and is most commonly used for reporting capabilities of a VMM. There are two options which is to check against an invalid leaf or a leaf that returns the same data. Two examples are below.

This first example displays using an invalid CPUID leaf to determine if the system is virtualized.

UINT64 UmpIsSystemVirtualized(void)
{
    unsigned int invalid_leaf = 0x13371337;
    unsigned int valid_leaf = 0x40000000;
    
    struct _HV_DETAILS
    {
        unsigned int Data[4];
    };
    
    _HV_DETAILS InvalidLeafResponse = { 0 };
    _HV_DETAILS ValidLeafResponse = { 0 };
  
    __cpuid( &InvalidLeafResponse, invalid_leaf );
    __cpuid( &ValidLeafResponse, valid_leaf );
  
    if( ( InvalidLeafResponse.Data[ 0 ] != ValidLeafResponse.Data[ 0 ] ) || 
        ( InvalidLeafResponse.Data[ 1 ] != ValidLeafResponse.Data[ 1 ] ) || 
        ( InvalidLeafResponse.Data[ 2 ] != ValidLeafResponse.Data[ 2 ] ) || 
        ( InvalidLeafResponse.Data[ 3 ] != ValidLeafResponse.Data[ 3 ] ) )
        return STATUS_HV_DETECTED;
    
    return STATUS_HV_NOT_PRESENT;
}
This second example uses the highest low function leaf to compare data to what would be given on a real system.

UINT64 UmpIsSystemVirtualized2(void)
{
    cpuid_buffer_t regs;
    __cpuid((int32_t*)&regs, 0x40000000);

    cpuid_buffer_t reserved_regs;
    __cpuid((int32_t*)&reserved_regs, 0);
    __cpuid((int32_t*)&reserved_regs, reserved_regs.eax);

    if (reserved_regs.eax != regs.eax || 
        reserved_regs.ebx != regs.ebx || 
        reserved_regs.ecx != regs.ecx || 
        reserved_regs.edx != regs.edx)
            return STATUS_HV_DETECTED;
            
    return STATUS_HV_NOT_PRESENT;
}
Advanced Detection Methods
This section will cover a advanced detection methods that, while reliable, can be much more difficult to implement and some may require further inspection of results after execution. The cache side-channel attacks are very different. One of the cache side-channels that can be used is super simple, but quite effective. We’ll also cover the standard timing attacks and their flaws prior to addressing the anti-cheat methods discovered.

INVD/WBINVD
This method is used to determine if the hypervisor emulates the INVD instruction properly. As is expected, many public platforms do not emulate the instruction appropriately leaving a detection vector wide open. This method was supplied by a member of ours, drew, who uses it and corroborates its effectiveness.

pushfq
cli
push 1                 ; Set cache data
wbinvd                 ; Flush writeback data set from previous instruction to system memory.
mov byte ptr [rsp], 0  ; Set memory to 0. This is in WB memory so it will not be in system memory.
invd                   ; Flush the caches but do not write back to system memory. Real hardware will result in loss of previous operation.
pop rax                ; Proper system behaviour will have AL = 1; Hypervisor/emulator that uses WBINVD or does nothing will have AL = 0.
popfq
ret
The subtle behaviors of a real system should be emulated properly to avoid this type of detection. It’s present on a handful of open-source hypervisor platforms. As an exercise to the reader, try to determine how to mitigate this side-channel.

There are many other cache side-channels; the most common is gathering statistics on cache misses and locating conflicting cache sets. These can be hit or miss depending on implementation and require lots of testing prior to implementation to ensure very few, if any, false positives. These types of solutions require making sure that the prefetcher is unable to determine cache usage by randomizing cache set accesses and ensuring that new reads from a cache set are correct in terms of how many lines are read, whether the valid cache lines were probed properly, and so on. It’s a very involved process, so we didn’t plan on including the implementation of such a check in this article.

The above method is example is enough to be validated, and we encourage you to validate it as well! Be aware that this can cause #GP(0) if SGX is used.

RDTSC/CPUID/RDTSC
If you’ve done performance profiling, or worked on sandbox detection for anti-malware (or more questionable purposes), you’ve likely used or encountered this sort of timing check. There’s plenty of literature covering the details of this attack, and in most cases it’s relatively effective. However, hypervisor developers are becoming more clever and have devised methods of reducing the time discrepancies to a very low margin.

This timing attack used to determine if a system is virtualized or not is common in anti-cheats as a baseline detection vector. It’s also used by malware to determine if it is sandboxed. In terms of effectiveness, we’d say it’s very effective. The solution, while somewhat confusing, passes the pafish checks and anti-cheat checks. We won’t be divulging any code, but let’s briefly go over the logic.

We know that timing attacks query the timestamp counter twice, either by direct use of the IA32_TIMESTAMP_COUNTER MSR or the intrinsic __rdtsc. Typically there will be instructions in between. Those instructions will cause VM-exits, typically, so the idea is to emulate the cycle count yourself - adding to an emulated cycle counter. You could use a disassembler, add an average, or devise a method that’s much more accurate. Trace from the first rdtsc instruction to the second, add an average cycle count to the emulated counter. No TSC offsetting, or other feature is utilized - though you can, for example, take advantage of the MTF. You will also need to determine an average number of cycles the VM transitions take and subtract that from the emulated counter. The typical average is between 1.2k - 2k cycles on modern processors.

Successfully implementing the solution, while not perfect, yields better results than the majority of tested solutions presented in literature and passes the virtualization checks devised. It’s important when attempting to implement the solution to not get bogged down with unnecessary details like SMIs, or how to synchronize (you do have to have a counter that is invariant across logical processors though). Keep it simple, silly.

IET Divergence
As an opposition to the standard timing attack we offer a more novel approach that doesn’t rely on the timestamp counter and requires much more effort to spoof. It has been briefly mentioned in a post here, and we decided to go into a little more detail.

IET divergence is the measurement and comparison of instruction execution time (IET) using two different instructions. Similar to the rdtsc;cpuid;rdtsc combination, IET divergence test uses a counter to profile two instructions, calculate the average execution time, and then compare the two instructions’ results. This detection method uses the actual performance counter accessed through IA32_APERF MSR instead of the timestamp counter. As discussed before the TSC can be emulated with relative ease, and poses a threat to standard detection methods. Spoofing the APERF counter is much more difficult and isn’t as simple as forcing a VM-exit on the APERF MSR and performing similar operations as the TSC emulation.

The test works like this:

Disable interrupts.
Setup registers for profiling loop.
Capture a starting clock count for an instruction (cpuid).
Execute with the same leaf every time, and capture end clock count.
Calculate the difference in clock count for that loop.
Store result in CPUID_IET array.
Repeat for second candidate instruction.
Repeat loop N times for a more refined timing profile.
Choosing the instructions is the most difficult part to this check as you will need to use an unconditionally exiting instruction to ensure that if a VMM is present the processor traps into it. The ideal candidate would be cpuid, but the second instruction must be chosen with care. It’s average IET must be longer than cpuid on real hardware, otherwise the check is pointless. The whole point is to compare the execution times of one instruction to an instruction that takes longer on real systems, because in a virtual environment cpuid will consume a lot of cycles before completing. The candidate instruction should take longer than the profiling target, not be a an instruction that could be trapped by the hypervisor, and can be setup relatively easily.

The IET divergence test is used by some anti-cheats as a counter to the more advanced hypervisors used for cheating. A sample implementation is shown below.

cli
xor     r8d, r8d
mov     ecx, IA32_APERF_MSR
rdmsr
shl     rdx, 20h
or      rax, rdx
mov     r9, rax
lea     rsi, [rsp+20h]
xor     eax, eax
cpuid
mov     [rsi], eax
mov     [rsi+4], ebx
mov     [rsi+8], ecx
mov     [rsi+0Ch], edx
mov     ecx, IA32_APERF_MSR
rdmsr
shl     rdx, 20h
or      rax, rdx
mov     rdx, [rsp+30h]
sub     rax, r9
mov     [rdx+r8*8], rax

;
; TODO:
; 	Capture comparable instruction IET.
; 	Store result.
; 	Loop. Break at end.
; 	Enable interrupts.
; 	End profile.
;
This is an incomplete implementation and the steps would need to be repeated for the second instruction that executes longer than cpuid. The choosing of the second instruction is important to getting clear results. That being said, the effectiveness of this detection method is quite remarkable as it will catch even the most well hardened hypervisors. If you have a platform and are interested in researching the products that use this we encourage you to exit on APERF accesses and give some of the private anti-cheats a look.

WoW64 Descriptor Table
This is a detail that is missed by most publicly available mini hypervisors, although one of them, hvpp, properly handles this common oversight. As we already know WoW64 runs code in compatibility mode to support execution of 32-bit x86 (i686) code. Although WoW64 itself runs code in compatibility mode, a hypervisor will still execute natively as x64 code. This can be confusing when a hypervisor is configured to trap on GDT/IDT accesses since a real processor will only write 6 bytes to a descriptor table register when running in compatibility mode, rather than 10 bytes when running in long mode. Not handling this correctly is a common mistake that makes for an easy detection.

Let’s brain on how we can detect this. First thing we need is to be running in compatibility mode at CPL 0. This needs to be done at CPL 0 since Windows makes use of the User-Mode Instruction Prevention (UMIP) x86 security feature. We can temporarily drop into protected mode ourselves very briefly from Ring-0. This is a lot of work, but it’s the way to implement this detection.

Alternatively, it is theoretically possible that one could synchronize WoW64 user mode code to execute a SIDT/SGDT instruction after a kernel thread has temporarily disabled CR4.UMIP.

If you figured out how to get into compatibility/protected mode, here is the juicy detection itself:

UINT8 Descriptor[10];
*(UINT32 *)&Descriptor[6] = 0x13371337;
__sgdt(Descriptor);
if (*(UINT32 *)&Descriptor[6] != 0x13371337) {
    // Gotcha!
}
It works by checking if the hypervisor has accidentally written 4 extra bytes to our descriptor memory. It really is that simple! The mitigation is relatively trivial and requires that the VMM check if the current segment is a long mode segment, and write the proper length.

This is what mitigation for SIDT would look like. We’ll leave the mitigation for SGDT up to the reader.

VmcsReadGuestGdtEntry(X86_REG_CS, &SegmentDesc);

switch (InstructionInfo.Bits.InstructionIdentity) {
	case VMX_GDT_IDT_IDENTITY_SIDT:
		Descriptor->Limit = (u16)VmcsRead32(VMCS_GUEST_IDTR_LIMIT);
		if (SegmentDesc.Bits.L) {
			__writeqword((u64*)((UINTN)Descriptor + FIELD_OFFSET(X86_DESCRIPTOR, Base.UInt64)), (u64)VmcsRead(VMCS_GUEST_IDTR_BASE));
		} else {
			__writedword((u32*)((UINTN)Descriptor + FIELD_OFFSET(X86_DESCRIPTOR, Base.UInt32)),(u32)VmcsRead(VMCS_GUEST_IDTR_BASE));
		}
		break;
Anti-Cheat HV Detection
Documented below are the methods that BattlEye and EAC employ to detect virtualized systems. Our research began with trapping on all various MSRs: VMX MSRs, EFER, Feature Control, APERF, MPERF, DEBUGCTL, and LSTAR. We also trapped on execution of VMX/SVM instructions, and traced back all executions of RDTSC and CPUID. The results were somewhat disappointing.

BattlEye Procedures
RDTSC/CPUID/RDTSC
The method that BattlEye employs is the standard timing attack using the rdtsc;cpuid;rdtsc combination. They’ve moderately improved the code since the article posted on a members blog, and moved the check to the kernel; it still exists nonetheless. No other checks are made currently. We expect with the rolling out of new technology will also yield more attention to hypervisors.

This new component they’ve begun mapping into the kernel is still under investigation.

EasyAntiCheat Procedures
VMREAD
Currently EAC performs a single vmread upon driver initialization.



They properly wrap this in an exception handler which is an improvement from some of the methods documented before.



Unfortunately, the method around this is simple but if this works for them it seems that some platform is not denying access to vmread at CPL 0. The solution is to inject #UD to the guest when the VMM traps on vmread. We didn’t notice any accesses to CR4 or the MSRs we checked other than LSTAR, which wasn’t related to an LSTAR hook by a VMM.

It looks like a provider may have disabled PatchGuard, modified LSTAR, and they added the LSTAR check to catch it.

RDTSC/CPUID/RDTSC
EasyAntiCheat also uses the standard timing attack leaving them subject to being circumvented through proper TSC emulation (described in an earlier subsection).



Overall, these virtualization checks are lacking and relatively simple to circumvent. Other anti-cheats like ESEA, FACEIT, B5, and eSportal employ more aggressive checks that net them greater effectiveness with catching hypervisor based cheats. We expect that the anti-cheats supporting the majority of games will begin to take this into consideration as the popularity of hypervisors increases.

IA32_EFER
It came to our attention that EAC, after ~30 minutes of gameplay, queried IA32_EFER. We waited for a bit longer to see if any more reads/writes to MSRs came through, but after 40 minutes of sitting and waiting it was clear nothing else was coming. Below is the notification received in iPower’s tracer.



It’s clear that the code executing this read is in some virtualized section of code. Upon analysis this is confirmed.



We also confirmed that the bit it is checking is the syscall enable bit (SCE) in IA32_EFER. It checks this bit due to the release of the syscall hooking method using EFER. Without deobfuscating more of the code we believe it’s safe to assume this is the only bit it’s checking due to it’s relevance. Mitigation for this involves setting the bit corresponding to IA32_EFER in the MSR bitmap(s) and utilize the load/save space for IA32_EFER in the VMCS.

IofCallDriver/NtDeviceIoControlFile
Out of curiosity, we decided to take a look at BE and EACs calls to NtDeviceIoControlFile and IofCallDriver. We noticed an IofCallDriverWrapper in EAC, and that both anti-cheats use IofCallDriver in various places.

NTSTATUS __fastcall IofCallDriverWrapper(__int64 IoctlCode, _DEVICE_OBJECT *DeviceObject, void *InputBuffer, ULONG InputBufferLength, void *OutputBuffer, ULONG OutputBufferLength);
EAC uses IofCallDriver to query storage properties of the disk. This likely to gather information like the serial number, name, etc for hardware fingerprinting purposes.

if ( IofCallDriverWrapper(0x2D1400i64, DeviceObject, &InputBuffer, 0xCu, &StorageDescriptorHeader, 8u) < 0 )
  return v3;
  
if ( StorageDescriptorHeader.Size <= 0x28 )
  return v3;
  
pbuf = (PSTORAGE_DEVICE_DESCRIPTOR)alloc_memory(StorageDescriptorHeader.Size);
pbuf_1 = pbuf;

if ( !pbuf )
  return v3;
  
memset(pbuf, 0, StorageDescriptorHeader.Size);

*(_DWORD *)InputBuffer.AdditionalParameters = 0;

InputBuffer.QueryType = 0;
InputBuffer.PropertyId = 0;
if (IofCallDriverWrapper(0x2D1400i64, Device_Disk_Sys, &InputBuffer, 0xCu, pbuf_1, StorageDescriptorHeader.Size) >= 0)
{
    // ...
}
memset(&InputBuffer, 0, 0x21ui64);
v20 = -20;
if (IofCallDriver_ioctl(0x7C088i64, v5, &InputBuffer, 0x21u, OutputBuffer, 0x211u) >= 0)
{
    // ...
} 
EAC and BE also use NtDeviceIoControlFile to query NDIS driver with IOCTL_NDIS_QUERY_GLOBAL_STATS and OID of OID_802_3_PERMANENT_ADDRESS. This is used to acquire the MAC address of the system, also for hardware fingerprinting purposes.

if ( ZwCreateFile(&FileHandle, 0x120089u, &ObjectAttributes, &IoStatusBlock, 0i64, 0x80u, 7u, 1u, 0x20u, 0i64, 0) >= 0 )
   {
        current_thread = __readgsqword(0x188u);
        FileHandle_1 = FileHandle;
        old_previous_mode = GetPreviousMode(current_thread);
        SetPreviousMode(current_thread, 0);
        if ( NtDeviceIoControlFile )
        {
          OutputBufferLength = 6;
          InputBufferLength = 4;
          IoctlCode = 0x170002;
          status = NtDeviceIoControlFile(
                     FileHandle_1,
                     0i64,
                     0i64,
                     0i64,
                     &IoStatusBlock,
                     IoctlCode,
                     &InputBuffer,
                     InputBufferLength,
                     &OutputBuffer,
                     OutputBufferLength);
        }
  // ...
  }
This may or may not be a complete list of the queries made for the purposes of hardware fingerprinting, as we hadn’t dug much further. They could be directly obtaining from the SSDT and calling directly, or using other means to call these functions indirectly. We plan to do a more in-depth analysis of their hardware fingerprinting in a future article - this was just a quick dump out of curiosity when hooking NtDeviceIoControlFile and IofCallDriver.

Conclusion
In this article, we’ve covered a lot of different detection methods for hypervisors that can be employed; some effective, others not-so-much. We also detailed some methods of circumventing the documented detection vectors, but much of the actual implementation will be up to the reader. This was not intended to be a piece providing complete solutions to every method of detection (and there’s far too many even for this article). However, we wanted to document the most commonly used methods, regardless of stability.

We also took an brief look at EAC and BE’s virtualization checks which were somewhat disappointing given the growing popularity of using open-source hypervisor platforms for cheating. We’ve provided circumvention methods for their checks, and plan to release a complete, and refined solution for TSC emulation in the future. However, if the reader is not keen on waiting we provided a logical walkthrough of how to implement it. In future articles covering these two particular anti-cheats we plan to dig deeper into their hardware fingerprinting, reporting, and detection procedures.