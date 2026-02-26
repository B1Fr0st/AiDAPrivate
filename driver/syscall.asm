; syscall.asm — Indirect syscall stub for x64 Windows.
;
; Prototype (C++):
;   extern "C" NTSTATUS do_syscall_4(
;       uint32_t   syscall_idx,   ; RCX
;       uint8_t*   syscall_addr,  ; RDX  — pointer to a "syscall; ret" gadget in ntdll
;       uint64_t   a1,            ; R8
;       uint64_t   a2,            ; R9
;       uint64_t   a3,            ; [RSP+28h]
;       uint64_t   a4             ; [RSP+30h]
;   );
;
; The Windows syscall ABI expects:
;   EAX  = syscall number
;   R10  = 1st arg  (normally RCX in user-mode)
;   RDX  = 2nd arg
;   R8   = 3rd arg
;   R9   = 4th arg
;
; We shuffle the registers accordingly and JMP to the real
; "syscall; ret" instruction inside ntdll, so the return address
; on the call stack points into ntdll rather than our module.

.code

do_syscall_4 PROC
    ; Save the syscall gadget address before we clobber RDX
    mov     r11, rdx            ; r11 = syscall_addr (gadget)

    ; EAX = syscall index
    mov     eax, ecx            ; eax = syscall_idx

    ; Shuffle arguments into syscall ABI positions:
    ;   R10 = a1  (was R8)
    ;   RDX = a2  (was R9)
    ;   R8  = a3  (was [RSP+28h])
    ;   R9  = a4  (was [RSP+30h])
    mov     r10, r8             ; r10 = a1
    mov     rdx, r9             ; rdx = a2
    mov     r8,  [rsp + 28h]    ; r8  = a3
    mov     r9,  [rsp + 30h]    ; r9  = a4

    ; Jump to the "syscall; ret" gadget inside ntdll.
    ; The RET inside the gadget will return to our caller.
    jmp     r11
do_syscall_4 ENDP

END

