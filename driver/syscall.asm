PUBLIC EngCreateBitmapSyscall
PUBLIC NtGdiEngCreateDeviceBitmapSyscall
PUBLIC do_syscall_4

_TEXT SEGMENT


EngCreateBitmapSyscall PROC
    mov r10, rcx
    mov eax, 127Ch
    syscall
    ret
EngCreateBitmapSyscall ENDP


NtGdiEngCreateDeviceBitmapSyscall PROC
    mov r10, rcx
    mov eax, 127Eh
    syscall
    ret
NtGdiEngCreateDeviceBitmapSyscall ENDP


do_syscall_4 PROC
    mov eax, ecx
    mov r11, rdx
    mov rcx, r8
    mov rdx, r9
    mov r8, qword ptr [rsp+28h]
    mov r9, qword ptr [rsp+30h]
    mov r10, rcx
    jmp r11
do_syscall_4 ENDP

_TEXT ENDS

END
