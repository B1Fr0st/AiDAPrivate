

.code

do_syscall_4 PROC

    mov     r11, rdx


    mov     eax, ecx


    mov     r10, r8
    mov     rdx, r9
    mov     r8,  [rsp + 28h]
    mov     r9,  [rsp + 30h]


    jmp     r11
do_syscall_4 ENDP

END
