

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


aida_read_ssp PROC
    xor     rax, rax
    db      0F3h, 048h, 00Fh, 01Eh, 0C8h
    ret
aida_read_ssp ENDP

END
