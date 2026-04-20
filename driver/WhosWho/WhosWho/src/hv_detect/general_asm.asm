.code

__read_rsp proc
    mov rax, rsp
    add rax, 8
    ret
__read_rsp endp

__read_r15 proc
    mov rax, r15
    ret
__read_r15 endp

__read_tr proc
    str rax
    ret
__read_tr endp

__write_tr proc
    ltr cx
    ret
__write_tr endp

__read_cs proc
    mov ax, cs
    movzx rax, ax
    ret
__read_cs endp

__write_cs proc
    push rbx

    mov rbx, ss
    push rbx

    mov rbx, rsp
    add rbx, 8
    push rbx

    pushfq

    movzx rcx, cx
    push rcx

    lea rbx, [continue]
    push rbx

    iretq

continue:
    pop rbx
    ret
__write_cs endp

__read_ds proc
    mov ax, ds
    movzx rax, ax
    ret
__read_ds endp

__write_ds proc
    mov ds, cx
    ret
__write_ds endp

__read_es proc
    mov ax, es
    movzx rax, ax
    ret
__read_es endp

__write_es proc
    mov es, cx
    ret
__write_es endp

__read_ss proc
    mov ax, ss
    movzx rax, ax
    ret
__read_ss endp

__write_ss proc
    mov ss, cx
    ret
__write_ss endp

__read_fs proc
    mov ax, fs
    movzx rax, ax
    ret
__read_fs endp

__write_fs proc
    mov fs, cx
    ret
__write_fs endp

__read_gs proc
    mov ax, gs
    movzx rax, ax
    ret
__read_gs endp

__write_gs proc
    mov gs, cx
    ret
__write_gs endp

_cli proc
    cli
    ret
_cli endp

_sti proc
    sti
    ret
_sti endp

__lock_sidt proc
   db 0F0h
   sidt qword ptr [rcx]
   ret
__lock_sidt endp

__ss_fault_sidt proc
    mov rax, rsp
    mov rsp, 4AAAAAAAA555A555h
    sidt qword ptr [rsp]
    mov rsp, rax
    ret
__ss_fault_sidt endp

__gp_fault_sidt proc
    mov rax, 4AAAAAAAA555A555h
    sidt qword ptr [rax]
    ret
__gp_fault_sidt endp

__lock_lidt proc
   db 0F0h
   lidt fword ptr [rcx]
   ret
__lock_lidt endp

__ss_fault_lidt proc
    mov rax, rsp
    mov rsp, 4AAAAAAAA555A555h
    lidt fword ptr [rsp]
    mov rsp, rax
    ret
__ss_fault_lidt endp

__gp_fault_lidt proc
    mov rax, 4AAAAAAAA555A555h
    lidt fword ptr [rax]
    ret
__gp_fault_lidt endp

__cause_ss proc
    mov rax, rsp
    mov rsp, 4AAAAAAAA555A555h
    mov qword ptr [rsp], rax
    mov rsp, rax
    ret
__cause_ss endp

get_proc_number proc
    push rbx
    push rcx
    push rdx

    xor  eax, eax
    mov  eax, 0Bh
    xor  ecx, ecx
    cpuid

    mov  eax, edx

    pop  rdx
    pop  rcx
    pop rbx

    ret
get_proc_number endp

end
