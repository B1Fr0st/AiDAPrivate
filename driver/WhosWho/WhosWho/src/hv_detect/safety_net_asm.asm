.data

dummy_error_code                   dq 0h

divide_error_vector                dq 00h
debug_vector                       dq 01h
nmi_vector                         dq 02h
breakpoint_vector                  dq 03h
overflow_vector                    dq 04h
bound_range_exceeded_vector        dq 05h
invalid_opcode_vector              dq 06h
device_not_available_vector        dq 07h
double_fault_vector                dq 08h
invalid_tss_vector                 dq 0Ah
segment_not_present_vector         dq 0Bh
stack_segment_fault_vector         dq 0Ch
general_protection_vector          dq 0Dh
page_fault_vector                  dq 0Eh
x87_floating_point_error_vector    dq 10h
alignment_check_vector             dq 11h
machine_check_vector               dq 12h
simd_floating_point_error_vector   dq 13h
virtualization_exception_vector    dq 14h
control_protection_vector          dq 15h

extern exception_handler:proc

.code

save_general_regs macro
    push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
endm

restore_general_regs macro
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
endm

asm_core_handler proc
	save_general_regs

	mov rcx, rsp
	sub rsp, 20h
	call exception_handler
	add rsp, 20h

	restore_general_regs
	add rsp, 8
	add rsp, 8

	iretq
asm_core_handler endp

asm_de_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [divide_error_vector]
    jmp asm_core_handler
asm_de_handler endp

asm_db_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [debug_vector]
    jmp asm_core_handler
asm_db_handler endp

asm_nmi_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [nmi_vector]
    jmp asm_core_handler
asm_nmi_handler endp

asm_bp_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [breakpoint_vector]
    jmp asm_core_handler
asm_bp_handler endp

asm_of_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [overflow_vector]
    jmp asm_core_handler
asm_of_handler endp

asm_br_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [bound_range_exceeded_vector]
    jmp asm_core_handler
asm_br_handler endp

asm_ud_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [invalid_opcode_vector]
    jmp asm_core_handler
asm_ud_handler endp

asm_nm_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [device_not_available_vector]
    jmp asm_core_handler
asm_nm_handler endp

asm_df_handler proc
    push qword ptr [double_fault_vector]
    jmp asm_core_handler
asm_df_handler endp

asm_ts_handler proc
    push qword ptr [invalid_tss_vector]
    jmp asm_core_handler
asm_ts_handler endp

asm_np_handler proc
    push qword ptr [segment_not_present_vector]
    jmp asm_core_handler
asm_np_handler endp

asm_ss_handler proc
    push qword ptr [stack_segment_fault_vector]
    jmp asm_core_handler
asm_ss_handler endp

asm_gp_handler proc
    push qword ptr [general_protection_vector]
    jmp asm_core_handler
asm_gp_handler endp

asm_pf_handler proc
    push qword ptr [page_fault_vector]
    jmp asm_core_handler
asm_pf_handler endp

asm_mf_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [x87_floating_point_error_vector]
    jmp asm_core_handler
asm_mf_handler endp

asm_ac_handler proc
    push qword ptr [alignment_check_vector]
    jmp asm_core_handler
asm_ac_handler endp

asm_mc_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [machine_check_vector]
    jmp asm_core_handler
asm_mc_handler endp

asm_xm_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [simd_floating_point_error_vector]
    jmp asm_core_handler
asm_xm_handler endp

asm_ve_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [virtualization_exception_vector]
    jmp asm_core_handler
asm_ve_handler endp

asm_cp_handler proc
    push qword ptr [control_protection_vector]
    jmp asm_core_handler
asm_cp_handler endp

asm_syscall_handler proc
    jmp rcx
asm_syscall_handler endp

asm_switch_segments proc
    push rbx

    movzx rbx, dx
    push rbx

    mov rbx, rsp
    add rbx, 8
    push rbx

    pushfq

    movzx rbx, cx
    push rbx

    lea rbx, [continue]
    push rbx

    iretq

continue:

    pop rbx
    ret
asm_switch_segments endp

asm_switch_to_cpl_0 proc
    push rcx
    push r11

    syscall

    pop r11
    pop rcx

    ret
asm_switch_to_cpl_0 endp

asm_execute_compatibility_mode_code proc

    mov rax, 01337h
    int 3

    ret
asm_execute_compatibility_mode_code endp

__cause_ve proc
    int 14h
__cause_ve endp

end
