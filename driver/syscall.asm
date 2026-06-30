PUBLIC EngCreateBitmapSyscall
PUBLIC NtGdiEngCreateDeviceBitmapSyscall

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

_TEXT ENDS

END
