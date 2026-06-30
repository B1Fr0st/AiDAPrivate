PUBLIC EngCreateBitmapSyscall
PUBLIC NtGdiEngCreateDeviceBitmapSyscall

_TEXT SEGMENT

; x64 Windows syscall ABI:
; rcx = arg1 -- MUST be saved to r10 before syscall (syscall clobbers rcx with RIP)
; rdx = arg2
; r8  = arg3
; r9  = arg4
; The kernel restores arg1 from R10.

; NtGdiEngCreateBitmap — syscall 0x127C (SSDT index 636 + win32k base 0x1000)
; HBITMAP NtGdiEngCreateBitmap(SIZEL sizl, LONG lDelta, ULONG iFormat, FLONG fl, PVOID pvBits)
EngCreateBitmapSyscall PROC
    mov r10, rcx
    mov eax, 127Ch
    syscall
    ret
EngCreateBitmapSyscall ENDP

; NtGdiEngCreateDeviceBitmap — syscall 0x127E (SSDT index 638 + win32k base 0x1000)
; HBITMAP NtGdiEngCreateDeviceBitmap(DHSURF dhsurf, SIZEL sizl, ULONG iFormatCompat)
;   rcx = dhsurf  (user-mode pointer to fake DHSURF structure)
;   rdx = sizl    (SIZEL packed as QWORD: cx in low DWORD, cy in high DWORD)
;   r8  = iFormatCompat (6 = BMF_32BPP, must be 1-8)
NtGdiEngCreateDeviceBitmapSyscall PROC
    mov r10, rcx
    mov eax, 127Eh
    syscall
    ret
NtGdiEngCreateDeviceBitmapSyscall ENDP

_TEXT ENDS

END
