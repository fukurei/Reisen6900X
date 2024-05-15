;
; Summary: Assembly implementation for VMX.cpp
;

PUBLIC AsmEnableVmxOperation

.code text

;------------------------------------------------------------------------

AsmEnableVmxOperation PROC PUBLIC

    xor rax, rax			; Clear the RAX
    mov rax, cr4
    or rax, 02000h		; Set the 14th bit
    mov cr4, rax
    ret

AsmEnableVmxOperation ENDP

;------------------------------------------------------------------------

END