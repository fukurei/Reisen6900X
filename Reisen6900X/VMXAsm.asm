;
; Summary: Assembly implementation for VMX.cpp
;

PUBLIC AsmEnableVmxOperation
PUBLIC AsmVmxSaveState
PUBLIC AsmVmxRestoreState

PUBLIC AsmGetCs
PUBLIC AsmGetDs
PUBLIC AsmGetEs
PUBLIC AsmGetSs
PUBLIC AsmGetFs
PUBLIC AsmGetGs
PUBLIC AsmGetLdtr
PUBLIC AsmGetTr
PUBLIC AsmGetGdtBase
PUBLIC AsmGetIdtBase
PUBLIC AsmGetGdtLimit
PUBLIC AsmGetIdtLimit
PUBLIC AsmGetRflags

PUBLIC AsmVmexitHandler

EXTERN VmxVmexitHandler:PROC
EXTERN VmxVmresume:PROC
EXTERN VmxReturnStackPointerForVmxoff:PROC
EXTERN VmxReturnInstructionPointerForVmxoff:PROC

EXTERN VmxVirtualizeCurrentSystem:PROC

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

AsmVmxSaveState PROC PUBLIC

    push 0 ; Important, RSP SHOULD ALIGNED TO 0x10, UNLESS IT'LL MOSTLY CAUSE BSOD!!!!!!!
    
    ; Save State
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    sub rsp, 0100h ; Extra Safety
    
    mov rcx, rsp ; Guest RSP
    call VmxVirtualizeCurrentSystem

    int 3

    jmp AsmVmxRestoreState

AsmVmxSaveState ENDP

;------------------------------------------------------------------------

AsmVmxRestoreState PROC
    
    add rsp, 0100h
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    
    popfq	; restore r/eflags
    add rsp, 08h ; because we pushed an etra qword to make it aligned

    ret
    
AsmVmxRestoreState ENDP

;------------------------------------------------------------------------

AsmGetGdtBase PROC

    LOCAL   gdtr[10]:BYTE
    sgdt    gdtr
    mov     rax, QWORD PTR gdtr[2]
    ret

AsmGetGdtBase ENDP

;------------------------------------------------------------------------

AsmGetCs PROC

    mov     rax, cs
    ret

AsmGetCs ENDP

;------------------------------------------------------------------------

AsmGetDs PROC

    mov     rax, ds
    ret

AsmGetDs ENDP

;------------------------------------------------------------------------

AsmGetEs PROC

    mov     rax, es
    ret

AsmGetEs ENDP

;------------------------------------------------------------------------

AsmGetSs PROC

    mov     rax, ss
    ret

AsmGetSs ENDP

;------------------------------------------------------------------------

AsmGetFs PROC

    mov     rax, fs
    ret

AsmGetFs ENDP

;------------------------------------------------------------------------

AsmGetGs PROC

    mov     rax, gs
    ret

AsmGetGs ENDP

;------------------------------------------------------------------------

AsmGetLdtr PROC

    sldt    rax
    ret

AsmGetLdtr ENDP

;------------------------------------------------------------------------

AsmGetTr PROC

    str     rax
    ret

AsmGetTr ENDP

;------------------------------------------------------------------------

AsmGetIdtBase PROC

    LOCAL   idtr[10]:BYTE
    
    sidt    idtr
    mov     rax, QWORD PTR idtr[2]
    ret

AsmGetIdtBase ENDP

;------------------------------------------------------------------------

AsmGetGdtLimit PROC

    LOCAL    gdtr[10]:BYTE
    
    sgdt    gdtr
    mov     ax, WORD PTR gdtr[0]
    ret

AsmGetGdtLimit ENDP

;------------------------------------------------------------------------

AsmGetIdtLimit PROC

    LOCAL    idtr[10]:BYTE
    
    sidt    idtr
    mov     ax, WORD PTR idtr[0]
    ret

AsmGetIdtLimit ENDP

;------------------------------------------------------------------------

AsmGetAccessRights PROC
    lar     rax, rcx
    jz      no_error
    xor     rax, rax
no_error:
    ret
AsmGetAccessRights ENDP

;------------------------------------------------------------------------

AsmGetRflags PROC
    
    pushfq
    pop		rax
    ret
    
AsmGetRflags ENDP

;------------------------------------------------------------------------

AsmVmexitHandler PROC
    
    push 0  ; we might be in an unaligned stack state, so the memory before stack might cause 
            ; irql less or equal as it doesn't exist, so we just put some extra space avoid
            ; these kind of errors

    pushfq

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax	
    
    mov rcx, rsp		; Fast call argument to PGUEST_REGS
    sub	rsp, 020h		; Free some space for Shadow Section
    call	VmxVmexitHandler
    add	rsp, 020h		; Restore the state
    
    cmp	al, 1	; Check whether we have to turn off VMX or Not (the result is in RAX)
    je		AsmVmxoffHandler
    
RestoreState:
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    popfq

    sub rsp, 0100h      ; to avoid error in future functions
    jmp VmxVmresume
    
AsmVmexitHandler ENDP

;------------------------------------------------------------------------

AsmVmxoffHandler PROC
    
    sub rsp, 020h ; shadow space
    call VmxReturnStackPointerForVmxoff
    add rsp, 020h ; remove for shadow space
    
    mov [rsp+88h], rax  ; now, rax contains rsp
    
    sub rsp, 020h      ; shadow space
    call VmxReturnInstructionPointerForVmxoff
    add rsp, 020h      ; remove for shadow space
    
    mov rdx, rsp       ; save current rsp
    
    mov rbx, [rsp+88h] ; read rsp again
    
    mov rsp, rbx
    
    push rax            ; push the return address as we changed the stack, we push
                  		; it to the new stack
    
    mov rsp, rdx        ; restore previous rsp
                    
    sub rbx,08h         ; we push sth, so we have to add (sub) +8 from previous stack
                   		; also rbx already contains the rsp
    mov [rsp+88h], rbx  ; move the new pointer to the current stack
    
RestoreState:
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		         ; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    popfq
    pop		rsp     ; restore rsp

    ret             ; jump back to where we called Vmcall

AsmVmxoffHandler ENDP

;------------------------------------------------------------------------

END