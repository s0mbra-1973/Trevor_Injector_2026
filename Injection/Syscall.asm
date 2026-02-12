;-------------------------------------------------------------------------
; Trevor Injector 2026 - Direct Syscall Gateway (x64)
;-------------------------------------------------------------------------

.code

InternalSyscall proc
    ; Convención de llamada x64:
    ; Los argumentos de C++ llegan en: RCX, RDX, R8, R9 ...
    ; RCX contiene el SSN (System Service Number)
    
    mov eax, ecx           ; Movemos el SSN a EAX (donde lo espera el kernel)
    mov r10, rdx           ; El 1er arg de la función real pasa de RDX a R10
    
    ; Re-alineación de los siguientes argumentos:
    mov rdx, r8            ; El 2do arg pasa de R8 a RDX
    mov r8, r9             ; El 3er arg pasa de R9 a R8
    
    ; El 4to arg (y posteriores) están en la pila (Stack)
    ; Debemos moverlos para compensar el argumento extra (el SSN) que usamos
    mov r9, [rsp + 40]     ; Recuperamos el 4to arg real del shadow space
    
    ; Ejecutamos la llamada al sistema
    syscall
    
    ret
InternalSyscall endp

end