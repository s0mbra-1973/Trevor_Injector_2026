#include "ntdll_defs.h"
#include <windows.h>

// Definición de la función externa en Syscall.asm
extern "C" NTSTATUS InternalSyscall(DWORD ssn, ...);

/*
 * Función para extraer el número de syscall (SSN) dinámicamente.
 * Esto asegura compatibilidad entre diferentes versiones de Windows (10, 11, etc.)
 */
DWORD GetSyscallNumber(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    PBYTE pFunction = (PBYTE)GetProcAddress(hNtdll, functionName);
    if (!pFunction) return 0;

    // En Windows x64, el número de syscall está en el 5º byte de la función
    // Instrucción: mov eax, <numero> -> B8 XX XX XX XX
    return *(DWORD*)(pFunction + 4);
}

// --- Implementaciones de funciones seguras (Direct Syscalls) ---

NTSTATUS SafeNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) 
{
    DWORD ssn = GetSyscallNumber("NtAllocateVirtualMemory");
    return InternalSyscall(ssn, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS SafeNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten) 
{
    DWORD ssn = GetSyscallNumber("NtWriteVirtualMemory");
    return InternalSyscall(ssn, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS SafeNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect) 
{
    DWORD ssn = GetSyscallNumber("NtProtectVirtualMemory");
    return InternalSyscall(ssn, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}
