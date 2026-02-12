#ifndef INJECTION_MANAGER_H
#define INJECTION_MANAGER_H

#include <windows.h>

enum InjectionMethod {
    METHOD_MANUAL_MAP,      // Estándar, pero sólido
    METHOD_THREAD_HIJACK,   // Secuestro de contexto (Sigiloso)
    METHOD_APC_QUEUING      // Uso de Asynchronous Procedure Calls
};

class InjectionManager {
public:
    static bool Execute(InjectionMethod method, DWORD processId, const char* dllPath);
};

#endif