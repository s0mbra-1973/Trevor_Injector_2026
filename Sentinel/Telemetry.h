#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <windows.h>
#include <vector>
#include <string>

struct SystemHeat {
    bool isHooked;          // ¿Hay hooks en ntdll.dll?
    bool isDebuggerPresent; // ¿Nos están debugeando?
    bool isSandbox;         // ¿Estamos en una VM/Sandbox?
    int threatLevel;        // 0 (Seguro) a 100 (Peligro crítico)
};

class Sentinel {
public:
    static SystemHeat AnalyzeEnvironment();
    static bool IsSafeToProceed(SystemHeat heat);
private:
    static bool CheckForEDRHooks();
    static bool CheckForSandboxes();
};

#endif