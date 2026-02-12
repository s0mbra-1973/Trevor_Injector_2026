#ifndef METAMORPHIC_ENGINE_H
#define METAMORPHIC_ENGINE_H

#include <windows.h>
#include <vector>

// Macros para insertar basura (Junk Code) entre funciones críticas
#define INSERT_JUNK_CODE __asm { nop } __asm { xchg eax, eax }

class MetamorphicEngine {
public:
    // Inicia la mutación del proceso en memoria
    static bool MutateSelf();
    
    // Genera una firma única para la sesión actual
    static std::vector<BYTE> GenerateDynamicSignature();

private:
    // Inserta instrucciones matemáticas aleatorias que no alteran el resultado (NOPs lógicos)
    static void InjectLogicalNoise(PVOID address, SIZE_T size);
    
    // Cambia el orden de los registros utilizados en operaciones aritméticas
    static void ShuffleRegisters();
};

#endif