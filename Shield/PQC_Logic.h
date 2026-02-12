#ifndef PQC_LOGIC_H
#define PQC_LOGIC_H

#include <vector>
#include <cstdint>

// Parámetros de seguridad para el Retículo (Lattice)
// n = dimensión, q = módulo, sigma = distribución de error
#define LWE_DIMENSION 512
#define LWE_MODULO 12289
#define LWE_ERROR_SIGMA 3.2

/**
 * Estructura de la Llave de Invisibilidad
 * Basada en el problema matemático de "Aprendizaje con Errores".
 */
struct PQC_Lattice_Key {
    int16_t a[LWE_DIMENSION]; // Vector público
    int16_t s[LWE_DIMENSION]; // Secreto (Llave privada)
    int16_t e;                // Ruido/Error matemático
    int16_t b;                // Resultado b = a*s + e
};

/**
 * Clase principal del Escudo PQC
 */
class PQCShield {
public:
    // Genera un nuevo acertijo matemático
    static PQC_Lattice_Key GenerateChallenge();

    // Verifica si la ejecución es "legítima" resolviendo el retículo
    // Se usa para proteger los saltos lógicos (if/else) del inyector
    static bool VerifyInvisibility(PQC_Lattice_Key key);

    // Función de ofuscación de flujo
    // Bloquea descompiladores creando rutas lógicas computacionalmente caras
    static void DeployLatticeBarrier();
};

#endif // PQC_LOGIC_H
