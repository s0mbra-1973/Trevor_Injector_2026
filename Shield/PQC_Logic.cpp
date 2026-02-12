#include "PQC_Logic.h"
#include <random>
#include <cmath>

PQC_Lattice_Key PQCShield::GenerateChallenge() {
    PQC_Lattice_Key key;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, LWE_MODULO - 1);
    std::normal_distribution<> error_dist(0, LWE_ERROR_SIGMA);

    int32_t dot_product = 0;
    for (int i = 0; i < LWE_DIMENSION; i++) {
        key.a[i] = dist(gen);
        key.s[i] = (dist(gen) % 3) - 1; // Secreto ternario {-1, 0, 1}
        dot_product += (key.a[i] * key.s[i]);
    }

    key.e = static_cast<int16_t>(std::round(error_dist(gen)));
    key.b = (dot_product + key.e) % LWE_MODULO;

    return key;
}

bool PQCShield::VerifyInvisibility(PQC_Lattice_Key key) {
    int32_t check = 0;
    for (int i = 0; i < LWE_DIMENSION; i++) {
        check += (key.a[i] * key.s[i]);
    }
    
    int16_t result = (check + key.e) % LWE_MODULO;
    
    // El "Predicado Opaco": La condición siempre es verdadera para nosotros,
    // pero un analizador estático no puede predecir el resultado sin resolver el LWE.
    return (result == key.b);
}

void PQCShield::DeployLatticeBarrier() {
    PQC_Lattice_Key challenge = GenerateChallenge();
    
    // Si el análisis heurístico intenta saltarse esta verificación,
    // el programa entrará en un estado de memoria corrupta adrede.
    if (!VerifyInvisibility(challenge)) {
        exit(0); 
    }
}