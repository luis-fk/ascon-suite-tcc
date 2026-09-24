#ifndef AEAD_ORACLE_H
#define AEAD_ORACLE_H

#include <Arduino.h>

struct Result {
  int tested;     // adulteracoes aplicadas
  int rejected;   // recusadas pela verificacao da tag

  int leaked2;    // recusas com sequencia de texto claro >= 2 bytes
  int leaked3;    // idem, >= 3 bytes
  int leaked4;    // idem, >= LEAK_RUN bytes -- e este que define o veredito
  int maxRun;     // maior sequencia observada em toda a bateria
};

Result resultEmpty();
void   resultAdd(Result *total, Result part);

// Imprime "  <label> : R/T rejeitados", sinalizando vazamento se houver.
void printResult(const char *label, Result result);

// Decifra um pacote adulterado e contabiliza o veredito em result.
void aeadCheckTampered(const uint8_t *packet, size_t packetLength,
                       const uint8_t *associated, size_t associatedLength,
                       const uint8_t *nonceToUse,
                       Result *result);

#endif
