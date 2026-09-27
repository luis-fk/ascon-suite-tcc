// Entradas de teste: os buffers compartilhados e as formas de preenche-los.
// Tudo e determinista; nada e sorteado.

#ifndef BENCH_INPUTS_H
#define BENCH_INPUTS_H

#include "bench_config.h"
#include <ASCON.h>

// Classes de entrada do teste de tempo constante. A rampa e a entrada padrao
// de todas as medicoes; as outras cobrem extremos que uma rampa nao alcanca.
enum InputClass {
  CLASS_RAMP,          // varia por iteracao e por posicao
  CLASS_ZEROS,         // chave, nonce e texto todos 0x00
  CLASS_ONES,          // todos 0xFF
  CLASS_ALTERNATING,   // 0x55 e 0xAA
  CLASS_HASH,          // saida do Ascon-Hash sobre o numero da iteracao
  CLASS_COUNT
};

extern uint8_t key[ASCON128_KEY_SIZE];
extern uint8_t nonce[ASCON128_NONCE_SIZE];
extern uint8_t gcmIv[12];                              // IV de 96 bits do GCM
extern uint8_t plaintext[MAX_PLAINTEXT];
extern uint8_t ciphertext[MAX_PLAINTEXT + TAG_BYTES];  // Ascon: texto cifrado || tag
extern uint8_t recovered[MAX_PLAINTEXT];
extern uint8_t aesCiphertext[MAX_PLAINTEXT];
extern uint8_t aesTag[TAG_BYTES];

void inputsPrepareRamp(int iteration, size_t length);          // chave, nonce, IV e texto
void inputsPrepareRampKeepKey(int iteration, size_t length);   // nonce, IV e texto; chave intacta
void inputsPrepareClass(InputClass inputClass, int iteration, size_t length);
const char *inputsClassName(InputClass inputClass);

#endif
