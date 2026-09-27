// AES-128 via mbedTLS do proprio core do ESP32: GCM (cifra + autenticacao) e
// CTR (so a cifra), mais o que o SDK declara sobre aceleracao por hardware.

#ifndef BENCH_AES_H
#define BENCH_AES_H

#include "bench_timer.h"

extern const BenchSpec aesGcmEncryptSpec;
extern const BenchSpec aesGcmDecryptSpec;
extern const BenchSpec aesCtrSpec;   // a cifra AES sem autenticacao: instrumento de medicao

extern uint32_t aesDecryptFailures;   // tem de ser 0 (mesmo motivo do Ascon)
extern bool     aesApiError;          // qualquer retorno != 0 do mbedTLS nas medicoes

// Vetor de teste 2 do GCM (McGrew e Viega): chave, IV e texto nulos. Confere
// texto cifrado e tag, decifra, e recusa tag adulterada. Primeiras chamadas do
// AES no firmware: custo com cache fria cronometrado de brinde.
bool aesSelfCheck(uint32_t *firstEncryptCycles, uint32_t *firstDecryptCycles);

// Quatro macros do SDK: definida ou ausente. A prova de verdade e a medicao
// da secao [6]; isto so registra o que o build declara.
void aesReportBuildCapabilities();

#endif
