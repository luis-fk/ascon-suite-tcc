// Ascon-128a: as operacoes medidas e o autoteste com vetores oficiais.

#ifndef BENCH_ASCON_H
#define BENCH_ASCON_H

#include "bench_timer.h"

extern const BenchSpec asconEncryptSpec;
extern const BenchSpec asconDecryptSpec;

// Decifragens recusadas durante as medicoes. Tem de ser 0: uma recusa e mais
// rapida que uma decifragem completa e contaminaria o piso.
extern uint32_t asconDecryptFailures;

// Dois vetores do KAT oficial (Count 529 e 545 do ASCON-128a.txt): cifra,
// decifra e recusa de tag adulterada. E tambem a primeira chamada do Ascon no
// firmware, entao o custo dela, com a cache fria, e cronometrado de brinde.
bool asconSelfCheck(uint32_t *firstEncryptCycles, uint32_t *firstDecryptCycles);

#endif
