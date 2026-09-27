// Impressao e analise comuns: linhas de resultado, ajuste linear e a
// contagem de problemas e ressalvas que decide o veredito final.

#ifndef BENCH_REPORT_H
#define BENCH_REPORT_H

#include "bench_timer.h"

// PROBLEMA invalida o resultado (autoteste, erro de API, alocacao onde nao
// devia). RESSALVA e um achado que o texto precisa mencionar.
void reportProblem(const char *message);
void reportNote(const char *message);
int  reportProblemCount();
int  reportNoteCount();

void reportCrossRunLine(const char *label, const CrossRun *summary);
void reportStatsLine(const char *label, const CycleStats *stats);

// Custo marginal por bloco de 16 B, pelos pisos de 16 e 64 B (3 blocos de
// alavanca), e o desvio percentual do ponto de 32 B em relacao a essa reta.
double reportSlopePerBlock(uint32_t floor16, uint32_t floor64);
double reportLinearityPercent(uint32_t floor16, uint32_t floor32, uint32_t floor64);

#endif
