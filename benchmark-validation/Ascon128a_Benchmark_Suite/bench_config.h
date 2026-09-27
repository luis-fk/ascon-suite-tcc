// Parametros da suite. Mudar aqui, nao nos modulos.

#ifndef BENCH_CONFIG_H
#define BENCH_CONFIG_H

#include <Arduino.h>

#define RUNS          100    // execucoes independentes por tamanho e operacao
#define ITERATIONS    2000   // medidas dentro de cada execucao
#define WARMUP        16     // chamadas descartadas antes de medir (estabiliza a cache)
#define MAX_PLAINTEXT 64
#define TAG_BYTES     16
#define BLOCK_BYTES   16     // bloco do Ascon-128a e do AES

// Tamanhos de payload, em bytes. 0 mede a parcela fixa diretamente; 2 e 23 sao
// os dois tamanhos que ocorrem no dataset Tour Perret (7 % e 91 % das
// mensagens); 16, 32 e 64 sao fronteiras de bloco, usadas no modelo linear.
static const size_t payloadSizes[] = { 0, 2, 16, 23, 32, 64 };
#define SIZE_COUNT (sizeof(payloadSizes) / sizeof(payloadSizes[0]))

// Pilha da tarefa dedicada em que se mede o consumo de pilha de cada operacao.
#define PROBE_TASK_STACK_BYTES 8192

// Regua do acelerador: ESP32 TRM v5.8, secao 14.3.5 "Speed", p. 284: o nucleo
// cifra um bloco em 11 a 15 ciclos de clock.
#define TRM_BLOCK_CYCLES_MAX 15

// Desvio maximo do ponto de 32 B em relacao a reta 16->64 B para o modelo
// linear ser aceito. Sem modelo linear, a subtracao GCM - CTR nao isola nada.
#define LINEARITY_MAX_PERCENT 1.0

// Tolerancias dos vereditos, em ciclos.
#define FLOOR_MATCH_TOLERANCE 4      // piso com e sem interrupcoes
#define CLASS_MATCH_TOLERANCE 4      // pisos e medias entre classes de entrada

#endif
