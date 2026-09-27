// Memoria: heap por operacao e por tamanho, e pilha medida numa tarefa propria.

#ifndef BENCH_MEMORY_H
#define BENCH_MEMORY_H

#include "bench_timer.h"

struct HeapProbe {
  uint32_t freeBefore;
  uint32_t freeAfter;
  uint32_t minimumDuring;   // menor heap livre visto pelo observador enquanto a operacao rodava
  uint32_t samples;         // leituras que o observador fez nesse intervalo
  bool     watched;         // o observador chegou a rodar
};

struct StackProbe {
  const BenchSpec *spec;
  size_t           length;
  uint32_t         markStart;   // folga de pilha ao entrar na tarefa, antes de qualquer chamada
  uint32_t         markEnd;     // folga depois da operacao
  volatile bool    done;
};

// Uma operacao completa (beginRun, prepare, operacao, endRun) entre duas
// leituras do heap, com um OBSERVADOR no outro nucleo lendo o heap livre em
// laco durante a operacao e guardando o menor valor. Uma alocacao que e feita
// e liberada dentro da operacao nao muda o "antes" nem o "depois", mas aparece
// no menor valor visto. (O "heap minimo historico" do ESP-IDF nao serve para
// isso: e a soma dos minimos de cada regiao de memoria, e uma alocacao so
// deixa marca se a regiao em que caiu descer abaixo do proprio minimo.)
HeapProbe memoryHeapProbe(const BenchSpec *spec, size_t length);

// A marca d'agua de pilha e historica: vale o ponto mais fundo que a tarefa ja
// atingiu. Lida na tarefa principal, depois de Serial.print, ela nao mede nada.
// Por isso a operacao roda numa tarefa nova, e a marca e lida la dentro, antes
// e depois, sem imprimir nada no meio. No ESP-IDF a marca vem em bytes.
bool memoryStackProbe(const BenchSpec *spec, size_t length, StackProbe *probe);

#endif
