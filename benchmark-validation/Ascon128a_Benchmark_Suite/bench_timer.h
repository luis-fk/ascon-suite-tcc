// A primitiva de medicao. Tudo o que e cronometrado na suite passa por aqui,
// para que Ascon e AES sejam medidos exatamente da mesma forma.

#ifndef BENCH_TIMER_H
#define BENCH_TIMER_H

#include "bench_config.h"

typedef void (*BenchPrepare)(int iteration, size_t length);   // fora da regiao medida
typedef void (*BenchOperation)(size_t length);                // dentro da regiao medida
typedef void (*BenchRunHook)(size_t length);                  // antes e depois de uma execucao

struct BenchSpec {
  const char     *name;
  BenchRunHook    beginRun;    // pode ser NULL (ex.: setkey do AES, uma vez por execucao)
  BenchPrepare    prepare;
  BenchOperation  operation;
  BenchRunHook    endRun;      // pode ser NULL
};

struct CycleStats {
  uint32_t minCycles;
  uint32_t maxCycles;
  double   meanCycles;
  double   standardDeviation;
};

// Agregado ENTRE execucoes. A metrica e o piso (minimo) de cada execucao.
struct CrossRun {
  uint32_t minFloor;
  uint32_t maxFloor;
  double   sumFloors;
  int      runsAtFloor;             // execucoes que atingiram minFloor
  double   sumStandardDeviation;    // soma dos desvios dentro de cada execucao
  int      runs;
};

void benchCrossRunInit(CrossRun *summary, int runs);
void benchCrossRunAdd(CrossRun *summary, const CycleStats *stats);

// Uma execucao: WARMUP chamadas descartadas, depois 'iterations' medidas.
CycleStats benchMeasure(const BenchSpec *spec, size_t length, int iterations, bool interruptsOff);

// 'runs' execucoes seguidas; imprime um '.' por execucao.
CrossRun benchRepeat(const BenchSpec *spec, size_t length, int runs, int iterations, bool interruptsOff);

double benchCyclesToMicroseconds(double cycles);

#endif
