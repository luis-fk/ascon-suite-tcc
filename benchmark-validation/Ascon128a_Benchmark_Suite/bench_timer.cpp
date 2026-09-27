#include "bench_timer.h"

#include <math.h>
#include "freertos/FreeRTOS.h"

static portMUX_TYPE benchSpinlock = portMUX_INITIALIZER_UNLOCKED;

// A regiao medida e so a operacao. A chamada e indireta (ponteiro de funcao),
// o que custa poucos ciclos fixos, iguais para todas as operacoes.
static inline uint32_t timedCall(const BenchSpec *spec, size_t length, bool interruptsOff)
{
  uint32_t startCycles, endCycles;

  if (interruptsOff) {
    portENTER_CRITICAL(&benchSpinlock);
    startCycles = ESP.getCycleCount();
    spec->operation(length);
    endCycles = ESP.getCycleCount();
    portEXIT_CRITICAL(&benchSpinlock);
  }
  else {
    startCycles = ESP.getCycleCount();
    spec->operation(length);
    endCycles = ESP.getCycleCount();
  }

  return endCycles - startCycles;   // subtracao sem sinal trata a volta do contador
}

CycleStats benchMeasure(const BenchSpec *spec, size_t length, int iterations, bool interruptsOff)
{
  uint32_t minCycles = 0xFFFFFFFFu;
  uint32_t maxCycles = 0;
  double   sum = 0.0;
  double   sumOfSquares = 0.0;

  if (spec->beginRun != NULL) { spec->beginRun(length); }

  for (int iteration = 0; iteration < WARMUP; iteration++) {
    spec->prepare(iteration, length);
    spec->operation(length);
  }

  for (int iteration = 0; iteration < iterations; iteration++) {
    spec->prepare(iteration, length);

    uint32_t cycles = timedCall(spec, length, interruptsOff);

    if (cycles < minCycles) { minCycles = cycles; }
    if (cycles > maxCycles) { maxCycles = cycles; }

    sum          += (double) cycles;
    sumOfSquares += (double) cycles * (double) cycles;
  }

  if (spec->endRun != NULL) { spec->endRun(length); }

  CycleStats stats;
  stats.minCycles  = minCycles;
  stats.maxCycles  = maxCycles;
  stats.meanCycles = sum / iterations;

  double variance = sumOfSquares / iterations - stats.meanCycles * stats.meanCycles;
  stats.standardDeviation = variance > 0.0 ? sqrt(variance) : 0.0;

  return stats;
}

void benchCrossRunInit(CrossRun *summary, int runs)
{
  summary->minFloor             = 0xFFFFFFFFu;
  summary->maxFloor             = 0;
  summary->sumFloors            = 0.0;
  summary->runsAtFloor          = 0;
  summary->sumStandardDeviation = 0.0;
  summary->runs                 = runs;
}

void benchCrossRunAdd(CrossRun *summary, const CycleStats *stats)
{
  uint32_t floor = stats->minCycles;

  if (floor < summary->minFloor) {
    summary->minFloor    = floor;
    summary->runsAtFloor = 1;
  }
  else if (floor == summary->minFloor) {
    summary->runsAtFloor++;
  }

  if (floor > summary->maxFloor) { summary->maxFloor = floor; }

  summary->sumFloors            += (double) floor;
  summary->sumStandardDeviation += stats->standardDeviation;
}

CrossRun benchRepeat(const BenchSpec *spec, size_t length, int runs, int iterations, bool interruptsOff)
{
  CrossRun summary;
  benchCrossRunInit(&summary, runs);

  for (int run = 0; run < runs; run++) {
    CycleStats stats = benchMeasure(spec, length, iterations, interruptsOff);
    benchCrossRunAdd(&summary, &stats);

    Serial.print('.');   // progresso, fora da medicao
    delay(1);            // cede o processador entre execucoes (alimenta o watchdog)
  }

  Serial.println();
  return summary;
}

double benchCyclesToMicroseconds(double cycles)
{
  return cycles / (double) getCpuFrequencyMhz();   // ciclos / MHz = microssegundos
}
