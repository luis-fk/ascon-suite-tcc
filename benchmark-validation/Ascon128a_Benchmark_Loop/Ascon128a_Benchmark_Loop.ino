#include <ASCON.h>
#include <math.h>
#include "freertos/FreeRTOS.h"

#define MAX_PLAINTEXT 64
#define RUNS 100                 // N execucoes independentes por tamanho
#define ITERATIONS_PER_RUN 2000  // medidas dentro de cada execucao (igual ao single-run)

static uint8_t key[ASCON128_KEY_SIZE];
static uint8_t nonce[ASCON128_NONCE_SIZE];
static uint8_t plaintext[MAX_PLAINTEXT];
static uint8_t ciphertext[MAX_PLAINTEXT + ASCON128_TAG_SIZE];

// spinlock para medir a cifragem com interrupcoes desabilitadas (sem ruido de ISR)
static portMUX_TYPE benchmarkSpinlock = portMUX_INITIALIZER_UNLOCKED;

struct CycleStatistics {
  uint32_t minCycles;
  uint32_t maxCycles;
  double   meanCycles;
  double   standardDeviation;
};

// Agregado ENTRE as N execucoes (metrica: o piso de cada execucao).
struct CrossRunSummary {
  uint32_t minFloor;      // menor piso entre as execucoes (piso absoluto)
  uint32_t maxFloor;      // maior piso entre as execucoes
  double   sumFloors;     // soma dos pisos (para a media)
  int      runsAtFloor;   // quantas execucoes atingiram minFloor (reprodutibilidade)
  double   sumStandardDeviation;  // soma dos desvios intra-execucao (para a media)
};

static void fillVarying(uint8_t *buffer, size_t length, int iteration,
                        uint8_t perIterationStep, uint8_t perByteStep, uint8_t offset)
{
  for (size_t index = 0; index < length; index++) {
    buffer[index] = (uint8_t)(iteration * perIterationStep + index * perByteStep + offset);
  }
}

static void varyInputs(int iteration, size_t messageLength)
{
  fillVarying(key,       ASCON128_KEY_SIZE,   iteration, 31, 7, 1);
  fillVarying(nonce,     ASCON128_NONCE_SIZE, iteration, 17, 3, 0);
  fillVarying(plaintext, messageLength,       iteration, 13, 5, 0);
}

// Uma execucao: 'iterations' medidas de cifragem de 'messageLength' bytes, com
// interrupcoes desabilitadas durante cada cifragem (piso livre de ISR).
static CycleStatistics benchmarkEncrypt(size_t messageLength, int iterations)
{
  size_t ciphertextLength = 0;
  uint32_t minCycles = 0xFFFFFFFFu, maxCycles = 0;
  double cycleSum = 0.0, cycleSumOfSquares = 0.0;

  // aquecimento (estabiliza cache); nao contabilizado
  for (int iteration = 0; iteration < 16; iteration++) {
    varyInputs(iteration, messageLength);
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
  }

  for (int iteration = 0; iteration < iterations; iteration++) {
    varyInputs(iteration, messageLength);

    portENTER_CRITICAL(&benchmarkSpinlock);        // interrupcoes off: mede so a cifragem (sem ISR)
    uint32_t startCycles = ESP.getCycleCount();
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
    uint32_t endCycles = ESP.getCycleCount();
    portEXIT_CRITICAL(&benchmarkSpinlock);

    uint32_t cycles = endCycles - startCycles;     // subtracao uint32 trata o wrap do contador

    if (cycles < minCycles) {
      minCycles = cycles;
    }

    if (cycles > maxCycles) {
      maxCycles = cycles;
    }

    cycleSum          += (double) cycles;
    cycleSumOfSquares += (double) cycles * (double) cycles;
  }

  CycleStatistics stats;

  stats.minCycles  = minCycles;
  stats.maxCycles  = maxCycles;
  stats.meanCycles = cycleSum / iterations;

  double variance = cycleSumOfSquares / iterations - stats.meanCycles * stats.meanCycles;
  stats.standardDeviation = variance > 0.0 ? sqrt(variance) : 0.0;

  return stats;
}

static double cyclesToMicroseconds(double cycles)
{
  return cycles / (double) getCpuFrequencyMhz();  // ciclos / MHz = microssegundos
}

// Repete o benchmark 'runs' vezes para um tamanho e agrega a variacao ENTRE rodadas.
static CrossRunSummary repeatBenchmark(size_t messageLength, int runs, int iterationsPerRun)
{
  CrossRunSummary summary;
  summary.minFloor             = 0xFFFFFFFFu;
  summary.maxFloor             = 0;
  summary.sumFloors            = 0.0;
  summary.runsAtFloor          = 0;
  summary.sumStandardDeviation = 0.0;

  for (int run = 0; run < runs; run++) {
    CycleStatistics stats = benchmarkEncrypt(messageLength, iterationsPerRun);
    uint32_t floor = stats.minCycles;

    if (floor < summary.minFloor) {
      summary.minFloor = floor;
      summary.runsAtFloor = 1;             // novo piso: esta rodada e a primeira a atingi-lo
    }
    else if (floor == summary.minFloor) {
      summary.runsAtFloor++;
    }

    if (floor > summary.maxFloor) {
      summary.maxFloor = floor;
    }

    summary.sumFloors            += (double) floor;
    summary.sumStandardDeviation += stats.standardDeviation;

    Serial.print(".");   // progresso (fora da medicao)
    delay(1);            // cede o processador entre rodadas (alimenta o watchdog)
  }

  Serial.println();
  return summary;
}

static void printCrossRun(size_t messageLength, CrossRunSummary summary, int runs)
{
  double meanFloor = summary.sumFloors / runs;

  Serial.print("  "); Serial.print((unsigned) messageLength); Serial.print(" B  ");
  Serial.print("piso min "); Serial.print(summary.minFloor);
  Serial.print(" | piso max "); Serial.print(summary.maxFloor);
  Serial.print(" | spread "); Serial.print(summary.maxFloor - summary.minFloor);
  Serial.print(" | media dos pisos "); Serial.print(meanFloor, 1);
  Serial.print(" (~"); Serial.print(cyclesToMicroseconds(meanFloor), 2); Serial.print(" us)");
  Serial.print(" | rodadas no piso "); Serial.print(summary.runsAtFloor);
  Serial.print("/"); Serial.println(runs);
}

void setup()
{
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("=== Ascon-128a: reprodutibilidade entre execucoes (Secao 3.4.3) ===");
  Serial.print("CPU: "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
  Serial.print("N (execucoes por tamanho): "); Serial.println(RUNS);
  Serial.print("Medidas por execucao: "); Serial.println(ITERATIONS_PER_RUN);
  Serial.println();

  Serial.println("Rodando (cada '.' = 1 execucao):");

  Serial.print("  16 B: ");
  CrossRunSummary summary16 = repeatBenchmark(16, RUNS, ITERATIONS_PER_RUN);

  Serial.print("  32 B: ");
  CrossRunSummary summary32 = repeatBenchmark(32, RUNS, ITERATIONS_PER_RUN);

  Serial.print("  64 B: ");
  CrossRunSummary summary64 = repeatBenchmark(64, RUNS, ITERATIONS_PER_RUN);

  Serial.println();
  Serial.println("--- Entre execucoes (metrica: piso de ciclos por execucao) ---");
  printCrossRun(16, summary16, RUNS);
  printCrossRun(32, summary32, RUNS);
  printCrossRun(64, summary64, RUNS);

  Serial.println();
  Serial.println("--- Dentro de cada execucao (desvio medio das medidas) ---");
  Serial.print("  16 B: desvio medio "); Serial.print(summary16.sumStandardDeviation / RUNS, 2); Serial.println(" ciclos");
  Serial.print("  32 B: desvio medio "); Serial.print(summary32.sumStandardDeviation / RUNS, 2); Serial.println(" ciclos");
  Serial.print("  64 B: desvio medio "); Serial.print(summary64.sumStandardDeviation / RUNS, 2); Serial.println(" ciclos");

  Serial.println();

  uint32_t totalSpread = (summary16.maxFloor - summary16.minFloor)
                       + (summary32.maxFloor - summary32.minFloor)
                       + (summary64.maxFloor - summary64.minFloor);

  if (totalSpread == 0) {
    Serial.println(">>> Piso identico em todas as execucoes: medicao reprodutivel ate o ciclo <<<");
  }
  else {
    Serial.println(">>> Ha variacao de piso entre execucoes (ver 'spread' acima) <<<");
  }
}

void loop()
{
  delay(1000);  // o teste roda uma vez no setup(); cede o processador
}
